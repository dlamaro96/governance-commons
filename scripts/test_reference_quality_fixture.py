#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host admission controls only; native fixture shape/data is checked by SQL."""
import contextlib
import hashlib
import importlib.util
import io
import itertools
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('gc_quality_fixture', ROOT / 'scripts/runtime-install-quality-fixture.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class ReferenceFixtureTests(unittest.TestCase):
    # These profiles deliberately retain the pre-existing default/reference
    # call shapes. Each additional profile must not silently redirect either one.
    PROFILES = (
        ({'reference': False}, 'source-fixture.sql', 'QUALITY_FIXTURE_READY_V1', 'public.quality_fixture', 5, 20),
        ({'reference': True}, 'reference-quality-fixture.sql', 'REFERENCE_QUALITY_FIXTURE_READY_V1', 'public.reference_quality_fixture', 4, 20),
        ({'uniqueness': True}, 'uniqueness-quality-fixture.sql', 'UNIQUENESS_QUALITY_FIXTURE_READY_V1', 'public.uniqueness_quality_fixture', 4, 20),
        ({'range_profile': True}, 'range-quality-fixture.sql', 'RANGE_QUALITY_FIXTURE_READY_V1', 'public.range_quality_fixture', 1, 6),
    )

    def test_closed_profiles_admit_their_own_complete_source_only(self):
        for options, name, ready, _, _, _ in self.PROFILES:
            raw = (ROOT / 'deploy/compose' / name).read_bytes()
            with self.subTest(profile=name):
                body = fixture.fixture_sql(raw, **options)
                self.assertTrue(body.rstrip().endswith("SELECT '" + ready + "';"))
                self.assertNotIn('-- BEGIN ', body)
                self.assertNotIn('-- END ', body)
                self.assertIn('\nBEGIN;\n', body)
                self.assertEqual(body.count('\nCOMMIT;\n'), 1)

    def test_every_cross_profile_source_is_rejected(self):
        for source_options, name, _, _, _, _ in self.PROFILES:
            raw = (ROOT / 'deploy/compose' / name).read_bytes()
            for selected_options, selected_name, _, _, _, _ in self.PROFILES:
                if source_options == selected_options:
                    continue
                with self.subTest(source=name, selected=selected_name), self.assertRaisesRegex(ValueError, '^QUALITY_FIXTURE_SOURCE_REJECTED$'):
                    fixture.fixture_sql(raw, **selected_options)

    def test_partial_duplicated_oversized_and_trailing_sources_refuse(self):
        for options, name, ready, _, _, _ in self.PROFILES:
            raw = (ROOT / 'deploy/compose' / name).read_bytes()
            end = b'-- END ' + ready.replace('_READY_V1', '_V1').encode('ascii')
            for label, value in [
                ('missing end', raw.replace(end, b'')),
                ('trailing SQL', raw + b'\nSELECT 1;'),
                ('duplicate block', raw + raw),
                ('oversized', raw + b' ' * 65537),
                ('wrong receipt', raw.replace(ready.encode('ascii'), b'OTHER_FIXTURE_READY_V1')),
                ('invalid UTF-8', b'\xff' + raw),
            ]:
                with self.subTest(profile=name, malformed=label), self.assertRaisesRegex(ValueError, '^QUALITY_FIXTURE_SOURCE_REJECTED$'):
                    fixture.fixture_sql(value, **options)

    def test_multiple_profiles_refuse_through_python_before_runtime(self):
        for size in (2,3):
            for names in itertools.combinations(('reference','uniqueness','range_profile'),size):
                options={name:True for name in names}
                with self.subTest(options=options), self.assertRaisesRegex(ValueError, '^QUALITY_FIXTURE_SOURCE_REJECTED$'):
                    fixture.fixture_sql(fixture.RANGE_SOURCE.read_bytes(), **options)
                with patch.object(fixture.runtime,'require_local') as local, patch.object(fixture.runtime,'require_bootstrap') as bootstrap, patch.object(fixture.subprocess,'run') as run:
                    with self.assertRaisesRegex(ValueError, '^QUALITY_FIXTURE_SOURCE_REJECTED$'):
                        fixture.install(**options)
                    local.assert_not_called();bootstrap.assert_not_called();run.assert_not_called()

    def test_no_runtime_without_explicit_launcher_flag(self):
        for arguments in ([], ['--reference'], ['--uniqueness'], ['--range']):
            with self.subTest(arguments=arguments), patch.object(fixture, 'install') as install, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    fixture.main(arguments)
                self.assertEqual(error.exception.code, 2)
                install.assert_not_called()

    def test_mutually_exclusive_cli_rejects_both_orders_before_install(self):
        for flags in itertools.permutations(('--reference','--uniqueness','--range'),2):
            arguments=['--run-core',*flags]
            with self.subTest(arguments=arguments), patch.object(fixture, 'install') as install, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    fixture.main(arguments)
                self.assertEqual(error.exception.code, 2)
                install.assert_not_called()

    def test_closed_profile_selection_reaches_install_without_changing_default(self):
        for arguments, options in [(['--run-core'], {'reference': False}), (['--run-core', '--reference'], {'reference': True}), (['--run-core', '--uniqueness'], {'uniqueness': True}), (['--run-core', '--range'], {'range_profile': True})]:
            with patch.object(fixture, 'install', return_value={'result': 'HOST_CONTROL_ONLY'}) as install, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(fixture.main(arguments), 0)
                install.assert_called_once_with(**options)

    def test_selected_profile_executes_only_admitted_body_and_preserves_receipt(self):
        for options, name, ready, table, null_rows, rows in self.PROFILES:
            raw = (ROOT / 'deploy/compose' / name).read_bytes()
            expected = fixture.fixture_sql(raw, **options).encode('utf-8')
            order = []
            def execute(command, **kwargs):
                order.append('execute')
                self.assertEqual(command, fixture.runtime.COMPOSE + ['exec', '-T', 'source-postgres', 'psql', '-X', '-q', '-A', '-t', '-U', 'source_admin', '-d', 'harbor', '-v', 'ON_ERROR_STOP=1', '--file', '-'])
                self.assertEqual(kwargs['input'], expected)
                self.assertEqual(kwargs['cwd'], ROOT)
                self.assertEqual(kwargs['timeout'], 45)
                self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
                return subprocess.CompletedProcess(command, 0, (ready + '\n').encode('ascii'))
            with self.subTest(profile=name), patch.object(fixture.runtime, 'require_local', side_effect=lambda: order.append('local')), patch.object(fixture.runtime, 'require_bootstrap', side_effect=lambda: order.append('bootstrap')), patch.object(fixture.subprocess, 'run', side_effect=execute) as run:
                self.assertEqual(fixture.install(**options), {'fixture': table, 'result': 'READY', 'rows': rows, 'nullRows': null_rows, 'sqlSha256': hashlib.sha256(expected).hexdigest()})
                run.assert_called_once()
                self.assertEqual(order, ['local', 'bootstrap', 'execute'])

    def test_success_requires_selected_profile_receipt_and_successful_exit(self):
        for options, name, ready, _, _, _ in self.PROFILES:
            other_ready = [entry[2] for entry in self.PROFILES if entry[2] != ready]
            outcomes = [(0, b''), (1, ready.encode('ascii')), (0, ready.encode('ascii') + b'\nNOTICE: unexpected'), (0, b' ' * 129)]
            outcomes.extend((0, value.encode('ascii')) for value in other_ready)
            for code, output in outcomes:
                with self.subTest(profile=name, returncode=code, output=output), patch.object(fixture.runtime, 'require_local'), patch.object(fixture.runtime, 'require_bootstrap'), patch.object(fixture.subprocess, 'run', return_value=subprocess.CompletedProcess([], code, output)):
                    with self.assertRaisesRegex(RuntimeError, '^QUALITY_FIXTURE_INSTALL_REJECTED$'):
                        fixture.install(**options)

    def test_local_and_bootstrap_refusals_never_execute_fixture(self):
        for options, _, _, _, _, _ in self.PROFILES:
            for guard in ('require_local', 'require_bootstrap'):
                with self.subTest(options=options, guard=guard), patch.object(fixture.runtime, 'require_local') as local, patch.object(fixture.runtime, 'require_bootstrap') as bootstrap, patch.object(fixture.subprocess, 'run') as run:
                    (local if guard == 'require_local' else bootstrap).side_effect = SystemExit('HOST_CONTROL_REFUSAL')
                    with self.assertRaises(SystemExit):
                        fixture.install(**options)
                    run.assert_not_called()

    def test_missing_symlink_and_cross_profile_files_do_not_execute(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            wrong = directory / 'wrong.sql'
            wrong.write_bytes(fixture.REFERENCE_SOURCE.read_bytes())
            symlink = directory / 'symlink.sql'
            symlink.symlink_to(fixture.UNIQUENESS_SOURCE)
            for source in (directory / 'missing.sql', symlink, wrong):
                with self.subTest(source=source.name), patch.object(fixture, 'UNIQUENESS_SOURCE', source), patch.object(fixture.runtime, 'require_local'), patch.object(fixture.runtime, 'require_bootstrap'), patch.object(fixture.subprocess, 'run') as run:
                    with self.assertRaisesRegex(ValueError, '^QUALITY_FIXTURE_SOURCE_REJECTED$'):
                        fixture.install(uniqueness=True)
                    run.assert_not_called()

    def test_range_missing_symlink_and_wrong_profile_refuse_without_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            directory=Path(directory);wrong=directory/'wrong.sql';wrong.write_bytes(fixture.SOURCE.read_bytes())
            symlink=directory/'link.sql';symlink.symlink_to(fixture.RANGE_SOURCE)
            for source in (directory/'absent.sql',wrong,symlink):
                with self.subTest(source=source.name), patch.object(fixture,'RANGE_SOURCE',source), patch.object(fixture.runtime,'require_local'), patch.object(fixture.runtime,'require_bootstrap'), patch.object(fixture.subprocess,'run') as run:
                    with self.assertRaisesRegex(ValueError,'^QUALITY_FIXTURE_SOURCE_REJECTED$'):
                        fixture.install(range_profile=True)
                    run.assert_not_called()

    def test_install_failures_are_closed_without_raw_process_details(self):
        for arguments, table in [(['--run-core'], 'public.quality_fixture'), (['--run-core', '--reference'], 'public.reference_quality_fixture'), (['--run-core', '--uniqueness'], 'public.uniqueness_quality_fixture'), (['--run-core', '--range'], 'public.range_quality_fixture')]:
            stdout, stderr = io.StringIO(), io.StringIO()
            with self.subTest(arguments=arguments), patch.object(fixture, 'install', side_effect=RuntimeError('private diagnostic must not escape')), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(fixture.main(arguments), 1)
                self.assertEqual(stdout.getvalue(), '')
                self.assertEqual(json.loads(stderr.getvalue()), {'fixture': table, 'result': 'FAILED', 'code': 'QUALITY_FIXTURE_INSTALL_REJECTED'})


if __name__ == '__main__':
    unittest.main()
