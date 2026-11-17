#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host protocol controls only. Actual SQL admission belongs to the isolated native gate."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('gc_freshness_fixture', ROOT / 'scripts/runtime-freshness-fixture.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
READY = {'result': 'READY', 'rows': 6, 'nullRows': 1, 'withinWindow': True}


class FreshnessFixtureTests(unittest.TestCase):
    def invoke(self, step='refresh', value=READY, code=0):
        raw = value if isinstance(value, bytes) else json.dumps(value).encode()
        with patch.object(fixture.runtime, 'require_local'), patch.object(fixture.runtime, 'require_bootstrap'), patch.object(fixture.subprocess, 'run', return_value=subprocess.CompletedProcess([], code, raw)):
            return fixture.run_step(step)

    def test_closed_steps_refuse_before_any_runtime_admission(self):
        for step in ('repair', 'replace', 'refresh;DROP', '', None, True, ['read']):
            with self.subTest(step=step), patch.object(fixture.runtime, 'require_local') as local, patch.object(fixture.runtime, 'require_bootstrap') as bootstrap, patch.object(fixture.subprocess, 'run') as run:
                with self.assertRaisesRegex(ValueError, '^FRESHNESS_FIXTURE_STEP_REJECTED$'):
                    fixture.run_step(step)
                local.assert_not_called(); bootstrap.assert_not_called(); run.assert_not_called()

    def test_each_finite_step_uses_exact_source_bytes_and_psql_variable(self):
        raw = fixture.SOURCE.read_bytes()
        for step in ('prepare', 'read', 'refresh', 'stale'):
            order = []
            def execute(command, **kwargs):
                order.append('execute')
                self.assertEqual(command, fixture.runtime.COMPOSE + ['exec', '-T', 'source-postgres', 'psql', '-X', '-q', '-A', '-t', '-U', 'source_admin', '-d', 'harbor', '-v', 'ON_ERROR_STOP=1', '-v', 'fixture_step=' + step, '--file', '-'])
                self.assertEqual(kwargs, {'input': raw, 'cwd': fixture.ROOT, 'stdout': subprocess.PIPE, 'stderr': subprocess.DEVNULL, 'timeout': 45, 'check': False})
                return subprocess.CompletedProcess(command, 0, json.dumps(READY).encode())
            with self.subTest(step=step), patch.object(fixture.runtime, 'require_local', side_effect=lambda: order.append('local')), patch.object(fixture.runtime, 'require_bootstrap', side_effect=lambda: order.append('bootstrap')), patch.object(fixture.subprocess, 'run', side_effect=execute) as run:
                self.assertEqual(fixture.run_step(step), {**READY, 'step': step, 'fixture': 'public.freshness_quality_fixture', 'sqlSha256': hashlib.sha256(raw).hexdigest()})
                self.assertEqual(order, ['local', 'bootstrap', 'execute']); run.assert_called_once()

    def test_local_or_bootstrap_refusal_never_executes_source(self):
        for guard in ('require_local', 'require_bootstrap'):
            with patch.object(fixture.runtime, 'require_local') as local, patch.object(fixture.runtime, 'require_bootstrap') as bootstrap, patch.object(fixture.subprocess, 'run') as run:
                (local if guard == 'require_local' else bootstrap).side_effect = SystemExit('CONTROL_REFUSAL')
                with self.assertRaises(SystemExit): fixture.run_step('refresh')
                run.assert_not_called()

    def test_missing_symlink_empty_and_oversized_source_refuse(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); empty = root / 'empty.sql'; empty.write_bytes(b''); oversized = root / 'oversized.sql'; oversized.write_bytes(b'x' * 65537); link = root / 'link.sql'; link.symlink_to(fixture.SOURCE)
            for source in (root / 'missing.sql', empty, oversized, link):
                with self.subTest(source=source.name), patch.object(fixture, 'SOURCE', source), patch.object(fixture.runtime, 'require_local'), patch.object(fixture.runtime, 'require_bootstrap'), patch.object(fixture.subprocess, 'run') as run:
                    with self.assertRaisesRegex(ValueError, '^FRESHNESS_FIXTURE_SOURCE_REJECTED$'): fixture.run_step('read')
                    run.assert_not_called()

    def test_inert_prepare_and_read_allow_old_valid_anchor_but_refresh_requires_fresh_window(self):
        stale = {**READY, 'withinWindow': False}
        for step in ('prepare', 'read'): self.assertEqual(self.invoke(step, stale)['withinWindow'], False)
        for step in ('refresh','stale'):
            with self.assertRaisesRegex(RuntimeError, '^FRESHNESS_FIXTURE_REJECTED$'): self.invoke(step, stale)

    def test_receipt_requires_exact_shape_counts_and_boolean_types(self):
        for patch_value in ({'result': 'OTHER'}, {'rows': 7}, {'rows': 6.0}, {'rows': True}, {'nullRows': 0}, {'nullRows': True}, {'withinWindow': 1}, {'withinWindow': 'true'}, {'private': 'value'}):
            with self.subTest(patch=patch_value), self.assertRaisesRegex(RuntimeError, '^FRESHNESS_FIXTURE_REJECTED$'): self.invoke(value={**READY, **patch_value})
        for key in READY:
            value = {k: v for k, v in READY.items() if k != key}
            with self.assertRaisesRegex(RuntimeError, '^FRESHNESS_FIXTURE_REJECTED$'): self.invoke(value=value)

    def test_malformed_duplicate_oversized_invalid_utf8_and_failed_process_refuse(self):
        good = json.dumps(READY).encode()
        for code, raw in [(1, good), (0, b''), (0, b'null'), (0, b'[]'), (0, good + b'\nNOTICE: private'), (0, good + b' ' * 257), (0, b'\xff'), (0, good.replace(b'"rows": 6', b'"rows": 6,"rows": 6')), (0, good.replace(b'true', b'NaN'))]:
            with self.subTest(code=code, raw=raw[:20]), self.assertRaisesRegex(RuntimeError, '^FRESHNESS_FIXTURE_REJECTED$'): self.invoke(value=raw, code=code)

    def test_launcher_requires_explicit_core_and_one_known_step(self):
        for args in ([], ['--step', 'read'], ['--run-core'], ['--run-core', '--step', 'repair']):
            with self.subTest(args=args), patch.object(fixture, 'run_step') as execute, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as e: fixture.main(args)
                self.assertEqual(e.exception.code, 2); execute.assert_not_called()

    def test_launcher_uses_exact_requested_finite_step(self):
        for step in ('prepare', 'read', 'refresh', 'stale'):
            output = io.StringIO()
            with patch.object(fixture, 'run_step', return_value=READY) as execute, contextlib.redirect_stdout(output):
                self.assertEqual(fixture.main(['--run-core', '--step', step]), 0)
            execute.assert_called_once_with(step); self.assertEqual(json.loads(output.getvalue()), READY)

    def test_launcher_redacts_every_process_failure_without_stdout(self):
        for error in (RuntimeError('private SQL'), ValueError('private rows'), OSError('private path'), subprocess.TimeoutExpired(['private-command'], 45, output=b'private source')):
            out, err = io.StringIO(), io.StringIO()
            with patch.object(fixture, 'run_step', side_effect=error), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(fixture.main(['--run-core', '--step', 'refresh']), 1)
            self.assertEqual(out.getvalue(), ''); self.assertEqual(json.loads(err.getvalue()), {'result': 'FAILED', 'code': 'FRESHNESS_FIXTURE_REJECTED'})


if __name__ == '__main__': unittest.main()
