# SPDX-License-Identifier: Apache-2.0
"""Host launcher controls only: no Docker or PostgreSQL execution."""
import ast
from collections import Counter
import contextlib
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import re
import sys
import tempfile
import time
import unittest
from datetime import datetime
from unittest import mock

RUNNER = Path(__file__).with_name('runtime-test-range-quality-worker.py')
spec = importlib.util.spec_from_file_location('range_worker_gate_controls', RUNNER)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def harness():
    h = gate.Harness()
    h.source = {'id': '1'*64}
    h.worker = {'id': '2'*64, 'image': 'sha256:'+'3'*64}
    h.helper = {'id': '4'*64, 'image': h.worker['image'], 'owner': h.marker, 'running': True}
    h.owned = {name: {'oid': str(20000+i), 'owner': 'source_admin', 'marker': h.marker} for i, name in enumerate(h.names.values())}
    h.domain_oid = '30000'
    return h


def embedded():
    tree = ast.parse(gate.WORKER)
    nodes = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ('require', 'measurement')]
    scope = {'re': re, 'datetime': datetime, 'math': math}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<embedded-controls>', 'exec'), scope)
    return scope


class Controls(unittest.TestCase):
    def test_opt_in_before_any_runtime_or_source_read(self):
        with mock.patch.object(sys, 'argv', [str(RUNNER)]), mock.patch.object(gate, 'Harness') as constructor, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                gate.main()
        self.assertEqual(caught.exception.code, 2)
        constructor.assert_not_called()

    def test_sources_and_effective_mount_bytes_are_equal_and_bound(self):
        hashes = gate.source_hashes()
        effective = gate.effective_hashes(hashes)
        for relative, path in gate.OVERLAYS.items():
            self.assertEqual(hashes[relative], hashlib.sha256((gate.ROOT/relative).read_bytes()).hexdigest())
            self.assertEqual(effective[relative], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(hashes['python/governance_workers/quality.py'], effective['python/governance_workers/quality.py'])
        for path in [RUNNER, gate.WORKER_PATH]:
            self.assertEqual(hashes[str(path.relative_to(gate.ROOT))], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(len(gate.CHECKS), len(set(gate.CHECKS)))
        self.assertEqual(len(gate.CHECKS), 16)

    def test_fixed_public_layout_and_exact_root_sources(self):
        root = RUNNER.resolve().parents[1]
        self.assertEqual(gate.ROOT, root)
        self.assertEqual(gate.CANDIDATE, root)
        self.assertEqual(gate.HASH_VECTORS, root/'tests/fixtures/quality-range-hash-vectors.json')
        self.assertEqual(gate.FIXTURE_PATH, root/'deploy/compose/range-quality-fixture.sql')
        self.assertEqual(gate.WORKER_PATH, root/'scripts/range_quality_worker_program.py')
        self.assertEqual(gate.OVERLAYS, {name: root/name for name in (
            'python/governance_workers/quality.py', 'python/governance_workers/server.py')})
        self.assertTrue(all('.local/' not in name for name in gate.source_hashes()))

    def test_independent_integer_oracles_and_only_owned_insert_targets(self):
        h = harness()
        statements = []
        owned = {'tables': h.owned, 'domain': {'oid': h.domain_oid, 'owner': 'source_admin', 'marker': h.marker}}
        h.sql = lambda statement, **kwargs: statements.append(statement) or json.dumps(owned)
        h.prepare()
        text = statements[0]
        self.assertEqual(text.count('CREATE TABLE'), 17)
        self.assertNotIn('range_quality_fixture', text)
        self.assertIn('AS bigint;', text)
        source_rows = {'canonical': [-1,0,5,10,11,None], 'canonical_null': [None]*6,
                       'allnull': [None]*5, 'empty': []}
        for kind in ('int2','int4','int8','large','extrema'):
            line = next(line for line in text.splitlines() if line.startswith('INSERT INTO public."'+h.names[kind]+'" VALUES '))
            values = line.split(' VALUES ',1)[1].removesuffix(';')
            self.assertRegex(values, r'^\((?:NULL|-?[0-9]+)\)(?:,\((?:NULL|-?[0-9]+)\))*$')
            source_rows[kind] = [None if part=='NULL' else int(part) for part in re.findall(r'\(([^()]+)\)', values)]
        self.assertEqual(source_rows['int2'][0], -32768)
        self.assertEqual(source_rows['int4'][-2], 2147483647)
        self.assertEqual(source_rows['int8'][0], -9223372036854775808)
        self.assertEqual(source_rows['int8'][-2], 9223372036854775807)
        self.assertEqual(source_rows['large'], [9007199254740992,9007199254740993,9007199254740994,None])
        main = next(n for n in ast.parse(gate.WORKER).body if isinstance(n, ast.FunctionDef) and n.name=='main')
        expected = ast.literal_eval(next(n.value for n in main.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='expected' for t in n.targets)))
        self.assertEqual(len(expected), 11)
        for kind, counts, minimum, maximum in expected:
            values = source_rows[kind]
            actual = (len(values),sum(v is None for v in values),sum(v is not None and v<int(minimum) for v in values),sum(v is not None and v>int(maximum) for v in values))
            self.assertEqual(counts, actual, kind)
        self.assertIn('generate_series(1,100001)', text)
        self.assertIn('ENABLE ROW LEVEL SECURITY', text)
        self.assertTrue(text.startswith('BEGIN;') and text.endswith('COMMIT;'))

    def test_independent_check_inventory_and_fixed_three_hash_vectors(self):
        expected = ['canonical_six_rows_inclusive_oracle','canonical_all_null',
                    'builtin_int2_int4_int8_exact','above_js_safe_integer_singleton',
                    'int64_extrema_and_equal_bounds','three_canonical_binding_hash_vectors',
                    'owned_all_null_and_empty','lowered_row_bound_and_100001_refusal',
                    'actual_plan_cost_and_bytes_refusal','all_eight_target_pins_refused_when_stale',
                    'numeric_float_money_text_domain_unsupported','rls_and_inheritance_unsupported',
                    'native_reader_role_and_read_only_default','native_reader_dml_denied',
                    'closed_aggregates_without_source_values','actual_lock_timeout_refusal']
        self.assertEqual(gate.CHECKS, expected)
        tree = ast.parse(gate.WORKER)
        lists = [ast.literal_eval(n) for n in ast.walk(tree) if isinstance(n,ast.List) and all(isinstance(e,ast.Constant) and isinstance(e.value,str) for e in n.elts)]
        self.assertIn(expected[:-1], lists)
        self.assertIn(expected[-1:], lists)
        vectors = ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='VECTORS' for t in n.targets)))
        frozen = json.loads(gate.HASH_VECTORS.read_text())['vectors']
        self.assertEqual(len(vectors),3)
        for vector, recorded in zip(vectors,frozen):
            minimum,maximum,want = vector
            self.assertEqual((minimum,maximum,want),(recorded['preimage']['minimum'],recorded['preimage']['maximum'],recorded['rangeHash']))
            self.assertEqual(hashlib.sha256(recorded['canonicalUtf8'].encode()).hexdigest(),want)

    def test_cleanup_exact_oid_owner_marker_and_dependency_order(self):
        h = harness()
        statements = []
        h.sql = lambda statement, **kw: statements.append((statement, kw)) or ('0' if statement.startswith('SELECT ') else '')
        h.cleanup_objects()
        text = statements[0][0]
        self.assertLess(text.index(f'DROP TABLE public."{h.names["child"]}"'), text.index(f'DROP TABLE public."{h.names["parent"]}"'))
        self.assertGreater(text.index('DROP DOMAIN'), text.rindex('DROP TABLE'))
        self.assertNotIn('CASCADE', text)
        self.assertNotIn('range_quality_fixture', text)
        for name, pin in h.owned.items():
            self.assertIn(f"c.relname='{name}'", text)
            self.assertIn(f"c.oid={pin['oid']}::oid", text)
        self.assertEqual(text.count('Fixture ownership mismatch'), 18)
        self.assertEqual(text.count("r.rolname='source_admin'"), 18)
        self.assertTrue(all(kw == {'cleanup': True} for _, kw in statements))

    def test_hostile_cleanup_name_cannot_reach_sql(self):
        h = harness()
        h.names['many'] = 'unrelated_table'
        h.sql = mock.Mock()
        with self.assertRaises(gate.base.Refusal): h.cleanup_objects()
        h.sql.assert_not_called()

    def test_helper_uses_exact_readonly_overlays_no_dependency_start_and_no_secret_export(self):
        h = harness()
        calls = []
        overrides = []
        def command(args, **kw):
            calls.append((args, kw))
            if 'config' in args or 'run' in args:
                prefix = args[:len(gate.base.COMPOSE)]
                self.assertEqual(prefix, gate.base.COMPOSE)
                self.assertEqual(args[len(prefix)], '-f')
                path = Path(args[len(prefix)+1]); overrides.append(path)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.read_text(), 'services:\n  python-worker:\n    image: "'+h.worker['image']+'"\n    pull_policy: never\n    build: !reset null\n    restart: "no"\n')
            return h.helper['id'] if 'run' in args else ''
        h.command = command
        h.helper_identity = lambda: h.helper
        h.start_helper()
        self.assertEqual(calls[1][0][-2:], ['config', '--quiet'])
        self.assertEqual(calls[1][1], {'seconds': 15})
        args = calls[2][0]
        for token in ('--no-deps', '--rm', '--detach', '480'):
            self.assertIn(token, args)
        self.assertNotIn('--pull', args)
        self.assertNotIn('--build', args)
        for name, path in gate.OVERLAYS.items():
            self.assertIn(str(path.resolve())+':/worker/'+name.removeprefix('python/')+':ro', args)
        self.assertNotIn('env', args)
        self.assertNotIn('--privileged', args)
        self.assertNotIn('--publish', args)
        self.assertIn('io.governance-commons.qualification='+h.marker, args)
        self.assertEqual(overrides[0], overrides[1])
        self.assertTrue(all(not path.exists() for path in overrides))

    def test_invalid_worker_image_cannot_write_override_or_launch_helper(self):
        h = harness()
        h.worker['image'] = 'mutable-tag:latest'
        h.command = mock.Mock()
        with mock.patch.object(gate.tempfile, 'TemporaryDirectory') as directory:
            with self.assertRaises(gate.base.Refusal): h.start_helper()
            directory.assert_not_called()
        h.command.assert_not_called()

    def test_config_refusal_never_starts_helper_and_removes_owned_override(self):
        for output in (None, 'unexpected expanded configuration'):
            h = harness(); calls = []; paths = []
            def command(args, **kw):
                calls.append(args)
                if 'config' in args:
                    paths.append(Path(args[len(gate.base.COMPOSE)+1]))
                    if output is None: raise gate.base.Refusal()
                    return output
                return ''
            h.command = command
            with self.assertRaises(gate.base.Refusal): h.start_helper()
            self.assertTrue(paths)
            self.assertTrue(all(not path.exists() for path in paths))
            self.assertFalse(any('run' in args for args in calls))

    def test_failed_helper_start_removes_only_its_private_override(self):
        h = harness(); paths = []
        def command(args, **kw):
            if 'run' in args:
                paths.append(Path(args[len(gate.base.COMPOSE)+1]))
                raise gate.base.Refusal()
            return ''
        h.command = command
        with self.assertRaises(gate.base.Refusal): h.start_helper()
        self.assertEqual(len(paths), 1)
        self.assertFalse(paths[0].exists())

    def test_helper_identity_refuses_foreign_owner_image_or_mount(self):
        h = harness()
        mounts = [{'Destination': '/worker/'+name.removeprefix('python/'), 'Source': str(path.resolve()), 'Type': 'bind', 'RW': False} for name, path in gate.OVERLAYS.items()]
        value = {**h.helper, 'mounts': mounts, 'autoRemove': True, 'restart': 'no'}
        def admit(candidate):
            h.command = mock.Mock(side_effect=[h.helper['id'], json.dumps(candidate)])
            return h.helper_identity()
        self.assertEqual(admit(value), h.helper)
        for candidate in [{**value, 'owner': 'foreign'}, {**value, 'image': 'sha256:'+'9'*64},
                          {**value, 'autoRemove': False}, {**value, 'restart': 'unless-stopped'},
                          {**value, 'mounts': [*mounts, mounts[0]]},
                          {**value, 'mounts': [{**mounts[0], 'RW': True}, mounts[1]]},
                          {**value, 'mounts': [{**mounts[0], 'Source': '/unrelated'}, mounts[1]]},
                          {**value, 'mounts': [*mounts, {'Destination': '/worker/foreign'}]}]:
            with self.assertRaises(gate.base.Refusal): admit(candidate)

    def test_helper_cleanup_removes_only_verified_id_and_handles_prior_auto_removal(self):
        h = harness()
        h.helper_identity = mock.Mock(side_effect=[h.helper, None])
        h.command = mock.Mock(return_value='')
        h.cleanup_helper()
        h.command.assert_called_once_with(['docker', 'rm', '--force', '4'*64], seconds=20, cleanup=True)
        h.helper_identity = mock.Mock(return_value=None)
        h.command.reset_mock()
        h.cleanup_helper()
        h.command.assert_not_called()

    def test_exact_measurement_validator_rejects_values_wrong_oracle_and_hash(self):
        validate = embedded()['measurement']
        expected = (6,1,1,1)
        range_hash = 'd9d1c5de1d8da97b52234be367e92343b365e59e7f3bde85748db969b857d161'
        keys = ('rowCount','nullCount','belowCount','aboveCount')
        value = dict(zip(keys, expected), formatVersion=1, kind='range', strategy='exact-bounded-role-scope',rangeHash=range_hash,
                     observedStartedAt='2026-01-01T00:00:00.000Z', observedFinishedAt='2026-01-01T00:00:00.100Z',
                     elapsedMs=100, sourceVersion='170004', adapterVersion='1', queryTemplate='postgresql-range-v1',
                     estimatedCost=2, estimatedBytes=128)
        self.assertEqual(validate(value, expected, range_hash), value)
        for edit in ({'rows': [-1,11]}, {'keys': ['private']}, {'belowCount': 2}, {'aboveCount': True},
                     {'rangeHash': '0'*64}, {'elapsedMs': 30001}, {'kind': 'reference-allowed-values'}):
            with self.assertRaises(ValueError): validate({**value, **edit}, expected, range_hash)

    def test_closed_worker_response_requires_all_checks_and_original_hashes(self):
        h = harness()
        h.helper_identity = lambda: h.helper
        hashes = gate.source_hashes()
        effective = gate.effective_hashes(hashes)
        value = {'ok': True, 'checks': gate.CHECKS[:-1], 'hashes': effective, 'measurements': [{}]*11, 'plans': [[1, 10]]}
        for edit in ({}, {'checks': []}, {'hashes': {}}, {'measurements': []}, {'plans': []}, {'rawKeys': ['private']}):
            h.command = lambda *args, **kwargs: json.dumps({**value, **edit})
            if not edit: self.assertEqual(h.worker_call('run', {}, hashes), value)
            else:
                with self.assertRaises(gate.base.Refusal): h.worker_call('run', {}, hashes)

    def test_actual_bounded_process_output_and_owned_stall_cleanup(self):
        self.assertEqual(gate.bounded_command([sys.executable, '-c', "print('ok')"], None, 2, gate.ROOT), 'ok')
        for fd, amount in [(1, 65537), (2, 8193)]:
            with self.assertRaises(gate.base.Refusal) as caught:
                gate.bounded_command([sys.executable, '-c', f"import os;os.write({fd},b'x'*{amount})"], None, 2, gate.ROOT)
            self.assertNotIn('xxxxx', str(caught.exception))
        with tempfile.TemporaryDirectory() as folder:
            pidfile = Path(folder)/'pid'
            code = "import os,pathlib,sys,time;pathlib.Path(sys.argv[1]).write_text(str(os.getpid()));time.sleep(20)"
            started = time.monotonic()
            with self.assertRaises(gate.base.Refusal):
                gate.bounded_command([sys.executable, '-c', code, str(pidfile)], None, .3, gate.ROOT)
            self.assertLess(time.monotonic()-started, 3)
            with self.assertRaises(ProcessLookupError): os.kill(int(pidfile.read_text()), 0)

    def test_failure_retains_failed_state_and_checks_canonical_and_catalog_cleanup(self):
        h = mock.Mock()
        h.phase = 'local_admission'
        h.inventory.return_value = {'catalog': 'a'*64, 'types': 'b'*64}
        h.canonical_targets.return_value = {}
        h.canonical_digest.return_value = 'c'*64
        h.targets.return_value = {}
        h.fixture_digest.return_value = {}
        def worker(mode, *_):
            if mode == 'run': raise gate.base.Refusal()
            return {'ok': True}
        h.worker_call.side_effect = worker
        with mock.patch.object(sys, 'argv', [str(RUNNER), '--run-local']), mock.patch.object(gate, 'Harness', return_value=h), mock.patch.object(gate, 'source_hashes', return_value={}), contextlib.redirect_stdout(io.StringIO()) as output:
            result = gate.main()
        self.assertEqual(result, 1)
        self.assertEqual(json.loads(output.getvalue())['phase'], 'real_executor')
        h.cleanup.assert_called_once_with()
        self.assertEqual(h.inventory.call_args_list, [mock.call(), mock.call(cleanup=True)])
        self.assertEqual(h.canonical_digest.call_args_list, [mock.call(), mock.call(cleanup=True)])

    def test_lock_failure_still_cleans_owned_objects_and_helper(self):
        h = harness()
        h.finish_lock = mock.Mock(side_effect=gate.base.Refusal())
        h.cleanup_objects = mock.Mock(side_effect=gate.base.Refusal())
        h.cleanup_helper = mock.Mock()
        with self.assertRaises(gate.base.Refusal): h.cleanup()
        h.cleanup_objects.assert_called_once_with()
        h.cleanup_helper.assert_called_once_with()


if __name__ == '__main__': unittest.main()
