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

RUNNER = Path(__file__).with_name('runtime-test-volume-quality-worker.py')
spec = importlib.util.spec_from_file_location('volume_worker_gate_controls', RUNNER)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def harness():
    h = gate.Harness()
    h.source = {'id': '1'*64}
    h.worker = {'id': '2'*64, 'image': 'sha256:'+'3'*64}
    h.helper = {'id': '4'*64, 'image': h.worker['image'], 'owner': h.marker, 'running': True}
    h.owned = {name: {'oid': str(20000+i), 'owner': 'source_admin', 'marker': h.marker, 'kind': {'view':'v','materialized':'m','partition':'p'}.get(kind,'r')} for i, (kind,name) in enumerate(h.names.items())}
    return h


class Controls(unittest.TestCase):
    def test_fixed_public_layout_and_exact_source_mapping(self):
        self.assertEqual(gate.ROOT, RUNNER.resolve().parents[1])
        self.assertEqual(gate.CANDIDATE, gate.ROOT)
        self.assertEqual(gate.WORKER_PATH, gate.ROOT / 'scripts/volume_quality_worker_program.py')
        self.assertEqual(gate.OVERLAYS, {name: gate.ROOT/name for name in (
            'python/governance_workers/quality.py', 'python/governance_workers/server.py')})
        hashes=gate.source_hashes()
        effective=gate.effective_hashes(hashes)
        for name in gate.OVERLAYS:
            self.assertEqual(effective[name], hashes[name])
        self.assertIn('scripts/runtime-test-volume-quality-worker.py', hashes)
        self.assertIn('scripts/volume_quality_worker_program.py', hashes)
        self.assertFalse(any('.local/' in name for name in hashes))

    def test_opt_in_before_any_runtime_or_source_read(self):
        with mock.patch.object(sys, 'argv', [str(RUNNER)]), mock.patch.object(gate, 'Harness') as constructor, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as caught:
                gate.main()
        self.assertEqual(caught.exception.code, 2)
        constructor.assert_not_called()

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

    def test_closed_worker_response_requires_all_checks_and_original_hashes(self):
        h = harness()
        h.helper_identity = lambda: h.helper
        hashes = gate.source_hashes()
        effective = gate.effective_hashes(hashes)
        value = {'ok': True, 'checks': gate.CHECKS[:-1], 'hashes': effective, 'measurements': [{}]*8, 'plans': [[1, 10]]}
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

    def test_lock_failure_still_cleans_owned_objects_and_helper(self):
        h = harness()
        h.finish_lock = mock.Mock(side_effect=gate.base.Refusal())
        h.cleanup_objects = mock.Mock(side_effect=gate.base.Refusal())
        h.cleanup_helper = mock.Mock()
        with self.assertRaises(gate.base.Refusal): h.cleanup()
        h.cleanup_objects.assert_called_once_with()
        h.cleanup_helper.assert_called_once_with()

    def test_checkout_effective_and_program_sources_are_measured_separately(self):
        values=gate.source_hashes();effective=gate.effective_hashes(values)
        for name,path in gate.OVERLAYS.items():
            self.assertEqual(values[name],hashlib.sha256((gate.ROOT/name).read_bytes()).hexdigest())
            self.assertEqual(effective[name],hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(values[str(RUNNER.relative_to(gate.ROOT))],hashlib.sha256(RUNNER.read_bytes()).hexdigest())
        self.assertEqual(values[str(gate.WORKER_PATH.relative_to(gate.ROOT))],hashlib.sha256(gate.WORKER_PATH.read_bytes()).hexdigest())
        self.assertEqual(gate.CANDIDATE,RUNNER.resolve().parents[1])
        self.assertEqual(gate.ROOT,RUNNER.resolve().parents[1])
        self.assertEqual(gate.WORKER_PATH,RUNNER.with_name('volume_quality_worker_program.py'))

    def test_owned_fixture_shape_and_static_counts(self):
        h=harness();statements=[]
        h.sql=lambda text,**kw:statements.append(text) or json.dumps(h.owned)
        h.prepare();text=statements[0]
        self.assertEqual(text.count('CREATE TABLE'),13)
        self.assertEqual(text.count('CREATE VIEW'),1)
        self.assertEqual(text.count('CREATE MATERIALIZED VIEW'),1)
        self.assertIn('generate_series(1,100000)',text)
        self.assertIn('generate_series(1,100001)',text)
        self.assertIn('FORCE ROW LEVEL SECURITY',text)
        self.assertIn('GRANT SELECT(amount)',text)
        self.assertNotIn('volume_quality_fixture',text)
        for line in text.splitlines():
            if line.startswith(('INSERT INTO','ALTER TABLE','GRANT SELECT','REVOKE ALL','REFRESH MATERIALIZED')):
                self.assertTrue(any('"'+n+'"' in line for n in h.names.values()))
        tree=ast.parse(gate.WORKER);main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
        expected=ast.literal_eval(next(n.value for n in main.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='expected' for t in n.targets)))
        self.assertEqual(expected,[('six',6,0,5,'FAIL'),('six',6,6,6,'PASS'),('six',6,7,7,'FAIL'),
            ('empty',0,0,0,'PASS'),('empty',0,1,1,'FAIL'),('limit',100000,100000,100000,'PASS'),
            ('wide',6,6,6,'PASS'),('six',6,0,100000,'PASS')])

    def test_table_target_discovery_does_not_load_or_fake_a_column(self):
        h=harness();statements=[]
        records={name:{'kind':'table','databaseOid':'42','schemaOid':'43','relationOid':pin['oid'],
                       'schemaName':'public','tableName':name} for name,pin in h.owned.items()}
        h.sql=lambda text,**kw:statements.append(text) or json.dumps(records)
        targets=h.targets();self.assertEqual(set(targets),set(gate.KINDS))
        self.assertTrue(all(set(t)=={'kind','databaseOid','schemaOid','relationOid','schemaName','tableName'} for t in targets.values()))
        self.assertNotIn('pg_attribute',statements[0]);self.assertNotIn('format_type',statements[0])
        records[h.names['six']]['relationOid']='1'
        with self.assertRaises(gate.base.Refusal):h.targets()

    def test_cleanup_checks_oid_owner_marker_kind_and_dependency_order_without_cascade(self):
        h=harness();statements=[]
        h.sql=lambda text,**kw:statements.append((text,kw)) or ('0' if text.startswith('SELECT ') else '')
        h.cleanup_objects();text=statements[0][0]
        self.assertEqual(text.count('Fixture ownership mismatch'),15)
        self.assertNotIn('CASCADE',text)
        self.assertLess(text.index('DROP TABLE public."'+h.names['child']),text.index('DROP TABLE public."'+h.names['parent']))
        self.assertLess(text.index('DROP TABLE public."'+h.names['leaf']),text.index('DROP TABLE public."'+h.names['partition']))
        self.assertLess(text.index('DROP VIEW'),text.index('DROP TABLE public."'+h.names['six']))
        self.assertLess(text.index('DROP MATERIALIZED VIEW'),text.index('DROP TABLE public."'+h.names['six']))
        for name,pin in h.owned.items():
            self.assertIn("c.relname='"+name+"'",text);self.assertIn('c.oid='+pin['oid']+'::oid',text)
            self.assertIn("c.relkind='"+pin['kind']+"'",text)
        self.assertTrue(all(kw=={'cleanup':True} for _,kw in statements))

    def test_check_inventory_matches_declared_native_checks_without_unsupported_claims(self):
        self.assertEqual(len(gate.CHECKS),15);self.assertEqual(len(set(gate.CHECKS)),15)
        tree=ast.parse(gate.WORKER)
        lists=[ast.literal_eval(n) for n in ast.walk(tree) if isinstance(n,ast.List) and all(isinstance(e,ast.Constant) and isinstance(e.value,str) for e in n.elts)]
        self.assertIn(gate.CHECKS[:-1],lists);self.assertIn(gate.CHECKS[-1:],lists)
        self.assertIn('return execute(source,secret',gate.WORKER)
        self.assertIn("limited['budget'][field]=cap;refused",gate.WORKER)
        self.assertNotIn('quality.execute=',gate.WORKER)
        self.assertNotIn('quality._estimates=',gate.WORKER)

    def test_native_measurement_closed_count_hash_threshold_and_time_oracle(self):
        tree=ast.parse(gate.WORKER)
        nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('require','binding','measurement')]
        scope={'re':re,'datetime':datetime,'math':math,'json':json,'hashlib':hashlib}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'<native-controls>','exec'),scope)
        bound=scope['binding']()
        self.assertEqual(bound['volumeHash'],'3b2199a5b4d34da6e2408b6fe7f6158434cad02517ee08b2c24ad06551a51219')
        value={'formatVersion':1,'kind':'volume','strategy':'exact-bounded-role-scope','rowCount':6,
          'volumeHash':bound['volumeHash'],'observedStartedAt':'2026-01-01T00:00:01.000Z','observedFinishedAt':'2026-01-01T00:00:01.100Z',
          'elapsedMs':100,'sourceVersion':'170004','adapterVersion':'1','queryTemplate':'postgresql-volume-v1','estimatedCost':2,'estimatedBytes':128}
        self.assertEqual(scope['measurement'](value,6,bound),'FAIL')
        for low,high,rows,want in [(6,6,6,'PASS'),(7,7,6,'FAIL'),(0,0,0,'PASS'),(1,1,0,'FAIL')]:
            b=scope['binding'](low,high)
            self.assertEqual(scope['measurement']({**value,'rowCount':rows,'volumeHash':b['volumeHash']},rows,b),want)
        for changes in [{'rowCount':True},{'rowCount':6.0},{'rowCount':5},{'volumeHash':'0'*64},
                        {'nullCount':6},{'rawRows':['private']},{'columnName':'private'},
                        {'observedFinishedAt':'2026-01-01T00:00:00.000Z'},{'elapsedMs':30001}]:
            with self.assertRaises(ValueError):scope['measurement']({**value,**changes},6,bound)

    def test_failed_native_program_retains_failure_and_inventory_cleanup(self):
        h=mock.Mock();h.phase='local_admission';h.inventory.return_value={'catalog':'a'*64,'types':'b'*64}
        h.targets.return_value={};h.fixture_digest.return_value={}
        def worker(mode,*_):
            if mode=='run':raise gate.base.Refusal()
            return {'ok':True}
        h.worker_call.side_effect=worker
        with mock.patch.object(sys,'argv',[str(RUNNER),'--run-local']),mock.patch.object(gate,'Harness',return_value=h),mock.patch.object(gate,'source_hashes',return_value={}),contextlib.redirect_stdout(io.StringIO()) as output:
            result=gate.main()
        self.assertEqual(result,1);self.assertEqual(json.loads(output.getvalue())['phase'],'real_executor')
        h.cleanup.assert_called_once_with()
        self.assertEqual(h.inventory.call_args_list,[mock.call(),mock.call(cleanup=True)])


if __name__=='__main__':unittest.main()
