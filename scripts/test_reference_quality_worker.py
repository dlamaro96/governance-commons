#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host-only controls; these do not qualify PostgreSQL or execute Docker."""
import ast
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

RUNNER = Path(__file__).with_name('runtime-test-reference-quality-worker.py')
spec = importlib.util.spec_from_file_location('reference_worker_controls', RUNNER)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def harness():
    h = gate.Harness()
    h.source = {'id': '1'*64}
    h.worker = {'id': '2'*64}
    h.owned = {name: {'oid': str(20000+i), 'owner':'source_admin', 'marker':h.marker}
               for i,name in enumerate(h.names.values())}
    h.domain_oid = '30000'
    return h


def embedded_functions():
    tree = ast.parse(gate.WORKER)
    nodes = [n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('require','binding','measurement')]
    scope = {'hashlib':hashlib,'json':json,'re':re,'datetime':datetime,'math':math}
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<embedded-controls>','exec'),scope)
    return scope


class WorkerControls(unittest.TestCase):
    def test_01_opt_in_refuses_before_runtime(self):
        with mock.patch.object(sys,'argv',[str(RUNNER)]), mock.patch.object(gate,'Harness') as constructor, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised: gate.main()
        self.assertEqual(raised.exception.code,2)
        constructor.assert_not_called()

    def test_02_sources_include_actual_baseline_and_runner(self):
        hashes=gate.source_hashes()
        for path in ('scripts/runtime-test-quality-worker.py','python/governance_workers/quality.py',str(RUNNER.relative_to(gate.ROOT))):
            self.assertEqual(hashes[path],hashlib.sha256((gate.ROOT/path).read_bytes()).hexdigest())
        self.assertEqual(len(gate.CHECKS),16)
        self.assertEqual(len(set(gate.CHECKS)),16)

    def test_03_real_fixture_sql_has_independent_exact_byte_oracle(self):
        h=harness();statements=[]
        owned={'tables':h.owned,'domain':{'oid':h.domain_oid,'owner':'source_admin','marker':h.marker}}
        h.sql=lambda text,**kw: statements.append(text) or json.dumps(owned)
        h.prepare();text=statements[0]
        self.assertTrue(text.startswith('BEGIN;'))
        self.assertTrue(text.endswith('COMMIT;'))
        self.assertEqual(text.count('CREATE TABLE'),11)
        self.assertIn(f'INHERITS (public."{h.names["parent"]}")',text)
        self.assertIn('varchar(256)',text)
        self.assertIn('char(8)',text)
        self.assertIn('ENABLE ROW LEVEL SECURITY',text)
        self.assertIn("generate_series(0,256)",text)
        self.assertIn("repeat('x',125)",text)
        inserts=[line for line in text.splitlines() if line.startswith('INSERT INTO') and 'decode(' in line]
        self.assertEqual(len(inserts),2)
        for insert in inserts:
            values=[bytes.fromhex(x).decode('utf-8') for x in re.findall(r"decode\('([a-f0-9]*)','hex'\)",insert)]
            self.assertEqual(values,['01','1','A','a',' A','A ','A\t','A\n','','é','e\u0301','١','001'])
            self.assertEqual(sum(v not in {'01','1','A','a'} for v in values),9)
            self.assertEqual(sum(v not in {'A'} for v in values),12)
            self.assertEqual(sum(v not in set() for v in values),13)
            self.assertEqual(insert.count('(NULL)'),1)

    def test_04_cleanup_exact_oid_marker_and_dependency_order(self):
        h=harness();calls=[]
        h.sql=lambda text,**kw: calls.append((text,kw)) or ('0' if text.startswith('SELECT ') else '')
        h.cleanup_objects();text=calls[0][0]
        self.assertLess(text.index(f'DROP TABLE public."{h.names["child"]}"'),text.index(f'DROP TABLE public."{h.names["parent"]}"'))
        self.assertGreater(text.index('DROP DOMAIN'),text.rindex('DROP TABLE'))
        self.assertNotIn('CASCADE',text)
        for name,pin in h.owned.items():
            self.assertIn(f"c.relname='{name}'",text)
            self.assertIn(f"c.oid={pin['oid']}::oid",text)
        self.assertIn(f"obj_description(t.oid,'pg_type')='{h.marker}'",text)
        self.assertIn(f't.oid={h.domain_oid}::oid',text)
        self.assertIn("r.rolname='source_admin'",text)
        self.assertTrue(all(kw=={'cleanup':True} for _,kw in calls))

    def test_05_untrusted_cleanup_name_refused_without_sql(self):
        h=harness();h.names['child']='foreign_table';h.sql=mock.Mock()
        with self.assertRaises(gate.base.Refusal):h.cleanup_objects()
        h.sql.assert_not_called()

    def test_06_lost_commit_cleanup_still_requires_exact_marker_owner(self):
        h=harness();h.owned={};h.domain_oid=None;calls=[]
        h.sql=lambda text,**kw:calls.append(text) or ('0' if text.startswith('SELECT ') else '')
        h.cleanup_objects();text=calls[0]
        self.assertEqual(text.count('Fixture ownership mismatch'),12)
        self.assertEqual(text.count("r.rolname='source_admin'"),12)
        self.assertEqual(text.count("='"+h.marker+"'"),12)

    def test_07_measurement_schema_and_binding_reject_extra_values(self):
        funcs=embedded_functions();pin=funcs['binding'](['01','A'])
        self.assertEqual(pin['bindingHash'],hashlib.sha256(b'{"asOf":"2026-01-01T00:00:00.000Z","codeStatus":"active","codes":["01","A"],"publicationHash":"'+b'a'*64+b'","setId":"70000000-0000-4000-8000-000000000099","version":1}').hexdigest())
        value={'formatVersion':1,'kind':'reference-allowed-values','strategy':'exact-bounded-role-scope','rowCount':14,'nullCount':1,'invalidCount':9,'referenceBindingHash':pin['bindingHash'],'observedStartedAt':'2026-01-01T00:00:00.000Z','observedFinishedAt':'2026-01-01T00:00:00.100Z','elapsedMs':100,'sourceVersion':'170004','adapterVersion':'1','queryTemplate':'postgresql-reference-allowed-values-v1','estimatedCost':2.0,'estimatedBytes':128}
        check=funcs['measurement'];self.assertEqual(check(value,14,1,9,pin['bindingHash']),value)
        for edit in ({'rows':['private-row']},{'codes':['private-code']},{'invalidCount':8},{'rowCount':True},{'referenceBindingHash':'b'*64},{'elapsedMs':30001}):
            with self.subTest(edit=next(iter(edit))),self.assertRaises(ValueError):check({**value,**edit},14,1,9,pin['bindingHash'])

    def test_08_worker_result_cannot_omit_checks_or_source_bindings(self):
        h=harness();hashes={'python/governance_workers/quality.py':'a'*64}
        def response(value):h.command=lambda *a,**kw:json.dumps(value)
        valid={'ok':True,'checks':gate.CHECKS[:-1],'hashes':hashes,'measurements':[{}]*10}
        response(valid);self.assertEqual(h.worker_call('run',{},hashes),valid)
        for edit in ({'checks':[]},{'hashes':{}},{'measurements':[]},{'ok':False}):
            response({**valid,**edit})
            with self.subTest(edit=next(iter(edit))),self.assertRaises(gate.base.Refusal):h.worker_call('run',{},hashes)

    def test_09_actual_bounded_streams_and_no_diagnostic_echo(self):
        self.assertEqual(gate.bounded_command([sys.executable,'-c',"print('ok')"],None,2,gate.ROOT),'ok')
        for fd,size in ((1,65537),(2,8193)):
            with self.subTest(fd=fd),self.assertRaises(gate.base.Refusal) as raised:
                gate.bounded_command([sys.executable,'-c',f"import os;os.write({fd},b'private-sentinel'*{size})"],None,2,gate.ROOT)
            self.assertNotIn('private-sentinel',str(raised.exception))

    def test_10_actual_stalled_owned_process_is_killed_and_reaped(self):
        with tempfile.TemporaryDirectory() as folder:
            pidfile=Path(folder)/'pid'
            code="import os,pathlib,sys,time;pathlib.Path(sys.argv[1]).write_text(str(os.getpid()));time.sleep(20)"
            start=time.monotonic()
            with self.assertRaises(gate.base.Refusal):gate.bounded_command([sys.executable,'-c',code,str(pidfile)],None,.3,gate.ROOT)
            self.assertLess(time.monotonic()-start,3)
            self.assertTrue(pidfile.exists())
            with self.assertRaises(ProcessLookupError):os.kill(int(pidfile.read_text()),0)

    def test_11_failure_preserves_failure_and_calls_cleanup_inventory(self):
        h=mock.Mock();h.worker={};h.source={};h.phase='local_admission';h.inventory.return_value={'catalog':'a'*64,'types':'b'*64}
        h.targets.return_value={};h.fixture_digest.return_value={}
        def worker(mode,*_):
            if mode=='run':raise gate.base.Refusal()
            return {'ok':True}
        h.worker_call.side_effect=worker
        with mock.patch.object(sys,'argv',[str(RUNNER),'--run-local']),mock.patch.object(gate,'Harness',return_value=h),mock.patch.object(gate,'source_hashes',return_value={}),contextlib.redirect_stdout(io.StringIO()) as output:
            result=gate.main()
        self.assertEqual(result,1)
        self.assertEqual(json.loads(output.getvalue())['phase'],'real_executor')
        h.cleanup.assert_called_once_with()
        self.assertEqual(h.inventory.call_args_list,[mock.call(),mock.call(cleanup=True)])

    def test_12_lock_failure_still_cleans_objects_and_uses_remote_deadline(self):
        h=harness();h.finish_lock=mock.Mock(side_effect=gate.base.Refusal());h.cleanup_objects=mock.Mock()
        with self.assertRaises(gate.base.Refusal):h.cleanup()
        h.cleanup_objects.assert_called_once_with()
        child=mock.Mock();child.poll.return_value=None
        h.await_lock=mock.Mock()
        with mock.patch.object(gate.subprocess,'Popen',return_value=child) as spawn:
            h.start_lock()
        args=spawn.call_args.args[0]
        self.assertIn('14s',args);self.assertIn('--kill-after=2s',args)
        self.assertTrue(spawn.call_args.kwargs['start_new_session'])
        _,input_file=h.lock_owner
        input_file.seek(0);sql=input_file.read().decode();input_file.close();h.lock_owner=None
        self.assertIn('pg_sleep(8)',sql)
        self.assertIn('ACCESS EXCLUSIVE MODE',sql)
        self.assertTrue(sql.endswith('ROLLBACK;'))


if __name__=='__main__':unittest.main()
