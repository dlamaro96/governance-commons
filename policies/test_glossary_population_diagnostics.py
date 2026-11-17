# SPDX-License-Identifier: Apache-2.0
"""Failure-only projection and actual bounded host subprocess controls; no Docker."""
import ast
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import glossary_population_diagnostics as evidence

ROOT=Path(__file__).resolve().parents[1]
COMMIT='a'*40
FOLDER='.local/evidence/source-connectors-upgrade-20261117T060000-123456abcdef'
TITLE='PRIVATE_SYNTHETIC_TITLE'

class Controls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='gc-population-diagnostic-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        target=self.root/evidence.TEST;target.parent.mkdir(parents=True);target.write_text(f"test('{TITLE}',async()=>{{}});\n")
        self.inventory=lambda root:[{'path':evidence.TEST,'sha256':evidence.digest(evidence.read_file(root,evidence.TEST,1024))}]
        self.patches=[patch.object(evidence,'source_inventory',self.inventory),patch.object(evidence,'suite_files',lambda root,phase:[evidence.TEST] if phase=='population-native-tests' else [])]
        for p in self.patches:p.start();self.addCleanup(p.stop)
        (self.root/FOLDER).mkdir(parents=True)
        self.report={'schema_version':1,'result':'FAIL','commit':COMMIT,'command':evidence.COMMAND,'profile':evidence.PROFILE,
          'started_at':'2026-11-17T06:00:00+00:00','recorded_at':'2026-11-17T06:00:40+00:00','failed_phase':'population-native-tests','evidence_directory':FOLDER,
          'diagnostic_sources':self.inventory(self.root),'failure_diagnostic':{'phase':'population-native-tests','category':'suite_failed','commandLog':None,'elapsedMs':30000},
          'private_logs':[],'cleanup':{'ownedRemoved':True,'resourceInventoryPreserved':True},'privateConfig':'PRIVATE_SECRET'}
        self.timing={'phase':'publication','elapsedMs':30000,'queryCount':1,'omittedQueries':0,'code':'RELATION_RETRY','sqlstate':None,
          'queries':[{'phase':'publication','query':'stage','startedMs':15000,'elapsedMs':14999,'outcome':'rejected','sqlstate':'57014'}]}
        self.write(self.raw())
    def raw(self):
        return f'phase=population-native-tests\nexit=1\nTAP version 13\nnot ok 1 - {TITLE}\n  ---\n  error: |-\n    Population qualification failed; diagnostic\n    '+evidence.TIMING_MARKER+json.dumps(self.timing,separators=(',',':'))+'\n  stack: |-\n    PRIVATE_STACK_SQL_SECRET\n  ...\n1..1\n# tests 1\n'+evidence.MARKER+'suite_failed\n'
    def write(self,text):
        name=FOLDER+'/001-population-native-tests.log';(self.root/name).write_text(text)
        row={'path':name,'sha256':evidence.digest(text.encode())};self.report['private_logs']=[row];self.report['failure_diagnostic']['commandLog']=dict(row)
    def result(self):return evidence.safe_report(self.root,self.report,COMMIT)
    def test_only_closed_failure_data_and_exact_source_coordinates_survive(self):
        result=self.result();self.assertIsNotNone(result);self.assertEqual(result['outcome'],'NOT_PASSED');self.assertEqual(result['purpose'],'FAILURE_DIAGNOSTIC_ONLY')
        self.assertEqual(result['tests'],[{'file':evidence.TEST,'line':1,'status':'failed'}]);self.assertEqual(result['population_timings'][0]['queries'][0]['sqlstate'],'57014')
        for forbidden in ('PRIVATE_',TITLE,'commandLog','.local/','password','error:'):self.assertNotIn(forbidden,json.dumps(result))
    def test_success_other_commit_or_changed_source_is_never_qualified(self):
        for field,value in [('result','PASS'),('commit','b'*40),('command','other'),('profile','other')]:
            before=self.report[field];self.report[field]=value;self.assertIsNone(self.result());self.report[field]=before
        (self.root/evidence.TEST).write_text('changed');self.assertIsNone(self.result())
    def test_log_tamper_symlink_and_marker_mismatch_refuse(self):
        name=self.report['private_logs'][0]['path'];p=self.root/name;p.write_text(p.read_text()+'tamper');self.assertIsNone(self.result());self.write(self.raw())
        original=p.read_text();p.unlink();p.symlink_to(self.root/evidence.TEST);self.assertIsNone(self.result());p.unlink();self.write(original)
        for text in (original.replace(evidence.MARKER+'suite_failed','unknown'),original.replace('exit=1','exit=0'),original+evidence.MARKER+'suite_failed\n'):
            self.write(text);self.assertIsNone(self.result())
    def test_transitive_source_import_cannot_hide_a_symlink_by_normalizing_it(self):
        from types import SimpleNamespace
        main=self.root/'main.ts';main.write_text("import './linked.ts';\n")
        target=self.root/'target.ts';target.write_text('export const value=1;\n')
        link=self.root/'linked.ts';link.symlink_to(target)
        original=self.patches[0];original.stop()
        try:
            with patch.object(evidence,'FIXED',('main.ts',)),patch.object(evidence,'predecessor',lambda root:SimpleNamespace(sources=lambda:[])):
                with self.assertRaises(ValueError):evidence.source_inventory(self.root)
                link.unlink();link.write_text(target.read_text());self.assertEqual(len(evidence.source_inventory(self.root)),2)
        finally:original.start()
    def test_success_skipped_and_unknown_titles_do_not_supply_diagnostics(self):
        for old,new in [('not ok 1','ok 1'),(TITLE,TITLE+' # SKIP synthetic'),(TITLE,'PRIVATE_UNKNOWN_TITLE')]:
            self.write(self.raw().replace(old,new));result=self.result();self.assertIsNotNone(result);self.assertEqual(result['population_timings'],[])
    def test_phase_marker_outside_failed_error_or_with_extra_fields_refuses(self):
        self.write(self.raw().replace('  error: |-','  arbitrary: |-'));self.assertIsNone(self.result())
        self.timing['private']='PRIVATE_VALUE';self.write(self.raw());self.assertIsNone(self.result())
    def test_unknown_codes_bad_timing_and_truncation_are_not_accepted(self):
        for field,value in [('phase','PRIVATE'),('code','PRIVATE'),('sqlstate','ABCDE'),('elapsedMs',-1),('omittedQueries',1),('queryCount',True)]:
            original=self.timing[field];self.timing[field]=value;self.write(self.raw());self.assertIsNone(self.result());self.timing[field]=original
        self.timing['queries'][0]['sqlstate']='PRIVATE';self.write(self.raw());self.assertIsNone(self.result())
    def test_timeout_without_tap_keeps_unknown_cause_and_unobserved_test(self):
        self.report['failure_diagnostic']['category']='command_timeout';self.write('phase=population-native-tests\nexit=-9\n'+evidence.MARKER+'command_timeout\n')
        result=self.result();self.assertEqual(result['exit_code'],-9);self.assertEqual(result['tests'][0]['status'],'not_observed');self.assertEqual(result['population_timings'],[])
    def test_actual_bounded_process_failure_preserves_phase_across_cleanup(self):
        spec=importlib.util.spec_from_file_location('population_test_runner',ROOT/'scripts/runtime-test-glossary-population-upgrade.py');runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
        for timeout in (False,True):
            with patch.object(runner,'ROOT',self.root):
                h=runner.Harness.__new__(runner.Harness);h.folder=self.root/FOLDER;h.serial=10;h.phase='population-native-tests';h.deadline=time.monotonic()+10;h.cleanup_deadline=None
                h.output_bytes=0;h.private_values=[];h.last_command=None;h.command_failure=None;h.report={};h.admission=lambda:None
                with self.assertRaises(RuntimeError) as caught:h.command([sys.executable,'-c','import time;time.sleep(2)' if timeout else 'raise SystemExit(3)'],timeout=.03 if timeout else 2)
                h.phase='cleanup';h.command([sys.executable,'-c','pass'],timeout=2);h.remember_failure(caught.exception)
                failure=h.report['failure_diagnostic'];self.assertEqual(failure['phase'],'population-native-tests');self.assertEqual(failure['category'],'command_timeout' if timeout else 'command_failed');self.assertGreaterEqual(failure['elapsedMs'],0)
    def test_collector_exports_only_failed_or_cancelled_stage_and_never_qualifies_success(self):
        tree=ast.parse((ROOT/'policies/ci_evidence.py').read_text());start=next(i for i,n in enumerate(tree.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='population_diagnostic' for t in n.targets))
        code=compile(ast.fix_missing_locations(ast.Module(body=tree.body[start:start+3],type_ignores=[])),'actual-collector-block','exec')
        import os
        for outcome in ('success','failure','cancelled','skipped'):
            dest=self.root/('artifact-'+outcome);dest.mkdir();report={'outcome':'PASS'}
            env={'load_population_diagnostic':lambda *args:self.result(),'ROOT':self.root,'os':os,'outcomes':{'glossary_population_upgrade':outcome},'DEST':dest,'report':report,'json':json}
            exec(code,env);self.assertEqual((dest/'glossary-population-diagnostic.json').exists(),outcome in ('failure','cancelled'))
            if outcome=='success':self.assertEqual(report['outcome'],'NOT_PASSED')
    def test_actual_node_failed_tap_is_accepted_without_message_reflection(self):
        import shutil
        node=shutil.which('node');self.assertIsNotNone(node)
        target=ROOT/'.local/population-diagnostic-host-failure.test.ts';target.parent.mkdir(exist_ok=True)
        helper=(ROOT/'tests/fixtures/glossary-population-diagnostic.ts').as_uri()
        target.write_text("import test from 'node:test';import {observePopulationPool} from "+json.dumps(helper)+";test("+json.dumps(TITLE)+",async()=>{const o=observePopulationPool({options:{},end:async()=>{},connect:async()=>({query:async()=>{throw Object.assign(new Error('PRIVATE_DRIVER'),{code:'57014'})},release(){}})});const c=await o.pool.connect();o.phase('publication');try{await c.query('PRIVATE_SQL',[])}catch(e){throw o.failure(e)}});\n")
        self.addCleanup(lambda:target.unlink(missing_ok=True))
        run=subprocess.run([node,'--import','tsx','--test','--test-reporter=tap',str(target)],cwd=ROOT,capture_output=True,text=True,timeout=10)
        self.assertEqual(run.returncode,1);self.write('phase=population-native-tests\nexit=1\n'+run.stdout+evidence.MARKER+'suite_failed\n')
        result=self.result();self.assertIsNotNone(result);self.assertEqual(result['population_timings'][0]['queries'][-1]['sqlstate'],'57014');self.assertNotIn('PRIVATE_',json.dumps(result))

if __name__=='__main__':unittest.main()
