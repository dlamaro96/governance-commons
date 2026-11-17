# SPDX-License-Identifier: Apache-2.0
"""Failure-only evidence controls; actual local subprocesses, never Docker."""
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
import quality_upgrade_diagnostics as evidence

ROOT=Path(__file__).resolve().parents[1]
COMMIT='a'*40
FOLDER='.local/evidence/source-connectors-upgrade-20261117T060000-123456abcdef'
TITLE='PRIVATE_SYNTHETIC_TITLE'

class Controls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='gc-quality-diagnostic-');self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        target=self.root/evidence.TEST;target.parent.mkdir(parents=True);target.write_text(f"test('{TITLE}',async()=>{{}});\n")
        self.inventory=lambda root:[{'path':evidence.TEST,'sha256':evidence.digest(evidence.read_file(root,evidence.TEST,1024))}]
        for p in (patch.object(evidence,'source_inventory',self.inventory),patch.object(evidence,'suite_files',lambda root,phase:[evidence.TEST] if phase=='quality-native-tests' else [])):
            p.start();self.addCleanup(p.stop)
        (self.root/FOLDER).mkdir(parents=True)
        self.report={'schema_version':1,'result':'FAIL','commit':COMMIT,'command':evidence.COMMAND,'profile':evidence.PROFILE,
          'started_at':'2026-11-17T06:00:00+00:00','recorded_at':'2026-11-17T06:00:40+00:00','failed_phase':'quality-native-tests','evidence_directory':FOLDER,
          'quality_diagnostic_sources':self.inventory(self.root),'failure_diagnostic':{'phase':'quality-native-tests','category':'suite_failed','commandLog':None,'elapsedMs':30000},
          'private_logs':[],'cleanup':{'ownedRemoved':True,'resourceInventoryPreserved':True},'privateConfig':'PRIVATE_SECRET'}
        self.write(self.raw())
    def raw(self):
        return f'phase=quality-native-tests\nexit=1\nTAP version 13\nnot ok 1 - {TITLE}\n  ---\n  duration_ms: 1\n  error: PRIVATE_SQL_VALUES_SECRET\n  code: \'ERR_ASSERTION\'\n  stack: |-\n    PRIVATE_STACK\n  ...\n1..1\n# tests 1\n# suites 0\n# pass 0\n# fail 1\n# cancelled 0\n# skipped 0\n# todo 0\n'+evidence.MARKER+'suite_failed\n'
    def write(self,text,ordinal=1,phase='quality-native-tests'):
        name=f'{FOLDER}/{ordinal:03d}-{phase}.log';(self.root/name).write_text(text)
        row={'path':name,'sha256':evidence.digest(text.encode())};self.report['private_logs']=[row];self.report['failure_diagnostic']['commandLog']=dict(row)
    def result(self):return evidence.safe_report(self.root,self.report,COMMIT)
    def test_validated_failure_projection_excludes_every_raw_field(self):
        result=self.result();self.assertIsNotNone(result);self.assertEqual(result['outcome'],'NOT_PASSED');self.assertEqual(result['purpose'],'FAILURE_DIAGNOSTIC_ONLY')
        self.assertEqual(result['counts_state'],'COMPLETE');self.assertEqual(result['tap_counts']['fail'],1)
        self.assertEqual(result['tests'],[{'file':evidence.TEST,'line':1,'status':'failed','classification':'ASSERTION_FAILURE'}])
        for forbidden in ('PRIVATE_',TITLE,'.local/','commandLog','error:','stack:'):self.assertNotIn(forbidden,json.dumps(result))
    def test_exact_command_commit_source_and_capture_status_are_required(self):
        for field,value in [('result','PASS'),('commit','b'*40),('command','./dev test --suite glossary-population-upgrade'),('profile','other'),('quality_diagnostic_capture','UNAVAILABLE')]:
            old=copy.deepcopy(self.report);self.report[field]=value;self.assertIsNone(self.result());self.report=old
        (self.root/evidence.TEST).write_text('changed');self.assertIsNone(self.result())
    def test_selected_log_hash_symlink_path_duplicate_and_marker_tampering_refuse(self):
        name=self.report['private_logs'][0]['path'];path=self.root/name
        path.write_text(path.read_text()+'changed');self.assertIsNone(self.result());self.write(self.raw())
        path.unlink();path.symlink_to(self.root/evidence.TEST);self.assertIsNone(self.result());path.unlink();self.write(self.raw())
        original=copy.deepcopy(self.report)
        for mutate in (lambda: self.report['private_logs'].append(dict(self.report['private_logs'][0])),
                       lambda: self.report['failure_diagnostic'].update(extra='PRIVATE'),
                       lambda: self.report['failure_diagnostic']['commandLog'].update(path='/PRIVATE'),
                       lambda: self.report['failure_diagnostic'].update(phase='PRIVATE')):
            mutate();self.assertIsNone(self.result());self.report=copy.deepcopy(original)
        for text in (self.raw().replace('exit=1','exit=0'),self.raw().replace(evidence.MARKER+'suite_failed','unknown'),self.raw()+evidence.MARKER+'suite_failed\n'):
            self.write(text);self.assertIsNone(self.result())
    def test_missing_duplicate_overflow_and_inconsistent_totals_stay_unavailable(self):
        for text in (self.raw().replace('# fail 1\n',''),self.raw().replace('# tests 1\n','# tests 1\n# tests 1\n'),
                     self.raw().replace('# fail 1','# fail 999999'),self.raw().replace('# pass 0','# pass 1'),
                     self.raw().replace('1..1','1..2'),self.raw().replace('1..1','1..1\n1..invalid'),self.raw().replace('# fail 1','# fail -1'),self.raw().replace('# tests 1','# tests 1\n# tests -1')):
            self.write(text);result=self.result();self.assertIsNotNone(result);self.assertIsNone(result['tap_counts']);self.assertEqual(result['counts_state'],'UNAVAILABLE_OR_INVALID')
    def test_unknown_duplicate_or_skipped_titles_cannot_claim_known_failure(self):
        self.write(self.raw().replace(TITLE,'PRIVATE_UNKNOWN'))
        result=self.result();self.assertTrue(result['unmapped_test_output']);self.assertEqual(result['tests'][0]['status'],'not_observed');self.assertEqual(result['counts_state'],'PARTIAL_OR_UNMAPPED')
        self.write(self.raw().replace('1..1',f'not ok 2 - {TITLE}\n1..2').replace('# tests 1','# tests 2').replace('# fail 1','# fail 2'))
        result=self.result();self.assertTrue(result['unmapped_test_output']);self.assertEqual(len(result['tests']),1)
        self.write(self.raw().replace(TITLE,TITLE+' # SKIP synthetic').replace('# fail 1','# fail 0').replace('# skipped 0','# skipped 1'))
        result=self.result();self.assertEqual(result['tests'][0]['status'],'skipped');self.assertIsNone(result['tests'][0]['classification']);self.assertEqual(result['outcome'],'NOT_PASSED')
    def test_closed_codes_never_parse_indented_error_payload_or_duplicate_fields(self):
        for text in (self.raw().replace("  code: 'ERR_ASSERTION'","    code: '57014'"),
                     self.raw().replace("  code: 'ERR_ASSERTION'","  code: 'PRIVATE_SECRET'"),
                     self.raw().replace("  code: 'ERR_ASSERTION'","  code: '57014'\n  code: '42501'"),
                     self.raw().replace("  code: 'ERR_ASSERTION'","  code: '57014'\n  code: 'PRIVATE malformed'")):
            self.write(text);result=self.result();self.assertEqual(result['tests'][0]['classification'],'UNKNOWN');self.assertNotIn('PRIVATE_',json.dumps(result))
        self.write(self.raw().replace("code: 'ERR_ASSERTION'","code: '42883'"));self.assertEqual(self.result()['tests'][0]['classification'],'DATABASE_FUNCTION_UNAVAILABLE')
    def test_timeout_without_tap_retains_unknown_unobserved_scope(self):
        self.report['failure_diagnostic']['category']='command_timeout';self.write('phase=quality-native-tests\nexit=-9\n'+evidence.MARKER+'command_timeout\n')
        result=self.result();self.assertEqual(result['category'],'command_timeout');self.assertEqual(result['tests'][0]['status'],'not_observed');self.assertIsNone(result['tap_counts'])
        self.report['failure_diagnostic'].update(category='invariant_failed',commandLog=None);self.assertFalse(self.result()['command_log_available'])
    def test_actual_node_tap_failure_is_classified_without_raw_error_reflection(self):
        import shutil
        node=shutil.which('node');self.assertIsNotNone(node)
        target=self.root/'actual.test.mjs';target.write_text("import test from 'node:test';import assert from 'node:assert/strict';test("+json.dumps(TITLE)+",()=>assert.equal('PRIVATE_VALUE','PRIVATE_OTHER'));\n")
        run=subprocess.run([node,'--test','--test-reporter=tap',str(target)],capture_output=True,text=True,timeout=10)
        self.assertEqual(run.returncode,1);self.write('phase=quality-native-tests\nexit=1\n'+run.stdout+evidence.MARKER+'suite_failed\n')
        result=self.result();self.assertEqual(result['counts_state'],'COMPLETE');self.assertEqual(result['tests'][0]['classification'],'ASSERTION_FAILURE');self.assertNotIn('PRIVATE_',json.dumps(result))
    def runner(self):
        spec=importlib.util.spec_from_file_location('quality_diagnostic_runner',ROOT/'scripts/runtime-test-quality-upgrade.py');runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner);return runner
    def harness(self,runner):
        h=runner.Harness.__new__(runner.Harness);h.folder=self.root/FOLDER;h.serial=10;h.phase='quality-native-tests';h.deadline=time.monotonic()+10;h.cleanup_deadline=None
        h.output_bytes=0;h.private_values=[];h.last_command=None;h.command_failure=None;h.report={};h.admission=lambda:None;return h
    def test_actual_execute_records_failed_suite_before_mandatory_readback_and_cleanup(self):
        runner=self.runner()
        with patch.object(runner.base,'ROOT',self.root):
            h=self.harness(runner);h.report={'checks':[],'sourceStages':[]};h.phase='quality-predecessor';h.repository_stage=None
            ledger=[{'name':str(index)} for index in range(18)];applied=[];readbacks=[]
            h.sql=lambda query:json.dumps([] if 'pg_tables' in query else ledger+([{'name':'019'}] if applied else []))
            def migrate(target):
                first=not applied;applied.append(True)
                return subprocess.CompletedProcess([],0,'Applied '+runner.MIGRATION+'\n' if first else '', '')
            h.migrate=migrate
            def helper(args,**kwargs):
                self.assertIn('--test',args)
                return h.command([sys.executable,'-c','raise SystemExit(3)'],timeout=2,allow_failure=True)
            h.helper=helper
            def readback(unused):
                readbacks.append(True);h.command([sys.executable,'-c','print("PRIVATE_READBACK")'],timeout=2);return []
            frozen=[{'path':runner.REPOSITORY,'sha256':'a'*64}]
            with patch.object(runner,'sources',lambda:frozen),patch.object(runner,'predecessor_phase',lambda *args:None),patch.object(runner,'canonical_snapshot',lambda *args:{}),patch.object(runner,'repository_phase',lambda *args:{}),patch.object(runner.sql019,'readback',readback):
                with self.assertRaisesRegex(RuntimeError,'Native quality execution suite failed'):runner.execute(h)
            self.assertEqual(len(readbacks),2,'mandatory source readbacks still execute')
            retained=copy.deepcopy(h.report['failure_diagnostic']);self.assertEqual(retained['category'],'suite_failed')
            self.assertNotEqual(retained['commandLog']['path'],h.last_command['path'])
            h.phase='cleanup';h.command([sys.executable,'-c','pass'],timeout=2);h.remember_quality_failure(RuntimeError('PRIVATE later error'))
            self.assertEqual(h.report['failure_diagnostic'],retained)
            self.assertEqual(retained['commandLog']['sha256'],evidence.digest((self.root/retained['commandLog']['path']).read_bytes()))
    def test_original_bounded_command_timeout_survives_cleanup(self):
        runner=self.runner()
        with patch.object(runner.base,'ROOT',self.root):
            h=self.harness(runner)
            with self.assertRaises(RuntimeError) as caught:h.command([sys.executable,'-c','import time;time.sleep(2)'],timeout=.03)
            h.phase='cleanup';h.command([sys.executable,'-c','pass'],timeout=2);h.remember_quality_failure(caught.exception)
            failure=h.report['failure_diagnostic'];self.assertEqual(failure['phase'],'quality-native-tests');self.assertEqual(failure['category'],'command_timeout')
    def test_diagnostic_io_failure_does_not_replace_failed_execution(self):
        runner=self.runner();h=self.harness(runner)
        with patch.object(h,'remember_failure',side_effect=OSError('PRIVATE_IO')):h.remember_quality_failure(RuntimeError('original failed execution'))
        self.assertEqual(h.report,{'quality_diagnostic_capture':'UNAVAILABLE'})
    def repaired(self):
        from types import SimpleNamespace
        plan=[{'phase':'quality-native-tests','files':[evidence.TEST],'titles':[TITLE],'expected':1}]
        module=SimpleNamespace(native_plan=lambda selected:plan,allowed_pins=lambda selected:{evidence.TEST:{'b'*64}})
        for patcher in (patch.object(evidence,'repaired_wrapper',lambda root:(module,object())),patch.object(evidence,'repaired_source_inventory',self.inventory)):
            patcher.start();self.addCleanup(patcher.stop)
        self.report.update(command=evidence.REPAIRED_COMMAND,profile=evidence.REPAIRED_PROFILE,qualification='EXPLICIT_REPAIRED_CHAIN',historicalOutcome='HISTORICAL_NOT_EXECUTED',through='019',repairedCheckoutSources=self.inventory(self.root),repairedNativePlan=plan,
            repairedNativeSuites=[{'phase':'quality-native-tests','files':[evidence.TEST],'expected':1,'result':'FAIL','tests':{'tests':1,'suites':0,'pass':0,'fail':1,'cancelled':0,'skipped':0,'todo':0},'exitStatus':1,'checkoutSources':self.inventory(self.root),'effectiveSources':self.inventory(self.root)}])
        return lambda:evidence.safe_repaired_report(self.root,self.report,COMMIT)
    def test_repaired_scope_requires_own_wrapper_identity_and_full_current_sources(self):
        result=self.repaired();value=result();self.assertIsNotNone(value);self.assertEqual(value['command'],evidence.REPAIRED_COMMAND);self.assertEqual(value['profile'],evidence.REPAIRED_PROFILE)
        self.assertEqual(value['repaired_scope'],'SQL019_COMMAND_IDENTITY_ONLY');self.assertEqual(value['native_declared_effective_source_files'],self.inventory(self.root));self.assertEqual(value['outcome'],'NOT_PASSED')
        for key,bad in [('command',evidence.COMMAND),('profile',evidence.PROFILE),('through','024'),('qualification','HISTORICAL'),('historicalOutcome','PASS'),('repairedCheckoutSources',[])]:
            original=copy.deepcopy(self.report);self.report[key]=bad;self.assertIsNone(result());self.report=original
        self.assertIsNone(self.result(),'historical decoder cannot accept repaired report')
    def test_repaired_native_coordinates_bind_order_and_exact_declared_immutable_overrides(self):
        result=self.repaired();stage=self.report['repairedNativeSuites'][0]
        stage['effectiveSources'][0]['sha256']='b'*64;self.assertIsNotNone(result(),'exact independently declared predecessor pin is admissible')
        original=copy.deepcopy(self.report)
        for mutate in (lambda:self.report['repairedNativeSuites'][0]['effectiveSources'][0].update(sha256='c'*64),
                       lambda:self.report['repairedNativeSuites'][0]['effectiveSources'][0].update(path='PRIVATE_UNKNOWN'),
                       lambda:self.report['repairedNativeSuites'][0].update(expected=2),
                       lambda:self.report['repairedNativeSuites'][0].update(result='PRIVATE'),
                       lambda:self.report['repairedNativeSuites'][0].update(exitStatus=0),
                       lambda:self.report['repairedNativeSuites'][0]['tests'].update(fail=0),
                       lambda:self.report['repairedNativeSuites'][0].update(checkoutSources=[]),
                       lambda:self.report['repairedNativeSuites'].append(copy.deepcopy(self.report['repairedNativeSuites'][0])),
                       lambda:self.report.update(repairedNativeSuites=[]),
                       lambda:self.report['repairedNativePlan'][0].update(files=['PRIVATE_UNKNOWN'])):
            mutate();self.assertIsNone(result());self.report=copy.deepcopy(original)
    def test_repaired_setup_failure_has_no_invented_native_or_schema_pass(self):
        result=self.repaired();self.report['repairedNativeSuites']=[];self.report['failed_phase']='relation-candidate-upgrade'
        self.report['failure_diagnostic'].update(phase='relation-candidate-upgrade',category='command_failed')
        self.write('phase=relation-candidate-upgrade\nexit=1\n'+evidence.MARKER+'command_failed\n',phase='relation-candidate-upgrade')
        value=result();self.assertIsNotNone(value);self.assertIsNone(value['native_declared_effective_source_files']);self.assertEqual(value['tests'],[]);self.assertIsNone(value['tap_counts']);self.assertEqual(value['outcome'],'NOT_PASSED')
    def test_repaired_readback_failures_do_not_reuse_native_counters(self):
        result=self.repaired();self.report['failure_diagnostic']['category']='command_failed'
        self.write('phase=quality-native-tests\nexit=1\nPRIVATE_READBACK_FAILURE\n'+evidence.MARKER+'command_failed\n')
        stage=self.report['repairedNativeSuites'][0];stage.update(result='PASS',exitStatus=0,tests={'tests':1,'suites':0,'pass':1,'fail':0,'cancelled':0,'skipped':0,'todo':0})
        value=result();self.assertIsNotNone(value);self.assertIsNone(value['tap_counts']);self.assertEqual(value['tests'][0]['status'],'not_observed')
        self.report['repairedNativeSuites']=[]
        value=result();self.assertIsNotNone(value);self.assertIsNone(value['native_declared_effective_source_files']);self.assertIsNone(value['tap_counts'])
    def test_actual_repaired_wrapper_manifest_is_complete_before_diagnostic_admission(self):
        module,selected=evidence.repaired_wrapper(ROOT)
        expected=module.sources(selected)
        self.assertEqual(evidence.repaired_source_inventory(ROOT),expected)
        self.assertIn('scripts/runtime-test-governance-repaired-upgrade.py',{row['path'] for row in expected})
        self.assertIn('packages/db/migrations/032_relation_candidate_validation.sql',{row['path'] for row in expected})

    def test_repaired_manifest_has_own_finite_budget_without_widening_historical_logs(self):
        self.report['private_logs'].extend({'path':f'{FOLDER}/{i:03d}-quality-native-tests.log','sha256':'a'*64} for i in range(2,2050))
        self.assertIsNone(self.result(),'historical manifest remains capped at2048')
        result=self.repaired();self.assertIsNotNone(result())
        self.report['private_logs'].extend({'path':f'{FOLDER}/{i:03d}-quality-native-tests.log','sha256':'a'*64} for i in range(2050,4097));self.assertIsNotNone(result())
        self.report['private_logs'].append({'path':f'{FOLDER}/4097-quality-native-tests.log','sha256':'a'*64});self.assertIsNone(result())

    def test_repaired_loader_never_aliases_retired_filename_or_malformed_json(self):
        result=self.repaired();old=self.root/evidence.REPORT;old.parent.mkdir(exist_ok=True);old.write_text(json.dumps(self.report))
        self.assertIsNone(evidence.load_repaired_report(self.root,COMMIT));new=self.root/evidence.REPAIRED_REPORT;new.write_text(json.dumps(self.report));self.assertEqual(evidence.load_repaired_report(self.root,COMMIT),result())
        new.write_text('{"result":"FAIL","result":"PASS"}');self.assertIsNone(evidence.load_repaired_report(self.root,COMMIT))

    def test_collector_is_failure_only_and_never_reads_foreign_shard(self):
        import os
        tree=ast.parse((ROOT/'policies/ci_evidence.py').read_text());start=next(i for i,node in enumerate(tree.body) if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='quality_diagnostic' for target in node.targets))
        code=compile(ast.fix_missing_locations(ast.Module(body=tree.body[start:start+3],type_ignores=[])),'actual-quality-collector','exec')
        for outcome in ('failure','cancelled','success','skipped','NOT_IN_SHARD'):
            dest=self.root/outcome;dest.mkdir();report={'outcome':'PASS'};called=[]
            def load(*args):called.append(True);return self.result()
            exec(code,{'load_quality_diagnostic':load,'ROOT':self.root,'os':os,'REQUIRED':{'quality_repaired_upgrade'} if outcome!='NOT_IN_SHARD' else set(),'outcomes':{'quality_repaired_upgrade':outcome},'DEST':dest,'report':report,'json':json})
            self.assertEqual((dest/'quality-repaired-upgrade-diagnostic.json').exists(),outcome in ('failure','cancelled'))
            self.assertEqual(bool(called),outcome!='NOT_IN_SHARD')
            if outcome=='success':self.assertEqual(report['outcome'],'NOT_PASSED')

if __name__=='__main__':unittest.main()
