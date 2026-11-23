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
    def test_retired_collector_never_loads_or_exports_historical_population_report(self):
        tree=ast.parse((ROOT/'policies/ci_evidence.py').read_text())
        self.assertFalse(any(isinstance(n,ast.ImportFrom) and n.module=='glossary_population_diagnostics' for n in ast.walk(tree)))
        self.assertFalse(any(isinstance(n,ast.Name) and n.id=='load_population_diagnostic' for n in ast.walk(tree)))
        assignments=[n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Subscript) and isinstance(t.value,ast.Name) and t.value.id=='report' and isinstance(t.slice,ast.Constant) and t.slice.value=='glossary_population_diagnostic' for t in n.targets)]
        self.assertEqual(len(assignments),1)
        code=compile(ast.fix_missing_locations(ast.Module(body=assignments,type_ignores=[])),'actual-retired-collector','exec')
        old=self.root/evidence.REPORT;old.parent.mkdir(exist_ok=True);old.write_text(json.dumps(self.report))
        for outcome in ('success','failure','cancelled','skipped'):
            report={'outcome':'NOT_PASSED'};exec(code,{'report':report,'outcomes':{'glossary_population_upgrade':outcome}})
            self.assertEqual(report,{'outcome':'NOT_PASSED','glossary_population_diagnostic':'HISTORICAL_NOT_EXECUTED'})
        self.assertFalse(any(isinstance(n,ast.Constant) and n.value=='glossary-population-diagnostic.json' for n in ast.walk(tree)))
    def test_retired_canonical_population_report_is_refused_in_every_shard(self):
        import ci_shards
        path=self.root/evidence.REPORT;path.parent.mkdir(exist_ok=True)
        for shard in (None,*ci_shards.SHARDS):
            self.assertFalse(ci_shards.foreign_evidence(self.root,shard))
            path.write_text(json.dumps(self.report));self.assertTrue(ci_shards.foreign_evidence(self.root,shard));path.unlink()
            path.symlink_to(self.root/'missing-private-report');self.assertTrue(ci_shards.foreign_evidence(self.root,shard));path.unlink()

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

class CanonicalSnapshotControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('population_snapshot_controls',ROOT/'scripts/runtime-test-glossary-population-upgrade.py')
        cls.runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.runner)

    class SQL:
        def __init__(self,outputs):self.outputs=iter(outputs);self.queries=[]
        def sql(self,query,**kwargs):
            self.queries.append((query,kwargs));output=next(self.outputs)
            if isinstance(output,Exception):raise output
            return output

    @staticmethod
    def row(table,rows=1,digest='a'*64):return {'table':table,'rows':rows,'sha256':digest}
    @staticmethod
    def output(*rows):return '\n'.join(json.dumps(row) for row in rows)
    @staticmethod
    def tables(count):return ['public.table_'+chr(97+n//26)+chr(97+n%26) for n in range(count)]

    def test_original_complete_json_digest_expression_and_multiplicity_are_unchanged(self):
        tables=['public.asset_revisions','gc_authority.write_lock_claims']
        h=self.SQL([self.output(self.row(tables[0],11001),self.row(tables[1],0,'b'*64))])
        result=self.runner.canonical_snapshot(h,tables)
        self.assertEqual(result,{tables[0]:{'rows':11001,'sha256':'a'*64},tables[1]:{'rows':0,'sha256':'b'*64}})
        self.assertEqual(len(h.queries),1);query,kwargs=h.queries[0];self.assertEqual(kwargs,{})
        digest="encode(sha256(convert_to(coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]')::text,'UTF8')),'hex')"
        expected=[f"SELECT jsonb_build_object('table','{table}','rows',count(*),'sha256',{digest}) FROM {table} r;" for table in tables]
        self.assertEqual(query,'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n'+'\n'.join(expected)+'\nCOMMIT;')
        self.assertNotRegex(query,r'(?i)\b(DISTINCT|LIMIT|WHERE|row_hashes)\b')

    def test_inventory_is_fully_validated_before_first_command(self):
        for tables in (None,('public.assets',),['public.assets']*2,self.tables(513),
                       ['public.assets',None],['public.assets',[]],['public.assets','assets'],
                       ['public.assets','public.assets; DELETE FROM public.assets'],
                       ['public.assets','public."assets"'],['public.assets','public.assets extra']):
            with self.subTest(tables=str(tables)[:80]):
                h=self.SQL([])
                with self.assertRaisesRegex(RuntimeError,'Invalid fixed snapshot table'):self.runner.canonical_snapshot(h,tables)
                self.assertEqual(h.queries,[])

    def test_exact_batch_bound_preserves_all_tables_and_empty_inventory(self):
        for count in (0,1,16,17,32,33,512):
            with self.subTest(count=count):
                tables=self.tables(count);h=self.SQL([self.output(*(self.row(t) for t in tables[n:n+16])) for n in range(0,count,16)])
                self.assertEqual(list(self.runner.canonical_snapshot(h,tables)),tables)
                self.assertEqual(len(h.queries),(count+15)//16)
                self.assertEqual([query.count('SELECT jsonb_build_object(') for query,_ in h.queries],[len(tables[n:n+16]) for n in range(0,count,16)])

    def test_missing_extra_duplicate_reordered_foreign_or_blank_rows_refuse(self):
        first,second=self.row('public.assets'),self.row('public.audit')
        outputs=[self.output(*rows) for rows in ([first],[first,second,second],[first,first],[second,first],[first,self.row('public.unknown')])]
        outputs.extend(['',self.output(first)+'\n\n'+self.output(second),self.output(first)+'\nnot-json'])
        for output in outputs:
            with self.subTest(output=output):
                with self.assertRaisesRegex(RuntimeError,'Invalid canonical snapshot'):
                    self.runner.canonical_snapshot(self.SQL([output]),['public.assets','public.audit'])

    def test_closed_count_digest_and_json_key_schema_refuses_invalid_values(self):
        rows=[self.row('public.assets',True),self.row('public.assets',-1),self.row('public.assets',1.0),
              self.row('public.assets',1,None),self.row('public.assets',1,'A'*64),self.row('public.assets',1,'a'*63),
              {**self.row('public.assets'),'extra':True},[],None,{'rows':1,'sha256':'a'*64}]
        outputs=[json.dumps(row) for row in rows]
        outputs.append('{"table":"public.assets","rows":0,"rows":1,"sha256":"'+'a'*64+'"}')
        for output in outputs:
            with self.subTest(output=output):
                with self.assertRaisesRegex(RuntimeError,'Invalid canonical snapshot'):
                    self.runner.canonical_snapshot(self.SQL([output]),['public.assets'])

    def test_later_command_error_or_partial_batch_never_returns_partial_snapshot(self):
        tables=self.tables(33);first=self.output(*(self.row(t) for t in tables[:16]))
        for second in (RuntimeError('synthetic command failure'),self.output(self.row(tables[16]))):
            with self.subTest(second=str(second)):
                h=self.SQL([first,second])
                with self.assertRaises(RuntimeError):self.runner.canonical_snapshot(h,tables)
                self.assertEqual(len(h.queries),2)

    def test_runner_is_already_bound_and_has_no_external_batch_helper(self):
        path='scripts/runtime-test-glossary-population-upgrade.py'
        self.assertIn(path,evidence.FIXED)
        tree=ast.parse((ROOT/path).read_text())
        function=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='canonical_snapshot')
        self.assertFalse(any(isinstance(node,(ast.Import,ast.ImportFrom)) for node in ast.walk(function)))

if __name__=='__main__':unittest.main()
