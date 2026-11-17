# SPDX-License-Identifier: Apache-2.0
"""Host controls exercise orchestration with Docker/SQL leaves replaced; no native execution."""
import ast,hashlib,importlib.util,json,re,shutil,subprocess,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('candidate_gate',ROOT/'scripts/runtime-test-relation-candidate-upgrade.py');g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
class Controls(unittest.TestCase):
 def test_exact_migration_and_transitive_source_inventory(self):
  self.assertEqual(len(g.migrations()),32);rows=g.sources();self.assertEqual(len(rows),len({r['path'] for r in rows}));paths={r['path'] for r in rows}
  for p in [g.BASELINE,g.NEW_TEST,'tests/fixtures/relation-candidate.ts',*[p['fixture'] for p in g.PREDECESSORS]]:self.assertIn(p,paths)
  self.assertNotIn('tests/fixtures/business-domains.ts',paths)
  self.assertEqual(g.sha((ROOT/'packages/db/migrations/018_glossary_nominal_candidates.sql').read_bytes()),'60361c7b2ddee2f1f095d0e832116b4b97cc04fdbee6a88b398721e5bee13fea')
 def test_fixed031_baseline_does_not_follow_current_import032(self):
  self.assertEqual(len(g.transport.NAMES),32);self.assertEqual(g.transport.NAMES[-1],g.MIGRATION)
  self.assertEqual(len(g.BASE_NAMES),31);self.assertEqual(g.BASE_NAMES[-1],'031_authority_read_grants.sql')
  self.assertEqual(g.NAMES,[*g.BASE_NAMES,g.MIGRATION]);self.assertEqual(g.NAMES.count(g.MIGRATION),1)
  self.assertEqual(g.migrations(),g.NAMES)
 def test_sql_function_has_only_two_exact_fences_and_original_acl(self):
  old=(ROOT/'packages/db/migrations/018_glossary_nominal_candidates.sql').read_text();new=(ROOT/'packages/db/migrations'/g.MIGRATION).read_text();start='CREATE OR REPLACE FUNCTION public.gc_relation_check_type';old=old[old.index(start):];new=new[new.index(start):]
  count=" OR (SELECT count(*) FROM public.gc_relation_nominal_candidates(head_definition) c JOIN public.assets a ON a.tenant_id=tenant AND a.id=c.asset_id WHERE (public.gc_relation_endpoint_eligible(tenant,a.id,head_definition,'source')\n   OR public.gc_relation_endpoint_eligible(tenant,a.id,head_definition,'target')))>2000 THEN"
  fenced=" OR (WITH candidates AS MATERIALIZED (\n   SELECT a.id AS asset_id FROM public.gc_relation_nominal_candidates(head_definition) c\n   JOIN public.assets a ON a.tenant_id=tenant AND a.id=c.asset_id\n  ) SELECT count(*) FROM candidates c WHERE (public.gc_relation_endpoint_eligible(tenant,c.asset_id,head_definition,'source')\n   OR public.gc_relation_endpoint_eligible(tenant,c.asset_id,head_definition,'target')))>2000 THEN"
  minimum="  IF side_min>0 AND EXISTS(SELECT 1 FROM public.gc_relation_nominal_candidates(head_definition) c JOIN public.assets a ON a.tenant_id=tenant AND a.id=c.asset_id\n   WHERE public.gc_relation_endpoint_eligible(tenant,a.id,head_definition,CASE WHEN selected_side='incident' THEN 'source' ELSE selected_side END)\n   AND NOT EXISTS(SELECT 1 FROM public.relation_participations p WHERE p.tenant_id=tenant AND p.relation_type_id=type_identity\n    AND p.asset_id=a.id AND p.side=selected_side AND p.status='active')) THEN"
  fenced_min="  IF side_min>0 AND EXISTS(WITH candidates AS MATERIALIZED (\n    SELECT a.id AS asset_id FROM public.gc_relation_nominal_candidates(head_definition) c\n    JOIN public.assets a ON a.tenant_id=tenant AND a.id=c.asset_id\n   ) SELECT 1 FROM candidates c\n   WHERE public.gc_relation_endpoint_eligible(tenant,c.asset_id,head_definition,CASE WHEN selected_side='incident' THEN 'source' ELSE selected_side END)\n   AND NOT EXISTS(SELECT 1 FROM public.relation_participations p WHERE p.tenant_id=tenant AND p.relation_type_id=type_identity\n    AND p.asset_id=c.asset_id AND p.side=selected_side AND p.status='active')) THEN"
  self.assertEqual(old.count(count),1);self.assertEqual(old.count(minimum),1);self.assertEqual(new.replace(fenced,count).replace(fenced_min,minimum),old)
 def test_all_original_declarations_and_new_cases_are_mandatory(self):
  self.assertEqual([len(g.declarations(p)) for p,n in g.TESTS],[10,5,6,4,1]);self.assertEqual(len(g.declarations(g.BASELINE)),1);self.assertEqual(len(g.declarations(g.NEW_TEST)),10)
  self.assertEqual(len(g.PHASES),14)
 def test_exact_effective_predecessor_sources_and_current_identity(self):
  rows=g.sources();pins=g.predecessor_pins();original=g.effective_sources(rows,'original-0-tests');current=g.effective_sources(rows,'current-0-tests');self.assertEqual(current,rows)
  changed={r['path'] for r,s in zip(rows,original) if r!=s};self.assertEqual(changed,{p['path'] for p in pins})
  self.assertEqual({p['path']:p['sha256'] for p in pins},{r['path']:r['sha256'] for r in original if r['path'] in changed})
  for invalid in ('pre018','current-unknown-tests','schema32-upgrade'):
   with self.assertRaises(RuntimeError):g.effective_sources(rows,invalid)
  with self.assertRaises(RuntimeError):g.effective_sources(rows[1:]+[rows[0],rows[0]],'original-0-tests')
  with self.assertRaises(RuntimeError):g.effective_sources([r for r in rows if r['path']!=pins[0]['path']],'original-0-tests')
 def test_fixture_tamper_refuses_before_helper(self):
  with tempfile.TemporaryDirectory() as tmp:
   p=Path(tmp)/'bad';p.write_text('changed')
   with patch.object(g,'source_file',return_value=p):
    with self.assertRaises(RuntimeError):g.predecessor_pins()
 def test_actual_setup_uses_exact_original_or_current_prefix(self):
  for prefix in (18,31):
   with self.subTest(prefix=prefix),tempfile.TemporaryDirectory() as tmp:
    calls=[]
    class Fake:
     folder=Path(tmp);id='owned';created=False;report={};secret_path=Path(tmp)/'private.json'
     def inventory(self):return {'containers':[],'volumes':[],'networks':[]}
     def memory_admission(self):return {'admitted':True}
     def docker(self,*a,**kw):
      calls.append(a)
      out=json.dumps([{'Endpoints':{'docker':{'Host':'unix:///owned'}}}]) if a[:2]==('context','inspect') else 'sha256:'+'a'*64 if a[:2]==('image','inspect') else ''
      return types.SimpleNamespace(stdout=out,returncode=0)
     def sql(self,s,**kw):return json.dumps([{'name':n,'checksum':g.sha((ROOT/'packages/db/migrations'/n).read_bytes())} for n in g.NAMES[:prefix]]) if 'json_agg(json_build_object' in s else ''
     def migrate(self,p):stages.append(sorted(x.name for x in p.glob('*.sql')))
    h=Fake();stages=[]
    with patch.object(g.transport,'migrations',return_value=g.NAMES[:prefix]):g.transport.setup(h)
    self.assertEqual([len(s) for s in stages],[11,12,13,prefix]);self.assertEqual(stages[-1],g.NAMES[:prefix]);self.assertNotIn(g.MIGRATION,stages[-1]);self.assertTrue(h.created);self.assertEqual(set(json.loads(h.secret_path.read_text())),{'owner','legacy'})
    run=next(c for c in calls if c[0]=='run');self.assertIn('--pull',run);self.assertIn('never',run);self.assertIn('--network',run);self.assertIn('none',run);self.assertIn('--read-only',run)
 def test_execute_preserves_exact_scope_order_and_totals(self):
  for scope,prefix in [('original',18),('current',31)]:
   events=[];h=types.SimpleNamespace(scope=scope,prefix=prefix,frozen=[],report={'nativeSuites':[]})
   def suite(h,name,path,count):events.append(('suite',name,path,count));h.report['nativeSuites'].append({'tests':{'tests':count}})
   old=g.transport.migrations
   with patch.object(g,'sources',return_value=[]),patch.object(g.transport,'setup',lambda h:events.append(('setup',g.transport.migrations()))),patch.object(g,'suite',suite),patch.object(g,'apply32',lambda h:events.append(('upgrade',h.prefix))):g.execute(h)
   self.assertIs(g.transport.migrations,old);self.assertEqual(events[0],('setup',g.NAMES[:prefix]));self.assertEqual(events[1],('suite','baseline',g.BASELINE,1));self.assertEqual(events[2],('upgrade',prefix));self.assertEqual(events[-1],('suite','regressions',g.NEW_TEST,10));self.assertEqual(h.report['tests']['tests'],37)
 def test_setup_and_migration_failure_restore_hooks_and_phases(self):
  h=types.SimpleNamespace(prefix=18,frozen=[]);old=g.transport.migrations
  with patch.object(g,'sources',return_value=[]),patch.object(g.transport,'setup',side_effect=RuntimeError('bounded')):
   with self.assertRaises(RuntimeError):g.execute(h)
  self.assertIs(g.transport.migrations,old)
  h=object.__new__(g.Harness);h.phase='original-baseline-tests';seen=[]
  with patch.object(g.transport.Harness,'migrate',lambda h,*a,**k:seen.append(h.phase)):h.migrate(Path('x'))
  self.assertEqual(seen,['schema-original-baseline-tests']);self.assertEqual(h.phase,'original-baseline-tests')
  with patch.object(g.transport.Harness,'migrate',side_effect=RuntimeError('bounded')):
   with self.assertRaises(RuntimeError):h.migrate(Path('x'))
  self.assertEqual(h.phase,'original-baseline-tests')
 def apply_fixture(self,prefix,tamper=None):
  with tempfile.TemporaryDirectory() as tmp:
   old={'signature':'gc_relation_check_type(uuid,uuid)','owner':'1','acl':'owner-only','definer':True,'config':['row_security=on'],'volatility':'v','body':'old'};fixed={**old,'signature':'other(uuid)','body':'same'};state={'public.assets':{'rows':2,'sha256':'a'*64}}
   class Fake:
    folder=Path(tmp);phase='';report={};n=0
    def save(self):pass
    def migrate(self,p):self.n+=1;self.names=sorted(x.name for x in p.glob('*.sql'));return types.SimpleNamespace(stdout='Applied '+g.MIGRATION+'\n' if self.n==1 else '')
    def sql(self,s):
     if s==g.TABLES:return json.dumps(list(state))
     if s==g.GUARDS:return 'changed' if tamper=='guard' and self.n else '{}'
     values=[old,fixed] if self.n==0 else [{**old,'body':'new'},fixed]
     if self.n and tamper=='acl':values[0]['acl']='wider'
     if self.n and tamper=='other':values[1]={**fixed,'body':'changed'}
     return json.dumps(values)
   h=Fake();h.prefix=prefix
   def snap(h,t):return {'changed':True} if h.n and tamper=='row' else state
   def ledger(h,n):return [{'name':x,'checksum':'changed' if tamper=='ledger' and h.n and x!=g.MIGRATION else 'same'} for x in n]
   with patch.object(g,'snapshot',snap),patch.object(g,'ledger',ledger):g.apply32(h)
   self.assertEqual(h.n,2);self.assertEqual(h.names,[*g.NAMES[:prefix],g.MIGRATION]);self.assertTrue(h.report['upgrade']['preservation']);self.assertTrue(h.report['upgrade']['replay'])
 def test_both_populated_prefix_upgrades_preserve_and_replay(self):
  for prefix in (18,31):self.apply_fixture(prefix)
 def test_upgrade_refuses_row_ledger_function_acl_or_guard_changes(self):
  for tamper in ('row','ledger','other','acl','guard'):
   with self.subTest(tamper=tamper),self.assertRaises(RuntimeError):self.apply_fixture(31,tamper)
 def test_actual_helper_mounts_only_exact_phase_sources_and_probe(self):
  for phase in ('original-baseline-tests','current-regressions-tests'):
   with tempfile.TemporaryDirectory() as tmp:
    h=object.__new__(g.Harness);h.id='owned';h.serial=1;h.owned=[];h.phase=phase;h.folder=Path(tmp);h.secret_path=Path(tmp)/'secret';h.secret_path.write_text('{}');h.frozen=g.sources();h.report={'cachedPackageAdmission':{}};h.app_image='sha256:'+'a'*64;calls=[]
    h.docker=lambda *a,**k:(calls.append(a) or types.SimpleNamespace(stdout='',returncode=0))
    h.helper(['node','-e','']);a=calls[0];mounts=[a[i+1] for i,x in enumerate(a) if x=='--volume'];self.assertTrue(all(x.endswith(':ro') for x in mounts));self.assertEqual(len(mounts),len(h.frozen)+2);self.assertIn('--read-only',a);self.assertEqual(a[a.index('--pull')+1],'never')
    self.assertEqual(a[a.index('--network')+1],'container:owned');self.assertIn(g.PROBE,a)
    for p in g.PREDECESSORS:
     origin=p['fixture'] if phase.startswith('original-') else p['path'];self.assertIn(str(ROOT/origin)+':/app/'+p['path']+':ro',mounts)
    self.assertEqual(h.report['sourceChecks'][0]['effectiveSources'],g.effective_sources(h.frozen,phase))
    with self.assertRaises(RuntimeError):h.helper(['node','-e',''],mounts=[(Path(tmp),'/app')])
 def test_real_node_source_verifier_rejects_start_and_exit_tampering(self):
  node=shutil.which('node');self.assertIsNotNone(node)
  with tempfile.TemporaryDirectory() as tmp:
   d=Path(tmp);f=d/'source';f.write_text('original');c=d/'config';c.write_text('{}');p=d/'check.cjs';p.write_text(g.verifier([{'path':'source','sha256':g.sha(f.read_bytes())}],g.sha(c.read_bytes())).replace("'/app/'+row.path",json.dumps(str(d)+'/')+'+row.path').replace("'/run/authn-config.json'",json.dumps(str(c))))
   self.assertEqual(subprocess.run([node,'--require',str(p),'-e',''],capture_output=True,timeout=10).returncode,0)
   bad=subprocess.run([node,'--require',str(p),'-e',"require('node:fs').writeFileSync("+json.dumps(str(f))+",'changed')"],capture_output=True,timeout=10);self.assertNotEqual(bad.returncode,0);self.assertIn(b'REFERENCE_IMPORT_SOURCE_MISMATCH',bad.stderr)
   self.assertNotEqual(subprocess.run([node,'--require',str(p),'-e',''],capture_output=True,timeout=10).returncode,0)
 def test_exact_suite_tap_refuses_skip_failure_duplicate_and_wrong_identity(self):
  title=g.declarations(g.BASELINE)[0];valid='# Subtest: '+title+'\nok 1 - '+title+'\n'+''.join('# '+k+' '+str(v)+'\n' for k,v in {'tests':1,'suites':0,'pass':1,'fail':0,'cancelled':0,'skipped':0,'todo':0}.items())+'# duration_ms 1.2\n'
  def run(text,status=0):
   h=types.SimpleNamespace(scope='current',frozen=[],report={'nativeSuites':[]},save=lambda:None,helper=lambda *a,**k:types.SimpleNamespace(stdout=text,returncode=status))
   with patch.object(g,'readback',return_value={}),patch.object(g,'sources',return_value=[]):g.suite(h,'baseline',g.BASELINE,1)
  run(valid)
  for bad in (valid.replace('# skipped 0','# skipped 1'),valid.replace('# fail 0','# fail 1'),valid+'# tests 1\n',valid.replace('ok 1 - '+title,'ok 1 - wrong')):
   with self.assertRaises(RuntimeError):run(bad)
  with self.assertRaises(RuntimeError):run(valid,1)
 def test_throwing_cleanup_still_removes_credentials_and_never_passes(self):
  (ROOT/'.local').mkdir(exist_ok=True)
  with tempfile.TemporaryDirectory(dir=ROOT/'.local') as tmp:
   secret=Path(tmp)/'secret';secret.write_text('private');h=types.SimpleNamespace(folder=Path(tmp),secret_path=secret,report={},cleanup=lambda:(_ for _ in ()).throw(TimeoutError()),save=lambda **k:None)
   self.assertTrue(g.finish(h,False));self.assertFalse(secret.exists());self.assertEqual(h.report['result'],'FAIL');self.assertTrue(h.report['cleanup']['generatedCredentialsRemoved'])
 def test_snapshot_covers_full_rows_as_multiset(self):
  calls=[];h=types.SimpleNamespace(sql=lambda s:(calls.append(s) or '{"rows":1,"sha256":"a"}'));self.assertEqual(g.snapshot(h,['public.assets'])['public.assets']['rows'],1);self.assertIn('to_jsonb(r)::text',calls[0]);self.assertIn('ORDER BY value',calls[0])
  with self.assertRaises(RuntimeError):g.snapshot(h,['public.assets;DROP'])
 def test_actual_native_expression_extractor_retains_both_joined_predicates(self):
  node=shutil.which('node');self.assertIsNotNone(node);source=(ROOT/g.NEW_TEST).read_text();body=source[source.index('function expression('):source.index('\nconst oldCount=')]
  declaration='CREATE OR REPLACE FUNCTION public.gc_relation_check_type';program="import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';const declaration="+json.dumps(declaration)+';\n'+body+'''
for(const file of ['018_glossary_nominal_candidates.sql','032_relation_candidate_validation.sql'])for(const kind of ['count','missing']){
 const q=expression(readFileSync('packages/db/migrations/'+file,'utf8'),kind);
 assert.ok(q.startsWith(file.startsWith('018')?'SELECT':'WITH'));
 assert.ok(q.includes('a.tenant_id=$1::uuid AND a.id=c.asset_id'));
 assert.ok(q.includes('gc_relation_endpoint_eligible($1::uuid,'));
 assert.ok(q.includes('$2::jsonb'));assert.ok(!q.includes('head_definition'));
 if(kind==='missing'){assert.ok(q.includes('$3::text'));assert.ok(q.includes('$4::uuid'));assert.ok(q.endsWith("p.status='active')"));}
}
'''
  (ROOT/'.local').mkdir(exist_ok=True)
  with tempfile.TemporaryDirectory(dir=ROOT/'.local') as tmp:
   p=Path(tmp)/'check.mts';p.write_text(program);r=subprocess.run([node,'--import','tsx',str(p)],cwd=ROOT,capture_output=True,timeout=10);self.assertEqual(r.returncode,0,r.stderr.decode())
if __name__=='__main__':unittest.main()
