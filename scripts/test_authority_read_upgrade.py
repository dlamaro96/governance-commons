# SPDX-License-Identifier: Apache-2.0
"""Host composition controls; no PostgreSQL or Docker execution."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('authority_read_gate',ROOT/'scripts/runtime-test-authority-read-upgrade.py')
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
class Controls(unittest.TestCase):
 def test_actual_alternate_fixture_uses_normalized_registry_digest(self):
  node=shutil.which('node');self.assertIsNotNone(node)
  source=(ROOT/g.NEW_TEST).read_text()
  body=source[source.index('async function alternate('):source.index('\nasync function corrupt(')]
  imports="\n".join('import '+names+' from '+json.dumps((ROOT/path).as_uri())+';' for names,path in (
   ('{makeDecisionFixture,parsed}','tests/unit/fixtures/authority-decision.ts'),
   ('{hashAuthorityRegistry}','packages/authority/src/decision-identity.ts'),
   ('{decisionHash,decisionShapes,validateRegistry}','packages/authority/src/decision-schema.ts')))
  program=imports+'''
import assert from 'node:assert/strict';
import {randomInt,randomUUID} from 'node:crypto';
const uid=randomUUID, f={registry:makeDecisionFixture().registry,registryId:randomUUID(),owner:{}};
const original={registry:f.registry,registryId:f.registryId};let installs=0;
async function foundationInstall(owner,operation,args){
 assert.equal(owner,f.owner);assert.equal(operation,'registry-install');
 const [id,version,raw,digest]=args, registry=JSON.parse(raw),{digest:_,...content}=registry;
 const normalized=decisionShapes.registry(registry,'');validateRegistry(normalized);
 assert.equal(registry.version,version);assert.equal(normalized.digest,digest);
 assert.equal(hashAuthorityRegistry(content).value,digest);
 assert.notEqual(decisionHash(content),digest,'Fixture must exercise noncanonical input array order');
 installs++;return {};
}
async function mutate(target,work){assert.equal(target,f);await work();}
async function addGrant(target,role){assert.equal(target,f);assert.notEqual(target.registryId,original.registryId);assert.notEqual(target.registry.digest,original.registry.digest);return {ref:{id:randomUUID()}};}
'''+body+'''
const result=await alternate(f,{});assert.equal(installs,1);assert.equal(f.registry,original.registry);assert.equal(f.registryId,original.registryId);assert.equal(typeof result.grant,'string');
'''
  (ROOT/'.local').mkdir(exist_ok=True)
  with tempfile.TemporaryDirectory(prefix='authority-fixture-',dir=ROOT/'.local') as tmp:
   file=Path(tmp)/'check.mts';file.write_text(program)
   result=subprocess.run([node,'--import','tsx',str(file)],cwd=ROOT,capture_output=True,timeout=10)
   self.assertEqual(result.returncode,0,result.stderr.decode())
 def test_explicit_current_chain_and_source_admission(self):
  names=g.migrations();self.assertEqual(len(names),31);self.assertEqual(names[29:],[ '030_quality_volume.sql','031_authority_read_grants.sql'])
  rows=g.sources();self.assertEqual(len(rows),len({r['path'] for r in rows}));by={r['path']:r['sha256'] for r in rows}
  for path in ('scripts/qualification_quality_pre030.py','tests/qualification/predecessors/quality-service-sql029.ts.txt','tests/qualification/predecessors/repository-sql029.ts.txt',g.NEW_TEST,'packages/db/migrations/'+g.MIGRATION):self.assertIn(path,by)
  self.assertEqual(by['packages/db/migrations/013_authority_foundation.sql'],'4a9304cf02ab51fc085a6018cd22980e948bc6cd1167b3595ccb817b2cf41fbf')
 def test_original_loader_and_validator_delta_is_exact(self):
  old=(ROOT/'packages/db/migrations/013_authority_foundation.sql').read_text();new=(ROOT/'packages/db/migrations'/g.MIGRATION).read_text()
  def fn(text,name,head='CREATE FUNCTION'):
   i=text.index(head+' gc_authority.'+name+'(');return text[i:text.index('END $$;',i)+7]
  loader=fn(old,'load_human_closure_v1').replace('CREATE FUNCTION','CREATE OR REPLACE FUNCTION',1)
  anchor=' -- Fixed identities are checked against current canonical columns before JSON.'
  loader=loader.replace(anchor,' -- All grant bodies retain their original validation after complete bounded\n -- scalar admission; only exact root registry parsing is reused within one call.\n PERFORM gc_authority.validate_read_grants_v1(auth.tenant_id,all_grants);\n'+anchor)
  loader=loader.replace(" ELSIF mk->>'family'='grant' THEN PERFORM gc_authority.validate_grant(auth.tenant_id,(mk->>'id')::uuid,true);",'')
  self.assertEqual(loader,fn(new,'load_human_closure_v1','CREATE OR REPLACE FUNCTION'))
  self.assertNotIn('CREATE OR REPLACE FUNCTION gc_authority.validate_grant(',new)
  self.assertNotIn("set_config",new[:new.index('CREATE OR REPLACE FUNCTION')])
  self.assertIn('REVOKE ALL ON FUNCTION gc_authority.validate_read_grants_v1(uuid,uuid[]) FROM PUBLIC,gc_app;',new)
 def test_scope_hook_only_after_original_installation_assertions(self):
  calls=[];h=object.__new__(g.Harness);h.scope='original';h.applied031=False
  def apply(h,n):calls.append(('upgrade',n));h.applied031=True
  with patch.object(g,'apply031',apply),patch.object(g.authority.Harness,'suite',lambda h,*a:calls.append(('suite',a[0]))):
   h.suite('authn_storage_regression',Path('unused'),64);h.suite('authority_loader',Path('unused'),160)
  self.assertEqual(calls,[('upgrade',13),('suite','authn_storage_regression'),('suite','authority_loader')])
  calls.clear();h.scope='current';h.applied031=False
  with patch.object(g,'apply031',apply),patch.object(g.authority.Harness,'suite',lambda h,*a:calls.append(('suite',a[0]))):h.suite('authn_storage_regression',Path('unused'),64)
  self.assertEqual(calls,[('suite','authn_storage_regression')])
 def test_migration_mount_phase_restored_on_success_and_error(self):
  h=object.__new__(g.Harness);h.phase='upgrade-refusals';seen=[]
  with patch.object(g.authority.Harness,'migrate',lambda h,*a,**k:seen.append(h.phase)):
   h.migrate(Path('prefix'));self.assertEqual(h.phase,'upgrade-refusals')
  self.assertEqual(seen,['schema-upgrade-refusals'])
  with patch.object(g.authority.Harness,'migrate',side_effect=RuntimeError('bounded')):
   with self.assertRaises(RuntimeError):h.migrate(Path('prefix'))
  self.assertEqual(h.phase,'upgrade-refusals')
 def test_current_setup_applies_all_thirty_before_optimization(self):
  with tempfile.TemporaryDirectory() as tmp:
   class Fake:
    folder=Path(tmp);id='owned';created=False;report={};private_values=[];secret_path=Path(tmp)/'private.json'
    def inventory(self):return {'containers':[],'volumes':[],'networks':[]}
    def memory_admission(self):return {'admitted':True}
    def docker(self,*args,**kw):
     if args[:2]==('context','inspect'):out=json.dumps([{'Endpoints':{'docker':{'Host':'unix:///owned'}}}])
     elif args[:2]==('image','inspect'):out='sha256:'+'a'*64
     else:out=''
     return types.SimpleNamespace(stdout=out,returncode=0)
    def sql(self,text,**kw):
     if 'json_agg(json_build_object' in text:return json.dumps([{'name':n,'checksum':g.sha((ROOT/'packages/db/migrations'/n).read_bytes())} for n in g.NAMES[:30]])
     return ''
    def migrate(self,path):applied.append(sorted(p.name for p in path.glob('*.sql')))
   applied=[];h=Fake();g.setup(h)
   self.assertEqual([len(a) for a in applied],[11,12,13,30]);self.assertEqual(applied[-1],g.NAMES[:30]);self.assertNotIn(g.MIGRATION,applied[-1]);self.assertTrue(h.created)
   config=json.loads(h.secret_path.read_text());self.assertEqual(set(config),{'owner','admin','legacy'})
 def test_current_execution_keeps_every_native_suite_in_order(self):
  calls=[];h=types.SimpleNamespace(scope='current',frozen=[],report={'readUpgrade':{'ledger':[]}},applied031=False)
  def suite(key,path,offset):calls.append(('suite',key,str(path.relative_to(ROOT)),offset));h.report.setdefault('nativeSuites',[]).append({'phase':key,'path':str(path.relative_to(ROOT)),'expected':len(g.authority.diagnostics.declarations(ROOT,str(path.relative_to(ROOT)))),'result':'PASS','tests':dict.fromkeys(('tests','pass','fail','cancelled','skipped','todo'),0)})
  h.suite=suite
  with patch.object(g,'sources',return_value=[]),patch.object(g,'setup',lambda h:calls.append(('setup',))),patch.object(g,'additional_roles',lambda h,n:calls.append(('roles',n))),patch.object(g,'apply031',lambda h,n:calls.append(('upgrade',n))):g.execute(h)
  suites=[c for c in calls if c[0]=='suite'];self.assertEqual(len(suites),29)
  self.assertEqual([c[2] for c in suites[:12]],[p for p,n in g.CURRENT]);self.assertEqual(suites[12][1],'before031_authority_storage')
  self.assertEqual([c[2] for c in suites[13:25]],[p for p,n in g.CURRENT]);self.assertEqual(suites[-1][2],g.NEW_TEST)
  self.assertLess(calls.index(('upgrade',30)),calls.index(suites[13]))
 def test_original_execution_delegates_original_not_copied_success(self):
  calls=[];h=types.SimpleNamespace(scope='original',frozen=[],report={'readUpgrade':{'ledger':[]}},applied031=False)
  def original(h):calls.append('actual-original-execute');h.applied031=True;h.report['nativeSuites']=[{**p,'result':'PASS','tests':dict.fromkeys(('tests','pass','fail','cancelled','skipped','todo'),0)} for p in g.planned_suites('original')[:-1]]
  def suite(*args):calls.append(args);h.report['nativeSuites'].append({**g.planned_suites('original')[-1],'result':'PASS','tests':dict.fromkeys(('tests','pass','fail','cancelled','skipped','todo'),0)})
  h.suite=suite
  with patch.object(g,'sources',return_value=[]),patch.object(g.authority,'execute',original),patch.object(g,'additional_roles',lambda h,n:calls.append(('roles',n))):g.execute(h)
  self.assertEqual(calls[0],'actual-original-execute');self.assertEqual(calls[1],('roles',256));self.assertEqual(calls[2][0],'authority_read_regressions')
 def test_exact_scope_counts_and_identities(self):
  original,current=g.planned_suites('original'),g.planned_suites('current')
  self.assertEqual((len(original),sum(r['expected'] for r in original)),(8,133))
  self.assertEqual((len(current),sum(r['expected'] for r in current)),(29,423))
  self.assertEqual(len(set(r['phase'] for r in current)),29)
 def test_missing_original_upgrade_refuses(self):
  h=types.SimpleNamespace(scope='original',frozen=[],report={'readUpgrade':{'ledger':[]}},applied031=False)
  with patch.object(g.authority,'execute',lambda h:None):
   with self.assertRaises(RuntimeError):g.execute(h)
 def test_exact_tap_rejects_skips_failure_and_malformed(self):
  valid='\n'.join('# '+k+' '+str(v) for k,v in {'tests':10,'suites':0,'pass':10,'fail':0,'cancelled':0,'skipped':0,'todo':0}.items())+'\n# duration_ms 1.2\n'
  self.assertEqual(g.volume.totals(valid)['tests'],10)
  for bad in (valid+'# tests 10\n',valid.replace('# tests 10','# tests 10001'),valid.replace('# duration_ms 1.2','# duration_ms Infinity')):self.assertIsNone(g.volume.totals(bad))
  for key in ('fail','skipped','todo','cancelled'):
   with self.assertRaises(RuntimeError):g.authority.base.tap_summary(valid.replace('# '+key+' 0','# '+key+' 1'),10)
 def test_original_escaped_title_is_retained_exactly(self):
  rows=g.authority.diagnostics.declarations(ROOT,'tests/qualification/authority-authn-foundation-storage.test.ts')
  self.assertEqual(len(rows),21);self.assertIn("independent issuer channels cannot consume or issue each other's bound attempts",[r['title'] for r in rows])
 def test_effective_sources_never_select_pre030(self):
  rows=[{'path':'apps/api/src/repository.ts','sha256':'a'*64}]
  for phase in g.NATIVE_PHASES:self.assertEqual(g.volume.effective_sources(rows,phase),rows)
  self.assertEqual(g.volume.predecessor_pins(),[])
  with self.assertRaises(RuntimeError):g.volume.effective_sources(rows,'undeclared')
 def test_snapshot_includes_complete_table_target(self):
  calls=[];h=types.SimpleNamespace(sql=lambda text:(calls.append(text) or '{"rows":2,"sha256":"'+'a'*64+'"}'))
  self.assertEqual(g.snapshot(h,['public.quality_rules'])['public.quality_rules']['rows'],2)
  self.assertIn('to_jsonb(r)::text',calls[0]);self.assertNotIn("-'table_asset_id'",calls[0])
 def apply_fixture(self,prefix,tamper=None):
  with tempfile.TemporaryDirectory() as tmp:
   loader={'signature':'gc_authority.load_human_closure_v1(text,text)','owner':'1','acl':None,'definer':False,'config':['search_path=pg_catalog'],'volatility':'v','body':'old'}
   fixed={'signature':'gc_authority.validate_grant(uuid,uuid,boolean)','owner':'1','acl':None,'definer':False,'config':None,'volatility':'v','body':'immutable'}
   class Fake:
    folder=Path(tmp);phase='';applied031=False;report={};n=0
    def migrate(self,path):
     self.n+=1;self.observed=sorted(p.name for p in path.glob('*.sql'))
     return types.SimpleNamespace(stdout=('Applied '+g.MIGRATION+'\n') if self.n==1 else '')
    def sql(self,text):
     values=[loader,fixed] if self.n==0 else [{**loader,'body':'new'},fixed,{'signature':'gc_authority.validate_read_grants_v1(uuid,uuid[])'}]
     if tamper=='acl' and self.n:values[0]['acl']='widened'
     return json.dumps(values)
   h=Fake();state={'public.quality_rules':{'rows':3,'sha256':'a'*64}}
   def snap(h,tables):return {**state,'forged':True} if tamper=='row' and h.n else state
   with patch.object(g.volume,'canonical_tables',return_value=list(state)),patch.object(g,'snapshot',snap),patch.object(g,'ledger',lambda h,names:[{'name':n} for n in names]):g.apply031(h,prefix)
   self.assertTrue(h.applied031);self.assertTrue(h.report['readUpgrade']['preservation']);self.assertTrue(h.report['readUpgrade']['replay']);self.assertEqual(h.n,2)
   self.assertEqual(h.observed,[*g.NAMES[:prefix],g.MIGRATION])
 def test_both_forward_prefixes_preserve_full_state_and_inert_replay(self):
  for prefix in (13,30):self.apply_fixture(prefix)
 def test_upgrade_refuses_changed_loader_acl(self):
  with self.assertRaises(RuntimeError):self.apply_fixture(30,'acl')
 def test_upgrade_refuses_changed_canonical_row(self):
  with self.assertRaises(RuntimeError):self.apply_fixture(30,'row')
 def test_generated_verifier_detects_real_node_exit_tamper(self):
  node=shutil.which('node');self.assertIsNotNone(node)
  with tempfile.TemporaryDirectory() as tmp:
   d=Path(tmp);f=d/'source';f.write_text('original');config=d/'config';config.write_text('{}')
   body=g.volume.verifier([{'path':'source','sha256':g.sha(f.read_bytes())}],g.sha(config.read_bytes())).replace("'/app/'+row.path",json.dumps(str(d)+'/' )+'+row.path').replace("'/run/authn-config.json'",json.dumps(str(config)))
   check=d/'check.cjs';check.write_text(body)
   ok=subprocess.run([node,'--require',str(check),'-e',''],capture_output=True,timeout=10);self.assertEqual(ok.returncode,0)
   mutate="require('node:fs').writeFileSync("+json.dumps(str(f))+",'changed')"
   bad=subprocess.run([node,'--require',str(check),'-e',mutate],capture_output=True,timeout=10);self.assertNotEqual(bad.returncode,0);self.assertIn(b'QUALITY_VOLUME_SOURCE_MISMATCH',bad.stderr)
   badstart=subprocess.run([node,'--require',str(check),'-e',''],capture_output=True,timeout=10);self.assertNotEqual(badstart.returncode,0)

import shutil
if __name__=='__main__':unittest.main()
