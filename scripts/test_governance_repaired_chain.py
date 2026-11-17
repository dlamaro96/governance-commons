# SPDX-License-Identifier: Apache-2.0
"""Host-only composition controls. DB/Docker leaves are substituted, never native claims."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import types
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('repaired_gate',ROOT/'scripts/runtime-test-governance-repaired-upgrade.py');g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)

def tap(titles,failed=False):
 out='TAP version 13\n'+''.join(f'# Subtest: {t}\n'+('not ok' if failed and i==1 else 'ok')+f' {i} - {t}\n' for i,t in enumerate(titles,1))
 return out+f'1..{len(titles)}\n# tests {len(titles)}\n# suites 0\n# pass {len(titles)-int(failed)}\n# fail {int(failed)}\n# cancelled 0\n# skipped 0\n# todo 0\n# duration_ms 1.0\n'

def proof(rows,config):
 value={'pid':1,'manifest':g.sha(json.dumps(rows,separators=(',',':')).encode()),'config':config,
 'tools':{'node':{'version':'v24.22.3','sha256':'a'*64},'tsx':{'version':'4.20.5','sha256':'b'*64}}}
 return ''.join('# '+g.MARKER+json.dumps({'event':e,**value})+'\n' for e in ('start','exit'))

def inventory(names):return [{'name':n,'checksum':g.sha((ROOT/'packages/db/migrations'/n).read_bytes()),'applied_at':'2026-01-01T00:00:00Z'} for n in names]

def fixture(through,folder):
 selected=g.load(through);cls=g.harness_class(selected)
 # Run the real constructors and every ancestor source wrapper. Only command,
 # database operations and the pre014 infrastructure setup leaf are replaced.
 h=cls(through);h.folder=folder;h.secret_path=folder/'private-config.json';h.secret_path.write_text('{"owner":"synthetic","legacy":"synthetic"}')
 h.app_image='sha256:'+'c'*64;h.report['cachedPackageAdmission']={'fixture':True};h.ledger=[];h.calls=[];h.failed_native=None
 h.functions=[{'signature':'gc_relation_check_type(uuid,uuid)','owner':'owner','acl':'private','definer':True,'config':[],'volatility':'v','body':'before'}]
 h.guards='{"rls":[],"triggers":[]}'
 def sql(query,**kw):
  if query==selected.repaired.TABLES:return '[]'
  if 'json_agg(to_jsonb(m)' in query:return json.dumps(h.ledger)
  if query==selected.repaired.FUNCTIONS:return json.dumps(h.functions)
  if query==selected.repaired.GUARDS:return h.guards
  if 'NOT EXISTS(SELECT 1 FROM sources WHERE next_scan_generation' in query:return 't'
  raise AssertionError('Unaccounted SQL leaf')
 h.sql=sql;h.snapshot=lambda tables:{}
 h.sql_result=lambda query,**kw:types.SimpleNamespace(stdout=sql(query),stderr='',returncode=0)
 def migrate(directory,**kw):
  names=sorted(p.name for p in directory.glob('*.sql'));h.calls.append(('migrate',h.phase,names))
  existing=[r['name'] for r in h.ledger]
  if not set(existing)<=set(names):raise AssertionError('Migrator omitted applied032')
  missing=[n for n in names if n not in existing]
  h.ledger=sorted([*h.ledger,*inventory(missing)],key=lambda r:r['name'])
  if selected.repaired.MIGRATION in missing:h.functions[0]['body']='after'
  return types.SimpleNamespace(stdout=''.join('Applied '+n+'\n' for n in missing),stderr='',returncode=0)
 h.migrate=migrate
 def command(args,**kwargs):
  h.calls.append(('command',h.phase,args));require=lambda v:None if v else (_ for _ in ()).throw(AssertionError('Unexpected native command'))
  require(args[0]=='docker' and 'run' in args and h.app_image in args);offset=args.index(h.app_image);argv=args[offset+1:]
  if '--test' in argv:
   record=h.report['repairedNativeSuites'][-1];titles=next(p['titles'] for p in h.repaired_plan if p['phase']==h.phase)
   failed=h.failed_native==h.phase
   return types.SimpleNamespace(stdout=proof(record['effectiveSources'],g.sha(h.secret_path.read_bytes()))+tap(titles,failed),stderr='',returncode=int(failed))
  require('-e' in argv);code=argv[argv.index('-e')+1]
  patterns=[r'JSON\.stringify\((\[.*?\])\.map\(',r'const paths=(\[.*?\]);']
  found=next((re.search(p,code) for p in patterns if re.search(p,code)),None);require(found is not None)
  paths=json.loads(found[1]);rows=[{'path':p,'sha256':g.sha((ROOT/p).read_bytes())} for p in paths]
  effective,_=g.mounted_sources(args,offset,rows,h.repaired_pins,h.folder)
  return types.SimpleNamespace(stdout=json.dumps(effective),stderr='',returncode=0)
 h.command=command
 base=next(m for m in g.ancestry(selected) if Path(m.__file__).name=='runtime-test-source-connectors-upgrade.py')
 def setup(h):h.ledger=inventory(base.NAMES);h.report['sources']=base.sources();h.report['checks'].append('substituted infrastructure leaf only')
 return selected,h,patch.object(base,'execute',setup)

class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  (ROOT/'.local').mkdir(exist_ok=True)
 def test_exact_closed_profiles_and_native_declarations(self):
  totals=[]
  for key in g.PROFILES:
   module=g.load(key);plan=g.native_plan(module);totals.append(sum(r['expected'] for r in plan))
   self.assertEqual([r['phase'] for r in plan[:4]],list(g.SINGLE_PHASES.values())[:4]);self.assertEqual(plan[3]['expected'],26)
  self.assertEqual(totals,[98,113,126,140,158,194,263])
  for key in ('017','025','32','018,032','../018'):
   with self.assertRaises(RuntimeError):g.load(key)
 def test_inert_historical_and_repaired_manifests_bind_helper(self):
  for key in g.PROFILES:
   m=g.load(key);old=m.sources();new=g.sources(m)
   self.assertIn({'path':'scripts/qualification_relation_candidate.py','sha256':g.sha((ROOT/'scripts/qualification_relation_candidate.py').read_bytes())},old)
   self.assertIn('packages/authority/src/authentication-installation.ts',{r['path'] for r in new});self.assertTrue(set(r['path'] for r in old)<=set(r['path'] for r in new));self.assertIn('packages/db/migrations/'+m.repaired.MIGRATION,{r['path'] for r in new})
   self.assertFalse(m.repaired.active(types.SimpleNamespace()))
 def test_repair_context_and_contiguous_prefix_refusal(self):
  m=g.load('024');h=types.SimpleNamespace();r=m.repaired;r.activate(h,'024',ROOT)
  with self.assertRaises(RuntimeError):r.activate(h,'024',ROOT)
  with self.assertRaises(RuntimeError):r.names(h,[*m.NAMES,m.MIGRATION])
  h.relation_candidate_mode['applied']=True
  self.assertEqual(r.names(h,[*m.NAMES,m.MIGRATION])[-1],r.MIGRATION)
  with self.assertRaises(RuntimeError):r.names(h,[m.NAMES[1]])
  h.relation_candidate_mode['extra']=True
  with self.assertRaises(RuntimeError):r.active(h)
 def test_actual_all_seven_stage_compositions_keep32_and_exact_tests(self):
  for through in g.PROFILES:
   with self.subTest(through=through),tempfile.TemporaryDirectory(dir=ROOT/'.local') as tmp:
    selected,h,p=fixture(through,Path(tmp))
    with p:g.execute(h,selected)
    self.assertEqual(h.relation_candidate_mode['completed'],list(range(18,int(through)+1)))
    self.assertEqual(h.report['tests']['tests'],sum(r['expected'] for r in h.repaired_plan))
    self.assertTrue(all(r['mountedReadback']['startupAndExit'] for r in h.report['repairedNativeSuites']))
    migrations=[c for c in h.calls if c[0]=='migrate'];repair=next(i for i,c in enumerate(migrations) if c[1]=='relation-candidate-upgrade')
    self.assertTrue(all(selected.repaired.MIGRATION in c[2] for c in migrations[repair:]))
    self.assertEqual([c[2][-1] for c in migrations[:repair]],['015_approval_workflows.sql']*2+['016_glossary_publication.sql']*2+['017_relation_scope_candidates.sql']*2+['018_glossary_nominal_candidates.sql']*2)
    self.assertEqual(len(h.report['repairedNativeSuites']),len(h.repaired_plan))
 def test_default_historical_stage_does_not_apply32(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'.local') as tmp:
   selected,h,p=fixture('018',Path(tmp));h.relation_candidate_mode=None
   # Bypass only outer repaired-only native census, not the original stages.
   h.helper=lambda args,**kw:types.SimpleNamespace(returncode=0,stdout=tap(g.declarations([x for x in args if x.startswith('tests/')])) )
   with p:selected.execute(h)
   self.assertNotIn(selected.repaired.MIGRATION,[r['name'] for r in h.ledger]);self.assertNotIn('relationCandidateRepair',h.report)
 def test_missing_reordered_or_duplicate_stage_refuses(self):
  m=g.load('019');r=m.repaired;h=types.SimpleNamespace(report={});r.activate(h,'019',ROOT);h.relation_candidate_mode['applied']=True
  with self.assertRaises(RuntimeError):r.complete(h,[*m.NAMES,m.MIGRATION])
 def test_all_prior_ledger_fields_and32_are_preserved(self):
  m=g.load('019');h=types.SimpleNamespace();r=m.repaired;r.activate(h,'019',ROOT);h.relation_candidate_mode['applied']=True
  prior=inventory([*m.NAMES,r.MIGRATION]);current=sorted([*prior,*inventory([m.MIGRATION])],key=lambda r:r['name'])
  self.assertTrue(r.after(h,prior,current,m.NAMES,m.MIGRATION))
  for changed in ([x for x in current if x['name']!=r.MIGRATION],[{**x,'applied_at':'changed'} if x['name']==r.MIGRATION else x for x in current],[{**x,'checksum':'0'*64} if x['name']==m.MIGRATION else x for x in current]):
   with self.assertRaises(RuntimeError):r.after(h,prior,changed,m.NAMES,m.MIGRATION)
 def test_repair_only_function_body_change_and_replay_are_checked(self):
  for defect in ('acl','canonical','replay'):
   with self.subTest(defect=defect),tempfile.TemporaryDirectory(dir=ROOT/'.local') as tmp:
    selected,h,p=fixture('018',Path(tmp));h.ledger=inventory([*selected.NAMES,selected.MIGRATION]);original=h.migrate
    def migrate(path,**kw):
     result=original(path,**kw)
     if defect=='acl':h.functions[0]['acl']='changed'
     if defect=='replay' and h.phase=='relation-candidate-replay':result.stdout='Applied '+selected.repaired.MIGRATION
     if defect=='canonical':h.guards='changed'
     return result
    h.migrate=migrate
    with self.assertRaises(RuntimeError):selected.repaired.apply(h,[*selected.NAMES,selected.MIGRATION])
 def test_nonzero_native_returns_to_original_post_readback_and_refusal(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'.local') as tmp:
   selected,h,p=fixture('019',Path(tmp));h.failed_native='quality-native-tests'
   with p,self.assertRaisesRegex(RuntimeError,'Native quality execution suite failed'):selected.execute(h)
   rec=h.report['repairedNativeSuites'][-1];self.assertEqual(rec['exitStatus'],1);self.assertEqual(rec['tests']['fail'],1);self.assertEqual(rec['result'],'FAIL');self.assertIsNone(h.report['tests'])
   quality=[c for c in h.calls if c[0]=='command' and c[1]=='quality-native-tests'];self.assertEqual(len(quality),3)
   self.assertNotIn('--test',quality[-1][2]);self.assertTrue(h.report['sourceStages'][-1]['mountedModulesAfter'])
 def test_actual_nested_overrides_retained_and_no_undeclared_source(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'.local') as tmp:
   selected,h,p=fixture('024',Path(tmp))
   with p:g.execute(h,selected)
   records={r['phase']:r for r in h.report['repairedNativeSuites']}
   expected={'population-native-tests':'02513444534aa7cbed358235478bae0ea8cdd14e3dfd3b5fe5f76897c1e9dcf6','quality-native-tests':'b7ac63819810bf1df411307537d114525f284c489384e8db570626c92ccb2a08'}
   for phase,digest in expected.items():self.assertEqual(next(r['sha256'] for r in records[phase]['effectiveSources'] if r['path']=='apps/api/src/repository.ts'),digest)
   for rec in records.values():self.assertEqual(len(rec['effectiveSources']),len(h.repaired_frozen))
 def test_mount_refuses_duplicate_writeable_or_unapproved_file(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'.local') as tmp:
   p=Path(tmp)/'evil';p.write_text('tamper');rows=[{'path':'package.json','sha256':g.sha((ROOT/'package.json').read_bytes())}]
   for args in [['run','--volume',str(p)+':/app/package.json:rw','image'],['run','--volume',str(p)+':/app/package.json:ro','image'],['run','--volume',str(p)+':/app/package.json:ro','--volume',str(p)+':/app/package.json:ro','image']]:
    with self.assertRaises(RuntimeError):g.mounted_sources(args,len(args)-1,rows,{},Path(tmp))
 def test_partial_duplicate_skipped_or_malformed_tap_cannot_pass(self):
  self.assertIsNone(g.totals('# tests 1\n'));self.assertIsNone(g.totals(tap(['one'])+'# tests 1\n'))
  self.assertEqual(g.totals(tap(['one'],True))['fail'],1)
  self.assertIsNone(g.totals(tap(['one']).replace('# pass 1','# pass 0')))
 def test_actual_node_multifile_order_preserves_exact_unique_titles(self):
  node=shutil.which('node');self.assertIsNotNone(node)
  self.assertRegex(subprocess.run([node,'--version'],capture_output=True,text=True,check=True).stdout,r'^v24\.')
  with tempfile.TemporaryDirectory(dir=ROOT/'.local') as tmp:
   folder=Path(tmp);expected=['z first','z second','a first','a second'];files=[]
   for name,titles in [('z.test.cjs',expected[:2]),('a.test.cjs',expected[2:])]:
    p=folder/name;p.write_text("const test=require('node:test');\n"+''.join('test('+json.dumps(title)+',()=>{});\n' for title in titles));files.append(str(p))
   result=subprocess.run([node,'--test','--test-reporter=tap','--test-isolation=none','--test-concurrency=1',*files],capture_output=True,text=True,timeout=20)
   self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(g.totals(result.stdout),{'tests':4,'suites':0,'pass':4,'fail':0,'cancelled':0,'skipped':0,'todo':0})
   observed=g.native_titles(result.stdout,expected);self.assertNotEqual(observed,expected);self.assertEqual(observed,expected[2:]+expected[:2])
 def test_native_titles_reject_duplicate_missing_foreign_directive_number_or_plan(self):
  expected=['one','two'];good=tap(list(reversed(expected)))
  self.assertEqual(g.native_titles(good,expected),list(reversed(expected)))
  for output in (tap(['one','one']),tap(['one']),tap(['one','foreign']),good.replace('ok 1 - two','ok 1 - two # SKIP'),good.replace('ok 2 - one','ok 1 - one'),good.replace('1..2','1..3'),good+'1..2\n',good.replace('ok 2 - one','not ok 2 - one'),good+'not ok 3 - extra\n'):
   with self.subTest(output=output),self.assertRaises(RuntimeError):g.native_titles(output,expected)
 def test_proof_requires_both_events_exact_source_tools_and_config(self):
  rows=[{'path':'x','sha256':'a'*64}];good=proof(rows,'b'*64);self.assertTrue(g.observed_proofs(good,rows,'b'*64)['startupAndExit'])
  for value in (good.splitlines()[0],good+good,good.replace('v24.22.3','v20.0.0'),good.replace('"event": "exit"','"event": "start"'),good.replace('"config": "'+('b'*64)+'"','"config": "'+('c'*64)+'"')):
   with self.assertRaises(RuntimeError):g.observed_proofs(value,rows,'b'*64)
 def test_actual_node_verifier_rejects_startup_and_exit_tamper(self):
  node=shutil.which('node');self.assertIsNotNone(node,'Node required for verifier control')
  with tempfile.TemporaryDirectory(dir=ROOT/'.local') as tmp:
   p=Path(tmp);(p/'value').write_text('before');(p/'config').write_text('private');(p/'node_modules').symlink_to(ROOT/'node_modules',target_is_directory=True)
   rows=[{'path':'value','sha256':g.sha(b'before')}];body=g.verifier(rows,g.sha(b'private')).replace("'/app/'+r.path",json.dumps(str(p))+"+'/'+r.path").replace("'/run/authn-config.json'",json.dumps(str(p/'config')))
   probe=p/'probe.cjs';probe.write_text(body)
   (p/'actual.test.cjs').write_text("require('node:test')('actual owned native test runner',()=>{})");good=subprocess.run([node,'--require',str(probe),'--test','--test-reporter=tap',str(p/'actual.test.cjs')],capture_output=True,text=True);self.assertEqual(good.returncode,0,good.stderr);g.observed_proofs(good.stdout,rows,g.sha(b'private'))
   changed=subprocess.run([node,'--require',str(probe),'-e',"require('node:fs').writeFileSync("+json.dumps(str(p/'value'))+",'after')"],capture_output=True,text=True);self.assertNotEqual(changed.returncode,0);self.assertIn('REPAIRED_SOURCE_MISMATCH',changed.stderr)
   start=subprocess.run([node,'--require',str(probe),'-e','0'],capture_output=True,text=True);self.assertNotEqual(start.returncode,0)
 def test_cleanup_throw_unconditionally_removes_credentials(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'.local') as tmp:
   p=Path(tmp);secret=p/'private-config.json';secret.write_text('private');events=[]
   h=types.SimpleNamespace(folder=p,secret_path=secret,report={},resources_before={},cleanup=lambda:(_ for _ in ()).throw(TimeoutError()),save=lambda **kw:events.append(kw))
   self.assertTrue(g.finish(h,False));self.assertFalse(secret.exists());self.assertEqual(h.report['result'],'FAIL');self.assertTrue(h.report['cleanup']['generatedCredentialsRemoved']);self.assertNotIn('ownedRemoved',h.report['cleanup'])
 def test_same_selected_report_propagates_all_nested_constructors(self):
  for through in g.PROFILES:
   selected=g.load(through);h=g.harness_class(selected)(through)
   for m in g.ancestry(selected):
    if hasattr(m,'REPORT'):self.assertEqual(m.REPORT,selected.REPORT)
    if Path(m.__file__).name=='runtime-test-source-connectors-upgrade.py':break
   self.assertEqual(h.report['profile'],'isolated-governance-repaired-sql'+through)
   self.assertEqual(h.report['command'],'./dev test --suite '+g.PROFILES[through][1]);self.assertLess(h.deadline-time.monotonic(),600)
 def test_source_change_or_missing_helper_refuses(self):
  m=g.load('018');p=ROOT/'scripts/qualification_relation_candidate.py';original=p.read_bytes()
  try:
   before=g.sources(m);p.write_bytes(original+b'\n');self.assertNotEqual(g.sources(m),before)
   p.unlink()
   with self.assertRaises(Exception):g.sources(m)
  finally:p.write_bytes(original)

if __name__=='__main__':unittest.main()
