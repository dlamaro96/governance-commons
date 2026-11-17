#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit repaired SQL018..024 chains; original entrypoints remain historical."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
PROBE='/app/governance-repaired-check.cjs'
MARKER='REPAIRED_SOURCE_V1 '
PROFILES={
 '018':('glossary-population','glossary-population-repaired-upgrade'),
 '019':('quality','quality-repaired-upgrade'),
 '020':('lineage','lineage-repaired-upgrade'),
 '021':('classification','classification-repaired-upgrade'),
 '022':('reference','reference-repaired-upgrade'),
 '023':('reference-quality','reference-quality-repaired-upgrade'),
 '024':('reference-structure','reference-structure-repaired-upgrade'),
}
SINGLE_PHASES={
 'runtime-test-approvals-upgrade.py':'approval-native-tests',
 'runtime-test-glossary-upgrade.py':'glossary-native-tests',
 'runtime-test-relation-scope-upgrade.py':'scope-native-tests',
 'runtime-test-glossary-population-upgrade.py':'population-native-tests',
 'runtime-test-quality-upgrade.py':'quality-native-tests',
 'runtime-test-lineage-upgrade.py':'lineage-native-tests',
 'runtime-test-classification-upgrade.py':'classification-native-tests',
 'runtime-test-reference-upgrade.py':'reference-native-tests',
}

def require(value,message):
 if not value:raise RuntimeError(message)
def sha(data):return hashlib.sha256(data).hexdigest()
def load(through):
 require(through in PROFILES,'Closed repaired profile required')
 path=ROOT/'scripts'/('runtime-test-'+PROFILES[through][0]+'-upgrade.py')
 spec=importlib.util.spec_from_file_location('repaired_selected_'+through,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def ancestry(selected):
 out=[];m=selected
 while hasattr(m,'__file__') and Path(m.__file__).name.startswith('runtime-test-'):
  require(m not in out,'Cyclic qualification modules');out.append(m)
  if not hasattr(m,'base'):break
  m=m.base
 return out

def source_file(path):
 require(path.is_relative_to(ROOT) and not path.is_symlink() and path.is_file() and path.stat().st_size<=8*1024*1024,'Unavailable bounded qualification source')
 return path

def sources(selected):
 paths={r['path'] for r in selected.sources()}
 paths.update(('scripts/runtime-test-governance-repaired-upgrade.py','scripts/qualification_relation_candidate.py','packages/db/migrations/'+selected.repaired.MIGRATION))
 # Keep the exact inherited dependency closure and bind the actual modules loaded
 # by its Python imports, including all fixed predecessor source verifiers.
 for m in ancestry(selected):paths.add(str(Path(m.__file__).relative_to(ROOT)))
 paths.update(('docs/execution/authentication-legacy-function-census.json','scripts/authentication-install.ts'))
 pending=[ROOT/p for p in paths if p.endswith(('.ts','.tsx'))]
 while pending:
  current=pending.pop()
  for relative in re.findall(r'''(?:from\s*|import\s*(?:\(\s*)?|require\s*\(\s*)['"](\.[^'"]+)['"]''',source_file(current).read_text()):
   candidate=Path(os.path.abspath(current.parent/relative))
   if candidate.suffix=='.js' and not candidate.is_file():candidate=candidate.with_suffix('.ts')
   if not candidate.suffix:candidate=candidate.with_suffix('.ts') if candidate.with_suffix('.ts').is_file() else candidate/'index.ts'
   candidate=source_file(candidate);name=str(candidate.relative_to(ROOT))
   if name not in paths:paths.add(name);pending.append(candidate)
 require(len(paths)<=512,'Bounded source inventory required')
 return [{'path':p,'sha256':sha(source_file(ROOT/p).read_bytes())} for p in sorted(paths)]

def declarations(files):
 out=[]
 for name in files:
  text=source_file(ROOT/name).read_text();titles=re.findall(r"^test\('([^'\n]+)'",text,re.M)
  require(len(titles)==len(re.findall(r'^test\(',text,re.M)) and titles,'Exact literal native declarations required')
  out.extend(titles)
 require(len(set(out))==len(out),'Duplicate native declaration');return out

def native_plan(selected):
 out=[]
 for m in reversed(ancestry(selected)):
  filename=Path(m.__file__).name
  if filename in SINGLE_PHASES:out.append({'phase':SINGLE_PHASES[filename],'files':list(m.TESTS)})
  elif filename=='runtime-test-reference-quality-upgrade.py':
   out.extend([{'phase':'reference-quality-completeness-tests','files':list(m.COMPLETENESS_TESTS)}, {'phase':'reference-quality-native-tests','files':list(m.TESTS)}])
  elif filename=='runtime-test-reference-structure-upgrade.py':
   out.extend([{'phase':'structure-reference-tests','files':['tests/api/reference-data-storage.test.ts']},
               {'phase':'structure-reference-quality-tests','files':['tests/api/reference-quality-storage.test.ts']},
               {'phase':'structure-native-tests','files':list(m.TESTS)}])
 return [{**r,'titles':declarations(r['files']),'expected':len(declarations(r['files']))} for r in out]

def allowed_pins(selected):
 pins={}
 def add(path,digest):pins.setdefault(path,set()).add(digest)
 for m in ancestry(selected):
  for row in [*getattr(m,'PREDECESSORS',()),*getattr(m,'NATIVE_BINDINGS',())]:add(row['path'],row['sha256'])
  if hasattr(m,'sql019'):
   for path,row in m.sql019.BINDINGS.items():add(path,row[1])
  for attr,field in [('repository','REPOSITORY'),('approval_binding','SERVICE')]:
   if hasattr(m,attr):binding=getattr(m,attr);add(getattr(binding,field),binding.DIGEST)
 return pins

def totals(output):
 values={}
 for key in ('tests','suites','pass','fail','cancelled','skipped','todo'):
  found=re.findall(r'^# '+key+r' (\d+)$',output,re.M)
  if len(found)!=1:return None
  values[key]=int(found[0])
 if values['tests']!=sum(values[k] for k in ('pass','fail','cancelled','skipped','todo')):return None
 return values

def native_titles(output,expected):
 # Node may sort files independently of argv. Require every exact declaration
 # once, in the same emitted Subtest/result sequence, with contiguous TAP IDs.
 titles=re.findall(r'^# Subtest: (.+)$',output,re.M)
 results=re.findall(r'^(ok|not ok) ([0-9]+) - (.+)$',output,re.M)
 passed=[(i,title) for status,i,title in results if status=='ok']
 require(len(results)==len(expected) and len(titles)==len(expected) and len(set(titles))==len(titles)
   and set(titles)==set(expected) and [t for _,t in passed]==titles
   and [int(i) for i,_ in passed]==list(range(1,len(expected)+1))
   and re.findall(r'^1\.\.([0-9]+)$',output,re.M)==[str(len(expected))],
   'Exact native declaration identities differ')
 return titles

def verifier(rows,config):
 # Each actual Node process verifies every final mounted byte at startup/exit.
 # Only digests and tool identities are emitted; no configuration values/code.
 return """const fs=require('node:fs'),c=require('node:crypto');
const rows=ROWS,config=CONFIG,hash=x=>c.createHash('sha256').update(x).digest('hex');
function check(event){const actual=rows.map(r=>({path:r.path,sha256:hash(fs.readFileSync('/app/'+r.path))}));
if(JSON.stringify(actual)!==JSON.stringify(rows)||hash(fs.readFileSync('/run/authn-config.json'))!==config)throw new Error('REPAIRED_SOURCE_MISMATCH');
const tools={node:{version:process.version,sha256:hash(fs.readFileSync(process.execPath))},tsx:{version:require('tsx/package.json').version,sha256:hash(fs.readFileSync(require.resolve('tsx')))}};
if(!/^v24\\.\\d+\\.\\d+$/.test(tools.node.version))throw new Error('REPAIRED_TOOL_MISMATCH');
console.log('# REPAIRED_SOURCE_V1 '+JSON.stringify({event,pid:process.pid,manifest:hash(JSON.stringify(actual)),config,tools}));}
check('start');process.on('exit',()=>check('exit'));
""".replace('ROWS',json.dumps(rows,separators=(',',':'))).replace('CONFIG',json.dumps(config))

def observed_proofs(output,rows,config):
 frames=[]
 for line in output.splitlines():
  matched=re.fullmatch(r'(?:# )*REPAIRED_SOURCE_V1 (.+)',line)
  if matched:
   value=json.loads(matched[1]);require(type(value) is dict and set(value)=={'event','pid','manifest','config','tools'}
    and value['event'] in ('start','exit') and type(value['pid']) is int and value['pid']>0
    and value['manifest']==sha(json.dumps(rows,separators=(',',':')).encode()) and value['config']==config,'Malformed mounted-byte proof')
   require(type(value['tools']) is dict and set(value['tools'])=={'node','tsx'},'Malformed tool proof')
   for key in ('node','tsx'):
    tool=value['tools'][key];require(type(tool) is dict and set(tool)=={'version','sha256'} and type(tool['version']) is str
      and re.fullmatch(r'[a-f0-9]{64}',tool['sha256']),'Malformed tool identity')
   require(re.fullmatch(r'v24\.\d+\.\d+',value['tools']['node']['version']),'Pinned Node required');frames.append(value)
 require(2<=len(frames)<=256 and all(v['tools']==frames[0]['tools'] for v in frames),'Missing/inconsistent source tool proofs')
 for pid in {v['pid'] for v in frames}:
  require([v['event'] for v in frames if v['pid']==pid]==['start','exit'],'Missing or duplicate process source proof')
 return {'processes':len(frames)//2,'manifestSha256':frames[0]['manifest'],'configSha256':config,'tools':frames[0]['tools'],'startupAndExit':True}

def mounted_sources(args,offset,frozen,pins,folder):
 mounts=[]
 for i,value in enumerate(args[:offset]):
  if value=='--volume':
   parts=args[i+1].rsplit(':',2);require(len(parts)==3 and parts[2]=='ro','Read-only helper mounts required')
   mounts.append((Path(parts[0]),parts[1]))
 require(len({target for _,target in mounts})==len(mounts),'Duplicate helper target')
 effective=[];extra=[]
 for row in frozen:
  target='/app/'+row['path'];cover=[(host,dest) for host,dest in mounts if target==dest or target.startswith(dest.rstrip('/')+'/')]
  if not cover:
   actual=ROOT/row['path'];extra.extend(['--volume',str(actual)+':'+target+':ro'])
  else:
   host,dest=max(cover,key=lambda r:len(r[1]));actual=host if dest==target else host/target[len(dest)+1:]
  require((actual.is_relative_to(ROOT) or actual.is_relative_to(folder)) and not actual.is_symlink() and actual.is_file(),'Invalid effective mounted source')
  digest=sha(actual.read_bytes());require(digest==row['sha256'] or digest in pins.get(row['path'],set()),'Undeclared mounted source substitution')
  effective.append({'path':row['path'],'sha256':digest})
 return effective,extra

def harness_class(selected):
 class Harness(selected.Harness):
  def __init__(self,through):
   require(through in PROFILES,'Closed repaired profile required')
   self.repaired_through=through;self.repaired_suite=PROFILES[through][1]
   self.repaired_frozen=sources(selected);self.repaired_plan=native_plan(selected);self.repaired_pins=allowed_pins(selected)
   selected.REPORT=ROOT/'.local/evidence'/(self.repaired_suite+'.json')
   super().__init__();selected.repaired.activate(self,through,ROOT)
   self.report.update(repairedCheckoutSources=self.repaired_frozen,repairedNativePlan=self.repaired_plan,repairedNativeSuites=[])
   self.save()
  def save(self,*,final=False):
   self.report.update(command='./dev test --suite '+self.repaired_suite,profile='isolated-governance-repaired-sql'+self.repaired_through,
       qualification='EXPLICIT_REPAIRED_CHAIN',historicalOutcome='HISTORICAL_NOT_EXECUTED',through=self.repaired_through)
   return super().save(final=final)
  def docker(self,*args,**kwargs):
   # Inspect the FINAL command after every inherited immutable-source wrapper.
   # No wrapper, mount or predecessor assertion is bypassed/reimplemented.
   if not (args and args[0]=='run' and getattr(self,'app_image',None) in args and '--test' in args):return super().docker(*args,**kwargs)
   require(sources(selected)==self.repaired_frozen,'Checkout source changed before native suite')
   offset=args.index(self.app_image);argv=list(args[offset+1:]);require(argv and argv[0]=='node','Fixed Node suite required')
   plan=[p for p in self.repaired_plan if p['phase']==self.phase];require(len(plan)==1,'Undeclared native phase')
   plan=plan[0];seen=self.report['repairedNativeSuites'];require(len(seen)<len(self.repaired_plan) and self.repaired_plan[len(seen)]==plan,'Skipped/reordered/repeated native phase')
   files=[x for x in argv if x.startswith('tests/')];require(files==plan['files'],'Native test file inventory differs')
   if self.phase=='population-native-tests' or self.phase in [r['phase'] for r in self.repaired_plan if self.repaired_plan.index(r)>3]:
    require(self.relation_candidate_mode['applied'],'Population/later suite cannot precede SQL032')
   rows,extra=mounted_sources(args,offset,self.repaired_frozen,self.repaired_pins,self.folder)
   require(PROBE not in args and not any(PROBE in x for x in args[:offset]),'Conflicting repaired verifier')
   config=sha(self.secret_path.read_bytes());body=verifier(rows,config).encode();probe=self.folder/('repaired-source-'+str(len(seen))+'.cjs')
   with probe.open('xb') as f:f.write(body)
   probe.chmod(0o444)
   self.report['tests']=None
   record={'phase':self.phase,'files':files,'expected':plan['expected'],'tests':None,'exitStatus':None,'result':'RUNNING',
       'checkoutSources':self.repaired_frozen,'effectiveSources':rows,'verifierSha256':sha(body)};seen.append(record)
   command=[*args[:offset],*extra,'--volume',str(probe)+':'+PROBE+':ro',self.app_image,argv[0],'--require',PROBE,*argv[1:]]
   try:
    result=super().docker(*command,**kwargs);record.update(tests=totals(result.stdout),exitStatus=result.returncode,result='FAIL')
    if result.returncode!=0:
     if hasattr(self,'remember_quality_failure'):self.remember_quality_failure(RuntimeError('Native suite failed'))
     try:record['mountedReadback']=observed_proofs(result.stdout,rows,config)
     except BaseException as e:record['sourceProofErrorType']=type(e).__name__
     return result  # Preserve inherited mandatory post-helper readback/refusal.
    record['mountedReadback']=observed_proofs(result.stdout,rows,config)
    require(record['tests'] is not None and record['tests']['tests']==plan['expected']
      and record['tests']['pass']==plan['expected'] and all(record['tests'][k]==0 for k in ('fail','cancelled','skipped','todo')),'Repaired native suite failed')
    record['observedTitles']=native_titles(result.stdout,plan['titles'])
    record['result']='PASS';return result
   except BaseException:
    record['result']='FAIL';raise
   finally:
    require(sha(probe.read_bytes())==sha(body) and sources(selected)==self.repaired_frozen,'Native source/probe changed')
    record['sourceHashesMatched']=True
 return Harness

def execute(h,selected):
 selected.execute(h)
 require(sources(selected)==h.repaired_frozen,'Final repaired checkout differs')
 require(h.relation_candidate_mode['completed']==list(range(18,int(h.repaired_through)+1)),'Every repaired stage required')
 suites=h.report['repairedNativeSuites'];require(len(suites)==len(h.repaired_plan) and all(r['result']=='PASS' for r in suites),'Every inherited native suite required')
 total=sum(r['tests']['tests'] for r in suites)
 h.report.update(tests={'tests':total,'suites':0,'pass':total,'fail':0,'cancelled':0,'skipped':0,'todo':0},repairedSourceHashesMatched=True)
 h.report['limitations']=[*h.report.get('limitations',[]),'Explicit repaired chain: SQL032 executes after original SQL017→018 preservation/replay and before all26 original population assertions; later prefixes retain the same032 ledger row. This does not relabel historical018-only failures.', 'Every inherited stage executes with its exact original test declarations and product budgets; immutable source-module overrides retain their existing precedence. No shared runtime, source worker, API or browser qualification is inferred.']

def finish(h,failed):
 try:
  h.phase='cleanup';h.cleanup()
  if h.resources_before is not None:
   h.deadline=h.cleanup_deadline;require(h.inventory()==h.resources_before,'Preexisting inventory changed');h.report.setdefault('cleanup',{})['resourceInventoryPreserved']=True
 except BaseException as e:
  failed=True
  if hasattr(h,'remember_quality_failure'):h.remember_quality_failure(e)
  h.report.setdefault('failed_phase',h.phase);h.report['cleanupErrorType']=type(e).__name__
 finally:
  try:h.secret_path.unlink(missing_ok=True);require(not h.secret_path.exists(),'Private credential remains');h.report.setdefault('cleanup',{})['generatedCredentialsRemoved']=True
  except BaseException as e:
   failed=True
   if hasattr(h,'remember_quality_failure'):h.remember_quality_failure(e)
   h.report.setdefault('failed_phase',h.phase);h.report['credentialCleanupErrorType']=type(e).__name__
 h.report.update(result='FAIL' if failed else 'PASS',recorded_at=datetime.now(timezone.utc).isoformat(),evidence_directory=str(h.folder.relative_to(ROOT)))
 h.report['private_logs']=[{'path':str(p.relative_to(ROOT)),'sha256':sha(p.read_bytes())} for p in sorted(h.folder.glob('*.log'))];h.save(final=True);return failed

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run-local',action='store_true');parser.add_argument('--through',choices=tuple(PROFILES),required=True);args=parser.parse_args();require(args.run_local,'Explicit local admission required')
 selected=load(args.through);h=harness_class(selected)(args.through);failed=False
 try:execute(h,selected)
 except BaseException as e:
  failed=True
  if hasattr(h,'remember_quality_failure'):h.remember_quality_failure(e)
  h.report.update(failed_phase=h.phase,error_type=type(e).__name__,error='Inspect bounded private phase evidence')
 failed=finish(h,failed);print(json.dumps({'result':h.report['result'],'through':args.through,'report':str(selected.REPORT.relative_to(ROOT))}));return int(failed)
if __name__=='__main__':raise SystemExit(main())
