#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Populated SQL035-to036 scope alignment and inactive held metadata evaluation."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
REPORT=ROOT/'.local/evidence/held-metadata-authority.json'
MIGRATION='036_authority_scope_alignment.sql'
PREFLIGHT='tests/qualification/authority-scope-preflight.test.ts'
SEED='tests/qualification/authority-scope-legacy-seed.test.ts'
SCOPE='tests/qualification/authority-scope-alignment.test.ts'
HELD='tests/qualification/held-metadata-evaluation.test.ts'
PREFLIGHT_PHASE='scope-alignment-preflight'
SEED_PHASE='scope-alignment-legacy-seed'
SCOPE_PHASE='scope-alignment-native'
HELD_PHASE='held-metadata-authority-native'
EXECUTION_SECONDS=780
CLEANUP_SECONDS=90
WRAPPER_SECONDS=900

def module(path,name):
 spec=importlib.util.spec_from_file_location(name,path);result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
predecessor=module(ROOT/'scripts/runtime-test-reviewed-classification-producer.py','held_metadata_predecessor')
read,authority,volume=predecessor.read,predecessor.authority,predecessor.volume
require,sha=predecessor.require,predecessor.sha
_original_sources=predecessor.sources
NAMES=[*predecessor.NAMES,MIGRATION]
PHASES=(*predecessor.PHASES,PREFLIGHT_PHASE,SEED_PHASE,SCOPE_PHASE,HELD_PHASE)
EXPECTED_HELD_TESTS=17
FUNCTIONS=read.FUNCTIONS.replace("'signature',p.oid::regprocedure::text", "'metadata',to_jsonb(p)-'prosrc','oid',p.oid::text,'signature',p.oid::regprocedure::text")
SIGNATURES={'source_guard':'gc_authority.source_guard()',
 'validate_grant':'gc_authority.validate_grant(uuid,uuid,boolean)',
 'validate_read_grants_v1':'gc_authority.validate_read_grants_v1(uuid,uuid[])'}

def sources():
 require(sorted(p.name for p in (ROOT/'packages/db/migrations').glob('*.sql'))==NAMES,'Exactly immutable SQL001–036 required')
 paths={r['path'] for r in _original_sources()}|{PREFLIGHT,SEED,SCOPE,HELD,
  'scripts/runtime-test-held-metadata-authority.py','scripts/test_held_metadata_authority.py',
  'packages/db/migrations/'+MIGRATION}
 pending=[ROOT/p for p in paths if p.endswith(('.ts','.tsx'))]
 while pending:
  current=pending.pop()
  for name in re.findall(r'''(?:from\s*|import\s*(?:\(\s*)?|require\s*\(\s*)['"](\.[^'"]+)['"]''',volume.source_file(current).read_text()):
   candidate=Path(os.path.abspath(current.parent/name))
   if candidate.suffix=='.js' and not candidate.exists():candidate=candidate.with_suffix('.ts')
   if not candidate.suffix:candidate=candidate.with_suffix('.ts') if candidate.with_suffix('.ts').exists() else candidate/'index.ts'
   candidate=volume.source_file(candidate);rel=str(candidate.relative_to(ROOT))
   if rel not in paths:
    paths.add(rel)
    if candidate.suffix in ('.ts','.tsx'):pending.append(candidate)
 require(len(paths)<=1024,'Qualification source inventory exceeds bound')
 return [{'path':p,'sha256':sha(volume.source_file(ROOT/p).read_bytes())} for p in sorted(paths)]

predecessor.sources=sources
volume.sources=sources
volume.PHASES=PHASES
volume.effective_sources=lambda rows,phase:rows if phase in PHASES else (_ for _ in ()).throw(RuntimeError('Undeclared native phase'))

def marker_from_tap(output):
 matches=re.findall(r'^# GC_SCOPE_LEGACY_V1=(.+)$',output,re.M)
 require(len(matches)==1,'Exactly one source-bound legacy seed marker required')
 value=json.loads(matches[0])
 require(type(value) is dict and set(value)=={'formatVersion','profile','tenantId','grants'}
  and value['formatVersion']==1 and value['profile']=='scope-alignment-sql035-legacy'
  and re.fullmatch(r'[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}',value['tenantId']), 'Invalid legacy seed marker')
 grants=value['grants'];require(type(grants) is list and len(grants)==9,'Exactly nine retained legacy heads required')
 kinds={'reverse-own','future-reverse-own','expired-reverse-own','child-effect-lifetime','child-onward-lifetime','revoked-bad-ancestor'}
 for row in grants:
  require(type(row) is dict and set(row)=={'id','kind','mustRefuse','headSha256'}
   and re.fullmatch(r'[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}',row['id'])
   and row['kind'] in kinds and type(row['mustRefuse']) is bool
   and re.fullmatch(r'[a-f0-9]{64}',row['headSha256']), 'Invalid retained legacy head')
 require(len({r['id'] for r in grants})==9 and {r['kind'] for r in grants}==kinds
  and sum(r['mustRefuse'] for r in grants)==7,'Legacy seed coverage differs')
 return value

class Harness(predecessor.Harness):
 def __init__(self):
  predecessor.REPORT=REPORT
  predecessor.sources=sources
  super().__init__()
  self.legacy_marker=None
  self.report.update(command='python3 scripts/runtime-test-held-metadata-authority.py --run-local',
   profile='isolated-held-metadata-authority-sql036')
  self.save(final=True)
 def helper(self,args,**kwargs):
  result=super().helper(args,**kwargs)
  if self.phase==SEED_PHASE and '--test' in args:
   require(result.returncode==0,'Native legacy seed failed')
   self.legacy_marker=marker_from_tap(result.stdout)
  return result

def expected_function_bodies():
 source=(ROOT/'packages/db/migrations'/MIGRATION).read_text();result={}
 for name,signature in SIGNATURES.items():
  blocks=re.findall(r'EXECUTE \$replace_'+name+r'\$(.*?)\$replace_'+name+r'\$;',source,re.S)
  require(len(blocks)==1,'Exactly one admitted replacement required')
  bodies=re.findall(r'\bAS \$\$(.*?)\$\$;',blocks[0],re.S)
  require(len(bodies)==1 and blocks[0].count('CREATE OR REPLACE FUNCTION ')==1,'Exact replacement body required')
  result[signature]=hashlib.md5(bodies[0].encode()).hexdigest()
 require(source.count('CREATE OR REPLACE FUNCTION ')==3,'Undeclared function replacement')
 return result

def preserve_installation(before_tables,before_functions,before_privileges,before_triggers,
                          after_tables,after_functions,after_privileges,after_triggers):
 require(after_tables==before_tables,'Scope repair changed table inventory')
 require(after_privileges==before_privileges,'Scope repair changed privileges or RLS')
 require(after_triggers==before_triggers,'Scope repair changed trigger definitions')
 old={r['signature']:r for r in before_functions};new={r['signature']:r for r in after_functions}
 require(len(old)==len(before_functions) and len(new)==len(after_functions) and set(old)==set(new),'Scope repair changed function inventory')
 expected=expected_function_bodies();require(set(expected)<=set(old),'Required original functions missing')
 for signature,row in old.items():
  wanted=dict(row)
  if signature in expected:
   require(row['body']!=expected[signature],'Scope repair must replace the original body')
   wanted['body']=expected[signature]
  require(new[signature]==wanted,'Function differs beyond exact admitted body replacement')

def execute(h):
 require(EXPECTED_HELD_TESTS>0,'Held native suite must be integrated before execution')
 predecessor.execute(h)
 h.report['predecessor035']={key:h.report[key] for key in ('installation','populatedReplay','nativeTotals')}
 # Allocate every later principal before the036 preservation baseline.
 h.phase='held-metadata-test-principals';read.additional_roles(h,192)
 read.config_offset(h,128);volume.native_suite(h,PREFLIGHT_PHASE,PREFLIGHT,8)
 read.config_offset(h,136);volume.native_suite(h,SEED_PHASE,SEED,1)
 require(h.legacy_marker is not None,'Native legacy marker missing')
 config=json.loads(h.secret_path.read_text());require('authorityScopeLegacyFixtures' not in config,'Legacy seed marker already set')
 config['authorityScopeLegacyFixtures']=[h.legacy_marker]
 h.secret_path.write_text(json.dumps(config));h.secret_path.chmod(0o600)
 h.report['privateConfigSha256']=sha(h.secret_path.read_bytes())
 h.report['legacyScopeSeed']={'retainedHeads':9,'incompatibleHeads':7,'compatibleParents':2,
  'markerSha256':sha(json.dumps(h.legacy_marker,sort_keys=True).encode()),'sourceBound':True}
 target=h.folder/'scope-alignment-target';target.mkdir()
 for name in NAMES:shutil.copyfile(ROOT/'packages/db/migrations'/name,target/name)
 h.phase='scope-alignment-before036'
 tables=volume.canonical_tables(h);before=read.snapshot(h,tables);prior=read.ledger(h,predecessor.NAMES)
 functions=json.loads(h.sql(FUNCTIONS));privileges=json.loads(h.sql(predecessor.predecessor.PRIVILEGES));triggers=json.loads(h.sql(predecessor.predecessor.TRIGGERS))
 h.phase='scope-alignment-install036'
 require(re.findall(r'^Applied (.+)$',h.migrate(target).stdout,re.M)==[MIGRATION],'Exactly036 must apply')
 ledger=read.ledger(h,NAMES);current_tables=volume.canonical_tables(h)
 current_functions=json.loads(h.sql(FUNCTIONS));current_privileges=json.loads(h.sql(predecessor.predecessor.PRIVILEGES));current_triggers=json.loads(h.sql(predecessor.predecessor.TRIGGERS))
 preserve_installation(tables,functions,privileges,triggers,current_tables,current_functions,current_privileges,current_triggers)
 require(ledger[:-1]==prior and read.snapshot(h,tables)==before,'SQL036 changed prior rows/epochs/ledger')
 h.report['installation']={'before':before,'priorLedger':prior,'ledger':ledger,'preservation':True,
  'changedFunctionBodies':expected_function_bodies(),'functionIdentitiesPreserved':True,
  'functionsBeforeSha256':sha(json.dumps(functions,sort_keys=True).encode()),
  'functionsAfterSha256':sha(json.dumps(current_functions,sort_keys=True).encode()),
  'privilegesSha256':sha(json.dumps(privileges,sort_keys=True).encode()),
  'triggersSha256':sha(json.dumps(triggers,sort_keys=True).encode())}
 def replay(phase):
  h.phase=phase;snapshot=read.snapshot(h,current_tables)
  checks=h.report.setdefault('replayChecks',{}).setdefault(phase,{})
  def checked(name,passed):checks[name]=bool(passed);require(passed,'Replay changed '+name)
  checked('migrationNoop','Applied' not in h.migrate(target).stdout)
  checked('ledgerPreserved',read.ledger(h,NAMES)==ledger)
  checked('tableInventoryPreserved',volume.canonical_tables(h)==current_tables)
  checked('rowsPreserved',read.snapshot(h,current_tables)==snapshot)
  checked('functionsPreserved',json.loads(h.sql(FUNCTIONS))==current_functions)
  checked('privilegesPreserved',json.loads(h.sql(predecessor.predecessor.PRIVILEGES))==current_privileges)
  checked('triggersPreserved',json.loads(h.sql(predecessor.predecessor.TRIGGERS))==current_triggers)
  return snapshot
 replay('scope-alignment-replay-before');h.report['installation']['replayBefore']=True
 read.config_offset(h,137);volume.native_suite(h,SCOPE_PHASE,SCOPE,16)
 read.config_offset(h,153);volume.native_suite(h,HELD_PHASE,HELD,EXPECTED_HELD_TESTS)
 populated=replay('held-metadata-populated-replay')
 require(sources()==h.frozen and [r['phase'] for r in h.report['nativeSuites']]==list(PHASES),'Source or phase drifted')
 h.report.update(sources=h.frozen,migrations=ledger,sourceHashesMatched=True,
  nativeTotals={key:sum(r['tests'][key] for r in h.report['nativeSuites']) for key in ('tests','pass','fail','cancelled','skipped','todo')},
  populatedReplay={'snapshot':populated,'preservation':True},
  limitations=['Held metadata evaluation remains an inactive diagnostic; no effect capability or content API activation.',
   'The98 predecessor cases execute before036; historical SQL031 body/cache qualifications are not silently relabelled.',
   'One780-second execution deadline includes source admission and all schemas;90-second owned cleanup inside900-second wrapper.',
   'Cached dependencies and exact current read-only mounts; no live-vendor or release qualification.'])

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run-local',action='store_true');args=parser.parse_args()
 require(args.run_local,'Explicit --run-local required');h=Harness();failed=False
 try:execute(h)
 except BaseException as error:
  failed=True;h.report.update(failed_phase=h.phase,error_type=type(error).__name__,error='Inspect bounded private evidence')
 finally:
  try:
   h.phase='cleanup';h.cleanup()
   if h.resources_before is not None:
    observed=h.inventory();(h.folder/'resources-after.json').write_text(json.dumps(observed,sort_keys=True)+'\n')
    require(observed==h.resources_before,'Preexisting resource inventory changed');h.report['cleanup']['resourceInventoryPreserved']=True
  except BaseException as error:failed=True;h.report['cleanupErrorType']=type(error).__name__
  finally:
   try:
    h.secret_path.unlink(missing_ok=True);require(not h.secret_path.exists(),'Generated credential cleanup refused');h.report.setdefault('cleanup',{})['generatedCredentialsRemoved']=True
   except BaseException as error:
    failed=True;h.report.setdefault('cleanup',{})['generatedCredentialsRemoved']=False;h.report['credentialCleanupErrorType']=type(error).__name__
  h.report.update(result='FAIL' if failed else 'PASS',recorded_at=datetime.now(timezone.utc).isoformat(),evidence_directory=str(h.folder.relative_to(ROOT)))
  h.report['private_logs']=[{'path':str(p.relative_to(ROOT)),'sha256':sha(p.read_bytes())} for p in sorted(h.folder.glob('*.log'))];h.save(final=True)
 print(json.dumps({'result':h.report['result'],'report':str(REPORT.relative_to(ROOT))}));return int(failed)
if __name__=='__main__':raise SystemExit(main())
