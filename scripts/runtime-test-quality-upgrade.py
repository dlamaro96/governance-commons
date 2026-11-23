#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SQL018→019 native quality execution upgrade; disposable PostgreSQL, no shared launch."""
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import re
import shutil

ROOT=Path(__file__).resolve().parents[1]
_pin_spec=importlib.util.spec_from_file_location('quality_sql019_binding',ROOT/'scripts/qualification_quality_sql019.py')
sql019=importlib.util.module_from_spec(_pin_spec);_pin_spec.loader.exec_module(sql019)
spec=importlib.util.spec_from_file_location('quality_upgrade_base',ROOT/'scripts/runtime-test-glossary-population-upgrade.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
repaired = base.repaired
REPORT=ROOT/'.local/evidence/quality-upgrade.json'
MIGRATION='019_quality_execution.sql'
NAMES=[*base.NAMES,base.MIGRATION]
TESTS=['tests/qualification/quality.test.ts']
require,sha=base.require,base.sha
REPOSITORY='apps/api/src/repository.ts'
REPOSITORY_TARGET='/app/'+REPOSITORY
PREDECESSOR_COMMIT='a3e1b674fb45c13a045286d05bc3c68012370872'
PREDECESSOR_BLOB='d741fdde750be30fec5062df4e813fc2a9cba877'
PREDECESSOR_SHA256='02513444534aa7cbed358235478bae0ea8cdd14e3dfd3b5fe5f76897c1e9dcf6'
PREDECESSOR_FIXTURE='tests/qualification/predecessors/repository-sql018.ts.txt'

def sources():
 paths={row['path'] for row in base.sources()}
 paths.add(PREDECESSOR_FIXTURE)
 paths.update(sql019.INPUTS)
 paths.update(['policies/quality_upgrade_diagnostics.py','policies/api_evidence.py','policies/authentication_evidence.py','policies/ci_evidence.py'])
 paths.update(['scripts/runtime-test-quality-upgrade.py',*TESTS,'packages/domain/src/quality-service.ts','packages/domain/src/quality.ts','packages/domain/src/quality-contracts.ts','packages/domain/src/glossary-service.ts','packages/db/migrations/'+MIGRATION,'apps/api/src/repository.ts','packages/domain/src/approval-service.ts','packages/domain/src/approval.ts','packages/domain/src/approval-contracts.ts','packages/domain/src/glossary.ts','packages/domain/src/glossary-contracts.ts','packages/domain/src/model-service.ts','packages/domain/src/cursor.ts'])
 pending=[ROOT/name for name in paths if name.endswith(('.ts','.tsx'))]
 while pending:
  current=pending.pop()
  source=current.read_text()+'\n'+sql019.historical_imports(ROOT,str(current.relative_to(ROOT)))
  for relative in re.findall(r'''(?:from\s*|import\s*)['"](\.[^'"]+)['"]''',source):
   candidate=(current.parent/relative).resolve()
   if not candidate.suffix:
    candidate=candidate.with_suffix('.ts') if candidate.with_suffix('.ts').is_file() else candidate/'index.ts'
   require(candidate.is_relative_to(ROOT) and candidate.is_file(),'Unresolved local qualification source')
   name=str(candidate.relative_to(ROOT))
   if name not in paths:paths.add(name);pending.append(candidate)
 return [{'path':name,'sha256':sha((ROOT/name).read_bytes())} for name in sorted(paths)]

class Harness(base.Harness):
 def __init__(self):
  self.repository_stage=None
  base.REPORT=REPORT
  super().__init__()
  self.report.update(command='./dev test --suite quality-upgrade',profile='isolated-quality-execution')

 def remember_quality_failure(self,error):
  # Diagnostics must not mask the original failed operation or skip its readback.
  try:self.remember_failure(error)
  except Exception:self.report.setdefault('quality_diagnostic_capture','UNAVAILABLE')

 def helper(self,args,*,mounts=(),**kwargs):
  if self.phase==sql019.PHASE:
   return sql019.run(self,self.repository_helper,args,root=ROOT,inventory=sources(),repository_phase=repository_phase,mounts=mounts,**kwargs)
  return self.repository_helper(args,mounts=mounts,**kwargs)

 def repository_helper(self,args,*,mounts=(),**kwargs):
  stage=self.repository_stage
  if stage is None:return super().helper(args,mounts=mounts,**kwargs)
  mounts=tuple(mounts)
  require(args and args[0]=='node','Repository phase check requires the fixed Node helper')
  require(all(target!=REPOSITORY_TARGET and not REPOSITORY_TARGET.startswith(target.rstrip('/')+'/')
              and target!='/app/quality-repository-check.cjs' for _,target in mounts),
          'Caller mount conflicts with the fixed repository phase')
  require(not stage['file'].is_symlink() and sha(stage['file'].read_bytes())==stage['sha256'],
          'Frozen repository phase source changed before execution')
  require(not stage['probe'].is_symlink() and sha(stage['probe'].read_bytes())==stage['probeSha256'],
          'Repository phase verifier changed before execution')
  extra=[(stage['probe'],'/app/quality-repository-check.cjs')]
  if stage['override']:extra.append((stage['file'],REPOSITORY_TARGET))
  check={'stage':stage['name'],'phase':self.phase,'repositorySha256':stage['sha256'],'verifierSha256':stage['probeSha256'],'result':'RUNNING'}
  self.report.setdefault('repositoryPhaseChecks',[]).append(check)
  try:
   # The inherited helper appends these exact read-only file mounts after its
   # ordinary source-directory mounts. Preload checks actual container bytes at
   # Node startup and exit, including each native test child process.
   result=super().helper([args[0],'--require','/app/quality-repository-check.cjs',*args[1:]],mounts=[*mounts,*extra],**kwargs)
   check.update(result='PASS' if result.returncode==0 else 'NONZERO',exitStatus=result.returncode)
   return result
  except BaseException:
   check['result']='FAIL'
   raise
  finally:
   require(not stage['file'].is_symlink() and sha(stage['file'].read_bytes())==stage['sha256'],
           'Frozen repository phase source changed during execution')
   require(not stage['probe'].is_symlink() and sha(stage['probe'].read_bytes())==stage['probeSha256'],
           'Repository phase verifier changed during execution')


def repository_phase(h,name,file,expected,override):
 probe=h.folder/(name+'-repository-check.cjs')
 body="const fs=require('node:fs'),crypto=require('node:crypto');\n"
 body+='const path='+json.dumps(REPOSITORY_TARGET)+',expected='+json.dumps(expected)+';\n'
 body+="function check(){if(crypto.createHash('sha256').update(fs.readFileSync(path)).digest('hex')!==expected)throw new Error('QUALITY_REPOSITORY_PHASE_MISMATCH');}\ncheck();process.on('exit',check);\n"
 with probe.open('x') as output:output.write(body)
 probe.chmod(0o444)
 return {'name':name,'file':file,'sha256':expected,'override':override,'probe':probe,'probeSha256':sha(body.encode())}


def predecessor_phase(h,frozen):
 h.phase='quality-predecessor-source'
 # Checked-in exact Git-blob bytes make this work in a clean shallow CI clone;
 # immutable origin was independently compared when this fixture was authored.
 fixture=ROOT/PREDECESSOR_FIXTURE
 require(not fixture.is_symlink() and fixture.is_file() and fixture.stat().st_size<=262144,
         'Immutable predecessor repository fixture is unavailable')
 with fixture.open('rb') as source:content=source.read(262145)
 require(0<len(content)<=262144 and sha(content)==PREDECESSOR_SHA256,'Immutable predecessor repository bytes differ')
 file=h.folder/'predecessor-repository.ts'
 with file.open('xb') as output:output.write(content)
 file.chmod(0o444)
 current=next(row['sha256'] for row in frozen if row['path']==REPOSITORY)
 original=base.sources()
 require(sum(row['path']==REPOSITORY for row in original)==1,'Predecessor source inventory omits the repository')
 effective=[{**row,'sha256':PREDECESSOR_SHA256} if row['path']==REPOSITORY else row for row in original]
 record={'stage':'SQL001-018-predecessor','result':'RUNNING','checkoutSources':original,'effectiveSources':effective,
         'override':{'path':REPOSITORY,'commit':PREDECESSOR_COMMIT,'gitBlob':PREDECESSOR_BLOB,'sha256':PREDECESSOR_SHA256,
                     'fixture':PREDECESSOR_FIXTURE,
                     'checkoutSha256':current,'privateFile':str(file.relative_to(ROOT)),'mountTarget':REPOSITORY_TARGET,'readOnly':True},
         'scope':'Only the repository module is the immutable predecessor; all other dependency/test bytes are the recorded checkout sources.'}
 h.report['sourceStages']=[record]
 h.repository_stage=repository_phase(h,'predecessor',file,PREDECESSOR_SHA256,True)
 h.save()
 try:
  # Full real predecessor execution remains mandatory; no test or security
  # assertion is bypassed to accommodate the later SQL019-only audit function.
  base.execute(h)
  require(base.sources()==original,'Predecessor checkout dependency or test source changed')
  record.update(result='PASS',effectiveSourcesAfter=effective)
 finally:
  h.repository_stage=None
  record['overrideReleased']=True
  record['privateFileSha256After']=sha(file.read_bytes())
  record['checkoutRepositorySha256After']=sha((ROOT/REPOSITORY).read_bytes())
  record['sourceHashesMatched']=record['privateFileSha256After']==PREDECESSOR_SHA256 and record['checkoutRepositorySha256After']==current
  if record['result']=='RUNNING':record['result']='FAIL'
  if not record['sourceHashesMatched']:record['result']='FAIL'
  require(record['sourceHashesMatched'],'Repository phase restoration readback differs')
  h.report['sources']=frozen
  h.save()


def canonical_snapshot(h,tables):
 """Hash every canonical row once, then sort only fixed-width row digests.

 Repeated predecessor population tests leave large revision payloads. A full
 jsonb_agg materializes those payloads together before hashing; reducing each
 row to 32 bytes first preserves multiset content/count comparisons without
 that unbounded intermediate JSON tree. Duplicate rows remain duplicated.
 """
 # Each batch uses one psql process and one read-only database snapshot. The
 # row-digest SQL and every table remain unchanged; only transport is batched.
 # Keep the inherited 120s command / 600s lifecycle / 4MiB output limits.
 require(type(tables) is list and len(tables)<=512,'Invalid fixed snapshot table inventory')
 for table in tables:
  require(isinstance(table,str) and re.fullmatch(r'[a-z_]+\.[a-z_]+',table),'Invalid fixed snapshot table')
 require(len(set(tables))==len(tables),'Invalid fixed snapshot table inventory')
 result={}
 for offset in range(0,len(tables),16):
  batch=tables[offset:offset+16]
  queries=[]
  for table in batch:
   queries.append(f"""WITH row_hashes AS MATERIALIZED (
   SELECT sha256(convert_to(to_jsonb(r)::text,'UTF8')) AS value FROM {table} r
  ) SELECT jsonb_build_object('table','{table}','rows',count(*),'sha256',encode(sha256(
   coalesce(string_agg(value,''::bytea ORDER BY value),''::bytea)),'hex')) FROM row_hashes;""")
  observed=h.sql_result('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n'+'\n'.join(queries)+'\nCOMMIT;',allow_failure=True)
  if observed.returncode:
   category='SQL_COMMAND_FAILED'
   for code,pattern in (
    ('CONNECTION_LOST',r'server closed the connection unexpectedly|connection to server was lost'),
    ('OUT_OF_MEMORY',r'out of memory|could not allocate memory'),
    ('STORAGE_FULL',r'no space left on device'),
    ('PERMISSION_DENIED',r'permission denied'),
   ):
    if re.search(pattern,observed.stderr,re.IGNORECASE):category=code;break
   # A failed batch never supplies a snapshot, even when earlier statements
   # succeeded. Report only its fixed inventory, never raw SQL/result/error text.
   h.report['qualitySnapshotFailure']={'tables':batch,'exitStatus':observed.returncode,'category':category}
   require(False,'Quality canonical snapshot failed; safe category retained')
  lines=observed.stdout.splitlines()
  require(len(lines)==len(batch),'Invalid canonical snapshot count')
  for table,line in zip(batch,lines):
   row=json.loads(line)
   require(isinstance(row,dict) and set(row)=={'table','rows','sha256'} and row['table']==table
           and type(row['rows']) is int and row['rows']>=0 and isinstance(row['sha256'],str)
           and re.fullmatch(r'[a-f0-9]{64}',row['sha256']),'Invalid canonical snapshot')
   result[table]={'rows':row['rows'],'sha256':row['sha256']}
 return result


def execute(h):
 frozen=sources()
 h.report['quality_diagnostic_sources']=frozen
 predecessor_phase(h,frozen)
 h.report['sources']=frozen
 h.phase='quality-predecessor'
 tables=json.loads(h.sql("SELECT json_agg(schemaname||'.'||tablename ORDER BY schemaname,tablename) FROM pg_tables WHERE schemaname IN('public','gc_authn','gc_authority') AND tablename<>'schema_migrations';"))
 before=canonical_snapshot(h,tables)
 ledger=json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;'))
 target=h.folder/'quality-target';target.mkdir()
 for name in repaired.names(h, [*NAMES,MIGRATION]):shutil.copyfile(base.MIGRATIONS/name,target/name)
 h.phase='quality-upgrade'
 result=h.migrate(target)
 require(re.findall(r'^Applied (.+)$',result.stdout,re.MULTILINE)==[MIGRATION],'Expected exact SQL019 application')
 require(canonical_snapshot(h,tables)==before,'Quality upgrade changed predecessor canonical/history rows')
 after=json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;'))
 require((repaired.after(h, ledger, after, NAMES, MIGRATION) if repaired.active(h) else len(ledger)==18 and after[:18]==ledger and len(after)==19),'Quality upgrade changed predecessor ledger')
 require('Applied' not in h.migrate(target).stdout and canonical_snapshot(h,tables)==before,'Quality replay changed predecessor rows')
 h.report['qualitySnapshotAlgorithm']='sha256 of sorted fixed-width SHA256 canonical row digests, with duplicate multiplicity and exact row count'
 h.report['qualityUpgradeBaseline']=[{'table':name,**row} for name,row in before.items()]
 h.report['checks'].append('Exact SQL018→019 application and inert replay preserve all predecessor canonical, protected, audit and receipt rows and original migration ledger')
 h.phase='quality-native-tests'
 expected=sum(len(re.findall(r'^test\(', (ROOT/name).read_text(),re.MULTILINE)) for name in TESTS)
 current=next(row['sha256'] for row in frozen if row['path']==REPOSITORY)
 require(expected==15,'Expected all fifteen original quality execution cases')
 stage={'stage':'SQL019-quality','result':'RUNNING','checkoutSources':frozen,'effectiveModuleSources':sql019.expected_sources(),'repositoryOverride':True,
        'scope':'Four exact ee21065 modules; all other inherited overlays remain bound by their own phase records.'}
 h.report['sourceStages'].append(stage)
 h.repository_stage=repository_phase(h,'current',ROOT/REPOSITORY,current,False)
 try:
  stage['mountedModulesBefore']=sql019.readback(h)
  tested=h.helper(['node','--import','tsx','--test','--test-reporter=tap','--test-concurrency=1',*TESTS],timeout=180,allow_failure=True)
  # Retain the failed suite before the mandatory source readback replaces last_command.
  if tested.returncode:h.remember_quality_failure(RuntimeError('Native quality suite returned nonzero'))
  stage['mountedModulesAfter']=sql019.readback(h)
  require(tested.returncode==0,'Native quality execution suite failed; retained bounded TAP identifies failing case')
  h.report['tests']=base.tap_summary(tested.stdout,expected)
  stage['checkoutSourcesAfter']=sources()
  require(stage['checkoutSourcesAfter']==frozen,'Quality test source changed during native execution')
  stage['result']='PASS'
 finally:
  h.repository_stage=None
  if stage['result']=='RUNNING':stage['result']='FAIL'
 require(sources()==frozen,'Quality execution source changed during native qualification')
 repaired.complete(h, [*NAMES, MIGRATION])
 h.report['migrations']=[{'name':name,'sha256':sha((base.MIGRATIONS/name).read_bytes())} for name in repaired.names(h, [*NAMES,MIGRATION])]
 h.report['limitations']=['Predecessor SQL001–018 tests mount the exact recorded immutable repository module; SQL019 tests bind exact ee21065 service/parser/contracts/repository with mounted readback and startup/exit checks. Outer predecessor module overlays retain their verified precedence; other dependencies/tests use the recorded checkout bytes.',
  'Approved quality execution storage and production domain-service paths; API/browser and Temporal restart qualification remain separate.','Canonical content authority remains inactive. No shared runtime or external infrastructure was modified.']

def main():
 h,failed=Harness(),False
 try:execute(h)
 except BaseException as error:
  failed=True;h.remember_quality_failure(error);h.report.update(failed_phase=h.phase,error_type=type(error).__name__,error='Inspect bounded private diagnostics')
 finally:
  try:
   h.phase='cleanup';h.cleanup()
   if h.resources_before is not None:
    h.deadline=h.cleanup_deadline;require(h.inventory()==h.resources_before,'Preexisting resource inventory changed');h.report['cleanup']['resourceInventoryPreserved']=True
  except BaseException as error:
   failed=True;h.remember_quality_failure(error);h.report.setdefault('failed_phase',h.phase);h.report['cleanupErrorType']=type(error).__name__
  h.report.update(result='FAIL' if failed else 'PASS',recorded_at=datetime.now(timezone.utc).isoformat(),evidence_directory=str(h.folder.relative_to(ROOT)))
  h.report['private_logs']=[{'path':str(p.relative_to(ROOT)),'sha256':sha(p.read_bytes())} for p in sorted(h.folder.glob('*.log'))];h.save(final=True)
 print(json.dumps({'result':h.report['result'],'report':str(REPORT.relative_to(ROOT))}));return int(failed)

if __name__=='__main__':raise SystemExit(main())
