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
spec=importlib.util.spec_from_file_location('quality_upgrade_base',ROOT/'scripts/runtime-test-glossary-population-upgrade.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
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
 paths.update(['scripts/runtime-test-quality-upgrade.py',*TESTS,'packages/domain/src/quality-service.ts','packages/domain/src/quality.ts','packages/domain/src/quality-contracts.ts','packages/domain/src/glossary-service.ts','packages/db/migrations/'+MIGRATION,'apps/api/src/repository.ts','packages/domain/src/approval-service.ts','packages/domain/src/approval.ts','packages/domain/src/approval-contracts.ts','packages/domain/src/glossary.ts','packages/domain/src/glossary-contracts.ts','packages/domain/src/model-service.ts','packages/domain/src/cursor.ts'])
 pending=[ROOT/name for name in paths if name.endswith(('.ts','.tsx'))]
 while pending:
  current=pending.pop()
  for relative in re.findall(r'''(?:from\s*|import\s*)['"](\.[^'"]+)['"]''',current.read_text()):
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

 def helper(self,args,*,mounts=(),**kwargs):
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
 result={}
 for table in tables:
  require(re.fullmatch(r'[a-z_]+\.[a-z_]+',table),'Invalid fixed snapshot table')
  query=f"""WITH row_hashes AS MATERIALIZED (
   SELECT sha256(convert_to(to_jsonb(r)::text,'UTF8')) AS value FROM {table} r
  ) SELECT jsonb_build_object('rows',count(*),'sha256',encode(sha256(
   coalesce(string_agg(value,''::bytea ORDER BY value),''::bytea)),'hex')) FROM row_hashes;"""
  observed=h.sql_result(query,allow_failure=True)
  if observed.returncode:
   category='SQL_COMMAND_FAILED'
   for code,pattern in (
    ('CONNECTION_LOST',r'server closed the connection unexpectedly|connection to server was lost'),
    ('OUT_OF_MEMORY',r'out of memory|could not allocate memory'),
    ('STORAGE_FULL',r'no space left on device'),
    ('PERMISSION_DENIED',r'permission denied'),
   ):
    if re.search(pattern,observed.stderr,re.IGNORECASE):category=code;break
   h.report['qualitySnapshotFailure']={'table':table,'exitStatus':observed.returncode,'category':category}
   require(False,'Quality canonical snapshot failed; safe category retained')
  row=json.loads(observed.stdout.strip())
  require(isinstance(row,dict) and set(row)=={'rows','sha256'} and type(row['rows']) is int and row['rows']>=0
          and isinstance(row['sha256'],str) and re.fullmatch(r'[a-f0-9]{64}',row['sha256']),'Invalid canonical snapshot')
  result[table]=row
 return result


def execute(h):
 frozen=sources()
 predecessor_phase(h,frozen)
 h.report['sources']=frozen
 h.phase='quality-predecessor'
 tables=json.loads(h.sql("SELECT json_agg(schemaname||'.'||tablename ORDER BY schemaname,tablename) FROM pg_tables WHERE schemaname IN('public','gc_authn','gc_authority') AND tablename<>'schema_migrations';"))
 before=canonical_snapshot(h,tables)
 ledger=json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;'))
 target=h.folder/'quality-target';target.mkdir()
 for name in [*NAMES,MIGRATION]:shutil.copyfile(base.MIGRATIONS/name,target/name)
 h.phase='quality-upgrade'
 result=h.migrate(target)
 require(re.findall(r'^Applied (.+)$',result.stdout,re.MULTILINE)==[MIGRATION],'Expected exact SQL019 application')
 require(canonical_snapshot(h,tables)==before,'Quality upgrade changed predecessor canonical/history rows')
 after=json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;'))
 require(len(ledger)==18 and after[:18]==ledger and len(after)==19,'Quality upgrade changed predecessor ledger')
 require('Applied' not in h.migrate(target).stdout and canonical_snapshot(h,tables)==before,'Quality replay changed predecessor rows')
 h.report['qualitySnapshotAlgorithm']='sha256 of sorted fixed-width SHA256 canonical row digests, with duplicate multiplicity and exact row count'
 h.report['qualityUpgradeBaseline']=[{'table':name,**row} for name,row in before.items()]
 h.report['checks'].append('Exact SQL018→019 application and inert replay preserve all predecessor canonical, protected, audit and receipt rows and original migration ledger')
 h.phase='quality-native-tests'
 expected=sum(len(re.findall(r'^test\(', (ROOT/name).read_text(),re.MULTILINE)) for name in TESTS)
 current=next(row['sha256'] for row in frozen if row['path']==REPOSITORY)
 stage={'stage':'SQL019-quality','result':'RUNNING','effectiveSources':frozen,'repositoryOverride':False}
 h.report['sourceStages'].append(stage)
 h.repository_stage=repository_phase(h,'current',ROOT/REPOSITORY,current,False)
 try:
  tested=h.helper(['node','--import','tsx','--test','--test-reporter=tap','--test-concurrency=1',*TESTS],timeout=180,allow_failure=True)
  require(tested.returncode==0,'Native quality execution suite failed; retained bounded TAP identifies failing case')
  h.report['tests']=base.tap_summary(tested.stdout,expected)
  stage['effectiveSourcesAfter']=sources()
  require(stage['effectiveSourcesAfter']==frozen,'Quality test source changed during native execution')
  stage['result']='PASS'
 finally:
  h.repository_stage=None
  if stage['result']=='RUNNING':stage['result']='FAIL'
 require(sources()==frozen,'Quality execution source changed during native qualification')
 h.report['migrations']=[{'name':name,'sha256':sha((base.MIGRATIONS/name).read_bytes())} for name in [*NAMES,MIGRATION]]
 h.report['limitations']=['Predecessor SQL001–018 tests mount the exact recorded immutable repository module; only SQL019 tests use the current quality-aware repository. Other predecessor dependencies/tests use the recorded current checkout bytes.',
  'Approved quality execution storage and production domain-service paths; API/browser and Temporal restart qualification remain separate.','Canonical content authority remains inactive. No shared runtime or external infrastructure was modified.']

def main():
 h,failed=Harness(),False
 try:execute(h)
 except BaseException as error:
  failed=True;h.report.update(failed_phase=h.phase,error_type=type(error).__name__,error='Inspect bounded private diagnostics')
 finally:
  try:
   h.phase='cleanup';h.cleanup()
   if h.resources_before is not None:
    h.deadline=h.cleanup_deadline;require(h.inventory()==h.resources_before,'Preexisting resource inventory changed');h.report['cleanup']['resourceInventoryPreserved']=True
  except BaseException as error:
   failed=True;h.report['cleanupErrorType']=type(error).__name__
  h.report.update(result='FAIL' if failed else 'PASS',recorded_at=datetime.now(timezone.utc).isoformat(),evidence_directory=str(h.folder.relative_to(ROOT)))
  h.report['private_logs']=[{'path':str(p.relative_to(ROOT)),'sha256':sha(p.read_bytes())} for p in sorted(h.folder.glob('*.log'))];h.save(final=True)
 print(json.dumps({'result':h.report['result'],'report':str(REPORT.relative_to(ROOT))}));return int(failed)

if __name__=='__main__':raise SystemExit(main())
