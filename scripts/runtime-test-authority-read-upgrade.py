#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Two explicit isolated SQL031 scopes; no public runtime or deadline change.

original: execute every original foundation assertion, applying031 after the
original013 application/replay checks and before the original native suites.
current: actual001–030 populated by current native cases, then031 preservation.
"""
import argparse
from datetime import datetime,timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sys
import time
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
MIGRATION='031_authority_read_grants.sql'
NEW_TEST='tests/qualification/authority-read-grants.test.ts'
def module(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
authority=module(ROOT/'scripts/runtime-test-authority-foundation.py','authority_read_original')
volume=module(ROOT/'scripts/runtime-test-quality-volume-upgrade.py','authority_read_volume_transport')
require,sha=authority.require,authority.sha
NAMES=[*volume.NAMES,MIGRATION]
CURRENT=[*volume.LEGACY,*volume.TESTS]
CURRENT_PHASES=[f'{stage}-quality-{i}' for stage in ('before031','after031') for i in range(len(CURRENT))]
NATIVE_PHASES=tuple([*authority.diagnostics.SUITES,'authority_read_regressions','before031_authority_storage',*CURRENT_PHASES])
_original_volume_sources=volume.sources
_original_volume_migrations=volume.migrations
# Existing transport's only effective source mode is current: no old module
# overrides in either031 scope. Original013 is applied as exact migration bytes.
volume.PHASES=NATIVE_PHASES
volume.PREDECESSORS=[]
volume.predecessor_pins=lambda:[]
volume.effective_sources=lambda rows,phase: rows if phase in NATIVE_PHASES else (_ for _ in ()).throw(RuntimeError('Undeclared phase'))

def migrations():
 actual=sorted(p.name for p in (ROOT/'packages/db/migrations').glob('*.sql'))
 suffix=actual[len(NAMES):]
 successors=['032_relation_candidate_validation.sql','033_content_security_revisions.sql','034_classification_label_identities.sql', '035_reviewed_classification_producer.sql', '036_authority_scope_alignment.sql', '037_application_authentication_bridge.sql']
 require(actual[:len(NAMES)]==NAMES and suffix==successors[:len(suffix)],'Exact001–031 prefix and declared contiguous successors required')
 return list(NAMES)

def sources():
 migrations()
 # The volume source enumerator imports monitoring's fixed predecessor helper;
 # preserve its entire transitive admission even though031 has no overrides.
 saved=volume.migrations
 try:
  volume.migrations=lambda:volume.NAMES
  rows=_original_volume_sources()
 finally:volume.migrations=saved
 paths={r['path'] for r in rows}|{r['path'] for r in authority.sources()}|{
  'scripts/runtime-test-authority-read-upgrade.py',NEW_TEST,'packages/db/migrations/'+MIGRATION,
  'tests/qualification/predecessors/quality-service-sql029.ts.txt','tests/qualification/predecessors/repository-sql029.ts.txt'}
 pending=[ROOT/p for p in paths if p.endswith(('.ts','.tsx'))]
 while pending:
  p=pending.pop()
  for name in re.findall(r'''(?:from\s*|import\s*(?:\(\s*)?|require\s*\(\s*)['"](\.[^'"]+)['"]''',p.read_text()):
   q=Path(os.path.abspath(p.parent/name))
   if q.suffix=='.js' and not q.exists():q=q.with_suffix('.ts')
   if not q.suffix:q=q.with_suffix('.ts') if q.with_suffix('.ts').exists() else q/'index.ts'
   q=volume.source_file(q);rel=str(q.relative_to(ROOT))
   if rel not in paths:paths.add(rel);pending.append(q)
 return [{'path':p,'sha256':sha(volume.source_file(ROOT/p).read_bytes())} for p in sorted(paths)]
volume.sources=sources

class Harness(authority.Harness):
 def __init__(self,scope):
  self.scope=scope;self.applied031=False;self.frozen=sources()
  authority.REPORT=ROOT/'.local/evidence'/('authority-read-'+scope+'.json')
  super().__init__()
  self.report.update(command='python3 scripts/runtime-test-authority-read-upgrade.py --run-local --scope '+scope,
   profile='isolated-authority-read-'+scope,qualificationSources=self.frozen,scope=scope)
 def helper(self,args,**kwargs):
  native='--test' in args
  self.report['privateConfigSha256']=sha(self.secret_path.read_bytes())
  if not native:return volume.Harness.helper(self,args,**kwargs)
  require(self.phase in NATIVE_PHASES,'Undeclared native phase')
  path=args[-1];expected=len(re.findall(r'^test\(',volume.source_file(ROOT/path).read_text(),re.M))
  record={'phase':self.phase,'path':path,'expected':expected,'tests':None,'result':'RUNNING'}
  self.report.setdefault('nativeSuites',[]).append(record)
  before=volume.readback(self);record['mountedSourceBefore']=before
  result=volume.Harness.helper(self,args,**kwargs)
  actual=volume.totals(result.stdout);record.update(tests=actual,exitStatus=result.returncode,result='FAIL')
  after=volume.readback(self);record['mountedSourceAfter']=after
  require(before==after and sources()==self.frozen,'Mounted source/tool/config drift')
  require(result.returncode==0 and actual is not None,'Actual native suite failed')
  authority.base.tap_summary(result.stdout,expected)
  names=[r['title'] for r in authority.diagnostics.declarations(ROOT,path)]
  require(len(names)==expected and re.findall(r'^# Subtest: (.+)$',result.stdout,re.M)==names
   and re.findall(r'^ok [0-9]+ - (.+)$',result.stdout,re.M)==names,'Native identities differ')
  record.update(result='PASS',sourceHashesMatched=True)
  return result
 def migrate(self,directory,**kwargs):
  previous=self.phase;self.phase='schema-'+previous
  try:return super().migrate(directory,**kwargs)
  finally:self.phase=previous
 def suite(self,key,path,offset):
  if self.scope=='original' and key=='authn_storage_regression' and not self.applied031:
   apply031(self,13)
  return super().suite(key,path,offset)

def config_offset(h,offset):
 value=json.loads(h.secret_path.read_text());value['suiteOffset']=offset;h.secret_path.write_text(json.dumps(value))
 h.report['privateConfigSha256']=sha(h.secret_path.read_bytes())

def additional_roles(h,total):
 config=json.loads(h.secret_path.read_text());definitions=[];slots=config.setdefault('slots',[])
 for index in range(len(slots),total):
  slot={}
  for field,kind in [('login','login'),('api','api'),('nextLogin','login'),('nextApi','api')]:
   name,secret=f'gc_af_{field.lower()}_{index:03}',secrets.token_hex(24)
   definitions.append({'name':name,'kind':kind,'password':secret});h.private_values.append(secret)
   slot[field]={'name':name,'url':f'postgresql://{name}:{secret}@127.0.0.1:5432/{authority.base.DATABASE}'}
  slots.append(slot)
 if 'unregistered' not in config:
  name,secret='gc_af_unregistered',secrets.token_hex(24);h.private_values.append(secret)
  definitions.append({'name':name,'kind':'api','password':secret})
  config['unregistered']={'name':name,'url':f'postgresql://{name}:{secret}@127.0.0.1:5432/{authority.base.DATABASE}'}
 roles=module(ROOT/'scripts/authentication_roles.py','authority_read_roles')
 if definitions:h.sql(roles.executor_sql(authority.base.DATABASE,definitions))
 h.secret_path.write_text(json.dumps(config));h.secret_path.chmod(0o600)
 h.report['privateConfigSha256']=sha(h.secret_path.read_bytes())

def snapshot(h,tables):
 # Every complete column participates, including030's table_asset_id.
 result={}
 for table in tables:
  require(re.fullmatch(r'(?:public|gc_authn|gc_authority)\.[a-z_]+',table),'Unsafe canonical table')
  result[table]=json.loads(h.sql(f"WITH rows AS MATERIALIZED(SELECT sha256(convert_to(to_jsonb(r)::text,'UTF8')) value FROM {table} r) SELECT jsonb_build_object('rows',count(*),'sha256',encode(sha256(coalesce(string_agg(value,''::bytea ORDER BY value),''::bytea)),'hex')) FROM rows;"))
 return result

FUNCTIONS="SELECT json_agg(jsonb_build_object('signature',p.oid::regprocedure::text,'owner',p.proowner::text,'acl',p.proacl::text,'definer',p.prosecdef,'config',p.proconfig,'volatility',p.provolatile,'body',md5(p.prosrc)) ORDER BY p.oid::regprocedure::text) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN('public','gc_authn','gc_authority');"
def ledger(h,names):
 rows=json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM public.schema_migrations m;'))
 require([r['name'] for r in rows]==names and all(r['checksum']==sha((ROOT/'packages/db/migrations'/r['name']).read_bytes()) for r in rows),'Exact ledger mismatch')
 return rows

def apply031(h,prefix):
 h.phase='read-preupgrade';tables=volume.canonical_tables(h);before=snapshot(h,tables);prior=ledger(h,NAMES[:prefix]);functions=json.loads(h.sql(FUNCTIONS))
 target=h.folder/'read-target';target.mkdir()
 for name in [*NAMES[:prefix],MIGRATION]:shutil.copyfile(ROOT/'packages/db/migrations'/name,target/name)
 h.phase='schema-31-upgrade';result=h.migrate(target)
 require(re.findall(r'^Applied (.+)$',result.stdout,re.M)==[MIGRATION],'Exactly031 must apply')
 after=ledger(h,[*NAMES[:prefix],MIGRATION]);require(after[:-1]==prior,'Prior ledger changed')
 current=json.loads(h.sql(FUNCTIONS));by={r['signature']:r for r in current}
 for row in functions:
  observed=by[row['signature']]
  if row['signature']=='gc_authority.load_human_closure_v1(text,text)':
   require({k:v for k,v in row.items() if k!='body'}=={k:v for k,v in observed.items() if k!='body'},'Loader ACL/interface altered')
  else:require(row==observed,'Existing function changed')
 require(set(by)-{r['signature'] for r in functions}=={'gc_authority.validate_read_grants_v1(uuid,uuid[])'},'Unexpected functions added')
 require(volume.canonical_tables(h)==tables and snapshot(h,tables)==before,'Canonical state changed')
 h.phase='schema-31-replay';require('Applied' not in h.migrate(target).stdout,'031 replay not inert')
 require(ledger(h,[*NAMES[:prefix],MIGRATION])==after and volume.canonical_tables(h)==tables and snapshot(h,tables)==before and json.loads(h.sql(FUNCTIONS))==current,'Replay altered state')
 h.report.update(readUpgrade={'prefix':prefix,'before':before,'priorLedger':prior,'ledger':after,'functionsBeforeSha256':sha(json.dumps(functions,sort_keys=True).encode()),'functionsAfterSha256':sha(json.dumps(current,sort_keys=True).encode()),'preservation':True,'replay':True})
 h.applied031=True

def setup(h):
    context = json.loads(h.docker('context', 'inspect', sensitive=True).stdout)[0]['Endpoints']['docker']['Host']
    require(context.startswith(('unix://', 'npipe://')) and (not os.environ.get('DOCKER_HOST') or os.environ['DOCKER_HOST'].startswith(('unix://', 'npipe://'))), 'Local Docker only')
    h.resources_before = h.inventory()
    (h.folder / 'resources-before.json').write_text(json.dumps(h.resources_before, sort_keys=True) + '\n')
    h.report['memoryAdmission'] = h.memory_admission()
    image = re.search(r'^\s+image: (postgres:[^\s]+)$', (ROOT / 'deploy/compose/compose.yaml').read_text(), re.M)
    require(image is not None, 'Pinned cached PostgreSQL required')
    pg_image = h.docker('image', 'inspect', '--format', '{{.Id}}', image[1]).stdout.strip()
    h.app_image = h.docker('image', 'inspect', '--format', '{{.Id}}', 'governance-commons:dev').stdout.strip()
    require(all(re.fullmatch(r'sha256:[a-f0-9]{64}', v) for v in (pg_image, h.app_image)), 'Immutable cached image IDs required')
    h.report['images'] = {'postgres': pg_image, 'application': h.app_image}
    passwords = {role: secrets.token_hex(24) for role in ('postgres', authority.base.OWNER, 'gc_app')}
    h.private_values = list(passwords.values())
    url = lambda role: f'postgresql://{role}:{passwords[role]}@127.0.0.1:5432/{authority.base.DATABASE}'
    h.secret_path.write_text(json.dumps({'owner': url(authority.base.OWNER), 'admin': url('postgres'), 'legacy': url('gc_app')}))
    h.secret_path.chmod(0o600)
    h.report['privateConfigSha256'] = sha(h.secret_path.read_bytes())
    h.phase = 'database-start'
    h.docker('run', '--detach', '--pull', 'never', '--name', h.id, '--label', 'org.governance-commons.authn-run=' + h.id,
             '--network', 'none', '--memory', '512m', '--memory-swap', '512m', '--cpus', '1', '--pids-limit', '128',
             '--read-only', '--log-driver', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--user', 'postgres',
             '--tmpfs', '/var/lib/postgresql/data:rw,nosuid,nodev,size=256m,mode=1777', '--tmpfs', '/tmp:rw,nosuid,nodev,size=16m,mode=1777',
             '--tmpfs', '/var/run/postgresql:rw,nosuid,nodev,size=4m,mode=1777', '--env', 'PGDATA=/var/lib/postgresql/data/pgdata', '--entrypoint', 'sh', pg_image, '-ec',
             'initdb --auth-local=trust --auth-host=scram-sha-256 -D /var/lib/postgresql/data/pgdata >/tmp/init.log 2>&1; exec postgres -D /var/lib/postgresql/data/pgdata -c listen_addresses=127.0.0.1 -c shared_buffers=32MB -c work_mem=2MB -c maintenance_work_mem=16MB -c max_connections=16 -c min_wal_size=32MB -c max_wal_size=64MB -c log_statement=none -c log_min_error_statement=panic -c log_error_verbosity=terse')
    h.created = True
    end = time.monotonic() + 30
    while h.docker('exec', h.id, 'pg_isready', '-U', 'postgres', allow_failure=True).returncode:
        require(time.monotonic() < end, 'Owned PostgreSQL readiness deadline exceeded')
        time.sleep(.1)
    statement = 'ALTER ROLE postgres PASSWORD ' + authority.literal(passwords['postgres']) + ';'
    for role in (authority.base.OWNER, 'gc_app'):
        statement += f'CREATE ROLE {role} LOGIN PASSWORD {authority.literal(passwords[role])} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;'
    h.sql(statement + f'CREATE DATABASE {authority.base.DATABASE} OWNER {authority.base.OWNER};', database='postgres')
    h.sql(f'REVOKE ALL ON DATABASE {authority.base.DATABASE} FROM PUBLIC;GRANT CONNECT ON DATABASE {authority.base.DATABASE} TO {authority.base.OWNER},gc_app;REVOKE CREATE ON SCHEMA public FROM PUBLIC;ALTER SCHEMA public OWNER TO {authority.base.OWNER};')
    names = migrations()[:30]
    roles = authority.base.module(ROOT / 'scripts/authentication_roles.py', 'import_qualification_roles')
    for count in (11, 12, 13, 30):
        folder = h.folder / ('migrations-' + str(count))
        folder.mkdir()
        for name in names[:count]:
            shutil.copyfile(ROOT / 'packages/db/migrations' / name, folder / name)
        h.phase = 'schema-' + str(count)
        if count in (12, 13):
            try:
                h.sql(roles.prepare_sql(authority.base.OWNER, authority.base.DATABASE))
                h.migrate(folder)
            finally:
                h.sql(roles.finish_sql(authority.base.OWNER))
        else:
            h.migrate(folder)
    expected = [{'name': name, 'checksum': sha((ROOT / 'packages/db/migrations' / name).read_bytes())} for name in names]
    observed = json.loads(h.sql("SELECT json_agg(json_build_object('name',name,'checksum',checksum) ORDER BY name) FROM public.schema_migrations;"))
    require(observed == expected, 'Actual migration ledger differs')
    h.report['migrations'] = observed


def quality_suites(h,stage):
 for i,(path,count) in enumerate(CURRENT):
  require(len(re.findall(r'^test\(',(ROOT/path).read_text(),re.M))==count,'Current quality case count changed')
  h.suite(f'{stage}-quality-{i}',ROOT/path,0)

def planned_suites(scope):
 if scope=='original':
  pairs=list(authority.diagnostics.SUITES.items())+ [('authority_read_regressions',NEW_TEST)]
 else:
  pairs=[(f'before031-quality-{i}',p) for i,(p,n) in enumerate(CURRENT)]
  pairs += [('before031_authority_storage',authority.SUITES[0][1])]
  pairs += [(f'after031-quality-{i}',p) for i,(p,n) in enumerate(CURRENT)]
  pairs += [('authority_'+kind,path) for kind,path,offset in authority.SUITES]
  pairs += [('authority_read_regressions',NEW_TEST)]
 return [{'phase':key,'path':path,'expected':len(authority.diagnostics.declarations(ROOT,path))} for key,path in pairs]

def execute(h):
 h.report['qualificationSources']=h.frozen
 if h.scope=='original':
  # Original source/logic is unmodified; its suite hook is the explicit upgrade
  # boundary after013 missing-transfer/collision/application/replay assertions.
  authority.execute(h)
  require(h.applied031,'Original scope did not apply031')
  additional_roles(h,256)
 else:
  setup(h);additional_roles(h,288)
  quality_suites(h,'before031')
  h.suite('before031_authority_storage',ROOT/authority.SUITES[0][1],0)
  apply031(h,30)
  quality_suites(h,'after031')
  for kind,path,offset in authority.SUITES:h.suite('authority_'+kind,ROOT/path,offset)
 h.suite('authority_read_regressions',ROOT/NEW_TEST,224)
 require(sources()==h.frozen and all(r['result']=='PASS' for r in h.report['nativeSuites'])
  and [{k:r[k] for k in ('phase','path','expected')} for r in h.report['nativeSuites']]==planned_suites(h.scope),'Source/native scope incomplete')
 h.report.update(sources=h.frozen,qualificationSources=h.frozen,migrations=h.report['readUpgrade']['ledger'],sourceHashesMatched=True,
  nativeTotals={k:sum(r['tests'][k] for r in h.report['nativeSuites']) for k in ('tests','pass','fail','cancelled','skipped','todo')},
  limitations=['Inactive owner-only authority; no runtime content-authority activation.','Original scope applies exact001–013 then031; current scope applies exact001–030 then031. These are distinct claims.','Original25-second SQL/30-second operation budgets and all original native assertions unchanged.','Cached immutable images with exact current source mounts; no source worker, HTTP/browser or production claim.'])

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run-local',action='store_true');parser.add_argument('--scope',choices=('original','current'),required=True);args=parser.parse_args()
 require(args.run_local,'Explicit --run-local required')
 h=Harness(args.scope);failed=False
 try:execute(h)
 except BaseException as error:failed=True;h.report.update(failed_phase=h.phase,error_type=type(error).__name__,error='Inspect bounded private evidence')
 finally:
  try:
   h.phase='cleanup';h.cleanup()
   if h.resources_before is not None:
    h.deadline=h.cleanup_deadline;after=h.inventory();(h.folder/'resources-after.json').write_text(json.dumps(after,sort_keys=True)+'\n');require(after==h.resources_before,'Preexisting resource inventory changed');h.report['cleanup']['resourceInventoryPreserved']=True
  except BaseException as error:failed=True;h.report['cleanupErrorType']=type(error).__name__
  finally:
   try:h.secret_path.unlink(missing_ok=True);require(not h.secret_path.exists(),'Credential cleanup refused');h.report.setdefault('cleanup',{})['generatedCredentialsRemoved']=True
   except BaseException as error:failed=True;h.report.setdefault('cleanup',{})['generatedCredentialsRemoved']=False;h.report['credentialCleanupErrorType']=type(error).__name__
  h.report.update(result='FAIL' if failed else 'PASS',recorded_at=datetime.now(timezone.utc).isoformat(),evidence_directory=str(h.folder.relative_to(ROOT)))
  h.report['private_logs']=[{'path':str(p.relative_to(ROOT)),'sha256':sha(p.read_bytes())} for p in sorted(h.folder.glob('*.log'))];h.save(final=True)
 print(json.dumps({'result':h.report['result'],'report':str(authority.REPORT.relative_to(ROOT))}));return int(failed)
if __name__=='__main__':raise SystemExit(main())
