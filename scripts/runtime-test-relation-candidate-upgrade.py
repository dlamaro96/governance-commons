#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Explicit SQL018+032 / populated current SQL001–031+032 qualification.
No original018 PASS inference; all original26 assertions run after032 unchanged.
"""
import argparse
from datetime import datetime,timezone
import hashlib,importlib.util,json,os,re,shutil,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
MIGRATION='032_relation_candidate_validation.sql'
BASELINE='tests/qualification/relation-candidate-baseline.test.ts'
NEW_TEST='tests/qualification/relation-candidate-validation.test.ts'
TESTS=[('tests/qualification/glossary-publication.test.ts',10),('tests/qualification/glossary-publication-boundaries.test.ts',5),('tests/qualification/glossary-context.test.ts',6),('tests/qualification/relation-scope-candidates.test.ts',4),('tests/qualification/glossary-population.test.ts',1)]
PHASES=tuple(f'{scope}-{name}-tests' for scope in ('original','current') for name in ('baseline',*[str(i) for i in range(5)],'regressions'))
PROBE='/app/relation-candidate-source-check.cjs'
def module(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
transport=module(ROOT/'scripts/runtime-test-reference-import.py','candidate_transport')
require,sha,verifier,totals=transport.require,transport.sha,transport.verifier,transport.totals
BASE_NAMES=[*transport.base.NAMES,'015_approval_workflows.sql','016_glossary_publication.sql','017_relation_scope_candidates.sql','018_glossary_nominal_candidates.sql','019_quality_execution.sql','020_native_lineage.sql','021_classification_review.sql','022_reference_publication.sql','023_reference_quality.sql','024_reference_structures.sql','025_quality_uniqueness.sql','026_quality_range.sql','027_quality_monitoring.sql','028_quality_freshness.sql','029_quality_freshness_scheduling.sql','030_quality_volume.sql','031_authority_read_grants.sql']
NAMES=[*BASE_NAMES,MIGRATION]
PREDECESSORS=[
 {'path':'apps/api/src/repository.ts','fixture':'tests/qualification/predecessors/repository-sql018.ts.txt','commit':'a3e1b674fb45c13a045286d05bc3c68012370872','gitBlob':'d741fdde750be30fec5062df4e813fc2a9cba877','sha256':'02513444534aa7cbed358235478bae0ea8cdd14e3dfd3b5fe5f76897c1e9dcf6'},
 {'path':'packages/domain/src/approval-service.ts','fixture':'tests/qualification/predecessors/approval-service-sql020.ts.txt','commit':'88ee24835132e273aa3c67a95a213f79212deb8f','gitBlob':'574d0754c4c5d814e6006cbc2014c8724071a188','sha256':'c0bdee3d1a7f1ae91982fe34503282ee144ff4f1231575799ac89586fa1fa0f4'}]
source_file=transport.source_file

def migrations():
 actual=sorted(p.name for p in (ROOT/'packages/db/migrations').glob('*.sql'))
 require(len(NAMES)==32 and actual[:len(NAMES)]==NAMES and actual[len(NAMES):]==['033_content_security_revisions.sql','034_classification_label_identities.sql', '035_reviewed_classification_producer.sql', '036_authority_scope_alignment.sql', '037_application_authentication_bridge.sql'][:len(actual)-len(NAMES)],'Exact001–032 source prefix and declared contiguous033–037 successors required');return NAMES

def predecessor_pins():
 for p in PREDECESSORS:
  b=source_file(ROOT/p['fixture']).read_bytes();require(sha(b)==p['sha256'] and hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b,usedforsecurity=False).hexdigest()==p['gitBlob'],'Immutable predecessor module differs')
 return PREDECESSORS

def effective_sources(rows,phase):
 require(phase in PHASES,'Undeclared source phase');pins=predecessor_pins();require(len({r['path'] for r in rows})==len(rows) and all(any(r['path']==p['path'] for r in rows) for p in pins),'Missing source override')
 substitutions={p['path']:p['sha256'] for p in pins} if phase.startswith('original-') else {}
 return [{'path':r['path'],'sha256':substitutions.get(r['path'],r['sha256'])} for r in rows]

def sources():
 migrations();pins=predecessor_pins()
 paths={'scripts/runtime-test-relation-candidate-upgrade.py','scripts/runtime-test-reference-import.py','scripts/runtime-test-source-connectors-upgrade.py','scripts/runtime-test-authority-authn-foundation.py','scripts/authentication_roles.py','scripts/qualification_repository.py','scripts/qualification_approval_service.py','package.json','pnpm-lock.yaml','Dockerfile','tsconfig.json','deploy/compose/compose.yaml','packages/db/src/migrate.ts',BASELINE,NEW_TEST,*[p for p,_ in TESTS],*[p['fixture'] for p in pins],*[p['path'] for p in pins],*['packages/db/migrations/'+n for n in NAMES]}
 pending=[(ROOT/p,ROOT/p) for p in paths if p.endswith(('.ts','.tsx'))]+[(ROOT/p['fixture'],ROOT/p['path']) for p in pins]
 while pending:
  physical,logical=pending.pop()
  for rel in re.findall(r'''(?:from\s*|import\s*(?:\(\s*)?|require\s*\(\s*)['"](\.[^'"]+)['"]''',source_file(physical).read_text()):
   p=Path(os.path.abspath(logical.parent/rel))
   if p.suffix=='.js' and not p.is_file():p=p.with_suffix('.ts')
   if not p.suffix:p=p.with_suffix('.ts') if p.with_suffix('.ts').is_file() else p/'index.ts'
   p=source_file(p);name=str(p.relative_to(ROOT))
   if name not in paths:paths.add(name);pending.append((p,p))
 require(len(paths)<=512,'Bounded source closure required')
 return [{'path':p,'sha256':sha(source_file(ROOT/p).read_bytes())} for p in sorted(paths)]

class Harness(transport.Harness):
    def __init__(self,scope):
        self.scope=scope;self.prefix=18 if scope=='original' else 31
        transport.REPORT=ROOT/'.local/evidence'/('relation-candidate-'+scope+'.json')
        super().__init__();self.frozen=sources();self.deadline=time.monotonic()+780
        self.report.update(command='python3 scripts/runtime-test-relation-candidate-upgrade.py --run-local --scope '+scope,profile='isolated-relation-candidate-'+scope,sources=self.frozen,tests=None,nativeSuites=[],limitations=['Only declared relation/glossary fixtures populate baseline; every current schema table is preserved, including empty tables. No full product regression, browser, source worker or original018 acceptance is inferred.','All original26 assertions and thirty-second product deadline are unchanged and execute after032; historical018 failures remain separate.'])
    def migrate(self,directory,**kwargs):
        phase=self.phase;self.phase='schema-'+phase
        try:return super().migrate(directory,**kwargs)
        finally:self.phase=phase
    def helper(self, args, *, mounts=(), timeout=120, allow_failure=False, sensitive=False, input=None):
        # Reuse bounded command/admission/label cleanup; mount the exact manifest
        # rather than unrelated documentation or a broad checkout directory.
        require(args and args[0] == 'node' and self.frozen is not None, 'Declared Node helper/source phase required')
        if 'cachedPackageAdmission' not in self.report:
            name = self.id + '-package-' + str(self.serial)
            self.owned.append(name)
            probe = "const fs=require('node:fs'),c=require('node:crypto');console.log(JSON.stringify({package:JSON.parse(fs.readFileSync('/app/package.json')),lock:c.createHash('sha256').update(fs.readFileSync('/app/pnpm-lock.yaml')).digest('hex')}))"
            observed = self.docker('run', '--rm', '--pull', 'never', '--name', name,
                '--label', 'org.governance-commons.authn-run=' + self.id, '--network', 'none',
                '--memory', '128m', '--memory-swap', '128m', '--cpus', '1', '--pids-limit', '32',
                '--read-only', '--log-driver', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                '--user', f'{os.getuid()}:{os.getgid()}', '--workdir', '/app', self.app_image, 'node', '-e', probe, sensitive=True)
            baked, host = json.loads(observed.stdout), json.loads((ROOT / 'package.json').read_text())
            require(baked['lock'] == sha((ROOT / 'pnpm-lock.yaml').read_bytes()), 'Cached dependency lock differs')
            require({k: v for k, v in baked['package'].items() if k != 'scripts'} == {k: v for k, v in host.items() if k != 'scripts'}, 'Cached dependency metadata differs')
            self.report['cachedPackageAdmission'] = {'lockSha256': baked['lock'], 'allowedDifference': 'package scripts only'}
        name = self.id + '-h' + str(self.serial)
        self.owned.append(name)
        command = ['run', '-i', '--rm', '--pull', 'never', '--name', name,
                   '--label', 'org.governance-commons.authn-run=' + self.id,
                   '--network', 'container:' + self.id, '--memory', '384m', '--memory-swap', '384m', '--cpus', '1', '--pids-limit', '128',
                   '--read-only', '--log-driver', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                   '--user', f'{os.getuid()}:{os.getgid()}', '--tmpfs', '/tmp:rw,nosuid,nodev,size=32m,mode=1777', '--workdir', '/app',
                   '--env', 'HOME=/tmp', '--env', 'NODE_OPTIONS=--max-old-space-size=256', '--env', 'AUTHN_FOUNDATION_CONFIG=/run/authn-config.json',
                   '--volume', f'{self.secret_path}:/run/authn-config.json:ro']
        native=self.phase in PHASES
        effective=effective_sources(self.frozen,self.phase) if native else self.frozen
        overrides={p['path']:p['fixture'] for p in predecessor_pins()} if native and self.phase.startswith('original-') else {}
        targets = set()
        for row in self.frozen:
            # Migration helpers receive exact prefix directories instead. Native
            # readback later mounts every original migration and manifest file.
            if row['path'].startswith('packages/db/migrations/') and self.phase.startswith('schema-'):
                continue
            target = '/app/' + row['path']
            command += ['--volume', f'{ROOT / overrides.get(row["path"],row["path"])}:{target}:ro']
            targets.add(target)
        for host, target in mounts:
            require(target not in targets and target != PROBE and target != '/run/authn-config.json', 'Conflicting helper mount')
            require(not any(target.startswith(x + '/') or x.startswith(target.rstrip('/') + '/') for x in targets), 'Overlapping helper mount')
            command += ['--volume', f'{host}:{target}:ro']
            targets.add(target)
        native = self.phase in PHASES
        probe_path = None
        if native:
            require(sources() == self.frozen, 'Checkout changed before native helper')
            probe_path = self.folder / ('source-check-' + str(self.serial) + '.cjs')
            body = verifier(effective, sha(self.secret_path.read_bytes())).encode()
            with probe_path.open('xb') as output:
                output.write(body)
            probe_path.chmod(0o444)
            command += ['--volume', f'{probe_path}:{PROBE}:ro']
            args = [args[0], '--require', PROBE, *args[1:]]
            record = {'phase': self.phase, 'verifierSha256': sha(body), 'sourceCount': len(self.frozen), 'result': 'RUNNING',
                      'checkoutSources':self.frozen,'effectiveSources':effective,'overrides':[p for p in PREDECESSORS if p['path'] in overrides]}
            self.report.setdefault('sourceChecks', []).append(record)
        try:
            result = self.docker(*command, self.app_image, *args, timeout=timeout, allow_failure=allow_failure, sensitive=sensitive, input=input)
            if native:
                record.update(result='PASS' if result.returncode == 0 else 'NONZERO', exitStatus=result.returncode)
            return result
        except BaseException:
            if native:
                record['result'] = 'FAIL'
            raise
        finally:
            if native:
                require(sha(probe_path.read_bytes()) == sha(body) and sources() == self.frozen, 'Native helper source changed')
                record['sourceHashesMatched'] = True


def readback(h):
 probe="const fs=require('node:fs'),c=require('node:crypto'),s=p=>c.createHash('sha256').update(fs.readFileSync(p)).digest('hex');console.log(JSON.stringify({sources:"+json.dumps([r['path'] for r in h.frozen])+".map(path=>({path,sha256:s(path)})),node:{version:process.version,sha256:s(process.execPath)},tsx:{version:require('tsx/package.json').version,sha256:s(require.resolve('tsx'))},config:s('/run/authn-config.json')}));"
 observed=json.loads(h.helper(['node','-e',probe],sensitive=True).stdout)
 require(set(observed)=={'sources','node','tsx','config'} and observed['sources']==effective_sources(h.frozen,h.phase) and observed['config']==sha(h.secret_path.read_bytes()),'Actual mounted bytes differ')
 require(re.fullmatch(r'v24\.\d+\.\d+',observed['node']['version']) and all(re.fullmatch(r'[a-f0-9]{64}',observed[k]['sha256']) for k in ('node','tsx')),'Pinned tools differ');return observed

def declarations(path):return re.findall(r"^test\('([^'\n]+)'",source_file(ROOT/path).read_text(),re.M)

def suite(h,name,path,count):
 h.phase=h.scope+'-'+name+'-tests';expected=declarations(path);require(len(expected)==count,'Exact declaration inventory differs')
 record={'phase':h.phase,'path':path,'expected':count,'tests':None,'result':'RUNNING'};h.report['nativeSuites'].append(record);record['mountedBefore']=readback(h)
 tested=h.helper(['node','--import','tsx','--test','--test-reporter=tap','--test-concurrency=1',path],timeout=300,allow_failure=True)
 record.update(tests=totals(tested.stdout),exitStatus=tested.returncode,result='FAIL');record['mountedAfter']=readback(h)
 require(record['mountedBefore']==record['mountedAfter'] and sources()==h.frozen,'Source/tool/config drift')
 require(tested.returncode==0 and record['tests'] is not None,'Native suite failed; bounded private TAP retained');transport.base.base.tap_summary(tested.stdout,count)
 require(re.findall(r'^# Subtest: (.+)$',tested.stdout,re.M)==expected and re.findall(r'^ok [0-9]+ - (.+)$',tested.stdout,re.M)==expected,'Test identities differ');record['result']='PASS';h.save()

TABLES="SELECT json_agg(schemaname||'.'||tablename ORDER BY schemaname,tablename) FROM pg_tables WHERE schemaname IN('public','gc_authn','gc_authority') AND tablename<>'schema_migrations';"
FUNCTIONS="SELECT json_agg(jsonb_build_object('signature',p.oid::regprocedure::text,'owner',p.proowner::text,'acl',p.proacl::text,'definer',p.prosecdef,'config',p.proconfig,'volatility',p.provolatile,'body',md5(p.prosrc)) ORDER BY p.oid::regprocedure::text) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN('public','gc_authn','gc_authority');"
GUARDS="SELECT jsonb_build_object('rls',(SELECT jsonb_agg(jsonb_build_array(n.nspname,c.relname,c.relrowsecurity,c.relforcerowsecurity,c.relowner,c.relacl::text) ORDER BY n.nspname,c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='r' AND n.nspname IN('public','gc_authn','gc_authority')),'triggers',(SELECT jsonb_agg(jsonb_build_array(t.tgrelid::regclass::text,t.tgname,t.tgenabled,pg_get_triggerdef(t.oid)) ORDER BY t.tgrelid::regclass::text,t.tgname) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN('public','gc_authn','gc_authority')));"
def snapshot(h,tables):
 out={}
 for table in tables:
  require(re.fullmatch(r'(?:public|gc_authn|gc_authority)\.[a-z_]+',table),'Unsafe table')
  out[table]=json.loads(h.sql(f"WITH rows AS MATERIALIZED(SELECT sha256(convert_to(to_jsonb(r)::text,'UTF8')) value FROM {table} r) SELECT jsonb_build_object('rows',count(*),'sha256',encode(sha256(coalesce(string_agg(value,''::bytea ORDER BY value),''::bytea)),'hex')) FROM rows;"))
 return out

def ledger(h,names):
 rows=json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM public.schema_migrations m;'))
 require([r['name'] for r in rows]==names and all(r['checksum']==sha((ROOT/'packages/db/migrations'/r['name']).read_bytes()) for r in rows),'Ledger differs');return rows

def apply32(h):
 h.phase='preupgrade';tables=json.loads(h.sql(TABLES));before=snapshot(h,tables);prior=ledger(h,NAMES[:h.prefix]);functions=json.loads(h.sql(FUNCTIONS));guards=h.sql(GUARDS)
 target=h.folder/'candidate-target';target.mkdir()
 for name in [*NAMES[:h.prefix],MIGRATION]:shutil.copyfile(ROOT/'packages/db/migrations'/name,target/name)
 h.phase='schema32-upgrade';result=h.migrate(target);require(re.findall(r'^Applied (.+)$',result.stdout,re.M)==[MIGRATION],'Exactly032 must apply')
 after=ledger(h,[*NAMES[:h.prefix],MIGRATION]);require(after[:-1]==prior,'Original ledger changed')
 current=json.loads(h.sql(FUNCTIONS));require(len(current)==len(functions),'Function inventory changed');changed=[]
 for left,right in zip(functions,current):
  if left!=right:
   require(left['signature']==right['signature']=='gc_relation_check_type(uuid,uuid)' and {k:v for k,v in left.items() if k!='body'}=={k:v for k,v in right.items() if k!='body'},'Unexpected function/ACL change');changed.append(left['signature'])
 require(changed==['gc_relation_check_type(uuid,uuid)'],'Expected exact changed function')
 require(json.loads(h.sql(TABLES))==tables and snapshot(h,tables)==before and h.sql(GUARDS)==guards,'Canonical/guard state changed')
 h.phase='schema32-replay';require('Applied' not in h.migrate(target).stdout,'Replay reapplied migration')
 require(ledger(h,[*NAMES[:h.prefix],MIGRATION])==after and snapshot(h,tables)==before and h.sql(GUARDS)==guards and json.loads(h.sql(FUNCTIONS))==current,'Replay changed state')
 h.report['upgrade']={'prefix':h.prefix,'before':before,'priorLedger':prior,'ledger':after,'functionsBeforeSha256':sha(json.dumps(functions,sort_keys=True).encode()),'functionsAfterSha256':sha(json.dumps(current,sort_keys=True).encode()),'guardsSha256':sha(guards.encode()),'preservation':True,'replay':True};h.save()

def execute(h):
 frozen=sources();require(h.frozen==frozen,'Admission changed');old=transport.migrations
 try:transport.migrations=lambda:NAMES[:h.prefix];transport.setup(h)
 finally:transport.migrations=old
 suite(h,'baseline',BASELINE,1);apply32(h)
 for i,(path,count) in enumerate(TESTS):suite(h,str(i),path,count)
 suite(h,'regressions',NEW_TEST,10);require(sources()==frozen,'Final source changed')
 suites=h.report['nativeSuites'];require(len(suites)==7 and sum(r['tests']['tests'] for r in suites)==37,'All37 exact cases required')
 h.report.update(tests={'tests':37,'pass':37,'fail':0,'cancelled':0,'skipped':0,'todo':0,'suites':0},sourceHashesMatched=True)

def finish(h,failed):
 try:
  h.phase='cleanup';h.cleanup()
  if h.resources_before is not None:
   h.deadline=h.cleanup_deadline;require(h.inventory()==h.resources_before,'Preexisting inventory changed');h.report.setdefault('cleanup',{})['resourceInventoryPreserved']=True
 except BaseException as e:failed=True;h.report['cleanupErrorType']=type(e).__name__
 finally:
  try:h.secret_path.unlink(missing_ok=True);require(not h.secret_path.exists(),'Credential file remains');h.report.setdefault('cleanup',{})['generatedCredentialsRemoved']=True
  except BaseException as e:failed=True;h.report['credentialCleanupErrorType']=type(e).__name__
 h.report.update(result='FAIL' if failed else 'PASS',recorded_at=datetime.now(timezone.utc).isoformat(),evidence_directory=str(h.folder.relative_to(ROOT)))
 h.report['private_logs']=[{'path':str(p.relative_to(ROOT)),'sha256':sha(p.read_bytes())} for p in sorted(h.folder.glob('*.log'))];h.save(final=True);return failed

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run-local',action='store_true');parser.add_argument('--scope',choices=('original','current'),required=True);args=parser.parse_args();require(args.run_local,'Explicit --run-local required')
 h=Harness(args.scope);failed=False
 try:execute(h)
 except BaseException as e:failed=True;h.report.update(failed_phase=h.phase,error_type=type(e).__name__,error='Inspect bounded private phase evidence; no raw errors exported')
 failed=finish(h,failed);print(json.dumps({'result':h.report['result'],'scope':args.scope,'report':str(transport.REPORT)}));return int(failed)
if __name__=='__main__':raise SystemExit(main())
