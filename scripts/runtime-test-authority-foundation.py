#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Isolated SQL001–012→013 native qualification; no build/pull/shared fallback.

The existing real authentication foundation gate runs first, then the new
inactive authority upgrade and native suites. Every result remains source-bound;
only root may launch this runner. This file never activates content authority.
"""
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
LOCAL=ROOT/'.local/evidence'
REPORT=LOCAL/'authority-foundation.json'
sys.path.insert(0,str(ROOT/'policies'))
import authority_diagnostics as diagnostics

def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result

base=module(ROOT/'scripts/runtime-test-authority-authn-foundation.py','authority_predecessor_gate')
require,sha,literal=base.require,base.sha,base.literal
MIGRATION='013_authority_foundation.sql'
SUITES=[('storage','tests/qualification/authority-foundation-storage.test.ts',128),
        ('loader','tests/qualification/authority-foundation-loader.test.ts',160),
        ('concurrency','tests/qualification/authority-foundation-concurrency.test.ts',192)]

def sources():
    return diagnostics.source_inventory(ROOT)

class Harness(base.Harness):
    def __init__(self):
        os.umask(0o077);LOCAL.mkdir(parents=True,exist_ok=True)
        self.id='gc-authority-'+uuid.uuid4().hex[:12]
        self.folder=LOCAL/('authority-foundation-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+self.id[-12:]);self.folder.mkdir(mode=0o700)
        self.phase,self.serial,self.owned,self.created='admission',0,[],False
        self.deadline,self.cleanup_deadline=time.monotonic()+1680,None
        self.output_bytes,self.resources_before,self.private_values=0,None,[]
        self.last_command,self.command_failure=None,None
        self.secret_path=self.folder/'private-config.json';self.started=datetime.now(timezone.utc).isoformat()
        self.report={'schema_version':1,'result':'RUNNING','started_at':self.started,'command':'./dev test --suite authority-foundation',
            'profile':'isolated-inactive-authority-foundation','checks':[]}
        if re.fullmatch(r'[a-f0-9]{40}',os.environ.get('GITHUB_SHA','')):self.report['commit']=os.environ['GITHUB_SHA']
        if REPORT.exists():(self.folder/'previous-report.json').write_bytes(REPORT.read_bytes())
        # Admission still precedes runtime work; retain its failure even when the
        # disk floor prevents the first command from starting.
        self.save(final=True)

    def save(self,*,final=False):
        if not final:self.admission()
        data=(json.dumps(self.report,indent=2)+'\n').encode();(self.folder/'report.json').write_bytes(data);REPORT.write_bytes(data);REPORT.chmod(0o600)

    def command(self,args,**kwargs):
        phase,serial=self.phase,self.serial
        self.last_command=None
        error=None
        try:return super().command(args,**kwargs)
        except BaseException as caught:
            error=caught
            raise
        finally:
            log=self.folder/f'{self.serial:03d}-{phase}.log'
            if self.serial>serial and log.is_file():
                self.last_command={'phase':phase,'path':str(log.relative_to(ROOT)),'sha256':sha(log.read_bytes())}
            if error is not None and self.command_failure is None:
                category=('interrupted' if isinstance(error,KeyboardInterrupt) else 'command_timeout'
                    if str(error)=='Bounded qualification command timed out' else 'command_failed')
                self.command_failure=self.failure_record(phase,category,self.last_command)

    def failure_record(self,phase,category,command=None):
        if command is None or command['phase']!=phase:
            return {'phase':phase,'category':'interrupted' if category=='interrupted' else 'unknown','commandLog':None}
        path=ROOT/command['path'];data=path.read_bytes()
        # A command may fail admission before a usable exit record exists.
        header=re.match(rb'phase=[a-z_-]+\nexit=(-?[0-9]+)\n',data)
        if header is None or (category in ('command_failed','suite_failed') and int(header[1])==0):
            return {'phase':phase,'category':'unknown','commandLog':None}
        marker=('\n'+diagnostics.MARKER+category+'\n').encode()
        path.write_bytes(data+marker);self.output_bytes+=len(marker)
        row={'path':command['path'],'sha256':sha(data+marker)}
        for key,old in self.report.get('test_logs',{}).items():
            if old.get('path')==row['path']:self.report['test_logs'][key]=row
        return {'phase':phase,'category':category,'commandLog':row}

    def remember_failure(self,error):
        if 'failure_diagnostic' in self.report:return
        if self.command_failure is not None:failure=self.command_failure
        elif self.phase in diagnostics.SUITES and self.last_command is not None and self.last_command['phase']==self.phase:
            data=(ROOT/self.last_command['path']).read_bytes()
            code=re.match(rb'phase=[a-z_-]+\nexit=(-?[0-9]+)\n',data)
            failure=(self.failure_record(self.phase,'suite_failed',self.last_command) if code and int(code[1])!=0
                else {'phase':self.phase,'category':'invariant_failed','commandLog':None})
        else:failure={'phase':self.phase,'category':'interrupted' if isinstance(error,KeyboardInterrupt) else 'invariant_failed','commandLog':None}
        self.report['failure_diagnostic']=failure;self.report['failed_phase']=failure['phase']

    def helper(self,args,*,mounts=(),**kwargs):
        # Qualify the cached dependency environment before overlaying this
        # checkout's script-only package metadata. Never mask lock/dependency drift.
        if 'cachedPackageAdmission' not in self.report:
            observed=super().helper(['node','-e',"const fs=require('node:fs'),c=require('node:crypto');console.log(JSON.stringify({package:JSON.parse(fs.readFileSync('package.json')),packageHash:c.createHash('sha256').update(fs.readFileSync('package.json')).digest('hex'),lockHash:c.createHash('sha256').update(fs.readFileSync('pnpm-lock.yaml')).digest('hex')}))"])
            baked=json.loads(observed.stdout);host=json.loads((ROOT/'package.json').read_text())
            require(baked['lockHash']==sha((ROOT/'pnpm-lock.yaml').read_bytes()),'Cached lock differs from frozen checkout')
            require({k:v for k,v in baked['package'].items() if k!='scripts'}=={k:v for k,v in host.items() if k!='scripts'},'Cached package differs outside script commands')
            self.report['cachedPackageAdmission']={'bakedPackageSha256':baked['packageHash'],'mountedPackageSha256':sha((ROOT/'package.json').read_bytes()),'lockSha256':baked['lockHash'],'allowedDifference':'scripts only; all other package metadata and exact lock match'}
        extra=[(ROOT/'packages/authority-storage','/app/packages/authority-storage'),
               (ROOT/'tests/unit/fixtures','/app/tests/unit/fixtures'),
               (ROOT/'package.json','/app/package.json')]
        return super().helper(args,mounts=[*extra,*mounts],**kwargs)

    def inventory(self):
        result=super().inventory()
        result['networks']=self.docker('network','ls','--format','{{.ID}} {{.Name}}',sensitive=True).stdout.splitlines()
        result={k:sorted(v) for k,v in result.items()}
        if self.resources_before is None and not (self.folder/'resources-before.json').exists():
            (self.folder/'resources-before.json').write_text(json.dumps(result,indent=2)+'\n')
        return result

    def suite(self,key,path,offset):
        self.phase=key;self.memory_admission()
        config=json.loads(self.secret_path.read_text());config['suiteOffset']=offset;self.secret_path.write_text(json.dumps(config))
        expected=len(re.findall(r'^test\(',path.read_text(),re.MULTILINE));require(expected>0,'Empty native suite refused')
        result=self.helper(['node','--import','tsx','--test','--test-reporter=tap','--test-concurrency=1',str(path.relative_to(ROOT))],timeout=600 if key=='authority_loader' else 300,allow_failure=True)
        log=self.folder/f'{self.serial:03d}-{self.phase}.log'
        self.report.setdefault('test_logs',{})[key]={'path':str(log.relative_to(ROOT)),'sha256':sha(log.read_bytes())}
        require(result.returncode==0,'Required native suite failed; original safe TAP retained')
        self.report[key]=base.tap_summary(result.stdout,expected);self.save()


def execute(h):
    full_sources=sources()
    # The predecessor replaces its own source list. Keep the complete source
    # binding even when it fails before SQL013 or a native suite is reached.
    h.report['diagnostic_sources']=full_sources
    # This is real prerequisite execution, not copied totals from a historical run.
    base.execute(h)
    h.report['predecessor']={key:h.report[key] for key in ('tests','concurrency_tests','migrations','baseline','sources')}
    h.report['sources']=full_sources
    (h.folder/'resources-before.json').write_text(json.dumps(h.resources_before,indent=2)+'\n')
    require(len(h.report['migrations'])==12,'Exactly SQL001–012 must precede the authority migration')
    h.phase='authority-preupgrade'
    tables=json.loads(h.sql("SELECT json_agg(schemaname||'.'||tablename ORDER BY schemaname,tablename) FROM pg_tables WHERE schemaname IN('public','gc_authn') AND tablename<>'schema_migrations';"))
    before=h.snapshot(tables)
    ledger=json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM public.schema_migrations m;'))
    privilege_sql="SELECT json_agg(json_build_object('signature',p.oid::regprocedure::text,'owner',pg_get_userbyid(p.proowner),'definer',p.prosecdef,'legacy',has_function_privilege('gc_app',p.oid,'EXECUTE'),'acl',p.proacl::text) ORDER BY p.oid::regprocedure::text) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN('public','gc_authn');"
    privileges=json.loads(h.sql(privilege_sql))
    h.report['preupgradePrivilegesSha256']=sha(json.dumps(privileges,sort_keys=True,separators=(',',':')).encode())
    target=h.folder/'authority-target';target.mkdir()
    for name in [*base.NAMES,MIGRATION]:shutil.copyfile(base.MIGRATIONS/name,target/name)
    roles=module(ROOT/'scripts/authentication_roles.py','authority_role_transfer')
    h.phase='authority-missing-transfer'
    refused=h.migrate(target,allow_failure=True)
    require(refused.returncode!=0,'SQL013 unexpectedly bypassed the required ownership-transfer preparation')
    require(h.snapshot(tables)==before,'Missing transfer preparation changed predecessor rows')
    require(h.sql("SELECT count(*) FROM pg_namespace WHERE nspname='gc_authority';")=='0','Missing transfer preparation left a partial schema')
    try:
        h.sql(roles.prepare_sql(base.OWNER,base.DATABASE))
        # Namespace collision must abort every new migration statement.
        h.sql('CREATE SCHEMA gc_authority AUTHORIZATION gc_owner;')
        failed=h.migrate(target,allow_failure=True)
        require(failed.returncode!=0,'Existing authority namespace was overwritten')
        require(h.snapshot(tables)==before,'Refused migration changed predecessor rows')
        require(h.sql("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='gc_authority';")=='0','Refused migration left partial relations')
        h.sql('DROP SCHEMA gc_authority;')
    finally:
        h.sql(roles.finish_sql(base.OWNER))
    require(h.sql("SELECT count(*) FROM pg_auth_members WHERE roleid='gc_authn_definer'::regrole AND member='gc_owner'::regrole;")=='0','Failure cleanup retained transfer membership')
    try:
        h.sql(roles.prepare_sql(base.OWNER,base.DATABASE))
        h.phase='authority-upgrade'
        applied=h.migrate(target)
        require(re.findall(r'^Applied (.+)$',applied.stdout,re.MULTILINE)==[MIGRATION],'Upgrade was not exactly SQL013')
    finally:
        h.sql(roles.finish_sql(base.OWNER))
    require(h.snapshot(tables)==before,'SQL013 altered existing canonical or protected authentication rows')
    after_ledger=json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM public.schema_migrations m;'))
    require(after_ledger[:12]==ledger and len(after_ledger)==13,'Old checksum/timestamp ledger changed')
    after_privileges=json.loads(h.sql(privilege_sql));by_signature={r['signature']:r for r in after_privileges}
    require(all(by_signature.get(row['signature'])==row for row in privileges),'Existing function owner/definer/ACL changed')
    require('Applied' not in h.migrate(target).stdout,'SQL013 replay was not inert')
    require(h.snapshot(tables)==before,'Replay changed predecessor rows')
    h.report['checks'].append('Actual SQL001–012 rows/receipts and function ACLs survive missing ownership-transfer and transactional namespace refusal, exact SQL013 application and replay; original migration ledger remains byte-bound')
    h.report['migrations']=[{'name':name,'sha256':sha((base.MIGRATIONS/name).read_bytes())} for name in [*base.NAMES,MIGRATION]]
    h.report['authorityUpgradeBaseline']=[{'table':name,'rows':len(rows),'sha256':sha(json.dumps(rows,sort_keys=True,separators=(',',':')).encode())} for name,rows in before.items()]
    # Fresh native credentials/slots prevent old suite registrations or revocations
    # from masquerading as a clean fixture. No existing role is reactivated.
    config=json.loads(h.secret_path.read_text());definitions=[]
    for index in range(len(config['slots']),224):
        slot={}
        for field,kind in [('login','login'),('api','api'),('nextLogin','login'),('nextApi','api')]:
            name,secret=f'gc_af_{field.lower()}_{index:03}',secrets.token_hex(24)
            definitions.append({'name':name,'kind':kind,'password':secret});h.private_values.append(secret)
            slot[field]={'name':name,'url':f'postgresql://{name}:{secret}@127.0.0.1:5432/{base.DATABASE}'}
        config['slots'].append(slot)
    h.sql(roles.executor_sql(base.DATABASE,definitions));h.secret_path.write_text(json.dumps(config))
    # SQL013 touches canonical identity/member triggers: rerun both actual prior
    # protected-session suites on the upgraded schema, with new native roles.
    h.suite('authn_storage_regression',base.TEST,64)
    h.suite('authn_concurrency_regression',base.CONCURRENCY,96)
    for key,path,offset in SUITES:h.suite('authority_'+key,ROOT/path,offset)
    current=h.snapshot(tables)
    for name,rows in before.items():require(all(row in current[name] for row in rows),'Original predecessor row changed or disappeared')
    require(sources()==full_sources,'Authority gate source changed during execution')
    h.report['checks'].append('Real post-upgrade authentication storage/concurrency and all three inactive authority suites passed with native TCP roles, no skips or copied success totals')
    h.report['limitations']=[
        'Inactive owner-only candidate evidence; no content authorization, administration consent, runtime grant adapter, production containment/facts, scope-capacity or release qualification.',
        'All fixture grants and registry contexts are explicitly synthetic integrity probes; SQL012 protocol-issued sessions do not simulate an external OIDC exchange.',
        'Conservative full candidate selection may refuse production-valid scopes until a separately qualified canonical scope selector exists; no business population cap is inferred.',
        'This isolated native gate does not substitute for applicable full API/browser regressions or hosted immutable-image qualification.',
        'Cached image plus exact read-only source mounts; no build, pull, shared resource changes or production deployment.']


def main():
    h=Harness();failed=False
    try:execute(h)
    except BaseException as error:
        failed=True;h.remember_failure(error);h.report.update(result='FAIL',error_type=type(error).__name__,error='Native authority qualification failed; inspect bounded private evidence')
    finally:
        try:
            h.phase='cleanup';h.cleanup()
            if h.resources_before is not None:
                h.deadline=h.cleanup_deadline;after=h.inventory()
                (h.folder/'resources-after.json').write_text(json.dumps(after,indent=2)+'\n')
                require(after==h.resources_before,'Preexisting resource inventory changed')
                h.report['cleanup']['resourceInventoryPreserved']=True
                h.report['resourceInventories']=[{'path':str((h.folder/name).relative_to(ROOT)),'sha256':sha((h.folder/name).read_bytes())} for name in ('resources-before.json','resources-after.json') if (h.folder/name).exists()]
        except BaseException as error:
            failed=True;h.remember_failure(error);h.report.update(result='FAIL',cleanupFailure='Owned cleanup or resource preservation was not confirmed',cleanupErrorType=type(error).__name__)
        h.report['result']='FAIL' if failed else 'PASS';h.report['recorded_at']=datetime.now(timezone.utc).isoformat();h.report['evidence_directory']=str(h.folder.relative_to(ROOT))
        h.report['private_logs']=[{'path':str(p.relative_to(ROOT)),'sha256':sha(p.read_bytes())} for p in sorted(h.folder.glob('*.log'))];h.save(final=True)
    print(json.dumps({'result':h.report['result'],'report':str(REPORT.relative_to(ROOT))}));return int(failed)

if __name__=='__main__':raise SystemExit(main())
