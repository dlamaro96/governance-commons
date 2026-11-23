#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Private SQL033 content revision qualification on owned network-none PostgreSQL.

Populate exact SQL032, retain every existing row, ledger, function and privilege
boundary across SQL033, execute real mutation/concurrency/context cases and replay.
This is inactive provenance, not the complete authority or release gate.
"""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / '.local/evidence/content-security-revision.json'
NEW_TEST = 'tests/qualification/content-security-revision.test.ts'
MIGRATION = '033_content_security_revisions.sql'
PRECURSORS = [('content-revision-pre032-context', 'tests/qualification/authority-asset-context.test.ts', 13),
              ('content-revision-pre032-classification', 'tests/api/classification-storage.test.ts', 14)]
PHASE = 'content-security-revision-native'
PHASES = (*[row[0] for row in PRECURSORS], PHASE)
EXECUTION_SECONDS = 780
CLEANUP_SECONDS = 90
WRAPPER_SECONDS = 900

def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

asset = module(ROOT / 'scripts/runtime-test-authority-asset-context.py', 'content_revision_asset_transport')
read, authority, volume = asset.read, asset.authority, asset.volume
require, sha = asset.require, asset.sha
_original_sources = asset.sources
NAMES = [*asset.NAMES, MIGRATION]

def migrations():
    require(sorted(p.name for p in (ROOT / 'packages/db/migrations').glob('*.sql')) == NAMES,
            'Exactly immutable SQL001–033 required')
    return list(NAMES)

def sources():
    migrations()
    paths = {r['path'] for r in _original_sources()} | {
        NEW_TEST, 'scripts/runtime-test-content-security-revision.py', 'scripts/test_content_security_revision.py',
        'tests/api/classification-storage.test.ts', 'packages/db/migrations/' + MIGRATION}
    pending = [ROOT / p for p in paths if p.endswith(('.ts', '.tsx'))]
    while pending:
        current = pending.pop()
        for name in re.findall(r'''(?:from\s*|import\s*(?:\(\s*)?|require\s*\(\s*)['"](\.[^'"]+)['"]''', volume.source_file(current).read_text()):
            candidate = Path(os.path.abspath(current.parent / name))
            if candidate.suffix == '.js' and not candidate.exists():
                candidate = candidate.with_suffix('.ts')
            if not candidate.suffix:
                candidate = candidate.with_suffix('.ts') if candidate.with_suffix('.ts').exists() else candidate / 'index.ts'
            candidate = volume.source_file(candidate)
            rel = str(candidate.relative_to(ROOT))
            if rel not in paths:
                paths.add(rel)
                if candidate.suffix in ('.ts', '.tsx'):
                    pending.append(candidate)
    require(len(paths) <= 1024, 'Qualification source inventory exceeds bound')
    return [{'path': p, 'sha256': sha(volume.source_file(ROOT / p).read_bytes())} for p in sorted(paths)]

volume.PHASES = PHASES
volume.sources = sources
volume.effective_sources = lambda rows, phase: rows if phase in PHASES else (_ for _ in ()).throw(RuntimeError('Undeclared native phase'))

class Harness(authority.Harness):
    def __init__(self):
        # Source admission consumes this same absolute execution budget. The
        # shared foundation constructor has a longer profile; do not inherit or
        # renew its deadline after hashing this gate's current source closure.
        execution_started = time.monotonic()
        execution_deadline = execution_started + EXECUTION_SECONDS
        authority.REPORT = REPORT
        self.frozen = sources()
        super().__init__()
        self.deadline = execution_deadline
        self.report.update(command='python3 scripts/runtime-test-content-security-revision.py --run-local',
                           profile='isolated-content-security-revision-sql033', qualificationSources=self.frozen,
                           bounds={'executionSeconds': EXECUTION_SECONDS, 'cleanupSeconds': CLEANUP_SECONDS,
                                   'developerWrapperSeconds': WRAPPER_SECONDS, 'wrapperReserveSeconds': WRAPPER_SECONDS-EXECUTION_SECONDS-CLEANUP_SECONDS,
                                   'sourceAdmissionIncluded': True, 'sqlStatementSeconds': 25,
                                   'repositoryOperationSeconds': 30, 'defaultCommandSeconds': 120,
                                   'nativeHelperSeconds': 180})
        self.save(final=True)

    def command(self, args, **kwargs):
        # Final inventory is cleanup work too. Do not replace the absolute
        # execution deadline with a later cleanup deadline to read it back.
        if self.phase == 'cleanup':
            kwargs['cleanup'] = True
        return super().command(args, **kwargs)

    def helper(self, args, **kwargs):
        self.report['privateConfigSha256'] = sha(self.secret_path.read_bytes())
        return volume.Harness.helper(self, args, **kwargs)

    def migrate(self, directory, **kwargs):
        previous = self.phase
        self.phase = 'schema-' + previous
        try:
            return super().migrate(directory, **kwargs)
        finally:
            self.phase = previous

# Full ordinary-table metadata and native role flags/membership are part of the
# installation boundary. IDs/passwords are not published in the compact report.
PRIVILEGES = """SELECT jsonb_build_object(
 'tables',(SELECT jsonb_agg(jsonb_build_object('name',n.nspname||'.'||c.relname,'owner',c.relowner::text,'acl',c.relacl::text,'rls',c.relrowsecurity,'forced',c.relforcerowsecurity) ORDER BY n.nspname,c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN('public','gc_authn','gc_authority') AND c.relkind IN('r','p','v','m')),
 'roles',(SELECT jsonb_agg(jsonb_build_object('name',rolname,'oid',oid::text,'super',rolsuper,'inherit',rolinherit,'createRole',rolcreaterole,'createDb',rolcreatedb,'login',rolcanlogin,'replication',rolreplication,'bypass',rolbypassrls) ORDER BY rolname) FROM pg_roles WHERE rolname IN('gc_owner','gc_app','gc_authn_definer') OR rolname LIKE 'gc_af_%'),
 'memberships',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY roleid,member,grantor),'[]') FROM pg_auth_members m));"""

TRIGGERS = """SELECT coalesce(jsonb_agg(jsonb_build_object('schema',n.nspname,'table',c.relname,'name',t.tgname,'function',t.tgfoid::regprocedure::text,'definition',pg_get_triggerdef(t.oid),'enabled',t.tgenabled) ORDER BY n.nspname,c.relname,t.tgname),'[]') FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN('public','gc_authn','gc_authority') AND NOT t.tgisinternal;"""
FUNCTION_ADDITIONS = {'gc_authority.content_revision_head_guard()', 'gc_authority.content_revision_tenant_insert()',
                      'gc_authority.content_revision_advance()', 'gc_authority.content_revision_no_reset()'}
COVERED = {'assets','domains','asset_domain_placements','classification_taxonomies','classification_rules','classification_assignments'}
TRUNCATE_COVERED = COVERED | {'tenants','asset_revisions','domain_revisions','asset_domain_placement_revisions',
    'classification_taxonomy_versions','classification_rule_versions','classification_evaluations','classification_assignment_revisions','domain_type_versions'}

def trigger_additions():
    return {('gc_authority','content_security_heads','content_revision_head_guard'),
            ('gc_authority','content_security_heads','content_revision_head_no_truncate'),
            ('public','tenants','content_revision_tenant_insert'),('public','tenants','content_revision_tenant_no_reset')} | {
            ('public',name,'content_revision_advance') for name in COVERED} | {
            ('public',name,'content_revision_no_truncate') for name in TRUNCATE_COVERED}

def preserve_installation(before_tables, before_functions, before_privileges, before_triggers,
                          after_tables, after_functions, after_privileges, after_triggers):
    require(set(after_tables)-set(before_tables)=={'gc_authority.content_security_heads'}
            and set(before_tables)<=set(after_tables), 'SQL033 must add exactly the private revision table')
    functions={r['signature']:r for r in after_functions}
    require(all(functions.get(r['signature'])==r for r in before_functions), 'Existing function body/interface/ACL changed')
    require(set(functions)-{r['signature'] for r in before_functions}==FUNCTION_ADDITIONS, 'SQL033 function additions differ')
    before_by={r['name']:r for r in before_privileges['tables']}
    after_by={r['name']:r for r in after_privileges['tables']}
    require(set(after_by)-set(before_by)=={'gc_authority.content_security_heads'}
            and all(after_by.get(k)==v for k,v in before_by.items()), 'Existing table ACL/owner/RLS inventory changed')
    require({k:v for k,v in before_privileges.items() if k!='tables'}=={k:v for k,v in after_privileges.items() if k!='tables'},
            'Native role flags or memberships changed')
    head=after_by['gc_authority.content_security_heads']
    require(head['rls'] is True and head['forced'] is True, 'Private revision table must force RLS')
    key=lambda r:(r['schema'],r['table'],r['name'])
    triggers={key(r):r for r in after_triggers}
    require(all(triggers.get(key(r))==r for r in before_triggers), 'Existing trigger definition or enablement changed')
    require(set(triggers)-{key(r) for r in before_triggers}==trigger_additions(), 'SQL033 trigger coverage differs')

def execute(h):
    read.setup(h)
    read.additional_roles(h, 48)
    target=h.folder/'content-revision-target'
    target.mkdir()
    for name in NAMES[:-1]:
        shutil.copyfile(ROOT/'packages/db/migrations'/name,target/name)
    h.phase='content-revision-install032'
    require(re.findall(r'^Applied (.+)$',h.migrate(target).stdout,re.M)==NAMES[30:32], 'Exact031/032 predecessor installation required')
    read.ledger(h,NAMES[:-1])
    read.config_offset(h,0)
    for phase,path,expected in PRECURSORS:
        volume.native_suite(h,phase,path,expected)
    h.phase='content-revision-preupgrade'
    tables=volume.canonical_tables(h)
    before=read.snapshot(h,tables)
    require(all(before['public.'+name]['rows']>0 for name in COVERED), 'SQL032 preservation fixture must populate every covered canonical family')
    prior=read.ledger(h,NAMES[:-1])
    functions=json.loads(h.sql(read.FUNCTIONS))
    privileges=json.loads(h.sql(PRIVILEGES))
    triggers=json.loads(h.sql(TRIGGERS))
    shutil.copyfile(ROOT/'packages/db/migrations'/MIGRATION,target/MIGRATION)
    h.phase='content-revision-upgrade'
    require(re.findall(r'^Applied (.+)$',h.migrate(target).stdout,re.M)==[MIGRATION], 'Exactly033 must apply')
    ledger=read.ledger(h,NAMES)
    current_tables=volume.canonical_tables(h)
    current_functions=json.loads(h.sql(read.FUNCTIONS))
    current_privileges=json.loads(h.sql(PRIVILEGES))
    current_triggers=json.loads(h.sql(TRIGGERS))
    preserve_installation(tables,functions,privileges,triggers,current_tables,current_functions,current_privileges,current_triggers)
    require(ledger[:-1]==prior and read.snapshot(h,tables)==before, 'SQL033 changed existing canonical rows or migration history')
    baseline=json.loads(h.sql("SELECT jsonb_build_object('tenants',(SELECT count(*) FROM public.tenants),'heads',(SELECT count(*) FROM gc_authority.content_security_heads),'missing',(SELECT count(*) FROM public.tenants t LEFT JOIN gc_authority.content_security_heads h ON h.tenant_id=t.id WHERE h.tenant_id IS NULL),'nonInitial',(SELECT count(*) FROM gc_authority.content_security_heads WHERE revision<>1));"))
    require(baseline['tenants']>0 and baseline['heads']==baseline['tenants'] and baseline['missing']==baseline['nonInitial']==0,
            'Every populated existing tenant requires exactly one revision-one baseline')
    h.report['installation']={'before':before,'priorLedger':prior,'ledger':ledger,'baseline':baseline,'preservation':True,
        'functionsBeforeSha256':sha(json.dumps(functions,sort_keys=True).encode()),'functionsAfterSha256':sha(json.dumps(current_functions,sort_keys=True).encode()),
        'privilegesBeforeSha256':sha(json.dumps(privileges,sort_keys=True).encode()),'privilegesAfterSha256':sha(json.dumps(current_privileges,sort_keys=True).encode()),
        'triggersBeforeSha256':sha(json.dumps(triggers,sort_keys=True).encode()),'triggersAfterSha256':sha(json.dumps(current_triggers,sort_keys=True).encode()),
        'addedFunctions':sorted(FUNCTION_ADDITIONS),'addedTriggers':sorted(trigger_additions())}
    def replay(phase):
        h.phase=phase
        snapshot=read.snapshot(h,current_tables)
        require('Applied' not in h.migrate(target).stdout and read.ledger(h,NAMES)==ledger
                and volume.canonical_tables(h)==current_tables and read.snapshot(h,current_tables)==snapshot
                and json.loads(h.sql(read.FUNCTIONS))==current_functions and json.loads(h.sql(PRIVILEGES))==current_privileges
                and json.loads(h.sql(TRIGGERS))==current_triggers, 'SQL033 replay changed populated rows/ledger/functions/privileges/triggers')
        return snapshot
    replay('content-revision-replay-before')
    h.report['installation']['replayBefore']=True
    expected=len(re.findall(r'^test\(', (ROOT/NEW_TEST).read_text(),re.M))
    require(expected==20, 'Declared content revision native inventory differs')
    read.config_offset(h,16)
    volume.native_suite(h,PHASE,NEW_TEST,expected)
    require(json.loads(h.sql(read.FUNCTIONS))==current_functions and json.loads(h.sql(PRIVILEGES))==current_privileges
            and json.loads(h.sql(TRIGGERS))==current_triggers, 'Native fixtures changed functions/privileges/trigger definitions')
    populated=replay('content-revision-populated-replay')
    require(sources()==h.frozen and [r['phase'] for r in h.report['nativeSuites']]==list(PHASES), 'Qualification source or suite assignment drifted')
    h.report.update(sources=h.frozen,migrations=ledger,sourceHashesMatched=True,
        nativeTotals={key:sum(r['tests'][key] for r in h.report['nativeSuites']) for key in ('tests','pass','fail','cancelled','skipped','todo')},
        populatedReplay={'snapshot':populated,'preservation':True},
        limitations=['Inactive content-revision provenance only; no canonical authority decision or HTTP/browser activation.',
          'Exact populatedSQL032 with existing13 context and14 classification cases precedes SQL033;20 new native cases qualify its behavior.',
          'Counter overflow/missing-head controls disable only the new head guard in the owned isolated database and restore exact data/trigger state.',
          'Existing immutable-head deletions remain refused; successful supported mutations and failed rollback paths are distinguished.',
          'One780-second execution allowance includes source admission, plus existing90-second cleanup; SQL25s/repository30s remain unchanged.',
          'Cached immutable dependency images and exact read-only current-source mounts; no build, vendor or supported-release qualification.'])

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-local', action='store_true')
    args=parser.parse_args()
    require(args.run_local, 'Explicit --run-local required')
    h=Harness()
    failed=False
    try:
        execute(h)
    except BaseException as error:
        failed=True
        h.report.update(failed_phase=h.phase, error_type=type(error).__name__, error='Inspect bounded private evidence')
    finally:
        try:
            h.phase='cleanup'
            h.cleanup()
            if h.resources_before is not None:
                observed=h.inventory()
                (h.folder/'resources-after.json').write_text(json.dumps(observed,sort_keys=True)+'\n')
                require(observed==h.resources_before, 'Preexisting resource inventory changed')
                h.report['cleanup']['resourceInventoryPreserved']=True
        except BaseException as error:
            failed=True
            h.report['cleanupErrorType']=type(error).__name__
        finally:
            try:
                h.secret_path.unlink(missing_ok=True)
                require(not h.secret_path.exists(), 'Generated credential cleanup refused')
                h.report.setdefault('cleanup',{})['generatedCredentialsRemoved']=True
            except BaseException as error:
                failed=True
                h.report.setdefault('cleanup',{})['generatedCredentialsRemoved']=False
                h.report['credentialCleanupErrorType']=type(error).__name__
        h.report.update(result='FAIL' if failed else 'PASS', recorded_at=datetime.now(timezone.utc).isoformat(), evidence_directory=str(h.folder.relative_to(ROOT)))
        h.report['private_logs']=[{'path':str(p.relative_to(ROOT)),'sha256':sha(p.read_bytes())} for p in sorted(h.folder.glob('*.log'))]
        h.save(final=True)
    print(json.dumps({'result':h.report['result'],'report':str(REPORT.relative_to(ROOT))}))
    return int(failed)

if __name__=='__main__':
    raise SystemExit(main())
