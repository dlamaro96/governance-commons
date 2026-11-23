#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inactive native asset-context qualification on owned network-none PostgreSQL.

Apply exact SQL001–030 and then031/032, retain every table/ledger/function/ACL
boundary, execute the declared current-source native suite, and replay without
writes. This is not the complete authority, browser, or release gate.
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
REPORT = ROOT / '.local/evidence/authority-asset-context.json'
NEW_TEST = 'tests/qualification/authority-asset-context.test.ts'
PHASE = 'authority-asset-context-native'
EXECUTION_SECONDS = 780
CLEANUP_SECONDS = 90
WRAPPER_SECONDS = 900

def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

read = module(ROOT / 'scripts/runtime-test-authority-read-upgrade.py', 'asset_context_read_transport')
authority, volume = read.authority, read.volume
require, sha = read.require, read.sha
_original_sources = read.sources
NAMES = [*read.NAMES, '032_relation_candidate_validation.sql']

def sources():
    require(sorted(p.name for p in (ROOT / 'packages/db/migrations').glob('*.sql')) == NAMES,
            'Exactly immutable SQL001–032 required')
    paths = {r['path'] for r in _original_sources()} | {
        NEW_TEST, 'scripts/runtime-test-authority-asset-context.py', 'scripts/test_authority_asset_context.py',
        'packages/db/migrations/032_relation_candidate_validation.sql'}
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

volume.PHASES = (PHASE,)
volume.sources = sources
volume.effective_sources = lambda rows, phase: rows if phase == PHASE else (_ for _ in ()).throw(RuntimeError('Undeclared native phase'))

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
        self.report.update(command='python3 scripts/runtime-test-authority-asset-context.py --run-local',
                           profile='isolated-inactive-asset-context-sql032', qualificationSources=self.frozen,
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

def execute(h):
    read.setup(h)
    read.additional_roles(h, 48)
    read.config_offset(h, 0)
    h.phase = 'asset-context-preupgrade'
    tables = volume.canonical_tables(h)
    before = read.snapshot(h, tables)
    prior = read.ledger(h, NAMES[:30])
    functions = json.loads(h.sql(read.FUNCTIONS))
    privileges = json.loads(h.sql(PRIVILEGES))
    target = h.folder / 'asset-context-target'
    target.mkdir()
    for name in NAMES:
        shutil.copyfile(ROOT / 'packages/db/migrations' / name, target / name)
    h.phase = 'asset-context-upgrade'
    applied = h.migrate(target)
    require(re.findall(r'^Applied (.+)$', applied.stdout, re.M) == NAMES[30:], 'Exactly031 and032 must apply')
    ledger = read.ledger(h, NAMES)
    current = json.loads(h.sql(read.FUNCTIONS))
    by = {r['signature']: r for r in current}
    allowed = {'gc_authority.load_human_closure_v1(text,text)', 'gc_relation_check_type(uuid,uuid)'}
    changed = []
    for row in functions:
        observed = by[row['signature']]
        if observed != row:
            require(row['signature'] in allowed and {k:v for k,v in row.items() if k != 'body'} == {k:v for k,v in observed.items() if k != 'body'}, 'Unexpected function/ACL change')
            changed.append(row['signature'])
    require(set(changed) == allowed, 'Expected forward correction bodies differ')
    require(set(by) - {r['signature'] for r in functions} == {'gc_authority.validate_read_grants_v1(uuid,uuid[])'}, 'Unexpected function inventory')
    require(ledger[:-2] == prior and volume.canonical_tables(h) == tables and read.snapshot(h, tables) == before,
            'Forward installation changed existing canonical rows or ledger')
    require(json.loads(h.sql(PRIVILEGES)) == privileges, 'Forward installation changed role or table ACL inventory')
    h.report['installation'] = {'before': before, 'priorLedger': prior, 'ledger': ledger,
        'changedFunctionBodies': sorted(changed), 'functionsBeforeSha256': sha(json.dumps(functions, sort_keys=True).encode()),
        'functionsAfterSha256': sha(json.dumps(current, sort_keys=True).encode()),
        'privilegesSha256': sha(json.dumps(privileges, sort_keys=True).encode()), 'preservation': True}
    h.phase = 'asset-context-replay-before'
    require('Applied' not in h.migrate(target).stdout and read.ledger(h, NAMES) == ledger
            and volume.canonical_tables(h) == tables and read.snapshot(h, tables) == before
            and json.loads(h.sql(read.FUNCTIONS)) == current and json.loads(h.sql(PRIVILEGES)) == privileges,
            'Fresh forward replay changed canonical state')
    h.report['installation']['replayBefore'] = True
    expected = len(re.findall(r'^test\(', (ROOT / NEW_TEST).read_text(), re.M))
    require(expected == 13, 'Declared asset context suite inventory differs')
    volume.native_suite(h, PHASE, NEW_TEST, expected)
    h.phase = 'asset-context-populated-replay'
    populated = read.snapshot(h, tables)
    require(json.loads(h.sql(read.FUNCTIONS)) == current and json.loads(h.sql(PRIVILEGES)) == privileges,
            'Native fixtures changed function or privilege inventory')
    require('Applied' not in h.migrate(target).stdout and read.ledger(h, NAMES) == ledger
            and volume.canonical_tables(h) == tables and read.snapshot(h, tables) == populated
            and json.loads(h.sql(read.FUNCTIONS)) == current and json.loads(h.sql(PRIVILEGES)) == privileges,
            'Populated replay changed canonical state')
    require(sources() == h.frozen, 'Qualification inputs drifted')
    h.report.update(sources=h.frozen, migrations=ledger, sourceHashesMatched=True,
        populatedReplay={'snapshot':populated,'preservation':True},
        limitations=['Inactive native-owner asset context only; no runtime content authority or HTTP/browser qualification.',
          'Exact SQL001–030 starts empty, then031/032 and thirteen current-source native cases populate the owned database.',
          'Domain fixture uses existing projection/seal writes; it does not prove UI preview consent.',
          'Corrupt ACL/hierarchy and historical expired-session fixtures are owner-injected and restored; no production storage mutation.',
          'Original25-second SQL/30-second repository operation limits and bounded helper/process budgets unchanged.',
          'Cached immutable image dependencies with exact read-only current-source mounts; no image build or release claim.'])

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
