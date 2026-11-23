#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Private SQL034 stable label identity qualification on owned network-none PostgreSQL.

Populate SQL032, preserve SQL033 installation, author real reused-key history,
then preserve every prior canonical row and privilege boundary across SQL034.
Identity storage only: no classification fact producer or authority activation.
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
import uuid
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / '.local/evidence/classification-label-identities.json'
NEW_TEST = 'tests/qualification/classification-label-identities.test.ts'
MIGRATION = '034_classification_label_identities.sql'
PRECURSORS = [('classification-label-pre032-context', 'tests/qualification/authority-asset-context.test.ts', 13),
              ('classification-label-pre032-classification', 'tests/api/classification-storage.test.ts', 14)]
PHASE = 'classification-label-identities-native'
EXPECTED_TESTS = 23
PHASES = (*[row[0] for row in PRECURSORS], PHASE)
EXECUTION_SECONDS = 780
CLEANUP_SECONDS = 90
WRAPPER_SECONDS = 900

def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

predecessor = module(ROOT / 'scripts/runtime-test-content-security-revision.py', 'label_identity_predecessor')
read, authority, volume = predecessor.read, predecessor.authority, predecessor.volume
require, sha = predecessor.require, predecessor.sha
_original_sources = predecessor.sources
NAMES = [*predecessor.NAMES, MIGRATION]

def migrations():
    actual = sorted(p.name for p in (ROOT / 'packages/db/migrations').glob('*.sql'))
    successors = ['035_reviewed_classification_producer.sql', '036_authority_scope_alignment.sql']
    suffix = actual[len(NAMES):]
    require(actual[:len(NAMES)] == NAMES and suffix == successors[:len(suffix)],
            'Exact immutable SQL001–034 prefix and declared contiguous035–036 successors required')
    return list(NAMES)

def sources():
    migrations()
    paths = {r['path'] for r in _original_sources()} | {
        NEW_TEST, 'scripts/runtime-test-classification-label-identities.py', 'scripts/test_classification_label_identities.py',
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
        self.report.update(command='python3 scripts/runtime-test-classification-label-identities.py --run-local',
                           profile='isolated-classification-label-identities-sql034', qualificationSources=self.frozen,
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

# Reuse the exact predecessor object capture. Additional tables/functions/triggers
# are closed below; every prior row and role/ACL/object definition stays exact.
PRIVILEGES, TRIGGERS = predecessor.PRIVILEGES, predecessor.TRIGGERS
TABLE_ADDITIONS = {'gc_authority.classification_label_baselines',
                   'gc_authority.classification_label_identities',
                   'gc_authority.classification_label_version_bindings'}
FUNCTION_ADDITIONS = {'gc_authority.classification_label_write_guard()',
    'gc_authority.classification_label_version_complete(uuid,uuid,integer)',
    'gc_authority.classification_label_publish()', 'gc_authority.classification_label_head_complete()'}

def trigger_additions():
    return {('gc_authority', name.split('.')[1], trigger) for name in TABLE_ADDITIONS
            for trigger in ('classification_label_write_guard', 'classification_label_no_truncate')} | {
        ('public', 'classification_taxonomy_versions', 'classification_label_publish'),
        ('public', 'classification_taxonomies', 'classification_label_head_complete')}

def preserve_installation(before_tables, before_functions, before_privileges, before_triggers,
                          after_tables, after_functions, after_privileges, after_triggers):
    require(set(after_tables)-set(before_tables)==TABLE_ADDITIONS and set(before_tables)<=set(after_tables),
            'SQL034 must add exactly three private identity tables')
    functions={r['signature']:r for r in after_functions}
    require(len(functions)==len(after_functions) and all(functions.get(r['signature'])==r for r in before_functions),
            'Existing function body/interface/ACL changed')
    require(set(functions)-{r['signature'] for r in before_functions}==FUNCTION_ADDITIONS, 'SQL034 function additions differ')
    before_by={r['name']:r for r in before_privileges['tables']}
    after_by={r['name']:r for r in after_privileges['tables']}
    require(set(after_by)-set(before_by)==TABLE_ADDITIONS and all(after_by.get(k)==v for k,v in before_by.items()),
            'Existing table ACL/owner/RLS inventory changed')
    require({k:v for k,v in before_privileges.items() if k!='tables'}=={k:v for k,v in after_privileges.items() if k!='tables'},
            'Native role flags or memberships changed')
    require(all(after_by[name]['rls'] is True and after_by[name]['forced'] is True for name in TABLE_ADDITIONS),
            'Every private identity table must force RLS')
    key=lambda r:(r['schema'],r['table'],r['name'])
    triggers={key(r):r for r in after_triggers}
    require(len(triggers)==len(after_triggers) and all(triggers.get(key(r))==r for r in before_triggers),
            'Existing trigger definition or enablement changed')
    require(set(triggers)-{key(r) for r in before_triggers}==trigger_additions(), 'SQL034 trigger coverage differs')

def baseline_fixture():
    return {'tenantId':str(uuid.uuid4()), 'taxonomyId':str(uuid.uuid4()), 'baselineVersion':3,
            'retainedKey':'retained', 'absentKey':'absent', 'deprecatedKey':'deprecated', 'reusedKey':'reused'}

def baseline_definitions():
    labels=lambda pairs:[{'key':key,'name':key.title(),'description':'Synthetic installation baseline label.','status':status}
                         for key,status in pairs]
    sets=[[(key,'active') for key in ('retained','absent','deprecated','reused')],
          [('retained','active'),('deprecated','deprecated')],
          [('retained','active'),('deprecated','deprecated'),('reused','active')]]
    return [{'formatVersion':1,'name':'Synthetic baseline history','description':'Migration-era identity qualification.',
             'labels':labels(pairs)} for pairs in sets]

def seed_baselines(h):
    # This authored fixture is inside the hashed harness. No direct version/head
    # insertion can bypass the canonical publisher, journal or SQL033 epoch.
    fixtures=[baseline_fixture(),baseline_fixture()]
    permissions=['catalog:read','classification:read','classification:write','models:read','models:write']
    for fixture in fixtures:
        actor=str(uuid.uuid4());tenant=fixture['tenantId'];taxonomy=fixture['taxonomyId']
        commands=[]
        for expected,definition in enumerate(baseline_definitions()):
            body=json.dumps({'id':taxonomy,'expectedVersion':expected,'definition':definition},separators=(',',':'))
            commands.append("PERFORM public.gc_classification_command('classification.taxonomy.publish',"+
                authority.literal(str(uuid.uuid4()))+","+authority.literal(body)+"::jsonb,'classification-label-baseline');")
        h.sql("BEGIN; SET LOCAL statement_timeout='25s'; SET LOCAL lock_timeout='2s'; DO $fixture$ BEGIN "+
            "INSERT INTO public.tenants(id,name) VALUES("+authority.literal(tenant)+"::uuid,'Synthetic label identity tenant');"+
            "INSERT INTO public.identities(id,issuer,subject,name) VALUES("+authority.literal(actor)+"::uuid,"+
            "'https://classification-label-identity.invalid',"+authority.literal(actor)+",'Synthetic baseline steward');"+
            "PERFORM set_config('gc.tenant_id',"+authority.literal(tenant)+",true);"+
            "PERFORM set_config('gc.actor_id',"+authority.literal(actor)+",true);"+
            "INSERT INTO public.memberships(tenant_id,identity_id,role,permissions) VALUES("+authority.literal(tenant)+
            "::uuid,"+authority.literal(actor)+"::uuid,'synthetic',"+authority.literal(json.dumps(permissions))+"::jsonb);"+
            ''.join(commands)+" END $fixture$; SET CONSTRAINTS ALL IMMEDIATE; COMMIT;",role=authority.base.OWNER)
    config=json.loads(h.secret_path.read_text())
    config['classificationLabelBaselineFixtures']=fixtures
    h.secret_path.write_text(json.dumps(config));h.secret_path.chmod(0o600)
    h.report['privateConfigSha256']=sha(h.secret_path.read_bytes())
    return fixtures

# Derive expected reserved-key and current-only mapping sets independently from
# immutable canonical history. Capture before034, before any sidecar exists.
EXPECTED_BASELINE = """SELECT coalesce(jsonb_agg(jsonb_build_object(
 'tenantId',h.tenant_id,'taxonomyId',h.id,'baselineVersion',h.current_version,'baselineHash',v.definition_hash,
 'labels',v.definition->'labels','historicKeys',(SELECT jsonb_agg(k ORDER BY k COLLATE "C") FROM
  (SELECT DISTINCT l->>'key' k FROM public.classification_taxonomy_versions old
   CROSS JOIN LATERAL jsonb_array_elements(old.definition->'labels') l
   WHERE old.tenant_id=h.tenant_id AND old.taxonomy_id=h.id) keys)) ORDER BY h.tenant_id,h.id),'[]')
 FROM public.classification_taxonomies h JOIN public.classification_taxonomy_versions v
 ON (v.tenant_id,v.taxonomy_id,v.version)=(h.tenant_id,h.id,h.current_version);"""

def baseline_rows(h):
    return {name:json.loads(h.sql("SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM "+name+" r;"))
            for name in sorted(TABLE_ADDITIONS)}

def verify_baselines(expected, observed):
    require(type(expected) is list and expected, 'Populated current baseline inventory required')
    baselines=observed['gc_authority.classification_label_baselines']
    identities=observed['gc_authority.classification_label_identities']
    bindings=observed['gc_authority.classification_label_version_bindings']
    key=lambda r:(r['tenantId'],r['taxonomyId'])
    require(len({key(r) for r in expected})==len(expected), 'Duplicate expected taxonomy')
    require(len(baselines)==len(expected), 'Baseline cardinality differs')
    all_ids=set();identity_total=binding_total=0
    for taxonomy in expected:
        tenant,tax=key(taxonomy);version=taxonomy['baselineVersion']
        select=lambda rows:[r for r in rows if (r['tenant_id'],r['taxonomy_id'])==(tenant,tax)]
        b=select(baselines);ids=select(identities);bound=select(bindings)
        require(len(b)==1 and b[0]['baseline_version']==version and b[0]['baseline_hash']==taxonomy['baselineHash'],
                'Baseline current pin/hash differs')
        current={r['key']:r['status'] for r in taxonomy['labels']}
        by_key={r['label_key']:r for r in ids}
        require(len(by_key)==len(ids) and set(by_key)==set(taxonomy['historicKeys']), 'Historic reserved key union differs')
        for label,row in by_key.items():
            require(re.fullmatch(r'[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}',row['id']) and row['id'] not in all_ids,
                    'Label UUID identity missing or aliased across taxonomy/tenant')
            all_ids.add(row['id'])
            require(row['first_registered_version']==version and row['retired_at_version']==
                    (None if current.get(label)=='active' else version), 'Migration-era lifecycle differs')
        actual={r['label_key']:(r['taxonomy_version'],r['label_id'],r['label_status']) for r in bound}
        require(len(actual)==len(bound) and actual=={label:(version,by_key[label]['id'],status) for label,status in current.items()},
                'Bindings must equal the current definition only; no invented historical continuity')
        identity_total+=len(ids);binding_total+=len(bound)
    require(identity_total==len(identities) and binding_total==len(bindings), 'Foreign or unaccounted sidecar rows')
    return {'taxonomies':len(expected),'identities':identity_total,'bindings':binding_total,'currentPinOnly':True,
            'allHistoricKeysReserved':True,'migrationEraRetirement':True,'independentIds':True}

def execute(h):
    read.setup(h)
    read.additional_roles(h,48)
    target=h.folder/'classification-label-target';target.mkdir()
    for name in NAMES[:32]:shutil.copyfile(ROOT/'packages/db/migrations'/name,target/name)
    h.phase='classification-label-install032'
    require(re.findall(r'^Applied (.+)$',h.migrate(target).stdout,re.M)==NAMES[30:32], 'Exact031/032 predecessor installation required')
    read.ledger(h,NAMES[:32]);read.config_offset(h,0)
    for phase,path,expected in PRECURSORS:volume.native_suite(h,phase,path,expected)
    h.phase='classification-label-before033'
    tables=volume.canonical_tables(h);before=read.snapshot(h,tables);prior=read.ledger(h,NAMES[:32])
    require(all(before['public.'+name]['rows']>0 for name in predecessor.COVERED), 'SQL032 fixture must populate every033 covered family')
    functions=json.loads(h.sql(read.FUNCTIONS));privileges=json.loads(h.sql(PRIVILEGES));triggers=json.loads(h.sql(TRIGGERS))
    shutil.copyfile(ROOT/'packages/db/migrations'/predecessor.MIGRATION,target/predecessor.MIGRATION)
    h.phase='classification-label-install033'
    require(re.findall(r'^Applied (.+)$',h.migrate(target).stdout,re.M)==[predecessor.MIGRATION], 'Exactly033 must apply')
    ledger033=read.ledger(h,NAMES[:33]);tables033=volume.canonical_tables(h)
    functions033=json.loads(h.sql(read.FUNCTIONS));privileges033=json.loads(h.sql(PRIVILEGES));triggers033=json.loads(h.sql(TRIGGERS))
    predecessor.preserve_installation(tables,functions,privileges,triggers,tables033,functions033,privileges033,triggers033)
    require(ledger033[:-1]==prior and read.snapshot(h,tables)==before, 'SQL033 changed canonical rows or prior ledger')
    initial=json.loads(h.sql("SELECT jsonb_build_object('tenants',(SELECT count(*) FROM public.tenants),'heads',(SELECT count(*) FROM gc_authority.content_security_heads),'nonInitial',(SELECT count(*) FROM gc_authority.content_security_heads WHERE revision<>1),'missing',(SELECT count(*) FROM public.tenants t LEFT JOIN gc_authority.content_security_heads h ON h.tenant_id=t.id WHERE h.tenant_id IS NULL));"))
    require(initial['tenants']>0 and initial['heads']==initial['tenants'] and initial['nonInitial']==initial['missing']==0,
            'SQL033 requires every tenant revision-one head')
    h.report['predecessorInstallation']={'preservation':True,'priorLedger':prior,'ledger':ledger033,'baseline':initial}
    h.phase='classification-label-seed-history';fixtures=seed_baselines(h)
    expected=json.loads(h.sql(EXPECTED_BASELINE))
    require(all(any(r['tenantId']==f['tenantId'] and r['taxonomyId']==f['taxonomyId'] and r['baselineVersion']==3
                    and len(r['historicKeys'])==4 and len(r['labels'])==3 for r in expected) for f in fixtures),
            'Real publisher baseline histories incomplete')
    h.phase='classification-label-before034'
    before=read.snapshot(h,tables033)
    require(json.loads(h.sql(read.FUNCTIONS))==functions033 and json.loads(h.sql(PRIVILEGES))==privileges033
            and json.loads(h.sql(TRIGGERS))==triggers033, 'Baseline fixture changed object boundaries')
    shutil.copyfile(ROOT/'packages/db/migrations'/MIGRATION,target/MIGRATION)
    h.phase='classification-label-upgrade'
    require(re.findall(r'^Applied (.+)$',h.migrate(target).stdout,re.M)==[MIGRATION], 'Exactly034 must apply')
    ledger=read.ledger(h,NAMES);current_tables=volume.canonical_tables(h)
    current_functions=json.loads(h.sql(read.FUNCTIONS));current_privileges=json.loads(h.sql(PRIVILEGES));current_triggers=json.loads(h.sql(TRIGGERS))
    preserve_installation(tables033,functions033,privileges033,triggers033,current_tables,current_functions,current_privileges,current_triggers)
    require(ledger[:-1]==ledger033 and read.snapshot(h,tables033)==before, 'SQL034 changed old canonical rows, content epochs or ledger')
    baseline=verify_baselines(expected,baseline_rows(h))
    h.report['installation']={'before':before,'priorLedger':ledger033,'ledger':ledger,'baseline':baseline,'preservation':True,
        'baselineFixtureCount':len(fixtures),'expectedBaselineSha256':sha(json.dumps(expected,sort_keys=True).encode()),
        'functionsBeforeSha256':sha(json.dumps(functions033,sort_keys=True).encode()),'functionsAfterSha256':sha(json.dumps(current_functions,sort_keys=True).encode()),
        'privilegesBeforeSha256':sha(json.dumps(privileges033,sort_keys=True).encode()),'privilegesAfterSha256':sha(json.dumps(current_privileges,sort_keys=True).encode()),
        'triggersBeforeSha256':sha(json.dumps(triggers033,sort_keys=True).encode()),'triggersAfterSha256':sha(json.dumps(current_triggers,sort_keys=True).encode()),
        'addedTables':sorted(TABLE_ADDITIONS),'addedFunctions':sorted(FUNCTION_ADDITIONS),'addedTriggers':sorted(trigger_additions())}
    def replay(phase):
        h.phase=phase;snapshot=read.snapshot(h,current_tables)
        require('Applied' not in h.migrate(target).stdout and read.ledger(h,NAMES)==ledger
            and volume.canonical_tables(h)==current_tables and read.snapshot(h,current_tables)==snapshot
            and json.loads(h.sql(read.FUNCTIONS))==current_functions and json.loads(h.sql(PRIVILEGES))==current_privileges
            and json.loads(h.sql(TRIGGERS))==current_triggers, 'SQL034 replay changed rows/UUIDs/ledger/functions/privileges/triggers')
        return snapshot
    replay('classification-label-replay-before');h.report['installation']['replayBefore']=True
    require(len(re.findall(r'^test\(', (ROOT/NEW_TEST).read_text(),re.M))==EXPECTED_TESTS, 'Declared identity native inventory differs')
    read.config_offset(h,16);volume.native_suite(h,PHASE,NEW_TEST,EXPECTED_TESTS)
    require(json.loads(h.sql(read.FUNCTIONS))==current_functions and json.loads(h.sql(PRIVILEGES))==current_privileges
            and json.loads(h.sql(TRIGGERS))==current_triggers, 'Native fixtures changed function/privilege/trigger definitions')
    populated=replay('classification-label-populated-replay')
    require(sources()==h.frozen and [r['phase'] for r in h.report['nativeSuites']]==list(PHASES), 'Qualification source or phase drifted')
    h.report.update(sources=h.frozen,migrations=ledger,sourceHashesMatched=True,
        nativeTotals={key:sum(r['tests'][key] for r in h.report['nativeSuites']) for key in ('tests','pass','fail','cancelled','skipped','todo')},
        populatedReplay={'snapshot':populated,'preservation':True},
        limitations=['Private stable classification label identities only; no fact producer, policy decision or runtime authority activation.',
          'Unchanged13 context and14 classification cases populate032;033 preserves that state before real three-version baseline histories and034.',
          'Migration-era current-pin-only bindings and all historical-key reservations are checked independently; no historic identity continuity inferred.',
          'Original780-second execution includes source admission;90-second cleanup and900-second wrapper are unchanged.',
          'Cached immutable dependencies and exact current read-only source mounts; no build, vendor or supported-release qualification.'])

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
