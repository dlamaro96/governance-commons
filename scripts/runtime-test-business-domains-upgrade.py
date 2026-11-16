#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Qualify SQL010 -> SQL011 against isolated real roles, history and concurrency.

Never builds/pulls/restarts application services. Only the exact labelled temporary
container created here is removed. Failed attempts retain their original reports.
"""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import time
import traceback
import uuid

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / '.local/evidence'
REPORT = LOCAL / 'business-domains-upgrade.json'
DIAGNOSTIC = LOCAL / 'business-domains-upgrade-private.log'
MIGRATIONS = ROOT / 'packages/db/migrations'
# This historical gate proves the exact SQL010→011 boundary. New foundations
# have their own gates and must not silently change this baseline or its count.
NAMES = ['001_foundation.sql', '002_audit_envelopes.sql', '003_governance_models.sql',
         '004_model_migrations.sql', '005_model_migration_integrity.sql', '006_inherited_asset_types.sql',
         '007_asset_type_migrations.sql', '008_constrained_relations.sql', '009_relation_participation.sql',
         '010_relation_scope_discovery.sql', '011_business_domains.sql']
EXPECTED_LAST = '011_business_domains.sql'
OWNER = 'gc_business_domains_upgrade_owner'
DATABASE = 'business_domains_upgrade'
TENANT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
ACTOR = '10000000-0000-4000-8000-000000000001'
TEST = ROOT / 'tests/integration/business-domains-storage.test.ts'
CONCURRENCY = ROOT / 'tests/qualification/business-domains-concurrency.test.ts'
RESERVED = ['domain-type.create', 'domain-type.publish', 'domain.create', 'domain.update', 'domain.state', 'domain.hierarchy', 'domain.placement', 'domain-type-migration.execute']
BASELINE_TABLES = ['assets', 'asset_revisions', 'governance_models', 'governance_model_versions', 'governance_model_migrations',
                  'governance_model_migration_assets', 'asset_type_versions', 'asset_type_dependencies', 'asset_type_migrations', 'asset_type_migration_assets',
                  'relation_types', 'relation_type_versions', 'relation_type_endpoints', 'relations', 'relation_revisions',
                  'relation_participations', 'relation_participation_revisions', 'relation_graph_receipts', 'relation_graph_receipt_edges',
                  'relation_graph_receipt_bindings', 'relation_graph_receipt_assets', 'relation_graph_receipt_types', 'relation_graph_receipt_type_migrations',
                  'audit', 'outbox', 'idempotency']


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def private_log(text):
    fd = os.open(DIAGNOSTIC, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(text + '\n')


def command(args, *, input=None, timeout=120, allow_failure=False):
    private_log('COMMAND ' + json.dumps(args))
    try:
        result = subprocess.run(args, input=input, text=True, capture_output=True, timeout=timeout, cwd=ROOT)
    except subprocess.TimeoutExpired as error:
        private_log('TIMEOUT ' + str(error.stdout) + '\n' + str(error.stderr))
        raise
    private_log(f'EXIT {result.returncode}\nSTDOUT\n{result.stdout}\nSTDERR\n{result.stderr}')
    if result.returncode and not allow_failure:
        raise RuntimeError('Qualification command failed; private diagnostic retained')
    return result


def literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def source_hashes():
    paths = {Path(__file__).resolve(), TEST, CONCURRENCY, ROOT / 'tests/fixtures/business-domains.ts',
             ROOT / 'tests/fixtures/relation-participation.ts', ROOT / 'scripts/runtime-test-relation-participation-upgrade.py',
             ROOT / 'package.json', ROOT / 'pnpm-lock.yaml', ROOT / 'Dockerfile', ROOT / 'deploy/compose/compose.yaml'}
    for folder in ('packages/db/src', 'packages/domain/src', 'packages/authz/src', 'apps/api/src'):
        paths.update((ROOT / folder).rglob('*.ts'))
    paths.update(MIGRATIONS / name for name in NAMES)
    return [{'path': str(p.relative_to(ROOT)), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(paths)]


def tap_summary(output, expected):
    result = {}
    for name in ('tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo'):
        values = re.findall(rf'^# {name} (\d+)$', output, re.MULTILINE)
        require(len(values) == 1, 'Missing/ambiguous final TAP summary')
        result[name] = int(values[0])
    require(expected > 0 and result['tests'] == result['pass'] == expected, 'Executed test count does not match frozen source')
    require(all(result[name] == 0 for name in ('fail', 'cancelled', 'skipped', 'todo')), 'A required test did not pass')
    durations = re.findall(r'^# duration_ms ([0-9.]+)$', output, re.MULTILINE)
    require(len(durations) == 1, 'Missing final test duration')
    result['duration_ms'] = float(durations[0])
    return result


def prior_fixture_module():
    # Reuse only original synthetic fixture constructors. Their prior harness,
    # execution record and migration bytes remain unchanged and are hashed here.
    source = ROOT / 'scripts/runtime-test-relation-participation-upgrade.py'
    spec = importlib.util.spec_from_file_location('gc_prior_domain_baseline', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def graph_fixture_js():
    return """
import {db} from './packages/db/src/index.ts';
import {fixture,prepare,execute,plan,values,emptyChange} from './tests/fixtures/relation-participation.ts';
try {
 const f=await fixture({publish:false});
 const definition={...f.definition,formatVersion:2,cardinality:{outgoing:{min:1,max:2},incoming:{min:0,max:null}}};
 const prepared=await prepare(f,definition);f.typeId=prepared.relationTypeId;f.definition=definition;
 const creations=f.assets.map((a,i)=>({key:'baseline_'+i,sourceAssetId:a.id,sourceAssetVersion:a.version,targetAssetId:f.assets[1-i].id,targetAssetVersion:f.assets[1-i].version,values:values()}));
 const receipt=await execute(f,{...emptyChange(),relationTargets:[{kind:'create',reservationId:prepared.id,expectedHeadVersion:null,definition,plan:plan(f.typeId,{creations})}]});
 if(receipt.edgeOutcomes.length!==2||receipt.bindingOutcomes.length!==2)throw Error('Required participation baseline incomplete');
 console.log(JSON.stringify({receiptId:receipt.id,typeId:f.typeId,assetIds:f.assets.map(a=>a.id)}));
} finally {await db.destroy();}
"""


def main():
    LOCAL.mkdir(parents=True, exist_ok=True)
    attempts = LOCAL / 'business-domains-upgrade-attempts'
    if REPORT.exists() or DIAGNOSTIC.exists():
        attempts.mkdir(mode=0o700, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex[:8]
        for prior in (REPORT, DIAGNOSTIC):
            if prior.exists():
                saved = attempts / (stamp + '-' + prior.name)
                shutil.copyfile(prior, saved)
                saved.chmod(0o600)
    history = [json.loads(p.read_text()) for p in attempts.glob('*-business-domains-upgrade.json')]
    prior_results = {r: sum(v.get('result') == r for v in history) for r in sorted({v.get('result', 'UNKNOWN') for v in history})}
    DIAGNOSTIC.unlink(missing_ok=True)
    started = datetime.now(timezone.utc).isoformat()
    sources = source_hashes()
    REPORT.write_text(json.dumps({'result': 'RUNNING', 'started_at': started, 'sources': sources}, indent=2) + '\n')
    require(len(NAMES) == 11 and NAMES[-1] == EXPECTED_LAST, 'Qualification requires exact SQL001–011')
    expected_tests = len(re.findall(r'^test\(', TEST.read_text(), re.MULTILINE))
    expected_concurrency = len(re.findall(r'^test\(', CONCURRENCY.read_text(), re.MULTILINE))
    require(expected_tests > 0 and expected_concurrency > 0, 'No declared qualification cases')
    endpoint = json.loads(command(['docker', 'context', 'inspect']).stdout)[0]['Endpoints']['docker']['Host']
    override = os.environ.get('DOCKER_HOST', '')
    require(endpoint.startswith(('unix://', 'npipe://')) and (not override or override.startswith(('unix://', 'npipe://'))), 'Only local disposable Docker qualification is allowed')
    docker_version = json.loads(command(['docker', 'version', '--format', '{{json .}}']).stdout)
    tag = re.search(r'^\s+image: (postgres:[^\s]+)$', (ROOT / 'deploy/compose/compose.yaml').read_text(), re.MULTILINE)
    require(tag is not None, 'Pinned PostgreSQL image missing')
    postgres_image = command(['docker', 'image', 'inspect', '--format', '{{.Id}}', tag.group(1)]).stdout.strip()
    app_image = command(['docker', 'image', 'inspect', '--format', '{{.Id}}', 'governance-commons:dev']).stdout.strip()
    require(shutil.disk_usage(ROOT).free >= 2 * 1024**3, 'Qualification stopped below 2GiB free space')
    name = 'gc-business-domains-upgrade-' + uuid.uuid4().hex[:12]
    created = False
    checks = []
    prior = prior_fixture_module()
    with tempfile.TemporaryDirectory(prefix='gc-business-domains-upgrade-', dir=ROOT / '.local') as folder:
        temporary = Path(folder)
        temporary.chmod(0o755)
        before, target, damaged = temporary / 'before', temporary / 'target', temporary / 'damaged'
        for destination, names in ((before, NAMES[:10]), (target, NAMES), (damaged, NAMES)):
            destination.mkdir()
            for filename in names:
                shutil.copyfile(MIGRATIONS / filename, destination / filename)
        (damaged / NAMES[0]).write_text((damaged / NAMES[0]).read_text() + '\n-- Synthetic changed predecessor checksum\n')

        def sql(body, role=OWNER, database=DATABASE):
            return command(['docker', 'exec', '-i', name, 'psql', '-X', '-qAt', '--set', 'ON_ERROR_STOP=1', '-U', role, '-d', database], input=body).stdout.strip()

        def migrate(path, database=DATABASE, allow_failure=False):
            return command(['docker', 'run', '--rm', '--pull', 'never', '--network', 'container:' + name,
                            '--label', 'org.governance-commons.qualification-run=' + name, '--memory', '512m', '--cpus', '1',
                            '--security-opt', 'no-new-privileges:true', '--cap-drop', 'ALL',
                            '--env', f'MIGRATION_DATABASE_URL=postgresql://{OWNER}@127.0.0.1:5432/{database}',
                            '--volume', f'{ROOT / "packages/db/src"}:/app/packages/db/src:ro', '--volume', f'{path}:/app/packages/db/migrations:ro',
                            app_image, 'node', '--import', 'tsx', 'packages/db/src/migrate.ts'], allow_failure=allow_failure)

        mounts = []
        for path in ('packages/db/src', 'packages/domain/src', 'packages/authz/src', 'apps/api/src', 'tests/fixtures'):
            mounts += ['--volume', f'{ROOT / path}:/app/{path}:ro']
        mounts += ['--volume', f'{TEST}:/app/tests/integration/business-domains-storage.test.ts:ro',
                   '--volume', f'{CONCURRENCY}:/app/tests/qualification/business-domains-concurrency.test.ts:ro']
        runtime = ['docker', 'run', '--rm', '--pull', 'never', '--network', 'container:' + name,
                   '--label', 'org.governance-commons.qualification-run=' + name, '--memory', '512m', '--cpus', '1',
                   '--security-opt', 'no-new-privileges:true', '--cap-drop', 'ALL',
                   '--env', f'DATABASE_URL=postgresql://gc_app@127.0.0.1:5432/{DATABASE}',
                   '--env', f'BUSINESS_DOMAINS_OWNER_DATABASE_URL=postgresql://{OWNER}@127.0.0.1:5432/{DATABASE}', *mounts, app_image]

        def baseline(original=None):
            result = {}
            for table in BASELINE_TABLES:
                predicate = ''
                if original is not None:
                    # Compare all actual original rows exactly. A changed/deleted
                    # original cannot disappear unnoticed among later fixtures.
                    predicate = ' AND to_jsonb(r) IN (SELECT value FROM jsonb_array_elements(' + literal(json.dumps(original[table])) + '::jsonb))'
                result[table] = json.loads(sql(f"BEGIN; SET LOCAL gc.tenant_id='{TENANT}'; SET LOCAL gc.actor_id='{ACTOR}'; SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM public.{table} r WHERE tenant_id='{TENANT}'{predicate}; COMMIT;", 'gc_app'))
            return result

        try:
            command(['docker', 'run', '--detach', '--pull', 'never', '--name', name, '--label', 'org.governance-commons.qualification=business-domains-upgrade',
                     '--network', 'none', '--memory', '512m', '--cpus', '1', '--tmpfs', '/var/lib/postgresql/data:rw,size=256m', '--env', 'POSTGRES_HOST_AUTH_METHOD=trust', postgres_image])
            created = True
            for _ in range(100):
                ready = subprocess.run(['docker', 'exec', name, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'], capture_output=True, timeout=5)
                if ready.returncode == 0:
                    break
                time.sleep(.2)
            require(ready.returncode == 0, 'Disposable PostgreSQL did not start')
            sql(f'CREATE ROLE gc_app LOGIN NOSUPERUSER NOBYPASSRLS; CREATE ROLE {OWNER} LOGIN NOSUPERUSER NOBYPASSRLS;', 'postgres', 'postgres')
            sql(f'CREATE DATABASE {DATABASE} OWNER {OWNER};', 'postgres', 'postgres')
            sql(f'REVOKE ALL ON DATABASE {DATABASE} FROM PUBLIC; GRANT CONNECT ON DATABASE {DATABASE} TO {OWNER},gc_app;', 'postgres', 'postgres')
            migrate(before)
            require(sql('SELECT count(*) FROM schema_migrations;') == '10', 'Prior baseline must be exact SQL010')
            sql(prior.fixture_sql())
            command([*runtime, 'node', '--import', 'tsx', '--input-type=module', '-e', prior.typed_fixture_js()])
            mixed_fixture = json.loads(command([*runtime, 'node', '--import', 'tsx', '--input-type=module', '-e', prior.relation_fixture_js()]).stdout)
            graph_fixture = json.loads(command([*runtime, 'node', '--import', 'tsx', '--input-type=module', '-e', graph_fixture_js()]).stdout)
            original = baseline()
            require(len(original['relation_participations']) >= 2 and len(original['relation_graph_receipts']) >= 1, 'Actual participation/receipt baseline missing')
            checks.append('Exact SQL001–010 migrator creates representative legacy model/type assets, mixed relation histories and a complete positive-participation graph receipt through actual runtime code')
            for index, operation in enumerate(RESERVED):
                clone = DATABASE + '_collision_' + str(index)
                sql(f'CREATE DATABASE {clone} OWNER {OWNER} TEMPLATE {DATABASE};', 'postgres', 'postgres')
                sql(f'REVOKE ALL ON DATABASE {clone} FROM PUBLIC; GRANT CONNECT ON DATABASE {clone} TO {OWNER},gc_app;', 'postgres', 'postgres')
                foreign = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
                row = sql(f"BEGIN; SET LOCAL gc.tenant_id='{foreign}'; SET LOCAL gc.actor_id='10000000-0000-4000-8000-000000000005'; INSERT INTO idempotency(tenant_id,actor_id,operation,key,request_hash,response) VALUES('{foreign}','10000000-0000-4000-8000-000000000005',{literal(operation)},'synthetic-pre011-success','{'0'*64}','{{\"legacy\":true}}'); SELECT to_jsonb(i) FROM idempotency i WHERE operation={literal(operation)};COMMIT;", 'gc_app', clone)
                failed = migrate(target, clone, True)
                require(failed.returncode != 0 and 'DOMAIN_RESERVED_NAMESPACE_COLLISION' in failed.stderr, 'All-tenant namespace collision must fail explicitly')
                unchanged = sql(f"BEGIN;SET LOCAL gc.tenant_id='{foreign}';SELECT to_jsonb(i) FROM idempotency i WHERE operation={literal(operation)};COMMIT;", 'gc_app', clone)
                require(unchanged == row and sql("SELECT count(*) FROM schema_migrations;", database=clone) == '10'
                        and sql("SELECT to_regclass('public.domains') IS NULL;", database=clone) == 't', 'Failed collision upgrade did not fully roll back')
                sql(f'DROP DATABASE {clone};', 'postgres', 'postgres')
            checks.append('All eight newly reserved namespaces reject foreign-tenant prior success rows through forced RLS and preserve each exact row with complete upgrade rollback')
            rejected = migrate(damaged, allow_failure=True)
            require(rejected.returncode != 0 and 'checksum' in rejected.stderr.lower(), 'Changed applied predecessor checksum was accepted')
            require(sql('SELECT count(*) FROM schema_migrations;') == '10' and sql("SELECT to_regclass('public.domains') IS NULL;") == 't' and baseline() == original, 'Malformed predecessor changed baseline')
            checks.append('Malformed applied predecessor checksum aborts before SQL011 and preserves actual complete SQL010 state')
            applied = migrate(target)
            require(re.findall(r'^Applied (.+)$', applied.stdout, re.MULTILINE) == [EXPECTED_LAST], 'Forward upgrade must apply only SQL011')
            require(baseline() == original, 'SQL011 altered historical canonical, revision, normalized receipt or journal bytes')
            require(sql(f"BEGIN;SET LOCAL gc.tenant_id='{TENANT}';SELECT (SELECT count(*) FROM asset_domain_placements)+(SELECT count(*) FROM asset_domain_placement_revisions);COMMIT;", 'gc_app') == '0', 'Upgrade invented placement history')
            checks.append('SQL011 preserves exact legacy canonical/history/receipt/journal data and creates no fabricated placement rows or revisions')
            require('Applied' not in migrate(target).stdout, 'Checksum replay reapplied work')
            checksums = json.loads(sql("SELECT json_agg(json_build_object('name',name,'sha256',checksum) ORDER BY name) FROM schema_migrations;"))
            require(checksums == [{'name': n, 'sha256': hashlib.sha256((MIGRATIONS / n).read_bytes()).hexdigest()} for n in NAMES], 'Applied checksums differ from frozen SQL001–011')
            checks.append('Exact SQL001–011 checksum replay is idempotent with all ten applied predecessor bytes unchanged')
            domain_permissions = json.dumps(['catalog:read','catalog:write','models:read','models:write','domains:read','domains:write','domains:assign','audit:read'])
            sql(f"BEGIN;SET LOCAL gc.tenant_id='{TENANT}';SET LOCAL gc.actor_id='{ACTOR}';UPDATE memberships SET permissions={literal(domain_permissions)};COMMIT;")
            roles = json.loads(sql(f"""SELECT json_build_object('ownerSuperuser',(SELECT rolsuper FROM pg_roles WHERE rolname='{OWNER}'),
'ownerBypassRls',(SELECT rolbypassrls FROM pg_roles WHERE rolname='{OWNER}'),'runtimeSuperuser',(SELECT rolsuper FROM pg_roles WHERE rolname='gc_app'),
'runtimeBypassRls',(SELECT rolbypassrls FROM pg_roles WHERE rolname='gc_app'),'runtimeOwnsTables',EXISTS(SELECT 1 FROM pg_class WHERE relkind='r' AND relowner=(SELECT oid FROM pg_roles WHERE rolname='gc_app')),
'runtimeTemporary',has_database_privilege('gc_app',current_database(),'TEMP'),'runtimeCreateSchema',has_schema_privilege('gc_app','public','CREATE'),
'forcedRlsCount',(SELECT count(*) FROM pg_class WHERE relkind='r' AND (relname LIKE 'domain_%' OR relname LIKE 'asset_domain_%') AND relrowsecurity AND relforcerowsecurity));"""))
            require(roles == {'ownerSuperuser': False,'ownerBypassRls': False,'runtimeSuperuser': False,'runtimeBypassRls': False,'runtimeOwnsTables': False,'runtimeTemporary': False,'runtimeCreateSchema': False,'forcedRlsCount': 19}, 'Roles or forced RLS do not meet storage boundary')
            checks.append('All nineteen domain tables force tenant RLS; runtime owns no tables, cannot bypass RLS, and has no schema CREATE or TEMP capability')
            runtime_info = json.loads(command([*runtime, 'node', '--input-type=module', '-e', "import fs from 'node:fs';import crypto from 'node:crypto';const sha=p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');console.log(JSON.stringify({node:process.version,platform:process.platform,arch:process.arch,pg:JSON.parse(fs.readFileSync('node_modules/pg/package.json')).version,tsx:JSON.parse(fs.readFileSync('node_modules/tsx/package.json')).version,kysely:JSON.parse(fs.readFileSync('node_modules/kysely/package.json')).version,packageSha256:sha('package.json'),lockSha256:sha('pnpm-lock.yaml')}));"]).stdout)
            require(runtime_info['packageSha256'] == hashlib.sha256((ROOT / 'package.json').read_bytes()).hexdigest() and runtime_info['lockSha256'] == hashlib.sha256((ROOT / 'pnpm-lock.yaml').read_bytes()).hexdigest(), 'Cached runtime dependency manifests differ')
            tested = command([*runtime, 'node', '--import', 'tsx', '--test', '--test-reporter=tap', 'tests/integration/business-domains-storage.test.ts'], timeout=600)
            tests = tap_summary(tested.stdout, expected_tests)
            checks.append(f'All {tests["tests"]} real runtime-role storage cases pass without skips, cancellations or retries')
            concurrent = command([*runtime, 'node', '--import', 'tsx', '--test', '--test-reporter=tap', 'tests/qualification/business-domains-concurrency.test.ts'], timeout=900)
            concurrency = tap_summary(concurrent.stdout, expected_concurrency)
            checks.append(f'All {concurrency["tests"]} independent PostgreSQL-session concurrency/original-deadline cases pass without skips, cancellations or retries')
            require(baseline(original) == original, 'Qualification changed/deleted original legacy rows')
            require(source_hashes() == sources, 'Source changed during qualification; no stable pass can be recorded')
            container = json.loads(command(['docker', 'inspect', name]).stdout)[0]
            require(container['HostConfig']['NetworkMode'] == 'none' and not container['HostConfig']['PortBindings'], 'Disposable isolation changed')
            require(not any(m.get('Type') in ('volume','bind') for m in container['Mounts']), 'Database unexpectedly uses persistent storage')
            report = {'schema_version':1,'result':'PASS','started_at':started,'recorded_at':datetime.now(timezone.utc).isoformat(),
                      'command':'./dev test --suite business-domains-upgrade','scope':'Exact SQL010-to011 upgrade plus real direct storage/concurrency qualification',
                      'checks':checks,'storage_tests':tests,'concurrency_tests':concurrency,'expected_top_level_tests':expected_tests,'expected_concurrency_tests':expected_concurrency,
                      'runtime':{**runtime_info,'postgresql':sql('SHOW server_version;'),'python':platform.python_version(),'dockerClient':docker_version['Client']['Version'],'dockerEngine':docker_version['Server']['Version']},
                      'roles':roles,'postgres_image_reference':tag.group(1),'postgres_image':postgres_image,'app_image':app_image,'sources':sources,'applied_migrations':checksums,
                      'baseline':{'before_hash':canonical_hash(original),'after_hash':canonical_hash(baseline(original)),'mixed_fixture':mixed_fixture,'graph_fixture':graph_fixture},
                      'isolation':{'network':'none; helpers share only disposable namespace','published_ports':[],'database_storage':'disposable 256MiB tmpfs','production_volumes_used':False},
                      'diagnostic_history':{'archived_prior_attempts':len(history),'result_counts':prior_results,'private_reports_and_database_logs_retained':True,'qualification_test_retries':0},
                      'limitations':['Synthetic development predecessor and local native runtime roles; not production restore, hosted CI or a release qualification.',
                                     'Storage/concurrency use direct SQL and independent pure projections. HTTP authorization, authenticated replay, scanner orchestration and browser journeys require their separate real service gates.',
                                     'Direct SQL with outer statement_timeout zero proves cooperative original-clock rejection, not a universal hard interrupt at exactly 30 seconds.',
                                     'Existing cached application dependencies are recorded; current implementation and tests are mounted read-only.']}
        except Exception:
            if created:
                try:
                    command(['docker','logs',name],timeout=30)
                except Exception:
                    private_log('Database log collection failed before cleanup')
            raise
        finally:
            if created:
                helpers = command(['docker','ps','--all','--quiet','--filter','label=org.governance-commons.qualification-run='+name]).stdout.split()
                if helpers:
                    command(['docker','rm','--force',*helpers],timeout=30)
                command(['docker','rm','--force',name],timeout=30)
    report['disposable_container_removed'] = True
    REPORT.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({'result':'PASS','checks':len(checks),'storage_tests':tests,'concurrency_tests':concurrency,'disposable_container_removed':True}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        LOCAL.mkdir(parents=True,exist_ok=True)
        private_log(traceback.format_exc())
        partial=json.loads(REPORT.read_text()) if REPORT.exists() else {}
        partial.update({'result':'FAIL','recorded_at':datetime.now(timezone.utc).isoformat(),'error_type':type(error).__name__})
        REPORT.write_text(json.dumps(partial,indent=2)+'\n')
        raise SystemExit(f'Business-domain qualification failed: {type(error).__name__}; private diagnostics retained, no pass recorded')
