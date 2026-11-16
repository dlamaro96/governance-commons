#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Native SQL013→014 source storage gate in a disposable cached PostgreSQL.

No shared database, external vendor credential, build, pull or API mock is used.
The existing bounded harness owns admission, private diagnostics and cleanup.
"""
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / '.local/evidence/source-connectors-upgrade.json'
spec = importlib.util.spec_from_file_location('source_upgrade_base', ROOT / 'scripts/runtime-test-authority-authn-foundation.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
require, sha, literal = base.require, base.sha, base.literal
NAMES = [*base.NAMES, '013_authority_foundation.sql', '014_source_connectors.sql']


def sources():
    names = ['scripts/runtime-test-source-connectors-upgrade.py', 'scripts/runtime-test-authority-authn-foundation.py',
             'scripts/authentication_roles.py', 'scripts/test_authentication_roles.py',
             'package.json', 'pnpm-lock.yaml', 'deploy/compose/compose.yaml']
    paths = {ROOT / name for name in names}
    paths.update(base.MIGRATIONS / name for name in NAMES)
    paths.update((ROOT / 'packages/db/src').glob('*.ts'))
    return [{'path': str(p.relative_to(ROOT)), 'sha256': sha(p.read_bytes())} for p in sorted(paths)]


class Harness(base.Harness):
    def __init__(self):
        os.umask(0o077)
        REPORT.parent.mkdir(parents=True, exist_ok=True)
        self.id = 'gc-source-upgrade-' + uuid.uuid4().hex[:12]
        self.folder = REPORT.parent / ('source-connectors-upgrade-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + self.id[-12:])
        self.folder.mkdir(mode=0o700)
        self.phase, self.serial, self.owned, self.created = 'admission', 0, [], False
        self.deadline, self.cleanup_deadline = time.monotonic() + 600, None
        self.output_bytes, self.resources_before, self.private_values = 0, None, []
        self.secret_path = self.folder / 'private-config.json'
        self.report = {'schema_version': 1, 'result': 'RUNNING', 'started_at': datetime.now(timezone.utc).isoformat(),
                       'command': './dev test --suite source-connectors-upgrade', 'profile': 'isolated-source-storage', 'checks': []}
        if REPORT.exists():
            (self.folder / 'previous-report.json').write_bytes(REPORT.read_bytes())
        self.save()

    def save(self, *, final=False):
        if not final:
            self.admission()
        data = (json.dumps(self.report, indent=2) + '\n').encode()
        (self.folder / 'report.json').write_bytes(data)
        REPORT.write_bytes(data)
        REPORT.chmod(0o600)

    def helper(self, args, *, mounts=(), **kwargs):
        if 'cachedPackageAdmission' not in self.report:
            observed = super().helper(['node', '-e', "const fs=require('node:fs'),c=require('node:crypto');console.log(JSON.stringify({package:JSON.parse(fs.readFileSync('package.json')),lock:c.createHash('sha256').update(fs.readFileSync('pnpm-lock.yaml')).digest('hex')}))"])
            baked, host = json.loads(observed.stdout), json.loads((ROOT / 'package.json').read_text())
            require(baked['lock'] == sha((ROOT / 'pnpm-lock.yaml').read_bytes()), 'Cached dependency lock differs')
            require({k: v for k, v in baked['package'].items() if k != 'scripts'} == {k: v for k, v in host.items() if k != 'scripts'}, 'Cached dependency metadata differs')
            self.report['cachedPackageAdmission'] = {'lockSha256': baked['lock'], 'allowedDifference': 'package scripts only'}
        return super().helper(args, mounts=[(ROOT / 'package.json', '/app/package.json'), *mounts], **kwargs)


def deployment_state(h):
    """Stable actual catalog/ACL state, excluding statistics and all credentials."""
    return json.loads(h.sql("""SELECT jsonb_build_object(
      'relations',(SELECT coalesce(jsonb_agg(jsonb_build_array(c.oid,n.nspname,c.relname,c.relkind,c.relowner,c.reltype,c.relnatts,c.relacl) ORDER BY c.oid),'[]') FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relowner='gc_authn_definer'::regrole OR (n.nspname='gc_authn' AND c.relname='foundation_session')),
      'types',(SELECT coalesce(jsonb_agg(jsonb_build_array(t.oid,n.nspname,t.typname,t.typowner,t.typtype,t.typrelid,t.typelem,t.typarray,t.typacl) ORDER BY t.oid),'[]') FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE t.typowner='gc_authn_definer'::regrole OR (n.nspname='gc_authn' AND t.typname IN ('foundation_session','_foundation_session'))),
      'attributes',(SELECT coalesce(jsonb_agg(jsonb_build_array(a.attrelid,a.attnum,a.attname,a.atttypid,a.atttypmod,a.attndims,a.attnotnull,a.attisdropped) ORDER BY a.attrelid,a.attnum),'[]') FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid WHERE c.relowner='gc_authn_definer'::regrole AND a.attnum>0),
      'functions',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY p.oid),'[]') FROM pg_proc p WHERE p.proowner='gc_authn_definer'::regrole),
      'schemas',(SELECT coalesce(jsonb_agg(jsonb_build_array(nspname,nspowner,nspacl) ORDER BY nspname),'[]') FROM pg_namespace WHERE nspname IN ('public','gc_authn','gc_authority')),
      'memberships',(SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY roleid,member,grantor),'[]') FROM pg_auth_members m WHERE roleid='gc_authn_definer'::regrole OR member='gc_authn_definer'::regrole),
      'roles',(SELECT coalesce(jsonb_agg(jsonb_build_array(oid,rolname,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolinherit,rolbypassrls,rolreplication) ORDER BY oid),'[]') FROM pg_roles WHERE rolname IN ('gc_owner','gc_authn_definer')),
      'ledger',(SELECT jsonb_agg(to_jsonb(m) ORDER BY name) FROM public.schema_migrations m));"""))


def repeat_prepare(h, roles):
    before = deployment_state(h)
    try:
        h.sql(roles.prepare_sql(base.OWNER, base.DATABASE))
        require(h.sql("SELECT count(*)=1 AND bool_and(set_option AND NOT inherit_option AND NOT admin_option) FROM pg_auth_members WHERE roleid='gc_authn_definer'::regrole AND member='gc_owner'::regrole;") == 't', 'Repeated preparation did not stage exactly the SET-only ownership edge')
        require(h.sql("SELECT has_schema_privilege('gc_authn_definer','public','CREATE');") == 't', 'Repeated preparation did not stage the public transfer grant')
    finally:
        h.sql(roles.finish_sql(base.OWNER))
    require(deployment_state(h) == before, 'Preparation/finally cleanup changed protected catalog, ACL or ledger state')


def refused_prepare(h, roles, mutation):
    before = deployment_state(h)
    query = roles.prepare_sql(base.OWNER, base.DATABASE)
    require(query.startswith('BEGIN;\n') and query.endswith('COMMIT;\n'), 'Unexpected role preparation envelope')
    # Keep both the hostile fixture and generated preparation inside one outer
    # rollback transaction. Even an erroneously accepted probe cannot persist.
    body = query[len('BEGIN;\n'):-len('COMMIT;\n')]
    try:
        result = h.sql_result('BEGIN;\n' + mutation + '\n' + body + '\nROLLBACK;\n', allow_failure=True)
        require(result.returncode != 0 and 'AUTHN_DEFINER_OWNERSHIP_REJECTED' in result.stderr,
                'Hostile owned-object/ledger probe did not reach the expected preparation refusal')
    finally:
        h.sql(roles.finish_sql(base.OWNER))
    require(deployment_state(h) == before, 'Refused preparation or rollback changed protected catalog, ACL or ledger state')


def execute(h):
    frozen = sources()
    h.report['sources'] = frozen
    h.report['commit'] = h.command(['git', 'rev-parse', 'HEAD'], sensitive=True).stdout.strip()
    context = json.loads(h.docker('context', 'inspect', sensitive=True).stdout)[0]['Endpoints']['docker']['Host']
    require(context.startswith(('unix://', 'npipe://')) and (not os.environ.get('DOCKER_HOST') or os.environ['DOCKER_HOST'].startswith(('unix://', 'npipe://'))), 'Local Docker only')
    h.resources_before = h.inventory()
    h.report['memory_admission'] = h.memory_admission()
    image = re.search(r'^\s+image: (postgres:[^\s]+)$', (ROOT / 'deploy/compose/compose.yaml').read_text(), re.MULTILINE)
    require(image is not None, 'Pinned PostgreSQL image required')
    pg_image = h.docker('image', 'inspect', '--format', '{{.Id}}', image[1]).stdout.strip()
    h.app_image = h.docker('image', 'inspect', '--format', '{{.Id}}', 'governance-commons:dev').stdout.strip()
    h.report['images'] = {'postgres': pg_image, 'application': h.app_image}
    passwords = {role: secrets.token_hex(24) for role in ('postgres', base.OWNER, 'gc_app')}
    h.private_values = list(passwords.values())
    url = lambda role: f'postgresql://{role}:{passwords[role]}@127.0.0.1:5432/{base.DATABASE}'
    h.secret_path.write_text(json.dumps({'owner': url(base.OWNER), 'legacy': url('gc_app')}))
    h.phase = 'database-start'
    h.docker('run', '--detach', '--pull', 'never', '--name', h.id, '--label', 'org.governance-commons.authn-run=' + h.id,
             '--network', 'none', '--memory', '512m', '--memory-swap', '512m', '--cpus', '1', '--pids-limit', '128',
             '--read-only', '--log-driver', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--user', 'postgres',
             '--tmpfs', '/var/lib/postgresql/data:rw,nosuid,nodev,size=256m,mode=1777', '--tmpfs', '/tmp:rw,nosuid,nodev,size=16m,mode=1777',
             '--tmpfs', '/var/run/postgresql:rw,nosuid,nodev,size=4m,mode=1777', '--env', 'PGDATA=/var/lib/postgresql/data/pgdata',
             '--entrypoint', 'sh', pg_image, '-ec',
             'initdb --auth-local=trust --auth-host=scram-sha-256 -D /var/lib/postgresql/data/pgdata >/tmp/init.log 2>&1; exec postgres -D /var/lib/postgresql/data/pgdata -c listen_addresses=127.0.0.1 -c shared_buffers=32MB -c work_mem=2MB -c maintenance_work_mem=16MB -c max_connections=16 -c min_wal_size=32MB -c max_wal_size=64MB -c log_statement=none -c log_min_error_statement=panic -c log_error_verbosity=terse')
    h.created = True
    end = time.monotonic() + 30
    while h.docker('exec', h.id, 'pg_isready', '-U', 'postgres', allow_failure=True).returncode:
        require(time.monotonic() < end, 'Disposable PostgreSQL readiness deadline exceeded')
        time.sleep(.1)
    setup = f'ALTER ROLE postgres PASSWORD {literal(passwords["postgres"])};'
    for role in (base.OWNER, 'gc_app'):
        setup += f'CREATE ROLE {role} LOGIN PASSWORD {literal(passwords[role])} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;'
    h.sql(setup + f'CREATE DATABASE {base.DATABASE} OWNER {base.OWNER};', database='postgres')
    h.sql(f'REVOKE ALL ON DATABASE {base.DATABASE} FROM PUBLIC;GRANT CONNECT ON DATABASE {base.DATABASE} TO {base.OWNER},gc_app;REVOKE CREATE ON SCHEMA public FROM PUBLIC;ALTER SCHEMA public OWNER TO {base.OWNER};')
    folders = {}
    for name, count in [('legacy', 11), ('authn', 12), ('before', 13), ('target', 14), ('damaged', 14)]:
        folder = h.folder / name
        folder.mkdir()
        for migration in NAMES[:count]:
            shutil.copyfile(base.MIGRATIONS / migration, folder / migration)
        folders[name] = folder
    (folders['damaged'] / NAMES[0]).write_bytes((folders['damaged'] / NAMES[0]).read_bytes() + b'\n-- synthetic mismatch\n')
    h.phase = 'predecessor'
    h.migrate(folders['legacy'])
    roles = base.module(ROOT / 'scripts/authentication_roles.py', 'source_upgrade_roles')
    try:
        h.sql(roles.prepare_sql(base.OWNER, base.DATABASE))
        h.migrate(folders['authn'])
    finally:
        h.sql(roles.finish_sql(base.OWNER))
    h.phase = 'pre013-preparation'
    repeat_prepare(h, roles)
    declaration = re.search(r'CREATE TYPE gc_authn\.foundation_session AS\([^;]+\);', (base.MIGRATIONS / NAMES[12]).read_text())
    require(declaration is not None, 'Exact SQL013 bridge declaration missing')
    refused_prepare(h, roles, declaration[0] + 'ALTER TYPE gc_authn.foundation_session OWNER TO gc_authn_definer;')
    h.report['checks'].append('Native SQL012 preparation/cleanup accepts absent SQL013 bridge and rejects an exact-name pre-installation composite spoof with complete catalog/ledger rollback')
    try:
        h.sql(roles.prepare_sql(base.OWNER, base.DATABASE))
        h.migrate(folders['before'])
    finally:
        h.sql(roles.finish_sql(base.OWNER))
    tenant, foreign, source, asset, job = [str(uuid.uuid4()) for _ in range(5)]
    h.sql(f"INSERT INTO public.tenants VALUES('{tenant}','Synthetic Harbor'),('{foreign}','Synthetic Orchard');")
    scoped = f"BEGIN;SET LOCAL gc.tenant_id='{tenant}';SET LOCAL gc.actor_id='synthetic-source-upgrade';"
    h.sql(scoped + f"INSERT INTO sources(tenant_id,id,name,host,port,database_name,schema_name,secret_ref) VALUES('{tenant}','{source}','Synthetic source','source-postgres',5432,'harbor','public','demo-postgres');INSERT INTO assets(tenant_id,id,source_id,external_id,name,qualified_name,type,description,observed_at) VALUES('{tenant}','{asset}','{source}','stable-table','Orders','harbor.public.orders','table','Curated description',now());INSERT INTO asset_revisions(tenant_id,asset_id,version,snapshot) VALUES('{tenant}','{asset}',1,'{{\"synthetic\":true}}');INSERT INTO jobs(tenant_id,id,source_id,actor_id) VALUES('{tenant}','{job}','{source}','synthetic-actor');COMMIT;", role='gc_app')
    tables = ['public.sources', 'public.assets', 'public.asset_revisions', 'public.jobs', 'public.schema_migrations']
    before = h.snapshot(tables)
    require(len(before['public.schema_migrations']) == 13, 'Expected exact SQL013 predecessor')
    h.phase = 'checksum-refusal'
    refused = h.migrate(folders['damaged'], allow_failure=True)
    require(refused.returncode != 0 and 'Applied migration changed' in refused.stderr and h.snapshot(tables) == before, 'Checksum refusal mutated prior state')
    h.phase = 'upgrade'
    result = h.migrate(folders['target'])
    require(re.findall(r'^Applied (.+)$', result.stdout, re.MULTILINE) == [NAMES[-1]], 'Expected exactly SQL014 application')
    after = h.snapshot(tables)
    require([{k: v for k, v in row.items() if k != 'connector_id'} for row in after['public.sources']] == before['public.sources'], 'Existing source changed')
    require(all(row['connector_id'] == 'postgresql' for row in after['public.sources']), 'Legacy connector default differs')
    require(all(after[name] == before[name] for name in tables[1:4]), 'Asset, history or job changed')
    require(all(row in after['public.schema_migrations'] for row in before['public.schema_migrations']) and len(after['public.schema_migrations']) == 14, 'Predecessor ledger changed')
    require('Applied' not in h.migrate(folders['target']).stdout and h.snapshot(tables) == after, 'Replay changed state')
    h.report['checks'].append('Exact SQL013→014 upgrade, checksum refusal, replay, legacy default and unchanged source/assets/history/jobs/ledger')
    h.phase = 'repeat-preparation'
    repeat_prepare(h, roles)
    repeat_prepare(h, roles)
    for mutation in (
        'CREATE TABLE gc_authn.restart_hostile(value integer);ALTER TABLE gc_authn.restart_hostile OWNER TO gc_authn_definer;',
        'CREATE TYPE gc_authn.restart_hostile AS(value integer);ALTER TYPE gc_authn.restart_hostile OWNER TO gc_authn_definer;',
        "CREATE TYPE gc_authn.restart_hostile AS ENUM('synthetic');ALTER TYPE gc_authn.restart_hostile OWNER TO gc_authn_definer;",
        'ALTER TYPE gc_authn.foundation_session RENAME TO restart_changed;',
        'ALTER TYPE gc_authn.foundation_session RENAME ATTRIBUTE tenant_id TO changed_tenant;',
        'ALTER TYPE gc_authn.foundation_session ALTER ATTRIBUTE generation TYPE text;',
        'ALTER TYPE gc_authn.foundation_session DROP ATTRIBUTE expires_at;',
        'ALTER TYPE gc_authn.foundation_session OWNER TO gc_owner;',
        'ALTER FUNCTION gc_authn.foundation_session_v1(text) OWNER TO gc_owner;',
        'ALTER TYPE gc_authn.foundation_session SET SCHEMA public;',
        "UPDATE public.schema_migrations SET checksum=repeat('0',64) WHERE name='013_authority_foundation.sql';",
        "DELETE FROM public.schema_migrations WHERE name='013_authority_foundation.sql';",
    ):
        refused_prepare(h, roles, mutation)
    require(h.snapshot(tables) == after, 'Restart preparation probes altered legacy/canonical rows')
    h.report['checks'].append('Native SQL014 prepare/finish repeats twice; twelve hostile relation/type/shape/ownership/ledger probes refuse with exact rollback and no permission restoration')
    insert = lambda host='adb-123.1.azuredatabricks.net', port=443, catalog='harbor', schema='commerce', ref='harbor-reader', kind='unity-catalog', tid=tenant: f"INSERT INTO sources(tenant_id,id,name,host,port,database_name,schema_name,secret_ref,connector_id) VALUES('{tid}','{uuid.uuid4()}','Synthetic UC',{literal(host)},{port},{literal(catalog)},{literal(schema)},{literal(ref)},{literal(kind)});"
    h.sql(scoped + insert() + 'COMMIT;', role='gc_app')
    require(h.sql(scoped + 'SELECT count(*) FROM sources;COMMIT;', role='gc_app') == '2', 'Own-tenant source read did not return both connectors')
    cases = [dict(kind='unknown'), dict(host='metadata.example.invalid'), dict(port=80), dict(catalog='wrong.scope'), dict(schema='../other'), dict(ref='../private'), dict(tid=foreign)]
    for case in cases:
        result = h.sql_result('\\set VERBOSITY verbose\n' + scoped + insert(**case) + 'COMMIT;', role='gc_app', allow_failure=True)
        code = '42501' if 'tid' in case else '23514'
        require(result.returncode != 0 and re.search(r'ERROR:\s+' + code + ':', result.stderr), 'Expected source constraint/RLS refusal not observed')
    require(h.sql(scoped + 'SELECT count(*) FROM sources;COMMIT;', role='gc_app') == '2', 'Rejected writes left partial source rows')
    require(h.sql(f"BEGIN;SET LOCAL gc.tenant_id='{foreign}';SELECT count(*) FROM sources;COMMIT;", role='gc_app') == '0', 'Foreign source rows visible')
    require(h.sql("SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='public.sources'::regclass;") == 't', 'Forced source RLS missing')
    require(h.sql("SELECT NOT rolsuper AND NOT rolbypassrls AND NOT EXISTS(SELECT 1 FROM pg_class WHERE oid='public.sources'::regclass AND relowner='gc_app'::regrole) FROM pg_roles WHERE rolname='gc_app';") == 't', 'Runtime role owns or bypasses source storage')
    h.report['checks'].append('Native gc_app accepts UC, refuses seven invalid/foreign writes, sees no foreign sources, and retains forced RLS/non-owner/non-bypass role')
    require(sources() == frozen, 'Bound source changed during execution')
    h.report['migrations'] = [{'name': name, 'sha256': sha((base.MIGRATIONS / name).read_bytes())} for name in NAMES]
    h.report['limitations'] = ['Storage upgrade qualification only; external Databricks, HTTP pipeline and browser acceptance remain separate gates.', 'The inactive SQL013 authority foundation is a prerequisite, not activated by this gate.']


def main():
    h, failed = Harness(), False
    try:
        execute(h)
    except BaseException as error:
        failed = True
        h.report.update(failed_phase=h.phase, error_type=type(error).__name__, error='Inspect bounded private diagnostics')
    finally:
        try:
            h.phase = 'cleanup'
            h.cleanup()
            if h.resources_before is not None:
                h.deadline = h.cleanup_deadline
                require(h.inventory() == h.resources_before, 'Preexisting resource inventory changed')
                h.report['cleanup']['resourceInventoryPreserved'] = True
        except BaseException as error:
            failed = True
            h.report['cleanupErrorType'] = type(error).__name__
        h.report.update(result='FAIL' if failed else 'PASS', recorded_at=datetime.now(timezone.utc).isoformat(), evidence_directory=str(h.folder.relative_to(ROOT)))
        h.report['private_logs'] = [{'path': str(p.relative_to(ROOT)), 'sha256': sha(p.read_bytes())} for p in sorted(h.folder.glob('*.log'))]
        h.save(final=True)
    print(json.dumps({'result': h.report['result'], 'report': str(REPORT.relative_to(ROOT))}))
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
