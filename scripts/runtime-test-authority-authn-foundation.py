#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real SQL011→012 qualification, isolated cached-image/tmpfs profile only.

Never builds, pulls, touches a shared service, or deletes preexisting resources.
Secrets travel through private stdin/config mounts, never command lines or logs.
"""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import subprocess
import sys
import threading
import time
import uuid

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / '.local/evidence'
REPORT = LOCAL / 'authority-authn-foundation.json'
MIGRATIONS = ROOT / 'packages/db/migrations'
NAMES = ['001_foundation.sql', '002_audit_envelopes.sql', '003_governance_models.sql',
         '004_model_migrations.sql', '005_model_migration_integrity.sql', '006_inherited_asset_types.sql',
         '007_asset_type_migrations.sql', '008_constrained_relations.sql', '009_relation_participation.sql',
         '010_relation_scope_discovery.sql', '011_business_domains.sql', '012_authentication_foundation.sql']
TEST = ROOT / 'tests/qualification/authority-authn-foundation-storage.test.ts'
CONCURRENCY = ROOT / 'tests/qualification/authority-authn-foundation-concurrency.test.ts'
TENANT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
ACTOR = '10000000-0000-4000-8000-000000000001'
OWNER, DATABASE = 'gc_owner', 'gc_authn_qualification'
MIB, GIB = 1024**2, 1024**3
HOST_FLOOR, OUTPUT_CAP, DIAGNOSTIC_CAP = GIB, 100*MIB, 4*MIB


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


def source_hashes():
    paths = {Path(__file__).resolve(), TEST, CONCURRENCY,
             ROOT / 'tests/fixtures/authority-authn-foundation.ts', ROOT / 'scripts/authentication_roles.py', ROOT / 'scripts/authentication-install.ts',
             ROOT / 'scripts/runtime-test-business-domains-upgrade.py', ROOT / 'scripts/runtime-test-relation-participation-upgrade.py',
             ROOT / 'docs/execution/AUTHENTICATION_FOUNDATION_CONTRACT.md', ROOT / 'docs/execution/AUTHENTICATION_FOUNDATION_CANDIDATE.md',
             ROOT / 'docs/execution/AUTHENTICATION_FOUNDATION_QUALIFICATION.md', ROOT / 'docs/execution/authentication-legacy-function-census.json',
             ROOT / 'package.json', ROOT / 'pnpm-lock.yaml', ROOT / 'Dockerfile', ROOT / 'deploy/compose/compose.yaml'}
    paths.update(ROOT / name for name in ('dev', 'scripts/runtime.py', 'scripts/runtime-bootstrap.py',
        'scripts/runtime-authentication-roles.py', 'scripts/runtime-test-type-migration-upgrade.py', 'tsconfig.json',
        'policies/authentication_evidence.py', 'policies/api_evidence.py', 'policies/ci_evidence.py', 'policies/test_authentication_evidence.py',
        'policies/test_ci_evidence.py', '.github/workflows/ci.yml'))
    for folder in ('packages/db/src', 'packages/domain/src', 'packages/authz/src', 'packages/authority/src', 'apps/api/src', 'tests/fixtures'):
        paths.update((ROOT / folder).rglob('*.ts'))
    paths.update(MIGRATIONS / name for name in NAMES)
    return [{'path': str(p.relative_to(ROOT)), 'sha256': sha(p.read_bytes())} for p in sorted(paths)]


def tap_summary(output, expected):
    result = {}
    for field in ('tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo'):
        matches = re.findall(rf'^# {field} (\d+)$', output, re.MULTILINE)
        require(len(matches) == 1, 'Missing exact TAP totals')
        result[field] = int(matches[0])
    durations = re.findall(r'^# duration_ms ([0-9.]+)$', output, re.MULTILINE)
    require(len(durations) == 1, 'Missing exact TAP duration')
    result['duration_ms'] = float(durations[0])
    require(expected > 0 and result['tests'] == result['pass'] == expected and
            all(result[x] == 0 for x in ('fail', 'cancelled', 'skipped', 'todo')), 'Required native PostgreSQL case failed or did not execute')
    return result


class QualificationDeadlineExceeded(RuntimeError):
    """Explicit origin of an unchanged qualification deadline."""
    def __init__(self, budget, stage, phase):
        if budget not in ('execution', 'command', 'cleanup') or stage not in ('admission', 'running'):
            raise ValueError('Invalid qualification deadline marker')
        self.budget, self.stage, self.phase = budget, stage, phase
        super().__init__('Bounded qualification lifecycle deadline exceeded' if stage == 'admission'
                         else 'Bounded qualification command timed out')


class Harness:
    def __init__(self):
        os.umask(0o077)
        LOCAL.mkdir(parents=True, exist_ok=True)
        self.id = 'gc-authn-' + uuid.uuid4().hex[:12]
        self.folder = LOCAL / ('authority-authn-foundation-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + self.id[-12:])
        self.folder.mkdir(mode=0o700)
        self.phase, self.serial, self.owned, self.created = 'admission', 0, [], False
        self.deadline = time.monotonic() + 780  # leave cleanup time inside the900s developer wrapper
        self.cleanup_deadline = None
        self.output_bytes, self.resources_before = 0, None
        self.private_values = []
        self.secret_path = self.folder / 'private-config.json'
        self.started = datetime.now(timezone.utc).isoformat()
        self.report = {'schema_version': 1, 'result': 'RUNNING', 'started_at': self.started,
                       'command': './dev test --suite authority-authn-foundation', 'profile': 'authn-foundation-tmpfs', 'checks': []}
        if REPORT.exists():
            prior = self.folder / 'previous-report.json'
            prior.write_bytes(REPORT.read_bytes())
        self.save()

    def admission(self):
        require(shutil.disk_usage(ROOT).free >= HOST_FLOOR, 'Host free space below distinct authn profile 1GiB floor')
        retained = sum(p.stat().st_size for p in self.folder.rglob('*') if p.is_file())
        require(retained + self.output_bytes <= OUTPUT_CAP, 'New output exceeded 100MiB cumulative profile')

    def save(self, *, final=False):
        # A small terminal failure record must survive a resource-floor refusal.
        # No more runtime work or large diagnostics are allowed after that refusal.
        if not final:
            self.admission()
        encoded = (json.dumps(self.report, indent=2) + '\n').encode()
        (self.folder / 'report.json').write_bytes(encoded)
        REPORT.write_bytes(encoded)
        REPORT.chmod(0o600)

    def command(self, args, *, input=None, sensitive=False, allow_failure=False, timeout=120, cleanup=False):
        if not cleanup:
            self.admission()
        budget_end = self.cleanup_deadline if cleanup else self.deadline
        require(budget_end is not None, 'Bounded qualification lifecycle deadline exceeded')
        if time.monotonic() >= budget_end:
            raise QualificationDeadlineExceeded('cleanup' if cleanup else 'execution', 'admission', self.phase)
        self.serial += 1
        label = f'{self.serial:03d}-{self.phase}'
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT)
        payload = input.encode() if isinstance(input, str) else input

        def feed():
            try:
                if payload:
                    process.stdin.write(payload)
                process.stdin.close()
            except (BrokenPipeError, OSError):
                pass
        writer = threading.Thread(target=feed, daemon=True)
        writer.start()
        poll = selectors.DefaultSelector()
        poll.register(process.stdout, selectors.EVENT_READ, 'stdout')
        poll.register(process.stderr, selectors.EVENT_READ, 'stderr')
        data = {'stdout': bytearray(), 'stderr': bytearray()}
        command_deadline = time.monotonic() + timeout
        deadline = min(command_deadline, budget_end)
        deadline_budget = ('cleanup' if cleanup else 'execution') if budget_end <= command_deadline else 'command'
        failure = None
        try:
            while poll.get_map():
                if time.monotonic() >= deadline:
                    raise QualificationDeadlineExceeded(deadline_budget, 'running', self.phase)
                if not cleanup:
                    self.admission()
                for key, _ in poll.select(.2):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        poll.unregister(key.fileobj)
                        continue
                    require(sum(len(v) for v in data.values()) + len(block) <= DIAGNOSTIC_CAP, 'Command output exceeded 4MiB diagnostic cap')
                    data[key.data].extend(block)
            code = process.wait(timeout=3)
        except BaseException as error:
            failure = error
            process.kill()
            process.wait(timeout=5)
            code = process.returncode
        finally:
            poll.close()
            writer.join(timeout=2)
            process.stdout.close()
            process.stderr.close()
        # Never write private SQL/passwords or result rows into a diagnostic.
        result = subprocess.CompletedProcess([], code, data['stdout'].decode(errors='replace'), data['stderr'].decode(errors='replace'))
        log = f'phase={self.phase}\nexit={code}\n'
        if not sensitive:
            log += result.stdout + '\n' + result.stderr
        else:
            log += 'Private input/output intentionally omitted; assertions retain only safe outcomes.\n'
            if code != 0:
                # Only the primary psql error, never SQL/context/result rows.
                # Exact generated secrets and long hex strings are redacted first.
                primary = next((line for line in result.stderr.splitlines() if re.match(r'^(?:psql:[^:]+:\d+: )?ERROR:', line)), None)
                if primary:
                    for secret in self.private_values:
                        primary = primary.replace(secret, '[redacted]')
                    primary = re.sub(r'[0-9a-fA-F]{32,}', '[redacted]', primary)
                    log += 'Safe setup diagnostic: ' + primary[:256] + '\n'
        path = self.folder / (label + '.log')
        path.write_text(log)
        self.output_bytes += len(log.encode())  # conservative cumulative accounting, including repeated writes
        if failure:
            raise failure
        require(code == 0 or allow_failure, 'Qualification command failed; retained bounded diagnostic')
        return result

    def docker(self, *args, **kwargs):
        return self.command(['docker', *args], **kwargs)

    def inventory(self):
        return {key: self.docker(*args, sensitive=True).stdout.splitlines() for key, args in {
            'containers': ('ps', '-aq', '--no-trunc'), 'running': ('ps', '-q', '--no-trunc'), 'images': ('image', 'ls', '--no-trunc', '--digests', '--format', '{{.ID}} {{.Repository}}:{{.Tag}} {{.Digest}}'),
            'volumes': ('volume', 'ls', '-q')}.items()}

    def memory_admission(self):
        total = int(self.docker('info', '--format', '{{.MemTotal}}').stdout)
        lines = self.docker('stats', '--no-stream', '--format', '{{.MemUsage}}', sensitive=True).stdout.splitlines()
        used = 0
        for line in lines:
            match = re.fullmatch(r'\s*([0-9.]+)(B|KiB|MiB|GiB)\s*/.*', line)
            require(match is not None, 'Unrecognized Docker memory observation')
            used += float(match[1]) * {'B': 1, 'KiB': 1024, 'MiB': MIB, 'GiB': GIB}[match[2]]
        require(total - used - GIB >= 2*GIB, 'Docker observed headroom below 2GiB plus daemon reserve')
        return {'total_bytes': total, 'observed_working_bytes': int(used), 'daemon_reserve_bytes': GIB}

    def sql_result(self, body, role='postgres', database=DATABASE, allow_failure=False):
        return self.docker('exec', '-i', self.id, 'psql', '-X', '-qAt', '--set', 'ON_ERROR_STOP=1', '-U', role, '-d', database,
                           input=body, sensitive=True, allow_failure=allow_failure)

    def sql(self, body, **kwargs):
        return self.sql_result(body, **kwargs).stdout.strip()

    def helper(self, args, *, mounts=(), timeout=120, allow_failure=False, sensitive=False, input=None):
        name = self.id + '-h' + str(self.serial)
        self.owned.append(name)
        command = ['run', '-i', '--rm', '--pull', 'never', '--name', name, '--label', 'org.governance-commons.authn-run=' + self.id,
                   '--network', 'container:' + self.id, '--memory', '384m', '--memory-swap', '384m', '--cpus', '1', '--pids-limit', '128',
                   '--read-only', '--log-driver', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
                   '--user', f'{os.getuid()}:{os.getgid()}', '--tmpfs', '/tmp:rw,nosuid,nodev,size=32m,mode=1777', '--workdir', '/app',
                   '--env', 'HOME=/tmp', '--env', 'NODE_OPTIONS=--max-old-space-size=256', '--env', 'AUTHN_FOUNDATION_CONFIG=/run/authn-config.json',
                   '--volume', f'{self.secret_path}:/run/authn-config.json:ro']
        for folder in ('packages/db/src', 'packages/domain/src', 'packages/authz/src', 'packages/authority/src', 'apps/api/src', 'tests/fixtures', 'tests/qualification'):
            command += ['--volume', f'{ROOT / folder}:/app/{folder}:ro']
        command += ['--volume', f'{ROOT / "docs/execution/authentication-legacy-function-census.json"}:/app/docs/execution/authentication-legacy-function-census.json:ro']
        command += ['--volume', f'{ROOT / "scripts/authentication-install.ts"}:/app/scripts/authentication-install.ts:ro']
        for host, target in mounts:
            command += ['--volume', f'{host}:{target}:ro']
        return self.docker(*command, self.app_image, *args, timeout=timeout, allow_failure=allow_failure, sensitive=sensitive, input=input)

    def js(self, body, **kwargs):
        prefix = "import fs from 'node:fs';const config=JSON.parse(fs.readFileSync('/run/authn-config.json','utf8'));process.env.DATABASE_URL=config.legacy;process.env.MIGRATION_DATABASE_URL=config.owner;"
        # Static imports in a supplied fixture execute before its top-level body.
        # Bootstrap URLs in a separate module before loading any database module.
        name = 'script-' + uuid.uuid4().hex + '.mjs'
        script = self.folder / name
        script.write_text("import fs from 'node:fs';const config=JSON.parse(fs.readFileSync('/run/authn-config.json','utf8'));\n" + body)
        mounts = [*kwargs.pop('mounts', ()), (script, '/app/' + name)]
        return self.helper(['node', '--import', 'tsx', '--input-type=module', '-e', prefix + "await import('./" + name + "');"], mounts=mounts, **kwargs)

    def migrate(self, path, allow_failure=False):
        return self.js("try{await import('./packages/db/src/migrate.ts')}catch(error){console.error('MIGRATION_FAILED',String(error.code??''),String(error.message??'').slice(0,160));process.exitCode=1}",
                       mounts=[(path, '/app/packages/db/migrations')], allow_failure=allow_failure)

    def snapshot(self, tables):
        result = {}
        for table in tables:
            require(re.fullmatch(r'[a-z_]+(?:\.[a-z_]+)?', table), 'Invalid fixed snapshot table')
            result[table] = json.loads(self.sql(f"SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]') FROM {table} r;"))
        return result

    def cleanup(self):
        self.cleanup_deadline = time.monotonic() + 90
        failures = []
        for name in [*reversed(self.owned), self.id]:
            inspected = self.docker('inspect', '--format', '{{index .Config.Labels "org.governance-commons.authn-run"}}', name, allow_failure=True, sensitive=True, cleanup=True)
            if inspected.returncode:
                continue
            if inspected.stdout.strip() != self.id:
                failures.append('Owned label mismatch')
                continue
            removed = self.docker('rm', '-f', name, allow_failure=True, cleanup=True)
            if removed.returncode:
                failures.append('Owned removal failed')
        residual = self.docker('ps', '-aq', '--filter', 'label=org.governance-commons.authn-run=' + self.id, cleanup=True).stdout.strip()
        self.secret_path.unlink(missing_ok=True)
        require(not failures and not residual, 'Owned container cleanup incomplete; preserve failed report')
        self.report['cleanup'] = {'ownedRemoved': True}


def execute(h):
    roles = module(ROOT / 'scripts/authentication_roles.py', 'gc_authn_role_provisioner')
    previous = module(ROOT / 'scripts/runtime-test-relation-participation-upgrade.py', 'gc_authn_legacy_fixture')
    domain_previous = module(ROOT / 'scripts/runtime-test-business-domains-upgrade.py', 'gc_authn_domain_fixture')
    expected_census = json.loads((ROOT / 'docs/execution/authentication-legacy-function-census.json').read_text())
    h.report['sources'] = source_hashes()
    h.report['commit'] = h.command(['git', 'rev-parse', 'HEAD'], sensitive=True).stdout.strip()
    require(re.fullmatch(r'[0-9a-f]{40}', h.report['commit']), 'Invalid immutable base revision')
    context = json.loads(h.docker('context', 'inspect', sensitive=True).stdout)[0]['Endpoints']['docker']['Host']
    override = os.environ.get('DOCKER_HOST', '')
    require(context.startswith(('unix://', 'npipe://')) and (not override or override.startswith(('unix://', 'npipe://'))), 'Only local isolated Docker is allowed')
    h.resources_before = h.inventory()
    h.report['memory_admission'] = h.memory_admission()
    image = re.search(r'^\s+image: (postgres:[^\s]+)$', (ROOT / 'deploy/compose/compose.yaml').read_text(), re.MULTILINE)
    require(image is not None, 'Pinned PostgreSQL image missing')
    pg_image = h.docker('image', 'inspect', '--format', '{{.Id}}', image[1]).stdout.strip()
    h.app_image = h.docker('image', 'inspect', '--format', '{{.Id}}', 'governance-commons:dev').stdout.strip()
    h.report['images'] = {'postgres': pg_image, 'application': h.app_image}
    h.report['docker_version'] = h.docker('version', '--format', '{{.Server.Version}}').stdout.strip()
    password = {key: secrets.token_hex(24) for key in ('postgres', OWNER, 'gc_app')}
    url = lambda role, secret: f'postgresql://{role}:{secret}@127.0.0.1:5432/{DATABASE}'
    definitions, slots = [], []
    for index in range(64):
        slot = {}
        for field, kind in [('login', 'login'), ('api', 'api'), ('nextLogin', 'login'), ('nextApi', 'api')]:
            name, secret = f'gc_af_{field.lower()}_{index:02}', secrets.token_hex(24)
            definitions.append({'name': name, 'kind': kind, 'password': secret})
            slot[field] = {'name': name, 'url': url(name, secret)}
        slots.append(slot)
    unregistered = {'name': 'gc_af_unregistered', 'kind': 'api', 'password': secrets.token_hex(24)}
    definitions.append(unregistered)
    h.private_values = [*password.values(), *(row['password'] for row in definitions)]
    config = {'owner': url(OWNER, password[OWNER]), 'admin': url('postgres', password['postgres']), 'legacy': url('gc_app', password['gc_app']),
              'unregistered': {'name': unregistered['name'], 'url': url(unregistered['name'], unregistered['password'])}, 'slots': slots, 'suiteOffset': 0}
    h.secret_path.write_text(json.dumps(config))
    before, target, damaged = [h.folder / name for name in ('before', 'target', 'damaged')]
    for folder, names in [(before, NAMES[:11]), (target, NAMES), (damaged, NAMES)]:
        folder.mkdir()
        for name in names:
            shutil.copyfile(MIGRATIONS / name, folder / name)
    (damaged / NAMES[0]).write_bytes((damaged / NAMES[0]).read_bytes() + b'\n-- Synthetic predecessor checksum mismatch\n')
    h.phase = 'database-start'
    h.docker('run', '--detach', '--pull', 'never', '--name', h.id, '--label', 'org.governance-commons.authn-run=' + h.id,
             '--network', 'none', '--memory', '512m', '--memory-swap', '512m', '--cpus', '1', '--pids-limit', '128',
             '--read-only', '--log-driver', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--user', 'postgres',
             '--tmpfs', '/var/lib/postgresql/data:rw,nosuid,nodev,size=256m,mode=1777', '--tmpfs', '/tmp:rw,nosuid,nodev,size=16m,mode=1777',
             '--tmpfs', '/var/run/postgresql:rw,nosuid,nodev,size=4m,mode=1777', '--env', 'PGDATA=/var/lib/postgresql/data/pgdata',
             '--entrypoint', 'sh', pg_image, '-ec',
             "initdb --auth-local=trust --auth-host=scram-sha-256 -D /var/lib/postgresql/data/pgdata >/tmp/init.log 2>&1; exec postgres -D /var/lib/postgresql/data/pgdata -c listen_addresses=127.0.0.1 -c shared_buffers=32MB -c work_mem=2MB -c maintenance_work_mem=16MB -c max_connections=16 -c min_wal_size=32MB -c max_wal_size=64MB -c max_prepared_transactions=0 -c log_statement=none -c log_min_error_statement=panic -c log_error_verbosity=terse -c log_parameter_max_length=0 -c log_parameter_max_length_on_error=0")
    h.created = True
    deadline = time.monotonic() + 30
    while True:
        ready = h.docker('exec', h.id, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres', allow_failure=True)
        if ready.returncode == 0:
            break
        require(time.monotonic() < deadline, 'Isolated database did not become ready')
        time.sleep(.1)
    h.phase = 'predecessor'
    setup = f"ALTER ROLE postgres PASSWORD {literal(password['postgres'])};\n"
    for role in (OWNER, 'gc_app'):
        setup += f"CREATE ROLE {role} LOGIN PASSWORD {literal(password[role])} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;\n"
    setup += f'CREATE DATABASE {DATABASE} OWNER {OWNER};'
    h.sql(setup, database='postgres')
    h.sql(f'REVOKE ALL ON DATABASE {DATABASE} FROM PUBLIC;GRANT CONNECT ON DATABASE {DATABASE} TO {OWNER},gc_app;REVOKE CREATE ON SCHEMA public FROM PUBLIC;ALTER SCHEMA public OWNER TO {OWNER};')
    runtime = json.loads(h.js("import crypto from 'node:crypto';const sha=p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');console.log(JSON.stringify({node:process.version,pg:JSON.parse(fs.readFileSync('node_modules/pg/package.json')).version,tsx:JSON.parse(fs.readFileSync('node_modules/tsx/package.json')).version,kysely:JSON.parse(fs.readFileSync('node_modules/kysely/package.json')).version,packageSha256:sha('package.json'),lockSha256:sha('pnpm-lock.yaml')}));").stdout)
    require(runtime['packageSha256'] == sha((ROOT / 'package.json').read_bytes()) and runtime['lockSha256'] == sha((ROOT / 'pnpm-lock.yaml').read_bytes()), 'Cached image dependencies differ from frozen source')
    h.report['runtime'] = runtime
    h.migrate(before)
    # Original synthetic source constructors, actual runtime writes; no fabricated history.
    h.sql(previous.fixture_sql(), role=OWNER)
    h.js(previous.typed_fixture_js())
    h.js(previous.relation_fixture_js())
    h.js(domain_previous.graph_fixture_js())
    h.sql(f"BEGIN;SET LOCAL gc.tenant_id='{TENANT}';UPDATE memberships SET permissions='[\"catalog:read\",\"catalog:write\",\"models:read\",\"models:write\",\"domains:read\",\"domains:write\",\"domains:assign\",\"audit:read\"]' WHERE identity_id='{ACTOR}';COMMIT;", role=OWNER)
    h.js("const {db}=await import('./packages/db/src/index.ts');const {fixture,execute,reason,migrationPlan,digest}=await import('./tests/fixtures/business-domains.ts');try{const f=await fixture();await execute({kind:'domain.placement',assetId:f.asset.id,assetVersion:f.asset.version,domainId:f.domains[0].id,domainVersion:f.domains[0].version,expectedPlacementVersion:0,reason});const definition={...f.type.definition,version:2,label:'Synthetic preserved domain migration'};await execute({kind:'domain-type-migration.execute',typeId:f.type.typeId,expectedHeadVersion:1,definition,plan:migrationPlan(f.type,[1]),previewDigest:digest,reason});console.log('Actual domain history, placement and migration baseline created');}finally{await db.destroy()}")
    # Historical inactive identity/member and legacy auth rows survive byte-for-byte.
    h.sql(f"INSERT INTO public.identities(id,issuer,subject,name,active) VALUES('10000000-0000-4000-8000-000000000099','synthetic-upgrade','revoked','Synthetic revoked',false);BEGIN;SET LOCAL gc.tenant_id='{TENANT}';INSERT INTO memberships(tenant_id,identity_id,role,permissions,active) VALUES('{TENANT}','10000000-0000-4000-8000-000000000099','synthetic','[]',false);COMMIT;INSERT INTO public.sessions VALUES('{secrets.token_hex(32)}','{ACTOR}','{TENANT}','{secrets.token_hex(32)}',clock_timestamp()+interval '1 hour');INSERT INTO public.login_states VALUES('{secrets.token_hex(32)}','{secrets.token_hex(32)}','{secrets.token_hex(32)}',clock_timestamp()+interval '5 minutes');", role=OWNER)
    tables = json.loads(h.sql("SELECT json_agg(tablename ORDER BY tablename) FROM pg_tables WHERE schemaname='public' AND tablename<>'schema_migrations';"))
    prior_ledger = json.loads(h.sql("SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;"))
    require(len(prior_ledger) == 11, 'Predecessor is not exactly SQL001–011')
    original = h.snapshot(tables)
    for table in ('governance_model_migrations', 'asset_revisions', 'relation_graph_receipts', 'domain_revisions', 'asset_domain_placement_revisions', 'domain_type_migrations', 'audit', 'outbox', 'idempotency'):
        require(table in original and len(original[table]) > 0, 'Required representative baseline absent: ' + table)
    census_sql = "SELECT json_agg(json_build_object('signature',p.oid::regprocedure::text,'identity_arguments',pg_get_function_identity_arguments(p.oid),'name',p.proname,'security_definer',p.prosecdef,'owner',pg_get_userbyid(p.proowner),'legacy_runtime_execute',has_function_privilege('gc_app',p.oid,'EXECUTE'),'public_execute',EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE grantee=0 AND privilege_type='EXECUTE')) ORDER BY p.oid::regprocedure::text) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'gc\\_%' ESCAPE '\\';"
    census = json.loads(h.sql(census_sql))
    require(census == expected_census['functions'] and len(census) == 155 and sum(x['public_execute'] for x in census) == 56, 'Predecessor function census differs from frozen155/56 contract')
    h.report['checks'].append('Actual SQL001–011 baseline includes canonical/history/graph/domain receipts, private legacy auth and revoked principal rows;155/56 function census matches')
    h.phase = 'upgrade-refusals'
    failed = h.migrate(damaged, allow_failure=True)
    require(failed.returncode != 0 and 'Applied migration changed' in failed.stderr, 'Changed predecessor checksum accepted')
    failed = h.migrate(target, allow_failure=True)
    require(failed.returncode != 0, 'Missing definer prerequisite unexpectedly accepted')
    require(h.sql("SELECT to_regnamespace('gc_authn') IS NULL;") == 't' and h.snapshot(tables) == original, 'Failed prerequisite/checksum altered baseline')
    try:
        h.sql(roles.prepare_sql(OWNER, DATABASE))
        h.sql('ALTER ROLE gc_authn_definer LOGIN;')
        failed = h.migrate(target, allow_failure=True)
        require(failed.returncode != 0 and h.sql("SELECT to_regnamespace('gc_authn') IS NULL;") == 't', 'Unsafe definer prerequisite was accepted')
        h.sql('ALTER ROLE gc_authn_definer NOLOGIN;CREATE SCHEMA gc_authn AUTHORIZATION gc_owner;')
        failed = h.migrate(target, allow_failure=True)
        require(failed.returncode != 0, 'Conflicting protected namespace was overwritten')
        require(h.sql("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='gc_authn';") == '0', 'Conflicting namespace gained partial DDL')
        h.sql('DROP SCHEMA gc_authn;')
        h.phase = 'upgrade'
        applied = h.migrate(target)
        require(re.findall(r'^Applied (.+)$', applied.stdout, re.MULTILINE) == [NAMES[-1]], 'Forward application was not exactly SQL012')
    finally:
        h.sql(roles.finish_sql(OWNER))
    require(h.snapshot(tables) == original, 'Forward migration changed original rows or ledger')
    ledger_after = json.loads(h.sql("SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;"))
    require(ledger_after[:11] == prior_ledger and len(ledger_after) == 12, 'Prior ledger checksums/timestamps changed')
    h.report['checks'].append('Checksum, missing/unsafe prerequisite and namespace collisions fail transactionally before the exact forward application')
    h.phase = 'replay'
    protected_tables = ['gc_authn.' + row for row in json.loads(h.sql("SELECT json_agg(tablename ORDER BY tablename) FROM pg_tables WHERE schemaname='gc_authn';"))]
    require(len(protected_tables) == 13, 'Protected table census is not13')
    initial = h.snapshot(protected_tables)
    require(sum(len(rows) for key, rows in initial.items() if key != 'gc_authn.installation_root') == 0 and len(initial['gc_authn.installation_root']) == 1, 'Migration seeded authority/identity/session/fence rows')
    require('Applied' not in h.migrate(target).stdout and h.snapshot(protected_tables) == initial, 'Replay changed protected installation')
    checksums = json.loads(h.sql("SELECT json_agg(json_build_object('name',name,'sha256',checksum) ORDER BY name) FROM schema_migrations;"))
    require(checksums == [{'name': n, 'sha256': sha((MIGRATIONS / n).read_bytes())} for n in NAMES], 'Migration checksums disagree')
    h.report['migrations'] = checksums
    h.sql(roles.executor_sql(DATABASE, definitions))
    h.sql(roles.executor_sql(DATABASE, definitions))
    h.phase = 'role-provisioner-refusals'
    probe = definitions[-1]
    changed = {**probe, 'password': secrets.token_hex(24)}
    h.sql(roles.executor_sql(DATABASE, [changed]))
    h.js("const {Client}=await import('pg');const c=new Client({connectionString:config.unregistered.url});try{await c.connect();console.log('Original native SCRAM credential retained');}finally{await c.end();}", sensitive=True)
    # Preserve a wrong grant/NOLOGIN until an explicit test cleanup, never rely on
    # provisioner replay to silently restore or remove administrator decisions.
    h.sql(f"GRANT SELECT(name) ON public.assets TO {probe['name']};")
    try:
        require(h.sql_result(roles.executor_sql(DATABASE, [probe]), allow_failure=True).returncode != 0, 'Column grant was silently accepted or repaired')
        require(h.sql(f"SELECT has_column_privilege('{probe['name']}','public.assets','name','SELECT');") == 't', 'Rejected provisioning changed prior column grant')
    finally:
        h.sql(f"REVOKE SELECT(name) ON public.assets FROM {probe['name']};")
    h.sql(f"GRANT USAGE ON TYPE public.gc_authn_attempt_exchange TO {probe['name']};")
    try:
        require(h.sql_result(roles.executor_sql(DATABASE, [probe]), allow_failure=True).returncode != 0, 'Wrong return-type family was accepted')
    finally:
        h.sql(f"REVOKE USAGE ON TYPE public.gc_authn_attempt_exchange FROM {probe['name']};")
    h.sql(f"ALTER ROLE {probe['name']} NOLOGIN;")
    try:
        require(h.sql_result(roles.executor_sql(DATABASE, [probe]), allow_failure=True).returncode != 0, 'Revoked LOGIN was silently restored')
        require(h.sql(f"SELECT rolcanlogin FROM pg_roles WHERE rolname='{probe['name']}';") == 'f', 'Failed role replay reactivated LOGIN')
    finally:
        h.sql(f"ALTER ROLE {probe['name']} LOGIN;")
    # A rejected preparation must not turn cleanup into a repair of unrelated
    # administrator grants. Compare the complete exact membership row/options.
    membership_snapshot = "SELECT coalesce(json_agg(to_jsonb(m) ORDER BY grantor),'[]') FROM pg_auth_members m WHERE roleid='gc_authn_definer'::regrole AND member='gc_owner'::regrole;"
    for options in ('ADMIN TRUE, INHERIT FALSE, SET TRUE', 'ADMIN FALSE, INHERIT TRUE, SET TRUE', 'ADMIN FALSE, INHERIT FALSE, SET FALSE'):
        h.sql(f'GRANT gc_authn_definer TO gc_owner WITH {options};')
        try:
            unexpected = h.sql(membership_snapshot)
            require(h.sql_result(roles.prepare_sql(OWNER, DATABASE), allow_failure=True).returncode != 0, 'Unexpected membership was accepted during preparation')
            require(h.sql(membership_snapshot) == unexpected, 'Rejected preparation changed administrator membership')
            require(h.sql_result(roles.finish_sql(OWNER), allow_failure=True).returncode != 0, 'Unexpected membership was accepted during cleanup')
            require(h.sql(membership_snapshot) == unexpected, 'Cleanup repaired an unexpected administrator membership')
        finally:
            h.sql('REVOKE gc_authn_definer FROM gc_owner;')
    for schema in ('public', 'gc_authn'):
        h.sql(f'GRANT CREATE ON SCHEMA {schema} TO gc_authn_definer;')
        try:
            require(h.sql_result(roles.finish_sql(OWNER), allow_failure=True).returncode != 0, 'Unassociated schema CREATE grant was accepted')
            require(h.sql(f"SELECT has_schema_privilege('gc_authn_definer','{schema}','CREATE');") == 't', 'Cleanup removed an unassociated administrator schema grant')
        finally:
            h.sql(f'REVOKE CREATE ON SCHEMA {schema} FROM gc_authn_definer;')
    h.sql(roles.finish_sql(OWNER))
    # Cleanup commits temporary grants even when a later independent role-safety
    # check fails; a failed postcondition must not roll those revocations back.
    try:
        h.sql(roles.prepare_sql(OWNER, DATABASE))
        h.sql('ALTER ROLE gc_authn_definer CREATEDB;')
        require(h.sql_result(roles.finish_sql(OWNER), allow_failure=True).returncode != 0, 'Unsafe definer final assertion was not enforced')
        require(h.sql("SELECT NOT has_schema_privilege('gc_authn_definer','public','CREATE') AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE roleid='gc_authn_definer'::regrole AND member='gc_owner'::regrole);") == 't', 'Failed final assertion rolled back temporary privilege cleanup')
    finally:
        h.sql('ALTER ROLE gc_authn_definer NOCREATEDB;')
        h.sql(roles.finish_sql(OWNER))
    h.report['checks'].append('Native credential-preserving role replay rejects existing column/type grants and NOLOGIN; failed final assertion still removes temporary setup privileges')
    h.report['checks'].append('Thirteen private tables begin empty except immutable installation root; checksum/provisioner replay is exact, native SCRAM executors have finite capabilities')
    h.phase = 'installation-cli'
    cli_tenant = str(uuid.uuid4())
    h.sql(f"INSERT INTO public.tenants(id,name) VALUES('{cli_tenant}','Synthetic native CLI installation');", role=OWNER)
    db_oid = int(h.sql("SELECT oid FROM pg_database WHERE datname=current_database();"))
    owner_oid = int(h.sql("SELECT oid FROM pg_roles WHERE rolname='gc_owner';"))
    manifest = {'formatVersion': 1, 'requestId': str(uuid.uuid4()), 'releaseReference': 'synthetic-cli-release',
                'deploymentOperatorReference': 'synthetic-cli-operator', 'expectedDatabaseOid': db_oid,
                'expectedOwnerRoleOid': owner_oid, 'predecessorManifestHash': None,
                'operation': {'type': 'initialize-tenant', 'tenantId': cli_tenant, 'generation': 1}}
    cli = "process.argv=[process.execPath,'scripts/authentication-install.ts','--stdin'];await import('./scripts/authentication-install.ts');"
    first_cli = h.js(cli, input=json.dumps(manifest)).stdout
    replay_cli = h.js(cli, input=json.dumps(manifest)).stdout
    require(first_cli == replay_cli, 'Native CLI replay differs from its committed receipt')
    wrong_cli = h.js("process.env.MIGRATION_DATABASE_URL=config.legacy;" + cli, input=json.dumps(manifest), allow_failure=True)
    require(wrong_cli.returncode != 0, 'CLI accepted the legacy runtime as installation owner')
    h.report['checks'].append('Actual deployment CLI commits and exactly replays a receipt using native owner SCRAM; wrong-owner execution refuses')
    for path, offset, key in [(TEST, 0, 'tests'), (CONCURRENCY, 32, 'concurrency_tests')]:
        h.phase = key
        h.memory_admission()
        config['suiteOffset'] = offset
        h.secret_path.write_text(json.dumps(config))
        expected = len(re.findall(r'^test\(', path.read_text(), re.MULTILINE))
        result = h.helper(['node', '--import', 'tsx', '--test', '--test-reporter=tap', '--test-concurrency=1', str(path.relative_to(ROOT))], timeout=240, allow_failure=True)
        test_log = h.folder / f'{h.serial:03d}-{h.phase}.log'
        h.report.setdefault('test_logs', {})[key] = {'path': str(test_log.relative_to(ROOT)), 'sha256': sha(test_log.read_bytes())}
        require(result.returncode == 0, 'Native PostgreSQL suite failed; original safe TAP retained')
        h.report[key] = tap_summary(result.stdout, expected)
        h.report['checks'].append(f"All{expected} {key} pass with native connections, no failures, skips, cancellations or todos")
        h.save()
    current = h.snapshot(tables)
    for table, rows in original.items():
        require(all(row in current[table] for row in rows), 'An original row changed or disappeared: ' + table)
    h.report['baseline'] = [{'table': table, 'original_rows': len(rows), 'sha256': sha(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode())} for table, rows in original.items()]
    require(source_hashes() == h.report['sources'], 'Executed source changed; rerun frozen inputs')
    inspected = json.loads(h.docker('inspect', h.id, sensitive=True).stdout)[0]
    require(inspected['HostConfig']['NetworkMode'] == 'none' and not inspected['HostConfig']['PortBindings'] and inspected['HostConfig']['ReadonlyRootfs']
            and inspected['HostConfig']['LogConfig']['Type'] == 'none' and inspected['HostConfig']['Memory'] == 512*MIB
            and inspected['HostConfig']['MemorySwap'] == 512*MIB and not any(m['Type'] in ('volume', 'bind') for m in inspected['Mounts']), 'Database isolation/resource settings changed')
    h.report['isolation'] = {'network': 'none', 'readOnly': True, 'logDriver': 'none', 'memoryBytes': 896*MIB,
                             'pgdataTmpfsBytes': 256*MIB, 'hostFloorBytes': HOST_FLOOR, 'outputCapBytes': OUTPUT_CAP, 'diagnosticCapBytes': DIAGNOSTIC_CAP}
    h.report['limitations'] = ['Isolated inactive PostgreSQL authentication only; no shared-core migration, HTTP/OIDC/CSRF, runtime content authority, service leases, cutover or release qualification.',
        'Broker attestation is trusted; SQL does not verify JWT signatures or prove external exchange. Native later-transaction consumption is separately tested.',
        'Prearmed contention timeout is qualified; no universal in-function hard30-second timer is claimed.',
        'Observed memory headroom and host output caps do not guarantee Docker VM/host swap behavior. Existing services, images, volumes and prior evidence are preserved.']


def main():
    h = Harness()
    error = None
    try:
        execute(h)
    except BaseException as failure:
        error = failure
        h.report.update(result='FAIL', failed_phase=h.phase, error_type=type(failure).__name__, error='Qualification failed; inspect bounded private diagnostic. No runtime activation.')
    finally:
        try:
            h.phase = 'cleanup'
            h.cleanup()
            if h.resources_before is not None:
                # Readback uses the same reserved cleanup window after runtime work ends.
                h.deadline = h.cleanup_deadline
                require(h.inventory() == h.resources_before, 'Preexisting resource inventory changed')
                h.report['cleanup']['resourceInventoryPreserved'] = True
        except BaseException as failure:
            error = failure
            h.report.update(result='FAIL', failed_phase='cleanup', error_type=type(failure).__name__, error='Cleanup or resource preservation could not be established')
        if error is None:
            h.report['result'] = 'PASS'
        h.report['recorded_at'] = datetime.now(timezone.utc).isoformat()
        h.report['evidence_directory'] = str(h.folder.relative_to(ROOT))
        h.report['private_logs'] = [{'path': str(p.relative_to(ROOT)), 'sha256': sha(p.read_bytes())} for p in sorted(h.folder.glob('*.log'))]
        h.save(final=True)
    print(json.dumps({'result': h.report['result'], 'checks': len(h.report['checks']), 'report': str(REPORT.relative_to(ROOT))}))
    return 1 if error else 0


if __name__ == '__main__':
    raise SystemExit(main())
