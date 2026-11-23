#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SQL029→030 table-volume forward upgrade in fresh owned PostgreSQL.

Actual149 cases populate SQL029, then all original canonical fields/ledger must
survive030 and inert replay. The same149 +18 volume +4 hostile cases run after.
Exactly two immutable SQL029 modules are mounted only for predecessor suites;
reports distinguish checkout bytes from the actual effective module bytes.
No shared runtime, build/pull, real source worker, HTTP or browser claim.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / '.local/evidence/quality-volume-upgrade.json'
LEGACY = [('tests/qualification/quality.test.ts', 15), ('tests/api/reference-quality-storage.test.ts',21),
          ('tests/api/quality-uniqueness-storage.test.ts',16), ('tests/api/quality-range-storage.test.ts',18),
          ('tests/api/quality-monitoring-storage.test.ts',31), ('tests/api/quality-monitoring-invariants.test.ts',4),
          ('tests/api/quality-freshness-storage.test.ts',18), ('tests/api/quality-freshness-invariants.test.ts',4),
          ('tests/api/quality-freshness-monitoring-storage.test.ts',18), ('tests/api/quality-freshness-monitoring-invariants.test.ts',4)]
TESTS = [('tests/api/quality-volume-storage.test.ts',18), ('tests/api/quality-volume-invariants.test.ts',4)]
FAMILIES = ('completeness','reference','uniqueness','range','monitoring','monitoring-invariants',
            'freshness','freshness-invariants','freshness-monitoring','freshness-monitoring-invariants')
PHASES = tuple(f'{stage}-{family}-tests' for stage in ('pre029','post030') for family in FAMILIES) + ('post030-volume-tests','post030-volume-invariants-tests')
MIGRATION = '030_quality_volume.sql'
PROBE = '/app/quality-volume-upgrade-source-check.cjs'
spec = importlib.util.spec_from_file_location('quality_volume_source_base', ROOT / 'scripts/runtime-test-source-connectors-upgrade.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
require, sha = base.require, base.sha
NAMES = [*base.NAMES, '015_approval_workflows.sql', '016_glossary_publication.sql',
         '017_relation_scope_candidates.sql', '018_glossary_nominal_candidates.sql',
         '019_quality_execution.sql', '020_native_lineage.sql', '021_classification_review.sql',
         '022_reference_publication.sql', '023_reference_quality.sql', '024_reference_structures.sql', '025_quality_uniqueness.sql', '026_quality_range.sql', '027_quality_monitoring.sql', '028_quality_freshness.sql', '029_quality_freshness_scheduling.sql', MIGRATION]


def migrations():
    actual = sorted(path.name for path in (ROOT / 'packages/db/migrations').glob('*.sql'))
    successors = ['031_authority_read_grants.sql', '032_relation_candidate_validation.sql', '033_content_security_revisions.sql', '034_classification_label_identities.sql']
    suffix = actual[len(NAMES):]
    require(actual[:len(NAMES)] == NAMES and suffix == successors[:len(suffix)],
            'Exact SQL001–030 prefix and declared contiguous successors required')
    return NAMES


def source_file(path):
    path = Path(os.path.abspath(path))
    require(path.is_relative_to(ROOT), 'Qualification source outside checkout')
    require(all(not p.is_symlink() for p in (path, *path.parents) if p.is_relative_to(ROOT)), 'Qualification source symlinked')
    require(path.is_file(), 'Qualification source missing')
    return path


PREDECESSORS = [{'path': 'packages/domain/src/quality-service.ts', 'fixture': 'tests/qualification/predecessors/quality-service-sql029.ts.txt', 'commit': 'fca6bb94a8bd87965c4bf614ae492b85235f4ea9', 'gitBlob': '289dfdd222f7949d1aaabdb35c46cc48b7a5e975', 'sha256': '6a7691da7bf328341277ad0cf6737f44b5fd25cc61dbb97b2b345ecec14e1a73'}, {'path': 'apps/api/src/repository.ts', 'fixture': 'tests/qualification/predecessors/repository-sql029.ts.txt', 'commit': 'fca6bb94a8bd87965c4bf614ae492b85235f4ea9', 'gitBlob': 'c29e13fa15bbbfb4c4a7c0182f853e89f9ee1f60', 'sha256': '0b3305e0318db339031dee812b6c06d742f32c8af8b5a44b601b4d50569d9eed'}]


def predecessor_pins():
    for pin in PREDECESSORS:
        data=source_file(ROOT/pin['fixture']).read_bytes()
        require(sha(data)==pin['sha256'] and hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==pin['gitBlob'], 'Immutable SQL029 module differs')
        # Resolve the immutable module's relative imports in its original location.
        # A changed dependency set requires explicit gate review, never a broad overlay.
        imports=lambda data: re.findall(rb"(?:from\s*|import\s*(?:\(\s*)?|require\s*\(\s*)?['\"](\.[^'\"]+)['\"]",data)
        require(imports(data)==imports(source_file(ROOT/pin['path']).read_bytes()), 'SQL029 module dependency set differs')
    return PREDECESSORS


def effective_sources(rows, phase):
    require(phase in PHASES, 'Undeclared native source stage')
    pins=predecessor_pins()
    require(len({r['path'] for r in rows})==len(rows) and all(any(r['path']==p['path'] for r in rows) for p in pins), 'Missing declared phase module')
    substitutions={p['path']:p['sha256'] for p in pins} if phase.startswith('pre029-') else {}
    return [{'path':r['path'],'sha256':substitutions.get(r['path'],r['sha256'])} for r in rows]


def sources():
    pins=predecessor_pins()
    paths = {'scripts/runtime-test-quality-volume-upgrade.py', 'scripts/runtime-test-source-connectors-upgrade.py',
             'scripts/runtime-test-authority-authn-foundation.py', 'scripts/authentication_roles.py',
                     'scripts/runtime-test-quality-monitoring-upgrade.py', 'scripts/qualification_quality_pre030.py', 'scripts/qualification_quality_repository.py',
                     'tests/qualification/predecessors/repository-sql026.ts.txt',
             'package.json', 'pnpm-lock.yaml', 'Dockerfile', 'tsconfig.json', 'deploy/compose/compose.yaml',
             *(p['fixture'] for p in pins), *(p['path'] for p in pins), 'tests/fixtures/quality-volume.ts', 'tests/fixtures/quality-freshness-monitoring.ts', *(path for path, _ in TESTS), *(path for path, _ in LEGACY), 'tests/fixtures/reference-quality.ts', 'packages/db/src/migrate.ts',
             'packages/domain/src/quality-service.ts', 'apps/api/src/quality.ts',
             'apps/site-runner/src/quality-activity.ts', 'apps/workflow-worker/src/quality-http.ts',
             'tests/fixtures/quality-monitoring.ts', 'tests/fixtures/quality-freshness.ts', 'packages/domain/src/quality-monitoring-service.ts', 'apps/api/src/quality-monitoring.ts'}
    paths.update('packages/db/migrations/' + name for name in migrations())
    pending = [ROOT / path for path in paths if path.endswith(('.ts', '.tsx'))]
    while pending:
        current = pending.pop()
        text = source_file(current).read_text()
        relative = re.findall(r'''(?:from\s*|import\s*(?:\(\s*)?|require\s*\(\s*)['"](\.[^'"]+)['"]''', text)
        for name in relative:
            candidate = Path(os.path.abspath(current.parent / name))
            if candidate.suffix == '.js' and not candidate.is_file():
                candidate = candidate.with_suffix('.ts')
            if not candidate.suffix:
                candidate = candidate.with_suffix('.ts') if candidate.with_suffix('.ts').is_file() else candidate / 'index.ts'
            candidate = source_file(candidate)
            path = str(candidate.relative_to(ROOT))
            if path not in paths:
                paths.add(path)
                if candidate.suffix in ('.ts', '.tsx'):
                    pending.append(candidate)
    require(len(paths) <= 1024, 'Quality qualification source closure exceeds bound')
    result = []
    for path in sorted(paths):
        file = source_file(ROOT / path)
        result.append({'path': path, 'sha256': sha(file.read_bytes())})
    return result


def verifier(rows, config_hash):
    return ("const fs=require('node:fs'),crypto=require('node:crypto');\nconst rows=" + json.dumps(rows) + ";\n"
            "function check(){for(const row of rows){if(crypto.createHash('sha256').update(fs.readFileSync('/app/'+row.path)).digest('hex')!==row.sha256)throw new Error('QUALITY_VOLUME_SOURCE_MISMATCH');}"
            "if(crypto.createHash('sha256').update(fs.readFileSync('/run/authn-config.json')).digest('hex')!==" + json.dumps(config_hash) + ")throw new Error('QUALITY_VOLUME_CONFIG_MISMATCH');}\n"
            "check();process.on('exit',check);\n")


def totals(output):
    result = {}
    for field in ('tests', 'suites', 'pass', 'fail', 'cancelled', 'skipped', 'todo'):
        found = re.findall(rf'^# {field} (\d+)$', output, re.M)
        if len(found) != 1 or int(found[0]) > 10000:
            return None
        result[field] = int(found[0])
    duration = re.findall(r'^# duration_ms ([0-9]+(?:\.[0-9]+)?)$', output, re.M)
    if len(duration) != 1 or not math.isfinite(float(duration[0])):
        return None
    result['duration_ms'] = float(duration[0])
    return result


class Harness(base.Harness):
    def __init__(self):
        base.REPORT = REPORT
        self.frozen = None
        super().__init__()
        self.report.update(command='python3 scripts/runtime-test-quality-volume-upgrade.py --run-local',
                           profile='fresh-populated-sql029-to030-volume', tests=None)
        self.save()

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
        overrides={p['path']:p['fixture'] for p in predecessor_pins()} if native and self.phase.startswith('pre029-') else {}
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
    passwords = {role: secrets.token_hex(24) for role in ('postgres', base.base.OWNER, 'gc_app')}
    h.private_values = list(passwords.values())
    url = lambda role: f'postgresql://{role}:{passwords[role]}@127.0.0.1:5432/{base.base.DATABASE}'
    h.secret_path.write_text(json.dumps({'owner': url(base.base.OWNER), 'legacy': url('gc_app')}))
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
    statement = 'ALTER ROLE postgres PASSWORD ' + base.literal(passwords['postgres']) + ';'
    for role in (base.base.OWNER, 'gc_app'):
        statement += f'CREATE ROLE {role} LOGIN PASSWORD {base.literal(passwords[role])} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;'
    h.sql(statement + f'CREATE DATABASE {base.base.DATABASE} OWNER {base.base.OWNER};', database='postgres')
    h.sql(f'REVOKE ALL ON DATABASE {base.base.DATABASE} FROM PUBLIC;GRANT CONNECT ON DATABASE {base.base.DATABASE} TO {base.base.OWNER},gc_app;REVOKE CREATE ON SCHEMA public FROM PUBLIC;ALTER SCHEMA public OWNER TO {base.base.OWNER};')
    names = migrations()
    roles = base.base.module(ROOT / 'scripts/authentication_roles.py', 'freshness_qualification_roles')
    for count in (11, 12, 13, 29):
        folder = h.folder / ('migrations-' + str(count))
        folder.mkdir()
        for name in names[:count]:
            shutil.copyfile(ROOT / 'packages/db/migrations' / name, folder / name)
        h.phase = 'schema-' + str(count)
        if count in (12, 13):
            try:
                h.sql(roles.prepare_sql(base.base.OWNER, base.base.DATABASE))
                h.migrate(folder)
            finally:
                h.sql(roles.finish_sql(base.base.OWNER))
        else:
            h.migrate(folder)
    expected = [{'name': name, 'checksum': sha((ROOT / 'packages/db/migrations' / name).read_bytes())} for name in names[:29]]
    observed = json.loads(h.sql("SELECT json_agg(json_build_object('name',name,'checksum',checksum) ORDER BY name) FROM public.schema_migrations;"))
    require(observed == expected, 'Actual migration ledger differs')
    h.report['predecessorMigrations'] = observed


def readback(h):
    probe = ("const fs=require('node:fs'),c=require('node:crypto'),sha=p=>c.createHash('sha256').update(fs.readFileSync(p)).digest('hex');"
             "console.log(JSON.stringify({sources:" + json.dumps([r['path'] for r in h.frozen]) + ".map(path=>({path,sha256:sha(path)})),node:{version:process.version,sha256:sha(process.execPath)},tsx:{version:require('tsx/package.json').version,entrySha256:sha(require.resolve('tsx'))},configSha256:sha('/run/authn-config.json')}));")
    observed = json.loads(h.helper(['node', '-e', probe], sensitive=True).stdout)
    require(set(observed) == {'sources', 'node', 'tsx', 'configSha256'} and observed['sources'] == effective_sources(h.frozen,h.phase), 'Actual mounted quality source bytes differ')
    require(observed['configSha256'] == h.report['privateConfigSha256'], 'Actual private configuration differs')
    require(re.fullmatch(r'v24\.[0-9]+\.[0-9]+', observed['node']['version']) is not None and all(re.fullmatch(r'[a-f0-9]{64}', x) for x in (observed['node']['sha256'], observed['tsx']['entrySha256'])), 'Pinned native Node24/tool readback invalid')
    return observed


def declared_tests(path, expected):
    source = source_file(ROOT / path).read_text()
    names = re.findall(r"^test\('([^'\\\n]+)'\s*,", source, re.M)
    require(len(names) == expected and len(set(names)) == expected
            and len(re.findall(r'^test\(', source, re.M)) == expected,
            'Mandatory static native case inventory differs')
    return names


def native_suite(h, phase, path, expected):
    h.phase = phase
    names = declared_tests(path, expected)
    record = {'phase': phase, 'path': path, 'expected': expected, 'testNames': names,
              'tests': None, 'exitStatus': None, 'result': 'RUNNING'}
    h.report.setdefault('nativeSuites', []).append(record)
    h.report.update(tests=None, testExitStatus=None)
    before = readback(h)
    record['mountedSourceBefore'] = before
    tested = h.helper(['node', '--import', 'tsx', '--test', '--test-reporter=tap', '--test-concurrency=1', path], timeout=180, allow_failure=True)
    actual = totals(tested.stdout)
    record.update(tests=actual, exitStatus=tested.returncode, result='FAIL')
    h.report.update(tests=actual, testExitStatus=tested.returncode)
    record['mountedSourceAfter'] = readback(h)
    require(before == record['mountedSourceAfter'] and sources() == h.frozen, 'Source/tool/config changed during native suite')
    require(tested.returncode == 0 and actual is not None and actual['suites'] == 0,
            'Native suite failed; inspect retained private TAP')
    base.base.tap_summary(tested.stdout, expected)
    observed = re.findall(r'^# Subtest: (.+)$', tested.stdout, re.M)
    outcomes = re.findall(r'^ok [0-9]+ - (.+)$', tested.stdout, re.M)
    require(observed == names and outcomes == names, 'Native case identity or ordering differs')
    record.update(result='PASS', sourceHashesMatched=True)
    h.save()


def canonical_tables(h):
    # Discover every ordinary table in all three application namespaces. No
    # fixed current count or manually curated table subset can hide new data.
    value = json.loads(h.sql("SELECT json_agg(n.nspname||'.'||c.relname ORDER BY n.nspname,c.relname) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='r' AND n.nspname IN('public','gc_authn','gc_authority') AND c.relname<>'schema_migrations';"))
    require(type(value) is list and 1 <= len(value) <= 512 and len(set(value)) == len(value)
            and all(type(x) is str and re.fullmatch(r'(?:public|gc_authn|gc_authority)\.[a-z_]+', x) for x in value), 'Invalid complete canonical table inventory')
    return value


def canonical_snapshot(h, tables):
    # Hash every complete row first, then aggregate only fixed32byte digests.
    # Repeated equal rows stay repeated; comparison is exact multiset+count.
    require(type(tables) is list and 1 <= len(tables) <= 512
            and len(set(tables)) == len(tables), 'Invalid canonical table inventory')
    result = {}
    for table in tables:
        require(re.fullmatch(r'(?:public|gc_authn|gc_authority)\.[a-z_]+', table), 'Invalid canonical table')
        # The only additive field is absent on029 and NULL on every old row on030.
        # Preserve all original fields; separately prove the new field's shape/data.
        projection="(to_jsonb(r)-'table_asset_id')" if table=='public.quality_rules' else 'to_jsonb(r)'
        row = json.loads(h.sql(f"""WITH row_hashes AS MATERIALIZED (
          SELECT sha256(convert_to({projection}::text,'UTF8')) AS value FROM {table} r
        ) SELECT jsonb_build_object('rows',count(*),'sha256',encode(sha256(
          coalesce(string_agg(value,''::bytea ORDER BY value),''::bytea)),'hex')) FROM row_hashes;"""))
        require(type(row) is dict and set(row) == {'rows', 'sha256'} and type(row['rows']) is int
                and row['rows'] >= 0 and re.fullmatch(r'[a-f0-9]{64}', row['sha256']), 'Invalid canonical digest')
        result[table] = row
    return result


def ledger(h, count):
    rows = json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM public.schema_migrations m;'))
    require(type(rows) is list and len(rows) == count and [r['name'] for r in rows] == NAMES[:count], 'Exact migration ledger differs')
    require(all(r['checksum'] == sha((ROOT / 'packages/db/migrations' / r['name']).read_bytes()) for r in rows), 'Migration checksum differs')
    return rows



def legacy_target_column(h, added):
    shape=h.sql("SELECT count(*) FROM pg_attribute WHERE attrelid='public.quality_rules'::regclass AND attname='table_asset_id' AND NOT attisdropped;")
    require(shape==('1' if added else '0'), 'Expected exact additive table target column')
    if added:
        require(h.sql('SELECT count(*) FROM public.quality_rules WHERE table_asset_id IS NOT NULL;')=='0', 'Legacy rules acquired table targets')


def upgrade(h):
    h.phase = 'pre029-canonical-snapshot'
    tables = canonical_tables(h)
    before = canonical_snapshot(h, tables)
    populated = ['quality_rules', 'quality_rule_versions', 'quality_runs', 'quality_rule_reference_bindings',
                 'quality_run_reference_bindings', 'reference_releases', 'audit', 'outbox', 'idempotency', 'quality_monitors', 'quality_monitor_versions', 'quality_monitor_schedule_segments', 'quality_monitor_occurrences', 'quality_monitor_incidents', 'quality_monitor_incident_events', 'quality_monitor_projection_receipts', 'quality_monitor_notifications']
    require(all(before.get('public.' + table, {}).get('rows', 0) > 0 for table in populated), 'Populated predecessor rows required')
    measured = json.loads(h.sql("SELECT json_object_agg(kind,n) FROM(SELECT measurement->>'kind' kind,count(*) n FROM quality_runs WHERE status='succeeded' GROUP BY measurement->>'kind') q;"))
    require(type(measured) is dict and set(measured) == {'completeness', 'reference-allowed-values', 'uniqueness', 'range', 'freshness'}
            and all(type(count) is int and count > 0 for count in measured.values()), 'Actual old-family successful measurements required')
    previous = ledger(h, 29)
    legacy_target_column(h, False)
    target = h.folder / 'migrations-30'
    target.mkdir()
    for name in migrations():
        shutil.copyfile(ROOT / 'packages/db/migrations' / name, target / name)
    h.phase = 'schema-30-upgrade'
    migrated = h.migrate(target)
    require(re.findall(r'^Applied (.+)$', migrated.stdout, re.M) == [MIGRATION], 'Expected exact SQL030 application')
    after_tables = canonical_tables(h)
    require(after_tables == tables, 'Volume upgrade changed canonical table inventory')
    require(canonical_snapshot(h, tables) == before, 'Volume upgrade changed predecessor rows')
    legacy_target_column(h, True)
    after = ledger(h, 30)
    require(after[:29] == previous, 'Volume upgrade changed predecessor ledger')
    h.phase = 'schema-30-replay'
    require('Applied' not in h.migrate(target).stdout, 'Volume replay reapplied migration')
    require(canonical_tables(h) == tables and canonical_snapshot(h, tables) == before and ledger(h, 30) == after, 'Volume replay changed any rows or ledger')
    legacy_target_column(h, True)
    h.report['oldRowProjection']={'public.quality_rules':'all original fields; added table_asset_id absent before and NULL on all retained rows after upgrade/replay'}
    h.report.update(upgradeBaseline=[{'table': key, **row} for key, row in before.items()],
                    newTables=[], predecessorMeasurementCounts=measured, predecessorLedger=previous, migrations=after,
                    upgradePreservation=True, replayPreservation=True)
    h.report['checks'].append('Populated SQL029→030 and inert replay preserve all canonical rows and full prior ledger')
    h.save()


def execute(h):
    h.frozen = sources()
    h.report.update(sources=h.frozen, commit=h.command(['git', 'rev-parse', 'HEAD'], sensitive=True).stdout.strip(),
        predecessorModulePins=predecessor_pins(),
        limitations=['Fresh SQL001–029 with all149 current predecessor native cases; historical CI upgrade gates remain separately mandatory.',
                     'SQL030 reruns the same149 cases plus volume18 and hostile4; explicit completion fixtures do not qualify Python, HTTP, Temporal or browser execution.',
                     'Pre030 alone mounts exactly two immutable SQL029 modules. Other dependencies remain current and measured. Post030 runs current candidate modules.',
                     'Cached dependencies admitted by exact lock/metadata; mounted effective sources checked at every native startup/exit and read back before/after.'])
    setup(h)
    for family, (path, count) in zip(FAMILIES, LEGACY, strict=True):
        native_suite(h, 'pre029-' + family + '-tests', path, count)
    upgrade(h)
    for family, (path, count) in zip(FAMILIES, LEGACY, strict=True):
        native_suite(h, 'post030-' + family + '-tests', path, count)
    for phase, (path, count) in zip(('post030-volume-tests', 'post030-volume-invariants-tests'), TESTS, strict=True):
        native_suite(h, phase, path, count)
    require(sources() == h.frozen and [r['phase'] for r in h.report['nativeSuites']] == list(PHASES)
            and all(r['result'] == 'PASS' for r in h.report['nativeSuites']), 'Mandatory native phases incomplete')
    h.report['sourceHashesMatched'] = True
    h.report['checks'].append('Exact149 legacy cases before/after and volume18+hostile4 passed without skipped, retried or substituted cases')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-local', action='store_true')
    args = parser.parse_args()
    require(args.run_local, 'Explicit --run-local required; importing this module never executes runtime')
    h = Harness()
    failed = False
    try:
        execute(h)
    except BaseException as error:
        failed = True
        h.report.update(failed_phase=h.phase, error_type=type(error).__name__, error='Inspect retained private bounded diagnostic; no driver details exported')
    finally:
        try:
            h.phase = 'cleanup'
            h.cleanup()
            if h.resources_before is not None:
                h.deadline = h.cleanup_deadline
                after = h.inventory()
                (h.folder / 'resources-after.json').write_text(json.dumps(after, sort_keys=True) + '\n')
                require(after == h.resources_before, 'Preexisting resource inventory changed')
                h.report['cleanup']['resourceInventoryPreserved'] = True
                h.report['privateResourceInventories'] = {name: {'path': str((h.folder / ('resources-' + name + '.json')).relative_to(ROOT)), 'sha256': sha((h.folder / ('resources-' + name + '.json')).read_bytes())} for name in ('before', 'after')}
        except BaseException as error:
            failed = True
            h.report['cleanupErrorType'] = type(error).__name__
        finally:
            # Docker cleanup can fail before the inherited credential removal.
            # Always remove this run's private file without claiming resources
            # were cleaned up when the Docker work failed.
            try:
                h.secret_path.unlink(missing_ok=True)
                removed = not h.secret_path.exists()
                h.report.setdefault('cleanup', {})['generatedCredentialsRemoved'] = removed
                require(removed, 'Generated credential cleanup incomplete')
            except BaseException as error:
                failed = True
                h.report.setdefault('cleanup', {})['generatedCredentialsRemoved'] = False
                h.report['credentialCleanupErrorType'] = type(error).__name__
        h.report.update(result='FAIL' if failed else 'PASS', recorded_at=datetime.now(timezone.utc).isoformat(), evidence_directory=str(h.folder.relative_to(ROOT)))
        h.report['private_logs'] = [{'path': str(p.relative_to(ROOT)), 'sha256': sha(p.read_bytes())} for p in sorted(h.folder.glob('*.log'))]
        h.save(final=True)
    print(json.dumps({'result': h.report['result'], 'report': str(REPORT.relative_to(ROOT))}))
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
