#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Qualify initialized local core seed replay and synthetic membership revocation.

Run only in the root-coordinated exclusive core slot, after all current migrations
(at least SQL001–012) and the first
harbor-demo seed. This is not a clean-install, restore or general authz test. It
runs the real developer seed command twice unchanged, then once with two known
synthetic memberships temporarily changed. It never builds, migrates explicitly,
restarts services, removes volumes or asks for credentials. The real seed command
retains its existing Compose dependency behavior; matching applied migration and
image checks are prerequisites. Exact restoration is mandatory even after failure.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import uuid

from runtime import COMPOSE, ROOT, require_bootstrap, require_local

LOCAL = ROOT / '.local/evidence'
REPORT = LOCAL / 'business-domain-seed.json'
HARBOR = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
SUMMIT = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
STEWARD = '10000000-0000-4000-8000-000000000001'
CONSUMER = '10000000-0000-4000-8000-000000000003'
ENGINEER = '10000000-0000-4000-8000-000000000006'
REVOKED = 'domains:write'
QUALITY_REVOKED = 'quality:execute'
CLASSIFICATION_REVOKED = 'classification:approve'
REFERENCE_REVOKED = 'reference:approve'
REFERENCE_TABLES = ('reference_sets', 'reference_releases', 'reference_values')
QUALITY_TABLES = ('quality_rules', 'quality_rule_versions', 'quality_runs')
# Independent historical marker inputs: do not derive these from the new seed
# implementation, which could otherwise change both the writer and its oracle.
PERSONA_GRANTS = (
    ('steward', HARBOR, ('domains:read', 'domains:write', 'domains:assign')),
    ('owner', HARBOR, ('domains:read', 'domains:write', 'domains:assign')),
    ('consumer', HARBOR, ()), ('auditor', HARBOR, ('domains:read',)),
    ('summit', SUMMIT, ('domains:read', 'domains:write', 'domains:assign')),
    ('engineer', HARBOR, ('domains:read', 'domains:write', 'domains:assign')),
)
TABLES = (
    'domain_types', 'domain_type_versions', 'domain_type_dependencies', 'domains',
    'domain_revisions', 'asset_domain_placements', 'asset_domain_placement_revisions',
    'domain_type_migrations', 'domain_type_migration_domains', 'domain_scope_state',
    'domain_transaction_bindings', 'domain_operation_contexts', 'domain_migration_operations',
    'domain_operation_type_claims', 'domain_operation_domain_claims',
    'domain_operation_placement_claims', 'domain_operation_journal_claims',
    'domain_operation_scope_members', 'domain_operation_policies',
)
OPERATIONS = ('domain-type.create', 'domain-type.publish', 'domain.create', 'domain.update',
              'domain.state', 'domain.hierarchy', 'domain.placement', 'domain-type-migration.execute')
ACTIONS = ('domain.', 'domain_type.', 'asset_domain_placement.', 'domain_type_migration.')
RUNNING_SERVICES = ('api', 'workflow-worker', 'site-runner')
MAX_OUTPUT = 1024 * 1024


def now():
    return datetime.now(timezone.utc).isoformat()


def require(value, message):
    if not value:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def expected_permission_markers():
    result = {}
    for index, (role, tenant, domain_grants) in enumerate(PERSONA_GRANTS, 1):
        identity = '10000000-0000-4000-8000-' + str(index).zfill(12)
        quality_grants = ['quality:read'] if role in ('consumer', 'auditor') else ['quality:read', 'quality:write', 'quality:execute']
        classification_grants = ([] if role == 'consumer' else ['classification:read'] if role == 'auditor'
                                 else ['classification:read', 'classification:write', 'classification:approve'])
        reference_grants = (['reference:read'] if role in ('consumer', 'auditor')
                            else ['reference:read', 'reference:write', 'reference:approve'])
        for operation, grants in (('bootstrap.domain-permissions.v1', list(domain_grants)),
                                  ('bootstrap.quality-permissions.v1', quality_grants),
                                  ('bootstrap.classification-permissions.v1', classification_grants),
                                  ('bootstrap.reference-permissions.v1', reference_grants)):
            if grants:
                body = {'dataset': 'harbor-demo', 'identityId': identity, 'role': role, 'permissions': grants}
                result[(tenant, identity, operation)] = digest(json.dumps(body, sort_keys=True, separators=(',', ':')).encode())
    return result


def revoked_engineer(engineer):
    require(isinstance(engineer.get('permissions'), list)
            and all(permission in engineer['permissions'] for permission in (REVOKED, QUALITY_REVOKED, CLASSIFICATION_REVOKED, REFERENCE_REVOKED)),
            'Engineer must initially hold all four exact permissions being tested')
    return {**engineer, 'permissions': [permission for permission in engineer['permissions']
                                      if permission not in (REVOKED, QUALITY_REVOKED, CLASSIFICATION_REVOKED, REFERENCE_REVOKED)]}


def verify_classification_permissions(rows):
    """Validate the same six read-back personas; never repair their authority."""
    require(isinstance(rows, list) and len(rows) == len(PERSONA_GRANTS),
            'All six seeded classification memberships are required')
    for index, ((role, tenant, _), row) in enumerate(zip(PERSONA_GRANTS, rows), 1):
        grants = (set() if role == 'consumer' else {'classification:read'} if role == 'auditor'
                  else {'classification:read', 'classification:write', 'classification:approve'})
        require(isinstance(row, dict) and set(row) == {'identity_id', 'tenant_id', 'role', 'active', 'permissions'}
                and row['identity_id'] == '10000000-0000-4000-8000-' + str(index).zfill(12)
                and row['tenant_id'] == tenant and row['role'] == role and row['active'] is True
                and isinstance(row['permissions'], list) and all(isinstance(value, str) for value in row['permissions'])
                and len([value for value in row['permissions'] if value.startswith('classification:')]) == len(grants)
                and {value for value in row['permissions'] if value.startswith('classification:')} == grants,
                'Seeded classification authority is missing, revoked or wider than the declared persona baseline')
    return rows


def verify_reference_permissions(rows):
    """Validate the same six read-back personas; never repair their authority."""
    require(isinstance(rows, list) and len(rows) == len(PERSONA_GRANTS),
            'All six seeded reference memberships are required')
    for index, ((role, tenant, _), row) in enumerate(zip(PERSONA_GRANTS, rows), 1):
        grants = ({'reference:read'} if role in ('consumer', 'auditor')
                  else {'reference:read', 'reference:write', 'reference:approve'})
        require(isinstance(row, dict) and set(row) == {'identity_id', 'tenant_id', 'role', 'active', 'permissions'}
                and row['identity_id'] == '10000000-0000-4000-8000-' + str(index).zfill(12)
                and row['tenant_id'] == tenant and row['role'] == role and row['active'] is True
                and isinstance(row['permissions'], list) and all(isinstance(value, str) for value in row['permissions'])
                and len([value for value in row['permissions'] if value.startswith('reference:')]) == len(grants)
                and {value for value in row['permissions'] if value.startswith('reference:')} == grants,
                'Seeded reference authority is missing, revoked or wider than the declared persona baseline')
    return rows


def migration_inventory(directory):
    """Bind every present migration; later migrations cannot be silently omitted."""
    paths = sorted(directory.glob('*.sql'))
    require(len(paths) >= 12, 'Current-schema seed gate requires at least SQL001–012')
    require(all(re.fullmatch(rf'{index:03d}_[a-z0-9_]+\.sql', path.name)
                for index, path in enumerate(paths, 1)),
            'Current migration filenames must form an exact contiguous sequence')
    require(paths[11].name == '012_authentication_foundation.sql',
            'Current-schema seed gate requires the authentication foundation')
    return [{'name': path.name, 'checksum': digest(path.read_bytes())} for path in paths]


def verify_applied_migrations(applied, expected):
    require(applied == expected,
            'Running core schema does not exactly match current migration filenames/checksums; harness never applies migrations')


def json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def json_sql(value):
    return literal(json.dumps(value, separators=(',', ':'))) + '::jsonb'


def action_predicate(column):
    return '(' + ' OR '.join(column + ' LIKE ' + literal(prefix.replace('_', r'\_') + '%') + " ESCAPE '\\'" for prefix in ACTIONS) + ')'


def source_hashes():
    paths = {ROOT / 'package.json', ROOT / 'pnpm-lock.yaml', ROOT / 'pnpm-workspace.yaml'}
    for folder in ('packages/db/src', 'packages/domain/src', 'packages/authz/src', 'apps/api/src'):
        paths.update((ROOT / folder).rglob('*.ts'))
    paths.update((ROOT / 'packages/db/migrations').glob('*.sql'))
    return [{'path': str(p.relative_to(ROOT)), 'sha256': digest(p.read_bytes())} for p in sorted(paths)]


def host_hashes():
    return [{'path': str(p.relative_to(ROOT)), 'sha256': digest(p.read_bytes())} for p in (
        Path(__file__).resolve(), ROOT / 'scripts/test_business_domain_seed.py', ROOT / 'dev', ROOT / 'scripts/runtime.py',
        ROOT / 'deploy/compose/compose.yaml', ROOT / 'Dockerfile')]


class Harness:
    def __init__(self, attempt):
        self.attempt = attempt
        self.log = attempt / 'command-summary.jsonl'
        self.commands = []
        self.seed_context = None

    def command(self, args, label, *, stdin=None, timeout=45):
        # Never log SQL, fixture JSON, environment values or arbitrary process
        # output. Hash bounded stdout/stderr; safe diagnostics name only stages.
        started = time.monotonic()
        status, timed_out, interrupted = None, False, None
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            process = subprocess.Popen(args, cwd=ROOT, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                process.communicate(input=stdin.encode() if stdin is not None else None, timeout=timeout)
                status = process.returncode
            except BaseException as error:
                timed_out = isinstance(error, subprocess.TimeoutExpired)
                interrupted = None if timed_out else error
                # Kill only this command's newly created process group. A one-shot
                # Docker container has its own lifecycle; real_seed handles it.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=10)
                status = process.returncode
            metadata = {'stage': label, 'exit_status': status, 'timed_out': timed_out,
                        'duration_ms': round((time.monotonic() - started) * 1000, 3)}
            values = []
            for name, stream in (('stdout', stdout), ('stderr', stderr)):
                size = stream.tell()
                stream.seek(0)
                hasher = hashlib.sha256()
                while chunk := stream.read(65536):
                    hasher.update(chunk)
                metadata[name] = {'bytes': size, 'sha256': hasher.hexdigest()}
                stream.seek(0)
                values.append(stream.read(MAX_OUTPUT + 1))
            self.commands.append(metadata)
            fd = os.open(self.log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, 'a') as stream:
                stream.write(json.dumps(metadata, sort_keys=True) + '\n')
            if interrupted is not None:
                raise interrupted
            require(not timed_out, label + ': command timeout; output hashes retained')
            require(status == 0, label + ': command failed; output hashes retained')
            require(all(len(v) <= MAX_OUTPUT for v in values), label + ': bounded output exceeded')
            return values[0].decode('utf-8').strip()

    def seed_containers(self):
        values = self.command(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=governance-commons',
                               '--filter', 'label=com.docker.compose.service=seed'], 'identify-seed-containers').splitlines()
        require(all(re.fullmatch('[a-f0-9]{12,64}', value) for value in values), 'Unexpected seed container identifier')
        return set(values)

    def cleanup_seed(self):
        if self.seed_context is None:
            return
        before, image = self.seed_context
        # No unrelated container is stopped: this exact exclusive call must
        # have created it, and its project/service/one-off labels, generated
        # name and exact seed image must all match before cleanup.
        for identifier in sorted(self.seed_containers() - before):
            fields = self.command(['docker', 'inspect', '--format',
                '{{.Image}}|{{.Name}}|{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.service"}}|{{index .Config.Labels "com.docker.compose.oneoff"}}', identifier], 'owned-seed-cleanup-check').split('|')
            require(len(fields) == 5 and fields[0] == image and fields[1].startswith('/governance-commons-seed-run-')
                    and fields[2:4] == ['governance-commons', 'seed'] and fields[4].lower() == 'true',
                    'Unrecognized seed container; stop qualification and inspect before fixture restoration')
            self.command(['docker', 'stop', '--time', '10', identifier], 'stop-only-owned-one-shot-seed', timeout=25)
        # Give daemon-side auto-removal its own bounded completion window.
        deadline = time.monotonic() + 10
        stable = 0
        while stable < 3:
            remaining = self.seed_containers() - before
            require(time.monotonic() < deadline, 'Owned seed container remains; restoration requires an idle seed')
            if remaining:
                raise RuntimeError('Owned seed cleanup has not completed; retry before restoration')
            stable += 1
            time.sleep(0.25)
        self.seed_context = None

    def real_seed(self, label, image):
        before = self.seed_containers()
        # The qualification requires exclusive seed ownership. Preserve stopped
        # predecessor containers; any running seed is a prerequisite failure.
        for identifier in sorted(before):
            running = self.command(['docker', 'inspect', '--format', '{{.State.Running}}', identifier], 'existing-seed-state')
            require(running == 'false', 'Another seed invocation is already running')
        self.seed_context = (before, image)
        failure = None
        try:
            self.command([str(ROOT / 'dev'), 'seed', '--dataset', 'harbor-demo'], label, timeout=150)
        except BaseException as error:
            failure = error
        finally:
            self.cleanup_seed()
        if failure is not None:
            raise failure

    def query(self, body, label, *, timeout=45):
        return self.command(COMPOSE + ['exec', '-T', 'postgres', 'psql', '-X', '-qAt', '-U', 'postgres',
                                       '-d', 'governance', '-v', 'ON_ERROR_STOP=1'], label,
                            stdin="SET statement_timeout='30s'; SET lock_timeout='5s'; SET TIME ZONE 'UTC';\n" + body,
                            timeout=timeout)

    def service_images(self):
        result = {}
        for service in RUNNING_SERVICES:
            identifier = self.command(COMPOSE + ['ps', '-q', service], 'identify-' + service)
            require(bool(re.fullmatch('[a-f0-9]{12,64}', identifier)), 'Expected one running ' + service + ' container')
            value = self.command(['docker', 'inspect', '--format', '{{.Image}} {{.State.Running}}', identifier], 'image-' + service)
            image, running = value.split()
            require(running == 'true' and bool(re.fullmatch(r'sha256:[a-f0-9]{64}', image)), service + ' is not running a qualified image')
            result[service] = {'container_id': identifier, 'image': image}
        result['seed'] = self.command(['docker', 'image', 'inspect', '--format', '{{.Id}}', 'governance-commons:dev'], 'seed-image')
        require(all(result[s]['image'] == result['seed'] for s in RUNNING_SERVICES), 'Seed and running services do not share the same image')
        return result

    def image_sources(self, identifier, sources):
        script = "import {readFile} from 'node:fs/promises'; import {createHash} from 'node:crypto';\n"
        script += 'const paths=' + json.dumps([v['path'] for v in sources]) + ';\n'
        script += "const rows=[];for(const path of paths)rows.push({path,sha256:createHash('sha256').update(await readFile('/app/'+path)).digest('hex')});console.log(JSON.stringify({node:process.version,sources:rows}));"
        result = json.loads(self.command(['docker', 'exec', '-i', identifier, 'node', '--input-type=module', '-'], 'running-image-source-readback', stdin=script))
        require(result['sources'] == sources, 'Current seed/service sources differ from the running image')
        return result

    def snapshot(self):
        selected = ["tenant_id IN ('" + HARBOR + "','" + SUMMIT + "')"]
        tables = [(name, selected[0] + (" AND kind='domain'" if name == 'domain_transaction_bindings' else '')) for name in TABLES]
        tables += [('audit', selected[0] + ' AND ' + action_predicate('action')),
                   ('outbox', selected[0] + ' AND ' + action_predicate('event_type')),
                   ('idempotency', selected[0] + ' AND (operation IN (' + ','.join(map(literal, OPERATIONS)) + ") OR operation='bootstrap.domain-permissions.v1')")]
        values = []
        for table, predicate in tables:
            # Hash every serialized column, including outbox delivery metadata.
            # Sorted fixed-length row digests retain duplicates and avoid retaining
            # all private canonical/revision/claim payloads in a Python report.
            values.append(literal(table) + ", (SELECT jsonb_build_object('rows',count(*),'serialized_bytes',coalesce(sum(octet_length(payload)),0),"
                          "'sha256',CASE WHEN count(*)<=20000 AND coalesce(sum(octet_length(payload)),0)<=67108864 THEN "
                          "encode(sha256(convert_to(coalesce(string_agg(encode(sha256(convert_to(payload,'UTF8')),'hex'),'' ORDER BY "
                          "encode(sha256(convert_to(payload,'UTF8')),'hex')),''),'UTF8')),'hex') ELSE NULL END) "
                          'FROM (SELECT to_jsonb(r)::text payload FROM public.' + table + ' r WHERE ' + predicate + ') s)')
        result = json.loads(self.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SELECT jsonb_build_object(' + ','.join(values) + '); COMMIT;', 'domain-row-digests'))
        require(all(v['sha256'] is not None for v in result.values()), 'Domain digest profile exceeded its bounded snapshot size')
        return result

    def glossary_definition_snapshot(self):
        # These six definition families are separate from the historical domain
        # snapshot. Existing operator revisions are preserved, never reset to v1.
        tenant = "tenant_id IN ('" + HARBOR + "','" + SUMMIT + "')"
        families = (
            ('governance_models', 'id'), ('governance_model_versions', 'model_id'),
            ('asset_type_versions', 'model_id'), ('asset_type_dependencies', 'model_id'),
            ('workflow_definitions', 'id'), ('workflow_definition_versions', 'workflow_id'),
        )
        values = []
        for table, key in families:
            identifier = 'glossary_review' if table.startswith('workflow_') else 'business_term'
            values.append(literal(table) + ", (SELECT jsonb_build_object('rows',count(*),'serialized_bytes',coalesce(sum(octet_length(payload)),0),"
                          "'sha256',CASE WHEN count(*)<=20000 AND coalesce(sum(octet_length(payload)),0)<=67108864 THEN "
                          "encode(sha256(convert_to(coalesce(string_agg(encode(sha256(convert_to(payload,'UTF8')),'hex'),'' ORDER BY "
                          "encode(sha256(convert_to(payload,'UTF8')),'hex')),''),'UTF8')),'hex') ELSE NULL END) "
                          'FROM (SELECT to_jsonb(r)::text payload FROM public.' + table + ' r WHERE ' + tenant
                          + ' AND ' + key + '=' + literal(identifier) + ') s)')
        result = json.loads(self.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SELECT jsonb_build_object('
                                     + ','.join(values) + '); COMMIT;', 'glossary-definition-row-digests'))
        require(isinstance(result, dict) and set(result) == {table for table, _ in families}
                and all(isinstance(row, dict) and set(row) == {'rows', 'serialized_bytes', 'sha256'}
                        and type(row['rows']) is int and 0 <= row['rows'] <= 20000
                        and type(row['serialized_bytes']) is int and 0 <= row['serialized_bytes'] <= 67108864
                        and isinstance(row['sha256'], str) and re.fullmatch('[a-f0-9]{64}', row['sha256'])
                        for row in result.values()),
                'Glossary definition digest profile exceeded its bounded snapshot size or shape')
        require(result['governance_models']['rows'] == 2 and result['workflow_definitions']['rows'] == 2
                and all(result[table]['rows'] >= 2 for table in
                        ('governance_model_versions', 'asset_type_versions', 'workflow_definition_versions')),
                'Initial business_term and glossary_review definitions in both synthetic tenants are required')
        return result

    def memberships(self):
        return json.loads(self.query("BEGIN READ ONLY; SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY identity_id),'[]') FROM memberships m WHERE tenant_id="
                                     + literal(HARBOR) + ' AND identity_id IN (' + literal(CONSUMER) + ',' + literal(ENGINEER) + '); COMMIT;', 'synthetic-membership-readback'))

    def permission_markers(self):
        expected = expected_permission_markers()
        # LIMIT detects an extra receipt without materializing an unbounded set.
        # Retain the entire row, including creation time, for replay equality.
        result = json.loads(self.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY tenant_id,actor_id,operation),'[]') FROM ("
            "SELECT * FROM public.idempotency WHERE tenant_id IN (" + literal(HARBOR) + ',' + literal(SUMMIT)
            + ") AND operation IN ('bootstrap.domain-permissions.v1','bootstrap.quality-permissions.v1','bootstrap.classification-permissions.v1','bootstrap.reference-permissions.v1')"
            " AND key='harbor-demo' ORDER BY tenant_id,actor_id,operation LIMIT 23) r; COMMIT;", 'permission-marker-readback'))
        require(isinstance(result, list) and len(result) == len(expected), 'Initial domain, quality, classification and reference permission markers are incomplete or unexpected')
        seen = set()
        for row in result:
            require(isinstance(row, dict) and set(row) == {'tenant_id', 'actor_id', 'operation', 'key', 'request_hash', 'response', 'created_at'},
                    'Permission marker row shape is invalid')
            require(all(isinstance(row[key], str) for key in ('tenant_id', 'actor_id', 'operation', 'key', 'request_hash', 'created_at')),
                    'Permission marker scalar shape is invalid')
            key = (row['tenant_id'], row['actor_id'], row['operation'])
            response = row['response']
            require(key in expected and key not in seen and row['key'] == 'harbor-demo' and row['request_hash'] == expected[key]
                    and isinstance(response, dict) and set(response) == {'dataset', 'version', 'applied'}
                    and response['dataset'] == 'harbor-demo' and type(response['version']) is int and response['version'] == 1
                    and type(response['applied']) is bool and bool(row['created_at']),
                    'Permission marker differs from the independent declared domain/quality/classification/reference upgrade')
            seen.add(key)
        return result

    def quality_permissions(self):
        # A baseline prerequisite only. Qualification never repairs missing or
        # revoked authority to make its own fixture pass.
        scope = ' OR '.join('(tenant_id=' + literal(tenant) + ' AND identity_id='
                            + literal('10000000-0000-4000-8000-' + str(index).zfill(12)) + ')'
                            for index, (_, tenant, _) in enumerate(PERSONA_GRANTS, 1))
        rows = json.loads(self.query("BEGIN READ ONLY; SELECT coalesce(jsonb_agg(jsonb_build_object('identity_id',identity_id,'tenant_id',tenant_id,"
            "'role',role,'active',active,'permissions',permissions) ORDER BY identity_id),'[]') FROM public.memberships WHERE "
            + scope + '; COMMIT;', 'initial-quality-permissions'))
        require(isinstance(rows, list) and len(rows) == len(PERSONA_GRANTS), 'All six seeded quality memberships are required')
        for index, ((role, tenant, _), row) in enumerate(zip(PERSONA_GRANTS, rows), 1):
            grants = {'quality:read'} if role in ('consumer', 'auditor') else {'quality:read', 'quality:write', 'quality:execute'}
            require(isinstance(row, dict) and set(row) == {'identity_id', 'tenant_id', 'role', 'active', 'permissions'}
                    and row['identity_id'] == '10000000-0000-4000-8000-' + str(index).zfill(12)
                    and row['tenant_id'] == tenant and row['role'] == role and row['active'] is True
                    and isinstance(row['permissions'], list) and all(isinstance(value, str) for value in row['permissions'])
                    and len([value for value in row['permissions'] if value.startswith('quality:')]) == len(grants)
                    and {value for value in row['permissions'] if value.startswith('quality:')} == grants,
                    'Seeded quality authority is missing, revoked or wider than the declared persona baseline')
        return rows

    def quality_snapshot(self):
        # Separate from the immutable historical domain/glossary snapshot shapes.
        # Empty quality data is valid: seed creates no rules, runs or fake results.
        tenant = "tenant_id IN ('" + HARBOR + "','" + SUMMIT + "')"
        tables = [(name, tenant) for name in QUALITY_TABLES]
        tables += [('audit', tenant + " AND action LIKE 'quality.%'"),
                   ('outbox', tenant + " AND event_type LIKE 'quality.%'"),
                   ('idempotency', tenant + " AND operation LIKE 'quality.%'")]
        values = []
        for table, predicate in tables:
            values.append(literal(table) + ", (SELECT jsonb_build_object('rows',count(*),'serialized_bytes',coalesce(sum(octet_length(payload)),0),"
                          "'sha256',CASE WHEN count(*)<=20000 AND coalesce(sum(octet_length(payload)),0)<=67108864 THEN "
                          "encode(sha256(convert_to(coalesce(string_agg(encode(sha256(convert_to(payload,'UTF8')),'hex'),'' ORDER BY "
                          "encode(sha256(convert_to(payload,'UTF8')),'hex')),''),'UTF8')),'hex') ELSE NULL END) "
                          'FROM (SELECT to_jsonb(r)::text payload FROM public.' + table + ' r WHERE ' + predicate + ') s)')
        result = json.loads(self.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SELECT jsonb_build_object('
                                     + ','.join(values) + '); COMMIT;', 'quality-row-digests'))
        require(isinstance(result, dict) and set(result) == {table for table, _ in tables}
                and all(isinstance(row, dict) and set(row) == {'rows', 'serialized_bytes', 'sha256'}
                        and type(row['rows']) is int and 0 <= row['rows'] <= 20000
                        and type(row['serialized_bytes']) is int and 0 <= row['serialized_bytes'] <= 67108864
                        and isinstance(row['sha256'], str) and re.fullmatch('[a-f0-9]{64}', row['sha256'])
                        for row in result.values()),
                'Quality digest profile exceeded its bounded snapshot size or shape')
        return result

    def reference_snapshot(self):
        # Separate from the immutable historical domain/glossary snapshot shapes.
        # Empty reference data is valid: seed creates no sets, releases or fake approvals.
        tenant = "tenant_id IN ('" + HARBOR + "','" + SUMMIT + "')"
        tables = [(name, tenant) for name in REFERENCE_TABLES]
        tables += [('audit', tenant + " AND action LIKE 'reference.%'"),
                   ('outbox', tenant + " AND event_type LIKE 'reference.%'"),
                   ('idempotency', tenant + " AND operation LIKE 'reference.%'")]
        values = []
        for table, predicate in tables:
            values.append(literal(table) + ", (SELECT jsonb_build_object('rows',count(*),'serialized_bytes',coalesce(sum(octet_length(payload)),0),"
                          "'sha256',CASE WHEN count(*)<=20000 AND coalesce(sum(octet_length(payload)),0)<=67108864 THEN "
                          "encode(sha256(convert_to(coalesce(string_agg(encode(sha256(convert_to(payload,'UTF8')),'hex'),'' ORDER BY "
                          "encode(sha256(convert_to(payload,'UTF8')),'hex')),''),'UTF8')),'hex') ELSE NULL END) "
                          'FROM (SELECT to_jsonb(r)::text payload FROM public.' + table + ' r WHERE ' + predicate + ') s)')
        result = json.loads(self.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SELECT jsonb_build_object('
                                     + ','.join(values) + '); COMMIT;', 'reference-row-digests'))
        require(isinstance(result, dict) and set(result) == {table for table, _ in tables}
                and all(isinstance(row, dict) and set(row) == {'rows', 'serialized_bytes', 'sha256'}
                        and type(row['rows']) is int and 0 <= row['rows'] <= 20000
                        and type(row['serialized_bytes']) is int and 0 <= row['serialized_bytes'] <= 67108864
                        and isinstance(row['sha256'], str) and re.fullmatch('[a-f0-9]{64}', row['sha256'])
                        for row in result.values()),
                'Reference digest profile exceeded its bounded snapshot size or shape')
        return result

    def all_personas_digest(self):
        # Only synthetic six; no session, source secret or unrelated fixture scan.
        return self.query("SELECT encode(sha256(convert_to(coalesce(jsonb_agg(to_jsonb(m) ORDER BY tenant_id,identity_id),'[]')::text,'UTF8')),'hex') "
                          "FROM memberships m WHERE (tenant_id=" + literal(HARBOR) + " AND identity_id IN ('10000000-0000-4000-8000-000000000001',"
                          + literal(CONSUMER) + ",'10000000-0000-4000-8000-000000000002','10000000-0000-4000-8000-000000000004'," + literal(ENGINEER)
                          + ")) OR (tenant_id=" + literal(SUMMIT) + " AND identity_id='10000000-0000-4000-8000-000000000005')", 'six-persona-membership-digest')

    def locked_fixture_sql(self, statements):
        # Lock all identities in one ordered phase, then memberships. Actor is
        # included; no unrelated membership, domain, session or identity is edited.
        ids = ','.join(map(literal, sorted((STEWARD, CONSUMER, ENGINEER))))
        return "BEGIN; SET LOCAL ROLE gc_owner; SET LOCAL gc.tenant_id=" + literal(HARBOR) + '; SET LOCAL gc.actor_id=' + literal(STEWARD) + ";\nDO $fixture$ BEGIN\n" \
            + 'PERFORM pg_advisory_xact_lock(hashtextextended(' + literal(HARBOR) + ',0));\n' \
            + 'PERFORM id FROM identities WHERE id IN (' + ids + ') ORDER BY id FOR UPDATE;\n' \
            + 'PERFORM identity_id FROM memberships WHERE tenant_id=' + literal(HARBOR) + ' AND identity_id IN (' + ids + ') ORDER BY identity_id FOR UPDATE;\n' \
            + statements + '\nEND $fixture$; COMMIT;'

    def mutate(self, original, revoked):
        original_engineer = next(v for v in original if v['identity_id'] == ENGINEER)
        original_consumer = next(v for v in original if v['identity_id'] == CONSUMER)
        statements = 'IF (SELECT to_jsonb(m) FROM memberships m WHERE tenant_id=' + literal(HARBOR) + ' AND identity_id=' + literal(ENGINEER) + ') IS DISTINCT FROM ' + json_sql(original_engineer) \
            + ' OR (SELECT to_jsonb(m) FROM memberships m WHERE tenant_id=' + literal(HARBOR) + ' AND identity_id=' + literal(CONSUMER) + ') IS DISTINCT FROM ' + json_sql(original_consumer) \
            + " THEN RAISE EXCEPTION 'Synthetic fixture changed before qualification'; END IF;\n" \
            + 'UPDATE memberships SET permissions=' + json_sql(revoked['permissions']) + ' WHERE tenant_id=' + literal(HARBOR) + ' AND identity_id=' + literal(ENGINEER) + ';\n' \
            + 'DELETE FROM memberships WHERE tenant_id=' + literal(HARBOR) + ' AND identity_id=' + literal(CONSUMER) + ';'
        self.query(self.locked_fixture_sql(statements), 'revoke-engineer-and-delete-consumer')

    def restore_sql(self, original):
        engineer = next(v for v in original if v['identity_id'] == ENGINEER)
        consumer = next(v for v in original if v['identity_id'] == CONSUMER)
        # Preserve all actual original columns. A failed seed may have recreated
        # the consumer or regranted permissions. Restore those exact tested fields;
        # refuse unrelated row-shape/role/activity changes instead of overwriting.
        statements = 'IF (SELECT to_jsonb(m)-\'permissions\' FROM memberships m WHERE tenant_id=' + literal(HARBOR) + ' AND identity_id=' + literal(ENGINEER) + ') IS DISTINCT FROM (' + json_sql(engineer) + "-'permissions') " \
            + "THEN RAISE EXCEPTION 'Engineer fixture changed outside the qualification fields'; END IF;\n" \
            + 'IF EXISTS(SELECT 1 FROM memberships m WHERE tenant_id=' + literal(HARBOR) + ' AND identity_id=' + literal(CONSUMER) + ' AND (to_jsonb(m)-\'permissions\') IS DISTINCT FROM (' + json_sql(consumer) + "-'permissions')) " \
            + "THEN RAISE EXCEPTION 'Consumer fixture changed outside the qualification fields'; END IF;\n" \
            + 'UPDATE memberships SET permissions=' + json_sql(engineer['permissions']) + ' WHERE tenant_id=' + literal(HARBOR) + ' AND identity_id=' + literal(ENGINEER) + ';\n' \
            + 'INSERT INTO memberships SELECT (jsonb_populate_record(NULL::memberships,' + json_sql(consumer) + ')).* ON CONFLICT(tenant_id,identity_id) DO UPDATE SET permissions=EXCLUDED.permissions;\n' \
            + 'IF (SELECT to_jsonb(m) FROM memberships m WHERE tenant_id=' + literal(HARBOR) + ' AND identity_id=' + literal(ENGINEER) + ') IS DISTINCT FROM ' + json_sql(engineer) \
            + ' OR (SELECT to_jsonb(m) FROM memberships m WHERE tenant_id=' + literal(HARBOR) + ' AND identity_id=' + literal(CONSUMER) + ') IS DISTINCT FROM ' + json_sql(consumer) \
            + " THEN RAISE EXCEPTION 'Exact synthetic fixture restoration failed'; END IF;"
        return self.locked_fixture_sql(statements)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-core', action='store_true', help='Execute only after root has reserved the exclusive core qualification slot.')
    args = parser.parse_args()
    if not args.run_core:
        parser.error('--run-core is required; authoring or importing this script never mutates a database')
    LOCAL.mkdir(parents=True, exist_ok=True)
    attempts = LOCAL / 'business-domain-seed-attempts'
    attempts.mkdir(mode=0o700, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex[:8]
    attempt = attempts / stamp
    attempt.mkdir(mode=0o700)
    lock = open(LOCAL / 'business-domain-seed.lock', 'a+')
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit('A business-domain seed qualification already holds the local lock')
    harness = Harness(attempt)
    report = {'schema_version': 1, 'suite': 'business-domain-seed', 'profile': 'core', 'result': 'RUNNING', 'started_at': now(),
              'command': 'python3 scripts/runtime-test-business-domain-seed.py --run-core',
              'seed_command': './dev seed --dataset harbor-demo', 'seed_invocations': [], 'checks': [],
              'host_runtime': {'python': platform.python_version(), 'system': platform.system()},
              'fixture_restore': {'required': False, 'result': 'NOT_REQUIRED'},
              'limitations': ['Existing initialized local synthetic core only; no clean-install or general source/seed qualification.',
                              'No concurrent mutating API/browser/seed tests; local lock excludes only this harness.',
                              'All columns of domain rows/journals are hashed; unrelated non-domain fixtures and legacy transaction bindings are excluded.',
                              'Glossary definition equality covers only business_term and glossary_review in the two synthetic tenants; glossary journals and resource effects are excluded.',
                              'Quality equality covers all rule/version/run rows and quality journals/idempotency in the two synthetic tenants; no queued/running quality run is allowed.',
                              'All four permission-marker families are checked against independent declared hashes; exact quality/classification/reference grants are baseline prerequisites, never repaired by this gate.',
                              'Reference equality covers all set/release/value rows and reference journals/idempotency in both synthetic tenants; pending or ready reference approvals are excluded by admission.',
                              'Classification scope covers persona grants and immutable seed receipts, not definition/evaluation/assignment storage or deleted-owner recovery.',
                              'Outbox delivery must drain before baseline; no projector or service is stopped.',
                              'Privileged local PostgreSQL inspection/restoration is separate from the real seed runtime gc_owner/gc_app paths.',
                              'SIGINT/SIGTERM trigger finally restoration; SIGKILL or host failure requires the private recovery SQL before other tests.']}
    private_write(attempt / 'execution.json', json_bytes(report))
    original = None
    persona_digest = None
    mutation_attempted = False
    previous_handlers = {}

    def interrupted(signum, frame):
        raise InterruptedError('Qualification interrupted; exact fixture restoration is mandatory')

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.signal(signum, interrupted)
        for prior in attempts.glob('*/execution.json'):
            if prior.parent == attempt:
                continue
            previous = json.loads(prior.read_text())
            restore = previous.get('fixture_restore', {})
            require(not (restore.get('required') and restore.get('result') in ('PENDING', 'FAIL')),
                    'A previous attempt requires exact fixture recovery before another core gate')
        require_bootstrap()
        require_local()
        import shutil
        require(shutil.disk_usage(ROOT).free >= 2 * 1024**3, 'Free disk below 2GiB; no seed invocation started')
        expected = migration_inventory(ROOT / 'packages/db/migrations')
        require(len(expected) >= 22 and expected[21]['name'] == '022_reference_publication.sql',
                'Current seed preservation gate requires SQL022 reference publication')
        applied = json.loads(harness.query("SELECT coalesce(jsonb_agg(jsonb_build_object('name',name,'checksum',checksum) ORDER BY name),'[]') FROM schema_migrations", 'applied-migration-readback'))
        verify_applied_migrations(applied, expected)
        report['migrations'] = applied
        report['docker_versions'] = {'engine': harness.command(['docker', 'version', '--format', '{{.Server.Version}}'], 'docker-engine-version'),
                                     'compose': harness.command(['docker', 'compose', 'version', '--short'], 'docker-compose-version')}
        require(harness.query("SELECT count(*) FROM jobs WHERE status IN ('queued','running')", 'active-job-precondition') == '0', 'Wait for existing queued/running jobs before this gate')
        require(harness.query("SELECT count(*) FROM public.quality_runs WHERE status IN ('queued','running')", 'active-quality-run-precondition') == '0',
                'Wait for existing queued/running quality runs before this gate')
        require(harness.query("SELECT count(*) FROM public.approval_requests WHERE binding='reference.publish' AND status IN ('pending','ready')", 'active-reference-approval-precondition') == '0',
                'Wait for existing pending/ready reference approvals before this gate')
        roles = json.loads(harness.query("SELECT jsonb_object_agg(rolname,jsonb_build_object('superuser',rolsuper,'bypassrls',rolbypassrls)) FROM pg_roles WHERE rolname IN ('gc_owner','gc_app')", 'seed-role-readback'))
        require(set(roles) == {'gc_owner', 'gc_app'} and all(not value['superuser'] and not value['bypassrls'] for value in roles.values()), 'Seed roles must remain nonsuperuser and nonbypass')
        report['roles'] = roles
        sources, hosts = source_hashes(), host_hashes()
        images = harness.service_images()
        report.update({'sources': sources, 'host_sources': hosts, 'images_before': images,
                       'image_source_readback': harness.image_sources(images['api']['container_id'], sources),
                       'base_commit': harness.command(['git', 'rev-parse', 'HEAD'], 'base-commit')})
        markers = json.loads(harness.query("SELECT jsonb_build_object('trees',(SELECT count(*) FROM idempotency WHERE tenant_id IN (" + literal(HARBOR) + ',' + literal(SUMMIT)
            + ") AND operation IN ('domain-type.create','domain.create') AND key IN ('harbor-demo.domains.v1.type','harbor-demo.domains.v1.root','harbor-demo.domains.v1.child.0','harbor-demo.domains.v1.child.1')),"
            "'engineer_upgrade',(SELECT count(*) FROM idempotency WHERE tenant_id=" + literal(HARBOR) + ' AND actor_id=' + literal(ENGINEER)
            + " AND operation='bootstrap.domain-permissions.v1' AND key='harbor-demo' AND response->>'version'='1'))", 'seed-baseline-markers'))
        require(markers == {'trees': 8, 'engineer_upgrade': 1}, 'Initial typed-tree seed and engineer permission-upgrade marker are required')
        report['baseline_markers'] = markers
        permission_markers = harness.permission_markers()
        report['permissionMarkerSnapshot'] = {'before': permission_markers}
        verify_reference_permissions(verify_classification_permissions(harness.quality_permissions()))
        original = harness.memberships()
        require(len(original) == 2, 'Both original engineer/consumer synthetic memberships are required')
        engineer = next(v for v in original if v['identity_id'] == ENGINEER)
        consumer = next(v for v in original if v['identity_id'] == CONSUMER)
        require(engineer['role'] == 'engineer' and consumer['role'] == 'consumer' and engineer['active'] and consumer['active'], 'Unexpected synthetic membership identity/role/activity')
        revoked = revoked_engineer(engineer)
        identity_rows = json.loads(harness.query('SELECT jsonb_agg(jsonb_build_object(\'id\',id,\'subject\',subject,\'name\',name,\'active\',active) ORDER BY id) FROM identities WHERE id IN (' + literal(ENGINEER) + ',' + literal(CONSUMER) + ')', 'synthetic-identity-precondition'))
        require(identity_rows == [{'id': CONSUMER, 'subject': CONSUMER, 'name': 'Harbor Analyst', 'active': True},
                                  {'id': ENGINEER, 'subject': ENGINEER, 'name': 'Harbor Engineer', 'active': True}], 'Only the exact declared synthetic identities may be qualified')
        persona_digest = harness.all_personas_digest()
        private_write(attempt / 'synthetic-membership-before.json', json_bytes(original))
        private_write(attempt / 'restore-synthetic-memberships.sql', harness.restore_sql(original).encode())
        deadline = time.monotonic() + 20
        while harness.query('SELECT count(*) FROM outbox WHERE tenant_id IN (' + literal(HARBOR) + ',' + literal(SUMMIT) + ') AND processed_at IS NULL AND ' + action_predicate('event_type'), 'wait-domain-outbox-drain') != '0':
            require(time.monotonic() < deadline, 'Domain outbox did not drain before exact-byte baseline')
            time.sleep(0.25)
        deadline = time.monotonic() + 20
        while harness.query('SELECT count(*) FROM public.outbox WHERE tenant_id IN (' + literal(HARBOR) + ',' + literal(SUMMIT)
                            + ") AND processed_at IS NULL AND event_type LIKE 'quality.%'", 'wait-quality-outbox-drain') != '0':
            require(time.monotonic() < deadline, 'Quality outbox did not drain before exact-byte baseline')
            time.sleep(0.25)
        deadline = time.monotonic() + 20
        while harness.query('SELECT count(*) FROM public.outbox WHERE tenant_id IN (' + literal(HARBOR) + ',' + literal(SUMMIT)
                            + ") AND processed_at IS NULL AND event_type LIKE 'reference.%'", 'wait-reference-outbox-drain') != '0':
            require(time.monotonic() < deadline, 'Reference outbox did not drain before exact-byte baseline')
            time.sleep(0.25)
        before = harness.snapshot()
        require(before['domain_types']['rows'] >= 2 and before['domains']['rows'] >= 6 and before['domain_revisions']['rows'] >= 6 and before['audit']['rows'] >= 8 and before['outbox']['rows'] >= 8, 'Actual typed domain/revision/journal baseline is incomplete')
        report['before'] = before
        glossary_definitions = harness.glossary_definition_snapshot()
        report['glossaryDefinitionSnapshot'] = {'before': glossary_definitions}
        quality = harness.quality_snapshot()
        report['qualitySnapshot'] = {'before': quality}
        reference = harness.reference_snapshot()
        report['referenceSnapshot'] = {'before': reference}
        def run_seed(phase):
            entry = {'phase': phase, 'started_at': now(), 'result': 'RUNNING'}
            report['seed_invocations'].append(entry)
            private_write(attempt / 'execution.json', json_bytes(report))
            try:
                harness.real_seed('real-seed-' + phase, images['seed'])
                entry.update({'result': 'PASS', 'exit_status': 0})
            except BaseException:
                entry['result'] = 'FAIL'
                raise
            finally:
                entry['finished_at'] = now()
            return entry

        for index in range(2):
            entry = run_seed('unchanged-' + str(index + 1))
            after = harness.snapshot()
            require(after == before, 'Repeated real seed changed domain canonical/history/journal/idempotency bytes')
            require(harness.all_personas_digest() == persona_digest, 'Repeated real seed changed existing persona memberships')
            require(harness.glossary_definition_snapshot() == glossary_definitions, 'Repeated real seed changed existing glossary definition rows')
            require(harness.quality_snapshot() == quality, 'Repeated real seed changed quality canonical/history/journal/idempotency bytes')
            require(harness.reference_snapshot() == reference, 'Repeated real seed changed reference canonical/history/journal/idempotency bytes')
            require(harness.permission_markers() == permission_markers, 'Repeated real seed changed domain, quality, classification or reference permission marker rows')
            entry.update({'domain_snapshot_equal': True, 'persona_memberships_equal': True, 'glossary_definitions_equal': True,
                          'quality_snapshot_equal': True, 'reference_snapshot_equal': True, 'permission_markers_equal': True})
        report['checks'].append('two real seed replays preserve exact domain and persona membership row digests')
        mutation_attempted = True  # Even uncertain command outcome requires restore.
        report['fixture_restore'] = {'required': True, 'result': 'PENDING'}
        private_write(attempt / 'execution.json', json_bytes(report))
        harness.mutate(original, revoked)
        require(harness.memberships() == [revoked], 'Actual revocation/deletion fixture readback differs')
        entry = run_seed('revoked-engineer-and-deleted-consumer')
        require(harness.memberships() == [revoked], 'Real seed restored revoked permission or recreated deleted consumer membership')
        require(harness.snapshot() == before, 'Seed after revocation/deletion changed domain data or journals')
        require(harness.glossary_definition_snapshot() == glossary_definitions, 'Seed after revocation/deletion changed glossary definition rows')
        require(harness.quality_snapshot() == quality, 'Seed after revocation/deletion changed quality data or journals')
        require(harness.reference_snapshot() == reference, 'Seed after revocation/deletion changed reference data or journals')
        require(harness.permission_markers() == permission_markers, 'Seed after revocation/deletion changed permission marker rows')
        entry.update({'domain_snapshot_equal': True, 'permission_still_revoked': True, 'consumer_membership_still_absent': True, 'glossary_definitions_equal': True,
                      'quality_execute_still_revoked': True, 'classification_approve_still_revoked': True, 'reference_approve_still_revoked': True,
                      'quality_snapshot_equal': True, 'reference_snapshot_equal': True, 'permission_markers_equal': True})
        report['checks'] += ['later engineer domains:write revocation survives real seed', 'deleted synthetic consumer membership is not recreated',
                             'three real seed replays preserve exact existing business_term and glossary_review definition rows',
                             'later engineer quality:execute revocation survives real seed',
                             'later engineer classification:approve revocation survives real seed',
                             'later engineer reference:approve revocation survives real seed',
                             'three real seed replays preserve exact reference canonical/history/journal/idempotency bytes',
                             'three real seed replays preserve exact quality canonical/history/journal/idempotency bytes',
                             'three real seed replays retain exact independently checked domain, quality, classification and reference permission markers']
        report['result'] = 'PASS'
    except BaseException as error:
        report['result'] = 'FAIL'
        # Exceptions from subprocess/SQL never print command inputs or outputs.
        report['failure'] = str(error) if isinstance(error, (RuntimeError, InterruptedError)) else type(error).__name__
    finally:
        cleanup_errors = []
        if harness.seed_context is not None or mutation_attempted:
            for signum in previous_handlers:
                signal.signal(signum, signal.SIG_IGN)
        if harness.seed_context is not None:
            for _ in range(3):
                try:
                    harness.cleanup_seed()
                    break
                except Exception as error:
                    cleanup_errors.append(str(error) if isinstance(error, RuntimeError) else type(error).__name__)
                    time.sleep(0.25)
            if harness.seed_context is not None:
                report['result'] = 'FAIL'
                report['seed_cleanup_failure'] = cleanup_errors
        if mutation_attempted and original is not None:
            restore_errors = []
            if harness.seed_context is None:
                for _ in range(3):
                    try:
                        harness.query(harness.restore_sql(original), 'restore-exact-synthetic-memberships')
                        require(harness.memberships() == original, 'Exact restored membership readback differs')
                        require(harness.all_personas_digest() == persona_digest, 'A synthetic persona differs after restoration')
                        report['fixture_restore'] = {'required': True, 'result': 'PASS', 'original_rows_sha256': digest(json_bytes(original)), 'all_six_personas_sha256': persona_digest, 'prior_attempt_errors': restore_errors}
                        report['checks'].append('exact captured membership rows restored and all six personas unchanged')
                        break
                    except Exception as error:
                        restore_errors.append(str(error) if isinstance(error, RuntimeError) else type(error).__name__)
                        time.sleep(0.25)
            if report['fixture_restore']['result'] != 'PASS':
                report['result'] = 'FAIL'
                report['fixture_restore'] = {'required': True, 'result': 'FAIL', 'errors': restore_errors,
                                             'seed_idle_verified': harness.seed_context is None,
                                             'recovery_sql': str((attempt / 'restore-synthetic-memberships.sql').relative_to(ROOT)),
                                             'required_action': 'Stop subsequent core gates; verify the owned seed has exited, restore the exact private fixture backup under the recorded locks, then verify before resuming.'}
        try:
            if 'sources' in report:
                report['sources_after'] = source_hashes()
                report['host_sources_after'] = host_hashes()
                report['images_after'] = harness.service_images()
                image_readback = harness.image_sources(report['images_after']['api']['container_id'], report['sources'])
                report['source_freeze_matched'] = report['sources_after'] == report['sources'] and report['host_sources_after'] == report['host_sources']
                report['images_unchanged'] = report['images_after'] == report['images_before']
                report['image_sources_after_matched'] = image_readback['sources'] == report['sources']
                require(report['source_freeze_matched'] and report['images_unchanged'] and report['image_sources_after_matched'], 'Source or runtime image changed during seed qualification')
            if 'before' in report:
                report['after_restoration'] = harness.snapshot()
                require(report['after_restoration'] == report['before'], 'Domain rows changed before final readback')
            if 'glossaryDefinitionSnapshot' in report:
                report['glossaryDefinitionSnapshot']['after_restoration'] = harness.glossary_definition_snapshot()
                require(report['glossaryDefinitionSnapshot']['after_restoration'] == report['glossaryDefinitionSnapshot']['before'],
                        'Glossary definition rows changed before final readback')
            if 'qualitySnapshot' in report:
                report['qualitySnapshot']['after_restoration'] = harness.quality_snapshot()
                require(report['qualitySnapshot']['after_restoration'] == report['qualitySnapshot']['before'],
                        'Quality rows changed before final readback')
            if 'referenceSnapshot' in report:
                report['referenceSnapshot']['after_restoration'] = harness.reference_snapshot()
                require(report['referenceSnapshot']['after_restoration'] == report['referenceSnapshot']['before'],
                        'Reference rows changed before final readback')
            if 'permissionMarkerSnapshot' in report:
                report['permissionMarkerSnapshot']['after_restoration'] = harness.permission_markers()
                require(report['permissionMarkerSnapshot']['after_restoration'] == report['permissionMarkerSnapshot']['before'],
                        'Domain, quality, classification or reference permission markers changed before final readback')
        except Exception as error:
            report['result'] = 'FAIL'
            report['final_readback_failure'] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
        report['finished_at'] = now()
        report['commands'] = harness.commands
        report['private_artifacts'] = [{'path': str(p.relative_to(ROOT)), 'sha256': digest(p.read_bytes()), 'bytes': p.stat().st_size}
                                       for p in sorted(attempt.iterdir()) if p.is_file() and p.name != 'execution.json']
        report['attempt_path'] = str(attempt.relative_to(ROOT))
        report['publication_rule'] = 'Review scoped summary before publication; private fixture/recovery files remain ignored. No API/browser/full capability pass is inferred.'
        encoded = json_bytes(report)
        private_write(attempt / 'execution.json', encoded)
        private_write(REPORT, encoded)
        private_write(attempt / 'manifest.json', json_bytes({'execution_sha256': digest(encoded), 'artifacts': report['private_artifacts']}))
        print(json.dumps({'suite': report['suite'], 'result': report['result'], 'fixture_restore': report['fixture_restore']['result'],
                          'evidence': str(REPORT.relative_to(ROOT)), 'sha256': digest(encoded), 'failure': report.get('failure'),
                          'final_readback_failure': report.get('final_readback_failure')}))
        lock.close()
    return 0 if report['result'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
