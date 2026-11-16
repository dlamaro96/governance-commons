#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Revalidate inactive authentication qualification; export no private records.

The independent publisher binds all declared sources, replays both exact TAP
logs against static source declarations, and requires completed owned cleanup.
Failed/partial reports remain private and cannot qualify a successful CI step.
"""
from __future__ import annotations
import ast
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from api_evidence import declaration_literal

MIB = 1024**2
MAX_REPORT = 4*MIB
COMMAND = './dev test --suite authority-authn-foundation'
PROFILE = 'authn-foundation-tmpfs'
MIGRATIONS = ('001_foundation.sql', '002_audit_envelopes.sql', '003_governance_models.sql',
              '004_model_migrations.sql', '005_model_migration_integrity.sql', '006_inherited_asset_types.sql',
              '007_asset_type_migrations.sql', '008_constrained_relations.sql', '009_relation_participation.sql',
              '010_relation_scope_discovery.sql', '011_business_domains.sql', '012_authentication_foundation.sql')
TESTS = {'tests': 'tests/qualification/authority-authn-foundation-storage.test.ts',
         'concurrency_tests': 'tests/qualification/authority-authn-foundation-concurrency.test.ts'}
FIXED_SOURCES = (
    'scripts/runtime-test-authority-authn-foundation.py', *TESTS.values(),
    'tests/fixtures/authority-authn-foundation.ts', 'scripts/authentication_roles.py', 'scripts/authentication-install.ts',
    'scripts/runtime-test-business-domains-upgrade.py', 'scripts/runtime-test-relation-participation-upgrade.py',
    'docs/execution/AUTHENTICATION_FOUNDATION_CONTRACT.md', 'docs/execution/AUTHENTICATION_FOUNDATION_CANDIDATE.md',
    'docs/execution/AUTHENTICATION_FOUNDATION_QUALIFICATION.md', 'docs/execution/authentication-legacy-function-census.json',
    'package.json', 'pnpm-lock.yaml', 'Dockerfile', 'deploy/compose/compose.yaml',
    'dev', 'scripts/runtime.py', 'scripts/runtime-bootstrap.py', 'scripts/runtime-authentication-roles.py',
    'scripts/runtime-test-type-migration-upgrade.py', 'tsconfig.json', 'policies/authentication_evidence.py',
    'policies/ci_evidence.py', 'policies/api_evidence.py', 'policies/test_authentication_evidence.py', 'policies/test_ci_evidence.py', '.github/workflows/ci.yml',
)
SOURCE_FOLDERS = ('packages/db/src', 'packages/domain/src', 'packages/authz/src', 'packages/authority/src', 'apps/api/src', 'tests/fixtures')
ISOLATION = {'network': 'none', 'readOnly': True, 'logDriver': 'none', 'memoryBytes': 896*MIB,
             'pgdataTmpfsBytes': 256*MIB, 'hostFloorBytes': 1024*MIB, 'outputCapBytes': 100*MIB, 'diagnosticCapBytes': 4*MIB}
CHECKS = [
    'Actual SQL001–011 baseline includes canonical/history/graph/domain receipts, private legacy auth and revoked principal rows;155/56 function census matches',
    'Checksum, missing/unsafe prerequisite and namespace collisions fail transactionally before the exact forward application',
    'Native credential-preserving role replay rejects existing column/type grants and NOLOGIN; failed final assertion still removes temporary setup privileges',
    'Thirteen private tables begin empty except immutable installation root; checksum/provisioner replay is exact, native SCRAM executors have finite capabilities',
    'Actual deployment CLI commits and exactly replays a receipt using native owner SCRAM; wrong-owner execution refuses',
]
LIMITATIONS = [
    'Inactive isolated PostgreSQL authentication only; no HTTP/OIDC/CSRF, shared-core migration, content authority, cutover or release qualification.',
    'Source bindings and cached dependency hashes do not attest the complete application image; broker claims remain trusted.',
    'Raw TAP, titles, errors, SQL, credentials, identity/session records, baseline values and private evidence paths are not published.',
    'Resource observations and successful owned cleanup do not guarantee Docker VM or host swap behavior.',
]


def require(condition):
    if not condition:
        raise ValueError('Authentication evidence rejected')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys))


def integer(value, low=0, high=2**63-1):
    require(type(value) is int and low <= value <= high)
    return value


def hashed(value):
    require(type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None)
    return value


def timestamp(value):
    require(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?\+00:00', value) is not None)
    return datetime.fromisoformat(value)


def read_file(root, name, cap):
    require(type(name) is str and name and '\\' not in name and not Path(name).is_absolute())
    parts = name.split('/')
    require(all(part not in ('', '.', '..') for part in parts))
    path = root
    for part in parts:
        path = path / part
        require(not path.is_symlink())
    require(path.resolve().is_relative_to(root.resolve()))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_size <= cap)
        with os.fdopen(fd, 'rb', closefd=False) as source:
            data = source.read(cap+1)
        require(len(data) <= cap)
        return data
    finally:
        os.close(fd)


def source_inventory(root):
    names = set(FIXED_SOURCES) | {'packages/db/migrations/' + name for name in MIGRATIONS}
    for folder in SOURCE_FOLDERS:
        base = root / folder
        require(base.is_dir() and not base.is_symlink())
        require(not any(path.is_symlink() for path in base.rglob('*')))
        names.update(str(path.relative_to(root)) for path in base.rglob('*.ts'))
    require(len(names) <= 4096)
    require(all(len(name) <= 512 and re.fullmatch(r'[A-Za-z0-9_.\-/]+', name) is not None for name in names))
    return [{'path': name, 'sha256': digest(read_file(root, name, 16*MIB))} for name in sorted(names)]


def declarations(root, name):
    rows = []
    seen = set()
    for line, source in enumerate(read_file(root, name, 4*MIB).decode('utf-8').splitlines(), 1):
        if not re.match(r'^\s*(?:test|it|describe)(?:\s*\(|\.)', source):
            continue
        literal = declaration_literal(source)
        title = ast.literal_eval(literal) if literal is not None else None
        require(type(title) is str and 0 < len(title) <= 1000 and title not in seen and not any(ord(c) < 32 for c in title))
        seen.add(title)
        rows.append({'title': title, 'file': name, 'line': line})
    require(0 < len(rows) <= 10000)
    return rows


def tap_summary(data, key, rows):
    text = data.decode('utf-8')
    require(text.startswith(f'phase={key}\nexit=0\n'))
    require(len(re.findall(r'^TAP version 13$', text, re.M)) == 1)
    require(re.findall(r'^1\.\.([0-9]+)$', text, re.M) == [str(len(rows))])
    matches = re.findall(r'^(ok|not ok) ([1-9][0-9]*) - ([^\r\n]*)$', text, re.M)
    require(matches == [('ok', str(i), row['title']) for i, row in enumerate(rows, 1)])
    counts = {}
    for field in ('tests', 'suites', 'pass', 'fail', 'cancelled', 'skipped', 'todo'):
        values = re.findall(r'^# ' + field + r' ([0-9]+)$', text, re.M)
        require(len(values) == 1)
        counts[field] = int(values[0])
    require(counts == {'tests': len(rows), 'suites': 0, 'pass': len(rows), 'fail': 0, 'cancelled': 0, 'skipped': 0, 'todo': 0})
    durations = re.findall(r'^# duration_ms ([0-9]+(?:\.[0-9]+)?)$', text, re.M)
    require(len(durations) == 1)
    duration = float(durations[0])
    require(math.isfinite(duration) and 0 <= duration <= 240_000)
    counts.pop('suites')
    return {**counts, 'duration_ms': duration}


def _safe_report(root, value, commit):
    exact(value, ('schema_version', 'result', 'started_at', 'recorded_at', 'commit', 'command', 'profile', 'checks',
                  'sources', 'migrations', 'images', 'docker_version', 'runtime', 'tests', 'concurrency_tests',
                  'baseline', 'isolation', 'cleanup', 'limitations', 'private_logs', 'evidence_directory', 'memory_admission', 'test_logs'))
    require(type(value['schema_version']) is int and value['schema_version'] == 1 and value['result'] == 'PASS')
    require(type(commit) is str and re.fullmatch('[a-f0-9]{40}', commit) is not None and value['commit'] == commit)
    require(value['command'] == COMMAND and value['profile'] == PROFILE)
    require(timestamp(value['started_at']) <= timestamp(value['recorded_at']))
    sources = source_inventory(root)
    require(value['sources'] == sources)
    hashes = {row['path']: row['sha256'] for row in sources}
    migrations = [{'name': name, 'sha256': hashes['packages/db/migrations/' + name]} for name in MIGRATIONS]
    require(value['migrations'] == migrations)
    exact(value['images'], ('postgres', 'application'))
    for image in value['images'].values():
        require(type(image) is str and re.fullmatch('sha256:[a-f0-9]{64}', image) is not None)
    require(type(value['docker_version']) is str and re.fullmatch(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:[-+][a-zA-Z0-9.-]{1,64})?', value['docker_version']) is not None)
    runtime = value['runtime']
    exact(runtime, ('node', 'pg', 'tsx', 'kysely', 'packageSha256', 'lockSha256'))
    package = strict_json(read_file(root, 'package.json', MIB))
    require(runtime['node'] == 'v24.22.3')
    for dependency in ('pg', 'tsx', 'kysely'):
        expected = package.get('dependencies', {}).get(dependency, package.get('devDependencies', {}).get(dependency))
        require(type(expected) is str and re.fullmatch(r'\d+\.\d+\.\d+', expected) is not None and runtime[dependency] == expected)
    require(runtime['packageSha256'] == hashes['package.json'] and runtime['lockSha256'] == hashes['pnpm-lock.yaml'])
    require(type(value['isolation']) is dict and value['isolation'] == ISOLATION and type(value['isolation'].get('readOnly')) is bool)
    for key in ('memoryBytes', 'pgdataTmpfsBytes', 'hostFloorBytes', 'outputCapBytes', 'diagnosticCapBytes'):
        integer(value['isolation'][key])
    exact(value['cleanup'], ('ownedRemoved', 'resourceInventoryPreserved'))
    require(all(flag is True for flag in value['cleanup'].values()))
    memory = value['memory_admission']
    exact(memory, ('total_bytes', 'observed_working_bytes', 'daemon_reserve_bytes'))
    for number in memory.values():
        integer(number)
    require(memory['daemon_reserve_bytes'] == 1024*MIB and memory['total_bytes'] - memory['observed_working_bytes'] - memory['daemon_reserve_bytes'] >= 2048*MIB)
    folder = value['evidence_directory']
    require(type(folder) is str and re.fullmatch(r'\.local/evidence/authority-authn-foundation-\d{8}T\d{6}-[a-f0-9]{12}', folder) is not None)
    logs = value['private_logs']
    require(type(logs) is list and 0 < len(logs) <= 2048)
    log_data = {}
    total = 0
    for row in logs:
        exact(row, ('path', 'sha256'))
        name = row['path']
        require(type(name) is str and name.startswith(folder + '/') and re.fullmatch(r'[0-9]{3,6}-[a-z_-]+\.log', name[len(folder)+1:]) is not None and name not in log_data)
        data = read_file(root, name, 4*MIB)
        require(digest(data) == hashed(row['sha256']))
        total += len(data)
        require(total <= 100*MIB)
        log_data[name] = data
    exact(value['test_logs'], TESTS)
    results = {}
    coordinates = []
    test_log_hashes = {}
    for key, name in TESTS.items():
        ref = value['test_logs'][key]
        exact(ref, ('path', 'sha256'))
        require(type(ref['path']) is str and ref['path'] in log_data and digest(log_data[ref['path']]) == hashed(ref['sha256']))
        rows = declarations(root, name)
        counts = tap_summary(log_data[ref['path']], key, rows)
        exact(value[key], counts)
        for count_key, number in value[key].items():
            if count_key == 'duration_ms':
                require(type(number) in (int, float) and math.isfinite(number))
            else:
                integer(number, 0, 10000)
        require(value[key] == counts)
        results[key] = counts
        coordinates += [{'file': row['file'], 'line': row['line'], 'status': 'passed'} for row in rows]
        test_log_hashes[key] = ref['sha256']
    require(type(value['baseline']) is list and 0 < len(value['baseline']) <= 512)
    tables = set()
    for row in value['baseline']:
        exact(row, ('table', 'original_rows', 'sha256'))
        require(type(row['table']) is str and re.fullmatch('[a-z][a-z0-9_]{0,62}', row['table']) is not None and row['table'] not in tables)
        tables.add(row['table'])
        integer(row['original_rows'], 0, 1_000_000)
        hashed(row['sha256'])
    # These private descriptive fields are never copied. Their exact outer shape
    # is checked so arbitrary extra fields cannot masquerade as safe evidence.
    for field, cap in (('checks', 64), ('limitations', 16)):
        require(type(value[field]) is list and 0 < len(value[field]) <= cap)
        require(all(type(item) is str and 0 < len(item.encode('utf-8')) <= 2048 for item in value[field]))
    require(value['checks'] == CHECKS + [f"All{results[key]['tests']} {key} pass with native connections, no failures, skips, cancellations or todos" for key in TESTS])
    require(source_inventory(root) == sources)
    return {'schema_version': 1, 'purpose': 'INACTIVE_AUTHENTICATION_FOUNDATION_COORDINATES_ONLY',
            'outcome': 'PASS', 'commit': commit, 'started_at': value['started_at'], 'recorded_at': value['recorded_at'],
            'command': COMMAND, 'profile': PROFILE, 'counts': results, 'tests': coordinates,
            'source_files': hashes, 'source_manifest_sha256': digest(json.dumps(hashes, sort_keys=True, separators=(',', ':')).encode()),
            'migrations': migrations, 'images': dict(value['images']), 'runtime': dict(runtime),
            'isolation': dict(ISOLATION), 'cleanup': {'ownedRemoved': True, 'resourceInventoryPreserved': True},
            'private_test_log_sha256': test_log_hashes, 'limitations': list(LIMITATIONS)}


def safe_report(root, value, commit):
    try:
        return _safe_report(root, value, commit)
    except (OSError, ValueError, TypeError, KeyError, SyntaxError, RecursionError, OverflowError):
        return None


def strict_json(data):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result)
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('Nonfinite JSON')
    return json.loads(data.decode('utf-8'), object_pairs_hook=pairs, parse_constant=invalid)


def load_report(root, commit):
    try:
        data = read_file(root, '.local/evidence/authority-authn-foundation.json', MAX_REPORT)
        return safe_report(root, strict_json(data), commit)
    except (OSError, ValueError, TypeError, RecursionError, OverflowError):
        return None
