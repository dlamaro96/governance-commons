# SPDX-License-Identifier: Apache-2.0
"""Failure-only authority diagnostics. Never a success/qualification publisher."""
from __future__ import annotations
import json
import re
from authentication_evidence import (MIB, declarations, digest, exact, hashed,
    read_file, require, source_inventory as predecessor_sources, strict_json, timestamp)

COMMAND = './dev test --suite authority-foundation'
PROFILE = 'isolated-inactive-authority-foundation'
REPORT = '.local/evidence/authority-foundation.json'
SUITES = {
    'tests': 'tests/qualification/authority-authn-foundation-storage.test.ts',
    'concurrency_tests': 'tests/qualification/authority-authn-foundation-concurrency.test.ts',
    'authn_storage_regression': 'tests/qualification/authority-authn-foundation-storage.test.ts',
    'authn_concurrency_regression': 'tests/qualification/authority-authn-foundation-concurrency.test.ts',
    **{f'authority_{kind}': f'tests/qualification/authority-foundation-{kind}.test.ts'
       for kind in ('storage', 'loader', 'concurrency')},
}
PHASES = frozenset(('admission', 'database-start', 'predecessor', 'upgrade-refusals',
    'upgrade', 'replay', 'role-provisioner-refusals', 'installation-cli',
    'authority-preupgrade', 'authority-missing-transfer', 'authority-upgrade', 'cleanup', *SUITES))
CATEGORIES = frozenset(('command_timeout', 'command_failed', 'suite_failed',
    'invariant_failed', 'interrupted', 'unknown'))
MARKER = 'AUTHORITY_DIAGNOSTIC_V1='
FIXED_SOURCES = (
    'scripts/runtime-test-authority-foundation.py', 'packages/db/migrations/013_authority_foundation.sql',
    'docs/execution/CANONICAL_AUTHORITY_FOUNDATION_CONTRACT.md',
    'docs/execution/CANONICAL_AUTHORITY_FOUNDATION_CANDIDATE.md',
    'docs/adr/0014-inactive-canonical-authority-foundation.md', 'tests/fixtures/authority-foundation.ts',
    'policies/authority_diagnostics.py', 'policies/test_authority_diagnostics.py', *SUITES.values(),
)
SOURCE_FOLDERS = ('packages/authority-storage', 'tests/unit/fixtures')


def source_inventory(root):
    names = {row['path'] for row in predecessor_sources(root)} | set(FIXED_SOURCES)
    for folder in SOURCE_FOLDERS:
        base = root / folder
        require(base.is_dir() and not base.is_symlink())
        require(not any(path.is_symlink() for path in base.rglob('*')))
        names.update(str(path.relative_to(root)) for path in base.rglob('*.ts'))
    require(len(names) <= 4096)
    require(all(len(name) <= 512 and re.fullmatch(r'[A-Za-z0-9_.\-/]+', name) for name in names))
    return [{'path': name, 'sha256': digest(read_file(root, name, 16*MIB))} for name in sorted(names)]


def _tap(root, phase, text):
    """Partial TAP is useful diagnostic evidence, but never counted as a pass."""
    if phase not in SUITES:
        return [], False, False, [], []
    expected = declarations(root, SUITES[phase])
    require(len(expected) <= 256)
    records, states, locations = {}, set(), set()
    matches = list(re.finditer(r'^(ok|not ok) ([1-9][0-9]*) - ([^\r\n]*)$', text, re.M))
    unmapped = False
    for index, match in enumerate(matches):
        number = int(match[2])
        title = re.sub(r' # (?:SKIP|TODO)(?: .*)?$', '', match[3])
        if number > len(expected) or number in records or title != expected[number-1]['title']:
            unmapped = True
            continue
        chunk = text[match.end():matches[index+1].start() if index+1 < len(matches) else len(text)]
        status = 'passed' if match[1] == 'ok' else 'failed'
        if title != match[3]:
            status = 'skipped'
        elif re.search(r"^\s+failureType: ['\"]?cancelledByParent['\"]?\s*$", chunk, re.M):
            status = 'cancelled'
        records[number] = {'file': expected[number-1]['file'], 'line': expected[number-1]['line'], 'status': status}
        if status in ('failed', 'cancelled'):
            # Only the fixture's fixed error prefix; arbitrary code/message fields
            # and successful/expected-refusal output do not supply SQLSTATEs.
            states.update(re.findall(r"^\s+(?:error: ['\"]?)?PostgreSQL rejected qualification operation \(([0-9A-Z]{5})\)", chunk, re.M))
            for name in (SUITES[phase], 'tests/fixtures/authority-foundation.ts', 'tests/fixtures/authority-authn-foundation.ts'):
                lines = read_file(root, name, 4*MIB).decode('utf-8').splitlines()
                for line, column in re.findall(r'(?:^|[/\\])' + re.escape(name) + r':([1-9][0-9]{0,5}):([1-9][0-9]{0,5})(?=[)\s]|$)', chunk, re.M):
                    line, column = int(line), int(column)
                    if line <= len(lines) and column <= len(lines[line-1])+1:
                        locations.add((name, line, column))
    tests = [records.get(i, {'file': row['file'], 'line': row['line'], 'status': 'not_observed'})
             for i, row in enumerate(expected, 1)]
    complete = (not unmapped and len(records) == len(expected)
                and re.findall(r'^TAP version 13$', text, re.M) == ['TAP version 13']
                and re.findall(r'^1\.\.([0-9]+)$', text, re.M) == [str(len(expected))]
                and re.findall(r'^# tests ([0-9]+)$', text, re.M) == [str(len(expected))])
    return tests, complete, unmapped, sorted(states)[:16], [
        {'file': name, 'line': line, 'column': column} for name, line, column in sorted(locations)[:16]]


def _safe_report(root, value, commit):
    require(type(value) is dict and type(value.get('schema_version')) is int and value['schema_version'] == 1 and value.get('result') == 'FAIL')
    require(type(commit) is str and re.fullmatch('[a-f0-9]{40}', commit) and value.get('commit') == commit)
    require(value.get('command') == COMMAND and value.get('profile') == PROFILE)
    start, end = timestamp(value['started_at']), timestamp(value['recorded_at'])
    require(0 <= (end-start).total_seconds() <= 3600)
    sources = source_inventory(root)
    require(value['diagnostic_sources'] == sources)
    folder = value['evidence_directory']
    require(type(folder) is str and re.fullmatch(r'\.local/evidence/authority-foundation-[0-9]{8}T[0-9]{6}-[0-9a-f]{12}', folder))
    failure = value['failure_diagnostic']
    exact(failure, ('phase', 'category', 'commandLog'))
    phase, category = failure['phase'], failure['category']
    require(phase in PHASES and phase == value.get('failed_phase') and category in CATEGORIES)
    logs = value['private_logs']
    require(type(logs) is list and len(logs) <= 2048)
    selected, total_bytes, seen, ordinals = None, 0, set(), set()
    log_digests = []
    for row in logs:
        exact(row, ('path', 'sha256'))
        name = row['path']
        require(type(name) is str and name.startswith(folder+'/') and '/' not in name[len(folder)+1:])
        match = re.fullmatch(r'([0-9]{3,4})-([a-z_-]+)\.log', name[len(folder)+1:])
        require(match is not None and match[2] in PHASES and name not in seen)
        require(1 <= int(match[1]) <= 2048 and int(match[1]) not in ordinals)
        seen.add(name)
        ordinals.add(int(match[1]))
        data = read_file(root, name, 4*MIB+1024)
        total_bytes += len(data)
        require(total_bytes <= 100*MIB and digest(data) == hashed(row['sha256']))
        text = data.decode('utf-8')
        header = re.match(r'phase=([a-z_-]+)\nexit=(-?[0-9]{1,3})\n', text)
        require(header is not None and header[1] == match[2])
        if row == failure['commandLog']:
            selected = (text, int(header[2]), row['sha256'])
            require(header[1] == phase)
        log_digests.append({'ordinal': int(match[1]), 'phase': match[2], 'sha256': row['sha256']})
    if failure['commandLog'] is None:
        require(category in ('invariant_failed', 'interrupted', 'unknown'))
        text, exit_code, command_digest = '', None, None
    else:
        exact(failure['commandLog'], ('path', 'sha256'))
        require(selected is not None)
        text, exit_code, command_digest = selected
        markers = re.findall(r'^'+MARKER+r'([a-z_]+)$', text, re.M)
        require(markers == [category] and text.endswith(MARKER+category+'\n'))
        require(category in ('command_timeout', 'command_failed', 'suite_failed', 'interrupted', 'unknown'))
        if category in ('command_failed', 'suite_failed'):
            require(exit_code != 0)
        if category == 'suite_failed':
            require(phase in SUITES)
    tests, complete, unmapped, states, locations = _tap(root, phase, text)
    if phase in ('predecessor', 'upgrade', 'replay', 'authority-upgrade') and exit_code not in (None, 0):
        states = sorted(set(re.findall(r'^MIGRATION_FAILED ([0-9A-Z]{5})(?: |$)', text, re.M)))[:16]
    cleanup = value.get('cleanup', {})
    require(type(cleanup) is dict)
    require(set(cleanup) <= {'ownedRemoved', 'resourceInventoryPreserved'} and all(type(flag) is bool for flag in cleanup.values()))
    flags = {name: cleanup.get(name) is True for name in ('ownedRemoved', 'resourceInventoryPreserved')}
    return {'schema_version': 1, 'purpose': 'FAILURE_DIAGNOSTIC_ONLY', 'outcome': 'NOT_PASSED',
        'commit': commit, 'command': COMMAND, 'profile': PROFILE,
        'started_at': value['started_at'], 'recorded_at': value['recorded_at'],
        'failed_phase': phase, 'category': category, 'exit_code': exit_code,
        'command_log_sha256': command_digest, 'sqlstates': states, 'tests': tests,
        'failure_locations': locations, 'tap_complete': complete, 'unmapped_test_output': unmapped,
        'command_log_available': selected is not None, 'cleanup': flags,
        'source_files': sources, 'source_inventory_sha256': digest(json.dumps(sources, sort_keys=True, separators=(',', ':')).encode()),
        'log_digests': log_digests,
        'limitations': ['Diagnostic evidence only; no successful test, migration, runtime or release qualification.',
            'Only exact static test declarations and fixed tagged SQLSTATEs are exported; missing or incomplete output may leave the cause unknown.',
            'Raw logs, test titles, messages, SQL, credentials and private paths remain private; cleanup flags are runner observations.']}


def safe_report(root, value, commit):
    try:
        return _safe_report(root, value, commit)
    except (OSError, ValueError, TypeError, KeyError, IndexError, OverflowError):
        return None


def load_report(root, commit):
    try:
        return safe_report(root, strict_json(read_file(root, REPORT, 4*MIB)), commit)
    except (OSError, ValueError, TypeError, KeyError):
        return None
