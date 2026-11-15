#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded, pinned public-repository CodeQL runner. No application install or upload."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
from urllib.parse import quote, unquote, urlparse
from urllib.request import urlopen
import uuid

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / 'policies/sast-policy.json'
CONFIG = ROOT / '.github/codeql/codeql-config.yml'
LANGUAGES = ('javascript-typescript', 'python', 'actions')
GIB = 1024 ** 3


class Rejected(Exception):
    """A bounded failure reason safe to include in the public execution summary."""


def require(condition, reason):
    if not condition:
        raise Rejected(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_hash(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(chunk)
    return value.hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate-json-key')
        result[key] = value
    return result


def read_json(path, limit=20 * 1024 * 1024):
    require(path.is_file() and not path.is_symlink(), 'missing-or-symlink-report')
    require(path.stat().st_size <= limit, 'report-size-limit')
    try:
        return json.loads(path.read_text(), object_pairs_hook=unique_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Rejected('non-finite-json')))
    except (ValueError, UnicodeError):
        raise Rejected('malformed-json') from None


def safe_path(value):
    require(isinstance(value, str) and value and '\\' not in value and '\x00' not in value,
            'invalid-relative-path')
    path = PurePosixPath(value)
    require(not path.is_absolute() and all(part not in ('', '.', '..') for part in value.split('/')),
            'invalid-relative-path')
    require(not any(ord(char) < 32 for char in value), 'control-character-path')
    return value


def expected_language(path, data=b''):
    if path.endswith(('.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts')):
        return 'javascript-typescript'
    if path.endswith('.py'):
        return 'python'
    # Extensionless developer tools must be required, not merely incidental extraction.
    first_line = data.split(b'\n', 1)[0][:1024]
    if first_line.startswith(b'#!') and re.search(rb'(?:^|[/ \t])python(?:[0-9]+(?:\.[0-9]+)*)?(?:[ \t\r]|$)', first_line):
        return 'python'
    if first_line.startswith(b'#!') and re.search(rb'(?:^|[/ \t])node(?:[ \t\r]|$)', first_line):
        return 'javascript-typescript'
    if ((path.startswith('.github/workflows/') and path.endswith(('.yml', '.yaml')))
            or PurePosixPath(path).name in ('action.yml', 'action.yaml')):
        return 'actions'
    return None


def git(root, *args):
    result = subprocess.run(['git', *args], cwd=root, capture_output=True, check=True, timeout=30)
    return result.stdout


def snapshot(root, destination, policy):
    # Include staged, unstaged and new publishable files; ignore developer secrets/build data.
    names = sorted(set(git(root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard')
                       .decode('utf-8').rstrip('\0').split('\0')))
    require(0 < len(names) <= policy['maxSourceFiles'], 'source-file-limit')
    exclusions = policy['coverageExclusions']
    require(exclusions == [], 'coverage-exclusions-require-reviewed-policy-change')
    files, total = {}, 0
    destination.mkdir(parents=True, exist_ok=False)
    for name in names:
        safe_path(name)
        path = root / name
        if not path.exists() and not path.is_symlink():
            continue  # A tracked worktree deletion is part of this precise snapshot.
        require(not path.is_symlink() and path.is_file(), 'source-symlink-or-submodule')
        require(path.resolve().is_relative_to(root.resolve()), 'source-outside-root')
        size = path.stat().st_size
        total += size
        require(total <= policy['maxSourceBytes'], 'source-byte-limit')
        data = path.read_bytes()
        require(len(data) == size, 'source-changed-during-snapshot')
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        files[name] = {'sha256': digest(data), 'bytes': size, 'language': expected_language(name, data)}
    expected = {language: sorted(name for name, row in files.items() if row['language'] == language)
                for language in LANGUAGES}
    require(all(expected.values()), 'expected-language-has-no-source')
    # File bytes, HEAD and dirty status are independently captured; a dirty tree is not its HEAD.
    head = git(root, 'rev-parse', 'HEAD').decode().strip()
    require(re.fullmatch('[0-9a-f]{40}', head), 'invalid-git-head')
    manifest = {'schemaVersion': 1, 'head': head,
                'dirty': bool(git(root, 'status', '--porcelain', '--untracked-files=all')),
                'files': files, 'expected': expected, 'bytes': total,
                'exclusions': ['git-ignored files', 'deleted worktree files',
                               'other file types copied but outside the three language scopes']}
    manifest['sourceDigest'] = digest(canonical(files))
    verify_snapshot(destination, manifest)
    # Detect edits during the copy, including files changed after their own copy.
    for name, row in files.items():
        require((root / name).is_file() and file_hash(root / name) == row['sha256'],
                'source-changed-during-snapshot')
    require(git(root, 'rev-parse', 'HEAD').decode().strip() == head, 'head-changed-during-snapshot')
    after_names = sorted(set(git(root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard').decode('utf-8').rstrip('\0').split('\0')))
    require(after_names == names, 'source-file-set-changed-during-snapshot')
    # git ls-files includes deleted tracked paths, so an unchanged listing alone
    # cannot detect a tracked file restored after its absent copy slot.
    present_names = {name for name in after_names if (root / name).exists() or (root / name).is_symlink()}
    require(present_names == set(files), 'source-presence-changed-during-snapshot')
    return manifest


def verify_snapshot(source, manifest):
    actual = {p.relative_to(source).as_posix() for p in source.rglob('*') if not p.is_dir()}
    require(actual == set(manifest['files']), 'snapshot-file-set-changed')
    for name, row in manifest['files'].items():
        path = source / safe_path(name)
        require(not path.is_symlink() and file_hash(path) == row['sha256'], 'snapshot-bytes-changed')
    require(digest(canonical(manifest['files'])) == manifest['sourceDigest'], 'snapshot-digest-mismatch')


def platform_key():
    system = platform.system().lower()
    machine = {'x86_64': 'x64', 'amd64': 'x64', 'aarch64': 'arm64', 'arm64': 'arm64'}.get(platform.machine().lower())
    require(system in ('linux', 'darwin') and machine, 'platform-unsupported-use-linux-or-wsl2')
    return f'{system}-{machine}'


def capacity(path, minimum):
    require(shutil.disk_usage(path).free >= minimum, 'disk-budget-refused')


def tool_inventory(directory):
    rows = {}
    for path in sorted(directory.rglob('*')):
        name = path.relative_to(directory).as_posix()
        if name == 'provenance.json':
            continue
        if path.is_symlink():
            require(path.resolve().is_relative_to(directory.resolve()), 'tool-symlink-outside-bundle')
            rows[name] = {'link': os.readlink(path)}
        elif path.is_file():
            rows[name] = {'sha256': file_hash(path), 'executable': bool(path.stat().st_mode & stat.S_IXUSR)}
    return rows


def install(toolchain, policy, target_platform=None, archive_path=None):
    require(not toolchain.exists(), 'toolchain-already-exists-no-overwrite')
    selected_platform = target_platform or platform_key()
    require(selected_platform in policy['bundles'], 'unsupported-target-platform')
    bundle = policy['bundles'][selected_platform]
    toolchain.parent.mkdir(parents=True, exist_ok=True)
    capacity(toolchain.parent, (0 if archive_path else bundle['bytes']) + (bundle['unpackedBudgetGiB'] + policy['diskFloorGiB']) * GIB)
    staging = toolchain.parent / ('install-' + uuid.uuid4().hex)
    staging.mkdir(mode=0o700)
    archive = Path(archive_path).resolve() if archive_path else staging / 'bundle.tar.gz'
    url = f"https://github.com/github/codeql-action/releases/download/{policy['bundleRelease']}/{bundle['file']}"
    try:
        if not archive_path:
            with urlopen(url, timeout=60) as response, archive.open('xb') as output:
                size = 0
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    require(size <= bundle['bytes'], 'bundle-size-mismatch')
                    capacity(staging, policy['diskFloorGiB'] * GIB)
                    output.write(chunk)
        require(archive.is_file() and not archive.is_symlink() and archive.stat().st_size == bundle['bytes']
                and file_hash(archive) == bundle['sha256'], 'bundle-checksum-mismatch')
        extracted = staging / 'extracted'
        extracted.mkdir()
        with tarfile.open(archive, 'r:gz') as tar:
            members = tar.getmembers()
            require(len(members) <= 200000, 'bundle-file-limit')
            require(sum(m.size for m in members) <= bundle['unpackedBudgetGiB'] * GIB, 'bundle-unpacked-budget')
            for member in members:
                name = safe_path(member.name.rstrip('/'))
                require(name == 'codeql' or name.startswith('codeql/'), 'unexpected-bundle-root')
                require(member.isfile() or member.isdir() or member.issym() or member.islnk(), 'unsafe-bundle-member')
                target = extracted / name
                require(target.resolve().is_relative_to(extracted.resolve()), 'unsafe-bundle-path')
                if member.issym() or member.islnk():
                    link = (target.parent if member.issym() else extracted) / member.linkname
                    require(not PurePosixPath(member.linkname).is_absolute()
                            and link.resolve().is_relative_to((extracted / 'codeql').resolve()), 'unsafe-bundle-link')
                capacity(staging, policy['diskFloorGiB'] * GIB)
                # Archive digest is checked first; all member/link targets are independently bounded.
                tar.extract(member, extracted)
        installed = extracted / 'codeql'
        write_json(installed / 'provenance.json', {'version': policy['cliVersion'], 'platform': selected_platform,
                   'bundle': bundle, 'files': tool_inventory(installed)})
        installed.rename(toolchain)
    finally:
        shutil.rmtree(staging)  # Only this invocation's newly-created staging tree.


def verify_toolchain(toolchain, policy, target_platform=None):
    selected_platform = target_platform or platform_key()
    record = read_json(toolchain / 'provenance.json', 64 * 1024 * 1024)
    require(record.get('version') == policy['cliVersion'] and record.get('platform') == selected_platform
            and record.get('bundle') == policy['bundles'][selected_platform], 'toolchain-pin-mismatch')
    require(record.get('files') == tool_inventory(toolchain), 'toolchain-content-mismatch')
    require((toolchain / 'codeql').is_file(), 'missing-codeql-executable')
    return record


def coverage(decoded, manifest, language):
    require(isinstance(decoded, dict) and set(decoded) == {'#select'}, 'coverage-result-sets')
    table = decoded['#select']
    require(isinstance(table, dict) and 'next' not in table, 'coverage-truncated')
    require(table.get('columns') == [{'name': 'path', 'kind': 'String'}], 'coverage-columns')
    tuples = table.get('tuples')
    require(isinstance(tuples, list) and tuples, 'coverage-empty')
    require(all(isinstance(row, list) and len(row) == 1 and isinstance(row[0], str) for row in tuples),
            'coverage-malformed-row')
    paths = {safe_path(row[0]) for row in tuples}
    require(paths <= set(manifest['files']), 'coverage-outside-snapshot')
    expected = set(manifest['expected'][language])
    require(expected and expected <= paths, 'coverage-incomplete')
    return {'expectedFiles': len(expected), 'extractedExpectedFiles': len(expected & paths),
            'databaseFiles': len(paths), 'extractedPathsDigest': digest(canonical(sorted(paths)))}


def timestamp(value):
    require(isinstance(value, str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value), 'triage-invalid-time')
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    except ValueError:
        raise Rejected('triage-invalid-time') from None


def triage_register(value):
    require(isinstance(value, dict) and set(value) == {'schemaVersion', 'decisions'}
            and value['schemaVersion'] == 1 and isinstance(value['decisions'], list), 'triage-schema')
    decisions = {}
    fields = {'fingerprint', 'disposition', 'owner', 'reviewedBy', 'reviewUrl', 'reviewedAt', 'expiresAt',
              'component', 'exploitability', 'exposure', 'evidence', 'mitigation'}
    for decision in value['decisions']:
        require(isinstance(decision, dict) and set(decision) == fields, 'triage-decision-schema')
        key = decision['fingerprint']
        require(isinstance(key, str) and re.fullmatch('[0-9a-f]{64}', key) and key not in decisions,
                'triage-fingerprint-invalid-or-duplicate')
        require(decision['disposition'] in ('false_positive', 'accepted_risk', 'remediation_pending'), 'triage-disposition')
        require(all(isinstance(decision[k], str) and 1 <= len(decision[k]) <= 4000 for k in fields), 'triage-empty-fields')
        for keyname in ('owner', 'reviewedBy'):
            require(re.fullmatch(r'@[A-Za-z0-9][A-Za-z0-9-]{0,38}', decision[keyname]), 'triage-real-account-required')
        require(decision['reviewUrl'].startswith('https://'), 'triage-review-link-required')
        timestamp(decision['reviewedAt']); timestamp(decision['expiresAt'])
        decisions[key] = decision
    return decisions


def artifact_path(location, run):
    if 'uri' not in location and isinstance(location.get('index'), int):
        artifacts = run.get('artifacts', [])
        index = location['index']
        require(0 <= index < len(artifacts), 'finding-artifact-index')
        location = artifacts[index]['location']
    require(location.get('uriBaseId') in (None, '%SRCROOT%'), 'finding-unknown-uri-base')
    uri = location.get('uri')
    require(isinstance(uri, str) and not urlparse(uri).scheme and not urlparse(uri).netloc,
            'finding-not-source-relative')
    return safe_path(unquote(uri))


def evaluate_sarif(sarif, manifest, language, policy, decisions, now):
    require(isinstance(sarif, dict) and sarif.get('version') == '2.1.0', 'sarif-version')
    runs = sarif.get('runs')
    require(isinstance(runs, list) and len(runs) == 1, 'sarif-run-count')
    run = runs[0]
    driver = run.get('tool', {}).get('driver', {})
    require(driver.get('name') in ('CodeQL', 'CodeQL command-line toolchain')
            and driver.get('semanticVersion', driver.get('version')) == policy['cliVersion'], 'sarif-tool-pin')
    require(run.get('automationDetails', {}).get('id', '').rstrip('/') == f'governance-commons/{language}', 'sarif-language-category')
    invocations = run.get('invocations')
    require(isinstance(invocations, list) and invocations and
            all(inv.get('executionSuccessful') is True for inv in invocations), 'sarif-invocation-not-successful')
    for invocation in invocations:
        require(invocation.get('exitCode', 0) == 0, 'sarif-invocation-exit')
        for field in ('toolExecutionNotifications', 'toolConfigurationNotifications'):
            for notification in invocation.get(field, []):
                # Even a successful process can report partial extraction/query warnings.
                require(notification.get('level', 'warning') in ('none', 'note'), 'sarif-warning-or-error-diagnostic')
    rules = {}
    for component in [driver, *run.get('tool', {}).get('extensions', [])]:
        for rule in component.get('rules', []):
            require(rule.get('id') not in rules, 'sarif-duplicate-rule')
            rules[rule['id']] = rule
    require(rules, 'sarif-no-query-rules')
    results = run.get('results')
    require(isinstance(results, list), 'sarif-missing-results')
    findings = []
    for result in results:
        rule_id = result.get('ruleId')
        require(rule_id in rules, 'sarif-unknown-rule')
        rule = rules[rule_id]
        properties = rule.get('properties', {})
        numeric = properties.get('security-severity')
        if numeric is not None:
            require(type(numeric) in (str, int, float), 'unknown-finding-severity')
            try:
                score = float(numeric)
            except (ValueError, TypeError):
                raise Rejected('unknown-finding-severity') from None
            require(math.isfinite(score) and 0 <= score <= 10, 'unknown-finding-severity')
            severity = 'critical' if score >= 9 else 'high' if score >= 7 else 'medium' if score >= 4 else 'low'
        else:
            require('security' not in properties.get('tags', []), 'security-finding-without-severity')
            level = rule.get('defaultConfiguration', {}).get('level')
            require(level in ('error', 'warning', 'note'), 'unknown-finding-severity')
            severity = {'error': 'high', 'warning': 'medium', 'note': 'low'}[level]
        locations = result.get('locations')
        require(isinstance(locations, list) and len(locations) >= 1, 'finding-missing-location')
        physical = locations[0].get('physicalLocation', {})
        path = artifact_path(physical.get('artifactLocation', {}), run)
        require(path in manifest['files'], 'finding-outside-snapshot')
        region = physical.get('region', {})
        line = region.get('startLine')
        require(type(line) is int and line > 0, 'finding-missing-line')
        line_hash = result.get('partialFingerprints', {}).get('primaryLocationLineHash')
        require(isinstance(line_hash, str) and line_hash, 'finding-missing-fingerprint')
        fingerprint = digest(canonical({'ruleId': rule_id, 'language': language, 'path': path,
                             'fileSha256': manifest['files'][path]['sha256'], 'lineHash': line_hash,
                             'queryPackVersion': policy['languages'][language]['queryVersion']}))
        decision = decisions.get(fingerprint)
        disposition, blocking = 'untriaged', True
        if decision:
            reviewed, expires = timestamp(decision['reviewedAt']), timestamp(decision['expiresAt'])
            require(reviewed <= now < expires and expires - reviewed <= timedelta(days=policy['maxExceptionDays']),
                    'triage-expired-or-invalid-window')
            disposition = decision['disposition']
            blocking = disposition == 'remediation_pending' and severity in ('high', 'critical')
        # SARIF/source suppressions never independently authorize dismissal.
        if result.get('suppressions') and disposition not in ('false_positive', 'accepted_risk'):
            blocking = True
        findings.append({'fingerprint': fingerprint, 'ruleId': rule_id, 'path': path, 'line': line,
                         'severity': severity, 'disposition': disposition, 'blocking': blocking,
                         'sourceSuppressed': bool(result.get('suppressions'))})
    return findings


def aggregate(job_results):
    return set(job_results) == set(LANGUAGES) and all(value == 'success' for value in job_results.values())


def publish_sarif(raw, destination, replacements):
    # The original report stays local. No source snippets, command lines or local absolute roots in public artifacts.
    def scrub(value):
        if isinstance(value, dict):
            return {key: scrub(item) for key, item in value.items()
                    if key not in ('contents', 'snippet', 'commandLine', 'environmentVariables', 'executableLocation')}
        if isinstance(value, list):
            return [scrub(item) for item in value]
        if isinstance(value, str):
            for original, replacement in replacements:
                value = value.replace(original, replacement)
                # SARIF pack/file URIs percent-encode spaces and non-ASCII path
                # segments; scrub those spellings as well as ordinary log text.
                value = value.replace(quote(original, safe='/'), quote(replacement, safe='/'))
                value = value.replace(quote(original, safe=''), quote(replacement, safe=''))
        return value
    write_json(destination, scrub(raw))


# Diagnostic hints only: fixed public labels, never a log excerpt, path or source value.
# Their presence cannot change extraction, coverage, findings or upload outcomes.
FAILURE_MARKERS = {
    'database_initializing': b'initializing database',
    'build_command_started': b'running build command',
    'extractor_command_started': b'running command',
    'database_finalizing': b'finalizing database',
    'trap_import_started': b'running trap import',
    'fatal_error': b'a fatal error occurred',
    'spawn_abnormal': b'spawned process exited abnormally',
    'permission_denied': b'permission denied',
    'operation_not_permitted': b'operation not permitted',
    'missing_file': b'no such file or directory',
    'executable_not_found': b'executable file not found',
    'cannot_start_process': b'cannot run program',
    'no_source_code': b'no source code',
    'environment_required': b'must be set',
    'unknown_option': b'unknown option',
    'unrecognized_option': b'unrecognized option',
    'invalid_option': b'invalid option',
    'out_of_memory': b'outofmemoryerror',
    'heap_limit': b'heap limit',
    'insufficient_memory': b'not enough memory',
    'disk_full': b'no space left on device',
    'execution_format': b'exec format error',
    'shared_library_missing': b'error while loading shared libraries',
    'unsatisfied_native_link': b'unsatisfiedlinkerror',
    'null_pointer': b'nullpointerexception',
    'initialization_error': b'exceptionininitializererror',
    'class_not_found': b'classnotfoundexception',
    'illegal_argument': b'illegalargumentexception',
    'syntax_error': b'syntax error',
    'connection_refused': b'connection refused',
    'name_resolution': b'name or service not known',
}


def scanner_failure_diagnostics(stdout, stderr, max_bytes):
    result = {'schemaVersion': 1, 'scope': 'FIXED_MARKERS_ONLY_NOT_A_CAUSE_DETERMINATION', 'streams': {}}
    for label, path in [('stdout', stdout), ('stderr', stderr)]:
        try:
            require(not path.is_symlink(), 'diagnostic-symlink')
            size = path.stat().st_size
            if size > max_bytes:
                result['streams'][label] = {'bytes': size, 'available': False, 'reason': 'diagnostic-log-limit'}
                continue
            with path.open('rb') as stream:
                first = stream.read(32768)
                stream.seek(max(len(first), size - 32768))
                last = stream.read(32768)
            sample = first.lower() + b'\n' + last.lower()
            result['streams'][label] = {'bytes': size, 'sha256': file_hash(path), 'available': True,
                'sample': 'HEAD_AND_TAIL_UP_TO_64_KIB',
                'markers': sorted(marker for marker, needle in FAILURE_MARKERS.items() if needle in sample)}
        except (OSError, Rejected):
            result['streams'][label] = {'available': False, 'reason': 'diagnostic-unavailable'}
    return result


def container_command(container, args, cwd, name):
    platform_name = 'linux/arm64' if container['platform'] == 'linux-arm64' else 'linux/amd64'
    output, toolchain = container['output'], container['toolchain']
    # All paths preserve their absolute spelling so the same CLI commands/reports work natively.
    # No application volumes, credentials, Docker socket, network, persistent container or image pull.
    return ['docker', 'run', '--rm', '--name', name, '--pull=never', '--platform', platform_name,
            '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--pids-limit=256', '--cpus=2', '--memory=4g', '--user', f'{os.getuid()}:{os.getgid()}',
            '--tmpfs', '/tmp:rw,nosuid,size=268435456',
            '--mount', f'type=bind,source={toolchain},target={toolchain},readonly',
            '--mount', f'type=bind,source={output},target={output}',
            '--mount', f'type=bind,source={output / "source"},target={output / "source"},readonly',
            '--workdir', str(cwd), '--entrypoint', args[0], container['image'], *args[1:]]


class Runner:
    def __init__(self, output, policy, container=None):
        self.output, self.policy, self.container = output, policy, container
        self.deadline = time.monotonic() + policy['languageTimeoutSeconds']
        self.steps = []
        self.failure_diagnostics = None

    def command(self, name, args, cwd):
        started = time.monotonic()
        self.failure_diagnostics = None
        capacity(self.output, self.policy['diskFloorGiB'] * GIB)
        log = self.output / f'{name}.log'
        stdout = self.output / f'{name}.stdout'
        env = {key: os.environ[key] for key in ('PATH', 'LANG', 'LC_ALL', 'TMPDIR', 'SYSTEMROOT') if key in os.environ}
        # Do not inherit tokens, provider credentials, extractor overrides or arbitrary CodeQL options.
        invocation = [str(arg) for arg in args]
        owned_container = None
        if self.container:
            owned_container = 'gc-sast-' + uuid.uuid4().hex
            invocation = container_command(self.container, invocation, cwd, owned_container)
        with log.open('wb') as stream, stdout.open('wb') as output_stream:
            process = subprocess.Popen(invocation, cwd=cwd, env=env,
                                       stdout=output_stream, stderr=stream, start_new_session=True)
            try:
                while process.poll() is None:
                    require(time.monotonic() < self.deadline, 'language-timeout')
                    capacity(self.output, self.policy['diskFloorGiB'] * GIB)
                    require(log.stat().st_size + stdout.stat().st_size <= self.policy['maxReportBytes'], 'scanner-log-limit')
                    time.sleep(0.25)
                require(time.monotonic() < self.deadline, 'language-timeout')
                require(log.stat().st_size + stdout.stat().st_size <= self.policy['maxReportBytes'], 'scanner-log-limit')
                self.steps.append({'step': name, 'exitCode': process.returncode, 'durationSeconds': round(time.monotonic() - started, 3)})
                if process.returncode != 0:
                    self.failure_diagnostics = scanner_failure_diagnostics(stdout, log, self.policy['maxReportBytes'])
                require(process.returncode == 0, f'scanner-command-failed:{name}')
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
                if owned_container:
                    # Killing the Docker client does not reliably stop its container. Remove only
                    # this invocation's unpredictable name, including timeout/floor/cancellation paths.
                    subprocess.run(['docker', 'container', 'rm', '--force', owned_container],
                                   env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        return stdout


def scan_language(language, output, source, manifest, toolchain, policy, decisions, container=None):
    spec = policy['languages'][language]
    folder = output / language
    folder.mkdir()
    runner = Runner(folder, policy, container)
    summary = {'schemaVersion': 1, 'language': language, 'sourceDigest': manifest['sourceDigest'],
               'head': manifest['head'], 'dirty': manifest['dirty'], 'analysis': 'NOT_PASSED',
               'findingsGate': 'NOT_EVALUATED', 'upload': 'NOT_ATTEMPTED', 'steps': runner.steps,
               'cliVersion': policy['cliVersion'], 'queryPack': spec['queryPack'], 'queryVersion': spec['queryVersion'],
               'containerImage': container['image'] if container else None}
    try:
        cli = toolchain / 'codeql'
        if 'runtime' in spec:
            runtime = runner.command('extractor-runtime', [spec['runtime']['command'], '--version'], source).read_text().strip()
            require(runtime == spec['runtime']['version'], 'extractor-runtime-version-mismatch')
            summary['extractorRuntime'] = runtime
        common = [f'--common-caches={folder / "cache"}']
        version_log = runner.command('version', [cli, 'version', '--format=json', *common], source)
        require(read_json(version_log).get('version') == policy['cliVersion'], 'resolved-cli-version-mismatch')
        # Force all library dependencies to the verified bundle, never a developer's external pack cache.
        packs = sorted({p.parent for p in toolchain.glob('qlpacks/*/*/*/qlpack.yml')})
        query_root = toolchain / 'qlpacks' / spec['queryPack'] / spec['queryVersion']
        library_root = toolchain / 'qlpacks' / spec['library'] / spec['libraryVersion']
        require(query_root in packs and library_root in packs, 'expected-bundled-pack-version-missing')
        summary['library'] = spec['library']
        summary['libraryVersion'] = spec['libraryVersion']
        summary['coverageQuerySha256'] = file_hash(source / f'policies/codeql/{language}/ExtractedPaths.ql')
        require(packs, 'bundle-has-no-packs')
        search = '--additional-packs=' + os.pathsep.join(str(path) for path in packs)
        suites = [f"{spec['queryPack']}@{spec['queryVersion']}:codeql-suites/{spec['extractor']}-{suite}.qls"
                  for suite in policy['suites']]
        resolved = runner.command('queries', [cli, 'resolve', 'queries', '--format=json', search, *common, *suites], source)
        paths = read_json(resolved)
        require(isinstance(paths, list) and paths and all(isinstance(p, str) for p in paths), 'empty-resolved-query-set')
        query_hashes = {}
        for value in paths:
            path = Path(value).resolve()
            require(path.is_relative_to(query_root.resolve()) and path.is_file(), 'query-outside-exact-verified-pack')
            query_hashes[path.relative_to(toolchain).as_posix()] = file_hash(path)
        summary['querySetDigest'] = digest(canonical(query_hashes))
        summary['queryCount'] = len(query_hashes)
        write_json(folder / 'queries.json', query_hashes)
        db = folder / 'database'
        runner.command('extract', [cli, 'database', 'create', db, f'--language={spec["extractor"]}',
                       '--build-mode=none', f'--source-root={source}', f'--codescanning-config={source / ".github/codeql/codeql-config.yml"}',
                       f'--threads={policy["threads"]}', f'--ram={policy["ramMiB"]}', *common], source)
        raw = folder / 'raw.sarif'
        runner.command('analyze', [cli, 'database', 'analyze', db, *suites, search, *common,
                       '--format=sarifv2.1.0', f'--output={raw}', f'--sarif-category=governance-commons/{language}',
                       '--sarif-add-baseline-file-info', '--sarif-include-diagnostics',
                       '--no-sarif-add-file-contents', '--no-sarif-add-snippets', '--sarif-include-query-help=never',
                       '--no-default-compilation-cache', '--min-disk-free=2048',
                       f'--threads={policy["threads"]}', f'--ram={policy["ramMiB"]}'], source)
        bqrs = folder / 'coverage.bqrs'
        runner.command('coverage-query', [cli, 'query', 'run', source / f'policies/codeql/{language}/ExtractedPaths.ql',
                       f'--database={db}', f'--output={bqrs}', search, *common, '--no-default-compilation-cache',
                       '--min-disk-free=2048', f'--threads={policy["threads"]}', f'--ram={policy["ramMiB"]}'], source)
        decoded = folder / 'coverage.json'
        runner.command('coverage-decode', [cli, 'bqrs', 'decode', bqrs, '--format=json', f'--output={decoded}', *common], source)
        summary['coverage'] = coverage(read_json(decoded), manifest, language)
        sarif = read_json(raw, policy['maxReportBytes'])
        findings = evaluate_sarif(sarif, manifest, language, policy, decisions, datetime.now(timezone.utc))
        verify_snapshot(source, manifest)
        summary.update(analysis='PASS', findingsGate='BLOCKED' if any(f['blocking'] for f in findings) else 'PASS', findings=findings)
        summary['rawSarifSha256'] = file_hash(raw)
        report = output / 'public' / f'{language}.sarif'
        publish_sarif(sarif, report, [(str(source), '/governance-commons'), (str(output), '/sast-run'), (str(toolchain), '/codeql')])
        summary['publishedSarifSha256'] = file_hash(report)
    except (Rejected, OSError, ValueError, KeyError, TypeError) as error:
        summary['failure'] = str(error) if isinstance(error, Rejected) else f'invalid-scanner-output:{type(error).__name__}'
        if runner.failure_diagnostics is not None:
            summary['failureDiagnostics'] = runner.failure_diagnostics
        if isinstance(error, Rejected) and str(error) == 'scanner-cancelled':
            raise
    finally:
        write_json(output / 'public' / f'{language}-summary.json', summary)
    return summary


def repository_scope(root, repository):
    require(re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository), 'invalid-public-repository')
    remote = git(root, 'remote', 'get-url', 'origin').decode().strip().removesuffix('.git')
    require(remote in (f'https://github.com/{repository}', f'git@github.com:{repository}', f'ssh://git@github.com/{repository}'),
            'public-repository-does-not-match-origin')
    require(os.environ.get('GC_REPOSITORY_PRIVATE', 'false') == 'false', 'codeql-private-use-not-authorized')


def container_images(image, images):
    require(not (image and images), 'choose-one-container-image-option')
    if images:
        try:
            values = json.loads(images, object_pairs_hook=unique_pairs)
        except ValueError:
            raise Rejected('container-image-map-json') from None
        require(isinstance(values, dict) and set(values) == set(LANGUAGES), 'container-image-map-languages')
    elif image:
        values = dict.fromkeys(LANGUAGES, image)
    else:
        return None
    require(all(isinstance(value, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', value)
                for value in values.values()), 'container-requires-existing-immutable-image-id')
    return values


def run_scan(args, policy):
    started = time.monotonic()
    started_at = datetime.now(timezone.utc).isoformat()
    source_root = getattr(args, 'source_root', ROOT)
    images = container_images(args.container_image, args.container_images)
    repository_scope(source_root, args.public_repository or policy['publicRepository'])
    output = Path(args.output).resolve() if args.output else ROOT / '.local/sast' / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])
    require(output.is_relative_to(ROOT / '.local'), 'scan-output-must-be-in-ignored-local-directory')
    require(not output.exists(), 'output-already-exists-no-stale-reuse')
    output.parent.mkdir(parents=True, exist_ok=True)
    capacity(output.parent, policy['scanAdmissionGiB'] * GIB)
    output.mkdir(mode=0o700)
    result = {'schemaVersion': 1, 'startedAt': started_at, 'outcome': 'NOT_PASSED', 'analysis': 'NOT_PASSED', 'findingsGate': 'NOT_EVALUATED',
              'upload': 'NOT_ATTEMPTED', 'platform': args.platform or platform_key(), 'languages': {},
              'purpose': 'REPOSITORY_SOURCE' if source_root == ROOT else 'SYNTHETIC_NEGATIVE_CONTROL',
              'containerImages': images,
              'invocation': {'entrypoint': 'policies/sast.py' if source_root == ROOT else 'policies/sast_probe.py',
                             'language': args.language or 'all', 'platform': args.platform or platform_key()},
              'limitations': ['No hosted ingestion or analysis read-back in this command.',
                              'SQL/RLS, dependencies, images and general IaC are outside this source scan.',
                              'Automated findings do not replace independent security review.'], 'configurationSha256': file_hash(CONFIG),
              'policySha256': file_hash(POLICY), 'triageSha256': file_hash(ROOT / 'policies/sast-triage.json')}
    try:
        toolchain = Path(args.toolchain).resolve() if args.toolchain else ROOT / '.local/security-tools' / ('codeql-' + policy['cliVersion'])
        require(toolchain.exists(), 'toolchain-missing-run-explicit-install')
        selected_platform = args.platform or platform_key()
        if not images:
            require(not (Path.home() / '.config/codeql/config').exists(), 'native-user-codeql-config-present-use-isolated-runtime')
        require(selected_platform == platform_key() or images, 'cross-platform-scan-requires-container')
        container = None
        if images:
            require(selected_platform in ('linux-arm64', 'linux-x64'), 'container-requires-linux-platform')
            runtime_env = {key: os.environ[key] for key in ('PATH', 'LANG', 'LC_ALL', 'TMPDIR', 'SYSTEMROOT') if key in os.environ}
            endpoint = subprocess.run(['docker', 'context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'],
                                      env=runtime_env, capture_output=True, text=True, check=True, timeout=15).stdout.strip()
            require(endpoint.startswith(('unix://', 'npipe://')), 'container-requires-local-docker-context')
            subprocess.run(['docker', 'image', 'inspect', *sorted(set(images.values()))], env=runtime_env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=15)
            container = {'platform': selected_platform, 'output': output, 'toolchain': toolchain}
        provenance = verify_toolchain(toolchain, policy, selected_platform)
        result['bundleSha256'] = provenance['bundle']['sha256']
        source = output / 'source'
        manifest = snapshot(source_root, source, policy)
        write_json(output / 'public/source-manifest.json', manifest)
        require(read_json(source / 'policies/sast-policy.json') == policy, 'policy-changed-during-snapshot')
        result['configurationSha256'] = manifest['files']['.github/codeql/codeql-config.yml']['sha256']
        result['policySha256'] = manifest['files']['policies/sast-policy.json']['sha256']
        result['triageSha256'] = manifest['files']['policies/sast-triage.json']['sha256']
        result['runnerSha256'] = file_hash(Path(__file__))
        result.update(head=manifest['head'], dirty=manifest['dirty'], sourceDigest=manifest['sourceDigest'])
        decisions = triage_register(read_json(source / 'policies/sast-triage.json'))
        for language in ([args.language] if args.language else LANGUAGES):
            execution_container = {**container, 'image': images[language]} if container else None
            result['languages'][language] = scan_language(language, output, source, manifest, toolchain, policy, decisions, execution_container)
        result['analysis'] = 'PASS' if all(s['analysis'] == 'PASS' for s in result['languages'].values()) else 'NOT_PASSED'
        result['findingsGate'] = ('NOT_EVALUATED' if result['analysis'] != 'PASS' else
                                  'PASS' if all(s['findingsGate'] == 'PASS' for s in result['languages'].values()) else 'BLOCKED')
        result['scope'] = 'SINGLE_LANGUAGE' if args.language else 'ALL_REQUIRED_LANGUAGES'
        result['outcome'] = 'PASS' if result['analysis'] == 'PASS' and result['findingsGate'] == 'PASS' else 'NOT_PASSED'
    except (Rejected, OSError, subprocess.SubprocessError) as error:
        result['failure'] = str(error) if isinstance(error, Rejected) else type(error).__name__
    finally:
        result['finishedAt'] = datetime.now(timezone.utc).isoformat()
        result['durationSeconds'] = round(time.monotonic() - started, 3)
        result['freeDiskBytesAtFinish'] = shutil.disk_usage(output).free
        write_json(output / 'public/summary.json', result)
        print(json.dumps({'outcome': result['outcome'], 'analysis': result['analysis'], 'findingsGate': result['findingsGate'],
                          'report': str(output / 'public/summary.json')}))
    return result['outcome'] == 'PASS'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('install', 'run', 'aggregate'))
    parser.add_argument('--toolchain', default=os.environ.get('GC_SAST_TOOLCHAIN'))
    parser.add_argument('--archive', help='Previously downloaded bundle; exact pinned size and checksum are still verified.')
    parser.add_argument('--platform', default=os.environ.get('GC_SAST_PLATFORM'), choices=('linux-arm64', 'linux-x64', 'darwin-arm64', 'darwin-x64'))
    parser.add_argument('--container-images', default=os.environ.get('GC_SAST_CONTAINER_IMAGES'), help='JSON map of every required language to an existing immutable local image ID.')
    parser.add_argument('--container-image', default=os.environ.get('GC_SAST_CONTAINER_IMAGE'), help='Existing local immutable image ID for isolated Linux CLI execution; never pulls an image.')
    parser.add_argument('--output')
    parser.add_argument('--language', choices=LANGUAGES)
    parser.add_argument('--public-repository', help='Explicit public GitHub repository; must match origin. Not a private-use license.')
    args = parser.parse_args()
    policy = read_json(POLICY)
    if args.command == 'aggregate':
        values = {language: os.environ.get('GC_SAST_' + language.replace('-', '_').upper(), '') for language in LANGUAGES}
        print(json.dumps({'outcome': 'PASS' if aggregate(values) else 'NOT_PASSED', 'children': values}))
        return aggregate(values)
    repository_scope(ROOT, args.public_repository or policy['publicRepository'])
    if args.command == 'install':
        toolchain = Path(args.toolchain).resolve() if args.toolchain else ROOT / '.local/security-tools' / ('codeql-' + policy['cliVersion'])
        install(toolchain, policy, args.platform, args.archive)
        print('Pinned CodeQL installed. No source scan or findings pass has been claimed.')
        return True
    return run_scan(args, policy)


if __name__ == '__main__':
    def cancelled(_signal, _frame):
        raise Rejected('scanner-cancelled')
    signal.signal(signal.SIGTERM, cancelled)
    try:
        raise SystemExit(0 if main() else 1)
    except (Rejected, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({'outcome': 'NOT_PASSED', 'failure': str(error) if isinstance(error, Rejected) else type(error).__name__}))
        raise SystemExit(1)
