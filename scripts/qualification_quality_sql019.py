#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact SQL019 quality module binding, solely for its historical native phase.

Later full-chain gates may already mount these same bytes. Those mounts retain
precedence only after exact identity checks; no product fallback is installed.
"""
import hashlib
import json
from pathlib import Path
import re

COMMIT = 'ee21065ed1d4fd07878d59f8e8c825d3335c881f'
PHASE = 'quality-native-tests'
REPOSITORY = 'apps/api/src/repository.ts'
PROBE_TARGET = '/app/quality-sql019-check.cjs'
BINDINGS = {
    'packages/domain/src/quality-service.ts': ('tests/qualification/predecessors/quality-service-sql022.ts.txt', '9d510d1cf4eb5a99c6667efad7eea9c4ed302ce450d469b77a086f428410b982', '80160627852ff36f7c8d58f99171cce996e2a94c'),
    'packages/domain/src/quality.ts': ('tests/qualification/predecessors/quality-sql022.ts.txt', 'e9ef493c57c149154efd627204dde21dd1f3d7277afcbd108d5e7dd9423bace0', 'bb3b725212a622fa65345fa8cb77bde706f27135'),
    'packages/domain/src/quality-contracts.ts': ('tests/qualification/predecessors/quality-contracts-sql022.ts.txt', '21b61ae254b6633f74bf071a68301d8a5cc6f077dc3fb58d938bd22e36163a83', '5b5763224209e406b0f076e0ba15d2a4e83035e1'),
    REPOSITORY: ('tests/qualification/predecessors/repository-sql020.ts.txt', 'b7ac63819810bf1df411307537d114525f284c489384e8db570626c92ccb2a08', '179df94770bb2f51d983737c7134f29ce338f10f'),
}
INPUTS = frozenset(('scripts/qualification_quality_sql019.py', *(row[0] for row in BINDINGS.values())))


def require(value, message):
    if not value:
        raise RuntimeError(message)


def sha(content):
    return hashlib.sha256(content).hexdigest()


def checked(file, expected):
    file = Path(file)
    require(not file.is_symlink() and file.is_file() and file.stat().st_size <= 262144,
            'SQL019 qualification source unavailable')
    with file.open('rb') as stream:
        data = stream.read(262145)
    require(0 < len(data) <= 262144 and sha(data) == expected, 'SQL019 qualification source differs')
    return data


def fixture(root, path):
    name, digest, blob = BINDINGS[path]
    data = checked(root / name, digest)
    require(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data, usedforsecurity=False).hexdigest() == blob,
            'SQL019 qualification Git identity differs')
    return data


def historical_imports(root, path):
    return fixture(root, path).decode() if path in BINDINGS else ''


def expected_sources():
    return [{'path': path, 'sha256': row[1]} for path, row in sorted(BINDINGS.items())]


def verifier():
    return ("const fs=require('node:fs'),crypto=require('node:crypto');\n"
            'const rows=' + json.dumps(expected_sources(), separators=(',', ':')) + ';\n'
            "function check(){for(const row of rows)if(crypto.createHash('sha256').update(fs.readFileSync('/app/'+row.path)).digest('hex')!==row.sha256)throw new Error('QUALITY_SQL019_SOURCE_MISMATCH');}\n"
            "check();process.on('exit',check);\n")


def readback(h):
    require(h.phase == PHASE, 'SQL019 readback outside its historical native phase')
    code = ("const fs=require('node:fs'),crypto=require('node:crypto');const paths="
            + json.dumps(sorted(BINDINGS))
            + ";console.log(JSON.stringify(paths.map(path=>({path,sha256:crypto.createHash('sha256').update(fs.readFileSync('/app/'+path)).digest('hex')}))));")
    observed = h.helper(['node', '-e', code], timeout=30)
    require(observed.returncode == 0 and len(observed.stdout.encode()) <= 4096,
            'SQL019 mounted source readback failed')
    rows = json.loads(observed.stdout)
    require(rows == expected_sources(), 'SQL019 mounted source readback differs')
    return rows


def related(left, right):
    return left == right or left.startswith(right.rstrip('/') + '/') or right.startswith(left.rstrip('/') + '/')


def run(h, inherited, args, *, root, inventory, repository_phase, mounts=(), **kwargs):
    if h.phase != PHASE:
        return inherited(args, mounts=mounts, **kwargs)
    require(args and args[0] == 'node', 'SQL019 source phase requires Node')
    require(all(set(row) == {'path', 'sha256'} and isinstance(row['path'], str)
                and isinstance(row['sha256'], str) and re.fullmatch('[a-f0-9]{64}', row['sha256']) for row in inventory)
            and len({row['path'] for row in inventory}) == len(inventory), 'SQL019 source inventory malformed')
    original = h.repository_stage
    require(type(original) is dict, 'SQL019 repository phase is absent')
    repo_file, repo_digest, _ = BINDINGS[REPOSITORY]
    current = original.get('name') == 'current' and original.get('override') is False
    if not current:
        require(isinstance(original.get('name'), str) and re.fullmatch(r'classification020-[1-9][0-9]*', original['name'])
                and original.get('override') is True and original.get('sha256') == repo_digest,
                'SQL019 outer repository binding differs')
        checked(original['file'], repo_digest)
    rows = {row['path']: row['sha256'] for row in inventory}
    selected, checks, additions = [], [], []
    mounts = tuple(mounts)
    require(all(not related(target, PROBE_TARGET) for _, target in mounts), 'SQL019 verifier mount conflicts')
    for path, (name, digest, blob) in BINDINGS.items():
        require(path in rows and rows.get(name) == digest, 'SQL019 source inventory omits exact binding')
        checked(root / path, rows[path]); fixture(root, path)
        target = '/app/' + path
        found = [(Path(host), other) for host, other in mounts if related(other, target)]
        if path == REPOSITORY:
            require(not found, 'SQL019 repository mount must use its existing phase')
        else:
            require(not found or len(found) == 1 and found[0][1] == target, 'SQL019 module mount conflicts')
            if found:
                checked(found[0][0], digest)
                checks.append((found[0][0], digest))
            else:
                additions.append((root / name, target))
        selected.append({'path': path, 'fixture': name, 'commit': COMMIT, 'gitBlob': blob,
                         'sha256': digest, 'checkoutSha256': rows[path], 'mountTarget': target, 'readOnly': True,
                         'delegated': not current if path == REPOSITORY else bool(found)})
    serial = len(h.report.get('quality019ModuleChecks', [])) + 1
    probe = h.folder / ('quality-sql019-' + str(serial) + '.cjs')
    body = verifier().encode()
    with probe.open('xb') as stream:
        stream.write(body)
    probe.chmod(0o444)
    record = {'phase': PHASE, 'result': 'RUNNING', 'bindings': selected,
              'effectiveModuleSources': expected_sources(), 'verifierSha256': sha(body),
              'scope': 'These four exact SQL019 modules only; inherited source records retain any approval-family overrides.'}
    h.report.setdefault('quality019ModuleChecks', []).append(record)
    try:
        # Keep the public current/False entry seam intact: an outer SQL020
        # wrapper can substitute first. Standalone SQL019 installs the same pin.
        if current:
            require(original['file'] == root / REPOSITORY and original['sha256'] == rows[REPOSITORY],
                    'SQL019 current repository declaration differs')
            h.repository_stage = repository_phase(h, 'sql019-' + str(serial), root / repo_file, repo_digest, True)
        result = inherited([args[0], '--require', PROBE_TARGET, *args[1:]],
                           mounts=[*mounts, *additions, (probe, PROBE_TARGET)], **kwargs)
        record.update(result='PASS' if result.returncode == 0 else 'NONZERO', exitStatus=result.returncode)
        return result
    except BaseException:
        record['result'] = 'FAIL'
        raise
    finally:
        h.repository_stage = original
        record['overrideReleased'] = True
        try:
            checked(probe, sha(body))
            for path in BINDINGS:
                fixture(root, path); checked(root / path, rows[path])
            for file, digest in checks:
                checked(file, digest)
            if not current:
                checked(original['file'], repo_digest)
            record['sourceHashesMatched'] = True
        except BaseException:
            record.update(result='FAIL', sourceHashesMatched=False)
            raise
