#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact qualification-only repository binding for SQL015–018 native suites.

No application compatibility fallback: only the four named historical native
phases may substitute this reviewed immutable module. All other checkout
dependencies remain current and are explicitly recorded by the calling gate.
"""
import hashlib
import json
from pathlib import Path
import re

REPOSITORY = 'apps/api/src/repository.ts'
TARGET = '/app/' + REPOSITORY
FIXTURE = 'tests/qualification/predecessors/repository-sql018.ts.txt'
COMMIT = 'a3e1b674fb45c13a045286d05bc3c68012370872'
BLOB = 'd741fdde750be30fec5062df4e813fc2a9cba877'
DIGEST = '02513444534aa7cbed358235478bae0ea8cdd14e3dfd3b5fe5f76897c1e9dcf6'
PROBE_TARGET = '/app/predecessor-repository-check.cjs'
OUTER_PROBE_TARGET = '/app/quality-repository-check.cjs'
PHASES = frozenset(('approval-native-tests', 'glossary-native-tests', 'scope-native-tests', 'population-native-tests'))


def require(value, message):
    if not value:
        raise RuntimeError(message)


def digest(content):
    return hashlib.sha256(content).hexdigest()


def read_exact(path, expected):
    require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 262144,
            'Qualification repository source unavailable')
    with path.open('rb') as source:
        content = source.read(262145)
    require(0 < len(content) <= 262144 and digest(content) == expected,
            'Qualification repository source hash differs')
    return content


def related(target, protected):
    return target == protected or protected.startswith(target.rstrip('/') + '/') or target.startswith(protected + '/')


def verifier_source(code):
    body = "const fs=require('node:fs'),crypto=require('node:crypto');\n"
    body += 'const path=' + json.dumps(TARGET) + ',expected=' + json.dumps(DIGEST) + ';\n'
    body += "function check(){if(crypto.createHash('sha256').update(fs.readFileSync(path)).digest('hex')!==expected)throw new Error('" + code + "');}\ncheck();process.on('exit',check);\n"
    return body


def delegated(h, args, mounts):
    """Accept only the already-qualified DQ outer predecessor wrapper's seam."""
    stage = getattr(h, 'repository_stage', None)
    if stage is None:
        return None
    require(type(stage) is dict and stage.get('name') == 'predecessor' and stage.get('override') is True
            and stage.get('sha256') == DIGEST, 'Unrecognized outer repository phase')
    file, probe, probe_hash = stage.get('file'), stage.get('probe'), stage.get('probeSha256')
    require(isinstance(file, Path) and isinstance(probe, Path)
            and file.parent == h.folder and probe.parent == h.folder
            and isinstance(probe_hash, str) and re.fullmatch('[a-f0-9]{64}', probe_hash),
            'Unrecognized outer repository files')
    require(args[:3] == ['node', '--require', OUTER_PROBE_TARGET]
            and sum(Path(host) == file and target == TARGET for host, target in mounts) == 1
            and sum(Path(host) == probe and target == OUTER_PROBE_TARGET for host, target in mounts) == 1
            and all((Path(host) == file and target == TARGET) or not related(target, TARGET) for host, target in mounts)
            and all((Path(host) == probe and target == OUTER_PROBE_TARGET) or not related(target, OUTER_PROBE_TARGET) for host, target in mounts),
            'Outer repository verifier or mount differs')
    read_exact(file, DIGEST)
    require(read_exact(probe, probe_hash) == verifier_source('QUALITY_REPOSITORY_PHASE_MISMATCH').encode(),
            'Outer repository verifier program differs')
    return file, probe, probe_hash


def run(h, inherited, args, *, root, mounts=(), **kwargs):
    if h.phase not in PHASES:
        return inherited(args, mounts=mounts, **kwargs)
    mounts = tuple(mounts)
    require(args and args[0] == 'node' and '--test' in args, 'Expected native Node test phase')
    outer = delegated(h, args, mounts)
    if outer:
        # Its existing whole-predecessor sourceStages and startup/exit verifier
        # remain authoritative; never install a second competing file mount.
        try:
            return inherited(args, mounts=mounts, **kwargs)
        finally:
            read_exact(outer[0], DIGEST)
            read_exact(outer[1], outer[2])
    require(all(not related(target, TARGET) and not related(target, PROBE_TARGET) for _, target in mounts),
            'Caller mount conflicts with qualification repository')
    sources = [dict(row) for row in h.report['sources']]
    selected = [row for row in sources if row['path'] == REPOSITORY]
    require(len(selected) == 1 and any(row == {'path': FIXTURE, 'sha256': DIGEST} for row in sources),
            'Qualification source inventory omits exact repository binding')
    current = selected[0]['sha256']
    read_exact(root / REPOSITORY, current)
    content = read_exact(root / FIXTURE, DIGEST)
    file, probe = h.folder / (h.phase + '-repository.ts'), h.folder / (h.phase + '-repository-check.cjs')
    with file.open('xb') as output:
        output.write(content)
    file.chmod(0o444)
    body = verifier_source('PREDECESSOR_REPOSITORY_MISMATCH')
    with probe.open('x') as output:
        output.write(body)
    probe.chmod(0o444)
    probe_hash = digest(body.encode())
    effective = [{**row, 'sha256': DIGEST} if row['path'] == REPOSITORY else row for row in sources]
    record = {'phase': h.phase, 'result': 'RUNNING', 'checkoutSources': sources, 'effectiveSources': effective,
              'override': {'path': REPOSITORY, 'commit': COMMIT, 'gitBlob': BLOB, 'sha256': DIGEST,
                           'fixture': FIXTURE, 'checkoutSha256': current, 'privateFile': str(file.relative_to(root)),
                           'mountTarget': TARGET, 'readOnly': True, 'verifierSha256': probe_hash},
              'scope': 'Only the repository is bound by this record; a separate predecessorApprovalStages or outer classification source record may additionally bind the approval service. Other dependencies and tests retain recorded checkout bytes.'}
    h.report.setdefault('predecessorRepositoryStages', []).append(record)
    try:
        result = inherited([args[0], '--require', PROBE_TARGET, *args[1:]],
                           mounts=[*mounts, (probe, PROBE_TARGET), (file, TARGET)], **kwargs)
        record.update(result='PASS' if result.returncode == 0 else 'NONZERO', exitStatus=result.returncode)
        return result
    except BaseException:
        record['result'] = 'FAIL'
        raise
    finally:
        record['overrideReleased'] = True  # No harness state or checkout file was replaced.
        try:
            read_exact(file, DIGEST)
            read_exact(probe, probe_hash)
            read_exact(root / REPOSITORY, current)
            record.update(sourceHashesMatched=True, checkoutRepositorySha256After=current, privateFileSha256After=DIGEST)
        except BaseException:
            record.update(result='FAIL', sourceHashesMatched=False)
            raise
