#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact approval service binding for the four SQL015–018 native phases only."""
import hashlib
import importlib.util
import json
from pathlib import Path

_spec = importlib.util.spec_from_file_location('approval_repository_binding', Path(__file__).with_name('qualification_repository.py'))
_repository = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_repository)
require, digest, read_exact, related = _repository.require, _repository.digest, _repository.read_exact, _repository.related
SERVICE = 'packages/domain/src/approval-service.ts'
TARGET = '/app/' + SERVICE
FIXTURE = 'tests/qualification/predecessors/approval-service-sql020.ts.txt'
COMMIT = '88ee24835132e273aa3c67a95a213f79212deb8f'
BLOB = '574d0754c4c5d814e6006cbc2014c8724071a188'
DIGEST = 'c0bdee3d1a7f1ae91982fe34503282ee144ff4f1231575799ac89586fa1fa0f4'
PROBE_TARGET = '/app/predecessor-approval-service-check.cjs'
OUTER_PROBE_TARGET = '/app/classification-source-check.cjs'
OUTER_PATHS = frozenset((SERVICE, 'apps/api/src/approvals.ts', 'apps/api/src/repository.ts'))
PHASES = frozenset(('approval-native-tests', 'glossary-native-tests', 'scope-native-tests', 'population-native-tests'))


def verifier_source():
    return ("const fs=require('node:fs'),crypto=require('node:crypto');\n"
            + 'const path=' + json.dumps(TARGET) + ',expected=' + json.dumps(DIGEST) + ';\n'
            + "function check(){if(crypto.createHash('sha256').update(fs.readFileSync(path)).digest('hex')!==expected)throw new Error('PREDECESSOR_APPROVAL_SERVICE_MISMATCH');}\ncheck();process.on('exit',check);\n")


def outer_verifier(rows):
    # Exact existing classification wrapper format, including every mounted
    # family module. Its own outer before/after source checks remain intact.
    return ("const fs=require('node:fs'),crypto=require('node:crypto');\nconst rows=" + json.dumps(rows) + ";\n"
            "function check(){for(const row of rows)if(crypto.createHash('sha256').update(fs.readFileSync('/app/'+row.path)).digest('hex')!==row.sha256)throw new Error('CLASSIFICATION_SOURCE_PHASE_MISMATCH');}\ncheck();process.on('exit',check);\n")


def delegated(h, args, mounts, root):
    stage = getattr(h, 'classification_predecessor', None)
    if stage is None:
        return None
    require(type(stage) is dict and set(stage) == {'sources'}
            and getattr(h, 'classification_current', None) is None,
            'Unrecognized outer approval source phase')
    checks = h.report.get('classificationSourceChecks')
    require(type(checks) is list and bool(checks), 'Missing outer approval source check')
    check = checks[-1]
    require(type(check) is dict and check.get('phase') == h.phase
            and check.get('stage') == 'SQL001-020' and check.get('result') == 'RUNNING',
            'Unrecognized outer approval source check')
    declared = {'path': SERVICE, 'fixture': FIXTURE, 'gitBlob': BLOB, 'sha256': DIGEST, 'commit': COMMIT, 'readOnly': True}
    require(type(check.get('overrides')) is list and check['overrides'].count(declared) == 1,
            'Outer approval service override is not declared exactly')
    sources = check.get('effectiveSources')
    require(type(sources) is list and all(type(row) is dict and set(row) == {'path', 'sha256'} for row in sources)
            and len({row['path'] for row in sources}) == len(sources),
            'Invalid outer effective source inventory')
    rows = [dict(row) for row in sources if row['path'] in OUTER_PATHS]
    require(len(rows) == 3 and next(row['sha256'] for row in rows if row['path'] == SERVICE) == DIGEST,
            'Outer approval service binding differs')
    exact = root / FIXTURE
    protected = [(Path(host), target) for host, target in mounts if related(target, TARGET)]
    probes = [(Path(host), target) for host, target in mounts if related(target, OUTER_PROBE_TARGET)]
    require(protected == [(exact, TARGET)] and len(probes) == 1 and probes[0][1] == OUTER_PROBE_TARGET
            and probes[0][0].parent == h.folder,
            'Outer approval mount or verifier differs')
    require(sum(args[i:i+2] == ['--require', OUTER_PROBE_TARGET] for i in range(len(args)-1)) == 1,
            'Missing or duplicate outer approval preload')
    read_exact(exact, DIGEST)
    body = outer_verifier(rows).encode()
    require(read_exact(probes[0][0], check.get('verifierSha256')) == body,
            'Outer approval verifier program differs')
    return exact, probes[0][0], digest(body)


def run(h, inherited, args, *, root, mounts=(), **kwargs):
    if h.phase not in PHASES:
        return inherited(args, mounts=mounts, **kwargs)
    require(args and args[0] == 'node' and '--test' in args, 'Expected historical native Node tests')
    mounts = tuple(mounts)
    outer = delegated(h, args, mounts, root)
    if outer:
        # Do not compete with the outer classification verifier or repository
        # precedence. It has already declared and mounted these exact bytes.
        try:
            return inherited(args, mounts=mounts, **kwargs)
        finally:
            read_exact(outer[0], DIGEST)
            read_exact(outer[1], outer[2])
    require(all(not related(target, TARGET) and not related(target, PROBE_TARGET)
                for _, target in mounts), 'Caller mount conflicts with historical approval service')
    sources = [dict(row) for row in h.report['sources']]
    selected = [row for row in sources if row['path'] == SERVICE]
    require(len(selected) == 1 and len({row['path'] for row in sources}) == len(sources)
            and any(row == {'path': FIXTURE, 'sha256': DIGEST} for row in sources),
            'Qualification inventory omits exact approval binding')
    current = selected[0]['sha256']
    read_exact(root / SERVICE, current)
    content = read_exact(root / FIXTURE, DIGEST)
    require(hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content, usedforsecurity=False).hexdigest() == BLOB,
            'Historical approval Git object identity differs')
    file = h.folder / (h.phase + '-approval-service.ts')
    probe = h.folder / (h.phase + '-approval-service-check.cjs')
    with file.open('xb') as output:
        output.write(content)
    file.chmod(0o444)
    body = verifier_source().encode()
    with probe.open('xb') as output:
        output.write(body)
    probe.chmod(0o444)
    record = {'phase': h.phase, 'result': 'RUNNING', 'checkoutSources': sources,
              'effectiveSources': [{**row, 'sha256': DIGEST} if row['path'] == SERVICE else row for row in sources],
              'override': {'path': SERVICE, 'commit': COMMIT, 'gitBlob': BLOB, 'sha256': DIGEST,
                           'fixture': FIXTURE, 'checkoutSha256': current, 'privateFile': str(file.relative_to(root)),
                           'mountTarget': TARGET, 'readOnly': True, 'verifierSha256': digest(body)},
              'scope': 'Only the approval service uses the immutable SQL020-compatible module; the separately verified SQL018 repository binding retains its original precedence.'}
    h.report.setdefault('predecessorApprovalStages', []).append(record)
    try:
        result = inherited([args[0], '--require', PROBE_TARGET, *args[1:]],
                           mounts=[*mounts, (probe, PROBE_TARGET), (file, TARGET)], **kwargs)
        record.update(result='PASS' if result.returncode == 0 else 'NONZERO', exitStatus=result.returncode)
        return result
    except BaseException:
        record['result'] = 'FAIL'
        raise
    finally:
        record['overrideReleased'] = True
        try:
            read_exact(file, DIGEST)
            read_exact(probe, digest(body))
            read_exact(root / SERVICE, current)
            record.update(sourceHashesMatched=True, checkoutServiceSha256After=current, privateFileSha256After=DIGEST)
        except BaseException:
            record.update(result='FAIL', sourceHashesMatched=False)
            raise
