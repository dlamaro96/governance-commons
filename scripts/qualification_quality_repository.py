#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact repository selection for compact SQL024–027 native quality gates.

The immutable SQL026 repository uses only earlier tables/functions. Historical
native phases mount these exact bytes; SQL027 phases use the current checkout.
No application fallback, Git history dependency or arbitrary source override.
"""
import hashlib
from pathlib import Path

REPOSITORY = 'apps/api/src/repository.ts'
FIXTURE = 'tests/qualification/predecessors/repository-sql026.ts.txt'
COMMIT = '629e475c2fb00198b51e673074eabd0aa5bcff48'
BLOB = '074a6ac9b0e1ba33e06197009386563d92e7ea33'
DIGEST = '9cb5f78fe0d70e1d614f7940ed3de4e44394ae47befd817c2f7816f08fe654f5'
PHASES = {
    'uniqueness': frozenset(('pre024-completeness-tests', 'pre024-reference-tests',
                            'post025-completeness-tests', 'post025-reference-tests', 'post025-uniqueness-tests')),
    'range': frozenset(('pre025-completeness-tests', 'pre025-reference-tests', 'pre025-uniqueness-tests',
                       'post026-completeness-tests', 'post026-reference-tests', 'post026-uniqueness-tests', 'post026-range-tests')),
    'monitoring': frozenset(('pre026-completeness-tests', 'pre026-reference-tests',
                            'pre026-uniqueness-tests', 'pre026-range-tests')),
}


def require(value, message):
    if not value:
        raise RuntimeError(message)


def checked(root, relative, expected):
    path = root / relative
    require(path.is_file() and all(not p.is_symlink() for p in (path, *path.parents) if p.is_relative_to(root)),
            'Quality repository source missing or symlinked')
    require(path.stat().st_size <= 262144, 'Quality repository source exceeds bound')
    with path.open('rb') as source:
        data = source.read(262145)
    require(0 < len(data) <= 262144 and hashlib.sha256(data).hexdigest() == expected,
            'Quality repository source hash differs')
    return path


def select(root, frozen, gate, phase):
    require(gate in PHASES, 'Unknown quality repository gate')
    sources = [dict(row) for row in frozen]
    if phase not in PHASES[gate]:
        return {'sources': sources, 'override': None}
    selected = [row for row in sources if row['path'] == REPOSITORY]
    require(len(selected) == 1 and sum(row == {'path': FIXTURE, 'sha256': DIGEST} for row in sources) == 1,
            'Quality repository source inventory omits immutable binding')
    current = selected[0]['sha256']
    checked(root, REPOSITORY, current)
    checked(root, FIXTURE, DIGEST)
    effective = [{**row, 'sha256': DIGEST} if row['path'] == REPOSITORY else row for row in sources]
    return {'sources': effective, 'override': {
        'path': REPOSITORY, 'fixture': FIXTURE, 'commit': COMMIT, 'gitBlob': BLOB,
        'sha256': DIGEST, 'checkoutSha256': current, 'readOnly': True,
        'mountTarget': '/app/' + REPOSITORY,
    }}


def mounted_path(root, row, selected):
    override = selected['override']
    return root / (FIXTURE if override is not None and row['path'] == REPOSITORY else row['path'])
