#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exact local Docker image and immutable Git-source admission for the protected gate."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time


def require(value, message='Protected image qualification rejected'):
    if not value:
        raise RuntimeError(message)


def image_id(value):
    require(type(value) is str and re.fullmatch(r'sha256:[a-f0-9]{64}', value), 'Exact immutable application image ID required')
    return value


def admitted_sources(rows):
    require(type(rows) is list and 0 < len(rows) <= 4096)
    names = []
    for row in rows:
        require(type(row) is dict and set(row) == {'path', 'sha256'})
        name = row['path']
        require(type(name) is str and 0 < len(name) <= 512 and re.fullmatch(r'[A-Za-z0-9_.\-/]+', name))
        require(all(part not in ('', '.', '..') for part in name.split('/')))
        require(re.fullmatch(r'[a-f0-9]{64}', row['sha256']))
        names.append(name)
    require(names == sorted(set(names)), 'Image source inventory must be sorted and unique')
    return names


def verify_git_sources(root: Path, rows, commit):
    """Re-read committed blobs; a dirty filesystem cannot certify a baked CI image."""
    names = admitted_sources(rows)
    require(type(commit) is str and re.fullmatch(r'[a-f0-9]{40}', commit))
    query = ''.join(commit + ':' + name + '\n' for name in names).encode()
    # Immutable-object size preflight bounds allocation before reading any blob body.
    checked = subprocess.run(['git', '--no-replace-objects', 'cat-file', '--batch-check'],
                             cwd=root, input=query, capture_output=True, timeout=30)
    require(checked.returncode == 0 and not checked.stderr and len(checked.stdout) <= 4*1024*1024)
    headers = checked.stdout.decode('ascii').splitlines()
    require(len(headers) == len(rows))
    total = 0
    for line in headers:
        fields = line.split(' ')
        require(len(fields) == 3 and re.fullmatch('[a-f0-9]{40}', fields[0]) and fields[1] == 'blob' and fields[2].isdigit())
        size = int(fields[2]); require(0 <= size <= 16*1024*1024)
        total += size + len(line) + 2
        require(total <= 64*1024*1024, 'Immutable source byte budget exceeded before materialization')
    result = subprocess.run(['git', '--no-replace-objects', 'cat-file', '--batch'], cwd=root, input=query, capture_output=True, timeout=30)
    require(result.returncode == 0 and not result.stderr and len(result.stdout) <= 64*1024*1024)
    data, position = result.stdout, 0
    for row in rows:
        end = data.find(b'\n', position)
        require(end >= position)
        header = data[position:end].decode('ascii').split(' ')
        require(len(header) == 3 and re.fullmatch('[a-f0-9]{40}', header[0]) and header[1] == 'blob' and header[2].isdigit())
        size = int(header[2]); require(0 <= size <= 16*1024*1024)
        position = end + 1
        body = data[position:position+size]
        require(len(body) == size and hashlib.sha256(body).hexdigest() == row['sha256'], 'Declared source differs from immutable commit')
        position += size
        require(data[position:position+1] == b'\n'); position += 1
    require(position == len(data))


BAKED_READER = r"""const fs=require('node:fs'),crypto=require('node:crypto');
const names=JSON.parse(process.argv[1]);
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
const read=name=>{let p='/app';for(const part of name.split('/')){p+='/'+part;const s=fs.lstatSync(p);if(s.isSymbolicLink())throw Error('BAKED_SOURCE_REJECTED');}const s=fs.statSync(p);if(!s.isFile()||s.size>16777216)throw Error('BAKED_SOURCE_REJECTED');return fs.readFileSync(p);};
try{const sources=names.map(path=>({path,sha256:hash(read(path))}));process.stdout.write(JSON.stringify({sources,packageSha256:hash(read('package.json')),lockSha256:hash(read('pnpm-lock.yaml')),node:process.version}));}catch{process.stderr.write('BAKED_SOURCE_REJECTED\n');process.exitCode=1;}
"""


def attest_image(h, root: Path, selected, rows, commit):
    """Inspect a fresh no-network, unmounted container before executing its reader."""
    selected = image_id(selected)
    names = admitted_sources(rows)
    verify_git_sources(root, rows, commit)
    name = h.id + '-baked-source-reader'
    h.owned.append(name)
    h.docker('create', '--pull', 'never', '--name', name, '--label', 'org.governance-commons.protected-run='+h.id,
        '--network', 'none', '--memory', '128m', '--memory-swap', '128m', '--pids-limit', '32',
        '--read-only', '--log-driver', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
        '--user', '1000:1000', '--env', 'NODE_OPTIONS=--max-old-space-size=64',
        '--entrypoint', 'node', selected, '-e', BAKED_READER, json.dumps(names), sensitive=True, timeout=20)
    try:
        actual = h.docker('inspect', '--format', '{{json .}}', name, sensitive=True).stdout
        observed = json.loads(actual)
        require(observed['Image'] == selected and not observed['Mounts'], 'Baked image reader was changed or mounted')
        result = h.docker('start', '-a', name, sensitive=True, timeout=30)
        exit_code = h.docker('inspect', '--format', '{{.State.ExitCode}}', name, sensitive=True).stdout.strip()
        require(exit_code == '0', 'Baked image reader did not complete')
        value = json.loads(result.stdout)
        require(set(value) == {'sources', 'packageSha256', 'lockSha256', 'node'})
        require(value['sources'] == rows and value['node'] == 'v24.22.3', 'Baked image source/runtime mismatch')
        require(value['packageSha256'] == hashlib.sha256((root/'package.json').read_bytes()).hexdigest())
        require(value['lockSha256'] == hashlib.sha256((root/'pnpm-lock.yaml').read_bytes()).hexdigest())
        return {'imageId': selected, 'sourceMode': 'baked-unmounted', 'commit': commit,
                'sources': value['sources'], 'packageSha256': value['packageSha256'], 'lockSha256': value['lockSha256']}
    finally:
        # This early owned cleanup has its own bound; final profile cleanup retains
        # its separate reserve and must not depend on successful admission.
        previous_cleanup_deadline = h.cleanup_deadline
        h.cleanup_deadline = time.monotonic() + 20
        try:
            h.docker('rm', '-f', name, cleanup=True, sensitive=True, timeout=20)
        finally:
            h.cleanup_deadline = previous_cleanup_deadline
