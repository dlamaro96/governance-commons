#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Scan an immutable locally built image; retain full findings and package inventory."""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tarfile
import tempfile
import time
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
PIN = json.loads((ROOT/'policies/security-tools.json').read_text())['trivy']
SEVERITIES = {'UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024*1024), b''):
            value.update(chunk)
    return value.hexdigest()


def read_json(path, limit=32*1024*1024):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= limit, 'report-file-rejected')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('non-finite-json')))


def install():
    target = platform.system().lower()+'_'+{'aarch64':'arm64','arm64':'arm64','x86_64':'x64'}.get(platform.machine(), 'unknown')
    require(target in PIN['archives'], 'unsupported-scanner-platform')
    artifact = PIN['archives'][target]
    directory = ROOT/'.local/toolchain'/('trivy-'+PIN['version']+'-'+target)
    binary, receipt = directory/'trivy', directory/'provenance.json'
    if binary.exists() or receipt.exists():
        provenance = read_json(receipt)
        require(binary.is_file() and not binary.is_symlink() and
                provenance['archiveSha256'] == artifact['sha256'] and sha(binary) == provenance['binarySha256'], 'cached-scanner-differs')
        return binary
    directory.mkdir(parents=True, exist_ok=True)
    url = 'https://github.com/aquasecurity/trivy/releases/download/v'+PIN['version']+'/'+artifact['name']
    # Download only the pinned bounded archive. Never execute a remote installer.
    deadline = time.monotonic()+120
    with tempfile.TemporaryFile() as archive:
        digest, size = hashlib.sha256(), 0
        with urlopen(url, timeout=30) as response:
            while chunk := response.read(1024*1024):
                size += len(chunk)
                require(size <= artifact['bytes'] and time.monotonic() < deadline, 'scanner-download-budget')
                digest.update(chunk); archive.write(chunk)
        require(size == artifact['bytes'] and digest.hexdigest() == artifact['sha256'], 'scanner-checksum-mismatch')
        archive.seek(0)
        with tarfile.open(fileobj=archive, mode='r:gz') as bundle:
            members = [m for m in bundle.getmembers() if m.name == 'trivy']
            require(len(members) == 1 and members[0].isfile() and 0 < members[0].size <= 256*1024*1024, 'scanner-archive-rejected')
            with bundle.extractfile(members[0]) as source, binary.open('xb') as destination:
                while chunk := source.read(1024*1024):
                    destination.write(chunk)
    binary.chmod(0o700)
    receipt.write_text(json.dumps({'archiveSha256':artifact['sha256'], 'binarySha256':sha(binary), 'url':url})+'\n')
    return binary


def database(metadata, now):
    require(type(metadata) is dict and metadata.get('Version') == 2, 'database-schema-rejected')
    updated = datetime.fromisoformat(metadata['UpdatedAt'].replace('Z','+00:00'))
    require(updated.tzinfo is not None and -timedelta(minutes=5) <= now-updated <= timedelta(hours=48), 'database-not-fresh')
    return metadata['UpdatedAt']


def assess(report, image, profile):
    require(type(report) is dict and report.get('SchemaVersion') == 2 and
            report.get('ArtifactType') == 'container_image' and report.get('ArtifactName') == image, 'image-report-mismatch')
    require(type(report.get('Trivy')) is dict and report['Trivy'].get('Version') == PIN['version'], 'report-scanner-version-mismatch')
    metadata = report.get('Metadata', {})
    require(type(metadata) is dict and type(metadata.get('ImageConfig')) is dict and
            type(metadata.get('OS')) is dict, 'invalid-image-metadata')
    require(metadata.get('ImageID') == image and metadata.get('ImageConfig', {}).get('os') == 'linux', 'image-metadata-mismatch')
    require(metadata['ImageConfig'].get('architecture') in ('amd64','arm64'), 'image-platform-rejected')
    require(metadata.get('OS', {}).get('Family') in ('debian','alpine') and not metadata.get('OS', {}).get('EOSL'), 'unsupported-image-os')
    results = report.get('Results')
    require(type(results) is list and results, 'missing-scan-results')
    counts, packages, scopes = Counter(), 0, set()
    findings = []
    for result in results:
        require(type(result) is dict and result.get('Class') in ('os-pkgs','lang-pkgs'), 'unexpected-scan-scope')
        inventory = result.get('Packages')
        require(type(inventory) is list and inventory, 'missing-package-inventory')
        require(all(type(package) is dict and all(type(package.get(key)) is str and package[key]
                    for key in ('Name','Version')) for package in inventory), 'invalid-package-identity')
        packages += len(inventory); scopes.add(result.get('Type'))
        vulnerabilities = result.get('Vulnerabilities', [])
        require(type(vulnerabilities) is list and not result.get('ExperimentalModifiedFindings'), 'suppressed-or-invalid-findings')
        for finding in vulnerabilities:
            require(type(finding) is dict and finding.get('Severity') in SEVERITIES and
                    all(type(finding.get(k)) is str and finding[k] for k in ('VulnerabilityID','PkgName','InstalledVersion')), 'invalid-finding')
            counts[finding['Severity']] += 1
            findings.append({key:finding.get(key) for key in ('VulnerabilityID','PkgName','InstalledVersion','FixedVersion','Severity','Status','PrimaryURL')})
    require({'debian','node-pkg'} <= scopes if profile == 'application' else {'alpine','python-pkg'} <= scopes, 'incomplete-runtime-coverage')
    return {'outcome':'FAIL' if counts['HIGH']+counts['CRITICAL'] else 'PASS',
            'architecture':metadata['ImageConfig']['architecture'], 'packages':packages,
            'counts':{key:counts[key] for key in sorted(SEVERITIES)}, 'findings':findings}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    parser.add_argument('--profile', required=True, choices=('application','python-worker'))
    parser.add_argument('--output', required=True, type=Path, help='New directory for this execution; existing paths are rejected')
    parser.add_argument('--cache', type=Path, default=ROOT/'.local/trivy-cache')
    parser.add_argument('--install', action='store_true')
    parser.add_argument('--scanner', type=Path, help='Explicit installed scanner; version and executable digest are recorded')
    args = parser.parse_args()
    require(bool(args.install) != bool(args.scanner), 'select-install-or-scanner')
    require(re.fullmatch(r'sha256:[0-9a-f]{64}',args.image), 'immutable-image-required')
    folder = args.output.resolve(); folder.mkdir(parents=True, exist_ok=False)
    summary = {'schemaVersion':1,'outcome':'FAIL','complete':False,'image':args.image,'profile':args.profile,
               'startedAt':datetime.now(timezone.utc).isoformat(), 'scannerVersion':PIN['version']}
    env = {k:v for k,v in os.environ.items() if not k.startswith('TRIVY_')}
    def execute(command, name, timeout=30):
        with (folder/(name+'.log')).open('wb') as log:
            result = subprocess.run(command, cwd=folder, env=env, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
        require(result.returncode == 0, name+'-failed')
    phase = 'scanner-admission'
    try:
        binary = install() if args.install else args.scanner.resolve(strict=True)
        summary['scannerSha256'] = sha(binary)
        execute([str(binary),'version','--format','json'],'scanner-version')
        require(read_json(folder/'scanner-version.log')['Version'] == PIN['version'], 'scanner-version-mismatch')
        phase = 'source-record'
        execute(['git','-C',str(ROOT),'rev-parse','HEAD'],'revision')
        summary['commit'] = (folder/'revision.log').read_text().strip()
        require(re.fullmatch('[a-f0-9]{40}',summary['commit']), 'revision-unavailable')
        execute(['git','-C',str(ROOT),'status','--porcelain'],'working-tree')
        summary['dirty'] = bool((folder/'working-tree.log').stat().st_size)
        summary['controls'] = {p:sha(ROOT/p) for p in ('Dockerfile','python/Dockerfile','policies/scan_images.py','policies/security-tools.json')}
        (folder/'empty-ignore').write_text('')
        command = [str(binary),'image','--image-src','docker','--cache-dir',str(args.cache.resolve()),
                   '--timeout','5m','--scanners','vuln','--list-all-pkgs','--ignorefile',str(folder/'empty-ignore'),
                   '--format','json','--no-progress','--output',str(folder/'image.json'),args.image]
        summary['command'] = ['trivy','image','--image-src','docker','--timeout','5m','--scanners','vuln',
                              '--list-all-pkgs','--ignorefile','empty-ignore','--format','json','--no-progress','--output','image.json',args.image]
        phase = 'image-scan'
        execute(command,'scan',330)
        phase = 'report-validation'
        summary['databaseUpdatedAt'] = database(read_json(args.cache.resolve()/'db/metadata.json'), datetime.now(timezone.utc))
        require(sha(binary) == summary['scannerSha256'], 'scanner-changed')
        require(all(sha(ROOT/p) == value for p,value in summary['controls'].items()), 'controls-changed')
        summary.update(assess(read_json(folder/'image.json'),args.image,args.profile))
        summary['reportSha256'] = sha(folder/'image.json')
        summary['complete'] = True
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, subprocess.SubprocessError, tarfile.TarError):
        summary.update(outcome='FAIL',complete=False,error='SCAN_INCOMPLETE',failurePhase=phase)
    summary['finishedAt'] = datetime.now(timezone.utc).isoformat()
    summary['limitations'] = ['Known-vulnerability detection for this exact image and database; not proof of absence of vulnerabilities.',
                              'High/critical findings fail without suppressions, including unfixed findings. Lower/unknown findings remain visible.',
                              'Infrastructure images, exploitability review, application SAST/DAST and release qualification are separate.']
    (folder/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps({key:summary.get(key) for key in ('outcome','complete','image','counts','packages')}))
    return 0 if summary['complete'] and summary['outcome'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
