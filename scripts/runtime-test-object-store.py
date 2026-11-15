#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Probe the real S3 service through the API's existing credentials; no new image."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import subprocess

from runtime import COMPOSE, ROOT, require_bootstrap, require_local


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--readiness', action='store_true')
    args = parser.parse_args()
    require_bootstrap(); require_local()
    script = ROOT / 'scripts/runtime-s3-check.mjs'
    command = COMPOSE + ['exec', '-T', 'api', 'node', '--input-type=module', '-']
    if args.readiness:
        command.append('--readiness')
    report = {'schema_version': 1, 'profile': 'core', 'started_at': datetime.now(timezone.utc).isoformat(),
        'command': 'python3 scripts/runtime-test-object-store.py --readiness' if args.readiness else './dev test --suite object-store',
        'revision': {'base_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(), 'working_tree': 'file-hash-bound; commit binding pending'},
        'limitations': ['Local single-node S3 with static application credentials only', 'No product document/evidence object workflows, per-tenant buckets/policies, STS, encryption at rest, HA, backup or enterprise qualification', 'Prior core-runtime and core-recovery records checked Seaweed master health only; neither established authenticated S3 readiness']}
    try:
        result = subprocess.run(command, cwd=ROOT, input=script.read_text(), capture_output=True, text=True, timeout=90)
        probe = json.loads(result.stdout)
        report.update(probe)
        report['exit_status'] = result.returncode
        if result.returncode or probe.get('result') != 'passed':
            report['result'] = 'failed'
            report['exit_status'] = 1
        report['images'] = []
        for service in ['seaweedfs', 'api']:
            image = subprocess.run(COMPOSE + ['images', '-q', service], cwd=ROOT, capture_output=True, text=True, timeout=15)
            if image.returncode == 0:
                report['images'].append({'service': service, 'sha256': image.stdout.strip().removeprefix('sha256:')})
    except (subprocess.SubprocessError, ValueError):
        report.update({'result': 'failed', 'exit_status': 1, 'error': 'S3 probe failed; arbitrary container output withheld'})
    report['finished_at'] = datetime.now(timezone.utc).isoformat()
    files = ['scripts/runtime.py', 'scripts/runtime-test-object-store.py', 'scripts/runtime-s3-check.mjs', 'deploy/compose/compose.yaml', 'deploy/compose/init-secrets.sh', 'deploy/compose/health-seaweed.sh', 'deploy/compose/seaweed-master.toml']
    report['implementation_files'] = [{'path': path, 'sha256': hashlib.sha256((ROOT / path).read_bytes()).hexdigest()} for path in files]
    destination = ROOT / ('.local/evidence/s3-readiness.json' if args.readiness else 'docs/verification/core-object-store.json')
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'suite': report.get('suite', 's3-probe'), 'result': report['result'], 'evidence': str(destination.relative_to(ROOT)), 'checks': report.get('checks', []), 'error': report.get('error')}))
    return report['exit_status']


if __name__ == '__main__':
    raise SystemExit(main())
