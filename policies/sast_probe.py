#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real negative control: scan generated vulnerable synthetic code, expect rejection.

This is never a product scan, finding waiver or clean scan. It performs no upload.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
import uuid

import sast


def fixture_sources():
    return {
        'app.ts': '''import express from 'express';
import { exec } from 'node:child_process';
const app = express();
app.get('/synthetic', (req, res) => {
  exec(String(req.query.command));
  res.send('synthetic scanner control');
});
app.listen(9999);
''',
        'worker.py': '''from flask import Flask, request
import os
app = Flask(__name__)
@app.route('/synthetic')
def synthetic():
    os.system(request.args.get('command'))
    return 'synthetic scanner control'
''',
        '.github/workflows/probe.yml': '''name: Synthetic scanner control
on: [issues]
permissions:
  contents: write
jobs:
  synthetic:
    runs-on: ubuntu-latest
    steps:
      - run: echo '${{ github.event.issue.title }}'
'''
    }


def verified_negative_control(result):
    expected = {'javascript-typescript': 'js/command-line-injection',
                'python': 'py/command-line-injection', 'actions': 'actions/code-injection/critical'}
    languages = result.get('languages', {})
    return result.get('purpose') == 'SYNTHETIC_NEGATIVE_CONTROL' and set(languages) == set(expected) and all(
        row.get('analysis') == 'PASS' and row.get('findingsGate') == 'BLOCKED' and
        any(f.get('blocking') and f.get('severity') in ('critical', 'high') and f.get('ruleId') == expected[language]
            for f in row.get('findings', []))
        for language, row in languages.items())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain')
    parser.add_argument('--platform', choices=('linux-arm64', 'linux-x64', 'darwin-arm64', 'darwin-x64'))
    parser.add_argument('--container-image')
    parser.add_argument('--container-images')
    args = parser.parse_args()
    policy = sast.read_json(sast.POLICY)
    name = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    fixture = sast.ROOT / '.local/sast-probes' / name
    fixture.mkdir(parents=True)
    for relative, content in fixture_sources().items():
        target = fixture / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    for relative in ('policies/sast-policy.json', 'policies/sast-triage.json', '.github/codeql/codeql-config.yml'):
        target = fixture / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(sast.ROOT / relative, target)
    # No project triage decisions apply to a deliberately vulnerable control.
    sast.write_json(fixture / 'policies/sast-triage.json', {'schemaVersion': 1, 'decisions': []})
    shutil.copytree(sast.ROOT / 'policies/codeql', fixture / 'policies/codeql')
    def git(*values):
        subprocess.run(['git', '-C', str(fixture), *values], check=True, capture_output=True, timeout=30)
    git('init', '-q')
    git('remote', 'add', 'origin', f'https://github.com/{policy["publicRepository"]}.git')
    git('add', '.')
    git('-c', 'user.name=Synthetic Scanner Control', '-c', 'user.email=scanner-fixture@example.invalid',
        'commit', '-qm', 'Generated synthetic scanner control; never published')
    args.source_root = fixture
    args.output = str(sast.ROOT / '.local/sast' / ('negative-control-' + name))
    args.language = None
    args.public_repository = policy['publicRepository']
    sast.run_scan(args, policy)
    result = sast.read_json(Path(args.output) / 'public/summary.json')
    passed = verified_negative_control(result)
    report = {'purpose': 'SYNTHETIC_NEGATIVE_CONTROL', 'controlOutcome': 'PASS' if passed else 'NOT_PASSED',
              'expectedOutcome': 'successful analysis and rejected high/critical findings in all three languages',
              'productScan': False, 'upload': 'NOT_ATTEMPTED', 'sourceDigest': result.get('sourceDigest')}
    sast.write_json(Path(args.output) / 'public/negative-control.json', report)
    print(json.dumps(report))
    return passed


if __name__ == '__main__':
    raise SystemExit(0 if main() else 1)
