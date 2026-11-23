#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""CI-only handoff from the tested core image to fresh protected authentication."""
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or not re.fullmatch(r'[a-f0-9]{40}', os.environ.get('GITHUB_SHA', '')):
        raise RuntimeError('Explicit hosted CI context required')
    spec = importlib.util.spec_from_file_location('core_launcher', ROOT/'scripts/runtime.py')
    launcher = importlib.util.module_from_spec(spec); spec.loader.exec_module(launcher)
    launcher.require_local(); launcher.require_bootstrap()
    def capture(command, timeout=30):
        return subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=True, timeout=timeout).stdout.strip()
    ids = capture([*launcher.COMPOSE, 'ps', '-q', 'api']).splitlines()
    if len(ids) != 1 or not re.fullmatch('[a-f0-9]{12,64}', ids[0]):
        raise RuntimeError('Exactly one tested core API container required')
    container = json.loads(capture(['docker', 'inspect', '--format', '{{json .}}', ids[0]]))
    labels = container['Config']['Labels']
    image = container['Image']
    if labels.get('com.docker.compose.project') != 'governance-commons' or labels.get('com.docker.compose.service') != 'api' or not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
        raise RuntimeError('Tested core application image not confirmed')
    node = capture(['node', '-p', 'process.execPath'])
    browser = capture([node, '--input-type=module', '-e', "import {chromium} from '@playwright/test';process.stdout.write(chromium.executablePath());"])
    for value in (node, browser):
        if not Path(value).is_absolute() or not Path(value).is_file() or not os.access(value, os.X_OK) or '\n' in value:
            raise RuntimeError('Installed CI tool unavailable')
    # Only this CI-owned core project stops; preserve its volumes and all evidence.
    subprocess.run([str(ROOT/'dev'), 'down'], cwd=ROOT, check=True, timeout=100)
    env = {**os.environ, 'GC_PINNED_NODE': node, 'GC_BROWSER_EXECUTABLE': browser,
           'GC_PROTECTED_AUTHN_IMAGE': image, 'GC_PROTECTED_AUTHN_MODE': 'immutable-image'}
    subprocess.run([str(ROOT/'dev'), 'test', '--suite', 'protected-authn'], cwd=ROOT, env=env, check=True, timeout=1800)


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        print('PROTECTED_CI_QUALIFICATION_FAILED: inspect private bounded evidence; no pass was inferred.', file=sys.stderr)
        raise SystemExit(1)
