#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise exact historical hash dispositions with the verified pinned scanner.

Requires the scanner installed by `python3 policies/scan_secrets.py --install`.
No scanner installation, network call, Docker operation or source mutation occurs.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
COMMIT = '64a13ed44dfc091193514e289f067e2574c7e07e'
EVIDENCE = 'docs/verification/product-search-postgres-local.json'
BLOB_SHA256 = '33261438f5072b40a07eaa5ffe01f5cf8d6c5cc8838e4e158b7fe4f2e7c61606'
LINES = (221, 283, 298, 374, 384, 389, 391, 394, 399, 402, 410, 414, 420, 422,
         425, 440, 450, 452, 453, 458, 476, 480, 487, 490, 491, 497, 510, 511, 533)


def git(*args, cwd=ROOT):
    return subprocess.run(['git', *args], cwd=cwd, capture_output=True, check=True,
                          timeout=30).stdout


class SecretFingerprintTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('fingerprint_scanner', ROOT / 'policies/scan_secrets.py')
        scanner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scanner)
        architecture = {'aarch64': 'arm64', 'arm64': 'arm64', 'x86_64': 'x64', 'AMD64': 'x64'}.get(platform.machine())
        directory = ROOT / '.local/toolchain' / f"gitleaks-{scanner.PIN['version']}-{platform.system().lower()}_{architecture}"
        if not (directory / 'gitleaks').is_file() or not (directory / 'provenance.json').is_file():
            raise RuntimeError('Install the explicitly pinned scanner before these native regression tests.')
        # install() validates existing archive/binary provenance and cannot fetch
        # in this branch because both required cached files are already present.
        cls.executable = scanner.install()
        version = subprocess.run([str(cls.executable), 'version'], capture_output=True,
                                 text=True, check=True, timeout=10).stdout.strip()
        if version != scanner.PIN['version']:
            raise RuntimeError('Pinned scanner version differs.')
        cls.historical = git('show', f'{COMMIT}:{EVIDENCE}')
        if hashlib.sha256(cls.historical).hexdigest() != BLOB_SHA256:
            raise RuntimeError('Immutable historical evidence bytes differ.')

    def scan(self, mode, target, ignore, *, options=()):
        with tempfile.TemporaryDirectory(prefix='gc-fingerprint-report-') as temporary:
            output = Path(temporary) / 'report.json'
            args = [str(self.executable), mode, str(target), *options,
                    '--gitleaks-ignore-path', str(ignore), '--redact=100', '--no-banner',
                    '--no-color', '--report-format=json', f'--report-path={output}', '--exit-code=1']
            # Prevent inherited configuration/baseline inputs from turning the
            # unchanged default detector tests into a false pass.
            env = {k: v for k, v in os.environ.items() if not k.startswith('GITLEAKS_')}
            result = subprocess.run(args, cwd=ROOT, env=env, capture_output=True, timeout=90)
            self.assertIn(result.returncode, (0, 1), 'Native scanner failed, not a finding result.')
            self.assertTrue(output.is_file(), 'Native scanner did not produce its report.')
            findings = json.loads(output.read_bytes())
            self.assertIsInstance(findings, list)
            self.assertEqual(result.returncode, 1 if findings else 0)
            return findings

    def test_dispositions_are_exact_immutable_source_digests_and_only_these_fingerprints(self):
        entries = [line for line in (ROOT / '.gitleaksignore').read_text().splitlines()
                   if line and not line.startswith('#')]
        expected = [f'{COMMIT}:{EVIDENCE}:generic-api-key:{line}' for line in LINES]
        self.assertEqual(entries, expected)
        self.assertEqual(len(entries), len(set(entries)))
        value = json.loads(self.historical)
        lines = self.historical.decode().splitlines()
        for line in LINES:
            match = re.fullmatch(r'\s*"([^"]+)": "([0-9a-f]{64})",?', lines[line - 1])
            self.assertIsNotNone(match)
            path, digest = match.groups()
            self.assertEqual(value['source_sha256'][path], digest)
            self.assertEqual(hashlib.sha256(git('show', f'{COMMIT}:{path}')).hexdigest(), digest)
        # The public correction changes representation only, never the evidence.
        current = json.loads((ROOT / EVIDENCE).read_bytes())
        records = current.pop('source_files')
        self.assertEqual(records, [{'path': p, 'sha256': h} for p, h in value.pop('source_sha256').items()])
        self.assertEqual(current, value)

    def test_exact_historical_scan_has_29_findings_without_dispositions_and_zero_with_them(self):
        with tempfile.TemporaryDirectory(prefix='gc-fingerprint-empty-') as temporary:
            directory = Path(temporary)
            empty = directory / '.gitleaksignore'
            empty.write_text('')
            # Gitleaks also loads the target repository's ignore file. A borrowed
            # immutable object database without a checkout proves the baseline
            # without ever renaming or disabling the real repository's policy.
            clone = directory / 'exact-history'
            git('clone', '--shared', '--no-checkout', '--no-hardlinks', str(ROOT), str(clone))
            options = (f'--log-opts={COMMIT}^..{COMMIT}',)
            baseline = self.scan('git', clone, empty, options=options)
            self.assertEqual(sorted(x['Fingerprint'] for x in baseline),
                             sorted(f'{COMMIT}:{EVIDENCE}:generic-api-key:{line}' for line in LINES))
            self.assertEqual(self.scan('git', ROOT, ROOT / '.gitleaksignore', options=options), [])

    def test_worktree_and_altered_path_keep_findings_while_corrected_records_scan_clean(self):
        with tempfile.TemporaryDirectory(prefix='gc-fingerprint-worktree-') as temporary:
            directory = Path(temporary)
            path = directory / EVIDENCE
            path.parent.mkdir(parents=True)
            path.write_bytes(self.historical)
            findings = self.scan('dir', directory, ROOT / '.gitleaksignore')
            self.assertEqual(len(findings), 29)
            self.assertTrue(all(x['RuleID'] == 'generic-api-key' and not x.get('Commit') for x in findings))
            path.rename(path.with_name('renamed-evidence.json'))
            findings = self.scan('dir', directory, ROOT / '.gitleaksignore')
            self.assertEqual(len(findings), 29)
            path.with_name('renamed-evidence.json').unlink()
            path.write_bytes((ROOT / EVIDENCE).read_bytes())
            self.assertEqual(self.scan('dir', directory, ROOT / '.gitleaksignore'), [])

    def test_new_commit_and_appended_synthetic_secret_do_not_inherit_history_dispositions(self):
        with tempfile.TemporaryDirectory(prefix='gc-fingerprint-history-') as temporary:
            directory = Path(temporary)
            git('init', '-q', cwd=directory)
            path = directory / EVIDENCE
            path.parent.mkdir(parents=True)
            path.write_bytes(self.historical)
            git('add', '.', cwd=directory)
            git('-c', 'user.name=Synthetic scanner fixture', '-c', 'user.email=scanner@example.invalid',
                '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Synthetic digest fixture', cwd=directory)
            commit = git('rev-parse', 'HEAD', cwd=directory).decode().strip()
            self.assertNotEqual(commit, COMMIT)
            findings = self.scan('git', directory, ROOT / '.gitleaksignore')
            self.assertEqual(len(findings), 29)
            self.assertTrue(all(x['Commit'] == commit for x in findings))
            # Deliberately generated noncredential content; never a live token.
            token = 'ghp_' + hashlib.sha256(b'Solely synthetic scanner negative fixture').hexdigest()[:36]
            path.write_text((ROOT / EVIDENCE).read_text() + '\nsynthetic_token = "' + token + '"\n')
            findings = self.scan('dir', directory, ROOT / '.gitleaksignore')
            self.assertTrue(any(x['RuleID'] == 'github-pat' for x in findings))


if __name__ == '__main__':
    unittest.main()
