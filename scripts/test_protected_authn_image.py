#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Adversarial bounds and immutable-source checks for image qualification."""
import hashlib
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from protected_authn_image import admitted_sources, image_id, verify_git_sources

ROOT = Path(__file__).resolve().parents[1]


class ImageAdmissionTests(unittest.TestCase):
    def test_only_immutable_digest_and_safe_unique_paths_are_admitted(self):
        self.assertEqual(image_id('sha256:'+'a'*64), 'sha256:'+'a'*64)
        for invalid in ('latest', 'example:latest', 'sha256:'+'a'*63, 'sha256:'+'A'*64):
            with self.assertRaises(RuntimeError): image_id(invalid)
        for names in (['../outside'], ['/outside'], ['a/./b'], ['a', 'a'], ['b', 'a']):
            with self.assertRaises(RuntimeError): admitted_sources([{'path':p, 'sha256':'a'*64} for p in names])

    def test_real_git_blob_matches_and_changed_declared_bytes_are_refused(self):
        commit = subprocess.check_output(['git','rev-parse','HEAD'], cwd=ROOT, text=True).strip()
        blob = subprocess.check_output(['git','--no-replace-objects','show',commit+':CONTRIBUTING.md'],cwd=ROOT)
        rows = [{'path':'CONTRIBUTING.md','sha256':hashlib.sha256(blob).hexdigest()}]
        verify_git_sources(ROOT, rows, commit)
        with self.assertRaises(RuntimeError): verify_git_sources(ROOT,[{'path':'CONTRIBUTING.md','sha256':'0'*64}],commit)

    def test_aggregate_byte_budget_refuses_before_blob_materialization(self):
        rows = [{'path':str(i), 'sha256':'a'*64} for i in range(5)]
        preflight = (('a'*40+' blob 16777216\n')*5).encode()
        with patch('protected_authn_image.subprocess.run',return_value=subprocess.CompletedProcess([],0,preflight,b'')) as run:
            with self.assertRaises(RuntimeError): verify_git_sources(ROOT,rows,'a'*40)
            self.assertEqual(run.call_count,1)
            self.assertIn('--batch-check',run.call_args.args[0])

    def test_missing_or_nonblob_source_cannot_be_treated_as_image_evidence(self):
        for header in (b'not-present missing\n',('a'*40+' tree 12\n').encode()):
            with patch('protected_authn_image.subprocess.run',return_value=subprocess.CompletedProcess([],0,header,b'')) as run:
                with self.assertRaises(RuntimeError): verify_git_sources(ROOT,[{'path':'example','sha256':'a'*64}],'a'*40)
                self.assertEqual(run.call_count,1)


if __name__=='__main__':unittest.main()
