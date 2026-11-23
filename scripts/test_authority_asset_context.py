# SPDX-License-Identifier: Apache-2.0
"""Real harness-constructor budget controls; no Docker or process execution."""
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('asset_context_budget_gate', ROOT / 'scripts/runtime-test-authority-asset-context.py')
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


class Controls(unittest.TestCase):
    def test_declared036_successor_is_excluded_and_gapped_or_unknown_inventory_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);folder=root/'packages/db/migrations';folder.mkdir(parents=True)
            for name in g.NAMES:(folder/name).write_text('-- historical prefix')
            for name in (g.NEW_TEST,'scripts/runtime-test-authority-asset-context.py','scripts/test_authority_asset_context.py',):
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('')
            with patch.object(g,'ROOT',root),patch.object(g.volume,'ROOT',root),patch.object(g,'_original_sources',return_value=[]):
                before=g.sources();self.assertEqual(len(g.migrations()),32)
                suffix=['033_content_security_revisions.sql', '034_classification_label_identities.sql', '035_reviewed_classification_producer.sql', '036_authority_scope_alignment.sql']
                for name in suffix:
                    path=folder/name;path.write_text('-- declared successor only')
                    self.assertEqual(g.migrations(),g.NAMES);self.assertEqual(g.sources(),before)
                    self.assertNotIn('packages/db/migrations/'+name,{row['path'] for row in before})
                    path.write_text('-- successor content never belongs to this historical profile')
                    self.assertEqual(g.sources(),before)
                for name in ('036_undeclared.sql','037_undeclared.sql'):
                    extra=folder/name;extra.write_text('-- unreviewed')
                    with self.assertRaises(RuntimeError):g.sources()
                    extra.unlink()
                missing=folder/'035_reviewed_classification_producer.sql'
                old=missing.read_bytes();missing.unlink()
                with self.assertRaises(RuntimeError):g.sources()
                missing.write_bytes(old);self.assertEqual(g.sources(),before)

    def test_exact_contiguous033034_successors_are_admitted_without_expanding032_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);folder=root/'packages/db/migrations';folder.mkdir(parents=True)
            for name in g.NAMES: (folder/name).write_text('-- historical prefix')
            for name in (g.NEW_TEST,'scripts/runtime-test-authority-asset-context.py','scripts/test_authority_asset_context.py'):
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('')
            with patch.object(g,'ROOT',root),patch.object(g.volume,'ROOT',root),patch.object(g,'_original_sources',return_value=[]):
                before=g.sources()
                successor=folder/'033_content_security_revisions.sql';successor.write_text('-- unexecuted successor')
                self.assertEqual(g.migrations(),g.NAMES);self.assertEqual(len(g.migrations()),32)
                self.assertEqual(g.sources(),before)
                self.assertNotIn('packages/db/migrations/'+successor.name,{row['path'] for row in before})
                successor.write_text('-- changed unexecuted bytes');self.assertEqual(g.sources(),before)
                latest=folder/'034_classification_label_identities.sql';latest.write_text('-- not applied')
                self.assertEqual(g.sources(),before);self.assertEqual(g.migrations(),g.NAMES)
                latest.write_text('-- changed latest');self.assertEqual(g.sources(),before)
                successor.unlink()
                with self.assertRaises(RuntimeError):g.sources()
                successor.write_text('-- restore required predecessor')
                for name in ('033_undeclared.sql','034_undeclared.sql','035_undeclared.sql'):
                    extra=folder/name;extra.write_text('-- unreviewed')
                    with self.assertRaises(RuntimeError):g.sources()
                    extra.unlink()
                (folder/g.NAMES[-1]).unlink()
                with self.assertRaises(RuntimeError):g.sources()

    @contextmanager
    def harness(self, admission_seconds):
        clock = [1000.0]
        calls = []
        def sources():
            calls.append(clock[0])
            clock[0] += admission_seconds
            return [{'path': 'synthetic-input.ts', 'sha256': 'a' * 64}]
        old_mask = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory(prefix='gc-asset-context-budget-') as directory:
                folder = Path(directory)
                with patch.object(g, 'REPORT', folder / 'published-report.json'), \
                     patch.object(g.authority, 'LOCAL', folder / 'evidence'), \
                     patch.object(g.authority, 'REPORT', folder / 'base-report.json'), \
                     patch.object(g, 'sources', side_effect=sources), \
                     patch.object(g.time, 'monotonic', side_effect=lambda: clock[0]), \
                     patch.object(g.authority.base.subprocess, 'Popen', side_effect=AssertionError('No process may start in this host control')) as process:
                    actual = g.Harness()
                    yield actual, clock, calls, process
                    process.assert_not_called()
        finally:
            os.umask(old_mask)

    def test_actual_constructor_counts_source_admission_in_one_absolute_deadline(self):
        for elapsed in (0, 37, 779, 781):
            with self.subTest(source_admission_seconds=elapsed), self.harness(elapsed) as (h, clock, calls, process):
                self.assertEqual(calls, [1000.0])
                self.assertEqual(h.deadline, 1780.0)
                self.assertEqual(h.deadline-clock[0], 780-elapsed)
                self.assertIsNone(h.cleanup_deadline)
                saved=json.loads((h.folder / 'report.json').read_text())
                self.assertEqual(saved['bounds'], {
                    'executionSeconds':780, 'cleanupSeconds':90, 'developerWrapperSeconds':900,
                    'wrapperReserveSeconds':30, 'sourceAdmissionIncluded':True,
                    'sqlStatementSeconds':25, 'repositoryOperationSeconds':30,
                    'defaultCommandSeconds':120, 'nativeHelperSeconds':180})
                self.assertEqual(saved['qualificationSources'], h.frozen)
                # Even long source admission cannot acquire a fresh command or
                # inherited1680s allowance after the original780s expires.
                clock[0]=max(clock[0], h.deadline)
                with patch.object(h, 'admission'), self.assertRaisesRegex(RuntimeError, 'lifecycle deadline exceeded'):
                    h.command(['forbidden-process'], timeout=120)
                self.assertEqual(h.deadline, 1780.0)
                process.assert_not_called()

    def test_actual_cleanup_reserves_ninety_seconds_without_renewing_execution(self):
        with self.harness(37) as (h, clock, calls, process):
            clock[0]=h.deadline
            h.phase='cleanup'
            def docker(*args, **kwargs):
                self.assertTrue(kwargs.get('cleanup'))
                self.assertIn(args[0], ('inspect', 'ps'))
                return types.SimpleNamespace(returncode=1 if args[0]=='inspect' else 0, stdout='')
            # Execute the inherited cleanup implementation, replacing only the
            # external Docker transport. Its actual90s allowance is measured.
            with patch.object(h, 'docker', side_effect=docker):
                h.cleanup()
            self.assertEqual(h.deadline,1780.0)
            self.assertEqual(h.cleanup_deadline,1870.0)
            self.assertEqual(h.cleanup_deadline-clock[0],g.CLEANUP_SECONDS)
            self.assertLess((h.cleanup_deadline-calls[0]),g.WRAPPER_SECONDS)
            self.assertEqual(h.report['cleanup'],{'ownedRemoved':True})
            # Cleanup-phase inventory must use cleanup=True, including callers
            # that do not themselves set that flag; it cannot renew execution.
            with patch.object(g.authority.Harness,'command',return_value='bounded-cleanup') as inherited:
                self.assertEqual(h.command(['inventory']), 'bounded-cleanup')
                inherited.assert_called_once_with(['inventory'],cleanup=True)
            clock[0]=h.cleanup_deadline
            with self.assertRaisesRegex(RuntimeError,'lifecycle deadline exceeded'):
                h.command(['forbidden-cleanup-process'])
            self.assertEqual(h.deadline,1780.0)
            process.assert_not_called()

    def test_repeated_expired_commands_cannot_reset_the_execution_clock(self):
        with self.harness(781) as (h, clock, calls, process):
            for advance in (0,30,120):
                clock[0]+=advance
                with patch.object(h,'admission'), self.assertRaisesRegex(RuntimeError,'lifecycle deadline exceeded'):
                    h.command(['forbidden-process'],timeout=600)
                self.assertEqual(h.deadline,calls[0]+780)
            process.assert_not_called()


if __name__ == '__main__':
    unittest.main()
