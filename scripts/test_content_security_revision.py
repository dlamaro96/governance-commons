# SPDX-License-Identifier: Apache-2.0
"""Real harness-constructor budget controls; no Docker or process execution."""
from contextlib import contextmanager
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('content_revision_budget_gate', ROOT / 'scripts/runtime-test-content-security-revision.py')
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


class Controls(unittest.TestCase):
    def test_exact033_inventory_binds_controls_and_admits_only_unexecuted034(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);folder=root/'packages/db/migrations';folder.mkdir(parents=True)
            for name in g.NAMES: (folder/name).write_text('-- exact prefix')
            for name in (g.NEW_TEST,'scripts/runtime-test-content-security-revision.py','scripts/test_content_security_revision.py','tests/api/classification-storage.test.ts'):
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('')
            with patch.object(g,'ROOT',root),patch.object(g.volume,'ROOT',root),patch.object(g,'_original_sources',return_value=[]):
                before=g.sources();self.assertEqual(len(g.migrations()),33)
                bound={row['path'] for row in before}
                self.assertIn('packages/db/migrations/'+g.MIGRATION,bound)
                self.assertIn('scripts/test_content_security_revision.py',bound)
                (folder/g.MIGRATION).write_text('-- changed candidate bytes')
                self.assertNotEqual(g.sources(),before)
                changed=g.sources()
                successor=folder/'034_classification_label_identities.sql';successor.write_text('-- not applied')
                self.assertEqual(g.migrations(),g.NAMES);self.assertEqual(g.sources(),changed)
                self.assertNotIn('packages/db/migrations/'+successor.name,{r['path'] for r in changed})
                successor.write_text('-- changed unexecuted successor');self.assertEqual(g.sources(),changed)
                for name in ('033_undeclared.sql','034_undeclared.sql','035_undeclared.sql'):
                    extra=folder/name;extra.write_text('-- unreviewed')
                    with self.assertRaises(RuntimeError):g.sources()
                    extra.unlink()
                (folder/g.MIGRATION).unlink()
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
            with tempfile.TemporaryDirectory(prefix='gc-content-revision-budget-') as directory:
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


class InstallationControls(unittest.TestCase):
    def inputs(self):
        old_tables=['public.assets']
        old_functions=[{'signature':'public.existing()','owner':'1','acl':None,'body':'fixed'}]
        old_privileges={'tables':[{'name':'public.assets','owner':'1','acl':'fixed','rls':True,'forced':True}],
                        'roles':[{'name':'gc_app','super':False}], 'memberships':[]}
        old_triggers=[{'schema':'public','table':'assets','name':'existing_guard','enabled':'O','definition':'fixed'}]
        new_tables=[*old_tables,'gc_authority.content_security_heads']
        new_functions=[*copy.deepcopy(old_functions),*[{'signature':name} for name in sorted(g.FUNCTION_ADDITIONS)]]
        new_privileges=copy.deepcopy(old_privileges)
        new_privileges['tables'].append({'name':'gc_authority.content_security_heads','owner':'1','acl':'private','rls':True,'forced':True})
        new_triggers=[*copy.deepcopy(old_triggers),*[{'schema':schema,'table':table,'name':name} for schema,table,name in sorted(g.trigger_additions())]]
        return [old_tables,old_functions,old_privileges,old_triggers,new_tables,new_functions,new_privileges,new_triggers]

    def test_exact_additions_preserve_prior_inventory(self):
        g.preserve_installation(*self.inputs())
        self.assertEqual(len(g.COVERED),6)
        self.assertIn(('public','domain_type_versions','content_revision_no_truncate'),g.trigger_additions())

    def test_existing_body_acl_role_and_trigger_changes_are_refused(self):
        for change in ('function_body','function_acl','table_acl','runtime_role','trigger','dropped_table'):
            with self.subTest(change=change):
                values=self.inputs()
                if change=='function_body': values[5][0]['body']='changed'
                elif change=='function_acl': values[5][0]['acl']='runtime=EXECUTE'
                elif change=='table_acl': values[6]['tables'][0]['acl']='widened'
                elif change=='runtime_role': values[6]['roles'][0]['super']=True
                elif change=='trigger': values[7][0]['enabled']='D'
                elif change=='dropped_table': values[4].remove('public.assets')
                with self.assertRaises(RuntimeError): g.preserve_installation(*values)

    def test_undeclared_schema_expansion_missing_guards_and_unforced_rls_are_refused(self):
        for change in ('extra_table','extra_function','missing_guard','extra_guard','unforced_rls'):
            with self.subTest(change=change):
                values=self.inputs()
                if change=='extra_table': values[4].append('public.undeclared')
                elif change=='extra_function': values[5].append({'signature':'gc_authority.escape()'})
                elif change=='missing_guard': values[7].pop()
                elif change=='extra_guard': values[7].append({'schema':'public','table':'assets','name':'undeclared'})
                elif change=='unforced_rls': values[6]['tables'][-1]['forced']=False
                with self.assertRaises(RuntimeError): g.preserve_installation(*values)


if __name__ == '__main__':
    unittest.main()
