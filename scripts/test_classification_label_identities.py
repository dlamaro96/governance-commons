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
spec = importlib.util.spec_from_file_location('classification_label_identity_budget_gate', ROOT / 'scripts/runtime-test-classification-label-identities.py')
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


class Controls(unittest.TestCase):
    def test_declared037_successor_is_excluded_and_gapped_or_unknown_inventory_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);folder=root/'packages/db/migrations';folder.mkdir(parents=True)
            for name in g.NAMES:(folder/name).write_text('-- historical prefix')
            for name in (g.NEW_TEST,'scripts/runtime-test-classification-label-identities.py','scripts/test_classification_label_identities.py','tests/api/classification-storage.test.ts',):
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('')
            with patch.object(g,'ROOT',root),patch.object(g.volume,'ROOT',root),patch.object(g,'_original_sources',return_value=[]):
                before=g.sources();self.assertEqual(len(g.migrations()),34)
                suffix=['035_reviewed_classification_producer.sql', '036_authority_scope_alignment.sql', '037_application_authentication_bridge.sql']
                for name in suffix:
                    path=folder/name;path.write_text('-- declared successor only')
                    self.assertEqual(g.migrations(),g.NAMES);self.assertEqual(g.sources(),before)
                    self.assertNotIn('packages/db/migrations/'+name,{row['path'] for row in before})
                    path.write_text('-- successor content never belongs to this historical profile')
                    self.assertEqual(g.sources(),before)
                for name in ('036_undeclared.sql','037_undeclared.sql','038_undeclared.sql'):
                    extra=folder/name;extra.write_text('-- unreviewed')
                    with self.assertRaises(RuntimeError):g.sources()
                    extra.unlink()
                missing=folder/'035_reviewed_classification_producer.sql'
                old=missing.read_bytes();missing.unlink()
                with self.assertRaises(RuntimeError):g.sources()
                missing.write_bytes(old);self.assertEqual(g.sources(),before)

    def test_exact034_inventory_binds_seed_harness_host_and_migration_and_refuses_successors(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);folder=root/'packages/db/migrations';folder.mkdir(parents=True)
            for name in g.NAMES:(folder/name).write_text('-- exact prefix')
            for name in (g.NEW_TEST,'scripts/runtime-test-classification-label-identities.py',
                         'scripts/test_classification_label_identities.py','tests/api/classification-storage.test.ts'):
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('')
            with patch.object(g,'ROOT',root),patch.object(g.volume,'ROOT',root),patch.object(g,'_original_sources',return_value=[]):
                before=g.sources();self.assertEqual(len(g.migrations()),34)
                for name in ('packages/db/migrations/'+g.MIGRATION,'scripts/runtime-test-classification-label-identities.py',
                             'scripts/test_classification_label_identities.py',g.NEW_TEST):
                    self.assertIn(name,{row['path'] for row in before})
                    path=root/name;old=path.read_bytes();path.write_bytes(old+b'// changed source')
                    self.assertNotEqual(g.sources(),before);path.write_bytes(old)
                for name in ('034_undeclared.sql','035_undeclared.sql'):
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
            with tempfile.TemporaryDirectory(prefix='gc-classification-label-budget-') as directory:
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
        new_tables=[*old_tables,*sorted(g.TABLE_ADDITIONS)]
        new_functions=[*copy.deepcopy(old_functions),*[{'signature':name} for name in sorted(g.FUNCTION_ADDITIONS)]]
        new_privileges=copy.deepcopy(old_privileges)
        new_privileges['tables'].extend({'name':name,'owner':'1','acl':'private','rls':True,'forced':True} for name in sorted(g.TABLE_ADDITIONS))
        new_triggers=[*copy.deepcopy(old_triggers),*[{'schema':schema,'table':table,'name':name} for schema,table,name in sorted(g.trigger_additions())]]
        return [old_tables,old_functions,old_privileges,old_triggers,new_tables,new_functions,new_privileges,new_triggers]

    def test_exact_additions_preserve_prior_inventory(self):
        g.preserve_installation(*self.inputs())
        self.assertEqual(len(g.TABLE_ADDITIONS),3)
        self.assertEqual(len(g.FUNCTION_ADDITIONS),4)
        self.assertEqual(len(g.trigger_additions()),8)
        self.assertIn(('public','classification_taxonomies','classification_label_head_complete'),g.trigger_additions())

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


class BaselineControls(unittest.TestCase):
    def inputs(self):
        expected=[];observed={name:[] for name in g.TABLE_ADDITIONS}
        for tenant,tax,ids in [('a','t',['00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000002','00000000-0000-4000-8000-000000000003','00000000-0000-4000-8000-000000000004']),
                               ('b','u',['00000000-0000-4000-8000-000000000005','00000000-0000-4000-8000-000000000006','00000000-0000-4000-8000-000000000007','00000000-0000-4000-8000-000000000008'])]:
            labels=g.baseline_definitions()[2]['labels'];current={r['key']:r['status'] for r in labels}
            expected.append({'tenantId':tenant,'taxonomyId':tax,'baselineVersion':3,'baselineHash':'a'*64,
                             'labels':labels,'historicKeys':['retained','absent','deprecated','reused']})
            observed['gc_authority.classification_label_baselines'].append({'tenant_id':tenant,'taxonomy_id':tax,'baseline_version':3,'baseline_hash':'a'*64})
            for key,identity in zip(expected[-1]['historicKeys'],ids):
                observed['gc_authority.classification_label_identities'].append({'tenant_id':tenant,'taxonomy_id':tax,
                    'id':identity,'label_key':key,'first_registered_version':3,'retired_at_version':None if current.get(key)=='active' else 3})
                if key in current:
                    observed['gc_authority.classification_label_version_bindings'].append({'tenant_id':tenant,'taxonomy_id':tax,
                        'taxonomy_version':3,'label_key':key,'label_id':identity,'label_status':current[key]})
        return expected,observed

    def test_complete_current_only_baseline_reserves_omitted_history(self):
        result=g.verify_baselines(*self.inputs())
        self.assertEqual((result['taxonomies'],result['identities'],result['bindings']),(2,8,6))
        self.assertTrue(result['currentPinOnly'] and result['allHistoricKeysReserved'])

    def test_historic_binding_reactivation_alias_and_foreign_missing_rows_refused(self):
        for fault in ('historical_binding','omitted_reservation','wrong_retirement','invented_first_version','wrong_pin','wrong_hash',
                      'wrong_status','wrong_label_uuid','duplicate_key','foreign_row','missing_taxonomy','uuid_alias'):
            with self.subTest(fault=fault):
                expected,rows=self.inputs();baselines=rows['gc_authority.classification_label_baselines'];identities=rows['gc_authority.classification_label_identities'];bindings=rows['gc_authority.classification_label_version_bindings']
                if fault=='historical_binding':bindings.append({**bindings[0],'taxonomy_version':1})
                elif fault=='omitted_reservation':identities.pop(1)
                elif fault=='wrong_retirement':identities[1]['retired_at_version']=None
                elif fault=='invented_first_version':identities[0]['first_registered_version']=1
                elif fault=='wrong_pin':baselines[0]['baseline_version']=1
                elif fault=='wrong_hash':baselines[0]['baseline_hash']='b'*64
                elif fault=='wrong_status':bindings[0]['label_status']='deprecated'
                elif fault=='wrong_label_uuid':bindings[0]['label_id']=identities[1]['id']
                elif fault=='duplicate_key':identities.append(copy.deepcopy(identities[0]))
                elif fault=='foreign_row':bindings.append({**bindings[0],'tenant_id':'unaccounted'})
                elif fault=='missing_taxonomy':baselines.pop()
                elif fault=='uuid_alias':identities[4]['id']=identities[0]['id']
                with self.assertRaises(RuntimeError):g.verify_baselines(expected,rows)

    def test_seed_uses_canonical_publisher_and_exports_two_scoped_markers(self):
        with tempfile.TemporaryDirectory() as directory:
            secret=Path(directory)/'private.json';secret.write_text(json.dumps({'synthetic':'preserved'}));calls=[]
            h=types.SimpleNamespace(secret_path=secret,report={},sql=lambda body,**kw:calls.append((body,kw)))
            markers=g.seed_baselines(h)
            self.assertEqual(len(markers),2);self.assertEqual(len(calls),2)
            self.assertNotEqual(markers[0]['tenantId'],markers[1]['tenantId'])
            self.assertNotEqual(markers[0]['taxonomyId'],markers[1]['taxonomyId'])
            for marker,(body,options) in zip(markers,calls):
                self.assertEqual(marker['baselineVersion'],3);self.assertEqual(options,{'role':g.authority.base.OWNER})
                self.assertEqual(body.count("public.gc_classification_command('classification.taxonomy.publish'"),3)
                self.assertNotIn('INSERT INTO public.classification_taxonomies',body)
                self.assertNotIn('INSERT INTO public.classification_taxonomy_versions',body)
                self.assertIn("SET LOCAL statement_timeout='25s'",body)
                self.assertIn("SET LOCAL lock_timeout='2s'",body)
                self.assertIn('SET CONSTRAINTS ALL IMMEDIATE; COMMIT;',body)
            config=json.loads(secret.read_text());self.assertEqual(config['synthetic'],'preserved')
            self.assertEqual(config['classificationLabelBaselineFixtures'],markers)
            self.assertEqual(h.report['privateConfigSha256'],g.sha(secret.read_bytes()))

    def test_seed_histories_have_exact_removed_deprecated_and_reused_states(self):
        definitions=g.baseline_definitions();self.assertEqual(len(definitions),3)
        states=[{r['key']:r['status'] for r in definition['labels']} for definition in definitions]
        self.assertEqual(states,[{'retained':'active','absent':'active','deprecated':'active','reused':'active'},
            {'retained':'active','deprecated':'deprecated'}, {'retained':'active','deprecated':'deprecated','reused':'active'}])



if __name__ == '__main__':
    unittest.main()
