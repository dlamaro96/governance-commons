#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host controls for SQL037 admission/preservation; no Docker or SQL execution."""
import copy
from contextlib import contextmanager, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('application_authn_bridge_host_controls',ROOT/'scripts/runtime-test-application-authn-bridge.py')
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)

class SourceControls(unittest.TestCase):
 @contextmanager
 def synthetic(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);folder=root/'packages/db/migrations';folder.mkdir(parents=True)
   for name in g.NAMES:(folder/name).write_text('-- synthetic exact prefix')
   for name in [g.SEED,g.NATIVE,'scripts/runtime-test-application-authn-bridge.py','scripts/test_application_authn_bridge.py']:
    p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('')
   with patch.object(g,'ROOT',root),patch.object(g.volume,'ROOT',root),patch.object(g,'original_sources',return_value=[]):yield root,folder
 def test_exact037_and_native_partition_are_source_bound(self):
  rows=g.sources();paths={r['path'] for r in rows}
  self.assertEqual(len(paths),len(rows));self.assertEqual(len(g.NAMES),37);self.assertEqual(g.NAMES[-1],g.MIGRATION)
  for path in [g.SEED,g.NATIVE,'scripts/runtime-test-application-authn-bridge.py','scripts/test_application_authn_bridge.py',*['packages/db/migrations/'+n for n in g.NAMES]]:self.assertIn(path,paths)
  self.assertEqual(len(g.volume.declared_tests(g.SEED,1)),1)
  self.assertEqual(g.EXPECTED_TESTS,25);self.assertEqual(len(g.volume.declared_tests(g.NATIVE,25)),25)
  self.assertEqual(g.PHASES,('application-authn-predecessor','application-authn-native'))
 def test_missing_renamed037_extra038_or_gapped_prefix_refuses(self):
  with self.synthetic() as (root,folder):
   before=g.sources();target=folder/g.MIGRATION;renamed=target.with_name('037_renamed.sql')
   target.rename(renamed)
   with self.assertRaises(RuntimeError):g.sources()
   renamed.rename(target)
   extra=folder/'038_undeclared.sql';extra.write_text('-- unknown')
   with self.assertRaises(RuntimeError):g.sources()
   extra.unlink()
   for name in [g.NAMES[12],g.NAMES[-2],g.NAMES[-1]]:
    p=folder/name;old=p.read_bytes();p.unlink()
    with self.assertRaises(RuntimeError):g.sources()
    p.write_bytes(old)
   self.assertEqual(g.sources(),before)
 def test_migration_control_native_and_transitive_bytes_are_bound(self):
  with self.synthetic() as (root,folder):
   original=g.sources()
   for name in ['packages/db/migrations/'+g.MIGRATION,g.SEED,g.NATIVE,'scripts/test_application_authn_bridge.py','scripts/runtime-test-application-authn-bridge.py']:
    p=root/name;old=p.read_bytes();p.write_bytes(old+b'changed');self.assertNotEqual(g.sources(),original);p.write_bytes(old)
   native=root/g.NATIVE;native.write_text("import './leaf.js';")
   with self.assertRaises(RuntimeError):g.sources()
   leaf=native.with_name('leaf.ts');leaf.write_text('export {};')
   first=g.sources();self.assertIn(str(leaf.relative_to(root)),{r['path'] for r in first})
   leaf.write_text('export const changed=true;');self.assertNotEqual(g.sources(),first)
   leaf.unlink();leaf.symlink_to(root/g.SEED)
   with self.assertRaises(RuntimeError):g.sources()
 def test_source_bound_is_not_silently_truncated(self):
  with self.synthetic() as (root,folder):
   native=root/g.NATIVE;imports=[]
   for i in range(1025):
    leaf=native.with_name(f'leaf{i}.ts');leaf.write_text('export {};');imports.append(f"import './leaf{i}.js';")
   native.write_text('\n'.join(imports))
   with self.assertRaisesRegex(RuntimeError,'inventory exceeds bound'):g.sources()
 def test_unknown_native_phase_cannot_use_current_source_overlay(self):
  rows=[{'path':'synthetic.ts','sha256':'a'*64}]
  for phase in g.PHASES:self.assertEqual(g.volume.effective_sources(rows,phase),rows)
  for phase in ('','content-security-revision-native','application-authn-unregistered'):
   with self.assertRaises(RuntimeError):g.volume.effective_sources(rows,phase)

class PreservationControls(unittest.TestCase):
 def inputs(self):
  before={'functions':[{'signature':'public.existing()','oid':'1','body':'fixed','metadata':{'proparallel':'u'},'acl':'fixed'}],
   'privileges':{'tables':[{'name':'public.assets','owner':'1','acl':'private','rls':True,'forced':True}],
    'roles':[{'name':'gc_app','super':False,'bypass':False}],'memberships':[]},
   'triggers':[{'schema':'public','table':'assets','name':'existing','definition':'fixed','enabled':'O'}],
   'types':[{'name':'public.gc_authn_authenticated_session','metadata':{'oid':'91','typowner':'10','typtype':'c'},
    'acl':[{'grantee':'10','grantor':'10','privilege_type':'USAGE','is_grantable':False}]},
    {'name':'public.existing','metadata':{'oid':'92'},'acl':[]}]}
  after=copy.deepcopy(before)
  after['functions'] += [{'signature':name} for name in sorted(g.NEW_FUNCTIONS)]
  after['privileges']['tables'] += [{'name':name,'owner':'1','acl':'private','rls':True,'forced':True} for name in sorted(g.TABLES)]
  for i in range(7):after['triggers'].append({'schema':'gc_authn','table':'application_bridge_installations' if i<4 else 'application_bridge_receipts','name':f'new{i}'})
  after['types'] += [{'name':name,'metadata':{},'acl':[]} for name in sorted(g.TABLES|{'gc_authn._application_bridge_installations','gc_authn._application_bridge_receipts'})]
  after['types'][0]['acl'].append({'grantee':'42','grantor':'10','privilege_type':'USAGE','is_grantable':False})
  return before,after
 def test_exact_additions_and_native_oid_string_usage_grant_pass(self):
  before,after=self.inputs();g.preserve(before,after,42)
  self.assertEqual(len(g.TABLES),2);self.assertEqual(len(g.NEW_FUNCTIONS),9)
  self.assertIn("to_jsonb(p)-'prosrc'",g.FUNCTIONS);self.assertIn("to_jsonb(t)-'typacl'",g.TYPES)
 def test_existing_metadata_roles_grants_or_triggers_cannot_change(self):
  for fault in ['function_body','function_oid','function_metadata','function_acl','table_acl','table_rls','table_owner','role','membership','trigger','type_metadata','type_acl','result_type_metadata']:
   with self.subTest(fault=fault):
    before,after=self.inputs()
    if fault.startswith('function_'):after['functions'][0][fault.removeprefix('function_')]='changed'
    elif fault.startswith('table_'):after['privileges']['tables'][0][fault.removeprefix('table_')]='changed'
    elif fault=='role':after['privileges']['roles'][0]['super']=True
    elif fault=='membership':after['privileges']['memberships'].append({'roleid':'99','member':'42'})
    elif fault=='trigger':after['triggers'][0]['enabled']='D'
    elif fault=='type_metadata':after['types'][1]['metadata']['oid']='999'
    elif fault=='type_acl':after['types'][1]['acl'].append({'grantee':'42'})
    elif fault=='result_type_metadata':after['types'][0]['metadata']['typowner']='42'
    with self.assertRaises(RuntimeError):g.preserve(before,after,42)
 def test_type_grant_must_be_exact_non_grantable_usage_to_application_oid(self):
  for fault in ['missing','grantable','wrong_grantee','numeric_grantee','wrong_grantor','wrong_privilege','extra_grant','removed_old_grant']:
   with self.subTest(fault=fault):
    before,after=self.inputs();acl=after['types'][0]['acl']
    if fault=='missing':acl.pop()
    elif fault=='grantable':acl[-1]['is_grantable']=True
    elif fault=='wrong_grantee':acl[-1]['grantee']='43'
    elif fault=='numeric_grantee':acl[-1]['grantee']=42
    elif fault=='wrong_grantor':acl[-1]['grantor']='99'
    elif fault=='wrong_privilege':acl[-1]['privilege_type']='CREATE'
    elif fault=='extra_grant':acl.append({'grantee':'0','grantor':'10','privilege_type':'USAGE','is_grantable':False})
    elif fault=='removed_old_grant':acl.pop(0)
    with self.assertRaises(RuntimeError):g.preserve(before,after,42)
 def test_missing_or_extra_objects_or_unrelated_trigger_targets_refuse(self):
  for fault in ['missing_function','extra_function','missing_table','extra_table','missing_trigger','extra_trigger','trigger_target','extra_type','missing_type']:
   with self.subTest(fault=fault):
    before,after=self.inputs()
    if fault=='missing_function':after['functions'].pop()
    elif fault=='extra_function':after['functions'].append({'signature':'public.escape()'})
    elif fault=='missing_table':after['privileges']['tables'].pop()
    elif fault=='extra_table':after['privileges']['tables'].append({'name':'public.escape'})
    elif fault=='missing_trigger':after['triggers'].pop()
    elif fault=='extra_trigger':after['triggers'].append({'schema':'gc_authn','table':'application_bridge_installations','name':'extra'})
    elif fault=='trigger_target':after['triggers'][-1]['table']='sessions'
    elif fault=='extra_type':after['types'].append({'name':'public.escape'})
    elif fault=='missing_type':after['types'].pop()
    with self.assertRaises(RuntimeError):g.preserve(before,after,42)

class FailureAndReportControls(unittest.TestCase):
 def test_failure_cleanup_and_private_report_outcome_are_fail_closed(self):
  for fault in (None,'execution','controlled','cleanup','inventory','credential'):
   with self.subTest(fault=fault),tempfile.TemporaryDirectory() as directory:
    root=Path(directory);folder=root/'evidence';folder.mkdir();secret=folder/'secret.json';secret.write_text('{}');calls=[]
    h=types.SimpleNamespace(folder=folder,secret_path=secret,phase='native',resources_before=['original'],report={'cleanup':{}},save=lambda **kw:calls.append('save'))
    def cleanup():
     calls.append('cleanup')
     if fault=='cleanup':raise RuntimeError('PRIVATE_SYNTHETIC cleanup')
     h.report['cleanup']['ownedRemoved']=True
    h.cleanup=cleanup;h.inventory=lambda: ['changed'] if fault=='inventory' else ['original']
    def execute(_):
     calls.append('execute')
     if fault=='execution':raise RuntimeError('PRIVATE_SYNTHETIC secret')
     if fault=='controlled':raise RuntimeError('Unexpected public type privilege change')
    if fault=='credential':h.secret_path=types.SimpleNamespace(unlink=lambda **kw:None,exists=lambda:True)
    with patch.object(g,'ROOT',root),patch.object(g,'REPORT',root/'report.json'),patch.object(g,'Harness',return_value=h),patch.object(g,'execute',side_effect=execute),patch.object(sys,'argv',['gate','--run-local']),redirect_stdout(io.StringIO()) as output:
     code=g.main()
    self.assertEqual(code,int(fault is not None));self.assertEqual(h.report['result'],'PASS' if fault is None else 'FAIL')
    self.assertIn('cleanup',calls);self.assertEqual(calls[-1],'save')
    self.assertNotIn('PRIVATE_SYNTHETIC',json.dumps(h.report)+output.getvalue())
    if fault=='controlled':self.assertEqual(h.report['failedAssertion'],'Unexpected public type privilege change')
    if fault!='credential':self.assertFalse(secret.exists());self.assertTrue(h.report['cleanup']['generatedCredentialsRemoved'])
    else:self.assertFalse(h.report['cleanup']['generatedCredentialsRemoved'])
 def test_explicit_local_argument_required_before_harness_creation(self):
  with patch.object(sys,'argv',['gate']),patch.object(g,'Harness') as harness:
   with self.assertRaises(RuntimeError):g.main()
   harness.assert_not_called()

class BudgetControls(unittest.TestCase):
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
                     patch.object(g.content, 'sources', side_effect=sources), \
                     patch.object(g.content.time, 'monotonic', side_effect=lambda: clock[0]), \
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
            self.assertEqual(h.cleanup_deadline-clock[0],g.content.CLEANUP_SECONDS)
            self.assertLess((h.cleanup_deadline-calls[0]),g.content.WRAPPER_SECONDS)
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


if __name__=='__main__':unittest.main()
