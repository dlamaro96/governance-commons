# SPDX-License-Identifier: Apache-2.0
"""Host negative controls; Docker and SQL execution are separately qualified."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def module(path,name):
 spec=importlib.util.spec_from_file_location(name,path);result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
g=module(ROOT/'scripts/runtime-test-held-metadata-authority.py','held_metadata_controls')
base=module(ROOT/'scripts/test_classification_label_identities.py','held_metadata_budget_controls')
base.g=g

class BudgetControls(unittest.TestCase):
 harness=base.Controls.harness
 test_absolute_admission_deadline=base.Controls.test_actual_constructor_counts_source_admission_in_one_absolute_deadline
 test_owned_cleanup_deadline=base.Controls.test_actual_cleanup_reserves_ninety_seconds_without_renewing_execution
 test_expired_commands=base.Controls.test_repeated_expired_commands_cannot_reset_the_execution_clock

class PreservationControls(unittest.TestCase):
 def inputs(self):
  tables=['public.assets'];functions=[{'signature':s,'oid':str(i),'body':'old','acl':'fixed','owner':'1','definer':False,'config':['row_security=on'],'volatility':'v','metadata':{'proisstrict':False,'proparallel':'u','proleakproof':False,'prolang':123,'procost':100,'prosupport':'-','proargdefaults':None}} for i,s in enumerate(g.SIGNATURES.values())]
  functions.append({'signature':'public.existing()','oid':'99','body':'fixed','acl':'fixed'})
  privileges={'tables':[{'name':'public.assets','owner':'1','acl':'fixed','rls':True,'forced':True}],'roles':[{'name':'gc_app','super':False}],'memberships':[]}
  triggers=[{'schema':'public','table':'assets','name':'fixed','enabled':'O','definition':'fixed'}]
  after=copy.deepcopy(functions)
  for row in after:
   if row['signature'] in g.expected_function_bodies():row['body']=g.expected_function_bodies()[row['signature']]
  return [tables,functions,privileges,triggers,copy.deepcopy(tables),after,copy.deepcopy(privileges),copy.deepcopy(triggers)]
 def test_exact_three_admitted_bodies_and_unchanged_interfaces(self):
  self.assertEqual(len(g.expected_function_bodies()),3);g.preserve_installation(*self.inputs())
 def test_complete_pg_proc_metadata_cannot_change(self):
  self.assertIn("'metadata',to_jsonb(p)-'prosrc'",g.FUNCTIONS)
  for key in self.inputs()[1][0]['metadata']:
   with self.subTest(field=key):
    x=self.inputs();x[5][0]['metadata'][key]='changed'
    with self.assertRaises(RuntimeError):g.preserve_installation(*x)
 def test_no_unrelated_or_interface_changes_are_permitted(self):
  for fault in ['body','unchanged','oid','acl','owner','definer','config','volatility','other_function','extra_function','missing_function','duplicate_function','table','rls','role','trigger']:
   with self.subTest(fault=fault):
    x=self.inputs()
    if fault=='unchanged':x[5][0]['body']=x[1][0]['body']
    elif fault in ['body','oid','acl','owner','definer','config','volatility']:x[5][0][fault]='changed'
    elif fault=='other_function':x[5][-1]['body']='changed'
    elif fault=='extra_function':x[5].append({'signature':'public.extra()'})
    elif fault=='missing_function':x[5].pop(0)
    elif fault=='duplicate_function':x[5].append(x[5][0])
    elif fault=='table':x[4].append('public.extra')
    elif fault=='rls':x[6]['tables'][0]['forced']=False
    elif fault=='role':x[6]['roles'][0]['super']=True
    elif fault=='trigger':x[7][0]['enabled']='D'
    with self.assertRaises(RuntimeError):g.preserve_installation(*x)
 def test_exact036_source_prefix_and_all_native_test_bindings(self):
  rows=g.sources();paths={r['path'] for r in rows};self.assertEqual(len(rows),len(paths));self.assertEqual(len(g.NAMES),36)
  for path in [g.PREFLIGHT,g.SEED,g.SCOPE,g.HELD,'packages/authority-runtime/src/held-metadata-composition.ts','packages/authority-storage/src/repository.ts','packages/db/migrations/'+g.MIGRATION]:self.assertIn(path,paths)
  self.assertEqual(len(g.predecessor.NAMES),35);self.assertEqual(len(g.predecessor.PHASES),5)
  for path,count in [(g.PREFLIGHT,8),(g.SEED,1),(g.SCOPE,16),(g.HELD,g.EXPECTED_HELD_TESTS)]:self.assertEqual(len(g.volume.declared_tests(path,count)),count)
  self.assertEqual(len(g.PHASES),9);self.assertGreater(g.EXPECTED_HELD_TESTS,0)
 def test_declared037_stays_outside036_and_gaps_renames_or_unknown038_refuse(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);folder=root/'packages/db/migrations';folder.mkdir(parents=True)
   for name in g.NAMES:(folder/name).write_text('-- historical prefix')
   for name in [g.PREFLIGHT,g.SEED,g.SCOPE,g.HELD,'scripts/runtime-test-held-metadata-authority.py','scripts/test_held_metadata_authority.py']:
    path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('')
   with patch.object(g,'ROOT',root),patch.object(g.volume,'ROOT',root),patch.object(g,'_original_sources',return_value=[]):
    before=g.sources();self.assertEqual(len(g.migrations()),36)
    successor=folder/'037_application_authentication_bridge.sql';successor.write_text('-- declared successor')
    self.assertEqual(g.migrations(),g.NAMES);self.assertEqual(g.sources(),before)
    self.assertNotIn('packages/db/migrations/'+successor.name,{r['path'] for r in before})
    successor.write_text('-- changed but unexecuted');self.assertEqual(g.sources(),before)
    renamed=successor.with_name('037_undeclared.sql');successor.rename(renamed)
    with self.assertRaises(RuntimeError):g.sources()
    renamed.rename(successor)
    extra=folder/'038_undeclared.sql';extra.write_text('-- unreviewed')
    with self.assertRaises(RuntimeError):g.sources()
    extra.unlink();missing=folder/g.MIGRATION;old=missing.read_bytes();missing.unlink()
    with self.assertRaises(RuntimeError):g.sources()
    missing.write_bytes(old);self.assertEqual(g.sources(),before)

 def test_missing_extra_gap_or_changed_migration_does_not_pass(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);folder=root/'packages/db/migrations';folder.mkdir(parents=True)
   for n in g.NAMES:(folder/n).write_text('-- prefix')
   for n in [g.PREFLIGHT,g.SEED,g.SCOPE,g.HELD,'scripts/runtime-test-held-metadata-authority.py','scripts/test_held_metadata_authority.py']:
    p=root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('')
   with patch.object(g,'ROOT',root),patch.object(g.volume,'ROOT',root),patch.object(g,'_original_sources',return_value=[]):
    original=g.sources();target=folder/g.MIGRATION;target.write_text('-- changed');self.assertNotEqual(g.sources(),original)
    for name in ['036_undeclared.sql','037_undeclared.sql']:
     extra=folder/name;extra.write_text('-- extra')
     with self.assertRaises(RuntimeError):g.sources()
     extra.unlink()
    (folder/g.NAMES[13]).unlink()
    with self.assertRaises(RuntimeError):g.sources()

class MarkerControls(unittest.TestCase):
 def marker(self):
  kinds=['reverse-own','future-reverse-own','expired-reverse-own','child-effect-lifetime','child-effect-lifetime','child-onward-lifetime','child-onward-lifetime','revoked-bad-ancestor','revoked-bad-ancestor']
  return {'formatVersion':1,'profile':'scope-alignment-sql035-legacy','tenantId':'10000000-0000-0000-0000-000000000000',
   'grants':[{'id':f'20000000-0000-0000-0000-{i:012x}','kind':k,'mustRefuse':i not in [3,5],'headSha256':'a'*64} for i,k in enumerate(kinds)]}
 def test_exact_marker_round_trip(self):
  value=self.marker();self.assertEqual(g.marker_from_tap('# GC_SCOPE_LEGACY_V1='+json.dumps(value)),value)
 def test_missing_duplicate_extra_and_incomplete_markers_refuse(self):
  with self.assertRaises(RuntimeError):g.marker_from_tap('')
  line='# GC_SCOPE_LEGACY_V1='+json.dumps(self.marker())
  with self.assertRaises(RuntimeError):g.marker_from_tap(line+'\n'+line)
  for fault in ['extra','profile','duplicate_id','head_count','digest','kind','boolean','refusal_count']:
   with self.subTest(fault=fault):
    value=self.marker()
    if fault=='extra':value['untrusted']=True
    elif fault=='profile':value['profile']='different'
    elif fault=='duplicate_id':value['grants'][1]['id']=value['grants'][0]['id']
    elif fault=='head_count':value['grants'].pop()
    elif fault=='digest':value['grants'][0]['headSha256']='not-a-digest'
    elif fault=='kind':value['grants'][0]['kind']='other'
    elif fault=='boolean':value['grants'][0]['mustRefuse']=1
    elif fault=='refusal_count':value['grants'][0]['mustRefuse']=False
    with self.assertRaises(RuntimeError):g.marker_from_tap('# GC_SCOPE_LEGACY_V1='+json.dumps(value))

class SafeDiagnosticControls(unittest.TestCase):
 def test_exact_closed_success_shape(self):
  result=g.safe_diagnostics(None,None,{'ownedRemoved':True,'resourceInventoryPreserved':True,'generatedCredentialsRemoved':True,'secret':'PRIVATE'})
  self.assertEqual(result,{'execution':{'phase':'none','category':'none','deadlineBudget':'none','deadlineStage':'none'},
   'cleanup':{'failure':{'phase':'none','category':'none','deadlineBudget':'none','deadlineStage':'none'},'ownedRemoved':True,'resourceInventoryPreserved':True,'generatedCredentialsRemoved':True}})
 def test_unobserved_or_wrong_typed_cleanup_values_are_unknown(self):
  for cleanup in (None,[],{'ownedRemoved':1,'resourceInventoryPreserved':'PRIVATE','generatedCredentialsRemoved':False}):
   result=g.safe_diagnostics(None,None,cleanup)['cleanup']
   self.assertIsNone(result['ownedRemoved']);self.assertIsNone(result['resourceInventoryPreserved'])
   self.assertIs(result['generatedCredentialsRemoved'],False if type(cleanup) is dict else None)
 def test_private_exception_text_and_phase_never_escape(self):
  for error in (RuntimeError('PRIVATE_SECRET'),OSError('PRIVATE_PATH'),ValueError('PRIVATE_INPUT')):
   result=g.safe_failure(error,'PRIVATE_SECRET')
   self.assertEqual(result,{'phase':'unknown','category':'other_failure','deadlineBudget':'none','deadlineStage':'none'})
   self.assertNotIn('PRIVATE',json.dumps(result))
 def test_plain_message_cannot_forge_explicit_deadline(self):
  for message in ('Bounded qualification lifecycle deadline exceeded','Bounded qualification command timed out'):
   self.assertEqual(g.safe_failure(RuntimeError(message),'scope-alignment-before036'),
    {'phase':'scope-alignment-before036','category':'other_failure','deadlineBudget':'none','deadlineStage':'none'})
 def test_deadline_marker_carries_original_phase_after_unwind(self):
  for budget in ('execution','command','cleanup'):
   for stage in ('admission','running'):
    error=g.authority.base.QualificationDeadlineExceeded(budget,stage,'schema-scope-alignment-install036')
    result=g.safe_failure(error,'cleanup')
    self.assertEqual(result,{'phase':'schema-scope-alignment-install036','category':'deadline_exceeded','deadlineBudget':budget,'deadlineStage':stage})
 def test_invalid_or_untrusted_marker_data_never_escape(self):
  error=g.authority.base.QualificationDeadlineExceeded('execution','running','PRIVATE_PHASE')
  self.assertEqual(g.safe_failure(error,'cleanup')['phase'],'unknown')
  error.budget='PRIVATE_BUDGET';error.stage='PRIVATE_STAGE'
  result=g.safe_failure(error,'PRIVATE_PHASE')
  self.assertEqual(result,{'phase':'unknown','category':'other_failure','deadlineBudget':'none','deadlineStage':'none'})
 def test_known_categories_do_not_copy_exception_messages(self):
  for error,category in [(KeyboardInterrupt('PRIVATE'),'interrupted'),
    (RuntimeError('Qualification command failed; retained bounded diagnostic'),'command_failed'),
    (RuntimeError('Native suite failed; inspect retained private TAP'),'native_failed')]:
   self.assertEqual(g.safe_failure(error,g.HELD_PHASE)['category'],category)
 def test_explicit_admission_deadline_refuses_before_subprocess(self):
  for cleanup in (False,True):
   with base.Controls.harness(self,0) as (h,clock,calls,process):
    if cleanup:h.phase='cleanup';h.cleanup_deadline=clock[0]
    else:clock[0]=h.deadline
    with patch.object(h,'admission'),self.assertRaises(g.authority.base.QualificationDeadlineExceeded) as caught:
     h.command(['forbidden-process'],cleanup=cleanup)
    self.assertEqual(caught.exception.budget,'cleanup' if cleanup else 'execution')
    self.assertEqual(caught.exception.stage,'admission');process.assert_not_called()
 def test_actual_subprocess_marks_which_unchanged_deadline_limited_it(self):
  import sys,time
  for budget in ('execution','command','cleanup'):
   with self.subTest(budget=budget),tempfile.TemporaryDirectory() as directory:
    h=object.__new__(g.authority.base.Harness);h.folder=Path(directory);h.phase='scope-alignment-before036'
    h.serial=0;h.output_bytes=0;h.private_values=[];h.admission=lambda:None
    now=time.monotonic();h.deadline=now+(.25 if budget=='execution' else 5)
    h.cleanup_deadline=now+.25 if budget=='cleanup' else None
    deadline=h.deadline
    with self.assertRaises(g.authority.base.QualificationDeadlineExceeded) as caught:
     h.command([sys.executable,'-c','import time; time.sleep(2)'],timeout=.25 if budget=='command' else 5,cleanup=budget=='cleanup')
    self.assertEqual((caught.exception.budget,caught.exception.stage),(budget,'running'))
    self.assertEqual(str(caught.exception),'Bounded qualification command timed out');self.assertEqual(h.deadline,deadline)
 def test_main_preserves_execution_failure_and_reports_cleanup_separately(self):
  import contextlib,io,sys,types
  for cleanup_fails in (False,True):
   with self.subTest(cleanup_fails=cleanup_fails),tempfile.TemporaryDirectory(dir=ROOT/'.local') as directory:
    folder=Path(directory);secret=folder/'private-config.json';secret.write_text('synthetic-private-input')
    h=types.SimpleNamespace(phase='scope-alignment-before036',report={},resources_before=None,folder=folder,secret_path=secret)
    def cleanup():
     if cleanup_fails:raise g.authority.base.QualificationDeadlineExceeded('cleanup','running','cleanup')
     h.report['cleanup']={'ownedRemoved':True}
    h.cleanup=cleanup;h.save=lambda **kwargs:None
    failure=g.authority.base.QualificationDeadlineExceeded('execution','running','scope-alignment-before036')
    output=io.StringIO()
    with patch.object(g,'Harness',return_value=h),patch.object(g,'execute',side_effect=failure),patch.object(sys,'argv',['runner','--run-local']),contextlib.redirect_stdout(output):
     self.assertEqual(g.main(),1)
    data=json.loads(output.getvalue());self.assertEqual(set(data),{'result','report','diagnostics'});self.assertEqual(data['result'],'FAIL')
    self.assertEqual(data['report'],str(g.REPORT.relative_to(ROOT)))
    self.assertEqual(data['diagnostics']['execution'],{'phase':'scope-alignment-before036','category':'deadline_exceeded','deadlineBudget':'execution','deadlineStage':'running'})
    cleaned=data['diagnostics']['cleanup'];self.assertTrue(cleaned['generatedCredentialsRemoved']);self.assertIsNone(cleaned['resourceInventoryPreserved'])
    self.assertEqual(cleaned['failure']['deadlineBudget'],'cleanup' if cleanup_fails else 'none')
    self.assertIs(cleaned['ownedRemoved'],None if cleanup_fails else True)
    self.assertLess(len(output.getvalue().encode()),2048);self.assertNotIn('synthetic-private-input',output.getvalue())

if __name__=='__main__':unittest.main()
