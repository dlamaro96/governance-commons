# SPDX-License-Identifier: Apache-2.0
"""Producer migration admission, preservation and absolute lifecycle controls."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def module(path,name):
 spec=importlib.util.spec_from_file_location(name,path);result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
g=module(ROOT/'scripts/runtime-test-reviewed-classification-producer.py','producer_gate_controls')
base=module(ROOT/'scripts/test_classification_label_identities.py','producer_budget_controls')
base.g=g

class BudgetControls(unittest.TestCase):
 harness=base.Controls.harness
 test_absolute_admission_deadline=base.Controls.test_actual_constructor_counts_source_admission_in_one_absolute_deadline
 test_owned_cleanup_deadline=base.Controls.test_actual_cleanup_reserves_ninety_seconds_without_renewing_execution
 test_expired_commands=base.Controls.test_repeated_expired_commands_cannot_reset_the_execution_clock

class PreservationControls(unittest.TestCase):
 def inputs(self):
  before_tables=['public.assets'];before_functions=[{'signature':'public.existing()','body':'fixed','acl':'fixed'}]
  before_privileges={'tables':[{'name':'public.assets','owner':'1','acl':'fixed','rls':True,'forced':True}],
   'roles':[{'name':'gc_app','super':False}],'memberships':[]}
  before_triggers=[{'schema':g.TRIGGER_TARGET[0],'table':g.TRIGGER_TARGET[1],'name':g.TRIGGER_TARGET[2],
   'function':'gc_authority.deferred_complete()',
   'enabled':'O','definition':'CREATE CONSTRAINT TRIGGER authority_binding_complete AFTER INSERT ON gc_authority.write_bindings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gc_authority.deferred_complete()'},
   {'schema':'public','table':'assets','name':'keep','enabled':'O','definition':'fixed'}]
  after_tables=before_tables+sorted(g.TABLE_ADDITIONS)
  after_functions=copy.deepcopy(before_functions)+[{'signature':s} for s in sorted(g.FUNCTION_ADDITIONS)]
  after_privileges=copy.deepcopy(before_privileges);after_privileges['tables'] += [{'name':s,'owner':'1','acl':'private','rls':True,'forced':True} for s in sorted(g.TABLE_ADDITIONS)]
  after_triggers=copy.deepcopy(before_triggers);after_triggers[0]['definition']=after_triggers[0]['definition'].replace('gc_authority.deferred_complete()','gc_authority.write_binding_complete_v2()')
  after_triggers[0]['function']='gc_authority.write_binding_complete_v2()'
  after_triggers += [{'schema':schema,'table':table,'name':name} for schema,table,name in sorted(g.TRIGGER_ADDITIONS)]
  return [before_tables,before_functions,before_privileges,before_triggers,after_tables,after_functions,after_privileges,after_triggers]
 def test_only_declared_target_changes(self):
  g.preserve_installation(*self.inputs());self.assertEqual(len(g.TABLE_ADDITIONS),2);self.assertEqual(len(g.FUNCTION_ADDITIONS),12);self.assertEqual(len(g.TRIGGER_ADDITIONS),7)
 def test_old_object_and_trigger_semantics_cannot_drift(self):
  for fault in ['function','acl','role','trigger_timing','trigger_enabled','trigger_function','original_trigger_function','unrelated_trigger','missing_original','extra_table','unforced_rls','extra_function','missing_guard']:
   with self.subTest(fault=fault):
    x=self.inputs()
    if fault=='function':x[5][0]['body']='changed'
    elif fault=='acl':x[6]['tables'][0]['acl']='wider'
    elif fault=='role':x[6]['roles'][0]['super']=True
    elif fault=='trigger_timing':x[7][0]['definition']=x[7][0]['definition'].replace('INITIALLY DEFERRED','INITIALLY IMMEDIATE')
    elif fault=='trigger_enabled':x[7][0]['enabled']='D'
    elif fault=='trigger_function':x[7][0]['function']='gc_authority.deferred_complete()'
    elif fault=='original_trigger_function':x[3][0]['function']='gc_authority.unrelated()'
    elif fault=='unrelated_trigger':x[7][1]['definition']='changed'
    elif fault=='missing_original':x[3].pop(0)
    elif fault=='extra_table':x[4].append('public.unregistered')
    elif fault=='unforced_rls':x[6]['tables'][-1]['forced']=False
    elif fault=='extra_function':x[5].append({'signature':'gc_authority.escape()'})
    elif fault=='missing_guard':x[7].pop()
    with self.assertRaises(RuntimeError):g.preserve_installation(*x)
 def test_declared037_successor_is_excluded_and_gapped_or_unknown_inventory_refuses(self):
     with tempfile.TemporaryDirectory() as directory:
         root=Path(directory);folder=root/'packages/db/migrations';folder.mkdir(parents=True)
         for name in g.NAMES:(folder/name).write_text('-- historical prefix')
         for name in (g.NEW_TEST,g.FACT_TEST,'tests/fixtures/reviewed-classification-facts.ts','scripts/runtime-test-reviewed-classification-producer.py','scripts/test_reviewed_classification_producer.py',):
             path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('')
         with patch.object(g,'ROOT',root),patch.object(g.volume,'ROOT',root),patch.object(g,'_original_sources',return_value=[]):
             before=g.sources();self.assertEqual(len(g.migrations()),35)
             suffix=['036_authority_scope_alignment.sql', '037_application_authentication_bridge.sql']
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

 def test_source_admission_exact035_and_declared_prefix(self):
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory);folder=root/'packages/db/migrations';folder.mkdir(parents=True)
   for n in g.NAMES:(folder/n).write_text('-- prefix')
   for n in [g.NEW_TEST,g.FACT_TEST,'tests/fixtures/reviewed-classification-facts.ts','scripts/runtime-test-reviewed-classification-producer.py','scripts/test_reviewed_classification_producer.py']:
    p=root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('')
   with patch.object(g,'ROOT',root),patch.object(g.volume,'ROOT',root),patch.object(g,'_original_sources',return_value=[]):
    original=g.sources();self.assertEqual(len(g.NAMES),35)
    for n in [g.NEW_TEST,'packages/db/migrations/'+g.MIGRATION]:
     p=root/n;old=p.read_bytes();p.write_bytes(old+b'changed');self.assertNotEqual(g.sources(),original);p.write_bytes(old)
    for n in ['035_undeclared.sql','036_undeclared.sql']:
     p=folder/n;p.write_text('extra')
     with self.assertRaises(RuntimeError):g.sources()
     p.unlink()
    (folder/g.MIGRATION).unlink()
    with self.assertRaises(RuntimeError):g.sources()

if __name__=='__main__':unittest.main()
