# SPDX-License-Identifier: Apache-2.0
"""Host-only controls for the bounded native-gate snapshot; no Docker launch."""
import importlib.util
import json
from pathlib import Path
import re
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('quality_snapshot_gate',ROOT/'scripts/runtime-test-quality-upgrade.py')
gate=importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class FakeSQL:
 def __init__(self,outputs):
  self.outputs=iter(outputs)
  self.queries=[]
  self.report={}
 def sql_result(self,query,**kwargs):
  self.queries.append((query,kwargs))
  return next(self.outputs)


def success(*rows):
 return SimpleNamespace(returncode=0,stdout='\n'.join(json.dumps(row) for row in rows)+'\n',stderr='')

def row(table,rows=1,digest='a'*64):
 return {'table':table,'rows':rows,'sha256':digest}


class QualitySnapshotTest(unittest.TestCase):
 def test_every_table_uses_sorted_fixed_width_row_hashes_with_multiplicity(self):
  h=FakeSQL([success(row('public.asset_revisions',33571),row('gc_authority.write_lock_claims',0,'b'*64))])
  observed=gate.canonical_snapshot(h,['public.asset_revisions','gc_authority.write_lock_claims'])
  self.assertEqual(observed,{'public.asset_revisions':{'rows':33571,'sha256':'a'*64},
                             'gc_authority.write_lock_claims':{'rows':0,'sha256':'b'*64}})
  self.assertEqual(len(h.queries),1)
  query,kwargs=h.queries[0]
  self.assertTrue(query.startswith('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n'))
  self.assertTrue(query.endswith('\nCOMMIT;'))
  for table in observed:
   self.assertIn('FROM '+table+' r',query)
   self.assertIn("sha256(convert_to(to_jsonb(r)::text,'UTF8'))",query)
   self.assertIn('WITH row_hashes AS MATERIALIZED',query)
   self.assertIn("string_agg(value,''::bytea ORDER BY value)",query)
   self.assertIn("coalesce(string_agg(value,''::bytea ORDER BY value),''::bytea)",query)
   self.assertIn("'rows',count(*)",query)
   self.assertNotRegex(query,re.compile(r'jsonb?_agg|DISTINCT|LIMIT|WHERE',re.IGNORECASE))
   self.assertEqual(kwargs,{'allow_failure':True})

 def test_identifier_validation_precedes_sql(self):
  for table in ('public.assets; DELETE FROM public.assets','public."assets"','public.assets extra','assets'):
   with self.subTest(table=table):
    h=FakeSQL([])
    with self.assertRaisesRegex(RuntimeError,'Invalid fixed snapshot table'):
     gate.canonical_snapshot(h,['public.assets',table])
    self.assertEqual(h.queries,[])

 def test_malformed_digest_count_or_result_fails_closed(self):
  for result in ({'rows':True,'sha256':'a'*64},{'rows':-1,'sha256':'a'*64},
                 {'rows':1,'sha256':'A'*64},{'rows':1,'sha256':None},
                 {'rows':1,'sha256':'a'*63},{'rows':1,'sha256':'a'*64,'extra':True},[]):
   with self.subTest(result=result):
    if isinstance(result,dict):result={'table':'public.asset_revisions',**result}
    h=FakeSQL([SimpleNamespace(returncode=0,stdout=json.dumps(result),stderr='')])
    with self.assertRaisesRegex(RuntimeError,'Invalid canonical snapshot'):
     gate.canonical_snapshot(h,['public.asset_revisions'])

 def test_connection_failure_retains_only_safe_category_and_stops_snapshot(self):
  private='private test payload must not be retained'
  tables=['public.assets','public.asset_revisions','public.audit']
  h=FakeSQL([SimpleNamespace(returncode=2,stdout=json.dumps(row(tables[0]))+'\n'+private,
            stderr='server closed the connection unexpectedly\n'+private)])
  with self.assertRaisesRegex(RuntimeError,'safe category retained'):
   gate.canonical_snapshot(h,tables)
  self.assertEqual(len(h.queries),1)
  self.assertEqual(h.report,{'qualitySnapshotFailure':{'tables':tables,
                                                     'exitStatus':2,'category':'CONNECTION_LOST'}})
  self.assertNotIn(private,json.dumps(h.report))

 def test_failure_categories_do_not_guess_memory_from_generic_connection_exit(self):
  for stderr,code in (('out of memory','OUT_OF_MEMORY'),('No space left on device','STORAGE_FULL'),
                      ('permission denied for table','PERMISSION_DENIED'),('unclassified private detail','SQL_COMMAND_FAILED')):
   with self.subTest(code=code):
    h=FakeSQL([SimpleNamespace(returncode=2,stdout='',stderr=stderr)])
    with self.assertRaises(RuntimeError):gate.canonical_snapshot(h,['public.assets'])
    self.assertEqual(h.report['qualitySnapshotFailure']['category'],code)
    self.assertNotIn(stderr,json.dumps(h.report))

 def test_missing_extra_duplicate_reordered_or_foreign_output_fails_closed(self):
  first,second=row('public.assets'),row('public.audit')
  for rows in ([first],[first,second,second],[first,first],[second,first],[first,row('public.unknown')]):
   with self.subTest(rows=rows):
    with self.assertRaisesRegex(RuntimeError,'Invalid canonical snapshot'):
     gate.canonical_snapshot(FakeSQL([success(*rows)]),['public.assets','public.audit'])

 def test_duplicate_or_unbounded_inventory_never_executes(self):
  for tables in (['public.assets']*2,['public.assets']*513,('public.assets',),[None],[[]]):
   with self.subTest(tables=str(tables)[:60]):
    h=FakeSQL([])
    with self.assertRaisesRegex(RuntimeError,'Invalid fixed snapshot table'):gate.canonical_snapshot(h,tables)
    self.assertEqual(h.queries,[])

 def test_fixed_batch_bound_preserves_full_ordered_inventory(self):
  tables=['public.table_'+chr(97+n) for n in range(26)]
  h=FakeSQL([success(*(row(t) for t in tables[:16])),success(*(row(t) for t in tables[16:]))])
  self.assertEqual(list(gate.canonical_snapshot(h,tables)),tables)
  self.assertEqual(len(h.queries),2)
  self.assertEqual([q.count('WITH row_hashes AS MATERIALIZED') for q,_ in h.queries],[16,10])
  empty=FakeSQL([])
  self.assertEqual(gate.canonical_snapshot(empty,[]),{})
  self.assertEqual(empty.queries,[])

 def test_failed_later_batch_never_returns_partial_snapshot(self):
  tables=['public.table_'+chr(97+n) for n in range(20)]
  h=FakeSQL([success(*(row(t) for t in tables[:16])),SimpleNamespace(returncode=1,stdout='',stderr='permission denied')])
  with self.assertRaisesRegex(RuntimeError,'safe category retained'):gate.canonical_snapshot(h,tables)
  self.assertEqual(h.report['qualitySnapshotFailure']['tables'],tables[16:])
  self.assertEqual(len(h.queries),2)


if __name__=='__main__':unittest.main()
