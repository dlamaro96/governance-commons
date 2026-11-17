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


def success(rows,digest='a'*64):
 return SimpleNamespace(returncode=0,stdout=json.dumps({'rows':rows,'sha256':digest}),stderr='')


class QualitySnapshotTest(unittest.TestCase):
 def test_every_table_uses_sorted_fixed_width_row_hashes_with_multiplicity(self):
  h=FakeSQL([success(33571),success(0,'b'*64)])
  observed=gate.canonical_snapshot(h,['public.asset_revisions','gc_authority.write_lock_claims'])
  self.assertEqual(observed,{'public.asset_revisions':{'rows':33571,'sha256':'a'*64},
                             'gc_authority.write_lock_claims':{'rows':0,'sha256':'b'*64}})
  self.assertEqual(len(h.queries),2)
  for (query,kwargs),table in zip(h.queries,observed):
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
     gate.canonical_snapshot(h,[table])
    self.assertEqual(h.queries,[])

 def test_malformed_digest_count_or_result_fails_closed(self):
  for result in ({'rows':True,'sha256':'a'*64},{'rows':-1,'sha256':'a'*64},
                 {'rows':1,'sha256':'A'*64},{'rows':1,'sha256':None},
                 {'rows':1,'sha256':'a'*63},{'rows':1,'sha256':'a'*64,'extra':True},[]):
   with self.subTest(result=result):
    h=FakeSQL([SimpleNamespace(returncode=0,stdout=json.dumps(result),stderr='')])
    with self.assertRaisesRegex(RuntimeError,'Invalid canonical snapshot'):
     gate.canonical_snapshot(h,['public.asset_revisions'])

 def test_connection_failure_retains_only_safe_category_and_stops_snapshot(self):
  private='private test payload must not be retained'
  h=FakeSQL([success(1),SimpleNamespace(returncode=2,stdout=private,
            stderr='server closed the connection unexpectedly\n'+private),success(3)])
  with self.assertRaisesRegex(RuntimeError,'safe category retained'):
   gate.canonical_snapshot(h,['public.assets','public.asset_revisions','public.audit'])
  self.assertEqual(len(h.queries),2)
  self.assertEqual(h.report,{'qualitySnapshotFailure':{'table':'public.asset_revisions',
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


if __name__=='__main__':unittest.main()
