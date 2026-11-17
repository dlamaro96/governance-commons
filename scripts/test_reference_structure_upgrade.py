"""Host source-composition controls only. Docker helper leaf is replaced, never launched."""
import ast, importlib.util, json, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('structure_gate',ROOT/'scripts/runtime-test-reference-structure-upgrade.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
LEAF=m.Harness.__mro__[-2];q=m.base.base.base.base.base
class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.h=object.__new__(m.Harness);self.h.folder=Path(self.tmp.name);self.h.report={'cachedPackageAdmission':True}
  self.h.structure_predecessor={'sources':m.sources()};self.h.structure_current=None;self.h.structure_serial=0
  self.h.reference_quality_predecessor={'sources':m.base.sources()};self.h.reference_quality_current=None;self.h.reference_quality_serial=0
  self.h.reference_predecessor={'sources':m.base.base.sources()};self.h.reference_current=None;self.h.reference_serial=0
  self.h.classification_predecessor={'sources':m.base.base.base.sources()};self.h.classification_current=None;self.h.classification_serial=0
  self.h.repository_stage=None;self.h.phase='lineage-native-tests';self.calls=[]
  def leaf(h,args,*,mounts=(),**kwargs):self.calls.append((list(args),list(mounts),kwargs));return subprocess.CompletedProcess(args,0,'{}','')
  p=patch.object(LEAF,'helper',leaf);p.start();self.addCleanup(p.stop)
 def mounts(self):return [(host,target) for _,mounts,_ in self.calls for host,target in mounts]
 def selected(self,path):
  found=[Path(host) for host,target in self.mounts() if target=='/app/'+path];self.assertEqual(len(found),1);return found[0]
 def to022(self):
  self.h.reference_predecessor=None;self.h.reference_current={'sources':m.base.base.sources()};self.h.classification_predecessor=None;self.h.phase='reference-native-tests'
 def to023(self):
  self.h.reference_quality_predecessor=None;self.h.reference_quality_current={'sources':m.base.sources()};self.h.reference_predecessor=None;self.h.classification_predecessor=None;self.h.phase='reference-quality-native-tests'
 def test_exact_fixtures_and_migration_case_inventory(self):
  m.fixtures();self.assertEqual(len(m.NAMES),23);self.assertEqual(m.NAMES[-1],'023_reference_quality.sql');self.assertEqual(sum((ROOT/p).read_text().count('\ntest(') for p in m.TESTS),30);self.assertEqual(len(m.PREDECESSORS),3)
 def test_migration_is_the_complete_single_generated_candidate(self):
  data=(ROOT/'packages/db/migrations'/m.MIGRATION).read_bytes();self.assertEqual(m.sha(data),'71a019163fec45a88fc91f4cb53839e582c23eb37db7615928ae5d7f888dcd2c');self.assertEqual(data.decode().count('CREATE FUNCTION public.gc_reference_structure_release_seal()'),1)
 def test_sql023_default_hook_requires_exact_current_phase_and_retained_source_map(self):
  self.to023();rows=[r for r in self.h.reference_quality_current['sources'] if r['path'].endswith('.ts')]
  self.assertEqual(m.base.Harness.reference_quality_native_source_expectations(self.h,rows),m.base.native_sources(rows))
  with self.assertRaises(RuntimeError):m.base.Harness.reference_quality_native_source_expectations(self.h,[{'path':'a.ts','sha256':'a'*64}])
 def test_sql018_repository_remains_exact(self):
  self.h.phase='approval-native-tests';f=self.h.folder/'predecessor.ts';f.write_bytes((ROOT/q.PREDECESSOR_FIXTURE).read_bytes());stage=q.repository_phase(self.h,'predecessor',f,q.PREDECESSOR_SHA256,True);self.h.repository_stage=stage
  self.h.helper(['node','--test','owned.ts']);self.assertEqual(m.sha(self.selected(m.REPOSITORY).read_bytes()),q.PREDECESSOR_SHA256);self.assertIs(self.h.repository_stage,stage);self.assertNotIn('structureSourceChecks',self.h.report)
 def test_sql019_repository_still_uses_original_classification_pin(self):
  self.h.phase='quality-native-tests';stage=q.repository_phase(self.h,'current',ROOT/q.REPOSITORY,m.sha((ROOT/q.REPOSITORY).read_bytes()),False);self.h.repository_stage=stage
  self.h.helper(['node','--test','owned.ts']);row=next(r for r in m.base.base.base.PREDECESSORS if r['path']==m.REPOSITORY);self.assertEqual(m.sha(self.selected(m.REPOSITORY).read_bytes()),row['sha256']);self.assertIs(self.h.repository_stage,stage)
 def test_sql021_exact_older_approval_and_repository_take_precedence(self):
  self.h.classification_predecessor=None;self.h.classification_current={'sources':m.base.base.base.sources()};self.h.phase='classification-native-tests';self.h.helper(['node','--test','owned.ts'])
  for row in m.base.base.PREDECESSORS:self.assertEqual(m.sha(self.selected(row['path']).read_bytes()),row['sha256'])
  self.assertNotIn('structureSourceChecks',self.h.report)
 def test_sql022_declared_approval_bytes_and_prior_repository(self):
  self.to022();rows=[r for r in self.h.reference_current['sources'] if r['path'].endswith('.ts')];expected=self.h.reference_native_source_expectations(rows);self.h.helper(['node','--test','owned.ts'])
  for row in m.PREDECESSORS:
   if row['path']!=m.REPOSITORY:self.assertEqual(m.sha(self.selected(row['path']).read_bytes()),row['sha256'])
  repo=next(r for r in m.base.PREDECESSORS if r['path']==m.REPOSITORY);self.assertEqual(m.sha(self.selected(m.REPOSITORY).read_bytes()),repo['sha256'])
  actual=[r for r in self.h.report['referenceSourceChecks'][-1]['effectiveSources'] if r['path'].endswith('.ts')];self.assertEqual(actual,expected)
 def test_sql023_three_declared_pins_and_honest_quality_verifier(self):
  self.to023();rows=[r for r in self.h.reference_quality_current['sources'] if r['path'].endswith('.ts')];expected=self.h.reference_quality_native_source_expectations(rows);self.h.helper(['node','--test','owned.ts'])
  for row in m.PREDECESSORS:self.assertEqual(m.sha(self.selected(row['path']).read_bytes()),row['sha256']);self.assertEqual(next(r['sha256'] for r in expected if r['path']==row['path']),row['sha256'])
  quality=self.h.report['referenceQualitySourceChecks'][-1];repo=next(r for r in quality['effectiveOwnedSources'] if r['path']==m.REPOSITORY);self.assertEqual(repo['sha256'],m.PREDECESSORS[-1]['sha256'])
 def test_sql024_retains_only_exact_pre_volume_service_and_repository(self):
  self.to023();self.h.reference_quality_current=None;self.h.structure_predecessor=None;self.h.structure_current={'sources':m.sources()};self.h.phase='structure-native-tests';self.h.helper(['node','--test','owned.ts'])
  for row in m.NATIVE_BINDINGS:self.assertEqual(m.sha(self.selected(row['path']).read_bytes()),row['sha256'])
  self.assertFalse(any(target=='/app/'+row['path'] for _,target in self.mounts() for row in m.PREDECESSORS if row['path']!=m.REPOSITORY))
  record=self.h.report['structureSourceChecks'][-1];self.assertEqual({r['path'] for r in record['overrides']},{r['path'] for r in m.NATIVE_BINDINGS});self.assertTrue(record['sourceHashesMatched'])
  expected=m.native_sources(self.h.structure_current['sources']);self.assertEqual(record['effectiveOwnedSources'],[r for r in expected if r['path'] in {p['path'] for p in (*m.PREDECESSORS,*m.NATIVE_BINDINGS)}])
 def test_standalone_sql023_mounts_and_reports_each_retained_native_module(self):
  self.to023();standalone=object.__new__(m.base.Harness);standalone.__dict__.update(self.h.__dict__)
  rows=[r for r in standalone.reference_quality_current['sources'] if r['path'].endswith('.ts')]
  expected=standalone.reference_quality_native_source_expectations(rows)
  standalone.helper(['node','--test','owned.ts'])
  for row in m.base.NATIVE_BINDINGS:
   self.assertEqual(m.sha(self.selected(row['path']).read_bytes()),row['sha256'])
   self.assertEqual(next(r['sha256'] for r in expected if r['path']==row['path']),row['sha256'])
  record=standalone.report['referenceQualitySourceChecks'][-1]
  self.assertEqual(record['effectiveOwnedSources'],[r for r in expected if r['path'] in m.base.NON_REPOSITORY|{m.REPOSITORY}])
  self.assertEqual(len(self.mounts()),len({target for _,target in self.mounts()}))
 def test_standalone_sql023_rejects_duplicate_or_untrusted_service_override_before_leaf(self):
  self.to023();standalone=object.__new__(m.base.Harness);standalone.__dict__.update(self.h.__dict__)
  row=m.base.NATIVE_BINDINGS[0];target='/app/'+row['path'];fixed=(ROOT/row['fixture'],target)
  for mounts in ([(ROOT/'package.json',target)],[fixed,fixed],[(ROOT/'package.json','/app/packages/domain')]):
   with self.assertRaises(RuntimeError):standalone.helper(['node'],mounts=mounts)
  self.assertEqual(self.calls,[])
 def test_sql022_outer_quality_bytes_keep_precedence_over_later_service(self):
  self.to022();self.h.helper(['node','--test','owned.ts'])
  row=next(r for r in m.base.PREDECESSORS if r['path']=='packages/domain/src/quality-service.ts')
  self.assertEqual(m.sha(self.selected(row['path']).read_bytes()),row['sha256'])
 def test_sql023_nested_retained_service_has_one_exact_mount_and_honest_verifier(self):
  self.to023();self.h.helper(['node','--test','owned.ts']);row=m.base.NATIVE_BINDINGS[0]
  self.assertEqual(m.sha(self.selected(row['path']).read_bytes()),row['sha256'])
  record=self.h.report['referenceQualitySourceChecks'][-1]
  self.assertEqual(next(r['sha256'] for r in record['effectiveOwnedSources'] if r['path']==row['path']),row['sha256'])
  self.assertEqual(len(self.mounts()),len({target for _,target in self.mounts()}))
 def test_changed_missing_or_wrong_phase_source_map_refused(self):
  self.to023();rows=[r for r in self.h.reference_quality_current['sources'] if r['path'].endswith('.ts')]
  for value in [rows[:-1],[{**rows[0],'sha256':'0'*64},*rows[1:]]]:
   with self.assertRaises(RuntimeError):self.h.reference_quality_native_source_expectations(value)
  self.h.phase='unknown'
  with self.assertRaises(RuntimeError):self.h.helper(['node'])
  self.assertEqual(self.calls,[])
 def test_untrusted_conflicting_mounts_refused_before_leaf(self):
  self.to023()
  for target in ['/app','/app/apps/api/src',m.PROBE,'/app/apps/api/src/repository.ts']:
   with self.subTest(target=target),self.assertRaises(RuntimeError):self.h.helper(['node'],mounts=[(ROOT/'package.json',target)])
  self.assertEqual(self.calls,[])
 def test_leaf_failure_preserves_failure_and_releases_nested_overlays(self):
  self.to023()
  with patch.object(LEAF,'helper',side_effect=RuntimeError('synthetic leaf failure')),self.assertRaisesRegex(RuntimeError,'synthetic leaf'):self.h.helper(['node'])
  for name in ['structureSourceChecks','referenceQualitySourceChecks']:
   record=self.h.report[name][-1];self.assertEqual(record['result'],'FAIL');self.assertTrue(record['overrideReleased']);self.assertTrue(record['sourceHashesMatched'])
 def test_failed_native_suite_replaces_inherited_totals_with_actual_tap(self):
  self.to023();self.h.reference_quality_current=None;self.h.structure_predecessor=None;self.h.report['tests']={'tests':21,'pass':21};frozen=m.sources();measured=[r for r in frozen if r['path'].endswith('.ts')]
  tap='TAP version 13\nnot ok 1 - synthetic failure\n1..1\n# tests 1\n# suites 0\n# pass 0\n# fail 1\n# cancelled 0\n# skipped 0\n# todo 0\n# duration_ms 1.25\n'
  def fake(args,**kwargs):return subprocess.CompletedProcess(args,0,json.dumps(m.native_sources(measured)),'') if '-e' in args else subprocess.CompletedProcess(args,1,tap,'')
  with patch.object(self.h,'helper',fake),self.assertRaises(RuntimeError):m.run_suite(self.h,frozen,'structure-native-tests',m.TESTS,30,'structureTests')
  self.assertEqual(self.h.report['tests']['tests'],1);self.assertEqual(self.h.report['tests']['fail'],1);self.assertEqual(self.h.report['structureTestsExitStatus'],1);self.assertIsNone(self.h.structure_current)
 def test_malformed_or_skipped_tap_cannot_qualify(self):
  with self.assertRaises(RuntimeError):m.native_tap_totals('not TAP')
  tap='TAP version 13\nok 1 - skip # SKIP\n1..1\n# tests 1\n# suites 0\n# pass 0\n# fail 0\n# cancelled 0\n# skipped 1\n# todo 0\n# duration_ms 1.25\n'
  with self.assertRaises(RuntimeError):m.tap_summary(tap,1)
 def test_generated_verifier_rejects_real_startup_and_exit_tampering(self):
  node=shutil.which('node');self.assertIsNotNone(node);owned=self.h.folder/'input.ts';owned.write_text('safe');row={'path':'input.ts','sha256':m.sha(owned.read_bytes())};script=m.verifier([row]).replace("'/app/'+row.path",json.dumps(str(self.h.folder)+'/')+'+row.path');probe=self.h.folder/'probe.cjs';probe.write_text(script)
  run=lambda code:subprocess.run([node,'--require',str(probe),'-e',code],capture_output=True,text=True,timeout=10)
  self.assertEqual(run('0').returncode,0);owned.write_text('changed');self.assertNotEqual(run('0').returncode,0);owned.write_text('safe');self.assertNotEqual(run('require("node:fs").writeFileSync('+json.dumps(str(owned))+',"changed")').returncode,0)
if __name__=='__main__':unittest.main()
