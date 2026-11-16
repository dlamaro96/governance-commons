#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host-only predecessor binding controls; no Docker or database execution."""
import hashlib
import importlib.util
import shutil
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('pin',ROOT/'scripts/qualification_repository.py')
pin=importlib.util.module_from_spec(spec);spec.loader.exec_module(pin)
NODE=shutil.which('node')
if NODE is None:raise RuntimeError('Node is required for qualification repository controls')
CONTENT=(ROOT/pin.FIXTURE).read_bytes()
ARGS=['node','--import','tsx','--test','tests/qualification/synthetic.test.ts']

class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  for path,body in ((pin.REPOSITORY,b'export const current = true;\n'),(pin.FIXTURE,CONTENT)):
   file=self.root/path;file.parent.mkdir(parents=True,exist_ok=True);file.write_bytes(body)
  self.folder=self.root/'.local/evidence/attempt';self.folder.mkdir(parents=True)
  self.h=SimpleNamespace(folder=self.folder,phase='approval-native-tests',report={'sources':[
   {'path':name,'sha256':pin.digest((self.root/name).read_bytes())} for name in (pin.REPOSITORY,pin.FIXTURE)]})
  self.calls=[]
 def inherited(self,args,**kwargs):
  self.calls.append((args,kwargs));return SimpleNamespace(returncode=0)
 def run_pin(self,**kwargs):
  return pin.run(self.h,kwargs.pop('inherited',self.inherited),kwargs.pop('args',ARGS),root=self.root,**kwargs)
 def outer(self):
  file=self.folder/'outer.ts';file.write_bytes(CONTENT)
  spec=importlib.util.spec_from_file_location('current_quality_gate',ROOT/'scripts/runtime-test-quality-upgrade.py')
  quality=importlib.util.module_from_spec(spec);spec.loader.exec_module(quality)
  self.h.repository_stage=quality.repository_phase(self.h,'predecessor',file,pin.DIGEST,True)
  probe=self.h.repository_stage['probe']
  return ['node','--require',pin.OUTER_PROBE_TARGET,*ARGS[1:]],[(file,pin.TARGET),(probe,pin.OUTER_PROBE_TARGET)]
 def test_all_four_native_phases_mount_exact_file_and_preserve_current_checkout(self):
  before=(self.root/pin.REPOSITORY).read_bytes()
  for phase in sorted(pin.PHASES):
   self.h.phase=phase;self.run_pin()
   args,kw=self.calls[-1];self.assertEqual(args[:3],['node','--require',pin.PROBE_TARGET])
   mounted=dict((target,host) for host,target in kw['mounts'])
   self.assertEqual(mounted[pin.TARGET].read_bytes(),CONTENT)
   self.assertEqual(mounted[pin.TARGET].stat().st_mode&0o777,0o444)
   stage=self.h.report['predecessorRepositoryStages'][-1]
   self.assertEqual(stage['result'],'PASS');self.assertTrue(stage['overrideReleased']);self.assertTrue(stage['sourceHashesMatched'])
   self.assertEqual(next(r['sha256'] for r in stage['effectiveSources'] if r['path']==pin.REPOSITORY),pin.DIGEST)
  self.assertEqual((self.root/pin.REPOSITORY).read_bytes(),before)
 def test_current019_and_non_test_phases_are_untouched(self):
  for phase in ('quality-native-tests','quality-upgrade','admission'):
   self.h.phase=phase;self.run_pin()
   self.assertEqual(self.calls[-1],(ARGS,{'mounts':()}))
  self.assertNotIn('predecessorRepositoryStages',self.h.report)
 def test_caller_mount_conflict_and_malformed_fixture_refuse_before_execution(self):
  for target in ('/app','/app/apps/api/src',pin.TARGET,pin.TARGET+'/child',pin.PROBE_TARGET):
   with self.assertRaises(RuntimeError):self.run_pin(mounts=[(self.folder/'foreign',target)])
  (self.root/pin.FIXTURE).write_bytes(b'wrong')
  with self.assertRaises(RuntimeError):self.run_pin()
  self.assertEqual(self.calls,[])
 def test_nonzero_and_exception_preserve_failure_and_release(self):
  self.run_pin(inherited=lambda *a,**k:SimpleNamespace(returncode=7))
  self.assertEqual(self.h.report['predecessorRepositoryStages'][-1]['result'],'NONZERO')
  self.h.phase='glossary-native-tests'
  def fail(*a,**k):raise ValueError('synthetic')
  with self.assertRaises(ValueError):self.run_pin(inherited=fail)
  stage=self.h.report['predecessorRepositoryStages'][-1]
  self.assertEqual(stage['result'],'FAIL');self.assertTrue(stage['overrideReleased'])
 def test_return_time_private_file_and_checkout_tamper_are_refused(self):
  for target in ('private','probe','checkout'):
   self.h.phase={'private':'approval-native-tests','probe':'glossary-native-tests','checkout':'scope-native-tests'}[target]
   def tamper(args,**kw):
    path=self.root/pin.REPOSITORY if target=='checkout' else next(host for host,dest in kw['mounts'] if dest==(pin.TARGET if target=='private' else pin.PROBE_TARGET))
    path.chmod(0o600);path.write_bytes(b'changed');return SimpleNamespace(returncode=0)
   with self.assertRaises(RuntimeError):self.run_pin(inherited=tamper)
   stage=self.h.report['predecessorRepositoryStages'][-1]
   self.assertEqual(stage['result'],'FAIL');self.assertFalse(stage['sourceHashesMatched']);self.assertTrue(stage['overrideReleased'])
 def test_exact_outer_delegation_keeps_one_mount_and_existing_evidence(self):
  args,mounts=self.outer();self.h.report['sourceStages']=[{'original':True}]
  self.run_pin(args=args,mounts=mounts)
  self.assertEqual(self.calls,[(args,{'mounts':tuple(mounts)})])
  self.assertEqual(self.h.report['sourceStages'],[{'original':True}]);self.assertNotIn('predecessorRepositoryStages',self.h.report)
 def test_outer_forged_program_missing_or_duplicate_mount_and_wrong_stage_refuse(self):
  args,mounts=self.outer()
  for bad in (mounts[:1],mounts+[mounts[0]],mounts+[(self.folder,'/app')]):
   with self.assertRaises(RuntimeError):self.run_pin(args=args,mounts=bad)
  probe=self.h.repository_stage['probe'];probe.chmod(0o600);probe.write_text('/* no verifier */')
  self.h.repository_stage['probeSha256']=pin.digest(probe.read_bytes())
  with self.assertRaises(RuntimeError):self.run_pin(args=args,mounts=mounts)
  self.h.repository_stage['name']='current'
  with self.assertRaises(RuntimeError):self.run_pin(args=args,mounts=mounts)
  self.assertEqual(self.calls,[])
 def test_delegated_file_tamper_after_execution_refuses(self):
  args,mounts=self.outer()
  def tamper(*a,**k):self.h.repository_stage['file'].write_bytes(b'changed');return SimpleNamespace(returncode=0)
  with self.assertRaises(RuntimeError):self.run_pin(args=args,mounts=mounts,inherited=tamper)
 def test_actual_node_verifier_checks_startup_and_exit(self):
  self.run_pin();probe=self.calls[-1][1]['mounts'][0][0];file=self.calls[-1][1]['mounts'][1][0]
  source=probe.read_text();self.assertEqual(source.count(json.dumps(pin.TARGET)),1)
  host_probe=self.folder/'host-check.cjs';host_probe.write_text(source.replace(json.dumps(pin.TARGET),json.dumps(str(file))))
  def invoke(code):return subprocess.run([str(NODE),'--require',str(host_probe),'-e',code],capture_output=True,timeout=5)
  self.assertEqual(invoke('').returncode,0)
  file.chmod(0o600)
  self.assertNotEqual(invoke("require('node:fs').writeFileSync("+json.dumps(str(file))+",'changed')").returncode,0)
  self.assertNotEqual(invoke('').returncode,0)
 def test_fixture_matches_fixed_digest_and_git_blob_and_descendants_share_wrapper(self):
  self.assertEqual(pin.digest(CONTENT),pin.DIGEST)
  # Git object identity is a format compatibility check, not a security hash.
  # SHA256 above binds the bytes without needing history in a shallow checkout.
  framed=b'blob '+str(len(CONTENT)).encode('ascii')+b'\0'+CONTENT
  self.assertEqual(hashlib.sha1(framed,usedforsecurity=False).hexdigest(),pin.BLOB)
  for script in ('approvals','glossary','relation-scope','glossary-population'):
   spec=importlib.util.spec_from_file_location('gate_'+script,ROOT/('scripts/runtime-test-'+script+'-upgrade.py'))
   gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
   self.assertEqual(Path(__import__('inspect').getfile(gate.Harness.helper)).name,'runtime-test-approvals-upgrade.py')
   self.assertIn('repository.run',__import__('inspect').getsource(gate.Harness.helper))
   self.assertIn('scripts/qualification_repository.py',{r['path'] for r in gate.sources()})

if __name__=='__main__':unittest.main()
