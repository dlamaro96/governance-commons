#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host-only historical source binding; the Docker leaf is never executed."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
pin = load('approval_pin', ROOT / 'scripts/qualification_approval_service.py')
CONTENT = (ROOT / pin.FIXTURE).read_bytes()
ARGS = ['node', '--import', 'tsx', '--test', 'tests/qualification/synthetic.test.ts']
NODE = shutil.which('node')
if NODE is None:
    raise RuntimeError('Node is required for source verifier controls')

class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name, data in ((pin.SERVICE, b'export const current = true;\n'), (pin.FIXTURE, CONTENT)):
            file = self.root / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(data)
        self.folder = self.root / '.local/evidence/attempt'
        self.folder.mkdir(parents=True)
        self.h = SimpleNamespace(folder=self.folder, phase='approval-native-tests', report={'sources':[
            {'path': name, 'sha256': pin.digest((self.root / name).read_bytes())} for name in (pin.SERVICE, pin.FIXTURE)]})
        self.calls = []
    def leaf(self, args, **kwargs):
        self.calls.append((args, kwargs))
        return SimpleNamespace(returncode=0)
    def run_pin(self, **kwargs):
        return pin.run(self.h, kwargs.pop('inherited', self.leaf), kwargs.pop('args', ARGS), root=self.root, **kwargs)
    def outer(self):
        rows = [{'path': name, 'sha256': pin.DIGEST if name == pin.SERVICE else 'a'*64} for name in sorted(pin.OUTER_PATHS)]
        probe = self.folder / 'classification-source-1.cjs'
        probe.write_text(pin.outer_verifier(rows))
        self.h.classification_predecessor = {'sources': self.h.report['sources']}
        self.h.classification_current = None
        self.h.report['classificationSourceChecks'] = [{'phase': self.h.phase, 'stage':'SQL001-020', 'result':'RUNNING',
            'effectiveSources': rows, 'verifierSha256': pin.digest(probe.read_bytes()),
            'overrides':[{'path':pin.SERVICE,'fixture':pin.FIXTURE,'gitBlob':pin.BLOB,'sha256':pin.DIGEST,'commit':pin.COMMIT,'readOnly':True}]}]
        return ['node','--require',pin.OUTER_PROBE_TARGET,*ARGS[1:]], [(self.root / pin.FIXTURE, pin.TARGET),(probe,pin.OUTER_PROBE_TARGET)]
    def test_every_historical_phase_binds_exact_bytes_and_retains_checkout(self):
        before = (self.root / pin.SERVICE).read_bytes()
        for phase in sorted(pin.PHASES):
            self.h.phase = phase
            self.run_pin()
            args, options = self.calls[-1]
            self.assertEqual(args[:3], ['node','--require',pin.PROBE_TARGET])
            mounted = {target: host for host, target in options['mounts']}
            self.assertEqual(mounted[pin.TARGET].read_bytes(), CONTENT)
            self.assertEqual(mounted[pin.TARGET].stat().st_mode & 0o777, 0o444)
            record = self.h.report['predecessorApprovalStages'][-1]
            self.assertTrue(record['overrideReleased'] and record['sourceHashesMatched'])
            self.assertEqual(record['result'], 'PASS')
            self.assertEqual(next(r['sha256'] for r in record['effectiveSources'] if r['path'] == pin.SERVICE), pin.DIGEST)
        self.assertEqual((self.root / pin.SERVICE).read_bytes(), before)
    def test_other_phases_leave_current_code_and_arguments_untouched(self):
        for phase in ('admission','approval-upgrade','quality-native-tests','lineage-native-tests','classification-native-tests','reference-native-tests','structure-native-tests'):
            self.h.phase = phase
            self.run_pin()
            self.assertEqual(self.calls[-1], (ARGS, {'mounts':()}))
        self.assertNotIn('predecessorApprovalStages', self.h.report)
    def test_undeclared_conflicting_duplicate_mount_or_changed_fixture_refuses(self):
        for mounts in ([(self.folder,'/app')],[(self.folder,'/app/packages/domain')],[(self.root/pin.FIXTURE,pin.TARGET)],[(self.folder,pin.PROBE_TARGET)],[(self.root/pin.FIXTURE,pin.TARGET)]*2):
            with self.assertRaises(RuntimeError): self.run_pin(mounts=mounts)
        (self.root/pin.FIXTURE).write_bytes(b'changed')
        with self.assertRaises(RuntimeError): self.run_pin()
        self.assertEqual(self.calls, [])
    def test_nonzero_or_exception_never_becomes_a_pass(self):
        self.run_pin(inherited=lambda *a,**k: SimpleNamespace(returncode=7))
        self.assertEqual(self.h.report['predecessorApprovalStages'][-1]['result'],'NONZERO')
        self.h.phase='glossary-native-tests'
        def fail(*a,**k): raise ValueError('synthetic leaf failure')
        with self.assertRaises(ValueError): self.run_pin(inherited=fail)
        self.assertEqual(self.h.report['predecessorApprovalStages'][-1]['result'],'FAIL')
    def test_after_return_tamper_of_mount_probe_or_checkout_refuses(self):
        for target,phase in zip(('mount','probe','checkout'), sorted(pin.PHASES)):
            self.h.phase=phase
            def tamper(args,**options):
                file=self.root/pin.SERVICE if target=='checkout' else next(Path(host) for host,dest in options['mounts'] if dest==(pin.TARGET if target=='mount' else pin.PROBE_TARGET))
                file.chmod(0o600);file.write_bytes(b'changed');return SimpleNamespace(returncode=0)
            with self.assertRaises(RuntimeError):self.run_pin(inherited=tamper)
            record=self.h.report['predecessorApprovalStages'][-1]
            self.assertEqual(record['result'],'FAIL');self.assertFalse(record['sourceHashesMatched'])
    def test_outer_exact_declared_binding_retains_one_mount_and_verifier(self):
        args,mounts=self.outer();self.run_pin(args=args,mounts=mounts)
        self.assertEqual(self.calls,[(args,{'mounts':tuple(mounts)})])
        self.assertNotIn('predecessorApprovalStages',self.h.report)
    def test_outer_missing_duplicate_forged_or_undeclared_binding_refuses(self):
        args,mounts=self.outer()
        for invalid in (mounts[1:],mounts+[mounts[0]],mounts+[(self.folder,'/app/packages')],mounts+[mounts[1]]):
            with self.assertRaises(RuntimeError):self.run_pin(args=args,mounts=invalid)
        for bad in (ARGS,args[:1]+args[3:],args[:1]+args[1:3]+args[1:]):
            with self.assertRaises(RuntimeError):self.run_pin(args=bad,mounts=mounts)
        record=self.h.report['classificationSourceChecks'][-1]
        probe=mounts[1][0];probe.write_text('/* forged check */');record['verifierSha256']=pin.digest(probe.read_bytes())
        with self.assertRaises(RuntimeError):self.run_pin(args=args,mounts=mounts)
        record['overrides']=[]
        with self.assertRaises(RuntimeError):self.run_pin(args=args,mounts=mounts)
        self.assertEqual(self.calls,[])
    def test_outer_actual_bytes_are_rechecked_after_child_exit(self):
        args,mounts=self.outer()
        def tamper(*a,**k):(self.root/pin.FIXTURE).write_bytes(b'changed');return SimpleNamespace(returncode=0)
        with self.assertRaises(RuntimeError):self.run_pin(args=args,mounts=mounts,inherited=tamper)
    def test_real_node_preload_checks_startup_and_exit(self):
        self.run_pin();mounts=dict((target,host) for host,target in self.calls[-1][1]['mounts']);file=mounts[pin.TARGET]
        probe=self.folder/'host-probe.cjs';probe.write_text(mounts[pin.PROBE_TARGET].read_text().replace(json.dumps(pin.TARGET),json.dumps(str(file))))
        invoke=lambda code:subprocess.run([NODE,'--require',str(probe),'-e',code],capture_output=True,timeout=5)
        self.assertEqual(invoke('').returncode,0);file.chmod(0o600)
        self.assertNotEqual(invoke('require("node:fs").writeFileSync('+json.dumps(str(file))+',"changed")').returncode,0)
        self.assertNotEqual(invoke('').returncode,0)
    def test_actual_standalone_and_nested_harnesses_preserve_overlay_precedence(self):
        # Run real Python helper composition to its subprocess leaf. No Docker
        # operation or native pass is simulated; only exact mounts are asserted.
        for family in ('glossary','classification','reference','reference-quality'):
            gate=load('composition_'+family,ROOT/('scripts/runtime-test-'+family+'-upgrade.py'))
            with tempfile.TemporaryDirectory(dir=ROOT/'.local') as folder:
                h=object.__new__(gate.Harness);h.folder=Path(folder);h.phase='approval-native-tests';h.report={'cachedPackageAdmission':True,'sources':gate.sources()};h.repository_stage=None
                chain=[];module=gate
                while hasattr(module,'base'):
                    chain.append(module);module=module.base
                for prefix in ('classification','reference','reference_quality'):
                    selected=next((m for m in chain if (ROOT/('scripts/runtime-test-'+prefix.replace('_','-')+'-upgrade.py')).resolve()==Path(m.__file__).resolve()),None)
                    if selected is not None:
                        setattr(h,prefix+'_predecessor',{'sources':selected.sources()});setattr(h,prefix+'_current',None);setattr(h,prefix+'_serial',0)
                quality=next((m for m in chain if hasattr(m,'repository_phase')),None)
                stage=None
                if quality is not None:
                    owned=h.folder/'sql018.ts';owned.write_bytes((ROOT/quality.PREDECESSOR_FIXTURE).read_bytes());stage=quality.repository_phase(h,'predecessor',owned,quality.PREDECESSOR_SHA256,True);h.repository_stage=stage
                calls=[]
                def leaf(self,args,*,mounts=(),**kwargs):calls.append((args,list(mounts)));return subprocess.CompletedProcess(args,0,'{}','')
                with patch.object(gate.Harness.__mro__[-2],'helper',leaf):h.helper(ARGS)
                self.assertEqual(len(calls),1);mounts=calls[0][1]
                service=[Path(host) for host,target in mounts if target==pin.TARGET];self.assertEqual(len(service),1);self.assertEqual(pin.digest(service[0].read_bytes()),pin.DIGEST)
                repository=[Path(host) for host,target in mounts if target=='/app/apps/api/src/repository.ts'];self.assertEqual(len(repository),1);self.assertEqual(pin.digest(repository[0].read_bytes()),pin._repository.DIGEST)
                self.assertIs(h.repository_stage,stage)
                if family=='glossary':self.assertTrue(h.report['predecessorApprovalStages'][-1]['sourceHashesMatched'])
                else:self.assertNotIn('predecessorApprovalStages',h.report);self.assertTrue(h.report['classificationSourceChecks'][-1]['sourceHashesMatched'])
    def test_fixed_fixture_identity_and_all_four_standalone_inventories(self):
        self.assertEqual(pin.digest(CONTENT),pin.DIGEST)
        self.assertEqual(hashlib.sha1(b'blob '+str(len(CONTENT)).encode()+b'\0'+CONTENT,usedforsecurity=False).hexdigest(),pin.BLOB)
        for family in ('approvals','glossary','relation-scope','glossary-population'):
            gate=load('inventory_'+family,ROOT/('scripts/runtime-test-'+family+'-upgrade.py'))
            paths={row['path'] for row in gate.sources()}
            self.assertIn('scripts/qualification_approval_service.py',paths);self.assertIn(pin.FIXTURE,paths)

if __name__=='__main__': unittest.main()
