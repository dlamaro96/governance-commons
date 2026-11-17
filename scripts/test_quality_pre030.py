#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise exact historical source selection; no runtime or database."""
import hashlib
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('quality_pre030_control',ROOT/'scripts/qualification_quality_pre030.py')
binding=importlib.util.module_from_spec(spec);spec.loader.exec_module(binding)
sha=lambda value:hashlib.sha256(value).hexdigest()

class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='gc-pre030-controls-');self.root=Path(self.tmp.name).resolve()
        for relative in binding.INPUTS:
            path=self.root/relative;path.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/relative,path)
        for relative in binding.BINDINGS:
            path=self.root/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('export const current = true;\n')
        self.frozen=[{'path':str(p.relative_to(self.root)),'sha256':sha(p.read_bytes())} for p in sorted(self.root.rglob('*')) if p.is_file()]
    def tearDown(self):self.tmp.cleanup()
    def selected(self,gate='freshness-scheduling',phase='post029-freshness-monitoring-tests',rows=None):
        return binding.select(self.root,self.frozen if rows is None else rows,gate,phase)
    def test_every_declared_phase_has_exact_service_and_repository_without_duplicate_targets(self):
        for gate,phases in binding.PHASES.items():
            for phase in phases:
                with self.subTest(gate=gate,phase=phase):
                    result=self.selected(gate,phase);self.assertEqual(len(result['overrides']),2)
                    self.assertEqual({x['path'] for x in result['overrides']},set(binding.BINDINGS))
                    old=gate in binding.repository.PHASES and phase in binding.repository.PHASES[gate]
                    self.assertEqual(result['override']['sha256'],binding.repository.DIGEST if old else binding.BINDINGS[binding.REPOSITORY][1])
                    bypath={r['path']:r['sha256'] for r in result['sources']}
                    self.assertEqual(bypath[binding.SERVICE],binding.BINDINGS[binding.SERVICE][1])
                    for row in result['sources']:self.assertEqual(sha(binding.mounted_path(self.root,row,result).read_bytes()),row['sha256'])
                    untouched=lambda rows:[r for r in rows if r['path'] not in binding.BINDINGS]
                    self.assertEqual(untouched(result['sources']),untouched(self.frozen))
    def test_non_native_migration_prefix_has_no_module_override(self):
        for gate in binding.PHASES:
            result=self.selected(gate,'schema-13');self.assertEqual(result,{'sources':self.frozen,'override':None,'overrides':[]})
            self.assertEqual([binding.mounted_path(self.root,r,result) for r in self.frozen],[self.root/r['path'] for r in self.frozen])
    def test_no_unknown_gate_or_post030_native_phase_can_use_historical_modules(self):
        for gate,phase in [('volume','pre029-completeness-tests'),('freshness','post030-freshness-tests'),('range','post026-invented-tests')]:
            with self.assertRaises(RuntimeError):self.selected(gate,phase)
    def test_missing_or_duplicate_target_and_fixture_inventories_refuse(self):
        for target in (*binding.BINDINGS,*(x[0] for x in binding.BINDINGS.values())):
            with self.subTest(target=target):
                rows=[r for r in self.frozen if r['path']!=target]
                with self.assertRaises(RuntimeError):self.selected(rows=rows)
                duplicate=next(r for r in self.frozen if r['path']==target)
                with self.assertRaises(RuntimeError):self.selected(rows=[*self.frozen,duplicate])
    def test_changed_checkout_and_retained_bytes_cannot_claim_recorded_hash(self):
        for target in (*binding.BINDINGS,*(x[0] for x in binding.BINDINGS.values())):
            path=self.root/target;original=path.read_bytes();path.write_bytes(original+b'changed')
            with self.assertRaises(RuntimeError):self.selected()
            path.write_bytes(original)
    def test_recording_forged_fixture_hash_does_not_override_immutable_contract(self):
        path=self.root/binding.BINDINGS[binding.SERVICE][0];path.write_text('export const substitute = true;')
        rows=[{**r,'sha256':sha(path.read_bytes())} if r['path']==str(path.relative_to(self.root)) else r for r in self.frozen]
        with self.assertRaises(RuntimeError):self.selected(rows=rows)
    def test_symlinked_fixture_and_parent_refuse_even_matching_bytes(self):
        target=binding.BINDINGS[binding.SERVICE][0];path=self.root/target;data=path.read_bytes();path.unlink();owned=self.root/'owned.txt';owned.write_bytes(data);path.symlink_to(owned)
        with self.assertRaises(RuntimeError):self.selected()
        path.unlink();path.write_bytes(data);directory=path.parent;retained=directory.with_name('retained');directory.rename(retained);directory.symlink_to(retained,target_is_directory=True)
        with self.assertRaises(RuntimeError):self.selected()
    def test_retained_git_blob_and_complete_commit_identity_are_independent(self):
        self.assertRegex(binding.COMMIT,r'^[a-f0-9]{40}$')
        for target,(fixture,digest,blob) in binding.BINDINGS.items():
            raw=(ROOT/fixture).read_bytes();self.assertEqual(sha(raw),digest)
            self.assertEqual(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),blob)
    def test_import_closure_includes_each_retained_module_at_original_relative_base(self):
        for target,(fixture,_,_) in binding.BINDINGS.items():
            text=binding.historical_imports(self.root,target)
            self.assertIn((self.root/fixture).read_text(),text)
        self.assertIn((self.root/binding.repository.FIXTURE).read_text(),binding.historical_imports(self.root,binding.REPOSITORY))
        self.assertEqual(binding.historical_imports(self.root,'apps/api/src/unrelated.ts'),'')
    def test_duplicate_selected_mount_destination_refuses(self):
        selected=self.selected();selected['overrides'].append(selected['overrides'][0])
        row=next(r for r in self.frozen if r['path']==selected['overrides'][0]['path'])
        with self.assertRaises(RuntimeError):binding.mounted_path(self.root,row,selected)

if __name__=='__main__':unittest.main()
