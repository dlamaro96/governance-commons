#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host-only SQL019 source composition controls; no Docker/database execution."""
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('quality019_gate', ROOT / 'scripts/runtime-test-quality-upgrade.py')
gate = importlib.util.module_from_spec(spec); spec.loader.exec_module(gate)
pin = gate.sql019
LEAF = gate.Harness.__mro__[-2]
NODE = shutil.which('node')
if NODE is None:
    raise RuntimeError('Node is required for SQL019 binding controls')
ARGS = ['node', '--import', 'tsx', '--test', '--test-reporter=tap', '--test-concurrency=1', *gate.TESTS]


class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name, (fixture, digest, blob) in pin.BINDINGS.items():
            for relative, data in ((name, b'export const current = true;\n'), (fixture, (ROOT / fixture).read_bytes())):
                target = self.root / relative; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
        self.inventory = [{'path': name, 'sha256': pin.sha((self.root / name).read_bytes())}
                          for name in sorted((*pin.BINDINGS, *(row[0] for row in pin.BINDINGS.values())))]
        self.h = object.__new__(gate.Harness)
        self.h.folder = self.root / '.local/evidence/owned'; self.h.folder.mkdir(parents=True)
        self.h.phase = pin.PHASE; self.h.report = {'cachedPackageAdmission': True}
        self.stage = gate.repository_phase(self.h, 'current', self.root / pin.REPOSITORY,
                                          pin.sha((self.root / pin.REPOSITORY).read_bytes()), False)
        self.h.repository_stage = self.stage
        self.calls = []
        def leaf(h, args, *, mounts=(), **kwargs):
            self.calls.append((list(args), list(mounts), kwargs))
            return subprocess.CompletedProcess(args, 0, '', '')
        for mocked in (patch.object(gate, 'ROOT', self.root), patch.object(gate, 'sources', lambda: self.inventory),
                       patch.object(LEAF, 'helper', leaf)):
            mocked.start(); self.addCleanup(mocked.stop)

    def execute(self, **kwargs):
        return self.h.helper(ARGS, **kwargs)

    def mounts(self):
        return {target: Path(host) for host, target in self.calls[-1][1]}

    def test_standalone_binds_all_four_exact_modules_once_and_restores_stage(self):
        self.execute()
        for path, (_, digest, _) in pin.BINDINGS.items():
            mounts = [(file, target) for file, target in self.calls[-1][1] if target == '/app/' + path]
            self.assertEqual(len(mounts), 1); self.assertEqual(pin.sha(Path(mounts[0][0]).read_bytes()), digest)
        self.assertIs(self.h.repository_stage, self.stage)
        check = self.h.report['quality019ModuleChecks'][-1]
        self.assertTrue(check['sourceHashesMatched']); self.assertTrue(check['overrideReleased'])
        self.assertEqual(check['effectiveModuleSources'], pin.expected_sources())
        self.assertEqual(check['result'], 'PASS')

    def test_existing_exact_outer_quality_mounts_are_not_duplicated(self):
        mounts = [(self.root / row[0], '/app/' + path) for path, row in pin.BINDINGS.items() if path != pin.REPOSITORY]
        row = pin.BINDINGS[pin.REPOSITORY]
        outer = gate.repository_phase(self.h, 'classification020-1', self.root / row[0], row[1], True)
        self.h.repository_stage = outer
        self.execute(mounts=mounts)
        self.assertIs(self.h.repository_stage, outer)
        for path in pin.BINDINGS:
            self.assertEqual(sum(target == '/app/' + path for _, target in self.calls[-1][1]), 1)
        self.assertTrue(all(row['delegated'] for row in self.h.report['quality019ModuleChecks'][-1]['bindings']))

    def test_wrong_outer_bytes_duplicate_or_parent_mount_refuse_before_leaf(self):
        path = 'packages/domain/src/quality.ts'; good = (self.root / pin.BINDINGS[path][0], '/app/' + path)
        for mounts in ([(self.root / path, good[1])], [good, good], [(good[0], '/app/packages/domain')], [(good[0], pin.PROBE_TARGET)]):
            with self.subTest(mounts=mounts), self.assertRaises(RuntimeError): self.execute(mounts=mounts)
        self.assertEqual(self.calls, [])

    def test_unrecognized_outer_repository_stage_and_wrong_digest_refuse(self):
        for stage in ({**self.stage, 'name': 'unknown'}, {**self.stage, 'name': 'classification020-1', 'override': True}):
            self.h.repository_stage = stage
            with self.assertRaises(RuntimeError): self.execute()
        self.assertEqual(self.calls, [])

    def test_missing_binding_inventory_and_fixture_tamper_refuse(self):
        original = list(self.inventory)
        self.inventory.pop()
        with self.assertRaises(RuntimeError): self.execute()
        self.inventory[:] = original
        (self.root / pin.BINDINGS['packages/domain/src/quality.ts'][0]).write_bytes(b'changed')
        with self.assertRaises(RuntimeError): self.execute()
        self.assertEqual(self.calls, [])

    def test_symlink_fixture_and_module_mount_refuse(self):
        path = 'packages/domain/src/quality.ts'; fixture = self.root / pin.BINDINGS[path][0]
        link = self.root / 'linked.ts'; link.symlink_to(fixture)
        with self.assertRaises(RuntimeError): self.execute(mounts=[(link, '/app/' + path)])
        data = fixture.read_bytes(); fixture.unlink(); real = self.root / 'real.ts'; real.write_bytes(data); fixture.symlink_to(real)
        with self.assertRaises(RuntimeError): self.execute()
        self.assertEqual(self.calls, [])

    def test_nonzero_leaf_and_throw_restore_phase_without_false_pass(self):
        with patch.object(LEAF, 'helper', return_value=SimpleNamespace(returncode=7)):
            self.assertEqual(self.execute().returncode, 7)
        self.assertEqual(self.h.report['quality019ModuleChecks'][-1]['result'], 'NONZERO')
        with patch.object(LEAF, 'helper', side_effect=ValueError('synthetic')), self.assertRaises(ValueError): self.execute()
        self.assertEqual(self.h.report['quality019ModuleChecks'][-1]['result'], 'FAIL')
        self.assertIs(self.h.repository_stage, self.stage)

    def test_return_time_current_source_and_delegated_source_tamper_fail(self):
        for delegated in (False, True):
            path = 'packages/domain/src/quality.ts'
            file = self.root / (pin.BINDINGS[path][0] if delegated else path)
            old = file.read_bytes()
            def tamper(h, args, **kwargs):
                file.write_bytes(b'changed'); return SimpleNamespace(returncode=0)
            mounts = [(file, '/app/' + path)] if delegated else []
            with patch.object(LEAF, 'helper', tamper), self.assertRaises(RuntimeError): self.execute(mounts=mounts)
            self.assertIs(self.h.repository_stage, self.stage)
            self.assertFalse(self.h.report['quality019ModuleChecks'][-1]['sourceHashesMatched'])
            file.write_bytes(old)

    def test_earlier_repository_phase_is_unchanged(self):
        self.h.phase = 'population-native-tests'
        # Invoke the new selector directly: it must not interpret or replace an
        # earlier phase's independently verified SQL018 repository declaration.
        marker = object(); calls = []
        result = pin.run(self.h, lambda args, **kw: calls.append((args, kw)) or marker, ARGS,
                         root=self.root, inventory=[], repository_phase=gate.repository_phase)
        self.assertIs(result, marker); self.assertEqual(calls, [(ARGS, {'mounts': ()})])
        self.assertNotIn('quality019ModuleChecks', self.h.report)

    def test_actual_node_verifier_rejects_startup_and_exit_tampering(self):
        self.execute()
        directory = self.root / 'mounted'
        for path, (fixture, _, _) in pin.BINDINGS.items():
            file = directory / path; file.parent.mkdir(parents=True, exist_ok=True); file.write_bytes((self.root / fixture).read_bytes())
        code = pin.verifier().replace("'/app/'+row.path", json.dumps(str(directory) + '/') + '+row.path')
        probe = self.root / 'actual.cjs'; probe.write_text(code)
        run = lambda js: subprocess.run([NODE, '--require', str(probe), '-e', js], capture_output=True, timeout=5)
        self.assertEqual(run('0').returncode, 0)
        file = directory / 'packages/domain/src/quality.ts'
        self.assertNotEqual(run("require('node:fs').writeFileSync(" + json.dumps(str(file)) + ",'changed')").returncode, 0)
        self.assertNotEqual(run('0').returncode, 0)

    def test_readback_requires_exact_four_hashes_and_safe_exit(self):
        valid = pin.expected_sources()
        for rows, code in ((valid, 0), (valid[:-1], 0), ([*valid, valid[0]], 0), ([{**valid[0], 'sha256': '0' * 64}, *valid[1:]], 0), (valid, 1)):
            h = SimpleNamespace(phase=pin.PHASE, helper=lambda *a, **k: SimpleNamespace(returncode=code, stdout=json.dumps(rows)))
            if rows == valid and code == 0: self.assertEqual(pin.readback(h), valid)
            else:
                with self.assertRaises(RuntimeError): pin.readback(h)

    def test_original_fifteen_tests_and_fixture_identities_are_retained(self):
        self.assertEqual(sum(len(re.findall(r'^test\(', (ROOT / path).read_text(), re.MULTILINE)) for path in gate.TESTS), 15)
        for path in pin.BINDINGS: pin.fixture(ROOT, path)
        source = (ROOT / 'scripts/runtime-test-quality-upgrade.py').read_text()
        self.assertIn("require(expected==15", source)
        self.assertIn("stage['mountedModulesBefore']=sql019.readback(h)", source)
        self.assertIn("stage['mountedModulesAfter']=sql019.readback(h)", source)
        self.assertIn('base.tap_summary(tested.stdout,expected)', source)


class FullChainControls(unittest.TestCase):
    def test_real_structure_wrappers_delegate_exact_sql019_modules_once(self):
        spec = importlib.util.spec_from_file_location('quality019_structure', ROOT / 'scripts/runtime-test-reference-structure-upgrade.py')
        outer = importlib.util.module_from_spec(spec); spec.loader.exec_module(outer)
        with tempfile.TemporaryDirectory() as folder:
            h = object.__new__(outer.Harness); h.folder = Path(folder); h.report = {'cachedPackageAdmission': True}
            for name, module in (('structure', outer), ('reference_quality', outer.base), ('reference', outer.base.base), ('classification', outer.base.base.base)):
                setattr(h, name + '_predecessor', {'sources': module.sources()}); setattr(h, name + '_current', None); setattr(h, name + '_serial', 0)
            quality = outer.base.base.base.base.base
            h.phase = pin.PHASE
            stage = quality.repository_phase(h, 'current', ROOT / pin.REPOSITORY, pin.sha((ROOT / pin.REPOSITORY).read_bytes()), False)
            h.repository_stage = stage
            calls = []
            def leaf(h, args, *, mounts=(), **kwargs):
                calls.append((args, mounts)); return SimpleNamespace(returncode=0)
            with patch.object(outer.Harness.__mro__[-2], 'helper', leaf): h.helper(ARGS)
            self.assertEqual(len(calls), 1); self.assertIs(h.repository_stage, stage)
            for path, (_, digest, _) in pin.BINDINGS.items():
                selected = [Path(file) for file, target in calls[0][1] if target == '/app/' + path]
                self.assertEqual(len(selected), 1); self.assertEqual(pin.sha(selected[0].read_bytes()), digest)
            self.assertTrue(all(row['delegated'] for row in h.report['quality019ModuleChecks'][-1]['bindings']))
            self.assertEqual(h.report['classificationSourceChecks'][-1]['result'], 'PASS')


if __name__ == '__main__':
    unittest.main()
