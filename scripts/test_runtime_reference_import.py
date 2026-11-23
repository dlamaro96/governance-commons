#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host controls for the native gate; never starts Docker or PostgreSQL."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('reference_import_gate', ROOT / 'scripts/runtime-test-reference-import.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def tap(passed=5, failed=0, skipped=0):
    return '\n'.join([f'# tests {passed + failed + skipped}', '# suites 0', f'# pass {passed}',
                      f'# fail {failed}', '# cancelled 0', f'# skipped {skipped}', '# todo 0', '# duration_ms 1.25', ''])


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='gc-import-controls-')
        self.root = Path(self.temp.name).resolve()
        self.root_patch = patch.object(gate, 'ROOT', self.root)
        self.root_patch.start()
        for name in ['scripts/runtime-test-reference-import.py', 'scripts/runtime-test-source-connectors-upgrade.py',
                     'scripts/runtime-test-authority-authn-foundation.py', 'scripts/authentication_roles.py',
                     'package.json', 'pnpm-lock.yaml', 'Dockerfile', 'tsconfig.json', 'deploy/compose/compose.yaml',
                     gate.TEST, 'tests/fixtures/reference-quality.ts', 'packages/db/src/migrate.ts',
                     'packages/domain/src/reference-import-service.ts', 'apps/api/src/reference-import.ts']:
            self.write(name, '{}\n' if name.endswith('.json') else '')
        self.write('deploy/compose/compose.yaml', 'services:\n  postgres:\n    image: postgres:17\n')
        for name in gate.NAMES:
            self.write('packages/db/migrations/' + name, '-- synthetic host-only migration fixture\n')

    def tearDown(self):
        self.root_patch.stop()
        self.temp.cleanup()

    def write(self, name, body):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
        return target

    def harness(self, phase='native-import-tests'):
        h = gate.Harness.__new__(gate.Harness)
        h.frozen = gate.sources()
        h.id, h.serial, h.phase = 'gc-owned-host-control', 1, phase
        h.app_image = 'sha256:' + 'a' * 64
        h.folder = self.root / '.local/evidence/control'
        h.folder.mkdir(parents=True, exist_ok=True)
        h.secret_path = h.folder / 'private-config.json'
        h.secret_path.write_text('{}')
        h.report = {'checks': [], 'cachedPackageAdmission': {}, 'privateConfigSha256': gate.sha(b'{}')}
        h.owned, h.calls = [], []
        def docker(*args, **kwargs):
            h.calls.append((args, kwargs))
            h.serial += 1
            return subprocess.CompletedProcess(args, 0, '{}', '')
        h.docker = docker
        return h

    def test_exact_current_migration_inventory(self):
        self.assertEqual(gate.migrations(), gate.NAMES)
        file = self.root / 'packages/db/migrations' / gate.NAMES[-1]
        file.unlink()
        with self.assertRaises(RuntimeError):
            gate.migrations()
        file.write_text('-- restored fixture')
        self.write('packages/db/migrations/025_undeclared.sql', '-- extra')
        with self.assertRaises(RuntimeError):
            gate.migrations()

    def test_current_schema_binds_all_34_migrations_including_classification_identity(self):
        self.assertEqual(len(gate.NAMES), 34)
        self.assertEqual(gate.NAMES[-3:], ['032_relation_candidate_validation.sql', '033_content_security_revisions.sql', '034_classification_label_identities.sql'])
        before = {row['path']: row['sha256'] for row in gate.sources()}
        for name in gate.NAMES:
            self.assertIn('packages/db/migrations/' + name, before)
        path = 'packages/db/migrations/034_classification_label_identities.sql'
        self.write(path, '-- changed current migration')
        after = {row['path']: row['sha256'] for row in gate.sources()}
        self.assertNotEqual(before[path], after[path])
        (self.root / path).unlink()
        with self.assertRaises(RuntimeError):
            gate.sources()

    def test_current_schema_refuses_renamed_or_unreviewed_successor(self):
        path = self.root / 'packages/db/migrations/034_classification_label_identities.sql'
        renamed = path.with_name('033_undeclared.sql')
        path.rename(renamed)
        with self.assertRaises(RuntimeError): gate.sources()
        renamed.rename(path)
        self.write('packages/db/migrations/034_undeclared.sql', '-- unreviewed successor')
        with self.assertRaises(RuntimeError): gate.sources()

    def test_transitive_imports_and_missing_source_refusal(self):
        self.write(gate.TEST, "import {x} from '../../packages/domain/src/leaf.js';\nawait import('./side.ts');\n")
        self.write('packages/domain/src/leaf.ts', "export {x} from './deep/index.ts';\n")
        self.write('packages/domain/src/deep/index.ts', 'export const x=1;\n')
        self.write('tests/api/side.ts', 'export {};\n')
        paths = {row['path'] for row in gate.sources()}
        self.assertTrue({'packages/domain/src/leaf.ts', 'packages/domain/src/deep/index.ts', 'tests/api/side.ts'} <= paths)
        (self.root / 'tests/api/side.ts').unlink()
        with self.assertRaises(RuntimeError):
            gate.sources()

    def test_symlinked_leaf_and_parent_refused(self):
        original = self.write('packages/domain/src/real.ts', 'export {};\n')
        link = self.root / 'packages/domain/src/link.ts'
        link.symlink_to(original)
        self.write(gate.TEST, "import '../../packages/domain/src/link.ts';\n")
        with self.assertRaises(RuntimeError):
            gate.sources()
        link.unlink()
        directory = self.root / 'alias'
        directory.symlink_to(original.parent, target_is_directory=True)
        self.write(gate.TEST, "import '../../alias/real.ts';\n")
        with self.assertRaises(RuntimeError):
            gate.sources()

    def test_real_node_startup_and_exit_source_and_config_checks(self):
        node = shutil.which('node')
        self.assertIsNotNone(node, 'Node must be installed; this control never silently skips')
        file = self.write('payload.txt', 'original')
        config = self.write('private-config.json', '{}')
        rows = [{'path': 'payload.txt', 'sha256': gate.sha(b'original')}]
        # Only the two fixed container roots are remapped to owned temporary
        # files; the exact generated verifier/check/exit logic executes in Node.
        source = gate.verifier(rows, gate.sha(b'{}'))
        self.assertEqual(source.count("'/app/'"), 1)
        self.assertEqual(source.count("'/run/authn-config.json'"), 1)
        source = source.replace("'/app/'", json.dumps(str(self.root) + '/')).replace("'/run/authn-config.json'", json.dumps(str(config)))
        preload = self.write('verifier.cjs', source)
        def run(body=''):
            return subprocess.run([node, '--require', str(preload), '-e', body], capture_output=True, text=True, timeout=10)
        self.assertEqual(run().returncode, 0)
        file.write_text('changed')
        self.assertNotEqual(run().returncode, 0)
        file.write_text('original')
        changed = run('require("node:fs").writeFileSync(' + json.dumps(str(file)) + ',"changed")')
        self.assertNotEqual(changed.returncode, 0)
        self.assertIn('REFERENCE_IMPORT_SOURCE_MISMATCH', changed.stderr)
        file.write_text('original')
        changed = run('require("node:fs").writeFileSync(' + json.dumps(str(config)) + ',"changed")')
        self.assertNotEqual(changed.returncode, 0)
        self.assertIn('REFERENCE_IMPORT_CONFIG_MISMATCH', changed.stderr)

    def test_native_helper_exact_readonly_mounts_and_owned_verifier(self):
        h = self.harness()
        h.helper(['node', '--test', gate.TEST], allow_failure=True)
        args, kwargs = h.calls[-1]
        mounts = [args[i + 1] for i, v in enumerate(args) if v == '--volume']
        for row in h.frozen:
            self.assertIn(f'{self.root / row["path"]}:/app/{row["path"]}:ro', mounts)
        self.assertEqual(len(mounts), len(h.frozen) + 2)
        self.assertTrue(all(v.endswith(':ro') for v in mounts))
        self.assertIn('container:' + h.id, args)
        for option in ('--read-only', '--cap-drop', '--security-opt', '--pids-limit', '--memory', '--pull'):
            self.assertIn(option, args)
        self.assertEqual(args[-5:], ('node', '--require', gate.PROBE, '--test', gate.TEST))
        self.assertTrue(h.report['sourceChecks'][0]['sourceHashesMatched'])
        self.assertEqual(h.report['sourceChecks'][0]['result'], 'PASS')
        self.assertEqual(h.owned, ['gc-owned-host-control-h1'])
        self.assertTrue(kwargs['allow_failure'])

    def test_schema_prefix_mount_and_overlap_refusal(self):
        h = self.harness('schema-12')
        folder = self.root / 'prefix'
        folder.mkdir()
        h.helper(['node', '-e', ''], mounts=[(folder, '/app/packages/db/migrations')])
        args = h.calls[-1][0]
        mounts = [args[i + 1] for i, v in enumerate(args) if v == '--volume']
        self.assertIn(f'{folder}:/app/packages/db/migrations:ro', mounts)
        self.assertFalse(any('/app/packages/db/migrations/001_' in v for v in mounts))
        self.assertNotIn('--require', args)
        with self.assertRaises(RuntimeError):
            h.helper(['node', '-e', ''], mounts=[(folder, '/app/packages/domain')])

    def test_helper_host_mutation_refused_after_leaf_returns(self):
        h = self.harness()
        def mutate(*args, **kwargs):
            self.write('Dockerfile', 'mutated')
            return subprocess.CompletedProcess(args, 0, '{}', '')
        h.docker = mutate
        with self.assertRaisesRegex(RuntimeError, 'source changed'):
            h.helper(['node', '-e', ''])

    def test_cached_dependency_admission_refuses_lock_mismatch(self):
        h = self.harness('schema-11')
        del h.report['cachedPackageAdmission']
        h.docker = lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, json.dumps({'package': {}, 'lock': '0' * 64}), '')
        with self.assertRaisesRegex(RuntimeError, 'dependency lock'):
            h.helper(['node', '-e', ''])
        self.assertEqual(h.owned, ['gc-owned-host-control-package-1'])

    def test_readback_checks_actual_sources_config_and_tools(self):
        h = self.harness()
        value = {'sources': h.frozen, 'configSha256': h.report['privateConfigSha256'],
                 'node': {'version': 'v24.22.3', 'sha256': 'a' * 64}, 'tsx': {'version': '4.20.0', 'entrySha256': 'b' * 64}}
        h.helper = lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps(value))
        self.assertEqual(gate.readback(h), value)
        for mutate in (lambda: value.update(sources=[]), lambda: value.update(configSha256='0' * 64),
                       lambda: value['node'].update(version='v20.0.0')):
            saved = json.loads(json.dumps(value))
            mutate()
            with self.assertRaises(RuntimeError):
                gate.readback(h)
            value = saved

    def test_tap_exact_totals_and_current_failures_retained(self):
        self.assertEqual(gate.totals(tap())['pass'], 5)
        self.assertIsNone(gate.totals(tap() + '# pass 5\n'))
        self.assertIsNone(gate.totals(tap().replace('# tests 5\n', '')))
        self.write(gate.TEST, 'test(\n' * 5)
        for output, code, good in ((tap(), 0, True), (tap(0, 5), 1, False), (tap(4, 0, 1), 0, False)):
            h = self.harness()
            h.command = lambda *args, **kwargs: SimpleNamespace(stdout='a' * 40)
            h.helper = lambda *args, **kwargs: subprocess.CompletedProcess([], code, output, '')
            with patch.object(gate, 'setup'), patch.object(gate, 'readback', return_value={'sourceProof': 'stable'}):
                if good:
                    gate.execute(h)
                    self.assertTrue(h.report['sourceHashesMatched'])
                else:
                    with self.assertRaises(RuntimeError):
                        gate.execute(h)
                    self.assertEqual(h.report['tests'], gate.totals(output))
                    self.assertEqual(h.report['testExitStatus'], code)

    def test_prepare_finally_finishes_roles_after_migration_failure(self):
        h = self.harness('admission')
        h.memory_admission = lambda: {}
        h.inventory = lambda: {'containers': []}
        h.private_values, h.created = [], False
        calls = []
        def docker(*args, **kwargs):
            out = json.dumps([{'Endpoints': {'docker': {'Host': 'unix:///owned-control'}}}]) if args[:2] == ('context', 'inspect') else 'sha256:' + 'a' * 64
            return subprocess.CompletedProcess(args, 0, out, '')
        h.docker = docker
        h.sql = lambda statement, **kwargs: calls.append(statement)
        def migrate(folder):
            calls.append(folder.name)
            if folder.name == 'migrations-12':
                raise RuntimeError('Synthetic migration failure')
        h.migrate = migrate
        roles = SimpleNamespace(prepare_sql=lambda *a: 'PREPARE', finish_sql=lambda *a: 'FINISH')
        with patch.object(gate.base.base, 'module', return_value=roles), patch.dict(os.environ, {'DOCKER_HOST': ''}):
            with self.assertRaisesRegex(RuntimeError, 'Synthetic migration'):
                gate.setup(h)
        self.assertEqual(calls[-3:], ['PREPARE', 'migrations-12', 'FINISH'])

    def test_main_cleanup_on_failure_and_inventory_change(self):
        for fail_execute, inventory_changed in ((True, False), (False, True), (False, False)):
            h = self.harness('control')
            h.resources_before = {'containers': ['preexisting']}
            (h.folder / 'resources-before.json').write_text(json.dumps(h.resources_before))
            h.cleanup_deadline = 1
            h.inventory = lambda: {'containers': []} if inventory_changed else h.resources_before
            def cleanup():
                h.secret_path.unlink()
                h.report['cleanup'] = {'ownedRemoved': True}
            h.cleanup, h.save = cleanup, lambda **kwargs: None
            with patch.object(gate, 'Harness', return_value=h), patch.object(gate, 'execute', side_effect=RuntimeError('private') if fail_execute else None), patch.object(gate, 'REPORT', self.root / '.local/evidence/reference-import.json'), patch.object(sys, 'argv', ['gate', '--run-local']), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gate.main(), int(fail_execute or inventory_changed))
            self.assertFalse(h.secret_path.exists())
            self.assertTrue(h.report['cleanup']['ownedRemoved'])
            if inventory_changed:
                self.assertIn('cleanupErrorType', h.report)
            else:
                self.assertTrue(h.report['cleanup']['resourceInventoryPreserved'])

    def test_main_removes_credentials_when_real_cleanup_docker_call_throws(self):
        for error in (TimeoutError('synthetic timeout'), RuntimeError('synthetic daemon failure')):
            with self.subTest(error=type(error).__name__):
                h = self.harness('control')
                h.resources_before = {'containers': ['preexisting']}
                h.inventory = lambda: self.fail('Inventory cannot be verified after failed cleanup')
                h.docker = lambda *args, **kwargs: (_ for _ in ()).throw(error)
                saved = []
                h.save = lambda **kwargs: saved.append((kwargs, h.secret_path.exists()))
                # Use the actual inherited cleanup: its first Docker inspect
                # raises before it can reach its own secret_path.unlink.
                with patch.object(gate, 'Harness', return_value=h), patch.object(gate, 'execute'), patch.object(gate, 'REPORT', self.root / '.local/evidence/reference-import.json'), patch.object(sys, 'argv', ['gate', '--run-local']), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(gate.main(), 1)
                self.assertFalse(h.secret_path.exists())
                self.assertEqual(h.report['result'], 'FAIL')
                self.assertEqual(h.report['cleanupErrorType'], type(error).__name__)
                self.assertEqual(h.report['cleanup'], {'generatedCredentialsRemoved': True})
                self.assertEqual(saved, [({'final': True}, False)])

    def test_main_preserves_failure_when_credential_removal_is_denied(self):
        h = self.harness('control')
        h.resources_before = None
        h.docker = lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError('synthetic timeout'))
        h.save = lambda **kwargs: None
        with patch.object(gate, 'Harness', return_value=h), patch.object(gate, 'execute'), patch.object(gate, 'REPORT', self.root / '.local/evidence/reference-import.json'), patch.object(sys, 'argv', ['gate', '--run-local']), patch.object(type(h.secret_path), 'unlink', side_effect=PermissionError('synthetic permission refusal')), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(gate.main(), 1)
        self.assertTrue(h.secret_path.exists())
        self.assertEqual(h.report['result'], 'FAIL')
        self.assertEqual(h.report['cleanupErrorType'], 'TimeoutError')
        self.assertEqual(h.report['credentialCleanupErrorType'], 'PermissionError')
        self.assertEqual(h.report['cleanup'], {'generatedCredentialsRemoved': False})


if __name__ == '__main__':
    unittest.main()
