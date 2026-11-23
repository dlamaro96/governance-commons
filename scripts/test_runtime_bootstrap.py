#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the actual bootstrap only in fresh temporary workspaces, never shared runtime."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
TENANT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
CUSTOM = {'connectorId':'unity-catalog','tenantIds':[TENANT],
          'workspaceUrl':'https://adb-123.1.azuredatabricks.net','catalog':'harbor','schema':'commerce',
          'clientId':'synthetic-client','clientSecret':'synthetic-preserved-custom-secret',
          'principalId':'synthetic-reader','operatorNote':{'retain':['exact','values']}}

spec = importlib.util.spec_from_file_location('runtime_bootstrap_controls', ROOT/'scripts/runtime.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class BootstrapPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='gc-bootstrap-preservation-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'scripts').mkdir()
        (self.root/'deploy/compose').mkdir(parents=True)
        shutil.copyfile(ROOT/'scripts/runtime-bootstrap.py',self.root/'scripts/runtime-bootstrap.py')
        for filename in ('source-fixture.sql','reference-quality-fixture.sql','uniqueness-quality-fixture.sql','range-quality-fixture.sql'):
            shutil.copyfile(ROOT/'deploy/compose'/filename,self.root/'deploy/compose'/filename)
        self.local = self.root/'.local'
        self.provider = self.local/'source-credentials/secrets.json'
        self.legacy = self.local/'source-secrets.json'

    def run_bootstrap(self, success=True):
        result = subprocess.run([sys.executable,'-B','scripts/runtime-bootstrap.py'],cwd=self.root,
                                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        output = result.stdout+result.stderr
        self.assertNotIn(CUSTOM['clientSecret'].encode(),output)
        self.assertNotIn(b'synthetic-legacy-password',output)
        if success: self.assertEqual(result.returncode,0,output.decode())
        else:
            self.assertNotEqual(result.returncode,0)
            self.assertIn(b'Source credential provider is invalid or changed',output)
        return result

    def write_legacy(self, value, raw=False, mode=0o600):
        self.local.mkdir(mode=0o700,exist_ok=True)
        self.legacy.write_bytes(value if raw else json.dumps(value).encode())
        self.legacy.chmod(mode)

    def parsed(self):
        return json.loads(self.provider.read_bytes())

    def test_fresh_workspace_creates_private_directory_provider_only(self):
        self.run_bootstrap()
        self.assertFalse(self.legacy.exists())
        self.assertEqual(stat.S_IMODE(self.provider.parent.stat().st_mode),0o700)
        self.assertEqual(stat.S_IMODE(self.provider.stat().st_mode),0o600)
        state=json.loads((self.local/'bootstrap.json').read_text())
        self.assertEqual(self.parsed()['demo-postgres']['password'],state['SOURCE_READER_PASSWORD'])
        self.assertEqual(list(self.provider.parent.iterdir()),[self.provider])

    def test_fresh_bootstrap_includes_each_closed_quality_profile_once(self):
        self.run_bootstrap()
        generated=(self.local/'source-init.sql').read_text()
        for marker in ('QUALITY_FIXTURE_V1','REFERENCE_QUALITY_FIXTURE_V1','UNIQUENESS_QUALITY_FIXTURE_V1','RANGE_QUALITY_FIXTURE_V1'):
            self.assertEqual(generated.count('-- BEGIN '+marker),1)
            self.assertEqual(generated.count('-- END '+marker),1)
        expected=(ROOT/'deploy/compose/range-quality-fixture.sql').read_text()
        self.assertIn(expected,generated)

    def test_repeat_preserves_custom_uc_and_provider_bytes_inode_and_bootstrap_credentials(self):
        self.run_bootstrap()
        entries=self.parsed();entries['operator-uc']=CUSTOM
        raw=(json.dumps(entries,separators=(',',':'))+'\n').encode()
        self.provider.write_bytes(raw)
        inode=self.provider.stat().st_ino
        state=(self.local/'bootstrap.json').read_bytes()
        self.run_bootstrap()
        self.assertEqual(self.provider.read_bytes(),raw)
        self.assertEqual(self.provider.stat().st_ino,inode)
        self.assertEqual((self.local/'bootstrap.json').read_bytes(),state)
        self.assertEqual(self.parsed()['operator-uc'],CUSTOM)

    def test_legacy_regular_provider_import_preserves_original_and_custom_entries(self):
        entries={'operator-uc':CUSTOM,'demo-postgres':{'tenantIds':[TENANT],'password':'synthetic-legacy-password'}}
        self.write_legacy(entries,mode=0o400)
        raw=self.legacy.read_bytes();before=self.legacy.stat()
        self.run_bootstrap()
        self.assertEqual(self.legacy.read_bytes(),raw)
        self.assertEqual((self.legacy.stat().st_ino,self.legacy.stat().st_mtime_ns,self.legacy.stat().st_mode),
                         (before.st_ino,before.st_mtime_ns,before.st_mode))
        self.assertEqual(self.parsed()['operator-uc'],CUSTOM)
        self.assertEqual(stat.S_IMODE(self.provider.stat().st_mode),0o600)
        self.assertNotEqual(self.parsed()['demo-postgres']['password'],'synthetic-legacy-password')

    def test_legacy_symlink_import_never_rewrites_or_chmods_its_target(self):
        self.local.mkdir(mode=0o700)
        external=self.root/'external-provider.json'
        raw=json.dumps({'operator-uc':CUSTOM},indent=1).encode()
        external.write_bytes(raw);external.chmod(0o400)
        self.legacy.symlink_to(external)
        before=external.stat()
        self.run_bootstrap();self.run_bootstrap()
        self.assertTrue(self.legacy.is_symlink())
        self.assertEqual(os.readlink(self.legacy),str(external))
        self.assertEqual(external.read_bytes(),raw)
        self.assertEqual((external.stat().st_ino,external.stat().st_mtime_ns,external.stat().st_mode),
                         (before.st_ino,before.st_mtime_ns,before.st_mode))
        self.assertEqual(self.parsed()['operator-uc'],CUSTOM)

    def test_canonical_provider_wins_and_atomic_rotation_stays_visible(self):
        self.run_bootstrap()
        self.write_legacy({'stale-entry':CUSTOM})
        entries=self.parsed();entries['operator-uc']=dict(CUSTOM,clientSecret='synthetic-rotated-secret')
        replacement=self.provider.parent/'replacement.json'
        raw=json.dumps(entries).encode();replacement.write_bytes(raw);replacement.chmod(0o600)
        old_inode=self.provider.stat().st_ino
        os.replace(replacement,self.provider)
        self.assertNotEqual(self.provider.stat().st_ino,old_inode)
        self.run_bootstrap()
        self.assertEqual(self.provider.read_bytes(),raw)
        self.assertNotIn('stale-entry',self.parsed())
        self.assertEqual(self.parsed()['operator-uc']['clientSecret'],'synthetic-rotated-secret')

    def test_managed_demo_repair_changes_only_reserved_entry_and_publishes_atomically(self):
        self.run_bootstrap()
        entries=self.parsed();entries['operator-uc']=CUSTOM
        entries['future-adapter']={'tenantIds':[TENANT],'connectorId':'future-adapter','opaque':['retained',1]}
        entries['demo-postgres']['password']='synthetic-legacy-password'
        self.provider.write_text(json.dumps(entries));before=self.provider.stat().st_ino
        self.run_bootstrap()
        after=self.parsed()
        self.assertNotEqual(self.provider.stat().st_ino,before)
        self.assertEqual(after['operator-uc'],entries['operator-uc'])
        self.assertEqual(after['future-adapter'],entries['future-adapter'])
        self.assertEqual(after['demo-postgres']['password'],json.loads((self.local/'bootstrap.json').read_text())['SOURCE_READER_PASSWORD'])
        self.assertEqual(list(self.provider.parent.iterdir()),[self.provider])

    def test_invalid_canonical_provider_refuses_before_other_bootstrap_outputs_are_rewritten(self):
        self.run_bootstrap();self.write_legacy({'operator-uc':CUSTOM})
        originals={name:(self.local/name).read_bytes() for name in ('bootstrap.json','runtime.env','source-init.sql')}
        documents=[b'{"duplicate":{},"duplicate":{}}',b'{',b'[]',b'{"x":"\\ud800"}',b'{"x":NaN}',
                   b'['*17+b'0'+b']'*17,b'{"x":{"tenantIds":["one","one"]}}',
                   json.dumps({'x':{'tenantIds':[TENANT],'payload':[0]*32768}}).encode(),b' '*((1024*1024)+1)]
        for raw in documents:
            with self.subTest(size=len(raw)):
                self.provider.write_bytes(raw)
                self.run_bootstrap(success=False)
                self.assertEqual(self.provider.read_bytes(),raw)
                for name,data in originals.items(): self.assertEqual((self.local/name).read_bytes(),data)

    def test_invalid_legacy_provider_is_never_overwritten_or_migrated(self):
        self.write_legacy(b'{"secret":"synthetic-preserved-custom-secret","secret":{}}',raw=True)
        raw=self.legacy.read_bytes()
        self.run_bootstrap(success=False)
        self.assertEqual(self.legacy.read_bytes(),raw)
        self.assertFalse(self.provider.parent.exists())
        self.assertFalse((self.local/'bootstrap.json').exists())

    def test_new_directory_missing_file_or_symlink_cannot_resurrect_legacy_credentials(self):
        self.run_bootstrap();self.write_legacy({'operator-uc':CUSTOM})
        self.provider.unlink()
        self.run_bootstrap(success=False)
        self.assertFalse(self.provider.exists())
        self.provider.symlink_to(self.legacy)
        raw=self.legacy.read_bytes()
        self.run_bootstrap(success=False)
        self.assertTrue(self.provider.is_symlink())
        self.assertEqual(self.legacy.read_bytes(),raw)

    def test_insecure_canonical_file_or_directory_is_refused_not_repaired(self):
        self.run_bootstrap();raw=self.provider.read_bytes()
        for mode in (0o644,0o640,0o400,0o700):
            with self.subTest(mode=mode):
                self.provider.chmod(mode);self.run_bootstrap(success=False)
                self.assertEqual(self.provider.read_bytes(),raw)
                self.assertEqual(stat.S_IMODE(self.provider.stat().st_mode),mode)
        self.provider.chmod(0o600);self.provider.parent.chmod(0o755)
        self.run_bootstrap(success=False)
        self.assertEqual(stat.S_IMODE(self.provider.parent.stat().st_mode),0o755)

    def test_worker_mount_is_readonly_directory_and_path_addresses_current_file(self):
        compose=(ROOT/'deploy/compose/compose.yaml').read_text()
        worker=compose[compose.index('  python-worker:\n'):]
        self.assertIn('SOURCE_SECRETS_FILE: /run/source-credentials/secrets.json',worker)
        self.assertIn('POSTGRES_TARGETS_FILE: /run/source-credentials/postgres-targets.json',worker)
        self.assertIn('../../.local/source-credentials:/run/source-credentials:ro',worker)
        self.assertNotIn('../../.local/source-secrets.json:',worker)

    def test_bootstrap_never_creates_or_rewrites_operator_postgres_target_policy(self):
        self.run_bootstrap()
        policy=self.provider.parent/'postgres-targets.json'
        self.assertFalse(policy.exists())
        raw=b'{"formatVersion":1,"targets":{"operator-controlled":"preserve exact bytes"}}\n'
        policy.write_bytes(raw);policy.chmod(0o400)
        before=policy.stat()
        self.run_bootstrap()
        after=policy.stat()
        self.assertEqual(policy.read_bytes(),raw)
        self.assertEqual((after.st_ino,after.st_mtime_ns,after.st_mode),(before.st_ino,before.st_mtime_ns,before.st_mode))


class ExistingImageStartupTests(unittest.TestCase):
    """Exercise the real startup and image validators with no external commands."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='gc-existing-image-startup-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        files = {name: b'synthetic' for name in runtime.INTEGRITY_CONTROLS}
        files.update({'package.json': b'{"name":"synthetic"}', 'pnpm-lock.yaml': b'lockfileVersion: 9',
                      'pnpm-workspace.yaml': b'packages: []', 'apps/api/src/main.ts': b'export const main = 1;',
                      'packages/domain/src/model.ts': b'export const model = 1;',
                      'python/pyproject.toml': b'[project]\nname="synthetic"', 'python/uv.lock': b'version = 1',
                      'python/governance_workers/main.py': b'VALUE = 1\n', 'python/tests/test_main.py': b'VALUE = 2\n'})
        for name, body in files.items():
            path = self.root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        self.images = {'governance-commons:dev': 'sha256:'+'1'*64,
                       'governance-commons-python:dev': 'sha256:'+'2'*64,
                       'synthetic-postgres:cached': 'sha256:'+'3'*64}
        (self.root/'deploy/compose/compose.yaml').write_text('services:\n'+''.join(
            f'  service{index}:\n    image: {name}\n' for index, name in enumerate(self.images)))
        self.root_patch = patch.object(runtime, 'ROOT', self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.local_patch = patch.object(runtime, 'LOCAL', self.root/'.local')
        self.local_patch.start()
        self.addCleanup(self.local_patch.stop)
        (self.root/'.local').mkdir(mode=0o700)
        self.snapshot = runtime.integrity_source_snapshot()
        self.recorded_images = {'api': self.images['governance-commons:dev'],
                                'python-worker': self.images['governance-commons-python:dev']}
        runtime.write_build_receipt(self.snapshot, self.recorded_images)

    def startup(self, *, no_build=True, fault=None, profile='core', free=None):
        events, commands, inspections = [], [], {}
        selected_images = dict(self.images)
        def guard(name):
            events.append(name)
            if fault == name:
                raise SystemExit('synthetic prerequisite refusal')
        def run(args, **kwargs):
            commands.append((args, kwargs))
            if args == runtime.COMPOSE+['config', '--quiet']:
                events.append('compose-config')
            elif args[:len(runtime.COMPOSE)+1] == runtime.COMPOSE+['build']:
                events.append('build-'+args[-1])
                if fault == 'build-'+args[-1]:
                    raise subprocess.CalledProcessError(1, args)
            elif args[:len(runtime.COMPOSE)+1] == runtime.COMPOSE+['up']:
                name = 'postgres' if args[-1] == 'postgres' else 'migration' if args[-1] == 'migrate' else 'services'
                events.append(name)
                if fault == name:
                    raise subprocess.CalledProcessError(1, args)
            elif args[1] == 'scripts/runtime-authentication-roles.py':
                events.append('roles-'+args[-1])
                if fault == 'roles-'+args[-1]:
                    raise subprocess.CalledProcessError(1, args)
            elif args[1:] == ['scripts/runtime-test-object-store.py', '--readiness']:
                events.append('object-store-readiness')
            else:
                raise AssertionError('Unexpected service command')
        def integrity(args, data=b'', timeout=30):
            if args == runtime.COMPOSE+['config', '--images']:
                events.append('cached-image-inventory')
                return ('\n'.join(self.images)+'\n').encode()
            if args[:3] == ['docker', 'image', 'inspect']:
                names = args[5:]
                if len(names) > 1:
                    events.append('cached-images-inspected')
                    if fault == 'missing-dependency-image':
                        runtime.integrity_require(False)
                else:
                    name = names[0]
                    inspections[name] = inspections.get(name, 0)+1
                    if fault == 'missing-api-image' and name == 'governance-commons:dev':
                        runtime.integrity_require(False)
                    if fault == 'retag-before-readback' and name == 'governance-commons:dev':
                        selected_images[name] = 'sha256:'+'4'*64
                    if fault == 'retag-after-readback' and name == 'governance-commons:dev' and inspections[name] >= 3:
                        return ('sha256:'+'4'*64+'\n').encode()
                return ('\n'.join(selected_images[name] for name in names)+'\n').encode()
            if args[:2] == ['docker', 'run']:
                service = 'api' if selected_images['governance-commons:dev'] in args else 'python-worker'
                events.append('readback-'+service)
                self.assertIn('--pull', args)
                self.assertEqual(args[args.index('--pull')+1], 'never')
                self.assertEqual(args[args.index('--network')+1], 'none')
                names = self.snapshot['profiles'][service]
                sources = [{'path': name.removeprefix('python/') if service == 'python-worker' else name,
                            'sha256': self.snapshot['sources'][name]} for name in names]
                self.assertEqual(json.loads(data), [row['path'] for row in sources])
                if fault == 'stale-'+service:
                    sources[0]['sha256'] = '0'*64
                if fault == 'source-drift' and service == 'python-worker':
                    (self.root/'package.json').write_text('{"changed":true}')
                return json.dumps({'formatVersion': 1, 'profile': service, 'sources': sources,
                                   'checks': ['package-manifests', 'selected-runtime-imports'] if service == 'api'
                                   else ['python-parse', 'project-lock-parse', 'psycopg-import']}).encode()
            if args[:3] == ['docker', 'container', 'ls']:
                events.append('integrity-cleanup')
                return b''
            raise AssertionError('Unexpected integrity command')
        def verify(snapshot, images):
            events.append('snapshot-verification')
            original_verify(snapshot, images)
            events.append('snapshot-verified')
        def read_receipt(snapshot):
            events.append('receipt-read')
            return original_read(snapshot)
        def write_receipt(snapshot, images):
            events.append('receipt-publish')
            original_write(snapshot, images)
            events.append('receipt-published')
        def capture(args, timeout=15):
            if args == ['docker', 'info', '--format', '{{json .}}']:
                return json.dumps({'ServerVersion': 'synthetic', 'MemTotal': 8*1024**3, 'NCPU': 4, 'Architecture': 'arm64'})
            if args == ['docker', 'compose', 'version', '--short']:
                return 'synthetic'
            if args[:3] == ['docker', 'image', 'inspect']:
                return '\n'.join(self.images[name] for name in args[5:])
            raise AssertionError('Unexpected doctor command')
        original_verify = runtime.verify_build_snapshot
        original_read, original_write = runtime.read_build_receipt, runtime.write_build_receipt
        argv = ['dev', 'up', '--profile', profile]+(['--no-build'] if no_build else [])
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(sys, 'argv', argv))
            for name in ('require_bootstrap', 'require_local', 'authentication_bootstrap', 'require_build_disk'):
                stack.enter_context(patch.object(runtime, name, side_effect=lambda *_, name=name: guard(name)))
            if free is None:
                stack.enter_context(patch.object(runtime, 'doctor', side_effect=lambda: (events.append('doctor'), fault != 'doctor')[1]))
            else:
                stack.enter_context(patch.object(runtime.shutil, 'which', return_value='/synthetic/tool'))
                stack.enter_context(patch.object(runtime.shutil, 'disk_usage', return_value=SimpleNamespace(free=free)))
                stack.enter_context(patch.object(runtime.socket, 'socket'))
            stack.enter_context(patch.object(runtime, 'run', side_effect=run))
            stack.enter_context(patch.object(runtime, 'capture', side_effect=capture))
            stack.enter_context(patch.object(runtime, 'integrity_command', side_effect=integrity))
            stack.enter_context(patch.object(runtime, 'verify_build_snapshot', side_effect=verify))
            stack.enter_context(patch.object(runtime, 'read_build_receipt', side_effect=read_receipt))
            stack.enter_context(patch.object(runtime, 'write_build_receipt', side_effect=write_receipt))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            error = None
            try:
                runtime.main()
            except (SystemExit, subprocess.CalledProcessError) as caught:
                error = caught
        return events, commands, error

    def assert_no_canonical_mutation(self, events):
        self.assertFalse(set(events).intersection({'postgres', 'migration', 'services', 'roles-prepare', 'roles-finish', 'roles-executors'}))

    def test_existing_images_require_both_readbacks_and_snapshot_before_migration_without_build_or_pull(self):
        events, commands, error = self.startup()
        self.assertIsNone(error)
        self.assertEqual(events, ['require_bootstrap', 'require_local', 'authentication_bootstrap', 'doctor', 'compose-config',
                                 'receipt-read', 'cached-image-inventory', 'cached-images-inspected', 'readback-api', 'integrity-cleanup',
                                 'readback-python-worker', 'integrity-cleanup', 'snapshot-verification', 'snapshot-verified',
                                 'postgres', 'roles-prepare', 'migration', 'roles-finish', 'roles-executors', 'services', 'object-store-readiness'])
        for args, _ in commands:
            self.assertNotIn('build', args)
            self.assertNotIn('pull', args)
            if args[:len(runtime.COMPOSE)+1] == runtime.COMPOSE+['up']:
                self.assertIn('--no-build', args)
                self.assertEqual(args[args.index('--pull')+1], 'never')

    def test_default_startup_still_builds_serially_and_keeps_prior_flags(self):
        events, commands, error = self.startup(no_build=False)
        self.assertIsNone(error)
        self.assertNotIn('cached-image-inventory', events)
        self.assertEqual([event for event in events if event.startswith('build-')], ['build-api', 'build-python-worker'])
        self.assertEqual(events.count('require_build_disk'), 2)
        for args, kwargs in commands:
            if 'build' in args:
                self.assertEqual(kwargs['timeout'], 1800)
                self.assertEqual(kwargs['env']['COMPOSE_PARALLEL_LIMIT'], '1')
            self.assertNotIn('--pull', args)
        self.assertLess(events.index('snapshot-verified'), events.index('postgres'))
        self.assertLess(events.index('snapshot-verified'), events.index('receipt-publish'))
        self.assertLess(events.index('receipt-published'), events.index('postgres'))
        self.assertEqual(events.count('snapshot-verified'), 2)

    def test_missing_images_stale_images_source_drift_and_retag_refuse_before_canonical_mutation(self):
        for fault in ('missing-dependency-image', 'missing-api-image', 'stale-api', 'stale-python-worker',
                      'retag-after-readback', 'retag-before-readback', 'source-drift'):
            with self.subTest(fault=fault):
                events, _, error = self.startup(fault=fault)
                self.assertIsInstance(error, SystemExit)
                self.assertIn('integrity check failed', str(error))
                self.assert_no_canonical_mutation(events)
                if fault in ('retag-after-readback', 'source-drift'):
                    self.assertIn('readback-api', events)
                    self.assertIn('readback-python-worker', events)
                    self.assertIn('snapshot-verification', events)
                    self.assertNotIn('snapshot-verified', events)

    def test_existing_images_do_not_bypass_bootstrap_local_authentication_or_doctor(self):
        for fault in ('require_bootstrap', 'require_local', 'authentication_bootstrap', 'doctor'):
            with self.subTest(fault=fault):
                events, commands, error = self.startup(fault=fault)
                self.assertIsInstance(error, SystemExit)
                self.assertEqual(commands, [])
                self.assert_no_canonical_mutation(events)

    def test_no_build_keeps_exact_four_gib_doctor_floor(self):
        for free in (4*1024**3-1, 4*1024**3):
            with self.subTest(free=free):
                events, _, error = self.startup(free=free)
                if free < 4*1024**3:
                    self.assertIsInstance(error, SystemExit)
                    self.assert_no_canonical_mutation(events)
                    self.assertNotIn('cached-image-inventory', events)
                else:
                    self.assertIsNone(error)
                    self.assertIn('object-store-readiness', events)

    def test_migration_or_prepare_failure_retains_role_cleanup_and_prevents_application_start(self):
        for fault in ('roles-prepare', 'migration'):
            with self.subTest(fault=fault):
                events, _, error = self.startup(fault=fault)
                self.assertIsInstance(error, subprocess.CalledProcessError)
                self.assertEqual(events[-1], 'roles-finish')
                self.assertNotIn('roles-executors', events)
                self.assertNotIn('services', events)
                self.assertNotIn('object-store-readiness', events)

    def test_no_build_other_profiles_are_refused_before_any_command(self):
        events, commands, error = self.startup(profile='full')
        self.assertIsInstance(error, SystemExit)
        self.assertIn('PROFILE NOT IMPLEMENTED', str(error))
        self.assertEqual((events, commands), ([], []))

    def test_no_build_is_rejected_on_every_other_command_before_side_effects(self):
        commands = ('help', 'doctor', 'bootstrap', 'seed', 'status', 'test', 'authn-install', 'benchmark',
                    'k8s-smoke', 'backup', 'restore', 'export-support-bundle', 'down')
        for command in commands:
            with self.subTest(command=command), contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(sys, 'argv', ['dev', command, '--no-build']))
                for name in ('run', 'capture', 'require_bootstrap', 'require_local', 'doctor'):
                    stack.enter_context(patch.object(runtime, name, side_effect=AssertionError('Unexpected side effect')))
                stderr = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                with self.assertRaises(SystemExit) as caught:
                    runtime.main()
                self.assertEqual(caught.exception.code, 2)
                self.assertIn('--no-build is supported only with up', stderr.getvalue())

    def test_recipe_only_changes_refuse_even_when_every_image_source_and_lock_hash_matches(self):
        for name in runtime.INTEGRITY_CONTROLS:
            with self.subTest(control=name):
                path = self.root/name
                previous = path.read_bytes()
                path.write_bytes(previous+b'\n# changed build input\n')
                try:
                    current = runtime.integrity_source_snapshot()
                    self.assertEqual(current['profiles'], self.snapshot['profiles'])
                    for names in current['profiles'].values():
                        for source in names:
                            self.assertEqual(current['sources'][source], self.snapshot['sources'][source])
                    events, _, error = self.startup()
                    self.assertIsInstance(error, SystemExit)
                    self.assert_no_canonical_mutation(events)
                    self.assertNotIn('readback-api', events)
                    self.assertNotIn('readback-python-worker', events)
                finally:
                    path.write_bytes(previous)

    def test_successful_default_build_replaces_receipt_then_no_build_reuses_it_without_rewriting(self):
        receipt = self.root/'.local'/runtime.BUILD_RECEIPT_NAME
        previous, inode = receipt.read_bytes(), receipt.stat().st_ino
        (self.root/'python/Dockerfile').write_text('changed synthetic Python recipe')
        events, _, error = self.startup(no_build=False)
        self.assertIsNone(error)
        self.assertNotEqual(receipt.read_bytes(), previous)
        self.assertNotEqual(receipt.stat().st_ino, inode)
        self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
        self.assertEqual(runtime.read_build_receipt(runtime.integrity_source_snapshot()), self.recorded_images)
        self.assertLess(events.index('readback-python-worker'), events.index('receipt-publish'))
        self.assertLess(events.index('snapshot-verified'), events.index('receipt-publish'))
        self.assertEqual(events[events.index('receipt-published')+1:events.index('postgres')], ['snapshot-verification', 'snapshot-verified'])
        previous, inode = receipt.read_bytes(), receipt.stat().st_ino
        events, _, error = self.startup()
        self.assertIsNone(error)
        self.assertNotIn('receipt-publish', events)
        self.assertEqual((receipt.read_bytes(), receipt.stat().st_ino), (previous, inode))

    def test_failed_default_build_or_verification_never_publishes_a_receipt(self):
        receipt = self.root/'.local'/runtime.BUILD_RECEIPT_NAME
        previous, inode = receipt.read_bytes(), receipt.stat().st_ino
        for fault in ('build-api', 'build-python-worker', 'stale-api', 'stale-python-worker', 'retag-after-readback', 'source-drift'):
            with self.subTest(fault=fault):
                original = (self.root/'package.json').read_bytes()
                events, _, error = self.startup(no_build=False, fault=fault)
                self.assertIsNotNone(error)
                self.assertNotIn('receipt-publish', events)
                self.assert_no_canonical_mutation(events)
                self.assertEqual((receipt.read_bytes(), receipt.stat().st_ino), (previous, inode))
                (self.root/'package.json').write_bytes(original)
        receipt.unlink()
        events, _, error = self.startup(no_build=False, fault='build-python-worker')
        self.assertIsNotNone(error)
        self.assertFalse(receipt.exists())
        self.assertNotIn('receipt-publish', events)

    def test_missing_or_malformed_receipt_refuses_before_image_readback_and_mutation(self):
        receipt = self.root/'.local'/runtime.BUILD_RECEIPT_NAME
        original = receipt.read_bytes()
        value = json.loads(original)
        variants = [None, b'', b'{', original.replace(b'"formatVersion":1', b'"formatVersion":true'),
                    original.replace(b'"formatVersion":1', b'"formatVersion":1,"formatVersion":1'),
                    original.replace(b'"formatVersion":1', b'"formatVersion":NaN'), b'\xff',
                    b'['*1200+b'0'+b']'*1200, original+b' ', b' '*(runtime.BUILD_RECEIPT_MAX_BYTES+1),
                    runtime.build_receipt_bytes(value|{'unexpected': True}),
                    runtime.build_receipt_bytes(value|{'images': {**self.recorded_images, 'api': 'not-an-image'}}),
                    runtime.build_receipt_bytes(value|{'snapshot': {**self.snapshot, 'profiles': {}}}),
                    runtime.build_receipt_bytes(value|{'snapshot': {**self.snapshot, 'sources': {}}})]
        for index, body in enumerate(variants):
            with self.subTest(variant=index):
                receipt.unlink(missing_ok=True)
                if body is not None:
                    receipt.write_bytes(body)
                    receipt.chmod(0o600)
                events, _, error = self.startup()
                self.assertIsInstance(error, SystemExit)
                self.assert_no_canonical_mutation(events)
                self.assertNotIn('cached-image-inventory', events)
                self.assertNotIn('readback-api', events)
                self.assertEqual(receipt.read_bytes() if receipt.exists() else None, body)

    def test_receipt_with_different_valid_image_id_cannot_authorize_fresh_readbacks(self):
        receipt = self.root/'.local'/runtime.BUILD_RECEIPT_NAME
        value = json.loads(receipt.read_bytes())
        value['images']['api'] = 'sha256:'+'5'*64
        receipt.write_bytes(runtime.build_receipt_bytes(value))
        events, _, error = self.startup()
        self.assertIsInstance(error, SystemExit)
        self.assertIn('readback-api', events)
        self.assertIn('readback-python-worker', events)
        self.assertIn('snapshot-verified', events)
        self.assert_no_canonical_mutation(events)

    def test_receipt_private_regular_file_and_directory_are_required_without_repair(self):
        receipt = self.root/'.local'/runtime.BUILD_RECEIPT_NAME
        original = receipt.read_bytes()
        for mode in (0o644, 0o400):
            receipt.chmod(mode)
            with self.subTest(mode=mode):
                events, _, error = self.startup()
                self.assertIsInstance(error, SystemExit)
                self.assert_no_canonical_mutation(events)
                self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), mode)
        receipt.chmod(0o600)
        receipt.parent.chmod(0o755)
        events, _, error = self.startup()
        self.assertIsInstance(error, SystemExit)
        self.assert_no_canonical_mutation(events)
        self.assertEqual(stat.S_IMODE(receipt.parent.stat().st_mode), 0o755)
        receipt.parent.chmod(0o700)
        external = self.root/'external-receipt.json'
        external.write_bytes(original)
        external.chmod(0o600)
        receipt.unlink()
        receipt.symlink_to(external)
        events, _, error = self.startup()
        self.assertIsInstance(error, SystemExit)
        self.assert_no_canonical_mutation(events)
        self.assertTrue(receipt.is_symlink())
        self.assertEqual(external.read_bytes(), original)
        receipt.unlink()
        os.link(external, receipt)
        events, _, error = self.startup()
        self.assertIsInstance(error, SystemExit)
        self.assert_no_canonical_mutation(events)
        receipt.unlink()
        os.mkfifo(receipt, 0o600)
        events, _, error = self.startup()
        self.assertIsInstance(error, SystemExit)
        self.assert_no_canonical_mutation(events)
        self.assertTrue(stat.S_ISFIFO(receipt.lstat().st_mode))

    def test_atomic_receipt_write_failure_preserves_previous_receipt_and_cleans_owned_temp(self):
        receipt = self.root/'.local'/runtime.BUILD_RECEIPT_NAME
        previous, inode = receipt.read_bytes(), receipt.stat().st_ino
        for operation in ('replace', 'fsync'):
            with self.subTest(operation=operation), patch.object(runtime.os, operation, side_effect=OSError('synthetic write failure')):
                with self.assertRaises(SystemExit):
                    runtime.write_build_receipt(self.snapshot, self.recorded_images)
            self.assertEqual((receipt.read_bytes(), receipt.stat().st_ino), (previous, inode))
            self.assertEqual(list(receipt.parent.iterdir()), [receipt])
        collision = receipt.parent/('.build-receipt-'+'a'*32+'.tmp')
        collision.write_bytes(b'preserve unrelated colliding file')
        with patch.object(runtime.uuid, 'uuid4', return_value=SimpleNamespace(hex='a'*32)):
            with self.assertRaises(SystemExit):
                runtime.write_build_receipt(self.snapshot, self.recorded_images)
        self.assertEqual(collision.read_bytes(), b'preserve unrelated colliding file')
        self.assertEqual((receipt.read_bytes(), receipt.stat().st_ino), (previous, inode))

    def test_receipt_replacement_during_read_refuses_the_obsolete_open_file(self):
        receipt = self.root/'.local'/runtime.BUILD_RECEIPT_NAME
        original_stat = runtime.os.stat
        def replace_then_stat(path, **kwargs):
            if path == runtime.BUILD_RECEIPT_NAME:
                replacement = receipt.parent/'replacement.json'
                replacement.write_bytes(receipt.read_bytes())
                replacement.chmod(0o600)
                os.replace(replacement, receipt)
            return original_stat(path, **kwargs)
        with patch.object(runtime.os, 'stat', side_effect=replace_then_stat):
            with self.assertRaises(SystemExit):
                runtime.read_build_receipt(self.snapshot)

    def test_source_change_during_receipt_publication_is_rechecked_before_startup(self):
        original_write = runtime.write_build_receipt
        def publish_then_change(snapshot, images):
            original_write(snapshot, images)
            (self.root/'python/Dockerfile').write_text('changed after receipt publication')
        with patch.object(runtime, 'write_build_receipt', side_effect=publish_then_change):
            events, _, error = self.startup(no_build=False)
        self.assertIsInstance(error, SystemExit)
        self.assertIn('receipt-published', events)
        self.assertEqual(events[-1], 'snapshot-verification')
        self.assert_no_canonical_mutation(events)
        with self.assertRaises(SystemExit):
            runtime.read_build_receipt(runtime.integrity_source_snapshot())


if __name__=='__main__': unittest.main()
