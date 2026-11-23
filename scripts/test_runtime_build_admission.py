#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host-only admission tests: no Docker, bootstrap or service commands execute."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('runtime_build_admission', Path(__file__).with_name('runtime.py'))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
GIB = 1024**3


class BuildAdmissionTests(unittest.TestCase):
    def doctor(self, free, cached):
        def capture(args, timeout=15):
            if args == ['docker', 'info', '--format', '{{json .}}']:
                return json.dumps({'ServerVersion': 'synthetic', 'MemTotal': 8*GIB, 'NCPU': 4, 'Architecture': 'arm64'})
            if args == ['docker', 'compose', 'version', '--short']:
                return 'synthetic'
            if args == ['docker', 'image', 'inspect', '--format', '{{.Id}}', 'synthetic:app']:
                if not cached:
                    raise subprocess.CalledProcessError(1, args)
                return 'sha256:synthetic'
            raise AssertionError('Unexpected external request')
        with tempfile.TemporaryDirectory(prefix='gc-build-admission-') as temp:
            root = Path(temp)
            (root/'deploy/compose').mkdir(parents=True)
            (root/'deploy/compose/compose.yaml').write_text('services:\n  app:\n    image: synthetic:app\n')
            output = io.StringIO()
            with patch.object(runtime, 'ROOT', root), patch.object(runtime, 'LOCAL', root/'.local'), \
                    patch.object(runtime, 'capture', side_effect=capture), patch.object(runtime, 'run', side_effect=AssertionError('Real command forbidden')), \
                    patch.object(runtime, 'require_local'), patch.object(runtime.shutil, 'which', return_value='/synthetic/tool'), \
                    patch.object(runtime.shutil, 'disk_usage', return_value=SimpleNamespace(free=free)), \
                    patch.object(runtime.socket, 'socket'), contextlib.redirect_stdout(output):
                passed = runtime.doctor()
            report = json.loads(output.getvalue())
            self.assertEqual(report, json.loads((root/'.local/doctor.json').read_text()))
            self.assertEqual(passed, report['passed'])
            return passed, next(check for check in report['checks'] if check['check'] == 'disk')

    def startup(self, free, doctor=True, build_failure=False):
        calls = []
        def run(args, **kwargs):
            calls.append((args, kwargs))
            if build_failure and args == runtime.COMPOSE + ['build', 'api']:
                raise subprocess.CalledProcessError(1, args)
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(sys, 'argv', ['dev', 'up']))
            for name in ('require_bootstrap', 'require_local', 'authentication_bootstrap'):
                stack.enter_context(patch.object(runtime, name))
            stack.enter_context(patch.object(runtime, 'doctor', return_value=doctor))
            stack.enter_context(patch.object(runtime, 'integrity_source_snapshot', return_value={}))
            stack.enter_context(patch.object(runtime, 'verify_built_image', return_value='sha256:'+'1'*64))
            stack.enter_context(patch.object(runtime, 'verify_build_snapshot'))
            stack.enter_context(patch.object(runtime, 'write_build_receipt'))
            disk = stack.enter_context(patch.object(runtime.shutil, 'disk_usage', side_effect=[SimpleNamespace(free=n) for n in free]))
            stack.enter_context(patch.object(runtime, 'run', side_effect=run))
            stack.enter_context(patch.object(runtime, 'capture', side_effect=AssertionError('Real command forbidden')))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            error = None
            try:
                runtime.main()
            except (SystemExit, subprocess.CalledProcessError) as caught:
                error = caught
            return calls, error, disk.call_count

    def test_build_floor_is_exact_bytes_with_safe_service_error(self):
        self.assertEqual(runtime.BUILD_DISK_FLOOR_BYTES, 4*GIB)
        for free in (4*GIB-1, 4*GIB, 4*GIB+1):
            with self.subTest(free=free), patch.object(runtime.shutil, 'disk_usage', return_value=SimpleNamespace(free=free)):
                if free < 4*GIB:
                    with self.assertRaisesRegex(SystemExit, 'Build stopped for api:.*at least 4 GiB'):
                        runtime.require_build_disk('api')
                else:
                    runtime.require_build_disk('api')

    def test_cached_doctor_refuses_old_failure_capacity_and_one_byte_below(self):
        for free in (21*GIB//10, 4*GIB-1, 4*GIB):
            with self.subTest(free=free):
                passed, check = self.doctor(free, cached=True)
                self.assertEqual(passed, free >= 4*GIB)
                self.assertEqual(check['passed'], passed)
                self.assertIn('admission budget 4.0 GiB', check['detail'])

    def test_missing_images_keep_eight_gib_floor(self):
        for free in (4*GIB, 8*GIB-1, 8*GIB):
            with self.subTest(free=free):
                passed, check = self.doctor(free, cached=False)
                self.assertEqual(passed, free >= 8*GIB)
                self.assertIn('admission budget 8.0 GiB', check['detail'])

    def test_low_space_stops_before_first_build_or_startup(self):
        calls, error, reads = self.startup([4*GIB-1])
        self.assertIsInstance(error, SystemExit)
        self.assertIn('Build stopped for api', str(error))
        self.assertEqual(calls, [(runtime.COMPOSE+['config', '--quiet'], {'timeout': 30})])
        self.assertEqual(reads, 1)

    def test_space_drop_between_builds_prevents_python_and_all_startup(self):
        calls, error, reads = self.startup([4*GIB, 4*GIB-1])
        self.assertIsInstance(error, SystemExit)
        self.assertIn('Build stopped for python-worker', str(error))
        self.assertEqual([args for args, _ in calls], [runtime.COMPOSE+['config', '--quiet'], runtime.COMPOSE+['build', 'api']])
        self.assertEqual(reads, 2)

    def test_boundary_allows_only_serial_builds_with_existing_timeouts(self):
        calls, error, reads = self.startup([4*GIB, 4*GIB])
        self.assertIsNone(error)
        builds = [(args, kwargs) for args, kwargs in calls if 'build' in args]
        self.assertEqual([args for args, _ in builds], [runtime.COMPOSE+['build', 'api'], runtime.COMPOSE+['build', 'python-worker']])
        for _, kwargs in builds:
            self.assertEqual(kwargs['timeout'], 1800)
            self.assertEqual(kwargs['env']['COMPOSE_PARALLEL_LIMIT'], '1')
        self.assertEqual(reads, 2)
        self.assertEqual([args for args, _ in calls][3], runtime.COMPOSE+['up', '-d', '--no-build', '--wait', '--wait-timeout', '120', 'postgres'])

    def test_build_error_still_aborts_without_later_build_or_startup(self):
        calls, error, reads = self.startup([4*GIB], build_failure=True)
        self.assertIsInstance(error, subprocess.CalledProcessError)
        self.assertEqual([args for args, _ in calls], [runtime.COMPOSE+['config', '--quiet'], runtime.COMPOSE+['build', 'api']])
        self.assertEqual(reads, 1)

    def test_doctor_failure_prevents_config_build_and_capacity_recheck(self):
        calls, error, reads = self.startup([], doctor=False)
        self.assertIsInstance(error, SystemExit)
        self.assertEqual(calls, [])
        self.assertEqual(reads, 0)


if __name__ == '__main__':
    unittest.main()
