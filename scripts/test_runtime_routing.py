#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host-only launcher routing checks; these never launch Docker or a gate."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('gc_runtime', Path(__file__).with_name('runtime.py'))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class RuntimeRoutingTests(unittest.TestCase):
    def test_explicit_authority_read_scopes_and_historical_route_are_distinct(self):
        for suite, argv in (
                ('authority-read-original', ['scripts/runtime-test-authority-read-upgrade.py', '--run-local', '--scope', 'original']),
                ('authority-read-current', ['scripts/runtime-test-authority-read-upgrade.py', '--run-local', '--scope', 'current']),
                ('authority-foundation', ['scripts/runtime-test-authority-foundation.py'])):
            calls = []
            with self.subTest(suite=suite), patch.object(sys, 'argv', ['dev', 'test', '--suite', suite]), \
                    patch.object(runtime, 'require_local', side_effect=lambda: calls.append('local')), \
                    patch.object(runtime, 'require_bootstrap', side_effect=AssertionError('core bootstrap reached')), \
                    patch.object(runtime, 'run', side_effect=lambda args, **kw: calls.append((args, kw))):
                runtime.main()
            self.assertEqual(calls, ['local', ([sys.executable, *argv], {'timeout': 1800})])

    def test_authority_read_scopes_refuse_remote_or_unavailable_local_context(self):
        for suite in ('authority-read-original', 'authority-read-current'):
            for override, endpoint in (('tcp://remote.invalid:2375', 'unix:///local.sock'), ('', 'ssh://remote.invalid'), ('', None)):
                with self.subTest(suite=suite, endpoint=endpoint), \
                        patch.object(sys, 'argv', ['dev', 'test', '--suite', suite]), \
                        patch.dict(os.environ, {'DOCKER_HOST': override}), \
                        patch.object(runtime, 'capture', return_value=json.dumps([{'Endpoints': {'docker': {'Host': endpoint}}}]) if endpoint else 'invalid'), \
                        patch.object(runtime, 'require_bootstrap', side_effect=AssertionError('core bootstrap reached')), \
                        patch.object(runtime, 'run') as run:
                    with self.assertRaises(SystemExit): runtime.main()
                    run.assert_not_called()

    def test_authority_read_failures_propagate_without_retry_or_core_fallback(self):
        for scope in ('original', 'current'):
            with self.subTest(scope=scope), patch.object(sys, 'argv', ['dev', 'test', '--suite', 'authority-read-' + scope]), \
                    patch.object(runtime, 'require_local'), \
                    patch.object(runtime, 'require_bootstrap', side_effect=AssertionError('core bootstrap reached')), \
                    patch.object(runtime, 'run', side_effect=RuntimeError('synthetic gate failure')) as run:
                with self.assertRaisesRegex(RuntimeError, '^synthetic gate failure$'): runtime.main()
                run.assert_called_once_with([sys.executable, 'scripts/runtime-test-authority-read-upgrade.py', '--run-local', '--scope', scope], timeout=1800)

    def test_held_metadata_gate_requires_local_context_before_exact_isolated_runner(self):
        calls = []
        with patch.object(sys, 'argv', ['dev', 'test', '--suite', 'held-metadata-authority']), \
                patch.object(runtime, 'require_local', side_effect=lambda: calls.append('local')), \
                patch.object(runtime, 'require_bootstrap', side_effect=AssertionError('core bootstrap reached')), \
                patch.object(runtime, 'run', side_effect=lambda args, **kw: calls.append((args, kw))):
            runtime.main()
        self.assertEqual(calls, ['local', ([sys.executable, 'scripts/runtime-test-held-metadata-authority.py', '--run-local'], {'timeout': 900})])

    def test_held_metadata_gate_refuses_remote_or_unavailable_local_context(self):
        for override, endpoint in (('tcp://remote.invalid:2375', 'unix:///local.sock'), ('', 'ssh://remote.invalid'), ('', None)):
            with self.subTest(endpoint=endpoint), patch.object(sys, 'argv', ['dev', 'test', '--suite', 'held-metadata-authority']), \
                    patch.dict(os.environ, {'DOCKER_HOST': override}), \
                    patch.object(runtime, 'capture', return_value=json.dumps([{'Endpoints': {'docker': {'Host': endpoint}}}]) if endpoint else 'invalid'), \
                    patch.object(runtime, 'require_bootstrap', side_effect=AssertionError('core bootstrap reached')), \
                    patch.object(runtime, 'run') as run:
                with self.assertRaises(SystemExit): runtime.main()
                run.assert_not_called()

    def test_application_authn_bridge_gate_requires_local_context_before_exact_isolated_runner(self):
        calls = []
        with patch.object(sys, 'argv', ['dev', 'test', '--suite', 'application-authn-bridge']), \
                patch.object(runtime, 'require_local', side_effect=lambda: calls.append('local')), \
                patch.object(runtime, 'require_bootstrap', side_effect=AssertionError('core bootstrap reached')), \
                patch.object(runtime, 'run', side_effect=lambda args, **kw: calls.append((args, kw))):
            runtime.main()
        self.assertEqual(calls, ['local', ([sys.executable, 'scripts/runtime-test-application-authn-bridge.py', '--run-local'], {'timeout': 900})])

    def test_application_authn_bridge_gate_refuses_remote_or_unavailable_local_context(self):
        for override, endpoint in (('tcp://remote.invalid:2375', 'unix:///local.sock'), ('', 'ssh://remote.invalid'), ('', None)):
            with self.subTest(endpoint=endpoint), patch.object(sys, 'argv', ['dev', 'test', '--suite', 'application-authn-bridge']), \
                    patch.dict(os.environ, {'DOCKER_HOST': override}), \
                    patch.object(runtime, 'capture', return_value=json.dumps([{'Endpoints': {'docker': {'Host': endpoint}}}]) if endpoint else 'invalid'), \
                    patch.object(runtime, 'require_bootstrap', side_effect=AssertionError('core bootstrap reached')), \
                    patch.object(runtime, 'run') as run:
                with self.assertRaises(SystemExit): runtime.main()
                run.assert_not_called()

    def test_postgres_target_gate_checks_local_context_without_bootstrap(self):
        calls = []
        def capture(args, timeout=15):
            calls.append(('context', args))
            return json.dumps([{'Endpoints': {'docker': {'Host': 'unix:///synthetic/docker.sock'}}}])
        def run(args, **kwargs):
            calls.append(('gate', args, kwargs))
        with patch.object(sys, 'argv', ['dev', 'test', '--suite', 'postgres-targets']), \
                patch.dict(os.environ, {'DOCKER_HOST': ''}), \
                patch.object(runtime, 'capture', capture), patch.object(runtime, 'run', run), \
                patch.object(runtime, 'require_bootstrap', side_effect=AssertionError('core bootstrap reached')):
            runtime.main()
        self.assertEqual(calls, [
            ('context', ['docker', 'context', 'inspect']),
            ('gate', [sys.executable, 'scripts/runtime-test-postgres-targets.py'], {'timeout': 480}),
        ])

    def test_remote_or_unavailable_context_cannot_launch_postgres_gate(self):
        for override, endpoint in (('tcp://remote.invalid:2375', 'unix:///local.sock'),
                                   ('', 'ssh://remote.invalid'), ('', None)):
            with self.subTest(override=override, endpoint=endpoint), \
                    patch.object(sys, 'argv', ['dev', 'test', '--suite', 'postgres-targets']), \
                    patch.dict(os.environ, {'DOCKER_HOST': override}), \
                    patch.object(runtime, 'capture', return_value=json.dumps([{'Endpoints': {'docker': {'Host': endpoint}}}]) if endpoint else 'invalid'), \
                    patch.object(runtime, 'run') as run, \
                    patch.object(runtime, 'require_bootstrap', side_effect=AssertionError('core bootstrap reached')):
                with self.assertRaises(SystemExit):
                    runtime.main()
                run.assert_not_called()

    def test_gate_failure_propagates_and_does_not_fall_through_to_core(self):
        with patch.object(sys, 'argv', ['dev', 'test', '--suite', 'postgres-targets']), \
                patch.object(runtime, 'require_local'), \
                patch.object(runtime, 'require_bootstrap', side_effect=AssertionError('core bootstrap reached')), \
                patch.object(runtime, 'run', side_effect=RuntimeError('synthetic gate failure')) as run:
            with self.assertRaisesRegex(RuntimeError, '^synthetic gate failure$'):
                runtime.main()
            run.assert_called_once_with([sys.executable, 'scripts/runtime-test-postgres-targets.py'], timeout=480)

    def test_help_lists_gate_without_inspecting_docker(self):
        output = io.StringIO()
        with patch.object(sys, 'argv', ['dev', 'help']), contextlib.redirect_stdout(output), \
                patch.object(runtime, 'capture') as capture, patch.object(runtime, 'run') as run:
            runtime.main()
        self.assertIn('./dev test --suite postgres-targets', output.getvalue())
        self.assertIn('./dev test --suite uniqueness-upgrade', output.getvalue())
        self.assertIn('./dev test --suite uniqueness-worker', output.getvalue())
        self.assertIn('./dev test --suite range-upgrade', output.getvalue())
        self.assertIn('./dev test --suite range-worker', output.getvalue())
        self.assertIn('./dev test --suite monitoring-upgrade', output.getvalue())
        self.assertIn('./dev test --suite authority-read-original', output.getvalue())
        self.assertIn('./dev test --suite authority-read-current', output.getvalue())
        self.assertIn('./dev test --suite authority-foundation', output.getvalue())
        self.assertIn('./dev test --suite held-metadata-authority', output.getvalue())
        self.assertIn('./dev test --suite application-authn-bridge', output.getvalue())
        capture.assert_not_called()
        run.assert_not_called()

    def test_both_uniqueness_gates_refuse_remote_and_unavailable_context(self):
        for suite in ('uniqueness-upgrade', 'uniqueness-worker', 'range-upgrade', 'range-worker', 'monitoring-upgrade'):
            for override, endpoint in (('tcp://remote.invalid:2375', 'unix:///local.sock'), ('', 'ssh://remote.invalid'), ('', None)):
                with self.subTest(suite=suite, override=override, endpoint=endpoint), \
                        patch.object(sys, 'argv', ['dev', 'test', '--suite', suite]), \
                        patch.dict(os.environ, {'DOCKER_HOST': override}), \
                        patch.object(runtime, 'capture', return_value=json.dumps([{'Endpoints': {'docker': {'Host': endpoint}}}]) if endpoint else 'invalid'), \
                        patch.object(runtime, 'require_bootstrap'), patch.object(runtime, 'run') as run:
                    with self.assertRaises(SystemExit):
                        runtime.main()
                    run.assert_not_called()

    def test_uniqueness_worker_missing_bootstrap_cannot_even_inspect_or_launch_core(self):
        with patch.object(sys, 'argv', ['dev', 'test', '--suite', 'uniqueness-worker']), \
                patch.object(runtime, 'require_bootstrap', side_effect=SystemExit('bootstrap unavailable')), \
                patch.object(runtime, 'capture') as capture, patch.object(runtime, 'run') as run:
            with self.assertRaisesRegex(SystemExit, '^bootstrap unavailable$'):
                runtime.main()
            capture.assert_not_called()
            run.assert_not_called()

    def test_range_worker_missing_bootstrap_cannot_even_inspect_or_launch_core(self):
        with patch.object(sys, 'argv', ['dev', 'test', '--suite', 'range-worker']), \
                patch.object(runtime, 'require_bootstrap', side_effect=SystemExit('bootstrap unavailable')), \
                patch.object(runtime, 'capture') as capture, patch.object(runtime, 'run') as run:
            with self.assertRaisesRegex(SystemExit, '^bootstrap unavailable$'):
                runtime.main()
            capture.assert_not_called()
            run.assert_not_called()



class RepairedRelationRoutingTests(unittest.TestCase):
    CHAIN = (
        ('glossary-population', '018', 1500), ('quality', '019', 1800),
        ('lineage', '020', 1800), ('classification', '021', 2100),
        ('reference', '022', 2400), ('reference-quality', '023', 2700),
        ('reference-structure', '024', 3000),
    )
    ROUTES = tuple((name+'-repaired-upgrade', ['scripts/runtime-test-governance-repaired-upgrade.py', '--run-local', '--through', through], timeout)
                   for name,through,timeout in CHAIN) + tuple(
        ('relation-candidate-'+scope, ['scripts/runtime-test-relation-candidate-upgrade.py','--run-local','--scope',scope],900)
        for scope in ('original','current'))

    def test_nine_exact_routes_guard_before_execution_without_bootstrap(self):
        for suite,argv,timeout in self.ROUTES:
            calls=[]
            with self.subTest(suite=suite), patch.object(sys,'argv',['dev','test','--suite',suite]), \
                    patch.object(runtime,'require_local',side_effect=lambda:calls.append('local')), \
                    patch.object(runtime,'require_bootstrap',side_effect=AssertionError('core bootstrap reached')), \
                    patch.object(runtime,'run',side_effect=lambda args,**kwargs:calls.append((args,kwargs))):
                runtime.main()
            self.assertEqual(calls,['local',([sys.executable,*argv],{'timeout':timeout})])

    def test_all_nine_refuse_remote_and_unknown_local_context_before_execution(self):
        for suite,_,_ in self.ROUTES:
            for override,endpoint in (('tcp://remote.invalid:2375','unix:///local.sock'),('', 'ssh://remote.invalid'),('',None)):
                with self.subTest(suite=suite,endpoint=endpoint), patch.object(sys,'argv',['dev','test','--suite',suite]), \
                        patch.dict(os.environ,{'DOCKER_HOST':override}), \
                        patch.object(runtime,'capture',return_value=json.dumps([{'Endpoints':{'docker':{'Host':endpoint}}}]) if endpoint else 'invalid'), \
                        patch.object(runtime,'require_bootstrap',side_effect=AssertionError('core bootstrap reached')), \
                        patch.object(runtime,'run') as run:
                    with self.assertRaises(SystemExit):runtime.main()
                    run.assert_not_called()

    def test_nine_failures_propagate_once_without_retry_or_fallback(self):
        for suite,argv,timeout in self.ROUTES:
            with self.subTest(suite=suite), patch.object(sys,'argv',['dev','test','--suite',suite]), \
                    patch.object(runtime,'require_local'), \
                    patch.object(runtime,'require_bootstrap',side_effect=AssertionError('core bootstrap reached')), \
                    patch.object(runtime,'run',side_effect=RuntimeError('synthetic gate refusal')) as run:
                with self.assertRaisesRegex(RuntimeError,'^synthetic gate refusal$'):runtime.main()
                run.assert_called_once_with([sys.executable,*argv],timeout=timeout)

    def test_original_seven_commands_still_execute_original_runners(self):
        for name,_,timeout in self.CHAIN:
            with self.subTest(name=name), patch.object(sys,'argv',['dev','test','--suite',name+'-upgrade']), \
                    patch.object(runtime,'require_local'), \
                    patch.object(runtime,'require_bootstrap',side_effect=AssertionError('core bootstrap reached')), \
                    patch.object(runtime,'run') as run:
                runtime.main()
                run.assert_called_once_with([sys.executable,'scripts/runtime-test-'+name+'-upgrade.py'],timeout=timeout)

    def test_help_lists_all_distinct_routes_without_execution(self):
        output=io.StringIO()
        with patch.object(sys,'argv',['dev','help']), contextlib.redirect_stdout(output), \
                patch.object(runtime,'capture') as capture,patch.object(runtime,'run') as run:
            runtime.main()
        for suite,_,_ in self.ROUTES:self.assertEqual(output.getvalue().count('./dev test --suite '+suite+' '),1)
        capture.assert_not_called();run.assert_not_called()



class CoreAuthenticationInstallRoutingTests(unittest.TestCase):
    def test_explicit_setup_guards_then_runs_only_fixed_installer_steps(self):
        calls=[]
        with patch.object(sys,'argv',['dev','authn-core-install']), \
                patch.object(runtime,'require_bootstrap',side_effect=lambda:calls.append('bootstrap')), \
                patch.object(runtime,'require_local',side_effect=lambda:calls.append('local')), \
                patch.object(runtime,'authentication_bootstrap',side_effect=lambda:calls.append('authentication')), \
                patch.object(runtime,'run',side_effect=lambda args,**kw:calls.append((args,kw))):
            runtime.main()
        self.assertEqual(calls,['bootstrap','local','authentication',
            ([sys.executable,'scripts/runtime-keycloak-client.py'],{'timeout':90}),
            (runtime.COMPOSE+['run','--rm','--no-deps','-T','authn-install-state'],{'timeout':60}),
            (runtime.COMPOSE+['run','--rm','--no-deps','-T','authn-install'],{'timeout':180})])

    def test_setup_guard_and_command_failures_do_not_continue_or_retry(self):
        for guard in ('require_bootstrap','require_local','authentication_bootstrap'):
            with patch.object(sys,'argv',['dev','authn-core-install']), \
                    patch.object(runtime,'require_bootstrap'),patch.object(runtime,'require_local'),patch.object(runtime,'authentication_bootstrap'), \
                    patch.object(runtime,guard,side_effect=SystemExit('synthetic admission refusal')),patch.object(runtime,'run') as run:
                with self.assertRaises(SystemExit):runtime.main()
                run.assert_not_called()
        for failed in range(3):
            calls=[]
            def run(args,**kwargs):
                calls.append(args)
                if len(calls)==failed+1:raise RuntimeError('synthetic setup refusal')
            with patch.object(sys,'argv',['dev','authn-core-install']), \
                    patch.object(runtime,'require_bootstrap'),patch.object(runtime,'require_local'),patch.object(runtime,'authentication_bootstrap'), \
                    patch.object(runtime,'run',side_effect=run):
                with self.assertRaisesRegex(RuntimeError,'synthetic setup refusal'):runtime.main()
            self.assertEqual(len(calls),failed+1)

if __name__ == '__main__':
    unittest.main()
