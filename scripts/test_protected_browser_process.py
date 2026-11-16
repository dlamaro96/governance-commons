#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real isolated host subprocesses only; no Docker, browser, services or name kills."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import protected_browser_process as owned

HERE = Path(__file__).resolve().parent
PYTHON = Path(sys.executable).resolve()
WRAPPER = HERE/'protected_browser_process.py'


class BrowserProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='gc-owned-process-')
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)
        self.children = []
        self.addCleanup(self.remove_children)

    def spawn(self, code):
        child = subprocess.Popen([str(PYTHON), '-c', code], start_new_session=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.children.append((child, owned.identity(child.pid)))
        return child

    def remove_children(self):
        for child, original in self.children:
            current = owned.identity(child.pid)
            if original and owned.same(original, current) and current['live']:
                os.kill(child.pid, signal.SIGKILL)
            child.wait(timeout=5)

    def run_command(self, code, timeout=5):
        return owned.run([str(PYTHON), '-c', code], cwd=self.root, folder=self.root/'control',
            executable=PYTHON, expected_hash=owned.digest(PYTHON), deadline=time.monotonic()+15,
            admit=lambda: None, timeout=timeout)

    def test_kernel_identity_has_actual_group_and_owner(self):
        actual = owned.identity(os.getpid())
        self.assertEqual((actual['pgid'], actual['uid']), (os.getpgrp(), os.getuid()))
        self.assertTrue(owned.same(actual, owned.identity(os.getpid())))
        self.assertFalse(owned.same({**actual, 'start': 'different'}, actual))

    def test_fast_normal_completion_is_cleaned(self):
        result, proof = self.run_command('print("complete")')
        self.assertEqual(result.stdout.strip(), 'complete')
        self.assertEqual((proof['result'], proof['trigger'], proof['remainingLive']), ('PASS','normal',0))
        self.assertEqual(proof['registeredBrowserGroups'], 0)  # Full gate publisher refuses zero browsers.

    def test_nonzero_completion_is_distinct_from_cleanup_success(self):
        result, proof = self.run_command('raise SystemExit(7)')
        self.assertEqual(result.returncode,7)
        self.assertEqual((proof['result'],proof['trigger'],proof['remainingLive']),('PASS','nonzero',0))

    def test_our_process_group_cannot_become_owned(self):
        current = owned.identity(os.getpid())
        with self.assertRaises(RuntimeError):
            owned.Tracker(current,self.root,'a'*64)

    def test_registered_exec_preserves_exact_arguments_and_environment(self):
        payload = 'import os,sys,json; print(json.dumps([sys.argv[1:],os.environ["GC_PROCESS_TEST"]]))'
        code = f'import subprocess,os; os.environ["GC_PROCESS_TEST"]="trusted"; p=subprocess.run({[str(WRAPPER), "-c", payload, "a space", "--literal=$x"]!r},start_new_session=True); raise SystemExit(p.returncode)'
        result, proof = self.run_command(code)
        self.assertEqual(json.loads(result.stdout), [['a space','--literal=$x'],'trusted'])
        self.assertEqual(proof['registeredBrowserGroups'], 1)
        self.assertEqual((proof['result'],proof['remainingLive']), ('PASS',0))

    def test_timeout_cleans_registered_and_observed_detached_children_only(self):
        control = self.spawn('import time; time.sleep(30)')
        pid_file = self.root/'detached.json'
        descendant = 'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)'
        browser = f'import subprocess,signal,time,json,os; signal.signal(signal.SIGTERM,signal.SIG_IGN); p=subprocess.Popen({[str(PYTHON),"-c",descendant]!r},start_new_session=True); open({str(pid_file)!r},"w").write(json.dumps([os.getpid(),p.pid])); time.sleep(30)'
        code = f'import subprocess,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); subprocess.Popen({[str(WRAPPER),"-c",browser]!r},start_new_session=True); time.sleep(30)'
        with self.assertRaises(owned.BrowserCommandFailure) as failure:
            self.run_command(code, timeout=1.5)
        proof = failure.exception.proof
        self.assertEqual((proof['result'],proof['trigger'],proof['remainingLive']), ('PASS','timeout',0))
        self.assertEqual(proof['registeredBrowserGroups'],1)
        self.assertGreaterEqual(proof['trackedProcesses'],3)
        self.assertGreater(proof['killSignals'],0)
        self.assertIsNone(control.poll(), 'Unrelated process must survive')
        for pid in json.loads(pid_file.read_text()):
            observed = owned.identity(pid)
            self.assertTrue(observed is None or not observed['live'])

    def tracker(self):
        child = self.spawn('import time; time.sleep(30)')
        directory = self.root/'registry'; directory.mkdir(mode=0o700)
        return child, owned.Tracker(owned.identity(child.pid),directory,'a'*64)

    def test_reused_identity_refuses_signal(self):
        child, tracker = self.tracker()
        original = tracker.known[child.pid]
        with patch.object(owned,'identity',return_value={**original,'start':'changed'}), patch.object(owned.os,'kill') as kill, patch.object(owned.os,'killpg') as killpg:
            tracker.signal_owned({child.pid:original},signal.SIGKILL)
        kill.assert_not_called(); killpg.assert_not_called()
        self.assertEqual(tracker.conflicts,{child.pid})
        self.assertIsNone(child.poll())

    def test_foreign_registration_refused_and_owned_root_still_cleaned(self):
        child, tracker = self.tracker()
        foreign = self.spawn('import time; time.sleep(30)')
        row = owned.identity(foreign.pid)
        owned.write_private(tracker.directory/(str(foreign.pid)+'.json'),{k:row[k] for k in ('pid','ppid','pgid','uid','start')}|{'token':tracker.token})
        proof = tracker.close(child,'exception')
        self.assertEqual(proof['result'],'FAIL')
        self.assertGreater(proof['unresolvedGroups'],0)
        self.assertIsNotNone(child.poll())
        self.assertIsNone(foreign.poll())

    def test_inventory_error_still_cleans_known_root_and_refuses_proof(self):
        child, tracker = self.tracker()
        with patch.object(owned,'table',side_effect=RuntimeError('metadata unavailable')):
            proof = tracker.close(child,'exception')
        self.assertEqual((proof['result'],proof['remainingLive']),('FAIL',0))
        self.assertGreater(proof['unresolvedGroups'],0)
        self.assertIsNotNone(child.poll())

    def test_selector_constructor_failure_spawns_nothing(self):
        with patch.object(owned.selectors,'DefaultSelector',side_effect=RuntimeError('setup')), patch.object(owned.subprocess,'Popen') as spawn:
            with self.assertRaises(RuntimeError): self.run_command('import time; time.sleep(30)')
        spawn.assert_not_called()

    def test_first_identity_failure_reaps_gated_child_before_cli_exec(self):
        marker = self.root/'must-not-execute'
        actual = owned.subprocess.Popen
        children = []
        def spawn(*args,**kwargs):
            child = actual(*args,**kwargs); children.append(child); return child
        with patch.object(owned,'identity',side_effect=RuntimeError('initial metadata failure')), patch.object(owned.subprocess,'Popen',side_effect=spawn):
            with self.assertRaises(owned.BrowserCommandFailure) as failure:
                self.run_command(f'open({str(marker)!r},"w").write("bad")')
        self.assertFalse(marker.exists())
        self.assertEqual(len(children),1)
        self.assertIsNotNone(children[0].returncode)
        self.assertEqual((failure.exception.proof['result'],failure.exception.proof['remainingLive']),('FAIL',0))

    def test_selector_setup_failure_uses_bounded_cleanup(self):
        with patch.object(owned.selectors.DefaultSelector,'register',side_effect=RuntimeError('setup')):
            with self.assertRaises(owned.BrowserCommandFailure) as failure:
                self.run_command('import time; time.sleep(30)')
        self.assertEqual((failure.exception.proof['result'],failure.exception.proof['remainingLive']),('PASS',0))
        self.assertEqual(failure.exception.proof['trigger'],'exception')

    def test_malformed_registry_cannot_authorize_a_group(self):
        child, tracker = self.tracker()
        owned.write_private(tracker.directory/'9.json',{'pid':9})
        proof = tracker.close(child,'exception')
        self.assertEqual((proof['result'],proof['registeredBrowserGroups'],proof['remainingLive']),('FAIL',0,0))

    def test_launcher_registration_failure_never_executes_target(self):
        marker = self.root/'must-not-exist'
        result = subprocess.run([str(WRAPPER),'-c',f'open({str(marker)!r},"w").write("bad")'],
            env={**os.environ,'GC_PROTECTED_BROWSER_CONTROL':str(self.root/'missing')},
            capture_output=True,start_new_session=True,timeout=5)
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(marker.exists())
        self.assertEqual(result.stderr.decode().strip(),'OWNED_BROWSER_LAUNCH_REFUSED')


if __name__ == '__main__':
    unittest.main()
