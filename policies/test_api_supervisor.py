#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute real Node process groups; only the test copies shorten the timers."""
import shutil
import signal
import subprocess
import time
import unittest
from api_evidence import API_TEST_SUPERVISOR

NODE = shutil.which('node')


class SupervisorTests(unittest.TestCase):
    def command(self, child, *, short=False):
        code=API_TEST_SUPERVISOR
        if short:
            code=code.replace('1740000','500').replace('10000','100')
        return [NODE,'--input-type=module','-e',code,'--','--input-type=module','-e',child]

    def test_production_deadlines_are_unchanged(self):
        self.assertIn('},10000)',API_TEST_SUPERVISOR)
        self.assertIn('stop(124),1740000)',API_TEST_SUPERVISOR)
        self.assertIn("detached:true",API_TEST_SUPERVISOR)
        self.assertIn("process.kill(-child.pid,signal)",API_TEST_SUPERVISOR)

    def test_child_status_and_output_are_preserved(self):
        for code in (0,7):
            result=subprocess.run(self.command(f'console.log("synthetic-output");process.exit({code});'),capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,code);self.assertEqual(result.stdout,'synthetic-output\n')

    def test_stalled_child_is_killed_even_if_it_ignores_term(self):
        started=time.monotonic()
        result=subprocess.run(self.command('process.on("SIGTERM",()=>{});console.log("started");setInterval(()=>{},1000);',short=True),capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,124);self.assertEqual(result.stdout,'started\n')
        self.assertLess(time.monotonic()-started,5)

    def test_timeout_removes_descendants_and_closes_inherited_pipes(self):
        child='import {spawn} from "node:child_process";process.on("SIGTERM",()=>{});spawn(process.execPath,["-e",\'process.on("SIGTERM",()=>{});setInterval(()=>{},1000)\'],{stdio:"inherit"});console.log("grandchild-started");setInterval(()=>{},1000);'
        result=subprocess.run(self.command(child,short=True),capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,124);self.assertEqual(result.stdout,'grandchild-started\n')

    def test_blocked_child_event_loop_cannot_delay_supervisor_deadline(self):
        child='process.on("SIGTERM",()=>{});console.log("busy");while(true){}'
        result=subprocess.run(self.command(child,short=True),capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,124);self.assertEqual(result.stdout,'busy\n')

    def test_normal_exit_also_removes_descendants(self):
        child='import {spawn} from "node:child_process";spawn(process.execPath,["-e","setInterval(()=>{},1000)"],{stdio:"inherit"});process.exit(0);'
        result=subprocess.run(self.command(child),capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0)

    def test_external_term_is_forwarded_with_bounded_cleanup(self):
        process=subprocess.Popen(self.command('process.on("SIGTERM",()=>{});console.log("started");setInterval(()=>{},1000);',short=True),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            self.assertEqual(process.stdout.readline(),'started\n')
            process.send_signal(signal.SIGTERM)
            process.communicate(timeout=5)
            self.assertEqual(process.returncode,143)
        finally:
            if process.poll() is None:process.kill();process.wait(timeout=2)
            process.stdout.close();process.stderr.close()


if __name__=='__main__':
    unittest.main()
