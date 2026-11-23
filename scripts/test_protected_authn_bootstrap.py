#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Actual bootstrap shell/file checks plus orchestration checks; no Docker qualification."""
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('protected_bootstrap_runner', ROOT/'scripts/runtime-test-protected-authn.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def service(name):
    text = (ROOT/'deploy/protected-authn/compose.yaml').read_text()
    match = re.search(r'^  '+re.escape(name)+r':\n(.*?)(?=^  [A-Za-z0-9_-]+:|\Z)', text, re.M | re.S)
    if match is None:
        raise AssertionError('Required bootstrap service missing')
    return match.group(1)


def shell(name, output):
    block = service(name)
    command = re.search(r'^    command:\n      - >-\n((?:        [^\n]*\n)+)', block, re.M)
    if command is None:
        raise AssertionError('Expected one literal folded bootstrap shell')
    return ' '.join(line.strip() for line in command.group(1).splitlines()).replace('$$', '$').replace(
        '${LOCAL_UID:?}', str(os.getuid())).replace('${LOCAL_GID:?}', str(os.getgid())).replace('/output', str(output))


class PrivateBootstrapTests(unittest.TestCase):
    def test_failure_output_never_uses_arbitrary_phase_or_exception_text(self):
        private = 'private callback or credential must not be exported'
        self.assertEqual(runner.failure_phase({'failure':{'phase':'tool-hash-admission','message':private}}),'tool-hash-admission')
        for failure in ({'phase':private,'message':private},{'phase':[private]},private,None):
            self.assertEqual(runner.failure_phase({'failure':failure}),'unavailable')

    def test_admission_and_browser_launch_share_one_hash_boundary(self):
        self.assertEqual(runner.binary_sha(Path(__file__)),runner.browser_process.digest(Path(__file__)))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='gc-private-bootstrap-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root/'output'
        self.output.mkdir(mode=0o700)
        self.source = self.root/'private-config.json'
        self.data = b'{"synthetic":"not-a-credential","literal":"$x;\\n"}'
        self.source.write_bytes(self.data)
        self.source.chmod(0o600)

    def invoke(self, name, data=None):
        return subprocess.run(['/bin/sh','-ec',shell(name,self.output)],input=data,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3)

    def initialize(self):
        result = self.invoke('qualification-private-bootstrap')
        self.assertEqual(result.returncode,0,result.stderr.decode())

    def test_privilege_and_mount_separation_uses_no_dac_bypass(self):
        root, copy = service('qualification-private-bootstrap'), service('qualification-private-copy')
        self.assertIn("user: '0:0'",root)
        self.assertIn('cap_add: [CHOWN]',root)
        self.assertNotIn('/input',root)
        self.assertNotIn('private-config.json',root)
        self.assertIn("user: '${LOCAL_UID:?}:${LOCAL_GID:?}'",copy)
        self.assertNotIn('cap_add:',copy)
        self.assertNotIn('/input',copy)
        for block in (root,copy):
            self.assertIn('cap_drop: [ALL]',block)
            self.assertIn('network_mode: none',block)
            self.assertIn('read_only: true',block)
            self.assertIn('security_opt: [no-new-privileges:true]',block)
            self.assertIn('logging: {driver: none}',block)
            self.assertEqual(block.split('    volumes:\n')[1].strip(),'- qualification-private:/output')
        self.assertIn('stdin_open: true',copy)

    def test_actual_shell_copies_exact_bytes_and_retains_private_modes(self):
        self.initialize()
        result = self.invoke('qualification-private-copy',runner.private_configuration(self.source))
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(result.stdout,b'')
        self.assertEqual((self.output/'config.json').read_bytes(),self.data)
        self.assertEqual(self.source.read_bytes(),self.data)
        for path, mode in ((self.source,0o600),(self.output,0o700),
                           (self.output/'batch',0o700),(self.output/'config.json',0o600)):
            self.assertEqual((path.stat().st_uid,stat.S_IMODE(path.stat().st_mode)),(os.getuid(),mode))

    def test_actual_shell_accepts_exact_limit_and_refuses_empty_or_oversized_input(self):
        self.initialize()
        target = self.output/'config.json'
        for data, valid in ((b'x'*65536,True),(b'',False),(b'x'*65537,False),(b'x'*131072,False)):
            with self.subTest(size=len(data)):
                target.unlink(missing_ok=True)
                result = self.invoke('qualification-private-copy',data)
                self.assertEqual(result.returncode==0,valid)
                self.assertLessEqual(target.stat().st_size,65537)
                self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o600)

    def test_actual_shell_refuses_existing_and_dangling_targets_without_overwrite(self):
        self.initialize()
        target = self.output/'config.json'
        target.write_bytes(b'original')
        result = self.invoke('qualification-private-copy',self.data)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(target.read_bytes(),b'original')
        target.unlink()
        missing = self.root/'must-not-create'
        target.symlink_to(missing)
        self.assertNotEqual(self.invoke('qualification-private-copy',self.data).returncode,0)
        self.assertFalse(missing.exists())
        self.assertTrue(target.is_symlink())

    def test_root_initialization_refuses_preexisting_or_symlinked_batch(self):
        batch = self.output/'batch'
        batch.symlink_to(self.root/'must-not-create')
        self.assertNotEqual(self.invoke('qualification-private-bootstrap').returncode,0)
        self.assertTrue(batch.is_symlink())
        batch.unlink()
        self.initialize()
        self.assertNotEqual(self.invoke('qualification-private-bootstrap').returncode,0)

    def test_host_read_requires_regular_owned_0600_bounded_file(self):
        self.assertEqual(runner.private_configuration(self.source),self.data)
        for data,mode in ((b'',0o600),(b'x'*65537,0o600),(self.data,0o644),(self.data,0o400)):
            with self.subTest(size=len(data),mode=mode):
                self.source.write_bytes(data)
                self.source.chmod(mode)
                with self.assertRaises(RuntimeError): runner.private_configuration(self.source)
                self.source.chmod(0o600)
        self.source.write_bytes(b'x'*65536)
        self.assertEqual(len(runner.private_configuration(self.source)),65536)

    def test_host_read_refuses_symlinks_directories_and_fifo_without_blocking(self):
        link = self.root/'link'
        link.symlink_to(self.source)
        with self.assertRaises(OSError): runner.private_configuration(link)
        with self.assertRaises(RuntimeError): runner.private_configuration(self.output)
        fifo = self.root/'pipe'
        os.mkfifo(fifo,0o600)
        with self.assertRaises(RuntimeError): runner.private_configuration(fifo)

    def harness(self, *, label='owned-project', observed=None, change=False):
        calls = []
        expected = {'uid':os.getuid(),'gid':os.getgid(),'configMode':0o600,'batchMode':0o700,
                    'configSha256':runner.sha(self.data)}
        def compose(*args, **kwargs):
            calls.append(('compose',args,kwargs))
            if change and args[-1]=='qualification-private-copy': self.source.write_bytes(b'changed')
        def docker(*args, **kwargs):
            calls.append(('docker',args,kwargs))
            return SimpleNamespace(stdout=label+'\n')
        def reader(mode):
            calls.append(('reader',mode))
            return SimpleNamespace(stdout=json.dumps(expected if observed is None else observed))
        value = SimpleNamespace(secret_path=self.source,id='owned-project',compose=compose,docker=docker,
                                private_reader=reader,private_ready=False,report={})
        return value,calls

    def test_orchestration_sends_only_sensitive_bounded_stdin_after_owned_volume_check(self):
        h,calls = self.harness()
        runner.Harness.prepare_private(h)
        self.assertTrue(h.private_ready)
        self.assertEqual([x[0] for x in calls],['compose','docker','compose','reader'])
        self.assertEqual(calls[0][1],('run','--rm','--no-deps','qualification-private-bootstrap'))
        self.assertEqual(calls[0][2],{'timeout':30})
        self.assertEqual(calls[2][1],('run','--rm','--no-deps','-T','qualification-private-copy'))
        self.assertEqual(calls[2][2],{'input':self.data,'sensitive':True,'timeout':30})
        self.assertNotIn(self.data.decode(),repr(h.report))

    def test_wrong_project_refuses_before_credentials_are_sent(self):
        h,calls = self.harness(label='unrelated-project')
        with self.assertRaises(RuntimeError): runner.Harness.prepare_private(h)
        self.assertEqual([x[0] for x in calls],['compose','docker'])
        self.assertFalse(h.private_ready)
        self.assertEqual(h.report,{})

    def test_source_change_or_wrong_volume_readback_never_marks_ready(self):
        for options in ({'change':True},{'observed':{'wrong':'metadata'}}):
            with self.subTest(options=options):
                self.source.write_bytes(self.data)
                h,calls = self.harness(**options)
                with self.assertRaises(RuntimeError): runner.Harness.prepare_private(h)
                self.assertFalse(h.private_ready)
                self.assertEqual(h.report,{})


if __name__=='__main__': unittest.main()
