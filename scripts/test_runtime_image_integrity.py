#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host source/orchestration checks only; Docker is never executed here."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('runtime_image_integrity', Path(__file__).with_name('runtime.py'))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
IMAGE = 'sha256:'+'1'*64
OTHER_IMAGE = 'sha256:'+'2'*64


class ImageIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='gc-image-integrity-host-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        files = {name:b'synthetic' for name in runtime.INTEGRITY_CONTROLS}
        files.update({'package.json':b'{"name":"fixture"}', 'pnpm-lock.yaml':b'lockfileVersion: 9', 'pnpm-workspace.yaml':b'packages: []',
                      'apps/api/src/route.ts':b'export const route = 1;', 'apps/web/package.json':b'{"name":"web"}',
                      'packages/domain/src/model.ts':b'export const model = 1;', 'packages/domain/package.json':b'{"name":"domain"}',
                      'python/pyproject.toml':b'[project]\nname="fixture"', 'python/uv.lock':b'version = 1',
                      'python/governance_workers/server.py':b'VALUE = 1\n', 'python/tests/test_worker.py':b'VALUE = 2\n'})
        for name, body in files.items():
            path=self.root/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(body)
        self.root_patch=patch.object(runtime,'ROOT',self.root);self.root_patch.start();self.addCleanup(self.root_patch.stop)
        self.snapshot=runtime.integrity_source_snapshot()

    def reply(self, service='api'):
        return {'formatVersion':1,'profile':service,
                'sources':[{'path':name.removeprefix('python/') if service=='python-worker' else name,
                            'sha256':self.snapshot['sources'][name]} for name in self.snapshot['profiles'][service]],
                'checks':['package-manifests','selected-runtime-imports'] if service=='api' else ['python-parse','project-lock-parse','psycopg-import']}

    def verify(self, service='api', output=None, image_after=IMAGE, fail_run=False):
        calls=[];inspects=0
        def command(args,data=b'',timeout=30):
            nonlocal inspects
            calls.append((args,data,timeout))
            if args[:3]==['docker','image','inspect']:
                inspects+=1;return ((IMAGE if inspects==1 else image_after)+'\n').encode()
            if args[:2]==['docker','run']:
                if fail_run:raise SystemExit('synthetic bounded command failure')
                return output if output is not None else json.dumps(self.reply(service)).encode()
            if args[:3]==['docker','container','ls']:
                return b''
            raise AssertionError('Unexpected Docker operation')
        with patch.object(runtime,'integrity_command',side_effect=command):
            error=None;selected=None
            try:selected=runtime.verify_built_image(service,self.snapshot)
            except SystemExit as caught:error=caught
        return selected,error,calls

    def test_snapshot_includes_untracked_package_manifests_and_python_but_no_generated_or_private_files(self):
        for path in ('apps/web/dist/generated.js','packages/x/node_modules/lib.js','python/tests/__pycache__/cached.pyc','.local/private.json'):
            p=self.root/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('ignored')
        p=self.root/'apps/api/src/untracked.ts';p.write_text('export const added = true;')
        actual=runtime.integrity_source_snapshot()
        self.assertIn('apps/api/src/untracked.ts',actual['sources'])
        self.assertIn('apps/web/package.json',actual['profiles']['api'])
        self.assertIn('packages/domain/package.json',actual['profiles']['api'])
        self.assertIn('python/tests/test_worker.py',actual['profiles']['python-worker'])
        self.assertFalse(any(any(v in path.split('/') for v in ('dist','node_modules','__pycache__','.local')) for path in actual['sources']))

    def test_source_symlink_fifo_private_name_and_file_budget_refuse_before_materialization(self):
        p=self.root/'apps/api/src/unsafe.ts'
        p.symlink_to(self.root/'package.json')
        with self.assertRaises(SystemExit):runtime.integrity_source_snapshot()
        p.unlink();os.mkfifo(p)
        with self.assertRaises(SystemExit):runtime.integrity_source_snapshot()
        p.unlink();p=self.root/'apps/api/.env.local';p.write_text('not-a-secret')
        with self.assertRaises(SystemExit):runtime.integrity_source_snapshot()
        p.unlink()
        with patch.object(runtime,'INTEGRITY_MAX_FILE_BYTES',2),self.assertRaises(SystemExit):runtime.integrity_source_snapshot()
        with patch.object(runtime,'INTEGRITY_MAX_FILES',2),self.assertRaises(SystemExit):runtime.integrity_source_snapshot()
        with patch.object(runtime.os,'scandir',side_effect=PermissionError()),self.assertRaises(SystemExit):runtime.integrity_source_snapshot()
        (self.root/'apps/api/.local').mkdir()
        with self.assertRaises(SystemExit):runtime.integrity_source_snapshot()

    def test_exact_immutable_ids_security_flags_and_profile_paths(self):
        for service in ('api','python-worker'):
            with self.subTest(service=service):
                selected,error,calls=self.verify(service)
                self.assertIsNone(error);self.assertEqual(selected,IMAGE)
                command,data,timeout=next(c for c in calls if c[0][:2]==['docker','run'])
                self.assertEqual(timeout,60);self.assertIn(IMAGE,command);self.assertNotIn(runtime.INTEGRITY_PROFILES[service]['image'],command)
                for flag,value in (('--network','none'),('--pull','never'),('--cap-drop','ALL'),('--security-opt','no-new-privileges:true'),('--log-driver','none')):
                    self.assertEqual(command[command.index(flag)+1],value)
                self.assertIn('--read-only',command);self.assertIn('--rm',command);self.assertNotIn('--volume',command)
                self.assertEqual(json.loads(data),[row['path'] for row in self.reply(service)['sources']])
                self.assertEqual(calls[-1][0][:3],['docker','container','ls'])

    def test_docker_success_with_corrupt_package_hash_or_forged_response_refuses_and_cleans(self):
        corrupt=self.reply();next(row for row in corrupt['sources'] if row['path']=='package.json')['sha256']='0'*64
        nested=self.reply();next(row for row in nested['sources'] if row['path']=='apps/web/package.json')['sha256']='0'*64
        variants=[b'not-json',json.dumps(corrupt).encode(),json.dumps(nested).encode(),json.dumps(self.reply()|{'extra':True}).encode(),
                  json.dumps(self.reply()|{'formatVersion':True}).encode(),json.dumps(self.reply()|{'sources':list(reversed(self.reply()['sources']))}).encode(),
                  json.dumps(self.reply()).replace('"formatVersion": 1','"formatVersion": 1, "formatVersion": 1').encode()]
        for output in variants:
            with self.subTest(output=output[:40]):
                selected,error,calls=self.verify(output=output)
                self.assertIsNone(selected);self.assertIsInstance(error,SystemExit)
                self.assertEqual(calls[-1][0][:3],['docker','container','ls'])

    def test_alias_move_after_reader_and_command_timeout_both_refuse_with_cleanup(self):
        for options in ({'image_after':OTHER_IMAGE},{'fail_run':True}):
            with self.subTest(options=options):
                selected,error,calls=self.verify(**options)
                self.assertIsNone(selected);self.assertIsInstance(error,SystemExit)
                self.assertEqual(calls[-1][0][:3],['docker','container','ls'])

    def test_postbuild_source_edit_addition_deletion_and_final_alias_drift_refuse(self):
        images={service:IMAGE for service in runtime.INTEGRITY_PROFILES}
        path=self.root/'apps/api/src/route.ts';original=path.read_bytes()
        for mutation in ('edit','delete','add'):
            with self.subTest(mutation=mutation):
                if mutation=='edit':path.write_bytes(original+b' changed')
                elif mutation=='delete':path.unlink()
                else:(self.root/'apps/api/src/new.ts').write_text('new')
                with patch.object(runtime,'integrity_image_id',side_effect=AssertionError('Image query after source drift')),self.assertRaises(SystemExit):
                    runtime.verify_build_snapshot(self.snapshot,images)
                path.write_bytes(original)
                (self.root/'apps/api/src/new.ts').unlink(missing_ok=True)
        with patch.object(runtime,'integrity_image_id',return_value=OTHER_IMAGE),self.assertRaises(SystemExit):
            runtime.verify_build_snapshot(self.snapshot,images)

    def test_cleanup_removes_only_random_label_name_match_and_requires_absence(self):
        token='a'*32;name='gc-image-integrity-'+token;identifier='b'*64;calls=[]
        def command(args,data=b'',timeout=30):
            calls.append(args)
            return (identifier+'\n').encode() if len(calls)==1 else b''
        with patch.object(runtime,'integrity_command',side_effect=command):runtime.integrity_cleanup(name,token)
        self.assertIn('label=org.governance-commons.integrity='+token,calls[0])
        self.assertIn('name=^/'+name+'$',calls[0]);self.assertEqual(calls[1],['docker','rm','-f',identifier]);self.assertEqual(calls[0],calls[2])
        with patch.object(runtime,'integrity_command',return_value=(identifier+'\n').encode()),self.assertRaises(SystemExit):
            runtime.integrity_cleanup(name,token)

    def test_bounded_process_real_output_nonzero_timeout_and_overflow(self):
        self.assertEqual(runtime.integrity_command([sys.executable,'-c','import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'],b'bounded'),b'bounded')
        for program,limit,timeout in (('raise SystemExit(1)',4096,2),('import time;time.sleep(5)',4096,0.05),
                                     ('import sys;sys.stdout.write("x"*8192)',4096,2),('import sys;sys.stderr.write("x"*8192)',4096,2)):
            started=time.monotonic()
            with self.subTest(program=program),patch.object(runtime,'INTEGRITY_MAX_OUTPUT',limit),self.assertRaises(SystemExit):
                runtime.integrity_command([sys.executable,'-c',program],timeout=timeout)
            self.assertLess(time.monotonic()-started,3)

    def test_actual_node_reader_checks_every_package_manifest_and_selected_imports(self):
        node=shutil.which('node')
        self.assertIsNotNone(node,'Node is required for the package reader host check')
        dependencies=Path.cwd()/'node_modules'
        self.assertTrue(dependencies.is_dir(),'Installed repository dependencies are required')
        (self.root/'node_modules').symlink_to(dependencies,target_is_directory=True)
        # Substitute only the image filesystem root. Reader/parse/import logic
        # is executed unchanged; this is not Docker/image qualification.
        program=runtime.API_INTEGRITY_READER.replace("let file='/app';",'let file='+json.dumps(str(self.root))+';')
        names=self.snapshot['profiles']['api']
        result=subprocess.run([node,'--input-type=module','-e',program],cwd=self.root,input=json.dumps(names).encode(),capture_output=True,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(json.loads(result.stdout),self.reply())
        for path,body in (('package.json',b'{'),('apps/web/package.json',b'{'),('packages/domain/package.json',b'{"name":"\xff"}')):
            target=self.root/path;original=target.read_bytes();target.write_bytes(body)
            try:
                failed=subprocess.run([node,'--input-type=module','-e',program],cwd=self.root,input=json.dumps(names).encode(),capture_output=True,timeout=20)
                self.assertNotEqual(failed.returncode,0)
                self.assertEqual(failed.stdout,b'')
                self.assertEqual(failed.stderr,b'IMAGE_INTEGRITY_REJECTED\n')
            finally:target.write_bytes(original)

    def test_corrupt_image_blocks_all_migration_and_startup_after_successful_build(self):
        calls=[]
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(sys,'argv',['dev','up']))
            for name in ('require_bootstrap','require_local','authentication_bootstrap','require_build_disk'):
                stack.enter_context(patch.object(runtime,name))
            stack.enter_context(patch.object(runtime,'doctor',return_value=True))
            stack.enter_context(patch.object(runtime,'run',side_effect=lambda args,**kwargs:calls.append(args)))
            stack.enter_context(patch.object(runtime,'verify_built_image',side_effect=SystemExit('image bytes mismatched')))
            with self.assertRaises(SystemExit):runtime.main()
        self.assertEqual(calls,[runtime.COMPOSE+['config','--quiet'],runtime.COMPOSE+['build','api']])

    def test_changed_sources_after_two_verified_builds_block_all_migration_and_startup(self):
        calls=[]
        def verify(service,snapshot):
            if service=='python-worker':(self.root/'package.json').write_text('{"changed":true}')
            return IMAGE
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(sys,'argv',['dev','up']))
            for name in ('require_bootstrap','require_local','authentication_bootstrap','require_build_disk'):
                stack.enter_context(patch.object(runtime,name))
            stack.enter_context(patch.object(runtime,'doctor',return_value=True))
            stack.enter_context(patch.object(runtime,'run',side_effect=lambda args,**kwargs:calls.append(args)))
            stack.enter_context(patch.object(runtime,'verify_built_image',side_effect=verify))
            with self.assertRaises(SystemExit):runtime.main()
        self.assertEqual(calls,[runtime.COMPOSE+['config','--quiet'],runtime.COMPOSE+['build','api'],runtime.COMPOSE+['build','python-worker']])


if __name__ == '__main__':
    unittest.main()
