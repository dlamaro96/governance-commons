#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the actual bootstrap only in fresh temporary workspaces, never shared runtime."""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TENANT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
CUSTOM = {'connectorId':'unity-catalog','tenantIds':[TENANT],
          'workspaceUrl':'https://adb-123.1.azuredatabricks.net','catalog':'harbor','schema':'commerce',
          'clientId':'synthetic-client','clientSecret':'synthetic-preserved-custom-secret',
          'principalId':'synthetic-reader','operatorNote':{'retain':['exact','values']}}


class BootstrapPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='gc-bootstrap-preservation-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'scripts').mkdir()
        (self.root/'deploy/compose').mkdir(parents=True)
        shutil.copyfile(ROOT/'scripts/runtime-bootstrap.py',self.root/'scripts/runtime-bootstrap.py')
        for filename in ('source-fixture.sql','reference-quality-fixture.sql'):
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


if __name__=='__main__': unittest.main()
