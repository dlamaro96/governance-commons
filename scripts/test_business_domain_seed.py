#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Pure current-schema admission tests; no Docker, database or seed invocation."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('business_domain_seed', ROOT / 'scripts/runtime-test-business-domain-seed.py')
seed = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(seed)


class CurrentSchemaAdmissionTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='gc-seed-schema-')
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)

    def migrations(self, count):
        expected = []
        for index in range(1, count + 1):
            name = '012_authentication_foundation.sql' if index == 12 else f'{index:03d}_synthetic.sql'
            body = f'-- Synthetic migration {index}\n'.encode()
            (self.directory / name).write_bytes(body)
            expected.append({'name': name, 'checksum': hashlib.sha256(body).hexdigest()})
        return expected

    def test_exact_minimum_and_later_schema_bind_every_file(self):
        expected = self.migrations(12)
        self.assertEqual(seed.migration_inventory(self.directory), expected)
        for index in (13, 14, 15):
            name, body = f'{index:03d}_synthetic.sql', f'-- Later {index}\n'.encode()
            (self.directory / name).write_bytes(body)
            expected.append({'name': name, 'checksum': hashlib.sha256(body).hexdigest()})
            actual = seed.migration_inventory(self.directory)
            self.assertEqual(actual, expected)
            seed.verify_applied_migrations(actual, expected)

    def test_short_missing_duplicate_and_malformed_sequences_refuse(self):
        self.migrations(11)
        with self.assertRaises(RuntimeError): seed.migration_inventory(self.directory)
        self.migrations(14)
        missing = self.directory / '005_synthetic.sql'
        missing.unlink()
        with self.assertRaises(RuntimeError): seed.migration_inventory(self.directory)
        missing.write_text('-- Restored synthetic fixture\n')
        duplicate = self.directory / '014_duplicate.sql'
        duplicate.write_text('-- Duplicate ordinal\n')
        with self.assertRaises(RuntimeError): seed.migration_inventory(self.directory)
        duplicate.unlink()
        (self.directory / 'unexpected.sql').write_text('-- Invalid filename\n')
        with self.assertRaises(RuntimeError): seed.migration_inventory(self.directory)

    def test_authentication_foundation_is_required(self):
        self.migrations(14)
        (self.directory / '012_authentication_foundation.sql').rename(self.directory / '012_other.sql')
        with self.assertRaises(RuntimeError): seed.migration_inventory(self.directory)

    def test_applied_missing_extra_renamed_reordered_or_changed_checksum_refuses(self):
        expected = self.migrations(14)
        changed = [dict(row) for row in expected]
        changed[3]['checksum'] = '0' * 64
        renamed = [dict(row) for row in expected]
        renamed[3]['name'] = '004_other.sql'
        for applied in (expected[:-1], expected + [expected[-1]], expected[::-1], changed, renamed):
            with self.subTest(applied=applied):
                with self.assertRaises(RuntimeError): seed.verify_applied_migrations(applied, expected)

    def test_changed_file_bytes_cannot_match_previous_ledger(self):
        ledger = self.migrations(14)
        (self.directory / ledger[0]['name']).write_bytes(b'-- Synthetic altered predecessor\n')
        with self.assertRaises(RuntimeError):
            seed.verify_applied_migrations(ledger, seed.migration_inventory(self.directory))

    def test_checkout_inventory_includes_actual_current_migrations(self):
        directory = ROOT / 'packages/db/migrations'
        expected = [{'name': path.name, 'checksum': hashlib.sha256(path.read_bytes()).hexdigest()}
                    for path in sorted(directory.glob('*.sql'))]
        self.assertGreaterEqual(len(expected), 12)
        self.assertEqual(seed.migration_inventory(directory), expected)


if __name__ == '__main__':
    unittest.main()
