#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Pure current-schema admission tests; no Docker, database or seed invocation."""
import copy
import hashlib
import json
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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
        for index in (13, 14, 15, 16):
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


class GlossaryDefinitionReadbackTests(unittest.TestCase):
    """Closed SQL projection and admission controls only; no database execution."""
    def snapshot(self):
        return {name: {'rows': rows, 'serialized_bytes': 80 * rows, 'sha256': 'a' * 64}
                for name, rows in (
                    ('governance_models', 2), ('governance_model_versions', 9),
                    ('asset_type_versions', 9), ('asset_type_dependencies', 14),
                    ('workflow_definitions', 2), ('workflow_definition_versions', 7))}

    def read(self, result):
        harness = seed.Harness(Path('/synthetic-unused-attempt'))
        with patch.object(harness, 'query', return_value=json.dumps(result)) as query:
            actual = harness.glossary_definition_snapshot()
        return actual, query.call_args

    def test_existing_operator_versions_and_dependencies_are_preserved_as_read(self):
        expected = self.snapshot()
        actual, _ = self.read(expected)
        self.assertEqual(actual, expected)
        # Neither a v1 byte template nor zero-dependency starter assumptions are
        # allowed to replace legitimate existing operator definitions.
        self.assertEqual(actual['asset_type_versions']['rows'], 9)
        self.assertEqual(actual['asset_type_dependencies']['rows'], 14)

    def test_query_is_read_only_and_every_family_has_exact_tenant_and_key_scope(self):
        _, call = self.read(self.snapshot())
        statement, label = call.args
        self.assertEqual(label, 'glossary-definition-row-digests')
        self.assertTrue(statement.startswith('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SELECT '))
        self.assertTrue(statement.endswith('; COMMIT;'))
        scope = "tenant_id IN ('" + seed.HARBOR + "','" + seed.SUMMIT + "')"
        families = (('governance_models', 'id', 'business_term'),
                    ('governance_model_versions', 'model_id', 'business_term'),
                    ('asset_type_versions', 'model_id', 'business_term'),
                    ('asset_type_dependencies', 'model_id', 'business_term'),
                    ('workflow_definitions', 'id', 'glossary_review'),
                    ('workflow_definition_versions', 'workflow_id', 'glossary_review'))
        self.assertEqual(statement.count(scope), len(families))
        for table, key, value in families:
            self.assertIn('FROM public.' + table + ' r WHERE ' + scope + ' AND ' + key + "='" + value + "'", statement)
        for forbidden in ('UPDATE ', 'INSERT ', 'DELETE ', 'public.audit ', 'public.outbox ', 'public.approval_requests '):
            self.assertNotIn(forbidden, statement)

    def test_missing_heads_versions_overflow_and_invalid_digest_fail_closed(self):
        cases = []
        for table, field, value in (
                ('governance_models', 'rows', 1), ('workflow_definitions', 'rows', 3),
                ('asset_type_versions', 'rows', 1), ('workflow_definition_versions', 'rows', 0),
                ('asset_type_dependencies', 'rows', 20001), ('asset_type_dependencies', 'rows', True),
                ('governance_model_versions', 'serialized_bytes', 67108865),
                ('workflow_definition_versions', 'sha256', None),
                ('workflow_definition_versions', 'sha256', 'not-a-digest')):
            changed = copy.deepcopy(self.snapshot())
            changed[table][field] = value
            cases.append(changed)
        absent = self.snapshot()
        del absent['asset_type_dependencies']
        cases.extend([absent, [], {}])
        for index, value in enumerate(cases):
            with self.subTest(case=index):
                with self.assertRaises(RuntimeError):
                    self.read(value)


if __name__ == '__main__':
    unittest.main()
