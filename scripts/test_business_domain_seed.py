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
        for index in (13, 14, 15, 16, 17, 18, 19, 20, 21, 22):
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


class QualitySeedPreservationTests(unittest.TestCase):
    """Host-only admission/SQL shape tests; native reseeding remains the real gate."""
    def read(self, method, result):
        harness = seed.Harness(Path('/synthetic-unused-attempt'))
        with patch.object(harness, 'query', return_value=json.dumps(result)) as query:
            actual = getattr(harness, method)()
        return actual, query.call_args.args

    def markers(self):
        return [{'tenant_id': tenant, 'actor_id': actor, 'operation': operation,
                 'key': 'harbor-demo', 'request_hash': value,
                 'response': {'dataset': 'harbor-demo', 'version': 1, 'applied': True},
                 'created_at': '2026-11-16T00:00:00+00:00'}
                for (tenant, actor, operation), value in sorted(seed.expected_permission_markers().items())]

    def permissions(self):
        return [{'tenant_id': tenant, 'identity_id': '10000000-0000-4000-8000-' + str(index).zfill(12),
                 'role': role, 'active': True,
                 'permissions': ['catalog:read', 'operator:preserved'] +
                    (['quality:read'] if role in ('consumer', 'auditor') else ['quality:read', 'quality:write', 'quality:execute']) +
                    ([] if role == 'consumer' else ['classification:read'] if role == 'auditor'
                     else ['classification:read', 'classification:write', 'classification:approve']) +
                    (['reference:read'] if role in ('consumer', 'auditor')
                     else ['reference:read', 'reference:write', 'reference:approve'])}
                for index, (role, tenant, _) in enumerate(seed.PERSONA_GRANTS, 1)]

    def snapshot(self):
        return {name: {'rows': 0, 'serialized_bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()}
                for name in (*seed.QUALITY_TABLES, 'audit', 'outbox', 'idempotency')}

    def test_independent_hashes_preserve_legacy_and_new_receipt_contracts(self):
        # Fixed vectors cross-checked with the real TypeScript typeHash codec;
        # changing writer+oracle together cannot silently change these old pins.
        expected = seed.expected_permission_markers()
        self.assertEqual(len(expected), 22)
        self.assertEqual(expected[(seed.HARBOR, seed.ENGINEER, 'bootstrap.domain-permissions.v1')],
                         '7d75f8ff5bdc1f51e4020e4b3323a8dfbdd73c3e8e6cbe270407ba98086e5bdb')
        self.assertEqual(expected[(seed.HARBOR, '10000000-0000-4000-8000-000000000004', 'bootstrap.domain-permissions.v1')],
                         'f48398bc96498f9b3d76e0ae0b4488c9b527a001f7c740012a425d33462c47fe')
        self.assertEqual(expected[(seed.HARBOR, seed.ENGINEER, 'bootstrap.quality-permissions.v1')],
                         '589cb1c2678511630c038bee731bf7f8a6504815ac7b0a6c801b9fdc470b280b')
        self.assertEqual(expected[(seed.HARBOR, seed.CONSUMER, 'bootstrap.quality-permissions.v1')],
                         'db5b0c4a3bedca374e064ac21652abecf0782d28672348793b1bb45e15443239')
        self.assertEqual(expected[(seed.HARBOR, seed.ENGINEER, 'bootstrap.classification-permissions.v1')],
                         'cf56cd849c8de856954f3729fb80c4decbac876b0709332adb69108a9c0ca339')
        self.assertEqual(expected[(seed.HARBOR, '10000000-0000-4000-8000-000000000004', 'bootstrap.classification-permissions.v1')],
                         'cd3140f4e96b5f53ee3ab7ba53f0a37409bcbf3112bea5ad32b6fdd60f3e8140')
        markers = self.markers()
        markers[-1]['response']['applied'] = False  # Refusal receipts are retained, never rewritten.
        actual, (statement, label) = self.read('permission_markers', markers)
        self.assertEqual(actual, markers)
        self.assertEqual(label, 'permission-marker-readback')
        self.assertIn('LIMIT 23', statement)
        self.assertIn("'bootstrap.classification-permissions.v1'", statement)
        self.assertIn('to_jsonb(r)', statement)  # Creation time and every receipt column stay in equality.
        self.assertTrue(statement.startswith('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;'))

    def test_missing_duplicate_transplanted_changed_or_malformed_markers_refuse(self):
        cases = [[], self.markers()[:-1], self.markers() + self.markers()[:1]]
        for field, value in (('tenant_id', seed.SUMMIT), ('actor_id', seed.CONSUMER),
                             ('request_hash', '0' * 64), ('request_hash', []),
                             ('key', 'another-dataset'), ('created_at', ''),
                             ('response', {'dataset': 'harbor-demo', 'version': True, 'applied': True}),
                             ('response', {'dataset': 'harbor-demo', 'version': 1, 'applied': 1}),
                             ('response', {'dataset': 'harbor-demo', 'version': 1, 'applied': True, 'extra': True})):
            changed = self.markers()
            changed[0][field] = value
            cases.append(changed)
        duplicate = self.markers()
        duplicate[-1] = duplicate[0]
        cases.append(duplicate)
        for index, value in enumerate(cases):
            with self.subTest(case=index):
                with self.assertRaises(RuntimeError): self.read('permission_markers', value)

    def test_all_personas_have_exact_quality_grants_without_changing_other_permissions(self):
        expected = self.permissions()
        actual, (statement, _) = self.read('quality_permissions', expected)
        self.assertEqual(actual, expected)
        self.assertEqual(statement.count(' AND identity_id='), 6)
        self.assertNotIn('UPDATE', statement)
        self.assertIn('operator:preserved', actual[0]['permissions'])

    def test_missing_inactive_wrong_tenant_or_widened_quality_authority_refuses(self):
        cases = [self.permissions()[:-1]]
        for index, field, value in ((2, 'permissions', ['quality:read', 'quality:execute']),
                                    (3, 'permissions', ['quality:read', 'quality:write']),
                                    (5, 'permissions', ['quality:read', 'quality:write']),
                                    (2, 'permissions', ['quality:read', 'quality:read']),
                                    (0, 'permissions', ['quality:read', None]),
                                    (4, 'tenant_id', seed.HARBOR), (1, 'active', False)):
            changed = self.permissions()
            changed[index][field] = value
            cases.append(changed)
        for index, value in enumerate(cases):
            with self.subTest(case=index):
                with self.assertRaises(RuntimeError): self.read('quality_permissions', value)

    def test_quality_snapshot_preserves_empty_or_existing_rows_and_all_columns(self):
        expected = self.snapshot()
        expected['quality_rule_versions'] = {'rows': 9, 'serialized_bytes': 8192, 'sha256': 'b' * 64}
        actual, (statement, label) = self.read('quality_snapshot', expected)
        self.assertEqual(actual, expected)
        self.assertEqual(label, 'quality-row-digests')
        tenant = "tenant_id IN ('" + seed.HARBOR + "','" + seed.SUMMIT + "')"
        self.assertEqual(statement.count(tenant), 6)
        for table in seed.QUALITY_TABLES:
            self.assertIn('FROM public.' + table + ' r WHERE ' + tenant, statement)
        self.assertEqual(statement.count('to_jsonb(r)::text payload'), 6)
        self.assertIn("action LIKE 'quality.%'", statement)
        self.assertIn("event_type LIKE 'quality.%'", statement)
        self.assertIn("operation LIKE 'quality.%'", statement)
        self.assertTrue(statement.startswith('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;'))
        for forbidden in ('UPDATE ', 'INSERT ', 'DELETE ', "-'processed_at'", "-'attempts'", 'bootstrap.domain'):
            self.assertNotIn(forbidden, statement)

    def test_quality_snapshot_missing_extra_overflow_or_unhashable_refuses(self):
        cases = [{}, [], self.snapshot() | {'unexpected': self.snapshot()['audit']}]
        for field, value in (('rows', True), ('rows', -1), ('rows', 20001),
                             ('serialized_bytes', 67108865), ('serialized_bytes', -1),
                             ('sha256', None), ('sha256', 'bad')):
            changed = self.snapshot()
            changed['quality_runs'][field] = value
            cases.append(changed)
        for index, value in enumerate(cases):
            with self.subTest(case=index):
                with self.assertRaises(RuntimeError): self.read('quality_snapshot', value)

    def test_revocation_removes_four_actions_only_and_restoration_keeps_original_fields(self):
        engineer = self.permissions()[-1] | {'permissions': ['catalog:read', 'domains:write', 'quality:read', 'quality:execute', 'classification:read', 'classification:write', 'classification:approve', 'reference:read', 'reference:write', 'reference:approve', 'custom:retained']}
        original = copy.deepcopy(engineer)
        revoked = seed.revoked_engineer(engineer)
        self.assertEqual(engineer, original)
        self.assertEqual(revoked['permissions'], ['catalog:read', 'quality:read', 'classification:read', 'classification:write', 'reference:read', 'reference:write', 'custom:retained'])
        harness = seed.Harness(Path('/synthetic-unused-attempt'))
        consumer = self.permissions()[2]
        with patch.object(harness, 'query') as query:
            harness.mutate([consumer, engineer], revoked)
        mutation = query.call_args.args[0]
        restoration = harness.restore_sql([consumer, engineer])
        self.assertIn('SET permissions=' + seed.json_sql(revoked['permissions']), mutation)
        self.assertIn('SET permissions=' + seed.json_sql(engineer['permissions']), restoration)
        self.assertIn('jsonb_populate_record(NULL::memberships,' + seed.json_sql(consumer), restoration)
        for statement in (mutation, restoration):
            self.assertLess(statement.index('pg_advisory_xact_lock'), statement.index('FROM identities'))
            self.assertLess(statement.index('FROM identities'), statement.index('FROM memberships'))
            self.assertIn('ORDER BY id FOR UPDATE', statement)
            self.assertIn('ORDER BY identity_id FOR UPDATE', statement)
            # Shared recovery still changes only engineer/consumer; an owner
            # may have durable approval/classification references in this core.
            self.assertNotIn('10000000-0000-4000-8000-000000000002', statement)
        for missing in ('domains:write', 'quality:execute', 'classification:approve', 'reference:approve'):
            with self.assertRaises(RuntimeError):
                seed.revoked_engineer(engineer | {'permissions': [v for v in engineer['permissions'] if v != missing]})

    def test_exact_classification_grants_preserve_other_permissions_and_exclude_consumer(self):
        rows = self.permissions()
        original = copy.deepcopy(rows)
        self.assertEqual(seed.verify_classification_permissions(rows), original)
        self.assertEqual(rows, original)
        self.assertFalse(any(p.startswith('classification:') for p in rows[2]['permissions']))
        self.assertEqual([p for p in rows[3]['permissions'] if p.startswith('classification:')], ['classification:read'])
        self.assertIn('operator:preserved', rows[0]['permissions'])

    def test_missing_revoked_widened_duplicate_or_transplanted_classification_grants_refuse(self):
        cases = [[], self.permissions()[:-1]]
        for index, field, value in (
                (2, 'permissions', ['catalog:read', 'classification:read']),
                (3, 'permissions', ['classification:read', 'classification:approve']),
                (5, 'permissions', ['classification:read', 'classification:write']),
                (0, 'permissions', ['classification:read', 'classification:write', 'classification:approve', 'classification:read']),
                (0, 'permissions', ['classification:read', 'classification:write', 'classification:approve', 'classification:unknown']),
                (0, 'permissions', ['classification:read', None]),
                (4, 'tenant_id', seed.HARBOR), (1, 'active', False), (1, 'role', 'steward')):
            changed = self.permissions()
            changed[index][field] = value
            cases.append(changed)
        for index, rows in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(RuntimeError):
                seed.verify_classification_permissions(rows)

    def test_exact_five_classification_markers_have_no_consumer_or_extra_receipt(self):
        expected = seed.expected_permission_markers()
        classification = {key: value for key, value in expected.items() if key[2] == 'bootstrap.classification-permissions.v1'}
        self.assertEqual(len(classification), 5)
        self.assertNotIn((seed.HARBOR, seed.CONSUMER, 'bootstrap.classification-permissions.v1'), classification)
        # Remove classification while retaining all other families, including
        # the original eleven receipts, then append a forged consumer receipt.
        old_only = [row for row in self.markers() if row['operation'] != 'bootstrap.classification-permissions.v1']
        self.assertEqual(len(old_only), 17)
        self.assertEqual(len([row for row in old_only if row['operation'] != 'bootstrap.reference-permissions.v1']), 11)
        forged = copy.deepcopy(next(row for row in self.markers() if row['operation'] == 'bootstrap.classification-permissions.v1'))
        forged['actor_id'] = seed.CONSUMER
        for rows in (old_only, self.markers() + [forged]):
            with self.subTest(receipts=len(rows)), self.assertRaises(RuntimeError):
                self.read('permission_markers', rows)


    def test_six_reference_receipts_match_fixed_vectors_and_old_sixteen_remain_required(self):
        expected = seed.expected_permission_markers()
        pins = [
            '9ff26a3c1e1144781a2438042f5fa3c697b97c7f22a286725a57a645a433d256',
            '7841c47c3fcb9f50da4748870dcce734bfa2bb1e1f44b65f4cb7c19dff342b90',
            'ebbb4edee81c37943669e571edbad206eefae4c7fd768ddba50cc2c470615a9b',
            '820093bdeba363982098e0b0064551c0116cd9dcfe6a591398a00907f6d97026',
            '44e28c3481b65726afdca5a4ff50c986393f31ecb613142d3d66e8dc721827e6',
            '16a363bec82f47297ed13e90b83d5eb09d081433a237436b3a7922ab0e1b837d']
        for index, ((_, tenant, _), pin) in enumerate(zip(seed.PERSONA_GRANTS, pins), 1):
            self.assertEqual(expected[(tenant, '10000000-0000-4000-8000-' + str(index).zfill(12),
                                       'bootstrap.reference-permissions.v1')], pin)
        old = [row for row in self.markers() if row['operation'] != 'bootstrap.reference-permissions.v1']
        self.assertEqual(len(old), 16)
        reference = [row for row in self.markers() if row['operation'] == 'bootstrap.reference-permissions.v1']
        self.assertEqual(len(reference), 6)
        for rows in (old, reference, self.markers() + reference[:1]):
            with self.subTest(receipts=len(rows)), self.assertRaises(RuntimeError):
                self.read('permission_markers', rows)
        _, (statement, _) = self.read('permission_markers', self.markers())
        self.assertIn("'bootstrap.reference-permissions.v1'", statement)

    def test_exact_reference_grants_keep_read_only_personas_and_other_authority(self):
        rows = self.permissions()
        original = copy.deepcopy(rows)
        self.assertEqual(seed.verify_reference_permissions(rows), original)
        self.assertEqual(rows, original)
        for index in (2, 3):
            self.assertEqual([p for p in rows[index]['permissions'] if p.startswith('reference:')], ['reference:read'])
        self.assertIn('operator:preserved', rows[0]['permissions'])

    def test_missing_revoked_widened_duplicate_or_transplanted_reference_grants_refuse(self):
        cases = [[], self.permissions()[:-1]]
        for index, field, value in (
                (2, 'permissions', []), (2, 'permissions', ['reference:read', 'reference:write']),
                (3, 'permissions', ['reference:read', 'reference:approve']),
                (5, 'permissions', ['reference:read', 'reference:write']),
                (0, 'permissions', ['reference:read', 'reference:write', 'reference:approve', 'reference:read']),
                (0, 'permissions', ['reference:read', 'reference:write', 'reference:approve', 'reference:unknown']),
                (0, 'permissions', ['reference:read', None]),
                (4, 'tenant_id', seed.HARBOR), (1, 'active', False), (1, 'role', 'steward')):
            changed = self.permissions()
            changed[index][field] = value
            cases.append(changed)
        for index, rows in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(RuntimeError):
                seed.verify_reference_permissions(rows)

    def reference_snapshot(self):
        return {name: {'rows': 0, 'serialized_bytes': 0, 'sha256': hashlib.sha256(b'').hexdigest()}
                for name in (*seed.REFERENCE_TABLES, 'audit', 'outbox', 'idempotency')}

    def test_reference_snapshot_includes_full_existing_versions_and_receipts_in_both_tenants(self):
        expected = self.reference_snapshot()
        expected['reference_releases'] = {'rows': 9, 'serialized_bytes': 8192, 'sha256': 'b' * 64}
        actual, (statement, label) = self.read('reference_snapshot', expected)
        self.assertEqual(actual, expected)
        self.assertEqual(label, 'reference-row-digests')
        tenant = "tenant_id IN ('" + seed.HARBOR + "','" + seed.SUMMIT + "')"
        self.assertEqual(statement.count(tenant), 6)
        for table in seed.REFERENCE_TABLES:
            self.assertIn('FROM public.' + table + ' r WHERE ' + tenant, statement)
        self.assertEqual(statement.count('to_jsonb(r)::text payload'), 6)
        for column in ('action', 'event_type', 'operation'):
            self.assertIn(column + " LIKE 'reference.%'", statement)
        self.assertTrue(statement.startswith('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;'))
        for forbidden in ('UPDATE ', 'INSERT ', 'DELETE ', "-'processed_at'", "-'attempts'", 'bootstrap.reference'):
            self.assertNotIn(forbidden, statement)

    def test_reference_snapshot_missing_extra_overflow_or_unhashable_refuses(self):
        cases = [{}, [], self.reference_snapshot() | {'unexpected': self.reference_snapshot()['audit']}]
        for field, value in (('rows', True), ('rows', -1), ('rows', 20001),
                             ('serialized_bytes', 67108865), ('serialized_bytes', -1),
                             ('sha256', None), ('sha256', 'bad')):
            changed = self.reference_snapshot()
            changed['reference_values'][field] = value
            cases.append(changed)
        for index, value in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(RuntimeError):
                self.read('reference_snapshot', value)


if __name__ == '__main__':
    unittest.main()
