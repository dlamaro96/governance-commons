#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host-side generation checks; native catalog/refusal proof is in the upgrade gate."""
import hashlib
from pathlib import Path
import re
import unittest
from unittest.mock import patch

import authentication_roles as roles

ROOT = Path(__file__).resolve().parents[1]


class AuthenticationRoleTests(unittest.TestCase):
    def test_bridge_shape_matches_the_immutable_migration_and_its_checksum(self):
        raw = (ROOT / 'packages/db/migrations/013_authority_foundation.sql').read_bytes()
        declaration = re.search(r'CREATE TYPE gc_authn\.foundation_session AS\(([^;]+)\);', raw.decode()).group(1)
        aliases = {'integer': 'int4', 'bigint': 'int8'}
        fields = tuple((name, aliases.get(kind, kind)) for name, kind in (part.split() for part in declaration.split(',')))
        self.assertEqual(len(fields), 13)
        self.assertEqual(roles.FOUNDATION_FIELDS, fields)
        query = roles.prepare_sql('gc_owner', 'governance')
        self.assertIn(hashlib.sha256(raw).hexdigest(), query)
        self.assertIn("m.name='013_authority_foundation.sql'", query)
        self.assertIn("t.typname='foundation_session'", query)
        self.assertIn("p.proname='foundation_session_v1'", query)

    def test_missing_source_refuses_before_emitting_deployment_sql(self):
        with patch.object(Path, 'read_bytes', side_effect=FileNotFoundError):
            with self.assertRaises(FileNotFoundError):
                roles.prepare_sql('gc_owner', 'governance')

    def test_changed_migration_bytes_cannot_reuse_the_recorded_pin(self):
        original = roles.prepare_sql('gc_owner', 'governance')
        replacement = b'-- deliberately different synthetic migration bytes\n'
        with patch.object(Path, 'read_bytes', return_value=replacement):
            changed = roles.prepare_sql('gc_owner', 'governance')
        self.assertNotEqual(original, changed)
        self.assertIn(hashlib.sha256(replacement).hexdigest(), changed)

    def test_only_proven_catalog_oids_are_exempted_and_grants_follow_validation(self):
        query = roles.prepare_sql('gc_owner', 'governance')
        self.assertTrue(query.startswith('BEGIN;\n'))
        self.assertTrue(query.endswith('COMMIT;\n'))
        self.assertIn('foundation_type oid; foundation_array oid; foundation_relation oid;', query)
        self.assertIn('oid IS DISTINCT FROM foundation_relation', query)
        self.assertIn('oid IS DISTINCT FROM foundation_type AND oid IS DISTINCT FROM foundation_array', query)
        self.assertIn('a.typelem=t.oid AND a.typrelid=0', query)
        self.assertIn('x.attisdropped OR x.attnotnull OR x.atttypmod<>-1', query)
        self.assertLess(query.rindex("RAISE EXCEPTION 'AUTHN_DEFINER_OWNERSHIP_REJECTED'"), query.index('GRANT gc_authn_definer'))
        self.assertIn('WITH ADMIN FALSE, INHERIT FALSE, SET TRUE', query)
        self.assertNotIn('ALTER ROLE', query)

    def test_identifiers_remain_quoted_and_hostile_delimiters_fail_closed(self):
        for bad in ('', 'x' * 64, 'é' * 32, 'a\x00b', 'a\nb', 'a\x7fb', '$authn_deployment$'):
            with self.subTest(bad=repr(bad)), self.assertRaises(ValueError):
                roles.prepare_sql(bad, 'governance')
        for reserved in ('postgres', 'gc_app', 'gc_authn_definer'):
            with self.subTest(reserved=reserved), self.assertRaises(ValueError):
                roles.prepare_sql(reserved, 'governance')
        query = roles.prepare_sql('migration"owner\'quoted', 'db"quoted')
        self.assertIn('TO "migration""owner\'quoted" WITH ADMIN FALSE', query)
        self.assertIn("WHERE rolname='migration\"owner''quoted')", query)

    def test_finish_keeps_commit_before_assertion_and_exact_membership_cleanup(self):
        query = roles.finish_sql('gc_owner')
        cleanup, assertions = query.split('-- Cleanup commits before assertions,', 1)
        self.assertIn('AND a.set_option AND NOT a.inherit_option AND NOT a.admin_option', cleanup)
        self.assertIn('(NOT a.set_option OR a.inherit_option OR a.admin_option)', cleanup)
        self.assertIn('REVOKE gc_authn_definer FROM "gc_owner"', cleanup)
        self.assertIn('AUTHN_DEFINER_FINAL_STATE_REJECTED', assertions)
        self.assertNotIn('BEGIN;', query)


if __name__ == '__main__':
    unittest.main()
