# SPDX-License-Identifier: Apache-2.0
"""Real local PostgreSQL tests; skipped explicitly outside the configured core worker."""
import json
import os
import unittest
import psycopg
from governance_workers.postgresql import scan, ScanFailure

@unittest.skipUnless(os.environ.get("SOURCE_SECRETS_FILE"), "requires real core source and site-local secret file")
class RealPostgresTest(unittest.TestCase):
    def setUp(self):
        with open(os.environ["SOURCE_SECRETS_FILE"], encoding="utf-8") as handle:
            self.secret = json.load(handle)["demo-postgres"]
        self.source = {key: self.secret[key] for key in ("host", "port", "database", "schema")}
        self.tenant = self.secret["tenantIds"][0]

    def test_actual_metadata_repeatable_identity_no_source_values(self):
        first = scan(self.source, self.secret, self.tenant)
        second = scan(self.source, self.secret, self.tenant)
        self.assertTrue(first["complete"])
        self.assertGreaterEqual(len(first["records"]), 30)
        self.assertEqual([r["externalId"] for r in first["records"]], [r["externalId"] for r in second["records"]])
        self.assertEqual(first["permissionFingerprint"], second["permissionFingerprint"])
        self.assertEqual({r["type"] for r in first["records"]}, {"schema", "table", "view", "column"})
        self.assertNotIn("person-1@example.invalid", json.dumps(first))
        self.assertNotIn(self.secret["password"], json.dumps(first))
        column = next(r for r in first["records"] if r["name"] == "customer_id" and r["type"] == "column")
        self.assertEqual(column["metadata"]["dataType"], "integer")
        self.assertIn("ordinalPosition", column["metadata"])

    def test_source_role_cannot_write(self):
        with psycopg.connect(host=self.secret["host"], port=self.secret["port"], dbname=self.secret["database"],
                user=self.secret["username"], password=self.secret["password"], connect_timeout=5) as conn:
            self.assertEqual(conn.execute("SHOW default_transaction_read_only").fetchone()[0], "on")
            with self.assertRaises(psycopg.Error):
                conn.execute("UPDATE customers SET display_name=display_name WHERE false")

    def test_other_tenant_cannot_use_source_secret(self):
        with self.assertRaisesRegex(ScanFailure, "SOURCE_SCOPE_DENIED"):
            scan(self.source, self.secret, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
