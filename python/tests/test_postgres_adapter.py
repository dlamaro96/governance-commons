# SPDX-License-Identifier: Apache-2.0
"""Adapter integration with real policy/CA files; database I/O is a test double.

These tests do not qualify a live PostgreSQL server or TLS handshake.
"""
import ipaddress
import json
import os
from pathlib import Path
import signal
import tempfile
import time
import unittest
from unittest.mock import patch

import psycopg
from governance_workers import postgresql as pg, postgres_targets as targets
from test_postgres_targets import document, source, secret


class Rows:
    def __init__(self, rows=()):
        self.rows = list(rows)

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class CatalogConnection:
    def __init__(self, params, *, incomplete=False, privileged=False, alarm=False):
        self.params = params
        self.incomplete, self.privileged, self.alarm = incomplete, privileged, alarm
        self.closed = False
        self.close_had_ca = None
        self.queries = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        if not self.closed:
            self.close_had_ca = "sslrootcert" not in self.params or Path(self.params["sslrootcert"]).is_file()
            self.closed = True

    def execute(self, query, params=None):
        self.queries.append((query, params))
        if self.alarm:
            signal.raise_signal(signal.SIGALRM)
        if query.startswith("SET TRANSACTION"):
            return Rows()
        if "current_user AS role" in query:
            return Rows([{"role": "metadata_reader", "version": "17.0 synthetic", "db_oid": "23"}])
        if "rolsuper" in query:
            return Rows([{"role_oid": "42", "rolsuper": self.privileged, "rolbypassrls": False}])
        if "pg_namespace WHERE" in query:
            return Rows([{"oid": "18", "nspname": params[0], "allowed": True}])
        if "FROM pg_class c JOIN" in query:
            return Rows([{"oid": "65", "relname": "orders", "relkind": "r", "allowed": not self.incomplete,
                          "description": "Synthetic table", "description_truncated": False}])
        if "FROM pg_attribute a" in query:
            return Rows([{"attnum": 1, "attname": "order_id", "data_type": "integer", "attnotnull": True,
                          "description": None, "description_truncated": False, "primary_key": True}])
        raise AssertionError("Unexpected metadata SQL")


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name).resolve()
        self.path = self.directory / "targets.json"
        self.path.write_text(json.dumps(document()))
        self.path.chmod(0o600)
        self.env = patch.dict(os.environ, {"POSTGRES_TARGETS_FILE": str(self.path)}, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.dns = patch.object(targets, "_resolve", return_value=(ipaddress.ip_address("10.8.0.4"),))
        self.resolve = self.dns.start()
        self.addCleanup(self.dns.stop)
        self.connections = []

    def connect(self, **params):
        connection = CatalogConnection(params)
        self.connections.append(connection)
        return connection

    def failure(self, code, call):
        with self.assertRaises(pg.ScanFailure) as error:
            call()
        self.assertEqual(error.exception.code, code)
        return error.exception

    def test_generic_policy_reaches_pinned_readonly_metadata_and_ca_outlives_close(self):
        with patch.object(pg.psycopg, "connect", side_effect=self.connect):
            result = pg.scan(source(), secret(), "tenant-one")
        self.assertTrue(result["complete"])
        self.assertEqual([record["externalId"] for record in result["records"]],
                         ["pg:23:schema:18", "pg:23:relation:65", "pg:23:relation:65:column:1"])
        self.assertNotIn(secret()["password"], json.dumps(result))
        self.assertEqual(len(self.connections), 1)
        conn = self.connections[0]
        self.assertEqual(conn.params["host"], source()["host"])
        self.assertEqual(conn.params["hostaddr"], "10.8.0.4")
        self.assertEqual(conn.params["sslmode"], "verify-full")
        self.assertEqual(conn.queries[0][0], "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        self.assertTrue(conn.closed)
        self.assertTrue(conn.close_had_ca)
        self.assertFalse(Path(conn.params["sslrootcert"]).parent.exists())

    def test_each_scan_reloads_policy_and_revocation_cannot_fall_back(self):
        with patch.object(pg.psycopg, "connect", side_effect=self.connect) as connect:
            pg.scan(source(), secret(), "tenant-one")
            revoked = document()
            revoked["targets"]["warehouse"]["tenantIds"] = ["tenant-two"]
            replacement = self.directory / "replacement"
            replacement.write_text(json.dumps(revoked))
            replacement.chmod(0o600)
            replacement.replace(self.path)
            self.failure("SOURCE_SCOPE_DENIED", lambda: pg.scan(source(), secret(), "tenant-one"))
            self.assertEqual(connect.call_count, 1)

    def test_missing_relative_corrupt_or_unsafe_policy_refuses_before_connect(self):
        with patch.object(pg.psycopg, "connect") as connect:
            for value in (None, "", "relative.json", str(self.directory / "missing")):
                if value is None:
                    os.environ.pop("POSTGRES_TARGETS_FILE", None)
                else:
                    os.environ["POSTGRES_TARGETS_FILE"] = value
                self.failure("SOURCE_TARGET_POLICY_UNAVAILABLE", lambda: pg.scan(source(), secret(), "tenant-one"))
            os.environ["POSTGRES_TARGETS_FILE"] = str(self.path)
            self.path.write_text("{}")
            self.failure("SOURCE_TARGET_POLICY_INVALID", lambda: pg.scan(source(), secret(), "tenant-one"))
            self.path.chmod(0o644)
            self.failure("SOURCE_TARGET_POLICY_UNAVAILABLE", lambda: pg.scan(source(), secret(), "tenant-one"))
            connect.assert_not_called()

    def test_exact_demo_with_and_without_conformance_ref_remains_explicit(self):
        legacy_source = {"host": "source-postgres", "port": 5432, "database": "harbor", "schema": "public"}
        legacy_secret = dict(legacy_source, tenantIds=["tenant-one"], username="harbor_reader", password="synthetic")
        os.environ.pop("POSTGRES_TARGETS_FILE")
        with patch.object(pg.psycopg, "connect", side_effect=self.connect):
            for ref in (None, "demo-postgres"):
                actual = dict(legacy_source)
                if ref is not None:
                    actual["secretRef"] = ref
                result = pg.scan(actual, legacy_secret, "tenant-one")
                self.assertTrue(result["complete"])
        self.assertEqual(len(self.connections), 2)
        for conn in self.connections:
            self.assertEqual(conn.params["sslmode"], "disable")
            self.assertEqual(conn.params["hostaddr"], "10.8.0.4")
            self.assertEqual(conn.params["user"], "harbor_reader")
            self.assertTrue(conn.closed)

    def test_demo_exception_cannot_expand_target_ref_role_or_tenant(self):
        src = {"host": "source-postgres", "port": 5432, "database": "harbor", "schema": "public", "secretRef": "demo-postgres"}
        sec = {k: v for k, v in src.items() if k != "secretRef"}
        sec.update(tenantIds=["tenant-one"], username="harbor_reader", password="synthetic")
        os.environ.pop("POSTGRES_TARGETS_FILE")
        with patch.object(pg.psycopg, "connect") as connect:
            for key, value in (("host", "other.test"), ("port", 5433), ("database", "other"), ("schema", "other")):
                self.failure("SOURCE_TARGET_POLICY_UNAVAILABLE", lambda: pg.scan(dict(src, **{key: value}), dict(sec, **{key: value}), "tenant-one"))
            self.failure("SOURCE_TARGET_POLICY_UNAVAILABLE", lambda: pg.scan(dict(src, secretRef="another"), sec, "tenant-one"))
            self.failure("SOURCE_DESTINATION_DENIED", lambda: pg.scan(src, dict(sec, secretRef="another"), "tenant-one"))
            self.failure("SOURCE_TARGET_DENIED", lambda: pg.scan(src, dict(sec, username="source_admin"), "tenant-one"))
            self.failure("SOURCE_SCOPE_DENIED", lambda: pg.scan(src, sec, "tenant-two"))
            self.failure("SOURCE_SCOPE_DENIED", lambda: pg.scan(src, dict(sec, tenantIds="tenant-one"), "tenant-one"))
            connect.assert_not_called()

    def test_demo_dns_is_bounded_and_cannot_resolve_public_or_metadata(self):
        src = {"host": "source-postgres", "port": 5432, "database": "harbor", "schema": "public"}
        sec = dict(src, tenantIds=["tenant-one"], username="harbor_reader", password="synthetic")
        with patch.object(pg.psycopg, "connect") as connect:
            for address in ("8.8.8.8", "127.0.0.1", "169.254.169.254", "fd20:ce::254"):
                self.resolve.return_value = (ipaddress.ip_address(address),)
                self.failure("SOURCE_DESTINATION_DENIED", lambda: pg.scan(src, sec, "tenant-one"))
            connect.assert_not_called()

    def test_failed_scope_or_privilege_never_returns_complete_and_closes_connection(self):
        for option, code in (("incomplete", "SOURCE_SCOPE_INCOMPLETE"), ("privileged", "SOURCE_PRIVILEGE_TOO_BROAD")):
            def connect(**params):
                conn = CatalogConnection(params, **{option: True})
                self.connections.append(conn)
                return conn
            with patch.object(pg.psycopg, "connect", side_effect=connect):
                self.failure(code, lambda: pg.scan(source(), secret(), "tenant-one"))
            self.assertTrue(self.connections[-1].closed)
            self.assertTrue(self.connections[-1].close_had_ca)
            self.assertFalse(Path(self.connections[-1].params["sslrootcert"]).parent.exists())

    def test_connection_driver_failure_is_safe_and_ca_is_removed(self):
        directories = []

        def connect(**params):
            directories.append(Path(params["sslrootcert"]).parent)
            raise psycopg.OperationalError("synthetic private server detail and password")

        with patch.object(pg.psycopg, "connect", side_effect=connect):
            error = self.failure("SOURCE_DATABASE_ERROR", lambda: pg.scan(source(), secret(), "tenant-one"))
        self.assertIsNone(error.__cause__)
        self.assertTrue(error.__suppress_context__)
        self.assertEqual(str(error), "SOURCE_DATABASE_ERROR")
        self.assertFalse(directories[0].exists())

    def test_original_deadline_includes_policy_loading(self):
        before = time.monotonic()
        with patch.object(pg, "MAX_SECONDS", .05), patch.object(targets, "load_policy", side_effect=lambda _: time.sleep(.5)), patch.object(pg.psycopg, "connect") as connect:
            self.failure("SOURCE_DEADLINE_EXCEEDED", lambda: pg.scan(source(), secret(), "tenant-one"))
            connect.assert_not_called()
        self.assertLess(time.monotonic() - before, .3)

    def test_pending_connect_alarm_closes_registered_connection_before_ca(self):
        def connect(**params):
            self.assertGreater(params["connect_timeout"], 1)
            self.assertLessEqual(params["connect_timeout"], 5)
            self.assertIn(signal.SIGALRM, signal.pthread_sigmask(signal.SIG_BLOCK, set()))
            conn = self.connect(**params)
            signal.raise_signal(signal.SIGALRM)
            return conn

        with patch.object(pg.psycopg, "connect", side_effect=connect):
            self.failure("SOURCE_DEADLINE_EXCEEDED", lambda: pg.scan(source(), secret(), "tenant-one"))
        conn = self.connections[0]
        self.assertTrue(conn.closed)
        self.assertTrue(conn.close_had_ca)
        self.assertEqual(conn.queries, [])
        self.assertFalse(Path(conn.params["sslrootcert"]).parent.exists())

    def test_query_alarm_closes_connection_before_ca_without_success(self):
        def connect(**params):
            conn = CatalogConnection(params, alarm=True)
            self.connections.append(conn)
            return conn

        with patch.object(pg.psycopg, "connect", side_effect=connect):
            self.failure("SOURCE_DEADLINE_EXCEEDED", lambda: pg.scan(source(), secret(), "tenant-one"))
        conn = self.connections[0]
        self.assertTrue(conn.closed)
        self.assertTrue(conn.close_had_ca)
        self.assertFalse(Path(conn.params["sslrootcert"]).parent.exists())
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0, 0))


if __name__ == "__main__":
    unittest.main()
