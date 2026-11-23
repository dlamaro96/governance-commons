# SPDX-License-Identifier: Apache-2.0
"""Catalog-shaped fixtures; host tests do not claim live PostgreSQL execution."""
from contextlib import contextmanager
import json
import time
import unittest
from unittest.mock import patch

import psycopg
from governance_workers import postgresql as pg, postgres_lineage as lineage
from test_postgres_adapter import CatalogConnection, Rows


def relation(oid, kind="r"):
    return {"oid": str(oid), "relkind": kind}


def rule(view, rewrite):
    return {"view_oid": str(view), "rewrite_oid": str(rewrite)}


def witness(rewrite, target, number=0, *, dependency="n", object_kind="relation", kind="r", scoped=True):
    return {"rewrite_oid": str(rewrite), "referenced_oid": str(target), "attribute_number": number,
            "dependency_kind": dependency, "object_kind": object_kind, "relation_kind": kind,
            "same_schema": scoped}


class Catalog:
    def __init__(self, rules=(), witnesses=()):
        self.rules, self.witnesses = list(rules), list(witnesses)
        self.calls = []

    def execute(self, query, params):
        self.calls.append((query, params))
        if query == lineage._RULES:
            return Rows(self.rules[:params[-1]])
        if query == lineage._WITNESSES:
            return Rows(self.witnesses[:params[-1]])
        raise AssertionError("Unexpected lineage catalog query")


class LineageTests(unittest.TestCase):
    def refusal(self, code, action):
        with self.assertRaises(pg.ScanFailure) as caught:
            action()
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)

    def test_empty_schema_or_table_only_always_has_closed_envelope_without_extra_queries(self):
        for relations in ([], [relation(7)]):
            conn = Catalog()
            self.assertEqual(lineage.extract(conn, "1", "2", relations), {
                "formatVersion": 1, "kind": "postgresql-view-dependencies", "adapterVersion": "1",
                "queryTemplate": "postgresql-view-dependencies-v1", "views": []})
            self.assertEqual(conn.calls, [])

    def test_return_rules_cover_empty_views_materialized_views_and_direct_chain_only(self):
        conn = Catalog([rule(20, 120), rule(2, 102), rule(3, 103)], [
            witness(120, 2, 1, kind="v"), witness(102, 7, 1), witness(103, 3, dependency="i", kind="v")])
        result = lineage.extract(conn, "11", "4", [relation(20, "m"), relation(2, "v"), relation(3, "v"), relation(7)])
        self.assertEqual(result["views"], [
            {"viewExternalId": "pg:11:relation:2", "rewriteOid": "102", "dependencies": [
                {"referencedExternalId": "pg:11:relation:7", "referencedAttributeNumbers": [1]}], "gaps": []},
            {"viewExternalId": "pg:11:relation:20", "rewriteOid": "120", "dependencies": [
                {"referencedExternalId": "pg:11:relation:2", "referencedAttributeNumbers": [1]}], "gaps": []},
            {"viewExternalId": "pg:11:relation:3", "rewriteOid": "103", "dependencies": [], "gaps": []}])
        self.assertEqual(conn.calls[0][1], (["2", "3", "20"], 1001))
        self.assertEqual(conn.calls[1][1], ("4", ["102", "103", "120"], 10001))
        self.assertIn("r.ev_type = '1' AND r.is_instead", conn.calls[0][0])
        self.assertIn("d.objsubid = 0", conn.calls[1][0])
        for forbidden in ("pg_get_viewdef", "ev_action", "prosrc", "relname", "nspname"):
            self.assertNotRegex(" ".join(query for query, _ in conn.calls), rf"\b{forbidden}\b")

    def test_internal_ownership_is_not_edge_but_normal_self_reference_and_cycle_survive(self):
        conn = Catalog([rule(2, 12), rule(3, 13)], [witness(12, 2, dependency="i", kind="v"),
            witness(12, 2, kind="v"), witness(12, 3, kind="m"), witness(13, 2, kind="v")])
        views = lineage.extract(conn, "1", "9", [relation(2, "v"), relation(3, "m")])["views"]
        self.assertEqual([dep["referencedExternalId"] for dep in views[0]["dependencies"]],
                         ["pg:1:relation:2", "pg:1:relation:3"])
        self.assertEqual(views[1]["dependencies"][0]["referencedExternalId"], "pg:1:relation:2")

    def test_witnesses_are_sorted_unique_not_output_column_mappings(self):
        rows = [witness(12, 3, n) for n in (32767, 1, 0, 3, 1, 0)] + [witness(12, 20, 2)]
        result = lineage.extract(Catalog([rule(2, 12)], list(reversed(rows))), "1", "9",
                                 [relation(2, "v"), relation(3), relation(20)])
        self.assertEqual(result["views"][0]["dependencies"], [
            {"referencedExternalId": "pg:1:relation:20", "referencedAttributeNumbers": [2]},
            {"referencedExternalId": "pg:1:relation:3", "referencedAttributeNumbers": [0, 1, 3, 32767]}])

    def test_external_unsupported_and_routine_dependencies_only_emit_closed_gaps(self):
        rows = [witness(12, 981234, 4, scoped=False), witness(12, 981235, kind="S"),
                witness(12, 981236, object_kind="routine", kind=None, scoped=None),
                witness(12, 981237, object_kind="other", kind=None, scoped=None)]
        conn = Catalog([rule(2, 12)], rows + rows)
        result = lineage.extract(conn, "1", "9", [relation(2, "v")])
        self.assertEqual(result["views"][0]["gaps"], ["OPAQUE_ROUTINE_DEPENDENCY", "OUT_OF_SCOPE_RELATION", "UNSUPPORTED_RELATION_KIND"])
        self.assertEqual(result["views"][0]["dependencies"], [])
        self.assertNotIn("98123", json.dumps(result))

    def test_supported_foreign_and_partitioned_relations_are_valid_scanned_endpoints(self):
        rows = [witness(12, 3, kind="f"), witness(12, 4, kind="p")]
        result = lineage.extract(Catalog([rule(2, 12)], rows), "1", "9", [relation(2, "v"), relation(3, "f"), relation(4, "p")])
        self.assertEqual(len(result["views"][0]["dependencies"]), 2)
        self.assertEqual(result["views"][0]["gaps"], [])

    def test_oid_grammar_and_scan_inventory_are_not_coerced(self):
        for value in ("0", "01", "4294967296", "-1", "1.0", "1\n", 1, True, None):
            self.refusal("SOURCE_LINEAGE_INVALID", lambda: lineage.extract(Catalog(), value, "2", []))
            self.refusal("SOURCE_LINEAGE_INVALID", lambda: lineage.extract(Catalog(), "1", value, []))
        self.assertEqual(lineage.extract(Catalog(), "4294967295", "4294967295", [relation(4294967295)])["views"], [])
        for rows in ([relation(1), relation(1)], [relation(1, "S")], [{"oid": "01", "relkind": "v"}]):
            self.refusal("SOURCE_LINEAGE_INVALID", lambda: lineage.extract(Catalog(), "1", "2", rows))

    def test_each_scanned_view_requires_exactly_one_valid_return_rule(self):
        for rules in ([], [rule(3, 13)], [rule(2, 12), rule(2, 13)], [rule(2, 0)]):
            self.refusal("SOURCE_LINEAGE_INVALID", lambda: lineage.extract(Catalog(rules), "1", "9", [relation(2, "v")]))
        self.refusal("SOURCE_LINEAGE_INVALID", lambda: lineage.extract(Catalog([rule(2, 12), rule(3, 12)]), "1", "9", [relation(2, "v"), relation(3, "v")]))

    def test_malformed_in_scope_catalog_relationships_fail_closed(self):
        rows = [witness(999, 3), witness(12, 999), witness(12, 3, kind="v"),
                witness(12, 3, scoped=None), witness(12, 3, kind=None), witness(12, 3, object_kind="unknown")]
        for number in (-1, 32768, True, "1", None):
            rows.append(witness(12, 3, number))
        for row in rows:
            self.refusal("SOURCE_LINEAGE_INVALID", lambda: lineage.extract(Catalog([rule(2, 12)], [row]), "1", "9", [relation(2, "v"), relation(3)]))

    def test_view_boundary_1000_succeeds_and_1001_refuses_before_queries(self):
        relations = [relation(i, "v") for i in range(1, 1001)]
        rules = [rule(i, i + 2000) for i in range(1, 1001)]
        self.assertEqual(len(lineage.extract(Catalog(rules), "1", "2", relations)["views"]), 1000)
        conn = Catalog(rules)
        self.refusal("SOURCE_LINEAGE_LIMIT", lambda: lineage.extract(conn, "1", "2", relations + [relation(1001, "v")]))
        self.assertEqual(conn.calls, [])
        self.refusal("SOURCE_LINEAGE_LIMIT", lambda: lineage.extract(Catalog(rules + [rule(1001, 3001)]), "1", "2", relations))

    def test_5000_distinct_edges_boundary_is_shared_across_views(self):
        relations = [relation(1, "v"), relation(2, "v")] + [relation(i) for i in range(10, 2511)]
        rows = [witness(rewrite, target) for rewrite in (5001, 5002) for target in range(10, 2510)]
        rules = [rule(1, 5001), rule(2, 5002)]
        result = lineage.extract(Catalog(rules, rows), "1", "2", relations)
        self.assertEqual(sum(len(view["dependencies"]) for view in result["views"]), 5000)
        self.refusal("SOURCE_LINEAGE_LIMIT", lambda: lineage.extract(Catalog(rules, rows + [witness(5002, 2510)]), "1", "2", relations))

    def test_raw_10000_row_budget_precedes_dedup_and_gap_filtering(self):
        for row in (witness(12, 3), witness(12, 981234, scoped=False), witness(12, 2, dependency="i", kind="v")):
            rows = [row] * 10000
            lineage.extract(Catalog([rule(2, 12)], rows), "1", "9", [relation(2, "v"), relation(3)])
            conn = Catalog([rule(2, 12)], rows + [row])
            self.refusal("SOURCE_LINEAGE_LIMIT", lambda: lineage.extract(conn, "1", "9", [relation(2, "v"), relation(3)]))
            self.assertEqual(conn.calls[-1][1][-1], 10001)

    def test_utf8_envelope_bytes_are_charged_at_exact_boundary(self):
        result = lineage.extract(Catalog([rule(2, 12)], [witness(12, 3)]), "1", "9", [relation(2, "v"), relation(3)])
        size = len(json.dumps(result).encode("utf-8"))
        with patch.object(lineage, "MAX_BYTES", size):
            self.assertEqual(lineage.extract(Catalog([rule(2, 12)], [witness(12, 3)]), "1", "9", [relation(2, "v"), relation(3)]), result)
        with patch.object(lineage, "MAX_BYTES", size - 1):
            self.refusal("SOURCE_LINEAGE_LIMIT", lambda: lineage.extract(Catalog([rule(2, 12)], [witness(12, 3)]), "1", "9", [relation(2, "v"), relation(3)]))


class MetadataCatalog(CatalogConnection):
    def __init__(self, *, delay=False, failure=None):
        super().__init__({})
        self.delay, self.failure = delay, failure

    def execute(self, query, params=None):
        if query == lineage._RULES:
            self.queries.append((query, params))
            return Rows([rule(65, 75)])
        if query == lineage._WITNESSES:
            self.queries.append((query, params))
            if self.delay:
                time.sleep(.5)
            if self.failure:
                raise self.failure
            return Rows([witness(75, 65, dependency="i", kind="v")])
        result = super().execute(query, params)
        if "FROM pg_class c JOIN" in query:
            result.rows[0]["relkind"] = "v"
        return result


class MetadataIntegrationTests(unittest.TestCase):
    source = {"database": "synthetic", "schema": "public"}

    def test_lineage_is_inside_original_transaction_and_total_scan_bytes(self):
        conn = MetadataCatalog()
        result = pg._metadata(conn, self.source)
        self.assertEqual(conn.queries[0][0], "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
        self.assertEqual(result["lineage"]["views"][0]["viewExternalId"], "pg:23:relation:65")
        self.assertEqual(result["lineage"]["views"][0]["dependencies"], [])
        base = {key: value for key, value in result.items() if key != "lineage"}
        with patch.object(pg, "MAX_BYTES", len(json.dumps(base).encode()) + 10):
            with self.assertRaisesRegex(pg.ScanFailure, "^SOURCE_BYTE_LIMIT$"):
                pg._metadata(MetadataCatalog(), self.source)

    @contextmanager
    def connection_parameters(self, *_):
        yield {}

    def test_lineage_database_failure_does_not_return_partial_scan_or_raw_error(self):
        conn = MetadataCatalog(failure=psycopg.OperationalError("synthetic hidden dependency detail"))
        with patch.object(pg, "_connection_parameters", self.connection_parameters), patch.object(pg.psycopg, "connect", return_value=conn):
            with self.assertRaises(pg.ScanFailure) as caught:
                pg.scan(self.source, {}, "synthetic")
        self.assertEqual(str(caught.exception), "SOURCE_DATABASE_ERROR")
        self.assertTrue(caught.exception.__suppress_context__)
        self.assertTrue(conn.closed)

    def test_lineage_uses_original_scan_deadline_and_connection_cleanup(self):
        from governance_workers import postgres_targets
        conn = MetadataCatalog(delay=True)
        before = time.monotonic()
        with patch.object(pg, "MAX_SECONDS", .05), patch.object(postgres_targets, "_remaining", return_value=5), \
                patch.object(pg, "_connection_parameters", self.connection_parameters), patch.object(pg.psycopg, "connect", return_value=conn):
            with self.assertRaisesRegex(pg.ScanFailure, "^SOURCE_DEADLINE_EXCEEDED$"):
                pg.scan(self.source, {}, "synthetic")
        self.assertLess(time.monotonic() - before, .3)
        self.assertTrue(conn.closed)


if __name__ == "__main__":
    unittest.main()
