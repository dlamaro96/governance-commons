# SPDX-License-Identifier: Apache-2.0
"""Adapter conformance fixtures, not live Databricks qualification."""
import copy
import io
import json
import socket
import threading
import time
import unittest
from unittest.mock import patch

from governance_workers import unity_catalog as uc
from governance_workers.dispatch import scan as dispatch
from governance_workers.postgresql import ScanFailure

METASTORE = "22222222-2222-4222-8222-222222222222"
TABLE = "33333333-3333-4333-8333-333333333333"
SOURCE = {"connectorId": "unity-catalog", "workspaceUrl": "https://adb-123456789.1.azuredatabricks.net",
          "catalog": "harbor", "schema": "commerce"}
SECRET = dict(SOURCE, tenantIds=["harbor-tenant"], accessToken="synthetic-fixture-token-only", principalId="fixture-reader")
SCHEMA = {"name": "commerce", "catalog_name": "harbor", "full_name": "harbor.commerce",
          "metastore_id": METASTORE, "created_at": 1700000000000, "comment": "Synthetic commerce schema"}
TABLE_INFO = {"name": "orders", "catalog_name": "harbor", "schema_name": "commerce",
              "full_name": "harbor.commerce.orders", "metastore_id": METASTORE,
              "table_id": TABLE, "table_type": "MANAGED", "columns": [
                  {"name": "order_id", "position": 0, "nullable": False, "type_text": "bigint"},
                  {"name": "total", "position": 1, "nullable": True, "type_text": "decimal(18,2)"}]}


class AdapterTest(unittest.TestCase):
    def run_scan(self, pages=None, schema=None):
        responses = [copy.deepcopy(schema or SCHEMA)] + copy.deepcopy(pages if pages is not None else [{"tables": [TABLE_INFO]}]) + [copy.deepcopy(schema or SCHEMA)]
        with patch.object(uc.Client, "get", side_effect=responses) as request:
            result = uc.scan(SOURCE, SECRET, "harbor-tenant")
        return result, request

    def test_real_api_shape_normalizes_without_copying_untrusted_fields(self):
        table = dict(TABLE_INFO, properties={"password": "excluded"}, view_definition="excluded", storage_location="excluded")
        result, calls = self.run_scan([{"tables": [table]}])
        self.assertEqual([x["type"] for x in result["records"]], ["schema", "table", "column", "column"])
        self.assertTrue(result["complete"])
        self.assertFalse(result["absenceReconciliation"])
        self.assertNotIn("excluded", json.dumps(result))
        self.assertNotIn(SECRET["accessToken"], json.dumps(result))
        self.assertEqual(calls.call_args_list[1].args[1]["max_results"], 0)
        self.assertEqual(result["records"][2]["metadata"]["ordinalPosition"], 1)

    def test_empty_page_with_next_token_is_not_terminal(self):
        result, calls = self.run_scan([{"tables": [], "next_page_token": "opaque&token"}, {"tables": [TABLE_INFO]}])
        self.assertEqual(len(result["records"]), 4)
        self.assertEqual(calls.call_args_list[2].args[1]["page_token"], "opaque&token")

    def test_empty_terminal_listing_never_proves_absence(self):
        result, _ = self.run_scan([{}])
        self.assertEqual(len(result["records"]), 1)
        self.assertFalse(result["absenceReconciliation"])

    def test_loop_and_page_bound_fail_without_partial_result(self):
        with self.assertRaisesRegex(ScanFailure, "SOURCE_PAGINATION_LOOP"):
            self.run_scan([{"next_page_token": "one"}, {"next_page_token": "one"}])
        with patch.object(uc, "MAX_PAGES", 1), self.assertRaisesRegex(ScanFailure, "SOURCE_PAGE_LIMIT"):
            self.run_scan([{"next_page_token": "one"}])

    def test_table_identity_survives_rename_and_columns_survive_reorder(self):
        original, _ = self.run_scan()
        changed = copy.deepcopy(TABLE_INFO)
        changed.update(name="purchases", full_name="harbor.commerce.purchases")
        changed["columns"].reverse()
        for i, column in enumerate(changed["columns"]):
            column["position"] = i
        updated, _ = self.run_scan([{"tables": [changed]}])
        self.assertEqual(original["records"][1]["externalId"], updated["records"][1]["externalId"])
        self.assertEqual({x["name"]: x["externalId"] for x in original["records"][2:]},
                         {x["name"]: x["externalId"] for x in updated["records"][2:]})

    def test_recreated_schema_has_new_identity(self):
        before, _ = self.run_scan()
        after, _ = self.run_scan(schema=dict(SCHEMA, created_at=1700000000001))
        self.assertNotEqual(before["records"][0]["externalId"], after["records"][0]["externalId"])

    def test_missing_stable_table_identity_refused(self):
        for invalid in (None, "orders", "../orders", "", "000", "00000000-0000-0000-0000-000000000000"):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ScanFailure, "SOURCE_RESPONSE_INVALID"):
                self.run_scan([{"tables": [dict(TABLE_INFO, table_id=invalid)]}])

    def test_scope_and_browse_only_responses_refused(self):
        for change, code in (({"catalog_name": "other"}, "SOURCE_SCOPE_MISMATCH"),
                             ({"metastore_id": "44444444-4444-4444-8444-444444444444"}, "SOURCE_SCOPE_MISMATCH"),
                             ({"browse_only": True}, "SOURCE_SCOPE_INCOMPLETE"),
                             ({"columns": None}, "SOURCE_SCOPE_INCOMPLETE")):
            with self.subTest(change=change), self.assertRaisesRegex(ScanFailure, code):
                self.run_scan([{"tables": [dict(TABLE_INFO, **change)]}])

    def test_duplicate_tables_and_columns_refused(self):
        with self.assertRaisesRegex(ScanFailure, "SOURCE_DUPLICATE_ID"):
            self.run_scan([{"tables": [TABLE_INFO, TABLE_INFO]}])
        duplicate = copy.deepcopy(TABLE_INFO)
        duplicate["columns"][1]["name"] = "order_id"
        with self.assertRaisesRegex(ScanFailure, "SOURCE_DUPLICATE_ID"):
            self.run_scan([{"tables": [duplicate]}])

    def test_column_shape_and_unknown_table_type_refused(self):
        for change in ({"position": True}, {"position": -1}, {"nullable": "true"}, {"type_text": None}):
            table = copy.deepcopy(TABLE_INFO)
            table["columns"][0].update(change)
            with self.subTest(change=change), self.assertRaisesRegex(ScanFailure, "SOURCE_RESPONSE_INVALID"):
                self.run_scan([{"tables": [table]}])
        with self.assertRaisesRegex(ScanFailure, "SOURCE_TYPE_UNSUPPORTED"):
            self.run_scan([{"tables": [dict(TABLE_INFO, table_type="NEW_KIND")]}])
        with self.assertRaisesRegex(ScanFailure, "SOURCE_TYPE_UNSUPPORTED"):
            self.run_scan([{"tables": [dict(TABLE_INFO, table_type=[])]}])

    def test_schema_replacement_during_pagination_refuses_whole_scan(self):
        responses = [copy.deepcopy(SCHEMA), {"tables": [copy.deepcopy(TABLE_INFO)]}, dict(SCHEMA, created_at=1700000000001)]
        with patch.object(uc.Client, "get", side_effect=responses), self.assertRaisesRegex(ScanFailure, "SOURCE_SCOPE_CHANGED"):
            uc.scan(SOURCE, SECRET, "harbor-tenant")

    def test_views_and_truncated_comments_are_explicit(self):
        result, _ = self.run_scan([{"tables": [dict(TABLE_INFO, table_type="MATERIALIZED_VIEW", comment="a" * 5000)]}])
        self.assertEqual(result["records"][1]["type"], "view")
        self.assertEqual(len(result["records"][1]["metadata"]["sourceDescription"]), 4096)
        self.assertTrue(result["records"][1]["metadata"]["sourceDescriptionTruncated"])

    def test_unicode_and_jsonb_incompatible_comments_fail_without_partial_result(self):
        for value in ("invalid\x00comment", "invalid\ud800comment"):
            with self.subTest(kind="comment"), self.assertRaisesRegex(ScanFailure, "SOURCE_RESPONSE_INVALID"):
                self.run_scan([{"tables": [dict(TABLE_INFO, comment=value)]}])
        for value in ("column\udfff", "column\x7f"):
            table = copy.deepcopy(TABLE_INFO)
            table["columns"][0]["name"] = value
            with self.subTest(kind="name"), self.assertRaisesRegex(ScanFailure, "SOURCE_RESPONSE_INVALID"):
                self.run_scan([{"tables": [table]}])
        comment = "وصف 😀\nsecond line\tindented"
        result, _ = self.run_scan([{"tables": [dict(TABLE_INFO, comment=comment)]}])
        self.assertEqual(result["records"][1]["metadata"]["sourceDescription"], comment)

    def test_scope_unicode_del_and_principal_invalid_before_token_exchange(self):
        with patch.object(uc, "token_for") as token:
            for value in ("schema\ud800", "schema\x7f"):
                with self.subTest(value_kind="scope"), self.assertRaisesRegex(ScanFailure, "SOURCE_TARGET_DENIED"):
                    uc.scan(dict(SOURCE, schema=value), dict(SECRET, schema=value), "harbor-tenant")
            for value in ("principal\ud800", "principal\x00"):
                with self.subTest(value_kind="principal"), self.assertRaisesRegex(ScanFailure, "SOURCE_CREDENTIAL_INVALID"):
                    uc.scan(SOURCE, dict(SECRET, principalId=value), "harbor-tenant")
            token.assert_not_called()

    def test_emitted_numeric_metadata_is_javascript_exact(self):
        with self.assertRaisesRegex(ScanFailure, "SOURCE_IDENTITY_UNAVAILABLE"):
            self.run_scan(schema=dict(SCHEMA, created_at=9007199254740992))
        table = copy.deepcopy(TABLE_INFO)
        table["columns"][0]["position"] = 9007199254740991
        with self.assertRaisesRegex(ScanFailure, "SOURCE_RESPONSE_INVALID"):
            self.run_scan([{"tables": [table]}])

    def test_records_and_output_bytes_bounded(self):
        with patch.object(uc, "MAX_RECORDS", 3), self.assertRaisesRegex(ScanFailure, "SOURCE_RECORD_LIMIT"):
            self.run_scan()
        with patch.object(uc, "MAX_BYTES", 2100), self.assertRaisesRegex(ScanFailure, "SOURCE_BYTE_LIMIT"):
            self.run_scan()

    def test_tenant_and_exact_registered_target_required_before_network(self):
        for source, secret, tenant in ((SOURCE, SECRET, "other-tenant"),
                                     (dict(SOURCE, catalog="other"), SECRET, "harbor-tenant"),
                                     (SOURCE, dict(SECRET, connectorId="postgresql"), "harbor-tenant")):
            with patch.object(uc.Client, "get") as request, self.assertRaises(ScanFailure):
                uc.scan(source, secret, tenant)
            request.assert_not_called()

    def test_operator_secret_cannot_expand_destination_policy(self):
        for url in ("http://adb-1.azuredatabricks.net", "https://localhost", "https://169.254.169.254",
                    "https://adb-1.azuredatabricks.net.evil.example", "https://user@adb-1.azuredatabricks.net",
                    "https://adb-1.azuredatabricks.net:443", "https://adb-1.azuredatabricks.net/",
                    "https://adb-1.azuredatabricks.net?redirect=evil", "https://adb-1.azuredatabricks.net#fragment"):
            with self.subTest(url=url), self.assertRaisesRegex(ScanFailure, "SOURCE_DESTINATION_DENIED"):
                uc.validate_target(dict(SOURCE, workspaceUrl=url), dict(SECRET, workspaceUrl=url), "harbor-tenant")

    def test_credential_header_injection_refused(self):
        with patch.object(uc.Client, "get") as request, self.assertRaises(ScanFailure):
            uc.scan(SOURCE, dict(SECRET, accessToken="synthetic\r\nX-evil: yes"), "harbor-tenant")
        request.assert_not_called()

    def test_dispatch_is_closed_and_secret_type_bound(self):
        with patch.object(uc, "scan", return_value={"adapter": "unity"}) as adapter:
            self.assertEqual(dispatch(SOURCE, SECRET, "harbor-tenant"), {"adapter": "unity"})
            adapter.assert_called_once_with(SOURCE, SECRET, "harbor-tenant")
        with self.assertRaisesRegex(ScanFailure, "SOURCE_TARGET_DENIED"):
            dispatch(dict(SOURCE, connectorId="postgresql"), SECRET, "harbor-tenant")
        with self.assertRaisesRegex(ScanFailure, "SOURCE_CONNECTOR_UNSUPPORTED"):
            dispatch({"connectorId": "arbitrary-module"}, {"connectorId": "arbitrary-module"}, "harbor-tenant")


class Response(io.BytesIO):
    def __init__(self, value, status=200, headers=None):
        super().__init__(value)
        self.status, self.headers = status, headers or {"Content-Type": "application/json"}

    def getheader(self, name, default=None):
        return self.headers.get(name, default)


class TransportTest(unittest.TestCase):
    def request(self, response):
        pairs = list(response.headers.items()) if isinstance(response.headers, dict) else response.headers
        response.getheaders = lambda: pairs
        response.getheader = lambda name, default=None: next((v for k, v in pairs if k.lower() == name.lower()), default)
        with patch.object(uc, "PinnedHTTPSConnection") as constructor:
            connection = constructor.return_value
            connection.sock = None
            connection._deadline_socket = None
            connection.getresponse.return_value = response
            result = uc.Client("adb-123.1.azuredatabricks.net", SECRET["accessToken"]).get("/tables", {"page_token": "a&b"})
            connection.close.assert_called_once()
            self.assertIn("page_token=a%26b", connection.request.call_args.args[1])
            return result

    def test_parses_bounded_json(self):
        self.assertEqual(self.request(Response(b'{"tables":[]}')), {"tables": []})

    def test_http_failure_and_redirect_do_not_copy_source_error_or_follow(self):
        for status, code in ((301, "SOURCE_HTTP_ERROR"), (401, "SOURCE_AUTHENTICATION_FAILED"),
                             (403, "SOURCE_SCOPE_DENIED"), (404, "SOURCE_SCOPE_UNAVAILABLE"),
                             (429, "SOURCE_RATE_LIMITED"), (500, "SOURCE_HTTP_ERROR")):
            with self.subTest(status=status), self.assertRaisesRegex(ScanFailure, "^" + code + "$"):
                self.request(Response(b'source-secret-error', status, {"Location": "https://evil.example"}))

    def test_invalid_ambiguous_and_compressed_json_refused(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'[]', b'not json', b'"\xff"',
                    b'{"a":1e999}', b'{"a":"\\ud800"}', b'[' * 33 + b'0' + b']' * 33,
                    b'{"a":[' + b'0,' * 262143 + b'0]}'):
            with self.subTest(raw=raw), self.assertRaisesRegex(ScanFailure, "SOURCE_RESPONSE_INVALID"):
                self.request(Response(raw))
        with self.assertRaisesRegex(ScanFailure, "SOURCE_RESPONSE_INVALID"):
            self.request(Response(b'{}', headers={"Content-Type": "application/json", "Content-Encoding": "gzip"}))

    def test_framing_duplicates_and_mismatched_lengths_refused(self):
        for fields in ([('Content-Length', '1'), ('Content-Length', '2')],
                       [('Content-Length', '2'), ('Transfer-Encoding', 'chunked')],
                       [('Content-Length', '-1')], [('Content-Length', '3')],
                       [('Transfer-Encoding', 'gzip')], [('Content-Type', 'application/json')]):
            with self.subTest(fields=fields), self.assertRaisesRegex(ScanFailure, "SOURCE_RESPONSE_INVALID"):
                self.request(Response(b'{}', headers=[('Content-Type', 'application/json')] + fields))

    def test_declared_body_bounds_refuse_before_read_and_close_response(self):
        response = Response(b'{}', headers={"Content-Type": "application/json", "Content-Length": str(uc.MAX_PAGE_BYTES + 1)})
        with patch.object(response, "read1", side_effect=AssertionError("preflight must refuse")), \
                self.assertRaisesRegex(ScanFailure, "SOURCE_BYTE_LIMIT"):
            self.request(response)
        self.assertTrue(response.closed)

    def test_page_size_and_scan_deadline_are_enforced(self):
        with patch.object(uc, "MAX_PAGE_BYTES", 8), self.assertRaisesRegex(ScanFailure, "SOURCE_BYTE_LIMIT"):
            self.request(Response(b'{"tables":[]}'))
        with patch.object(uc, "MAX_SECONDS", -1), self.assertRaisesRegex(ScanFailure, "SOURCE_DEADLINE_EXCEEDED"):
            self.request(Response(b'{}'))

    def test_dns_rebinding_and_mixed_public_private_answers_refused_before_socket(self):
        public = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))
        for address in ("127.0.0.1", "169.254.169.254", "10.0.0.1", "::1", "::ffff:127.0.0.1"):
            private = (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))
            with self.subTest(address=address), patch.object(socket, "getaddrinfo", return_value=[public, private]), \
                    patch.object(socket, "socket") as create, self.assertRaisesRegex(ScanFailure, "SOURCE_DESTINATION_DENIED"):
                uc.PinnedHTTPSConnection("adb-123.1.azuredatabricks.net", time.monotonic() + 1).connect()
            create.assert_not_called()

    def test_pinned_ip_connection_preserves_tls_hostname(self):
        answer = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))
        with patch.object(socket, "getaddrinfo", return_value=[answer]) as dns, patch.object(socket, "socket") as create:
            connection = uc.PinnedHTTPSConnection("adb-123.1.azuredatabricks.net", time.monotonic() + 1)
            with patch.object(connection._context, "wrap_socket") as tls:
                connection.connect()
                create.return_value.connect.assert_called_once_with(("8.8.8.8", 443))
                tls.assert_called_once_with(create.return_value, server_hostname="adb-123.1.azuredatabricks.net", do_handshake_on_connect=False)
                tls.return_value.do_handshake.assert_called_once_with()
                dns.assert_called_once()

    def test_dns_wait_is_bounded_by_metadata_original_deadline(self):
        release = threading.Event()

        def lookup(*_args, **_kwargs):
            release.wait(1)
            return []

        started = time.monotonic()
        try:
            with patch.object(socket, "getaddrinfo", side_effect=lookup), patch.object(uc, "MAX_SECONDS", 0.04), \
                    self.assertRaisesRegex(ScanFailure, "SOURCE_DEADLINE_EXCEEDED"):
                uc.Client("adb-123.1.azuredatabricks.net", SECRET["accessToken"]).get("/tables")
            self.assertLess(time.monotonic() - started, 0.5)
        finally:
            release.set()

    def wire_request(self, payload, seconds=0.06):
        """Actual HTTP parser/socket, no external host or TLS-server fiction."""
        client, peer = socket.socketpair()
        release = threading.Event()
        connection = uc.PinnedHTTPSConnection("adb-123.1.azuredatabricks.net", time.monotonic() + seconds)
        connection.sock = client
        connection._deadline_socket = client

        def serve():
            try:
                peer.recv(4096)
                peer.sendall(payload)
                release.wait(1)
            except OSError:
                pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            with patch.object(uc, "MAX_SECONDS", seconds), patch.object(uc, "PinnedHTTPSConnection", return_value=connection):
                return uc.Client("adb-123.1.azuredatabricks.net", SECRET["accessToken"]).get("/tables")
        finally:
            release.set()
            thread.join(1)
            peer.close()
            client.close()

    def test_actual_partial_headers_and_detached_bodies_interrupt_at_original_deadline(self):
        payloads = [b"HTTP/1.1 200 OK\r\nContent-Type:",
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 100\r\n\r\n{",
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\nF"]
        for payload in payloads:
            started = time.monotonic()
            with self.subTest(length=len(payload)), self.assertRaisesRegex(ScanFailure, "SOURCE_DEADLINE_EXCEEDED"):
                self.wire_request(payload)
            self.assertLess(time.monotonic() - started, 0.5)

    def test_more_than_64_body_chunks_work_without_loosening_header_limits(self):
        raw = json.dumps({"tables": [], "unknown": "x" * 80}).encode()
        chunks = b"".join(b"1\r\n" + bytes([byte]) + b"\r\n" for byte in raw) + b"0\r\n\r\n"
        result = self.wire_request(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n" + chunks)
        self.assertEqual(result, json.loads(raw))
        excessive = b"HTTP/1.1 200 OK\r\n" + b"X: ok\r\n" * 65 + b"\r\n{}"
        with self.assertRaisesRegex(ScanFailure, "SOURCE_RESPONSE_INVALID"):
            self.wire_request(excessive)

    def test_scan_byte_budget_and_deadline_do_not_reset_between_pages(self):
        first = Response(b'{"tables":[]}')
        second = Response(b'{"tables":[]}')
        for response in (first, second):
            response.getheaders = lambda: [('Content-Type', 'application/json')]
        with patch.object(uc, "PinnedHTTPSConnection") as constructor, patch.object(uc, "MAX_BYTES", 20):
            conn = constructor.return_value
            conn.sock = conn._deadline_socket = None
            conn.getresponse.side_effect = [first, second]
            client = uc.Client("adb-123.1.azuredatabricks.net", SECRET["accessToken"])
            client.get("/tables")
            original = client.deadline
            with self.assertRaisesRegex(ScanFailure, "SOURCE_BYTE_LIMIT"):
                client.get("/tables")
            self.assertEqual(client.deadline, original)
            client.deadline = time.monotonic() - 1
            with self.assertRaisesRegex(ScanFailure, "SOURCE_DEADLINE_EXCEEDED"):
                client.get("/tables")
            self.assertEqual(constructor.call_count, 2)


if __name__ == "__main__":
    unittest.main()
