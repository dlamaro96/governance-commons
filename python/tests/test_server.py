# SPDX-License-Identifier: Apache-2.0
"""Actual loopback worker HTTP boundary and private-file resolution.

Adapter responses are controlled unit fixtures; no live Databricks or database
qualification is implied. The server runs on the main thread as in production.
"""
import copy
import json
from pathlib import Path
import select
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from governance_workers import server, unity_catalog
from governance_workers.postgresql import ScanFailure
from test_unity_catalog import SOURCE, SECRET, SCHEMA, TABLE_INFO

TOKEN = "synthetic-worker-credential-for-tests-only"


class WorkerHTTPTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "secrets.json"
        self.write_secret(SECRET)
        self.http = server.WorkerServer(("127.0.0.1", 0), TOKEN, self.path)
        self.http.timeout = 2
        self.addCleanup(self.http.server_close)
        self.payload = {"tenantId": "harbor-tenant", "source": dict(SOURCE, secretRef="selected")}

    def write_secret(self, secret):
        replacement = self.path.with_suffix(".new")
        replacement.write_text(json.dumps({"selected": secret}))
        replacement.chmod(0o600)
        replacement.replace(self.path)

    def request(self, body=None, headers=None, *, length=None, half_close=False, trickle=False):
        raw = json.dumps(self.payload).encode() if body is None else body
        headers = headers if headers is not None else [("Authorization", "Bearer " + TOKEN), ("Content-Type", "application/json")]
        fields = headers + [("Content-Length", str(len(raw) if length is None else length))]
        wire = ("POST /scan HTTP/1.1\r\nHost: local\r\n" + "".join(f"{key}: {value}\r\n" for key, value in fields) + "\r\n").encode("latin1") + raw
        received, errors = [], []

        def client():
            try:
                with socket.create_connection(self.http.server_address, timeout=2) as connection:
                    connection.sendall(wire)
                    if half_close:
                        connection.shutdown(socket.SHUT_WR)
                    if trickle:
                        for _ in range(12):
                            # Stop writing as soon as the response arrives;
                            # writing after server close can discard it via RST.
                            if select.select([connection], [], [], 0.015)[0]:
                                break
                            try:
                                connection.sendall(b' ')
                            except (BrokenPipeError, ConnectionResetError):
                                break
                    while True:
                        block = connection.recv(65536)
                        if not block:
                            break
                        received.append(block)
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=client)
        thread.start()
        started = time.monotonic()
        try:
            self.http.handle_request()
        finally:
            self.server_elapsed = time.monotonic() - started
            thread.join(3)
        self.assertFalse(thread.is_alive())
        if errors:
            raise errors[0]
        response = b"".join(received)
        head, body = response.split(b"\r\n\r\n", 1)
        self.assertIn(b"Content-Type: application/json", head)
        return int(head.split(b" ", 2)[1]), json.loads(body)

    def test_exact_secret_selected_freshly_and_not_returned(self):
        with patch.object(server, "scan", return_value={"complete": True, "records": []}) as scan:
            self.assertEqual(self.request(), (200, {"complete": True, "records": []}))
            self.assertEqual(scan.call_args.args[1]["accessToken"], SECRET["accessToken"])
            self.write_secret(dict(SECRET, accessToken="synthetic-rotated-token-only"))
            self.assertEqual(self.request()[0], 200)
            self.assertEqual(scan.call_args.args[1]["accessToken"], "synthetic-rotated-token-only")
            self.assertEqual(scan.call_args.args[2], "harbor-tenant")

    def test_wrong_tenant_connector_reference_and_target_never_complete(self):
        cases = [("tenantId", "other", "SOURCE_SCOPE_DENIED"),
                 ("connectorId", "postgresql", "SOURCE_TARGET_DENIED"),
                 ("secretRef", "missing", "SECRET_REFERENCE_DENIED"),
                 ("catalog", "other", "SOURCE_TARGET_DENIED")]
        original = copy.deepcopy(self.payload)
        with patch.object(unity_catalog, "token_for") as token:
            for key, value, code in cases:
                self.payload = copy.deepcopy(original)
                (self.payload if key == "tenantId" else self.payload["source"])[key] = value
                with self.subTest(key=key):
                    self.assertEqual(self.request(), (422, {"code": code}))
            token.assert_not_called()

    def test_failed_later_page_returns_only_error_no_partial_records(self):
        responses = [copy.deepcopy(SCHEMA), {"tables": [copy.deepcopy(TABLE_INFO)], "next_page_token": "next"}, ScanFailure("SOURCE_SCOPE_DENIED")]
        with patch.object(unity_catalog.Client, "get", side_effect=responses):
            self.assertEqual(self.request(), (422, {"code": "SOURCE_SCOPE_DENIED"}))

    def test_successful_empty_listing_explicitly_forbids_absence_reconciliation(self):
        with patch.object(unity_catalog.Client, "get", side_effect=[copy.deepcopy(SCHEMA), {}, copy.deepcopy(SCHEMA)]):
            status, result = self.request()
        self.assertEqual(status, 200)
        self.assertIs(result["absenceReconciliation"], False)
        self.assertEqual(len(result["records"]), 1)

    def test_ambiguous_malformed_unicode_and_nonfinite_json_refused_before_credentials(self):
        valid = json.dumps(self.payload).encode()
        cases = [b'{"tenantId":"other",' + valid[1:], b'[]', b'{"a":"\xff"}',
                 valid.replace(b'"commerce"', b'"\\ud800"'), valid.replace(b'"commerce"', b'"\\u0000"'),
                 valid[:-1] + b',"extra":NaN}', valid[:-1] + b',"extra":1e999}',
                 valid[:-1] + b',"extra":null}', b'[' * 17 + b'0' + b']' * 17,
                 b'{"many":[' + b'0,' * 2048 + b'0]}',
                 valid.replace(b'"secretRef": "selected"', b'"secretRef":"other","secretRef":"selected"')]
        with patch.object(server, "resolve") as resolve:
            for raw in cases:
                with self.subTest(length=len(raw)):
                    self.assertEqual(self.request(raw), (400, {"code": "INVALID_REQUEST"}))
            resolve.assert_not_called()

    def test_missing_duplicate_and_nonascii_authorization_refused_safely(self):
        for auth in ([], [("Authorization", "Bearer wrong")], [("Authorization", "Bearer \xff")],
                     [("Authorization", "Bearer " + TOKEN)] * 2):
            with self.subTest(count=len(auth)), patch.object(server, "resolve") as resolve:
                self.assertEqual(self.request(headers=auth + [("Content-Type", "application/json")]), (401, {"code": "UNAUTHORIZED"}))
                resolve.assert_not_called()

    def test_ambiguous_framing_and_short_body_refused_before_credentials(self):
        base = [("Authorization", "Bearer " + TOKEN), ("Content-Type", "application/json")]
        with patch.object(server, "resolve") as resolve:
            for extra in ([('Content-Length', '1')], [('Transfer-Encoding', 'chunked')],
                          [('Content-Encoding', 'gzip')], [('Content-Type', 'text/plain')]):
                with self.subTest(extra=extra):
                    self.assertEqual(self.request(headers=base + extra), (400, {"code": "INVALID_REQUEST"}))
            self.assertEqual(self.request(length=16385), (413, {"code": "REQUEST_SIZE"}))
            self.assertEqual(self.request(body=b'{}', length=3, half_close=True), (400, {"code": "INVALID_REQUEST"}))
            resolve.assert_not_called()

    def test_actual_partial_body_deadline_does_not_wait_for_peer_close(self):
        with patch.object(server, "REQUEST_SECONDS", 0.04), patch.object(server, "resolve") as resolve:
            started = time.monotonic()
            self.assertEqual(self.request(body=b'{', length=100), (408, {"code": "REQUEST_TIMEOUT"}))
            self.assertLess(time.monotonic() - started, 0.4)
            resolve.assert_not_called()

    def test_trickled_request_cannot_reset_absolute_body_deadline(self):
        with patch.object(server, "REQUEST_SECONDS", 0.06), patch.object(server, "resolve") as resolve:
            self.assertEqual(self.request(body=b'{', length=100, trickle=True), (408, {"code": "REQUEST_TIMEOUT"}))
            self.assertLess(self.server_elapsed, 0.14)
            resolve.assert_not_called()

    def test_valid_multilingual_input_survives_and_unexpected_adapter_error_is_sanitized(self):
        self.payload["source"]["name"] = "كتالوج 😀"
        with patch.object(server, "scan", side_effect=RuntimeError("credential must not escape")):
            self.assertEqual(self.request(), (500, {"code": "WORKER_FAILURE"}))


if __name__ == "__main__":
    unittest.main()
