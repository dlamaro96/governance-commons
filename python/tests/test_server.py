# SPDX-License-Identifier: Apache-2.0
"""Actual loopback worker HTTP boundary and private-file resolution.

Adapter responses are controlled unit fixtures; no live Databricks or database
qualification is implied. The server runs on the main thread as in production.
"""
import copy
import json
import os
from pathlib import Path
import select
import signal
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


def quality_payload():
    return {"tenantId": "harbor-tenant", "source": {"connectorId": "postgresql", "host": "quality.invalid",
            "port": 5432, "database": "synthetic", "schema": "public", "secretRef": "quality-selected"},
            "execution": {"formatVersion": 1, "kind": "completeness", "target": {
                "databaseOid": "23", "schemaOid": "18", "relationOid": "65", "attributeNumber": 1,
                "schemaName": "public", "tableName": "observations", "columnName": "value", "dataType": "integer"},
                "budget": {"maximumRows": 100000, "maximumSeconds": 30, "statementTimeoutMs": 15000,
                           "maximumEstimatedCost": 1000000, "maximumEstimatedBytes": 67108864}}}


def quality_measurement():
    return {"formatVersion": 1, "kind": "completeness", "strategy": "exact-bounded-role-scope",
            "rowCount": 20, "nullCount": 5, "observedStartedAt": "2026-11-16T00:00:00.000Z",
            "observedFinishedAt": "2026-11-16T00:00:00.005Z", "elapsedMs": 5,
            "sourceVersion": "170006", "adapterVersion": "1", "queryTemplate": "postgresql-completeness-v1",
            "estimatedCost": 1, "estimatedBytes": 80}


class WorkerHTTPTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "secrets.json"
        self.write_fixture("initial")
        self.http = server.WorkerServer(("127.0.0.1", 0), TOKEN, self.path)
        self.http.timeout = 2
        self.addCleanup(self.http.server_close)
        self.payload = {"tenantId": "harbor-tenant", "source": dict(SOURCE, secretRef="selected")}

    def write_fixture(self, variant):
        # Closed, public synthetic documents only: this fixture helper cannot
        # serialize a caller-supplied credential object to disk.
        documents = {
            "postgres": '{"quality-selected":{"connectorId":"postgresql","tenantIds":["harbor-tenant"],'
                        '"host":"quality.invalid","port":5432,"database":"synthetic","schema":"public",'
                        '"username":"synthetic-reader","password":"synthetic-quality-test-password"}}',
            "postgres-rotated": '{"quality-selected":{"connectorId":"postgresql","tenantIds":["harbor-tenant"],'
                                '"host":"quality.invalid","port":5432,"database":"synthetic","schema":"public",'
                                '"username":"synthetic-reader","password":"synthetic-quality-rotated-password"}}',
            "initial": '{"selected":{"connectorId":"unity-catalog",'
                       '"workspaceUrl":"https://adb-123456789.1.azuredatabricks.net",'
                       '"catalog":"harbor","schema":"commerce","tenantIds":["harbor-tenant"],'
                       '"accessToken":"synthetic-fixture-token-only","principalId":"fixture-reader"}}',
            "rotated": '{"selected":{"connectorId":"unity-catalog",'
                       '"workspaceUrl":"https://adb-123456789.1.azuredatabricks.net",'
                       '"catalog":"harbor","schema":"commerce","tenantIds":["harbor-tenant"],'
                       '"accessToken":"synthetic-rotated-token-only","principalId":"fixture-reader"}}',
        }
        document = documents[variant]
        replacement = self.path.with_suffix(".new")
        fd = os.open(replacement, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            self.assertEqual(os.fstat(stream.fileno()).st_mode & 0o777, 0o600)
            stream.write(document)
        replacement.replace(self.path)

    def request(self, body=None, headers=None, *, length=None, half_close=False, trickle=False, path="/scan"):
        raw = json.dumps(self.payload).encode() if body is None else body
        headers = headers if headers is not None else [("Authorization", "Bearer " + TOKEN), ("Content-Type", "application/json")]
        fields = headers + [("Content-Length", str(len(raw) if length is None else length))]
        wire = ("POST " + path + " HTTP/1.1\r\nHost: local\r\n" + "".join(f"{key}: {value}\r\n" for key, value in fields) + "\r\n").encode("latin1") + raw
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

    def raw_request(self, initial, *, delayed=(), trickle=False):
        """Real incomplete HTTP exchange; the peer never closes to end a read."""
        received, errors, writes = [], [], []

        def client():
            try:
                with socket.create_connection(self.http.server_address, timeout=2) as connection:
                    connection.sendall(initial)
                    for pause, fragment in delayed:
                        if select.select([connection], [], [], pause)[0]:
                            break
                        connection.sendall(fragment)
                    if trickle:
                        for _ in range(100):
                            if select.select([connection], [], [], 0.01)[0]:
                                break
                            connection.sendall(b"x")
                            writes.append(1)
                    while True:
                        block = connection.recv(65536)
                        if not block:
                            break
                        received.append(block)
            except (BrokenPipeError, ConnectionResetError):
                # An expired incomplete request may close with FIN or RST.
                pass
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
        return b"".join(received), len(writes)

    def assert_alarm_restored(self, handler, mask):
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(signal.getsignal(signal.SIGALRM), handler)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), mask)
        self.assertNotIn(signal.SIGALRM, signal.sigpending())

    def test_idle_partial_line_and_partial_headers_expire_and_worker_recovers(self):
        handler = signal.getsignal(signal.SIGALRM)
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        threads = set(threading.enumerate())
        prefixes = (b"", b"POST /quality", b"POST /quality HTTP/1.1\r\nHost: local\r\nX-Slow: ")
        for prefix in prefixes:
            with self.subTest(prefix=prefix), patch.object(server, "REQUEST_SECONDS", 0.08), \
                    patch.object(server, "resolve") as resolve, patch.object(self.http, "handle_error") as error:
                self.assertEqual(self.raw_request(prefix)[0], b"")
                self.assertLess(self.server_elapsed, 0.4)
                resolve.assert_not_called()
                error.assert_not_called()
            self.assert_alarm_restored(handler, mask)
            self.assertEqual(set(threading.enumerate()), threads)
            with patch.object(server, "scan", return_value={"complete": True, "records": []}):
                self.assertEqual(self.request(), (200, {"complete": True, "records": []}))

    def test_trickled_headers_cannot_reset_absolute_admission_deadline(self):
        initial = b"POST /quality HTTP/1.1\r\nHost: local\r\nX-Slow: "
        with patch.object(server, "REQUEST_SECONDS", 0.12), patch.object(server, "resolve") as resolve:
            response, writes = self.raw_request(initial, trickle=True)
            self.assertEqual(response, b"")
            self.assertGreaterEqual(writes, 2)
            self.assertLess(self.server_elapsed, 0.4)
            resolve.assert_not_called()

    def test_body_uses_only_remaining_admission_budget_after_slow_headers(self):
        initial = ("POST /quality HTTP/1.1\r\nHost: local\r\nAuthorization: Bearer " + TOKEN +
                   "\r\nContent-Type: application/json\r\nContent-Length: 100\r\nX-Slow: ").encode()
        with patch.object(server, "REQUEST_SECONDS", 0.25), patch.object(server, "resolve") as resolve:
            response, writes = self.raw_request(initial, delayed=((0.16, b"done\r\n\r\n{"),), trickle=True)
            head, body = response.split(b"\r\n\r\n", 1)
            self.assertEqual(int(head.split(b" ", 2)[1]), 408)
            self.assertEqual(json.loads(body), {"code": "REQUEST_TIMEOUT"})
            self.assertGreaterEqual(writes, 2)
            self.assertGreater(self.server_elapsed, 0.20)
            self.assertLess(self.server_elapsed, 0.34)
            resolve.assert_not_called()

    def test_admission_ends_before_private_secret_and_adapter_execution(self):
        handler = signal.getsignal(signal.SIGALRM)
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        original_resolve = server.resolve

        def resolve(*args):
            self.assert_alarm_restored(handler, mask)
            return original_resolve(*args)

        for path, adapter, fixture, payload, expected in (
                ("/scan", "scan", "initial", self.payload, {"complete": True, "records": []}),
                ("/quality", "execute_quality", "postgres", quality_payload(), quality_measurement())):
            self.payload = payload
            self.write_fixture(fixture)

            def execute(*_args):
                self.assert_alarm_restored(handler, mask)
                # A real independent adapter guard must install successfully,
                # and work may outlast the already-ended admission budget.
                with server.deadline(0.3):
                    time.sleep(0.10)
                return expected

            with self.subTest(path=path), patch.object(server, "REQUEST_SECONDS", 0.06), \
                    patch.object(server, "resolve", side_effect=resolve), patch.object(server, adapter, side_effect=execute) as called:
                result = {"measurement": expected} if path == "/quality" else expected
                self.assertEqual(self.request(path=path), (200, result))
                self.assertEqual(called.call_count, 1)
                self.assertGreater(self.server_elapsed, 0.09)
            self.assert_alarm_restored(handler, mask)

    def test_admission_guard_restores_after_health_and_parser_errors(self):
        handler = signal.getsignal(signal.SIGALRM)
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        for request, status in ((b"GET /health HTTP/1.1\r\nHost: local\r\n\r\n", 200),
                                (b"BAD /health HTTP/1.1\r\nHost: local\r\n\r\n", 501),
                                (b"POST /quality HTTP/invalid\r\n\r\n", 400)):
            with self.subTest(status=status):
                response, _ = self.raw_request(request)
                self.assertIn(str(status).encode(), response)
                self.assert_alarm_restored(handler, mask)

    def test_exact_secret_selected_freshly_and_not_returned(self):
        with patch.object(server, "scan", return_value={"complete": True, "records": []}) as scan:
            self.assertEqual(self.request(), (200, {"complete": True, "records": []}))
            self.assertEqual(scan.call_args.args[1], SECRET)
            previous_inode = self.path.stat().st_ino
            self.write_fixture("rotated")
            self.assertNotEqual(self.path.stat().st_ino, previous_inode)
            self.assertEqual(self.request(), (200, {"complete": True, "records": []}))
            self.assertEqual(scan.call_args.args[1], dict(SECRET, accessToken="synthetic-rotated-token-only"))
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


    def test_quality_http_resolves_exact_private_credential_and_returns_only_measurement(self):
        self.payload = quality_payload()
        self.write_fixture("postgres")
        expected = quality_measurement()
        with patch.object(server, "execute_quality", return_value=expected) as execute, patch.object(server, "scan") as scan:
            response = self.request(path="/quality")
            self.assertEqual(response, (200, {"measurement": expected}))
            self.assertEqual(execute.call_args.args[0], self.payload["source"])
            self.assertEqual(execute.call_args.args[2:], ("harbor-tenant", self.payload["execution"]))
            self.assertEqual(execute.call_args.args[1]["username"], "synthetic-reader")
            self.assertEqual(execute.call_args.args[1]["password"], "synthetic-quality-test-password")
            self.assertNotIn("password", json.dumps(response))
            self.assertNotIn("source", response[1])
            self.assertNotIn("verdict", response[1]["measurement"])
            scan.assert_not_called()
            self.write_fixture("postgres-rotated")
            self.assertEqual(self.request(path="/quality"), response)
            self.assertEqual(execute.call_args.args[1]["password"], "synthetic-quality-rotated-password")

    def test_quality_malformed_envelopes_fail_before_any_credential_or_executor(self):
        valid = quality_payload()
        invalid = []
        for path in ((), ("execution",), ("execution", "target"), ("execution", "budget"), ("source",)):
            value = copy.deepcopy(valid)
            item = value
            for key in path:
                item = item[key]
            item["unexpected"] = True
            invalid.append(value)
        for key in ("tenantId", "source", "execution"):
            value = copy.deepcopy(valid)
            del value[key]
            invalid.append(value)
        for key, value in (("connectorId", "unity-catalog"), ("connectorId", None), ("secretRef", "../private")):
            item = copy.deepcopy(valid)
            item["source"][key] = value
            invalid.append(item)
        with patch.object(server, "resolve") as resolve, patch.object(server, "execute_quality") as execute, patch.object(server, "scan") as scan:
            for payload in invalid:
                with self.subTest(keys=list(payload)):
                    status, result = self.request(json.dumps(payload).encode(), path="/quality")
                    self.assertEqual(status, 400)
                    self.assertIn(result, ({"code": "INVALID_REQUEST"}, {"code": "QUALITY_INPUT_INVALID"}))
            resolve.assert_not_called()
            execute.assert_not_called()
            scan.assert_not_called()

    def test_quality_target_and_budget_admission_precedes_secret_resolution(self):
        values = []
        for key, value in (("databaseOid", "01"), ("relationOid", "4294967296"), ("attributeNumber", True),
                           ("attributeNumber", 32768), ("tableName", "é" * 32), ("dataType", "x" * 257)):
            payload = quality_payload()
            payload["execution"]["target"][key] = value
            values.append(payload)
        for key, value in (("maximumRows", 100001), ("maximumRows", True), ("maximumSeconds", 31),
                           ("statementTimeoutMs", 15001), ("maximumEstimatedCost", -1), ("maximumEstimatedBytes", 67108865)):
            payload = quality_payload()
            payload["execution"]["budget"][key] = value
            values.append(payload)
        with patch.object(server, "resolve") as resolve, patch.object(server, "execute_quality") as execute:
            for payload in values:
                self.assertEqual(self.request(json.dumps(payload).encode(), path="/quality"), (400, {"code": "QUALITY_INPUT_INVALID"}))
            mismatch = quality_payload()
            mismatch["execution"]["target"]["schemaName"] = "different"
            self.assertEqual(self.request(json.dumps(mismatch).encode(), path="/quality"), (422, {"code": "QUALITY_TARGET_STALE"}))
            resolve.assert_not_called()
            execute.assert_not_called()

    def test_quality_duplicate_unicode_nonfinite_and_physical_json_bounds(self):
        raw = json.dumps(quality_payload()).encode()
        invalid = [raw.replace(b'"formatVersion": 1', b'"formatVersion":1,"formatVersion":1'),
                   raw.replace(b'"maximumRows": 100000', b'"maximumRows":NaN'),
                   raw.replace(b'"maximumEstimatedCost": 1000000', b'"maximumEstimatedCost":1e999'),
                   raw.replace(b'"observations"', b'"\\ud800"'), raw.replace(b'"observations"', b'"\\u0000"'),
                   raw.replace(b'"observations"', b'"\xff"'), b'[' * 17 + b'0' + b']' * 17,
                   b'{"many":[' + b'0,' * 2048 + b'0]}']
        with patch.object(server, "resolve") as resolve, patch.object(server, "execute_quality") as execute:
            for value in invalid:
                self.assertEqual(self.request(value, path="/quality"), (400, {"code": "INVALID_REQUEST"}))
            self.assertEqual(self.request(raw, length=16385, path="/quality"), (413, {"code": "REQUEST_SIZE"}))
            resolve.assert_not_called()
            execute.assert_not_called()

    def test_quality_authentication_framing_and_path_are_exact(self):
        self.payload = quality_payload()
        base = [("Authorization", "Bearer " + TOKEN), ("Content-Type", "application/json")]
        with patch.object(server, "resolve") as resolve, patch.object(server, "execute_quality") as execute:
            for headers in (base[1:], [("Authorization", "Bearer wrong")] + base[1:], base + [base[0]]):
                self.assertEqual(self.request(headers=headers, path="/quality"), (401, {"code": "UNAUTHORIZED"}))
            for extra in ([('Content-Length', '1')], [('Transfer-Encoding', 'chunked')], [('Content-Encoding', 'gzip')], [('Content-Type', 'text/plain')]):
                self.assertEqual(self.request(headers=base + extra, path="/quality"), (400, {"code": "INVALID_REQUEST"}))
            for path in ("/quality/", "/quality?source=private", "/unknown"):
                self.assertEqual(self.request(path=path), (404, {"code": "NOT_FOUND"}))
            self.assertEqual(self.request(body=b'{}', length=3, half_close=True, path="/quality"), (400, {"code": "INVALID_REQUEST"}))
            resolve.assert_not_called()
            execute.assert_not_called()

    def test_quality_actual_partial_body_deadline_never_resolves_credentials(self):
        with patch.object(server, "REQUEST_SECONDS", 0.06), patch.object(server, "resolve") as resolve, patch.object(server, "execute_quality") as execute:
            self.assertEqual(self.request(body=b'{', length=100, trickle=True, path="/quality"), (408, {"code": "REQUEST_TIMEOUT"}))
            self.assertLess(self.server_elapsed, 0.2)
            resolve.assert_not_called()
            execute.assert_not_called()

    def test_quality_safe_executor_and_secret_failures_have_no_partial_measurement(self):
        self.payload = quality_payload()
        self.write_fixture("postgres")
        for code in ("QUALITY_RESOURCE_LIMIT", "QUALITY_TARGET_STALE", "QUALITY_TARGET_UNSUPPORTED", "SOURCE_DATABASE_ERROR", "SOURCE_DEADLINE_EXCEEDED"):
            with patch.object(server, "execute_quality", side_effect=ScanFailure(code)):
                self.assertEqual(self.request(path="/quality"), (422, {"code": code}))
        with patch.object(server, "execute_quality", side_effect=RuntimeError("synthetic credential, SQL and private row must not escape")):
            self.assertEqual(self.request(path="/quality"), (500, {"code": "WORKER_FAILURE"}))
        with patch.object(server, "execute_quality") as execute:
            self.payload["source"]["secretRef"] = "missing"
            self.assertEqual(self.request(path="/quality"), (422, {"code": "SECRET_REFERENCE_DENIED"}))
            self.payload = quality_payload()
            self.payload["tenantId"] = "another-tenant"
            self.assertEqual(self.request(path="/quality"), (422, {"code": "SOURCE_SCOPE_DENIED"}))
            execute.assert_not_called()

    def test_scan_and_quality_envelopes_cannot_be_interchanged(self):
        scan_payload = copy.deepcopy(self.payload)
        with patch.object(server, "resolve") as resolve, patch.object(server, "execute_quality") as execute, patch.object(server, "scan") as scan:
            self.assertEqual(self.request(json.dumps(quality_payload()).encode()), (400, {"code": "INVALID_REQUEST"}))
            self.assertEqual(self.request(json.dumps(scan_payload).encode(), path="/quality"), (400, {"code": "INVALID_REQUEST"}))
            resolve.assert_not_called()
            execute.assert_not_called()
            scan.assert_not_called()
        # The preceding failed quality request does not change the scan route.
        with patch.object(server, "scan", return_value={"complete": True, "records": []}) as scan, patch.object(server, "execute_quality") as execute:
            self.assertEqual(self.request(), (200, {"complete": True, "records": []}))
            self.assertEqual(scan.call_count, 1)
            execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
