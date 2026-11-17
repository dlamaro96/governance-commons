# SPDX-License-Identifier: Apache-2.0
"""Protocol/transport negatives with synthetic credentials, not live UC proof."""
import base64
import io
import json
import socket
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from governance_workers import oauth
from governance_workers.postgresql import ScanFailure

HOST = "adb-123456789.1.azuredatabricks.net"
SECRET = {"connectorId": "unity-catalog", "workspaceUrl": "https://" + HOST,
          "clientId": "synthetic-client", "clientSecret": "synthetic-client-secret"}
TOKEN = "synthetic-access-token-for-tests"
SUCCESS = {"token_type": "Bearer", "access_token": TOKEN, "expires_in": 3600, "scope": "all-apis"}


class Response:
    def __init__(self, raw=None, status=200, headers=None):
        self.status = status
        self.body = io.BytesIO(raw if raw is not None else json.dumps(SUCCESS).encode())
        self.headers = [("Content-Type", "application/json")] if headers is None else headers

    def getheaders(self):
        return self.headers

    def getheader(self, key, default=None):
        return next((v for k, v in self.headers if k.lower() == key.lower()), default)

    def read1(self, count):
        return self.body.read(count)

    def close(self):
        self.body.close()


class OAuthTest(unittest.TestCase):
    def request(self, response=None, secret=None):
        connection = MagicMock()
        connection.sock = None
        connection.getresponse.return_value = response or Response()
        with patch.object(oauth, "PinnedHTTPSConnection", return_value=connection) as factory:
            token = oauth.token_for(SECRET if secret is None else secret, HOST)
        connection.close.assert_called()
        return token, connection, factory

    def rejected(self, response, code="SOURCE_RESPONSE_INVALID"):
        with self.assertRaises(ScanFailure) as caught:
            self.request(response)
        self.assertEqual(str(caught.exception), code)

    def test_exact_fixed_workspace_m2m_request_and_only_token_returned(self):
        token, connection, factory = self.request()
        self.assertEqual(token, TOKEN)
        self.assertEqual(factory.call_args.args[0], HOST)
        args, kwargs = connection.request.call_args
        self.assertEqual(args, ("POST", "/oidc/v1/token"))
        self.assertEqual(kwargs["body"], b"grant_type=client_credentials&scope=all-apis")
        credentials = base64.b64decode(kwargs["headers"]["Authorization"].removeprefix("Basic ")).decode()
        self.assertEqual(credentials, SECRET["clientId"] + ":" + SECRET["clientSecret"])
        self.assertEqual(kwargs["headers"]["Accept-Encoding"], "identity")

    def test_rotated_client_secret_is_used_without_cache(self):
        _, first, _ = self.request()
        _, second, _ = self.request(secret=dict(SECRET, clientSecret="synthetic-rotated-secret"))
        self.assertNotEqual(first.request.call_args.kwargs["headers"]["Authorization"],
                            second.request.call_args.kwargs["headers"]["Authorization"])

    def test_explicit_static_token_has_no_network_and_mixed_forms_refused(self):
        static = {k: SECRET[k] for k in ("connectorId", "workspaceUrl")}
        with patch.object(oauth, "PinnedHTTPSConnection", side_effect=AssertionError("no exchange")):
            self.assertEqual(oauth.token_for(dict(static, accessToken=TOKEN), HOST), TOKEN)
            for extra in ({"clientId": "one"}, {"clientSecret": "secret"}):
                with self.assertRaisesRegex(ScanFailure, "SOURCE_CREDENTIAL_INVALID"):
                    oauth.token_for(dict(static, accessToken=TOKEN, **extra), HOST)

    def test_bad_credentials_or_destination_rejected_before_transport(self):
        cases = [(dict(SECRET, clientId="id:other"), HOST, "SOURCE_CREDENTIAL_INVALID"),
                 (dict(SECRET, clientSecret="bad\r\nsecret-value"), HOST, "SOURCE_CREDENTIAL_INVALID"),
                 (dict(SECRET, clientSecret=None), HOST, "SOURCE_CREDENTIAL_INVALID"),
                 (dict(SECRET, workspaceUrl="https://other.cloud.databricks.com"), HOST, "SOURCE_DESTINATION_DENIED"),
                 (SECRET, "localhost", "SOURCE_DESTINATION_DENIED"),
                 (dict(SECRET, workspaceUrl="https://a..cloud.databricks.com"), "a..cloud.databricks.com", "SOURCE_DESTINATION_DENIED")]
        with patch.object(oauth, "PinnedHTTPSConnection", side_effect=AssertionError("must not connect")):
            for secret, host, code in cases:
                with self.subTest(code=code), self.assertRaisesRegex(ScanFailure, code):
                    oauth.token_for(secret, host)

    def test_status_failures_do_not_follow_redirects_or_expose_bodies(self):
        for status, code in ((302, "SOURCE_HTTP_ERROR"), (307, "SOURCE_HTTP_ERROR"),
                             (400, "SOURCE_AUTHENTICATION_FAILED"), (401, "SOURCE_AUTHENTICATION_FAILED"),
                             (403, "SOURCE_SCOPE_DENIED"), (429, "SOURCE_RATE_LIMITED"), (500, "SOURCE_HTTP_ERROR")):
            with self.subTest(status=status):
                response = Response(b"synthetic-private-provider-error", status)
                response.read1 = MagicMock(side_effect=AssertionError("error body must not be read"))
                self.rejected(response, code)
                self.assertTrue(response.body.closed)

    def test_response_fields_and_lifetime_are_strict(self):
        for key, value in (("token_type", "MAC"), ("access_token", "bad\ntoken"), ("access_token", "x" * 8193),
                           ("expires_in", True), ("expires_in", "3600"), ("expires_in", 0),
                           ("expires_in", 119), ("expires_in", 3601), ("scope", "other")):
            with self.subTest(field=key, value_type=type(value).__name__):
                self.rejected(Response(json.dumps(dict(SUCCESS, **{key: value})).encode()))
        for key in ("token_type", "access_token", "expires_in"):
            body = dict(SUCCESS)
            del body[key]
            self.rejected(Response(json.dumps(body).encode()))

    def test_optional_scope_and_valid_content_length(self):
        body = {k: v for k, v in SUCCESS.items() if k != "scope"}
        raw = json.dumps(body).encode()
        token, _, _ = self.request(Response(raw, headers=[("Content-Type", "application/json; charset=utf-8"),
                                                         ("Content-Length", str(len(raw)))]))
        self.assertEqual(token, TOKEN)

    def test_response_encodings_and_ambiguous_framing_refused(self):
        for headers in ([('Content-Type', 'text/html')], [('Content-Type', 'application/json'), ('Content-Encoding', 'gzip')],
                        [('Content-Type', 'application/json'), ('Content-Length', '65537')],
                        [('Content-Type', 'application/json'), ('Content-Length', '1')],
                        [('Content-Type', 'application/json'), ('Content-Length', '1'), ('Content-Length', '2')],
                        [('Content-Type', 'application/json'), ('Content-Length', '1'), ('Transfer-Encoding', 'chunked')],
                        [('Content-Type', 'application/json'), ('Transfer-Encoding', 'gzip')]):
            with self.subTest(headers=headers):
                self.rejected(Response(headers=headers))

    def test_duplicate_keys_malformed_json_and_body_cap(self):
        for raw in (b'{"access_token":"one","access_token":"two"}', b'{"x":NaN}', b'[]', b'\xff', b'{',
                    json.dumps(dict(SUCCESS, unknown="\ud800")).encode(),
                    json.dumps(dict(SUCCESS, unknown=[0] * 2048)).encode(),
                    json.dumps(SUCCESS).encode()[:-1] + b',"unknown":1e999}',
                    b'[' * 9 + b'0' + b']' * 9):
            with self.subTest(length=len(raw)):
                self.rejected(Response(raw))
        self.rejected(Response(b" " * (oauth.MAX_RESPONSE_BYTES + 1)), "SOURCE_BYTE_LIMIT")

    def test_detached_response_is_closed_even_while_failure_is_retained(self):
        response = Response(b'{"access_token":"one","access_token":"two"}')
        with self.assertRaises(ScanFailure) as caught:
            self.request(response)
        self.assertEqual(caught.exception.code, "SOURCE_RESPONSE_INVALID")
        self.assertTrue(response.body.closed)

    def test_network_errors_are_sanitized_and_connection_closed(self):
        connection = MagicMock()
        connection.request.side_effect = OSError("synthetic-credential-in-error")
        with patch.object(oauth, "PinnedHTTPSConnection", return_value=connection), self.assertRaises(ScanFailure) as caught:
            oauth.token_for(SECRET, HOST)
        self.assertEqual(str(caught.exception), "SOURCE_TRANSPORT_ERROR")
        self.assertTrue(caught.exception.__suppress_context__)
        connection.close.assert_called()
        with patch.object(oauth, "PinnedHTTPSConnection", side_effect=OSError("private-certificate-path")), \
                self.assertRaisesRegex(ScanFailure, "SOURCE_TRANSPORT_ERROR"):
            oauth.token_for(SECRET, HOST)

    def test_public_dns_pin_and_tls_original_hostname(self):
        address = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))
        raw, secure, context = MagicMock(), MagicMock(), MagicMock()
        context.wrap_socket.return_value = secure
        with patch.object(oauth.socket, "getaddrinfo", return_value=[address]), patch.object(oauth.socket, "socket", return_value=raw), \
                patch.object(oauth.ssl, "create_default_context", return_value=context):
            conn = oauth.PinnedHTTPSConnection(HOST, time.monotonic() + 2)
            conn.connect()
            self.assertIs(conn.sock, secure)
            raw.connect.assert_called_once_with(("8.8.8.8", 443))
            context.wrap_socket.assert_called_once_with(raw, server_hostname=HOST, do_handshake_on_connect=False)
            secure.do_handshake.assert_called_once_with()
            conn.close()

    def test_any_private_loopback_or_multicast_dns_address_refused(self):
        for ip in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "224.0.0.1"):
            answer = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, 443))]
            with self.subTest(ip=ip), patch.object(oauth.socket, "getaddrinfo", return_value=answer), \
                    self.assertRaisesRegex(ScanFailure, "SOURCE_DESTINATION_DENIED"):
                oauth._resolve(HOST, time.monotonic() + 1)

    def test_dns_wait_obeys_original_deadline_and_bounded_slots(self):
        release = threading.Event()

        def lookup(*_args, **_kwargs):
            release.wait(1)
            return []

        started = time.monotonic()
        try:
            with patch.object(oauth.socket, "getaddrinfo", side_effect=lookup), \
                    self.assertRaisesRegex(ScanFailure, "SOURCE_DEADLINE_EXCEEDED"):
                oauth._resolve(HOST, started + 0.03)
            self.assertLess(time.monotonic() - started, 0.5)
        finally:
            release.set()
        with patch.object(oauth._DNS_SLOTS, "acquire", return_value=False), \
                self.assertRaisesRegex(ScanFailure, "SOURCE_TRANSPORT_ERROR"):
            oauth._resolve(HOST, time.monotonic() + 1)

    def test_real_header_parser_limits_before_body_materialization(self):
        for response in (b"HTTP/1.1 200 OK\r\nX-Large: " + b"x" * 8192 + b"\r\n\r\n",
                         b"HTTP/1.1 200 OK\r\n" + b"X: ok\r\n" * 65 + b"\r\n"):
            sock = MagicMock()
            sock.makefile.return_value = io.BytesIO(response)
            parser = oauth._Response(sock)
            with self.assertRaisesRegex(ScanFailure, "SOURCE_RESPONSE_INVALID"):
                parser.begin()
            parser.close()

    def test_real_blocked_header_read_is_interrupted_by_original_deadline(self):
        client, peer = socket.socketpair()
        self.addCleanup(peer.close)
        self.addCleanup(client.close)

        class BlockedConnection:
            def __init__(self):
                self.sock = client

            def request(self, *_args, **_kwargs):
                pass

            def getresponse(self):
                response = oauth._Response(client)
                try:
                    response.begin()
                    return response
                except BaseException:
                    response.close()
                    raise

            def close(self):
                client.close()

        started = time.monotonic()
        with patch.object(oauth, "MAX_SECONDS", 0.05), patch.object(oauth, "PinnedHTTPSConnection", return_value=BlockedConnection()), \
                self.assertRaisesRegex(ScanFailure, "SOURCE_DEADLINE_EXCEEDED"):
            oauth.token_for(SECRET, HOST)
        self.assertLess(time.monotonic() - started, 0.5)

    def test_connection_close_body_keeps_deadline_socket_until_read_finishes(self):
        client, peer = socket.socketpair()
        release = threading.Event()
        self.addCleanup(peer.close)
        self.addCleanup(client.close)
        connection = oauth.PinnedHTTPSConnection(HOST, time.monotonic() + 1)
        connection.sock = client
        connection._deadline_socket = client

        def serve():
            try:
                peer.recv(4096)
                peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                             b"Content-Length: 1024\r\nConnection: close\r\n\r\n{")
                release.wait(1)
            except OSError:
                pass

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        started = time.monotonic()
        try:
            with patch.object(oauth, "MAX_SECONDS", 0.05), patch.object(oauth, "PinnedHTTPSConnection", return_value=connection), \
                    self.assertRaisesRegex(ScanFailure, "SOURCE_DEADLINE_EXCEEDED"):
                oauth.token_for(SECRET, HOST)
            self.assertLess(time.monotonic() - started, 0.5)
            self.assertIsNone(connection.sock)  # CPython detached it before body read.
        finally:
            release.set()
            thread.join(1)

    def test_tls_handshake_is_published_before_blocking_and_deadline_interrupts_it(self):
        client, peer = socket.socketpair()
        self.addCleanup(peer.close)

        class ConnectedSocket(socket.socket):
            def connect(self, _address):
                pass  # Already connected socketpair, actual SSL handshake below.

        raw = ConnectedSocket(fileno=client.detach())
        self.addCleanup(raw.close)
        address = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))
        started = time.monotonic()
        with patch.object(oauth, "MAX_SECONDS", 0.05), patch.object(oauth, "_resolve", return_value=address), \
                patch.object(oauth.socket, "socket", return_value=raw), \
                self.assertRaisesRegex(ScanFailure, "SOURCE_DEADLINE_EXCEEDED"):
            oauth.token_for(SECRET, HOST)
        self.assertLess(time.monotonic() - started, 0.5)


if __name__ == "__main__":
    unittest.main()
