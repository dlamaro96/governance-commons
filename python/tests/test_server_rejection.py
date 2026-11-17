# SPDX-License-Identifier: Apache-2.0
"""Actual owned loopback early-refusal transport; no source execution."""
import json
import select
import signal
import socket
import threading
import time
import unittest
from unittest.mock import patch

from governance_workers import server
import test_server as baseline


class RefusalTransport(unittest.TestCase):
    setUp = baseline.WorkerHTTPTest.setUp
    write_fixture = baseline.WorkerHTTPTest.write_fixture
    request = baseline.WorkerHTTPTest.request
    assert_alarm_restored = baseline.WorkerHTTPTest.assert_alarm_restored

    def test_full_bounded_early_refusals_deliver_exact_response_without_reset(self):
        base = [('Authorization', 'Bearer ' + baseline.TOKEN), ('Content-Type', 'application/json')]
        cases = [(b'x' * 65537, base, '/quality', 413, 'REQUEST_SIZE'),
                 (b'x' * 65536, base + [('Content-Encoding', 'gzip')], '/quality', 400, 'INVALID_REQUEST'),
                 (b'x' * 65536, base + [('Transfer-Encoding', 'chunked')], '/quality', 400, 'INVALID_REQUEST'),
                 (b'x' * 65536, base + [('Content-Length', '65536')], '/quality', 400, 'INVALID_REQUEST'),
                 (b'x' * 65536, base[1:], '/quality', 401, 'UNAUTHORIZED'),
                 (b'x' * 16385, base, '/scan', 413, 'REQUEST_SIZE'),
                 (b'x' * 65536, base, '/unavailable', 404, 'NOT_FOUND')]
        with patch.object(server, 'request_payload') as parse, patch.object(server, 'resolve') as resolve, \
             patch.object(server, 'execute_quality') as execute, patch.object(server, 'scan') as scan:
            for body, headers, path, status, code in cases:
                with self.subTest(status=status, code=code, path=path):
                    # Existing helper reads all the way to EOF and rejects RST.
                    self.assertEqual(self.request(body, headers, path=path), (status, {'code': code}))
            parse.assert_not_called(); resolve.assert_not_called(); execute.assert_not_called(); scan.assert_not_called()

    def exchange(self, *, body=b'', header_delay=0, send_for=0, measure_reads=False):
        received, errors, sent, drained = [], [], [], []
        initial = b'POST /quality HTTP/1.1\r\nHost: local\r\n'
        suffix = b'Content-Type: application/json\r\nContent-Length: 999999\r\n\r\n'
        started = time.monotonic()
        def client():
            try:
                with socket.create_connection(self.http.server_address, timeout=2) as connection:
                    connection.sendall(initial)
                    if header_delay: time.sleep(header_delay)
                    connection.sendall(suffix + body)
                    until = time.monotonic() + send_for
                    eof = False
                    while time.monotonic() < until:
                        # Observe the already published refusal/FIN while this
                        # adversarial peer continues to send its discarded body.
                        if not eof and select.select([connection], [], [], 0)[0]:
                            data = connection.recv(65536)
                            if data: received.append(data)
                            else: eof = True
                        try: connection.sendall(b'x'); sent.append(1)
                        except (BrokenPipeError, ConnectionResetError): break
                        time.sleep(.01)
                    while not eof:
                        try: data = connection.recv(65536)
                        except ConnectionResetError:
                            # This adversarial peer deliberately exceeds the discard cap.
                            if len(body) > server.REJECT_DRAIN_BYTES: break
                            raise
                        if not data: break
                        received.append(data)
            except BaseException as error: errors.append(error)
        original = server.Handler._drain_refused_body
        def observed(handler):
            connection = handler.connection
            class Observed:
                def __getattr__(self, name): return getattr(connection, name)
                def recv(self, size):
                    data = connection.recv(size); drained.append(len(data)); return data
            handler.connection = Observed()
            try: return original(handler)
            finally: handler.connection = connection
        thread = threading.Thread(target=client)
        thread.start()
        try:
            with patch.object(server.Handler, '_drain_refused_body', observed if measure_reads else original):
                self.http.handle_request()
            elapsed = time.monotonic() - started
        finally: thread.join(2)
        self.assertFalse(thread.is_alive())
        if errors: raise errors[0]
        response = b''.join(received)
        head, payload = response.split(b'\r\n\r\n', 1)
        self.assertEqual(int(head.split(b' ', 2)[1]), 401)
        self.assertEqual(json.loads(payload), {'code': 'UNAUTHORIZED'})
        self.assertIn(b'Content-Length: ' + str(len(payload)).encode(), head)
        return elapsed, sent, drained

    def test_slow_sender_cannot_extend_discard_window(self):
        handler = signal.getsignal(signal.SIGALRM)
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        with patch.object(server, 'request_payload') as parse, patch.object(server, 'resolve') as resolve:
            elapsed, sent, _ = self.exchange(send_for=.2)
            self.assertGreaterEqual(len(sent), 4)
            self.assertGreaterEqual(elapsed, .075)
            self.assertLess(elapsed, .2)
            parse.assert_not_called(); resolve.assert_not_called()
        self.assert_alarm_restored(handler, mask)

    def test_discard_never_extends_original_request_deadline(self):
        handler = signal.getsignal(signal.SIGALRM)
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        with patch.object(server, 'REQUEST_SECONDS', .06), patch.object(server, 'resolve') as resolve:
            elapsed, _, _ = self.exchange(header_delay=.035, send_for=.08)
            self.assertGreaterEqual(elapsed, .045)
            self.assertLess(elapsed, .11)
            resolve.assert_not_called()
        self.assert_alarm_restored(handler, mask)

    def test_discard_has_actual_receive_byte_cap(self):
        with patch.object(server, 'request_payload') as parse, patch.object(server, 'resolve') as resolve:
            elapsed, _, drained = self.exchange(body=b'x' * 200000, measure_reads=True)
            self.assertEqual(sum(drained), 65537)
            self.assertLess(elapsed, .2)
            parse.assert_not_called(); resolve.assert_not_called()

    def test_timeout_frame_requires_exact_bounded_body_without_masking_reset(self):
        body = b'{"code": "REQUEST_TIMEOUT"}'
        header = b'HTTP/1.0 408 Request Timeout\r\nContent-Type: application/json\r\nContent-Length: 27\r\n\r\n'
        self.assertTrue(baseline.complete_timeout_frame(header + body))
        self.assertFalse(baseline.complete_timeout_frame(header + body[:-1]))
        self.assertFalse(baseline.complete_timeout_frame(header[:-1]))
        for bad in (header + body + b'x', header.replace(b'408', b'200') + body,
                    header.replace(b'27', b'9999') + body,
                    header.replace(b'27', b'27\r\nContent-Length: 27') + body,
                    header.replace(b'27', b'27\r\nTransfer-Encoding: chunked') + body,
                    header.replace(b'27', b'+27') + body,
                    header.replace(b'application/json', b'text/plain') + body,
                    header + body.replace(b'REQUEST_TIMEOUT', b'INVALID_TIMEOUT')):
            with self.assertRaises((ValueError, json.JSONDecodeError)):
                baseline.complete_timeout_frame(bad)

    def test_admitted_complete_body_has_no_refusal_drain(self):
        with patch.object(server.Handler, '_drain_refused_body') as drain, \
             patch.object(server, 'scan', return_value={'complete': True, 'records': []}):
            self.assertEqual(self.request(), (200, {'complete': True, 'records': []}))
            drain.assert_not_called()


if __name__ == '__main__': unittest.main()
