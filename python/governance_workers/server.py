# SPDX-License-Identifier: Apache-2.0
"""One isolated Python execution process with an authenticated bounded HTTP boundary."""
from contextlib import ExitStack
import hmac
import json
import math
import os
import re
import socket
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from .deadline import deadline
from .dispatch import scan
from .quality import REFERENCE_KIND, execute as execute_quality, validate_execution
from .postgresql import ScanFailure
from .secrets import resolve

MAX_REQUEST_BYTES = 16384
MAX_REFERENCE_REQUEST_BYTES = 65536
REQUEST_SECONDS = 30
REJECT_DRAIN_BYTES = MAX_REFERENCE_REQUEST_BYTES + 1
REJECT_DRAIN_SECONDS = 0.1


class RequestSizeError(ValueError):
    """A bounded envelope exceeded its admitted family's byte limit."""


def request_payload(raw, operation="scan"):
    """Bound and reject ambiguous JSON before selecting any credential."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def invalid_constant(_value):
        raise ValueError("nonfinite constant")

    if operation not in ("scan", "quality"):
        raise ValueError("request operation")
    maximum = MAX_REFERENCE_REQUEST_BYTES if operation == 'quality' else MAX_REQUEST_BYTES
    if not 0 < len(raw) <= maximum:
        raise RequestSizeError("request size")
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 16:
                raise ValueError("request depth")
        elif byte in (93, 125):
            depth -= 1
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid_constant)
    pending, nodes = [value], 0
    while pending:
        item = pending.pop()
        nodes += 1
        if nodes > 2048:
            raise ValueError("request nodes")
        if isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str):
            item.encode("utf-8")
            if "\x00" in item:
                raise ValueError("NUL string")
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError("nonfinite number")
    if (not isinstance(value, dict) or set(value) != ({"tenantId", "source"} if operation == "scan" else {"tenantId", "source", "execution"})
            or not isinstance(value["tenantId"], str) or not 1 <= len(value["tenantId"]) <= 128
            or not isinstance(value["source"], dict)):
        raise ValueError("request shape")
    source = value["source"]
    ref = source.get("secretRef")
    if (not isinstance(ref, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", ref)
            or source.get("connectorId", "postgresql") not in ("postgresql", "unity-catalog")):
        raise ValueError("source shape")
    if operation == "quality":
        # The family is inside duplicate-aware JSON. Large quality framing is
        # not admission for completeness/uniqueness, unknown families or loose envelopes.
        execution = value['execution']
        if (len(raw) > MAX_REQUEST_BYTES and
                (type(execution) is not dict or execution.get('kind') != REFERENCE_KIND)):
            raise RequestSizeError("request size")
        if set(source) != {"connectorId", "host", "port", "database", "schema", "secretRef"} or source.get("connectorId") != "postgresql":
            raise ValueError("quality source shape")
        validate_execution(source, value["execution"])
    return value


class WorkerServer(HTTPServer):
    def __init__(self, address, token, secrets_path):
        if (not isinstance(token, str) or not 32 <= len(token) <= 256
                or not token.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in token)):
            raise RuntimeError("WORKER_TOKEN is invalid")
        self.worker_token, self.secrets_path = token, secrets_path
        super().__init__(address, Handler)

class Handler(BaseHTTPRequestHandler):
    def handle_one_request(self):
        # One absolute admission budget starts before the first request byte;
        # fresh bytes cannot extend it. The synchronous worker owns no timer
        # threads, and all EOF/error paths restore the process signal state.
        self._admission_deadline = time.monotonic() + REQUEST_SECONDS
        self.connection.settimeout(REQUEST_SECONDS)
        try:
            with ExitStack() as admission:
                self._admission = admission
                admission.enter_context(deadline(REQUEST_SECONDS))
                super().handle_one_request()
        except (ScanFailure, TimeoutError, ConnectionError):
            # Incomplete request lines/headers need not have response state yet.
            self.close_connection = True
        finally:
            self._admission = None

    def log_message(self, *_args):
        pass

    def reply(self, code, value):
        body = json.dumps(value).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        if getattr(self, "_unread_request_body", False):
            self._unread_request_body = False
            self._drain_refused_body()

    def _drain_refused_body(self):
        # Closing a TCP socket with an unread request can reset an already sent
        # refusal. Publish the response/FIN first, then discard a bounded suffix.
        # Never parse it, retain it, or restart the original admission deadline.
        self.wfile.flush()
        try:
            self.connection.shutdown(socket.SHUT_WR)
            expires = min(self._admission_deadline, time.monotonic() + REJECT_DRAIN_SECONDS)
            remaining_bytes = REJECT_DRAIN_BYTES
            while remaining_bytes:
                remaining_seconds = expires - time.monotonic()
                if remaining_seconds <= 0:
                    break
                self.connection.settimeout(remaining_seconds)
                discarded = self.connection.recv(min(8192, remaining_bytes))
                if not discarded:
                    break
                remaining_bytes -= len(discarded)
        except OSError:
            # Timeout, peer reset and disconnected peers all finish this refusal.
            # ScanFailure intentionally propagates to the original deadline guard.
            pass

    def do_GET(self):
        self.reply(200 if self.path == "/health" else 404, {"status": "ready"} if self.path == "/health" else {"code": "NOT_FOUND"})

    def do_POST(self):
        self.close_connection = True
        self._unread_request_body = True
        if self.path not in ("/scan", "/quality"):
            return self.reply(404, {"code": "NOT_FOUND"})
        authorization = self.headers.get_all("Authorization", [])
        if (len(authorization) != 1 or not authorization[0].isascii()
                or not hmac.compare_digest(authorization[0], f"Bearer {self.server.worker_token}")):
            return self.reply(401, {"code": "UNAUTHORIZED"})
        try:
            for name in ("Content-Length", "Content-Type", "Content-Encoding"):
                if len(self.headers.get_all(name, [])) > 1:
                    raise ValueError("duplicate header")
            if (self.headers.get_all("Transfer-Encoding", [])
                    or self.headers.get("Content-Type", "").lower() not in ("application/json", "application/json; charset=utf-8")
                    or self.headers.get("Content-Encoding", "identity").lower() != "identity"):
                raise ValueError("request framing")
            length = self.headers.get("Content-Length", "0")
            if not length.isascii() or not length.isdigit() or len(length) > 8:
                raise ValueError("request length")
            size = int(length)
            maximum = MAX_REFERENCE_REQUEST_BYTES if self.path == '/quality' else MAX_REQUEST_BYTES
            if not 0 < size <= maximum:
                return self.reply(413, {"code": "REQUEST_SIZE"})
            try:
                # The request line and headers already consumed part of this
                # same admission budget; do not restart it for the body.
                raw = self.rfile.read(size)
                self._unread_request_body = False
            except (TimeoutError, ScanFailure):
                return self.reply(408, {"code": "REQUEST_TIMEOUT"})
            if len(raw) != size:
                raise ValueError("short request")
            payload = request_payload(raw, "quality" if self.path == "/quality" else "scan")
            source = payload["source"]
            # Credential/provider access and adapters have their own deadlines.
            # Close admission first so the adapter keeps its full scan budget.
            self._admission.close()
            self._admission = None
            secret = resolve(self.server.secrets_path, source["secretRef"], payload["tenantId"], source.get("connectorId", "postgresql"))
            result = (200, {"measurement": execute_quality(source, secret, payload["tenantId"], payload["execution"])}) if self.path == "/quality" else (200, scan(source, secret, payload["tenantId"]))
        except ScanFailure as error:
            if self._admission is not None and error.code == "SOURCE_DEADLINE_EXCEEDED":
                result = (408, {"code": "REQUEST_TIMEOUT"})
            else:
                result = (400 if error.code == "QUALITY_INPUT_INVALID" else 422, {"code": error.code})
        except RequestSizeError:
            result = (413, {"code": "REQUEST_SIZE"})
        except (ValueError, KeyError, TypeError, RecursionError):
            result = (400, {"code": "INVALID_REQUEST"})
        except Exception:
            result = (500, {"code": "WORKER_FAILURE"})
        self.reply(*result)


def main():
    with WorkerServer(("0.0.0.0", 8080), os.environ["WORKER_TOKEN"], os.environ["SOURCE_SECRETS_FILE"]) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
