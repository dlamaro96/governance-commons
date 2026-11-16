# SPDX-License-Identifier: Apache-2.0
"""One isolated Python execution process with an authenticated bounded HTTP boundary."""
import hmac
import json
import math
import os
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from .deadline import deadline
from .dispatch import scan
from .postgresql import ScanFailure
from .secrets import resolve

MAX_REQUEST_BYTES = 16384
REQUEST_SECONDS = 30


def request_payload(raw):
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

    if not 0 < len(raw) <= MAX_REQUEST_BYTES:
        raise ValueError("request size")
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
    if (not isinstance(value, dict) or set(value) != {"tenantId", "source"}
            or not isinstance(value["tenantId"], str) or not 1 <= len(value["tenantId"]) <= 128
            or not isinstance(value["source"], dict)):
        raise ValueError("request shape")
    source = value["source"]
    ref = source.get("secretRef")
    if (not isinstance(ref, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", ref)
            or source.get("connectorId", "postgresql") not in ("postgresql", "unity-catalog")):
        raise ValueError("source shape")
    return value


class WorkerServer(HTTPServer):
    def __init__(self, address, token, secrets_path):
        if (not isinstance(token, str) or not 32 <= len(token) <= 256
                or not token.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in token)):
            raise RuntimeError("WORKER_TOKEN is invalid")
        self.worker_token, self.secrets_path = token, secrets_path
        super().__init__(address, Handler)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def reply(self, code, value):
        body = json.dumps(value).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.reply(200 if self.path == "/health" else 404, {"status": "ready"} if self.path == "/health" else {"code": "NOT_FOUND"})

    def do_POST(self):
        self.connection.settimeout(REQUEST_SECONDS)
        self.close_connection = True
        if self.path != "/scan":
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
            if not 0 < size <= MAX_REQUEST_BYTES:
                return self.reply(413, {"code": "REQUEST_SIZE"})
            try:
                # End this body-read deadline before the adapter installs its
                # own scan deadline; slow partial requests cannot extend it.
                with deadline(REQUEST_SECONDS):
                    raw = self.rfile.read(size)
            except (TimeoutError, ScanFailure):
                return self.reply(408, {"code": "REQUEST_TIMEOUT"})
            if len(raw) != size:
                raise ValueError("short request")
            payload = request_payload(raw)
            source = payload["source"]
            secret = resolve(self.server.secrets_path, source["secretRef"], payload["tenantId"], source.get("connectorId", "postgresql"))
            result = (200, scan(source, secret, payload["tenantId"]))
        except ScanFailure as error:
            result = (422, {"code": error.code})
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
