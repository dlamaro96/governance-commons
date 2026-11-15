# SPDX-License-Identifier: Apache-2.0
"""One isolated Python execution process with an authenticated bounded HTTP boundary."""
import hmac
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from .postgresql import scan, ScanFailure

TOKEN = os.environ["WORKER_TOKEN"]
if len(TOKEN) < 32:
    raise RuntimeError("WORKER_TOKEN requires at least 32 characters")
with open(os.environ["SOURCE_SECRETS_FILE"], encoding="utf-8") as handle:
    SECRETS = json.load(handle)

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
        self.connection.settimeout(30)
        if self.path != "/scan":
            return self.reply(404, {"code": "NOT_FOUND"})
        if not hmac.compare_digest(self.headers.get("Authorization", ""), f"Bearer {TOKEN}"):
            return self.reply(401, {"code": "UNAUTHORIZED"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 16384:
                return self.reply(413, {"code": "REQUEST_SIZE"})
            payload = json.loads(self.rfile.read(size))
            source = payload["source"]
            secret = SECRETS.get(source["secretRef"])
            if not secret:
                return self.reply(403, {"code": "SECRET_REFERENCE_DENIED"})
            return self.reply(200, scan(source, secret, payload["tenantId"]))
        except ScanFailure as error:
            return self.reply(422, {"code": error.code})
        except (ValueError, KeyError, TypeError):
            return self.reply(400, {"code": "INVALID_REQUEST"})
        except Exception:
            return self.reply(500, {"code": "WORKER_FAILURE"})

HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
