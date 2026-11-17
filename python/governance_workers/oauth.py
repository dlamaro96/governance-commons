# SPDX-License-Identifier: Apache-2.0
"""Workspace OAuth M2M; short-lived tokens remain in this scan's memory only."""
import base64
import http.client
import ipaddress
import json
import math
import queue
import re
import socket
import ssl
import threading
import time

from .postgresql import ScanFailure

MAX_RESPONSE_BYTES = 64 * 1024
MAX_REQUEST_BYTES = 12 * 1024
MAX_SECONDS = 20
MIN_TOKEN_LIFETIME = 120
WORKSPACE = re.compile(r"[a-z0-9][a-z0-9.-]*\.(?:azuredatabricks\.net|cloud\.databricks\.com|gcp\.databricks\.com)\Z")
_DNS_SLOTS = threading.BoundedSemaphore(4)


def _fail(code):
    raise ScanFailure(code)


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        _fail("SOURCE_DEADLINE_EXCEEDED")
    return remaining


def _resolve(host, deadline):
    # getaddrinfo has no portable timeout. At most four daemon lookups may exist;
    # callers stop at their original deadline and never wait for an expired one.
    if not _DNS_SLOTS.acquire(blocking=False):
        _fail("SOURCE_TRANSPORT_ERROR")
    result = queue.Queue(maxsize=1)

    def lookup():
        try:
            result.put(socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM))
        except Exception:
            result.put(None)
        finally:
            _DNS_SLOTS.release()

    try:
        threading.Thread(target=lookup, daemon=True, name="uc-oauth-dns").start()
    except RuntimeError:
        _DNS_SLOTS.release()
        _fail("SOURCE_TRANSPORT_ERROR")
    try:
        addresses = result.get(timeout=_remaining(deadline))
    except queue.Empty:
        _fail("SOURCE_DEADLINE_EXCEEDED")
    _remaining(deadline)
    if not addresses or len(addresses) > 16:
        _fail("SOURCE_DESTINATION_DENIED")
    for family, kind, _, _, address in addresses:
        ip = ipaddress.ip_address(address[0])
        if (family not in (socket.AF_INET, socket.AF_INET6) or kind != socket.SOCK_STREAM
                or not ip.is_global or ip.is_multicast or address[1] != 443
                or (family == socket.AF_INET6 and address[3] != 0)):
            _fail("SOURCE_DESTINATION_DENIED")
    return addresses[0]


class _HeaderReader:
    def __init__(self, stream):
        self.stream, self.bytes, self.lines = stream, 0, 0

    def readline(self, limit=-1):
        line = self.stream.readline(min(limit if limit >= 0 else 8193, 8193))
        self.bytes += len(line)
        self.lines += 1
        if len(line) > 8192 or self.bytes > 16384 or self.lines > 64:
            _fail("SOURCE_RESPONSE_INVALID")
        return line

    def __getattr__(self, name):
        return getattr(self.stream, name)


class _Response(http.client.HTTPResponse):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fp = _HeaderReader(self.fp)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    response_class = _Response

    def __init__(self, host, deadline):
        super().__init__(host, 443, timeout=min(5, _remaining(deadline)), context=ssl.create_default_context())
        self.deadline = deadline
        self._deadline_socket = None

    def connect(self):
        family, kind, protocol, _, address = _resolve(self.host, self.deadline)
        raw = socket.socket(family, kind, protocol)
        self.sock = raw  # The deadline watchdog can interrupt connect/handshake.
        self._deadline_socket = raw
        try:
            raw.settimeout(min(5, _remaining(self.deadline)))
            raw.connect(address)
            _remaining(self.deadline)
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host, do_handshake_on_connect=False)
            self._deadline_socket = self.sock
            self.sock.settimeout(min(5, _remaining(self.deadline)))
            self.sock.do_handshake()
            _remaining(self.deadline)
        except BaseException:
            raw.close()
            raise


def _abort(conn):
    # shutdown wakes an active header/body read; close alone need not do so.
    # HTTPConnection detaches sock for Connection: close responses even while
    # their file stream is still reading. Keep the exact owned socket identity.
    sock = getattr(conn, "_deadline_socket", None) or conn.sock
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
    conn.close()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("SOURCE_RESPONSE_INVALID")
        result[key] = value
    return result


def _json_body(raw):
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
            if depth > 8:
                _fail("SOURCE_RESPONSE_INVALID")
        elif byte in (93, 125):
            depth -= 1
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                       parse_constant=lambda _: _fail("SOURCE_RESPONSE_INVALID"))
    pending, nodes = [value], 0
    while pending:
        item = pending.pop()
        nodes += 1
        if nodes > 2048:
            _fail("SOURCE_RESPONSE_INVALID")
        if isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str):
            item.encode("utf-8")  # Reject escaped lone surrogates in unknown fields too.
        elif isinstance(item, float) and not math.isfinite(item):
            _fail("SOURCE_RESPONSE_INVALID")
    return value


def _visible(value, minimum, maximum):
    return (isinstance(value, str) and minimum <= len(value) <= maximum
            and value.isascii() and all(32 < ord(c) < 127 for c in value))


def _target(secret, host):
    if (not isinstance(secret, dict) or not isinstance(host, str) or len(host) > 253
            or not WORKSPACE.fullmatch(host)
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split("."))
            or secret.get("workspaceUrl") != "https://" + host
            or secret.get("connectorId") != "unity-catalog"):
        _fail("SOURCE_DESTINATION_DENIED")


def token_for(secret, host):
    """Exactly one credential form: accessToken OR clientId + clientSecret.

    OAuth endpoint/scope are fixed, with no redirect, proxy, retries or cache.
    The caller must first authorize tenant and exact catalog/schema scope.
    """
    _target(secret, host)
    if "accessToken" in secret:
        if ("clientId" in secret or "clientSecret" in secret
                or not _visible(secret["accessToken"], 16, 8192)):
            _fail("SOURCE_CREDENTIAL_INVALID")
        return secret["accessToken"]
    client_id, client_secret = secret.get("clientId"), secret.get("clientSecret")
    if (not _visible(client_id, 1, 256) or ":" in client_id
            or not _visible(client_secret, 16, 8192)):
        _fail("SOURCE_CREDENTIAL_INVALID")
    basic = base64.b64encode((client_id + ":" + client_secret).encode("ascii")).decode("ascii")
    body = b"grant_type=client_credentials&scope=all-apis"
    if len(basic) + len(body) > MAX_REQUEST_BYTES:
        _fail("SOURCE_CREDENTIAL_INVALID")
    started = time.monotonic()
    deadline = started + MAX_SECONDS
    try:
        conn = PinnedHTTPSConnection(host, deadline)
    except (OSError, ValueError):
        raise ScanFailure("SOURCE_TRANSPORT_ERROR") from None
    timer = threading.Timer(_remaining(deadline), _abort, args=(conn,))
    timer.daemon = True
    response = None
    try:
        timer.start()
        conn.request("POST", "/oidc/v1/token", body=body, headers={
            "Authorization": "Basic " + basic, "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json", "Accept-Encoding": "identity"})
        _remaining(deadline)
        response = conn.getresponse()
        _remaining(deadline)
        if response.status != 200:
            _fail({400: "SOURCE_AUTHENTICATION_FAILED", 401: "SOURCE_AUTHENTICATION_FAILED",
                   403: "SOURCE_SCOPE_DENIED", 429: "SOURCE_RATE_LIMITED"}.get(response.status, "SOURCE_HTTP_ERROR"))
        headers = [key.lower() for key, _ in response.getheaders()]
        if (any(headers.count(key) > 1 for key in ("content-type", "content-length", "content-encoding", "transfer-encoding"))
                or ("content-length" in headers and "transfer-encoding" in headers)
                or response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json"
                or response.getheader("Content-Encoding", "identity").lower() != "identity"
                or response.getheader("Transfer-Encoding", "chunked").lower() != "chunked"):
            _fail("SOURCE_RESPONSE_INVALID")
        length = response.getheader("Content-Length")
        if length is not None and (not length.isascii() or not length.isdigit() or len(length) > 6 or int(length) > MAX_RESPONSE_BYTES):
            _fail("SOURCE_RESPONSE_INVALID")
        chunks, size = [], 0
        while True:
            remaining = _remaining(deadline)
            sock = getattr(conn, "_deadline_socket", None) or conn.sock
            if sock:
                sock.settimeout(min(5, remaining))
            block = response.read1(min(8192, MAX_RESPONSE_BYTES + 1 - size))
            _remaining(deadline)
            if not block:
                break
            size += len(block)
            if size > MAX_RESPONSE_BYTES:
                _fail("SOURCE_BYTE_LIMIT")
            chunks.append(block)
        if length is not None and int(length) != size:
            _fail("SOURCE_RESPONSE_INVALID")
        value = _json_body(b"".join(chunks))
        if (not isinstance(value, dict) or value.get("token_type") != "Bearer"
                or not _visible(value.get("access_token"), 16, 8192)
                or type(value.get("expires_in")) is not int
                or not MIN_TOKEN_LIFETIME <= value["expires_in"] <= 3600
                or value["expires_in"] - (time.monotonic() - started) < MIN_TOKEN_LIFETIME
                or ("scope" in value and value["scope"] != "all-apis")):
            _fail("SOURCE_RESPONSE_INVALID")
        _remaining(deadline)
        return value["access_token"]
    except ScanFailure:
        raise
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise ScanFailure("SOURCE_RESPONSE_INVALID") from None
    except (OSError, http.client.HTTPException, RuntimeError):
        _remaining(deadline)
        raise ScanFailure("SOURCE_TRANSPORT_ERROR") from None
    finally:
        timer.cancel()
        if response is not None:
            response.close()
        conn.close()
