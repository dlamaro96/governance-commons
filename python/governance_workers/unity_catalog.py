# SPDX-License-Identifier: Apache-2.0
"""Read-only Unity Catalog REST metadata extraction; no SQL or source writes.

An exhausted permission-filtered listing is observation, not proof of absence.
The result therefore never authorizes absence reconciliation. Transport targets
and credentials come from a tenant-bound local secret, not source metadata.
"""
import hashlib
import http.client
import json
import math
import re
import threading
import time
from datetime import datetime, timezone
from urllib.parse import quote, urlencode, urlsplit
from uuid import UUID

from .postgresql import MAX_BYTES, MAX_RECORDS, ScanFailure
from .deadline import deadline
from .oauth import PinnedHTTPSConnection as _PinnedHTTPSConnection, _Response, _abort, _remaining, token_for

MAX_PAGES = 200
MAX_SECONDS = 90
MAX_PAGE_BYTES = 2 * 1024 * 1024
API = "/api/2.1/unity-catalog"
WORKSPACE = re.compile(r"[a-z0-9][a-z0-9.-]*\.(?:azuredatabricks\.net|cloud\.databricks\.com|gcp\.databricks\.com)\Z")
TABLE_TYPES = {"MANAGED", "EXTERNAL", "VIEW", "MATERIALIZED_VIEW", "STREAMING_TABLE",
               "MANAGED_SHALLOW_CLONE", "EXTERNAL_SHALLOW_CLONE", "FOREIGN", "METRIC_VIEW"}


def fail(code):
    raise ScanFailure(code)


def text(value, maximum=512):
    if not isinstance(value, str) or not value or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        fail("SOURCE_RESPONSE_INVALID")
    try:
        value.encode("utf-8")
    except UnicodeError:
        fail("SOURCE_RESPONSE_INVALID")
    return value


def identifier(value):
    value = text(value, 36)
    try:
        if str(UUID(value)) != value.lower() or UUID(value).int == 0:
            fail("SOURCE_RESPONSE_INVALID")
    except ValueError:
        fail("SOURCE_RESPONSE_INVALID")
    return value.lower()


def validate_target(source, secret, tenant_id):
    if not isinstance(source, dict) or not isinstance(secret, dict):
        fail("SOURCE_TARGET_DENIED")
    if not isinstance(secret.get("tenantIds"), list) or tenant_id not in secret["tenantIds"]:
        fail("SOURCE_SCOPE_DENIED")
    if source.get("connectorId") != "unity-catalog" or secret.get("connectorId") != "unity-catalog":
        fail("SOURCE_TARGET_DENIED")
    for key in ("workspaceUrl", "catalog", "schema"):
        if not isinstance(source.get(key), str) or not source[key] or source[key] != secret.get(key):
            fail("SOURCE_TARGET_DENIED")
    try:
        url = urlsplit(secret["workspaceUrl"])
        host = url.hostname
        if (url.scheme != "https" or not host or not WORKSPACE.fullmatch(host)
                or url.netloc != host or url.path or url.query or url.fragment):
            fail("SOURCE_DESTINATION_DENIED")
    except ValueError:
        fail("SOURCE_DESTINATION_DENIED")
    for key in ("catalog", "schema"):
        if len(source[key]) > 255 or any(ord(c) < 32 or ord(c) == 127 or c in ". /\\" for c in source[key]):
            fail("SOURCE_TARGET_DENIED")
        try:
            source[key].encode("utf-8")
        except UnicodeError:
            fail("SOURCE_TARGET_DENIED")
    # Non-secret identity label makes credential rotation independent of scan identity.
    principal = secret.get("principalId")
    if (not isinstance(principal, str) or not 1 <= len(principal) <= 256
            or any(ord(c) < 32 or ord(c) == 127 for c in principal)):
        fail("SOURCE_CREDENTIAL_INVALID")
    try:
        principal.encode("utf-8")
    except UnicodeError:
        fail("SOURCE_CREDENTIAL_INVALID")
    return host


class _ChunkReader:
    """Bound chunk framing separately from initial headers and decoded bytes."""
    def __init__(self, stream):
        self.stream, self.bytes = stream, 0

    def readline(self, limit=-1):
        line = self.stream.readline(min(limit if limit >= 0 else 8193, 8193))
        self.bytes += len(line)
        if len(line) > 8192 or self.bytes > 65536:
            fail("SOURCE_RESPONSE_INVALID")
        return line

    def read(self, count):
        # HTTPResponse.read1 uses read(2) only for each chunk's trailing CRLF;
        # decoded payload uses read1 and is charged by Client instead.
        if count != 2:
            fail("SOURCE_RESPONSE_INVALID")
        block = self.stream.read(count)
        self.bytes += len(block)
        if self.bytes > 65536:
            fail("SOURCE_RESPONSE_INVALID")
        return block

    def __getattr__(self, name):
        return getattr(self.stream, name)


class _MetadataResponse(_Response):
    def begin(self):
        super().begin()
        if self.chunked and self.fp is not None and not isinstance(self.fp, _ChunkReader):
            # The shared initial-header parser remains capped at 64 lines and
            # 16KiB. Metadata may legitimately span more than 64 body chunks.
            self.fp = _ChunkReader(self.fp.stream)


class PinnedHTTPSConnection(_PinnedHTTPSConnection):
    response_class = _MetadataResponse


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            fail("SOURCE_RESPONSE_INVALID")
        value[key] = item
    return value


def _metadata_json(raw):
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
            if depth > 32:
                fail("SOURCE_RESPONSE_INVALID")
        elif byte in (93, 125):
            depth -= 1
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                       parse_constant=lambda _: fail("SOURCE_RESPONSE_INVALID"))
    pending, nodes = [value], 0
    while pending:
        item = pending.pop()
        nodes += 1
        if nodes > 262144:
            fail("SOURCE_RESPONSE_INVALID")
        if isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str):
            item.encode("utf-8")
        elif isinstance(item, float) and not math.isfinite(item):
            fail("SOURCE_RESPONSE_INVALID")
    if not isinstance(value, dict):
        fail("SOURCE_RESPONSE_INVALID")
    return value


class Client:
    def __init__(self, host, token):
        self.host, self.token = host, token
        self.deadline = time.monotonic() + MAX_SECONDS
        self.bytes = 0

    def get(self, path, query=None):
        _remaining(self.deadline)
        # No environment proxies, redirects, cookies or auth-bearing retry requests.
        try:
            conn = PinnedHTTPSConnection(self.host, self.deadline)
        except (OSError, ValueError):
            raise ScanFailure("SOURCE_TRANSPORT_ERROR") from None
        timer, response = None, None
        try:
            timer = threading.Timer(_remaining(self.deadline), _abort, args=(conn,))
            timer.daemon = True
            timer.start()
            conn.request("GET", API + path + ("?" + urlencode(query) if query else ""),
                         headers={"Authorization": "Bearer " + self.token, "Accept": "application/json", "Accept-Encoding": "identity"})
            _remaining(self.deadline)
            response = conn.getresponse()
            _remaining(self.deadline)
            if response.status != 200:
                fail({401: "SOURCE_AUTHENTICATION_FAILED", 403: "SOURCE_SCOPE_DENIED",
                      404: "SOURCE_SCOPE_UNAVAILABLE", 429: "SOURCE_RATE_LIMITED"}.get(response.status, "SOURCE_HTTP_ERROR"))
            headers = [key.lower() for key, _ in response.getheaders()]
            if (any(headers.count(key) > 1 for key in ("content-type", "content-length", "content-encoding", "transfer-encoding"))
                    or ("content-length" in headers and "transfer-encoding" in headers)
                    or response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json"
                    or response.getheader("Content-Encoding", "identity").lower() != "identity"
                    or response.getheader("Transfer-Encoding", "chunked").lower() != "chunked"):
                fail("SOURCE_RESPONSE_INVALID")
            length = response.getheader("Content-Length")
            if length is not None:
                if not length.isascii() or not length.isdigit() or len(length) > 10:
                    fail("SOURCE_RESPONSE_INVALID")
                if int(length) > min(MAX_PAGE_BYTES, MAX_BYTES - self.bytes):
                    fail("SOURCE_BYTE_LIMIT")
            chunks, size = [], 0
            while True:
                remaining = _remaining(self.deadline)
                # read1 returns after one underlying read, so a slow peer cannot
                # reset a per-read timeout forever while extending the wall deadline.
                sock = getattr(conn, "_deadline_socket", None) or conn.sock
                if sock:
                    sock.settimeout(min(5, remaining))
                block = response.read1(min(65536, MAX_PAGE_BYTES + 1 - size, MAX_BYTES + 1 - self.bytes))
                _remaining(self.deadline)
                if not block:
                    break
                size += len(block)
                self.bytes += len(block)
                if size > MAX_PAGE_BYTES or self.bytes > MAX_BYTES:
                    fail("SOURCE_BYTE_LIMIT")
                chunks.append(block)
            if length is not None and int(length) != size:
                fail("SOURCE_RESPONSE_INVALID")
            value = _metadata_json(b"".join(chunks))
            _remaining(self.deadline)
            return value
        except ScanFailure:
            raise
        except (UnicodeError, ValueError, RecursionError, OverflowError):
            raise ScanFailure("SOURCE_RESPONSE_INVALID") from None
        except (OSError, http.client.HTTPException, RuntimeError):
            _remaining(self.deadline)
            raise ScanFailure("SOURCE_TRANSPORT_ERROR") from None
        finally:
            if timer is not None:
                timer.cancel()
            if response is not None:
                response.close()
            conn.close()


def description(record):
    value = record.get("comment")
    if value is not None and not isinstance(value, str):
        fail("SOURCE_RESPONSE_INVALID")
    if value is not None:
        # Preserve multiline/non-ASCII documentation, but never produce a
        # completion that PostgreSQL jsonb cannot represent (NUL/surrogates).
        try:
            value.encode("utf-8")
        except UnicodeError:
            fail("SOURCE_RESPONSE_INVALID")
        if "\x00" in value:
            fail("SOURCE_RESPONSE_INVALID")
    return {"sourceDescription": value[:4096] if value else value,
            "sourceDescriptionTruncated": bool(value and len(value) > 4096)}


def scan(source, secret, tenant_id):
    with deadline(MAX_SECONDS):
        return _scan(source, secret, tenant_id)


def _scan(source, secret, tenant_id):
    host = validate_target(source, secret, tenant_id)
    client = Client(host, token_for(secret, host))
    namespace = source["catalog"] + "." + source["schema"]
    schema = client.get("/schemas/" + quote(namespace, safe=""))
    if (schema.get("name") != source["schema"] or schema.get("catalog_name") != source["catalog"]
            or schema.get("full_name") != namespace):
        fail("SOURCE_SCOPE_MISMATCH")
    metastore = identifier(schema.get("metastore_id"))
    created_at = schema.get("created_at")
    if type(created_at) is not int or not 0 <= created_at <= 9007199254740991:
        fail("SOURCE_IDENTITY_UNAVAILABLE")
    # The schema API has no immutable schema ID. Include creation time to avoid
    # merging a recreated namespace; renames are intentionally not auto-merged.
    schema_key = hashlib.sha256(json.dumps([metastore, namespace, created_at]).encode()).hexdigest()
    schema_id = "uc:" + metastore + ":schema:" + schema_key
    records, identities = [], set()
    encoded_bytes = 0

    def append(record):
        nonlocal encoded_bytes
        if record["externalId"] in identities:
            fail("SOURCE_DUPLICATE_ID")
        identities.add(record["externalId"])
        encoded_bytes += len(json.dumps(record, ensure_ascii=True).encode())
        if len(records) >= MAX_RECORDS:
            fail("SOURCE_RECORD_LIMIT")
        if encoded_bytes > MAX_BYTES - 2048:
            fail("SOURCE_BYTE_LIMIT")
        text(record["qualifiedName"], 1024)
        records.append(record)

    append({"externalId": schema_id, "name": source["schema"], "qualifiedName": namespace,
            "type": "schema", "metadata": {"provenance": "source-observed", "metastoreId": metastore,
            "identityBasis": "namespace-and-creation-time", **description(schema)}})
    page_token, tokens = None, set()
    for _ in range(MAX_PAGES):
        query = {"catalog_name": source["catalog"], "schema_name": source["schema"], "max_results": 0,
                 "omit_properties": "true", "omit_username": "true", "include_browse": "false"}
        if page_token:
            query["page_token"] = page_token
        page = client.get("/tables", query)
        tables = page.get("tables", [])
        if not isinstance(tables, list):
            fail("SOURCE_RESPONSE_INVALID")
        for table in tables:
            if not isinstance(table, dict):
                fail("SOURCE_RESPONSE_INVALID")
            name = text(table.get("name"), 255)
            qualified = namespace + "." + name
            if (table.get("catalog_name") != source["catalog"] or table.get("schema_name") != source["schema"]
                    or table.get("full_name") != qualified or table.get("metastore_id") != metastore):
                fail("SOURCE_SCOPE_MISMATCH")
            if table.get("browse_only", False) is not False:
                fail("SOURCE_SCOPE_INCOMPLETE")
            table_id = "uc:" + metastore + ":table:" + identifier(table.get("table_id"))
            kind = table.get("table_type")
            if not isinstance(kind, str) or kind not in TABLE_TYPES:
                fail("SOURCE_TYPE_UNSUPPORTED")
            append({"externalId": table_id, "name": name, "qualifiedName": qualified,
                    "parentExternalId": schema_id, "type": "view" if "VIEW" in kind else "table",
                    "metadata": {"provenance": "source-observed", "tableType": kind, "metastoreId": metastore,
                                 **description(table)}})
            columns = table.get("columns")
            if not isinstance(columns, list):
                fail("SOURCE_SCOPE_INCOMPLETE")
            positions = set()
            for column in columns:
                if not isinstance(column, dict):
                    fail("SOURCE_RESPONSE_INVALID")
                column_name = text(column.get("name"), 255)
                position, nullable = column.get("position"), column.get("nullable")
                if (type(position) is not int or not 0 <= position < 9007199254740991
                        or position in positions or type(nullable) is not bool):
                    fail("SOURCE_RESPONSE_INVALID")
                positions.add(position)
                # REST columns have no immutable ID: name-derived identity is
                # explicit, insensitive to reordering, and never proves absence.
                column_key = hashlib.sha256(column_name.encode()).hexdigest()
                append({"externalId": table_id + ":column:" + column_key, "name": column_name,
                        "qualifiedName": qualified + "." + column_name, "type": "column", "parentExternalId": table_id,
                        "metadata": {"provenance": "source-observed", "identityBasis": "table-id-and-column-name",
                                     "dataType": text(column.get("type_text"), 4096), "nullable": nullable,
                                     "ordinalPosition": position + 1, **description(column)}})
        page_token = page.get("next_page_token")
        if page_token in (None, ""):
            break
        text(page_token, 8192)
        if page_token in tokens:
            fail("SOURCE_PAGINATION_LOOP")
        tokens.add(page_token)
    else:
        fail("SOURCE_PAGE_LIMIT")
    # REST listing is not transactional. Detect a replaced namespace across
    # pagination rather than attach new tables to the previous incarnation.
    final_schema = client.get("/schemas/" + quote(namespace, safe=""))
    if any(final_schema.get(key) != schema.get(key) for key in ("name", "catalog_name", "full_name", "metastore_id", "created_at")):
        fail("SOURCE_SCOPE_CHANGED")
    permission = {"connector": "unity-catalog", "host": host, "metastore": metastore,
                  "scope": namespace, "principal": secret["principalId"], "coverage": "permission-filtered"}
    return {"observedAt": datetime.now(timezone.utc).isoformat(), "sourceVersion": "Unity Catalog REST 2.1",
            "permissionFingerprint": hashlib.sha256(json.dumps(permission, sort_keys=True).encode()).hexdigest(),
            "records": records, "complete": True, "absenceReconciliation": False}
