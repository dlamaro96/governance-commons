# SPDX-License-Identifier: Apache-2.0
"""Refreshable local secret snapshots. Never logs paths, references or values."""
import json
import math
import os
import re
import stat

from .postgresql import ScanFailure

MAX_BYTES = 1024 * 1024
MAX_NODES = 32768
MAX_DEPTH = 16
REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
CONNECTORS = frozenset({"postgresql", "unity-catalog"})


def _fail(code="SECRET_PROVIDER_INVALID"):
    raise ScanFailure(code)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _parse(raw):
    # Check nesting before json.loads can recursively materialize a hostile file.
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
            if depth > MAX_DEPTH:
                _fail()
        elif byte in (93, 125):
            depth -= 1
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                       parse_constant=lambda _: _fail())
    pending, nodes = [value], 0
    while pending:
        item = pending.pop()
        nodes += 1
        if nodes > MAX_NODES:
            _fail()
        if isinstance(item, dict):
            for key in item:
                if not key or len(key.encode("utf-8")) > 256:
                    _fail()
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str):
            if len(item.encode("utf-8")) > 65536:
                _fail()
        elif isinstance(item, float) and not math.isfinite(item):
            _fail()
    if not isinstance(value, dict):
        _fail()
    return value


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _read(path):
    # NONBLOCK prevents an unexpected FIFO/device from blocking before fstat.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_mode & 0o077
                or before.st_uid not in (0, os.geteuid())
                or not 0 < before.st_size <= MAX_BYTES):
            _fail("SECRET_PROVIDER_UNAVAILABLE")
        chunks, size = [], 0
        while size <= MAX_BYTES:
            block = os.read(fd, min(65536, MAX_BYTES + 1 - size))
            if not block:
                break
            size += len(block)
            chunks.append(block)
        if size != before.st_size or _stamp(before) != _stamp(os.fstat(fd)):
            _fail("SECRET_PROVIDER_UNAVAILABLE")
        return b"".join(chunks)
    finally:
        os.close(fd)


def resolve(path, ref, tenant_id, connector_id):
    """Return only the requested current entry; adapter still checks exact target.

    The operator owns the configured path. No cache, chmod, fallback reference,
    environment lookup or secret mutation is performed. A missing connectorId
    denotes PostgreSQL only, preserving the original local provider format.
    """
    if not isinstance(ref, str) or not REFERENCE.fullmatch(ref):
        _fail("SECRET_REFERENCE_DENIED")
    if (not isinstance(tenant_id, str) or not 1 <= len(tenant_id) <= 128
            or not isinstance(connector_id, str) or connector_id not in CONNECTORS):
        _fail("SOURCE_SCOPE_DENIED")
    try:
        entries = _parse(_read(path))
        secret = entries.get(ref)
        if not isinstance(secret, dict):
            _fail("SECRET_REFERENCE_DENIED")
        tenants = secret.get("tenantIds")
        if (not isinstance(tenants, list) or not 1 <= len(tenants) <= 256
                or any(not isinstance(x, str) or not 1 <= len(x) <= 128 for x in tenants)
                or len(set(tenants)) != len(tenants)):
            _fail()
        if tenant_id not in tenants:
            _fail("SOURCE_SCOPE_DENIED")
        if secret.get("connectorId", "postgresql") != connector_id:
            _fail("SOURCE_TARGET_DENIED")
        return secret
    except ScanFailure:
        raise
    except (OSError, TypeError):
        raise ScanFailure("SECRET_PROVIDER_UNAVAILABLE") from None
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise ScanFailure("SECRET_PROVIDER_INVALID") from None
