# SPDX-License-Identifier: Apache-2.0
"""Deployment-owned PostgreSQL destinations; no connections or credentials cached.

Call load_policy for each scan, then keep prepare_connection's context open until
the connection is closed. The caller must wrap the complete synchronous scan in
deadline.deadline; libpq's integer connect_timeout is not a whole-scan deadline.
This module deliberately does not import the PostgreSQL adapter.
"""
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
import ipaddress
import json
import math
import os
import re
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from types import MappingProxyType

MAX_BYTES = 1024 * 1024
MAX_CA_BYTES = 65536
MAX_ADDRESSES = 16
MAX_DNS_SECONDS = 5
_REFERENCE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_CERT = re.compile(r"-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----")
_PRIVATE = tuple(map(ipaddress.ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")))
_METADATA = frozenset(map(ipaddress.ip_address, ("168.63.129.16", "100.100.100.200", "fd00:ec2::254", "fd20:ce::254")))
_DNS_SLOTS = threading.BoundedSemaphore(4)
# Trusted fixed child program, not supplied by source configuration. No credential
# is sent to this process. Its result is bounded before serialization.
_DNS_SCRIPT = """import json,socket,sys
try:
 rows=socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),family=socket.AF_UNSPEC,type=socket.SOCK_STREAM,proto=socket.IPPROTO_TCP)
 if not 1<=len(rows)<=16: sys.exit(2)
 out=[]
 for family,kind,proto,_,addr in rows:
  if family not in (socket.AF_INET,socket.AF_INET6) or kind!=socket.SOCK_STREAM or proto!=socket.IPPROTO_TCP: sys.exit(2)
  if len(addr[0])>64 or (family==socket.AF_INET6 and (addr[2]!=0 or addr[3]!=0)): sys.exit(2)
  out.append([family,addr[0],addr[1]])
 sys.stdout.write(json.dumps(out,separators=(',',':')))
except Exception: sys.exit(2)
"""


class TargetPolicyError(Exception):
    """Only a fixed safe code crosses the worker boundary."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _fail(code="SOURCE_TARGET_POLICY_INVALID"):
    raise TargetPolicyError(code)


@contextmanager
def _blocked_alarm():
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


class _Resources:
    """Own exact resources despite an asynchronous outer deadline exception.

    Acquisitions and registration are masked together. The temporary handler
    cleans registered resources even if the alarm lands at normal cleanup entry,
    then restores/delegates to the prior handler. It never resets an alarm timer.
    """
    def __init__(self):
        self.callbacks = []
        self.installed = False
        self.previous = None

    def __enter__(self):
        if threading.current_thread() is not threading.main_thread():
            _fail("SOURCE_DEADLINE_UNAVAILABLE")
        with _blocked_alarm():
            self.previous = signal.getsignal(signal.SIGALRM)
            signal.signal(signal.SIGALRM, self._alarm)
            self.installed = True
        return self

    def own(self, callback):
        # Called only inside _blocked_alarm, immediately after acquisition.
        self.callbacks.append(callback)
        return callback

    def release(self, callback):
        with _blocked_alarm():
            self.callbacks.remove(callback)
            callback()

    def _finish(self):
        with _blocked_alarm():
            failure = None
            while self.callbacks:
                callback = self.callbacks.pop()
                try:
                    callback()
                except Exception as error:
                    failure = error
            if self.installed:
                signal.signal(signal.SIGALRM, self.previous)
                self.installed = False
            if failure is not None:
                raise TargetPolicyError("SOURCE_RESOURCE_CLEANUP_FAILED") from None

    def _alarm(self, signum, frame):
        self._finish()
        if callable(self.previous):
            self.previous(signum, frame)
        elif self.previous == signal.SIG_DFL:
            signal.raise_signal(signum)

    def __exit__(self, *_):
        self._finish()


@dataclass(frozen=True, slots=True, repr=False)
class Target:
    tenant_ids: frozenset[str]
    host: str
    port: int
    database: str
    schema: str
    allowed_cidrs: tuple
    ca_pem: str


@dataclass(frozen=True, slots=True, repr=False)
class TargetPolicy:
    targets: Mapping[str, Target]


@dataclass(frozen=True, slots=True, repr=False)
class PreparedParameters(Mapping):
    _values: Mapping = field(repr=False)

    def __getitem__(self, key):
        return self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)

    def __repr__(self):
        return "<PreparedPostgresParameters redacted>"


def _text(value, limit, *, controls=False):
    if type(value) is not str or not value or len(value) > limit:
        _fail()
    try:
        if len(value.encode("utf-8")) > limit or "\0" in value:
            _fail()
    except UnicodeError:
        _fail()
    if not controls and any(ord(c) < 32 or ord(c) == 127 for c in value):
        _fail()
    return value


def _keys(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        _fail()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _json(document):
    if type(document) not in (str, bytes) or len(document) > MAX_BYTES:
        _fail()
    raw = document.encode("utf-8") if type(document) is str else document
    if not 0 < len(raw) <= MAX_BYTES:
        _fail()
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
                _fail()
        elif byte in (93, 125):
            depth -= 1
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=lambda _: _fail())
    pending, count = [value], 0
    while pending:
        node = pending.pop()
        count += 1
        if count > 32768:
            _fail()
        if type(node) is dict:
            pending.extend(node.keys())
            pending.extend(node.values())
        elif type(node) is list:
            pending.extend(node)
        elif type(node) is str:
            _text(node, MAX_CA_BYTES, controls=True)
    return value


def _host(host):
    _text(host, 253)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if not all(_LABEL.fullmatch(label) for label in host.split(".")):
            _fail()
        # Do not let getaddrinfo reinterpret legacy decimal/octal IP spellings.
        if re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*", host):
            _fail()
    else:
        if host != str(address) or "%" in host:
            _fail()
    return host


def _tenants(value):
    if type(value) is not list or not 1 <= len(value) <= 256:
        _fail()
    for item in value:
        _text(item, 128)
    if len(set(value)) != len(value):
        _fail()
    return frozenset(value)


def _ca(value):
    _text(value, MAX_CA_BYTES, controls=True)
    value.encode("ascii")
    blocks = _CERT.findall(value)
    if not 1 <= len(blocks) <= 16 or _CERT.sub("", value).strip():
        _fail()
    # No system roots are loaded. Reject non-certificates and non-CA leaf material.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=value)
    if len(context.get_ca_certs(binary_form=True)) != len(blocks):
        _fail()
    return value


def parse_policy(document: bytes | str) -> TargetPolicy:
    """Closed, bounded JSON only; returns a deeply immutable policy snapshot."""
    try:
        value = _json(document)
        _keys(value, ("formatVersion", "targets"))
        if type(value["formatVersion"]) is not int or value["formatVersion"] != 1:
            _fail()
        targets = value["targets"]
        if type(targets) is not dict or len(targets) > 1024:
            _fail()
        parsed = {}
        for ref, item in targets.items():
            if not _REFERENCE.fullmatch(ref):
                _fail()
            _keys(item, ("tenantIds", "host", "port", "database", "schema", "allowedCidrs", "tls"))
            host = _host(item["host"])
            port = item["port"]
            if type(port) is not int or not 1 <= port <= 65535:
                _fail()
            database, schema = _text(item["database"], 63), _text(item["schema"], 63)
            if "=" in database or database.lower().startswith(("postgres://", "postgresql://")):
                _fail()  # libpq must never expand dbname as a connection string.
            cidrs = item["allowedCidrs"]
            if type(cidrs) is not list or not 1 <= len(cidrs) <= 256:
                _fail()
            networks = []
            for cidr in cidrs:
                _text(cidr, 64)
                network = ipaddress.ip_network(cidr, strict=True)
                if str(network) != cidr or network in networks:
                    _fail()
                networks.append(network)
            _keys(item["tls"], ("mode", "caPem"))
            if item["tls"]["mode"] != "verify-full":
                _fail()
            parsed[ref] = Target(_tenants(item["tenantIds"]), host, port, database, schema,
                                 tuple(networks), _ca(item["tls"]["caPem"]))
        return TargetPolicy(MappingProxyType(parsed))
    except TargetPolicyError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError, ssl.SSLError):
        raise TargetPolicyError("SOURCE_TARGET_POLICY_INVALID") from None


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _open_file(path, resources):
    # Descriptor-relative traversal prevents intermediate symlink substitution.
    name = os.fspath(path)
    if type(name) is not str or not name or len(name) > 4096 or "\0" in name or ".." in name.split("/"):
        _fail("SOURCE_TARGET_POLICY_UNAVAILABLE")
    parts = os.path.abspath(name).split("/")[1:]
    with _blocked_alarm():
        parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        close_parent = resources.own(lambda fd=parent: os.close(fd))
    for part in parts[:-1]:
        with _blocked_alarm():
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            close_next = resources.own(lambda fd=next_fd: os.close(fd))
            resources.release(close_parent)
            parent, close_parent = next_fd, close_next
    with _blocked_alarm():
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        resources.own(lambda: os.close(fd))
        resources.release(close_parent)
    return fd


def _read_policy_bytes(fd):
    chunks, size = [], 0
    while size <= MAX_BYTES:
        block = os.read(fd, min(65536, MAX_BYTES + 1 - size))
        if not block:
            break
        size += len(block)
        chunks.append(block)
    return b"".join(chunks)


def load_policy(path: str | os.PathLike) -> TargetPolicy:
    """Verify one descriptor snapshot; concurrent rotation may safely refuse.

    Both reads are bounded. Matching bytes supplement metadata checks because
    equal-length in-place writes can share filesystem timestamps. The operator
    must still publish by atomic replacement; repeated reads do not provide an
    immutable snapshot against an adversarial writer changing the open inode.
    """
    try:
        with _Resources() as resources:
            fd = _open_file(path, resources)
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) not in (0o400, 0o600)
                    or before.st_uid not in (0, os.geteuid()) or before.st_nlink != 1
                    or not 0 < before.st_size <= MAX_BYTES):
                _fail("SOURCE_TARGET_POLICY_UNAVAILABLE")
            raw = _read_policy_bytes(fd)
            if len(raw) != before.st_size or _stamp(before) != _stamp(os.fstat(fd)):
                _fail("SOURCE_TARGET_POLICY_UNAVAILABLE")
            os.lseek(fd, 0, os.SEEK_SET)
            verified = _read_policy_bytes(fd)
            if raw != verified or _stamp(before) != _stamp(os.fstat(fd)):
                _fail("SOURCE_TARGET_POLICY_UNAVAILABLE")
        return parse_policy(raw)
    except (OSError, TypeError, ValueError):
        raise TargetPolicyError("SOURCE_TARGET_POLICY_UNAVAILABLE") from None


def _remaining(deadline_at):
    try:
        valid = type(deadline_at) in (float, int) and math.isfinite(deadline_at)
    except (ValueError, OverflowError):
        valid = False
    if not valid:
        _fail("SOURCE_DEADLINE_UNAVAILABLE")
    remaining = deadline_at - time.monotonic()
    if remaining <= 0:
        _fail("SOURCE_DEADLINE_EXCEEDED")
    return remaining


def _reap(process):
    if process.poll() is None:
        # This exact child is unreaped, so its PID cannot have been reused.
        try:
            process.kill()
        except ProcessLookupError:
            pass
    process.wait()
    if process.stdout is not None:
        process.stdout.close()


def _resolve(host, port, deadline_at):
    """Own/reap the DNS child on every exit, including the caller's SIGALRM.

    Like deadline.py this cannot promise progress for a task uninterruptibly
    stuck in the kernel; no detached resolver thread is left alive.
    """
    _remaining(deadline_at)
    try:
        with _Resources() as resources:
            with _blocked_alarm():
                if not _DNS_SLOTS.acquire(blocking=False):
                    _fail("SOURCE_TRANSPORT_ERROR")
                resources.own(_DNS_SLOTS.release)
            with _blocked_alarm():
                process = subprocess.Popen([sys.executable, "-I", "-c", _DNS_SCRIPT, host, str(port)],
                                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.DEVNULL, close_fds=True,
                                           env={"LANG": "C", "LC_ALL": "C"})
                resources.own(lambda: _reap(process))
            try:
                raw, _ = process.communicate(timeout=min(MAX_DNS_SECONDS, _remaining(deadline_at)))
            except subprocess.TimeoutExpired:
                _fail("SOURCE_DEADLINE_EXCEEDED")
            _remaining(deadline_at)
            if process.returncode != 0 or not 0 < len(raw) <= 4096:
                _fail("SOURCE_DESTINATION_DENIED")
            rows = json.loads(raw)
            if type(rows) is not list or not 1 <= len(rows) <= MAX_ADDRESSES:
                _fail("SOURCE_DESTINATION_DENIED")
            result = []
            for row in rows:
                if (type(row) is not list or len(row) != 3 or type(row[0]) is not int
                        or row[0] not in (socket.AF_INET, socket.AF_INET6) or type(row[1]) is not str
                        or type(row[2]) is not int or row[2] != port or "%" in row[1]):
                    _fail("SOURCE_DESTINATION_DENIED")
                address = ipaddress.ip_address(row[1])
                if (address.version == 4) != (row[0] == socket.AF_INET):
                    _fail("SOURCE_DESTINATION_DENIED")
                result.append(address)
            return tuple(result)
    except TargetPolicyError:
        raise
    except (OSError, ValueError, TypeError):
        raise TargetPolicyError("SOURCE_TRANSPORT_ERROR") from None


def _address_allowed(address, target):
    private = any(address.version == network.version and address in network for network in _PRIVATE)
    if (address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast
            or address.is_reserved or address in _METADATA
            or (address.version == 6 and (address.is_site_local or address.ipv4_mapped or address.sixtofour or address.teredo))
            or not (address.is_global or private)
            or not any(address.version == network.version and address in network for network in target.allowed_cidrs)):
        _fail("SOURCE_DESTINATION_DENIED")


def _environment():
    if any(key.startswith(("PG", "OPENSSL_", "SSL_CERT_")) or key == "SSLKEYLOGFILE" for key in os.environ):
        _fail("SOURCE_CONNECTION_ENVIRONMENT_DENIED")


def _libpq_version():
    from psycopg import pq
    return pq.version()


@contextmanager
def prepare_connection(policy: TargetPolicy, source: Mapping, secret: Mapping, tenant_id: str, *, deadline_at: float):
    """Yield immutable redacted-repr psycopg kwargs, with owned CA lifetime.

    Only password authentication is permitted. libpq >=17 is required for the
    explicit sslcertmode control. Fixed hostaddr prevents libpq DNS re-resolution;
    host is retained for TLS identity/SNI. One selected approved IP, no fallback.
    """
    _remaining(deadline_at)
    _environment()
    if _libpq_version() < 170000:
        _fail("SOURCE_TLS_UNAVAILABLE")
    if (type(policy) is not TargetPolicy or not isinstance(source, Mapping) or not isinstance(secret, Mapping)
            or type(tenant_id) is not str or not tenant_id):
        _fail("SOURCE_TARGET_DENIED")
    ref = source.get("secretRef")
    if type(ref) is not str or not _REFERENCE.fullmatch(ref) or ref not in policy.targets:
        _fail("SOURCE_TARGET_DENIED")
    target = policy.targets[ref]
    if source.get("connectorId", "postgresql") != "postgresql" or secret.get("connectorId", "postgresql") != "postgresql":
        _fail("SOURCE_TARGET_DENIED")
    try:
        permitted = _tenants(secret.get("tenantIds"))
        username = _text(secret.get("username"), 63)
        password = _text(secret.get("password"), 4096, controls=True)
    except TargetPolicyError:
        raise TargetPolicyError("SOURCE_TARGET_DENIED") from None
    if tenant_id not in target.tenant_ids or tenant_id not in permitted:
        _fail("SOURCE_SCOPE_DENIED")
    for key in ("host", "port", "database", "schema"):
        expected = getattr(target, key)
        if any(type(item.get(key)) is not type(expected) or item.get(key) != expected for item in (source, secret)):
            _fail("SOURCE_TARGET_DENIED")
    # The provider binds ref externally. A supplied self-identifying ref must
    # agree too; credentials never choose a different policy target.
    if "secretRef" in secret and secret["secretRef"] != ref:
        _fail("SOURCE_TARGET_DENIED")
    addresses = _resolve(target.host, target.port, deadline_at)
    for address in addresses:
        _address_allowed(address, target)
    _remaining(deadline_at)
    with _Resources() as resources:
        try:
            with _blocked_alarm():
                directory = tempfile.mkdtemp(prefix="gc-postgres-ca-")
                resources.own(lambda: _remove_ca(directory))
                os.chmod(directory, 0o700)
            ca_path = os.path.join(directory, "ca.pem")
            with _blocked_alarm():
                fd = os.open(ca_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                close_ca = resources.own(lambda: os.close(fd))
            pending = memoryview(target.ca_pem.encode("ascii"))
            while pending:
                count = os.write(fd, pending)
                if count <= 0:
                    _fail("SOURCE_TLS_UNAVAILABLE")
                pending = pending[count:]
                _remaining(deadline_at)
            resources.release(close_ca)
            crl_dir = os.path.join(directory, "crls")
            os.mkdir(crl_dir, 0o700)
            remaining = _remaining(deadline_at)
            if remaining < 2:
                _fail("SOURCE_DEADLINE_EXCEEDED")  # libpq rounds 1s up to 2s.
            kwargs = PreparedParameters(MappingProxyType({
                "host": target.host, "hostaddr": str(addresses[0]), "port": target.port,
                "dbname": target.database, "user": username, "password": password,
                "connect_timeout": min(5, math.floor(remaining)), "passfile": os.devnull,
                "sslmode": "verify-full", "sslrootcert": ca_path, "ssl_min_protocol_version": "TLSv1.2",
                "sslcertmode": "disable", "sslcert": os.path.join(directory, "absent.crt"),
                "sslkey": os.path.join(directory, "absent.key"), "sslcrl": os.path.join(directory, "absent.crl"),
                "sslcrldir": crl_dir, "sslcompression": "0", "sslsni": "1",
                "gssencmode": "disable", "gssdelegation": "0", "require_auth": "scram-sha-256,md5,password",
                "channel_binding": "prefer", "application_name": "governance-commons-metadata",
                "options": "-c search_path=pg_catalog -c default_transaction_read_only=on -c statement_timeout=15000 -c lock_timeout=2000",
            }))
            _environment()
        except (OSError, UnicodeError):
            raise TargetPolicyError("SOURCE_TLS_UNAVAILABLE") from None
        yield kwargs
        _remaining(deadline_at)


def _remove_ca(directory):
    # Remove only our finite file set; never follow caller-supplied paths or
    # recursively delete arbitrary contents. Unexpected changes fail closed.
    try:
        for name in ("ca.pem",):
            try:
                os.unlink(os.path.join(directory, name))
            except FileNotFoundError:
                pass
        try:
            os.rmdir(os.path.join(directory, "crls"))
        except FileNotFoundError:
            pass
        os.rmdir(directory)
    except OSError:
        raise TargetPolicyError("SOURCE_TLS_CLEANUP_FAILED") from None
