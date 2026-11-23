#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate local-only credentials; never print credential values."""
import json
import math
import os
import re
import stat
from pathlib import Path
import secrets
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local"
STATE = LOCAL / "bootstrap.json"


def output_error():
    raise SystemExit("Local bootstrap output is invalid or changed; private output was not confirmed.")


def output_stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def output_metadata(directory, name):
    try:
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        output_error()
    return output_stamp(info)


def output_directory(path):
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    info = os.fstat(directory)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        os.close(directory)
        output_error()
    return directory


def write(path, value):
    """Publish only private regular outputs, never truncate or follow a link."""
    directory, temporary = None, None
    try:
        directory = output_directory(path)
        before = output_metadata(directory, path.name)
        candidate = ".bootstrap-" + secrets.token_hex(16)
        fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory)
        temporary = candidate
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(value.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        current = path.parent.lstat()
        opened = os.fstat(directory)
        if ((current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
                or not stat.S_ISDIR(current.st_mode) or current.st_uid != os.geteuid()
                or stat.S_IMODE(current.st_mode) != 0o700
                or output_metadata(directory, path.name) != before):
            output_error()
        os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        temporary = None
        os.fsync(directory)
    except (OSError, ValueError, UnicodeError):
        output_error()
    finally:
        if directory is not None:
            try:
                if temporary is not None:
                    os.unlink(temporary, dir_fd=directory)
            finally:
                os.close(directory)


def read_state(path):
    directory, fd = None, None
    try:
        directory = output_directory(path)
        before = output_metadata(directory, path.name)
        if before is None:
            return None
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=directory)
        opened = os.fstat(fd)
        if output_stamp(opened) != before or not 0 < opened.st_size <= 65536:
            output_error()
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(65537)
        if (len(raw) != opened.st_size or output_stamp(os.fstat(fd)) != before
                or output_metadata(directory, path.name) != before):
            output_error()
        value = json.loads(raw)
        if not isinstance(value, dict):
            output_error()
        return value
    except (OSError, ValueError, TypeError, RecursionError):
        output_error()
    finally:
        if fd is not None:
            os.close(fd)
        if directory is not None:
            os.close(directory)


try:
    LOCAL.mkdir(mode=0o700, exist_ok=True)
    local_info = LOCAL.lstat()
    if (not stat.S_ISDIR(local_info.st_mode) or local_info.st_uid != os.geteuid()
            or stat.S_IMODE(local_info.st_mode) != 0o700):
        output_error()
except OSError:
    output_error()

def source_error():
    raise SystemExit("Source credential provider is invalid or changed; no provider data was overwritten.")


def provider_stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def parse_provider(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                source_error()
            result[key] = value
        return result
    depth, quoted, escaped = 0, False, False
    for byte in raw:
        if quoted:
            if escaped: escaped = False
            elif byte == 92: escaped = True
            elif byte == 34: quoted = False
        elif byte == 34: quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > 16: source_error()
        elif byte in (93, 125): depth -= 1
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                       parse_constant=lambda _: source_error())
    pending, nodes = [value], 0
    while pending:
        item = pending.pop(); nodes += 1
        if nodes > 32768: source_error()
        if isinstance(item, dict):
            if any(not key or len(key.encode("utf-8")) > 256 for key in item): source_error()
            pending.extend(item.values())
        elif isinstance(item, list): pending.extend(item)
        elif isinstance(item, str):
            if len(item.encode("utf-8")) > 65536: source_error()
        elif isinstance(item, float) and not math.isfinite(item): source_error()
    if not isinstance(value, dict): source_error()
    for ref, entry in value.items():
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", ref) or not isinstance(entry, dict): source_error()
        tenants = entry.get("tenantIds")
        if (not isinstance(tenants, list) or not 1 <= len(tenants) <= 256
                or any(not isinstance(t, str) or not 1 <= len(t) <= 128 for t in tenants)
                or len(set(tenants)) != len(tenants)):
            source_error()
        # Preserve provider entries for future adapters too; dispatch, not
        # bootstrap, owns which connector implementations are executable.
        connector = entry.get("connectorId", "postgresql")
        if not isinstance(connector, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", connector): source_error()
    return value


def read_provider(path, *, legacy=False):
    fd = None
    try:
        # Only this explicit one-time legacy import follows an operator's old
        # symlink. The old file and its target are never changed or chmodded.
        selected = path.resolve(strict=True) if legacy else path
        fd = os.open(selected, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_mode & 0o077
                or (not legacy and stat.S_IMODE(before.st_mode) != 0o600)
                or before.st_uid not in (0, os.geteuid()) or not 0 < before.st_size <= 1024*1024): source_error()
        with os.fdopen(fd, 'rb', closefd=False) as stream: raw = stream.read(1024*1024+1)
        if len(raw) != before.st_size or provider_stamp(before) != provider_stamp(os.fstat(fd)): source_error()
        return parse_provider(raw), provider_stamp(before)
    except (OSError, ValueError, TypeError, RecursionError, OverflowError):
        source_error()
    finally:
        if fd is not None: os.close(fd)


CREDENTIALS = LOCAL / "source-credentials"
PROVIDER = CREDENTIALS / "secrets.json"
LEGACY_PROVIDER = LOCAL / "source-secrets.json"
# Validate before rewriting any bootstrap outputs. An existing new directory
# with a missing/invalid file never falls back to the stale legacy provider.
if os.path.lexists(CREDENTIALS):
    info = CREDENTIALS.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700): source_error()
    provider_entries, provider_before = read_provider(PROVIDER)
elif os.path.lexists(LEGACY_PROVIDER):
    provider_entries, _ = read_provider(LEGACY_PROVIDER, legacy=True)
    provider_before = None
else:
    provider_entries, provider_before = {}, None


def publish_provider(demo):
    if provider_before is not None and provider_entries.get("demo-postgres") == demo:
        # Ordinary repeat bootstrap preserves even custom formatting and inode.
        return
    merged = {**provider_entries, "demo-postgres": demo}
    raw = (json.dumps(merged, indent=2) + "\n").encode("utf-8")
    if len(raw) > 1024*1024: source_error()
    parse_provider(raw)
    path = None
    try:
        if provider_before is None:
            CREDENTIALS.mkdir(mode=0o700)
        elif provider_stamp(PROVIDER.lstat()) != provider_before:
            source_error()
        fd, name = tempfile.mkstemp(prefix=".secrets-", dir=CREDENTIALS)
        path = Path(name)
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        if provider_before is not None and provider_stamp(PROVIDER.lstat()) != provider_before: source_error()
        os.replace(path, PROVIDER)
        path = None
    except (OSError, ValueError):
        source_error()
    finally:
        if path is not None: path.unlink(missing_ok=True)


values = read_state(STATE)
if values is None:
    values = {key: secrets.token_hex(24) for key in (
        "POSTGRES_PASSWORD", "GC_OWNER_PASSWORD", "GC_APP_PASSWORD", "KEYCLOAK_DB_PASSWORD",
        "TEMPORAL_DB_PASSWORD", "SOURCE_ADMIN_PASSWORD", "SOURCE_READER_PASSWORD", "SESSION_KEY",
        "SITE_TOKEN", "WORKER_TOKEN", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY", "KEYCLOAK_ADMIN_PASSWORD")}
    values["personas"] = {username: secrets.token_urlsafe(18) for username in ("steward", "owner", "consumer", "auditor", "summit", "engineer")}
    write(STATE, json.dumps(values, indent=2) + "\n")

# Inactive foundation executors have separate native credentials. Preserve
# existing values and never reactivate/rotate an already provisioned role.
for key in ('GC_AUTHN_LOGIN_PASSWORD', 'GC_AUTHN_API_PASSWORD'):
    if key not in values:
        values[key] = secrets.token_urlsafe(36)
write(STATE, json.dumps(values, indent=2) + "\n")

tenants = ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]
env = {key: value for key, value in values.items()
       if key not in ('personas', 'GC_AUTHN_LOGIN_PASSWORD', 'GC_AUTHN_API_PASSWORD')}
env.update({"LOCAL_UID": str(os.getuid()), "LOCAL_GID": str(os.getgid()), "SITE_TENANTS": ",".join(tenants)})
write(LOCAL / "runtime.env", "".join(f"{key}={value}\n" for key, value in env.items()))
# Authentication processes receive only their own native credential. The core
# content API never receives either protected executor or owner connection.
origin = "http://127.0.0.1:4310"
issuer = "http://localhost:4311/realms/governance"
authn_base = {"AUTHN_ENVIRONMENT": "local-development", "PUBLIC_AUTHN_ORIGIN": origin}
login_env = {**authn_base, "AUTHN_LOGIN_DATABASE_URL": f"postgresql://gc_authn_login:{values['GC_AUTHN_LOGIN_PASSWORD']}@postgres:5432/governance",
    "OIDC_PROVIDER": "keycloak", "OIDC_ISSUER": issuer, "OIDC_CLIENT_ID": "governance-protected-web",
    "OIDC_REDIRECT_URI": origin + "/authn/callback", "OIDC_AUTHORIZATION_ENDPOINT": issuer + "/protocol/openid-connect/auth",
    "OIDC_TOKEN_ENDPOINT": issuer + "/protocol/openid-connect/token", "OIDC_JWKS_URI": issuer + "/protocol/openid-connect/certs",
    "OIDC_TRANSPORT_ALIASES_JSON": json.dumps({issuer + suffix: "http://keycloak:8080/realms/governance" + suffix for suffix in ("/.well-known/openid-configuration", "/protocol/openid-connect/token", "/protocol/openid-connect/certs")}, separators=(",", ":")),
    "AUTHN_POST_LOGIN_PATH": "/", "HOST": "0.0.0.0", "PORT": "4312"}
session_env = {**authn_base, "AUTHN_API_DATABASE_URL": f"postgresql://gc_authn_api:{values['GC_AUTHN_API_PASSWORD']}@postgres:5432/governance"}
write(LOCAL / "authn-login.env", "".join(f"{key}={value}\n" for key, value in login_env.items()))
write(LOCAL / "authn-session.env", "".join(f"{key}={value}\n" for key, value in session_env.items()))
publish_provider({"tenantIds": [tenants[0]], "host": "source-postgres", "port": 5432,
    "database": "harbor", "schema": "public", "username": "harbor_reader", "password": values["SOURCE_READER_PASSWORD"]})
write(LOCAL / "seaweed-s3.json", json.dumps({"identities": [{"name": "governance-local", "credentials": [{
    "accessKey": values["S3_ACCESS_KEY_ID"], "secretKey": values["S3_SECRET_ACCESS_KEY"]}], "actions": ["Admin", "Read", "Write", "List", "Tagging"]}]}, indent=2) + "\n")
users = []
for i, (username, name) in enumerate([( "steward", "Harper Steward"), ("owner", "Robin Owner"),
        ("consumer", "Casey Consumer"), ("auditor", "Avery Auditor"), ("summit", "Jordan Summit"), ("engineer", "Morgan Engineer")], 1):
    first, last = name.split(" ")
    users.append({"id": f"10000000-0000-4000-8000-{i:012d}", "username": username, "enabled": True,
        "emailVerified": True, "email": f"{username}@example.invalid", "firstName": first, "lastName": last,
        "credentials": [{"type": "password", "value": values["personas"][username], "temporary": False}], "requiredActions": []})
realm = {"realm": "governance", "enabled": True, "displayName": "Governance Commons — local synthetic identities",
    "registrationAllowed": False, "resetPasswordAllowed": False, "loginWithEmailAllowed": False,
    "bruteForceProtected": True, "sslRequired": "none", "users": users, "clients": [{
    "clientId": "governance-web", "name": "Governance Commons", "enabled": True, "publicClient": True,
    "standardFlowEnabled": True, "directAccessGrantsEnabled": False, "serviceAccountsEnabled": False,
    "redirectUris": ["http://localhost:4310/auth/callback"], "webOrigins": ["http://localhost:4310"],
    "attributes": {"pkce.code.challenge.method": "S256", "post.logout.redirect.uris": "http://localhost:4310/*"}}]}
realm["clients"].append({"clientId": "governance-protected-web", "name": "Governance Commons protected login", "enabled": True, "publicClient": True,
    "standardFlowEnabled": True, "directAccessGrantsEnabled": False, "serviceAccountsEnabled": False,
    "redirectUris": [origin + "/authn/callback"], "webOrigins": [origin],
    "attributes": {"pkce.code.challenge.method": "S256"}})
write(LOCAL / "governance-realm.json", json.dumps(realm, indent=2) + "\n")
# Credentials are hex generated above, never external SQL fragments.
sql = "\\set ON_ERROR_STOP on\n"
for role, password in [("gc_owner", "GC_OWNER_PASSWORD"), ("gc_app", "GC_APP_PASSWORD"), ("keycloak", "KEYCLOAK_DB_PASSWORD"), ("temporal", "TEMPORAL_DB_PASSWORD")]:
    sql += f"CREATE ROLE {role} LOGIN PASSWORD '{values[password]}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;\n"
for database, role in [("governance", "gc_owner"), ("keycloak", "keycloak"), ("temporal", "temporal"), ("temporal_visibility", "temporal")]:
    sql += f"CREATE DATABASE {database} OWNER {role};\nREVOKE ALL ON DATABASE {database} FROM PUBLIC;\nGRANT CONNECT ON DATABASE {database} TO {role};\n"
sql += "GRANT CONNECT ON DATABASE governance TO gc_app;\n\\connect governance\nREVOKE CREATE ON SCHEMA public FROM PUBLIC;\nALTER SCHEMA public OWNER TO gc_owner;\n"
write(LOCAL / "postgres-init.sql", sql)
source = (ROOT / "deploy/compose/source-fixture.sql").read_text() + "\n" + (ROOT / "deploy/compose/reference-quality-fixture.sql").read_text() + "\n" + (ROOT / "deploy/compose/uniqueness-quality-fixture.sql").read_text() + "\n" + (ROOT / "deploy/compose/range-quality-fixture.sql").read_text()
source = f"CREATE ROLE harbor_reader LOGIN PASSWORD '{values['SOURCE_READER_PASSWORD']}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;\nALTER ROLE harbor_reader SET default_transaction_read_only=on;\n" + source
write(LOCAL / "source-init.sql", source)
print("Local secrets generated/preserved in .local (directory 0700, files 0600).")
print("To retrieve your local login only: python3 scripts/runtime-credential.py steward")
print("Never commit or paste .local contents. Re-running bootstrap preserves existing credentials.")
