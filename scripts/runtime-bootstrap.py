#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate local-only credentials; never print credential values."""
import json
import os
from pathlib import Path
import secrets

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local"
LOCAL.mkdir(mode=0o700, exist_ok=True)
os.chmod(LOCAL, 0o700)
STATE = LOCAL / "bootstrap.json"

def write(path, value):
    path.write_text(value, encoding="utf-8")
    os.chmod(path, 0o600)

if STATE.exists():
    values = json.loads(STATE.read_text())
else:
    values = {key: secrets.token_hex(24) for key in (
        "POSTGRES_PASSWORD", "GC_OWNER_PASSWORD", "GC_APP_PASSWORD", "KEYCLOAK_DB_PASSWORD",
        "TEMPORAL_DB_PASSWORD", "SOURCE_ADMIN_PASSWORD", "SOURCE_READER_PASSWORD", "SESSION_KEY",
        "SITE_TOKEN", "WORKER_TOKEN", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY", "KEYCLOAK_ADMIN_PASSWORD")}
    values["personas"] = {username: secrets.token_urlsafe(18) for username in ("steward", "owner", "consumer", "auditor", "summit", "engineer")}
    write(STATE, json.dumps(values, indent=2) + "\n")

tenants = ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]
env = {key: value for key, value in values.items() if key != "personas"}
env.update({"LOCAL_UID": str(os.getuid()), "LOCAL_GID": str(os.getgid()), "SITE_TENANTS": ",".join(tenants)})
write(LOCAL / "runtime.env", "".join(f"{key}={value}\n" for key, value in env.items()))
write(LOCAL / "source-secrets.json", json.dumps({"demo-postgres": {
    "tenantIds": [tenants[0]], "host": "source-postgres", "port": 5432, "database": "harbor", "schema": "public",
    "username": "harbor_reader", "password": values["SOURCE_READER_PASSWORD"]}}, indent=2) + "\n")
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
write(LOCAL / "governance-realm.json", json.dumps(realm, indent=2) + "\n")
# Credentials are hex generated above, never external SQL fragments.
sql = "\\set ON_ERROR_STOP on\n"
for role, password in [("gc_owner", "GC_OWNER_PASSWORD"), ("gc_app", "GC_APP_PASSWORD"), ("keycloak", "KEYCLOAK_DB_PASSWORD"), ("temporal", "TEMPORAL_DB_PASSWORD")]:
    sql += f"CREATE ROLE {role} LOGIN PASSWORD '{values[password]}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;\n"
for database, role in [("governance", "gc_owner"), ("keycloak", "keycloak"), ("temporal", "temporal"), ("temporal_visibility", "temporal")]:
    sql += f"CREATE DATABASE {database} OWNER {role};\nREVOKE ALL ON DATABASE {database} FROM PUBLIC;\nGRANT CONNECT ON DATABASE {database} TO {role};\n"
sql += "GRANT CONNECT ON DATABASE governance TO gc_app;\n\\connect governance\nREVOKE CREATE ON SCHEMA public FROM PUBLIC;\nALTER SCHEMA public OWNER TO gc_owner;\n"
write(LOCAL / "postgres-init.sql", sql)
source = (ROOT / "deploy/compose/source-fixture.sql").read_text()
source = f"CREATE ROLE harbor_reader LOGIN PASSWORD '{values['SOURCE_READER_PASSWORD']}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;\nALTER ROLE harbor_reader SET default_transaction_read_only=on;\n" + source
write(LOCAL / "source-init.sql", source)
print("Local secrets generated/preserved in .local (directory 0700, files 0600).")
print("To retrieve your local login only: python3 scripts/runtime-credential.py steward")
print("Never commit or paste .local contents. Re-running bootstrap preserves existing credentials.")
