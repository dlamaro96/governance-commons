# SPDX-License-Identifier: Apache-2.0
"""Bounded catalog extraction. Never executes source-authored SQL or reads rows."""
import hashlib
import ipaddress
import json
import math
import os
import time
from contextlib import contextmanager
from datetime import datetime, timezone
import psycopg
from psycopg.rows import dict_row

MAX_RECORDS = 10000
MAX_BYTES = 8 * 1024 * 1024
MAX_SECONDS = 90
_DEMO_TARGET = {"host": "source-postgres", "port": 5432, "database": "harbor", "schema": "public"}

class ScanFailure(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _matching_scope(source, secret, tenant_id):
    if type(source) is not dict or type(secret) is not dict:
        raise ScanFailure("SOURCE_TARGET_DENIED")
    tenants = secret.get("tenantIds")
    if (type(tenant_id) is not str or not 1 <= len(tenant_id) <= 128
            or type(tenants) is not list or not 1 <= len(tenants) <= 256
            or any(type(item) is not str or not 1 <= len(item) <= 128 for item in tenants)
            or len(set(tenants)) != len(tenants) or tenant_id not in tenants):
        raise ScanFailure("SOURCE_SCOPE_DENIED")
    if source.get("connectorId", "postgresql") != "postgresql" or secret.get("connectorId", "postgresql") != "postgresql":
        raise ScanFailure("SOURCE_TARGET_DENIED")
    for key, expected_type in (("host", str), ("port", int), ("database", str), ("schema", str)):
        if (type(source.get(key)) is not expected_type or type(secret.get(key)) is not expected_type
                or source[key] != secret[key]):
            raise ScanFailure("SOURCE_TARGET_DENIED")


def _demo(source):
    # The no-ref form is used only by the existing direct Python conformance
    # fixture. Authenticated worker HTTP requests require an explicit secretRef.
    return all(source.get(key) == value for key, value in _DEMO_TARGET.items()) and source.get("secretRef", "demo-postgres") == "demo-postgres"


def validate_target(source, secret, tenant_id):
    """Preserve the finite local conformance guard; never admits generic hosts."""
    _matching_scope(source, secret, tenant_id)
    if not _demo(source) or secret.get("secretRef", "demo-postgres") != "demo-postgres":
        raise ScanFailure("SOURCE_DESTINATION_DENIED")


@contextmanager
def _connection_parameters(source, secret, tenant_id, deadline_at):
    from . import postgres_targets

    _matching_scope(source, secret, tenant_id)
    if _demo(source):
        validate_target(source, secret, tenant_id)
        # This explicit synthetic local exception is never used after a generic
        # policy error. It is exact host/port/database/schema/ref + reader role.
        if (secret.get("username") != "harbor_reader" or type(secret.get("password")) is not str
                or not secret["password"] or len(secret["password"]) > 4096
                or "\0" in secret["password"]):
            raise ScanFailure("SOURCE_TARGET_DENIED")
        try:
            secret["password"].encode("utf-8")
        except UnicodeError:
            raise ScanFailure("SOURCE_TARGET_DENIED") from None
        postgres_targets._environment()
        if postgres_targets._libpq_version() < 170000:
            raise ScanFailure("SOURCE_TLS_UNAVAILABLE")
        # libpq's connect timeout cannot bound its synchronous resolver. Pin the
        # finite local exception too, without permitting public/metadata targets.
        demo_network = postgres_targets.Target(frozenset({tenant_id}), "source-postgres", 5432, "harbor", "public",
            tuple(map(ipaddress.ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))), "")
        addresses = postgres_targets._resolve("source-postgres", 5432, deadline_at)
        for address in addresses:
            postgres_targets._address_allowed(address, demo_network)
        yield {"host": "source-postgres", "hostaddr": str(addresses[0]), "port": 5432, "dbname": "harbor",
               "user": "harbor_reader", "password": secret["password"], "connect_timeout": 5,
               "sslmode": "disable", "gssencmode": "disable", "gssdelegation": "0",
               "require_auth": "scram-sha-256,md5,password", "passfile": os.devnull,
               "options": "-c search_path=pg_catalog -c default_transaction_read_only=on -c statement_timeout=15000 -c lock_timeout=2000"}
        return
    path = os.environ.get("POSTGRES_TARGETS_FILE")
    if not path or not os.path.isabs(path):
        raise ScanFailure("SOURCE_TARGET_POLICY_UNAVAILABLE")
    policy = postgres_targets.load_policy(path)
    with postgres_targets.prepare_connection(policy, source, secret, tenant_id, deadline_at=deadline_at) as params:
        yield params


def scan(source, secret, tenant_id):
    # Late imports avoid the existing ScanFailure -> deadline -> adapter cycle.
    from .deadline import deadline
    from .postgres_targets import TargetPolicyError, _Resources, _blocked_alarm, _remaining

    deadline_at = time.monotonic() + MAX_SECONDS
    try:
        with deadline(MAX_SECONDS):
            with _connection_parameters(source, secret, tenant_id, deadline_at) as params:
                # CA files outlive connect, every query and the connection close.
                with _Resources() as connections:
                    with _blocked_alarm():
                        remaining = _remaining(deadline_at)
                        if remaining < 2:
                            raise ScanFailure("SOURCE_DEADLINE_EXCEEDED")
                        # Bound this masked acquire/register interval using
                        # libpq's own connect timer; never restart the scan clock.
                        connect_params = dict(params)
                        connect_params["connect_timeout"] = min(5, math.floor(remaining))
                        conn = psycopg.connect(**connect_params, row_factory=dict_row)
                        connections.own(conn.close)
                    # Closing rolls back this read-only transaction. Avoid the
                    # driver's context-manager rollback warning, which can log
                    # source-authored diagnostic text if rollback itself fails.
                    return _metadata(conn, source)
    except TargetPolicyError as error:
        raise ScanFailure(error.code) from None
    except psycopg.Error:
        # Do not attach raw driver details as a cause: they can contain secrets.
        raise ScanFailure("SOURCE_DATABASE_ERROR") from None


def _metadata(conn, source):
    from .postgres_lineage import extract as extract_lineage

    conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
    identity = conn.execute("SELECT current_user AS role, current_setting('server_version') AS version, oid::text AS db_oid FROM pg_database WHERE datname=current_database()").fetchone()
    role = conn.execute("SELECT oid::text AS role_oid, rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user").fetchone()
    if role["rolsuper"] or role["rolbypassrls"]:
        raise ScanFailure("SOURCE_PRIVILEGE_TOO_BROAD")
    schema = conn.execute("SELECT oid::text, nspname, has_schema_privilege(oid, 'USAGE') AS allowed FROM pg_namespace WHERE nspname=%s", (source["schema"],)).fetchone()
    if not schema or not schema["allowed"]:
        raise ScanFailure("SOURCE_SCHEMA_DENIED")
    # All relations are inspected for scope completeness before SELECT privilege filtering.
    relations = conn.execute("""SELECT c.oid::text, c.relname, c.relkind,
        has_table_privilege(c.oid, 'SELECT') AS allowed,
        left(obj_description(c.oid, 'pg_class'),4096) AS description,
        length(obj_description(c.oid, 'pg_class')) > 4096 AS description_truncated
        FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname=%s AND c.relkind IN ('r','p','v','m','f') ORDER BY c.oid LIMIT %s""",
        (source["schema"], MAX_RECORDS + 1)).fetchall()
    if len(relations) > MAX_RECORDS:
        raise ScanFailure("SOURCE_RECORD_LIMIT")
    if any(not row["allowed"] for row in relations):
        raise ScanFailure("SOURCE_SCOPE_INCOMPLETE")
    prefix = f"pg:{identity['db_oid']}"
    schema_id = f"{prefix}:schema:{schema['oid']}"
    namespace = f"{source['database']}.{source['schema']}"
    records = [{"externalId": schema_id, "name": source["schema"], "qualifiedName": namespace,
                "type": "schema", "metadata": {"oid": schema["oid"], "provenance": "source-observed"}}]
    for rel in relations:
        rel_id = f"{prefix}:relation:{rel['oid']}"
        qualified = f"{namespace}.{rel['relname']}"
        records.append({"externalId": rel_id, "name": rel["relname"], "qualifiedName": qualified,
            "type": "view" if rel["relkind"] in ("v", "m") else "table", "parentExternalId": schema_id,
            "metadata": {"oid": rel["oid"], "relationKind": rel["relkind"], "schema": source["schema"], "table": rel["relname"], "sourceDescription": rel["description"], "sourceDescriptionTruncated": bool(rel["description_truncated"]), "provenance": "source-observed"}})
        columns = conn.execute("""SELECT a.attnum, a.attname, format_type(a.atttypid,a.atttypmod) AS data_type,
            a.attnotnull, left(col_description(a.attrelid,a.attnum),4096) AS description,
            length(col_description(a.attrelid,a.attnum)) > 4096 AS description_truncated,
            EXISTS (SELECT 1 FROM pg_constraint c WHERE c.conrelid=a.attrelid AND c.contype='p' AND a.attnum=ANY(c.conkey)) AS primary_key
            FROM pg_attribute a WHERE a.attrelid=%s::oid AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum""", (rel["oid"],)).fetchall()
        for col in columns:
            records.append({"externalId": f"{rel_id}:column:{col['attnum']}", "name": col["attname"],
                "qualifiedName": f"{qualified}.{col['attname']}", "type": "column", "parentExternalId": rel_id,
                "metadata": {"dataType": col["data_type"], "nullable": not col["attnotnull"], "ordinalPosition": col["attnum"],
                    "primaryKey": col["primary_key"], "sourceDescription": col["description"], "sourceDescriptionTruncated": bool(col["description_truncated"]), "provenance": "source-observed"}})
        if len(records) > MAX_RECORDS:
            raise ScanFailure("SOURCE_RECORD_LIMIT")
    # Inventory is not authorization: excluding relation OIDs permits confirmed absence
    # reconciliation. Every extant relation was checked above; reduced SELECT
    # privilege fails the entire scan rather than changing a completeness claim.
    permissions = {"databaseOid": identity["db_oid"], "roleOid": role["role_oid"],
        "schemaOid": schema["oid"], "requiredPrivileges": ["USAGE_SCHEMA", "SELECT_ALL_EXTANT_RELATIONS"]}
    result = {"observedAt": datetime.now(timezone.utc).isoformat(), "sourceVersion": identity["version"],
        "permissionFingerprint": hashlib.sha256(json.dumps(permissions, sort_keys=True).encode()).hexdigest(),
        "records": records, "complete": True,
        "lineage": extract_lineage(conn, identity["db_oid"], schema["oid"], relations)}
    if len(json.dumps(result).encode()) > MAX_BYTES:
        raise ScanFailure("SOURCE_BYTE_LIMIT")
    return result
