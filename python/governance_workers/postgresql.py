# SPDX-License-Identifier: Apache-2.0
"""Bounded catalog extraction. Never executes source-authored SQL or reads rows."""
import hashlib
import json
from datetime import datetime, timezone
import psycopg
from psycopg.rows import dict_row

MAX_RECORDS = 10000
MAX_BYTES = 8 * 1024 * 1024

class ScanFailure(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def validate_target(source, secret, tenant_id):
    if tenant_id not in secret.get("tenantIds", []):
        raise ScanFailure("SOURCE_SCOPE_DENIED")
    for key in ("host", "port", "database", "schema"):
        if source.get(key) != secret.get(key):
            raise ScanFailure("SOURCE_TARGET_DENIED")
    if secret.get("host") != "source-postgres" or secret.get("port") != 5432:
        raise ScanFailure("SOURCE_DESTINATION_DENIED")


def scan(source, secret, tenant_id):
    validate_target(source, secret, tenant_id)
    try:
        with psycopg.connect(host=secret["host"], port=secret["port"], dbname=secret["database"],
                user=secret["username"], password=secret["password"], connect_timeout=5,
                options="-c default_transaction_read_only=on -c statement_timeout=15000 -c lock_timeout=2000",
                row_factory=dict_row) as conn:
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            identity = conn.execute("SELECT current_user AS role, current_setting('server_version') AS version, oid::text AS db_oid FROM pg_database WHERE datname=current_database()").fetchone()
            role = conn.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user").fetchone()
            if role["rolsuper"] or role["rolbypassrls"]:
                raise ScanFailure("SOURCE_PRIVILEGE_TOO_BROAD")
            schema = conn.execute("SELECT oid::text, nspname, has_schema_privilege(oid, 'USAGE') AS allowed FROM pg_namespace WHERE nspname=%s", (source["schema"],)).fetchone()
            if not schema or not schema["allowed"]:
                raise ScanFailure("SOURCE_SCHEMA_DENIED")
            # All relations are inspected for scope completeness before SELECT privilege filtering.
            relations = conn.execute("""SELECT c.oid::text, c.relname, c.relkind,
                has_table_privilege(c.oid, 'SELECT') AS allowed,
                obj_description(c.oid, 'pg_class') AS description
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
                    "metadata": {"oid": rel["oid"], "relationKind": rel["relkind"], "schema": source["schema"], "table": rel["relname"], "sourceDescription": rel["description"], "provenance": "source-observed"}})
                columns = conn.execute("""SELECT a.attnum, a.attname, format_type(a.atttypid,a.atttypmod) AS data_type,
                    a.attnotnull, col_description(a.attrelid,a.attnum) AS description,
                    EXISTS (SELECT 1 FROM pg_constraint c WHERE c.conrelid=a.attrelid AND c.contype='p' AND a.attnum=ANY(c.conkey)) AS primary_key
                    FROM pg_attribute a WHERE a.attrelid=%s::oid AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum""", (rel["oid"],)).fetchall()
                for col in columns:
                    records.append({"externalId": f"{rel_id}:column:{col['attnum']}", "name": col["attname"],
                        "qualifiedName": f"{qualified}.{col['attname']}", "type": "column", "parentExternalId": rel_id,
                        "metadata": {"dataType": col["data_type"], "nullable": not col["attnotnull"], "ordinalPosition": col["attnum"],
                            "primaryKey": col["primary_key"], "sourceDescription": col["description"], "provenance": "source-observed"}})
                if len(records) > MAX_RECORDS:
                    raise ScanFailure("SOURCE_RECORD_LIMIT")
            # Names intentionally excluded: a rename preserves the authorization-context fingerprint.
            permissions = {"role": identity["role"], "schemaOid": schema["oid"], "relationOids": [r["oid"] for r in relations]}
            result = {"observedAt": datetime.now(timezone.utc).isoformat(), "sourceVersion": identity["version"],
                "permissionFingerprint": hashlib.sha256(json.dumps(permissions, sort_keys=True).encode()).hexdigest(),
                "records": records, "complete": True}
            if len(json.dumps(result).encode()) > MAX_BYTES:
                raise ScanFailure("SOURCE_BYTE_LIMIT")
            return result
    except psycopg.Error as error:
        # Driver messages may contain hostnames or credentials. Only stable codes cross the boundary.
        raise ScanFailure("SOURCE_DATABASE_ERROR") from error
