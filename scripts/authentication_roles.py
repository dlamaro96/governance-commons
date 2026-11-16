#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Closed deployment SQL for the inactive authentication foundation.

These functions return SQL for an authenticated cluster administrator. The caller
must send it through private stdin, never logs or command arguments. No command
connects to a database implicitly, rotates an existing password, enables a revoked
role, or supplies application authority. Canonical registration is a separate
native migration-owner operation.
"""
import re

DEFINER = "gc_authn_definer"
FUNCTIONS = {
    "login": (
        "public.gc_authn_attempt_begin(text,text,text)",
        "public.gc_authn_attempt_consume(uuid,text)",
        "public.gc_authn_session_issue(uuid,text,text,text,text,text,timestamp with time zone,timestamp with time zone,timestamp with time zone,text,text)",
    ),
    "api": (
        "public.gc_authn_session_inspect(text)",
        "public.gc_authn_session_revoke(text,text,integer)",
        "public.gc_authn_session_select(text,text,integer,uuid,text)",
    ),
}
TYPES = {
    "login": ("gc_authn_attempt_started", "gc_authn_attempt_exchange", "gc_authn_session_issued"),
    "api": ("gc_authn_authenticated_session", "gc_authn_session_revoked", "gc_authn_session_selected"),
}


def identifier(value):
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= 63 or '$authn_deployment$' in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Invalid deployment identifier")
    return '"' + value.replace('"', '""') + '"'


def literal(value):
    if not isinstance(value, str) or "\x00" in value or '$authn_deployment$' in value:
        raise ValueError("Invalid deployment scalar")
    return "'" + value.replace("'", "''") + "'"


def safe_role(alias, login):
    return (f"{alias}.rolcanlogin IS DISTINCT FROM {'true' if login else 'false'} OR "
            f"{alias}.rolsuper OR {alias}.rolcreatedb OR {alias}.rolcreaterole OR "
            f"{alias}.rolinherit OR {alias}.rolbypassrls OR {alias}.rolreplication")


def _administrator(database=None):
    expected = (f"IF current_database() <> {literal(database)} THEN RAISE EXCEPTION 'AUTHN_DEPLOYMENT_DATABASE_REJECTED'; END IF;" if database else "")
    return f"""SET standard_conforming_strings = on;
DO $authn_deployment$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=session_user AND rolsuper)
    OR session_user<>current_user THEN RAISE EXCEPTION 'AUTHN_DEPLOYMENT_ADMIN_REQUIRED'; END IF;
 {expected}
 IF current_setting('max_prepared_transactions')::integer <> 0 THEN
  RAISE EXCEPTION 'AUTHN_PREPARED_TRANSACTIONS_UNSUPPORTED'; END IF;
END $authn_deployment$;
"""


def prepare_sql(owner, database):
    """Create/validate only the definer and stage an exact SET-only transfer grant."""
    owner_id, _ = identifier(owner), identifier(database)
    if owner in (DEFINER, "gc_app", "postgres"):
        raise ValueError("Invalid migration owner")
    return "BEGIN;\n" + _administrator(database) + f"""
DO $authn_deployment$ DECLARE r pg_catalog.pg_roles%ROWTYPE; BEGIN
 SELECT * INTO r FROM pg_catalog.pg_roles WHERE rolname={literal(owner)};
 IF NOT FOUND OR {safe_role('r', True)} THEN RAISE EXCEPTION 'AUTHN_OWNER_FLAGS_REJECTED'; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname=current_database() AND datdba=r.oid)
    OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname='public' AND nspowner=r.oid) THEN
  RAISE EXCEPTION 'AUTHN_OWNER_OBJECTS_REJECTED'; END IF;
 IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=r.oid OR roleid=r.oid) THEN
  RAISE EXCEPTION 'AUTHN_OWNER_MEMBERSHIP_REJECTED'; END IF;
 SELECT * INTO r FROM pg_catalog.pg_roles WHERE rolname='gc_authn_definer';
 IF NOT FOUND THEN
  CREATE ROLE gc_authn_definer NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
 ELSE
  IF {safe_role('r', False)} OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=r.oid OR roleid=r.oid) THEN
   RAISE EXCEPTION 'AUTHN_DEFINER_REJECTED'; END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_class WHERE relowner=r.oid)
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspowner=r.oid)
     OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
       WHERE p.proowner=r.oid AND n.nspname NOT IN ('public','gc_authn')) THEN
   RAISE EXCEPTION 'AUTHN_DEFINER_OWNERSHIP_REJECTED'; END IF;
 END IF;
END $authn_deployment$;
GRANT gc_authn_definer TO {owner_id} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
GRANT CREATE ON SCHEMA public TO gc_authn_definer;
COMMIT;
"""


def finish_sql(owner):
    """Remove only staged transfer permissions, including after failed migration."""
    owner_id = identifier(owner)
    if owner in (DEFINER, "gc_app", "postgres"):
        raise ValueError("Invalid migration owner")
    return _administrator() + f"""
DO $authn_deployment$ BEGIN
 IF EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members a
   JOIN pg_catalog.pg_roles granted ON granted.oid=a.roleid
   JOIN pg_catalog.pg_roles member_role ON member_role.oid=a.member
   WHERE granted.rolname='gc_authn_definer' AND member_role.rolname={literal(owner)}
     AND a.set_option AND NOT a.inherit_option AND NOT a.admin_option)
 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members a
   JOIN pg_catalog.pg_roles granted ON granted.oid=a.roleid
   JOIN pg_catalog.pg_roles member_role ON member_role.oid=a.member
   WHERE granted.rolname='gc_authn_definer' AND member_role.rolname={literal(owner)}
     AND (NOT a.set_option OR a.inherit_option OR a.admin_option)) THEN
  REVOKE gc_authn_definer FROM {owner_id};
  REVOKE CREATE ON SCHEMA public FROM gc_authn_definer;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname='gc_authn') THEN
   REVOKE CREATE ON SCHEMA gc_authn FROM gc_authn_definer;
  END IF;
 END IF;
END $authn_deployment$;
-- Cleanup commits before assertions, so an independent unsafe flag cannot
-- roll the exact transfer-permission revocations back.
DO $authn_deployment$ DECLARE r pg_catalog.pg_roles%ROWTYPE; BEGIN
 SELECT * INTO r FROM pg_catalog.pg_roles WHERE rolname='gc_authn_definer';
 IF FOUND AND ({safe_role('r', False)} OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=r.oid OR roleid=r.oid)
    OR pg_catalog.has_schema_privilege(r.oid,'public','CREATE')
    OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n WHERE n.nspname='gc_authn'
      AND pg_catalog.has_schema_privilege(r.oid,n.oid,'CREATE'))) THEN
  RAISE EXCEPTION 'AUTHN_DEFINER_FINAL_STATE_REJECTED'; END IF;
 SELECT * INTO STRICT r FROM pg_catalog.pg_roles WHERE rolname={literal(owner)};
 IF {safe_role('r', True)} OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=r.oid OR roleid=r.oid) THEN
  RAISE EXCEPTION 'AUTHN_OWNER_FINAL_STATE_REJECTED'; END IF;
END $authn_deployment$;
"""


def executor_sql(database, roles):
    """Create exact role families after SQL012; matching existing roles are read-only.

    Roles must be new, or already have precisely the intended usable family. A
    missing grant or NOLOGIN on an existing role is an explicit refusal, not an
    invitation to restore access. Credentials for existing roles are never used.
    """
    database_id = identifier(database)
    if not isinstance(roles, list) or not roles:
        raise ValueError("An explicit deployment role list is required")
    names = set()
    chunks = ["BEGIN;\n", _administrator(database)]
    for role in roles:
        if not isinstance(role, dict) or set(role) != {"name", "kind", "password"}:
            raise ValueError("Invalid deployment role fields")
        name, kind, password = role["name"], role["kind"], role["password"]
        role_id = identifier(name)
        if name in names or name in ("postgres", "gc_owner", "gc_app", DEFINER) or kind not in FUNCTIONS:
            raise ValueError("Invalid or duplicate deployment role")
        if not isinstance(password, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", password):
            raise ValueError("Invalid generated deployment credential")
        names.add(name)
        grants = "\n".join(f"GRANT EXECUTE ON FUNCTION {signature} TO {role_id};" for signature in FUNCTIONS[kind])
        grants += "\n" + "\n".join(f"GRANT USAGE ON TYPE public.{name_} TO {role_id};" for name_ in TYPES[kind])
        checks = "\n".join(
            f"IF pg_catalog.has_function_privilege(r.oid,{literal(signature)},'EXECUTE') IS DISTINCT FROM {'true' if family==kind else 'false'} THEN RAISE EXCEPTION 'AUTHN_EXECUTOR_FUNCTIONS_REJECTED'; END IF;"
            for family, signatures in FUNCTIONS.items() for signature in signatures)
        checks += "\n" + "\n".join(
            f"IF pg_catalog.has_type_privilege(r.oid,{literal('public.'+typename)},'USAGE') IS DISTINCT FROM {'true' if family==kind else 'false'} THEN RAISE EXCEPTION 'AUTHN_EXECUTOR_TYPES_REJECTED'; END IF;"
            for family, typenames in TYPES.items() for typename in typenames)
        chunks.append(f"""
DO $authn_deployment$ DECLARE r pg_catalog.pg_roles%ROWTYPE; BEGIN
 SELECT * INTO r FROM pg_catalog.pg_roles WHERE rolname={literal(name)};
 IF NOT FOUND THEN
  CREATE ROLE {role_id} LOGIN PASSWORD {literal(password)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION;
  GRANT CONNECT ON DATABASE {database_id} TO {role_id};
  GRANT USAGE ON SCHEMA public TO {role_id};
  {grants}
 END IF;
 SELECT * INTO STRICT r FROM pg_catalog.pg_roles WHERE rolname={literal(name)};
 IF {safe_role('r', True)} OR EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=r.oid OR roleid=r.oid) THEN
  RAISE EXCEPTION 'AUTHN_EXECUTOR_FLAGS_REJECTED'; END IF;
 IF NOT pg_catalog.has_database_privilege(r.oid,current_database(),'CONNECT')
    OR pg_catalog.has_database_privilege(r.oid,current_database(),'CREATE')
    OR pg_catalog.has_database_privilege(r.oid,current_database(),'TEMP')
    OR NOT pg_catalog.has_schema_privilege(r.oid,'public','USAGE')
    OR pg_catalog.has_schema_privilege(r.oid,'public','CREATE')
    OR pg_catalog.has_schema_privilege(r.oid,'gc_authn','USAGE') THEN
  RAISE EXCEPTION 'AUTHN_EXECUTOR_SCHEMA_REJECTED'; END IF;
 IF EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE CASE WHEN n.nspname IN ('public','gc_authn') AND c.relkind IN ('r','p','v','m','f')
     THEN (c.relowner=r.oid OR pg_catalog.has_table_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
       OR pg_catalog.has_any_column_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')) ELSE false END)
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
   WHERE CASE WHEN n.nspname IN ('public','gc_authn') AND c.relkind='S'
     THEN pg_catalog.has_sequence_privilege(r.oid,c.oid,'USAGE,SELECT,UPDATE') ELSE false END) THEN
  RAISE EXCEPTION 'AUTHN_EXECUTOR_BASE_ACCESS_REJECTED'; END IF;
 {checks}
 IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
   WHERE n.nspname IN ('public','gc_authn') AND pg_catalog.has_function_privilege(r.oid,p.oid,'EXECUTE')
   AND p.oid NOT IN ({','.join(literal(s)+'::pg_catalog.regprocedure' for s in FUNCTIONS[kind])})) THEN
  RAISE EXCEPTION 'AUTHN_EXECUTOR_EXTRA_FUNCTION_REJECTED'; END IF;
END $authn_deployment$;
""")
    return "".join(chunks) + "COMMIT;\n"
