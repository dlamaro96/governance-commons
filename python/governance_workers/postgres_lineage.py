# SPDX-License-Identifier: Apache-2.0
"""Direct PostgreSQL rewrite dependencies, never source SQL or column mappings.

The caller owns the scan's read-only repeatable-read transaction and deadline.
Only relation identities already admitted by that scan can become endpoints.
"""
import json
import re

from .postgresql import ScanFailure

MAX_VIEWS = 1000
MAX_EDGES = 5000
MAX_WITNESS_ROWS = 10000
MAX_BYTES = 1024 * 1024
_OID = re.compile(r"[1-9][0-9]{0,9}\Z")
_RELATION_KINDS = frozenset(("r", "p", "v", "m", "f"))

_RULES = """SELECT r.ev_class::text AS view_oid, r.oid::text AS rewrite_oid
    FROM pg_catalog.pg_rewrite r
    WHERE r.ev_class = ANY(%s::oid[]) AND r.rulename = '_RETURN'
      AND r.ev_type = '1' AND r.is_instead
    ORDER BY r.ev_class, r.oid LIMIT %s"""

# Include all dependency classes and kinds in the raw-row budget. The projection
# never selects source text, object names, function bodies or an external schema.
_WITNESSES = """SELECT d.objid::text AS rewrite_oid,
      d.refobjid::text AS referenced_oid, d.refobjsubid AS attribute_number,
      d.deptype AS dependency_kind,
      CASE d.refclassid WHEN 'pg_catalog.pg_class'::regclass THEN 'relation'
        WHEN 'pg_catalog.pg_proc'::regclass THEN 'routine' ELSE 'other' END AS object_kind,
      c.relkind AS relation_kind, (c.relnamespace = %s::oid) AS same_schema
    FROM pg_catalog.pg_depend d
    LEFT JOIN pg_catalog.pg_class c
      ON d.refclassid = 'pg_catalog.pg_class'::regclass AND c.oid = d.refobjid
    WHERE d.classid = 'pg_catalog.pg_rewrite'::regclass
      AND d.objid = ANY(%s::oid[]) AND d.objsubid = 0
    ORDER BY d.objid, d.refclassid, d.refobjid, d.refobjsubid, d.deptype LIMIT %s"""


def _invalid():
    raise ScanFailure("SOURCE_LINEAGE_INVALID")


def _oid(value):
    if type(value) is not str or not _OID.fullmatch(value) or int(value) > 4294967295:
        _invalid()
    return value


def extract(conn, database_oid, schema_oid, relations):
    """Return one closed envelope; any overflow refuses the entire scan."""
    database_oid, schema_oid = _oid(database_oid), _oid(schema_oid)
    admitted = {}
    views = {}
    for relation in relations:
        oid = _oid(relation["oid"])
        kind = relation["relkind"]
        if oid in admitted or kind not in _RELATION_KINDS:
            _invalid()
        admitted[oid] = kind
        if kind in ("v", "m"):
            views[oid] = {"dependencies": {}, "gaps": set()}
            if len(views) > MAX_VIEWS:
                raise ScanFailure("SOURCE_LINEAGE_LIMIT")
    prefix = f"pg:{database_oid}:relation:"
    result = {"formatVersion": 1, "kind": "postgresql-view-dependencies",
              "adapterVersion": "1", "queryTemplate": "postgresql-view-dependencies-v1", "views": []}
    if views:
        rules = conn.execute(_RULES, (sorted(views, key=int), MAX_VIEWS + 1)).fetchall()
        if len(rules) > MAX_VIEWS:
            raise ScanFailure("SOURCE_LINEAGE_LIMIT")
        by_rewrite = {}
        for rule in rules:
            view_oid, rewrite_oid = _oid(rule["view_oid"]), _oid(rule["rewrite_oid"])
            if view_oid not in views or "rewriteOid" in views[view_oid] or rewrite_oid in by_rewrite:
                _invalid()
            views[view_oid]["rewriteOid"] = rewrite_oid
            by_rewrite[rewrite_oid] = view_oid
        if len(by_rewrite) != len(views):
            _invalid()
        rows = conn.execute(_WITNESSES, (schema_oid, sorted(by_rewrite, key=int), MAX_WITNESS_ROWS + 1)).fetchall()
        if len(rows) > MAX_WITNESS_ROWS:
            raise ScanFailure("SOURCE_LINEAGE_LIMIT")
        edges = 0
        for row in rows:
            rewrite_oid = _oid(row["rewrite_oid"])
            referenced_oid = _oid(row["referenced_oid"])
            if rewrite_oid not in by_rewrite:
                _invalid()
            view_oid = by_rewrite[rewrite_oid]
            view = views[view_oid]
            dependency_kind, object_kind = row["dependency_kind"], row["object_kind"]
            # _RETURN is internally owned by its own view. That i-dependency is
            # not a data edge; a NORMAL dependency on the same OID still is.
            if dependency_kind != "n":
                continue
            if object_kind == "routine":
                view["gaps"].add("OPAQUE_ROUTINE_DEPENDENCY")
                continue
            if object_kind == "other":
                continue
            if object_kind != "relation" or row["relation_kind"] is None or type(row["same_schema"]) is not bool:
                _invalid()
            if row["relation_kind"] not in _RELATION_KINDS:
                view["gaps"].add("UNSUPPORTED_RELATION_KIND")
                continue
            if not row["same_schema"]:
                view["gaps"].add("OUT_OF_SCOPE_RELATION")
                continue
            # A supported relation in the registered schema must be present in
            # the complete, SELECT-admitted inventory from this same snapshot.
            if admitted.get(referenced_oid) != row["relation_kind"]:
                _invalid()
            number = row["attribute_number"]
            if type(number) is not int or not 0 <= number <= 32767:
                _invalid()
            dependencies = view["dependencies"]
            if referenced_oid not in dependencies:
                edges += 1
                if edges > MAX_EDGES:
                    raise ScanFailure("SOURCE_LINEAGE_LIMIT")
                dependencies[referenced_oid] = set()
            dependencies[referenced_oid].add(number)
        for oid in sorted(views, key=lambda value: prefix + value):
            view = views[oid]
            result["views"].append({"viewExternalId": prefix + oid, "rewriteOid": view["rewriteOid"],
                "dependencies": [{"referencedExternalId": prefix + target,
                    "referencedAttributeNumbers": sorted(numbers)}
                    for target, numbers in sorted(view["dependencies"].items(), key=lambda pair: prefix + pair[0])],
                "gaps": sorted(view["gaps"])})
    if len(json.dumps(result).encode("utf-8")) > MAX_BYTES:
        raise ScanFailure("SOURCE_LINEAGE_LIMIT")
    return result
