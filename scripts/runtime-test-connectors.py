#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real PostgreSQL conformance in the synthetic local source only. No source values."""
import json
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ["docker", "compose", "--project-name", "governance-commons", "--env-file", str(ROOT / ".local/runtime.env"), "-f", str(ROOT / "deploy/compose/compose.yaml")]

def execute(args):
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError("Connector conformance subprocess failed; inspect project-local service health")
    return result.stdout

def sql(statement):
    # This helper receives only fixed statements and generated hex identifiers below.
    execute(COMPOSE + ["exec", "-T", "source-postgres", "psql", "-U", "source_admin", "-d", "harbor", "-v", "ON_ERROR_STOP=1", "-c", statement])

WORKER_SCAN = '''import json,os
from governance_workers.postgresql import scan,ScanFailure
with open(os.environ["SOURCE_SECRETS_FILE"]) as f: secret=json.load(f)["demo-postgres"]
source={k:secret[k] for k in ("host","port","database","schema")}
try:
 result=scan(source,secret,secret["tenantIds"][0])
 print(json.dumps({"ok":True,"fingerprint":result["permissionFingerprint"],"version":result["sourceVersion"],"records":[{"id":r["externalId"],"name":r["name"],"parent":r.get("parentExternalId")} for r in result["records"]]}))
except ScanFailure as e: print(json.dumps({"ok":False,"code":e.code}))
'''

def scan():
    return json.loads(execute(COMPOSE + ["exec", "-T", "python-worker", "/worker/.venv/bin/python", "-c", WORKER_SCAN]))

def main():
    unit = subprocess.run(COMPOSE + ["exec", "-T", "python-worker", "/worker/.venv/bin/python", "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=ROOT, timeout=120)
    if unit.returncode:
        raise RuntimeError("Worker source/unit suite failed")
    original = "gc_conformance_" + uuid.uuid4().hex[:12]
    renamed = original + "_renamed"
    try:
        sql(f'CREATE TABLE "{original}" (before_name integer PRIMARY KEY, description text);')
        before = scan()
        assert before["ok"], "Initial real source scan failed"
        table = next(r for r in before["records"] if r["name"] == original)
        column = next(r for r in before["records"] if r["name"] == "before_name" and r["parent"] == table["id"])
        sql(f'ALTER TABLE "{original}" RENAME TO "{renamed}"; ALTER TABLE "{renamed}" RENAME COLUMN before_name TO after_name;')
        after = scan()
        assert after["ok"]
        assert next(r for r in after["records"] if r["name"] == renamed)["id"] == table["id"], "Table rename changed external identity"
        assert next(r for r in after["records"] if r["name"] == "after_name" and r["parent"] == table["id"])["id"] == column["id"], "Column rename changed external identity"
        assert before["fingerprint"] == after["fingerprint"], "Rename changed authorization context"
        sql(f'REVOKE SELECT ON "{renamed}" FROM harbor_reader;')
        revoked = scan()
        assert revoked == {"ok": False, "code": "SOURCE_SCOPE_INCOMPLETE"}, "Reduced privileges incorrectly returned a complete snapshot"
        sql(f'DROP TABLE "{renamed}";')
        deleted = scan()
        assert deleted["ok"] and deleted["fingerprint"] == before["fingerprint"], "Deletion was confused with authorization-context change"
        assert not any(r["id"] == table["id"] for r in deleted["records"]), "Deleted source table remained observed"
        print(json.dumps({"suite":"postgresql-local-conformance","result":"passed","sourceVersion":deleted["version"],"checks":["read-only credentials","tenant destination guard","metadata without source values","table rename stable OID","column rename stable attnum","permission reduction incomplete scan","deletion preserves authorization fingerprint"]}))
    finally:
        sql(f'DROP TABLE IF EXISTS "{original}"; DROP TABLE IF EXISTS "{renamed}";')

if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"suite":"postgresql-local-conformance","result":"failed","error":str(error)}), file=sys.stderr)
        raise SystemExit(1)
