#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Controlled local restart persistence; never removes volumes or source data."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from runtime import COMPOSE, ROOT, require_bootstrap, require_local

TABLES = ("tenants", "identities", "memberships", "sources", "assets", "asset_revisions", "jobs", "audit", "idempotency", "schema_migrations")
SERVICES = ("api", "workflow-worker", "site-runner", "python-worker", "keycloak", "temporal", "opensearch", "seaweedfs", "source-postgres", "postgres")
EVIDENCE = ROOT / "docs/verification/core-recovery.json"
commands = []

def execute(arguments, timeout=120):
    result = subprocess.run(arguments, cwd=ROOT, text=True, capture_output=True, timeout=timeout)
    commands.append({"command": [str(a).replace(str(ROOT) + "/", "") for a in arguments], "exit_status": result.returncode})
    if result.returncode:
        # Never persist arbitrary Docker logs; upstream output can contain config.
        raise RuntimeError(f"Command {len(commands)} failed with exit status {result.returncode}")
    return result.stdout.strip()

def query(statement):
    return execute(COMPOSE + ["exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "governance", "-qAt", "-v", "ON_ERROR_STOP=1", "-c", statement])

def snapshot():
    # The fixed table names are code, not user input. Only counts and digests leave
    # PostgreSQL; sessions, CSRF state and source credentials are never selected.
    pairs = []
    for table in TABLES:
        pairs.append(f"'{table}', (SELECT jsonb_build_object('count',count(*),'sha256',encode(sha256(convert_to(coalesce(string_agg(row_to_json(t)::text,'' ORDER BY row_to_json(t)::text),''),'UTF8')),'hex')) FROM {table} t)")
    return json.loads(query("BEGIN TRANSACTION READ ONLY; SELECT jsonb_build_object(" + ",".join(pairs) + "); COMMIT;"))

def service_state():
    output = execute(COMPOSE + ["ps", "--all", "--format", "json"])
    return [{"service": r["Service"], "state": r["State"], "health": r.get("Health"), "exit_status": r.get("ExitCode")} for r in map(json.loads, output.splitlines())]

def main():
    require_bootstrap(); require_local()
    report = {"schema_version": 1, "suite": "core-restart-persistence", "profile": "core", "started_at": datetime.now(timezone.utc).isoformat(),
        "revision": {"base_commit": execute(["git", "rev-parse", "HEAD"]), "working_tree": "file-hash-bound; final commit binding pending"},
        "limitations": ["Existing initialized synthetic local volumes only", "No concurrent mutating tests or browser actions allowed", "No in-flight workflow interruption tested", "No clean installation, restore, upgrade, HA or enterprise qualification"],
        "commands": commands}
    try:
        if query("SELECT count(*) FROM jobs WHERE status IN ('queued','running')") != "0":
            raise RuntimeError("Installation has queued/running jobs; wait for completion before recovery test")
        before = snapshot()
        for _ in range(2):
            execute(COMPOSE + ["run", "--rm", "seed"])
            if snapshot() != before:
                raise RuntimeError("Repeated seed changed canonical data; idempotency was not verified")
        report["seed_invocations"] = 2
        report["before"] = before
        # A graceful stop exercises persistent volumes without deleting containers,
        # resetting identities, or deleting external resources.
        execute(COMPOSE + ["stop", "--timeout", "30", *SERVICES], timeout=180)
        execute(COMPOSE + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "240", "api", "workflow-worker", "site-runner", "python-worker"], timeout=300)
        after = snapshot()
        report["after"] = after
        report["services"] = service_state()
        if before != after:
            raise RuntimeError("Canonical data changed across restart")
        for service in SERVICES:
            row = next(r for r in report["services"] if r["service"] == service)
            if row["state"] != "running" or row["health"] != "healthy":
                raise RuntimeError(f"Service {service} did not recover to healthy")
        report.update({"result": "passed", "checks": ["two idempotent seed invocations", "canonical data digests unchanged", "graceful persistent-volume restart", "all ten long-running services healthy"]})
    except Exception as error:
        report.update({"result": "failed", "error": str(error)})
    finally:
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        report["implementation_sha256"] = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in [Path(__file__), ROOT / "scripts/runtime.py", ROOT / "deploy/compose/compose.yaml", ROOT / "deploy/compose/init-temporal.sh", ROOT / "deploy/compose/temporal-dynamic.yaml", ROOT / "packages/db/src/seed.ts"]}
        EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
        EVIDENCE.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"suite": report["suite"], "result": report["result"], "evidence": str(EVIDENCE.relative_to(ROOT)), "error": report.get("error")}))
    return 0 if report["result"] == "passed" else 1

if __name__ == "__main__":
    raise SystemExit(main())
