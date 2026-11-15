#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Inspect an actual completed Temporal scan; never export its raw history."""
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from runtime import COMPOSE, ROOT, require_bootstrap, require_local

def execute(args):
    result = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=45)
    if result.returncode:
        raise RuntimeError("History inspection subprocess failed; raw logs withheld")
    return result.stdout.strip()

def main():
    require_bootstrap(); require_local()
    evidence = {"schema_version": 1, "suite": "temporal-payload-boundary", "profile": "core", "started_at": datetime.now(timezone.utc).isoformat(),
        "command": "./dev test --suite histories", "revision": {"base_commit": execute(["git", "rev-parse", "HEAD"]), "working_tree": "file-hash-bound; final commit binding pending"},
        "limitations": ["One completed real synthetic local scan only", "Does not qualify failed/retried histories, in-flight recovery, other workflows or enterprise Temporal"]}
    try:
        row = execute(COMPOSE + ["exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "governance", "-At", "-v", "ON_ERROR_STOP=1", "-c", "SELECT tenant_id::text || ':' || id::text FROM jobs WHERE status='succeeded' ORDER BY finished_at DESC LIMIT 1"])
        if not row:
            raise RuntimeError("Prerequisite: complete a real scan through the application first")
        tenant, job = row.split(":")
        workflow = "scan:" + row
        raw = execute(COMPOSE + ["run", "--rm", "--no-deps", "--entrypoint", "temporal", "temporal-namespace", "workflow", "show", "--workflow-id", workflow, "--output", "json"])
        history = json.loads(raw)
        expected = {
            "EVENT_TYPE_WORKFLOW_EXECUTION_STARTED": ("input", {"tenantId": tenant, "jobId": job}),
            "EVENT_TYPE_ACTIVITY_TASK_SCHEDULED": ("input", {"tenantId": tenant, "jobId": job}),
            "EVENT_TYPE_ACTIVITY_TASK_COMPLETED": ("result", None),
            "EVENT_TYPE_WORKFLOW_EXECUTION_COMPLETED": ("result", None),
        }
        observations, decoded_text = [], []
        for event in history["events"]:
            for value in event.values():
                if not isinstance(value, dict):
                    continue
                for field, content in value.items():
                    if not isinstance(content, dict) or "payloads" not in content:
                        continue
                    event_type = event["eventType"]
                    if event_type not in expected or expected[event_type][0] != field or len(content["payloads"]) != 1:
                        raise RuntimeError("Unexpected Temporal payload boundary")
                    payload_text = base64.b64decode(content["payloads"][0]["data"], validate=True).decode()
                    payload = json.loads(payload_text)
                    decoded_text.append(payload_text)
                    if expected[event_type][1] is not None:
                        if payload != expected[event_type][1]:
                            raise RuntimeError("Workflow or activity input contains more than scoped IDs")
                    elif set(payload) != {"status", "assetCount"} or payload["status"] != "succeeded" or type(payload["assetCount"]) is not int or payload["assetCount"] < 1:
                        raise RuntimeError("Completion payload is not a sanitized successful count")
                    observations.append({"event_type": event_type, "field": field, "keys": sorted(payload)})
        if sorted(o["event_type"] for o in observations) != sorted(expected):
            raise RuntimeError("Expected four successful scan payload boundaries")
        state = json.loads((ROOT / ".local/bootstrap.json").read_text())
        secrets = [value for value in state.values() if isinstance(value, str)] + list(state["personas"].values())
        inspected = raw + "\n" + "\n".join(decoded_text)
        if any(secret in inspected for secret in secrets):
            raise RuntimeError("A bootstrap credential was found in history; history withheld")
        evidence.update({"result": "passed", "exit_status": 0, "workflow_id": workflow, "event_count": len(history["events"]), "payloads": observations,
            "history_sha256": hashlib.sha256(raw.encode()).hexdigest(), "checks": ["workflow and activity input contain tenant/job IDs only", "activity and workflow result contain status/count only", "no bootstrap credentials in raw or decoded payloads"], "raw_history_exported": False})
    except Exception as error:
        evidence.update({"result": "failed", "exit_status": 1, "error": str(error)})
    finally:
        evidence["finished_at"] = datetime.now(timezone.utc).isoformat()
        evidence["implementation_sha256"] = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in ["scripts/runtime-test-histories.py", "apps/workflow-worker/src/index.ts", "apps/workflow-worker/src/workflows.ts", "apps/site-runner/src/index.ts"]}
        destination = ROOT / "docs/verification/core-temporal-payloads.json"
        destination.write_text(json.dumps(evidence, indent=2) + "\n")
        print(json.dumps({"suite": evidence["suite"], "result": evidence["result"], "evidence": str(destination.relative_to(ROOT)), "error": evidence.get("error")}))
    return evidence["exit_status"]

if __name__ == "__main__":
    raise SystemExit(main())
