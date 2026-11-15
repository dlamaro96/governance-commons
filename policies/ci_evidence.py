#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Publish only test outcomes and explicit post-login synthetic catalog images."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / ".local/ci-artifacts"
DEST.mkdir(parents=True, exist_ok=True)
if any(DEST.iterdir()):
    raise SystemExit("Artifact staging must be empty; refusing to publish a mixed or stale directory")
allowed_outcomes = {"success", "failure", "cancelled", "skipped"}
outcomes = {}
for step in ("bootstrap", "services", "seed", "connectors", "security", "browser"):
    value = os.environ.get(f"GC_{step.upper()}_RESULT", "skipped")
    outcomes[step] = value if value in allowed_outcomes else "unknown"
report = {
    "schema_version": 1,
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "commit": os.environ.get("GITHUB_SHA"),
    "run_url": f"https://github.com/{os.environ.get('GITHUB_REPOSITORY', '')}/actions/runs/{os.environ.get('GITHUB_RUN_ID', '')}",
    "profile": "core / GitHub-hosted Ubuntu 24.04 / synthetic PostgreSQL",
    "steps": outcomes,
    "outcome": "PASS" if all(value == "success" for value in outcomes.values()) else "NOT_PASSED",
    "tests": [],
    "screenshots": [],
    "limitations": ["No traces, videos, error messages, stdout, cookies, request headers, bootstrap files or raw Playwright reports are published.",
                    "This local synthetic profile is not vendor-live, full accessibility, enterprise or release qualification."],
}
source = ROOT / ".local/evidence/playwright-results.json"
if source.is_file():
    data = json.loads(source.read_text())
    def collect(suites):
        for suite in suites:
            collect(suite.get("suites", []))
            for spec in suite.get("specs", []):
                for test in spec.get("tests", []):
                    # Test titles and errors can contain values; retain only
                    # source locations and known outcome enums.
                    results = test.get("results", [])
                    status = test.get("status", "unknown")
                    filename = Path(str(spec.get("file", ""))).name
                    if filename not in {"vertical-slice.spec.ts", "ui-accessibility.spec.ts"}:
                        continue
                    line = spec.get("line")
                    report["tests"].append({"file": "tests/e2e/" + filename, "line": line if isinstance(line, int) else None,
                        "status": status if status in {"expected", "unexpected", "flaky", "skipped"} else "unknown",
                        "attempts": len(results), "duration_ms": sum(r.get("duration", 0) for r in results)})
    collect(data.get("suites", []))
if outcomes["browser"] == "success" and (not report["tests"] or any(test["status"] != "expected" for test in report["tests"])):
    report["outcome"] = "NOT_PASSED"
if outcomes["browser"] == "success":
    names = [f"catalog-en-light-{width}.png" for width in (390, 768, 1024, 1280, 1440)]
    names += ["catalog-en-dark-1440.png", "catalog-history.png"]
    names += [f"catalog-ar-dark-{width}.png" for width in (390, 768, 1440)]
    for name in names:
        path = ROOT / "docs/verification/screenshots" / name
        if path.is_file() and not path.is_symlink() and path.stat().st_size < 16 * 1024 * 1024:
            shutil.copyfile(path, DEST / name)
            report["screenshots"].append(name)
(DEST / "behavior-summary.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({"outcome": report["outcome"], "test_records": len(report["tests"]), "screenshots": len(report["screenshots"])}))
sys.exit(0 if report["outcome"] == "PASS" else 1)
