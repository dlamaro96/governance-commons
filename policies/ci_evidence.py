#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Publish only test outcomes and explicit post-login synthetic catalog images."""
from datetime import datetime, timezone
import json
import os
import re
from pathlib import Path
import shutil
import sys
from api_evidence import safe_report
from authentication_evidence import load_report as load_authentication_report

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / ".local/ci-artifacts"
DEST.mkdir(parents=True, exist_ok=True)
if any(DEST.iterdir()):
    raise SystemExit("Artifact staging must be empty; refusing to publish a mixed or stale directory")
allowed_outcomes = {"success", "failure", "cancelled", "skipped"}
outcomes = {}
for step in ("bootstrap", "services", "object_store", "seed", "connectors", "security", "model_upgrade", "asset_type_upgrade", "type_migration_upgrade", "relations_upgrade", "relation_participation_upgrade", "business_domains_upgrade", "business_domain_seed", "authority_authn_foundation", "browser"):
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
# The API runner retains raw TAP privately. Only an independently revalidated,
# exact-source report enters this staging directory; absence cannot turn a
# claimed successful security step into verified behavior.
api_source = ROOT / ".local/evidence/api-summary.json"
api_report = None
if api_source.is_file() and not api_source.is_symlink() and api_source.stat().st_size <= 4 * 1024 * 1024:
    try:
        api_report = safe_report(ROOT, json.loads(api_source.read_text()), os.environ.get("GITHUB_SHA"))
    except (OSError, ValueError):
        pass
api_mismatch = bool(api_report and (outcomes["security"] == "skipped" or
                    (outcomes["security"] == "success") != (api_report["outcome"] == "PASS")))
if api_mismatch:
    api_report = None
report["api_evidence"] = "STEP_RESULT_MISMATCH" if api_mismatch else "VERIFIED_PASS" if api_report and api_report["outcome"] == "PASS" else "NOT_PASSED" if api_report else "UNAVAILABLE_OR_INVALID"
if api_report:
    (DEST / "api-summary.json").write_text(json.dumps(api_report, indent=2) + "\n")
if outcomes["security"] == "success" and (not api_report or api_report["outcome"] != "PASS"):
    report["outcome"] = "NOT_PASSED"
# A successful native foundation step requires exact source/log/cleanup evidence.
# Only the closed coordinate projection is staged; failed originals stay private.
authn_report = load_authentication_report(ROOT, os.environ.get("GITHUB_SHA"))
authn_mismatch = bool(authn_report and outcomes["authority_authn_foundation"] != "success")
if authn_mismatch:
    authn_report = None
report["authentication_evidence"] = "STEP_RESULT_MISMATCH" if authn_mismatch else "VERIFIED_PASS" if authn_report else "UNAVAILABLE_OR_INVALID"
if authn_report:
    (DEST / "authentication-summary.json").write_text(json.dumps(authn_report, indent=2) + "\n")
if outcomes["authority_authn_foundation"] == "success" and not authn_report:
    report["outcome"] = "NOT_PASSED"
def failure_locations(results, filename):
    """Only reviewed repository coordinates; never copy exception text/paths."""
    locations = set()
    for result in results[:4]:
        if result.get("status") == "passed":
            continue
        errors = result.get("errors", [])
        if not isinstance(errors, list):
            errors = []
        if isinstance(result.get("error"), dict):
            errors = [result["error"], *errors]
        for error in errors[:8]:
            if not isinstance(error, dict):
                continue
            # Playwright source frames include the actual assertion/helper line.
            # Extract only this already-allowlisted test file, with bounded numeric
            # coordinates. Absolute prefixes, snippets and messages remain private.
            stack = error.get("stack", "")
            if not isinstance(stack, str):
                continue
            pattern = r"(?:^|[/\\])tests[/\\]e2e[/\\]" + re.escape(filename) + r":([1-9][0-9]{0,5}):([1-9][0-9]{0,5})(?=[)\s]|$)"
            for line, column in re.findall(pattern, stack[:65536]):
                locations.add((int(line), int(column)))
    return [{"file": "tests/e2e/" + filename, "line": line, "column": column}
            for line, column in sorted(locations)[:8]]

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
                    if filename not in {"vertical-slice.spec.ts", "ui-accessibility.spec.ts", "models.spec.ts", "model-migrations.spec.ts", "asset-types.spec.ts", "asset-type-migrations.spec.ts", "relations.spec.ts", "relation-migrations.spec.ts", "business-domains.spec.ts"}:
                        continue
                    line = spec.get("line")
                    report["tests"].append({"file": "tests/e2e/" + filename, "line": line if isinstance(line, int) else None,
                        "status": status if status in {"expected", "unexpected", "flaky", "skipped"} and results and all(r.get("status") == "passed" for r in results) else "unknown",
                        "attempts": len(results), "duration_ms": sum(r.get("duration", 0) for r in results),
                        "failure_locations": failure_locations(results, filename)})
    collect(data.get("suites", []))
if outcomes["browser"] == "success":
    # A successful filtered run is not the mandatory browser gate. Require all
    # registered journeys, once each, as well as their successful outcomes.
    expected = {f"tests/e2e/{name}.spec.ts": 2 for name in ("vertical-slice", "ui-accessibility", "models", "model-migrations", "asset-types", "asset-type-migrations", "relations", "relation-migrations")}
    expected["tests/e2e/business-domains.spec.ts"] = 3
    observed = {name: sum(test["file"] == name for test in report["tests"]) for name in expected}
    locations = {(test["file"], test["line"]) for test in report["tests"]}
    if observed != expected or len(locations) != sum(expected.values()) or any(test["status"] != "expected" or test["attempts"] != 1 for test in report["tests"]):
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
