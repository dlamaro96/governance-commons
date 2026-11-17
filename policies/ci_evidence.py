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
from protected_authn_evidence import load_report as load_protected_report, copy_captures as copy_protected_captures
from authentication_evidence import read_file as bounded_read, strict_json as private_json
from authority_diagnostics import load_report as load_authority_diagnostic

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / ".local/ci-artifacts"
DEST.mkdir(parents=True, exist_ok=True)
if any(DEST.iterdir()):
    raise SystemExit("Artifact staging must be empty; refusing to publish a mixed or stale directory")
allowed_outcomes = {"success", "failure", "cancelled", "skipped"}
outcomes = {}
for step in ("bootstrap", "services", "object_store", "seed", "connectors", "security", "model_upgrade", "asset_type_upgrade", "type_migration_upgrade", "relations_upgrade", "relation_participation_upgrade", "business_domains_upgrade", "business_domain_seed", "authority_authn_foundation", "authority_foundation", "source_connectors_upgrade", "postgres_targets", "glossary_upgrade", "relation_scope_upgrade", "glossary_population_upgrade", "quality_upgrade", "quality_worker", "lineage_upgrade", "lineage_worker", "classification_upgrade", "reference_upgrade", "reference_quality_upgrade", "reference_quality_worker", "reference_structure_upgrade", "reference_import", "browser", "protected_authn"):
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
                    "This local synthetic profile is not vendor-live, full accessibility, enterprise or release qualification.",
                    "Canonical authority success, source-connector upgrade, configurable PostgreSQL TLS, glossary upgrade, completeness, lineage, classification, reference-data, reference-quality, reference-structure and reference-import native gates remain CI step outcomes only; authority failures may include a separately source-bound, failure-only diagnostic. Raw native reports/logs and unreviewed completeness/lineage/classification/reference-data/reference-quality/reference-structure/reference-import captures and all raw import uploads remain private."],
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
# Diagnostics never qualify a successful gate. Preserve only an independently
# source/log-bound failure projection and keep the required step failed.
authority_diagnostic = load_authority_diagnostic(ROOT, os.environ.get("GITHUB_SHA"))
if authority_diagnostic and outcomes["authority_foundation"] in {"failure", "cancelled"}:
    (DEST / "authority-foundation-diagnostic.json").write_text(json.dumps(authority_diagnostic, indent=2) + "\n")
    report["authority_foundation_diagnostic"] = "FAILURE_DIAGNOSTIC_ONLY"
else:
    report["authority_foundation_diagnostic"] = "STEP_RESULT_MISMATCH" if authority_diagnostic else "UNAVAILABLE_OR_INVALID"
if authority_diagnostic and outcomes["authority_foundation"] == "success":
    report["outcome"] = "NOT_PASSED"
# Protected transport is a separate required gate, never a replacement for
# native foundation or the thirty-one core browser journeys. Hosted collection
# requires the independently bound, baked image mode; local overlays refuse.
protected_report = load_protected_report(ROOT, os.environ.get("GITHUB_SHA"))
protected_mismatch = bool(protected_report and outcomes["protected_authn"] != "success")
if protected_mismatch:
    protected_report = None
report["protected_authentication_evidence"] = "STEP_RESULT_MISMATCH" if protected_mismatch else "VERIFIED_PASS" if protected_report else "UNAVAILABLE_OR_INVALID"
if protected_report:
    try:
        original = private_json(bounded_read(ROOT, ".local/evidence/protected-authn.json", 4*1024*1024))
        copy_protected_captures(ROOT, original, DEST, protected_report)
        (DEST / "protected-authentication-summary.json").write_text(json.dumps(protected_report, indent=2) + "\n")
    except (OSError, ValueError, TypeError, KeyError):
        # A race or incomplete second read cannot leave a success-qualified
        # partial capture set in the public staging directory.
        from protected_authn_evidence import CAPTURES
        for name in CAPTURES:
            (DEST / name).unlink(missing_ok=True)
        protected_report = None
        report["protected_authentication_evidence"] = "UNAVAILABLE_OR_INVALID"
if outcomes["protected_authn"] == "success" and not protected_report:
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
REVIEWED_TITLES = {
    "reference-import.spec.ts": 'REF006: raw JSON and CSV import, complete reconciliation consent and independent publication',
    "reference-structures.spec.ts": 'REF-STRUCT: independent hierarchy and crosswalk publication, temporal gaps, immutable history and endpoint visibility',
    "reference-quality.spec.ts": 'REF-DQ: approved allowed values, exact non-null thresholds, historical reference pins and current source observations',
    "reference-data.spec.ts": 'REF: independent publication, complete bilingual downloads, scheduled successor and current access boundaries',
    "classification.spec.ts": 'CLS: real metadata suggestion, independent application, immutable pins, reviewed withdrawal and access boundaries',
    "quality.spec.ts": "DQ: real column completeness, immutable thresholds, aggregate outcomes and current read boundaries",
    "lineage.spec.ts": "LIN-001/004/006: real PostgreSQL view dependencies, evidence, paged exploration and tenant isolation",
}
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
                    if filename not in {"vertical-slice.spec.ts", "ui-accessibility.spec.ts", "models.spec.ts", "model-migrations.spec.ts", "asset-types.spec.ts", "asset-type-migrations.spec.ts", "relations.spec.ts", "relation-migrations.spec.ts", "business-domains.spec.ts", "source-connectors.spec.ts", "postgres-configuration.spec.ts", "approvals.spec.ts", "glossary.spec.ts", "quality.spec.ts", "lineage.spec.ts", "classification.spec.ts", "reference-data.spec.ts", "reference-quality.spec.ts", "reference-structures.spec.ts", "reference-import.spec.ts"}:
                        continue
                    # Bind each new journey to its reviewed declaration, without
                    # exporting arbitrary titles or accepting a same-file substitute.
                    if filename in REVIEWED_TITLES and spec.get("title") != REVIEWED_TITLES[filename]:
                        status = "unknown"
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
    expected["tests/e2e/source-connectors.spec.ts"] = 1
    expected["tests/e2e/postgres-configuration.spec.ts"] = 1
    expected["tests/e2e/approvals.spec.ts"] = 1
    expected["tests/e2e/glossary.spec.ts"] = 2
    expected["tests/e2e/quality.spec.ts"] = 1
    expected["tests/e2e/lineage.spec.ts"] = 1
    expected["tests/e2e/classification.spec.ts"] = 1
    expected["tests/e2e/reference-data.spec.ts"] = 1
    expected["tests/e2e/reference-quality.spec.ts"] = 1
    expected["tests/e2e/reference-structures.spec.ts"] = 1
    expected["tests/e2e/reference-import.spec.ts"] = 1
    observed = {name: sum(test["file"] == name for test in report["tests"]) for name in expected}
    locations = {(test["file"], test["line"]) for test in report["tests"]}
    if observed != expected or len(locations) != sum(expected.values()) or any(test["status"] != "expected" or test["attempts"] != 1 for test in report["tests"]):
        report["outcome"] = "NOT_PASSED"
if outcomes["browser"] == "success":
    names = [f"catalog-en-light-{width}.png" for width in (390, 768, 1024, 1280, 1440)]
    names += ["catalog-en-dark-1440.png", "catalog-history.png"]
    names += [f"catalog-ar-dark-{width}.png" for width in (390, 768, 1440)]
    connector_captures = {f"m8-source-connectors-{state}-{language}-{width}.png"
                          for state in ("form", "registered", "failure", "denial")
                          for language, width in (("en", 1440), ("ar", 390))}
    names += sorted(connector_captures)
    postgres_captures = {f"m8-postgres-configuration-{state}-{language}-{width}.png"
                         for state in ("form", "failure")
                         for language, width in (("en", 1440), ("ar", 390))}
    names += sorted(postgres_captures)
    for name in names:
        path = ROOT / "docs/verification/screenshots" / name
        if path.is_file() and not path.is_symlink() and 0 < path.stat().st_size < 16 * 1024 * 1024:
            shutil.copyfile(path, DEST / name)
            report["screenshots"].append(name)
        elif name in connector_captures | postgres_captures:
            report["outcome"] = "NOT_PASSED"
(DEST / "behavior-summary.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({"outcome": report["outcome"], "test_records": len(report["tests"]), "screenshots": len(report["screenshots"])}))
sys.exit(0 if report["outcome"] == "PASS" else 1)
