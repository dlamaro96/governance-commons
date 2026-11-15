#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the publication collector in an isolated synthetic artifact tree."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

COLLECTOR = Path(__file__).with_name("ci_evidence.py")
FILES = ("vertical-slice", "ui-accessibility", "models", "model-migrations", "asset-types", "asset-type-migrations", "relations")
STEPS = ("bootstrap", "services", "object_store", "seed", "connectors", "security", "model_upgrade", "asset_type_upgrade", "type_migration_upgrade", "relations_upgrade", "browser")


class EvidenceGateTests(unittest.TestCase):
    def collect(self, mutation=None, failed_step=None):
        specs = [{"file": f"{name}.spec.ts", "line": line, "title": "PRIVATE_SYNTHETIC_TITLE",
                  "tests": [{"status": "expected", "results": [{"status": "passed", "duration": 1, "stdout": ["PRIVATE_SYNTHETIC_OUTPUT"]}]}]}
                 for name in FILES for line in (10, 20)]
        if mutation:
            mutation(specs)
        with tempfile.TemporaryDirectory(prefix="gc-ci-evidence-") as temporary:
            root = Path(temporary)
            (root / "policies").mkdir()
            shutil.copyfile(COLLECTOR, root / "policies/ci_evidence.py")
            source = root / ".local/evidence"
            source.mkdir(parents=True)
            (source / "playwright-results.json").write_text(json.dumps({"suites": [{"specs": specs}]}))
            env = {**os.environ, **{f"GC_{step.upper()}_RESULT": "success" for step in STEPS},
                   "GITHUB_SHA": "synthetic-fixture", "GITHUB_REPOSITORY": "example/fixture", "GITHUB_RUN_ID": "1"}
            if failed_step:
                env[f"GC_{failed_step.upper()}_RESULT"] = "failure"
            result = subprocess.run([sys.executable, str(root / "policies/ci_evidence.py")],
                                    env=env, capture_output=True, text=True, timeout=10)
            report = json.loads((root / ".local/ci-artifacts/behavior-summary.json").read_text())
            serialized = json.dumps(report)
            self.assertNotIn("PRIVATE_SYNTHETIC", serialized)
            return result.returncode, report

    def test_all_fourteen_required_journeys_are_accepted_and_private_payloads_omitted(self):
        code, report = self.collect()
        self.assertEqual(code, 0)
        self.assertEqual(report["outcome"], "PASS")
        self.assertEqual(len(report["tests"]), 14)

    def test_older_twelve_test_gate_cannot_hide_missing_relation_journeys(self):
        code, report = self.collect(lambda specs: specs.__delitem__(slice(12, None)))
        self.assertEqual(code, 1)
        self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_duplicate_source_locations_cannot_replace_an_unexecuted_journey(self):
        code, _ = self.collect(lambda specs: specs[-1].update(line=10))
        self.assertEqual(code, 1)

    def test_skipped_flaky_or_unexpected_results_fail_even_when_step_claims_success(self):
        for status in ("skipped", "flaky", "unexpected"):
            with self.subTest(status=status):
                code, _ = self.collect(lambda specs: specs[-1]["tests"][0].update(status=status))
                self.assertEqual(code, 1)

    def test_real_service_failure_cannot_be_overridden_by_successful_browser_results(self):
        for step in ("object_store", "model_upgrade", "asset_type_upgrade", "type_migration_upgrade", "relations_upgrade"):
            with self.subTest(step=step):
                code, report = self.collect(failed_step=step)
                self.assertEqual(code, 1)
                self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_unexecuted_or_repeated_results_cannot_claim_a_single_pass(self):
        for results in ([], [{"status": "failed"}], [{"status": "passed"}, {"status": "passed"}]):
            with self.subTest(results=results):
                code, _ = self.collect(lambda specs: specs[-1]["tests"][0].update(results=results))
                self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
