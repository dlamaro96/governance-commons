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
from api_evidence import collect as collect_api
import test_api_evidence

COLLECTOR = Path(__file__).with_name("ci_evidence.py")
FILES = ("vertical-slice", "ui-accessibility", "models", "model-migrations", "asset-types", "asset-type-migrations", "relations", "relation-migrations")
STEPS = ("bootstrap", "services", "object_store", "seed", "connectors", "security", "model_upgrade", "asset_type_upgrade", "type_migration_upgrade", "relations_upgrade", "relation_participation_upgrade", "browser")


class EvidenceGateTests(unittest.TestCase):
    def collect(self, mutation=None, failed_step=None, api_mutation=None, omit_api=False):
        specs = [{"file": f"{name}.spec.ts", "line": line, "title": "PRIVATE_SYNTHETIC_TITLE",
                  "tests": [{"status": "expected", "results": [{"status": "passed", "duration": 1, "stdout": ["PRIVATE_SYNTHETIC_OUTPUT"]}]}]}
                 for name in FILES for line in (10, 20)]
        if mutation:
            mutation(specs)
        with tempfile.TemporaryDirectory(prefix="gc-ci-evidence-") as temporary:
            root = Path(temporary)
            (root / "policies").mkdir()
            shutil.copyfile(COLLECTOR, root / "policies/ci_evidence.py")
            shutil.copyfile(COLLECTOR.with_name("api_evidence.py"), root / "policies/api_evidence.py")
            api_file = root / "tests/integration/example.test.ts"
            api_file.parent.mkdir(parents=True)
            api_file.write_text("test('synthetic API test', async () => {});\n")
            source = root / ".local/evidence"
            source.mkdir(parents=True)
            (source / "playwright-results.json").write_text(json.dumps({"suites": [{"specs": specs}]}))
            api = collect_api(root, b"TAP version 13\nok 1 - synthetic API test\n1..1\n# tests 1\n# suites 0\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n", 0, "a" * 40, True)
            if api_mutation:
                api_mutation(api)
            if not omit_api:
                (source / "api-summary.json").write_text(json.dumps(api))
            env = {**os.environ, **{f"GC_{step.upper()}_RESULT": "success" for step in STEPS},
                   "GITHUB_SHA": "a" * 40, "GITHUB_REPOSITORY": "example/fixture", "GITHUB_RUN_ID": "1"}
            if failed_step:
                env[f"GC_{failed_step.upper()}_RESULT"] = "failure"
            result = subprocess.run([sys.executable, str(root / "policies/ci_evidence.py")],
                                    env=env, capture_output=True, text=True, timeout=10)
            report = json.loads((root / ".local/ci-artifacts/behavior-summary.json").read_text())
            serialized = json.dumps(report)
            self.assertNotIn("PRIVATE_SYNTHETIC", serialized)
            for artifact in (root / ".local/ci-artifacts").glob("*.json"):
                self.assertNotIn("PRIVATE_SYNTHETIC", artifact.read_text())
            return result.returncode, report

    def test_all_sixteen_required_journeys_are_accepted_and_private_payloads_omitted(self):
        code, report = self.collect()
        self.assertEqual(code, 0)
        self.assertEqual(report["outcome"], "PASS")
        self.assertEqual(len(report["tests"]), 16)

    def test_older_fourteen_test_gate_cannot_hide_missing_participation_journeys(self):
        code, report = self.collect(lambda specs: specs.__delitem__(slice(14, None)))
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
        for step in ("object_store", "model_upgrade", "asset_type_upgrade", "type_migration_upgrade", "relations_upgrade", "relation_participation_upgrade"):
            with self.subTest(step=step):
                code, report = self.collect(failed_step=step)
                self.assertEqual(code, 1)
                self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_failed_assertion_coordinates_are_allowlisted_without_private_payloads(self):
        failure = {"status": "failed", "duration": 3, "error": {
            "message": "PRIVATE_SYNTHETIC_MESSAGE", "stack": (
                "PRIVATE_SYNTHETIC_ERROR\n"
                "    at capture (/PRIVATE_SYNTHETIC_PATH/tests/e2e/relation-migrations.spec.ts:65:9)\n"
                "    at /PRIVATE_SYNTHETIC_PATH/tests/e2e/relation-migrations.spec.ts:173:3\n"
                "    at /PRIVATE_SYNTHETIC_PATH/tests/e2e/private.spec.ts:4:5\n")}}
        code, report = self.collect(lambda specs: specs[-1]["tests"][0].update(results=[failure]), failed_step="browser")
        self.assertEqual(code, 1)
        self.assertEqual(report["tests"][-1]["failure_locations"], [
            {"file": "tests/e2e/relation-migrations.spec.ts", "line": 65, "column": 9},
            {"file": "tests/e2e/relation-migrations.spec.ts", "line": 173, "column": 3}])

    def test_untrusted_or_successful_error_fields_cannot_publish_payloads(self):
        for stack in (None, {"PRIVATE_SYNTHETIC": True}, "tests/e2e/relation-migrations.spec.ts:0:2", "tests/e2e/relation-migrations.spec.ts:1:1000000"):
            with self.subTest(stack=stack):
                code, report = self.collect(lambda specs: specs[-1]["tests"][0]["results"][0].update(error={"stack": stack}))
                self.assertEqual(code, 0)
                self.assertEqual(report["tests"][-1]["failure_locations"], [])

    def test_unexecuted_or_repeated_results_cannot_claim_a_single_pass(self):
        for results in ([], [{"status": "failed"}], [{"status": "passed"}, {"status": "passed"}]):
            with self.subTest(results=results):
                code, _ = self.collect(lambda specs: specs[-1]["tests"][0].update(results=results))
                self.assertEqual(code, 1)

    def test_missing_or_invalid_api_evidence_cannot_qualify_successful_security_step(self):
        code, report = self.collect(omit_api=True)
        self.assertEqual(code, 1)
        self.assertEqual(report["api_evidence"], "UNAVAILABLE_OR_INVALID")
        for mutate in (lambda value: value.update(commit="b" * 40), lambda value: value.update(error="PRIVATE_SYNTHETIC_ERROR"),
                       lambda value: value["tests"][0].update(status="skipped")):
            code, report = self.collect(api_mutation=mutate)
            self.assertEqual(code, 1)
            self.assertEqual(report["api_evidence"], "UNAVAILABLE_OR_INVALID")

    def test_security_step_failure_remains_failed_with_a_valid_prior_api_pass(self):
        code, report = self.collect(failed_step="security")
        self.assertEqual(code, 1)
        self.assertEqual(report["outcome"], "NOT_PASSED")
        self.assertEqual(report["api_evidence"], "STEP_RESULT_MISMATCH")


def load_tests(loader, tests, pattern):
    # The existing hosted quality command also exercises the new API evidence
    # boundary; no new workflow privilege or artifact path is required.
    tests.addTests(loader.loadTestsFromModule(test_api_evidence))
    return tests


if __name__ == "__main__":
    unittest.main()
