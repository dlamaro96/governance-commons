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
import test_authentication_evidence
import test_protected_authn_evidence
import authentication_evidence
import protected_authn_evidence
from test_authentication_evidence import fixture as authentication_fixture

COLLECTOR = Path(__file__).with_name("ci_evidence.py")
FILES = ("vertical-slice", "ui-accessibility", "models", "model-migrations", "asset-types", "asset-type-migrations", "relations", "relation-migrations", "business-domains", "source-connectors")
STEPS = ("bootstrap", "services", "object_store", "seed", "connectors", "security", "model_upgrade", "asset_type_upgrade", "type_migration_upgrade", "relations_upgrade", "relation_participation_upgrade", "business_domains_upgrade", "business_domain_seed", "authority_authn_foundation", "authority_foundation", "source_connectors_upgrade", "browser", "protected_authn")


CONNECTOR_CAPTURES = tuple(f"m8-source-connectors-{state}-{language}-{width}.png"
                           for state in ("form", "registered", "failure", "denial")
                           for language, width in (("en", 1440), ("ar", 390)))
# Valid synthetic one-pixel PNG; this exercises only named artifact copying, not
# real UI/accessibility/image/source qualification.
PNG = bytes.fromhex("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000b49444154789c6360000200000500017a5eab3f0000000049454e44ae426082")


class EvidenceGateTests(unittest.TestCase):
    def collect(self, mutation=None, failed_step=None, api_mutation=None, omit_api=False, omitted_step=None, authn_mutation=None, omit_authn=False, protected_mutation=None, omit_protected=False, omitted_capture=None, symlink_capture=None, empty_capture=None):
        specs = [{"file": f"{name}.spec.ts", "line": line, "title": "PRIVATE_SYNTHETIC_TITLE",
                  "tests": [{"status": "expected", "results": [{"status": "passed", "duration": 1, "stdout": ["PRIVATE_SYNTHETIC_OUTPUT"]}]}]}
                 for name in FILES for line in ((10, 20, 30) if name == "business-domains" else (10,) if name == "source-connectors" else (10, 20))]
        if mutation:
            mutation(specs)
        with tempfile.TemporaryDirectory(prefix="gc-ci-evidence-") as temporary:
            root = Path(temporary)
            (root / "policies").mkdir()
            shutil.copyfile(COLLECTOR, root / "policies/ci_evidence.py")
            shutil.copyfile(COLLECTOR.with_name("api_evidence.py"), root / "policies/api_evidence.py")
            shutil.copyfile(COLLECTOR.with_name("authentication_evidence.py"), root / "policies/authentication_evidence.py")
            shutil.copyfile(COLLECTOR.with_name("protected_authn_evidence.py"), root / "policies/protected_authn_evidence.py")
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
            authn = authentication_fixture(root)
            protected = test_protected_authn_evidence.fixture(root)
            # Both source inventories overlap intentionally. Finish all synthetic
            # source preparation before recording either execution's hashes.
            authn["sources"] = authentication_evidence.source_inventory(root)
            hashes = {row["path"]: row["sha256"] for row in authn["sources"]}
            authn["runtime"]["packageSha256"] = hashes["package.json"]
            authn["runtime"]["lockSha256"] = hashes["pnpm-lock.yaml"]
            if protected_mutation:
                protected_mutation(protected)
            if not omit_protected:
                (source / "protected-authn.json").write_text(json.dumps(protected))
            if authn_mutation:
                authn_mutation(authn)
            if not omit_authn:
                (source / "authority-authn-foundation.json").write_text(json.dumps(authn))
            # The two newly required native gates remain step claims only.
            # Their arbitrary private originals must never enter public artifacts.
            for private_name in ("authority-foundation.json", "source-connectors-upgrade.json"):
                (source / private_name).write_text(json.dumps({"PRIVATE_SYNTHETIC_NATIVE_REPORT": True}))
            captures = root / "docs/verification/screenshots"
            captures.mkdir(parents=True, exist_ok=True)
            (captures / "unreviewed-private.png").write_bytes(b"PRIVATE_SYNTHETIC_IMAGE")
            for name in CONNECTOR_CAPTURES:
                if name == omitted_capture:
                    continue
                path = captures / name
                if name == symlink_capture:
                    path.symlink_to(captures / "unreviewed-private.png")
                else:
                    path.write_bytes(b"" if name == empty_capture else PNG)
            env = {**os.environ, **{f"GC_{step.upper()}_RESULT": "success" for step in STEPS},
                   "GITHUB_SHA": "a" * 40, "GITHUB_REPOSITORY": "example/fixture", "GITHUB_RUN_ID": "1"}
            if failed_step:
                env[f"GC_{failed_step.upper()}_RESULT"] = "failure"
            if omitted_step:
                env.pop(f"GC_{omitted_step.upper()}_RESULT", None)
            result = subprocess.run([sys.executable, str(root / "policies/ci_evidence.py")],
                                    env=env, capture_output=True, text=True, timeout=10)
            report = json.loads((root / ".local/ci-artifacts/behavior-summary.json").read_text())
            self.assertFalse((root / ".local/ci-artifacts/unreviewed-private.png").exists())
            for private_name in ("authority-foundation.json", "source-connectors-upgrade.json"):
                self.assertFalse((root / ".local/ci-artifacts" / private_name).exists())
            for name in report["screenshots"]:
                if name in CONNECTOR_CAPTURES:
                    self.assertEqual((root / ".local/ci-artifacts" / name).read_bytes(), PNG)
            serialized = json.dumps(report)
            self.assertNotIn("PRIVATE_SYNTHETIC", serialized)
            for artifact in (root / ".local/ci-artifacts").glob("*.json"):
                self.assertNotIn("PRIVATE_SYNTHETIC", artifact.read_text())
            return result.returncode, report

    def test_all_twenty_required_journeys_are_accepted_and_private_payloads_omitted(self):
        code, report = self.collect()
        self.assertEqual(code, 0)
        self.assertEqual(report["outcome"], "PASS")
        self.assertEqual(len(report["tests"]), 20)
        self.assertEqual(set(report["screenshots"]), set(CONNECTOR_CAPTURES))
        self.assertEqual(len(report["steps"]), 18)

    def test_older_nineteen_journey_gate_cannot_hide_missing_source_connector_journey(self):
        code, report = self.collect(lambda specs: specs.__setitem__(slice(None), [s for s in specs if s["file"] != "source-connectors.spec.ts"]))
        self.assertEqual(len(report["tests"]), 19)
        self.assertEqual(code, 1)
        self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_source_connector_journey_cannot_be_duplicated(self):
        code, report = self.collect(lambda specs: specs.append(dict(specs[-1])))
        self.assertEqual(code, 1)
        self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_source_connector_captures_are_required_regular_allowlisted_files(self):
        for option in ("omitted_capture", "symlink_capture", "empty_capture"):
            for name in CONNECTOR_CAPTURES:
                with self.subTest(option=option, name=name):
                    code, report = self.collect(**{option:name})
                    self.assertEqual(code, 1)
                    self.assertNotIn(name, report["screenshots"])
                    self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_required_participation_journeys_cannot_be_replaced_by_domain_journeys(self):
        code, report = self.collect(lambda specs: specs.__setitem__(slice(None), [s for s in specs if s["file"] != "relation-migrations.spec.ts"]))
        self.assertEqual(code, 1)
        self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_older_sixteen_test_gate_cannot_hide_missing_business_domain_journeys(self):
        code, report = self.collect(lambda specs: specs.__setitem__(slice(None), [s for s in specs if s["file"] not in ("business-domains.spec.ts", "source-connectors.spec.ts")]))
        self.assertEqual(len(report["tests"]), 16)
        self.assertEqual(code, 1)
        self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_each_business_domain_journey_must_execute(self):
        code, report = self.collect(lambda specs: specs.remove(next(s for s in specs if s["file"] == "business-domains.spec.ts" and s["line"] == 30)))
        self.assertEqual(len(report["tests"]), 19)
        self.assertEqual(code, 1)
        self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_missing_business_domain_qualification_steps_fail_closed(self):
        for step in ("business_domains_upgrade", "business_domain_seed", "authority_authn_foundation", "authority_foundation", "source_connectors_upgrade"):
            with self.subTest(step=step):
                code, report = self.collect(omitted_step=step)
                self.assertEqual(code, 1)
                self.assertEqual(report["steps"][step], "skipped")
                self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_duplicate_source_locations_cannot_replace_an_unexecuted_journey(self):
        code, _ = self.collect(lambda specs: next(s for s in specs if s["file"] == "business-domains.spec.ts" and s["line"] == 30).update(line=10))
        self.assertEqual(code, 1)

    def test_skipped_flaky_or_unexpected_results_fail_even_when_step_claims_success(self):
        for status in ("skipped", "flaky", "unexpected"):
            with self.subTest(status=status):
                code, _ = self.collect(lambda specs: specs[-1]["tests"][0].update(status=status))
                self.assertEqual(code, 1)

    def test_real_service_failure_cannot_be_overridden_by_successful_browser_results(self):
        for step in ("object_store", "model_upgrade", "asset_type_upgrade", "type_migration_upgrade", "relations_upgrade", "relation_participation_upgrade", "business_domains_upgrade", "business_domain_seed", "authority_authn_foundation", "authority_foundation", "source_connectors_upgrade"):
            with self.subTest(step=step):
                code, report = self.collect(failed_step=step)
                self.assertEqual(code, 1)
                self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_failed_assertion_coordinates_are_allowlisted_without_private_payloads(self):
        for filename in ("relation-migrations.spec.ts", "business-domains.spec.ts", "source-connectors.spec.ts"):
            with self.subTest(filename=filename):
                failure = {"status": "failed", "duration": 3, "error": {
                    "message": "PRIVATE_SYNTHETIC_MESSAGE", "stack": (
                        "PRIVATE_SYNTHETIC_ERROR\n"
                        f"    at capture (/PRIVATE_SYNTHETIC_PATH/tests/e2e/{filename}:65:9)\n"
                        f"    at /PRIVATE_SYNTHETIC_PATH/tests/e2e/{filename}:173:3\n"
                        "    at /PRIVATE_SYNTHETIC_PATH/tests/e2e/private.spec.ts:4:5\n")}}
                def mutate(specs):
                    next(spec for spec in specs if spec["file"] == filename)["tests"][0].update(results=[failure])
                code, report = self.collect(mutate, failed_step="browser")
                self.assertEqual(code, 1)
                target = next(record for record in report["tests"] if record["file"] == "tests/e2e/" + filename)
                self.assertEqual(target["failure_locations"], [
                    {"file": "tests/e2e/" + filename, "line": 65, "column": 9},
                    {"file": "tests/e2e/" + filename, "line": 173, "column": 3}])

    def test_untrusted_or_successful_error_fields_cannot_publish_payloads(self):
        for stack in (None, {"PRIVATE_SYNTHETIC": True}, "tests/e2e/business-domains.spec.ts:0:2", "tests/e2e/business-domains.spec.ts:1:1000000"):
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

    def test_authentication_native_gate_and_evidence_are_required(self):
        self.assertEqual(len(STEPS), 18)
        code, report = self.collect(omit_authn=True)
        self.assertEqual(code, 1)
        self.assertEqual(report["authentication_evidence"], "UNAVAILABLE_OR_INVALID")
        for mutation in (lambda report: report.update(commit="b"*40),
                         lambda report: report.update(secret="PRIVATE_SYNTHETIC"),
                         lambda report: report["cleanup"].update(ownedRemoved=False),
                         lambda report: report["tests"].update(skipped=1)):
            code, report = self.collect(authn_mutation=mutation)
            self.assertEqual(code, 1)
            self.assertEqual(report["authentication_evidence"], "UNAVAILABLE_OR_INVALID")
        for option in ("failed_step", "omitted_step"):
            code, report = self.collect(**{option: "authority_authn_foundation"})
            self.assertEqual(code, 1)
            self.assertEqual(report["authentication_evidence"], "STEP_RESULT_MISMATCH")

    def test_protected_transport_gate_and_baked_evidence_are_required(self):
        code, report = self.collect(omit_protected=True)
        self.assertEqual(code, 1)
        self.assertEqual(report["protected_authentication_evidence"], "UNAVAILABLE_OR_INVALID")
        for mutation in (lambda r: r.update(commit="b"*40),
                         lambda r: r.update(evidenceMode="mounted-source", imageAttestation=None),
                         lambda r: r["cleanup"].update(resourceInventoryPreserved=False),
                         lambda r: r["captures"].pop(),
                         lambda r: r["imageAttestation"].update(sourceMode="mounted")):
            code, report = self.collect(protected_mutation=mutation)
            self.assertEqual(code, 1)
            self.assertEqual(report["protected_authentication_evidence"], "UNAVAILABLE_OR_INVALID")
        for option in ("failed_step", "omitted_step"):
            code, report = self.collect(**{option: "protected_authn"})
            self.assertEqual(code, 1)
            self.assertEqual(report["protected_authentication_evidence"], "STEP_RESULT_MISMATCH")

    def test_workflow_executes_and_collects_all_eighteen_steps(self):
        workflow = (COLLECTOR.parent.parent / ".github/workflows/ci.yml").read_text()
        self.assertIn("id: authority_authn_foundation\n        run: ./dev test --suite authority-authn-foundation", workflow)
        self.assertLess(workflow.index("id: authority_authn_foundation"), workflow.index("id: browser"))
        self.assertIn("id: authority_foundation\n        run: ./dev test --suite authority-foundation", workflow)
        self.assertIn("id: source_connectors_upgrade\n        run: ./dev test --suite source-connectors-upgrade", workflow)
        self.assertLess(workflow.index("id: authority_authn_foundation"), workflow.index("id: authority_foundation"))
        self.assertLess(workflow.index("id: authority_foundation"), workflow.index("id: source_connectors_upgrade"))
        self.assertLess(workflow.index("id: source_connectors_upgrade"), workflow.index("id: browser"))
        self.assertIn("tests/e2e/source-connectors.spec.ts", workflow)
        self.assertIn("name: Source credential persistence\n        run: python3 scripts/test_runtime_bootstrap.py", workflow)
        config = (COLLECTOR.parent.parent / ".github/playwright.ci.config.ts").read_text()
        self.assertIn("{ name: 'source-connectors', testMatch: /source-connectors\\.spec\\.ts/, dependencies: ['business-domains'] }", config)
        self.assertIn("id: protected_authn", workflow)
        self.assertLess(workflow.index("id: browser"), workflow.index("id: protected_authn"))
        for step in STEPS:
            self.assertEqual(workflow.count("id: " + step + "\n"), 1)
            self.assertIn("GC_" + step.upper() + "_RESULT: ${{ steps." + step + ".outcome }}", workflow)


def load_tests(loader, tests, pattern):
    # The existing hosted quality command also exercises the new API evidence
    # boundary; no new workflow privilege or artifact path is required.
    tests.addTests(loader.loadTestsFromModule(test_api_evidence))
    tests.addTests(loader.loadTestsFromModule(test_authentication_evidence))
    tests.addTests(loader.loadTestsFromModule(test_protected_authn_evidence))
    return tests


if __name__ == "__main__":
    unittest.main()
