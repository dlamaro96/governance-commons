#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the publication collector in an isolated synthetic artifact tree."""
import json
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from api_evidence import collect as collect_api
import test_api_evidence
import test_authentication_evidence
import test_protected_authn_evidence
import test_authority_diagnostics
import authority_diagnostics
import authentication_evidence
import protected_authn_evidence
from test_authentication_evidence import fixture as authentication_fixture

COLLECTOR = Path(__file__).with_name("ci_evidence.py")
FILES = ("vertical-slice", "ui-accessibility", "models", "model-migrations", "asset-types", "asset-type-migrations", "relations", "relation-migrations", "business-domains", "source-connectors", "postgres-configuration", "approvals", "glossary", "quality", "lineage", "classification", "reference-data", "reference-quality", "reference-structures", "reference-import", "quality-uniqueness", "quality-range", "quality-monitoring", "quality-freshness", "quality-freshness-monitoring", "quality-volume", "catalog-sorting")
STEPS = ("bootstrap", "services", "object_store", "seed", "connectors", "security", "model_upgrade", "asset_type_upgrade", "type_migration_upgrade", "relations_upgrade", "relation_participation_upgrade", "business_domains_upgrade", "business_domain_seed", "authority_authn_foundation", "authority_read_original", "authority_read_current", "authority_asset_context", "content_security_revision", "classification_label_identities", "source_connectors_upgrade", "postgres_targets", "glossary_upgrade", "relation_scope_upgrade", "relation_candidate_original", "relation_candidate_current", "glossary_population_repaired_upgrade", "quality_repaired_upgrade", "quality_worker", "lineage_repaired_upgrade", "lineage_worker", "classification_repaired_upgrade", "reference_repaired_upgrade", "reference_quality_repaired_upgrade", "reference_quality_worker", "reference_structure_repaired_upgrade", "reference_import", "uniqueness_upgrade", "uniqueness_worker", "range_upgrade", "range_worker", "monitoring_upgrade", "freshness_upgrade", "freshness_worker", "freshness_scheduling_upgrade", "volume_upgrade", "volume_worker", "browser", "protected_authn")
QUALITY_TITLE = "DQ: real column completeness, immutable thresholds, aggregate outcomes and current read boundaries"
LINEAGE_TITLE = "LIN-001/004/006: real PostgreSQL view dependencies, evidence, paged exploration and tenant isolation"


CONNECTOR_CAPTURES = tuple(f"m8-source-connectors-{state}-{language}-{width}.png"
                           for state in ("form", "registered", "failure", "denial")
                           for language, width in (("en", 1440), ("ar", 390)))
SORTING_CAPTURES = ("catalog-name-desc-1440.png", "catalog-name-desc-390.png", "catalog-name-desc-ar-390.png")
POSTGRES_CAPTURES = tuple(f"m8-postgres-configuration-{state}-{language}-{width}.png"
                         for state in ("form", "failure")
                         for language, width in (("en", 1440), ("ar", 390)))
# Valid synthetic one-pixel PNG; this exercises only named artifact copying, not
# real UI/accessibility/image/source qualification.
PNG = bytes.fromhex("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c4890000000b49444154789c6360000200000500017a5eab3f0000000049454e44ae426082")


VOLUME_TITLE = 'DQ-VOLUME: exact table counts, immutable thresholds, scheduled recovery and reopened issue history'
FRESHNESS_MONITORING_TITLE = 'DQ-FRESHNESS-MONITOR: scheduled latest timestamps recover, reopen and expire without rewriting a recorded pass'
FRESHNESS_TITLE = 'DQ-FRESHNESS: exact source-clock latest age, immutable duration versions, all-null outcome and current read boundaries'
MONITORING_TITLE = 'DQ-MONITOR: actual UTC scheduling deduplicates failures, verifies recovery and preserves reopened issue history'
RANGE_TITLE = 'DQ-RANGE: exact inclusive integer bounds, immutable thresholds, no-data semantics and current read boundaries'
UNIQUENESS_TITLE = 'DQ-UNI: exact duplicate groups, immutable thresholds, no-data semantics and current read boundaries'
REFERENCE_IMPORT_TITLE = 'REF006: raw JSON and CSV import, complete reconciliation consent and independent publication'
REFERENCE_STRUCTURE_TITLE = 'REF-STRUCT: independent hierarchy and crosswalk publication, temporal gaps, immutable history and endpoint visibility'
REFERENCE_QUALITY_TITLE = 'REF-DQ: approved allowed values, exact non-null thresholds, historical reference pins and current source observations'
REFERENCE_TITLE = 'REF: independent publication, complete bilingual downloads, scheduled successor and current access boundaries'
CLASSIFICATION_TITLE = 'CLS: real metadata suggestion, independent application, immutable pins, reviewed withdrawal and access boundaries'

class EvidenceGateTests(unittest.TestCase):
    def collect(self, mutation=None, failed_step=None, api_mutation=None, omit_api=False, omitted_step=None, authn_mutation=None, omit_authn=False, protected_mutation=None, omit_protected=False, omitted_capture=None, symlink_capture=None, empty_capture=None, authority=False, authority_mutation=None, failed_outcome="failure", shard=None, shard_environment=None, retained_foreign=None):
        specs = [{"file": f"{name}.spec.ts", "line": line, "title": "UX-04: catalog sorting spans real source results and resets cursor after changing order" if name == "catalog-sorting" else VOLUME_TITLE if name == "quality-volume" else FRESHNESS_MONITORING_TITLE if name == "quality-freshness-monitoring" else FRESHNESS_TITLE if name == "quality-freshness" else MONITORING_TITLE if name == "quality-monitoring" else RANGE_TITLE if name == "quality-range" else UNIQUENESS_TITLE if name == "quality-uniqueness" else QUALITY_TITLE if name == "quality" else LINEAGE_TITLE if name == "lineage" else CLASSIFICATION_TITLE if name == "classification" else REFERENCE_TITLE if name == "reference-data" else REFERENCE_QUALITY_TITLE if name == "reference-quality" else REFERENCE_STRUCTURE_TITLE if name == "reference-structures" else REFERENCE_IMPORT_TITLE if name == "reference-import" else "PRIVATE_SYNTHETIC_TITLE",
                  "tests": [{"status": "expected", "results": [{"status": "passed", "duration": 1, "stdout": ["PRIVATE_SYNTHETIC_OUTPUT"]}]}]}
                 for name in FILES for line in ((10, 20, 30) if name == "business-domains" else (10,) if name in ("source-connectors", "postgres-configuration", "approvals", "quality", "lineage", "classification", "reference-data", "reference-quality", "reference-structures", "reference-import", "quality-uniqueness", "quality-range", "quality-monitoring", "quality-freshness", "quality-freshness-monitoring", "quality-volume", "catalog-sorting") else (10, 20))]
        if mutation:
            mutation(specs)
        with tempfile.TemporaryDirectory(prefix="gc-ci-evidence-") as temporary:
            root = Path(temporary)
            commit = "a" * 40
            if shard is not None:
                subprocess.run(['git','init','--quiet',str(root)],check=True,capture_output=True,timeout=10)
                subprocess.run(['git','-c','user.name=Synthetic test','-c','user.email=synthetic@example.invalid','-c','commit.gpgsign=false','commit','--allow-empty','--quiet','-m','Synthetic shard identity'],cwd=root,check=True,capture_output=True,timeout=10)
                commit=subprocess.run(['git','rev-parse','HEAD'],cwd=root,check=True,capture_output=True,text=True,timeout=10).stdout.strip()
            (root / "policies").mkdir()
            shutil.copyfile(COLLECTOR, root / "policies/ci_evidence.py")
            shutil.copyfile(COLLECTOR.with_name("ci_shards.py"), root / "policies/ci_shards.py")
            shutil.copyfile(COLLECTOR.with_name("quality_upgrade_diagnostics.py"), root / "policies/quality_upgrade_diagnostics.py")
            shutil.copyfile(COLLECTOR.with_name("api_evidence.py"), root / "policies/api_evidence.py")
            shutil.copyfile(COLLECTOR.with_name("authentication_evidence.py"), root / "policies/authentication_evidence.py")
            shutil.copyfile(COLLECTOR.with_name("protected_authn_evidence.py"), root / "policies/protected_authn_evidence.py")
            shutil.copyfile(COLLECTOR.with_name("authority_diagnostics.py"), root / "policies/authority_diagnostics.py")
            shutil.copyfile(COLLECTOR.with_name("glossary_population_diagnostics.py"), root / "policies/glossary_population_diagnostics.py")
            api_file = root / "tests/integration/example.test.ts"
            api_file.parent.mkdir(parents=True)
            api_file.write_text("test('synthetic API test', async () => {});\n")
            source = root / ".local/evidence"
            source.mkdir(parents=True)
            (source / "playwright-results.json").write_text(json.dumps({"suites": [{"specs": specs}]}))
            api = collect_api(root, b"TAP version 13\nok 1 - synthetic API test\n1..1\n# tests 1\n# suites 0\n# pass 1\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n", 0, commit, True)
            if api_mutation:
                api_mutation(api)
            if not omit_api:
                (source / "api-summary.json").write_text(json.dumps(api))
            with patch.object(test_authentication_evidence, "COMMIT", commit):
                authn = authentication_fixture(root)
            authority_report = test_authority_diagnostics.fixture(root) if authority else None
            with patch.object(test_protected_authn_evidence, "COMMIT", commit):
                protected = test_protected_authn_evidence.fixture(root)
            # Both source inventories overlap intentionally. Finish all synthetic
            # source preparation before recording either execution's hashes.
            authn["sources"] = authentication_evidence.source_inventory(root)
            hashes = {row["path"]: row["sha256"] for row in authn["sources"]}
            authn["runtime"]["packageSha256"] = hashes["package.json"]
            authn["runtime"]["lockSha256"] = hashes["pnpm-lock.yaml"]
            if authority_report:
                authority_report['diagnostic_sources'] = authority_diagnostics.source_inventory(root)
                if authority_mutation:
                    authority_mutation(authority_report)
            if protected_mutation:
                protected_mutation(protected)
            if not omit_protected:
                (source / "protected-authn.json").write_text(json.dumps(protected))
            if authn_mutation:
                authn_mutation(authn)
            if not omit_authn:
                (source / "authority-authn-foundation.json").write_text(json.dumps(authn))
            # These native gates remain step claims only.
            # Their arbitrary private originals must never enter public artifacts.
            for private_name in ("authority-foundation.json", "authority-read-original.json", "authority-read-current.json", "authority-asset-context.json", "content-security-revision.json", "source-connectors-upgrade.json", "postgres-targets.json", "quality-repaired-upgrade.json", "quality-worker.json", "lineage-repaired-upgrade.json", "lineage-worker.json", "classification-repaired-upgrade.json", "reference-repaired-upgrade.json", "reference-quality-repaired-upgrade.json", "reference-quality-worker.json", "reference-structure-repaired-upgrade.json", "reference-import.json", "reference-import-upload.json", "reference-import-upload.csv", "quality-uniqueness-upgrade.json", "uniqueness-quality-worker.json", "quality-range-upgrade.json", "range-quality-worker.json", "quality-monitoring-upgrade.json", "quality-freshness-upgrade.json", "freshness-quality-worker.json", "quality-freshness-scheduling-upgrade.json", "quality-volume-upgrade.json", "volume-quality-worker.json"):
                if private_name == 'authority-foundation.json' and not authority and retained_foreign != private_name:continue
                value = authority_report if private_name == 'authority-foundation.json' and authority_report else {"PRIVATE_SYNTHETIC_NATIVE_REPORT": True}
                (source / private_name).write_text(json.dumps(value))
            captures = root / "docs/verification/screenshots"
            captures.mkdir(parents=True, exist_ok=True)
            (captures / "unreviewed-private.png").write_bytes(b"PRIVATE_SYNTHETIC_IMAGE")
            (captures / "quality-unreviewed.png").write_bytes(b"PRIVATE_SYNTHETIC_IMAGE")
            (captures / "lineage-unreviewed.png").write_bytes(b"PRIVATE_SYNTHETIC_IMAGE")
            (captures / "classification-unreviewed.png").write_bytes(b"PRIVATE_SYNTHETIC_IMAGE")
            (captures / "reference-data-unreviewed.png").write_bytes(b"PRIVATE_SYNTHETIC_IMAGE")
            (captures / "reference-quality-unreviewed.png").write_bytes(b"PRIVATE_SYNTHETIC_IMAGE")
            (captures / "reference-structures-unreviewed.png").write_bytes(b"PRIVATE_SYNTHETIC_IMAGE")
            (captures / "quality-uniqueness-unreviewed.png").write_bytes(b"PRIVATE_SYNTHETIC_IMAGE")
            (captures / "quality-range-unreviewed.png").write_bytes(b"PRIVATE_SYNTHETIC_IMAGE")
            (captures / "quality-monitoring-unreviewed.png").write_bytes(b"PRIVATE_SYNTHETIC_IMAGE")
            (captures / "quality-freshness-unreviewed.png").write_bytes(b"PRIVATE_SYNTHETIC_IMAGE")
            (captures / "quality-freshness-monitoring-unreviewed.png").write_bytes(b"PRIVATE_SYNTHETIC_IMAGE")
            (captures / "quality-volume-unreviewed.png").write_bytes(b"PRIVATE_SYNTHETIC_IMAGE")
            for name in ("reference-import-duplicate-en-1440.png", "reference-import-complete-change-ar-390.png", "reference-import-removal-en-1440.png", "reference-import-published-ar-390.png"):
                (captures / name).write_bytes(b"PRIVATE_SYNTHETIC_IMPORT_IMAGE")
            for name in CONNECTOR_CAPTURES + POSTGRES_CAPTURES + SORTING_CAPTURES:
                if name == omitted_capture:
                    continue
                folder = root / ".local/evidence/catalog-sorting-captures" if name in SORTING_CAPTURES else captures
                folder.mkdir(parents=True, exist_ok=True)
                path = folder / name
                if name == symlink_capture:
                    path.symlink_to(captures / "unreviewed-private.png")
                else:
                    path.write_bytes(b"" if name == empty_capture else PNG)
            env = {**os.environ, **{f"GC_{step.upper()}_RESULT": "success" for step in STEPS},
                   "GITHUB_SHA": commit, "GITHUB_RUN_ATTEMPT": "1", "GITHUB_REPOSITORY": "example/fixture", "GITHUB_RUN_ID": "1"}
            if shard is not None:
                import ci_shards
                required=ci_shards.required_steps(shard)
                for step in STEPS:
                    if step not in required:env['GC_'+step.upper()+'_RESULT']='skipped'
                for step,names in ci_shards.EVIDENCE.items():
                    if step not in required:
                        for name in names:
                            if name != retained_foreign:(source/name).unlink(missing_ok=True)
            if shard_environment:env.update(shard_environment)
            if failed_step:
                env[f"GC_{failed_step.upper()}_RESULT"] = failed_outcome
            if omitted_step:
                env.pop(f"GC_{omitted_step.upper()}_RESULT", None)
            result = subprocess.run([sys.executable, str(root / "policies/ci_evidence.py"), *(["--shard",shard] if shard is not None else [])],
                                    env=env, capture_output=True, text=True, timeout=10)
            report = json.loads((root / ".local/ci-artifacts/behavior-summary.json").read_text())
            self.assertFalse((root / ".local/ci-artifacts/unreviewed-private.png").exists())
            self.assertFalse((root / ".local/ci-artifacts/quality-unreviewed.png").exists())
            self.assertFalse((root / ".local/ci-artifacts/lineage-unreviewed.png").exists())
            self.assertFalse((root / ".local/ci-artifacts/classification-unreviewed.png").exists())
            self.assertFalse((root / ".local/ci-artifacts/reference-data-unreviewed.png").exists())
            self.assertFalse((root / ".local/ci-artifacts/reference-quality-unreviewed.png").exists())
            self.assertFalse((root / ".local/ci-artifacts/reference-structures-unreviewed.png").exists())
            self.assertEqual(list((root / ".local/ci-artifacts").glob("*uniqueness*")), [])
            self.assertEqual(list((root / ".local/ci-artifacts").glob("*range*")), [])
            self.assertEqual(list((root / ".local/ci-artifacts").glob("*monitoring*")), [])
            self.assertEqual(list((root / ".local/ci-artifacts").glob("*freshness*")), [])
            self.assertEqual(list((root / ".local/ci-artifacts").glob("*volume*")), [])
            self.assertEqual(list((root / ".local/ci-artifacts").glob("reference-import*")), [])
            for private_name in ("authority-foundation.json", "authority-read-original.json", "authority-read-current.json", "authority-asset-context.json", "content-security-revision.json", "source-connectors-upgrade.json", "postgres-targets.json", "quality-repaired-upgrade.json", "quality-worker.json", "lineage-repaired-upgrade.json", "lineage-worker.json", "classification-repaired-upgrade.json", "reference-repaired-upgrade.json", "reference-quality-repaired-upgrade.json", "reference-quality-worker.json", "reference-structure-repaired-upgrade.json", "reference-import.json", "reference-import-upload.json", "reference-import-upload.csv", "quality-uniqueness-upgrade.json", "uniqueness-quality-worker.json", "quality-range-upgrade.json", "range-quality-worker.json", "quality-monitoring-upgrade.json", "quality-freshness-upgrade.json", "freshness-quality-worker.json", "quality-freshness-scheduling-upgrade.json", "quality-volume-upgrade.json", "volume-quality-worker.json"):
                self.assertFalse((root / ".local/ci-artifacts" / private_name).exists())
            for name in report["screenshots"]:
                if name in CONNECTOR_CAPTURES + POSTGRES_CAPTURES + SORTING_CAPTURES:
                    self.assertEqual((root / ".local/ci-artifacts" / name).read_bytes(), PNG)
            serialized = json.dumps(report)
            self.assertNotIn("PRIVATE_SYNTHETIC", serialized)
            for artifact in (root / ".local/ci-artifacts").glob("*.json"):
                self.assertNotIn("PRIVATE_SYNTHETIC", artifact.read_text())
            diagnostic_path = root / '.local/ci-artifacts/authority-foundation-diagnostic.json'
            self.assertEqual(diagnostic_path.exists(), report['authority_foundation_diagnostic'] == 'FAILURE_DIAGNOSTIC_ONLY')
            if diagnostic_path.exists():
                diagnostic = json.loads(diagnostic_path.read_text())
                self.assertEqual(diagnostic['purpose'], 'FAILURE_DIAGNOSTIC_ONLY')
                self.assertEqual(diagnostic['outcome'], 'NOT_PASSED')
                self.assertEqual(diagnostic['failed_phase'], 'authority_loader')
            return result.returncode, report

    def test_all_thirty_eight_required_journeys_are_accepted_and_private_payloads_omitted(self):
        code, report = self.collect()
        self.assertEqual(code, 0)
        self.assertEqual(report["outcome"], "PASS")
        self.assertEqual(len(report["tests"]), 38)
        self.assertEqual(set(report["screenshots"]), set(CONNECTOR_CAPTURES + POSTGRES_CAPTURES + SORTING_CAPTURES))
        self.assertEqual(len(report["steps"]), 48)

    def test_reference_quality_requires_one_reviewed_journey(self):
        def target(specs):
            return next(spec for spec in specs if spec["file"] == "reference-quality.spec.ts")
        mutations = (
            lambda specs: specs.remove(target(specs)),
            lambda specs: specs.append(dict(target(specs))),
            lambda specs: target(specs).update(title="PRIVATE_SYNTHETIC_SUBSTITUTE"),
            lambda specs: target(specs).pop("title"),
            lambda specs: target(specs)["tests"][0].update(status="skipped"),
            lambda specs: target(specs)["tests"][0].update(results=[]),
            lambda specs: target(specs)["tests"][0].update(results=[{"status":"passed"},{"status":"passed"}]),
        )
        for number, mutation in enumerate(mutations):
            with self.subTest(mutation=number):
                code, report = self.collect(mutation)
                self.assertEqual(code, 1)
                self.assertEqual(report["outcome"], "NOT_PASSED")
                if number == 0:
                    self.assertEqual(len(report["tests"]), 37)

    def test_reference_import_requires_one_exact_unretried_success(self):
        def target(specs):
            return next(spec for spec in specs if spec["file"] == "reference-import.spec.ts")
        mutations = (
            lambda specs: specs.remove(target(specs)),
            lambda specs: specs.append({**target(specs), "line": 99}),
            lambda specs: target(specs).update(title="PRIVATE_SYNTHETIC_SUBSTITUTE"),
            lambda specs: target(specs).pop("title"),
            lambda specs: target(specs)["tests"][0].update(status="skipped"),
            lambda specs: target(specs)["tests"][0].update(results=[]),
            lambda specs: target(specs)["tests"][0].update(results=[{"status": "passed"}, {"status": "passed"}]),
            lambda specs: target(specs)["tests"][0].update(status="flaky"),
            lambda specs: target(specs)["tests"][0].update(results=[{"status": "failed"}]),
        )
        for number, mutation in enumerate(mutations):
            with self.subTest(mutation=number):
                code, report = self.collect(mutation)
                self.assertEqual(code, 1)
                self.assertEqual(report["outcome"], "NOT_PASSED")
                if number == 0:
                    self.assertEqual(len(report["tests"]), 37)

    def test_reference_import_native_step_must_be_present_and_successful(self):
        for outcome in ("failure", "cancelled", "skipped", "unknown"):
            with self.subTest(outcome=outcome):
                code, report = self.collect(failed_step="reference_import", failed_outcome=outcome)
                self.assertEqual(code, 1)
                self.assertEqual(report["outcome"], "NOT_PASSED")
                self.assertEqual(report["steps"]["reference_import"], outcome)
        code, report = self.collect(omitted_step="reference_import")
        self.assertEqual(code, 1)
        self.assertEqual(report["steps"]["reference_import"], "skipped")
        self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_uniqueness_requires_one_exact_unretried_success(self):
        def target(specs):
            return next(spec for spec in specs if spec["file"] == "quality-uniqueness.spec.ts")
        mutations = (
            lambda specs: specs.remove(target(specs)),
            lambda specs: specs.append({**target(specs), "line": 99}),
            lambda specs: target(specs).update(title="PRIVATE_SYNTHETIC_SUBSTITUTE"),
            lambda specs: target(specs).pop("title"),
            lambda specs: target(specs)["tests"][0].update(status="skipped"),
            lambda specs: target(specs)["tests"][0].update(results=[]),
            lambda specs: target(specs)["tests"][0].update(results=[{"status": "passed"}, {"status": "passed"}]),
            lambda specs: target(specs)["tests"][0].update(status="flaky"),
            lambda specs: target(specs)["tests"][0].update(results=[{"status": "failed"}]),
        )
        for number, mutation in enumerate(mutations):
            with self.subTest(mutation=number):
                code, report = self.collect(mutation)
                self.assertEqual(code, 1)
                self.assertEqual(report["outcome"], "NOT_PASSED")
                if number == 0:
                    # The previous complete 37-journey report cannot qualify.
                    self.assertEqual(len(report["tests"]), 37)

    def test_range_requires_one_exact_unretried_success(self):
        def target(specs):
            return next(spec for spec in specs if spec["file"] == "quality-range.spec.ts")
        mutations = (
            lambda specs: specs.remove(target(specs)),
            lambda specs: specs.append({**target(specs), "line": 99}),
            lambda specs: target(specs).update(title="PRIVATE_SYNTHETIC_SUBSTITUTE"),
            lambda specs: target(specs).pop("title"),
            lambda specs: target(specs)["tests"][0].update(status="skipped"),
            lambda specs: target(specs)["tests"][0].update(results=[]),
            lambda specs: target(specs)["tests"][0].update(results=[{"status": "passed"}, {"status": "passed"}]),
            lambda specs: target(specs)["tests"][0].update(status="flaky"),
            lambda specs: target(specs)["tests"][0].update(results=[{"status": "failed"}]),
        )
        for number, mutation in enumerate(mutations):
            with self.subTest(mutation=number):
                code, report = self.collect(mutation)
                self.assertEqual(code, 1)
                self.assertEqual(report["outcome"], "NOT_PASSED")
                if number == 0:
                    # The previous complete 37-journey report cannot qualify.
                    self.assertEqual(len(report["tests"]), 37)

    def test_monitoring_requires_one_exact_unretried_success(self):
        def target(specs):
            return next(spec for spec in specs if spec["file"] == "quality-monitoring.spec.ts")
        mutations = (
            lambda specs: specs.remove(target(specs)),
            lambda specs: specs.append({**target(specs), "line": 99}),
            lambda specs: target(specs).update(title="PRIVATE_SYNTHETIC_SUBSTITUTE"),
            lambda specs: target(specs).pop("title"),
            lambda specs: target(specs)["tests"][0].update(status="skipped"),
            lambda specs: target(specs)["tests"][0].update(results=[]),
            lambda specs: target(specs)["tests"][0].update(results=[{"status": "passed"}, {"status": "passed"}]),
            lambda specs: target(specs)["tests"][0].update(status="flaky"),
            lambda specs: target(specs)["tests"][0].update(results=[{"status": "failed"}]),
        )
        for number, mutation in enumerate(mutations):
            with self.subTest(mutation=number):
                code, report = self.collect(mutation)
                self.assertEqual(code, 1)
                self.assertEqual(report["outcome"], "NOT_PASSED")
                if number == 0:
                    # The previous complete 37-journey report cannot qualify.
                    self.assertEqual(len(report["tests"]), 37)

    def test_freshness_requires_one_exact_unretried_success(self):
        def target(specs):
            return next(spec for spec in specs if spec["file"] == "quality-freshness.spec.ts")
        mutations = (
            lambda specs: specs.remove(target(specs)),
            lambda specs: specs.append({**target(specs), "line": 99}),
            lambda specs: target(specs).update(title="PRIVATE_SYNTHETIC_SUBSTITUTE"),
            lambda specs: target(specs).pop("title"),
            lambda specs: target(specs)["tests"][0].update(status="skipped"),
            lambda specs: target(specs)["tests"][0].update(results=[]),
            lambda specs: target(specs)["tests"][0].update(results=[{"status": "passed"}, {"status": "passed"}]),
            lambda specs: target(specs)["tests"][0].update(status="flaky"),
            lambda specs: target(specs)["tests"][0].update(results=[{"status": "failed"}]),
        )
        for number, mutation in enumerate(mutations):
            with self.subTest(mutation=number):
                code, report = self.collect(mutation)
                self.assertEqual(code, 1)
                self.assertEqual(report["outcome"], "NOT_PASSED")
                if number == 0:
                    # The previous complete 37-journey report cannot qualify.
                    self.assertEqual(len(report["tests"]), 37)

    def test_scheduled_freshness_requires_one_exact_unretried_success(self):
        def target(specs):
            return next(spec for spec in specs if spec["file"] == "quality-freshness-monitoring.spec.ts")
        mutations = (
            lambda specs: specs.remove(target(specs)),
            lambda specs: specs.append({**target(specs), "line": 99}),
            lambda specs: target(specs).update(title="PRIVATE_SYNTHETIC_SUBSTITUTE"),
            lambda specs: target(specs).pop("title"),
            lambda specs: target(specs)["tests"][0].update(status="skipped"),
            lambda specs: target(specs)["tests"][0].update(results=[]),
            lambda specs: target(specs)["tests"][0].update(results=[{"status": "passed"}, {"status": "passed"}]),
            lambda specs: target(specs)["tests"][0].update(status="flaky"),
            lambda specs: target(specs)["tests"][0].update(results=[{"status": "failed"}]),
        )
        for number, mutation in enumerate(mutations):
            with self.subTest(mutation=number):
                code, report = self.collect(mutation)
                self.assertEqual(code, 1)
                self.assertEqual(report["outcome"], "NOT_PASSED")
                if number == 0:
                    # The previous complete 37-journey report cannot qualify.
                    self.assertEqual(len(report["tests"]), 37)

    def test_volume_requires_one_exact_unretried_success(self):
        def target(specs):
            return next(spec for spec in specs if spec["file"] == "quality-volume.spec.ts")
        mutations = (
            lambda specs: specs.remove(target(specs)),
            lambda specs: specs.append({**target(specs), "line": 99}),
            lambda specs: target(specs).update(title="PRIVATE_SYNTHETIC_SUBSTITUTE"),
            lambda specs: target(specs).pop("title"),
            lambda specs: target(specs)["tests"][0].update(status="skipped"),
            lambda specs: target(specs)["tests"][0].update(results=[]),
            lambda specs: target(specs)["tests"][0].update(results=[{"status": "passed"}, {"status": "passed"}]),
            lambda specs: target(specs)["tests"][0].update(status="flaky"),
            lambda specs: target(specs)["tests"][0].update(results=[{"status": "failed"}]),
        )
        for number, mutation in enumerate(mutations):
            with self.subTest(mutation=number):
                code, report = self.collect(mutation)
                self.assertEqual(code, 1)
                self.assertEqual(report["outcome"], "NOT_PASSED")
                if number == 0:
                    # The previous complete 37-journey report cannot qualify.
                    self.assertEqual(len(report["tests"]), 37)

    def test_uniqueness_and_range_stages_require_current_success(self):
        for step in ("uniqueness_upgrade", "uniqueness_worker", "range_upgrade", "range_worker", "monitoring_upgrade", "freshness_upgrade", "freshness_worker", "volume_upgrade", "volume_worker"):
            for outcome in ("failure", "cancelled", "skipped", "unknown"):
                with self.subTest(step=step, outcome=outcome):
                    code, report = self.collect(failed_step=step, failed_outcome=outcome)
                    self.assertEqual(code, 1)
                    self.assertEqual(report["outcome"], "NOT_PASSED")
                    self.assertEqual(report["steps"][step], outcome)
            code, report = self.collect(omitted_step=step)
            self.assertEqual(code, 1)
            self.assertEqual(report["steps"][step], "skipped")
            self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_reference_structures_require_one_reviewed_journey(self):
        def target(specs):
            return next(spec for spec in specs if spec["file"] == "reference-structures.spec.ts")
        mutations = (
            lambda specs: specs.remove(target(specs)),
            lambda specs: specs.append(dict(target(specs))),
            lambda specs: target(specs).update(title="PRIVATE_SYNTHETIC_SUBSTITUTE"),
            lambda specs: target(specs).pop("title"),
            lambda specs: target(specs)["tests"][0].update(status="skipped"),
            lambda specs: target(specs)["tests"][0].update(results=[]),
            lambda specs: target(specs)["tests"][0].update(results=[{"status":"passed"},{"status":"passed"}]),
        )
        for number, mutation in enumerate(mutations):
            with self.subTest(mutation=number):
                code, report = self.collect(mutation)
                self.assertEqual(code, 1)
                self.assertEqual(report["outcome"], "NOT_PASSED")
                if number == 0:
                    self.assertEqual(len(report["tests"]), 37)

    def test_reference_journey_requires_exactly_one_reviewed_success(self):
        mutations = (
            lambda specs: specs.__setitem__(slice(None), [s for s in specs if s["file"] != "reference-data.spec.ts"]),
            lambda specs: specs.append(dict(next(s for s in specs if s["file"] == "reference-data.spec.ts"))),
            lambda specs: next(s for s in specs if s["file"] == "reference-data.spec.ts").update(title="PRIVATE_SYNTHETIC_SUBSTITUTE"),
            lambda specs: next(s for s in specs if s["file"] == "reference-data.spec.ts").pop("title"),
            lambda specs: next(s for s in specs if s["file"] == "reference-data.spec.ts")["tests"][0].update(status="skipped"),
            lambda specs: next(s for s in specs if s["file"] == "reference-data.spec.ts")["tests"][0].update(results=[]),
            lambda specs: next(s for s in specs if s["file"] == "reference-data.spec.ts")["tests"][0].update(results=[{"status":"passed"},{"status":"passed"}]),
        )
        for number, mutation in enumerate(mutations):
            with self.subTest(mutation=number):
                code, report = self.collect(mutation)
                self.assertEqual(code, 1)
                self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_lineage_journey_is_required_exactly_once_with_reviewed_title(self):
        mutations = (
            lambda specs: specs.__setitem__(slice(None), [s for s in specs if s["file"] != "lineage.spec.ts"]),
            lambda specs: specs.append(dict(next(s for s in specs if s["file"] == "lineage.spec.ts"))),
            lambda specs: next(s for s in specs if s["file"] == "lineage.spec.ts").update(title="PRIVATE_SYNTHETIC_SUBSTITUTE"),
            lambda specs: next(s for s in specs if s["file"] == "lineage.spec.ts").pop("title"),
        )
        for number, mutation in enumerate(mutations):
            with self.subTest(mutation=number):
                code, report = self.collect(mutation)
                self.assertEqual(code, 1)
                self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_classification_journey_is_required_exactly_once_with_reviewed_title(self):
        mutations = (
            lambda specs: specs.__setitem__(slice(None), [s for s in specs if s["file"] != "classification.spec.ts"]),
            lambda specs: specs.append(dict(next(s for s in specs if s["file"] == "classification.spec.ts"))),
            lambda specs: next(s for s in specs if s["file"] == "classification.spec.ts").update(title="PRIVATE_SYNTHETIC_SUBSTITUTE"),
            lambda specs: next(s for s in specs if s["file"] == "classification.spec.ts").pop("title"),
        )
        for number, mutation in enumerate(mutations):
            with self.subTest(mutation=number):
                code, report = self.collect(mutation)
                self.assertEqual(code, 1)
                self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_lineage_cancelled_skipped_or_unknown_stage_cannot_qualify(self):
        for step in ("lineage_repaired_upgrade", "lineage_worker", "classification_repaired_upgrade", "reference_repaired_upgrade", "reference_quality_repaired_upgrade", "reference_quality_worker", "reference_structure_repaired_upgrade", "reference_import", "uniqueness_upgrade", "uniqueness_worker", "range_upgrade", "range_worker", "monitoring_upgrade", "freshness_upgrade", "freshness_worker", "volume_upgrade", "volume_worker"):
            for outcome in ("cancelled", "skipped", "PRIVATE_SYNTHETIC_INVALID"):
                with self.subTest(step=step, outcome=outcome):
                    code, report = self.collect(failed_step=step, failed_outcome=outcome)
                    self.assertEqual(code, 1)
                    self.assertEqual(report["steps"][step], outcome if outcome != "PRIVATE_SYNTHETIC_INVALID" else "unknown")
                    self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_quality_journey_is_required_exactly_once_with_reviewed_title(self):
        mutations = (
            lambda specs: specs.__setitem__(slice(None), [s for s in specs if s["file"] != "quality.spec.ts"]),
            lambda specs: specs.append(dict(next(s for s in specs if s["file"] == "quality.spec.ts"))),
            lambda specs: next(s for s in specs if s["file"] == "quality.spec.ts").update(title="PRIVATE_SYNTHETIC_SUBSTITUTE"),
            lambda specs: next(s for s in specs if s["file"] == "quality.spec.ts").pop("title"),
        )
        for number, mutation in enumerate(mutations):
            with self.subTest(mutation=number):
                code, report = self.collect(mutation)
                self.assertEqual(code, 1)
                self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_quality_cancelled_skipped_or_unknown_stage_cannot_qualify(self):
        for step in ("quality_repaired_upgrade", "quality_worker"):
            for outcome in ("cancelled", "skipped", "PRIVATE_SYNTHETIC_INVALID"):
                with self.subTest(step=step, outcome=outcome):
                    code, report = self.collect(failed_step=step, failed_outcome=outcome)
                    self.assertEqual(code, 1)
                    self.assertEqual(report["steps"][step], outcome if outcome != "PRIVATE_SYNTHETIC_INVALID" else "unknown")
                    self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_approval_and_glossary_journeys_are_required_once(self):
        for filename in ("approvals.spec.ts", "glossary.spec.ts"):
            with self.subTest(filename=filename):
                code, report = self.collect(lambda specs: specs.__setitem__(slice(None), [s for s in specs if s["file"] != filename]))
                self.assertEqual(code, 1)
                self.assertEqual(report["outcome"], "NOT_PASSED")
                code, _ = self.collect(lambda specs: specs.append(dict(next(s for s in specs if s["file"] == filename))))
                self.assertEqual(code, 1)

    def test_retired_authority_failure_remains_private_without_qualifying_new_run(self):
        code, report = self.collect(authority=True, failed_step='authority_foundation')
        self.assertEqual(code, 1)
        self.assertEqual(report['authority_foundation_diagnostic'], 'HISTORICAL_NOT_EXECUTED')
        self.assertEqual(report['outcome'], 'NOT_PASSED')

    def test_retired_authority_report_cannot_be_attached_to_new_success_or_missing_result(self):
        for options in ({}, {'omitted_step':'authority_read_original'}, {'omitted_step':'authority_read_current'}):
            code, report = self.collect(authority=True, **options)
            self.assertEqual(code, 1)
            self.assertEqual(report['authority_foundation_diagnostic'], 'HISTORICAL_NOT_EXECUTED')

    def test_retired_authority_diagnostic_stale_or_raw_fields_are_never_loaded(self):
        for mutate in (lambda r:r.update(commit='b'*40),lambda r:r.update(diagnostic_sources=[]),
                       lambda r:r['failure_diagnostic'].update(error='PRIVATE_SYNTHETIC_SECRET'),
                       lambda r:r['failure_diagnostic']['commandLog'].update(sha256='0'*64)):
            code, report = self.collect(authority=True, authority_mutation=mutate, failed_step='authority_foundation')
            self.assertEqual(code, 1)
            self.assertEqual(report['authority_foundation_diagnostic'], 'HISTORICAL_NOT_EXECUTED')

    def test_missing_source_connector_journey_cannot_qualify_complete_gate(self):
        code, report = self.collect(lambda specs: specs.__setitem__(slice(None), [s for s in specs if s["file"] != "source-connectors.spec.ts"]))
        self.assertEqual(len(report["tests"]), 37)
        self.assertEqual(code, 1)
        self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_source_connector_journey_cannot_be_duplicated(self):
        code, report = self.collect(lambda specs: specs.append(dict(next(s for s in specs if s["file"] == "source-connectors.spec.ts"))))
        self.assertEqual(code, 1)
        self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_missing_postgres_configuration_cannot_qualify_complete_gate(self):
        code, report = self.collect(lambda specs: specs.__setitem__(slice(None), [s for s in specs if s["file"] != "postgres-configuration.spec.ts"]))
        self.assertEqual(len(report["tests"]), 37)
        self.assertEqual(code, 1)
        self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_postgres_configuration_journey_cannot_be_duplicated(self):
        code, report = self.collect(lambda specs: specs.append(dict(next(s for s in specs if s["file"] == "postgres-configuration.spec.ts"))))
        self.assertEqual(code, 1)
        self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_postgres_configuration_captures_are_required_regular_allowlisted_files(self):
        for option in ("omitted_capture", "symlink_capture", "empty_capture"):
            for name in POSTGRES_CAPTURES:
                with self.subTest(option=option, name=name):
                    code, report = self.collect(**{option:name})
                    self.assertEqual(code, 1)
                    self.assertNotIn(name, report["screenshots"])
                    self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_source_connector_captures_are_required_regular_allowlisted_files(self):
        for option in ("omitted_capture", "symlink_capture", "empty_capture"):
            for name in CONNECTOR_CAPTURES:
                with self.subTest(option=option, name=name):
                    code, report = self.collect(**{option:name})
                    self.assertEqual(code, 1)
                    self.assertNotIn(name, report["screenshots"])
                    self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_catalog_sorting_journey_and_captures_are_required(self):
        for option in ('omitted_capture','symlink_capture','empty_capture'):
            for name in SORTING_CAPTURES:
                with self.subTest(option=option,name=name):
                    code, report = self.collect(**{option:name})
                    self.assertEqual(code,1)
                    self.assertEqual(report['outcome'],'NOT_PASSED')
        for change in ('missing','title','skipped'):
            def mutate(specs):
                row=next(s for s in specs if s['file']=='catalog-sorting.spec.ts')
                if change=='missing':specs.remove(row)
                elif change=='title':row['title']='unreviewed substitute'
                else:row['tests'][0]['results'][0]['status']='skipped'
            code, report=self.collect(mutate)
            self.assertEqual(code,1)
            self.assertEqual(report['outcome'],'NOT_PASSED')

    def test_required_participation_journeys_cannot_be_replaced_by_domain_journeys(self):
        code, report = self.collect(lambda specs: specs.__setitem__(slice(None), [s for s in specs if s["file"] != "relation-migrations.spec.ts"]))
        self.assertEqual(code, 1)
        self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_older_sixteen_test_gate_cannot_hide_missing_business_domain_journeys(self):
        code, report = self.collect(lambda specs: specs.__setitem__(slice(None), [s for s in specs if s["file"] not in ("business-domains.spec.ts", "source-connectors.spec.ts", "postgres-configuration.spec.ts", "approvals.spec.ts", "glossary.spec.ts", "quality.spec.ts", "lineage.spec.ts", "classification.spec.ts", "reference-data.spec.ts", "reference-quality.spec.ts", "reference-structures.spec.ts", "reference-import.spec.ts", "quality-uniqueness.spec.ts", "quality-range.spec.ts", "quality-monitoring.spec.ts", "quality-freshness.spec.ts", "quality-freshness-monitoring.spec.ts", "quality-volume.spec.ts", "catalog-sorting.spec.ts")]))
        self.assertEqual(len(report["tests"]), 16)
        self.assertEqual(code, 1)
        self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_each_business_domain_journey_must_execute(self):
        code, report = self.collect(lambda specs: specs.remove(next(s for s in specs if s["file"] == "business-domains.spec.ts" and s["line"] == 30)))
        self.assertEqual(len(report["tests"]), 37)
        self.assertEqual(code, 1)
        self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_missing_business_domain_qualification_steps_fail_closed(self):
        for step in ("business_domains_upgrade", "business_domain_seed", "authority_authn_foundation", "authority_read_original", "authority_read_current", "authority_asset_context", "content_security_revision", "classification_label_identities", "source_connectors_upgrade", "postgres_targets", "glossary_upgrade", "relation_scope_upgrade", "relation_candidate_original", "relation_candidate_current", "glossary_population_repaired_upgrade", "quality_repaired_upgrade", "quality_worker", "lineage_repaired_upgrade", "lineage_worker", "classification_repaired_upgrade", "reference_repaired_upgrade", "reference_quality_repaired_upgrade", "reference_quality_worker", "reference_structure_repaired_upgrade", "reference_import", "uniqueness_upgrade", "uniqueness_worker", "range_upgrade", "range_worker", "monitoring_upgrade", "freshness_upgrade", "freshness_worker", "volume_upgrade", "volume_worker"):
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
        for step in ("object_store", "model_upgrade", "asset_type_upgrade", "type_migration_upgrade", "relations_upgrade", "relation_participation_upgrade", "business_domains_upgrade", "business_domain_seed", "authority_authn_foundation", "authority_read_original", "authority_read_current", "authority_asset_context", "content_security_revision", "classification_label_identities", "source_connectors_upgrade", "postgres_targets", "glossary_upgrade", "relation_scope_upgrade", "relation_candidate_original", "relation_candidate_current", "glossary_population_repaired_upgrade", "quality_repaired_upgrade", "quality_worker", "lineage_repaired_upgrade", "lineage_worker", "classification_repaired_upgrade", "reference_repaired_upgrade", "reference_quality_repaired_upgrade", "reference_quality_worker", "reference_structure_repaired_upgrade", "reference_import", "uniqueness_upgrade", "uniqueness_worker", "range_upgrade", "range_worker", "monitoring_upgrade", "freshness_upgrade", "freshness_worker", "volume_upgrade", "volume_worker"):
            with self.subTest(step=step):
                code, report = self.collect(failed_step=step)
                self.assertEqual(code, 1)
                self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_failed_assertion_coordinates_are_allowlisted_without_private_payloads(self):
        for filename in ("relation-migrations.spec.ts", "business-domains.spec.ts", "source-connectors.spec.ts", "postgres-configuration.spec.ts", "quality.spec.ts", "lineage.spec.ts", "reference-quality.spec.ts", "reference-structures.spec.ts", "reference-import.spec.ts", "quality-uniqueness.spec.ts", "quality-range.spec.ts", "quality-monitoring.spec.ts", "quality-freshness.spec.ts", "quality-freshness-monitoring.spec.ts", "quality-volume.spec.ts", "catalog-sorting.spec.ts"):
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
        self.assertEqual(len(STEPS), 48)
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

    def test_workflow_executes_and_collects_all_forty_six_steps(self):
        workflow = (COLLECTOR.parent.parent / ".github/workflows/ci.yml").read_text()
        self.assertIn("id: authority_authn_foundation\n        run: ./dev test --suite authority-authn-foundation", workflow)
        self.assertLess(workflow.index("id: authority_authn_foundation"), workflow.index("id: browser"))
        self.assertNotIn("id: authority_foundation\n", workflow)
        self.assertIn("id: authority_read_original\n        run: ./dev test --suite authority-read-original", workflow)
        self.assertIn("id: authority_read_current\n        run: ./dev test --suite authority-read-current", workflow)
        self.assertIn("id: authority_asset_context\n        run: ./dev test --suite authority-asset-context", workflow)
        self.assertIn("python3 scripts/test_authority_read_upgrade.py", workflow)
        self.assertIn("id: source_connectors_upgrade\n        run: ./dev test --suite source-connectors-upgrade", workflow)
        self.assertLess(workflow.index("id: authority_authn_foundation"), workflow.index("id: authority_read_original"))
        self.assertLess(workflow.index("id: authority_read_current"), workflow.index("id: authority_asset_context"))
        self.assertLess(workflow.index("id: authority_asset_context"), workflow.index("id: source_connectors_upgrade"))
        self.assertIn("id: postgres_targets\n        run: ./dev test --suite postgres-targets", workflow)
        self.assertLess(workflow.index("id: source_connectors_upgrade"), workflow.index("id: postgres_targets"))
        self.assertLess(workflow.index("id: postgres_targets"), workflow.index("id: browser"))
        self.assertIn("tests/e2e/source-connectors.spec.ts", workflow)
        self.assertIn("tests/e2e/postgres-configuration.spec.ts", workflow)
        self.assertIn("id: glossary_upgrade\n        run: ./dev test --suite glossary-upgrade", workflow)
        self.assertIn("id: relation_scope_upgrade\n        run: ./dev test --suite relation-scope-upgrade", workflow)
        self.assertIn("id: glossary_population_repaired_upgrade\n        run: ./dev test --suite glossary-population-repaired-upgrade", workflow)
        self.assertIn("id: quality_repaired_upgrade\n        run: ./dev test --suite quality-repaired-upgrade", workflow)
        self.assertIn("id: quality_worker\n        run: ./dev test --suite quality-worker", workflow)
        self.assertLess(workflow.index("id: glossary_population_repaired_upgrade"), workflow.index("id: quality_repaired_upgrade"))
        self.assertLess(workflow.index("id: quality_repaired_upgrade"), workflow.index("id: quality_worker"))
        self.assertIn("id: lineage_repaired_upgrade\n        run: ./dev test --suite lineage-repaired-upgrade", workflow)
        self.assertIn("id: lineage_worker\n        run: ./dev test --suite lineage-worker", workflow)
        self.assertIn("id: classification_repaired_upgrade\n        run: ./dev test --suite classification-repaired-upgrade", workflow)
        self.assertLess(workflow.index("id: lineage_worker"), workflow.index("id: classification_repaired_upgrade"))
        self.assertIn("id: reference_repaired_upgrade\n        run: ./dev test --suite reference-repaired-upgrade", workflow)
        self.assertLess(workflow.index("id: classification_repaired_upgrade"), workflow.index("id: reference_repaired_upgrade"))
        self.assertIn("id: reference_quality_repaired_upgrade\n        run: ./dev test --suite reference-quality-repaired-upgrade", workflow)
        self.assertIn("id: reference_quality_worker\n        run: ./dev test --suite reference-quality-worker", workflow)
        self.assertLess(workflow.index("id: reference_repaired_upgrade"), workflow.index("id: reference_quality_repaired_upgrade"))
        self.assertLess(workflow.index("id: reference_quality_repaired_upgrade"), workflow.index("id: reference_quality_worker"))
        self.assertLess(workflow.index("id: reference_quality_worker"), workflow.index("id: browser"))
        self.assertIn("id: reference_structure_repaired_upgrade\n        run: ./dev test --suite reference-structure-repaired-upgrade", workflow)
        self.assertLess(workflow.index("id: reference_quality_worker"), workflow.index("id: reference_structure_repaired_upgrade"))
        self.assertLess(workflow.index("id: reference_structure_repaired_upgrade"), workflow.index("id: browser"))
        self.assertIn("run: python3 scripts/test_reference_structure_upgrade.py", workflow)
        self.assertIn("run: python3 scripts/test_runtime_reference_import.py", workflow)
        self.assertIn("id: reference_import\n        run: ./dev test --suite reference-import", workflow)
        self.assertLess(workflow.index("id: reference_structure_repaired_upgrade"), workflow.index("id: reference_import"))
        self.assertLess(workflow.index("id: reference_import"), workflow.index("id: browser"))
        self.assertIn("id: uniqueness_upgrade\n        run: ./dev test --suite uniqueness-upgrade", workflow)
        self.assertIn("id: uniqueness_worker\n        run: ./dev test --suite uniqueness-worker", workflow)
        self.assertLess(workflow.index("id: reference_import"), workflow.index("id: uniqueness_upgrade"))
        self.assertLess(workflow.index("id: uniqueness_upgrade"), workflow.index("id: uniqueness_worker"))
        self.assertLess(workflow.index("id: uniqueness_worker"), workflow.index("id: browser"))
        self.assertIn("run: python3 scripts/test_quality_uniqueness_upgrade.py", workflow)
        self.assertIn("run: python3 scripts/test_uniqueness_worker_gate.py", workflow)
        self.assertIn("id: range_upgrade\n        run: ./dev test --suite range-upgrade", workflow)
        self.assertIn("id: range_worker\n        run: ./dev test --suite range-worker", workflow)
        self.assertLess(workflow.index("id: uniqueness_worker"), workflow.index("id: range_upgrade"))
        self.assertLess(workflow.index("id: range_upgrade"), workflow.index("id: range_worker"))
        self.assertLess(workflow.index("id: range_worker"), workflow.index("id: browser"))
        self.assertIn("run: python3 scripts/test_quality_range_upgrade.py", workflow)
        self.assertIn("run: python3 scripts/test_range_worker_gate.py", workflow)
        self.assertIn("python3 scripts/test_qualification_approval_service.py", workflow)
        self.assertLess(workflow.index("id: quality_worker"), workflow.index("id: lineage_repaired_upgrade"))
        self.assertLess(workflow.index("id: lineage_repaired_upgrade"), workflow.index("id: lineage_worker"))
        self.assertLess(workflow.index("id: lineage_worker"), workflow.index("id: browser"))
        self.assertIn("tests/e2e/approvals.spec.ts tests/e2e/glossary.spec.ts tests/e2e/quality.spec.ts tests/e2e/lineage.spec.ts", workflow)
        self.assertIn("name: Source credential persistence\n        run: python3 scripts/test_runtime_bootstrap.py", workflow)
        self.assertIn("run: python3 scripts/test_reference_quality_fixture.py", workflow)
        config = (COLLECTOR.parent.parent / ".github/playwright.ci.config.ts").read_text()
        self.assertIn("{ name: 'source-connectors', testMatch: /source-connectors\\.spec\\.ts/, dependencies: ['business-domains'] }", config)
        self.assertIn("{ name: 'postgres-configuration', testMatch: /postgres-configuration\\.spec\\.ts/, dependencies: ['source-connectors'] }", config)
        self.assertIn("{ name: 'quality', testMatch: /(^|[/\\\\])quality\\.spec\\.ts$/, dependencies: ['glossary'] }", config)
        self.assertIn("{ name: 'lineage', testMatch: /lineage\\.spec\\.ts/, dependencies: ['quality'] }", config)
        self.assertIn("tests/e2e/reference-data.spec.ts tests/e2e/reference-quality.spec.ts tests/e2e/reference-structures.spec.ts tests/e2e/reference-import.spec.ts", workflow)
        self.assertIn("{ name: 'reference-import', testMatch: /reference-import\\.spec\\.ts/, dependencies: ['reference-structures'] }", config)
        self.assertIn("tests/e2e/reference-import.spec.ts tests/e2e/quality-uniqueness.spec.ts", workflow)
        self.assertIn("{ name: 'quality-uniqueness', testMatch: /quality-uniqueness\\.spec\\.ts/, dependencies: ['reference-import'] }", config)
        self.assertIn("tests/e2e/quality-uniqueness.spec.ts tests/e2e/quality-range.spec.ts", workflow)
        self.assertIn("{ name: 'quality-range', testMatch: /quality-range\\.spec\\.ts/, dependencies: ['quality-uniqueness'] }", config)
        self.assertIn("{ name: 'reference-structures', testMatch: /reference-structures\\.spec\\.ts/, dependencies: ['reference-quality'] }", config)
        self.assertIn("{ name: 'reference-quality', testMatch: /reference-quality\\.spec\\.ts/, dependencies: ['reference-data'] }", config)
        self.assertIn("{ name: 'reference-data', testMatch: /reference-data\\.spec\\.ts/, dependencies: ['classification'] }", config)
        self.assertLess(workflow.index("id: monitoring_upgrade"), workflow.index("id: freshness_upgrade"))
        self.assertLess(workflow.index("id: freshness_upgrade"), workflow.index("id: freshness_worker"))
        self.assertLess(workflow.index("id: freshness_worker"), workflow.index("id: browser"))
        self.assertIn("run: python3 scripts/test_quality_freshness_upgrade.py", workflow)
        self.assertIn("run: python3 scripts/test_quality_freshness_scheduling_upgrade.py", workflow)
        self.assertLess(workflow.index("id: freshness_upgrade"), workflow.index("id: freshness_scheduling_upgrade"))
        self.assertLess(workflow.index("id: freshness_scheduling_upgrade"), workflow.index("id: browser"))
        self.assertIn("tests/e2e/quality-freshness.spec.ts tests/e2e/quality-freshness-monitoring.spec.ts", workflow)
        self.assertIn("{ name: 'quality-freshness-monitoring', testMatch: /quality-freshness-monitoring\\.spec\\.ts/, dependencies: ['quality-freshness'] }", config)
        self.assertIn("run: python3 scripts/test_freshness_worker_gate.py", workflow)
        self.assertIn("run: python3 scripts/test_runtime_freshness_fixture.py", workflow)
        self.assertIn("tests/e2e/quality-monitoring.spec.ts tests/e2e/quality-freshness.spec.ts", workflow)
        self.assertIn("{ name: 'quality-freshness', testMatch: /quality-freshness\\.spec\\.ts/, dependencies: ['quality-monitoring'] }", config)
        self.assertIn("id: volume_upgrade\n        run: ./dev test --suite volume-upgrade", workflow)
        self.assertIn("id: volume_worker\n        run: ./dev test --suite volume-worker", workflow)
        self.assertLess(workflow.index("id: freshness_worker"), workflow.index("id: volume_upgrade"))
        self.assertLess(workflow.index("id: volume_upgrade"), workflow.index("id: volume_worker"))
        self.assertLess(workflow.index("id: volume_worker"), workflow.index("id: browser"))
        for control in ("test_quality_volume_upgrade.py", "test_quality_pre030.py", "test_quality_sql019_binding.py", "test_volume_worker_gate.py", "test_volume_fixture.py"):
            self.assertIn("run: python3 scripts/"+control, workflow)
        self.assertIn("tests/e2e/quality-freshness-monitoring.spec.ts tests/e2e/quality-volume.spec.ts", workflow)
        self.assertIn("{ name: 'quality-volume', testMatch: /quality-volume\\.spec\\.ts/, dependencies: ['quality-freshness-monitoring'] }", config)
        self.assertIn("id: protected_authn", workflow)
        self.assertLess(workflow.index("id: browser"), workflow.index("id: protected_authn"))
        for step in STEPS:
            self.assertEqual(workflow.count("id: " + step + "\n"), 1)
            self.assertIn("GC_" + step.upper() + "_RESULT: ${{ steps." + step + ".outcome }}", workflow)


class QualityCommandRoutingTests(unittest.TestCase):
    """Exercise launcher guards and order with all execution replaced, never Docker."""
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('quality_ci_runtime', COLLECTOR.parent.parent / 'scripts/runtime.py')
        cls.runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.runtime)

    def test_isolated_upgrade_does_not_require_core_bootstrap(self):
        calls = []
        with patch.object(sys, 'argv', ['dev', 'test', '--suite', 'quality-upgrade']), \
                patch.object(self.runtime, 'require_local', side_effect=lambda: calls.append('local')), \
                patch.object(self.runtime, 'require_bootstrap', side_effect=AssertionError('core bootstrap reached')), \
                patch.object(self.runtime, 'run', side_effect=lambda args, **kw: calls.append((args, kw))):
            self.runtime.main()
        self.assertEqual(calls, ['local', ([sys.executable, 'scripts/runtime-test-quality-upgrade.py'], {'timeout': 1800})])

    def test_reference_structure_upgrade_runs_without_core_bootstrap(self):
        calls = []
        with patch.object(sys, 'argv', ['dev', 'test', '--suite', 'reference-structure-upgrade']), \
                patch.object(self.runtime, 'require_local', side_effect=lambda: calls.append('local')), \
                patch.object(self.runtime, 'require_bootstrap', side_effect=AssertionError('core bootstrap reached')), \
                patch.object(self.runtime, 'run', side_effect=lambda args, **kw: calls.append((args, kw))):
            self.runtime.main()
        self.assertEqual(calls, ['local', ([sys.executable, 'scripts/runtime-test-reference-structure-upgrade.py'], {'timeout': 3000})])

    def test_reference_import_runs_without_core_bootstrap_with_explicit_local_opt_in(self):
        calls = []
        with patch.object(sys, 'argv', ['dev', 'test', '--suite', 'reference-import']), \
                patch.object(self.runtime, 'require_local', side_effect=lambda: calls.append('local')), \
                patch.object(self.runtime, 'require_bootstrap', side_effect=AssertionError('core bootstrap reached')), \
                patch.object(self.runtime, 'run', side_effect=lambda args, **kw: calls.append((args, kw))):
            self.runtime.main()
        self.assertEqual(calls, ['local', ([sys.executable, 'scripts/runtime-test-reference-import.py', '--run-local'], {'timeout': 900})])

    def test_worker_requires_existing_local_bootstrap_and_explicit_local_opt_in(self):
        calls = []
        with patch.object(sys, 'argv', ['dev', 'test', '--suite', 'quality-worker']), \
                patch.object(self.runtime, 'require_bootstrap', side_effect=lambda: calls.append('bootstrap')), \
                patch.object(self.runtime, 'require_local', side_effect=lambda: calls.append('local')), \
                patch.object(self.runtime, 'run', side_effect=lambda args, **kw: calls.append((args, kw))):
            self.runtime.main()
        self.assertEqual(calls, ['bootstrap', 'local', ([sys.executable, 'scripts/runtime-test-quality-worker.py', '--run-local'], {'timeout': 360})])

    def test_uniqueness_upgrade_is_isolated_with_explicit_local_opt_in(self):
        calls = []
        with patch.object(sys, 'argv', ['dev', 'test', '--suite', 'uniqueness-upgrade']), \
                patch.object(self.runtime, 'require_local', side_effect=lambda: calls.append('local')), \
                patch.object(self.runtime, 'require_bootstrap', side_effect=AssertionError('core bootstrap reached')), \
                patch.object(self.runtime, 'run', side_effect=lambda args, **kw: calls.append((args, kw))):
            self.runtime.main()
        self.assertEqual(calls, ['local', ([sys.executable, 'scripts/runtime-test-quality-uniqueness-upgrade.py', '--run-local'], {'timeout': 900})])

    def test_uniqueness_worker_requires_core_and_explicit_local_opt_in(self):
        calls = []
        with patch.object(sys, 'argv', ['dev', 'test', '--suite', 'uniqueness-worker']), \
                patch.object(self.runtime, 'require_bootstrap', side_effect=lambda: calls.append('bootstrap')), \
                patch.object(self.runtime, 'require_local', side_effect=lambda: calls.append('local')), \
                patch.object(self.runtime, 'run', side_effect=lambda args, **kw: calls.append((args, kw))):
            self.runtime.main()
        self.assertEqual(calls, ['bootstrap', 'local', ([sys.executable, 'scripts/runtime-test-uniqueness-quality-worker.py', '--run-local'], {'timeout': 900})])

    def test_range_upgrade_is_isolated_with_explicit_local_opt_in(self):
        calls = []
        with patch.object(sys, 'argv', ['dev', 'test', '--suite', 'range-upgrade']), \
                patch.object(self.runtime, 'require_local', side_effect=lambda: calls.append('local')), \
                patch.object(self.runtime, 'require_bootstrap', side_effect=AssertionError('core bootstrap reached')), \
                patch.object(self.runtime, 'run', side_effect=lambda args, **kw: calls.append((args, kw))):
            self.runtime.main()
        self.assertEqual(calls, ['local', ([sys.executable, 'scripts/runtime-test-quality-range-upgrade.py', '--run-local'], {'timeout': 900})])

    def test_monitoring_upgrade_is_isolated_with_explicit_local_opt_in(self):
        calls = []
        with patch.object(sys, 'argv', ['dev', 'test', '--suite', 'monitoring-upgrade']), \
                patch.object(self.runtime, 'require_local', side_effect=lambda: calls.append('local')), \
                patch.object(self.runtime, 'require_bootstrap', side_effect=AssertionError('core bootstrap reached')), \
                patch.object(self.runtime, 'run', side_effect=lambda args, **kw: calls.append((args, kw))):
            self.runtime.main()
        self.assertEqual(calls, ['local', ([sys.executable, 'scripts/runtime-test-quality-monitoring-upgrade.py', '--run-local'], {'timeout': 900})])

    def test_freshness_upgrade_is_isolated_with_explicit_local_opt_in(self):
        calls = []
        with patch.object(sys, 'argv', ['dev', 'test', '--suite', 'freshness-upgrade']), \
                patch.object(self.runtime, 'require_local', side_effect=lambda: calls.append('local')), \
                patch.object(self.runtime, 'require_bootstrap', side_effect=AssertionError('core bootstrap reached')), \
                patch.object(self.runtime, 'run', side_effect=lambda args, **kw: calls.append((args, kw))):
            self.runtime.main()
        self.assertEqual(calls, ['local', ([sys.executable, 'scripts/runtime-test-quality-freshness-upgrade.py', '--run-local'], {'timeout': 900})])

    def test_freshness_scheduling_upgrade_is_isolated_with_explicit_local_opt_in(self):
        calls = []
        with patch.object(sys, 'argv', ['dev', 'test', '--suite', 'freshness-scheduling-upgrade']), \
                patch.object(self.runtime, 'require_local', side_effect=lambda: calls.append('local')), \
                patch.object(self.runtime, 'require_bootstrap', side_effect=AssertionError('core bootstrap reached')), \
                patch.object(self.runtime, 'run', side_effect=lambda args, **kw: calls.append((args, kw))):
            self.runtime.main()
        self.assertEqual(calls, ['local', ([sys.executable, 'scripts/runtime-test-quality-freshness-scheduling-upgrade.py', '--run-local'], {'timeout': 900})])

    def test_volume_upgrade_is_isolated_with_explicit_local_opt_in(self):
        calls = []
        with patch.object(sys, 'argv', ['dev', 'test', '--suite', 'volume-upgrade']), \
                patch.object(self.runtime, 'require_local', side_effect=lambda: calls.append('local')), \
                patch.object(self.runtime, 'require_bootstrap', side_effect=AssertionError('core bootstrap reached')), \
                patch.object(self.runtime, 'run', side_effect=lambda args, **kw: calls.append((args, kw))):
            self.runtime.main()
        self.assertEqual(calls, ['local', ([sys.executable, 'scripts/runtime-test-quality-volume-upgrade.py', '--run-local'], {'timeout': 900})])

    def test_range_worker_requires_core_and_explicit_local_opt_in(self):
        calls = []
        with patch.object(sys, 'argv', ['dev', 'test', '--suite', 'range-worker']), \
                patch.object(self.runtime, 'require_bootstrap', side_effect=lambda: calls.append('bootstrap')), \
                patch.object(self.runtime, 'require_local', side_effect=lambda: calls.append('local')), \
                patch.object(self.runtime, 'run', side_effect=lambda args, **kw: calls.append((args, kw))):
            self.runtime.main()
        self.assertEqual(calls, ['bootstrap', 'local', ([sys.executable, 'scripts/runtime-test-range-quality-worker.py', '--run-local'], {'timeout': 900})])

    def test_freshness_worker_requires_core_and_explicit_local_opt_in(self):
        calls = []
        with patch.object(sys, 'argv', ['dev', 'test', '--suite', 'freshness-worker']), \
                patch.object(self.runtime, 'require_bootstrap', side_effect=lambda: calls.append('bootstrap')), \
                patch.object(self.runtime, 'require_local', side_effect=lambda: calls.append('local')), \
                patch.object(self.runtime, 'run', side_effect=lambda args, **kw: calls.append((args, kw))):
            self.runtime.main()
        self.assertEqual(calls, ['bootstrap', 'local', ([sys.executable, 'scripts/runtime-test-freshness-quality-worker.py', '--run-local'], {'timeout': 900})])

    def test_volume_worker_requires_core_and_explicit_local_opt_in(self):
        calls = []
        with patch.object(sys, 'argv', ['dev', 'test', '--suite', 'volume-worker']), \
                patch.object(self.runtime, 'require_bootstrap', side_effect=lambda: calls.append('bootstrap')), \
                patch.object(self.runtime, 'require_local', side_effect=lambda: calls.append('local')), \
                patch.object(self.runtime, 'run', side_effect=lambda args, **kw: calls.append((args, kw))):
            self.runtime.main()
        self.assertEqual(calls, ['bootstrap', 'local', ([sys.executable, 'scripts/runtime-test-volume-quality-worker.py', '--run-local'], {'timeout': 900})])

    def test_quality_gate_refusal_does_not_fall_through_or_launch(self):
        for suite in ('quality-upgrade', 'quality-worker', 'reference-structure-upgrade', 'reference-import', 'uniqueness-upgrade', 'uniqueness-worker', 'range-upgrade', 'range-worker', 'monitoring-upgrade', 'freshness-upgrade', 'freshness-scheduling-upgrade', 'freshness-worker', 'volume-upgrade', 'volume-worker'):
            with self.subTest(suite=suite), \
                    patch.object(sys, 'argv', ['dev', 'test', '--suite', suite]), \
                    patch.object(self.runtime, 'require_bootstrap'), \
                    patch.object(self.runtime, 'require_local', side_effect=SystemExit('local refusal')), \
                    patch.object(self.runtime, 'run') as run:
                with self.assertRaisesRegex(SystemExit, '^local refusal$'):
                    self.runtime.main()
                run.assert_not_called()
            with self.subTest(suite=suite, failure=True), \
                    patch.object(sys, 'argv', ['dev', 'test', '--suite', suite]), \
                    patch.object(self.runtime, 'require_bootstrap'), patch.object(self.runtime, 'require_local'), \
                    patch.object(self.runtime, 'run', side_effect=subprocess.CalledProcessError(1, 'synthetic')) as run:
                with self.assertRaises(subprocess.CalledProcessError):
                    self.runtime.main()
                self.assertEqual(run.call_count, 1)

    def test_seed_installs_or_validates_source_before_existing_persona_seed(self):
        with patch.object(sys, 'argv', ['dev', 'seed', '--dataset', 'harbor-demo']), \
                patch.object(self.runtime, 'require_bootstrap'), patch.object(self.runtime, 'require_local'), \
                patch.object(self.runtime, 'run') as run:
            self.runtime.main()
        self.assertEqual([(call.args, call.kwargs) for call in run.call_args_list], [
            (([sys.executable, 'scripts/runtime-install-quality-fixture.py', '--run-core'],), {'timeout': 60}),
            (([sys.executable, 'scripts/runtime-install-quality-fixture.py', '--run-core', '--reference'],), {'timeout': 60}),
            (([sys.executable, 'scripts/runtime-install-quality-fixture.py', '--run-core', '--uniqueness'],), {'timeout': 60}),
            (([sys.executable, 'scripts/runtime-install-quality-fixture.py', '--run-core', '--range'],), {'timeout': 60}),
            (([sys.executable, 'scripts/runtime-volume-fixture.py', '--run-core', '--step', 'prepare'],), {'timeout': 60}),
            ((self.runtime.COMPOSE + ['run', '--rm', 'seed'],), {'timeout': 120}),
        ])

    def test_reference_fixture_refusal_prevents_persona_seed_after_completeness_validation(self):
        with patch.object(sys, 'argv', ['dev', 'seed', '--dataset', 'harbor-demo']), \
                patch.object(self.runtime, 'require_bootstrap'), patch.object(self.runtime, 'require_local'), \
                patch.object(self.runtime, 'run', side_effect=[None, subprocess.CalledProcessError(1, 'synthetic')]) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                self.runtime.main()
        self.assertEqual([(call.args, call.kwargs) for call in run.call_args_list], [
            (([sys.executable, 'scripts/runtime-install-quality-fixture.py', '--run-core'],), {'timeout': 60}),
            (([sys.executable, 'scripts/runtime-install-quality-fixture.py', '--run-core', '--reference'],), {'timeout': 60}),
        ])

    def test_uniqueness_fixture_refusal_prevents_persona_seed_after_old_profiles(self):
        with patch.object(sys, 'argv', ['dev', 'seed', '--dataset', 'harbor-demo']), \
                patch.object(self.runtime, 'require_bootstrap'), patch.object(self.runtime, 'require_local'), \
                patch.object(self.runtime, 'run', side_effect=[None, None, subprocess.CalledProcessError(1, 'synthetic')]) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                self.runtime.main()
        self.assertEqual([(call.args, call.kwargs) for call in run.call_args_list], [
            (([sys.executable, 'scripts/runtime-install-quality-fixture.py', '--run-core'],), {'timeout': 60}),
            (([sys.executable, 'scripts/runtime-install-quality-fixture.py', '--run-core', '--reference'],), {'timeout': 60}),
            (([sys.executable, 'scripts/runtime-install-quality-fixture.py', '--run-core', '--uniqueness'],), {'timeout': 60}),
        ])

    def test_range_fixture_refusal_prevents_persona_seed_after_old_profiles(self):
        with patch.object(sys, 'argv', ['dev', 'seed', '--dataset', 'harbor-demo']), \
                patch.object(self.runtime, 'require_bootstrap'), patch.object(self.runtime, 'require_local'), \
                patch.object(self.runtime, 'run', side_effect=[None, None, None, subprocess.CalledProcessError(1, 'synthetic')]) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                self.runtime.main()
        self.assertEqual([(call.args, call.kwargs) for call in run.call_args_list], [
            (([sys.executable, 'scripts/runtime-install-quality-fixture.py', '--run-core'],), {'timeout': 60}),
            (([sys.executable, 'scripts/runtime-install-quality-fixture.py', '--run-core', '--reference'],), {'timeout': 60}),
            (([sys.executable, 'scripts/runtime-install-quality-fixture.py', '--run-core', '--uniqueness'],), {'timeout': 60}),
            (([sys.executable, 'scripts/runtime-install-quality-fixture.py', '--run-core', '--range'],), {'timeout': 60}),
        ])

    def test_volume_prepare_refusal_never_repairs_or_runs_persona_seed(self):
        with patch.object(sys, 'argv', ['dev', 'seed', '--dataset', 'harbor-demo']), patch.object(self.runtime, 'require_bootstrap'), patch.object(self.runtime, 'require_local'), patch.object(self.runtime, 'run', side_effect=[None,None,None,None,subprocess.CalledProcessError(1,'synthetic')]) as run:
            with self.assertRaises(subprocess.CalledProcessError):self.runtime.main()
        self.assertEqual(run.call_count,5)
        self.assertEqual(run.call_args.args,([sys.executable,'scripts/runtime-volume-fixture.py','--run-core','--step','prepare'],))
        self.assertNotIn('repair',str(run.call_args_list))

    def test_fixture_refusal_or_unknown_dataset_cannot_run_seed(self):
        with patch.object(sys, 'argv', ['dev', 'seed', '--dataset', 'harbor-demo']), \
                patch.object(self.runtime, 'require_bootstrap'), patch.object(self.runtime, 'require_local'), \
                patch.object(self.runtime, 'run', side_effect=subprocess.CalledProcessError(1, 'synthetic')) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                self.runtime.main()
            run.assert_called_once_with([sys.executable, 'scripts/runtime-install-quality-fixture.py', '--run-core'], timeout=60)
        with patch.object(sys, 'argv', ['dev', 'seed', '--dataset', 'unsupported']), \
                patch.object(self.runtime, 'require_bootstrap'), patch.object(self.runtime, 'require_local'), \
                patch.object(self.runtime, 'run') as run:
            with self.assertRaises(SystemExit):
                self.runtime.main()
            run.assert_not_called()


def load_tests(loader, tests, pattern):
    # The existing hosted quality command also exercises the new API evidence
    # boundary; no new workflow privilege or artifact path is required.
    tests.addTests(loader.loadTestsFromModule(test_api_evidence))
    tests.addTests(loader.loadTestsFromModule(test_authentication_evidence))
    tests.addTests(loader.loadTestsFromModule(test_protected_authn_evidence))
    tests.addTests(loader.loadTestsFromModule(test_authority_diagnostics))
    return tests


if __name__ == "__main__":
    unittest.main()
