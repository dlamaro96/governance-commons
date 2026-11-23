#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic parser/staging controls; these never claim real API execution."""
import copy
import contextlib
import io
import subprocess
from types import SimpleNamespace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from api_evidence import collect, declaration_literal, run, safe_report, source_inventory

COMMIT = "a" * 40
SOURCE = """// SPDX-License-Identifier: Apache-2.0
test('first static test', async () => {
  assert.equal(value, expected);
});
test('second static test', async () => {
  assert.equal(value, expected);
});
"""


def tap(failed=False):
    diagnostic = """  ---
  duration_ms: 1.2
  location: '/PRIVATE_PATH/tests/integration/example.test.ts:5:1'
  error: 'PRIVATE_ERROR_TOKEN'
  expected: 'PRIVATE_EXPECTED'
  actual: 'PRIVATE_ACTUAL'
  stack: |-
    TestContext.<anonymous> (/PRIVATE_PATH/tests/integration/example.test.ts:6:3)
    PRIVATE_STACK_BODY
    injected (/PRIVATE_PATH/tests/integration/unknown.test.ts:6:3)
    out_of_range (/PRIVATE_PATH/tests/integration/example.test.ts:999:3)
  ...
""" if failed else ""
    return ("TAP version 13\n# Subtest: first static test\nok 1 - first static test\n"
            "# Subtest: second static test\n" + ("not ok" if failed else "ok") + " 2 - second static test\n" + diagnostic
            + "1..2\n# tests 2\n# suites 0\n# pass " + ("1" if failed else "2") + "\n# fail " + ("1" if failed else "0")
            + "\n# cancelled 0\n# skipped 0\n# todo 0\n# duration_ms 3\n").encode()


class ApiEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="gc-api-evidence-")
        self.root = Path(self.directory.name)
        self.source = self.root / "tests/integration/example.test.ts"
        self.source.parent.mkdir(parents=True)
        self.source.write_text(SOURCE)

    def tearDown(self):
        self.directory.cleanup()

    def report(self, output=None, code=0, match=True, truncated=False):
        return collect(self.root, tap() if output is None else output, code, COMMIT, match, truncated)

    def run_control(self, *, stale=False, preparation_code=0, preparation_output=b"PRIVATE_PREPARATION", preparation_timeout=False):
        events, waits, commands = [], [], []
        hashes = {name: source['sha256'] for name, source in source_inventory(self.root)[0].items()}
        def command(args, **kwargs):
            if args[:2] == ['git', 'rev-parse']:
                return SimpleNamespace(returncode=0, stdout=COMMIT+'\n')
            boundary = 'api' if 'exec' in args else 'qualification-runner'
            events.append('readback-'+boundary)
            return SimpleNamespace(returncode=0, stdout=json.dumps({} if stale else hashes).encode())
        def launch(args, **kwargs):
            preparation = 'authn-test-fixture' in args
            events.append('preparation' if preparation else 'tests'); commands.append(args)
            class Process:
                stdout = io.BytesIO(preparation_output if preparation else tap())
                killed = False
                def wait(self, timeout=None):
                    waits.append(('preparation' if preparation else 'tests', timeout))
                    if preparation and preparation_timeout and not self.killed:
                        raise subprocess.TimeoutExpired(args, timeout)
                    return preparation_code if preparation else 0
                def kill(self):
                    self.killed = True
                def terminate(self):
                    self.killed = True
            return Process()
        with patch('api_evidence.subprocess.run', side_effect=command), patch('api_evidence.subprocess.Popen', side_effect=launch), contextlib.redirect_stdout(io.StringIO()):
            code = run(self.root)
        report = json.loads((self.root/'.local/evidence/api-summary.json').read_text())
        self.assertNotIn('PRIVATE', json.dumps(report))
        self.assertEqual(safe_report(self.root, report, COMMIT), report)
        return code, report, events, waits, commands

    def test_stale_image_sources_cannot_invoke_owner_preparation_or_tests(self):
        code, report, events, _, commands = self.run_control(stale=True)
        self.assertEqual(code, 1); self.assertEqual(report['outcome'], 'NOT_PASSED')
        self.assertIn('RUNTIME_SOURCE_MISMATCH', report['flags'])
        self.assertEqual(events, ['readback-api']); self.assertEqual(commands, [])
        self.assertEqual(list((self.root/'.local/evidence/api-runs').glob('*/preparation.log')), [])

    def test_failed_owner_preparation_prevents_test_launch_and_retains_failure(self):
        code, report, events, waits, _ = self.run_control(preparation_code=7)
        self.assertEqual(code, 1); self.assertEqual(report['outcome'], 'NOT_PASSED')
        self.assertEqual(report['exit_code'], 7); self.assertIn('RUNNER_FAILED', report['flags'])
        self.assertEqual(events, ['readback-api', 'readback-qualification-runner', 'preparation', 'readback-api', 'readback-qualification-runner'])
        self.assertEqual(report['observed_results'], 0)
        retained = list((self.root/'.local/evidence/api-runs').glob('*/preparation.log'))
        self.assertEqual(len(retained), 1); self.assertEqual(retained[0].read_bytes(), b'PRIVATE_PREPARATION')
        self.assertEqual(retained[0].stat().st_mode & 0o777, 0o600)
        self.assertTrue(all(0 < seconds <= 180 for _, seconds in waits))

    def test_preparation_timeout_or_output_overflow_never_starts_tests(self):
        for options, expected in (({'preparation_timeout': True}, 124), ({'preparation_output': b'x'*65537}, 125)):
            with self.subTest(options=list(options)):
                code, report, events, _, _ = self.run_control(**options)
                self.assertEqual(code, 1); self.assertEqual(report['exit_code'], expected)
                self.assertEqual(report['outcome'], 'NOT_PASSED'); self.assertNotIn('tests', events)
                self.assertTrue(all(p.stat().st_size <= 65536 for p in (self.root/'.local/evidence/api-runs').glob('*/preparation.log')))

    def test_successful_preparation_follows_both_readbacks_with_unchanged_test_supervisor(self):
        code, report, events, waits, commands = self.run_control()
        self.assertEqual(code, 0); self.assertEqual(report['outcome'], 'PASS')
        self.assertEqual(events, ['readback-api', 'readback-qualification-runner', 'preparation', 'tests', 'readback-api', 'readback-qualification-runner'])
        self.assertEqual([kind for kind, _ in waits], ['preparation', 'tests'])
        self.assertLessEqual(waits[0][1], 180); self.assertLess(waits[1][1], 1800)
        self.assertIn('stop(124),150000)', commands[0][commands[0].index('-e')+1])
        self.assertIn('stop(124),1740000)', commands[1][commands[1].index('-e')+1])
        self.assertEqual(commands[0][-6:], ['tsx', 'scripts/protected-core-test-fixture.ts', '--batch', '/state/qualification', '--core-plan', '/state/plan.json'])
        self.assertNotIn('authn-test-fixture', (Path(__file__).resolve().parents[1]/'scripts/test-security.sh').read_text())

    def test_new_run_invalidates_latest_before_failure_and_preserves_archives(self):
        archive = self.root / ".local/evidence/api-runs/prior-invocation"
        archive.mkdir(parents=True)
        archived_summary = archive / "summary.json"
        archived_tap = archive / "output.tap"
        summary = json.dumps(self.report(tap(True), code=1)).encode()
        archived_summary.write_bytes(summary)
        archived_tap.write_bytes(tap(True))
        latest = self.root / ".local/evidence/api-summary.json"
        missing_target = archive / "absent.json"
        for entry in ("regular", "symlink", "dangling_symlink", "absent"):
            with self.subTest(entry=entry):
                latest.unlink(missing_ok=True)
                if entry == "regular":
                    latest.write_bytes(summary)
                elif entry == "symlink":
                    latest.symlink_to(archived_summary)
                elif entry == "dangling_symlink":
                    latest.symlink_to(missing_target)
                # Stop at the first subsequent operation: no Docker/API execution.
                with patch("api_evidence.source_inventory", side_effect=OSError("source unavailable")), \
                        patch("api_evidence.subprocess.run") as command, \
                        patch("api_evidence.subprocess.Popen") as process:
                    with self.assertRaises(OSError):
                        run(self.root)
                    command.assert_not_called()
                    process.assert_not_called()
                self.assertFalse(latest.exists())
                self.assertFalse(latest.is_symlink())
                self.assertEqual(archived_summary.read_bytes(), summary)
                self.assertEqual(archived_tap.read_bytes(), tap(True))
                self.assertFalse(missing_target.exists())
                self.assertEqual(sorted(path.name for path in archive.iterdir()), ["output.tap", "summary.json"])

    def support_fixture(self):
        self.source.write_text("import {fixture} from '../fixtures/protected-core-authentication.ts';\n"+SOURCE)
        helper=self.root/'tests/fixtures/protected-core-authentication.ts'
        helper.parent.mkdir(parents=True);helper.write_text("import {value} from './nested.ts';\nexport const fixture=value;\n")
        (helper.parent/'nested.ts').write_text('export const value=1;\n')
        for name in ('scripts/protected-core-test-fixture.ts','scripts/test-security.sh','deploy/compose/compose.yaml','policies/api_evidence.py','package.json','pnpm-lock.yaml','tsconfig.json'):
            p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('// synthetic control input\n')
        return helper

    def test_imported_helpers_and_explicit_provisioning_are_bound_without_extra_declarations(self):
        self.support_fixture()
        files,declarations,flags=source_inventory(self.root)
        self.assertEqual(flags,set());self.assertEqual(len(declarations),2);self.assertEqual(len(files),10)
        self.assertIn('scripts/protected-core-test-fixture.ts',files)
        self.assertIn('tests/fixtures/nested.ts',files)
        report=self.report();self.assertEqual(report['outcome'],'PASS');self.assertEqual(safe_report(self.root,report,COMMIT),report)
        (self.root/'scripts/protected-core-test-fixture.ts').write_text('// changed owner provisioning\n')
        self.assertIsNone(safe_report(self.root,report,COMMIT))

    def test_missing_provisioning_and_transitive_imports_fail_closed(self):
        self.support_fixture()
        for name in ('scripts/protected-core-test-fixture.ts','tests/fixtures/nested.ts'):
            p=self.root/name;original=p.read_bytes();p.unlink()
            self.assertIn('SOURCE_DECLARATION_INVALID',source_inventory(self.root)[2]);p.write_bytes(original)

    def test_symlinked_helpers_and_imports_escaping_root_fail_closed(self):
        helper=self.support_fixture();saved=helper.read_bytes();target=helper.parent/'target.ts';target.write_bytes(saved)
        helper.unlink();helper.symlink_to(target)
        self.assertIn('SOURCE_DECLARATION_INVALID',source_inventory(self.root)[2]);helper.unlink();helper.write_bytes(saved)
        self.source.write_text("import '../fixtures/../../../../outside.ts';\n"+SOURCE)
        self.assertIn('SOURCE_DECLARATION_INVALID',source_inventory(self.root)[2])

    def test_complete_static_results_are_source_bound_without_titles(self):
        report = self.report()
        self.assertEqual(report["outcome"], "PASS")
        self.assertEqual(report["expected_tests"], 2)
        self.assertEqual([row["line"] for row in report["tests"]], [2, 5])
        self.assertNotIn("static test", json.dumps(report))
        self.assertEqual(safe_report(self.root, report, COMMIT), report)

    def test_real_failure_shape_retains_only_declared_coordinates(self):
        report = self.report(tap(True), code=1)
        self.assertEqual(report["outcome"], "NOT_PASSED")
        self.assertEqual(report["counts"]["fail"], 1)
        self.assertEqual(report["tests"][1]["failure_locations"], [
            {"file": "tests/integration/example.test.ts", "line": 5, "column": 1},
            {"file": "tests/integration/example.test.ts", "line": 6, "column": 3}])
        self.assertNotIn("PRIVATE", json.dumps(report))
        self.assertEqual(safe_report(self.root, report, COMMIT), report)

    def test_dynamic_unknown_names_and_file_failures_are_not_published(self):
        for name in (b"PRIVATE_DYNAMIC_TITLE", b"/PRIVATE_PATH/tests/integration/example.test.ts"):
            with self.subTest(name=name):
                report = self.report(tap().replace(b"ok 2 - second static test", b"not ok 2 - " + name), code=1)
                self.assertIn("UNMAPPED_RESULT", report["flags"])
                self.assertNotIn("PRIVATE", json.dumps(report))
                self.assertEqual(report["outcome"], "NOT_PASSED")

    def test_truncated_duplicate_missing_and_misnumbered_results_fail_closed(self):
        candidates = [tap()[:100], tap() + b"# tests 2\n", tap().replace(b"ok 2 - second static test", b"ok 2 - first static test"),
                      tap().replace(b"ok 2 -", b"ok 3 -"), tap().replace(b"1..2", b"1..1"), tap().replace(b"# pass 2", b"# pass 99")]
        for output in candidates:
            with self.subTest(output_hash=len(output)):
                self.assertEqual(self.report(output)["outcome"], "NOT_PASSED")

    def test_timeout_truncation_and_runtime_source_mismatch_never_pass(self):
        for changes in ({"code": 124}, {"truncated": True}, {"match": False}):
            self.assertEqual(self.report(**changes)["outcome"], "NOT_PASSED")

    def test_skipped_and_todo_are_not_passing_execution(self):
        for suffix in (b" # SKIP PRIVATE_REASON", b" # TODO PRIVATE_REASON"):
            report = self.report(tap().replace(b"ok 2 - second static test", b"ok 2 - second static test" + suffix))
            self.assertEqual(report["outcome"], "NOT_PASSED")
            self.assertNotIn("PRIVATE", json.dumps(report))

    def test_dynamic_or_duplicate_source_declarations_fail_closed(self):
        for addition in ("test(`dynamic ${secret}`, async () => {});\n", "  test('nested', async () => {});\n", "test('first static test', async () => {});\n"):
            self.source.write_text(SOURCE + addition)
            self.assertIn("SOURCE_DECLARATION_INVALID", self.report()["flags"])

    def test_static_literal_scan_preserves_escaped_quotes_and_backslashes(self):
        single = r"""test('escaped \' quote and \\ slash', async () => {});"""
        double = r'''test("double \" quote and \\ slash", async () => {});'''
        self.source.write_text(SOURCE + single + "\n" + double + "\n")
        _, declarations, flags = source_inventory(self.root)
        self.assertEqual(flags, set())
        self.assertEqual(set(declarations), {"first static test", "second static test",
                                            "escaped ' quote and \\ slash", 'double " quote and \\ slash'})
        self.assertEqual(declaration_literal('test( \t"name" \t, async () => {});'), '"name"')

    def test_static_literal_scan_rejects_malformed_or_nonliteral_declarations(self):
        malformed = ["test(", "test(   ", "test('unclosed", 'test("unclosed', "test('trailing\\",
                     "test('name')", "test('name' + 'suffix', async () => {});", "test(`dynamic`, async () => {});",
                     "test(identifier, async () => {});", " test('nested', async () => {});",
                     "test.only('focused', async () => {});", "test('escaped\\' quote, async () => {});"]
        for text in malformed:
            with self.subTest(length=len(text)):
                self.assertIsNone(declaration_literal(text))
                self.source.write_text(SOURCE + text + "\n")
                self.assertIn("SOURCE_DECLARATION_INVALID", source_inventory(self.root)[2])

    def test_long_malformed_backslash_and_quote_sequences_fail_closed(self):
        for quote in ("'", '"'):
            for payload in ("\\" * 131072, ("\\" + quote) * 65536 + "\\"):
                with self.subTest(quote=quote, length=len(payload)):
                    text = "test(" + quote + payload
                    self.assertIsNone(declaration_literal(text))
                    self.source.write_text(SOURCE + text + "\n")
                    _, declarations, flags = source_inventory(self.root)
                    self.assertEqual(set(declarations), {"first static test", "second static test"})
                    self.assertEqual(flags, {"SOURCE_DECLARATION_INVALID"})

    def test_staging_rejects_wrong_commit_changed_source_and_extra_fields(self):
        report = self.report()
        self.assertIsNone(safe_report(self.root, report, "b" * 40))
        extended = {**report, "error": "PRIVATE_PAYLOAD"}
        self.assertIsNone(safe_report(self.root, extended, COMMIT))
        self.source.write_text(SOURCE + "// different source\n")
        self.assertIsNone(safe_report(self.root, report, COMMIT))

    def test_staging_rejects_private_fields_and_out_of_bounds_coordinates(self):
        report = self.report(tap(True), code=1)
        mutations = [lambda value: value["tests"][0].update(title="PRIVATE_TITLE"),
                     lambda value: value["tests"][1]["failure_locations"][0].update(line=999),
                     lambda value: value["tests"][1]["failure_locations"][0].update(column=999),
                     lambda value: value["flags"].append("PRIVATE_ERROR"),
                     lambda value: value.update(timestamp="PRIVATE_TIMESTAMP"),
                     lambda value: value.update(outcome="PASS")]
        for mutate in mutations:
            value = copy.deepcopy(report); mutate(value)
            self.assertIsNone(safe_report(self.root, value, COMMIT))

    def test_staging_reconstructs_fixed_metadata_instead_of_copying_it(self):
        report = self.report()
        for field in ("command", "profile", "limitations"):
            report[field] = "PRIVATE_PAYLOAD"
        safe = safe_report(self.root, report, COMMIT)
        self.assertIsNotNone(safe)
        self.assertNotIn("PRIVATE", json.dumps(safe))

    def test_malformed_nested_types_fail_without_exposing_them(self):
        for field, value in (("tests", [{}]), ("flags", [{}]), ("counts", []), ("exit_code", "PRIVATE")):
            report = self.report(); report[field] = value
            self.assertIsNone(safe_report(self.root, report, COMMIT))


if __name__ == "__main__":
    unittest.main()
