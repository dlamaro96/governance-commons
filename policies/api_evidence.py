#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the real API suite; retain bounded private TAP and publish only coordinates.

No title, error, SQL, expected/actual value or log excerpt enters the safe report.
An outcome maps to a test only when its title exactly matches one static source
declaration. Unknown/dynamic declarations, missing results and truncation fail
closed. This is execution evidence, not proof that every security case exists.
"""
from __future__ import annotations

import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import threading
import uuid

ROOT = Path(__file__).resolve().parents[1]
MAX_OUTPUT = 32 * 1024 * 1024
FILE = re.compile(r"tests/integration/[a-z0-9-]+\.test\.ts\Z")
DECLARATION = re.compile(r"^test\(\s*((['\"])(?:\\.|(?!\2).)*\2)\s*,")
COUNTERS = ("tests", "suites", "pass", "fail", "cancelled", "skipped", "todo")
FLAGS = {"SOURCE_DECLARATION_INVALID", "OUTPUT_TRUNCATED", "TAP_ENVELOPE_INVALID", "TAP_COUNTS_INVALID",
         "UNMAPPED_RESULT", "DUPLICATE_RESULT", "MISSING_RESULT", "RUNTIME_SOURCE_MISMATCH", "RUNNER_FAILED"}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_inventory(root: Path) -> tuple[dict, dict, set[str]]:
    files, declarations, flags = {}, {}, set()
    for path in sorted((root / "tests/integration").glob("*.test.ts")):
        name = str(path.relative_to(root))
        if path.is_symlink() or not FILE.fullmatch(name):
            flags.add("SOURCE_DECLARATION_INVALID")
            continue
        data = path.read_bytes()
        lines = data.decode("utf-8").splitlines()
        files[name] = {"sha256": digest(data), "lines": lines}
        for line, text in enumerate(lines, 1):
            if not re.match(r"^\s*(?:test|it|describe)(?:\s*\(|\.)", text):
                continue
            match = DECLARATION.match(text)
            try:
                title = ast.literal_eval(match[1]) if match else None
            except (SyntaxError, ValueError):
                title = None
            if not isinstance(title, str) or not title or len(title) > 1000 or any(ord(c) < 32 for c in title) or title in declarations:
                flags.add("SOURCE_DECLARATION_INVALID")
                continue
            declarations[title] = {"file": name, "line": line}
    if not files or not declarations:
        flags.add("SOURCE_DECLARATION_INVALID")
    return files, declarations, flags


def failure_coordinates(block: str, files: dict) -> list[dict]:
    coordinates = set()
    for filename, source in files.items():
        basename = Path(filename).name
        pattern = r"(?:^|[/\\])tests[/\\]integration[/\\]" + re.escape(basename) + r":([1-9][0-9]{0,5}):([1-9][0-9]{0,5})(?=[)'\"\s]|$)"
        for raw_line, raw_column in re.findall(pattern, block[:262144], re.MULTILINE):
            line, column = int(raw_line), int(raw_column)
            if line <= len(source["lines"]) and column <= len(source["lines"][line - 1]) + 1:
                coordinates.add((filename, line, column))
    return [{"file": file, "line": line, "column": column} for file, line, column in sorted(coordinates)[:8]]


def collect(root: Path, output: bytes, exit_code: int, commit: str | None, runtime_sources_match: bool,
            truncated: bool = False) -> dict:
    files, declarations, flags = source_inventory(root)
    if truncated or len(output) > MAX_OUTPUT:
        flags.add("OUTPUT_TRUNCATED")
    if not runtime_sources_match:
        flags.add("RUNTIME_SOURCE_MISMATCH")
    if exit_code:
        flags.add("RUNNER_FAILED")
    text = output[:MAX_OUTPUT].decode("utf-8", errors="replace")
    if len(re.findall(r"^TAP version 13$", text, re.MULTILINE)) != 1:
        flags.add("TAP_ENVELOPE_INVALID")
    plan = re.findall(r"^1\.\.([0-9]{1,6})$", text, re.MULTILINE)
    counters = {}
    for name in COUNTERS:
        values = re.findall(r"^# " + name + r" ([0-9]{1,6})$", text, re.MULTILINE)
        counters[name] = int(values[0]) if len(values) == 1 else None
    matches = list(re.finditer(r"^(ok|not ok) ([1-9][0-9]{0,5}) - ([^\r\n]*)$", text, re.MULTILINE))
    tests, seen = [], set()
    for index, match in enumerate(matches):
        title = match[3]
        status = "passed" if match[1] == "ok" else "failed"
        directive = re.search(r" # (SKIP|TODO)(?: .*)?$", title, re.IGNORECASE)
        if directive:
            status = "skipped" if directive[1].upper() == "SKIP" else "todo"
            title = title[:directive.start()]
        declaration = declarations.get(title)
        block = text[match.end():matches[index + 1].start() if index + 1 < len(matches) else len(text)]
        if declaration is None:
            flags.add("UNMAPPED_RESULT")
            continue
        identity = (declaration["file"], declaration["line"])
        if identity in seen:
            flags.add("DUPLICATE_RESULT")
        seen.add(identity)
        tests.append({**declaration, "status": status,
                      "failure_locations": failure_coordinates(block, files) if status == "failed" else []})
    if len(seen) != len(declarations):
        flags.add("MISSING_RESULT")
    expected = len(declarations)
    count_valid = (len(plan) == 1 and int(plan[0]) == expected == len(matches)
                   and counters["tests"] == expected and counters["suites"] == 0
                   and all(value is not None for value in counters.values())
                   and sum(counters[name] for name in ("pass", "fail", "cancelled", "skipped", "todo")) == expected
                   and counters["pass"] == sum(row["status"] == "passed" for row in tests)
                   and counters["fail"] == sum(row["status"] == "failed" for row in tests)
                   and counters["skipped"] == sum(row["status"] == "skipped" for row in tests)
                   and counters["todo"] == sum(row["status"] == "todo" for row in tests)
                   and [int(match[2]) for match in matches] == list(range(1, expected + 1)))
    if not count_valid:
        flags.add("TAP_COUNTS_INVALID")
    passed = not flags and counters["pass"] == expected and all(counters[name] == 0 for name in ("fail", "cancelled", "skipped", "todo"))
    hashes = {name: source["sha256"] for name, source in files.items()}
    return {"schema_version": 1, "purpose": "REAL_API_TEST_COORDINATES_ONLY", "timestamp": datetime.now(timezone.utc).isoformat(),
            "commit": commit if isinstance(commit, str) and re.fullmatch(r"[a-f0-9]{40}", commit) else None,
            "command": "./dev test --suite security", "profile": "real core API/PostgreSQL; Node TAP; synthetic fixtures",
            "outcome": "PASS" if passed else "NOT_PASSED", "exit_code": exit_code,
            "runtime_test_sources_match": runtime_sources_match, "expected_tests": expected,
            "observed_results": len(matches), "counts": counters, "tests": tests, "flags": sorted(flags),
            "source_files": hashes, "source_manifest_sha256": digest(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()),
            "private_output_sha256": digest(output[:MAX_OUTPUT]),
            "limitations": ["Only exact static repository test declarations and bounded source coordinates are published; raw TAP, titles, errors and values remain private.",
                            "Runtime binding covers the executed test files only, not application image/source equivalence, browser or full release qualification."]}


def _safe_report(root: Path, value: object, commit: str | None) -> dict | None:
    """Revalidate an existing runner report before CI artifact staging.

    Exact field/type inventories prevent an untrusted extra property from being
    copied to the public artifact. Recompute source/declaration bindings now.
    """
    files, declarations, source_flags = source_inventory(root)
    expected_fields = {"schema_version", "purpose", "timestamp", "commit", "command", "profile", "outcome", "exit_code",
                       "runtime_test_sources_match", "expected_tests", "observed_results", "counts", "tests", "flags", "source_files",
                       "source_manifest_sha256", "private_output_sha256", "limitations"}
    if not isinstance(value, dict) or set(value) != expected_fields or source_flags:
        return None
    if value["schema_version"] != 1 or value["purpose"] != "REAL_API_TEST_COORDINATES_ONLY" or value["commit"] != commit:
        return None
    timestamp = value["timestamp"]
    if not isinstance(timestamp, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?\+00:00", timestamp):
        return None
    datetime.fromisoformat(timestamp)
    if not isinstance(commit, str) or not re.fullmatch(r"[a-f0-9]{40}", commit):
        return None
    hashes = {name: source["sha256"] for name, source in files.items()}
    if value["source_files"] != hashes or value["source_manifest_sha256"] != digest(json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode()):
        return None
    if type(value["expected_tests"]) is not int or value["expected_tests"] != len(declarations) or type(value["observed_results"]) is not int or not 0 <= value["observed_results"] <= 100000:
        return None
    if type(value["exit_code"]) is not int or not -128 <= value["exit_code"] <= 255 or type(value["runtime_test_sources_match"]) is not bool:
        return None
    if not isinstance(value["counts"], dict) or set(value["counts"]) != set(COUNTERS) or any(v is not None and (type(v) is not int or not 0 <= v <= 100000) for v in value["counts"].values()):
        return None
    if not isinstance(value["flags"], list) or len(value["flags"]) > len(FLAGS) or any(flag not in FLAGS for flag in value["flags"]):
        return None
    if not isinstance(value["private_output_sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", value["private_output_sha256"]):
        return None
    if not isinstance(value["tests"], list) or len(value["tests"]) > 100000:
        return None
    declared = {(row["file"], row["line"]) for row in declarations.values()}
    tests = []
    for row in value["tests"]:
        if not isinstance(row, dict) or set(row) != {"file", "line", "status", "failure_locations"} or type(row.get("line")) is not int or (row.get("file"), row.get("line")) not in declared or row["status"] not in {"passed", "failed", "skipped", "todo"}:
            return None
        locations = row["failure_locations"]
        if not isinstance(locations, list) or len(locations) > 8 or row["status"] != "failed" and locations:
            return None
        for point in locations:
            if not isinstance(point, dict) or set(point) != {"file", "line", "column"} or point.get("file") not in files or type(point.get("line")) is not int or type(point.get("column")) is not int:
                return None
            lines = files[point["file"]]["lines"]
            if not 1 <= point["line"] <= len(lines) or not 1 <= point["column"] <= len(lines[point["line"] - 1]) + 1:
                return None
        tests.append(row)
    counts = value["counts"]
    identities = {(row["file"], row["line"]) for row in tests}
    is_pass = (not value["flags"] and value["exit_code"] == 0 and value["runtime_test_sources_match"]
               and len(tests) == len(identities) == len(declared) == value["observed_results"] == counts["tests"] == counts["pass"]
               and identities == declared and all(row["status"] == "passed" for row in tests)
               and all(counts[name] == 0 for name in ("suites", "fail", "cancelled", "skipped", "todo")))
    if value["outcome"] != ("PASS" if is_pass else "NOT_PASSED"):
        return None
    # Reconstruct all textual metadata; never propagate caller-owned strings.
    output = collect(root, b"", 1, commit, False)
    output["timestamp"] = timestamp
    for field in ("outcome", "exit_code", "runtime_test_sources_match", "expected_tests", "observed_results", "counts", "tests", "flags", "source_files", "source_manifest_sha256", "private_output_sha256"):
        output[field] = value[field]
    return output


def safe_report(root: Path, value: object, commit: str | None) -> dict | None:
    try:
        return _safe_report(root, value, commit)
    except (KeyError, TypeError, ValueError, OSError):
        return None


def run(root: Path) -> int:
    # A failed new invocation must never stage the previous invocation's result.
    # Unlink only the latest entry, including a symlink; preserve archive targets.
    latest = root / ".local/evidence/api-summary.json"
    latest.unlink(missing_ok=True)
    files, _, source_flags = source_inventory(root)
    hashes = {name: source["sha256"] for name, source in files.items()}
    directory = root / ".local/evidence/api-runs" / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex)
    directory.mkdir(parents=True, mode=0o700)
    raw_path = directory / "output.tap"
    compose = ["docker", "compose", "--project-name", "governance-commons", "--env-file", str(root / ".local/runtime.env"), "-f", str(root / "deploy/compose/compose.yaml"), "exec", "-T", "api"]
    readback_script = "import{readFileSync}from'node:fs';import{createHash}from'node:crypto';const names=JSON.parse(process.argv[1]);process.stdout.write(JSON.stringify(Object.fromEntries(names.map(name=>[name,createHash('sha256').update(readFileSync(name)).digest('hex')]))));"
    def matching_sources() -> bool:
        try:
            result = subprocess.run([*compose, "node", "--input-type=module", "-e", readback_script, json.dumps(list(hashes))], cwd=root, capture_output=True, timeout=30)
            return result.returncode == 0 and len(result.stdout) <= 65536 and json.loads(result.stdout) == hashes
        except (OSError, subprocess.SubprocessError, ValueError):
            return False
    before = not source_flags and matching_sources()
    truncated, exit_code = [False], 1
    with raw_path.open("xb") as output:
        raw_path.chmod(0o600)
        if before:
            command = [*compose, "node", "--import", "tsx", "--test", "--test-concurrency=1", "--test-reporter=tap", *hashes]
            try:
                process = subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                def drain() -> None:
                    retained = 0
                    assert process.stdout is not None
                    while chunk := process.stdout.read(65536):
                        available = max(0, MAX_OUTPUT - retained)
                        output.write(chunk[:available]); retained += min(len(chunk), available)
                        if len(chunk) > available:
                            truncated[0] = True
                reader = threading.Thread(target=drain, daemon=True); reader.start()
                try:
                    exit_code = process.wait(timeout=840)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(); exit_code = 124
                reader.join(timeout=5)
                if reader.is_alive():
                    truncated[0] = True; exit_code = 124
            except OSError:
                exit_code = 1
    current_files, _, current_flags = source_inventory(root)
    after = (before and matching_sources() and not current_flags
             and {name: source["sha256"] for name, source in current_files.items()} == hashes)
    git = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True)
    commit = git.stdout.strip() if git.returncode == 0 else None
    report = collect(root, raw_path.read_bytes(), exit_code, commit, after, truncated[0])
    report_path = directory / "summary.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n"); report_path.chmod(0o600)
    if latest.is_symlink():
        raise SystemExit("Refusing a symlinked API summary destination")
    latest.write_bytes(report_path.read_bytes()); latest.chmod(0o600)
    print(json.dumps({"outcome": report["outcome"], "expected_tests": report["expected_tests"], "observed_results": report["observed_results"], "counts": report["counts"], "flags": report["flags"], "safe_summary": ".local/evidence/api-summary.json"}))
    return 0 if report["outcome"] == "PASS" else 1


if __name__ == "__main__":
    if sys.argv[1:] != ["run"]:
        raise SystemExit("Usage: python3 policies/api_evidence.py run")
    raise SystemExit(run(ROOT))
