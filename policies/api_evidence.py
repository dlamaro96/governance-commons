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
import os
import stat
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
MAX_OUTPUT = 32 * 1024 * 1024
FILE = re.compile(r"tests/integration/[a-z0-9-]+\.test\.ts\Z")
COUNTERS = ("tests", "suites", "pass", "fail", "cancelled", "skipped", "todo")
FLAGS = {"SOURCE_DECLARATION_INVALID", "OUTPUT_TRUNCATED", "TAP_ENVELOPE_INVALID", "TAP_COUNTS_INVALID",
         "UNMAPPED_RESULT", "DUPLICATE_RESULT", "MISSING_RESULT", "RUNTIME_SOURCE_MISMATCH", "RUNNER_FAILED"}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_bytes(path: Path) -> bytes:
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size>16*1024*1024:raise ValueError()
        with os.fdopen(fd,'rb',closefd=False) as stream:data=stream.read(16*1024*1024+1)
        after=os.fstat(fd)
        if len(data)!=before.st_size or (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise ValueError()
        return data
    finally:os.close(fd)


def declaration_literal(text: str) -> str | None:
    """Read one quoted static title in a single forward pass, without backtracking."""
    if not text.startswith("test("):
        return None
    index = len("test(")
    while index < len(text) and text[index].isspace():
        index += 1
    if index == len(text) or text[index] not in ("'", '"'):
        return None
    start, quote = index, text[index]
    index += 1
    while index < len(text):
        if text[index] == "\\":
            # Consume the escape and its character together, including quotes.
            index += 2
        elif text[index] == quote:
            end = index + 1
            index = end
            while index < len(text) and text[index].isspace():
                index += 1
            return text[start:end] if index < len(text) and text[index] == "," else None
        else:
            index += 1
    return None


def source_inventory(root: Path) -> tuple[dict, dict, set[str]]:
    files, declarations, flags = {}, {}, set()
    for path in sorted((root / "tests/integration").glob("*.test.ts")):
        name = str(path.relative_to(root))
        if path.is_symlink() or not FILE.fullmatch(name):
            flags.add("SOURCE_DECLARATION_INVALID")
            continue
        try:
            data=source_bytes(path)
            lines=data.decode("utf-8").splitlines()
        except (OSError,ValueError,UnicodeError):
            flags.add("SOURCE_DECLARATION_INVALID")
            continue
        files[name] = {"sha256": digest(data), "lines": lines}
        for line, text in enumerate(lines, 1):
            if not re.match(r"^\s*(?:test|it|describe)(?:\s*\(|\.)", text):
                continue
            literal = declaration_literal(text)
            try:
                title = ast.literal_eval(literal) if literal is not None else None
            except (SyntaxError, ValueError):
                title = None
            if not isinstance(title, str) or not title or len(title) > 1000 or any(ord(c) < 32 for c in title) or title in declarations:
                flags.add("SOURCE_DECLARATION_INVALID")
                continue
            declarations[title] = {"file": name, "line": line}
    if not files or not declarations:
        flags.add("SOURCE_DECLARATION_INVALID")
    # Bind imported fixtures, product readers and explicit owner provisioning as
    # well as declarations. Only declaration files are passed to node --test.
    pending=list(files)
    total=sum(len("\n".join(row["lines"]).encode()) for row in files.values())
    while pending:
        current=pending.pop()
        text="\n".join(files[current]["lines"])
        dependencies=re.findall(r"(?:from\s*|import\s*(?:\(\s*)?|require\s*\(\s*)['\"](\.[^'\"]+)['\"]",text)
        requested=[]
        for relative in dependencies:
            candidate=Path(os.path.abspath((root/current).parent/relative))
            if candidate.suffix=='.js' and not candidate.exists():candidate=candidate.with_suffix('.ts')
            if not candidate.suffix:candidate=candidate.with_suffix('.ts') if candidate.with_suffix('.ts').exists() else candidate/'index.ts'
            requested.append(candidate)
        if current=='tests/fixtures/protected-core-authentication.ts':
            requested.extend(root/name for name in ('scripts/protected-core-test-fixture.ts','scripts/test-security.sh','deploy/compose/compose.yaml','policies/api_evidence.py','package.json','pnpm-lock.yaml','tsconfig.json'))
        for candidate in requested:
            try:
                name=candidate.relative_to(root).as_posix()
                if not re.fullmatch(r'[A-Za-z0-9_./-]{1,256}',name) or any((root/part).is_symlink() for part in [name,*[str(x) for x in Path(name).parents if str(x)!='.']]):raise ValueError()
                if name in files:continue
                metadata=candidate.lstat()
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size>16*1024*1024 or len(files)>=512:raise ValueError()
                data=source_bytes(candidate);total+=len(data)
                if len(data)!=metadata.st_size or total>64*1024*1024:raise ValueError()
                files[name]={'sha256':digest(data),'lines':data.decode('utf8').splitlines()}
                if candidate.suffix in ('.ts','.tsx','.py'):pending.append(name)
            except (OSError,ValueError,UnicodeError):flags.add('SOURCE_DECLARATION_INVALID')
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
                            "Runtime binding covers declaration sources, their relative import closure and explicit qualification provisioning inputs in both application and isolated test images. It does not certify the complete dependency image, browser or release qualification."]}


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


# The production image has no shell/coreutils. Keep the original 1740-second
# in-container deadline and ten-second TERM-to-KILL grace in a separate Node
# process, so a stuck test event loop cannot renew or prevent the deadline.
API_TEST_SUPERVISOR = r"""import {spawn} from 'node:child_process';
import {constants} from 'node:os';
const child=spawn(process.execPath,process.argv.slice(1),{stdio:'inherit',detached:true});
let forced=null,finished=false,hardTimer;
const signalGroup=signal=>{if(Number.isSafeInteger(child.pid)&&child.pid>1){try{process.kill(-child.pid,signal);}catch(e){if(e.code!=='ESRCH')throw e;}}};
const finish=(code)=>{if(finished)return;finished=true;clearTimeout(deadline);clearTimeout(hardTimer);
 try{signalGroup('SIGKILL');}catch{code=125;}process.exit(code);};
const stop=code=>{if(finished||forced!==null)return;forced=code;
 try{signalGroup('SIGTERM');}catch{finish(125);return;}
 hardTimer=setTimeout(()=>{try{signalGroup('SIGKILL');}catch{finish(125);}},10000);};
const deadline=setTimeout(()=>stop(124),1740000);
for(const signal of ['SIGTERM','SIGINT','SIGHUP'])process.on(signal,()=>stop(128+constants.signals[signal]));
child.once('error',()=>finish(125));
child.once('exit',(code,signal)=>finish(forced??code??(128+(constants.signals[signal]??1))));
"""


def prepare_fixture(command: list[str], root: Path, output_path: Path, timeout: float) -> int:
    """Keep owner preparation output private and bounded, separate from TAP."""
    with output_path.open("xb") as output:
        output_path.chmod(0o600)
        process = subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        overflow = [False]
        def drain() -> None:
            retained = 0
            assert process.stdout is not None
            try:
                while chunk := process.stdout.read1(65536):
                    available = max(0, 65536-retained)
                    output.write(chunk[:available]); output.flush(); retained += min(len(chunk), available)
                    if len(chunk) > available:
                        overflow[0] = True
                        process.terminate()
            except (OSError, ValueError):
                overflow[0] = True
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
        reader = threading.Thread(target=drain, daemon=True); reader.start()
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill(); process.wait(timeout=5); code = 124
        reader.join(timeout=5)
        if reader.is_alive():
            return 124
        if process.stdout is not None:
            process.stdout.close()
        return 125 if overflow[0] else code


def run(root: Path) -> int:
    # A failed new invocation must never stage the previous invocation's result.
    # Unlink only the latest entry, including a symlink; preserve archive targets.
    latest = root / ".local/evidence/api-summary.json"
    latest.unlink(missing_ok=True)
    files, _, source_flags = source_inventory(root)
    hashes = {name: source["sha256"] for name, source in files.items()}
    git = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True)
    commit = git.stdout.strip() if git.returncode == 0 else None
    directory = root / ".local/evidence/api-runs" / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex)
    directory.mkdir(parents=True, mode=0o700)
    raw_path = directory / "output.tap"
    compose_base = ["docker", "compose", "--project-name", "governance-commons", "--env-file", str(root / ".local/runtime.env"), "-f", str(root / "deploy/compose/compose.yaml")]
    compose = [*compose_base, "run", "--rm", "--no-deps", "-T", "qualification-runner"]
    application = [*compose_base, "exec", "-T", "api"]
    readback_script = "import{readFileSync}from'node:fs';import{createHash}from'node:crypto';const names=JSON.parse(process.argv[1]);process.stdout.write(JSON.stringify(Object.fromEntries(names.map(name=>[name,createHash('sha256').update(readFileSync(name)).digest('hex')]))));"
    def matching_sources() -> bool:
        try:
            for boundary in (application, compose):
                result = subprocess.run([*boundary, "node", "--input-type=module", "-e", readback_script, json.dumps(list(hashes))], cwd=root, capture_output=True, timeout=30)
                if result.returncode != 0 or len(result.stdout) > 1024*1024 or json.loads(result.stdout) != hashes:return False
            return True
        except (OSError, subprocess.SubprocessError, ValueError):
            return False
    before = not source_flags and matching_sources()
    truncated, exit_code = [False], 1
    with raw_path.open("xb") as output:
        raw_path.chmod(0o600)
        if before:
            # Admission must precede owner writes. Preparation and API execution
            # share the original host budget; the test supervisor is unchanged.
            execution_deadline = time.monotonic()+1800
            preparation = [*compose_base, "run", "--rm", "--no-deps", "-T", "authn-test-fixture",
                           "node", "--input-type=module", "-e", API_TEST_SUPERVISOR.replace("1740000", "150000"), "--",
                           "--import", "tsx", "scripts/protected-core-test-fixture.ts", "--batch", "/state/qualification",
                           "--core-plan", "/state/plan.json"]
            try:
                exit_code = prepare_fixture(preparation, root, directory / "preparation.log", min(180, execution_deadline-time.monotonic()))
            except (OSError, subprocess.SubprocessError):
                exit_code = 1
        if before and exit_code == 0:
            command = [*compose, "node", "--input-type=module", "-e", API_TEST_SUPERVISOR, "--",
                       "--import", "tsx", "--test", "--test-concurrency=1", "--test-reporter=tap", *(name for name in hashes if FILE.fullmatch(name))]
            try:
                process = subprocess.Popen(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                def drain() -> None:
                    retained = 0
                    assert process.stdout is not None
                    while chunk := process.stdout.read1(65536):
                        available = max(0, MAX_OUTPUT - retained)
                        output.write(chunk[:available]); output.flush(); retained += min(len(chunk), available)
                        if len(chunk) > available:
                            truncated[0] = True
                reader = threading.Thread(target=drain, daemon=True); reader.start()
                try:
                    exit_code = process.wait(timeout=max(0.001, execution_deadline-time.monotonic()))
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
