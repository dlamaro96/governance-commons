#!/usr/bin/env python3
"""Pinned gitleaks scan of publishable worktree files and all reachable history.

SPDX-License-Identifier: Apache-2.0
"""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
PIN = json.loads((ROOT / "policies/security-tools.json").read_text())["gitleaks"]


def command(argv: list[str], timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(argv, cwd=ROOT, text=True, capture_output=True, timeout=timeout)


def install() -> Path:
    architecture = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "x64", "AMD64": "x64"}.get(platform.machine())
    target = f"{platform.system().lower()}_{architecture}"
    if target not in PIN["archives"]:
        raise ValueError(f"No verified scanner artifact for {target}; use a supported Linux/WSL2 host")
    directory = ROOT / ".local/toolchain" / f"gitleaks-{PIN['version']}-{target}"
    executable = directory / "gitleaks"
    provenance = directory / "provenance.json"
    if executable.exists() and provenance.exists():
        recorded = json.loads(provenance.read_text())
        if recorded.get("archive_sha256") == PIN["archives"][target] and hashlib.sha256(executable.read_bytes()).hexdigest() == recorded.get("binary_sha256"):
            return executable
        raise ValueError("Cached scanner differs from verified provenance; inspect before replacing it")
    base = f"https://github.com/gitleaks/gitleaks/releases/download/v{PIN['version']}/"
    checksums = urlopen(base + f"gitleaks_{PIN['version']}_checksums.txt", timeout=45).read()
    if hashlib.sha256(checksums).hexdigest() != PIN["checksums_sha256"]:
        raise ValueError("Official checksum file does not match the pinned digest")
    archive_name = f"gitleaks_{PIN['version']}_{target}.tar.gz"
    checksum_lines = {line.split()[-1].lstrip("*"): line.split()[0] for line in checksums.decode().splitlines()}
    if checksum_lines.get(archive_name) != PIN["archives"][target]:
        raise ValueError("Pinned archive digest disagrees with official checksum file")
    archive = urlopen(base + archive_name, timeout=60).read()
    if hashlib.sha256(archive).hexdigest() != PIN["archives"][target]:
        raise ValueError("Scanner archive checksum mismatch")
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        member = bundle.getmember("gitleaks")
        if not member.isfile() or member.size > 64 * 1024 * 1024:
            raise ValueError("Unsafe scanner archive member")
        binary = bundle.extractfile(member).read()
        license_text = bundle.extractfile("LICENSE").read() if "LICENSE" in bundle.getnames() else None
    directory.mkdir(parents=True, exist_ok=True)
    executable.write_bytes(binary)
    executable.chmod(0o700)
    if license_text:
        (directory / "LICENSE").write_bytes(license_text)
    provenance.write_text(json.dumps({"version": PIN["version"], "url": base + archive_name,
                         "archive_sha256": PIN["archives"][target], "binary_sha256": hashlib.sha256(binary).hexdigest()}, indent=2) + "\n")
    return executable


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install", action="store_true", help="Download only the explicitly pinned, checksum-verified scanner if absent")
    parser.add_argument("--output", type=Path, default=ROOT / "docs/security/secret-scan.json")
    args = parser.parse_args()
    try:
        if not args.install:
            parser.error("Use --install to authorize retrieval of the pinned public scanner artifact")
        executable = install()
        actual_version = command([str(executable), "version"]).stdout.strip()
        if actual_version != PIN["version"]:
            raise ValueError("Scanner version differs from the pin")
        listing = command(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"])
        if listing.returncode:
            raise ValueError("Could not enumerate publishable files")
        files = sorted(set(filter(None, listing.stdout.split("\0"))))
        fingerprint = hashlib.sha256()
        count = 0
        with tempfile.TemporaryDirectory(prefix="governance-public-scan-") as temporary:
            temp = Path(temporary)
            snapshot = temp / "source"
            snapshot.mkdir()
            for name in files:
                source = ROOT / name
                if source.resolve() == args.output.resolve():
                    continue
                if source.is_symlink():
                    raise ValueError(f"Publication scan requires explicit review of symlink: {name}")
                if not source.is_file():
                    continue
                if source.stat().st_size > 64 * 1024 * 1024:
                    raise ValueError(f"File exceeds reviewed scan bound: {name}")
                data = source.read_bytes()
                fingerprint.update(name.encode() + b"\0" + hashlib.sha256(data).digest())
                destination = snapshot / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
                count += 1
            results = []
            targets = [("publishable_worktree", ["dir", str(snapshot)]), ("reachable_git_history", ["git", "--log-opts=--all", str(ROOT)])]
            for label, options in targets:
                output = temp / f"{label}.json"
                argv = [str(executable), *options, "--redact=100", "--no-banner", "--report-format=json", f"--report-path={output}", "--exit-code=1"]
                result = command(argv)
                if not output.is_file():
                    raise ValueError(f"{label} scanner produced no report; no successful scan claimed")
                findings = json.loads(output.read_text())
                if not isinstance(findings, list):
                    raise ValueError(f"{label} scanner report has an invalid shape")
                if result.returncode not in {0, 1} or (result.returncode == 1 and not findings):
                    raise ValueError(f"{label} scanner failed; no successful scan claimed (exit {result.returncode})")
                safe_findings = [{key: finding.get(key) for key in ("RuleID", "File", "StartLine", "EndLine", "Commit", "Fingerprint")} for finding in findings]
                results.append({"scope": label, "outcome": "FAIL" if findings else "PASS", "exit_code": result.returncode,
                                "finding_count": len(findings), "findings": safe_findings})
        report = {"schema_version": 1, "tool": "gitleaks", "tool_version": actual_version,
                  "tool_pin": "policies/security-tools.json", "command": "python3 policies/scan_secrets.py --install" + (" --output " + str(args.output.relative_to(ROOT)) if args.output.is_relative_to(ROOT) and args.output != ROOT / "docs/security/secret-scan.json" else ""),
                  "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
                  "commit": command(["git", "rev-parse", "HEAD"]).stdout.strip() or None,
                  "working_tree_manifest_sha256": fingerprint.hexdigest(), "publishable_files_scanned": count,
                  "worktree_dirty": bool(command(["git", "status", "--porcelain"]).stdout),
                  "platform": {"system": platform.system(), "architecture": platform.machine()},
                  "outcome": "PASS" if all(result["outcome"] == "PASS" for result in results) else "FAIL", "results": results,
                  "limitations": ["Detection by pinned gitleaks rules is not proof that every possible secret is absent.",
                                  "Scans publishable files, excluding ignored runtime secrets/dependencies and this newly generated safe summary; history covers every reachable revision.",
                                  "The source snapshot hash identifies uncommitted files tested; a supported release must rerun at its exact final commit.",
                                  "Tool checksum verification is against pinned official release metadata; no independent signing/provenance claim."]}
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"outcome": report["outcome"], "tool_version": actual_version, "files": count,
                          "results": [{key: result[key] for key in ("scope", "outcome", "finding_count")} for result in results]}, indent=2))
        return 0 if report["outcome"] == "PASS" else 1
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        failure = {"schema_version": 1, "outcome": "FAIL", "tool": "gitleaks", "tool_version": PIN["version"], "reason": str(error), "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(), "qualification_complete": False}
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(failure, indent=2) + "\n")
        except OSError:
            pass
        print(json.dumps(failure))
        return 1


if __name__ == "__main__":
    sys.exit(main())
