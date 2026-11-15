#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Portable local launcher. Unsupported programme commands fail explicitly."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local"
COMPOSE = ["docker", "compose", "--project-name", "governance-commons", "--env-file", str(LOCAL / "runtime.env"), "-f", str(ROOT / "deploy/compose/compose.yaml")]

def run(args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, timeout=kwargs.pop("timeout", 900), **kwargs)

def capture(args, timeout=15):
    return run(args, capture_output=True, text=True, timeout=timeout).stdout.strip()

def require_local():
    override = os.environ.get("DOCKER_HOST", "")
    if override and not override.startswith(("unix://", "npipe://")):
        raise SystemExit("Refusing non-local DOCKER_HOST override; this launcher is authorized for local services only.")
    try:
        endpoint = json.loads(capture(["docker", "context", "inspect"]))[0]["Endpoints"]["docker"]["Host"]
    except Exception:
        raise SystemExit("Docker context unavailable. Start your local Docker engine and retry.")
    if not endpoint.startswith(("unix://", "npipe://")):
        raise SystemExit("Refusing non-local Docker context; this launcher is authorized for local services only.")

def doctor():
    checks = []
    def check(name, passed, detail):
        checks.append({"check": name, "passed": bool(passed), "detail": detail})
    for binary in ("docker", "python3", "git"):
        check(binary, bool(shutil.which(binary)), shutil.which(binary) or "missing")
    if not shutil.which("docker"):
        print(json.dumps({"checks": checks, "passed": False}, indent=2)); return False
    require_local()
    try:
        info = json.loads(capture(["docker", "info", "--format", "{{json .}}"], 30))
        check("docker_engine", True, info.get("ServerVersion"))
        memory = info["MemTotal"] / 1024**3
        check("docker_memory", memory >= 5.5, f"{memory:.2f} GiB; provisional core floor 5.5 GiB, measured qualification pending")
        check("docker_cpu", info["NCPU"] >= 4, f"{info['NCPU']} vCPU; provisional core floor 4")
        check("architecture", info["Architecture"] in ("aarch64", "arm64", "x86_64", "amd64"), info["Architecture"])
        check("compose", True, capture(["docker", "compose", "version", "--short"]))
    except (subprocess.SubprocessError, KeyError, ValueError) as error:
        check("docker_engine", False, type(error).__name__)
    disk = shutil.disk_usage(ROOT).free / 1024**3
    images = sorted(set(re.findall(r"^\s+image: (.+)$", (ROOT / "deploy/compose/compose.yaml").read_text(), re.MULTILINE)))
    cached = False
    try:
        capture(["docker", "image", "inspect", "--format", "{{.Id}}", *images], 30)
        cached = True
    except subprocess.SubprocessError:
        pass
    required_disk = 2.0 if cached else 8.0
    check("disk", disk >= required_disk, f"{disk:.2f} GiB free; admission budget {required_disk:.1f} GiB ({'images cached' if cached else 'images or build missing'}); measured qualification pending")
    running = []
    if (LOCAL / "runtime.env").exists():
        try:
            running = capture(COMPOSE + ["ps", "--services", "--status", "running"]).splitlines()
        except subprocess.SubprocessError:
            pass
    for port, service in ((4310, "api"), (4311, "keycloak")):
        try:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", port))
            check(f"port_{port}", True, "available")
        except OSError:
            check(f"port_{port}", service in running, "owned by active project service" if service in running else "in use by another process")
    result = {"timestamp": datetime.now(timezone.utc).isoformat(), "host": platform.system(), "checks": checks,
        "resource_qualification": "provisional floors only; full profile and benchmark qualification pending", "passed": all(c["passed"] for c in checks)}
    print(json.dumps(result, indent=2))
    LOCAL.mkdir(mode=0o700, exist_ok=True)
    (LOCAL / "doctor.json").write_text(json.dumps(result, indent=2) + "\n")
    return result["passed"]

def require_bootstrap():
    if not (LOCAL / "runtime.env").exists():
        raise SystemExit("Run ./dev bootstrap first. Credentials will be generated locally.")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", default="help", choices=["help", "doctor", "bootstrap", "up", "seed", "status", "test", "benchmark", "k8s-smoke", "backup", "restore", "export-support-bundle", "down"])
    parser.add_argument("--profile", default="core")
    parser.add_argument("--dataset", default="harbor-demo")
    parser.add_argument("--suite", default="smoke")
    parser.add_argument("--output")
    parser.add_argument("--input")
    parser.add_argument("--target")
    parser.add_argument("--redact", action="store_true")
    args = parser.parse_args()
    if args.command == "help":
        print("""Governance Commons local development
  ./dev doctor                        Verify local Docker, capacity and ports (JSON)
  ./dev bootstrap                     Generate/preserve random local secrets
  ./dev up --profile core             Build and start real core dependencies and app
  ./dev seed --dataset harbor-demo    Seed two tenants and six synthetic personas
  ./dev status                        Show project service status
  ./dev test --suite smoke            Run locally configured smoke acceptance gate
  ./dev test --suite security         Run locally configured isolation gate
  ./dev test --suite connectors       Run Python contract/source tests
  ./dev test --suite recovery         Verify repeated seed and persistent restart
  ./dev test --suite histories        Inspect a completed scan's Temporal payloads
  ./dev down                          Stop this project, preserve volumes

Full/AI profiles, complete acceptance, upgrade, benchmark, Kubernetes,
backup/restore and support bundle are required milestones. Commands fail
explicitly until their executable implementation is available; no mock pass.
Bootstrap secret retrieval: python3 scripts/runtime-credential.py steward
macOS/Linux: ./dev; Windows: run the same commands inside WSL2 with Docker.
Never use docker compose config output in public logs: it expands secrets.""")
        return
    if args.command == "bootstrap":
        run([sys.executable, "scripts/runtime-bootstrap.py"], timeout=30); return
    if args.command == "doctor":
        raise SystemExit(0 if doctor() else 1)
    if args.command in ("benchmark", "k8s-smoke", "backup", "restore", "export-support-bundle"):
        raise SystemExit(f"NOT IMPLEMENTED: {args.command}; requirement remains open. No operation performed.")
    if args.profile != "core":
        raise SystemExit(f"PROFILE NOT IMPLEMENTED: {args.profile}; full/ai-local qualification remains open.")
    require_bootstrap(); require_local()
    if args.command == "up":
        if not doctor():
            raise SystemExit("Doctor failed; correct the reported prerequisite before startup.")
        run(COMPOSE + ["config", "--quiet"], timeout=30)
        for service in ("api", "python-worker"):
            if shutil.disk_usage(ROOT).free < 2 * 1024**3:
                raise SystemExit("Build stopped: less than 2 GiB free disk. Preserve unrelated resources and recover space before retrying.")
            run(COMPOSE + ["build", service], timeout=1800, env={**os.environ, "COMPOSE_PARALLEL_LIMIT": "1"})
        run(COMPOSE + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "240", "api", "workflow-worker", "site-runner", "python-worker"], timeout=360)
        print("Core stack is ready at http://localhost:4310. Run ./dev seed --dataset harbor-demo.")
    elif args.command == "seed":
        if args.dataset != "harbor-demo":
            raise SystemExit("Only the independently authored harbor-demo dataset is implemented.")
        run(COMPOSE + ["run", "--rm", "seed"], timeout=120)
    elif args.command == "status":
        output = capture(COMPOSE + ["ps", "--all", "--format", "json"], timeout=30)
        rows = [json.loads(line) for line in output.splitlines() if line.strip()]
        print(json.dumps({"project": "governance-commons", "services": [{"service": r["Service"], "state": r["State"], "health": r.get("Health"), "exitCode": r.get("ExitCode")} for r in rows]}, indent=2))
    elif args.command == "down":
        run(COMPOSE + ["down", "--timeout", "30"], timeout=90)
        print("Project stopped. Persistent volumes and local credentials were preserved.")
    elif args.command == "test":
        script = ROOT / "scripts" / f"test-{args.suite}.sh"
        if script.exists():
            run(["sh", str(script)], timeout=900)
        elif args.suite == "connectors":
            run([sys.executable, "scripts/runtime-test-connectors.py"], timeout=300)
        elif args.suite == "recovery":
            run([sys.executable, "scripts/runtime-test-recovery.py"], timeout=600)
        elif args.suite == "histories":
            run([sys.executable, "scripts/runtime-test-histories.py"], timeout=120)
        else:
            raise SystemExit(f"TEST NOT IMPLEMENTED: {args.suite}; no gate has been claimed as passing.")

if __name__ == "__main__":
    try:
        main()
    except subprocess.TimeoutExpired:
        raise SystemExit("Command timed out; operation was not verified as successful.")
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode)
