#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Portable local launcher. Unsupported programme commands fail explicitly."""
import argparse
import hashlib
import selectors
import time
import uuid
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local"
# Provisional floor: image caching does not eliminate application rebuild space.
BUILD_DISK_FLOOR_BYTES = 4 * 1024**3
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
    free_bytes = shutil.disk_usage(ROOT).free
    disk = free_bytes / 1024**3
    images = sorted(set(re.findall(r"^\s+image: (.+)$", (ROOT / "deploy/compose/compose.yaml").read_text(), re.MULTILINE)))
    cached = False
    try:
        capture(["docker", "image", "inspect", "--format", "{{.Id}}", *images], 30)
        cached = True
    except subprocess.SubprocessError:
        pass
    required_bytes = BUILD_DISK_FLOOR_BYTES if cached else 8 * 1024**3
    required_disk = required_bytes / 1024**3
    check("disk", free_bytes >= required_bytes, f"{disk:.2f} GiB free; admission budget {required_disk:.1f} GiB ({'images cached' if cached else 'images or build missing'}); measured qualification pending")
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

def require_build_disk(service):
    free = shutil.disk_usage(ROOT).free
    if free < BUILD_DISK_FLOOR_BYTES:
        raise SystemExit(f"Build stopped for {service}: {free / 1024**3:.2f} GiB free; at least 4 GiB is required before each application build. Preserve unrelated resources and recover space before retrying.")


# These checks attest selected shipped source bytes and entry-independent runtime
# imports only. They do not certify the complete installed dependency closure.
INTEGRITY_MAX_FILES = 4096
INTEGRITY_MAX_FILE_BYTES = 16 * 1024**2
INTEGRITY_MAX_SOURCE_BYTES = 128 * 1024**2
INTEGRITY_MAX_OUTPUT = 4 * 1024**2
INTEGRITY_PROFILES = {
    'api': {'image': 'governance-commons:dev', 'root': '/app', 'user': '1000:1000',
            'roots': ('apps', 'packages'), 'files': ('package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml')},
    'python-worker': {'image': 'governance-commons-python:dev', 'root': '/worker', 'user': '10001:10001',
                      'roots': ('python/governance_workers', 'python/tests'), 'files': ('python/pyproject.toml', 'python/uv.lock')},
}
INTEGRITY_CONTROLS = ('Dockerfile', 'python/Dockerfile', '.dockerignore', 'deploy/compose/compose.yaml')
INTEGRITY_EXCLUDED = frozenset(('node_modules', 'dist', '__pycache__', '.venv'))


def integrity_require(value):
    if not value:
        raise SystemExit('Application image integrity check failed; startup stopped before migration. No application images or volumes were removed.')


def integrity_command(args, data=b'', timeout=30):
    """Bound both output streams and the original wall time; never echo stderr."""
    integrity_require(os.name == 'posix' and len(data) <= INTEGRITY_MAX_OUTPUT)
    process = None
    try:
        with selectors.DefaultSelector() as selector:
            process = subprocess.Popen(args, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, start_new_session=True)
            output, errors, offset = bytearray(), bytearray(), 0
            for stream, kind in ((process.stdout, 'out'), (process.stderr, 'err')):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, kind)
            if data:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, 'in')
            else:
                process.stdin.close()
            end = time.monotonic() + timeout
            while selector.get_map():
                remaining = end-time.monotonic()
                integrity_require(remaining > 0)
                for key, _ in selector.select(min(remaining, 0.1)):
                    if key.data == 'in':
                        try:
                            offset += os.write(key.fd, data[offset:offset+65536])
                        except BrokenPipeError:
                            offset = len(data)
                        if offset == len(data):
                            selector.unregister(key.fileobj); key.fileobj.close()
                    else:
                        chunk = os.read(key.fd, 65536)
                        if not chunk:
                            selector.unregister(key.fileobj); key.fileobj.close()
                        else:
                            target = output if key.data == 'out' else errors
                            integrity_require(len(output)+len(errors)+len(chunk) <= INTEGRITY_MAX_OUTPUT)
                            target.extend(chunk)
            code = process.wait(timeout=max(0.001, end-time.monotonic()))
            integrity_require(code == 0)
            return bytes(output)
    except (OSError, subprocess.SubprocessError, ValueError):
        integrity_require(False)
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream and not stream.closed:
                    stream.close()


def integrity_source_snapshot():
    """Include untracked shipped files; ignore only known generated directories."""
    names, profiles = set(INTEGRITY_CONTROLS), {}
    deadline_at = time.monotonic() + 30
    for service, profile in INTEGRITY_PROFILES.items():
        selected = set(profile['files'])
        for prefix in profile['roots']:
            directory = ROOT/prefix
            integrity_require(directory.is_dir() and not directory.is_symlink())
            for current, dirs, files in os.walk(directory, followlinks=False, onerror=lambda _error: integrity_require(False)):
                integrity_require(time.monotonic() < deadline_at)
                integrity_require(not set(dirs).intersection(('.local', '.git', '.aws', '.codex')))
                dirs[:] = sorted(name for name in dirs if name not in INTEGRITY_EXCLUDED)
                integrity_require(all(not (Path(current)/name).is_symlink() for name in dirs))
                for name in files:
                    relative = (Path(current)/name).relative_to(ROOT).as_posix()
                    integrity_require(not name.startswith('.env') and re.fullmatch(r'[A-Za-z0-9_./-]{1,512}', relative))
                    selected.add(relative)
                    integrity_require(len(names | selected) <= INTEGRITY_MAX_FILES)
        profiles[service] = sorted(selected)
        names.update(selected)
    integrity_require(len(names) <= INTEGRITY_MAX_FILES)
    sources, total = {}, 0
    for name in sorted(names):
        path = ROOT/name
        integrity_require(time.monotonic() < deadline_at and stat.S_ISREG(path.lstat().st_mode))
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
            before = os.fstat(stream.fileno())
            integrity_require(not path.is_symlink() and stat.S_ISREG(before.st_mode) and before.st_size <= INTEGRITY_MAX_FILE_BYTES)
            total += before.st_size
            integrity_require(total <= INTEGRITY_MAX_SOURCE_BYTES)
            body = stream.read(INTEGRITY_MAX_FILE_BYTES+1)
            after = os.fstat(stream.fileno())
            integrity_require(len(body) == before.st_size and (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) ==
                              (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns))
            sources[name] = hashlib.sha256(body).hexdigest()
    return {'sources': sources, 'profiles': profiles}


API_INTEGRITY_READER = r"""import fs from 'node:fs';import crypto from 'node:crypto';
try {
 const paths=JSON.parse(fs.readFileSync(0,'utf8'));let total=0;
 if(!Array.isArray(paths)||paths.length>4096)throw 0;
 const sources=paths.map(path=>{if(typeof path!=='string'||!/^[A-Za-z0-9_./-]{1,512}$/.test(path)||path.split('/').some(p=>!p||p==='.'||p==='..'))throw 0;
 let file='/app';for(const part of path.split('/')){file+='/'+part;if(fs.lstatSync(file).isSymbolicLink())throw 0;}
 const stat=fs.statSync(file);if(!stat.isFile()||stat.size>16777216||(total+=stat.size)>134217728)throw 0;
 const bytes=fs.readFileSync(file);if(path.split('/').at(-1)==='package.json'){const p=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));if(!p||typeof p!=='object'||Array.isArray(p))throw 0;}
 return {path,sha256:crypto.createHash('sha256').update(bytes).digest('hex')};});
 for(const name of ['fastify','pg','kysely','@temporalio/client'])await import(name);
 process.stdout.write(JSON.stringify({formatVersion:1,profile:'api',sources,checks:['package-manifests','selected-runtime-imports']}));
} catch {process.stderr.write('IMAGE_INTEGRITY_REJECTED\n');process.exitCode=1;}
"""
PYTHON_INTEGRITY_READER = r"""import ast,hashlib,json,pathlib,sys,tomllib
try:
 paths=json.load(sys.stdin);total=0;sources=[]
 if type(paths) is not list or len(paths)>4096:raise ValueError()
 for name in paths:
  if type(name) is not str or len(name)>512 or any(p in ('','.','..') for p in name.split('/')):raise ValueError()
  path=pathlib.Path('/worker')
  for part in name.split('/'):
   path=path/part
   if path.is_symlink():raise ValueError()
  info=path.stat();total+=info.st_size
  if not path.is_file() or info.st_size>16777216 or total>134217728:raise ValueError()
  body=path.read_bytes()
  if name.endswith('.py'):ast.parse(body,filename=name)
  if name in ('pyproject.toml','uv.lock'):tomllib.loads(body.decode('utf-8'))
  sources.append({'path':name,'sha256':hashlib.sha256(body).hexdigest()})
 import psycopg
 sys.stdout.write(json.dumps({'formatVersion':1,'profile':'python-worker','sources':sources,'checks':['python-parse','project-lock-parse','psycopg-import']}))
except BaseException:
 sys.stderr.write('IMAGE_INTEGRITY_REJECTED\n');sys.exit(1)
"""


def integrity_image_id(service):
    value = integrity_command(['docker', 'image', 'inspect', '--format', '{{.Id}}', INTEGRITY_PROFILES[service]['image']]).decode('ascii').strip()
    integrity_require(re.fullmatch(r'sha256:[a-f0-9]{64}', value))
    return value


def integrity_cleanup(name, token):
    query = ['docker', 'container', 'ls', '-aq', '--filter', 'label=org.governance-commons.integrity='+token, '--filter', 'name=^/'+name+'$']
    identifiers = integrity_command(query, timeout=10).decode('ascii').splitlines()
    integrity_require(len(identifiers) <= 1 and all(re.fullmatch(r'[a-f0-9]{12,64}', value) for value in identifiers))
    if identifiers:
        integrity_command(['docker', 'rm', '-f', identifiers[0]], timeout=10)
        integrity_require(not integrity_command(query, timeout=10).strip())


def verify_built_image(service, snapshot):
    profile = INTEGRITY_PROFILES[service]
    selected = integrity_image_id(service)
    names = snapshot['profiles'][service]
    expected = [{'path': name.removeprefix('python/') if service == 'python-worker' else name,
                 'sha256': snapshot['sources'][name]} for name in names]
    token = uuid.uuid4().hex
    name = 'gc-image-integrity-'+token
    checks = ['package-manifests','selected-runtime-imports'] if service == 'api' else ['python-parse','project-lock-parse','psycopg-import']
    command = ['docker','run','--rm','--pull','never','--name',name,'--label','org.governance-commons.integrity='+token,
               '--network','none','--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true',
               '--memory','384m','--memory-swap','384m','--pids-limit','64','--log-driver','none','--user',profile['user'],
               '--workdir',profile['root'],'-i']
    if service == 'api':
        command += ['--env','TSX_DISABLE_CACHE=1','--env','NODE_OPTIONS=--max-old-space-size=256','--entrypoint','node',selected,'--import','tsx','--input-type=module','-e',API_INTEGRITY_READER]
    else:
        command += ['--env','PYTHONDONTWRITEBYTECODE=1','--entrypoint','/worker/.venv/bin/python',selected,'-B','-c',PYTHON_INTEGRITY_READER]
    try:
        raw = integrity_command(command, json.dumps([row['path'] for row in expected]).encode(), timeout=60)
        def exact_object(pairs):
            result = {}
            for key, value in pairs:
                integrity_require(key not in result)
                result[key] = value
            return result
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=exact_object)
        integrity_require(type(value) is dict and type(value.get('formatVersion')) is int and
                          value == {'formatVersion':1,'profile':service,'sources':expected,'checks':checks})
        integrity_require(integrity_image_id(service) == selected)
        return selected
    except (UnicodeError, ValueError, OSError):
        integrity_require(False)
    finally:
        integrity_cleanup(name, token)


def verify_build_snapshot(snapshot, images):
    integrity_require(integrity_source_snapshot() == snapshot)
    integrity_require(set(images) == set(INTEGRITY_PROFILES))
    for service, selected in images.items():
        integrity_require(integrity_image_id(service) == selected)


def require_bootstrap():
    if not (LOCAL / "runtime.env").exists():
        raise SystemExit("Run ./dev bootstrap first. Credentials will be generated locally.")

def authentication_bootstrap():
    """Validate private executor prerequisites before any startup mutation."""
    try:
        path = LOCAL / "bootstrap.json"
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 65536:
            raise ValueError("Invalid private bootstrap")
        values = json.loads(path.read_text())
        for key in ("GC_AUTHN_LOGIN_PASSWORD", "GC_AUTHN_API_PASSWORD"):
            if not isinstance(values.get(key), str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", values[key]):
                raise ValueError("Missing generated executor credential")
        return values
    except (OSError, ValueError, AttributeError):
        raise SystemExit("Private authentication credentials are missing or invalid. Run ./dev bootstrap before startup; existing credentials are preserved.")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", default="help", choices=["help", "doctor", "bootstrap", "up", "seed", "status", "test", "authn-install", "benchmark", "k8s-smoke", "backup", "restore", "export-support-bundle", "down"])
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
  ./dev seed --dataset harbor-demo    Seed two tenants, six personas and typed domain trees
  ./dev status                        Show project service status
  ./dev test --suite smoke            Run locally configured smoke acceptance gate
  ./dev test --suite security         Run locally configured isolation gate
  ./dev test --suite sast             Run pinned local CodeQL; no Docker or token required
  ./dev test --suite model-upgrade    Verify receipt upgrade in isolated PostgreSQL
  ./dev test --suite asset-type-upgrade Verify inherited-type upgrade in isolated PostgreSQL
  ./dev test --suite type-migration-upgrade Verify complete typed receipts and principal locking
  ./dev test --suite relations-upgrade Verify asserted relation storage and concurrency
  ./dev test --suite relation-participation-upgrade Verify complete graph operations and required participation
  ./dev test --suite business-domains-upgrade Verify typed domain storage, hierarchy, placement and concurrency
  ./dev test --suite business-domain-seed Verify domain seed recovery, provenance and repeatability
  ./dev test --suite authority-authn-foundation Verify inactive authentication through native PostgreSQL roles
  ./dev test --suite glossary-population-repaired-upgrade Verify isolated-governance-repaired-sql018
  ./dev test --suite quality-repaired-upgrade Verify isolated-governance-repaired-sql019
  ./dev test --suite lineage-repaired-upgrade Verify isolated-governance-repaired-sql020
  ./dev test --suite classification-repaired-upgrade Verify isolated-governance-repaired-sql021
  ./dev test --suite reference-repaired-upgrade Verify isolated-governance-repaired-sql022
  ./dev test --suite reference-quality-repaired-upgrade Verify isolated-governance-repaired-sql023
  ./dev test --suite reference-structure-repaired-upgrade Verify isolated-governance-repaired-sql024
  ./dev test --suite relation-candidate-original Verify isolated-relation-candidate-original
  ./dev test --suite relation-candidate-current Verify isolated-relation-candidate-current
  ./dev test --suite authority-foundation Verify historical SQL001–013 authority foundation
  ./dev test --suite authority-read-original Verify explicit SQL013-to031 authority read upgrade
  ./dev test --suite authority-read-current Verify populated SQL030-to031 authority read upgrade
  ./dev test --suite protected-authn  Verify isolated real OIDC and protected session lifecycle
  ./dev test --suite source-connectors-upgrade Verify source storage upgrade and native tenant isolation
  ./dev test --suite postgres-targets Verify isolated configurable PostgreSQL TLS and metadata boundaries
  ./dev test --suite approvals-upgrade Verify approval storage, upgrade and concurrent decisions
  ./dev test --suite glossary-upgrade Verify approved term publication and graph transaction integrity
  ./dev test --suite relation-scope-upgrade Verify complete graph scope on populated catalogs
  ./dev test --suite glossary-population-upgrade Verify multi-policy publication on populated catalogs
  ./dev test --suite quality-upgrade  Verify completeness storage, upgrade and current authorization
  ./dev test --suite quality-worker   Verify completeness execution against the local synthetic source
  ./dev test --suite lineage-upgrade Verify PostgreSQL lineage storage, generation fencing and upgrade
  ./dev test --suite lineage-worker  Verify real PostgreSQL dependency extraction and owned fixture cleanup
  ./dev test --suite classification-upgrade Verify immutable suggestions, review decisions and label history
  ./dev test --suite reference-upgrade Verify governed code-list publication, effective dates and immutable downloads
  ./dev test --suite reference-quality-upgrade Verify immutable reference-backed quality storage and authority
  ./dev test --suite reference-quality-worker Verify byte-exact allowed values against the local PostgreSQL source
  ./dev test --suite reference-structure-upgrade Verify temporal hierarchies, crosswalks and concurrent authority
  ./dev test --suite reference-import Verify bounded code-row import against current-schema PostgreSQL
  ./dev test --suite uniqueness-upgrade Verify uniqueness storage, immutable counts and retained quality families
  ./dev test --suite uniqueness-worker Verify exact duplicate groups against the local PostgreSQL source
  ./dev test --suite range-upgrade Verify exact integer-range storage and retained quality families
  ./dev test --suite range-worker Verify inclusive integer bounds against the local PostgreSQL source
  ./dev test --suite monitoring-upgrade Verify scheduled quality, deduplicated issues and verified recovery
  ./dev test --suite freshness-upgrade Verify exact timestamp age storage and retained quality families
  ./dev test --suite freshness-scheduling-upgrade Verify clock-bounded scheduled freshness and retained evidence
  ./dev test --suite freshness-worker Verify timestamp aggregates against the local PostgreSQL source
  ./dev test --suite volume-upgrade Verify exact table volume and retained quality evidence
  ./dev test --suite volume-worker Verify table counts against the local PostgreSQL source
  ./dev authn-install --input FILE    Apply one private, typed inactive installation manifest
  ./dev test --suite relation-preparation-expiry Verify the original fifteen-minute lease and committed retries
  ./dev test --suite connectors       Run Python contract/source tests
  ./dev test --suite recovery         Verify repeated seed and persistent restart
  ./dev test --suite histories        Inspect a completed scan's Temporal payloads
  ./dev test --suite object-store     Verify authenticated S3 and a synthetic roundtrip
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
    if args.command == "test" and args.suite == "sast":
        command = [sys.executable, "policies/sast.py", "run"]
        if args.output:
            command.extend(["--output", args.output])
        run(command, timeout=5500); return
    if args.command == "test" and args.suite == "protected-authn":
        # This fresh profile owns its credentials and never depends on core bootstrap.
        require_local()
        run([sys.executable, "scripts/runtime-test-protected-authn.py"], timeout=1800); return
    if args.command == "test" and args.suite == "source-connectors-upgrade":
        require_local()
        run([sys.executable, "scripts/runtime-test-source-connectors-upgrade.py"], timeout=900); return
    if args.command == "test" and args.suite == "glossary-upgrade":
        require_local()
        run([sys.executable, "scripts/runtime-test-glossary-upgrade.py"], timeout=900); return
    if args.command == "test" and args.suite == "glossary-population-upgrade":
        require_local()
        run([sys.executable, "scripts/runtime-test-glossary-population-upgrade.py"], timeout=1500); return
    if args.command == "test" and args.suite == "volume-upgrade":
        require_local()
        run([sys.executable, "scripts/runtime-test-quality-volume-upgrade.py", "--run-local"], timeout=900); return
    if args.command == "test" and args.suite == "freshness-scheduling-upgrade":
        require_local()
        run([sys.executable, "scripts/runtime-test-quality-freshness-scheduling-upgrade.py", "--run-local"], timeout=900); return
    if args.command == "test" and args.suite == "freshness-upgrade":
        require_local()
        run([sys.executable, "scripts/runtime-test-quality-freshness-upgrade.py", "--run-local"], timeout=900); return
    if args.command == "test" and args.suite == "monitoring-upgrade":
        require_local()
        run([sys.executable, "scripts/runtime-test-quality-monitoring-upgrade.py", "--run-local"], timeout=900); return
    if args.command == "test" and args.suite == "range-upgrade":
        require_local()
        run([sys.executable, "scripts/runtime-test-quality-range-upgrade.py", "--run-local"], timeout=900); return
    if args.command == "test" and args.suite == "uniqueness-upgrade":
        require_local()
        run([sys.executable, "scripts/runtime-test-quality-uniqueness-upgrade.py", "--run-local"], timeout=900); return
    if args.command == "test" and args.suite == "reference-import":
        require_local()
        run([sys.executable, "scripts/runtime-test-reference-import.py", "--run-local"], timeout=900); return
    if args.command == "test" and args.suite == "reference-structure-upgrade":
        require_local()
        run([sys.executable, "scripts/runtime-test-reference-structure-upgrade.py"], timeout=3000); return
    if args.command == "test" and args.suite == "reference-quality-upgrade":
        require_local()
        run([sys.executable, "scripts/runtime-test-reference-quality-upgrade.py"], timeout=2700); return
    if args.command == "test" and args.suite == "reference-upgrade":
        require_local()
        run([sys.executable, "scripts/runtime-test-reference-upgrade.py"], timeout=2400); return
    if args.command == "test" and args.suite == "classification-upgrade":
        require_local()
        run([sys.executable, "scripts/runtime-test-classification-upgrade.py"], timeout=2100); return
    if args.command == "test" and args.suite == "lineage-upgrade":
        require_local()
        run([sys.executable, "scripts/runtime-test-lineage-upgrade.py"], timeout=1800); return
    if args.command == "test" and args.suite == "quality-upgrade":
        require_local()
        run([sys.executable, "scripts/runtime-test-quality-upgrade.py"], timeout=1800); return
    if args.command == "test" and args.suite == "relation-scope-upgrade":
        require_local()
        run([sys.executable, "scripts/runtime-test-relation-scope-upgrade.py"], timeout=1200); return
    if args.command == "test" and args.suite == "approvals-upgrade":
        require_local()
        run([sys.executable, "scripts/runtime-test-approvals-upgrade.py"], timeout=900); return
    if args.command == "test" and args.suite == "postgres-targets":
        require_local()
        run([sys.executable, "scripts/runtime-test-postgres-targets.py"], timeout=480); return
    if args.command == "test" and args.suite == "authority-read-original":
        require_local()
        run([sys.executable, "scripts/runtime-test-authority-read-upgrade.py", "--run-local", "--scope", "original"], timeout=1800); return
    if args.command == "test" and args.suite == "authority-read-current":
        require_local()
        run([sys.executable, "scripts/runtime-test-authority-read-upgrade.py", "--run-local", "--scope", "current"], timeout=1800); return
    if args.command == "test" and args.suite == "authority-foundation":
        require_local()
        run([sys.executable, "scripts/runtime-test-authority-foundation.py"], timeout=1800); return
    if args.command == "test" and args.suite == "glossary-population-repaired-upgrade":
        require_local()
        run([sys.executable, 'scripts/runtime-test-governance-repaired-upgrade.py', '--run-local', '--through', '018'], timeout=1500); return
    if args.command == "test" and args.suite == "quality-repaired-upgrade":
        require_local()
        run([sys.executable, 'scripts/runtime-test-governance-repaired-upgrade.py', '--run-local', '--through', '019'], timeout=1800); return
    if args.command == "test" and args.suite == "lineage-repaired-upgrade":
        require_local()
        run([sys.executable, 'scripts/runtime-test-governance-repaired-upgrade.py', '--run-local', '--through', '020'], timeout=1800); return
    if args.command == "test" and args.suite == "classification-repaired-upgrade":
        require_local()
        run([sys.executable, 'scripts/runtime-test-governance-repaired-upgrade.py', '--run-local', '--through', '021'], timeout=2100); return
    if args.command == "test" and args.suite == "reference-repaired-upgrade":
        require_local()
        run([sys.executable, 'scripts/runtime-test-governance-repaired-upgrade.py', '--run-local', '--through', '022'], timeout=2400); return
    if args.command == "test" and args.suite == "reference-quality-repaired-upgrade":
        require_local()
        run([sys.executable, 'scripts/runtime-test-governance-repaired-upgrade.py', '--run-local', '--through', '023'], timeout=2700); return
    if args.command == "test" and args.suite == "reference-structure-repaired-upgrade":
        require_local()
        run([sys.executable, 'scripts/runtime-test-governance-repaired-upgrade.py', '--run-local', '--through', '024'], timeout=3000); return
    if args.command == "test" and args.suite == "relation-candidate-original":
        require_local()
        run([sys.executable, 'scripts/runtime-test-relation-candidate-upgrade.py', '--run-local', '--scope', 'original'], timeout=900); return
    if args.command == "test" and args.suite == "relation-candidate-current":
        require_local()
        run([sys.executable, 'scripts/runtime-test-relation-candidate-upgrade.py', '--run-local', '--scope', 'current'], timeout=900); return
    require_bootstrap(); require_local()
    if args.command == "up":
        authentication_bootstrap()
        if not doctor():
            raise SystemExit("Doctor failed; correct the reported prerequisite before startup.")
        run(COMPOSE + ["config", "--quiet"], timeout=30)
        integrity_snapshot = integrity_source_snapshot()
        checked_images = {}
        for service in ("api", "python-worker"):
            require_build_disk(service)
            run(COMPOSE + ["build", service], timeout=1800, env={**os.environ, "COMPOSE_PARALLEL_LIMIT": "1"})
            checked_images[service] = verify_built_image(service, integrity_snapshot)
        verify_build_snapshot(integrity_snapshot, checked_images)
        run(COMPOSE + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "120", "postgres"], timeout=180)
        try:
            run([sys.executable, "scripts/runtime-authentication-roles.py", "prepare"], timeout=90)
            run(COMPOSE + ["up", "--no-build", "--no-deps", "--force-recreate",
                "--abort-on-container-exit", "--exit-code-from", "migrate", "migrate"], timeout=180)
        finally:
            # Remove the SET-only transfer grant even when migration fails.
            run([sys.executable, "scripts/runtime-authentication-roles.py", "finish"], timeout=90)
        run([sys.executable, "scripts/runtime-authentication-roles.py", "executors"], timeout=90)
        run(COMPOSE + ["up", "-d", "--no-build", "--wait", "--wait-timeout", "240", "api", "workflow-worker", "site-runner", "python-worker"], timeout=360)
        run([sys.executable, "scripts/runtime-test-object-store.py", "--readiness"], timeout=60)
        print("Core stack is ready at http://localhost:4310. Run ./dev seed --dataset harbor-demo.")
    elif args.command == "authn-install":
        if not args.input:
            raise SystemExit('A private installation manifest is required: --input FILE')
        path = Path(args.input)
        metadata = path.lstat()
        if not path.is_file() or path.is_symlink() or metadata.st_mode & 0o077 or metadata.st_size > 65536:
            raise SystemExit('Manifest must be a private regular file (0600), at most 64KiB.')
        with path.open('rb') as stream:
            manifest = stream.read(65537)
        if len(manifest) > 65536:
            raise SystemExit('Installation manifest exceeds its 64KiB limit.')
        run(COMPOSE + ['run', '--rm', '--no-deps', '-T', 'migrate', 'node', '--import', 'tsx',
            'scripts/authentication-install.ts', '--stdin'], input=manifest, timeout=60)
    elif args.command == "seed":
        if args.dataset != "harbor-demo":
            raise SystemExit("Only the independently authored harbor-demo dataset is implemented.")
        run([sys.executable, "scripts/runtime-install-quality-fixture.py", "--run-core"], timeout=60)
        run([sys.executable, "scripts/runtime-install-quality-fixture.py", "--run-core", "--reference"], timeout=60)
        run([sys.executable, "scripts/runtime-install-quality-fixture.py", "--run-core", "--uniqueness"], timeout=60)
        run([sys.executable, "scripts/runtime-install-quality-fixture.py", "--run-core", "--range"], timeout=60)
        run([sys.executable, "scripts/runtime-volume-fixture.py", "--run-core", "--step", "prepare"], timeout=60)
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
            run(["sh", str(script)], timeout=2100 if args.suite == "security" else 900)
        elif args.suite == "connectors":
            run([sys.executable, "scripts/runtime-test-connectors.py"], timeout=300)
        elif args.suite == "lineage-worker":
            run([sys.executable, "python/tests/test_postgres_lineage_conformance.py", "--run-core"], timeout=720)
        elif args.suite == "volume-worker":
            run([sys.executable, "scripts/runtime-test-volume-quality-worker.py", "--run-local"], timeout=900)
        elif args.suite == "freshness-worker":
            run([sys.executable, "scripts/runtime-test-freshness-quality-worker.py", "--run-local"], timeout=900)
        elif args.suite == "range-worker":
            run([sys.executable, "scripts/runtime-test-range-quality-worker.py", "--run-local"], timeout=900)
        elif args.suite == "uniqueness-worker":
            run([sys.executable, "scripts/runtime-test-uniqueness-quality-worker.py", "--run-local"], timeout=900)
        elif args.suite == "reference-quality-worker":
            run([sys.executable, "scripts/runtime-test-reference-quality-worker.py", "--run-local"], timeout=480)
        elif args.suite == "quality-worker":
            run([sys.executable, "scripts/runtime-test-quality-worker.py", "--run-local"], timeout=360)
        elif args.suite == "recovery":
            run([sys.executable, "scripts/runtime-test-recovery.py"], timeout=600)
        elif args.suite == "object-store":
            run([sys.executable, "scripts/runtime-test-object-store.py"], timeout=120)
        elif args.suite == "model-upgrade":
            run([sys.executable, "scripts/runtime-test-model-upgrade.py"], timeout=300)
        elif args.suite == "asset-type-upgrade":
            run([sys.executable, "scripts/runtime-test-asset-type-upgrade.py"], timeout=300)
        elif args.suite == "relations-upgrade":
            run([sys.executable, "scripts/runtime-test-relations-upgrade.py"], timeout=900)
        elif args.suite == "relation-participation-upgrade":
            run([sys.executable, "scripts/runtime-test-relation-participation-upgrade.py"], timeout=900)
        elif args.suite == "business-domains-upgrade":
            run([sys.executable, "scripts/runtime-test-business-domains-upgrade.py"], timeout=900)
        elif args.suite == "business-domain-seed":
            run([sys.executable, "scripts/runtime-test-business-domain-seed.py", "--run-core"], timeout=900)
        elif args.suite == "authority-authn-foundation":
            run([sys.executable, "scripts/runtime-test-authority-authn-foundation.py"], timeout=900)
        elif args.suite == "relation-preparation-expiry":
            # The test observes the original database deadline; it never shortens
            # the lease. Its own 22-minute bound expires before this outer bound.
            run(COMPOSE + ["exec", "-T", "api", "node", "--import", "tsx", "--test",
                "--test-concurrency=1", "--test-reporter=tap",
                "tests/qualification/relation-preparation-expiry.test.ts"], timeout=1380)
        elif args.suite == "type-migration-upgrade":
            run([sys.executable, "scripts/runtime-test-type-migration-upgrade.py"], timeout=300)
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
