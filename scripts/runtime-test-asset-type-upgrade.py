#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Qualify SQL006 and runtime storage guards in a disposable local PostgreSQL."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import traceback
import uuid

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local/evidence"
REPORT = LOCAL / "asset-type-upgrade.json"
DIAGNOSTIC = LOCAL / "asset-type-upgrade-private.log"
MIGRATIONS = ROOT / "packages/db/migrations"
NAMES = ["001_foundation.sql", "002_audit_envelopes.sql", "003_governance_models.sql",
         "004_model_migrations.sql", "005_model_migration_integrity.sql", "006_inherited_asset_types.sql"]
TEST = ROOT / "tests/integration/asset-type-storage.test.ts"
TENANT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
ACTOR = "10000000-0000-4000-8000-000000000001"
ASSET = "30000000-0000-4000-8000-000000000001"
MODEL = "synthetic_pre006_model"
OWNER = "gc_asset_upgrade_owner"
DATABASE = "asset_type_upgrade"


def private_log(text):
    descriptor = os.open(DIAGNOSTIC, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(text + "\n")


def command(args, *, input=None, timeout=120):
    # All endpoints/credentials here are disposable fixtures. No inherited service
    # environment, production endpoints, command output or SQL is printed.
    private_log("COMMAND " + json.dumps(args))
    try:
        result = subprocess.run(args, input=input, capture_output=True, text=True, timeout=timeout, cwd=ROOT)
    except subprocess.TimeoutExpired as error:
        private_log("TIMEOUT " + str(error.stdout) + "\n" + str(error.stderr))
        raise
    private_log(f"EXIT {result.returncode}\nSTDOUT\n{result.stdout}\nSTDERR\n{result.stderr}")
    if result.returncode:
        raise RuntimeError("Qualification command failed; private diagnostic retained")
    return result


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def source_hashes():
    paths = {Path(__file__).resolve(), TEST, ROOT / "apps/api/src/repository.ts",
             ROOT / "package.json", ROOT / "pnpm-lock.yaml", ROOT / "Dockerfile", ROOT / "deploy/compose/compose.yaml"}
    for folder in ("packages/db/src", "packages/domain/src", "packages/authz/src"):
        paths.update((ROOT / folder).rglob("*.ts"))
    paths.update(MIGRATIONS / name for name in NAMES)
    return [{"path": str(path.relative_to(ROOT)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in sorted(paths)]


def fixture_sql():
    definition = {"formatVersion": 1, "id": MODEL, "version": 1,
                  "attributes": {"amount": {"type": "decimal", "required": True}}}
    values = {"amount": "12345678901234567890.12345678901234567890"}
    snapshot = {"id": ASSET, "version": 1, "modelId": MODEL, "modelVersion": 1, "attributes": values}
    return f"""
BEGIN;
INSERT INTO tenants(id,name) VALUES('{TENANT}','Synthetic inherited-type upgrade tenant');
INSERT INTO identities(id,issuer,subject,name) VALUES('{ACTOR}','synthetic-upgrade','steward','Synthetic upgrade steward');
SET LOCAL gc.tenant_id='{TENANT}';
SET LOCAL gc.actor_id='{ACTOR}';
INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES('{TENANT}','{ACTOR}','steward','["catalog:read","catalog:write","models:read","models:write"]');
INSERT INTO governance_models(tenant_id,id,current_version,created_by) VALUES('{TENANT}','{MODEL}',1,'{ACTOR}');
INSERT INTO governance_model_versions(tenant_id,model_id,version,definition,definition_hash,created_by)
 VALUES('{TENANT}','{MODEL}',1,{literal(json.dumps(definition))},'{digest(definition)}','{ACTOR}');
INSERT INTO assets(tenant_id,id,external_id,name,qualified_name,type,description,owner_id,version,observed_at,model_id,model_version,attributes)
 VALUES('{TENANT}','{ASSET}','synthetic-upgrade-source-key','Synthetic pre006 asset','synthetic.pre006.asset','dataset','Preserved curated description','{ACTOR}',1,now(),'{MODEL}',1,{literal(json.dumps(values))});
INSERT INTO asset_revisions(tenant_id,asset_id,version,snapshot) VALUES('{TENANT}','{ASSET}',1,{literal(json.dumps(snapshot))});
COMMIT;
"""


def tap_summary(output, expected):
    names = ("tests", "pass", "fail", "cancelled", "skipped", "todo")
    summary = {}
    for name in names:
        matches = re.findall(rf"^# {name} (\d+)$", output, re.MULTILINE)
        require(len(matches) == 1, "Missing or ambiguous final TAP summary")
        summary[name] = int(matches[0])
    require(expected > 0 and summary["tests"] == summary["pass"] == expected,
            "Storage test count did not match the mounted source declarations")
    require(all(summary[name] == 0 for name in names[2:]), "Storage suite contains a failure, cancellation, skip or todo")
    durations = re.findall(r"^# duration_ms ([0-9.]+)$", output, re.MULTILINE)
    require(len(durations) == 1, "Missing final TAP duration")
    summary["duration_ms"] = float(durations[0])
    return summary


def main():
    LOCAL.mkdir(parents=True, exist_ok=True)
    DIAGNOSTIC.unlink(missing_ok=True)
    started = datetime.now(timezone.utc).isoformat()
    REPORT.write_text(json.dumps({"result": "RUNNING", "started_at": started}) + "\n")
    sources = source_hashes()
    expected_tests = len(re.findall(r"^test\(", TEST.read_text(), re.MULTILINE))
    require(expected_tests > 0, "Storage test source has no top-level tests")
    endpoint = json.loads(command(["docker", "context", "inspect"]).stdout)[0]["Endpoints"]["docker"]["Host"]
    override = os.environ.get("DOCKER_HOST", "")
    require(endpoint.startswith(("unix://", "npipe://")) and
            (not override or override.startswith(("unix://", "npipe://"))), "Qualification requires a local Docker engine")
    match = re.search(r"^\s+image: (postgres:[^\s]+)$", (ROOT / "deploy/compose/compose.yaml").read_text(), re.MULTILINE)
    require(match is not None, "Pinned PostgreSQL image was not found")
    postgres_tag = match.group(1)
    postgres_image = command(["docker", "image", "inspect", "--format", "{{.Id}}", postgres_tag]).stdout.strip()
    app_image = command(["docker", "image", "inspect", "--format", "{{.Id}}", "governance-commons:dev"]).stdout.strip()
    require(shutil.disk_usage(ROOT).free >= 2 * 1024**3, "Qualification stopped below the 2GiB disk floor")
    name = "gc-asset-type-upgrade-" + uuid.uuid4().hex[:12]
    created = False
    checks = []
    with tempfile.TemporaryDirectory(prefix="gc-asset-type-upgrade-", dir=ROOT / ".local") as directory:
        temporary = Path(directory)
        temporary.chmod(0o755)
        before, target = temporary / "before", temporary / "target"
        for destination, names in ((before, NAMES[:5]), (target, NAMES)):
            destination.mkdir()
            for filename in names:
                shutil.copyfile(MIGRATIONS / filename, destination / filename)

        def sql(body, role=OWNER, database=DATABASE):
            return command(["docker", "exec", "-i", name, "psql", "-X", "-qAt", "--set", "ON_ERROR_STOP=1",
                            "-U", role, "-d", database], input=body).stdout.strip()

        def migrate(path):
            return command(["docker", "run", "--rm", "--pull", "never", "--network", "container:" + name,
                            "--memory", "512m", "--cpus", "1", "--security-opt", "no-new-privileges:true", "--cap-drop", "ALL",
                            "--env", f"MIGRATION_DATABASE_URL=postgresql://{OWNER}@127.0.0.1:5432/{DATABASE}",
                            "--volume", f"{ROOT / 'packages/db/src'}:/app/packages/db/src:ro",
                            "--volume", f"{path}:/app/packages/db/migrations:ro",
                            app_image, "node", "--import", "tsx", "packages/db/src/migrate.ts"])

        def baseline():
            # to_jsonb-minus also works before the new fields exist. Compare every
            # preexisting canonical and revision field, including exact decimals.
            return json.loads(sql(f"""BEGIN; SET LOCAL gc.tenant_id='{TENANT}';
SELECT jsonb_build_object('asset',(SELECT to_jsonb(a)-'type_state' FROM assets a WHERE id='{ASSET}'),
 'head',(SELECT to_jsonb(m)-'type_id' FROM governance_models m WHERE id='{MODEL}'),
 'version',(SELECT to_jsonb(v) FROM governance_model_versions v WHERE model_id='{MODEL}'),
 'revisions',(SELECT jsonb_agg(to_jsonb(r) ORDER BY version) FROM asset_revisions r WHERE asset_id='{ASSET}'));
COMMIT;""", "gc_app"))

        try:
            command(["docker", "run", "--detach", "--pull", "never", "--name", name,
                     "--label", "org.governance-commons.qualification=asset-type-upgrade", "--network", "none",
                     "--memory", "512m", "--cpus", "1", "--tmpfs", "/var/lib/postgresql/data:rw,size=256m",
                     "--env", "POSTGRES_HOST_AUTH_METHOD=trust", postgres_image])
            created = True
            ready = False
            for _ in range(100):
                result = subprocess.run(["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"], capture_output=True, timeout=5)
                if result.returncode == 0:
                    ready = True
                    break
                time.sleep(0.2)
            require(ready, "Isolated PostgreSQL did not become ready")
            sql(f"CREATE ROLE gc_app LOGIN NOSUPERUSER NOBYPASSRLS; CREATE ROLE {OWNER} LOGIN NOSUPERUSER NOBYPASSRLS;", "postgres", "postgres")
            sql(f"CREATE DATABASE {DATABASE} OWNER {OWNER};", "postgres", "postgres")
            sql(f"REVOKE ALL ON DATABASE {DATABASE} FROM PUBLIC; GRANT CONNECT ON DATABASE {DATABASE} TO {OWNER},gc_app;", "postgres", "postgres")
            migrate(before)
            require(sql("SELECT count(*) FROM schema_migrations;") == "5", "Baseline did not apply exactly five migrations")
            sql(fixture_sql())
            original = baseline()
            require(original["asset"] is not None and len(original["revisions"]) == 1, "Baseline fixture is incomplete")
            checks.append("Actual checksum migrator applies001–005 and a pre006 attribute-model asset with exact decimal values and immutable revision is recorded")
            applied = migrate(target)
            require(re.findall(r"^Applied (.+)$", applied.stdout, re.MULTILINE) == [NAMES[5]], "Upgrade did not apply exactly006")
            require(baseline() == original, "SQL006 changed existing canonical or revision data")
            new_fields = json.loads(sql(f"BEGIN; SET LOCAL gc.tenant_id='{TENANT}'; SELECT json_build_object('typeId',(SELECT type_id FROM governance_models WHERE id='{MODEL}'),'state',(SELECT type_state FROM assets WHERE id='{ASSET}')); COMMIT;", "gc_app"))
            require(new_fields == {"typeId": None, "state": None}, "Legacy model or asset gained an authored type interpretation")
            checks.append("SQL006 preserves every preexisting model/asset/revision field and leaves legacy type identity and lifecycle unset")
            replay = migrate(target)
            require("Applied" not in replay.stdout, "Checksum replay reapplied migration work")
            applied_checksums = json.loads(sql("SELECT json_agg(json_build_object('name',name,'sha256',checksum) ORDER BY name) FROM schema_migrations;"))
            require(applied_checksums == [{"name": name, "sha256": hashlib.sha256((target / name).read_bytes()).hexdigest()} for name in NAMES], "Applied migration checksums differ from the exact six sources")
            checks.append("Actual checksum migrator replays all six migrations without reapplication and recorded checksums match source bytes")
            roles = json.loads(sql(f"""SELECT json_build_object(
 'ownerSuperuser',(SELECT rolsuper FROM pg_roles WHERE rolname='{OWNER}'),
 'ownerBypassRls',(SELECT rolbypassrls FROM pg_roles WHERE rolname='{OWNER}'),
 'runtimeSuperuser',(SELECT rolsuper FROM pg_roles WHERE rolname='gc_app'),
 'runtimeBypassRls',(SELECT rolbypassrls FROM pg_roles WHERE rolname='gc_app'),
 'runtimeLogin',(SELECT rolcanlogin FROM pg_roles WHERE rolname='gc_app'),
 'runtimeOwnsTables',EXISTS(SELECT 1 FROM pg_class WHERE relkind IN ('r','p') AND relowner=(SELECT oid FROM pg_roles WHERE rolname='gc_app')),
 'runtimeTemporary',has_database_privilege('gc_app',current_database(),'TEMP'),
 'runtimeCreateSchema',has_schema_privilege('gc_app','public','CREATE'),
 'forcedRlsCount',(SELECT count(*) FROM pg_class WHERE relname IN ('asset_type_versions','asset_type_dependencies') AND relrowsecurity AND relforcerowsecurity));"""))
            require(roles == {"ownerSuperuser": False, "ownerBypassRls": False, "runtimeSuperuser": False,
                              "runtimeBypassRls": False, "runtimeLogin": True, "runtimeOwnsTables": False,
                              "runtimeTemporary": False, "runtimeCreateSchema": False, "forcedRlsCount": 2}, "Role ownership/privilege/RLS qualification failed")
            require(sql("SELECT current_user;", "gc_app") == "gc_app", "Runtime probe did not use the gc_app login")
            checks.append("Migration and runtime roles are non-superusers without BYPASSRLS; gc_app owns no tables and has neither TEMP nor schema CREATE; both new tables force RLS")
            mounts = []
            for folder in ("packages/db/src", "packages/domain/src", "packages/authz/src"):
                mounts += ["--volume", f"{ROOT / folder}:/app/{folder}:ro"]
            mounts += ["--volume", f"{target}:/app/packages/db/migrations:ro",
                       "--volume", f"{TEST}:/app/tests/integration/asset-type-storage.test.ts:ro",
                       "--volume", f"{ROOT / 'apps/api/src/repository.ts'}:/app/apps/api/src/repository.ts:ro"]
            runtime = ["docker", "run", "--rm", "--pull", "never", "--network", "container:" + name,
                       "--memory", "512m", "--cpus", "1", "--security-opt", "no-new-privileges:true", "--cap-drop", "ALL",
                       "--env", f"DATABASE_URL=postgresql://gc_app@127.0.0.1:5432/{DATABASE}", *mounts, app_image]
            runtime_info = json.loads(command([*runtime, "node", "--input-type=module", "-e",
                "import fs from 'node:fs';import crypto from 'node:crypto';const sha=p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');console.log(JSON.stringify({node:process.version,platform:process.platform,arch:process.arch,pg:JSON.parse(fs.readFileSync('node_modules/pg/package.json')).version,tsx:JSON.parse(fs.readFileSync('node_modules/tsx/package.json')).version,kysely:JSON.parse(fs.readFileSync('node_modules/kysely/package.json')).version,packageSha256:sha('package.json'),lockSha256:sha('pnpm-lock.yaml')}));"]).stdout)
            require(runtime_info["packageSha256"] == hashlib.sha256((ROOT / 'package.json').read_bytes()).hexdigest() and
                    runtime_info["lockSha256"] == hashlib.sha256((ROOT / 'pnpm-lock.yaml').read_bytes()).hexdigest(), "Runtime image dependency manifest differs from current source")
            tested = command([*runtime, "node", "--import", "tsx", "--test", "--test-reporter=tap", "tests/integration/asset-type-storage.test.ts"])
            tests = tap_summary(tested.stdout, expected_tests)
            checks.append(f"All{tests['tests']} mounted-source PostgreSQL storage cases pass through the actual gc_app login with no failures, cancellations, skips or todos")
            require(baseline() == original, "Storage tests changed the preserved baseline asset")
            require(source_hashes() == sources, "Qualification sources changed during execution; rerun against a frozen snapshot")
            inspected = json.loads(command(["docker", "inspect", name]).stdout)[0]
            require(inspected["HostConfig"]["NetworkMode"] == "none" and not inspected["HostConfig"]["PortBindings"], "Disposable database isolation changed")
            require(not any(mount.get("Type") in ("volume", "bind") for mount in inspected["Mounts"]), "Disposable database unexpectedly uses persistent storage")
            postgres_version = sql("SHOW server_version;")
            report = {"schema_version": 1, "result": "PASS", "started_at": started,
                      "recorded_at": datetime.now(timezone.utc).isoformat(), "command": "./dev test --suite asset-type-upgrade",
                      "scope": "SQL005-to006 inherited asset-type development upgrade and runtime storage integrity",
                      "checks": checks, "storage_tests": tests, "expected_top_level_tests": expected_tests,
                      "runtime": {**runtime_info, "postgresql": postgres_version}, "roles": roles,
                      "postgres_image_reference": postgres_tag, "postgres_image": postgres_image, "app_image": app_image,
                      "isolation": {"network": "none; helpers share only disposable database network namespace", "published_ports": [],
                                    "database_storage": "disposable256MiB tmpfs", "production_volumes_used": False,
                                    "runtime_connection": "gc_app login to disposable loopback PostgreSQL; trust authentication only within its isolated namespace"},
                      "baseline": {"tenant_id": TENANT, "asset_id": ASSET, "model_id": MODEL, "before_hash": digest(original), "after_hash": digest(baseline())},
                      "applied_migrations": applied_checksums, "sources": sources,
                      "limitations": ["Synthetic development schema upgrade, not a released predecessor, backup restore or complete SYS-OPS-003 qualification.",
                                      "Storage tests deliberately exercise direct SQL, separate from HTTP authorization, inherited-type application services and browser workflows.",
                                      "Complete typed-attribute resolution and validation remain domain-owned; SQL checks identity, referenced inheritance and supported ownership/lifecycle storage invariants.",
                                      "Application dependencies come from the recorded cached image; current source is mounted read-only and dependency manifests are checked for equality."]}
        finally:
            if created:
                command(["docker", "rm", "--force", name], timeout=30)
    report["disposable_container_removed"] = True
    REPORT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"result": "PASS", "checks": len(checks), "storage_tests": tests, "disposable_container_removed": True}))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        LOCAL.mkdir(parents=True, exist_ok=True)
        private_log(traceback.format_exc())
        REPORT.write_text(json.dumps({"result": "FAIL", "recorded_at": datetime.now(timezone.utc).isoformat(), "error_type": type(error).__name__}) + "\n")
        raise SystemExit(f"Asset-type upgrade qualification failed: {type(error).__name__}; private diagnostics retained, no pass recorded")
