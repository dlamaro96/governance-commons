#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Qualify SQL007 and full typed-migration guards in a disposable local PostgreSQL."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import time
import traceback
import uuid

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / ".local/evidence"
REPORT = LOCAL / "type-migration-upgrade.json"
DIAGNOSTIC = LOCAL / "type-migration-upgrade-private.log"
MIGRATIONS = ROOT / "packages/db/migrations"
NAMES = ["001_foundation.sql", "002_audit_envelopes.sql", "003_governance_models.sql",
         "004_model_migrations.sql", "005_model_migration_integrity.sql", "006_inherited_asset_types.sql", "007_asset_type_migrations.sql"]
TEST = ROOT / "tests/integration/asset-type-migration-storage.test.ts"
CONCURRENCY_TEST = ROOT / "tests/qualification/asset-type-migration-concurrency.test.ts"
TENANT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
ACTOR = "10000000-0000-4000-8000-000000000001"
ASSET = "30000000-0000-4000-8000-000000000001"
MODEL = "synthetic_pre007_model"
TYPED_MODEL = "synthetic_pre007_type"
TYPED_ASSET = "30000000-0000-4000-8000-000000000002"
RECEIPT = "40000000-0000-4000-8000-000000000001"
OWNER = "gc_type_migration_upgrade_owner"
DATABASE = "type_migration_upgrade"


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
    paths = {Path(__file__).resolve(), TEST, CONCURRENCY_TEST, ROOT / "apps/api/src/repository.ts",
             ROOT / "package.json", ROOT / "pnpm-lock.yaml", ROOT / "Dockerfile", ROOT / "deploy/compose/compose.yaml",
             ROOT / "dev", ROOT / "scripts/runtime.py"}
    for folder in ("packages/db/src", "packages/domain/src", "packages/authz/src"):
        paths.update((ROOT / folder).rglob("*.ts"))
    paths.update(MIGRATIONS.glob("*.sql"))
    return [{"path": str(path.relative_to(ROOT)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in sorted(paths)]


def fixture_sql():
    definitions = [{"formatVersion": 1, "id": MODEL, "version": version,
                    "attributes": {"amount": {"type": "decimal", "required": True}}} for version in (1, 2)]
    values = {"amount": "12345678901234567890.12345678901234567890"}
    snapshots = [{"id": ASSET, "version": version, "modelId": MODEL, "modelVersion": version,
                  "attributes": values, "ownerId": ACTOR, "typeState": None} for version in (1, 2)]
    plan = {"formatVersion": 1, "modelId": MODEL, "targetVersion": 2, "sourceVersions": [1], "acknowledgedChanges": [], "operations": []}
    entries = [{"assetId": ASSET, "fromAssetVersion": 1, "toAssetVersion": 2, "fromModelVersion": 1, "toModelVersion": 2,
                "beforeHash": digest(values), "afterHash": digest(values)}]
    model_rows = ",".join(f"('{TENANT}','{MODEL}',{item['version']},{literal(json.dumps(item))},'{digest(item)}','{ACTOR}')" for item in definitions)
    revision_rows = ",".join(f"('{TENANT}','{ASSET}',{item['version']},{literal(json.dumps(item))})" for item in snapshots)
    return f"""
BEGIN;
INSERT INTO tenants(id,name) VALUES('{TENANT}','Synthetic type-migration upgrade tenant'),
 ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','Synthetic foreign type-migration tenant');
INSERT INTO identities(id,issuer,subject,name) VALUES('{ACTOR}','synthetic-upgrade','steward','Synthetic upgrade steward'),
 ('10000000-0000-4000-8000-000000000002','synthetic-upgrade','owner','Synthetic upgrade owner'),
 ('10000000-0000-4000-8000-000000000005','synthetic-upgrade','foreign','Synthetic foreign steward');
SET LOCAL gc.tenant_id='{TENANT}'; SET LOCAL gc.actor_id='{ACTOR}';
INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES
 ('{TENANT}','{ACTOR}','steward','["catalog:read","catalog:write","models:read","models:write"]'),
 ('{TENANT}','10000000-0000-4000-8000-000000000002','owner','["catalog:read","catalog:write","models:read","models:write"]');
SET LOCAL gc.tenant_id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES
 ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','10000000-0000-4000-8000-000000000005','steward','["catalog:read","catalog:write","models:read","models:write"]');
SET LOCAL gc.tenant_id='{TENANT}';
INSERT INTO governance_models(tenant_id,id,current_version,created_by) VALUES('{TENANT}','{MODEL}',2,'{ACTOR}');
INSERT INTO governance_model_versions(tenant_id,model_id,version,definition,definition_hash,created_by) VALUES {model_rows};
INSERT INTO assets(tenant_id,id,external_id,name,qualified_name,type,description,owner_id,version,observed_at,model_id,model_version,attributes)
 VALUES('{TENANT}','{ASSET}','synthetic-upgrade-source-key','Synthetic pre007 asset','synthetic.pre007.asset','dataset','Preserved curated description','{ACTOR}',2,now(),'{MODEL}',2,{literal(json.dumps(values))});
INSERT INTO asset_revisions(tenant_id,asset_id,version,snapshot) VALUES {revision_rows};
INSERT INTO governance_model_migrations(tenant_id,id,model_id,from_version,to_version,plan,plan_hash,preview_digest,asset_count,assets,executed_by)
 VALUES('{TENANT}','{RECEIPT}','{MODEL}',1,2,{literal(json.dumps(plan))},'{digest(plan)}','{digest("Synthetic pre007 preview")}',1,{literal(json.dumps(entries))},'{ACTOR}');
COMMIT;
"""


def typed_fixture_js():
    # Resolve through the actual mounted domain and snapshot through the production
    # repository adapter. No code or fixture is loaded from a mutable service image.
    return f"""
import {{randomUUID}} from 'node:crypto';
import {{db,scope}} from './packages/db/src/index.ts';
import {{resolveAssetType}} from './packages/domain/src/asset-type.ts';
import {{typeHash}} from './packages/domain/src/asset-type-policy.ts';
import {{assetView}} from './apps/api/src/repository.ts';
const tenant='{TENANT}',actor='{ACTOR}',model='{TYPED_MODEL}',asset='{TYPED_ASSET}';
const parsed=resolveAssetType({{formatVersion:1,id:model,version:1,parents:[],attributes:{{amount:{{type:'decimal',required:true}}}},
 overrideAttributes:[],requiredOwner:true,lifecycle:{{initial:'draft',states:['draft','active'],transitions:[{{from:'draft',to:'active'}}]}}}},[]);
if(!parsed.ok) throw Error('Invalid synthetic baseline type');
try {{
 const result=parsed.value;
 await scope(tenant,actor,async tx=>{{
  await tx.insertInto('governance_models').values({{tenant_id:tenant,id:model,type_id:randomUUID(),current_version:1,created_by:actor}}).execute();
  await tx.insertInto('governance_model_versions').values({{tenant_id:tenant,model_id:model,version:1,definition:JSON.stringify(result.model),definition_hash:typeHash(result.model),created_by:actor}}).execute();
  await tx.insertInto('asset_type_versions').values({{tenant_id:tenant,model_id:model,version:1,definition:JSON.stringify(result.definition),definition_hash:typeHash(result.definition),resolved:JSON.stringify(result),resolution_hash:typeHash(result),created_by:actor}}).execute();
  const row=await tx.insertInto('assets').values({{tenant_id:tenant,id:asset,external_id:'synthetic-pre007-type-asset',name:'Synthetic typed baseline asset',qualified_name:'synthetic.pre007.type.asset',type:'dataset',description:'Preserved typed baseline',owner_id:actor,version:1,observed_at:new Date(),model_id:model,model_version:1,attributes:JSON.stringify({{amount:'9876543210.123456789'}}),type_state:'active'}}).returningAll().executeTakeFirstOrThrow();
  await tx.insertInto('asset_revisions').values({{tenant_id:tenant,asset_id:asset,version:1,snapshot:JSON.stringify(assetView(row))}}).execute();
 }});
 console.log('Synthetic pre007 typed fixture recorded');
}} finally {{await db.destroy();}}
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
    attempts = LOCAL / "type-migration-upgrade-attempts"
    if DIAGNOSTIC.exists():
        attempts.mkdir(mode=0o700, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8]
        for previous in (DIAGNOSTIC, REPORT):
            if previous.exists():
                archived = attempts / (stamp + "-" + previous.name)
                shutil.copyfile(previous, archived)
                archived.chmod(0o600)
    prior_attempts = [json.loads(path.read_text()) for path in sorted(attempts.glob("*-type-migration-upgrade.json"))]
    prior_results = {result: sum(attempt.get("result") == result for attempt in prior_attempts)
                     for result in sorted({attempt.get("result", "UNKNOWN") for attempt in prior_attempts})}
    DIAGNOSTIC.unlink(missing_ok=True)
    started = datetime.now(timezone.utc).isoformat()
    REPORT.write_text(json.dumps({"result": "RUNNING", "started_at": started}) + "\n")
    sources = source_hashes()
    expected_tests = len(re.findall(r"^test\(", TEST.read_text(), re.MULTILINE))
    expected_concurrency = len(re.findall(r"^test\(", CONCURRENCY_TEST.read_text(), re.MULTILINE))
    require(expected_concurrency > 0, "Concurrency source has no top-level tests")
    require(expected_tests > 0, "Storage test source has no top-level tests")
    endpoint = json.loads(command(["docker", "context", "inspect"]).stdout)[0]["Endpoints"]["docker"]["Host"]
    docker_version = json.loads(command(["docker", "version", "--format", "{{json .}}"]).stdout)
    override = os.environ.get("DOCKER_HOST", "")
    require(endpoint.startswith(("unix://", "npipe://")) and
            (not override or override.startswith(("unix://", "npipe://"))), "Qualification requires a local Docker engine")
    match = re.search(r"^\s+image: (postgres:[^\s]+)$", (ROOT / "deploy/compose/compose.yaml").read_text(), re.MULTILINE)
    require(match is not None, "Pinned PostgreSQL image was not found")
    postgres_tag = match.group(1)
    postgres_image = command(["docker", "image", "inspect", "--format", "{{.Id}}", postgres_tag]).stdout.strip()
    app_image = command(["docker", "image", "inspect", "--format", "{{.Id}}", "governance-commons:dev"]).stdout.strip()
    require(shutil.disk_usage(ROOT).free >= 2 * 1024**3, "Qualification stopped below the 2GiB disk floor")
    name = "gc-type-migration-upgrade-" + uuid.uuid4().hex[:12]
    created = False
    checks = []
    with tempfile.TemporaryDirectory(prefix="gc-type-migration-upgrade-", dir=ROOT / ".local") as directory:
        temporary = Path(directory)
        temporary.chmod(0o755)
        before, target = temporary / "before", temporary / "target"
        for destination, names in ((before, NAMES[:6]), (target, NAMES)):
            destination.mkdir()
            for filename in names:
                shutil.copyfile(MIGRATIONS / filename, destination / filename)

        def sql(body, role=OWNER, database=DATABASE):
            return command(["docker", "exec", "-i", name, "psql", "-X", "-qAt", "--set", "ON_ERROR_STOP=1",
                            "-U", role, "-d", database], input=body).stdout.strip()

        def migrate(path):
            return command(["docker", "run", "--rm", "--pull", "never", "--network", "container:" + name,
                            "--label", "org.governance-commons.qualification-run=" + name,
                            "--memory", "512m", "--cpus", "1", "--security-opt", "no-new-privileges:true", "--cap-drop", "ALL",
                            "--env", f"MIGRATION_DATABASE_URL=postgresql://{OWNER}@127.0.0.1:5432/{DATABASE}",
                            "--volume", f"{ROOT / 'packages/db/src'}:/app/packages/db/src:ro",
                            "--volume", f"{path}:/app/packages/db/migrations:ro",
                            app_image, "node", "--import", "tsx", "packages/db/src/migrate.ts"])

        mounts = []
        for folder in ("packages/db/src", "packages/domain/src", "packages/authz/src"):
            mounts += ["--volume", f"{ROOT / folder}:/app/{folder}:ro"]
        mounts += ["--volume", f"{target}:/app/packages/db/migrations:ro",
                   "--volume", f"{TEST}:/app/tests/integration/asset-type-migration-storage.test.ts:ro",
                   "--volume", f"{CONCURRENCY_TEST}:/app/tests/qualification/asset-type-migration-concurrency.test.ts:ro",
                   "--volume", f"{ROOT / 'apps/api/src/repository.ts'}:/app/apps/api/src/repository.ts:ro"]
        runtime = ["docker", "run", "--rm", "--pull", "never", "--network", "container:" + name,
                   "--label", "org.governance-commons.qualification-run=" + name,
                   "--memory", "512m", "--cpus", "1", "--security-opt", "no-new-privileges:true", "--cap-drop", "ALL",
                   "--env", f"DATABASE_URL=postgresql://gc_app@127.0.0.1:5432/{DATABASE}",
                   "--env", f"TYPE_MIGRATION_OWNER_DATABASE_URL=postgresql://{OWNER}@127.0.0.1:5432/{DATABASE}",
                   *mounts, app_image]

        def baseline():
            return json.loads(sql(f"""BEGIN; SET LOCAL gc.tenant_id='{TENANT}'; SET LOCAL gc.actor_id='{ACTOR}';
SELECT jsonb_build_object(
 'assets',(SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM assets a WHERE id IN ('{ASSET}','{TYPED_ASSET}')),
 'heads',(SELECT jsonb_agg(to_jsonb(m) ORDER BY id) FROM governance_models m WHERE id IN ('{MODEL}','{TYPED_MODEL}')),
 'versions',(SELECT jsonb_agg(to_jsonb(v) ORDER BY model_id,version) FROM governance_model_versions v WHERE model_id IN ('{MODEL}','{TYPED_MODEL}')),
 'typedVersions',(SELECT jsonb_agg(to_jsonb(v) ORDER BY model_id,version) FROM asset_type_versions v WHERE model_id='{TYPED_MODEL}'),
 'typedDependencies',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY model_id,version,dependency_model_id),'[]'::jsonb) FROM asset_type_dependencies d WHERE model_id='{TYPED_MODEL}'),
 'revisions',(SELECT jsonb_agg(to_jsonb(r) ORDER BY asset_id,version) FROM asset_revisions r WHERE asset_id IN ('{ASSET}','{TYPED_ASSET}')),
 'receipts',(SELECT jsonb_agg(to_jsonb(m) ORDER BY id) FROM governance_model_migrations m WHERE id='{RECEIPT}'),
 'references',(SELECT jsonb_agg(to_jsonb(m) ORDER BY migration_id,asset_id) FROM governance_model_migration_assets m WHERE migration_id='{RECEIPT}'));
COMMIT;""", "gc_app"))

        try:
            command(["docker", "run", "--detach", "--pull", "never", "--name", name,
                     "--label", "org.governance-commons.qualification=type-migration-upgrade", "--network", "none",
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
            require(sql("SELECT count(*) FROM schema_migrations;") == "6", "Baseline did not apply exactly six migrations")
            sql(fixture_sql())
            command([*runtime, "node", "--import", "tsx", "--input-type=module", "-e", typed_fixture_js()])
            original = baseline()
            require(len(original["assets"]) == 2 and len(original["revisions"]) == 3 and len(original["receipts"]) == len(original["references"]) == 1 and len(original["typedVersions"]) == 1, "Baseline fixture is incomplete")
            checks.append("Actual checksum migrator applies001–006; legacy model migration receipt and normalized references plus an authored type/asset are recorded through real runtime source")
            applied = migrate(target)
            require(re.findall(r"^Applied (.+)$", applied.stdout, re.MULTILINE) == [NAMES[6]], "Upgrade did not apply exactly007")
            require(baseline() == original, "SQL007 changed existing canonical, receipt, dependency or revision data")
            require(sql(f"BEGIN; SET LOCAL gc.tenant_id='{TENANT}'; SELECT count(*) FROM asset_type_migrations; COMMIT;", "gc_app") == "0", "Upgrade invented typed migration receipts")
            checks.append("SQL007 preserves every legacy/typed model, asset, revision, dependency, receipt and normalized reference field without inventing typed receipts")
            replay = migrate(target)
            require("Applied" not in replay.stdout, "Checksum replay reapplied migration work")
            applied_checksums = json.loads(sql("SELECT json_agg(json_build_object('name',name,'sha256',checksum) ORDER BY name) FROM schema_migrations;"))
            require(applied_checksums == [{"name": name, "sha256": hashlib.sha256((target / name).read_bytes()).hexdigest()} for name in NAMES], "Applied migration checksums differ from the exact seven sources")
            checks.append("Actual checksum migrator replays all seven migrations without reapplication and recorded checksums match source bytes")
            roles = json.loads(sql(f"""SELECT json_build_object(
 'ownerSuperuser',(SELECT rolsuper FROM pg_roles WHERE rolname='{OWNER}'),
 'ownerBypassRls',(SELECT rolbypassrls FROM pg_roles WHERE rolname='{OWNER}'),
 'runtimeSuperuser',(SELECT rolsuper FROM pg_roles WHERE rolname='gc_app'),
 'runtimeBypassRls',(SELECT rolbypassrls FROM pg_roles WHERE rolname='gc_app'),
 'runtimeLogin',(SELECT rolcanlogin FROM pg_roles WHERE rolname='gc_app'),
 'runtimeOwnsTables',EXISTS(SELECT 1 FROM pg_class WHERE relkind IN ('r','p') AND relowner=(SELECT oid FROM pg_roles WHERE rolname='gc_app')),
 'runtimeTemporary',has_database_privilege('gc_app',current_database(),'TEMP'),
 'runtimeCreateSchema',has_schema_privilege('gc_app','public','CREATE'),
 'forcedRlsCount',(SELECT count(*) FROM pg_class WHERE relname IN ('asset_type_migrations','asset_type_migration_assets') AND relrowsecurity AND relforcerowsecurity));"""))
            require(roles == {"ownerSuperuser": False, "ownerBypassRls": False, "runtimeSuperuser": False,
                              "runtimeBypassRls": False, "runtimeLogin": True, "runtimeOwnsTables": False,
                              "runtimeTemporary": False, "runtimeCreateSchema": False, "forcedRlsCount": 2}, "Role ownership/privilege/RLS qualification failed")
            require(sql("SELECT current_user;", "gc_app") == "gc_app", "Runtime probe did not use the gc_app login")
            checks.append("Migration and runtime roles are non-superusers without BYPASSRLS; gc_app owns no tables and has neither TEMP nor schema CREATE; both typed receipt tables force RLS")
            runtime_info = json.loads(command([*runtime, "node", "--input-type=module", "-e",
                "import fs from 'node:fs';import crypto from 'node:crypto';const sha=p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');console.log(JSON.stringify({node:process.version,platform:process.platform,arch:process.arch,pg:JSON.parse(fs.readFileSync('node_modules/pg/package.json')).version,tsx:JSON.parse(fs.readFileSync('node_modules/tsx/package.json')).version,kysely:JSON.parse(fs.readFileSync('node_modules/kysely/package.json')).version,packageSha256:sha('package.json'),lockSha256:sha('pnpm-lock.yaml')}));"]).stdout)
            require(runtime_info["packageSha256"] == hashlib.sha256((ROOT / 'package.json').read_bytes()).hexdigest() and
                    runtime_info["lockSha256"] == hashlib.sha256((ROOT / 'pnpm-lock.yaml').read_bytes()).hexdigest(), "Runtime image dependency manifest differs from current source")
            tested = command([*runtime, "node", "--import", "tsx", "--test", "--test-reporter=tap", "tests/integration/asset-type-migration-storage.test.ts"])
            tests = tap_summary(tested.stdout, expected_tests)
            checks.append(f"All{tests['tests']} mounted-source PostgreSQL storage cases pass through the actual gc_app login with no failures, cancellations, skips or todos")
            # The original SQL006→007 checks and storage cases above run on exactly
            # seven migrations. Current application services may depend on later
            # guards; qualify their regression separately on the current schema.
            later_migrations = sorted(path for path in MIGRATIONS.glob("*.sql") if path.name not in NAMES)
            for path in later_migrations:
                shutil.copyfile(path, target / path.name)
            if later_migrations:
                migrate(target)
            concurrency_schema = json.loads(sql("SELECT json_agg(json_build_object('name',name,'sha256',checksum) ORDER BY name) FROM schema_migrations;"))
            concurrent = command([*runtime, "node", "--import", "tsx", "--test", "--test-reporter=tap", "tests/qualification/asset-type-migration-concurrency.test.ts"], timeout=180)
            concurrency_tests = tap_summary(concurrent.stdout, expected_concurrency)
            checks.append(f"All{concurrency_tests['tests']} mounted-source principal-lock and concurrency cases pass on the separately recorded service regression schema with actual isolated owner/runtime logins and no failures, cancellations, skips or todos")
            require(baseline() == original, "Storage/concurrency tests changed the preserved baseline fixtures")
            require(source_hashes() == sources, "Qualification sources changed during execution; rerun against a frozen snapshot")
            inspected = json.loads(command(["docker", "inspect", name]).stdout)[0]
            require(inspected["HostConfig"]["NetworkMode"] == "none" and not inspected["HostConfig"]["PortBindings"], "Disposable database isolation changed")
            require(not any(mount.get("Type") in ("volume", "bind") for mount in inspected["Mounts"]), "Disposable database unexpectedly uses persistent storage")
            postgres_version = sql("SHOW server_version;")
            report = {"schema_version": 1, "result": "PASS", "started_at": started,
                      "recorded_at": datetime.now(timezone.utc).isoformat(), "command": "./dev test --suite type-migration-upgrade",
                      "scope": "SQL006-to007 upgrade and storage integrity; current-schema principal-lock service/concurrency regression",
                      "checks": checks, "storage_tests": tests, "expected_top_level_tests": expected_tests,
                      "concurrency_tests": concurrency_tests, "expected_concurrency_tests": expected_concurrency,
                      "runtime": {**runtime_info, "postgresql": postgres_version,
                                  "python": platform.python_version(), "dockerClient": docker_version["Client"]["Version"],
                                  "dockerEngine": docker_version["Server"]["Version"]}, "roles": roles,
                      "postgres_image_reference": postgres_tag, "postgres_image": postgres_image, "app_image": app_image,
                      "isolation": {"network": "none; helpers share only disposable database network namespace", "published_ports": [],
                                    "database_storage": "disposable256MiB tmpfs", "production_volumes_used": False,
                                    "runtime_connection": "gc_app login to disposable loopback PostgreSQL; trust authentication only within its isolated namespace"},
                      "baseline": {"tenant_id": TENANT, "asset_ids": [ASSET, TYPED_ASSET], "model_ids": [MODEL, TYPED_MODEL], "legacy_receipt_id": RECEIPT, "before_hash": digest(original), "after_hash": digest(baseline())},
                      "applied_migrations": applied_checksums, "sources": sources,
                      "service_regression_schema": {"applied_migrations": concurrency_schema, "note": "Original upgrade/storage gates execute on001–007; current service/concurrency regressions execute after any explicitly recorded later migrations."},
                      "diagnostic_history": {"archived_prior_attempts": len(prior_attempts), "result_counts": prior_results,
                                             "private_reports_and_database_logs_retained": True,
                                             "qualification_test_retries": 0},
                      "limitations": ["Synthetic development schema upgrade, not a released predecessor, backup restore or complete SYS-OPS-003 qualification.",
                                      "Storage tests deliberately exercise direct SQL. Concurrency tests exercise the real locking function and scoped domain paths; HTTP, OIDC and browser workflows are separate qualifications.",
                                      "Domain parsing and full ancestry resolution remain required. SQL proves exact receipt tuples against immutable revisions and the explicitly tested principal-lock boundary, not all future administrative ingress.",
                                      "Application dependencies come from the recorded cached image; current source is mounted read-only and dependency manifests are checked for equality.",
                                      "Earlier diagnostic attempts, including failed SQL development iterations, remain private and are counted separately; this result binds only the final executed source hashes and does not relabel earlier failures."]}
        except Exception:
            if created:
                try:
                    command(["docker", "logs", name], timeout=30)
                except Exception:
                    private_log("Database diagnostics could not be collected before cleanup")
            raise
        finally:
            if created:
                helpers = command(["docker", "ps", "--all", "--quiet", "--filter",
                                   "label=org.governance-commons.qualification-run=" + name]).stdout.split()
                if helpers:
                    command(["docker", "rm", "--force", *helpers], timeout=30)
                command(["docker", "rm", "--force", name], timeout=30)
    report["disposable_container_removed"] = True
    REPORT.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"result": "PASS", "checks": len(checks), "storage_tests": tests, "concurrency_tests": concurrency_tests, "disposable_container_removed": True}))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        LOCAL.mkdir(parents=True, exist_ok=True)
        private_log(traceback.format_exc())
        REPORT.write_text(json.dumps({"result": "FAIL", "recorded_at": datetime.now(timezone.utc).isoformat(), "error_type": type(error).__name__}) + "\n")
        raise SystemExit(f"Type-migration upgrade qualification failed: {type(error).__name__}; private diagnostics retained, no pass recorded")
