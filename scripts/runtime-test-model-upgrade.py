#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Qualify migration005 using actual migrator code in a disposable isolated PG."""
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
import uuid

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "packages/db/migrations"
LOCAL = ROOT / ".local/evidence"
NAMES = ["001_foundation.sql", "002_audit_envelopes.sql", "003_governance_models.sql",
         "004_model_migrations.sql", "005_model_migration_integrity.sql"]
TENANTS = ["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"]
ACTOR = "10000000-0000-4000-8000-000000000001"
OWNER = "gc_upgrade_owner"


def command(args, *, input=None, success=True, timeout=120):
    result = subprocess.run(args, input=input, capture_output=True, text=True, timeout=timeout, cwd=ROOT)
    if (result.returncode == 0) != success:
        # Private diagnostic files may contain SQL; never publish command output.
        LOCAL.mkdir(parents=True, exist_ok=True)
        diagnostic = LOCAL / "model-upgrade-private.log"
        descriptor = os.open(diagnostic, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(result.stdout + result.stderr)
        raise RuntimeError("Unexpected qualification command outcome; private local diagnostic retained")
    return result


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def literal(value):
    return "'" + str(value).replace("'", "''") + "'"


def fixture_sql(invalid=False):
    statements = ["BEGIN;", f"INSERT INTO identities(id,issuer,subject,name) VALUES('{ACTOR}','synthetic-upgrade','steward','Synthetic upgrade steward');"]
    for index, tenant in enumerate(TENANTS):
        statements += [f"INSERT INTO tenants VALUES('{tenant}','Synthetic upgrade tenant {index}');",
                       f"SELECT set_config('gc.tenant_id','{tenant}',true);",
                       f"INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES('{tenant}','{ACTOR}','steward','[]');"]
        for kind in ("complete", "gap"):
            model = f"upgrade_{index}_{kind}"
            asset = str(uuid.uuid5(uuid.NAMESPACE_URL, f"governance-commons/{model}/asset"))
            receipt = str(uuid.uuid5(uuid.NAMESPACE_URL, f"governance-commons/{model}/receipt"))
            statements.append(f"INSERT INTO governance_models(tenant_id,id,current_version,created_by) VALUES('{tenant}','{model}',2,'{ACTOR}');")
            for version in (1, 2):
                definition = {"formatVersion": 1, "id": model, "version": version, "attributes": {}}
                statements.append(f"INSERT INTO governance_model_versions(tenant_id,model_id,version,definition,definition_hash,created_by) VALUES('{tenant}','{model}',{version},{literal(json.dumps(definition))},'{digest(definition)}','{ACTOR}');")
            statements.append(f"INSERT INTO assets(tenant_id,id,external_id,name,qualified_name,type,version,observed_at,model_id,model_version) VALUES('{tenant}','{asset}','{asset}','Synthetic upgrade asset','fixture.{model}','dataset',2,now(),'{model}',2);")
            for version in ((1, 2) if kind == "complete" else (2,)):
                snapshot = {"id": asset, "version": version, "modelId": model, "modelVersion": version, "attributes": {}}
                statements.append(f"INSERT INTO asset_revisions(tenant_id,asset_id,version,snapshot) VALUES('{tenant}','{asset}',{version},{literal(json.dumps(snapshot))});")
            plan = {"formatVersion": 1, "modelId": "mismatched_fixture" if invalid and index == 0 and kind == "complete" else model,
                    "targetVersion": 2, "sourceVersions": [1], "acknowledgedChanges": [], "operations": []}
            assets = [{"assetId": asset, "fromAssetVersion": 1, "toAssetVersion": 2, "fromModelVersion": 1,
                       "toModelVersion": 2, "beforeHash": digest({}), "afterHash": digest({})}]
            statements.append(f"INSERT INTO governance_model_migrations(tenant_id,id,model_id,from_version,to_version,plan,plan_hash,preview_digest,asset_count,assets,executed_by) VALUES('{tenant}','{receipt}','{model}',1,2,{literal(json.dumps(plan))},'{digest(plan)}','{digest({'fixture': model})}',1,{literal(json.dumps(assets))},'{ACTOR}');")
    statements.append("COMMIT;")
    return "\n".join(statements)


def main():
    LOCAL.mkdir(parents=True, exist_ok=True)
    (LOCAL / "model-migration-upgrade.json").write_text(json.dumps({"result": "RUNNING", "started_at": datetime.now(timezone.utc).isoformat()}) + "\n")
    # Never borrow production endpoints or join the running application network.
    endpoint = json.loads(command(["docker", "context", "inspect"]).stdout)[0]["Endpoints"]["docker"]["Host"]
    override = os.environ.get("DOCKER_HOST", "")
    if not endpoint.startswith(("unix://", "npipe://")) or override and not override.startswith(("unix://", "npipe://")):
        raise RuntimeError("Qualification requires a local Docker engine")
    image = re.search(r"^\s+image: (postgres:[^\s]+)$", (ROOT / "deploy/compose/compose.yaml").read_text(), re.MULTILINE).group(1)
    command(["docker", "image", "inspect", image, "governance-commons:dev"])
    app_image = command(["docker", "image", "inspect", "--format", "{{.Id}}", "governance-commons:dev"]).stdout.strip()
    if shutil.disk_usage(ROOT).free < 2 * 1024**3:
        raise RuntimeError("Qualification stopped below the2GiB disk floor")
    name = "gc-model-upgrade-" + uuid.uuid4().hex[:12]
    created = False
    started = datetime.now(timezone.utc).isoformat()
    with tempfile.TemporaryDirectory(prefix="gc-model-upgrade-", dir=ROOT / ".local") as directory:
        temporary = Path(directory)
        temporary.chmod(0o755)
        before, target = temporary / "before", temporary / "target"
        for destination, names in ((before, NAMES[:4]), (target, NAMES)):
            destination.mkdir()
            for filename in names:
                shutil.copyfile(MIGRATIONS / filename, destination / filename)

        def sql(database, body, role=OWNER):
            return command(["docker", "exec", "-i", name, "psql", "-X", "-qAt", "--set", "ON_ERROR_STOP=1", "-U", role, "-d", database], input=body).stdout.strip()

        def migrate(database, path, success=True):
            return command(["docker", "run", "--rm", "--network", "container:" + name,
                            "--env", f"MIGRATION_DATABASE_URL=postgresql://{OWNER}@127.0.0.1:5432/{database}",
                            "--volume", f"{ROOT / 'packages/db/src'}:/app/packages/db/src:ro",
                            "--volume", f"{path}:/app/packages/db/migrations:ro",
                            app_image, "node", "--import", "tsx", "packages/db/src/migrate.ts"], success=success)

        try:
            command(["docker", "run", "--detach", "--name", name, "--label", "org.governance-commons.qualification=model-upgrade",
                     "--network", "none", "--memory", "512m", "--cpus", "1", "--tmpfs", "/var/lib/postgresql/data:rw,size=256m",
                     "--env", "POSTGRES_HOST_AUTH_METHOD=trust", image])
            created = True
            ready = False
            for _ in range(100):
                status = subprocess.run(["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"], capture_output=True, timeout=5)
                if status.returncode == 0:
                    ready = True
                    break
                time.sleep(0.2)
            if not ready:
                raise RuntimeError("Isolated PostgreSQL did not become ready")
            sql("postgres", f"CREATE ROLE gc_app NOLOGIN NOSUPERUSER NOBYPASSRLS; CREATE ROLE {OWNER} LOGIN NOSUPERUSER NOBYPASSRLS;", "postgres")
            for database in ("upgrade_valid", "upgrade_invalid"):
                sql("postgres", f"CREATE DATABASE {database} OWNER {OWNER};", "postgres")
                sql("postgres", f"REVOKE ALL ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {OWNER},gc_app;", "postgres")
                migrate(database, before)
                sql(database, fixture_sql(invalid=database == "upgrade_invalid"))
            migrate("upgrade_valid", target)
            cases = []
            for tenant in TENANTS:
                counts = sql("upgrade_valid", f"BEGIN; SET LOCAL gc.tenant_id='{tenant}'; SELECT json_build_object('receipts',(SELECT count(*) FROM governance_model_migrations),'normalized',(SELECT count(*) FROM governance_model_migration_assets),'exceptions',(SELECT count(*) FROM governance_model_migration_integrity_exceptions),'missing_from',(SELECT count(*) FROM governance_model_migration_integrity_exceptions WHERE missing_revisions->0->>'side'='from' AND reason='missing_pre_005_asset_revision')); COMMIT;")
                observed = json.loads(counts)
                assert observed == {"receipts": 2, "normalized": 1, "exceptions": 1, "missing_from": 1}, observed
            cases.append("Owner-run forced-RLS backfill visits both tenants and distinguishes complete receipts from missing historical revisions")
            replay = migrate("upgrade_valid", target)
            assert "Applied" not in replay.stdout
            assert sql("upgrade_valid", "SELECT count(*) FROM schema_migrations;") == "5"
            cases.append("Actual checksum migrator replays without reapplying any of the five migrations")
            failure = migrate("upgrade_invalid", target, success=False)
            assert "23514" in failure.stderr
            state = json.loads(sql("upgrade_invalid", "SELECT json_build_object('applied',(SELECT count(*) FROM schema_migrations),'shape_function',(SELECT count(*) FROM pg_proc WHERE proname='gc_model_migration_shape'),'normalized_table',to_regclass('public.governance_model_migration_assets') IS NOT NULL);"))
            assert state == {"applied": 4, "shape_function": 0, "normalized_table": False}, state
            for tenant in TENANTS:
                assert sql("upgrade_invalid", f"BEGIN; SET LOCAL gc.tenant_id='{tenant}'; SELECT count(*) FROM governance_model_migrations; COMMIT;") == "2"
            cases.append("Malformed historical plan identity rejects005 and rolls back all schema work while preserving original receipts")
            role = json.loads(sql("upgrade_valid", f"SELECT json_build_object('owner_superuser',(SELECT rolsuper FROM pg_roles WHERE rolname='{OWNER}'),'owner_bypass',(SELECT rolbypassrls FROM pg_roles WHERE rolname='{OWNER}'),'runtime_superuser',(SELECT rolsuper FROM pg_roles WHERE rolname='gc_app'),'runtime_bypass',(SELECT rolbypassrls FROM pg_roles WHERE rolname='gc_app'));"))
            assert not any(role.values())
            cases.append("Migration owner and runtime roles are non-superusers without BYPASSRLS")
            # Owner installs a controlled temporary trigger. Runtime still has no
            # CREATE/TEMP grant; the attempted writes run as gc_app. Exact error
            # diagnostics prove we reached the inner guard/PK, not an earlier
            # unrelated privilege error.
            sql("upgrade_valid", f"""
BEGIN;
SET LOCAL gc.tenant_id='{TENANTS[0]}';
SET LOCAL ROLE {OWNER};
CREATE TEMP TABLE receipt_reference_probe(payload jsonb) ON COMMIT DROP;
CREATE FUNCTION pg_temp.gc_receipt_reference_probe() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER AS $body$
 BEGIN
  INSERT INTO public.governance_model_migration_assets
   SELECT * FROM jsonb_populate_record(NULL::public.governance_model_migration_assets,NEW.payload);
  RETURN NEW;
 END $body$;
CREATE TRIGGER probe AFTER INSERT ON receipt_reference_probe FOR EACH ROW EXECUTE FUNCTION pg_temp.gc_receipt_reference_probe();
GRANT INSERT ON receipt_reference_probe TO gc_app;
RESET ROLE;
SET LOCAL ROLE gc_app;
DO $probe$
DECLARE caught boolean := false; diagnostic text;
BEGIN
 IF current_user <> 'gc_app' THEN RAISE EXCEPTION 'Probe has the wrong runtime role'; END IF;
 IF has_database_privilege(current_user,current_database(),'TEMP') THEN RAISE EXCEPTION 'Runtime unexpectedly has TEMP'; END IF;
 BEGIN
  INSERT INTO pg_temp.receipt_reference_probe SELECT jsonb_set(to_jsonb(r),'{{after_hash}}',to_jsonb(repeat('0',64))) FROM public.governance_model_migration_assets r LIMIT 1;
 EXCEPTION WHEN insufficient_privilege THEN
  GET STACKED DIAGNOSTICS diagnostic = MESSAGE_TEXT;
  IF diagnostic <> 'Model migration references must derive from their immutable parent receipt' THEN RAISE; END IF;
  caught := true;
 END;
 IF NOT caught THEN RAISE EXCEPTION 'Forged nested reference was accepted'; END IF;
 caught := false;
 BEGIN
  INSERT INTO pg_temp.receipt_reference_probe SELECT to_jsonb(r) FROM public.governance_model_migration_assets r LIMIT 1;
 EXCEPTION WHEN unique_violation THEN
  GET STACKED DIAGNOSTICS diagnostic = CONSTRAINT_NAME;
  IF diagnostic <> 'governance_model_migration_assets_pkey' THEN RAISE; END IF;
  caught := true;
 END;
 IF NOT caught THEN RAISE EXCEPTION 'Duplicate nested reference was accepted'; END IF;
 IF (SELECT count(*) FROM public.governance_model_migration_assets) <> 1 THEN RAISE EXCEPTION 'Normalized references changed'; END IF;
END $probe$;
ROLLBACK;
""", "postgres")
            cases.append("Owner-installed nested trigger runs as gc_app: forged parent membership is rejected by the guard and exact duplicate membership by the primary key, without granting runtime TEMP")
            postgres = sql("upgrade_valid", "SHOW server_version;")
            report = {"schema_version": 1, "started_at": started, "recorded_at": datetime.now(timezone.utc).isoformat(),
                      "scope": "SQL004-to005 receipt-integrity development upgrade, actual checksum migrator and isolated PostgreSQL",
                      "command": "./dev test --suite model-upgrade", "result": "PASS", "checks": cases,
                      "postgresql": postgres, "postgres_image": image, "app_image": app_image,
                      "isolation": {"network": "none; migrator shares only the disposable database network namespace", "published_ports": [], "database_storage": "disposable256MiB tmpfs", "production_volumes_used": False},
                      "sources": [{"path": str(path.relative_to(ROOT)), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                                  for path in [*(MIGRATIONS / filename for filename in NAMES), ROOT / "packages/db/src/migrate.ts", Path(__file__).resolve()]],
                      "limitations": ["Fixtures deliberately construct pre005 records, including an incomplete initial revision; they are not product user journeys.", "This qualifies a development schema transition, not a released-version upgrade, backup restore, interrupted durable bulk migration, or complete SYS-OPS-003.", "Runtime insert/update/tenant-denial and application getter behavior are qualified separately by real integration tests."]}
        finally:
            if created:
                command(["docker", "rm", "--force", name], timeout=30)
    report["disposable_container_removed"] = True
    LOCAL.mkdir(parents=True, exist_ok=True)
    (LOCAL / "model-migration-upgrade.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"result": "PASS", "checks": len(report["checks"]), "disposable_container_removed": True}))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, AssertionError, subprocess.SubprocessError) as error:
        LOCAL.mkdir(parents=True, exist_ok=True)
        (LOCAL / "model-migration-upgrade.json").write_text(json.dumps({"result": "FAIL", "recorded_at": datetime.now(timezone.utc).isoformat(), "error_type": type(error).__name__}) + "\n")
        raise SystemExit(f"Model upgrade qualification failed: {type(error).__name__}; no pass recorded")
