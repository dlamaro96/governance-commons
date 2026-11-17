#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SQL019→020 native lineage upgrade; disposable PostgreSQL, no shared launch."""
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('lineage_upgrade_base', ROOT / 'scripts/runtime-test-quality-upgrade.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
repaired = base.repaired
REPORT = ROOT / '.local/evidence/lineage-upgrade.json'
MIGRATION = '020_native_lineage.sql'
NAMES = [*base.NAMES, base.MIGRATION]
MIGRATIONS = ROOT / 'packages/db/migrations'
TESTS = ['tests/qualification/lineage.test.ts']
require, sha = base.require, base.sha


def sources():
    paths = {row['path'] for row in base.sources()}
    paths.update(['scripts/runtime-test-lineage-upgrade.py', 'packages/db/migrations/' + MIGRATION,
                  'apps/api/src/source-scans.ts', 'apps/api/src/lineage.ts', *TESTS])
    pending = [ROOT / name for name in paths if name.endswith(('.ts', '.tsx'))]
    while pending:
        current = pending.pop()
        for relative in re.findall(r'''(?:from\s*|import\s*)['"](\.[^'"]+)['"]''', current.read_text()):
            candidate = (current.parent / relative).resolve()
            if not candidate.suffix:
                candidate = candidate.with_suffix('.ts') if candidate.with_suffix('.ts').is_file() else candidate / 'index.ts'
            require(candidate.is_relative_to(ROOT) and candidate.is_file(), 'Unresolved local qualification source')
            name = str(candidate.relative_to(ROOT))
            if name not in paths:
                paths.add(name)
                pending.append(candidate)
    return [{'path': name, 'sha256': sha((ROOT / name).read_bytes())} for name in sorted(paths)]


class Harness(base.Harness):
    def __init__(self):
        base.REPORT = REPORT
        super().__init__()
        self.report.update(command='./dev test --suite lineage-upgrade', profile='isolated-postgresql-lineage')

    def helper(self, args, *, mounts=(), **kwargs):
        # Actual scan handlers import the wire and connector contracts; the
        # predecessor harness otherwise uses those modules from its cached image.
        fixed = ['packages/contracts/src', 'packages/connectors/src']
        require(all(not (target == '/app/' + folder or target.startswith('/app/' + folder + '/'))
                    for _, target in mounts for folder in fixed), 'Conflicting lineage contract mount')
        return super().helper(args, mounts=[*((ROOT / folder, '/app/' + folder) for folder in fixed), *mounts], **kwargs)


def legacy_snapshot(h, tables):
    """Compare every legacy field; separately verify exact added-column defaults."""
    result = {}
    excluded = {'public.sources': ['next_scan_generation', 'accepted_scan_generation'], 'public.jobs': ['scan_generation']}
    for table in tables:
        require(re.fullmatch(r'[a-z_]+\.[a-z_]+', table), 'Invalid fixed snapshot table')
        columns = excluded.get(table, [])
        projection = 'to_jsonb(r)' + ''.join("-'" + name + "'" for name in columns)
        row = json.loads(h.sql(f"""WITH hashes AS MATERIALIZED (
          SELECT sha256(convert_to(({projection})::text,'UTF8')) AS value FROM {table} r
        ) SELECT jsonb_build_object('rows',count(*),'sha256',encode(sha256(
          coalesce(string_agg(value,''::bytea ORDER BY value),''::bytea)),'hex')) FROM hashes;"""))
        require(isinstance(row, dict) and set(row) == {'rows', 'sha256'} and type(row['rows']) is int
                and row['rows'] >= 0 and isinstance(row['sha256'], str) and re.fullmatch(r'[a-f0-9]{64}', row['sha256']),
                'Invalid lineage predecessor snapshot')
        result[table] = row
    return result


def execute(h):
    frozen = sources()
    h.report['diagnostic_sources'] = frozen
    base.execute(h)
    h.report['predecessor_quality_tests'] = dict(h.report['tests'])
    h.report['sources'] = frozen
    h.phase = 'lineage-predecessor'
    tables = json.loads(h.sql("SELECT json_agg(schemaname||'.'||tablename ORDER BY schemaname,tablename) FROM pg_tables WHERE schemaname IN('public','gc_authn','gc_authority') AND tablename<>'schema_migrations';"))
    before = legacy_snapshot(h, tables)
    ledger = json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;'))
    require((repaired.before(h, ledger, NAMES) if repaired.active(h) else len(NAMES) == 19 and [row['name'] for row in ledger] == NAMES), 'Expected exact SQL001–019 predecessor')
    target = h.folder / 'lineage-target'
    target.mkdir()
    for name in repaired.names(h, [*NAMES, MIGRATION]):
        shutil.copyfile(MIGRATIONS / name, target / name)
    h.phase = 'lineage-upgrade'
    migrated = h.migrate(target)
    require(re.findall(r'^Applied (.+)$', migrated.stdout, re.MULTILINE) == [MIGRATION], 'Expected exact SQL020 application')
    require(legacy_snapshot(h, tables) == before, 'Lineage upgrade changed legacy canonical/history fields')
    defaults = "SELECT NOT EXISTS(SELECT 1 FROM sources WHERE next_scan_generation<>1 OR accepted_scan_generation<>0) AND NOT EXISTS(SELECT 1 FROM jobs WHERE scan_generation IS NOT NULL);"
    require(h.sql(defaults) == 't', 'Lineage initial generation defaults differ')
    after = json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;'))
    require((repaired.after(h, ledger, after, NAMES, MIGRATION) if repaired.active(h) else len(after) == 20 and after[:19] == ledger and after[-1]['name'] == MIGRATION), 'Lineage changed predecessor ledger')
    require('Applied' not in h.migrate(target).stdout, 'Lineage replay reapplied migration')
    require(legacy_snapshot(h, tables) == before and h.sql(defaults) == 't', 'Lineage replay changed predecessor data')
    require(json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;')) == after, 'Lineage replay changed ledger')
    h.report['lineageUpgradeBaseline'] = [{'table': name, **row} for name, row in before.items()]
    h.report['checks'].append('Exact SQL019→020 and inert replay preserve all legacy fields and ledger; generation additions exactly 1/0/null')
    h.phase = 'lineage-native-tests'
    measured = [row for row in frozen if row['path'].endswith('.ts')]
    probe = "const fs=require('node:fs'),crypto=require('node:crypto');console.log(JSON.stringify(" + json.dumps([row['path'] for row in measured]) + ".map(path=>({path,sha256:crypto.createHash('sha256').update(fs.readFileSync(path)).digest('hex')}))));"
    observed = json.loads(h.helper(['node', '-e', probe]).stdout)
    # A later isolated upgrader may mount an explicitly pinned predecessor.
    # The actual filesystem readback is unchanged; only its declared expected
    # source bytes are phase-aware. Standalone lineage remains identity-bound.
    expected_sources = h.native_source_expectations(measured) if hasattr(h, 'native_source_expectations') else measured
    require(observed == expected_sources, 'Actual native helper source bytes differ')
    h.report['nativeSourceReadback'] = {'result': 'PASS', 'files': len(measured),
                                      'checkoutManifestSha256': sha(json.dumps(measured, sort_keys=True).encode()),
                                      'manifestSha256': sha(json.dumps(observed, sort_keys=True).encode())}
    expected = sum(len(re.findall(r'^test\(', (ROOT / name).read_text(), re.MULTILINE)) for name in TESTS)
    require(expected == 13, 'Expected thirteen native lineage cases')
    tested = h.helper(['node', '--import', 'tsx', '--test', '--test-reporter=tap', '--test-concurrency=1', *TESTS], timeout=180, allow_failure=True)
    require(tested.returncode == 0, 'Native lineage suite failed; retained TAP identifies failing case')
    h.report['tests'] = base.base.tap_summary(tested.stdout, expected)
    require(sources() == frozen, 'Lineage source changed during native qualification')
    repaired.complete(h, [*NAMES, MIGRATION])
    h.report['migrations'] = [{'name': name, 'sha256': sha((MIGRATIONS / name).read_bytes())} for name in repaired.names(h, [*NAMES, MIGRATION])]
    h.report['limitations'] = [
        'Real isolated PostgreSQL and production scan handlers/read service; completion payloads in this gate are authored fixtures, not worker extraction evidence.',
        'Full predecessor SQL001–019 execution uses the exact repository phase override recorded by the quality gate.',
        'Legacy snapshots exclude only newly added generation columns, whose defaults are independently checked.',
        'Worker extraction, API transport, Temporal and browser qualification remain separate; no shared runtime or external infrastructure modified.',
        'Canonical content authority remains inactive; column mappings and SQL bodies are not collected.']


def main():
    h, failed = Harness(), False
    try:
        execute(h)
    except BaseException as error:
        failed = True
        h.report.update(failed_phase=h.phase, error_type=type(error).__name__, error='Inspect bounded private diagnostics')
    finally:
        try:
            h.phase = 'cleanup'
            h.cleanup()
            if h.resources_before is not None:
                h.deadline = h.cleanup_deadline
                require(h.inventory() == h.resources_before, 'Preexisting resource inventory changed')
                h.report['cleanup']['resourceInventoryPreserved'] = True
        except BaseException as error:
            failed = True
            h.report['cleanupErrorType'] = type(error).__name__
        h.report.update(result='FAIL' if failed else 'PASS', recorded_at=datetime.now(timezone.utc).isoformat(),
                        evidence_directory=str(h.folder.relative_to(ROOT)))
        h.report['private_logs'] = [{'path': str(p.relative_to(ROOT)), 'sha256': sha(p.read_bytes())} for p in sorted(h.folder.glob('*.log'))]
        h.save(final=True)
    print(json.dumps({'result': h.report['result'], 'report': str(REPORT.relative_to(ROOT))}))
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
