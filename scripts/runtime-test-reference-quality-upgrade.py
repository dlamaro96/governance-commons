#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SQL022→023 reference-backed quality; full predecessors, owned disposable DB."""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('reference_quality_upgrade_base', ROOT / 'scripts/runtime-test-reference-upgrade.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
REPORT = ROOT / '.local/evidence/reference-quality-upgrade.json'
MIGRATION = '023_reference_quality.sql'
MIGRATIONS = ROOT / 'packages/db/migrations'
NAMES = [*base.NAMES, base.MIGRATION]
TESTS = ['tests/api/reference-quality-storage.test.ts']
COMPLETENESS_TESTS = ['tests/qualification/quality.test.ts']
require, sha = base.require, base.sha
COMMIT = '591220ab2b398c8af2ed3c9a8441641fa77bfc8d'
PREDECESSORS = ({'path': 'packages/domain/src/quality-contracts.ts', 'fixture': 'tests/qualification/predecessors/quality-contracts-sql022.ts.txt', 'gitBlob': '5b5763224209e406b0f076e0ba15d2a4e83035e1', 'sha256': '21b61ae254b6633f74bf071a68301d8a5cc6f077dc3fb58d938bd22e36163a83'}, {'path': 'packages/domain/src/quality.ts', 'fixture': 'tests/qualification/predecessors/quality-sql022.ts.txt', 'gitBlob': 'bb3b725212a622fa65345fa8cb77bde706f27135', 'sha256': 'e9ef493c57c149154efd627204dde21dd1f3d7277afcbd108d5e7dd9423bace0'}, {'path': 'packages/domain/src/quality-service.ts', 'fixture': 'tests/qualification/predecessors/quality-service-sql022.ts.txt', 'gitBlob': '80160627852ff36f7c8d58f99171cce996e2a94c', 'sha256': '9d510d1cf4eb5a99c6667efad7eea9c4ed302ce450d469b77a086f428410b982'}, {'path': 'apps/api/src/repository.ts', 'fixture': 'tests/qualification/predecessors/repository-sql022.ts.txt', 'gitBlob': 'b70e95bc65dc4b9723b01948604c722b560ba82e', 'sha256': '75aa5e716c537a0caafabba08e5e3ada6aefeae3a42d11c8b942444d6073a1ee'})
PROBE = '/app/reference-quality-source-check.cjs'
REPOSITORY = 'apps/api/src/repository.ts'
NON_REPOSITORY = {'packages/domain/src/quality-contracts.ts', 'packages/domain/src/quality.ts', 'packages/domain/src/quality-service.ts'}


def sources():
    paths = {row['path'] for row in base.sources()}
    paths.update(['scripts/runtime-test-reference-quality-upgrade.py', 'packages/db/migrations/' + MIGRATION,
                  'tests/fixtures/reference-quality.ts', *TESTS, *COMPLETENESS_TESTS])
    paths.update(row['fixture'] for row in PREDECESSORS)
    paths.update(row['path'] for row in PREDECESSORS)
    pending = [ROOT / name for name in paths if name.endswith(('.ts', '.tsx'))]
    while pending:
        current = pending.pop()
        for relative in re.findall(r'''(?:from\s*|import\s*)['"](\.[^'"]+)['"]''', current.read_text()):
            candidate = (current.parent / relative).resolve()
            if not candidate.suffix:
                candidate = candidate.with_suffix('.ts') if candidate.with_suffix('.ts').is_file() else candidate / 'index.ts'
            require(candidate.is_relative_to(ROOT) and candidate.is_file(), 'Unresolved reference quality source')
            name = str(candidate.relative_to(ROOT))
            if name not in paths:
                paths.add(name)
                pending.append(candidate)
    return [{'path': name, 'sha256': sha((ROOT / name).read_bytes())} for name in sorted(paths)]


def fixtures():
    for row in PREDECESSORS:
        value = base.base.read_exact(ROOT / row['fixture'], row['sha256'])
        require(hashlib.sha1(b'blob ' + str(len(value)).encode() + b'\0' + value, usedforsecurity=False).hexdigest() == row['gitBlob'],
                'Immutable reference quality predecessor Git identity differs')


def effective_sources(measured, paths):
    require(type(measured) is list and 1 <= len(measured) <= 4096
            and all(type(row) is dict and set(row) == {'path', 'sha256'} for row in measured)
            and len({row['path'] for row in measured}) == len(measured), 'Invalid reference quality source map')
    replacements = {row['path']: row['sha256'] for row in PREDECESSORS if row['path'] in paths}
    return [{'path': row['path'], 'sha256': replacements.get(row['path'], row['sha256'])} for row in measured]


def verifier(rows):
    return ("const fs=require('node:fs'),crypto=require('node:crypto');\nconst rows=" + json.dumps(rows) + ";\n"
            "function check(){for(const row of rows)if(crypto.createHash('sha256').update(fs.readFileSync('/app/'+row.path)).digest('hex')!==row.sha256)throw new Error('REFERENCE_QUALITY_SOURCE_PHASE_MISMATCH');}\ncheck();process.on('exit',check);\n")


class Harness(base.Harness):
    def __init__(self):
        base.REPORT = REPORT
        self.reference_quality_predecessor = None
        self.reference_quality_current = None
        self.reference_quality_serial = 0
        super().__init__()
        self.report.update(command='./dev test --suite reference-quality-upgrade', profile='isolated-postgresql-reference-quality')

    def predecessor_expectations(self, measured, all_paths=False):
        stage = self.reference_quality_predecessor
        require(stage is not None and self.reference_quality_current is None, 'Undeclared reference quality predecessor readback')
        require(all(row['path'] in {r['path'] for r in stage['sources']} for row in measured), 'Readback source outside frozen inventory')
        fixtures()
        return effective_sources(measured, NON_REPOSITORY | ({REPOSITORY} if all_paths else set()))

    def native_source_expectations(self, measured):
        # Preserve the inherited SQL020 repository/approval source pins first.
        return self.predecessor_expectations(super().native_source_expectations(measured))

    def classification_native_source_expectations(self, measured):
        # Preserve the inherited SQL021 repository/approval source pins first.
        return self.predecessor_expectations(super().classification_native_source_expectations(measured))

    def reference_native_source_expectations(self, measured):
        require(self.reference_current is not None and self.reference_predecessor is None
                and self.phase == 'reference-native-tests', 'Undeclared SQL022 source readback')
        original = [row for row in self.reference_current['sources'] if row['path'].endswith('.ts')]
        require(measured == original, 'SQL022 checkout source map differs')
        return self.predecessor_expectations(measured, all_paths=True)

    def helper(self, args, *, mounts=(), **kwargs):
        stage = self.reference_quality_predecessor
        current = self.reference_quality_current
        if stage is None and current is None:
            return super().helper(args, mounts=mounts, **kwargs)
        require(not (stage is not None and current is not None) and args and args[0] == 'node', 'Invalid reference quality source phase')
        mounts = list(mounts)
        paths = NON_REPOSITORY | ({REPOSITORY} if stage is not None and self.reference_current is not None else set())
        targets = {'/app/' + p for p in paths} | {PROBE}
        require(all(not (target == fixed or target.startswith(fixed + '/') or fixed.startswith(target.rstrip('/') + '/'))
                    for _, target in mounts for fixed in targets), 'Conflicting reference quality source mount')
        fixtures()
        original = stage or current
        effective = effective_sources(original['sources'], paths) if stage is not None else [dict(row) for row in original['sources']]
        selected = []
        if stage is not None:
            for row in PREDECESSORS:
                if row['path'] in paths:
                    mounts.append((ROOT / row['fixture'], '/app/' + row['path']))
                    selected.append({**row, 'commit': COMMIT, 'readOnly': True})
        else:
            require(self.phase in ('reference-quality-completeness-tests', 'reference-quality-native-tests')
                    and self.reference_current is None and self.reference_predecessor is None
                    and self.classification_current is None and self.classification_predecessor is None
                    and self.repository_stage is None, 'Overlapping current reference quality source phase')
            paths = NON_REPOSITORY | {REPOSITORY}
        expected = [row for row in effective if row['path'] in paths]
        require(len(expected) == len(paths), 'Reference quality source inventory omits phase modules')
        self.reference_quality_serial += 1
        probe = self.folder / ('reference-quality-source-' + str(self.reference_quality_serial) + '.cjs')
        data = verifier(expected).encode()
        with probe.open('xb') as output:
            output.write(data)
        probe.chmod(0o444)
        record = {'phase': self.phase, 'stage': 'SQL001-022' if stage is not None else 'SQL023', 'result': 'RUNNING',
                  'checkoutSources': original['sources'], 'effectiveOwnedSources': expected,
                  'overrides': selected, 'verifierSha256': sha(data),
                  'repositoryPrecedence': 'SQL022 pinned module' if REPOSITORY in paths and stage is not None else 'inherited SQL018/020/021 or current SQL023'}
        self.report.setdefault('referenceQualitySourceChecks', []).append(record)
        try:
            result = super().helper([args[0], '--require', PROBE, *args[1:]], mounts=[*mounts, (probe, PROBE)], **kwargs)
            record.update(result='PASS' if result.returncode == 0 else 'NONZERO', exitStatus=result.returncode)
            return result
        except BaseException:
            record['result'] = 'FAIL'
            raise
        finally:
            record['overrideReleased'] = True
            base.base.read_exact(probe, sha(data))
            fixtures()
            for row in PREDECESSORS:
                source = next(item for item in original['sources'] if item['path'] == row['path'])
                base.base.read_exact(ROOT / row['path'], source['sha256'])
            record['sourceHashesMatched'] = True


def run_suite(h, frozen, phase, tests, expected, field):
    h.phase = phase
    h.report.update(tests=None)
    h.report[field + 'ExitStatus'] = None
    h.reference_quality_current = {'sources': frozen}
    try:
        measured = [row for row in frozen if row['path'].endswith('.ts')]
        probe = "const fs=require('node:fs'),crypto=require('node:crypto');console.log(JSON.stringify(" + json.dumps([row['path'] for row in measured]) + ".map(path=>({path,sha256:crypto.createHash('sha256').update(fs.readFileSync(path)).digest('hex')}))));"
        observed = json.loads(h.helper(['node', '-e', probe]).stdout)
        require(observed == measured, 'Actual reference quality native source bytes differ')
        h.report[field + 'SourceReadback'] = {'result': 'PASS', 'files': len(measured), 'manifestSha256': sha(json.dumps(observed, sort_keys=True).encode())}
        count = sum(len(re.findall(r'^test\(', (ROOT / name).read_text(), re.MULTILINE)) for name in tests)
        require(count == expected, 'Reference quality case inventory differs')
        tested = h.helper(['node', '--import', 'tsx', '--test', '--test-reporter=tap', '--test-concurrency=1', *tests], timeout=300, allow_failure=True)
        h.report[field + 'ExitStatus'] = tested.returncode
        h.report['tests'] = base.native_tap_totals(tested.stdout)
        require(tested.returncode == 0, 'Native reference quality suite failed; retained TAP identifies failing case')
        h.report[field] = base.tap_summary(tested.stdout, expected)
        h.report['tests'] = dict(h.report[field])
    finally:
        h.reference_quality_current = None


def execute(h):
    frozen = sources()
    fixtures()
    h.report['diagnostic_sources'] = frozen
    h.reference_quality_predecessor = {'sources': frozen}
    try:
        base.execute(h)  # Every prior native stage and refusal case remains required.
    finally:
        h.reference_quality_predecessor = None
    h.report['predecessor_reference_tests'] = dict(h.report['tests'])
    h.report['sources'] = frozen
    h.phase = 'reference-quality-predecessor'
    tables = json.loads(h.sql("SELECT json_agg(schemaname||'.'||tablename ORDER BY schemaname,tablename) FROM pg_tables WHERE schemaname IN('public','gc_authn','gc_authority') AND tablename<>'schema_migrations';"))
    before = base.canonical_snapshot(h, tables)
    ledger = json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;'))
    require(len(NAMES) == 22 and [row['name'] for row in ledger] == NAMES, 'Expected exact SQL001–022 predecessor')
    require(all(row['checksum'] == sha((MIGRATIONS / row['name']).read_bytes()) for row in ledger), 'Reference quality predecessor checksum differs')
    target = h.folder / 'reference-quality-target'
    target.mkdir()
    for name in [*NAMES, MIGRATION]:
        shutil.copyfile(MIGRATIONS / name, target / name)
    h.phase = 'reference-quality-upgrade'
    migrated = h.migrate(target)
    require(re.findall(r'^Applied (.+)$', migrated.stdout, re.MULTILINE) == [MIGRATION], 'Expected exact SQL023 application')
    require(base.canonical_snapshot(h, tables) == before, 'Reference quality changed predecessor rows')
    after = json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;'))
    require(len(after) == 23 and after[:22] == ledger and after[-1]['name'] == MIGRATION
            and after[-1]['checksum'] == sha((MIGRATIONS / MIGRATION).read_bytes()), 'Reference quality changed predecessor ledger')
    require('Applied' not in h.migrate(target).stdout, 'Reference quality replay reapplied migration')
    require(base.canonical_snapshot(h, tables) == before, 'Reference quality replay changed predecessor rows')
    require(json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;')) == after, 'Reference quality replay changed ledger')
    h.report['referenceQualityUpgradeBaseline'] = [{'table': name, **row} for name, row in before.items()]
    h.report['checks'].append('Exact SQL022→023 and inert replay preserve every predecessor row and full checksum/timestamp ledger')
    run_suite(h, frozen, 'reference-quality-completeness-tests', COMPLETENESS_TESTS, 15, 'completenessTests')
    run_suite(h, frozen, 'reference-quality-native-tests', TESTS, 21, 'referenceQualityTests')
    require(sources() == frozen, 'Reference quality source changed during native qualification')
    h.report['migrations'] = [{'name': name, 'sha256': sha((MIGRATIONS / name).read_bytes())} for name in [*NAMES, MIGRATION]]
    h.report['limitations'] = [
        'Disposable PostgreSQL storage/service only. Measurements are explicit native fixtures, not source executor, HTTP, Temporal or browser evidence.',
        'All predecessor gates execute. SQL022 quality modules are exact 591220a fixtures; SQL018/020/021 repository overrides retain their earlier precedence.',
        'SQL023 runs the current source tree, the original fifteen completeness cases and twenty-one reference cases with real source-byte readbacks.',
        'Same-millisecond head collision is an explicitly owner-authored rollback-contained timestamp fixture, not a production clock assertion.',
        'No two-minute expired-lease wait or live external source execution is claimed; source execution is a separate qualification.',
        'Reports, source bindings and bounded raw TAP remain private. No shared application service or preexisting resource is mutated.']


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
        h.report.update(result='FAIL' if failed else 'PASS', recorded_at=datetime.now(timezone.utc).isoformat(), evidence_directory=str(h.folder.relative_to(ROOT)))
        h.report['private_logs'] = [{'path': str(p.relative_to(ROOT)), 'sha256': sha(p.read_bytes())} for p in sorted(h.folder.glob('*.log'))]
        h.save(final=True)
    print(json.dumps({'result': h.report['result'], 'report': str(REPORT.relative_to(ROOT))}))
    return int(failed)


if __name__ == '__main__':
    raise SystemExit(main())
