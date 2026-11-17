#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Candidate SQL023→024 structure gate. All predecessors; owned disposable DB only."""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('structure_upgrade_base', ROOT / 'scripts/runtime-test-reference-quality-upgrade.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
repaired = base.repaired
REPORT = ROOT / '.local/evidence/reference-structure-upgrade.json'
MIGRATION = '024_reference_structures.sql'
MIGRATIONS = ROOT / 'packages/db/migrations'
NAMES = [*base.NAMES, base.MIGRATION]
TESTS = ['tests/api/reference-structure-storage.test.ts', 'tests/api/reference-structure-concurrency.test.ts']
require, sha = base.require, base.sha
canonical_snapshot = base.base.canonical_snapshot
native_tap_totals = base.base.native_tap_totals
tap_summary = base.base.tap_summary
COMMIT = '6b090767d3d7ca2a1645b81c97a96354d3b26358'
PREDECESSORS = ({'path': 'packages/domain/src/approval-service.ts', 'fixture': 'tests/qualification/predecessors/approval-service-sql023.ts.txt', 'gitBlob': '0611657abc7af29c021105defd4397fdc3a56872', 'sha256': 'c9a2a002a1e9bb54c114778c3e49adac1bf98ce34728a87f1a16d140e9e2ed83'}, {'path': 'apps/api/src/approvals.ts', 'fixture': 'tests/qualification/predecessors/approvals-sql023.ts.txt', 'gitBlob': '4bb24777f769df13f2bedb5fa91dba5b24f69598', 'sha256': 'b03e2e6e7b081d8ae78222e4b3b9557547a136ee116534f458a23950ac33857d'}, {'path': 'apps/api/src/repository.ts', 'fixture': 'tests/qualification/predecessors/repository-sql023.ts.txt', 'gitBlob': 'a2734a8d7999e2bb66aedff2c6f80e44e7030260', 'sha256': '3e48472c23f874bf8eb478c8ecb1c88f380c5649df12d56c1929a6458c352048'})
NATIVE_BINDINGS = ({'path': 'packages/domain/src/quality-service.ts', 'fixture': 'tests/qualification/predecessors/quality-service-sql029.ts.txt', 'gitBlob': '289dfdd222f7949d1aaabdb35c46cc48b7a5e975', 'sha256': '6a7691da7bf328341277ad0cf6737f44b5fd25cc61dbb97b2b345ecec14e1a73', 'commit': 'fca6bb94a8bd87965c4bf614ae492b85235f4ea9'}, {'path': 'apps/api/src/repository.ts', 'fixture': 'tests/qualification/predecessors/repository-sql026.ts.txt', 'gitBlob': '074a6ac9b0e1ba33e06197009386563d92e7ea33', 'sha256': '9cb5f78fe0d70e1d614f7940ed3de4e44394ae47befd817c2f7816f08fe654f5', 'commit': '629e475c2fb00198b51e673074eabd0aa5bcff48'})
PROBE = '/app/reference-structure-source-check.cjs'
REPOSITORY = 'apps/api/src/repository.ts'


def sources():
    paths = {row['path'] for row in base.sources()}
    paths.update(['scripts/runtime-test-reference-structure-upgrade.py', 'packages/db/migrations/' + MIGRATION,
                  'packages/domain/src/reference-structure.ts', 'packages/domain/src/reference-structure-contracts.ts',
                  'packages/domain/src/reference-structure-service.ts', 'apps/api/src/reference-structure.ts',
                  'apps/api/src/reference-structure-publication.ts', 'tests/fixtures/reference-structure.ts', *TESTS])
    paths.update(row['fixture'] for row in (*PREDECESSORS,*NATIVE_BINDINGS))
    paths.update(row['path'] for row in PREDECESSORS)
    pending = [ROOT / path for path in paths if path.endswith(('.ts', '.tsx'))]
    while pending:
        current = pending.pop()
        text=current.read_text()+'\n'+'\n'.join((ROOT/row['fixture']).read_text() for row in NATIVE_BINDINGS if row['path']==str(current.relative_to(ROOT)))
        for relative in re.findall(r'''(?:from\s*|import\s*)['"](\.[^'"]+)['"]''', text):
            candidate = (current.parent / relative).resolve()
            if candidate.suffix == '.js' and not candidate.exists():
                candidate = candidate.with_suffix('.ts')
            if not candidate.suffix:
                candidate = candidate.with_suffix('.ts') if candidate.with_suffix('.ts').is_file() else candidate / 'index.ts'
            require(candidate.is_relative_to(ROOT) and candidate.is_file(), 'Unresolved structure source')
            name = str(candidate.relative_to(ROOT))
            if name not in paths:
                paths.add(name)
                pending.append(candidate)
    return [{'path': path, 'sha256': sha((ROOT / path).read_bytes())} for path in sorted(paths)]


def fixtures():
    for row in (*PREDECESSORS,*NATIVE_BINDINGS):
        data = base.base.base.read_exact(ROOT / row['fixture'], row['sha256'])
        require(hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data, usedforsecurity=False).hexdigest() == row['gitBlob'],
                'Structure predecessor Git identity differs')


def effective_sources(measured, paths):
    require(type(measured) is list and 1 <= len(measured) <= 4096
            and all(type(row) is dict and set(row) == {'path', 'sha256'} for row in measured)
            and len({row['path'] for row in measured}) == len(measured), 'Invalid structure source map')
    replacements = {row['path']: row['sha256'] for row in PREDECESSORS if row['path'] in paths}
    require(set(replacements).issubset({row['path'] for row in measured}), 'Structure source map omits predecessor modules')
    return [{'path': row['path'], 'sha256': replacements.get(row['path'], row['sha256'])} for row in measured]


def native_sources(measured):
    fixtures()
    require(type(measured) is list and 1 <= len(measured) <= 4096
            and all(type(row) is dict and set(row)=={'path','sha256'} for row in measured)
            and len({row['path'] for row in measured})==len(measured), 'Invalid historical native source map')
    replacements={row['path']:row['sha256'] for row in NATIVE_BINDINGS}
    require(set(replacements).issubset({row['path'] for row in measured}), 'Native source map omits retained modules')
    return [{**row,'sha256':replacements.get(row['path'],row['sha256'])} for row in measured]


def verifier(rows):
    return ("const fs=require('node:fs'),crypto=require('node:crypto');\nconst rows=" + json.dumps(rows) + ";\n"
            "function check(){for(const row of rows)if(crypto.createHash('sha256').update(fs.readFileSync('/app/'+row.path)).digest('hex')!==row.sha256)throw new Error('REFERENCE_STRUCTURE_SOURCE_PHASE_MISMATCH');}\ncheck();process.on('exit',check);\n")


class Harness(base.Harness):
    def __init__(self):
        base.REPORT = REPORT
        self.structure_predecessor = None
        self.structure_current = None
        self.structure_serial = 0
        super().__init__()
        self.report.update(command='./dev test --suite reference-structure-upgrade', profile='isolated-postgresql-reference-structure')

    def reference_native_source_expectations(self, measured):
        require(self.structure_predecessor is not None and self.structure_current is None, 'Undeclared structure predecessor')
        # The inherited SQL022 repository pin wins; only its approval service/router need SQL023 bytes.
        return effective_sources(super().reference_native_source_expectations(measured), {row['path'] for row in PREDECESSORS} - {REPOSITORY})

    def reference_quality_native_source_expectations(self, measured):
        require(self.structure_predecessor is not None and self.structure_current is None
                and self.reference_quality_current is not None and self.reference_quality_predecessor is None
                and self.phase in ('reference-quality-completeness-tests', 'reference-quality-native-tests'), 'Undeclared SQL023 source readback')
        original = [row for row in self.reference_quality_current['sources'] if row['path'].endswith('.ts')]
        require(measured == original, 'SQL023 original source map differs')
        fixtures()
        return effective_sources(super().reference_quality_native_source_expectations(measured), {row['path'] for row in PREDECESSORS})

    def helper(self, args, *, mounts=(), **kwargs):
        # All older SQL018/020/021 overlays keep their precedence and measured probes unchanged.
        stage = (self.reference_current or self.reference_quality_current) if self.structure_predecessor is not None else None
        current = self.structure_current
        if stage is None and current is None:
            return super().helper(args, mounts=mounts, **kwargs)
        require(not (stage is not None and current is not None) and args and args[0] == 'node', 'Invalid structure source phase')
        paths = {row['path'] for row in PREDECESSORS} | ({row['path'] for row in NATIVE_BINDINGS} if current is not None else set())
        if stage is not None and self.reference_current is not None:
            require(self.phase == 'reference-native-tests' and self.reference_quality_predecessor is not None, 'Invalid SQL022 structure predecessor stage')
            paths.remove(REPOSITORY)
        elif stage is not None:
            require(self.phase in ('reference-quality-completeness-tests', 'reference-quality-native-tests'), 'Invalid SQL023 structure predecessor stage')
        else:
            require(self.phase in ('structure-reference-tests', 'structure-reference-quality-tests', 'structure-native-tests')
                    and self.reference_current is None and self.reference_predecessor is None
                    and self.reference_quality_current is None and self.reference_quality_predecessor is None
                    and self.classification_current is None and self.classification_predecessor is None
                    and self.repository_stage is None, 'Overlapping current structure source phase')
        mounts = list(mounts)
        targets = {'/app/' + path for path in paths} | {PROBE}
        require(all(not (target == fixed or target.startswith(fixed + '/') or fixed.startswith(target.rstrip('/') + '/'))
                    for _, target in mounts for fixed in targets), 'Conflicting structure source mount')
        fixtures()
        original = stage or current
        effective = effective_sources(original['sources'], paths) if stage is not None else native_sources(original['sources'])
        selected = []
        if stage is not None:
            for row in PREDECESSORS:
                if row['path'] in paths:
                    # An unchanged checkout needs no redundant/conflicting nested file mount.
                    checkout = next(item for item in original['sources'] if item['path'] == row['path'])
                    if checkout['sha256'] != row['sha256']:
                        mounts.append((ROOT / row['fixture'], '/app/' + row['path']))
                    selected.append({**row, 'commit': COMMIT, 'readOnly': True, 'mountRequired': checkout['sha256'] != row['sha256']})
        if current is not None:
            for row in NATIVE_BINDINGS:
                mounts.append((ROOT/row['fixture'],'/app/'+row['path']))
                selected.append({**row,'readOnly':True,'mountRequired':True})
        expected = [row for row in effective if row['path'] in paths]
        require(len(expected) == len(paths), 'Structure inventory omits phase modules')
        self.structure_serial += 1
        probe = self.folder / ('structure-source-' + str(self.structure_serial) + '.cjs')
        data = verifier(expected).encode()
        with probe.open('xb') as output:
            output.write(data)
        probe.chmod(0o444)
        record = {'phase': self.phase, 'stage': 'SQL022/023' if stage is not None else 'SQL024', 'result': 'RUNNING',
                  'checkoutSources': original['sources'], 'effectiveOwnedSources': expected, 'overrides': selected, 'verifierSha256': sha(data)}
        self.report.setdefault('structureSourceChecks', []).append(record)
        try:
            result = super().helper([args[0], '--require', PROBE, *args[1:]], mounts=[*mounts, (probe, PROBE)], **kwargs)
            record.update(result='PASS' if result.returncode == 0 else 'NONZERO', exitStatus=result.returncode)
            return result
        except BaseException:
            record['result'] = 'FAIL'
            raise
        finally:
            record['overrideReleased'] = True
            base.base.base.read_exact(probe, sha(data))
            fixtures()
            for row in (*PREDECESSORS,*NATIVE_BINDINGS):
                checkout = next(item for item in original['sources'] if item['path'] == row['path'])
                base.base.base.read_exact(ROOT / row['path'], checkout['sha256'])
            record['sourceHashesMatched'] = True


def run_suite(h, frozen, phase, tests, expected, field):
    h.phase = phase
    h.report.update(tests=None)
    h.report[field + 'ExitStatus'] = None
    h.structure_current = {'sources': frozen}
    try:
        measured = [row for row in frozen if row['path'].endswith('.ts')]
        probe = "const fs=require('node:fs'),crypto=require('node:crypto');console.log(JSON.stringify(" + json.dumps([row['path'] for row in measured]) + ".map(path=>({path,sha256:crypto.createHash('sha256').update(fs.readFileSync(path)).digest('hex')}))));"
        observed = json.loads(h.helper(['node', '-e', probe]).stdout)
        require(observed == native_sources(measured), 'Actual structure native source bytes differ')
        h.report[field + 'SourceReadback'] = {'result': 'PASS', 'files': len(measured), 'manifestSha256': sha(json.dumps(observed, sort_keys=True).encode())}
        count = sum(len(re.findall(r'^test\(', (ROOT / name).read_text(), re.MULTILINE)) for name in tests)
        require(count == expected, 'Structure case inventory differs')
        tested = h.helper(['node', '--import', 'tsx', '--test', '--test-reporter=tap', '--test-concurrency=1', *tests], timeout=300, allow_failure=True)
        h.report[field + 'ExitStatus'] = tested.returncode
        h.report['tests'] = native_tap_totals(tested.stdout)
        require(tested.returncode == 0, 'Native structure suite failed; retained TAP identifies failing case')
        h.report[field] = tap_summary(tested.stdout, expected)
        h.report['tests'] = dict(h.report[field])
    finally:
        h.structure_current = None


def execute(h):
    frozen = sources()
    fixtures()
    h.report['diagnostic_sources'] = frozen
    h.structure_predecessor = {'sources': frozen}
    try:
        base.execute(h)
    finally:
        h.structure_predecessor = None
    h.report['predecessor_reference_quality_tests'] = dict(h.report['tests'])
    h.report['sources'] = frozen
    h.phase = 'structure-predecessor'
    tables = json.loads(h.sql("SELECT json_agg(schemaname||'.'||tablename ORDER BY schemaname,tablename) FROM pg_tables WHERE schemaname IN('public','gc_authn','gc_authority') AND tablename<>'schema_migrations';"))
    before = canonical_snapshot(h, tables)
    ledger = json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;'))
    require((repaired.before(h, ledger, NAMES) if repaired.active(h) else len(NAMES) == 23 and [row['name'] for row in ledger] == NAMES), 'Expected exact SQL001–023 predecessor')
    require(all(row['checksum'] == sha((MIGRATIONS / row['name']).read_bytes()) for row in ledger), 'Structure predecessor checksum differs')
    target = h.folder / 'structure-target'
    target.mkdir()
    for name in repaired.names(h, [*NAMES, MIGRATION]):
        shutil.copyfile(MIGRATIONS / name, target / name)
    h.phase = 'structure-upgrade'
    migrated = h.migrate(target)
    require(re.findall(r'^Applied (.+)$', migrated.stdout, re.MULTILINE) == [MIGRATION], 'Expected exact SQL024 application')
    require(canonical_snapshot(h, tables) == before, 'Structure changed predecessor rows')
    after = json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;'))
    require((repaired.after(h, ledger, after, NAMES, MIGRATION) if repaired.active(h) else len(after) == 24 and after[:23] == ledger and after[-1]['name'] == MIGRATION
            and after[-1]['checksum'] == sha((MIGRATIONS / MIGRATION).read_bytes())), 'Structure changed predecessor ledger')
    require('Applied' not in h.migrate(target).stdout, 'Structure replay reapplied migration')
    require(canonical_snapshot(h, tables) == before, 'Structure replay changed predecessor rows')
    require(json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;')) == after, 'Structure replay changed ledger')
    h.report['structureUpgradeBaseline'] = [{'table': name, **row} for name, row in before.items()]
    h.report['checks'].append('Exact SQL023→024 and inert replay preserve every predecessor row and full checksum/timestamp ledger')
    run_suite(h, frozen, 'structure-reference-tests', ['tests/api/reference-data-storage.test.ts'], 18, 'structureReferenceTests')
    run_suite(h, frozen, 'structure-reference-quality-tests', ['tests/api/reference-quality-storage.test.ts'], 21, 'structureQualityTests')
    run_suite(h, frozen, 'structure-native-tests', TESTS, 30, 'structureTests')
    require(sources() == frozen, 'Structure source changed during native qualification')
    repaired.complete(h, [*NAMES, MIGRATION])
    h.report['migrations'] = [{'name': name, 'sha256': sha((MIGRATIONS / name).read_bytes())} for name in repaired.names(h, [*NAMES, MIGRATION])]
    h.report['limitations'] = [
        'Disposable PostgreSQL/service only; no source executor, HTTP conditional response, Temporal or browser evidence.',
        'All predecessor gates execute with exact prior overlays. SQL022/023 approval modules use immutable6b090767; SQL022 repository keeps its prior immutable pin.',
        'SQL024 retains exact pre-volume service and SQL026 repository with full readback and independent startup/exit verification, eighteen original reference and twenty-one reference-quality cases plus thirty structure cases (including eight observed lock races/ordering/budget controls).',
        'Bounded real clock wait checks an effective boundary; synthetic owner-only projection suppression is rollback-contained and explicitly hostile.',
        'Reports and bounded raw TAP stay private. No shared application services or preexisting resources are mutated.']


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
