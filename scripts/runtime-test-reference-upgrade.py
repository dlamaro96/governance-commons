#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SQL021→022 reference publications; full predecessors, owned disposable DB only."""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('reference_upgrade_base', ROOT / 'scripts/runtime-test-classification-upgrade.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
REPORT = ROOT / '.local/evidence/reference-upgrade.json'
MIGRATION = '022_reference_publication.sql'
MIGRATIONS = ROOT / 'packages/db/migrations'
NAMES = [*base.NAMES, base.MIGRATION]
TESTS = ['tests/api/reference-data-storage.test.ts']
require, sha = base.require, base.sha
COMMIT = '49c166c2f2e2da9a3e9723880b7fb239af20f684'
PREDECESSORS = (
    {'path': 'packages/domain/src/approval-service.ts', 'fixture': 'tests/qualification/predecessors/approval-service-sql021.ts.txt',
     'gitBlob': 'd9ee7215cc57a38fd48b37b1a6218469b297add3', 'sha256': '165033f5eefc472e2cb5b38be066b19f76fad996c70999aedf516282bba4700a'},
    {'path': 'apps/api/src/approvals.ts', 'fixture': 'tests/qualification/predecessors/approvals-sql021.ts.txt',
     'gitBlob': '683a859b3efb01c958be78cef424b26b5351ab7d', 'sha256': 'fdfb94001e453288121e319da66a5e2915da537997b43f256df416ddd00086e4'},
    {'path': 'apps/api/src/repository.ts', 'fixture': 'tests/qualification/predecessors/repository-sql021.ts.txt',
     'gitBlob': '38e05401f173d1890e837878ac581bbb6a0e9d15', 'sha256': '4a9701fb5638893dda51dedb4c4093fcf401467e6658e218075cb8ec9859c73f'},
)
PROBE = '/app/reference-source-check.cjs'
# Exact fixed-width row-hash aggregation retains duplicate multiplicity without
# materializing predecessor populations as one large JSON array.
canonical_snapshot = base.base.base.canonical_snapshot
native_tap_totals = base.native_tap_totals
tap_summary = base.base.base.base.tap_summary


def sources():
    paths = {row['path'] for row in base.sources()}
    paths.update(['scripts/runtime-test-reference-upgrade.py', 'packages/db/migrations/' + MIGRATION,
                  'packages/domain/src/reference-data.ts', 'packages/domain/src/reference-data-contracts.ts',
                  'packages/domain/src/reference-data-service.ts', 'apps/api/src/reference-data.ts',
                  'apps/api/src/reference-data-publication.ts', *TESTS])
    paths.update(row['fixture'] for row in PREDECESSORS)
    paths.update(row['path'] for row in PREDECESSORS)
    pending = [ROOT / name for name in paths if name.endswith(('.ts', '.tsx'))]
    while pending:
        current = pending.pop()
        for relative in re.findall(r'''(?:from\s*|import\s*)['"](\.[^'"]+)['"]''', current.read_text()):
            candidate = (current.parent / relative).resolve()
            if not candidate.suffix:
                candidate = candidate.with_suffix('.ts') if candidate.with_suffix('.ts').is_file() else candidate / 'index.ts'
            require(candidate.is_relative_to(ROOT) and candidate.is_file(), 'Unresolved local reference source')
            name = str(candidate.relative_to(ROOT))
            if name not in paths:
                paths.add(name)
                pending.append(candidate)
    return [{'path': name, 'sha256': sha((ROOT / name).read_bytes())} for name in sorted(paths)]


def fixtures():
    for row in PREDECESSORS:
        value = base.read_exact(ROOT / row['fixture'], row['sha256'])
        require(hashlib.sha1(b'blob ' + str(len(value)).encode() + b'\0' + value, usedforsecurity=False).hexdigest() == row['gitBlob'],
                'Immutable reference predecessor Git identity differs')


def effective_sources(measured):
    require(type(measured) is list and 3 <= len(measured) <= 4096
            and all(type(row) is dict and set(row) == {'path', 'sha256'} for row in measured)
            and len({row['path'] for row in measured}) == len(measured), 'Invalid reference source map')
    replacements = {row['path']: row['sha256'] for row in PREDECESSORS}
    require(set(replacements).issubset({row['path'] for row in measured}), 'Reference source map omits phase modules')
    return [{'path': row['path'], 'sha256': replacements.get(row['path'], row['sha256'])} for row in measured]


def verifier(rows):
    return ("const fs=require('node:fs'),crypto=require('node:crypto');\nconst rows=" + json.dumps(rows) + ";\n"
            "function check(){for(const row of rows)if(crypto.createHash('sha256').update(fs.readFileSync('/app/'+row.path)).digest('hex')!==row.sha256)throw new Error('REFERENCE_SOURCE_PHASE_MISMATCH');}\ncheck();process.on('exit',check);\n")


class Harness(base.Harness):
    def __init__(self):
        base.REPORT = REPORT
        self.reference_predecessor = None
        self.reference_current = None
        self.reference_serial = 0
        super().__init__()
        self.report.update(command='./dev test --suite reference-upgrade', profile='isolated-postgresql-reference')

    def reference_native_source_expectations(self, measured):
        # A later isolated forward gate may declare exact predecessor bytes.
        return measured

    def classification_native_source_expectations(self, measured):
        require(self.reference_predecessor is not None and self.reference_current is None
                and self.classification_predecessor is None and self.classification_current is not None
                and self.phase == 'classification-native-tests' and self.repository_stage is None,
                'Undeclared reference predecessor source-readback phase')
        original = [row for row in self.classification_current['sources'] if row['path'].endswith('.ts')]
        require(measured == original, 'Reference predecessor original source map differs')
        fixtures()
        return effective_sources(measured)

    def helper(self, args, *, mounts=(), **kwargs):
        # SQL001–020 remains entirely under the prior classification/quality
        # overlays. In particular this layer never overrides SQL018's repository.
        if self.reference_predecessor is not None and self.classification_predecessor is not None:
            require(self.reference_current is None and self.classification_current is None,
                    'Overlapping reference source stages')
            return super().helper(args, mounts=mounts, **kwargs)
        stage = self.classification_current if self.reference_predecessor is not None else None
        current = self.reference_current
        if stage is None and current is None:
            return super().helper(args, mounts=mounts, **kwargs)
        require(not (stage is not None and current is not None) and self.repository_stage is None
                and self.classification_predecessor is None and args and args[0] == 'node',
                'Invalid reference Node source phase')
        require(self.phase == ('classification-native-tests' if stage is not None else 'reference-native-tests'),
                'Unexpected reference source phase')
        mounts = list(mounts)
        fixtures()
        original = stage or current
        effective = effective_sources(original['sources']) if stage is not None else [dict(row) for row in original['sources']]
        if current is not None:
            native = self.reference_native_source_expectations([row for row in effective if row['path'].endswith('.ts')])
            require([row['path'] for row in native] == [row['path'] for row in effective if row['path'].endswith('.ts')],
                    'Reference effective source paths differ')
            expected = {row['path']: row['sha256'] for row in native}
            effective = [{**row, 'sha256': expected.get(row['path'], row['sha256'])} for row in effective]
        targets = ['/app/' + row['path'] for row in PREDECESSORS] + [PROBE]
        declared = {('/app/' + row['path']): row['sha256'] for row in effective
                    if current is not None and row['sha256'] != next(item['sha256'] for item in original['sources'] if item['path'] == row['path'])}
        for file, target in mounts:
            for fixed in targets:
                if target == fixed or target.startswith(fixed + '/') or fixed.startswith(target.rstrip('/') + '/'):
                    require(target == fixed and target in declared, 'Conflicting reference predecessor mount')
                    base.read_exact(file, declared[target])
        selected = []
        if stage is not None:
            for row in PREDECESSORS:
                mounts.append((ROOT / row['fixture'], '/app/' + row['path']))
                selected.append({**row, 'commit': COMMIT, 'readOnly': True})
            # The inherited classification expectation hook binds these same
            # effective bytes while preserving its original checkout snapshot.
        expected = [row for row in effective if row['path'] in {item['path'] for item in PREDECESSORS}]
        require(len(expected) == 3, 'Reference phase inventory omits modules')
        self.reference_serial += 1
        probe = self.folder / ('reference-source-' + str(self.reference_serial) + '.cjs')
        data = verifier(expected).encode()
        with probe.open('xb') as output:
            output.write(data)
        probe.chmod(0o444)
        record = {'phase': self.phase, 'stage': 'SQL021' if stage is not None else 'SQL022', 'result': 'RUNNING',
                  'checkoutSources': original['sources'], 'effectiveSources': effective, 'overrides': selected,
                  'verifierSha256': sha(data)}
        self.report.setdefault('referenceSourceChecks', []).append(record)
        try:
            result = super().helper([args[0], '--require', PROBE, *args[1:]], mounts=[*mounts, (probe, PROBE)], **kwargs)
            record.update(result='PASS' if result.returncode == 0 else 'NONZERO', exitStatus=result.returncode)
            return result
        except BaseException:
            record['result'] = 'FAIL'
            raise
        finally:
            record['overrideReleased'] = True
            base.read_exact(probe, sha(data))
            fixtures()
            for row in PREDECESSORS:
                checkout = next(item for item in original['sources'] if item['path'] == row['path'])
                base.read_exact(ROOT / row['path'], checkout['sha256'])
            record['sourceHashesMatched'] = True


def execute(h):
    frozen = sources()
    fixtures()
    h.report['diagnostic_sources'] = frozen
    h.reference_predecessor = {'sources': frozen}
    try:
        base.execute(h)  # All predecessor migrations, refusal probes and native suites remain mandatory.
    finally:
        h.reference_predecessor = None
    h.report['predecessor_classification_tests'] = dict(h.report['tests'])
    h.report['sources'] = frozen
    h.phase = 'reference-predecessor'
    tables = json.loads(h.sql("SELECT json_agg(schemaname||'.'||tablename ORDER BY schemaname,tablename) FROM pg_tables WHERE schemaname IN('public','gc_authn','gc_authority') AND tablename<>'schema_migrations';"))
    before = canonical_snapshot(h, tables)
    ledger = json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;'))
    require(len(NAMES) == 21 and [row['name'] for row in ledger] == NAMES, 'Expected exact SQL001–021 predecessor')
    require(all(row['checksum'] == sha((MIGRATIONS / row['name']).read_bytes()) for row in ledger), 'Reference predecessor checksum differs')
    target = h.folder / 'reference-target'
    target.mkdir()
    for name in [*NAMES, MIGRATION]:
        shutil.copyfile(MIGRATIONS / name, target / name)
    h.phase = 'reference-upgrade'
    migrated = h.migrate(target)
    require(re.findall(r'^Applied (.+)$', migrated.stdout, re.MULTILINE) == [MIGRATION], 'Expected exact SQL022 application')
    require(canonical_snapshot(h, tables) == before, 'Reference upgrade changed predecessor canonical/history rows')
    after = json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;'))
    require(len(after) == 22 and after[:21] == ledger and after[-1]['name'] == MIGRATION
            and after[-1]['checksum'] == sha((MIGRATIONS / MIGRATION).read_bytes()), 'Reference changed predecessor ledger')
    require('Applied' not in h.migrate(target).stdout, 'Reference replay reapplied migration')
    require(canonical_snapshot(h, tables) == before, 'Reference replay changed predecessor data')
    require(json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;')) == after, 'Reference replay changed ledger')
    h.report['referenceUpgradeBaseline'] = [{'table': name, **row} for name, row in before.items()]
    h.report['checks'].append('Exact SQL021→022 application and inert replay preserve every predecessor row and full checksum ledger')
    h.phase = 'reference-native-tests'
    h.report.update(tests=None, referenceNativeExitStatus=None)
    h.reference_current = {'sources': frozen}
    try:
        measured = [row for row in frozen if row['path'].endswith('.ts')]
        probe = "const fs=require('node:fs'),crypto=require('node:crypto');console.log(JSON.stringify(" + json.dumps([row['path'] for row in measured]) + ".map(path=>({path,sha256:crypto.createHash('sha256').update(fs.readFileSync(path)).digest('hex')}))));"
        observed = json.loads(h.helper(['node', '-e', probe]).stdout)
        expected_sources = h.reference_native_source_expectations(measured)
        require(observed == expected_sources, 'Actual reference native source bytes differ')
        h.report['referenceNativeSourceReadback'] = {'result': 'PASS', 'files': len(measured), 'checkoutManifestSha256': sha(json.dumps(measured, sort_keys=True).encode()), 'manifestSha256': sha(json.dumps(observed, sort_keys=True).encode())}
        expected = sum(len(re.findall(r'^test\(', (ROOT / name).read_text(), re.MULTILINE)) for name in TESTS)
        require(expected == 18, 'Expected eighteen native reference cases')
        tested = h.helper(['node', '--import', 'tsx', '--test', '--test-reporter=tap', '--test-concurrency=1', *TESTS], timeout=240, allow_failure=True)
        h.report['referenceNativeExitStatus'] = tested.returncode
        h.report['tests'] = native_tap_totals(tested.stdout)
        require(tested.returncode == 0, 'Native reference suite failed; retained TAP identifies failing case')
        h.report['tests'] = tap_summary(tested.stdout, expected)
    finally:
        h.reference_current = None
    require(sources() == frozen, 'Reference source changed during native qualification')
    h.report['migrations'] = [{'name': name, 'sha256': sha((MIGRATIONS / name).read_bytes())} for name in [*NAMES, MIGRATION]]
    h.report['limitations'] = [
        'Disposable PostgreSQL only: protected publication, independent decisions, real service reads and exact projection/history; no shared runtime mutation.',
        'SQL021 predecessor executes exact 49c166c service/router/repository bytes; existing SQL020 and SQL018 overlays retain precedence. referenceSourceChecks binds checkout and effective bytes.',
        'SQL022 phase executes current mounted sources with startup/exit checks and independent full source readback; all predecessor tests remain mandatory.',
        'Real bounded clock waits exercise effective-time boundaries; no timestamp mutation or simulated publication success.',
        'HTTP conditional responses, Temporal delivery/restart, browser/accessibility, external sources, crosswalks and data validation are separate qualifications. Raw reports remain private.']


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
