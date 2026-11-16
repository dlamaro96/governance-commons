#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""SQL020→021 native metadata classification; owned disposable PostgreSQL only."""
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('classification_upgrade_base', ROOT / 'scripts/runtime-test-lineage-upgrade.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
REPORT = ROOT / '.local/evidence/classification-upgrade.json'
MIGRATION = '021_classification_review.sql'
MIGRATIONS = ROOT / 'packages/db/migrations'
NAMES = [*base.NAMES, base.MIGRATION]
TESTS = ['tests/api/classification-storage.test.ts']
require, sha = base.require, base.sha
COMMIT = '88ee24835132e273aa3c67a95a213f79212deb8f'
REPOSITORY = 'apps/api/src/repository.ts'
PREDECESSORS = (
    {'path': 'packages/domain/src/approval-service.ts', 'fixture': 'tests/qualification/predecessors/approval-service-sql020.ts.txt',
     'gitBlob': '574d0754c4c5d814e6006cbc2014c8724071a188', 'sha256': 'c0bdee3d1a7f1ae91982fe34503282ee144ff4f1231575799ac89586fa1fa0f4'},
    {'path': 'apps/api/src/approvals.ts', 'fixture': 'tests/qualification/predecessors/approvals-sql020.ts.txt',
     'gitBlob': 'c34509d33e97a7849a81a96f04ecf30b9ca4300a', 'sha256': 'd276b51fac67659c45111722820ffb7798731d3540e455659df8595530356ce3'},
    {'path': REPOSITORY, 'fixture': 'tests/qualification/predecessors/repository-sql020.ts.txt',
     'gitBlob': '179df94770bb2f51d983737c7134f29ce338f10f', 'sha256': 'b7ac63819810bf1df411307537d114525f284c489384e8db570626c92ccb2a08'},
)
PROBE = '/app/classification-source-check.cjs'


def sources():
    paths = {row['path'] for row in base.sources()}
    paths.update(['scripts/runtime-test-classification-upgrade.py', 'packages/db/migrations/' + MIGRATION,
                  'packages/domain/src/classification.ts', 'packages/domain/src/classification-contracts.ts',
                  'packages/domain/src/classification-service.ts', 'apps/api/src/classification.ts', *TESTS])
    paths.update(row['fixture'] for row in PREDECESSORS)
    paths.update(row['path'] for row in PREDECESSORS)
    pending = [ROOT / name for name in paths if name.endswith(('.ts', '.tsx'))]
    while pending:
        current = pending.pop()
        for relative in re.findall(r'''(?:from\s*|import\s*)['"](\.[^'"]+)['"]''', current.read_text()):
            candidate = (current.parent / relative).resolve()
            if not candidate.suffix:
                candidate = candidate.with_suffix('.ts') if candidate.with_suffix('.ts').is_file() else candidate / 'index.ts'
            require(candidate.is_relative_to(ROOT) and candidate.is_file(), 'Unresolved local classification source')
            name = str(candidate.relative_to(ROOT))
            if name not in paths:
                paths.add(name)
                pending.append(candidate)
    return [{'path': name, 'sha256': sha((ROOT / name).read_bytes())} for name in sorted(paths)]


def read_exact(path, expected):
    require(not path.is_symlink() and path.is_file() and 0 < path.stat().st_size <= 262144,
            'Classification qualification source unavailable')
    with path.open('rb') as source:
        value = source.read(262145)
    require(0 < len(value) <= 262144 and sha(value) == expected, 'Classification qualification source changed')
    return value


def verifier(rows):
    return ("const fs=require('node:fs'),crypto=require('node:crypto');\nconst rows=" + json.dumps(rows) + ";\n"
            "function check(){for(const row of rows)if(crypto.createHash('sha256').update(fs.readFileSync('/app/'+row.path)).digest('hex')!==row.sha256)throw new Error('CLASSIFICATION_SOURCE_PHASE_MISMATCH');}\ncheck();process.on('exit',check);\n")


def native_tap_totals(output):
    """Retain actual current-suite counts, including failures; never infer PASS."""
    result = {}
    for key in ('tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo'):
        values = re.findall(r'^# ' + key + r' (\d+)$', output, re.MULTILINE)
        require(len(values) == 1 and len(values[0]) <= 7, 'Missing or ambiguous native TAP totals')
        result[key] = int(values[0])
        require(result[key] <= 1000000, 'Native TAP total exceeds bounded profile')
    durations = re.findall(r'^# duration_ms ([0-9]+(?:\.[0-9]+)?)$', output, re.MULTILINE)
    require(len(durations) == 1 and len(durations[0]) <= 32, 'Missing or ambiguous native TAP duration')
    result['duration_ms'] = float(durations[0])
    require(math.isfinite(result['duration_ms']) and result['duration_ms'] >= 0
            and result['tests'] == sum(result[k] for k in ('pass', 'fail', 'cancelled', 'skipped', 'todo')),
            'Native TAP totals are inconsistent')
    return result


class Harness(base.Harness):
    def __init__(self):
        base.REPORT = REPORT
        self.classification_predecessor = None
        self.classification_current = None
        self.classification_serial = 0
        super().__init__()
        self.report.update(command='./dev test --suite classification-upgrade', profile='isolated-postgresql-classification')

    def classification_native_source_expectations(self, measured):
        # A later isolated upgrader may declare exact predecessor modules.
        # Standalone classification still expects every checkout byte.
        return measured

    def native_source_expectations(self, measured):
        require(self.classification_predecessor is not None and self.classification_current is None
                and self.phase == 'lineage-native-tests' and self.repository_stage is None,
                'Undeclared classification predecessor readback phase')
        manifest = self.classification_predecessor['sources']
        require(type(measured) is list and len({r['path'] for r in measured}) == len(measured)
                and all(type(r) is dict and set(r) == {'path', 'sha256'} and r in manifest for r in measured),
                'Undeclared classification predecessor readback sources')
        replacements = {r['path']: r for r in PREDECESSORS}
        # Lineage's transitive native inventory imports service/repository but
        # does not instantiate the HTTP router. The separate startup verifier
        # checks all three mounted modules on every helper invocation.
        require({r['path'] for r in measured if r['path'] in replacements}
                == {'packages/domain/src/approval-service.ts', REPOSITORY},
                'Predecessor readback pinned-module subset differs')
        for row in PREDECESSORS:
            read_exact(ROOT / row['fixture'], row['sha256'])
        return [{**r, 'sha256': replacements[r['path']]['sha256']} if r['path'] in replacements else dict(r) for r in measured]

    def helper(self, args, *, mounts=(), **kwargs):
        mounts = list(mounts)
        require(all(target != '/app/tests/api' and not target.startswith('/app/tests/api/') for _, target in mounts),
                'Conflicting classification native-test mount')
        mounts.append((ROOT / 'tests/api', '/app/tests/api'))
        stage = self.classification_predecessor
        current = self.classification_current
        if stage is None and current is None:
            return super().helper(args, mounts=mounts, **kwargs)
        require(args and args[0] == 'node', 'Classification source phase requires fixed Node helper')
        require(all(target != PROBE for _, target in mounts), 'Conflicting classification verifier mount')
        self.classification_serial += 1
        original_repository_stage = self.repository_stage
        effective = [dict(row) for row in (stage or current)['sources']]
        if current is not None:
            native = self.classification_native_source_expectations([row for row in effective if row['path'].endswith('.ts')])
            expected = {row['path']: row['sha256'] for row in native}
            effective = [{**row, 'sha256': expected.get(row['path'], row['sha256'])} for row in effective]
        selected = []
        if stage is not None:
            for row in PREDECESSORS:
                content = read_exact(ROOT / row['fixture'], row['sha256'])
                require(hashlib.sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest() == row['gitBlob'],
                        'Immutable classification predecessor Git identity differs')
                path = row['path']
                if path == REPOSITORY and original_repository_stage is not None:
                    if original_repository_stage['name'] == 'predecessor':
                        # SQL001–018 still needs its older exact repository. Its
                        # existing wrapper and probe remain entirely intact.
                        require(original_repository_stage['override'] is True
                                and original_repository_stage['sha256'] == base.base.PREDECESSOR_SHA256,
                                'Unexpected SQL018 repository predecessor')
                        effective = [{**r, 'sha256': base.base.PREDECESSOR_SHA256} if r['path'] == path else r for r in effective]
                        continue
                    require(original_repository_stage['name'] == 'current' and original_repository_stage['override'] is False,
                            'Unexpected quality repository phase')
                    # SQL019's "current" was current before classification.
                    # Its native startup/exit verifier must pin SQL020 bytes,
                    # rather than assert today's SQL021-aware module ran there.
                    self.repository_stage = base.base.repository_phase(self, 'classification020-' + str(self.classification_serial),
                                                                      ROOT / row['fixture'], row['sha256'], True)
                else:
                    target = '/app/' + path
                    require(all(target != other and not target.startswith(other.rstrip('/') + '/')
                                and not other.startswith(target + '/') for _, other in mounts),
                            'Caller conflicts with immutable classification predecessor')
                    mounts.append((ROOT / row['fixture'], target))
                selected.append({**row, 'commit': COMMIT, 'readOnly': True})
                effective = [{**r, 'sha256': row['sha256']} if r['path'] == path else r for r in effective]
        expected = [{'path': r['path'], 'sha256': r['sha256']} for r in effective if r['path'] in {p['path'] for p in PREDECESSORS}]
        require(len(expected) == 3, 'Classification source inventory omits phase modules')
        probe = self.folder / ('classification-source-' + str(self.classification_serial) + '.cjs')
        data = verifier(expected).encode()
        with probe.open('xb') as output:
            output.write(data)
        probe.chmod(0o444)
        record = {'phase': self.phase, 'stage': 'SQL001-020' if stage is not None else 'SQL021', 'result': 'RUNNING',
                  'effectiveSources': effective, 'overrides': selected, 'verifierSha256': sha(data),
                  'sql018RepositoryPrecedence': bool(stage is not None and original_repository_stage is not None
                                                    and original_repository_stage['name'] == 'predecessor')}
        self.report.setdefault('classificationSourceChecks', []).append(record)
        try:
            result = super().helper([args[0], '--require', PROBE, *args[1:]], mounts=[*mounts, (probe, PROBE)], **kwargs)
            record.update(result='PASS' if result.returncode == 0 else 'NONZERO', exitStatus=result.returncode)
            return result
        except BaseException:
            record['result'] = 'FAIL'
            raise
        finally:
            self.repository_stage = original_repository_stage
            record['overrideReleased'] = True
            read_exact(probe, sha(data))
            for row in PREDECESSORS:
                read_exact(ROOT / row['fixture'], row['sha256'])
                selected_source = next(r for r in (stage or current)['sources'] if r['path'] == row['path'])
                read_exact(ROOT / row['path'], selected_source['sha256'])
            record['sourceHashesMatched'] = True


def execute(h):
    frozen = sources()
    h.report['diagnostic_sources'] = frozen
    h.classification_predecessor = {'sources': frozen}
    try:
        base.execute(h)  # All predecessor migrations and native tests remain mandatory.
    finally:
        h.classification_predecessor = None
    h.report['predecessor_lineage_tests'] = dict(h.report['tests'])
    h.report['sources'] = frozen
    h.phase = 'classification-predecessor'
    tables = json.loads(h.sql("SELECT json_agg(schemaname||'.'||tablename ORDER BY schemaname,tablename) FROM pg_tables WHERE schemaname IN('public','gc_authn','gc_authority') AND tablename<>'schema_migrations';"))
    # Every SQL020 field is legacy now, including source/job generation fields.
    before = base.base.canonical_snapshot(h, tables)
    ledger = json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;'))
    require(len(NAMES) == 20 and [row['name'] for row in ledger] == NAMES, 'Expected exact SQL001–020 predecessor')
    require(all(row['checksum'] == sha((MIGRATIONS / row['name']).read_bytes()) for row in ledger),
            'Classification predecessor migration checksum differs')
    target = h.folder / 'classification-target'
    target.mkdir()
    for name in [*NAMES, MIGRATION]:
        shutil.copyfile(MIGRATIONS / name, target / name)
    h.phase = 'classification-upgrade'
    migrated = h.migrate(target)
    require(re.findall(r'^Applied (.+)$', migrated.stdout, re.MULTILINE) == [MIGRATION], 'Expected exact SQL021 application')
    require(base.base.canonical_snapshot(h, tables) == before, 'Classification upgrade changed predecessor canonical/history rows')
    after = json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;'))
    require(len(after) == 21 and after[:20] == ledger and after[-1]['name'] == MIGRATION
            and after[-1]['checksum'] == sha((MIGRATIONS / MIGRATION).read_bytes()), 'Classification changed predecessor ledger')
    require('Applied' not in h.migrate(target).stdout, 'Classification replay reapplied migration')
    require(base.base.canonical_snapshot(h, tables) == before, 'Classification replay changed predecessor data')
    require(json.loads(h.sql('SELECT json_agg(to_jsonb(m) ORDER BY name) FROM schema_migrations m;')) == after, 'Classification replay changed ledger')
    h.report['classificationUpgradeBaseline'] = [{'table': name, **row} for name, row in before.items()]
    h.report['checks'].append('Exact SQL020→021 application and inert replay preserve every predecessor row, including SQL020 generation fields, and full checksum ledger')
    h.phase = 'classification-native-tests'
    # Predecessor totals remain in predecessor_lineage_tests. An unavailable or
    # failed current invocation must never appear as those earlier passing tests.
    h.report.update(tests=None, classificationNativeExitStatus=None)
    h.classification_current = {'sources': frozen}
    try:
        measured = [row for row in frozen if row['path'].endswith('.ts')]
        probe = "const fs=require('node:fs'),crypto=require('node:crypto');console.log(JSON.stringify(" + json.dumps([row['path'] for row in measured]) + ".map(path=>({path,sha256:crypto.createHash('sha256').update(fs.readFileSync(path)).digest('hex')}))));"
        observed = json.loads(h.helper(['node', '-e', probe]).stdout)
        expected_sources = h.classification_native_source_expectations(measured)
        require(observed == expected_sources, 'Actual classification native source bytes differ')
        h.report['classificationNativeSourceReadback'] = {'result': 'PASS', 'files': len(measured), 'checkoutManifestSha256': sha(json.dumps(measured, sort_keys=True).encode()), 'manifestSha256': sha(json.dumps(observed, sort_keys=True).encode())}
        expected = sum(len(re.findall(r'^test\(', (ROOT / name).read_text(), re.MULTILINE)) for name in TESTS)
        require(expected == 14, 'Expected fourteen native classification cases')
        tested = h.helper(['node', '--import', 'tsx', '--test', '--test-reporter=tap', '--test-concurrency=1', *TESTS], timeout=240, allow_failure=True)
        h.report['classificationNativeExitStatus'] = tested.returncode
        h.report['tests'] = native_tap_totals(tested.stdout)
        require(tested.returncode == 0, 'Native classification suite failed; retained TAP identifies failing case')
        h.report['tests'] = base.base.base.tap_summary(tested.stdout, expected)
    finally:
        h.classification_current = None
    require(sources() == frozen, 'Classification source changed during native qualification')
    h.report['migrations'] = [{'name': name, 'sha256': sha((MIGRATIONS / name).read_bytes())} for name in [*NAMES, MIGRATION]]
    h.report['limitations'] = [
        'Real disposable PostgreSQL, native runtime privileges and actual canonical command/scan/read services; fixture metadata is authored, not source extraction evidence.',
        'Pure TypeScript normalization/evaluation executes in the native suite before exact SQL comparison; no source rows, samples, probabilities or arbitrary code are involved.',
        'Predecessor service/router/repository execute pinned SQL020 source; SQL018 repository override retains precedence. classificationSourceChecks records actual effective bytes for every helper; inherited stage records alone are not SQL021 execution claims.',
        'SQL021 native phase uses current source with startup/exit and full source readback, without production compatibility fallback or skipped predecessor tests.',
        'HTTP/OIDC, Temporal restart/delivery, seeded persona upgrades and browser qualification remain separate. No shared runtime or unrelated infrastructure modified.']


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
