#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host controls for the native gate; never starts Docker or PostgreSQL."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('quality_freshness_gate', ROOT / 'scripts/runtime-test-quality-freshness-upgrade.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
HISTORICAL_FRESHNESS_SHA256 = gate.HISTORICAL_FRESHNESS_SHA256


def tap(passed=18, failed=0, skipped=0):
    count=passed+failed+skipped
    names=[f'Synthetic native case {i}' for i in range(count)]
    return '\n'.join([*(f'# Subtest: {name}\n'+('ok' if i<passed else 'not ok')+f' {i+1} - {name}' for i,name in enumerate(names)),f'# tests {passed + failed + skipped}', '# suites 0', f'# pass {passed}',
                      f'# fail {failed}', '# cancelled 0', f'# skipped {skipped}', '# todo 0', '# duration_ms 1.25', ''])


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='gc-unique-controls-')
        self.root = Path(self.temp.name).resolve()
        self.root_patch = patch.object(gate, 'ROOT', self.root)
        self.root_patch.start()
        self.history_patch = patch.object(gate, 'HISTORICAL_FRESHNESS_SHA256', gate.sha(b''))
        self.history_patch.start()
        for name in ['scripts/runtime-test-quality-freshness-upgrade.py', 'scripts/runtime-test-source-connectors-upgrade.py',
                     'scripts/runtime-test-authority-authn-foundation.py', 'scripts/authentication_roles.py',
                     'scripts/runtime-test-quality-monitoring-upgrade.py', 'scripts/qualification_quality_repository.py',
                     'tests/qualification/predecessors/repository-sql026.ts.txt',
                     'package.json', 'pnpm-lock.yaml', 'Dockerfile', 'tsconfig.json', 'deploy/compose/compose.yaml',
                     *(p for p,_ in gate.TESTS), *(p for p,_ in gate.LEGACY), 'tests/fixtures/reference-quality.ts', 'packages/db/src/migrate.ts',
                     'packages/domain/src/quality-service.ts', 'apps/api/src/quality.ts',
                     'apps/site-runner/src/quality-activity.ts', 'apps/workflow-worker/src/quality-http.ts',
                     'tests/fixtures/quality-monitoring.ts', 'tests/fixtures/quality-freshness.ts', 'packages/domain/src/quality-monitoring-service.ts', 'apps/api/src/quality-monitoring.ts']:
            self.write(name, '{}\n' if name.endswith('.json') else '')
        self.write('deploy/compose/compose.yaml', 'services:\n  postgres:\n    image: postgres:17\n')
        for name in gate.NAMES:
            self.write('packages/db/migrations/' + name, '-- synthetic host-only migration fixture\n')

        for name in gate.repository.INPUTS:
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(ROOT/name,path)
        for name in (gate.repository.SERVICE, gate.repository.REPOSITORY):
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True)
            if not path.exists() or path.stat().st_size==0: path.write_text('export {};\n')
            text=gate.repository.historical_imports(self.root,name)
            for relative in gate.re.findall(r'''(?:from\s*|import\s*(?:\(\s*)?|require\s*\(\s*)?['"](\.[^'"]+)['"]''',text):
                imported=Path(os.path.abspath(path.parent/relative))
                if imported.suffix=='.js':imported=imported.with_suffix('.ts')
                if not imported.suffix:imported=imported.with_suffix('.ts')
                imported.parent.mkdir(parents=True,exist_ok=True)
                if not imported.exists():imported.write_text('export {};\n')

    def tearDown(self):
        self.history_patch.stop()
        self.root_patch.stop()
        self.temp.cleanup()

    def write(self, name, body):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
        return target

    def harness(self, phase='post028-freshness-tests'):
        h = gate.Harness.__new__(gate.Harness)
        h.frozen = gate.sources()
        h.id, h.serial, h.phase = 'gc-owned-host-control', 1, phase
        h.app_image = 'sha256:' + 'a' * 64
        h.folder = self.root / '.local/evidence/control'
        h.folder.mkdir(parents=True, exist_ok=True)
        h.secret_path = h.folder / 'private-config.json'
        h.secret_path.write_text('{}')
        h.report = {'checks': [], 'cachedPackageAdmission': {}, 'privateConfigSha256': gate.sha(b'{}')}
        h.owned, h.calls = [], []
        def docker(*args, **kwargs):
            h.calls.append((args, kwargs))
            h.serial += 1
            return subprocess.CompletedProcess(args, 0, '{}', '')
        h.docker = docker
        return h

    def test_sql030_is_only_a_declared_contiguous_successor_never_a_phase_input(self):
        names=['025_quality_uniqueness.sql','026_quality_range.sql','027_quality_monitoring.sql','028_quality_freshness.sql','029_quality_freshness_scheduling.sql','030_quality_volume.sql']
        for name in names:
            if name not in gate.NAMES:self.write('packages/db/migrations/'+name,'-- successor only')
        self.assertEqual(gate.migrations(),gate.NAMES)
        self.assertNotIn('packages/db/migrations/030_quality_volume.sql',{r['path'] for r in gate.sources()})
        self.write('packages/db/migrations/031_undeclared.sql','-- undeclared')
        with self.assertRaises(RuntimeError):gate.migrations()
        (self.root/'packages/db/migrations/031_undeclared.sql').unlink()
        (self.root/'packages/db/migrations/030_quality_volume.sql').unlink()
        self.write('packages/db/migrations/030_wrong.sql','-- wrong successor')
        with self.assertRaises(RuntimeError):gate.migrations()

    def test_sql032_suffix_is_admitted_but_never_a_historical_phase_input(self):
        before = gate.sources()
        names = ['025_quality_uniqueness.sql', '026_quality_range.sql', '027_quality_monitoring.sql',
                 '028_quality_freshness.sql', '029_quality_freshness_scheduling.sql',
                 '030_quality_volume.sql', '031_authority_read_grants.sql', '032_relation_candidate_validation.sql']
        for name in names:
            if name not in gate.NAMES:
                self.write('packages/db/migrations/' + name, '-- successor only')
        self.assertEqual(gate.migrations(), gate.NAMES)
        self.assertEqual(gate.sources(), before)
        path = 'packages/db/migrations/032_relation_candidate_validation.sql'
        self.assertNotIn(path, {row['path'] for row in gate.sources()})
        self.write(path, '-- changed unexecuted successor')
        self.assertEqual(gate.sources(), before)
        future = self.write('packages/db/migrations/033_undeclared.sql', '-- unreviewed')
        with self.assertRaises(RuntimeError): gate.migrations()
        future.unlink()
        if '030_quality_volume.sql' not in gate.NAMES:
            (self.root/'packages/db/migrations/030_quality_volume.sql').unlink()
        else:
            (self.root/'packages/db/migrations'/gate.NAMES[-1]).unlink()
        with self.assertRaises(RuntimeError): gate.migrations()

    def test_sql033_suffix_is_admitted_but_never_a_historical_phase_input(self):
        before = gate.sources()
        names = ['025_quality_uniqueness.sql', '026_quality_range.sql', '027_quality_monitoring.sql',
                 '028_quality_freshness.sql', '029_quality_freshness_scheduling.sql',
                 '030_quality_volume.sql', '031_authority_read_grants.sql', '032_relation_candidate_validation.sql', '033_content_security_revisions.sql']
        for name in names:
            if name not in gate.NAMES:
                self.write('packages/db/migrations/' + name, '-- successor only')
        self.assertEqual(gate.migrations(), gate.NAMES)
        self.assertEqual(gate.sources(), before)
        path = 'packages/db/migrations/033_content_security_revisions.sql'
        self.assertNotIn(path, {row['path'] for row in gate.sources()})
        self.write(path, '-- changed unexecuted successor')
        self.assertEqual(gate.sources(), before)
        future = self.write('packages/db/migrations/034_undeclared.sql', '-- unreviewed')
        with self.assertRaises(RuntimeError): gate.migrations()
        future.unlink()
        (self.root/'packages/db/migrations/032_relation_candidate_validation.sql').unlink()
        with self.assertRaises(RuntimeError): gate.migrations()

    def test_sql031_suffix_is_admitted_but_never_a_historical_phase_input(self):
        before = gate.sources()
        names = ['025_quality_uniqueness.sql', '026_quality_range.sql', '027_quality_monitoring.sql',
                 '028_quality_freshness.sql', '029_quality_freshness_scheduling.sql',
                 '030_quality_volume.sql', '031_authority_read_grants.sql']
        for name in names:
            if name not in gate.NAMES:
                self.write('packages/db/migrations/' + name, '-- successor only')
        self.assertEqual(gate.migrations(), gate.NAMES)
        self.assertEqual(gate.sources(), before)
        path = 'packages/db/migrations/031_authority_read_grants.sql'
        self.assertNotIn(path, {row['path'] for row in gate.sources()})
        self.write(path, '-- changed unexecuted successor')
        self.assertEqual(gate.sources(), before)
        future = self.write('packages/db/migrations/032_undeclared.sql', '-- unreviewed')
        with self.assertRaises(RuntimeError): gate.migrations()
        future.unlink()
        if '030_quality_volume.sql' not in gate.NAMES:
            (self.root/'packages/db/migrations/030_quality_volume.sql').unlink()
        else:
            (self.root/'packages/db/migrations'/gate.NAMES[-1]).unlink()
        with self.assertRaises(RuntimeError): gate.migrations()

    def test_exact_current_migration_inventory(self):
        self.assertEqual(gate.migrations(), gate.NAMES)
        file = self.root / 'packages/db/migrations' / gate.NAMES[-1]
        file.unlink()
        with self.assertRaises(RuntimeError):
            gate.migrations()
        file.write_text('-- restored fixture')
        self.write('packages/db/migrations/028_undeclared.sql', '-- extra')
        with self.assertRaises(RuntimeError):
            gate.migrations()

    def test_immutable_sql028_fixture_hash_and_tamper_refusal(self):
        self.assertEqual(gate.sha((ROOT / gate.HISTORICAL_FRESHNESS).read_bytes()), HISTORICAL_FRESHNESS_SHA256)
        self.assertFalse(gate.HISTORICAL_FRESHNESS.endswith('.test.ts'))
        before = gate.sources()
        self.write(gate.HISTORICAL_FRESHNESS, 'changed historical assertion')
        with self.assertRaisesRegex(RuntimeError, 'Immutable SQL028 freshness test differs'):
            gate.sources()
        self.write(gate.HISTORICAL_FRESHNESS, '')
        self.assertEqual(gate.sources(), before)

    def test_sql029_successor_excluded_and_unknown_suffix_refuses(self):
        before = gate.sources()
        self.write('packages/db/migrations/029_quality_freshness_scheduling.sql', '-- later scheduling')
        self.assertEqual(gate.migrations(), gate.NAMES)
        self.assertEqual(gate.sources(), before)
        self.write('packages/db/migrations/029_quality_freshness_scheduling.sql', '-- changed later scheduling')
        self.assertEqual(gate.sources(), before)
        self.write('packages/db/migrations/030_undeclared.sql', '-- undeclared')
        with self.assertRaises(RuntimeError): gate.migrations()

    def test_transitive_imports_and_missing_source_refusal(self):
        self.write(gate.TESTS[-1][0], "import {x} from '../../packages/domain/src/leaf.js';\nawait import('./side.ts');\n")
        self.write('packages/domain/src/leaf.ts', "export {x} from './deep/index.ts';\n")
        self.write('packages/domain/src/deep/index.ts', 'export const x=1;\n')
        self.write('tests/api/side.ts', 'export {};\n')
        paths = {row['path'] for row in gate.sources()}
        self.assertTrue({'packages/domain/src/leaf.ts', 'packages/domain/src/deep/index.ts', 'tests/api/side.ts'} <= paths)
        (self.root / 'tests/api/side.ts').unlink()
        with self.assertRaises(RuntimeError):
            gate.sources()

    def test_latest_monitoring_harness_and_predecessor_binding_are_frozen_inputs(self):
        expected = {'scripts/runtime-test-quality-monitoring-upgrade.py',
                    'scripts/qualification_quality_repository.py',
                    'tests/qualification/predecessors/repository-sql026.ts.txt'}
        before = {row['path']: row['sha256'] for row in gate.sources()}
        self.assertTrue(expected <= before.keys())
        for name in expected:
            original = (self.root / name).read_bytes()
            (self.root / name).write_bytes(original + b'changed')
            if name == gate.repository.repository.FIXTURE:
                with self.assertRaisesRegex(RuntimeError,'hash differs'):gate.sources()
            else:
                after = {row['path']: row['sha256'] for row in gate.sources()}
                self.assertNotEqual(before[name], after[name])
            (self.root / name).write_bytes(original)
        (self.root / 'scripts/qualification_quality_repository.py').unlink()
        with self.assertRaises(RuntimeError):
            gate.sources()

    def test_symlinked_leaf_and_parent_refused(self):
        original = self.write('packages/domain/src/real.ts', 'export {};\n')
        link = self.root / 'packages/domain/src/link.ts'
        link.symlink_to(original)
        self.write(gate.TESTS[-1][0], "import '../../packages/domain/src/link.ts';\n")
        with self.assertRaises(RuntimeError):
            gate.sources()
        link.unlink()
        directory = self.root / 'alias'
        directory.symlink_to(original.parent, target_is_directory=True)
        self.write(gate.TESTS[-1][0], "import '../../alias/real.ts';\n")
        with self.assertRaises(RuntimeError):
            gate.sources()

    def test_real_node_startup_and_exit_source_and_config_checks(self):
        node = shutil.which('node')
        self.assertIsNotNone(node, 'Node must be installed; this control never silently skips')
        file = self.write('payload.txt', 'original')
        config = self.write('private-config.json', '{}')
        rows = [{'path': 'payload.txt', 'sha256': gate.sha(b'original')}]
        # Only the two fixed container roots are remapped to owned temporary
        # files; the exact generated verifier/check/exit logic executes in Node.
        source = gate.verifier(rows, gate.sha(b'{}'))
        self.assertEqual(source.count("'/app/'"), 1)
        self.assertEqual(source.count("'/run/authn-config.json'"), 1)
        source = source.replace("'/app/'", json.dumps(str(self.root) + '/')).replace("'/run/authn-config.json'", json.dumps(str(config)))
        preload = self.write('verifier.cjs', source)
        def run(body=''):
            return subprocess.run([node, '--require', str(preload), '-e', body], capture_output=True, text=True, timeout=10)
        self.assertEqual(run().returncode, 0)
        file.write_text('changed')
        self.assertNotEqual(run().returncode, 0)
        file.write_text('original')
        changed = run('require("node:fs").writeFileSync(' + json.dumps(str(file)) + ',"changed")')
        self.assertNotEqual(changed.returncode, 0)
        self.assertIn('QUALITY_FRESHNESS_SOURCE_MISMATCH', changed.stderr)
        file.write_text('original')
        changed = run('require("node:fs").writeFileSync(' + json.dumps(str(config)) + ',"changed")')
        self.assertNotEqual(changed.returncode, 0)
        self.assertIn('QUALITY_FRESHNESS_CONFIG_MISMATCH', changed.stderr)

    def test_native_helper_exact_readonly_mounts_and_owned_verifier(self):
        h = self.harness()
        h.helper(['node', '--test', gate.TESTS[-1][0]], allow_failure=True)
        args, kwargs = h.calls[-1]
        mounts = [args[i + 1] for i, v in enumerate(args) if v == '--volume']
        for row in h.frozen:
            self.assertIn(f'{gate.repository.mounted_path(self.root, row, gate.repository.select(self.root, h.frozen, gate.REPOSITORY_GATE, h.phase))}:/app/{row["path"]}:ro', mounts)
        self.assertEqual(len(mounts), len(h.frozen) + 2)
        selected=gate.repository.select(self.root,h.frozen,gate.REPOSITORY_GATE,h.phase)
        record=h.report['sourceChecks'][-1]
        self.assertEqual(record['effectiveSources'],selected['sources'])
        self.assertEqual(record['historicalBindings'],selected['overrides'])
        self.assertEqual(len({m.rsplit(':',2)[1] for m in mounts}),len(mounts))
        probe=next(m.rsplit(':',2)[0] for m in mounts if m.endswith(':'+gate.PROBE+':ro'))
        self.assertEqual(Path(probe).read_text(),gate.verifier(selected['sources'],gate.sha(b'{}')))
        self.assertTrue(all(v.endswith(':ro') for v in mounts))
        self.assertIn('container:' + h.id, args)
        for option in ('--read-only', '--cap-drop', '--security-opt', '--pids-limit', '--memory', '--pull'):
            self.assertIn(option, args)
        self.assertEqual(args[-5:], ('node', '--require', gate.PROBE, '--test', gate.TESTS[-1][0]))
        self.assertTrue(h.report['sourceChecks'][0]['sourceHashesMatched'])
        self.assertEqual(h.report['sourceChecks'][0]['result'], 'PASS')
        self.assertEqual(h.owned, ['gc-owned-host-control-h1'])
        self.assertTrue(kwargs['allow_failure'])

    def test_schema_prefix_mount_and_overlap_refusal(self):
        h = self.harness('schema-12')
        folder = self.root / 'prefix'
        folder.mkdir()
        h.helper(['node', '-e', ''], mounts=[(folder, '/app/packages/db/migrations')])
        args = h.calls[-1][0]
        mounts = [args[i + 1] for i, v in enumerate(args) if v == '--volume']
        self.assertIn(f'{folder}:/app/packages/db/migrations:ro', mounts)
        self.assertFalse(any('/app/packages/db/migrations/001_' in v for v in mounts))
        self.assertNotIn('--require', args)
        with self.assertRaises(RuntimeError):
            h.helper(['node', '-e', ''], mounts=[(folder, '/app/packages/domain')])

    def test_helper_host_mutation_refused_after_leaf_returns(self):
        h = self.harness()
        def mutate(*args, **kwargs):
            self.write('Dockerfile', 'mutated')
            return subprocess.CompletedProcess(args, 0, '{}', '')
        h.docker = mutate
        with self.assertRaisesRegex(RuntimeError, 'source changed'):
            h.helper(['node', '-e', ''])

    def test_cached_dependency_admission_refuses_lock_mismatch(self):
        h = self.harness('schema-11')
        del h.report['cachedPackageAdmission']
        h.docker = lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, json.dumps({'package': {}, 'lock': '0' * 64}), '')
        with self.assertRaisesRegex(RuntimeError, 'dependency lock'):
            h.helper(['node', '-e', ''])
        self.assertEqual(h.owned, ['gc-owned-host-control-package-1'])

    def test_readback_checks_actual_sources_config_and_tools(self):
        h = self.harness()
        value = {'sources': gate.repository.select(self.root,h.frozen,gate.REPOSITORY_GATE,h.phase)['sources'], 'configSha256': h.report['privateConfigSha256'],
                 'node': {'version': 'v24.22.3', 'sha256': 'a' * 64}, 'tsx': {'version': '4.20.0', 'entrySha256': 'b' * 64}}
        h.helper = lambda *args, **kwargs: SimpleNamespace(stdout=json.dumps(value))
        self.assertEqual(gate.readback(h), value)
        for mutate in (lambda: value.update(sources=[]), lambda: value.update(configSha256='0' * 64),
                       lambda: value['node'].update(version='v20.0.0')):
            saved = json.loads(json.dumps(value))
            mutate()
            with self.assertRaises(RuntimeError):
                gate.readback(h)
            value = saved

    def test_tap_exact_totals_case_identity_and_current_failures_retained(self):
        self.assertEqual(gate.totals(tap())['pass'], 18)
        self.assertIsNone(gate.totals(tap() + '# pass 18\n'))
        self.assertIsNone(gate.totals(tap().replace('# tests 18\n', '')))
        self.write(gate.TESTS[-1][0], ''.join(f"test('Synthetic native case {i}',()=>{{}});\n" for i in range(18)))
        cases=((tap(),0,True),(tap(0,18),1,False),(tap(17,0,1),0,False),
               (tap().replace('Synthetic native case 0','Substituted case'),0,False),
               (tap().replace('Synthetic native case 1\n','Synthetic native case 0\n'),0,False))
        for output, code, good in cases:
            with self.subTest(code=code,good=good,output=output[:60]):
                h = self.harness()
                h.save = lambda **kwargs: None
                h.helper = lambda *args, **kwargs: subprocess.CompletedProcess([], code, output, '')
                with patch.object(gate, 'readback', return_value={'sourceProof': 'stable'}):
                    if good:
                        gate.native_suite(h,'post028-freshness-tests',gate.TESTS[-1][0],18)
                        self.assertEqual(h.report['nativeSuites'][0]['result'],'PASS')
                    else:
                        with self.assertRaises(RuntimeError):
                            gate.native_suite(h,'post028-freshness-tests',gate.TESTS[-1][0],18)
                        self.assertEqual(h.report['tests'],gate.totals(output))
                        self.assertEqual(h.report['testExitStatus'],code)
                        self.assertEqual(h.report['nativeSuites'][0]['result'],'FAIL')

    def test_suite_resets_previous_totals_before_readback_failure(self):
        self.write(gate.TESTS[-1][0], ''.join(f"test('Synthetic native case {i}',()=>{{}});\n" for i in range(18)))
        h=self.harness();h.report.update(tests={'pass':21},testExitStatus=0)
        with patch.object(gate,'readback',side_effect=RuntimeError('Synthetic readback failure')):
            with self.assertRaises(RuntimeError):gate.native_suite(h,'post028-freshness-tests',gate.TESTS[-1][0],18)
        self.assertIsNone(h.report['tests']);self.assertIsNone(h.report['testExitStatus'])
        self.assertIsNone(h.report['nativeSuites'][0]['tests'])

    def test_setup_stops_at027_with_exact_prefix_and_role_finally(self):
        h=self.harness('admission');h.memory_admission=lambda:{};h.inventory=lambda:{};h.created=False
        h.docker=lambda *args,**kwargs:subprocess.CompletedProcess(args,0,json.dumps([{'Endpoints':{'docker':{'Host':'unix:///owned'}}}]) if args[:2]==('context','inspect') else 'sha256:'+'a'*64,'')
        calls=[]
        expected=[{'name':name,'checksum':gate.sha((self.root/'packages/db/migrations'/name).read_bytes())} for name in gate.NAMES[:27]]
        h.sql=lambda statement,**kwargs:json.dumps(expected) if statement.startswith('SELECT json_agg') else calls.append(statement)
        def migrate(folder):
            names=sorted(p.name for p in folder.glob('*.sql'));calls.append(names)
            self.assertEqual(names,gate.NAMES[:len(names)])
        h.migrate=migrate
        roles=SimpleNamespace(prepare_sql=lambda *a:'PREPARE',finish_sql=lambda *a:'FINISH')
        with patch.object(gate.base.base,'module',return_value=roles),patch.dict(os.environ,{'DOCKER_HOST':''}):gate.setup(h)
        self.assertEqual([len(x) for x in calls if isinstance(x,list)],[11,12,13,27])
        self.assertEqual(calls.count('PREPARE'),2);self.assertEqual(calls.count('FINISH'),2)
        self.assertEqual(h.report['predecessorMigrations'],expected)

    def test_execute_keeps_all_fourteen_native_phases_around_upgrade(self):
        h=self.harness();h.command=lambda *a,**k:SimpleNamespace(stdout='a'*40)
        events=[]
        def suite(h,phase,path,count):
            events.append((phase,path,count));h.report.setdefault('nativeSuites',[]).append({'phase':phase,'result':'PASS'})
        with patch.object(gate,'setup',side_effect=lambda h:events.append('setup')),patch.object(gate,'native_suite',side_effect=suite),patch.object(gate,'upgrade',side_effect=lambda h:events.append('upgrade')):gate.execute(h)
        expected=['setup',*[(f'pre027-{family}-tests',*test) for family,test in zip(gate.FAMILIES,gate.LEGACY)],'upgrade',*[(f'post028-{family}-tests',*test) for family,test in zip(gate.FAMILIES,gate.LEGACY)],*[(phase,*test) for phase,test in zip(gate.PHASES[-2:],gate.TESTS)]]
        self.assertEqual(events,expected);self.assertEqual(len(h.report['nativeSuites']),14)
        self.assertEqual([x[1] for x in events if isinstance(x,tuple)][:6],[x[0] for x in gate.LEGACY])
        self.assertTrue(h.report['sourceHashesMatched'])

    def test_upgrade_refuses_row_ledger_replay_and_missing_old_measurement(self):
        tables=['public.'+v for v in ['quality_rules','quality_rule_versions','quality_runs','quality_rule_reference_bindings','quality_run_reference_bindings','reference_releases','audit','outbox','idempotency','quality_monitors','quality_monitor_versions','quality_monitor_schedule_segments','quality_monitor_occurrences','quality_monitor_incidents','quality_monitor_incident_events','quality_monitor_projection_receipts','quality_monitor_notifications']]
        before={table:{'rows':1,'sha256':'a'*64} for table in tables}
        previous=[{'name':n,'checksum':gate.sha((self.root/'packages/db/migrations'/n).read_bytes()),'applied_at':'synthetic-fixed-time'} for n in gate.NAMES[:27]]
        following=[*previous,{'name':gate.MIGRATION,'checksum':gate.sha((self.root/'packages/db/migrations'/gate.MIGRATION).read_bytes()),'applied_at':'synthetic-next-time'}]
        for mutation in ('none','rows','ledger','replay','measurement','reference_alias','missing_uniqueness','missing_range','tables','empty_monitoring'):
            with self.subTest(mutation=mutation):
                h=self.harness('control');h.save=lambda **kwargs:None
                target=h.folder/'migrations-28'
                if target.exists():shutil.rmtree(target)
                table_calls=[]
                def read(text):
                    if 'FROM pg_class c' in text:
                        table_calls.append(text)
                        return json.dumps(sorted(tables + (['public.future_table'] if mutation=='tables' and len(table_calls)>1 else [])))
                    return json.dumps({'completeness':1} if mutation=='measurement' else {'completeness':1,'reference':1,'uniqueness':1,'range':1} if mutation=='reference_alias' else {'completeness':1,'reference-allowed-values':1} if mutation=='missing_uniqueness' else {'completeness':1,'reference-allowed-values':1,'uniqueness':1} if mutation=='missing_range' else {'completeness':1,'reference-allowed-values':1,'uniqueness':1,'range':1})
                h.sql=read
                copied=[]
                def migrate(folder):
                    self.assertEqual(sorted(p.name for p in folder.glob('*.sql')),gate.NAMES)
                    copied.append(folder)
                    return SimpleNamespace(stdout='Applied '+gate.MIGRATION+'\n' if len(copied)==1 or mutation=='replay' else '')
                h.migrate=migrate
                changed={**before,tables[0]:{'rows':2,'sha256':'b'*64}}
                after_ledger=[dict(x) for x in following]
                if mutation=='ledger':after_ledger[0]['applied_at']='changed'
                initial={**before,'public.quality_monitors':{'rows':0,'sha256':'a'*64}} if mutation=='empty_monitoring' else before
                with patch.object(gate,'canonical_snapshot',side_effect=[initial,changed if mutation=='rows' else before,before]),patch.object(gate,'ledger',side_effect=[previous,after_ledger,after_ledger]):
                    if mutation=='none':
                        gate.upgrade(h);self.assertTrue(h.report['upgradePreservation']);self.assertTrue(h.report['replayPreservation'])
                    else:
                        with self.assertRaises(RuntimeError):gate.upgrade(h)

    def test_complete_ordinary_table_discovery_is_dynamic_and_refuses_bad_inventory(self):
        h=self.harness();queries=[]
        tables=['gc_authn.identity','gc_authority.authority_head','public.audit','public.new_future_table']
        h.sql=lambda query:(queries.append(query) or json.dumps(tables))
        self.assertEqual(gate.canonical_tables(h),tables)
        self.assertIn("c.relkind='r'",queries[0]);self.assertIn("n.nspname IN('public','gc_authn','gc_authority')",queries[0])
        self.assertIn("c.relname<>'schema_migrations'",queries[0]);self.assertNotIn('LIMIT',queries[0])
        for bad in ([],None,['public.audit']*2,['other.audit'],['public.audit;SELECT'],['public.'+'x'*2]*513):
            h.sql=lambda query:json.dumps(bad)
            with self.assertRaises(RuntimeError):gate.canonical_tables(h)

    def test_snapshot_hashes_rows_before_aggregation_preserves_duplicate_count(self):
        h=self.harness();queries=[]
        def read(query):queries.append(query);return json.dumps({'rows':3,'sha256':'a'*64})
        h.sql=read
        self.assertEqual(gate.canonical_snapshot(h,['public.quality_runs'])['public.quality_runs']['rows'],3)
        self.assertIn('AS MATERIALIZED',queries[0]);self.assertIn("sha256(convert_to(to_jsonb(r)::text,'UTF8'))",queries[0]);self.assertIn("string_agg(value,''::bytea ORDER BY value)",queries[0]);self.assertNotIn('DISTINCT',queries[0])
        for bad in ([],['public.x;DROP TABLE x'],['public.quality_runs','public.quality_runs']):
            with self.assertRaises(RuntimeError):gate.canonical_snapshot(h,bad)

    def test_prepare_finally_finishes_roles_after_migration_failure(self):
        h = self.harness('admission')
        h.memory_admission = lambda: {}
        h.inventory = lambda: {'containers': []}
        h.private_values, h.created = [], False
        calls = []
        def docker(*args, **kwargs):
            out = json.dumps([{'Endpoints': {'docker': {'Host': 'unix:///owned-control'}}}]) if args[:2] == ('context', 'inspect') else 'sha256:' + 'a' * 64
            return subprocess.CompletedProcess(args, 0, out, '')
        h.docker = docker
        h.sql = lambda statement, **kwargs: calls.append(statement)
        def migrate(folder):
            calls.append(folder.name)
            if folder.name == 'migrations-12':
                raise RuntimeError('Synthetic migration failure')
        h.migrate = migrate
        roles = SimpleNamespace(prepare_sql=lambda *a: 'PREPARE', finish_sql=lambda *a: 'FINISH')
        with patch.object(gate.base.base, 'module', return_value=roles), patch.dict(os.environ, {'DOCKER_HOST': ''}):
            with self.assertRaisesRegex(RuntimeError, 'Synthetic migration'):
                gate.setup(h)
        self.assertEqual(calls[-3:], ['PREPARE', 'migrations-12', 'FINISH'])

    def test_main_cleanup_on_failure_and_inventory_change(self):
        for fail_execute, inventory_changed in ((True, False), (False, True), (False, False)):
            h = self.harness('control')
            h.resources_before = {'containers': ['preexisting']}
            (h.folder / 'resources-before.json').write_text(json.dumps(h.resources_before))
            h.cleanup_deadline = 1
            h.inventory = lambda: {'containers': []} if inventory_changed else h.resources_before
            def cleanup():
                h.secret_path.unlink()
                h.report['cleanup'] = {'ownedRemoved': True}
            h.cleanup, h.save = cleanup, lambda **kwargs: None
            with patch.object(gate, 'Harness', return_value=h), patch.object(gate, 'execute', side_effect=RuntimeError('private') if fail_execute else None), patch.object(gate, 'REPORT', self.root / '.local/evidence/quality-freshness-upgrade.json'), patch.object(sys, 'argv', ['gate', '--run-local']), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gate.main(), int(fail_execute or inventory_changed))
            self.assertFalse(h.secret_path.exists())
            self.assertTrue(h.report['cleanup']['ownedRemoved'])
            if inventory_changed:
                self.assertIn('cleanupErrorType', h.report)
            else:
                self.assertTrue(h.report['cleanup']['resourceInventoryPreserved'])

    def test_main_removes_credentials_when_real_cleanup_docker_call_throws(self):
        for error in (TimeoutError('synthetic timeout'), RuntimeError('synthetic daemon failure')):
            with self.subTest(error=type(error).__name__):
                h = self.harness('control')
                h.resources_before = {'containers': ['preexisting']}
                h.inventory = lambda: self.fail('Inventory cannot be verified after failed cleanup')
                h.docker = lambda *args, **kwargs: (_ for _ in ()).throw(error)
                saved = []
                h.save = lambda **kwargs: saved.append((kwargs, h.secret_path.exists()))
                # Use the actual inherited cleanup: its first Docker inspect
                # raises before it can reach its own secret_path.unlink.
                with patch.object(gate, 'Harness', return_value=h), patch.object(gate, 'execute'), patch.object(gate, 'REPORT', self.root / '.local/evidence/quality-freshness-upgrade.json'), patch.object(sys, 'argv', ['gate', '--run-local']), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(gate.main(), 1)
                self.assertFalse(h.secret_path.exists())
                self.assertEqual(h.report['result'], 'FAIL')
                self.assertEqual(h.report['cleanupErrorType'], type(error).__name__)
                self.assertEqual(h.report['cleanup'], {'generatedCredentialsRemoved': True})
                self.assertEqual(saved, [({'final': True}, False)])

    def test_main_preserves_failure_when_credential_removal_is_denied(self):
        h = self.harness('control')
        h.resources_before = None
        h.docker = lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError('synthetic timeout'))
        h.save = lambda **kwargs: None
        with patch.object(gate, 'Harness', return_value=h), patch.object(gate, 'execute'), patch.object(gate, 'REPORT', self.root / '.local/evidence/quality-freshness-upgrade.json'), patch.object(sys, 'argv', ['gate', '--run-local']), patch.object(type(h.secret_path), 'unlink', side_effect=PermissionError('synthetic permission refusal')), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(gate.main(), 1)
        self.assertTrue(h.secret_path.exists())
        self.assertEqual(h.report['result'], 'FAIL')
        self.assertEqual(h.report['cleanupErrorType'], 'TimeoutError')
        self.assertEqual(h.report['credentialCleanupErrorType'], 'PermissionError')
        self.assertEqual(h.report['cleanup'], {'generatedCredentialsRemoved': False})


if __name__ == '__main__':
    unittest.main()
