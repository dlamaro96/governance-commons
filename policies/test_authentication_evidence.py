#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Adversarial publication tests use synthetic files, never PostgreSQL or Docker."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import authentication_evidence as evidence

COMMIT = 'a'*40


def fixture(root):
    for name in evidence.FIXED_SOURCES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_text('synthetic source\n')
    for folder in evidence.SOURCE_FOLDERS:
        (root / folder).mkdir(parents=True, exist_ok=True)
    for name in evidence.MIGRATIONS:
        path = root / 'packages/db/migrations' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('-- synthetic immutable migration\n')
    (root/'package.json').write_text(json.dumps({'dependencies': {'pg': '8.23.1', 'kysely': '0.29.9'}, 'devDependencies': {'tsx': '4.20.6'}}))
    folder = '.local/evidence/authority-authn-foundation-20261116T090000-123456abcdef'
    (root/folder).mkdir(parents=True)
    tests, logs = {}, {}
    for i, (key, path) in enumerate(evidence.TESTS.items(), 1):
        titles = [f'PRIVATE_SYNTHETIC_{key}_{n}' for n in range(i)]
        (root/path).write_text(''.join(f"test('{title}', async () => {{}});\n" for title in titles))
        raw = f'phase={key}\nexit=0\nTAP version 13\n' + ''.join(f'ok {j} - {title}\n' for j, title in enumerate(titles, 1))
        raw += f'1..{i}\n# tests {i}\n# suites 0\n# pass {i}\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n# duration_ms 1.5\n'
        name = f'{folder}/{i:03d}-{key}.log'
        (root/name).write_text(raw)
        logs[key] = {'path': name, 'sha256': evidence.digest(raw.encode())}
        tests[key] = {'tests': i, 'pass': i, 'fail': 0, 'cancelled': 0, 'skipped': 0, 'todo': 0, 'duration_ms': 1.5}
    sources = evidence.source_inventory(root)
    hashes = {row['path']: row['sha256'] for row in sources}
    report = {'schema_version': 1, 'result': 'PASS', 'started_at': '2026-11-16T09:00:00+00:00', 'recorded_at': '2026-11-16T09:00:10+00:00',
              'commit': COMMIT, 'command': evidence.COMMAND, 'profile': evidence.PROFILE, 'checks': evidence.CHECKS + [f"All{tests[key]['tests']} {key} pass with native connections, no failures, skips, cancellations or todos" for key in evidence.TESTS],
              'sources': sources, 'migrations': [{'name': name, 'sha256': hashes['packages/db/migrations/'+name]} for name in evidence.MIGRATIONS],
              'images': {'postgres': 'sha256:'+'b'*64, 'application': 'sha256:'+'c'*64}, 'docker_version': '29.0.2',
              'runtime': {'node': 'v24.22.3', 'pg': '8.23.1', 'tsx': '4.20.6', 'kysely': '0.29.9', 'packageSha256': hashes['package.json'], 'lockSha256': hashes['pnpm-lock.yaml']},
              **tests, 'baseline': [{'table': 'sessions', 'original_rows': 1, 'sha256': 'd'*64}],
              'isolation': dict(evidence.ISOLATION), 'cleanup': {'ownedRemoved': True, 'resourceInventoryPreserved': True},
              'memory_admission': {'total_bytes': 8*1024*evidence.MIB, 'observed_working_bytes': 1024*evidence.MIB, 'daemon_reserve_bytes': 1024*evidence.MIB},
              'limitations': ['PRIVATE_SYNTHETIC_LIMITATION'], 'private_logs': list(logs.values()), 'test_logs': logs, 'evidence_directory': folder}
    return report


class AuthenticationEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='gc-authn-evidence-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.report = fixture(self.root)

    def validate(self, report=None):
        return evidence.safe_report(self.root, self.report if report is None else report, COMMIT)

    def save(self, report=None):
        path = self.root/'.local/evidence/authority-authn-foundation.json'
        path.write_text(json.dumps(self.report if report is None else report))
        return path

    def test_exact_execution_exports_only_safe_coordinates_and_bound_sources(self):
        result = self.validate()
        self.assertIsNotNone(result)
        self.assertEqual(result['counts']['tests']['tests'], 1)
        self.assertEqual(result['counts']['concurrency_tests']['tests'], 2)
        self.assertEqual(len(result['tests']), 3)
        raw = json.dumps(result)
        for forbidden in ('PRIVATE_SYNTHETIC', 'evidence_directory', 'private_logs', 'original_rows', 'sessions'):
            self.assertNotIn(forbidden, raw)
        self.save()
        self.assertEqual(evidence.load_report(self.root, COMMIT), result)

    def test_unknown_private_fields_at_every_boundary_are_rejected(self):
        paths = [(), ('runtime',), ('images',), ('isolation',), ('cleanup',), ('memory_admission',), ('tests',),
                 ('sources', 0), ('migrations', 0), ('baseline', 0), ('private_logs', 0), ('test_logs',), ('test_logs', 'tests')]
        for path in paths:
            with self.subTest(path=path):
                report = copy.deepcopy(self.report)
                target = report
                for part in path:
                    target = target[part]
                target['credential'] = 'PRIVATE_SYNTHETIC_SECRET'
                self.assertIsNone(self.validate(report))

    def test_partial_failed_missing_or_wrong_commit_never_passes(self):
        self.assertIsNone(evidence.load_report(self.root, COMMIT))
        for mutation in ({'result': 'FAIL'}, {'result': 'RUNNING'}, {'commit': 'b'*40}, {'schema_version': True},
                         {'checks': []}, {'checks': evidence.CHECKS}, {'command': 'echo PASS'}, {'profile': 'core'}, {'recorded_at': '2026-11-16T08:00:00+00:00'}):
            self.assertIsNone(self.validate({**self.report, **mutation}))
        del self.report['tests']
        self.assertIsNone(self.validate())

    def test_source_mutation_removal_addition_escape_and_duplicates_are_rejected(self):
        for rows in [self.report['sources'][:-1], self.report['sources']*2, [{'path': '../escape', 'sha256': 'a'*64}],
                     [{**self.report['sources'][0], 'sha256': 'a'*64}, *self.report['sources'][1:]]]:
            self.assertIsNone(self.validate({**self.report, 'sources': rows}))
        path = self.root/evidence.FIXED_SOURCES[0]
        original = path.read_bytes()
        path.write_bytes(original+b'changed')
        self.assertIsNone(self.validate())
        path.write_bytes(original)
        (self.root/'packages/authority/src/new.ts').write_text('new source')
        self.assertIsNone(self.validate())

    def test_symlinked_sources_or_parent_directories_are_not_admitted(self):
        path = self.root/'packages/authority/src/linked.ts'
        path.symlink_to(self.root/'package.json')
        self.assertIsNone(self.validate())
        path.unlink()
        folder = self.root/'packages/authority/src/nested'
        folder.symlink_to(self.root/'tests', target_is_directory=True)
        self.assertIsNone(self.validate())

    def test_source_derived_counts_and_no_skips_are_required(self):
        for key in evidence.TESTS:
            for field, number in [('tests', 99), ('pass', 0), ('fail', 1), ('skipped', 1), ('cancelled', 1), ('todo', 1), ('tests', True), ('duration_ms', float('nan'))]:
                report = copy.deepcopy(self.report)
                report[key][field] = number
                self.assertIsNone(self.validate(report))
        path = self.root/evidence.TESTS['tests']
        path.write_text(path.read_text()+"test.skip('omitted', () => {});\n")
        self.report['sources'] = evidence.source_inventory(self.root)
        self.assertIsNone(self.validate())

    def test_log_integrity_envelope_titles_and_counts_are_independently_replayed(self):
        ref = self.report['test_logs']['tests']
        path = self.root/ref['path']
        original = path.read_text()
        mutations = [original+'changed', original.replace('ok 1 -', 'not ok 1 -'), original.replace('# pass 1', '# pass 2'),
                     original.replace('1..1', '1..2'), original.replace('PRIVATE_SYNTHETIC_tests_0', 'unknown'),
                     original.replace('PRIVATE_SYNTHETIC_tests_0', 'PRIVATE_SYNTHETIC_tests_0 # SKIP'),
                     original+'# pass 1\n', original.replace('exit=0', 'exit=1'), original+'TAP version 13\n']
        path.write_text(mutations[0])
        self.assertIsNone(self.validate())  # An unchanged digest cannot hide changed original bytes.
        for text in mutations[1:]:
            path.write_text(text)
            ref['sha256'] = evidence.digest(text.encode())
            self.assertIsNone(self.validate())  # Even matching new digests do not hide invalid TAP.

    def test_cleanup_isolation_memory_and_runtime_dependencies_are_required(self):
        for path, bad in [(('cleanup', 'ownedRemoved'), False), (('cleanup', 'resourceInventoryPreserved'), False),
                          (('cleanup', 'ownedRemoved'), 1), (('isolation', 'network'), 'bridge'), (('isolation', 'memoryBytes'), 1),
                          (('memory_admission', 'total_bytes'), 1), (('runtime', 'packageSha256'), '0'*64),
                          (('runtime', 'pg'), '0.0.0'), (('runtime', 'node'), 'v20.0.0')]:
            report = copy.deepcopy(self.report)
            report[path[0]][path[1]] = bad
            self.assertIsNone(self.validate(report))

    def test_private_paths_cannot_escape_or_publish_other_files(self):
        for name in ['../private', '/tmp/private', self.report['evidence_directory']+'/../config.log', self.report['evidence_directory']+'/private-config.json']:
            report = copy.deepcopy(self.report)
            report['private_logs'][0]['path'] = name
            self.assertIsNone(self.validate(report))
        path = self.root/self.report['private_logs'][0]['path']
        path.unlink()
        path.symlink_to(self.root/'package.json')
        self.assertIsNone(self.validate())

    def test_duplicate_keys_nonfinite_json_oversize_and_symlinked_reports_fail_closed(self):
        path = self.save()
        for raw in ['{"result":"PASS","result":"PASS"}', '{"x":NaN}', json.dumps(self.report)+'x', '\xff']:
            path.write_text(raw)
            self.assertIsNone(evidence.load_report(self.root, COMMIT))
        path.write_bytes(b' '*(evidence.MAX_REPORT+1))
        self.assertIsNone(evidence.load_report(self.root, COMMIT))
        path.unlink()
        path.symlink_to(self.root/'package.json')
        self.assertIsNone(evidence.load_report(self.root, COMMIT))


if __name__ == '__main__':
    unittest.main()
