#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Adversarial policy tests using explicitly synthetic reports, never scan evidence."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import importlib.machinery
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('sast', Path(__file__).with_name('sast.py'))
sast = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sast)
POLICY = sast.read_json(sast.POLICY)
NOW = datetime(2026, 11, 16, 12, tzinfo=timezone.utc)


def manifest():
    files = {name: {'sha256': sast.digest(name.encode()), 'bytes': len(name), 'language': lang}
             for name, lang in [('app.ts', 'javascript-typescript'), ('worker.py', 'python'),
                                ('.github/workflows/check.yml', 'actions')]}
    return {'files': files, 'expected': {lang: [name] for name, lang in
            [('app.ts', 'javascript-typescript'), ('worker.py', 'python'), ('.github/workflows/check.yml', 'actions')]},
            'sourceDigest': sast.digest(sast.canonical(files))}


def sarif(finding=False):
    value = {'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': 'CodeQL', 'semanticVersion': POLICY['cliVersion'], 'rules': [{
            'id': 'js/command-line-injection', 'properties': {'security-severity': '9.8', 'tags': ['security']}}]}},
        'automationDetails': {'id': 'governance-commons/javascript-typescript/'},
        'invocations': [{'executionSuccessful': True}], 'results': []}]}
    if finding:
        value['runs'][0]['results'] = [{'ruleId': 'js/command-line-injection',
            'message': {'text': 'Synthetic command injection fixture, not an actual product finding.'},
            'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'app.ts', 'uriBaseId': '%SRCROOT%'},
                                               'region': {'startLine': 4}}}],
            'partialFingerprints': {'primaryLocationLineHash': 'synthetic-line:1'}}]
    return value


def decoded(paths):
    return {'#select': {'columns': [{'name': 'path', 'kind': 'String'}], 'tuples': [[p] for p in paths]}}


class FindingsTests(unittest.TestCase):
    def evaluate(self, value, decisions=None, source=None):
        return sast.evaluate_sarif(value, source or manifest(), 'javascript-typescript', POLICY, decisions or {}, NOW)

    def test_complete_successful_zero_findings_is_only_a_policy_pass(self):
        self.assertEqual(self.evaluate(sarif()), [])

    def test_cli_success_does_not_make_a_critical_finding_pass(self):
        findings = self.evaluate(sarif(True))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['severity'], 'critical')
        self.assertTrue(findings[0]['blocking'])
        self.assertEqual(findings[0]['disposition'], 'untriaged')

    def test_missing_malformed_partial_failed_and_wrong_language_reports_fail(self):
        changes = [lambda r: r.pop('results'), lambda r: r.pop('invocations'),
                   lambda r: r.update(invocations=[]), lambda r: r['invocations'][0].update(executionSuccessful=False),
                   lambda r: r['invocations'][0].update(exitCode=2),
                   lambda r: r['invocations'][0].update(toolExecutionNotifications=[{'level': 'warning'}]),
                   lambda r: r['invocations'][0].update(toolConfigurationNotifications=[{'level': 'error'}]),
                   lambda r: r.update(automationDetails={'id': 'governance-commons/python/'}),
                   lambda r: r['tool']['driver'].update(semanticVersion='2.0.0'),
                   lambda r: r['tool']['driver'].update(rules=[])]
        for change in changes:
            with self.subTest(change=change):
                value = sarif(); change(value['runs'][0])
                with self.assertRaises(sast.Rejected):
                    self.evaluate(value)

    def test_duplicated_or_absent_language_runs_cannot_hide_missing_analysis(self):
        for runs in ([], [sarif()['runs'][0], sarif()['runs'][0]]):
            with self.assertRaises(sast.Rejected):
                self.evaluate({'version': '2.1.0', 'runs': runs})

    def test_missing_unknown_nan_and_infinite_security_severity_fail(self):
        for score in (None, 'unknown', 'NaN', 'Infinity', -1, 11, True):
            value = sarif(True)
            value['runs'][0]['tool']['driver']['rules'][0]['properties']['security-severity'] = score
            with self.assertRaises(sast.Rejected):
                self.evaluate(value)

    def test_untriaged_source_suppression_never_dismisses_finding(self):
        value = sarif(True)
        value['runs'][0]['results'][0]['suppressions'] = [{'kind': 'inSource', 'status': 'accepted'}]
        self.assertTrue(self.evaluate(value)[0]['blocking'])

    def test_source_locations_and_fingerprints_are_required(self):
        for uri in ('../app.ts', '%2e%2e/app.ts', 'file:///private/app.ts', '//host/app.ts', 'unknown.ts', 'app%00.ts'):
            value = sarif(True)
            value['runs'][0]['results'][0]['locations'][0]['physicalLocation']['artifactLocation']['uri'] = uri
            with self.assertRaises(sast.Rejected):
                self.evaluate(value)
        value = sarif(True); value['runs'][0]['results'][0].pop('partialFingerprints')
        with self.assertRaises(sast.Rejected):
            self.evaluate(value)

    def decision(self, fingerprint, disposition='accepted_risk'):
        # Fixture actors are explicitly synthetic, never published as project sign-offs.
        return {'fingerprint': fingerprint, 'disposition': disposition, 'owner': '@synthetic-owner',
                'reviewedBy': '@synthetic-reviewer', 'reviewUrl': 'https://example.invalid/review/1',
                'reviewedAt': '2026-11-15T12:00:00Z', 'expiresAt': '2026-12-15T12:00:00Z',
                'component': 'synthetic component', 'exploitability': 'synthetic assessment',
                'exposure': 'synthetic fixture only', 'evidence': 'synthetic evidence',
                'mitigation': 'synthetic control'}

    def test_only_exact_unexpired_evidenced_exception_unblocks(self):
        fingerprint = self.evaluate(sarif(True))[0]['fingerprint']
        decision = self.decision(fingerprint)
        register = sast.triage_register({'schemaVersion': 1, 'decisions': [decision]})
        self.assertFalse(self.evaluate(sarif(True), register)[0]['blocking'])
        changed = manifest(); changed['files']['app.ts']['sha256'] = 'b' * 64
        self.assertTrue(self.evaluate(sarif(True), register, changed)[0]['blocking'])
        for expiry in ('2026-11-16T11:59:59Z', '2028-01-01T00:00:00Z'):
            decision['expiresAt'] = expiry
            with self.assertRaises(sast.Rejected):
                self.evaluate(sarif(True), register)

    def test_pending_critical_and_high_remediation_remains_blocking(self):
        fingerprint = self.evaluate(sarif(True))[0]['fingerprint']
        decision = self.decision(fingerprint, 'remediation_pending')
        self.assertTrue(self.evaluate(sarif(True), {fingerprint: decision})[0]['blocking'])

    def test_no_blanket_or_unowned_triage_and_no_duplicate_decisions(self):
        fingerprint = self.evaluate(sarif(True))[0]['fingerprint']
        for field, replacement in [('fingerprint', '*'), ('owner', ''), ('evidence', ''),
                                   ('reviewUrl', 'unrecorded'), ('disposition', 'ignore')]:
            decision = self.decision(fingerprint); decision[field] = replacement
            with self.assertRaises(sast.Rejected):
                sast.triage_register({'schemaVersion': 1, 'decisions': [decision]})
        with self.assertRaises(sast.Rejected):
            sast.triage_register({'schemaVersion': 1, 'decisions': [self.decision(fingerprint)] * 2})


class PublicationRedactionTests(unittest.TestCase):
    def test_real_detector_projects_only_fixed_rule_ids_not_matched_bytes(self):
        path = sast.ROOT / 'scripts/github/bootstrap'
        loader = importlib.machinery.SourceFileLoader('publication_bootstrap_fixture', str(path))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        fixtures = [('private-key', b'-----BEGIN ' + b'PRIVATE KEY-----'),
                    ('github-token', b'ghp_' + b'S' * 36),
                    ('aws-access-key', b'AKIA' + b'S' * 16),
                    ('personal-email', b'synthetic-person' + b'@gmail.com')]
        for rule, value in fixtures:
            with self.subTest(rule=rule):
                result = module.publication_findings('synthetic-fixture.txt', value)
                self.assertEqual(result, [{'path': 'synthetic-fixture.txt', 'rule': rule}])
                self.assertNotIn(value.decode(), json.dumps(result))
        self.assertEqual(module.publication_findings('clean.txt', b'ordinary project text'), [])
        with mock.patch.dict(module.SECRET_RULES, {'unknown': __import__('re').compile(b'test')}, clear=True):
            with self.assertRaisesRegex(ValueError, 'Unrecognized publication finding rule'):
                module.publication_findings('synthetic.txt', b'test')


class CoverageAndSnapshotTests(unittest.TestCase):
    def test_extensionless_interpreted_tools_are_required_coverage_targets(self):
        for header in (b'#!/usr/bin/env python3\n', b'#!/usr/bin/python3.14\n', b'#!/usr/bin/env -S python3 -u\n'):
            self.assertEqual(sast.expected_language('scripts/tool', header), 'python')
        self.assertEqual(sast.expected_language('scripts/tool', b'#!/usr/bin/env node\n'), 'javascript-typescript')
        for data in (b'# documentation mentioning python3', b'#!/usr/bin/env python-wrapper\n', b'#!/bin/sh\n# python3'):
            self.assertIsNone(sast.expected_language('scripts/tool', data))

    def test_database_file_coverage_is_distinct_from_source_inventory(self):
        self.assertEqual(sast.coverage(decoded(['app.ts']), manifest(), 'javascript-typescript')['extractedExpectedFiles'], 1)
        for value in (decoded([]), decoded(['worker.py']), decoded(['outside.ts']),
                      {'#select': {'columns': [{'name': 'path', 'kind': 'String'}], 'tuples': [['app.ts']], 'next': 50}}):
            with self.assertRaises(sast.Rejected):
                sast.coverage(value, manifest(), 'javascript-typescript')

    def test_partial_or_malformed_coverage_rejected(self):
        values = [decoded(['../app.ts']), {}, {'#select': {'tuples': [['app.ts']]}},
                  {'#select': {'columns': [{'name': 'path', 'kind': 'String'}], 'tuples': [['app.ts', 'invented']]}}]
        for value in values:
            with self.assertRaises(sast.Rejected):
                sast.coverage(value, manifest(), 'javascript-typescript')

    def test_snapshot_includes_untracked_source_excludes_ignored_and_detects_changes(self):
        with tempfile.TemporaryDirectory(prefix='gc-sast-policy-') as temporary:
            root = Path(temporary)
            subprocess.run(['git', 'init', '-q', root], check=True)
            for path, data in {'.gitignore': '.local/\n.env\n', 'app.ts': 'export const value = 1;',
                               'worker.py': 'value = 1\n', 'scripts/tool': '#!/usr/bin/env python3\nvalue = 2\n',
                               '.github/workflows/check.yml': 'name: fixture\n',
                               '.env': 'SYNTHETIC_IGNORED_VALUE=1\n'}.items():
                file = root / path; file.parent.mkdir(parents=True, exist_ok=True); file.write_text(data)
            subprocess.run(['git', '-C', str(root), 'add', '.gitignore'], check=True)
            # Tests never create a project commit or sign-off; this disposable fixture needs a HEAD.
            subprocess.run(['git', '-C', str(root), '-c', 'user.name=Synthetic Test', '-c',
                            'user.email=fixture@example.invalid', 'commit', '-qm', 'synthetic fixture'], check=True)
            source = root / '.local/source'
            result = sast.snapshot(root, source, POLICY)
            self.assertTrue(result['dirty'])
            self.assertIn('app.ts', result['files'])
            self.assertNotIn('.env', result['files'])
            self.assertIn('scripts/tool', result['expected']['python'])
            self.assertEqual(set(result['expected']), set(sast.LANGUAGES))
            (source / 'app.ts').write_text('modified')
            with self.assertRaises(sast.Rejected):
                sast.verify_snapshot(source, result)

    def test_snapshot_rejects_concurrent_restoration_of_a_deleted_tracked_file(self):
        with tempfile.TemporaryDirectory(prefix='gc-sast-restored-') as temporary:
            root = Path(temporary)
            subprocess.run(['git', 'init', '-q', root], check=True)
            for name, data in {'.gitignore': '.local/\n', 'app.ts': 'export const x = 1', 'worker.py': 'x = 1',
                               'restored.py': 'x = 2', '.github/workflows/test.yml': 'name: fixture'}.items():
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(data)
            subprocess.run(['git', '-C', str(root), 'add', '.'], check=True)
            subprocess.run(['git', '-C', str(root), '-c', 'user.name=Synthetic Test', '-c',
                            'user.email=fixture@example.invalid', 'commit', '-qm', 'synthetic fixture'], check=True)
            (root / 'restored.py').unlink()
            original_git, listings = sast.git, 0
            def restoring_git(directory, *args):
                nonlocal listings
                if args[0] == 'ls-files':
                    listings += 1
                    if listings == 2:
                        (root / 'restored.py').write_text('x = 2')
                return original_git(directory, *args)
            with mock.patch.object(sast, 'git', side_effect=restoring_git):
                with self.assertRaisesRegex(sast.Rejected, 'source-presence-changed-during-snapshot'):
                    sast.snapshot(root, root / '.local/source', POLICY)

    def test_tool_manifest_detects_changed_executable_and_escaping_symlink(self):
        with tempfile.TemporaryDirectory(prefix='gc-sast-tool-') as temporary:
            root = Path(temporary); binary = root / 'codeql'; binary.write_text('synthetic executable')
            before = sast.tool_inventory(root); binary.write_text('changed')
            self.assertNotEqual(before, sast.tool_inventory(root))
            (root / 'outside').symlink_to('/etc/hosts')
            with self.assertRaises(sast.Rejected):
                sast.tool_inventory(root)

    def test_duplicate_malformed_oversized_or_nonfinite_json_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'report.json'
            for raw in ('{"runs":[],"runs":[]}', '{', '{"score":NaN}'):
                path.write_text(raw)
                with self.assertRaises(sast.Rejected):
                    sast.read_json(path)
            path.write_text('{}')
            with self.assertRaises(sast.Rejected):
                sast.read_json(path, limit=1)

    def test_publication_scrub_removes_local_roots_and_source_bodies(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'published.sarif'
            sast.publish_sarif({'message': '/private/example/source/app.ts', 'snippet': {'text': 'PRIVATE'},
                               'contents': {'text': 'PRIVATE'}, 'commandLine': 'PRIVATE'}, path,
                              [('/private/example/source', '/governance-commons')])
            text = path.read_text()
            self.assertNotIn('PRIVATE', text)
            self.assertNotIn('/private/', text)
            self.assertIn('/governance-commons/app.ts', text)


    def test_publication_scrubs_percent_encoded_pack_and_file_uri_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'published.sarif'
            root = '/Users/synthetic/Private Project/é/toolchain'
            payload = {'tool': {'extensions': [{'locations': [
                {'uri': 'file://' + sast.quote(root, safe='/') + '/qlpack.yml'},
                {'uri': sast.quote(root, safe='') + '%2Fqlpack.yml'},
            ]}]}, 'message': root + '/query.ql'}
            sast.publish_sarif(payload, output, [(root, '/codeql')])
            text = output.read_text()
            for private in ('/Users/', 'Private', '%20', '%C3%A9', '%2FUsers', 'synthetic'):
                self.assertNotIn(private, text)
            decoded = json.loads(text)
            self.assertEqual(decoded['tool']['extensions'][0]['locations'][0]['uri'], 'file:///codeql/qlpack.yml')
            self.assertEqual(decoded['tool']['extensions'][0]['locations'][1]['uri'], '%2Fcodeql%2Fqlpack.yml')
            self.assertEqual(decoded['message'], '/codeql/query.ql')


class FailureDiagnosticTests(unittest.TestCase):
    def test_only_fixed_markers_sizes_and_hashes_are_published(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); stdout = root / 'out'; stderr = root / 'err'
            private = b'SYNTHETIC_PRIVATE_VALUE /private/project/source.ts --credential=example'
            stdout.write_bytes(b'Initializing database ' + private)
            stderr.write_bytes(b'A fatal error occurred: Permission denied ' + private)
            result = sast.scanner_failure_diagnostics(stdout, stderr, 1024)
            self.assertEqual(result['streams']['stdout']['markers'], ['database_initializing'])
            self.assertEqual(result['streams']['stderr']['markers'], ['fatal_error', 'permission_denied'])
            self.assertEqual(result['streams']['stderr']['sha256'], sast.file_hash(stderr))
            self.assertEqual(result['streams']['stderr']['bytes'], stderr.stat().st_size)
            rendered = json.dumps(result)
            for value in ('SYNTHETIC_PRIVATE_VALUE', '/private/', 'source.ts', 'credential', 'Permission denied'):
                self.assertNotIn(value, rendered)
            stderr.write_bytes(b'x' * 1025)
            self.assertEqual(sast.scanner_failure_diagnostics(stdout, stderr, 1024)['streams']['stderr'],
                             {'bytes': 1025, 'available': False, 'reason': 'diagnostic-log-limit'})
            stderr.write_bytes(b'Initializing database' + b'x' * 40000 + b'Permission denied' + b'x' * 40000 + b'A fatal error occurred')
            bounded = sast.scanner_failure_diagnostics(stdout, stderr, 100000)['streams']['stderr']
            self.assertEqual(bounded['markers'], ['database_initializing', 'fatal_error'])
            self.assertEqual(bounded['sha256'], sast.file_hash(stderr))
            stderr.unlink(); stderr.symlink_to(stdout)
            self.assertEqual(sast.scanner_failure_diagnostics(stdout, stderr, 1024)['streams']['stderr'],
                             {'available': False, 'reason': 'diagnostic-unavailable'})

    def test_real_failed_command_retains_rejection_and_success_has_no_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); runner = sast.Runner(root, POLICY)
            with self.assertRaisesRegex(sast.Rejected, 'scanner-command-failed:fixture'):
                runner.command('fixture', [sys.executable, '-c',
                    "import sys; sys.stderr.write('A fatal error occurred: synthetic-private-message'); sys.exit(2)"], root)
            self.assertEqual(runner.steps[-1]['exitCode'], 2)
            self.assertEqual(runner.failure_diagnostics['streams']['stderr']['markers'], ['fatal_error'])
            self.assertNotIn('synthetic-private-message', json.dumps(runner.failure_diagnostics))
            runner.command('success', [sys.executable, '-c', 'pass'], root)
            self.assertIsNone(runner.failure_diagnostics)
            self.assertEqual(runner.steps[-1]['exitCode'], 0)


class WorkflowTests(unittest.TestCase):
    def test_aggregate_rejects_failed_cancelled_skipped_missing_extra_children(self):
        good = dict.fromkeys(sast.LANGUAGES, 'success')
        self.assertTrue(sast.aggregate(good))
        for language in sast.LANGUAGES:
            for status in ('failure', 'cancelled', 'skipped', ''):
                changed = {**good, language: status}
                self.assertFalse(sast.aggregate(changed))
        missing = good.copy(); missing.pop('actions')
        self.assertFalse(sast.aggregate(missing))
        self.assertFalse(sast.aggregate({**good, 'unexpected': 'success'}))

    def test_every_language_has_independent_required_hosted_job_and_shared_runner(self):
        text = (sast.ROOT / '.github/workflows/security.yml').read_text()
        for language in sast.LANGUAGES:
            self.assertIn(f'  sast-{language}:', text)
            self.assertIn(f'run --language {language} --output', text)
            self.assertIn(f'needs.sast-{language}.result', text)
            self.assertIn(f'governance-commons/{language}', text)
        self.assertNotIn('pull_request_target', text)
        self.assertNotIn('paths-ignore:', text)
        self.assertNotIn('continue-on-error:', text)
        self.assertEqual(text.count('security-events: write'), 3)
        self.assertEqual(text.count('wait-for-processing: true'), 3)
        self.assertNotIn('secrets.', text)
        self.assertNotIn('init@', text)
        self.assertNotIn('analyze@', text)
        self.assertIn('permissions: {}', text)

    def test_container_has_only_owned_mounts_and_no_pull_network_or_socket(self):
        container = {'image': 'sha256:' + 'a' * 64, 'platform': 'linux-arm64',
                     'output': Path('/tmp/owned-run'), 'toolchain': Path('/tmp/owned-tool')}
        command = sast.container_command(container, ['/tmp/owned-tool/codeql', 'version'],
                                         Path('/tmp/owned-run/source'), 'gc-sast-fixture')
        self.assertIn('--pull=never', command)
        self.assertIn('--network=none', command)
        self.assertIn('--read-only', command)
        self.assertNotIn('/var/run/docker.sock', ' '.join(command))
        mounts = [command[i + 1] for i, item in enumerate(command) if item == '--mount']
        self.assertEqual(len(mounts), 3)
        self.assertEqual(sum(value.endswith(',readonly') for value in mounts), 2)
        self.assertEqual(command[command.index('--name') + 1], 'gc-sast-fixture')

    def test_timeout_removes_exact_owned_container_not_only_client_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            container = {'image': 'sha256:' + 'a' * 64, 'platform': 'linux-arm64',
                         'output': output, 'toolchain': output / 'tool'}
            runner = sast.Runner(output, POLICY, container)
            runner.deadline = 0
            process = mock.Mock(pid=1234)
            process.poll.return_value = None
            with mock.patch.object(sast.subprocess, 'Popen', return_value=process) as start, \
                    mock.patch.object(sast.subprocess, 'run') as cleanup, \
                    mock.patch.object(sast.os, 'killpg') as kill:
                with self.assertRaisesRegex(sast.Rejected, 'language-timeout'):
                    runner.command('fixture', ['/tmp/owned-tool/codeql', 'version'], output)
                command = start.call_args.args[0]
                name = command[command.index('--name') + 1]
                self.assertRegex(name, '^gc-sast-[0-9a-f]{32}$')
                self.assertEqual(cleanup.call_args.args[0], ['docker', 'container', 'rm', '--force', name])
                self.assertTrue(kill.called)
                self.assertNotIn('GITHUB_TOKEN', start.call_args.kwargs['env'])

    def test_negative_control_requires_actual_injection_rules_in_all_languages(self):
        import sast_probe
        expected = {'javascript-typescript': 'js/command-line-injection',
                    'python': 'py/command-line-injection', 'actions': 'actions/code-injection/critical'}
        result = {'purpose': 'SYNTHETIC_NEGATIVE_CONTROL', 'languages': {language: {
            'analysis': 'PASS', 'findingsGate': 'BLOCKED', 'findings': [
                {'blocking': True, 'severity': 'critical', 'ruleId': rule}]}
            for language, rule in expected.items()}}
        self.assertTrue(sast_probe.verified_negative_control(result))
        result['languages']['javascript-typescript']['findings'][0]['ruleId'] = 'js/unrelated-high-finding'
        self.assertFalse(sast_probe.verified_negative_control(result))
        result['languages'].pop('actions')
        self.assertFalse(sast_probe.verified_negative_control(result))

    def test_container_map_requires_every_language_exactly_and_immutable_ids(self):
        values = dict.fromkeys(sast.LANGUAGES, 'sha256:' + 'a' * 64)
        self.assertEqual(sast.container_images(None, json.dumps(values)), values)
        for changed in ({'python': values['python']}, {**values, 'actions': 'mutable:tag'},
                        {**values, 'other': values['python']}):
            with self.assertRaises(sast.Rejected):
                sast.container_images(None, json.dumps(changed))
        with self.assertRaises(sast.Rejected):
            sast.container_images(values['python'], json.dumps(values))

    def test_action_pins_and_bundle_pins_are_explicit(self):
        pins = sast.read_json(sast.ROOT / '.github/action-pins.json')
        upload = [p for p in pins if p['repository'] == 'github/codeql-action/upload-sarif']
        self.assertEqual(len(upload), 1)
        self.assertEqual(upload[0]['commit'], '33d7b85da1a04171e211befe2c739303b9a4c066')
        self.assertEqual(POLICY['cliVersion'], '2.27.4')
        self.assertEqual(set(POLICY['languages']), set(sast.LANGUAGES))
        self.assertEqual(POLICY['coverageExclusions'], [])
        self.assertGreaterEqual(POLICY['diskFloorGiB'], 2)
        for bundle in POLICY['bundles'].values():
            self.assertRegex(bundle['sha256'], '^[0-9a-f]{64}$')

    def test_real_triage_register_starts_empty_without_invented_signoffs(self):
        self.assertEqual(sast.triage_register(sast.read_json(sast.ROOT / 'policies/sast-triage.json')), {})


if __name__ == '__main__':
    unittest.main()
