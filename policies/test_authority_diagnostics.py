# SPDX-License-Identifier: Apache-2.0
"""Closed failure projections and actual host-command failure capture; no Docker."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import authority_diagnostics as evidence
from test_authentication_evidence import fixture as predecessor_fixture

COMMIT = 'a'*40
ROOT = Path(__file__).resolve().parents[1]
FOLDER = '.local/evidence/authority-foundation-20261116T160000-123456abcdef'
TITLE = 'PRIVATE_SYNTHETIC_NATIVE_ASSERTION'


def fixture(root):
    if not (root/'package.json').exists():
        predecessor_fixture(root)
    for name in evidence.FIXED_SOURCES:
        path = root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():path.write_text('synthetic source\n')
    for name in evidence.SOURCE_FOLDERS:(root/name).mkdir(parents=True, exist_ok=True)
    for phase in ('authority_storage', 'authority_loader', 'authority_concurrency'):
        (root/evidence.SUITES[phase]).write_text(f"test('{TITLE}', async () => {{}});\n// A safe source coordinate\n")
    (root/FOLDER).mkdir(parents=True, exist_ok=True)
    log = {'path': FOLDER+'/001-authority_loader.log', 'sha256': ''}
    raw = (f'phase=authority_loader\nexit=1\nTAP version 13\nnot ok 1 - {TITLE}\n'
           '  ---\n  error: \'PostgreSQL rejected qualification operation (57014) PRIVATE_SYNTHETIC_SECRET\'\n'
           '  stack: |-\n    PRIVATE_SYNTHETIC_STACK\n'
           '    at /PRIVATE_SYNTHETIC_PATH/tests/qualification/authority-foundation-loader.test.ts:2:4\n'
           '  ...\n1..1\n# tests 1\n'+evidence.MARKER+'suite_failed\n')
    (root/log['path']).write_text(raw);log['sha256']=evidence.digest(raw.encode())
    return {'schema_version': 1, 'result': 'FAIL', 'commit': COMMIT, 'command': evidence.COMMAND, 'profile': evidence.PROFILE,
        'started_at': '2026-11-16T16:00:00+00:00', 'recorded_at': '2026-11-16T16:00:10+00:00',
        'failed_phase': 'authority_loader', 'evidence_directory': FOLDER, 'diagnostic_sources': evidence.source_inventory(root),
        'failure_diagnostic': {'phase': 'authority_loader', 'category': 'suite_failed', 'commandLog': dict(log)},
        'private_logs': [log], 'cleanup': {'ownedRemoved': True, 'resourceInventoryPreserved': True},
        'error': 'PRIVATE_SYNTHETIC_ERROR', 'privateConfig': 'PRIVATE_SYNTHETIC_CREDENTIAL'}


class AuthorityDiagnosticTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='gc-authority-diagnostic-');self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.report=fixture(self.root)

    def validate(self, report=None):
        return evidence.safe_report(self.root, self.report if report is None else report, COMMIT)

    def write_log(self, text):
        row=self.report['private_logs'][0];(self.root/row['path']).write_text(text)
        row['sha256']=evidence.digest(text.encode());self.report['failure_diagnostic']['commandLog']=dict(row)

    def test_failure_exports_only_exact_coordinates_codes_and_digests(self):
        value=self.validate();self.assertIsNotNone(value)
        self.assertEqual(value['purpose'],'FAILURE_DIAGNOSTIC_ONLY');self.assertEqual(value['outcome'],'NOT_PASSED')
        self.assertEqual(value['sqlstates'],['57014']);self.assertTrue(value['tap_complete'])
        self.assertEqual(value['tests'],[{'file':evidence.SUITES['authority_loader'],'line':1,'status':'failed'}])
        self.assertEqual(value['failure_locations'],[{'file':evidence.SUITES['authority_loader'],'line':2,'column':4}])
        for forbidden in ('PRIVATE_SYNTHETIC','.local/','error','stdout','password','privateConfig','commandLog'):
            self.assertNotIn(forbidden,json.dumps(value))

    def test_success_stale_revision_command_profile_phase_or_source_never_publishes(self):
        for change in ({'result':'PASS'},{'result':'RUNNING'},{'schema_version':True},{'commit':'b'*40},
                       {'command':'echo success'},{'profile':'core'},{'failed_phase':'upgrade'},
                       {'recorded_at':'2026-11-16T15:00:00+00:00'},{'diagnostic_sources':[]}):
            with self.subTest(change=change):self.assertIsNone(self.validate({**self.report,**change}))
        path=self.root/'packages/authority-storage/added.ts';path.write_text('new source')
        self.assertIsNone(self.validate());path.unlink()
        path=self.root/evidence.FIXED_SOURCES[0];path.write_text('changed source')
        self.assertIsNone(self.validate())

    def test_closed_diagnostic_and_log_records_reject_forbidden_fields(self):
        for keys in [('failure_diagnostic',),('failure_diagnostic','commandLog'),('private_logs',0),('cleanup',)]:
            value=copy.deepcopy(self.report);target=value
            for key in keys:target=target[key]
            target['stdout']='PRIVATE_SYNTHETIC_SECRET';self.assertIsNone(self.validate(value))
        for phase in ('arbitrary/private/value','unknown_phase'):
            value=copy.deepcopy(self.report);value['failed_phase']=phase;value['failure_diagnostic']['phase']=phase
            self.assertIsNone(self.validate(value))

    def test_exact_log_path_hash_header_and_source_are_required(self):
        for path in ('../outside','/private/file',FOLDER+'/../elsewhere.log',FOLDER+'/001-upgrade.log'):
            value=copy.deepcopy(self.report);value['failure_diagnostic']['commandLog']['path']=path
            self.assertIsNone(self.validate(value))
        row=self.report['private_logs'][0];path=self.root/row['path'];original=path.read_bytes()
        path.write_bytes(original+b'tamper');self.assertIsNone(self.validate());path.write_bytes(original)
        path.unlink();path.symlink_to(self.root/'package.json');self.assertIsNone(self.validate());path.unlink();path.write_bytes(original)
        self.write_log(original.decode().replace('phase=authority_loader','phase=upgrade',1));self.assertIsNone(self.validate())

    def test_timeout_partial_tap_preserves_missing_tests_without_inventing_failure_or_success(self):
        self.report['failure_diagnostic']['category']='command_timeout'
        self.write_log('phase=authority_loader\nexit=-9\nTAP version 13\n'+evidence.MARKER+'command_timeout\n')
        value=self.validate();self.assertIsNotNone(value);self.assertFalse(value['tap_complete'])
        self.assertEqual(value['tests'][0]['status'],'not_observed');self.assertEqual(value['category'],'command_timeout')
        self.assertEqual(value['exit_code'],-9);self.assertEqual(value['sqlstates'],[])

    def test_unmapped_retried_titles_and_arbitrary_error_codes_are_not_exported(self):
        raw=(self.root/self.report['private_logs'][0]['path']).read_text()
        for body in (raw.replace(TITLE,'PRIVATE_SYNTHETIC_OTHER'),raw.replace('1..1',f'not ok 1 - {TITLE}\n1..1')):
            self.write_log(body);value=self.validate();self.assertFalse(value['tap_complete']);self.assertTrue(value['unmapped_test_output'])
        self.write_log(raw.replace('PostgreSQL rejected qualification operation (57014)','arbitrary SQLSTATE 28000 code: 42501'))
        self.assertEqual(self.validate()['sqlstates'],[])

    def test_invariant_without_command_is_explicit_and_cleanup_is_not_inferred(self):
        self.report['failure_diagnostic'].update(category='invariant_failed',commandLog=None)
        self.report['cleanup']={}
        value=self.validate();self.assertIsNotNone(value);self.assertIsNone(value['exit_code'])
        self.assertFalse(value['command_log_available']);self.assertEqual(value['sqlstates'],[])
        self.assertFalse(any(value['cleanup'].values()))

    def test_wrong_or_missing_command_marker_and_false_zero_exit_refuse(self):
        raw=(self.root/self.report['private_logs'][0]['path']).read_text()
        for text in (raw.replace(evidence.MARKER+'suite_failed','arbitrary'),raw.replace('exit=1','exit=0'),raw+evidence.MARKER+'suite_failed\n'):
            self.write_log(text);self.assertIsNone(self.validate())

    def test_only_failed_migration_fixed_tag_supplies_sqlstate(self):
        log=self.report['private_logs'][0]
        (self.root/log['path']).unlink()
        log['path']=FOLDER+'/001-authority-upgrade.log'
        self.report['failed_phase']='authority-upgrade'
        self.report['failure_diagnostic'].update(phase='authority-upgrade',category='command_failed')
        self.write_log('phase=authority-upgrade\nexit=1\nMIGRATION_FAILED 42702 PRIVATE_SYNTHETIC_SQL\ncode: 42501\n'+evidence.MARKER+'command_failed\n')
        result=self.validate();self.assertEqual(result['sqlstates'],['42702']);self.assertEqual(result['tests'],[])

    def test_fixed_report_loader_refuses_oversize_symlink_and_duplicate_keys(self):
        path=self.root/evidence.REPORT;path.write_text(json.dumps(self.report));self.assertIsNotNone(evidence.load_report(self.root,COMMIT))
        path.write_text('{"result":"FAIL","result":"FAIL"}');self.assertIsNone(evidence.load_report(self.root,COMMIT))
        path.write_bytes(b'x'*(4*evidence.MIB+1));self.assertIsNone(evidence.load_report(self.root,COMMIT))
        path.unlink();path.symlink_to(self.root/self.report['private_logs'][0]['path']);self.assertIsNone(evidence.load_report(self.root,COMMIT))

    def test_actual_host_command_timeout_and_nonzero_preserve_original_phase_through_cleanup(self):
        spec=importlib.util.spec_from_file_location('authority_diagnostic_test_runner',ROOT/'scripts/runtime-test-authority-foundation.py')
        runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
        for timeout in (True,False):
            with self.subTest(timeout=timeout),patch.object(runner,'ROOT',self.root):
                h=runner.Harness.__new__(runner.Harness);h.folder=self.root/FOLDER
                h.phase='authority_loader';h.serial=10;h.deadline=time.monotonic()+10;h.cleanup_deadline=None
                h.output_bytes=0;h.private_values=[];h.last_command=None;h.command_failure=None;h.report={}
                h.admission=lambda:None
                code='import time; time.sleep(2)' if timeout else 'raise SystemExit(3)'
                with self.assertRaises(RuntimeError) as caught:
                    h.command([sys.executable,'-c',code],timeout=.03 if timeout else 2)
                h.phase='cleanup'
                h.command([sys.executable,'-c','pass'],timeout=2)
                h.remember_failure(caught.exception)
                failure=h.report['failure_diagnostic'];self.assertEqual(failure['phase'],'authority_loader')
                self.assertEqual(failure['category'],'command_timeout' if timeout else 'command_failed')
                self.assertTrue((self.root/failure['commandLog']['path']).read_text().endswith(evidence.MARKER+failure['category']+'\n'))
                value=copy.deepcopy(self.report);value['failure_diagnostic']=failure
                value['private_logs']=[{'path':str(p.relative_to(self.root)),'sha256':evidence.digest(p.read_bytes())} for p in sorted((self.root/FOLDER).glob('*.log'))]
                self.assertIsNotNone(self.validate(value))

    def test_actual_suite_exit_capture_and_cleanup_failure_do_not_replace_primary(self):
        spec=importlib.util.spec_from_file_location('authority_diagnostic_suite_runner',ROOT/'scripts/runtime-test-authority-foundation.py')
        runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
        with patch.object(runner,'ROOT',self.root):
            h=runner.Harness.__new__(runner.Harness);h.folder=self.root/FOLDER;h.phase='authority_loader';h.serial=20
            h.deadline=time.monotonic()+10;h.cleanup_deadline=None;h.output_bytes=0;h.private_values=[]
            h.last_command=None;h.command_failure=None;h.report={};h.admission=lambda:None
            raw=(self.root/self.report['private_logs'][0]['path']).read_text().split('TAP version 13\n',1)[1].split(evidence.MARKER)[0]
            h.command([sys.executable,'-c','import sys; print("TAP version 13"); print('+repr(raw)+'); sys.exit(1)'],allow_failure=True,timeout=2)
            h.remember_failure(RuntimeError('private assertion'))
            self.assertEqual(h.report['failure_diagnostic']['category'],'suite_failed')
            before=copy.deepcopy(h.report['failure_diagnostic']);h.phase='cleanup'
            h.remember_failure(RuntimeError('cleanup private error'));self.assertEqual(before,h.report['failure_diagnostic'])


if __name__=='__main__':unittest.main()
