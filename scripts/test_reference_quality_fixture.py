#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Host admission controls only; native fixture shape/data is checked by SQL."""
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('gc_quality_fixture', ROOT / 'scripts/runtime-install-quality-fixture.py')
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class ReferenceFixtureTests(unittest.TestCase):
    def test_closed_profiles_admit_their_own_complete_source_only(self):
        for reference, name, ready in [(False, 'source-fixture.sql', 'QUALITY_FIXTURE_READY_V1'),
                                       (True, 'reference-quality-fixture.sql', 'REFERENCE_QUALITY_FIXTURE_READY_V1')]:
            raw = (ROOT / 'deploy/compose' / name).read_bytes()
            body = fixture.fixture_sql(raw, reference=reference)
            self.assertTrue(body.rstrip().endswith("SELECT '" + ready + "';"))
            with self.assertRaises(ValueError):
                fixture.fixture_sql(raw, reference=not reference)

    def test_partial_duplicated_oversized_and_trailing_sources_refuse(self):
        raw = fixture.REFERENCE_SOURCE.read_bytes()
        for value in [raw.replace(b'-- END REFERENCE_QUALITY_FIXTURE_V1', b''),
                      raw + b'\nSELECT 1;', raw + raw, raw + b' ' * 65537,
                      raw.replace(b'REFERENCE_QUALITY_FIXTURE_READY_V1', b'QUALITY_FIXTURE_READY_V1'),
                      b'\xff' + raw]:
            with self.subTest(size=len(value)), self.assertRaises(ValueError):
                fixture.fixture_sql(value, reference=True)

    def test_no_runtime_without_explicit_launcher_flag(self):
        with patch.object(fixture, 'install') as install:
            with self.assertRaises(SystemExit):
                fixture.main(['--reference'])
            install.assert_not_called()

    def test_closed_profile_selection_reaches_install_without_changing_default(self):
        import contextlib
        import io
        for arguments, reference in [(['--run-core'], False), (['--run-core', '--reference'], True)]:
            with patch.object(fixture, 'install', return_value={'result': 'HOST_CONTROL_ONLY'}) as install, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(fixture.main(arguments), 0)
                install.assert_called_once_with(reference=reference)


if __name__ == '__main__':
    unittest.main()
