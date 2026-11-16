# SPDX-License-Identifier: Apache-2.0
"""Real filesystem provider tests; all credentials are synthetic."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from governance_workers import secrets as provider
from governance_workers.postgresql import ScanFailure


class SecretProviderTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "provider.json"
        self.entry = {"tenantIds": ["harbor"], "connectorId": "unity-catalog",
                      "clientSecret": "synthetic-old-credential"}
        self.write({"selected": self.entry, "other": {"tenantIds": ["summit"], "password": "unrelated"}})

    def write(self, value, raw=False):
        self.path.write_bytes(value if raw else json.dumps(value).encode())
        self.path.chmod(0o600)

    def resolve(self, ref="selected", tenant="harbor", connector="unity-catalog"):
        return provider.resolve(self.path, ref, tenant, connector)

    def denied(self, code, **kwargs):
        with self.assertRaises(ScanFailure) as caught:
            self.resolve(**kwargs)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)

    def test_returns_only_selected_entry_and_caller_changes_do_not_persist(self):
        actual = self.resolve()
        self.assertEqual(actual, self.entry)
        self.assertNotIn("unrelated", json.dumps(actual))
        actual["tenantIds"].append("summit")
        self.denied("SOURCE_SCOPE_DENIED", tenant="summit")

    def test_atomic_file_replacement_is_loaded_next_scan(self):
        previous = self.resolve()
        replacement = self.path.with_suffix(".new")
        replacement.write_text(json.dumps({"selected": dict(self.entry, clientSecret="synthetic-new-credential")}))
        replacement.chmod(0o600)
        os.replace(replacement, self.path)
        self.assertEqual(previous["clientSecret"], "synthetic-old-credential")
        self.assertEqual(self.resolve()["clientSecret"], "synthetic-new-credential")

    def test_legacy_connector_defaults_only_to_postgresql(self):
        self.write({"selected": {"tenantIds": ["harbor"], "password": "synthetic"}})
        self.assertEqual(self.resolve(connector="postgresql")["password"], "synthetic")
        self.denied("SOURCE_TARGET_DENIED")

    def test_exact_tenant_connector_and_reference_no_fallback(self):
        self.denied("SOURCE_SCOPE_DENIED", tenant="summit")
        self.denied("SOURCE_TARGET_DENIED", connector="postgresql")
        self.denied("SECRET_REFERENCE_DENIED", ref="missing")
        self.denied("SECRET_REFERENCE_DENIED", ref="../selected")
        self.denied("SOURCE_SCOPE_DENIED", connector="custom-code")
        self.denied("SOURCE_SCOPE_DENIED", connector=[])

    def test_malformed_membership_lists_are_not_authority(self):
        for tenants in ("harbor", [], ["harbor", "harbor"], [None], ["harbor"] * 257):
            with self.subTest(tenants_type=type(tenants).__name__):
                self.write({"selected": dict(self.entry, tenantIds=tenants)})
                self.denied("SECRET_PROVIDER_INVALID")

    def test_modes_are_refused_and_never_repaired(self):
        for mode in (0o644, 0o640, 0o604, 0o602):
            with self.subTest(mode=mode):
                self.path.chmod(mode)
                self.denied("SECRET_PROVIDER_UNAVAILABLE")
                self.assertEqual(self.path.stat().st_mode & 0o777, mode)
        self.path.chmod(0o400)
        self.assertEqual(self.resolve(), self.entry)

    def test_missing_symlink_directory_and_fifo_are_refused(self):
        self.path.unlink()
        self.denied("SECRET_PROVIDER_UNAVAILABLE")
        target = self.path.with_suffix(".real")
        target.write_text("{}")
        target.chmod(0o600)
        self.path.symlink_to(target)
        self.denied("SECRET_PROVIDER_UNAVAILABLE")
        self.path.unlink()
        self.path.mkdir()
        self.denied("SECRET_PROVIDER_UNAVAILABLE")
        self.path.rmdir()
        os.mkfifo(self.path, 0o600)
        self.denied("SECRET_PROVIDER_UNAVAILABLE")

    def test_physical_size_preflight_refuses_before_read(self):
        with self.path.open("wb") as file:
            file.truncate(provider.MAX_BYTES + 1)
        with patch.object(provider.os, "read", side_effect=AssertionError("must not materialize")):
            self.denied("SECRET_PROVIDER_UNAVAILABLE")

    def test_duplicate_keys_invalid_utf8_unicode_and_nonfinite_numbers_refused(self):
        documents = [b'{"selected":{},"selected":{}}', b'{"selected":{"tenantIds":[],"tenantIds":["harbor"]}}',
                     b'{"secret":"\xff"}', b'{"secret":"\\ud800"}', b'{"secret":NaN}', b'{"secret":1e999}', b'[]']
        for raw in documents:
            with self.subTest(length=len(raw)):
                self.write(raw, raw=True)
                self.denied("SECRET_PROVIDER_INVALID")

    def test_nesting_and_node_bounds_refused(self):
        for raw in (b'[' * 17 + b'0' + b']' * 17,
                    json.dumps({"many": [0] * provider.MAX_NODES}).encode()):
            with self.subTest(length=len(raw)):
                self.write(raw, raw=True)
                self.denied("SECRET_PROVIDER_INVALID")

    def test_in_place_change_during_read_refused(self):
        original = os.read
        changed = False

        def read(fd, size):
            nonlocal changed
            data = original(fd, size)
            if not changed:
                changed = True
                with self.path.open("ab") as file:
                    file.write(b" ")
            return data

        with patch.object(provider.os, "read", side_effect=read):
            self.denied("SECRET_PROVIDER_UNAVAILABLE")

    def test_errors_do_not_expose_path_or_underlying_io_details(self):
        with patch.object(provider.os, "open", side_effect=PermissionError("synthetic-private-path-and-value")):
            with self.assertRaises(ScanFailure) as caught:
                self.resolve()
        self.assertEqual(str(caught.exception), "SECRET_PROVIDER_UNAVAILABLE")
        self.assertTrue(caught.exception.__suppress_context__)


if __name__ == "__main__":
    unittest.main()
