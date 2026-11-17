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

    def test_same_stamp_same_length_rewrites_refused_even_when_json_equivalent(self):
        original = self.path.read_bytes()
        equivalent = original.replace(b'"connectorId": ', b'"connectorId":\t')
        self.assertEqual(json.loads(original), json.loads(equivalent))
        for replacement in (original.replace(b"synthetic-old-credential", b"synthetic-new-credential"), equivalent):
            with self.subTest(equivalent=replacement == equivalent):
                self.assertEqual(len(original), len(replacement))
                self.path.write_bytes(original)
                before, original_read, changed = self.path.stat(), os.read, False

                def read(fd, count):
                    nonlocal changed
                    data = original_read(fd, count)
                    if data and not changed:
                        changed = True
                        self.path.write_bytes(replacement)
                    return data

                # Simulate an indistinguishable filesystem metadata timestamp;
                # bytes still come from real reads and writes of the same inode.
                with patch.object(provider.os, "fstat", return_value=before), patch.object(provider.os, "read", side_effect=read):
                    self.denied("SECRET_PROVIDER_UNAVAILABLE")
                self.assertTrue(changed)

    def test_same_stamp_torn_valid_json_cannot_mix_tenant_and_credential(self):
        original = self.path.read_bytes().replace(b'"clientSecret":', b" " * 65536 + b'"clientSecret":')
        replacement = original.replace(b"harbor", b"summit").replace(b"synthetic-old-credential", b"synthetic-new-credential")
        self.assertEqual(len(original), len(replacement))
        self.path.write_bytes(original)
        before, original_read = self.path.stat(), os.read
        first_pass, changed, first_complete = [], False, False

        def read(fd, count):
            nonlocal changed, first_complete
            data = original_read(fd, count)
            if not first_complete:
                first_pass.append(data)
                first_complete = not data
            if data and not changed:
                changed = True
                self.path.write_bytes(replacement)
            return data

        with patch.object(provider.os, "fstat", return_value=before), patch.object(provider.os, "read", side_effect=read):
            self.denied("SECRET_PROVIDER_UNAVAILABLE")
        mixed = json.loads(b"".join(first_pass))["selected"]
        self.assertEqual(mixed["tenantIds"], ["harbor"])
        self.assertEqual(mixed["clientSecret"], "synthetic-new-credential")
        self.denied("SOURCE_SCOPE_DENIED")
        self.assertEqual(self.resolve(tenant="summit")["clientSecret"], "synthetic-new-credential")

    def test_verification_growth_is_bounded_and_refused(self):
        before, original_read, original_seek = self.path.stat(), os.read, os.lseek
        verifying, verification_bytes = False, 0

        def seek(fd, offset, whence):
            nonlocal verifying
            result = original_seek(fd, offset, whence)
            verifying = True
            self.path.write_bytes(b"x" * (provider.MAX_BYTES + 100))
            return result

        def read(fd, count):
            nonlocal verification_bytes
            data = original_read(fd, count)
            if verifying:
                verification_bytes += len(data)
            return data

        with patch.object(provider.os, "fstat", return_value=before), patch.object(provider.os, "lseek", side_effect=seek), patch.object(provider.os, "read", side_effect=read):
            self.denied("SECRET_PROVIDER_UNAVAILABLE")
        self.assertEqual(verification_bytes, provider.MAX_BYTES + 1)

    def test_verification_metadata_change_refuses_identical_bytes(self):
        original_read, original_seek, verifying, changed = os.read, os.lseek, False, False

        def seek(fd, offset, whence):
            nonlocal verifying
            verifying = True
            return original_seek(fd, offset, whence)

        def read(fd, count):
            nonlocal changed
            data = original_read(fd, count)
            if verifying and data and not changed:
                changed = True
                self.path.chmod(0o400)
            return data

        with patch.object(provider.os, "lseek", side_effect=seek), patch.object(provider.os, "read", side_effect=read):
            self.denied("SECRET_PROVIDER_UNAVAILABLE")
        self.assertTrue(changed)
        self.assertEqual(self.resolve(), self.entry)

    def test_in_flight_atomic_replacement_refuses_then_next_call_loads_new_file(self):
        replacement = self.path.with_suffix(".new")
        replacement.write_bytes(self.path.read_bytes().replace(b"synthetic-old-credential", b"synthetic-new-credential"))
        replacement.chmod(0o600)
        original_read, replaced = os.read, False

        def read(fd, count):
            nonlocal replaced
            data = original_read(fd, count)
            if data and not replaced:
                replaced = True
                os.replace(replacement, self.path)
            return data

        with patch.object(provider.os, "read", side_effect=read):
            self.denied("SECRET_PROVIDER_UNAVAILABLE")
        self.assertTrue(replaced)
        self.assertEqual(self.resolve()["clientSecret"], "synthetic-new-credential")

    def test_unlinked_or_multiple_link_provider_is_not_admitted(self):
        original_open = os.open

        def open_then_unlink(*args, **kwargs):
            fd = original_open(*args, **kwargs)
            self.path.unlink()
            return fd

        with patch.object(provider.os, "open", side_effect=open_then_unlink):
            self.denied("SECRET_PROVIDER_UNAVAILABLE")
        self.write({"selected": self.entry})
        alias = self.path.with_suffix(".hardlink")
        os.link(self.path, alias)
        self.denied("SECRET_PROVIDER_UNAVAILABLE")
        alias.unlink()
        self.assertEqual(self.resolve(), self.entry)

    def test_maximum_size_snapshot_is_bounded_on_both_reads(self):
        raw = self.path.read_bytes()
        self.path.write_bytes(raw + b" " * (provider.MAX_BYTES - len(raw)))
        original_read, total = os.read, 0

        def read(fd, count):
            nonlocal total
            data = original_read(fd, count)
            total += len(data)
            return data

        with patch.object(provider.os, "read", side_effect=read):
            self.assertEqual(self.resolve(), self.entry)
        self.assertEqual(total, 2 * provider.MAX_BYTES)

    def test_errors_do_not_expose_path_or_underlying_io_details(self):
        with patch.object(provider.os, "open", side_effect=PermissionError("synthetic-private-path-and-value")):
            with self.assertRaises(ScanFailure) as caught:
                self.resolve()
        self.assertEqual(str(caught.exception), "SECRET_PROVIDER_UNAVAILABLE")
        self.assertTrue(caught.exception.__suppress_context__)


if __name__ == "__main__":
    unittest.main()
