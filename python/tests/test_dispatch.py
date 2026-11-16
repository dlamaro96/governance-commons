# SPDX-License-Identifier: Apache-2.0
"""Closed dispatch and exact tenant/target boundaries, with no external service."""
import unittest
from unittest.mock import patch

from governance_workers import dispatch
from governance_workers.postgresql import ScanFailure


class DispatchTest(unittest.TestCase):
    def test_legacy_postgres_and_explicit_unity_select_only_exact_adapter(self):
        for connector, adapter in ((None, dispatch.postgresql), ("unity-catalog", dispatch.unity_catalog)):
            source = {} if connector is None else {"connectorId": connector}
            secret = dict(source, tenantIds=["harbor"])
            completion = {"complete": True, "records": []}
            with self.subTest(connector=connector), patch.object(adapter, "scan", return_value=completion) as call:
                self.assertIs(dispatch.scan(source, secret, "harbor"), completion)
                call.assert_called_once_with(source, secret, "harbor")

    def test_unknown_mismatched_and_malformed_shapes_never_execute(self):
        cases = [(None, {}, "SOURCE_TARGET_DENIED"), ({}, [], "SOURCE_TARGET_DENIED"),
                 ({"connectorId": "unity-catalog"}, {}, "SOURCE_TARGET_DENIED"),
                 ({"connectorId": "custom"}, {"connectorId": "custom"}, "SOURCE_CONNECTOR_UNSUPPORTED"),
                 ({"connectorId": []}, {"connectorId": []}, "SOURCE_CONNECTOR_UNSUPPORTED")]
        with patch.object(dispatch.postgresql, "scan") as pg, patch.object(dispatch.unity_catalog, "scan") as uc:
            for source, secret, code in cases:
                with self.subTest(code=code), self.assertRaisesRegex(ScanFailure, "^" + code + "$"):
                    dispatch.scan(source, secret, "harbor")
            pg.assert_not_called()
            uc.assert_not_called()

    def test_string_substring_duplicate_and_wrong_tenant_are_not_membership(self):
        with patch.object(dispatch.postgresql, "scan") as call:
            for tenants in ("harbor", ["other"], ["harbor", "harbor"], [None], [], ["harbor"] * 257):
                with self.subTest(tenants=tenants), self.assertRaisesRegex(ScanFailure, "SOURCE_SCOPE_DENIED"):
                    dispatch.scan({}, {"tenantIds": tenants}, "harbor")
            with self.assertRaisesRegex(ScanFailure, "SOURCE_SCOPE_DENIED"):
                dispatch.scan({}, {"tenantIds": ["harbor"]}, "har")
            call.assert_not_called()

    def test_adapter_failure_propagates_without_completion_or_fallback(self):
        error = ScanFailure("SOURCE_SCOPE_CHANGED")
        with patch.object(dispatch.unity_catalog, "scan", side_effect=error), patch.object(dispatch.postgresql, "scan") as fallback:
            with self.assertRaises(ScanFailure) as caught:
                dispatch.scan({"connectorId": "unity-catalog"}, {"connectorId": "unity-catalog", "tenantIds": ["harbor"]}, "harbor")
            self.assertIs(caught.exception, error)
            fallback.assert_not_called()


if __name__ == "__main__":
    unittest.main()
