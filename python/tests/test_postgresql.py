# SPDX-License-Identifier: Apache-2.0
import unittest
from governance_workers.postgresql import validate_target, ScanFailure

class DestinationTest(unittest.TestCase):
    def setUp(self):
        self.source = {"host": "source-postgres", "port": 5432, "database": "harbor", "schema": "public"}
        self.secret = dict(self.source, tenantIds=["harbor"])
    def test_valid_scope(self):
        validate_target(self.source, self.secret, "harbor")
    def test_tenant_denied(self):
        with self.assertRaisesRegex(ScanFailure, "SOURCE_SCOPE_DENIED"):
            validate_target(self.source, self.secret, "summit")
    def test_ssrf_target_denied(self):
        for host in ("169.254.169.254", "postgres", "localhost", "example.com"):
            with self.assertRaisesRegex(ScanFailure, "SOURCE_TARGET_DENIED"):
                validate_target(dict(self.source, host=host), self.secret, "harbor")
    def test_secret_cannot_expand_network(self):
        with self.assertRaisesRegex(ScanFailure, "SOURCE_DESTINATION_DENIED"):
            validate_target(dict(self.source, host="postgres"), dict(self.secret, host="postgres"), "harbor")

if __name__ == "__main__":
    unittest.main()
