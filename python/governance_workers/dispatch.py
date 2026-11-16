# SPDX-License-Identifier: Apache-2.0
"""Closed built-in adapter dispatch; source input cannot import executable code."""
from . import postgresql, unity_catalog
from .postgresql import ScanFailure


def scan(source, secret, tenant_id):
    if not isinstance(source, dict) or not isinstance(secret, dict):
        raise ScanFailure("SOURCE_TARGET_DENIED")
    connector = source.get("connectorId", "postgresql")
    if secret.get("connectorId", "postgresql") != connector:
        raise ScanFailure("SOURCE_TARGET_DENIED")
    if connector not in ("postgresql", "unity-catalog"):
        raise ScanFailure("SOURCE_CONNECTOR_UNSUPPORTED")
    tenants = secret.get("tenantIds")
    if (not isinstance(tenant_id, str) or not 1 <= len(tenant_id) <= 128
            or not isinstance(tenants, list) or not 1 <= len(tenants) <= 256
            or any(not isinstance(item, str) or not 1 <= len(item) <= 128 for item in tenants)
            or len(set(tenants)) != len(tenants) or tenant_id not in tenants):
        raise ScanFailure("SOURCE_SCOPE_DENIED")
    if connector == "postgresql":
        return postgresql.scan(source, secret, tenant_id)
    if connector == "unity-catalog":
        return unity_catalog.scan(source, secret, tenant_id)
