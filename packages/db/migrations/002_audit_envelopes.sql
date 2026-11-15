-- SPDX-License-Identifier: Apache-2.0
-- Preserve the exact hashed form. Legacy rows can be verified by deterministic reconstruction.
ALTER TABLE audit ADD COLUMN envelope jsonb;
REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON schema_migrations FROM gc_app;
