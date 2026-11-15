-- SPDX-License-Identifier: Apache-2.0
-- A receipt exists only when the model version and its entire bound cohort commit.
CREATE TABLE governance_model_migrations (
 tenant_id uuid NOT NULL REFERENCES tenants,
 id uuid NOT NULL DEFAULT gen_random_uuid(),
 model_id text NOT NULL,
 from_version integer NOT NULL CHECK(from_version > 0),
 to_version integer NOT NULL CHECK(to_version = from_version + 1),
 plan jsonb NOT NULL CHECK(jsonb_typeof(plan) = 'object'),
 plan_hash text NOT NULL CHECK(plan_hash ~ '^[a-f0-9]{64}$'),
 preview_digest text NOT NULL CHECK(preview_digest ~ '^[a-f0-9]{64}$'),
 asset_count integer NOT NULL CHECK(asset_count BETWEEN 0 AND 1000),
 assets jsonb NOT NULL CHECK(jsonb_typeof(assets) = 'array' AND jsonb_array_length(assets) = asset_count),
 executed_by uuid NOT NULL,
 executed_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,id),
 UNIQUE(tenant_id,model_id,to_version),
 FOREIGN KEY(tenant_id,model_id,from_version) REFERENCES governance_model_versions(tenant_id,model_id,version),
 FOREIGN KEY(tenant_id,model_id,to_version) REFERENCES governance_model_versions(tenant_id,model_id,version),
 FOREIGN KEY(tenant_id,executed_by) REFERENCES memberships(tenant_id,identity_id)
);
ALTER TABLE governance_model_migrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE governance_model_migrations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON governance_model_migrations
 USING(tenant_id=gc_tenant()) WITH CHECK(tenant_id=gc_tenant());
CREATE TRIGGER model_migrations_immutable BEFORE UPDATE OR DELETE ON governance_model_migrations
 FOR EACH ROW EXECUTE FUNCTION gc_immutable_audit();
GRANT SELECT,INSERT ON governance_model_migrations TO gc_app;
REVOKE UPDATE,DELETE,TRUNCATE ON governance_model_migrations FROM gc_app;
