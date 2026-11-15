-- SPDX-License-Identifier: Apache-2.0
CREATE TABLE governance_models (
 tenant_id uuid NOT NULL REFERENCES tenants,
 id text NOT NULL CHECK(id ~ '^[A-Za-z_][A-Za-z0-9_.-]{0,63}$' AND id NOT IN ('__proto__','prototype','constructor')),
 current_version integer NOT NULL CHECK(current_version > 0),
 created_by uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,created_by) REFERENCES memberships(tenant_id,identity_id)
);
CREATE TABLE governance_model_versions (
 tenant_id uuid NOT NULL,
 model_id text NOT NULL,
 version integer NOT NULL CHECK(version > 0),
 definition jsonb NOT NULL CHECK(jsonb_typeof(definition) = 'object'),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[a-f0-9]{64}$'),
 created_by uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,model_id,version),
 FOREIGN KEY(tenant_id,model_id) REFERENCES governance_models(tenant_id,id),
 FOREIGN KEY(tenant_id,created_by) REFERENCES memberships(tenant_id,identity_id),
 CHECK(definition ?& ARRAY['id','version','formatVersion','attributes']
  AND jsonb_typeof(definition->'id') = 'string' AND jsonb_typeof(definition->'version') = 'number'
  AND jsonb_typeof(definition->'formatVersion') = 'number'
  AND definition->>'id' = model_id AND definition->>'version' = version::text
  AND definition->>'formatVersion' = '1' AND jsonb_typeof(definition->'attributes') = 'object')
);
ALTER TABLE governance_models ADD CONSTRAINT model_head_version_fk
 FOREIGN KEY(tenant_id,id,current_version) REFERENCES governance_model_versions(tenant_id,model_id,version)
 DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE assets
 ADD COLUMN model_id text,
 ADD COLUMN model_version integer,
 ADD COLUMN attributes jsonb NOT NULL DEFAULT '{}',
 ADD CONSTRAINT asset_attributes_object CHECK(jsonb_typeof(attributes) = 'object'),
 ADD CONSTRAINT unbound_asset_attributes_empty CHECK(model_id IS NOT NULL OR attributes='{}'::jsonb),
 ADD CONSTRAINT asset_model_paired CHECK((model_id IS NULL) = (model_version IS NULL)),
 ADD CONSTRAINT asset_model_version_fk FOREIGN KEY(tenant_id,model_id,model_version)
 REFERENCES governance_model_versions(tenant_id,model_id,version);
CREATE INDEX assets_model_bindings_idx ON assets(tenant_id,model_id,id);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['governance_models','governance_model_versions'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id=gc_tenant()) WITH CHECK (tenant_id=gc_tenant())',t);
 END LOOP;
END $$;
CREATE TRIGGER model_versions_immutable BEFORE UPDATE OR DELETE ON governance_model_versions
 FOR EACH ROW EXECUTE FUNCTION gc_immutable_audit();
GRANT SELECT,INSERT,UPDATE ON governance_models TO gc_app;
GRANT SELECT,INSERT ON governance_model_versions TO gc_app;
REVOKE UPDATE,DELETE,TRUNCATE ON governance_model_versions FROM gc_app;
