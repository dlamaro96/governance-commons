-- SPDX-License-Identifier: Apache-2.0
CREATE TABLE IF NOT EXISTS tenants (id uuid PRIMARY KEY, name text NOT NULL);
CREATE TABLE IF NOT EXISTS identities (id uuid PRIMARY KEY, issuer text NOT NULL, subject text NOT NULL, name text NOT NULL, active boolean NOT NULL DEFAULT true, UNIQUE(issuer,subject));
CREATE TABLE IF NOT EXISTS memberships (tenant_id uuid NOT NULL REFERENCES tenants, identity_id uuid NOT NULL REFERENCES identities, role text NOT NULL, permissions jsonb NOT NULL DEFAULT '[]', active boolean NOT NULL DEFAULT true, PRIMARY KEY(tenant_id,identity_id));
CREATE TABLE IF NOT EXISTS sessions (id_hash text PRIMARY KEY, identity_id uuid NOT NULL REFERENCES identities, tenant_id uuid NOT NULL REFERENCES tenants, csrf text NOT NULL, expires_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS login_states (id_hash text PRIMARY KEY, verifier text NOT NULL, nonce text NOT NULL, expires_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS sources (tenant_id uuid NOT NULL REFERENCES tenants, id uuid NOT NULL, name text NOT NULL, host text NOT NULL, port integer NOT NULL CHECK(port BETWEEN 1 AND 65535), database_name text NOT NULL, schema_name text NOT NULL, secret_ref text NOT NULL, status text NOT NULL DEFAULT 'unconfigured', last_successful_scan timestamptz, permission_fingerprint text, version integer NOT NULL DEFAULT 1, PRIMARY KEY(tenant_id,id));
CREATE TABLE IF NOT EXISTS assets (tenant_id uuid NOT NULL REFERENCES tenants, id uuid NOT NULL, source_id uuid, external_id text NOT NULL, name text NOT NULL, qualified_name text NOT NULL, type text NOT NULL, description text NOT NULL DEFAULT '', owner_id uuid, parent_external_id text, metadata jsonb NOT NULL DEFAULT '{}', visibility text NOT NULL DEFAULT 'tenant' CHECK(visibility IN ('tenant','restricted')), allowed_identities jsonb NOT NULL DEFAULT '[]', status text NOT NULL DEFAULT 'active', version integer NOT NULL DEFAULT 1, observed_at timestamptz NOT NULL, updated_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,source_id,external_id), FOREIGN KEY(tenant_id,source_id) REFERENCES sources(tenant_id,id), FOREIGN KEY(tenant_id,owner_id) REFERENCES memberships(tenant_id,identity_id));
CREATE INDEX IF NOT EXISTS assets_source_idx ON assets(tenant_id,source_id,type,name,id);
CREATE TABLE IF NOT EXISTS asset_revisions (tenant_id uuid NOT NULL, asset_id uuid NOT NULL, version integer NOT NULL, snapshot jsonb NOT NULL, recorded_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,asset_id,version), FOREIGN KEY(tenant_id,asset_id) REFERENCES assets(tenant_id,id));
CREATE TABLE IF NOT EXISTS jobs (tenant_id uuid NOT NULL, id uuid NOT NULL, source_id uuid NOT NULL, status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','succeeded','failed','cancelled')), actor_id text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz, asset_count integer, error_code text, PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,source_id) REFERENCES sources(tenant_id,id));
CREATE TABLE IF NOT EXISTS audit (tenant_id uuid NOT NULL REFERENCES tenants, sequence bigint GENERATED ALWAYS AS IDENTITY, id uuid NOT NULL, actor_id text NOT NULL, actor_name text NOT NULL, action text NOT NULL, resource_id text NOT NULL, changes jsonb NOT NULL, correlation_id text NOT NULL, occurred_at timestamptz NOT NULL, previous_hash text NOT NULL, hash text NOT NULL, PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,sequence));
CREATE TABLE IF NOT EXISTS outbox (tenant_id uuid NOT NULL REFERENCES tenants, id uuid NOT NULL, event_type text NOT NULL, resource_id text NOT NULL, resource_version integer NOT NULL, payload jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), processed_at timestamptz, attempts integer NOT NULL DEFAULT 0, PRIMARY KEY(tenant_id,id));
CREATE INDEX IF NOT EXISTS outbox_pending_idx ON outbox(tenant_id,created_at) WHERE processed_at IS NULL;
CREATE TABLE IF NOT EXISTS idempotency (tenant_id uuid NOT NULL REFERENCES tenants, actor_id text NOT NULL, operation text NOT NULL, key text NOT NULL, request_hash text NOT NULL, response jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(tenant_id,actor_id,operation,key));
CREATE FUNCTION gc_tenant() RETURNS uuid LANGUAGE sql STABLE AS $$ SELECT nullif(current_setting('gc.tenant_id',true),'')::uuid $$;
CREATE FUNCTION gc_actor() RETURNS text LANGUAGE sql STABLE AS $$ SELECT nullif(current_setting('gc.actor_id',true),'') $$;
DO $$ DECLARE t text; BEGIN
FOREACH t IN ARRAY ARRAY['sources','assets','asset_revisions','jobs','audit','outbox','idempotency'] LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
 EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
 EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = gc_tenant()) WITH CHECK (tenant_id = gc_tenant())',t);
END LOOP; END $$;
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY membership_scope ON memberships USING (tenant_id=gc_tenant() OR identity_id::text=gc_actor()) WITH CHECK(tenant_id=gc_tenant());
CREATE FUNCTION gc_immutable_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit is append only'; END $$;
CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON audit FOR EACH ROW EXECUTE FUNCTION gc_immutable_audit();
CREATE TRIGGER revisions_immutable BEFORE UPDATE OR DELETE ON asset_revisions FOR EACH ROW EXECUTE FUNCTION gc_immutable_audit();
GRANT USAGE ON SCHEMA public TO gc_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO gc_app;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA public TO gc_app;
REVOKE UPDATE,DELETE,TRUNCATE ON audit,asset_revisions FROM gc_app;
REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON tenants,identities,memberships FROM gc_app;
