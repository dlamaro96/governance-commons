-- SPDX-License-Identifier: Apache-2.0
ALTER TABLE governance_models ADD COLUMN type_id uuid;
CREATE UNIQUE INDEX governance_model_type_identity ON governance_models(tenant_id,type_id) WHERE type_id IS NOT NULL;
ALTER TABLE assets ADD COLUMN type_state text CHECK(type_state IS NULL OR type_state ~ '^[A-Za-z_][A-Za-z0-9_.-]{0,63}$');

CREATE FUNCTION gc_type_pins_valid(pins jsonb,maximum integer) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE pin jsonb; ids text[] := ARRAY[]::text[];
BEGIN
 IF jsonb_typeof(pins) IS DISTINCT FROM 'array' THEN RETURN false; END IF;
 IF jsonb_array_length(pins)>maximum THEN RETURN false; END IF;
 FOR pin IN SELECT value FROM jsonb_array_elements(pins) LOOP
  IF jsonb_typeof(pin) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(pin))<>2 OR NOT pin ?& ARRAY['id','version']
   OR jsonb_typeof(pin->'id') IS DISTINCT FROM 'string' OR jsonb_typeof(pin->'version') IS DISTINCT FROM 'number' THEN RETURN false; END IF;
  IF pin->>'id' !~ '^[A-Za-z_][A-Za-z0-9_.-]{0,63}$' OR pin->>'id'=ANY(ARRAY['__proto__','prototype','constructor'])
   OR pin->>'version' !~ '^[1-9][0-9]{0,9}$' THEN RETURN false; END IF;
  IF (pin->>'version')::numeric>2147483647 OR pin->>'id'=ANY(ids) THEN RETURN false; END IF;
  ids:=array_append(ids,pin->>'id');
 END LOOP;
 RETURN true;
END $$;

CREATE TABLE asset_type_versions (
 tenant_id uuid NOT NULL,
 model_id text NOT NULL,
 version integer NOT NULL,
 definition jsonb NOT NULL CHECK(octet_length(definition::text)<=262144),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[a-f0-9]{64}$'),
 resolved jsonb NOT NULL CHECK(octet_length(resolved::text)<=524288),
 resolution_hash text NOT NULL CHECK(resolution_hash ~ '^[a-f0-9]{64}$'),
 created_by uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,model_id,version),
 FOREIGN KEY(tenant_id,model_id,version) REFERENCES governance_model_versions(tenant_id,model_id,version),
 FOREIGN KEY(tenant_id,created_by) REFERENCES memberships(tenant_id,identity_id),
 CHECK(jsonb_typeof(definition)='object' AND definition ?& ARRAY['formatVersion','id','version','parents','attributes','overrideAttributes','requiredOwner','lifecycle']
  AND jsonb_typeof(definition->'formatVersion')='number' AND jsonb_typeof(definition->'id')='string' AND jsonb_typeof(definition->'version')='number'
  AND definition->>'formatVersion'='1' AND definition->>'id'=model_id AND definition->>'version'=version::text
  AND gc_type_pins_valid(definition->'parents',8)),
 CHECK(jsonb_typeof(resolved)='object' AND resolved ?& ARRAY['definition','dependencies','model','requiredOwner','lifecycle']
  AND resolved->'definition'=definition AND jsonb_typeof(resolved->'dependencies')='array'
  AND gc_type_pins_valid(resolved->'dependencies',64) AND jsonb_typeof(resolved->'requiredOwner')='boolean'
  AND jsonb_typeof(resolved->'lifecycle')='object' AND jsonb_typeof(resolved->'lifecycle'->'states')='array'
  AND jsonb_array_length(resolved->'lifecycle'->'states') BETWEEN 1 AND 32)
);
CREATE TABLE asset_type_dependencies (
 tenant_id uuid NOT NULL,
 model_id text NOT NULL,
 version integer NOT NULL,
 dependency_model_id text NOT NULL,
 dependency_version integer NOT NULL,
 PRIMARY KEY(tenant_id,model_id,version,dependency_model_id),
 FOREIGN KEY(tenant_id,model_id,version) REFERENCES asset_type_versions(tenant_id,model_id,version),
 FOREIGN KEY(tenant_id,dependency_model_id,dependency_version) REFERENCES asset_type_versions(tenant_id,model_id,version),
 CHECK(model_id<>dependency_model_id)
);
DO $$ DECLARE name text; BEGIN
 FOREACH name IN ARRAY ARRAY['asset_type_versions','asset_type_dependencies'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id=gc_tenant()) WITH CHECK (tenant_id=gc_tenant())',name);
  EXECUTE format('CREATE TRIGGER immutable_version BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION gc_immutable_audit()',name);
  EXECUTE format('GRANT SELECT,INSERT ON %I TO gc_app',name);
  EXECUTE format('REVOKE UPDATE,DELETE,TRUNCATE ON %I FROM gc_app',name);
 END LOOP;
END $$;

CREATE FUNCTION gc_type_identity_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.type_id IS DISTINCT FROM OLD.type_id THEN RAISE EXCEPTION 'Asset type identity is immutable' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER type_identity_immutable BEFORE UPDATE ON governance_models FOR EACH ROW EXECUTE FUNCTION gc_type_identity_immutable();

CREATE FUNCTION gc_type_version_consistent() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE expected jsonb; actual jsonb; owner_required boolean; inherited_lifecycle jsonb; parent_lifecycle jsonb;
BEGIN
 IF NOT gc_type_pins_valid(NEW.definition->'parents',8) OR NOT gc_type_pins_valid(NEW.resolved->'dependencies',64) THEN
  RAISE EXCEPTION 'Asset type pins must be bounded unique exact references' USING ERRCODE='23514';
 END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('id',id,'version',version) ORDER BY id,version),'[]'::jsonb) INTO expected FROM (
  SELECT p->>'id' AS id,(p->>'version')::integer AS version FROM jsonb_array_elements(NEW.definition->'parents') p
  UNION
  SELECT d->>'id',(d->>'version')::integer FROM jsonb_array_elements(NEW.definition->'parents') p
   JOIN asset_type_versions v ON v.tenant_id=NEW.tenant_id AND v.model_id=p->>'id' AND v.version=(p->>'version')::integer
   CROSS JOIN LATERAL jsonb_array_elements(v.resolved->'dependencies') d
 ) closure;
 SELECT coalesce(jsonb_agg(p ORDER BY p->>'id',(p->>'version')::integer),'[]'::jsonb) INTO actual FROM jsonb_array_elements(NEW.resolved->'dependencies') p;
 IF expected IS DISTINCT FROM actual OR NOT gc_type_pins_valid(expected,64) THEN
  RAISE EXCEPTION 'Resolved dependencies must equal complete authored parent closure' USING ERRCODE='23514';
 END IF;
 IF jsonb_typeof(NEW.definition->'requiredOwner') IS DISTINCT FROM 'boolean' OR jsonb_typeof(NEW.resolved->'requiredOwner') IS DISTINCT FROM 'boolean' THEN
  RAISE EXCEPTION 'Asset type ownership constraints must be explicit booleans' USING ERRCODE='23514';
 END IF;
 SELECT (NEW.definition->>'requiredOwner')::boolean OR coalesce(bool_or((v.resolved->>'requiredOwner')::boolean),false) INTO owner_required
  FROM jsonb_array_elements(NEW.definition->'parents') p LEFT JOIN asset_type_versions v
   ON v.tenant_id=NEW.tenant_id AND v.model_id=p->>'id' AND v.version=(p->>'version')::integer;
 IF (NEW.resolved->>'requiredOwner')::boolean IS DISTINCT FROM owner_required THEN
  RAISE EXCEPTION 'Resolved ownership must retain every required parent owner' USING ERRCODE='23514';
 END IF;
 IF NEW.definition->'lifecycle'='null'::jsonb THEN
  FOR parent_lifecycle IN SELECT v.resolved->'lifecycle' FROM jsonb_array_elements(NEW.definition->'parents') p JOIN asset_type_versions v
   ON v.tenant_id=NEW.tenant_id AND v.model_id=p->>'id' AND v.version=(p->>'version')::integer LOOP
   IF inherited_lifecycle IS NOT NULL AND inherited_lifecycle IS DISTINCT FROM parent_lifecycle THEN
    RAISE EXCEPTION 'Inherited lifecycles must be unambiguous' USING ERRCODE='23514';
   END IF;
   inherited_lifecycle:=parent_lifecycle;
  END LOOP;
  -- A missing parent is rejected by the projected FK. Do not fabricate its policy.
  IF inherited_lifecycle IS NOT NULL AND inherited_lifecycle IS DISTINCT FROM NEW.resolved->'lifecycle' THEN
   RAISE EXCEPTION 'Resolved lifecycle must match its pinned inheritance' USING ERRCODE='23514';
  END IF;
  IF jsonb_array_length(NEW.definition->'parents')=0 THEN
   RAISE EXCEPTION 'A root type requires an explicit lifecycle' USING ERRCODE='23514';
  END IF;
 ELSIF NEW.definition->'lifecycle' IS DISTINCT FROM NEW.resolved->'lifecycle' THEN
  RAISE EXCEPTION 'Explicit lifecycle must match the resolution' USING ERRCODE='23514';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM governance_model_versions v JOIN governance_models m ON m.tenant_id=v.tenant_id AND m.id=v.model_id
  WHERE v.tenant_id=NEW.tenant_id AND v.model_id=NEW.model_id AND v.version=NEW.version AND m.type_id IS NOT NULL AND v.definition=NEW.resolved->'model') THEN
  RAISE EXCEPTION 'Asset type resolution must match its immutable attribute model' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER type_version_consistent BEFORE INSERT ON asset_type_versions FOR EACH ROW EXECUTE FUNCTION gc_type_version_consistent();

CREATE FUNCTION gc_type_dependencies_insert() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER AS $$ BEGIN
 INSERT INTO asset_type_dependencies(tenant_id,model_id,version,dependency_model_id,dependency_version)
  SELECT NEW.tenant_id,NEW.model_id,NEW.version,item->>'id',(item->>'version')::integer FROM jsonb_array_elements(NEW.resolved->'dependencies') item;
 RETURN NEW;
END $$;
CREATE TRIGGER type_dependencies_insert AFTER INSERT ON asset_type_versions FOR EACH ROW EXECUTE FUNCTION gc_type_dependencies_insert();
CREATE FUNCTION gc_type_dependency_guard() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER AS $$ BEGIN
 IF pg_trigger_depth()<>2 OR NOT EXISTS(SELECT 1 FROM asset_type_versions v WHERE v.tenant_id=NEW.tenant_id AND v.model_id=NEW.model_id AND v.version=NEW.version
  AND v.resolved->'dependencies' @> jsonb_build_array(jsonb_build_object('id',NEW.dependency_model_id,'version',NEW.dependency_version))) THEN
  RAISE EXCEPTION 'Asset type dependencies must derive from their immutable resolution' USING ERRCODE='42501';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER type_dependency_guard BEFORE INSERT ON asset_type_dependencies FOR EACH ROW EXECUTE FUNCTION gc_type_dependency_guard();

CREATE FUNCTION gc_typed_model_version_required() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER AS $$ BEGIN
 IF EXISTS(SELECT 1 FROM governance_models m WHERE m.tenant_id=NEW.tenant_id AND m.id=NEW.model_id AND m.type_id IS NOT NULL)
  AND NOT EXISTS(SELECT 1 FROM asset_type_versions v WHERE v.tenant_id=NEW.tenant_id AND v.model_id=NEW.model_id AND v.version=NEW.version) THEN
  RAISE EXCEPTION 'Authored asset types require a matching immutable resolved version' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER typed_model_version_required AFTER INSERT ON governance_model_versions
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gc_typed_model_version_required();

CREATE FUNCTION gc_asset_type_constraints() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER AS $$
DECLARE constraints jsonb;
BEGIN
 SELECT resolved INTO constraints FROM asset_type_versions WHERE tenant_id=NEW.tenant_id AND model_id=NEW.model_id AND version=NEW.model_version;
 IF constraints IS NULL THEN
  IF EXISTS(SELECT 1 FROM governance_models m WHERE m.tenant_id=NEW.tenant_id AND m.id=NEW.model_id AND m.type_id IS NOT NULL) THEN
   RAISE EXCEPTION 'Authored asset constraints must exist before assignment' USING ERRCODE='23514';
  END IF;
  IF NEW.type_state IS NOT NULL THEN RAISE EXCEPTION 'Attribute-only assets cannot have an authored type state' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF NEW.type_state IS NULL OR NOT constraints->'lifecycle'->'states' @> to_jsonb(NEW.type_state) THEN
  RAISE EXCEPTION 'Asset state is outside its pinned lifecycle' USING ERRCODE='23514';
 END IF;
 IF (constraints->>'requiredOwner')::boolean AND (NEW.owner_id IS NULL OR NOT EXISTS(
  SELECT 1 FROM memberships m JOIN identities i ON i.id=m.identity_id
  WHERE m.tenant_id=NEW.tenant_id AND m.identity_id=NEW.owner_id AND m.active AND i.active)) THEN
  RAISE EXCEPTION 'Asset type requires an active tenant owner' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER asset_type_constraints BEFORE INSERT OR UPDATE ON assets FOR EACH ROW EXECUTE FUNCTION gc_asset_type_constraints();
