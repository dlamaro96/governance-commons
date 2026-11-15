-- SPDX-License-Identifier: Apache-2.0
-- Authored asserted relations. Prior migrations and historical snapshots are immutable.
-- Every cross-row writer shares the existing tenant ledger. Trigger acquisition is
-- deliberately nonblocking: a caller may already hold an asset row lock.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR pg_has_role('gc_app',current_user,'MEMBER') THEN
  RAISE EXCEPTION 'Relation guards require an isolated non-bypass owner' USING ERRCODE='42501';
 END IF;
END $$;
ALTER TABLE public.governance_models ADD CONSTRAINT governance_models_type_fk_identity UNIQUE(tenant_id,type_id);

CREATE FUNCTION public.gc_relation_keys(value jsonb,keys text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT jsonb_typeof(value)='object' AND value ?& keys AND value-keys='{}'::jsonb
$$;
CREATE FUNCTION public.gc_relation_safe_id(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT value ~ '^[A-Za-z_][A-Za-z0-9_.-]{0,63}$' AND value<>ALL(ARRAY['__proto__','prototype','constructor'])
$$;
CREATE FUNCTION public.gc_relation_utf16_length(value text) RETURNS integer
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT char_length(value)+count(*)::integer FROM regexp_split_to_table(value,'') c WHERE ascii(c)>65535
$$;
CREATE FUNCTION public.gc_relation_utc(value timestamptz) RETURNS text
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT to_char(value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
$$;
CREATE FUNCTION public.gc_relation_json_bounded(value jsonb,maximum_nodes integer,maximum_depth integer,maximum_bytes integer)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 WITH RECURSIVE walk(item,level) AS (
  SELECT value,0 UNION ALL
  SELECT child.item,parent.level+1 FROM walk parent CROSS JOIN LATERAL (
   SELECT v AS item FROM jsonb_each(CASE WHEN jsonb_typeof(parent.item)='object' THEN parent.item ELSE '{}'::jsonb END) obj(k,v)
   UNION ALL SELECT v FROM jsonb_array_elements(CASE WHEN jsonb_typeof(parent.item)='array' THEN parent.item ELSE '[]'::jsonb END) arr(v)
  ) child WHERE parent.level<=maximum_depth
 ), bounded AS (SELECT * FROM walk LIMIT maximum_nodes+1)
 SELECT octet_length(value::text)<=maximum_bytes AND count(*)<=maximum_nodes AND max(level)<=maximum_depth FROM bounded
$$;
CREATE FUNCTION public.gc_relation_uuid_list(value jsonb,maximum integer) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE item jsonb; previous text;
BEGIN
 IF value IS NULL OR jsonb_typeof(value)<>'array' OR jsonb_array_length(value)>maximum THEN RETURN false; END IF;
 FOR item IN SELECT v FROM jsonb_array_elements(value) a(v) LOOP
  IF jsonb_typeof(item)<>'string' OR item#>>'{}' !~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
   OR (previous IS NOT NULL AND (item#>>'{}') COLLATE "C"<=previous COLLATE "C") THEN RETURN false; END IF;
  previous:=item#>>'{}';
 END LOOP;
 RETURN true;
END $$;
CREATE FUNCTION public.gc_relation_state_list(value jsonb,nullable boolean) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE item jsonb; previous text;
BEGIN
 IF nullable AND value='null'::jsonb THEN RETURN true; END IF;
 IF value IS NULL OR jsonb_typeof(value)<>'array' OR jsonb_array_length(value) NOT BETWEEN 1 AND 32 THEN RETURN false; END IF;
 FOR item IN SELECT v FROM jsonb_array_elements(value) a(v) LOOP
  IF jsonb_typeof(item)<>'string' OR NOT public.gc_relation_safe_id(item#>>'{}')
   OR (previous IS NOT NULL AND (item#>>'{}') COLLATE "C"<=previous COLLATE "C") THEN RETURN false; END IF;
  previous:=item#>>'{}';
 END LOOP;
 RETURN true;
END $$;
CREATE FUNCTION public.gc_relation_endpoint_rules(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE item jsonb; previous text;
BEGIN
 IF value IS NULL OR jsonb_typeof(value)<>'array' OR jsonb_array_length(value) NOT BETWEEN 1 AND 32 THEN RETURN false; END IF;
 FOR item IN SELECT v FROM jsonb_array_elements(value) a(v) LOOP
  IF NOT public.gc_relation_keys(item,ARRAY['typeId','includeDescendants']) OR jsonb_typeof(item->'includeDescendants')<>'boolean'
   OR NOT public.gc_relation_uuid_list(jsonb_build_array(item->'typeId'),1)
   OR (previous IS NOT NULL AND (item->>'typeId') COLLATE "C"<=previous COLLATE "C") THEN RETURN false; END IF;
  previous:=item->>'typeId';
 END LOOP;
 RETURN true;
END $$;

CREATE TABLE public.relation_types (
 tenant_id uuid NOT NULL REFERENCES public.tenants(id),
 id text NOT NULL CHECK(public.gc_relation_safe_id(id)),
 type_id uuid NOT NULL,
 current_version integer NOT NULL CHECK(current_version>0),
 created_by uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT date_trunc('milliseconds',now()),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,type_id), UNIQUE(tenant_id,type_id,id),
 FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id)
);
CREATE TABLE public.relation_type_versions (
 tenant_id uuid NOT NULL,
 relation_type_id uuid NOT NULL,
 version integer NOT NULL CHECK(version>0),
 definition jsonb NOT NULL CHECK(public.gc_relation_json_bounded(definition,20000,24,524288)),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[a-f0-9]{64}$'),
 created_by uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT date_trunc('milliseconds',now()),
 PRIMARY KEY(tenant_id,relation_type_id,version),
 FOREIGN KEY(tenant_id,relation_type_id) REFERENCES public.relation_types(tenant_id,type_id),
 FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id)
);
ALTER TABLE public.relation_types ADD CONSTRAINT relation_type_head_version_fk
 FOREIGN KEY(tenant_id,type_id,current_version) REFERENCES public.relation_type_versions(tenant_id,relation_type_id,version)
 DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE public.relation_type_endpoints (
 tenant_id uuid NOT NULL, relation_type_id uuid NOT NULL, version integer NOT NULL,
 side text NOT NULL CHECK(side IN ('source','target')), type_id uuid NOT NULL, include_descendants boolean NOT NULL,
 PRIMARY KEY(tenant_id,relation_type_id,version,side,type_id),
 FOREIGN KEY(tenant_id,relation_type_id,version) REFERENCES public.relation_type_versions(tenant_id,relation_type_id,version),
 FOREIGN KEY(tenant_id,type_id) REFERENCES public.governance_models(tenant_id,type_id)
);
CREATE TABLE public.relations (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 relation_type_id uuid NOT NULL,
 relation_type_version integer NOT NULL CHECK(relation_type_version>0),
 source_asset_id uuid NOT NULL, target_asset_id uuid NOT NULL,
 attributes jsonb NOT NULL CHECK(jsonb_typeof(attributes)='object' AND public.gc_relation_json_bounded(attributes,20000,16,524288)),
 owner_id uuid,
 state text NOT NULL CHECK(public.gc_relation_safe_id(state)),
 version integer NOT NULL CHECK(version>0),
 status text NOT NULL CHECK(status IN ('active','tombstoned')),
 valid_from timestamptz, valid_to timestamptz,
 visibility text NOT NULL CHECK(visibility IN ('tenant','restricted')),
 allowed_identities jsonb NOT NULL CHECK(public.gc_relation_uuid_list(allowed_identities,100)),
 provenance jsonb NOT NULL,
 created_by uuid NOT NULL, updated_by uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT date_trunc('milliseconds',now()),
 updated_at timestamptz NOT NULL DEFAULT date_trunc('milliseconds',now()),
 PRIMARY KEY(tenant_id,id),
 UNIQUE(tenant_id,id,relation_type_id,relation_type_version,source_asset_id,target_asset_id),
 FOREIGN KEY(tenant_id,relation_type_id,relation_type_version) REFERENCES public.relation_type_versions(tenant_id,relation_type_id,version),
 FOREIGN KEY(tenant_id,source_asset_id) REFERENCES public.assets(tenant_id,id),
 FOREIGN KEY(tenant_id,target_asset_id) REFERENCES public.assets(tenant_id,id),
 FOREIGN KEY(tenant_id,owner_id) REFERENCES public.memberships(tenant_id,identity_id),
 FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id),
 FOREIGN KEY(tenant_id,updated_by) REFERENCES public.memberships(tenant_id,identity_id),
 CHECK((valid_from IS NULL OR (isfinite(valid_from) AND valid_from=date_trunc('milliseconds',valid_from)
   AND valid_from>='0001-01-01 UTC'::timestamptz AND valid_from<'10000-01-01 UTC'::timestamptz))
  AND (valid_to IS NULL OR (isfinite(valid_to) AND valid_to=date_trunc('milliseconds',valid_to)
   AND valid_to>='0001-01-01 UTC'::timestamptz AND valid_to<'10000-01-01 UTC'::timestamptz))
  AND (valid_from IS NULL OR valid_to IS NULL OR valid_from<valid_to)),
 CHECK((visibility='tenant' AND allowed_identities='[]'::jsonb) OR (visibility='restricted' AND jsonb_array_length(allowed_identities)>0))
);
CREATE UNIQUE INDEX relation_live_pair ON public.relations(tenant_id,relation_type_id,source_asset_id,target_asset_id) WHERE status='active';
CREATE INDEX relation_source ON public.relations(tenant_id,source_asset_id,id) WHERE status='active';
CREATE INDEX relation_target ON public.relations(tenant_id,target_asset_id,id) WHERE status='active';
CREATE INDEX relation_type_cohort ON public.relations(tenant_id,relation_type_id,id) WHERE status='active';
CREATE TABLE public.relation_revisions (
 tenant_id uuid NOT NULL, relation_id uuid NOT NULL, version integer NOT NULL CHECK(version>0),
 snapshot jsonb NOT NULL CHECK(public.gc_relation_json_bounded(snapshot,25000,24,1048576)),
 recorded_by uuid NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT date_trunc('milliseconds',now()),
 relation_type_id uuid GENERATED ALWAYS AS ((snapshot->>'relationTypeId')::uuid) STORED NOT NULL,
 relation_type_version integer GENERATED ALWAYS AS ((snapshot->>'relationTypeVersion')::integer) STORED NOT NULL,
 source_asset_id uuid GENERATED ALWAYS AS ((snapshot->'source'->>'assetId')::uuid) STORED NOT NULL,
 source_asset_version integer GENERATED ALWAYS AS ((snapshot->'source'->>'assetVersion')::integer) STORED NOT NULL,
 target_asset_id uuid GENERATED ALWAYS AS ((snapshot->'target'->>'assetId')::uuid) STORED NOT NULL,
 target_asset_version integer GENERATED ALWAYS AS ((snapshot->'target'->>'assetVersion')::integer) STORED NOT NULL,
 owner_id uuid GENERATED ALWAYS AS ((snapshot->>'ownerId')::uuid) STORED,
 PRIMARY KEY(tenant_id,relation_id,version),
 FOREIGN KEY(tenant_id,relation_id,relation_type_id,relation_type_version,source_asset_id,target_asset_id)
  REFERENCES public.relations(tenant_id,id,relation_type_id,relation_type_version,source_asset_id,target_asset_id),
 FOREIGN KEY(tenant_id,source_asset_id,source_asset_version) REFERENCES public.asset_revisions(tenant_id,asset_id,version),
 FOREIGN KEY(tenant_id,target_asset_id,target_asset_version) REFERENCES public.asset_revisions(tenant_id,asset_id,version),
 FOREIGN KEY(tenant_id,owner_id) REFERENCES public.memberships(tenant_id,identity_id),
 FOREIGN KEY(tenant_id,recorded_by) REFERENCES public.memberships(tenant_id,identity_id)
);
ALTER TABLE public.relations ADD CONSTRAINT relation_current_revision_fk
 FOREIGN KEY(tenant_id,id,version) REFERENCES public.relation_revisions(tenant_id,relation_id,version) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE public.relation_allowed_identities (
 tenant_id uuid NOT NULL, relation_id uuid NOT NULL, version integer NOT NULL, identity_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,relation_id,version,identity_id),
 FOREIGN KEY(tenant_id,relation_id,version) REFERENCES public.relation_revisions(tenant_id,relation_id,version),
 FOREIGN KEY(tenant_id,identity_id) REFERENCES public.memberships(tenant_id,identity_id)
);
CREATE TABLE public.tenant_graph_revisions (
 tenant_id uuid PRIMARY KEY REFERENCES public.tenants(id), revision bigint NOT NULL DEFAULT 0 CHECK(revision>=0)
);
-- Private transactional workset. Entries are derived from canonical writes and
-- removed only after final-state constraint checks. No caller-supplied GUC is proof.
CREATE TABLE public.relation_validation_work (
 tenant_id uuid NOT NULL REFERENCES public.tenants(id), transaction_id xid8 NOT NULL, relation_type_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,transaction_id,relation_type_id),
 FOREIGN KEY(tenant_id,relation_type_id) REFERENCES public.relation_types(tenant_id,type_id)
);
-- Backfill before FORCE RLS; no canonical data or existing audit row is changed.
INSERT INTO public.tenant_graph_revisions(tenant_id) SELECT id FROM public.tenants;
DO $$ DECLARE table_name text; BEGIN
 FOREACH table_name IN ARRAY ARRAY['relation_types','relation_type_versions','relation_type_endpoints','relations','relation_revisions','relation_allowed_identities','tenant_graph_revisions','relation_validation_work'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',table_name);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',table_name);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.gc_tenant()) WITH CHECK(tenant_id=public.gc_tenant())',table_name);
 END LOOP;
END $$;
GRANT SELECT,INSERT,UPDATE ON public.relation_types,public.relations TO gc_app;
GRANT SELECT,INSERT ON public.relation_type_versions,public.relation_revisions TO gc_app;
GRANT SELECT ON public.relation_type_endpoints,public.relation_allowed_identities,public.tenant_graph_revisions TO gc_app;
REVOKE ALL ON public.relation_validation_work FROM gc_app;
REVOKE DELETE,TRUNCATE ON public.relation_types,public.relations FROM gc_app;
DO $$ DECLARE table_name text; BEGIN
 FOREACH table_name IN ARRAY ARRAY['relation_type_versions','relation_type_endpoints','relation_revisions','relation_allowed_identities'] LOOP
  EXECUTE format('CREATE TRIGGER immutable_history BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.gc_immutable_audit()',table_name);
  EXECUTE format('REVOKE UPDATE,DELETE,TRUNCATE ON public.%I FROM gc_app',table_name);
 END LOOP;
END $$;

CREATE FUNCTION public.gc_relation_mutation_fence() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant();
BEGIN
 IF tenant IS NULL OR TG_TABLE_SCHEMA<>'public' OR TG_RELID NOT IN
  ('public.assets'::regclass,'public.asset_revisions'::regclass,'public.governance_models'::regclass,
   'public.governance_model_versions'::regclass,'public.asset_type_versions'::regclass,
   'public.relation_types'::regclass,'public.relation_type_versions'::regclass,'public.relations'::regclass) THEN
  RAISE EXCEPTION 'A scoped canonical relation mutation is required' USING ERRCODE='42501';
 END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended(tenant::text,0)) THEN
  RAISE EXCEPTION 'Canonical mutation requires a stable tenant execution window' USING ERRCODE='55P03';
 END IF;
 -- The write also rejects an old Repeatable Read snapshot after another writer.
 -- Conservative statement-level bumps are opaque and roll back with all writes.
 INSERT INTO public.tenant_graph_revisions(tenant_id,revision) VALUES(tenant,0) ON CONFLICT(tenant_id) DO NOTHING;
 UPDATE public.tenant_graph_revisions SET revision=revision+1 WHERE tenant_id=tenant AND revision<9223372036854775807;
 IF NOT FOUND THEN RAISE EXCEPTION 'Graph mutation fence is unavailable' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_mutation_fence() FROM PUBLIC;
DO $$ DECLARE table_name text; BEGIN
 FOREACH table_name IN ARRAY ARRAY['assets','asset_revisions','governance_models','governance_model_versions','asset_type_versions','relation_types','relation_type_versions','relations'] LOOP
  EXECUTE format('CREATE TRIGGER relation_mutation_fence BEFORE INSERT OR UPDATE OR DELETE ON public.%I FOR EACH STATEMENT EXECUTE FUNCTION public.gc_relation_mutation_fence()',table_name);
 END LOOP;
END $$;
CREATE FUNCTION public.gc_relation_decimal(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT value ~ '^-?(0|[1-9][0-9]*)(\.[0-9]*[1-9])?$' AND value<>'-0' AND length(value)<=1003
  AND greatest(1,length(replace(ltrim(split_part(value,'.',1),'-0'),'.',''))+length(split_part(value,'.',2)))<=1000
$$;
CREATE FUNCTION public.gc_relation_schema_valid(schema jsonb,depth integer DEFAULT 0,metadata boolean DEFAULT true) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE kind text; allowed text[]; item record; option text; bounds text[];
BEGIN
 IF schema IS NULL OR depth>8 OR jsonb_typeof(schema)<>'object' THEN RETURN false; END IF;
 kind:=schema->>'type';
 allowed:=CASE kind WHEN 'text' THEN ARRAY['minLength','maxLength'] WHEN 'richText' THEN ARRAY['minLength','maxLength']
  WHEN 'number' THEN ARRAY['integer','minimum','maximum'] WHEN 'decimal' THEN ARRAY['precision','scale','minimum','maximum']
  WHEN 'enum' THEN ARRAY['values'] WHEN 'uri' THEN ARRAY['schemes','maxLength'] WHEN 'list' THEN ARRAY['items','minItems','maxItems']
  WHEN 'object' THEN ARRAY['properties'] WHEN 'boolean' THEN ARRAY[]::text[] WHEN 'date' THEN ARRAY[]::text[]
  WHEN 'timestamp' THEN ARRAY[]::text[] WHEN 'duration' THEN ARRAY[]::text[] ELSE NULL END;
 IF allowed IS NULL OR schema-(allowed||ARRAY['type']||CASE WHEN metadata THEN ARRAY['required','label'] ELSE ARRAY[]::text[] END)<>'{}'::jsonb
  OR jsonb_typeof(schema->'type') IS DISTINCT FROM 'string' THEN RETURN false; END IF;
 IF schema ? 'required' AND jsonb_typeof(schema->'required')<>'boolean' THEN RETURN false; END IF;
 IF schema ? 'label' AND (jsonb_typeof(schema->'label')<>'string' OR public.gc_relation_utf16_length(schema->>'label')>256) THEN RETURN false; END IF;
 FOREACH option IN ARRAY ARRAY['minLength','maxLength','precision','scale','minItems','maxItems'] LOOP
  IF schema ? option AND (jsonb_typeof(schema->option)<>'number' OR schema->>option !~ '^(0|[1-9][0-9]{0,5})$'
   OR (schema->>option)::numeric>CASE WHEN option IN ('minLength','maxLength') THEN 65536 ELSE 1000 END
   OR (option='precision' AND schema->>option='0')) THEN RETURN false; END IF;
 END LOOP;
 IF coalesce((schema->>'minLength')::integer,0)>coalesce((schema->>'maxLength')::integer,65536)
 OR coalesce((schema->>'minItems')::integer,0)>coalesce((schema->>'maxItems')::integer,1000)
 OR coalesce((schema->>'scale')::integer,0)>coalesce((schema->>'precision')::integer,1000) THEN RETURN false; END IF;
 IF kind='number' THEN
  IF schema ? 'integer' AND jsonb_typeof(schema->'integer')<>'boolean' THEN RETURN false; END IF;
  FOREACH option IN ARRAY ARRAY['minimum','maximum'] LOOP
   IF schema ? option AND (jsonb_typeof(schema->option)<>'number' OR abs((schema->>option)::numeric)>1.7976931348623157e308) THEN RETURN false; END IF;
  END LOOP;
  IF schema ?& ARRAY['minimum','maximum'] AND ((schema->>'minimum')::numeric>(schema->>'maximum')::numeric
   OR (schema->>'integer'='true' AND ceil((schema->>'minimum')::numeric)>floor((schema->>'maximum')::numeric))) THEN RETURN false; END IF;
 ELSIF kind='decimal' THEN
  FOREACH option IN ARRAY ARRAY['minimum','maximum'] LOOP
   IF schema ? option AND (jsonb_typeof(schema->option)<>'string' OR NOT public.gc_relation_decimal(schema->>option)) THEN RETURN false; END IF;
  END LOOP;
  IF schema ?& ARRAY['minimum','maximum'] AND (schema->>'minimum')::numeric>(schema->>'maximum')::numeric THEN RETURN false; END IF;
 ELSIF kind IN ('enum','uri') THEN
  option:=CASE kind WHEN 'enum' THEN 'values' ELSE 'schemes' END;
  IF kind='enum' OR schema ? option THEN
   IF jsonb_typeof(schema->option) IS DISTINCT FROM 'array' OR jsonb_array_length(schema->option) NOT BETWEEN 1 AND (CASE kind WHEN 'enum' THEN 256 ELSE 8 END) THEN RETURN false; END IF;
   IF EXISTS(SELECT 1 FROM jsonb_array_elements(schema->option) v WHERE jsonb_typeof(v)<>'string'
    OR public.gc_relation_utf16_length(v#>>'{}')>CASE kind WHEN 'enum' THEN 1024 ELSE 16 END
    OR (kind='uri' AND v#>>'{}'<>ALL(ARRAY['https','http','urn','mailto','s3','gs','abfs','abfss'])))
    OR (SELECT count(*)<>count(DISTINCT v) FROM jsonb_array_elements(schema->option) v) THEN RETURN false; END IF;
  END IF;
 ELSIF kind='list' THEN
  IF NOT public.gc_relation_schema_valid(schema->'items',depth+1,false) THEN RETURN false; END IF;
 ELSIF kind='object' THEN
  IF jsonb_typeof(schema->'properties') IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(schema->'properties'))>128 THEN RETURN false; END IF;
  FOR item IN SELECT key,value FROM jsonb_each(schema->'properties') LOOP
   IF NOT public.gc_relation_safe_id(item.key) OR NOT public.gc_relation_schema_valid(item.value,depth+1,true) THEN RETURN false; END IF;
  END LOOP;
 END IF;
 RETURN true;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END $$;
CREATE FUNCTION public.gc_relation_value_valid(schema jsonb,value jsonb,depth integer DEFAULT 0) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE kind text:=schema->>'type'; item record; text_value text; whole text; fraction text; scheme text; date_value date;
BEGIN
 IF value IS NULL OR depth>16 THEN RETURN false; END IF;
 IF kind='object' THEN
  IF jsonb_typeof(value)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(value))>128
   OR EXISTS(SELECT 1 FROM jsonb_object_keys(value) k WHERE NOT (schema->'properties') ? k) THEN RETURN false; END IF;
  FOR item IN SELECT key,v FROM jsonb_each(schema->'properties') fields(key,v) LOOP
   IF NOT value ? item.key THEN IF item.v->>'required'='true' THEN RETURN false; END IF;
   ELSIF NOT public.gc_relation_value_valid(item.v,value->item.key,depth+1) THEN RETURN false; END IF;
  END LOOP;
  RETURN true;
 ELSIF kind='list' THEN
  IF jsonb_typeof(value)<>'array' OR jsonb_array_length(value) NOT BETWEEN coalesce((schema->>'minItems')::integer,0) AND coalesce((schema->>'maxItems')::integer,1000) THEN RETURN false; END IF;
  RETURN NOT EXISTS(SELECT 1 FROM jsonb_array_elements(value) v WHERE NOT public.gc_relation_value_valid(schema->'items',v,depth+1));
 ELSIF kind='boolean' THEN RETURN jsonb_typeof(value)='boolean';
 ELSIF kind='number' THEN
  IF jsonb_typeof(value)<>'number' OR abs((value#>>'{}')::numeric)>1.7976931348623157e308 THEN RETURN false; END IF;
  RETURN (schema->>'integer' IS DISTINCT FROM 'true' OR ((value#>>'{}')::numeric=trunc((value#>>'{}')::numeric) AND abs((value#>>'{}')::numeric)<=9007199254740991))
   AND (NOT schema ? 'minimum' OR (value#>>'{}')::numeric>=(schema->>'minimum')::numeric)
   AND (NOT schema ? 'maximum' OR (value#>>'{}')::numeric<=(schema->>'maximum')::numeric);
 END IF;
 IF jsonb_typeof(value)<>'string' THEN RETURN false; END IF;
 text_value:=value#>>'{}'; IF public.gc_relation_utf16_length(text_value)>65536 THEN RETURN false; END IF;
 IF kind IN ('text','richText') THEN RETURN public.gc_relation_utf16_length(text_value) BETWEEN coalesce((schema->>'minLength')::integer,0) AND coalesce((schema->>'maxLength')::integer,65536);
 ELSIF kind='decimal' THEN
  IF NOT public.gc_relation_decimal(text_value) THEN RETURN false; END IF;
  whole:=ltrim(split_part(text_value,'.',1),'-');fraction:=split_part(text_value,'.',2);
  RETURN greatest(1,CASE WHEN whole='0' THEN 0 ELSE length(whole) END+length(fraction))<=coalesce((schema->>'precision')::integer,1000)
   AND length(fraction)<=coalesce((schema->>'scale')::integer,(schema->>'precision')::integer,1000)
   AND (NOT schema ? 'minimum' OR text_value::numeric>=(schema->>'minimum')::numeric)
   AND (NOT schema ? 'maximum' OR text_value::numeric<=(schema->>'maximum')::numeric);
 ELSIF kind='enum' THEN RETURN schema->'values' @> jsonb_build_array(value);
 ELSIF kind IN ('date','timestamp') THEN
  IF kind='date' AND text_value !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' THEN RETURN false; END IF;
  IF kind='timestamp' AND text_value !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]{1,9})?Z$' THEN RETURN false; END IF;
  date_value:=left(text_value,10)::date;RETURN to_char(date_value,'YYYY-MM-DD')=left(text_value,10) AND date_value>='0001-01-01'::date;
 ELSIF kind='duration' THEN
  RETURN text_value ~ '^P(0|[1-9][0-9]{0,8})W$' OR (text_value ~ '^P((0|[1-9][0-9]{0,8})Y)?((0|[1-9][0-9]{0,8})M)?((0|[1-9][0-9]{0,8})D)?(T((0|[1-9][0-9]{0,8})H)?((0|[1-9][0-9]{0,8})M)?((0|[1-9][0-9]{0,8})(\.[0-9]{1,9})?S)?)?$'
   AND text_value<>'P' AND right(text_value,1)<>'T');
 ELSIF kind='uri' THEN
  scheme:=split_part(text_value,':',1);
  RETURN public.gc_relation_utf16_length(text_value)<=coalesce((schema->>'maxLength')::integer,65536)
   AND text_value ~ '^[A-Za-z0-9._~:/?#\[\]@!$&''()*+,;=%-]+$' AND text_value !~ '%([^0-9A-Fa-f]|[0-9A-Fa-f]([^0-9A-Fa-f]|$)|$)'
   AND text_value ~ '^[a-z][a-z0-9+.-]*:.+$'
   AND coalesce(schema->'schemes','["https","http","urn","mailto","s3","gs","abfs","abfss"]'::jsonb) @> jsonb_build_array(scheme)
   AND text_value !~ '^[a-z][a-z0-9+.-]*://[^/?#]*@'
   AND (scheme<>ALL(ARRAY['http','https']) OR text_value ~ '^https?://[^/?#[:space:]]+');
 END IF;
 RETURN false;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR datetime_field_overflow THEN RETURN false;
END $$;
CREATE FUNCTION public.gc_relation_definition_valid(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE side text; limits jsonb; step jsonb; states jsonb;
BEGIN
 IF NOT public.gc_relation_keys(value,ARRAY['formatVersion','id','version','label','inverseLabel','direction','sourceTypes','targetTypes','sourceStates','targetStates','cardinality','allowSelf','cycles','attributes','requiredOwner','lifecycle'])
 OR value->'formatVersion'<>'1'::jsonb OR jsonb_typeof(value->'id')<>'string' OR NOT public.gc_relation_safe_id(value->>'id')
 OR jsonb_typeof(value->'version')<>'number' OR value->>'version' !~ '^[1-9][0-9]{0,9}$' OR (value->>'version')::numeric>2147483647
 OR jsonb_typeof(value->'label')<>'string' OR public.gc_relation_utf16_length(value->>'label') NOT BETWEEN 1 AND 120
 OR jsonb_typeof(value->'inverseLabel')<>'string' OR public.gc_relation_utf16_length(value->>'inverseLabel') NOT BETWEEN 1 AND 120
 OR jsonb_typeof(value->'direction')<>'string' OR value->>'direction' NOT IN ('directed','undirected')
 OR jsonb_typeof(value->'cycles')<>'string' OR value->>'cycles' NOT IN ('allow','acyclic')
 OR jsonb_typeof(value->'allowSelf')<>'boolean' OR jsonb_typeof(value->'requiredOwner')<>'boolean'
 OR (value->>'cycles'='acyclic' AND value->>'allowSelf'='true')
 OR NOT public.gc_relation_endpoint_rules(value->'sourceTypes') OR NOT public.gc_relation_endpoint_rules(value->'targetTypes')
 OR NOT public.gc_relation_state_list(value->'sourceStates',true) OR NOT public.gc_relation_state_list(value->'targetStates',true)
 OR NOT public.gc_relation_keys(value->'cardinality',ARRAY['outgoing','incoming']) THEN RETURN false; END IF;
 FOREACH side IN ARRAY ARRAY['outgoing','incoming'] LOOP
  limits:=value->'cardinality'->side;
  IF NOT public.gc_relation_keys(limits,ARRAY['min','max']) OR limits->'min'<>'0'::jsonb
   OR (limits->'max'<>'null'::jsonb AND (jsonb_typeof(limits->'max')<>'number' OR limits->>'max' !~ '^[1-9][0-9]{0,3}$' OR (limits->>'max')::integer>1000)) THEN RETURN false; END IF;
 END LOOP;
 IF value->>'direction'='undirected' AND (value->'sourceTypes'<>value->'targetTypes' OR value->'sourceStates'<>value->'targetStates'
  OR value->'cardinality'->'outgoing'<>value->'cardinality'->'incoming') THEN RETURN false; END IF;
 IF NOT public.gc_relation_schema_valid(jsonb_build_object('type','object','properties',value->'attributes'))
  OR NOT public.gc_relation_keys(value->'lifecycle',ARRAY['initial','states','transitions']) THEN RETURN false; END IF;
 states:=value->'lifecycle'->'states';
 IF jsonb_typeof(states)<>'array' OR jsonb_array_length(states) NOT BETWEEN 1 AND 32
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(states) v WHERE jsonb_typeof(v)<>'string' OR NOT public.gc_relation_safe_id(v#>>'{}'))
  OR (SELECT count(*)<>count(DISTINCT v) FROM jsonb_array_elements(states) v)
  OR NOT states @> jsonb_build_array(value->'lifecycle'->'initial')
  OR jsonb_typeof(value->'lifecycle'->'transitions')<>'array' OR jsonb_array_length(value->'lifecycle'->'transitions')>256
  OR (SELECT count(*)<>count(DISTINCT v) FROM jsonb_array_elements(value->'lifecycle'->'transitions') v) THEN RETURN false; END IF;
 FOR step IN SELECT v FROM jsonb_array_elements(value->'lifecycle'->'transitions') t(v) LOOP
  IF NOT public.gc_relation_keys(step,ARRAY['from','to']) OR step->'from'=step->'to'
   OR NOT states @> jsonb_build_array(step->'from') OR NOT states @> jsonb_build_array(step->'to') THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END $$;

CREATE FUNCTION public.gc_relation_authorize(actions text[]) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE actor uuid;
BEGIN
 BEGIN actor:=public.gc_actor()::uuid; EXCEPTION WHEN invalid_text_representation THEN
  RAISE EXCEPTION 'Asserted relations require an authenticated member' USING ERRCODE='42501'; END;
 IF actor IS NULL OR NOT EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id
  WHERE m.tenant_id=public.gc_tenant() AND m.identity_id=actor AND m.active AND i.active AND m.permissions @> to_jsonb(actions)) THEN
  RAISE EXCEPTION 'Current membership does not permit this relation operation' USING ERRCODE='42501';
 END IF;
END $$;
CREATE FUNCTION public.gc_relation_publication_principals(type_identity uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE requested uuid[]; live_count bigint;
BEGIN
 SELECT count(*),array_agg(DISTINCT owner_id ORDER BY owner_id) FILTER (WHERE owner_id IS NOT NULL)
 INTO live_count,requested FROM public.relations WHERE tenant_id=public.gc_tenant() AND relation_type_id=type_identity AND status='active';
 IF live_count>1000 THEN RAISE EXCEPTION 'RELATION_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 -- Actor is added inside the reviewed function. Do not lock it separately before
 -- lower UUID owners: all global identities precede all tenant memberships.
 PERFORM public.gc_lock_type_migration_principals(coalesce(requested,ARRAY[]::uuid[]));
END $$;
CREATE FUNCTION public.gc_relation_type_head_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$ BEGIN
 PERFORM public.gc_relation_publication_principals(NEW.type_id);
 PERFORM public.gc_relation_authorize(ARRAY['models:read','models:write']);
 IF TG_OP='INSERT' THEN
  IF NEW.current_version<>1 OR NEW.created_by::text IS DISTINCT FROM public.gc_actor() THEN
   RAISE EXCEPTION 'Relation type identity starts at version one' USING ERRCODE='23514'; END IF;
 ELSIF ROW(NEW.tenant_id,NEW.id,NEW.type_id,NEW.created_by,NEW.created_at) IS DISTINCT FROM ROW(OLD.tenant_id,OLD.id,OLD.type_id,OLD.created_by,OLD.created_at)
  OR NEW.current_version::bigint<>OLD.current_version::bigint+1 THEN
  RAISE EXCEPTION 'Relation type identity is immutable and publication advances one version' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER relation_type_head_guard BEFORE INSERT OR UPDATE ON public.relation_types FOR EACH ROW EXECUTE FUNCTION public.gc_relation_type_head_guard();
CREATE FUNCTION public.gc_relation_type_version_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE head public.relation_types;
BEGIN
 PERFORM public.gc_relation_publication_principals(NEW.relation_type_id);
 PERFORM public.gc_relation_authorize(ARRAY['models:read','models:write']);
 SELECT * INTO head FROM public.relation_types WHERE tenant_id=NEW.tenant_id AND type_id=NEW.relation_type_id;
 IF head IS NULL OR NEW.created_by::text IS DISTINCT FROM public.gc_actor()
 OR NOT public.gc_relation_definition_valid(NEW.definition)
 OR NEW.definition->>'id' IS DISTINCT FROM head.id OR NEW.definition->>'version' IS DISTINCT FROM NEW.version::text
 OR NEW.definition_hash IS DISTINCT FROM public.gc_type_migration_hash(NEW.definition)
 OR NOT ((NEW.version=1 AND head.current_version=1) OR NEW.version::bigint=head.current_version::bigint+1) THEN
  RAISE EXCEPTION 'Relation definition must match its exact identity, version and hash' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER relation_type_version_guard BEFORE INSERT ON public.relation_type_versions FOR EACH ROW EXECUTE FUNCTION public.gc_relation_type_version_guard();
CREATE FUNCTION public.gc_relation_type_project() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ BEGIN
 IF TG_RELID<>'public.relation_type_versions'::regclass OR NEW.tenant_id IS DISTINCT FROM public.gc_tenant() THEN
  RAISE EXCEPTION 'Relation endpoint references require their immutable definition' USING ERRCODE='42501'; END IF;
 INSERT INTO public.relation_type_endpoints(tenant_id,relation_type_id,version,side,type_id,include_descendants)
 SELECT NEW.tenant_id,NEW.relation_type_id,NEW.version,s.side,(item->>'typeId')::uuid,(item->>'includeDescendants')::boolean
 FROM unnest(ARRAY['source','target']) s(side)
 CROSS JOIN LATERAL jsonb_array_elements(NEW.definition->(s.side||'Types')) a(item);
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_type_project() FROM PUBLIC;
CREATE TRIGGER relation_type_project AFTER INSERT ON public.relation_type_versions FOR EACH ROW EXECUTE FUNCTION public.gc_relation_type_project();
CREATE FUNCTION public.gc_relation_endpoint_projection_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.relation_type_versions v WHERE v.tenant_id=NEW.tenant_id AND v.relation_type_id=NEW.relation_type_id
  AND v.version=NEW.version AND v.definition->(NEW.side||'Types') @> jsonb_build_array(jsonb_build_object('typeId',NEW.type_id,'includeDescendants',NEW.include_descendants))) THEN
  RAISE EXCEPTION 'Endpoint references must equal their immutable definition' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER relation_endpoint_projection_guard BEFORE INSERT ON public.relation_type_endpoints FOR EACH ROW EXECUTE FUNCTION public.gc_relation_endpoint_projection_guard();

CREATE FUNCTION public.gc_relation_row_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE definition jsonb; expected_provenance jsonb; requested uuid[];
BEGIN
 requested:=array_remove(ARRAY[NEW.owner_id,CASE WHEN TG_OP='UPDATE' THEN OLD.owner_id ELSE NULL END],NULL);
 PERFORM public.gc_lock_type_migration_principals(requested);
 PERFORM public.gc_relation_authorize(ARRAY['catalog:read','catalog:write','models:read']);
 IF NEW.updated_by::text IS DISTINCT FROM public.gc_actor() OR NEW.updated_at<>date_trunc('milliseconds',NEW.updated_at)
  OR NEW.created_at<>date_trunc('milliseconds',NEW.created_at) THEN
  RAISE EXCEPTION 'Relation mutation attribution must match its authenticated actor' USING ERRCODE='23514'; END IF;
 SELECT v.definition INTO definition FROM public.relation_type_versions v
  WHERE v.tenant_id=NEW.tenant_id AND v.relation_type_id=NEW.relation_type_id AND v.version=NEW.relation_type_version;
 IF definition IS NULL THEN RAISE EXCEPTION 'Relation type is unavailable' USING ERRCODE='23503'; END IF;
 IF (definition->>'direction'='undirected' AND NEW.source_asset_id>NEW.target_asset_id)
  OR (definition->>'allowSelf'='false' AND NEW.source_asset_id=NEW.target_asset_id)
  OR NOT definition->'lifecycle'->'states' @> to_jsonb(NEW.state)
  OR NOT public.gc_relation_value_valid(jsonb_build_object('type','object','properties',definition->'attributes'),NEW.attributes)
  OR (NEW.visibility='restricted' AND NOT NEW.allowed_identities @> jsonb_build_array(public.gc_actor())) THEN
  RAISE EXCEPTION 'Relation fields violate their pinned definition or visibility' USING ERRCODE='23514'; END IF;
 IF (definition->>'requiredOwner'='true' OR (NEW.owner_id IS NOT NULL AND (TG_OP='INSERT' OR NEW.owner_id IS DISTINCT FROM OLD.owner_id)))
  AND (NEW.owner_id IS NULL OR NOT EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id
   WHERE m.tenant_id=NEW.tenant_id AND m.identity_id=NEW.owner_id AND m.active AND i.active)) THEN
  RAISE EXCEPTION 'Relation owner must be an active tenant member' USING ERRCODE='23514'; END IF;
 expected_provenance:=jsonb_build_object('origin','asserted','source',jsonb_build_object('kind','manual','identityId',NEW.created_by),
  'authority','manual-assertion','precedence',NULL,'actorId',NEW.created_by,'assertedAt',public.gc_relation_utc(NEW.created_at),
  'ingestedAt',public.gc_relation_utc(NEW.created_at),'sourceObservedAt',NULL,'sourceVersion',NULL,'sourceRunId',NULL,'confidence',NULL);
 IF NEW.provenance IS DISTINCT FROM expected_provenance THEN
  RAISE EXCEPTION 'Asserted provenance must retain its actual actor and transaction time' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.version<>1 OR NEW.status<>'active' OR NEW.state<>definition->'lifecycle'->>'initial'
   OR NEW.created_by<>NEW.updated_by OR NEW.created_at<>NEW.updated_at
   OR NOT EXISTS(SELECT 1 FROM public.relation_types t WHERE t.tenant_id=NEW.tenant_id AND t.type_id=NEW.relation_type_id AND t.current_version=NEW.relation_type_version) THEN
   RAISE EXCEPTION 'New asserted relation requires the current type and initial lifecycle state' USING ERRCODE='23514'; END IF;
 ELSE
  IF OLD.status='tombstoned' OR ROW(NEW.tenant_id,NEW.id,NEW.relation_type_id,NEW.relation_type_version,NEW.source_asset_id,NEW.target_asset_id,NEW.created_by,NEW.created_at,NEW.provenance)
   IS DISTINCT FROM ROW(OLD.tenant_id,OLD.id,OLD.relation_type_id,OLD.relation_type_version,OLD.source_asset_id,OLD.target_asset_id,OLD.created_by,OLD.created_at,OLD.provenance)
   OR NEW.version::bigint<>OLD.version::bigint+1 OR NEW.updated_at<OLD.updated_at THEN
   RAISE EXCEPTION 'Relation identity, pins and tombstones are immutable; versions advance by one' USING ERRCODE='23514'; END IF;
  IF NEW.status='tombstoned' AND ROW(NEW.attributes,NEW.owner_id,NEW.state,NEW.valid_from,NEW.valid_to,NEW.visibility,NEW.allowed_identities)
   IS DISTINCT FROM ROW(OLD.attributes,OLD.owner_id,OLD.state,OLD.valid_from,OLD.valid_to,OLD.visibility,OLD.allowed_identities) THEN
   RAISE EXCEPTION 'Tombstone cannot rewrite relation values' USING ERRCODE='23514'; END IF;
  IF NEW.state<>OLD.state AND (NEW.status<>'active'
   OR NOT definition->'lifecycle'->'transitions' @> jsonb_build_array(jsonb_build_object('from',OLD.state,'to',NEW.state))
   OR ROW(NEW.attributes,NEW.owner_id,NEW.valid_from,NEW.valid_to,NEW.visibility,NEW.allowed_identities)
    IS DISTINCT FROM ROW(OLD.attributes,OLD.owner_id,OLD.valid_from,OLD.valid_to,OLD.visibility,OLD.allowed_identities)) THEN
   RAISE EXCEPTION 'Relation lifecycle changes require one legal pinned transition' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER relation_row_guard BEFORE INSERT OR UPDATE ON public.relations FOR EACH ROW EXECUTE FUNCTION public.gc_relation_row_guard();

CREATE FUNCTION public.gc_relation_snapshot_base(row_value public.relations) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE definition jsonb; logical_key text;
BEGIN
 SELECT v.definition,t.id INTO definition,logical_key FROM public.relation_type_versions v JOIN public.relation_types t
  ON t.tenant_id=v.tenant_id AND t.type_id=v.relation_type_id
  WHERE v.tenant_id=row_value.tenant_id AND v.relation_type_id=row_value.relation_type_id AND v.version=row_value.relation_type_version;
 RETURN jsonb_build_object('id',row_value.id,'relationTypeId',row_value.relation_type_id,'relationTypeKey',logical_key,
  'relationTypeVersion',row_value.relation_type_version,'version',row_value.version,'direction',definition->'direction',
  'label',definition->'label','inverseLabel',definition->'inverseLabel','attributes',row_value.attributes,
  'ownerId',row_value.owner_id,'state',row_value.state,'validFrom',public.gc_relation_utc(row_value.valid_from),'validTo',public.gc_relation_utc(row_value.valid_to),
  'visibility',row_value.visibility,'allowedIdentityIds',row_value.allowed_identities,'status',row_value.status,'provenance',row_value.provenance,
  'createdAt',public.gc_relation_utc(row_value.created_at),'createdBy',row_value.created_by,'updatedAt',public.gc_relation_utc(row_value.updated_at),'updatedBy',row_value.updated_by);
END $$;
CREATE FUNCTION public.gc_relation_endpoint_snapshot(tenant uuid,asset uuid,revision integer) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE recorded jsonb; type_identity uuid;
BEGIN
 SELECT r.snapshot,m.type_id INTO recorded,type_identity FROM public.asset_revisions r
 JOIN public.governance_models m ON m.tenant_id=r.tenant_id AND m.id=r.snapshot->>'modelId'
 JOIN public.asset_type_versions v ON v.tenant_id=m.tenant_id AND v.model_id=m.id AND v.version=(r.snapshot->>'modelVersion')::integer
 WHERE r.tenant_id=tenant AND r.asset_id=asset AND r.version=revision AND m.type_id IS NOT NULL
  AND r.snapshot->>'id'=asset::text AND r.snapshot->>'version'=revision::text
  AND jsonb_typeof(r.snapshot->'name')='string' AND (v.resolved->'lifecycle'->'states') @> (r.snapshot->'typeState');
 IF recorded IS NULL THEN RAISE EXCEPTION 'Relation endpoint revision is unavailable or not an authored type' USING ERRCODE='23514'; END IF;
 RETURN jsonb_build_object('assetId',asset,'name',recorded->'name','assetVersion',revision,'typeId',type_identity,
  'modelId',recorded->'modelId','modelVersion',recorded->'modelVersion','state',recorded->'typeState');
END $$;
CREATE FUNCTION public.gc_relation_revision_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE parent public.relations; expected jsonb; source_version integer; target_version integer;
BEGIN
 SELECT * INTO parent FROM public.relations WHERE tenant_id=NEW.tenant_id AND id=NEW.relation_id;
 IF parent IS NULL OR NEW.version<>parent.version OR NEW.recorded_by<>parent.updated_by OR NEW.recorded_at<>parent.updated_at
  OR NEW.recorded_by::text IS DISTINCT FROM public.gc_actor() THEN
  RAISE EXCEPTION 'Relation revision must record its current canonical mutation' USING ERRCODE='23514'; END IF;
 source_version:=(NEW.snapshot->'source'->>'assetVersion')::integer;target_version:=(NEW.snapshot->'target'->>'assetVersion')::integer;
 IF NOT EXISTS(SELECT 1 FROM public.assets a WHERE a.tenant_id=NEW.tenant_id AND a.id=parent.source_asset_id AND a.version=source_version)
  OR NOT EXISTS(SELECT 1 FROM public.assets a WHERE a.tenant_id=NEW.tenant_id AND a.id=parent.target_asset_id AND a.version=target_version) THEN
  RAISE EXCEPTION 'Relation revision must capture actual current endpoint revisions' USING ERRCODE='23514'; END IF;
 expected:=public.gc_relation_snapshot_base(parent)||jsonb_build_object(
  'source',public.gc_relation_endpoint_snapshot(NEW.tenant_id,parent.source_asset_id,source_version),
  'target',public.gc_relation_endpoint_snapshot(NEW.tenant_id,parent.target_asset_id,target_version));
 IF EXISTS(SELECT 1 FROM public.assets a JOIN public.governance_models m ON m.tenant_id=a.tenant_id AND m.id=a.model_id
  CROSS JOIN LATERAL (SELECT CASE WHEN a.id=parent.source_asset_id THEN expected->'source' ELSE expected->'target' END AS endpoint) s
  WHERE a.tenant_id=NEW.tenant_id AND a.id IN (parent.source_asset_id,parent.target_asset_id)
   AND jsonb_build_object('assetId',a.id,'name',a.name,'assetVersion',a.version,'typeId',m.type_id,
    'modelId',a.model_id,'modelVersion',a.model_version,'state',a.type_state) IS DISTINCT FROM s.endpoint) THEN
  RAISE EXCEPTION 'Current endpoint values require their exact immutable asset revision' USING ERRCODE='23514'; END IF;
 IF NEW.snapshot IS DISTINCT FROM expected THEN RAISE EXCEPTION 'Relation snapshot must equal canonical values and real endpoint revisions' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER relation_revision_guard BEFORE INSERT ON public.relation_revisions FOR EACH ROW EXECUTE FUNCTION public.gc_relation_revision_guard();
CREATE FUNCTION public.gc_relation_acl_project() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ BEGIN
 IF TG_RELID<>'public.relation_revisions'::regclass OR NEW.tenant_id IS DISTINCT FROM public.gc_tenant() THEN
  RAISE EXCEPTION 'Relation visibility references require their immutable revision' USING ERRCODE='42501'; END IF;
 INSERT INTO public.relation_allowed_identities(tenant_id,relation_id,version,identity_id)
 SELECT NEW.tenant_id,NEW.relation_id,NEW.version,(item#>>'{}')::uuid FROM jsonb_array_elements(NEW.snapshot->'allowedIdentityIds') a(item);
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_acl_project() FROM PUBLIC;
CREATE TRIGGER relation_acl_project AFTER INSERT ON public.relation_revisions FOR EACH ROW EXECUTE FUNCTION public.gc_relation_acl_project();
CREATE FUNCTION public.gc_relation_acl_projection_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.relation_revisions r WHERE r.tenant_id=NEW.tenant_id AND r.relation_id=NEW.relation_id AND r.version=NEW.version
  AND r.snapshot->'allowedIdentityIds' @> jsonb_build_array(NEW.identity_id)) THEN
  RAISE EXCEPTION 'Visibility references must equal their immutable revision' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER relation_acl_projection_guard BEFORE INSERT ON public.relation_allowed_identities FOR EACH ROW EXECUTE FUNCTION public.gc_relation_acl_projection_guard();

-- Mirrors model schemaDifference's migration decision: removals, type changes,
-- enum removals and URI scheme removals need migration. Other scalar constraints
-- are allowed only after all live values pass the proposed definition below.
CREATE FUNCTION public.gc_relation_schema_compatible(before_schema jsonb,after_schema jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE item record;
BEGIN
 IF before_schema->'type' IS DISTINCT FROM after_schema->'type' THEN RETURN false; END IF;
 IF before_schema->>'type'='object' THEN
  FOR item IN SELECT key,value FROM jsonb_each(before_schema->'properties') LOOP
   IF NOT (after_schema->'properties') ? item.key OR NOT public.gc_relation_schema_compatible(item.value,after_schema->'properties'->item.key) THEN RETURN false; END IF;
  END LOOP;
 ELSIF before_schema->>'type'='list' THEN RETURN public.gc_relation_schema_compatible(before_schema->'items',after_schema->'items');
 ELSIF before_schema->>'type'='enum' THEN RETURN (after_schema->'values') @> (before_schema->'values');
 ELSIF before_schema->>'type'='uri' THEN
  RETURN coalesce(after_schema->'schemes','["https","http","urn","mailto","s3","gs","abfs","abfss"]'::jsonb)
   @> coalesce(before_schema->'schemes','["https","http","urn","mailto","s3","gs","abfs","abfss"]'::jsonb);
 END IF;
 RETURN true;
END $$;
CREATE FUNCTION public.gc_relation_endpoint_eligible(tenant uuid,asset uuid,definition jsonb,side text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE endpoint public.assets; policy jsonb; own_type uuid; states jsonb;
BEGIN
 IF side NOT IN ('source','target') OR tenant IS DISTINCT FROM public.gc_tenant() THEN RETURN false; END IF;
 SELECT * INTO endpoint FROM public.assets WHERE tenant_id=tenant AND id=asset;
 SELECT m.type_id,v.resolved INTO own_type,policy FROM public.governance_models m
  JOIN public.asset_type_versions v ON v.tenant_id=m.tenant_id AND v.model_id=m.id AND v.version=endpoint.model_version
  WHERE m.tenant_id=tenant AND m.id=endpoint.model_id AND m.type_id IS NOT NULL;
 IF endpoint IS NULL OR endpoint.type_state IS NULL OR NOT policy->'lifecycle'->'states' @> to_jsonb(endpoint.type_state) THEN RETURN false; END IF;
 states:=definition->(side||'States');
 IF states<>'null'::jsonb AND NOT states @> jsonb_build_array(endpoint.type_state) THEN RETURN false; END IF;
 RETURN EXISTS(SELECT 1 FROM jsonb_array_elements(definition->(side||'Types')) rule
  WHERE (rule->>'typeId')::uuid=own_type OR (rule->>'includeDescendants'='true' AND EXISTS(
   SELECT 1 FROM public.asset_type_dependencies d JOIN public.governance_models m
    ON m.tenant_id=d.tenant_id AND m.id=d.dependency_model_id
   WHERE d.tenant_id=tenant AND d.model_id=endpoint.model_id AND d.version=endpoint.model_version AND m.type_id=(rule->>'typeId')::uuid)));
END $$;
CREATE FUNCTION public.gc_relation_enqueue() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid; type_identity uuid;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' THEN RAISE EXCEPTION 'Untrusted relation validation source' USING ERRCODE='42501'; END IF;
 tenant:=NEW.tenant_id;
 IF tenant IS DISTINCT FROM public.gc_tenant() THEN RAISE EXCEPTION 'Relation validation tenant is unavailable' USING ERRCODE='42501'; END IF;
 IF TG_RELID='public.assets'::regclass THEN
  IF TG_OP='UPDATE' AND ROW(NEW.model_id,NEW.model_version,NEW.type_state) IS DISTINCT FROM ROW(OLD.model_id,OLD.model_version,OLD.type_state) THEN
   INSERT INTO public.relation_validation_work(tenant_id,transaction_id,relation_type_id)
   SELECT DISTINCT tenant,pg_current_xact_id(),r.relation_type_id FROM public.relations r
    WHERE r.tenant_id=tenant AND r.status='active' AND (r.source_asset_id=NEW.id OR r.target_asset_id=NEW.id)
   ON CONFLICT DO NOTHING;
  END IF;
 ELSIF TG_RELID IN ('public.relations'::regclass,'public.relation_type_versions'::regclass) THEN
  type_identity:=NEW.relation_type_id;
 ELSIF TG_RELID='public.relation_types'::regclass THEN type_identity:=NEW.type_id;
 ELSE RAISE EXCEPTION 'Untrusted relation validation source' USING ERRCODE='42501'; END IF;
 IF type_identity IS NOT NULL THEN
  INSERT INTO public.relation_validation_work(tenant_id,transaction_id,relation_type_id)
   VALUES(tenant,pg_current_xact_id(),type_identity) ON CONFLICT DO NOTHING;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_enqueue() FROM PUBLIC;
CREATE TRIGGER relation_validation_enqueue AFTER INSERT OR UPDATE ON public.relations FOR EACH ROW EXECUTE FUNCTION public.gc_relation_enqueue();
CREATE TRIGGER relation_type_validation_enqueue AFTER INSERT OR UPDATE ON public.relation_types FOR EACH ROW EXECUTE FUNCTION public.gc_relation_enqueue();
CREATE TRIGGER relation_version_validation_enqueue AFTER INSERT ON public.relation_type_versions FOR EACH ROW EXECUTE FUNCTION public.gc_relation_enqueue();
CREATE TRIGGER relation_endpoint_validation_enqueue AFTER UPDATE ON public.assets FOR EACH ROW EXECUTE FUNCTION public.gc_relation_enqueue();

CREATE FUNCTION public.gc_relation_validate_final() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=NEW.tenant_id; type_identity uuid:=NEW.relation_type_id; head_definition jsonb;
 edge_count bigint; endpoint_count bigint; projected_bytes bigint; row_value record; outgoing bigint; incoming bigint;
 src uuid[]; dst uuid[]; nodes uuid[]; remaining integer[]; leaf uuid; parents integer[]; edge_index integer; node_index integer; left_index integer; right_index integer; old_parent integer;
BEGIN
 IF TG_RELID<>'public.relation_validation_work'::regclass OR tenant IS DISTINCT FROM public.gc_tenant()
  OR NEW.transaction_id<>pg_current_xact_id() THEN RAISE EXCEPTION 'Untrusted relation validation work' USING ERRCODE='42501'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.relation_validation_work w WHERE w.tenant_id=tenant AND w.transaction_id=NEW.transaction_id AND w.relation_type_id=type_identity) THEN RETURN NEW; END IF;
 SELECT v.definition INTO head_definition FROM public.relation_types t JOIN public.relation_type_versions v
  ON v.tenant_id=t.tenant_id AND v.relation_type_id=t.type_id AND v.version=t.current_version
  WHERE t.tenant_id=tenant AND t.type_id=type_identity;
 IF head_definition IS NULL THEN RAISE EXCEPTION 'Relation publication requires its immutable version' USING ERRCODE='23514'; END IF;
 SELECT count(*),coalesce(sum(octet_length(attributes::text)+octet_length(allowed_identities::text)),0) INTO edge_count,projected_bytes
  FROM public.relations WHERE tenant_id=tenant AND relation_type_id=type_identity AND status='active';
 SELECT count(*) INTO endpoint_count FROM (
  SELECT source_asset_id FROM public.relations WHERE tenant_id=tenant AND relation_type_id=type_identity AND status='active'
  UNION SELECT target_asset_id FROM public.relations WHERE tenant_id=tenant AND relation_type_id=type_identity AND status='active'
 ) endpoints;
 IF edge_count>1000 OR endpoint_count>2000 OR projected_bytes>524288 THEN
  RAISE EXCEPTION 'RELATION_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 -- Measure a deterministic bounded projected validation closure. Definitions are
 -- counted once per pin; source-native metadata is deliberately not graph input.
 SELECT coalesce(sum(octet_length(public.gc_type_migration_canonical(jsonb_build_object('id',r.id,'version',r.version,
  'relationTypeId',r.relation_type_id,'relationTypeVersion',r.relation_type_version,'sourceAssetId',r.source_asset_id,'targetAssetId',r.target_asset_id,
  'attributes',r.attributes,'ownerId',r.owner_id,'state',r.state,'visibility',r.visibility,'allowedIdentityIds',r.allowed_identities)))),0)
 INTO projected_bytes FROM public.relations r WHERE r.tenant_id=tenant AND r.relation_type_id=type_identity AND r.status='active';
 SELECT projected_bytes+coalesce(sum(octet_length(v.definition::text)),0) INTO projected_bytes
 FROM public.relation_type_versions v WHERE v.tenant_id=tenant AND v.relation_type_id=type_identity
  AND (v.version=(head_definition->>'version')::integer OR EXISTS(SELECT 1 FROM public.relations r WHERE r.tenant_id=tenant
   AND r.relation_type_id=type_identity AND r.relation_type_version=v.version AND r.status='active'));
 SELECT projected_bytes+coalesce(sum(octet_length(jsonb_build_object('id',a.id,'name',a.name,'version',a.version,
  'modelId',a.model_id,'modelVersion',a.model_version,'state',a.type_state,'visibility',a.visibility,'allowedIdentityIds',a.allowed_identities)::text)),0)
 INTO projected_bytes FROM public.assets a WHERE a.tenant_id=tenant AND EXISTS(SELECT 1 FROM public.relations r
  WHERE r.tenant_id=tenant AND r.relation_type_id=type_identity AND r.status='active' AND (r.source_asset_id=a.id OR r.target_asset_id=a.id));
 IF projected_bytes>524288 THEN RAISE EXCEPTION 'RELATION_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 FOR row_value IN SELECT r.*,v.definition AS policy FROM public.relations r JOIN public.relation_type_versions v
  ON v.tenant_id=r.tenant_id AND v.relation_type_id=r.relation_type_id AND v.version=r.relation_type_version
  WHERE r.tenant_id=tenant AND r.relation_type_id=type_identity AND r.status='active' ORDER BY r.id LOOP
  IF NOT public.gc_relation_endpoint_eligible(tenant,row_value.source_asset_id,row_value.policy,'source')
   OR NOT public.gc_relation_endpoint_eligible(tenant,row_value.target_asset_id,row_value.policy,'target') THEN
   RAISE EXCEPTION 'RELATION_MIGRATION_REQUIRED' USING ERRCODE='23514'; END IF;
  -- An ordinary mutation follows each edge's immutable pin. Publishing a newer
  -- head does not silently impose its scalar constraints on older live pins.
  IF NOT public.gc_relation_value_valid(jsonb_build_object('type','object','properties',row_value.policy->'attributes'),row_value.attributes) THEN
   RAISE EXCEPTION 'RELATION_MIGRATION_REQUIRED' USING ERRCODE='23514'; END IF;
  IF row_value.policy->>'direction'='undirected' THEN
   SELECT count(*) INTO outgoing FROM public.relations r WHERE r.tenant_id=tenant AND r.relation_type_id=type_identity AND r.status='active'
    AND (r.source_asset_id=row_value.source_asset_id OR r.target_asset_id=row_value.source_asset_id);
   SELECT count(*) INTO incoming FROM public.relations r WHERE r.tenant_id=tenant AND r.relation_type_id=type_identity AND r.status='active'
    AND (r.source_asset_id=row_value.target_asset_id OR r.target_asset_id=row_value.target_asset_id);
  ELSE
   SELECT count(*) INTO outgoing FROM public.relations r WHERE r.tenant_id=tenant AND r.relation_type_id=type_identity AND r.status='active' AND r.source_asset_id=row_value.source_asset_id;
   SELECT count(*) INTO incoming FROM public.relations r WHERE r.tenant_id=tenant AND r.relation_type_id=type_identity AND r.status='active' AND r.target_asset_id=row_value.target_asset_id;
  END IF;
  IF (row_value.policy->'cardinality'->'outgoing'->>'max' IS NOT NULL AND outgoing>(row_value.policy->'cardinality'->'outgoing'->>'max')::integer)
   OR (row_value.policy->'cardinality'->'incoming'->>'max' IS NOT NULL AND incoming>(row_value.policy->'cardinality'->'incoming'->>'max')::integer) THEN
   RAISE EXCEPTION 'RELATION_CARDINALITY' USING ERRCODE='23514'; END IF;
 END LOOP;
 IF head_definition->>'cycles'='acyclic' AND edge_count>0 THEN
  SELECT array_agg(source_asset_id ORDER BY id),array_agg(target_asset_id ORDER BY id) INTO src,dst
   FROM public.relations WHERE tenant_id=tenant AND relation_type_id=type_identity AND status='active';
  IF head_definition->>'direction'='directed' THEN
   SELECT array_agg(n) INTO remaining FROM generate_series(1,cardinality(src)) n;
   WHILE cardinality(remaining)>0 LOOP
    SELECT src[n] INTO leaf FROM unnest(remaining) n WHERE NOT EXISTS(SELECT 1 FROM unnest(remaining) m WHERE dst[m]=src[n]) ORDER BY src[n] LIMIT 1;
    IF leaf IS NULL THEN RAISE EXCEPTION 'RELATION_CYCLE' USING ERRCODE='23514'; END IF;
    SELECT coalesce(array_agg(n),'{}'::integer[]) INTO remaining FROM unnest(remaining) n WHERE src[n]<>leaf;
   END LOOP;
  ELSE
   SELECT array_agg(id ORDER BY id) INTO nodes FROM (SELECT DISTINCT unnest(src||dst) AS id) n;
   SELECT array_agg(n) INTO parents FROM generate_series(1,cardinality(nodes)) n;
   FOR edge_index IN 1..cardinality(src) LOOP
    left_index:=array_position(nodes,src[edge_index]);right_index:=array_position(nodes,dst[edge_index]);
    IF parents[left_index]=parents[right_index] THEN RAISE EXCEPTION 'RELATION_CYCLE' USING ERRCODE='23514'; END IF;
    old_parent:=parents[right_index];
    FOR node_index IN 1..cardinality(nodes) LOOP IF parents[node_index]=old_parent THEN parents[node_index]:=parents[left_index]; END IF; END LOOP;
   END LOOP;
  END IF;
 END IF;
 DELETE FROM public.relation_validation_work WHERE tenant_id=tenant AND transaction_id=NEW.transaction_id AND relation_type_id=type_identity;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_validate_final() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER relation_final_constraints AFTER INSERT ON public.relation_validation_work
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_relation_validate_final();

CREATE FUNCTION public.gc_relation_mutation_complete() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE expected_action text; snapshot jsonb;
BEGIN
 SELECT r.snapshot INTO snapshot FROM public.relation_revisions r WHERE r.tenant_id=NEW.tenant_id AND r.relation_id=NEW.id AND r.version=NEW.version;
 IF snapshot IS NULL OR (snapshot-ARRAY['source','target']) IS DISTINCT FROM public.gc_relation_snapshot_base(NEW) THEN
  RAISE EXCEPTION 'Every relation mutation requires its exact immutable revision' USING ERRCODE='23514'; END IF;
 expected_action:=CASE WHEN TG_OP='INSERT' THEN 'relation.created' WHEN NEW.status='tombstoned' THEN 'relation.tombstoned'
  WHEN NEW.state<>OLD.state THEN 'relation.transitioned' ELSE 'relation.updated' END;
 IF NOT EXISTS(SELECT 1 FROM public.audit a JOIN public.outbox o ON o.tenant_id=a.tenant_id AND o.id=a.id
  WHERE a.tenant_id=NEW.tenant_id AND a.action=expected_action AND a.resource_id=NEW.id::text AND a.actor_id=NEW.updated_by::text
   AND a.changes->>'resourceVersion'=NEW.version::text AND a.envelope->>'version'=NEW.version::text
   AND o.event_type=a.action AND o.resource_id=a.resource_id AND o.resource_version=NEW.version) THEN
  RAISE EXCEPTION 'Every relation mutation requires paired audit and outbox records' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER relation_mutation_complete AFTER INSERT OR UPDATE ON public.relations
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_relation_mutation_complete();
CREATE FUNCTION public.gc_relation_publication_complete() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE expected_action text:=CASE WHEN NEW.version=1 THEN 'relation_type.created' ELSE 'relation_type.published' END;
 logical_key text; expected jsonb; actual jsonb; previous_definition jsonb; binding record;
BEGIN
 SELECT id INTO logical_key FROM public.relation_types t WHERE t.tenant_id=NEW.tenant_id AND t.type_id=NEW.relation_type_id AND t.current_version>=NEW.version;
 IF logical_key IS NULL THEN RAISE EXCEPTION 'Relation version must be published by its head' USING ERRCODE='23514'; END IF;
 IF NEW.version>1 AND EXISTS(SELECT 1 FROM public.relations r WHERE r.tenant_id=NEW.tenant_id AND r.relation_type_id=NEW.relation_type_id AND r.status='active') THEN
  SELECT v.definition INTO previous_definition FROM public.relation_type_versions v
   WHERE v.tenant_id=NEW.tenant_id AND v.relation_type_id=NEW.relation_type_id AND v.version=NEW.version-1;
  IF previous_definition IS NULL
   OR (previous_definition-ARRAY['id','version','label','inverseLabel','attributes']) IS DISTINCT FROM (NEW.definition-ARRAY['id','version','label','inverseLabel','attributes'])
   OR NOT public.gc_relation_schema_compatible(jsonb_build_object('type','object','properties',previous_definition->'attributes'),jsonb_build_object('type','object','properties',NEW.definition->'attributes')) THEN
   RAISE EXCEPTION 'RELATION_MIGRATION_REQUIRED' USING ERRCODE='23514'; END IF;
  IF EXISTS(SELECT 1 FROM public.relations r JOIN public.relation_type_versions v
   ON v.tenant_id=r.tenant_id AND v.relation_type_id=r.relation_type_id AND v.version=r.relation_type_version
   WHERE r.tenant_id=NEW.tenant_id AND r.relation_type_id=NEW.relation_type_id AND r.status='active'
    AND (v.definition->>'requiredOwner'='true' OR NEW.definition->>'requiredOwner'='true')
    AND NOT EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id
     WHERE m.tenant_id=r.tenant_id AND m.identity_id=r.owner_id AND m.active AND i.active)) THEN
   RAISE EXCEPTION 'RELATION_MIGRATION_REQUIRED' USING ERRCODE='23514'; END IF;
 END IF;
 -- Check each publication event's exact target, including intermediate versions
 -- when multiple publications share a transaction. A later relaxed head cannot
 -- hide an incompatible earlier publication. Current mutations remain pin-scoped.
 FOR binding IN SELECT r.attributes,v.definition AS policy FROM public.relations r JOIN public.relation_type_versions v
  ON v.tenant_id=r.tenant_id AND v.relation_type_id=r.relation_type_id AND v.version=r.relation_type_version
  WHERE r.tenant_id=NEW.tenant_id AND r.relation_type_id=NEW.relation_type_id AND r.status='active' LOOP
  IF (binding.policy-ARRAY['id','version','label','inverseLabel','attributes']) IS DISTINCT FROM (NEW.definition-ARRAY['id','version','label','inverseLabel','attributes'])
   OR NOT public.gc_relation_schema_compatible(jsonb_build_object('type','object','properties',binding.policy->'attributes'),jsonb_build_object('type','object','properties',NEW.definition->'attributes'))
   OR NOT public.gc_relation_value_valid(jsonb_build_object('type','object','properties',NEW.definition->'attributes'),binding.attributes) THEN
   RAISE EXCEPTION 'RELATION_MIGRATION_REQUIRED' USING ERRCODE='23514'; END IF;
 END LOOP;
 SELECT jsonb_agg(jsonb_build_object('side',s.side,'typeId',item->'typeId','includeDescendants',item->'includeDescendants') ORDER BY s.side,item->>'typeId') INTO expected
  FROM unnest(ARRAY['source','target']) s(side) CROSS JOIN LATERAL jsonb_array_elements(NEW.definition->(s.side||'Types')) a(item);
 SELECT jsonb_agg(jsonb_build_object('side',r.side,'typeId',r.type_id,'includeDescendants',r.include_descendants) ORDER BY r.side,r.type_id) INTO actual
  FROM public.relation_type_endpoints r WHERE r.tenant_id=NEW.tenant_id AND r.relation_type_id=NEW.relation_type_id AND r.version=NEW.version;
 IF expected IS DISTINCT FROM actual THEN RAISE EXCEPTION 'Relation endpoint references must be complete' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.audit a JOIN public.outbox o ON o.tenant_id=a.tenant_id AND o.id=a.id
  WHERE a.tenant_id=NEW.tenant_id AND a.action=expected_action AND a.resource_id=logical_key AND a.actor_id=NEW.created_by::text
   AND a.changes->>'resourceVersion'=NEW.version::text AND a.envelope->>'version'=NEW.version::text
   AND o.event_type=a.action AND o.resource_id=a.resource_id AND o.resource_version=NEW.version) THEN
  RAISE EXCEPTION 'Relation publication requires paired audit and outbox records' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER relation_publication_complete AFTER INSERT ON public.relation_type_versions
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_relation_publication_complete();
CREATE TRIGGER relation_no_delete BEFORE DELETE ON public.relations FOR EACH ROW EXECUTE FUNCTION public.gc_immutable_audit();
CREATE TRIGGER relation_type_no_delete BEFORE DELETE ON public.relation_types FOR EACH ROW EXECUTE FUNCTION public.gc_immutable_audit();
