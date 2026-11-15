-- SPDX-License-Identifier: Apache-2.0
-- Complete authored-type migrations augment, never reinterpret, SQL004/005 receipts.
-- The sole SECURITY DEFINER operation locks existing scoped principals. It grants
-- neither identity writes nor a tenant-selection or arbitrary-query capability.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
    OR pg_has_role('gc_app',current_user,'MEMBER') THEN
  RAISE EXCEPTION 'Type migration function requires an isolated non-bypass migration owner' USING ERRCODE='42501';
 END IF;
END $$;
CREATE FUNCTION public.gc_lock_type_migration_principals(requested uuid[]) RETURNS void
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE scoped_tenant uuid := public.gc_tenant(); scoped_actor uuid; selected uuid[]; item uuid;
BEGIN
 IF requested IS NULL OR coalesce(array_ndims(requested),1)<>1 OR cardinality(requested)>2001
    OR array_position(requested,NULL) IS NOT NULL THEN
  RAISE EXCEPTION 'Principal locks require a bounded one-dimensional non-null UUID array' USING ERRCODE='22023';
 END IF;
 BEGIN scoped_actor:=public.gc_actor()::uuid;
 EXCEPTION WHEN invalid_text_representation THEN
  RAISE EXCEPTION 'Principal locking requires an authenticated tenant context' USING ERRCODE='42501';
 END;
 IF scoped_tenant IS NULL OR scoped_actor IS NULL OR NOT EXISTS(
  SELECT 1 FROM public.memberships m WHERE m.tenant_id=scoped_tenant AND m.identity_id=scoped_actor
 ) THEN RAISE EXCEPTION 'Principal locking requires an authenticated tenant context' USING ERRCODE='42501'; END IF;
 SELECT array_agg(DISTINCT value ORDER BY value) INTO selected FROM unnest(array_append(requested,scoped_actor)) value;
 -- Separate phases make the ordering independent of the join planner. Explicit
 -- tenant predicates matter: actor-membership RLS also exposes other tenants.
 FOR item IN SELECT i.id FROM public.identities i WHERE i.id=ANY(selected)
  AND EXISTS(SELECT 1 FROM public.memberships m WHERE m.tenant_id=scoped_tenant AND m.identity_id=i.id)
  ORDER BY i.id FOR SHARE OF i LOOP NULL; END LOOP;
 FOR item IN SELECT m.identity_id FROM public.memberships m
  WHERE m.tenant_id=scoped_tenant AND m.identity_id=ANY(selected)
  ORDER BY m.identity_id FOR SHARE OF m LOOP NULL; END LOOP;
 -- Callers reread activity and authorization after this lock boundary. Inactive
 -- identities/memberships are intentionally locked to allow explicit owner repair.
END $$;
REVOKE ALL ON FUNCTION public.gc_lock_type_migration_principals(uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_lock_type_migration_principals(uuid[]) TO gc_app;

-- Canonical JSON for this bounded data contract. All object keys are safe ASCII;
-- strings preserve Unicode and JSON escaping. Numeric notation is normalized
-- exactly, without lossy SQL float casts, to JSON.stringify's fixed/exponent
-- thresholds. Valid domain numbers arrive as JSON.stringify binary64 decimals;
-- decimal attributes remain strings. This is not an arbitrary JSON/JCS API.
CREATE FUNCTION public.gc_type_migration_canonical(value jsonb,depth integer DEFAULT 0) RETURNS text
LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE kind text:=jsonb_typeof(value); nodes integer; result text; part record; raw text; negative text:='';
 digits text; exponent integer; decimal_position integer; whole text; fraction text;
BEGIN
 IF value IS NULL OR depth IS NULL OR depth<0 OR depth>32 OR octet_length(value::text)>8388608 THEN
  RAISE EXCEPTION 'Typed migration canonical JSON exceeds its bounds' USING ERRCODE='23514';
 END IF;
 IF depth=0 THEN
  WITH RECURSIVE walk(item,level) AS (
   SELECT value,0 UNION ALL
   SELECT child.item,parent.level+1 FROM walk parent CROSS JOIN LATERAL (
    SELECT v AS item FROM jsonb_each(CASE WHEN jsonb_typeof(parent.item)='object' THEN parent.item ELSE '{}'::jsonb END) AS obj(k,v)
    UNION ALL
    SELECT v AS item FROM jsonb_array_elements(CASE WHEN jsonb_typeof(parent.item)='array' THEN parent.item ELSE '[]'::jsonb END) AS arr(v)
   ) child WHERE parent.level<33
  ) SELECT count(*) INTO nodes FROM (SELECT 1 FROM walk LIMIT 100001) bounded;
  IF nodes>100000 THEN RAISE EXCEPTION 'Typed migration canonical JSON exceeds its node budget' USING ERRCODE='23514'; END IF;
 END IF;
 IF kind='object' THEN
  result:='';
  FOR part IN SELECT key,item FROM jsonb_each(value) AS fields(key,item) ORDER BY key COLLATE "C" LOOP
   IF part.key !~ '^[A-Za-z_][A-Za-z0-9_.-]{0,63}$' OR part.key=ANY(ARRAY['__proto__','prototype','constructor']) THEN
    RAISE EXCEPTION 'Typed migration canonical JSON requires safe object keys' USING ERRCODE='23514';
   END IF;
   result:=result||CASE WHEN result='' THEN '' ELSE ',' END||to_jsonb(part.key)::text||':'||public.gc_type_migration_canonical(part.item,depth+1);
  END LOOP;
  RETURN '{'||result||'}';
 ELSIF kind='array' THEN
  SELECT string_agg(public.gc_type_migration_canonical(item,depth+1),',' ORDER BY ordinal) INTO result
   FROM jsonb_array_elements(value) WITH ORDINALITY AS values_(item,ordinal);
  RETURN '['||coalesce(result,'')||']';
 ELSIF kind='number' THEN
  raw:=value::text;
  IF raw::numeric=0 THEN RETURN '0'; END IF;
  IF left(raw,1)='-' THEN negative:='-'; raw:=substr(raw,2); END IF;
  whole:=split_part(raw,'.',1); fraction:=CASE WHEN position('.' IN raw)>0 THEN split_part(raw,'.',2) ELSE '' END;
  digits:=ltrim(whole||fraction,'0'); decimal_position:=length(whole)- (length(whole||fraction)-length(digits));
  digits:=rtrim(digits,'0'); exponent:=decimal_position-1;
  IF exponent>=-6 AND exponent<21 THEN
   IF decimal_position<=0 THEN result:='0.'||repeat('0',-decimal_position)||digits;
   ELSIF decimal_position>=length(digits) THEN result:=digits||repeat('0',decimal_position-length(digits));
   ELSE result:=substr(digits,1,decimal_position)||'.'||substr(digits,decimal_position+1); END IF;
  ELSE
   result:=left(digits,1)||CASE WHEN length(digits)>1 THEN '.'||substr(digits,2) ELSE '' END
    ||'e'||CASE WHEN exponent>=0 THEN '+' ELSE '' END||exponent::text;
  END IF;
  RETURN negative||result;
 ELSE RETURN value::text;
 END IF;
END $$;
CREATE FUNCTION public.gc_type_migration_hash(value jsonb) RETURNS text
LANGUAGE sql IMMUTABLE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT encode(sha256(convert_to(public.gc_type_migration_canonical(value),'UTF8')),'hex')
$$;

-- A real composite identity reference supplements the immutable type UUID guard.
ALTER TABLE public.governance_models ADD CONSTRAINT governance_model_typed_identity UNIQUE(tenant_id,id,type_id);
CREATE TABLE public.asset_type_migrations (
 tenant_id uuid NOT NULL,
 id uuid NOT NULL,
 model_id text NOT NULL,
 type_id uuid NOT NULL,
 from_version integer NOT NULL CHECK(from_version>0),
 to_version integer NOT NULL CHECK(to_version::bigint=from_version::bigint+1),
 plan jsonb NOT NULL CHECK(jsonb_typeof(plan)='object' AND octet_length(plan::text)<=8388608),
 plan_hash text NOT NULL CHECK(plan_hash ~ '^[a-f0-9]{64}$'),
 preview_digest text NOT NULL CHECK(preview_digest ~ '^[a-f0-9]{64}$'),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[a-f0-9]{64}$'),
 resolution_hash text NOT NULL CHECK(resolution_hash ~ '^[a-f0-9]{64}$'),
 source_resolutions jsonb NOT NULL CHECK(jsonb_typeof(source_resolutions)='array' AND jsonb_array_length(source_resolutions)<=1001),
 asset_count integer NOT NULL CHECK(asset_count BETWEEN 0 AND 1000),
 assets jsonb NOT NULL CHECK(jsonb_typeof(assets)='array' AND jsonb_array_length(assets)=asset_count AND octet_length(assets::text)<=8388608),
 executed_by uuid NOT NULL,
 executed_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,id),
 UNIQUE(tenant_id,id,model_id,type_id,to_version),
 FOREIGN KEY(tenant_id,id,model_id,to_version) REFERENCES public.governance_model_migrations(tenant_id,id,model_id,to_version),
 FOREIGN KEY(tenant_id,model_id,type_id) REFERENCES public.governance_models(tenant_id,id,type_id),
 FOREIGN KEY(tenant_id,model_id,from_version) REFERENCES public.asset_type_versions(tenant_id,model_id,version),
 FOREIGN KEY(tenant_id,model_id,to_version) REFERENCES public.asset_type_versions(tenant_id,model_id,version),
 FOREIGN KEY(tenant_id,executed_by) REFERENCES public.memberships(tenant_id,identity_id)
);
CREATE TABLE public.asset_type_migration_assets (
 tenant_id uuid NOT NULL, migration_id uuid NOT NULL, asset_id uuid NOT NULL,
 model_id text NOT NULL, type_id uuid NOT NULL,
 from_asset_version integer NOT NULL, to_asset_version integer NOT NULL,
 from_model_version integer NOT NULL, to_model_version integer NOT NULL,
 before_hash text NOT NULL, after_hash text NOT NULL,
 before_tuple jsonb NOT NULL, after_tuple jsonb NOT NULL,
 before_tuple_hash text NOT NULL CHECK(before_tuple_hash ~ '^[a-f0-9]{64}$'),
 after_tuple_hash text NOT NULL CHECK(after_tuple_hash ~ '^[a-f0-9]{64}$'),
 PRIMARY KEY(tenant_id,migration_id,asset_id),
 FOREIGN KEY(tenant_id,migration_id,model_id,type_id,to_model_version) REFERENCES public.asset_type_migrations(tenant_id,id,model_id,type_id,to_version),
 FOREIGN KEY(tenant_id,migration_id,asset_id) REFERENCES public.governance_model_migration_assets(tenant_id,migration_id,asset_id),
 FOREIGN KEY(tenant_id,asset_id,from_asset_version) REFERENCES public.asset_revisions(tenant_id,asset_id,version),
 FOREIGN KEY(tenant_id,asset_id,to_asset_version) REFERENCES public.asset_revisions(tenant_id,asset_id,version),
 FOREIGN KEY(tenant_id,model_id,from_model_version) REFERENCES public.asset_type_versions(tenant_id,model_id,version),
 FOREIGN KEY(tenant_id,model_id,to_model_version) REFERENCES public.asset_type_versions(tenant_id,model_id,version)
);
DO $$ DECLARE name text; BEGIN
 FOREACH name IN ARRAY ARRAY['asset_type_migrations','asset_type_migration_assets'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.gc_tenant()) WITH CHECK(tenant_id=public.gc_tenant())',name);
  EXECUTE format('CREATE TRIGGER immutable_type_migration BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.gc_immutable_audit()',name);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC',name);
  EXECUTE format('GRANT SELECT,INSERT ON public.%I TO gc_app',name);
  EXECUTE format('REVOKE UPDATE,DELETE,TRUNCATE ON public.%I FROM gc_app',name);
 END LOOP;
END $$;

CREATE FUNCTION public.gc_type_migration_consistent() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE base public.governance_model_migrations%ROWTYPE; entry jsonb; reference jsonb; pin jsonb; actual jsonb;
 previous_asset uuid; previous_version integer:=0; version_number integer; tuple jsonb; snapshot jsonb; side text;
 previous_override uuid; previous_mapping_version integer:=0; previous_mapping_state text; previous_change text;
 base_entry jsonb; fields text[]:=ARRAY['assetId','fromAssetVersion','toAssetVersion','fromModelVersion','toModelVersion','beforeHash','afterHash'];
BEGIN
 SELECT * INTO base FROM public.governance_model_migrations WHERE tenant_id=NEW.tenant_id AND id=NEW.id;
 IF NOT FOUND OR base.model_id IS DISTINCT FROM NEW.model_id OR base.from_version IS DISTINCT FROM NEW.from_version
  OR base.to_version IS DISTINCT FROM NEW.to_version OR base.preview_digest IS DISTINCT FROM NEW.preview_digest
  OR base.asset_count IS DISTINCT FROM NEW.asset_count OR base.executed_by IS DISTINCT FROM NEW.executed_by
  OR base.executed_at IS DISTINCT FROM NEW.executed_at THEN
  RAISE EXCEPTION 'Typed receipt must exactly augment its base receipt' USING ERRCODE='23514';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM public.governance_models m WHERE m.tenant_id=NEW.tenant_id AND m.id=NEW.model_id AND m.type_id=NEW.type_id)
  OR NOT EXISTS(SELECT 1 FROM public.asset_type_versions v WHERE v.tenant_id=NEW.tenant_id AND v.model_id=NEW.model_id AND v.version=NEW.to_version
   AND v.definition_hash=NEW.definition_hash AND v.resolution_hash=NEW.resolution_hash) THEN
  RAISE EXCEPTION 'Typed receipt must bind the exact immutable target type identity and hashes' USING ERRCODE='23514';
 END IF;
 IF jsonb_typeof(NEW.plan) IS DISTINCT FROM 'object'
  OR NOT NEW.plan ?& ARRAY['formatVersion','typeId','attributes','owner','lifecycle','acknowledgedPolicyChanges']
  OR NEW.plan-ARRAY['formatVersion','typeId','attributes','owner','lifecycle','acknowledgedPolicyChanges']<>'{}'::jsonb
  OR NEW.plan->'formatVersion' IS DISTINCT FROM '1'::jsonb OR NEW.plan->'typeId' IS DISTINCT FROM to_jsonb(NEW.type_id::text)
  OR NEW.plan->'attributes' IS DISTINCT FROM base.plan OR NEW.plan_hash IS DISTINCT FROM public.gc_type_migration_hash(NEW.plan)
  OR base.plan_hash IS DISTINCT FROM public.gc_type_migration_hash(base.plan)
  OR jsonb_typeof(NEW.plan->'owner') IS DISTINCT FROM 'object'
  OR (NEW.plan->'owner')-ARRAY['default','overrides']<>'{}'::jsonb
  OR NEW.plan->'owner'->'default' IS DISTINCT FROM '"preserve"'::jsonb
  OR jsonb_typeof(NEW.plan->'owner'->'overrides') IS DISTINCT FROM 'array'
  OR jsonb_typeof(NEW.plan->'lifecycle') IS DISTINCT FROM 'object'
  OR (NEW.plan->'lifecycle')-ARRAY['onUnmapped','mappings']<>'{}'::jsonb
  OR NEW.plan->'lifecycle'->>'onUnmapped' NOT IN ('preserve','error')
  OR jsonb_typeof(NEW.plan->'lifecycle'->'onUnmapped') IS DISTINCT FROM 'string'
  OR jsonb_typeof(NEW.plan->'lifecycle'->'mappings') IS DISTINCT FROM 'array'
  OR jsonb_typeof(NEW.plan->'acknowledgedPolicyChanges') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'Typed receipt plan identity, shape and canonical hashes must agree' USING ERRCODE='23514';
 END IF;
 IF jsonb_array_length(NEW.plan->'owner'->'overrides')>1000 OR jsonb_array_length(NEW.plan->'lifecycle'->'mappings')>1000
  OR jsonb_array_length(NEW.plan->'acknowledgedPolicyChanges')>3 THEN
  RAISE EXCEPTION 'Typed receipt plan exceeds its bounded policy arrays' USING ERRCODE='23514';
 END IF;
 -- Canonical nested policy fields are bounded, typed, unique and ordered. Their
 -- transformation semantics remain shared domain code; storage binds the actual
 -- resulting tuple to the immutable revision, independently of those semantics.
 FOR entry IN SELECT value FROM jsonb_array_elements(NEW.plan->'owner'->'overrides') LOOP
  IF jsonb_typeof(entry) IS DISTINCT FROM 'object' OR NOT entry ?& ARRAY['assetId','ownerId']
   OR entry-ARRAY['assetId','ownerId']<>'{}'::jsonb OR jsonb_typeof(entry->'assetId') IS DISTINCT FROM 'string'
   OR entry->>'assetId' !~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
   OR jsonb_typeof(entry->'ownerId') NOT IN ('string','null') THEN
   RAISE EXCEPTION 'Typed receipt owner overrides require exact nullable UUID fields' USING ERRCODE='23514';
  END IF;
  IF entry->'ownerId'<>'null'::jsonb AND entry->>'ownerId' !~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$' THEN
   RAISE EXCEPTION 'Typed receipt owner overrides require canonical lowercase UUIDs' USING ERRCODE='23514';
  END IF;
  IF (previous_override IS NOT NULL AND (entry->>'assetId')::uuid<=previous_override)
   OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(base.assets) AS cohort(item) WHERE cohort.item->'assetId'=entry->'assetId') THEN
   RAISE EXCEPTION 'Typed receipt owner overrides must be sorted unique members of the exact cohort' USING ERRCODE='23514';
  END IF;
  previous_override:=(entry->>'assetId')::uuid;
 END LOOP;
 FOR entry IN SELECT value FROM jsonb_array_elements(NEW.plan->'lifecycle'->'mappings') LOOP
  IF jsonb_typeof(entry) IS DISTINCT FROM 'object' OR NOT entry ?& ARRAY['sourceVersion','from','to']
   OR entry-ARRAY['sourceVersion','from','to']<>'{}'::jsonb OR jsonb_typeof(entry->'sourceVersion') IS DISTINCT FROM 'number'
   OR entry->>'sourceVersion' !~ '^[1-9][0-9]{0,9}$' OR (entry->>'sourceVersion')::numeric>2147483647
   OR jsonb_typeof(entry->'from') IS DISTINCT FROM 'string' OR jsonb_typeof(entry->'to') IS DISTINCT FROM 'string'
   OR entry->>'from' !~ '^[A-Za-z_][A-Za-z0-9_.-]{0,63}$' OR entry->>'to' !~ '^[A-Za-z_][A-Za-z0-9_.-]{0,63}$'
   OR entry->>'from'=ANY(ARRAY['__proto__','constructor','prototype']) OR entry->>'to'=ANY(ARRAY['__proto__','constructor','prototype']) THEN
   RAISE EXCEPTION 'Typed receipt lifecycle mappings require exact version and safe state fields' USING ERRCODE='23514';
  END IF;
  version_number:=(entry->>'sourceVersion')::integer;
  IF version_number<previous_mapping_version
   OR (version_number=previous_mapping_version AND (entry->>'from') COLLATE "C"<=previous_mapping_state COLLATE "C")
   OR NOT (base.plan->'sourceVersions') @> (entry->'sourceVersion') THEN
   RAISE EXCEPTION 'Typed receipt lifecycle mappings must be sorted unique source-version state pairs' USING ERRCODE='23514';
  END IF;
  previous_mapping_version:=version_number; previous_mapping_state:=entry->>'from';
 END LOOP;
 FOR entry IN SELECT value FROM jsonb_array_elements(NEW.plan->'acknowledgedPolicyChanges') LOOP
  IF jsonb_typeof(entry) IS DISTINCT FROM 'string' OR entry#>>'{}' NOT IN ('parents_changed','required_owner_changed','lifecycle_changed')
   OR (previous_change IS NOT NULL AND (entry#>>'{}') COLLATE "C"<=previous_change COLLATE "C") THEN
   RAISE EXCEPTION 'Typed receipt policy acknowledgements must be exact sorted unique change codes' USING ERRCODE='23514';
  END IF;
  previous_change:=entry#>>'{}';
 END LOOP;
 IF jsonb_typeof(NEW.source_resolutions) IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.source_resolutions)>1001 THEN
  RAISE EXCEPTION 'Typed receipt requires bounded exact source resolutions' USING ERRCODE='23514';
 END IF;
 FOR pin IN SELECT value FROM jsonb_array_elements(NEW.source_resolutions) LOOP
  IF jsonb_typeof(pin) IS DISTINCT FROM 'object' OR NOT pin ?& ARRAY['version','resolutionHash']
   OR pin-ARRAY['version','resolutionHash']<>'{}'::jsonb OR jsonb_typeof(pin->'version') IS DISTINCT FROM 'number'
   OR pin->>'version' !~ '^[1-9][0-9]{0,9}$' OR (pin->>'version')::numeric>2147483647
   OR jsonb_typeof(pin->'resolutionHash') IS DISTINCT FROM 'string' OR pin->>'resolutionHash' !~ '^[a-f0-9]{64}$' THEN
   RAISE EXCEPTION 'Typed receipt contains an invalid source resolution' USING ERRCODE='23514';
  END IF;
  version_number:=(pin->>'version')::integer;
  IF version_number<=previous_version OR NOT EXISTS(SELECT 1 FROM public.asset_type_versions v
   WHERE v.tenant_id=NEW.tenant_id AND v.model_id=NEW.model_id AND v.version=version_number AND v.resolution_hash=pin->>'resolutionHash') THEN
   RAISE EXCEPTION 'Typed receipt source resolutions must be exact unique immutable pins' USING ERRCODE='23514';
  END IF;
  previous_version:=version_number;
 END LOOP;
 SELECT coalesce(jsonb_agg(source_pins.item->'version' ORDER BY (source_pins.item->>'version')::integer),'[]'::jsonb) INTO actual
  FROM jsonb_array_elements(NEW.source_resolutions) AS source_pins(item);
 IF actual IS DISTINCT FROM (SELECT jsonb_agg(v ORDER BY v) FROM (
  SELECT (value::text)::integer AS v FROM jsonb_array_elements(base.plan->'sourceVersions')
  UNION SELECT base.from_version) versions) THEN
  RAISE EXCEPTION 'Typed receipt source resolutions must cover the exact head and base cohort' USING ERRCODE='23514';
 END IF;
 IF jsonb_typeof(NEW.assets) IS DISTINCT FROM 'array' OR jsonb_array_length(NEW.assets)<>NEW.asset_count THEN
  RAISE EXCEPTION 'Typed receipt assets must cover the exact base cohort' USING ERRCODE='23514';
 END IF;
 FOR entry IN SELECT value FROM jsonb_array_elements(NEW.assets) LOOP
  IF jsonb_typeof(entry) IS DISTINCT FROM 'object' OR NOT entry ?& (fields||ARRAY['before','after','beforeTupleHash','afterTupleHash'])
   OR entry-(fields||ARRAY['before','after','beforeTupleHash','afterTupleHash'])<>'{}'::jsonb THEN
   RAISE EXCEPTION 'Typed asset receipt has an invalid exact shape' USING ERRCODE='23514';
  END IF;
  base_entry:=entry-ARRAY['before','after','beforeTupleHash','afterTupleHash'];
  SELECT value INTO reference FROM jsonb_array_elements(base.assets) WHERE value=base_entry;
  IF reference IS NULL OR (previous_asset IS NOT NULL AND (entry->>'assetId')::uuid<=previous_asset) THEN
   RAISE EXCEPTION 'Typed asset receipt must match its exact sorted base cohort' USING ERRCODE='23514';
  END IF;
  previous_asset:=(entry->>'assetId')::uuid;
  FOREACH side IN ARRAY ARRAY['before','after'] LOOP
   tuple:=entry->side;
   IF jsonb_typeof(tuple) IS DISTINCT FROM 'object' OR NOT tuple ?& ARRAY['modelId','modelVersion','attributes','ownerId','state']
    OR tuple-ARRAY['modelId','modelVersion','attributes','ownerId','state']<>'{}'::jsonb
    OR jsonb_typeof(tuple->'attributes') IS DISTINCT FROM 'object'
    OR jsonb_typeof(tuple->'state') IS DISTINCT FROM 'string'
    OR jsonb_typeof(tuple->'ownerId') NOT IN ('string','null')
    OR tuple->'modelId' IS DISTINCT FROM to_jsonb(NEW.model_id)
    OR tuple->'modelVersion' IS DISTINCT FROM entry->(CASE side WHEN 'before' THEN 'fromModelVersion' ELSE 'toModelVersion' END)
    OR entry->>(side||'TupleHash') IS DISTINCT FROM public.gc_type_migration_hash(tuple)
    OR entry->>(side||'Hash') IS DISTINCT FROM public.gc_type_migration_hash(tuple->'attributes') THEN
    RAISE EXCEPTION 'Typed asset receipt tuple identity and canonical hashes must agree' USING ERRCODE='23514';
   END IF;
   SELECT r.snapshot INTO snapshot FROM public.asset_revisions r WHERE r.tenant_id=NEW.tenant_id AND r.asset_id=previous_asset
    AND r.version=(entry->>(CASE side WHEN 'before' THEN 'fromAssetVersion' ELSE 'toAssetVersion' END))::integer;
   IF snapshot IS NULL OR NOT snapshot ?& ARRAY['modelId','modelVersion','attributes','ownerId','typeState']
    OR tuple IS DISTINCT FROM jsonb_build_object('modelId',snapshot->'modelId','modelVersion',snapshot->'modelVersion',
      'attributes',snapshot->'attributes','ownerId',snapshot->'ownerId','state',snapshot->'typeState') THEN
    RAISE EXCEPTION 'Typed asset receipt tuples must equal actual immutable revision snapshots' USING ERRCODE='23514';
   END IF;
  END LOOP;
 END LOOP;
 RETURN NEW;
END $$;
CREATE TRIGGER type_migration_consistent BEFORE INSERT ON public.asset_type_migrations
 FOR EACH ROW EXECUTE FUNCTION public.gc_type_migration_consistent();

CREATE FUNCTION public.gc_guard_type_migration_asset() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF pg_trigger_depth()<>2 OR NOT EXISTS(
  SELECT 1 FROM public.asset_type_migrations m CROSS JOIN LATERAL jsonb_array_elements(m.assets) entry
  JOIN public.governance_model_migration_assets b ON b.tenant_id=m.tenant_id AND b.migration_id=m.id AND b.asset_id=(entry->>'assetId')::uuid
  WHERE m.tenant_id=NEW.tenant_id AND m.id=NEW.migration_id AND m.model_id=NEW.model_id AND m.type_id=NEW.type_id
   AND b.asset_id=NEW.asset_id AND b.model_id=NEW.model_id AND b.from_asset_version=NEW.from_asset_version AND b.to_asset_version=NEW.to_asset_version
   AND b.from_model_version=NEW.from_model_version AND b.to_model_version=NEW.to_model_version AND b.before_hash=NEW.before_hash AND b.after_hash=NEW.after_hash
   AND entry->'before'=NEW.before_tuple AND entry->'after'=NEW.after_tuple
   AND entry->>'beforeTupleHash'=NEW.before_tuple_hash AND entry->>'afterTupleHash'=NEW.after_tuple_hash
 ) THEN RAISE EXCEPTION 'Typed migration references must derive exactly from their immutable parent receipt' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER type_migration_asset_insert_guard BEFORE INSERT ON public.asset_type_migration_assets
 FOR EACH ROW EXECUTE FUNCTION public.gc_guard_type_migration_asset();
CREATE FUNCTION public.gc_normalize_type_migration_assets() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 INSERT INTO public.asset_type_migration_assets(tenant_id,migration_id,asset_id,model_id,type_id,from_asset_version,to_asset_version,
  from_model_version,to_model_version,before_hash,after_hash,before_tuple,after_tuple,before_tuple_hash,after_tuple_hash)
 SELECT NEW.tenant_id,NEW.id,(entry->>'assetId')::uuid,NEW.model_id,NEW.type_id,(entry->>'fromAssetVersion')::integer,
  (entry->>'toAssetVersion')::integer,(entry->>'fromModelVersion')::integer,(entry->>'toModelVersion')::integer,
  entry->>'beforeHash',entry->>'afterHash',entry->'before',entry->'after',entry->>'beforeTupleHash',entry->>'afterTupleHash'
 FROM jsonb_array_elements(NEW.assets) entry;
 RETURN NEW;
END $$;
CREATE TRIGGER type_migration_normalize AFTER INSERT ON public.asset_type_migrations
 FOR EACH ROW EXECUTE FUNCTION public.gc_normalize_type_migration_assets();
CREATE FUNCTION public.gc_type_migration_complete() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM public.governance_models m WHERE m.tenant_id=NEW.tenant_id AND m.id=NEW.model_id AND m.type_id IS NOT NULL)
  AND NOT EXISTS(SELECT 1 FROM public.asset_type_migrations m WHERE m.tenant_id=NEW.tenant_id AND m.id=NEW.id
   AND m.asset_count=(SELECT count(*) FROM public.asset_type_migration_assets a WHERE a.tenant_id=m.tenant_id AND a.migration_id=m.id)) THEN
  RAISE EXCEPTION 'Authored-type migrations require a complete immutable typed receipt' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER typed_migration_complete AFTER INSERT ON public.governance_model_migrations
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_type_migration_complete();
REVOKE ALL ON FUNCTION public.gc_type_migration_canonical(jsonb,integer),public.gc_type_migration_hash(jsonb),
 public.gc_type_migration_consistent(),public.gc_guard_type_migration_asset(),public.gc_normalize_type_migration_assets(),public.gc_type_migration_complete() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_type_migration_canonical(jsonb,integer),public.gc_type_migration_hash(jsonb),
 public.gc_type_migration_consistent(),public.gc_guard_type_migration_asset(),public.gc_normalize_type_migration_assets(),public.gc_type_migration_complete() TO gc_app;
