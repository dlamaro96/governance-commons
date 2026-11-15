-- SPDX-License-Identifier: Apache-2.0
-- Receipt identity/reference integrity only. Typed values, operation semantics,
-- canonical hashes and destructive-change acknowledgements remain domain-owned.
CREATE FUNCTION public.gc_model_migration_shape(
 p_plan jsonb, p_assets jsonb, p_model_id text, p_from integer, p_to integer, p_count integer
) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER
SET search_path = pg_catalog AS $$
DECLARE item jsonb; value jsonb; previous_version bigint := 0; numeric_version bigint;
 previous_asset uuid; asset_uuid uuid; actual_versions jsonb;
BEGIN
 IF jsonb_typeof(p_plan) IS DISTINCT FROM 'object'
    OR jsonb_typeof(p_assets) IS DISTINCT FROM 'array'
    OR p_from IS NULL OR p_to IS NULL OR p_from < 1
    OR p_to::bigint <> p_from::bigint + 1
    OR p_count IS NULL OR p_count < 0 OR p_count > 1000 THEN RETURN false; END IF;
 -- This database byte guard is intentionally broader than HTTP/domain budgets.
 IF octet_length(p_plan::text) > 8388608
    OR jsonb_array_length(p_assets) <> p_count
    OR NOT (p_plan ?& ARRAY['formatVersion','modelId','targetVersion','sourceVersions','acknowledgedChanges','operations'])
    OR p_plan - ARRAY['formatVersion','modelId','targetVersion','sourceVersions','acknowledgedChanges','operations'] <> '{}'::jsonb
    OR p_plan->'formatVersion' IS DISTINCT FROM '1'::jsonb
    OR jsonb_typeof(p_plan->'modelId') IS DISTINCT FROM 'string'
    OR p_plan->>'modelId' IS DISTINCT FROM p_model_id
    OR jsonb_typeof(p_plan->'targetVersion') IS DISTINCT FROM 'number'
    OR p_plan->>'targetVersion' IS DISTINCT FROM p_to::text
    OR jsonb_typeof(p_plan->'sourceVersions') IS DISTINCT FROM 'array'
    OR jsonb_typeof(p_plan->'acknowledgedChanges') IS DISTINCT FROM 'array'
    OR jsonb_typeof(p_plan->'operations') IS DISTINCT FROM 'array' THEN RETURN false; END IF;
 IF jsonb_array_length(p_plan->'sourceVersions') > 1000
    OR jsonb_array_length(p_plan->'acknowledgedChanges') > 2048
    OR jsonb_array_length(p_plan->'operations') > 64 THEN RETURN false; END IF;
 FOR value IN SELECT * FROM jsonb_array_elements(p_plan->'sourceVersions') LOOP
  IF jsonb_typeof(value) IS DISTINCT FROM 'number' OR value::text !~ '^[1-9][0-9]{0,9}$' THEN RETURN false; END IF;
  numeric_version := value::text::bigint;
  IF numeric_version <= previous_version OR numeric_version > p_from THEN RETURN false; END IF;
  previous_version := numeric_version;
 END LOOP;
 FOR item IN SELECT * FROM jsonb_array_elements(p_plan->'acknowledgedChanges') LOOP
  IF jsonb_typeof(item) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
  IF NOT (item ?& ARRAY['code','path']) OR item - ARRAY['code','path'] <> '{}'::jsonb
     OR jsonb_typeof(item->'code') IS DISTINCT FROM 'string'
     OR item->>'code' NOT IN ('attribute_removed','type_changed','constraints_changed')
     OR jsonb_typeof(item->'path') IS DISTINCT FROM 'string'
     OR char_length(item->>'path') NOT BETWEEN 1 AND 1024 THEN RETURN false; END IF;
 END LOOP;
 FOR item IN SELECT * FROM jsonb_array_elements(p_plan->'operations') LOOP
  IF jsonb_typeof(item) IS DISTINCT FROM 'object'
     OR jsonb_typeof(item->'op') IS DISTINCT FROM 'string'
     OR char_length(item->>'op') NOT BETWEEN 1 AND 32 THEN RETURN false; END IF;
 END LOOP;
 FOR item IN SELECT * FROM jsonb_array_elements(p_assets) LOOP
  IF jsonb_typeof(item) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
  IF NOT (item ?& ARRAY['assetId','fromAssetVersion','toAssetVersion','fromModelVersion','toModelVersion','beforeHash','afterHash'])
     OR item - ARRAY['assetId','fromAssetVersion','toAssetVersion','fromModelVersion','toModelVersion','beforeHash','afterHash'] <> '{}'::jsonb
     OR jsonb_typeof(item->'assetId') IS DISTINCT FROM 'string'
     OR item->>'assetId' !~* '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
     OR jsonb_typeof(item->'beforeHash') IS DISTINCT FROM 'string'
     OR item->>'beforeHash' !~ '^[a-f0-9]{64}$'
     OR jsonb_typeof(item->'afterHash') IS DISTINCT FROM 'string'
     OR item->>'afterHash' !~ '^[a-f0-9]{64}$' THEN RETURN false; END IF;
  FOR value IN SELECT item->key FROM unnest(ARRAY['fromAssetVersion','toAssetVersion','fromModelVersion','toModelVersion']) AS fields(key) LOOP
   IF jsonb_typeof(value) IS DISTINCT FROM 'number' OR value::text !~ '^[1-9][0-9]{0,9}$'
      THEN RETURN false; END IF;
   IF value::text::bigint > 2147483647 THEN RETURN false; END IF;
  END LOOP;
  asset_uuid := (item->>'assetId')::uuid;
  IF previous_asset IS NOT NULL AND asset_uuid <= previous_asset THEN RETURN false; END IF;
  previous_asset := asset_uuid;
  IF (item->>'toAssetVersion')::bigint <> (item->>'fromAssetVersion')::bigint + 1
     OR (item->>'fromModelVersion')::bigint > p_from
     OR (item->>'toModelVersion')::bigint <> p_to THEN RETURN false; END IF;
 END LOOP;
 SELECT coalesce(jsonb_agg(version ORDER BY version), '[]'::jsonb) INTO actual_versions
 FROM (SELECT DISTINCT (entry->>'fromModelVersion')::integer AS version FROM jsonb_array_elements(p_assets) AS entry) AS pins;
 RETURN actual_versions = p_plan->'sourceVersions';
END $$;

ALTER TABLE public.governance_model_migrations
 ADD CONSTRAINT model_migration_shape CHECK(public.gc_model_migration_shape(plan,assets,model_id,from_version,to_version,asset_count)),
 ADD CONSTRAINT model_migration_reference_identity UNIQUE(tenant_id,id,model_id,to_version);

CREATE TABLE public.governance_model_migration_assets (
 tenant_id uuid NOT NULL,
 migration_id uuid NOT NULL,
 asset_id uuid NOT NULL,
 model_id text NOT NULL,
 from_asset_version integer NOT NULL CHECK(from_asset_version > 0),
 to_asset_version integer NOT NULL CHECK(to_asset_version::bigint = from_asset_version::bigint + 1),
 from_model_version integer NOT NULL CHECK(from_model_version > 0),
 to_model_version integer NOT NULL CHECK(to_model_version > from_model_version),
 before_hash text NOT NULL CHECK(before_hash ~ '^[a-f0-9]{64}$'),
 after_hash text NOT NULL CHECK(after_hash ~ '^[a-f0-9]{64}$'),
 PRIMARY KEY(tenant_id,migration_id,asset_id),
 FOREIGN KEY(tenant_id,migration_id,model_id,to_model_version)
  REFERENCES public.governance_model_migrations(tenant_id,id,model_id,to_version),
 FOREIGN KEY(tenant_id,asset_id) REFERENCES public.assets(tenant_id,id),
 FOREIGN KEY(tenant_id,asset_id,from_asset_version) REFERENCES public.asset_revisions(tenant_id,asset_id,version),
 FOREIGN KEY(tenant_id,asset_id,to_asset_version) REFERENCES public.asset_revisions(tenant_id,asset_id,version),
 FOREIGN KEY(tenant_id,model_id,from_model_version) REFERENCES public.governance_model_versions(tenant_id,model_id,version),
 FOREIGN KEY(tenant_id,model_id,to_model_version) REFERENCES public.governance_model_versions(tenant_id,model_id,version)
);

-- Pre-005 development fixture receipts can lack a real initial revision. Preserve
-- that defect explicitly; never synthesize an old snapshot or exempt new writes.
CREATE TABLE public.governance_model_migration_integrity_exceptions (
 tenant_id uuid NOT NULL,
 migration_id uuid NOT NULL,
 reason text NOT NULL CHECK(reason = 'missing_pre_005_asset_revision'),
 missing_revisions jsonb NOT NULL CHECK(jsonb_typeof(missing_revisions) = 'array'
  AND jsonb_array_length(missing_revisions) BETWEEN 1 AND 2000),
 recorded_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(tenant_id,migration_id),
 FOREIGN KEY(tenant_id,migration_id) REFERENCES public.governance_model_migrations(tenant_id,id)
);

DO $$ DECLARE relation_name text; BEGIN
 FOREACH relation_name IN ARRAY ARRAY['governance_model_migration_assets','governance_model_migration_integrity_exceptions'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',relation_name);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',relation_name);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.gc_tenant()) WITH CHECK(tenant_id=public.gc_tenant())',relation_name);
 END LOOP;
END $$;

-- The migration owner also obeys forced RLS. Enumerate only the unscoped tenant
-- registry, then set an explicit local scope for each receipt/reference backfill.
DO $$ DECLARE organization record; receipt record; missing jsonb;
 previous_tenant text := current_setting('gc.tenant_id',true);
BEGIN
 FOR organization IN SELECT id FROM public.tenants ORDER BY id LOOP
  PERFORM set_config('gc.tenant_id',organization.id::text,true);
  FOR receipt IN SELECT * FROM public.governance_model_migrations WHERE tenant_id=organization.id ORDER BY id LOOP
   IF EXISTS (
    SELECT 1 FROM jsonb_array_elements(receipt.assets) AS entry
    WHERE NOT EXISTS (SELECT 1 FROM public.assets a WHERE a.tenant_id=receipt.tenant_id AND a.id=(entry->>'assetId')::uuid)
       OR NOT EXISTS (SELECT 1 FROM public.governance_model_versions v WHERE v.tenant_id=receipt.tenant_id
         AND v.model_id=receipt.model_id AND v.version=(entry->>'fromModelVersion')::integer)
   ) THEN
    RAISE EXCEPTION 'Historical model migration has an invalid tenant-scoped identity'
      USING ERRCODE='23514', DETAIL=format('tenant=%s receipt=%s',receipt.tenant_id,receipt.id);
   END IF;
   SELECT jsonb_agg(jsonb_build_object('assetId',asset_id,'side',side,'assetVersion',version) ORDER BY asset_id,side)
   INTO missing FROM (
    SELECT (entry->>'assetId')::uuid AS asset_id, side,
     (entry->>(CASE side WHEN 'from' THEN 'fromAssetVersion' ELSE 'toAssetVersion' END))::integer AS version
    FROM jsonb_array_elements(receipt.assets) AS entry CROSS JOIN unnest(ARRAY['from','to']) AS sides(side)
   ) AS expected
   WHERE NOT EXISTS (SELECT 1 FROM public.asset_revisions r
    WHERE r.tenant_id=receipt.tenant_id AND r.asset_id=expected.asset_id AND r.version=expected.version);
   IF missing IS NOT NULL THEN
    INSERT INTO public.governance_model_migration_integrity_exceptions(tenant_id,migration_id,reason,missing_revisions)
    VALUES(receipt.tenant_id,receipt.id,'missing_pre_005_asset_revision',missing);
   END IF;
   INSERT INTO public.governance_model_migration_assets
    (tenant_id,migration_id,asset_id,model_id,from_asset_version,to_asset_version,from_model_version,to_model_version,before_hash,after_hash)
   SELECT receipt.tenant_id,receipt.id,(entry->>'assetId')::uuid,receipt.model_id,
    (entry->>'fromAssetVersion')::integer,(entry->>'toAssetVersion')::integer,
    (entry->>'fromModelVersion')::integer,(entry->>'toModelVersion')::integer,entry->>'beforeHash',entry->>'afterHash'
   FROM jsonb_array_elements(receipt.assets) AS entry
   WHERE EXISTS (SELECT 1 FROM public.asset_revisions r WHERE r.tenant_id=receipt.tenant_id
     AND r.asset_id=(entry->>'assetId')::uuid AND r.version=(entry->>'fromAssetVersion')::integer)
    AND EXISTS (SELECT 1 FROM public.asset_revisions r WHERE r.tenant_id=receipt.tenant_id
     AND r.asset_id=(entry->>'assetId')::uuid AND r.version=(entry->>'toAssetVersion')::integer);
  END LOOP;
 END LOOP;
 PERFORM set_config('gc.tenant_id',coalesce(previous_tenant,''),true);
END $$;

CREATE FUNCTION public.gc_guard_model_migration_asset() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog AS $$
BEGIN
 -- Trigger depth alone is NOT authorization. Exact immutable parent membership,
 -- atomic complete normalization and the child PK leave no extra writable slot.
 IF pg_trigger_depth() <> 2 OR EXISTS (
  SELECT 1 FROM public.governance_model_migration_integrity_exceptions e
   WHERE e.tenant_id=NEW.tenant_id AND e.migration_id=NEW.migration_id
 ) OR NOT EXISTS (
  SELECT 1 FROM public.governance_model_migrations m CROSS JOIN LATERAL jsonb_array_elements(m.assets) AS entry
  WHERE m.tenant_id=NEW.tenant_id AND m.id=NEW.migration_id AND m.model_id=NEW.model_id
   AND m.to_version=NEW.to_model_version AND (entry->>'assetId')::uuid=NEW.asset_id
   AND (entry->>'fromAssetVersion')::integer=NEW.from_asset_version AND (entry->>'toAssetVersion')::integer=NEW.to_asset_version
   AND (entry->>'fromModelVersion')::integer=NEW.from_model_version AND (entry->>'toModelVersion')::integer=NEW.to_model_version
   AND entry->>'beforeHash'=NEW.before_hash AND entry->>'afterHash'=NEW.after_hash
 ) THEN
  RAISE EXCEPTION 'Model migration references must derive from their immutable parent receipt' USING ERRCODE='42501';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER model_migration_asset_insert_guard BEFORE INSERT ON public.governance_model_migration_assets
 FOR EACH ROW EXECUTE FUNCTION public.gc_guard_model_migration_asset();

CREATE FUNCTION public.gc_normalize_model_migration_assets() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog AS $$
BEGIN
 INSERT INTO public.governance_model_migration_assets
  (tenant_id,migration_id,asset_id,model_id,from_asset_version,to_asset_version,from_model_version,to_model_version,before_hash,after_hash)
 SELECT NEW.tenant_id,NEW.id,(entry->>'assetId')::uuid,NEW.model_id,
  (entry->>'fromAssetVersion')::integer,(entry->>'toAssetVersion')::integer,
  (entry->>'fromModelVersion')::integer,(entry->>'toModelVersion')::integer,entry->>'beforeHash',entry->>'afterHash'
 FROM jsonb_array_elements(NEW.assets) AS entry;
 RETURN NEW;
END $$;
CREATE TRIGGER model_migration_normalize AFTER INSERT ON public.governance_model_migrations
 FOR EACH ROW EXECUTE FUNCTION public.gc_normalize_model_migration_assets();
CREATE TRIGGER model_migration_assets_immutable BEFORE UPDATE OR DELETE ON public.governance_model_migration_assets
 FOR EACH ROW EXECUTE FUNCTION public.gc_immutable_audit();
CREATE TRIGGER model_migration_integrity_exceptions_immutable BEFORE UPDATE OR DELETE ON public.governance_model_migration_integrity_exceptions
 FOR EACH ROW EXECUTE FUNCTION public.gc_immutable_audit();

REVOKE ALL ON public.governance_model_migration_assets,public.governance_model_migration_integrity_exceptions FROM PUBLIC;
GRANT SELECT,INSERT ON public.governance_model_migration_assets TO gc_app;
REVOKE UPDATE,DELETE,TRUNCATE ON public.governance_model_migration_assets FROM gc_app;
GRANT SELECT ON public.governance_model_migration_integrity_exceptions TO gc_app;
REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON public.governance_model_migration_integrity_exceptions FROM gc_app;
REVOKE ALL ON FUNCTION public.gc_model_migration_shape(jsonb,jsonb,text,integer,integer,integer),
 public.gc_guard_model_migration_asset(),public.gc_normalize_model_migration_assets() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_model_migration_shape(jsonb,jsonb,text,integer,integer,integer),
 public.gc_guard_model_migration_asset(),public.gc_normalize_model_migration_assets() TO gc_app;
