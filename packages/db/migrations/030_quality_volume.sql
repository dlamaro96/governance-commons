-- SPDX-License-Identifier: Apache-2.0
-- Exact table volume. Existing column rows/hashes are not rewritten.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls)) OR pg_has_role('gc_app',current_user,'MEMBER') THEN
  RAISE EXCEPTION 'QUALITY_STORAGE_INVALID' USING ERRCODE='42501';END IF;
END $$;
ALTER TABLE public.quality_rules ALTER COLUMN column_asset_id DROP NOT NULL;
ALTER TABLE public.quality_rules ADD COLUMN table_asset_id uuid;
ALTER TABLE public.quality_rules ADD CONSTRAINT quality_rule_table_fk FOREIGN KEY(tenant_id,table_asset_id) REFERENCES public.assets(tenant_id,id);
ALTER TABLE public.quality_rules ADD CONSTRAINT quality_rule_target_xor CHECK((column_asset_id IS NULL)<>(table_asset_id IS NULL));
CREATE INDEX quality_rules_table ON public.quality_rules(tenant_id,table_asset_id,id) WHERE table_asset_id IS NOT NULL;
ALTER TABLE public.quality_runs ALTER COLUMN column_asset_id DROP NOT NULL;
ALTER TABLE public.quality_runs ADD CONSTRAINT quality_run_target_kind CHECK((column_asset_id IS NULL)=(inputs#>>'{execution,kind}'='volume') AND inputs#>>'{execution,kind}' IS NOT NULL);
ALTER TABLE public.quality_monitor_incidents ALTER COLUMN column_asset_id DROP NOT NULL;

CREATE FUNCTION public.gc_quality_volume_settings_valid(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ BEGIN
 RETURN coalesce(public.gc_quality_monitor_integer(value->'minimumRows',0,100000) AND public.gc_quality_monitor_integer(value->'maximumRows',0,100000)
 AND (value->>'minimumRows')::integer<=(value->>'maximumRows')::integer
 AND value->'comparison'='"row-count-inclusive"'::jsonb AND value->'scope'='"entire-table"'::jsonb,false);
 EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END $$;
CREATE FUNCTION public.gc_quality_volume_definition_valid(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ BEGIN
 IF public.gc_relation_keys(value,ARRAY['formatVersion','kind','target','name','purpose','ownerId','severity','minimumRows','maximumRows','comparison','scope']) IS NOT TRUE
 OR value->'formatVersion' IS DISTINCT FROM '1'::jsonb OR value->'kind' IS DISTINCT FROM '"volume"'::jsonb
 OR public.gc_relation_keys(value->'target',ARRAY['kind','tableAssetId']) IS NOT TRUE OR value#>'{target,kind}' IS DISTINCT FROM '"table"'::jsonb
 OR jsonb_typeof(value#>'{target,tableAssetId}') IS DISTINCT FROM 'string' OR NOT public.gc_approval_uuid(value#>>'{target,tableAssetId}')
 OR jsonb_typeof(value->'ownerId') IS DISTINCT FROM 'string' OR NOT public.gc_approval_uuid(value->>'ownerId')
 OR jsonb_typeof(value->'name') IS DISTINCT FROM 'string' OR public.gc_approval_text(value->>'name',240,false) IS NULL OR value->>'name' IS DISTINCT FROM public.gc_approval_text(value->>'name',240,false)
 OR jsonb_typeof(value->'purpose') IS DISTINCT FROM 'string' OR public.gc_approval_text(value->>'purpose',4096,true) IS NULL OR value->>'purpose' IS DISTINCT FROM public.gc_approval_text(value->>'purpose',4096,true)
 OR jsonb_typeof(value->'severity') IS DISTINCT FROM 'string' OR value->>'severity' NOT IN ('info','warning','critical')
 THEN RETURN false;END IF;
 RETURN public.gc_quality_volume_settings_valid(value) AND octet_length(value::text)<=16384;
END $$;
CREATE FUNCTION public.gc_quality_volume_binding(definition jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ DECLARE settings jsonb;BEGIN
 IF public.gc_quality_volume_definition_valid(definition) IS NOT TRUE THEN RETURN NULL;END IF;
 settings:=jsonb_build_object('minimumRows',definition->'minimumRows','maximumRows',definition->'maximumRows','comparison','row-count-inclusive','scope','entire-table');
 RETURN settings||jsonb_build_object('volumeHash',public.gc_type_migration_hash(settings||'{"formatVersion":1,"kind":"volume"}'::jsonb));
END $$;
CREATE FUNCTION public.gc_quality_volume_measurement_valid(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ DECLARE compatible jsonb;BEGIN
 IF public.gc_relation_keys(value,ARRAY['formatVersion','kind','strategy','rowCount','volumeHash','observedStartedAt','observedFinishedAt','elapsedMs','sourceVersion','adapterVersion','queryTemplate','estimatedCost','estimatedBytes']) IS NOT TRUE
 OR value->'kind' IS DISTINCT FROM '"volume"'::jsonb OR value->'queryTemplate' IS DISTINCT FROM '"postgresql-volume-v1"'::jsonb
 OR jsonb_typeof(value->'volumeHash') IS DISTINCT FROM 'string' OR value->>'volumeHash' !~ '^[a-f0-9]{64}$' THEN RETURN false;END IF;
 -- Reuse only the unchanged count/timing/budget grammar; zero nullCount is not
 -- volume evidence and is never persisted or returned in a volume representation.
 compatible:=(value-'volumeHash')||'{"kind":"completeness","queryTemplate":"postgresql-completeness-v1","nullCount":0}'::jsonb;
 RETURN public.gc_quality_completeness_measurement_valid(compatible);
END $$;
CREATE FUNCTION public.gc_quality_volume_verdict(measured jsonb,binding jsonb) RETURNS text
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ BEGIN
 IF public.gc_quality_volume_measurement_valid(measured) IS NOT TRUE OR public.gc_relation_keys(binding,ARRAY['minimumRows','maximumRows','comparison','scope','volumeHash']) IS NOT TRUE
 OR public.gc_quality_volume_settings_valid(binding) IS NOT TRUE OR jsonb_typeof(binding->'volumeHash') IS DISTINCT FROM 'string'
 OR binding->>'volumeHash' IS DISTINCT FROM public.gc_type_migration_hash((binding-'volumeHash')||'{"formatVersion":1,"kind":"volume"}'::jsonb)
 OR measured->>'volumeHash' IS DISTINCT FROM binding->>'volumeHash' THEN RETURN NULL;END IF;
 RETURN CASE WHEN (measured->>'rowCount')::integer BETWEEN (binding->>'minimumRows')::integer AND (binding->>'maximumRows')::integer THEN 'PASS' ELSE 'FAIL' END;
END $$;
CREATE FUNCTION public.gc_quality_table_visible(table_identity uuid,actor_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM public.assets t JOIN public.assets s ON s.tenant_id=t.tenant_id AND s.source_id=t.source_id AND s.external_id=t.parent_external_id
 JOIN public.sources src ON src.tenant_id=t.tenant_id AND src.id=t.source_id
 JOIN public.memberships m ON m.tenant_id=t.tenant_id AND m.identity_id=actor_identity JOIN public.identities i ON i.id=m.identity_id
 WHERE t.tenant_id=public.gc_tenant() AND t.id=table_identity AND t.type='table' AND s.type='schema'
 AND m.active AND i.active AND m.permissions @> '["catalog:read","quality:read"]'::jsonb
 AND (t.visibility='tenant' OR t.allowed_identities @> to_jsonb(ARRAY[actor_identity::text]))
 AND (s.visibility='tenant' OR s.allowed_identities @> to_jsonb(ARRAY[actor_identity::text])))
$$;
CREATE FUNCTION public.gc_quality_table_inputs(table_identity uuid,actor_identity uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE t public.assets;s public.assets;src public.sources;parts text[];schema_parts text[];connection jsonb;target jsonb;BEGIN
 IF NOT public.gc_quality_table_visible(table_identity,actor_identity) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
 SELECT * INTO t FROM public.assets WHERE tenant_id=public.gc_tenant() AND id=table_identity;
 SELECT * INTO s FROM public.assets WHERE tenant_id=t.tenant_id AND source_id=t.source_id AND external_id=t.parent_external_id;
 SELECT * INTO src FROM public.sources WHERE tenant_id=t.tenant_id AND id=t.source_id;
 IF src.connector_id IS DISTINCT FROM 'postgresql' OR t.status IS DISTINCT FROM 'active' OR s.status IS DISTINCT FROM 'active' OR t.metadata->>'relationKind' IS DISTINCT FROM 'r' THEN
  RAISE EXCEPTION 'QUALITY_TARGET_UNSUPPORTED' USING ERRCODE='0A000';END IF;
 parts:=regexp_match(t.external_id,'^pg:([1-9][0-9]{0,9}):relation:([1-9][0-9]{0,9})$');
 schema_parts:=regexp_match(s.external_id,'^pg:([1-9][0-9]{0,9}):schema:([1-9][0-9]{0,9})$');
 IF parts IS NULL OR schema_parts IS NULL OR parts[1]<>schema_parts[1] OR parts[1]::bigint>4294967295 OR parts[2]::bigint>4294967295 OR schema_parts[2]::bigint>4294967295
 OR t.metadata->>'oid' IS DISTINCT FROM parts[2] OR s.metadata->>'oid' IS DISTINCT FROM schema_parts[2]
 OR t.metadata->>'schema' IS DISTINCT FROM s.name OR t.metadata->>'table' IS DISTINCT FROM t.name OR src.schema_name IS DISTINCT FROM s.name
 OR EXISTS(SELECT 1 FROM unnest(ARRAY[s.name,t.name]) n WHERE octet_length(n) NOT BETWEEN 1 AND 63) THEN RAISE EXCEPTION 'QUALITY_TARGET_UNSUPPORTED' USING ERRCODE='0A000';END IF;
 connection:=jsonb_build_object('connectorId','postgresql','host',src.host,'port',src.port,'database',src.database_name,'schema',src.schema_name,'secretRef',src.secret_ref);
 target:=jsonb_build_object('kind','table','databaseOid',parts[1],'schemaOid',schema_parts[2],'relationOid',parts[2],'schemaName',s.name,'tableName',t.name);
 RETURN jsonb_build_object('sourceId',src.id,'sourceVersion',src.version,'sourceConfigHash',public.gc_type_migration_hash(connection),'source',connection,
  'schemaAssetId',s.id,'schemaAssetVersion',s.version,'tableAssetId',t.id,'tableAssetVersion',t.version,'columnAssetId',NULL,
  'execution',jsonb_build_object('formatVersion',1,'kind','volume','target',target,'budget',jsonb_build_object('maximumRows',100000,'maximumSeconds',30,'statementTimeoutMs',15000,'maximumEstimatedCost',1000000,'maximumEstimatedBytes',67108864)));
END $$;
-- Exact authored target derivation. No column ID is invented for table rules.
CREATE FUNCTION public.gc_quality_input_target(inputs jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN inputs#>>'{execution,kind}'='volume' THEN jsonb_build_object('kind','table','tableAssetId',inputs->'tableAssetId')
 ELSE jsonb_build_object('tableAssetId',inputs->'tableAssetId','columnAssetId',inputs->'columnAssetId') END
$$;


CREATE OR REPLACE FUNCTION public.gc_quality_definition_valid(value jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ BEGIN
 IF value->>'kind'='volume' THEN RETURN public.gc_quality_volume_definition_valid(value);END IF;
 IF value->>'kind'='freshness' THEN RETURN public.gc_quality_freshness_definition_valid(value);END IF;
 IF value->>'kind'='range' THEN RETURN public.gc_quality_range_definition_valid(value);END IF;
 IF value->>'kind'='uniqueness' THEN RETURN public.gc_quality_uniqueness_definition_valid(value);END IF;
 IF value->>'kind'='completeness' THEN RETURN public.gc_quality_completeness_definition_valid(value);END IF;
 IF public.gc_relation_keys(value,ARRAY['formatVersion','kind','target','name','purpose','ownerId','severity','maximumInvalidBasisPoints','reference','comparison','nullPolicy']) IS NOT TRUE
 OR value->>'kind' IS DISTINCT FROM 'reference-allowed-values' OR value->>'comparison' IS DISTINCT FROM 'utf8-exact' OR value->>'nullPolicy' IS DISTINCT FROM 'exclude'
 OR public.gc_relation_keys(value->'reference',ARRAY['setId','selection','codeStatus']) IS NOT TRUE OR NOT public.gc_reference_uuid(value#>'{reference,setId}')
 OR value#>>'{reference,selection}' IS DISTINCT FROM 'effective-at-run' OR value#>>'{reference,codeStatus}' IS DISTINCT FROM 'active' THEN RETURN false;END IF;
 RETURN public.gc_quality_completeness_definition_valid((value-ARRAY['maximumInvalidBasisPoints','reference','comparison','nullPolicy'])||jsonb_build_object('kind','completeness','maximumNullBasisPoints',value->'maximumInvalidBasisPoints'));
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_measurement_valid(value jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ BEGIN
 IF value->>'kind'='volume' THEN RETURN public.gc_quality_volume_measurement_valid(value);END IF;
 IF value->>'kind'='freshness' THEN RETURN public.gc_quality_freshness_measurement_valid(value);END IF;
 IF value->>'kind'='range' THEN RETURN public.gc_quality_range_measurement_valid(value);END IF;
 IF value->>'kind'='uniqueness' THEN RETURN public.gc_quality_uniqueness_measurement_valid(value);END IF;
 IF value->>'kind'='completeness' THEN RETURN public.gc_quality_completeness_measurement_valid(value);END IF;
 IF public.gc_relation_keys(value,ARRAY['formatVersion','kind','strategy','rowCount','nullCount','invalidCount','referenceBindingHash','observedStartedAt','observedFinishedAt','elapsedMs','sourceVersion','adapterVersion','queryTemplate','estimatedCost','estimatedBytes']) IS NOT TRUE
 OR value->>'kind' IS DISTINCT FROM 'reference-allowed-values' OR value->>'queryTemplate' IS DISTINCT FROM 'postgresql-reference-allowed-values-v1'
 OR jsonb_typeof(value->'referenceBindingHash') IS DISTINCT FROM 'string' OR value->>'referenceBindingHash' !~ '^[a-f0-9]{64}$'
 OR jsonb_typeof(value->'invalidCount') IS DISTINCT FROM 'number' OR value->>'invalidCount' !~ '^(0|[1-9][0-9]{0,5})$' THEN RETURN false;END IF;
 IF public.gc_quality_completeness_measurement_valid((value-ARRAY['invalidCount','referenceBindingHash'])||jsonb_build_object('kind','completeness','queryTemplate','postgresql-completeness-v1')) IS NOT TRUE THEN RETURN false;END IF;
 RETURN (value->>'invalidCount')::integer<=(value->>'rowCount')::integer-(value->>'nullCount')::integer;
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_visible(column_identity uuid,actor_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT public.gc_quality_table_visible(column_identity,actor_identity) OR EXISTS(SELECT 1 FROM public.assets c JOIN public.assets t ON t.tenant_id=c.tenant_id AND t.source_id=c.source_id AND t.external_id=c.parent_external_id
 JOIN public.assets s ON s.tenant_id=t.tenant_id AND s.source_id=t.source_id AND s.external_id=t.parent_external_id
 JOIN public.memberships m ON m.tenant_id=c.tenant_id AND m.identity_id=actor_identity JOIN public.identities i ON i.id=m.identity_id
 WHERE c.tenant_id=public.gc_tenant() AND c.id=column_identity AND c.type='column' AND t.type='table' AND s.type='schema'
 AND m.active AND i.active AND m.permissions @> '["catalog:read","quality:read"]'::jsonb
 AND (c.visibility='tenant' OR c.allowed_identities @> to_jsonb(ARRAY[actor_identity::text]))
 AND (t.visibility='tenant' OR t.allowed_identities @> to_jsonb(ARRAY[actor_identity::text]))
 AND (s.visibility='tenant' OR s.allowed_identities @> to_jsonb(ARRAY[actor_identity::text])));
$$;

CREATE OR REPLACE FUNCTION public.gc_quality_inputs(column_identity uuid,actor_identity uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE c public.assets;t public.assets;s public.assets;src public.sources;parts text[];schema_parts text[];connection jsonb;target jsonb;BEGIN
 IF EXISTS(SELECT 1 FROM public.assets WHERE tenant_id=public.gc_tenant() AND id=column_identity AND type='table') THEN RETURN public.gc_quality_table_inputs(column_identity,actor_identity);END IF;
 IF NOT public.gc_quality_visible(column_identity,actor_identity) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002'; END IF;
 SELECT * INTO c FROM public.assets WHERE tenant_id=public.gc_tenant() AND id=column_identity;
 SELECT * INTO t FROM public.assets WHERE tenant_id=c.tenant_id AND source_id=c.source_id AND external_id=c.parent_external_id;
 SELECT * INTO s FROM public.assets WHERE tenant_id=c.tenant_id AND source_id=c.source_id AND external_id=t.parent_external_id;
 SELECT * INTO src FROM public.sources WHERE tenant_id=c.tenant_id AND id=c.source_id;
 IF src.connector_id<>'postgresql' OR c.status<>'active' OR t.status<>'active' OR s.status<>'active' OR t.metadata->>'relationKind' IS DISTINCT FROM 'r' THEN
  RAISE EXCEPTION 'QUALITY_TARGET_UNSUPPORTED' USING ERRCODE='0A000'; END IF;
 parts:=regexp_match(c.external_id,'^pg:([1-9][0-9]{0,9}):relation:([1-9][0-9]{0,9}):column:([1-9][0-9]{0,4})$');
 schema_parts:=regexp_match(s.external_id,'^pg:([1-9][0-9]{0,9}):schema:([1-9][0-9]{0,9})$');
 IF parts IS NULL OR schema_parts IS NULL OR parts[1]<>schema_parts[1] OR parts[1]::bigint>4294967295 OR parts[2]::bigint>4294967295
 OR schema_parts[2]::bigint>4294967295 OR parts[3]::integer>32767 OR t.external_id<>'pg:'||parts[1]||':relation:'||parts[2]
 OR t.metadata->>'oid' IS DISTINCT FROM parts[2] OR s.metadata->>'oid' IS DISTINCT FROM schema_parts[2]
 OR c.metadata->>'ordinalPosition' IS DISTINCT FROM parts[3] OR t.metadata->>'schema' IS DISTINCT FROM s.name
 OR t.metadata->>'table' IS DISTINCT FROM t.name OR src.schema_name IS DISTINCT FROM s.name
 OR coalesce(length(c.metadata->>'dataType'),0) NOT BETWEEN 1 AND 256
 OR EXISTS(SELECT 1 FROM unnest(ARRAY[s.name,t.name,c.name]) n WHERE octet_length(n) NOT BETWEEN 1 AND 63) THEN
  RAISE EXCEPTION 'QUALITY_TARGET_UNSUPPORTED' USING ERRCODE='0A000'; END IF;
 connection:=jsonb_build_object('connectorId','postgresql','host',src.host,'port',src.port,'database',src.database_name,'schema',src.schema_name,'secretRef',src.secret_ref);
 target:=jsonb_build_object('databaseOid',parts[1],'schemaOid',schema_parts[2],'relationOid',parts[2],'attributeNumber',parts[3]::integer,
  'schemaName',s.name,'tableName',t.name,'columnName',c.name,'dataType',c.metadata->>'dataType');
 RETURN jsonb_build_object('sourceId',src.id,'sourceVersion',src.version,'sourceConfigHash',public.gc_type_migration_hash(connection),'source',connection,
  'schemaAssetId',s.id,'schemaAssetVersion',s.version,'tableAssetId',t.id,'tableAssetVersion',t.version,'columnAssetId',c.id,'columnAssetVersion',c.version,
  'execution',jsonb_build_object('formatVersion',1,'kind','completeness','target',target,'budget',jsonb_build_object('maximumRows',100000,'maximumSeconds',30,'statementTimeoutMs',15000,'maximumEstimatedCost',1000000,'maximumEstimatedBytes',67108864)));
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_lock(column_identity uuid,actor_identity uuid,owner_identity uuid DEFAULT NULL) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE item uuid;BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(public.gc_tenant()::text,0));
 FOR item IN SELECT id FROM public.identities WHERE id=ANY(ARRAY[actor_identity,owner_identity]) ORDER BY id FOR SHARE LOOP NULL;END LOOP;
 FOR item IN SELECT identity_id FROM public.memberships WHERE tenant_id=public.gc_tenant() AND identity_id=ANY(ARRAY[actor_identity,owner_identity]) ORDER BY identity_id FOR SHARE LOOP NULL;END LOOP;
 FOR item IN SELECT id FROM public.sources WHERE tenant_id=public.gc_tenant() AND id=(SELECT source_id FROM public.assets WHERE tenant_id=public.gc_tenant() AND id=column_identity) FOR SHARE LOOP NULL;END LOOP;
 FOR item IN SELECT id FROM public.assets WHERE tenant_id=public.gc_tenant() AND id IN (
  SELECT c.id FROM public.assets c WHERE c.tenant_id=public.gc_tenant() AND c.id=column_identity
  UNION SELECT t.id FROM public.assets c JOIN public.assets t ON t.tenant_id=c.tenant_id AND t.source_id=c.source_id AND t.external_id=c.parent_external_id WHERE c.tenant_id=public.gc_tenant() AND c.id=column_identity
  UNION SELECT s.id FROM public.assets c JOIN public.assets t ON t.tenant_id=c.tenant_id AND t.source_id=c.source_id AND t.external_id=c.parent_external_id
  JOIN public.assets s ON s.tenant_id=t.tenant_id AND s.source_id=t.source_id AND s.external_id=t.parent_external_id WHERE c.tenant_id=public.gc_tenant() AND c.id=column_identity AND c.type='column'
 ) ORDER BY id FOR SHARE LOOP NULL;END LOOP;
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_eligibility(asset_identity uuid,actor_identity uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE a public.assets;v jsonb;BEGIN
 SELECT a0.* INTO a FROM public.assets a0 JOIN public.memberships m ON m.tenant_id=a0.tenant_id AND m.identity_id=actor_identity JOIN public.identities i ON i.id=m.identity_id
 WHERE a0.tenant_id=public.gc_tenant() AND a0.id=asset_identity AND m.active AND i.active AND m.permissions @> '["catalog:read","quality:read"]'::jsonb
 AND (a0.visibility='tenant' OR a0.allowed_identities @> to_jsonb(ARRAY[actor_identity::text]));
 IF NOT FOUND THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
 IF a.type NOT IN ('column','table') THEN RETURN jsonb_build_object('supported',false,'reason','COLUMN_REQUIRED','tableAssetId',NULL,'columnAssetId',NULL);END IF;
 BEGIN v:=public.gc_quality_inputs(asset_identity,actor_identity);
 EXCEPTION WHEN feature_not_supported THEN RETURN jsonb_build_object('supported',false,'reason','QUALITY_TARGET_UNSUPPORTED','tableAssetId',NULL,'columnAssetId',CASE WHEN a.type='column' THEN asset_identity ELSE NULL END);END;
 RETURN jsonb_build_object('supported',true,'reason',NULL,'tableAssetId',v->'tableAssetId','columnAssetId',CASE WHEN a.type='column' THEN asset_identity ELSE NULL END);
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_rule_visible(rule_identity uuid,selected_version integer,actor_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM public.quality_rule_versions v JOIN public.quality_rules r ON r.tenant_id=v.tenant_id AND r.id=v.rule_id
 WHERE v.tenant_id=public.gc_tenant() AND v.rule_id=rule_identity AND v.version=selected_version
 AND public.gc_quality_visible(coalesce(r.column_asset_id,r.table_asset_id),actor_identity)
 AND (v.definition->>'kind' IN ('completeness','uniqueness','range','freshness','volume') OR (v.definition->>'kind'='reference-allowed-values' AND EXISTS(
 SELECT 1 FROM public.quality_rule_reference_bindings b WHERE b.tenant_id=v.tenant_id AND b.rule_id=v.rule_id AND b.rule_version=v.version
 AND b.set_id::text=v.definition#>>'{reference,setId}' AND public.gc_reference_visible(b.set_id,actor_identity)))))
$$;

CREATE OR REPLACE FUNCTION public.gc_quality_run_visible(run_identity uuid,actor_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM public.quality_runs q WHERE q.tenant_id=public.gc_tenant() AND q.id=run_identity
 AND public.gc_quality_rule_visible(q.rule_id,q.rule_version,actor_identity)
 AND (q.inputs#>>'{execution,kind}' IN ('completeness','uniqueness','range','freshness','volume') OR EXISTS(SELECT 1 FROM public.quality_run_reference_bindings b
 WHERE b.tenant_id=q.tenant_id AND b.run_id=q.id AND public.gc_reference_visible(b.set_id,actor_identity))))
$$;

CREATE OR REPLACE FUNCTION public.gc_quality_run_lock(run_identity uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE r public.quality_runs;v public.quality_rule_versions;BEGIN
 SELECT * INTO r FROM public.quality_runs WHERE tenant_id=public.gc_tenant() AND id=run_identity;
 SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=r.tenant_id AND rule_id=r.rule_id AND version=r.rule_version;
 IF EXISTS(SELECT 1 FROM public.quality_monitor_occurrences o WHERE o.tenant_id=r.tenant_id AND o.run_id=r.id) THEN
  IF v.definition->>'kind'='reference-allowed-values' THEN PERFORM public.gc_quality_reference_lock(coalesce(r.column_asset_id,r.table_asset_id),r.requester_id,v.owner_id,(v.definition#>>'{reference,setId}')::uuid);
  ELSE PERFORM public.gc_quality_lock(coalesce(r.column_asset_id,r.table_asset_id),r.requester_id,v.owner_id);END IF;
 ELSIF v.definition->>'kind'='reference-allowed-values' THEN PERFORM public.gc_quality_reference_lock(coalesce(r.column_asset_id,r.table_asset_id),r.requester_id,v.owner_id,(v.definition#>>'{reference,setId}')::uuid);
 ELSIF v.definition->>'kind' IN ('uniqueness','range','freshness','volume') THEN PERFORM public.gc_quality_lock(coalesce(r.column_asset_id,r.table_asset_id),r.requester_id,v.owner_id);
 ELSE PERFORM public.gc_quality_lock(coalesce(r.column_asset_id,r.table_asset_id),r.requester_id);END IF;
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_run_can_execute(run_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT coalesce((SELECT (NOT EXISTS(SELECT 1 FROM public.quality_monitor_occurrences o WHERE o.tenant_id=r.tenant_id AND o.run_id=r.id) OR EXISTS(SELECT 1 FROM public.quality_rule_versions v WHERE v.tenant_id=r.tenant_id AND v.rule_id=r.rule_id AND v.version=r.rule_version AND public.gc_quality_reference_owner_active(v.owner_id))) AND public.gc_quality_can_execute(coalesce(r.column_asset_id,r.table_asset_id),r.requester_id) AND
 (r.inputs#>>'{execution,kind}'='completeness' OR (r.inputs#>>'{execution,kind}' IN ('uniqueness','range','freshness','volume') AND public.gc_quality_run_visible(r.id,r.requester_id) AND EXISTS(SELECT 1 FROM public.quality_rule_versions v WHERE v.tenant_id=r.tenant_id AND v.rule_id=r.rule_id AND v.version=r.rule_version AND public.gc_quality_reference_owner_active(v.owner_id))) OR (r.inputs#>>'{execution,kind}'='reference-allowed-values' AND public.gc_quality_reference_run_current(r.id)))
 FROM public.quality_runs r WHERE r.tenant_id=public.gc_tenant() AND r.id=run_identity),false)
$$;

CREATE OR REPLACE FUNCTION public.gc_quality_run_view(run_identity uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT jsonb_build_object('id',r.id,'ruleId',r.rule_id,'ruleVersion',r.rule_version,'ruleHash',r.rule_hash,'requesterId',r.requester_id,'columnAssetId',r.column_asset_id,'tableAssetId',r.table_asset_id,
  'status',r.status,'version',r.version,'attempt',r.attempt,'createdAt',public.gc_relation_utc(r.created_at),'startedAt',public.gc_relation_utc(r.started_at),'finishedAt',public.gc_relation_utc(r.finished_at),
  'expiresAt',public.gc_relation_utc(r.expires_at),'measurement',r.measurement,'verdict',r.verdict,'errorCode',r.error_code) || CASE WHEN r.inputs#>>'{execution,kind}'='reference-allowed-values' THEN jsonb_build_object('kind','reference-allowed-values','reference',(r.inputs#>'{execution,reference}')-'codes') WHEN r.inputs#>>'{execution,kind}'='uniqueness' THEN jsonb_build_object('kind','uniqueness') WHEN r.inputs#>>'{execution,kind}'='range' THEN jsonb_build_object('kind','range','range',r.inputs#>'{execution,range}') WHEN r.inputs#>>'{execution,kind}'='freshness' THEN jsonb_build_object('kind','freshness','freshness',r.inputs#>'{execution,freshness}') WHEN r.inputs#>>'{execution,kind}'='volume' THEN jsonb_build_object('kind','volume','volume',r.inputs#>'{execution,volume}') ELSE '{}'::jsonb END
 FROM public.quality_runs r WHERE r.tenant_id=public.gc_tenant() AND r.id=run_identity;
$$;

CREATE OR REPLACE FUNCTION public.gc_quality_refresh_inputs(run_identity uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE r public.quality_runs;v public.quality_rule_versions;result jsonb;BEGIN
 SELECT * INTO r FROM public.quality_runs WHERE tenant_id=public.gc_tenant() AND id=run_identity;
 result:=public.gc_quality_inputs(coalesce(r.column_asset_id,r.table_asset_id),r.requester_id);
 IF r.inputs#>>'{execution,kind}'='reference-allowed-values' THEN
  result:=jsonb_set(result,'{execution}',(result->'execution')||jsonb_build_object('kind','reference-allowed-values','reference',r.inputs#>'{execution,reference}'));
 ELSIF r.inputs#>>'{execution,kind}'='uniqueness' THEN
  result:=jsonb_set(result,'{execution}',(result->'execution')||jsonb_build_object('kind','uniqueness','budget',(result#>'{execution,budget}')||jsonb_build_object('maximumValueBytes',4096,'maximumTotalValueBytes',67108864)));
 ELSIF r.inputs#>>'{execution,kind}'='range' THEN
  SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=r.tenant_id AND rule_id=r.rule_id AND version=r.rule_version;
  result:=jsonb_set(result,'{execution}',(result->'execution')||jsonb_build_object('kind','range','range',public.gc_quality_range_binding(v.definition)));
 ELSIF r.inputs#>>'{execution,kind}'='freshness' THEN
  SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=r.tenant_id AND rule_id=r.rule_id AND version=r.rule_version;
  result:=jsonb_set(result,'{execution}',(result->'execution')||jsonb_build_object('kind','freshness','freshness',public.gc_quality_freshness_binding(v.definition)));
 ELSIF r.inputs#>>'{execution,kind}'='volume' THEN
  SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=r.tenant_id AND rule_id=r.rule_id AND version=r.rule_version;
  result:=jsonb_set(result,'{execution}',(result->'execution')||jsonb_build_object('volume',public.gc_quality_volume_binding(v.definition)));
 END IF;RETURN result;
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_command(operation text,command_key text,body jsonb,correlation text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant();actor uuid;old public.idempotency;rule public.quality_rules;v public.quality_rule_versions;r public.quality_runs;
 definition jsonb;result jsonb;inputs jsonb;hash text;identity uuid;column_identity uuid;expected integer;now_at timestamptz;actions text[];binding jsonb;as_of_time timestamptz;BEGIN
 IF operation NOT IN ('quality.rule.publish','quality.run.request','quality.run.cancel') OR operation IS NULL
 OR command_key IS NULL OR length(command_key) NOT BETWEEN 8 AND 128 OR command_key ~ '[[:cntrl:]]'
 OR correlation IS NULL OR length(correlation) NOT BETWEEN 1 AND 128 OR correlation ~ '[[:cntrl:]]'
 OR body IS NULL OR jsonb_typeof(body)<>'object' OR octet_length(body::text)>20000 THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;
 actions:=ARRAY['catalog:read','quality:read',CASE WHEN operation='quality.rule.publish' THEN 'quality:write' ELSE 'quality:execute' END];
 PERFORM public.gc_relation_authorize(actions);actor:=public.gc_actor()::uuid;
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text,0));hash:=public.gc_type_migration_hash(body);
 SELECT * INTO old FROM public.idempotency WHERE tenant_id=tenant AND actor_id=actor::text AND idempotency.operation=gc_quality_command.operation AND key=command_key;
 IF FOUND THEN
  IF old.request_hash<>hash THEN RAISE EXCEPTION 'IDEMPOTENCY_CONFLICT' USING ERRCODE='40001';END IF;
  column_identity:=CASE WHEN operation='quality.rule.publish' THEN coalesce(old.response#>>'{rule,definition,target,columnAssetId}',old.response#>>'{rule,definition,target,tableAssetId}')::uuid ELSE coalesce(old.response#>>'{run,columnAssetId}',old.response#>>'{run,tableAssetId}')::uuid END;
  IF operation='quality.rule.publish' THEN
   SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=tenant AND rule_id=(old.response#>>'{rule,id}')::uuid AND version=(old.response#>>'{rule,version}')::integer;
   IF v.definition->>'kind'='reference-allowed-values' THEN PERFORM public.gc_quality_reference_lock(column_identity,actor,v.owner_id,(v.definition#>>'{reference,setId}')::uuid);
   ELSIF v.definition->>'kind' IN ('uniqueness','range','freshness','volume') THEN PERFORM public.gc_quality_lock(column_identity,actor,v.owner_id);
   ELSE PERFORM public.gc_quality_lock(column_identity,actor);END IF;
   IF NOT public.gc_quality_rule_visible(v.rule_id,v.version,actor) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  ELSE
   SELECT * INTO r FROM public.quality_runs WHERE tenant_id=tenant AND id=(old.response#>>'{run,id}')::uuid;
   SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=tenant AND rule_id=r.rule_id AND version=r.rule_version;
   IF v.definition->>'kind'='reference-allowed-values' THEN PERFORM public.gc_quality_reference_lock(column_identity,actor,v.owner_id,(v.definition#>>'{reference,setId}')::uuid);
   ELSIF v.definition->>'kind' IN ('uniqueness','range','freshness','volume') THEN PERFORM public.gc_quality_lock(column_identity,actor,v.owner_id);
   ELSE PERFORM public.gc_quality_lock(column_identity,actor);END IF;
   IF NOT public.gc_quality_run_visible(r.id,actor) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  END IF;
  PERFORM public.gc_relation_authorize(actions);RETURN old.response;
 END IF;
 IF operation='quality.rule.publish' THEN
  IF public.gc_relation_keys(body,ARRAY['id','expectedVersion','definition']) IS NOT TRUE OR NOT public.gc_approval_uuid(body->>'id')
  OR public.gc_quality_definition_valid(body->'definition') IS NOT TRUE OR jsonb_typeof(body->'expectedVersion') IS DISTINCT FROM 'number'
  OR body->>'expectedVersion' !~ '^(0|[1-9][0-9]{0,9})$' OR (body->>'expectedVersion')::bigint>=2147483647 THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;
  identity:=(body->>'id')::uuid;definition:=body->'definition';expected:=(body->>'expectedVersion')::integer;column_identity:=coalesce(definition#>>'{target,columnAssetId}',definition#>>'{target,tableAssetId}')::uuid;
  -- Existing rule identity is authorized before caller-supplied replacement
  -- targets, version diagnostics or owner checks can reveal its existence.
  SELECT * INTO rule FROM public.quality_rules WHERE tenant_id=tenant AND id=identity;
  IF (expected>0 AND rule.id IS NULL) OR (rule.id IS NOT NULL AND NOT public.gc_quality_rule_visible(rule.id,rule.current_version,actor)) THEN
   RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  PERFORM public.gc_quality_lock(column_identity,actor,(definition->>'ownerId')::uuid);PERFORM public.gc_relation_authorize(actions);
  IF rule.id IS NOT NULL AND NOT public.gc_quality_rule_visible(rule.id,rule.current_version,actor) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  IF rule.id IS NOT NULL AND coalesce(rule.column_asset_id,rule.table_asset_id) IS DISTINCT FROM column_identity THEN RAISE EXCEPTION 'QUALITY_TARGET_IMMUTABLE' USING ERRCODE='40001';END IF;
  IF definition->>'kind'='reference-allowed-values' THEN
   PERFORM 1 FROM public.reference_sets WHERE tenant_id=tenant AND id=(definition#>>'{reference,setId}')::uuid FOR SHARE;
   IF NOT public.gc_reference_visible((definition#>>'{reference,setId}')::uuid,actor) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  END IF;
  inputs:=public.gc_quality_inputs(column_identity,actor);
  IF public.gc_quality_input_target(inputs) IS DISTINCT FROM definition->'target' THEN RAISE EXCEPTION 'QUALITY_TARGET_STALE' USING ERRCODE='40001';END IF;
  IF NOT EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id WHERE m.tenant_id=tenant AND m.identity_id=(definition->>'ownerId')::uuid AND m.active AND i.active) THEN
   RAISE EXCEPTION 'QUALITY_OWNER_UNAVAILABLE' USING ERRCODE='42501';END IF;
  IF (expected=0 AND rule.id IS NOT NULL) OR (expected>0 AND (rule.id IS NULL OR rule.current_version<>expected OR coalesce(rule.column_asset_id,rule.table_asset_id) IS DISTINCT FROM column_identity)) THEN
   RAISE EXCEPTION 'VERSION_CONFLICT' USING ERRCODE='40001';END IF;
  IF expected>0 THEN
   SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=tenant AND rule_id=identity AND version=expected;
   IF v.definition->'target' IS DISTINCT FROM definition->'target' THEN RAISE EXCEPTION 'QUALITY_TARGET_IMMUTABLE' USING ERRCODE='40001';END IF;
  END IF;
  now_at:=clock_timestamp();
  IF expected=0 THEN INSERT INTO public.quality_rules(tenant_id,id,column_asset_id,current_version,created_by,created_at,table_asset_id) VALUES(tenant,identity,CASE WHEN definition->>'kind'='volume' THEN NULL ELSE column_identity END,1,actor,now_at,CASE WHEN definition->>'kind'='volume' THEN column_identity ELSE NULL END);
  ELSE UPDATE public.quality_rules SET current_version=expected+1 WHERE tenant_id=tenant AND id=identity;END IF;
  INSERT INTO public.quality_rule_versions VALUES(tenant,identity,expected+1,definition,public.gc_type_migration_hash(definition),(definition->>'ownerId')::uuid,actor,now_at);
  IF definition->>'kind'='reference-allowed-values' THEN INSERT INTO public.quality_rule_reference_bindings(tenant_id,rule_id,rule_version,set_id)
   VALUES(tenant,identity,expected+1,(definition#>>'{reference,setId}')::uuid);END IF;
  PERFORM public.gc_approval_journal('quality.rule_published',NULL,column_identity::text,expected+1,jsonb_build_object('ruleId',identity,'definitionHash',public.gc_type_migration_hash(definition)),correlation);
  result:=jsonb_build_object('rule',public.gc_quality_rule_view(identity,expected+1));
 ELSIF operation='quality.run.request' THEN
  IF public.gc_relation_keys(body,ARRAY['ruleId','id','ruleVersion','ruleHash']||CASE WHEN body ? 'referenceAsOf' THEN ARRAY['referenceAsOf'] ELSE ARRAY[]::text[] END) IS NOT TRUE OR NOT public.gc_approval_uuid(body->>'ruleId') OR NOT public.gc_approval_uuid(body->>'id')
  OR jsonb_typeof(body->'ruleVersion') IS DISTINCT FROM 'number' OR body->>'ruleVersion' !~ '^[1-9][0-9]{0,9}$' OR (body->>'ruleVersion')::bigint>2147483647
  OR jsonb_typeof(body->'ruleHash') IS DISTINCT FROM 'string' OR body->>'ruleHash' !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;
  SELECT * INTO rule FROM public.quality_rules WHERE tenant_id=tenant AND id=(body->>'ruleId')::uuid;
  IF rule.id IS NULL OR NOT public.gc_quality_visible(coalesce(rule.column_asset_id,rule.table_asset_id),actor) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  column_identity:=coalesce(rule.column_asset_id,rule.table_asset_id);
  SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=tenant AND rule_id=rule.id AND version=(body->>'ruleVersion')::integer;
  IF v.version IS NULL OR NOT public.gc_quality_rule_visible(rule.id,v.version,actor) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  IF v.definition->>'kind'='reference-allowed-values' THEN PERFORM public.gc_quality_reference_lock(column_identity,actor,v.owner_id,(v.definition#>>'{reference,setId}')::uuid);
  ELSIF v.definition->>'kind' IN ('uniqueness','range','freshness','volume') THEN PERFORM public.gc_quality_lock(column_identity,actor,v.owner_id);
   ELSE PERFORM public.gc_quality_lock(column_identity,actor);END IF;
  PERFORM public.gc_relation_authorize(actions);
  IF NOT public.gc_quality_rule_visible(rule.id,v.version,actor) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  IF v.version IS NULL OR rule.current_version<>v.version OR v.definition_hash IS DISTINCT FROM body->>'ruleHash' THEN RAISE EXCEPTION 'VERSION_CONFLICT' USING ERRCODE='40001';END IF;
  inputs:=public.gc_quality_inputs(column_identity,actor);
  IF v.definition->'target' IS DISTINCT FROM public.gc_quality_input_target(inputs) THEN RAISE EXCEPTION 'QUALITY_TARGET_STALE' USING ERRCODE='40001';END IF;
  identity:=(body->>'id')::uuid;now_at:=clock_timestamp();
  IF v.definition->>'kind'='reference-allowed-values' THEN
   IF NOT public.gc_quality_reference_owner_active(v.owner_id) THEN RAISE EXCEPTION 'QUALITY_OWNER_UNAVAILABLE' USING ERRCODE='42501';END IF;
   IF body ? 'referenceAsOf' AND NOT public.gc_reference_instant(body->'referenceAsOf') THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;
   as_of_time:=CASE WHEN body ? 'referenceAsOf' THEN (body->>'referenceAsOf')::timestamptz ELSE date_trunc('milliseconds',now_at) END;
   IF as_of_time>now_at THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;
   binding:=public.gc_quality_reference_binding((v.definition#>>'{reference,setId}')::uuid,actor,as_of_time);
   inputs:=jsonb_set(inputs,'{execution}',(inputs->'execution')||jsonb_build_object('kind','reference-allowed-values','reference',binding));
  ELSIF body ? 'referenceAsOf' THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';
  ELSIF v.definition->>'kind'='volume' THEN
   IF NOT public.gc_quality_reference_owner_active(v.owner_id) THEN RAISE EXCEPTION 'QUALITY_OWNER_UNAVAILABLE' USING ERRCODE='42501';END IF;
   inputs:=jsonb_set(inputs,'{execution}',(inputs->'execution')||jsonb_build_object('volume',public.gc_quality_volume_binding(v.definition)));
  ELSIF v.definition->>'kind'='freshness' THEN
   IF NOT public.gc_quality_reference_owner_active(v.owner_id) THEN RAISE EXCEPTION 'QUALITY_OWNER_UNAVAILABLE' USING ERRCODE='42501';END IF;
   inputs:=jsonb_set(inputs,'{execution}',(inputs->'execution')||jsonb_build_object('kind','freshness','freshness',public.gc_quality_freshness_binding(v.definition)));
  ELSIF v.definition->>'kind'='range' THEN
   IF NOT public.gc_quality_reference_owner_active(v.owner_id) THEN RAISE EXCEPTION 'QUALITY_OWNER_UNAVAILABLE' USING ERRCODE='42501';END IF;
   inputs:=jsonb_set(inputs,'{execution}',(inputs->'execution')||jsonb_build_object('kind','range','range',public.gc_quality_range_binding(v.definition)));
  ELSIF v.definition->>'kind'='uniqueness' THEN
   IF NOT public.gc_quality_reference_owner_active(v.owner_id) THEN RAISE EXCEPTION 'QUALITY_OWNER_UNAVAILABLE' USING ERRCODE='42501';END IF;
   inputs:=jsonb_set(inputs,'{execution}',(inputs->'execution')||jsonb_build_object('kind','uniqueness','budget',(inputs#>'{execution,budget}')||jsonb_build_object('maximumValueBytes',4096,'maximumTotalValueBytes',67108864)));
  END IF;
  INSERT INTO public.quality_runs(tenant_id,id,rule_id,rule_version,rule_hash,requester_id,source_id,schema_asset_id,table_asset_id,column_asset_id,inputs,input_hash,status,expires_at,created_at)
  VALUES(tenant,identity,rule.id,v.version,v.definition_hash,actor,(inputs->>'sourceId')::uuid,(inputs->>'schemaAssetId')::uuid,(inputs->>'tableAssetId')::uuid,(inputs->>'columnAssetId')::uuid,
   inputs,public.gc_type_migration_hash(inputs),'queued',now_at+interval '10 minutes',now_at);
  IF binding IS NOT NULL THEN INSERT INTO public.quality_run_reference_bindings(tenant_id,run_id,set_id,release_version,publication_hash,as_of,code_status,binding_hash)
   VALUES(tenant,identity,(binding->>'setId')::uuid,(binding->>'version')::integer,binding->>'publicationHash',as_of_time,'active',binding->>'bindingHash');END IF;
  PERFORM public.gc_approval_journal('quality.run_requested',NULL,column_identity::text,1,jsonb_build_object('ruleId',rule.id,'runId',identity,'ruleVersion',v.version,'inputHash',public.gc_type_migration_hash(inputs)),correlation);
  result:=jsonb_build_object('run',public.gc_quality_run_view(identity));
 ELSE
  IF public.gc_relation_keys(body,ARRAY['runId','expectedVersion','reason']) IS NOT TRUE OR NOT public.gc_approval_uuid(body->>'runId')
  OR jsonb_typeof(body->'expectedVersion') IS DISTINCT FROM 'number' OR body->>'expectedVersion' !~ '^[1-9][0-9]{0,9}$' OR (body->>'expectedVersion')::bigint>2147483647
  OR jsonb_typeof(body->'reason') IS DISTINCT FROM 'string' OR public.gc_approval_text(body->>'reason',4096,true) IS NULL THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;
  identity:=(body->>'runId')::uuid;SELECT * INTO r FROM public.quality_runs WHERE tenant_id=tenant AND id=identity;
  IF r.id IS NULL OR NOT public.gc_quality_run_visible(r.id,actor) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  column_identity:=coalesce(r.column_asset_id,r.table_asset_id);
  SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=tenant AND rule_id=r.rule_id AND version=r.rule_version;
  IF v.definition->>'kind'='reference-allowed-values' THEN PERFORM public.gc_quality_reference_lock(column_identity,actor,v.owner_id,(v.definition#>>'{reference,setId}')::uuid);
  ELSIF v.definition->>'kind' IN ('uniqueness','range','freshness','volume') THEN PERFORM public.gc_quality_lock(column_identity,actor,v.owner_id);
   ELSE PERFORM public.gc_quality_lock(column_identity,actor);END IF;
  PERFORM public.gc_relation_authorize(actions);
  IF NOT public.gc_quality_run_visible(r.id,actor) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  IF r.version<>(body->>'expectedVersion')::integer OR r.status NOT IN ('queued','running') THEN RAISE EXCEPTION 'VERSION_CONFLICT' USING ERRCODE='40001';END IF;
  UPDATE public.quality_runs SET status='cancelled',version=version+1,finished_at=clock_timestamp(),error_code='QUALITY_CANCELLED' WHERE tenant_id=tenant AND id=identity;
  PERFORM public.gc_approval_journal('quality.run_cancelled',NULL,column_identity::text,r.version+1,jsonb_build_object('ruleId',r.rule_id,'runId',identity,'reason',public.gc_approval_text(body->>'reason',4096,true)),correlation);
  result:=jsonb_build_object('run',public.gc_quality_run_view(identity));
 END IF;
 INSERT INTO public.idempotency(tenant_id,actor_id,operation,key,request_hash,response) VALUES(tenant,actor::text,operation,command_key,hash,result);
 RETURN result;
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_claim(run_identity uuid,claim_identity uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE r public.quality_runs;inputs jsonb;now_at timestamptz;error text;BEGIN
 IF public.gc_actor() IS DISTINCT FROM 'site:local' OR claim_identity IS NULL THEN RAISE EXCEPTION 'QUALITY_SITE_REQUIRED' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(public.gc_tenant()::text,0));SELECT * INTO r FROM public.quality_runs WHERE tenant_id=public.gc_tenant() AND id=run_identity;
 IF r.id IS NULL THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
 IF (r.inputs#>>'{execution,kind}' IN ('reference-allowed-values','uniqueness','range','freshness','volume') OR EXISTS(SELECT 1 FROM public.quality_monitor_occurrences o WHERE o.tenant_id=r.tenant_id AND o.run_id=r.id)) AND r.status IN ('succeeded','failed','cancelled') THEN PERFORM public.gc_quality_run_lock(r.id);IF NOT public.gc_quality_run_can_execute(r.id) THEN RAISE EXCEPTION 'QUALITY_AUTHORITY_REVOKED' USING ERRCODE='42501';END IF;END IF;
 IF r.status IN ('succeeded','failed','cancelled') THEN RETURN jsonb_build_object('status','terminal','run',public.gc_quality_run_view(r.id));END IF;
 PERFORM public.gc_quality_run_lock(r.id);now_at:=clock_timestamp();
 IF NOT public.gc_quality_run_can_execute(r.id) THEN error:='QUALITY_AUTHORITY_REVOKED';
 ELSIF r.expires_at<=now_at THEN error:='QUALITY_DEADLINE_EXCEEDED';
 ELSE
  BEGIN inputs:=public.gc_quality_refresh_inputs(r.id);
  EXCEPTION WHEN feature_not_supported OR no_data_found THEN error:='QUALITY_TARGET_STALE';END;
  IF error IS NULL AND inputs IS DISTINCT FROM r.inputs THEN error:='QUALITY_TARGET_STALE';END IF;
 END IF;
 IF error IS NOT NULL THEN PERFORM public.gc_quality_terminal(r.id,error);RETURN jsonb_build_object('status','terminal','run',public.gc_quality_run_view(r.id));END IF;
 IF r.status='running' AND r.lease_expires_at>now_at THEN
  IF r.claim_id<>claim_identity THEN RETURN jsonb_build_object('status','busy','retryAt',public.gc_relation_utc(r.lease_expires_at));END IF;
 ELSE
  IF r.attempt>=3 THEN PERFORM public.gc_quality_terminal(r.id,'QUALITY_ATTEMPTS_EXHAUSTED');RETURN jsonb_build_object('status','terminal','run',public.gc_quality_run_view(r.id));END IF;
  IF r.claim_id=claim_identity THEN RAISE EXCEPTION 'QUALITY_CLAIM_EXPIRED' USING ERRCODE='40001';END IF;
  UPDATE public.quality_runs SET status='running',version=version+1,attempt=attempt+1,claim_id=claim_identity,claimed_at=now_at,lease_expires_at=least(expires_at,now_at+interval '120 seconds'),started_at=coalesce(started_at,now_at)
   WHERE tenant_id=r.tenant_id AND id=r.id RETURNING * INTO r;
  PERFORM public.gc_approval_journal('quality.run_claimed',NULL,coalesce(r.column_asset_id,r.table_asset_id)::text,r.version,jsonb_build_object('ruleId',r.rule_id,'runId',r.id,'attempt',r.attempt),'quality:'||r.id::text);
 END IF;
 RETURN jsonb_build_object('status','claimed','runId',r.id,'claimId',r.claim_id,'attempt',r.attempt,'leaseExpiresAt',public.gc_relation_utc(r.lease_expires_at),'source',r.inputs->'source','execution',r.inputs->'execution');
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_terminal(run_identity uuid,error text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE r public.quality_runs;BEGIN
 SELECT * INTO r FROM public.quality_runs WHERE tenant_id=public.gc_tenant() AND id=run_identity;
 IF r.id IS NULL OR r.status NOT IN ('queued','running') THEN RETURN;END IF;
 UPDATE public.quality_runs SET status=CASE WHEN error='QUALITY_AUTHORITY_REVOKED' THEN 'cancelled' ELSE 'failed' END,version=version+1,finished_at=clock_timestamp(),error_code=error WHERE tenant_id=r.tenant_id AND id=r.id;
 PERFORM public.gc_approval_journal('quality.run_finished',NULL,coalesce(r.column_asset_id,r.table_asset_id)::text,r.version+1,jsonb_build_object('ruleId',r.rule_id,'runId',r.id,'errorCode',error),'quality:'||r.id::text);
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_finish(run_identity uuid,body jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE r public.quality_runs;v public.quality_rule_versions;inputs jsonb;measured jsonb;error text;hash text;outcome text;now_at timestamptz;BEGIN
 IF public.gc_actor() IS DISTINCT FROM 'site:local' THEN RAISE EXCEPTION 'QUALITY_SITE_REQUIRED' USING ERRCODE='42501';END IF;
 IF (public.gc_relation_keys(body,ARRAY['claimId','attempt','measurement']) IS NOT TRUE AND public.gc_relation_keys(body,ARRAY['claimId','attempt','errorCode']) IS NOT TRUE)
 OR NOT public.gc_approval_uuid(body->>'claimId') OR jsonb_typeof(body->'attempt') IS DISTINCT FROM 'number' OR body->>'attempt' !~ '^[1-3]$'
 OR octet_length(body::text)>20000 THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;
 IF body ? 'measurement' THEN
  IF public.gc_quality_measurement_valid(body->'measurement') IS NOT TRUE THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;
  measured:=body->'measurement';
 ELSE
  IF jsonb_typeof(body->'errorCode') IS DISTINCT FROM 'string' OR body->>'errorCode' NOT IN ('QUALITY_RESOURCE_LIMIT','QUALITY_TARGET_STALE','QUALITY_TARGET_UNSUPPORTED','QUALITY_SOURCE_FAILED','QUALITY_DEADLINE_EXCEEDED','QUALITY_CLOCK_SKEW') THEN
   RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;error:=body->>'errorCode';
 END IF;
 hash:=public.gc_type_migration_hash(body);PERFORM pg_advisory_xact_lock(hashtextextended(public.gc_tenant()::text,0));
 SELECT * INTO r FROM public.quality_runs WHERE tenant_id=public.gc_tenant() AND id=run_identity;
 IF r.id IS NULL THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
 PERFORM public.gc_quality_run_lock(r.id);now_at:=clock_timestamp();
 IF error='QUALITY_CLOCK_SKEW' AND r.inputs#>>'{execution,kind}' IS DISTINCT FROM 'freshness' THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;
 IF r.status IN ('succeeded','failed','cancelled') THEN
  IF NOT public.gc_quality_run_can_execute(r.id) THEN RAISE EXCEPTION 'QUALITY_AUTHORITY_REVOKED' USING ERRCODE='42501';END IF;
  IF r.completion_hash IS DISTINCT FROM hash OR r.claim_id IS DISTINCT FROM (body->>'claimId')::uuid OR r.attempt<>(body->>'attempt')::integer THEN
   RAISE EXCEPTION 'QUALITY_COMPLETION_CONFLICT' USING ERRCODE='40001';END IF;
  RETURN jsonb_build_object('run',public.gc_quality_run_view(r.id));
 END IF;
 IF r.status<>'running' OR r.claim_id IS DISTINCT FROM (body->>'claimId')::uuid OR r.attempt<>(body->>'attempt')::integer THEN
  RAISE EXCEPTION 'QUALITY_CLAIM_CONFLICT' USING ERRCODE='40001';END IF;
 IF NOT public.gc_quality_run_can_execute(r.id) THEN error:='QUALITY_AUTHORITY_REVOKED';
 ELSIF r.expires_at<=now_at THEN error:='QUALITY_DEADLINE_EXCEEDED';
 ELSIF r.lease_expires_at<=now_at THEN RAISE EXCEPTION 'QUALITY_CLAIM_EXPIRED' USING ERRCODE='40001';
 ELSE
  BEGIN inputs:=public.gc_quality_refresh_inputs(r.id);
  EXCEPTION WHEN feature_not_supported OR no_data_found THEN error:='QUALITY_TARGET_STALE';END;
  IF inputs IS DISTINCT FROM r.inputs THEN error:='QUALITY_TARGET_STALE';END IF;
 END IF;
 IF error IS NULL THEN
  IF (measured->>'observedStartedAt')::timestamptz<r.claimed_at-interval '1 second'
   OR (measured->>'observedFinishedAt')::timestamptz>now_at+interval '1 second' THEN RAISE EXCEPTION 'QUALITY_OBSERVATION_INVALID' USING ERRCODE='22023';END IF;
  SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=r.tenant_id AND rule_id=r.rule_id AND version=r.rule_version;
  IF measured->>'kind' IS DISTINCT FROM r.inputs#>>'{execution,kind}' THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;
  IF v.definition->>'kind'='reference-allowed-values' THEN
   IF measured->>'referenceBindingHash' IS DISTINCT FROM r.inputs#>>'{execution,reference,bindingHash}' THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;
   outcome:=CASE WHEN (measured->>'rowCount')::bigint-(measured->>'nullCount')::bigint=0 THEN 'NO_DATA'
    WHEN (measured->>'invalidCount')::bigint*10000<=((measured->>'rowCount')::bigint-(measured->>'nullCount')::bigint)*(v.definition->>'maximumInvalidBasisPoints')::bigint THEN 'PASS' ELSE 'FAIL' END;
  ELSIF v.definition->>'kind'='volume' THEN
   outcome:=public.gc_quality_volume_verdict(measured,r.inputs#>'{execution,volume}');
   IF outcome IS NULL THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;
  ELSIF v.definition->>'kind'='freshness' THEN
   outcome:=public.gc_quality_freshness_verdict(measured,r.inputs#>'{execution,freshness}');
   IF outcome IS NULL THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;
  ELSIF v.definition->>'kind'='range' THEN
   IF measured->>'rangeHash' IS DISTINCT FROM r.inputs#>>'{execution,range,rangeHash}' THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;
   outcome:=CASE WHEN (measured->>'rowCount')::bigint-(measured->>'nullCount')::bigint=0 THEN 'NO_DATA'
    WHEN ((measured->>'belowCount')::bigint+(measured->>'aboveCount')::bigint)*10000<=((measured->>'rowCount')::bigint-(measured->>'nullCount')::bigint)*(v.definition->>'maximumOutOfRangeBasisPoints')::bigint THEN 'PASS' ELSE 'FAIL' END;
  ELSIF v.definition->>'kind'='uniqueness' THEN
   outcome:=CASE WHEN (measured->>'rowCount')::bigint-(measured->>'nullCount')::bigint=0 THEN 'NO_DATA'
    WHEN (measured->>'duplicateRowCount')::bigint*10000<=((measured->>'rowCount')::bigint-(measured->>'nullCount')::bigint)*(v.definition->>'maximumDuplicateBasisPoints')::bigint THEN 'PASS' ELSE 'FAIL' END;
  ELSE outcome:=CASE WHEN (measured->>'rowCount')::bigint=0 THEN 'NO_DATA'
   WHEN (measured->>'nullCount')::bigint*10000<=(measured->>'rowCount')::bigint*(v.definition->>'maximumNullBasisPoints')::bigint THEN 'PASS' ELSE 'FAIL' END;END IF;
  UPDATE public.quality_runs SET status='succeeded',version=version+1,finished_at=now_at,measurement=measured,verdict=outcome,completion_hash=hash WHERE tenant_id=r.tenant_id AND id=r.id;
 ELSE
  UPDATE public.quality_runs SET status=CASE WHEN error='QUALITY_AUTHORITY_REVOKED' THEN 'cancelled' ELSE 'failed' END,version=version+1,finished_at=now_at,error_code=error,completion_hash=hash WHERE tenant_id=r.tenant_id AND id=r.id;
 END IF;
 PERFORM public.gc_approval_journal('quality.run_finished',NULL,coalesce(r.column_asset_id,r.table_asset_id)::text,r.version+1,jsonb_build_object('ruleId',r.rule_id,'runId',r.id,'ruleVersion',r.rule_version,'verdict',outcome,'errorCode',error),'quality:'||r.id::text);
 RETURN jsonb_build_object('run',public.gc_quality_run_view(r.id));
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_monitor_lock(monitor_ids uuid[],new_definitions jsonb[] DEFAULT ARRAY[]::jsonb[],issue_ids uuid[] DEFAULT ARRAY[]::uuid[],occurrence_ids uuid[] DEFAULT ARRAY[]::uuid[],extra_principals uuid[] DEFAULT ARRAY[]::uuid[]) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant();defs jsonb[];principals uuid[];rules uuid[];columns uuid[];references_ids uuid[];item uuid;BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text,0));
 SELECT coalesce(array_agg(d),'{}'::jsonb[]) INTO defs FROM (
  SELECT v.definition d FROM public.quality_monitor_versions v JOIN public.quality_monitors m ON m.tenant_id=v.tenant_id AND m.id=v.monitor_id AND m.definition_version=v.version WHERE m.tenant_id=tenant AND m.id=ANY(monitor_ids)
  UNION ALL SELECT v.definition FROM public.quality_monitor_versions v JOIN public.quality_monitor_occurrences o ON o.tenant_id=v.tenant_id AND o.monitor_id=v.monitor_id AND o.definition_version=v.version WHERE o.tenant_id=tenant AND o.id=ANY(occurrence_ids)
  UNION ALL SELECT unnest(new_definitions)) d;
 SELECT array_agg(DISTINCT id) INTO rules FROM (
  SELECT (d#>>'{rule,id}')::uuid id FROM unnest(defs) d
  UNION SELECT rule_id FROM public.quality_monitor_incidents WHERE tenant_id=tenant AND id=ANY(issue_ids)) q;
 SELECT array_agg(DISTINCT id) INTO principals FROM (
  SELECT unnest(extra_principals) id UNION SELECT CASE WHEN public.gc_approval_uuid(public.gc_actor()) THEN public.gc_actor()::uuid END
  UNION SELECT (d->>'executorId')::uuid FROM unnest(defs) d
  UNION SELECT (d#>>'{routing,ownerId}')::uuid FROM unnest(defs) d
  UNION SELECT x::uuid FROM unnest(defs) d CROSS JOIN LATERAL jsonb_array_elements_text(d#>'{routing,recipientIds}') x
  UNION SELECT v.owner_id FROM unnest(defs) d JOIN public.quality_rule_versions v ON v.tenant_id=tenant AND v.rule_id=(d#>>'{rule,id}')::uuid AND v.version=(d#>>'{rule,version}')::integer
  UNION SELECT v.owner_id FROM public.quality_monitor_incidents i JOIN public.quality_rule_versions v ON v.tenant_id=i.tenant_id AND v.rule_id=i.rule_id AND v.version=i.rule_version WHERE i.tenant_id=tenant AND i.id=ANY(issue_ids)
  UNION SELECT assigned_owner_id FROM public.quality_monitor_incidents WHERE tenant_id=tenant AND id=ANY(issue_ids)) q WHERE id IS NOT NULL;
 -- No resource lock is taken until the complete global identity and tenant membership union is held.
 FOR item IN SELECT id FROM public.identities WHERE id=ANY(principals) ORDER BY id FOR SHARE LOOP NULL;END LOOP;
 FOR item IN SELECT identity_id FROM public.memberships WHERE tenant_id=tenant AND identity_id=ANY(principals) ORDER BY identity_id FOR SHARE LOOP NULL;END LOOP;
 SELECT array_agg(coalesce(column_asset_id,table_asset_id)) INTO columns FROM public.quality_rules WHERE tenant_id=tenant AND id=ANY(rules);
 FOR item IN SELECT id FROM public.sources WHERE tenant_id=tenant AND id IN(SELECT source_id FROM public.assets WHERE tenant_id=tenant AND id=ANY(columns)) ORDER BY id FOR SHARE LOOP NULL;END LOOP;
 FOR item IN SELECT id FROM public.assets WHERE tenant_id=tenant AND id IN(
  SELECT id FROM public.assets WHERE tenant_id=tenant AND id=ANY(columns)
  UNION SELECT t.id FROM public.assets c JOIN public.assets t ON t.tenant_id=c.tenant_id AND t.source_id=c.source_id AND t.external_id=c.parent_external_id WHERE c.tenant_id=tenant AND c.id=ANY(columns)
  UNION SELECT s.id FROM public.assets c JOIN public.assets t ON t.tenant_id=c.tenant_id AND t.source_id=c.source_id AND t.external_id=c.parent_external_id JOIN public.assets s ON s.tenant_id=t.tenant_id AND s.source_id=t.source_id AND s.external_id=t.parent_external_id WHERE c.tenant_id=tenant AND c.id=ANY(columns) AND c.type='column'
 ) ORDER BY id FOR SHARE LOOP NULL;END LOOP;
 SELECT array_agg(DISTINCT (v.definition#>>'{reference,setId}')::uuid) INTO references_ids FROM public.quality_rule_versions v WHERE v.tenant_id=tenant AND v.definition->>'kind'='reference-allowed-values' AND (
  EXISTS(SELECT 1 FROM unnest(defs) d WHERE v.rule_id=(d#>>'{rule,id}')::uuid AND v.version=(d#>>'{rule,version}')::integer)
  OR EXISTS(SELECT 1 FROM public.quality_monitor_incidents i WHERE i.tenant_id=tenant AND i.id=ANY(issue_ids) AND i.rule_id=v.rule_id AND i.rule_version=v.version));
 FOR item IN SELECT id FROM public.reference_sets WHERE tenant_id=tenant AND id=ANY(references_ids) ORDER BY id FOR SHARE LOOP NULL;END LOOP;
 FOR item IN SELECT id FROM public.quality_rules WHERE tenant_id=tenant AND id=ANY(rules) ORDER BY id FOR SHARE LOOP NULL;END LOOP;
 FOR item IN SELECT id FROM public.quality_monitors WHERE tenant_id=tenant AND id=ANY(monitor_ids) ORDER BY id FOR UPDATE LOOP NULL;END LOOP;
 FOR item IN SELECT id FROM public.quality_monitor_occurrences WHERE tenant_id=tenant AND id=ANY(occurrence_ids) ORDER BY id FOR SHARE LOOP NULL;END LOOP;
 FOR item IN SELECT id FROM public.quality_runs WHERE tenant_id=tenant AND id IN(SELECT run_id FROM public.quality_monitor_occurrences WHERE tenant_id=tenant AND (id=ANY(occurrence_ids) OR monitor_id=ANY(monitor_ids) AND disposition='enqueued' AND ordinal>(SELECT last_projected_ordinal FROM public.quality_monitors WHERE tenant_id=tenant AND id=monitor_id))) ORDER BY id FOR UPDATE LOOP NULL;END LOOP;
 FOR item IN SELECT id FROM public.quality_monitor_incidents WHERE tenant_id=tenant AND id=ANY(issue_ids) ORDER BY id FOR UPDATE LOOP NULL;END LOOP;
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_monitor_inputs(monitor_definition jsonb,at_time timestamptz) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE v public.quality_rule_versions;r public.quality_rules;inputs jsonb;binding jsonb;executor uuid:=(monitor_definition->>'executorId')::uuid;BEGIN
 SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=public.gc_tenant() AND rule_id=(monitor_definition#>>'{rule,id}')::uuid AND version=(monitor_definition#>>'{rule,version}')::integer;
 SELECT * INTO r FROM public.quality_rules WHERE tenant_id=v.tenant_id AND id=v.rule_id;
 IF NOT public.gc_quality_rule_visible(v.rule_id,v.version,executor) OR NOT public.gc_quality_can_execute(coalesce(r.column_asset_id,r.table_asset_id),executor) OR NOT public.gc_quality_reference_owner_active(v.owner_id) THEN RAISE EXCEPTION 'MONITOR_FORBIDDEN' USING ERRCODE='42501';END IF;
 IF r.current_version IS DISTINCT FROM v.version OR v.definition_hash IS DISTINCT FROM monitor_definition#>>'{rule,definitionHash}' THEN RAISE EXCEPTION 'MONITOR_PIN_STALE' USING ERRCODE='40001';END IF;
 IF v.definition->>'kind' NOT IN ('completeness','reference-allowed-values','uniqueness','range','freshness','volume') THEN RAISE EXCEPTION 'MONITOR_RULE_UNSUPPORTED' USING ERRCODE='0A000';END IF;
 inputs:=public.gc_quality_inputs(coalesce(r.column_asset_id,r.table_asset_id),executor);
 IF v.definition->'target' IS DISTINCT FROM public.gc_quality_input_target(inputs) THEN RAISE EXCEPTION 'MONITOR_PIN_STALE' USING ERRCODE='40001';END IF;
 IF v.definition->>'kind'='reference-allowed-values' THEN
  binding:=public.gc_quality_reference_binding((v.definition#>>'{reference,setId}')::uuid,executor,at_time);
  inputs:=jsonb_set(inputs,'{execution}',(inputs->'execution')||jsonb_build_object('kind','reference-allowed-values','reference',binding));
 ELSIF v.definition->>'kind'='uniqueness' THEN inputs:=jsonb_set(inputs,'{execution}',(inputs->'execution')||jsonb_build_object('kind','uniqueness','budget',(inputs#>'{execution,budget}')||jsonb_build_object('maximumValueBytes',4096,'maximumTotalValueBytes',67108864)));
 ELSIF v.definition->>'kind'='range' THEN inputs:=jsonb_set(inputs,'{execution}',(inputs->'execution')||jsonb_build_object('kind','range','range',public.gc_quality_range_binding(v.definition)));
 ELSIF v.definition->>'kind'='freshness' THEN inputs:=jsonb_set(inputs,'{execution}',(inputs->'execution')||jsonb_build_object('kind','freshness','freshness',public.gc_quality_freshness_binding(v.definition)));
 ELSIF v.definition->>'kind'='volume' THEN inputs:=jsonb_set(inputs,'{execution}',(inputs->'execution')||jsonb_build_object('volume',public.gc_quality_volume_binding(v.definition)));
 END IF;RETURN inputs;
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_monitor_scope(monitor_identity uuid,definition jsonb,inputs jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ BEGIN
 IF inputs#>>'{execution,kind}' IS NULL OR inputs#>>'{execution,kind}' NOT IN ('completeness','reference-allowed-values','uniqueness','range','freshness','volume') THEN RAISE EXCEPTION 'MONITOR_RULE_UNSUPPORTED' USING ERRCODE='0A000';END IF;
 RETURN jsonb_build_object('formatVersion',1,'monitorId',monitor_identity,'executorId',definition->'executorId','rule',definition->'rule',
 'sourceId',inputs->'sourceId','sourceVersion',inputs->'sourceVersion','sourceConfigHash',inputs->'sourceConfigHash','schemaAssetId',inputs->'schemaAssetId','tableAssetId',inputs->'tableAssetId','columnAssetId',inputs->'columnAssetId','targetHash',public.gc_type_migration_hash(inputs#>'{execution,target}'),
 'family',CASE inputs#>>'{execution,kind}' WHEN 'uniqueness' THEN '{"kind":"uniqueness","comparison":"utf8-exact","nullPolicy":"exclude"}'::jsonb
 WHEN 'volume' THEN jsonb_build_object('kind','volume','volumeHash',inputs#>'{execution,volume,volumeHash}')
 WHEN 'freshness' THEN jsonb_build_object('kind','freshness','freshnessHash',inputs#>'{execution,freshness,freshnessHash}')
 WHEN 'range' THEN jsonb_build_object('kind','range','rangeHash',inputs#>'{execution,range,rangeHash}')
 WHEN 'reference-allowed-values' THEN jsonb_build_object('kind','reference-allowed-values','setId',inputs#>'{execution,reference,setId}','version',inputs#>'{execution,reference,version}','publicationHash',inputs#>'{execution,reference,publicationHash}','codeStatus','active','codesHash',public.gc_type_migration_hash(inputs#>'{execution,reference,codes}'))
 ELSE '{"kind":"completeness"}'::jsonb END)||CASE WHEN inputs#>>'{execution,kind}'='volume' THEN '{"targetKind":"table"}'::jsonb ELSE '{}'::jsonb END;
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_monitor_block(monitor_definition jsonb,at_time timestamptz) RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE v public.quality_rule_versions;r public.quality_rules;executor uuid:=(monitor_definition->>'executorId')::uuid;BEGIN
 IF (monitor_definition->>'authorizationExpiresAt')::timestamptz<=at_time THEN RETURN 'AUTHORIZATION_EXPIRED';END IF;
 IF NOT public.gc_quality_reference_owner_active(executor) OR NOT EXISTS(SELECT 1 FROM public.memberships WHERE tenant_id=public.gc_tenant() AND identity_id=executor AND permissions @> '["catalog:read","quality:read","quality:execute"]') THEN RETURN 'EXECUTOR_UNAVAILABLE';END IF;
 SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=public.gc_tenant() AND rule_id=(monitor_definition#>>'{rule,id}')::uuid AND version=(monitor_definition#>>'{rule,version}')::integer;
 SELECT * INTO r FROM public.quality_rules WHERE tenant_id=public.gc_tenant() AND id=v.rule_id;
 IF NOT public.gc_quality_visible(coalesce(r.column_asset_id,r.table_asset_id),executor) THEN RETURN 'TARGET_UNAVAILABLE';END IF;
 IF NOT public.gc_quality_reference_owner_active(v.owner_id) THEN RETURN 'RULE_OWNER_UNAVAILABLE';END IF;
 IF v.definition->>'kind'='reference-allowed-values' AND NOT public.gc_reference_visible((v.definition#>>'{reference,setId}')::uuid,executor) THEN RETURN 'REFERENCE_UNAVAILABLE';END IF;
 IF r.current_version IS DISTINCT FROM v.version OR v.definition_hash IS DISTINCT FROM monitor_definition#>>'{rule,definitionHash}' THEN RETURN 'RULE_VERSION_CHANGED';END IF;
 BEGIN PERFORM public.gc_quality_monitor_inputs(monitor_definition,at_time);
 EXCEPTION WHEN feature_not_supported THEN IF v.definition->>'kind'='reference-allowed-values' AND SQLERRM='QUALITY_REFERENCE_UNAVAILABLE' THEN RETURN 'REFERENCE_UNAVAILABLE';ELSE RETURN 'TARGET_UNAVAILABLE';END IF;
 WHEN no_data_found THEN RETURN 'TARGET_UNAVAILABLE';WHEN serialization_failure THEN RETURN 'TARGET_UNAVAILABLE';WHEN insufficient_privilege THEN RETURN 'EXECUTOR_UNAVAILABLE';END;
 RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_issue_view(issue_identity uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT jsonb_build_object('id',i.id,'version',i.version,'monitorId',i.monitor_id,'comparisonScopeHash',i.comparison_scope_hash,
 'rule',jsonb_build_object('id',i.rule_id,'version',i.rule_version,'definitionHash',i.rule_hash),'category','data-quality','severity',i.severity,'tableAssetId',i.table_asset_id,'columnAssetId',i.column_asset_id,
 'status',i.status,'episode',i.episode,'assignedOwnerId',i.assigned_owner_id,'ownerAvailable',public.gc_quality_rule_visible(i.rule_id,i.rule_version,i.assigned_owner_id),
 'openedAt',public.gc_relation_utc(i.opened_at),'acknowledgeDueAt',public.gc_relation_utc(i.acknowledge_due_at),'resolveDueAt',public.gc_relation_utc(i.resolve_due_at),
 'opening',i.opening,'lastFailure',i.last_failure,'recovery',CASE WHEN public.gc_quality_monitor_recovery_current(i.id) THEN i.recovery ELSE NULL END,'resolution',i.resolution,'superseded',i.superseded)||CASE WHEN i.column_asset_id IS NULL THEN '{"targetKind":"table"}'::jsonb ELSE '{}'::jsonb END
 FROM public.quality_monitor_incidents i WHERE i.tenant_id=public.gc_tenant() AND i.id=issue_identity
$$;

CREATE OR REPLACE FUNCTION public.gc_quality_monitor_occurrence(monitor_identity uuid,definition_version integer,occurrence_identity uuid,origin text,first_at timestamptz,last_at timestamptz,slot_count integer,skip_reason text,inputs jsonb DEFAULT NULL,segment_identity integer DEFAULT NULL) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant();m public.quality_monitors;v public.quality_monitor_versions;run_identity uuid;scope jsonb;scope_hash text;binding jsonb;now_at timestamptz:=date_trunc('milliseconds',clock_timestamp());next_ordinal integer;BEGIN
 SELECT * INTO m FROM public.quality_monitors WHERE tenant_id=tenant AND id=monitor_identity;
 SELECT * INTO v FROM public.quality_monitor_versions WHERE tenant_id=tenant AND monitor_id=m.id AND version=definition_version;
 IF m.id IS NULL OR v.version IS NULL OR (skip_reason IS NULL)<>(inputs IS NOT NULL) OR m.last_admitted_ordinal=2147483647 THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 next_ordinal:=m.last_admitted_ordinal+1;
 IF inputs IS NOT NULL THEN
  run_identity:=gen_random_uuid();scope:=public.gc_quality_monitor_scope(m.id,v.definition,inputs);scope_hash:=public.gc_type_migration_hash(scope);
  INSERT INTO public.quality_runs(tenant_id,id,rule_id,rule_version,rule_hash,requester_id,source_id,schema_asset_id,table_asset_id,column_asset_id,inputs,input_hash,status,expires_at,created_at)
  VALUES(tenant,run_identity,v.rule_id,v.rule_version,v.rule_hash,m.executor_id,(inputs->>'sourceId')::uuid,(inputs->>'schemaAssetId')::uuid,(inputs->>'tableAssetId')::uuid,(inputs->>'columnAssetId')::uuid,
   inputs,public.gc_type_migration_hash(inputs),'queued',least(now_at+interval '10 minutes',(v.definition->>'authorizationExpiresAt')::timestamptz),now_at);
  binding:=inputs#>'{execution,reference}';
  IF binding IS NOT NULL THEN INSERT INTO public.quality_run_reference_bindings(tenant_id,run_id,set_id,release_version,publication_hash,as_of,code_status,binding_hash)
   VALUES(tenant,run_identity,(binding->>'setId')::uuid,(binding->>'version')::integer,binding->>'publicationHash',(binding->>'asOf')::timestamptz,'active',binding->>'bindingHash');END IF;
  PERFORM public.gc_approval_journal('quality.run_requested',NULL,coalesce(inputs->>'columnAssetId',inputs->>'tableAssetId'),1,jsonb_build_object('ruleId',v.rule_id,'runId',run_identity,'ruleVersion',v.rule_version,'inputHash',public.gc_type_migration_hash(inputs)),'monitor:'||occurrence_identity::text);
 END IF;
 INSERT INTO public.quality_monitor_occurrences(tenant_id,id,monitor_id,definition_version,definition_hash,ordinal,rule_id,rule_version,rule_hash,executor_id,origin,segment,first_slot_at,last_slot_at,slot_count,disposition,reason,run_id,comparison_scope,comparison_scope_hash,recorded_at)
 VALUES(tenant,occurrence_identity,m.id,v.version,v.definition_hash,next_ordinal,v.rule_id,v.rule_version,v.rule_hash,m.executor_id,origin,segment_identity,first_at,last_at,slot_count,CASE WHEN skip_reason IS NULL THEN 'enqueued' ELSE 'skipped' END,skip_reason,run_identity,scope,scope_hash,now_at);
 UPDATE public.quality_monitors SET last_admitted_ordinal=next_ordinal,current_observation=CASE WHEN run_identity IS NOT NULL THEN jsonb_build_object('state','pending','occurrenceId',occurrence_identity,'runId',run_identity)
 ELSE jsonb_build_object('state','unknown','reason',CASE WHEN skip_reason IN('RULE_VERSION_CHANGED','AUTHORIZATION_EXPIRED','EXECUTOR_UNAVAILABLE','RULE_OWNER_UNAVAILABLE','TARGET_UNAVAILABLE','REFERENCE_UNAVAILABLE') THEN 'BLOCKED' ELSE 'SKIPPED' END,'occurrenceId',occurrence_identity) END WHERE tenant_id=tenant AND id=m.id;
 PERFORM public.gc_approval_journal('quality.monitor_occurrence',NULL,m.id::text,next_ordinal,jsonb_build_object('occurrenceId',occurrence_identity,'definitionVersion',v.version,'definitionHash',v.definition_hash,'ordinal',next_ordinal,'disposition',CASE WHEN skip_reason IS NULL THEN 'enqueued' ELSE 'skipped' END,'reason',skip_reason,'runId',run_identity,'comparisonScopeHash',scope_hash),'monitor:'||m.id::text);
 RETURN occurrence_identity;
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_monitor_occurrence_seal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE v public.quality_monitor_versions;m public.quality_monitors;q public.quality_runs;s public.quality_monitor_schedule_segments;observed public.quality_monitor_occurrences;step_seconds integer;BEGIN
 SELECT * INTO observed FROM public.quality_monitor_occurrences WHERE tenant_id=NEW.tenant_id AND id=NEW.id;
 IF observed.id IS NULL THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 SELECT * INTO m FROM public.quality_monitors WHERE tenant_id=observed.tenant_id AND id=observed.monitor_id;
 SELECT * INTO v FROM public.quality_monitor_versions WHERE tenant_id=observed.tenant_id AND monitor_id=observed.monitor_id AND version=observed.definition_version;
 IF observed.definition_hash IS DISTINCT FROM v.definition_hash OR observed.rule_id<>v.rule_id OR observed.rule_version<>v.rule_version OR observed.rule_hash<>v.rule_hash OR observed.executor_id<>m.executor_id
 OR NOT public.gc_quality_monitor_journal_present('quality.monitor_occurrence',m.id::text,observed.ordinal,jsonb_build_object('occurrenceId',observed.id,'definitionVersion',v.version,'definitionHash',v.definition_hash,'ordinal',observed.ordinal,'disposition',observed.disposition,'reason',observed.reason,'runId',observed.run_id,'comparisonScopeHash',observed.comparison_scope_hash)) THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 IF observed.origin='schedule' THEN
  SELECT * INTO s FROM public.quality_monitor_schedule_segments WHERE tenant_id=observed.tenant_id AND monitor_id=observed.monitor_id AND segment=observed.segment;step_seconds:=(v.definition#>>'{schedule,intervalSeconds}')::integer;
  IF s.definition_version<>observed.definition_version OR observed.first_slot_at<s.created_at OR s.cutoff_at IS NOT NULL AND observed.last_slot_at>=s.cutoff_at
  OR observed.first_slot_at IS DISTINCT FROM public.gc_quality_monitor_first_slot(v.definition,observed.first_slot_at) OR observed.last_slot_at IS DISTINCT FROM observed.first_slot_at+(observed.slot_count-1)*make_interval(secs=>step_seconds)
  OR (v.definition#>>'{schedule,endsAt}')::timestamptz IS NOT NULL AND observed.last_slot_at>=(v.definition#>>'{schedule,endsAt}')::timestamptz
  OR observed.recorded_at<observed.last_slot_at OR observed.disposition='enqueued' AND observed.slot_count<>1 THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 END IF;
 IF observed.run_id IS NOT NULL THEN
  SELECT * INTO q FROM public.quality_runs WHERE tenant_id=observed.tenant_id AND id=observed.run_id;
  IF q.rule_id<>observed.rule_id OR q.rule_version<>observed.rule_version OR q.rule_hash<>observed.rule_hash OR q.requester_id<>observed.executor_id OR q.created_at<>observed.recorded_at
  OR q.expires_at>least(q.created_at+interval '10 minutes',(v.definition->>'authorizationExpiresAt')::timestamptz)
  OR observed.comparison_scope IS DISTINCT FROM public.gc_quality_monitor_scope(m.id,v.definition,q.inputs) OR observed.comparison_scope_hash IS DISTINCT FROM public.gc_type_migration_hash(observed.comparison_scope)
  OR NOT public.gc_quality_monitor_journal_present('quality.run_requested',coalesce(q.column_asset_id,q.table_asset_id)::text,1,jsonb_build_object('ruleId',q.rule_id,'runId',q.id,'ruleVersion',q.rule_version,'inputHash',q.input_hash)) THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 END IF;RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_volume_rule_seal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ BEGIN
 IF NEW.definition->>'kind' IS DISTINCT FROM 'volume' THEN RETURN NULL;END IF;
 IF NOT EXISTS(SELECT 1 FROM public.quality_rules r WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.rule_id AND r.column_asset_id IS NULL AND r.table_asset_id::text=NEW.definition#>>'{target,tableAssetId}')
 OR public.gc_quality_volume_definition_valid(NEW.definition) IS NOT TRUE
 OR NEW.definition_hash IS DISTINCT FROM public.gc_type_migration_hash(NEW.definition)
 OR NEW.owner_id::text IS DISTINCT FROM NEW.definition->>'ownerId'
 OR EXISTS(SELECT 1 FROM public.quality_rule_reference_bindings b WHERE b.tenant_id=NEW.tenant_id AND b.rule_id=NEW.rule_id AND b.rule_version=NEW.version)
 OR (SELECT count(*) FROM public.audit a JOIN public.outbox o ON o.tenant_id=a.tenant_id AND o.id=a.id
 WHERE a.tenant_id=NEW.tenant_id AND a.action='quality.rule_published' AND a.resource_id=NEW.definition#>>'{target,tableAssetId}'
 AND o.event_type=a.action AND o.resource_id=a.resource_id AND o.resource_version=NEW.version
 AND a.changes=jsonb_build_object('ruleId',NEW.rule_id,'definitionHash',NEW.definition_hash,'resourceVersion',NEW.version))<>1
 THEN RAISE EXCEPTION 'QUALITY_STORAGE_INVALID' USING ERRCODE='23514';END IF;RETURN NULL;
END $$;

CREATE CONSTRAINT TRIGGER quality_volume_rule_seal AFTER INSERT ON public.quality_rule_versions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_quality_volume_rule_seal();

CREATE OR REPLACE FUNCTION public.gc_quality_volume_run_seal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE v public.quality_rule_versions;journal_action text;expected text;expected_changes jsonb;BEGIN
 SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=NEW.tenant_id AND rule_id=NEW.rule_id AND version=NEW.rule_version;
 IF NEW.inputs#>>'{execution,kind}' IS DISTINCT FROM 'volume' AND v.definition->>'kind' IS DISTINCT FROM 'volume' THEN RETURN NULL;END IF;
 IF NEW.column_asset_id IS NOT NULL OR NOT EXISTS(SELECT 1 FROM public.quality_rules r WHERE r.tenant_id=NEW.tenant_id AND r.id=NEW.rule_id AND r.column_asset_id IS NULL AND r.table_asset_id=NEW.table_asset_id)
 OR public.gc_relation_keys(NEW.inputs,ARRAY['sourceId','sourceVersion','sourceConfigHash','source','schemaAssetId','schemaAssetVersion','tableAssetId','tableAssetVersion','columnAssetId','execution']) IS NOT TRUE
 OR NEW.inputs->'columnAssetId' IS DISTINCT FROM 'null'::jsonb OR NEW.inputs->>'sourceId' IS DISTINCT FROM NEW.source_id::text OR NEW.inputs->>'schemaAssetId' IS DISTINCT FROM NEW.schema_asset_id::text OR NEW.inputs->>'tableAssetId' IS DISTINCT FROM NEW.table_asset_id::text
 OR public.gc_relation_keys(NEW.inputs#>'{execution,target}',ARRAY['kind','databaseOid','schemaOid','relationOid','schemaName','tableName']) IS NOT TRUE OR NEW.inputs#>>'{execution,target,kind}' IS DISTINCT FROM 'table'
 OR v.definition->>'kind' IS DISTINCT FROM 'volume' OR NEW.inputs#>>'{execution,kind}' IS DISTINCT FROM 'volume'
 OR public.gc_quality_volume_definition_valid(v.definition) IS NOT TRUE OR NEW.rule_hash IS DISTINCT FROM v.definition_hash
 OR NEW.input_hash IS DISTINCT FROM public.gc_type_migration_hash(NEW.inputs)
 OR public.gc_relation_keys(NEW.inputs->'execution',ARRAY['formatVersion','kind','target','budget','volume']) IS NOT TRUE
 OR NEW.inputs#>'{execution,formatVersion}' IS DISTINCT FROM '1'::jsonb
 OR NEW.inputs#>'{execution,budget}' IS DISTINCT FROM '{"maximumRows":100000,"maximumSeconds":30,"statementTimeoutMs":15000,"maximumEstimatedCost":1000000,"maximumEstimatedBytes":67108864}'::jsonb
 OR NEW.inputs#>'{execution,volume}' IS DISTINCT FROM public.gc_quality_volume_binding(v.definition)
 OR v.definition->'target' IS DISTINCT FROM jsonb_build_object('kind','table','tableAssetId',NEW.table_asset_id)
 OR EXISTS(SELECT 1 FROM public.quality_run_reference_bindings b WHERE b.tenant_id=NEW.tenant_id AND b.run_id=NEW.id)
 THEN RAISE EXCEPTION 'QUALITY_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 IF NEW.status='succeeded' THEN
  IF public.gc_quality_volume_measurement_valid(NEW.measurement) IS NOT TRUE OR NEW.measurement->>'volumeHash' IS DISTINCT FROM NEW.inputs#>>'{execution,volume,volumeHash}' THEN RAISE EXCEPTION 'QUALITY_STORAGE_INVALID' USING ERRCODE='23514';END IF;
  expected:=public.gc_quality_volume_verdict(NEW.measurement,NEW.inputs#>'{execution,volume}');
  IF expected IS NULL THEN RAISE EXCEPTION 'QUALITY_STORAGE_INVALID' USING ERRCODE='23514';END IF;
  IF NEW.verdict IS DISTINCT FROM expected OR NEW.completion_hash IS NULL THEN RAISE EXCEPTION 'QUALITY_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 END IF;
 IF TG_OP='INSERT' THEN journal_action:='quality.run_requested';expected_changes:=jsonb_build_object('ruleId',NEW.rule_id,'runId',NEW.id,'ruleVersion',NEW.rule_version,'inputHash',NEW.input_hash,'resourceVersion',NEW.version);
 ELSIF NEW.status='running' THEN journal_action:='quality.run_claimed';expected_changes:=jsonb_build_object('ruleId',NEW.rule_id,'runId',NEW.id,'attempt',NEW.attempt,'resourceVersion',NEW.version);
 ELSIF NEW.error_code='QUALITY_CANCELLED' THEN
  journal_action:='quality.run_cancelled';
  SELECT a.changes INTO expected_changes FROM public.audit a WHERE a.tenant_id=NEW.tenant_id AND a.action=journal_action AND a.resource_id=NEW.table_asset_id::text
   AND a.changes->>'runId'=NEW.id::text AND a.changes->>'resourceVersion'=NEW.version::text LIMIT 1;
  IF public.gc_relation_keys(expected_changes,ARRAY['ruleId','runId','reason','resourceVersion']) IS NOT TRUE
   OR public.gc_approval_text(expected_changes->>'reason',4096,true) IS NULL OR expected_changes->>'reason' IS DISTINCT FROM public.gc_approval_text(expected_changes->>'reason',4096,true)
  THEN RAISE EXCEPTION 'QUALITY_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 ELSE journal_action:='quality.run_finished';
  expected_changes:=CASE WHEN NEW.completion_hash IS NULL THEN jsonb_build_object('ruleId',NEW.rule_id,'runId',NEW.id,'errorCode',NEW.error_code,'resourceVersion',NEW.version)
   ELSE jsonb_build_object('ruleId',NEW.rule_id,'runId',NEW.id,'ruleVersion',NEW.rule_version,'verdict',NEW.verdict,'errorCode',NEW.error_code,'resourceVersion',NEW.version) END;
 END IF;
 IF (SELECT count(*) FROM public.audit a JOIN public.outbox o ON o.tenant_id=a.tenant_id AND o.id=a.id
 WHERE a.tenant_id=NEW.tenant_id AND a.action=journal_action AND a.resource_id=NEW.table_asset_id::text AND o.event_type=a.action AND o.resource_id=a.resource_id AND o.resource_version=NEW.version
 AND a.changes->>'runId'=NEW.id::text AND a.changes->>'ruleId'=NEW.rule_id::text AND a.changes->>'resourceVersion'=NEW.version::text
 AND a.changes=expected_changes)<>1 THEN RAISE EXCEPTION 'QUALITY_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 RETURN NULL;
END $$;

CREATE CONSTRAINT TRIGGER quality_volume_run_seal AFTER INSERT OR UPDATE ON public.quality_runs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_quality_volume_run_seal();

CREATE FUNCTION public.gc_quality_target_seal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE r public.quality_rules;BEGIN
 SELECT * INTO r FROM public.quality_rules WHERE tenant_id=NEW.tenant_id AND id=NEW.rule_id;
 IF r.id IS NULL OR (NEW.definition->>'kind'='volume') IS DISTINCT FROM (r.table_asset_id IS NOT NULL)
 OR (r.table_asset_id IS NOT NULL AND NEW.definition->'target' IS DISTINCT FROM jsonb_build_object('kind','table','tableAssetId',r.table_asset_id))
 OR (r.column_asset_id IS NOT NULL AND NEW.definition#>>'{target,columnAssetId}' IS DISTINCT FROM r.column_asset_id::text) THEN RAISE EXCEPTION 'QUALITY_STORAGE_INVALID' USING ERRCODE='23514';END IF;RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER quality_target_seal AFTER INSERT ON public.quality_rule_versions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_quality_target_seal();
CREATE FUNCTION public.gc_quality_volume_issue_seal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE v public.quality_rule_versions;BEGIN
 SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=NEW.tenant_id AND rule_id=NEW.rule_id AND version=NEW.rule_version;
 IF v.version IS NULL OR (v.definition->>'kind'='volume') IS DISTINCT FROM (NEW.column_asset_id IS NULL)
 OR v.definition->'target' IS DISTINCT FROM (CASE WHEN v.definition->>'kind'='volume' THEN jsonb_build_object('kind','table','tableAssetId',NEW.table_asset_id) ELSE jsonb_build_object('tableAssetId',NEW.table_asset_id,'columnAssetId',NEW.column_asset_id) END)
 THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER quality_volume_issue_seal AFTER INSERT OR UPDATE ON public.quality_monitor_incidents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_quality_volume_issue_seal();

REVOKE ALL ON FUNCTION public.gc_quality_volume_settings_valid(jsonb),public.gc_quality_volume_definition_valid(jsonb),public.gc_quality_volume_binding(jsonb),public.gc_quality_volume_measurement_valid(jsonb),public.gc_quality_volume_verdict(jsonb,jsonb),public.gc_quality_table_visible(uuid,uuid),public.gc_quality_table_inputs(uuid,uuid),public.gc_quality_input_target(jsonb),public.gc_quality_volume_rule_seal(),public.gc_quality_volume_run_seal(),public.gc_quality_target_seal(),public.gc_quality_volume_issue_seal() FROM PUBLIC,gc_app;
