-- SPDX-License-Identifier: Apache-2.0
-- Exact inclusive signed-int64 range. Forward-only candidate; no source values are retained.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls)) OR pg_has_role('gc_app',current_user,'MEMBER') THEN
  RAISE EXCEPTION 'QUALITY_STORAGE_INVALID' USING ERRCODE='42501'; END IF;
END $$;

CREATE FUNCTION public.gc_quality_range_bounds_valid(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ DECLARE field text;number_value numeric;BEGIN
 IF public.gc_relation_keys(value,ARRAY['minimum','maximum','comparison','nullPolicy']) IS NOT TRUE
 OR value->>'comparison' IS DISTINCT FROM 'int64-inclusive' OR value->>'nullPolicy' IS DISTINCT FROM 'exclude' THEN RETURN false;END IF;
 FOREACH field IN ARRAY ARRAY['minimum','maximum'] LOOP
  IF jsonb_typeof(value->field) IS DISTINCT FROM 'string' OR length(value->>field)>20 OR value->>field !~ '^(0|-?[1-9][0-9]*)$' THEN RETURN false;END IF;
  number_value:=(value->>field)::numeric;IF number_value< -9223372036854775808::numeric OR number_value>9223372036854775807::numeric THEN RETURN false;END IF;
 END LOOP;
 RETURN (value->>'minimum')::numeric<=(value->>'maximum')::numeric;
 EXCEPTION WHEN numeric_value_out_of_range OR invalid_text_representation THEN RETURN false;
END $$;

CREATE FUNCTION public.gc_quality_range_definition_valid(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ BEGIN
 IF public.gc_relation_keys(value,ARRAY['formatVersion','kind','target','name','purpose','ownerId','severity','maximumOutOfRangeBasisPoints','minimum','maximum','comparison','nullPolicy']) IS NOT TRUE
 OR value->>'kind' IS DISTINCT FROM 'range'
 OR public.gc_quality_range_bounds_valid(jsonb_build_object('minimum',value->'minimum','maximum',value->'maximum','comparison',value->'comparison','nullPolicy',value->'nullPolicy')) IS NOT TRUE THEN RETURN false;END IF;
 RETURN public.gc_quality_completeness_definition_valid((value-ARRAY['maximumOutOfRangeBasisPoints','minimum','maximum','comparison','nullPolicy'])||jsonb_build_object('kind','completeness','maximumNullBasisPoints',value->'maximumOutOfRangeBasisPoints'))
 AND octet_length(value::text)<=16384;
END $$;

CREATE FUNCTION public.gc_quality_range_binding(definition jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ DECLARE bounds jsonb;BEGIN
 IF public.gc_quality_range_definition_valid(definition) IS NOT TRUE THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;
 bounds:=jsonb_build_object('minimum',definition->'minimum','maximum',definition->'maximum','comparison','int64-inclusive','nullPolicy','exclude');
 RETURN bounds||jsonb_build_object('rangeHash',public.gc_type_migration_hash(bounds||jsonb_build_object('formatVersion',1,'kind','range')));
END $$;

CREATE FUNCTION public.gc_quality_range_measurement_valid(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ DECLARE field text;BEGIN
 IF public.gc_relation_keys(value,ARRAY['formatVersion','kind','strategy','rowCount','nullCount','belowCount','aboveCount','rangeHash','observedStartedAt','observedFinishedAt','elapsedMs','sourceVersion','adapterVersion','queryTemplate','estimatedCost','estimatedBytes']) IS NOT TRUE
 OR value->>'kind' IS DISTINCT FROM 'range' OR value->>'queryTemplate' IS DISTINCT FROM 'postgresql-range-v1'
 OR jsonb_typeof(value->'rangeHash') IS DISTINCT FROM 'string' OR value->>'rangeHash' !~ '^[a-f0-9]{64}$' THEN RETURN false;END IF;
 IF public.gc_quality_completeness_measurement_valid((value-ARRAY['belowCount','aboveCount','rangeHash'])||jsonb_build_object('kind','completeness','queryTemplate','postgresql-completeness-v1')) IS NOT TRUE THEN RETURN false;END IF;
 FOREACH field IN ARRAY ARRAY['belowCount','aboveCount'] LOOP
  IF jsonb_typeof(value->field) IS DISTINCT FROM 'number' OR value->>field !~ '^(0|[1-9][0-9]{0,5})$' THEN RETURN false;END IF;
 END LOOP;
 RETURN (value->>'belowCount')::bigint+(value->>'aboveCount')::bigint<=(value->>'rowCount')::bigint-(value->>'nullCount')::bigint;
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_definition_valid(value jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ BEGIN
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

CREATE OR REPLACE FUNCTION public.gc_quality_rule_visible(rule_identity uuid,selected_version integer,actor_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM public.quality_rule_versions v JOIN public.quality_rules r ON r.tenant_id=v.tenant_id AND r.id=v.rule_id
 WHERE v.tenant_id=public.gc_tenant() AND v.rule_id=rule_identity AND v.version=selected_version
 AND public.gc_quality_visible(r.column_asset_id,actor_identity)
 AND (v.definition->>'kind' IN ('completeness','uniqueness','range') OR (v.definition->>'kind'='reference-allowed-values' AND EXISTS(
 SELECT 1 FROM public.quality_rule_reference_bindings b WHERE b.tenant_id=v.tenant_id AND b.rule_id=v.rule_id AND b.rule_version=v.version
 AND b.set_id::text=v.definition#>>'{reference,setId}' AND public.gc_reference_visible(b.set_id,actor_identity)))))
$$;

CREATE OR REPLACE FUNCTION public.gc_quality_run_visible(run_identity uuid,actor_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM public.quality_runs q WHERE q.tenant_id=public.gc_tenant() AND q.id=run_identity
 AND public.gc_quality_rule_visible(q.rule_id,q.rule_version,actor_identity)
 AND (q.inputs#>>'{execution,kind}' IN ('completeness','uniqueness','range') OR EXISTS(SELECT 1 FROM public.quality_run_reference_bindings b
 WHERE b.tenant_id=q.tenant_id AND b.run_id=q.id AND public.gc_reference_visible(b.set_id,actor_identity))))
$$;

CREATE OR REPLACE FUNCTION public.gc_quality_run_view(run_identity uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT jsonb_build_object('id',r.id,'ruleId',r.rule_id,'ruleVersion',r.rule_version,'ruleHash',r.rule_hash,'requesterId',r.requester_id,'columnAssetId',r.column_asset_id,'tableAssetId',r.table_asset_id,
  'status',r.status,'version',r.version,'attempt',r.attempt,'createdAt',public.gc_relation_utc(r.created_at),'startedAt',public.gc_relation_utc(r.started_at),'finishedAt',public.gc_relation_utc(r.finished_at),
  'expiresAt',public.gc_relation_utc(r.expires_at),'measurement',r.measurement,'verdict',r.verdict,'errorCode',r.error_code) || CASE WHEN r.inputs#>>'{execution,kind}'='reference-allowed-values' THEN jsonb_build_object('kind','reference-allowed-values','reference',(r.inputs#>'{execution,reference}')-'codes') WHEN r.inputs#>>'{execution,kind}'='uniqueness' THEN jsonb_build_object('kind','uniqueness') WHEN r.inputs#>>'{execution,kind}'='range' THEN jsonb_build_object('kind','range','range',r.inputs#>'{execution,range}') ELSE '{}'::jsonb END
 FROM public.quality_runs r WHERE r.tenant_id=public.gc_tenant() AND r.id=run_identity;
$$;

CREATE OR REPLACE FUNCTION public.gc_quality_run_lock(run_identity uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE r public.quality_runs;v public.quality_rule_versions;BEGIN
 SELECT * INTO r FROM public.quality_runs WHERE tenant_id=public.gc_tenant() AND id=run_identity;
 SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=r.tenant_id AND rule_id=r.rule_id AND version=r.rule_version;
 IF v.definition->>'kind'='reference-allowed-values' THEN PERFORM public.gc_quality_reference_lock(r.column_asset_id,r.requester_id,v.owner_id,(v.definition#>>'{reference,setId}')::uuid);
 ELSIF v.definition->>'kind' IN ('uniqueness','range') THEN PERFORM public.gc_quality_lock(r.column_asset_id,r.requester_id,v.owner_id);
 ELSE PERFORM public.gc_quality_lock(r.column_asset_id,r.requester_id);END IF;
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_run_can_execute(run_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT coalesce((SELECT public.gc_quality_can_execute(r.column_asset_id,r.requester_id) AND
 (r.inputs#>>'{execution,kind}'='completeness' OR (r.inputs#>>'{execution,kind}' IN ('uniqueness','range') AND public.gc_quality_run_visible(r.id,r.requester_id) AND EXISTS(SELECT 1 FROM public.quality_rule_versions v WHERE v.tenant_id=r.tenant_id AND v.rule_id=r.rule_id AND v.version=r.rule_version AND public.gc_quality_reference_owner_active(v.owner_id))) OR (r.inputs#>>'{execution,kind}'='reference-allowed-values' AND public.gc_quality_reference_run_current(r.id)))
 FROM public.quality_runs r WHERE r.tenant_id=public.gc_tenant() AND r.id=run_identity),false)
$$;

CREATE OR REPLACE FUNCTION public.gc_quality_refresh_inputs(run_identity uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE r public.quality_runs;v public.quality_rule_versions;result jsonb;BEGIN
 SELECT * INTO r FROM public.quality_runs WHERE tenant_id=public.gc_tenant() AND id=run_identity;
 result:=public.gc_quality_inputs(r.column_asset_id,r.requester_id);
 IF r.inputs#>>'{execution,kind}'='reference-allowed-values' THEN
  result:=jsonb_set(result,'{execution}',(result->'execution')||jsonb_build_object('kind','reference-allowed-values','reference',r.inputs#>'{execution,reference}'));
 ELSIF r.inputs#>>'{execution,kind}'='uniqueness' THEN
  result:=jsonb_set(result,'{execution}',(result->'execution')||jsonb_build_object('kind','uniqueness','budget',(result#>'{execution,budget}')||jsonb_build_object('maximumValueBytes',4096,'maximumTotalValueBytes',67108864)));
 ELSIF r.inputs#>>'{execution,kind}'='range' THEN
  SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=r.tenant_id AND rule_id=r.rule_id AND version=r.rule_version;
  result:=jsonb_set(result,'{execution}',(result->'execution')||jsonb_build_object('kind','range','range',public.gc_quality_range_binding(v.definition)));
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
  column_identity:=CASE WHEN operation='quality.rule.publish' THEN (old.response->'rule'->'definition'->'target'->>'columnAssetId')::uuid ELSE (old.response->'run'->>'columnAssetId')::uuid END;
  IF operation='quality.rule.publish' THEN
   SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=tenant AND rule_id=(old.response#>>'{rule,id}')::uuid AND version=(old.response#>>'{rule,version}')::integer;
   IF v.definition->>'kind'='reference-allowed-values' THEN PERFORM public.gc_quality_reference_lock(column_identity,actor,v.owner_id,(v.definition#>>'{reference,setId}')::uuid);
   ELSIF v.definition->>'kind' IN ('uniqueness','range') THEN PERFORM public.gc_quality_lock(column_identity,actor,v.owner_id);
   ELSE PERFORM public.gc_quality_lock(column_identity,actor);END IF;
   IF NOT public.gc_quality_rule_visible(v.rule_id,v.version,actor) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  ELSE
   SELECT * INTO r FROM public.quality_runs WHERE tenant_id=tenant AND id=(old.response#>>'{run,id}')::uuid;
   SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=tenant AND rule_id=r.rule_id AND version=r.rule_version;
   IF v.definition->>'kind'='reference-allowed-values' THEN PERFORM public.gc_quality_reference_lock(column_identity,actor,v.owner_id,(v.definition#>>'{reference,setId}')::uuid);
   ELSIF v.definition->>'kind' IN ('uniqueness','range') THEN PERFORM public.gc_quality_lock(column_identity,actor,v.owner_id);
   ELSE PERFORM public.gc_quality_lock(column_identity,actor);END IF;
   IF NOT public.gc_quality_run_visible(r.id,actor) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  END IF;
  PERFORM public.gc_relation_authorize(actions);RETURN old.response;
 END IF;
 IF operation='quality.rule.publish' THEN
  IF public.gc_relation_keys(body,ARRAY['id','expectedVersion','definition']) IS NOT TRUE OR NOT public.gc_approval_uuid(body->>'id')
  OR public.gc_quality_definition_valid(body->'definition') IS NOT TRUE OR jsonb_typeof(body->'expectedVersion') IS DISTINCT FROM 'number'
  OR body->>'expectedVersion' !~ '^(0|[1-9][0-9]{0,9})$' OR (body->>'expectedVersion')::bigint>=2147483647 THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;
  identity:=(body->>'id')::uuid;definition:=body->'definition';expected:=(body->>'expectedVersion')::integer;column_identity:=(definition->'target'->>'columnAssetId')::uuid;
  -- Existing rule identity is authorized before caller-supplied replacement
  -- targets, version diagnostics or owner checks can reveal its existence.
  SELECT * INTO rule FROM public.quality_rules WHERE tenant_id=tenant AND id=identity;
  IF (expected>0 AND rule.id IS NULL) OR (rule.id IS NOT NULL AND NOT public.gc_quality_rule_visible(rule.id,rule.current_version,actor)) THEN
   RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  PERFORM public.gc_quality_lock(column_identity,actor,(definition->>'ownerId')::uuid);PERFORM public.gc_relation_authorize(actions);
  IF rule.id IS NOT NULL AND NOT public.gc_quality_rule_visible(rule.id,rule.current_version,actor) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  IF rule.id IS NOT NULL AND rule.column_asset_id<>column_identity THEN RAISE EXCEPTION 'QUALITY_TARGET_IMMUTABLE' USING ERRCODE='40001';END IF;
  IF definition->>'kind'='reference-allowed-values' THEN
   PERFORM 1 FROM public.reference_sets WHERE tenant_id=tenant AND id=(definition#>>'{reference,setId}')::uuid FOR SHARE;
   IF NOT public.gc_reference_visible((definition#>>'{reference,setId}')::uuid,actor) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  END IF;
  inputs:=public.gc_quality_inputs(column_identity,actor);
  IF inputs->'tableAssetId' IS DISTINCT FROM definition->'target'->'tableAssetId' THEN RAISE EXCEPTION 'QUALITY_TARGET_STALE' USING ERRCODE='40001';END IF;
  IF NOT EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id WHERE m.tenant_id=tenant AND m.identity_id=(definition->>'ownerId')::uuid AND m.active AND i.active) THEN
   RAISE EXCEPTION 'QUALITY_OWNER_UNAVAILABLE' USING ERRCODE='42501';END IF;
  IF (expected=0 AND rule.id IS NOT NULL) OR (expected>0 AND (rule.id IS NULL OR rule.current_version<>expected OR rule.column_asset_id<>column_identity)) THEN
   RAISE EXCEPTION 'VERSION_CONFLICT' USING ERRCODE='40001';END IF;
  IF expected>0 THEN
   SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=tenant AND rule_id=identity AND version=expected;
   IF v.definition->'target' IS DISTINCT FROM definition->'target' THEN RAISE EXCEPTION 'QUALITY_TARGET_IMMUTABLE' USING ERRCODE='40001';END IF;
  END IF;
  now_at:=clock_timestamp();
  IF expected=0 THEN INSERT INTO public.quality_rules VALUES(tenant,identity,column_identity,1,actor,now_at);
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
  IF rule.id IS NULL OR NOT public.gc_quality_visible(rule.column_asset_id,actor) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  column_identity:=rule.column_asset_id;
  SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=tenant AND rule_id=rule.id AND version=(body->>'ruleVersion')::integer;
  IF v.version IS NULL OR NOT public.gc_quality_rule_visible(rule.id,v.version,actor) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  IF v.definition->>'kind'='reference-allowed-values' THEN PERFORM public.gc_quality_reference_lock(column_identity,actor,v.owner_id,(v.definition#>>'{reference,setId}')::uuid);
  ELSIF v.definition->>'kind' IN ('uniqueness','range') THEN PERFORM public.gc_quality_lock(column_identity,actor,v.owner_id);
   ELSE PERFORM public.gc_quality_lock(column_identity,actor);END IF;
  PERFORM public.gc_relation_authorize(actions);
  IF NOT public.gc_quality_rule_visible(rule.id,v.version,actor) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  IF v.version IS NULL OR rule.current_version<>v.version OR v.definition_hash IS DISTINCT FROM body->>'ruleHash' THEN RAISE EXCEPTION 'VERSION_CONFLICT' USING ERRCODE='40001';END IF;
  inputs:=public.gc_quality_inputs(column_identity,actor);
  IF v.definition->'target' IS DISTINCT FROM jsonb_build_object('tableAssetId',inputs->'tableAssetId','columnAssetId',inputs->'columnAssetId') THEN RAISE EXCEPTION 'QUALITY_TARGET_STALE' USING ERRCODE='40001';END IF;
  identity:=(body->>'id')::uuid;now_at:=clock_timestamp();
  IF v.definition->>'kind'='reference-allowed-values' THEN
   IF NOT public.gc_quality_reference_owner_active(v.owner_id) THEN RAISE EXCEPTION 'QUALITY_OWNER_UNAVAILABLE' USING ERRCODE='42501';END IF;
   IF body ? 'referenceAsOf' AND NOT public.gc_reference_instant(body->'referenceAsOf') THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;
   as_of_time:=CASE WHEN body ? 'referenceAsOf' THEN (body->>'referenceAsOf')::timestamptz ELSE date_trunc('milliseconds',now_at) END;
   IF as_of_time>now_at THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;
   binding:=public.gc_quality_reference_binding((v.definition#>>'{reference,setId}')::uuid,actor,as_of_time);
   inputs:=jsonb_set(inputs,'{execution}',(inputs->'execution')||jsonb_build_object('kind','reference-allowed-values','reference',binding));
  ELSIF body ? 'referenceAsOf' THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';
  ELSIF v.definition->>'kind'='range' THEN
   IF NOT public.gc_quality_reference_owner_active(v.owner_id) THEN RAISE EXCEPTION 'QUALITY_OWNER_UNAVAILABLE' USING ERRCODE='42501';END IF;
   inputs:=jsonb_set(inputs,'{execution}',(inputs->'execution')||jsonb_build_object('kind','range','range',public.gc_quality_range_binding(v.definition)));
  ELSIF v.definition->>'kind'='uniqueness' THEN
   IF NOT public.gc_quality_reference_owner_active(v.owner_id) THEN RAISE EXCEPTION 'QUALITY_OWNER_UNAVAILABLE' USING ERRCODE='42501';END IF;
   inputs:=jsonb_set(inputs,'{execution}',(inputs->'execution')||jsonb_build_object('kind','uniqueness','budget',(inputs#>'{execution,budget}')||jsonb_build_object('maximumValueBytes',4096,'maximumTotalValueBytes',67108864)));
  END IF;
  INSERT INTO public.quality_runs(tenant_id,id,rule_id,rule_version,rule_hash,requester_id,source_id,schema_asset_id,table_asset_id,column_asset_id,inputs,input_hash,status,expires_at,created_at)
  VALUES(tenant,identity,rule.id,v.version,v.definition_hash,actor,(inputs->>'sourceId')::uuid,(inputs->>'schemaAssetId')::uuid,(inputs->>'tableAssetId')::uuid,column_identity,
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
  column_identity:=r.column_asset_id;
  SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=tenant AND rule_id=r.rule_id AND version=r.rule_version;
  IF v.definition->>'kind'='reference-allowed-values' THEN PERFORM public.gc_quality_reference_lock(column_identity,actor,v.owner_id,(v.definition#>>'{reference,setId}')::uuid);
  ELSIF v.definition->>'kind' IN ('uniqueness','range') THEN PERFORM public.gc_quality_lock(column_identity,actor,v.owner_id);
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
 IF r.inputs#>>'{execution,kind}' IN ('reference-allowed-values','uniqueness','range') AND r.status IN ('succeeded','failed','cancelled') THEN PERFORM public.gc_quality_run_lock(r.id);IF NOT public.gc_quality_run_can_execute(r.id) THEN RAISE EXCEPTION 'QUALITY_AUTHORITY_REVOKED' USING ERRCODE='42501';END IF;END IF;
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
  PERFORM public.gc_approval_journal('quality.run_claimed',NULL,r.column_asset_id::text,r.version,jsonb_build_object('ruleId',r.rule_id,'runId',r.id,'attempt',r.attempt),'quality:'||r.id::text);
 END IF;
 RETURN jsonb_build_object('status','claimed','runId',r.id,'claimId',r.claim_id,'attempt',r.attempt,'leaseExpiresAt',public.gc_relation_utc(r.lease_expires_at),'source',r.inputs->'source','execution',r.inputs->'execution');
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
  IF jsonb_typeof(body->'errorCode') IS DISTINCT FROM 'string' OR body->>'errorCode' NOT IN ('QUALITY_RESOURCE_LIMIT','QUALITY_TARGET_STALE','QUALITY_TARGET_UNSUPPORTED','QUALITY_SOURCE_FAILED','QUALITY_DEADLINE_EXCEEDED') THEN
   RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;error:=body->>'errorCode';
 END IF;
 hash:=public.gc_type_migration_hash(body);PERFORM pg_advisory_xact_lock(hashtextextended(public.gc_tenant()::text,0));
 SELECT * INTO r FROM public.quality_runs WHERE tenant_id=public.gc_tenant() AND id=run_identity;
 IF r.id IS NULL THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
 PERFORM public.gc_quality_run_lock(r.id);now_at:=clock_timestamp();
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
 PERFORM public.gc_approval_journal('quality.run_finished',NULL,r.column_asset_id::text,r.version+1,jsonb_build_object('ruleId',r.rule_id,'runId',r.id,'ruleVersion',r.rule_version,'verdict',outcome,'errorCode',error),'quality:'||r.id::text);
 RETURN jsonb_build_object('run',public.gc_quality_run_view(r.id));
END $$;

-- These deferred checks add range-only consistency without changing the
-- existing completeness, uniqueness or reference seals, grants, tables or stored bytes.
CREATE FUNCTION public.gc_quality_range_rule_seal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ BEGIN
 IF NEW.definition->>'kind' IS DISTINCT FROM 'range' THEN RETURN NULL;END IF;
 IF public.gc_quality_range_definition_valid(NEW.definition) IS NOT TRUE
 OR NEW.definition_hash IS DISTINCT FROM public.gc_type_migration_hash(NEW.definition)
 OR NEW.owner_id::text IS DISTINCT FROM NEW.definition->>'ownerId'
 OR EXISTS(SELECT 1 FROM public.quality_rule_reference_bindings b WHERE b.tenant_id=NEW.tenant_id AND b.rule_id=NEW.rule_id AND b.rule_version=NEW.version)
 OR (SELECT count(*) FROM public.audit a JOIN public.outbox o ON o.tenant_id=a.tenant_id AND o.id=a.id
 WHERE a.tenant_id=NEW.tenant_id AND a.action='quality.rule_published' AND a.resource_id=NEW.definition#>>'{target,columnAssetId}'
 AND o.event_type=a.action AND o.resource_id=a.resource_id AND o.resource_version=NEW.version
 AND a.changes=jsonb_build_object('ruleId',NEW.rule_id,'definitionHash',NEW.definition_hash,'resourceVersion',NEW.version))<>1
 THEN RAISE EXCEPTION 'QUALITY_STORAGE_INVALID' USING ERRCODE='23514';END IF;RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER quality_range_rule_seal AFTER INSERT ON public.quality_rule_versions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_quality_range_rule_seal();

CREATE FUNCTION public.gc_quality_range_run_seal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE v public.quality_rule_versions;journal_action text;expected text;expected_changes jsonb;BEGIN
 SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=NEW.tenant_id AND rule_id=NEW.rule_id AND version=NEW.rule_version;
 IF NEW.inputs#>>'{execution,kind}' IS DISTINCT FROM 'range' AND v.definition->>'kind' IS DISTINCT FROM 'range' THEN RETURN NULL;END IF;
 IF v.definition->>'kind' IS DISTINCT FROM 'range' OR NEW.inputs#>>'{execution,kind}' IS DISTINCT FROM 'range'
 OR public.gc_quality_range_definition_valid(v.definition) IS NOT TRUE OR NEW.rule_hash IS DISTINCT FROM v.definition_hash
 OR NEW.input_hash IS DISTINCT FROM public.gc_type_migration_hash(NEW.inputs)
 OR public.gc_relation_keys(NEW.inputs->'execution',ARRAY['formatVersion','kind','target','budget','range']) IS NOT TRUE
 OR NEW.inputs#>'{execution,formatVersion}' IS DISTINCT FROM '1'::jsonb
 OR NEW.inputs#>'{execution,budget}' IS DISTINCT FROM '{"maximumRows":100000,"maximumSeconds":30,"statementTimeoutMs":15000,"maximumEstimatedCost":1000000,"maximumEstimatedBytes":67108864}'::jsonb
 OR NEW.inputs#>'{execution,range}' IS DISTINCT FROM public.gc_quality_range_binding(v.definition)
 OR v.definition->'target' IS DISTINCT FROM jsonb_build_object('tableAssetId',NEW.table_asset_id,'columnAssetId',NEW.column_asset_id)
 OR EXISTS(SELECT 1 FROM public.quality_run_reference_bindings b WHERE b.tenant_id=NEW.tenant_id AND b.run_id=NEW.id)
 THEN RAISE EXCEPTION 'QUALITY_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 IF NEW.status='succeeded' THEN
  IF public.gc_quality_range_measurement_valid(NEW.measurement) IS NOT TRUE OR NEW.measurement->>'rangeHash' IS DISTINCT FROM NEW.inputs#>>'{execution,range,rangeHash}' THEN RAISE EXCEPTION 'QUALITY_STORAGE_INVALID' USING ERRCODE='23514';END IF;
  expected:=CASE WHEN (NEW.measurement->>'rowCount')::bigint-(NEW.measurement->>'nullCount')::bigint=0 THEN 'NO_DATA'
   WHEN ((NEW.measurement->>'belowCount')::bigint+(NEW.measurement->>'aboveCount')::bigint)*10000<=((NEW.measurement->>'rowCount')::bigint-(NEW.measurement->>'nullCount')::bigint)*(v.definition->>'maximumOutOfRangeBasisPoints')::bigint THEN 'PASS' ELSE 'FAIL' END;
  IF NEW.verdict IS DISTINCT FROM expected OR NEW.completion_hash IS NULL THEN RAISE EXCEPTION 'QUALITY_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 END IF;
 IF TG_OP='INSERT' THEN journal_action:='quality.run_requested';expected_changes:=jsonb_build_object('ruleId',NEW.rule_id,'runId',NEW.id,'ruleVersion',NEW.rule_version,'inputHash',NEW.input_hash,'resourceVersion',NEW.version);
 ELSIF NEW.status='running' THEN journal_action:='quality.run_claimed';expected_changes:=jsonb_build_object('ruleId',NEW.rule_id,'runId',NEW.id,'attempt',NEW.attempt,'resourceVersion',NEW.version);
 ELSIF NEW.error_code='QUALITY_CANCELLED' THEN
  journal_action:='quality.run_cancelled';
  SELECT a.changes INTO expected_changes FROM public.audit a WHERE a.tenant_id=NEW.tenant_id AND a.action=journal_action AND a.resource_id=NEW.column_asset_id::text
   AND a.changes->>'runId'=NEW.id::text AND a.changes->>'resourceVersion'=NEW.version::text LIMIT 1;
  IF public.gc_relation_keys(expected_changes,ARRAY['ruleId','runId','reason','resourceVersion']) IS NOT TRUE
   OR public.gc_approval_text(expected_changes->>'reason',4096,true) IS NULL OR expected_changes->>'reason' IS DISTINCT FROM public.gc_approval_text(expected_changes->>'reason',4096,true)
  THEN RAISE EXCEPTION 'QUALITY_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 ELSE journal_action:='quality.run_finished';
  expected_changes:=CASE WHEN NEW.completion_hash IS NULL THEN jsonb_build_object('ruleId',NEW.rule_id,'runId',NEW.id,'errorCode',NEW.error_code,'resourceVersion',NEW.version)
   ELSE jsonb_build_object('ruleId',NEW.rule_id,'runId',NEW.id,'ruleVersion',NEW.rule_version,'verdict',NEW.verdict,'errorCode',NEW.error_code,'resourceVersion',NEW.version) END;
 END IF;
 IF (SELECT count(*) FROM public.audit a JOIN public.outbox o ON o.tenant_id=a.tenant_id AND o.id=a.id
 WHERE a.tenant_id=NEW.tenant_id AND a.action=journal_action AND a.resource_id=NEW.column_asset_id::text AND o.event_type=a.action AND o.resource_id=a.resource_id AND o.resource_version=NEW.version
 AND a.changes->>'runId'=NEW.id::text AND a.changes->>'ruleId'=NEW.rule_id::text AND a.changes->>'resourceVersion'=NEW.version::text
 AND a.changes=expected_changes)<>1 THEN RAISE EXCEPTION 'QUALITY_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER quality_range_run_seal AFTER INSERT OR UPDATE ON public.quality_runs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_quality_range_run_seal();
REVOKE ALL ON FUNCTION public.gc_quality_range_bounds_valid(jsonb),public.gc_quality_range_binding(jsonb),public.gc_quality_range_definition_valid(jsonb),public.gc_quality_range_measurement_valid(jsonb),public.gc_quality_range_rule_seal(),public.gc_quality_range_run_seal() FROM PUBLIC,gc_app;
