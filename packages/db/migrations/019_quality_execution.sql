-- SPDX-License-Identifier: Apache-2.0
-- Initial aggregate-only PostgreSQL completeness family. No source writes.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls)) OR pg_has_role('gc_app',current_user,'MEMBER') THEN
  RAISE EXCEPTION 'QUALITY_STORAGE_INVALID' USING ERRCODE='42501'; END IF;
END $$;
CREATE TABLE public.quality_rules (
 tenant_id uuid NOT NULL REFERENCES public.tenants(id),id uuid NOT NULL,column_asset_id uuid NOT NULL,current_version integer NOT NULL CHECK(current_version>0),
 created_by uuid NOT NULL,created_at timestamptz NOT NULL,PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,column_asset_id) REFERENCES public.assets(tenant_id,id),FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id)
);
CREATE TABLE public.quality_rule_versions (
 tenant_id uuid NOT NULL,rule_id uuid NOT NULL,version integer NOT NULL CHECK(version>0),definition jsonb NOT NULL CHECK(octet_length(definition::text)<=16384),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[a-f0-9]{64}$'),owner_id uuid NOT NULL,created_by uuid NOT NULL,created_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,rule_id,version),UNIQUE(tenant_id,rule_id,version,definition_hash),FOREIGN KEY(tenant_id,rule_id) REFERENCES public.quality_rules(tenant_id,id),
 FOREIGN KEY(tenant_id,owner_id) REFERENCES public.memberships(tenant_id,identity_id),FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id)
);
ALTER TABLE public.quality_rules ADD CONSTRAINT quality_current_version FOREIGN KEY(tenant_id,id,current_version)
 REFERENCES public.quality_rule_versions(tenant_id,rule_id,version) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE public.quality_runs (
 tenant_id uuid NOT NULL,id uuid NOT NULL,rule_id uuid NOT NULL,rule_version integer NOT NULL,rule_hash text NOT NULL,requester_id uuid NOT NULL,
 source_id uuid NOT NULL,schema_asset_id uuid NOT NULL,table_asset_id uuid NOT NULL,column_asset_id uuid NOT NULL,
 inputs jsonb NOT NULL CHECK(octet_length(inputs::text)<=16384),input_hash text NOT NULL CHECK(input_hash ~ '^[a-f0-9]{64}$'),
 status text NOT NULL CHECK(status IN ('queued','running','succeeded','failed','cancelled')),version integer NOT NULL DEFAULT 1 CHECK(version>0),
 attempt integer NOT NULL DEFAULT 0 CHECK(attempt BETWEEN 0 AND 3),claim_id uuid,claimed_at timestamptz,lease_expires_at timestamptz,expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL,started_at timestamptz,finished_at timestamptz,measurement jsonb,verdict text CHECK(verdict IN ('PASS','FAIL','NO_DATA')),
 error_code text CHECK(error_code IN ('QUALITY_RESOURCE_LIMIT','QUALITY_TARGET_STALE','QUALITY_TARGET_UNSUPPORTED','QUALITY_SOURCE_FAILED','QUALITY_DEADLINE_EXCEEDED','QUALITY_AUTHORITY_REVOKED','QUALITY_ATTEMPTS_EXHAUSTED','QUALITY_CANCELLED')),
 completion_hash text CHECK(completion_hash ~ '^[a-f0-9]{64}$'),PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,rule_id,rule_version,rule_hash) REFERENCES public.quality_rule_versions(tenant_id,rule_id,version,definition_hash),
 FOREIGN KEY(tenant_id,requester_id) REFERENCES public.memberships(tenant_id,identity_id),FOREIGN KEY(tenant_id,source_id) REFERENCES public.sources(tenant_id,id),
 FOREIGN KEY(tenant_id,schema_asset_id) REFERENCES public.assets(tenant_id,id),FOREIGN KEY(tenant_id,table_asset_id) REFERENCES public.assets(tenant_id,id),
 FOREIGN KEY(tenant_id,column_asset_id) REFERENCES public.assets(tenant_id,id),CHECK(expires_at>created_at),
 CHECK((claim_id IS NULL)=(lease_expires_at IS NULL)),CHECK((claim_id IS NULL)=(claimed_at IS NULL)),CHECK((status IN ('queued','running'))=(finished_at IS NULL)),
 CHECK((status='succeeded')=(measurement IS NOT NULL)),CHECK((status='succeeded')=(verdict IS NOT NULL)),CHECK(measurement IS NULL OR octet_length(measurement::text)<=16384),
 CHECK((status IN ('failed','cancelled'))=(error_code IS NOT NULL))
);
CREATE INDEX quality_pending ON public.quality_runs(tenant_id,status,created_at,id);
CREATE INDEX quality_rules_asset ON public.quality_rules(tenant_id,column_asset_id,id);
CREATE INDEX quality_runs_rule ON public.quality_runs(tenant_id,rule_id,id);
DO $$ DECLARE name text;BEGIN
 FOREACH name IN ARRAY ARRAY['quality_rules','quality_rule_versions','quality_runs'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',name);EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.gc_tenant()) WITH CHECK(tenant_id=public.gc_tenant())',name);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC,gc_app',name);EXECUTE format('GRANT SELECT ON public.%I TO gc_app',name);
 END LOOP;
END $$;
CREATE TRIGGER quality_versions_immutable BEFORE UPDATE OR DELETE ON public.quality_rule_versions FOR EACH ROW EXECUTE FUNCTION public.gc_immutable_audit();
CREATE FUNCTION public.gc_quality_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$ BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'QUALITY_IMMUTABLE' USING ERRCODE='42501'; END IF;
 IF TG_TABLE_NAME='quality_rules' THEN
  IF (to_jsonb(NEW)-'current_version') IS DISTINCT FROM (to_jsonb(OLD)-'current_version') OR NEW.current_version<>OLD.current_version+1 THEN
   RAISE EXCEPTION 'QUALITY_IMMUTABLE' USING ERRCODE='42501'; END IF;
 ELSE
  IF OLD.status IN ('succeeded','failed','cancelled') OR
   (to_jsonb(NEW)-ARRAY['status','version','attempt','claim_id','claimed_at','lease_expires_at','started_at','finished_at','measurement','verdict','error_code','completion_hash']) IS DISTINCT FROM
   (to_jsonb(OLD)-ARRAY['status','version','attempt','claim_id','claimed_at','lease_expires_at','started_at','finished_at','measurement','verdict','error_code','completion_hash'])
   OR NEW.version<>OLD.version+1 OR NEW.attempt<OLD.attempt THEN RAISE EXCEPTION 'QUALITY_IMMUTABLE' USING ERRCODE='42501'; END IF;
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER quality_rules_guard BEFORE UPDATE OR DELETE ON public.quality_rules FOR EACH ROW EXECUTE FUNCTION public.gc_quality_guard();
CREATE TRIGGER quality_runs_guard BEFORE UPDATE OR DELETE ON public.quality_runs FOR EACH ROW EXECUTE FUNCTION public.gc_quality_guard();

CREATE FUNCTION public.gc_quality_visible(column_identity uuid,actor_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM public.assets c JOIN public.assets t ON t.tenant_id=c.tenant_id AND t.source_id=c.source_id AND t.external_id=c.parent_external_id
 JOIN public.assets s ON s.tenant_id=t.tenant_id AND s.source_id=t.source_id AND s.external_id=t.parent_external_id
 JOIN public.memberships m ON m.tenant_id=c.tenant_id AND m.identity_id=actor_identity JOIN public.identities i ON i.id=m.identity_id
 WHERE c.tenant_id=public.gc_tenant() AND c.id=column_identity AND c.type='column' AND t.type='table' AND s.type='schema'
 AND m.active AND i.active AND m.permissions @> '["catalog:read","quality:read"]'::jsonb
 AND (c.visibility='tenant' OR c.allowed_identities @> to_jsonb(ARRAY[actor_identity::text]))
 AND (t.visibility='tenant' OR t.allowed_identities @> to_jsonb(ARRAY[actor_identity::text]))
 AND (s.visibility='tenant' OR s.allowed_identities @> to_jsonb(ARRAY[actor_identity::text])));
$$;
-- Locks use the same tenant ledger before principals, then source and assets.
CREATE FUNCTION public.gc_quality_lock(column_identity uuid,actor_identity uuid,owner_identity uuid DEFAULT NULL) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE item uuid;BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(public.gc_tenant()::text,0));
 FOR item IN SELECT id FROM public.identities WHERE id=ANY(ARRAY[actor_identity,owner_identity]) ORDER BY id FOR SHARE LOOP NULL;END LOOP;
 FOR item IN SELECT identity_id FROM public.memberships WHERE tenant_id=public.gc_tenant() AND identity_id=ANY(ARRAY[actor_identity,owner_identity]) ORDER BY identity_id FOR SHARE LOOP NULL;END LOOP;
 FOR item IN SELECT id FROM public.sources WHERE tenant_id=public.gc_tenant() AND id=(SELECT source_id FROM public.assets WHERE tenant_id=public.gc_tenant() AND id=column_identity) FOR SHARE LOOP NULL;END LOOP;
 FOR item IN SELECT id FROM public.assets WHERE tenant_id=public.gc_tenant() AND id IN (
  SELECT c.id FROM public.assets c WHERE c.tenant_id=public.gc_tenant() AND c.id=column_identity
  UNION SELECT t.id FROM public.assets c JOIN public.assets t ON t.tenant_id=c.tenant_id AND t.source_id=c.source_id AND t.external_id=c.parent_external_id WHERE c.tenant_id=public.gc_tenant() AND c.id=column_identity
  UNION SELECT s.id FROM public.assets c JOIN public.assets t ON t.tenant_id=c.tenant_id AND t.source_id=c.source_id AND t.external_id=c.parent_external_id
  JOIN public.assets s ON s.tenant_id=t.tenant_id AND s.source_id=t.source_id AND s.external_id=t.parent_external_id WHERE c.tenant_id=public.gc_tenant() AND c.id=column_identity
 ) ORDER BY id FOR SHARE LOOP NULL;END LOOP;
END $$;
CREATE FUNCTION public.gc_quality_inputs(column_identity uuid,actor_identity uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE c public.assets;t public.assets;s public.assets;src public.sources;parts text[];schema_parts text[];connection jsonb;target jsonb;BEGIN
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
CREATE FUNCTION public.gc_quality_eligibility(asset_identity uuid,actor_identity uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE a public.assets;v jsonb;BEGIN
 SELECT a0.* INTO a FROM public.assets a0 JOIN public.memberships m ON m.tenant_id=a0.tenant_id AND m.identity_id=actor_identity JOIN public.identities i ON i.id=m.identity_id
 WHERE a0.tenant_id=public.gc_tenant() AND a0.id=asset_identity AND m.active AND i.active AND m.permissions @> '["catalog:read","quality:read"]'::jsonb
 AND (a0.visibility='tenant' OR a0.allowed_identities @> to_jsonb(ARRAY[actor_identity::text]));
 IF NOT FOUND THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
 IF a.type<>'column' THEN RETURN jsonb_build_object('supported',false,'reason','COLUMN_REQUIRED','tableAssetId',NULL,'columnAssetId',NULL);END IF;
 BEGIN v:=public.gc_quality_inputs(asset_identity,actor_identity);
 EXCEPTION WHEN feature_not_supported THEN RETURN jsonb_build_object('supported',false,'reason','QUALITY_TARGET_UNSUPPORTED','tableAssetId',NULL,'columnAssetId',asset_identity);END;
 RETURN jsonb_build_object('supported',true,'reason',NULL,'tableAssetId',v->'tableAssetId','columnAssetId',asset_identity);
END $$;
CREATE FUNCTION public.gc_quality_rule_view(rule_identity uuid,selected_version integer) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT jsonb_build_object('id',r.id,'version',v.version,'currentVersion',r.current_version,'definition',v.definition,'definitionHash',v.definition_hash,'createdAt',public.gc_relation_utc(v.created_at),'createdBy',v.created_by)
 FROM public.quality_rules r JOIN public.quality_rule_versions v ON v.tenant_id=r.tenant_id AND v.rule_id=r.id
 WHERE r.tenant_id=public.gc_tenant() AND r.id=rule_identity AND v.version=coalesce(selected_version,r.current_version);
$$;
CREATE FUNCTION public.gc_quality_run_view(run_identity uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT jsonb_build_object('id',r.id,'ruleId',r.rule_id,'ruleVersion',r.rule_version,'ruleHash',r.rule_hash,'requesterId',r.requester_id,'columnAssetId',r.column_asset_id,'tableAssetId',r.table_asset_id,
  'status',r.status,'version',r.version,'attempt',r.attempt,'createdAt',public.gc_relation_utc(r.created_at),'startedAt',public.gc_relation_utc(r.started_at),'finishedAt',public.gc_relation_utc(r.finished_at),
  'expiresAt',public.gc_relation_utc(r.expires_at),'measurement',r.measurement,'verdict',r.verdict,'errorCode',r.error_code)
 FROM public.quality_runs r WHERE r.tenant_id=public.gc_tenant() AND r.id=run_identity;
$$;
CREATE FUNCTION public.gc_quality_definition_valid(value jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ BEGIN
 IF public.gc_relation_keys(value,ARRAY['formatVersion','kind','target','name','purpose','ownerId','severity','maximumNullBasisPoints']) IS NOT TRUE
 OR value->'formatVersion' IS DISTINCT FROM '1'::jsonb OR value->>'kind' IS DISTINCT FROM 'completeness'
 OR public.gc_relation_keys(value->'target',ARRAY['tableAssetId','columnAssetId']) IS NOT TRUE
 OR NOT public.gc_approval_uuid(value->'target'->>'tableAssetId') OR NOT public.gc_approval_uuid(value->'target'->>'columnAssetId') OR NOT public.gc_approval_uuid(value->>'ownerId')
 OR jsonb_typeof(value->'name') IS DISTINCT FROM 'string' OR public.gc_approval_text(value->>'name',240,false) IS NULL
 OR value->>'name' IS DISTINCT FROM public.gc_approval_text(value->>'name',240,false)
 OR jsonb_typeof(value->'purpose') IS DISTINCT FROM 'string' OR public.gc_approval_text(value->>'purpose',4096,true) IS NULL
 OR value->>'purpose' IS DISTINCT FROM public.gc_approval_text(value->>'purpose',4096,true)
 OR value->>'severity' NOT IN ('info','warning','critical') OR jsonb_typeof(value->'severity') IS DISTINCT FROM 'string'
 OR jsonb_typeof(value->'maximumNullBasisPoints') IS DISTINCT FROM 'number' OR value->>'maximumNullBasisPoints' !~ '^(0|[1-9][0-9]{0,4})$' THEN RETURN false;END IF;
 RETURN (value->>'maximumNullBasisPoints')::integer<=10000 AND octet_length(value::text)<=16384;
END $$;
CREATE FUNCTION public.gc_quality_can_execute(column_identity uuid,actor_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT public.gc_quality_visible(column_identity,actor_identity) AND EXISTS(SELECT 1 FROM public.memberships WHERE tenant_id=public.gc_tenant() AND identity_id=actor_identity AND permissions @> '["quality:execute"]'::jsonb);
$$;
CREATE FUNCTION public.gc_quality_command(operation text,command_key text,body jsonb,correlation text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant();actor uuid;old public.idempotency;rule public.quality_rules;v public.quality_rule_versions;r public.quality_runs;
 definition jsonb;result jsonb;inputs jsonb;hash text;identity uuid;column_identity uuid;expected integer;now_at timestamptz;actions text[];BEGIN
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
  PERFORM public.gc_quality_lock(column_identity,actor);PERFORM public.gc_relation_authorize(actions);
  IF NOT public.gc_quality_visible(column_identity,actor) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  RETURN old.response;
 END IF;
 IF operation='quality.rule.publish' THEN
  IF public.gc_relation_keys(body,ARRAY['id','expectedVersion','definition']) IS NOT TRUE OR NOT public.gc_approval_uuid(body->>'id')
  OR public.gc_quality_definition_valid(body->'definition') IS NOT TRUE OR jsonb_typeof(body->'expectedVersion') IS DISTINCT FROM 'number'
  OR body->>'expectedVersion' !~ '^(0|[1-9][0-9]{0,9})$' OR (body->>'expectedVersion')::bigint>=2147483647 THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;
  identity:=(body->>'id')::uuid;definition:=body->'definition';expected:=(body->>'expectedVersion')::integer;column_identity:=(definition->'target'->>'columnAssetId')::uuid;
  -- Existing rule identity is authorized before caller-supplied replacement
  -- targets, version diagnostics or owner checks can reveal its existence.
  SELECT * INTO rule FROM public.quality_rules WHERE tenant_id=tenant AND id=identity;
  IF (expected>0 AND rule.id IS NULL) OR (rule.id IS NOT NULL AND NOT public.gc_quality_visible(rule.column_asset_id,actor)) THEN
   RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  IF rule.id IS NOT NULL AND rule.column_asset_id<>column_identity THEN
   RAISE EXCEPTION 'QUALITY_TARGET_IMMUTABLE' USING ERRCODE='40001';END IF;
  PERFORM public.gc_quality_lock(column_identity,actor,(definition->>'ownerId')::uuid);PERFORM public.gc_relation_authorize(actions);
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
  PERFORM public.gc_approval_journal('quality.rule_published',NULL,column_identity::text,expected+1,jsonb_build_object('ruleId',identity,'definitionHash',public.gc_type_migration_hash(definition)),correlation);
  result:=jsonb_build_object('rule',public.gc_quality_rule_view(identity,expected+1));
 ELSIF operation='quality.run.request' THEN
  IF public.gc_relation_keys(body,ARRAY['ruleId','id','ruleVersion','ruleHash']) IS NOT TRUE OR NOT public.gc_approval_uuid(body->>'ruleId') OR NOT public.gc_approval_uuid(body->>'id')
  OR jsonb_typeof(body->'ruleVersion') IS DISTINCT FROM 'number' OR body->>'ruleVersion' !~ '^[1-9][0-9]{0,9}$' OR (body->>'ruleVersion')::bigint>2147483647
  OR jsonb_typeof(body->'ruleHash') IS DISTINCT FROM 'string' OR body->>'ruleHash' !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;
  SELECT * INTO rule FROM public.quality_rules WHERE tenant_id=tenant AND id=(body->>'ruleId')::uuid;
  IF rule.id IS NULL OR NOT public.gc_quality_visible(rule.column_asset_id,actor) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  column_identity:=rule.column_asset_id;PERFORM public.gc_quality_lock(column_identity,actor);PERFORM public.gc_relation_authorize(actions);
  SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=tenant AND rule_id=rule.id AND version=(body->>'ruleVersion')::integer;
  IF v.version IS NULL OR rule.current_version<>v.version OR v.definition_hash IS DISTINCT FROM body->>'ruleHash' THEN RAISE EXCEPTION 'VERSION_CONFLICT' USING ERRCODE='40001';END IF;
  inputs:=public.gc_quality_inputs(column_identity,actor);
  IF v.definition->'target' IS DISTINCT FROM jsonb_build_object('tableAssetId',inputs->'tableAssetId','columnAssetId',inputs->'columnAssetId') THEN RAISE EXCEPTION 'QUALITY_TARGET_STALE' USING ERRCODE='40001';END IF;
  identity:=(body->>'id')::uuid;now_at:=clock_timestamp();
  INSERT INTO public.quality_runs(tenant_id,id,rule_id,rule_version,rule_hash,requester_id,source_id,schema_asset_id,table_asset_id,column_asset_id,inputs,input_hash,status,expires_at,created_at)
  VALUES(tenant,identity,rule.id,v.version,v.definition_hash,actor,(inputs->>'sourceId')::uuid,(inputs->>'schemaAssetId')::uuid,(inputs->>'tableAssetId')::uuid,column_identity,
   inputs,public.gc_type_migration_hash(inputs),'queued',now_at+interval '10 minutes',now_at);
  PERFORM public.gc_approval_journal('quality.run_requested',NULL,column_identity::text,1,jsonb_build_object('ruleId',rule.id,'runId',identity,'ruleVersion',v.version,'inputHash',public.gc_type_migration_hash(inputs)),correlation);
  result:=jsonb_build_object('run',public.gc_quality_run_view(identity));
 ELSE
  IF public.gc_relation_keys(body,ARRAY['runId','expectedVersion','reason']) IS NOT TRUE OR NOT public.gc_approval_uuid(body->>'runId')
  OR jsonb_typeof(body->'expectedVersion') IS DISTINCT FROM 'number' OR body->>'expectedVersion' !~ '^[1-9][0-9]{0,9}$' OR (body->>'expectedVersion')::bigint>2147483647
  OR jsonb_typeof(body->'reason') IS DISTINCT FROM 'string' OR public.gc_approval_text(body->>'reason',4096,true) IS NULL THEN RAISE EXCEPTION 'QUALITY_INPUT_INVALID' USING ERRCODE='22023';END IF;
  identity:=(body->>'runId')::uuid;SELECT * INTO r FROM public.quality_runs WHERE tenant_id=tenant AND id=identity;
  IF r.id IS NULL OR NOT public.gc_quality_visible(r.column_asset_id,actor) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  column_identity:=r.column_asset_id;PERFORM public.gc_quality_lock(column_identity,actor);PERFORM public.gc_relation_authorize(actions);
  IF NOT public.gc_quality_visible(column_identity,actor) THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  IF r.version<>(body->>'expectedVersion')::integer OR r.status NOT IN ('queued','running') THEN RAISE EXCEPTION 'VERSION_CONFLICT' USING ERRCODE='40001';END IF;
  UPDATE public.quality_runs SET status='cancelled',version=version+1,finished_at=clock_timestamp(),error_code='QUALITY_CANCELLED' WHERE tenant_id=tenant AND id=identity;
  PERFORM public.gc_approval_journal('quality.run_cancelled',NULL,column_identity::text,r.version+1,jsonb_build_object('ruleId',r.rule_id,'runId',identity,'reason',public.gc_approval_text(body->>'reason',4096,true)),correlation);
  result:=jsonb_build_object('run',public.gc_quality_run_view(identity));
 END IF;
 INSERT INTO public.idempotency(tenant_id,actor_id,operation,key,request_hash,response) VALUES(tenant,actor::text,operation,command_key,hash,result);
 RETURN result;
END $$;
CREATE FUNCTION public.gc_quality_terminal(run_identity uuid,error text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE r public.quality_runs;BEGIN
 SELECT * INTO r FROM public.quality_runs WHERE tenant_id=public.gc_tenant() AND id=run_identity;
 IF r.id IS NULL OR r.status NOT IN ('queued','running') THEN RETURN;END IF;
 UPDATE public.quality_runs SET status=CASE WHEN error='QUALITY_AUTHORITY_REVOKED' THEN 'cancelled' ELSE 'failed' END,version=version+1,finished_at=clock_timestamp(),error_code=error WHERE tenant_id=r.tenant_id AND id=r.id;
 PERFORM public.gc_approval_journal('quality.run_finished',NULL,r.column_asset_id::text,r.version+1,jsonb_build_object('ruleId',r.rule_id,'runId',r.id,'errorCode',error),'quality:'||r.id::text);
END $$;
CREATE FUNCTION public.gc_quality_claim(run_identity uuid,claim_identity uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE r public.quality_runs;inputs jsonb;now_at timestamptz;error text;BEGIN
 IF public.gc_actor() IS DISTINCT FROM 'site:local' OR claim_identity IS NULL THEN RAISE EXCEPTION 'QUALITY_SITE_REQUIRED' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(public.gc_tenant()::text,0));SELECT * INTO r FROM public.quality_runs WHERE tenant_id=public.gc_tenant() AND id=run_identity;
 IF r.id IS NULL THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
 IF r.status IN ('succeeded','failed','cancelled') THEN RETURN jsonb_build_object('status','terminal','run',public.gc_quality_run_view(r.id));END IF;
 PERFORM public.gc_quality_lock(r.column_asset_id,r.requester_id);now_at:=clock_timestamp();
 IF NOT public.gc_quality_can_execute(r.column_asset_id,r.requester_id) THEN error:='QUALITY_AUTHORITY_REVOKED';
 ELSIF r.expires_at<=now_at THEN error:='QUALITY_DEADLINE_EXCEEDED';
 ELSE
  BEGIN inputs:=public.gc_quality_inputs(r.column_asset_id,r.requester_id);
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
CREATE FUNCTION public.gc_quality_measurement_valid(value jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ DECLARE field text;BEGIN
 IF public.gc_relation_keys(value,ARRAY['formatVersion','kind','strategy','rowCount','nullCount','observedStartedAt','observedFinishedAt','elapsedMs','sourceVersion','adapterVersion','queryTemplate','estimatedCost','estimatedBytes']) IS NOT TRUE
 OR value->'formatVersion' IS DISTINCT FROM '1'::jsonb OR value->>'kind' IS DISTINCT FROM 'completeness' OR value->>'strategy' IS DISTINCT FROM 'exact-bounded-role-scope'
 OR value->>'adapterVersion' IS DISTINCT FROM '1' OR value->>'queryTemplate' IS DISTINCT FROM 'postgresql-completeness-v1'
 OR jsonb_typeof(value->'sourceVersion') IS DISTINCT FROM 'string' OR value->>'sourceVersion' !~ '^[0-9]{5,16}$' THEN RETURN false;END IF;
 FOREACH field IN ARRAY ARRAY['rowCount','nullCount','elapsedMs','estimatedBytes'] LOOP
  IF jsonb_typeof(value->field) IS DISTINCT FROM 'number' OR value->>field !~ '^(0|[1-9][0-9]{0,8})$' THEN RETURN false;END IF;
 END LOOP;
 FOREACH field IN ARRAY ARRAY['observedStartedAt','observedFinishedAt'] LOOP
  IF jsonb_typeof(value->field) IS DISTINCT FROM 'string' OR value->>field !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'
   OR public.gc_relation_utc((value->>field)::timestamptz) IS DISTINCT FROM value->>field THEN RETURN false;END IF;
 END LOOP;
 IF jsonb_typeof(value->'estimatedCost') IS DISTINCT FROM 'number' THEN RETURN false;END IF;
 RETURN (value->>'rowCount')::integer<=100000 AND (value->>'nullCount')::integer<=(value->>'rowCount')::integer
 AND (value->>'elapsedMs')::integer<=30000 AND (value->>'estimatedBytes')::integer<=67108864
 AND (value->>'estimatedCost')::numeric BETWEEN 0 AND 1000000
 AND (value->>'observedFinishedAt')::timestamptz>=(value->>'observedStartedAt')::timestamptz
 AND (value->>'observedFinishedAt')::timestamptz-(value->>'observedStartedAt')::timestamptz<=interval '31 seconds'
 AND abs(extract(epoch FROM ((value->>'observedFinishedAt')::timestamptz-(value->>'observedStartedAt')::timestamptz))*1000-(value->>'elapsedMs')::integer)<=1000;
 EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow OR numeric_value_out_of_range THEN RETURN false;
END $$;
CREATE FUNCTION public.gc_quality_finish(run_identity uuid,body jsonb) RETURNS jsonb
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
 PERFORM public.gc_quality_lock(r.column_asset_id,r.requester_id);now_at:=clock_timestamp();
 IF r.status IN ('succeeded','failed','cancelled') THEN
  IF NOT public.gc_quality_can_execute(r.column_asset_id,r.requester_id) THEN RAISE EXCEPTION 'QUALITY_AUTHORITY_REVOKED' USING ERRCODE='42501';END IF;
  IF r.completion_hash IS DISTINCT FROM hash OR r.claim_id IS DISTINCT FROM (body->>'claimId')::uuid OR r.attempt<>(body->>'attempt')::integer THEN
   RAISE EXCEPTION 'QUALITY_COMPLETION_CONFLICT' USING ERRCODE='40001';END IF;
  RETURN jsonb_build_object('run',public.gc_quality_run_view(r.id));
 END IF;
 IF r.status<>'running' OR r.claim_id IS DISTINCT FROM (body->>'claimId')::uuid OR r.attempt<>(body->>'attempt')::integer THEN
  RAISE EXCEPTION 'QUALITY_CLAIM_CONFLICT' USING ERRCODE='40001';END IF;
 IF NOT public.gc_quality_can_execute(r.column_asset_id,r.requester_id) THEN error:='QUALITY_AUTHORITY_REVOKED';
 ELSIF r.expires_at<=now_at THEN error:='QUALITY_DEADLINE_EXCEEDED';
 ELSIF r.lease_expires_at<=now_at THEN RAISE EXCEPTION 'QUALITY_CLAIM_EXPIRED' USING ERRCODE='40001';
 ELSE
  BEGIN inputs:=public.gc_quality_inputs(r.column_asset_id,r.requester_id);
  EXCEPTION WHEN feature_not_supported OR no_data_found THEN error:='QUALITY_TARGET_STALE';END;
  IF inputs IS DISTINCT FROM r.inputs THEN error:='QUALITY_TARGET_STALE';END IF;
 END IF;
 IF error IS NULL THEN
  IF (measured->>'observedStartedAt')::timestamptz<r.claimed_at-interval '1 second'
   OR (measured->>'observedFinishedAt')::timestamptz>now_at+interval '1 second' THEN RAISE EXCEPTION 'QUALITY_OBSERVATION_INVALID' USING ERRCODE='22023';END IF;
  SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=r.tenant_id AND rule_id=r.rule_id AND version=r.rule_version;
  outcome:=CASE WHEN (measured->>'rowCount')::bigint=0 THEN 'NO_DATA'
   WHEN (measured->>'nullCount')::bigint*10000<=(measured->>'rowCount')::bigint*(v.definition->>'maximumNullBasisPoints')::bigint THEN 'PASS' ELSE 'FAIL' END;
  UPDATE public.quality_runs SET status='succeeded',version=version+1,finished_at=now_at,measurement=measured,verdict=outcome,completion_hash=hash WHERE tenant_id=r.tenant_id AND id=r.id;
 ELSE
  UPDATE public.quality_runs SET status=CASE WHEN error='QUALITY_AUTHORITY_REVOKED' THEN 'cancelled' ELSE 'failed' END,version=version+1,finished_at=now_at,error_code=error,completion_hash=hash WHERE tenant_id=r.tenant_id AND id=r.id;
 END IF;
 PERFORM public.gc_approval_journal('quality.run_finished',NULL,r.column_asset_id::text,r.version+1,jsonb_build_object('ruleId',r.rule_id,'runId',r.id,'ruleVersion',r.rule_version,'verdict',outcome,'errorCode',error),'quality:'||r.id::text);
 RETURN jsonb_build_object('run',public.gc_quality_run_view(r.id));
END $$;
CREATE FUNCTION public.gc_quality_namespace_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$ DECLARE protected boolean;BEGIN
 IF TG_TABLE_NAME='idempotency' THEN protected:=(CASE WHEN TG_OP='DELETE' THEN OLD.operation ELSE NEW.operation END) LIKE 'quality.%' OR (TG_OP='UPDATE' AND OLD.operation LIKE 'quality.%');
 ELSIF TG_TABLE_NAME='audit' THEN protected:=NEW.action LIKE 'quality.%';
 ELSE protected:=(CASE WHEN TG_OP='DELETE' THEN OLD.event_type ELSE NEW.event_type END) LIKE 'quality.%' OR (TG_OP='UPDATE' AND OLD.event_type LIKE 'quality.%');END IF;
 IF TG_TABLE_NAME='outbox' AND TG_OP='UPDATE' AND protected THEN
  IF (to_jsonb(NEW)-ARRAY['processed_at','attempts'])=(to_jsonb(OLD)-ARRAY['processed_at','attempts']) AND NEW.attempts>=OLD.attempts THEN RETURN NEW;END IF;
 END IF;
 IF protected AND current_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.quality_runs'::regclass) THEN RAISE EXCEPTION 'QUALITY_RESERVED_NAMESPACE' USING ERRCODE='42501';END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END $$;
CREATE TRIGGER quality_namespace_guard BEFORE INSERT OR UPDATE OR DELETE ON public.idempotency FOR EACH ROW EXECUTE FUNCTION public.gc_quality_namespace_guard();
CREATE TRIGGER quality_namespace_guard BEFORE INSERT ON public.audit FOR EACH ROW EXECUTE FUNCTION public.gc_quality_namespace_guard();
CREATE TRIGGER quality_namespace_guard BEFORE INSERT OR UPDATE OR DELETE ON public.outbox FOR EACH ROW EXECUTE FUNCTION public.gc_quality_namespace_guard();
REVOKE ALL ON FUNCTION public.gc_quality_guard(),public.gc_quality_visible(uuid,uuid),public.gc_quality_lock(uuid,uuid,uuid),public.gc_quality_inputs(uuid,uuid),public.gc_quality_eligibility(uuid,uuid),
 public.gc_quality_rule_view(uuid,integer),public.gc_quality_run_view(uuid),public.gc_quality_definition_valid(jsonb),public.gc_quality_can_execute(uuid,uuid),public.gc_quality_command(text,text,jsonb,text),
 public.gc_quality_terminal(uuid,text),public.gc_quality_claim(uuid,uuid),public.gc_quality_measurement_valid(jsonb),public.gc_quality_finish(uuid,jsonb),public.gc_quality_namespace_guard() FROM PUBLIC,gc_app;
GRANT EXECUTE ON FUNCTION public.gc_quality_visible(uuid,uuid),public.gc_quality_eligibility(uuid,uuid),public.gc_quality_rule_view(uuid,integer),public.gc_quality_run_view(uuid),
 public.gc_quality_command(text,text,jsonb,text),public.gc_quality_claim(uuid,uuid),public.gc_quality_finish(uuid,jsonb) TO gc_app;
