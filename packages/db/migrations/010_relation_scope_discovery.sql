-- SPDX-License-Identifier: Apache-2.0
-- Forward scope-discovery correction for immutable SQL009. Qualification candidate;
-- applying this file to the core database requires the isolated gate and review.
-- Materialize identity closure once, authorize before count/size disclosure, and
-- keep the original operation clock through every bounded scan. Private scope
-- data is never caller authority; claims/final validation remain independently derived.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
  OR pg_has_role('gc_app',current_user,'MEMBER') THEN
  RAISE EXCEPTION 'Graph discovery requires an isolated non-bypass migration owner' USING ERRCODE='42501';
 END IF;
END $$;

-- A GUC changed inside an already running SELECT cannot arm its outer timeout.
-- These cooperative checkpoints therefore use the protected operation's actual
-- start, in addition to the service's separately pre-armed statement timeout.
CREATE FUNCTION public.gc_relation_graph_scope_tick(started_at timestamptz,subject uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF started_at IS NULL OR clock_timestamp()>=started_at+interval '30 seconds' THEN
  RAISE EXCEPTION 'Graph operation deadline exceeded' USING ERRCODE='57014'; END IF;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_scope_tick(timestamptz,uuid) FROM PUBLIC,gc_app;
CREATE FUNCTION public.gc_relation_graph_scope_eligible(tenant uuid,asset uuid,definition jsonb,side text,started_at timestamptz) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE result boolean;
BEGIN
 PERFORM public.gc_relation_graph_scope_tick(started_at,asset);
 result:=public.gc_relation_endpoint_eligible(tenant,asset,definition,side);
 PERFORM public.gc_relation_graph_scope_tick(started_at,asset);
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_scope_eligible(uuid,uuid,jsonb,text,timestamptz) FROM PUBLIC,gc_app;
-- Scope needs only the nominal pin/state, never an asset's description/metadata.
CREATE FUNCTION public.gc_relation_graph_scope_project(asset uuid,asset_version integer,model_key text,model_version integer,state text,request_body jsonb,started_at timestamptz) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE row_value public.assets; result jsonb;
BEGIN
 PERFORM public.gc_relation_graph_scope_tick(started_at,asset);
 row_value.id:=asset;row_value.version:=asset_version;row_value.model_id:=model_key;row_value.model_version:=model_version;row_value.type_state:=state;
 result:=public.gc_relation_graph_project_endpoint(row_value,request_body);
 PERFORM public.gc_relation_graph_scope_tick(started_at,asset);
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_scope_project(uuid,integer,text,integer,text,jsonb,timestamptz) FROM PUBLIC,gc_app;

CREATE OR REPLACE FUNCTION public.gc_relation_graph_candidate_types(selected_operation uuid) RETURNS TABLE(relation_type_id uuid)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 WITH op AS MATERIALIZED (SELECT o.tenant_id,o.id,o.normalized_change_set,o.created_at FROM public.relation_graph_operations o
  WHERE o.tenant_id=public.gc_tenant() AND o.id=selected_operation AND o.transaction_id=pg_current_xact_id()),
 changed_ids AS MATERIALIZED (SELECT a.id,a.version,a.model_id,a.model_version,a.type_state FROM public.assets a CROSS JOIN op
  WHERE a.tenant_id=op.tenant_id AND (EXISTS(SELECT 1 FROM jsonb_array_elements(op.normalized_change_set->'assetChanges') e(v) WHERE v->>'assetId'=a.id::text)
   OR EXISTS(SELECT 1 FROM public.relation_graph_operation_model_claims m WHERE m.tenant_id=op.tenant_id AND m.operation_id=op.id AND m.model_id=a.model_id))),
 changed AS MATERIALIZED (SELECT a.id,public.gc_relation_graph_scope_project(a.id,a.version,a.model_id,a.model_version,a.type_state,
  jsonb_build_object('changeSet',op.normalized_change_set),op.created_at) AS proposed FROM changed_ids a CROSS JOIN op)
 SELECT c.relation_type_id FROM public.relation_graph_operation_type_claims c CROSS JOIN op WHERE c.tenant_id=op.tenant_id AND c.operation_id=op.id
 UNION SELECT t.type_id FROM public.relation_types t JOIN public.relation_type_versions v ON v.tenant_id=t.tenant_id AND v.relation_type_id=t.type_id AND v.version=t.current_version
  CROSS JOIN op WHERE t.tenant_id=op.tenant_id AND public.gc_relation_graph_scope_tick(op.created_at,t.type_id)
  AND EXISTS(SELECT 1 FROM changed a WHERE
   public.gc_relation_graph_scope_eligible(op.tenant_id,a.id,v.definition,'source',op.created_at) OR public.gc_relation_graph_scope_eligible(op.tenant_id,a.id,v.definition,'target',op.created_at)
   OR public.gc_relation_projected_eligible(a.proposed,v.definition,'source') OR public.gc_relation_projected_eligible(a.proposed,v.definition,'target')
   OR EXISTS(SELECT 1 FROM public.relations r WHERE r.tenant_id=op.tenant_id AND r.relation_type_id=t.type_id AND r.status='active' AND a.id IN(r.source_asset_id,r.target_asset_id))
   OR EXISTS(SELECT 1 FROM public.relation_participations b WHERE b.tenant_id=op.tenant_id AND b.relation_type_id=t.type_id AND b.status='active' AND b.asset_id=a.id))
$$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_candidate_types(uuid) FROM PUBLIC,gc_app;

CREATE OR REPLACE FUNCTION public.gc_relation_graph_candidate_assets(selected_operation uuid) RETURNS TABLE(asset_id uuid,action text)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 WITH op AS MATERIALIZED (SELECT o.tenant_id,o.id,o.normalized_change_set,o.created_at FROM public.relation_graph_operations o WHERE o.tenant_id=public.gc_tenant() AND o.id=selected_operation AND o.transaction_id=pg_current_xact_id()),
 types AS MATERIALIZED (SELECT ids.relation_type_id,coalesce(c.before_definition,v.definition) AS before_definition,coalesce(c.after_definition,v.definition) AS after_definition,c.plan
  FROM public.gc_relation_graph_candidate_types(selected_operation) ids CROSS JOIN op
  LEFT JOIN public.relation_graph_operation_type_claims c ON c.tenant_id=op.tenant_id AND c.operation_id=op.id AND c.relation_type_id=ids.relation_type_id
  LEFT JOIN public.relation_types t ON t.tenant_id=op.tenant_id AND t.type_id=ids.relation_type_id
  LEFT JOIN public.relation_type_versions v ON v.tenant_id=t.tenant_id AND v.relation_type_id=t.type_id AND v.version=t.current_version)
 SELECT a.id,coalesce((SELECT v->>'kind' FROM jsonb_array_elements(op.normalized_change_set->'assetChanges') e(v) WHERE v->>'assetId'=a.id::text),
  CASE WHEN EXISTS(SELECT 1 FROM public.relation_graph_operation_model_claims m WHERE m.tenant_id=op.tenant_id AND m.operation_id=op.id AND m.model_id=a.model_id) THEN 'type-migrate' ELSE 'preserve' END)
 FROM public.assets a CROSS JOIN op WHERE a.tenant_id=op.tenant_id AND public.gc_relation_graph_scope_tick(op.created_at,a.id) AND (
  EXISTS(SELECT 1 FROM jsonb_array_elements(op.normalized_change_set->'assetChanges') e(v) WHERE v->>'assetId'=a.id::text)
  OR EXISTS(SELECT 1 FROM public.relation_graph_operation_model_claims m WHERE m.tenant_id=op.tenant_id AND m.operation_id=op.id AND m.model_id=a.model_id)
  OR EXISTS(SELECT 1 FROM types t WHERE public.gc_relation_graph_scope_eligible(op.tenant_id,a.id,t.before_definition,'source',op.created_at)
   OR public.gc_relation_graph_scope_eligible(op.tenant_id,a.id,t.before_definition,'target',op.created_at) OR public.gc_relation_graph_scope_eligible(op.tenant_id,a.id,t.after_definition,'source',op.created_at)
   OR public.gc_relation_graph_scope_eligible(op.tenant_id,a.id,t.after_definition,'target',op.created_at)
   OR EXISTS(SELECT 1 FROM public.relations r WHERE r.tenant_id=op.tenant_id AND r.relation_type_id=t.relation_type_id AND r.status='active' AND a.id IN(r.source_asset_id,r.target_asset_id))
   OR EXISTS(SELECT 1 FROM public.relation_participations b WHERE b.tenant_id=op.tenant_id AND b.relation_type_id=t.relation_type_id AND b.status='active' AND b.asset_id=a.id)
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(coalesce(t.plan->'creations','[]')) e(v) WHERE a.id::text IN(v->>'sourceAssetId',v->>'targetAssetId'))))
$$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_candidate_assets(uuid) FROM PUBLIC,gc_app;

CREATE FUNCTION public.gc_relation_graph_capture_scope(selected_operation uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE captured record; started_at timestamptz;
BEGIN
 SELECT o.created_at INTO started_at FROM public.relation_graph_operations o WHERE o.tenant_id=public.gc_tenant() AND o.id=selected_operation
  AND o.transaction_id=pg_current_xact_id() AND o.actor_id=public.gc_actor()::uuid AND o.state='open';
 IF started_at IS NULL THEN RAISE EXCEPTION 'Scope requires the protected current operation' USING ERRCODE='42501'; END IF;
 PERFORM public.gc_relation_graph_scope_tick(started_at,selected_operation);
 SELECT * INTO captured FROM (
 WITH op AS MATERIALIZED (SELECT o.tenant_id,o.id,o.normalized_change_set,o.created_at,o.request_body,o.actor_id FROM public.relation_graph_operations o WHERE o.tenant_id=public.gc_tenant() AND o.id=selected_operation AND o.transaction_id=pg_current_xact_id() AND o.actor_id=public.gc_actor()::uuid AND o.state='open'),
 ids AS MATERIALIZED (SELECT relation_type_id FROM public.gc_relation_graph_candidate_types(selected_operation)),
 types AS MATERIALIZED (SELECT ids.relation_type_id,coalesce(c.before_definition,v.definition) AS before_definition,coalesce(c.after_definition,v.definition) AS after_definition,c.plan
  FROM ids CROSS JOIN op
  LEFT JOIN public.relation_graph_operation_type_claims c ON c.tenant_id=op.tenant_id AND c.operation_id=op.id AND c.relation_type_id=ids.relation_type_id
  LEFT JOIN public.relation_types t ON t.tenant_id=op.tenant_id AND t.type_id=ids.relation_type_id
  LEFT JOIN public.relation_type_versions v ON v.tenant_id=t.tenant_id AND v.relation_type_id=t.type_id AND v.version=t.current_version)
 ,assets AS MATERIALIZED (SELECT a.id AS asset_id,coalesce((SELECT v->>'kind' FROM jsonb_array_elements(op.normalized_change_set->'assetChanges') e(v) WHERE v->>'assetId'=a.id::text),
  CASE WHEN EXISTS(SELECT 1 FROM public.relation_graph_operation_model_claims m WHERE m.tenant_id=op.tenant_id AND m.operation_id=op.id AND m.model_id=a.model_id) THEN 'type-migrate' ELSE 'preserve' END) AS action
 FROM public.assets a CROSS JOIN op WHERE a.tenant_id=op.tenant_id AND public.gc_relation_graph_scope_tick(op.created_at,a.id) AND (
  EXISTS(SELECT 1 FROM jsonb_array_elements(op.normalized_change_set->'assetChanges') e(v) WHERE v->>'assetId'=a.id::text)
  OR EXISTS(SELECT 1 FROM public.relation_graph_operation_model_claims m WHERE m.tenant_id=op.tenant_id AND m.operation_id=op.id AND m.model_id=a.model_id)
  OR EXISTS(SELECT 1 FROM types t WHERE public.gc_relation_graph_scope_eligible(op.tenant_id,a.id,t.before_definition,'source',op.created_at)
   OR public.gc_relation_graph_scope_eligible(op.tenant_id,a.id,t.before_definition,'target',op.created_at) OR public.gc_relation_graph_scope_eligible(op.tenant_id,a.id,t.after_definition,'source',op.created_at)
   OR public.gc_relation_graph_scope_eligible(op.tenant_id,a.id,t.after_definition,'target',op.created_at)
   OR EXISTS(SELECT 1 FROM public.relations r WHERE r.tenant_id=op.tenant_id AND r.relation_type_id=t.relation_type_id AND r.status='active' AND a.id IN(r.source_asset_id,r.target_asset_id))
   OR EXISTS(SELECT 1 FROM public.relation_participations b WHERE b.tenant_id=op.tenant_id AND b.relation_type_id=t.relation_type_id AND b.status='active' AND b.asset_id=a.id)
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(coalesce(t.plan->'creations','[]')) e(v) WHERE a.id::text IN(v->>'sourceAssetId',v->>'targetAssetId')))))
 ,scope_access AS MATERIALIZED (SELECT EXISTS(SELECT 1 FROM assets c JOIN public.assets a ON a.tenant_id=op.tenant_id AND a.id=c.asset_id
   WHERE a.visibility='restricted' AND NOT a.allowed_identities @> jsonb_build_array(op.actor_id))
  OR EXISTS(SELECT 1 FROM ids t JOIN public.relations r ON r.tenant_id=op.tenant_id AND r.relation_type_id=t.relation_type_id
   WHERE r.status='active' AND r.visibility='restricted' AND NOT r.allowed_identities @> jsonb_build_array(op.actor_id)) AS hidden FROM op),
 counts AS MATERIALIZED (SELECT hidden,
  CASE WHEN NOT hidden THEN (SELECT count(*) FROM assets) END AS asset_count,
  CASE WHEN NOT hidden THEN (SELECT count(*) FROM assets WHERE action<>'preserve') END AS change_count,
  CASE WHEN NOT hidden THEN (SELECT count(*) FROM public.relations r JOIN ids t ON t.relation_type_id=r.relation_type_id WHERE r.tenant_id=op.tenant_id AND r.status='active') END AS edge_count,
  CASE WHEN NOT hidden THEN (SELECT count(*) FROM public.relation_participations p JOIN ids t ON t.relation_type_id=p.relation_type_id WHERE p.tenant_id=op.tenant_id AND p.status='active') END AS binding_count
  FROM scope_access CROSS JOIN op),
 bounded AS MATERIALIZED (SELECT counts.*,NOT hidden AND asset_count<=2000 AND change_count<=1000 AND edge_count<=1000 AND binding_count<=4000 AS fits FROM counts),
 physical AS MATERIALIZED (SELECT bounded.*,CASE WHEN fits THEN
  octet_length(op.request_body::text)+octet_length(jsonb_build_object('changeSet',op.normalized_change_set,'previewDigest',op.request_body->'previewDigest')::text)
  +coalesce((SELECT sum(octet_length(to_jsonb(a)::text)+octet_length(a.attributes::text)*2) FROM public.assets a JOIN assets c ON c.asset_id=a.id WHERE a.tenant_id=op.tenant_id),0)
  +coalesce((SELECT sum(octet_length(h.snapshot::text)) FROM public.asset_revisions h JOIN public.assets a ON a.tenant_id=h.tenant_id AND a.id=h.asset_id AND a.version=h.version
    JOIN assets c ON c.asset_id=a.id WHERE a.tenant_id=op.tenant_id),0)
  +coalesce((SELECT sum(octet_length(r.attributes::text)*3+octet_length(r.allowed_identities::text)*3+octet_length(r.provenance::text)+1024)
    FROM public.relations r JOIN ids c ON c.relation_type_id=r.relation_type_id WHERE r.tenant_id=op.tenant_id AND r.status='active'),0)
  +coalesce((SELECT sum(octet_length(v.definition::text)*2) FROM ids c JOIN public.relation_types h ON h.tenant_id=op.tenant_id AND h.type_id=c.relation_type_id
    JOIN public.relation_type_versions v ON v.tenant_id=h.tenant_id AND v.relation_type_id=h.type_id AND v.version=h.current_version),0)
  +coalesce((SELECT sum(coalesce(octet_length(c.before_definition::text),0)+octet_length(c.after_definition::text)) FROM public.relation_graph_operation_type_claims c
    WHERE c.tenant_id=op.tenant_id AND c.operation_id=op.id),0)
  +coalesce((SELECT sum(coalesce(octet_length(c.before_resolution::text),0)+octet_length(c.after_resolution::text)) FROM public.relation_graph_operation_model_claims c
    WHERE c.tenant_id=op.tenant_id AND c.operation_id=op.id),0)
  END AS bytes FROM bounded CROSS JOIN op)
 SELECT hidden,fits,bytes,
  CASE WHEN fits AND bytes<=524288 THEN jsonb_build_object(
   'assets',(SELECT coalesce(jsonb_agg(jsonb_build_object('asset_id',asset_id,'action',action) ORDER BY asset_id),'[]') FROM assets),
   'types',(SELECT coalesce(jsonb_agg(relation_type_id ORDER BY relation_type_id),'[]') FROM ids)) END AS scope
 FROM physical
 ) AS result;
 IF captured.hidden THEN RAISE EXCEPTION 'RELATION_SCOPE_UNAVAILABLE' USING ERRCODE='42501'; END IF;
 IF captured.fits IS DISTINCT FROM true OR captured.bytes IS NULL OR captured.bytes>524288 THEN
  RAISE EXCEPTION 'RELATION_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 PERFORM public.gc_relation_graph_scope_tick(started_at,selected_operation);
 RETURN captured.scope;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_capture_scope(uuid) FROM PUBLIC,gc_app;

CREATE OR REPLACE FUNCTION public.gc_relation_graph_begin(operation_id uuid,idempotency_operation text,idempotency_key text,request_body jsonb,correlation_id text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
<<begin_context>>
DECLARE tenant uuid:=public.gc_tenant(); actor uuid:=public.gc_actor()::uuid; selected_operation uuid:=operation_id;
 request jsonb:=request_body; change_set jsonb:=request_body->'changeSet'; target jsonb; plan jsonb; expected jsonb; before_policy jsonb;
 type_identity uuid; head public.relation_types; prepared public.relation_type_preparations; policy jsonb; mode text;
 asset_row public.assets; before_tuple jsonb; after_tuple jsonb; asset_action text; changed boolean; candidate record; discovered_scope jsonb;
 type_claim public.relation_graph_operation_type_claims; principals uuid[]; source_versions jsonb; migration jsonb;
 remaining_ms bigint; previous_lock_ms bigint; started_at timestamptz:=date_trunc('milliseconds',clock_timestamp()); model_head public.governance_models; old_resolution jsonb; new_resolution jsonb; creation_map jsonb; enrollment_map jsonb;
BEGIN
 PERFORM public.gc_relation_authorize(ARRAY['models:read','models:write','catalog:read','catalog:write']);
 IF operation_id IS NULL OR idempotency_operation IS DISTINCT FROM 'relation-migration.execute'
  OR length(idempotency_key) NOT BETWEEN 8 AND 128 OR correlation_id IS NULL OR length(correlation_id) NOT BETWEEN 1 AND 200
  OR NOT public.gc_relation_keys(request,ARRAY['changeSet','previewDigest']) OR jsonb_typeof(request->'previewDigest')<>'string' OR request->>'previewDigest' !~ '^[a-f0-9]{64}$'
  OR NOT public.gc_relation_keys(change_set,ARRAY['formatVersion','relationTargets','assetChanges','assetTypeMigrations','repairsReceiptId'])
  OR change_set->'formatVersion'<>'1' OR NOT public.gc_relation_json_bounded(request,100000,32,524288)
  OR jsonb_typeof(change_set->'relationTargets')<>'array' OR jsonb_typeof(change_set->'assetChanges')<>'array'
  OR jsonb_typeof(change_set->'assetTypeMigrations')<>'array' OR jsonb_array_length(change_set->'relationTargets')>8
  OR jsonb_array_length(change_set->'assetTypeMigrations')>8 OR jsonb_array_length(change_set->'assetChanges')>1000
  OR jsonb_array_length(change_set->'relationTargets')+jsonb_array_length(change_set->'assetChanges')+jsonb_array_length(change_set->'assetTypeMigrations')=0
  OR (change_set->'repairsReceiptId'<>'null' AND NOT public.gc_relation_uuid_list(jsonb_build_array(change_set->'repairsReceiptId'),1)) THEN
  RAISE EXCEPTION 'Invalid bounded graph operation request' USING ERRCODE='23514'; END IF;
 change_set:=public.gc_relation_graph_normalize_change_set(change_set);
 request:=jsonb_build_object('changeSet',change_set,'previewDigest',request_body->'previewDigest');
 PERFORM public.gc_relation_graph_budget(started_at);
 IF NOT pg_try_advisory_xact_lock(hashtextextended(tenant::text||actor::text||idempotency_operation||idempotency_key,0))
  OR NOT pg_try_advisory_xact_lock(hashtextextended(tenant::text,0))
  OR NOT pg_try_advisory_xact_lock(hashtextextended('governance-models:'||tenant::text,0)) THEN
  RAISE EXCEPTION 'Graph operation requires its ordered execution window' USING ERRCODE='55P03'; END IF;
 IF EXISTS(SELECT 1 FROM public.idempotency i WHERE i.tenant_id=tenant AND i.actor_id=actor::text AND i.operation=idempotency_operation AND i.key=idempotency_key)
  OR (public.gc_relation_graph_current()).id IS NOT NULL THEN RAISE EXCEPTION 'Graph operation cannot reuse an existing execution binding' USING ERRCODE='23514'; END IF;
 IF change_set->'repairsReceiptId'<>'null' THEN PERFORM public.gc_relation_graph_repair_authorize((change_set->>'repairsReceiptId')::uuid); END IF;
 IF (SELECT count(*)<>count(DISTINCT v->>'assetId') FROM jsonb_array_elements(change_set->'assetChanges') e(v))
  OR (SELECT count(*)<>count(DISTINCT v->'definition'->>'id') FROM jsonb_array_elements(change_set->'assetTypeMigrations') e(v)) THEN
  RAISE EXCEPTION 'Duplicate asset change scope' USING ERRCODE='23514'; END IF;
 INSERT INTO public.relation_graph_operations(tenant_id,id,transaction_id,actor_id,state,idempotency_operation,idempotency_key,request_body,normalized_change_set,request_hash,correlation_id,created_at)
 VALUES(tenant,selected_operation,pg_current_xact_id(),actor,'open',idempotency_operation,idempotency_key,request_body,change_set,public.gc_type_migration_hash(request_body),correlation_id,started_at);
 FOR target IN SELECT v FROM jsonb_array_elements(change_set->'relationTargets') e(v) ORDER BY v->'plan'->>'relationTypeId' COLLATE "C" LOOP
  mode:=target->>'kind';plan:=target->'plan';
  IF (mode='create' AND NOT public.gc_relation_uuid_list(jsonb_build_array(target->'reservationId'),1))
   OR (mode<>'create' AND NOT public.gc_relation_positive_integer(target->'expectedHeadVersion')) THEN RAISE EXCEPTION 'Invalid target identity or optimistic head version' USING ERRCODE='23514'; END IF;
  IF NOT public.gc_relation_keys(target,CASE WHEN mode='create' THEN ARRAY['kind','reservationId','expectedHeadVersion','definition','plan'] ELSE ARRAY['kind','expectedHeadVersion','definition','plan'] END)
   OR NOT public.gc_relation_graph_plan_shape(plan,mode) THEN RAISE EXCEPTION 'Invalid complete relation target plan' USING ERRCODE='23514'; END IF;
  type_identity:=(plan->>'relationTypeId')::uuid;
  SELECT * INTO head FROM public.relation_types t WHERE t.tenant_id=tenant AND t.type_id=type_identity;
  IF mode='create' THEN
   PERFORM public.gc_relation_graph_budget(started_at);
   SELECT * INTO prepared FROM public.relation_type_preparations p WHERE p.tenant_id=tenant AND p.id=(target->>'reservationId')::uuid AND p.created_by=actor FOR UPDATE;
   IF prepared.id IS NULL OR prepared.type_id<>type_identity OR prepared.definition IS DISTINCT FROM target->'definition'
    OR prepared.consumed_operation_id IS NOT NULL OR head.id IS NOT NULL OR target->'expectedHeadVersion'<>'null'
    OR EXISTS(SELECT 1 FROM public.relation_types t WHERE t.tenant_id=tenant AND t.id=prepared.logical_key) THEN
    RAISE EXCEPTION 'RELATION_PREPARATION_CONFLICT' USING ERRCODE='23514'; END IF;
   IF clock_timestamp()>=prepared.expires_at THEN RAISE EXCEPTION 'RELATION_PREPARATION_EXPIRED' USING ERRCODE='23514'; END IF;
   policy:=prepared.definition;before_policy:=NULL;
   UPDATE public.relation_type_preparations p SET consumed_operation_id=selected_operation WHERE p.tenant_id=tenant AND p.id=prepared.id;
  ELSE
   IF head.id IS NULL THEN RAISE EXCEPTION 'RELATION_SCOPE_UNAVAILABLE' USING ERRCODE='42501'; END IF;
   IF head.current_version<>(target->>'expectedHeadVersion')::integer THEN RAISE EXCEPTION 'Relation head version conflict' USING ERRCODE='40001'; END IF;
   SELECT v.definition INTO before_policy FROM public.relation_type_versions v WHERE v.tenant_id=tenant AND v.relation_type_id=type_identity AND v.version=head.current_version
    AND v.definition_hash=public.gc_type_migration_hash(v.definition);
   IF before_policy IS NULL THEN RAISE EXCEPTION 'Stored relation head is inconsistent' USING ERRCODE='23514'; END IF;
   IF mode='publish' THEN
    policy:=target->'definition';
    IF NOT public.gc_relation_definition_valid(policy) OR policy->'formatVersion'<>'2' OR policy->>'id'<>head.id
     OR (policy->>'version')::bigint<>head.current_version::bigint+1 THEN RAISE EXCEPTION 'Invalid relation publication target' USING ERRCODE='23514'; END IF;
   ELSE
    IF target->'definition'<>'null' THEN RAISE EXCEPTION 'Repair does not publish a definition' USING ERRCODE='23514'; END IF;
    policy:=before_policy;
   END IF;
  END IF;
  SELECT coalesce(jsonb_agg(v ORDER BY v#>>'{}'),'[]') INTO expected FROM jsonb_array_elements(plan->'acknowledgedPolicyChanges') e(v);
  IF expected IS DISTINCT FROM public.gc_relation_policy_changes(CASE WHEN mode='publish' THEN before_policy ELSE NULL END,policy) THEN
   RAISE EXCEPTION 'Exact relation policy acknowledgements are required' USING ERRCODE='23514'; END IF;
  INSERT INTO public.relation_graph_operation_type_claims(tenant_id,operation_id,relation_type_id,mode,before_version,after_version,before_definition,after_definition,plan)
  VALUES(tenant,selected_operation,type_identity,mode,CASE WHEN mode='create' THEN NULL ELSE head.current_version END,(policy->>'version')::integer,before_policy,policy,plan);
 END LOOP;
 -- Capture the complete authored cohorts, including empty publications.
 FOR migration IN SELECT v FROM jsonb_array_elements(change_set->'assetTypeMigrations') e(v) ORDER BY v->'definition'->>'id' COLLATE "C" LOOP
  IF NOT public.gc_relation_keys(migration,ARRAY['expectedHeadVersion','definition','plan']) OR NOT public.gc_relation_positive_integer(migration->'expectedHeadVersion') THEN RAISE EXCEPTION 'Invalid nested authored migration' USING ERRCODE='23514'; END IF;
  SELECT * INTO model_head FROM public.governance_models m WHERE m.tenant_id=tenant AND m.id=migration->'definition'->>'id';
  IF model_head.id IS NULL OR model_head.type_id IS NULL OR model_head.current_version<>(migration->>'expectedHeadVersion')::integer
   OR model_head.type_id::text<>migration->'plan'->>'typeId' THEN RAISE EXCEPTION 'Nested authored migration head is unavailable or stale' USING ERRCODE='40001'; END IF;
  old_resolution:=public.gc_relation_graph_asset_policy(model_head.id,model_head.current_version,jsonb_build_object('changeSet',jsonb_build_object('assetTypeMigrations','[]'::jsonb)));
  new_resolution:=public.gc_relation_graph_resolve_asset(migration->'definition');
  IF (new_resolution->'definition'->>'version')::bigint<>model_head.current_version::bigint+1 THEN RAISE EXCEPTION 'Nested authored migration advances exactly once' USING ERRCODE='23514'; END IF;
  INSERT INTO public.relation_graph_operation_model_claims(tenant_id,operation_id,model_id,type_id,before_version,after_version,before_resolution,after_resolution,plan)
  VALUES(tenant,selected_operation,model_head.id,model_head.type_id,model_head.current_version,(new_resolution->'definition'->>'version')::integer,old_resolution,new_resolution,migration->'plan');
 END LOOP;
 -- First discover changes without row locks; the tenant ledger fences all
 -- canonical writers. Row locks are taken only after the entire union is known.
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(change_set->'assetChanges') e(v) WHERE NOT EXISTS(
  SELECT 1 FROM public.assets a WHERE a.tenant_id=tenant AND a.id=(v->>'assetId')::uuid)) THEN
  RAISE EXCEPTION 'RELATION_SCOPE_UNAVAILABLE' USING ERRCODE='42501'; END IF;
 -- One materialized closure supplies authorization, conditional scalar preflight
 -- and bounded identities. Counts are not evaluated for hidden cohorts.
 discovered_scope:=public.gc_relation_graph_capture_scope(selected_operation);
 PERFORM public.gc_relation_graph_charge(selected_operation,discovered_scope);
 -- Only the fully authorized, physically bounded identity scope is retained.
 INSERT INTO public.relation_graph_operation_asset_scope(tenant_id,operation_id,asset_id,action,projected_endpoint)
 SELECT tenant,selected_operation,a.id,c.action,public.gc_relation_graph_scope_project(a.id,a.version,a.model_id,a.model_version,a.type_state,request,started_at)
  FROM jsonb_to_recordset(discovered_scope->'assets') AS c(asset_id uuid,action text) JOIN public.assets a ON a.tenant_id=tenant AND a.id=c.asset_id;
 FOR candidate IN SELECT t.*,v.definition FROM jsonb_array_elements_text(discovered_scope->'types') AS ids(relation_type_id)
  JOIN public.relation_types t ON t.tenant_id=tenant AND t.type_id=ids.relation_type_id::uuid
  JOIN public.relation_type_versions v ON v.tenant_id=t.tenant_id AND v.relation_type_id=t.type_id AND v.version=t.current_version
  WHERE NOT EXISTS(SELECT 1 FROM public.relation_graph_operation_type_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.relation_type_id=t.type_id)
  ORDER BY t.id COLLATE "C" LOOP
  INSERT INTO public.relation_graph_operation_type_claims(tenant_id,operation_id,relation_type_id,mode,before_version,after_version,before_definition,after_definition)
  VALUES(tenant,selected_operation,candidate.type_id,'validation',candidate.current_version,candidate.current_version,candidate.definition,candidate.definition);
 END LOOP;
 PERFORM public.gc_relation_graph_charge(selected_operation,request_body);
 PERFORM public.gc_relation_graph_charge(selected_operation,request);
 FOR candidate IN SELECT c.before_definition,c.after_definition FROM public.relation_graph_operation_type_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation LOOP
  PERFORM public.gc_relation_graph_charge(selected_operation,to_jsonb(candidate));
 END LOOP;
 FOR candidate IN SELECT c.before_resolution,c.after_resolution FROM public.relation_graph_operation_model_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation LOOP
  PERFORM public.gc_relation_graph_charge(selected_operation,to_jsonb(candidate));
 END LOOP;
 FOR asset_row IN SELECT a.* FROM public.assets a JOIN public.relation_graph_operation_asset_scope s ON s.tenant_id=a.tenant_id AND s.asset_id=a.id
  WHERE s.tenant_id=tenant AND s.operation_id=selected_operation ORDER BY a.id LOOP
  SELECT s.action INTO asset_action FROM public.relation_graph_operation_asset_scope s WHERE s.tenant_id=tenant AND s.operation_id=selected_operation AND s.asset_id=asset_row.id;
  before_tuple:=public.gc_relation_asset_tuple(asset_row);after_tuple:=public.gc_relation_graph_project_asset(asset_row,request);
  PERFORM public.gc_relation_graph_charge(selected_operation,jsonb_build_object('before',before_tuple,'after',after_tuple,'name',asset_row.name,'allowedIdentityIds',asset_row.allowed_identities));
  INSERT INTO public.relation_graph_operation_asset_claims(tenant_id,operation_id,asset_id,action,before_row,before_tuple,after_tuple,from_version,to_version,consumed)
  VALUES(tenant,selected_operation,asset_row.id,asset_action,public.gc_relation_graph_asset_row(asset_row),before_tuple,after_tuple,asset_row.version,
   asset_row.version+CASE WHEN asset_action='preserve' THEN 0 ELSE 1 END,asset_action='preserve');
 END LOOP;
 -- The complete canonical row union precedes the one global principal phase.
 PERFORM public.gc_relation_graph_budget(started_at);
 PERFORM m.id FROM public.governance_models m JOIN public.relation_graph_operation_model_claims c ON c.tenant_id=m.tenant_id AND c.model_id=m.id
  WHERE c.tenant_id=tenant AND c.operation_id=selected_operation ORDER BY m.id COLLATE "C" FOR UPDATE OF m;
 PERFORM public.gc_relation_graph_budget(started_at);
 PERFORM t.type_id FROM public.relation_types t JOIN public.relation_graph_operation_type_claims c ON c.tenant_id=t.tenant_id AND c.relation_type_id=t.type_id
  WHERE c.tenant_id=tenant AND c.operation_id=selected_operation ORDER BY t.id COLLATE "C" FOR UPDATE OF t;
 PERFORM public.gc_relation_graph_budget(started_at);
 PERFORM a.id FROM public.assets a JOIN public.relation_graph_operation_asset_claims c ON c.tenant_id=a.tenant_id AND c.asset_id=a.id
  WHERE c.tenant_id=tenant AND c.operation_id=selected_operation ORDER BY a.id FOR UPDATE OF a;
 PERFORM public.gc_relation_graph_budget(started_at);
 PERFORM r.id FROM public.relations r JOIN public.relation_graph_operation_type_claims c ON c.tenant_id=r.tenant_id AND c.relation_type_id=r.relation_type_id
  WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND r.status='active' ORDER BY r.id FOR UPDATE OF r;
 PERFORM public.gc_relation_graph_budget(started_at);
 PERFORM b.id FROM public.relation_participations b JOIN public.relation_graph_operation_type_claims c ON c.tenant_id=b.tenant_id AND c.relation_type_id=b.relation_type_id
  WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND b.status='active' ORDER BY b.id FOR UPDATE OF b;
 -- Principal paths are schema-owned. Governed attributes may legitimately use
 -- names such as ownerId/allowedIdentityIds and must never become authority.
 WITH values_to_lock(value) AS (
  SELECT e.v->'values' FROM jsonb_array_elements(change_set->'relationTargets') t(v)
   CROSS JOIN LATERAL jsonb_array_elements(t.v->'plan'->'edges') e(v) WHERE e.v->>'action' IN('repair','repin')
  UNION ALL SELECT e.v->'values' FROM jsonb_array_elements(change_set->'relationTargets') t(v)
   CROSS JOIN LATERAL jsonb_array_elements(t.v->'plan'->'creations') e(v)
 ), requested AS (
  SELECT actor AS id
  UNION SELECT (e.v->>'ownerId')::uuid FROM jsonb_array_elements(change_set->'assetChanges') e(v) WHERE e.v->>'kind'='assign'
  UNION SELECT (e.v->>'ownerId')::uuid FROM jsonb_array_elements(change_set->'assetTypeMigrations') t(v)
   CROSS JOIN LATERAL jsonb_array_elements(t.v->'plan'->'owner'->'overrides') e(v)
  UNION SELECT (e.v->>'ownerId')::uuid FROM jsonb_array_elements(change_set->'relationTargets') t(v)
   CROSS JOIN LATERAL jsonb_array_elements(coalesce(nullif(t.v->'plan'->'transform','null')->'owner'->'overrides','[]')) e(v)
  UNION SELECT (value->>'ownerId')::uuid FROM values_to_lock
  UNION SELECT v::uuid FROM values_to_lock CROSS JOIN LATERAL jsonb_array_elements_text(value->'allowedIdentityIds') e(v)
  UNION SELECT (a.before_tuple->>'ownerId')::uuid FROM public.relation_graph_operation_asset_claims a WHERE a.tenant_id=tenant AND a.operation_id=selected_operation
  UNION SELECT v::uuid FROM public.relation_graph_operation_asset_claims a CROSS JOIN LATERAL jsonb_array_elements_text(a.before_row->'allowed_identities') e(v) WHERE a.tenant_id=tenant AND a.operation_id=selected_operation
  UNION SELECT r.owner_id FROM public.relations r JOIN public.relation_graph_operation_type_claims t ON t.tenant_id=r.tenant_id AND t.relation_type_id=r.relation_type_id WHERE t.tenant_id=tenant AND t.operation_id=selected_operation AND r.status='active'
  UNION SELECT v::uuid FROM public.relations r JOIN public.relation_graph_operation_type_claims t ON t.tenant_id=r.tenant_id AND t.relation_type_id=r.relation_type_id
   CROSS JOIN LATERAL jsonb_array_elements_text(r.allowed_identities) e(v) WHERE t.tenant_id=tenant AND t.operation_id=selected_operation AND r.status='active'
 ) SELECT array_agg(id ORDER BY id) INTO principals FROM requested WHERE id IS NOT NULL;
 IF cardinality(principals)>2001 THEN RAISE EXCEPTION 'RELATION_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 PERFORM public.gc_relation_graph_budget(started_at);
 PERFORM public.gc_lock_type_migration_principals(principals);
 PERFORM public.gc_relation_authorize(ARRAY['models:read','models:write','catalog:read','catalog:write']);
 UPDATE public.relation_graph_operations o SET principals=begin_context.principals WHERE o.tenant_id=tenant AND o.id=selected_operation;
 PERFORM public.gc_relation_graph_validate_intents(selected_operation);
 FOR type_claim IN SELECT * FROM public.relation_graph_operation_type_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation ORDER BY c.relation_type_id LOOP
  IF type_claim.mode<>'create' THEN PERFORM public.gc_relation_check_type(tenant,type_claim.relation_type_id); END IF;
  SELECT coalesce(jsonb_agg(version ORDER BY version),'[]') INTO source_versions FROM (
   SELECT r.relation_type_version AS version FROM public.relations r WHERE r.tenant_id=tenant AND r.relation_type_id=type_claim.relation_type_id AND r.status='active'
   UNION SELECT b.relation_type_version FROM public.relation_participations b WHERE b.tenant_id=tenant AND b.relation_type_id=type_claim.relation_type_id AND b.status='active') versions;
  IF type_claim.mode<>'validation' AND type_claim.plan->'sourceVersions' IS DISTINCT FROM source_versions THEN
   RAISE EXCEPTION 'Declared source versions must equal the exact edge and binding union' USING ERRCODE='23514'; END IF;
  PERFORM public.gc_relation_graph_install_edges(selected_operation,type_claim);
  PERFORM public.gc_relation_graph_install_bindings(selected_operation,type_claim);
 END LOOP;
 SELECT coalesce(jsonb_agg(jsonb_build_object('relationTypeId',c.relation_type_id,'key',c.key->'key','relationId',c.relation_id) ORDER BY c.relation_type_id,c.key->>'key'),'[]') INTO creation_map
  FROM public.relation_graph_operation_edge_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.action='create';
 SELECT coalesce(jsonb_agg(jsonb_build_object('relationTypeId',c.relation_type_id,'assetId',c.after_tuple->'assetId','side',c.after_tuple->'side','bindingId',c.binding_id)
  ORDER BY c.relation_type_id,c.after_tuple->>'assetId',c.after_tuple->>'side'),'[]') INTO enrollment_map
  FROM public.relation_graph_operation_binding_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.action='enroll';
 IF NOT EXISTS(SELECT 1 FROM public.relation_graph_operation_type_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.mode IN ('create','publish'))
  AND NOT EXISTS(SELECT 1 FROM public.relation_graph_operation_asset_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.action<>'preserve')
  AND NOT EXISTS(SELECT 1 FROM public.relation_graph_operation_model_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation)
  AND NOT EXISTS(SELECT 1 FROM public.relation_graph_operation_edge_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.action<>'preserve')
  AND NOT EXISTS(SELECT 1 FROM public.relation_graph_operation_binding_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.action<>'preserve') THEN
  RAISE EXCEPTION 'An empty graph repair cannot create a receipt' USING ERRCODE='23514'; END IF;
 INSERT INTO public.relation_graph_operation_journal_claims(tenant_id,operation_id,action,resource_id,resource_version)
 SELECT tenant,selected_operation,'relation_migration.executed',selected_operation::text,1
 UNION ALL SELECT tenant,selected_operation,CASE c.action WHEN 'assign' THEN 'asset.model_assigned' WHEN 'transition' THEN 'asset.type_transitioned' ELSE 'asset.type_migrated' END,c.asset_id::text,c.to_version
  FROM public.relation_graph_operation_asset_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.action<>'preserve'
 UNION ALL SELECT tenant,selected_operation,CASE WHEN c.action='create' THEN 'relation.created' WHEN c.action IN ('tombstone','replace') THEN 'relation.tombstoned'
   WHEN c.before_tuple->'values'->'state' IS DISTINCT FROM c.after_tuple->'values'->'state' THEN 'relation.transitioned' ELSE 'relation.updated' END,c.relation_id::text,c.to_version
  FROM public.relation_graph_operation_edge_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.action<>'preserve'
 UNION ALL SELECT tenant,selected_operation,CASE c.action WHEN 'enroll' THEN 'relation_participation.enrolled' WHEN 'repin' THEN 'relation_participation.repinned' ELSE 'relation_participation.released' END,c.binding_id::text,c.to_version
  FROM public.relation_graph_operation_binding_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.action<>'preserve'
 UNION ALL SELECT tenant,selected_operation,CASE c.mode WHEN 'create' THEN 'relation_type.created' ELSE 'relation_type.published' END,c.after_definition->>'id',c.after_version
  FROM public.relation_graph_operation_type_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.mode IN ('create','publish')
 UNION ALL SELECT tenant,selected_operation,'model.type_migrated',c.model_id,c.after_version FROM public.relation_graph_operation_model_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation;
 RETURN jsonb_build_object('operation',jsonb_build_object('id',selected_operation),'creations',creation_map,'enrollments',enrollment_map,
  'typeMigrations',(SELECT coalesce(jsonb_agg(jsonb_build_object('modelId',c.model_id,'migrationId',c.migration_id) ORDER BY c.model_id COLLATE "C"),'[]')
   FROM public.relation_graph_operation_model_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation));
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_begin(uuid,text,text,jsonb,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_graph_begin(uuid,text,text,jsonb,text) TO gc_app;
