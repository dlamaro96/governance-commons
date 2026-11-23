-- SPDX-License-Identifier: Apache-2.0
-- Forward correction for repeated glossary evidence and final graph checks.
-- Nominal candidates only avoid unrelated assets. Exact eligibility, authority,
-- explicit incident scope, publication clocks and final constraints are unchanged.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR pg_has_role('gc_app',current_user,'MEMBER') THEN
  RAISE EXCEPTION 'Scope optimization requires a non-bypass migration owner' USING ERRCODE='42501'; END IF;
END $$;

CREATE FUNCTION public.gc_relation_nominal_candidates(definition jsonb) RETURNS TABLE(asset_id uuid)
LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 WITH rules AS MATERIALIZED (
  SELECT DISTINCT (rule->>'typeId')::uuid AS type_id,rule->>'includeDescendants'='true' AS descendants
  FROM jsonb_array_elements(coalesce(definition->'sourceTypes','[]'::jsonb)||coalesce(definition->'targetTypes','[]'::jsonb)) e(rule)
 )
 SELECT a.id FROM rules r JOIN public.governance_models m ON m.tenant_id=public.gc_tenant() AND m.type_id=r.type_id
  JOIN public.assets a ON a.tenant_id=m.tenant_id AND a.model_id=m.id
 UNION
 SELECT a.id FROM rules r JOIN public.governance_models m ON m.tenant_id=public.gc_tenant() AND m.type_id=r.type_id
  JOIN public.asset_type_dependencies d ON d.tenant_id=m.tenant_id AND d.dependency_model_id=m.id
  JOIN public.assets a ON a.tenant_id=d.tenant_id AND a.model_id=d.model_id AND a.model_version=d.version WHERE r.descendants
$$;
REVOKE ALL ON FUNCTION public.gc_relation_nominal_candidates(jsonb) FROM PUBLIC,gc_app;


CREATE OR REPLACE FUNCTION public.gc_glossary_prepare(request_identity uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant(); actor uuid:=public.gc_actor()::uuid; request public.approval_requests; result public.glossary_publications;
 before_asset public.assets; prior uuid; type_ids uuid[]; asset_ids uuid[]; principals uuid[]; audience uuid[]; item uuid;
 before_endpoint jsonb; after_endpoint jsonb; baseline jsonb; definition jsonb; started timestamptz:=date_trunc('milliseconds',clock_timestamp());
 empty_request jsonb:='{"changeSet":{"assetTypeMigrations":[]}}'; BEGIN
 PERFORM public.gc_relation_authorize(ARRAY['catalog:read','catalog:write','models:read','models:write']);
 -- Match graph once() ordering and refuse a conflicting execution window before
 -- taking the tenant ledger, never introduce a ledger/idempotency inversion.
 IF NOT pg_try_advisory_xact_lock(hashtextextended(tenant::text||actor::text||'relation-migration.execute'||'glossary:'||request_identity::text,0))
 OR NOT pg_try_advisory_xact_lock(hashtextextended(tenant::text,0))
 OR NOT pg_try_advisory_xact_lock(hashtextextended('governance-models:'||tenant::text,0)) THEN RAISE EXCEPTION 'GLOSSARY_RETRY' USING ERRCODE='55P03'; END IF;
 SELECT * INTO request FROM public.approval_requests WHERE tenant_id=tenant AND id=request_identity FOR UPDATE;
 IF request.id IS NULL OR request.requester_id<>actor THEN RAISE EXCEPTION 'GLOSSARY_UNAVAILABLE' USING ERRCODE='P0002'; END IF;
 SELECT * INTO result FROM public.glossary_publications WHERE tenant_id=tenant AND id=request_identity;
 IF result.id IS NOT NULL THEN
  IF result.state<>'sealed' THEN RAISE EXCEPTION 'GLOSSARY_STATE_CONFLICT' USING ERRCODE='40001'; END IF;
  SELECT array_agg(DISTINCT id ORDER BY id) INTO audience FROM (SELECT actor AS id UNION SELECT assigned_identity_id FROM public.approval_tasks WHERE tenant_id=tenant AND request_id=request_identity) a;
  PERFORM public.gc_lock_type_migration_principals(audience);
  PERFORM public.gc_relation_authorize(ARRAY['catalog:read','catalog:write','models:read','models:write']);
  IF request.status<>'succeeded' OR request.result IS DISTINCT FROM result.receipt
  OR EXISTS(SELECT 1 FROM unnest(audience) a(id) WHERE NOT EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id WHERE m.tenant_id=tenant AND m.identity_id=a.id AND m.active AND i.active AND m.permissions @> '["catalog:read","catalog:write"]'::jsonb))
  OR NOT EXISTS(SELECT 1 FROM public.assets a WHERE a.tenant_id=tenant AND a.id=result.asset_id AND a.status='active' AND (a.visibility='tenant' OR a.allowed_identities @> jsonb_build_array(actor::text)))
  OR EXISTS(SELECT 1 FROM public.glossary_publication_links l WHERE l.tenant_id=tenant AND l.publication_id=result.id AND (
   NOT EXISTS(SELECT 1 FROM public.assets a WHERE a.tenant_id=tenant AND a.id=l.target_asset_id AND a.status='active' AND (a.visibility='tenant' OR a.allowed_identities @> jsonb_build_array(actor::text)))
   OR NOT EXISTS(SELECT 1 FROM public.relations r WHERE r.tenant_id=tenant AND r.id=l.relation_id AND (r.visibility='tenant' OR r.allowed_identities @> jsonb_build_array(actor::text)))))
  THEN RAISE EXCEPTION 'GLOSSARY_AUTHORITY_REVOKED' USING ERRCODE='42501'; END IF;
  RETURN public.gc_glossary_context(result); END IF;
 IF request.status<>'ready' OR request.binding<>'glossary.publish' OR request.expires_at<=clock_timestamp()
 OR (public.gc_relation_graph_current()).id IS NOT NULL OR (public.gc_glossary_current()).id IS NOT NULL THEN
  RAISE EXCEPTION 'GLOSSARY_STATE_CONFLICT' USING ERRCODE='40001'; END IF;
 IF (request.resource_version IS NOT NULL AND NOT EXISTS(SELECT 1 FROM public.assets a WHERE a.tenant_id=tenant AND a.id=request.resource_id AND (a.visibility='tenant' OR a.allowed_identities @> jsonb_build_array(actor::text))))
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(request.payload->'links')='array' THEN request.payload->'links' ELSE '[]'::jsonb END) l WHERE NOT EXISTS(SELECT 1 FROM public.assets a WHERE a.tenant_id=tenant AND a.id::text=l->>'targetAssetId' AND (a.visibility='tenant' OR a.allowed_identities @> jsonb_build_array(actor::text))))
 THEN RAISE EXCEPTION 'GLOSSARY_UNAVAILABLE' USING ERRCODE='P0002'; END IF;
 IF EXISTS(SELECT 1 FROM public.assets a WHERE a.tenant_id=tenant AND (a.id=request.resource_id OR a.id::text IN(SELECT l->>'targetAssetId' FROM jsonb_array_elements(CASE WHEN jsonb_typeof(request.payload->'links')='array' THEN request.payload->'links' ELSE '[]'::jsonb END) l)) AND octet_length(to_jsonb(a)::text)>524288)
 THEN RAISE EXCEPTION 'GLOSSARY_LIMIT' USING ERRCODE='54000'; END IF;
 PERFORM public.gc_glossary_payload_check(request);
 SELECT * INTO before_asset FROM public.assets a WHERE a.tenant_id=tenant AND a.id=request.resource_id;
 IF before_asset.id IS NOT NULL THEN before_endpoint:=public.gc_relation_graph_endpoint(before_asset.id,before_asset.version,public.gc_relation_asset_tuple(before_asset),empty_request); END IF;
 after_endpoint:=public.gc_relation_graph_endpoint(request.resource_id,coalesce(request.resource_version,0)+1,
  jsonb_build_object('modelId',request.payload#>'{typePin,modelId}','modelVersion',request.payload#>'{typePin,version}','state',request.payload->'state'),empty_request);
 SELECT current_publication_id INTO prior FROM public.glossary_terms WHERE tenant_id=tenant AND asset_id=request.resource_id;
 SELECT coalesce(array_agg(DISTINCT id ORDER BY id),'{}'::uuid[]) INTO type_ids FROM (
  SELECT h.type_id AS id FROM public.relation_types h JOIN public.relation_type_versions v ON v.tenant_id=h.tenant_id AND v.relation_type_id=h.type_id AND v.version=h.current_version
   WHERE h.tenant_id=tenant AND public.gc_relation_graph_scope_tick(started,h.type_id) AND (public.gc_relation_projected_eligible(before_endpoint,v.definition,'source') OR public.gc_relation_projected_eligible(before_endpoint,v.definition,'target')
    OR public.gc_relation_projected_eligible(after_endpoint,v.definition,'source') OR public.gc_relation_projected_eligible(after_endpoint,v.definition,'target'))
  UNION SELECT relation_type_id FROM public.relations WHERE tenant_id=tenant AND status='active' AND request.resource_id IN(source_asset_id,target_asset_id)
  UNION SELECT relation_type_id FROM public.relation_participations WHERE tenant_id=tenant AND status='active' AND asset_id=request.resource_id
  UNION SELECT (l#>>'{typePin,relationTypeId}')::uuid FROM jsonb_array_elements(request.payload->'links') l
  UNION SELECT relation_type_id FROM public.glossary_publication_links WHERE tenant_id=tenant AND publication_id=prior
 ) types;
 SELECT coalesce(array_agg(DISTINCT id ORDER BY id),'{}'::uuid[]) INTO asset_ids FROM (
  SELECT request.resource_id AS id UNION SELECT (l->>'targetAssetId')::uuid FROM jsonb_array_elements(request.payload->'links') l
  UNION SELECT eligible.asset_id FROM (
   WITH candidates AS MATERIALIZED (SELECT c.asset_id,v.definition FROM public.relation_types h
    JOIN public.relation_type_versions v ON v.tenant_id=h.tenant_id AND v.relation_type_id=h.type_id AND v.version=h.current_version
    CROSS JOIN LATERAL public.gc_relation_nominal_candidates(v.definition) c WHERE h.tenant_id=tenant AND h.type_id=ANY(type_ids))
   SELECT c.asset_id FROM candidates c WHERE public.gc_relation_graph_scope_eligible(tenant,c.asset_id,c.definition,'source',started)
    OR public.gc_relation_graph_scope_eligible(tenant,c.asset_id,c.definition,'target',started)
  ) eligible
  UNION SELECT source_asset_id FROM public.relations WHERE tenant_id=tenant AND relation_type_id=ANY(type_ids) AND status='active'
  UNION SELECT target_asset_id FROM public.relations WHERE tenant_id=tenant AND relation_type_id=ANY(type_ids) AND status='active'
  UNION SELECT asset_id FROM public.relation_participations WHERE tenant_id=tenant AND relation_type_id=ANY(type_ids) AND status='active'
 ) assets;
 IF EXISTS(SELECT 1 FROM public.assets a WHERE a.tenant_id=tenant AND a.id=ANY(asset_ids) AND a.visibility='restricted' AND NOT a.allowed_identities @> jsonb_build_array(actor::text))
 OR EXISTS(SELECT 1 FROM public.relations r WHERE r.tenant_id=tenant AND r.relation_type_id=ANY(type_ids) AND r.status='active' AND r.visibility='restricted' AND NOT r.allowed_identities @> jsonb_build_array(actor::text)) THEN
  RAISE EXCEPTION 'GLOSSARY_SCOPE_UNAVAILABLE' USING ERRCODE='42501'; END IF;
 IF cardinality(asset_ids)>2000 OR cardinality(type_ids)>1000
 OR (SELECT count(*) FROM public.relations WHERE tenant_id=tenant AND relation_type_id=ANY(type_ids) AND status='active')>1000
 OR (SELECT count(*) FROM public.relation_participations WHERE tenant_id=tenant AND relation_type_id=ANY(type_ids) AND status='active')>4000 THEN RAISE EXCEPTION 'GLOSSARY_LIMIT' USING ERRCODE='54000'; END IF;
 PERFORM public.gc_relation_graph_budget(started);
 PERFORM m.id FROM public.governance_models m WHERE m.tenant_id=tenant AND (m.id=request.payload#>>'{typePin,modelId}' OR m.id IN(SELECT a.model_id FROM public.assets a WHERE a.tenant_id=tenant AND a.id=ANY(asset_ids))) ORDER BY m.id COLLATE "C" FOR UPDATE;
 PERFORM type_id FROM public.relation_types WHERE tenant_id=tenant AND type_id=ANY(type_ids) ORDER BY id COLLATE "C" FOR UPDATE;
 PERFORM id FROM public.assets WHERE tenant_id=tenant AND id=ANY(asset_ids) ORDER BY id FOR UPDATE;
 PERFORM id FROM public.relations WHERE tenant_id=tenant AND relation_type_id=ANY(type_ids) AND status='active' ORDER BY id FOR UPDATE;
 PERFORM id FROM public.relation_participations WHERE tenant_id=tenant AND relation_type_id=ANY(type_ids) AND status='active' ORDER BY id FOR UPDATE;
 SELECT array_agg(DISTINCT id ORDER BY id) INTO audience FROM (SELECT actor AS id UNION SELECT assigned_identity_id FROM public.approval_tasks WHERE tenant_id=tenant AND request_id=request_identity) a;
 SELECT array_agg(DISTINCT id ORDER BY id) INTO principals FROM (
  SELECT unnest(audience) AS id UNION SELECT (request.payload->>'ownerId')::uuid
  UNION SELECT v::uuid FROM jsonb_array_elements_text(request.payload->'allowedIdentityIds') v
  UNION SELECT owner_id FROM public.assets WHERE tenant_id=tenant AND id=ANY(asset_ids)
  UNION SELECT v::uuid FROM public.assets a CROSS JOIN LATERAL jsonb_array_elements_text(a.allowed_identities) v WHERE a.tenant_id=tenant AND a.id=ANY(asset_ids)
  UNION SELECT owner_id FROM public.relations WHERE tenant_id=tenant AND relation_type_id=ANY(type_ids) AND status='active'
  UNION SELECT v::uuid FROM public.relations r CROSS JOIN LATERAL jsonb_array_elements_text(r.allowed_identities) v WHERE r.tenant_id=tenant AND r.relation_type_id=ANY(type_ids) AND r.status='active'
 ) p WHERE id IS NOT NULL;
 IF cardinality(principals)>2001 THEN RAISE EXCEPTION 'GLOSSARY_LIMIT' USING ERRCODE='54000'; END IF;
 PERFORM public.gc_lock_type_migration_principals(principals);
 PERFORM public.gc_relation_authorize(ARRAY['catalog:read','catalog:write','models:read','models:write']);
 IF EXISTS(SELECT 1 FROM unnest(audience) a(id) WHERE NOT EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id WHERE m.tenant_id=tenant AND m.identity_id=a.id AND m.active AND i.active AND m.permissions @> '["catalog:read","catalog:write"]'::jsonb))
 OR NOT EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id WHERE m.tenant_id=tenant AND m.identity_id=(request.payload->>'ownerId')::uuid AND m.active AND i.active)
 OR (request.payload->>'visibility'='restricted' AND EXISTS(SELECT 1 FROM unnest(audience) a(id) WHERE NOT request.payload->'allowedIdentityIds' @> jsonb_build_array(a.id::text)))
 OR EXISTS(SELECT 1 FROM public.assets a CROSS JOIN unnest(audience) viewer(id) WHERE a.tenant_id=tenant AND (a.id=request.resource_id OR a.id IN(SELECT (l->>'targetAssetId')::uuid FROM jsonb_array_elements(request.payload->'links') l)) AND a.visibility='restricted' AND NOT a.allowed_identities @> jsonb_build_array(viewer.id::text))
 THEN RAISE EXCEPTION 'GLOSSARY_AUTHORITY_REVOKED' USING ERRCODE='42501'; END IF;
 SELECT v.definition INTO definition FROM public.workflow_definition_versions v WHERE v.tenant_id=tenant AND v.workflow_id=request.workflow_id AND v.version=request.workflow_version AND v.definition_hash=request.workflow_hash;
 IF definition IS NULL OR request.expires_at<=clock_timestamp() OR (definition->>'separationOfDuties'='true' AND EXISTS(SELECT 1 FROM public.approval_tasks WHERE tenant_id=tenant AND request_id=request_identity AND assigned_identity_id=actor))
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(definition->'stages') WITH ORDINALITY s(v,n) WHERE (SELECT count(*) FROM public.approval_decisions d JOIN public.approval_tasks t ON t.tenant_id=d.tenant_id AND t.id=d.task_id WHERE d.tenant_id=tenant AND d.request_id=request_identity AND t.stage_index=s.n-1 AND d.decision='approve' AND d.actor_id=t.assigned_identity_id AND d.proposal_digest=request.proposal_digest)<(s.v->>'quorum')::integer)
 OR EXISTS(SELECT 1 FROM public.approval_decisions WHERE tenant_id=tenant AND request_id=request_identity AND decision='reject') THEN RAISE EXCEPTION 'GLOSSARY_APPROVAL_INVALID' USING ERRCODE='23514'; END IF;
 PERFORM public.gc_glossary_payload_check(request);
 FOREACH item IN ARRAY type_ids LOOP PERFORM public.gc_relation_graph_budget(started);PERFORM public.gc_relation_check_type(tenant,item); END LOOP;
 baseline:=public.gc_glossary_snapshot(type_ids,asset_ids,NULL,request.payload#>>'{typePin,modelId}');
 IF octet_length(baseline::text)>524288 THEN RAISE EXCEPTION 'GLOSSARY_LIMIT' USING ERRCODE='54000'; END IF;
 INSERT INTO public.glossary_publications(tenant_id,id,asset_id,asset_version,previous_publication_id,payload,proposal_digest,workflow_id,workflow_version,workflow_hash,actor_id,transaction_id,started_at,state,relation_type_ids,asset_ids,before_endpoint,after_endpoint,baseline)
 VALUES(tenant,request.id,request.resource_id,coalesce(request.resource_version,0)+1,prior,request.payload,request.proposal_digest,request.workflow_id,request.workflow_version,request.workflow_hash,actor,pg_current_xact_id(),started,'prepared',type_ids,asset_ids,before_endpoint,after_endpoint,baseline) RETURNING * INTO result;
 RETURN public.gc_glossary_context(result);
END $$;

CREATE OR REPLACE FUNCTION public.gc_glossary_graph_source_evidence(publication_identity uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE p public.glossary_publications; baseline jsonb; actual public.assets; tenant uuid:=public.gc_tenant(); type_ids uuid[]; asset_ids uuid[]; BEGIN
 p:=public.gc_glossary_current();PERFORM public.gc_glossary_budget(p);
 IF p.id IS DISTINCT FROM publication_identity OR p.state<>'staged' THEN RAISE EXCEPTION 'GLOSSARY_CONTEXT_REQUIRED' USING ERRCODE='42501'; END IF;
 SELECT coalesce(array_agg(DISTINCT id ORDER BY id),'{}'::uuid[]) INTO type_ids FROM (
  SELECT h.type_id AS id FROM public.relation_types h JOIN public.relation_type_versions v ON v.tenant_id=h.tenant_id AND v.relation_type_id=h.type_id AND v.version=h.current_version
   WHERE h.tenant_id=tenant AND public.gc_relation_graph_scope_tick(p.started_at,h.type_id) AND (public.gc_relation_projected_eligible(p.before_endpoint,v.definition,'source') OR public.gc_relation_projected_eligible(p.before_endpoint,v.definition,'target')
    OR public.gc_relation_projected_eligible(p.after_endpoint,v.definition,'source') OR public.gc_relation_projected_eligible(p.after_endpoint,v.definition,'target'))
  UNION SELECT relation_type_id FROM public.relations WHERE tenant_id=tenant AND status='active' AND p.asset_id IN(source_asset_id,target_asset_id)
  UNION SELECT relation_type_id FROM public.relation_participations WHERE tenant_id=tenant AND status='active' AND asset_id=p.asset_id
  UNION SELECT (l#>>'{typePin,relationTypeId}')::uuid FROM jsonb_array_elements(p.payload->'links') l
  UNION SELECT relation_type_id FROM public.glossary_publication_links WHERE tenant_id=tenant AND publication_id=p.previous_publication_id
 ) types;
 SELECT coalesce(array_agg(DISTINCT id ORDER BY id),'{}'::uuid[]) INTO asset_ids FROM (
  SELECT p.asset_id AS id UNION SELECT (l->>'targetAssetId')::uuid FROM jsonb_array_elements(p.payload->'links') l
  UNION SELECT eligible.asset_id FROM (
   WITH candidates AS MATERIALIZED (SELECT c.asset_id,v.definition FROM public.relation_types h
    JOIN public.relation_type_versions v ON v.tenant_id=h.tenant_id AND v.relation_type_id=h.type_id AND v.version=h.current_version
    CROSS JOIN LATERAL public.gc_relation_nominal_candidates(v.definition) c WHERE h.tenant_id=tenant AND h.type_id=ANY(type_ids))
   SELECT c.asset_id FROM candidates c WHERE public.gc_relation_graph_scope_eligible(tenant,c.asset_id,c.definition,'source',p.started_at)
    OR public.gc_relation_graph_scope_eligible(tenant,c.asset_id,c.definition,'target',p.started_at)
  ) eligible
  UNION SELECT source_asset_id FROM public.relations WHERE tenant_id=tenant AND relation_type_id=ANY(type_ids) AND status='active'
  UNION SELECT target_asset_id FROM public.relations WHERE tenant_id=tenant AND relation_type_id=ANY(type_ids) AND status='active'
  UNION SELECT asset_id FROM public.relation_participations WHERE tenant_id=tenant AND relation_type_id=ANY(type_ids) AND status='active'
 ) assets;
 IF type_ids IS DISTINCT FROM p.relation_type_ids OR asset_ids IS DISTINCT FROM p.asset_ids THEN RAISE EXCEPTION 'GLOSSARY_SOURCE_CHANGED' USING ERRCODE='40001'; END IF;
 baseline:=jsonb_set(p.baseline,'{assets}',coalesce((SELECT jsonb_agg(a ORDER BY a->>'id') FROM jsonb_array_elements(p.baseline->'assets') a WHERE a->>'id'<>p.asset_id::text),'[]'::jsonb));
 IF public.gc_glossary_snapshot(p.relation_type_ids,p.asset_ids,p.asset_id,p.payload#>>'{typePin,modelId}') IS DISTINCT FROM baseline THEN RAISE EXCEPTION 'GLOSSARY_SOURCE_CHANGED' USING ERRCODE='40001'; END IF;
 SELECT * INTO actual FROM public.assets WHERE tenant_id=p.tenant_id AND id=p.asset_id;
 IF actual.id IS NULL OR actual.version<>p.asset_version OR actual.source_id IS NOT NULL OR actual.type<>'business_term'
 OR actual.model_id IS DISTINCT FROM p.payload#>>'{typePin,modelId}' OR actual.model_version IS DISTINCT FROM (p.payload#>>'{typePin,version}')::integer
 OR actual.attributes IS DISTINCT FROM p.payload->'attributes' OR actual.owner_id IS DISTINCT FROM (p.payload->>'ownerId')::uuid
 OR actual.type_state IS DISTINCT FROM p.payload->>'state' OR actual.visibility IS DISTINCT FROM p.payload->>'visibility'
 OR actual.allowed_identities IS DISTINCT FROM p.payload->'allowedIdentityIds'
 OR jsonb_build_object('id',actual.id,'name',actual.name,'qualifiedName',actual.qualified_name,'type',actual.type,'description',actual.description,
  'ownerId',actual.owner_id,'ownerName',NULL,'sourceId',actual.source_id,'sourceName',NULL,'version',actual.version,'observedAt',public.gc_relation_utc(actual.observed_at),
  'updatedAt',public.gc_relation_utc(actual.updated_at),'status',actual.status,'metadata',actual.metadata,'modelId',actual.model_id,'modelVersion',actual.model_version,'attributes',actual.attributes,'typeState',actual.type_state) IS DISTINCT FROM p.asset_snapshot
 OR NOT EXISTS(SELECT 1 FROM public.asset_revisions h WHERE h.tenant_id=p.tenant_id AND h.asset_id=p.asset_id AND h.version=p.asset_version AND h.snapshot=p.asset_snapshot)
 THEN RAISE EXCEPTION 'GLOSSARY_SOURCE_CHANGED' USING ERRCODE='40001'; END IF;
 RETURN jsonb_build_object('formatVersion',1,'publicationId',p.id,'requestId',p.id,'tenantId',p.tenant_id,'actorId',p.actor_id,
  'relationTypeIds',to_jsonb(p.relation_type_ids),'beforeEndpoint',p.before_endpoint,'afterEndpoint',p.after_endpoint);
END $$;

CREATE OR REPLACE FUNCTION public.gc_relation_check_type(tenant uuid,type_identity uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE head_definition jsonb; binding record; selected_side text; side_min integer; side_max integer;
 edge_count bigint; endpoint_count bigint; projected_bytes bigint; row_value record; outgoing bigint; incoming bigint;
 src uuid[]; dst uuid[]; nodes uuid[]; remaining integer[]; leaf uuid; parents integer[]; edge_index integer; node_index integer; left_index integer; right_index integer; old_parent integer;
BEGIN
 IF tenant IS DISTINCT FROM public.gc_tenant() THEN RAISE EXCEPTION 'Untrusted graph tenant' USING ERRCODE='42501'; END IF;
 SELECT v.definition INTO head_definition FROM public.relation_types t JOIN public.relation_type_versions v
  ON v.tenant_id=t.tenant_id AND v.relation_type_id=t.type_id AND v.version=t.current_version
  WHERE t.tenant_id=tenant AND t.type_id=type_identity;
 IF head_definition IS NULL THEN RAISE EXCEPTION 'Relation publication requires its immutable version' USING ERRCODE='23514'; END IF;
 IF EXISTS(SELECT 1 FROM public.relations r WHERE r.tenant_id=tenant AND r.relation_type_id=type_identity AND r.status='active'
   AND r.visibility='restricted' AND NOT r.allowed_identities @> jsonb_build_array(public.gc_actor()))
 OR EXISTS(SELECT 1 FROM public.assets a WHERE a.tenant_id=tenant AND a.visibility='restricted'
  AND NOT a.allowed_identities @> jsonb_build_array(public.gc_actor()) AND (
   public.gc_relation_endpoint_eligible(tenant,a.id,head_definition,'source') OR public.gc_relation_endpoint_eligible(tenant,a.id,head_definition,'target')
   OR EXISTS(SELECT 1 FROM public.relations r WHERE r.tenant_id=tenant AND r.relation_type_id=type_identity AND r.status='active' AND a.id IN (r.source_asset_id,r.target_asset_id))
   OR EXISTS(SELECT 1 FROM public.relation_participations p WHERE p.tenant_id=tenant AND p.relation_type_id=type_identity AND p.asset_id=a.id AND p.status='active'))) THEN
  RAISE EXCEPTION 'RELATION_SCOPE_UNAVAILABLE' USING ERRCODE='42501'; END IF;
 IF (SELECT count(*) FROM public.relation_participations p WHERE p.tenant_id=tenant AND p.relation_type_id=type_identity AND p.status='active')>4000
 OR (SELECT count(*) FROM public.gc_relation_nominal_candidates(head_definition) c JOIN public.assets a ON a.tenant_id=tenant AND a.id=c.asset_id WHERE (public.gc_relation_endpoint_eligible(tenant,a.id,head_definition,'source')
   OR public.gc_relation_endpoint_eligible(tenant,a.id,head_definition,'target')))>2000 THEN
  RAISE EXCEPTION 'RELATION_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 FOR selected_side IN SELECT unnest(CASE WHEN head_definition->>'direction'='undirected' THEN ARRAY['incident'] ELSE ARRAY['source','target'] END) LOOP
  side_min:=(head_definition->'cardinality'->(CASE WHEN selected_side='target' THEN 'incoming' ELSE 'outgoing' END)->>'min')::integer;
  IF side_min>0 AND EXISTS(SELECT 1 FROM public.gc_relation_nominal_candidates(head_definition) c JOIN public.assets a ON a.tenant_id=tenant AND a.id=c.asset_id
   WHERE public.gc_relation_endpoint_eligible(tenant,a.id,head_definition,CASE WHEN selected_side='incident' THEN 'source' ELSE selected_side END)
   AND NOT EXISTS(SELECT 1 FROM public.relation_participations p WHERE p.tenant_id=tenant AND p.relation_type_id=type_identity
    AND p.asset_id=a.id AND p.side=selected_side AND p.status='active')) THEN
   RAISE EXCEPTION 'RELATION_PARTICIPATION_REQUIRED' USING ERRCODE='23514'; END IF;
 END LOOP;
 FOR binding IN SELECT p.*,v.definition AS policy FROM public.relation_participations p JOIN public.relation_type_versions v
  ON v.tenant_id=p.tenant_id AND v.relation_type_id=p.relation_type_id AND v.version=p.relation_type_version
  WHERE p.tenant_id=tenant AND p.relation_type_id=type_identity AND p.status='active' ORDER BY p.id LOOP
  IF public.gc_relation_structural_policy(binding.policy) IS DISTINCT FROM public.gc_relation_structural_policy(head_definition)
   OR (binding.policy->>'direction'='undirected')<>(binding.side='incident')
   OR NOT public.gc_relation_endpoint_eligible(tenant,binding.asset_id,binding.policy,CASE WHEN binding.side='incident' THEN 'source' ELSE binding.side END) THEN
   RAISE EXCEPTION 'RELATION_MIGRATION_REQUIRED' USING ERRCODE='23514'; END IF;
  SELECT count(*) INTO outgoing FROM public.relations r WHERE r.tenant_id=tenant AND r.relation_type_id=type_identity AND r.status='active'
   AND CASE binding.side WHEN 'source' THEN r.source_asset_id=binding.asset_id WHEN 'target' THEN r.target_asset_id=binding.asset_id
    ELSE binding.asset_id IN (r.source_asset_id,r.target_asset_id) END;
  side_min:=(binding.policy->'cardinality'->(CASE WHEN binding.side='target' THEN 'incoming' ELSE 'outgoing' END)->>'min')::integer;
  side_max:=(binding.policy->'cardinality'->(CASE WHEN binding.side='target' THEN 'incoming' ELSE 'outgoing' END)->>'max')::integer;
  IF outgoing<side_min THEN RAISE EXCEPTION 'RELATION_PARTICIPATION_REQUIRED' USING ERRCODE='23514'; END IF;
  IF side_max IS NOT NULL AND outgoing>side_max THEN RAISE EXCEPTION 'RELATION_CARDINALITY' USING ERRCODE='23514'; END IF;
 END LOOP;

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
  IF (row_value.policy->>'direction'='undirected' AND row_value.source_asset_id>row_value.target_asset_id)
   OR (row_value.policy->>'allowSelf'='false' AND row_value.source_asset_id=row_value.target_asset_id) THEN
   RAISE EXCEPTION 'Relation endpoint order or self policy is invalid' USING ERRCODE='23514'; END IF;
  IF public.gc_relation_structural_policy(row_value.policy) IS DISTINCT FROM public.gc_relation_structural_policy(head_definition) THEN
   RAISE EXCEPTION 'RELATION_MIGRATION_REQUIRED' USING ERRCODE='23514'; END IF;
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
 RETURN;
END $$;

REVOKE ALL ON FUNCTION public.gc_relation_check_type(uuid,uuid) FROM PUBLIC,gc_app;
