-- SPDX-License-Identifier: Apache-2.0
-- SQL015 -> SQL016 candidate. Approved glossary publication composes with the
-- existing complete-graph engine in one transaction; no caller supplies outcome.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR pg_has_role('gc_app',current_user,'MEMBER') THEN RAISE EXCEPTION 'GLOSSARY_STORAGE_INVALID' USING ERRCODE='42501'; END IF;
END $$;
ALTER TABLE public.assets ALTER COLUMN observed_at DROP NOT NULL;
-- Preserve the existing asset policy trigger inside hardened definer callers.
CREATE OR REPLACE FUNCTION public.gc_asset_type_constraints() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE constraints jsonb;
BEGIN
 SELECT resolved INTO constraints FROM public.asset_type_versions WHERE tenant_id=NEW.tenant_id AND model_id=NEW.model_id AND version=NEW.model_version;
 IF constraints IS NULL THEN
  IF EXISTS(SELECT 1 FROM public.governance_models m WHERE m.tenant_id=NEW.tenant_id AND m.id=NEW.model_id AND m.type_id IS NOT NULL) THEN
   RAISE EXCEPTION 'Authored asset constraints must exist before assignment' USING ERRCODE='23514';
  END IF;
  IF NEW.type_state IS NOT NULL THEN RAISE EXCEPTION 'Attribute-only assets cannot have an authored type state' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF NEW.type_state IS NULL OR NOT constraints->'lifecycle'->'states' @> to_jsonb(NEW.type_state) THEN
  RAISE EXCEPTION 'Asset state is outside its pinned lifecycle' USING ERRCODE='23514';
 END IF;
 IF (constraints->>'requiredOwner')::boolean AND (NEW.owner_id IS NULL OR NOT EXISTS(
  SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id
  WHERE m.tenant_id=NEW.tenant_id AND m.identity_id=NEW.owner_id AND m.active AND i.active)) THEN
  RAISE EXCEPTION 'Asset type requires an active tenant owner' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TABLE public.glossary_publications (
 tenant_id uuid NOT NULL, id uuid NOT NULL, asset_id uuid NOT NULL, asset_version integer NOT NULL CHECK(asset_version>0),
 previous_publication_id uuid, payload jsonb NOT NULL, proposal_digest text NOT NULL,
 workflow_id text NOT NULL, workflow_version integer NOT NULL, workflow_hash text NOT NULL, actor_id uuid NOT NULL,
 transaction_id xid8 NOT NULL, started_at timestamptz NOT NULL, state text NOT NULL CHECK(state IN('prepared','staged','sealed')),
 relation_type_ids uuid[] NOT NULL, asset_ids uuid[] NOT NULL, before_endpoint jsonb, after_endpoint jsonb NOT NULL,
 baseline jsonb NOT NULL, asset_snapshot jsonb, audit_id uuid, graph_operation_id uuid, receipt jsonb,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,asset_id,asset_version),
 FOREIGN KEY(tenant_id,id) REFERENCES public.approval_requests(tenant_id,id),
 FOREIGN KEY(tenant_id,actor_id) REFERENCES public.memberships(tenant_id,identity_id),
 FOREIGN KEY(tenant_id,previous_publication_id) REFERENCES public.glossary_publications(tenant_id,id),
 FOREIGN KEY(tenant_id,asset_id) REFERENCES public.assets(tenant_id,id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY(tenant_id,graph_operation_id) REFERENCES public.relation_graph_operations(tenant_id,id),
 CHECK(octet_length(payload::text)<=262144 AND octet_length(baseline::text)<=524288)
);
CREATE UNIQUE INDEX glossary_publication_transaction ON public.glossary_publications(tenant_id,transaction_id);
CREATE TABLE public.glossary_terms (
 tenant_id uuid NOT NULL, asset_id uuid NOT NULL, current_publication_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,asset_id), FOREIGN KEY(tenant_id,asset_id) REFERENCES public.assets(tenant_id,id),
 FOREIGN KEY(tenant_id,current_publication_id) REFERENCES public.glossary_publications(tenant_id,id)
);
CREATE TABLE public.glossary_publication_links (
 tenant_id uuid NOT NULL, publication_id uuid NOT NULL, ordinal integer NOT NULL CHECK(ordinal BETWEEN 0 AND 99),
 kind text NOT NULL CHECK(kind IN('broader','related','defines')), relation_id uuid NOT NULL, relation_type_id uuid NOT NULL, target_asset_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,publication_id,ordinal), UNIQUE(tenant_id,publication_id,relation_id),
 FOREIGN KEY(tenant_id,publication_id) REFERENCES public.glossary_publications(tenant_id,id),
 FOREIGN KEY(tenant_id,relation_id) REFERENCES public.relations(tenant_id,id),
 FOREIGN KEY(tenant_id,target_asset_id) REFERENCES public.assets(tenant_id,id),
 FOREIGN KEY(tenant_id,relation_type_id) REFERENCES public.relation_types(tenant_id,type_id)
);
DO $$ DECLARE name text; BEGIN
 FOREACH name IN ARRAY ARRAY['glossary_publications','glossary_terms','glossary_publication_links'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.gc_tenant()) WITH CHECK(tenant_id=public.gc_tenant())',name);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC,gc_app',name);
  EXECUTE format('GRANT SELECT ON public.%I TO gc_app',name);
 END LOOP;
END $$;
CREATE TRIGGER glossary_links_immutable BEFORE UPDATE OR DELETE ON public.glossary_publication_links FOR EACH ROW EXECUTE FUNCTION public.gc_immutable_audit();

CREATE FUNCTION public.gc_glossary_current() RETURNS public.glossary_publications
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT p FROM public.glossary_publications p WHERE p.tenant_id=public.gc_tenant() AND p.transaction_id=pg_current_xact_id();
$$;
CREATE FUNCTION public.gc_glossary_context(p public.glossary_publications) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('publicationId',p.id,'requestId',p.id,'assetId',p.asset_id,'assetVersion',p.asset_version,
 'state',p.state,'receipt',p.receipt,'previousPublicationId',p.previous_publication_id,'publication',p.payload,'proposalDigest',p.proposal_digest,
 'workflowId',p.workflow_id,'workflowVersion',p.workflow_version,'workflowHash',p.workflow_hash,
 'relationTypeIds',to_jsonb(p.relation_type_ids),'graphKey','glossary:'||p.id::text,'correlationId','glossary:'||p.id::text);
$$;
CREATE FUNCTION public.gc_glossary_budget(p public.glossary_publications) RETURNS void
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,pg_temp AS $$ BEGIN
 IF p.id IS NULL OR p.tenant_id IS DISTINCT FROM public.gc_tenant() OR p.actor_id::text IS DISTINCT FROM public.gc_actor()
 OR p.transaction_id IS DISTINCT FROM pg_current_xact_id() THEN RAISE EXCEPTION 'GLOSSARY_CONTEXT_REQUIRED' USING ERRCODE='42501'; END IF;
 PERFORM public.gc_relation_graph_budget(p.started_at);
END $$;
-- The same bounded canonical cohort is used before and after the sole authored
-- asset write. Metadata outside this resource, heads, edges and bindings cannot
-- be changed by a publication source exception.
CREATE FUNCTION public.gc_glossary_snapshot(type_ids uuid[], selected_assets uuid[], except_asset uuid DEFAULT NULL, term_model text DEFAULT NULL) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE bytes bigint; result jsonb; BEGIN
 SELECT coalesce(sum(n),0) INTO bytes FROM (
  SELECT octet_length(to_jsonb(t)::text)+2 AS n FROM public.relation_types t WHERE t.tenant_id=public.gc_tenant() AND t.type_id=ANY(type_ids)
  UNION ALL SELECT octet_length(to_jsonb(m)::text)+2 FROM public.governance_models m WHERE m.tenant_id=public.gc_tenant() AND (m.id=term_model OR m.id IN(SELECT a.model_id FROM public.assets a WHERE a.tenant_id=public.gc_tenant() AND a.id=ANY(selected_assets)))
  UNION ALL SELECT octet_length(to_jsonb(a)::text)+2 FROM public.assets a WHERE a.tenant_id=public.gc_tenant() AND a.id=ANY(selected_assets) AND (except_asset IS NULL OR a.id<>except_asset)
  UNION ALL SELECT octet_length(to_jsonb(r)::text)+2 FROM public.relations r WHERE r.tenant_id=public.gc_tenant() AND r.relation_type_id=ANY(type_ids) AND r.status='active'
  UNION ALL SELECT octet_length(to_jsonb(b)::text)+2 FROM public.relation_participations b WHERE b.tenant_id=public.gc_tenant() AND b.relation_type_id=ANY(type_ids) AND b.status='active'
 ) physical;
 IF bytes+64>524288 THEN RAISE EXCEPTION 'GLOSSARY_LIMIT' USING ERRCODE='54000'; END IF;
 SELECT jsonb_build_object(
 'models',coalesce((SELECT jsonb_agg(to_jsonb(m) ORDER BY m.id COLLATE "C") FROM public.governance_models m WHERE m.tenant_id=public.gc_tenant() AND (m.id=term_model OR m.id IN(SELECT a.model_id FROM public.assets a WHERE a.tenant_id=public.gc_tenant() AND a.id=ANY(selected_assets)))),'[]'::jsonb),
 'heads',coalesce((SELECT jsonb_agg(to_jsonb(t) ORDER BY t.type_id) FROM public.relation_types t WHERE t.tenant_id=public.gc_tenant() AND t.type_id=ANY(type_ids)),'[]'::jsonb),
 'assets',coalesce((SELECT jsonb_agg(to_jsonb(a) ORDER BY a.id) FROM public.assets a WHERE a.tenant_id=public.gc_tenant() AND a.id=ANY(selected_assets) AND (except_asset IS NULL OR a.id<>except_asset)),'[]'::jsonb),
 'edges',coalesce((SELECT jsonb_agg(to_jsonb(r) ORDER BY r.id) FROM public.relations r WHERE r.tenant_id=public.gc_tenant() AND r.relation_type_id=ANY(type_ids) AND r.status='active'),'[]'::jsonb),
 'bindings',coalesce((SELECT jsonb_agg(to_jsonb(b) ORDER BY b.id) FROM public.relation_participations b WHERE b.tenant_id=public.gc_tenant() AND b.relation_type_id=ANY(type_ids) AND b.status='active'),'[]'::jsonb)) INTO result;
 RETURN result;
END $$;
CREATE FUNCTION public.gc_glossary_payload_check(request public.approval_requests) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE v jsonb:=request.payload; pin jsonb:=v->'typePin'; policy jsonb; base public.assets; root_type uuid; selected_type uuid;
 translation jsonb; link jsonb; relation public.relation_type_versions; target public.assets; endpoint jsonb; source jsonb; locale_count integer;
 empty_request jsonb:='{"changeSet":{"assetTypeMigrations":[]}}'; BEGIN
 IF NOT public.gc_relation_keys(v,ARRAY['typePin','primaryLocale','ownerId','visibility','allowedIdentityIds','state','attributes','links'])
 OR NOT public.gc_relation_keys(pin,ARRAY['typeId','modelId','version','definitionHash','resolutionHash'])
 OR jsonb_typeof(v->'attributes') IS DISTINCT FROM 'object' OR jsonb_typeof(v->'links') IS DISTINCT FROM 'array' OR jsonb_array_length(v->'links')>100
 OR NOT public.gc_approval_uuid(v->>'ownerId') OR coalesce(v->>'visibility','') NOT IN('tenant','restricted')
 OR NOT public.gc_relation_uuid_list(v->'allowedIdentityIds',100) OR coalesce(v->>'state','') NOT IN('active','deprecated')
 OR jsonb_typeof(v->'primaryLocale') IS DISTINCT FROM 'string' OR v->>'primaryLocale' !~ '^([a-z]{2,3}|[a-z]{5,8})(-[A-Z][a-z]{3})?(-([A-Z]{2}|[0-9]{3}))?(-([a-z0-9]{5,8}|[0-9][a-z0-9]{3}))*$'
 OR jsonb_typeof(v->'attributes'->'translations') IS DISTINCT FROM 'array' OR jsonb_array_length(v->'attributes'->'translations') NOT BETWEEN 1 AND 32
 OR NOT public.gc_relation_positive_integer(pin->'version') OR NOT public.gc_approval_uuid(pin->>'typeId')
 OR (v->>'visibility'='tenant' AND v->'allowedIdentityIds'<>'[]') OR (v->>'visibility'='restricted' AND jsonb_array_length(v->'allowedIdentityIds')=0)
 THEN RAISE EXCEPTION 'GLOSSARY_INPUT_INVALID' USING ERRCODE='22023'; END IF;
 SELECT type_id INTO root_type FROM public.governance_models WHERE tenant_id=request.tenant_id AND id='business_term';
 SELECT type_id INTO selected_type FROM public.governance_models WHERE tenant_id=request.tenant_id AND id=pin->>'modelId' AND current_version=(pin->>'version')::integer;
 IF selected_type IS DISTINCT FROM (pin->>'typeId')::uuid OR root_type IS NULL THEN RAISE EXCEPTION 'GLOSSARY_PIN_STALE' USING ERRCODE='40001'; END IF;
 policy:=public.gc_relation_graph_asset_policy(pin->>'modelId',(pin->>'version')::integer,empty_request);
 IF NOT EXISTS(SELECT 1 FROM public.asset_type_versions t WHERE t.tenant_id=request.tenant_id AND t.model_id=pin->>'modelId' AND t.version=(pin->>'version')::integer
  AND t.definition_hash=pin->>'definitionHash' AND t.resolution_hash=pin->>'resolutionHash')
 OR (selected_type<>root_type AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(policy->'dependencies') d WHERE d->>'id'='business_term'))
 OR policy->>'requiredOwner' IS DISTINCT FROM 'true'
 OR NOT public.gc_relation_value_valid(jsonb_build_object('type','object','properties',policy->'model'->'attributes'),v->'attributes')
 THEN RAISE EXCEPTION 'GLOSSARY_POLICY_INVALID' USING ERRCODE='23514'; END IF;
 SELECT * INTO base FROM public.assets WHERE tenant_id=request.tenant_id AND id=request.resource_id;
 IF request.resource_version IS NULL THEN
  IF base.id IS NOT NULL OR policy->'lifecycle'->>'initial' IS DISTINCT FROM v->>'state' THEN RAISE EXCEPTION 'GLOSSARY_STATE_CONFLICT' USING ERRCODE='40001'; END IF;
 ELSIF base.id IS NULL OR base.version<>request.resource_version OR base.source_id IS NOT NULL OR base.type<>'business_term' OR base.status<>'active'
  OR base.model_id IS DISTINCT FROM pin->>'modelId' OR base.model_version IS DISTINCT FROM (pin->>'version')::integer THEN
  RAISE EXCEPTION 'GLOSSARY_STATE_CONFLICT' USING ERRCODE='40001';
 ELSIF base.type_state<>v->>'state' AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(policy->'lifecycle'->'transitions') t WHERE t->>'from'=base.type_state AND t->>'to'=v->>'state') THEN
  RAISE EXCEPTION 'GLOSSARY_POLICY_INVALID' USING ERRCODE='23514'; END IF;
 IF NOT policy->'lifecycle'->'states' @> jsonb_build_array(v->'state') THEN RAISE EXCEPTION 'GLOSSARY_POLICY_INVALID' USING ERRCODE='23514'; END IF;
 SELECT count(*) INTO locale_count FROM jsonb_array_elements(v->'attributes'->'translations') t WHERE t->>'locale'=v->>'primaryLocale';
 IF locale_count<>1 OR (SELECT count(*)<>count(DISTINCT lower(t->>'locale')) FROM jsonb_array_elements(v->'attributes'->'translations') t) THEN RAISE EXCEPTION 'GLOSSARY_INPUT_INVALID' USING ERRCODE='22023'; END IF;
 FOR translation IN SELECT t FROM jsonb_array_elements(v->'attributes'->'translations') t LOOP
  IF NOT public.gc_relation_keys(translation,ARRAY['locale','name','definition','synonyms','abbreviations','examples'])
  OR jsonb_typeof(translation->'locale') IS DISTINCT FROM 'string' OR translation->>'locale' !~ '^([a-z]{2,3}|[a-z]{5,8})(-[A-Z][a-z]{3})?(-([A-Z]{2}|[0-9]{3}))?(-([a-z0-9]{5,8}|[0-9][a-z0-9]{3}))*$'
  OR public.gc_approval_text(translation->>'name',240,false) IS DISTINCT FROM translation->>'name'
  OR public.gc_approval_text(translation->>'definition',16384,true) IS DISTINCT FROM translation->>'definition'
  OR jsonb_typeof(translation->'synonyms') IS DISTINCT FROM 'array' OR jsonb_array_length(translation->'synonyms')>32
  OR jsonb_typeof(translation->'abbreviations') IS DISTINCT FROM 'array' OR jsonb_array_length(translation->'abbreviations')>32
  OR jsonb_typeof(translation->'examples') IS DISTINCT FROM 'array' OR jsonb_array_length(translation->'examples')>16
  OR EXISTS(SELECT 1 FROM jsonb_array_elements((translation->'synonyms')||(translation->'abbreviations')) a WHERE jsonb_typeof(a)<>'string' OR public.gc_approval_text(a#>>'{}',240,false) IS DISTINCT FROM a#>>'{}')
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(translation->'examples') a WHERE jsonb_typeof(a)<>'string' OR public.gc_approval_text(a#>>'{}',4096,true) IS DISTINCT FROM a#>>'{}')
  OR (SELECT count(*)<>count(DISTINCT lower(normalize(alias,NFKC)) COLLATE "C") FROM jsonb_array_elements_text(jsonb_build_array(translation->'name')||(translation->'synonyms')||(translation->'abbreviations')) alias)
  THEN RAISE EXCEPTION 'GLOSSARY_INPUT_INVALID' USING ERRCODE='22023'; END IF;
 END LOOP;
 source:=public.gc_relation_graph_endpoint(request.resource_id,coalesce(request.resource_version,0)+1,
  jsonb_build_object('modelId',pin->'modelId','modelVersion',pin->'version','state',v->'state'),empty_request);
 IF (SELECT count(*) FROM jsonb_array_elements(v->'links') l WHERE l->>'kind'='broader')>1
 OR (SELECT count(*)<>count(DISTINCT (l->>'kind',l->>'targetAssetId')) FROM jsonb_array_elements(v->'links') l) THEN
  RAISE EXCEPTION 'GLOSSARY_LINK_INVALID' USING ERRCODE='23514'; END IF;
 FOR link IN SELECT l FROM jsonb_array_elements(v->'links') l LOOP
  IF NOT public.gc_relation_keys(link,ARRAY['kind','typePin','targetAssetId','targetAssetVersion']) OR coalesce(link->>'kind','') NOT IN('broader','related','defines')
  OR NOT public.gc_relation_keys(link->'typePin',ARRAY['relationTypeId','version','definitionHash']) OR NOT public.gc_approval_uuid(link->>'targetAssetId')
  OR NOT public.gc_approval_uuid(link#>>'{typePin,relationTypeId}') OR NOT public.gc_relation_positive_integer(link#>'{typePin,version}')
  OR jsonb_typeof(link#>'{typePin,definitionHash}') IS DISTINCT FROM 'string' OR link#>>'{typePin,definitionHash}' !~ '^[a-f0-9]{64}$'
  OR link->>'targetAssetId'=request.resource_id::text OR NOT public.gc_relation_positive_integer(link->'targetAssetVersion') THEN
   RAISE EXCEPTION 'GLOSSARY_LINK_INVALID' USING ERRCODE='23514'; END IF;
  SELECT v.* INTO relation FROM public.relation_type_versions v JOIN public.relation_types h ON h.tenant_id=v.tenant_id AND h.type_id=v.relation_type_id AND h.current_version=v.version
   WHERE v.tenant_id=request.tenant_id AND v.relation_type_id=(link->'typePin'->>'relationTypeId')::uuid AND v.version=(link->'typePin'->>'version')::integer;
  SELECT * INTO target FROM public.assets a WHERE a.tenant_id=request.tenant_id AND a.id=(link->>'targetAssetId')::uuid;
  IF relation.relation_type_id IS NULL OR relation.definition_hash IS DISTINCT FROM link->'typePin'->>'definitionHash'
  OR target.id IS NULL OR target.version<>(link->>'targetAssetVersion')::integer OR target.status<>'active' THEN RAISE EXCEPTION 'GLOSSARY_PIN_STALE' USING ERRCODE='40001'; END IF;
  endpoint:=public.gc_relation_graph_endpoint(target.id,target.version,public.gc_relation_asset_tuple(target),empty_request);
  IF NOT public.gc_relation_projected_eligible(source,relation.definition,'source') OR NOT public.gc_relation_projected_eligible(endpoint,relation.definition,'target')
  OR NOT public.gc_relation_value_valid(jsonb_build_object('type','object','properties',relation.definition->'attributes'),'{}'::jsonb)
  OR (link->>'kind'<>'defines' AND (target.type<>'business_term' OR target.source_id IS NOT NULL OR NOT(endpoint->>'typeId'=root_type::text OR EXISTS(SELECT 1 FROM jsonb_array_elements(endpoint->'ancestorTypes') a WHERE a->>'id'='business_term' AND a->>'typeId'=root_type::text))))
  OR (link->>'kind'='broader' AND (relation.definition->>'direction'<>'directed' OR relation.definition->>'cycles'<>'acyclic' OR relation.definition#>>'{cardinality,outgoing,max}' IS DISTINCT FROM '1')) THEN
   RAISE EXCEPTION 'GLOSSARY_LINK_INVALID' USING ERRCODE='23514'; END IF;
 END LOOP;
END $$;

CREATE FUNCTION public.gc_glossary_prepare(request_identity uuid) RETURNS jsonb
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
  UNION SELECT a.id FROM public.assets a WHERE a.tenant_id=tenant AND EXISTS(SELECT 1 FROM public.relation_types h JOIN public.relation_type_versions v ON v.tenant_id=h.tenant_id AND v.relation_type_id=h.type_id AND v.version=h.current_version
   WHERE h.tenant_id=tenant AND h.type_id=ANY(type_ids) AND (public.gc_relation_graph_scope_eligible(tenant,a.id,v.definition,'source',started) OR public.gc_relation_graph_scope_eligible(tenant,a.id,v.definition,'target',started)))
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

CREATE FUNCTION public.gc_glossary_stage(publication_identity uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE p public.glossary_publications; request public.approval_requests; a public.assets; primary_text jsonb; stamp timestamptz; snapshot jsonb; event_id uuid;
BEGIN
 p:=public.gc_glossary_current();PERFORM public.gc_glossary_budget(p);
 IF p.id IS DISTINCT FROM publication_identity OR p.state<>'prepared' OR public.gc_glossary_snapshot(p.relation_type_ids,p.asset_ids,NULL,p.payload#>>'{typePin,modelId}') IS DISTINCT FROM p.baseline
 OR (public.gc_relation_graph_current()).id IS NOT NULL THEN RAISE EXCEPTION 'GLOSSARY_STATE_CONFLICT' USING ERRCODE='40001'; END IF;
 SELECT * INTO request FROM public.approval_requests WHERE tenant_id=p.tenant_id AND id=p.id;
 IF request.status<>'ready' OR request.proposal_digest<>p.proposal_digest OR request.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'GLOSSARY_STATE_CONFLICT' USING ERRCODE='40001'; END IF;
 PERFORM public.gc_glossary_payload_check(request);
 SELECT t INTO primary_text FROM jsonb_array_elements(p.payload#>'{attributes,translations}') t WHERE t->>'locale'=p.payload->>'primaryLocale';
 stamp:=date_trunc('milliseconds',clock_timestamp());
 IF p.asset_version=1 THEN
  INSERT INTO public.assets(tenant_id,id,source_id,external_id,name,qualified_name,type,description,owner_id,metadata,visibility,allowed_identities,status,version,observed_at,updated_at,model_id,model_version,attributes,type_state)
  VALUES(p.tenant_id,p.asset_id,NULL,'glossary:'||p.asset_id::text,primary_text->>'name','glossary.'||p.asset_id::text,'business_term',primary_text->>'definition',(p.payload->>'ownerId')::uuid,
   jsonb_build_object('authoring',jsonb_build_object('kind','glossary','requestId',p.id,'proposalDigest',p.proposal_digest)),p.payload->>'visibility',p.payload->'allowedIdentityIds','active',1,NULL,stamp,
   p.payload#>>'{typePin,modelId}',(p.payload#>>'{typePin,version}')::integer,p.payload->'attributes',p.payload->>'state') RETURNING * INTO a;
 ELSE
  UPDATE public.assets SET name=primary_text->>'name',description=primary_text->>'definition',owner_id=(p.payload->>'ownerId')::uuid,
   visibility=p.payload->>'visibility',allowed_identities=p.payload->'allowedIdentityIds',version=p.asset_version,updated_at=stamp,
   attributes=p.payload->'attributes',type_state=p.payload->>'state'
   WHERE tenant_id=p.tenant_id AND id=p.asset_id AND version=p.asset_version-1 AND source_id IS NULL AND type='business_term' RETURNING * INTO a;
 END IF;
 IF a.id IS NULL THEN RAISE EXCEPTION 'GLOSSARY_STATE_CONFLICT' USING ERRCODE='40001'; END IF;
 snapshot:=jsonb_build_object('id',a.id,'name',a.name,'qualifiedName',a.qualified_name,'type',a.type,'description',a.description,
  'ownerId',a.owner_id,'ownerName',NULL,'sourceId',a.source_id,'sourceName',NULL,'version',a.version,'observedAt',public.gc_relation_utc(a.observed_at),
  'updatedAt',public.gc_relation_utc(a.updated_at),'status',a.status,'metadata',a.metadata,'modelId',a.model_id,'modelVersion',a.model_version,'attributes',a.attributes,'typeState',a.type_state);
 INSERT INTO public.asset_revisions(tenant_id,asset_id,version,snapshot,recorded_at) VALUES(p.tenant_id,p.asset_id,p.asset_version,snapshot,stamp);
 event_id:=public.gc_approval_journal('asset.glossary_published',NULL,p.asset_id::text,p.asset_version,jsonb_build_object('publicationId',p.id,'proposalDigest',p.proposal_digest,'snapshotHash',public.gc_type_migration_hash(snapshot)),'glossary:'||p.id::text);
 PERFORM public.gc_approval_journal('approval.succeeded',NULL,p.id::text,request.version+1,jsonb_build_object('publicationId',p.id,'assetId',p.asset_id,'assetVersion',p.asset_version,'proposalDigest',p.proposal_digest),'glossary:'||p.id::text);
 UPDATE public.glossary_publications SET state='staged',asset_snapshot=snapshot,audit_id=event_id WHERE tenant_id=p.tenant_id AND id=p.id RETURNING * INTO p;
 PERFORM public.gc_glossary_budget(p);RETURN public.gc_glossary_context(p);
END $$;

CREATE FUNCTION public.gc_glossary_graph_source_evidence(publication_identity uuid) RETURNS jsonb
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
  UNION SELECT a.id FROM public.assets a WHERE a.tenant_id=tenant AND EXISTS(SELECT 1 FROM public.relation_types h JOIN public.relation_type_versions v ON v.tenant_id=h.tenant_id AND v.relation_type_id=h.type_id AND v.version=h.current_version
   WHERE h.tenant_id=tenant AND h.type_id=ANY(type_ids) AND (public.gc_relation_graph_scope_eligible(tenant,a.id,v.definition,'source',p.started_at) OR public.gc_relation_graph_scope_eligible(tenant,a.id,v.definition,'target',p.started_at)))
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
-- Only the exact staged source has a previously validated baseline exception.
-- Final graph checking remains the original strict checker.
CREATE FUNCTION public.gc_glossary_graph_source_assert(tenant uuid,type_identity uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE p public.glossary_publications; BEGIN
 p:=public.gc_glossary_current();
 IF p.id IS NULL THEN PERFORM public.gc_relation_check_type(tenant,type_identity);RETURN; END IF;
 PERFORM public.gc_glossary_graph_source_evidence(p.id);
 IF tenant IS DISTINCT FROM p.tenant_id OR NOT type_identity=ANY(p.relation_type_ids) THEN RAISE EXCEPTION 'GLOSSARY_GRAPH_SCOPE_INVALID' USING ERRCODE='23514'; END IF;
END $$;

CREATE FUNCTION public.gc_glossary_finish(publication_identity uuid,graph_identity uuid DEFAULT NULL) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE p public.glossary_publications; op public.relation_graph_operations; request public.approval_requests; link jsonb; item record; edge public.relations;
 expected_ids uuid[]:='{}'; ordinal integer; now_at timestamptz; publication_receipt jsonb; type_identity uuid; baseline jsonb;
BEGIN
 p:=public.gc_glossary_current();PERFORM public.gc_glossary_budget(p);
 IF p.id IS DISTINCT FROM publication_identity OR p.state<>'staged' THEN RAISE EXCEPTION 'GLOSSARY_CONTEXT_REQUIRED' USING ERRCODE='42501'; END IF;
 SELECT * INTO request FROM public.approval_requests WHERE tenant_id=p.tenant_id AND id=p.id;
 IF request.status<>'ready' OR request.expires_at<=clock_timestamp() OR request.proposal_digest<>p.proposal_digest THEN RAISE EXCEPTION 'GLOSSARY_STATE_CONFLICT' USING ERRCODE='40001'; END IF;
 IF graph_identity IS NOT NULL THEN
  SELECT * INTO op FROM public.relation_graph_operations WHERE tenant_id=p.tenant_id AND id=graph_identity;
  IF op.id IS NULL OR op.transaction_id<>p.transaction_id OR op.actor_id<>p.actor_id OR op.state<>'sealed'
  OR op.idempotency_key<>'glossary:'||p.id::text OR op.correlation_id<>'glossary:'||p.id::text
  OR op.normalized_change_set->'assetChanges'<>'[]' OR op.normalized_change_set->'assetTypeMigrations'<>'[]'
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(op.normalized_change_set->'relationTargets') t WHERE t->>'kind'<>'repair')
  OR NOT EXISTS(SELECT 1 FROM public.idempotency i WHERE i.tenant_id=p.tenant_id AND i.actor_id=p.actor_id::text AND i.operation='relation-migration.execute' AND i.key=op.idempotency_key AND i.response=jsonb_build_object('receipt',op.receipt))
  THEN RAISE EXCEPTION 'GLOSSARY_GRAPH_INVALID' USING ERRCODE='23514'; END IF;
  IF (SELECT array_agg(relation_type_id ORDER BY relation_type_id) FROM public.relation_graph_operation_type_claims WHERE tenant_id=p.tenant_id AND operation_id=op.id) IS DISTINCT FROM p.relation_type_ids THEN
   RAISE EXCEPTION 'GLOSSARY_GRAPH_SCOPE_INVALID' USING ERRCODE='23514'; END IF;
  IF EXISTS(SELECT 1 FROM public.relation_graph_operation_edge_claims c WHERE c.tenant_id=p.tenant_id AND c.operation_id=op.id AND c.action NOT IN('preserve','create') AND NOT EXISTS(
   SELECT 1 FROM public.glossary_publication_links l WHERE l.tenant_id=p.tenant_id AND l.publication_id=p.previous_publication_id AND l.relation_id=c.relation_id))
  THEN RAISE EXCEPTION 'GLOSSARY_UNOWNED_LINK_CHANGE' USING ERRCODE='23514'; END IF;
  -- Enrollments are derived exclusively by the protected graph engine. Existing
  -- bindings may only leave this term when its approved endpoint no longer
  -- satisfies that binding's immutable policy; unrelated bindings are preserved.
  IF EXISTS(SELECT 1 FROM public.relation_graph_operation_binding_claims c
   WHERE c.tenant_id=p.tenant_id AND c.operation_id=op.id AND c.action NOT IN('preserve','enroll') AND NOT(
    c.action='release' AND c.before_tuple->>'assetId'=p.asset_id::text
    AND EXISTS(SELECT 1 FROM public.relation_type_versions v
     WHERE v.tenant_id=p.tenant_id AND v.relation_type_id=c.relation_type_id
      AND v.version=(c.before_tuple->>'relationTypeVersion')::integer
      AND NOT ((v.definition->>'direction'='undirected')=(c.before_tuple->>'side'='incident')
       AND public.gc_relation_projected_eligible(p.after_endpoint,v.definition,CASE WHEN c.before_tuple->>'side'='incident' THEN 'source' ELSE c.before_tuple->>'side' END)))))
  THEN RAISE EXCEPTION 'GLOSSARY_UNOWNED_BINDING_CHANGE' USING ERRCODE='23514'; END IF;
 ELSE
  IF (public.gc_relation_graph_current()).id IS NOT NULL THEN RAISE EXCEPTION 'GLOSSARY_GRAPH_INVALID' USING ERRCODE='23514'; END IF;
  -- A real metadata-only publication needs no fabricated graph operation.
  PERFORM public.gc_glossary_graph_source_evidence(p.id);
 END IF;
 FOR item IN SELECT l,ord-1 AS ordinal FROM jsonb_array_elements(p.payload->'links') WITH ORDINALITY e(l,ord) LOOP
  link:=item.l;ordinal:=item.ordinal;edge:=NULL;
  IF graph_identity IS NOT NULL THEN
   SELECT r.* INTO edge FROM public.relation_graph_operation_edge_claims c JOIN public.relations r ON r.tenant_id=c.tenant_id AND r.id=c.relation_id
    WHERE c.tenant_id=p.tenant_id AND c.operation_id=graph_identity AND c.action='create' AND c.key->>'key'='glossary_link_'||ordinal::text;
  END IF;
  IF edge.id IS NULL THEN
   SELECT r.* INTO edge FROM public.glossary_publication_links l JOIN public.relations r ON r.tenant_id=l.tenant_id AND r.id=l.relation_id
    WHERE l.tenant_id=p.tenant_id AND l.publication_id=p.previous_publication_id AND l.kind=link->>'kind'
    AND l.relation_type_id=(link#>>'{typePin,relationTypeId}')::uuid AND l.target_asset_id=(link->>'targetAssetId')::uuid AND r.status='active';
  END IF;
  IF edge.id IS NULL OR edge.status<>'active' OR edge.relation_type_id IS DISTINCT FROM (link#>>'{typePin,relationTypeId}')::uuid
  OR edge.relation_type_version IS DISTINCT FROM (link#>>'{typePin,version}')::integer
  OR NOT((edge.source_asset_id=p.asset_id AND edge.target_asset_id=(link->>'targetAssetId')::uuid) OR (EXISTS(SELECT 1 FROM public.relation_type_versions v WHERE v.tenant_id=p.tenant_id AND v.relation_type_id=edge.relation_type_id AND v.version=edge.relation_type_version AND v.definition->>'direction'='undirected') AND edge.target_asset_id=p.asset_id AND edge.source_asset_id=(link->>'targetAssetId')::uuid))
  OR edge.attributes<>'{}' OR edge.owner_id IS DISTINCT FROM (p.payload->>'ownerId')::uuid OR edge.visibility IS DISTINCT FROM p.payload->>'visibility'
  OR edge.allowed_identities IS DISTINCT FROM p.payload->'allowedIdentityIds' OR edge.valid_from IS NOT NULL OR edge.valid_to IS NOT NULL
  OR NOT EXISTS(SELECT 1 FROM public.relation_type_versions v WHERE v.tenant_id=p.tenant_id AND v.relation_type_id=edge.relation_type_id AND v.version=edge.relation_type_version AND edge.state=v.definition#>>'{lifecycle,initial}')
  THEN RAISE EXCEPTION 'GLOSSARY_LINK_OUTCOME_INVALID' USING ERRCODE='23514'; END IF;
  expected_ids:=array_append(expected_ids,edge.id);
  INSERT INTO public.glossary_publication_links VALUES(p.tenant_id,p.id,ordinal,link->>'kind',edge.id,edge.relation_type_id,(link->>'targetAssetId')::uuid);
 END LOOP;
 IF EXISTS(SELECT 1 FROM public.glossary_publication_links l JOIN public.relations r ON r.tenant_id=l.tenant_id AND r.id=l.relation_id WHERE l.tenant_id=p.tenant_id AND l.publication_id=p.previous_publication_id AND r.status='active' AND NOT r.id=ANY(expected_ids))
 OR EXISTS(SELECT 1 FROM public.relation_graph_operation_edge_claims c WHERE c.tenant_id=p.tenant_id AND c.operation_id=graph_identity AND c.action='create' AND NOT c.relation_id=ANY(expected_ids))
 THEN RAISE EXCEPTION 'GLOSSARY_LINK_OUTCOME_INVALID' USING ERRCODE='23514'; END IF;
 FOREACH type_identity IN ARRAY p.relation_type_ids LOOP PERFORM public.gc_glossary_budget(p);PERFORM public.gc_relation_check_type(p.tenant_id,type_identity); END LOOP;
 -- A hierarchy remains acyclic even if administrators use different declared
 -- broader relation types. The ledger prevents concurrent publication skew.
 IF EXISTS(WITH RECURSIVE edges AS (
   SELECT t.asset_id AS source,l.target_asset_id AS target FROM public.glossary_terms t JOIN public.glossary_publication_links l ON l.tenant_id=t.tenant_id AND l.publication_id=t.current_publication_id WHERE t.tenant_id=p.tenant_id AND t.asset_id<>p.asset_id AND l.kind='broader'
   UNION ALL SELECT p.asset_id,l.target_asset_id FROM public.glossary_publication_links l WHERE l.tenant_id=p.tenant_id AND l.publication_id=p.id AND l.kind='broader'
  ), walk(node,path,cycle) AS (
   SELECT target,ARRAY[source,target],source=target FROM edges WHERE source=p.asset_id
   UNION ALL SELECT e.target,w.path||e.target,e.target=ANY(w.path) FROM walk w JOIN edges e ON e.source=w.node WHERE NOT w.cycle AND cardinality(w.path)<=2000
  ) SELECT 1 FROM walk WHERE cycle OR cardinality(path)>2000) THEN RAISE EXCEPTION 'GLOSSARY_BROADER_CYCLE' USING ERRCODE='23514'; END IF;
 IF request.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'GLOSSARY_STATE_CONFLICT' USING ERRCODE='40001'; END IF;
 now_at:=date_trunc('milliseconds',clock_timestamp());
 publication_receipt:=jsonb_build_object('id',p.id,'assetId',p.asset_id,'assetVersion',p.asset_version,'proposalDigest',p.proposal_digest,
  'workflowPin',jsonb_build_object('id',p.workflow_id,'version',p.workflow_version,'definitionHash',p.workflow_hash),'graphReceiptId',graph_identity,'executedBy',p.actor_id,'executedAt',public.gc_relation_utc(now_at));
 INSERT INTO public.glossary_terms VALUES(p.tenant_id,p.asset_id,p.id) ON CONFLICT(tenant_id,asset_id) DO UPDATE SET current_publication_id=EXCLUDED.current_publication_id;
 UPDATE public.approval_requests SET status='succeeded',version=version+1,result=publication_receipt,updated_at=now_at WHERE tenant_id=p.tenant_id AND id=p.id AND status='ready';
 UPDATE public.glossary_publications SET state='sealed',graph_operation_id=graph_identity,receipt=publication_receipt WHERE tenant_id=p.tenant_id AND id=p.id;
 PERFORM public.gc_glossary_budget(p);RETURN publication_receipt;
END $$;

CREATE FUNCTION public.gc_glossary_asset_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE p public.glossary_publications; protected boolean; original jsonb; primary_text jsonb; BEGIN
 IF TG_OP='DELETE' THEN protected:=OLD.type='business_term' OR EXISTS(SELECT 1 FROM public.glossary_terms WHERE tenant_id=OLD.tenant_id AND asset_id=OLD.id);
 ELSE protected:=NEW.type='business_term' OR EXISTS(SELECT 1 FROM public.glossary_terms WHERE tenant_id=NEW.tenant_id AND asset_id=NEW.id);
  IF TG_OP='UPDATE' THEN protected:=protected OR OLD.type='business_term'; END IF;
 END IF;
 IF NOT protected THEN IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF; END IF;
 p:=public.gc_glossary_current();PERFORM public.gc_glossary_budget(p);
 IF TG_OP='DELETE' OR p.state<>'prepared' OR NEW.tenant_id<>p.tenant_id OR NEW.id<>p.asset_id OR NEW.version<>p.asset_version
 OR NEW.type<>'business_term' OR NEW.source_id IS NOT NULL OR NEW.status<>'active'
 OR NEW.model_id IS DISTINCT FROM p.payload#>>'{typePin,modelId}' OR NEW.model_version IS DISTINCT FROM (p.payload#>>'{typePin,version}')::integer
 OR NEW.attributes IS DISTINCT FROM p.payload->'attributes' OR NEW.owner_id IS DISTINCT FROM (p.payload->>'ownerId')::uuid
 OR NEW.type_state IS DISTINCT FROM p.payload->>'state' OR NEW.visibility IS DISTINCT FROM p.payload->>'visibility'
 OR NEW.allowed_identities IS DISTINCT FROM p.payload->'allowedIdentityIds' THEN RAISE EXCEPTION 'GLOSSARY_APPROVAL_REQUIRED' USING ERRCODE='42501'; END IF;
 SELECT t INTO primary_text FROM jsonb_array_elements(p.payload#>'{attributes,translations}') t WHERE t->>'locale'=p.payload->>'primaryLocale';
 IF NEW.name IS DISTINCT FROM primary_text->>'name' OR NEW.description IS DISTINCT FROM primary_text->>'definition' THEN RAISE EXCEPTION 'GLOSSARY_APPROVAL_REQUIRED' USING ERRCODE='42501'; END IF;
 IF TG_OP='INSERT' THEN
  IF p.before_endpoint IS NOT NULL OR NEW.observed_at IS NOT NULL OR NEW.external_id<>'glossary:'||p.asset_id::text OR NEW.qualified_name<>'glossary.'||p.asset_id::text
  OR NEW.parent_external_id IS NOT NULL OR NEW.metadata IS DISTINCT FROM jsonb_build_object('authoring',jsonb_build_object('kind','glossary','requestId',p.id,'proposalDigest',p.proposal_digest)) THEN RAISE EXCEPTION 'GLOSSARY_APPROVAL_REQUIRED' USING ERRCODE='42501'; END IF;
 ELSE
  SELECT a INTO original FROM jsonb_array_elements(p.baseline->'assets') a WHERE a->>'id'=p.asset_id::text;
  IF to_jsonb(OLD) IS DISTINCT FROM original OR (to_jsonb(NEW)-ARRAY['name','description','owner_id','visibility','allowed_identities','version','updated_at','attributes','type_state'])
   IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['name','description','owner_id','visibility','allowed_identities','version','updated_at','attributes','type_state']) THEN RAISE EXCEPTION 'GLOSSARY_APPROVAL_REQUIRED' USING ERRCODE='42501'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER glossary_asset_guard BEFORE INSERT OR UPDATE OR DELETE ON public.assets FOR EACH ROW EXECUTE FUNCTION public.gc_glossary_asset_guard();
CREATE FUNCTION public.gc_glossary_owned_link_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE p public.glossary_publications; op public.relation_graph_operations; BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.glossary_terms t JOIN public.glossary_publication_links l ON l.tenant_id=t.tenant_id AND l.publication_id=t.current_publication_id WHERE l.tenant_id=OLD.tenant_id AND l.relation_id=OLD.id) THEN
  IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF; END IF;
 p:=public.gc_glossary_current();PERFORM public.gc_glossary_budget(p);op:=public.gc_relation_graph_current();
 IF TG_OP='DELETE' OR p.state<>'staged' OR op.id IS NULL OR op.state<>'open' OR op.actor_id<>p.actor_id
 OR NOT EXISTS(SELECT 1 FROM public.glossary_publication_links l WHERE l.tenant_id=p.tenant_id AND l.publication_id=p.previous_publication_id AND l.relation_id=OLD.id)
 THEN RAISE EXCEPTION 'GLOSSARY_APPROVAL_REQUIRED' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER glossary_owned_link_guard BEFORE UPDATE OR DELETE ON public.relations FOR EACH ROW EXECUTE FUNCTION public.gc_glossary_owned_link_guard();
CREATE FUNCTION public.gc_glossary_namespace_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE protected boolean; BEGIN
 IF TG_TABLE_NAME='audit' THEN protected:=NEW.action='asset.glossary_published' OR NEW.action LIKE 'glossary.%';
 ELSE protected:=(CASE WHEN TG_OP='DELETE' THEN OLD.event_type ELSE NEW.event_type END)='asset.glossary_published'
  OR (CASE WHEN TG_OP='DELETE' THEN OLD.event_type ELSE NEW.event_type END) LIKE 'glossary.%';
  IF TG_OP='UPDATE' THEN protected:=protected OR OLD.event_type='asset.glossary_published' OR OLD.event_type LIKE 'glossary.%'; END IF;
 END IF;
 IF TG_TABLE_NAME='outbox' AND TG_OP='UPDATE' AND protected THEN
  IF (to_jsonb(NEW)-ARRAY['processed_at','attempts'])=(to_jsonb(OLD)-ARRAY['processed_at','attempts']) AND NEW.attempts>=OLD.attempts THEN RETURN NEW; END IF;
 END IF;
 IF protected AND current_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.glossary_publications'::regclass) THEN RAISE EXCEPTION 'GLOSSARY_RESERVED_NAMESPACE' USING ERRCODE='42501'; END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END $$;
CREATE TRIGGER glossary_namespace_guard BEFORE INSERT ON public.audit FOR EACH ROW EXECUTE FUNCTION public.gc_glossary_namespace_guard();
CREATE TRIGGER glossary_namespace_guard BEFORE INSERT OR UPDATE OR DELETE ON public.outbox FOR EACH ROW EXECUTE FUNCTION public.gc_glossary_namespace_guard();
CREATE FUNCTION public.gc_glossary_publication_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
 IF TG_OP='DELETE' OR OLD.state='sealed' THEN RAISE EXCEPTION 'Glossary publication history is immutable' USING ERRCODE='42501'; END IF;RETURN NEW;
END $$;
CREATE TRIGGER glossary_publication_immutable BEFORE UPDATE OR DELETE ON public.glossary_publications FOR EACH ROW EXECUTE FUNCTION public.gc_glossary_publication_immutable();
CREATE FUNCTION public.gc_glossary_complete() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE p public.glossary_publications; authored_asset public.assets; current_snapshot jsonb; type_identity uuid; BEGIN
 SELECT * INTO p FROM public.glossary_publications WHERE tenant_id=NEW.tenant_id AND id=NEW.id;
 PERFORM public.gc_glossary_budget(p);
 IF EXISTS(SELECT 1 FROM public.approval_requests WHERE tenant_id=p.tenant_id AND id=p.id AND expires_at<=clock_timestamp()) THEN
  RAISE EXCEPTION 'GLOSSARY_STATE_CONFLICT' USING ERRCODE='40001'; END IF;
 SELECT * INTO authored_asset FROM public.assets WHERE tenant_id=p.tenant_id AND id=p.asset_id;
 current_snapshot:=jsonb_build_object('id',authored_asset.id,'name',authored_asset.name,'qualifiedName',authored_asset.qualified_name,'type',authored_asset.type,'description',authored_asset.description,
  'ownerId',authored_asset.owner_id,'ownerName',NULL,'sourceId',authored_asset.source_id,'sourceName',NULL,'version',authored_asset.version,'observedAt',public.gc_relation_utc(authored_asset.observed_at),
  'updatedAt',public.gc_relation_utc(authored_asset.updated_at),'status',authored_asset.status,'metadata',authored_asset.metadata,'modelId',authored_asset.model_id,'modelVersion',authored_asset.model_version,'attributes',authored_asset.attributes,'typeState',authored_asset.type_state);
 IF p.state<>'sealed' OR p.asset_snapshot IS DISTINCT FROM current_snapshot OR authored_asset.version<>p.asset_version OR p.receipt IS NULL
 OR NOT EXISTS(SELECT 1 FROM public.glossary_terms WHERE tenant_id=p.tenant_id AND asset_id=p.asset_id AND current_publication_id=p.id)
 OR NOT EXISTS(SELECT 1 FROM public.approval_requests WHERE tenant_id=p.tenant_id AND id=p.id AND status='succeeded' AND result=p.receipt)
 OR NOT EXISTS(SELECT 1 FROM public.asset_revisions WHERE tenant_id=p.tenant_id AND asset_id=p.asset_id AND version=p.asset_version AND snapshot=p.asset_snapshot)
 OR NOT EXISTS(SELECT 1 FROM public.audit a JOIN public.outbox o ON o.tenant_id=a.tenant_id AND o.id=a.id WHERE a.tenant_id=p.tenant_id AND a.id=p.audit_id AND a.action='asset.glossary_published' AND a.resource_id=p.asset_id::text AND a.changes->>'publicationId'=p.id::text AND o.event_type=a.action AND o.resource_version=p.asset_version)
 OR NOT EXISTS(SELECT 1 FROM public.audit a JOIN public.outbox o ON o.tenant_id=a.tenant_id AND o.id=a.id JOIN public.approval_requests r ON r.tenant_id=a.tenant_id AND r.id=p.id WHERE a.tenant_id=p.tenant_id AND a.action='approval.succeeded' AND a.resource_id=p.id::text AND a.changes->>'publicationId'=p.id::text AND o.event_type=a.action AND o.resource_version=r.version)
 OR (SELECT count(*) FROM public.glossary_publication_links WHERE tenant_id=p.tenant_id AND publication_id=p.id)<>jsonb_array_length(p.payload->'links') THEN
  RAISE EXCEPTION 'GLOSSARY_INCOMPLETE_PUBLICATION' USING ERRCODE='23514'; END IF;
 FOREACH type_identity IN ARRAY p.relation_type_ids LOOP PERFORM public.gc_glossary_budget(p);PERFORM public.gc_relation_check_type(p.tenant_id,type_identity); END LOOP;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER glossary_publication_complete AFTER INSERT ON public.glossary_publications DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_glossary_complete();

-- SPDX-License-Identifier: Apache-2.0
-- Forward SQL016 graph integration, copied from immutable SQL010.
-- Protected staged publication augments only source scope/checks and the clock.
-- Ordinary source behavior and every final graph check remain strict.

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
 UNION SELECT unnest(p.relation_type_ids) FROM public.glossary_publications p CROSS JOIN op
  WHERE p.tenant_id=op.tenant_id AND p.transaction_id=pg_current_xact_id() AND p.actor_id=public.gc_actor()::uuid AND p.state='staged'
 UNION SELECT t.type_id FROM public.relation_types t JOIN public.relation_type_versions v ON v.tenant_id=t.tenant_id AND v.relation_type_id=t.type_id AND v.version=t.current_version
  CROSS JOIN op WHERE t.tenant_id=op.tenant_id AND public.gc_relation_graph_scope_tick(op.created_at,t.type_id)
  AND EXISTS(SELECT 1 FROM changed a WHERE
   public.gc_relation_graph_scope_eligible(op.tenant_id,a.id,v.definition,'source',op.created_at) OR public.gc_relation_graph_scope_eligible(op.tenant_id,a.id,v.definition,'target',op.created_at)
   OR public.gc_relation_projected_eligible(a.proposed,v.definition,'source') OR public.gc_relation_projected_eligible(a.proposed,v.definition,'target')
   OR EXISTS(SELECT 1 FROM public.relations r WHERE r.tenant_id=op.tenant_id AND r.relation_type_id=t.type_id AND r.status='active' AND a.id IN(r.source_asset_id,r.target_asset_id))
   OR EXISTS(SELECT 1 FROM public.relation_participations b WHERE b.tenant_id=op.tenant_id AND b.relation_type_id=t.type_id AND b.status='active' AND b.asset_id=a.id))
$$;

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
  OR EXISTS(SELECT 1 FROM public.glossary_publications p WHERE p.tenant_id=op.tenant_id AND p.transaction_id=pg_current_xact_id()
   AND p.actor_id=public.gc_actor()::uuid AND p.state='staged' AND p.asset_id=a.id)
  OR EXISTS(SELECT 1 FROM public.relation_graph_operation_model_claims m WHERE m.tenant_id=op.tenant_id AND m.operation_id=op.id AND m.model_id=a.model_id)
  OR EXISTS(SELECT 1 FROM types t WHERE public.gc_relation_graph_scope_eligible(op.tenant_id,a.id,t.before_definition,'source',op.created_at)
   OR public.gc_relation_graph_scope_eligible(op.tenant_id,a.id,t.before_definition,'target',op.created_at) OR public.gc_relation_graph_scope_eligible(op.tenant_id,a.id,t.after_definition,'source',op.created_at)
   OR public.gc_relation_graph_scope_eligible(op.tenant_id,a.id,t.after_definition,'target',op.created_at)
   OR EXISTS(SELECT 1 FROM public.relations r WHERE r.tenant_id=op.tenant_id AND r.relation_type_id=t.relation_type_id AND r.status='active' AND a.id IN(r.source_asset_id,r.target_asset_id))
   OR EXISTS(SELECT 1 FROM public.relation_participations b WHERE b.tenant_id=op.tenant_id AND b.relation_type_id=t.relation_type_id AND b.status='active' AND b.asset_id=a.id)
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(coalesce(t.plan->'creations','[]')) e(v) WHERE a.id::text IN(v->>'sourceAssetId',v->>'targetAssetId'))))
$$;

CREATE OR REPLACE FUNCTION public.gc_relation_graph_capture_scope(selected_operation uuid) RETURNS jsonb
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
  OR EXISTS(SELECT 1 FROM public.glossary_publications p WHERE p.tenant_id=op.tenant_id AND p.transaction_id=pg_current_xact_id()
   AND p.actor_id=public.gc_actor()::uuid AND p.state='staged' AND p.asset_id=a.id)
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

CREATE OR REPLACE FUNCTION public.gc_relation_graph_begin(operation_id uuid,idempotency_operation text,idempotency_key text,request_body jsonb,correlation_id text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
<<begin_context>>
DECLARE tenant uuid:=public.gc_tenant(); actor uuid:=public.gc_actor()::uuid; selected_operation uuid:=operation_id;
 request jsonb:=request_body; change_set jsonb:=request_body->'changeSet'; target jsonb; plan jsonb; expected jsonb; before_policy jsonb;
 type_identity uuid; head public.relation_types; prepared public.relation_type_preparations; policy jsonb; mode text;
 asset_row public.assets; before_tuple jsonb; after_tuple jsonb; asset_action text; changed boolean; candidate record; discovered_scope jsonb;
 type_claim public.relation_graph_operation_type_claims; principals uuid[]; source_versions jsonb; migration jsonb; glossary_context public.glossary_publications;
 remaining_ms bigint; previous_lock_ms bigint; started_at timestamptz:=date_trunc('milliseconds',clock_timestamp()); model_head public.governance_models; old_resolution jsonb; new_resolution jsonb; creation_map jsonb; enrollment_map jsonb;
BEGIN
 PERFORM public.gc_relation_authorize(ARRAY['models:read','models:write','catalog:read','catalog:write']);
 glossary_context:=public.gc_glossary_current();
 IF glossary_context.state='staged' THEN
  PERFORM public.gc_glossary_budget(glossary_context);
  started_at:=glossary_context.started_at;
 END IF;
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
  IF type_claim.mode<>'create' THEN PERFORM public.gc_glossary_graph_source_assert(tenant,type_claim.relation_type_id); END IF;
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

-- A terminal worker refusal is recorded only after the failed publication
-- transaction rolled back. Transport/timeouts never enter this finite command.
CREATE FUNCTION public.gc_glossary_fail(request_identity uuid,expected_version integer,failure_code text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant(); request public.approval_requests; outcome text; stamp timestamptz; BEGIN
 IF public.gc_actor() IS DISTINCT FROM 'site:local' OR expected_version IS NULL OR expected_version<1 OR failure_code NOT IN(
  'GLOSSARY_AUTHORITY_REVOKED','GLOSSARY_STATE_CONFLICT','GLOSSARY_POLICY_INVALID','GLOSSARY_INPUT_INVALID','GLOSSARY_LIMIT')
 OR failure_code IS NULL OR (public.gc_glossary_current()).id IS NOT NULL OR (public.gc_relation_graph_current()).id IS NOT NULL THEN
  RAISE EXCEPTION 'GLOSSARY_CONTEXT_REQUIRED' USING ERRCODE='42501'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text,0));
 SELECT * INTO request FROM public.approval_requests WHERE tenant_id=tenant AND id=request_identity FOR UPDATE;
 IF request.id IS NULL THEN RAISE EXCEPTION 'GLOSSARY_UNAVAILABLE' USING ERRCODE='P0002'; END IF;
 IF request.status<>'ready' OR request.version IS DISTINCT FROM expected_version THEN RETURN; END IF;
 stamp:=date_trunc('milliseconds',clock_timestamp());outcome:=CASE WHEN request.expires_at<=stamp THEN 'expired' ELSE 'failed' END;
 UPDATE public.approval_requests SET status=outcome,version=version+1,error_code=CASE WHEN outcome='failed' THEN failure_code END,updated_at=stamp WHERE tenant_id=tenant AND id=request.id;
 UPDATE public.approval_tasks SET status='cancelled',version=version+1 WHERE tenant_id=tenant AND request_id=request.id AND status IN('open','waiting');
 PERFORM public.gc_approval_journal('approval.'||outcome,NULL,request.id::text,request.version+1,jsonb_build_object('proposalDigest',request.proposal_digest,'code',CASE WHEN outcome='failed' THEN failure_code END),'glossary:'||request.id::text);
END $$;
DO $$ DECLARE signature text; BEGIN
 FOR signature IN SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'gc_glossary_%' LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,gc_app',signature);
 END LOOP;
END $$;
GRANT EXECUTE ON FUNCTION public.gc_glossary_prepare(uuid),public.gc_glossary_stage(uuid),public.gc_glossary_graph_source_evidence(uuid),public.gc_glossary_finish(uuid,uuid),public.gc_glossary_fail(uuid,integer,text) TO gc_app;
