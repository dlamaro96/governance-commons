-- SPDX-License-Identifier: Apache-2.0
-- Forward correction for immutable SQL016. Nominal type candidates are a
-- superset only: unchanged exact eligibility, explicit/incident cohorts,
-- authorization-before-counts, original 30-second clock and final validation
-- remain authoritative. No application role gains function or table privileges.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR pg_has_role('gc_app',current_user,'MEMBER') THEN
  RAISE EXCEPTION 'Scope optimization requires a non-bypass migration owner' USING ERRCODE='42501'; END IF;
END $$;

CREATE OR REPLACE FUNCTION public.gc_relation_graph_candidate_assets(selected_operation uuid) RETURNS TABLE(asset_id uuid,action text)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 WITH op AS MATERIALIZED (SELECT o.tenant_id,o.id,o.normalized_change_set,o.created_at FROM public.relation_graph_operations o WHERE o.tenant_id=public.gc_tenant() AND o.id=selected_operation AND o.transaction_id=pg_current_xact_id()),
 types AS MATERIALIZED (SELECT ids.relation_type_id,coalesce(c.before_definition,v.definition) AS before_definition,coalesce(c.after_definition,v.definition) AS after_definition,c.plan
  FROM public.gc_relation_graph_candidate_types(selected_operation) ids CROSS JOIN op
  LEFT JOIN public.relation_graph_operation_type_claims c ON c.tenant_id=op.tenant_id AND c.operation_id=op.id AND c.relation_type_id=ids.relation_type_id
  LEFT JOIN public.relation_types t ON t.tenant_id=op.tenant_id AND t.type_id=ids.relation_type_id
  LEFT JOIN public.relation_type_versions v ON v.tenant_id=t.tenant_id AND v.relation_type_id=t.type_id AND v.version=t.current_version)
 ,rules AS MATERIALIZED (
  SELECT DISTINCT (rule->>'typeId')::uuid AS type_id,rule->>'includeDescendants'='true' AS descendants
  FROM types t CROSS JOIN LATERAL jsonb_array_elements(
   coalesce(t.before_definition->'sourceTypes','[]'::jsonb)||coalesce(t.before_definition->'targetTypes','[]'::jsonb)
   ||coalesce(t.after_definition->'sourceTypes','[]'::jsonb)||coalesce(t.after_definition->'targetTypes','[]'::jsonb)) e(rule)
 ),nominal AS MATERIALIZED (
  SELECT a.id FROM rules r CROSS JOIN op JOIN public.governance_models m ON m.tenant_id=op.tenant_id AND m.type_id=r.type_id
   JOIN public.assets a ON a.tenant_id=m.tenant_id AND a.model_id=m.id
  UNION
  SELECT a.id FROM rules r CROSS JOIN op JOIN public.governance_models m ON m.tenant_id=op.tenant_id AND m.type_id=r.type_id
   JOIN public.asset_type_dependencies d ON d.tenant_id=m.tenant_id AND d.dependency_model_id=m.id
   JOIN public.assets a ON a.tenant_id=d.tenant_id AND a.model_id=d.model_id AND a.model_version=d.version WHERE r.descendants
 ),eligible AS MATERIALIZED (
  SELECT n.id FROM nominal n CROSS JOIN op WHERE EXISTS(SELECT 1 FROM types t WHERE
   public.gc_relation_graph_scope_eligible(op.tenant_id,n.id,t.before_definition,'source',op.created_at)
   OR public.gc_relation_graph_scope_eligible(op.tenant_id,n.id,t.before_definition,'target',op.created_at)
   OR public.gc_relation_graph_scope_eligible(op.tenant_id,n.id,t.after_definition,'source',op.created_at)
   OR public.gc_relation_graph_scope_eligible(op.tenant_id,n.id,t.after_definition,'target',op.created_at))
 ),selected AS MATERIALIZED (
  SELECT id FROM eligible
  UNION SELECT (v->>'assetId')::uuid FROM op CROSS JOIN LATERAL jsonb_array_elements(op.normalized_change_set->'assetChanges') e(v)
  UNION SELECT p.asset_id FROM public.glossary_publications p CROSS JOIN op WHERE p.tenant_id=op.tenant_id AND p.transaction_id=pg_current_xact_id()
   AND p.actor_id=public.gc_actor()::uuid AND p.state='staged'
  UNION SELECT a.id FROM public.relation_graph_operation_model_claims m CROSS JOIN op
   JOIN public.assets a ON a.tenant_id=op.tenant_id AND a.model_id=m.model_id WHERE m.tenant_id=op.tenant_id AND m.operation_id=op.id
  UNION SELECT r.source_asset_id FROM types t CROSS JOIN op JOIN public.relations r ON r.tenant_id=op.tenant_id AND r.relation_type_id=t.relation_type_id WHERE r.status='active'
  UNION SELECT r.target_asset_id FROM types t CROSS JOIN op JOIN public.relations r ON r.tenant_id=op.tenant_id AND r.relation_type_id=t.relation_type_id WHERE r.status='active'
  UNION SELECT b.asset_id FROM types t CROSS JOIN op JOIN public.relation_participations b ON b.tenant_id=op.tenant_id AND b.relation_type_id=t.relation_type_id WHERE b.status='active'
  UNION SELECT (v->>'sourceAssetId')::uuid FROM types t CROSS JOIN LATERAL jsonb_array_elements(coalesce(t.plan->'creations','[]'::jsonb)) e(v)
  UNION SELECT (v->>'targetAssetId')::uuid FROM types t CROSS JOIN LATERAL jsonb_array_elements(coalesce(t.plan->'creations','[]'::jsonb)) e(v)
 )
 SELECT a.id,coalesce((SELECT v->>'kind' FROM jsonb_array_elements(op.normalized_change_set->'assetChanges') e(v) WHERE v->>'assetId'=a.id::text),
  CASE WHEN EXISTS(SELECT 1 FROM public.relation_graph_operation_model_claims m WHERE m.tenant_id=op.tenant_id AND m.operation_id=op.id AND m.model_id=a.model_id) THEN 'type-migrate' ELSE 'preserve' END)
 FROM selected c CROSS JOIN op JOIN public.assets a ON a.tenant_id=op.tenant_id AND a.id=c.id
 WHERE public.gc_relation_graph_scope_tick(op.created_at,a.id)
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
 ,assets AS MATERIALIZED (SELECT asset_id,action FROM public.gc_relation_graph_candidate_assets(selected_operation))
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

REVOKE ALL ON FUNCTION public.gc_relation_graph_candidate_assets(uuid),public.gc_relation_graph_capture_scope(uuid) FROM PUBLIC,gc_app;
