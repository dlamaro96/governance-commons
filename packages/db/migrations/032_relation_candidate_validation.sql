-- SPDX-License-Identifier: Apache-2.0
-- SQL032: fence only the two nominal-candidate joins before exact eligibility.
-- Existing tenant/RLS, visibility, cardinality, locking and deadlines are unchanged.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR pg_has_role('gc_app',current_user,'MEMBER') THEN
  RAISE EXCEPTION 'Candidate validation requires a non-bypass migration owner' USING ERRCODE='42501'; END IF;
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
 OR (WITH candidates AS MATERIALIZED (
   SELECT a.id AS asset_id FROM public.gc_relation_nominal_candidates(head_definition) c
   JOIN public.assets a ON a.tenant_id=tenant AND a.id=c.asset_id
  ) SELECT count(*) FROM candidates c WHERE (public.gc_relation_endpoint_eligible(tenant,c.asset_id,head_definition,'source')
   OR public.gc_relation_endpoint_eligible(tenant,c.asset_id,head_definition,'target')))>2000 THEN
  RAISE EXCEPTION 'RELATION_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 FOR selected_side IN SELECT unnest(CASE WHEN head_definition->>'direction'='undirected' THEN ARRAY['incident'] ELSE ARRAY['source','target'] END) LOOP
  side_min:=(head_definition->'cardinality'->(CASE WHEN selected_side='target' THEN 'incoming' ELSE 'outgoing' END)->>'min')::integer;
  IF side_min>0 AND EXISTS(WITH candidates AS MATERIALIZED (
    SELECT a.id AS asset_id FROM public.gc_relation_nominal_candidates(head_definition) c
    JOIN public.assets a ON a.tenant_id=tenant AND a.id=c.asset_id
   ) SELECT 1 FROM candidates c
   WHERE public.gc_relation_endpoint_eligible(tenant,c.asset_id,head_definition,CASE WHEN selected_side='incident' THEN 'source' ELSE selected_side END)
   AND NOT EXISTS(SELECT 1 FROM public.relation_participations p WHERE p.tenant_id=tenant AND p.relation_type_id=type_identity
    AND p.asset_id=c.asset_id AND p.side=selected_side AND p.status='active')) THEN
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
