-- SPDX-License-Identifier: Apache-2.0
-- Align canonical scope and lifetime bounds with the authority evaluator.
-- Must execute through the existing single-transaction/checksum migration runner.
-- No table, row, trigger, role, policy, ACL or activation state is changed.
-- Proposed installation ceilings are refusal bounds, not throughput claims.
SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '2s';
SET LOCAL row_security = 'on';
DO $migration$
DECLARE
 max_tenants constant bigint:=10000;
 max_active_roots constant bigint:=100000;
 max_visited_rows constant bigint:=1000000;
 max_row_bytes constant bigint:=8388608;
 max_row_nodes constant bigint:=262144;
 max_row_depth constant bigint:=32;
 max_projection_bytes constant bigint:=2097152;
 deadline constant timestamptz:=transaction_timestamp()+interval '30 seconds';
 old_t text:=current_setting('gc.tenant_id',true);
 old_a text:=current_setting('gc.actor_id',true);
 tenant_count bigint:=0;active_count bigint:=0;visited_count bigint:=0;
 selected_tenant uuid;root_id uuid;next_id uuid;seen uuid[];hops integer;
 g gc_authority.grant_heads;p gc_authority.grant_heads;c gc_authority.connected_parents;
 raw_bytes bigint;measure bigint[];projection record;relation_name text;
BEGIN
 PERFORM gc_authority.owner_check();
 PERFORM gc_authority.require(NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls)),'42501');
 PERFORM gc_authority.require(clock_timestamp()<deadline,'57014');
 -- NOWAIT ensures incompatible active writers cause an atomic retry/refusal,
 -- not a tenant-row/DDL lock-order deadlock while scanning another tenant.
 LOCK TABLE public.tenants,gc_authority.tenant_heads,gc_authority.grant_heads,
   gc_authority.connected_parents,gc_authority.projection_measures
   IN SHARE ROW EXCLUSIVE MODE NOWAIT;
 PERFORM gc_authority.require(clock_timestamp()<deadline,'57014');
 -- The canonical tenant inventory is not subject to a tenant filter. Every
 -- private tenant table retains exactly the installed tenant RLS policy.
 PERFORM gc_authority.require(EXISTS(SELECT 1 FROM pg_catalog.pg_class WHERE oid='public.tenants'::regclass AND NOT relrowsecurity),'23514');
 FOREACH relation_name IN ARRAY ARRAY['tenant_heads','grant_heads','connected_parents','projection_measures'] LOOP
  PERFORM gc_authority.require(EXISTS(SELECT 1 FROM pg_catalog.pg_class q WHERE q.oid=('gc_authority.'||relation_name)::regclass AND q.relrowsecurity AND q.relforcerowsecurity)
   AND (SELECT count(*)=1 FROM pg_catalog.pg_policy z WHERE z.polrelid=('gc_authority.'||relation_name)::regclass)
   AND EXISTS(SELECT 1 FROM pg_catalog.pg_policy z WHERE z.polrelid=('gc_authority.'||relation_name)::regclass
     AND z.polname='authority_tenant' AND z.polpermissive AND z.polcmd='*' AND z.polroles=ARRAY[0::oid]
     AND pg_catalog.pg_get_expr(z.polqual,z.polrelid) IN('(tenant_id = gc_tenant())','(tenant_id = public.gc_tenant())')
     AND pg_catalog.pg_get_expr(z.polwithcheck,z.polrelid) IN('(tenant_id = gc_tenant())','(tenant_id = public.gc_tenant())')),'23514');
 END LOOP;
 PERFORM gc_authority.require(EXISTS(SELECT 1 FROM pg_catalog.pg_proc q WHERE q.oid='gc_authority.source_guard()'::regprocedure AND q.proowner=session_user::regrole::oid AND NOT q.prosecdef AND encode(sha256(convert_to(q.prosrc,'UTF8')),'hex')='d383cfdab763be0b2719fa99876eaa4b2f584500757451f6a0035eaaa7ba92f8'),'23514');
 PERFORM gc_authority.require(EXISTS(SELECT 1 FROM pg_catalog.pg_proc q WHERE q.oid='gc_authority.validate_grant(uuid,uuid,boolean)'::regprocedure AND q.proowner=session_user::regrole::oid AND NOT q.prosecdef AND encode(sha256(convert_to(q.prosrc,'UTF8')),'hex')='dba5952e02b6b85f6e464024362845f9fc4923abd5f303b4270f8e6190c7f6e5'),'23514');
 PERFORM gc_authority.require(EXISTS(SELECT 1 FROM pg_catalog.pg_proc q WHERE q.oid='gc_authority.validate_read_grants_v1(uuid,uuid[])'::regprocedure AND q.proowner=session_user::regrole::oid AND NOT q.prosecdef AND encode(sha256(convert_to(q.prosrc,'UTF8')),'hex')='ef7b28a1b423c7e9d0c17d8b981ea169556f1cbc448a33992eea4d19efe21714'),'23514');
 -- No authority table is read before setting this iteration's tenant.
 FOR selected_tenant IN SELECT t.id FROM public.tenants t ORDER BY t.id LIMIT max_tenants+1 LOOP
  tenant_count:=tenant_count+1;PERFORM gc_authority.require(tenant_count<=max_tenants,'54000');
  PERFORM gc_authority.require(clock_timestamp()<deadline,'57014');
  PERFORM set_config('gc.tenant_id',selected_tenant::text,true);
  PERFORM set_config('gc.actor_id','',true);
  -- No expiry/not-before pruning: lifecycle-active includes future and expired.
  FOR root_id IN SELECT h.id FROM gc_authority.grant_heads h
    WHERE h.tenant_id=selected_tenant AND h.state='active' ORDER BY h.id
    LIMIT max_active_roots-active_count+1 LOOP
   active_count:=active_count+1;PERFORM gc_authority.require(active_count<=max_active_roots,'54000');
   next_id:=root_id;seen:='{}';hops:=0;
   LOOP
    PERFORM gc_authority.require(clock_timestamp()<deadline,'57014');
    visited_count:=visited_count+1;PERFORM gc_authority.require(visited_count<=max_visited_rows,'54000');
    PERFORM gc_authority.require(NOT next_id=ANY(seen),'23514');seen:=array_append(seen,next_id);
    -- Scalar metadata first; exact protected projection measures already bind
    -- immutable issuance and the current head. Full row measure includes the
    -- separate control ceiling, which is not in the content grant DTO.
    SELECT m.canonical_bytes,m.json_nodes,m.json_depth INTO projection
      FROM gc_authority.projection_measures m JOIN gc_authority.grant_heads h
       ON (h.tenant_id,h.id,h.issuance_version,h.head_version)=(m.tenant_id,m.object_id,m.issuance_or_definition_version,m.head_version)
      WHERE h.tenant_id=selected_tenant AND h.id=next_id AND m.family='grant'
       AND m.definition_kind IS NULL AND m.sub_id IS NULL
       AND m.projection_form=CASE h.kind WHEN 'elevation' THEN 'grant-base' ELSE 'dto' END;
    PERFORM gc_authority.require(projection.canonical_bytes IS NOT NULL,'23514');
    PERFORM gc_authority.require(projection.canonical_bytes<=max_projection_bytes AND projection.json_nodes<=max_row_nodes AND projection.json_depth<=max_row_depth,'54000');
    SELECT octet_length(gc_authority.canonical(to_jsonb(h))),gc_authority.json_measure(to_jsonb(h))
      INTO raw_bytes,measure FROM gc_authority.grant_heads h WHERE h.tenant_id=selected_tenant AND h.id=next_id;
    PERFORM gc_authority.require(raw_bytes IS NOT NULL,'23514');
    PERFORM gc_authority.require(raw_bytes<=max_row_bytes AND measure[1]<=max_row_nodes AND measure[2]<=max_row_depth,'54000');
    PERFORM gc_authority.require(clock_timestamp()<deadline,'57014');
    SELECT * INTO g FROM gc_authority.grant_heads h WHERE h.tenant_id=selected_tenant AND h.id=next_id;
    PERFORM gc_authority.require(g.id IS NOT NULL,'23514');
    PERFORM gc_authority.require(gc_authority.scope_literal_subset(gc_authority.scope(g),g.effect_ceiling->'scope') AND gc_authority.temporal_subset(g.effect_ceiling->'validity',gc_authority.validity(g.not_before,g.expires_at)) AND (g.delegable_ceiling IS NULL OR (gc_authority.finite_subset(g.delegable_ceiling,g.effect_ceiling) AND gc_authority.scope_literal_subset(g.delegable_ceiling->'scope',gc_authority.scope(g)) AND gc_authority.scope_literal_subset(g.delegable_ceiling->'scope',g.effect_ceiling->'scope') AND gc_authority.temporal_subset(g.delegable_ceiling->'validity',gc_authority.validity(g.not_before,g.expires_at)))),'23514');
    EXIT WHEN g.kind IN('ordinary-role','responsibility');
    hops:=hops+1;PERFORM gc_authority.require(hops<=4 AND g.kind IN('delegation','elevation'),'23514');
    SELECT * INTO c FROM gc_authority.connected_parents e WHERE e.tenant_id=selected_tenant AND e.child_id=g.id;
    PERFORM gc_authority.require(c.child_id IS NOT NULL,'23514');
    -- Repeated parent body visits count as well as each root/ancestry visit.
    visited_count:=visited_count+1;PERFORM gc_authority.require(visited_count<=max_visited_rows,'54000');
    -- Parent scalar preflight precedes body selection even when already seen.
    SELECT octet_length(gc_authority.canonical(to_jsonb(h))),gc_authority.json_measure(to_jsonb(h))
      INTO raw_bytes,measure FROM gc_authority.grant_heads h WHERE h.tenant_id=selected_tenant AND h.id=c.parent_id;
    PERFORM gc_authority.require(raw_bytes IS NOT NULL,'23514');
    PERFORM gc_authority.require(raw_bytes<=max_row_bytes AND measure[1]<=max_row_nodes AND measure[2]<=max_row_depth,'54000');
    PERFORM gc_authority.require(clock_timestamp()<deadline,'57014');
    SELECT * INTO p FROM gc_authority.grant_heads h WHERE h.tenant_id=selected_tenant AND h.id=c.parent_id;
    PERFORM gc_authority.require(p.id IS NOT NULL AND p.kind<>'elevation' AND p.delegable_ceiling IS NOT NULL,'23514');
    PERFORM gc_authority.require(gc_authority.finite_subset(g.effect_ceiling,p.effect_ceiling) AND gc_authority.finite_subset(g.effect_ceiling,p.delegable_ceiling) AND gc_authority.temporal_subset(gc_authority.validity(g.not_before,g.expires_at),gc_authority.validity(p.not_before,p.expires_at)) AND gc_authority.temporal_subset(gc_authority.validity(g.not_before,g.expires_at),p.effect_ceiling->'validity') AND gc_authority.temporal_subset(gc_authority.validity(g.not_before,g.expires_at),p.delegable_ceiling->'validity') AND gc_authority.scope_literal_subset(gc_authority.scope(g),gc_authority.scope(p)) AND gc_authority.scope_literal_subset(gc_authority.scope(g),p.effect_ceiling->'scope') AND gc_authority.scope_literal_subset(gc_authority.scope(g),p.delegable_ceiling->'scope') AND gc_authority.scope_literal_subset(g.effect_ceiling->'scope',p.effect_ceiling->'scope') AND gc_authority.scope_literal_subset(g.effect_ceiling->'scope',p.delegable_ceiling->'scope'),'23514');
    next_id:=p.id;
   END LOOP;
  END LOOP;
 END LOOP;
 -- The old shape trigger is never invoked by preflight, and no row is rewritten.
 -- Only after every active root and retained ancestor passes do replacements run.
 PERFORM gc_authority.require(clock_timestamp()<deadline,'57014');
 EXECUTE $replace_source_guard$
CREATE OR REPLACE FUNCTION gc_authority.source_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,gc_authority,pg_temp SET row_security=on AS $$ DECLARE j jsonb;p jsonb;r jsonb;h gc_authority.definition_heads;v gc_authority.definition_versions;n integer:=0;rule_expr jsonb;stats integer[];BEGIN
 IF TG_TABLE_NAME='policy_versions' THEN SELECT gc_authority.registry(registry_document) INTO r FROM gc_authority.registries z JOIN gc_authority.tenant_heads t ON (t.registry_id,t.registry_version,t.registry_digest)=(z.id,z.version,z.digest) WHERE t.tenant_id=NEW.tenant_id;p:=gc_authority.policy(NEW.policy_document,r->'fields');FOR rule_expr IN SELECT value FROM jsonb_array_elements(p->'rules') LOOP stats:=gc_authority.expression_stats(rule_expr->'when');n:=n+stats[1];END LOOP;
 PERFORM gc_authority.require((p->>'id')::uuid=NEW.policy_id AND (p->>'version')::int=NEW.version AND gc_authority.hash(p)=NEW.policy_hash AND octet_length(gc_authority.canonical(p))=NEW.canonical_bytes AND jsonb_array_length(p->'rules')=NEW.rule_count AND n=NEW.expression_node_count,'23514');
 ELSIF TG_TABLE_NAME='grant_heads' THEN SELECT gc_authority.registry(registry_document) INTO r FROM gc_authority.registries WHERE (id,version,digest)=(NEW.registry_id,NEW.registry_version,NEW.registry_digest);PERFORM gc_authority.require(r IS NOT NULL,'23514');
 PERFORM gc_authority.require(pg_column_size(NEW.effect_ceiling)<=8388608 AND gc_authority.scope(NEW)=gc_authority.normalize(gc_authority.scope(NEW),'"scope"') AND NEW.effect_ceiling=gc_authority.normalize(NEW.effect_ceiling,'"effect"',r->'fields') AND gc_authority.scope_tenant(NEW.effect_ceiling->'scope')=NEW.tenant_id AND gc_authority.temporal_subset(NEW.effect_ceiling->'validity',gc_authority.validity(NEW.not_before,NEW.expires_at)) AND gc_authority.scope_literal_subset(gc_authority.scope(NEW),NEW.effect_ceiling->'scope'),'23514');
 PERFORM gc_authority.require(NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(NEW.effect_ceiling->'actions') x WHERE x=ANY(gc_authority.service_actions())),'23514');
 IF NEW.delegable_ceiling IS NOT NULL THEN PERFORM gc_authority.require(NEW.delegable_ceiling=gc_authority.normalize(NEW.delegable_ceiling,'"delegable"',r->'fields') AND gc_authority.scope_tenant(NEW.delegable_ceiling->'scope')=NEW.tenant_id AND gc_authority.finite_subset(NEW.delegable_ceiling,NEW.effect_ceiling) AND gc_authority.scope_literal_subset(NEW.delegable_ceiling->'scope',NEW.effect_ceiling->'scope') AND gc_authority.scope_literal_subset(NEW.delegable_ceiling->'scope',gc_authority.scope(NEW)) AND gc_authority.temporal_subset(NEW.delegable_ceiling->'validity',gc_authority.validity(NEW.not_before,NEW.expires_at)),'23514');END IF;
 IF NEW.control_ceiling IS NOT NULL THEN PERFORM gc_authority.require(NEW.control_ceiling=gc_authority.normalize(NEW.control_ceiling,'"control"',r->'fields') AND gc_authority.scope_tenant(NEW.control_ceiling->'scope')=NEW.tenant_id,'23514');END IF;
 PERFORM gc_authority.require((NEW.control_ceiling IS NOT NULL)=EXISTS(SELECT 1 FROM jsonb_array_elements_text(NEW.effect_ceiling->'actions') x WHERE x=ANY(gc_authority.admin_actions())),'23514');
 IF NEW.kind='elevation' THEN PERFORM gc_authority.require(NEW.expires_at IS NOT NULL AND NEW.delegable_ceiling IS NULL AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(NEW.effect_ceiling->'actions') x WHERE NOT x=ANY(gc_authority.compatible_actions())),'23514');ELSIF NEW.kind='delegation' THEN PERFORM gc_authority.require(NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(NEW.effect_ceiling->'actions') x WHERE x=ANY(gc_authority.field_actions())),'23514');END IF;
 END IF;RETURN NEW;END $$;
 $replace_source_guard$;
 PERFORM gc_authority.require(clock_timestamp()<deadline,'57014');
 EXECUTE $replace_validate_grant$
CREATE OR REPLACE FUNCTION gc_authority.validate_grant(t uuid,i uuid,read_mode boolean DEFAULT false) RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,gc_authority,pg_temp SET row_security=on AS $$
DECLARE g gc_authority.grant_heads;p gc_authority.grant_heads;c gc_authority.connected_parents;o gc_authority.ordinary_role_origins;r gc_authority.responsibility_origins;rp gc_authority.responsibility_role_pins;m gc_authority.group_memberships;visited uuid[]:='{}';people uuid[]:='{}';hops integer:=0;root_role uuid;root_version integer;pol record;reg jsonb;j jsonb;own_id uuid:=i;
BEGIN
 PERFORM gc_authority.tick();SELECT * INTO g FROM gc_authority.grant_heads WHERE tenant_id=t AND id=i;PERFORM gc_authority.require(g.id IS NOT NULL,'23514');
 PERFORM gc_authority.require((SELECT count(*) FROM gc_authority.grant_human_beneficiaries WHERE tenant_id=t AND grant_id=i)=CASE g.beneficiary_kind WHEN 'human' THEN 1 ELSE 0 END AND (SELECT count(*) FROM gc_authority.grant_group_beneficiaries WHERE tenant_id=t AND grant_id=i)=CASE g.beneficiary_kind WHEN 'group' THEN 1 ELSE 0 END,'23514');
 IF g.beneficiary_kind='human' THEN PERFORM gc_authority.require(EXISTS(SELECT 1 FROM gc_authority.grant_human_beneficiaries WHERE tenant_id=t AND grant_id=i AND identity_id=g.beneficiary_id),'23514');ELSE PERFORM gc_authority.require(EXISTS(SELECT 1 FROM gc_authority.grant_group_beneficiaries WHERE tenant_id=t AND grant_id=i AND group_id=g.beneficiary_id),'23514');END IF;
 PERFORM gc_authority.require((SELECT count(*) FROM gc_authority.ordinary_role_origins WHERE tenant_id=t AND grant_id=i)=CASE g.kind WHEN 'ordinary-role' THEN 1 ELSE 0 END AND (SELECT count(*) FROM gc_authority.responsibility_origins WHERE tenant_id=t AND grant_id=i)=CASE g.kind WHEN 'responsibility' THEN 1 ELSE 0 END AND (SELECT count(*) FROM gc_authority.connected_parents WHERE tenant_id=t AND child_id=i)=CASE WHEN g.kind IN('delegation','elevation') THEN 1 ELSE 0 END,'23514');
 LOOP
 PERFORM gc_authority.require(NOT g.id=ANY(visited),'23514');visited:=array_append(visited,g.id);
 -- Every retained ancestor must satisfy the corrected literal bounds, even if revoked.
 PERFORM gc_authority.require(gc_authority.scope_literal_subset(gc_authority.scope(g),g.effect_ceiling->'scope') AND gc_authority.temporal_subset(g.effect_ceiling->'validity',gc_authority.validity(g.not_before,g.expires_at)) AND (g.delegable_ceiling IS NULL OR (gc_authority.finite_subset(g.delegable_ceiling,g.effect_ceiling) AND gc_authority.scope_literal_subset(g.delegable_ceiling->'scope',gc_authority.scope(g)) AND gc_authority.scope_literal_subset(g.delegable_ceiling->'scope',g.effect_ceiling->'scope') AND gc_authority.temporal_subset(g.delegable_ceiling->'validity',gc_authority.validity(g.not_before,g.expires_at)))),'23514');
 IF g.kind='ordinary-role' THEN SELECT * INTO o FROM gc_authority.ordinary_role_origins WHERE tenant_id=t AND grant_id=g.id;root_role:=o.role_id;root_version:=o.role_version;EXIT;
 ELSIF g.kind='responsibility' THEN SELECT * INTO r FROM gc_authority.responsibility_origins WHERE tenant_id=t AND grant_id=g.id;SELECT * INTO rp FROM gc_authority.responsibility_role_pins WHERE tenant_id=t AND type_id=r.type_id AND type_version=r.type_version;PERFORM gc_authority.require(rp.type_id IS NOT NULL AND (r.mapped_role_id,r.mapped_role_version) IS NOT DISTINCT FROM (rp.role_id,rp.role_version) AND ((r.mapped_role_id IS NULL AND r.effective_grant_id IS NULL AND g.control_ceiling IS NULL AND g.delegable_ceiling IS NULL) OR (r.mapped_role_id IS NOT NULL AND r.effective_grant_id=g.id)),'23514');root_role:=r.mapped_role_id;root_version:=r.mapped_role_version;EXIT;END IF;
 hops:=hops+1;PERFORM gc_authority.require(hops<=4 AND g.beneficiary_kind='human' AND NOT g.beneficiary_id=ANY(people),'23514');people:=array_append(people,g.beneficiary_id);PERFORM gc_authority.require(NOT g.issuer_identity_id=ANY(people),'23514');
 SELECT * INTO c FROM gc_authority.connected_parents WHERE tenant_id=t AND child_id=g.id;SELECT * INTO p FROM gc_authority.grant_heads WHERE tenant_id=t AND id=c.parent_id;PERFORM gc_authority.require(p.id IS NOT NULL AND p.kind<>'elevation' AND c.parent_kind=CASE p.kind WHEN 'delegation' THEN 'delegation' ELSE 'grant' END AND p.delegable_ceiling IS NOT NULL,'23514');
 IF p.beneficiary_kind='human' THEN PERFORM gc_authority.require(p.beneficiary_id=g.issuer_identity_id AND c.via_group_membership_id IS NULL,'23514');ELSE SELECT * INTO m FROM gc_authority.group_memberships WHERE tenant_id=t AND id=c.via_group_membership_id AND issuance_version=c.via_group_membership_version;PERFORM gc_authority.require(m.id IS NOT NULL AND m.group_id=p.beneficiary_id AND m.identity_id=g.issuer_identity_id,'23514');END IF;
 PERFORM gc_authority.require(gc_authority.finite_subset(g.effect_ceiling,p.effect_ceiling) AND gc_authority.finite_subset(g.effect_ceiling,p.delegable_ceiling) AND gc_authority.temporal_subset(gc_authority.validity(g.not_before,g.expires_at),gc_authority.validity(p.not_before,p.expires_at)) AND gc_authority.temporal_subset(gc_authority.validity(g.not_before,g.expires_at),p.effect_ceiling->'validity') AND gc_authority.temporal_subset(gc_authority.validity(g.not_before,g.expires_at),p.delegable_ceiling->'validity') AND gc_authority.scope_literal_subset(gc_authority.scope(g),gc_authority.scope(p)) AND gc_authority.scope_literal_subset(gc_authority.scope(g),p.effect_ceiling->'scope') AND gc_authority.scope_literal_subset(gc_authority.scope(g),p.delegable_ceiling->'scope') AND gc_authority.scope_literal_subset(g.effect_ceiling->'scope',p.effect_ceiling->'scope') AND gc_authority.scope_literal_subset(g.effect_ceiling->'scope',p.delegable_ceiling->'scope') AND (p.delegable_ceiling->>'remainingDepth')::int>=hops,'23514');
 IF g.delegable_ceiling IS NOT NULL THEN PERFORM gc_authority.require(gc_authority.finite_subset(g.delegable_ceiling,p.delegable_ceiling) AND (g.delegable_ceiling->>'remainingDepth')::int<(p.delegable_ceiling->>'remainingDepth')::int,'23514');END IF;
 IF g.control_ceiling IS NOT NULL THEN PERFORM gc_authority.require(p.control_ceiling IS NOT NULL AND gc_authority.finite_subset(g.control_ceiling,p.control_ceiling) AND (NOT (g.control_ceiling->>'allowSelfBenefit')::boolean OR (p.control_ceiling->>'allowSelfBenefit')::boolean),'23514');END IF;g:=p;
 END LOOP;
 -- Exact root policy set cannot introduce service actions into a human origin.
 IF root_role IS NOT NULL THEN SELECT gc_authority.registry(registry_document) INTO reg FROM gc_authority.registries WHERE (id,version,digest)=(g.registry_id,g.registry_version,g.registry_digest);
 FOR pol IN SELECT p_sql.policy_document FROM gc_authority.role_policy_pins rp_sql JOIN gc_authority.policy_versions p_sql ON (p_sql.tenant_id,p_sql.policy_id,p_sql.version,p_sql.policy_hash)=(rp_sql.tenant_id,rp_sql.policy_id,rp_sql.policy_version,rp_sql.policy_hash) WHERE rp_sql.tenant_id=t AND rp_sql.role_id=root_role AND rp_sql.role_version=root_version LOOP j:=gc_authority.policy(pol.policy_document,reg->'fields');PERFORM gc_authority.require(NOT EXISTS(SELECT 1 FROM jsonb_array_elements(j->'rules') rule CROSS JOIN LATERAL jsonb_array_elements_text(rule->'actions') a WHERE a=ANY(gc_authority.service_actions())),'23514');END LOOP;END IF;
 SELECT * INTO g FROM gc_authority.grant_heads WHERE tenant_id=t AND id=own_id;
 IF NOT read_mode AND g.state='active' AND (g.expires_at IS NULL OR g.expires_at>clock_timestamp()) THEN
 PERFORM gc_authority.require(g.beneficiary_kind<>'group' OR EXISTS(SELECT 1 FROM gc_authority.definition_heads h WHERE h.tenant_id=t AND h.id=g.beneficiary_id AND h.kind='group' AND h.state='active'),'23514');
 IF root_role IS NOT NULL THEN PERFORM gc_authority.require(EXISTS(SELECT 1 FROM gc_authority.definition_heads h WHERE h.tenant_id=t AND h.id=root_role AND h.kind='role' AND h.state='active') AND NOT EXISTS(SELECT 1 FROM gc_authority.role_policy_pins p_sql JOIN gc_authority.definition_heads h ON h.tenant_id=p_sql.tenant_id AND h.id=p_sql.policy_id WHERE p_sql.tenant_id=t AND p_sql.role_id=root_role AND p_sql.role_version=root_version AND h.state<>'active'),'23514');END IF;
 IF r.type_id IS NOT NULL THEN PERFORM gc_authority.require(EXISTS(SELECT 1 FROM gc_authority.definition_heads h WHERE h.tenant_id=t AND h.id=r.type_id AND h.kind='responsibility-type' AND h.state='active'),'23514');END IF;END IF;
 PERFORM gc_authority.require_measure(t,'grant',g.id,1,g.head_version,NULL,CASE g.kind WHEN 'elevation' THEN 'grant-base' ELSE 'dto' END);PERFORM gc_authority.tick();
END $$;
 $replace_validate_grant$;
 PERFORM gc_authority.require(clock_timestamp()<deadline,'57014');
 EXECUTE $replace_validate_read_grants_v1$
CREATE OR REPLACE FUNCTION gc_authority.validate_read_grants_v1(t uuid,ids uuid[]) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,gc_authority,pg_temp SET row_security=on AS $$
DECLARE i uuid;cached_registry gc_authority.registries;selected_registry gc_authority.registries;cached_parsed jsonb;
BEGIN
 PERFORM gc_authority.owner_check();
 PERFORM gc_authority.require(t=public.gc_tenant() AND current_setting('transaction_read_only')='on'
  AND current_setting('transaction_isolation')='repeatable read','42501');
 PERFORM gc_authority.require(ids IS NOT NULL AND coalesce(array_ndims(ids),1)=1
  AND coalesce(array_lower(ids,1),1)=1 AND cardinality(ids)<=1536
  AND NOT EXISTS(SELECT 1 FROM unnest(ids) x WHERE NOT gc_authority.valid_uuid(x))
  AND cardinality(ids)=(SELECT count(DISTINCT x) FROM unnest(ids) x),'54000');
 FOREACH i IN ARRAY ids LOOP
  -- A new nested block resets every grant/ancestry variable for every ID.
DECLARE read_mode constant boolean:=true;g gc_authority.grant_heads;p gc_authority.grant_heads;c gc_authority.connected_parents;o gc_authority.ordinary_role_origins;r gc_authority.responsibility_origins;rp gc_authority.responsibility_role_pins;m gc_authority.group_memberships;visited uuid[]:='{}';people uuid[]:='{}';hops integer:=0;root_role uuid;root_version integer;pol record;reg jsonb;j jsonb;own_id uuid:=i;
BEGIN
 PERFORM gc_authority.tick();SELECT * INTO g FROM gc_authority.grant_heads WHERE tenant_id=t AND id=i;PERFORM gc_authority.require(g.id IS NOT NULL,'23514');
 PERFORM gc_authority.require((SELECT count(*) FROM gc_authority.grant_human_beneficiaries WHERE tenant_id=t AND grant_id=i)=CASE g.beneficiary_kind WHEN 'human' THEN 1 ELSE 0 END AND (SELECT count(*) FROM gc_authority.grant_group_beneficiaries WHERE tenant_id=t AND grant_id=i)=CASE g.beneficiary_kind WHEN 'group' THEN 1 ELSE 0 END,'23514');
 IF g.beneficiary_kind='human' THEN PERFORM gc_authority.require(EXISTS(SELECT 1 FROM gc_authority.grant_human_beneficiaries WHERE tenant_id=t AND grant_id=i AND identity_id=g.beneficiary_id),'23514');ELSE PERFORM gc_authority.require(EXISTS(SELECT 1 FROM gc_authority.grant_group_beneficiaries WHERE tenant_id=t AND grant_id=i AND group_id=g.beneficiary_id),'23514');END IF;
 PERFORM gc_authority.require((SELECT count(*) FROM gc_authority.ordinary_role_origins WHERE tenant_id=t AND grant_id=i)=CASE g.kind WHEN 'ordinary-role' THEN 1 ELSE 0 END AND (SELECT count(*) FROM gc_authority.responsibility_origins WHERE tenant_id=t AND grant_id=i)=CASE g.kind WHEN 'responsibility' THEN 1 ELSE 0 END AND (SELECT count(*) FROM gc_authority.connected_parents WHERE tenant_id=t AND child_id=i)=CASE WHEN g.kind IN('delegation','elevation') THEN 1 ELSE 0 END,'23514');
 LOOP
 PERFORM gc_authority.require(NOT g.id=ANY(visited),'23514');visited:=array_append(visited,g.id);
 -- Every retained ancestor must satisfy the corrected literal bounds, even if revoked.
 PERFORM gc_authority.require(gc_authority.scope_literal_subset(gc_authority.scope(g),g.effect_ceiling->'scope') AND gc_authority.temporal_subset(g.effect_ceiling->'validity',gc_authority.validity(g.not_before,g.expires_at)) AND (g.delegable_ceiling IS NULL OR (gc_authority.finite_subset(g.delegable_ceiling,g.effect_ceiling) AND gc_authority.scope_literal_subset(g.delegable_ceiling->'scope',gc_authority.scope(g)) AND gc_authority.scope_literal_subset(g.delegable_ceiling->'scope',g.effect_ceiling->'scope') AND gc_authority.temporal_subset(g.delegable_ceiling->'validity',gc_authority.validity(g.not_before,g.expires_at)))),'23514');
 IF g.kind='ordinary-role' THEN SELECT * INTO o FROM gc_authority.ordinary_role_origins WHERE tenant_id=t AND grant_id=g.id;root_role:=o.role_id;root_version:=o.role_version;EXIT;
 ELSIF g.kind='responsibility' THEN SELECT * INTO r FROM gc_authority.responsibility_origins WHERE tenant_id=t AND grant_id=g.id;SELECT * INTO rp FROM gc_authority.responsibility_role_pins WHERE tenant_id=t AND type_id=r.type_id AND type_version=r.type_version;PERFORM gc_authority.require(rp.type_id IS NOT NULL AND (r.mapped_role_id,r.mapped_role_version) IS NOT DISTINCT FROM (rp.role_id,rp.role_version) AND ((r.mapped_role_id IS NULL AND r.effective_grant_id IS NULL AND g.control_ceiling IS NULL AND g.delegable_ceiling IS NULL) OR (r.mapped_role_id IS NOT NULL AND r.effective_grant_id=g.id)),'23514');root_role:=r.mapped_role_id;root_version:=r.mapped_role_version;EXIT;END IF;
 hops:=hops+1;PERFORM gc_authority.require(hops<=4 AND g.beneficiary_kind='human' AND NOT g.beneficiary_id=ANY(people),'23514');people:=array_append(people,g.beneficiary_id);PERFORM gc_authority.require(NOT g.issuer_identity_id=ANY(people),'23514');
 SELECT * INTO c FROM gc_authority.connected_parents WHERE tenant_id=t AND child_id=g.id;SELECT * INTO p FROM gc_authority.grant_heads WHERE tenant_id=t AND id=c.parent_id;PERFORM gc_authority.require(p.id IS NOT NULL AND p.kind<>'elevation' AND c.parent_kind=CASE p.kind WHEN 'delegation' THEN 'delegation' ELSE 'grant' END AND p.delegable_ceiling IS NOT NULL,'23514');
 IF p.beneficiary_kind='human' THEN PERFORM gc_authority.require(p.beneficiary_id=g.issuer_identity_id AND c.via_group_membership_id IS NULL,'23514');ELSE SELECT * INTO m FROM gc_authority.group_memberships WHERE tenant_id=t AND id=c.via_group_membership_id AND issuance_version=c.via_group_membership_version;PERFORM gc_authority.require(m.id IS NOT NULL AND m.group_id=p.beneficiary_id AND m.identity_id=g.issuer_identity_id,'23514');END IF;
 PERFORM gc_authority.require(gc_authority.finite_subset(g.effect_ceiling,p.effect_ceiling) AND gc_authority.finite_subset(g.effect_ceiling,p.delegable_ceiling) AND gc_authority.temporal_subset(gc_authority.validity(g.not_before,g.expires_at),gc_authority.validity(p.not_before,p.expires_at)) AND gc_authority.temporal_subset(gc_authority.validity(g.not_before,g.expires_at),p.effect_ceiling->'validity') AND gc_authority.temporal_subset(gc_authority.validity(g.not_before,g.expires_at),p.delegable_ceiling->'validity') AND gc_authority.scope_literal_subset(gc_authority.scope(g),gc_authority.scope(p)) AND gc_authority.scope_literal_subset(gc_authority.scope(g),p.effect_ceiling->'scope') AND gc_authority.scope_literal_subset(gc_authority.scope(g),p.delegable_ceiling->'scope') AND gc_authority.scope_literal_subset(g.effect_ceiling->'scope',p.effect_ceiling->'scope') AND gc_authority.scope_literal_subset(g.effect_ceiling->'scope',p.delegable_ceiling->'scope') AND (p.delegable_ceiling->>'remainingDepth')::int>=hops,'23514');
 IF g.delegable_ceiling IS NOT NULL THEN PERFORM gc_authority.require(gc_authority.finite_subset(g.delegable_ceiling,p.delegable_ceiling) AND (g.delegable_ceiling->>'remainingDepth')::int<(p.delegable_ceiling->>'remainingDepth')::int,'23514');END IF;
 IF g.control_ceiling IS NOT NULL THEN PERFORM gc_authority.require(p.control_ceiling IS NOT NULL AND gc_authority.finite_subset(g.control_ceiling,p.control_ceiling) AND (NOT (g.control_ceiling->>'allowSelfBenefit')::boolean OR (p.control_ceiling->>'allowSelfBenefit')::boolean),'23514');END IF;g:=p;
 END LOOP;
 -- Exact root policy set cannot introduce service actions into a human origin.
 IF root_role IS NOT NULL THEN
 SELECT * INTO selected_registry FROM gc_authority.registries WHERE (id,version,digest)=(g.registry_id,g.registry_version,g.registry_digest);
 PERFORM gc_authority.require(selected_registry.id IS NOT NULL,'23514');
 -- The sole cache entry is derived inside this call from the exact retained DB
 -- tuple AND raw document. No caller-supplied parsed registry or cross-call state.
 IF cached_registry.id IS NULL OR
  (selected_registry.id,selected_registry.version,selected_registry.digest,selected_registry.registry_document)
  IS DISTINCT FROM (cached_registry.id,cached_registry.version,cached_registry.digest,cached_registry.registry_document) THEN
  cached_parsed:=gc_authority.registry(selected_registry.registry_document);cached_registry:=selected_registry;
 END IF;
 reg:=cached_parsed;
 FOR pol IN SELECT p_sql.policy_document FROM gc_authority.role_policy_pins rp_sql JOIN gc_authority.policy_versions p_sql ON (p_sql.tenant_id,p_sql.policy_id,p_sql.version,p_sql.policy_hash)=(rp_sql.tenant_id,rp_sql.policy_id,rp_sql.policy_version,rp_sql.policy_hash) WHERE rp_sql.tenant_id=t AND rp_sql.role_id=root_role AND rp_sql.role_version=root_version LOOP j:=gc_authority.policy(pol.policy_document,reg->'fields');PERFORM gc_authority.require(NOT EXISTS(SELECT 1 FROM jsonb_array_elements(j->'rules') rule CROSS JOIN LATERAL jsonb_array_elements_text(rule->'actions') a WHERE a=ANY(gc_authority.service_actions())),'23514');END LOOP;END IF;
 SELECT * INTO g FROM gc_authority.grant_heads WHERE tenant_id=t AND id=own_id;
 IF NOT read_mode AND g.state='active' AND (g.expires_at IS NULL OR g.expires_at>clock_timestamp()) THEN
 PERFORM gc_authority.require(g.beneficiary_kind<>'group' OR EXISTS(SELECT 1 FROM gc_authority.definition_heads h WHERE h.tenant_id=t AND h.id=g.beneficiary_id AND h.kind='group' AND h.state='active'),'23514');
 IF root_role IS NOT NULL THEN PERFORM gc_authority.require(EXISTS(SELECT 1 FROM gc_authority.definition_heads h WHERE h.tenant_id=t AND h.id=root_role AND h.kind='role' AND h.state='active') AND NOT EXISTS(SELECT 1 FROM gc_authority.role_policy_pins p_sql JOIN gc_authority.definition_heads h ON h.tenant_id=p_sql.tenant_id AND h.id=p_sql.policy_id WHERE p_sql.tenant_id=t AND p_sql.role_id=root_role AND p_sql.role_version=root_version AND h.state<>'active'),'23514');END IF;
 IF r.type_id IS NOT NULL THEN PERFORM gc_authority.require(EXISTS(SELECT 1 FROM gc_authority.definition_heads h WHERE h.tenant_id=t AND h.id=r.type_id AND h.kind='responsibility-type' AND h.state='active'),'23514');END IF;END IF;
 PERFORM gc_authority.require_measure(t,'grant',g.id,1,g.head_version,NULL,CASE g.kind WHEN 'elevation' THEN 'grant-base' ELSE 'dto' END);PERFORM gc_authority.tick();
END;
 END LOOP;
END $$;
 $replace_validate_read_grants_v1$;
 PERFORM gc_authority.require(clock_timestamp()<deadline,'57014');
 PERFORM set_config('gc.tenant_id',coalesce(old_t,''),true);
 PERFORM set_config('gc.actor_id',coalesce(old_a,''),true);
 PERFORM gc_authority.require(clock_timestamp()<deadline,'57014');
EXCEPTION
 WHEN query_canceled THEN
  PERFORM set_config('gc.tenant_id',coalesce(old_t,''),true);PERFORM set_config('gc.actor_id',coalesce(old_a,''),true);
  RAISE EXCEPTION 'AUTHORITY_SCOPE_UPGRADE_DEADLINE' USING ERRCODE='57014';
 WHEN lock_not_available THEN
  PERFORM set_config('gc.tenant_id',coalesce(old_t,''),true);PERFORM set_config('gc.actor_id',coalesce(old_a,''),true);
  RAISE EXCEPTION 'AUTHORITY_SCOPE_UPGRADE_BUSY' USING ERRCODE='55P03';
 WHEN SQLSTATE '54000' THEN
  PERFORM set_config('gc.tenant_id',coalesce(old_t,''),true);PERFORM set_config('gc.actor_id',coalesce(old_a,''),true);
  RAISE EXCEPTION 'AUTHORITY_SCOPE_UPGRADE_PROFILE_LIMIT' USING ERRCODE='54000';
 WHEN insufficient_privilege THEN
  PERFORM set_config('gc.tenant_id',coalesce(old_t,''),true);PERFORM set_config('gc.actor_id',coalesce(old_a,''),true);
  RAISE EXCEPTION 'AUTHORITY_SCOPE_UPGRADE_EXECUTOR_REJECTED' USING ERRCODE='42501';
 WHEN OTHERS THEN
  PERFORM set_config('gc.tenant_id',coalesce(old_t,''),true);PERFORM set_config('gc.actor_id',coalesce(old_a,''),true);
  RAISE EXCEPTION 'AUTHORITY_SCOPE_UPGRADE_INCOMPATIBLE' USING ERRCODE='23514';
END $migration$;
