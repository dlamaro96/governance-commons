-- SPDX-License-Identifier: Apache-2.0
-- Qualification candidate: isolated development database execution authorized;
-- core application requires its separately reviewed gate. SQL001--008 are immutable.
-- Receipt tuple hashes cover actual immutable RelationView/ParticipationBindingView
-- snapshots, not graph projections whose captured endpoint revisions can be newer.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR pg_has_role('gc_app',current_user,'MEMBER') THEN
  RAISE EXCEPTION 'Graph operations require an isolated non-bypass owner' USING ERRCODE='42501';
 END IF;
END $$;

-- Pre009 accepted arbitrary operation names. A legacy success in a newly
-- protected namespace cannot become a trusted replay. Serialize against all
-- writers, then inspect every tenant through forced RLS as the non-bypass owner.
-- Conflict aborts the transactional upgrade; no existing success is modified.
LOCK TABLE public.idempotency IN SHARE ROW EXCLUSIVE MODE;
DO $$ DECLARE tenant_uuid uuid; previous_tenant text:=current_setting('gc.tenant_id',true); BEGIN
 FOR tenant_uuid IN SELECT id FROM public.tenants ORDER BY id LOOP
  PERFORM set_config('gc.tenant_id',tenant_uuid::text,true);
  IF EXISTS(SELECT 1 FROM public.idempotency WHERE tenant_id=tenant_uuid
   AND operation IN ('relation-migration.execute','relation-migration.prepare')) THEN
   RAISE EXCEPTION 'Existing idempotency conflicts with protected relation migration namespaces' USING ERRCODE='23514';
  END IF;
 END LOOP;
 PERFORM set_config('gc.tenant_id',coalesce(previous_tenant,''),true);
END $$;

-- Historical revisions reference stable identity independently from their own
-- exact policy pin. Changing the current pin must never rewrite old snapshots.
ALTER TABLE public.relations ADD CONSTRAINT relation_stable_identity
 UNIQUE(tenant_id,id,relation_type_id,source_asset_id,target_asset_id);
DO $$ DECLARE name text; matches integer; BEGIN
 SELECT count(*),min(c.conname) INTO matches,name FROM pg_constraint c
 WHERE c.conrelid='public.relation_revisions'::regclass AND c.confrelid='public.relations'::regclass AND c.contype='f'
 AND (SELECT array_agg(a.attname::text ORDER BY k.ordinality) FROM unnest(c.conkey) WITH ORDINALITY k(n,ordinality)
  JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.n)
 =ARRAY['tenant_id','relation_id','relation_type_id','relation_type_version','source_asset_id','target_asset_id'];
 IF matches<>1 THEN RAISE EXCEPTION 'Expected exact historical relation foreign key'; END IF;
 EXECUTE format('ALTER TABLE public.relation_revisions DROP CONSTRAINT %I',name);
END $$;
ALTER TABLE public.relation_revisions ADD CONSTRAINT relation_revision_stable_identity
 FOREIGN KEY(tenant_id,relation_id,relation_type_id,source_asset_id,target_asset_id)
 REFERENCES public.relations(tenant_id,id,relation_type_id,source_asset_id,target_asset_id);
ALTER TABLE public.relation_revisions ADD CONSTRAINT relation_revision_exact_policy
 FOREIGN KEY(tenant_id,relation_type_id,relation_type_version)
 REFERENCES public.relation_type_versions(tenant_id,relation_type_id,version);

CREATE TABLE public.relation_graph_operations (
 tenant_id uuid NOT NULL REFERENCES public.tenants(id), id uuid NOT NULL,
 transaction_id xid8 NOT NULL, actor_id uuid NOT NULL, state text NOT NULL CHECK(state IN ('open','sealed','finalized')),
 idempotency_operation text NOT NULL CHECK(idempotency_operation='relation-migration.execute'),
 idempotency_key text NOT NULL, request_body jsonb NOT NULL, normalized_change_set jsonb NOT NULL, request_hash text NOT NULL,
 correlation_id text NOT NULL, created_at timestamptz NOT NULL DEFAULT date_trunc('milliseconds',clock_timestamp()),
 before_graph jsonb NOT NULL DEFAULT '{}', prepared_assets jsonb NOT NULL DEFAULT '{}',
 policies jsonb NOT NULL DEFAULT '[]', targets jsonb NOT NULL DEFAULT '[]', principals uuid[] NOT NULL DEFAULT '{}',
 receipt jsonb, retained_bytes bigint NOT NULL DEFAULT 0, retained_nodes bigint NOT NULL DEFAULT 0,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,transaction_id),
 UNIQUE(tenant_id,actor_id,idempotency_operation,idempotency_key),
 FOREIGN KEY(tenant_id,actor_id) REFERENCES public.memberships(tenant_id,identity_id),
 CHECK(public.gc_relation_json_bounded(request_body,100000,32,524288))
);
CREATE TABLE public.relation_type_preparations (
 tenant_id uuid NOT NULL REFERENCES public.tenants(id), id uuid NOT NULL, type_id uuid NOT NULL,
 logical_key text NOT NULL CHECK(public.gc_relation_safe_id(logical_key)), definition jsonb NOT NULL,
 definition_hash text NOT NULL, created_by uuid NOT NULL,
 created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 transaction_id xid8 NOT NULL, idempotency_key text NOT NULL, request_hash text NOT NULL,
 correlation_id text NOT NULL, consumed_operation_id uuid,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,type_id), UNIQUE(tenant_id,created_by,idempotency_key),
 FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id),
 FOREIGN KEY(tenant_id,consumed_operation_id) REFERENCES public.relation_graph_operations(tenant_id,id),
 CHECK(expires_at=created_at+interval '15 minutes')
);
CREATE TABLE public.relation_participations (
 tenant_id uuid NOT NULL, id uuid NOT NULL, relation_type_id uuid NOT NULL, relation_type_version integer NOT NULL,
 asset_id uuid NOT NULL, asset_version integer NOT NULL, side text NOT NULL CHECK(side IN ('source','target','incident')),
 status text NOT NULL CHECK(status IN ('active','released')), version integer NOT NULL CHECK(version>0),
 created_by uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT date_trunc('milliseconds',now()),
 updated_by uuid NOT NULL, updated_at timestamptz NOT NULL DEFAULT date_trunc('milliseconds',now()),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,id,relation_type_id,asset_id,side),
 FOREIGN KEY(tenant_id,relation_type_id,relation_type_version) REFERENCES public.relation_type_versions(tenant_id,relation_type_id,version),
 FOREIGN KEY(tenant_id,asset_id,asset_version) REFERENCES public.asset_revisions(tenant_id,asset_id,version),
 FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id),
 FOREIGN KEY(tenant_id,updated_by) REFERENCES public.memberships(tenant_id,identity_id)
);
CREATE UNIQUE INDEX relation_participation_active_identity
 ON public.relation_participations(tenant_id,relation_type_id,asset_id,side) WHERE status='active';
CREATE INDEX relation_participation_asset ON public.relation_participations(tenant_id,asset_id,id);
CREATE TABLE public.relation_participation_revisions (
 tenant_id uuid NOT NULL, binding_id uuid NOT NULL, version integer NOT NULL CHECK(version>0), snapshot jsonb NOT NULL,
 operation_id uuid NOT NULL, recorded_by uuid NOT NULL, recorded_at timestamptz NOT NULL,
 relation_type_id uuid GENERATED ALWAYS AS ((snapshot->>'relationTypeId')::uuid) STORED NOT NULL,
 relation_type_version integer GENERATED ALWAYS AS ((snapshot->>'relationTypeVersion')::integer) STORED NOT NULL,
 asset_id uuid GENERATED ALWAYS AS ((snapshot->>'assetId')::uuid) STORED NOT NULL,
 asset_version integer GENERATED ALWAYS AS ((snapshot->>'assetVersion')::integer) STORED NOT NULL,
 side text GENERATED ALWAYS AS (snapshot->>'side') STORED NOT NULL,
 PRIMARY KEY(tenant_id,binding_id,version),
 FOREIGN KEY(tenant_id,binding_id,relation_type_id,asset_id,side) REFERENCES public.relation_participations(tenant_id,id,relation_type_id,asset_id,side),
 FOREIGN KEY(tenant_id,relation_type_id,relation_type_version) REFERENCES public.relation_type_versions(tenant_id,relation_type_id,version),
 FOREIGN KEY(tenant_id,asset_id,asset_version) REFERENCES public.asset_revisions(tenant_id,asset_id,version),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES public.relation_graph_operations(tenant_id,id),
 FOREIGN KEY(tenant_id,recorded_by) REFERENCES public.memberships(tenant_id,identity_id)
);
ALTER TABLE public.relation_participations ADD CONSTRAINT participation_current_revision
 FOREIGN KEY(tenant_id,id,version) REFERENCES public.relation_participation_revisions(tenant_id,binding_id,version)
 DEFERRABLE INITIALLY DEFERRED;

-- These normalized rows are private authorization, never runtime assertions.
CREATE TABLE public.relation_graph_operation_type_claims (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, relation_type_id uuid NOT NULL,
 mode text NOT NULL CHECK(mode IN ('validation','create','publish','repair')),
 before_version integer, after_version integer NOT NULL, before_definition jsonb, after_definition jsonb NOT NULL,
 plan jsonb, head_consumed boolean NOT NULL DEFAULT false, definition_consumed boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,operation_id,relation_type_id),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES public.relation_graph_operations(tenant_id,id)
);
CREATE TABLE public.relation_graph_operation_asset_scope (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, asset_id uuid NOT NULL,
 action text NOT NULL CHECK(action IN ('preserve','assign','transition','type-migrate')),
 projected_endpoint jsonb NOT NULL,
 PRIMARY KEY(tenant_id,operation_id,asset_id),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES public.relation_graph_operations(tenant_id,id),
 FOREIGN KEY(tenant_id,asset_id) REFERENCES public.assets(tenant_id,id)
);
CREATE TABLE public.relation_graph_operation_asset_claims (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, asset_id uuid NOT NULL,
 action text NOT NULL CHECK(action IN ('preserve','assign','transition','type-migrate')),
 before_row jsonb NOT NULL, before_tuple jsonb NOT NULL, after_tuple jsonb NOT NULL,
 from_version integer NOT NULL, to_version integer NOT NULL, consumed boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,operation_id,asset_id),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES public.relation_graph_operations(tenant_id,id),
 FOREIGN KEY(tenant_id,asset_id,from_version) REFERENCES public.asset_revisions(tenant_id,asset_id,version)
);
CREATE TABLE public.relation_graph_operation_model_claims (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, model_id text NOT NULL, type_id uuid NOT NULL,
 migration_id uuid NOT NULL DEFAULT gen_random_uuid(),
 before_version integer NOT NULL, after_version integer NOT NULL, before_resolution jsonb NOT NULL, after_resolution jsonb NOT NULL,
 plan jsonb NOT NULL, head_consumed boolean NOT NULL DEFAULT false, model_consumed boolean NOT NULL DEFAULT false,
 authored_consumed boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,operation_id,model_id), UNIQUE(tenant_id,migration_id),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES public.relation_graph_operations(tenant_id,id),
 FOREIGN KEY(tenant_id,model_id,type_id) REFERENCES public.governance_models(tenant_id,id,type_id)
);
CREATE TABLE public.relation_graph_operation_journal_claims (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, action text NOT NULL, resource_id text NOT NULL, resource_version integer NOT NULL,
 audit_id uuid, outbox_written boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,operation_id,action,resource_id,resource_version), UNIQUE(tenant_id,audit_id),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES public.relation_graph_operations(tenant_id,id),
 FOREIGN KEY(tenant_id,audit_id) REFERENCES public.audit(tenant_id,id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE public.relation_graph_operation_edge_claims (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, relation_id uuid NOT NULL, relation_type_id uuid NOT NULL,
 key jsonb NOT NULL, action text NOT NULL CHECK(action IN ('preserve','create','repair','repin','tombstone')),
 role text NOT NULL CHECK(role IN ('changed','validation-only')), before_row jsonb, before_tuple jsonb, after_tuple jsonb NOT NULL,
 from_version integer, to_version integer NOT NULL, consumed boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,operation_id,relation_id),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES public.relation_graph_operations(tenant_id,id)
);
CREATE TABLE public.relation_graph_operation_binding_claims (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, binding_id uuid NOT NULL, relation_type_id uuid NOT NULL,
 key jsonb NOT NULL, action text NOT NULL CHECK(action IN ('preserve','enroll','repin','release')),
 role text NOT NULL CHECK(role IN ('changed','validation-only')), before_row jsonb, before_tuple jsonb, after_tuple jsonb NOT NULL,
 from_version integer, to_version integer NOT NULL, consumed boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,operation_id,binding_id),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES public.relation_graph_operations(tenant_id,id)
);
CREATE TABLE public.relation_graph_receipts (
 tenant_id uuid NOT NULL, id uuid NOT NULL, receipt jsonb NOT NULL,
 repairs_receipt_id uuid GENERATED ALWAYS AS ((receipt->>'repairsReceiptId')::uuid) STORED,
 executed_by uuid NOT NULL, executed_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,id) REFERENCES public.relation_graph_operations(tenant_id,id),
 FOREIGN KEY(tenant_id,repairs_receipt_id) REFERENCES public.relation_graph_receipts(tenant_id,id),
 FOREIGN KEY(tenant_id,executed_by) REFERENCES public.memberships(tenant_id,identity_id),
 CHECK(public.gc_relation_json_bounded(receipt,100000,32,524288))
);
CREATE TABLE public.relation_graph_receipt_edges (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, relation_id uuid NOT NULL,
 key jsonb NOT NULL, role text NOT NULL, action text NOT NULL,
 before_version integer, after_version integer NOT NULL,
 before_tuple_hash text, after_tuple_hash text NOT NULL,
 PRIMARY KEY(tenant_id,operation_id,relation_id),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES public.relation_graph_receipts(tenant_id,id),
 FOREIGN KEY(tenant_id,relation_id,before_version) REFERENCES public.relation_revisions(tenant_id,relation_id,version),
 FOREIGN KEY(tenant_id,relation_id,after_version) REFERENCES public.relation_revisions(tenant_id,relation_id,version)
);
CREATE TABLE public.relation_graph_receipt_bindings (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, binding_id uuid NOT NULL,
 key jsonb NOT NULL, role text NOT NULL, action text NOT NULL,
 before_version integer, after_version integer NOT NULL,
 before_tuple_hash text, after_tuple_hash text NOT NULL,
 PRIMARY KEY(tenant_id,operation_id,binding_id),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES public.relation_graph_receipts(tenant_id,id),
 FOREIGN KEY(tenant_id,binding_id,before_version) REFERENCES public.relation_participation_revisions(tenant_id,binding_id,version),
 FOREIGN KEY(tenant_id,binding_id,after_version) REFERENCES public.relation_participation_revisions(tenant_id,binding_id,version)
);
CREATE TABLE public.relation_graph_receipt_assets (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, asset_id uuid NOT NULL, role text NOT NULL,
 before_version integer NOT NULL, after_version integer NOT NULL,
 PRIMARY KEY(tenant_id,operation_id,asset_id),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES public.relation_graph_receipts(tenant_id,id),
 FOREIGN KEY(tenant_id,asset_id,before_version) REFERENCES public.asset_revisions(tenant_id,asset_id,version),
 FOREIGN KEY(tenant_id,asset_id,after_version) REFERENCES public.asset_revisions(tenant_id,asset_id,version)
);
CREATE TABLE public.relation_graph_receipt_types (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, relation_type_id uuid NOT NULL,
 before_version integer, after_version integer NOT NULL, definition_hash text NOT NULL, resolution_hash text NOT NULL,
 PRIMARY KEY(tenant_id,operation_id,relation_type_id),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES public.relation_graph_receipts(tenant_id,id),
 FOREIGN KEY(tenant_id,relation_type_id,before_version) REFERENCES public.relation_type_versions(tenant_id,relation_type_id,version),
 FOREIGN KEY(tenant_id,relation_type_id,after_version) REFERENCES public.relation_type_versions(tenant_id,relation_type_id,version)
);
CREATE TABLE public.relation_graph_receipt_type_migrations (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, migration_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,operation_id,migration_id), UNIQUE(tenant_id,migration_id),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES public.relation_graph_receipts(tenant_id,id),
 FOREIGN KEY(tenant_id,migration_id) REFERENCES public.asset_type_migrations(tenant_id,id)
);
CREATE TABLE public.relation_graph_replacements (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, predecessor_id uuid NOT NULL, successor_id uuid NOT NULL,
 relation_type_id uuid NOT NULL, creation_key text NOT NULL,
 PRIMARY KEY(tenant_id,operation_id,predecessor_id), UNIQUE(tenant_id,operation_id,successor_id),
 UNIQUE(tenant_id,operation_id,relation_type_id,creation_key),
 FOREIGN KEY(tenant_id,operation_id,predecessor_id) REFERENCES public.relation_graph_receipt_edges(tenant_id,operation_id,relation_id),
 FOREIGN KEY(tenant_id,operation_id,successor_id) REFERENCES public.relation_graph_receipt_edges(tenant_id,operation_id,relation_id),
 FOREIGN KEY(tenant_id,relation_type_id) REFERENCES public.relation_types(tenant_id,type_id)
);
DO $$ DECLARE name text; BEGIN
 FOREACH name IN ARRAY ARRAY['relation_graph_operations','relation_type_preparations','relation_participations','relation_participation_revisions',
  'relation_graph_operation_journal_claims','relation_graph_operation_type_claims','relation_graph_operation_asset_scope','relation_graph_operation_asset_claims','relation_graph_operation_model_claims','relation_graph_operation_edge_claims','relation_graph_operation_binding_claims',
  'relation_graph_receipts','relation_graph_receipt_edges','relation_graph_receipt_bindings','relation_graph_receipt_assets','relation_graph_receipt_types',
  'relation_graph_receipt_type_migrations','relation_graph_replacements'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.gc_tenant()) WITH CHECK(tenant_id=public.gc_tenant())',name);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC,gc_app',name);
 END LOOP;
 FOREACH name IN ARRAY ARRAY['relation_type_preparations','relation_participations','relation_participation_revisions','relation_graph_receipts',
  'relation_graph_receipt_edges','relation_graph_receipt_bindings','relation_graph_receipt_assets','relation_graph_receipt_types',
  'relation_graph_receipt_type_migrations','relation_graph_replacements'] LOOP
  EXECUTE format('GRANT SELECT ON public.%I TO gc_app',name);
 END LOOP;
 FOREACH name IN ARRAY ARRAY['relation_participation_revisions','relation_graph_receipts','relation_graph_receipt_edges','relation_graph_receipt_bindings',
  'relation_graph_receipt_assets','relation_graph_receipt_types','relation_graph_receipt_type_migrations','relation_graph_replacements'] LOOP
  EXECUTE format('CREATE TRIGGER immutable_history BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.gc_immutable_audit()',name);
 END LOOP;
END $$;
-- Runtime preparation reads are creator scoped as well as tenant scoped. The
-- forced-RLS owner follows this same boundary when consuming a reservation.
ALTER POLICY tenant_isolation ON public.relation_type_preparations
 USING(tenant_id=public.gc_tenant() AND created_by::text=public.gc_actor())
 WITH CHECK(tenant_id=public.gc_tenant() AND created_by::text=public.gc_actor());
GRANT INSERT,UPDATE ON public.relation_participations TO gc_app;
GRANT INSERT ON public.relation_participation_revisions TO gc_app;
CREATE TRIGGER participation_no_delete BEFORE DELETE ON public.relation_participations FOR EACH ROW EXECUTE FUNCTION public.gc_immutable_audit();

CREATE FUNCTION public.gc_relation_structural_policy(definition jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('direction',definition->'direction','sourceTypes',definition->'sourceTypes','targetTypes',definition->'targetTypes',
  'sourceStates',definition->'sourceStates','targetStates',definition->'targetStates','cardinality',definition->'cardinality',
  'allowSelf',definition->'allowSelf','cycles',definition->'cycles')
$$;
CREATE FUNCTION public.gc_relation_model(definition jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('formatVersion',1,'id',definition->'id','version',definition->'version','attributes',definition->'attributes')
$$;
CREATE FUNCTION public.gc_relation_asset_tuple(row_value public.assets) RETURNS jsonb
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('modelId',row_value.model_id,'modelVersion',row_value.model_version,'attributes',row_value.attributes,
  'ownerId',row_value.owner_id,'state',row_value.type_state)
$$;
CREATE FUNCTION public.gc_relation_graph_asset_row(row_value public.assets) RETURNS jsonb
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('id',row_value.id,'name',row_value.name,'version',row_value.version,
  'visibility',row_value.visibility,'allowed_identities',row_value.allowed_identities,
  'model_id',row_value.model_id,'model_version',row_value.model_version,'owner_id',row_value.owner_id,
  'type_state',row_value.type_state,'updated_at',public.gc_relation_utc(row_value.updated_at))
$$;
CREATE FUNCTION public.gc_relation_values(row_value public.relations) RETURNS jsonb
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('attributes',row_value.attributes,'ownerId',row_value.owner_id,'state',row_value.state,
  'validFrom',public.gc_relation_utc(row_value.valid_from),'validTo',public.gc_relation_utc(row_value.valid_to),
  'visibility',row_value.visibility,'allowedIdentityIds',row_value.allowed_identities)
$$;
CREATE FUNCTION public.gc_relation_binding_snapshot(row_value public.relation_participations) RETURNS jsonb
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('id',row_value.id,'version',row_value.version,'relationTypeId',row_value.relation_type_id,
  'relationTypeVersion',row_value.relation_type_version,'assetId',row_value.asset_id,'assetVersion',row_value.asset_version,
  'side',row_value.side,'status',row_value.status,'createdBy',row_value.created_by,'createdAt',public.gc_relation_utc(row_value.created_at),
  'updatedBy',row_value.updated_by,'updatedAt',public.gc_relation_utc(row_value.updated_at))
$$;

CREATE OR REPLACE FUNCTION public.gc_relation_definition_valid(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE side text; limits jsonb; step jsonb; states jsonb;
BEGIN
 IF NOT public.gc_relation_keys(value,ARRAY['formatVersion','id','version','label','inverseLabel','direction','sourceTypes','targetTypes','sourceStates','targetStates','cardinality','allowSelf','cycles','attributes','requiredOwner','lifecycle'])
 OR value->'formatVersion' NOT IN ('1'::jsonb,'2'::jsonb) OR jsonb_typeof(value->'id')<>'string' OR NOT public.gc_relation_safe_id(value->>'id')
 OR jsonb_typeof(value->'version')<>'number' OR value->>'version' !~ '^[1-9][0-9]{0,9}$' OR (value->>'version')::numeric>2147483647
 OR jsonb_typeof(value->'label')<>'string' OR public.gc_relation_utf16_length(value->>'label') NOT BETWEEN 1 AND 120
 OR jsonb_typeof(value->'inverseLabel')<>'string' OR public.gc_relation_utf16_length(value->>'inverseLabel') NOT BETWEEN 1 AND 120
 OR jsonb_typeof(value->'direction')<>'string' OR value->>'direction' NOT IN ('directed','undirected')
 OR jsonb_typeof(value->'cycles')<>'string' OR value->>'cycles' NOT IN ('allow','acyclic')
 OR jsonb_typeof(value->'allowSelf')<>'boolean' OR jsonb_typeof(value->'requiredOwner')<>'boolean'
 OR (value->>'cycles'='acyclic' AND value->>'allowSelf'='true')
 OR NOT public.gc_relation_endpoint_rules(value->'sourceTypes') OR NOT public.gc_relation_endpoint_rules(value->'targetTypes')
 OR NOT public.gc_relation_state_list(value->'sourceStates',true) OR NOT public.gc_relation_state_list(value->'targetStates',true)
 OR NOT public.gc_relation_keys(value->'cardinality',ARRAY['outgoing','incoming']) THEN RETURN false; END IF;
 FOREACH side IN ARRAY ARRAY['outgoing','incoming'] LOOP
  limits:=value->'cardinality'->side;
  IF NOT public.gc_relation_keys(limits,ARRAY['min','max']) OR jsonb_typeof(limits->'min')<>'number'
   OR limits->>'min' !~ '^(0|[1-9][0-9]{0,3})$' OR (limits->>'min')::integer>1000
   OR (value->>'formatVersion'='1' AND limits->'min'<>'0'::jsonb)
   OR (limits->'max'<>'null'::jsonb AND (jsonb_typeof(limits->'max')<>'number'
    OR limits->>'max' !~ '^(0|[1-9][0-9]{0,3})$' OR (limits->>'max')::integer>1000
    OR (limits->>'max')::integer<(limits->>'min')::integer
    OR (value->>'formatVersion'='1' AND limits->'max'='0'::jsonb))) THEN RETURN false; END IF;
 END LOOP;
 IF value->>'direction'='undirected' AND (value->'sourceTypes'<>value->'targetTypes' OR value->'sourceStates'<>value->'targetStates'
  OR value->'cardinality'->'outgoing'<>value->'cardinality'->'incoming') THEN RETURN false; END IF;
 IF NOT public.gc_relation_schema_valid(jsonb_build_object('type','object','properties',value->'attributes'))
  OR NOT public.gc_relation_keys(value->'lifecycle',ARRAY['initial','states','transitions']) THEN RETURN false; END IF;
 states:=value->'lifecycle'->'states';
 IF jsonb_typeof(states)<>'array' OR jsonb_array_length(states) NOT BETWEEN 1 AND 32
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(states) v WHERE jsonb_typeof(v)<>'string' OR NOT public.gc_relation_safe_id(v#>>'{}'))
  OR (SELECT count(*)<>count(DISTINCT v) FROM jsonb_array_elements(states) v)
  OR NOT states @> jsonb_build_array(value->'lifecycle'->'initial')
  OR jsonb_typeof(value->'lifecycle'->'transitions')<>'array' OR jsonb_array_length(value->'lifecycle'->'transitions')>256
  OR (SELECT count(*)<>count(DISTINCT v) FROM jsonb_array_elements(value->'lifecycle'->'transitions') v) THEN RETURN false; END IF;
 FOR step IN SELECT v FROM jsonb_array_elements(value->'lifecycle'->'transitions') t(v) LOOP
  IF NOT public.gc_relation_keys(step,ARRAY['from','to']) OR step->'from'=step->'to'
   OR NOT states @> jsonb_build_array(step->'from') OR NOT states @> jsonb_build_array(step->'to') THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END $$;

CREATE FUNCTION public.gc_relation_positive_integer(value jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT coalesce(jsonb_typeof(value)='number' AND value::text ~ '^[1-9][0-9]{0,9}$' AND value::text::numeric<=2147483647,false)
$$;
CREATE FUNCTION public.gc_relation_sorted_pins(value jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT coalesce(jsonb_agg(v ORDER BY v->>'id',(v->>'version')::integer),'[]') FROM jsonb_array_elements(value) e(v)
$$;
CREATE FUNCTION public.gc_relation_lifecycle_valid(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE states jsonb; item jsonb;
BEGIN
 IF public.gc_relation_keys(value,ARRAY['initial','states','transitions']) IS NOT TRUE
  OR jsonb_typeof(value->'initial') IS DISTINCT FROM 'string' THEN RETURN false; END IF;
 states:=value->'states';
 IF jsonb_typeof(states) IS DISTINCT FROM 'array' OR jsonb_array_length(states) NOT BETWEEN 1 AND 32
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(states) e(v) WHERE jsonb_typeof(v)<>'string' OR public.gc_relation_safe_id(v#>>'{}') IS NOT TRUE)
  OR (SELECT count(*)<>count(DISTINCT v) FROM jsonb_array_elements(states) e(v))
  OR NOT states @> jsonb_build_array(value->'initial') OR jsonb_typeof(value->'transitions') IS DISTINCT FROM 'array'
  OR jsonb_array_length(value->'transitions')>256 OR (SELECT count(*)<>count(DISTINCT v) FROM jsonb_array_elements(value->'transitions') e(v)) THEN RETURN false; END IF;
 FOR item IN SELECT v FROM jsonb_array_elements(value->'transitions') e(v) LOOP
  IF public.gc_relation_keys(item,ARRAY['from','to']) IS NOT TRUE OR item->'from'=item->'to'
   OR NOT states @> jsonb_build_array(item->'from') OR NOT states @> jsonb_build_array(item->'to') THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
END $$;

CREATE FUNCTION public.gc_relation_path(value jsonb) RETURNS text[]
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE result text[];
BEGIN
 IF jsonb_typeof(value) IS DISTINCT FROM 'array' OR jsonb_array_length(value) NOT BETWEEN 1 AND 8
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(value) e(v) WHERE jsonb_typeof(v)<>'string' OR NOT public.gc_relation_safe_id(v#>>'{}')) THEN
  RAISE EXCEPTION 'Invalid migration path' USING ERRCODE='23514'; END IF;
 SELECT array_agg(v ORDER BY n) INTO result FROM jsonb_array_elements_text(value) WITH ORDINALITY e(v,n);
 RETURN result;
END $$;
CREATE FUNCTION public.gc_relation_schema_at(model jsonb,path text[]) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE selected_schema jsonb:=jsonb_build_object('type','object','properties',model->'attributes'); part text;
BEGIN
 FOREACH part IN ARRAY path LOOP
  IF selected_schema->>'type' IS DISTINCT FROM 'object' THEN RETURN NULL; END IF;
  selected_schema:=selected_schema->'properties'->part;
 END LOOP;
 RETURN selected_schema;
END $$;
CREATE FUNCTION public.gc_relation_schema_changes(before_schema jsonb,after_schema jsonb,path text DEFAULT '/attributes',depth integer DEFAULT 0) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE result jsonb:='[]'; k text; required boolean;
BEGIN
 IF depth>16 THEN RAISE EXCEPTION 'RELATION_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 IF before_schema IS NULL THEN RETURN jsonb_build_array(jsonb_build_object('code','attribute_added','path',path,'requiresMigration',false)); END IF;
 IF after_schema IS NULL THEN RETURN jsonb_build_array(jsonb_build_object('code','attribute_removed','path',path,'requiresMigration',true)); END IF;
 IF before_schema->'type' IS DISTINCT FROM after_schema->'type' THEN
  RETURN jsonb_build_array(jsonb_build_object('code','type_changed','path',path,'requiresMigration',true)); END IF;
 IF before_schema->'label' IS DISTINCT FROM after_schema->'label' THEN
  result:=result||jsonb_build_array(jsonb_build_object('code','metadata_changed','path',path||'/label','requiresMigration',false)); END IF;
 IF (before_schema-ARRAY['type','label','properties','items']) IS DISTINCT FROM (after_schema-ARRAY['type','label','properties','items']) THEN
  required:=(before_schema->>'type'='enum' AND NOT ((after_schema->'values') @> (before_schema->'values')))
   OR (before_schema->>'type'='uri' AND NOT (coalesce(after_schema->'schemes','["https","http","urn","mailto","s3","gs","abfs","abfss"]'::jsonb) @> coalesce(before_schema->'schemes','["https","http","urn","mailto","s3","gs","abfs","abfss"]'::jsonb)));
  result:=result||jsonb_build_array(jsonb_build_object('code','constraints_changed','path',path,'requiresMigration',coalesce(required,false)));
 END IF;
 IF before_schema->>'type'='object' THEN
  FOR k IN SELECT key FROM jsonb_object_keys(coalesce(before_schema->'properties','{}')||coalesce(after_schema->'properties','{}')) e(key) ORDER BY key COLLATE "C" LOOP
   result:=result||public.gc_relation_schema_changes(before_schema->'properties'->k,after_schema->'properties'->k,
    path||CASE WHEN depth=0 THEN '/' ELSE '/properties/' END||k,depth+1);
  END LOOP;
 ELSIF before_schema->>'type'='list' THEN
  result:=result||public.gc_relation_schema_changes(before_schema->'items',after_schema->'items',path||'/items',depth+1);
 END IF;
 RETURN result;
END $$;
CREATE FUNCTION public.gc_relation_attribute_transform(head jsonb,source jsonb,target jsonb,plan jsonb,attributes jsonb,validate_only boolean DEFAULT false) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE result jsonb:=attributes; op jsonb; source_path text[]; destination_path text[]; schema jsonb;
 existing jsonb; destination_parent jsonb; prefix jsonb; i integer; mapping jsonb; acknowledgements jsonb; expected jsonb;
BEGIN
 IF NOT public.gc_relation_keys(plan,ARRAY['formatVersion','modelId','targetVersion','sourceVersions','acknowledgedChanges','operations'])
  OR plan->'formatVersion'<>'1' OR plan->'modelId' IS DISTINCT FROM head->'id' OR plan->'modelId' IS DISTINCT FROM target->'id'
  OR plan->'targetVersion' IS DISTINCT FROM target->'version' OR (target->>'version')::bigint<>(head->>'version')::bigint+1
  OR source->'id' IS DISTINCT FROM head->'id' OR (source->>'version')::integer>(head->>'version')::integer
  OR jsonb_typeof(plan->'sourceVersions') IS DISTINCT FROM 'array' OR (NOT validate_only AND NOT plan->'sourceVersions' @> jsonb_build_array(source->'version'))
  OR jsonb_typeof(plan->'operations') IS DISTINCT FROM 'array' OR jsonb_array_length(plan->'operations')>64
  OR jsonb_typeof(plan->'acknowledgedChanges') IS DISTINCT FROM 'array'
  OR (NOT validate_only AND NOT public.gc_relation_value_valid(jsonb_build_object('type','object','properties',source->'attributes'),attributes)) THEN
  RAISE EXCEPTION 'Invalid migration identity, source or scope' USING ERRCODE='23514'; END IF;
 SELECT coalesce(jsonb_agg(v-ARRAY['requiresMigration'] ORDER BY v->>'path',v->>'code'),'[]') INTO expected
  FROM jsonb_array_elements(public.gc_relation_schema_changes(jsonb_build_object('type','object','properties',head->'attributes'),jsonb_build_object('type','object','properties',target->'attributes'))) e(v)
  WHERE v->>'requiresMigration'='true';
 SELECT coalesce(jsonb_agg(v ORDER BY v->>'path',v->>'code'),'[]') INTO acknowledgements FROM jsonb_array_elements(plan->'acknowledgedChanges') e(v);
 IF acknowledgements IS DISTINCT FROM expected THEN RAISE EXCEPTION 'Exact destructive acknowledgements are required' USING ERRCODE='23514'; END IF;
 FOR op IN SELECT v FROM jsonb_array_elements(plan->'operations') e(v) LOOP
  IF jsonb_typeof(op->'op') IS DISTINCT FROM 'string' OR op->>'op' NOT IN ('rename','remove','set','enumMap','convert') OR NOT public.gc_relation_keys(op,
   CASE op->>'op' WHEN 'rename' THEN ARRAY['op','from','to','onMissing'] WHEN 'remove' THEN ARRAY['op','path','onMissing']
    WHEN 'set' THEN ARRAY['op','path','value','mode'] WHEN 'enumMap' THEN ARRAY['op','path','mappings','onMissing','onUnmapped']
    ELSE ARRAY['op','path','conversion','onMissing'] END) THEN RAISE EXCEPTION 'Invalid migration operation' USING ERRCODE='23514'; END IF;
  source_path:=public.gc_relation_path(CASE WHEN op->>'op'='rename' THEN op->'from' ELSE op->'path' END);
  destination_path:=CASE WHEN op->>'op'='rename' THEN public.gc_relation_path(op->'to') ELSE source_path END;
  schema:=public.gc_relation_schema_at(target,destination_path);
  IF (op->>'op'='set' AND schema IS NULL) OR (NOT validate_only AND op->>'op'<>'set' AND public.gc_relation_schema_at(source,source_path) IS NULL
    AND public.gc_relation_schema_at(head,source_path) IS NULL AND public.gc_relation_schema_at(target,source_path) IS NULL)
   OR (op->>'op'<>'remove' AND schema IS NULL) THEN RAISE EXCEPTION 'Migration path must name a declared field' USING ERRCODE='23514'; END IF;
  IF op->>'op'='rename' AND (source_path[1:least(cardinality(source_path),cardinality(destination_path))]=destination_path[1:least(cardinality(source_path),cardinality(destination_path))]) THEN
   RAISE EXCEPTION 'Overlapping rename paths are forbidden' USING ERRCODE='23514'; END IF;
  IF op->>'op'='set' AND (jsonb_typeof(op->'mode') IS DISTINCT FROM 'string' OR op->>'mode' NOT IN ('replace','ifMissing') OR NOT public.gc_relation_value_valid(schema,op->'value')) THEN
   RAISE EXCEPTION 'Invalid literal migration value' USING ERRCODE='23514'; END IF;
  IF op->>'op'<>'set' AND (jsonb_typeof(op->'onMissing') IS DISTINCT FROM 'string' OR op->>'onMissing' NOT IN ('skip','error')) THEN RAISE EXCEPTION 'Invalid missing-path policy' USING ERRCODE='23514'; END IF;
  IF op->>'op'='convert' AND (jsonb_typeof(op->'conversion') IS DISTINCT FROM 'string' OR op->>'conversion' NOT IN ('safeIntegerToDecimal','decimalToText','textToDecimal')
   OR schema->>'type'<>CASE WHEN op->>'conversion'='decimalToText' THEN 'text' ELSE 'decimal' END) THEN
   RAISE EXCEPTION 'Invalid conversion target' USING ERRCODE='23514'; END IF;
  IF op->>'op'='enumMap' THEN
   IF schema->>'type'<>'enum' OR jsonb_typeof(op->'onUnmapped') IS DISTINCT FROM 'string' OR op->>'onUnmapped' NOT IN ('keep','error') OR jsonb_typeof(op->'mappings') IS DISTINCT FROM 'array'
    OR jsonb_array_length(op->'mappings') NOT BETWEEN 1 AND 256
    OR (SELECT count(*)<>count(DISTINCT v->>'from') FROM jsonb_array_elements(op->'mappings') e(v)) THEN
    RAISE EXCEPTION 'Invalid enumeration mapping' USING ERRCODE='23514'; END IF;
   FOR mapping IN SELECT v FROM jsonb_array_elements(op->'mappings') e(v) LOOP
    IF NOT public.gc_relation_keys(mapping,ARRAY['from','to']) OR jsonb_typeof(mapping->'from')<>'string'
     OR jsonb_typeof(mapping->'to')<>'string' OR NOT schema->'values' @> jsonb_build_array(mapping->'to') THEN
     RAISE EXCEPTION 'Invalid enumeration destination' USING ERRCODE='23514'; END IF;
   END LOOP;
  END IF;
  IF validate_only THEN CONTINUE; END IF;
  -- Inspect each ancestor; #> alone confuses a missing parent and a scalar.
  prefix:=result;
  FOR i IN 1..cardinality(source_path)-1 LOOP
   IF jsonb_typeof(prefix)<>'object' THEN RAISE EXCEPTION 'Path cannot traverse a scalar or array' USING ERRCODE='23514'; END IF;
   prefix:=prefix->source_path[i]; IF prefix IS NULL THEN EXIT; END IF;
  END LOOP;
  IF prefix IS NOT NULL AND jsonb_typeof(prefix)<>'object' THEN RAISE EXCEPTION 'Path cannot traverse a scalar or array' USING ERRCODE='23514'; END IF;
  existing:=result#>source_path;
  IF op->>'op'<>'set' AND existing IS NULL THEN
   IF op->>'onMissing'='skip' THEN CONTINUE; END IF;
   RAISE EXCEPTION 'Migration source value is missing' USING ERRCODE='23514';
  END IF;
  destination_parent:=CASE WHEN cardinality(destination_path)=1 THEN result ELSE result#>destination_path[1:cardinality(destination_path)-1] END;
  IF op->>'op' IN ('set','rename') AND jsonb_typeof(destination_parent) IS DISTINCT FROM 'object' THEN
   RAISE EXCEPTION 'Destination parent must already exist' USING ERRCODE='23514'; END IF;
  CASE op->>'op'
   WHEN 'remove' THEN result:=result#-source_path;
   WHEN 'set' THEN IF existing IS NULL OR op->>'mode'='replace' THEN result:=jsonb_set(result,destination_path,op->'value',true); END IF;
   WHEN 'rename' THEN
    IF result#>destination_path IS NOT NULL THEN RAISE EXCEPTION 'Rename cannot overwrite a value' USING ERRCODE='23514'; END IF;
    result:=jsonb_set(result,destination_path,existing,true)#-source_path;
   WHEN 'enumMap' THEN
    IF jsonb_typeof(existing)<>'string' THEN RAISE EXCEPTION 'Enum mapping requires string input' USING ERRCODE='23514'; END IF;
    SELECT v->'to' INTO mapping FROM jsonb_array_elements(op->'mappings') e(v) WHERE v->'from'=existing;
    IF mapping IS NOT NULL THEN result:=jsonb_set(result,source_path,mapping,false);
    ELSIF op->>'onUnmapped'='error' THEN RAISE EXCEPTION 'Unmapped enumeration value' USING ERRCODE='23514'; END IF;
   WHEN 'convert' THEN
    IF op->>'conversion'='safeIntegerToDecimal' THEN
     IF jsonb_typeof(existing)<>'number' OR (existing::text)::numeric<>trunc((existing::text)::numeric)
      OR abs((existing::text)::numeric)>9007199254740991 THEN RAISE EXCEPTION 'Unsafe integer conversion' USING ERRCODE='23514'; END IF;
     result:=jsonb_set(result,source_path,to_jsonb(trunc((existing::text)::numeric)::text),false);
    ELSIF jsonb_typeof(existing)<>'string' OR NOT public.gc_relation_decimal(existing#>>'{}') THEN
     RAISE EXCEPTION 'Conversion requires an exact canonical decimal string' USING ERRCODE='23514'; END IF;
  END CASE;
 END LOOP;
 IF NOT validate_only AND NOT public.gc_relation_value_valid(jsonb_build_object('type','object','properties',target->'attributes'),result) THEN
  RAISE EXCEPTION 'Transformed values violate target attributes' USING ERRCODE='23514'; END IF;
 RETURN result;
END $$;

CREATE FUNCTION public.gc_relation_graph_current() RETURNS public.relation_graph_operations
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT o FROM public.relation_graph_operations o WHERE tenant_id=public.gc_tenant() AND transaction_id=pg_current_xact_id()
$$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_current() FROM PUBLIC,gc_app;

-- One aggregate ledger charges retained projections rather than granting each
-- nested target a fresh allowance. Physical expansion is checked before canonical
-- serialization; the recursive walk is bounded before materialization as well.
CREATE FUNCTION public.gc_relation_graph_charge(selected_operation uuid,value jsonb) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE bytes bigint; nodes bigint; total_bytes bigint; total_nodes bigint;
BEGIN
 IF value IS NULL THEN RETURN; END IF;
 IF EXISTS(SELECT 1 FROM public.relation_graph_operations o WHERE o.tenant_id=public.gc_tenant() AND o.id=selected_operation
   AND clock_timestamp()>=o.created_at+interval '30 seconds') THEN RAISE EXCEPTION 'Graph operation deadline exceeded' USING ERRCODE='57014'; END IF;
 IF NOT public.gc_relation_json_bounded(value,100000,32,524288) THEN
  RAISE EXCEPTION 'RELATION_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 bytes:=octet_length(public.gc_type_migration_canonical(value));
 WITH RECURSIVE walk(item) AS (SELECT value UNION ALL SELECT child.item FROM walk p CROSS JOIN LATERAL (
  SELECT v AS item FROM jsonb_each(CASE WHEN jsonb_typeof(p.item)='object' THEN p.item ELSE '{}' END) e(k,v)
  UNION ALL SELECT v FROM jsonb_array_elements(CASE WHEN jsonb_typeof(p.item)='array' THEN p.item ELSE '[]' END) e(v)) child)
 SELECT count(*) INTO nodes FROM walk;
 UPDATE public.relation_graph_operations o SET retained_bytes=o.retained_bytes+bytes,retained_nodes=o.retained_nodes+nodes
  WHERE o.tenant_id=public.gc_tenant() AND o.id=selected_operation AND o.transaction_id=pg_current_xact_id() AND o.state='open'
  RETURNING retained_bytes,retained_nodes INTO total_bytes,total_nodes;
 IF total_bytes IS NULL THEN RAISE EXCEPTION 'Only an open protected operation may retain evidence' USING ERRCODE='42501'; END IF;
 IF total_bytes>524288 OR total_nodes>100000 THEN RAISE EXCEPTION 'RELATION_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_charge(uuid,jsonb) FROM PUBLIC,gc_app;

CREATE FUNCTION public.gc_relation_graph_journal(action_name text,resource text,resource_version integer,actor uuid,correlation text) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
 SELECT EXISTS(SELECT 1 FROM public.audit a JOIN public.outbox o ON o.tenant_id=a.tenant_id AND o.id=a.id
  WHERE a.tenant_id=public.gc_tenant() AND a.action=action_name AND a.resource_id=resource AND a.actor_id=actor::text
   AND a.correlation_id=correlation AND a.changes->>'resourceVersion'=resource_version::text
   AND a.envelope->>'version'=resource_version::text AND a.envelope->>'actorId'=actor::text
   AND o.event_type=a.action AND o.resource_id=a.resource_id AND o.resource_version=resource_version
   AND o.payload->>'correlationId'=correlation AND o.payload->>'actorId'=actor::text)
$$;

CREATE FUNCTION public.gc_relation_graph_budget(started_at timestamptz) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE remaining_ms bigint; configured_ms bigint;
BEGIN
 remaining_ms:=floor(extract(epoch FROM started_at+interval '30 seconds'-clock_timestamp())*1000)::bigint;
 IF remaining_ms<=0 THEN RAISE EXCEPTION 'Graph operation deadline exceeded' USING ERRCODE='57014'; END IF;
 SELECT setting::bigint INTO configured_ms FROM pg_settings WHERE name='lock_timeout';
 PERFORM set_config('lock_timeout',least(remaining_ms,coalesce(nullif(configured_ms,0),remaining_ms))::text||'ms',true);
 SELECT setting::bigint INTO configured_ms FROM pg_settings WHERE name='statement_timeout';
 PERFORM set_config('statement_timeout',least(remaining_ms,coalesce(nullif(configured_ms,0),remaining_ms))::text||'ms',true);
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_budget(timestamptz) FROM PUBLIC,gc_app;

CREATE FUNCTION public.gc_relation_graph_journal_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
<<journal_context>>
DECLARE op public.relation_graph_operations; claim public.relation_graph_operation_journal_claims;
 action_name text; resource text; resource_version integer;
BEGIN
 op:=public.gc_relation_graph_current(); IF op.id IS NULL THEN IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF; END IF;
 IF TG_OP<>'INSERT' OR op.state<>'open' OR NEW.tenant_id IS DISTINCT FROM op.tenant_id OR op.actor_id::text IS DISTINCT FROM public.gc_actor() THEN
  RAISE EXCEPTION 'Graph journal writes require the actual open operation' USING ERRCODE='23514'; END IF;
 IF TG_RELID='public.audit'::regclass THEN
  action_name:=NEW.action;resource:=NEW.resource_id;
  IF NOT public.gc_relation_positive_integer(NEW.changes->'resourceVersion') OR NEW.actor_id<>op.actor_id::text OR NEW.correlation_id<>op.correlation_id
   OR NEW.envelope->>'actorId' IS DISTINCT FROM op.actor_id::text OR NEW.envelope->>'correlationId' IS DISTINCT FROM op.correlation_id
   OR NEW.envelope->>'action' IS DISTINCT FROM NEW.action OR NEW.envelope->>'resourceId' IS DISTINCT FROM NEW.resource_id
   OR NEW.envelope->'version' IS DISTINCT FROM NEW.changes->'resourceVersion' OR NEW.envelope->>'id' IS DISTINCT FROM NEW.id::text
   OR NEW.envelope->>'tenantId' IS DISTINCT FROM NEW.tenant_id::text THEN RAISE EXCEPTION 'Audit envelope must match its protected journal claim' USING ERRCODE='23514'; END IF;
  resource_version:=(NEW.changes->>'resourceVersion')::integer;
 ELSE
  action_name:=NEW.event_type;resource:=NEW.resource_id;resource_version:=NEW.resource_version;
  IF NEW.payload->>'actorId' IS DISTINCT FROM op.actor_id::text OR NEW.payload->>'correlationId' IS DISTINCT FROM op.correlation_id
   OR NEW.payload->>'type' IS DISTINCT FROM NEW.event_type OR NEW.payload->>'subject' IS DISTINCT FROM NEW.resource_id
   OR NEW.payload->>'resourceVersion' IS DISTINCT FROM NEW.resource_version::text OR NEW.payload->>'id' IS DISTINCT FROM NEW.id::text
   OR NEW.payload->>'tenantId' IS DISTINCT FROM NEW.tenant_id::text THEN RAISE EXCEPTION 'Outbox envelope must match its protected journal claim' USING ERRCODE='23514'; END IF;
 END IF;
 SELECT * INTO claim FROM public.relation_graph_operation_journal_claims c WHERE c.tenant_id=op.tenant_id AND c.operation_id=op.id
  AND c.action=action_name AND c.resource_id=resource AND c.resource_version=journal_context.resource_version;
 IF claim.operation_id IS NULL THEN RAISE EXCEPTION 'Unclaimed graph journal is forbidden' USING ERRCODE='23514'; END IF;
 IF TG_RELID='public.audit'::regclass THEN
  IF claim.audit_id IS NOT NULL THEN RAISE EXCEPTION 'A graph change has exactly one audit pair' USING ERRCODE='23514'; END IF;
  UPDATE public.relation_graph_operation_journal_claims c SET audit_id=NEW.id WHERE c.tenant_id=op.tenant_id AND c.operation_id=op.id
   AND c.action=action_name AND c.resource_id=resource AND c.resource_version=journal_context.resource_version;
 ELSE
  IF claim.audit_id IS DISTINCT FROM NEW.id OR claim.outbox_written OR NOT EXISTS(SELECT 1 FROM public.audit a WHERE a.tenant_id=op.tenant_id
    AND a.id=NEW.id AND a.action=action_name AND a.resource_id=resource AND a.changes->>'resourceVersion'=resource_version::text) THEN
   RAISE EXCEPTION 'A graph outbox must pair once with its exact inserted audit' USING ERRCODE='23514'; END IF;
  UPDATE public.relation_graph_operation_journal_claims c SET outbox_written=true WHERE c.tenant_id=op.tenant_id AND c.operation_id=op.id
   AND c.action=action_name AND c.resource_id=resource AND c.resource_version=journal_context.resource_version;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_journal_guard() FROM PUBLIC,gc_app;
CREATE TRIGGER graph_journal_claim_guard BEFORE INSERT OR UPDATE OR DELETE ON public.audit FOR EACH ROW EXECUTE FUNCTION public.gc_relation_graph_journal_guard();
CREATE TRIGGER graph_journal_claim_guard BEFORE INSERT OR UPDATE OR DELETE ON public.outbox FOR EACH ROW EXECUTE FUNCTION public.gc_relation_graph_journal_guard();

CREATE FUNCTION public.gc_relation_preparation_view(row_value public.relation_type_preparations) RETURNS jsonb
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('id',row_value.id,'relationTypeId',row_value.type_id,'definitionHash',row_value.definition_hash,
  'createdAt',public.gc_relation_utc(row_value.created_at),'expiresAt',public.gc_relation_utc(row_value.expires_at))
$$;
-- Independent grammar-owned normalization. Never descend into governed values,
-- literal transformations, schemas, or user arrays. Sorting preserves duplicates
-- and unknown fields; the strict validators below reject them, never erase them.
CREATE FUNCTION public.gc_relation_graph_sort(value jsonb,sort_path text[] DEFAULT NULL,numeric_key boolean DEFAULT false,second_path text[] DEFAULT NULL) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE result jsonb;
BEGIN
 IF jsonb_typeof(value) IS DISTINCT FROM 'array' THEN RAISE EXCEPTION 'Normalization requires an actual declared array' USING ERRCODE='23514'; END IF;
 SELECT coalesce(jsonb_agg(v ORDER BY
  CASE WHEN numeric_key THEN (CASE WHEN sort_path IS NULL THEN v#>>'{}' ELSE v#>>sort_path END)::numeric END,
  (CASE WHEN sort_path IS NULL THEN v#>>'{}' ELSE v#>>sort_path END) COLLATE "C",(v#>>second_path) COLLATE "C"),'[]') INTO result
 FROM jsonb_array_elements(value) e(v);
 RETURN result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RAISE EXCEPTION 'Invalid declared normalization key' USING ERRCODE='23514';
END $$;
CREATE FUNCTION public.gc_relation_graph_normalize_definition(value jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE result jsonb:=value; name text;
BEGIN
 IF jsonb_typeof(value) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Relation definition must be an object' USING ERRCODE='23514'; END IF;
 FOREACH name IN ARRAY ARRAY['sourceTypes','targetTypes'] LOOP
  result:=jsonb_set(result,ARRAY[name],public.gc_relation_graph_sort(result->name,ARRAY['typeId']));
 END LOOP;
 FOREACH name IN ARRAY ARRAY['sourceStates','targetStates'] LOOP
  IF result->name IS DISTINCT FROM 'null'::jsonb THEN result:=jsonb_set(result,ARRAY[name],public.gc_relation_graph_sort(result->name)); END IF;
 END LOOP;
 RETURN result;
END $$;
CREATE FUNCTION public.gc_relation_graph_normalize_values(value jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
BEGIN
 IF jsonb_typeof(value) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Relation values must be an object' USING ERRCODE='23514'; END IF;
 RETURN jsonb_set(value,'{allowedIdentityIds}',public.gc_relation_graph_sort(value->'allowedIdentityIds'));
END $$;
CREATE FUNCTION public.gc_relation_graph_normalize_transform(value jsonb,owner_key text) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE result jsonb:=value;
BEGIN
 IF jsonb_typeof(value) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Migration transform must be an object' USING ERRCODE='23514'; END IF;
 result:=jsonb_set(result,'{owner,overrides}',public.gc_relation_graph_sort(value->'owner'->'overrides',ARRAY[owner_key]));
 result:=jsonb_set(result,'{lifecycle,mappings}',public.gc_relation_graph_sort(value->'lifecycle'->'mappings',ARRAY['sourceVersion'],true,ARRAY['from']));
 RETURN result;
END $$;
CREATE FUNCTION public.gc_relation_graph_normalize_change_set(value jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE result jsonb:=value; targets jsonb:='[]'; migrations jsonb:='[]'; target jsonb; plan jsonb; entry jsonb; entries jsonb; name text;
BEGIN
 IF jsonb_typeof(value) IS DISTINCT FROM 'object' OR NOT public.gc_relation_json_bounded(value,100000,32,524288) THEN
  RAISE EXCEPTION 'Invalid bounded graph normalization input' USING ERRCODE='23514'; END IF;
 FOR target IN SELECT v FROM jsonb_array_elements(public.gc_relation_graph_sort(value->'relationTargets',ARRAY['plan','relationTypeId'])) e(v) LOOP
  plan:=target->'plan';
  IF jsonb_typeof(plan) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Migration plan must be an object' USING ERRCODE='23514'; END IF;
  plan:=jsonb_set(plan,'{sourceVersions}',public.gc_relation_graph_sort(plan->'sourceVersions',NULL,true));
  plan:=jsonb_set(plan,'{acknowledgedPolicyChanges}',public.gc_relation_graph_sort(plan->'acknowledgedPolicyChanges'));
  plan:=jsonb_set(plan,'{bindings}',public.gc_relation_graph_sort(plan->'bindings',ARRAY['bindingId']));
  IF plan->'transform' IS DISTINCT FROM 'null'::jsonb THEN plan:=jsonb_set(plan,'{transform}',public.gc_relation_graph_normalize_transform(plan->'transform','relationId')); END IF;
  FOREACH name IN ARRAY ARRAY['edges','creations'] LOOP
   entries:='[]';
   FOR entry IN SELECT v FROM jsonb_array_elements(public.gc_relation_graph_sort(plan->name,ARRAY[CASE WHEN name='edges' THEN 'relationId' ELSE 'key' END])) e(v) LOOP
    IF name='creations' OR entry->>'action' IN ('repair','repin') THEN entry:=jsonb_set(entry,'{values}',public.gc_relation_graph_normalize_values(entry->'values')); END IF;
    entries:=entries||jsonb_build_array(entry);
   END LOOP;
   plan:=jsonb_set(plan,ARRAY[name],entries);
  END LOOP;
  target:=jsonb_set(target,'{plan}',plan);
  IF target->>'kind'<>'repair' THEN target:=jsonb_set(target,'{definition}',public.gc_relation_graph_normalize_definition(target->'definition')); END IF;
  targets:=targets||jsonb_build_array(target);
 END LOOP;
 FOR target IN SELECT v FROM jsonb_array_elements(public.gc_relation_graph_sort(value->'assetTypeMigrations',ARRAY['definition','id'])) e(v) LOOP
  plan:=public.gc_relation_graph_normalize_transform(target->'plan','assetId');
  plan:=jsonb_set(plan,'{acknowledgedPolicyChanges}',public.gc_relation_graph_sort(plan->'acknowledgedPolicyChanges'));
  migrations:=migrations||jsonb_build_array(jsonb_set(target,'{plan}',plan));
 END LOOP;
 result:=jsonb_set(result,'{relationTargets}',targets);
 result:=jsonb_set(result,'{assetChanges}',public.gc_relation_graph_sort(value->'assetChanges',ARRAY['assetId']));
 result:=jsonb_set(result,'{assetTypeMigrations}',migrations);
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_sort(jsonb,text[],boolean,text[]),public.gc_relation_graph_normalize_definition(jsonb),
 public.gc_relation_graph_normalize_values(jsonb),public.gc_relation_graph_normalize_transform(jsonb,text),public.gc_relation_graph_normalize_change_set(jsonb) FROM PUBLIC,gc_app;

CREATE FUNCTION public.gc_relation_graph_prepare(idempotency_key text,request_body jsonb,correlation_id text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE actor uuid:=public.gc_actor()::uuid; tenant uuid:=public.gc_tenant(); prepared public.relation_type_preparations;
 moment timestamptz:=date_trunc('milliseconds',clock_timestamp()); definition jsonb;
BEGIN
 PERFORM public.gc_relation_authorize(ARRAY['models:read','models:write','catalog:read','catalog:write']);
 IF (public.gc_relation_graph_current()).id IS NOT NULL THEN RAISE EXCEPTION 'Preparation cannot join an active graph execution' USING ERRCODE='23514'; END IF;
 IF length(idempotency_key) NOT BETWEEN 8 AND 128 OR correlation_id IS NULL OR length(correlation_id) NOT BETWEEN 1 AND 200
  OR NOT public.gc_relation_keys(request_body,ARRAY['definition'])
  OR NOT public.gc_relation_json_bounded(request_body,100000,32,524288) THEN RAISE EXCEPTION 'Invalid relation preparation request' USING ERRCODE='23514'; END IF;
 definition:=public.gc_relation_graph_normalize_definition(request_body->'definition');
 IF NOT public.gc_relation_definition_valid(definition) OR definition->'formatVersion'<>'2' OR definition->'version'<>'1' THEN
  RAISE EXCEPTION 'Invalid relation preparation definition' USING ERRCODE='23514'; END IF;
 PERFORM public.gc_relation_graph_budget(moment);
 IF NOT pg_try_advisory_xact_lock(hashtextextended(tenant::text||actor::text||'relation-migration.prepare'||idempotency_key,0))
  OR NOT pg_try_advisory_xact_lock(hashtextextended(tenant::text,0)) THEN
  RAISE EXCEPTION 'Relation preparation requires a stable execution window' USING ERRCODE='55P03'; END IF;
 PERFORM public.gc_relation_graph_budget(moment);
 PERFORM public.gc_lock_type_migration_principals(ARRAY[actor]);
 PERFORM public.gc_relation_authorize(ARRAY['models:read','models:write','catalog:read','catalog:write']);
 IF EXISTS(SELECT 1 FROM public.relation_types WHERE tenant_id=tenant AND id=definition->>'id') THEN
  RAISE EXCEPTION 'RELATION_PREPARATION_CONFLICT' USING ERRCODE='23505'; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements((definition->'sourceTypes')||(definition->'targetTypes')) e(v)
  WHERE NOT EXISTS(SELECT 1 FROM public.governance_models m WHERE m.tenant_id=tenant AND m.type_id=(v->>'typeId')::uuid)) THEN
  RAISE EXCEPTION 'RELATION_SCOPE_UNAVAILABLE' USING ERRCODE='42501'; END IF;
 INSERT INTO public.relation_type_preparations(tenant_id,id,type_id,logical_key,definition,definition_hash,created_by,created_at,expires_at,
  transaction_id,idempotency_key,request_hash,correlation_id)
 VALUES(tenant,gen_random_uuid(),gen_random_uuid(),definition->>'id',definition,
  public.gc_type_migration_hash(definition),actor,moment,moment+interval '15 minutes',pg_current_xact_id(),
  idempotency_key,public.gc_type_migration_hash(request_body),correlation_id) RETURNING * INTO prepared;
 RETURN public.gc_relation_preparation_view(prepared);
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_prepare(text,jsonb,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_graph_prepare(text,jsonb,text) TO gc_app;

CREATE FUNCTION public.gc_relation_reserved_idempotency_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.relation_graph_operations; prepared public.relation_type_preparations;
BEGIN
 IF TG_OP<>'INSERT' AND OLD.operation IN ('relation-migration.execute','relation-migration.prepare') THEN
  RAISE EXCEPTION 'Graph idempotency success is immutable' USING ERRCODE='42501'; END IF;
 IF TG_OP='DELETE' THEN
  IF (public.gc_relation_graph_current()).id IS NOT NULL THEN RAISE EXCEPTION 'Graph execution permits only its reserved idempotency success' USING ERRCODE='23514'; END IF;
  RETURN OLD;
 END IF;
 IF NEW.operation NOT IN ('relation-migration.execute','relation-migration.prepare') THEN
  IF (public.gc_relation_graph_current()).id IS NOT NULL THEN RAISE EXCEPTION 'Graph execution permits only its reserved idempotency success' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF TG_OP<>'INSERT' OR NEW.tenant_id IS DISTINCT FROM public.gc_tenant() OR NEW.actor_id IS DISTINCT FROM public.gc_actor() THEN
  RAISE EXCEPTION 'Reserved success requires the actual scoped transaction' USING ERRCODE='42501'; END IF;
 IF NEW.operation='relation-migration.execute' THEN
  SELECT * INTO op FROM public.relation_graph_operations WHERE tenant_id=NEW.tenant_id AND transaction_id=pg_current_xact_id();
  IF op.id IS NULL OR op.state<>'sealed' OR op.actor_id::text<>NEW.actor_id OR op.idempotency_key<>NEW.key
   OR op.request_hash<>NEW.request_hash OR NEW.response IS DISTINCT FROM jsonb_build_object('receipt',op.receipt) THEN
   RAISE EXCEPTION 'Success must equal the sealed graph receipt' USING ERRCODE='23514'; END IF;
 ELSE
  SELECT * INTO prepared FROM public.relation_type_preparations WHERE tenant_id=NEW.tenant_id AND transaction_id=pg_current_xact_id()
   AND created_by::text=NEW.actor_id AND idempotency_key=NEW.key;
  IF prepared.id IS NULL OR prepared.request_hash<>NEW.request_hash
   OR NEW.response IS DISTINCT FROM jsonb_build_object('preparation',public.gc_relation_preparation_view(prepared)) THEN
   RAISE EXCEPTION 'Success must equal the protected preparation' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_reserved_idempotency_guard() FROM PUBLIC,gc_app;
CREATE TRIGGER relation_reserved_idempotency_guard BEFORE INSERT OR UPDATE OR DELETE ON public.idempotency
 FOR EACH ROW EXECUTE FUNCTION public.gc_relation_reserved_idempotency_guard();
CREATE FUNCTION public.gc_relation_preparation_complete() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.idempotency i WHERE i.tenant_id=NEW.tenant_id AND i.actor_id=NEW.created_by::text
  AND i.operation='relation-migration.prepare' AND i.key=NEW.idempotency_key AND i.request_hash=NEW.request_hash
  AND i.response=jsonb_build_object('preparation',public.gc_relation_preparation_view(NEW)))
  OR NOT public.gc_relation_graph_journal('relation_preparation.created',NEW.id::text,1,NEW.created_by,NEW.correlation_id) THEN
  RAISE EXCEPTION 'Preparation requires its exact success and journal' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_preparation_complete() FROM PUBLIC,gc_app;
CREATE CONSTRAINT TRIGGER relation_preparation_complete AFTER INSERT ON public.relation_type_preparations
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_relation_preparation_complete();

-- Independent authored resolution for a proposed nested migration. Exact parent
-- versions are immutable stored input; no caller-provided resolved object is read.
CREATE FUNCTION public.gc_relation_graph_resolve_asset(definition jsonb,verify_ancestry boolean DEFAULT true) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE parent record; item record; attributes jsonb:='{}'; inherited jsonb:='{}'; dependencies jsonb:='[]';
 required_owner boolean; lifecycle jsonb; key text; parent_lifecycle jsonb; ancestor record; closure jsonb; stored public.asset_type_versions;
BEGIN
 IF NOT public.gc_relation_keys(definition,ARRAY['formatVersion','id','version','parents','attributes','overrideAttributes','requiredOwner','lifecycle'])
  OR definition->'formatVersion'<>'1' OR jsonb_typeof(definition->'id') IS DISTINCT FROM 'string' OR NOT public.gc_relation_safe_id(definition->>'id')
  OR NOT public.gc_relation_positive_integer(definition->'version') OR NOT public.gc_relation_json_bounded(definition,20000,24,262144)
  OR NOT public.gc_type_pins_valid(definition->'parents',8) OR jsonb_typeof(definition->'requiredOwner')<>'boolean'
  OR jsonb_typeof(definition->'overrideAttributes')<>'array' OR jsonb_array_length(definition->'overrideAttributes')>128
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(definition->'overrideAttributes') e(v) WHERE jsonb_typeof(v)<>'string' OR public.gc_relation_safe_id(v#>>'{}') IS NOT TRUE)
  OR jsonb_typeof(definition->'attributes')<>'object' THEN
  RAISE EXCEPTION 'Invalid authored type migration definition' USING ERRCODE='23514'; END IF;
 IF verify_ancestry THEN
  WITH RECURSIVE ancestry(id,version,depth) AS (
   SELECT p->>'id',(p->>'version')::integer,1 FROM jsonb_array_elements(definition->'parents') e(p)
   UNION SELECT p->>'id',(p->>'version')::integer,a.depth+1 FROM ancestry a JOIN public.asset_type_versions v
    ON v.tenant_id=public.gc_tenant() AND v.model_id=a.id AND v.version=a.version
    CROSS JOIN LATERAL jsonb_array_elements(v.definition->'parents') e(p) WHERE a.depth<=8)
  SELECT coalesce(jsonb_agg(jsonb_build_object('id',id,'version',version,'depth',depth)),'[]') INTO closure FROM ancestry;
  IF jsonb_array_length(closure)>576 OR EXISTS(SELECT 1 FROM jsonb_array_elements(closure) e(v)
    WHERE (v->>'depth')::integer>8 OR v->'id'=definition->'id')
   OR (SELECT count(DISTINCT jsonb_build_object('id',v->'id','version',v->'version')) FROM jsonb_array_elements(closure) e(v))>64 THEN
   RAISE EXCEPTION 'Invalid bounded authored ancestry' USING ERRCODE='23514'; END IF;
  FOR ancestor IN SELECT DISTINCT v->>'id' AS id,(v->>'version')::integer AS version FROM jsonb_array_elements(closure) e(v) LOOP
   SELECT v.* INTO stored FROM public.asset_type_versions v JOIN public.governance_models h ON h.tenant_id=v.tenant_id AND h.id=v.model_id
    WHERE v.tenant_id=public.gc_tenant() AND v.model_id=ancestor.id AND v.version=ancestor.version AND v.version<=h.current_version;
   IF stored.model_id IS NULL OR stored.resolved IS DISTINCT FROM public.gc_relation_graph_resolve_asset(stored.definition,false) THEN
    RAISE EXCEPTION 'Every immutable ancestor resolution must match its authored policy' USING ERRCODE='23514'; END IF;
  END LOOP;
 END IF;
 required_owner:=(definition->>'requiredOwner')::boolean;
 FOR parent IN SELECT v.* FROM jsonb_array_elements(definition->'parents') e(p) LEFT JOIN public.asset_type_versions v
  ON v.tenant_id=public.gc_tenant() AND v.model_id=p->>'id' AND v.version=(p->>'version')::integer ORDER BY p->>'id' COLLATE "C" LOOP
  IF parent.model_id IS NULL OR parent.definition_hash<>public.gc_type_migration_hash(parent.definition)
   OR parent.resolution_hash<>public.gc_type_migration_hash(parent.resolved) THEN
   RAISE EXCEPTION 'Authored parent policy is unavailable or corrupt' USING ERRCODE='23514'; END IF;
  dependencies:=dependencies||jsonb_build_array(jsonb_build_object('id',parent.model_id,'version',parent.version))||(parent.resolved->'dependencies');
  required_owner:=required_owner OR (parent.resolved->>'requiredOwner')::boolean;
  parent_lifecycle:=parent.resolved->'lifecycle';
  IF definition->'lifecycle'='null' THEN
   IF lifecycle IS NOT NULL AND lifecycle<>parent_lifecycle THEN RAISE EXCEPTION 'Ambiguous inherited lifecycle' USING ERRCODE='23514'; END IF;
   lifecycle:=parent_lifecycle;
  END IF;
  FOR item IN SELECT * FROM jsonb_each(parent.resolved->'model'->'attributes') LOOP
   IF inherited ? item.key AND inherited->item.key<>item.value AND NOT definition->'overrideAttributes' @> jsonb_build_array(item.key) THEN
    RAISE EXCEPTION 'Inherited attributes require an explicit override' USING ERRCODE='23514'; END IF;
   inherited:=inherited||jsonb_build_object(item.key,item.value);
  END LOOP;
 END LOOP;
 IF definition->'lifecycle'<>'null' THEN lifecycle:=definition->'lifecycle'; END IF;
 IF lifecycle IS NULL OR NOT public.gc_relation_lifecycle_valid(lifecycle) THEN RAISE EXCEPTION 'Authored type needs a valid resolved lifecycle' USING ERRCODE='23514'; END IF;
 FOR key IN SELECT jsonb_array_elements_text(definition->'overrideAttributes') LOOP
  IF NOT inherited ? key OR NOT definition->'attributes' ? key THEN RAISE EXCEPTION 'Override must name an inherited and authored field' USING ERRCODE='23514'; END IF;
 END LOOP;
 IF (SELECT count(*)<>count(DISTINCT v) FROM jsonb_array_elements(definition->'overrideAttributes') e(v)) THEN
  RAISE EXCEPTION 'Duplicate authored override' USING ERRCODE='23514'; END IF;
 FOR item IN SELECT * FROM jsonb_each(definition->'attributes') LOOP
  IF inherited ? item.key AND NOT definition->'overrideAttributes' @> jsonb_build_array(item.key) THEN
   RAISE EXCEPTION 'Redeclared inherited attribute requires an override' USING ERRCODE='23514'; END IF;
 END LOOP;
 attributes:=inherited||(definition->'attributes');
 IF NOT public.gc_relation_schema_valid(jsonb_build_object('type','object','properties',attributes)) THEN
  RAISE EXCEPTION 'Invalid resolved attribute schema' USING ERRCODE='23514'; END IF;
 SELECT coalesce(jsonb_agg(v ORDER BY v->>'id',(v->>'version')::integer),'[]') INTO dependencies FROM (SELECT DISTINCT v FROM jsonb_array_elements(dependencies) e(v)) p;
 IF NOT public.gc_type_pins_valid(dependencies,64) OR dependencies @> jsonb_build_array(jsonb_build_object('id',definition->'id','version',definition->'version'))
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(dependencies) e(v) WHERE v->'id'=definition->'id') THEN
  RAISE EXCEPTION 'Invalid authored dependency closure' USING ERRCODE='23514'; END IF;
 RETURN jsonb_build_object('definition',definition,'dependencies',dependencies,'model',jsonb_build_object('formatVersion',1,
  'id',definition->'id','version',definition->'version','attributes',attributes),'requiredOwner',required_owner,'lifecycle',lifecycle);
END $$;
CREATE FUNCTION public.gc_relation_graph_asset_policy(model_key text,model_version integer,request_body jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE migration jsonb; policy public.asset_type_versions; model public.governance_model_versions;
BEGIN
 IF model_key IS NULL THEN RETURN NULL; END IF;
 IF NOT public.gc_relation_positive_integer(to_jsonb(model_version)) THEN RAISE EXCEPTION 'Invalid exact model pin' USING ERRCODE='23514'; END IF;
 SELECT v INTO migration FROM jsonb_array_elements(request_body->'changeSet'->'assetTypeMigrations') e(v)
  WHERE v->'definition'->>'id'=model_key AND (v->'definition'->>'version')::integer=model_version;
 IF migration IS NOT NULL THEN RETURN public.gc_relation_graph_resolve_asset(migration->'definition'); END IF;
 IF NOT EXISTS(SELECT 1 FROM public.governance_models h WHERE h.tenant_id=public.gc_tenant() AND h.id=model_key AND h.current_version>=model_version) THEN
  RAISE EXCEPTION 'Exact model pin must already be published' USING ERRCODE='23514'; END IF;
 SELECT * INTO policy FROM public.asset_type_versions WHERE tenant_id=public.gc_tenant() AND model_id=model_key AND version=model_version;
 IF policy IS NOT NULL THEN
  IF policy.definition_hash<>public.gc_type_migration_hash(policy.definition) OR policy.resolution_hash<>public.gc_type_migration_hash(policy.resolved)
   OR policy.resolved IS DISTINCT FROM public.gc_relation_graph_resolve_asset(policy.definition) THEN
   RAISE EXCEPTION 'Stored authored resolution is inconsistent' USING ERRCODE='23514'; END IF;
  RETURN policy.resolved;
 END IF;
 SELECT * INTO model FROM public.governance_model_versions WHERE tenant_id=public.gc_tenant() AND model_id=model_key AND version=model_version;
 IF model.model_id IS NULL OR model.definition_hash<>public.gc_type_migration_hash(model.definition)
  OR EXISTS(SELECT 1 FROM public.governance_models WHERE tenant_id=public.gc_tenant() AND id=model_key AND type_id IS NOT NULL) THEN
  RAISE EXCEPTION 'Stored model policy is unavailable or inconsistent' USING ERRCODE='23514'; END IF;
 RETURN jsonb_build_object('model',model.definition,'requiredOwner',false,'lifecycle',NULL,'dependencies','[]'::jsonb);
END $$;
CREATE FUNCTION public.gc_relation_graph_endpoint(asset_id uuid,asset_version integer,tuple jsonb,request_body jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE policy jsonb; own_type uuid; ancestors jsonb:='[]';
BEGIN
 IF tuple->>'modelId' IS NOT NULL THEN
  policy:=public.gc_relation_graph_asset_policy(tuple->>'modelId',(tuple->>'modelVersion')::integer,request_body);
  SELECT type_id INTO own_type FROM public.governance_models WHERE tenant_id=public.gc_tenant() AND id=tuple->>'modelId';
 END IF;
 IF own_type IS NOT NULL THEN
  SELECT coalesce(jsonb_agg(jsonb_build_object('typeId',m.type_id,'id',m.id,'version',p->'version') ORDER BY m.id COLLATE "C"),'[]') INTO ancestors
   FROM jsonb_array_elements(policy->'dependencies') e(p) JOIN public.governance_models m
    ON m.tenant_id=public.gc_tenant() AND m.id=p->>'id';
 ELSE policy:=NULL; END IF;
 RETURN jsonb_build_object('assetId',asset_id,'assetVersion',asset_version,'modelId',tuple->'modelId','modelVersion',tuple->'modelVersion',
  'state',tuple->'state','typeId',own_type,'policy',policy,'ancestorTypes',ancestors);
END $$;
CREATE FUNCTION public.gc_relation_projected_eligible(endpoint jsonb,definition jsonb,side text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT coalesce(endpoint->>'typeId' IS NOT NULL AND endpoint->'policy'->'lifecycle'->'states' @> jsonb_build_array(endpoint->'state')
  AND (definition->(side||'States')='null' OR definition->(side||'States') @> jsonb_build_array(endpoint->'state'))
  AND EXISTS(SELECT 1 FROM jsonb_array_elements(definition->(side||'Types')) e(rule)
   WHERE rule->'typeId'=endpoint->'typeId' OR (rule->>'includeDescendants'='true' AND EXISTS(
    SELECT 1 FROM jsonb_array_elements(endpoint->'ancestorTypes') a(pin) WHERE pin->'typeId'=rule->'typeId'))),false)
$$;
-- Scope discovery uses only nominal policy/state, never governed attributes.
-- Failed attribute repair cannot hide an otherwise eligible zero-edge asset.
CREATE FUNCTION public.gc_relation_graph_project_endpoint(row_value public.assets,request_body jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proposal jsonb; migration jsonb; policy jsonb; tuple jsonb; mapped jsonb; endpoint jsonb; changed boolean:=false;
BEGIN
 tuple:=jsonb_build_object('modelId',row_value.model_id,'modelVersion',row_value.model_version,'state',row_value.type_state);
 SELECT v INTO proposal FROM jsonb_array_elements(request_body->'changeSet'->'assetChanges') e(v) WHERE v->>'assetId'=row_value.id::text;
 SELECT v INTO migration FROM jsonb_array_elements(request_body->'changeSet'->'assetTypeMigrations') e(v) WHERE v->'definition'->>'id'=row_value.model_id;
 IF proposal IS NOT NULL THEN
  changed:=true;
  IF proposal->>'kind'='assign' THEN
   policy:=public.gc_relation_graph_asset_policy(proposal->>'modelId',(proposal->>'modelVersion')::integer,
    jsonb_build_object('changeSet',jsonb_build_object('assetTypeMigrations','[]'::jsonb)));
   tuple:=jsonb_build_object('modelId',proposal->'modelId','modelVersion',proposal->'modelVersion','state',
    CASE WHEN policy->'lifecycle'='null' THEN 'null'::jsonb WHEN row_value.model_id=proposal->>'modelId' AND row_value.type_state IS NOT NULL
     THEN to_jsonb(row_value.type_state) ELSE policy->'lifecycle'->'initial' END);
  ELSIF proposal->>'kind'='transition' THEN tuple:=tuple||jsonb_build_object('state',proposal->'state');
  ELSE RAISE EXCEPTION 'Invalid graph asset change' USING ERRCODE='23514'; END IF;
 ELSIF migration IS NOT NULL THEN
  changed:=true;
  SELECT v->'to' INTO mapped FROM jsonb_array_elements(migration->'plan'->'lifecycle'->'mappings') e(v)
   WHERE v->>'sourceVersion'=row_value.model_version::text AND v->>'from'=row_value.type_state;
  tuple:=tuple||jsonb_build_object('modelVersion',migration->'definition'->'version','state',coalesce(mapped,to_jsonb(row_value.type_state),'null'));
 END IF;
 endpoint:=public.gc_relation_graph_endpoint(row_value.id,row_value.version+CASE WHEN changed THEN 1 ELSE 0 END,tuple,request_body);
 RETURN endpoint||jsonb_build_object('policy',CASE WHEN endpoint->'policy'='null' THEN 'null'::jsonb ELSE jsonb_build_object('lifecycle',jsonb_build_object('states',endpoint->'policy'->'lifecycle'->'states')) END);
END $$;

CREATE FUNCTION public.gc_relation_graph_project_asset(row_value public.assets,request_body jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE proposal jsonb; migration jsonb; policy jsonb; source jsonb; head jsonb; result jsonb:=public.gc_relation_asset_tuple(row_value);
 override jsonb; mapped jsonb; state jsonb; typed_count integer;
BEGIN
 SELECT v INTO proposal FROM jsonb_array_elements(request_body->'changeSet'->'assetChanges') e(v) WHERE v->>'assetId'=row_value.id::text;
 SELECT count(*),min(v::text)::jsonb INTO typed_count,migration FROM jsonb_array_elements(request_body->'changeSet'->'assetTypeMigrations') e(v)
  WHERE v->'definition'->>'id'=row_value.model_id;
 IF typed_count>1 OR (proposal IS NOT NULL AND typed_count>0) THEN RAISE EXCEPTION 'Overlapping asset proposals' USING ERRCODE='23514'; END IF;
 IF proposal IS NULL AND migration IS NULL THEN RETURN result; END IF;
 source:=public.gc_relation_graph_asset_policy(row_value.model_id,row_value.model_version,jsonb_build_object('changeSet',jsonb_build_object('assetTypeMigrations','[]'::jsonb)));
 IF proposal IS NOT NULL THEN
  IF NOT public.gc_relation_positive_integer(proposal->'expectedVersion') OR (proposal->>'expectedVersion')::integer<>row_value.version THEN RAISE EXCEPTION 'Asset version conflict' USING ERRCODE='40001'; END IF;
  IF proposal->>'kind'='assign' THEN
   IF NOT public.gc_relation_keys(proposal,ARRAY['kind','assetId','expectedVersion','modelId','modelVersion','attributes','ownerId'])
    OR NOT public.gc_relation_positive_integer(proposal->'modelVersion') OR proposal->'ownerId' IS DISTINCT FROM result->'ownerId' THEN RAISE EXCEPTION 'Assignment must preserve actual ownership' USING ERRCODE='23514'; END IF;
   policy:=public.gc_relation_graph_asset_policy(proposal->>'modelId',(proposal->>'modelVersion')::integer,
    jsonb_build_object('changeSet',jsonb_build_object('assetTypeMigrations','[]'::jsonb)));
   state:=CASE WHEN policy->'lifecycle'='null' THEN 'null'::jsonb
    WHEN row_value.model_id=proposal->>'modelId' AND row_value.type_state IS NOT NULL THEN to_jsonb(row_value.type_state)
    ELSE policy->'lifecycle'->'initial' END;
   result:=result||jsonb_build_object('modelId',proposal->'modelId','modelVersion',proposal->'modelVersion','attributes',proposal->'attributes','state',state);
  ELSIF proposal->>'kind'='transition' THEN
   IF NOT public.gc_relation_keys(proposal,ARRAY['kind','assetId','expectedVersion','state']) OR source->'lifecycle' IS NULL
    OR NOT source->'lifecycle'->'transitions' @> jsonb_build_array(jsonb_build_object('from',row_value.type_state,'to',proposal->'state')) THEN
    RAISE EXCEPTION 'Asset transition must follow its actual pinned lifecycle' USING ERRCODE='23514'; END IF;
   policy:=source;result:=result||jsonb_build_object('state',proposal->'state');
  ELSE RAISE EXCEPTION 'Invalid graph asset change' USING ERRCODE='23514'; END IF;
 ELSE
  policy:=public.gc_relation_graph_resolve_asset(migration->'definition');
  SELECT v.resolved INTO head FROM public.governance_models m JOIN public.asset_type_versions v
   ON v.tenant_id=m.tenant_id AND v.model_id=m.id AND v.version=m.current_version
   WHERE m.tenant_id=row_value.tenant_id AND m.id=row_value.model_id AND m.current_version=(migration->>'expectedHeadVersion')::integer
    AND m.type_id=(migration->'plan'->>'typeId')::uuid;
  IF head IS NULL OR source IS NULL THEN RAISE EXCEPTION 'Nested type migration head is stale' USING ERRCODE='40001'; END IF;
  SELECT v->'ownerId' INTO override FROM jsonb_array_elements(migration->'plan'->'owner'->'overrides') e(v) WHERE v->>'assetId'=row_value.id::text;
  SELECT v->'to' INTO mapped FROM jsonb_array_elements(migration->'plan'->'lifecycle'->'mappings') e(v)
   WHERE (v->>'sourceVersion')::integer=row_value.model_version AND v->>'from'=row_value.type_state;
  IF mapped IS NULL AND migration->'plan'->'lifecycle'->>'onUnmapped'='error' THEN RAISE EXCEPTION 'Unmapped source asset state' USING ERRCODE='23514'; END IF;
  result:=jsonb_build_object('modelId',row_value.model_id,'modelVersion',policy->'definition'->'version',
   'attributes',public.gc_relation_attribute_transform(head->'model',source->'model',policy->'model',migration->'plan'->'attributes',row_value.attributes),
   'ownerId',coalesce(override,to_jsonb(row_value.owner_id),'null'),'state',coalesce(mapped,to_jsonb(row_value.type_state),'null'));
 END IF;
 IF NOT public.gc_relation_value_valid(jsonb_build_object('type','object','properties',policy->'model'->'attributes'),result->'attributes')
  OR (policy->'lifecycle'<>'null' AND NOT policy->'lifecycle'->'states' @> jsonb_build_array(result->'state')) THEN
  RAISE EXCEPTION 'Proposed asset violates its exact target policy' USING ERRCODE='23514'; END IF;
 RETURN result;
END $$;

CREATE FUNCTION public.gc_relation_check_type(tenant uuid,type_identity uuid) RETURNS void
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
 OR (SELECT count(*) FROM public.assets a WHERE a.tenant_id=tenant AND (public.gc_relation_endpoint_eligible(tenant,a.id,head_definition,'source')
   OR public.gc_relation_endpoint_eligible(tenant,a.id,head_definition,'target')))>2000 THEN
  RAISE EXCEPTION 'RELATION_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 FOR selected_side IN SELECT unnest(CASE WHEN head_definition->>'direction'='undirected' THEN ARRAY['incident'] ELSE ARRAY['source','target'] END) LOOP
  side_min:=(head_definition->'cardinality'->(CASE WHEN selected_side='target' THEN 'incoming' ELSE 'outgoing' END)->>'min')::integer;
  IF side_min>0 AND EXISTS(SELECT 1 FROM public.assets a WHERE a.tenant_id=tenant
   AND public.gc_relation_endpoint_eligible(tenant,a.id,head_definition,CASE WHEN selected_side='incident' THEN 'source' ELSE selected_side END)
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
CREATE OR REPLACE FUNCTION public.gc_relation_validate_final() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.relation_graph_operations;
BEGIN
 IF TG_RELID<>'public.relation_validation_work'::regclass OR NEW.tenant_id IS DISTINCT FROM public.gc_tenant()
  OR NEW.transaction_id<>pg_current_xact_id() THEN RAISE EXCEPTION 'Untrusted graph validation work' USING ERRCODE='42501'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.relation_validation_work w WHERE w.tenant_id=NEW.tenant_id AND w.transaction_id=NEW.transaction_id AND w.relation_type_id=NEW.relation_type_id) THEN RETURN NEW; END IF;
 op:=public.gc_relation_graph_current();
 IF op.id IS NOT NULL AND op.state='open' THEN RAISE EXCEPTION 'An unsealed graph operation cannot finalize' USING ERRCODE='23514'; END IF;
 PERFORM public.gc_relation_check_type(NEW.tenant_id,NEW.relation_type_id);
 DELETE FROM public.relation_validation_work WHERE tenant_id=NEW.tenant_id AND transaction_id=NEW.transaction_id AND relation_type_id=NEW.relation_type_id;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION public.gc_relation_enqueue() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=NEW.tenant_id; type_identity uuid;
BEGIN
 IF TG_TABLE_SCHEMA<>'public' OR tenant IS DISTINCT FROM public.gc_tenant() THEN RAISE EXCEPTION 'Untrusted relation validation source' USING ERRCODE='42501'; END IF;
 IF TG_RELID='public.assets'::regclass THEN
  IF TG_OP='INSERT' OR ROW(NEW.model_id,NEW.model_version,NEW.type_state) IS DISTINCT FROM ROW(OLD.model_id,OLD.model_version,OLD.type_state) THEN
   INSERT INTO public.relation_validation_work(tenant_id,transaction_id,relation_type_id)
   SELECT tenant,pg_current_xact_id(),t.type_id FROM public.relation_types t JOIN public.relation_type_versions v
    ON v.tenant_id=t.tenant_id AND v.relation_type_id=t.type_id AND v.version=t.current_version
   WHERE t.tenant_id=tenant AND (public.gc_relation_endpoint_eligible(tenant,NEW.id,v.definition,'source')
    OR public.gc_relation_endpoint_eligible(tenant,NEW.id,v.definition,'target')
    OR EXISTS(SELECT 1 FROM public.relations r WHERE r.tenant_id=tenant AND r.relation_type_id=t.type_id AND r.status='active' AND NEW.id IN(r.source_asset_id,r.target_asset_id))
    OR EXISTS(SELECT 1 FROM public.relation_participations p WHERE p.tenant_id=tenant AND p.relation_type_id=t.type_id AND p.asset_id=NEW.id AND p.status='active'))
   ON CONFLICT DO NOTHING;
  END IF;
 ELSIF TG_RELID IN ('public.relations'::regclass,'public.relation_type_versions'::regclass,'public.relation_participations'::regclass) THEN
  type_identity:=NEW.relation_type_id;
 ELSIF TG_RELID='public.relation_types'::regclass THEN type_identity:=NEW.type_id;
 ELSE RAISE EXCEPTION 'Untrusted relation validation source' USING ERRCODE='42501'; END IF;
 IF type_identity IS NOT NULL THEN
  INSERT INTO public.relation_validation_work(tenant_id,transaction_id,relation_type_id) VALUES(tenant,pg_current_xact_id(),type_identity) ON CONFLICT DO NOTHING;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER relation_endpoint_validation_enqueue ON public.assets;
CREATE TRIGGER relation_endpoint_validation_enqueue AFTER INSERT OR UPDATE ON public.assets FOR EACH ROW EXECUTE FUNCTION public.gc_relation_enqueue();
CREATE TRIGGER participation_validation_enqueue AFTER INSERT OR UPDATE ON public.relation_participations FOR EACH ROW EXECUTE FUNCTION public.gc_relation_enqueue();

CREATE FUNCTION public.gc_relation_policy_changes(before_definition jsonb,after_definition jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT coalesce(jsonb_agg(code ORDER BY code COLLATE "C"),'[]') FROM (VALUES
  ('direction','direction_changed'),('sourceTypes','source_types_changed'),('targetTypes','target_types_changed'),
  ('sourceStates','source_states_changed'),('targetStates','target_states_changed'),('cardinality','cardinality_changed'),
  ('allowSelf','self_policy_changed'),('cycles','cycles_changed'),('requiredOwner','required_owner_changed'),('lifecycle','lifecycle_changed')) fields(field,code)
 WHERE before_definition IS NOT NULL AND before_definition->field IS DISTINCT FROM after_definition->field
$$;
CREATE FUNCTION public.gc_relation_graph_values_valid(value jsonb,definition jsonb,require_active_owner boolean) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE start_time timestamptz; end_time timestamptz;
BEGIN
 IF NOT public.gc_relation_keys(value,ARRAY['attributes','ownerId','state','validFrom','validTo','visibility','allowedIdentityIds'])
  OR NOT public.gc_relation_value_valid(jsonb_build_object('type','object','properties',definition->'attributes'),value->'attributes')
  OR jsonb_typeof(value->'state')<>'string' OR NOT definition->'lifecycle'->'states' @> jsonb_build_array(value->'state')
  OR (value->'ownerId'<>'null' AND NOT public.gc_relation_uuid_list(jsonb_build_array(value->'ownerId'),1))
  OR NOT public.gc_relation_uuid_list(value->'allowedIdentityIds',100) OR value->>'visibility' NOT IN ('tenant','restricted')
  OR (value->>'visibility'='tenant' AND value->'allowedIdentityIds'<>'[]')
  OR (value->>'visibility'='restricted' AND NOT value->'allowedIdentityIds' @> jsonb_build_array(public.gc_actor())) THEN RETURN false; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements_text(value->'allowedIdentityIds') e(id)
  WHERE NOT EXISTS(SELECT 1 FROM public.memberships m WHERE m.tenant_id=public.gc_tenant() AND m.identity_id=id::uuid)) THEN RETURN false; END IF;
 IF (definition->>'requiredOwner'='true' OR require_active_owner) AND value->'ownerId'<>'null' AND NOT EXISTS(
  SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id
  WHERE m.tenant_id=public.gc_tenant() AND m.identity_id=(value->>'ownerId')::uuid AND m.active AND i.active) THEN RETURN false; END IF;
 IF definition->>'requiredOwner'='true' AND value->'ownerId'='null' THEN RETURN false; END IF;
 IF value->'validFrom'<>'null' THEN
  IF jsonb_typeof(value->'validFrom')<>'string' THEN RETURN false; END IF;
  start_time:=(value->>'validFrom')::timestamptz;
  IF public.gc_relation_utc(start_time)<>value->>'validFrom' OR NOT isfinite(start_time) THEN RETURN false; END IF;
 END IF;
 IF value->'validTo'<>'null' THEN
  IF jsonb_typeof(value->'validTo')<>'string' THEN RETURN false; END IF;
  end_time:=(value->>'validTo')::timestamptz;
  IF public.gc_relation_utc(end_time)<>value->>'validTo' OR NOT isfinite(end_time) THEN RETURN false; END IF;
 END IF;
 RETURN start_time IS NULL OR end_time IS NULL OR start_time<end_time;
EXCEPTION WHEN invalid_text_representation OR datetime_field_overflow OR invalid_datetime_format THEN RETURN false;
END $$;
CREATE FUNCTION public.gc_relation_graph_source_history_valid(row_value public.relations) RETURNS boolean
LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
 SELECT row_value.provenance=jsonb_build_object('origin','asserted','source',jsonb_build_object('kind','manual','identityId',row_value.created_by),
  'authority','manual-assertion','precedence',NULL,'actorId',row_value.created_by,'assertedAt',public.gc_relation_utc(row_value.created_at),
  'ingestedAt',public.gc_relation_utc(row_value.created_at),'sourceObservedAt',NULL,'sourceVersion',NULL,'sourceRunId',NULL,'confidence',NULL)
 AND EXISTS(SELECT 1 FROM public.relation_revisions r
  JOIN public.asset_revisions s ON s.tenant_id=r.tenant_id AND s.asset_id=r.source_asset_id AND s.version=r.source_asset_version
  JOIN public.asset_revisions t ON t.tenant_id=r.tenant_id AND t.asset_id=r.target_asset_id AND t.version=r.target_asset_version
  JOIN public.governance_models sm ON sm.tenant_id=s.tenant_id AND sm.id=s.snapshot->>'modelId' AND sm.type_id IS NOT NULL
  JOIN public.governance_models tm ON tm.tenant_id=t.tenant_id AND tm.id=t.snapshot->>'modelId' AND tm.type_id IS NOT NULL
  JOIN public.asset_type_versions sv ON sv.tenant_id=sm.tenant_id AND sv.model_id=sm.id AND sv.version=(s.snapshot->>'modelVersion')::integer
  JOIN public.asset_type_versions tv ON tv.tenant_id=tm.tenant_id AND tv.model_id=tm.id AND tv.version=(t.snapshot->>'modelVersion')::integer
  WHERE r.tenant_id=row_value.tenant_id AND r.relation_id=row_value.id AND r.version=row_value.version
   AND r.recorded_by=row_value.updated_by AND r.recorded_at=row_value.updated_at
   AND r.source_asset_id=row_value.source_asset_id AND r.target_asset_id=row_value.target_asset_id
   AND s.snapshot->>'id'=s.asset_id::text AND s.snapshot->>'version'=s.version::text
   AND t.snapshot->>'id'=t.asset_id::text AND t.snapshot->>'version'=t.version::text
   AND jsonb_typeof(s.snapshot->'name')='string' AND jsonb_typeof(s.snapshot->'typeState')='string'
   AND (sv.resolved->'lifecycle'->'states') @> (s.snapshot->'typeState')
   AND jsonb_typeof(t.snapshot->'name')='string' AND jsonb_typeof(t.snapshot->'typeState')='string'
   AND (tv.resolved->'lifecycle'->'states') @> (t.snapshot->'typeState')
   AND r.snapshot=public.gc_relation_snapshot_base(row_value)||jsonb_build_object(
    'source',jsonb_build_object('assetId',s.asset_id,'name',s.snapshot->'name','assetVersion',s.version,'typeId',sm.type_id,
     'modelId',s.snapshot->'modelId','modelVersion',s.snapshot->'modelVersion','state',s.snapshot->'typeState'),
    'target',jsonb_build_object('assetId',t.asset_id,'name',t.snapshot->'name','assetVersion',t.version,'typeId',tm.type_id,
     'modelId',t.snapshot->'modelId','modelVersion',t.snapshot->'modelVersion','state',t.snapshot->'typeState')))
$$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_source_history_valid(public.relations) FROM PUBLIC,gc_app;

CREATE FUNCTION public.gc_relation_graph_install_edges(p_operation_id uuid,type_claim public.relation_graph_operation_type_claims) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE row_value public.relations; disposition jsonb; proposed jsonb; before_tuple jsonb; after_tuple jsonb;
 source_version integer; target_version integer; after_source integer; after_target integer; policy jsonb; target_policy jsonb;
 target_pin integer; action text; key jsonb; source_pin_versions jsonb; transform jsonb; override jsonb; mapped jsonb;
 creation jsonb; new_id uuid; replaced boolean; request jsonb; tenant uuid:=public.gc_tenant();
BEGIN
 SELECT jsonb_build_object('changeSet',normalized_change_set) INTO request FROM public.relation_graph_operations WHERE tenant_id=tenant AND id=p_operation_id AND transaction_id=pg_current_xact_id() AND state='open';
 IF request IS NULL THEN RAISE EXCEPTION 'A live protected operation is required' USING ERRCODE='42501'; END IF;
 IF type_claim.mode<>'validation' THEN
  IF (SELECT coalesce(jsonb_agg(id ORDER BY id),'[]') FROM public.relations WHERE tenant_id=tenant AND relation_type_id=type_claim.relation_type_id AND status='active')
   IS DISTINCT FROM (SELECT coalesce(jsonb_agg(v->'relationId' ORDER BY v->>'relationId'),'[]') FROM jsonb_array_elements(type_claim.plan->'edges') e(v)) THEN
   RAISE EXCEPTION 'Every live edge requires one exact disposition' USING ERRCODE='23514'; END IF;
 END IF;
 transform:=type_claim.plan->'transform';
 FOR row_value IN SELECT * FROM public.relations WHERE tenant_id=tenant AND relation_type_id=type_claim.relation_type_id AND status='active' ORDER BY id LOOP
  SELECT v.definition INTO policy FROM public.relation_type_versions v WHERE v.tenant_id=tenant AND v.relation_type_id=row_value.relation_type_id AND v.version=row_value.relation_type_version;
  SELECT from_version,to_version INTO source_version,after_source FROM public.relation_graph_operation_asset_claims WHERE tenant_id=tenant AND operation_id=p_operation_id AND asset_id=row_value.source_asset_id;
  SELECT from_version,to_version INTO target_version,after_target FROM public.relation_graph_operation_asset_claims WHERE tenant_id=tenant AND operation_id=p_operation_id AND asset_id=row_value.target_asset_id;
  IF source_version IS NULL OR target_version IS NULL THEN RAISE EXCEPTION 'Incomplete endpoint scope' USING ERRCODE='23514'; END IF;
  key:=jsonb_build_object('kind','existing','relationId',row_value.id);
  before_tuple:=jsonb_build_object('key',key,'version',row_value.version,'relationTypeId',row_value.relation_type_id,'relationTypeVersion',row_value.relation_type_version,
   'sourceAssetId',row_value.source_asset_id,'sourceAssetVersion',source_version,'targetAssetId',row_value.target_asset_id,'targetAssetVersion',target_version,
   'status','active','values',public.gc_relation_values(row_value));
  SELECT v INTO disposition FROM jsonb_array_elements(coalesce(type_claim.plan->'edges','[]')) e(v) WHERE v->>'relationId'=row_value.id::text;
  IF type_claim.mode='validation' THEN disposition:=jsonb_build_object('relationId',row_value.id,'expectedVersion',row_value.version,'action','preserve'); END IF;
  IF (disposition->>'expectedVersion')::integer<>row_value.version THEN RAISE EXCEPTION 'Relation version conflict' USING ERRCODE='40001'; END IF;
  action:=disposition->>'action';target_pin:=row_value.relation_type_version;target_policy:=policy;proposed:=public.gc_relation_values(row_value);
  -- The only allowed source defect is a real inactive required owner. All other
  -- values and the current immutable revision remain independently checked.
  IF NOT public.gc_relation_graph_values_valid(proposed,policy||jsonb_build_object('requiredOwner',false),false)
   OR (policy->>'requiredOwner'='true' AND row_value.owner_id IS NULL)
   OR NOT public.gc_relation_graph_source_history_valid(row_value) THEN
   RAISE EXCEPTION 'Stored relation source is inconsistent' USING ERRCODE='23514'; END IF;
  IF action='migrate' THEN
   IF type_claim.mode<>'publish' OR transform IS NULL OR transform='null' THEN RAISE EXCEPTION 'Migration requires an explicit publication transform' USING ERRCODE='23514'; END IF;
   target_pin:=type_claim.after_version;target_policy:=type_claim.after_definition;
   SELECT v->'ownerId' INTO override FROM jsonb_array_elements(transform->'owner'->'overrides') e(v) WHERE v->>'relationId'=row_value.id::text;
   SELECT v->'to' INTO mapped FROM jsonb_array_elements(transform->'lifecycle'->'mappings') e(v)
    WHERE (v->>'sourceVersion')::integer=row_value.relation_type_version AND v->>'from'=row_value.state;
   IF mapped IS NULL AND transform->'lifecycle'->>'onUnmapped'='error' THEN RAISE EXCEPTION 'Unmapped relation lifecycle' USING ERRCODE='23514'; END IF;
   proposed:=proposed||jsonb_build_object('attributes',public.gc_relation_attribute_transform(public.gc_relation_model(type_claim.before_definition),public.gc_relation_model(policy),public.gc_relation_model(target_policy),transform->'attributes',row_value.attributes),
    'ownerId',coalesce(override,to_jsonb(row_value.owner_id),'null'),'state',coalesce(mapped,to_jsonb(row_value.state)));
   action:='repin';
  ELSIF action IN ('repair','repin') THEN
   proposed:=disposition->'values';
   IF action='repin' THEN
    IF (disposition->>'targetVersion')::integer<>type_claim.after_version THEN RAISE EXCEPTION 'Repin must target the operation head' USING ERRCODE='23514'; END IF;
    target_pin:=type_claim.after_version;target_policy:=type_claim.after_definition;
   END IF;
  ELSIF action IN ('tombstone','replace') THEN action:='tombstone';
  ELSIF action<>'preserve' THEN RAISE EXCEPTION 'Invalid relation disposition' USING ERRCODE='23514'; END IF;
  IF action<>'tombstone' AND NOT public.gc_relation_graph_values_valid(proposed,target_policy,action<>'preserve') THEN
   RAISE EXCEPTION 'Relation outcome violates its exact target policy' USING ERRCODE='23514'; END IF;
  IF type_claim.mode='publish' AND action<>'tombstone' AND NOT public.gc_relation_graph_values_valid(proposed,type_claim.after_definition,action<>'preserve') THEN
   RAISE EXCEPTION 'A retained source pin must remain compatible with publication own-value policy' USING ERRCODE='23514'; END IF;
  after_tuple:=before_tuple||jsonb_build_object('version',row_value.version+CASE WHEN action='preserve' THEN 0 ELSE 1 END,
   'relationTypeVersion',target_pin,'values',proposed,'status',CASE WHEN action='tombstone' THEN 'tombstoned' ELSE 'active' END,
   'sourceAssetVersion',CASE WHEN action='tombstone' THEN source_version ELSE after_source END,
   'targetAssetVersion',CASE WHEN action='tombstone' THEN target_version ELSE after_target END);
  PERFORM public.gc_relation_graph_charge(p_operation_id,jsonb_build_object('before',before_tuple,'after',after_tuple,'row',row_value));
  INSERT INTO public.relation_graph_operation_edge_claims(tenant_id,operation_id,relation_id,relation_type_id,key,action,role,before_row,before_tuple,after_tuple,from_version,to_version,consumed)
  VALUES(tenant,p_operation_id,row_value.id,row_value.relation_type_id,key,action,CASE WHEN action='preserve' THEN 'validation-only' ELSE 'changed' END,
   to_jsonb(row_value),before_tuple,after_tuple,row_value.version,(after_tuple->>'version')::integer,action='preserve');
 END LOOP;
 FOR creation IN SELECT v FROM jsonb_array_elements(coalesce(type_claim.plan->'creations','[]')) e(v) ORDER BY v->>'key' COLLATE "C" LOOP
  IF NOT public.gc_relation_keys(creation,ARRAY['key','sourceAssetId','targetAssetId','sourceAssetVersion','targetAssetVersion','values'])
   OR jsonb_typeof(creation->'key') IS DISTINCT FROM 'string'
   OR NOT public.gc_relation_safe_id(creation->>'key')
   OR NOT public.gc_relation_uuid_list(jsonb_build_array(creation->'sourceAssetId'),1) OR NOT public.gc_relation_uuid_list(jsonb_build_array(creation->'targetAssetId'),1)
   OR NOT public.gc_relation_positive_integer(creation->'sourceAssetVersion') OR NOT public.gc_relation_positive_integer(creation->'targetAssetVersion') THEN RAISE EXCEPTION 'Invalid relation creation' USING ERRCODE='23514'; END IF;
  SELECT from_version,to_version INTO source_version,after_source FROM public.relation_graph_operation_asset_claims WHERE tenant_id=tenant AND operation_id=p_operation_id AND asset_id=(creation->>'sourceAssetId')::uuid;
  SELECT from_version,to_version INTO target_version,after_target FROM public.relation_graph_operation_asset_claims WHERE tenant_id=tenant AND operation_id=p_operation_id AND asset_id=(creation->>'targetAssetId')::uuid;
  IF source_version IS NULL OR target_version IS NULL OR source_version<>(creation->>'sourceAssetVersion')::integer OR target_version<>(creation->>'targetAssetVersion')::integer THEN
   RAISE EXCEPTION 'Creation endpoint version conflict' USING ERRCODE='40001'; END IF;
  SELECT EXISTS(SELECT 1 FROM jsonb_array_elements(type_claim.plan->'edges') e(v) WHERE v->>'action'='replace' AND v->'creationKey'=creation->'key') INTO replaced;
  proposed:=creation->'values';
  IF NOT public.gc_relation_graph_values_valid(proposed,type_claim.after_definition,true)
   OR (NOT replaced AND proposed->'state' IS DISTINCT FROM type_claim.after_definition->'lifecycle'->'initial') THEN
   RAISE EXCEPTION 'Creation values violate their current policy' USING ERRCODE='23514'; END IF;
  new_id:=gen_random_uuid();key:=jsonb_build_object('kind','creation','relationTypeId',type_claim.relation_type_id,'key',creation->'key');
  after_tuple:=jsonb_build_object('key',key,'version',1,'relationTypeId',type_claim.relation_type_id,'relationTypeVersion',type_claim.after_version,
   'sourceAssetId',creation->'sourceAssetId','sourceAssetVersion',after_source,'targetAssetId',creation->'targetAssetId','targetAssetVersion',after_target,'status','active','values',proposed);
  PERFORM public.gc_relation_graph_charge(p_operation_id,after_tuple);
  INSERT INTO public.relation_graph_operation_edge_claims(tenant_id,operation_id,relation_id,relation_type_id,key,action,role,after_tuple,to_version)
  VALUES(tenant,p_operation_id,new_id,type_claim.relation_type_id,key,'create','changed',after_tuple,1);
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_install_edges(uuid,public.relation_graph_operation_type_claims) FROM PUBLIC,gc_app;

CREATE OR REPLACE FUNCTION public.gc_relation_mutation_fence() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant(); op public.relation_graph_operations;
BEGIN
 IF tenant IS NULL OR TG_TABLE_SCHEMA<>'public' OR TG_RELID NOT IN
  ('public.assets'::regclass,'public.asset_revisions'::regclass,'public.governance_models'::regclass,
   'public.governance_model_versions'::regclass,'public.asset_type_versions'::regclass,
   'public.relation_types'::regclass,'public.relation_type_versions'::regclass,'public.relations'::regclass,
   'public.relation_participations'::regclass,'public.relation_participation_revisions'::regclass,
   'public.relation_revisions'::regclass,'public.audit'::regclass,'public.outbox'::regclass) THEN
  RAISE EXCEPTION 'A scoped canonical relation mutation is required' USING ERRCODE='42501';
 END IF;
 op:=public.gc_relation_graph_current();
 IF op.id IS NOT NULL AND op.state<>'open' THEN RAISE EXCEPTION 'A sealed graph operation cannot write further canonical or journal data' USING ERRCODE='23514'; END IF;
 IF TG_RELID IN ('public.audit'::regclass,'public.outbox'::regclass) THEN RETURN NULL; END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended(tenant::text,0)) THEN
  RAISE EXCEPTION 'Canonical mutation requires a stable tenant execution window' USING ERRCODE='55P03';
 END IF;
 -- The write also rejects an old Repeatable Read snapshot after another writer.
 -- Conservative statement-level bumps are opaque and roll back with all writes.
 INSERT INTO public.tenant_graph_revisions(tenant_id,revision) VALUES(tenant,0) ON CONFLICT(tenant_id) DO NOTHING;
 UPDATE public.tenant_graph_revisions SET revision=revision+1 WHERE tenant_id=tenant AND revision<9223372036854775807;
 IF NOT FOUND THEN RAISE EXCEPTION 'Graph mutation fence is unavailable' USING ERRCODE='23514'; END IF;
 RETURN NULL;
END $$;
CREATE OR REPLACE FUNCTION public.gc_relation_publication_principals(type_identity uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE requested uuid[]; live_count bigint;
BEGIN
 IF (public.gc_relation_graph_current()).id IS NOT NULL THEN RETURN; END IF;
 SELECT count(*),array_agg(DISTINCT owner_id ORDER BY owner_id) FILTER (WHERE owner_id IS NOT NULL)
 INTO live_count,requested FROM public.relations WHERE tenant_id=public.gc_tenant() AND relation_type_id=type_identity AND status='active';
 IF live_count>1000 THEN RAISE EXCEPTION 'RELATION_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 -- Actor is added inside the reviewed function. Do not lock it separately before
 -- lower UUID owners: all global identities precede all tenant memberships.
 PERFORM public.gc_lock_type_migration_principals(coalesce(requested,ARRAY[]::uuid[]));
END $$;
CREATE OR REPLACE FUNCTION public.gc_relation_row_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.relation_graph_operations; claim public.relation_graph_operation_edge_claims; definition jsonb; expected_provenance jsonb; requested uuid[];
BEGIN

 op:=public.gc_relation_graph_current();
 IF op.id IS NOT NULL THEN
  PERFORM public.gc_relation_authorize(ARRAY['models:read','models:write','catalog:read','catalog:write']);
  SELECT * INTO claim FROM public.relation_graph_operation_edge_claims c WHERE c.tenant_id=NEW.tenant_id AND c.operation_id=op.id AND c.relation_id=NEW.id;
  IF op.state<>'open' OR op.actor_id::text<>public.gc_actor() OR claim.operation_id IS NULL OR claim.consumed
   OR NEW.updated_by<>op.actor_id OR NEW.updated_at<>date_trunc('milliseconds',NEW.updated_at)
   OR NEW.version<>claim.to_version OR NEW.relation_type_id<>claim.relation_type_id
   OR NEW.relation_type_version<>(claim.after_tuple->>'relationTypeVersion')::integer
   OR NEW.source_asset_id<>(claim.after_tuple->>'sourceAssetId')::uuid OR NEW.target_asset_id<>(claim.after_tuple->>'targetAssetId')::uuid
   OR NEW.status<>claim.after_tuple->>'status' OR public.gc_relation_values(NEW) IS DISTINCT FROM claim.after_tuple->'values' THEN
   RAISE EXCEPTION 'Canonical relation does not match its unconsumed protected claim' USING ERRCODE='23514'; END IF;
  IF TG_OP='UPDATE' THEN
   IF claim.before_row IS DISTINCT FROM to_jsonb(OLD) OR OLD.status<>'active'
    OR ROW(NEW.tenant_id,NEW.id,NEW.relation_type_id,NEW.source_asset_id,NEW.target_asset_id,NEW.created_by,NEW.created_at,NEW.provenance)
     IS DISTINCT FROM ROW(OLD.tenant_id,OLD.id,OLD.relation_type_id,OLD.source_asset_id,OLD.target_asset_id,OLD.created_by,OLD.created_at,OLD.provenance)
    OR NEW.updated_at<OLD.updated_at THEN RAISE EXCEPTION 'Claimed mutation must preserve immutable identity and actual before values' USING ERRCODE='23514'; END IF;
  ELSIF claim.before_row IS NOT NULL OR claim.action<>'create' OR NEW.created_by<>op.actor_id OR NEW.created_by<>NEW.updated_by
   OR NEW.created_at<>NEW.updated_at OR NEW.created_at<>date_trunc('milliseconds',NEW.created_at)
   OR NEW.provenance IS DISTINCT FROM jsonb_build_object('origin','asserted','source',jsonb_build_object('kind','manual','identityId',NEW.created_by),
     'authority','manual-assertion','precedence',NULL,'actorId',NEW.created_by,'assertedAt',public.gc_relation_utc(NEW.created_at),
     'ingestedAt',public.gc_relation_utc(NEW.created_at),'sourceObservedAt',NULL,'sourceVersion',NULL,'sourceRunId',NULL,'confidence',NULL) THEN
   RAISE EXCEPTION 'Claimed assertion needs its actual creation provenance' USING ERRCODE='23514'; END IF;
  UPDATE public.relation_graph_operation_edge_claims SET consumed=true WHERE tenant_id=NEW.tenant_id AND operation_id=op.id AND relation_id=NEW.id;
  RETURN NEW;
 END IF;
 requested:=array_remove(ARRAY[NEW.owner_id,CASE WHEN TG_OP='UPDATE' THEN OLD.owner_id ELSE NULL END],NULL);
 PERFORM public.gc_lock_type_migration_principals(requested);
 PERFORM public.gc_relation_authorize(ARRAY['catalog:read','catalog:write','models:read']);
 IF NEW.updated_by::text IS DISTINCT FROM public.gc_actor() OR NEW.updated_at<>date_trunc('milliseconds',NEW.updated_at)
  OR NEW.created_at<>date_trunc('milliseconds',NEW.created_at) THEN
  RAISE EXCEPTION 'Relation mutation attribution must match its authenticated actor' USING ERRCODE='23514'; END IF;
 SELECT v.definition INTO definition FROM public.relation_type_versions v
  WHERE v.tenant_id=NEW.tenant_id AND v.relation_type_id=NEW.relation_type_id AND v.version=NEW.relation_type_version;
 IF definition IS NULL THEN RAISE EXCEPTION 'Relation type is unavailable' USING ERRCODE='23503'; END IF;
 IF (definition->>'direction'='undirected' AND NEW.source_asset_id>NEW.target_asset_id)
  OR (definition->>'allowSelf'='false' AND NEW.source_asset_id=NEW.target_asset_id)
  OR NOT definition->'lifecycle'->'states' @> to_jsonb(NEW.state)
  OR NOT public.gc_relation_value_valid(jsonb_build_object('type','object','properties',definition->'attributes'),NEW.attributes)
  OR (NEW.visibility='restricted' AND NOT NEW.allowed_identities @> jsonb_build_array(public.gc_actor())) THEN
  RAISE EXCEPTION 'Relation fields violate their pinned definition or visibility' USING ERRCODE='23514'; END IF;
 IF (definition->>'requiredOwner'='true' OR (NEW.owner_id IS NOT NULL AND (TG_OP='INSERT' OR NEW.owner_id IS DISTINCT FROM OLD.owner_id)))
  AND (NEW.owner_id IS NULL OR NOT EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id
   WHERE m.tenant_id=NEW.tenant_id AND m.identity_id=NEW.owner_id AND m.active AND i.active)) THEN
  RAISE EXCEPTION 'Relation owner must be an active tenant member' USING ERRCODE='23514'; END IF;
 expected_provenance:=jsonb_build_object('origin','asserted','source',jsonb_build_object('kind','manual','identityId',NEW.created_by),
  'authority','manual-assertion','precedence',NULL,'actorId',NEW.created_by,'assertedAt',public.gc_relation_utc(NEW.created_at),
  'ingestedAt',public.gc_relation_utc(NEW.created_at),'sourceObservedAt',NULL,'sourceVersion',NULL,'sourceRunId',NULL,'confidence',NULL);
 IF NEW.provenance IS DISTINCT FROM expected_provenance THEN
  RAISE EXCEPTION 'Asserted provenance must retain its actual actor and transaction time' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.version<>1 OR NEW.status<>'active' OR NEW.state<>definition->'lifecycle'->>'initial'
   OR NEW.created_by<>NEW.updated_by OR NEW.created_at<>NEW.updated_at
   OR NOT EXISTS(SELECT 1 FROM public.relation_types t WHERE t.tenant_id=NEW.tenant_id AND t.type_id=NEW.relation_type_id AND t.current_version=NEW.relation_type_version) THEN
   RAISE EXCEPTION 'New asserted relation requires the current type and initial lifecycle state' USING ERRCODE='23514'; END IF;
 ELSE
  IF OLD.status='tombstoned' OR ROW(NEW.tenant_id,NEW.id,NEW.relation_type_id,NEW.relation_type_version,NEW.source_asset_id,NEW.target_asset_id,NEW.created_by,NEW.created_at,NEW.provenance)
   IS DISTINCT FROM ROW(OLD.tenant_id,OLD.id,OLD.relation_type_id,OLD.relation_type_version,OLD.source_asset_id,OLD.target_asset_id,OLD.created_by,OLD.created_at,OLD.provenance)
   OR NEW.version::bigint<>OLD.version::bigint+1 OR NEW.updated_at<OLD.updated_at THEN
   RAISE EXCEPTION 'Relation identity, pins and tombstones are immutable; versions advance by one' USING ERRCODE='23514'; END IF;
  IF NEW.status='tombstoned' AND ROW(NEW.attributes,NEW.owner_id,NEW.state,NEW.valid_from,NEW.valid_to,NEW.visibility,NEW.allowed_identities)
   IS DISTINCT FROM ROW(OLD.attributes,OLD.owner_id,OLD.state,OLD.valid_from,OLD.valid_to,OLD.visibility,OLD.allowed_identities) THEN
   RAISE EXCEPTION 'Tombstone cannot rewrite relation values' USING ERRCODE='23514'; END IF;
  IF NEW.state<>OLD.state AND (NEW.status<>'active'
   OR NOT definition->'lifecycle'->'transitions' @> jsonb_build_array(jsonb_build_object('from',OLD.state,'to',NEW.state))
   OR ROW(NEW.attributes,NEW.owner_id,NEW.valid_from,NEW.valid_to,NEW.visibility,NEW.allowed_identities)
    IS DISTINCT FROM ROW(OLD.attributes,OLD.owner_id,OLD.valid_from,OLD.valid_to,OLD.visibility,OLD.allowed_identities)) THEN
   RAISE EXCEPTION 'Relation lifecycle changes require one legal pinned transition' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION public.gc_relation_revision_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.relation_graph_operations; claim public.relation_graph_operation_edge_claims; parent public.relations; expected jsonb; source_version integer; target_version integer;
BEGIN
 SELECT * INTO parent FROM public.relations WHERE tenant_id=NEW.tenant_id AND id=NEW.relation_id;
 IF parent IS NULL OR NEW.version<>parent.version OR NEW.recorded_by<>parent.updated_by OR NEW.recorded_at<>parent.updated_at
  OR NEW.recorded_by::text IS DISTINCT FROM public.gc_actor() THEN
  RAISE EXCEPTION 'Relation revision must record its current canonical mutation' USING ERRCODE='23514'; END IF;
 source_version:=(NEW.snapshot->'source'->>'assetVersion')::integer;target_version:=(NEW.snapshot->'target'->>'assetVersion')::integer;
 op:=public.gc_relation_graph_current();
 IF op.id IS NOT NULL THEN
  SELECT * INTO claim FROM public.relation_graph_operation_edge_claims c WHERE c.tenant_id=NEW.tenant_id AND c.operation_id=op.id AND c.relation_id=NEW.relation_id;
  IF op.state<>'open' OR claim.operation_id IS NULL OR NOT claim.consumed OR claim.action='preserve' OR claim.to_version<>NEW.version
   OR source_version<>(claim.after_tuple->>'sourceAssetVersion')::integer OR target_version<>(claim.after_tuple->>'targetAssetVersion')::integer THEN
   RAISE EXCEPTION 'Revision requires the exact consumed operation outcome' USING ERRCODE='23514'; END IF;
  IF claim.action='tombstone' THEN
   expected:=public.gc_relation_snapshot_base(parent)||jsonb_build_object(
    'source',public.gc_relation_endpoint_snapshot(NEW.tenant_id,parent.source_asset_id,source_version),
    'target',public.gc_relation_endpoint_snapshot(NEW.tenant_id,parent.target_asset_id,target_version));
   IF NEW.snapshot IS DISTINCT FROM expected THEN RAISE EXCEPTION 'Historical tombstone requires captured actual before endpoints' USING ERRCODE='23514'; END IF;
   RETURN NEW;
  END IF;
 END IF;

 IF NOT EXISTS(SELECT 1 FROM public.assets a WHERE a.tenant_id=NEW.tenant_id AND a.id=parent.source_asset_id AND a.version=source_version)
  OR NOT EXISTS(SELECT 1 FROM public.assets a WHERE a.tenant_id=NEW.tenant_id AND a.id=parent.target_asset_id AND a.version=target_version) THEN
  RAISE EXCEPTION 'Relation revision must capture actual current endpoint revisions' USING ERRCODE='23514'; END IF;
 expected:=public.gc_relation_snapshot_base(parent)||jsonb_build_object(
  'source',public.gc_relation_endpoint_snapshot(NEW.tenant_id,parent.source_asset_id,source_version),
  'target',public.gc_relation_endpoint_snapshot(NEW.tenant_id,parent.target_asset_id,target_version));
 IF EXISTS(SELECT 1 FROM public.assets a JOIN public.governance_models m ON m.tenant_id=a.tenant_id AND m.id=a.model_id
  CROSS JOIN LATERAL (SELECT CASE WHEN a.id=parent.source_asset_id THEN expected->'source' ELSE expected->'target' END AS endpoint) s
  WHERE a.tenant_id=NEW.tenant_id AND a.id IN (parent.source_asset_id,parent.target_asset_id)
   AND jsonb_build_object('assetId',a.id,'name',a.name,'assetVersion',a.version,'typeId',m.type_id,
    'modelId',a.model_id,'modelVersion',a.model_version,'state',a.type_state) IS DISTINCT FROM s.endpoint) THEN
  RAISE EXCEPTION 'Current endpoint values require their exact immutable asset revision' USING ERRCODE='23514'; END IF;
 IF NEW.snapshot IS DISTINCT FROM expected THEN RAISE EXCEPTION 'Relation snapshot must equal canonical values and real endpoint revisions' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;

DO $$ DECLARE name text; BEGIN
 FOREACH name IN ARRAY ARRAY['relation_participations','relation_participation_revisions','relation_revisions','audit','outbox'] LOOP
  EXECUTE format('CREATE TRIGGER relation_mutation_fence BEFORE INSERT OR UPDATE OR DELETE ON public.%I FOR EACH STATEMENT EXECUTE FUNCTION public.gc_relation_mutation_fence()',name);
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_row_guard(),public.gc_relation_revision_guard(),public.gc_relation_publication_principals(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_publication_principals(uuid) TO gc_app;

CREATE FUNCTION public.gc_relation_graph_asset_write_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.relation_graph_operations; claim public.relation_graph_operation_asset_claims;
BEGIN
 op:=public.gc_relation_graph_current(); IF op.id IS NULL THEN RETURN NEW; END IF;
 SELECT * INTO claim FROM public.relation_graph_operation_asset_claims c WHERE c.tenant_id=NEW.tenant_id AND c.operation_id=op.id AND c.asset_id=NEW.id;
 IF TG_OP<>'UPDATE' OR op.state<>'open' OR op.actor_id::text<>public.gc_actor() OR claim.operation_id IS NULL OR claim.consumed OR claim.action='preserve'
  OR public.gc_relation_graph_asset_row(OLD) IS DISTINCT FROM claim.before_row OR NEW.version<>claim.to_version
  OR public.gc_relation_asset_tuple(NEW) IS DISTINCT FROM claim.after_tuple
  OR (to_jsonb(NEW)-ARRAY['model_id','model_version','attributes','owner_id','type_state','version','updated_at'])
   IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['model_id','model_version','attributes','owner_id','type_state','version','updated_at'])
  OR NEW.updated_at<OLD.updated_at THEN RAISE EXCEPTION 'Asset write must equal its protected transformation claim' USING ERRCODE='23514'; END IF;
 UPDATE public.relation_graph_operation_asset_claims SET consumed=true WHERE tenant_id=NEW.tenant_id AND operation_id=op.id AND asset_id=NEW.id;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_asset_write_guard() FROM PUBLIC,gc_app;
CREATE TRIGGER graph_asset_claim_guard BEFORE INSERT OR UPDATE ON public.assets FOR EACH ROW EXECUTE FUNCTION public.gc_relation_graph_asset_write_guard();
CREATE FUNCTION public.gc_relation_graph_asset_revision_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.relation_graph_operations; claim public.relation_graph_operation_asset_claims; actual public.assets; expected jsonb;
BEGIN
 op:=public.gc_relation_graph_current(); IF op.id IS NULL THEN RETURN NEW; END IF;
 SELECT * INTO claim FROM public.relation_graph_operation_asset_claims c WHERE c.tenant_id=NEW.tenant_id AND c.operation_id=op.id AND c.asset_id=NEW.asset_id;
 IF op.state<>'open' OR NEW.tenant_id IS DISTINCT FROM op.tenant_id OR op.actor_id::text IS DISTINCT FROM public.gc_actor()
  OR claim.operation_id IS NULL OR claim.action='preserve' OR NOT claim.consumed OR NEW.version<>claim.to_version
  OR NOT public.gc_relation_json_bounded(NEW.snapshot,100000,32,524288) THEN
  RAISE EXCEPTION 'Asset revision requires the exact consumed graph change claim' USING ERRCODE='23514'; END IF;
 SELECT * INTO actual FROM public.assets a WHERE a.tenant_id=NEW.tenant_id AND a.id=NEW.asset_id;
 IF actual.id IS NULL OR actual.version<>claim.to_version OR public.gc_relation_asset_tuple(actual) IS DISTINCT FROM claim.after_tuple THEN
  RAISE EXCEPTION 'Asset revision must follow its actual claimed canonical write' USING ERRCODE='23514'; END IF;
 -- Exact production assetView for a canonical returned assets row. Display joins
 -- are absent from this write path; no caller-provided name or native metadata is trusted.
 expected:=jsonb_build_object('id',actual.id,'name',actual.name,'qualifiedName',actual.qualified_name,'type',actual.type,
  'description',actual.description,'ownerId',actual.owner_id,'ownerName',NULL,'sourceId',actual.source_id,'sourceName',NULL,
  'version',actual.version,'observedAt',public.gc_relation_utc(actual.observed_at),'updatedAt',public.gc_relation_utc(actual.updated_at),
  'status',actual.status,'metadata',actual.metadata,'modelId',actual.model_id,'modelVersion',actual.model_version,
  'attributes',actual.attributes,'typeState',actual.type_state);
 PERFORM public.gc_relation_graph_charge(op.id,expected);
 IF NEW.snapshot IS DISTINCT FROM expected THEN RAISE EXCEPTION 'Asset revision must equal the complete actual canonical snapshot' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_asset_revision_guard() FROM PUBLIC,gc_app;
CREATE TRIGGER graph_asset_revision_claim_guard BEFORE INSERT ON public.asset_revisions FOR EACH ROW EXECUTE FUNCTION public.gc_relation_graph_asset_revision_guard();
CREATE FUNCTION public.gc_relation_participation_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.relation_graph_operations; claim public.relation_graph_operation_binding_claims;
BEGIN
 op:=public.gc_relation_graph_current();
 SELECT * INTO claim FROM public.relation_graph_operation_binding_claims c WHERE c.tenant_id=NEW.tenant_id AND c.operation_id=op.id AND c.binding_id=NEW.id;
 IF op.id IS NULL OR op.state<>'open' OR op.actor_id::text<>public.gc_actor() OR claim.operation_id IS NULL OR claim.consumed
  OR NEW.updated_by<>op.actor_id OR NEW.version<>claim.to_version
  OR NEW.relation_type_id<>claim.relation_type_id OR NEW.relation_type_version<>(claim.after_tuple->>'relationTypeVersion')::integer
  OR NEW.asset_id<>(claim.after_tuple->>'assetId')::uuid OR NEW.asset_version<>(claim.after_tuple->>'assetVersion')::integer
  OR NEW.side<>claim.after_tuple->>'side' OR NEW.status<>claim.after_tuple->>'status'
  OR NEW.created_at<>date_trunc('milliseconds',NEW.created_at) OR NEW.updated_at<>date_trunc('milliseconds',NEW.updated_at) THEN
  RAISE EXCEPTION 'Participation write requires its exact protected claim' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF claim.action<>'enroll' OR claim.before_row IS NOT NULL OR NEW.created_by<>op.actor_id OR NEW.created_at<>NEW.updated_at THEN
   RAISE EXCEPTION 'Enrollment must preserve its actual attribution' USING ERRCODE='23514'; END IF;
 ELSIF claim.before_row IS DISTINCT FROM to_jsonb(OLD) OR OLD.status<>'active'
  OR ROW(NEW.tenant_id,NEW.id,NEW.relation_type_id,NEW.asset_id,NEW.side,NEW.created_by,NEW.created_at)
   IS DISTINCT FROM ROW(OLD.tenant_id,OLD.id,OLD.relation_type_id,OLD.asset_id,OLD.side,OLD.created_by,OLD.created_at)
  OR NEW.updated_at<OLD.updated_at THEN RAISE EXCEPTION 'Participation identity and released history are immutable' USING ERRCODE='23514'; END IF;
 UPDATE public.relation_graph_operation_binding_claims SET consumed=true WHERE tenant_id=NEW.tenant_id AND operation_id=op.id AND binding_id=NEW.id;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_participation_guard() FROM PUBLIC,gc_app;
CREATE TRIGGER participation_guard BEFORE INSERT OR UPDATE ON public.relation_participations FOR EACH ROW EXECUTE FUNCTION public.gc_relation_participation_guard();
CREATE FUNCTION public.gc_relation_participation_revision_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.relation_graph_operations; parent public.relation_participations; claim public.relation_graph_operation_binding_claims;
BEGIN
 op:=public.gc_relation_graph_current();
 SELECT * INTO parent FROM public.relation_participations WHERE tenant_id=NEW.tenant_id AND id=NEW.binding_id;
 SELECT * INTO claim FROM public.relation_graph_operation_binding_claims c WHERE c.tenant_id=NEW.tenant_id AND c.operation_id=op.id AND c.binding_id=NEW.binding_id;
 IF op.id IS NULL OR op.state<>'open' OR NEW.operation_id<>op.id OR claim.operation_id IS NULL OR NOT claim.consumed OR claim.action='preserve'
  OR parent IS NULL OR NEW.version<>parent.version OR NEW.recorded_by<>parent.updated_by OR NEW.recorded_at<>parent.updated_at
  OR NEW.snapshot IS DISTINCT FROM public.gc_relation_binding_snapshot(parent) THEN
  RAISE EXCEPTION 'Binding revision must capture the exact claimed canonical outcome' USING ERRCODE='23514'; END IF;
 IF parent.status='active' AND NOT EXISTS(SELECT 1 FROM public.assets a WHERE a.tenant_id=NEW.tenant_id AND a.id=parent.asset_id AND a.version=parent.asset_version) THEN
  RAISE EXCEPTION 'Active binding must reference the actual final asset revision' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_participation_revision_guard() FROM PUBLIC,gc_app;
CREATE TRIGGER participation_revision_guard BEFORE INSERT ON public.relation_participation_revisions FOR EACH ROW EXECUTE FUNCTION public.gc_relation_participation_revision_guard();
CREATE FUNCTION public.gc_relation_participation_complete() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.relation_graph_operations; action text;
BEGIN
 op:=public.gc_relation_graph_current();
 action:=CASE WHEN TG_OP='INSERT' THEN 'relation_participation.enrolled' WHEN NEW.status='released' THEN 'relation_participation.released' ELSE 'relation_participation.repinned' END;
 IF op.id IS NULL OR NOT EXISTS(SELECT 1 FROM public.relation_participation_revisions r WHERE r.tenant_id=NEW.tenant_id AND r.binding_id=NEW.id
  AND r.version=NEW.version AND r.operation_id=op.id AND r.snapshot=public.gc_relation_binding_snapshot(NEW))
  OR NOT public.gc_relation_graph_journal(action,NEW.id::text,NEW.version,NEW.updated_by,op.correlation_id) THEN
  RAISE EXCEPTION 'Binding mutation requires immutable history and paired journals' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_participation_complete() FROM PUBLIC,gc_app;
CREATE CONSTRAINT TRIGGER participation_complete AFTER INSERT OR UPDATE ON public.relation_participations
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_relation_participation_complete();

CREATE FUNCTION public.gc_relation_graph_install_bindings(selected_operation uuid,type_claim public.relation_graph_operation_type_claims) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant(); old_binding public.relation_participations; asset_claim public.relation_graph_operation_asset_claims;
 disposition jsonb; before_tuple jsonb; after_tuple jsonb; endpoint jsonb; request jsonb; action text; selected_side text;
 required_min integer; new_id uuid; key jsonb; eligible boolean;
BEGIN
 SELECT jsonb_build_object('changeSet',o.normalized_change_set) INTO request FROM public.relation_graph_operations o WHERE o.tenant_id=tenant AND o.id=selected_operation AND o.transaction_id=pg_current_xact_id() AND o.state='open';
 IF request IS NULL THEN RAISE EXCEPTION 'Binding claims require a live protected operation' USING ERRCODE='42501'; END IF;
 IF type_claim.mode<>'validation' AND
  (SELECT coalesce(jsonb_agg(p.id ORDER BY p.id),'[]') FROM public.relation_participations p WHERE p.tenant_id=tenant AND p.relation_type_id=type_claim.relation_type_id AND p.status='active')
  IS DISTINCT FROM (SELECT coalesce(jsonb_agg(v->'bindingId' ORDER BY v->>'bindingId'),'[]') FROM jsonb_array_elements(type_claim.plan->'bindings') e(v)) THEN
  RAISE EXCEPTION 'Every active binding requires one exact disposition' USING ERRCODE='23514'; END IF;
 FOR old_binding IN SELECT * FROM public.relation_participations p WHERE p.tenant_id=tenant AND p.relation_type_id=type_claim.relation_type_id AND p.status='active' ORDER BY p.id LOOP
  SELECT * INTO asset_claim FROM public.relation_graph_operation_asset_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.asset_id=old_binding.asset_id;
  IF asset_claim.asset_id IS NULL OR NOT EXISTS(SELECT 1 FROM public.relation_participation_revisions r WHERE r.tenant_id=tenant AND r.binding_id=old_binding.id
   AND r.version=old_binding.version AND r.snapshot=public.gc_relation_binding_snapshot(old_binding)) THEN
   RAISE EXCEPTION 'Binding source requires actual immutable history' USING ERRCODE='23514'; END IF;
  endpoint:=public.gc_relation_graph_endpoint(asset_claim.asset_id,asset_claim.to_version,asset_claim.after_tuple,request);
  SELECT v INTO disposition FROM jsonb_array_elements(coalesce(type_claim.plan->'bindings','[]')) e(v) WHERE v->>'bindingId'=old_binding.id::text;
  IF type_claim.mode='validation' THEN disposition:=jsonb_build_object('bindingId',old_binding.id,'expectedVersion',old_binding.version,'action','preserve'); END IF;
  IF (disposition->>'expectedVersion')::integer<>old_binding.version THEN RAISE EXCEPTION 'Binding version conflict' USING ERRCODE='40001'; END IF;
  action:=disposition->>'action';key:=jsonb_build_object('kind','existing','bindingId',old_binding.id);
  before_tuple:=jsonb_build_object('key',key,'version',old_binding.version,'relationTypeId',old_binding.relation_type_id,
   'relationTypeVersion',old_binding.relation_type_version,'assetId',old_binding.asset_id,'assetVersion',asset_claim.from_version,'side',old_binding.side,'status','active');
  after_tuple:=before_tuple;
  IF action='repin' THEN
   IF (disposition->>'targetVersion')::integer<>type_claim.after_version THEN RAISE EXCEPTION 'Binding repin must select the operation head' USING ERRCODE='23514'; END IF;
   after_tuple:=after_tuple||jsonb_build_object('version',old_binding.version+1,'relationTypeVersion',type_claim.after_version,'assetVersion',asset_claim.to_version);
  ELSIF action='release' THEN
   eligible:=(type_claim.after_definition->>'direction'='undirected')=(old_binding.side='incident')
    AND public.gc_relation_projected_eligible(endpoint,type_claim.after_definition,CASE WHEN old_binding.side='incident' THEN 'source' ELSE old_binding.side END);
   required_min:=(type_claim.after_definition->'cardinality'->(CASE WHEN old_binding.side='target' THEN 'incoming' ELSE 'outgoing' END)->>'min')::integer;
   IF eligible AND required_min>0 THEN RAISE EXCEPTION 'Required eligible participation cannot be released' USING ERRCODE='23514'; END IF;
   after_tuple:=after_tuple||jsonb_build_object('version',old_binding.version+1,'status','released');
  ELSIF action<>'preserve' THEN RAISE EXCEPTION 'Invalid participation disposition' USING ERRCODE='23514';
  ELSE after_tuple:=after_tuple||jsonb_build_object('assetVersion',asset_claim.to_version); END IF;
  PERFORM public.gc_relation_graph_charge(selected_operation,jsonb_build_object('before',before_tuple,'after',after_tuple,'row',old_binding));
  INSERT INTO public.relation_graph_operation_binding_claims(tenant_id,operation_id,binding_id,relation_type_id,key,action,role,before_row,before_tuple,after_tuple,from_version,to_version,consumed)
  VALUES(tenant,selected_operation,old_binding.id,old_binding.relation_type_id,key,action,
   CASE WHEN action='preserve' THEN 'validation-only' ELSE 'changed' END,to_jsonb(old_binding),before_tuple,after_tuple,old_binding.version,(after_tuple->>'version')::integer,action='preserve');
 END LOOP;
 -- Derive every obligation from the full final asset candidates. The plan cannot
 -- make an enrollment optional by leaving an array element out.
 FOR asset_claim IN SELECT * FROM public.relation_graph_operation_asset_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation ORDER BY c.asset_id LOOP
  endpoint:=public.gc_relation_graph_endpoint(asset_claim.asset_id,asset_claim.to_version,asset_claim.after_tuple,request);
  FOR selected_side IN SELECT unnest(CASE WHEN type_claim.after_definition->>'direction'='undirected' THEN ARRAY['incident'] ELSE ARRAY['source','target'] END) LOOP
   required_min:=(type_claim.after_definition->'cardinality'->(CASE WHEN selected_side='target' THEN 'incoming' ELSE 'outgoing' END)->>'min')::integer;
   IF required_min=0 OR NOT public.gc_relation_projected_eligible(endpoint,type_claim.after_definition,CASE WHEN selected_side='incident' THEN 'source' ELSE selected_side END)
    OR EXISTS(SELECT 1 FROM public.relation_graph_operation_binding_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation
     AND c.relation_type_id=type_claim.relation_type_id AND c.after_tuple->>'assetId'=asset_claim.asset_id::text AND c.after_tuple->>'side'=selected_side
     AND c.after_tuple->>'status'='active') THEN CONTINUE; END IF;
   IF type_claim.mode='validation' THEN RAISE EXCEPTION 'Untargeted required enrollment needs an explicit graph target' USING ERRCODE='23514'; END IF;
   new_id:=gen_random_uuid();key:=jsonb_build_object('kind','enrollment','relationTypeId',type_claim.relation_type_id,'assetId',asset_claim.asset_id,'side',selected_side);
   after_tuple:=jsonb_build_object('key',key,'version',1,'relationTypeId',type_claim.relation_type_id,'relationTypeVersion',type_claim.after_version,
    'assetId',asset_claim.asset_id,'assetVersion',asset_claim.to_version,'side',selected_side,'status','active');
   PERFORM public.gc_relation_graph_charge(selected_operation,after_tuple);
   INSERT INTO public.relation_graph_operation_binding_claims(tenant_id,operation_id,binding_id,relation_type_id,key,action,role,after_tuple,to_version)
   VALUES(tenant,selected_operation,new_id,type_claim.relation_type_id,key,'enroll','changed',after_tuple,1);
  END LOOP;
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_install_bindings(uuid,public.relation_graph_operation_type_claims) FROM PUBLIC,gc_app;

CREATE FUNCTION public.gc_relation_graph_plan_shape(plan jsonb,mode text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE entry jsonb; action text; previous text; name text;
BEGIN
 IF NOT public.gc_relation_keys(plan,ARRAY['formatVersion','relationTypeId','sourceVersions','transform','edges','creations','bindings','enrollment','acknowledgedPolicyChanges'])
  OR plan->'formatVersion'<>'1' OR NOT public.gc_relation_uuid_list(jsonb_build_array(plan->'relationTypeId'),1)
  OR plan->>'enrollment' IS DISTINCT FROM 'complete-eligible-assets' OR mode IS NULL OR mode NOT IN ('create','publish','repair') THEN RETURN false; END IF;
 FOREACH name IN ARRAY ARRAY['sourceVersions','edges','creations','bindings','acknowledgedPolicyChanges'] LOOP
  IF jsonb_typeof(plan->name)<>'array' THEN RETURN false; END IF;
 END LOOP;
 IF jsonb_array_length(plan->'edges')>1000 OR jsonb_array_length(plan->'creations')>1000 OR jsonb_array_length(plan->'bindings')>4000 THEN RETURN false; END IF;
 FOR entry IN SELECT v FROM jsonb_array_elements(plan->'sourceVersions') e(v) LOOP
  IF jsonb_typeof(entry)<>'number' OR entry::text !~ '^[1-9][0-9]{0,9}$' OR entry::text::numeric>2147483647
   OR (previous IS NOT NULL AND previous::integer>=(entry::text)::integer) THEN RETURN false; END IF;
  previous:=entry::text;
 END LOOP;
 previous:=NULL;
 FOR entry IN SELECT v FROM jsonb_array_elements(plan->'edges') e(v) LOOP
  action:=entry->>'action';
  IF action IS NULL OR action NOT IN ('preserve','migrate','repair','repin','tombstone','replace') OR NOT public.gc_relation_keys(entry,
   CASE action WHEN 'repair' THEN ARRAY['relationId','expectedVersion','action','values'] WHEN 'repin' THEN ARRAY['relationId','expectedVersion','action','targetVersion','values']
    WHEN 'tombstone' THEN ARRAY['relationId','expectedVersion','action','reason'] WHEN 'replace' THEN ARRAY['relationId','expectedVersion','action','creationKey','reason']
    ELSE ARRAY['relationId','expectedVersion','action'] END)
   OR NOT public.gc_relation_uuid_list(jsonb_build_array(entry->'relationId'),1)
   OR jsonb_typeof(entry->'expectedVersion')<>'number' OR entry->>'expectedVersion' !~ '^[1-9][0-9]{0,9}$'
   OR (entry->>'expectedVersion')::numeric>2147483647
   OR (previous IS NOT NULL AND (entry->>'relationId') COLLATE "C"<=previous COLLATE "C")
   OR (action='migrate' AND mode<>'publish') THEN RETURN false; END IF;
  IF action IN ('tombstone','replace') AND (jsonb_typeof(entry->'reason')<>'string' OR char_length(entry->>'reason') NOT BETWEEN 1 AND 500 OR entry->>'reason' ~ '[[:cntrl:]]') THEN RETURN false; END IF;
  IF action='replace' AND (jsonb_typeof(entry->'creationKey') IS DISTINCT FROM 'string' OR public.gc_relation_safe_id(entry->>'creationKey') IS NOT TRUE) THEN RETURN false; END IF;
  IF action='repin' AND NOT public.gc_relation_positive_integer(entry->'targetVersion') THEN RETURN false; END IF;
  previous:=entry->>'relationId';
 END LOOP;
 previous:=NULL;
 FOR entry IN SELECT v FROM jsonb_array_elements(plan->'bindings') e(v) LOOP
  action:=entry->>'action';
  IF action IS NULL OR action NOT IN ('preserve','repin','release') OR NOT public.gc_relation_keys(entry,
   CASE action WHEN 'repin' THEN ARRAY['bindingId','expectedVersion','action','targetVersion'] WHEN 'release' THEN ARRAY['bindingId','expectedVersion','action','reason'] ELSE ARRAY['bindingId','expectedVersion','action'] END)
   OR NOT public.gc_relation_uuid_list(jsonb_build_array(entry->'bindingId'),1)
   OR jsonb_typeof(entry->'expectedVersion')<>'number' OR entry->>'expectedVersion' !~ '^[1-9][0-9]{0,9}$'
   OR (entry->>'expectedVersion')::numeric>2147483647
   OR (previous IS NOT NULL AND (entry->>'bindingId') COLLATE "C"<=previous COLLATE "C") THEN RETURN false; END IF;
  IF action='release' AND (jsonb_typeof(entry->'reason')<>'string' OR char_length(entry->>'reason') NOT BETWEEN 1 AND 500 OR entry->>'reason' ~ '[[:cntrl:]]') THEN RETURN false; END IF;
  IF action='repin' AND NOT public.gc_relation_positive_integer(entry->'targetVersion') THEN RETURN false; END IF;
  previous:=entry->>'bindingId';
 END LOOP;
 IF mode='create' AND (plan->'sourceVersions'<>'[]' OR plan->'edges'<>'[]' OR plan->'bindings'<>'[]') THEN RETURN false; END IF;
 IF (plan->'transform'<>'null') IS DISTINCT FROM EXISTS(SELECT 1 FROM jsonb_array_elements(plan->'edges') e(v) WHERE v->>'action'='migrate') THEN RETURN false; END IF;
 IF (SELECT count(*)<>count(DISTINCT v->>'key') FROM jsonb_array_elements(plan->'creations') e(v))
  OR (SELECT count(*)<>count(DISTINCT v->>'creationKey') FROM jsonb_array_elements(plan->'edges') e(v) WHERE v->>'action'='replace')
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(plan->'edges') e(v) WHERE v->>'action'='replace'
   AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(plan->'creations') c(item) WHERE item->'key'=v->'creationKey')) THEN RETURN false; END IF;
 RETURN true;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END $$;

-- Scalar discovery returns identities only. Complete authorization/count/byte
-- preflight runs over this relation before any unbounded cohort JSON is retained.
CREATE FUNCTION public.gc_relation_graph_candidate_types(selected_operation uuid) RETURNS TABLE(relation_type_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 WITH op AS (SELECT o.* FROM public.relation_graph_operations o WHERE o.tenant_id=public.gc_tenant() AND o.id=selected_operation AND o.transaction_id=pg_current_xact_id()),
 changed AS (SELECT a.id FROM public.assets a CROSS JOIN op WHERE a.tenant_id=op.tenant_id AND (
  EXISTS(SELECT 1 FROM jsonb_array_elements(op.normalized_change_set->'assetChanges') e(v) WHERE v->>'assetId'=a.id::text)
  OR EXISTS(SELECT 1 FROM public.relation_graph_operation_model_claims m WHERE m.tenant_id=op.tenant_id AND m.operation_id=op.id AND m.model_id=a.model_id)))
 SELECT c.relation_type_id FROM public.relation_graph_operation_type_claims c CROSS JOIN op WHERE c.tenant_id=op.tenant_id AND c.operation_id=op.id
 UNION SELECT t.type_id FROM public.relation_types t JOIN public.relation_type_versions v ON v.tenant_id=t.tenant_id AND v.relation_type_id=t.type_id AND v.version=t.current_version
  CROSS JOIN op WHERE t.tenant_id=op.tenant_id AND EXISTS(SELECT 1 FROM changed ids JOIN public.assets a ON a.tenant_id=op.tenant_id AND a.id=ids.id WHERE
   public.gc_relation_endpoint_eligible(op.tenant_id,a.id,v.definition,'source') OR public.gc_relation_endpoint_eligible(op.tenant_id,a.id,v.definition,'target')
   OR public.gc_relation_projected_eligible(public.gc_relation_graph_project_endpoint(a,jsonb_build_object('changeSet',op.normalized_change_set)),v.definition,'source')
   OR public.gc_relation_projected_eligible(public.gc_relation_graph_project_endpoint(a,jsonb_build_object('changeSet',op.normalized_change_set)),v.definition,'target')
   OR EXISTS(SELECT 1 FROM public.relations r WHERE r.tenant_id=op.tenant_id AND r.relation_type_id=t.type_id AND r.status='active' AND a.id IN(r.source_asset_id,r.target_asset_id))
   OR EXISTS(SELECT 1 FROM public.relation_participations b WHERE b.tenant_id=op.tenant_id AND b.relation_type_id=t.type_id AND b.status='active' AND b.asset_id=a.id))
$$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_candidate_types(uuid) FROM PUBLIC,gc_app;
CREATE FUNCTION public.gc_relation_graph_candidate_assets(selected_operation uuid) RETURNS TABLE(asset_id uuid,action text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 WITH op AS (SELECT o.* FROM public.relation_graph_operations o WHERE o.tenant_id=public.gc_tenant() AND o.id=selected_operation AND o.transaction_id=pg_current_xact_id()),
 types AS (SELECT ids.relation_type_id,coalesce(c.before_definition,v.definition) AS before_definition,coalesce(c.after_definition,v.definition) AS after_definition,c.plan
  FROM public.gc_relation_graph_candidate_types(selected_operation) ids CROSS JOIN op
  LEFT JOIN public.relation_graph_operation_type_claims c ON c.tenant_id=op.tenant_id AND c.operation_id=op.id AND c.relation_type_id=ids.relation_type_id
  LEFT JOIN public.relation_types t ON t.tenant_id=op.tenant_id AND t.type_id=ids.relation_type_id
  LEFT JOIN public.relation_type_versions v ON v.tenant_id=t.tenant_id AND v.relation_type_id=t.type_id AND v.version=t.current_version)
 SELECT a.id,coalesce((SELECT v->>'kind' FROM jsonb_array_elements(op.normalized_change_set->'assetChanges') e(v) WHERE v->>'assetId'=a.id::text),
  CASE WHEN EXISTS(SELECT 1 FROM public.relation_graph_operation_model_claims m WHERE m.tenant_id=op.tenant_id AND m.operation_id=op.id AND m.model_id=a.model_id) THEN 'type-migrate' ELSE 'preserve' END)
 FROM public.assets a CROSS JOIN op WHERE a.tenant_id=op.tenant_id AND (
  EXISTS(SELECT 1 FROM jsonb_array_elements(op.normalized_change_set->'assetChanges') e(v) WHERE v->>'assetId'=a.id::text)
  OR EXISTS(SELECT 1 FROM public.relation_graph_operation_model_claims m WHERE m.tenant_id=op.tenant_id AND m.operation_id=op.id AND m.model_id=a.model_id)
  OR EXISTS(SELECT 1 FROM types t WHERE public.gc_relation_endpoint_eligible(op.tenant_id,a.id,t.before_definition,'source')
   OR public.gc_relation_endpoint_eligible(op.tenant_id,a.id,t.before_definition,'target') OR public.gc_relation_endpoint_eligible(op.tenant_id,a.id,t.after_definition,'source')
   OR public.gc_relation_endpoint_eligible(op.tenant_id,a.id,t.after_definition,'target')
   OR EXISTS(SELECT 1 FROM public.relations r WHERE r.tenant_id=op.tenant_id AND r.relation_type_id=t.relation_type_id AND r.status='active' AND a.id IN(r.source_asset_id,r.target_asset_id))
   OR EXISTS(SELECT 1 FROM public.relation_participations b WHERE b.tenant_id=op.tenant_id AND b.relation_type_id=t.relation_type_id AND b.status='active' AND b.asset_id=a.id)
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(coalesce(t.plan->'creations','[]')) e(v) WHERE a.id::text IN(v->>'sourceAssetId',v->>'targetAssetId'))))
$$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_candidate_assets(uuid) FROM PUBLIC,gc_app;

CREATE FUNCTION public.gc_relation_graph_begin(operation_id uuid,idempotency_operation text,idempotency_key text,request_body jsonb,correlation_id text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
<<begin_context>>
DECLARE tenant uuid:=public.gc_tenant(); actor uuid:=public.gc_actor()::uuid; selected_operation uuid:=operation_id;
 request jsonb:=request_body; change_set jsonb:=request_body->'changeSet'; target jsonb; plan jsonb; expected jsonb; before_policy jsonb;
 type_identity uuid; head public.relation_types; prepared public.relation_type_preparations; policy jsonb; mode text;
 asset_row public.assets; before_tuple jsonb; after_tuple jsonb; asset_action text; changed boolean; candidate record;
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
 IF EXISTS(SELECT 1 FROM public.gc_relation_graph_candidate_assets(selected_operation) c JOIN public.assets a
  ON a.tenant_id=tenant AND a.id=c.asset_id WHERE a.visibility='restricted' AND NOT a.allowed_identities @> jsonb_build_array(actor))
  OR EXISTS(SELECT 1 FROM public.gc_relation_graph_candidate_types(selected_operation) t JOIN public.relations r
   ON r.tenant_id=tenant AND r.relation_type_id=t.relation_type_id WHERE r.status='active' AND r.visibility='restricted' AND NOT r.allowed_identities @> jsonb_build_array(actor)) THEN
  RAISE EXCEPTION 'RELATION_SCOPE_UNAVAILABLE' USING ERRCODE='42501'; END IF;
 IF (SELECT count(*) FROM public.gc_relation_graph_candidate_assets(selected_operation))>2000
  OR (SELECT count(*) FROM public.gc_relation_graph_candidate_assets(selected_operation) c WHERE c.action<>'preserve')>1000
  OR (SELECT count(*) FROM public.relations r JOIN public.gc_relation_graph_candidate_types(selected_operation) t ON t.relation_type_id=r.relation_type_id
   WHERE r.tenant_id=tenant AND r.status='active')>1000
  OR (SELECT count(*) FROM public.relation_participations p JOIN public.gc_relation_graph_candidate_types(selected_operation) t ON t.relation_type_id=p.relation_type_id
   WHERE p.tenant_id=tenant AND p.status='active')>4000 THEN RAISE EXCEPTION 'RELATION_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 -- Scalar database preflight precedes full governed tuples/private row copies.
 -- Full current rows and their actual immutable revisions are measured here,
 -- including source description/metadata, before any full row copy or write.
 IF octet_length(request_body::text)+octet_length(request::text)
  +coalesce((SELECT sum(octet_length(to_jsonb(a)::text)+octet_length(a.attributes::text)*2)
   FROM public.assets a JOIN public.gc_relation_graph_candidate_assets(selected_operation) c ON c.asset_id=a.id WHERE a.tenant_id=tenant),0)
  +coalesce((SELECT sum(octet_length(h.snapshot::text)) FROM public.asset_revisions h JOIN public.assets a
   ON a.tenant_id=h.tenant_id AND a.id=h.asset_id AND a.version=h.version JOIN public.gc_relation_graph_candidate_assets(selected_operation) c
   ON c.asset_id=a.id WHERE a.tenant_id=tenant),0)
  +coalesce((SELECT sum(octet_length(r.attributes::text)*3+octet_length(r.allowed_identities::text)*3+octet_length(r.provenance::text)+1024)
   FROM public.relations r JOIN public.gc_relation_graph_candidate_types(selected_operation) c ON c.relation_type_id=r.relation_type_id
   WHERE r.tenant_id=tenant AND r.status='active'),0)
  +coalesce((SELECT sum(octet_length(v.definition::text)*2) FROM public.gc_relation_graph_candidate_types(selected_operation) c
   JOIN public.relation_types h ON h.tenant_id=tenant AND h.type_id=c.relation_type_id JOIN public.relation_type_versions v
   ON v.tenant_id=h.tenant_id AND v.relation_type_id=h.type_id AND v.version=h.current_version),0)
  +coalesce((SELECT sum(coalesce(octet_length(c.before_definition::text),0)+octet_length(c.after_definition::text)) FROM public.relation_graph_operation_type_claims c
   WHERE c.tenant_id=tenant AND c.operation_id=selected_operation),0)
  +coalesce((SELECT sum(octet_length(c.before_resolution::text)+octet_length(c.after_resolution::text)) FROM public.relation_graph_operation_model_claims c
   WHERE c.tenant_id=tenant AND c.operation_id=selected_operation),0)>524288 THEN
  RAISE EXCEPTION 'RELATION_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 -- Only the fully authorized, physically bounded identity scope is retained.
 INSERT INTO public.relation_graph_operation_asset_scope(tenant_id,operation_id,asset_id,action,projected_endpoint)
 SELECT tenant,selected_operation,a.id,c.action,public.gc_relation_graph_project_endpoint(a,request)
  FROM public.gc_relation_graph_candidate_assets(selected_operation) c JOIN public.assets a ON a.tenant_id=tenant AND a.id=c.asset_id;
 FOR candidate IN SELECT t.*,v.definition FROM public.gc_relation_graph_candidate_types(selected_operation) ids
  JOIN public.relation_types t ON t.tenant_id=tenant AND t.type_id=ids.relation_type_id
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

CREATE OR REPLACE FUNCTION public.gc_relation_type_head_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.relation_graph_operations; claim public.relation_graph_operation_type_claims;
BEGIN

 op:=public.gc_relation_graph_current();
 IF op.id IS NOT NULL THEN
  SELECT * INTO claim FROM public.relation_graph_operation_type_claims c WHERE c.tenant_id=NEW.tenant_id AND c.operation_id=op.id AND c.relation_type_id=NEW.type_id;
  IF op.state<>'open' OR op.actor_id::text<>public.gc_actor() OR claim.operation_id IS NULL OR claim.head_consumed OR claim.mode NOT IN ('create','publish')
   OR NEW.current_version<>claim.after_version OR NEW.id<>claim.after_definition->>'id'
   OR (TG_OP='INSERT' AND (claim.mode<>'create' OR NEW.created_by<>op.actor_id OR NEW.current_version<>1))
   OR (TG_OP='UPDATE' AND (claim.mode<>'publish' OR OLD.current_version<>claim.before_version
    OR ROW(NEW.tenant_id,NEW.id,NEW.type_id,NEW.created_by,NEW.created_at) IS DISTINCT FROM ROW(OLD.tenant_id,OLD.id,OLD.type_id,OLD.created_by,OLD.created_at))) THEN
   RAISE EXCEPTION 'Relation head write requires its unique exact publication claim' USING ERRCODE='23514'; END IF;
  UPDATE public.relation_graph_operation_type_claims SET head_consumed=true WHERE tenant_id=NEW.tenant_id AND operation_id=op.id AND relation_type_id=NEW.type_id;
  RETURN NEW;
 END IF;
 PERFORM public.gc_relation_publication_principals(NEW.type_id);
 PERFORM public.gc_relation_authorize(ARRAY['models:read','models:write']);
 IF TG_OP='INSERT' THEN
  IF NEW.current_version<>1 OR NEW.created_by::text IS DISTINCT FROM public.gc_actor() THEN
   RAISE EXCEPTION 'Relation type identity starts at version one' USING ERRCODE='23514'; END IF;
 ELSIF ROW(NEW.tenant_id,NEW.id,NEW.type_id,NEW.created_by,NEW.created_at) IS DISTINCT FROM ROW(OLD.tenant_id,OLD.id,OLD.type_id,OLD.created_by,OLD.created_at)
  OR NEW.current_version::bigint<>OLD.current_version::bigint+1 THEN
  RAISE EXCEPTION 'Relation type identity is immutable and publication advances one version' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION public.gc_relation_type_version_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE head public.relation_types; op public.relation_graph_operations; claim public.relation_graph_operation_type_claims;
BEGIN

 op:=public.gc_relation_graph_current();
 IF op.id IS NOT NULL THEN
  SELECT * INTO claim FROM public.relation_graph_operation_type_claims c WHERE c.tenant_id=NEW.tenant_id AND c.operation_id=op.id AND c.relation_type_id=NEW.relation_type_id;
  IF op.state<>'open' OR op.actor_id::text<>public.gc_actor() OR claim.operation_id IS NULL OR claim.definition_consumed OR claim.mode NOT IN ('create','publish')
   OR NEW.version<>claim.after_version OR NEW.definition IS DISTINCT FROM claim.after_definition
   OR NEW.definition_hash<>public.gc_type_migration_hash(claim.after_definition) OR NEW.created_by<>op.actor_id THEN
   RAISE EXCEPTION 'Relation version requires its unique exact publication claim' USING ERRCODE='23514'; END IF;
  UPDATE public.relation_graph_operation_type_claims SET definition_consumed=true WHERE tenant_id=NEW.tenant_id AND operation_id=op.id AND relation_type_id=NEW.relation_type_id;
  RETURN NEW;
 END IF;
 PERFORM public.gc_relation_publication_principals(NEW.relation_type_id);
 PERFORM public.gc_relation_authorize(ARRAY['models:read','models:write']);
 SELECT * INTO head FROM public.relation_types WHERE tenant_id=NEW.tenant_id AND type_id=NEW.relation_type_id;
 IF head.id IS NULL OR NEW.created_by::text IS DISTINCT FROM public.gc_actor()
 OR NOT public.gc_relation_definition_valid(NEW.definition)
 OR NEW.definition->>'id' IS DISTINCT FROM head.id OR NEW.definition->>'version' IS DISTINCT FROM NEW.version::text
 OR NEW.definition_hash IS DISTINCT FROM public.gc_type_migration_hash(NEW.definition)
 OR NOT ((NEW.version=1 AND head.current_version=1) OR NEW.version::bigint=head.current_version::bigint+1) THEN
  RAISE EXCEPTION 'Relation definition must match its exact identity, version and hash' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE OR REPLACE FUNCTION public.gc_relation_publication_complete() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE expected_action text:=CASE WHEN NEW.version=1 THEN 'relation_type.created' ELSE 'relation_type.published' END;
 op public.relation_graph_operations; claim public.relation_graph_operation_type_claims; logical_key text; expected jsonb; actual jsonb; previous_definition jsonb; binding record;
BEGIN
 SELECT id INTO logical_key FROM public.relation_types t WHERE t.tenant_id=NEW.tenant_id AND t.type_id=NEW.relation_type_id AND t.current_version>=NEW.version;
 IF logical_key IS NULL THEN RAISE EXCEPTION 'Relation version must be published by its head' USING ERRCODE='23514'; END IF;
 op:=public.gc_relation_graph_current();
 IF op.id IS NOT NULL THEN
  SELECT * INTO claim FROM public.relation_graph_operation_type_claims c WHERE c.tenant_id=NEW.tenant_id AND c.operation_id=op.id AND c.relation_type_id=NEW.relation_type_id;
  IF op.state='open' OR claim.operation_id IS NULL OR NOT claim.head_consumed OR NOT claim.definition_consumed
   OR claim.after_version<>NEW.version OR claim.after_definition IS DISTINCT FROM NEW.definition THEN
   RAISE EXCEPTION 'Publication requires its sealed complete operation outcome' USING ERRCODE='23514'; END IF;
 ELSE
 IF NEW.version>1 AND EXISTS(SELECT 1 FROM public.relations r WHERE r.tenant_id=NEW.tenant_id AND r.relation_type_id=NEW.relation_type_id AND r.status='active') THEN
  SELECT v.definition INTO previous_definition FROM public.relation_type_versions v
   WHERE v.tenant_id=NEW.tenant_id AND v.relation_type_id=NEW.relation_type_id AND v.version=NEW.version-1;
  IF previous_definition IS NULL
   OR (previous_definition-ARRAY['formatVersion','id','version','label','inverseLabel','attributes']) IS DISTINCT FROM (NEW.definition-ARRAY['formatVersion','id','version','label','inverseLabel','attributes'])
   OR NOT public.gc_relation_schema_compatible(jsonb_build_object('type','object','properties',previous_definition->'attributes'),jsonb_build_object('type','object','properties',NEW.definition->'attributes')) THEN
   RAISE EXCEPTION 'RELATION_MIGRATION_REQUIRED' USING ERRCODE='23514'; END IF;
  IF EXISTS(SELECT 1 FROM public.relations r JOIN public.relation_type_versions v
   ON v.tenant_id=r.tenant_id AND v.relation_type_id=r.relation_type_id AND v.version=r.relation_type_version
   WHERE r.tenant_id=NEW.tenant_id AND r.relation_type_id=NEW.relation_type_id AND r.status='active'
    AND (v.definition->>'requiredOwner'='true' OR NEW.definition->>'requiredOwner'='true')
    AND NOT EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id
     WHERE m.tenant_id=r.tenant_id AND m.identity_id=r.owner_id AND m.active AND i.active)) THEN
   RAISE EXCEPTION 'RELATION_MIGRATION_REQUIRED' USING ERRCODE='23514'; END IF;
 END IF;
 -- Check each publication event's exact target, including intermediate versions
 -- when multiple publications share a transaction. A later relaxed head cannot
 -- hide an incompatible earlier publication. Current mutations remain pin-scoped.
 FOR binding IN SELECT r.attributes,v.definition AS policy FROM public.relations r JOIN public.relation_type_versions v
  ON v.tenant_id=r.tenant_id AND v.relation_type_id=r.relation_type_id AND v.version=r.relation_type_version
  WHERE r.tenant_id=NEW.tenant_id AND r.relation_type_id=NEW.relation_type_id AND r.status='active' LOOP
  IF (binding.policy-ARRAY['formatVersion','id','version','label','inverseLabel','attributes']) IS DISTINCT FROM (NEW.definition-ARRAY['formatVersion','id','version','label','inverseLabel','attributes'])
   OR NOT public.gc_relation_schema_compatible(jsonb_build_object('type','object','properties',binding.policy->'attributes'),jsonb_build_object('type','object','properties',NEW.definition->'attributes'))
   OR NOT public.gc_relation_value_valid(jsonb_build_object('type','object','properties',NEW.definition->'attributes'),binding.attributes) THEN
   RAISE EXCEPTION 'RELATION_MIGRATION_REQUIRED' USING ERRCODE='23514'; END IF;
 END LOOP;
 END IF;
 SELECT jsonb_agg(jsonb_build_object('side',s.side,'typeId',item->'typeId','includeDescendants',item->'includeDescendants') ORDER BY s.side,item->>'typeId') INTO expected
  FROM unnest(ARRAY['source','target']) s(side) CROSS JOIN LATERAL jsonb_array_elements(NEW.definition->(s.side||'Types')) a(item);
 SELECT jsonb_agg(jsonb_build_object('side',r.side,'typeId',r.type_id,'includeDescendants',r.include_descendants) ORDER BY r.side,r.type_id) INTO actual
  FROM public.relation_type_endpoints r WHERE r.tenant_id=NEW.tenant_id AND r.relation_type_id=NEW.relation_type_id AND r.version=NEW.version;
 IF expected IS DISTINCT FROM actual THEN RAISE EXCEPTION 'Relation endpoint references must be complete' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.audit a JOIN public.outbox o ON o.tenant_id=a.tenant_id AND o.id=a.id
  WHERE a.tenant_id=NEW.tenant_id AND a.action=expected_action AND a.resource_id=logical_key AND a.actor_id=NEW.created_by::text
   AND a.changes->>'resourceVersion'=NEW.version::text AND a.envelope->>'version'=NEW.version::text
   AND o.event_type=a.action AND o.resource_id=a.resource_id AND o.resource_version=NEW.version) THEN
  RAISE EXCEPTION 'Relation publication requires paired audit and outbox records' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION public.gc_relation_graph_model_write_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.relation_graph_operations; claim public.relation_graph_operation_model_claims; key text;
BEGIN
 op:=public.gc_relation_graph_current(); IF op.id IS NULL THEN RETURN NEW; END IF;
 IF TG_RELID='public.governance_models'::regclass THEN key:=NEW.id;
 ELSE key:=NEW.model_id; END IF;
 SELECT * INTO claim FROM public.relation_graph_operation_model_claims c WHERE c.tenant_id=NEW.tenant_id AND c.operation_id=op.id AND c.model_id=key;
 IF op.state<>'open' OR op.actor_id::text<>public.gc_actor() OR claim.operation_id IS NULL THEN
  RAISE EXCEPTION 'Graph model write requires a protected nested migration claim' USING ERRCODE='23514'; END IF;
 IF TG_RELID='public.governance_models'::regclass THEN
  IF TG_OP<>'UPDATE' OR claim.head_consumed OR OLD.current_version<>claim.before_version OR NEW.current_version<>claim.after_version
   OR (to_jsonb(NEW)-'current_version') IS DISTINCT FROM (to_jsonb(OLD)-'current_version') THEN
   RAISE EXCEPTION 'Nested model head must match its exact publication' USING ERRCODE='23514'; END IF;
  UPDATE public.relation_graph_operation_model_claims SET head_consumed=true WHERE tenant_id=NEW.tenant_id AND operation_id=op.id AND model_id=key;
 ELSIF TG_RELID='public.governance_model_versions'::regclass THEN
  IF TG_OP<>'INSERT' OR claim.model_consumed OR NEW.version<>claim.after_version OR NEW.created_by<>op.actor_id
   OR NEW.definition IS DISTINCT FROM claim.after_resolution->'model' OR NEW.definition_hash<>public.gc_type_migration_hash(NEW.definition) THEN
   RAISE EXCEPTION 'Nested attribute definition must equal independent resolution' USING ERRCODE='23514'; END IF;
  UPDATE public.relation_graph_operation_model_claims SET model_consumed=true WHERE tenant_id=NEW.tenant_id AND operation_id=op.id AND model_id=key;
 ELSIF TG_RELID='public.asset_type_versions'::regclass THEN
  IF TG_OP<>'INSERT' OR claim.authored_consumed OR NEW.version<>claim.after_version OR NEW.created_by<>op.actor_id
   OR NEW.definition IS DISTINCT FROM claim.after_resolution->'definition' OR NEW.resolved IS DISTINCT FROM claim.after_resolution
   OR NEW.definition_hash<>public.gc_type_migration_hash(NEW.definition) OR NEW.resolution_hash<>public.gc_type_migration_hash(NEW.resolved) THEN
   RAISE EXCEPTION 'Nested authored definition must equal independent resolution' USING ERRCODE='23514'; END IF;
  UPDATE public.relation_graph_operation_model_claims SET authored_consumed=true WHERE tenant_id=NEW.tenant_id AND operation_id=op.id AND model_id=key;
 ELSE RAISE EXCEPTION 'Untrusted model write trigger' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_model_write_guard() FROM PUBLIC,gc_app;
CREATE TRIGGER graph_model_claim_guard BEFORE INSERT OR UPDATE ON public.governance_models FOR EACH ROW EXECUTE FUNCTION public.gc_relation_graph_model_write_guard();
CREATE TRIGGER graph_model_claim_guard BEFORE INSERT ON public.governance_model_versions FOR EACH ROW EXECUTE FUNCTION public.gc_relation_graph_model_write_guard();
CREATE TRIGGER graph_model_claim_guard BEFORE INSERT ON public.asset_type_versions FOR EACH ROW EXECUTE FUNCTION public.gc_relation_graph_model_write_guard();

CREATE FUNCTION public.gc_relation_graph_snapshot(selected_operation uuid,after_state boolean) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant(); request jsonb; heads jsonb; endpoints jsonb:='[]'; edges jsonb; bindings jsonb; entry record; endpoint jsonb;
BEGIN
 SELECT jsonb_build_object('changeSet',o.normalized_change_set) INTO request FROM public.relation_graph_operations o WHERE o.tenant_id=tenant AND o.id=selected_operation AND o.transaction_id=pg_current_xact_id();
 IF request IS NULL THEN RAISE EXCEPTION 'Snapshot requires the actual operation' USING ERRCODE='42501'; END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('relationTypeId',t.relation_type_id,'version',CASE WHEN after_state THEN t.after_version ELSE t.before_version END)
  ORDER BY t.relation_type_id),'[]') INTO heads FROM public.relation_graph_operation_type_claims t
  WHERE t.tenant_id=tenant AND t.operation_id=selected_operation AND (after_state OR t.before_version IS NOT NULL);
 FOR entry IN SELECT a.* FROM public.relation_graph_operation_asset_claims a WHERE a.tenant_id=tenant AND a.operation_id=selected_operation ORDER BY a.asset_id LOOP
  endpoint:=public.gc_relation_graph_endpoint(entry.asset_id,CASE WHEN after_state THEN entry.to_version ELSE entry.from_version END,
   CASE WHEN after_state THEN entry.after_tuple ELSE entry.before_tuple END,request);
  PERFORM public.gc_relation_graph_charge(selected_operation,endpoint);
  endpoints:=endpoints||jsonb_build_array(endpoint);
 END LOOP;
 SELECT coalesce(jsonb_agg(CASE WHEN after_state THEN e.after_tuple ELSE e.before_tuple END ORDER BY e.relation_type_id,e.key->>'kind',coalesce(e.key->>'relationId',e.key->>'key')),'[]') INTO edges
  FROM public.relation_graph_operation_edge_claims e WHERE e.tenant_id=tenant AND e.operation_id=selected_operation AND (after_state OR e.before_tuple IS NOT NULL);
 SELECT coalesce(jsonb_agg(CASE WHEN after_state THEN b.after_tuple ELSE b.before_tuple END ORDER BY b.relation_type_id,b.key->>'kind',coalesce(b.key->>'bindingId',b.key->>'assetId'),b.key->>'side'),'[]') INTO bindings
  FROM public.relation_graph_operation_binding_claims b WHERE b.tenant_id=tenant AND b.operation_id=selected_operation AND (after_state OR b.before_tuple IS NOT NULL);
 RETURN jsonb_build_object('heads',heads,'endpoints',endpoints,'edges',edges,'bindings',bindings);
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_snapshot(uuid,boolean) FROM PUBLIC,gc_app;

CREATE FUNCTION public.gc_relation_graph_asset_evidence(model_key text,model_version integer,request jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE policy jsonb; identity uuid; ancestors jsonb;
BEGIN
 policy:=public.gc_relation_graph_asset_policy(model_key,model_version,request);
 SELECT m.type_id INTO identity FROM public.governance_models m WHERE m.tenant_id=public.gc_tenant() AND m.id=model_key;
 IF identity IS NULL THEN RETURN jsonb_build_object('kind','attributes','model',policy->'model','definitionHash',public.gc_type_migration_hash(policy->'model')); END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('typeId',m.type_id,'id',m.id,'version',p->'version') ORDER BY m.id COLLATE "C"),'[]') INTO ancestors
  FROM jsonb_array_elements(policy->'dependencies') e(p) JOIN public.governance_models m ON m.tenant_id=public.gc_tenant() AND m.id=p->>'id';
 RETURN jsonb_build_object('kind','authored','typeId',identity,'resolution',policy,'definitionHash',public.gc_type_migration_hash(policy->'definition'),
  'resolutionHash',public.gc_type_migration_hash(policy),'ancestorTypes',ancestors);
END $$;
CREATE FUNCTION public.gc_relation_graph_asset_preparation(selected_operation uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant(); request jsonb; policies jsonb:='[]'; evidence jsonb; changes jsonb:='[]'; migrations jsonb:='[]'; a record; m record;
 source_issues jsonb; old_policy jsonb; new_policy jsonb; pin record; policy_changes jsonb; source_policies jsonb; asset_ids jsonb;
BEGIN
 SELECT jsonb_build_object('changeSet',o.normalized_change_set) INTO request FROM public.relation_graph_operations o WHERE o.tenant_id=tenant AND o.id=selected_operation AND o.transaction_id=pg_current_xact_id();
 IF request IS NULL THEN RAISE EXCEPTION 'Asset evidence requires the actual operation' USING ERRCODE='42501'; END IF;
 FOR pin IN SELECT * FROM (
  SELECT ac.before_tuple->>'modelId' AS model_id,(ac.before_tuple->>'modelVersion')::integer AS version FROM public.relation_graph_operation_asset_claims ac
   WHERE ac.tenant_id=tenant AND ac.operation_id=selected_operation AND ac.action<>'preserve' AND ac.before_tuple->>'modelId' IS NOT NULL
  UNION SELECT ac.after_tuple->>'modelId',(ac.after_tuple->>'modelVersion')::integer FROM public.relation_graph_operation_asset_claims ac
   WHERE ac.tenant_id=tenant AND ac.operation_id=selected_operation AND ac.action<>'preserve' AND ac.after_tuple->>'modelId' IS NOT NULL
  UNION SELECT c.model_id,c.before_version FROM public.relation_graph_operation_model_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation
  UNION SELECT c.model_id,c.after_version FROM public.relation_graph_operation_model_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation) pins ORDER BY model_id COLLATE "C",version LOOP
  evidence:=public.gc_relation_graph_asset_evidence(pin.model_id,pin.version,request);
  PERFORM public.gc_relation_graph_charge(selected_operation,evidence);policies:=policies||jsonb_build_array(evidence);
 END LOOP;
 FOR a IN SELECT * FROM public.relation_graph_operation_asset_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.action<>'preserve' ORDER BY c.asset_id LOOP
  source_issues:='[]';
  old_policy:=public.gc_relation_graph_asset_policy(a.before_tuple->>'modelId',(a.before_tuple->>'modelVersion')::integer,request);
  new_policy:=public.gc_relation_graph_asset_policy(a.after_tuple->>'modelId',(a.after_tuple->>'modelVersion')::integer,request);
  IF a.action='type-migrate' AND old_policy->>'requiredOwner'='true' AND NOT EXISTS(
   SELECT 1 FROM public.memberships member JOIN public.identities identity ON identity.id=member.identity_id
    WHERE member.tenant_id=tenant AND member.identity_id=(a.before_tuple->>'ownerId')::uuid AND member.active AND identity.active) THEN
   source_issues:=jsonb_build_array(jsonb_build_object('code','required','path','/source/ownerId',
    'message','The pinned source requires an active owner; this migration repairs that policy violation.'));
  END IF;
  changes:=changes||jsonb_build_array(jsonb_build_object('kind',a.action,'assetId',a.asset_id,'fromAssetVersion',a.from_version,'toAssetVersion',a.to_version,
   'before',a.before_tuple,'after',a.after_tuple,'sourcePolicy',CASE WHEN a.before_tuple->>'modelId' IS NULL THEN NULL ELSE jsonb_build_object('modelId',a.before_tuple->'modelId','modelVersion',a.before_tuple->'modelVersion') END,
   'targetPolicy',CASE WHEN a.after_tuple->>'modelId' IS NULL THEN NULL ELSE jsonb_build_object('modelId',a.after_tuple->'modelId','modelVersion',a.after_tuple->'modelVersion') END,'sourceIssues',source_issues));
 END LOOP;
 FOR m IN SELECT * FROM public.relation_graph_operation_model_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation ORDER BY c.model_id COLLATE "C" LOOP
  SELECT coalesce(jsonb_agg(code ORDER BY code COLLATE "C"),'[]') INTO policy_changes FROM (VALUES
   ('parents_changed',public.gc_relation_sorted_pins(m.before_resolution->'definition'->'parents') IS DISTINCT FROM public.gc_relation_sorted_pins(m.after_resolution->'definition'->'parents')),
   ('required_owner_changed',m.before_resolution->'requiredOwner' IS DISTINCT FROM m.after_resolution->'requiredOwner'),
   ('lifecycle_changed',m.before_resolution->'lifecycle' IS DISTINCT FROM m.after_resolution->'lifecycle')) diffs(code,changed) WHERE changed;
  SELECT coalesce(jsonb_agg(jsonb_build_object('modelId',m.model_id,'modelVersion',version) ORDER BY version),'[]') INTO source_policies FROM (
   SELECT DISTINCT (ac.before_tuple->>'modelVersion')::integer AS version FROM public.relation_graph_operation_asset_claims ac
    WHERE ac.tenant_id=tenant AND ac.operation_id=selected_operation AND ac.action='type-migrate' AND ac.before_tuple->>'modelId'=m.model_id) pins;
  SELECT coalesce(jsonb_agg(ac.asset_id ORDER BY ac.asset_id),'[]') INTO asset_ids FROM public.relation_graph_operation_asset_claims ac
   WHERE ac.tenant_id=tenant AND ac.operation_id=selected_operation AND ac.action='type-migrate' AND ac.before_tuple->>'modelId'=m.model_id;
  migrations:=migrations||jsonb_build_array(jsonb_build_object('typeId',m.type_id,'modelId',m.model_id,'expectedHeadVersion',m.before_version,
   'headPolicy',jsonb_build_object('modelId',m.model_id,'modelVersion',m.before_version),'targetPolicy',jsonb_build_object('modelId',m.model_id,'modelVersion',m.after_version),
   'sourcePolicies',source_policies,'plan',m.plan,'assetIds',asset_ids,'changes',public.gc_relation_schema_changes(
    jsonb_build_object('type','object','properties',m.before_resolution->'model'->'attributes'),jsonb_build_object('type','object','properties',m.after_resolution->'model'->'attributes')),
   'policyChanges',policy_changes));
 END LOOP;
 RETURN jsonb_build_object('policies',policies,'changes',changes,'typeMigrations',migrations);
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_asset_preparation(uuid) FROM PUBLIC,gc_app;

CREATE FUNCTION public.gc_relation_graph_nested_receipt_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.relation_graph_operations; claim public.relation_graph_operation_model_claims;
BEGIN
 op:=public.gc_relation_graph_current(); IF op.id IS NULL THEN RETURN NEW; END IF;
 SELECT * INTO claim FROM public.relation_graph_operation_model_claims c WHERE c.tenant_id=NEW.tenant_id AND c.operation_id=op.id AND c.model_id=NEW.model_id;
 IF op.state<>'open' OR claim.operation_id IS NULL OR NEW.id<>claim.migration_id OR NEW.executed_by<>op.actor_id
  OR NEW.from_version<>claim.before_version OR NEW.to_version<>claim.after_version
  OR NEW.plan IS DISTINCT FROM (CASE WHEN TG_RELID='public.asset_type_migrations'::regclass THEN claim.plan ELSE claim.plan->'attributes' END) THEN
  RAISE EXCEPTION 'Nested receipt must match its protected complete migration claim' USING ERRCODE='23514'; END IF;
 IF NEW.asset_count<>(SELECT count(*) FROM public.relation_graph_operation_asset_claims a WHERE a.tenant_id=NEW.tenant_id AND a.operation_id=op.id
  AND a.action='type-migrate' AND a.before_tuple->>'modelId'=claim.model_id)
  OR (SELECT coalesce(jsonb_agg(v->'assetId' ORDER BY v->>'assetId'),'[]') FROM jsonb_array_elements(NEW.assets) e(v)) IS DISTINCT FROM
   (SELECT coalesce(jsonb_agg(a.asset_id ORDER BY a.asset_id),'[]') FROM public.relation_graph_operation_asset_claims a WHERE a.tenant_id=NEW.tenant_id AND a.operation_id=op.id
    AND a.action='type-migrate' AND a.before_tuple->>'modelId'=claim.model_id) THEN
  RAISE EXCEPTION 'Nested receipt cohort must equal captured complete membership' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_nested_receipt_guard() FROM PUBLIC,gc_app;
CREATE TRIGGER graph_nested_receipt_guard BEFORE INSERT ON public.governance_model_migrations FOR EACH ROW EXECUTE FUNCTION public.gc_relation_graph_nested_receipt_guard();
CREATE TRIGGER graph_nested_receipt_guard BEFORE INSERT ON public.asset_type_migrations FOR EACH ROW EXECUTE FUNCTION public.gc_relation_graph_nested_receipt_guard();

CREATE FUNCTION public.gc_relation_graph_seal(operation_id uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
<<seal_context>>
DECLARE tenant uuid:=public.gc_tenant(); selected_operation uuid:=operation_id; op public.relation_graph_operations;
 type_claim public.relation_graph_operation_type_claims; asset_claim public.relation_graph_operation_asset_claims;
 edge_claim public.relation_graph_operation_edge_claims; binding_claim public.relation_graph_operation_binding_claims;
 row_value public.assets; edge public.relations; binding public.relation_participations;
 before_snapshot jsonb; after_snapshot jsonb; before_graph jsonb; after_graph jsonb; asset_changes jsonb;
 policies jsonb; targets jsonb; identities jsonb; source_issues jsonb:='[]'; outcomes jsonb:='[]'; binding_outcomes jsonb:='[]'; asset_refs jsonb:='[]';
 creations jsonb; enrollments jsonb; replacements jsonb; nested jsonb; receipt jsonb; target jsonb; expected_action text; bytes bigint;
BEGIN
 SELECT * INTO op FROM public.relation_graph_operations o WHERE o.tenant_id=tenant AND o.id=selected_operation AND o.transaction_id=pg_current_xact_id() FOR UPDATE;
 IF op.id IS NULL OR op.state<>'open' OR op.actor_id::text<>public.gc_actor() THEN RAISE EXCEPTION 'Only the actual open graph operation can seal' USING ERRCODE='42501'; END IF;
 IF clock_timestamp()>=op.created_at+interval '30 seconds' THEN RAISE EXCEPTION 'Graph operation deadline exceeded' USING ERRCODE='57014'; END IF;
 PERFORM public.gc_relation_authorize(ARRAY['models:read','models:write','catalog:read','catalog:write']);
 IF EXISTS(SELECT 1 FROM public.relation_graph_operation_journal_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND (c.audit_id IS NULL OR NOT c.outbox_written)) THEN
  RAISE EXCEPTION 'Every graph change requires its exact paired journal before sealing' USING ERRCODE='23514'; END IF;
 IF EXISTS(SELECT 1 FROM public.relation_graph_operation_asset_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND NOT c.consumed)
  OR EXISTS(SELECT 1 FROM public.relation_graph_operation_edge_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND NOT c.consumed)
  OR EXISTS(SELECT 1 FROM public.relation_graph_operation_binding_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND NOT c.consumed)
  OR EXISTS(SELECT 1 FROM public.relation_graph_operation_type_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.mode IN ('create','publish') AND (NOT c.head_consumed OR NOT c.definition_consumed))
  OR EXISTS(SELECT 1 FROM public.relation_graph_operation_model_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND (NOT c.head_consumed OR NOT c.model_consumed OR NOT c.authored_consumed)) THEN
  RAISE EXCEPTION 'Every protected graph claim must be consumed exactly once before sealing' USING ERRCODE='23514'; END IF;
 FOR type_claim IN SELECT * FROM public.relation_graph_operation_type_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation ORDER BY c.relation_type_id LOOP
  IF NOT EXISTS(SELECT 1 FROM public.relation_types t JOIN public.relation_type_versions v ON v.tenant_id=t.tenant_id AND v.relation_type_id=t.type_id AND v.version=t.current_version
   WHERE t.tenant_id=tenant AND t.type_id=type_claim.relation_type_id AND t.current_version=type_claim.after_version
    AND v.definition=type_claim.after_definition AND v.definition_hash=public.gc_type_migration_hash(type_claim.after_definition)) THEN
   RAISE EXCEPTION 'Sealed policy must equal its exact claimed head and definition' USING ERRCODE='23514'; END IF;
  PERFORM public.gc_relation_check_type(tenant,type_claim.relation_type_id);
  IF (SELECT coalesce(jsonb_agg(r.id ORDER BY r.id),'[]') FROM public.relations r WHERE r.tenant_id=tenant AND r.relation_type_id=type_claim.relation_type_id AND r.status='active')
   IS DISTINCT FROM (SELECT coalesce(jsonb_agg(c.relation_id ORDER BY c.relation_id),'[]') FROM public.relation_graph_operation_edge_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.relation_type_id=type_claim.relation_type_id AND c.after_tuple->>'status'='active')
   OR (SELECT coalesce(jsonb_agg(p.id ORDER BY p.id),'[]') FROM public.relation_participations p WHERE p.tenant_id=tenant AND p.relation_type_id=type_claim.relation_type_id AND p.status='active')
   IS DISTINCT FROM (SELECT coalesce(jsonb_agg(c.binding_id ORDER BY c.binding_id),'[]') FROM public.relation_graph_operation_binding_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.relation_type_id=type_claim.relation_type_id AND c.after_tuple->>'status'='active') THEN
   RAISE EXCEPTION 'Sealed scope must equal complete actual live cohorts' USING ERRCODE='23514'; END IF;
 END LOOP;
 FOR asset_claim IN SELECT * FROM public.relation_graph_operation_asset_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation ORDER BY c.asset_id LOOP
  SELECT * INTO row_value FROM public.assets a WHERE a.tenant_id=tenant AND a.id=asset_claim.asset_id;
  SELECT jsonb_build_object('id',r.snapshot->'id','version',r.snapshot->'version','name',r.snapshot->'name','modelId',r.snapshot->'modelId','modelVersion',r.snapshot->'modelVersion','attributes',r.snapshot->'attributes','ownerId',r.snapshot->'ownerId','typeState',r.snapshot->'typeState') INTO before_snapshot FROM public.asset_revisions r WHERE r.tenant_id=tenant AND r.asset_id=asset_claim.asset_id AND r.version=asset_claim.from_version;
  SELECT jsonb_build_object('id',r.snapshot->'id','version',r.snapshot->'version','name',r.snapshot->'name','modelId',r.snapshot->'modelId','modelVersion',r.snapshot->'modelVersion','attributes',r.snapshot->'attributes','ownerId',r.snapshot->'ownerId','typeState',r.snapshot->'typeState') INTO after_snapshot FROM public.asset_revisions r WHERE r.tenant_id=tenant AND r.asset_id=asset_claim.asset_id AND r.version=asset_claim.to_version;
  IF row_value.id IS NULL OR row_value.version<>asset_claim.to_version OR public.gc_relation_asset_tuple(row_value) IS DISTINCT FROM asset_claim.after_tuple
   OR before_snapshot IS NULL OR after_snapshot IS NULL
   OR jsonb_build_object('modelId',before_snapshot->'modelId','modelVersion',before_snapshot->'modelVersion','attributes',before_snapshot->'attributes','ownerId',before_snapshot->'ownerId','state',before_snapshot->'typeState') IS DISTINCT FROM asset_claim.before_tuple
   OR jsonb_build_object('modelId',after_snapshot->'modelId','modelVersion',after_snapshot->'modelVersion','attributes',after_snapshot->'attributes','ownerId',after_snapshot->'ownerId','state',after_snapshot->'typeState') IS DISTINCT FROM asset_claim.after_tuple
   OR before_snapshot->>'id'<>asset_claim.asset_id::text OR after_snapshot->>'id'<>asset_claim.asset_id::text
   OR before_snapshot->>'version'<>asset_claim.from_version::text OR after_snapshot->>'version'<>asset_claim.to_version::text
   OR after_snapshot->>'name'<>row_value.name THEN
   RAISE EXCEPTION 'Asset outcome requires exact actual immutable before and after revisions' USING ERRCODE='23514'; END IF;
  IF asset_claim.action<>'preserve' AND NOT public.gc_relation_graph_journal(CASE asset_claim.action WHEN 'assign' THEN 'asset.model_assigned' WHEN 'transition' THEN 'asset.type_transitioned' ELSE 'asset.type_migrated' END,asset_claim.asset_id::text,asset_claim.to_version,op.actor_id,op.correlation_id) THEN
   RAISE EXCEPTION 'Changed asset requires its exact paired journal' USING ERRCODE='23514'; END IF;
  asset_refs:=asset_refs||jsonb_build_array(jsonb_build_object('assetId',asset_claim.asset_id,'role',CASE WHEN asset_claim.action='preserve' THEN 'validation-only' ELSE 'changed' END,
   'before',jsonb_build_object('id',asset_claim.asset_id,'version',asset_claim.from_version),'after',jsonb_build_object('id',asset_claim.asset_id,'version',asset_claim.to_version)));
 END LOOP;
 FOR edge_claim IN SELECT * FROM public.relation_graph_operation_edge_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation ORDER BY c.relation_type_id,c.key->>'kind',coalesce(c.key->>'relationId',c.key->>'key') LOOP
  SELECT * INTO edge FROM public.relations r WHERE r.tenant_id=tenant AND r.id=edge_claim.relation_id;
  SELECT r.snapshot INTO before_snapshot FROM public.relation_revisions r WHERE r.tenant_id=tenant AND r.relation_id=edge_claim.relation_id AND r.version=edge_claim.from_version;
  SELECT r.snapshot INTO after_snapshot FROM public.relation_revisions r WHERE r.tenant_id=tenant AND r.relation_id=edge_claim.relation_id AND r.version=edge_claim.to_version;
  IF edge.id IS NULL OR edge.version<>edge_claim.to_version OR after_snapshot IS NULL
   OR edge.relation_type_version<>(edge_claim.after_tuple->>'relationTypeVersion')::integer
   OR edge.status<>edge_claim.after_tuple->>'status' OR public.gc_relation_values(edge) IS DISTINCT FROM edge_claim.after_tuple->'values'
   OR (after_snapshot-ARRAY['source','target']) IS DISTINCT FROM public.gc_relation_snapshot_base(edge)
   OR (edge_claim.from_version IS NOT NULL AND before_snapshot IS NULL) THEN RAISE EXCEPTION 'Edge receipt outcome does not match actual immutable history' USING ERRCODE='23514'; END IF;
  IF edge_claim.action<>'preserve' THEN
   expected_action:=CASE WHEN edge_claim.action='create' THEN 'relation.created' WHEN edge.status='tombstoned' THEN 'relation.tombstoned'
    WHEN edge_claim.before_tuple->'values'->'state' IS DISTINCT FROM edge_claim.after_tuple->'values'->'state' THEN 'relation.transitioned' ELSE 'relation.updated' END;
   IF NOT public.gc_relation_graph_journal(expected_action,edge.id::text,edge.version,op.actor_id,op.correlation_id) THEN RAISE EXCEPTION 'Claimed edge requires its paired journal' USING ERRCODE='23514'; END IF;
  END IF;
  IF edge_claim.before_tuple IS NOT NULL AND EXISTS(SELECT 1 FROM public.relation_type_versions v WHERE v.tenant_id=tenant AND v.relation_type_id=edge.relation_type_id
   AND v.version=(edge_claim.before_tuple->>'relationTypeVersion')::integer AND v.definition->>'requiredOwner'='true')
   AND NOT EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id WHERE m.tenant_id=tenant
    AND m.identity_id=(edge_claim.before_tuple->'values'->>'ownerId')::uuid AND m.active AND i.active) THEN
   source_issues:=source_issues||jsonb_build_array(jsonb_build_object('kind','relation','issue',jsonb_build_object('code','source_required_owner_inactive',
    'relationId',edge.id,'ownerId',edge_claim.before_tuple->'values'->'ownerId')));
  END IF;
  outcomes:=outcomes||jsonb_build_array(jsonb_build_object('key',edge_claim.key,'role',edge_claim.role,'action',edge_claim.action,
   'before',CASE WHEN edge_claim.from_version IS NULL THEN NULL ELSE jsonb_build_object('id',edge.id,'version',edge_claim.from_version) END,
   'after',jsonb_build_object('id',edge.id,'version',edge_claim.to_version),'beforeTupleHash',public.gc_type_migration_hash(before_snapshot),'afterTupleHash',public.gc_type_migration_hash(after_snapshot)));
 END LOOP;
 FOR binding_claim IN SELECT * FROM public.relation_graph_operation_binding_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation ORDER BY c.relation_type_id,c.key->>'kind',coalesce(c.key->>'bindingId',c.key->>'assetId'),c.key->>'side' LOOP
  SELECT * INTO binding FROM public.relation_participations p WHERE p.tenant_id=tenant AND p.id=binding_claim.binding_id;
  SELECT r.snapshot INTO before_snapshot FROM public.relation_participation_revisions r WHERE r.tenant_id=tenant AND r.binding_id=binding_claim.binding_id AND r.version=binding_claim.from_version;
  SELECT r.snapshot INTO after_snapshot FROM public.relation_participation_revisions r WHERE r.tenant_id=tenant AND r.binding_id=binding_claim.binding_id AND r.version=binding_claim.to_version;
  IF binding.id IS NULL OR binding.version<>binding_claim.to_version OR after_snapshot IS DISTINCT FROM public.gc_relation_binding_snapshot(binding)
   OR (binding_claim.from_version IS NOT NULL AND before_snapshot IS NULL) THEN RAISE EXCEPTION 'Binding receipt outcome does not match actual immutable history' USING ERRCODE='23514'; END IF;
  IF binding_claim.action<>'preserve' THEN
   expected_action:=CASE binding_claim.action WHEN 'enroll' THEN 'relation_participation.enrolled' WHEN 'repin' THEN 'relation_participation.repinned' ELSE 'relation_participation.released' END;
   IF NOT public.gc_relation_graph_journal(expected_action,binding.id::text,binding.version,op.actor_id,op.correlation_id) THEN RAISE EXCEPTION 'Binding outcome requires its paired journal' USING ERRCODE='23514'; END IF;
  END IF;
  binding_outcomes:=binding_outcomes||jsonb_build_array(jsonb_build_object('key',binding_claim.key,'role',binding_claim.role,'action',binding_claim.action,
   'before',CASE WHEN binding_claim.from_version IS NULL THEN NULL ELSE jsonb_build_object('id',binding.id,'version',binding_claim.from_version) END,
   'after',jsonb_build_object('id',binding.id,'version',binding_claim.to_version),'beforeTupleHash',public.gc_type_migration_hash(before_snapshot),'afterTupleHash',public.gc_type_migration_hash(after_snapshot)));
 END LOOP;
 policies:='[]';
 FOR target IN SELECT jsonb_build_object('relationTypeId',relation_type_id,'definition',definition,'model',public.gc_relation_model(definition)) FROM (
  SELECT c.relation_type_id,c.after_definition AS definition FROM public.relation_graph_operation_type_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation
  UNION SELECT c.relation_type_id,c.before_definition FROM public.relation_graph_operation_type_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.before_definition IS NOT NULL
  UNION SELECT v.relation_type_id,v.definition FROM public.relation_type_versions v WHERE v.tenant_id=tenant AND EXISTS(
   SELECT 1 FROM public.relation_graph_operation_edge_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.relation_type_id=v.relation_type_id
    AND v.version IN((c.before_tuple->>'relationTypeVersion')::integer,(c.after_tuple->>'relationTypeVersion')::integer))
  UNION SELECT v.relation_type_id,v.definition FROM public.relation_type_versions v WHERE v.tenant_id=tenant AND EXISTS(
   SELECT 1 FROM public.relation_graph_operation_binding_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.relation_type_id=v.relation_type_id
    AND v.version IN((c.before_tuple->>'relationTypeVersion')::integer,(c.after_tuple->>'relationTypeVersion')::integer))) exact_policies ORDER BY relation_type_id,(definition->>'version')::integer LOOP
  PERFORM public.gc_relation_graph_charge(selected_operation,target);policies:=policies||jsonb_build_array(target);
 END LOOP;
 SELECT coalesce(jsonb_agg(jsonb_build_object('relationTypeId',c.relation_type_id,'mode',c.mode,'beforeVersion',c.before_version,'afterVersion',c.after_version,
  'definitionHash',public.gc_type_migration_hash(c.after_definition),'resolutionHash',public.gc_type_migration_hash(jsonb_build_object('definition',c.after_definition,'model',public.gc_relation_model(c.after_definition))),
  'beforeStructuralFingerprint',public.gc_type_migration_hash(public.gc_relation_structural_policy(c.before_definition)),
  'afterStructuralFingerprint',public.gc_type_migration_hash(public.gc_relation_structural_policy(c.after_definition)),
  'policyChanges',public.gc_relation_policy_changes(CASE WHEN c.mode='publish' THEN c.before_definition ELSE NULL END,c.after_definition),
  'attributeChanges',CASE WHEN c.mode='publish' THEN public.gc_relation_schema_changes(jsonb_build_object('type','object','properties',c.before_definition->'attributes'),jsonb_build_object('type','object','properties',c.after_definition->'attributes')) ELSE '[]'::jsonb END)
  ORDER BY c.relation_type_id),'[]') INTO targets FROM public.relation_graph_operation_type_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.mode<>'validation';
 SELECT coalesce(jsonb_agg(jsonb_build_object('assetId',c.asset_id,'name',c.before_row->'name') ORDER BY c.asset_id),'[]') INTO identities
  FROM public.relation_graph_operation_asset_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation;
 before_graph:=public.gc_relation_graph_snapshot(selected_operation,false);after_graph:=public.gc_relation_graph_snapshot(selected_operation,true);
 asset_changes:=public.gc_relation_graph_asset_preparation(selected_operation);
 SELECT source_issues||coalesce(jsonb_agg(jsonb_build_object('kind','asset','assetId',c->'assetId','issue',issue) ORDER BY c->>'assetId',issue->>'path'),'[]') INTO source_issues
  FROM jsonb_array_elements(asset_changes->'changes') a(c) CROSS JOIN LATERAL jsonb_array_elements(c->'sourceIssues') e(issue);
 IF jsonb_array_length(source_issues)>100 THEN RAISE EXCEPTION 'RELATION_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('relationTypeId',c.relation_type_id,'key',c.key->'key','relationId',c.relation_id) ORDER BY c.relation_type_id,c.key->>'key'),'[]') INTO creations
  FROM public.relation_graph_operation_edge_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.action='create';
 SELECT coalesce(jsonb_agg(jsonb_build_object('relationTypeId',c.relation_type_id,'assetId',c.key->'assetId','side',c.key->'side','bindingId',c.binding_id) ORDER BY c.relation_type_id,c.key->>'assetId',c.key->>'side'),'[]') INTO enrollments
  FROM public.relation_graph_operation_binding_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.action='enroll';
 SELECT coalesce(jsonb_agg(jsonb_build_object('predecessorId',e->'relationId','successorId',c.relation_id,'relationTypeId',t.relation_type_id,'creationKey',e->'creationKey') ORDER BY t.relation_type_id,e->>'relationId'),'[]') INTO replacements
  FROM public.relation_graph_operation_type_claims t CROSS JOIN LATERAL jsonb_array_elements(coalesce(t.plan->'edges','[]')) d(e)
  JOIN public.relation_graph_operation_edge_claims c ON c.tenant_id=t.tenant_id AND c.operation_id=t.operation_id AND c.relation_type_id=t.relation_type_id AND c.key->'key'=e->'creationKey' AND c.action='create'
  WHERE t.tenant_id=tenant AND t.operation_id=selected_operation AND e->>'action'='replace';
 IF EXISTS(SELECT 1 FROM public.relation_graph_operation_model_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND NOT EXISTS(
  SELECT 1 FROM public.asset_type_migrations m WHERE m.tenant_id=tenant AND m.id=c.migration_id AND m.model_id=c.model_id AND m.type_id=c.type_id
   AND m.from_version=c.before_version AND m.to_version=c.after_version AND m.plan=c.plan AND m.executed_by=op.actor_id)) THEN
  RAISE EXCEPTION 'Nested typed receipt is incomplete' USING ERRCODE='23514'; END IF;
 IF EXISTS(SELECT 1 FROM public.relation_graph_operation_model_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation
  AND NOT public.gc_relation_graph_journal('model.type_migrated',c.model_id,c.after_version,op.actor_id,op.correlation_id)) THEN
  RAISE EXCEPTION 'Nested model migration requires its exact paired journal' USING ERRCODE='23514'; END IF;
 SELECT coalesce(jsonb_agg(jsonb_build_object('modelId',c.model_id,'typeId',c.type_id,'migrationId',c.migration_id,'fromVersion',c.before_version,'toVersion',c.after_version) ORDER BY c.model_id COLLATE "C"),'[]') INTO nested
  FROM public.relation_graph_operation_model_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation;
 receipt:=jsonb_build_object('id',op.id,'formatVersion',1,'coverage','complete-authorized-affected-graph','executedBy',op.actor_id,
  'executedAt',public.gc_relation_utc(op.created_at),'correlationId',op.correlation_id,'repairsReceiptId',op.normalized_change_set->'repairsReceiptId',
  'changeSet',op.normalized_change_set,'requestHash',op.request_hash,'changeSetHash',public.gc_type_migration_hash(op.normalized_change_set),
  'previewDigest',op.request_body->'previewDigest','policies',policies,'targets',targets,'before',before_graph,'after',after_graph,
  'assetIdentities',identities,'assetChanges',asset_changes,'sourceIssues',source_issues,'edgeOutcomes',outcomes,'bindingOutcomes',binding_outcomes,
  'assetRevisions',asset_refs,'creations',creations,'enrollments',enrollments,'replacements',replacements,'nestedTypeReceipts',nested);
 PERFORM public.gc_relation_graph_charge(selected_operation,receipt);
 IF NOT public.gc_relation_json_bounded(receipt,100000,32,524288) OR octet_length(public.gc_type_migration_canonical(receipt))>524288 THEN
  RAISE EXCEPTION 'RELATION_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 IF NOT public.gc_relation_graph_journal('relation_migration.executed',op.id::text,1,op.actor_id,op.correlation_id) THEN
  RAISE EXCEPTION 'Graph execution requires its paired operation journal before sealing' USING ERRCODE='23514'; END IF;
 UPDATE public.relation_graph_operations o SET receipt=seal_context.receipt,state='sealed' WHERE o.tenant_id=tenant AND o.id=selected_operation;
 INSERT INTO public.relation_graph_receipts(tenant_id,id,receipt,executed_by,executed_at) VALUES(tenant,op.id,receipt,op.actor_id,op.created_at);
 INSERT INTO public.relation_graph_receipt_types(tenant_id,operation_id,relation_type_id,before_version,after_version,definition_hash,resolution_hash)
 SELECT tenant,op.id,(t->>'relationTypeId')::uuid,(t->>'beforeVersion')::integer,(t->>'afterVersion')::integer,t->>'definitionHash',t->>'resolutionHash' FROM jsonb_array_elements(targets) e(t);
 INSERT INTO public.relation_graph_receipt_edges(tenant_id,operation_id,relation_id,key,role,action,before_version,after_version,before_tuple_hash,after_tuple_hash)
 SELECT tenant,op.id,(e->'after'->>'id')::uuid,e->'key',e->>'role',e->>'action',(e->'before'->>'version')::integer,(e->'after'->>'version')::integer,e->>'beforeTupleHash',e->>'afterTupleHash' FROM jsonb_array_elements(outcomes) r(e);
 INSERT INTO public.relation_graph_receipt_bindings(tenant_id,operation_id,binding_id,key,role,action,before_version,after_version,before_tuple_hash,after_tuple_hash)
 SELECT tenant,op.id,(e->'after'->>'id')::uuid,e->'key',e->>'role',e->>'action',(e->'before'->>'version')::integer,(e->'after'->>'version')::integer,e->>'beforeTupleHash',e->>'afterTupleHash' FROM jsonb_array_elements(binding_outcomes) r(e);
 INSERT INTO public.relation_graph_receipt_assets(tenant_id,operation_id,asset_id,role,before_version,after_version)
 SELECT tenant,op.id,(e->>'assetId')::uuid,e->>'role',(e->'before'->>'version')::integer,(e->'after'->>'version')::integer FROM jsonb_array_elements(asset_refs) r(e);
 INSERT INTO public.relation_graph_receipt_type_migrations(tenant_id,operation_id,migration_id)
 SELECT tenant,op.id,(e->>'migrationId')::uuid FROM jsonb_array_elements(nested) r(e);
 INSERT INTO public.relation_graph_replacements(tenant_id,operation_id,predecessor_id,successor_id,relation_type_id,creation_key)
 SELECT tenant,op.id,(e->>'predecessorId')::uuid,(e->>'successorId')::uuid,(e->>'relationTypeId')::uuid,e->>'creationKey' FROM jsonb_array_elements(replacements) r(e);
 RETURN receipt;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_seal(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_graph_seal(uuid) TO gc_app;

CREATE FUNCTION public.gc_relation_graph_finalize() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.relation_graph_operations; type_identity uuid;
BEGIN
 SELECT * INTO op FROM public.relation_graph_operations o WHERE o.tenant_id=NEW.tenant_id AND o.id=NEW.id;
 IF op.id IS NULL OR op.transaction_id<>pg_current_xact_id() OR op.tenant_id IS DISTINCT FROM public.gc_tenant() OR op.actor_id::text IS DISTINCT FROM public.gc_actor() THEN
  RAISE EXCEPTION 'Untrusted graph finalization' USING ERRCODE='42501'; END IF;
 IF op.state='finalized' THEN RETURN NEW; END IF;
 IF clock_timestamp()>=op.created_at+interval '30 seconds' THEN RAISE EXCEPTION 'Graph operation deadline exceeded' USING ERRCODE='57014'; END IF;
 IF op.state<>'sealed' OR NOT EXISTS(SELECT 1 FROM public.idempotency i WHERE i.tenant_id=op.tenant_id AND i.actor_id=op.actor_id::text
  AND i.operation=op.idempotency_operation AND i.key=op.idempotency_key AND i.request_hash=op.request_hash AND i.response=jsonb_build_object('receipt',op.receipt))
  OR NOT EXISTS(SELECT 1 FROM public.relation_graph_receipts r WHERE r.tenant_id=op.tenant_id AND r.id=op.id AND r.receipt=op.receipt) THEN
  RAISE EXCEPTION 'Graph operation cannot commit without exact sealed receipt and idempotency success' USING ERRCODE='23514'; END IF;
 PERFORM public.gc_relation_authorize(ARRAY['models:read','models:write','catalog:read','catalog:write']);
 IF (SELECT count(*) FROM public.relation_graph_receipt_edges c WHERE c.tenant_id=op.tenant_id AND c.operation_id=op.id)<>jsonb_array_length(op.receipt->'edgeOutcomes')
  OR (SELECT count(*) FROM public.relation_graph_receipt_bindings c WHERE c.tenant_id=op.tenant_id AND c.operation_id=op.id)<>jsonb_array_length(op.receipt->'bindingOutcomes')
  OR (SELECT count(*) FROM public.relation_graph_receipt_assets c WHERE c.tenant_id=op.tenant_id AND c.operation_id=op.id)<>jsonb_array_length(op.receipt->'assetRevisions')
  OR (SELECT count(*) FROM public.relation_graph_receipt_types c WHERE c.tenant_id=op.tenant_id AND c.operation_id=op.id)<>jsonb_array_length(op.receipt->'targets')
  OR (SELECT count(*) FROM public.relation_graph_receipt_type_migrations c WHERE c.tenant_id=op.tenant_id AND c.operation_id=op.id)<>jsonb_array_length(op.receipt->'nestedTypeReceipts')
  OR (SELECT count(*) FROM public.relation_graph_replacements c WHERE c.tenant_id=op.tenant_id AND c.operation_id=op.id)<>jsonb_array_length(op.receipt->'replacements') THEN
  RAISE EXCEPTION 'Every exact receipt outcome requires its immutable normalized reference' USING ERRCODE='23514'; END IF;
 FOR type_identity IN SELECT c.relation_type_id FROM public.relation_graph_operation_type_claims c WHERE c.tenant_id=op.tenant_id AND c.operation_id=op.id ORDER BY c.relation_type_id LOOP
  PERFORM public.gc_relation_check_type(op.tenant_id,type_identity);
 END LOOP;
 IF EXISTS(SELECT 1 FROM public.relation_validation_work w WHERE w.tenant_id=op.tenant_id AND w.transaction_id=op.transaction_id
  AND NOT EXISTS(SELECT 1 FROM public.relation_graph_operation_type_claims c WHERE c.tenant_id=op.tenant_id AND c.operation_id=op.id AND c.relation_type_id=w.relation_type_id)) THEN
  RAISE EXCEPTION 'Unclaimed graph validation scope cannot commit' USING ERRCODE='23514'; END IF;
 DELETE FROM public.relation_validation_work WHERE tenant_id=op.tenant_id AND transaction_id=op.transaction_id;
 IF clock_timestamp()>=op.created_at+interval '30 seconds' THEN RAISE EXCEPTION 'Graph operation deadline exceeded' USING ERRCODE='57014'; END IF;
 UPDATE public.relation_graph_operations SET state='finalized' WHERE tenant_id=op.tenant_id AND id=op.id;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_finalize() FROM PUBLIC,gc_app;
CREATE CONSTRAINT TRIGGER relation_graph_finalize AFTER INSERT ON public.relation_graph_operations
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_relation_graph_finalize();

CREATE FUNCTION public.gc_relation_graph_transform_intent(transform jsonb,owner_key text,cohort jsonb,head_policy jsonb,target_policy jsonb,relation_identity uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE entry jsonb; expected jsonb; previous text; previous_version integer:=0; source_policy jsonb; logical_key text:=head_policy->'model'->>'id';
BEGIN
 IF NOT public.gc_relation_keys(transform,ARRAY['attributes','owner','lifecycle'])
  OR NOT public.gc_relation_keys(transform->'owner',ARRAY['default','overrides']) OR transform->'owner'->>'default' IS DISTINCT FROM 'preserve'
  OR jsonb_typeof(transform->'owner'->'overrides')<>'array' OR jsonb_array_length(transform->'owner'->'overrides')>1000
  OR NOT public.gc_relation_keys(transform->'lifecycle',ARRAY['onUnmapped','mappings']) OR jsonb_typeof(transform->'lifecycle'->'onUnmapped') IS DISTINCT FROM 'string' OR transform->'lifecycle'->>'onUnmapped' NOT IN ('preserve','error')
  OR jsonb_typeof(transform->'lifecycle'->'mappings')<>'array' OR jsonb_array_length(transform->'lifecycle'->'mappings')>1000 THEN
  RAISE EXCEPTION 'Invalid bounded owner or lifecycle transform' USING ERRCODE='23514'; END IF;
 SELECT coalesce(jsonb_agg(version ORDER BY version),'[]') INTO expected FROM (SELECT DISTINCT (v->>'version')::integer AS version FROM jsonb_array_elements(cohort) e(v)) pins;
 IF transform->'attributes'->'sourceVersions' IS DISTINCT FROM expected THEN RAISE EXCEPTION 'Transform pins must equal its exact transformed cohort' USING ERRCODE='23514'; END IF;
 PERFORM public.gc_relation_attribute_transform(head_policy->'model',head_policy->'model',target_policy->'model',transform->'attributes','{}',true);
 FOR entry IN SELECT v FROM jsonb_array_elements(transform->'owner'->'overrides') e(v) LOOP
  IF NOT public.gc_relation_keys(entry,ARRAY[owner_key,'ownerId']) OR NOT public.gc_relation_uuid_list(jsonb_build_array(entry->owner_key),1)
   OR (entry->'ownerId'<>'null' AND NOT public.gc_relation_uuid_list(jsonb_build_array(entry->'ownerId'),1))
   OR (previous IS NOT NULL AND (entry->>owner_key) COLLATE "C"<=previous COLLATE "C")
   OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(cohort) e(v) WHERE v->'id'=entry->owner_key) THEN
   RAISE EXCEPTION 'Overrides must be sorted unique exact transformed members' USING ERRCODE='23514'; END IF;
  IF entry->'ownerId'<>'null' AND NOT EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id
   WHERE m.tenant_id=public.gc_tenant() AND m.identity_id=(entry->>'ownerId')::uuid AND m.active AND i.active) THEN
   RAISE EXCEPTION 'Explicit transformed owner must be active in this tenant' USING ERRCODE='23514'; END IF;
  IF entry->'ownerId'='null' AND target_policy->>'requiredOwner'='true' THEN RAISE EXCEPTION 'Required ownership cannot be removed from one outcome' USING ERRCODE='23514'; END IF;
  previous:=entry->>owner_key;
 END LOOP;
 previous:=NULL;
 FOR entry IN SELECT v FROM jsonb_array_elements(transform->'lifecycle'->'mappings') e(v) LOOP
  IF NOT public.gc_relation_keys(entry,ARRAY['sourceVersion','from','to']) OR jsonb_typeof(entry->'sourceVersion')<>'number'
   OR entry->>'sourceVersion' !~ '^[1-9][0-9]{0,9}$' OR (entry->>'sourceVersion')::numeric>2147483647
   OR NOT public.gc_relation_safe_id(entry->>'from') OR NOT public.gc_relation_safe_id(entry->>'to')
   OR NOT expected @> jsonb_build_array(entry->'sourceVersion')
   OR (entry->>'sourceVersion')::integer<previous_version
   OR ((entry->>'sourceVersion')::integer=previous_version AND (entry->>'from') COLLATE "C"<=previous COLLATE "C") THEN
   RAISE EXCEPTION 'Lifecycle mappings require unique exact source-pin state pairs' USING ERRCODE='23514'; END IF;
  IF relation_identity IS NULL THEN
   SELECT v.resolved INTO source_policy FROM public.asset_type_versions v WHERE v.tenant_id=public.gc_tenant() AND v.model_id=logical_key AND v.version=(entry->>'sourceVersion')::integer;
  ELSE
   SELECT v.definition INTO source_policy FROM public.relation_type_versions v WHERE v.tenant_id=public.gc_tenant() AND v.relation_type_id=relation_identity AND v.version=(entry->>'sourceVersion')::integer;
  END IF;
  IF source_policy IS NULL OR NOT source_policy->'lifecycle'->'states' @> jsonb_build_array(entry->'from')
   OR NOT target_policy->'lifecycle'->'states' @> jsonb_build_array(entry->'to') THEN
   RAISE EXCEPTION 'Lifecycle mapping must bind valid states of exact policies' USING ERRCODE='23514'; END IF;
  previous_version:=(entry->>'sourceVersion')::integer;previous:=entry->>'from';
 END LOOP;
END $$;
CREATE FUNCTION public.gc_relation_graph_validate_intents(selected_operation uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant(); request jsonb; t record; m record; a record; cohort jsonb; expected jsonb; acknowledgements jsonb;
 old_policy jsonb; new_policy jsonb; explicit_owner jsonb; before_active boolean; after_active boolean;
BEGIN
 SELECT jsonb_build_object('changeSet',o.normalized_change_set) INTO request FROM public.relation_graph_operations o WHERE o.tenant_id=tenant AND o.id=selected_operation AND o.transaction_id=pg_current_xact_id() AND o.state='open';
 IF request IS NULL THEN RAISE EXCEPTION 'Intent validation requires the actual open operation' USING ERRCODE='42501'; END IF;
 FOR t IN SELECT * FROM public.relation_graph_operation_type_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.plan->'transform'<>'null' LOOP
  SELECT coalesce(jsonb_agg(jsonb_build_object('id',r.id,'version',r.relation_type_version) ORDER BY r.id),'[]') INTO cohort
   FROM public.relations r JOIN jsonb_array_elements(t.plan->'edges') e(v) ON v->>'relationId'=r.id::text
   WHERE r.tenant_id=tenant AND r.relation_type_id=t.relation_type_id AND r.status='active' AND v->>'action'='migrate';
  PERFORM public.gc_relation_graph_transform_intent(t.plan->'transform','relationId',cohort,
   t.before_definition||jsonb_build_object('model',public.gc_relation_model(t.before_definition)),
   t.after_definition||jsonb_build_object('model',public.gc_relation_model(t.after_definition)),t.relation_type_id);
 END LOOP;
 FOR m IN SELECT * FROM public.relation_graph_operation_model_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation LOOP
  IF NOT public.gc_relation_keys(m.plan,ARRAY['formatVersion','typeId','attributes','owner','lifecycle','acknowledgedPolicyChanges'])
   OR m.plan->'formatVersion'<>'1' OR m.plan->>'typeId'<>m.type_id::text OR jsonb_typeof(m.plan->'acknowledgedPolicyChanges')<>'array' THEN
   RAISE EXCEPTION 'Invalid nested authored migration plan' USING ERRCODE='23514'; END IF;
  SELECT coalesce(jsonb_agg(code ORDER BY code COLLATE "C"),'[]') INTO expected FROM (VALUES
   ('parents_changed',public.gc_relation_sorted_pins(m.before_resolution->'definition'->'parents') IS DISTINCT FROM public.gc_relation_sorted_pins(m.after_resolution->'definition'->'parents')),
   ('required_owner_changed',m.before_resolution->'requiredOwner' IS DISTINCT FROM m.after_resolution->'requiredOwner'),
   ('lifecycle_changed',m.before_resolution->'lifecycle' IS DISTINCT FROM m.after_resolution->'lifecycle')) diffs(code,changed) WHERE changed;
  SELECT coalesce(jsonb_agg(v ORDER BY v#>>'{}'),'[]') INTO acknowledgements FROM jsonb_array_elements(m.plan->'acknowledgedPolicyChanges') e(v);
  IF expected IS DISTINCT FROM acknowledgements THEN RAISE EXCEPTION 'Exact authored policy acknowledgements are required' USING ERRCODE='23514'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('id',ac.asset_id,'version',ac.before_tuple->'modelVersion') ORDER BY ac.asset_id),'[]') INTO cohort
   FROM public.relation_graph_operation_asset_claims ac WHERE ac.tenant_id=tenant AND ac.operation_id=selected_operation AND ac.action='type-migrate' AND ac.before_tuple->>'modelId'=m.model_id;
  PERFORM public.gc_relation_graph_transform_intent(jsonb_build_object('attributes',m.plan->'attributes','owner',m.plan->'owner','lifecycle',m.plan->'lifecycle'),
   'assetId',cohort,m.before_resolution,m.after_resolution,NULL);
 END LOOP;
 FOR a IN SELECT * FROM public.relation_graph_operation_asset_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.action<>'preserve' LOOP
  old_policy:=public.gc_relation_graph_asset_policy(a.before_tuple->>'modelId',(a.before_tuple->>'modelVersion')::integer,request);
  new_policy:=public.gc_relation_graph_asset_policy(a.after_tuple->>'modelId',(a.after_tuple->>'modelVersion')::integer,request);
  SELECT EXISTS(SELECT 1 FROM public.memberships member JOIN public.identities i ON i.id=member.identity_id
   WHERE member.tenant_id=tenant AND member.identity_id=(a.before_tuple->>'ownerId')::uuid AND member.active AND i.active) INTO before_active;
  SELECT EXISTS(SELECT 1 FROM public.memberships member JOIN public.identities i ON i.id=member.identity_id
   WHERE member.tenant_id=tenant AND member.identity_id=(a.after_tuple->>'ownerId')::uuid AND member.active AND i.active) INTO after_active;
  IF new_policy->>'requiredOwner'='true' AND NOT after_active THEN RAISE EXCEPTION 'Target asset requires an active owner' USING ERRCODE='23514'; END IF;
  IF a.action='type-migrate' AND old_policy->>'requiredOwner'='true' AND NOT before_active THEN
   SELECT * INTO m FROM public.relation_graph_operation_model_claims c WHERE c.tenant_id=tenant AND c.operation_id=selected_operation AND c.model_id=a.before_tuple->>'modelId';
   SELECT v->'ownerId' INTO explicit_owner FROM jsonb_array_elements(m.plan->'owner'->'overrides') e(v) WHERE v->>'assetId'=a.asset_id::text;
   IF NOT ((explicit_owner IS NOT NULL AND explicit_owner<>'null' AND after_active)
    OR (new_policy->>'requiredOwner'='false' AND m.plan->'acknowledgedPolicyChanges' @> '["required_owner_changed"]')) THEN
    RAISE EXCEPTION 'Invalid required source asset owner needs an explicit authorized repair' USING ERRCODE='23514'; END IF;
  END IF;
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_validate_intents(uuid) FROM PUBLIC,gc_app;

CREATE FUNCTION public.gc_relation_graph_receipt_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.relation_graph_operations; payload jsonb; normalized jsonb:=to_jsonb(NEW)-ARRAY['tenant_id','operation_id']; valid boolean:=false;
BEGIN
 op:=public.gc_relation_graph_current();
 IF op.id IS NULL OR op.state<>'sealed' OR NEW.tenant_id IS DISTINCT FROM op.tenant_id OR op.actor_id::text IS DISTINCT FROM public.gc_actor() THEN
  RAISE EXCEPTION 'Receipt storage derives only from the actual sealed operation' USING ERRCODE='42501'; END IF;
 IF TG_RELID='public.relation_graph_receipts'::regclass THEN
  IF NEW.id<>op.id OR NEW.receipt IS DISTINCT FROM op.receipt OR NEW.executed_by<>op.actor_id OR NEW.executed_at<>op.created_at THEN
   RAISE EXCEPTION 'Receipt must equal its protected sealed result' USING ERRCODE='23514'; END IF;
  RETURN NEW;
 END IF;
 IF NEW.operation_id<>op.id THEN RAISE EXCEPTION 'Normalized receipt children cannot cross operations' USING ERRCODE='23514'; END IF;
 payload:=op.receipt;
 IF TG_RELID='public.relation_graph_receipt_edges'::regclass THEN
  SELECT EXISTS(SELECT 1 FROM jsonb_array_elements(payload->'edgeOutcomes') e(v) WHERE normalized=jsonb_build_object(
   'relation_id',v->'after'->'id','key',v->'key','role',v->'role','action',v->'action','before_version',v->'before'->'version','after_version',v->'after'->'version',
   'before_tuple_hash',v->'beforeTupleHash','after_tuple_hash',v->'afterTupleHash')) INTO valid;
 ELSIF TG_RELID='public.relation_graph_receipt_bindings'::regclass THEN
  SELECT EXISTS(SELECT 1 FROM jsonb_array_elements(payload->'bindingOutcomes') e(v) WHERE normalized=jsonb_build_object(
   'binding_id',v->'after'->'id','key',v->'key','role',v->'role','action',v->'action','before_version',v->'before'->'version','after_version',v->'after'->'version',
   'before_tuple_hash',v->'beforeTupleHash','after_tuple_hash',v->'afterTupleHash')) INTO valid;
 ELSIF TG_RELID='public.relation_graph_receipt_assets'::regclass THEN
  SELECT EXISTS(SELECT 1 FROM jsonb_array_elements(payload->'assetRevisions') e(v) WHERE normalized=jsonb_build_object(
   'asset_id',v->'assetId','role',v->'role','before_version',v->'before'->'version','after_version',v->'after'->'version')) INTO valid;
 ELSIF TG_RELID='public.relation_graph_receipt_types'::regclass THEN
  SELECT EXISTS(SELECT 1 FROM jsonb_array_elements(payload->'targets') e(v) WHERE normalized=jsonb_build_object(
   'relation_type_id',v->'relationTypeId','before_version',v->'beforeVersion','after_version',v->'afterVersion','definition_hash',v->'definitionHash','resolution_hash',v->'resolutionHash')) INTO valid;
 ELSIF TG_RELID='public.relation_graph_receipt_type_migrations'::regclass THEN
  SELECT EXISTS(SELECT 1 FROM jsonb_array_elements(payload->'nestedTypeReceipts') e(v) WHERE normalized=jsonb_build_object('migration_id',v->'migrationId')) INTO valid;
 ELSIF TG_RELID='public.relation_graph_replacements'::regclass THEN
  SELECT EXISTS(SELECT 1 FROM jsonb_array_elements(payload->'replacements') e(v) WHERE normalized=jsonb_build_object(
   'predecessor_id',v->'predecessorId','successor_id',v->'successorId','relation_type_id',v->'relationTypeId','creation_key',v->'creationKey')) INTO valid;
 END IF;
 IF NOT valid THEN RAISE EXCEPTION 'Normalized reference must equal a derived exact sealed outcome' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_receipt_guard() FROM PUBLIC,gc_app;
DO $$ DECLARE name text; BEGIN
 FOREACH name IN ARRAY ARRAY['relation_graph_receipts','relation_graph_receipt_edges','relation_graph_receipt_bindings','relation_graph_receipt_assets',
  'relation_graph_receipt_types','relation_graph_receipt_type_migrations','relation_graph_replacements'] LOOP
  EXECUTE format('CREATE TRIGGER protected_receipt_insert BEFORE INSERT ON public.%I FOR EACH ROW EXECUTE FUNCTION public.gc_relation_graph_receipt_guard()',name);
 END LOOP;
END $$;
CREATE FUNCTION public.gc_relation_graph_asset_delete_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
BEGIN
 IF (public.gc_relation_graph_current()).id IS NOT NULL THEN RAISE EXCEPTION 'Graph operations do not hard-delete assets' USING ERRCODE='23514'; END IF;
 RETURN OLD;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_asset_delete_guard() FROM PUBLIC,gc_app;
CREATE TRIGGER graph_asset_delete_guard BEFORE DELETE ON public.assets FOR EACH ROW EXECUTE FUNCTION public.gc_relation_graph_asset_delete_guard();

CREATE FUNCTION public.gc_relation_graph_repair_authorize(receipt_id uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant(); actor jsonb:=jsonb_build_array(public.gc_actor()); prior public.relation_graph_receipts;
BEGIN
 SELECT * INTO prior FROM public.relation_graph_receipts r WHERE r.tenant_id=tenant AND r.id=receipt_id;
 IF prior.id IS NULL THEN RAISE EXCEPTION 'RELATION_SCOPE_UNAVAILABLE' USING ERRCODE='42501'; END IF;
 IF EXISTS(SELECT 1 FROM public.relation_graph_operation_asset_claims c LEFT JOIN public.assets a ON a.tenant_id=c.tenant_id AND a.id=c.asset_id
  WHERE c.tenant_id=tenant AND c.operation_id=receipt_id AND (a.id IS NULL OR (a.visibility='restricted' AND NOT a.allowed_identities @> actor)
   OR (c.before_row->>'visibility'='restricted' AND NOT c.before_row->'allowed_identities' @> actor)))
  OR EXISTS(SELECT 1 FROM public.relation_graph_receipt_edges e JOIN public.relations r ON r.tenant_id=e.tenant_id AND r.id=e.relation_id
   JOIN public.relation_revisions h ON h.tenant_id=e.tenant_id AND h.relation_id=e.relation_id AND h.version=e.after_version
   LEFT JOIN public.relation_revisions b ON b.tenant_id=e.tenant_id AND b.relation_id=e.relation_id AND b.version=e.before_version
   WHERE e.tenant_id=tenant AND e.operation_id=receipt_id AND ((r.visibility='restricted' AND NOT r.allowed_identities @> actor)
    OR (h.snapshot->>'visibility'='restricted' AND NOT h.snapshot->'allowedIdentityIds' @> actor)
    OR (b.snapshot->>'visibility'='restricted' AND NOT b.snapshot->'allowedIdentityIds' @> actor))) THEN
  RAISE EXCEPTION 'RELATION_SCOPE_UNAVAILABLE' USING ERRCODE='42501'; END IF;
END $$;
REVOKE ALL ON FUNCTION public.gc_relation_graph_repair_authorize(uuid) FROM PUBLIC,gc_app;

REVOKE ALL ON FUNCTION public.gc_relation_type_head_guard(),public.gc_relation_type_version_guard(),public.gc_relation_publication_complete() FROM PUBLIC,gc_app;

