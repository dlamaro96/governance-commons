-- SPDX-License-Identifier: Apache-2.0
-- Forward-only SQL010 -> SQL011. Qualification candidate, not an applied migration.
-- Claims are private capabilities derived from locked canonical data, never GUCs.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR pg_has_role('gc_app',current_user,'MEMBER') THEN
  RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='42501';
 END IF;
END $$;
LOCK TABLE public.idempotency IN SHARE ROW EXCLUSIVE MODE;
DO $$ DECLARE t uuid; prior text:=current_setting('gc.tenant_id',true); BEGIN
 FOR t IN SELECT id FROM public.tenants ORDER BY id LOOP
  PERFORM set_config('gc.tenant_id',t::text,true);
  IF EXISTS(SELECT 1 FROM public.idempotency WHERE tenant_id=t AND operation IN
   ('domain-type.create','domain-type.publish','domain.create','domain.update','domain.state','domain.hierarchy','domain.placement','domain-type-migration.execute')) THEN
   RAISE EXCEPTION 'DOMAIN_RESERVED_NAMESPACE_COLLISION' USING ERRCODE='23514';
  END IF;
 END LOOP;
 PERFORM set_config('gc.tenant_id',coalesce(prior,''),true);
END $$;

CREATE TABLE public.domain_types (
 tenant_id uuid NOT NULL REFERENCES public.tenants(id), id uuid NOT NULL,
 key text NOT NULL CHECK(public.gc_relation_safe_id(key)), current_version integer NOT NULL CHECK(current_version>0),
 created_at timestamptz NOT NULL, created_by uuid NOT NULL,
 PRIMARY KEY(tenant_id,id), CONSTRAINT domain_types_tenant_key UNIQUE(tenant_id,key),
 FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id)
);
CREATE TABLE public.domain_type_versions (
 tenant_id uuid NOT NULL, type_id uuid NOT NULL, version integer NOT NULL CHECK(version>0),
 definition jsonb NOT NULL, resolved jsonb NOT NULL,
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[a-f0-9]{64}$'),
 resolution_hash text NOT NULL CHECK(resolution_hash ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL, created_by uuid NOT NULL,
 PRIMARY KEY(tenant_id,type_id,version),
 FOREIGN KEY(tenant_id,type_id) REFERENCES public.domain_types(tenant_id,id),
 FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id)
);
ALTER TABLE public.domain_types ADD CONSTRAINT domain_type_current_version
 FOREIGN KEY(tenant_id,id,current_version) REFERENCES public.domain_type_versions(tenant_id,type_id,version) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE public.domain_type_dependencies (
 tenant_id uuid NOT NULL, type_id uuid NOT NULL, version integer NOT NULL, parent_type_id uuid NOT NULL, parent_version integer NOT NULL,
 PRIMARY KEY(tenant_id,type_id,version,parent_type_id), CHECK(type_id<>parent_type_id),
 FOREIGN KEY(tenant_id,type_id,version) REFERENCES public.domain_type_versions(tenant_id,type_id,version),
 FOREIGN KEY(tenant_id,parent_type_id,parent_version) REFERENCES public.domain_type_versions(tenant_id,type_id,version)
);
CREATE TABLE public.domains (
 tenant_id uuid NOT NULL REFERENCES public.tenants(id), id uuid NOT NULL, name text NOT NULL, description text NOT NULL,
 parent_id uuid, type_id uuid NOT NULL, type_version integer NOT NULL, attributes jsonb NOT NULL, owner_id uuid,
 state text NOT NULL, status text NOT NULL CHECK(status IN ('active','retired')), version integer NOT NULL CHECK(version>0),
 created_at timestamptz NOT NULL, created_by uuid NOT NULL, updated_at timestamptz NOT NULL, updated_by uuid NOT NULL,
 PRIMARY KEY(tenant_id,id), CHECK(parent_id IS DISTINCT FROM id),
 FOREIGN KEY(tenant_id,parent_id) REFERENCES public.domains(tenant_id,id),
 FOREIGN KEY(tenant_id,type_id,type_version) REFERENCES public.domain_type_versions(tenant_id,type_id,version),
 FOREIGN KEY(tenant_id,owner_id) REFERENCES public.memberships(tenant_id,identity_id),
 FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id),
 FOREIGN KEY(tenant_id,updated_by) REFERENCES public.memberships(tenant_id,identity_id)
);
CREATE INDEX domain_parent ON public.domains(tenant_id,parent_id,id);
CREATE INDEX domain_type_pin ON public.domains(tenant_id,type_id,type_version,id);
CREATE TABLE public.domain_revisions (
 tenant_id uuid NOT NULL, domain_id uuid NOT NULL, version integer NOT NULL CHECK(version>0), snapshot jsonb NOT NULL,
 PRIMARY KEY(tenant_id,domain_id,version), FOREIGN KEY(tenant_id,domain_id) REFERENCES public.domains(tenant_id,id)
);
ALTER TABLE public.domains ADD CONSTRAINT domain_current_revision FOREIGN KEY(tenant_id,id,version)
 REFERENCES public.domain_revisions(tenant_id,domain_id,version) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE public.asset_domain_placements (
 tenant_id uuid NOT NULL, asset_id uuid NOT NULL, version integer NOT NULL CHECK(version>0), domain_id uuid,
 recorded_asset_version integer NOT NULL CHECK(recorded_asset_version>0), recorded_domain_version integer,
 recorded_at timestamptz NOT NULL, recorded_by uuid NOT NULL,
 PRIMARY KEY(tenant_id,asset_id), CHECK((domain_id IS NULL)=(recorded_domain_version IS NULL)),
 FOREIGN KEY(tenant_id,asset_id) REFERENCES public.assets(tenant_id,id),
 FOREIGN KEY(tenant_id,asset_id,recorded_asset_version) REFERENCES public.asset_revisions(tenant_id,asset_id,version),
 FOREIGN KEY(tenant_id,domain_id,recorded_domain_version) REFERENCES public.domain_revisions(tenant_id,domain_id,version),
 FOREIGN KEY(tenant_id,recorded_by) REFERENCES public.memberships(tenant_id,identity_id)
);
CREATE INDEX domain_placed_assets ON public.asset_domain_placements(tenant_id,domain_id,asset_id);
CREATE TABLE public.asset_domain_placement_revisions (
 tenant_id uuid NOT NULL, asset_id uuid NOT NULL, version integer NOT NULL CHECK(version>0), snapshot jsonb NOT NULL,
 PRIMARY KEY(tenant_id,asset_id,version), FOREIGN KEY(tenant_id,asset_id) REFERENCES public.asset_domain_placements(tenant_id,asset_id)
);
ALTER TABLE public.asset_domain_placements ADD CONSTRAINT placement_current_revision FOREIGN KEY(tenant_id,asset_id,version)
 REFERENCES public.asset_domain_placement_revisions(tenant_id,asset_id,version) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE public.domain_type_migrations (
 tenant_id uuid NOT NULL, id uuid NOT NULL, type_id uuid NOT NULL, from_head_version integer NOT NULL, target_version integer NOT NULL,
 plan jsonb NOT NULL, plan_hash text NOT NULL, preview_digest text NOT NULL,
 target_definition_hash text NOT NULL, target_resolution_hash text NOT NULL, source_policies jsonb NOT NULL,
 receipt jsonb NOT NULL, executed_by uuid NOT NULL, executed_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,id), CHECK(target_version::bigint=from_head_version::bigint+1),
 FOREIGN KEY(tenant_id,type_id,from_head_version) REFERENCES public.domain_type_versions(tenant_id,type_id,version),
 FOREIGN KEY(tenant_id,type_id,target_version) REFERENCES public.domain_type_versions(tenant_id,type_id,version),
 FOREIGN KEY(tenant_id,executed_by) REFERENCES public.memberships(tenant_id,identity_id)
);
CREATE TABLE public.domain_type_migration_domains (
 tenant_id uuid NOT NULL, migration_id uuid NOT NULL, domain_id uuid NOT NULL, from_version integer NOT NULL, to_version integer NOT NULL,
 before_tuple_hash text NOT NULL CHECK(before_tuple_hash ~ '^[a-f0-9]{64}$'), after_tuple_hash text NOT NULL CHECK(after_tuple_hash ~ '^[a-f0-9]{64}$'),
 PRIMARY KEY(tenant_id,migration_id,domain_id), CHECK(to_version::bigint=from_version::bigint+1),
 FOREIGN KEY(tenant_id,migration_id) REFERENCES public.domain_type_migrations(tenant_id,id),
 FOREIGN KEY(tenant_id,domain_id,from_version) REFERENCES public.domain_revisions(tenant_id,domain_id,version),
 FOREIGN KEY(tenant_id,domain_id,to_version) REFERENCES public.domain_revisions(tenant_id,domain_id,version)
);
CREATE TABLE public.domain_scope_state (
 tenant_id uuid PRIMARY KEY REFERENCES public.tenants(id), epoch bigint NOT NULL CHECK(epoch>=0)
);
CREATE TABLE public.domain_transaction_bindings (
 tenant_id uuid NOT NULL REFERENCES public.tenants(id), transaction_id xid8 NOT NULL, actor_id text NOT NULL,
 kind text NOT NULL CHECK(kind IN ('domain','legacy')), started_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,transaction_id), UNIQUE(transaction_id)
);
CREATE TABLE public.domain_operation_contexts (
 tenant_id uuid NOT NULL, id uuid NOT NULL, transaction_id xid8 NOT NULL, actor_id uuid NOT NULL, actor_name text NOT NULL,
 started_at timestamptz NOT NULL, occurred_at timestamptz NOT NULL, mode text NOT NULL CHECK(mode IN ('ordinary','migration')),
 namespace text NOT NULL, idempotency_key text NOT NULL, request_body jsonb NOT NULL, request_hash text NOT NULL,
 reason text NOT NULL, correlation_id text NOT NULL, permissions text[] NOT NULL,
 response jsonb, projection jsonb, projection_hash text, initial_epoch bigint NOT NULL, increments integer NOT NULL DEFAULT 0,
 retained_bytes bigint NOT NULL DEFAULT 0, retained_nodes bigint NOT NULL DEFAULT 0,
 state text NOT NULL DEFAULT 'open' CHECK(state IN ('open','sealed','finalized')), prepared boolean NOT NULL DEFAULT false,
 domain_scope uuid[] NOT NULL DEFAULT '{}', asset_scope uuid[] NOT NULL DEFAULT '{}', type_scope uuid[] NOT NULL DEFAULT '{}', principals uuid[] NOT NULL DEFAULT '{}',
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,transaction_id),
 FOREIGN KEY(tenant_id,transaction_id) REFERENCES public.domain_transaction_bindings(tenant_id,transaction_id),
 FOREIGN KEY(tenant_id,actor_id) REFERENCES public.memberships(tenant_id,identity_id)
);
CREATE TABLE public.domain_migration_operations (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, type_id uuid NOT NULL, from_head_version integer NOT NULL, target_version integer NOT NULL,
 source_policies jsonb NOT NULL, receipt jsonb NOT NULL, receipt_hash text NOT NULL,
 PRIMARY KEY(tenant_id,operation_id), FOREIGN KEY(tenant_id,operation_id) REFERENCES public.domain_operation_contexts(tenant_id,id)
);
CREATE TABLE public.domain_operation_type_claims (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, type_id uuid NOT NULL, role text NOT NULL CHECK(role IN ('create','publish','validate')),
 before_head jsonb, after_head jsonb, version_row jsonb, dependencies jsonb NOT NULL DEFAULT '[]',
 head_written boolean NOT NULL DEFAULT false, version_written boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,operation_id,type_id), FOREIGN KEY(tenant_id,operation_id) REFERENCES public.domain_operation_contexts(tenant_id,id)
);
CREATE TABLE public.domain_operation_domain_claims (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, domain_id uuid NOT NULL, role text NOT NULL CHECK(role IN ('changed','validate')),
 before_view jsonb, before_revision jsonb, after_view jsonb NOT NULL, revision jsonb,
 row_written boolean NOT NULL DEFAULT false, revision_written boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,operation_id,domain_id), FOREIGN KEY(tenant_id,operation_id) REFERENCES public.domain_operation_contexts(tenant_id,id)
);
CREATE TABLE public.domain_operation_placement_claims (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, asset_id uuid NOT NULL, before_view jsonb, after_view jsonb NOT NULL, revision jsonb NOT NULL,
 asset_revision jsonb NOT NULL, target_domain_revision jsonb,
 row_written boolean NOT NULL DEFAULT false, revision_written boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,operation_id,asset_id), FOREIGN KEY(tenant_id,operation_id) REFERENCES public.domain_operation_contexts(tenant_id,id)
);
CREATE TABLE public.domain_operation_journal_claims (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, resource_kind text NOT NULL, resource_id uuid NOT NULL, resource_version integer NOT NULL,
 action text NOT NULL, data jsonb NOT NULL, event_id uuid, audit_written boolean NOT NULL DEFAULT false, outbox_written boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,operation_id,resource_kind,resource_id,resource_version),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES public.domain_operation_contexts(tenant_id,id)
);
DO $$ DECLARE n text; BEGIN
 FOREACH n IN ARRAY ARRAY['domain_types','domain_type_versions','domain_type_dependencies','domains','domain_revisions','asset_domain_placements',
 'asset_domain_placement_revisions','domain_type_migrations','domain_type_migration_domains','domain_scope_state','domain_transaction_bindings',
 'domain_operation_contexts','domain_migration_operations','domain_operation_type_claims','domain_operation_domain_claims','domain_operation_placement_claims','domain_operation_journal_claims'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.gc_tenant()) WITH CHECK(tenant_id=public.gc_tenant())',n);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC,gc_app',n);
 END LOOP;
 FOREACH n IN ARRAY ARRAY['domain_types','domain_type_versions','domain_type_dependencies','domains','domain_revisions','asset_domain_placements',
 'asset_domain_placement_revisions','domain_type_migrations','domain_type_migration_domains'] LOOP
  EXECUTE format('GRANT SELECT ON public.%I TO gc_app',n);
 END LOOP;
 FOREACH n IN ARRAY ARRAY['domain_type_versions','domain_type_dependencies','domain_revisions','asset_domain_placement_revisions','domain_type_migrations','domain_type_migration_domains'] LOOP
  EXECUTE format('CREATE TRIGGER domain_history_immutable BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.gc_immutable_audit()',n);
 END LOOP;
END $$;
GRANT INSERT,UPDATE ON public.domain_types,public.domains,public.asset_domain_placements TO gc_app;
GRANT INSERT ON public.domain_type_versions,public.domain_revisions,public.asset_domain_placement_revisions TO gc_app;

CREATE FUNCTION public.gc_domain_deadline() RETURNS void
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $$ BEGIN
 IF clock_timestamp()>=transaction_timestamp()+interval '30 seconds' THEN
  RAISE EXCEPTION 'DOMAIN_RETRY' USING ERRCODE='57014'; END IF;
END $$;
CREATE FUNCTION public.gc_domain_uuid(v jsonb,nullable boolean DEFAULT false) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT coalesce((nullable AND v='null'::jsonb) OR (jsonb_typeof(v)='string' AND v#>>'{}' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'),false)
$$;
CREATE FUNCTION public.gc_domain_text(v jsonb,maximum integer,required boolean DEFAULT true) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT coalesce(jsonb_typeof(v)='string' AND char_length(v#>>'{}')<=maximum AND v#>>'{}' !~ '[[:cntrl:]]'
 AND (NOT required OR length(btrim(v#>>'{}',chr(9)||chr(10)||chr(11)||chr(12)||chr(13)||chr(32)||chr(160)||chr(5760)||chr(8192)||chr(8193)||chr(8194)||chr(8195)||chr(8196)||chr(8197)||chr(8198)||chr(8199)||chr(8200)||chr(8201)||chr(8202)||chr(8232)||chr(8233)||chr(8239)||chr(8287)||chr(12288)||chr(65279)))>0),false)
$$;
CREATE FUNCTION public.gc_domain_authorize(actions text[]) RETURNS void
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ BEGIN
 IF NOT public.gc_domain_uuid(to_jsonb(public.gc_actor())) OR NOT EXISTS(SELECT 1 FROM public.memberships m
 JOIN public.identities i ON i.id=m.identity_id WHERE m.tenant_id=public.gc_tenant() AND m.identity_id::text=public.gc_actor()
 AND i.active AND m.active AND m.permissions @> to_jsonb(actions)) THEN
  RAISE EXCEPTION 'FORBIDDEN' USING ERRCODE='42501'; END IF;
END $$;
CREATE FUNCTION public.gc_domain_scope_epoch() RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE value bigint; BEGIN
 PERFORM public.gc_domain_authorize(ARRAY[]::text[]);
 IF NOT EXISTS(SELECT 1 FROM public.memberships WHERE tenant_id=public.gc_tenant() AND identity_id::text=public.gc_actor()
 AND (permissions @> '["models:read"]' OR permissions @> '["domains:read"]')) THEN RAISE EXCEPTION 'FORBIDDEN' USING ERRCODE='42501'; END IF;
 SELECT epoch INTO value FROM public.domain_scope_state WHERE tenant_id=public.gc_tenant(); RETURN coalesce(value,0);
END $$;
CREATE FUNCTION public.gc_domain_bind(family text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ BEGIN
 IF public.gc_tenant() IS NULL OR public.gc_actor() IS NULL THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
 INSERT INTO public.domain_transaction_bindings(tenant_id,transaction_id,actor_id,kind,started_at)
 VALUES(public.gc_tenant(),pg_current_xact_id(),public.gc_actor(),family,transaction_timestamp()) ON CONFLICT(transaction_id) DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM public.domain_transaction_bindings WHERE tenant_id=public.gc_tenant() AND transaction_id=pg_current_xact_id()
 AND actor_id=public.gc_actor() AND kind=family AND started_at=transaction_timestamp()) THEN
  RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
END $$;
CREATE FUNCTION public.gc_domain_legacy_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ BEGIN
 PERFORM public.gc_domain_bind('legacy'); RETURN NULL;
END $$;
DO $$ DECLARE n text; BEGIN
 FOREACH n IN ARRAY ARRAY['assets','asset_revisions','governance_models','governance_model_versions','governance_model_migrations',
 'governance_model_migration_assets','governance_model_migration_integrity_exceptions','asset_type_versions','asset_type_dependencies',
 'asset_type_migrations','asset_type_migration_assets','relation_types','relation_type_versions','relation_type_endpoints','relations','relation_revisions',
 'relation_allowed_identities','tenant_graph_revisions','relation_validation_work','relation_graph_operations','relation_type_preparations',
 'relation_participations','relation_participation_revisions','relation_graph_operation_type_claims','relation_graph_operation_asset_scope',
 'relation_graph_operation_asset_claims','relation_graph_operation_model_claims','relation_graph_operation_journal_claims',
 'relation_graph_operation_edge_claims','relation_graph_operation_binding_claims','relation_graph_receipts','relation_graph_receipt_edges',
 'relation_graph_receipt_bindings','relation_graph_receipt_assets','relation_graph_receipt_types','relation_graph_receipt_type_migrations','relation_graph_replacements'] LOOP
  EXECUTE format('CREATE TRIGGER a_domain_legacy_family BEFORE INSERT OR UPDATE OR DELETE ON public.%I FOR EACH STATEMENT EXECUTE FUNCTION public.gc_domain_legacy_guard()',n);
 END LOOP;
END $$;
CREATE FUNCTION public.gc_domain_current(require_open boolean DEFAULT true) RETURNS public.domain_operation_contexts
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.domain_operation_contexts; BEGIN
 PERFORM public.gc_domain_deadline();
 SELECT * INTO op FROM public.domain_operation_contexts WHERE tenant_id=public.gc_tenant() AND transaction_id=pg_current_xact_id();
 IF op.id IS NULL OR op.actor_id::text IS DISTINCT FROM public.gc_actor() OR op.started_at<>transaction_timestamp()
 OR (require_open AND (op.state<>'open' OR NOT op.prepared)) OR NOT EXISTS(SELECT 1 FROM public.domain_transaction_bindings
 WHERE tenant_id=op.tenant_id AND transaction_id=op.transaction_id AND actor_id=public.gc_actor() AND kind='domain') THEN
  RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
 RETURN op;
END $$;
CREATE FUNCTION public.gc_domain_charge_value(operation_id uuid,value jsonb,canonical boolean) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE bytes bigint; nodes bigint; BEGIN
 PERFORM public.gc_domain_deadline();
 -- Physical JSONB expansion is rejected before canonical serialization.
 IF value IS NULL OR pg_column_size(value)>524288 OR octet_length(value::text)>524288
 OR NOT public.gc_relation_json_bounded(value,100000,32,524288) THEN RAISE EXCEPTION 'DOMAIN_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 bytes:=CASE WHEN canonical THEN octet_length(public.gc_type_migration_canonical(value)) ELSE octet_length(value::text) END;
 WITH RECURSIVE tree(v) AS (SELECT value UNION ALL SELECT c.v FROM tree t CROSS JOIN LATERAL
  (SELECT e.value v FROM jsonb_each(CASE WHEN jsonb_typeof(t.v)='object' THEN t.v ELSE '{}' END) e
   UNION ALL SELECT a.value FROM jsonb_array_elements(CASE WHEN jsonb_typeof(t.v)='array' THEN t.v ELSE '[]' END) a) c)
 SELECT count(*) INTO nodes FROM tree;
 UPDATE public.domain_operation_contexts SET retained_bytes=retained_bytes+bytes,retained_nodes=retained_nodes+nodes
 WHERE tenant_id=public.gc_tenant() AND id=operation_id AND transaction_id=pg_current_xact_id() AND actor_id::text=public.gc_actor()
 RETURNING retained_bytes,retained_nodes INTO bytes,nodes;
 IF NOT FOUND THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
 IF bytes>524288 OR nodes>100000 THEN RAISE EXCEPTION 'DOMAIN_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 PERFORM public.gc_domain_deadline();
END $$;
CREATE FUNCTION public.gc_domain_charge(operation_id uuid,value jsonb) RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT public.gc_domain_charge_value(operation_id,value,true)
$$;
-- Asset snapshots retain the legacy metadata grammar. Physical JSON text is a
-- conservative byte charge and counts all nodes without interpreting metadata
-- keys as domain schema or changing the snapshot's exact immutable content.
CREATE FUNCTION public.gc_domain_charge_legacy_revision(operation_id uuid,value jsonb) RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT public.gc_domain_charge_value(operation_id,value,false)
$$;
CREATE FUNCTION public.gc_domain_view(row_value public.domains) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('id',row_value.id,'name',row_value.name,'description',row_value.description,'parentId',row_value.parent_id,
 'type',jsonb_build_object('typeId',row_value.type_id,'version',row_value.type_version),'attributes',row_value.attributes,'ownerId',row_value.owner_id,
 'state',row_value.state,'status',row_value.status,'version',row_value.version,'createdAt',public.gc_relation_utc(row_value.created_at),
 'createdBy',row_value.created_by,'updatedAt',public.gc_relation_utc(row_value.updated_at),'updatedBy',row_value.updated_by)
$$;
CREATE FUNCTION public.gc_domain_placement_view(row_value public.asset_domain_placements) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('assetId',row_value.asset_id,'version',row_value.version,'domainId',row_value.domain_id,
 'recordedAssetVersion',row_value.recorded_asset_version,'recordedDomainVersion',row_value.recorded_domain_version,
 'recordedAt',public.gc_relation_utc(row_value.recorded_at),'recordedBy',row_value.recorded_by)
$$;
CREATE FUNCTION public.gc_domain_type_view(row_value public.domain_type_versions,head integer) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('typeId',row_value.type_id,'key',row_value.definition->>'id','version',row_value.version,'currentVersion',head,
 'definition',row_value.definition,'resolved',row_value.resolved,'definitionHash',row_value.definition_hash,'resolutionHash',row_value.resolution_hash,
 'createdAt',public.gc_relation_utc(row_value.created_at),'createdBy',row_value.created_by)
$$;
CREATE FUNCTION public.gc_domain_tuple(view_value jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$ SELECT view_value-ARRAY['id','version','createdAt','createdBy','updatedAt','updatedBy'] $$;

CREATE FUNCTION public.gc_domain_definition_valid(v jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$ DECLARE p jsonb; k jsonb; BEGIN
 IF NOT public.gc_relation_json_bounded(v,100000,32,262144) OR NOT public.gc_relation_keys(v,
 ARRAY['formatVersion','kind','id','version','label','parents','attributes','overrideAttributes','requiredOwner','lifecycle'])
 OR v->'formatVersion'<>'1' OR v->>'kind'<>'domain-type' OR NOT public.gc_relation_safe_id(v->>'id')
 OR NOT public.gc_relation_positive_integer(v->'version') OR NOT public.gc_domain_text(v->'label',200)
 OR jsonb_typeof(v->'requiredOwner')<>'boolean' OR jsonb_typeof(v->'parents')<>'array' OR jsonb_array_length(v->'parents')>8
 OR jsonb_typeof(v->'overrideAttributes')<>'array' OR jsonb_array_length(v->'overrideAttributes')>128
 OR NOT public.gc_relation_schema_valid(jsonb_build_object('type','object','properties',v->'attributes'))
 OR (v->'lifecycle'<>'null' AND NOT public.gc_relation_lifecycle_valid(v->'lifecycle')) THEN RETURN false; END IF;
 FOR p IN SELECT value FROM jsonb_array_elements(v->'parents') LOOP
  IF NOT public.gc_relation_keys(p,ARRAY['typeId','version']) OR NOT public.gc_domain_uuid(p->'typeId')
  OR NOT public.gc_relation_positive_integer(p->'version') THEN RETURN false; END IF;
 END LOOP;
 IF (SELECT count(*)<>count(DISTINCT parent_value->>'typeId') FROM jsonb_array_elements(v->'parents') parent_value)
 OR (SELECT count(*)<>count(DISTINCT override_key) FROM jsonb_array_elements(v->'overrideAttributes') override_key) THEN RETURN false; END IF;
 FOR k IN SELECT value FROM jsonb_array_elements(v->'overrideAttributes') LOOP
  IF jsonb_typeof(k)<>'string' OR NOT public.gc_relation_safe_id(k#>>'{}') OR NOT v->'attributes' ? (k#>>'{}') THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
END $$;
-- A bounded unique closure is discovered first. Dependency-order evaluation then
-- visits each node once, including diamonds; longest path is independently kept.
CREATE FUNCTION public.gc_domain_resolve(operation_id uuid,root_id uuid,definition jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE pool jsonb:=jsonb_build_array(jsonb_build_object('typeId',root_id,'definition',definition));
 done jsonb:='[]'; item jsonb; p jsonb; existing jsonb; v public.domain_type_versions; attrs jsonb; inherited jsonb; resolved jsonb;
 deps jsonb; policies jsonb; policy jsonb; required_owner boolean; height integer; parent_result jsonb; entry record;
 i integer:=0; passes integer:=0; progress boolean; result jsonb; new_deps jsonb;
BEGIN
 IF NOT public.gc_domain_definition_valid(definition) THEN RAISE EXCEPTION 'DOMAIN_TYPE_INVALID' USING ERRCODE='23514'; END IF;
 PERFORM public.gc_domain_charge(operation_id,definition);
 WHILE i<jsonb_array_length(pool) LOOP
  PERFORM public.gc_domain_deadline(); item:=pool->i; i:=i+1;
  FOR p IN SELECT value FROM jsonb_array_elements(item->'definition'->'parents') LOOP
   IF p->>'typeId'=root_id::text THEN RAISE EXCEPTION 'DOMAIN_TYPE_INVALID' USING ERRCODE='23514'; END IF;
   SELECT value INTO existing FROM jsonb_array_elements(pool) WHERE value->'typeId'=p->'typeId';
   IF existing IS NOT NULL THEN
    IF existing->'definition'->'version'<>p->'version' THEN RAISE EXCEPTION 'DOMAIN_TYPE_INVALID' USING ERRCODE='23514'; END IF;
   ELSE
    IF jsonb_array_length(pool)>=65 THEN RAISE EXCEPTION 'DOMAIN_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
    IF EXISTS(SELECT 1 FROM public.domain_type_versions q WHERE q.tenant_id=public.gc_tenant() AND q.type_id=(p->>'typeId')::uuid AND q.version=(p->>'version')::integer
     AND (pg_column_size(q.definition)>262144 OR octet_length(q.definition::text)>262144 OR pg_column_size(q.resolved)>524288 OR octet_length(q.resolved::text)>524288)) THEN RAISE EXCEPTION 'DOMAIN_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
    SELECT * INTO v FROM public.domain_type_versions WHERE tenant_id=public.gc_tenant() AND type_id=(p->>'typeId')::uuid AND version=(p->>'version')::integer;
    IF NOT FOUND THEN RAISE EXCEPTION 'DOMAIN_TYPE_INVALID' USING ERRCODE='23514'; END IF;
    PERFORM public.gc_domain_charge(operation_id,v.definition); PERFORM public.gc_domain_charge(operation_id,v.resolved);
    IF NOT public.gc_domain_definition_valid(v.definition) OR v.definition->>'id'<> (SELECT key FROM public.domain_types WHERE tenant_id=v.tenant_id AND id=v.type_id)
    OR v.definition->>'version'<>v.version::text OR v.definition_hash<>public.gc_type_migration_hash(v.definition)
    OR v.resolution_hash<>public.gc_type_migration_hash(v.resolved) THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
    pool:=pool||jsonb_build_array(jsonb_build_object('typeId',v.type_id,'definition',v.definition,'storedResolved',v.resolved));
   END IF;
  END LOOP;
 END LOOP;
 IF (SELECT count(*)<>count(DISTINCT value->'definition'->>'id') FROM jsonb_array_elements(pool)) THEN RAISE EXCEPTION 'DOMAIN_TYPE_INVALID' USING ERRCODE='23514'; END IF;
 WHILE jsonb_array_length(done)<jsonb_array_length(pool) LOOP
  progress:=false; passes:=passes+1;
  IF passes>65 THEN RAISE EXCEPTION 'DOMAIN_TYPE_INVALID' USING ERRCODE='23514'; END IF;
  FOR item IN SELECT value FROM jsonb_array_elements(pool) ORDER BY value->>'typeId' LOOP
   PERFORM public.gc_domain_deadline();
   IF EXISTS(SELECT 1 FROM jsonb_array_elements(done) WHERE value->'typeId'=item->'typeId') THEN CONTINUE; END IF;
   IF EXISTS(SELECT 1 FROM jsonb_array_elements(item->'definition'->'parents') parent_pin
    WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(done) d WHERE d->'typeId'=parent_pin->'typeId')) THEN CONTINUE; END IF;
   inherited:='{}'; deps:='[]'; policies:='[]'; required_owner:=(item->'definition'->>'requiredOwner')::boolean; height:=0;
   FOR p IN SELECT value FROM jsonb_array_elements(item->'definition'->'parents') ORDER BY value->>'typeId' LOOP
    SELECT value INTO parent_result FROM jsonb_array_elements(done) WHERE value->'typeId'=p->'typeId';
    height:=greatest(height,(parent_result->>'height')::integer+1);
    required_owner:=required_owner OR (parent_result->'resolved'->>'requiredOwner')::boolean;
    policies:=policies||jsonb_build_array(parent_result->'resolved'->'lifecycle');
    deps:=deps||jsonb_build_array(p)||(parent_result->'resolved'->'dependencies');
    FOR entry IN SELECT key,value FROM jsonb_each(parent_result->'resolved'->'attributes') LOOP
     IF inherited ? entry.key AND inherited->entry.key<>entry.value AND NOT item->'definition'->'attributes' ? entry.key THEN
      RAISE EXCEPTION 'DOMAIN_TYPE_INVALID' USING ERRCODE='23514'; END IF;
     inherited:=inherited||jsonb_build_object(entry.key,entry.value);
    END LOOP;
   END LOOP;
   IF height>8 THEN RAISE EXCEPTION 'DOMAIN_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
   IF EXISTS(SELECT 1 FROM jsonb_array_elements_text(item->'definition'->'overrideAttributes') k WHERE NOT inherited ? k)
   OR EXISTS(SELECT 1 FROM jsonb_object_keys(item->'definition'->'attributes') k WHERE inherited ? k AND NOT item->'definition'->'overrideAttributes' @> to_jsonb(ARRAY[k])) THEN
    RAISE EXCEPTION 'DOMAIN_TYPE_INVALID' USING ERRCODE='23514'; END IF;
   attrs:=inherited||(item->'definition'->'attributes'); policy:=item->'definition'->'lifecycle';
   IF policy='null' THEN
    IF (SELECT count(DISTINCT value) FROM jsonb_array_elements(policies))<>1 THEN RAISE EXCEPTION 'DOMAIN_TYPE_INVALID' USING ERRCODE='23514'; END IF;
    policy:=policies->0;
   END IF;
   SELECT coalesce(jsonb_agg(value ORDER BY value->>'typeId',(value->>'version')::integer),'[]') INTO new_deps FROM (SELECT DISTINCT value FROM jsonb_array_elements(deps)) x;
   resolved:=jsonb_build_object('attributes',attrs,'requiredOwner',required_owner,'lifecycle',policy,'dependencies',new_deps);
   IF NOT public.gc_relation_schema_valid(jsonb_build_object('type','object','properties',attrs)) THEN RAISE EXCEPTION 'DOMAIN_TYPE_INVALID' USING ERRCODE='23514'; END IF;
   PERFORM public.gc_domain_charge(operation_id,resolved);
   IF item ? 'storedResolved' THEN
    IF item->'storedResolved' IS DISTINCT FROM resolved OR new_deps IS DISTINCT FROM
     (SELECT coalesce(jsonb_agg(jsonb_build_object('typeId',parent_type_id,'version',parent_version) ORDER BY parent_type_id),'[]')
      FROM public.domain_type_dependencies WHERE tenant_id=public.gc_tenant() AND type_id=(item->>'typeId')::uuid AND version=(item->'definition'->>'version')::integer) THEN
     RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
   END IF;
   done:=done||jsonb_build_array(jsonb_build_object('typeId',item->'typeId','resolved',resolved,'height',height)); progress:=true;
   IF item->>'typeId'=root_id::text THEN result:=resolved; END IF;
  END LOOP;
  IF NOT progress THEN RAISE EXCEPTION 'DOMAIN_TYPE_INVALID' USING ERRCODE='23514'; END IF;
 END LOOP;
 PERFORM public.gc_domain_deadline(); RETURN result;
END $$;
CREATE FUNCTION public.gc_domain_policy(operation_id uuid,type_identity uuid,version_number integer) RETURNS public.domain_type_versions
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE v public.domain_type_versions; actual jsonb; cached jsonb; BEGIN
 SELECT c.policy_row INTO cached FROM public.domain_operation_policies c WHERE c.tenant_id=public.gc_tenant() AND c.operation_id=gc_domain_policy.operation_id AND c.type_id=type_identity AND c.version=version_number;
 IF FOUND THEN RETURN jsonb_populate_record(NULL::public.domain_type_versions,cached); END IF;
 IF EXISTS(SELECT 1 FROM public.domain_type_versions q WHERE q.tenant_id=public.gc_tenant() AND q.type_id=type_identity AND q.version=version_number
 AND (pg_column_size(q.definition)>262144 OR octet_length(q.definition::text)>262144 OR pg_column_size(q.resolved)>524288 OR octet_length(q.resolved::text)>524288)) THEN RAISE EXCEPTION 'DOMAIN_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 SELECT * INTO v FROM public.domain_type_versions WHERE tenant_id=public.gc_tenant() AND type_id=type_identity AND version=version_number;
 IF NOT FOUND THEN RAISE EXCEPTION 'DOMAIN_TYPE_INVALID' USING ERRCODE='23514'; END IF;
 actual:=public.gc_domain_resolve(operation_id,type_identity,v.definition);
 IF actual IS DISTINCT FROM v.resolved OR v.definition_hash<>public.gc_type_migration_hash(v.definition)
 OR v.resolution_hash<>public.gc_type_migration_hash(actual) OR v.definition->>'version'<>v.version::text
 OR v.definition->>'id'<>(SELECT key FROM public.domain_types WHERE tenant_id=v.tenant_id AND id=v.type_id)
 OR actual->'dependencies' IS DISTINCT FROM (SELECT coalesce(jsonb_agg(jsonb_build_object('typeId',parent_type_id,'version',parent_version) ORDER BY parent_type_id),'[]')
 FROM public.domain_type_dependencies WHERE tenant_id=v.tenant_id AND type_id=v.type_id AND version=v.version) THEN
  RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
 PERFORM public.gc_domain_charge(operation_id,to_jsonb(v));
 INSERT INTO public.domain_operation_policies(tenant_id,operation_id,type_id,version,policy_row) VALUES(v.tenant_id,operation_id,v.type_id,v.version,to_jsonb(v));
 RETURN v;
END $$;
CREATE FUNCTION public.gc_domain_owner_active(owner_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT owner_identity IS NOT NULL AND EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id
 WHERE m.tenant_id=public.gc_tenant() AND m.identity_id=owner_identity AND m.active AND i.active)
$$;
CREATE FUNCTION public.gc_domain_tuple_valid(v jsonb,policy jsonb,require_owner_activity boolean DEFAULT true) RETURNS boolean
LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ BEGIN
 RETURN public.gc_domain_text(v->'name',200) AND public.gc_domain_text(v->'description',4000,false)
 AND public.gc_domain_uuid(v->'parentId',true) AND public.gc_domain_uuid(v->'ownerId',true)
 AND public.gc_relation_safe_id(v->>'state') AND v->>'status' IN ('active','retired')
 AND public.gc_relation_value_valid(jsonb_build_object('type','object','properties',policy->'attributes'),v->'attributes')
 AND policy->'lifecycle'->'states' @> jsonb_build_array(v->'state')
 AND (policy->>'requiredOwner'<>'true' OR (v->'ownerId'<>'null' AND (NOT require_owner_activity OR public.gc_domain_owner_active((v->>'ownerId')::uuid))));
END $$;
CREATE FUNCTION public.gc_domain_journal_claim(operation_id uuid,action_name text,resource_kind text,resource_id uuid,resource_version integer,data jsonb) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ BEGIN
 PERFORM public.gc_domain_charge(operation_id,data);
 INSERT INTO public.domain_operation_journal_claims(tenant_id,operation_id,resource_kind,resource_id,resource_version,action,data)
 VALUES(public.gc_tenant(),operation_id,resource_kind,resource_id,resource_version,action_name,data);
END $$;
CREATE FUNCTION public.gc_domain_claim_changed(operation_id uuid,before_value jsonb,after_value jsonb,action_name text,migration_id uuid DEFAULT NULL) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.domain_operation_contexts; revision jsonb; old_revision jsonb; identity uuid:=(after_value->>'id')::uuid; BEGIN
 SELECT * INTO op FROM public.domain_operation_contexts WHERE tenant_id=public.gc_tenant() AND id=operation_id;
 IF before_value IS NOT NULL THEN
  SELECT snapshot INTO old_revision FROM public.domain_revisions WHERE tenant_id=op.tenant_id AND domain_id=identity AND version=(before_value->>'version')::integer;
  IF old_revision->'domain' IS DISTINCT FROM before_value THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
 END IF;
 revision:=jsonb_build_object('formatVersion',1,'domain',after_value,'action',action_name,'reason',op.reason,'correlationId',op.correlation_id);
 PERFORM public.gc_domain_charge(operation_id,jsonb_build_array(before_value,old_revision,after_value,revision));
 INSERT INTO public.domain_operation_domain_claims(tenant_id,operation_id,domain_id,role,before_view,before_revision,after_view,revision)
 VALUES(op.tenant_id,operation_id,identity,'changed',before_value,old_revision,after_value,revision)
 ON CONFLICT ON CONSTRAINT domain_operation_domain_claims_pkey DO UPDATE SET role='changed',before_view=excluded.before_view,before_revision=excluded.before_revision,
 after_view=excluded.after_view,revision=excluded.revision;
 PERFORM public.gc_domain_journal_claim(operation_id,'domain.'||replace(action_name,'-','_'),'domain',identity,(after_value->>'version')::integer,
 jsonb_build_object('schemaVersion',1,'resourceKind','domain','domainId',identity,'previousVersion',before_value->'version','version',after_value->'version',
 'revisionHash',public.gc_type_migration_hash(revision),'migrationId',migration_id));
END $$;
CREATE FUNCTION public.gc_domain_adapt(v public.domain_type_versions) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('formatVersion',1,'id',v.definition->'id','version',v.version,'attributes',v.resolved->'attributes')
$$;

-- Identity-only discovery precedes authorization, counts, byte measurements and
-- payload capture. This is a phase boundary, not a reorderable WHERE predicate.
CREATE TABLE public.domain_operation_scope_members (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, kind text NOT NULL CHECK(kind IN ('domain','asset','type','subtree')),
 resource_id uuid NOT NULL, PRIMARY KEY(tenant_id,operation_id,kind,resource_id),
 FOREIGN KEY(tenant_id,operation_id) REFERENCES public.domain_operation_contexts(tenant_id,id)
);
ALTER TABLE public.domain_operation_scope_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.domain_operation_scope_members FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.domain_operation_scope_members USING(tenant_id=public.gc_tenant()) WITH CHECK(tenant_id=public.gc_tenant());
REVOKE ALL ON public.domain_operation_scope_members FROM PUBLIC,gc_app;
CREATE TABLE public.domain_operation_policies (
 tenant_id uuid NOT NULL, operation_id uuid NOT NULL, type_id uuid NOT NULL, version integer NOT NULL, policy_row jsonb NOT NULL,
 PRIMARY KEY(tenant_id,operation_id,type_id,version), FOREIGN KEY(tenant_id,operation_id) REFERENCES public.domain_operation_contexts(tenant_id,id),
 FOREIGN KEY(tenant_id,type_id,version) REFERENCES public.domain_type_versions(tenant_id,type_id,version)
);
ALTER TABLE public.domain_operation_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.domain_operation_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.domain_operation_policies USING(tenant_id=public.gc_tenant()) WITH CHECK(tenant_id=public.gc_tenant());
REVOKE ALL ON public.domain_operation_policies FROM PUBLIC,gc_app;

CREATE FUNCTION public.gc_domain_begin(operation_id uuid,idempotency_key text,request_body jsonb,correlation_id text,migration boolean) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
#variable_conflict use_variable
DECLARE tenant uuid:=public.gc_tenant(); actor uuid; ns text; required_permissions text[]; op public.domain_operation_contexts;
 kind text; fields text[]; reason text; subject uuid; type_identity uuid; parent_identity uuid; target_version integer;
 target public.domain_type_versions; head public.domain_types; source public.domain_type_versions; previous public.domain_type_versions;
 domain_row public.domains; placement_row public.asset_domain_placements; asset_row public.assets;
 before_value jsonb; after_value jsonb; response jsonb; projection jsonb; revision jsonb; source_policies jsonb:='[]'; outcomes jsonb:='[]';
 plan jsonb; change jsonb; policy_changes jsonb:='[]'; source_versions jsonb; mapped jsonb; override_value jsonb; selected_owner uuid;
 previous_required boolean; sources jsonb; attrs jsonb; tuple jsonb; expected_action text; retained jsonb; item jsonb; row_item record;
 principal_ids uuid[]; domain_ids uuid[]; asset_ids uuid[]; type_ids uuid[]; clock_text text; initial_epoch bigint; total bigint; max_depth integer;
 old_head jsonb; new_head jsonb; type_response jsonb; expected_version integer; old_parent uuid; state_name text;
BEGIN
 PERFORM public.gc_domain_deadline();
 kind:=CASE WHEN migration THEN 'domain-type-migration.execute' ELSE request_body->>'kind' END; ns:=kind;
 required_permissions:=CASE kind WHEN 'domain-type.create' THEN ARRAY['models:read','models:write']
 WHEN 'domain-type.publish' THEN ARRAY['models:read','models:write','domains:read']
 WHEN 'domain-type-migration.execute' THEN ARRAY['models:read','models:write','domains:read','domains:write']
 WHEN 'domain.placement' THEN ARRAY['catalog:read','catalog:write','domains:read','domains:assign']
 ELSE ARRAY['domains:read','domains:write'] END;
 PERFORM public.gc_domain_authorize(required_permissions); actor:=public.gc_actor()::uuid;
 IF operation_id IS NULL OR length(idempotency_key) NOT BETWEEN 8 AND 128 OR idempotency_key IS NULL
 OR correlation_id IS NULL OR correlation_id !~ '^[A-Za-z0-9._:-]{1,128}$' THEN RAISE EXCEPTION 'DOMAIN_INVALID' USING ERRCODE='23514'; END IF;
 fields:=CASE kind WHEN 'domain-type.create' THEN ARRAY['kind','definition','reason']
 WHEN 'domain-type.publish' THEN ARRAY['kind','typeId','expectedHeadVersion','definition','reason','previewDigest']
 WHEN 'domain-type-migration.execute' THEN ARRAY['typeId','expectedHeadVersion','definition','plan','reason','previewDigest']
 WHEN 'domain.create' THEN ARRAY['kind','name','description','parentId','type','attributes','ownerId','reason']
 WHEN 'domain.update' THEN ARRAY['kind','domainId','expectedVersion','name','description','attributes','ownerId','reason']
 WHEN 'domain.state' THEN ARRAY['kind','domainId','expectedVersion','state','reason']
 WHEN 'domain.hierarchy' THEN ARRAY['kind','change','previewDigest']
 WHEN 'domain.placement' THEN ARRAY['kind','assetId','expectedPlacementVersion','assetVersion','domainId','domainVersion','reason'] ELSE NULL END;
 IF fields IS NULL OR NOT public.gc_relation_keys(request_body,fields) THEN RAISE EXCEPTION 'DOMAIN_INVALID' USING ERRCODE='23514'; END IF;
 reason:=CASE WHEN kind='domain.hierarchy' THEN request_body->'change'->>'reason' ELSE request_body->>'reason' END;
 IF NOT public.gc_domain_text(to_jsonb(reason),500) THEN RAISE EXCEPTION 'DOMAIN_INVALID' USING ERRCODE='23514'; END IF;
 IF request_body ? 'previewDigest' AND (jsonb_typeof(request_body->'previewDigest')<>'string' OR request_body->>'previewDigest' !~ '^[a-f0-9]{64}$') THEN
  RAISE EXCEPTION 'DOMAIN_INVALID' USING ERRCODE='23514'; END IF;
 IF kind IN ('domain-type.publish','domain-type-migration.execute') AND
 (NOT public.gc_domain_uuid(request_body->'typeId') OR NOT public.gc_relation_positive_integer(request_body->'expectedHeadVersion')) THEN
  RAISE EXCEPTION 'DOMAIN_TYPE_INVALID' USING ERRCODE='23514'; END IF;
 IF kind='domain.create' AND (NOT public.gc_relation_keys(request_body->'type',ARRAY['typeId','version'])
 OR NOT public.gc_domain_uuid(request_body->'type'->'typeId') OR NOT public.gc_relation_positive_integer(request_body->'type'->'version')
 OR NOT public.gc_domain_uuid(request_body->'parentId',true) OR NOT public.gc_domain_uuid(request_body->'ownerId',true)) THEN
  RAISE EXCEPTION 'DOMAIN_INVALID' USING ERRCODE='23514'; END IF;
 IF kind IN ('domain.update','domain.state') AND (NOT public.gc_domain_uuid(request_body->'domainId') OR NOT public.gc_relation_positive_integer(request_body->'expectedVersion')) THEN
  RAISE EXCEPTION 'DOMAIN_INVALID' USING ERRCODE='23514'; END IF;
 IF kind='domain.update' AND NOT public.gc_domain_uuid(request_body->'ownerId',true) THEN RAISE EXCEPTION 'DOMAIN_INVALID' USING ERRCODE='23514'; END IF;
 IF kind='domain.hierarchy' THEN
  change:=request_body->'change';
  IF NOT public.gc_relation_keys(change,ARRAY['kind','domainId','expectedVersion','parentId','reason']) OR change->>'kind' NOT IN ('move','retire','restore')
  OR NOT public.gc_domain_uuid(change->'domainId') OR NOT public.gc_relation_positive_integer(change->'expectedVersion') OR NOT public.gc_domain_uuid(change->'parentId',true) THEN
   RAISE EXCEPTION 'DOMAIN_INVALID' USING ERRCODE='23514'; END IF;
 END IF;
 IF kind='domain.placement' AND (NOT public.gc_domain_uuid(request_body->'assetId') OR NOT public.gc_domain_uuid(request_body->'domainId',true)
 OR NOT public.gc_relation_positive_integer(request_body->'assetVersion') OR (request_body->'expectedPlacementVersion'<>'0' AND NOT public.gc_relation_positive_integer(request_body->'expectedPlacementVersion'))
 OR ((request_body->'domainId'='null')<>(request_body->'domainVersion'='null'))
 OR (request_body->'domainId'<>'null' AND NOT public.gc_relation_positive_integer(request_body->'domainVersion'))) THEN
  RAISE EXCEPTION 'DOMAIN_INVALID' USING ERRCODE='23514'; END IF;
 -- Reject incompatible prior writes before waiting on any advisory lock:
 -- a legacy writer may already hold the ledger that a valid once caller needs.
 PERFORM public.gc_domain_bind('domain');
 IF EXISTS(SELECT 1 FROM public.domain_operation_contexts WHERE tenant_id=tenant AND transaction_id=pg_current_xact_id()) THEN
  RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
 -- Direct callers take the same locks as once/record, never look-alike keys.
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text||actor::text||ns||idempotency_key,0)); PERFORM public.gc_domain_deadline();
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text,0)); PERFORM public.gc_domain_deadline();
 -- Domain policy may be read by every operation; sharing the model fence keeps
 -- the single ordering stable without acquiring it after a canonical row lock.
 PERFORM pg_advisory_xact_lock(hashtextextended('governance-models:'||tenant::text,0)); PERFORM public.gc_domain_deadline();
 PERFORM pg_advisory_xact_lock(hashtextextended('governance-domains:'||tenant::text,0)); PERFORM public.gc_domain_deadline();
 INSERT INTO public.domain_scope_state(tenant_id,epoch) VALUES(tenant,0) ON CONFLICT(tenant_id) DO NOTHING;
 SELECT epoch INTO initial_epoch FROM public.domain_scope_state WHERE tenant_id=tenant FOR UPDATE; PERFORM public.gc_domain_deadline();
 INSERT INTO public.domain_operation_contexts(tenant_id,id,transaction_id,actor_id,actor_name,started_at,occurred_at,mode,namespace,idempotency_key,
 request_body,request_hash,reason,correlation_id,permissions,initial_epoch)
 SELECT tenant,operation_id,pg_current_xact_id(),actor,i.name,transaction_timestamp(),date_trunc('milliseconds',transaction_timestamp()),
 CASE WHEN migration THEN 'migration' ELSE 'ordinary' END,ns,idempotency_key,request_body,'',reason,correlation_id,required_permissions,initial_epoch
 FROM public.identities i WHERE i.id=actor;
 -- Identity-only phase; no database-derived aggregate limits or payloads yet.
 subject:=CASE WHEN kind IN ('domain.update','domain.state') THEN (request_body->>'domainId')::uuid
 WHEN kind='domain.hierarchy' THEN (change->>'domainId')::uuid WHEN kind='domain.create' THEN operation_id END;
 type_identity:=CASE WHEN kind='domain-type.create' THEN operation_id WHEN kind IN ('domain-type.publish','domain-type-migration.execute') THEN (request_body->>'typeId')::uuid
 WHEN kind='domain.create' THEN (request_body->'type'->>'typeId')::uuid END;
 IF kind IN ('domain-type.publish','domain-type-migration.execute') THEN
  IF NOT EXISTS(SELECT 1 FROM public.domain_types WHERE tenant_id=tenant AND id=type_identity) THEN RAISE EXCEPTION 'DOMAIN_TYPE_NOT_FOUND' USING ERRCODE='23514'; END IF;
  INSERT INTO public.domain_operation_scope_members SELECT tenant,operation_id,'domain',id FROM public.domains WHERE tenant_id=tenant AND type_id=type_identity;
 ELSIF kind IN ('domain.update','domain.state','domain.hierarchy') THEN
  IF NOT EXISTS(SELECT 1 FROM public.domains WHERE tenant_id=tenant AND id=subject) THEN RAISE EXCEPTION 'DOMAIN_NOT_FOUND' USING ERRCODE='23514'; END IF;
  INSERT INTO public.domain_operation_scope_members VALUES(tenant,operation_id,'domain',subject);
 END IF;
 IF kind='domain.hierarchy' THEN
  WITH RECURSIVE subtree(id) AS (SELECT subject UNION SELECT d.id FROM public.domains d JOIN subtree s ON d.parent_id=s.id WHERE d.tenant_id=tenant)
  INSERT INTO public.domain_operation_scope_members SELECT tenant,operation_id,'subtree',id FROM subtree;
  INSERT INTO public.domain_operation_scope_members SELECT tenant,operation_id,'domain',s.resource_id FROM public.domain_operation_scope_members s
  WHERE s.tenant_id=tenant AND s.operation_id=operation_id AND s.kind='subtree' ON CONFLICT DO NOTHING;
  INSERT INTO public.domain_operation_scope_members SELECT tenant,operation_id,'asset',p.asset_id FROM public.asset_domain_placements p
  JOIN public.domain_operation_scope_members s ON s.tenant_id=p.tenant_id AND s.resource_id=p.domain_id AND s.operation_id=operation_id AND s.kind='subtree'
  WHERE p.tenant_id=tenant ON CONFLICT DO NOTHING;
 END IF;
 parent_identity:=CASE WHEN kind='domain.create' THEN (request_body->>'parentId')::uuid WHEN kind='domain.hierarchy' THEN (change->>'parentId')::uuid END;
 IF parent_identity IS NOT NULL THEN
  IF NOT EXISTS(SELECT 1 FROM public.domains WHERE tenant_id=tenant AND id=parent_identity) THEN RAISE EXCEPTION 'DOMAIN_NOT_FOUND' USING ERRCODE='23514'; END IF;
  INSERT INTO public.domain_operation_scope_members VALUES(tenant,operation_id,'domain',parent_identity) ON CONFLICT DO NOTHING;
 END IF;
 IF kind='domain.placement' THEN
  IF NOT EXISTS(SELECT 1 FROM public.assets a WHERE a.tenant_id=tenant AND a.id=(request_body->>'assetId')::uuid
   AND (a.visibility='tenant' OR a.allowed_identities @> jsonb_build_array(actor))) THEN RAISE EXCEPTION 'ASSET_NOT_FOUND' USING ERRCODE='23514'; END IF;
  INSERT INTO public.domain_operation_scope_members VALUES(tenant,operation_id,'asset',(request_body->>'assetId')::uuid);
  INSERT INTO public.domain_operation_scope_members SELECT tenant,operation_id,'domain',domain_id FROM public.asset_domain_placements
  WHERE tenant_id=tenant AND asset_id=(request_body->>'assetId')::uuid AND domain_id IS NOT NULL ON CONFLICT DO NOTHING;
  IF request_body->'domainId'<>'null' THEN
   IF NOT EXISTS(SELECT 1 FROM public.domains WHERE tenant_id=tenant AND id=(request_body->>'domainId')::uuid) THEN RAISE EXCEPTION 'DOMAIN_NOT_FOUND' USING ERRCODE='23514'; END IF;
   INSERT INTO public.domain_operation_scope_members VALUES(tenant,operation_id,'domain',(request_body->>'domainId')::uuid) ON CONFLICT DO NOTHING;
  END IF;
 END IF;
 WITH RECURSIVE ancestors(id) AS (SELECT s.resource_id FROM public.domain_operation_scope_members s WHERE s.tenant_id=tenant AND s.operation_id=operation_id AND s.kind='domain'
 UNION SELECT d.parent_id FROM public.domains d JOIN ancestors a ON a.id=d.id WHERE d.tenant_id=tenant AND d.parent_id IS NOT NULL)
 INSERT INTO public.domain_operation_scope_members SELECT tenant,operation_id,'domain',id FROM ancestors ON CONFLICT DO NOTHING;
 -- Asset visibility is a separate completed phase before any scope count/byte.
 IF EXISTS(SELECT 1 FROM public.domain_operation_scope_members s LEFT JOIN public.assets a ON a.tenant_id=s.tenant_id AND a.id=s.resource_id
 WHERE s.tenant_id=tenant AND s.operation_id=operation_id AND s.kind='asset'
 AND (a.id IS NULL OR (a.visibility='restricted' AND NOT a.allowed_identities @> jsonb_build_array(actor)))) THEN
  RAISE EXCEPTION 'DOMAIN_SCOPE_UNAVAILABLE' USING ERRCODE='42501'; END IF;
 IF EXISTS(SELECT 1 FROM public.domain_operation_scope_members s WHERE s.tenant_id=tenant AND s.operation_id=operation_id AND s.kind='asset') THEN
  PERFORM public.gc_domain_authorize(ARRAY['catalog:read']);
 END IF;
 PERFORM public.gc_domain_authorize(required_permissions); PERFORM public.gc_domain_deadline();
 IF (SELECT count(*) FROM public.domain_operation_scope_members s WHERE s.tenant_id=tenant AND s.operation_id=operation_id AND s.kind='domain')>1000
 OR (SELECT count(*) FROM public.domain_operation_scope_members s WHERE s.tenant_id=tenant AND s.operation_id=operation_id AND s.kind='asset')>1000 THEN
  RAISE EXCEPTION 'DOMAIN_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 PERFORM public.gc_domain_charge(operation_id,request_body);
 UPDATE public.domain_operation_contexts c SET request_hash=public.gc_type_migration_hash(request_body) WHERE c.tenant_id=tenant AND c.id=operation_id;
 IF request_body ? 'definition' AND NOT public.gc_domain_definition_valid(request_body->'definition') THEN RAISE EXCEPTION 'DOMAIN_TYPE_INVALID' USING ERRCODE='23514'; END IF;
 INSERT INTO public.domain_operation_scope_members SELECT tenant,operation_id,'type',d.type_id FROM public.domains d
 JOIN public.domain_operation_scope_members s ON s.tenant_id=d.tenant_id AND s.resource_id=d.id AND s.kind='domain' AND s.operation_id=operation_id
 WHERE d.tenant_id=tenant ON CONFLICT DO NOTHING;
 IF type_identity IS NOT NULL THEN INSERT INTO public.domain_operation_scope_members VALUES(tenant,operation_id,'type',type_identity) ON CONFLICT DO NOTHING; END IF;
 -- All immutable pins reachable from current domains, current heads and proposed
 -- parents contribute identities before the type-head lock phase.
 WITH RECURSIVE pins(type_id,version) AS (
 SELECT d.type_id,d.type_version FROM public.domains d JOIN public.domain_operation_scope_members s ON s.tenant_id=d.tenant_id AND s.resource_id=d.id AND s.kind='domain' AND s.operation_id=operation_id WHERE d.tenant_id=tenant
 UNION SELECT t.id,t.current_version FROM public.domain_types t JOIN public.domain_operation_scope_members s ON s.tenant_id=t.tenant_id AND s.resource_id=t.id AND s.kind='type' AND s.operation_id=operation_id WHERE t.tenant_id=tenant
 UNION SELECT (request_body->'type'->>'typeId')::uuid,(request_body->'type'->>'version')::integer WHERE kind='domain.create'
 UNION SELECT (p->>'typeId')::uuid,(p->>'version')::integer FROM jsonb_array_elements(coalesce(request_body->'definition'->'parents','[]')) p
 UNION SELECT (p->>'typeId')::uuid,(p->>'version')::integer FROM pins q JOIN public.domain_type_versions v ON v.tenant_id=tenant AND v.type_id=q.type_id AND v.version=q.version CROSS JOIN LATERAL jsonb_array_elements(v.definition->'parents') p)
 INSERT INTO public.domain_operation_scope_members SELECT DISTINCT tenant,operation_id,'type',type_id FROM pins ON CONFLICT DO NOTHING;
 -- Identity unions also consume the one retained document budget. Bound the
 -- scalar count before array/JSON aggregation, including historical policy heads.
 IF (SELECT count(*)*40 FROM public.domain_operation_scope_members s WHERE s.tenant_id=tenant AND s.operation_id=operation_id AND s.kind IN ('domain','asset','type'))>524288 THEN
  RAISE EXCEPTION 'DOMAIN_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 SELECT coalesce(array_agg(resource_id ORDER BY resource_id),'{}') INTO domain_ids FROM public.domain_operation_scope_members s WHERE s.tenant_id=tenant AND s.operation_id=operation_id AND s.kind='domain';
 SELECT coalesce(array_agg(resource_id ORDER BY resource_id),'{}') INTO asset_ids FROM public.domain_operation_scope_members s WHERE s.tenant_id=tenant AND s.operation_id=operation_id AND s.kind='asset';
 SELECT coalesce(array_agg(resource_id ORDER BY resource_id),'{}') INTO type_ids FROM public.domain_operation_scope_members s WHERE s.tenant_id=tenant AND s.operation_id=operation_id AND s.kind='type';
 PERFORM public.gc_domain_charge(operation_id,jsonb_build_object('domains',to_jsonb(domain_ids),'assets',to_jsonb(asset_ids),'types',to_jsonb(type_ids)));
 FOR row_item IN SELECT t.id FROM public.domain_types t WHERE t.tenant_id=tenant AND t.id=ANY(type_ids) ORDER BY t.id FOR UPDATE LOOP PERFORM public.gc_domain_deadline(); END LOOP;
 FOR row_item IN SELECT d.id FROM public.domains d WHERE d.tenant_id=tenant AND d.id=ANY(domain_ids) ORDER BY d.id FOR UPDATE LOOP PERFORM public.gc_domain_deadline(); END LOOP;
 FOR row_item IN SELECT a.id FROM public.assets a WHERE a.tenant_id=tenant AND a.id=ANY(asset_ids) ORDER BY a.id FOR UPDATE LOOP PERFORM public.gc_domain_deadline(); END LOOP;
 FOR row_item IN SELECT p.asset_id FROM public.asset_domain_placements p WHERE p.tenant_id=tenant AND p.asset_id=ANY(asset_ids) ORDER BY p.asset_id FOR UPDATE LOOP PERFORM public.gc_domain_deadline(); END LOOP;
 plan:=request_body->'plan';
 IF migration THEN
  IF NOT public.gc_relation_keys(plan,ARRAY['formatVersion','kind','typeId','attributes','owner','lifecycle','acknowledgedPolicyChanges']) OR plan->'formatVersion'<>'1'
  OR plan->>'kind'<>'domain-type-migration' OR plan->'typeId'<>request_body->'typeId'
  OR NOT public.gc_relation_keys(plan->'owner',ARRAY['default','overrides']) OR plan->'owner'->>'default'<>'preserve'
  OR jsonb_typeof(plan->'owner'->'overrides')<>'array' OR jsonb_array_length(plan->'owner'->'overrides')>1000
  OR NOT public.gc_relation_keys(plan->'lifecycle',ARRAY['onUnmapped','mappings']) OR plan->'lifecycle'->>'onUnmapped' NOT IN ('preserve','error')
  OR jsonb_typeof(plan->'lifecycle'->'mappings')<>'array' OR jsonb_array_length(plan->'lifecycle'->'mappings')>1000
  OR jsonb_typeof(plan->'acknowledgedPolicyChanges')<>'array' THEN RAISE EXCEPTION 'DOMAIN_MIGRATION_INVALID' USING ERRCODE='23514'; END IF;
  FOR item IN SELECT value FROM jsonb_array_elements(plan->'owner'->'overrides') LOOP
   IF NOT public.gc_relation_keys(item,ARRAY['domainId','ownerId']) OR NOT public.gc_domain_uuid(item->'domainId') OR NOT public.gc_domain_uuid(item->'ownerId',true)
   OR NOT EXISTS(SELECT 1 FROM public.domains d WHERE d.tenant_id=tenant AND d.type_id=type_identity AND d.id=(item->>'domainId')::uuid) THEN
    RAISE EXCEPTION 'DOMAIN_MIGRATION_INVALID' USING ERRCODE='23514'; END IF;
  END LOOP;
  IF (SELECT count(*)<>count(DISTINCT value->>'domainId') FROM jsonb_array_elements(plan->'owner'->'overrides')) THEN RAISE EXCEPTION 'DOMAIN_MIGRATION_INVALID' USING ERRCODE='23514'; END IF;
 END IF;
 SELECT array_agg(DISTINCT id ORDER BY id) INTO principal_ids FROM (
 SELECT actor id UNION SELECT d.owner_id FROM public.domains d WHERE d.tenant_id=tenant AND d.id=ANY(domain_ids) AND d.owner_id IS NOT NULL
 UNION SELECT (request_body->>'ownerId')::uuid WHERE request_body->'ownerId'<>'null'
 UNION SELECT (p->>'ownerId')::uuid FROM jsonb_array_elements(CASE WHEN migration THEN plan->'owner'->'overrides' ELSE '[]' END) p WHERE p->'ownerId'<>'null') principals;
 IF cardinality(principal_ids)>2001 THEN RAISE EXCEPTION 'DOMAIN_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 PERFORM public.gc_domain_charge(operation_id,to_jsonb(principal_ids));
 PERFORM public.gc_lock_type_migration_principals(principal_ids); PERFORM public.gc_domain_deadline(); PERFORM public.gc_domain_authorize(required_permissions);
 IF cardinality(asset_ids)>0 THEN
  PERFORM public.gc_domain_authorize(ARRAY['catalog:read']);
  IF EXISTS(SELECT 1 FROM public.assets a WHERE a.tenant_id=tenant AND a.id=ANY(asset_ids) AND a.visibility='restricted' AND NOT a.allowed_identities @> jsonb_build_array(actor)) THEN
   RAISE EXCEPTION 'DOMAIN_SCOPE_UNAVAILABLE' USING ERRCODE='42501'; END IF;
 END IF;
 UPDATE public.domain_operation_contexts c SET domain_scope=domain_ids,asset_scope=asset_ids,type_scope=type_ids,principals=principal_ids,
 actor_name=(SELECT name FROM public.identities WHERE id=actor) WHERE c.tenant_id=tenant AND c.id=operation_id RETURNING * INTO op;
 clock_text:=public.gc_relation_utc(op.occurred_at);
 -- Complete asset/domain authority has already been checked above. Reject
 -- physical oversized rows/revisions before SELECT *, JSON construction or hash.
 IF EXISTS(SELECT 1 FROM public.domains q WHERE q.tenant_id=tenant AND q.id=ANY(domain_ids)
  AND (octet_length(q.name)+octet_length(q.description)+pg_column_size(q.attributes)>524288 OR octet_length(q.attributes::text)>524288))
 OR EXISTS(SELECT 1 FROM public.domain_revisions r JOIN public.domains q ON q.tenant_id=r.tenant_id AND q.id=r.domain_id AND q.version=r.version
  WHERE q.tenant_id=tenant AND q.id=ANY(domain_ids) AND (pg_column_size(r.snapshot)>524288 OR octet_length(r.snapshot::text)>524288))
 OR EXISTS(SELECT 1 FROM public.asset_revisions r JOIN public.assets a ON a.tenant_id=r.tenant_id AND a.id=r.asset_id AND a.version=r.version
  WHERE a.tenant_id=tenant AND a.id=ANY(asset_ids) AND (pg_column_size(r.snapshot)>524288 OR octet_length(r.snapshot::text)>524288)) THEN
  RAISE EXCEPTION 'DOMAIN_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 PERFORM public.gc_domain_deadline();
 FOR domain_row IN SELECT d.* FROM public.domains d WHERE d.tenant_id=tenant AND d.id=ANY(domain_ids) ORDER BY d.id LOOP
  PERFORM public.gc_domain_deadline(); before_value:=public.gc_domain_view(domain_row);
  SELECT snapshot INTO revision FROM public.domain_revisions r WHERE r.tenant_id=tenant AND r.domain_id=domain_row.id AND r.version=domain_row.version;
  IF revision->'domain' IS DISTINCT FROM before_value THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  PERFORM public.gc_domain_charge(operation_id,jsonb_build_array(before_value,revision));
  INSERT INTO public.domain_operation_domain_claims(tenant_id,operation_id,domain_id,role,before_view,before_revision,after_view)
  VALUES(tenant,operation_id,domain_row.id,'validate',before_value,revision,before_value);
 END LOOP;
 IF kind IN ('domain-type.create','domain-type.publish','domain-type-migration.execute') THEN
  IF kind='domain-type.create' THEN
   IF (request_body->'definition'->>'version')::integer<>1 THEN RAISE EXCEPTION 'DOMAIN_TYPE_INVALID' USING ERRCODE='23514'; END IF;
   head:=jsonb_populate_record(NULL::public.domain_types,jsonb_build_object('tenant_id',tenant,'id',type_identity,'key',request_body->'definition'->>'id',
    'current_version',1,'created_at',clock_text,'created_by',actor)); old_head:=NULL;
  ELSE
   SELECT * INTO head FROM public.domain_types t WHERE t.tenant_id=tenant AND t.id=type_identity;
   IF head.current_version<>(request_body->>'expectedHeadVersion')::integer OR head.current_version=2147483647 THEN RAISE EXCEPTION 'VERSION_CONFLICT' USING ERRCODE='23514'; END IF;
   previous:=public.gc_domain_policy(operation_id,type_identity,head.current_version); old_head:=to_jsonb(head);
   IF request_body->'definition'->>'id'<>head.key OR (request_body->'definition'->>'version')::bigint<>head.current_version::bigint+1 THEN
    RAISE EXCEPTION 'DOMAIN_TYPE_INVALID' USING ERRCODE='23514'; END IF;
   head.current_version:=head.current_version+1;
  END IF;
  target:=jsonb_populate_record(NULL::public.domain_type_versions,jsonb_build_object('tenant_id',tenant,'type_id',type_identity,'version',head.current_version,
   'definition',request_body->'definition','created_at',clock_text,'created_by',actor));
  target.resolved:=public.gc_domain_resolve(operation_id,type_identity,target.definition);
  target.definition_hash:=public.gc_type_migration_hash(target.definition); target.resolution_hash:=public.gc_type_migration_hash(target.resolved);
  IF kind<>'domain-type.create' THEN
   IF (SELECT coalesce(jsonb_agg(value ORDER BY value->>'typeId'),'[]') FROM jsonb_array_elements(previous.definition->'parents')) IS DISTINCT FROM
    (SELECT coalesce(jsonb_agg(value ORDER BY value->>'typeId'),'[]') FROM jsonb_array_elements(target.definition->'parents')) THEN policy_changes:=policy_changes||'"parents_changed"'; END IF;
   IF previous.resolved->'requiredOwner'<>target.resolved->'requiredOwner' THEN policy_changes:=policy_changes||'"required_owner_changed"'; END IF;
   IF previous.resolved->'lifecycle'<>target.resolved->'lifecycle' THEN policy_changes:=policy_changes||'"lifecycle_changed"'; END IF;
   IF NOT migration AND (jsonb_array_length(policy_changes)>0 OR EXISTS(SELECT 1 FROM jsonb_array_elements(public.gc_relation_schema_changes(
    jsonb_build_object('type','object','properties',previous.resolved->'attributes'),jsonb_build_object('type','object','properties',target.resolved->'attributes'))) c WHERE c->>'requiresMigration'='true')) THEN
    RAISE EXCEPTION 'DOMAIN_MIGRATION_REQUIRED' USING ERRCODE='23514'; END IF;
  END IF;
  IF migration THEN
   IF (SELECT coalesce(jsonb_agg(value ORDER BY value#>>'{}'),'[]') FROM jsonb_array_elements(policy_changes)) IS DISTINCT FROM
    (SELECT coalesce(jsonb_agg(value ORDER BY value#>>'{}'),'[]') FROM jsonb_array_elements(plan->'acknowledgedPolicyChanges')) THEN
    RAISE EXCEPTION 'DOMAIN_MIGRATION_INVALID' USING ERRCODE='23514'; END IF;
   SELECT coalesce(jsonb_agg(type_version ORDER BY type_version),'[]') INTO source_versions FROM
    (SELECT DISTINCT d.type_version FROM public.domains d WHERE d.tenant_id=tenant AND d.type_id=type_identity) versions;
   IF plan->'attributes'->'sourceVersions' IS DISTINCT FROM source_versions THEN RAISE EXCEPTION 'DOMAIN_MIGRATION_INVALID' USING ERRCODE='23514'; END IF;
   -- Even an empty cohort validates every transform and acknowledgement. Actual
   -- members below run the execution path; validate_only never proves execution.
   PERFORM public.gc_relation_attribute_transform(public.gc_domain_adapt(previous),public.gc_domain_adapt(previous),public.gc_domain_adapt(target),plan->'attributes','{}',true);
   FOR item IN SELECT value FROM jsonb_array_elements(source_versions) LOOP
    source:=public.gc_domain_policy(operation_id,type_identity,(item#>>'{}')::integer);
    source_policies:=source_policies||jsonb_build_array(jsonb_build_object('pin',jsonb_build_object('typeId',type_identity,'version',source.version),
     'definitionHash',source.definition_hash,'resolutionHash',source.resolution_hash));
   END LOOP;
   FOR item IN SELECT value FROM jsonb_array_elements(plan->'lifecycle'->'mappings') LOOP
    IF NOT public.gc_relation_keys(item,ARRAY['sourceVersion','from','to']) OR NOT public.gc_relation_positive_integer(item->'sourceVersion')
    OR NOT public.gc_relation_safe_id(item->>'from') OR NOT public.gc_relation_safe_id(item->>'to') OR NOT source_versions @> jsonb_build_array(item->'sourceVersion') THEN
     RAISE EXCEPTION 'DOMAIN_MIGRATION_INVALID' USING ERRCODE='23514'; END IF;
    source:=public.gc_domain_policy(operation_id,type_identity,(item->>'sourceVersion')::integer);
    IF NOT source.resolved->'lifecycle'->'states' @> jsonb_build_array(item->'from') OR NOT target.resolved->'lifecycle'->'states' @> jsonb_build_array(item->'to') THEN
     RAISE EXCEPTION 'DOMAIN_MIGRATION_INVALID' USING ERRCODE='23514'; END IF;
   END LOOP;
   IF (SELECT count(*)<>count(DISTINCT jsonb_build_array(value->'sourceVersion',value->'from')) FROM jsonb_array_elements(plan->'lifecycle'->'mappings')) THEN
    RAISE EXCEPTION 'DOMAIN_MIGRATION_INVALID' USING ERRCODE='23514'; END IF;
  END IF;
  FOR domain_row IN SELECT d.* FROM public.domains d WHERE d.tenant_id=tenant AND d.type_id=type_identity ORDER BY d.id LOOP
   PERFORM public.gc_domain_deadline(); before_value:=public.gc_domain_view(domain_row);
   source:=public.gc_domain_policy(operation_id,type_identity,domain_row.type_version);
   IF NOT public.gc_domain_tuple_valid(before_value,source.resolved,false) THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
   IF NOT migration THEN
    IF NOT public.gc_domain_tuple_valid(before_value,target.resolved) THEN RAISE EXCEPTION 'DOMAIN_MIGRATION_REQUIRED' USING ERRCODE='23514'; END IF;
   ELSE
    attrs:=public.gc_relation_attribute_transform(public.gc_domain_adapt(previous),public.gc_domain_adapt(source),public.gc_domain_adapt(target),plan->'attributes',domain_row.attributes);
    SELECT value INTO override_value FROM jsonb_array_elements(plan->'owner'->'overrides') WHERE value->>'domainId'=domain_row.id::text;
    selected_owner:=CASE WHEN override_value IS NULL THEN domain_row.owner_id ELSE (override_value->>'ownerId')::uuid END;
    IF (override_value IS NOT NULL AND selected_owner IS NOT NULL AND NOT public.gc_domain_owner_active(selected_owner))
    OR (source.resolved->>'requiredOwner'='true' AND NOT public.gc_domain_owner_active(domain_row.owner_id)
     AND NOT (override_value IS NOT NULL AND public.gc_domain_owner_active(selected_owner))
     AND NOT (target.resolved->>'requiredOwner'='false' AND plan->'acknowledgedPolicyChanges' @> '["required_owner_changed"]')) THEN
     RAISE EXCEPTION 'DOMAIN_MIGRATION_INVALID' USING ERRCODE='23514'; END IF;
    SELECT value INTO mapped FROM jsonb_array_elements(plan->'lifecycle'->'mappings') WHERE value->>'sourceVersion'=domain_row.type_version::text AND value->>'from'=domain_row.state;
    IF mapped IS NULL AND plan->'lifecycle'->>'onUnmapped'='error' THEN RAISE EXCEPTION 'DOMAIN_MIGRATION_INVALID' USING ERRCODE='23514'; END IF;
    after_value:=before_value||jsonb_build_object('type',jsonb_build_object('typeId',type_identity,'version',target.version),'attributes',attrs,
     'ownerId',selected_owner,'state',coalesce(mapped->>'to',domain_row.state),'version',domain_row.version::bigint+1,'updatedAt',clock_text,'updatedBy',actor);
    IF domain_row.version=2147483647 OR NOT public.gc_domain_tuple_valid(after_value,target.resolved) THEN RAISE EXCEPTION 'DOMAIN_MIGRATION_INVALID' USING ERRCODE='23514'; END IF;
    PERFORM public.gc_domain_claim_changed(operation_id,before_value,after_value,'type-migrated',operation_id);
    outcomes:=outcomes||jsonb_build_array(jsonb_build_object('domainId',domain_row.id,'fromVersion',domain_row.version,'toVersion',domain_row.version+1,
     'before',public.gc_domain_tuple(before_value),'after',public.gc_domain_tuple(after_value)));
   END IF;
  END LOOP;
  new_head:=to_jsonb(head); type_response:=public.gc_domain_type_view(target,head.current_version);
  PERFORM public.gc_domain_charge(operation_id,jsonb_build_array(old_head,new_head,to_jsonb(target),target.resolved->'dependencies'));
  INSERT INTO public.domain_operation_type_claims(tenant_id,operation_id,type_id,role,before_head,after_head,version_row,dependencies)
  VALUES(tenant,operation_id,type_identity,CASE WHEN kind='domain-type.create' THEN 'create' ELSE 'publish' END,old_head,new_head,to_jsonb(target),target.resolved->'dependencies');
  PERFORM public.gc_domain_journal_claim(operation_id,CASE WHEN kind='domain-type.create' THEN 'domain_type.created' ELSE 'domain_type.published' END,
   'domain-type',type_identity,target.version,jsonb_build_object('schemaVersion',1,'resourceKind','domain-type','typeId',type_identity,
   'previousVersion',old_head->'current_version','version',target.version,'definitionHash',target.definition_hash,'resolutionHash',target.resolution_hash,
   'migrationId',CASE WHEN migration THEN operation_id ELSE NULL END));
  response:=jsonb_build_object('type',type_response);
  IF migration THEN
   projection:=jsonb_build_object('formatVersion',1,'kind','domain-type-migration-projection','typeId',type_identity,'fromHeadVersion',previous.version,
    'targetVersion',target.version,'planHash',public.gc_type_migration_hash(plan),'sourcePolicies',source_policies,'targetDefinitionHash',target.definition_hash,
    'targetResolutionHash',target.resolution_hash,'outcomes',outcomes);
   retained:=jsonb_build_object('formatVersion',1,'id',operation_id,'typeId',type_identity,'fromHeadVersion',previous.version,'targetVersion',target.version,
    'plan',plan,'planHash',public.gc_type_migration_hash(plan),'previewDigest',request_body->'previewDigest','sourcePolicies',source_policies,
    'targetDefinitionHash',target.definition_hash,'targetResolutionHash',target.resolution_hash,'outcomes',outcomes,'actorId',actor,'occurredAt',clock_text,'reason',reason,'correlationId',correlation_id);
   PERFORM public.gc_domain_charge(operation_id,jsonb_build_array(source_policies,outcomes,retained));
   INSERT INTO public.domain_migration_operations VALUES(tenant,operation_id,type_identity,previous.version,target.version,source_policies,retained,public.gc_type_migration_hash(retained));
   response:=response||jsonb_build_object('receipt',retained);
   PERFORM public.gc_domain_journal_claim(operation_id,'domain_type_migration.executed','domain-type-migration',operation_id,1,
    jsonb_build_object('schemaVersion',1,'resourceKind','domain-type-migration','migrationId',operation_id,'typeId',type_identity,'fromHeadVersion',previous.version,
    'targetVersion',target.version,'planHash',public.gc_type_migration_hash(plan),'previewDigest',request_body->'previewDigest','receiptHash',public.gc_type_migration_hash(retained)));
  END IF;
 ELSIF kind IN ('domain.create','domain.update','domain.state','domain.hierarchy') THEN
  IF kind='domain.create' THEN
   source:=public.gc_domain_policy(operation_id,(request_body->'type'->>'typeId')::uuid,(request_body->'type'->>'version')::integer);
   before_value:=NULL;
   after_value:=jsonb_build_object('id',operation_id,'name',request_body->'name','description',request_body->'description','parentId',request_body->'parentId',
    'type',request_body->'type','attributes',request_body->'attributes','ownerId',request_body->'ownerId','state',source.resolved->'lifecycle'->'initial','status','active',
    'version',1,'createdAt',clock_text,'createdBy',actor,'updatedAt',clock_text,'updatedBy',actor); expected_action:='created';
  ELSE
   SELECT * INTO domain_row FROM public.domains d WHERE d.tenant_id=tenant AND d.id=subject;
   expected_version:=CASE WHEN kind='domain.hierarchy' THEN (change->>'expectedVersion')::integer ELSE (request_body->>'expectedVersion')::integer END;
   IF domain_row.version<>expected_version OR domain_row.version=2147483647 THEN RAISE EXCEPTION 'VERSION_CONFLICT' USING ERRCODE='23514'; END IF;
   source:=public.gc_domain_policy(operation_id,domain_row.type_id,domain_row.type_version); before_value:=public.gc_domain_view(domain_row);
   IF NOT public.gc_domain_tuple_valid(before_value,source.resolved,false) THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
   IF domain_row.status='retired' AND NOT (kind='domain.hierarchy' AND change->>'kind'='restore') THEN RAISE EXCEPTION 'DOMAIN_RETIRED' USING ERRCODE='23514'; END IF;
   after_value:=before_value||jsonb_build_object('version',domain_row.version+1,'updatedAt',clock_text,'updatedBy',actor);
   IF kind='domain.update' THEN
    after_value:=after_value||jsonb_build_object('name',request_body->'name','description',request_body->'description','attributes',request_body->'attributes','ownerId',request_body->'ownerId'); expected_action:='updated';
   ELSIF kind='domain.state' THEN
    IF NOT source.resolved->'lifecycle'->'transitions' @> jsonb_build_array(jsonb_build_object('from',domain_row.state,'to',request_body->'state')) THEN
     RAISE EXCEPTION 'DOMAIN_INVALID' USING ERRCODE='23514'; END IF;
    after_value:=after_value||jsonb_build_object('state',request_body->'state'); expected_action:='state-changed';
   ELSE
    IF change->>'kind'='move' THEN after_value:=after_value||jsonb_build_object('parentId',change->'parentId'); expected_action:='moved';
    ELSE
     IF change->'parentId' IS DISTINCT FROM before_value->'parentId' THEN RAISE EXCEPTION 'DOMAIN_INVALID' USING ERRCODE='23514'; END IF;
     IF change->>'kind'='retire' THEN
      IF domain_row.status<>'active' OR EXISTS(SELECT 1 FROM public.asset_domain_placements p WHERE p.tenant_id=tenant AND p.domain_id=subject)
      OR EXISTS(SELECT 1 FROM public.domains d WHERE d.tenant_id=tenant AND d.parent_id=subject AND d.status='active') THEN RAISE EXCEPTION 'DOMAIN_IN_USE' USING ERRCODE='23514'; END IF;
      after_value:=after_value||'{"status":"retired"}'; expected_action:='retired';
     ELSE
      IF domain_row.status<>'retired' THEN RAISE EXCEPTION 'DOMAIN_INVALID' USING ERRCODE='23514'; END IF;
      after_value:=after_value||'{"status":"active"}'; expected_action:='restored';
     END IF;
    END IF;
   END IF;
  END IF;
  IF NOT public.gc_domain_tuple_valid(after_value,source.resolved) OR ((kind='domain.create' OR after_value->'ownerId' IS DISTINCT FROM before_value->'ownerId')
   AND after_value->'ownerId'<>'null' AND NOT public.gc_domain_owner_active((after_value->>'ownerId')::uuid)) THEN RAISE EXCEPTION 'DOMAIN_INVALID' USING ERRCODE='23514'; END IF;
  IF public.gc_domain_tuple(before_value) IS NOT DISTINCT FROM public.gc_domain_tuple(after_value) THEN RAISE EXCEPTION 'DOMAIN_NO_CHANGE' USING ERRCODE='23514'; END IF;
  IF kind='domain.create' OR (kind='domain.hierarchy' AND change->>'kind' IN ('move','restore')) THEN
   parent_identity:=(after_value->>'parentId')::uuid;
   IF parent_identity IS NOT NULL AND NOT EXISTS(SELECT 1 FROM public.domains d WHERE d.tenant_id=tenant AND d.id=parent_identity AND d.status='active') THEN
    RAISE EXCEPTION 'DOMAIN_RETIRED' USING ERRCODE='23514'; END IF;
   -- Walk every affected node's resulting ancestor chain with a bounded path.
   -- UNION discovery never recurses exponentially; this check proves depth/cycle.
   FOR row_item IN SELECT unnest(array_append(domain_ids,subject)) id LOOP
    WITH RECURSIVE chain(id,parent_id,path,cycle) AS (
     SELECT row_item.id,CASE WHEN row_item.id=subject THEN parent_identity ELSE d.parent_id END,ARRAY[row_item.id],false
     FROM (SELECT 1) seed LEFT JOIN public.domains d ON d.tenant_id=tenant AND d.id=row_item.id
     UNION ALL SELECT d.id,CASE WHEN d.id=subject THEN parent_identity ELSE d.parent_id END,c.path||d.id,d.id=ANY(c.path)
     FROM chain c JOIN public.domains d ON d.tenant_id=tenant AND d.id=c.parent_id WHERE NOT c.cycle AND cardinality(c.path)<=32)
    SELECT max(cardinality(path)),bool_or(cycle) INTO max_depth,previous_required FROM chain;
    IF previous_required OR max_depth>32 THEN RAISE EXCEPTION 'DOMAIN_HIERARCHY_CYCLE' USING ERRCODE='23514'; END IF;
   END LOOP;
  END IF;
  PERFORM public.gc_domain_claim_changed(operation_id,before_value,after_value,expected_action);
  response:=jsonb_build_object('domain',after_value);
 ELSE
  SELECT a.id,a.version INTO asset_row.id,asset_row.version FROM public.assets a WHERE a.tenant_id=tenant AND a.id=(request_body->>'assetId')::uuid;
  IF NOT FOUND THEN RAISE EXCEPTION 'ASSET_NOT_FOUND' USING ERRCODE='23514'; END IF;
  SELECT * INTO placement_row FROM public.asset_domain_placements p WHERE p.tenant_id=tenant AND p.asset_id=asset_row.id;
  before_value:=CASE WHEN FOUND THEN public.gc_domain_placement_view(placement_row) ELSE NULL END;
  IF asset_row.version<>(request_body->>'assetVersion')::integer OR coalesce(placement_row.version,0)<>(request_body->>'expectedPlacementVersion')::integer
  OR coalesce(placement_row.version,0)=2147483647 THEN RAISE EXCEPTION 'VERSION_CONFLICT' USING ERRCODE='23514'; END IF;
  IF placement_row.domain_id IS NOT DISTINCT FROM (request_body->>'domainId')::uuid THEN RAISE EXCEPTION 'DOMAIN_NO_CHANGE' USING ERRCODE='23514'; END IF;
  SELECT snapshot INTO retained FROM public.asset_revisions r WHERE r.tenant_id=tenant AND r.asset_id=asset_row.id AND r.version=asset_row.version;
  IF NOT FOUND THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  revision:=NULL; tuple:='null';
  IF request_body->'domainId'<>'null' THEN
   SELECT * INTO domain_row FROM public.domains d WHERE d.tenant_id=tenant AND d.id=(request_body->>'domainId')::uuid;
   IF domain_row.version<>(request_body->>'domainVersion')::integer THEN RAISE EXCEPTION 'VERSION_CONFLICT' USING ERRCODE='23514'; END IF;
   IF domain_row.status<>'active' THEN RAISE EXCEPTION 'DOMAIN_RETIRED' USING ERRCODE='23514'; END IF;
   tuple:=public.gc_domain_view(domain_row);
   SELECT snapshot INTO revision FROM public.domain_revisions r WHERE r.tenant_id=tenant AND r.domain_id=domain_row.id AND r.version=domain_row.version;
   IF revision->'domain' IS DISTINCT FROM tuple THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  END IF;
  after_value:=jsonb_build_object('assetId',asset_row.id,'version',coalesce(placement_row.version,0)+1,'domainId',request_body->'domainId',
   'recordedAssetVersion',asset_row.version,'recordedDomainVersion',request_body->'domainVersion','recordedAt',clock_text,'recordedBy',actor);
  item:=jsonb_build_object('formatVersion',1,'placement',after_value,'reason',reason,'correlationId',correlation_id);
  PERFORM public.gc_domain_charge(operation_id,jsonb_build_array(before_value,after_value,item,revision));
  PERFORM public.gc_domain_charge_legacy_revision(operation_id,retained);
  INSERT INTO public.domain_operation_placement_claims(tenant_id,operation_id,asset_id,before_view,after_view,revision,asset_revision,target_domain_revision)
  VALUES(tenant,operation_id,asset_row.id,before_value,after_value,item,retained,revision);
  expected_action:=CASE WHEN request_body->'domainId'='null' THEN 'unassigned' WHEN placement_row.domain_id IS NULL THEN 'assigned' ELSE 'reassigned' END;
  PERFORM public.gc_domain_journal_claim(operation_id,'asset_domain_placement.'||expected_action,'asset-domain-placement',asset_row.id,(after_value->>'version')::integer,
   jsonb_build_object('schemaVersion',1,'resourceKind','asset-domain-placement','assetId',asset_row.id,'previousVersion',coalesce(placement_row.version,0),
   'version',after_value->'version','recordedAssetVersion',asset_row.version,'recordedDomainVersion',request_body->'domainVersion','domainId',request_body->'domainId',
   'revisionHash',public.gc_type_migration_hash(item)));
  response:=jsonb_build_object('placement',after_value,'domain',tuple);
 END IF;
 IF NOT migration THEN projection:=jsonb_build_object('formatVersion',1,'kind','domain-write-projection','request',request_body,'response',response); END IF;
 PERFORM public.gc_domain_charge(operation_id,jsonb_build_array(response,projection));
 UPDATE public.domain_operation_contexts c SET response=response,projection=projection,projection_hash=public.gc_type_migration_hash(projection),prepared=true
 WHERE c.tenant_id=tenant AND c.id=operation_id;
 PERFORM public.gc_domain_deadline();
 RETURN jsonb_build_object('operationId',operation_id,'occurredAt',clock_text,'projectionHash',public.gc_type_migration_hash(projection))
 ||CASE WHEN migration THEN jsonb_build_object('receiptHash',public.gc_type_migration_hash(response->'receipt')) ELSE '{}' END;
END $$;
CREATE FUNCTION public.gc_domain_write_begin(operation_id uuid,idempotency_key text,request_body jsonb,correlation_id text) RETURNS jsonb
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT public.gc_domain_begin(operation_id,idempotency_key,request_body,correlation_id,false)
$$;
CREATE FUNCTION public.gc_domain_type_migration_begin(operation_id uuid,idempotency_key text,request_body jsonb,correlation_id text) RETURNS jsonb
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT public.gc_domain_begin(operation_id,idempotency_key,request_body,correlation_id,true)
$$;

CREATE FUNCTION public.gc_domain_statement_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ BEGIN
 PERFORM public.gc_domain_current(); IF TG_OP='DELETE' THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF; RETURN NULL;
END $$;
CREATE FUNCTION public.gc_domain_epoch_advance(operation_id uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE changed bigint; BEGIN
 UPDATE public.domain_scope_state SET epoch=epoch+1 WHERE tenant_id=public.gc_tenant() AND epoch<9223372036854775807 RETURNING epoch INTO changed;
 IF NOT FOUND THEN RAISE EXCEPTION 'DOMAIN_PROFILE_LIMIT' USING ERRCODE='54000'; END IF;
 UPDATE public.domain_operation_contexts c SET increments=increments+1 WHERE c.tenant_id=public.gc_tenant() AND c.id=operation_id;
 PERFORM public.gc_domain_deadline();
END $$;
CREATE FUNCTION public.gc_domain_row_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.domain_operation_contexts; t public.domain_operation_type_claims; d public.domain_operation_domain_claims;
 p public.domain_operation_placement_claims; old_value jsonb; new_value jsonb; BEGIN
 op:=public.gc_domain_current();
 IF NEW.tenant_id IS DISTINCT FROM op.tenant_id OR TG_OP NOT IN ('INSERT','UPDATE') THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
 IF TG_RELID='public.domain_types'::regclass THEN
  SELECT * INTO t FROM public.domain_operation_type_claims WHERE tenant_id=op.tenant_id AND operation_id=op.id AND type_id=NEW.id;
  old_value:=CASE WHEN TG_OP='UPDATE' THEN to_jsonb(OLD) ELSE NULL END; new_value:=to_jsonb(NEW);
  IF t.type_id IS NULL OR t.role='validate' OR t.head_written OR old_value IS DISTINCT FROM t.before_head OR new_value IS DISTINCT FROM t.after_head
  OR (TG_OP='INSERT')<>(t.role='create') THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  UPDATE public.domain_operation_type_claims SET head_written=true WHERE tenant_id=op.tenant_id AND operation_id=op.id AND type_id=NEW.id;
 ELSIF TG_RELID='public.domains'::regclass THEN
  SELECT * INTO d FROM public.domain_operation_domain_claims WHERE tenant_id=op.tenant_id AND operation_id=op.id AND domain_id=NEW.id;
  old_value:=CASE WHEN TG_OP='UPDATE' THEN public.gc_domain_view(OLD) ELSE NULL END; new_value:=public.gc_domain_view(NEW);
  IF d.domain_id IS NULL OR d.role<>'changed' OR d.row_written OR old_value IS DISTINCT FROM d.before_view OR new_value IS DISTINCT FROM d.after_view
  OR (TG_OP='INSERT')<>(d.before_view IS NULL) THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  UPDATE public.domain_operation_domain_claims SET row_written=true WHERE tenant_id=op.tenant_id AND operation_id=op.id AND domain_id=NEW.id;
 ELSE
  SELECT * INTO p FROM public.domain_operation_placement_claims WHERE tenant_id=op.tenant_id AND operation_id=op.id AND asset_id=NEW.asset_id;
  old_value:=CASE WHEN TG_OP='UPDATE' THEN public.gc_domain_placement_view(OLD) ELSE NULL END; new_value:=public.gc_domain_placement_view(NEW);
  IF p.asset_id IS NULL OR p.row_written OR old_value IS DISTINCT FROM p.before_view OR new_value IS DISTINCT FROM p.after_view
  OR (TG_OP='INSERT')<>(p.before_view IS NULL) THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  UPDATE public.domain_operation_placement_claims SET row_written=true WHERE tenant_id=op.tenant_id AND operation_id=op.id AND asset_id=NEW.asset_id;
 END IF;
 PERFORM public.gc_domain_epoch_advance(op.id); RETURN NEW;
END $$;
CREATE FUNCTION public.gc_domain_version_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.domain_operation_contexts; c public.domain_operation_type_claims; BEGIN
 op:=public.gc_domain_current();
 SELECT * INTO c FROM public.domain_operation_type_claims WHERE tenant_id=op.tenant_id AND operation_id=op.id AND type_id=NEW.type_id;
 IF TG_OP<>'INSERT' OR NEW.tenant_id IS DISTINCT FROM op.tenant_id OR c.type_id IS NULL OR c.role='validate' OR c.version_written
 OR NOT c.head_written OR to_jsonb(NEW) IS DISTINCT FROM c.version_row THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
 UPDATE public.domain_operation_type_claims SET version_written=true WHERE tenant_id=op.tenant_id AND operation_id=op.id AND type_id=NEW.type_id;
 RETURN NEW;
END $$;
CREATE FUNCTION public.gc_domain_install_dependencies() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.domain_operation_contexts; c public.domain_operation_type_claims; BEGIN
 op:=public.gc_domain_current();
 SELECT * INTO c FROM public.domain_operation_type_claims WHERE tenant_id=op.tenant_id AND operation_id=op.id AND type_id=NEW.type_id;
 INSERT INTO public.domain_type_dependencies(tenant_id,type_id,version,parent_type_id,parent_version)
 SELECT op.tenant_id,NEW.type_id,NEW.version,(value->>'typeId')::uuid,(value->>'version')::integer FROM jsonb_array_elements(c.dependencies);
 RETURN NULL;
END $$;
CREATE FUNCTION public.gc_domain_revision_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.domain_operation_contexts; d public.domain_operation_domain_claims; p public.domain_operation_placement_claims; actual jsonb; BEGIN
 op:=public.gc_domain_current();
 IF TG_OP<>'INSERT' OR NEW.tenant_id IS DISTINCT FROM op.tenant_id THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
 IF TG_RELID='public.domain_revisions'::regclass THEN
  SELECT * INTO d FROM public.domain_operation_domain_claims WHERE tenant_id=op.tenant_id AND operation_id=op.id AND domain_id=NEW.domain_id;
  SELECT public.gc_domain_view(r) INTO actual FROM public.domains r WHERE r.tenant_id=op.tenant_id AND r.id=NEW.domain_id;
  IF d.domain_id IS NULL OR d.role<>'changed' OR NOT d.row_written OR d.revision_written OR NEW.version::text IS DISTINCT FROM d.after_view->>'version'
  OR NEW.snapshot IS DISTINCT FROM d.revision OR actual IS DISTINCT FROM d.after_view THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  UPDATE public.domain_operation_domain_claims SET revision_written=true WHERE tenant_id=op.tenant_id AND operation_id=op.id AND domain_id=NEW.domain_id;
 ELSE
  SELECT * INTO p FROM public.domain_operation_placement_claims WHERE tenant_id=op.tenant_id AND operation_id=op.id AND asset_id=NEW.asset_id;
  SELECT public.gc_domain_placement_view(r) INTO actual FROM public.asset_domain_placements r WHERE r.tenant_id=op.tenant_id AND r.asset_id=NEW.asset_id;
  IF p.asset_id IS NULL OR NOT p.row_written OR p.revision_written OR NEW.version::text IS DISTINCT FROM p.after_view->>'version'
  OR NEW.snapshot IS DISTINCT FROM p.revision OR actual IS DISTINCT FROM p.after_view THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  UPDATE public.domain_operation_placement_claims SET revision_written=true WHERE tenant_id=op.tenant_id AND operation_id=op.id AND asset_id=NEW.asset_id;
 END IF;
 RETURN NEW;
END $$;
DO $$ DECLARE n text; BEGIN
 FOREACH n IN ARRAY ARRAY['domain_types','domains','asset_domain_placements','domain_type_versions','domain_revisions','asset_domain_placement_revisions'] LOOP
  EXECUTE format('CREATE TRIGGER domain_prepared_statement BEFORE INSERT OR UPDATE OR DELETE ON public.%I FOR EACH STATEMENT EXECUTE FUNCTION public.gc_domain_statement_guard()',n);
 END LOOP;
 FOREACH n IN ARRAY ARRAY['domain_types','domains','asset_domain_placements'] LOOP
  EXECUTE format('CREATE TRIGGER domain_exact_row BEFORE INSERT OR UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.gc_domain_row_guard()',n);
 END LOOP;
END $$;
CREATE TRIGGER domain_exact_version BEFORE INSERT ON public.domain_type_versions FOR EACH ROW EXECUTE FUNCTION public.gc_domain_version_guard();
CREATE TRIGGER domain_install_dependencies AFTER INSERT ON public.domain_type_versions FOR EACH ROW EXECUTE FUNCTION public.gc_domain_install_dependencies();
CREATE TRIGGER domain_exact_revision BEFORE INSERT ON public.domain_revisions FOR EACH ROW EXECUTE FUNCTION public.gc_domain_revision_guard();
CREATE TRIGGER domain_exact_revision BEFORE INSERT ON public.asset_domain_placement_revisions FOR EACH ROW EXECUTE FUNCTION public.gc_domain_revision_guard();

CREATE FUNCTION public.gc_domain_journal_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
#variable_conflict use_variable
DECLARE op public.domain_operation_contexts; c public.domain_operation_journal_claims;
 action_name text; old_action text; resource text; resource_kind text; version_number integer; expected jsonb; expected_envelope jsonb; prior_hash text; protected boolean; BEGIN
 IF TG_RELID='public.audit'::regclass THEN
  action_name:=CASE WHEN TG_OP='DELETE' THEN OLD.action ELSE NEW.action END;
  old_action:=CASE WHEN TG_OP='INSERT' THEN '' ELSE OLD.action END;
 ELSE
  action_name:=CASE WHEN TG_OP='DELETE' THEN OLD.event_type ELSE NEW.event_type END;
  old_action:=CASE WHEN TG_OP='INSERT' THEN '' ELSE OLD.event_type END;
 END IF;
 protected:=action_name LIKE 'domain.%' OR action_name LIKE 'domain_type.%' OR action_name LIKE 'asset_domain_placement.%' OR action_name LIKE 'domain_type_migration.%'
 OR old_action LIKE 'domain.%' OR old_action LIKE 'domain_type.%' OR old_action LIKE 'asset_domain_placement.%' OR old_action LIKE 'domain_type_migration.%';
 SELECT * INTO op FROM public.domain_operation_contexts WHERE tenant_id=public.gc_tenant() AND transaction_id=pg_current_xact_id();
 IF op.id IS NULL THEN
  IF NOT protected THEN
   PERFORM public.gc_domain_bind('legacy');
   IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
  END IF;
  -- Delivery metadata remains mutable; event identity, attribution and payload do not.
  IF TG_RELID='public.outbox'::regclass AND TG_OP='UPDATE' AND (to_jsonb(NEW)-ARRAY['processed_at','attempts'])=(to_jsonb(OLD)-ARRAY['processed_at','attempts']) THEN
   PERFORM public.gc_domain_bind('legacy'); RETURN NEW; END IF;
  RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514';
 END IF;
 op:=public.gc_domain_current();
 IF TG_OP<>'INSERT' OR NEW.tenant_id IS DISTINCT FROM op.tenant_id THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
 IF TG_RELID='public.audit'::regclass THEN
  resource:=NEW.resource_id; resource_kind:=NEW.changes->>'resourceKind';
  IF NOT public.gc_relation_positive_integer(NEW.changes->'resourceVersion') THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  version_number:=(NEW.changes->>'resourceVersion')::integer;
 ELSE resource:=NEW.resource_id; resource_kind:=NEW.payload->>'resourceKind'; version_number:=NEW.resource_version; END IF;
 IF NOT public.gc_domain_uuid(to_jsonb(resource)) THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
 SELECT * INTO c FROM public.domain_operation_journal_claims j WHERE j.tenant_id=op.tenant_id AND j.operation_id=op.id
 AND j.resource_kind=resource_kind AND j.resource_id=resource::uuid AND j.resource_version=version_number AND j.action=action_name;
 IF c.operation_id IS NULL OR (c.event_id IS NOT NULL AND c.event_id<>NEW.id) THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
 IF TG_RELID='public.audit'::regclass THEN
  expected:=c.data||jsonb_build_object('reason',op.reason,'resourceVersion',version_number);
  SELECT a.hash INTO prior_hash FROM public.audit a WHERE a.tenant_id=op.tenant_id ORDER BY a.sequence DESC LIMIT 1;
  expected_envelope:=jsonb_build_object('id',NEW.id,'tenantId',op.tenant_id,'actorId',op.actor_id,'actorName',op.actor_name,'action',c.action,
   'resourceId',resource,'version',version_number,'changes',expected,'correlationId',op.correlation_id,'occurredAt',public.gc_relation_utc(op.occurred_at),
   'previousHash',coalesce(prior_hash,repeat('0',64)));
  IF c.audit_written OR NEW.actor_id<>op.actor_id::text OR NEW.actor_name<>op.actor_name OR NEW.correlation_id<>op.correlation_id OR NEW.occurred_at<>op.occurred_at
  OR NEW.changes IS DISTINCT FROM expected OR NEW.envelope IS DISTINCT FROM expected_envelope OR NEW.previous_hash<>coalesce(prior_hash,repeat('0',64))
  OR NEW.hash<>public.gc_type_migration_hash(expected_envelope) THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  UPDATE public.domain_operation_journal_claims j SET event_id=NEW.id,audit_written=true WHERE j.tenant_id=op.tenant_id AND j.operation_id=op.id
  AND j.resource_kind=c.resource_kind AND j.resource_id=c.resource_id AND j.resource_version=c.resource_version;
 ELSE
  expected:=jsonb_build_object('specversion','1.0','id',NEW.id,'type',c.action,'source','governance-commons','subject',resource,'time',public.gc_relation_utc(op.occurred_at),
   'tenantId',op.tenant_id,'resourceVersion',version_number,'actorId',op.actor_id,'correlationId',op.correlation_id,'resourceKind',c.resource_kind,'data',c.data);
  IF c.outbox_written OR NEW.payload IS DISTINCT FROM expected OR NEW.created_at<>op.occurred_at OR NEW.processed_at IS NOT NULL OR NEW.attempts<>0 THEN
   RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  UPDATE public.domain_operation_journal_claims j SET event_id=NEW.id,outbox_written=true WHERE j.tenant_id=op.tenant_id AND j.operation_id=op.id
  AND j.resource_kind=c.resource_kind AND j.resource_id=c.resource_id AND j.resource_version=c.resource_version;
 END IF;
 PERFORM public.gc_domain_deadline(); RETURN NEW;
END $$;
CREATE TRIGGER domain_journal_claim BEFORE INSERT OR UPDATE OR DELETE ON public.audit FOR EACH ROW EXECUTE FUNCTION public.gc_domain_journal_guard();
CREATE TRIGGER domain_journal_claim BEFORE INSERT OR UPDATE OR DELETE ON public.outbox FOR EACH ROW EXECUTE FUNCTION public.gc_domain_journal_guard();

CREATE FUNCTION public.gc_domain_verify(operation_id uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
#variable_conflict use_variable
DECLARE op public.domain_operation_contexts; t public.domain_operation_type_claims; d public.domain_operation_domain_claims; p public.domain_operation_placement_claims;
 m public.domain_migration_operations; c public.domain_operation_journal_claims; actual jsonb; actual_before jsonb; actual_after jsonb; outcome jsonb; outcomes jsonb:='[]';
 receipt jsonb; response jsonb; target public.domain_type_versions; type_response jsonb; total integer; epoch bigint; BEGIN
 op:=public.gc_domain_current(false);
 IF op.id<>operation_id OR NOT op.prepared THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
 PERFORM public.gc_domain_authorize(op.permissions);
 IF cardinality(op.asset_scope)>0 THEN
  PERFORM public.gc_domain_authorize(ARRAY['catalog:read']);
  IF EXISTS(SELECT 1 FROM public.assets a WHERE a.tenant_id=op.tenant_id AND a.id=ANY(op.asset_scope)
   AND a.visibility='restricted' AND NOT a.allowed_identities @> jsonb_build_array(op.actor_id)) THEN RAISE EXCEPTION 'DOMAIN_SCOPE_UNAVAILABLE' USING ERRCODE='42501'; END IF;
 END IF;
 SELECT s.epoch INTO epoch FROM public.domain_scope_state s WHERE s.tenant_id=op.tenant_id;
 total:=(SELECT count(*) FROM public.domain_operation_type_claims claim_rows WHERE claim_rows.tenant_id=op.tenant_id AND claim_rows.operation_id=op.id AND role<>'validate')
  +(SELECT count(*) FROM public.domain_operation_domain_claims claim_rows WHERE claim_rows.tenant_id=op.tenant_id AND claim_rows.operation_id=op.id AND role='changed')
  +(SELECT count(*) FROM public.domain_operation_placement_claims claim_rows WHERE claim_rows.tenant_id=op.tenant_id AND claim_rows.operation_id=op.id);
 IF op.increments<>total OR epoch IS DISTINCT FROM op.initial_epoch+total THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
 FOR t IN SELECT * FROM public.domain_operation_type_claims claim_rows WHERE claim_rows.tenant_id=op.tenant_id AND claim_rows.operation_id=op.id ORDER BY type_id LOOP
  PERFORM public.gc_domain_deadline();
  IF NOT t.head_written OR NOT t.version_written THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  SELECT to_jsonb(h) INTO actual FROM public.domain_types h WHERE h.tenant_id=op.tenant_id AND h.id=t.type_id;
  IF actual IS DISTINCT FROM t.after_head THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  SELECT * INTO target FROM public.domain_type_versions WHERE tenant_id=op.tenant_id AND type_id=t.type_id AND version=(t.version_row->>'version')::integer;
  IF to_jsonb(target) IS DISTINCT FROM t.version_row THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object('typeId',parent_type_id,'version',parent_version) ORDER BY parent_type_id),'[]') INTO actual
  FROM public.domain_type_dependencies WHERE tenant_id=op.tenant_id AND type_id=t.type_id AND version=target.version;
  IF actual IS DISTINCT FROM t.dependencies THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  type_response:=public.gc_domain_type_view(target,(t.after_head->>'current_version')::integer);
  IF t.role='publish' THEN
   IF (SELECT coalesce(array_agg(id ORDER BY id),'{}') FROM public.domains WHERE tenant_id=op.tenant_id AND type_id=t.type_id) IS DISTINCT FROM
    (SELECT coalesce(array_agg(domain_id ORDER BY domain_id),'{}') FROM public.domain_operation_domain_claims claim_rows
    WHERE claim_rows.tenant_id=op.tenant_id AND claim_rows.operation_id=op.id AND before_view->'type'->>'typeId'=t.type_id::text) THEN
    RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  END IF;
 END LOOP;
 FOR d IN SELECT * FROM public.domain_operation_domain_claims claim_rows WHERE claim_rows.tenant_id=op.tenant_id AND claim_rows.operation_id=op.id ORDER BY domain_id LOOP
  PERFORM public.gc_domain_deadline();
  SELECT public.gc_domain_view(r) INTO actual FROM public.domains r WHERE r.tenant_id=op.tenant_id AND r.id=d.domain_id;
  IF actual IS DISTINCT FROM d.after_view OR (d.role='changed' AND (NOT d.row_written OR NOT d.revision_written))
   OR (d.role='validate' AND (d.row_written OR d.revision_written)) THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  IF d.before_view IS NOT NULL THEN
   SELECT snapshot INTO actual_before FROM public.domain_revisions WHERE tenant_id=op.tenant_id AND domain_id=d.domain_id AND version=(d.before_view->>'version')::integer;
   IF actual_before IS DISTINCT FROM d.before_revision THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  END IF;
  IF d.role='changed' THEN
   SELECT snapshot INTO actual_after FROM public.domain_revisions WHERE tenant_id=op.tenant_id AND domain_id=d.domain_id AND version=(d.after_view->>'version')::integer;
   IF actual_after IS DISTINCT FROM d.revision THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
   SELECT * INTO target FROM public.domain_type_versions WHERE tenant_id=op.tenant_id AND type_id=(actual->'type'->>'typeId')::uuid AND version=(actual->'type'->>'version')::integer;
   IF NOT public.gc_domain_tuple_valid(actual,target.resolved) THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
   IF op.mode='migration' THEN
    outcomes:=outcomes||jsonb_build_array(jsonb_build_object('domainId',d.domain_id,'fromVersion',actual_before->'domain'->'version','toVersion',actual_after->'domain'->'version',
     'before',public.gc_domain_tuple(actual_before->'domain'),'after',public.gc_domain_tuple(actual_after->'domain')));
   ELSE response:=jsonb_build_object('domain',actual); END IF;
  END IF;
 END LOOP;
 FOR p IN SELECT * FROM public.domain_operation_placement_claims claim_rows WHERE claim_rows.tenant_id=op.tenant_id AND claim_rows.operation_id=op.id ORDER BY asset_id LOOP
  PERFORM public.gc_domain_deadline();
  SELECT public.gc_domain_placement_view(r) INTO actual FROM public.asset_domain_placements r WHERE r.tenant_id=op.tenant_id AND r.asset_id=p.asset_id;
  SELECT snapshot INTO actual_after FROM public.asset_domain_placement_revisions WHERE tenant_id=op.tenant_id AND asset_id=p.asset_id AND version=(p.after_view->>'version')::integer;
  IF NOT p.row_written OR NOT p.revision_written OR actual IS DISTINCT FROM p.after_view OR actual_after IS DISTINCT FROM p.revision
  OR p.asset_revision IS DISTINCT FROM (SELECT snapshot FROM public.asset_revisions WHERE tenant_id=op.tenant_id AND asset_id=p.asset_id AND version=(p.after_view->>'recordedAssetVersion')::integer)
  OR NOT EXISTS(SELECT 1 FROM public.assets WHERE tenant_id=op.tenant_id AND id=p.asset_id AND version=(p.after_view->>'recordedAssetVersion')::integer) THEN
   RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  actual_after:='null';
  IF p.after_view->'domainId'<>'null' THEN
   IF p.target_domain_revision IS DISTINCT FROM (SELECT snapshot FROM public.domain_revisions WHERE tenant_id=op.tenant_id
    AND domain_id=(p.after_view->>'domainId')::uuid AND version=(p.after_view->>'recordedDomainVersion')::integer) THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
   SELECT public.gc_domain_view(r) INTO actual_after FROM public.domains r WHERE r.tenant_id=op.tenant_id AND r.id=(p.after_view->>'domainId')::uuid;
   IF actual_after IS DISTINCT FROM p.target_domain_revision->'domain' OR actual_after->>'status'<>'active' THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  END IF;
  response:=jsonb_build_object('placement',actual,'domain',actual_after);
 END LOOP;
 FOR c IN SELECT * FROM public.domain_operation_journal_claims claim_rows WHERE claim_rows.tenant_id=op.tenant_id AND claim_rows.operation_id=op.id LOOP
  PERFORM public.gc_domain_deadline();
  IF NOT c.audit_written OR NOT c.outbox_written OR c.event_id IS NULL
  OR NOT EXISTS(SELECT 1 FROM public.audit a WHERE a.tenant_id=op.tenant_id AND a.id=c.event_id AND a.action=c.action AND a.resource_id=c.resource_id::text
   AND a.actor_id=op.actor_id::text AND a.occurred_at=op.occurred_at AND a.correlation_id=op.correlation_id
   AND a.changes=c.data||jsonb_build_object('reason',op.reason,'resourceVersion',c.resource_version))
  OR NOT EXISTS(SELECT 1 FROM public.outbox o WHERE o.tenant_id=op.tenant_id AND o.id=c.event_id AND o.event_type=c.action
   AND o.resource_id=c.resource_id::text AND o.resource_version=c.resource_version AND o.payload->'data'=c.data
   AND o.payload->>'resourceKind'=c.resource_kind) THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
 END LOOP;
 IF type_response IS NOT NULL THEN response:=jsonb_build_object('type',type_response); END IF;
 IF op.mode='migration' THEN
  SELECT * INTO m FROM public.domain_migration_operations migration_rows WHERE migration_rows.tenant_id=op.tenant_id AND migration_rows.operation_id=op.id;
  receipt:=jsonb_build_object('formatVersion',1,'id',op.id,'typeId',m.type_id,'fromHeadVersion',m.from_head_version,'targetVersion',m.target_version,
   'plan',op.request_body->'plan','planHash',public.gc_type_migration_hash(op.request_body->'plan'),'previewDigest',op.request_body->'previewDigest',
   'sourcePolicies',m.source_policies,'targetDefinitionHash',type_response->'definitionHash','targetResolutionHash',type_response->'resolutionHash',
   'outcomes',outcomes,'actorId',op.actor_id,'occurredAt',public.gc_relation_utc(op.occurred_at),'reason',op.reason,'correlationId',op.correlation_id);
  IF receipt IS DISTINCT FROM m.receipt OR public.gc_type_migration_hash(receipt)<>m.receipt_hash THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  response:=response||jsonb_build_object('receipt',receipt);
 END IF;
 IF response IS DISTINCT FROM op.response THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
 PERFORM public.gc_domain_deadline(); RETURN response;
END $$;
CREATE FUNCTION public.gc_domain_seal(operation_id uuid,migration boolean) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.domain_operation_contexts; response jsonb; receipt jsonb; item jsonb; BEGIN
 op:=public.gc_domain_current();
 IF op.id<>operation_id OR (op.mode='migration')<>migration THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
 response:=public.gc_domain_verify(operation_id);
 IF migration THEN
  receipt:=response->'receipt';
  INSERT INTO public.domain_type_migrations(tenant_id,id,type_id,from_head_version,target_version,plan,plan_hash,preview_digest,target_definition_hash,
  target_resolution_hash,source_policies,receipt,executed_by,executed_at)
  VALUES(op.tenant_id,op.id,(receipt->>'typeId')::uuid,(receipt->>'fromHeadVersion')::integer,(receipt->>'targetVersion')::integer,
  receipt->'plan',receipt->>'planHash',receipt->>'previewDigest',receipt->>'targetDefinitionHash',receipt->>'targetResolutionHash',receipt->'sourcePolicies',receipt,op.actor_id,op.occurred_at);
  FOR item IN SELECT value FROM jsonb_array_elements(receipt->'outcomes') LOOP
   PERFORM public.gc_domain_deadline();
   INSERT INTO public.domain_type_migration_domains VALUES(op.tenant_id,op.id,(item->>'domainId')::uuid,(item->>'fromVersion')::integer,(item->>'toVersion')::integer,
    public.gc_type_migration_hash(item->'before'),public.gc_type_migration_hash(item->'after'));
  END LOOP;
 END IF;
 UPDATE public.domain_operation_contexts SET state='sealed' WHERE tenant_id=op.tenant_id AND id=op.id;
 PERFORM public.gc_domain_deadline(); RETURN response;
END $$;
CREATE FUNCTION public.gc_domain_write_seal(operation_id uuid) RETURNS jsonb
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ SELECT public.gc_domain_seal(operation_id,false) $$;
CREATE FUNCTION public.gc_domain_type_migration_seal(operation_id uuid) RETURNS jsonb
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ SELECT public.gc_domain_seal(operation_id,true) $$;

CREATE FUNCTION public.gc_domain_idempotency_guard() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE reserved text[]:=ARRAY['domain-type.create','domain-type.publish','domain.create','domain.update','domain.state','domain.hierarchy','domain.placement','domain-type-migration.execute'];
 op public.domain_operation_contexts; BEGIN
 IF (TG_OP IN ('UPDATE','DELETE') AND OLD.operation=ANY(reserved)) OR (TG_OP<>'INSERT' AND NEW.operation=ANY(reserved)) THEN
  RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
 IF TG_OP='DELETE' OR NOT NEW.operation=ANY(reserved) THEN
  PERFORM public.gc_domain_bind('legacy'); IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
 END IF;
 op:=public.gc_domain_current(false);
 IF op.state<>'sealed' OR NEW.tenant_id IS DISTINCT FROM op.tenant_id OR NEW.actor_id<>op.actor_id::text OR NEW.operation<>op.namespace
 OR NEW.key<>op.idempotency_key OR NEW.request_hash<>op.request_hash OR NEW.response IS DISTINCT FROM op.response THEN
  RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
 PERFORM public.gc_domain_deadline(); RETURN NEW;
END $$;
CREATE TRIGGER domain_reserved_idempotency BEFORE INSERT OR UPDATE OR DELETE ON public.idempotency FOR EACH ROW EXECUTE FUNCTION public.gc_domain_idempotency_guard();
CREATE FUNCTION public.gc_domain_finalize() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.domain_operation_contexts; expected_response jsonb; item jsonb; actual jsonb; m public.domain_type_migrations; child public.domain_type_migration_domains; BEGIN
 op:=public.gc_domain_current(false);
 IF op.id<>NEW.id OR op.tenant_id<>NEW.tenant_id OR op.state NOT IN ('sealed','finalized') THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
 expected_response:=public.gc_domain_verify(op.id);
 IF NOT EXISTS(SELECT 1 FROM public.idempotency i WHERE i.tenant_id=op.tenant_id AND i.actor_id=op.actor_id::text AND i.operation=op.namespace AND i.key=op.idempotency_key
 AND i.request_hash=op.request_hash AND i.response=expected_response) THEN RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
 IF op.mode='migration' THEN
  SELECT * INTO m FROM public.domain_type_migrations WHERE tenant_id=op.tenant_id AND id=op.id;
  actual:=expected_response->'receipt';
  IF m.id IS NULL OR m.receipt IS DISTINCT FROM actual OR m.type_id::text IS DISTINCT FROM actual->>'typeId'
  OR m.from_head_version::text IS DISTINCT FROM actual->>'fromHeadVersion' OR m.target_version::text IS DISTINCT FROM actual->>'targetVersion'
  OR m.plan IS DISTINCT FROM actual->'plan' OR m.plan_hash IS DISTINCT FROM actual->>'planHash' OR m.preview_digest IS DISTINCT FROM actual->>'previewDigest'
  OR m.target_definition_hash IS DISTINCT FROM actual->>'targetDefinitionHash' OR m.target_resolution_hash IS DISTINCT FROM actual->>'targetResolutionHash'
  OR m.source_policies IS DISTINCT FROM actual->'sourcePolicies' OR m.executed_by<>op.actor_id OR m.executed_at<>op.occurred_at THEN
   RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  IF (SELECT count(*) FROM public.domain_type_migration_domains WHERE tenant_id=op.tenant_id AND migration_id=op.id)<>jsonb_array_length(actual->'outcomes') THEN
   RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  FOR item IN SELECT value FROM jsonb_array_elements(actual->'outcomes') LOOP
   PERFORM public.gc_domain_deadline();
   SELECT * INTO child FROM public.domain_type_migration_domains WHERE tenant_id=op.tenant_id AND migration_id=op.id AND domain_id=(item->>'domainId')::uuid;
   IF child.domain_id IS NULL OR child.from_version::text<>item->>'fromVersion' OR child.to_version::text<>item->>'toVersion'
   OR child.before_tuple_hash<>public.gc_type_migration_hash(item->'before') OR child.after_tuple_hash<>public.gc_type_migration_hash(item->'after')
   OR item->'before' IS DISTINCT FROM (SELECT public.gc_domain_tuple(snapshot->'domain') FROM public.domain_revisions WHERE tenant_id=op.tenant_id AND domain_id=child.domain_id AND version=child.from_version)
   OR item->'after' IS DISTINCT FROM (SELECT public.gc_domain_tuple(snapshot->'domain') FROM public.domain_revisions WHERE tenant_id=op.tenant_id AND domain_id=child.domain_id AND version=child.to_version) THEN
    RAISE EXCEPTION 'DOMAIN_STORAGE_INVALID' USING ERRCODE='23514'; END IF;
  END LOOP;
 END IF;
 PERFORM public.gc_domain_deadline();
 IF op.state<>'finalized' THEN UPDATE public.domain_operation_contexts SET state='finalized' WHERE tenant_id=op.tenant_id AND id=op.id; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER domain_complete_operation AFTER INSERT ON public.domain_operation_contexts DEFERRABLE INITIALLY DEFERRED
 FOR EACH ROW EXECUTE FUNCTION public.gc_domain_finalize();

-- Disclosure of a stored success is independently authorized over its original
-- captured scope, even after descendants/placements move elsewhere. No private
-- identifiers, counts, epochs or policy values leave this boolean capability.
CREATE FUNCTION public.gc_domain_replay_authorize(operation text,key text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE op public.domain_operation_contexts; BEGIN
 PERFORM public.gc_domain_deadline();
 IF NOT public.gc_domain_uuid(to_jsonb(public.gc_actor())) THEN RETURN false; END IF;
 SELECT * INTO op FROM public.domain_operation_contexts c WHERE c.tenant_id=public.gc_tenant() AND c.actor_id::text=public.gc_actor()
 AND c.namespace=operation AND c.idempotency_key=key AND c.state='finalized';
 IF op.id IS NULL THEN RETURN false; END IF;
 BEGIN PERFORM public.gc_domain_authorize(op.permissions);
  IF cardinality(op.asset_scope)>0 THEN PERFORM public.gc_domain_authorize(ARRAY['catalog:read']); END IF;
 EXCEPTION WHEN insufficient_privilege THEN RETURN false; END;
 IF NOT EXISTS(SELECT 1 FROM public.idempotency i WHERE i.tenant_id=op.tenant_id AND i.actor_id=op.actor_id::text AND i.operation=op.namespace
 AND i.key=op.idempotency_key AND i.request_hash=op.request_hash AND i.response=op.response) THEN RETURN false; END IF;
 IF EXISTS(SELECT 1 FROM unnest(op.asset_scope) selected(id) LEFT JOIN public.assets a ON a.tenant_id=op.tenant_id AND a.id=selected.id
 WHERE a.id IS NULL OR (a.visibility='restricted' AND NOT a.allowed_identities @> jsonb_build_array(op.actor_id)))
 OR EXISTS(SELECT 1 FROM unnest(op.domain_scope) selected(id) LEFT JOIN public.domains d ON d.tenant_id=op.tenant_id AND d.id=selected.id WHERE d.id IS NULL)
 OR EXISTS(SELECT 1 FROM public.domain_operation_domain_claims c LEFT JOIN public.domains d ON d.tenant_id=c.tenant_id AND d.id=c.domain_id
 WHERE c.tenant_id=op.tenant_id AND c.operation_id=op.id AND (d.id IS NULL
 OR (c.before_view IS NOT NULL AND c.before_revision IS DISTINCT FROM (SELECT snapshot FROM public.domain_revisions r WHERE r.tenant_id=c.tenant_id AND r.domain_id=c.domain_id AND r.version=(c.before_view->>'version')::integer))
 OR (c.role='changed' AND c.revision IS DISTINCT FROM (SELECT snapshot FROM public.domain_revisions r WHERE r.tenant_id=c.tenant_id AND r.domain_id=c.domain_id AND r.version=(c.after_view->>'version')::integer)))) THEN RETURN false; END IF;
 IF EXISTS(SELECT 1 FROM public.domain_operation_placement_claims c WHERE c.tenant_id=op.tenant_id AND c.operation_id=op.id
 AND (c.revision IS DISTINCT FROM (SELECT snapshot FROM public.asset_domain_placement_revisions r WHERE r.tenant_id=c.tenant_id AND r.asset_id=c.asset_id AND r.version=(c.after_view->>'version')::integer)
 OR c.asset_revision IS DISTINCT FROM (SELECT snapshot FROM public.asset_revisions r WHERE r.tenant_id=c.tenant_id AND r.asset_id=c.asset_id AND r.version=(c.after_view->>'recordedAssetVersion')::integer))) THEN RETURN false; END IF;
 PERFORM public.gc_domain_deadline(); RETURN true;
END $$;

-- Every new internal helper is private, including immutable validators. Runtime
-- receives only the six reviewed entry points; no ownership or identity DML.
DO $$ DECLARE f record; BEGIN
 FOR f IN SELECT p.oid::regprocedure signature FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname LIKE 'gc_domain_%' LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,gc_app',f.signature);
 END LOOP;
END $$;
GRANT EXECUTE ON FUNCTION public.gc_domain_write_begin(uuid,text,jsonb,text),public.gc_domain_write_seal(uuid),
 public.gc_domain_type_migration_begin(uuid,text,jsonb,text),public.gc_domain_type_migration_seal(uuid),public.gc_domain_scope_epoch(),public.gc_domain_replay_authorize(text,text) TO gc_app;
