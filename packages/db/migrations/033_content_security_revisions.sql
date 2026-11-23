-- SPDX-License-Identifier: Apache-2.0
-- SQL033: private content revision provenance. This does not activate authority.
-- The counter covers the six canonical heads below, not live identity,
-- membership, approval-task or environmental facts. Those need their own pins.
DO $$ BEGIN
 IF session_user<>current_user
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR pg_has_role('gc_app',current_user,'MEMBER')
 OR NOT EXISTS(SELECT 1 FROM gc_authn.installation_root r
   WHERE r.owner_role_oid=session_user::regrole::oid AND r.owner_role_name=session_user
   AND r.database_oid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())) THEN
  RAISE EXCEPTION 'CONTENT_REVISION_EXECUTOR_REJECTED' USING ERRCODE='42501';
 END IF;
END $$;

-- Establish every existing tenant baseline while excluding writes to the source
-- heads. The migration runner commits this installation and its ledger together.
LOCK TABLE public.tenants,public.assets,public.domains,public.asset_domain_placements,
 public.classification_taxonomies,public.classification_rules,public.classification_assignments
 IN SHARE ROW EXCLUSIVE MODE;
CREATE TABLE gc_authority.content_security_heads(
 tenant_id uuid PRIMARY KEY REFERENCES public.tenants(id),
 revision bigint NOT NULL CHECK(revision>0)
);
REVOKE ALL ON gc_authority.content_security_heads FROM PUBLIC,gc_app;
ALTER TABLE gc_authority.content_security_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE gc_authority.content_security_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY authority_tenant ON gc_authority.content_security_heads
 USING(tenant_id=public.gc_tenant()) WITH CHECK(tenant_id=public.gc_tenant());
DO $$ DECLARE t uuid;previous_t text:=current_setting('gc.tenant_id',true);BEGIN
 FOR t IN SELECT id FROM public.tenants ORDER BY id LOOP
  PERFORM set_config('gc.tenant_id',t::text,true);
  INSERT INTO gc_authority.content_security_heads(tenant_id,revision) VALUES(t,1);
 END LOOP;
 PERFORM set_config('gc.tenant_id',coalesce(previous_t,''),true);
EXCEPTION WHEN OTHERS THEN
 PERFORM set_config('gc.tenant_id',coalesce(previous_t,''),true);RAISE;
END $$;

-- No direct writes or resets, including by an ordinary owner query. An owner
-- able to alter/disable triggers is a trusted migration administrator, not an
-- application executor. No runtime role receives this table or these functions.
CREATE FUNCTION gc_authority.content_revision_head_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ BEGIN
 IF TG_RELID<>'gc_authority.content_security_heads'::regclass OR TG_LEVEL<>'ROW'
 OR pg_trigger_depth()<2 OR TG_OP NOT IN('INSERT','UPDATE') THEN
  RAISE EXCEPTION 'CONTENT_REVISION_INTEGRITY' USING ERRCODE='23514';
 END IF;
 IF (TG_OP='INSERT' AND NEW.revision<>1)
 OR (TG_OP='UPDATE' AND (NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
   OR NEW.revision::numeric<>OLD.revision::numeric+1)) THEN
  RAISE EXCEPTION 'CONTENT_REVISION_INTEGRITY' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER content_revision_head_guard BEFORE INSERT OR UPDATE OR DELETE
 ON gc_authority.content_security_heads FOR EACH ROW EXECUTE FUNCTION gc_authority.content_revision_head_guard();

CREATE FUNCTION gc_authority.content_revision_tenant_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE previous_t text:=current_setting('gc.tenant_id',true);BEGIN
 IF TG_RELID<>'public.tenants'::regclass OR TG_LEVEL<>'ROW' OR TG_OP<>'INSERT' OR TG_WHEN<>'AFTER' THEN
  RAISE EXCEPTION 'CONTENT_REVISION_INTEGRITY' USING ERRCODE='23514';
 END IF;
 PERFORM set_config('gc.tenant_id',NEW.id::text,true);
 -- Deliberately no UPSERT: loss of a head must never silently reset its revision.
 INSERT INTO gc_authority.content_security_heads(tenant_id,revision) VALUES(NEW.id,1);
 PERFORM set_config('gc.tenant_id',coalesce(previous_t,''),true);
 RETURN NEW;
EXCEPTION WHEN OTHERS THEN
 PERFORM set_config('gc.tenant_id',coalesce(previous_t,''),true);RAISE;
END $$;
CREATE TRIGGER content_revision_tenant_insert AFTER INSERT ON public.tenants
 FOR EACH ROW EXECUTE FUNCTION gc_authority.content_revision_tenant_insert();

CREATE FUNCTION gc_authority.content_revision_advance() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid;head bigint;previous_t text:=current_setting('gc.tenant_id',true);BEGIN
 IF TG_LEVEL<>'ROW' OR TG_WHEN<>'AFTER' OR TG_OP NOT IN('INSERT','UPDATE','DELETE')
 OR TG_RELID<>ALL(ARRAY['public.assets'::regclass,'public.domains'::regclass,
  'public.asset_domain_placements'::regclass,'public.classification_taxonomies'::regclass,
  'public.classification_rules'::regclass,'public.classification_assignments'::regclass]) THEN
  RAISE EXCEPTION 'CONTENT_REVISION_INTEGRITY' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' AND NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
  RAISE EXCEPTION 'CONTENT_REVISION_INTEGRITY' USING ERRCODE='23514';
 END IF;
 tenant:=CASE WHEN TG_OP='DELETE' THEN OLD.tenant_id ELSE NEW.tenant_id END;
 -- Same lock domain as the canonical ledger/domain/classification writers.
 -- Never wait after a source row lock or retry a fraction of the transaction.
 IF NOT pg_try_advisory_xact_lock(hashtextextended(tenant::text,0)) THEN
  RAISE EXCEPTION 'CONTENT_REVISION_RETRY' USING ERRCODE='55P03';
 END IF;
 PERFORM set_config('gc.tenant_id',tenant::text,true);
 SELECT revision INTO head FROM gc_authority.content_security_heads
  WHERE tenant_id=tenant FOR UPDATE NOWAIT;
 IF NOT FOUND THEN RAISE EXCEPTION 'CONTENT_REVISION_INTEGRITY' USING ERRCODE='23514';END IF;
 IF head=9223372036854775807 THEN RAISE EXCEPTION 'CONTENT_REVISION_LIMIT' USING ERRCODE='54000';END IF;
 UPDATE gc_authority.content_security_heads SET revision=head+1 WHERE tenant_id=tenant;
 PERFORM set_config('gc.tenant_id',coalesce(previous_t,''),true);
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
EXCEPTION WHEN OTHERS THEN
 PERFORM set_config('gc.tenant_id',coalesce(previous_t,''),true);RAISE;
END $$;
DO $$ DECLARE name text;BEGIN
 FOREACH name IN ARRAY ARRAY['assets','domains','asset_domain_placements',
  'classification_taxonomies','classification_rules','classification_assignments'] LOOP
  EXECUTE format('CREATE TRIGGER content_revision_advance AFTER INSERT OR UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION gc_authority.content_revision_advance()',name);
 END LOOP;
END $$;

-- TRUNCATE does not fire row triggers and immutable revision pins may never
-- disappear. Tenant deletion/key reuse needs a separately reviewed purge and
-- tombstone contract; there is deliberately no reset/cascade escape here.
CREATE FUNCTION gc_authority.content_revision_no_reset() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$ BEGIN
 IF TG_RELID='public.tenants'::regclass AND TG_LEVEL='ROW' AND TG_OP='UPDATE' THEN
  IF NEW.id IS NOT DISTINCT FROM OLD.id THEN RETURN NEW;END IF;
 END IF;
 RAISE EXCEPTION 'CONTENT_REVISION_INTEGRITY' USING ERRCODE='23514';
END $$;
CREATE TRIGGER content_revision_tenant_no_reset BEFORE UPDATE OR DELETE ON public.tenants
 FOR EACH ROW EXECUTE FUNCTION gc_authority.content_revision_no_reset();
CREATE TRIGGER content_revision_head_no_truncate BEFORE TRUNCATE ON gc_authority.content_security_heads
 FOR EACH STATEMENT EXECUTE FUNCTION gc_authority.content_revision_no_reset();
DO $$ DECLARE name text;BEGIN
 FOREACH name IN ARRAY ARRAY['tenants','assets','domains','asset_domain_placements',
  'classification_taxonomies','classification_rules','classification_assignments',
  'asset_revisions','domain_revisions','asset_domain_placement_revisions',
  'classification_taxonomy_versions','classification_rule_versions','classification_evaluations',
  'classification_assignment_revisions','domain_type_versions'] LOOP
  EXECUTE format('CREATE TRIGGER content_revision_no_truncate BEFORE TRUNCATE ON public.%I FOR EACH STATEMENT EXECUTE FUNCTION gc_authority.content_revision_no_reset()',name);
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION gc_authority.content_revision_head_guard(),gc_authority.content_revision_tenant_insert(),
 gc_authority.content_revision_advance(),gc_authority.content_revision_no_reset() FROM PUBLIC,gc_app;
REVOKE ALL ON TYPE gc_authority.content_security_heads FROM PUBLIC,gc_app;
