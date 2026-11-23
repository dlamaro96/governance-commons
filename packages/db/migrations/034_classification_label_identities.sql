-- SPDX-License-Identifier: Apache-2.0
-- SQL034: private stable label identities. Existing assignments and definitions
-- are unchanged. Baselines describe installation-time knowledge, not history.
DO $$ BEGIN
 IF session_user<>current_user
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR pg_has_role('gc_app',current_user,'MEMBER')
 OR NOT EXISTS(SELECT 1 FROM gc_authn.installation_root r
   WHERE r.owner_role_oid=session_user::regrole::oid AND r.owner_role_name=session_user
   AND r.database_oid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())) THEN
  RAISE EXCEPTION 'CLASSIFICATION_LABEL_EXECUTOR_REJECTED' USING ERRCODE='42501';
 END IF;
END $$;
LOCK TABLE public.classification_taxonomies,public.classification_taxonomy_versions
 IN SHARE ROW EXCLUSIVE MODE;

CREATE TABLE gc_authority.classification_label_baselines(
 tenant_id uuid NOT NULL,taxonomy_id uuid NOT NULL,baseline_version integer NOT NULL CHECK(baseline_version>0),
 baseline_hash text NOT NULL,registered_at timestamptz NOT NULL CHECK(isfinite(registered_at)),
 PRIMARY KEY(tenant_id,taxonomy_id),
 FOREIGN KEY(tenant_id,taxonomy_id) REFERENCES public.classification_taxonomies(tenant_id,id),
 FOREIGN KEY(tenant_id,taxonomy_id,baseline_version,baseline_hash)
  REFERENCES public.classification_taxonomy_versions(tenant_id,taxonomy_id,version,definition_hash)
);
CREATE TABLE gc_authority.classification_label_identities(
 tenant_id uuid NOT NULL,id uuid NOT NULL,taxonomy_id uuid NOT NULL,
 label_key text NOT NULL CHECK(public.gc_relation_safe_id(label_key)),
 first_registered_version integer NOT NULL CHECK(first_registered_version>0),
 retired_at_version integer CHECK(retired_at_version>=first_registered_version),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,taxonomy_id,label_key),UNIQUE(tenant_id,taxonomy_id,label_key,id),
 FOREIGN KEY(tenant_id,taxonomy_id) REFERENCES gc_authority.classification_label_baselines(tenant_id,taxonomy_id),
 FOREIGN KEY(tenant_id,taxonomy_id,first_registered_version)
  REFERENCES public.classification_taxonomy_versions(tenant_id,taxonomy_id,version),
 FOREIGN KEY(tenant_id,taxonomy_id,retired_at_version)
  REFERENCES public.classification_taxonomy_versions(tenant_id,taxonomy_id,version)
);
CREATE TABLE gc_authority.classification_label_version_bindings(
 tenant_id uuid NOT NULL,taxonomy_id uuid NOT NULL,taxonomy_version integer NOT NULL,
 label_key text NOT NULL,label_id uuid NOT NULL,label_status text NOT NULL CHECK(label_status IN('active','deprecated')),
 PRIMARY KEY(tenant_id,taxonomy_id,taxonomy_version,label_key),
 FOREIGN KEY(tenant_id,taxonomy_id,taxonomy_version)
  REFERENCES public.classification_taxonomy_versions(tenant_id,taxonomy_id,version),
 FOREIGN KEY(tenant_id,taxonomy_id,label_key,label_id)
  REFERENCES gc_authority.classification_label_identities(tenant_id,taxonomy_id,label_key,id)
);
DO $$ DECLARE name text;BEGIN
 FOREACH name IN ARRAY ARRAY['classification_label_baselines','classification_label_identities','classification_label_version_bindings'] LOOP
  EXECUTE format('REVOKE ALL ON gc_authority.%I FROM PUBLIC,gc_app',name);
  EXECUTE format('REVOKE ALL ON TYPE gc_authority.%I FROM PUBLIC,gc_app',name);
  EXECUTE format('ALTER TABLE gc_authority.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE gc_authority.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY authority_tenant ON gc_authority.%I USING(tenant_id=public.gc_tenant()) WITH CHECK(tenant_id=public.gc_tenant())',name);
 END LOOP;
END $$;

-- Reserve every previously used key. A current key receives a NEW baseline
-- identity even if an older definition happened to use the same spelling.
-- Deliberately do not bind older versions or rewrite their approved assignments.
DO $$ DECLARE t uuid;previous_t text:=current_setting('gc.tenant_id',true);BEGIN
 FOR t IN SELECT id FROM public.tenants ORDER BY id LOOP
  PERFORM set_config('gc.tenant_id',t::text,true);
  IF EXISTS(SELECT 1 FROM public.classification_taxonomy_versions v
   JOIN public.classification_taxonomies h ON h.tenant_id=v.tenant_id AND h.id=v.taxonomy_id
   WHERE v.tenant_id=t AND v.version>h.current_version) THEN
   RAISE EXCEPTION 'CLASSIFICATION_LABEL_INTEGRITY' USING ERRCODE='23514';
  END IF;
  INSERT INTO gc_authority.classification_label_baselines
   SELECT h.tenant_id,h.id,h.current_version,v.definition_hash,statement_timestamp()
   FROM public.classification_taxonomies h JOIN public.classification_taxonomy_versions v
    ON (v.tenant_id,v.taxonomy_id,v.version)=(h.tenant_id,h.id,h.current_version) WHERE h.tenant_id=t;
  INSERT INTO gc_authority.classification_label_identities
   SELECT t,gen_random_uuid(),keys.taxonomy_id,keys.label_key,b.baseline_version,
    CASE WHEN EXISTS(SELECT 1 FROM jsonb_array_elements(current_pin.definition->'labels') l
      WHERE l->>'key'=keys.label_key AND l->>'status'='active') THEN NULL ELSE b.baseline_version END
   FROM (SELECT DISTINCT v.taxonomy_id,l->>'key' label_key
    FROM public.classification_taxonomy_versions v CROSS JOIN LATERAL jsonb_array_elements(v.definition->'labels') l
    WHERE v.tenant_id=t) keys
   JOIN gc_authority.classification_label_baselines b ON b.tenant_id=t AND b.taxonomy_id=keys.taxonomy_id
   JOIN public.classification_taxonomy_versions current_pin
    ON (current_pin.tenant_id,current_pin.taxonomy_id,current_pin.version)=(t,b.taxonomy_id,b.baseline_version);
  INSERT INTO gc_authority.classification_label_version_bindings
   SELECT t,b.taxonomy_id,b.baseline_version,l->>'key',i.id,l->>'status'
   FROM gc_authority.classification_label_baselines b
   JOIN public.classification_taxonomy_versions v ON (v.tenant_id,v.taxonomy_id,v.version)=(t,b.taxonomy_id,b.baseline_version)
   CROSS JOIN LATERAL jsonb_array_elements(v.definition->'labels') l
   JOIN gc_authority.classification_label_identities i ON i.tenant_id=t AND i.taxonomy_id=b.taxonomy_id AND i.label_key=l->>'key'
   WHERE b.tenant_id=t;
 END LOOP;
 PERFORM set_config('gc.tenant_id',coalesce(previous_t,''),true);
EXCEPTION WHEN OTHERS THEN
 PERFORM set_config('gc.tenant_id',coalesce(previous_t,''),true);RAISE;
END $$;

-- Trusted migration administrators can alter guards; ordinary owner queries
-- cannot directly manufacture, reset or remove identity provenance.
CREATE FUNCTION gc_authority.classification_label_write_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ BEGIN
 IF TG_LEVEL<>'ROW' OR TG_WHEN<>'BEFORE' OR pg_trigger_depth()<2 THEN
  RAISE EXCEPTION 'CLASSIFICATION_LABEL_INTEGRITY' USING ERRCODE='23514';
 END IF;
 IF TG_RELID IN('gc_authority.classification_label_baselines'::regclass,'gc_authority.classification_label_version_bindings'::regclass)
  AND TG_OP='INSERT' THEN RETURN NEW;END IF;
 IF TG_RELID='gc_authority.classification_label_identities'::regclass THEN
  IF TG_OP='INSERT' THEN RETURN NEW;END IF;
  IF TG_OP='UPDATE' AND (to_jsonb(NEW)-'retired_at_version')=(to_jsonb(OLD)-'retired_at_version')
   AND OLD.retired_at_version IS NULL AND NEW.retired_at_version IS NOT NULL THEN RETURN NEW;END IF;
 END IF;
 RAISE EXCEPTION 'CLASSIFICATION_LABEL_INTEGRITY' USING ERRCODE='23514';
END $$;
DO $$ DECLARE name text;BEGIN
 FOREACH name IN ARRAY ARRAY['classification_label_baselines','classification_label_identities','classification_label_version_bindings'] LOOP
  EXECUTE format('CREATE TRIGGER classification_label_write_guard BEFORE INSERT OR UPDATE OR DELETE ON gc_authority.%I FOR EACH ROW EXECUTE FUNCTION gc_authority.classification_label_write_guard()',name);
  EXECUTE format('CREATE TRIGGER classification_label_no_truncate BEFORE TRUNCATE ON gc_authority.%I FOR EACH STATEMENT EXECUTE FUNCTION gc_authority.classification_label_write_guard()',name);
 END LOOP;
END $$;

-- Complete version mapping, including lifecycle at that version. Later
-- retirement does not invalidate a legitimately recorded historical binding.
CREATE FUNCTION gc_authority.classification_label_version_complete(tenant uuid,taxonomy uuid,revision integer) RETURNS boolean
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM gc_authority.classification_label_baselines baseline
  JOIN public.classification_taxonomy_versions v ON (v.tenant_id,v.taxonomy_id,v.version)=(tenant,taxonomy,revision)
  WHERE (baseline.tenant_id,baseline.taxonomy_id)=(tenant,taxonomy) AND revision>=baseline.baseline_version
  AND (SELECT count(*) FROM gc_authority.classification_label_version_bindings b
   WHERE (b.tenant_id,b.taxonomy_id,b.taxonomy_version)=(tenant,taxonomy,revision))=jsonb_array_length(v.definition->'labels')
  AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(v.definition->'labels') l
   LEFT JOIN gc_authority.classification_label_version_bindings b
    ON (b.tenant_id,b.taxonomy_id,b.taxonomy_version,b.label_key)=(tenant,taxonomy,revision,l->>'key')
   LEFT JOIN gc_authority.classification_label_identities i
    ON (i.tenant_id,i.taxonomy_id,i.label_key,i.id)=(b.tenant_id,b.taxonomy_id,b.label_key,b.label_id)
   WHERE b.label_id IS NULL OR b.label_status IS DISTINCT FROM l->>'status' OR i.id IS NULL
    OR i.first_registered_version>revision
    OR (b.label_status='active' AND i.retired_at_version<=revision)
    OR (b.label_status='deprecated' AND (i.retired_at_version IS NULL OR i.retired_at_version>revision))))
$$;

CREATE FUNCTION gc_authority.classification_label_publish() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE previous_t text:=current_setting('gc.tenant_id',true);head integer;baseline integer;
 label jsonb;identity_row gc_authority.classification_label_identities%ROWTYPE;
BEGIN
 IF TG_RELID<>'public.classification_taxonomy_versions'::regclass OR TG_LEVEL<>'ROW' OR TG_WHEN<>'AFTER' OR TG_OP<>'INSERT' THEN
  RAISE EXCEPTION 'CLASSIFICATION_LABEL_INTEGRITY' USING ERRCODE='23514';
 END IF;
 IF NOT pg_try_advisory_xact_lock(hashtextextended(NEW.tenant_id::text,0)) THEN
  RAISE EXCEPTION 'CLASSIFICATION_LABEL_RETRY' USING ERRCODE='55P03';
 END IF;
 PERFORM set_config('gc.tenant_id',NEW.tenant_id::text,true);
 SELECT current_version INTO head FROM public.classification_taxonomies
  WHERE tenant_id=NEW.tenant_id AND id=NEW.taxonomy_id FOR UPDATE NOWAIT;
 IF NOT FOUND OR head<>NEW.version THEN RAISE EXCEPTION 'CLASSIFICATION_LABEL_INTEGRITY' USING ERRCODE='23514';END IF;
 SELECT baseline_version INTO baseline FROM gc_authority.classification_label_baselines
  WHERE tenant_id=NEW.tenant_id AND taxonomy_id=NEW.taxonomy_id;
 IF NOT FOUND THEN
  IF NEW.version<>1 THEN RAISE EXCEPTION 'CLASSIFICATION_LABEL_INTEGRITY' USING ERRCODE='23514';END IF;
  INSERT INTO gc_authority.classification_label_baselines
   VALUES(NEW.tenant_id,NEW.taxonomy_id,1,NEW.definition_hash,statement_timestamp());
 ELSIF NEW.version<=baseline OR NOT gc_authority.classification_label_version_complete(NEW.tenant_id,NEW.taxonomy_id,NEW.version-1) THEN
  RAISE EXCEPTION 'CLASSIFICATION_LABEL_INTEGRITY' USING ERRCODE='23514';
 END IF;
 FOR label IN SELECT item FROM jsonb_array_elements(NEW.definition->'labels') item LOOP
  SELECT * INTO identity_row FROM gc_authority.classification_label_identities
   WHERE tenant_id=NEW.tenant_id AND taxonomy_id=NEW.taxonomy_id AND label_key=label->>'key';
  IF NOT FOUND THEN
   INSERT INTO gc_authority.classification_label_identities
    VALUES(NEW.tenant_id,gen_random_uuid(),NEW.taxonomy_id,label->>'key',NEW.version,
     CASE WHEN label->>'status'='deprecated' THEN NEW.version ELSE NULL END) RETURNING * INTO identity_row;
  ELSIF label->>'status'='active' AND identity_row.retired_at_version IS NOT NULL THEN
   RAISE EXCEPTION 'classification label key retired' USING ERRCODE='23514';
  ELSIF label->>'status'='deprecated' AND identity_row.retired_at_version IS NULL THEN
   UPDATE gc_authority.classification_label_identities SET retired_at_version=NEW.version
    WHERE tenant_id=NEW.tenant_id AND id=identity_row.id;
  END IF;
  INSERT INTO gc_authority.classification_label_version_bindings
   VALUES(NEW.tenant_id,NEW.taxonomy_id,NEW.version,label->>'key',identity_row.id,label->>'status');
 END LOOP;
 UPDATE gc_authority.classification_label_identities i SET retired_at_version=NEW.version
  WHERE i.tenant_id=NEW.tenant_id AND i.taxonomy_id=NEW.taxonomy_id AND i.retired_at_version IS NULL
   AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(NEW.definition->'labels') l WHERE l->>'key'=i.label_key);
 IF NOT gc_authority.classification_label_version_complete(NEW.tenant_id,NEW.taxonomy_id,NEW.version) THEN
  RAISE EXCEPTION 'CLASSIFICATION_LABEL_INTEGRITY' USING ERRCODE='23514';
 END IF;
 PERFORM set_config('gc.tenant_id',coalesce(previous_t,''),true);
 RETURN NEW;
EXCEPTION WHEN OTHERS THEN
 PERFORM set_config('gc.tenant_id',coalesce(previous_t,''),true);RAISE;
END $$;
CREATE TRIGGER classification_label_publish AFTER INSERT ON public.classification_taxonomy_versions
 FOR EACH ROW EXECUTE FUNCTION gc_authority.classification_label_publish();

-- Validate the FINAL head, allowing multiple sequential publications in one
-- transaction. The existing deferred FK retains responsibility for a missing
-- definition; an existing definition without complete identity data is refused.
CREATE FUNCTION gc_authority.classification_label_head_complete() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE previous_t text:=current_setting('gc.tenant_id',true);head integer;BEGIN
 IF TG_RELID<>'public.classification_taxonomies'::regclass OR TG_LEVEL<>'ROW' OR TG_WHEN<>'AFTER' OR TG_OP NOT IN('INSERT','UPDATE') THEN
  RAISE EXCEPTION 'CLASSIFICATION_LABEL_INTEGRITY' USING ERRCODE='23514';
 END IF;
 PERFORM set_config('gc.tenant_id',NEW.tenant_id::text,true);
 SELECT current_version INTO head FROM public.classification_taxonomies WHERE tenant_id=NEW.tenant_id AND id=NEW.id;
 IF head IS NULL THEN RAISE EXCEPTION 'CLASSIFICATION_LABEL_INTEGRITY' USING ERRCODE='23514';END IF;
 IF EXISTS(SELECT 1 FROM public.classification_taxonomy_versions WHERE tenant_id=NEW.tenant_id AND taxonomy_id=NEW.id AND version=head)
 AND (NOT gc_authority.classification_label_version_complete(NEW.tenant_id,NEW.id,head)
  OR EXISTS(SELECT 1 FROM gc_authority.classification_label_identities i
   WHERE i.tenant_id=NEW.tenant_id AND i.taxonomy_id=NEW.id AND i.retired_at_version IS NULL
    AND NOT EXISTS(SELECT 1 FROM gc_authority.classification_label_version_bindings b
     WHERE (b.tenant_id,b.taxonomy_id,b.taxonomy_version,b.label_key,b.label_id,b.label_status)
      =(NEW.tenant_id,NEW.id,head,i.label_key,i.id,'active')))) THEN
  RAISE EXCEPTION 'CLASSIFICATION_LABEL_INTEGRITY' USING ERRCODE='23514';
 END IF;
 PERFORM set_config('gc.tenant_id',coalesce(previous_t,''),true);RETURN NEW;
EXCEPTION WHEN OTHERS THEN
 PERFORM set_config('gc.tenant_id',coalesce(previous_t,''),true);RAISE;
END $$;
CREATE CONSTRAINT TRIGGER classification_label_head_complete AFTER INSERT OR UPDATE ON public.classification_taxonomies
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gc_authority.classification_label_head_complete();
REVOKE ALL ON FUNCTION gc_authority.classification_label_write_guard(),
 gc_authority.classification_label_version_complete(uuid,uuid,integer),gc_authority.classification_label_publish(),
 gc_authority.classification_label_head_complete() FROM PUBLIC,gc_app;
