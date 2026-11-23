-- SPDX-License-Identifier: Apache-2.0
-- Explicit protected-authentication admission for the native application role.
-- Content permissions remain the existing application model; no authority activation.
DO $$ BEGIN
 IF current_user<>session_user OR current_setting('role')<>'none'
 OR NOT EXISTS(SELECT 1 FROM gc_authn.installation_root r WHERE r.owner_role_oid=session_user::regrole::oid AND r.owner_role_name=session_user AND r.database_oid=(SELECT oid FROM pg_database WHERE datname=current_database()))
 OR NOT EXISTS(SELECT 1 FROM public.schema_migrations WHERE name='036_authority_scope_alignment.sql' AND checksum='5c03e2cc221bc785d24b51a7b25a913ad38c4759726c9292c9e3ce8d16426569')
 THEN RAISE EXCEPTION 'APP_AUTHN_INSTALL_PREREQUISITE' USING ERRCODE='42501'; END IF;
END $$;

CREATE TABLE gc_authn.application_bridge_receipts(
 id uuid PRIMARY KEY CHECK(gc_authn.valid_uuid(id)),request_id uuid NOT NULL UNIQUE CHECK(gc_authn.valid_uuid(request_id)),
 sequence bigint NOT NULL UNIQUE CHECK(sequence>0),operation text NOT NULL CHECK(operation IN('application-bridge-install','application-bridge-revoke')),
 target_id uuid NOT NULL CHECK(gc_authn.valid_uuid(target_id)),manifest_hash text NOT NULL UNIQUE CHECK(gc_authn.valid_digest(manifest_hash)),
 manifest_encoding bytea NOT NULL CHECK(octet_length(manifest_encoding) BETWEEN 1 AND 65536),
 predecessor_hash text UNIQUE REFERENCES gc_authn.application_bridge_receipts(manifest_hash),
 release_reference text NOT NULL,operator_reference text NOT NULL,database_oid oid NOT NULL,owner_role_oid oid NOT NULL,
 recorded_at timestamptz NOT NULL CHECK(gc_authn.valid_time(recorded_at)),CHECK((sequence=1)=(predecessor_hash IS NULL))
);
CREATE TABLE gc_authn.application_bridge_installations(
 id uuid PRIMARY KEY CHECK(gc_authn.valid_uuid(id)),database_oid oid NOT NULL,app_role_oid oid NOT NULL,app_role_name name NOT NULL CHECK(app_role_name='gc_app'),
 api_registration_id uuid NOT NULL REFERENCES gc_authn.executor_registrations,
 bridge_generation integer NOT NULL UNIQUE CHECK(bridge_generation>0),authn_generation integer NOT NULL CHECK(authn_generation>0),
 installed_by uuid NOT NULL UNIQUE REFERENCES gc_authn.application_bridge_receipts(id) DEFERRABLE INITIALLY DEFERRED,
 installed_at timestamptz NOT NULL CHECK(gc_authn.valid_time(installed_at)),expires_at timestamptz NOT NULL CHECK(gc_authn.valid_time(expires_at)),
 revoked_at timestamptz CHECK(revoked_at IS NULL OR gc_authn.valid_time(revoked_at)),
 revoked_by uuid UNIQUE REFERENCES gc_authn.application_bridge_receipts(id) DEFERRABLE INITIALLY DEFERRED,
 CHECK(expires_at>installed_at),CHECK((revoked_at IS NULL)=(revoked_by IS NULL)),CHECK(revoked_at IS NULL OR revoked_at>=installed_at)
);
CREATE UNIQUE INDEX application_bridge_one_live ON gc_authn.application_bridge_installations((true)) WHERE revoked_at IS NULL;

CREATE FUNCTION gc_authn.application_role_safe(role_oid oid) RETURNS boolean LANGUAGE sql VOLATILE SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM pg_roles r WHERE r.oid=role_oid AND r.rolname='gc_app' AND r.rolcanlogin
 AND NOT(r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolinherit OR r.rolreplication OR r.rolbypassrls)
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid OR m.roleid=r.oid)
 AND NOT has_database_privilege(r.oid,current_database(),'CREATE,TEMP')
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE') OR (n.nspname='gc_authn' AND has_schema_privilege(r.oid,n.oid,'USAGE')))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relowner=r.oid OR (n.nspname='gc_authn' AND CASE WHEN c.relkind IN('r','p','v','m','f') THEN has_table_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,REFERENCES') WHEN c.relkind='S' THEN has_sequence_privilege(r.oid,c.oid,'SELECT,UPDATE,USAGE') ELSE false END))
 AND NOT EXISTS(SELECT 1 FROM pg_type t WHERE t.typowner=r.oid)
 AND NOT EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE p.proowner=r.oid OR ((n.nspname='gc_authn' OR (n.nspname='public' AND p.proname LIKE 'gc_authn_%')) AND has_function_privilege(r.oid,p.oid,'EXECUTE'))))
$$;

CREATE FUNCTION gc_authn.application_bridge_encoding(op text,request_id uuid,release_ref text,operator_ref text,expected_db_oid oid,expected_owner_oid oid,predecessor_hash text) RETURNS text LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,gc_authn AS $$
 SELECT 'gc-app-authn-install/v1;'||gc_authn.scalar(op,'S')||gc_authn.field('request_id',request_id::text,'U')||gc_authn.field('release_ref',release_ref,'S')||gc_authn.field('operator_ref',operator_ref,'S')||gc_authn.field('expected_db_oid',expected_db_oid::text,'I')||gc_authn.field('expected_owner_oid',expected_owner_oid::text,'I')||gc_authn.field('predecessor_hash',predecessor_hash,'S')
$$;
CREATE FUNCTION gc_authn.application_bridge_existing(request_id uuid,encoding text) RETURNS gc_authn.installation_result LANGUAGE plpgsql SET search_path=pg_catalog,gc_authn,pg_temp AS $$
DECLARE r gc_authn.application_bridge_receipts;
BEGIN
 PERFORM gc_authn.require_input(octet_length(encoding) BETWEEN 1 AND 65536);
 SELECT * INTO r FROM gc_authn.application_bridge_receipts x WHERE x.request_id=application_bridge_existing.request_id;
 IF FOUND THEN
  IF r.manifest_encoding<>convert_to(encoding,'UTF8') THEN RAISE EXCEPTION 'APP_AUTHN_INSTALL_CONFLICT' USING ERRCODE='23505'; END IF;
  RETURN(r.id,r.manifest_hash,r.target_id,r.recorded_at)::gc_authn.installation_result;
 END IF;RETURN NULL;
END $$;
CREATE FUNCTION gc_authn.application_bridge_append(op text,target uuid,request_id uuid,release_ref text,operator_ref text,predecessor_hash text,encoding text) RETURNS gc_authn.installation_result LANGUAGE plpgsql SET search_path=pg_catalog,gc_authn,pg_temp AS $$
DECLARE previous gc_authn.application_bridge_receipts;r gc_authn.application_bridge_receipts;
BEGIN
 SELECT * INTO previous FROM gc_authn.application_bridge_receipts ORDER BY sequence DESC LIMIT 1;
 IF previous.manifest_hash IS DISTINCT FROM predecessor_hash THEN RAISE EXCEPTION 'APP_AUTHN_INSTALL_CONFLICT' USING ERRCODE='23505'; END IF;
 INSERT INTO gc_authn.application_bridge_receipts
 SELECT gen_random_uuid(),request_id,coalesce(previous.sequence,0)+1,op,target,encode(sha256(convert_to(encoding,'UTF8')),'hex'),convert_to(encoding,'UTF8'),predecessor_hash,release_ref,operator_ref,root_row.database_oid,root_row.owner_role_oid,date_trunc('milliseconds',clock_timestamp()) FROM gc_authn.installation_root root_row WHERE singleton RETURNING * INTO r;
 RETURN(r.id,r.manifest_hash,r.target_id,r.recorded_at)::gc_authn.installation_result;
END $$;

CREATE FUNCTION gc_authn.install_application_bridge_v1(request_id uuid,release_ref text,operator_ref text,expected_db_oid oid,expected_owner_oid oid,predecessor_hash text,bridge_id uuid,expected_app_oid oid,api_registration_id uuid,bridge_generation integer,authn_generation integer,expires_at timestamptz) RETURNS gc_authn.installation_result LANGUAGE plpgsql SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE encoding text;receipt gc_authn.installation_result;api gc_authn.executor_registrations;previous integer;
BEGIN
 PERFORM gc_authn.install_check(request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,NULL);
 IF current_setting('role')<>'none' THEN RAISE EXCEPTION 'APP_AUTHN_EXECUTOR_REJECTED' USING ERRCODE='42501';END IF;
 PERFORM gc_authn.require_input(gc_authn.valid_uuid(bridge_id) AND expected_app_oid IS NOT NULL AND gc_authn.valid_uuid(api_registration_id) AND bridge_generation>0 AND authn_generation>0 AND gc_authn.valid_time(expires_at) AND (predecessor_hash IS NULL OR gc_authn.valid_digest(predecessor_hash)));
 encoding:=gc_authn.application_bridge_encoding('application-bridge-install',request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,predecessor_hash)||gc_authn.field('bridge_id',bridge_id::text,'U')||gc_authn.field('expected_app_oid',expected_app_oid::text,'I')||gc_authn.field('api_registration_id',api_registration_id::text,'U')||gc_authn.field('bridge_generation',bridge_generation::text,'I')||gc_authn.field('authn_generation',authn_generation::text,'I')||gc_authn.field('expires_at',expires_at::text,'T');
 receipt:=gc_authn.application_bridge_existing(request_id,encoding);IF receipt.installation_id IS NOT NULL THEN RETURN receipt;END IF;
 IF NOT gc_authn.application_role_safe(expected_app_oid) THEN RAISE EXCEPTION 'APP_AUTHN_EXECUTOR_REJECTED' USING ERRCODE='42501';END IF;
 api:=gc_authn.current_registration(api_registration_id,'api');
 PERFORM gc_authn.require_input(api.generation=authn_generation AND expires_at>clock_timestamp() AND expires_at<=api.expires_at);
 SELECT max(x.bridge_generation) INTO previous FROM gc_authn.application_bridge_installations x;
 IF EXISTS(SELECT 1 FROM gc_authn.application_bridge_installations WHERE revoked_at IS NULL) OR bridge_generation<>coalesce(previous,0)+1 THEN RAISE EXCEPTION 'APP_AUTHN_INSTALL_CONFLICT' USING ERRCODE='23505';END IF;
 receipt:=gc_authn.application_bridge_append('application-bridge-install',bridge_id,request_id,release_ref,operator_ref,predecessor_hash,encoding);
 INSERT INTO gc_authn.application_bridge_installations VALUES(bridge_id,expected_db_oid,expected_app_oid,'gc_app',api_registration_id,bridge_generation,authn_generation,receipt.installation_id,receipt.recorded_at,expires_at,NULL,NULL);
 RETURN receipt;
END $$;
CREATE FUNCTION gc_authn.revoke_application_bridge_v1(request_id uuid,release_ref text,operator_ref text,expected_db_oid oid,expected_owner_oid oid,predecessor_hash text,bridge_id uuid,expected_manifest_hash text) RETURNS gc_authn.installation_result LANGUAGE plpgsql SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE encoding text;receipt gc_authn.installation_result;b gc_authn.application_bridge_installations;original gc_authn.application_bridge_receipts;
BEGIN
 PERFORM gc_authn.install_check(request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,NULL);
 IF current_setting('role')<>'none' THEN RAISE EXCEPTION 'APP_AUTHN_EXECUTOR_REJECTED' USING ERRCODE='42501';END IF;
 PERFORM gc_authn.require_input(gc_authn.valid_uuid(bridge_id) AND gc_authn.valid_digest(expected_manifest_hash) AND (predecessor_hash IS NULL OR gc_authn.valid_digest(predecessor_hash)));
 encoding:=gc_authn.application_bridge_encoding('application-bridge-revoke',request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,predecessor_hash)||gc_authn.field('bridge_id',bridge_id::text,'U')||gc_authn.field('expected_manifest_hash',expected_manifest_hash,'S');
 receipt:=gc_authn.application_bridge_existing(request_id,encoding);IF receipt.installation_id IS NOT NULL THEN RETURN receipt;END IF;
 SELECT * INTO b FROM gc_authn.application_bridge_installations WHERE id=bridge_id;SELECT * INTO original FROM gc_authn.application_bridge_receipts WHERE id=b.installed_by;
 IF b.id IS NULL OR b.revoked_at IS NOT NULL OR original.manifest_hash IS DISTINCT FROM expected_manifest_hash THEN RAISE EXCEPTION 'APP_AUTHN_INSTALL_CONFLICT' USING ERRCODE='23505';END IF;
 receipt:=gc_authn.application_bridge_append('application-bridge-revoke',bridge_id,request_id,release_ref,operator_ref,predecessor_hash,encoding);
 UPDATE gc_authn.application_bridge_installations SET revoked_at=receipt.recorded_at,revoked_by=receipt.installation_id WHERE id=bridge_id;
 RETURN receipt;
END $$;

CREATE FUNCTION gc_authn.application_bridge_update() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
 IF OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL OR NEW.revoked_by IS NULL OR NEW.revoked_at<OLD.installed_at OR (to_jsonb(NEW)-ARRAY['revoked_at','revoked_by']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['revoked_at','revoked_by']) THEN RAISE EXCEPTION 'APP_AUTHN_IMMUTABLE' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE TRIGGER application_bridge_receipt_immutable BEFORE UPDATE OR DELETE ON gc_authn.application_bridge_receipts FOR EACH ROW EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER application_bridge_receipt_no_truncate BEFORE TRUNCATE ON gc_authn.application_bridge_receipts EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER application_bridge_installation_update BEFORE UPDATE ON gc_authn.application_bridge_installations FOR EACH ROW EXECUTE FUNCTION gc_authn.application_bridge_update();
CREATE TRIGGER application_bridge_installation_no_delete BEFORE DELETE ON gc_authn.application_bridge_installations FOR EACH ROW EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER application_bridge_installation_no_truncate BEFORE TRUNCATE ON gc_authn.application_bridge_installations EXECUTE FUNCTION gc_authn.immutable();

CREATE FUNCTION gc_authn.application_bridge_complete() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE r gc_authn.application_bridge_receipts;b gc_authn.application_bridge_installations;p gc_authn.application_bridge_receipts;root gc_authn.installation_root;encoding text;
BEGIN
 IF TG_TABLE_NAME='application_bridge_receipts' THEN r:=NEW;ELSE SELECT * INTO r FROM gc_authn.application_bridge_receipts WHERE id=CASE WHEN TG_OP='INSERT' THEN NEW.installed_by ELSE NEW.revoked_by END;END IF;
 SELECT * INTO root FROM gc_authn.installation_root WHERE singleton;
 SELECT * INTO b FROM gc_authn.application_bridge_installations WHERE id=r.target_id;
 PERFORM gc_authn.require_input(gc_authn.valid_text(r.release_reference,256) AND r.release_reference ~ '^[ -~]+$' AND gc_authn.valid_text(r.operator_reference,256) AND r.operator_reference ~ '^[ -~]+$');
 IF current_user<>session_user OR current_setting('role')<>'none' OR (r.database_oid,r.owner_role_oid) IS DISTINCT FROM (root.database_oid,root.owner_role_oid) OR root.owner_role_oid<>session_user::regrole::oid OR root.owner_role_name<>session_user THEN RAISE EXCEPTION 'APP_AUTHN_INSTALL_PREREQUISITE' USING ERRCODE='42501';END IF;
 SELECT * INTO p FROM gc_authn.application_bridge_receipts WHERE sequence=r.sequence-1;
 IF b.id IS NULL OR r.manifest_hash<>encode(sha256(r.manifest_encoding),'hex') OR p.manifest_hash IS DISTINCT FROM r.predecessor_hash OR (r.sequence>1 AND p.id IS NULL) THEN RAISE EXCEPTION 'APP_AUTHN_INSTALL_INTEGRITY' USING ERRCODE='23514';END IF;
 encoding:=gc_authn.application_bridge_encoding(r.operation,r.request_id,r.release_reference,r.operator_reference,r.database_oid,r.owner_role_oid,r.predecessor_hash);
 IF r.operation='application-bridge-install' THEN
  IF b.installed_by<>r.id OR b.installed_at<>r.recorded_at OR b.database_oid<>r.database_oid OR NOT EXISTS(SELECT 1 FROM gc_authn.executor_registrations a WHERE a.id=b.api_registration_id AND a.kind='api' AND a.generation=b.authn_generation AND b.expires_at<=a.expires_at) OR b.bridge_generation<>(SELECT count(*) FROM gc_authn.application_bridge_receipts WHERE operation='application-bridge-install' AND sequence<=r.sequence) THEN RAISE EXCEPTION 'APP_AUTHN_INSTALL_INTEGRITY' USING ERRCODE='23514';END IF;
  encoding:=encoding||gc_authn.field('bridge_id',b.id::text,'U')||gc_authn.field('expected_app_oid',b.app_role_oid::text,'I')||gc_authn.field('api_registration_id',b.api_registration_id::text,'U')||gc_authn.field('bridge_generation',b.bridge_generation::text,'I')||gc_authn.field('authn_generation',b.authn_generation::text,'I')||gc_authn.field('expires_at',b.expires_at::text,'T');
 ELSE
  IF b.revoked_by IS DISTINCT FROM r.id OR b.revoked_at IS DISTINCT FROM r.recorded_at THEN RAISE EXCEPTION 'APP_AUTHN_INSTALL_INTEGRITY' USING ERRCODE='23514';END IF;
  SELECT * INTO p FROM gc_authn.application_bridge_receipts WHERE id=b.installed_by;
  encoding:=encoding||gc_authn.field('bridge_id',b.id::text,'U')||gc_authn.field('expected_manifest_hash',p.manifest_hash,'S');
 END IF;
 IF r.manifest_encoding<>convert_to(encoding,'UTF8') THEN RAISE EXCEPTION 'APP_AUTHN_INSTALL_INTEGRITY' USING ERRCODE='23514';END IF;RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER application_bridge_receipt_complete AFTER INSERT ON gc_authn.application_bridge_receipts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gc_authn.application_bridge_complete();
CREATE CONSTRAINT TRIGGER application_bridge_installation_complete AFTER INSERT OR UPDATE ON gc_authn.application_bridge_installations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gc_authn.application_bridge_complete();

CREATE FUNCTION public.gc_app_protected_session_v1(session_hash text,csrf_hash text DEFAULT NULL) RETURNS public.gc_authn_authenticated_session LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE b gc_authn.application_bridge_installations;s gc_authn.sessions;p gc_authn.session_provenance;login gc_authn.executor_registrations;api gc_authn.executor_registrations;i gc_authn.issuer_registrations;binding gc_authn.identity_bindings;f gc_authn.tenant_fences;old_a text:=current_setting('gc.actor_id',true);old_t text:=current_setting('gc.tenant_id',true);
BEGIN
 IF current_setting('role')<>'none' OR session_user<>'gc_app' OR NOT gc_authn.application_role_safe(session_user::regrole::oid) THEN RAISE EXCEPTION 'APP_AUTHN_EXECUTOR_REJECTED' USING ERRCODE='42501';END IF;
 SELECT * INTO b FROM gc_authn.application_bridge_installations x WHERE x.revoked_at IS NULL AND x.app_role_oid=session_user::regrole::oid AND x.app_role_name=session_user AND x.database_oid=(SELECT oid FROM pg_database WHERE datname=current_database());
 IF b.id IS NULL OR b.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'APP_AUTHN_EXECUTOR_REJECTED' USING ERRCODE='42501';END IF;
 PERFORM gc_authn.require_input(gc_authn.valid_digest(session_hash) AND (csrf_hash IS NULL OR gc_authn.valid_digest(csrf_hash)));
 PERFORM gc_authn.require_auth(current_setting('transaction_isolation')='repeatable read' AND current_setting('transaction_read_only')='on');
 IF clock_timestamp()>=transaction_timestamp()+interval '30 seconds' THEN RAISE EXCEPTION 'APP_AUTHN_DEADLINE' USING ERRCODE='57014';END IF;
 api:=gc_authn.current_registration(b.api_registration_id,'api');
 SELECT * INTO s FROM gc_authn.sessions x WHERE x.session_hash=gc_app_protected_session_v1.session_hash;
 PERFORM gc_authn.require_auth(s.id IS NOT NULL AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND s.generation=api.generation AND s.generation=b.authn_generation);
 PERFORM gc_authn.validate_session(s.id);
 SELECT * INTO p FROM gc_authn.session_provenance WHERE session_id=s.id;
 login:=gc_authn.current_registration(p.issuing_executor_registration_id,'login');i:=gc_authn.live_issuer(login.id);
 SELECT * INTO binding FROM gc_authn.identity_bindings WHERE id=p.identity_binding_id;
 PERFORM gc_authn.require_auth((login.generation,i.id,binding.issuer_registration_id,binding.identity_id) IS NOT DISTINCT FROM (s.generation,p.issuer_registration_id,i.id,s.identity_id) AND binding.revoked_at IS NULL AND binding.expires_at>clock_timestamp() AND (csrf_hash IS NULL OR s.csrf_hash=csrf_hash));
 PERFORM set_config('gc.actor_id',s.identity_id::text,true);PERFORM set_config('gc.tenant_id',s.selected_tenant_id::text,true);
 PERFORM gc_authn.require_auth(EXISTS(SELECT 1 FROM public.identities x WHERE x.id=s.identity_id AND x.issuer=binding.canonical_issuer AND x.subject=binding.subject AND x.active) AND EXISTS(SELECT 1 FROM public.memberships m WHERE m.tenant_id=s.selected_tenant_id AND m.identity_id=s.identity_id AND m.active));
 SELECT * INTO f FROM gc_authn.tenant_fences WHERE tenant_id=s.selected_tenant_id;
 PERFORM gc_authn.require_auth(f.tenant_id IS NOT NULL AND f.generation=s.generation AND f.mode='inactive');
 IF clock_timestamp()>=transaction_timestamp()+interval '30 seconds' THEN RAISE EXCEPTION 'APP_AUTHN_DEADLINE' USING ERRCODE='57014';END IF;
 IF b.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'APP_AUTHN_EXECUTOR_REJECTED' USING ERRCODE='42501';END IF;
 PERFORM gc_authn.require_auth(least(s.expires_at,login.expires_at,api.expires_at,i.expires_at,binding.expires_at)>clock_timestamp());
 PERFORM set_config('gc.actor_id',coalesce(old_a,''),true);PERFORM set_config('gc.tenant_id',coalesce(old_t,''),true);
 RETURN(1,s.id,s.version,s.identity_id,s.selected_tenant_id,i.id,binding.id,s.authenticated_at,least(s.expires_at,login.expires_at,api.expires_at,i.expires_at,binding.expires_at,b.expires_at),s.generation,f.epoch,'inactive',false)::public.gc_authn_authenticated_session;
EXCEPTION WHEN SQLSTATE '23514' THEN PERFORM set_config('gc.actor_id',coalesce(old_a,''),true);PERFORM set_config('gc.tenant_id',coalesce(old_t,''),true);RAISE EXCEPTION 'APP_AUTHN_SESSION_REJECTED' USING ERRCODE='28000';
WHEN OTHERS THEN PERFORM set_config('gc.actor_id',coalesce(old_a,''),true);PERFORM set_config('gc.tenant_id',coalesce(old_t,''),true);RAISE;
END $$;

REVOKE ALL ON gc_authn.application_bridge_installations,gc_authn.application_bridge_receipts FROM PUBLIC,gc_app;
GRANT SELECT ON gc_authn.application_bridge_installations TO gc_authn_definer;
REVOKE ALL ON FUNCTION gc_authn.application_role_safe(oid),gc_authn.application_bridge_encoding(text,uuid,text,text,oid,oid,text),gc_authn.application_bridge_existing(uuid,text),gc_authn.application_bridge_append(text,uuid,uuid,text,text,text,text),gc_authn.install_application_bridge_v1(uuid,text,text,oid,oid,text,uuid,oid,uuid,integer,integer,timestamptz),gc_authn.revoke_application_bridge_v1(uuid,text,text,oid,oid,text,uuid,text),gc_authn.application_bridge_update(),gc_authn.application_bridge_complete() FROM PUBLIC,gc_app;
GRANT EXECUTE ON FUNCTION gc_authn.application_role_safe(oid) TO gc_authn_definer;
REVOKE ALL ON FUNCTION public.gc_app_protected_session_v1(text,text) FROM PUBLIC;
-- This grant alone is inert: only a separately installed live binding admits a caller.
GRANT EXECUTE ON FUNCTION public.gc_app_protected_session_v1(text,text) TO gc_app;
ALTER FUNCTION public.gc_app_protected_session_v1(text,text) OWNER TO gc_authn_definer;
GRANT USAGE ON TYPE public.gc_authn_authenticated_session TO gc_app;
