-- SPDX-License-Identifier: Apache-2.0
-- Inactive, detached authentication infrastructure. SQL001-011 stay immutable.
-- Contract SHA256: 7795a8114e3ea9969757a92d879788ff15e933c3b9438c469c97ff1a3cb23ee6
DO $$
DECLARE owner_oid oid; definer_oid oid;
BEGIN
 SELECT oid INTO owner_oid FROM pg_catalog.pg_roles WHERE rolname=session_user AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolinherit AND NOT rolbypassrls AND NOT rolreplication;
 SELECT oid INTO definer_oid FROM pg_catalog.pg_roles WHERE rolname='gc_authn_definer' AND NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolinherit AND NOT rolbypassrls AND NOT rolreplication;
 IF owner_oid IS NULL OR current_user<>session_user OR definer_oid IS NULL
 OR current_setting('max_prepared_transactions')::integer<>0
 OR NOT EXISTS(SELECT 1 FROM pg_database WHERE datname=current_database() AND datdba=owner_oid)
 OR NOT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='public' AND (nspowner=owner_oid OR nspowner='pg_database_owner'::regrole::oid))
 OR EXISTS(SELECT 1 FROM pg_namespace WHERE nspname='gc_authn')
 OR NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE roleid=definer_oid AND member=owner_oid AND set_option AND NOT inherit_option AND NOT admin_option)
 OR EXISTS(SELECT 1 FROM pg_auth_members WHERE (roleid=definer_oid OR member=definer_oid) AND NOT(roleid=definer_oid AND member=owner_oid AND set_option AND NOT inherit_option AND NOT admin_option))
 OR pg_has_role('gc_app',owner_oid,'MEMBER')
 OR EXISTS(SELECT 1 FROM pg_database d CROSS JOIN LATERAL aclexplode(coalesce(d.datacl,acldefault('d',d.datdba))) a WHERE d.datname=current_database() AND a.grantee=0 AND a.privilege_type IN('TEMPORARY','CREATE'))
 THEN RAISE EXCEPTION 'AUTHN_INSTALL_PREREQUISITE' USING ERRCODE='42501'; END IF;
END $$;
DO $$
DECLARE item record; f oid; actual_public boolean;
BEGIN
 PERFORM set_config('search_path','pg_catalog,public',true);
 IF (SELECT count(*) FROM public.schema_migrations)<>11 THEN RAISE EXCEPTION 'AUTHN_INSTALL_PREREQUISITE' USING ERRCODE='42501'; END IF;
 FOR item IN SELECT * FROM (VALUES ('001_foundation.sql','2cad0f9026b512c9c896d0a5a5162d58d7d08c8ad80bcda21180041f460fefaa'),
('002_audit_envelopes.sql','a2fa9227ea0c9d3e883d6b67e802e32840d68f63f45b16b603b5e23f4fb3d728'),
('003_governance_models.sql','fea03697b1871df21dc108b54d1b39ca0075f60432f8e3c6185ab796c67131aa'),
('004_model_migrations.sql','b0cd71b9d98e5073e96f42d6bb010df3cda8692bb2cc4fbd2887a97390f0525f'),
('005_model_migration_integrity.sql','799d4d20072126a9c3a1dfe9544668d022c3a4a478bc7010b4c84c5c0285e763'),
('006_inherited_asset_types.sql','5160923875148544b725d57447a0787e8b4167cd6239421bd2beb0d836571df8'),
('007_asset_type_migrations.sql','0abe6645087a2cffcd65d95e44cf7825640b7d7b4d91a3a589d3312fcb7e3df7'),
('008_constrained_relations.sql','b8d858ffade0b577848014cedef54218a4a7e47e7a9243c03c582ad829cf96f2'),
('009_relation_participation.sql','eb1b13ada40544c269b46ff5ca5c0ff4f83e3b18f0e65c3d075f0ca8352b8bfe'),
('010_relation_scope_discovery.sql','9437f8d179dd6f26ee757373dd8eb5eb40771681a0417a426e6e00575da8d91a'),
('011_business_domains.sql','ece1c39647d7ab3c2d0e7fcf5d21f908951884ee48e101b836292444909b6c78')) v(filename,digest) LOOP
  IF NOT EXISTS(SELECT 1 FROM public.schema_migrations WHERE name=item.filename AND checksum=item.digest) THEN RAISE EXCEPTION 'AUTHN_INSTALL_PREREQUISITE' USING ERRCODE='42501'; END IF;
 END LOOP;
 IF (SELECT count(*) FROM pg_proc f JOIN pg_namespace n ON n.oid=f.pronamespace WHERE n.nspname='public' AND f.proname LIKE 'gc\_%' ESCAPE '\')<>155 THEN RAISE EXCEPTION 'AUTHN_INSTALL_PREREQUISITE' USING ERRCODE='42501'; END IF;
 FOR item IN SELECT * FROM (VALUES ('public.gc_actor()',true,true),
('public.gc_asset_type_constraints()',true,true),
('public.gc_domain_adapt(domain_type_versions)',false,false),
('public.gc_domain_authorize(text[])',false,false),
('public.gc_domain_begin(uuid,text,jsonb,text,boolean)',false,false),
('public.gc_domain_bind(text)',false,false),
('public.gc_domain_charge_legacy_revision(uuid,jsonb)',false,false),
('public.gc_domain_charge(uuid,jsonb)',false,false),
('public.gc_domain_charge_value(uuid,jsonb,boolean)',false,false),
('public.gc_domain_claim_changed(uuid,jsonb,jsonb,text,uuid)',false,false),
('public.gc_domain_current(boolean)',false,false),
('public.gc_domain_deadline()',false,false),
('public.gc_domain_definition_valid(jsonb)',false,false),
('public.gc_domain_epoch_advance(uuid)',false,false),
('public.gc_domain_finalize()',false,false),
('public.gc_domain_idempotency_guard()',false,false),
('public.gc_domain_install_dependencies()',false,false),
('public.gc_domain_journal_claim(uuid,text,text,uuid,integer,jsonb)',false,false),
('public.gc_domain_journal_guard()',false,false),
('public.gc_domain_legacy_guard()',false,false),
('public.gc_domain_owner_active(uuid)',false,false),
('public.gc_domain_placement_view(asset_domain_placements)',false,false),
('public.gc_domain_policy(uuid,uuid,integer)',false,false),
('public.gc_domain_replay_authorize(text,text)',false,true),
('public.gc_domain_resolve(uuid,uuid,jsonb)',false,false),
('public.gc_domain_revision_guard()',false,false),
('public.gc_domain_row_guard()',false,false),
('public.gc_domain_scope_epoch()',false,true),
('public.gc_domain_seal(uuid,boolean)',false,false),
('public.gc_domain_statement_guard()',false,false),
('public.gc_domain_text(jsonb,integer,boolean)',false,false),
('public.gc_domain_tuple(jsonb)',false,false),
('public.gc_domain_tuple_valid(jsonb,jsonb,boolean)',false,false),
('public.gc_domain_type_migration_begin(uuid,text,jsonb,text)',false,true),
('public.gc_domain_type_migration_seal(uuid)',false,true),
('public.gc_domain_type_view(domain_type_versions,integer)',false,false),
('public.gc_domain_uuid(jsonb,boolean)',false,false),
('public.gc_domain_verify(uuid)',false,false),
('public.gc_domain_version_guard()',false,false),
('public.gc_domain_view(domains)',false,false),
('public.gc_domain_write_begin(uuid,text,jsonb,text)',false,true),
('public.gc_domain_write_seal(uuid)',false,true),
('public.gc_guard_model_migration_asset()',false,true),
('public.gc_guard_type_migration_asset()',false,true),
('public.gc_immutable_audit()',true,true),
('public.gc_lock_type_migration_principals(uuid[])',false,true),
('public.gc_model_migration_shape(jsonb,jsonb,text,integer,integer,integer)',false,true),
('public.gc_normalize_model_migration_assets()',false,true),
('public.gc_normalize_type_migration_assets()',false,true),
('public.gc_relation_acl_project()',false,false),
('public.gc_relation_acl_projection_guard()',true,true),
('public.gc_relation_asset_tuple(assets)',true,true),
('public.gc_relation_attribute_transform(jsonb,jsonb,jsonb,jsonb,jsonb,boolean)',true,true),
('public.gc_relation_authorize(text[])',true,true),
('public.gc_relation_binding_snapshot(relation_participations)',true,true),
('public.gc_relation_check_type(uuid,uuid)',false,false),
('public.gc_relation_decimal(text)',true,true),
('public.gc_relation_definition_valid(jsonb)',true,true),
('public.gc_relation_endpoint_eligible(uuid,uuid,jsonb,text)',true,true),
('public.gc_relation_endpoint_projection_guard()',true,true),
('public.gc_relation_endpoint_rules(jsonb)',true,true),
('public.gc_relation_endpoint_snapshot(uuid,uuid,integer)',true,true),
('public.gc_relation_enqueue()',false,false),
('public.gc_relation_graph_asset_delete_guard()',false,false),
('public.gc_relation_graph_asset_evidence(text,integer,jsonb)',true,true),
('public.gc_relation_graph_asset_policy(text,integer,jsonb)',true,true),
('public.gc_relation_graph_asset_preparation(uuid)',false,false),
('public.gc_relation_graph_asset_revision_guard()',false,false),
('public.gc_relation_graph_asset_row(assets)',true,true),
('public.gc_relation_graph_asset_write_guard()',false,false),
('public.gc_relation_graph_begin(uuid,text,text,jsonb,text)',false,true),
('public.gc_relation_graph_budget(timestamp with time zone)',false,false),
('public.gc_relation_graph_candidate_assets(uuid)',false,false),
('public.gc_relation_graph_candidate_types(uuid)',false,false),
('public.gc_relation_graph_capture_scope(uuid)',false,false),
('public.gc_relation_graph_charge(uuid,jsonb)',false,false),
('public.gc_relation_graph_current()',false,false),
('public.gc_relation_graph_endpoint(uuid,integer,jsonb,jsonb)',true,true),
('public.gc_relation_graph_finalize()',false,false),
('public.gc_relation_graph_install_bindings(uuid,relation_graph_operation_type_claims)',false,false),
('public.gc_relation_graph_install_edges(uuid,relation_graph_operation_type_claims)',false,false),
('public.gc_relation_graph_journal_guard()',false,false),
('public.gc_relation_graph_journal(text,text,integer,uuid,text)',true,true),
('public.gc_relation_graph_model_write_guard()',false,false),
('public.gc_relation_graph_nested_receipt_guard()',false,false),
('public.gc_relation_graph_normalize_change_set(jsonb)',false,false),
('public.gc_relation_graph_normalize_definition(jsonb)',false,false),
('public.gc_relation_graph_normalize_transform(jsonb,text)',false,false),
('public.gc_relation_graph_normalize_values(jsonb)',false,false),
('public.gc_relation_graph_plan_shape(jsonb,text)',true,true),
('public.gc_relation_graph_prepare(text,jsonb,text)',false,true),
('public.gc_relation_graph_project_asset(assets,jsonb)',true,true),
('public.gc_relation_graph_project_endpoint(assets,jsonb)',true,true),
('public.gc_relation_graph_receipt_guard()',false,false),
('public.gc_relation_graph_repair_authorize(uuid)',false,false),
('public.gc_relation_graph_resolve_asset(jsonb,boolean)',true,true),
('public.gc_relation_graph_scope_eligible(uuid,uuid,jsonb,text,timestamp with time zone)',false,false),
('public.gc_relation_graph_scope_project(uuid,integer,text,integer,text,jsonb,timestamp with time zone)',false,false),
('public.gc_relation_graph_scope_tick(timestamp with time zone,uuid)',false,false),
('public.gc_relation_graph_seal(uuid)',false,true),
('public.gc_relation_graph_snapshot(uuid,boolean)',false,false),
('public.gc_relation_graph_sort(jsonb,text[],boolean,text[])',false,false),
('public.gc_relation_graph_source_history_valid(relations)',false,false),
('public.gc_relation_graph_transform_intent(jsonb,text,jsonb,jsonb,jsonb,uuid)',true,true),
('public.gc_relation_graph_validate_intents(uuid)',false,false),
('public.gc_relation_graph_values_valid(jsonb,jsonb,boolean)',true,true),
('public.gc_relation_json_bounded(jsonb,integer,integer,integer)',true,true),
('public.gc_relation_keys(jsonb,text[])',true,true),
('public.gc_relation_lifecycle_valid(jsonb)',true,true),
('public.gc_relation_model(jsonb)',true,true),
('public.gc_relation_mutation_complete()',true,true),
('public.gc_relation_mutation_fence()',false,false),
('public.gc_relation_participation_complete()',false,false),
('public.gc_relation_participation_guard()',false,false),
('public.gc_relation_participation_revision_guard()',false,false),
('public.gc_relation_path(jsonb)',true,true),
('public.gc_relation_policy_changes(jsonb,jsonb)',true,true),
('public.gc_relation_positive_integer(jsonb)',true,true),
('public.gc_relation_preparation_complete()',false,false),
('public.gc_relation_preparation_view(relation_type_preparations)',true,true),
('public.gc_relation_projected_eligible(jsonb,jsonb,text)',true,true),
('public.gc_relation_publication_complete()',false,false),
('public.gc_relation_publication_principals(uuid)',false,true),
('public.gc_relation_reserved_idempotency_guard()',false,false),
('public.gc_relation_revision_guard()',false,false),
('public.gc_relation_row_guard()',false,false),
('public.gc_relation_safe_id(text)',true,true),
('public.gc_relation_schema_at(jsonb,text[])',true,true),
('public.gc_relation_schema_changes(jsonb,jsonb,text,integer)',true,true),
('public.gc_relation_schema_compatible(jsonb,jsonb)',true,true),
('public.gc_relation_schema_valid(jsonb,integer,boolean)',true,true),
('public.gc_relation_snapshot_base(relations)',true,true),
('public.gc_relation_sorted_pins(jsonb)',true,true),
('public.gc_relation_state_list(jsonb,boolean)',true,true),
('public.gc_relation_structural_policy(jsonb)',true,true),
('public.gc_relation_type_head_guard()',false,false),
('public.gc_relation_type_project()',false,false),
('public.gc_relation_type_version_guard()',false,false),
('public.gc_relation_utc(timestamp with time zone)',true,true),
('public.gc_relation_utf16_length(text)',true,true),
('public.gc_relation_uuid_list(jsonb,integer)',true,true),
('public.gc_relation_validate_final()',false,false),
('public.gc_relation_values(relations)',true,true),
('public.gc_relation_value_valid(jsonb,jsonb,integer)',true,true),
('public.gc_tenant()',true,true),
('public.gc_type_dependencies_insert()',true,true),
('public.gc_type_dependency_guard()',true,true),
('public.gc_typed_model_version_required()',true,true),
('public.gc_type_identity_immutable()',true,true),
('public.gc_type_migration_canonical(jsonb,integer)',false,true),
('public.gc_type_migration_complete()',false,true),
('public.gc_type_migration_consistent()',false,true),
('public.gc_type_migration_hash(jsonb)',false,true),
('public.gc_type_pins_valid(jsonb,integer)',true,true),
('public.gc_type_version_consistent()',true,true)) v(signature,public_execute,legacy_execute) LOOP
  f:=to_regprocedure(item.signature);
  SELECT EXISTS(SELECT 1 FROM pg_proc q CROSS JOIN LATERAL aclexplode(coalesce(q.proacl,acldefault('f',q.proowner))) a WHERE q.oid=f AND a.grantee=0 AND a.privilege_type='EXECUTE') INTO actual_public;
  IF f IS NULL OR actual_public IS DISTINCT FROM item.public_execute OR has_function_privilege('gc_app',f,'EXECUTE') IS DISTINCT FROM item.legacy_execute OR (SELECT proowner FROM pg_proc WHERE oid=f)<>session_user::regrole::oid THEN RAISE EXCEPTION 'AUTHN_INSTALL_PREREQUISITE' USING ERRCODE='42501'; END IF;
 END LOOP;
END $$;
CREATE SCHEMA gc_authn;
REVOKE ALL ON SCHEMA gc_authn FROM PUBLIC,gc_app;
GRANT USAGE,CREATE ON SCHEMA gc_authn,public TO gc_authn_definer;
ALTER DEFAULT PRIVILEGES IN SCHEMA gc_authn REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA gc_authn REVOKE USAGE ON TYPES FROM PUBLIC;
CREATE TYPE gc_authn.installation_result AS (installation_id uuid,manifest_hash text,target_id uuid,recorded_at timestamptz);
CREATE TYPE public.gc_authn_attempt_started AS (format_version integer,attempt_id uuid,expires_at timestamptz);
CREATE TYPE public.gc_authn_attempt_exchange AS (format_version integer,attempt_id uuid,verifier text,issuer_id uuid,issuer text,client_id text,redirect_uri text,nonce_hash text,expires_at timestamptz);
CREATE TYPE public.gc_authn_session_issued AS (format_version integer,session_id uuid,session_version integer,selected_tenant_id uuid,expires_at timestamptz);
CREATE TYPE public.gc_authn_authenticated_session AS (format_version integer,session_id uuid,session_version integer,identity_id uuid,selected_tenant_id uuid,issuer_id uuid,identity_binding_id uuid,authenticated_at timestamptz,expires_at timestamptz,generation integer,tenant_fence_epoch integer,authority_mode text,content_authority boolean);
CREATE TYPE public.gc_authn_session_revoked AS (format_version integer,session_id uuid,session_version integer,logged_out boolean);
CREATE TYPE public.gc_authn_session_selected AS (format_version integer,session_id uuid,session_version integer,selected_tenant_id uuid,tenant_fence_epoch integer,authority_mode text);
REVOKE ALL ON TYPE public.gc_authn_attempt_started,public.gc_authn_attempt_exchange,public.gc_authn_session_issued,public.gc_authn_authenticated_session,public.gc_authn_session_revoked,public.gc_authn_session_selected FROM PUBLIC,gc_app;
CREATE FUNCTION gc_authn.valid_uuid(v uuid) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$ SELECT v IS NOT NULL AND v<>'00000000-0000-0000-0000-000000000000'::uuid $$;
CREATE FUNCTION gc_authn.valid_time(v timestamptz) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$ SELECT v IS NOT NULL AND isfinite(v) AND v>='0001-01-01 00:00:00+00'::timestamptz AND v<'10000-01-01 00:00:00+00'::timestamptz AND v=date_trunc('milliseconds',v) $$;
CREATE FUNCTION gc_authn.valid_text(v text,lim integer) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$ SELECT v IS NOT NULL AND octet_length(v) BETWEEN 1 AND lim AND v !~ '[[:cntrl:]]' $$;
CREATE FUNCTION gc_authn.valid_digest(v text) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$ SELECT v IS NOT NULL AND octet_length(v)=64 AND v ~ '^[0-9a-f]{64}$' $$;
CREATE TABLE gc_authn.installation_root(singleton boolean PRIMARY KEY CHECK(singleton),database_oid oid NOT NULL,owner_role_oid oid NOT NULL,owner_role_name name NOT NULL,contract_hash text NOT NULL CHECK(gc_authn.valid_digest(contract_hash)),installed_at timestamptz NOT NULL CHECK(gc_authn.valid_time(installed_at)));
INSERT INTO gc_authn.installation_root VALUES(true,(SELECT oid FROM pg_database WHERE datname=current_database()),session_user::regrole::oid,session_user,'7795a8114e3ea9969757a92d879788ff15e933c3b9438c469c97ff1a3cb23ee6',date_trunc('milliseconds',clock_timestamp()));
CREATE TABLE gc_authn.installation_receipts(
 id uuid PRIMARY KEY CHECK(gc_authn.valid_uuid(id)),request_id uuid NOT NULL UNIQUE CHECK(gc_authn.valid_uuid(request_id)),deployment_database_oid oid NOT NULL,owner_role_oid oid NOT NULL,owner_role_name name NOT NULL,
 operation text NOT NULL CHECK(operation IN('register-executor','advance-generation','advance-tenant-generation','register-issuer','bind-identity','initialize-tenant','revoke-executor','revoke-issuer','revoke-binding')),
 target_id uuid NOT NULL CHECK(gc_authn.valid_uuid(target_id)),manifest_hash text NOT NULL UNIQUE CHECK(gc_authn.valid_digest(manifest_hash)),manifest_encoding bytea NOT NULL CHECK(octet_length(manifest_encoding) BETWEEN 1 AND 65536),predecessor_hash text REFERENCES gc_authn.installation_receipts(manifest_hash),release_reference text NOT NULL CHECK(gc_authn.valid_text(release_reference,256)),deployment_operator_reference text NOT NULL CHECK(gc_authn.valid_text(deployment_operator_reference,256)),recorded_at timestamptz NOT NULL CHECK(gc_authn.valid_time(recorded_at)),CHECK(manifest_hash=encode(sha256(manifest_encoding),'hex')));
CREATE TABLE gc_authn.executor_registrations(
 id uuid PRIMARY KEY CHECK(gc_authn.valid_uuid(id)),role_oid oid NOT NULL UNIQUE,role_name name NOT NULL UNIQUE,kind text NOT NULL CHECK(kind IN('login','api')),channel_id uuid NOT NULL CHECK(gc_authn.valid_uuid(channel_id)),generation integer NOT NULL CHECK(generation>0),installation_id uuid NOT NULL UNIQUE REFERENCES gc_authn.installation_receipts,installed_at timestamptz NOT NULL CHECK(gc_authn.valid_time(installed_at)),expires_at timestamptz NOT NULL CHECK(gc_authn.valid_time(expires_at)),revoked_at timestamptz CHECK(revoked_at IS NULL OR gc_authn.valid_time(revoked_at)),UNIQUE(kind,channel_id,generation),UNIQUE(id,kind,channel_id,generation),UNIQUE(id,kind,generation),CHECK(expires_at>installed_at),CHECK(revoked_at IS NULL OR revoked_at>=installed_at));
CREATE TABLE gc_authn.generation_heads(kind text NOT NULL CHECK(kind IN('login','api')),channel_id uuid NOT NULL CHECK(gc_authn.valid_uuid(channel_id)),generation integer NOT NULL CHECK(generation>0),executor_registration_id uuid NOT NULL UNIQUE,version integer NOT NULL CHECK(version>0),installation_id uuid NOT NULL REFERENCES gc_authn.installation_receipts,advanced_at timestamptz NOT NULL CHECK(gc_authn.valid_time(advanced_at)),PRIMARY KEY(kind,channel_id),FOREIGN KEY(executor_registration_id,kind,channel_id,generation) REFERENCES gc_authn.executor_registrations(id,kind,channel_id,generation));
CREATE TABLE gc_authn.issuer_registrations(id uuid PRIMARY KEY CHECK(gc_authn.valid_uuid(id)),executor_registration_id uuid NOT NULL UNIQUE,executor_kind text NOT NULL DEFAULT 'login' CHECK(executor_kind='login'),generation integer NOT NULL CHECK(generation>0),issuer text NOT NULL CHECK(gc_authn.valid_text(issuer,2048)),client_id text NOT NULL CHECK(gc_authn.valid_text(client_id,256)),redirect_uri text NOT NULL CHECK(gc_authn.valid_text(redirect_uri,2048)),environment text NOT NULL CHECK(environment IN('isolated-test','local-development','production')),installation_id uuid NOT NULL UNIQUE REFERENCES gc_authn.installation_receipts,installed_at timestamptz NOT NULL CHECK(gc_authn.valid_time(installed_at)),expires_at timestamptz NOT NULL CHECK(gc_authn.valid_time(expires_at)),revoked_at timestamptz CHECK(revoked_at IS NULL OR gc_authn.valid_time(revoked_at)),FOREIGN KEY(executor_registration_id,executor_kind,generation) REFERENCES gc_authn.executor_registrations(id,kind,generation),CHECK(expires_at>installed_at),CHECK(revoked_at IS NULL OR revoked_at>=installed_at));
CREATE TABLE gc_authn.identity_bindings(id uuid PRIMARY KEY CHECK(gc_authn.valid_uuid(id)),issuer_registration_id uuid NOT NULL REFERENCES gc_authn.issuer_registrations,identity_id uuid NOT NULL REFERENCES public.identities,subject text NOT NULL CHECK(gc_authn.valid_text(subject,1024)),canonical_issuer text NOT NULL CHECK(gc_authn.valid_text(canonical_issuer,2048)),version integer NOT NULL DEFAULT 1 CHECK(version=1),installation_id uuid NOT NULL UNIQUE REFERENCES gc_authn.installation_receipts,installed_at timestamptz NOT NULL CHECK(gc_authn.valid_time(installed_at)),expires_at timestamptz NOT NULL CHECK(gc_authn.valid_time(expires_at)),revoked_at timestamptz CHECK(revoked_at IS NULL OR gc_authn.valid_time(revoked_at)),UNIQUE(issuer_registration_id,subject),UNIQUE(issuer_registration_id,identity_id),UNIQUE(id,identity_id),CHECK(expires_at>installed_at),CHECK(revoked_at IS NULL OR revoked_at>=installed_at));
CREATE TABLE gc_authn.login_attempts(id uuid PRIMARY KEY CHECK(gc_authn.valid_uuid(id)),state_hash text NOT NULL UNIQUE CHECK(gc_authn.valid_digest(state_hash)),nonce_hash text NOT NULL CHECK(gc_authn.valid_digest(nonce_hash)),issuer_registration_id uuid NOT NULL REFERENCES gc_authn.issuer_registrations,executor_registration_id uuid NOT NULL REFERENCES gc_authn.executor_registrations,generation integer NOT NULL CHECK(generation>0),verifier text CHECK(verifier IS NULL OR (octet_length(verifier) BETWEEN 43 AND 128 AND verifier ~ '^[A-Za-z0-9._~-]+$')),created_at timestamptz NOT NULL CHECK(gc_authn.valid_time(created_at)),expires_at timestamptz NOT NULL CHECK(gc_authn.valid_time(expires_at)),CHECK(expires_at=created_at+interval '300 seconds'));
CREATE TABLE gc_authn.attempt_consumptions(attempt_id uuid PRIMARY KEY REFERENCES gc_authn.login_attempts,executor_registration_id uuid NOT NULL REFERENCES gc_authn.executor_registrations,generation integer NOT NULL CHECK(generation>0),consumed_at timestamptz NOT NULL CHECK(gc_authn.valid_time(consumed_at)),consumed_transaction_id xid8 NOT NULL,issue_deadline_at timestamptz NOT NULL CHECK(gc_authn.valid_time(issue_deadline_at)),CHECK(issue_deadline_at>consumed_at AND issue_deadline_at<=consumed_at+interval '60 seconds'));
CREATE TABLE gc_authn.sessions(id uuid PRIMARY KEY CHECK(gc_authn.valid_uuid(id)),session_hash text NOT NULL UNIQUE CHECK(gc_authn.valid_digest(session_hash)),identity_id uuid NOT NULL REFERENCES public.identities,selected_tenant_id uuid NOT NULL,csrf_hash text NOT NULL CHECK(gc_authn.valid_digest(csrf_hash)),version integer NOT NULL CHECK(version>0),generation integer NOT NULL CHECK(generation>0),issued_at timestamptz NOT NULL CHECK(gc_authn.valid_time(issued_at)),authenticated_at timestamptz NOT NULL CHECK(gc_authn.valid_time(authenticated_at)),expires_at timestamptz NOT NULL CHECK(gc_authn.valid_time(expires_at)),revoked_at timestamptz CHECK(revoked_at IS NULL OR gc_authn.valid_time(revoked_at)),FOREIGN KEY(selected_tenant_id,identity_id) REFERENCES public.memberships(tenant_id,identity_id),UNIQUE(id,identity_id),CHECK(authenticated_at<=issued_at AND expires_at>issued_at AND expires_at<=issued_at+interval '1800 seconds'),CHECK(revoked_at IS NULL OR revoked_at>=issued_at));
CREATE TABLE gc_authn.session_provenance(session_id uuid PRIMARY KEY REFERENCES gc_authn.sessions,attempt_id uuid NOT NULL UNIQUE REFERENCES gc_authn.attempt_consumptions(attempt_id),identity_binding_id uuid NOT NULL REFERENCES gc_authn.identity_bindings,issuer_registration_id uuid NOT NULL REFERENCES gc_authn.issuer_registrations,issuing_executor_registration_id uuid NOT NULL REFERENCES gc_authn.executor_registrations,issuing_role_oid oid NOT NULL,generation integer NOT NULL CHECK(generation>0),initial_tenant_id uuid NOT NULL,identity_id uuid NOT NULL,initial_version integer NOT NULL CHECK(initial_version=1),initial_csrf_hash text NOT NULL CHECK(gc_authn.valid_digest(initial_csrf_hash)),session_hash text NOT NULL UNIQUE CHECK(gc_authn.valid_digest(session_hash)),authenticated_at timestamptz NOT NULL CHECK(gc_authn.valid_time(authenticated_at)),token_issued_at timestamptz NOT NULL CHECK(gc_authn.valid_time(token_issued_at)),token_expires_at timestamptz NOT NULL CHECK(gc_authn.valid_time(token_expires_at)),id_token_hash text NOT NULL CHECK(gc_authn.valid_digest(id_token_hash)),issued_at timestamptz NOT NULL CHECK(gc_authn.valid_time(issued_at)),expires_at timestamptz NOT NULL CHECK(gc_authn.valid_time(expires_at)),FOREIGN KEY(initial_tenant_id,identity_id) REFERENCES public.memberships(tenant_id,identity_id),FOREIGN KEY(session_id,identity_id) REFERENCES gc_authn.sessions(id,identity_id),UNIQUE(issuer_registration_id,id_token_hash),CHECK(authenticated_at<=token_issued_at AND token_issued_at<=issued_at AND token_expires_at>issued_at));
CREATE TABLE gc_authn.session_events(session_id uuid NOT NULL,version integer NOT NULL CHECK(version>0),kind text NOT NULL CHECK(kind IN('issued','tenant-selected','revoked')),identity_id uuid NOT NULL,previous_tenant_id uuid,selected_tenant_id uuid NOT NULL,csrf_hash text NOT NULL CHECK(gc_authn.valid_digest(csrf_hash)),occurred_at timestamptz NOT NULL CHECK(gc_authn.valid_time(occurred_at)),executor_registration_id uuid NOT NULL REFERENCES gc_authn.executor_registrations,executor_role_oid oid NOT NULL,generation integer NOT NULL CHECK(generation>0),PRIMARY KEY(session_id,version),FOREIGN KEY(session_id,identity_id) REFERENCES gc_authn.sessions(id,identity_id),FOREIGN KEY(previous_tenant_id,identity_id) REFERENCES public.memberships(tenant_id,identity_id),FOREIGN KEY(selected_tenant_id,identity_id) REFERENCES public.memberships(tenant_id,identity_id),CHECK((kind='issued' AND version=1 AND previous_tenant_id IS NULL) OR (kind<>'issued' AND version>1 AND previous_tenant_id IS NOT NULL)));
CREATE TABLE gc_authn.registration_revocations(installation_id uuid PRIMARY KEY REFERENCES gc_authn.installation_receipts,target_kind text NOT NULL CHECK(target_kind IN('executor','issuer','binding')),target_id uuid NOT NULL CHECK(gc_authn.valid_uuid(target_id)),revoked_at timestamptz NOT NULL CHECK(gc_authn.valid_time(revoked_at)),executor_registration_id uuid UNIQUE REFERENCES gc_authn.executor_registrations,issuer_registration_id uuid UNIQUE REFERENCES gc_authn.issuer_registrations,identity_binding_id uuid UNIQUE REFERENCES gc_authn.identity_bindings,CHECK(num_nonnulls(executor_registration_id,issuer_registration_id,identity_binding_id)=1),CHECK((target_kind='executor' AND target_id=executor_registration_id AND issuer_registration_id IS NULL AND identity_binding_id IS NULL) OR (target_kind='issuer' AND target_id=issuer_registration_id AND executor_registration_id IS NULL AND identity_binding_id IS NULL) OR(target_kind='binding' AND target_id=identity_binding_id AND executor_registration_id IS NULL AND issuer_registration_id IS NULL)));
CREATE TABLE gc_authn.tenant_fences(tenant_id uuid PRIMARY KEY REFERENCES public.tenants,mode text NOT NULL CHECK(mode='inactive'),generation integer NOT NULL CHECK(generation>0),epoch integer NOT NULL CHECK(epoch>0),installation_id uuid NOT NULL UNIQUE REFERENCES gc_authn.installation_receipts,initialized_at timestamptz NOT NULL CHECK(gc_authn.valid_time(initialized_at)));
ALTER TABLE gc_authn.tenant_fences ENABLE ROW LEVEL SECURITY;
ALTER TABLE gc_authn.tenant_fences FORCE ROW LEVEL SECURITY;
CREATE POLICY authn_selected_tenant ON gc_authn.tenant_fences TO gc_authn_definer USING(tenant_id=public.gc_tenant()) WITH CHECK(false);
DO $$ BEGIN EXECUTE format('CREATE POLICY authn_install_owner ON gc_authn.tenant_fences TO %I USING(true) WITH CHECK(true)',session_user); END $$;
-- Scalar admission and private exact installation codec. No arbitrary SQL/JSON dispatcher.
CREATE FUNCTION gc_authn.require_input(ok boolean) RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN IF ok IS DISTINCT FROM true THEN RAISE EXCEPTION 'AUTHN_INPUT_INVALID' USING ERRCODE='22023'; END IF; END $$;
CREATE FUNCTION gc_authn.require_auth(ok boolean) RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN IF ok IS DISTINCT FROM true THEN RAISE EXCEPTION 'AUTHN_REJECTED' USING ERRCODE='28000'; END IF; END $$;
CREATE FUNCTION gc_authn.require_mutation() RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN PERFORM gc_authn.require_auth(current_setting('transaction_isolation')='read committed' AND current_setting('transaction_read_only')='off'); END $$;
CREATE FUNCTION gc_authn.scalar(v text,kind text) RETURNS text LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
BEGIN IF v IS NULL THEN RETURN 'N;'; END IF;
 CASE kind WHEN 'S' THEN RETURN 'S'||octet_length(v)::text||':'||v; WHEN 'U' THEN RETURN 'U'||v::uuid::text||';'; WHEN 'I' THEN RETURN 'I'||v::bigint::text||';'; WHEN 'T' THEN PERFORM gc_authn.require_input(gc_authn.valid_time(v::timestamptz)); RETURN 'T'||to_char(v::timestamptz AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')||';'; ELSE RAISE EXCEPTION 'AUTHN_INPUT_INVALID' USING ERRCODE='22023'; END CASE;
END $$;
CREATE FUNCTION gc_authn.field(k text,v text,kind text) RETURNS text LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$ SELECT gc_authn.scalar(k,'S')||gc_authn.scalar(v,kind) $$;
CREATE FUNCTION gc_authn.install_encoding(op text,request_id uuid,release_ref text,operator_ref text,expected_db_oid oid,expected_owner_oid oid,predecessor_hash text) RETURNS text LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT 'gc-authn-install/v1;'||gc_authn.scalar(op,'S')||gc_authn.field('request_id',request_id::text,'U')||gc_authn.field('release_ref',release_ref,'S')||gc_authn.field('operator_ref',operator_ref,'S')||gc_authn.field('expected_db_oid',expected_db_oid::text,'I')||gc_authn.field('expected_owner_oid',expected_owner_oid::text,'I')||gc_authn.field('predecessor_hash',predecessor_hash,'S') $$;
CREATE FUNCTION gc_authn.install_check(request_id uuid,release_ref text,operator_ref text,expected_db_oid oid,expected_owner_oid oid,predecessor_hash text) RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE r gc_authn.installation_root;
BEGIN
 PERFORM gc_authn.require_mutation();
 SELECT * INTO r FROM gc_authn.installation_root WHERE singleton;
 IF NOT FOUND OR session_user::regrole::oid<>r.owner_role_oid OR current_user::regrole::oid<>r.owner_role_oid OR r.database_oid<>(SELECT oid FROM pg_database WHERE datname=current_database()) OR NOT EXISTS(SELECT 1 FROM pg_roles WHERE oid=r.owner_role_oid AND rolname=r.owner_role_name AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolinherit AND NOT rolbypassrls AND NOT rolreplication) THEN RAISE EXCEPTION 'AUTHN_EXECUTOR_REJECTED' USING ERRCODE='42501'; END IF;
 PERFORM gc_authn.require_input(gc_authn.valid_uuid(request_id) AND gc_authn.valid_text(release_ref,256) AND release_ref ~ '^[ -~]+$' AND gc_authn.valid_text(operator_ref,256) AND operator_ref ~ '^[ -~]+$' AND expected_db_oid=r.database_oid AND expected_owner_oid=r.owner_role_oid AND (predecessor_hash IS NULL OR gc_authn.valid_digest(predecessor_hash)));
 IF predecessor_hash IS NOT NULL AND NOT EXISTS(SELECT 1 FROM gc_authn.installation_receipts WHERE manifest_hash=install_check.predecessor_hash) THEN RAISE EXCEPTION 'AUTHN_INSTALL_CONFLICT' USING ERRCODE='23505'; END IF;
 -- A single bounded deployment lock serializes request IDs and exact scalar installation effects.
 PERFORM pg_advisory_xact_lock(hashtextextended('gc-authn-install:'||r.database_oid::text,0));
END $$;
CREATE FUNCTION gc_authn.install_existing(request_id uuid,encoding text) RETURNS gc_authn.installation_result LANGUAGE plpgsql SET search_path=pg_catalog,gc_authn,pg_temp AS $$
DECLARE r gc_authn.installation_receipts;
BEGIN
 PERFORM gc_authn.require_input(octet_length(encoding)<=65536);
 SELECT * INTO r FROM gc_authn.installation_receipts x WHERE x.request_id=install_existing.request_id;
 IF FOUND THEN IF r.manifest_encoding<>convert_to(encoding,'UTF8') THEN RAISE EXCEPTION 'AUTHN_INSTALL_CONFLICT' USING ERRCODE='23505'; END IF; RETURN (r.id,r.manifest_hash,r.target_id,r.recorded_at)::gc_authn.installation_result; END IF; RETURN NULL;
END $$;
CREATE FUNCTION gc_authn.install_receipt(op text,target uuid,request_id uuid,release_ref text,operator_ref text,predecessor_hash text,encoding text) RETURNS gc_authn.installation_result LANGUAGE plpgsql SET search_path=pg_catalog,gc_authn,pg_temp AS $$
DECLARE r gc_authn.installation_receipts;
BEGIN
 INSERT INTO gc_authn.installation_receipts(id,request_id,deployment_database_oid,owner_role_oid,owner_role_name,operation,target_id,manifest_hash,manifest_encoding,predecessor_hash,release_reference,deployment_operator_reference,recorded_at)
 SELECT gen_random_uuid(),request_id,database_oid,owner_role_oid,owner_role_name,op,target,encode(sha256(convert_to(encoding,'UTF8')),'hex'),convert_to(encoding,'UTF8'),predecessor_hash,release_ref,operator_ref,date_trunc('milliseconds',clock_timestamp()) FROM gc_authn.installation_root WHERE singleton RETURNING * INTO r;
 RETURN (r.id,r.manifest_hash,r.target_id,r.recorded_at)::gc_authn.installation_result;
END $$;
CREATE FUNCTION gc_authn.role_safe(role_oid oid,role_name text) RETURNS boolean LANGUAGE sql VOLATILE SET search_path=pg_catalog AS $$
 SELECT EXISTS(SELECT 1 FROM pg_roles r WHERE r.oid=role_oid AND r.rolname::text=role_name AND r.rolcanlogin AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolinherit AND NOT r.rolbypassrls AND NOT r.rolreplication
 AND NOT EXISTS(SELECT 1 FROM pg_auth_members a WHERE a.roleid=r.oid OR a.member=r.oid)
 AND NOT has_database_privilege(r.oid,current_database(),'CREATE,TEMP')
 AND NOT EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspowner=r.oid OR has_schema_privilege(r.oid,n.oid,'CREATE') OR (n.nspname='gc_authn' AND has_schema_privilege(r.oid,n.oid,'USAGE')))
 AND NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relowner=r.oid OR (n.nspname IN('public','gc_authn') AND CASE WHEN c.relkind IN('r','p','v','m','f') THEN has_table_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(r.oid,c.oid,'SELECT,INSERT,UPDATE,REFERENCES') WHEN c.relkind='S' THEN has_sequence_privilege(r.oid,c.oid,'SELECT,UPDATE,USAGE') ELSE false END))
 AND NOT EXISTS(SELECT 1 FROM pg_proc f JOIN pg_namespace n ON n.oid=f.pronamespace WHERE f.proowner=r.oid OR (n.nspname IN('public','gc_authn') AND has_function_privilege(r.oid,f.oid,'EXECUTE') AND NOT (
 f.oid=ANY(CASE (SELECT x.kind FROM gc_authn.executor_registrations x WHERE x.role_oid=r.oid)
 WHEN 'login' THEN ARRAY[to_regprocedure('public.gc_authn_attempt_begin(text,text,text)'),to_regprocedure('public.gc_authn_attempt_consume(uuid,text)'),to_regprocedure('public.gc_authn_session_issue(uuid,text,text,text,text,text,timestamp with time zone,timestamp with time zone,timestamp with time zone,text,text)')]
 WHEN 'api' THEN ARRAY[to_regprocedure('public.gc_authn_session_inspect(text)'),to_regprocedure('public.gc_authn_session_revoke(text,text,integer)'),to_regprocedure('public.gc_authn_session_select(text,text,integer,uuid,text)')]
 ELSE ARRAY[to_regprocedure('public.gc_authn_attempt_begin(text,text,text)'),to_regprocedure('public.gc_authn_attempt_consume(uuid,text)'),to_regprocedure('public.gc_authn_session_issue(uuid,text,text,text,text,text,timestamp with time zone,timestamp with time zone,timestamp with time zone,text,text)'),to_regprocedure('public.gc_authn_session_inspect(text)'),to_regprocedure('public.gc_authn_session_revoke(text,text,integer)'),to_regprocedure('public.gc_authn_session_select(text,text,integer,uuid,text)')] END)::boolean
 )))) $$;
CREATE FUNCTION gc_authn.current_registration(registration uuid,required_kind text) RETURNS gc_authn.executor_registrations LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,gc_authn,pg_temp AS $$
DECLARE r gc_authn.executor_registrations;
BEGIN
 SELECT x.* INTO r FROM gc_authn.executor_registrations x JOIN gc_authn.generation_heads h ON (h.executor_registration_id,h.kind,h.channel_id,h.generation)=(x.id,x.kind,x.channel_id,x.generation) WHERE x.id=registration AND x.kind=required_kind;
 IF NOT FOUND OR r.revoked_at IS NOT NULL OR r.expires_at<=clock_timestamp() OR NOT gc_authn.role_safe(r.role_oid,r.role_name::text) THEN RAISE EXCEPTION 'AUTHN_EXECUTOR_REJECTED' USING ERRCODE='42501'; END IF; RETURN r;
END $$;
CREATE FUNCTION gc_authn.executor(required_kind text) RETURNS gc_authn.executor_registrations LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,gc_authn,pg_temp AS $$
DECLARE id uuid;
BEGIN SELECT r.id INTO id FROM gc_authn.executor_registrations r WHERE r.role_oid=session_user::regrole::oid AND r.role_name=session_user AND r.kind=required_kind; IF NOT FOUND THEN RAISE EXCEPTION 'AUTHN_EXECUTOR_REJECTED' USING ERRCODE='42501'; END IF; RETURN gc_authn.current_registration(id,required_kind); END $$;
CREATE FUNCTION gc_authn.immutable() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN RAISE EXCEPTION 'AUTHN_IMMUTABLE' USING ERRCODE='23514'; END $$;
CREATE FUNCTION gc_authn.registration_update() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL OR NEW.revoked_at<OLD.installed_at OR (to_jsonb(NEW)-'revoked_at') IS DISTINCT FROM (to_jsonb(OLD)-'revoked_at') THEN RAISE EXCEPTION 'AUTHN_IMMUTABLE' USING ERRCODE='23514'; END IF; RETURN NEW;
END $$;
CREATE FUNCTION gc_authn.head_update() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
 IF (NEW.kind,NEW.channel_id) IS DISTINCT FROM (OLD.kind,OLD.channel_id) OR OLD.version=2147483647 OR NEW.version<>OLD.version+1 OR NEW.generation<=OLD.generation OR NEW.executor_registration_id=OLD.executor_registration_id OR NEW.advanced_at<OLD.advanced_at THEN RAISE EXCEPTION 'AUTHN_IMMUTABLE' USING ERRCODE='23514'; END IF; RETURN NEW; END $$;
CREATE FUNCTION gc_authn.fence_update() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
 IF (NEW.tenant_id,NEW.mode,NEW.initialized_at) IS DISTINCT FROM (OLD.tenant_id,OLD.mode,OLD.initialized_at) OR OLD.epoch=2147483647 OR NEW.epoch<>OLD.epoch+1 OR NEW.generation<=OLD.generation OR NEW.installation_id=OLD.installation_id THEN RAISE EXCEPTION 'AUTHN_IMMUTABLE' USING ERRCODE='23514'; END IF; RETURN NEW; END $$;
CREATE FUNCTION gc_authn.attempt_update() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
 IF OLD.verifier IS NULL OR NEW.verifier IS NOT NULL OR (to_jsonb(NEW)-'verifier') IS DISTINCT FROM (to_jsonb(OLD)-'verifier') THEN RAISE EXCEPTION 'AUTHN_IMMUTABLE' USING ERRCODE='23514'; END IF; RETURN NEW; END $$;
CREATE FUNCTION gc_authn.session_update() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
 IF OLD.revoked_at IS NOT NULL OR OLD.version=2147483647 OR NEW.version<>OLD.version+1 OR (to_jsonb(NEW)-ARRAY['selected_tenant_id','csrf_hash','version','revoked_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['selected_tenant_id','csrf_hash','version','revoked_at'])
 OR (NEW.revoked_at IS NULL AND NEW.csrf_hash=OLD.csrf_hash) OR (NEW.revoked_at IS NOT NULL AND ((NEW.selected_tenant_id,NEW.csrf_hash) IS DISTINCT FROM (OLD.selected_tenant_id,OLD.csrf_hash) OR NEW.revoked_at<OLD.issued_at)) THEN RAISE EXCEPTION 'AUTHN_IMMUTABLE' USING ERRCODE='23514'; END IF; RETURN NEW; END $$;
CREATE FUNCTION gc_authn.lock_configuration(executing_registration_id uuid,issuing_registration_id uuid,issuer_id uuid,binding_id uuid,tenant_ids uuid[]) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE ids uuid[]; n integer;
BEGIN
 PERFORM gc_authn.require_input(gc_authn.valid_uuid(executing_registration_id) AND tenant_ids IS NOT NULL AND coalesce(array_ndims(tenant_ids),1)=1 AND cardinality(tenant_ids)<=2 AND array_position(tenant_ids,NULL) IS NULL AND NOT ('00000000-0000-0000-0000-000000000000'::uuid=ANY(tenant_ids)) AND tenant_ids=ARRAY(SELECT DISTINCT v FROM unnest(tenant_ids) v ORDER BY v));
 SELECT array_agg(DISTINCT v ORDER BY v) INTO ids FROM unnest(ARRAY[executing_registration_id,issuing_registration_id]) v WHERE v IS NOT NULL;
 PERFORM h.kind FROM gc_authn.generation_heads h WHERE h.executor_registration_id=ANY(ids) ORDER BY h.kind,h.channel_id FOR SHARE;
 GET DIAGNOSTICS n=ROW_COUNT; PERFORM gc_authn.require_auth(n=cardinality(ids));
 PERFORM r.id FROM gc_authn.executor_registrations r WHERE r.id=ANY(ids) ORDER BY r.id FOR SHARE;
 GET DIAGNOSTICS n=ROW_COUNT; PERFORM gc_authn.require_auth(n=cardinality(ids));
 IF issuer_id IS NOT NULL THEN PERFORM i.id FROM gc_authn.issuer_registrations i WHERE i.id=issuer_id AND i.executor_registration_id=coalesce(issuing_registration_id,executing_registration_id) FOR SHARE; PERFORM gc_authn.require_auth(FOUND); END IF;
 IF binding_id IS NOT NULL THEN PERFORM b.id FROM gc_authn.identity_bindings b WHERE b.id=binding_id AND b.issuer_registration_id=issuer_id FOR SHARE; PERFORM gc_authn.require_auth(FOUND); END IF;
 PERFORM f.tenant_id FROM gc_authn.tenant_fences f WHERE f.tenant_id=ANY(tenant_ids) ORDER BY f.tenant_id FOR SHARE;
 GET DIAGNOSTICS n=ROW_COUNT; PERFORM gc_authn.require_auth(n=cardinality(tenant_ids));
END $$;
CREATE FUNCTION gc_authn.lock_principals(identity_id uuid,tenant_ids uuid[]) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE old_actor text:=current_setting('gc.actor_id',true); old_tenant text:=current_setting('gc.tenant_id',true); t uuid;
BEGIN
 PERFORM gc_authn.require_input(gc_authn.valid_uuid(identity_id) AND tenant_ids IS NOT NULL AND array_ndims(tenant_ids)=1 AND cardinality(tenant_ids) BETWEEN 1 AND 2 AND array_position(tenant_ids,NULL) IS NULL AND NOT ('00000000-0000-0000-0000-000000000000'::uuid=ANY(tenant_ids)) AND tenant_ids=ARRAY(SELECT DISTINCT v FROM unnest(tenant_ids) v ORDER BY v));
 PERFORM set_config('gc.actor_id',identity_id::text,true);
 PERFORM i.id FROM public.identities i WHERE i.id=identity_id FOR SHARE; PERFORM gc_authn.require_auth(FOUND);
 FOREACH t IN ARRAY tenant_ids LOOP
  PERFORM set_config('gc.tenant_id',t::text,true);
  PERFORM m.identity_id FROM public.memberships m WHERE m.tenant_id=t AND m.identity_id=lock_principals.identity_id FOR SHARE;
  PERFORM gc_authn.require_auth(FOUND);
 END LOOP;
 PERFORM set_config('gc.actor_id',coalesce(old_actor,''),true); PERFORM set_config('gc.tenant_id',coalesce(old_tenant,''),true);
EXCEPTION WHEN OTHERS THEN PERFORM set_config('gc.actor_id',coalesce(old_actor,''),true);PERFORM set_config('gc.tenant_id',coalesce(old_tenant,''),true);RAISE;
END $$;
CREATE FUNCTION gc_authn.validate_session(session_id uuid) RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE s gc_authn.sessions; p gc_authn.session_provenance; e gc_authn.session_events; first_event gc_authn.session_events; prior gc_authn.session_events; a gc_authn.login_attempts; c gc_authn.attempt_consumptions; b gc_authn.identity_bindings; i gc_authn.issuer_registrations; r gc_authn.executor_registrations;
BEGIN
 SELECT * INTO s FROM gc_authn.sessions x WHERE x.id=session_id;
 SELECT * INTO p FROM gc_authn.session_provenance x WHERE x.session_id=validate_session.session_id;
 SELECT * INTO e FROM gc_authn.session_events x WHERE x.session_id=validate_session.session_id AND x.version=s.version;
 SELECT * INTO first_event FROM gc_authn.session_events x WHERE x.session_id=validate_session.session_id AND x.version=1;
 IF s.id IS NULL OR p.session_id IS NULL OR e.session_id IS NULL OR first_event.session_id IS NULL OR EXISTS(SELECT 1 FROM gc_authn.session_events x WHERE x.session_id=s.id AND x.version>s.version)
 OR (p.session_id,p.session_hash,p.identity_id,p.generation,p.authenticated_at,p.issued_at,p.expires_at) IS DISTINCT FROM (s.id,s.session_hash,s.identity_id,s.generation,s.authenticated_at,s.issued_at,s.expires_at)
 OR (e.identity_id,e.selected_tenant_id,e.csrf_hash,e.generation) IS DISTINCT FROM (s.identity_id,s.selected_tenant_id,s.csrf_hash,s.generation)
 OR (s.revoked_at IS NULL AND e.kind='revoked') OR (s.revoked_at IS NOT NULL AND (e.kind<>'revoked' OR e.occurred_at<>s.revoked_at))
 OR (first_event.kind,first_event.identity_id,first_event.selected_tenant_id,first_event.csrf_hash,first_event.occurred_at,first_event.executor_registration_id,first_event.executor_role_oid,first_event.generation) IS DISTINCT FROM ('issued',p.identity_id,p.initial_tenant_id,p.initial_csrf_hash,p.issued_at,p.issuing_executor_registration_id,p.issuing_role_oid,p.generation)
 THEN RAISE EXCEPTION 'AUTHN_INTEGRITY' USING ERRCODE='23514'; END IF;
 SELECT * INTO a FROM gc_authn.login_attempts WHERE id=p.attempt_id;
 SELECT * INTO c FROM gc_authn.attempt_consumptions WHERE attempt_id=p.attempt_id;
 SELECT * INTO b FROM gc_authn.identity_bindings WHERE id=p.identity_binding_id;
 SELECT * INTO i FROM gc_authn.issuer_registrations WHERE id=p.issuer_registration_id;
 SELECT * INTO r FROM gc_authn.executor_registrations WHERE id=p.issuing_executor_registration_id;
 IF a.id IS NULL OR c.attempt_id IS NULL OR b.id IS NULL OR i.id IS NULL OR r.id IS NULL OR a.verifier IS NOT NULL
 OR (a.issuer_registration_id,a.executor_registration_id,a.generation) IS DISTINCT FROM (i.id,r.id,p.generation)
 OR (c.executor_registration_id,c.generation) IS DISTINCT FROM (r.id,p.generation)
 OR (b.issuer_registration_id,b.identity_id,b.canonical_issuer) IS DISTINCT FROM (i.id,p.identity_id,i.issuer)
 OR (i.executor_registration_id,i.generation,r.role_oid,r.kind) IS DISTINCT FROM (r.id,p.generation,p.issuing_role_oid,'login')
 OR p.issued_at<c.consumed_at OR p.issued_at>=c.issue_deadline_at OR p.token_issued_at<a.created_at-interval '30 seconds'
 OR p.expires_at>least(p.issued_at+interval '1800 seconds',r.expires_at,i.expires_at,b.expires_at)
 THEN RAISE EXCEPTION 'AUTHN_INTEGRITY' USING ERRCODE='23514'; END IF;
 IF s.version>1 THEN
  SELECT * INTO prior FROM gc_authn.session_events x WHERE x.session_id=s.id AND x.version=s.version-1;
  IF prior.session_id IS NULL OR prior.kind='revoked' OR e.previous_tenant_id<>prior.selected_tenant_id OR e.occurred_at<prior.occurred_at
   OR (e.kind='tenant-selected' AND e.csrf_hash=prior.csrf_hash)
   OR (e.kind='revoked' AND (e.selected_tenant_id,e.csrf_hash) IS DISTINCT FROM (prior.selected_tenant_id,prior.csrf_hash))
   OR NOT EXISTS(SELECT 1 FROM gc_authn.executor_registrations x WHERE x.id=e.executor_registration_id AND x.kind='api' AND x.role_oid=e.executor_role_oid AND x.generation=e.generation)
  THEN RAISE EXCEPTION 'AUTHN_INTEGRITY' USING ERRCODE='23514'; END IF;
 END IF;
END $$;
CREATE FUNCTION gc_authn.session_consistent() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$ BEGIN
 IF TG_TABLE_NAME='sessions' THEN PERFORM gc_authn.validate_session(NEW.id); ELSE PERFORM gc_authn.validate_session(NEW.session_id); END IF; RETURN NULL;
END $$;
CREATE FUNCTION gc_authn.attempt_consistent() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE a gc_authn.login_attempts; c gc_authn.attempt_consumptions; ident uuid;
BEGIN
 IF TG_TABLE_NAME='login_attempts' THEN ident:=NEW.id; ELSE ident:=NEW.attempt_id; END IF;
 SELECT * INTO a FROM gc_authn.login_attempts WHERE id=ident;
 SELECT * INTO c FROM gc_authn.attempt_consumptions WHERE attempt_id=ident;
 IF a.id IS NULL OR NOT EXISTS(SELECT 1 FROM gc_authn.issuer_registrations i WHERE i.id=a.issuer_registration_id AND i.executor_registration_id=a.executor_registration_id AND i.generation=a.generation)
 OR ((a.verifier IS NULL)<>(c.attempt_id IS NOT NULL))
 OR (c.attempt_id IS NOT NULL AND ((c.executor_registration_id,c.generation) IS DISTINCT FROM (a.executor_registration_id,a.generation) OR c.consumed_at<a.created_at OR c.consumed_at>=a.expires_at OR c.issue_deadline_at<>least(a.expires_at,c.consumed_at+interval '60 seconds')))
 THEN RAISE EXCEPTION 'AUTHN_INTEGRITY' USING ERRCODE='23514'; END IF; RETURN NULL;
END $$;
CREATE FUNCTION gc_authn.install_consistent() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE r gc_authn.installation_receipts; ok boolean:=false; d timestamptz;
BEGIN
 IF TG_TABLE_NAME='installation_receipts' THEN r:=NEW;
 ELSE SELECT * INTO r FROM gc_authn.installation_receipts WHERE id=NEW.installation_id; END IF;
 CASE r.operation
 WHEN 'register-executor' THEN SELECT EXISTS(SELECT 1 FROM gc_authn.executor_registrations WHERE id=r.target_id AND installation_id=r.id AND installed_at=r.recorded_at) INTO ok;
 WHEN 'advance-generation' THEN SELECT EXISTS(SELECT 1 FROM gc_authn.generation_heads WHERE executor_registration_id=r.target_id AND installation_id=r.id AND advanced_at=r.recorded_at) INTO ok;
 WHEN 'register-issuer' THEN SELECT EXISTS(SELECT 1 FROM gc_authn.issuer_registrations WHERE id=r.target_id AND installation_id=r.id AND installed_at=r.recorded_at) INTO ok;
 WHEN 'bind-identity' THEN SELECT EXISTS(SELECT 1 FROM gc_authn.identity_bindings WHERE id=r.target_id AND installation_id=r.id AND installed_at=r.recorded_at) INTO ok;
 WHEN 'initialize-tenant' THEN SELECT EXISTS(SELECT 1 FROM gc_authn.tenant_fences WHERE tenant_id=r.target_id AND installation_id=r.id AND initialized_at=r.recorded_at AND epoch=1) INTO ok;
 WHEN 'advance-tenant-generation' THEN SELECT EXISTS(SELECT 1 FROM gc_authn.tenant_fences WHERE tenant_id=r.target_id AND installation_id=r.id AND epoch>1) INTO ok;
 WHEN 'revoke-executor','revoke-issuer','revoke-binding' THEN
  SELECT EXISTS(SELECT 1 FROM gc_authn.registration_revocations v WHERE v.installation_id=r.id AND v.target_id=r.target_id AND 'revoke-'||v.target_kind=r.operation AND v.revoked_at=r.recorded_at) INTO ok;
 ELSE ok:=false; END CASE;
 -- Receipt checks concern insertion transaction. Historical heads are never reinterpreted.
 IF NOT ok THEN RAISE EXCEPTION 'AUTHN_INTEGRITY' USING ERRCODE='23514'; END IF;
 IF TG_TABLE_NAME IN('executor_registrations','issuer_registrations','identity_bindings') THEN
 IF NEW.revoked_at IS NOT NULL THEN
  SELECT v.revoked_at INTO d FROM gc_authn.registration_revocations v WHERE v.target_id=NEW.id AND v.target_kind=CASE TG_TABLE_NAME WHEN 'executor_registrations' THEN 'executor' WHEN 'issuer_registrations' THEN 'issuer' ELSE 'binding' END;
  IF d IS DISTINCT FROM NEW.revoked_at THEN RAISE EXCEPTION 'AUTHN_INTEGRITY' USING ERRCODE='23514'; END IF;
 END IF;
 END IF;
 IF TG_TABLE_NAME='registration_revocations' THEN
  CASE NEW.target_kind WHEN 'executor' THEN SELECT revoked_at INTO d FROM gc_authn.executor_registrations WHERE id=NEW.target_id;
   WHEN 'issuer' THEN SELECT revoked_at INTO d FROM gc_authn.issuer_registrations WHERE id=NEW.target_id;
   WHEN 'binding' THEN SELECT revoked_at INTO d FROM gc_authn.identity_bindings WHERE id=NEW.target_id; END CASE;
  IF d IS DISTINCT FROM NEW.revoked_at THEN RAISE EXCEPTION 'AUTHN_INTEGRITY' USING ERRCODE='23514'; END IF;
 END IF; RETURN NULL;
END $$;

CREATE FUNCTION gc_authn.provision_executor(request_id uuid, release_ref text, operator_ref text, expected_db_oid oid, expected_owner_oid oid, predecessor_hash text, registration_id uuid, channel_id uuid, role_name text, expected_role_oid oid, kind text, generation integer, expires_at timestamptz) RETURNS gc_authn.installation_result LANGUAGE plpgsql SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE op constant text:='register-executor'; encoding text; result gc_authn.installation_result; head gc_authn.generation_heads; registration gc_authn.executor_registrations; issuer_row gc_authn.issuer_registrations; fence gc_authn.tenant_fences;
BEGIN
 PERFORM gc_authn.install_check(request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,predecessor_hash);
 PERFORM gc_authn.require_input(gc_authn.valid_uuid(registration_id) AND gc_authn.valid_uuid(channel_id) AND gc_authn.valid_text(role_name,63) AND kind IN('login','api') AND generation>0 AND gc_authn.valid_time(expires_at) AND expected_role_oid>0);
 encoding:=gc_authn.install_encoding(op,request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,predecessor_hash)||gc_authn.field('registration_id',registration_id::text,'U')||gc_authn.field('channel_id',channel_id::text,'U')||gc_authn.field('role_name',role_name::text,'S')||gc_authn.field('expected_role_oid',expected_role_oid::text,'I')||gc_authn.field('kind',kind::text,'S')||gc_authn.field('generation',generation::text,'I')||gc_authn.field('expires_at',expires_at::text,'T'); result:=gc_authn.install_existing(request_id,encoding); IF result.installation_id IS NOT NULL THEN RETURN result; END IF;
 PERFORM gc_authn.require_input(expires_at>clock_timestamp());
 IF NOT gc_authn.role_safe(expected_role_oid,role_name) THEN RAISE EXCEPTION 'AUTHN_EXECUTOR_REJECTED' USING ERRCODE='42501'; END IF;
 result:=gc_authn.install_receipt(op,registration_id,request_id,release_ref,operator_ref,predecessor_hash,encoding);
 INSERT INTO gc_authn.executor_registrations(id,role_oid,role_name,kind,channel_id,generation,installation_id,installed_at,expires_at) VALUES(registration_id,expected_role_oid,role_name::name,kind,channel_id,generation,result.installation_id,result.recorded_at,expires_at);
 IF NOT gc_authn.role_safe(expected_role_oid,role_name) THEN RAISE EXCEPTION 'AUTHN_EXECUTOR_REJECTED' USING ERRCODE='42501'; END IF;
 RETURN result;
EXCEPTION WHEN unique_violation OR foreign_key_violation OR check_violation OR not_null_violation THEN RAISE EXCEPTION 'AUTHN_INSTALL_CONFLICT' USING ERRCODE='23505';
END $$;

CREATE FUNCTION gc_authn.advance_generation(request_id uuid, release_ref text, operator_ref text, expected_db_oid oid, expected_owner_oid oid, predecessor_hash text, kind text, channel_id uuid, registration_id uuid, expected_previous_registration_id uuid, expected_head_version integer) RETURNS gc_authn.installation_result LANGUAGE plpgsql SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE op constant text:='advance-generation'; encoding text; result gc_authn.installation_result; head gc_authn.generation_heads; registration gc_authn.executor_registrations; issuer_row gc_authn.issuer_registrations; fence gc_authn.tenant_fences;
BEGIN
 PERFORM gc_authn.install_check(request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,predecessor_hash);
 PERFORM gc_authn.require_input(kind IN('login','api') AND gc_authn.valid_uuid(channel_id) AND gc_authn.valid_uuid(registration_id) AND ((expected_previous_registration_id IS NULL AND expected_head_version IS NULL) OR (gc_authn.valid_uuid(expected_previous_registration_id) AND expected_head_version>0)));
 encoding:=gc_authn.install_encoding(op,request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,predecessor_hash)||gc_authn.field('kind',kind::text,'S')||gc_authn.field('channel_id',channel_id::text,'U')||gc_authn.field('registration_id',registration_id::text,'U')||gc_authn.field('expected_previous_registration_id',expected_previous_registration_id::text,'U')||gc_authn.field('expected_head_version',expected_head_version::text,'I'); result:=gc_authn.install_existing(request_id,encoding); IF result.installation_id IS NOT NULL THEN RETURN result; END IF;
 SELECT * INTO head FROM gc_authn.generation_heads h WHERE h.kind=advance_generation.kind AND h.channel_id=advance_generation.channel_id FOR UPDATE;
 IF (head.executor_registration_id,head.version) IS DISTINCT FROM (expected_previous_registration_id,expected_head_version) THEN RAISE EXCEPTION 'AUTHN_INSTALL_CONFLICT' USING ERRCODE='23505'; END IF;
 SELECT * INTO registration FROM gc_authn.executor_registrations r WHERE r.id=registration_id AND r.kind=advance_generation.kind AND r.channel_id=advance_generation.channel_id FOR SHARE;
 PERFORM gc_authn.require_auth(registration.id IS NOT NULL AND registration.revoked_at IS NULL AND registration.expires_at>clock_timestamp() AND gc_authn.role_safe(registration.role_oid,registration.role_name::text) AND (head.version IS NULL OR (head.version<2147483647 AND registration.generation>head.generation)));
 result:=gc_authn.install_receipt(op,registration_id,request_id,release_ref,operator_ref,predecessor_hash,encoding);
 IF head.version IS NULL THEN INSERT INTO gc_authn.generation_heads VALUES(kind,channel_id,registration.generation,registration_id,1,result.installation_id,result.recorded_at);
 ELSE UPDATE gc_authn.generation_heads h SET generation=registration.generation,executor_registration_id=registration_id,version=head.version+1,installation_id=result.installation_id,advanced_at=result.recorded_at WHERE h.kind=advance_generation.kind AND h.channel_id=advance_generation.channel_id; END IF;
 RETURN result;
EXCEPTION WHEN unique_violation OR foreign_key_violation OR check_violation OR not_null_violation THEN RAISE EXCEPTION 'AUTHN_INSTALL_CONFLICT' USING ERRCODE='23505';
END $$;

CREATE FUNCTION gc_authn.valid_endpoint(value text,environment text) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE parts text[]; authority text; host_name text; port_value text; scheme text; tail text; labels text[]; label text;
BEGIN
 IF gc_authn.valid_text(value,2048) IS DISTINCT FROM true OR octet_length(value)<>char_length(value) OR environment NOT IN('isolated-test','local-development','production') THEN RETURN false; END IF;
 parts:=regexp_match(value,'^(https|http)://([^/?#]+)([/?].*)?$');
 IF parts IS NULL THEN RETURN false; END IF;
 scheme:=parts[1];authority:=parts[2];tail:=coalesce(parts[3],'');
 -- The accepted raw bytes are never repaired or normalized. Percent escapes are structural only.
 IF tail !~ '^([A-Za-z0-9._~!$&''()*+,;=:@/?-]|%[0-9A-Fa-f]{2})*$' THEN RETURN false; END IF;
 IF left(authority,1)='[' THEN
  parts:=regexp_match(authority,'^(\[::1\])(:([1-9][0-9]{0,4}))?$');
  IF parts IS NULL THEN RETURN false; END IF;
  host_name:=parts[1];port_value:=parts[3];
 ELSE
  parts:=regexp_match(authority,'^([a-z0-9.-]+)(:([1-9][0-9]{0,4}))?$');
  IF parts IS NULL OR octet_length(parts[1])>253 THEN RETURN false; END IF;
  host_name:=parts[1];port_value:=parts[3];labels:=string_to_array(host_name,'.');
  IF host_name ~ '^[0-9.]+$' THEN
   IF cardinality(labels)<>4 THEN RETURN false; END IF;
   FOREACH label IN ARRAY labels LOOP
    IF label !~ '^(0|[1-9][0-9]{0,2})$' OR label::integer>255 THEN RETURN false; END IF;
   END LOOP;
  ELSE
   IF labels[cardinality(labels)] !~ '^[a-z]' THEN RETURN false; END IF;
   FOREACH label IN ARRAY labels LOOP
    IF octet_length(label) NOT BETWEEN 1 AND 63 OR label !~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$' THEN RETURN false; END IF;
   END LOOP;
  END IF;
 END IF;
 IF port_value IS NOT NULL AND port_value::integer>65535 THEN RETURN false; END IF;
 RETURN scheme='https' OR (environment IN('isolated-test','local-development') AND host_name IN('localhost','127.0.0.1','[::1]'));
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END $$;
CREATE FUNCTION gc_authn.provision_issuer(request_id uuid, release_ref text, operator_ref text, expected_db_oid oid, expected_owner_oid oid, predecessor_hash text, issuer_id uuid, registration_id uuid, generation integer, issuer text, client_id text, redirect_uri text, environment text, expires_at timestamptz) RETURNS gc_authn.installation_result LANGUAGE plpgsql SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE op constant text:='register-issuer'; encoding text; result gc_authn.installation_result; head gc_authn.generation_heads; registration gc_authn.executor_registrations; issuer_row gc_authn.issuer_registrations; fence gc_authn.tenant_fences;
BEGIN
 PERFORM gc_authn.install_check(request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,predecessor_hash);
 PERFORM gc_authn.require_input(gc_authn.valid_uuid(issuer_id) AND gc_authn.valid_uuid(registration_id) AND generation>0 AND gc_authn.valid_text(issuer,2048) AND gc_authn.valid_text(client_id,256) AND gc_authn.valid_text(redirect_uri,2048) AND environment IN('isolated-test','local-development','production') AND gc_authn.valid_time(expires_at));
 PERFORM gc_authn.require_input(gc_authn.valid_endpoint(issuer,environment) AND gc_authn.valid_endpoint(redirect_uri,environment));
 encoding:=gc_authn.install_encoding(op,request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,predecessor_hash)||gc_authn.field('issuer_id',issuer_id::text,'U')||gc_authn.field('registration_id',registration_id::text,'U')||gc_authn.field('generation',generation::text,'I')||gc_authn.field('issuer',issuer::text,'S')||gc_authn.field('client_id',client_id::text,'S')||gc_authn.field('redirect_uri',redirect_uri::text,'S')||gc_authn.field('environment',environment::text,'S')||gc_authn.field('expires_at',expires_at::text,'T'); result:=gc_authn.install_existing(request_id,encoding); IF result.installation_id IS NOT NULL THEN RETURN result; END IF;
 PERFORM gc_authn.require_input(expires_at>clock_timestamp());
 SELECT * INTO registration FROM gc_authn.executor_registrations r WHERE r.id=registration_id AND r.kind='login' AND r.generation=provision_issuer.generation FOR SHARE;
 PERFORM gc_authn.require_auth(registration.id IS NOT NULL AND registration.revoked_at IS NULL AND registration.expires_at>clock_timestamp() AND gc_authn.role_safe(registration.role_oid,registration.role_name::text));
 result:=gc_authn.install_receipt(op,issuer_id,request_id,release_ref,operator_ref,predecessor_hash,encoding);
 INSERT INTO gc_authn.issuer_registrations(id,executor_registration_id,generation,issuer,client_id,redirect_uri,environment,installation_id,installed_at,expires_at) VALUES(issuer_id,registration_id,generation,issuer,client_id,redirect_uri,environment,result.installation_id,result.recorded_at,expires_at);
 RETURN result;
EXCEPTION WHEN unique_violation OR foreign_key_violation OR check_violation OR not_null_violation THEN RAISE EXCEPTION 'AUTHN_INSTALL_CONFLICT' USING ERRCODE='23505';
END $$;

CREATE FUNCTION gc_authn.bind_identity(request_id uuid, release_ref text, operator_ref text, expected_db_oid oid, expected_owner_oid oid, predecessor_hash text, binding_id uuid, issuer_id uuid, identity_id uuid, expected_issuer text, expected_subject text, expires_at timestamptz) RETURNS gc_authn.installation_result LANGUAGE plpgsql SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE op constant text:='bind-identity'; encoding text; result gc_authn.installation_result; head gc_authn.generation_heads; registration gc_authn.executor_registrations; issuer_row gc_authn.issuer_registrations; fence gc_authn.tenant_fences;
BEGIN
 PERFORM gc_authn.install_check(request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,predecessor_hash);
 PERFORM gc_authn.require_input(gc_authn.valid_uuid(binding_id) AND gc_authn.valid_uuid(issuer_id) AND gc_authn.valid_uuid(identity_id) AND gc_authn.valid_text(expected_issuer,2048) AND gc_authn.valid_text(expected_subject,1024) AND gc_authn.valid_time(expires_at));
 encoding:=gc_authn.install_encoding(op,request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,predecessor_hash)||gc_authn.field('binding_id',binding_id::text,'U')||gc_authn.field('issuer_id',issuer_id::text,'U')||gc_authn.field('identity_id',identity_id::text,'U')||gc_authn.field('expected_issuer',expected_issuer::text,'S')||gc_authn.field('expected_subject',expected_subject::text,'S')||gc_authn.field('expires_at',expires_at::text,'T'); result:=gc_authn.install_existing(request_id,encoding); IF result.installation_id IS NOT NULL THEN RETURN result; END IF;
 PERFORM gc_authn.require_input(expires_at>clock_timestamp());
 SELECT * INTO issuer_row FROM gc_authn.issuer_registrations i WHERE i.id=issuer_id FOR SHARE;
 PERFORM gc_authn.require_auth(issuer_row.id IS NOT NULL AND issuer_row.issuer=expected_issuer AND issuer_row.revoked_at IS NULL AND issuer_row.expires_at>clock_timestamp());
 PERFORM i.id FROM public.identities i WHERE i.id=identity_id AND i.issuer=expected_issuer AND i.subject=expected_subject FOR SHARE;
 PERFORM gc_authn.require_auth(FOUND);
 result:=gc_authn.install_receipt(op,binding_id,request_id,release_ref,operator_ref,predecessor_hash,encoding);
 INSERT INTO gc_authn.identity_bindings(id,issuer_registration_id,identity_id,subject,canonical_issuer,installation_id,installed_at,expires_at) VALUES(binding_id,issuer_id,identity_id,expected_subject,expected_issuer,result.installation_id,result.recorded_at,expires_at);
 RETURN result;
EXCEPTION WHEN unique_violation OR foreign_key_violation OR check_violation OR not_null_violation THEN RAISE EXCEPTION 'AUTHN_INSTALL_CONFLICT' USING ERRCODE='23505';
END $$;

CREATE FUNCTION gc_authn.initialize_tenant(request_id uuid, release_ref text, operator_ref text, expected_db_oid oid, expected_owner_oid oid, predecessor_hash text, tenant_id uuid, generation integer) RETURNS gc_authn.installation_result LANGUAGE plpgsql SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE op constant text:='initialize-tenant'; encoding text; result gc_authn.installation_result; head gc_authn.generation_heads; registration gc_authn.executor_registrations; issuer_row gc_authn.issuer_registrations; fence gc_authn.tenant_fences;
BEGIN
 PERFORM gc_authn.install_check(request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,predecessor_hash);
 PERFORM gc_authn.require_input(gc_authn.valid_uuid(tenant_id) AND generation>0);
 encoding:=gc_authn.install_encoding(op,request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,predecessor_hash)||gc_authn.field('tenant_id',tenant_id::text,'U')||gc_authn.field('generation',generation::text,'I'); result:=gc_authn.install_existing(request_id,encoding); IF result.installation_id IS NOT NULL THEN RETURN result; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant_id::text,0));
 PERFORM t.id FROM public.tenants t WHERE t.id=tenant_id FOR SHARE; PERFORM gc_authn.require_auth(FOUND);
 result:=gc_authn.install_receipt(op,tenant_id,request_id,release_ref,operator_ref,predecessor_hash,encoding);
 INSERT INTO gc_authn.tenant_fences VALUES(tenant_id,'inactive',generation,1,result.installation_id,result.recorded_at);
 RETURN result;
EXCEPTION WHEN unique_violation OR foreign_key_violation OR check_violation OR not_null_violation THEN RAISE EXCEPTION 'AUTHN_INSTALL_CONFLICT' USING ERRCODE='23505';
END $$;

CREATE FUNCTION gc_authn.advance_tenant_generation(request_id uuid, release_ref text, operator_ref text, expected_db_oid oid, expected_owner_oid oid, predecessor_hash text, tenant_id uuid, expected_generation integer, expected_epoch integer, generation integer) RETURNS gc_authn.installation_result LANGUAGE plpgsql SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE op constant text:='advance-tenant-generation'; encoding text; result gc_authn.installation_result; head gc_authn.generation_heads; registration gc_authn.executor_registrations; issuer_row gc_authn.issuer_registrations; fence gc_authn.tenant_fences;
BEGIN
 PERFORM gc_authn.install_check(request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,predecessor_hash);
 PERFORM gc_authn.require_input(gc_authn.valid_uuid(tenant_id) AND expected_generation>0 AND expected_epoch>0 AND expected_epoch<2147483647 AND generation>expected_generation);
 encoding:=gc_authn.install_encoding(op,request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,predecessor_hash)||gc_authn.field('tenant_id',tenant_id::text,'U')||gc_authn.field('expected_generation',expected_generation::text,'I')||gc_authn.field('expected_epoch',expected_epoch::text,'I')||gc_authn.field('generation',generation::text,'I'); result:=gc_authn.install_existing(request_id,encoding); IF result.installation_id IS NOT NULL THEN RETURN result; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant_id::text,0));
 PERFORM h.kind FROM gc_authn.generation_heads h WHERE h.generation=advance_tenant_generation.generation ORDER BY h.kind,h.channel_id FOR SHARE;
 PERFORM r.id FROM gc_authn.executor_registrations r JOIN gc_authn.generation_heads h ON h.executor_registration_id=r.id WHERE h.generation=advance_tenant_generation.generation ORDER BY r.id FOR SHARE OF r;
 PERFORM i.id FROM gc_authn.issuer_registrations i JOIN gc_authn.generation_heads h ON h.executor_registration_id=i.executor_registration_id WHERE h.generation=advance_tenant_generation.generation ORDER BY i.id FOR SHARE OF i;
 PERFORM gc_authn.require_auth(EXISTS(SELECT 1 FROM gc_authn.executor_registrations r JOIN gc_authn.generation_heads h ON h.executor_registration_id=r.id WHERE r.kind='api' AND h.generation=advance_tenant_generation.generation AND r.revoked_at IS NULL AND r.expires_at>clock_timestamp() AND gc_authn.role_safe(r.role_oid,r.role_name::text)) AND EXISTS(SELECT 1 FROM gc_authn.executor_registrations r JOIN gc_authn.generation_heads h ON h.executor_registration_id=r.id JOIN gc_authn.issuer_registrations i ON i.executor_registration_id=r.id WHERE r.kind='login' AND h.generation=advance_tenant_generation.generation AND r.revoked_at IS NULL AND r.expires_at>clock_timestamp() AND i.revoked_at IS NULL AND i.expires_at>clock_timestamp() AND gc_authn.role_safe(r.role_oid,r.role_name::text)));
 SELECT * INTO fence FROM gc_authn.tenant_fences f WHERE f.tenant_id=advance_tenant_generation.tenant_id FOR UPDATE;
 IF (fence.generation,fence.epoch) IS DISTINCT FROM (expected_generation,expected_epoch) THEN RAISE EXCEPTION 'AUTHN_INSTALL_CONFLICT' USING ERRCODE='23505'; END IF;
 result:=gc_authn.install_receipt(op,tenant_id,request_id,release_ref,operator_ref,predecessor_hash,encoding);
 UPDATE gc_authn.tenant_fences f SET generation=advance_tenant_generation.generation,epoch=expected_epoch+1,installation_id=result.installation_id WHERE f.tenant_id=advance_tenant_generation.tenant_id;
 RETURN result;
EXCEPTION WHEN unique_violation OR foreign_key_violation OR check_violation OR not_null_violation THEN RAISE EXCEPTION 'AUTHN_INSTALL_CONFLICT' USING ERRCODE='23505';
END $$;

CREATE FUNCTION gc_authn.revoke_executor(request_id uuid, release_ref text, operator_ref text, expected_db_oid oid, expected_owner_oid oid, predecessor_hash text, registration_id uuid) RETURNS gc_authn.installation_result LANGUAGE plpgsql SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE op constant text:='revoke-executor'; encoding text; result gc_authn.installation_result; existing gc_authn.executor_registrations; registration uuid; issuer_ref uuid;
BEGIN
 PERFORM gc_authn.install_check(request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,predecessor_hash);
 PERFORM gc_authn.require_input(gc_authn.valid_uuid(registration_id));
 encoding:=gc_authn.install_encoding(op,request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,predecessor_hash)||gc_authn.field('registration_id',registration_id::text,'U');
 result:=gc_authn.install_existing(request_id,encoding); IF result.installation_id IS NOT NULL THEN RETURN result; END IF;
 SELECT * INTO existing FROM gc_authn.executor_registrations WHERE id=registration_id;
 PERFORM gc_authn.require_auth(existing.id IS NOT NULL AND existing.revoked_at IS NULL);
 registration:=existing.id;
 PERFORM h.kind FROM gc_authn.generation_heads h WHERE h.executor_registration_id=registration ORDER BY h.kind,h.channel_id FOR SHARE;
 PERFORM r.id FROM gc_authn.executor_registrations r WHERE r.id=registration FOR UPDATE;
  SELECT * INTO existing FROM gc_authn.executor_registrations WHERE id=registration_id;
 PERFORM gc_authn.require_auth(existing.revoked_at IS NULL);
 result:=gc_authn.install_receipt(op,registration_id,request_id,release_ref,operator_ref,predecessor_hash,encoding);
 UPDATE gc_authn.executor_registrations SET revoked_at=result.recorded_at WHERE id=registration_id;
 INSERT INTO gc_authn.registration_revocations(installation_id,target_kind,target_id,revoked_at,executor_registration_id) VALUES(result.installation_id,'executor',registration_id,result.recorded_at,registration_id);
 RETURN result;
EXCEPTION WHEN unique_violation OR foreign_key_violation OR check_violation OR not_null_violation THEN RAISE EXCEPTION 'AUTHN_INSTALL_CONFLICT' USING ERRCODE='23505';
END $$;

CREATE FUNCTION gc_authn.revoke_issuer(request_id uuid, release_ref text, operator_ref text, expected_db_oid oid, expected_owner_oid oid, predecessor_hash text, issuer_id uuid) RETURNS gc_authn.installation_result LANGUAGE plpgsql SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE op constant text:='revoke-issuer'; encoding text; result gc_authn.installation_result; existing gc_authn.issuer_registrations; registration uuid; issuer_ref uuid;
BEGIN
 PERFORM gc_authn.install_check(request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,predecessor_hash);
 PERFORM gc_authn.require_input(gc_authn.valid_uuid(issuer_id));
 encoding:=gc_authn.install_encoding(op,request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,predecessor_hash)||gc_authn.field('issuer_id',issuer_id::text,'U');
 result:=gc_authn.install_existing(request_id,encoding); IF result.installation_id IS NOT NULL THEN RETURN result; END IF;
 SELECT * INTO existing FROM gc_authn.issuer_registrations WHERE id=issuer_id;
 PERFORM gc_authn.require_auth(existing.id IS NOT NULL AND existing.revoked_at IS NULL);
 registration:=existing.executor_registration_id; issuer_ref:=existing.id;
 PERFORM h.kind FROM gc_authn.generation_heads h WHERE h.executor_registration_id=registration ORDER BY h.kind,h.channel_id FOR SHARE;
 PERFORM r.id FROM gc_authn.executor_registrations r WHERE r.id=registration FOR SHARE;
 PERFORM i.id FROM gc_authn.issuer_registrations i WHERE i.id=issuer_ref FOR UPDATE;
 SELECT * INTO existing FROM gc_authn.issuer_registrations WHERE id=issuer_id;
 PERFORM gc_authn.require_auth(existing.revoked_at IS NULL);
 result:=gc_authn.install_receipt(op,issuer_id,request_id,release_ref,operator_ref,predecessor_hash,encoding);
 UPDATE gc_authn.issuer_registrations SET revoked_at=result.recorded_at WHERE id=issuer_id;
 INSERT INTO gc_authn.registration_revocations(installation_id,target_kind,target_id,revoked_at,issuer_registration_id) VALUES(result.installation_id,'issuer',issuer_id,result.recorded_at,issuer_id);
 RETURN result;
EXCEPTION WHEN unique_violation OR foreign_key_violation OR check_violation OR not_null_violation THEN RAISE EXCEPTION 'AUTHN_INSTALL_CONFLICT' USING ERRCODE='23505';
END $$;

CREATE FUNCTION gc_authn.revoke_binding(request_id uuid, release_ref text, operator_ref text, expected_db_oid oid, expected_owner_oid oid, predecessor_hash text, binding_id uuid) RETURNS gc_authn.installation_result LANGUAGE plpgsql SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE op constant text:='revoke-binding'; encoding text; result gc_authn.installation_result; existing gc_authn.identity_bindings; registration uuid; issuer_ref uuid;
BEGIN
 PERFORM gc_authn.install_check(request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,predecessor_hash);
 PERFORM gc_authn.require_input(gc_authn.valid_uuid(binding_id));
 encoding:=gc_authn.install_encoding(op,request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,predecessor_hash)||gc_authn.field('binding_id',binding_id::text,'U');
 result:=gc_authn.install_existing(request_id,encoding); IF result.installation_id IS NOT NULL THEN RETURN result; END IF;
 SELECT * INTO existing FROM gc_authn.identity_bindings WHERE id=binding_id;
 PERFORM gc_authn.require_auth(existing.id IS NOT NULL AND existing.revoked_at IS NULL);
 issuer_ref:=existing.issuer_registration_id; SELECT executor_registration_id INTO registration FROM gc_authn.issuer_registrations WHERE id=issuer_ref;
 PERFORM h.kind FROM gc_authn.generation_heads h WHERE h.executor_registration_id=registration ORDER BY h.kind,h.channel_id FOR SHARE;
 PERFORM r.id FROM gc_authn.executor_registrations r WHERE r.id=registration FOR SHARE;
 PERFORM i.id FROM gc_authn.issuer_registrations i WHERE i.id=issuer_ref FOR SHARE;
PERFORM b.id FROM gc_authn.identity_bindings b WHERE b.id=binding_id FOR UPDATE;
 SELECT * INTO existing FROM gc_authn.identity_bindings WHERE id=binding_id;
 PERFORM gc_authn.require_auth(existing.revoked_at IS NULL);
 result:=gc_authn.install_receipt(op,binding_id,request_id,release_ref,operator_ref,predecessor_hash,encoding);
 UPDATE gc_authn.identity_bindings SET revoked_at=result.recorded_at WHERE id=binding_id;
 INSERT INTO gc_authn.registration_revocations(installation_id,target_kind,target_id,revoked_at,identity_binding_id) VALUES(result.installation_id,'binding',binding_id,result.recorded_at,binding_id);
 RETURN result;
EXCEPTION WHEN unique_violation OR foreign_key_violation OR check_violation OR not_null_violation THEN RAISE EXCEPTION 'AUTHN_INSTALL_CONFLICT' USING ERRCODE='23505';
END $$;
CREATE FUNCTION gc_authn.live_issuer(registration uuid) RETURNS gc_authn.issuer_registrations LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog,gc_authn,pg_temp AS $$
DECLARE r gc_authn.issuer_registrations;
BEGIN SELECT * INTO r FROM gc_authn.issuer_registrations i WHERE i.executor_registration_id=registration; PERFORM gc_authn.require_auth(r.id IS NOT NULL AND r.revoked_at IS NULL AND r.expires_at>clock_timestamp()); RETURN r; END $$;
-- Point-in-time collision guard only: this does not couple detached session provenance to legacy rows.
CREATE FUNCTION gc_authn.legacy_session_hash_exists(session_hash text) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
BEGIN
 PERFORM gc_authn.require_input(gc_authn.valid_digest(session_hash));
 RETURN EXISTS(SELECT 1 FROM public.sessions s WHERE s.id_hash=legacy_session_hash_exists.session_hash);
END $$;
CREATE FUNCTION gc_authn.checked_session(session_hash text,allow_dead boolean DEFAULT false) RETURNS gc_authn.sessions LANGUAGE plpgsql SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE a gc_authn.executor_registrations; r gc_authn.executor_registrations; i gc_authn.issuer_registrations; b gc_authn.identity_bindings; p gc_authn.session_provenance; s gc_authn.sessions; old_actor text:=current_setting('gc.actor_id',true); old_tenant text:=current_setting('gc.tenant_id',true);
BEGIN
 a:=gc_authn.executor('api');
 SELECT * INTO s FROM gc_authn.sessions x WHERE x.session_hash=checked_session.session_hash;
 PERFORM gc_authn.require_auth(s.id IS NOT NULL AND s.revoked_at IS NULL AND s.generation=a.generation);
 PERFORM gc_authn.validate_session(s.id);
 SELECT * INTO p FROM gc_authn.session_provenance WHERE session_id=s.id;
 r:=gc_authn.current_registration(p.issuing_executor_registration_id,'login');
 i:=gc_authn.live_issuer(r.id);
 SELECT * INTO b FROM gc_authn.identity_bindings WHERE id=p.identity_binding_id;
 PERFORM gc_authn.require_auth((r.generation,i.id,b.issuer_registration_id,b.identity_id) IS NOT DISTINCT FROM (s.generation,p.issuer_registration_id,i.id,s.identity_id));
 PERFORM set_config('gc.actor_id',s.identity_id::text,true);PERFORM set_config('gc.tenant_id',s.selected_tenant_id::text,true);
 PERFORM gc_authn.require_auth(EXISTS(SELECT 1 FROM public.identities x WHERE x.id=s.identity_id AND x.issuer=b.canonical_issuer AND x.subject=b.subject AND (allow_dead OR x.active)));
 IF NOT allow_dead THEN
  PERFORM gc_authn.require_auth(s.expires_at>clock_timestamp() AND b.revoked_at IS NULL AND b.expires_at>clock_timestamp()
   AND EXISTS(SELECT 1 FROM public.memberships m WHERE m.tenant_id=s.selected_tenant_id AND m.identity_id=s.identity_id AND m.active)
   AND EXISTS(SELECT 1 FROM gc_authn.tenant_fences f WHERE f.tenant_id=s.selected_tenant_id AND f.generation=s.generation AND f.mode='inactive'));
 END IF;
 PERFORM set_config('gc.actor_id',coalesce(old_actor,''),true);PERFORM set_config('gc.tenant_id',coalesce(old_tenant,''),true);RETURN s;
EXCEPTION WHEN OTHERS THEN PERFORM set_config('gc.actor_id',coalesce(old_actor,''),true);PERFORM set_config('gc.tenant_id',coalesce(old_tenant,''),true);RAISE;
END $$;
CREATE FUNCTION public.gc_authn_attempt_begin(state_hash text,verifier text,nonce_hash text) RETURNS public.gc_authn_attempt_started LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE r gc_authn.executor_registrations; i gc_authn.issuer_registrations; now_at timestamptz; new_id uuid;
BEGIN
 PERFORM gc_authn.require_mutation();PERFORM gc_authn.require_input(gc_authn.valid_digest(state_hash) AND gc_authn.valid_digest(nonce_hash) AND verifier IS NOT NULL AND octet_length(verifier) BETWEEN 43 AND 128 AND verifier ~ '^[A-Za-z0-9._~-]+$');
 r:=gc_authn.executor('login');i:=gc_authn.live_issuer(r.id);
 PERFORM gc_authn.lock_configuration(r.id,r.id,i.id,NULL,ARRAY[]::uuid[]);
 r:=gc_authn.executor('login');i:=gc_authn.live_issuer(r.id);now_at:=date_trunc('milliseconds',clock_timestamp());new_id:=gen_random_uuid();
 INSERT INTO gc_authn.login_attempts VALUES(new_id,state_hash,nonce_hash,i.id,r.id,r.generation,verifier,now_at,now_at+interval '300 seconds');
 RETURN (1,new_id,now_at+interval '300 seconds')::public.gc_authn_attempt_started;
EXCEPTION WHEN SQLSTATE '22023' THEN RAISE EXCEPTION 'AUTHN_INPUT_INVALID' USING ERRCODE='22023'; WHEN SQLSTATE '42501' THEN RAISE EXCEPTION 'AUTHN_EXECUTOR_REJECTED' USING ERRCODE='42501'; WHEN OTHERS THEN RAISE EXCEPTION 'AUTHN_REJECTED' USING ERRCODE='28000'; END $$;
CREATE FUNCTION public.gc_authn_attempt_consume(attempt_id uuid,state_hash text) RETURNS public.gc_authn_attempt_exchange LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE r gc_authn.executor_registrations; i gc_authn.issuer_registrations; a gc_authn.login_attempts; now_at timestamptz;
BEGIN
 PERFORM gc_authn.require_mutation();PERFORM gc_authn.require_input(gc_authn.valid_uuid(attempt_id) AND gc_authn.valid_digest(state_hash));r:=gc_authn.executor('login');i:=gc_authn.live_issuer(r.id);
 PERFORM gc_authn.lock_configuration(r.id,r.id,i.id,NULL,ARRAY[]::uuid[]);
 SELECT * INTO a FROM gc_authn.login_attempts x WHERE x.id=attempt_id FOR UPDATE;
 r:=gc_authn.executor('login');i:=gc_authn.live_issuer(r.id);
 PERFORM gc_authn.require_auth(a.id IS NOT NULL AND (a.executor_registration_id,a.issuer_registration_id,a.generation,a.state_hash) IS NOT DISTINCT FROM (r.id,i.id,r.generation,state_hash) AND a.verifier IS NOT NULL AND a.expires_at>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM gc_authn.attempt_consumptions c WHERE c.attempt_id=a.id));
 now_at:=date_trunc('milliseconds',clock_timestamp());
 INSERT INTO gc_authn.attempt_consumptions VALUES(a.id,r.id,r.generation,now_at,pg_current_xact_id(),least(a.expires_at,now_at+interval '60 seconds'));
 UPDATE gc_authn.login_attempts x SET verifier=NULL WHERE x.id=a.id;
 RETURN (1,a.id,a.verifier,i.id,i.issuer,i.client_id,i.redirect_uri,a.nonce_hash,a.expires_at)::public.gc_authn_attempt_exchange;
EXCEPTION WHEN SQLSTATE '22023' THEN RAISE EXCEPTION 'AUTHN_INPUT_INVALID' USING ERRCODE='22023'; WHEN SQLSTATE '42501' THEN RAISE EXCEPTION 'AUTHN_EXECUTOR_REJECTED' USING ERRCODE='42501'; WHEN OTHERS THEN RAISE EXCEPTION 'AUTHN_REJECTED' USING ERRCODE='28000'; END $$;
CREATE FUNCTION public.gc_authn_session_issue(attempt_id uuid,issuer text,subject text,audience text,nonce_hash text,id_token_hash text,authenticated_at timestamptz,token_issued_at timestamptz,token_expires_at timestamptz,session_hash text,csrf_hash text) RETURNS public.gc_authn_session_issued LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE r gc_authn.executor_registrations; i gc_authn.issuer_registrations; b gc_authn.identity_bindings; a gc_authn.login_attempts; c gc_authn.attempt_consumptions; t uuid; selected_tenant uuid; s_id uuid; now_at timestamptz; expiry timestamptz; old_actor text:=current_setting('gc.actor_id',true);old_tenant text:=current_setting('gc.tenant_id',true);
BEGIN
 PERFORM gc_authn.require_mutation();PERFORM gc_authn.require_input(gc_authn.valid_uuid(attempt_id) AND gc_authn.valid_text(issuer,2048) AND gc_authn.valid_text(subject,1024) AND gc_authn.valid_text(audience,256) AND gc_authn.valid_digest(nonce_hash) AND gc_authn.valid_digest(id_token_hash) AND gc_authn.valid_digest(session_hash) AND gc_authn.valid_digest(csrf_hash) AND gc_authn.valid_time(authenticated_at) AND gc_authn.valid_time(token_issued_at) AND gc_authn.valid_time(token_expires_at));
 r:=gc_authn.executor('login');i:=gc_authn.live_issuer(r.id);
 SELECT * INTO a FROM gc_authn.login_attempts x WHERE x.id=attempt_id;
 SELECT * INTO b FROM gc_authn.identity_bindings x WHERE x.issuer_registration_id=i.id AND x.subject=gc_authn_session_issue.subject;
 PERFORM gc_authn.require_auth(a.id IS NOT NULL AND b.id IS NOT NULL AND (a.executor_registration_id,a.issuer_registration_id,a.generation) IS NOT DISTINCT FROM (r.id,i.id,r.generation));
 PERFORM set_config('gc.actor_id',b.identity_id::text,true);PERFORM set_config('gc.tenant_id','',true);
 -- Stream the complete ordered membership selection; never authorize a first-N prefix.
 FOR t IN SELECT m.tenant_id FROM public.memberships m WHERE m.identity_id=b.identity_id AND m.active ORDER BY m.tenant_id LOOP
  PERFORM set_config('gc.tenant_id',t::text,true);
  IF EXISTS(SELECT 1 FROM gc_authn.tenant_fences f WHERE f.tenant_id=t AND f.mode='inactive' AND f.generation=r.generation) THEN selected_tenant:=t;EXIT; END IF;
 END LOOP;
 PERFORM gc_authn.require_auth(selected_tenant IS NOT NULL);
 PERFORM gc_authn.lock_configuration(r.id,r.id,i.id,b.id,ARRAY[selected_tenant]);
 PERFORM gc_authn.lock_principals(b.identity_id,ARRAY[selected_tenant]);
 SELECT * INTO a FROM gc_authn.login_attempts x WHERE x.id=attempt_id FOR UPDATE;
 -- Consumption is immutable; the locked attempt serializes issue attempts.
 SELECT * INTO c FROM gc_authn.attempt_consumptions x WHERE x.attempt_id=gc_authn_session_issue.attempt_id;
 r:=gc_authn.executor('login');i:=gc_authn.live_issuer(r.id);
 SELECT * INTO b FROM gc_authn.identity_bindings x WHERE x.id=b.id;
 PERFORM set_config('gc.actor_id',b.identity_id::text,true);PERFORM set_config('gc.tenant_id',selected_tenant::text,true);
 PERFORM gc_authn.require_auth(c.attempt_id IS NOT NULL AND c.consumed_transaction_id<>pg_current_xact_id() AND c.issue_deadline_at>clock_timestamp() AND a.expires_at>clock_timestamp() AND a.verifier IS NULL
 AND (a.executor_registration_id,a.issuer_registration_id,a.generation,a.nonce_hash,i.issuer,i.client_id,b.subject,b.canonical_issuer) IS NOT DISTINCT FROM (r.id,i.id,r.generation,nonce_hash,issuer,audience,subject,issuer)
 AND b.revoked_at IS NULL AND b.expires_at>clock_timestamp() AND authenticated_at<=token_issued_at AND token_issued_at<=clock_timestamp() AND token_issued_at>=a.created_at-interval '30 seconds' AND token_expires_at>clock_timestamp() AND token_expires_at>token_issued_at
 AND EXISTS(SELECT 1 FROM public.identities x WHERE x.id=b.identity_id AND x.issuer=b.canonical_issuer AND x.subject=b.subject AND x.active)
 AND EXISTS(SELECT 1 FROM public.memberships m WHERE m.tenant_id=selected_tenant AND m.identity_id=b.identity_id AND m.active)
 AND EXISTS(SELECT 1 FROM gc_authn.tenant_fences f WHERE f.tenant_id=selected_tenant AND f.generation=r.generation AND f.mode='inactive')
 AND NOT EXISTS(SELECT 1 FROM gc_authn.session_provenance p WHERE p.attempt_id=a.id));
 PERFORM gc_authn.require_auth(NOT gc_authn.legacy_session_hash_exists(session_hash));
 now_at:=date_trunc('milliseconds',clock_timestamp());expiry:=least(now_at+interval '1800 seconds',r.expires_at,i.expires_at,b.expires_at);s_id:=gen_random_uuid();PERFORM gc_authn.require_auth(expiry>clock_timestamp());
 INSERT INTO gc_authn.sessions VALUES(s_id,session_hash,b.identity_id,selected_tenant,csrf_hash,1,r.generation,now_at,authenticated_at,expiry,NULL);
 INSERT INTO gc_authn.session_provenance VALUES(s_id,a.id,b.id,i.id,r.id,r.role_oid,r.generation,selected_tenant,b.identity_id,1,csrf_hash,session_hash,authenticated_at,token_issued_at,token_expires_at,id_token_hash,now_at,expiry);
 INSERT INTO gc_authn.session_events VALUES(s_id,1,'issued',b.identity_id,NULL,selected_tenant,csrf_hash,now_at,r.id,r.role_oid,r.generation);
 PERFORM gc_authn.validate_session(s_id);
 PERFORM gc_authn.require_auth(expiry>clock_timestamp() AND c.issue_deadline_at>clock_timestamp() AND token_expires_at>clock_timestamp());
 PERFORM set_config('gc.actor_id',coalesce(old_actor,''),true);PERFORM set_config('gc.tenant_id',coalesce(old_tenant,''),true);
 RETURN (1,s_id,1,selected_tenant,expiry)::public.gc_authn_session_issued;
EXCEPTION WHEN OTHERS THEN
 PERFORM set_config('gc.actor_id',coalesce(old_actor,''),true);PERFORM set_config('gc.tenant_id',coalesce(old_tenant,''),true);
 IF SQLSTATE='22023' THEN RAISE EXCEPTION 'AUTHN_INPUT_INVALID' USING ERRCODE='22023'; ELSIF SQLSTATE='42501' THEN RAISE EXCEPTION 'AUTHN_EXECUTOR_REJECTED' USING ERRCODE='42501'; ELSE RAISE EXCEPTION 'AUTHN_REJECTED' USING ERRCODE='28000'; END IF;
END $$;
CREATE FUNCTION public.gc_authn_session_inspect(session_hash text) RETURNS public.gc_authn_authenticated_session LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE s gc_authn.sessions; p gc_authn.session_provenance; epoch integer;old_actor text:=current_setting('gc.actor_id',true);old_tenant text:=current_setting('gc.tenant_id',true);
BEGIN
 PERFORM gc_authn.require_auth(current_setting('transaction_isolation')='repeatable read' AND current_setting('transaction_read_only')='on');
 PERFORM gc_authn.require_input(gc_authn.valid_digest(session_hash));s:=gc_authn.checked_session(session_hash);
 SELECT * INTO p FROM gc_authn.session_provenance WHERE session_id=s.id;
 PERFORM set_config('gc.actor_id',s.identity_id::text,true);PERFORM set_config('gc.tenant_id',s.selected_tenant_id::text,true);
 SELECT f.epoch INTO epoch FROM gc_authn.tenant_fences f WHERE f.tenant_id=s.selected_tenant_id AND f.generation=s.generation AND f.mode='inactive';
 PERFORM gc_authn.require_auth(epoch IS NOT NULL AND s.expires_at>clock_timestamp());
 PERFORM set_config('gc.actor_id',coalesce(old_actor,''),true);PERFORM set_config('gc.tenant_id',coalesce(old_tenant,''),true);
 RETURN (1,s.id,s.version,s.identity_id,s.selected_tenant_id,p.issuer_registration_id,p.identity_binding_id,s.authenticated_at,s.expires_at,s.generation,epoch,'inactive',false)::public.gc_authn_authenticated_session;
EXCEPTION WHEN OTHERS THEN
 PERFORM set_config('gc.actor_id',coalesce(old_actor,''),true);PERFORM set_config('gc.tenant_id',coalesce(old_tenant,''),true);
 IF SQLSTATE='22023' THEN RAISE EXCEPTION 'AUTHN_INPUT_INVALID' USING ERRCODE='22023'; ELSIF SQLSTATE='42501' THEN RAISE EXCEPTION 'AUTHN_EXECUTOR_REJECTED' USING ERRCODE='42501'; ELSE RAISE EXCEPTION 'AUTHN_REJECTED' USING ERRCODE='28000'; END IF;
END $$;
CREATE FUNCTION public.gc_authn_session_revoke(session_hash text,csrf_hash text,expected_session_version integer) RETURNS public.gc_authn_session_revoked LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE s gc_authn.sessions;r gc_authn.executor_registrations;now_at timestamptz;
BEGIN
 PERFORM gc_authn.require_mutation();PERFORM gc_authn.require_input(gc_authn.valid_digest(session_hash) AND gc_authn.valid_digest(csrf_hash) AND expected_session_version>0);
 s:=gc_authn.checked_session(session_hash,true);
 PERFORM x.id FROM gc_authn.sessions x WHERE x.id=s.id FOR UPDATE;
 s:=gc_authn.checked_session(session_hash,true);r:=gc_authn.executor('api');
 PERFORM gc_authn.require_auth(s.csrf_hash=csrf_hash);
 IF s.version<>expected_session_version OR s.version=2147483647 THEN RAISE EXCEPTION 'AUTHN_VERSION_CONFLICT' USING ERRCODE='40001'; END IF;
 now_at:=date_trunc('milliseconds',clock_timestamp());
 UPDATE gc_authn.sessions x SET revoked_at=now_at,version=s.version+1 WHERE x.id=s.id;
 INSERT INTO gc_authn.session_events VALUES(s.id,s.version+1,'revoked',s.identity_id,s.selected_tenant_id,s.selected_tenant_id,s.csrf_hash,now_at,r.id,r.role_oid,r.generation);
 PERFORM gc_authn.validate_session(s.id);
 RETURN (1,s.id,s.version+1,true)::public.gc_authn_session_revoked;
EXCEPTION WHEN SQLSTATE '22023' THEN RAISE EXCEPTION 'AUTHN_INPUT_INVALID' USING ERRCODE='22023'; WHEN SQLSTATE '42501' THEN RAISE EXCEPTION 'AUTHN_EXECUTOR_REJECTED' USING ERRCODE='42501'; WHEN SQLSTATE '40001' THEN RAISE EXCEPTION 'AUTHN_VERSION_CONFLICT' USING ERRCODE='40001'; WHEN OTHERS THEN RAISE EXCEPTION 'AUTHN_REJECTED' USING ERRCODE='28000'; END $$;
CREATE FUNCTION public.gc_authn_session_select(session_hash text,csrf_hash text,expected_session_version integer,tenant_id uuid,replacement_csrf_hash text) RETURNS public.gc_authn_session_selected LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,gc_authn,pg_temp SET row_security=on AS $$
DECLARE s gc_authn.sessions; p gc_authn.session_provenance;r gc_authn.executor_registrations;tenants uuid[];epoch integer;now_at timestamptz;old_actor text:=current_setting('gc.actor_id',true);old_tenant text:=current_setting('gc.tenant_id',true);
BEGIN
 PERFORM gc_authn.require_mutation();PERFORM gc_authn.require_input(gc_authn.valid_digest(session_hash) AND gc_authn.valid_digest(csrf_hash) AND gc_authn.valid_digest(replacement_csrf_hash) AND expected_session_version>0 AND gc_authn.valid_uuid(tenant_id));
 s:=gc_authn.checked_session(session_hash);
 PERFORM gc_authn.require_auth(s.csrf_hash=csrf_hash AND replacement_csrf_hash<>s.csrf_hash);
 IF s.version<>expected_session_version OR s.version=2147483647 THEN RAISE EXCEPTION 'AUTHN_VERSION_CONFLICT' USING ERRCODE='40001'; END IF;
 r:=gc_authn.executor('api');SELECT * INTO p FROM gc_authn.session_provenance WHERE session_id=s.id;
 PERFORM set_config('gc.actor_id',s.identity_id::text,true);PERFORM set_config('gc.tenant_id',tenant_id::text,true);
 PERFORM gc_authn.require_auth(EXISTS(SELECT 1 FROM public.memberships m WHERE m.tenant_id=gc_authn_session_select.tenant_id AND m.identity_id=s.identity_id AND m.active));
 SELECT array_agg(DISTINCT v ORDER BY v) INTO tenants FROM unnest(ARRAY[s.selected_tenant_id,tenant_id]) v;
 PERFORM gc_authn.lock_configuration(r.id,p.issuing_executor_registration_id,p.issuer_registration_id,p.identity_binding_id,tenants);
 PERFORM gc_authn.lock_principals(s.identity_id,tenants);
 PERFORM x.id FROM gc_authn.sessions x WHERE x.id=s.id FOR UPDATE;
 s:=gc_authn.checked_session(session_hash);r:=gc_authn.executor('api');
 PERFORM gc_authn.require_auth(s.csrf_hash=csrf_hash AND replacement_csrf_hash<>s.csrf_hash);
 IF s.version<>expected_session_version OR s.version=2147483647 THEN RAISE EXCEPTION 'AUTHN_VERSION_CONFLICT' USING ERRCODE='40001'; END IF;
 PERFORM set_config('gc.actor_id',s.identity_id::text,true);PERFORM set_config('gc.tenant_id',tenant_id::text,true);
 SELECT f.epoch INTO epoch FROM gc_authn.tenant_fences f WHERE f.tenant_id=gc_authn_session_select.tenant_id AND f.generation=s.generation AND f.mode='inactive';
 PERFORM gc_authn.require_auth(epoch IS NOT NULL AND EXISTS(SELECT 1 FROM public.memberships m WHERE m.tenant_id=gc_authn_session_select.tenant_id AND m.identity_id=s.identity_id AND m.active) AND s.expires_at>clock_timestamp());
 now_at:=date_trunc('milliseconds',clock_timestamp());
 UPDATE gc_authn.sessions x SET selected_tenant_id=tenant_id,csrf_hash=replacement_csrf_hash,version=s.version+1 WHERE x.id=s.id;
 INSERT INTO gc_authn.session_events VALUES(s.id,s.version+1,'tenant-selected',s.identity_id,s.selected_tenant_id,tenant_id,replacement_csrf_hash,now_at,r.id,r.role_oid,r.generation);
 PERFORM gc_authn.validate_session(s.id);
 PERFORM gc_authn.require_auth(s.expires_at>clock_timestamp());
 PERFORM set_config('gc.actor_id',coalesce(old_actor,''),true);PERFORM set_config('gc.tenant_id',coalesce(old_tenant,''),true);
 RETURN (1,s.id,s.version+1,tenant_id,epoch,'inactive')::public.gc_authn_session_selected;
EXCEPTION WHEN OTHERS THEN
 PERFORM set_config('gc.actor_id',coalesce(old_actor,''),true);PERFORM set_config('gc.tenant_id',coalesce(old_tenant,''),true);
 IF SQLSTATE='22023' THEN RAISE EXCEPTION 'AUTHN_INPUT_INVALID' USING ERRCODE='22023'; ELSIF SQLSTATE='42501' THEN RAISE EXCEPTION 'AUTHN_EXECUTOR_REJECTED' USING ERRCODE='42501'; ELSIF SQLSTATE='40001' THEN RAISE EXCEPTION 'AUTHN_VERSION_CONFLICT' USING ERRCODE='40001'; ELSE RAISE EXCEPTION 'AUTHN_REJECTED' USING ERRCODE='28000'; END IF;
END $$;

-- Literal immutable and deferred invariant guards. No writable context GUC is authority.
CREATE TRIGGER authn_no_delete BEFORE DELETE ON gc_authn.installation_root FOR EACH ROW EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER authn_update_guard BEFORE UPDATE ON gc_authn.installation_root FOR EACH ROW EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER authn_no_delete BEFORE DELETE ON gc_authn.installation_receipts FOR EACH ROW EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER authn_update_guard BEFORE UPDATE ON gc_authn.installation_receipts FOR EACH ROW EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER authn_no_delete BEFORE DELETE ON gc_authn.executor_registrations FOR EACH ROW EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER authn_update_guard BEFORE UPDATE ON gc_authn.executor_registrations FOR EACH ROW EXECUTE FUNCTION gc_authn.registration_update();
CREATE TRIGGER authn_no_delete BEFORE DELETE ON gc_authn.generation_heads FOR EACH ROW EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER authn_update_guard BEFORE UPDATE ON gc_authn.generation_heads FOR EACH ROW EXECUTE FUNCTION gc_authn.head_update();
CREATE TRIGGER authn_no_delete BEFORE DELETE ON gc_authn.issuer_registrations FOR EACH ROW EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER authn_update_guard BEFORE UPDATE ON gc_authn.issuer_registrations FOR EACH ROW EXECUTE FUNCTION gc_authn.registration_update();
CREATE TRIGGER authn_no_delete BEFORE DELETE ON gc_authn.identity_bindings FOR EACH ROW EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER authn_update_guard BEFORE UPDATE ON gc_authn.identity_bindings FOR EACH ROW EXECUTE FUNCTION gc_authn.registration_update();
CREATE TRIGGER authn_no_delete BEFORE DELETE ON gc_authn.login_attempts FOR EACH ROW EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER authn_update_guard BEFORE UPDATE ON gc_authn.login_attempts FOR EACH ROW EXECUTE FUNCTION gc_authn.attempt_update();
CREATE TRIGGER authn_no_delete BEFORE DELETE ON gc_authn.attempt_consumptions FOR EACH ROW EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER authn_update_guard BEFORE UPDATE ON gc_authn.attempt_consumptions FOR EACH ROW EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER authn_no_delete BEFORE DELETE ON gc_authn.sessions FOR EACH ROW EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER authn_update_guard BEFORE UPDATE ON gc_authn.sessions FOR EACH ROW EXECUTE FUNCTION gc_authn.session_update();
CREATE TRIGGER authn_no_delete BEFORE DELETE ON gc_authn.session_provenance FOR EACH ROW EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER authn_update_guard BEFORE UPDATE ON gc_authn.session_provenance FOR EACH ROW EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER authn_no_delete BEFORE DELETE ON gc_authn.session_events FOR EACH ROW EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER authn_update_guard BEFORE UPDATE ON gc_authn.session_events FOR EACH ROW EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER authn_no_delete BEFORE DELETE ON gc_authn.registration_revocations FOR EACH ROW EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER authn_update_guard BEFORE UPDATE ON gc_authn.registration_revocations FOR EACH ROW EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER authn_no_delete BEFORE DELETE ON gc_authn.tenant_fences FOR EACH ROW EXECUTE FUNCTION gc_authn.immutable();
CREATE TRIGGER authn_update_guard BEFORE UPDATE ON gc_authn.tenant_fences FOR EACH ROW EXECUTE FUNCTION gc_authn.fence_update();
CREATE CONSTRAINT TRIGGER authn_install_complete AFTER INSERT OR UPDATE ON gc_authn.installation_receipts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gc_authn.install_consistent();
CREATE CONSTRAINT TRIGGER authn_install_complete AFTER INSERT OR UPDATE ON gc_authn.executor_registrations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gc_authn.install_consistent();
CREATE CONSTRAINT TRIGGER authn_install_complete AFTER INSERT OR UPDATE ON gc_authn.generation_heads DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gc_authn.install_consistent();
CREATE CONSTRAINT TRIGGER authn_install_complete AFTER INSERT OR UPDATE ON gc_authn.issuer_registrations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gc_authn.install_consistent();
CREATE CONSTRAINT TRIGGER authn_install_complete AFTER INSERT OR UPDATE ON gc_authn.identity_bindings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gc_authn.install_consistent();
CREATE CONSTRAINT TRIGGER authn_install_complete AFTER INSERT OR UPDATE ON gc_authn.registration_revocations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gc_authn.install_consistent();
CREATE CONSTRAINT TRIGGER authn_install_complete AFTER INSERT OR UPDATE ON gc_authn.tenant_fences DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gc_authn.install_consistent();
CREATE CONSTRAINT TRIGGER authn_attempt_complete AFTER INSERT OR UPDATE ON gc_authn.login_attempts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gc_authn.attempt_consistent();
CREATE CONSTRAINT TRIGGER authn_attempt_complete AFTER INSERT OR UPDATE ON gc_authn.attempt_consumptions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gc_authn.attempt_consistent();
CREATE CONSTRAINT TRIGGER authn_session_complete AFTER INSERT OR UPDATE ON gc_authn.sessions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gc_authn.session_consistent();
CREATE CONSTRAINT TRIGGER authn_session_complete AFTER INSERT OR UPDATE ON gc_authn.session_provenance DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gc_authn.session_consistent();
CREATE CONSTRAINT TRIGGER authn_session_complete AFTER INSERT OR UPDATE ON gc_authn.session_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gc_authn.session_consistent();

-- Preserve the exact historical effective gc_app privileges while closing PUBLIC paths.
REVOKE ALL ON FUNCTION public.gc_actor() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_actor() TO gc_app;
REVOKE ALL ON FUNCTION public.gc_asset_type_constraints() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_asset_type_constraints() TO gc_app;
REVOKE ALL ON FUNCTION public.gc_immutable_audit() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_immutable_audit() TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_acl_projection_guard() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_acl_projection_guard() TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_asset_tuple(assets) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_asset_tuple(assets) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_attribute_transform(jsonb,jsonb,jsonb,jsonb,jsonb,boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_attribute_transform(jsonb,jsonb,jsonb,jsonb,jsonb,boolean) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_authorize(text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_authorize(text[]) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_binding_snapshot(relation_participations) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_binding_snapshot(relation_participations) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_decimal(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_decimal(text) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_definition_valid(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_definition_valid(jsonb) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_endpoint_eligible(uuid,uuid,jsonb,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_endpoint_eligible(uuid,uuid,jsonb,text) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_endpoint_projection_guard() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_endpoint_projection_guard() TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_endpoint_rules(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_endpoint_rules(jsonb) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_endpoint_snapshot(uuid,uuid,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_endpoint_snapshot(uuid,uuid,integer) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_graph_asset_evidence(text,integer,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_graph_asset_evidence(text,integer,jsonb) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_graph_asset_policy(text,integer,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_graph_asset_policy(text,integer,jsonb) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_graph_asset_row(assets) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_graph_asset_row(assets) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_graph_endpoint(uuid,integer,jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_graph_endpoint(uuid,integer,jsonb,jsonb) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_graph_journal(text,text,integer,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_graph_journal(text,text,integer,uuid,text) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_graph_plan_shape(jsonb,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_graph_plan_shape(jsonb,text) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_graph_project_asset(assets,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_graph_project_asset(assets,jsonb) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_graph_project_endpoint(assets,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_graph_project_endpoint(assets,jsonb) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_graph_resolve_asset(jsonb,boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_graph_resolve_asset(jsonb,boolean) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_graph_transform_intent(jsonb,text,jsonb,jsonb,jsonb,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_graph_transform_intent(jsonb,text,jsonb,jsonb,jsonb,uuid) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_graph_values_valid(jsonb,jsonb,boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_graph_values_valid(jsonb,jsonb,boolean) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_json_bounded(jsonb,integer,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_json_bounded(jsonb,integer,integer,integer) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_keys(jsonb,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_keys(jsonb,text[]) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_lifecycle_valid(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_lifecycle_valid(jsonb) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_model(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_model(jsonb) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_mutation_complete() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_mutation_complete() TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_path(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_path(jsonb) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_policy_changes(jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_policy_changes(jsonb,jsonb) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_positive_integer(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_positive_integer(jsonb) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_preparation_view(relation_type_preparations) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_preparation_view(relation_type_preparations) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_projected_eligible(jsonb,jsonb,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_projected_eligible(jsonb,jsonb,text) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_safe_id(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_safe_id(text) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_schema_at(jsonb,text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_schema_at(jsonb,text[]) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_schema_changes(jsonb,jsonb,text,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_schema_changes(jsonb,jsonb,text,integer) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_schema_compatible(jsonb,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_schema_compatible(jsonb,jsonb) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_schema_valid(jsonb,integer,boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_schema_valid(jsonb,integer,boolean) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_snapshot_base(relations) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_snapshot_base(relations) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_sorted_pins(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_sorted_pins(jsonb) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_state_list(jsonb,boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_state_list(jsonb,boolean) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_structural_policy(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_structural_policy(jsonb) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_utc(timestamp with time zone) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_utc(timestamp with time zone) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_utf16_length(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_utf16_length(text) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_uuid_list(jsonb,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_uuid_list(jsonb,integer) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_values(relations) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_values(relations) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_relation_value_valid(jsonb,jsonb,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_relation_value_valid(jsonb,jsonb,integer) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_tenant() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_tenant() TO gc_app;
REVOKE ALL ON FUNCTION public.gc_type_dependencies_insert() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_type_dependencies_insert() TO gc_app;
REVOKE ALL ON FUNCTION public.gc_type_dependency_guard() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_type_dependency_guard() TO gc_app;
REVOKE ALL ON FUNCTION public.gc_typed_model_version_required() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_typed_model_version_required() TO gc_app;
REVOKE ALL ON FUNCTION public.gc_type_identity_immutable() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_type_identity_immutable() TO gc_app;
REVOKE ALL ON FUNCTION public.gc_type_pins_valid(jsonb,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_type_pins_valid(jsonb,integer) TO gc_app;
REVOKE ALL ON FUNCTION public.gc_type_version_consistent() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.gc_type_version_consistent() TO gc_app;
GRANT EXECUTE ON FUNCTION public.gc_tenant(),public.gc_actor() TO gc_authn_definer;
REVOKE ALL ON gc_authn.installation_root,gc_authn.installation_receipts,gc_authn.executor_registrations,gc_authn.generation_heads,gc_authn.issuer_registrations,gc_authn.identity_bindings,gc_authn.login_attempts,gc_authn.attempt_consumptions,gc_authn.sessions,gc_authn.session_provenance,gc_authn.session_events,gc_authn.registration_revocations,gc_authn.tenant_fences FROM PUBLIC,gc_app;
GRANT SELECT ON gc_authn.executor_registrations,gc_authn.generation_heads,gc_authn.issuer_registrations,gc_authn.identity_bindings,gc_authn.login_attempts,gc_authn.attempt_consumptions,gc_authn.sessions,gc_authn.session_provenance,gc_authn.session_events,gc_authn.tenant_fences TO gc_authn_definer;
GRANT SELECT(id,issuer,subject,active) ON public.identities TO gc_authn_definer;
GRANT SELECT(tenant_id,identity_id,active) ON public.memberships TO gc_authn_definer;
GRANT SELECT(id) ON public.tenants TO gc_authn_definer;
GRANT INSERT ON gc_authn.login_attempts,gc_authn.attempt_consumptions,gc_authn.sessions,gc_authn.session_provenance,gc_authn.session_events TO gc_authn_definer;
GRANT UPDATE(verifier) ON gc_authn.login_attempts TO gc_authn_definer;
GRANT UPDATE(selected_tenant_id,csrf_hash,version,revoked_at) ON gc_authn.sessions TO gc_authn_definer;
REVOKE ALL ON FUNCTION gc_authn.valid_uuid(uuid) FROM PUBLIC,gc_app;
ALTER FUNCTION gc_authn.valid_uuid(uuid) OWNER TO gc_authn_definer;
REVOKE ALL ON FUNCTION gc_authn.valid_time(timestamptz) FROM PUBLIC,gc_app;
ALTER FUNCTION gc_authn.valid_time(timestamptz) OWNER TO gc_authn_definer;
REVOKE ALL ON FUNCTION gc_authn.valid_text(text,integer) FROM PUBLIC,gc_app;
ALTER FUNCTION gc_authn.valid_text(text,integer) OWNER TO gc_authn_definer;
REVOKE ALL ON FUNCTION gc_authn.valid_digest(text) FROM PUBLIC,gc_app;
ALTER FUNCTION gc_authn.valid_digest(text) OWNER TO gc_authn_definer;
REVOKE ALL ON FUNCTION gc_authn.require_input(boolean) FROM PUBLIC,gc_app;
ALTER FUNCTION gc_authn.require_input(boolean) OWNER TO gc_authn_definer;
REVOKE ALL ON FUNCTION gc_authn.require_auth(boolean) FROM PUBLIC,gc_app;
ALTER FUNCTION gc_authn.require_auth(boolean) OWNER TO gc_authn_definer;
REVOKE ALL ON FUNCTION gc_authn.require_mutation() FROM PUBLIC,gc_app;
ALTER FUNCTION gc_authn.require_mutation() OWNER TO gc_authn_definer;
REVOKE ALL ON FUNCTION gc_authn.scalar(text,text) FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.field(text,text,text) FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.install_encoding(text,uuid,text,text,oid,oid,text) FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.install_check(uuid,text,text,oid,oid,text) FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.install_existing(uuid,text) FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.install_receipt(text,uuid,uuid,text,text,text,text) FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.role_safe(oid,text) FROM PUBLIC,gc_app;
ALTER FUNCTION gc_authn.role_safe(oid,text) OWNER TO gc_authn_definer;
REVOKE ALL ON FUNCTION gc_authn.current_registration(uuid,text) FROM PUBLIC,gc_app;
ALTER FUNCTION gc_authn.current_registration(uuid,text) OWNER TO gc_authn_definer;
REVOKE ALL ON FUNCTION gc_authn.executor(text) FROM PUBLIC,gc_app;
ALTER FUNCTION gc_authn.executor(text) OWNER TO gc_authn_definer;
REVOKE ALL ON FUNCTION gc_authn.immutable() FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.registration_update() FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.head_update() FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.fence_update() FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.attempt_update() FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.session_update() FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.lock_configuration(uuid,uuid,uuid,uuid,uuid[]) FROM PUBLIC,gc_app;
GRANT EXECUTE ON FUNCTION gc_authn.lock_configuration(uuid,uuid,uuid,uuid,uuid[]) TO gc_authn_definer;
REVOKE ALL ON FUNCTION gc_authn.lock_principals(uuid,uuid[]) FROM PUBLIC,gc_app;
GRANT EXECUTE ON FUNCTION gc_authn.lock_principals(uuid,uuid[]) TO gc_authn_definer;
REVOKE ALL ON FUNCTION gc_authn.validate_session(uuid) FROM PUBLIC,gc_app;
ALTER FUNCTION gc_authn.validate_session(uuid) OWNER TO gc_authn_definer;
REVOKE ALL ON FUNCTION gc_authn.session_consistent() FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.attempt_consistent() FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.install_consistent() FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.provision_executor(uuid,text,text,oid,oid,text,uuid,uuid,text,oid,text,integer,timestamptz) FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.advance_generation(uuid,text,text,oid,oid,text,text,uuid,uuid,uuid,integer) FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.provision_issuer(uuid,text,text,oid,oid,text,uuid,uuid,integer,text,text,text,text,timestamptz) FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.bind_identity(uuid,text,text,oid,oid,text,uuid,uuid,uuid,text,text,timestamptz) FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.initialize_tenant(uuid,text,text,oid,oid,text,uuid,integer) FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.advance_tenant_generation(uuid,text,text,oid,oid,text,uuid,integer,integer,integer) FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.revoke_executor(uuid,text,text,oid,oid,text,uuid) FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.revoke_issuer(uuid,text,text,oid,oid,text,uuid) FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.revoke_binding(uuid,text,text,oid,oid,text,uuid) FROM PUBLIC,gc_app;
REVOKE ALL ON FUNCTION gc_authn.live_issuer(uuid) FROM PUBLIC,gc_app;
ALTER FUNCTION gc_authn.live_issuer(uuid) OWNER TO gc_authn_definer;
REVOKE ALL ON FUNCTION gc_authn.checked_session(text,boolean) FROM PUBLIC,gc_app;
ALTER FUNCTION gc_authn.checked_session(text,boolean) OWNER TO gc_authn_definer;
REVOKE ALL ON FUNCTION public.gc_authn_attempt_begin(text,text,text) FROM PUBLIC,gc_app;
ALTER FUNCTION public.gc_authn_attempt_begin(text,text,text) OWNER TO gc_authn_definer;
REVOKE ALL ON FUNCTION public.gc_authn_attempt_consume(uuid,text) FROM PUBLIC,gc_app;
ALTER FUNCTION public.gc_authn_attempt_consume(uuid,text) OWNER TO gc_authn_definer;
REVOKE ALL ON FUNCTION public.gc_authn_session_issue(uuid,text,text,text,text,text,timestamptz,timestamptz,timestamptz,text,text) FROM PUBLIC,gc_app;
ALTER FUNCTION public.gc_authn_session_issue(uuid,text,text,text,text,text,timestamptz,timestamptz,timestamptz,text,text) OWNER TO gc_authn_definer;
REVOKE ALL ON FUNCTION public.gc_authn_session_inspect(text) FROM PUBLIC,gc_app;
ALTER FUNCTION public.gc_authn_session_inspect(text) OWNER TO gc_authn_definer;
REVOKE ALL ON FUNCTION public.gc_authn_session_revoke(text,text,integer) FROM PUBLIC,gc_app;
ALTER FUNCTION public.gc_authn_session_revoke(text,text,integer) OWNER TO gc_authn_definer;
REVOKE ALL ON FUNCTION public.gc_authn_session_select(text,text,integer,uuid,text) FROM PUBLIC,gc_app;
ALTER FUNCTION public.gc_authn_session_select(text,text,integer,uuid,text) OWNER TO gc_authn_definer;
-- SET-only deployment membership must be selected explicitly for the finite owner grants.
SET LOCAL ROLE gc_authn_definer;
DO $$ BEGIN
 EXECUTE format('GRANT EXECUTE ON FUNCTION gc_authn.valid_uuid(uuid) TO %I',session_user);
 EXECUTE format('GRANT EXECUTE ON FUNCTION gc_authn.valid_time(timestamptz) TO %I',session_user);
 EXECUTE format('GRANT EXECUTE ON FUNCTION gc_authn.valid_text(text,integer) TO %I',session_user);
 EXECUTE format('GRANT EXECUTE ON FUNCTION gc_authn.valid_digest(text) TO %I',session_user);
 EXECUTE format('GRANT EXECUTE ON FUNCTION gc_authn.require_input(boolean) TO %I',session_user);
 EXECUTE format('GRANT EXECUTE ON FUNCTION gc_authn.require_auth(boolean) TO %I',session_user);
 EXECUTE format('GRANT EXECUTE ON FUNCTION gc_authn.require_mutation() TO %I',session_user);
 EXECUTE format('GRANT EXECUTE ON FUNCTION gc_authn.role_safe(oid,text) TO %I',session_user);
 EXECUTE format('GRANT EXECUTE ON FUNCTION gc_authn.current_registration(uuid,text) TO %I',session_user);
 EXECUTE format('GRANT EXECUTE ON FUNCTION gc_authn.executor(text) TO %I',session_user);
 EXECUTE format('GRANT EXECUTE ON FUNCTION gc_authn.validate_session(uuid) TO %I',session_user);
 EXECUTE format('GRANT EXECUTE ON FUNCTION gc_authn.live_issuer(uuid) TO %I',session_user);
 EXECUTE format('GRANT EXECUTE ON FUNCTION gc_authn.checked_session(text,boolean) TO %I',session_user);
 EXECUTE format('GRANT EXECUTE ON FUNCTION public.gc_authn_attempt_begin(text,text,text) TO %I',session_user);
 EXECUTE format('GRANT EXECUTE ON FUNCTION public.gc_authn_attempt_consume(uuid,text) TO %I',session_user);
 EXECUTE format('GRANT EXECUTE ON FUNCTION public.gc_authn_session_issue(uuid,text,text,text,text,text,timestamptz,timestamptz,timestamptz,text,text) TO %I',session_user);
 EXECUTE format('GRANT EXECUTE ON FUNCTION public.gc_authn_session_inspect(text) TO %I',session_user);
 EXECUTE format('GRANT EXECUTE ON FUNCTION public.gc_authn_session_revoke(text,text,integer) TO %I',session_user);
 EXECUTE format('GRANT EXECUTE ON FUNCTION public.gc_authn_session_select(text,text,integer,uuid,text) TO %I',session_user);
END $$;
RESET ROLE;
REVOKE CREATE ON SCHEMA gc_authn,public FROM gc_authn_definer;
-- Runtime role grants are the separately authenticated fixed role-provisioning step.
-- No enabled executor/issuer/head/fence/session is installed by SQL012.

REVOKE ALL ON FUNCTION gc_authn.valid_endpoint(text,text) FROM PUBLIC,gc_app,gc_authn_definer;
REVOKE ALL ON FUNCTION gc_authn.legacy_session_hash_exists(text) FROM PUBLIC,gc_app;
GRANT EXECUTE ON FUNCTION gc_authn.legacy_session_hash_exists(text) TO gc_authn_definer;
