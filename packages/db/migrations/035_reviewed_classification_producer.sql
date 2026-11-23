-- SPDX-License-Identifier: Apache-2.0
-- SQL035: explicit native-owner installation of one reviewed-classification
-- producer. No runtime grants, content-authority activation or inferred producer.
DO $$ BEGIN PERFORM gc_authority.owner_check(); END $$;

CREATE TABLE gc_authority.classification_producer_installations(
 tenant_id uuid NOT NULL REFERENCES gc_authority.tenant_heads, id uuid NOT NULL CHECK(gc_authority.valid_uuid(id)),
 version integer NOT NULL CHECK(version>0), request_id uuid NOT NULL CHECK(gc_authority.valid_uuid(request_id)),
 operation text NOT NULL CHECK(operation IN('bind','revoke')),
 implementation text NOT NULL CHECK(implementation='reviewed-metadata-classification-v1'),
 expected_generation bigint NOT NULL CHECK(expected_generation>0),
 expected_authn_fence_epoch bigint NOT NULL CHECK(expected_authn_fence_epoch>0),
 expected_authority_epoch bigint NOT NULL CHECK(expected_authority_epoch>0),
 authority_epoch_after bigint NOT NULL CHECK(authority_epoch_after=expected_authority_epoch+1),
 expected_binding_version integer NOT NULL CHECK(expected_binding_version>=0 AND version=expected_binding_version+1),
 expected_previous_installation_id uuid, previous_manifest_hash text,
 registry_id uuid NOT NULL, registry_version integer NOT NULL, registry_digest text NOT NULL,
 producer_id uuid NOT NULL CHECK(gc_authority.valid_uuid(producer_id)), producer_version integer NOT NULL CHECK(producer_version>0),
 database_oid oid NOT NULL, owner_role_oid oid NOT NULL, release_reference text NOT NULL, operator_reference text NOT NULL,
 recorded_at timestamptz NOT NULL CHECK(gc_authority.valid_time(recorded_at)),
 transaction_id xid8 NOT NULL UNIQUE REFERENCES gc_authority.write_bindings, backend_pid integer NOT NULL,
 request_encoding bytea NOT NULL CHECK(octet_length(request_encoding) BETWEEN 1 AND 4096),
 manifest_encoding bytea NOT NULL CHECK(octet_length(manifest_encoding) BETWEEN 1 AND 4096),
 manifest_hash text NOT NULL CHECK(manifest_hash ~ '^[0-9a-f]{64}$'),
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,version), UNIQUE(tenant_id,request_id), UNIQUE(tenant_id,version,id),
 FOREIGN KEY(tenant_id,expected_previous_installation_id) REFERENCES gc_authority.classification_producer_installations(tenant_id,id),
 FOREIGN KEY(registry_id,registry_version,registry_digest) REFERENCES gc_authority.registries(id,version,digest),
 CHECK((version=1 AND expected_previous_installation_id IS NULL AND previous_manifest_hash IS NULL AND operation='bind')
    OR (version>1 AND expected_previous_installation_id IS NOT NULL AND previous_manifest_hash ~ '^[0-9a-f]{64}$'))
);
CREATE TABLE gc_authority.classification_producer_heads(
 tenant_id uuid PRIMARY KEY REFERENCES gc_authority.tenant_heads,
 version integer NOT NULL CHECK(version>0), installation_id uuid NOT NULL,
 FOREIGN KEY(tenant_id,version,installation_id) REFERENCES gc_authority.classification_producer_installations(tenant_id,version,id)
);
DO $$ DECLARE n text; BEGIN
 FOREACH n IN ARRAY ARRAY['classification_producer_installations','classification_producer_heads'] LOOP
  EXECUTE format('ALTER TABLE gc_authority.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE gc_authority.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY authority_tenant ON gc_authority.%I USING(tenant_id=public.gc_tenant()) WITH CHECK(tenant_id=public.gc_tenant())',n);
  EXECUTE format('CREATE TRIGGER authority_no_truncate BEFORE TRUNCATE ON gc_authority.%I FOR EACH STATEMENT EXECUTE FUNCTION gc_authority.immutable()',n);
  EXECUTE format('REVOKE ALL ON gc_authority.%I FROM PUBLIC,gc_app',n);
 END LOOP;
END $$;
CREATE TRIGGER classification_producer_receipt_immutable BEFORE UPDATE OR DELETE ON gc_authority.classification_producer_installations
 FOR EACH STATEMENT EXECUTE FUNCTION gc_authority.immutable();

-- Exact typed codecs. Null producer fields in a revoke request distinguish its
-- supplied parameters from the retained producer derived from its predecessor.
CREATE FUNCTION gc_authority.classification_producer_request_encoding_v1(r gc_authority.classification_producer_installations)
RETURNS bytea LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT convert_to('gc-reviewed-classification-producer-request/v1;'||gc_authority.scalar(r.operation,'S')
 ||gc_authority.field('implementation',r.implementation,'S')
 ||gc_authority.field('request_id',r.request_id::text,'U')||gc_authority.field('release_ref',r.release_reference,'S')
 ||gc_authority.field('operator_ref',r.operator_reference,'S')||gc_authority.field('expected_db_oid',r.database_oid::text,'I')
 ||gc_authority.field('expected_owner_oid',r.owner_role_oid::text,'I')||gc_authority.field('tenant_id',r.tenant_id::text,'U')
 ||gc_authority.field('expected_generation',r.expected_generation::text,'I')
 ||gc_authority.field('expected_authn_fence_epoch',r.expected_authn_fence_epoch::text,'I')
 ||gc_authority.field('expected_authority_epoch',r.expected_authority_epoch::text,'I')
 ||gc_authority.field('expected_binding_version',r.expected_binding_version::text,'I')
 ||gc_authority.field('expected_previous_installation_id',r.expected_previous_installation_id::text,'U')
 ||gc_authority.field('registry_id',r.registry_id::text,'U')||gc_authority.field('registry_version',r.registry_version::text,'I')
 ||gc_authority.field('registry_digest',r.registry_digest,'S')
 ||gc_authority.field('producer_id',CASE WHEN r.operation='bind' THEN r.producer_id::text END,'U')
 ||gc_authority.field('producer_version',CASE WHEN r.operation='bind' THEN r.producer_version::text END,'I'),'UTF8')
$$;
CREATE FUNCTION gc_authority.classification_producer_manifest_encoding_v1(r gc_authority.classification_producer_installations)
RETURNS bytea LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT convert_to('gc-reviewed-classification-producer-receipt/v1;'
 ||gc_authority.field('request_encoding',convert_from(r.request_encoding,'UTF8'),'S')
 ||gc_authority.field('installation_id',r.id::text,'U')||gc_authority.field('version',r.version::text,'I')
 ||gc_authority.field('previous_manifest_hash',r.previous_manifest_hash,'S')
 ||gc_authority.field('producer_id',r.producer_id::text,'U')||gc_authority.field('producer_version',r.producer_version::text,'I')
 ||gc_authority.field('recorded_at',gc_authority.utc(r.recorded_at),'S')
 ||gc_authority.field('authority_epoch_after',r.authority_epoch_after::text,'I'),'UTF8')
$$;
CREATE FUNCTION gc_authority.classification_producer_receipt_v1(r gc_authority.classification_producer_installations)
RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('formatVersion',1,'installationId',r.id,'tenantId',r.tenant_id,'version',r.version,
 'operation',r.operation,'implementation',r.implementation,'producer',jsonb_build_object('id',r.producer_id,'version',r.producer_version),
 'authorityEpochAfter',r.authority_epoch_after::text,'manifestHash',r.manifest_hash,'recordedAt',gc_authority.utc(r.recorded_at))
$$;

-- Historic structural validation never requires the old write transaction to be
-- the current transaction, or an old producer still to be active today.
CREATE FUNCTION gc_authority.validate_classification_producer_receipt_v1(r gc_authority.classification_producer_installations)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,gc_authority,pg_temp SET row_security=on AS $$
DECLARE prior gc_authority.classification_producer_installations;
BEGIN
 PERFORM gc_authority.owner_check();PERFORM gc_authority.tick();
 PERFORM gc_authority.require(r.tenant_id=public.gc_tenant() AND r.id IS NOT NULL
  AND r.implementation='reviewed-metadata-classification-v1' AND r.operation IN('bind','revoke')
  AND r.database_oid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND r.owner_role_oid=session_user::regrole::oid
  AND length(r.release_reference) BETWEEN 1 AND 256 AND r.release_reference !~ '[[:cntrl:]]'
  AND length(r.operator_reference) BETWEEN 1 AND 256 AND r.operator_reference !~ '[[:cntrl:]]'
  AND r.request_encoding=gc_authority.classification_producer_request_encoding_v1(r)
  AND r.manifest_encoding=gc_authority.classification_producer_manifest_encoding_v1(r)
  AND r.manifest_hash=encode(sha256(r.manifest_encoding),'hex'),'23514');
 IF r.version=1 THEN
  PERFORM gc_authority.require(r.expected_previous_installation_id IS NULL AND r.previous_manifest_hash IS NULL AND r.operation='bind','23514');
 ELSE
  SELECT * INTO prior FROM gc_authority.classification_producer_installations
   WHERE tenant_id=r.tenant_id AND id=r.expected_previous_installation_id;
  PERFORM gc_authority.require(prior.version=r.expected_binding_version AND prior.manifest_hash=r.previous_manifest_hash
   AND prior.authority_epoch_after<=r.expected_authority_epoch
   AND (prior.expected_generation,prior.registry_id,prior.registry_version,prior.registry_digest)
       =(r.expected_generation,r.registry_id,r.registry_version,r.registry_digest)
   AND (r.operation='bind' OR (r.producer_id,r.producer_version)=(prior.producer_id,prior.producer_version)),'23514');
 END IF;
END $$;

CREATE FUNCTION gc_authority.validate_classification_producer_write_v1(r gc_authority.classification_producer_installations)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,gc_authority,pg_temp SET row_security=on AS $$
DECLARE b gc_authority.write_bindings;h gc_authority.tenant_heads;f gc_authn.tenant_fences;j jsonb;p jsonb;n integer;
BEGIN
 PERFORM gc_authority.validate_classification_producer_receipt_v1(r);b:=gc_authority.sealed();
 SELECT * INTO h FROM gc_authority.tenant_heads WHERE tenant_id=r.tenant_id FOR UPDATE;
 SELECT * INTO f FROM gc_authn.tenant_fences WHERE tenant_id=r.tenant_id FOR SHARE;
 PERFORM gc_authority.require((b.transaction_id,b.backend_pid,b.owner_role_oid,b.tenant_id,b.epoch_before,b.epoch_after)
  =(r.transaction_id,r.backend_pid,r.owner_role_oid,r.tenant_id,r.expected_authority_epoch,r.authority_epoch_after)
  AND r.transaction_id=pg_current_xact_id() AND r.backend_pid=pg_backend_pid()
  AND h.authority_epoch=b.epoch_after AND h.mode='inactive'
  AND (h.generation,h.registry_id,h.registry_version,h.registry_digest)
      =(r.expected_generation,r.registry_id,r.registry_version,r.registry_digest)
  AND f.mode='inactive' AND f.generation=r.expected_generation AND f.epoch=r.expected_authn_fence_epoch
  AND r.recorded_at>=date_trunc('milliseconds',b.started_at) AND r.recorded_at<=clock_timestamp(),'23514');
 -- The exact immutable registry was validated at installation. Recheck its
 -- admitted document and registration for every bind; revoke need not be live.
 IF r.operation='bind' THEN
  SELECT gc_authority.registry(registry_document) INTO j FROM gc_authority.registries
   WHERE id=r.registry_id AND version=r.registry_version AND digest=r.registry_digest;
  SELECT count(*) INTO n FROM jsonb_array_elements(j->'producers') x
   WHERE x#>>'{ref,id}'=r.producer_id::text AND x#>>'{ref,version}'=r.producer_version::text;
  PERFORM gc_authority.require(n=1,'23514');
  SELECT x INTO p FROM jsonb_array_elements(j->'producers') x
   WHERE x#>>'{ref,id}'=r.producer_id::text AND x#>>'{ref,version}'=r.producer_version::text;
  PERFORM gc_authority.require(p->>'tenantId'=r.tenant_id::text AND p->>'kind'='classifications' AND p->>'state'='active'
   AND (p#>>'{validity,notBefore}' IS NULL OR (p#>>'{validity,notBefore}')::timestamptz<=r.recorded_at)
   AND (p#>>'{validity,expiresAt}' IS NULL OR (p#>>'{validity,expiresAt}')::timestamptz>clock_timestamp()),'23514');
 END IF;
 PERFORM gc_authority.tick();
END $$;

CREATE FUNCTION gc_authority.classification_producer_guard_v1() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,gc_authority,pg_temp SET row_security=on AS $$
DECLARE r gc_authority.classification_producer_installations;h gc_authority.classification_producer_heads;
BEGIN
 PERFORM gc_authority.owner_check();PERFORM gc_authority.tick();
 IF TG_OP='DELETE' THEN PERFORM gc_authority.require(false,'23514');END IF;
 PERFORM gc_authority.require(NEW.tenant_id=public.gc_tenant(),'23514');
 IF TG_TABLE_NAME='classification_producer_installations' THEN
  r:=NEW;PERFORM gc_authority.validate_classification_producer_write_v1(r);
  SELECT * INTO h FROM gc_authority.classification_producer_heads WHERE tenant_id=r.tenant_id;
  PERFORM gc_authority.require((h.tenant_id IS NULL AND r.version=1)
   OR (h.version=r.expected_binding_version AND h.installation_id=r.expected_previous_installation_id),'23514');
 ELSE
  SELECT * INTO r FROM gc_authority.classification_producer_installations WHERE tenant_id=NEW.tenant_id AND id=NEW.installation_id AND version=NEW.version;
  PERFORM gc_authority.validate_classification_producer_write_v1(r);
  IF TG_OP='INSERT' THEN PERFORM gc_authority.require(NEW.version=1,'23514');
  ELSE PERFORM gc_authority.require(NEW.tenant_id=OLD.tenant_id AND NEW.version=OLD.version+1 AND r.expected_previous_installation_id=OLD.installation_id,'23514');END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER classification_producer_installation_guard BEFORE INSERT ON gc_authority.classification_producer_installations
 FOR EACH ROW EXECUTE FUNCTION gc_authority.classification_producer_guard_v1();
CREATE TRIGGER classification_producer_head_guard BEFORE INSERT OR UPDATE OR DELETE ON gc_authority.classification_producer_heads
 FOR EACH ROW EXECUTE FUNCTION gc_authority.classification_producer_guard_v1();

CREATE FUNCTION gc_authority.classification_producer_complete_v1() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,gc_authority,pg_temp SET row_security=on AS $$
DECLARE r gc_authority.classification_producer_installations;h gc_authority.classification_producer_heads;
 old_t text:=current_setting('gc.tenant_id',true);
BEGIN
 PERFORM set_config('gc.tenant_id',NEW.tenant_id::text,true);
 IF TG_TABLE_NAME='classification_producer_installations' THEN r:=NEW;
 ELSE SELECT * INTO r FROM gc_authority.classification_producer_installations WHERE tenant_id=NEW.tenant_id AND id=NEW.installation_id AND version=NEW.version;END IF;
 PERFORM gc_authority.validate_classification_producer_write_v1(r);
 -- The installer's EXCEPTION block creates a subtransaction. Prove both rows
 -- share that actual write xid, while the sealed receipt binds its top-level
 -- transaction and backend; a row xmin need not equal the top-level xid.
 SELECT x.* INTO h FROM gc_authority.classification_producer_heads x
 JOIN gc_authority.classification_producer_installations source
  ON (source.tenant_id,source.version,source.id)=(x.tenant_id,x.version,x.installation_id)
 WHERE x.tenant_id=r.tenant_id AND x.version=r.version AND x.installation_id=r.id
  AND x.xmin=source.xmin AND source.transaction_id=pg_current_xact_id() AND source.backend_pid=pg_backend_pid();
 PERFORM gc_authority.require(h.version=r.version AND h.installation_id=r.id,'23514');
 PERFORM set_config('gc.tenant_id',coalesce(old_t,''),true);RETURN NULL;
EXCEPTION WHEN OTHERS THEN PERFORM set_config('gc.tenant_id',coalesce(old_t,''),true);RAISE;
END $$;
CREATE CONSTRAINT TRIGGER classification_producer_receipt_complete AFTER INSERT ON gc_authority.classification_producer_installations
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gc_authority.classification_producer_complete_v1();
CREATE CONSTRAINT TRIGGER classification_producer_head_complete AFTER INSERT OR UPDATE ON gc_authority.classification_producer_heads
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gc_authority.classification_producer_complete_v1();

-- Only this binding-completion target changes. All original lifecycle source
-- validators and triggers retain their exact bodies and deferred semantics.
CREATE FUNCTION gc_authority.write_binding_complete_v2() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,gc_authority,pg_temp SET row_security=on AS $$
DECLARE b gc_authority.write_bindings;r gc_authority.classification_producer_installations;
 old_t text:=current_setting('gc.tenant_id',true);
BEGIN
 PERFORM set_config('gc.tenant_id',NEW.tenant_id::text,true);b:=gc_authority.sealed();
 PERFORM gc_authority.require(b.transaction_id=NEW.transaction_id,'23514');
 SELECT * INTO r FROM gc_authority.classification_producer_installations WHERE transaction_id=b.transaction_id AND tenant_id=b.tenant_id;
 IF FOUND THEN
  PERFORM gc_authority.validate_classification_producer_write_v1(r);
  PERFORM gc_authority.require(EXISTS(SELECT 1 FROM gc_authority.classification_producer_heads h
   JOIN gc_authority.classification_producer_installations source
    ON (source.tenant_id,source.version,source.id)=(h.tenant_id,h.version,h.installation_id)
   WHERE h.tenant_id=r.tenant_id AND h.version=r.version AND h.installation_id=r.id
    AND h.xmin=source.xmin AND source.transaction_id=pg_current_xact_id() AND source.backend_pid=pg_backend_pid()),'23514');
 ELSE
  PERFORM gc_authority.require(EXISTS(SELECT 1 FROM gc_authority.lifecycle_revisions WHERE tenant_id=b.tenant_id AND xmin=pg_current_xact_id()::xid),'23514');
 END IF;
 PERFORM set_config('gc.tenant_id',coalesce(old_t,''),true);RETURN NULL;
EXCEPTION WHEN OTHERS THEN PERFORM set_config('gc.tenant_id',coalesce(old_t,''),true);RAISE;
END $$;
DROP TRIGGER authority_binding_complete ON gc_authority.write_bindings;
CREATE CONSTRAINT TRIGGER authority_binding_complete AFTER INSERT ON gc_authority.write_bindings
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION gc_authority.write_binding_complete_v2();

CREATE FUNCTION gc_authority.change_reviewed_classification_producer_v1(
 p_operation text,request_id uuid,release_ref text,operator_ref text,expected_db_oid oid,expected_owner_oid oid,
 tenant_id uuid,expected_generation bigint,expected_authn_fence_epoch bigint,expected_authority_epoch bigint,
 expected_binding_version integer,expected_previous_installation_id uuid,
 registry_id uuid,registry_version integer,registry_digest text,producer_id uuid,producer_version integer
) RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,gc_authority,pg_temp SET row_security=on AS $$
DECLARE r gc_authority.classification_producer_installations;prior gc_authority.classification_producer_installations;
 saved gc_authority.classification_producer_installations;h gc_authority.classification_producer_heads;
 actual gc_authority.tenant_heads;f gc_authn.tenant_fences;answer jsonb;
 old_t text:=current_setting('gc.tenant_id',true);old_a text:=current_setting('gc.actor_id',true);
 old_lock text:=current_setting('lock_timeout');
BEGIN
 PERFORM gc_authority.install_check(request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid);
 PERFORM gc_authority.require(p_operation IN('bind','revoke') AND gc_authority.valid_uuid(tenant_id)
  AND expected_generation>0 AND expected_authn_fence_epoch>0 AND expected_authority_epoch BETWEEN 1 AND 9223372036854775806
  AND expected_binding_version BETWEEN 0 AND 2147483646
  AND ((expected_binding_version=0 AND expected_previous_installation_id IS NULL AND p_operation='bind')
    OR (expected_binding_version>0 AND gc_authority.valid_uuid(expected_previous_installation_id)))
  AND gc_authority.valid_uuid(registry_id) AND registry_version>0 AND registry_digest ~ '^[0-9a-f]{64}$'
  AND ((p_operation='bind' AND gc_authority.valid_uuid(producer_id) AND producer_version>0)
    OR (p_operation='revoke' AND producer_id IS NULL AND producer_version IS NULL)));
 r.tenant_id:=tenant_id;r.request_id:=request_id;r.operation:=p_operation;r.implementation:='reviewed-metadata-classification-v1';
 r.expected_generation:=expected_generation;r.expected_authn_fence_epoch:=expected_authn_fence_epoch;
 r.expected_authority_epoch:=expected_authority_epoch;r.authority_epoch_after:=expected_authority_epoch+1;
 r.expected_binding_version:=expected_binding_version;r.version:=expected_binding_version+1;
 r.expected_previous_installation_id:=expected_previous_installation_id;
 r.registry_id:=registry_id;r.registry_version:=registry_version;r.registry_digest:=registry_digest;
 r.producer_id:=producer_id;r.producer_version:=producer_version;
 r.database_oid:=expected_db_oid;r.owner_role_oid:=expected_owner_oid;
 r.release_reference:=release_ref;r.operator_reference:=operator_ref;
 r.request_encoding:=gc_authority.classification_producer_request_encoding_v1(r);
 PERFORM gc_authority.require(octet_length(r.request_encoding)<=4096,'54000');
 PERFORM set_config('gc.tenant_id',tenant_id::text,true);
 -- Never block indefinitely on request replay before the tenant lock budget is
 -- installed. A concurrent identical request gets a finite retryable refusal.
 PERFORM gc_authority.require(pg_try_advisory_xact_lock(hashtextextended('gc-classification-producer:'||tenant_id::text||':'||request_id::text,0)),'55P03');
 SELECT * INTO saved FROM gc_authority.classification_producer_installations x
  WHERE x.tenant_id=r.tenant_id AND x.request_id=r.request_id;
 IF FOUND THEN
  PERFORM gc_authority.require(saved.request_encoding=r.request_encoding,'40001');
  PERFORM gc_authority.validate_classification_producer_receipt_v1(saved);
  answer:=gc_authority.classification_producer_receipt_v1(saved);
 ELSE
  PERFORM gc_authority.foundation_write_begin_v1(tenant_id,expected_authority_epoch);
  PERFORM gc_authority.foundation_write_locks_v1('{}'::uuid[],'{}'::uuid[]);
  SELECT * INTO actual FROM gc_authority.tenant_heads x WHERE x.tenant_id=r.tenant_id;
  SELECT * INTO f FROM gc_authn.tenant_fences x WHERE x.tenant_id=r.tenant_id;
  PERFORM gc_authority.require((actual.generation,actual.registry_id,actual.registry_version,actual.registry_digest)
    =(r.expected_generation,r.registry_id,r.registry_version,r.registry_digest)
   AND f.generation=r.expected_generation AND f.epoch=r.expected_authn_fence_epoch,'40001');
  SELECT * INTO h FROM gc_authority.classification_producer_heads x WHERE x.tenant_id=r.tenant_id FOR UPDATE;
  PERFORM gc_authority.require((h.tenant_id IS NULL AND r.version=1)
   OR (h.version=r.expected_binding_version AND h.installation_id=r.expected_previous_installation_id),'40001');
  IF r.version>1 THEN
   SELECT * INTO prior FROM gc_authority.classification_producer_installations x
    WHERE x.tenant_id=r.tenant_id AND x.id=r.expected_previous_installation_id;
   PERFORM gc_authority.validate_classification_producer_receipt_v1(prior);
   r.previous_manifest_hash:=prior.manifest_hash;
   IF p_operation='revoke' THEN r.producer_id:=prior.producer_id;r.producer_version:=prior.producer_version;END IF;
  END IF;
  r.id:=gen_random_uuid();r.recorded_at:=date_trunc('milliseconds',clock_timestamp());
  r.transaction_id:=pg_current_xact_id();r.backend_pid:=pg_backend_pid();
  r.manifest_encoding:=gc_authority.classification_producer_manifest_encoding_v1(r);
  PERFORM gc_authority.require(octet_length(r.manifest_encoding)<=4096,'54000');
  r.manifest_hash:=encode(sha256(r.manifest_encoding),'hex');
  INSERT INTO gc_authority.classification_producer_installations SELECT (r).*;
  IF h.tenant_id IS NULL THEN
   INSERT INTO gc_authority.classification_producer_heads VALUES(r.tenant_id,r.version,r.id);
  ELSE
   UPDATE gc_authority.classification_producer_heads x SET version=r.version,installation_id=r.id WHERE x.tenant_id=r.tenant_id;
  END IF;
  answer:=gc_authority.classification_producer_receipt_v1(r);
 END IF;
 PERFORM gc_authority.tick();
 PERFORM set_config('gc.tenant_id',coalesce(old_t,''),true);PERFORM set_config('gc.actor_id',coalesce(old_a,''),true);
 PERFORM set_config('lock_timeout',old_lock,true);RETURN answer;
EXCEPTION WHEN OTHERS THEN
 PERFORM set_config('gc.tenant_id',coalesce(old_t,''),true);PERFORM set_config('gc.actor_id',coalesce(old_a,''),true);
 PERFORM set_config('lock_timeout',old_lock,true);RAISE;
END $$;
CREATE FUNCTION gc_authority.install_reviewed_classification_producer_v1(
 request_id uuid,release_ref text,operator_ref text,expected_db_oid oid,expected_owner_oid oid,
 tenant_id uuid,expected_generation bigint,expected_authn_fence_epoch bigint,expected_authority_epoch bigint,
 expected_binding_version integer,expected_previous_installation_id uuid,
 registry_id uuid,registry_version integer,registry_digest text,producer_id uuid,producer_version integer
) RETURNS jsonb LANGUAGE sql SET search_path=pg_catalog,gc_authority,pg_temp SET row_security=on AS $$
 SELECT gc_authority.change_reviewed_classification_producer_v1('bind',request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,
 tenant_id,expected_generation,expected_authn_fence_epoch,expected_authority_epoch,expected_binding_version,expected_previous_installation_id,
 registry_id,registry_version,registry_digest,producer_id,producer_version)
$$;
CREATE FUNCTION gc_authority.revoke_reviewed_classification_producer_v1(
 request_id uuid,release_ref text,operator_ref text,expected_db_oid oid,expected_owner_oid oid,
 tenant_id uuid,expected_generation bigint,expected_authn_fence_epoch bigint,expected_authority_epoch bigint,
 expected_binding_version integer,expected_previous_installation_id uuid,
 registry_id uuid,registry_version integer,registry_digest text
) RETURNS jsonb LANGUAGE sql SET search_path=pg_catalog,gc_authority,pg_temp SET row_security=on AS $$
 SELECT gc_authority.change_reviewed_classification_producer_v1('revoke',request_id,release_ref,operator_ref,expected_db_oid,expected_owner_oid,
 tenant_id,expected_generation,expected_authn_fence_epoch,expected_authority_epoch,expected_binding_version,expected_previous_installation_id,
 registry_id,registry_version,registry_digest,NULL::uuid,NULL::integer)
$$;

CREATE FUNCTION gc_authority.load_reviewed_classification_producer_v1(session_hash text)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog,gc_authority,pg_temp SET row_security=on AS $$
DECLARE auth gc_authn.foundation_session;again gc_authn.foundation_session;
 h gc_authority.tenant_heads;p gc_authority.classification_producer_heads;r gc_authority.classification_producer_installations;
 answer jsonb;bound jsonb:=NULL;old_t text:=current_setting('gc.tenant_id',true);old_a text:=current_setting('gc.actor_id',true);
BEGIN
 PERFORM gc_authority.owner_check();PERFORM gc_authority.tick();
 PERFORM gc_authority.require(current_setting('transaction_isolation')='repeatable read' AND current_setting('transaction_read_only')='on','42501');
 SELECT * INTO auth FROM gc_authn.foundation_session_v1(session_hash);
 PERFORM gc_authority.require(auth.session_id IS NOT NULL,'28000');
 PERFORM set_config('gc.tenant_id',auth.tenant_id::text,true);PERFORM set_config('gc.actor_id',auth.identity_id::text,true);
 SELECT * INTO h FROM gc_authority.tenant_heads WHERE tenant_id=auth.tenant_id;
 PERFORM gc_authority.require(h.tenant_id IS NOT NULL AND h.generation=auth.generation AND h.mode='inactive','23514');
 SELECT * INTO p FROM gc_authority.classification_producer_heads WHERE tenant_id=auth.tenant_id;
 IF p.tenant_id IS NULL THEN
  PERFORM gc_authority.require(NOT EXISTS(SELECT 1 FROM gc_authority.classification_producer_installations WHERE tenant_id=auth.tenant_id),'23514');
 ELSE
  SELECT * INTO r FROM gc_authority.classification_producer_installations
   WHERE tenant_id=auth.tenant_id AND id=p.installation_id AND version=p.version;
  PERFORM gc_authority.validate_classification_producer_receipt_v1(r);
  PERFORM gc_authority.require((r.expected_generation,r.registry_id,r.registry_version,r.registry_digest)
    =(h.generation,h.registry_id,h.registry_version,h.registry_digest)
   AND r.authority_epoch_after<=h.authority_epoch,'23514');
  bound:=jsonb_build_object('installationId',r.id,'version',r.version,'operation',r.operation,'implementation',r.implementation,
   'producer',jsonb_build_object('id',r.producer_id,'version',r.producer_version),
   'authorityEpochAfter',r.authority_epoch_after::text,'manifestHash',r.manifest_hash);
 END IF;
 answer:=jsonb_build_object('formatVersion',1,'tenantId',h.tenant_id,'generation',h.generation::text,
  'authorityEpoch',h.authority_epoch::text,'registryId',h.registry_id,'registryVersion',h.registry_version,
  'registryDigest',h.registry_digest,'asOf',gc_authority.utc(date_trunc('milliseconds',transaction_timestamp())),'binding',bound);
 SELECT * INTO again FROM gc_authn.foundation_session_v1(session_hash);
 PERFORM gc_authority.require(auth IS NOT DISTINCT FROM again,'28000');PERFORM gc_authority.tick();
 PERFORM set_config('gc.tenant_id',coalesce(old_t,''),true);PERFORM set_config('gc.actor_id',coalesce(old_a,''),true);RETURN answer;
EXCEPTION WHEN OTHERS THEN
 PERFORM set_config('gc.tenant_id',coalesce(old_t,''),true);PERFORM set_config('gc.actor_id',coalesce(old_a,''),true);RAISE;
END $$;
-- Explicit closure for new routines/types, without rewriting prior object ACLs.
REVOKE ALL ON TYPE gc_authority.classification_producer_installations,gc_authority.classification_producer_heads FROM PUBLIC,gc_app;
DO $$ DECLARE r record;BEGIN
 FOR r IN SELECT p.oid::regprocedure AS signature FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='gc_authority' AND p.proname IN('classification_producer_request_encoding_v1','classification_producer_manifest_encoding_v1',
 'classification_producer_receipt_v1','validate_classification_producer_receipt_v1','validate_classification_producer_write_v1',
 'classification_producer_guard_v1','classification_producer_complete_v1','write_binding_complete_v2',
 'change_reviewed_classification_producer_v1','install_reviewed_classification_producer_v1','revoke_reviewed_classification_producer_v1',
 'load_reviewed_classification_producer_v1') LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,gc_app',r.signature);
 END LOOP;
END $$;
