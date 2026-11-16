-- SPDX-License-Identifier: Apache-2.0
-- Reviewed, immutable reference-code publications with effective-time reads.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls)) OR pg_has_role('gc_app',current_user,'MEMBER') THEN
  RAISE EXCEPTION 'reference forbidden' USING ERRCODE='42501'; END IF;
END $$;

CREATE FUNCTION public.gc_reference_uuid(value jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT coalesce(jsonb_typeof(value)='string' AND public.gc_approval_uuid(value#>>'{}') AND value#>>'{}'<>'00000000-0000-0000-0000-000000000000',false)
$$;
CREATE FUNCTION public.gc_reference_instant(value jsonb,nullable boolean DEFAULT false) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ BEGIN
 IF value='null'::jsonb THEN RETURN nullable; END IF;
 RETURN coalesce(jsonb_typeof(value)='string' AND value#>>'{}' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$'
 AND left(value#>>'{}',4)<>'0000' AND public.gc_relation_utc((value#>>'{}')::timestamptz)=value#>>'{}',false);
 EXCEPTION WHEN data_exception THEN RETURN false;
END $$;
CREATE FUNCTION public.gc_reference_labels(value jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE language text; item jsonb; result jsonb:='{}'; name text; description text; BEGIN
 IF public.gc_relation_keys(value,ARRAY['en','ar']) IS NOT TRUE THEN RETURN NULL; END IF;
 FOREACH language IN ARRAY ARRAY['en','ar'] LOOP
  item:=value->language;
  IF public.gc_relation_keys(item,ARRAY['label','description']) IS NOT TRUE THEN RETURN NULL; END IF;
  name:=public.gc_classification_text(item->'label',240,'display');description:=public.gc_classification_text(item->'description',2048,'multiline');
  IF name IS NULL OR description IS NULL THEN RETURN NULL; END IF;
  result:=result||jsonb_build_object(language,jsonb_build_object('label',name,'description',description));
 END LOOP; RETURN result;
END $$;
CREATE FUNCTION public.gc_reference_audience(value jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE ids jsonb; BEGIN
 IF public.gc_relation_keys(value,ARRAY['visibility','allowedIdentityIds']) IS NOT TRUE
 OR jsonb_typeof(value->'visibility') IS DISTINCT FROM 'string' OR value->>'visibility' NOT IN('tenant','restricted')
 OR jsonb_typeof(value->'allowedIdentityIds') IS DISTINCT FROM 'array' THEN RETURN NULL; END IF;
 IF jsonb_array_length(value->'allowedIdentityIds')>64 OR EXISTS(SELECT 1 FROM jsonb_array_elements(value->'allowedIdentityIds') x WHERE NOT public.gc_reference_uuid(x))
 OR (SELECT count(*)<>count(DISTINCT x) FROM jsonb_array_elements(value->'allowedIdentityIds') x)
 OR (value->>'visibility'='tenant') IS DISTINCT FROM (jsonb_array_length(value->'allowedIdentityIds')=0) THEN RETURN NULL; END IF;
 SELECT coalesce(jsonb_agg(x ORDER BY (x#>>'{}') COLLATE "C"),'[]') INTO ids FROM jsonb_array_elements(value->'allowedIdentityIds') x;
 RETURN jsonb_build_object('visibility',value->'visibility','allowedIdentityIds',ids);
END $$;
CREATE FUNCTION public.gc_reference_release_normalize(value jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE item jsonb; normalized jsonb; rows jsonb:='[]'; labels jsonb; result jsonb; BEGIN
 IF public.gc_relation_keys(value,ARRAY['formatVersion','kind','labels','ownerId','status','activation','validUntil','values']) IS NOT TRUE
 OR value->'formatVersion' IS DISTINCT FROM '1'::jsonb OR value->'kind' IS DISTINCT FROM '"reference-code-list"'::jsonb
 OR NOT public.gc_reference_uuid(value->'ownerId') OR jsonb_typeof(value->'status') IS DISTINCT FROM 'string' OR value->>'status' NOT IN('active','deprecated')
 OR NOT public.gc_reference_instant(value->'validUntil',true) OR jsonb_typeof(value->'values') IS DISTINCT FROM 'array'
 OR octet_length(public.gc_type_migration_canonical(value))>245760 THEN RETURN NULL; END IF;
 IF jsonb_array_length(value->'values') NOT BETWEEN 1 AND 256 THEN RETURN NULL; END IF;
 IF value#>>'{activation,kind}'='on-publication' THEN
  IF public.gc_relation_keys(value->'activation',ARRAY['kind']) IS NOT TRUE THEN RETURN NULL; END IF;
 ELSIF value#>>'{activation,kind}'='at' THEN
  IF public.gc_relation_keys(value->'activation',ARRAY['kind','at']) IS NOT TRUE OR NOT public.gc_reference_instant(value#>'{activation,at}')
  OR (value->'validUntil'<>'null'::jsonb AND (value->>'validUntil')::timestamptz<=(value#>>'{activation,at}')::timestamptz) THEN RETURN NULL; END IF;
 ELSE RETURN NULL; END IF;
 labels:=public.gc_reference_labels(value->'labels');IF labels IS NULL THEN RETURN NULL; END IF;
 FOR item IN SELECT x FROM jsonb_array_elements(value->'values') x LOOP
  IF public.gc_relation_keys(item,ARRAY['code','labels','ownerId','status','validFrom','validUntil']) IS NOT TRUE
  OR jsonb_typeof(item->'code') IS DISTINCT FROM 'string' OR (item->>'code') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
  OR NOT public.gc_reference_uuid(item->'ownerId') OR jsonb_typeof(item->'status') IS DISTINCT FROM 'string' OR item->>'status' NOT IN('active','deprecated')
  OR NOT public.gc_reference_instant(item->'validFrom',true) OR NOT public.gc_reference_instant(item->'validUntil',true)
  OR (item->'validFrom'<>'null'::jsonb AND item->'validUntil'<>'null'::jsonb AND (item->>'validFrom')::timestamptz>=(item->>'validUntil')::timestamptz) THEN RETURN NULL; END IF;
  normalized:=public.gc_reference_labels(item->'labels');IF normalized IS NULL THEN RETURN NULL; END IF;
  rows:=rows||jsonb_build_array(item||jsonb_build_object('labels',normalized));
 END LOOP;
 IF (SELECT count(*)<>count(DISTINCT x->>'code') FROM jsonb_array_elements(rows) x)
 OR (SELECT count(DISTINCT id)>64 FROM (SELECT value->>'ownerId' id UNION ALL SELECT x->>'ownerId' FROM jsonb_array_elements(rows) x) p) THEN RETURN NULL; END IF;
 SELECT jsonb_agg(x ORDER BY (x->>'code') COLLATE "C") INTO rows FROM jsonb_array_elements(rows) x;
 result:=value||jsonb_build_object('labels',labels,'values',rows);
 IF octet_length(public.gc_type_migration_canonical(result))>245760 THEN RETURN NULL; END IF; RETURN result;
 EXCEPTION WHEN data_exception OR check_violation OR program_limit_exceeded THEN RETURN NULL;
END $$;
CREATE FUNCTION public.gc_reference_payload_normalize(value jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE release jsonb; audience jsonb; result jsonb; expected numeric; BEGIN
 IF public.gc_relation_keys(value,ARRAY['formatVersion','kind','setId','expectedVersion','audience','release']) IS NOT TRUE
 OR value->'formatVersion' IS DISTINCT FROM '1'::jsonb OR value->'kind' IS DISTINCT FROM '"reference-publication"'::jsonb
 OR NOT public.gc_reference_uuid(value->'setId') OR jsonb_typeof(value->'expectedVersion') IS DISTINCT FROM 'number' THEN RETURN NULL; END IF;
 expected:=(value->>'expectedVersion')::numeric;IF expected<0 OR expected>2147483646 OR expected<>trunc(expected) THEN RETURN NULL; END IF;
 release:=public.gc_reference_release_normalize(value->'release');audience:=public.gc_reference_audience(value->'audience');
 IF release IS NULL OR audience IS NULL THEN RETURN NULL; END IF;
 IF (SELECT count(DISTINCT id)>64 FROM (SELECT release->>'ownerId' id UNION ALL SELECT x->>'ownerId' FROM jsonb_array_elements(release->'values') x
 UNION ALL SELECT x#>>'{}' FROM jsonb_array_elements(audience->'allowedIdentityIds') x) p) THEN RETURN NULL; END IF;
 result:=value||jsonb_build_object('release',release,'audience',audience);
 IF octet_length(public.gc_type_migration_canonical(result))>262144 THEN RETURN NULL; END IF; RETURN result;
 EXCEPTION WHEN data_exception OR check_violation OR program_limit_exceeded THEN RETURN NULL;
END $$;
CREATE FUNCTION public.gc_reference_bundle_valid(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE release jsonb; BEGIN
 IF public.gc_relation_keys(value,ARRAY['formatVersion','kind','setId','version','labels','ownerId','status','publishedAt','effectiveFrom','validUntil','values']) IS NOT TRUE
 OR NOT public.gc_reference_uuid(value->'setId') OR NOT public.gc_relation_positive_integer(value->'version')
 OR NOT public.gc_reference_instant(value->'publishedAt') OR NOT public.gc_reference_instant(value->'effectiveFrom')
 OR (value->>'effectiveFrom')::timestamptz<(value->>'publishedAt')::timestamptz
 OR octet_length(public.gc_type_migration_canonical(value))>262144 THEN RETURN false; END IF;
 release:=(value-ARRAY['setId','version','publishedAt','effectiveFrom'])||jsonb_build_object('activation',jsonb_build_object('kind','at','at',value->'effectiveFrom'));
 RETURN public.gc_reference_release_normalize(release) IS NOT NULL AND release=public.gc_reference_release_normalize(release);
 EXCEPTION WHEN data_exception OR check_violation OR program_limit_exceeded THEN RETURN false;
END $$;

CREATE TABLE public.reference_sets (
 tenant_id uuid NOT NULL REFERENCES public.tenants(id),id uuid NOT NULL,current_version integer NOT NULL CHECK(current_version>0),
 visibility text NOT NULL,allowed_identities jsonb NOT NULL,created_by uuid NOT NULL,created_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id),
 CHECK(public.gc_reference_audience(jsonb_build_object('visibility',visibility,'allowedIdentityIds',allowed_identities)) IS NOT NULL
 AND public.gc_reference_audience(jsonb_build_object('visibility',visibility,'allowedIdentityIds',allowed_identities))=jsonb_build_object('visibility',visibility,'allowedIdentityIds',allowed_identities))
);
CREATE TABLE public.reference_releases (
 tenant_id uuid NOT NULL,set_id uuid NOT NULL,version integer NOT NULL CHECK(version>0),approval_request_id uuid NOT NULL,
 approved_payload jsonb NOT NULL,proposal_digest text NOT NULL,published_bundle jsonb NOT NULL,publication_hash text NOT NULL,
 published_at timestamptz NOT NULL,effective_from timestamptz NOT NULL,valid_until timestamptz,owner_id uuid NOT NULL,status text NOT NULL,
 created_xid xid8 NOT NULL DEFAULT pg_current_xact_id(),
 PRIMARY KEY(tenant_id,set_id,version),UNIQUE(tenant_id,approval_request_id),
 FOREIGN KEY(tenant_id,set_id) REFERENCES public.reference_sets(tenant_id,id),FOREIGN KEY(tenant_id,approval_request_id) REFERENCES public.approval_requests(tenant_id,id),
 FOREIGN KEY(tenant_id,owner_id) REFERENCES public.memberships(tenant_id,identity_id),
 CHECK(public.gc_reference_bundle_valid(published_bundle) AND publication_hash=public.gc_type_migration_hash(published_bundle)),
 CHECK(approved_payload=public.gc_reference_payload_normalize(approved_payload) AND public.gc_reference_payload_normalize(approved_payload) IS NOT NULL),
 CHECK(published_bundle->>'setId'=set_id::text AND (published_bundle->>'version')::integer=version
 AND published_bundle->>'ownerId'=owner_id::text AND published_bundle->>'status'=status
 AND published_bundle->>'publishedAt'=public.gc_relation_utc(published_at) AND published_bundle->>'effectiveFrom'=public.gc_relation_utc(effective_from)
 AND (published_bundle->>'validUntil') IS NOT DISTINCT FROM public.gc_relation_utc(valid_until))
);
CREATE INDEX reference_effective ON public.reference_releases(tenant_id,set_id,effective_from DESC,version DESC) INCLUDE(published_at,valid_until,status,publication_hash);
ALTER TABLE public.reference_sets ADD CONSTRAINT reference_current_version FOREIGN KEY(tenant_id,id,current_version)
 REFERENCES public.reference_releases(tenant_id,set_id,version) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE public.reference_values (
 tenant_id uuid NOT NULL,set_id uuid NOT NULL,version integer NOT NULL,code text COLLATE "C" NOT NULL,labels jsonb NOT NULL,owner_id uuid NOT NULL,
 status text NOT NULL,valid_from timestamptz,valid_until timestamptz,
 PRIMARY KEY(tenant_id,set_id,version,code),FOREIGN KEY(tenant_id,set_id,version) REFERENCES public.reference_releases(tenant_id,set_id,version),
 FOREIGN KEY(tenant_id,owner_id) REFERENCES public.memberships(tenant_id,identity_id)
);
DO $$ DECLARE name text; BEGIN
 FOREACH name IN ARRAY ARRAY['reference_sets','reference_releases','reference_values'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',name);EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.gc_tenant()) WITH CHECK(tenant_id=public.gc_tenant())',name);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC,gc_app',name);EXECUTE format('GRANT SELECT ON public.%I TO gc_app',name);
 END LOOP;
 FOREACH name IN ARRAY ARRAY['reference_releases','reference_values'] LOOP
  EXECUTE format('CREATE TRIGGER reference_immutable BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.gc_immutable_audit()',name);
 END LOOP;
END $$;
CREATE TRIGGER reference_head_guard BEFORE UPDATE OR DELETE ON public.reference_sets FOR EACH ROW EXECUTE FUNCTION public.gc_classification_head_guard();

CREATE FUNCTION public.gc_reference_actor_can(audience jsonb,actor uuid,permission_name text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id WHERE m.tenant_id=public.gc_tenant()
 AND m.identity_id=actor AND m.active AND i.active AND m.permissions @> to_jsonb(ARRAY['catalog:read','reference:read',permission_name])
 AND (audience->>'visibility'='tenant' OR audience->'allowedIdentityIds' @> to_jsonb(ARRAY[actor::text])))
$$;
CREATE FUNCTION public.gc_reference_visible(set_identity uuid,actor_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM public.reference_sets s WHERE s.tenant_id=public.gc_tenant() AND s.id=set_identity
 AND public.gc_reference_actor_can(jsonb_build_object('visibility',s.visibility,'allowedIdentityIds',s.allowed_identities),actor_identity,'reference:read'))
$$;
CREATE FUNCTION public.gc_reference_request_visible(request_identity uuid,actor_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM public.approval_requests r WHERE r.tenant_id=public.gc_tenant() AND r.id=request_identity AND r.binding='reference.publish'
 AND public.gc_reference_actor_can(r.payload->'audience',actor_identity,'reference:read')
 AND (NOT EXISTS(SELECT 1 FROM public.reference_sets s WHERE s.tenant_id=r.tenant_id AND s.id=r.resource_id)
 OR public.gc_reference_visible(r.resource_id,actor_identity)))
$$;
CREATE FUNCTION public.gc_reference_payload_current(value jsonb) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE h public.reference_sets; BEGIN
 IF public.gc_reference_payload_normalize(value) IS NULL OR value IS DISTINCT FROM public.gc_reference_payload_normalize(value) THEN RETURN false; END IF;
 SELECT * INTO h FROM public.reference_sets WHERE tenant_id=public.gc_tenant() AND id=(value->>'setId')::uuid;
 IF coalesce(h.current_version,0)<>(value->>'expectedVersion')::integer OR (h.id IS NOT NULL AND jsonb_build_object('visibility',h.visibility,'allowedIdentityIds',h.allowed_identities)<>value->'audience') THEN RETURN false; END IF;
 RETURN NOT EXISTS(SELECT 1 FROM (SELECT (value#>>'{release,ownerId}')::uuid id UNION SELECT (v->>'ownerId')::uuid FROM jsonb_array_elements(value#>'{release,values}') v
 UNION SELECT (v#>>'{}')::uuid FROM jsonb_array_elements(value#>'{audience,allowedIdentityIds}') v) p
 WHERE NOT EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id WHERE m.tenant_id=public.gc_tenant() AND m.identity_id=p.id AND m.active AND i.active));
 EXCEPTION WHEN data_exception OR check_violation OR program_limit_exceeded THEN RETURN false;
END $$;
CREATE FUNCTION public.gc_reference_lock_review(request_identity uuid) RETURNS public.approval_requests
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE r public.approval_requests;principal uuid;principals uuid[]; BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(public.gc_tenant()::text,0));
 SELECT * INTO r FROM public.approval_requests WHERE tenant_id=public.gc_tenant() AND id=request_identity AND binding='reference.publish';
 IF NOT FOUND THEN RAISE EXCEPTION 'reference resource not found' USING ERRCODE='P0002';END IF;
 SELECT array_agg(DISTINCT id ORDER BY id) INTO principals FROM (
  SELECT r.requester_id id UNION SELECT assigned_identity_id FROM public.approval_tasks WHERE tenant_id=r.tenant_id AND request_id=r.id
  UNION SELECT (r.payload#>>'{release,ownerId}')::uuid UNION SELECT (v->>'ownerId')::uuid FROM jsonb_array_elements(r.payload#>'{release,values}') v
  UNION SELECT (v#>>'{}')::uuid FROM jsonb_array_elements(r.payload#>'{audience,allowedIdentityIds}') v) p;
 IF cardinality(principals)>64 THEN RAISE EXCEPTION 'reference limit' USING ERRCODE='54000';END IF;
 FOR principal IN SELECT id FROM public.identities WHERE id=ANY(principals) ORDER BY id FOR SHARE LOOP NULL;END LOOP;
 FOR principal IN SELECT identity_id FROM public.memberships WHERE tenant_id=r.tenant_id AND identity_id=ANY(principals) ORDER BY identity_id FOR SHARE LOOP NULL;END LOOP;
 PERFORM 1 FROM public.reference_sets WHERE tenant_id=r.tenant_id AND id=r.resource_id FOR UPDATE;
 RETURN r;
END $$;
CREATE FUNCTION public.gc_reference_review_authorized(r public.approval_requests) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT r.binding='reference.publish' AND r.tenant_id=public.gc_tenant()
 AND public.gc_reference_actor_can(r.payload->'audience',r.requester_id,'reference:write')
 AND public.gc_reference_request_visible(r.id,r.requester_id)
 AND NOT EXISTS(SELECT 1 FROM public.approval_tasks t WHERE t.tenant_id=r.tenant_id AND t.request_id=r.id
 AND (t.assigned_identity_id=r.requester_id OR NOT public.gc_reference_actor_can(r.payload->'audience',t.assigned_identity_id,'reference:approve')))
$$;

ALTER TABLE public.approval_requests DROP CONSTRAINT approval_requests_binding_check;
ALTER TABLE public.approval_requests ADD CONSTRAINT approval_requests_binding_check CHECK(binding IN('glossary.publish','classification.review','reference.publish'));
CREATE FUNCTION public.gc_reference_command(operation text,command_key text,body jsonb,correlation text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant(); actor uuid; old public.idempotency; payload jsonb; normalized jsonb; w public.workflow_definition_versions;
 h public.reference_sets; keys text[]; reviewers uuid[]; principals uuid[]; stage jsonb; assignment text; stamp timestamptz; expiry timestamptz;
 request_id uuid; hash text; result jsonb; BEGIN
 IF operation IS DISTINCT FROM 'reference.propose' OR command_key IS NULL OR length(command_key) NOT BETWEEN 8 AND 128 OR command_key ~ '[[:cntrl:]]'
 OR correlation IS NULL OR length(correlation) NOT BETWEEN 1 AND 128 OR correlation ~ '[[:cntrl:]]'
 OR public.gc_relation_keys(body,ARRAY['id','setId','expectedVersion','audience','release','workflow','assignments','expiresAt']) IS NOT TRUE
 OR octet_length(public.gc_type_migration_canonical(body))>327680 OR NOT public.gc_reference_uuid(body->'id')
 OR public.gc_relation_keys(body->'workflow',ARRAY['id','version','definitionHash']) IS NOT TRUE
 OR jsonb_typeof(body#>'{workflow,id}') IS DISTINCT FROM 'string' OR NOT public.gc_relation_safe_id(body#>>'{workflow,id}')
 OR NOT public.gc_relation_positive_integer(body#>'{workflow,version}') OR jsonb_typeof(body#>'{workflow,definitionHash}') IS DISTINCT FROM 'string'
 OR body#>>'{workflow,definitionHash}' !~ '^[a-f0-9]{64}$' OR jsonb_typeof(body->'assignments') IS DISTINCT FROM 'object'
 OR NOT public.gc_reference_instant(body->'expiresAt') THEN RAISE EXCEPTION 'reference request invalid' USING ERRCODE='22023'; END IF;
 payload:=public.gc_reference_payload_normalize(jsonb_build_object('formatVersion',1,'kind','reference-publication','setId',body->'setId','expectedVersion',body->'expectedVersion','audience',body->'audience','release',body->'release'));
 IF payload IS NULL OR (SELECT count(*) FROM jsonb_object_keys(body->'assignments')) NOT BETWEEN 1 AND 64
 OR EXISTS(SELECT 1 FROM jsonb_each(body->'assignments') a WHERE NOT public.gc_relation_safe_id(a.key) OR NOT public.gc_reference_uuid(a.value)) THEN RAISE EXCEPTION 'reference request invalid' USING ERRCODE='22023'; END IF;
 normalized:=body||jsonb_build_object('release',payload->'release','audience',payload->'audience');
 PERFORM public.gc_relation_authorize(ARRAY['catalog:read','reference:read','reference:write']);actor:=public.gc_actor()::uuid;
 IF NOT public.gc_reference_actor_can(payload->'audience',actor,'reference:write') THEN RAISE EXCEPTION 'reference forbidden' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text||actor::text||operation||command_key,0));
 hash:=public.gc_type_migration_hash(normalized);
 SELECT * INTO old FROM public.idempotency WHERE tenant_id=tenant AND actor_id=actor::text AND idempotency.operation=gc_reference_command.operation AND key=command_key;
 IF FOUND THEN
  PERFORM public.gc_lock_type_migration_principals(ARRAY[]::uuid[]);PERFORM public.gc_relation_authorize(ARRAY['catalog:read','reference:read','reference:write']);
  IF NOT public.gc_reference_request_visible((body->>'id')::uuid,actor) OR NOT EXISTS(SELECT 1 FROM public.approval_requests WHERE tenant_id=tenant AND id=(body->>'id')::uuid AND requester_id=actor) THEN RAISE EXCEPTION 'reference resource not found' USING ERRCODE='P0002';END IF;
  IF old.request_hash<>hash THEN RAISE EXCEPTION 'IDEMPOTENCY_CONFLICT' USING ERRCODE='40001';END IF; RETURN old.response;
 END IF;
 SELECT v.* INTO w FROM public.workflow_definition_versions v JOIN public.workflow_definitions head ON head.tenant_id=v.tenant_id AND head.id=v.workflow_id AND head.current_version=v.version
 WHERE v.tenant_id=tenant AND v.workflow_id=body#>>'{workflow,id}' AND v.version=(body#>>'{workflow,version}')::integer AND v.definition_hash=body#>>'{workflow,definitionHash}';
 IF NOT FOUND THEN RAISE EXCEPTION 'WORKFLOW_PIN_STALE' USING ERRCODE='40001';END IF;
 IF w.definition->>'separationOfDuties'<>'true' THEN RAISE EXCEPTION 'reference request invalid' USING ERRCODE='22023';END IF;
 SELECT array_agg(DISTINCT a#>>'{}' ORDER BY a#>>'{}') INTO keys FROM jsonb_array_elements(w.definition->'stages') s CROSS JOIN LATERAL jsonb_array_elements(s->'assignments') a;
 IF (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(body->'assignments') k) IS DISTINCT FROM keys THEN RAISE EXCEPTION 'reference request invalid' USING ERRCODE='22023';END IF;
 SELECT array_agg(DISTINCT (a.value#>>'{}')::uuid ORDER BY (a.value#>>'{}')::uuid) INTO reviewers FROM jsonb_each(body->'assignments') a;
 IF actor=ANY(reviewers) OR cardinality(reviewers)<>cardinality(keys) THEN RAISE EXCEPTION 'reference forbidden' USING ERRCODE='42501';END IF;
 SELECT array_agg(DISTINCT id ORDER BY id) INTO principals FROM (SELECT actor id UNION SELECT unnest(reviewers)
 UNION SELECT (payload#>>'{release,ownerId}')::uuid UNION SELECT (v->>'ownerId')::uuid FROM jsonb_array_elements(payload#>'{release,values}') v
 UNION SELECT (v#>>'{}')::uuid FROM jsonb_array_elements(payload#>'{audience,allowedIdentityIds}') v) p;
 IF cardinality(principals)>64 THEN RAISE EXCEPTION 'reference limit' USING ERRCODE='54000';END IF;
 PERFORM public.gc_lock_type_migration_principals(principals);
 SELECT * INTO h FROM public.reference_sets WHERE tenant_id=tenant AND id=(payload->>'setId')::uuid FOR UPDATE;
 PERFORM public.gc_relation_authorize(ARRAY['catalog:read','reference:read','reference:write']);
 IF NOT public.gc_reference_actor_can(payload->'audience',actor,'reference:write') OR EXISTS(SELECT 1 FROM unnest(reviewers) p WHERE NOT public.gc_reference_actor_can(payload->'audience',p,'reference:approve')) THEN RAISE EXCEPTION 'reference forbidden' USING ERRCODE='42501';END IF;
 IF h.id IS NOT NULL AND NOT public.gc_reference_visible(h.id,actor) THEN RAISE EXCEPTION 'reference resource not found' USING ERRCODE='P0002';END IF;
 IF NOT public.gc_reference_payload_current(payload) THEN RAISE EXCEPTION 'reference version conflict' USING ERRCODE='40001';END IF;
 stamp:=date_trunc('milliseconds',clock_timestamp());expiry:=(body->>'expiresAt')::timestamptz;
 IF expiry<=stamp OR expiry>stamp+interval '366 days' THEN RAISE EXCEPTION 'reference request invalid' USING ERRCODE='22023';END IF;
 IF (payload#>>'{release,activation,kind}'='at' AND (payload#>>'{release,activation,at}')::timestamptz<=stamp)
 OR (payload#>'{release,validUntil}'<>'null'::jsonb AND (payload#>>'{release,validUntil}')::timestamptz<=stamp) THEN RAISE EXCEPTION 'reference schedule stale' USING ERRCODE='40001';END IF;
 request_id:=(body->>'id')::uuid;
 hash:=public.gc_type_migration_hash(jsonb_build_object('id',request_id,'binding','reference.publish','payload',payload,'workflow',body->'workflow','assignments',body->'assignments','expiresAt',body->'expiresAt'));
 INSERT INTO public.approval_requests(tenant_id,id,binding,resource_id,resource_version,payload,proposal_digest,workflow_id,workflow_version,workflow_hash,requester_id,status,expires_at,created_at,updated_at)
 VALUES(tenant,request_id,'reference.publish',(payload->>'setId')::uuid,nullif((payload->>'expectedVersion')::integer,0),payload,hash,w.workflow_id,w.version,w.definition_hash,actor,'pending',expiry,stamp,stamp);
 FOR stage IN SELECT s.value||jsonb_build_object('_ordinal',s.ordinality-1) FROM jsonb_array_elements(w.definition->'stages') WITH ORDINALITY s LOOP
  FOR assignment IN SELECT a#>>'{}' FROM jsonb_array_elements(stage->'assignments') a LOOP
   INSERT INTO public.approval_tasks(tenant_id,id,request_id,stage_index,assignment,assigned_identity_id,status,opened_at,expires_at)
   VALUES(tenant,gen_random_uuid(),request_id,(stage->>'_ordinal')::integer,assignment,(body->'assignments'->>assignment)::uuid,
   CASE WHEN stage->>'_ordinal'='0' THEN 'open' ELSE 'waiting' END,CASE WHEN stage->>'_ordinal'='0' THEN stamp END,
   CASE WHEN stage->>'_ordinal'='0' THEN least(expiry,stamp+make_interval(secs=>(stage->>'deadlineSeconds')::integer)) END);
  END LOOP;
 END LOOP;
 PERFORM public.gc_approval_journal('approval.submitted',request_id,request_id::text,1,jsonb_build_object('binding','reference.publish','proposalDigest',hash,'workflowId',w.workflow_id,'workflowVersion',w.version),correlation,true);
 result:=jsonb_build_object('instance',jsonb_build_object('id',request_id));
 INSERT INTO public.idempotency(tenant_id,actor_id,operation,key,request_hash,response) VALUES(tenant,actor::text,operation,command_key,public.gc_type_migration_hash(normalized),result);
 RETURN result;
END $$;

CREATE FUNCTION public.gc_reference_publish(request_identity uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE r public.approval_requests; h public.reference_sets; prior public.reference_releases; w jsonb; release jsonb; bundle jsonb; publication_result jsonb;
 stamp timestamptz; effective timestamptz; expiry timestamptz; expected integer; item jsonb; BEGIN
 r:=public.gc_reference_lock_review(request_identity);
 PERFORM public.gc_relation_authorize(ARRAY['catalog:read','reference:read','reference:write']);
 IF public.gc_actor() IS DISTINCT FROM r.requester_id::text OR NOT public.gc_reference_review_authorized(r) THEN RAISE EXCEPTION 'reference forbidden' USING ERRCODE='42501';END IF;
 -- Retained success is authorized before new-head or effective-time checks.
 IF r.status='succeeded' THEN RETURN r.result;END IF;
 IF r.status<>'ready' THEN RAISE EXCEPTION 'reference version conflict' USING ERRCODE='40001';END IF;
 stamp:=date_trunc('milliseconds',clock_timestamp());IF r.expires_at<=stamp THEN RAISE EXCEPTION 'reference approval expired' USING ERRCODE='40001';END IF;
 SELECT definition INTO w FROM public.workflow_definition_versions WHERE tenant_id=r.tenant_id AND workflow_id=r.workflow_id AND version=r.workflow_version AND definition_hash=r.workflow_hash;
 IF w IS NULL THEN RAISE EXCEPTION 'WORKFLOW_PIN_STALE' USING ERRCODE='40001';END IF;
 IF w->>'separationOfDuties'<>'true' OR EXISTS(SELECT 1 FROM public.approval_decisions WHERE tenant_id=r.tenant_id AND request_id=r.id AND decision='reject')
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(w->'stages') WITH ORDINALITY s(v,n) WHERE (SELECT count(*) FROM public.approval_decisions d JOIN public.approval_tasks t ON t.tenant_id=d.tenant_id AND t.id=d.task_id
 WHERE d.tenant_id=r.tenant_id AND d.request_id=r.id AND t.stage_index=s.n-1 AND d.decision='approve' AND d.actor_id=t.assigned_identity_id AND d.actor_id<>r.requester_id AND d.proposal_digest=r.proposal_digest)<(s.v->>'quorum')::integer)
 THEN RAISE EXCEPTION 'reference approval invalid' USING ERRCODE='23514';END IF;
 IF NOT public.gc_reference_payload_current(r.payload) THEN RAISE EXCEPTION 'reference version conflict' USING ERRCODE='40001';END IF;
 release:=r.payload->'release';expected:=(r.payload->>'expectedVersion')::integer;
 IF expected>=2147483647 THEN RAISE EXCEPTION 'reference limit' USING ERRCODE='54000';END IF;
 SELECT * INTO h FROM public.reference_sets WHERE tenant_id=r.tenant_id AND id=r.resource_id;
 SELECT * INTO prior FROM public.reference_releases WHERE tenant_id=r.tenant_id AND set_id=r.resource_id AND version=expected;
 effective:=CASE WHEN release#>>'{activation,kind}'='on-publication' THEN stamp ELSE (release#>>'{activation,at}')::timestamptz END;
 expiry:=(release->>'validUntil')::timestamptz;
 IF (release#>>'{activation,kind}'='at' AND effective<=stamp) OR (prior.set_id IS NOT NULL AND (effective<=prior.effective_from OR stamp<prior.published_at))
 OR (expiry IS NOT NULL AND expiry<=effective) THEN RAISE EXCEPTION 'reference schedule stale' USING ERRCODE='40001';END IF;
 bundle:=(release-'activation')||jsonb_build_object('setId',r.resource_id,'version',expected+1,'publishedAt',public.gc_relation_utc(stamp),'effectiveFrom',public.gc_relation_utc(effective));
 IF NOT public.gc_reference_bundle_valid(bundle) THEN RAISE EXCEPTION 'reference storage invalid' USING ERRCODE='23514';END IF;
 IF expected=0 THEN
  INSERT INTO public.reference_sets VALUES(r.tenant_id,r.resource_id,1,r.payload#>>'{audience,visibility}',r.payload#>'{audience,allowedIdentityIds}',r.requester_id,stamp);
 ELSE UPDATE public.reference_sets SET current_version=expected+1 WHERE tenant_id=r.tenant_id AND id=r.resource_id AND current_version=expected;END IF;
 INSERT INTO public.reference_releases(tenant_id,set_id,version,approval_request_id,approved_payload,proposal_digest,published_bundle,publication_hash,published_at,effective_from,valid_until,owner_id,status)
 VALUES(r.tenant_id,r.resource_id,expected+1,r.id,r.payload,r.proposal_digest,bundle,public.gc_type_migration_hash(bundle),stamp,effective,expiry,(release->>'ownerId')::uuid,release->>'status');
 FOR item IN SELECT v FROM jsonb_array_elements(release->'values') v LOOP
  INSERT INTO public.reference_values VALUES(r.tenant_id,r.resource_id,expected+1,item->>'code',item->'labels',(item->>'ownerId')::uuid,item->>'status',(item->>'validFrom')::timestamptz,(item->>'validUntil')::timestamptz);
 END LOOP;
 publication_result:=jsonb_build_object('binding','reference.publish','setId',r.resource_id,'version',expected+1,'publicationHash',public.gc_type_migration_hash(bundle),'publishedAt',public.gc_relation_utc(stamp),'effectiveFrom',public.gc_relation_utc(effective));
 UPDATE public.approval_requests SET status='succeeded',version=version+1,result=publication_result,updated_at=stamp WHERE tenant_id=r.tenant_id AND id=r.id;
 PERFORM public.gc_approval_journal('reference.published',NULL,r.resource_id::text,expected+1,jsonb_build_object('approvalInstanceId',r.id,'publicationHash',public.gc_type_migration_hash(bundle),'proposalDigest',r.proposal_digest),'reference:'||r.id::text);
 PERFORM public.gc_approval_journal('approval.succeeded',NULL,r.id::text,r.version+1,jsonb_build_object('binding','reference.publish','setId',r.resource_id,'version',expected+1,'proposalDigest',r.proposal_digest),'reference:'||r.id::text);
 RETURN publication_result;
END $$;
CREATE FUNCTION public.gc_reference_fail(request_identity uuid,ready_version integer,code text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE r public.approval_requests; BEGIN
 IF public.gc_actor() IS DISTINCT FROM 'site:local' OR code IS NULL OR code NOT IN('REFERENCE_AUTHORITY_REVOKED','REFERENCE_PRECONDITIONS_CHANGED','REFERENCE_EXPIRED','REFERENCE_APPROVAL_INVALID') THEN RAISE EXCEPTION 'reference forbidden' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(public.gc_tenant()::text,0));
 SELECT * INTO r FROM public.approval_requests WHERE tenant_id=public.gc_tenant() AND id=request_identity AND binding='reference.publish' AND status='ready' AND version=ready_version;
 IF NOT FOUND THEN RETURN;END IF;
 UPDATE public.approval_requests SET status='failed',version=version+1,error_code=code,updated_at=date_trunc('milliseconds',clock_timestamp()) WHERE tenant_id=r.tenant_id AND id=r.id;
 PERFORM public.gc_approval_journal('approval.failed',NULL,r.id::text,r.version+1,jsonb_build_object('code',code,'proposalDigest',r.proposal_digest),'reference:'||r.id::text);
END $$;

CREATE FUNCTION public.gc_approval_command_pre_reference(operation text,command_key text,body jsonb,correlation text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant();actor uuid;r public.approval_requests;t public.approval_tasks;old public.idempotency;hash text;result jsonb;stamp timestamptz;reason text;decision_id uuid;required text[];BEGIN
 -- The binding comes only from the current canonical request. Neither generic
 -- submit nor an unknown operation can enter the classification effect family.
 IF operation NOT IN('approval.decide','approval.cancel') OR NOT public.gc_approval_uuid(body->>'requestId') OR NOT EXISTS(
  SELECT 1 FROM public.approval_requests WHERE tenant_id=tenant AND id=(body->>'requestId')::uuid AND binding='classification.review') THEN
  RETURN public.gc_approval_command_glossary_legacy(operation,command_key,body,correlation);
 END IF;
 IF command_key IS NULL OR length(command_key) NOT BETWEEN 8 AND 128 OR command_key ~ '[[:cntrl:]]' OR correlation IS NULL OR length(correlation) NOT BETWEEN 1 AND 128 OR correlation ~ '[[:cntrl:]]'
 OR body IS NULL OR octet_length(body::text)>16384 OR public.gc_relation_keys(body,CASE WHEN operation='approval.cancel' THEN ARRAY['requestId','proposalDigest','reason'] ELSE ARRAY['requestId','proposalDigest','taskId','taskVersion','decision','reason'] END) IS NOT TRUE
 OR jsonb_typeof(body->'proposalDigest') IS DISTINCT FROM 'string' OR body->>'proposalDigest' !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023';END IF;
 required:=ARRAY['catalog:read','classification:read',CASE WHEN operation='approval.cancel' THEN 'classification:write' ELSE 'classification:approve' END];
 PERFORM public.gc_relation_authorize(required);actor:=public.gc_actor()::uuid;
 r:=public.gc_classification_lock_review((body->>'requestId')::uuid);PERFORM public.gc_relation_authorize(required);
 IF NOT public.gc_classification_visible(r.resource_id,actor) OR (r.requester_id<>actor AND NOT EXISTS(SELECT 1 FROM public.approval_tasks WHERE tenant_id=tenant AND request_id=r.id AND assigned_identity_id=actor))
 OR (operation='approval.cancel' AND r.requester_id<>actor) THEN RAISE EXCEPTION 'classification resource not found' USING ERRCODE='P0002';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text||actor::text||operation||command_key,0));hash:=public.gc_type_migration_hash(body);
 SELECT * INTO old FROM public.idempotency WHERE tenant_id=tenant AND actor_id=actor::text AND idempotency.operation=gc_approval_command_pre_reference.operation AND key=command_key;
 IF FOUND THEN IF old.request_hash<>hash THEN RAISE EXCEPTION 'IDEMPOTENCY_CONFLICT' USING ERRCODE='40001';END IF;RETURN old.response;END IF;
 stamp:=date_trunc('milliseconds',clock_timestamp());
 IF r.status<>'pending' OR r.expires_at<=stamp OR r.proposal_digest IS DISTINCT FROM body->>'proposalDigest' THEN RAISE EXCEPTION 'APPROVAL_STATE_CONFLICT' USING ERRCODE='40001';END IF;
 reason:=public.gc_classification_text(body->'reason',4096,'multiline');IF reason IS NULL THEN RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023';END IF;
 IF operation='approval.cancel' THEN
  UPDATE public.approval_requests SET status='cancelled',version=version+1,updated_at=stamp WHERE tenant_id=tenant AND id=r.id;
  UPDATE public.approval_tasks SET status='cancelled',version=version+1 WHERE tenant_id=tenant AND request_id=r.id AND status IN('open','waiting');
 ELSE
  IF NOT public.gc_approval_uuid(body->>'taskId') OR NOT public.gc_relation_positive_integer(body->'taskVersion') OR jsonb_typeof(body->'decision') IS DISTINCT FROM 'string' OR body->>'decision' NOT IN('approve','reject') THEN RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023';END IF;
  SELECT * INTO t FROM public.approval_tasks WHERE tenant_id=tenant AND request_id=r.id AND id=(body->>'taskId')::uuid;
  IF t.id IS NULL OR t.assigned_identity_id<>actor OR actor=r.requester_id OR t.version<>(body->>'taskVersion')::integer OR t.stage_index<>r.stage_index OR t.status<>'open' OR t.expires_at<=stamp THEN RAISE EXCEPTION 'APPROVAL_TASK_CONFLICT' USING ERRCODE='40001';END IF;
  IF NOT public.gc_classification_review_authorized(r) THEN RAISE EXCEPTION 'classification forbidden' USING ERRCODE='42501';END IF;
  IF NOT public.gc_classification_payload_current(r.payload) THEN RAISE EXCEPTION 'classification evidence stale' USING ERRCODE='40001';END IF;
  decision_id:=gen_random_uuid();INSERT INTO public.approval_decisions VALUES(tenant,decision_id,r.id,t.id,t.version,r.proposal_digest,actor,body->>'decision',reason,stamp);
  UPDATE public.approval_tasks SET status='decided',version=version+1 WHERE tenant_id=tenant AND id=t.id;
  UPDATE public.approval_requests SET version=version+1,updated_at=stamp WHERE tenant_id=tenant AND id=r.id;
 END IF;
 PERFORM public.gc_approval_journal(CASE WHEN operation='approval.cancel' THEN 'approval.cancelled' ELSE 'approval.decided' END,r.id,r.id::text,r.version+1,
 jsonb_build_object('proposalDigest',r.proposal_digest,'taskId',t.id,'decisionId',decision_id,'decision',body->>'decision','reason',reason),correlation,true);
 result:=jsonb_build_object('request',public.gc_approval_request_view(r.id));
 INSERT INTO public.idempotency(tenant_id,actor_id,operation,key,request_hash,response) VALUES(tenant,actor::text,operation,command_key,hash,result);RETURN result;
END $$;
CREATE FUNCTION public.gc_approval_tick_pre_reference(request_identity uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE r public.approval_requests;w jsonb;s jsonb;stamp timestamptz;deadline timestamptz;outcome text:='pending';error text;approvals integer;BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.approval_requests WHERE tenant_id=public.gc_tenant() AND id=request_identity AND binding='classification.review') THEN RETURN public.gc_approval_tick_glossary_legacy(request_identity);END IF;
 r:=public.gc_classification_lock_review(request_identity);
 IF r.status<>'pending' THEN RETURN jsonb_build_object('id',r.id,'status',r.status,'version',r.version,'nextWakeAt',NULL);END IF;
 SELECT definition INTO w FROM public.workflow_definition_versions WHERE tenant_id=r.tenant_id AND workflow_id=r.workflow_id AND version=r.workflow_version AND definition_hash=r.workflow_hash;
 s:=w->'stages'->r.stage_index;stamp:=date_trunc('milliseconds',clock_timestamp());
 SELECT min(expires_at) INTO deadline FROM public.approval_tasks WHERE tenant_id=r.tenant_id AND request_id=r.id AND stage_index=r.stage_index;
 IF stamp>=least(r.expires_at,deadline) THEN outcome:='expired';
 ELSIF NOT public.gc_classification_review_authorized(r) THEN outcome:='cancelled';error:='CLASSIFICATION_AUTHORITY_REVOKED';
 ELSIF EXISTS(SELECT 1 FROM public.approval_decisions d JOIN public.approval_tasks t ON t.tenant_id=d.tenant_id AND t.id=d.task_id WHERE d.tenant_id=r.tenant_id AND d.request_id=r.id AND t.stage_index=r.stage_index AND d.decision='reject') THEN outcome:='rejected';
 ELSE
  SELECT count(*) INTO approvals FROM public.approval_decisions d JOIN public.approval_tasks t ON t.tenant_id=d.tenant_id AND t.id=d.task_id WHERE d.tenant_id=r.tenant_id AND d.request_id=r.id AND t.stage_index=r.stage_index AND d.decision='approve';
  IF approvals>=(s->>'quorum')::integer THEN
   UPDATE public.approval_tasks SET status='cancelled',version=version+1 WHERE tenant_id=r.tenant_id AND request_id=r.id AND stage_index=r.stage_index AND status='open';
   IF r.stage_index+1=jsonb_array_length(w->'stages') THEN outcome:='ready';
   ELSE
    s:=w->'stages'->(r.stage_index+1);deadline:=least(r.expires_at,stamp+make_interval(secs=>(s->>'deadlineSeconds')::integer));
    UPDATE public.approval_tasks SET status='open',version=version+1,opened_at=stamp,expires_at=deadline WHERE tenant_id=r.tenant_id AND request_id=r.id AND stage_index=r.stage_index+1 AND status='waiting';
    UPDATE public.approval_requests SET stage_index=stage_index+1,version=version+1,updated_at=stamp WHERE tenant_id=r.tenant_id AND id=r.id;
    PERFORM public.gc_approval_journal('approval.stage_opened',r.id,r.id::text,r.version+1,jsonb_build_object('stageIndex',r.stage_index+1),'workflow:'||r.id::text);
    RETURN jsonb_build_object('id',r.id,'status','pending','version',r.version+1,'nextWakeAt',public.gc_relation_utc(deadline));
   END IF;
  END IF;
 END IF;
 IF outcome<>'pending' THEN
  UPDATE public.approval_requests SET status=outcome,version=version+1,updated_at=stamp,error_code=error WHERE tenant_id=r.tenant_id AND id=r.id;
  UPDATE public.approval_tasks SET status='cancelled',version=version+1 WHERE tenant_id=r.tenant_id AND request_id=r.id AND status IN('open','waiting');
  PERFORM public.gc_approval_journal('approval.'||outcome,r.id,r.id::text,r.version+1,jsonb_build_object('proposalDigest',r.proposal_digest),'workflow:'||r.id::text);
 END IF;
 RETURN jsonb_build_object('id',r.id,'status',outcome,'version',r.version+CASE WHEN outcome='pending' THEN 0 ELSE 1 END,'nextWakeAt',CASE WHEN outcome='pending' THEN public.gc_relation_utc(least(r.expires_at,deadline)) END);
END $$;
CREATE OR REPLACE FUNCTION public.gc_approval_command(operation text,command_key text,body jsonb,correlation text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant();actor uuid;r public.approval_requests;t public.approval_tasks;old public.idempotency;hash text;result jsonb;stamp timestamptz;reason text;decision_id uuid;required text[];BEGIN
 -- The binding comes only from the current canonical request. Neither generic
 -- submit nor an unknown operation can enter the classification effect family.
 IF operation NOT IN('approval.decide','approval.cancel') OR NOT public.gc_approval_uuid(body->>'requestId') OR NOT EXISTS(
  SELECT 1 FROM public.approval_requests WHERE tenant_id=tenant AND id=(body->>'requestId')::uuid AND binding='reference.publish') THEN
  RETURN public.gc_approval_command_pre_reference(operation,command_key,body,correlation);
 END IF;
 IF command_key IS NULL OR length(command_key) NOT BETWEEN 8 AND 128 OR command_key ~ '[[:cntrl:]]' OR correlation IS NULL OR length(correlation) NOT BETWEEN 1 AND 128 OR correlation ~ '[[:cntrl:]]'
 OR body IS NULL OR octet_length(body::text)>16384 OR public.gc_relation_keys(body,CASE WHEN operation='approval.cancel' THEN ARRAY['requestId','proposalDigest','reason'] ELSE ARRAY['requestId','proposalDigest','taskId','taskVersion','decision','reason'] END) IS NOT TRUE
 OR jsonb_typeof(body->'proposalDigest') IS DISTINCT FROM 'string' OR body->>'proposalDigest' !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'reference request invalid' USING ERRCODE='22023';END IF;
 required:=ARRAY['catalog:read','reference:read',CASE WHEN operation='approval.cancel' THEN 'reference:write' ELSE 'reference:approve' END];
 PERFORM public.gc_relation_authorize(required);actor:=public.gc_actor()::uuid;
 r:=public.gc_reference_lock_review((body->>'requestId')::uuid);PERFORM public.gc_relation_authorize(required);
 IF NOT public.gc_reference_request_visible(r.id,actor) OR (r.requester_id<>actor AND NOT EXISTS(SELECT 1 FROM public.approval_tasks WHERE tenant_id=tenant AND request_id=r.id AND assigned_identity_id=actor))
 OR (operation='approval.cancel' AND r.requester_id<>actor) THEN RAISE EXCEPTION 'reference resource not found' USING ERRCODE='P0002';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text||actor::text||operation||command_key,0));hash:=public.gc_type_migration_hash(body);
 SELECT * INTO old FROM public.idempotency WHERE tenant_id=tenant AND actor_id=actor::text AND idempotency.operation=gc_approval_command.operation AND key=command_key;
 IF FOUND THEN IF old.request_hash<>hash THEN RAISE EXCEPTION 'IDEMPOTENCY_CONFLICT' USING ERRCODE='40001';END IF;RETURN old.response;END IF;
 stamp:=date_trunc('milliseconds',clock_timestamp());
 IF r.status<>'pending' OR r.expires_at<=stamp OR r.proposal_digest IS DISTINCT FROM body->>'proposalDigest' THEN RAISE EXCEPTION 'APPROVAL_STATE_CONFLICT' USING ERRCODE='40001';END IF;
 reason:=public.gc_classification_text(body->'reason',4096,'multiline');IF reason IS NULL THEN RAISE EXCEPTION 'reference request invalid' USING ERRCODE='22023';END IF;
 IF operation='approval.cancel' THEN
  UPDATE public.approval_requests SET status='cancelled',version=version+1,updated_at=stamp WHERE tenant_id=tenant AND id=r.id;
  UPDATE public.approval_tasks SET status='cancelled',version=version+1 WHERE tenant_id=tenant AND request_id=r.id AND status IN('open','waiting');
 ELSE
  IF NOT public.gc_approval_uuid(body->>'taskId') OR NOT public.gc_relation_positive_integer(body->'taskVersion') OR jsonb_typeof(body->'decision') IS DISTINCT FROM 'string' OR body->>'decision' NOT IN('approve','reject') THEN RAISE EXCEPTION 'reference request invalid' USING ERRCODE='22023';END IF;
  SELECT * INTO t FROM public.approval_tasks WHERE tenant_id=tenant AND request_id=r.id AND id=(body->>'taskId')::uuid;
  IF t.id IS NULL OR t.assigned_identity_id<>actor OR actor=r.requester_id OR t.version<>(body->>'taskVersion')::integer OR t.stage_index<>r.stage_index OR t.status<>'open' OR t.expires_at<=stamp THEN RAISE EXCEPTION 'APPROVAL_TASK_CONFLICT' USING ERRCODE='40001';END IF;
  IF NOT public.gc_reference_review_authorized(r) THEN RAISE EXCEPTION 'reference forbidden' USING ERRCODE='42501';END IF;
  IF NOT public.gc_reference_payload_current(r.payload) THEN RAISE EXCEPTION 'reference version conflict' USING ERRCODE='40001';END IF;
  decision_id:=gen_random_uuid();INSERT INTO public.approval_decisions VALUES(tenant,decision_id,r.id,t.id,t.version,r.proposal_digest,actor,body->>'decision',reason,stamp);
  UPDATE public.approval_tasks SET status='decided',version=version+1 WHERE tenant_id=tenant AND id=t.id;
  UPDATE public.approval_requests SET version=version+1,updated_at=stamp WHERE tenant_id=tenant AND id=r.id;
 END IF;
 PERFORM public.gc_approval_journal(CASE WHEN operation='approval.cancel' THEN 'approval.cancelled' ELSE 'approval.decided' END,r.id,r.id::text,r.version+1,
 jsonb_build_object('proposalDigest',r.proposal_digest,'taskId',t.id,'decisionId',decision_id,'decision',body->>'decision','reason',reason),correlation,true);
 result:=jsonb_build_object('request',public.gc_approval_request_view(r.id));
 INSERT INTO public.idempotency(tenant_id,actor_id,operation,key,request_hash,response) VALUES(tenant,actor::text,operation,command_key,hash,result);RETURN result;
END $$;
CREATE OR REPLACE FUNCTION public.gc_approval_tick(request_identity uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE r public.approval_requests;w jsonb;s jsonb;stamp timestamptz;deadline timestamptz;outcome text:='pending';error text;approvals integer;BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.approval_requests WHERE tenant_id=public.gc_tenant() AND id=request_identity AND binding='reference.publish') THEN RETURN public.gc_approval_tick_pre_reference(request_identity);END IF;
 r:=public.gc_reference_lock_review(request_identity);
 IF r.status<>'pending' THEN RETURN jsonb_build_object('id',r.id,'status',r.status,'version',r.version,'nextWakeAt',NULL);END IF;
 SELECT definition INTO w FROM public.workflow_definition_versions WHERE tenant_id=r.tenant_id AND workflow_id=r.workflow_id AND version=r.workflow_version AND definition_hash=r.workflow_hash;
 s:=w->'stages'->r.stage_index;stamp:=date_trunc('milliseconds',clock_timestamp());
 SELECT min(expires_at) INTO deadline FROM public.approval_tasks WHERE tenant_id=r.tenant_id AND request_id=r.id AND stage_index=r.stage_index;
 IF stamp>=least(r.expires_at,deadline) THEN outcome:='expired';
 ELSIF NOT public.gc_reference_review_authorized(r) THEN outcome:='cancelled';error:='REFERENCE_AUTHORITY_REVOKED';
 ELSIF EXISTS(SELECT 1 FROM public.approval_decisions d JOIN public.approval_tasks t ON t.tenant_id=d.tenant_id AND t.id=d.task_id WHERE d.tenant_id=r.tenant_id AND d.request_id=r.id AND t.stage_index=r.stage_index AND d.decision='reject') THEN outcome:='rejected';
 ELSE
  SELECT count(*) INTO approvals FROM public.approval_decisions d JOIN public.approval_tasks t ON t.tenant_id=d.tenant_id AND t.id=d.task_id WHERE d.tenant_id=r.tenant_id AND d.request_id=r.id AND t.stage_index=r.stage_index AND d.decision='approve';
  IF approvals>=(s->>'quorum')::integer THEN
   UPDATE public.approval_tasks SET status='cancelled',version=version+1 WHERE tenant_id=r.tenant_id AND request_id=r.id AND stage_index=r.stage_index AND status='open';
   IF r.stage_index+1=jsonb_array_length(w->'stages') THEN outcome:='ready';
   ELSE
    s:=w->'stages'->(r.stage_index+1);deadline:=least(r.expires_at,stamp+make_interval(secs=>(s->>'deadlineSeconds')::integer));
    UPDATE public.approval_tasks SET status='open',version=version+1,opened_at=stamp,expires_at=deadline WHERE tenant_id=r.tenant_id AND request_id=r.id AND stage_index=r.stage_index+1 AND status='waiting';
    UPDATE public.approval_requests SET stage_index=stage_index+1,version=version+1,updated_at=stamp WHERE tenant_id=r.tenant_id AND id=r.id;
    PERFORM public.gc_approval_journal('approval.stage_opened',r.id,r.id::text,r.version+1,jsonb_build_object('stageIndex',r.stage_index+1),'workflow:'||r.id::text);
    RETURN jsonb_build_object('id',r.id,'status','pending','version',r.version+1,'nextWakeAt',public.gc_relation_utc(deadline));
   END IF;
  END IF;
 END IF;
 IF outcome<>'pending' THEN
  UPDATE public.approval_requests SET status=outcome,version=version+1,updated_at=stamp,error_code=error WHERE tenant_id=r.tenant_id AND id=r.id;
  UPDATE public.approval_tasks SET status='cancelled',version=version+1 WHERE tenant_id=r.tenant_id AND request_id=r.id AND status IN('open','waiting');
  PERFORM public.gc_approval_journal('approval.'||outcome,r.id,r.id::text,r.version+1,jsonb_build_object('proposalDigest',r.proposal_digest),'workflow:'||r.id::text);
 END IF;
 RETURN jsonb_build_object('id',r.id,'status',outcome,'version',r.version+CASE WHEN outcome='pending' THEN 0 ELSE 1 END,'nextWakeAt',CASE WHEN outcome='pending' THEN public.gc_relation_utc(least(r.expires_at,deadline)) END);
END $$;
CREATE FUNCTION public.gc_reference_release_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE r public.approval_requests;h public.reference_sets;prior public.reference_releases;expected jsonb; BEGIN
 IF current_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.reference_releases'::regclass)
 OR NEW.created_xid<>pg_current_xact_id() THEN RAISE EXCEPTION 'reference forbidden' USING ERRCODE='42501';END IF;
 SELECT * INTO r FROM public.approval_requests WHERE tenant_id=NEW.tenant_id AND id=NEW.approval_request_id;
 SELECT * INTO h FROM public.reference_sets WHERE tenant_id=NEW.tenant_id AND id=NEW.set_id;
 IF r.id IS NULL OR r.binding<>'reference.publish' OR r.status<>'ready' OR r.resource_id<>NEW.set_id
 OR coalesce(r.resource_version,0)<>NEW.version-1 OR r.payload IS DISTINCT FROM NEW.approved_payload OR r.proposal_digest IS DISTINCT FROM NEW.proposal_digest
 OR h.current_version IS DISTINCT FROM NEW.version
 OR jsonb_build_object('visibility',h.visibility,'allowedIdentityIds',h.allowed_identities) IS DISTINCT FROM r.payload->'audience'
 OR (r.payload->>'expectedVersion')::integer<>NEW.version-1 THEN RAISE EXCEPTION 'reference storage invalid' USING ERRCODE='23514';END IF;
 expected:=((r.payload->'release')-'activation')||jsonb_build_object('setId',NEW.set_id,'version',NEW.version,'publishedAt',public.gc_relation_utc(NEW.published_at),'effectiveFrom',public.gc_relation_utc(NEW.effective_from));
 IF expected IS DISTINCT FROM NEW.published_bundle
 OR (r.payload#>>'{release,activation,kind}'='on-publication' AND NEW.effective_from<>NEW.published_at)
 OR (r.payload#>>'{release,activation,kind}'='at' AND (NEW.effective_from IS DISTINCT FROM (r.payload#>>'{release,activation,at}')::timestamptz OR NEW.effective_from<=NEW.published_at))
 THEN RAISE EXCEPTION 'reference storage invalid' USING ERRCODE='23514';END IF;
 IF NEW.version>1 THEN
  SELECT * INTO prior FROM public.reference_releases WHERE tenant_id=NEW.tenant_id AND set_id=NEW.set_id AND version=NEW.version-1;
  IF prior.set_id IS NULL OR NEW.effective_from<=prior.effective_from OR NEW.published_at<prior.published_at THEN RAISE EXCEPTION 'reference storage invalid' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER reference_release_guard BEFORE INSERT ON public.reference_releases FOR EACH ROW EXECUTE FUNCTION public.gc_reference_release_guard();
CREATE FUNCTION public.gc_reference_value_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE r public.reference_releases;projection jsonb; BEGIN
 IF current_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.reference_releases'::regclass) THEN RAISE EXCEPTION 'reference forbidden' USING ERRCODE='42501';END IF;
 SELECT * INTO r FROM public.reference_releases WHERE tenant_id=NEW.tenant_id AND set_id=NEW.set_id AND version=NEW.version;
 projection:=jsonb_build_object('code',NEW.code,'labels',NEW.labels,'ownerId',NEW.owner_id,'status',NEW.status,'validFrom',public.gc_relation_utc(NEW.valid_from),'validUntil',public.gc_relation_utc(NEW.valid_until));
 IF r.set_id IS NULL OR r.created_xid<>pg_current_xact_id() OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(r.published_bundle->'values') value WHERE value=projection)
 THEN RAISE EXCEPTION 'reference storage invalid' USING ERRCODE='23514';END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER reference_value_guard BEFORE INSERT ON public.reference_values FOR EACH ROW EXECUTE FUNCTION public.gc_reference_value_guard();
CREATE FUNCTION public.gc_reference_release_seal() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE r public.approval_requests;values jsonb;result jsonb; BEGIN
 SELECT * INTO r FROM public.approval_requests WHERE tenant_id=NEW.tenant_id AND id=NEW.approval_request_id;
 SELECT coalesce(jsonb_agg(jsonb_build_object('code',v.code,'labels',v.labels,'ownerId',v.owner_id,'status',v.status,'validFrom',public.gc_relation_utc(v.valid_from),'validUntil',public.gc_relation_utc(v.valid_until)) ORDER BY v.code COLLATE "C"),'[]')
 INTO values FROM public.reference_values v WHERE v.tenant_id=NEW.tenant_id AND v.set_id=NEW.set_id AND v.version=NEW.version;
 result:=jsonb_build_object('binding','reference.publish','setId',NEW.set_id,'version',NEW.version,'publicationHash',NEW.publication_hash,'publishedAt',public.gc_relation_utc(NEW.published_at),'effectiveFrom',public.gc_relation_utc(NEW.effective_from));
 IF values IS DISTINCT FROM NEW.published_bundle->'values' OR r.binding IS DISTINCT FROM 'reference.publish' OR r.status IS DISTINCT FROM 'succeeded'
 OR r.result IS DISTINCT FROM result OR r.payload IS DISTINCT FROM NEW.approved_payload OR r.proposal_digest IS DISTINCT FROM NEW.proposal_digest
 OR NOT EXISTS(SELECT 1 FROM public.reference_sets s WHERE s.tenant_id=NEW.tenant_id AND s.id=NEW.set_id AND s.current_version>=NEW.version)
 OR (SELECT count(*) FROM public.audit a JOIN public.outbox o ON o.tenant_id=a.tenant_id AND o.id=a.id
  WHERE a.tenant_id=NEW.tenant_id AND a.action='reference.published' AND a.resource_id=NEW.set_id::text AND o.event_type=a.action AND o.resource_id=a.resource_id AND o.resource_version=NEW.version
  AND a.changes=jsonb_build_object('approvalInstanceId',r.id,'publicationHash',NEW.publication_hash,'proposalDigest',r.proposal_digest,'resourceVersion',NEW.version))<>1
 OR (SELECT count(*) FROM public.audit a JOIN public.outbox o ON o.tenant_id=a.tenant_id AND o.id=a.id
  WHERE a.tenant_id=NEW.tenant_id AND a.action='approval.succeeded' AND a.resource_id=r.id::text AND o.event_type=a.action AND o.resource_id=a.resource_id AND o.resource_version=r.version
  AND a.changes=jsonb_build_object('binding','reference.publish','setId',NEW.set_id,'version',NEW.version,'proposalDigest',r.proposal_digest,'resourceVersion',r.version))<>1
 THEN RAISE EXCEPTION 'reference storage invalid' USING ERRCODE='23514';END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER reference_release_seal AFTER INSERT ON public.reference_releases DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_reference_release_seal();
CREATE FUNCTION public.gc_reference_approval_seal() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$ BEGIN
 IF NEW.binding='reference.publish' AND NEW.status='succeeded' AND NOT EXISTS(
 SELECT 1 FROM public.reference_releases r WHERE r.tenant_id=NEW.tenant_id AND r.approval_request_id=NEW.id AND r.set_id=NEW.resource_id
 AND r.proposal_digest=NEW.proposal_digest AND r.approved_payload=NEW.payload
 AND NEW.result=jsonb_build_object('binding','reference.publish','setId',r.set_id,'version',r.version,'publicationHash',r.publication_hash,'publishedAt',public.gc_relation_utc(r.published_at),'effectiveFrom',public.gc_relation_utc(r.effective_from)))
 THEN RAISE EXCEPTION 'reference storage invalid' USING ERRCODE='23514';END IF; RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER reference_approval_seal AFTER INSERT OR UPDATE ON public.approval_requests DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_reference_approval_seal();

CREATE FUNCTION public.gc_reference_namespace_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$ DECLARE protected boolean;BEGIN
 IF TG_TABLE_NAME='idempotency' THEN protected:=(CASE WHEN TG_OP='DELETE' THEN OLD.operation ELSE NEW.operation END) LIKE 'reference.%' OR (TG_OP='UPDATE' AND OLD.operation LIKE 'reference.%');
 ELSIF TG_TABLE_NAME='audit' THEN protected:=(CASE WHEN TG_OP='DELETE' THEN OLD.action ELSE NEW.action END) LIKE 'reference.%';
 ELSE protected:=(CASE WHEN TG_OP='DELETE' THEN OLD.event_type ELSE NEW.event_type END) LIKE 'reference.%' OR (TG_OP='UPDATE' AND OLD.event_type LIKE 'reference.%');END IF;
 IF TG_TABLE_NAME='outbox' AND TG_OP='UPDATE' THEN
  IF protected AND (to_jsonb(NEW)-ARRAY['processed_at','attempts'])=(to_jsonb(OLD)-ARRAY['processed_at','attempts']) AND NEW.attempts>=OLD.attempts THEN RETURN NEW;END IF;
 END IF;
 IF protected AND current_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.reference_releases'::regclass) THEN RAISE EXCEPTION 'reference forbidden' USING ERRCODE='42501';END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END $$;
CREATE TRIGGER reference_namespace_guard BEFORE INSERT OR UPDATE OR DELETE ON public.idempotency FOR EACH ROW EXECUTE FUNCTION public.gc_reference_namespace_guard();
CREATE TRIGGER reference_namespace_guard BEFORE INSERT ON public.audit FOR EACH ROW EXECUTE FUNCTION public.gc_reference_namespace_guard();
CREATE TRIGGER reference_namespace_guard BEFORE INSERT OR UPDATE OR DELETE ON public.outbox FOR EACH ROW EXECUTE FUNCTION public.gc_reference_namespace_guard();
REVOKE ALL ON FUNCTION public.gc_reference_uuid(jsonb),
 public.gc_reference_instant(jsonb,boolean),
 public.gc_reference_labels(jsonb),
 public.gc_reference_audience(jsonb),
 public.gc_reference_release_normalize(jsonb),
 public.gc_reference_payload_normalize(jsonb),
 public.gc_reference_bundle_valid(jsonb),
 public.gc_reference_actor_can(jsonb,uuid,text),
 public.gc_reference_visible(uuid,uuid),
 public.gc_reference_request_visible(uuid,uuid),
 public.gc_reference_payload_current(jsonb),
 public.gc_reference_lock_review(uuid),
 public.gc_reference_review_authorized(public.approval_requests),
 public.gc_reference_command(text,text,jsonb,text),
 public.gc_reference_publish(uuid),
 public.gc_reference_fail(uuid,integer,text),
 public.gc_reference_release_guard(),
 public.gc_reference_value_guard(),
 public.gc_reference_release_seal(),
 public.gc_reference_approval_seal(),
 public.gc_reference_namespace_guard(),
 public.gc_approval_command_pre_reference(text,text,jsonb,text),
 public.gc_approval_tick_pre_reference(uuid) FROM PUBLIC,gc_app;
GRANT EXECUTE ON FUNCTION public.gc_reference_visible(uuid,uuid),public.gc_reference_request_visible(uuid,uuid),public.gc_reference_payload_current(jsonb),public.gc_reference_command(text,text,jsonb,text),public.gc_reference_publish(uuid),public.gc_reference_fail(uuid,integer,text) TO gc_app;
