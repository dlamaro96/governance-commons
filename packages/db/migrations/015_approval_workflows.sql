-- SPDX-License-Identifier: Apache-2.0
-- Candidate SQL014 -> SQL015. This initial executable family supports ordered
-- stages of parallel human approvals. It does not authorize a resource effect.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls))
 OR pg_has_role('gc_app',current_user,'MEMBER') THEN
  RAISE EXCEPTION 'APPROVAL_STORAGE_INVALID' USING ERRCODE='42501';
 END IF;
END $$;

CREATE TABLE public.workflow_definitions (
 tenant_id uuid NOT NULL REFERENCES public.tenants(id), id text NOT NULL CHECK(public.gc_relation_safe_id(id)),
 current_version integer NOT NULL CHECK(current_version>0), created_by uuid NOT NULL, created_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id)
);
CREATE TABLE public.workflow_definition_versions (
 tenant_id uuid NOT NULL, workflow_id text NOT NULL, version integer NOT NULL CHECK(version>0),
 definition jsonb NOT NULL CHECK(octet_length(definition::text)<=65536),
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[a-f0-9]{64}$'), created_by uuid NOT NULL, created_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,workflow_id,version), FOREIGN KEY(tenant_id,workflow_id) REFERENCES public.workflow_definitions(tenant_id,id),
 FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id)
);
ALTER TABLE public.workflow_definitions ADD CONSTRAINT workflow_current_version
 FOREIGN KEY(tenant_id,id,current_version) REFERENCES public.workflow_definition_versions(tenant_id,workflow_id,version) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE public.approval_requests (
 tenant_id uuid NOT NULL REFERENCES public.tenants(id), id uuid NOT NULL, binding text NOT NULL CHECK(binding='glossary.publish'),
 resource_id uuid NOT NULL, resource_version integer CHECK(resource_version>0), payload jsonb NOT NULL CHECK(octet_length(payload::text)<=262144),
 proposal_digest text NOT NULL CHECK(proposal_digest ~ '^[a-f0-9]{64}$'), workflow_id text NOT NULL, workflow_version integer NOT NULL,
 workflow_hash text NOT NULL CHECK(workflow_hash ~ '^[a-f0-9]{64}$'), requester_id uuid NOT NULL,
 stage_index integer NOT NULL DEFAULT 0 CHECK(stage_index BETWEEN 0 AND 15), version integer NOT NULL DEFAULT 1 CHECK(version>0),
 status text NOT NULL CHECK(status IN ('pending','ready','rejected','cancelled','expired','succeeded','failed')),
 result jsonb, error_code text, expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,id), FOREIGN KEY(tenant_id,workflow_id,workflow_version) REFERENCES public.workflow_definition_versions(tenant_id,workflow_id,version),
 FOREIGN KEY(tenant_id,requester_id) REFERENCES public.memberships(tenant_id,identity_id), CHECK(expires_at>created_at)
);
CREATE INDEX approval_pending ON public.approval_requests(tenant_id,status,created_at,id);
CREATE TABLE public.approval_tasks (
 tenant_id uuid NOT NULL, id uuid NOT NULL, request_id uuid NOT NULL, stage_index integer NOT NULL CHECK(stage_index BETWEEN 0 AND 15),
 assignment text NOT NULL CHECK(public.gc_relation_safe_id(assignment)), assigned_identity_id uuid NOT NULL,
 version integer NOT NULL DEFAULT 1 CHECK(version>0), status text NOT NULL CHECK(status IN ('waiting','open','decided','cancelled')),
 opened_at timestamptz, expires_at timestamptz,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,request_id,stage_index,assignment), UNIQUE(tenant_id,request_id,stage_index,assigned_identity_id),
 UNIQUE(tenant_id,request_id,id), FOREIGN KEY(tenant_id,request_id) REFERENCES public.approval_requests(tenant_id,id),
 FOREIGN KEY(tenant_id,assigned_identity_id) REFERENCES public.memberships(tenant_id,identity_id),
 CHECK((opened_at IS NULL)=(expires_at IS NULL)), CHECK(expires_at IS NULL OR expires_at>opened_at)
);
CREATE INDEX approval_assigned ON public.approval_tasks(tenant_id,assigned_identity_id,status,request_id);
CREATE TABLE public.approval_decisions (
 tenant_id uuid NOT NULL, id uuid NOT NULL, request_id uuid NOT NULL, task_id uuid NOT NULL, task_version integer NOT NULL CHECK(task_version>0),
 proposal_digest text NOT NULL, actor_id uuid NOT NULL, decision text NOT NULL CHECK(decision IN ('approve','reject')),
 reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 1 AND 4096), decided_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,id), UNIQUE(tenant_id,task_id), FOREIGN KEY(tenant_id,request_id,task_id) REFERENCES public.approval_tasks(tenant_id,request_id,id),
 FOREIGN KEY(tenant_id,actor_id) REFERENCES public.memberships(tenant_id,identity_id)
);
-- Delivery state is separate from the search projector's outbox acknowledgement.
CREATE TABLE public.approval_dispatch (
 tenant_id uuid NOT NULL, request_id uuid NOT NULL, event_id uuid NOT NULL,
 dispatched_at timestamptz, attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0),
 PRIMARY KEY(tenant_id,event_id), FOREIGN KEY(tenant_id,request_id) REFERENCES public.approval_requests(tenant_id,id),
 FOREIGN KEY(tenant_id,event_id) REFERENCES public.outbox(tenant_id,id)
);

DO $$ DECLARE name text; BEGIN
 FOREACH name IN ARRAY ARRAY['workflow_definitions','workflow_definition_versions','approval_requests','approval_tasks','approval_decisions','approval_dispatch'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.gc_tenant()) WITH CHECK(tenant_id=public.gc_tenant())',name);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC,gc_app',name);
  EXECUTE format('GRANT SELECT ON public.%I TO gc_app',name);
 END LOOP;
END $$;
CREATE TRIGGER workflow_versions_immutable BEFORE UPDATE OR DELETE ON public.workflow_definition_versions FOR EACH ROW EXECUTE FUNCTION public.gc_immutable_audit();
CREATE TRIGGER approval_decisions_immutable BEFORE UPDATE OR DELETE ON public.approval_decisions FOR EACH ROW EXECUTE FUNCTION public.gc_immutable_audit();

CREATE FUNCTION public.gc_approval_uuid(value text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT coalesce(value ~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$',false);
$$;

CREATE FUNCTION public.gc_approval_text(value text,maximum integer,multiline boolean) RETURNS text
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE cleaned text; BEGIN
 IF value IS NULL THEN RETURN NULL; END IF;
 cleaned:=normalize(btrim(value,U&'\0009\000A\000B\000C\000D\0020\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000\FEFF'),NFC);
 IF public.gc_relation_utf16_length(cleaned) NOT BETWEEN 1 AND maximum
 OR cleaned ~ U&'[\0001-\0008\000B\000C\000E-\001F\007F-\009F]'
 OR (NOT multiline AND cleaned ~ U&'[\0009\000A\000D]') THEN RETURN NULL; END IF;
 RETURN cleaned;
END $$;

CREATE FUNCTION public.gc_approval_definition_valid(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE stage jsonb; BEGIN
 IF value IS NULL OR octet_length(value::text)>65536 OR NOT public.gc_relation_keys(value,ARRAY['formatVersion','id','version','name','separationOfDuties','stages'])
 OR value->'formatVersion'<>'1'::jsonb OR jsonb_typeof(value->'id')<>'string' OR NOT public.gc_relation_safe_id(value->>'id')
 OR jsonb_typeof(value->'version')<>'number' OR value->>'version' !~ '^[1-9][0-9]{0,9}$' OR (value->>'version')::bigint>2147483647
 OR jsonb_typeof(value->'name')<>'string' OR public.gc_approval_text(value->>'name',240,false) IS NULL OR value->>'name' IS DISTINCT FROM public.gc_approval_text(value->>'name',240,false)
 OR jsonb_typeof(value->'separationOfDuties')<>'boolean' OR jsonb_typeof(value->'stages')<>'array'
 OR jsonb_array_length(value->'stages') NOT BETWEEN 1 AND 16 THEN RETURN false; END IF;
 IF (SELECT count(*)<>count(DISTINCT s->>'id') FROM jsonb_array_elements(value->'stages') s) THEN RETURN false; END IF;
 FOR stage IN SELECT s FROM jsonb_array_elements(value->'stages') s LOOP
  IF NOT public.gc_relation_keys(stage,ARRAY['id','name','assignments','quorum','deadlineSeconds','rejection'])
  OR jsonb_typeof(stage->'id')<>'string' OR NOT public.gc_relation_safe_id(stage->>'id') OR jsonb_typeof(stage->'name')<>'string'
  OR public.gc_approval_text(stage->>'name',240,false) IS NULL OR stage->>'name' IS DISTINCT FROM public.gc_approval_text(stage->>'name',240,false)
  OR jsonb_typeof(stage->'rejection')<>'string' OR stage->>'rejection' IS DISTINCT FROM 'any' OR jsonb_typeof(stage->'assignments')<>'array' OR jsonb_array_length(stage->'assignments') NOT BETWEEN 1 AND 16
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(stage->'assignments') a WHERE jsonb_typeof(a)<>'string' OR NOT public.gc_relation_safe_id(a#>>'{}'))
  OR (SELECT count(*)<>count(DISTINCT a) FROM jsonb_array_elements(stage->'assignments') a)
  OR jsonb_typeof(stage->'quorum')<>'number' OR stage->>'quorum' !~ '^[1-9][0-9]?$' OR (stage->>'quorum')::integer>jsonb_array_length(stage->'assignments')
  OR jsonb_typeof(stage->'deadlineSeconds')<>'number' OR stage->>'deadlineSeconds' !~ '^[1-9][0-9]{0,7}$'
  OR (stage->>'deadlineSeconds')::integer>31536000 THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END $$;

CREATE FUNCTION public.gc_approval_journal(action_name text,request_identity uuid,resource text,revision integer,data jsonb,correlation text,dispatch boolean DEFAULT false) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant(); actor text:=public.gc_actor(); actor_name text; event_id uuid:=gen_random_uuid();
 occurred timestamptz:=clock_timestamp(); stamp text; prior text; envelope jsonb; BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text,0));
 SELECT name INTO actor_name FROM public.identities WHERE id::text=actor;
 actor_name:=coalesce(actor_name,'Workflow service'); stamp:=public.gc_relation_utc(occurred);
 SELECT hash INTO prior FROM public.audit WHERE tenant_id=tenant ORDER BY sequence DESC LIMIT 1;
 prior:=coalesce(prior,repeat('0',64));
 envelope:=jsonb_build_object('id',event_id,'tenantId',tenant,'actorId',actor,'actorName',actor_name,'action',action_name,
  'resourceId',resource,'version',revision,'changes',data,'correlationId',correlation,'occurredAt',stamp,'previousHash',prior);
 INSERT INTO public.audit(tenant_id,id,actor_id,actor_name,action,resource_id,changes,correlation_id,occurred_at,previous_hash,hash,envelope)
 VALUES(tenant,event_id,actor,actor_name,action_name,resource,data||jsonb_build_object('resourceVersion',revision),correlation,occurred,prior,public.gc_type_migration_hash(envelope),envelope);
 INSERT INTO public.outbox(tenant_id,id,event_type,resource_id,resource_version,payload,created_at)
 VALUES(tenant,event_id,action_name,resource,revision,jsonb_build_object('specversion','1.0','id',event_id,'type',action_name,'source','governance-commons',
  'subject',resource,'time',stamp,'tenantId',tenant,'resourceVersion',revision,'actorId',actor,'correlationId',correlation),occurred);
 IF dispatch AND request_identity IS NOT NULL THEN INSERT INTO public.approval_dispatch(tenant_id,request_id,event_id) VALUES(tenant,request_identity,event_id); END IF;
 RETURN event_id;
END $$;

CREATE FUNCTION public.gc_approval_request_view(request_identity uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT jsonb_build_object('id',r.id,'binding',r.binding,'resourceId',r.resource_id,'resourceVersion',r.resource_version,'payload',r.payload,
  'proposalDigest',r.proposal_digest,'workflowId',r.workflow_id,'workflowVersion',r.workflow_version,'workflowHash',r.workflow_hash,
  'requesterId',r.requester_id,'stageIndex',r.stage_index,'version',r.version,'status',r.status,'result',r.result,'errorCode',r.error_code,
  'expiresAt',public.gc_relation_utc(r.expires_at),'createdAt',public.gc_relation_utc(r.created_at),'updatedAt',public.gc_relation_utc(r.updated_at),
  'tasks',coalesce((SELECT jsonb_agg(jsonb_build_object('id',t.id,'stageIndex',t.stage_index,'assignment',t.assignment,
   'assignedIdentityId',t.assigned_identity_id,'version',t.version,'status',t.status,'openedAt',public.gc_relation_utc(t.opened_at),
   'expiresAt',public.gc_relation_utc(t.expires_at)) ORDER BY t.stage_index,t.assignment) FROM public.approval_tasks t WHERE t.tenant_id=r.tenant_id AND t.request_id=r.id),'[]'::jsonb),
  'decisions',coalesce((SELECT jsonb_agg(jsonb_build_object('id',d.id,'taskId',d.task_id,'taskVersion',d.task_version,'actorId',d.actor_id,
   'decision',d.decision,'reason',d.reason,'decidedAt',public.gc_relation_utc(d.decided_at)) ORDER BY d.decided_at,d.id)
   FROM public.approval_decisions d WHERE d.tenant_id=r.tenant_id AND d.request_id=r.id),'[]'::jsonb))
 FROM public.approval_requests r WHERE r.tenant_id=public.gc_tenant() AND r.id=request_identity;
$$;

CREATE FUNCTION public.gc_approval_command(operation text,command_key text,body jsonb,correlation text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant(); actor uuid; old public.idempotency; request public.approval_requests;
 workflow public.workflow_definition_versions; task public.approval_tasks; definition jsonb; stage jsonb; assignment text;
 required_keys text[]; principals uuid[]; result jsonb; hash text; resource uuid; now_at timestamptz:=clock_timestamp(); expiry timestamptz;
 stage_number integer; expected integer; decision_id uuid; BEGIN
 IF operation NOT IN ('approval.definition.publish','approval.submit','approval.decide','approval.cancel')
 OR command_key IS NULL OR length(command_key) NOT BETWEEN 8 AND 128 OR correlation IS NULL OR length(correlation) NOT BETWEEN 1 AND 128
 OR body IS NULL OR jsonb_typeof(body)<>'object' OR octet_length(body::text)>327680 THEN
  RAISE EXCEPTION 'APPROVAL_INPUT_INVALID' USING ERRCODE='22023'; END IF;
 PERFORM public.gc_relation_authorize(CASE WHEN operation='approval.definition.publish' THEN ARRAY['models:read','models:write'] ELSE ARRAY['catalog:read','catalog:write'] END);
 actor:=public.gc_actor()::uuid;
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text||actor::text||operation||command_key,0));
 hash:=public.gc_type_migration_hash(body);
 SELECT * INTO old FROM public.idempotency WHERE tenant_id=tenant AND actor_id=actor::text AND idempotency.operation=gc_approval_command.operation AND key=command_key;
 IF FOUND THEN
  IF old.request_hash<>hash THEN RAISE EXCEPTION 'IDEMPOTENCY_CONFLICT' USING ERRCODE='40001'; END IF;
  -- Replay observes current authority after all blocking locks as well.
  PERFORM public.gc_lock_type_migration_principals(ARRAY[]::uuid[]);
  PERFORM public.gc_relation_authorize(CASE WHEN operation='approval.definition.publish' THEN ARRAY['models:read','models:write'] ELSE ARRAY['catalog:read','catalog:write'] END);
  RETURN old.response;
 END IF;
 IF operation='approval.definition.publish' THEN
  IF NOT public.gc_relation_keys(body,ARRAY['definition','expectedVersion']) OR NOT public.gc_approval_definition_valid(body->'definition')
  OR jsonb_typeof(body->'expectedVersion')<>'number' OR body->>'expectedVersion' !~ '^(0|[1-9][0-9]{0,9})$' THEN
   RAISE EXCEPTION 'APPROVAL_INPUT_INVALID' USING ERRCODE='22023'; END IF;
  definition:=body->'definition'; expected:=(body->>'expectedVersion')::integer;
  IF (definition->>'version')::bigint<>expected::bigint+1 OR
   coalesce((SELECT current_version FROM public.workflow_definitions WHERE tenant_id=tenant AND id=definition->>'id'),0)<>expected THEN
   RAISE EXCEPTION 'VERSION_CONFLICT' USING ERRCODE='40001'; END IF;
  PERFORM public.gc_lock_type_migration_principals(ARRAY[]::uuid[]);
  PERFORM public.gc_relation_authorize(ARRAY['models:read','models:write']);
  now_at:=clock_timestamp();
  IF expected=0 THEN INSERT INTO public.workflow_definitions VALUES(tenant,definition->>'id',1,actor,now_at);
  ELSE UPDATE public.workflow_definitions SET current_version=expected+1 WHERE tenant_id=tenant AND id=definition->>'id'; END IF;
  INSERT INTO public.workflow_definition_versions VALUES(tenant,definition->>'id',expected+1,definition,public.gc_type_migration_hash(definition),actor,now_at);
  PERFORM public.gc_approval_journal('workflow.definition_published',NULL,definition->>'id',expected+1,
   jsonb_build_object('definitionHash',public.gc_type_migration_hash(definition)),correlation);
  result:=jsonb_build_object('definition',definition,'definitionHash',public.gc_type_migration_hash(definition));
 ELSIF operation='approval.submit' THEN
  IF NOT public.gc_relation_keys(body,ARRAY['id','binding','resourceId','resourceVersion','payload','workflowId','workflowVersion','workflowHash','assignments','expiresAt'])
  OR body->>'binding'<>'glossary.publish' OR jsonb_typeof(body->'payload')<>'object' OR octet_length((body->'payload')::text)>262144
  OR jsonb_typeof(body->'assignments')<>'object' OR (SELECT count(*) FROM jsonb_object_keys(body->'assignments'))>256
  OR NOT public.gc_approval_uuid(body->>'id') OR NOT public.gc_approval_uuid(body->>'resourceId')
  OR (body->'resourceVersion'<>'null'::jsonb AND (jsonb_typeof(body->'resourceVersion')<>'number' OR body->>'resourceVersion' !~ '^[1-9][0-9]{0,9}$'))
  OR jsonb_typeof(body->'workflowVersion')<>'number' OR body->>'workflowVersion' !~ '^[1-9][0-9]{0,9}$'
  OR jsonb_typeof(body->'expiresAt')<>'string' THEN RAISE EXCEPTION 'APPROVAL_INPUT_INVALID' USING ERRCODE='22023'; END IF;
  resource:=(body->>'id')::uuid; expiry:=(body->>'expiresAt')::timestamptz;
  IF expiry<=now_at OR expiry>now_at+interval '366 days' THEN RAISE EXCEPTION 'APPROVAL_EXPIRY_INVALID' USING ERRCODE='22023'; END IF;
  SELECT v.* INTO workflow FROM public.workflow_definition_versions v JOIN public.workflow_definitions w
   ON w.tenant_id=v.tenant_id AND w.id=v.workflow_id AND w.current_version=v.version
   WHERE v.tenant_id=tenant AND v.workflow_id=body->>'workflowId' AND v.version=(body->>'workflowVersion')::integer;
  IF NOT FOUND OR workflow.definition_hash IS DISTINCT FROM body->>'workflowHash' THEN RAISE EXCEPTION 'WORKFLOW_PIN_STALE' USING ERRCODE='40001'; END IF;
  definition:=workflow.definition;
  SELECT array_agg(DISTINCT a#>>'{}' ORDER BY a#>>'{}') INTO required_keys
   FROM jsonb_array_elements(definition->'stages') s CROSS JOIN LATERAL jsonb_array_elements(s->'assignments') a;
  IF (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(body->'assignments') k) IS DISTINCT FROM required_keys
  OR EXISTS(SELECT 1 FROM jsonb_each(body->'assignments') p WHERE jsonb_typeof(p.value)<>'string' OR NOT public.gc_approval_uuid(p.value#>>'{}')) THEN
   RAISE EXCEPTION 'APPROVAL_ASSIGNMENTS_INVALID' USING ERRCODE='22023'; END IF;
  SELECT array_agg(DISTINCT (v#>>'{}')::uuid ORDER BY (v#>>'{}')::uuid) INTO principals FROM jsonb_each(body->'assignments') p(k,v);
  PERFORM public.gc_lock_type_migration_principals(principals);
  PERFORM public.gc_relation_authorize(ARRAY['catalog:read','catalog:write']);
  now_at:=clock_timestamp();
  IF expiry<=now_at OR expiry>now_at+interval '366 days' THEN RAISE EXCEPTION 'APPROVAL_EXPIRY_INVALID' USING ERRCODE='22023'; END IF;
  IF EXISTS(SELECT 1 FROM unnest(principals) AS selected(principal_id) WHERE NOT EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id
   WHERE m.tenant_id=tenant AND m.identity_id=selected.principal_id AND m.active AND i.active AND m.permissions @> '["catalog:read","catalog:write"]'::jsonb))
  OR (definition->>'separationOfDuties'='true' AND actor=ANY(principals)) THEN RAISE EXCEPTION 'APPROVAL_ASSIGNMENT_DENIED' USING ERRCODE='42501'; END IF;
  FOR stage IN SELECT s FROM jsonb_array_elements(definition->'stages') s LOOP
   IF (SELECT count(*)<>count(DISTINCT body->'assignments'->>(a#>>'{}')) FROM jsonb_array_elements(stage->'assignments') a) THEN
    RAISE EXCEPTION 'APPROVAL_DISTINCT_REVIEWERS_REQUIRED' USING ERRCODE='22023'; END IF;
  END LOOP;
  INSERT INTO public.approval_requests(tenant_id,id,binding,resource_id,resource_version,payload,proposal_digest,workflow_id,workflow_version,workflow_hash,
   requester_id,status,expires_at,created_at,updated_at)
  VALUES(tenant,resource,body->>'binding',(body->>'resourceId')::uuid,(body->>'resourceVersion')::integer,body->'payload',hash,
   workflow.workflow_id,workflow.version,workflow.definition_hash,actor,'pending',expiry,now_at,now_at);
  stage_number:=0;
  FOR stage IN SELECT s FROM jsonb_array_elements(definition->'stages') s LOOP
   FOR assignment IN SELECT a#>>'{}' FROM jsonb_array_elements(stage->'assignments') a LOOP
    INSERT INTO public.approval_tasks(tenant_id,id,request_id,stage_index,assignment,assigned_identity_id,status,opened_at,expires_at)
    VALUES(tenant,gen_random_uuid(),resource,stage_number,assignment,(body->'assignments'->>assignment)::uuid,
     CASE WHEN stage_number=0 THEN 'open' ELSE 'waiting' END,CASE WHEN stage_number=0 THEN now_at END,
     CASE WHEN stage_number=0 THEN least(expiry,now_at+make_interval(secs=>(stage->>'deadlineSeconds')::integer)) END);
   END LOOP;
   stage_number:=stage_number+1;
  END LOOP;
  PERFORM public.gc_approval_journal('approval.submitted',resource,resource::text,1,jsonb_build_object('proposalDigest',hash,'workflowId',workflow.workflow_id,'workflowVersion',workflow.version),correlation,true);
  result:=jsonb_build_object('request',public.gc_approval_request_view(resource));
 ELSE
  IF NOT public.gc_approval_uuid(body->>'requestId') THEN RAISE EXCEPTION 'APPROVAL_INPUT_INVALID' USING ERRCODE='22023'; END IF;
  resource:=(body->>'requestId')::uuid;
  SELECT * INTO request FROM public.approval_requests WHERE tenant_id=tenant AND id=resource;
  IF NOT FOUND OR (request.requester_id<>actor AND NOT EXISTS(SELECT 1 FROM public.approval_tasks WHERE tenant_id=tenant AND request_id=resource AND assigned_identity_id=actor)) THEN
   RAISE EXCEPTION 'APPROVAL_UNAVAILABLE' USING ERRCODE='P0002'; END IF;
  SELECT array_agg(DISTINCT id ORDER BY id) INTO principals FROM (SELECT request.requester_id AS id UNION SELECT assigned_identity_id FROM public.approval_tasks WHERE tenant_id=tenant AND request_id=resource) p;
  PERFORM public.gc_lock_type_migration_principals(principals);
  PERFORM public.gc_relation_authorize(ARRAY['catalog:read','catalog:write']);
  now_at:=clock_timestamp();
  IF request.status<>'pending' OR request.expires_at<=now_at OR request.proposal_digest IS DISTINCT FROM body->>'proposalDigest' THEN
   RAISE EXCEPTION 'APPROVAL_STATE_CONFLICT' USING ERRCODE='40001'; END IF;
  IF operation='approval.cancel' THEN
   IF NOT public.gc_relation_keys(body,ARRAY['requestId','proposalDigest','reason']) OR request.requester_id<>actor THEN
    RAISE EXCEPTION 'APPROVAL_CANCEL_DENIED' USING ERRCODE='42501'; END IF;
  ELSE
   IF NOT public.gc_relation_keys(body,ARRAY['requestId','proposalDigest','taskId','taskVersion','decision','reason'])
   OR NOT public.gc_approval_uuid(body->>'taskId') OR jsonb_typeof(body->'taskVersion')<>'number' OR body->>'taskVersion' !~ '^[1-9][0-9]{0,9}$'
   OR body->>'decision' NOT IN ('approve','reject') THEN RAISE EXCEPTION 'APPROVAL_INPUT_INVALID' USING ERRCODE='22023'; END IF;
   SELECT * INTO task FROM public.approval_tasks WHERE tenant_id=tenant AND request_id=resource AND id=(body->>'taskId')::uuid;
   SELECT * INTO workflow FROM public.workflow_definition_versions WHERE tenant_id=tenant AND workflow_id=request.workflow_id AND version=request.workflow_version;
   IF task.id IS NULL OR task.assigned_identity_id<>actor OR task.version<>(body->>'taskVersion')::integer OR task.stage_index<>request.stage_index
   OR task.status<>'open' OR task.expires_at<=now_at OR (workflow.definition->>'separationOfDuties'='true' AND actor=request.requester_id) THEN
    RAISE EXCEPTION 'APPROVAL_TASK_CONFLICT' USING ERRCODE='40001'; END IF;
  END IF;
  IF jsonb_typeof(body->'reason')<>'string' OR public.gc_approval_text(body->>'reason',4096,true) IS NULL THEN RAISE EXCEPTION 'APPROVAL_REASON_REQUIRED' USING ERRCODE='22023'; END IF;
  body:=jsonb_set(body,'{reason}',to_jsonb(public.gc_approval_text(body->>'reason',4096,true)));
  IF operation='approval.cancel' THEN
   UPDATE public.approval_requests SET status='cancelled',version=version+1,updated_at=now_at WHERE tenant_id=tenant AND id=resource;
   UPDATE public.approval_tasks SET status='cancelled',version=version+1 WHERE tenant_id=tenant AND request_id=resource AND status IN ('open','waiting');
  ELSE
   decision_id:=gen_random_uuid();
   INSERT INTO public.approval_decisions VALUES(tenant,decision_id,resource,task.id,task.version,request.proposal_digest,actor,body->>'decision',body->>'reason',now_at);
   UPDATE public.approval_tasks SET status='decided',version=version+1 WHERE tenant_id=tenant AND id=task.id;
   UPDATE public.approval_requests SET version=version+1,updated_at=now_at WHERE tenant_id=tenant AND id=resource;
  END IF;
  PERFORM public.gc_approval_journal(CASE WHEN operation='approval.cancel' THEN 'approval.cancelled' ELSE 'approval.decided' END,
   resource,resource::text,request.version+1,jsonb_build_object('proposalDigest',request.proposal_digest,'taskId',task.id,'decisionId',decision_id,'decision',body->>'decision','reason',body->>'reason'),correlation,true);
  result:=jsonb_build_object('request',public.gc_approval_request_view(resource));
 END IF;
 INSERT INTO public.idempotency(tenant_id,actor_id,operation,key,request_hash,response) VALUES(tenant,actor::text,operation,command_key,hash,result);
 RETURN result;
END $$;

-- Only canonical decisions can advance a request. The worker supplies an ID,
-- never an outcome, requester identity, clock, or approval count.
CREATE FUNCTION public.gc_approval_tick(request_identity uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant(); request public.approval_requests; definition jsonb; stage jsonb; principals uuid[]; principal uuid;
 now_at timestamptz:=clock_timestamp(); outcome text:='pending'; approvals integer; stage_deadline timestamptz; BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text,0));
 SELECT * INTO request FROM public.approval_requests WHERE tenant_id=tenant AND id=request_identity;
 IF NOT FOUND THEN RAISE EXCEPTION 'APPROVAL_UNAVAILABLE' USING ERRCODE='P0002'; END IF;
 IF request.status<>'pending' THEN RETURN jsonb_build_object('id',request.id,'status',request.status,'version',request.version,'nextWakeAt',NULL); END IF;
 SELECT array_agg(DISTINCT id ORDER BY id) INTO principals FROM (SELECT request.requester_id AS id UNION SELECT assigned_identity_id FROM public.approval_tasks WHERE tenant_id=tenant AND request_id=request.id) p;
 FOR principal IN SELECT id FROM public.identities WHERE id=ANY(principals) ORDER BY id FOR SHARE LOOP NULL; END LOOP;
 FOR principal IN SELECT identity_id FROM public.memberships WHERE tenant_id=tenant AND identity_id=ANY(principals) ORDER BY identity_id FOR SHARE LOOP NULL; END LOOP;
 now_at:=clock_timestamp();
 SELECT v.definition INTO definition FROM public.workflow_definition_versions v WHERE v.tenant_id=tenant AND v.workflow_id=request.workflow_id AND v.version=request.workflow_version;
 stage:=definition->'stages'->request.stage_index;
 SELECT min(expires_at) INTO stage_deadline FROM public.approval_tasks WHERE tenant_id=tenant AND request_id=request.id AND stage_index=request.stage_index;
 IF now_at>=least(request.expires_at,stage_deadline) THEN outcome:='expired';
 ELSIF EXISTS(SELECT 1 FROM unnest(principals) AS selected(principal_id) WHERE NOT EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id
  WHERE m.tenant_id=tenant AND m.identity_id=selected.principal_id AND m.active AND i.active AND m.permissions @> '["catalog:read","catalog:write"]'::jsonb)) THEN outcome:='cancelled';
 ELSIF EXISTS(SELECT 1 FROM public.approval_decisions d JOIN public.approval_tasks t ON t.tenant_id=d.tenant_id AND t.id=d.task_id
  WHERE d.tenant_id=tenant AND d.request_id=request.id AND t.stage_index=request.stage_index AND d.decision='reject') THEN outcome:='rejected';
 ELSE
  SELECT count(*) INTO approvals FROM public.approval_decisions d JOIN public.approval_tasks t ON t.tenant_id=d.tenant_id AND t.id=d.task_id
   WHERE d.tenant_id=tenant AND d.request_id=request.id AND t.stage_index=request.stage_index AND d.decision='approve';
  IF approvals>=(stage->>'quorum')::integer THEN
   UPDATE public.approval_tasks SET status='cancelled',version=version+1 WHERE tenant_id=tenant AND request_id=request.id AND stage_index=request.stage_index AND status='open';
   IF request.stage_index+1=jsonb_array_length(definition->'stages') THEN outcome:='ready';
   ELSE
    stage:=definition->'stages'->(request.stage_index+1);
    stage_deadline:=least(request.expires_at,now_at+make_interval(secs=>(stage->>'deadlineSeconds')::integer));
    UPDATE public.approval_tasks SET status='open',version=version+1,opened_at=now_at,expires_at=stage_deadline
     WHERE tenant_id=tenant AND request_id=request.id AND stage_index=request.stage_index+1 AND status='waiting';
    UPDATE public.approval_requests SET stage_index=stage_index+1,version=version+1,updated_at=now_at WHERE tenant_id=tenant AND id=request.id;
    PERFORM public.gc_approval_journal('approval.stage_opened',request.id,request.id::text,request.version+1,jsonb_build_object('stageIndex',request.stage_index+1),'workflow:'||request.id::text);
    RETURN jsonb_build_object('id',request.id,'status','pending','version',request.version+1,'nextWakeAt',public.gc_relation_utc(stage_deadline));
   END IF;
  END IF;
 END IF;
 IF outcome<>'pending' THEN
  UPDATE public.approval_requests SET status=outcome,version=version+1,updated_at=now_at,error_code=CASE WHEN outcome='cancelled' THEN 'REQUEST_AUTHORITY_REVOKED' END WHERE tenant_id=tenant AND id=request.id;
  UPDATE public.approval_tasks SET status='cancelled',version=version+1 WHERE tenant_id=tenant AND request_id=request.id AND status IN ('open','waiting');
  PERFORM public.gc_approval_journal('approval.'||outcome,request.id,request.id::text,request.version+1,jsonb_build_object('proposalDigest',request.proposal_digest),'workflow:'||request.id::text);
 END IF;
 RETURN jsonb_build_object('id',request.id,'status',outcome,'version',request.version+CASE WHEN outcome='pending' THEN 0 ELSE 1 END,
  'nextWakeAt',CASE WHEN outcome='pending' THEN public.gc_relation_utc(least(request.expires_at,stage_deadline)) END);
END $$;

CREATE FUNCTION public.gc_approval_dispatch_ack(event_identity uuid) RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 UPDATE public.approval_dispatch SET dispatched_at=coalesce(dispatched_at,clock_timestamp()),attempts=attempts+1
 WHERE tenant_id=public.gc_tenant() AND event_id=event_identity;
$$;

-- Reserve journal/idempotency namespaces so generic application DML cannot
-- impersonate decisions, acknowledgements or a completed approval command.
CREATE FUNCTION public.gc_approval_namespace_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE protected boolean; BEGIN
 IF TG_TABLE_NAME='idempotency' THEN protected:=(CASE WHEN TG_OP='DELETE' THEN OLD.operation ELSE NEW.operation END) LIKE 'approval.%'
  OR (TG_OP='UPDATE' AND OLD.operation LIKE 'approval.%');
 ELSIF TG_TABLE_NAME='audit' THEN protected:=(CASE WHEN TG_OP='DELETE' THEN OLD.action ELSE NEW.action END) LIKE ANY(ARRAY['approval.%','workflow.%']);
 ELSE protected:=(CASE WHEN TG_OP='DELETE' THEN OLD.event_type ELSE NEW.event_type END) LIKE ANY(ARRAY['approval.%','workflow.%'])
  OR (TG_OP='UPDATE' AND OLD.event_type LIKE ANY(ARRAY['approval.%','workflow.%'])); END IF;
 IF TG_TABLE_NAME='outbox' AND TG_OP='UPDATE' AND protected THEN
  IF (to_jsonb(NEW)-ARRAY['processed_at','attempts'])=(to_jsonb(OLD)-ARRAY['processed_at','attempts'])
   AND NEW.attempts>=OLD.attempts THEN RETURN NEW; END IF;
 END IF;
 IF protected AND current_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.approval_requests'::regclass) THEN
  RAISE EXCEPTION 'APPROVAL_RESERVED_NAMESPACE' USING ERRCODE='42501'; END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW;
END $$;
CREATE TRIGGER approval_namespace_guard BEFORE INSERT OR UPDATE OR DELETE ON public.idempotency FOR EACH ROW EXECUTE FUNCTION public.gc_approval_namespace_guard();
CREATE TRIGGER approval_namespace_guard BEFORE INSERT ON public.audit FOR EACH ROW EXECUTE FUNCTION public.gc_approval_namespace_guard();
CREATE TRIGGER approval_namespace_guard BEFORE INSERT OR UPDATE OR DELETE ON public.outbox FOR EACH ROW EXECUTE FUNCTION public.gc_approval_namespace_guard();

REVOKE ALL ON FUNCTION public.gc_approval_uuid(text),public.gc_approval_text(text,integer,boolean),public.gc_approval_definition_valid(jsonb),public.gc_approval_journal(text,uuid,text,integer,jsonb,text,boolean),
 public.gc_approval_request_view(uuid),public.gc_approval_command(text,text,jsonb,text),public.gc_approval_tick(uuid),
 public.gc_approval_dispatch_ack(uuid),public.gc_approval_namespace_guard() FROM PUBLIC,gc_app;
GRANT EXECUTE ON FUNCTION public.gc_approval_command(text,text,jsonb,text),public.gc_approval_tick(uuid),public.gc_approval_dispatch_ack(uuid) TO gc_app;
