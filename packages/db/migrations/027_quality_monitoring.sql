-- SPDX-License-Identifier: Apache-2.0
-- Private SQL027 candidate: fixed UTC monitoring, never source writes.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls)) OR pg_has_role('gc_app',current_user,'MEMBER') THEN
  RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='42501';END IF;
END $$;
CREATE TABLE public.quality_monitors(
 tenant_id uuid NOT NULL REFERENCES public.tenants(id),id uuid NOT NULL,rule_id uuid NOT NULL,executor_id uuid NOT NULL,
 revision integer NOT NULL CHECK(revision>0),definition_version integer NOT NULL CHECK(definition_version>0),
 state text NOT NULL CHECK(state IN('enabled','paused','retired')),blocked text CHECK(blocked IN('RULE_VERSION_CHANGED','AUTHORIZATION_EXPIRED','EXECUTOR_UNAVAILABLE','RULE_OWNER_UNAVAILABLE','TARGET_UNAVAILABLE','REFERENCE_UNAVAILABLE')),
 next_slot_at timestamptz,last_admitted_ordinal integer NOT NULL DEFAULT 0 CHECK(last_admitted_ordinal>=0),
 last_projected_ordinal integer NOT NULL DEFAULT 0 CHECK(last_projected_ordinal>=0 AND last_projected_ordinal<=last_admitted_ordinal),
 current_observation jsonb NOT NULL DEFAULT '{"state":"unobserved"}',last_conclusive jsonb,
 created_by uuid NOT NULL,created_at timestamptz NOT NULL,PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,rule_id) REFERENCES public.quality_rules(tenant_id,id),
 FOREIGN KEY(tenant_id,executor_id) REFERENCES public.memberships(tenant_id,identity_id),
 FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id),
 CHECK(executor_id=created_by),CHECK(octet_length(current_observation::text)<=8192),CHECK(last_conclusive IS NULL OR octet_length(last_conclusive::text)<=8192)
);
CREATE UNIQUE INDEX quality_monitor_one_enabled_rule ON public.quality_monitors(tenant_id,rule_id) WHERE state='enabled';
CREATE INDEX quality_monitor_due ON public.quality_monitors(tenant_id,next_slot_at,id) WHERE state='enabled' AND blocked IS NULL;
CREATE TABLE public.quality_monitor_versions(
 tenant_id uuid NOT NULL,monitor_id uuid NOT NULL,version integer NOT NULL CHECK(version>0),definition jsonb NOT NULL,
 definition_hash text NOT NULL CHECK(definition_hash~'^[a-f0-9]{64}$'),rule_id uuid NOT NULL,rule_version integer NOT NULL,rule_hash text NOT NULL,
 owner_id uuid NOT NULL,created_by uuid NOT NULL,created_at timestamptz NOT NULL,created_xid xid8 NOT NULL DEFAULT pg_current_xact_id(),
 PRIMARY KEY(tenant_id,monitor_id,version),UNIQUE(tenant_id,monitor_id,version,definition_hash),
 FOREIGN KEY(tenant_id,monitor_id) REFERENCES public.quality_monitors(tenant_id,id),
 FOREIGN KEY(tenant_id,rule_id,rule_version,rule_hash) REFERENCES public.quality_rule_versions(tenant_id,rule_id,version,definition_hash),
 FOREIGN KEY(tenant_id,owner_id) REFERENCES public.memberships(tenant_id,identity_id),
 FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id),CHECK(octet_length(public.gc_type_migration_canonical(definition))<=32768)
);
ALTER TABLE public.quality_monitors ADD CONSTRAINT quality_monitor_head FOREIGN KEY(tenant_id,id,definition_version)
 REFERENCES public.quality_monitor_versions(tenant_id,monitor_id,version) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE public.quality_monitor_schedule_segments(
 tenant_id uuid NOT NULL,monitor_id uuid NOT NULL,segment integer NOT NULL CHECK(segment>0),definition_version integer NOT NULL,
 next_slot_at timestamptz,cutoff_at timestamptz,mode text NOT NULL CHECK(mode IN('live','MISSED','PAUSED')),
 created_at timestamptz NOT NULL,created_by text NOT NULL,created_revision integer NOT NULL CHECK(created_revision>0),closed_at timestamptz,closed_revision integer,created_xid xid8 NOT NULL DEFAULT pg_current_xact_id(),
 PRIMARY KEY(tenant_id,monitor_id,segment),UNIQUE(tenant_id,monitor_id,created_revision),FOREIGN KEY(tenant_id,monitor_id,definition_version) REFERENCES public.quality_monitor_versions(tenant_id,monitor_id,version),
 CHECK((cutoff_at IS NULL)=(closed_at IS NULL)),CHECK((cutoff_at IS NULL)=(closed_revision IS NULL)),CHECK(cutoff_at IS NOT DISTINCT FROM closed_at),CHECK(created_by='site:local' OR public.gc_approval_uuid(created_by)),
 CHECK(cutoff_at IS NULL OR cutoff_at>=created_at),CHECK(mode<>'MISSED' OR cutoff_at IS NOT NULL)
);
CREATE UNIQUE INDEX quality_monitor_open_segment ON public.quality_monitor_schedule_segments(tenant_id,monitor_id) WHERE cutoff_at IS NULL;
CREATE TABLE public.quality_monitor_occurrences(
 tenant_id uuid NOT NULL,id uuid NOT NULL,monitor_id uuid NOT NULL,definition_version integer NOT NULL,definition_hash text NOT NULL,
 ordinal integer NOT NULL CHECK(ordinal>0),rule_id uuid NOT NULL,rule_version integer NOT NULL,rule_hash text NOT NULL,executor_id uuid NOT NULL,
 origin text NOT NULL CHECK(origin IN('schedule','recovery-request')),segment integer,first_slot_at timestamptz,last_slot_at timestamptz,slot_count integer,
 disposition text NOT NULL CHECK(disposition IN('enqueued','skipped')),reason text,
 run_id uuid,comparison_scope jsonb,comparison_scope_hash text,recorded_at timestamptz NOT NULL,
 created_xid xid8 NOT NULL DEFAULT pg_current_xact_id(),PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,monitor_id,ordinal),UNIQUE(tenant_id,run_id),
 FOREIGN KEY(tenant_id,monitor_id,definition_version,definition_hash) REFERENCES public.quality_monitor_versions(tenant_id,monitor_id,version,definition_hash),
 FOREIGN KEY(tenant_id,rule_id,rule_version,rule_hash) REFERENCES public.quality_rule_versions(tenant_id,rule_id,version,definition_hash),
 FOREIGN KEY(tenant_id,executor_id) REFERENCES public.memberships(tenant_id,identity_id),FOREIGN KEY(tenant_id,run_id) REFERENCES public.quality_runs(tenant_id,id),
 FOREIGN KEY(tenant_id,monitor_id,segment) REFERENCES public.quality_monitor_schedule_segments(tenant_id,monitor_id,segment),
 CHECK((origin='schedule')=(segment IS NOT NULL)),
 CHECK((origin='schedule' AND first_slot_at IS NOT NULL AND last_slot_at IS NOT NULL AND slot_count IS NOT NULL) OR (origin='recovery-request' AND first_slot_at IS NULL AND last_slot_at IS NULL AND slot_count IS NULL)),
 CHECK(slot_count IS NULL OR (slot_count>0 AND first_slot_at<=last_slot_at)),
 CHECK((disposition='enqueued' AND run_id IS NOT NULL AND comparison_scope IS NOT NULL AND comparison_scope_hash IS NOT NULL) OR (disposition='skipped' AND run_id IS NULL AND comparison_scope IS NULL AND comparison_scope_hash IS NULL)),
 CHECK((disposition='skipped')=(reason IS NOT NULL)),CHECK(reason IS NULL OR reason IN('MISSED','MAINTENANCE','OVERLAP','CAPACITY','PAUSED','RULE_VERSION_CHANGED','AUTHORIZATION_EXPIRED','EXECUTOR_UNAVAILABLE','RULE_OWNER_UNAVAILABLE','TARGET_UNAVAILABLE','REFERENCE_UNAVAILABLE')),
 CHECK(comparison_scope_hash IS NULL OR comparison_scope_hash~'^[a-f0-9]{64}$'),CHECK(comparison_scope IS NULL OR octet_length(comparison_scope::text)<=8192)
);
CREATE UNIQUE INDEX quality_monitor_slot_identity ON public.quality_monitor_occurrences(tenant_id,monitor_id,definition_version,first_slot_at) WHERE origin='schedule';
CREATE TABLE public.quality_monitor_incidents(
 tenant_id uuid NOT NULL,id uuid NOT NULL,monitor_id uuid NOT NULL,comparison_scope_hash text NOT NULL,
 version integer NOT NULL CHECK(version>0),episode integer NOT NULL CHECK(episode>0),status text NOT NULL CHECK(status IN('open','acknowledged','resolved','superseded')),
 rule_id uuid NOT NULL,rule_version integer NOT NULL,rule_hash text NOT NULL,table_asset_id uuid NOT NULL,column_asset_id uuid NOT NULL,
 severity text NOT NULL CHECK(severity IN('info','warning','critical')),assigned_owner_id uuid NOT NULL,
 opened_at timestamptz NOT NULL,acknowledge_due_at timestamptz NOT NULL,resolve_due_at timestamptz NOT NULL,
 opening jsonb NOT NULL,last_failure jsonb NOT NULL,recovery jsonb,resolution jsonb,superseded jsonb,
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,monitor_id,comparison_scope_hash),
 FOREIGN KEY(tenant_id,monitor_id) REFERENCES public.quality_monitors(tenant_id,id),
 FOREIGN KEY(tenant_id,rule_id,rule_version,rule_hash) REFERENCES public.quality_rule_versions(tenant_id,rule_id,version,definition_hash),
 FOREIGN KEY(tenant_id,table_asset_id) REFERENCES public.assets(tenant_id,id),FOREIGN KEY(tenant_id,column_asset_id) REFERENCES public.assets(tenant_id,id),
 FOREIGN KEY(tenant_id,assigned_owner_id) REFERENCES public.memberships(tenant_id,identity_id),
 CHECK(comparison_scope_hash~'^[a-f0-9]{64}$'),CHECK(acknowledge_due_at<=resolve_due_at AND opened_at<acknowledge_due_at),
 CHECK(octet_length(to_jsonb(ROW(opening,last_failure,recovery,resolution,superseded))::text)<=65536)
);
CREATE TABLE public.quality_monitor_incident_events(
 tenant_id uuid NOT NULL,id uuid NOT NULL,issue_id uuid NOT NULL,version integer NOT NULL,episode integer NOT NULL,
 kind text NOT NULL CHECK(kind IN('opened','failed-again','acknowledged','assigned','recovery-available','recovery-invalidated','resolved','reopened','superseded')),
 monitor_id uuid NOT NULL,definition_version integer NOT NULL,definition_hash text NOT NULL,occurrence_id uuid,run_id uuid,
 actor_id text NOT NULL,occurred_at timestamptz NOT NULL,reason text,snapshot jsonb NOT NULL,created_xid xid8 NOT NULL DEFAULT pg_current_xact_id(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,issue_id,version),FOREIGN KEY(tenant_id,issue_id) REFERENCES public.quality_monitor_incidents(tenant_id,id),
 FOREIGN KEY(tenant_id,monitor_id,definition_version,definition_hash) REFERENCES public.quality_monitor_versions(tenant_id,monitor_id,version,definition_hash),
 FOREIGN KEY(tenant_id,occurrence_id) REFERENCES public.quality_monitor_occurrences(tenant_id,id),FOREIGN KEY(tenant_id,run_id) REFERENCES public.quality_runs(tenant_id,id),
 CHECK(octet_length(snapshot::text)<=65536),CHECK(actor_id='site:local' OR public.gc_approval_uuid(actor_id))
);
CREATE TABLE public.quality_monitor_projection_receipts(
 tenant_id uuid NOT NULL,occurrence_id uuid NOT NULL,monitor_id uuid NOT NULL,ordinal integer NOT NULL,run_id uuid,run_version integer,completion_hash text,
 projected_at timestamptz NOT NULL,created_xid xid8 NOT NULL DEFAULT pg_current_xact_id(),PRIMARY KEY(tenant_id,occurrence_id),UNIQUE(tenant_id,monitor_id,ordinal),
 FOREIGN KEY(tenant_id,occurrence_id) REFERENCES public.quality_monitor_occurrences(tenant_id,id),FOREIGN KEY(tenant_id,monitor_id) REFERENCES public.quality_monitors(tenant_id,id),
 FOREIGN KEY(tenant_id,run_id) REFERENCES public.quality_runs(tenant_id,id),CHECK((run_id IS NULL)=(run_version IS NULL)),CHECK(run_version IS NULL OR run_version>0)
);
CREATE TABLE public.quality_monitor_notifications(
 tenant_id uuid NOT NULL,id uuid NOT NULL,event_id uuid NOT NULL,issue_id uuid NOT NULL,recipient_id uuid NOT NULL,template text NOT NULL,
 suppressed text CHECK(suppressed IN('SILENCED','RECIPIENT_UNAVAILABLE','RATE_LIMITED')),created_at timestamptz NOT NULL,read_at timestamptz,version integer NOT NULL DEFAULT 1,
 created_xid xid8 NOT NULL DEFAULT pg_current_xact_id(),PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,event_id,recipient_id),
 FOREIGN KEY(tenant_id,event_id) REFERENCES public.quality_monitor_incident_events(tenant_id,id),FOREIGN KEY(tenant_id,issue_id) REFERENCES public.quality_monitor_incidents(tenant_id,id),
 FOREIGN KEY(tenant_id,recipient_id) REFERENCES public.memberships(tenant_id,identity_id),CHECK(version IN(1,2)),CHECK((version=2)=(read_at IS NOT NULL)),
 CHECK(template IN('quality-issue-opened-v1','quality-issue-reopened-v1','quality-issue-assigned-v1','quality-recovery-available-v1','quality-issue-resolved-v1'))
);
CREATE INDEX quality_monitor_notification_recipient ON public.quality_monitor_notifications(tenant_id,recipient_id,id);
DO $$ DECLARE name text;BEGIN
 FOREACH name IN ARRAY ARRAY['quality_monitors','quality_monitor_versions','quality_monitor_schedule_segments','quality_monitor_occurrences','quality_monitor_incidents','quality_monitor_incident_events','quality_monitor_projection_receipts','quality_monitor_notifications'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',name);EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.gc_tenant()) WITH CHECK(tenant_id=public.gc_tenant())',name);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC,gc_app',name);EXECUTE format('GRANT SELECT ON public.%I TO gc_app',name);
 END LOOP;
 FOREACH name IN ARRAY ARRAY['quality_monitor_versions','quality_monitor_occurrences','quality_monitor_incident_events','quality_monitor_projection_receipts'] LOOP
  EXECUTE format('CREATE TRIGGER monitor_immutable BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.gc_immutable_audit()',name);
 END LOOP;
END $$;

-- SPDX-License-Identifier: Apache-2.0
CREATE FUNCTION public.gc_quality_monitor_integer(value jsonb,minimum bigint,maximum bigint) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN jsonb_typeof(value)='number' AND value#>>'{}'~'^(0|[1-9][0-9]{0,15})$' THEN (value#>>'{}')::bigint BETWEEN minimum AND maximum ELSE false END
$$;
CREATE FUNCTION public.gc_quality_monitor_windows_valid(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ DECLARE item jsonb;previous_until timestamptz;BEGIN
 IF jsonb_typeof(value) IS DISTINCT FROM 'array' THEN RETURN false;END IF;
 IF jsonb_array_length(value)>32 THEN RETURN false;END IF;
 FOR item IN SELECT v FROM jsonb_array_elements(value) v LOOP
  IF public.gc_relation_keys(item,ARRAY['from','until']) IS NOT TRUE OR NOT public.gc_reference_instant(item->'from') OR NOT public.gc_reference_instant(item->'until') THEN RETURN false;END IF;
  IF (item->>'from')::timestamptz>=(item->>'until')::timestamptz OR previous_until>(item->>'from')::timestamptz THEN RETURN false;END IF;
  previous_until:=(item->>'until')::timestamptz;
 END LOOP;RETURN true;
END $$;
CREATE FUNCTION public.gc_quality_monitor_definition_valid(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ DECLARE s jsonb;r jsonb;i jsonb;item jsonb;previous_id text;BEGIN
 IF public.gc_relation_keys(value,ARRAY['formatVersion','name','purpose','rule','executorId','authorizationExpiresAt','schedule','maintenance','silences','routing','issue','recoveryMaximumAgeSeconds','retry']) IS NOT TRUE
 OR value->'formatVersion' IS DISTINCT FROM '1'::jsonb OR octet_length(public.gc_type_migration_canonical(value))>32768
 OR jsonb_typeof(value->'name') IS DISTINCT FROM 'string' OR public.gc_approval_text(value->>'name',240,false) IS NULL OR value->>'name' IS DISTINCT FROM public.gc_approval_text(value->>'name',240,false)
 OR jsonb_typeof(value->'purpose') IS DISTINCT FROM 'string' OR public.gc_approval_text(value->>'purpose',4096,true) IS NULL OR value->>'purpose' IS DISTINCT FROM public.gc_approval_text(value->>'purpose',4096,true)
 OR NOT public.gc_approval_uuid(value->>'executorId') OR NOT public.gc_reference_instant(value->'authorizationExpiresAt')
 OR public.gc_relation_keys(value->'rule',ARRAY['id','version','definitionHash']) IS NOT TRUE OR NOT public.gc_approval_uuid(value#>>'{rule,id}')
 OR NOT public.gc_quality_monitor_integer(value#>'{rule,version}',1,2147483647) OR jsonb_typeof(value#>'{rule,definitionHash}') IS DISTINCT FROM 'string' OR value#>>'{rule,definitionHash}' !~ '^[a-f0-9]{64}$'
 OR NOT public.gc_quality_monitor_windows_valid(value->'maintenance') OR NOT public.gc_quality_monitor_windows_valid(value->'silences')
 OR value->'retry' IS DISTINCT FROM '{"policy":"quality-run-v1"}'::jsonb THEN RETURN false;END IF;
 s:=value->'schedule';r:=value->'routing';i:=value->'issue';
 IF public.gc_relation_keys(s,ARRAY['kind','timeZone','startsAt','endsAt','intervalSeconds','lateGraceSeconds','missedSlots','overlap']) IS NOT TRUE
 OR s->>'kind' IS DISTINCT FROM 'fixed-interval' OR s->>'timeZone' IS DISTINCT FROM 'UTC' OR s->>'missedSlots' IS DISTINCT FROM 'skip' OR s->>'overlap' IS DISTINCT FROM 'skip'
 OR NOT public.gc_reference_instant(s->'startsAt') OR NOT public.gc_reference_instant(s->'endsAt',true)
 OR NOT public.gc_quality_monitor_integer(s->'intervalSeconds',60,604800) OR NOT public.gc_quality_monitor_integer(s->'lateGraceSeconds',0,300) THEN RETURN false;END IF;
 IF s->'endsAt'<>'null'::jsonb AND (s->>'endsAt')::timestamptz<=(s->>'startsAt')::timestamptz OR (s->>'lateGraceSeconds')::integer>=(s->>'intervalSeconds')::integer
 OR NOT public.gc_quality_monitor_integer(value->'recoveryMaximumAgeSeconds',(s->>'intervalSeconds')::integer,604800) THEN RETURN false;END IF;
 IF public.gc_relation_keys(r,ARRAY['channel','ownerId','recipientIds']) IS NOT TRUE OR r->>'channel' IS DISTINCT FROM 'in-app' OR NOT public.gc_approval_uuid(r->>'ownerId')
 OR jsonb_typeof(r->'recipientIds') IS DISTINCT FROM 'array' THEN RETURN false;END IF;
 IF jsonb_array_length(r->'recipientIds') NOT BETWEEN 1 AND 16 THEN RETURN false;END IF;
 FOR item IN SELECT v FROM jsonb_array_elements(r->'recipientIds') v LOOP
  IF jsonb_typeof(item) IS DISTINCT FROM 'string' OR NOT public.gc_approval_uuid(item#>>'{}') OR previous_id COLLATE "C">=(item#>>'{}') COLLATE "C" THEN RETURN false;END IF;
  previous_id:=item#>>'{}';
 END LOOP;
 IF NOT r->'recipientIds' @> jsonb_build_array(r->>'ownerId') OR public.gc_relation_keys(i,ARRAY['category','acknowledgeWithinSeconds','resolveWithinSeconds']) IS NOT TRUE
 OR i->>'category' IS DISTINCT FROM 'data-quality' OR NOT public.gc_quality_monitor_integer(i->'acknowledgeWithinSeconds',1,2678400)
 OR NOT public.gc_quality_monitor_integer(i->'resolveWithinSeconds',1,2678400) THEN RETURN false;END IF;
 RETURN (i->>'acknowledgeWithinSeconds')::integer<=(i->>'resolveWithinSeconds')::integer;
END $$;
CREATE FUNCTION public.gc_quality_monitor_first_slot(definition jsonb,at_time timestamptz) RETURNS timestamptz
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ DECLARE start_at timestamptz:=(definition#>>'{schedule,startsAt}')::timestamptz;last_at timestamptz:=(definition#>>'{schedule,endsAt}')::timestamptz;step_seconds integer:=(definition#>>'{schedule,intervalSeconds}')::integer;result timestamptz;BEGIN
 result:=start_at+greatest(0,ceil(extract(epoch FROM at_time-start_at)/step_seconds))*make_interval(secs=>step_seconds);
 IF result>='10000-01-01'::timestamptz OR last_at IS NOT NULL AND result>=last_at THEN RETURN NULL;END IF;RETURN result;
END $$;
CREATE FUNCTION public.gc_quality_monitor_in_window(windows jsonb,at_time timestamptz) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT EXISTS(SELECT 1 FROM jsonb_array_elements(windows) w WHERE (w->>'from')::timestamptz<=at_time AND (w->>'until')::timestamptz>at_time)
$$;

-- SPDX-License-Identifier: Apache-2.0
CREATE FUNCTION public.gc_quality_monitor_lock(monitor_ids uuid[],new_definitions jsonb[] DEFAULT ARRAY[]::jsonb[],issue_ids uuid[] DEFAULT ARRAY[]::uuid[],occurrence_ids uuid[] DEFAULT ARRAY[]::uuid[],extra_principals uuid[] DEFAULT ARRAY[]::uuid[]) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant();defs jsonb[];principals uuid[];rules uuid[];columns uuid[];references_ids uuid[];item uuid;BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text,0));
 SELECT coalesce(array_agg(d),'{}'::jsonb[]) INTO defs FROM (
  SELECT v.definition d FROM public.quality_monitor_versions v JOIN public.quality_monitors m ON m.tenant_id=v.tenant_id AND m.id=v.monitor_id AND m.definition_version=v.version WHERE m.tenant_id=tenant AND m.id=ANY(monitor_ids)
  UNION ALL SELECT v.definition FROM public.quality_monitor_versions v JOIN public.quality_monitor_occurrences o ON o.tenant_id=v.tenant_id AND o.monitor_id=v.monitor_id AND o.definition_version=v.version WHERE o.tenant_id=tenant AND o.id=ANY(occurrence_ids)
  UNION ALL SELECT unnest(new_definitions)) d;
 SELECT array_agg(DISTINCT id) INTO rules FROM (
  SELECT (d#>>'{rule,id}')::uuid id FROM unnest(defs) d
  UNION SELECT rule_id FROM public.quality_monitor_incidents WHERE tenant_id=tenant AND id=ANY(issue_ids)) q;
 SELECT array_agg(DISTINCT id) INTO principals FROM (
  SELECT unnest(extra_principals) id UNION SELECT CASE WHEN public.gc_approval_uuid(public.gc_actor()) THEN public.gc_actor()::uuid END
  UNION SELECT (d->>'executorId')::uuid FROM unnest(defs) d
  UNION SELECT (d#>>'{routing,ownerId}')::uuid FROM unnest(defs) d
  UNION SELECT x::uuid FROM unnest(defs) d CROSS JOIN LATERAL jsonb_array_elements_text(d#>'{routing,recipientIds}') x
  UNION SELECT v.owner_id FROM unnest(defs) d JOIN public.quality_rule_versions v ON v.tenant_id=tenant AND v.rule_id=(d#>>'{rule,id}')::uuid AND v.version=(d#>>'{rule,version}')::integer
  UNION SELECT v.owner_id FROM public.quality_monitor_incidents i JOIN public.quality_rule_versions v ON v.tenant_id=i.tenant_id AND v.rule_id=i.rule_id AND v.version=i.rule_version WHERE i.tenant_id=tenant AND i.id=ANY(issue_ids)
  UNION SELECT assigned_owner_id FROM public.quality_monitor_incidents WHERE tenant_id=tenant AND id=ANY(issue_ids)) q WHERE id IS NOT NULL;
 -- No resource lock is taken until the complete global identity and tenant membership union is held.
 FOR item IN SELECT id FROM public.identities WHERE id=ANY(principals) ORDER BY id FOR SHARE LOOP NULL;END LOOP;
 FOR item IN SELECT identity_id FROM public.memberships WHERE tenant_id=tenant AND identity_id=ANY(principals) ORDER BY identity_id FOR SHARE LOOP NULL;END LOOP;
 SELECT array_agg(column_asset_id) INTO columns FROM public.quality_rules WHERE tenant_id=tenant AND id=ANY(rules);
 FOR item IN SELECT id FROM public.sources WHERE tenant_id=tenant AND id IN(SELECT source_id FROM public.assets WHERE tenant_id=tenant AND id=ANY(columns)) ORDER BY id FOR SHARE LOOP NULL;END LOOP;
 FOR item IN SELECT id FROM public.assets WHERE tenant_id=tenant AND id IN(
  SELECT id FROM public.assets WHERE tenant_id=tenant AND id=ANY(columns)
  UNION SELECT t.id FROM public.assets c JOIN public.assets t ON t.tenant_id=c.tenant_id AND t.source_id=c.source_id AND t.external_id=c.parent_external_id WHERE c.tenant_id=tenant AND c.id=ANY(columns)
  UNION SELECT s.id FROM public.assets c JOIN public.assets t ON t.tenant_id=c.tenant_id AND t.source_id=c.source_id AND t.external_id=c.parent_external_id JOIN public.assets s ON s.tenant_id=t.tenant_id AND s.source_id=t.source_id AND s.external_id=t.parent_external_id WHERE c.tenant_id=tenant AND c.id=ANY(columns)
 ) ORDER BY id FOR SHARE LOOP NULL;END LOOP;
 SELECT array_agg(DISTINCT (v.definition#>>'{reference,setId}')::uuid) INTO references_ids FROM public.quality_rule_versions v WHERE v.tenant_id=tenant AND v.definition->>'kind'='reference-allowed-values' AND (
  EXISTS(SELECT 1 FROM unnest(defs) d WHERE v.rule_id=(d#>>'{rule,id}')::uuid AND v.version=(d#>>'{rule,version}')::integer)
  OR EXISTS(SELECT 1 FROM public.quality_monitor_incidents i WHERE i.tenant_id=tenant AND i.id=ANY(issue_ids) AND i.rule_id=v.rule_id AND i.rule_version=v.version));
 FOR item IN SELECT id FROM public.reference_sets WHERE tenant_id=tenant AND id=ANY(references_ids) ORDER BY id FOR SHARE LOOP NULL;END LOOP;
 FOR item IN SELECT id FROM public.quality_rules WHERE tenant_id=tenant AND id=ANY(rules) ORDER BY id FOR SHARE LOOP NULL;END LOOP;
 FOR item IN SELECT id FROM public.quality_monitors WHERE tenant_id=tenant AND id=ANY(monitor_ids) ORDER BY id FOR UPDATE LOOP NULL;END LOOP;
 FOR item IN SELECT id FROM public.quality_monitor_occurrences WHERE tenant_id=tenant AND id=ANY(occurrence_ids) ORDER BY id FOR SHARE LOOP NULL;END LOOP;
 FOR item IN SELECT id FROM public.quality_runs WHERE tenant_id=tenant AND id IN(SELECT run_id FROM public.quality_monitor_occurrences WHERE tenant_id=tenant AND (id=ANY(occurrence_ids) OR monitor_id=ANY(monitor_ids) AND disposition='enqueued' AND ordinal>(SELECT last_projected_ordinal FROM public.quality_monitors WHERE tenant_id=tenant AND id=monitor_id))) ORDER BY id FOR UPDATE LOOP NULL;END LOOP;
 FOR item IN SELECT id FROM public.quality_monitor_incidents WHERE tenant_id=tenant AND id=ANY(issue_ids) ORDER BY id FOR UPDATE LOOP NULL;END LOOP;
END $$;
CREATE FUNCTION public.gc_quality_monitor_visible(monitor_identity uuid,actor_identity uuid,selected_version integer DEFAULT NULL) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM public.quality_monitors m JOIN public.quality_monitor_versions v ON v.tenant_id=m.tenant_id AND v.monitor_id=m.id AND v.version=coalesce(selected_version,m.definition_version)
 WHERE m.tenant_id=public.gc_tenant() AND m.id=monitor_identity AND public.gc_quality_rule_visible(v.rule_id,v.rule_version,actor_identity)
 AND (selected_version IS NOT NULL OR (
  (m.last_conclusive IS NULL OR public.gc_quality_run_visible((m.last_conclusive#>>'{evidence,runId}')::uuid,actor_identity))
  AND (m.current_observation->>'state' NOT IN('pending','conclusive') OR public.gc_quality_run_visible(coalesce(m.current_observation->>'runId',m.current_observation#>>'{evidence,runId}')::uuid,actor_identity)))))
$$;
CREATE FUNCTION public.gc_quality_occurrence_visible(occurrence_identity uuid,actor_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM public.quality_monitor_occurrences o WHERE o.tenant_id=public.gc_tenant() AND o.id=occurrence_identity
 AND public.gc_quality_monitor_visible(o.monitor_id,actor_identity,o.definition_version) AND (o.run_id IS NULL OR public.gc_quality_run_visible(o.run_id,actor_identity)))
$$;
CREATE FUNCTION public.gc_quality_issue_visible(issue_identity uuid,actor_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM public.quality_monitor_incidents i WHERE i.tenant_id=public.gc_tenant() AND i.id=issue_identity
 AND public.gc_quality_rule_visible(i.rule_id,i.rule_version,actor_identity)
 AND public.gc_quality_run_visible((i.opening->>'runId')::uuid,actor_identity) AND public.gc_quality_run_visible((i.last_failure->>'runId')::uuid,actor_identity)
 AND (i.recovery IS NULL OR public.gc_quality_run_visible((i.recovery->>'runId')::uuid,actor_identity))
 AND (i.resolution IS NULL OR public.gc_quality_run_visible((i.resolution#>>'{evidence,runId}')::uuid,actor_identity))
 AND (i.superseded IS NULL OR public.gc_quality_monitor_visible((i.superseded->>'replacementMonitorId')::uuid,actor_identity,(i.superseded->>'replacementDefinitionVersion')::integer)))
$$;
CREATE FUNCTION public.gc_quality_issue_event_visible(event_identity uuid,actor_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM public.quality_monitor_incident_events e WHERE e.tenant_id=public.gc_tenant() AND e.id=event_identity
 AND public.gc_quality_issue_visible(e.issue_id,actor_identity)
 AND public.gc_quality_monitor_visible(e.monitor_id,actor_identity,e.definition_version)
 AND (e.occurrence_id IS NULL OR public.gc_quality_occurrence_visible(e.occurrence_id,actor_identity))
 AND (e.kind<>'resolved' OR public.gc_quality_run_visible((e.snapshot#>>'{resolution,evidence,runId}')::uuid,actor_identity)))
$$;
CREATE FUNCTION public.gc_quality_notification_visible(notification_identity uuid,actor_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM public.quality_monitor_notifications n WHERE n.tenant_id=public.gc_tenant() AND n.id=notification_identity AND n.recipient_id=actor_identity AND n.suppressed IS NULL AND public.gc_quality_issue_event_visible(n.event_id,actor_identity))
$$;
CREATE FUNCTION public.gc_quality_monitor_inputs(monitor_definition jsonb,at_time timestamptz) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE v public.quality_rule_versions;r public.quality_rules;inputs jsonb;binding jsonb;executor uuid:=(monitor_definition->>'executorId')::uuid;BEGIN
 SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=public.gc_tenant() AND rule_id=(monitor_definition#>>'{rule,id}')::uuid AND version=(monitor_definition#>>'{rule,version}')::integer;
 SELECT * INTO r FROM public.quality_rules WHERE tenant_id=v.tenant_id AND id=v.rule_id;
 IF NOT public.gc_quality_rule_visible(v.rule_id,v.version,executor) OR NOT public.gc_quality_can_execute(r.column_asset_id,executor) OR NOT public.gc_quality_reference_owner_active(v.owner_id) THEN RAISE EXCEPTION 'MONITOR_FORBIDDEN' USING ERRCODE='42501';END IF;
 IF r.current_version IS DISTINCT FROM v.version OR v.definition_hash IS DISTINCT FROM monitor_definition#>>'{rule,definitionHash}' THEN RAISE EXCEPTION 'MONITOR_PIN_STALE' USING ERRCODE='40001';END IF;
 inputs:=public.gc_quality_inputs(r.column_asset_id,executor);
 IF v.definition->'target' IS DISTINCT FROM jsonb_build_object('tableAssetId',inputs->'tableAssetId','columnAssetId',inputs->'columnAssetId') THEN RAISE EXCEPTION 'MONITOR_PIN_STALE' USING ERRCODE='40001';END IF;
 IF v.definition->>'kind'='reference-allowed-values' THEN
  binding:=public.gc_quality_reference_binding((v.definition#>>'{reference,setId}')::uuid,executor,at_time);
  inputs:=jsonb_set(inputs,'{execution}',(inputs->'execution')||jsonb_build_object('kind','reference-allowed-values','reference',binding));
 ELSIF v.definition->>'kind'='uniqueness' THEN inputs:=jsonb_set(inputs,'{execution}',(inputs->'execution')||jsonb_build_object('kind','uniqueness','budget',(inputs#>'{execution,budget}')||jsonb_build_object('maximumValueBytes',4096,'maximumTotalValueBytes',67108864)));
 ELSIF v.definition->>'kind'='range' THEN inputs:=jsonb_set(inputs,'{execution}',(inputs->'execution')||jsonb_build_object('kind','range','range',public.gc_quality_range_binding(v.definition)));
 END IF;RETURN inputs;
END $$;
CREATE FUNCTION public.gc_quality_monitor_scope(monitor_identity uuid,definition jsonb,inputs jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT jsonb_build_object('formatVersion',1,'monitorId',monitor_identity,'executorId',definition->'executorId','rule',definition->'rule',
 'sourceId',inputs->'sourceId','sourceVersion',inputs->'sourceVersion','sourceConfigHash',inputs->'sourceConfigHash','schemaAssetId',inputs->'schemaAssetId','tableAssetId',inputs->'tableAssetId','columnAssetId',inputs->'columnAssetId','targetHash',public.gc_type_migration_hash(inputs#>'{execution,target}'),
 'family',CASE inputs#>>'{execution,kind}' WHEN 'uniqueness' THEN '{"kind":"uniqueness","comparison":"utf8-exact","nullPolicy":"exclude"}'::jsonb
 WHEN 'range' THEN jsonb_build_object('kind','range','rangeHash',inputs#>'{execution,range,rangeHash}')
 WHEN 'reference-allowed-values' THEN jsonb_build_object('kind','reference-allowed-values','setId',inputs#>'{execution,reference,setId}','version',inputs#>'{execution,reference,version}','publicationHash',inputs#>'{execution,reference,publicationHash}','codeStatus','active','codesHash',public.gc_type_migration_hash(inputs#>'{execution,reference,codes}'))
 ELSE '{"kind":"completeness"}'::jsonb END)
$$;
CREATE FUNCTION public.gc_quality_monitor_block(monitor_definition jsonb,at_time timestamptz) RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE v public.quality_rule_versions;r public.quality_rules;executor uuid:=(monitor_definition->>'executorId')::uuid;BEGIN
 IF (monitor_definition->>'authorizationExpiresAt')::timestamptz<=at_time THEN RETURN 'AUTHORIZATION_EXPIRED';END IF;
 IF NOT public.gc_quality_reference_owner_active(executor) OR NOT EXISTS(SELECT 1 FROM public.memberships WHERE tenant_id=public.gc_tenant() AND identity_id=executor AND permissions @> '["catalog:read","quality:read","quality:execute"]') THEN RETURN 'EXECUTOR_UNAVAILABLE';END IF;
 SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=public.gc_tenant() AND rule_id=(monitor_definition#>>'{rule,id}')::uuid AND version=(monitor_definition#>>'{rule,version}')::integer;
 SELECT * INTO r FROM public.quality_rules WHERE tenant_id=public.gc_tenant() AND id=v.rule_id;
 IF NOT public.gc_quality_visible(r.column_asset_id,executor) THEN RETURN 'TARGET_UNAVAILABLE';END IF;
 IF NOT public.gc_quality_reference_owner_active(v.owner_id) THEN RETURN 'RULE_OWNER_UNAVAILABLE';END IF;
 IF v.definition->>'kind'='reference-allowed-values' AND NOT public.gc_reference_visible((v.definition#>>'{reference,setId}')::uuid,executor) THEN RETURN 'REFERENCE_UNAVAILABLE';END IF;
 IF r.current_version IS DISTINCT FROM v.version OR v.definition_hash IS DISTINCT FROM monitor_definition#>>'{rule,definitionHash}' THEN RETURN 'RULE_VERSION_CHANGED';END IF;
 BEGIN PERFORM public.gc_quality_monitor_inputs(monitor_definition,at_time);
 EXCEPTION WHEN feature_not_supported THEN IF v.definition->>'kind'='reference-allowed-values' AND SQLERRM='QUALITY_REFERENCE_UNAVAILABLE' THEN RETURN 'REFERENCE_UNAVAILABLE';ELSE RETURN 'TARGET_UNAVAILABLE';END IF;
 WHEN no_data_found THEN RETURN 'TARGET_UNAVAILABLE';WHEN serialization_failure THEN RETURN 'TARGET_UNAVAILABLE';WHEN insufficient_privilege THEN RETURN 'EXECUTOR_UNAVAILABLE';END;
 RETURN NULL;
END $$;

-- SPDX-License-Identifier: Apache-2.0
CREATE FUNCTION public.gc_quality_monitor_view(monitor_identity uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT jsonb_build_object('id',m.id,'revision',m.revision,'definitionVersion',m.definition_version,'definitionHash',v.definition_hash,'definition',v.definition,
 'state',m.state,'blocked',m.blocked,'nextSlotAt',public.gc_relation_utc(m.next_slot_at),'lastAdmittedOrdinal',m.last_admitted_ordinal,'lastProjectedOrdinal',m.last_projected_ordinal,
 'currentObservation',CASE WHEN m.current_observation->>'state'='conclusive' AND (m.current_observation#>>'{evidence,observedFinishedAt}')::timestamptz+make_interval(secs=>(v.definition->>'recoveryMaximumAgeSeconds')::integer)<clock_timestamp()
 THEN jsonb_build_object('state','unknown','reason','STALE','occurrenceId',m.current_observation#>'{evidence,occurrenceId}') ELSE m.current_observation END,
 'lastConclusive',m.last_conclusive,'createdAt',public.gc_relation_utc(m.created_at),'createdBy',m.created_by)
 FROM public.quality_monitors m JOIN public.quality_monitor_versions v ON v.tenant_id=m.tenant_id AND v.monitor_id=m.id AND v.version=m.definition_version WHERE m.tenant_id=public.gc_tenant() AND m.id=monitor_identity
$$;
CREATE FUNCTION public.gc_quality_monitor_definition_view(monitor_identity uuid,selected_version integer) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT jsonb_build_object('monitorId',v.monitor_id,'definitionVersion',v.version,'definitionHash',v.definition_hash,'definition',v.definition,'createdAt',public.gc_relation_utc(v.created_at),'createdBy',v.created_by)
 FROM public.quality_monitor_versions v WHERE v.tenant_id=public.gc_tenant() AND v.monitor_id=monitor_identity AND v.version=selected_version
$$;
CREATE FUNCTION public.gc_quality_occurrence_view(occurrence_identity uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT jsonb_build_object('id',o.id,'monitorId',o.monitor_id,'definitionVersion',o.definition_version,'definitionHash',o.definition_hash,'ordinal',o.ordinal,
 'rule',jsonb_build_object('id',o.rule_id,'version',o.rule_version,'definitionHash',o.rule_hash),'executorId',o.executor_id,'origin',o.origin,
 'slots',CASE WHEN o.origin='schedule' THEN jsonb_build_object('firstAt',public.gc_relation_utc(o.first_slot_at),'lastAt',public.gc_relation_utc(o.last_slot_at),'count',o.slot_count) ELSE NULL END,
 'recordedAt',public.gc_relation_utc(o.recorded_at),'disposition',o.disposition,'reason',o.reason,'runId',o.run_id,'comparisonScopeHash',o.comparison_scope_hash)
 FROM public.quality_monitor_occurrences o WHERE o.tenant_id=public.gc_tenant() AND o.id=occurrence_identity
$$;
CREATE FUNCTION public.gc_quality_monitor_recovery_eligible(issue_identity uuid,evidence jsonb) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE i public.quality_monitor_incidents;m public.quality_monitors;v public.quality_monitor_versions;inputs jsonb;now_at timestamptz:=date_trunc('milliseconds',clock_timestamp());BEGIN
 SELECT * INTO i FROM public.quality_monitor_incidents WHERE tenant_id=public.gc_tenant() AND id=issue_identity;
 SELECT * INTO m FROM public.quality_monitors WHERE tenant_id=i.tenant_id AND id=i.monitor_id;
 SELECT * INTO v FROM public.quality_monitor_versions WHERE tenant_id=m.tenant_id AND monitor_id=m.id AND version=m.definition_version;
 IF evidence IS NULL OR i.status NOT IN('open','acknowledged') OR m.state<>'enabled' OR m.blocked IS NOT NULL
 OR m.last_projected_ordinal<>m.last_admitted_ordinal OR (evidence->>'ordinal')::integer<>m.last_admitted_ordinal
 OR v.rule_id<>i.rule_id OR v.rule_version<>i.rule_version OR v.rule_hash<>i.rule_hash
 OR (evidence->>'observedFinishedAt')::timestamptz>now_at OR (evidence->>'observedFinishedAt')::timestamptz+make_interval(secs=>(v.definition->>'recoveryMaximumAgeSeconds')::integer)<now_at
 OR public.gc_quality_monitor_block(v.definition,now_at) IS NOT NULL THEN RETURN false;END IF;
 inputs:=public.gc_quality_monitor_inputs(v.definition,now_at);
 RETURN public.gc_type_migration_hash(public.gc_quality_monitor_scope(m.id,v.definition,inputs))=i.comparison_scope_hash
 AND EXISTS(SELECT 1 FROM public.quality_monitor_occurrences o JOIN public.quality_runs q ON q.tenant_id=o.tenant_id AND q.id=o.run_id
 WHERE o.tenant_id=i.tenant_id AND o.id=(evidence->>'occurrenceId')::uuid AND o.monitor_id=m.id AND o.ordinal=m.last_admitted_ordinal
 AND q.id=(evidence->>'runId')::uuid AND q.version=(evidence->>'runVersion')::integer AND q.completion_hash=evidence->>'completionHash'
 AND q.status='succeeded' AND q.verdict='PASS' AND o.comparison_scope_hash=i.comparison_scope_hash);
 EXCEPTION WHEN feature_not_supported OR no_data_found OR serialization_failure OR insufficient_privilege THEN RETURN false;
END $$;
CREATE FUNCTION public.gc_quality_monitor_recovery_current(issue_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT coalesce((SELECT public.gc_quality_monitor_recovery_eligible(i.id,i.recovery) FROM public.quality_monitor_incidents i WHERE i.tenant_id=public.gc_tenant() AND i.id=issue_identity),false)
$$;
CREATE FUNCTION public.gc_quality_issue_view(issue_identity uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT jsonb_build_object('id',i.id,'version',i.version,'monitorId',i.monitor_id,'comparisonScopeHash',i.comparison_scope_hash,
 'rule',jsonb_build_object('id',i.rule_id,'version',i.rule_version,'definitionHash',i.rule_hash),'category','data-quality','severity',i.severity,'tableAssetId',i.table_asset_id,'columnAssetId',i.column_asset_id,
 'status',i.status,'episode',i.episode,'assignedOwnerId',i.assigned_owner_id,'ownerAvailable',public.gc_quality_rule_visible(i.rule_id,i.rule_version,i.assigned_owner_id),
 'openedAt',public.gc_relation_utc(i.opened_at),'acknowledgeDueAt',public.gc_relation_utc(i.acknowledge_due_at),'resolveDueAt',public.gc_relation_utc(i.resolve_due_at),
 'opening',i.opening,'lastFailure',i.last_failure,'recovery',CASE WHEN public.gc_quality_monitor_recovery_current(i.id) THEN i.recovery ELSE NULL END,'resolution',i.resolution,'superseded',i.superseded)
 FROM public.quality_monitor_incidents i WHERE i.tenant_id=public.gc_tenant() AND i.id=issue_identity
$$;
CREATE FUNCTION public.gc_quality_issue_event_view(event_identity uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT jsonb_build_object('id',e.id,'issueId',e.issue_id,'version',e.version,'episode',e.episode,'kind',e.kind,
 'monitor',jsonb_build_object('monitorId',e.monitor_id,'definitionVersion',e.definition_version,'definitionHash',e.definition_hash),
 'occurrenceId',e.occurrence_id,'runId',e.run_id,'actorId',e.actor_id,'at',public.gc_relation_utc(e.occurred_at),'reason',e.reason,'resolution',CASE WHEN e.kind='resolved' THEN e.snapshot->'resolution' ELSE NULL END)
 FROM public.quality_monitor_incident_events e WHERE e.tenant_id=public.gc_tenant() AND e.id=event_identity
$$;
CREATE FUNCTION public.gc_quality_notification_view(notification_identity uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT jsonb_build_object('id',n.id,'eventId',n.event_id,'issueId',n.issue_id,'recipientId',n.recipient_id,'template',n.template,'createdAt',public.gc_relation_utc(n.created_at),'readAt',public.gc_relation_utc(n.read_at),'version',n.version)
 FROM public.quality_monitor_notifications n WHERE n.tenant_id=public.gc_tenant() AND n.id=notification_identity
$$;

-- SPDX-License-Identifier: Apache-2.0
-- The actor is never changed: site-created runs retain the human requester in
-- their canonical row, with a separate occurrence journal proving delegation.
CREATE FUNCTION public.gc_quality_monitor_occurrence(monitor_identity uuid,definition_version integer,occurrence_identity uuid,origin text,first_at timestamptz,last_at timestamptz,slot_count integer,skip_reason text,inputs jsonb DEFAULT NULL,segment_identity integer DEFAULT NULL) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant();m public.quality_monitors;v public.quality_monitor_versions;run_identity uuid;scope jsonb;scope_hash text;binding jsonb;now_at timestamptz:=date_trunc('milliseconds',clock_timestamp());next_ordinal integer;BEGIN
 SELECT * INTO m FROM public.quality_monitors WHERE tenant_id=tenant AND id=monitor_identity;
 SELECT * INTO v FROM public.quality_monitor_versions WHERE tenant_id=tenant AND monitor_id=m.id AND version=definition_version;
 IF m.id IS NULL OR v.version IS NULL OR (skip_reason IS NULL)<>(inputs IS NOT NULL) OR m.last_admitted_ordinal=2147483647 THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 next_ordinal:=m.last_admitted_ordinal+1;
 IF inputs IS NOT NULL THEN
  run_identity:=gen_random_uuid();scope:=public.gc_quality_monitor_scope(m.id,v.definition,inputs);scope_hash:=public.gc_type_migration_hash(scope);
  INSERT INTO public.quality_runs(tenant_id,id,rule_id,rule_version,rule_hash,requester_id,source_id,schema_asset_id,table_asset_id,column_asset_id,inputs,input_hash,status,expires_at,created_at)
  VALUES(tenant,run_identity,v.rule_id,v.rule_version,v.rule_hash,m.executor_id,(inputs->>'sourceId')::uuid,(inputs->>'schemaAssetId')::uuid,(inputs->>'tableAssetId')::uuid,(inputs->>'columnAssetId')::uuid,
   inputs,public.gc_type_migration_hash(inputs),'queued',least(now_at+interval '10 minutes',(v.definition->>'authorizationExpiresAt')::timestamptz),now_at);
  binding:=inputs#>'{execution,reference}';
  IF binding IS NOT NULL THEN INSERT INTO public.quality_run_reference_bindings(tenant_id,run_id,set_id,release_version,publication_hash,as_of,code_status,binding_hash)
   VALUES(tenant,run_identity,(binding->>'setId')::uuid,(binding->>'version')::integer,binding->>'publicationHash',(binding->>'asOf')::timestamptz,'active',binding->>'bindingHash');END IF;
  PERFORM public.gc_approval_journal('quality.run_requested',NULL,inputs->>'columnAssetId',1,jsonb_build_object('ruleId',v.rule_id,'runId',run_identity,'ruleVersion',v.rule_version,'inputHash',public.gc_type_migration_hash(inputs)),'monitor:'||occurrence_identity::text);
 END IF;
 INSERT INTO public.quality_monitor_occurrences(tenant_id,id,monitor_id,definition_version,definition_hash,ordinal,rule_id,rule_version,rule_hash,executor_id,origin,segment,first_slot_at,last_slot_at,slot_count,disposition,reason,run_id,comparison_scope,comparison_scope_hash,recorded_at)
 VALUES(tenant,occurrence_identity,m.id,v.version,v.definition_hash,next_ordinal,v.rule_id,v.rule_version,v.rule_hash,m.executor_id,origin,segment_identity,first_at,last_at,slot_count,CASE WHEN skip_reason IS NULL THEN 'enqueued' ELSE 'skipped' END,skip_reason,run_identity,scope,scope_hash,now_at);
 UPDATE public.quality_monitors SET last_admitted_ordinal=next_ordinal,current_observation=CASE WHEN run_identity IS NOT NULL THEN jsonb_build_object('state','pending','occurrenceId',occurrence_identity,'runId',run_identity)
 ELSE jsonb_build_object('state','unknown','reason',CASE WHEN skip_reason IN('RULE_VERSION_CHANGED','AUTHORIZATION_EXPIRED','EXECUTOR_UNAVAILABLE','RULE_OWNER_UNAVAILABLE','TARGET_UNAVAILABLE','REFERENCE_UNAVAILABLE') THEN 'BLOCKED' ELSE 'SKIPPED' END,'occurrenceId',occurrence_identity) END WHERE tenant_id=tenant AND id=m.id;
 PERFORM public.gc_approval_journal('quality.monitor_occurrence',NULL,m.id::text,next_ordinal,jsonb_build_object('occurrenceId',occurrence_identity,'definitionVersion',v.version,'definitionHash',v.definition_hash,'ordinal',next_ordinal,'disposition',CASE WHEN skip_reason IS NULL THEN 'enqueued' ELSE 'skipped' END,'reason',skip_reason,'runId',run_identity,'comparisonScopeHash',scope_hash),'monitor:'||m.id::text);
 RETURN occurrence_identity;
END $$;
CREATE FUNCTION public.gc_quality_monitor_capacity(monitor_identity uuid,source_identity uuid) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT CASE WHEN count(*) FILTER(WHERE o.monitor_id=monitor_identity)>0 THEN 'OVERLAP'
 WHEN count(*)>=8 OR count(*) FILTER(WHERE q.source_id=source_identity)>=2 THEN 'CAPACITY' ELSE NULL END
 FROM public.quality_monitor_occurrences o JOIN public.quality_runs q ON q.tenant_id=o.tenant_id AND q.id=o.run_id
 WHERE o.tenant_id=public.gc_tenant() AND q.status IN('queued','running')
$$;
CREATE FUNCTION public.gc_quality_monitor_tick(monitor_identity uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant();m public.quality_monitors;v public.quality_monitor_versions;s public.quality_monitor_schedule_segments;
 now_at timestamptz:=date_trunc('milliseconds',clock_timestamp());last_due timestamptz;end_at timestamptz;through_at timestamptz;next_at timestamptz;slot_window jsonb;reason text;inputs jsonb;occ uuid;run_identity uuid;step_seconds integer;count_slots bigint;state_name text:='idle';BEGIN
 IF public.gc_actor() IS DISTINCT FROM 'site:local' THEN RAISE EXCEPTION 'MONITOR_FORBIDDEN' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text,0));
 SELECT * INTO m FROM public.quality_monitors WHERE tenant_id=tenant AND id=monitor_identity;
 IF m.id IS NULL THEN RAISE EXCEPTION 'MONITOR_UNAVAILABLE' USING ERRCODE='P0002';END IF;
 SELECT * INTO s FROM public.quality_monitor_schedule_segments WHERE tenant_id=tenant AND monitor_id=m.id AND next_slot_at IS NOT NULL AND
 (cutoff_at IS NOT NULL OR m.state='enabled' AND m.blocked IS NULL AND mode='live') ORDER BY segment LIMIT 1;
 IF s.segment IS NOT NULL THEN SELECT * INTO v FROM public.quality_monitor_versions WHERE tenant_id=tenant AND monitor_id=m.id AND version=s.definition_version;END IF;
 PERFORM public.gc_quality_monitor_lock(ARRAY[m.id],CASE WHEN v.version IS NULL THEN ARRAY[]::jsonb[] ELSE ARRAY[v.definition] END);
 now_at:=date_trunc('milliseconds',clock_timestamp());
 IF s.segment IS NOT NULL AND s.next_slot_at<=now_at THEN
  step_seconds:=(v.definition#>>'{schedule,intervalSeconds}')::integer;end_at:=least(s.cutoff_at,(v.definition#>>'{schedule,endsAt}')::timestamptz);
  IF end_at IS NOT NULL AND s.next_slot_at>=end_at THEN UPDATE public.quality_monitor_schedule_segments SET next_slot_at=NULL WHERE tenant_id=tenant AND monitor_id=m.id AND segment=s.segment;state_name:='advanced';
  ELSE
   last_due:=s.next_slot_at+floor(extract(epoch FROM least(now_at,coalesce(end_at-interval '1 millisecond',now_at))-s.next_slot_at)/step_seconds)*make_interval(secs=>step_seconds);through_at:=last_due;
   SELECT w INTO slot_window FROM jsonb_array_elements(v.definition->'maintenance') w WHERE (w->>'from')::timestamptz<=s.next_slot_at AND (w->>'until')::timestamptz>s.next_slot_at LIMIT 1;
   IF s.mode='PAUSED' THEN reason:='PAUSED';
   ELSIF slot_window IS NOT NULL THEN reason:='MAINTENANCE';through_at:=least(last_due,public.gc_quality_monitor_first_slot(v.definition,(slot_window->>'until')::timestamptz)-make_interval(secs=>step_seconds));
   ELSE
    SELECT w INTO slot_window FROM jsonb_array_elements(v.definition->'maintenance') w WHERE (w->>'from')::timestamptz>s.next_slot_at ORDER BY w->>'from' LIMIT 1;
    IF slot_window IS NOT NULL THEN through_at:=least(through_at,public.gc_quality_monitor_first_slot(v.definition,(slot_window->>'from')::timestamptz)-make_interval(secs=>step_seconds));END IF;
    IF s.cutoff_at IS NULL AND s.mode='live' AND (end_at IS NULL OR now_at<end_at) AND extract(epoch FROM now_at-last_due)<=(v.definition#>>'{schedule,lateGraceSeconds}')::integer THEN
     IF s.next_slot_at=last_due THEN reason:=public.gc_quality_monitor_block(v.definition,now_at);
      IF reason IS NULL THEN inputs:=public.gc_quality_monitor_inputs(v.definition,now_at);reason:=public.gc_quality_monitor_capacity(m.id,(inputs->>'sourceId')::uuid);IF reason IS NOT NULL THEN inputs:=NULL;END IF;END IF;
     ELSE reason:='MISSED';through_at:=least(through_at,last_due-make_interval(secs=>step_seconds));END IF;
    ELSE reason:='MISSED';END IF;
   END IF;
   count_slots:=floor(extract(epoch FROM through_at-s.next_slot_at)/step_seconds)+1;
   IF count_slots NOT BETWEEN 1 AND 2147483647 THEN RAISE EXCEPTION 'MONITOR_LIMIT' USING ERRCODE='54000';END IF;
   occ:=public.gc_quality_monitor_occurrence(m.id,v.version,gen_random_uuid(),'schedule',s.next_slot_at,through_at,count_slots::integer,reason,inputs,s.segment);
   SELECT run_id INTO run_identity FROM public.quality_monitor_occurrences WHERE tenant_id=tenant AND id=occ;
   next_at:=public.gc_quality_monitor_first_slot(v.definition,through_at+make_interval(secs=>step_seconds));IF end_at IS NOT NULL AND next_at>=end_at THEN next_at:=NULL;END IF;
   UPDATE public.quality_monitor_schedule_segments SET next_slot_at=next_at WHERE tenant_id=tenant AND monitor_id=m.id AND segment=s.segment;
   IF s.cutoff_at IS NULL THEN UPDATE public.quality_monitors SET next_slot_at=next_at,blocked=CASE WHEN reason IN('RULE_VERSION_CHANGED','AUTHORIZATION_EXPIRED','EXECUTOR_UNAVAILABLE','RULE_OWNER_UNAVAILABLE','TARGET_UNAVAILABLE','REFERENCE_UNAVAILABLE') THEN reason END WHERE tenant_id=tenant AND id=m.id;END IF;
   state_name:=CASE WHEN reason IN('RULE_VERSION_CHANGED','AUTHORIZATION_EXPIRED','EXECUTOR_UNAVAILABLE','RULE_OWNER_UNAVAILABLE','TARGET_UNAVAILABLE','REFERENCE_UNAVAILABLE') THEN 'blocked' ELSE 'advanced' END;
  END IF;
 END IF;
 SELECT * INTO m FROM public.quality_monitors WHERE tenant_id=tenant AND id=monitor_identity;
 RETURN jsonb_build_object('monitorId',m.id,'state',state_name,'nextWakeAt',CASE WHEN m.state='enabled' AND m.blocked IS NULL THEN public.gc_relation_utc(m.next_slot_at) END,'occurrenceId',occ,'runId',run_identity);
END $$;

-- SPDX-License-Identifier: Apache-2.0
CREATE FUNCTION public.gc_quality_monitor_issue_snapshot(i public.quality_monitor_incidents) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT to_jsonb(i)||jsonb_build_object('opened_at',public.gc_relation_utc(i.opened_at),'acknowledge_due_at',public.gc_relation_utc(i.acknowledge_due_at),'resolve_due_at',public.gc_relation_utc(i.resolve_due_at))
$$;
CREATE FUNCTION public.gc_quality_monitor_event(issue_identity uuid,event_kind text,definition_version integer,occurrence_identity uuid,reason text DEFAULT NULL) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant();i public.quality_monitor_incidents;v public.quality_monitor_versions;o public.quality_monitor_occurrences;
 event_identity uuid:=gen_random_uuid();notification_identity uuid;recipient uuid;template_name text;cause text;now_at timestamptz:=date_trunc('milliseconds',clock_timestamp());action_name text;BEGIN
 SELECT * INTO i FROM public.quality_monitor_incidents WHERE tenant_id=tenant AND id=issue_identity;
 SELECT * INTO v FROM public.quality_monitor_versions WHERE tenant_id=tenant AND monitor_id=i.monitor_id AND version=definition_version;
 SELECT * INTO o FROM public.quality_monitor_occurrences WHERE tenant_id=tenant AND id=occurrence_identity;
 action_name:='quality.issue_'||replace(event_kind,'-','_');
 INSERT INTO public.quality_monitor_incident_events(tenant_id,id,issue_id,version,episode,kind,monitor_id,definition_version,definition_hash,occurrence_id,run_id,actor_id,occurred_at,reason,snapshot)
 VALUES(tenant,event_identity,i.id,i.version,i.episode,event_kind,i.monitor_id,v.version,v.definition_hash,o.id,o.run_id,public.gc_actor(),now_at,reason,public.gc_quality_monitor_issue_snapshot(i));
 PERFORM public.gc_approval_journal(action_name,NULL,i.id::text,i.version,jsonb_build_object('eventId',event_identity,'monitorId',i.monitor_id,'definitionVersion',v.version,'definitionHash',v.definition_hash,'occurrenceId',o.id,'runId',o.run_id,'episode',i.episode),'monitor-issue:'||i.id::text);
 template_name:=CASE event_kind WHEN 'opened' THEN 'quality-issue-opened-v1' WHEN 'reopened' THEN 'quality-issue-reopened-v1' WHEN 'assigned' THEN 'quality-issue-assigned-v1' WHEN 'recovery-available' THEN 'quality-recovery-available-v1' WHEN 'resolved' THEN 'quality-issue-resolved-v1' END;
 IF template_name IS NOT NULL THEN
  FOR recipient IN SELECT DISTINCT id FROM (SELECT x::uuid id FROM jsonb_array_elements_text(v.definition#>'{routing,recipientIds}') x UNION SELECT i.assigned_owner_id) q ORDER BY id LOOP
   cause:=CASE WHEN public.gc_quality_monitor_in_window(v.definition->'silences',coalesce(o.first_slot_at,o.recorded_at,now_at)) THEN 'SILENCED'
    WHEN NOT public.gc_quality_issue_visible(i.id,recipient) THEN 'RECIPIENT_UNAVAILABLE'
    WHEN (SELECT count(*) FROM public.quality_monitor_notifications WHERE tenant_id=tenant AND recipient_id=recipient AND suppressed IS NULL AND created_at>=(date_trunc('hour',now_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC') AND created_at<(date_trunc('hour',now_at AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')+interval '1 hour')>=20 THEN 'RATE_LIMITED' END;
   notification_identity:=gen_random_uuid();
   INSERT INTO public.quality_monitor_notifications(tenant_id,id,event_id,issue_id,recipient_id,template,suppressed,created_at) VALUES(tenant,notification_identity,event_identity,i.id,recipient,template_name,cause,now_at);
   PERFORM public.gc_approval_journal('quality.notification_created',NULL,notification_identity::text,1,jsonb_build_object('eventId',event_identity,'issueId',i.id,'recipientId',recipient,'template',template_name,'suppressed',cause),'monitor-event:'||event_identity::text);
  END LOOP;
 END IF;RETURN event_identity;
END $$;
CREATE FUNCTION public.gc_quality_monitor_reconcile(monitor_identity uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant();m public.quality_monitors;v public.quality_monitor_versions;o public.quality_monitor_occurrences;q public.quality_runs;i public.quality_monitor_incidents;previous public.quality_monitor_incidents;
 evidence jsonb;observation jsonb;event_kind text;issue_identity uuid;issue_ids uuid[];now_at timestamptz;state_name text:='idle';BEGIN
 IF public.gc_actor() IS DISTINCT FROM 'site:local' THEN RAISE EXCEPTION 'MONITOR_FORBIDDEN' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text,0));
 SELECT * INTO m FROM public.quality_monitors WHERE tenant_id=tenant AND id=monitor_identity;
 IF m.id IS NULL THEN RAISE EXCEPTION 'MONITOR_UNAVAILABLE' USING ERRCODE='P0002';END IF;
 SELECT * INTO o FROM public.quality_monitor_occurrences WHERE tenant_id=tenant AND monitor_id=m.id AND ordinal=m.last_projected_ordinal+1;
 IF o.id IS NULL THEN RETURN jsonb_build_object('monitorId',m.id,'state','idle','nextWakeAt',NULL,'occurrenceId',NULL,'runId',NULL);END IF;
 SELECT * INTO i FROM public.quality_monitor_incidents WHERE tenant_id=tenant AND monitor_id=m.id AND comparison_scope_hash=o.comparison_scope_hash;
 SELECT * INTO previous FROM public.quality_monitor_incidents WHERE tenant_id=tenant AND monitor_id=m.id AND recovery IS NOT NULL AND (recovery->>'ordinal')::integer=m.last_projected_ordinal AND id IS DISTINCT FROM i.id;
 issue_ids:=array_remove(ARRAY[i.id,previous.id],NULL);
 PERFORM public.gc_quality_monitor_lock(ARRAY[m.id],ARRAY[]::jsonb[],issue_ids,ARRAY[o.id]);
 now_at:=date_trunc('milliseconds',clock_timestamp());
 SELECT * INTO q FROM public.quality_runs WHERE tenant_id=tenant AND id=o.run_id;
 IF o.run_id IS NOT NULL AND q.status IN('queued','running') THEN RETURN jsonb_build_object('monitorId',m.id,'state','idle','nextWakeAt',public.gc_relation_utc(least(q.expires_at,clock_timestamp()+interval '60 seconds')),'occurrenceId',o.id,'runId',q.id);END IF;
 SELECT * INTO v FROM public.quality_monitor_versions WHERE tenant_id=tenant AND monitor_id=m.id AND version=o.definition_version;
 IF q.status='succeeded' AND q.verdict IN('PASS','FAIL') THEN
  evidence:=jsonb_build_object('occurrenceId',o.id,'ordinal',o.ordinal,'runId',q.id,'runVersion',q.version,'completionHash',q.completion_hash,'comparisonScopeHash',o.comparison_scope_hash,'observedFinishedAt',q.measurement->'observedFinishedAt');
  observation:=jsonb_build_object('state','conclusive','verdict',q.verdict,'evidence',evidence);
 ELSE
  observation:=jsonb_build_object('state','unknown','reason',CASE WHEN o.disposition='skipped' THEN CASE WHEN o.reason IN('RULE_VERSION_CHANGED','AUTHORIZATION_EXPIRED','EXECUTOR_UNAVAILABLE','RULE_OWNER_UNAVAILABLE','TARGET_UNAVAILABLE','REFERENCE_UNAVAILABLE') THEN 'BLOCKED' ELSE 'SKIPPED' END WHEN q.status='cancelled' THEN 'CANCELLED' WHEN q.verdict='NO_DATA' THEN 'NO_DATA' ELSE 'EXECUTION_FAILED' END,'occurrenceId',o.id);
 END IF;
 INSERT INTO public.quality_monitor_projection_receipts(tenant_id,occurrence_id,monitor_id,ordinal,run_id,run_version,completion_hash,projected_at)
 VALUES(tenant,o.id,m.id,o.ordinal,q.id,q.version,q.completion_hash,now_at);
 UPDATE public.quality_monitors SET last_projected_ordinal=o.ordinal,
  current_observation=CASE WHEN last_admitted_ordinal=o.ordinal THEN observation ELSE current_observation END,
  last_conclusive=CASE WHEN evidence IS NOT NULL THEN jsonb_build_object('verdict',q.verdict,'evidence',evidence) ELSE last_conclusive END WHERE tenant_id=tenant AND id=m.id;
 -- This projection never calls source execution or live executor authorization.
 -- A completed result remains finishable/projectable when an owner is revoked.
 IF previous.id IS NOT NULL THEN
  UPDATE public.quality_monitor_incidents SET version=version+1,recovery=NULL WHERE tenant_id=tenant AND id=previous.id;
  PERFORM public.gc_quality_monitor_event(previous.id,'recovery-invalidated',o.definition_version,o.id);
 END IF;
 IF q.status='succeeded' AND q.verdict IN('PASS','FAIL') THEN
  IF q.verdict='FAIL' THEN
   IF i.id IS NULL THEN
    issue_identity:=gen_random_uuid();
    INSERT INTO public.quality_monitor_incidents(tenant_id,id,monitor_id,comparison_scope_hash,version,episode,status,rule_id,rule_version,rule_hash,table_asset_id,column_asset_id,severity,assigned_owner_id,opened_at,acknowledge_due_at,resolve_due_at,opening,last_failure)
    SELECT tenant,issue_identity,m.id,o.comparison_scope_hash,1,1,'open',o.rule_id,o.rule_version,o.rule_hash,q.table_asset_id,q.column_asset_id,rv.definition->>'severity',v.owner_id,now_at,
     now_at+make_interval(secs=>(v.definition#>>'{issue,acknowledgeWithinSeconds}')::integer),now_at+make_interval(secs=>(v.definition#>>'{issue,resolveWithinSeconds}')::integer),evidence,evidence
     FROM public.quality_rule_versions rv WHERE rv.tenant_id=tenant AND rv.rule_id=o.rule_id AND rv.version=o.rule_version;
    event_kind:='opened';
   ELSE
    issue_identity:=i.id;event_kind:=CASE WHEN i.status IN('resolved','superseded') THEN 'reopened' ELSE 'failed-again' END;
    UPDATE public.quality_monitor_incidents SET version=version+1,status=CASE WHEN i.status IN('resolved','superseded') THEN 'open' ELSE i.status END,
     episode=episode+CASE WHEN i.status IN('resolved','superseded') THEN 1 ELSE 0 END,last_failure=evidence,recovery=NULL,resolution=NULL,superseded=NULL,
     opening=CASE WHEN i.status IN('resolved','superseded') THEN evidence ELSE opening END,
     opened_at=CASE WHEN i.status IN('resolved','superseded') THEN now_at ELSE opened_at END,
     acknowledge_due_at=CASE WHEN i.status IN('resolved','superseded') THEN now_at+make_interval(secs=>(v.definition#>>'{issue,acknowledgeWithinSeconds}')::integer) ELSE acknowledge_due_at END,
     resolve_due_at=CASE WHEN i.status IN('resolved','superseded') THEN now_at+make_interval(secs=>(v.definition#>>'{issue,resolveWithinSeconds}')::integer) ELSE resolve_due_at END
     WHERE tenant_id=tenant AND id=i.id;
   END IF;
   PERFORM public.gc_quality_monitor_event(issue_identity,event_kind,o.definition_version,o.id);
  ELSIF i.id IS NOT NULL AND i.status IN('open','acknowledged') AND public.gc_quality_monitor_recovery_eligible(i.id,evidence) THEN
   UPDATE public.quality_monitor_incidents SET version=version+1,recovery=evidence WHERE tenant_id=tenant AND id=i.id;
   PERFORM public.gc_quality_monitor_event(i.id,'recovery-available',o.definition_version,o.id);
  ELSIF i.id IS NOT NULL AND i.recovery IS NOT NULL THEN
   UPDATE public.quality_monitor_incidents SET version=version+1,recovery=NULL WHERE tenant_id=tenant AND id=i.id;
   PERFORM public.gc_quality_monitor_event(i.id,'recovery-invalidated',o.definition_version,o.id);
  END IF;
 ELSE
  IF i.id IS NOT NULL AND i.recovery IS NOT NULL THEN UPDATE public.quality_monitor_incidents SET version=version+1,recovery=NULL WHERE tenant_id=tenant AND id=i.id;PERFORM public.gc_quality_monitor_event(i.id,'recovery-invalidated',o.definition_version,o.id);END IF;
 END IF;
 PERFORM public.gc_approval_journal('quality.monitor_projected',NULL,m.id::text,o.ordinal,jsonb_build_object('occurrenceId',o.id,'ordinal',o.ordinal,'runId',q.id,'runVersion',q.version,'completionHash',q.completion_hash),'monitor:'||m.id::text);
 RETURN jsonb_build_object('monitorId',m.id,'state','advanced','nextWakeAt',public.gc_relation_utc(now_at),'occurrenceId',o.id,'runId',q.id);
END $$;
CREATE FUNCTION public.gc_quality_monitor_work() RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE result jsonb;BEGIN
 IF public.gc_actor() IS DISTINCT FROM 'site:local' THEN RAISE EXCEPTION 'MONITOR_FORBIDDEN' USING ERRCODE='42501';END IF;
 SELECT jsonb_build_object('items',coalesce(jsonb_agg(jsonb_build_object('tenantId',tenant_id,'monitorId',id,'work',work) ORDER BY priority,id),'[]'::jsonb)) INTO result FROM (
  SELECT m.tenant_id,m.id,CASE WHEN EXISTS(SELECT 1 FROM public.quality_monitor_occurrences o LEFT JOIN public.quality_runs q ON q.tenant_id=o.tenant_id AND q.id=o.run_id WHERE o.tenant_id=m.tenant_id AND o.monitor_id=m.id AND o.ordinal=m.last_projected_ordinal+1 AND (o.run_id IS NULL OR q.status NOT IN('queued','running'))) THEN 'reconcile' ELSE 'tick' END work,
   CASE WHEN m.last_projected_ordinal<m.last_admitted_ordinal THEN 0 ELSE 1 END priority
  FROM public.quality_monitors m WHERE m.tenant_id=public.gc_tenant() AND (
   EXISTS(SELECT 1 FROM public.quality_monitor_occurrences o LEFT JOIN public.quality_runs q ON q.tenant_id=o.tenant_id AND q.id=o.run_id WHERE o.tenant_id=m.tenant_id AND o.monitor_id=m.id AND o.ordinal=m.last_projected_ordinal+1 AND (o.run_id IS NULL OR q.status NOT IN('queued','running')))
   OR EXISTS(SELECT 1 FROM public.quality_monitor_schedule_segments s WHERE s.tenant_id=m.tenant_id AND s.monitor_id=m.id AND s.next_slot_at<=clock_timestamp() AND (s.cutoff_at IS NOT NULL OR m.state='enabled' AND m.blocked IS NULL AND s.mode='live')))
  ORDER BY priority,m.id LIMIT 50) work;
 RETURN result;
END $$;

-- SPDX-License-Identifier: Apache-2.0
CREATE FUNCTION public.gc_quality_monitor_rotate(monitor_identity uuid,selected_version integer,new_state text,at_time timestamptz) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE next_segment integer;v public.quality_monitor_versions;next_at timestamptz;BEGIN
 UPDATE public.quality_monitor_schedule_segments SET next_slot_at=CASE WHEN next_slot_at>=at_time THEN NULL ELSE next_slot_at END,cutoff_at=at_time,closed_at=at_time,closed_revision=(SELECT revision FROM public.quality_monitors WHERE tenant_id=public.gc_tenant() AND id=monitor_identity),mode=CASE WHEN mode='live' THEN 'MISSED' ELSE mode END WHERE tenant_id=public.gc_tenant() AND monitor_id=monitor_identity AND cutoff_at IS NULL;
 SELECT coalesce(max(segment),0)+1 INTO next_segment FROM public.quality_monitor_schedule_segments WHERE tenant_id=public.gc_tenant() AND monitor_id=monitor_identity;
 SELECT * INTO v FROM public.quality_monitor_versions WHERE tenant_id=public.gc_tenant() AND monitor_id=monitor_identity AND version=selected_version;
 next_at:=public.gc_quality_monitor_first_slot(v.definition,at_time);
 IF new_state<>'retired' THEN
  INSERT INTO public.quality_monitor_schedule_segments(tenant_id,monitor_id,segment,definition_version,next_slot_at,mode,created_at,created_by,created_revision)
   VALUES(public.gc_tenant(),monitor_identity,next_segment,selected_version,next_at,CASE WHEN new_state='enabled' THEN 'live' ELSE 'PAUSED' END,at_time,public.gc_actor(),(SELECT revision FROM public.quality_monitors WHERE tenant_id=public.gc_tenant() AND id=monitor_identity));
 END IF;
 UPDATE public.quality_monitors SET next_slot_at=CASE WHEN new_state='enabled' THEN next_at END WHERE tenant_id=public.gc_tenant() AND id=monitor_identity;
END $$;
CREATE FUNCTION public.gc_quality_monitor_command(operation text,command_key text,body jsonb,correlation text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant();actor uuid;old public.idempotency;m public.quality_monitors;v public.quality_monitor_versions;i public.quality_monitor_incidents;n public.quality_monitor_notifications;
 replacement public.quality_monitor_versions;o public.quality_monitor_occurrences;definition jsonb;actions text[];fields text[];hash text;result jsonb;identity uuid;new_owner uuid;replacement_id uuid;extra_defs jsonb[]:=ARRAY[]::jsonb[];
 now_at timestamptz;expected integer;state_name text;reason text;inputs jsonb;scope jsonb;prior_scope jsonb;block text;extra_occ uuid;version_for_event integer;BEGIN
 IF operation IS NULL OR operation NOT IN('quality.monitor.publish','quality.monitor.state','quality.issue.acknowledge','quality.issue.assign','quality.issue.resolve','quality.issue.supersede','quality.issue.recovery.request','quality.notification.mark-read')
 OR command_key IS NULL OR length(command_key) NOT BETWEEN 8 AND 128 OR command_key~'[[:cntrl:]]' OR correlation IS NULL OR length(correlation) NOT BETWEEN 1 AND 128 OR correlation~'[[:cntrl:]]'
 OR body IS NULL OR jsonb_typeof(body) IS DISTINCT FROM 'object' OR octet_length(body::text)>65536 THEN RAISE EXCEPTION 'MONITOR_INPUT_INVALID' USING ERRCODE='22023';END IF;
 actions:=ARRAY['catalog:read','quality:read'];
 IF operation NOT IN('quality.notification.mark-read','quality.issue.recovery.request') THEN actions:=actions||ARRAY['quality:write'];END IF;
 IF operation IN('quality.monitor.publish','quality.issue.recovery.request') OR operation='quality.monitor.state' AND body->>'action'='resume' THEN actions:=actions||ARRAY['quality:execute'];END IF;
 PERFORM public.gc_relation_authorize(actions);actor:=public.gc_actor()::uuid;
 IF operation='quality.monitor.publish' THEN
  IF public.gc_relation_keys(body,ARRAY['id','expectedRevision','definition']) IS NOT TRUE OR NOT public.gc_approval_uuid(body->>'id') OR NOT public.gc_quality_monitor_integer(body->'expectedRevision',0,2147483646)
  OR public.gc_quality_monitor_definition_valid(body->'definition') IS NOT TRUE THEN RAISE EXCEPTION 'MONITOR_INPUT_INVALID' USING ERRCODE='22023';END IF;
  identity:=(body->>'id')::uuid;definition:=body->'definition';expected:=(body->>'expectedRevision')::integer;extra_defs:=ARRAY[definition];
 ELSIF operation='quality.monitor.state' THEN
  IF public.gc_relation_keys(body,ARRAY['monitorId','expectedRevision','action','reason']) IS NOT TRUE OR NOT public.gc_approval_uuid(body->>'monitorId') OR NOT public.gc_quality_monitor_integer(body->'expectedRevision',1,2147483646)
  OR body->>'action' IS NULL OR body->>'action' NOT IN('pause','resume','retire') THEN RAISE EXCEPTION 'MONITOR_INPUT_INVALID' USING ERRCODE='22023';END IF;
  identity:=(body->>'monitorId')::uuid;expected:=(body->>'expectedRevision')::integer;
 ELSIF operation='quality.notification.mark-read' THEN
  IF public.gc_relation_keys(body,ARRAY['notificationId','expectedVersion']) IS NOT TRUE OR NOT public.gc_approval_uuid(body->>'notificationId') OR NOT public.gc_quality_monitor_integer(body->'expectedVersion',1,2147483646) THEN RAISE EXCEPTION 'MONITOR_INPUT_INVALID' USING ERRCODE='22023';END IF;
  identity:=(body->>'notificationId')::uuid;expected:=(body->>'expectedVersion')::integer;
 ELSE
  fields:=ARRAY['issueId','expectedVersion','reason']||CASE operation WHEN 'quality.issue.assign' THEN ARRAY['ownerId'] WHEN 'quality.issue.resolve' THEN ARRAY['recoveryOccurrenceId','recoveryRunId','recoveryRunVersion','rootCause','remediation'] WHEN 'quality.issue.supersede' THEN ARRAY['replacementMonitorId','replacementDefinitionVersion'] WHEN 'quality.issue.recovery.request' THEN ARRAY['id'] ELSE ARRAY[]::text[] END;
  IF public.gc_relation_keys(body,fields) IS NOT TRUE OR NOT public.gc_approval_uuid(body->>'issueId') OR NOT public.gc_quality_monitor_integer(body->'expectedVersion',1,2147483646) THEN RAISE EXCEPTION 'MONITOR_INPUT_INVALID' USING ERRCODE='22023';END IF;
  identity:=(body->>'issueId')::uuid;expected:=(body->>'expectedVersion')::integer;
  IF operation='quality.issue.assign' THEN IF NOT public.gc_approval_uuid(body->>'ownerId') THEN RAISE EXCEPTION 'MONITOR_INPUT_INVALID' USING ERRCODE='22023';END IF;new_owner:=(body->>'ownerId')::uuid;END IF;
  IF operation='quality.issue.resolve' AND (NOT public.gc_approval_uuid(body->>'recoveryOccurrenceId') OR NOT public.gc_approval_uuid(body->>'recoveryRunId') OR NOT public.gc_quality_monitor_integer(body->'recoveryRunVersion',1,2147483647)
   OR jsonb_typeof(body->'rootCause') IS DISTINCT FROM 'string' OR public.gc_approval_text(body->>'rootCause',4096,true) IS NULL OR body->>'rootCause' IS DISTINCT FROM public.gc_approval_text(body->>'rootCause',4096,true)
   OR jsonb_typeof(body->'remediation') IS DISTINCT FROM 'string' OR public.gc_approval_text(body->>'remediation',4096,true) IS NULL OR body->>'remediation' IS DISTINCT FROM public.gc_approval_text(body->>'remediation',4096,true)) THEN RAISE EXCEPTION 'MONITOR_INPUT_INVALID' USING ERRCODE='22023';END IF;
  IF operation='quality.issue.supersede' THEN IF NOT public.gc_approval_uuid(body->>'replacementMonitorId') OR NOT public.gc_quality_monitor_integer(body->'replacementDefinitionVersion',1,2147483647) THEN RAISE EXCEPTION 'MONITOR_INPUT_INVALID' USING ERRCODE='22023';END IF;replacement_id:=(body->>'replacementMonitorId')::uuid;END IF;
  IF operation='quality.issue.recovery.request' AND NOT public.gc_approval_uuid(body->>'id') THEN RAISE EXCEPTION 'MONITOR_INPUT_INVALID' USING ERRCODE='22023';END IF;
 END IF;
 IF operation NOT IN('quality.monitor.publish','quality.notification.mark-read') THEN
  IF jsonb_typeof(body->'reason') IS DISTINCT FROM 'string' OR public.gc_approval_text(body->>'reason',4096,true) IS NULL OR body->>'reason' IS DISTINCT FROM public.gc_approval_text(body->>'reason',4096,true) THEN RAISE EXCEPTION 'MONITOR_INPUT_INVALID' USING ERRCODE='22023';END IF;reason:=body->>'reason';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text,0));hash:=public.gc_type_migration_hash(body);
 SELECT * INTO old FROM public.idempotency z WHERE z.tenant_id=tenant AND z.actor_id=actor::text AND z.operation=gc_quality_monitor_command.operation AND z.key=command_key;
 IF operation IN('quality.monitor.publish','quality.monitor.state') THEN
  SELECT * INTO m FROM public.quality_monitors WHERE tenant_id=tenant AND id=identity;
  IF (operation='quality.monitor.state' OR expected>0) AND m.id IS NULL OR m.id IS NOT NULL AND NOT public.gc_quality_monitor_visible(m.id,actor) THEN RAISE EXCEPTION 'MONITOR_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  IF old.key IS NOT NULL AND operation='quality.monitor.publish' THEN extra_defs:=extra_defs||ARRAY[old.response#>'{monitor,definition}'];END IF;
 ELSIF operation='quality.notification.mark-read' THEN
  SELECT * INTO n FROM public.quality_monitor_notifications WHERE tenant_id=tenant AND id=identity;
  IF n.id IS NULL OR NOT public.gc_quality_notification_visible(n.id,actor) THEN RAISE EXCEPTION 'MONITOR_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  SELECT * INTO i FROM public.quality_monitor_incidents WHERE tenant_id=tenant AND id=n.issue_id;SELECT * INTO m FROM public.quality_monitors WHERE tenant_id=tenant AND id=i.monitor_id;
 ELSE
  SELECT * INTO i FROM public.quality_monitor_incidents WHERE tenant_id=tenant AND id=identity;
  IF i.id IS NULL OR NOT public.gc_quality_issue_visible(i.id,actor) THEN RAISE EXCEPTION 'MONITOR_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  SELECT * INTO m FROM public.quality_monitors WHERE tenant_id=tenant AND id=i.monitor_id;
  extra_occ:=(CASE WHEN operation='quality.issue.resolve' THEN i.recovery->>'occurrenceId' ELSE i.last_failure->>'occurrenceId' END)::uuid;
  IF replacement_id IS NOT NULL THEN
   SELECT * INTO replacement FROM public.quality_monitor_versions WHERE tenant_id=tenant AND monitor_id=replacement_id AND version=(body->>'replacementDefinitionVersion')::integer;
   IF replacement.version IS NULL OR NOT public.gc_quality_monitor_visible(replacement_id,actor,replacement.version) THEN RAISE EXCEPTION 'MONITOR_UNAVAILABLE' USING ERRCODE='P0002';END IF;
   extra_defs:=extra_defs||ARRAY[replacement.definition];
  END IF;
 END IF;
 PERFORM public.gc_quality_monitor_lock(array_remove(ARRAY[coalesce(m.id,CASE WHEN operation='quality.monitor.publish' THEN identity END),replacement_id],NULL),extra_defs,array_remove(ARRAY[i.id],NULL),array_remove(ARRAY[extra_occ],NULL),array_remove(ARRAY[new_owner],NULL));
 PERFORM public.gc_relation_authorize(actions);
 IF m.id IS NOT NULL AND operation IN('quality.monitor.publish','quality.monitor.state') AND NOT public.gc_quality_monitor_visible(m.id,actor)
 OR i.id IS NOT NULL AND NOT public.gc_quality_issue_visible(i.id,actor) OR n.id IS NOT NULL AND NOT public.gc_quality_notification_visible(n.id,actor)
 OR replacement_id IS NOT NULL AND NOT public.gc_quality_monitor_visible(replacement_id,actor,replacement.version) THEN RAISE EXCEPTION 'MONITOR_UNAVAILABLE' USING ERRCODE='P0002';END IF;
 IF old.key IS NOT NULL THEN
  IF old.request_hash IS DISTINCT FROM hash THEN RAISE EXCEPTION 'IDEMPOTENCY_CONFLICT' USING ERRCODE='40001';END IF;
  IF operation='quality.monitor.publish' AND NOT public.gc_quality_monitor_visible(identity,actor,(old.response#>>'{monitor,definitionVersion}')::integer) THEN RAISE EXCEPTION 'MONITOR_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  IF operation='quality.issue.recovery.request' AND NOT public.gc_quality_occurrence_visible((old.response#>>'{occurrence,id}')::uuid,actor) THEN RAISE EXCEPTION 'MONITOR_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  RETURN old.response;
 END IF;
 now_at:=date_trunc('milliseconds',clock_timestamp());
 IF operation='quality.monitor.publish' THEN
  IF definition->>'executorId'<>actor::text THEN RAISE EXCEPTION 'MONITOR_FORBIDDEN' USING ERRCODE='42501';END IF;
  IF NOT public.gc_quality_rule_visible((definition#>>'{rule,id}')::uuid,(definition#>>'{rule,version}')::integer,actor) THEN RAISE EXCEPTION 'MONITOR_UNAVAILABLE' USING ERRCODE='P0002';END IF;
  IF (definition->>'authorizationExpiresAt')::timestamptz<=now_at OR (definition->>'authorizationExpiresAt')::timestamptz>now_at+interval '31 days' THEN RAISE EXCEPTION 'MONITOR_INPUT_INVALID' USING ERRCODE='22023';END IF;
  IF EXISTS(SELECT 1 FROM jsonb_array_elements_text(definition#>'{routing,recipientIds}') x WHERE NOT public.gc_quality_rule_visible((definition#>>'{rule,id}')::uuid,(definition#>>'{rule,version}')::integer,x::uuid)) THEN RAISE EXCEPTION 'MONITOR_FORBIDDEN' USING ERRCODE='42501';END IF;
  inputs:=public.gc_quality_monitor_inputs(definition,now_at);
  IF expected=0 AND m.id IS NOT NULL OR expected>0 AND (m.revision<>expected OR m.executor_id<>actor OR m.rule_id::text<>definition#>>'{rule,id}' OR m.state='retired') THEN RAISE EXCEPTION 'VERSION_CONFLICT' USING ERRCODE='40001';END IF;
  IF m.id IS NULL AND (SELECT count(*) FROM public.quality_monitors WHERE tenant_id=tenant AND state='enabled')>=100 THEN RAISE EXCEPTION 'MONITOR_LIMIT' USING ERRCODE='54000';END IF;
  IF EXISTS(SELECT 1 FROM public.quality_monitors WHERE tenant_id=tenant AND rule_id=(definition#>>'{rule,id}')::uuid AND state='enabled' AND id<>identity) AND coalesce(m.state,'enabled')='enabled' THEN RAISE EXCEPTION 'VERSION_CONFLICT' USING ERRCODE='40001';END IF;
  IF m.id IS NULL THEN INSERT INTO public.quality_monitors(tenant_id,id,rule_id,executor_id,revision,definition_version,state,created_by,created_at) VALUES(tenant,identity,(definition#>>'{rule,id}')::uuid,actor,1,1,'enabled',actor,now_at);state_name:='enabled';
  ELSE state_name:=m.state;UPDATE public.quality_monitors SET revision=revision+1,definition_version=definition_version+1,blocked=NULL,current_observation=jsonb_build_object('state','unknown','reason','STALE','occurrenceId',NULL) WHERE tenant_id=tenant AND id=identity;END IF;
  SELECT * INTO m FROM public.quality_monitors WHERE tenant_id=tenant AND id=identity;
  INSERT INTO public.quality_monitor_versions(tenant_id,monitor_id,version,definition,definition_hash,rule_id,rule_version,rule_hash,owner_id,created_by,created_at)
  VALUES(tenant,identity,m.definition_version,definition,public.gc_type_migration_hash(definition),(definition#>>'{rule,id}')::uuid,(definition#>>'{rule,version}')::integer,definition#>>'{rule,definitionHash}',(definition#>>'{routing,ownerId}')::uuid,actor,now_at);
  PERFORM public.gc_quality_monitor_rotate(identity,m.definition_version,state_name,now_at);
  PERFORM public.gc_approval_journal('quality.monitor_published',NULL,identity::text,m.revision,jsonb_build_object('definitionVersion',m.definition_version,'definitionHash',public.gc_type_migration_hash(definition)),correlation);
  result:=jsonb_build_object('monitor',public.gc_quality_monitor_view(identity));
 ELSIF operation='quality.monitor.state' THEN
  IF m.revision<>expected OR m.state='retired' THEN RAISE EXCEPTION 'VERSION_CONFLICT' USING ERRCODE='40001';END IF;
  SELECT * INTO v FROM public.quality_monitor_versions WHERE tenant_id=tenant AND monitor_id=m.id AND version=m.definition_version;
  state_name:=CASE body->>'action' WHEN 'pause' THEN 'paused' WHEN 'resume' THEN 'enabled' ELSE 'retired' END;
  IF state_name='enabled' THEN
   IF actor<>m.executor_id THEN RAISE EXCEPTION 'MONITOR_FORBIDDEN' USING ERRCODE='42501';END IF;
   IF EXISTS(SELECT 1 FROM jsonb_array_elements_text(v.definition#>'{routing,recipientIds}') x WHERE NOT public.gc_quality_rule_visible(v.rule_id,v.rule_version,x::uuid)) THEN RAISE EXCEPTION 'MONITOR_FORBIDDEN' USING ERRCODE='42501';END IF;
   IF public.gc_quality_monitor_block(v.definition,now_at) IS NOT NULL THEN RAISE EXCEPTION 'MONITOR_PIN_STALE' USING ERRCODE='40001';END IF;
   IF (SELECT count(*) FROM public.quality_monitors WHERE tenant_id=tenant AND state='enabled' AND id<>m.id)>=100 THEN RAISE EXCEPTION 'MONITOR_LIMIT' USING ERRCODE='54000';END IF;
   IF EXISTS(SELECT 1 FROM public.quality_monitors WHERE tenant_id=tenant AND rule_id=m.rule_id AND state='enabled' AND id<>m.id) THEN RAISE EXCEPTION 'VERSION_CONFLICT' USING ERRCODE='40001';END IF;
  END IF;
  UPDATE public.quality_monitors SET revision=revision+1,state=state_name,blocked=NULL,current_observation=jsonb_build_object('state','unknown','reason','STALE','occurrenceId',NULL) WHERE tenant_id=tenant AND id=m.id;
  PERFORM public.gc_quality_monitor_rotate(m.id,m.definition_version,state_name,now_at);
  PERFORM public.gc_approval_journal('quality.monitor_state_changed',NULL,m.id::text,m.revision+1,jsonb_build_object('definitionVersion',v.version,'definitionHash',v.definition_hash,'state',state_name,'reason',reason),correlation);
  result:=jsonb_build_object('monitor',public.gc_quality_monitor_view(m.id));
 ELSIF operation='quality.notification.mark-read' THEN
  IF n.version<>expected OR n.read_at IS NOT NULL THEN RAISE EXCEPTION 'VERSION_CONFLICT' USING ERRCODE='40001';END IF;
  UPDATE public.quality_monitor_notifications SET version=2,read_at=now_at WHERE tenant_id=tenant AND id=n.id;
  PERFORM public.gc_approval_journal('quality.notification_read',NULL,n.id::text,2,jsonb_build_object('eventId',n.event_id,'issueId',n.issue_id,'recipientId',n.recipient_id),correlation);
  result:=jsonb_build_object('notification',public.gc_quality_notification_view(n.id));
 ELSE
  IF i.version<>expected OR i.status NOT IN('open','acknowledged') THEN RAISE EXCEPTION 'VERSION_CONFLICT' USING ERRCODE='40001';END IF;
  SELECT * INTO v FROM public.quality_monitor_versions WHERE tenant_id=tenant AND monitor_id=m.id AND version=m.definition_version;
  version_for_event:=v.version;SELECT * INTO o FROM public.quality_monitor_occurrences WHERE tenant_id=tenant AND id=extra_occ;
  IF operation='quality.issue.acknowledge' THEN
   IF i.status<>'open' THEN RAISE EXCEPTION 'VERSION_CONFLICT' USING ERRCODE='40001';END IF;
   UPDATE public.quality_monitor_incidents SET version=version+1,status='acknowledged' WHERE tenant_id=tenant AND id=i.id;
  ELSIF operation='quality.issue.assign' THEN
   IF NOT public.gc_quality_issue_visible(i.id,new_owner) THEN RAISE EXCEPTION 'MONITOR_FORBIDDEN' USING ERRCODE='42501';END IF;
   UPDATE public.quality_monitor_incidents SET version=version+1,assigned_owner_id=new_owner WHERE tenant_id=tenant AND id=i.id;
  ELSIF operation='quality.issue.resolve' THEN
   IF NOT public.gc_quality_monitor_recovery_current(i.id) OR i.recovery->>'occurrenceId' IS DISTINCT FROM body->>'recoveryOccurrenceId' OR i.recovery->>'runId' IS DISTINCT FROM body->>'recoveryRunId' OR i.recovery->'runVersion' IS DISTINCT FROM body->'recoveryRunVersion' THEN RAISE EXCEPTION 'RECOVERY_UNAVAILABLE' USING ERRCODE='40001';END IF;
   UPDATE public.quality_monitor_incidents SET version=version+1,status='resolved',resolution=jsonb_build_object('rootCause',body->'rootCause','remediation',body->'remediation','reason',reason,'evidence',i.recovery,'at',public.gc_relation_utc(now_at),'by',actor),recovery=NULL WHERE tenant_id=tenant AND id=i.id;
  ELSIF operation='quality.issue.supersede' THEN
   IF m.last_admitted_ordinal<>m.last_projected_ordinal OR EXISTS(SELECT 1 FROM public.quality_monitor_occurrences oc JOIN public.quality_runs q ON q.tenant_id=oc.tenant_id AND q.id=oc.run_id WHERE oc.tenant_id=tenant AND oc.monitor_id=m.id AND q.status IN('queued','running')) THEN RAISE EXCEPTION 'RECOVERY_UNAVAILABLE' USING ERRCODE='40001';END IF;
   inputs:=public.gc_quality_monitor_inputs(replacement.definition,now_at);scope:=public.gc_quality_monitor_scope(replacement.monitor_id,replacement.definition,inputs);
   SELECT comparison_scope INTO prior_scope FROM public.quality_monitor_occurrences WHERE tenant_id=tenant AND id=(i.opening->>'occurrenceId')::uuid;
   IF (scope-'monitorId') IS NOT DISTINCT FROM (prior_scope-'monitorId') THEN RAISE EXCEPTION 'RECOVERY_UNAVAILABLE' USING ERRCODE='40001';END IF;
   UPDATE public.quality_monitor_incidents SET version=version+1,status='superseded',superseded=jsonb_build_object('reason',reason,'replacementMonitorId',replacement.monitor_id,'replacementDefinitionVersion',replacement.version,'at',public.gc_relation_utc(now_at),'by',actor),recovery=NULL WHERE tenant_id=tenant AND id=i.id;
  ELSE
   IF actor<>m.executor_id OR m.state<>'enabled' OR m.blocked IS NOT NULL OR public.gc_quality_monitor_block(v.definition,now_at) IS NOT NULL OR public.gc_quality_monitor_in_window(v.definition->'maintenance',now_at) THEN RAISE EXCEPTION 'RECOVERY_UNAVAILABLE' USING ERRCODE='40001';END IF;
   inputs:=public.gc_quality_monitor_inputs(v.definition,now_at);
   IF public.gc_quality_monitor_capacity(m.id,(inputs->>'sourceId')::uuid) IS NOT NULL OR public.gc_type_migration_hash(public.gc_quality_monitor_scope(m.id,v.definition,inputs))<>i.comparison_scope_hash THEN RAISE EXCEPTION 'RECOVERY_UNAVAILABLE' USING ERRCODE='40001';END IF;
   extra_occ:=public.gc_quality_monitor_occurrence(m.id,v.version,(body->>'id')::uuid,'recovery-request',NULL,NULL,NULL,NULL,inputs);
   result:=jsonb_build_object('occurrence',public.gc_quality_occurrence_view(extra_occ));
  END IF;
  IF operation<>'quality.issue.recovery.request' THEN
   PERFORM public.gc_quality_monitor_event(i.id,CASE operation WHEN 'quality.issue.acknowledge' THEN 'acknowledged' WHEN 'quality.issue.assign' THEN 'assigned' WHEN 'quality.issue.resolve' THEN 'resolved' ELSE 'superseded' END,coalesce(o.definition_version,version_for_event),o.id,reason);
   result:=jsonb_build_object('issue',public.gc_quality_issue_view(i.id));
  END IF;
 END IF;
 INSERT INTO public.idempotency(tenant_id,actor_id,operation,key,request_hash,response) VALUES(tenant,actor::text,operation,command_key,hash,result);
 RETURN result;
END $$;

-- SPDX-License-Identifier: Apache-2.0
-- SQL026 behavior retained outside registered monitor occurrences.
CREATE OR REPLACE FUNCTION public.gc_quality_run_lock(run_identity uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE r public.quality_runs;v public.quality_rule_versions;BEGIN
 SELECT * INTO r FROM public.quality_runs WHERE tenant_id=public.gc_tenant() AND id=run_identity;
 SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=r.tenant_id AND rule_id=r.rule_id AND version=r.rule_version;
 IF EXISTS(SELECT 1 FROM public.quality_monitor_occurrences o WHERE o.tenant_id=r.tenant_id AND o.run_id=r.id) THEN
  IF v.definition->>'kind'='reference-allowed-values' THEN PERFORM public.gc_quality_reference_lock(r.column_asset_id,r.requester_id,v.owner_id,(v.definition#>>'{reference,setId}')::uuid);
  ELSE PERFORM public.gc_quality_lock(r.column_asset_id,r.requester_id,v.owner_id);END IF;
 ELSIF v.definition->>'kind'='reference-allowed-values' THEN PERFORM public.gc_quality_reference_lock(r.column_asset_id,r.requester_id,v.owner_id,(v.definition#>>'{reference,setId}')::uuid);
 ELSIF v.definition->>'kind' IN ('uniqueness','range') THEN PERFORM public.gc_quality_lock(r.column_asset_id,r.requester_id,v.owner_id);
 ELSE PERFORM public.gc_quality_lock(r.column_asset_id,r.requester_id);END IF;
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_run_can_execute(run_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT coalesce((SELECT (NOT EXISTS(SELECT 1 FROM public.quality_monitor_occurrences o WHERE o.tenant_id=r.tenant_id AND o.run_id=r.id) OR EXISTS(SELECT 1 FROM public.quality_rule_versions v WHERE v.tenant_id=r.tenant_id AND v.rule_id=r.rule_id AND v.version=r.rule_version AND public.gc_quality_reference_owner_active(v.owner_id))) AND public.gc_quality_can_execute(r.column_asset_id,r.requester_id) AND
 (r.inputs#>>'{execution,kind}'='completeness' OR (r.inputs#>>'{execution,kind}' IN ('uniqueness','range') AND public.gc_quality_run_visible(r.id,r.requester_id) AND EXISTS(SELECT 1 FROM public.quality_rule_versions v WHERE v.tenant_id=r.tenant_id AND v.rule_id=r.rule_id AND v.version=r.rule_version AND public.gc_quality_reference_owner_active(v.owner_id))) OR (r.inputs#>>'{execution,kind}'='reference-allowed-values' AND public.gc_quality_reference_run_current(r.id)))
 FROM public.quality_runs r WHERE r.tenant_id=public.gc_tenant() AND r.id=run_identity),false)
$$;

CREATE OR REPLACE FUNCTION public.gc_quality_claim(run_identity uuid,claim_identity uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE r public.quality_runs;inputs jsonb;now_at timestamptz;error text;BEGIN
 IF public.gc_actor() IS DISTINCT FROM 'site:local' OR claim_identity IS NULL THEN RAISE EXCEPTION 'QUALITY_SITE_REQUIRED' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(public.gc_tenant()::text,0));SELECT * INTO r FROM public.quality_runs WHERE tenant_id=public.gc_tenant() AND id=run_identity;
 IF r.id IS NULL THEN RAISE EXCEPTION 'QUALITY_UNAVAILABLE' USING ERRCODE='P0002';END IF;
 IF (r.inputs#>>'{execution,kind}' IN ('reference-allowed-values','uniqueness','range') OR EXISTS(SELECT 1 FROM public.quality_monitor_occurrences o WHERE o.tenant_id=r.tenant_id AND o.run_id=r.id)) AND r.status IN ('succeeded','failed','cancelled') THEN PERFORM public.gc_quality_run_lock(r.id);IF NOT public.gc_quality_run_can_execute(r.id) THEN RAISE EXCEPTION 'QUALITY_AUTHORITY_REVOKED' USING ERRCODE='42501';END IF;END IF;
 IF r.status IN ('succeeded','failed','cancelled') THEN RETURN jsonb_build_object('status','terminal','run',public.gc_quality_run_view(r.id));END IF;
 PERFORM public.gc_quality_run_lock(r.id);now_at:=clock_timestamp();
 IF NOT public.gc_quality_run_can_execute(r.id) THEN error:='QUALITY_AUTHORITY_REVOKED';
 ELSIF r.expires_at<=now_at THEN error:='QUALITY_DEADLINE_EXCEEDED';
 ELSE
  BEGIN inputs:=public.gc_quality_refresh_inputs(r.id);
  EXCEPTION WHEN feature_not_supported OR no_data_found THEN error:='QUALITY_TARGET_STALE';END;
  IF error IS NULL AND inputs IS DISTINCT FROM r.inputs THEN error:='QUALITY_TARGET_STALE';END IF;
 END IF;
 IF error IS NOT NULL THEN PERFORM public.gc_quality_terminal(r.id,error);RETURN jsonb_build_object('status','terminal','run',public.gc_quality_run_view(r.id));END IF;
 IF r.status='running' AND r.lease_expires_at>now_at THEN
  IF r.claim_id<>claim_identity THEN RETURN jsonb_build_object('status','busy','retryAt',public.gc_relation_utc(r.lease_expires_at));END IF;
 ELSE
  IF r.attempt>=3 THEN PERFORM public.gc_quality_terminal(r.id,'QUALITY_ATTEMPTS_EXHAUSTED');RETURN jsonb_build_object('status','terminal','run',public.gc_quality_run_view(r.id));END IF;
  IF r.claim_id=claim_identity THEN RAISE EXCEPTION 'QUALITY_CLAIM_EXPIRED' USING ERRCODE='40001';END IF;
  UPDATE public.quality_runs SET status='running',version=version+1,attempt=attempt+1,claim_id=claim_identity,claimed_at=now_at,lease_expires_at=least(expires_at,now_at+interval '120 seconds'),started_at=coalesce(started_at,now_at)
   WHERE tenant_id=r.tenant_id AND id=r.id RETURNING * INTO r;
  PERFORM public.gc_approval_journal('quality.run_claimed',NULL,r.column_asset_id::text,r.version,jsonb_build_object('ruleId',r.rule_id,'runId',r.id,'attempt',r.attempt),'quality:'||r.id::text);
 END IF;
 RETURN jsonb_build_object('status','claimed','runId',r.id,'claimId',r.claim_id,'attempt',r.attempt,'leaseExpiresAt',public.gc_relation_utc(r.lease_expires_at),'source',r.inputs->'source','execution',r.inputs->'execution');
END $$;

-- SPDX-License-Identifier: Apache-2.0
CREATE FUNCTION public.gc_quality_monitor_journal_present(action_name text,resource text,revision integer,expected jsonb) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT count(*)=1 FROM public.audit a JOIN public.outbox o ON o.tenant_id=a.tenant_id AND o.id=a.id
 WHERE a.tenant_id=public.gc_tenant() AND a.action=action_name AND a.resource_id=resource
 AND a.changes=expected||jsonb_build_object('resourceVersion',revision)
 AND o.event_type=action_name AND o.resource_id=resource AND o.resource_version=revision
 AND o.payload=jsonb_build_object('specversion','1.0','id',a.id,'type',action_name,'source','governance-commons','subject',resource,'time',public.gc_relation_utc(a.occurred_at),'tenantId',a.tenant_id,'resourceVersion',revision,'actorId',a.actor_id,'correlationId',a.correlation_id)
 AND o.created_at=a.occurred_at
 AND a.envelope=jsonb_build_object('id',a.id,'tenantId',a.tenant_id,'actorId',a.actor_id,'actorName',a.actor_name,'action',action_name,'resourceId',resource,'version',revision,'changes',expected,'correlationId',a.correlation_id,'occurredAt',public.gc_relation_utc(a.occurred_at),'previousHash',a.previous_hash)
 AND a.hash=public.gc_type_migration_hash(a.envelope)
$$;
CREATE FUNCTION public.gc_quality_monitor_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$ DECLARE n jsonb:=to_jsonb(NEW);o jsonb:=to_jsonb(OLD);allowed text[];BEGIN
 IF current_user<>(SELECT r.rolname FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE c.oid=TG_RELID) OR TG_OP='DELETE' THEN RAISE EXCEPTION 'MONITOR_FORBIDDEN' USING ERRCODE='42501';END IF;
 PERFORM public.gc_domain_bind('legacy');
 IF n->>'tenant_id' IS DISTINCT FROM public.gc_tenant()::text OR (n ? 'created_xid' AND TG_OP='INSERT' AND n->>'created_xid' IS DISTINCT FROM pg_current_xact_id()::text) THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 IF TG_OP='UPDATE' THEN
  IF TG_TABLE_NAME='quality_monitors' THEN
   allowed:=ARRAY['revision','definition_version','state','blocked','next_slot_at','last_admitted_ordinal','last_projected_ordinal','current_observation','last_conclusive'];
   IF (n->>'revision')::integer NOT BETWEEN (o->>'revision')::integer AND (o->>'revision')::integer+1
   OR (n->>'definition_version')::integer NOT BETWEEN (o->>'definition_version')::integer AND (o->>'definition_version')::integer+1
   OR (n->>'last_admitted_ordinal')::integer NOT BETWEEN (o->>'last_admitted_ordinal')::integer AND (o->>'last_admitted_ordinal')::integer+1
   OR (n->>'last_projected_ordinal')::integer NOT BETWEEN (o->>'last_projected_ordinal')::integer AND (o->>'last_projected_ordinal')::integer+1
   OR o->>'state'='retired' AND n->>'state'<>'retired'
   OR public.gc_actor()='site:local' AND (n-ARRAY['blocked','next_slot_at','last_admitted_ordinal','last_projected_ordinal','current_observation','last_conclusive']) IS DISTINCT FROM (o-ARRAY['blocked','next_slot_at','last_admitted_ordinal','last_projected_ordinal','current_observation','last_conclusive']) THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
  ELSIF TG_TABLE_NAME='quality_monitor_schedule_segments' THEN
   allowed:=ARRAY['next_slot_at','cutoff_at','closed_at','closed_revision','mode'];
   IF o->'next_slot_at'='null'::jsonb AND n->'next_slot_at'<>'null'::jsonb OR n->'next_slot_at'<>'null'::jsonb AND (n->>'next_slot_at')::timestamptz<(o->>'next_slot_at')::timestamptz
   OR o->'cutoff_at'<>'null'::jsonb AND (n-ARRAY['next_slot_at']) IS DISTINCT FROM (o-ARRAY['next_slot_at'])
   OR public.gc_actor()='site:local' AND (n-'next_slot_at') IS DISTINCT FROM (o-'next_slot_at') THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
  ELSIF TG_TABLE_NAME='quality_monitor_incidents' THEN
   allowed:=ARRAY['version','episode','status','assigned_owner_id','opened_at','acknowledge_due_at','resolve_due_at','opening','last_failure','recovery','resolution','superseded'];
   IF (n->>'version')::integer<>(o->>'version')::integer+1 OR (n->>'episode')::integer NOT BETWEEN (o->>'episode')::integer AND (o->>'episode')::integer+1 THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
  ELSIF TG_TABLE_NAME='quality_monitor_notifications' THEN
   allowed:=ARRAY['read_at','version'];
   IF o->>'version'<>'1' OR n->>'version'<>'2' OR n->'read_at'='null'::jsonb OR n->>'recipient_id' IS DISTINCT FROM public.gc_actor() THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
  ELSE RAISE EXCEPTION 'MONITOR_FORBIDDEN' USING ERRCODE='42501';END IF;
  IF n-allowed IS DISTINCT FROM o-allowed THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
DO $$ DECLARE name text;BEGIN
 FOREACH name IN ARRAY ARRAY['quality_monitors','quality_monitor_versions','quality_monitor_schedule_segments','quality_monitor_occurrences','quality_monitor_incidents','quality_monitor_incident_events','quality_monitor_projection_receipts','quality_monitor_notifications'] LOOP
  EXECUTE format('CREATE TRIGGER quality_monitor_guard BEFORE INSERT OR UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.gc_quality_monitor_guard()',name);
 END LOOP;
END $$;
CREATE FUNCTION public.gc_quality_monitor_evidence_valid(value jsonb,monitor_identity uuid,scope_hash text,expected_verdict text) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ BEGIN
 IF public.gc_relation_keys(value,ARRAY['occurrenceId','ordinal','runId','runVersion','completionHash','comparisonScopeHash','observedFinishedAt']) IS NOT TRUE
 OR NOT public.gc_approval_uuid(value->>'occurrenceId') OR NOT public.gc_approval_uuid(value->>'runId')
 OR NOT public.gc_quality_monitor_integer(value->'ordinal',1,2147483647) OR NOT public.gc_quality_monitor_integer(value->'runVersion',1,2147483647) THEN RETURN false;END IF;
 RETURN EXISTS(SELECT 1 FROM public.quality_monitor_occurrences o JOIN public.quality_runs q ON q.tenant_id=o.tenant_id AND q.id=o.run_id WHERE o.tenant_id=public.gc_tenant() AND o.id=(value->>'occurrenceId')::uuid AND o.monitor_id=monitor_identity AND o.ordinal=(value->>'ordinal')::integer
 AND o.comparison_scope_hash=scope_hash AND value->>'comparisonScopeHash'=scope_hash AND q.id=(value->>'runId')::uuid AND q.version=(value->>'runVersion')::integer AND q.completion_hash=value->>'completionHash'
 AND q.status='succeeded' AND q.verdict=expected_verdict AND value->'observedFinishedAt'=q.measurement->'observedFinishedAt');
END $$;
CREATE FUNCTION public.gc_quality_monitor_version_seal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE m public.quality_monitors;revision integer;BEGIN
 SELECT * INTO m FROM public.quality_monitors WHERE tenant_id=NEW.tenant_id AND id=NEW.monitor_id;
 SELECT created_revision INTO revision FROM public.quality_monitor_schedule_segments WHERE tenant_id=NEW.tenant_id AND monitor_id=NEW.monitor_id AND definition_version=NEW.version ORDER BY segment LIMIT 1;
 IF public.gc_quality_monitor_definition_valid(NEW.definition) IS NOT TRUE OR NEW.definition_hash IS DISTINCT FROM public.gc_type_migration_hash(NEW.definition)
 OR NEW.definition->>'executorId' IS DISTINCT FROM m.executor_id::text OR NEW.created_by<>m.executor_id OR NEW.rule_id<>m.rule_id
 OR NEW.definition->'rule' IS DISTINCT FROM jsonb_build_object('id',NEW.rule_id,'version',NEW.rule_version,'definitionHash',NEW.rule_hash)
 OR NEW.definition#>>'{routing,ownerId}' IS DISTINCT FROM NEW.owner_id::text OR revision IS NULL
 OR NOT public.gc_quality_monitor_journal_present('quality.monitor_published',m.id::text,revision,jsonb_build_object('definitionVersion',NEW.version,'definitionHash',NEW.definition_hash))
 THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER quality_monitor_version_seal AFTER INSERT ON public.quality_monitor_versions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_quality_monitor_version_seal();
CREATE FUNCTION public.gc_quality_monitor_occurrence_seal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE v public.quality_monitor_versions;m public.quality_monitors;q public.quality_runs;s public.quality_monitor_schedule_segments;observed public.quality_monitor_occurrences;step_seconds integer;BEGIN
 SELECT * INTO observed FROM public.quality_monitor_occurrences WHERE tenant_id=NEW.tenant_id AND id=NEW.id;
 IF observed.id IS NULL THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 SELECT * INTO m FROM public.quality_monitors WHERE tenant_id=observed.tenant_id AND id=observed.monitor_id;
 SELECT * INTO v FROM public.quality_monitor_versions WHERE tenant_id=observed.tenant_id AND monitor_id=observed.monitor_id AND version=observed.definition_version;
 IF observed.definition_hash IS DISTINCT FROM v.definition_hash OR observed.rule_id<>v.rule_id OR observed.rule_version<>v.rule_version OR observed.rule_hash<>v.rule_hash OR observed.executor_id<>m.executor_id
 OR NOT public.gc_quality_monitor_journal_present('quality.monitor_occurrence',m.id::text,observed.ordinal,jsonb_build_object('occurrenceId',observed.id,'definitionVersion',v.version,'definitionHash',v.definition_hash,'ordinal',observed.ordinal,'disposition',observed.disposition,'reason',observed.reason,'runId',observed.run_id,'comparisonScopeHash',observed.comparison_scope_hash)) THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 IF observed.origin='schedule' THEN
  SELECT * INTO s FROM public.quality_monitor_schedule_segments WHERE tenant_id=observed.tenant_id AND monitor_id=observed.monitor_id AND segment=observed.segment;step_seconds:=(v.definition#>>'{schedule,intervalSeconds}')::integer;
  IF s.definition_version<>observed.definition_version OR observed.first_slot_at<s.created_at OR s.cutoff_at IS NOT NULL AND observed.last_slot_at>=s.cutoff_at
  OR observed.first_slot_at IS DISTINCT FROM public.gc_quality_monitor_first_slot(v.definition,observed.first_slot_at) OR observed.last_slot_at IS DISTINCT FROM observed.first_slot_at+(observed.slot_count-1)*make_interval(secs=>step_seconds)
  OR (v.definition#>>'{schedule,endsAt}')::timestamptz IS NOT NULL AND observed.last_slot_at>=(v.definition#>>'{schedule,endsAt}')::timestamptz
  OR observed.recorded_at<observed.last_slot_at OR observed.disposition='enqueued' AND observed.slot_count<>1 THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 END IF;
 IF observed.run_id IS NOT NULL THEN
  SELECT * INTO q FROM public.quality_runs WHERE tenant_id=observed.tenant_id AND id=observed.run_id;
  IF q.rule_id<>observed.rule_id OR q.rule_version<>observed.rule_version OR q.rule_hash<>observed.rule_hash OR q.requester_id<>observed.executor_id OR q.created_at<>observed.recorded_at
  OR q.expires_at>least(q.created_at+interval '10 minutes',(v.definition->>'authorizationExpiresAt')::timestamptz)
  OR observed.comparison_scope IS DISTINCT FROM public.gc_quality_monitor_scope(m.id,v.definition,q.inputs) OR observed.comparison_scope_hash IS DISTINCT FROM public.gc_type_migration_hash(observed.comparison_scope)
  OR NOT public.gc_quality_monitor_journal_present('quality.run_requested',q.column_asset_id::text,1,jsonb_build_object('ruleId',q.rule_id,'runId',q.id,'ruleVersion',q.rule_version,'inputHash',q.input_hash)) THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 END IF;RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER quality_monitor_occurrence_seal AFTER INSERT ON public.quality_monitor_occurrences DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_quality_monitor_occurrence_seal();
CREATE FUNCTION public.gc_quality_monitor_projection_seal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE o public.quality_monitor_occurrences;q public.quality_runs;BEGIN
 SELECT * INTO o FROM public.quality_monitor_occurrences WHERE tenant_id=NEW.tenant_id AND id=NEW.occurrence_id;
 SELECT * INTO q FROM public.quality_runs WHERE tenant_id=NEW.tenant_id AND id=o.run_id;
 IF o.monitor_id<>NEW.monitor_id OR o.ordinal<>NEW.ordinal OR o.run_id IS DISTINCT FROM NEW.run_id OR q.version IS DISTINCT FROM NEW.run_version OR q.completion_hash IS DISTINCT FROM NEW.completion_hash
 OR q.status IN('queued','running') OR (SELECT count(*) FROM public.quality_monitor_projection_receipts WHERE tenant_id=NEW.tenant_id AND monitor_id=NEW.monitor_id AND ordinal<=NEW.ordinal)<>NEW.ordinal
 OR NOT public.gc_quality_monitor_journal_present('quality.monitor_projected',NEW.monitor_id::text,NEW.ordinal,jsonb_build_object('occurrenceId',o.id,'ordinal',o.ordinal,'runId',q.id,'runVersion',q.version,'completionHash',q.completion_hash)) THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER quality_monitor_projection_seal AFTER INSERT ON public.quality_monitor_projection_receipts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_quality_monitor_projection_seal();
CREATE FUNCTION public.gc_quality_monitor_event_seal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE i public.quality_monitor_incidents;v public.quality_monitor_versions;BEGIN
 SELECT * INTO i FROM public.quality_monitor_incidents WHERE tenant_id=NEW.tenant_id AND id=NEW.issue_id;
 SELECT * INTO v FROM public.quality_monitor_versions WHERE tenant_id=NEW.tenant_id AND monitor_id=NEW.monitor_id AND version=NEW.definition_version;
 IF NEW.monitor_id<>i.monitor_id OR NEW.definition_hash<>v.definition_hash OR (SELECT count(*) FROM public.quality_monitor_incident_events WHERE tenant_id=NEW.tenant_id AND issue_id=NEW.issue_id AND version<=NEW.version)<>NEW.version
 OR (NEW.version=i.version AND NEW.snapshot IS DISTINCT FROM public.gc_quality_monitor_issue_snapshot(i)) OR NEW.snapshot->>'id'<>NEW.issue_id::text OR NEW.snapshot->>'version'<>NEW.version::text OR NEW.snapshot->>'episode'<>NEW.episode::text
 OR NOT public.gc_quality_monitor_evidence_valid(NEW.snapshot->'opening',i.monitor_id,i.comparison_scope_hash,'FAIL') OR NOT public.gc_quality_monitor_evidence_valid(NEW.snapshot->'last_failure',i.monitor_id,i.comparison_scope_hash,'FAIL')
 OR NEW.snapshot->'recovery'<>'null'::jsonb AND NOT public.gc_quality_monitor_evidence_valid(NEW.snapshot->'recovery',i.monitor_id,i.comparison_scope_hash,'PASS')
 OR (NEW.kind='resolved') IS DISTINCT FROM (NEW.snapshot->'resolution'<>'null'::jsonb)
 OR NEW.snapshot->'resolution'<>'null'::jsonb AND NOT public.gc_quality_monitor_evidence_valid(NEW.snapshot#>'{resolution,evidence}',i.monitor_id,i.comparison_scope_hash,'PASS')
 OR NOT public.gc_quality_monitor_journal_present('quality.issue_'||replace(NEW.kind,'-','_'),i.id::text,NEW.version,jsonb_build_object('eventId',NEW.id,'monitorId',i.monitor_id,'definitionVersion',v.version,'definitionHash',v.definition_hash,'occurrenceId',NEW.occurrence_id,'runId',NEW.run_id,'episode',NEW.episode)) THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER quality_monitor_event_seal AFTER INSERT ON public.quality_monitor_incident_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_quality_monitor_event_seal();
CREATE FUNCTION public.gc_quality_monitor_notification_seal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.quality_monitor_incident_events WHERE tenant_id=NEW.tenant_id AND id=NEW.event_id AND issue_id=NEW.issue_id)
 OR NOT public.gc_quality_monitor_journal_present('quality.notification_created',NEW.id::text,1,jsonb_build_object('eventId',NEW.event_id,'issueId',NEW.issue_id,'recipientId',NEW.recipient_id,'template',NEW.template,'suppressed',NEW.suppressed))
 OR NEW.version=2 AND NOT public.gc_quality_monitor_journal_present('quality.notification_read',NEW.id::text,2,jsonb_build_object('eventId',NEW.event_id,'issueId',NEW.issue_id,'recipientId',NEW.recipient_id)) THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER quality_monitor_notification_seal AFTER INSERT OR UPDATE ON public.quality_monitor_notifications DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_quality_monitor_notification_seal();
CREATE FUNCTION public.gc_quality_monitor_head_seal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE m public.quality_monitors;i public.quality_monitor_incidents;v public.quality_monitor_versions;s public.quality_monitor_schedule_segments;expected_conclusive jsonb;expected_observation jsonb;segment_start timestamptz;expected_cursor timestamptz;consumed bigint;step_seconds integer;BEGIN
 IF TG_TABLE_NAME='quality_monitor_incidents' THEN
  SELECT * INTO i FROM public.quality_monitor_incidents WHERE tenant_id=NEW.tenant_id AND id=NEW.id;
  IF NOT EXISTS(SELECT 1 FROM public.quality_monitor_incident_events e WHERE e.tenant_id=i.tenant_id AND e.issue_id=i.id AND e.version=i.version AND e.snapshot=public.gc_quality_monitor_issue_snapshot(i)) THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 ELSE
  SELECT * INTO m FROM public.quality_monitors WHERE tenant_id=NEW.tenant_id AND id=CASE WHEN TG_TABLE_NAME='quality_monitors' THEN to_jsonb(NEW)->>'id' ELSE to_jsonb(NEW)->>'monitor_id' END::uuid;
  SELECT * INTO v FROM public.quality_monitor_versions WHERE tenant_id=m.tenant_id AND monitor_id=m.id AND version=m.definition_version;
  IF m.rule_id<>v.rule_id OR m.executor_id::text<>v.definition->>'executorId' OR m.last_admitted_ordinal<>(SELECT count(*) FROM public.quality_monitor_occurrences WHERE tenant_id=m.tenant_id AND monitor_id=m.id)
  OR m.last_projected_ordinal<>(SELECT count(*) FROM public.quality_monitor_projection_receipts WHERE tenant_id=m.tenant_id AND monitor_id=m.id)
  OR m.definition_version<>(SELECT count(*) FROM public.quality_monitor_versions WHERE tenant_id=m.tenant_id AND monitor_id=m.id)
  OR m.revision<>(SELECT count(*) FROM public.audit WHERE tenant_id=m.tenant_id AND resource_id=m.id::text AND action IN('quality.monitor_published','quality.monitor_state_changed'))
  THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
  SELECT jsonb_build_object('verdict',q.verdict,'evidence',jsonb_build_object('occurrenceId',o.id,'ordinal',o.ordinal,'runId',q.id,'runVersion',q.version,'completionHash',q.completion_hash,'comparisonScopeHash',o.comparison_scope_hash,'observedFinishedAt',q.measurement->'observedFinishedAt')) INTO expected_conclusive
   FROM public.quality_monitor_occurrences o JOIN public.quality_runs q ON q.tenant_id=o.tenant_id AND q.id=o.run_id WHERE o.tenant_id=m.tenant_id AND o.monitor_id=m.id AND o.ordinal<=m.last_projected_ordinal AND q.status='succeeded' AND q.verdict IN('PASS','FAIL') ORDER BY o.ordinal DESC LIMIT 1;
  IF m.last_conclusive IS DISTINCT FROM expected_conclusive THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
  IF m.current_observation->>'state'='conclusive' THEN
   expected_observation:=jsonb_build_object('state','conclusive','verdict',expected_conclusive->'verdict','evidence',expected_conclusive->'evidence');
   IF m.last_admitted_ordinal<>m.last_projected_ordinal OR expected_conclusive#>>'{evidence,ordinal}' IS DISTINCT FROM m.last_admitted_ordinal::text OR m.current_observation IS DISTINCT FROM expected_observation THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
  ELSIF m.current_observation->>'state'='pending' THEN
   IF m.last_admitted_ordinal<=m.last_projected_ordinal OR NOT EXISTS(SELECT 1 FROM public.quality_monitor_occurrences o WHERE o.tenant_id=m.tenant_id AND o.monitor_id=m.id AND o.ordinal=m.last_admitted_ordinal AND o.disposition='enqueued' AND m.current_observation=jsonb_build_object('state','pending','occurrenceId',o.id,'runId',o.run_id)) THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
  ELSIF m.current_observation->>'state'='unobserved' THEN
   IF m.last_admitted_ordinal<>0 OR m.current_observation<>'{"state":"unobserved"}'::jsonb THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
  ELSIF m.current_observation->>'state'='unknown' THEN
   IF m.current_observation->>'reason'='STALE' THEN
    IF m.current_observation<>jsonb_build_object('state','unknown','reason','STALE','occurrenceId',NULL) THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
   ELSIF NOT EXISTS(SELECT 1 FROM public.quality_monitor_occurrences o LEFT JOIN public.quality_runs q ON q.tenant_id=o.tenant_id AND q.id=o.run_id WHERE o.tenant_id=m.tenant_id AND o.monitor_id=m.id AND o.ordinal=m.last_admitted_ordinal AND m.current_observation=jsonb_build_object('state','unknown','reason',CASE WHEN o.disposition='skipped' THEN CASE WHEN o.reason IN('RULE_VERSION_CHANGED','AUTHORIZATION_EXPIRED','EXECUTOR_UNAVAILABLE','RULE_OWNER_UNAVAILABLE','TARGET_UNAVAILABLE','REFERENCE_UNAVAILABLE') THEN 'BLOCKED' ELSE 'SKIPPED' END WHEN q.status='cancelled' THEN 'CANCELLED' WHEN q.verdict='NO_DATA' THEN 'NO_DATA' ELSE 'EXECUTION_FAILED' END,'occurrenceId',o.id) AND (o.disposition='skipped' OR q.status IN('failed','cancelled') OR q.verdict='NO_DATA')) THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
  ELSE RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
  IF TG_TABLE_NAME='quality_monitor_schedule_segments' THEN
   SELECT * INTO s FROM public.quality_monitor_schedule_segments WHERE tenant_id=NEW.tenant_id AND monitor_id=NEW.monitor_id AND segment=NEW.segment;
   IF NOT EXISTS(SELECT 1 FROM public.audit a WHERE a.tenant_id=s.tenant_id AND a.resource_id=s.monitor_id::text AND a.action IN('quality.monitor_published','quality.monitor_state_changed') AND a.changes->>'resourceVersion'=s.created_revision::text AND a.actor_id=s.created_by)
   OR s.closed_revision IS NOT NULL AND NOT EXISTS(SELECT 1 FROM public.audit a WHERE a.tenant_id=s.tenant_id AND a.resource_id=s.monitor_id::text AND a.action IN('quality.monitor_published','quality.monitor_state_changed') AND a.changes->>'resourceVersion'=s.closed_revision::text)
   THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
   SELECT * INTO v FROM public.quality_monitor_versions WHERE tenant_id=s.tenant_id AND monitor_id=s.monitor_id AND version=s.definition_version;
   step_seconds:=(v.definition#>>'{schedule,intervalSeconds}')::integer;segment_start:=public.gc_quality_monitor_first_slot(v.definition,s.created_at);
   SELECT coalesce(sum(slot_count),0) INTO consumed FROM public.quality_monitor_occurrences WHERE tenant_id=s.tenant_id AND monitor_id=s.monitor_id AND segment=s.segment;
   IF consumed>2147483647 OR EXISTS(SELECT 1 FROM(SELECT first_slot_at,lag(last_slot_at) OVER(ORDER BY first_slot_at) AS prior FROM public.quality_monitor_occurrences WHERE tenant_id=s.tenant_id AND monitor_id=s.monitor_id AND segment=s.segment) q WHERE first_slot_at IS DISTINCT FROM coalesce(prior+make_interval(secs=>step_seconds),segment_start)) THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
   expected_cursor:=public.gc_quality_monitor_first_slot(v.definition,segment_start+consumed*make_interval(secs=>step_seconds));
   IF s.cutoff_at IS NOT NULL AND expected_cursor>=s.cutoff_at THEN expected_cursor:=NULL;END IF;
   IF s.next_slot_at IS DISTINCT FROM expected_cursor THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
  END IF;
 END IF;RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER quality_monitor_head_seal AFTER INSERT OR UPDATE ON public.quality_monitors DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_quality_monitor_head_seal();
CREATE CONSTRAINT TRIGGER quality_monitor_head_seal AFTER INSERT OR UPDATE ON public.quality_monitor_schedule_segments DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_quality_monitor_head_seal();
CREATE CONSTRAINT TRIGGER quality_monitor_head_seal AFTER INSERT OR UPDATE ON public.quality_monitor_incidents DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_quality_monitor_head_seal();

-- SPDX-License-Identifier: Apache-2.0
CREATE FUNCTION public.gc_quality_monitoring_audit_valid(action text,resource_id text,changes jsonb) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE identity uuid;v public.quality_monitor_versions;o public.quality_monitor_occurrences;p public.quality_monitor_projection_receipts;e public.quality_monitor_incident_events;n public.quality_monitor_notifications;expected jsonb;state_action text;BEGIN
 IF NOT public.gc_approval_uuid(resource_id) OR jsonb_typeof(changes) IS DISTINCT FROM 'object' OR NOT public.gc_quality_monitor_integer(changes->'resourceVersion',1,2147483647) THEN RETURN false;END IF;identity:=resource_id::uuid;
 IF action='quality.monitor_published' THEN
  IF NOT public.gc_quality_monitor_integer(changes->'definitionVersion',1,2147483647) THEN RETURN false;END IF;
  SELECT * INTO v FROM public.quality_monitor_versions WHERE tenant_id=public.gc_tenant() AND monitor_id=identity AND version=(changes->>'definitionVersion')::integer;
  expected:=jsonb_build_object('definitionVersion',v.version,'definitionHash',v.definition_hash,'resourceVersion',changes->'resourceVersion');
 ELSIF action='quality.monitor_state_changed' THEN
  IF NOT public.gc_quality_monitor_integer(changes->'definitionVersion',1,2147483647) OR changes->>'state' IS NULL OR changes->>'state' NOT IN('enabled','paused','retired') OR public.gc_approval_text(changes->>'reason',4096,true) IS NULL THEN RETURN false;END IF;
  SELECT * INTO v FROM public.quality_monitor_versions WHERE tenant_id=public.gc_tenant() AND monitor_id=identity AND version=(changes->>'definitionVersion')::integer;
  state_action:=CASE changes->>'state' WHEN 'enabled' THEN 'resume' WHEN 'paused' THEN 'pause' ELSE 'retire' END;
  IF NOT EXISTS(SELECT 1 FROM public.idempotency z WHERE z.tenant_id=public.gc_tenant() AND z.operation='quality.monitor.state' AND z.request_hash=public.gc_type_migration_hash(jsonb_build_object('monitorId',identity,'expectedRevision',(changes->>'resourceVersion')::integer-1,'action',state_action,'reason',changes->'reason'))
   AND z.response#>>'{monitor,id}'=resource_id AND z.response#>'{monitor,revision}'=changes->'resourceVersion') THEN RETURN false;END IF;
  expected:=jsonb_build_object('definitionVersion',v.version,'definitionHash',v.definition_hash,'state',changes->'state','reason',changes->'reason','resourceVersion',changes->'resourceVersion');
 ELSIF action='quality.monitor_occurrence' THEN
  IF NOT public.gc_approval_uuid(changes->>'occurrenceId') THEN RETURN false;END IF;
  SELECT * INTO o FROM public.quality_monitor_occurrences WHERE tenant_id=public.gc_tenant() AND id=(changes->>'occurrenceId')::uuid AND monitor_id=identity;
  expected:=jsonb_build_object('occurrenceId',o.id,'definitionVersion',o.definition_version,'definitionHash',o.definition_hash,'ordinal',o.ordinal,'disposition',o.disposition,'reason',o.reason,'runId',o.run_id,'comparisonScopeHash',o.comparison_scope_hash,'resourceVersion',o.ordinal);
 ELSIF action='quality.monitor_projected' THEN
  IF NOT public.gc_approval_uuid(changes->>'occurrenceId') THEN RETURN false;END IF;
  SELECT * INTO p FROM public.quality_monitor_projection_receipts WHERE tenant_id=public.gc_tenant() AND occurrence_id=(changes->>'occurrenceId')::uuid AND monitor_id=identity;
  expected:=jsonb_build_object('occurrenceId',p.occurrence_id,'ordinal',p.ordinal,'runId',p.run_id,'runVersion',p.run_version,'completionHash',p.completion_hash,'resourceVersion',p.ordinal);
 ELSIF action IN('quality.issue_opened','quality.issue_failed_again','quality.issue_acknowledged','quality.issue_assigned','quality.issue_recovery_available','quality.issue_recovery_invalidated','quality.issue_resolved','quality.issue_reopened','quality.issue_superseded') THEN
  IF NOT public.gc_approval_uuid(changes->>'eventId') THEN RETURN false;END IF;
  SELECT * INTO e FROM public.quality_monitor_incident_events WHERE tenant_id=public.gc_tenant() AND id=(changes->>'eventId')::uuid AND issue_id=identity AND 'quality.issue_'||replace(kind,'-','_')=action;
  expected:=jsonb_build_object('eventId',e.id,'monitorId',e.monitor_id,'definitionVersion',e.definition_version,'definitionHash',e.definition_hash,'occurrenceId',e.occurrence_id,'runId',e.run_id,'episode',e.episode,'resourceVersion',e.version);
 ELSIF action IN('quality.notification_created','quality.notification_read') THEN
  SELECT * INTO n FROM public.quality_monitor_notifications WHERE tenant_id=public.gc_tenant() AND id=identity;
  IF n.id IS NULL THEN RETURN false;END IF;
  expected:=jsonb_build_object('eventId',n.event_id,'issueId',n.issue_id,'recipientId',n.recipient_id,'resourceVersion',CASE WHEN action='quality.notification_created' THEN 1 ELSE 2 END)
    ||CASE WHEN action='quality.notification_created' THEN jsonb_build_object('template',n.template,'suppressed',n.suppressed) ELSE '{}'::jsonb END;
  IF action='quality.notification_read' AND n.read_at IS NULL THEN RETURN false;END IF;
 ELSE RETURN false;END IF;
 RETURN changes IS NOT DISTINCT FROM expected;
 EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR invalid_datetime_format OR datetime_field_overflow THEN RETURN false;
END $$;
CREATE FUNCTION public.gc_quality_monitoring_audit_visible(action text,resource_id text,changes jsonb,actor uuid) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE identity uuid;BEGIN
 IF actor::text IS DISTINCT FROM public.gc_actor() OR NOT EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id WHERE m.tenant_id=public.gc_tenant() AND m.identity_id=actor AND m.active AND i.active AND m.permissions @> '["catalog:read","quality:read","audit:read"]')
 OR public.gc_quality_monitoring_audit_valid(action,resource_id,changes) IS NOT TRUE THEN RETURN false;END IF;
 identity:=resource_id::uuid;
 IF action IN('quality.monitor_published','quality.monitor_state_changed') THEN RETURN public.gc_quality_monitor_visible(identity,actor,(changes->>'definitionVersion')::integer);
 ELSIF action IN('quality.monitor_occurrence','quality.monitor_projected') THEN RETURN public.gc_quality_occurrence_visible((changes->>'occurrenceId')::uuid,actor);
 ELSIF action IN('quality.issue_opened','quality.issue_failed_again','quality.issue_acknowledged','quality.issue_assigned','quality.issue_recovery_available','quality.issue_recovery_invalidated','quality.issue_resolved','quality.issue_reopened','quality.issue_superseded') THEN
  RETURN public.gc_quality_issue_event_visible((changes->>'eventId')::uuid,actor);
 ELSIF action IN('quality.notification_created','quality.notification_read') THEN RETURN public.gc_quality_notification_visible(identity,actor);
 END IF;RETURN false;
 EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR invalid_datetime_format OR datetime_field_overflow THEN RETURN false;
END $$;
CREATE FUNCTION public.gc_quality_monitor_journal_seal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE row_data jsonb;event_identity uuid;a public.audit;action_name text;BEGIN
 row_data:=CASE WHEN TG_OP='DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
 action_name:=coalesce(row_data->>'action',row_data->>'event_type');
 event_identity:=(row_data->>'id')::uuid;SELECT * INTO a FROM public.audit WHERE tenant_id=(row_data->>'tenant_id')::uuid AND id=event_identity;
 IF a.id IS NULL OR public.gc_quality_monitoring_audit_valid(a.action,a.resource_id,a.changes) IS NOT TRUE
 OR NOT public.gc_quality_monitor_journal_present(a.action,a.resource_id,(a.changes->>'resourceVersion')::integer,a.changes-'resourceVersion') THEN RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='23514';END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER quality_monitor_journal_insert_seal AFTER INSERT ON public.audit DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN(NEW.action IN('quality.monitor_published','quality.monitor_state_changed','quality.monitor_occurrence','quality.monitor_projected','quality.issue_opened','quality.issue_failed_again','quality.issue_acknowledged','quality.issue_assigned','quality.issue_recovery_available','quality.issue_recovery_invalidated','quality.issue_resolved','quality.issue_reopened','quality.issue_superseded','quality.notification_created','quality.notification_read')) EXECUTE FUNCTION public.gc_quality_monitor_journal_seal();
CREATE CONSTRAINT TRIGGER quality_monitor_journal_update_seal AFTER UPDATE ON public.audit DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN(OLD.action IN('quality.monitor_published','quality.monitor_state_changed','quality.monitor_occurrence','quality.monitor_projected','quality.issue_opened','quality.issue_failed_again','quality.issue_acknowledged','quality.issue_assigned','quality.issue_recovery_available','quality.issue_recovery_invalidated','quality.issue_resolved','quality.issue_reopened','quality.issue_superseded','quality.notification_created','quality.notification_read') OR NEW.action IN('quality.monitor_published','quality.monitor_state_changed','quality.monitor_occurrence','quality.monitor_projected','quality.issue_opened','quality.issue_failed_again','quality.issue_acknowledged','quality.issue_assigned','quality.issue_recovery_available','quality.issue_recovery_invalidated','quality.issue_resolved','quality.issue_reopened','quality.issue_superseded','quality.notification_created','quality.notification_read')) EXECUTE FUNCTION public.gc_quality_monitor_journal_seal();
CREATE CONSTRAINT TRIGGER quality_monitor_journal_delete_seal AFTER DELETE ON public.audit DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN(OLD.action IN('quality.monitor_published','quality.monitor_state_changed','quality.monitor_occurrence','quality.monitor_projected','quality.issue_opened','quality.issue_failed_again','quality.issue_acknowledged','quality.issue_assigned','quality.issue_recovery_available','quality.issue_recovery_invalidated','quality.issue_resolved','quality.issue_reopened','quality.issue_superseded','quality.notification_created','quality.notification_read')) EXECUTE FUNCTION public.gc_quality_monitor_journal_seal();
CREATE CONSTRAINT TRIGGER quality_monitor_journal_insert_seal AFTER INSERT ON public.outbox DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN(NEW.event_type IN('quality.monitor_published','quality.monitor_state_changed','quality.monitor_occurrence','quality.monitor_projected','quality.issue_opened','quality.issue_failed_again','quality.issue_acknowledged','quality.issue_assigned','quality.issue_recovery_available','quality.issue_recovery_invalidated','quality.issue_resolved','quality.issue_reopened','quality.issue_superseded','quality.notification_created','quality.notification_read')) EXECUTE FUNCTION public.gc_quality_monitor_journal_seal();
CREATE CONSTRAINT TRIGGER quality_monitor_journal_update_seal AFTER UPDATE ON public.outbox DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN(OLD.event_type IN('quality.monitor_published','quality.monitor_state_changed','quality.monitor_occurrence','quality.monitor_projected','quality.issue_opened','quality.issue_failed_again','quality.issue_acknowledged','quality.issue_assigned','quality.issue_recovery_available','quality.issue_recovery_invalidated','quality.issue_resolved','quality.issue_reopened','quality.issue_superseded','quality.notification_created','quality.notification_read') OR NEW.event_type IN('quality.monitor_published','quality.monitor_state_changed','quality.monitor_occurrence','quality.monitor_projected','quality.issue_opened','quality.issue_failed_again','quality.issue_acknowledged','quality.issue_assigned','quality.issue_recovery_available','quality.issue_recovery_invalidated','quality.issue_resolved','quality.issue_reopened','quality.issue_superseded','quality.notification_created','quality.notification_read')) EXECUTE FUNCTION public.gc_quality_monitor_journal_seal();
CREATE CONSTRAINT TRIGGER quality_monitor_journal_delete_seal AFTER DELETE ON public.outbox DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN(OLD.event_type IN('quality.monitor_published','quality.monitor_state_changed','quality.monitor_occurrence','quality.monitor_projected','quality.issue_opened','quality.issue_failed_again','quality.issue_acknowledged','quality.issue_assigned','quality.issue_recovery_available','quality.issue_recovery_invalidated','quality.issue_resolved','quality.issue_reopened','quality.issue_superseded','quality.notification_created','quality.notification_read')) EXECUTE FUNCTION public.gc_quality_monitor_journal_seal();
-- Every new helper starts private. Only closed read/command entry points are executable by gc_app.
DO $$ DECLARE f regprocedure;BEGIN
 FOR f IN SELECT p.oid::regprocedure FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname=ANY(ARRAY['gc_quality_monitor_integer','gc_quality_monitor_windows_valid','gc_quality_monitor_definition_valid','gc_quality_monitor_first_slot','gc_quality_monitor_in_window','gc_quality_monitor_lock','gc_quality_monitor_visible','gc_quality_occurrence_visible','gc_quality_issue_visible','gc_quality_issue_event_visible','gc_quality_notification_visible','gc_quality_monitor_inputs','gc_quality_monitor_scope','gc_quality_monitor_block','gc_quality_monitor_view','gc_quality_monitor_definition_view','gc_quality_occurrence_view','gc_quality_monitor_recovery_eligible','gc_quality_monitor_recovery_current','gc_quality_issue_view','gc_quality_issue_event_view','gc_quality_notification_view','gc_quality_monitor_occurrence','gc_quality_monitor_capacity','gc_quality_monitor_tick','gc_quality_monitor_issue_snapshot','gc_quality_monitor_event','gc_quality_monitor_reconcile','gc_quality_monitor_work','gc_quality_monitor_rotate','gc_quality_monitor_command','gc_quality_monitor_journal_present','gc_quality_monitor_guard','gc_quality_monitor_evidence_valid','gc_quality_monitor_version_seal','gc_quality_monitor_occurrence_seal','gc_quality_monitor_projection_seal','gc_quality_monitor_event_seal','gc_quality_monitor_notification_seal','gc_quality_monitor_head_seal','gc_quality_monitoring_audit_valid','gc_quality_monitoring_audit_visible','gc_quality_monitor_journal_seal']) LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC,gc_app',f);
 END LOOP;
 FOR f IN SELECT p.oid::regprocedure FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname=ANY(ARRAY['gc_quality_monitor_visible','gc_quality_occurrence_visible','gc_quality_issue_visible','gc_quality_issue_event_visible','gc_quality_notification_visible','gc_quality_monitor_view','gc_quality_monitor_definition_view','gc_quality_occurrence_view','gc_quality_issue_view','gc_quality_issue_event_view','gc_quality_notification_view','gc_quality_monitor_command','gc_quality_monitor_tick','gc_quality_monitor_reconcile','gc_quality_monitor_work','gc_quality_monitoring_audit_visible']) LOOP
  EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO gc_app',f);
 END LOOP;
END $$;
