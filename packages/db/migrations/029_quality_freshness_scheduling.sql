-- SPDX-License-Identifier: Apache-2.0
-- Scheduled freshness uses exact successful-claim-anchored recovery eligibility.
-- All existing rows, DTO evidence keys, rule hashes and worker envelopes are retained.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls)) OR pg_has_role('gc_app',current_user,'MEMBER') THEN
  RAISE EXCEPTION 'MONITOR_STORAGE_INVALID' USING ERRCODE='42501';END IF;
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_monitor_inputs(monitor_definition jsonb,at_time timestamptz) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ DECLARE v public.quality_rule_versions;r public.quality_rules;inputs jsonb;binding jsonb;executor uuid:=(monitor_definition->>'executorId')::uuid;BEGIN
 SELECT * INTO v FROM public.quality_rule_versions WHERE tenant_id=public.gc_tenant() AND rule_id=(monitor_definition#>>'{rule,id}')::uuid AND version=(monitor_definition#>>'{rule,version}')::integer;
 SELECT * INTO r FROM public.quality_rules WHERE tenant_id=v.tenant_id AND id=v.rule_id;
 IF NOT public.gc_quality_rule_visible(v.rule_id,v.version,executor) OR NOT public.gc_quality_can_execute(r.column_asset_id,executor) OR NOT public.gc_quality_reference_owner_active(v.owner_id) THEN RAISE EXCEPTION 'MONITOR_FORBIDDEN' USING ERRCODE='42501';END IF;
 IF r.current_version IS DISTINCT FROM v.version OR v.definition_hash IS DISTINCT FROM monitor_definition#>>'{rule,definitionHash}' THEN RAISE EXCEPTION 'MONITOR_PIN_STALE' USING ERRCODE='40001';END IF;
 IF v.definition->>'kind' NOT IN ('completeness','reference-allowed-values','uniqueness','range','freshness') THEN RAISE EXCEPTION 'MONITOR_RULE_UNSUPPORTED' USING ERRCODE='0A000';END IF;
 inputs:=public.gc_quality_inputs(r.column_asset_id,executor);
 IF v.definition->'target' IS DISTINCT FROM jsonb_build_object('tableAssetId',inputs->'tableAssetId','columnAssetId',inputs->'columnAssetId') THEN RAISE EXCEPTION 'MONITOR_PIN_STALE' USING ERRCODE='40001';END IF;
 IF v.definition->>'kind'='reference-allowed-values' THEN
  binding:=public.gc_quality_reference_binding((v.definition#>>'{reference,setId}')::uuid,executor,at_time);
  inputs:=jsonb_set(inputs,'{execution}',(inputs->'execution')||jsonb_build_object('kind','reference-allowed-values','reference',binding));
 ELSIF v.definition->>'kind'='uniqueness' THEN inputs:=jsonb_set(inputs,'{execution}',(inputs->'execution')||jsonb_build_object('kind','uniqueness','budget',(inputs#>'{execution,budget}')||jsonb_build_object('maximumValueBytes',4096,'maximumTotalValueBytes',67108864)));
 ELSIF v.definition->>'kind'='range' THEN inputs:=jsonb_set(inputs,'{execution}',(inputs->'execution')||jsonb_build_object('kind','range','range',public.gc_quality_range_binding(v.definition)));
 ELSIF v.definition->>'kind'='freshness' THEN inputs:=jsonb_set(inputs,'{execution}',(inputs->'execution')||jsonb_build_object('kind','freshness','freshness',public.gc_quality_freshness_binding(v.definition)));
 END IF;RETURN inputs;
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_monitor_scope(monitor_identity uuid,definition jsonb,inputs jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ BEGIN
 IF inputs#>>'{execution,kind}' IS NULL OR inputs#>>'{execution,kind}' NOT IN ('completeness','reference-allowed-values','uniqueness','range','freshness') THEN RAISE EXCEPTION 'MONITOR_RULE_UNSUPPORTED' USING ERRCODE='0A000';END IF;
 RETURN jsonb_build_object('formatVersion',1,'monitorId',monitor_identity,'executorId',definition->'executorId','rule',definition->'rule',
 'sourceId',inputs->'sourceId','sourceVersion',inputs->'sourceVersion','sourceConfigHash',inputs->'sourceConfigHash','schemaAssetId',inputs->'schemaAssetId','tableAssetId',inputs->'tableAssetId','columnAssetId',inputs->'columnAssetId','targetHash',public.gc_type_migration_hash(inputs#>'{execution,target}'),
 'family',CASE inputs#>>'{execution,kind}' WHEN 'uniqueness' THEN '{"kind":"uniqueness","comparison":"utf8-exact","nullPolicy":"exclude"}'::jsonb
 WHEN 'freshness' THEN jsonb_build_object('kind','freshness','freshnessHash',inputs#>'{execution,freshness,freshnessHash}')
 WHEN 'range' THEN jsonb_build_object('kind','range','rangeHash',inputs#>'{execution,range,rangeHash}')
 WHEN 'reference-allowed-values' THEN jsonb_build_object('kind','reference-allowed-values','setId',inputs#>'{execution,reference,setId}','version',inputs#>'{execution,reference,version}','publicationHash',inputs#>'{execution,reference,publicationHash}','codeStatus','active','codesHash',public.gc_type_migration_hash(inputs#>'{execution,reference,codes}'))
 ELSE '{"kind":"completeness"}'::jsonb END);
END $$;

-- Exact elapsed microseconds; no timestamp addition, floating point or future credit.
CREATE FUNCTION public.gc_quality_monitor_freshness_time(claimed_at timestamptz,finished_at timestamptz,projected_at timestamptz,observed_finished_at timestamptz,evaluated_at timestamptz,measured_age numeric,maximum_age integer,recovery_age integer) RETURNS text
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$ DECLARE remaining numeric;BEGIN
 IF claimed_at IS NULL OR finished_at IS NULL OR projected_at IS NULL OR observed_finished_at IS NULL OR evaluated_at IS NULL
 OR NOT isfinite(claimed_at) OR NOT isfinite(finished_at) OR NOT isfinite(projected_at) OR NOT isfinite(observed_finished_at) OR NOT isfinite(evaluated_at)
 OR EXISTS(SELECT 1 FROM unnest(ARRAY[claimed_at,finished_at,projected_at,observed_finished_at,evaluated_at]) instant WHERE extract(epoch FROM instant)*1000000 NOT BETWEEN -62135596800000000::numeric AND 253402300799999999::numeric)
 OR measured_age IS NULL OR measured_age::text IN ('NaN','Infinity','-Infinity') OR measured_age<>trunc(measured_age) OR abs(measured_age)>315537897599999999::numeric
 OR maximum_age IS NULL OR maximum_age NOT BETWEEN 1 AND 31536000 OR recovery_age IS NULL OR recovery_age NOT BETWEEN 60 AND 604800
 OR claimed_at>finished_at THEN RETURN 'evidence-unavailable';END IF;
 remaining:=maximum_age::numeric*1000000-greatest(measured_age,0);
 IF remaining<0 THEN RETURN 'evidence-unavailable';END IF;
 -- projected_at is millisecond-truncated; a valid projection may precede F by <1ms.
 IF evaluated_at<greatest(claimed_at,finished_at,projected_at,observed_finished_at) THEN RETURN 'clock-before-recorded-marker';END IF;
 IF extract(epoch FROM evaluated_at)*1000000-extract(epoch FROM claimed_at)*1000000>remaining
 OR extract(epoch FROM evaluated_at)*1000000-extract(epoch FROM observed_finished_at)*1000000>recovery_age::numeric*1000000 THEN RETURN 'expired';END IF;
 RETURN 'eligible';
END $$;

-- Private canonical check. Explicit time is for owner-only qualification vectors.
-- Production callers omit it: the one eligibility clock is read only after the
-- canonical records and current input scope have been obtained under caller locks.
CREATE FUNCTION public.gc_quality_monitor_freshness_current(monitor_identity uuid,evidence jsonb,evaluation_time timestamptz DEFAULT NULL) RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE m public.quality_monitors;v public.quality_monitor_versions;o public.quality_monitor_occurrences;q public.quality_runs;p public.quality_monitor_projection_receipts;inputs jsonb;scope jsonb;now_at timestamptz;BEGIN
 SELECT * INTO m FROM public.quality_monitors WHERE tenant_id=public.gc_tenant() AND id=monitor_identity;
 SELECT * INTO v FROM public.quality_monitor_versions WHERE tenant_id=m.tenant_id AND monitor_id=m.id AND version=m.definition_version;
 IF m.id IS NULL OR v.version IS NULL OR evidence IS NULL OR public.gc_quality_monitor_evidence_valid(evidence,m.id,evidence->>'comparisonScopeHash','PASS') IS NOT TRUE THEN RETURN 'evidence-unavailable';END IF;
 SELECT * INTO o FROM public.quality_monitor_occurrences WHERE tenant_id=m.tenant_id AND id=(evidence->>'occurrenceId')::uuid;
 SELECT * INTO q FROM public.quality_runs WHERE tenant_id=m.tenant_id AND id=o.run_id;
 SELECT * INTO p FROM public.quality_monitor_projection_receipts WHERE tenant_id=m.tenant_id AND occurrence_id=o.id;
 IF q.inputs#>>'{execution,kind}' IS DISTINCT FROM 'freshness' OR public.gc_quality_freshness_verdict(q.measurement,q.inputs#>'{execution,freshness}') IS DISTINCT FROM 'PASS'
 OR p.occurrence_id IS NULL OR p.monitor_id IS DISTINCT FROM m.id OR p.ordinal IS DISTINCT FROM o.ordinal OR p.run_id IS DISTINCT FROM q.id OR p.run_version IS DISTINCT FROM q.version OR p.completion_hash IS DISTINCT FROM q.completion_hash
 OR o.definition_version IS DISTINCT FROM v.version OR o.definition_hash IS DISTINCT FROM v.definition_hash OR o.rule_id IS DISTINCT FROM v.rule_id OR o.rule_version IS DISTINCT FROM v.rule_version OR o.rule_hash IS DISTINCT FROM v.rule_hash
 OR o.executor_id IS DISTINCT FROM m.executor_id OR q.requester_id IS DISTINCT FROM m.executor_id THEN RETURN 'evidence-unavailable';END IF;
 IF m.last_projected_ordinal IS DISTINCT FROM m.last_admitted_ordinal OR o.ordinal IS DISTINCT FROM m.last_admitted_ordinal
 OR m.current_observation IS DISTINCT FROM jsonb_build_object('state','conclusive','verdict','PASS','evidence',evidence) THEN RETURN 'newer-observation';END IF;
 IF m.state<>'enabled' OR m.blocked IS NOT NULL OR NOT public.gc_quality_run_visible(q.id,m.executor_id) THEN RETURN 'current-authority-unavailable';END IF;
 inputs:=public.gc_quality_monitor_inputs(v.definition,coalesce(evaluation_time,clock_timestamp()));
 scope:=public.gc_quality_monitor_scope(m.id,v.definition,inputs);
 IF scope IS DISTINCT FROM o.comparison_scope OR public.gc_type_migration_hash(scope) IS DISTINCT FROM o.comparison_scope_hash THEN RETURN 'current-scope-mismatch';END IF;
 IF public.gc_quality_monitor_block(v.definition,coalesce(evaluation_time,clock_timestamp())) IS NOT NULL THEN RETURN 'current-authority-unavailable';END IF;
 now_at:=coalesce(evaluation_time,clock_timestamp());
 IF (v.definition->>'authorizationExpiresAt')::timestamptz<=now_at THEN RETURN 'current-authority-unavailable';END IF;
 RETURN public.gc_quality_monitor_freshness_time(q.claimed_at,q.finished_at,p.projected_at,(q.measurement->>'observedFinishedAt')::timestamptz,now_at,
  (q.measurement->>'ageMicroseconds')::numeric,(q.inputs#>>'{execution,freshness,maximumAgeSeconds}')::integer,(v.definition->>'recoveryMaximumAgeSeconds')::integer);
 EXCEPTION WHEN feature_not_supported OR no_data_found OR insufficient_privilege THEN RETURN 'current-authority-unavailable';
 WHEN serialization_failure THEN RETURN 'current-scope-mismatch';
END $$;

CREATE OR REPLACE FUNCTION public.gc_quality_monitor_recovery_eligible(issue_identity uuid,evidence jsonb) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE i public.quality_monitor_incidents;m public.quality_monitors;v public.quality_monitor_versions;inputs jsonb;now_at timestamptz:=date_trunc('milliseconds',clock_timestamp());BEGIN
 SELECT * INTO i FROM public.quality_monitor_incidents WHERE tenant_id=public.gc_tenant() AND id=issue_identity;
 SELECT * INTO m FROM public.quality_monitors WHERE tenant_id=i.tenant_id AND id=i.monitor_id;
 SELECT * INTO v FROM public.quality_monitor_versions WHERE tenant_id=m.tenant_id AND monitor_id=m.id AND version=m.definition_version;
 IF EXISTS(SELECT 1 FROM public.quality_rule_versions rv WHERE rv.tenant_id=v.tenant_id AND rv.rule_id=v.rule_id AND rv.version=v.rule_version AND rv.definition->>'kind'='freshness') THEN
  RETURN i.status IN ('open','acknowledged') AND v.rule_id=i.rule_id AND v.rule_version=i.rule_version AND v.rule_hash=i.rule_hash AND evidence->>'comparisonScopeHash'=i.comparison_scope_hash
   AND public.gc_quality_monitor_freshness_current(m.id,evidence)='eligible';
 END IF;
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

CREATE OR REPLACE FUNCTION public.gc_quality_monitor_view(monitor_identity uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE m public.quality_monitors;v public.quality_monitor_versions;observation jsonb;reason text;BEGIN
 SELECT * INTO m FROM public.quality_monitors WHERE tenant_id=public.gc_tenant() AND id=monitor_identity;
 SELECT * INTO v FROM public.quality_monitor_versions WHERE tenant_id=m.tenant_id AND monitor_id=m.id AND version=m.definition_version;
 IF m.id IS NULL OR v.version IS NULL THEN RETURN NULL;END IF;
 observation:=m.current_observation;
 IF observation->>'state'='conclusive' AND observation->>'verdict'='PASS'
 AND EXISTS(SELECT 1 FROM public.quality_rule_versions rv WHERE rv.tenant_id=v.tenant_id AND rv.rule_id=v.rule_id AND rv.version=v.rule_version AND rv.definition->>'kind'='freshness') THEN
  reason:=public.gc_quality_monitor_freshness_current(m.id,observation->'evidence');
  IF reason<>'eligible' THEN observation:=jsonb_build_object('state','unknown','reason',CASE WHEN reason IN ('expired','clock-before-recorded-marker') THEN 'STALE' ELSE 'BLOCKED' END,'occurrenceId',observation#>'{evidence,occurrenceId}');END IF;
 ELSIF observation->>'state'='conclusive' AND (observation#>>'{evidence,observedFinishedAt}')::timestamptz+make_interval(secs=>(v.definition->>'recoveryMaximumAgeSeconds')::integer)<clock_timestamp()
 THEN observation:=jsonb_build_object('state','unknown','reason','STALE','occurrenceId',observation#>'{evidence,occurrenceId}');END IF;
 RETURN jsonb_build_object('id',m.id,'revision',m.revision,'definitionVersion',m.definition_version,'definitionHash',v.definition_hash,'definition',v.definition,
 'state',m.state,'blocked',m.blocked,'nextSlotAt',public.gc_relation_utc(m.next_slot_at),'lastAdmittedOrdinal',m.last_admitted_ordinal,'lastProjectedOrdinal',m.last_projected_ordinal,
 'currentObservation',observation,'lastConclusive',m.last_conclusive,'createdAt',public.gc_relation_utc(m.created_at),'createdBy',m.created_by);
END $$;

-- No external clock or private canonical evidence checker is runtime-callable.
REVOKE ALL ON FUNCTION public.gc_quality_monitor_freshness_time(timestamptz,timestamptz,timestamptz,timestamptz,timestamptz,numeric,integer,integer),public.gc_quality_monitor_freshness_current(uuid,jsonb,timestamptz) FROM PUBLIC,gc_app;
