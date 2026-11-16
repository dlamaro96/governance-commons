-- SPDX-License-Identifier: Apache-2.0
-- Server-ordered PostgreSQL catalog observations, separate from asserted relations.
ALTER TABLE public.sources ADD COLUMN next_scan_generation bigint NOT NULL DEFAULT 1,
 ADD COLUMN accepted_scan_generation bigint NOT NULL DEFAULT 0,
 ADD CONSTRAINT sources_scan_generation CHECK(accepted_scan_generation>=0 AND next_scan_generation>accepted_scan_generation);
ALTER TABLE public.jobs ADD COLUMN scan_generation bigint CHECK(scan_generation>0),
 ADD CONSTRAINT jobs_scan_generation_identity UNIQUE(tenant_id,id,source_id,scan_generation);
CREATE UNIQUE INDEX jobs_source_generation ON public.jobs(tenant_id,source_id,scan_generation) WHERE scan_generation IS NOT NULL;
CREATE TABLE public.lineage_observations (
 tenant_id uuid NOT NULL,id uuid NOT NULL,source_id uuid NOT NULL,scan_generation bigint NOT NULL CHECK(scan_generation>0),
 payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object' AND octet_length(payload::text)<=2097152),
 payload_hash text NOT NULL CHECK(payload_hash ~ '^[a-f0-9]{64}$'),source_version text NOT NULL CHECK(length(source_version)<=256),
 observed_at timestamptz NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),created_xid xid8 NOT NULL DEFAULT pg_current_xact_id(),
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,source_id,scan_generation),UNIQUE(tenant_id,id,source_id),
 FOREIGN KEY(tenant_id,id,source_id,scan_generation) REFERENCES public.jobs(tenant_id,id,source_id,scan_generation),
 FOREIGN KEY(tenant_id,source_id) REFERENCES public.sources(tenant_id,id)
);
CREATE TABLE public.lineage_edge_observations (
 tenant_id uuid NOT NULL,id text NOT NULL CHECK(id ~ '^[a-f0-9]{64}$'),observation_id uuid NOT NULL,source_id uuid NOT NULL,
 upstream_asset_id uuid NOT NULL,upstream_version integer NOT NULL,downstream_asset_id uuid NOT NULL,downstream_version integer NOT NULL,
 referenced_attribute_numbers smallint[] NOT NULL CHECK(cardinality(referenced_attribute_numbers) BETWEEN 1 AND 10000 AND 0<=ALL(referenced_attribute_numbers) AND array_position(referenced_attribute_numbers,NULL) IS NULL),
 evidence_hash text NOT NULL CHECK(evidence_hash ~ '^[a-f0-9]{64}$'),PRIMARY KEY(tenant_id,id),
 UNIQUE(tenant_id,observation_id,upstream_asset_id,downstream_asset_id),
 FOREIGN KEY(tenant_id,observation_id,source_id) REFERENCES public.lineage_observations(tenant_id,id,source_id),
 FOREIGN KEY(tenant_id,upstream_asset_id,upstream_version) REFERENCES public.asset_revisions(tenant_id,asset_id,version),
 FOREIGN KEY(tenant_id,downstream_asset_id,downstream_version) REFERENCES public.asset_revisions(tenant_id,asset_id,version)
);
CREATE INDEX lineage_edges_upstream ON public.lineage_edge_observations(tenant_id,observation_id,upstream_asset_id,id);
CREATE INDEX lineage_edges_downstream ON public.lineage_edge_observations(tenant_id,observation_id,downstream_asset_id,id);
DO $$ DECLARE name text; BEGIN
 FOREACH name IN ARRAY ARRAY['lineage_observations','lineage_edge_observations'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',name);
  EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.gc_tenant()) WITH CHECK(tenant_id=public.gc_tenant())',name);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC,gc_app',name);
  EXECUTE format('GRANT SELECT,INSERT ON public.%I TO gc_app',name);
  EXECUTE format('CREATE TRIGGER immutable BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.gc_immutable_audit()',name);
 END LOOP;
END $$;
-- The source and the endpoint revision must belong to the same registered source.
-- Canonical source IDs are immutable in source observations; no name-based joins.
CREATE FUNCTION public.gc_lineage_edge_scope() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.lineage_observations l WHERE l.tenant_id=NEW.tenant_id AND l.id=NEW.observation_id AND l.source_id=NEW.source_id AND l.created_xid=pg_current_xact_id())
 OR NOT EXISTS(SELECT 1 FROM public.assets a WHERE a.tenant_id=NEW.tenant_id AND a.id=NEW.upstream_asset_id AND a.source_id=NEW.source_id)
 OR NOT EXISTS(SELECT 1 FROM public.assets a WHERE a.tenant_id=NEW.tenant_id AND a.id=NEW.downstream_asset_id AND a.source_id=NEW.source_id AND a.type='view') THEN
  RAISE EXCEPTION 'LINEAGE_SCOPE_INVALID' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER lineage_edge_scope BEFORE INSERT ON public.lineage_edge_observations FOR EACH ROW EXECUTE FUNCTION public.gc_lineage_edge_scope();
REVOKE ALL ON FUNCTION public.gc_lineage_edge_scope() FROM PUBLIC;

-- Reject a partial commit that separates observation, canonical completion and journals.
CREATE FUNCTION public.gc_lineage_completion_journal() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE expected_count bigint;matched_count bigint;stored_count bigint;
BEGIN
 IF NEW.created_xid<>pg_current_xact_id() OR NEW.payload_hash<>public.gc_type_migration_hash(NEW.payload) THEN
  RAISE EXCEPTION 'LINEAGE_EVIDENCE_INVALID' USING ERRCODE='23514'; END IF;
 WITH projection AS (
  SELECT v.value AS view_,d.value AS dependency FROM jsonb_array_elements(NEW.payload->'views') v
   CROSS JOIN LATERAL jsonb_array_elements(v.value->'dependencies') d
 ) SELECT count(*),count(*) FILTER(WHERE e.id IS NOT NULL
  AND e.id=public.gc_type_migration_hash(jsonb_build_object('jobId',NEW.id,'upstream',u.id,'downstream',d.id))
  AND e.evidence_hash=public.gc_type_migration_hash(jsonb_build_object('viewExternalId',view_->>'viewExternalId','rewriteOid',view_->>'rewriteOid')||dependency)
  AND to_jsonb(e.referenced_attribute_numbers)=dependency->'referencedAttributeNumbers'
  AND ur.snapshot#>>'{metadata,scanId}'=NEW.id::text AND dr.snapshot#>>'{metadata,scanId}'=NEW.id::text
  AND ur.snapshot->>'sourceId'=NEW.source_id::text AND dr.snapshot->>'sourceId'=NEW.source_id::text
  AND ur.snapshot->>'type' IN ('table','view') AND dr.snapshot->>'type'='view')
 INTO expected_count,matched_count FROM projection p
 LEFT JOIN public.assets u ON u.tenant_id=NEW.tenant_id AND u.source_id=NEW.source_id AND u.external_id=p.dependency->>'referencedExternalId'
 LEFT JOIN public.assets d ON d.tenant_id=NEW.tenant_id AND d.source_id=NEW.source_id AND d.external_id=p.view_->>'viewExternalId'
 LEFT JOIN public.lineage_edge_observations e ON e.tenant_id=NEW.tenant_id AND e.observation_id=NEW.id AND e.upstream_asset_id=u.id AND e.downstream_asset_id=d.id
 LEFT JOIN public.asset_revisions ur ON ur.tenant_id=e.tenant_id AND ur.asset_id=e.upstream_asset_id AND ur.version=e.upstream_version
 LEFT JOIN public.asset_revisions dr ON dr.tenant_id=e.tenant_id AND dr.asset_id=e.downstream_asset_id AND dr.version=e.downstream_version;
 SELECT count(*) INTO stored_count FROM public.lineage_edge_observations WHERE tenant_id=NEW.tenant_id AND observation_id=NEW.id;
 IF expected_count<>matched_count OR expected_count<>stored_count OR expected_count>5000 THEN
  RAISE EXCEPTION 'LINEAGE_PROJECTION_INVALID' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.jobs j JOIN public.audit a ON a.tenant_id=j.tenant_id AND a.resource_id=j.id::text
  JOIN public.outbox o ON o.tenant_id=a.tenant_id AND o.id=a.id AND o.event_type=a.action AND o.resource_id=a.resource_id
  WHERE j.tenant_id=NEW.tenant_id AND j.id=NEW.id AND j.source_id=NEW.source_id AND j.scan_generation=NEW.scan_generation
   AND j.status='succeeded' AND a.action='scan.completed' AND a.changes->>'lineageHash'=NEW.payload_hash) THEN
  RAISE EXCEPTION 'LINEAGE_JOURNAL_REQUIRED' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER lineage_completion_journal AFTER INSERT ON public.lineage_observations
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_lineage_completion_journal();
REVOKE ALL ON FUNCTION public.gc_lineage_completion_journal() FROM PUBLIC;
