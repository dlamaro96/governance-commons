-- SPDX-License-Identifier: Apache-2.0
-- Versioned metadata classification with separate reviewed assignments.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls)) OR pg_has_role('gc_app',current_user,'MEMBER') THEN
  RAISE EXCEPTION 'classification forbidden' USING ERRCODE='42501'; END IF;
END $$;
CREATE FUNCTION public.gc_classification_text(value jsonb,maximum integer,mode text) RETURNS text
LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE raw text; normalized text;
BEGIN
 IF jsonb_typeof(value) IS DISTINCT FROM 'string' OR maximum IS NULL OR maximum<1
 OR mode IS NULL OR mode NOT IN('display','multiline','literal','observed') THEN RETURN NULL; END IF;
 raw:=value#>>'{}';
 -- Check the ORIGINAL before normalization/trim: no oversized whitespace or
 -- control characters can become acceptable merely by disappearing in trim.
 IF public.gc_relation_utf16_length(raw)>maximum
 OR raw ~ U&'[\0001-\0008\000B\000C\000E-\001F\007F-\009F]'
 OR (mode<>'multiline' AND raw ~ U&'[\0009\000A\000D]') THEN RETURN NULL; END IF;
 IF mode='observed' THEN normalized:=raw;
 ELSIF mode='literal' THEN normalized:=normalize(raw,NFC);
 ELSE normalized:=public.gc_approval_text(normalize(raw,NFC),maximum,mode='multiline'); END IF;
 IF normalized IS NULL OR public.gc_relation_utf16_length(normalized) NOT BETWEEN 1 AND maximum THEN RETURN NULL; END IF;
 RETURN normalized;
END $$;

CREATE FUNCTION public.gc_classification_pin_valid(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE revision numeric;
BEGIN
 IF public.gc_relation_keys(value,ARRAY['id','version','definitionHash']) IS NOT TRUE
 OR jsonb_typeof(value->'id') IS DISTINCT FROM 'string' OR NOT public.gc_approval_uuid(value->>'id')
 OR jsonb_typeof(value->'version') IS DISTINCT FROM 'number'
 OR jsonb_typeof(value->'definitionHash') IS DISTINCT FROM 'string'
 OR (value->>'definitionHash') COLLATE "C" !~ '^[a-f0-9]{64}$' THEN RETURN false; END IF;
 revision:=(value->>'version')::numeric;
 RETURN revision BETWEEN 1 AND 2147483647 AND revision=trunc(revision);
EXCEPTION WHEN data_exception OR check_violation OR program_limit_exceeded THEN RETURN false;
END $$;

-- Helpers return the same normalized definitions as the pure parser, or SQL
-- NULL on malformed input. The public boolean predicates accept noncanonical
-- display spelling only when it can normalize without discarding authored fields.
CREATE FUNCTION public.gc_classification_taxonomy_normalize(value jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE label_row jsonb; normalized_label jsonb; label_rows jsonb:='[]'::jsonb;
 name_text text; description_text text; seen text[]:=ARRAY[]::text[]; result jsonb;
BEGIN
 IF public.gc_relation_keys(value,ARRAY['formatVersion','name','description','labels']) IS NOT TRUE
 OR value->'formatVersion' IS DISTINCT FROM '1'::jsonb
 OR jsonb_typeof(value->'labels') IS DISTINCT FROM 'array' THEN RETURN NULL; END IF;
 IF jsonb_array_length(value->'labels') NOT BETWEEN 1 AND 128 THEN RETURN NULL; END IF;
 IF octet_length(public.gc_type_migration_canonical(value))>65536 THEN RETURN NULL; END IF;
 name_text:=public.gc_classification_text(value->'name',240,'display');
 description_text:=public.gc_classification_text(value->'description',4096,'multiline');
 IF name_text IS NULL OR description_text IS NULL THEN RETURN NULL; END IF;
 FOR label_row IN SELECT item FROM jsonb_array_elements(value->'labels') WITH ORDINALITY AS a(item,ordinal) ORDER BY ordinal LOOP
  IF public.gc_relation_keys(label_row,ARRAY['key','name','description','status']) IS NOT TRUE
  OR jsonb_typeof(label_row->'key') IS DISTINCT FROM 'string'
  OR public.gc_relation_safe_id(label_row->>'key') IS NOT TRUE
  OR jsonb_typeof(label_row->'status') IS DISTINCT FROM 'string'
  OR label_row->>'status' NOT IN('active','deprecated') THEN RETURN NULL; END IF;
  IF (label_row->>'key')=ANY(seen) THEN RETURN NULL; END IF;
  seen:=array_append(seen,label_row->>'key');
  normalized_label:=jsonb_build_object('key',label_row->'key',
   'name',public.gc_classification_text(label_row->'name',240,'display'),
   'description',public.gc_classification_text(label_row->'description',4096,'multiline'),'status',label_row->'status');
  IF normalized_label->'name'='null'::jsonb OR normalized_label->'description'='null'::jsonb THEN RETURN NULL; END IF;
  label_rows:=label_rows||jsonb_build_array(normalized_label);
 END LOOP;
 result:=jsonb_build_object('formatVersion',1,'name',name_text,'description',description_text,'labels',label_rows);
 IF octet_length(public.gc_type_migration_canonical(result))>65536 THEN RETURN NULL; END IF;
 RETURN result;
EXCEPTION WHEN data_exception OR check_violation OR program_limit_exceeded THEN RETURN NULL;
END $$;

CREATE FUNCTION public.gc_classification_taxonomy_valid(value jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
 SELECT public.gc_classification_taxonomy_normalize(value) IS NOT NULL
$$;

CREATE FUNCTION public.gc_classification_rule_normalize(value jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE predicate jsonb; normalized_predicate jsonb; predicates jsonb:='[]'::jsonb;
 asset_type jsonb; seen text[]:=ARRAY[]::text[]; name_text text; purpose_text text; result jsonb;
BEGIN
 IF public.gc_relation_keys(value,ARRAY['formatVersion','kind','name','purpose','ownerId','status','assetTypes','label','all']) IS NOT TRUE
 OR value->'formatVersion' IS DISTINCT FROM '1'::jsonb OR value->'kind' IS DISTINCT FROM '"metadata-literal"'::jsonb
 OR jsonb_typeof(value->'ownerId') IS DISTINCT FROM 'string' OR NOT public.gc_approval_uuid(value->>'ownerId')
 OR jsonb_typeof(value->'status') IS DISTINCT FROM 'string' OR value->>'status' NOT IN('active','retired')
 OR jsonb_typeof(value->'assetTypes') IS DISTINCT FROM 'array' OR jsonb_typeof(value->'all') IS DISTINCT FROM 'array'
 OR public.gc_relation_keys(value->'label',ARRAY['taxonomy','labelKey']) IS NOT TRUE
 OR NOT public.gc_classification_pin_valid(value->'label'->'taxonomy')
 OR jsonb_typeof(value->'label'->'labelKey') IS DISTINCT FROM 'string'
 OR public.gc_relation_safe_id(value->'label'->>'labelKey') IS NOT TRUE THEN RETURN NULL; END IF;
 IF jsonb_array_length(value->'assetTypes') NOT BETWEEN 1 AND 3 OR jsonb_array_length(value->'all') NOT BETWEEN 1 AND 8 THEN RETURN NULL; END IF;
 IF octet_length(public.gc_type_migration_canonical(value))>65536 THEN RETURN NULL; END IF;
 name_text:=public.gc_classification_text(value->'name',240,'display');purpose_text:=public.gc_classification_text(value->'purpose',4096,'multiline');
 IF name_text IS NULL OR purpose_text IS NULL THEN RETURN NULL; END IF;
 FOR asset_type IN SELECT item FROM jsonb_array_elements(value->'assetTypes') WITH ORDINALITY AS a(item,ordinal) ORDER BY ordinal LOOP
  IF jsonb_typeof(asset_type) IS DISTINCT FROM 'string' OR asset_type#>>'{}' NOT IN('table','view','column')
  OR (asset_type#>>'{}')=ANY(seen) THEN RETURN NULL; END IF;
  seen:=array_append(seen,asset_type#>>'{}');
 END LOOP;
 FOR predicate IN SELECT item FROM jsonb_array_elements(value->'all') WITH ORDINALITY AS a(item,ordinal) ORDER BY ordinal LOOP
  IF public.gc_relation_keys(predicate,ARRAY['field','operator','comparison','literal']) IS NOT TRUE
  OR jsonb_typeof(predicate->'field') IS DISTINCT FROM 'string' OR predicate->>'field' NOT IN('name','qualifiedName','dataType')
  OR jsonb_typeof(predicate->'operator') IS DISTINCT FROM 'string' OR predicate->>'operator' NOT IN('equals','contains','starts-with','ends-with')
  OR jsonb_typeof(predicate->'comparison') IS DISTINCT FROM 'string' OR predicate->>'comparison' NOT IN('exact','ascii-insensitive') THEN RETURN NULL; END IF;
  normalized_predicate:=jsonb_build_object('field',predicate->'field','operator',predicate->'operator','comparison',predicate->'comparison',
   'literal',public.gc_classification_text(predicate->'literal',256,'literal'));
  IF normalized_predicate->'literal'='null'::jsonb THEN RETURN NULL; END IF;
  predicates:=predicates||jsonb_build_array(normalized_predicate);
 END LOOP;
 result:=jsonb_build_object('formatVersion',1,'kind','metadata-literal','name',name_text,'purpose',purpose_text,
  'ownerId',value->'ownerId','status',value->'status','assetTypes',value->'assetTypes','label',value->'label','all',predicates);
 IF octet_length(public.gc_type_migration_canonical(result))>65536 THEN RETURN NULL; END IF;
 RETURN result;
EXCEPTION WHEN data_exception OR check_violation OR program_limit_exceeded THEN RETURN NULL;
END $$;

CREATE FUNCTION public.gc_classification_rule_valid(value jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
 SELECT public.gc_classification_rule_normalize(value) IS NOT NULL
$$;

CREATE FUNCTION public.gc_classification_asset_valid(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE revision numeric;
BEGIN
 IF public.gc_relation_keys(value,ARRAY['id','version','type','name','qualifiedName','dataType']) IS NOT TRUE
 OR jsonb_typeof(value->'id') IS DISTINCT FROM 'string' OR NOT public.gc_approval_uuid(value->>'id')
 OR jsonb_typeof(value->'version') IS DISTINCT FROM 'number'
 OR jsonb_typeof(value->'type') IS DISTINCT FROM 'string' OR public.gc_relation_safe_id(value->>'type') IS NOT TRUE
 OR public.gc_classification_text(value->'name',2048,'observed') IS NULL
 OR public.gc_classification_text(value->'qualifiedName',2048,'observed') IS NULL
 OR (value->'dataType' IS DISTINCT FROM 'null'::jsonb AND public.gc_classification_text(value->'dataType',2048,'observed') IS NULL) THEN RETURN false; END IF;
 revision:=(value->>'version')::numeric;
 IF revision NOT BETWEEN 1 AND 2147483647 OR revision<>trunc(revision) THEN RETURN false; END IF;
 RETURN octet_length(public.gc_type_migration_canonical(value))<=32768;
EXCEPTION WHEN data_exception OR check_violation OR program_limit_exceeded THEN RETURN false;
END $$;

CREATE FUNCTION public.gc_classification_input_digest(rule jsonb,asset jsonb) RETURNS text
LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE normalized_rule jsonb; selected_fields jsonb;
BEGIN
 normalized_rule:=public.gc_classification_rule_normalize(rule);
 IF normalized_rule IS NULL OR NOT public.gc_classification_asset_valid(asset) THEN
  RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023'; END IF;
 -- Exact preimage: {formatVersion:1,assetId,assetType,fields}. Selected field
 -- names are DISTINCT; values are exact observed string/null (not NFC/folded).
 -- No asset revision, unselected field, rule identity or label enters the digest.
 SELECT jsonb_object_agg(selected.field,asset->selected.field ORDER BY selected.field COLLATE "C") INTO selected_fields
 FROM (SELECT DISTINCT p->>'field' AS field FROM jsonb_array_elements(normalized_rule->'all') AS predicates(p)) AS selected;
 RETURN public.gc_type_migration_hash(jsonb_build_object('formatVersion',1,'assetId',asset->'id','assetType',asset->'type','fields',selected_fields));
EXCEPTION WHEN data_exception OR check_violation OR program_limit_exceeded THEN
 RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023';
END $$;

CREATE FUNCTION public.gc_classification_evaluate(rule jsonb,pin jsonb,asset jsonb,evaluated_at timestamptz) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog,pg_temp AS $$
DECLARE normalized_rule jsonb; supported boolean; evidence_matches jsonb:='[]'::jsonb; predicate_row record;
 raw_value text; compared text; literal_value text; matched boolean; outcome text; result jsonb;
 utc_instant timestamp; utc_year numeric; stamp text;
BEGIN
 normalized_rule:=public.gc_classification_rule_normalize(rule);
 IF normalized_rule IS NULL OR NOT public.gc_classification_pin_valid(pin) OR NOT public.gc_classification_asset_valid(asset)
 OR pin->>'definitionHash' IS DISTINCT FROM public.gc_type_migration_hash(normalized_rule)
 OR evaluated_at IS NULL OR NOT isfinite(evaluated_at) THEN RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023'; END IF;
 utc_instant:=evaluated_at AT TIME ZONE 'UTC';utc_year:=extract(year FROM utc_instant);
 IF utc_instant<>date_trunc('milliseconds',utc_instant) OR utc_year NOT BETWEEN -1 AND 9999 THEN
  RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023'; END IF;
 stamp:=public.gc_relation_utc(evaluated_at);
 -- JS ISO year 0000 is PostgreSQL 1 BC (there is no PostgreSQL year zero).
 IF utc_year=-1 THEN stamp:='0000'||substr(stamp,5); END IF;
 IF stamp !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$' THEN
  RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023'; END IF;
 supported:=(normalized_rule->'assetTypes') @> jsonb_build_array(asset->'type');
 IF supported THEN
  FOR predicate_row IN SELECT predicate,ordinal FROM jsonb_array_elements(normalized_rule->'all') WITH ORDINALITY AS a(predicate,ordinal) ORDER BY ordinal LOOP
   raw_value:=asset->>(predicate_row.predicate->>'field');
   IF raw_value IS NULL THEN CONTINUE; END IF;
   compared:=normalize(raw_value,NFC);literal_value:=predicate_row.predicate->>'literal';
   IF predicate_row.predicate->>'comparison'='ascii-insensitive' THEN
    compared:=translate(compared,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz');
    literal_value:=translate(literal_value,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz');
   END IF;
   CASE predicate_row.predicate->>'operator'
    WHEN 'equals' THEN matched:=compared COLLATE "C"=literal_value COLLATE "C";
    WHEN 'contains' THEN matched:=strpos(compared COLLATE "C",literal_value COLLATE "C")>0;
    WHEN 'starts-with' THEN matched:=left(compared,char_length(literal_value)) COLLATE "C"=literal_value COLLATE "C";
    WHEN 'ends-with' THEN matched:=right(compared,char_length(literal_value)) COLLATE "C"=literal_value COLLATE "C";
    ELSE RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023';
   END CASE;
   IF matched THEN evidence_matches:=evidence_matches||jsonb_build_array(jsonb_build_object(
    'conditionIndex',predicate_row.ordinal-1,'field',predicate_row.predicate->'field','value',raw_value,
    'valueHash',encode(sha256(convert_to(raw_value,'UTF8')),'hex'))); END IF;
  END LOOP;
 END IF;
 outcome:=CASE WHEN NOT supported THEN 'unsupported'
  WHEN jsonb_array_length(evidence_matches)=jsonb_array_length(normalized_rule->'all') THEN 'matched' ELSE 'not_matched' END;
 result:=jsonb_build_object('outcome',outcome,'evidence',jsonb_build_object('formatVersion',1,'kind','metadata-literal',
  'assetId',asset->'id','observedAssetVersion',asset->'version','inputDigest',public.gc_classification_input_digest(normalized_rule,asset),
  'rule',pin,'label',normalized_rule->'label','evaluatedAt',stamp,'matches',evidence_matches,
  'confidence',jsonb_build_object('kind','not-estimated','reason','metadata-only'),
  'samplePolicy',jsonb_build_object('kind','metadata-only','sourceRowsRead',0,'sourceSamplesStored',0)));
 -- Full {outcome,evidence} envelope, not just the inner evidence. No truncation.
 IF octet_length(public.gc_type_migration_canonical(result))>32768 THEN
  RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023'; END IF;
 RETURN result;
EXCEPTION WHEN data_exception OR check_violation OR program_limit_exceeded THEN
 RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023';
END $$;

CREATE TABLE public.classification_taxonomies (
 tenant_id uuid NOT NULL REFERENCES public.tenants(id),id uuid NOT NULL,current_version integer NOT NULL CHECK(current_version>0),
 created_by uuid NOT NULL,created_at timestamptz NOT NULL,PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id)
);
CREATE TABLE public.classification_taxonomy_versions (
 tenant_id uuid NOT NULL,taxonomy_id uuid NOT NULL,version integer NOT NULL CHECK(version>0),definition jsonb NOT NULL,
 definition_hash text NOT NULL CHECK(definition_hash ~ '^[a-f0-9]{64}$'),created_by uuid NOT NULL,created_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,taxonomy_id,version),UNIQUE(tenant_id,taxonomy_id,version,definition_hash),
 FOREIGN KEY(tenant_id,taxonomy_id) REFERENCES public.classification_taxonomies(tenant_id,id),FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id),
 CHECK(public.gc_classification_taxonomy_valid(definition) AND definition=public.gc_classification_taxonomy_normalize(definition) AND definition_hash=public.gc_type_migration_hash(definition))
);
ALTER TABLE public.classification_taxonomies ADD CONSTRAINT classification_taxonomy_current FOREIGN KEY(tenant_id,id,current_version)
 REFERENCES public.classification_taxonomy_versions(tenant_id,taxonomy_id,version) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE public.classification_rules (
 tenant_id uuid NOT NULL REFERENCES public.tenants(id),id uuid NOT NULL,current_version integer NOT NULL CHECK(current_version>0),
 created_by uuid NOT NULL,created_at timestamptz NOT NULL,PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id)
);
CREATE TABLE public.classification_rule_versions (
 tenant_id uuid NOT NULL,rule_id uuid NOT NULL,version integer NOT NULL CHECK(version>0),definition jsonb NOT NULL,definition_hash text NOT NULL CHECK(definition_hash ~ '^[a-f0-9]{64}$'),
 taxonomy_id uuid NOT NULL,taxonomy_version integer NOT NULL,taxonomy_hash text NOT NULL,owner_id uuid NOT NULL,created_by uuid NOT NULL,created_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,rule_id,version),UNIQUE(tenant_id,rule_id,version,definition_hash),FOREIGN KEY(tenant_id,rule_id) REFERENCES public.classification_rules(tenant_id,id),
 FOREIGN KEY(tenant_id,taxonomy_id,taxonomy_version,taxonomy_hash) REFERENCES public.classification_taxonomy_versions(tenant_id,taxonomy_id,version,definition_hash),
 FOREIGN KEY(tenant_id,owner_id) REFERENCES public.memberships(tenant_id,identity_id),FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id),
 CHECK(public.gc_classification_rule_valid(definition) AND definition=public.gc_classification_rule_normalize(definition) AND definition_hash=public.gc_type_migration_hash(definition)),
 CHECK(definition->>'ownerId'=owner_id::text AND definition#>>'{label,taxonomy,id}'=taxonomy_id::text AND (definition#>>'{label,taxonomy,version}')::integer=taxonomy_version AND definition#>>'{label,taxonomy,definitionHash}'=taxonomy_hash)
);
ALTER TABLE public.classification_rules ADD CONSTRAINT classification_rule_current FOREIGN KEY(tenant_id,id,current_version)
 REFERENCES public.classification_rule_versions(tenant_id,rule_id,version) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE public.classification_evaluations (
 tenant_id uuid NOT NULL,id uuid NOT NULL,asset_id uuid NOT NULL,asset_version integer NOT NULL,rule_id uuid NOT NULL,rule_version integer NOT NULL,rule_hash text NOT NULL,
 outcome text NOT NULL CHECK(outcome IN('matched','not_matched','unsupported')),evidence jsonb NOT NULL,evidence_hash text NOT NULL,created_by uuid NOT NULL,created_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,asset_id,asset_version) REFERENCES public.asset_revisions(tenant_id,asset_id,version),
 FOREIGN KEY(tenant_id,rule_id,rule_version,rule_hash) REFERENCES public.classification_rule_versions(tenant_id,rule_id,version,definition_hash),
 FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id),
 CHECK(evidence_hash=public.gc_type_migration_hash(evidence) AND octet_length(public.gc_type_migration_canonical(jsonb_build_object('outcome',outcome,'evidence',evidence)))<=32768)
);
CREATE INDEX classification_evaluations_asset ON public.classification_evaluations(tenant_id,asset_id,id);
CREATE TABLE public.classification_assignments (
 tenant_id uuid NOT NULL,id uuid NOT NULL,asset_id uuid NOT NULL,taxonomy_id uuid NOT NULL,label_key text NOT NULL CHECK(public.gc_relation_safe_id(label_key)),
 version integer NOT NULL CHECK(version>0),status text NOT NULL CHECK(status IN('active','withdrawn')),created_by uuid NOT NULL,created_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,id),UNIQUE(tenant_id,asset_id,taxonomy_id,label_key),FOREIGN KEY(tenant_id,asset_id) REFERENCES public.assets(tenant_id,id),
 FOREIGN KEY(tenant_id,taxonomy_id) REFERENCES public.classification_taxonomies(tenant_id,id),FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id)
);
CREATE TABLE public.classification_assignment_revisions (
 tenant_id uuid NOT NULL,assignment_id uuid NOT NULL,version integer NOT NULL CHECK(version>0),status text NOT NULL CHECK(status IN('active','withdrawn')),
 suggestion_id uuid NOT NULL,approval_request_id uuid NOT NULL,reason text,actor_id uuid NOT NULL,created_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,assignment_id,version),UNIQUE(tenant_id,approval_request_id),FOREIGN KEY(tenant_id,assignment_id) REFERENCES public.classification_assignments(tenant_id,id),
 FOREIGN KEY(tenant_id,suggestion_id) REFERENCES public.classification_evaluations(tenant_id,id),FOREIGN KEY(tenant_id,approval_request_id) REFERENCES public.approval_requests(tenant_id,id),
 FOREIGN KEY(tenant_id,actor_id) REFERENCES public.memberships(tenant_id,identity_id),CHECK((status='withdrawn')=(reason IS NOT NULL)),
 CHECK(reason IS NULL OR reason=public.gc_classification_text(to_jsonb(reason),4096,'multiline'))
);
ALTER TABLE public.classification_assignments ADD CONSTRAINT classification_assignment_current FOREIGN KEY(tenant_id,id,version)
 REFERENCES public.classification_assignment_revisions(tenant_id,assignment_id,version) DEFERRABLE INITIALLY DEFERRED;
DO $$ DECLARE name text;BEGIN
 FOREACH name IN ARRAY ARRAY['classification_taxonomies','classification_taxonomy_versions','classification_rules','classification_rule_versions','classification_evaluations','classification_assignments','classification_assignment_revisions'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',name);EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.gc_tenant()) WITH CHECK(tenant_id=public.gc_tenant())',name);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC,gc_app',name);EXECUTE format('GRANT SELECT ON public.%I TO gc_app',name);
 END LOOP;
 FOREACH name IN ARRAY ARRAY['classification_taxonomy_versions','classification_rule_versions','classification_evaluations','classification_assignment_revisions'] LOOP
  EXECUTE format('CREATE TRIGGER classification_immutable BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.gc_immutable_audit()',name);
 END LOOP;
END $$;
CREATE FUNCTION public.gc_classification_head_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$ BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'classification forbidden' USING ERRCODE='42501'; END IF;
 IF TG_TABLE_NAME='classification_assignments' THEN
  IF (to_jsonb(NEW)-ARRAY['version','status']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['version','status']) OR NEW.version<>OLD.version+1 THEN
   RAISE EXCEPTION 'classification forbidden' USING ERRCODE='42501';END IF;
 ELSE
  IF (to_jsonb(NEW)-'current_version') IS DISTINCT FROM (to_jsonb(OLD)-'current_version') OR NEW.current_version<>OLD.current_version+1 THEN
   RAISE EXCEPTION 'classification forbidden' USING ERRCODE='42501';END IF;
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER classification_head_guard BEFORE UPDATE OR DELETE ON public.classification_taxonomies FOR EACH ROW EXECUTE FUNCTION public.gc_classification_head_guard();
CREATE TRIGGER classification_head_guard BEFORE UPDATE OR DELETE ON public.classification_rules FOR EACH ROW EXECUTE FUNCTION public.gc_classification_head_guard();
CREATE TRIGGER classification_head_guard BEFORE UPDATE OR DELETE ON public.classification_assignments FOR EACH ROW EXECUTE FUNCTION public.gc_classification_head_guard();
CREATE FUNCTION public.gc_classification_visible(asset_identity uuid,actor_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM public.assets a JOIN public.memberships m ON m.tenant_id=a.tenant_id AND m.identity_id=actor_identity JOIN public.identities i ON i.id=m.identity_id
 WHERE a.tenant_id=public.gc_tenant() AND a.id=asset_identity AND m.active AND i.active AND m.permissions @> '["catalog:read","classification:read"]'::jsonb
 AND (a.visibility='tenant' OR a.allowed_identities @> to_jsonb(ARRAY[actor_identity::text])));
$$;
CREATE FUNCTION public.gc_classification_actor_can(asset_identity uuid,actor_identity uuid,permission_name text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT public.gc_classification_visible(asset_identity,actor_identity) AND EXISTS(SELECT 1 FROM public.memberships m WHERE m.tenant_id=public.gc_tenant() AND m.identity_id=actor_identity AND m.permissions @> jsonb_build_array(permission_name));
$$;
CREATE FUNCTION public.gc_classification_asset_input(asset_identity uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT jsonb_build_object('id',a.id,'version',a.version,'type',a.type,'name',a.name,'qualifiedName',a.qualified_name,
 'dataType',CASE WHEN jsonb_typeof(a.metadata->'dataType')='string' THEN a.metadata->'dataType' ELSE 'null'::jsonb END)
 FROM public.assets a WHERE a.tenant_id=public.gc_tenant() AND a.id=asset_identity;
$$;
CREATE FUNCTION public.gc_classification_taxonomy_view(selected_id uuid,selected_version integer) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT jsonb_build_object('id',h.id,'version',v.version,'currentVersion',h.current_version,'definition',v.definition,'definitionHash',v.definition_hash,'createdBy',v.created_by,'createdAt',public.gc_relation_utc(v.created_at))
 FROM public.classification_taxonomies h JOIN public.classification_taxonomy_versions v ON v.tenant_id=h.tenant_id AND v.taxonomy_id=h.id
 WHERE h.tenant_id=public.gc_tenant() AND h.id=selected_id AND v.version=coalesce(selected_version,h.current_version);
$$;
CREATE FUNCTION public.gc_classification_rule_view(selected_id uuid,selected_version integer) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT jsonb_build_object('id',h.id,'version',v.version,'currentVersion',h.current_version,'definition',v.definition,'definitionHash',v.definition_hash,'createdBy',v.created_by,'createdAt',public.gc_relation_utc(v.created_at))
 FROM public.classification_rules h JOIN public.classification_rule_versions v ON v.tenant_id=h.tenant_id AND v.rule_id=h.id
 WHERE h.tenant_id=public.gc_tenant() AND h.id=selected_id AND v.version=coalesce(selected_version,h.current_version);
$$;
CREATE FUNCTION public.gc_classification_evidence_current(evaluation_identity uuid) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE e public.classification_evaluations;r public.classification_rule_versions;input jsonb;BEGIN
 SELECT * INTO e FROM public.classification_evaluations WHERE tenant_id=public.gc_tenant() AND id=evaluation_identity;
 IF NOT FOUND THEN RETURN false;END IF;
 SELECT * INTO r FROM public.classification_rule_versions WHERE tenant_id=e.tenant_id AND rule_id=e.rule_id AND version=e.rule_version AND definition_hash=e.rule_hash;
 input:=public.gc_classification_asset_input(e.asset_id);
 RETURN coalesce(public.gc_classification_input_digest(r.definition,input)=e.evidence->>'inputDigest',false);
 EXCEPTION WHEN data_exception OR check_violation OR program_limit_exceeded THEN RETURN false;
END $$;
CREATE FUNCTION public.gc_classification_suggestion_view(selected_id uuid,actor_identity uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT jsonb_build_object('id',e.id,'assetId',e.asset_id,'evaluationId',e.id,'evidence',e.evidence,'evidenceHash',e.evidence_hash,
 'evidenceCurrent',public.gc_classification_evidence_current(e.id),'currentAssignmentVersion',coalesce(a.version,0),'createdAt',public.gc_relation_utc(e.created_at),'createdBy',e.created_by)
 FROM public.classification_evaluations e LEFT JOIN public.classification_assignments a ON a.tenant_id=e.tenant_id AND a.asset_id=e.asset_id AND a.taxonomy_id::text=e.evidence#>>'{label,taxonomy,id}' AND a.label_key=e.evidence#>>'{label,labelKey}'
 WHERE e.tenant_id=public.gc_tenant() AND e.id=selected_id AND e.outcome='matched' AND public.gc_classification_visible(e.asset_id,actor_identity);
$$;
CREATE FUNCTION public.gc_classification_assignment_view(selected_id uuid,actor_identity uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT jsonb_build_object('id',a.id,'assetId',a.asset_id,'label',e.evidence->'label','version',a.version,'status',a.status,'suggestionId',r.suggestion_id,
 'approvalInstanceId',r.approval_request_id,'evidence',e.evidence,'evidenceCurrent',public.gc_classification_evidence_current(e.id),
 'createdAt',public.gc_relation_utc(a.created_at),'updatedAt',public.gc_relation_utc(r.created_at),'updatedBy',r.actor_id,'reason',coalesce(r.reason,''))
 FROM public.classification_assignments a JOIN public.classification_assignment_revisions r ON r.tenant_id=a.tenant_id AND r.assignment_id=a.id AND r.version=a.version
 JOIN public.classification_evaluations e ON e.tenant_id=r.tenant_id AND e.id=r.suggestion_id
 WHERE a.tenant_id=public.gc_tenant() AND a.id=selected_id AND public.gc_classification_visible(a.asset_id,actor_identity);
$$;
CREATE FUNCTION public.gc_classification_label_current(label jsonb) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM public.classification_taxonomies h JOIN public.classification_taxonomy_versions v ON v.tenant_id=h.tenant_id AND v.taxonomy_id=h.id AND v.version=h.current_version
 WHERE h.tenant_id=public.gc_tenant() AND h.id::text=label#>>'{taxonomy,id}' AND v.version::text=label#>>'{taxonomy,version}' AND v.definition_hash=label#>>'{taxonomy,definitionHash}'
 AND EXISTS(SELECT 1 FROM jsonb_array_elements(v.definition->'labels') l WHERE l->>'key'=label->>'labelKey' AND l->>'status'='active'));
$$;
CREATE FUNCTION public.gc_classification_payload_current(value jsonb) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE e public.classification_evaluations;a public.classification_assignments;v public.classification_assignment_revisions;BEGIN
 SELECT * INTO e FROM public.classification_evaluations WHERE tenant_id=public.gc_tenant() AND id::text=value->>'suggestionId' AND outcome='matched' AND asset_id::text=value->>'assetId';
 IF NOT FOUND OR e.evidence IS DISTINCT FROM value->'evidence' OR e.evidence_hash IS DISTINCT FROM value->>'evidenceHash' OR e.evidence->'label' IS DISTINCT FROM value->'label' THEN RETURN false;END IF;
 SELECT * INTO a FROM public.classification_assignments WHERE tenant_id=e.tenant_id AND asset_id=e.asset_id AND taxonomy_id::text=value#>>'{label,taxonomy,id}' AND label_key=value#>>'{label,labelKey}';
 IF coalesce(a.version,0)::text IS DISTINCT FROM value->>'expectedAssignmentVersion' OR (a.id IS NOT NULL AND a.id::text IS DISTINCT FROM value->>'assignmentId') THEN RETURN false;END IF;
 IF value->>'change'='withdraw' THEN
  SELECT * INTO v FROM public.classification_assignment_revisions WHERE tenant_id=a.tenant_id AND assignment_id=a.id AND version=a.version;
  RETURN a.status='active' AND v.suggestion_id=e.id;
 ELSIF value->>'change'<>'apply' THEN RETURN false;END IF;
 RETURN EXISTS(SELECT 1 FROM public.assets WHERE tenant_id=e.tenant_id AND id=e.asset_id AND status='active')
 AND public.gc_classification_evidence_current(e.id) AND public.gc_classification_label_current(e.evidence->'label')
 AND EXISTS(SELECT 1 FROM public.classification_rules h JOIN public.classification_rule_versions r ON r.tenant_id=h.tenant_id AND r.rule_id=h.id AND r.version=h.current_version
  JOIN public.memberships m ON m.tenant_id=r.tenant_id AND m.identity_id=r.owner_id JOIN public.identities i ON i.id=m.identity_id
  WHERE h.tenant_id=e.tenant_id AND h.id=e.rule_id AND h.current_version=e.rule_version AND r.definition_hash=e.rule_hash AND r.definition->>'status'='active' AND m.active AND i.active);
 EXCEPTION WHEN data_exception OR check_violation OR program_limit_exceeded THEN RETURN false;
END $$;
-- The proposal contains server-selected evidence and a canonical slot version;
-- the requester cannot supply an approval result or an arbitrary label payload.
CREATE FUNCTION public.gc_classification_propose(body jsonb,correlation text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant();actor uuid:=public.gc_actor()::uuid;e public.classification_evaluations;a public.classification_assignments;v public.classification_assignment_revisions;
 w public.workflow_definition_versions;payload jsonb;change jsonb;stage jsonb;assignment text;keys text[];principals uuid[];principal uuid;expected integer;resource uuid;slot uuid;expiry timestamptz;stamp timestamptz;reason text;hash text;BEGIN
 IF public.gc_relation_keys(body,ARRAY['id','change','workflow','assignments','expiresAt']) IS NOT TRUE OR NOT public.gc_approval_uuid(body->>'id')
 OR public.gc_relation_keys(body->'workflow',ARRAY['id','version','definitionHash']) IS NOT TRUE OR NOT public.gc_relation_safe_id(body#>>'{workflow,id}')
 OR NOT public.gc_relation_positive_integer(body#>'{workflow,version}') OR body#>>'{workflow,definitionHash}' !~ '^[a-f0-9]{64}$'
 OR jsonb_typeof(body->'assignments') IS DISTINCT FROM 'object' OR jsonb_typeof(body->'expiresAt') IS DISTINCT FROM 'string'
 OR body->>'expiresAt' !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$' THEN RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023';END IF;
 change:=body->'change';
 IF change->>'kind'='apply' THEN
  IF public.gc_relation_keys(change,ARRAY['kind','suggestionId','expectedAssignmentVersion']) IS NOT TRUE OR NOT public.gc_approval_uuid(change->>'suggestionId') THEN RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023';END IF;
  SELECT * INTO e FROM public.classification_evaluations WHERE tenant_id=tenant AND id=(change->>'suggestionId')::uuid AND outcome='matched';
  IF NOT FOUND THEN RAISE EXCEPTION 'classification resource not found' USING ERRCODE='P0002';END IF;
  SELECT * INTO a FROM public.classification_assignments WHERE tenant_id=tenant AND asset_id=e.asset_id AND taxonomy_id=(e.evidence#>>'{label,taxonomy,id}')::uuid AND label_key=e.evidence#>>'{label,labelKey}';
 ELSIF change->>'kind'='withdraw' THEN
  IF public.gc_relation_keys(change,ARRAY['kind','assignmentId','expectedAssignmentVersion','reason']) IS NOT TRUE OR NOT public.gc_approval_uuid(change->>'assignmentId') THEN RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023';END IF;
  reason:=public.gc_classification_text(change->'reason',4096,'multiline');IF reason IS NULL THEN RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023';END IF;
  SELECT * INTO a FROM public.classification_assignments WHERE tenant_id=tenant AND id=(change->>'assignmentId')::uuid AND status='active';
  IF NOT FOUND THEN RAISE EXCEPTION 'classification resource not found' USING ERRCODE='P0002';END IF;
  SELECT * INTO v FROM public.classification_assignment_revisions WHERE tenant_id=tenant AND assignment_id=a.id AND version=a.version;
  SELECT * INTO e FROM public.classification_evaluations WHERE tenant_id=tenant AND id=v.suggestion_id;
 ELSE RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023';END IF;
 IF jsonb_typeof(change->'expectedAssignmentVersion') IS DISTINCT FROM 'number' OR change->>'expectedAssignmentVersion' !~ '^(0|[1-9][0-9]{0,9})$' THEN RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023';END IF;
 expected:=(change->>'expectedAssignmentVersion')::integer;slot:=coalesce(a.id,gen_random_uuid());resource:=(body->>'id')::uuid;expiry:=(body->>'expiresAt')::timestamptz;
 SELECT v0.* INTO w FROM public.workflow_definition_versions v0 JOIN public.workflow_definitions h ON h.tenant_id=v0.tenant_id AND h.id=v0.workflow_id AND h.current_version=v0.version
 WHERE v0.tenant_id=tenant AND v0.workflow_id=body#>>'{workflow,id}' AND v0.version=(body#>>'{workflow,version}')::integer AND v0.definition_hash=body#>>'{workflow,definitionHash}';
 IF NOT FOUND THEN RAISE EXCEPTION 'classification pin stale' USING ERRCODE='40001';END IF;
 IF w.definition->>'separationOfDuties'<>'true' THEN RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023';END IF;
 SELECT array_agg(DISTINCT a0#>>'{}' ORDER BY a0#>>'{}') INTO keys FROM jsonb_array_elements(w.definition->'stages') s CROSS JOIN LATERAL jsonb_array_elements(s->'assignments') a0;
 IF (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(body->'assignments') k) IS DISTINCT FROM keys
 OR EXISTS(SELECT 1 FROM jsonb_each(body->'assignments') p WHERE jsonb_typeof(p.value)<>'string' OR NOT public.gc_approval_uuid(p.value#>>'{}')) THEN RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023';END IF;
 SELECT array_agg(DISTINCT (p.value#>>'{}')::uuid ORDER BY (p.value#>>'{}')::uuid) INTO principals FROM jsonb_each(body->'assignments') p;
 IF actor=ANY(principals) OR cardinality(principals)<>cardinality(keys) THEN RAISE EXCEPTION 'classification forbidden' USING ERRCODE='42501';END IF;
 -- Complete sorted principal set before any identity/asset lock.
 PERFORM public.gc_lock_type_migration_principals(principals||ARRAY[(SELECT owner_id FROM public.classification_rule_versions WHERE tenant_id=tenant AND rule_id=e.rule_id AND version=e.rule_version)]);
 PERFORM 1 FROM public.assets WHERE tenant_id=tenant AND id=e.asset_id FOR SHARE;
 PERFORM public.gc_relation_authorize(ARRAY['catalog:read','classification:read','classification:write']);
 IF NOT public.gc_classification_actor_can(e.asset_id,actor,'classification:write') OR EXISTS(SELECT 1 FROM unnest(principals) p WHERE NOT public.gc_classification_actor_can(e.asset_id,p,'classification:approve')) THEN RAISE EXCEPTION 'classification forbidden' USING ERRCODE='42501';END IF;
 stamp:=date_trunc('milliseconds',clock_timestamp());IF expiry<=stamp OR expiry>stamp+interval '366 days' THEN RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023';END IF;
 IF coalesce(a.version,0)<>expected THEN RAISE EXCEPTION 'classification version conflict' USING ERRCODE='40001';END IF;
 payload:=jsonb_build_object('formatVersion',1,'kind','classification-review','change',change->'kind','assetId',e.asset_id,'assignmentId',slot,'expectedAssignmentVersion',expected,
 'suggestionId',e.id,'label',e.evidence->'label','evidence',e.evidence,'evidenceHash',e.evidence_hash,'reason',coalesce(reason,''));
 IF NOT public.gc_classification_payload_current(payload) THEN RAISE EXCEPTION 'classification evidence stale' USING ERRCODE='40001';END IF;
 hash:=public.gc_type_migration_hash(jsonb_build_object('id',resource,'binding','classification.review','payload',payload,'workflow',body->'workflow','assignments',body->'assignments','expiresAt',body->'expiresAt'));
 INSERT INTO public.approval_requests(tenant_id,id,binding,resource_id,resource_version,payload,proposal_digest,workflow_id,workflow_version,workflow_hash,requester_id,status,expires_at,created_at,updated_at)
 VALUES(tenant,resource,'classification.review',e.asset_id,(SELECT version FROM public.assets WHERE tenant_id=tenant AND id=e.asset_id),payload,hash,w.workflow_id,w.version,w.definition_hash,actor,'pending',expiry,stamp,stamp);
 FOR stage IN SELECT s.value||jsonb_build_object('_ordinal',s.ordinality-1) FROM jsonb_array_elements(w.definition->'stages') WITH ORDINALITY s LOOP
  FOR assignment IN SELECT a0#>>'{}' FROM jsonb_array_elements(stage->'assignments') a0 LOOP
   INSERT INTO public.approval_tasks(tenant_id,id,request_id,stage_index,assignment,assigned_identity_id,status,opened_at,expires_at)
   VALUES(tenant,gen_random_uuid(),resource,(stage->>'_ordinal')::integer,assignment,(body->'assignments'->>assignment)::uuid,
   CASE WHEN stage->>'_ordinal'='0' THEN 'open' ELSE 'waiting' END,CASE WHEN stage->>'_ordinal'='0' THEN stamp END,
   CASE WHEN stage->>'_ordinal'='0' THEN least(expiry,stamp+make_interval(secs=>(stage->>'deadlineSeconds')::integer)) END);
  END LOOP;
 END LOOP;
 PERFORM public.gc_approval_journal('approval.submitted',resource,resource::text,1,jsonb_build_object('binding','classification.review','proposalDigest',hash,'workflowId',w.workflow_id,'workflowVersion',w.version),correlation,true);
 RETURN jsonb_build_object('instance',jsonb_build_object('id',resource));
END $$;
CREATE FUNCTION public.gc_classification_command(operation text,command_key text,body jsonb,correlation text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant();actor uuid;old public.idempotency;required text[];hash text;result jsonb;definition jsonb;selected uuid;expected integer;stamp timestamptz;owner uuid;
 rule public.classification_rule_versions;input jsonb;evaluation jsonb;BEGIN
 IF operation IS NULL OR operation NOT IN('classification.taxonomy.publish','classification.rule.publish','classification.evaluate','classification.propose') OR command_key IS NULL OR length(command_key) NOT BETWEEN 8 AND 128
 OR command_key ~ '[[:cntrl:]]' OR correlation IS NULL OR length(correlation) NOT BETWEEN 1 AND 128 OR correlation ~ '[[:cntrl:]]'
 OR jsonb_typeof(body) IS DISTINCT FROM 'object' OR octet_length(body::text)>98304 THEN RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023';END IF;
 required:=CASE WHEN operation IN('classification.taxonomy.publish','classification.rule.publish') THEN ARRAY['catalog:read','classification:read','classification:write','models:read','models:write'] ELSE ARRAY['catalog:read','classification:read','classification:write'] END;
 PERFORM public.gc_relation_authorize(required);actor:=public.gc_actor()::uuid;
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text,0));PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text||actor::text||operation||command_key,0));
 hash:=public.gc_type_migration_hash(body);
 SELECT * INTO old FROM public.idempotency WHERE tenant_id=tenant AND actor_id=actor::text AND idempotency.operation=gc_classification_command.operation AND key=command_key;
 IF FOUND THEN
  IF old.request_hash<>hash THEN RAISE EXCEPTION 'classification version conflict' USING ERRCODE='40001';END IF;
  PERFORM public.gc_lock_type_migration_principals(ARRAY[]::uuid[]);PERFORM public.gc_relation_authorize(required);
  IF operation='classification.evaluate' AND NOT public.gc_classification_visible((body->>'assetId')::uuid,actor) THEN RAISE EXCEPTION 'classification resource not found' USING ERRCODE='P0002';END IF;
  IF operation='classification.propose' AND NOT EXISTS(SELECT 1 FROM public.approval_requests WHERE tenant_id=tenant AND id=(body->>'id')::uuid AND requester_id=actor AND binding='classification.review' AND public.gc_classification_visible(resource_id,actor)) THEN RAISE EXCEPTION 'classification resource not found' USING ERRCODE='P0002';END IF;
  RETURN old.response;
 END IF;
 IF operation IN('classification.taxonomy.publish','classification.rule.publish') THEN
  IF public.gc_relation_keys(body,ARRAY['id','expectedVersion','definition']) IS NOT TRUE OR NOT public.gc_approval_uuid(body->>'id')
  OR jsonb_typeof(body->'expectedVersion') IS DISTINCT FROM 'number' OR body->>'expectedVersion' !~ '^(0|[1-9][0-9]{0,9})$' THEN RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023';END IF;
  selected:=(body->>'id')::uuid;expected:=(body->>'expectedVersion')::integer;
  definition:=CASE WHEN operation='classification.taxonomy.publish' THEN public.gc_classification_taxonomy_normalize(body->'definition') ELSE public.gc_classification_rule_normalize(body->'definition') END;
  IF definition IS NULL THEN RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023';END IF;
  IF operation='classification.rule.publish' THEN owner:=(definition->>'ownerId')::uuid;END IF;
  PERFORM public.gc_lock_type_migration_principals(array_remove(ARRAY[owner],NULL));PERFORM public.gc_relation_authorize(required);stamp:=date_trunc('milliseconds',clock_timestamp());
  IF operation='classification.taxonomy.publish' THEN
   IF coalesce((SELECT current_version FROM public.classification_taxonomies WHERE tenant_id=tenant AND id=selected),0)<>expected THEN RAISE EXCEPTION 'classification version conflict' USING ERRCODE='40001';END IF;
   IF expected=0 THEN INSERT INTO public.classification_taxonomies VALUES(tenant,selected,1,actor,stamp);ELSE UPDATE public.classification_taxonomies SET current_version=expected+1 WHERE tenant_id=tenant AND id=selected;END IF;
   INSERT INTO public.classification_taxonomy_versions VALUES(tenant,selected,expected+1,definition,public.gc_type_migration_hash(definition),actor,stamp);
   result:=jsonb_build_object('taxonomy',public.gc_classification_taxonomy_view(selected,expected+1));
  ELSE
   IF coalesce((SELECT current_version FROM public.classification_rules WHERE tenant_id=tenant AND id=selected),0)<>expected THEN RAISE EXCEPTION 'classification version conflict' USING ERRCODE='40001';END IF;
   IF NOT public.gc_classification_label_current(definition->'label') THEN RAISE EXCEPTION 'classification pin stale' USING ERRCODE='40001';END IF;
   IF NOT EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id WHERE m.tenant_id=tenant AND m.identity_id=owner AND m.active AND i.active) THEN RAISE EXCEPTION 'classification forbidden' USING ERRCODE='42501';END IF;
   IF expected=0 THEN INSERT INTO public.classification_rules VALUES(tenant,selected,1,actor,stamp);ELSE UPDATE public.classification_rules SET current_version=expected+1 WHERE tenant_id=tenant AND id=selected;END IF;
   INSERT INTO public.classification_rule_versions VALUES(tenant,selected,expected+1,definition,public.gc_type_migration_hash(definition),(definition#>>'{label,taxonomy,id}')::uuid,(definition#>>'{label,taxonomy,version}')::integer,definition#>>'{label,taxonomy,definitionHash}',owner,actor,stamp);
   result:=jsonb_build_object('rule',public.gc_classification_rule_view(selected,expected+1));
  END IF;
  PERFORM public.gc_approval_journal(operation,NULL,selected::text,expected+1,jsonb_build_object('definitionHash',public.gc_type_migration_hash(definition)),correlation);
 ELSIF operation='classification.evaluate' THEN
  IF public.gc_relation_keys(body,ARRAY['id','assetId','expectedAssetVersion','rule']) IS NOT TRUE OR NOT public.gc_approval_uuid(body->>'id') OR NOT public.gc_approval_uuid(body->>'assetId') OR NOT public.gc_relation_positive_integer(body->'expectedAssetVersion') OR NOT public.gc_classification_pin_valid(body->'rule') THEN RAISE EXCEPTION 'classification request invalid' USING ERRCODE='22023';END IF;
  selected:=(body->>'id')::uuid;
  SELECT v.* INTO rule FROM public.classification_rule_versions v JOIN public.classification_rules h ON h.tenant_id=v.tenant_id AND h.id=v.rule_id AND h.current_version=v.version
   WHERE v.tenant_id=tenant AND v.rule_id=(body#>>'{rule,id}')::uuid AND v.version=(body#>>'{rule,version}')::integer AND v.definition_hash=body#>>'{rule,definitionHash}' AND v.definition->>'status'='active';
  IF NOT FOUND OR NOT public.gc_classification_label_current(rule.definition->'label') THEN RAISE EXCEPTION 'classification pin stale' USING ERRCODE='40001';END IF;
  PERFORM public.gc_lock_type_migration_principals(ARRAY[rule.owner_id]);PERFORM 1 FROM public.assets WHERE tenant_id=tenant AND id=(body->>'assetId')::uuid FOR SHARE;PERFORM public.gc_relation_authorize(required);
  IF NOT public.gc_classification_visible((body->>'assetId')::uuid,actor) THEN RAISE EXCEPTION 'classification resource not found' USING ERRCODE='P0002';END IF;
  IF NOT EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id WHERE m.tenant_id=tenant AND m.identity_id=rule.owner_id AND m.active AND i.active) THEN RAISE EXCEPTION 'classification forbidden' USING ERRCODE='42501';END IF;
  input:=public.gc_classification_asset_input((body->>'assetId')::uuid);
  IF input->'version' IS DISTINCT FROM body->'expectedAssetVersion' OR NOT EXISTS(SELECT 1 FROM public.assets WHERE tenant_id=tenant AND id=(body->>'assetId')::uuid AND status='active') THEN RAISE EXCEPTION 'classification version conflict' USING ERRCODE='40001';END IF;
  stamp:=date_trunc('milliseconds',clock_timestamp());evaluation:=public.gc_classification_evaluate(rule.definition,body->'rule',input,stamp);
  INSERT INTO public.classification_evaluations VALUES(tenant,selected,(body->>'assetId')::uuid,(body->>'expectedAssetVersion')::integer,rule.rule_id,rule.version,rule.definition_hash,evaluation->>'outcome',evaluation->'evidence',public.gc_type_migration_hash(evaluation->'evidence'),actor,stamp);
  result:=jsonb_build_object('evaluation',evaluation||jsonb_build_object('id',selected,'createdBy',actor,'suggestionId',CASE WHEN evaluation->>'outcome'='matched' THEN selected END,'evidenceHash',public.gc_type_migration_hash(evaluation->'evidence')));
  PERFORM public.gc_approval_journal(operation,NULL,body->>'assetId',(body->>'expectedAssetVersion')::integer,jsonb_build_object('evaluationId',selected,'outcome',evaluation->'outcome','evidenceHash',public.gc_type_migration_hash(evaluation->'evidence')),correlation);
 ELSE result:=public.gc_classification_propose(body,correlation);
 END IF;
 INSERT INTO public.idempotency(tenant_id,actor_id,operation,key,request_hash,response) VALUES(tenant,actor::text,operation,command_key,hash,result);RETURN result;
END $$;

CREATE FUNCTION public.gc_approval_command_glossary_legacy(operation text,command_key text,body jsonb,correlation text) RETURNS jsonb
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
 SELECT * INTO old FROM public.idempotency WHERE tenant_id=tenant AND actor_id=actor::text AND idempotency.operation=gc_approval_command_glossary_legacy.operation AND key=command_key;
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


CREATE FUNCTION public.gc_approval_tick_glossary_legacy(request_identity uuid) RETURNS jsonb
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

ALTER TABLE public.approval_requests DROP CONSTRAINT approval_requests_binding_check;
ALTER TABLE public.approval_requests ADD CONSTRAINT approval_requests_binding_check CHECK(binding IN('glossary.publish','classification.review'));
CREATE FUNCTION public.gc_classification_lock_review(request_identity uuid) RETURNS public.approval_requests
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE r public.approval_requests;principal uuid;principals uuid[];BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(public.gc_tenant()::text,0));
 SELECT * INTO r FROM public.approval_requests WHERE tenant_id=public.gc_tenant() AND id=request_identity AND binding='classification.review';
 IF NOT FOUND THEN RAISE EXCEPTION 'classification resource not found' USING ERRCODE='P0002';END IF;
 SELECT array_agg(DISTINCT id ORDER BY id) INTO principals FROM (
  SELECT r.requester_id AS id UNION SELECT assigned_identity_id FROM public.approval_tasks WHERE tenant_id=r.tenant_id AND request_id=r.id
  UNION SELECT owner_id FROM public.classification_rule_versions WHERE tenant_id=r.tenant_id AND rule_id::text=r.payload#>>'{evidence,rule,id}' AND version::text=r.payload#>>'{evidence,rule,version}'
 ) p;
 FOR principal IN SELECT id FROM public.identities WHERE id=ANY(principals) ORDER BY id FOR SHARE LOOP NULL;END LOOP;
 FOR principal IN SELECT identity_id FROM public.memberships WHERE tenant_id=r.tenant_id AND identity_id=ANY(principals) ORDER BY identity_id FOR SHARE LOOP NULL;END LOOP;
 PERFORM 1 FROM public.assets WHERE tenant_id=r.tenant_id AND id=r.resource_id FOR SHARE;
 RETURN r;
END $$;
CREATE FUNCTION public.gc_classification_review_authorized(r public.approval_requests) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT r.binding='classification.review' AND r.tenant_id=public.gc_tenant() AND public.gc_classification_actor_can(r.resource_id,r.requester_id,'classification:write')
 AND NOT EXISTS(SELECT 1 FROM public.approval_tasks t WHERE t.tenant_id=r.tenant_id AND t.request_id=r.id AND (t.assigned_identity_id=r.requester_id OR NOT public.gc_classification_actor_can(r.resource_id,t.assigned_identity_id,'classification:approve')));
$$;
CREATE OR REPLACE FUNCTION public.gc_approval_command(operation text,command_key text,body jsonb,correlation text) RETURNS jsonb
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
 SELECT * INTO old FROM public.idempotency WHERE tenant_id=tenant AND actor_id=actor::text AND idempotency.operation=gc_approval_command.operation AND key=command_key;
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
CREATE OR REPLACE FUNCTION public.gc_approval_tick(request_identity uuid) RETURNS jsonb
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
CREATE FUNCTION public.gc_classification_publish(request_identity uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE r public.approval_requests;w jsonb;e public.classification_evaluations;a public.classification_assignments;expected integer;stamp timestamptz;state text;publication_result jsonb;BEGIN
 r:=public.gc_classification_lock_review(request_identity);
 PERFORM public.gc_relation_authorize(ARRAY['catalog:read','classification:read','classification:write']);
 IF public.gc_actor() IS DISTINCT FROM r.requester_id::text OR NOT public.gc_classification_review_authorized(r) THEN RAISE EXCEPTION 'classification forbidden' USING ERRCODE='42501';END IF;
 IF r.status='succeeded' THEN RETURN r.result;END IF;
 IF r.status<>'ready' THEN RAISE EXCEPTION 'classification version conflict' USING ERRCODE='40001';END IF;
 stamp:=date_trunc('milliseconds',clock_timestamp());IF r.expires_at<=stamp THEN RAISE EXCEPTION 'classification approval expired' USING ERRCODE='40001';END IF;
 SELECT v.definition INTO w FROM public.workflow_definition_versions v
 WHERE v.tenant_id=r.tenant_id AND v.workflow_id=r.workflow_id AND v.version=r.workflow_version AND v.definition_hash=r.workflow_hash;
 IF w IS NULL THEN RAISE EXCEPTION 'classification pin stale' USING ERRCODE='40001';END IF;
 IF w->>'separationOfDuties'<>'true' OR EXISTS(SELECT 1 FROM public.approval_decisions WHERE tenant_id=r.tenant_id AND request_id=r.id AND decision='reject')
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(w->'stages') WITH ORDINALITY s(v,n) WHERE (SELECT count(*) FROM public.approval_decisions d JOIN public.approval_tasks t ON t.tenant_id=d.tenant_id AND t.id=d.task_id
 WHERE d.tenant_id=r.tenant_id AND d.request_id=r.id AND t.stage_index=s.n-1 AND d.decision='approve' AND d.actor_id=t.assigned_identity_id AND d.actor_id<>r.requester_id AND d.proposal_digest=r.proposal_digest)<(s.v->>'quorum')::integer)
 THEN RAISE EXCEPTION 'classification approval invalid' USING ERRCODE='23514';END IF;
 IF NOT public.gc_classification_payload_current(r.payload) THEN RAISE EXCEPTION 'classification evidence stale' USING ERRCODE='40001';END IF;
 SELECT * INTO e FROM public.classification_evaluations WHERE tenant_id=r.tenant_id AND id=(r.payload->>'suggestionId')::uuid;
 expected:=(r.payload->>'expectedAssignmentVersion')::integer;state:=CASE WHEN r.payload->>'change'='apply' THEN 'active' ELSE 'withdrawn' END;
 IF expected=0 THEN
  INSERT INTO public.classification_assignments VALUES(r.tenant_id,(r.payload->>'assignmentId')::uuid,r.resource_id,(r.payload#>>'{label,taxonomy,id}')::uuid,r.payload#>>'{label,labelKey}',1,state,r.requester_id,stamp) RETURNING * INTO a;
 ELSE
  UPDATE public.classification_assignments SET version=version+1,status=state WHERE tenant_id=r.tenant_id AND id=(r.payload->>'assignmentId')::uuid AND version=expected RETURNING * INTO a;
 END IF;
 IF a.id IS NULL THEN RAISE EXCEPTION 'classification version conflict' USING ERRCODE='40001';END IF;
 INSERT INTO public.classification_assignment_revisions VALUES(r.tenant_id,a.id,a.version,state,e.id,r.id,CASE WHEN state='withdrawn' THEN r.payload->>'reason' END,r.requester_id,stamp);
 publication_result:=jsonb_build_object('binding','classification.review','assetId',r.resource_id,'assignmentId',a.id,'assignmentVersion',a.version,'status',state,'evidenceHash',e.evidence_hash);
 UPDATE public.approval_requests SET status='succeeded',version=version+1,result=publication_result,updated_at=stamp WHERE tenant_id=r.tenant_id AND id=r.id;
 PERFORM public.gc_approval_journal(CASE WHEN state='active' THEN 'classification.applied' ELSE 'classification.withdrawn' END,NULL,r.resource_id::text,(SELECT version FROM public.assets WHERE tenant_id=r.tenant_id AND id=r.resource_id),
 jsonb_build_object('assignmentId',a.id,'assignmentVersion',a.version,'approvalInstanceId',r.id,'evidenceHash',e.evidence_hash,'suggestionId',e.id),'classification:'||r.id::text);
 PERFORM public.gc_approval_journal('approval.succeeded',NULL,r.id::text,r.version+1,jsonb_build_object('binding','classification.review','assignmentId',a.id,'assignmentVersion',a.version,'proposalDigest',r.proposal_digest),'classification:'||r.id::text);
 RETURN publication_result;
END $$;
CREATE FUNCTION public.gc_classification_fail(request_identity uuid,ready_version integer,code text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE r public.approval_requests;BEGIN
 IF public.gc_actor() IS DISTINCT FROM 'site:local' OR code IS NULL OR code NOT IN('CLASSIFICATION_AUTHORITY_REVOKED','CLASSIFICATION_PRECONDITIONS_CHANGED','CLASSIFICATION_EXPIRED','CLASSIFICATION_APPROVAL_INVALID') THEN RAISE EXCEPTION 'classification forbidden' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(public.gc_tenant()::text,0));
 SELECT * INTO r FROM public.approval_requests WHERE tenant_id=public.gc_tenant() AND id=request_identity AND binding='classification.review' AND status='ready' AND version=ready_version;
 IF NOT FOUND THEN RETURN;END IF;
 UPDATE public.approval_requests SET status='failed',version=version+1,error_code=code,updated_at=date_trunc('milliseconds',clock_timestamp()) WHERE tenant_id=r.tenant_id AND id=r.id;
 PERFORM public.gc_approval_journal('approval.failed',NULL,r.id::text,r.version+1,jsonb_build_object('code',code,'proposalDigest',r.proposal_digest),'classification:'||r.id::text);
END $$;
CREATE FUNCTION public.gc_classification_namespace_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$ DECLARE protected boolean;BEGIN
 IF TG_TABLE_NAME='idempotency' THEN protected:=(CASE WHEN TG_OP='DELETE' THEN OLD.operation ELSE NEW.operation END) LIKE 'classification.%' OR (TG_OP='UPDATE' AND OLD.operation LIKE 'classification.%');
 ELSIF TG_TABLE_NAME='audit' THEN protected:=(CASE WHEN TG_OP='DELETE' THEN OLD.action ELSE NEW.action END) LIKE 'classification.%';
 ELSE protected:=(CASE WHEN TG_OP='DELETE' THEN OLD.event_type ELSE NEW.event_type END) LIKE 'classification.%' OR (TG_OP='UPDATE' AND OLD.event_type LIKE 'classification.%');END IF;
 IF TG_TABLE_NAME='outbox' AND TG_OP='UPDATE' THEN
  IF protected AND (to_jsonb(NEW)-ARRAY['processed_at','attempts'])=(to_jsonb(OLD)-ARRAY['processed_at','attempts']) AND NEW.attempts>=OLD.attempts THEN RETURN NEW;END IF;
 END IF;
 IF protected AND current_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.classification_evaluations'::regclass) THEN RAISE EXCEPTION 'classification forbidden' USING ERRCODE='42501';END IF;
 IF TG_OP='DELETE' THEN RETURN OLD;END IF;RETURN NEW;
END $$;
CREATE TRIGGER classification_namespace_guard BEFORE INSERT OR UPDATE OR DELETE ON public.idempotency FOR EACH ROW EXECUTE FUNCTION public.gc_classification_namespace_guard();
CREATE TRIGGER classification_namespace_guard BEFORE INSERT ON public.audit FOR EACH ROW EXECUTE FUNCTION public.gc_classification_namespace_guard();
CREATE TRIGGER classification_namespace_guard BEFORE INSERT OR UPDATE OR DELETE ON public.outbox FOR EACH ROW EXECUTE FUNCTION public.gc_classification_namespace_guard();

REVOKE ALL ON FUNCTION public.gc_classification_text(jsonb,integer,text),
 public.gc_classification_pin_valid(jsonb),
 public.gc_classification_taxonomy_normalize(jsonb),
 public.gc_classification_taxonomy_valid(jsonb),
 public.gc_classification_rule_normalize(jsonb),
 public.gc_classification_rule_valid(jsonb),
 public.gc_classification_asset_valid(jsonb),
 public.gc_classification_input_digest(jsonb,jsonb),
 public.gc_classification_evaluate(jsonb,jsonb,jsonb,timestamptz),
 public.gc_classification_head_guard(),
 public.gc_classification_visible(uuid,uuid),
 public.gc_classification_actor_can(uuid,uuid,text),
 public.gc_classification_asset_input(uuid),
 public.gc_classification_taxonomy_view(uuid,integer),
 public.gc_classification_rule_view(uuid,integer),
 public.gc_classification_evidence_current(uuid),
 public.gc_classification_suggestion_view(uuid,uuid),
 public.gc_classification_assignment_view(uuid,uuid),
 public.gc_classification_label_current(jsonb),
 public.gc_classification_payload_current(jsonb),
 public.gc_classification_propose(jsonb,text),
 public.gc_classification_command(text,text,jsonb,text),
 public.gc_approval_command_glossary_legacy(text,text,jsonb,text),
 public.gc_approval_tick_glossary_legacy(uuid),
 public.gc_classification_lock_review(uuid),
 public.gc_classification_review_authorized(public.approval_requests),
 public.gc_approval_command(text,text,jsonb,text),
 public.gc_approval_tick(uuid),
 public.gc_classification_publish(uuid),
 public.gc_classification_fail(uuid,integer,text),
 public.gc_classification_namespace_guard() FROM PUBLIC,gc_app;
GRANT EXECUTE ON FUNCTION public.gc_classification_visible(uuid,uuid),public.gc_classification_taxonomy_view(uuid,integer),public.gc_classification_rule_view(uuid,integer),public.gc_classification_assignment_view(uuid,uuid),public.gc_classification_suggestion_view(uuid,uuid),public.gc_classification_payload_current(jsonb),public.gc_classification_command(text,text,jsonb,text),public.gc_approval_command(text,text,jsonb,text),public.gc_approval_tick(uuid),public.gc_classification_publish(uuid),public.gc_classification_fail(uuid,integer,text) TO gc_app;
