-- SPDX-License-Identifier: Apache-2.0
-- Immutable reviewed hierarchies and crosswalks pin exact code-list releases.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname=current_user AND (rolsuper OR rolbypassrls)) OR pg_has_role('gc_app',current_user,'MEMBER') THEN
  RAISE EXCEPTION 'reference structure forbidden' USING ERRCODE='42501'; END IF;
END $$;

CREATE FUNCTION public.gc_reference_structure_pin(value jsonb) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT coalesce(public.gc_relation_keys(value,ARRAY['setId','version','publicationHash'])
 AND public.gc_reference_uuid(value->'setId') AND public.gc_relation_positive_integer(value->'version')
 AND jsonb_typeof(value->'publicationHash')='string' AND value->>'publicationHash' ~ '^[a-f0-9]{64}$',false)
$$;
CREATE FUNCTION public.gc_reference_structure_release_normalize(value jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE item jsonb; entries jsonb:='[]'; labels jsonb; result jsonb; keys text[]; family text;
 method_details text; notes text; basis text; confidence jsonb; amount numeric;
BEGIN
 family:=value->>'kind';
 keys:=ARRAY['formatVersion','kind','labels','ownerId','status','activation','validUntil'];
 IF family='reference-hierarchy' THEN keys:=keys||ARRAY['reference','multiParent','edges'];
 ELSIF family='reference-crosswalk' THEN keys:=keys||ARRAY['source','target','cardinality','overlapPolicy','mappings'];
 ELSE RETURN NULL; END IF;
 IF public.gc_relation_keys(value,keys) IS NOT TRUE OR value->'formatVersion' IS DISTINCT FROM '1'::jsonb
 OR NOT public.gc_reference_uuid(value->'ownerId') OR jsonb_typeof(value->'status') IS DISTINCT FROM 'string'
 OR value->>'status' NOT IN('active','deprecated') OR NOT public.gc_reference_instant(value->'validUntil',true)
 OR octet_length(public.gc_type_migration_canonical(value))>245760 THEN RETURN NULL; END IF;
 labels:=public.gc_reference_labels(value->'labels');IF labels IS NULL THEN RETURN NULL; END IF;
 IF value#>>'{activation,kind}'='on-publication' THEN
  IF public.gc_relation_keys(value->'activation',ARRAY['kind']) IS NOT TRUE THEN RETURN NULL; END IF;
 ELSIF value#>>'{activation,kind}'='at' THEN
  IF public.gc_relation_keys(value->'activation',ARRAY['kind','at']) IS NOT TRUE OR NOT public.gc_reference_instant(value#>'{activation,at}')
  OR (value->'validUntil'<>'null'::jsonb AND (value->>'validUntil')::timestamptz<=(value#>>'{activation,at}')::timestamptz) THEN RETURN NULL; END IF;
 ELSE RETURN NULL; END IF;
 IF family='reference-hierarchy' THEN
  IF NOT public.gc_reference_structure_pin(value->'reference') OR value->>'multiParent' NOT IN('forbid','allow')
  OR jsonb_typeof(value->'multiParent') IS DISTINCT FROM 'string' OR jsonb_typeof(value->'edges') IS DISTINCT FROM 'array' THEN RETURN NULL; END IF;
  entries:=value->'edges';
 ELSE
  IF NOT public.gc_reference_structure_pin(value->'source') OR NOT public.gc_reference_structure_pin(value->'target')
  OR value#>>'{source,setId}'=value#>>'{target,setId}' OR value->'cardinality' IS DISTINCT FROM '"many-to-many"'::jsonb
  OR value->'overlapPolicy' IS DISTINCT FROM '"reject-overlapping-pair"'::jsonb
  OR jsonb_typeof(value->'mappings') IS DISTINCT FROM 'array' THEN RETURN NULL; END IF;
  entries:=value->'mappings';
 END IF;
 IF jsonb_array_length(entries)>256 THEN RETURN NULL; END IF;
 result:='[]';
 FOR item IN SELECT x FROM jsonb_array_elements(entries) x LOOP
  IF NOT public.gc_reference_instant(item->'validFrom',true) OR NOT public.gc_reference_instant(item->'validUntil',true)
  OR (item->'validFrom'<>'null'::jsonb AND item->'validUntil'<>'null'::jsonb AND (item->>'validFrom')::timestamptz>=(item->>'validUntil')::timestamptz) THEN RETURN NULL; END IF;
  IF family='reference-hierarchy' THEN
   IF public.gc_relation_keys(item,ARRAY['parentCode','childCode','validFrom','validUntil']) IS NOT TRUE
   OR jsonb_typeof(item->'parentCode') IS DISTINCT FROM 'string' OR jsonb_typeof(item->'childCode') IS DISTINCT FROM 'string'
   OR (item->>'parentCode') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
   OR (item->>'childCode') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
   OR item->>'parentCode'=item->>'childCode' THEN RETURN NULL; END IF;
  ELSE
   IF public.gc_relation_keys(item,ARRAY['sourceCode','targetCode','validFrom','validUntil','relation','method','methodDetails','transformationNotes','confidence']) IS NOT TRUE
   OR jsonb_typeof(item->'sourceCode') IS DISTINCT FROM 'string' OR jsonb_typeof(item->'targetCode') IS DISTINCT FROM 'string'
   OR (item->>'sourceCode') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
   OR (item->>'targetCode') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
   OR jsonb_typeof(item->'relation') IS DISTINCT FROM 'string' OR item->>'relation' NOT IN('equivalent','source-broader','source-narrower','related')
   OR jsonb_typeof(item->'method') IS DISTINCT FROM 'string' OR item->>'method' NOT IN('steward-asserted','source-reported','rule-described') THEN RETURN NULL; END IF;
   method_details:=public.gc_classification_text(item->'methodDetails',512,'multiline');
   notes:=public.gc_classification_text(item->'transformationNotes',2048,'multiline');
   IF method_details IS NULL OR notes IS NULL THEN RETURN NULL; END IF;
   confidence:=item->'confidence';
   IF confidence->>'kind'='not-assessed' THEN
    IF public.gc_relation_keys(confidence,ARRAY['kind']) IS NOT TRUE THEN RETURN NULL; END IF;
   ELSIF confidence->>'kind'='declared' THEN
    IF public.gc_relation_keys(confidence,ARRAY['kind','basisPoints','basis']) IS NOT TRUE
    OR jsonb_typeof(confidence->'basisPoints') IS DISTINCT FROM 'number' THEN RETURN NULL; END IF;
    amount:=(confidence->>'basisPoints')::numeric;basis:=public.gc_classification_text(confidence->'basis',1024,'multiline');
    IF amount<0 OR amount>10000 OR amount<>trunc(amount) OR basis IS NULL THEN RETURN NULL; END IF;
    confidence:=confidence||jsonb_build_object('basis',basis);
   ELSE RETURN NULL; END IF;
   item:=item||jsonb_build_object('methodDetails',method_details,'transformationNotes',notes,'confidence',confidence);
  END IF;
  result:=result||jsonb_build_array(item);
 END LOOP;
 -- Canonical rows preserve half-open interval boundaries; temporal overlap and
 -- endpoint coverage are validated against the actual publication clock below.
 IF family='reference-hierarchy' THEN
  SELECT coalesce(jsonb_agg(x ORDER BY (x->>'parentCode') COLLATE "C",(x->>'childCode') COLLATE "C",x->>'validFrom' NULLS FIRST,x->>'validUntil' NULLS LAST),'[]') INTO result FROM jsonb_array_elements(result) x;
  result:=value||jsonb_build_object('labels',labels,'edges',result);
 ELSE
  SELECT coalesce(jsonb_agg(x ORDER BY (x->>'sourceCode') COLLATE "C",(x->>'targetCode') COLLATE "C",x->>'validFrom' NULLS FIRST,x->>'validUntil' NULLS LAST),'[]') INTO result FROM jsonb_array_elements(result) x;
  result:=value||jsonb_build_object('labels',labels,'mappings',result);
 END IF;
 IF octet_length(public.gc_type_migration_canonical(result))>245760 THEN RETURN NULL; END IF; RETURN result;
 EXCEPTION WHEN data_exception OR check_violation OR program_limit_exceeded THEN RETURN NULL;
END $$;
CREATE FUNCTION public.gc_reference_structure_payload_normalize(value jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE release jsonb;expected numeric;result jsonb;BEGIN
 IF public.gc_relation_keys(value,ARRAY['formatVersion','kind','structureId','expectedVersion','release']) IS NOT TRUE
 OR value->'formatVersion' IS DISTINCT FROM '1'::jsonb OR value->'kind' IS DISTINCT FROM '"reference-structure-publication"'::jsonb
 OR NOT public.gc_reference_uuid(value->'structureId') OR jsonb_typeof(value->'expectedVersion') IS DISTINCT FROM 'number' THEN RETURN NULL; END IF;
 expected:=(value->>'expectedVersion')::numeric;IF expected<0 OR expected>2147483646 OR expected<>trunc(expected) THEN RETURN NULL; END IF;
 release:=public.gc_reference_structure_release_normalize(value->'release');IF release IS NULL THEN RETURN NULL;END IF;
 result:=value||jsonb_build_object('release',release);IF octet_length(public.gc_type_migration_canonical(result))>262144 THEN RETURN NULL; END IF; RETURN result;
 EXCEPTION WHEN data_exception OR check_violation OR program_limit_exceeded THEN RETURN NULL;
END $$;
CREATE FUNCTION public.gc_reference_structure_bundle_valid(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE release jsonb;keys text[];BEGIN
 keys:=ARRAY['formatVersion','kind','structureId','version','labels','ownerId','status','publishedAt','effectiveFrom','validUntil'];
 IF value->>'kind'='reference-hierarchy' THEN keys:=keys||ARRAY['reference','multiParent','edges'];
 ELSIF value->>'kind'='reference-crosswalk' THEN keys:=keys||ARRAY['source','target','cardinality','overlapPolicy','mappings'];ELSE RETURN false;END IF;
 IF public.gc_relation_keys(value,keys) IS NOT TRUE OR NOT public.gc_reference_uuid(value->'structureId')
 OR NOT public.gc_relation_positive_integer(value->'version') OR NOT public.gc_reference_instant(value->'publishedAt') OR NOT public.gc_reference_instant(value->'effectiveFrom')
 OR (value->>'effectiveFrom')::timestamptz<(value->>'publishedAt')::timestamptz OR octet_length(public.gc_type_migration_canonical(value))>262144 THEN RETURN false; END IF;
 release:=(value-ARRAY['structureId','version','publishedAt','effectiveFrom'])||jsonb_build_object('activation',CASE WHEN value->'publishedAt'=value->'effectiveFrom'
 THEN jsonb_build_object('kind','on-publication') ELSE jsonb_build_object('kind','at','at',value->'effectiveFrom') END);
 RETURN public.gc_reference_structure_release_normalize(release) IS NOT NULL AND release=public.gc_reference_structure_release_normalize(release);
 EXCEPTION WHEN data_exception OR check_violation OR program_limit_exceeded THEN RETURN false;
END $$;

CREATE TABLE public.reference_structure_heads (
 tenant_id uuid NOT NULL REFERENCES public.tenants(id),id uuid NOT NULL,kind text NOT NULL,
 reference_set_id uuid,source_set_id uuid,target_set_id uuid,current_version integer NOT NULL CHECK(current_version>0),
 created_by uuid NOT NULL,created_at timestamptz NOT NULL,PRIMARY KEY(tenant_id,id),
 FOREIGN KEY(tenant_id,created_by) REFERENCES public.memberships(tenant_id,identity_id),
 FOREIGN KEY(tenant_id,reference_set_id) REFERENCES public.reference_sets(tenant_id,id),
 FOREIGN KEY(tenant_id,source_set_id) REFERENCES public.reference_sets(tenant_id,id),
 FOREIGN KEY(tenant_id,target_set_id) REFERENCES public.reference_sets(tenant_id,id),
 CHECK((kind='reference-hierarchy' AND reference_set_id IS NOT NULL AND source_set_id IS NULL AND target_set_id IS NULL)
 OR (kind='reference-crosswalk' AND reference_set_id IS NULL AND source_set_id IS NOT NULL AND target_set_id IS NOT NULL AND source_set_id<>target_set_id))
);
CREATE TABLE public.reference_structure_releases (
 tenant_id uuid NOT NULL,structure_id uuid NOT NULL,version integer NOT NULL CHECK(version>0),approval_request_id uuid NOT NULL,
 approved_payload jsonb NOT NULL,proposal_digest text NOT NULL,published_bundle jsonb NOT NULL,publication_hash text NOT NULL,
 published_at timestamptz NOT NULL,effective_from timestamptz NOT NULL,valid_until timestamptz,owner_id uuid NOT NULL,status text NOT NULL,
 reference_set_id uuid,reference_version integer,source_set_id uuid,source_version integer,target_set_id uuid,target_version integer,
 created_xid xid8 NOT NULL DEFAULT pg_current_xact_id(),PRIMARY KEY(tenant_id,structure_id,version),UNIQUE(tenant_id,approval_request_id),
 FOREIGN KEY(tenant_id,structure_id) REFERENCES public.reference_structure_heads(tenant_id,id),
 FOREIGN KEY(tenant_id,approval_request_id) REFERENCES public.approval_requests(tenant_id,id),
 FOREIGN KEY(tenant_id,owner_id) REFERENCES public.memberships(tenant_id,identity_id),
 FOREIGN KEY(tenant_id,reference_set_id,reference_version) REFERENCES public.reference_releases(tenant_id,set_id,version),
 FOREIGN KEY(tenant_id,source_set_id,source_version) REFERENCES public.reference_releases(tenant_id,set_id,version),
 FOREIGN KEY(tenant_id,target_set_id,target_version) REFERENCES public.reference_releases(tenant_id,set_id,version),
 CHECK(public.gc_reference_structure_bundle_valid(published_bundle) AND publication_hash=public.gc_type_migration_hash(published_bundle)),
 CHECK(approved_payload=public.gc_reference_structure_payload_normalize(approved_payload) AND public.gc_reference_structure_payload_normalize(approved_payload) IS NOT NULL),
 CHECK(published_bundle->>'structureId'=structure_id::text AND (published_bundle->>'version')::integer=version
 AND published_bundle->>'ownerId'=owner_id::text AND published_bundle->>'status'=status
 AND published_bundle->>'publishedAt'=public.gc_relation_utc(published_at) AND published_bundle->>'effectiveFrom'=public.gc_relation_utc(effective_from)
 AND (published_bundle->>'validUntil') IS NOT DISTINCT FROM public.gc_relation_utc(valid_until)
 AND (published_bundle#>>'{reference,setId}') IS NOT DISTINCT FROM reference_set_id::text AND (published_bundle#>>'{reference,version}')::integer IS NOT DISTINCT FROM reference_version
 AND (published_bundle#>>'{source,setId}') IS NOT DISTINCT FROM source_set_id::text AND (published_bundle#>>'{source,version}')::integer IS NOT DISTINCT FROM source_version
 AND (published_bundle#>>'{target,setId}') IS NOT DISTINCT FROM target_set_id::text AND (published_bundle#>>'{target,version}')::integer IS NOT DISTINCT FROM target_version)
);
CREATE INDEX reference_structure_effective ON public.reference_structure_releases(tenant_id,structure_id,effective_from DESC,version DESC) INCLUDE(published_at,valid_until,status,publication_hash);
ALTER TABLE public.reference_structure_heads ADD CONSTRAINT reference_structure_current_version FOREIGN KEY(tenant_id,id,current_version)
 REFERENCES public.reference_structure_releases(tenant_id,structure_id,version) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE public.reference_hierarchy_edges (
 tenant_id uuid NOT NULL,structure_id uuid NOT NULL,version integer NOT NULL,entry_index integer NOT NULL CHECK(entry_index BETWEEN 0 AND 255),
 reference_set_id uuid NOT NULL,reference_version integer NOT NULL,parent_code text COLLATE "C" NOT NULL,child_code text COLLATE "C" NOT NULL,valid_from timestamptz,valid_until timestamptz,
 PRIMARY KEY(tenant_id,structure_id,version,entry_index),FOREIGN KEY(tenant_id,structure_id,version) REFERENCES public.reference_structure_releases(tenant_id,structure_id,version),
 FOREIGN KEY(tenant_id,reference_set_id,reference_version,parent_code) REFERENCES public.reference_values(tenant_id,set_id,version,code),
 FOREIGN KEY(tenant_id,reference_set_id,reference_version,child_code) REFERENCES public.reference_values(tenant_id,set_id,version,code)
);
CREATE TABLE public.reference_crosswalk_mappings (
 tenant_id uuid NOT NULL,structure_id uuid NOT NULL,version integer NOT NULL,entry_index integer NOT NULL CHECK(entry_index BETWEEN 0 AND 255),
 source_set_id uuid NOT NULL,source_version integer NOT NULL,target_set_id uuid NOT NULL,target_version integer NOT NULL,
 source_code text COLLATE "C" NOT NULL,target_code text COLLATE "C" NOT NULL,relation text NOT NULL,method text NOT NULL,
 method_details text NOT NULL,transformation_notes text NOT NULL,confidence jsonb NOT NULL,valid_from timestamptz,valid_until timestamptz,
 PRIMARY KEY(tenant_id,structure_id,version,entry_index),FOREIGN KEY(tenant_id,structure_id,version) REFERENCES public.reference_structure_releases(tenant_id,structure_id,version),
 FOREIGN KEY(tenant_id,source_set_id,source_version,source_code) REFERENCES public.reference_values(tenant_id,set_id,version,code),
 FOREIGN KEY(tenant_id,target_set_id,target_version,target_code) REFERENCES public.reference_values(tenant_id,set_id,version,code)
);
DO $$ DECLARE name text;BEGIN
 FOREACH name IN ARRAY ARRAY['reference_structure_heads','reference_structure_releases','reference_hierarchy_edges','reference_crosswalk_mappings'] LOOP
  EXECUTE format('ALTER TABLE public.%I ENABLE ROW LEVEL SECURITY',name);EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY',name);
  EXECUTE format('CREATE POLICY tenant_isolation ON public.%I USING(tenant_id=public.gc_tenant()) WITH CHECK(tenant_id=public.gc_tenant())',name);
  EXECUTE format('REVOKE ALL ON public.%I FROM PUBLIC,gc_app',name);EXECUTE format('GRANT SELECT ON public.%I TO gc_app',name);
 END LOOP;
 FOREACH name IN ARRAY ARRAY['reference_structure_releases','reference_hierarchy_edges','reference_crosswalk_mappings'] LOOP
  EXECUTE format('CREATE TRIGGER reference_structure_immutable BEFORE UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.gc_immutable_audit()',name);
 END LOOP;
END $$;
CREATE TRIGGER reference_structure_head_guard BEFORE UPDATE OR DELETE ON public.reference_structure_heads FOR EACH ROW EXECUTE FUNCTION public.gc_classification_head_guard();

-- SPDX-License-Identifier: Apache-2.0
CREATE FUNCTION public.gc_reference_structure_endpoints(release jsonb) RETURNS uuid[]
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
 SELECT CASE WHEN release->>'kind'='reference-hierarchy' THEN ARRAY[(release#>>'{reference,setId}')::uuid]
 ELSE ARRAY(SELECT p FROM unnest(ARRAY[(release#>>'{source,setId}')::uuid,(release#>>'{target,setId}')::uuid]) p ORDER BY p) END
$$;
CREATE FUNCTION public.gc_reference_structure_actor_can(release jsonb,actor uuid,permission_name text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id
 WHERE m.tenant_id=public.gc_tenant() AND m.identity_id=actor AND m.active AND i.active
 AND m.permissions @> to_jsonb(ARRAY['catalog:read','reference:read',permission_name]))
 AND NOT EXISTS(SELECT 1 FROM unnest(public.gc_reference_structure_endpoints(release)) endpoint WHERE NOT public.gc_reference_visible(endpoint,actor))
$$;
CREATE FUNCTION public.gc_reference_structure_visible(structure_identity uuid,actor_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM public.reference_structure_heads h WHERE h.tenant_id=public.gc_tenant() AND h.id=structure_identity
 AND CASE WHEN h.kind='reference-hierarchy' THEN public.gc_reference_visible(h.reference_set_id,actor_identity)
 ELSE public.gc_reference_visible(h.source_set_id,actor_identity) AND public.gc_reference_visible(h.target_set_id,actor_identity) END)
$$;
CREATE FUNCTION public.gc_reference_structure_request_visible(request_identity uuid,actor_identity uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT EXISTS(SELECT 1 FROM public.approval_requests r WHERE r.tenant_id=public.gc_tenant() AND r.id=request_identity
 AND r.binding='reference.structure.publish' AND public.gc_reference_structure_actor_can(r.payload->'release',actor_identity,'reference:read'))
$$;
CREATE FUNCTION public.gc_reference_structure_authorize(actor uuid,write_required boolean) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$ BEGIN
 IF public.gc_actor() IS DISTINCT FROM actor::text OR write_required IS NULL THEN RAISE EXCEPTION 'reference structure forbidden' USING ERRCODE='42501'; END IF;
 PERFORM public.gc_lock_type_migration_principals(ARRAY[]::uuid[]);
 IF NOT EXISTS(SELECT 1 FROM public.memberships m JOIN public.identities i ON i.id=m.identity_id
 WHERE m.tenant_id=public.gc_tenant() AND m.identity_id=actor AND m.active AND i.active
 AND m.permissions @> CASE WHEN write_required THEN '["catalog:read","reference:read","reference:write"]'::jsonb ELSE '["catalog:read","reference:read"]'::jsonb END)
 THEN RAISE EXCEPTION 'reference structure forbidden' USING ERRCODE='42501';END IF;
END $$;

-- Validate bounded half-open interval rows and a temporal DAG. Kahn's algorithm
-- uses fixed arrays, never unbounded recursive path enumeration.
CREATE FUNCTION public.gc_reference_structure_temporal_valid(release jsonb,start_at timestamptz,end_at timestamptz) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE entries jsonb;left_key text;right_key text;item jsonb;nodes text[];froms timestamptz[]:='{}';untils timestamptz[]:='{}';
 parents integer[]:='{}';children integer[]:='{}';points timestamptz[];point timestamptz;starts timestamptz;ends timestamptz;
 active boolean[];degrees integer[];depths integer[];queue integer[];position integer;vertex integer;i integer;j integer;n integer;count_rows integer;
BEGIN
 IF start_at IS NULL OR (end_at IS NOT NULL AND end_at<=start_at) THEN RETURN false;END IF;
 IF release->>'kind'='reference-hierarchy' THEN entries:=release->'edges';left_key:='parentCode';right_key:='childCode';
 ELSE entries:=release->'mappings';left_key:='sourceCode';right_key:='targetCode';END IF;
 count_rows:=jsonb_array_length(entries);IF count_rows>256 THEN RETURN false;END IF;
 SELECT array_agg(code ORDER BY code COLLATE "C") INTO nodes FROM
 (SELECT DISTINCT x->>left_key code FROM jsonb_array_elements(entries) x UNION SELECT DISTINCT x->>right_key FROM jsonb_array_elements(entries) x) p;
 n:=coalesce(cardinality(nodes),0);IF release->>'kind'='reference-hierarchy' AND n>256 THEN RETURN false;END IF;
 FOR item IN SELECT x FROM jsonb_array_elements(entries) x LOOP
  starts:=coalesce((item->>'validFrom')::timestamptz,start_at);ends:=coalesce((item->>'validUntil')::timestamptz,end_at);
  IF starts<start_at OR (ends IS NOT NULL AND ends<=starts) OR (end_at IS NOT NULL AND (ends IS NULL OR ends>end_at)) THEN RETURN false;END IF;
  froms:=array_append(froms,starts);untils:=array_append(untils,ends);
  parents:=array_append(parents,array_position(nodes,item->>left_key));children:=array_append(children,array_position(nodes,item->>right_key));
 END LOOP;
 -- Duplicate ordered pairs with overlapping intervals are always refused.
 FOR i IN 1..count_rows LOOP FOR j IN i+1..count_rows LOOP
  IF parents[i]=parents[j] AND children[i]=children[j]
  AND (untils[j] IS NULL OR froms[i]<untils[j]) AND (untils[i] IS NULL OR froms[j]<untils[i]) THEN RETURN false;END IF;
 END LOOP;END LOOP;
 IF release->>'kind'<>'reference-hierarchy' OR count_rows=0 THEN RETURN true;END IF;
 SELECT array_agg(p ORDER BY p) INTO points FROM (SELECT DISTINCT unnest(froms) p UNION SELECT DISTINCT p FROM unnest(untils) p WHERE p IS NOT NULL) boundaries;
 IF cardinality(points)>514 THEN RETURN false;END IF;
 FOREACH point IN ARRAY points LOOP
  IF end_at IS NOT NULL AND point>=end_at THEN CONTINUE;END IF;
  degrees:=array_fill(0,ARRAY[n]);depths:=array_fill(1,ARRAY[n]);active:=array_fill(false,ARRAY[count_rows]);queue:='{}';
  FOR i IN 1..count_rows LOOP
   active[i]:=froms[i]<=point AND (untils[i] IS NULL OR point<untils[i]);
   IF active[i] THEN degrees[children[i]]:=degrees[children[i]]+1;END IF;
  END LOOP;
  FOR i IN 1..n LOOP
   IF release->>'multiParent'='forbid' AND degrees[i]>1 THEN RETURN false;END IF;
   IF degrees[i]=0 THEN queue:=array_append(queue,i);END IF;
  END LOOP;
  position:=1;
  WHILE position<=cardinality(queue) LOOP
   vertex:=queue[position];position:=position+1;
   FOR i IN 1..count_rows LOOP
    IF active[i] AND parents[i]=vertex THEN
     depths[children[i]]:=greatest(depths[children[i]],depths[vertex]+1);IF depths[children[i]]>256 THEN RETURN false;END IF;
     degrees[children[i]]:=degrees[children[i]]-1;
     IF degrees[children[i]]=0 THEN queue:=array_append(queue,children[i]);END IF;
    END IF;
   END LOOP;
  END LOOP;
  IF cardinality(queue)<>n THEN RETURN false;END IF;
 END LOOP;RETURN true;
 EXCEPTION WHEN data_exception OR check_violation OR program_limit_exceeded THEN RETURN false;
END $$;

-- Caller holds every endpoint head lock. Published bytes stay immutable if a
-- later endpoint successor creates an effective-read gap.
CREATE FUNCTION public.gc_reference_structure_endpoints_valid(release jsonb,start_at timestamptz,end_at timestamptz) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE role text;pin jsonb;r public.reference_releases;boundary timestamptz;item jsonb;entry_start timestamptz;entry_end timestamptz;codes text[];code_value text;v public.reference_values;
BEGIN
 FOREACH role IN ARRAY CASE WHEN release->>'kind'='reference-hierarchy' THEN ARRAY['reference'] ELSE ARRAY['source','target'] END LOOP
  pin:=release->role;
  SELECT * INTO r FROM public.reference_releases WHERE tenant_id=public.gc_tenant() AND set_id=(pin->>'setId')::uuid AND version=(pin->>'version')::integer;
  IF r.set_id IS NULL OR r.publication_hash IS DISTINCT FROM pin->>'publicationHash' OR r.status<>'active' OR start_at<r.effective_from THEN RETURN false;END IF;
  SELECT least(r.valid_until,min(effective_from)) INTO boundary FROM public.reference_releases WHERE tenant_id=r.tenant_id AND set_id=r.set_id AND version>r.version;
  IF boundary IS NOT NULL AND (end_at IS NULL OR end_at>boundary OR start_at>=boundary) THEN RETURN false;END IF;
  FOR item IN SELECT x FROM jsonb_array_elements(CASE WHEN role='reference' THEN release->'edges' ELSE release->'mappings' END) x LOOP
   entry_start:=coalesce((item->>'validFrom')::timestamptz,start_at);entry_end:=coalesce((item->>'validUntil')::timestamptz,end_at);
   codes:=CASE WHEN role='reference' THEN ARRAY[item->>'parentCode',item->>'childCode'] WHEN role='source' THEN ARRAY[item->>'sourceCode'] ELSE ARRAY[item->>'targetCode'] END;
   FOREACH code_value IN ARRAY codes LOOP
    SELECT * INTO v FROM public.reference_values WHERE tenant_id=r.tenant_id AND set_id=r.set_id AND version=r.version AND reference_values.code=code_value;
    IF v.set_id IS NULL OR v.status<>'active' OR (v.valid_from IS NOT NULL AND entry_start<v.valid_from)
    OR (v.valid_until IS NOT NULL AND (entry_end IS NULL OR entry_end>v.valid_until)) THEN RETURN false;END IF;
   END LOOP;
  END LOOP;
 END LOOP;
 RETURN public.gc_reference_structure_temporal_valid(release,start_at,end_at);
 EXCEPTION WHEN data_exception OR check_violation OR program_limit_exceeded THEN RETURN false;
END $$;

-- SPDX-License-Identifier: Apache-2.0
CREATE FUNCTION public.gc_reference_structure_payload_current(value jsonb) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE h public.reference_structure_heads;release jsonb;start_at timestamptz;end_at timestamptz;BEGIN
 IF public.gc_reference_structure_payload_normalize(value) IS NULL OR value IS DISTINCT FROM public.gc_reference_structure_payload_normalize(value) THEN RETURN false;END IF;
 release:=value->'release';
 SELECT * INTO h FROM public.reference_structure_heads WHERE tenant_id=public.gc_tenant() AND id=(value->>'structureId')::uuid;
 IF coalesce(h.current_version,0)<>(value->>'expectedVersion')::integer THEN RETURN false;END IF;
 IF h.id IS NOT NULL AND (h.kind<>release->>'kind'
 OR h.reference_set_id IS DISTINCT FROM (release#>>'{reference,setId}')::uuid
 OR h.source_set_id IS DISTINCT FROM (release#>>'{source,setId}')::uuid
 OR h.target_set_id IS DISTINCT FROM (release#>>'{target,setId}')::uuid) THEN RETURN false;END IF;
 IF NOT public.gc_reference_structure_actor_can(release,(release->>'ownerId')::uuid,'reference:read') THEN RETURN false;END IF;
 start_at:=CASE WHEN release#>>'{activation,kind}'='on-publication' THEN date_trunc('milliseconds',clock_timestamp()) ELSE (release#>>'{activation,at}')::timestamptz END;
 end_at:=(release->>'validUntil')::timestamptz;
 RETURN public.gc_reference_structure_endpoints_valid(release,start_at,end_at);
 EXCEPTION WHEN data_exception OR check_violation OR program_limit_exceeded THEN RETURN false;
END $$;
CREATE FUNCTION public.gc_reference_structure_lock_review(request_identity uuid) RETURNS public.approval_requests
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE r public.approval_requests;principal uuid;principals uuid[];endpoint uuid;BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(public.gc_tenant()::text,0));
 SELECT * INTO r FROM public.approval_requests WHERE tenant_id=public.gc_tenant() AND id=request_identity AND binding='reference.structure.publish';
 IF NOT FOUND THEN RAISE EXCEPTION 'reference structure resource not found' USING ERRCODE='P0002';END IF;
 SELECT array_agg(DISTINCT id ORDER BY id) INTO principals FROM (
  SELECT r.requester_id id UNION SELECT assigned_identity_id FROM public.approval_tasks WHERE tenant_id=r.tenant_id AND request_id=r.id
  UNION SELECT (r.payload#>>'{release,ownerId}')::uuid
  UNION SELECT CASE WHEN public.gc_approval_uuid(public.gc_actor()) THEN public.gc_actor()::uuid END) p WHERE id IS NOT NULL;
 IF cardinality(principals)>67 THEN RAISE EXCEPTION 'reference structure limit' USING ERRCODE='54000';END IF;
 FOR principal IN SELECT id FROM public.identities WHERE id=ANY(principals) ORDER BY id FOR SHARE LOOP NULL;END LOOP;
 FOR principal IN SELECT identity_id FROM public.memberships WHERE tenant_id=r.tenant_id AND identity_id=ANY(principals) ORDER BY identity_id FOR SHARE LOOP NULL;END LOOP;
 FOR endpoint IN SELECT id FROM public.reference_sets WHERE tenant_id=r.tenant_id AND id=ANY(public.gc_reference_structure_endpoints(r.payload->'release')) ORDER BY id FOR UPDATE LOOP NULL;END LOOP;
 PERFORM 1 FROM public.reference_structure_heads WHERE tenant_id=r.tenant_id AND id=r.resource_id FOR UPDATE;
 PERFORM 1 FROM public.approval_requests WHERE tenant_id=r.tenant_id AND id=r.id FOR UPDATE;
 RETURN r;
END $$;
CREATE FUNCTION public.gc_reference_structure_review_authorized(r public.approval_requests) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
 SELECT r.binding='reference.structure.publish' AND r.tenant_id=public.gc_tenant()
 AND public.gc_reference_structure_actor_can(r.payload->'release',r.requester_id,'reference:write')
 AND public.gc_reference_structure_actor_can(r.payload->'release',(r.payload#>>'{release,ownerId}')::uuid,'reference:read')
 AND NOT EXISTS(SELECT 1 FROM public.approval_tasks t WHERE t.tenant_id=r.tenant_id AND t.request_id=r.id
 AND (t.assigned_identity_id=r.requester_id OR NOT public.gc_reference_structure_actor_can(r.payload->'release',t.assigned_identity_id,'reference:approve')))
$$;

ALTER TABLE public.approval_requests DROP CONSTRAINT approval_requests_binding_check;
ALTER TABLE public.approval_requests ADD CONSTRAINT approval_requests_binding_check CHECK(binding IN('glossary.publish','classification.review','reference.publish','reference.structure.publish'));

CREATE FUNCTION public.gc_reference_structure_command(operation text,command_key text,body jsonb,correlation text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant(); actor uuid; old public.idempotency; payload jsonb; normalized jsonb; w public.workflow_definition_versions;
 h public.reference_structure_heads; keys text[]; reviewers uuid[]; principals uuid[]; stage jsonb; assignment text; stamp timestamptz; expiry timestamptz;
 request_id uuid; hash text; result jsonb; BEGIN
 IF operation IS DISTINCT FROM 'reference.structure.propose' OR command_key IS NULL OR length(command_key) NOT BETWEEN 8 AND 128 OR command_key ~ '[[:cntrl:]]'
 OR correlation IS NULL OR length(correlation) NOT BETWEEN 1 AND 128 OR correlation ~ '[[:cntrl:]]'
 OR public.gc_relation_keys(body,ARRAY['id','structureId','expectedVersion','release','workflow','assignments','expiresAt']) IS NOT TRUE
 OR octet_length(public.gc_type_migration_canonical(body))>327680 OR NOT public.gc_reference_uuid(body->'id')
 OR public.gc_relation_keys(body->'workflow',ARRAY['id','version','definitionHash']) IS NOT TRUE
 OR jsonb_typeof(body#>'{workflow,id}') IS DISTINCT FROM 'string' OR NOT public.gc_relation_safe_id(body#>>'{workflow,id}')
 OR NOT public.gc_relation_positive_integer(body#>'{workflow,version}') OR jsonb_typeof(body#>'{workflow,definitionHash}') IS DISTINCT FROM 'string'
 OR body#>>'{workflow,definitionHash}' !~ '^[a-f0-9]{64}$' OR jsonb_typeof(body->'assignments') IS DISTINCT FROM 'object'
 OR NOT public.gc_reference_instant(body->'expiresAt') THEN RAISE EXCEPTION 'reference structure request invalid' USING ERRCODE='22023'; END IF;
 payload:=public.gc_reference_structure_payload_normalize(jsonb_build_object('formatVersion',1,'kind','reference-structure-publication','structureId',body->'structureId','expectedVersion',body->'expectedVersion','release',body->'release'));
 IF payload IS NULL OR (SELECT count(*) FROM jsonb_object_keys(body->'assignments')) NOT BETWEEN 1 AND 64
 OR EXISTS(SELECT 1 FROM jsonb_each(body->'assignments') a WHERE NOT public.gc_relation_safe_id(a.key) OR NOT public.gc_reference_uuid(a.value)) THEN RAISE EXCEPTION 'reference structure request invalid' USING ERRCODE='22023'; END IF;
 normalized:=body||jsonb_build_object('release',payload->'release');
 PERFORM public.gc_relation_authorize(ARRAY['catalog:read','reference:read','reference:write']);actor:=public.gc_actor()::uuid;
 IF NOT public.gc_reference_structure_actor_can(payload->'release',actor,'reference:write') THEN RAISE EXCEPTION 'reference structure forbidden' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text||actor::text||operation||command_key,0));
 hash:=public.gc_type_migration_hash(normalized);
 SELECT * INTO old FROM public.idempotency WHERE tenant_id=tenant AND actor_id=actor::text AND idempotency.operation=gc_reference_structure_command.operation AND key=command_key;
 IF FOUND THEN
  PERFORM public.gc_lock_type_migration_principals(ARRAY[]::uuid[]);PERFORM public.gc_relation_authorize(ARRAY['catalog:read','reference:read','reference:write']);
  IF NOT public.gc_reference_structure_request_visible((body->>'id')::uuid,actor) OR NOT EXISTS(SELECT 1 FROM public.approval_requests WHERE tenant_id=tenant AND id=(body->>'id')::uuid AND requester_id=actor) THEN RAISE EXCEPTION 'reference structure resource not found' USING ERRCODE='P0002';END IF;
  IF old.request_hash<>hash THEN RAISE EXCEPTION 'IDEMPOTENCY_CONFLICT' USING ERRCODE='40001';END IF; RETURN old.response;
 END IF;
 IF EXISTS(SELECT 1 FROM public.reference_structure_heads WHERE tenant_id=tenant AND id=(payload->>'structureId')::uuid) AND NOT public.gc_reference_structure_visible((payload->>'structureId')::uuid,actor) THEN RAISE EXCEPTION 'reference structure resource not found' USING ERRCODE='P0002';END IF;
 SELECT v.* INTO w FROM public.workflow_definition_versions v JOIN public.workflow_definitions head ON head.tenant_id=v.tenant_id AND head.id=v.workflow_id AND head.current_version=v.version
 WHERE v.tenant_id=tenant AND v.workflow_id=body#>>'{workflow,id}' AND v.version=(body#>>'{workflow,version}')::integer AND v.definition_hash=body#>>'{workflow,definitionHash}';
 IF NOT FOUND THEN RAISE EXCEPTION 'WORKFLOW_PIN_STALE' USING ERRCODE='40001';END IF;
 IF w.definition->>'separationOfDuties'<>'true' THEN RAISE EXCEPTION 'reference structure request invalid' USING ERRCODE='22023';END IF;
 SELECT array_agg(DISTINCT a#>>'{}' ORDER BY a#>>'{}') INTO keys FROM jsonb_array_elements(w.definition->'stages') s CROSS JOIN LATERAL jsonb_array_elements(s->'assignments') a;
 IF (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(body->'assignments') k) IS DISTINCT FROM keys THEN RAISE EXCEPTION 'reference structure request invalid' USING ERRCODE='22023';END IF;
 SELECT array_agg(DISTINCT (a.value#>>'{}')::uuid ORDER BY (a.value#>>'{}')::uuid) INTO reviewers FROM jsonb_each(body->'assignments') a;
 IF actor=ANY(reviewers) OR cardinality(reviewers)<>cardinality(keys) THEN RAISE EXCEPTION 'reference structure forbidden' USING ERRCODE='42501';END IF;
 SELECT array_agg(DISTINCT id ORDER BY id) INTO principals FROM (SELECT actor id UNION SELECT unnest(reviewers)
 UNION SELECT (payload#>>'{release,ownerId}')::uuid) p;
 IF cardinality(principals)>66 THEN RAISE EXCEPTION 'reference structure limit' USING ERRCODE='54000';END IF;
 PERFORM public.gc_lock_type_migration_principals(principals);
 PERFORM 1 FROM public.reference_sets WHERE tenant_id=tenant AND id=ANY(public.gc_reference_structure_endpoints(payload->'release')) ORDER BY id FOR UPDATE;
 SELECT * INTO h FROM public.reference_structure_heads WHERE tenant_id=tenant AND id=(payload->>'structureId')::uuid FOR UPDATE;
 PERFORM public.gc_relation_authorize(ARRAY['catalog:read','reference:read','reference:write']);
 IF NOT public.gc_reference_structure_actor_can(payload->'release',actor,'reference:write') OR EXISTS(SELECT 1 FROM unnest(reviewers) p WHERE NOT public.gc_reference_structure_actor_can(payload->'release',p,'reference:approve')) THEN RAISE EXCEPTION 'reference structure forbidden' USING ERRCODE='42501';END IF;
 IF h.id IS NOT NULL AND NOT public.gc_reference_structure_visible(h.id,actor) THEN RAISE EXCEPTION 'reference structure resource not found' USING ERRCODE='P0002';END IF;
 IF NOT public.gc_reference_structure_actor_can(payload->'release',actor,'reference:write') THEN RAISE EXCEPTION 'reference structure resource not found' USING ERRCODE='P0002';END IF;
 IF NOT public.gc_reference_structure_payload_current(payload) THEN RAISE EXCEPTION 'reference structure version conflict' USING ERRCODE='40001';END IF;
 stamp:=date_trunc('milliseconds',clock_timestamp());expiry:=(body->>'expiresAt')::timestamptz;
 IF expiry<=stamp OR expiry>stamp+interval '366 days' THEN RAISE EXCEPTION 'reference structure request invalid' USING ERRCODE='22023';END IF;
 IF (payload#>>'{release,activation,kind}'='at' AND (payload#>>'{release,activation,at}')::timestamptz<=stamp)
 OR (payload#>'{release,validUntil}'<>'null'::jsonb AND (payload#>>'{release,validUntil}')::timestamptz<=stamp) THEN RAISE EXCEPTION 'reference structure schedule stale' USING ERRCODE='40001';END IF;
 request_id:=(body->>'id')::uuid;
 hash:=public.gc_type_migration_hash(jsonb_build_object('id',request_id,'binding','reference.structure.publish','payload',payload,'workflow',body->'workflow','assignments',body->'assignments','expiresAt',body->'expiresAt'));
 INSERT INTO public.approval_requests(tenant_id,id,binding,resource_id,resource_version,payload,proposal_digest,workflow_id,workflow_version,workflow_hash,requester_id,status,expires_at,created_at,updated_at)
 VALUES(tenant,request_id,'reference.structure.publish',(payload->>'structureId')::uuid,nullif((payload->>'expectedVersion')::integer,0),payload,hash,w.workflow_id,w.version,w.definition_hash,actor,'pending',expiry,stamp,stamp);
 FOR stage IN SELECT s.value||jsonb_build_object('_ordinal',s.ordinality-1) FROM jsonb_array_elements(w.definition->'stages') WITH ORDINALITY s LOOP
  FOR assignment IN SELECT a#>>'{}' FROM jsonb_array_elements(stage->'assignments') a LOOP
   INSERT INTO public.approval_tasks(tenant_id,id,request_id,stage_index,assignment,assigned_identity_id,status,opened_at,expires_at)
   VALUES(tenant,gen_random_uuid(),request_id,(stage->>'_ordinal')::integer,assignment,(body->'assignments'->>assignment)::uuid,
   CASE WHEN stage->>'_ordinal'='0' THEN 'open' ELSE 'waiting' END,CASE WHEN stage->>'_ordinal'='0' THEN stamp END,
   CASE WHEN stage->>'_ordinal'='0' THEN least(expiry,stamp+make_interval(secs=>(stage->>'deadlineSeconds')::integer)) END);
  END LOOP;
 END LOOP;
 PERFORM public.gc_approval_journal('approval.submitted',request_id,request_id::text,1,jsonb_build_object('binding','reference.structure.publish','proposalDigest',hash,'workflowId',w.workflow_id,'workflowVersion',w.version),correlation,true);
 result:=jsonb_build_object('instance',jsonb_build_object('id',request_id));
 INSERT INTO public.idempotency(tenant_id,actor_id,operation,key,request_hash,response) VALUES(tenant,actor::text,operation,command_key,public.gc_type_migration_hash(normalized),result);
 RETURN result;
END $$;

CREATE FUNCTION public.gc_reference_structure_publish(request_identity uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE r public.approval_requests; h public.reference_structure_heads; prior public.reference_structure_releases; w jsonb; release jsonb; bundle jsonb; publication_result jsonb;
 stamp timestamptz; effective timestamptz; expiry timestamptz; expected integer; item jsonb; BEGIN
 r:=public.gc_reference_structure_lock_review(request_identity);
 PERFORM public.gc_relation_authorize(ARRAY['catalog:read','reference:read','reference:write']);
 IF public.gc_actor() IS DISTINCT FROM r.requester_id::text OR NOT public.gc_reference_structure_review_authorized(r) THEN RAISE EXCEPTION 'reference structure forbidden' USING ERRCODE='42501';END IF;
 -- Retained success is authorized before new-head or effective-time checks.
 IF r.status='succeeded' THEN RETURN r.result;END IF;
 IF r.status<>'ready' THEN RAISE EXCEPTION 'reference structure version conflict' USING ERRCODE='40001';END IF;
 stamp:=date_trunc('milliseconds',clock_timestamp());IF r.expires_at<=stamp THEN RAISE EXCEPTION 'reference structure approval expired' USING ERRCODE='40001';END IF;
 SELECT definition INTO w FROM public.workflow_definition_versions WHERE tenant_id=r.tenant_id AND workflow_id=r.workflow_id AND version=r.workflow_version AND definition_hash=r.workflow_hash;
 IF w IS NULL THEN RAISE EXCEPTION 'WORKFLOW_PIN_STALE' USING ERRCODE='40001';END IF;
 IF w->>'separationOfDuties'<>'true' OR EXISTS(SELECT 1 FROM public.approval_decisions WHERE tenant_id=r.tenant_id AND request_id=r.id AND decision='reject')
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(w->'stages') WITH ORDINALITY s(v,n) WHERE (SELECT count(*) FROM public.approval_decisions d JOIN public.approval_tasks t ON t.tenant_id=d.tenant_id AND t.id=d.task_id
 WHERE d.tenant_id=r.tenant_id AND d.request_id=r.id AND t.stage_index=s.n-1 AND d.decision='approve' AND d.actor_id=t.assigned_identity_id AND d.actor_id<>r.requester_id AND d.proposal_digest=r.proposal_digest)<(s.v->>'quorum')::integer)
 THEN RAISE EXCEPTION 'reference structure approval invalid' USING ERRCODE='23514';END IF;
 IF NOT public.gc_reference_structure_payload_current(r.payload) THEN RAISE EXCEPTION 'reference structure version conflict' USING ERRCODE='40001';END IF;
 release:=r.payload->'release';expected:=(r.payload->>'expectedVersion')::integer;
 IF expected>=2147483647 THEN RAISE EXCEPTION 'reference structure limit' USING ERRCODE='54000';END IF;
 SELECT * INTO h FROM public.reference_structure_heads WHERE tenant_id=r.tenant_id AND id=r.resource_id;
 SELECT * INTO prior FROM public.reference_structure_releases WHERE tenant_id=r.tenant_id AND structure_id=r.resource_id AND version=expected;
 effective:=CASE WHEN release#>>'{activation,kind}'='on-publication' THEN stamp ELSE (release#>>'{activation,at}')::timestamptz END;
 expiry:=(release->>'validUntil')::timestamptz;
 IF (release#>>'{activation,kind}'='at' AND effective<=stamp) OR (prior.structure_id IS NOT NULL AND (effective<=prior.effective_from OR stamp<prior.published_at))
 OR (expiry IS NOT NULL AND expiry<=effective) THEN RAISE EXCEPTION 'reference structure schedule stale' USING ERRCODE='40001';END IF;
 bundle:=(release-'activation')||jsonb_build_object('structureId',r.resource_id,'version',expected+1,'publishedAt',public.gc_relation_utc(stamp),'effectiveFrom',public.gc_relation_utc(effective));
 IF NOT public.gc_reference_structure_endpoints_valid(release,effective,expiry) THEN RAISE EXCEPTION 'reference structure endpoint changed' USING ERRCODE='40001';END IF;
 IF NOT public.gc_reference_structure_bundle_valid(bundle) THEN RAISE EXCEPTION 'reference structure storage invalid' USING ERRCODE='23514';END IF;
 IF expected=0 THEN
  INSERT INTO public.reference_structure_heads VALUES(r.tenant_id,r.resource_id,release->>'kind',(release#>>'{reference,setId}')::uuid,(release#>>'{source,setId}')::uuid,(release#>>'{target,setId}')::uuid,1,r.requester_id,stamp);
 ELSE UPDATE public.reference_structure_heads SET current_version=expected+1 WHERE tenant_id=r.tenant_id AND id=r.resource_id AND current_version=expected;END IF;
 INSERT INTO public.reference_structure_releases(tenant_id,structure_id,version,approval_request_id,approved_payload,proposal_digest,published_bundle,publication_hash,published_at,effective_from,valid_until,owner_id,status,reference_set_id,reference_version,source_set_id,source_version,target_set_id,target_version)
 VALUES(r.tenant_id,r.resource_id,expected+1,r.id,r.payload,r.proposal_digest,bundle,public.gc_type_migration_hash(bundle),stamp,effective,expiry,(release->>'ownerId')::uuid,release->>'status',(release#>>'{reference,setId}')::uuid,(release#>>'{reference,version}')::integer,(release#>>'{source,setId}')::uuid,(release#>>'{source,version}')::integer,(release#>>'{target,setId}')::uuid,(release#>>'{target,version}')::integer);
 IF release->>'kind'='reference-hierarchy' THEN
  INSERT INTO public.reference_hierarchy_edges
  SELECT r.tenant_id,r.resource_id,expected+1,(v.n-1)::integer,(release#>>'{reference,setId}')::uuid,(release#>>'{reference,version}')::integer,
   v.item->>'parentCode',v.item->>'childCode',(v.item->>'validFrom')::timestamptz,(v.item->>'validUntil')::timestamptz
  FROM jsonb_array_elements(release->'edges') WITH ORDINALITY v(item,n);
 ELSE
  INSERT INTO public.reference_crosswalk_mappings
  SELECT r.tenant_id,r.resource_id,expected+1,(v.n-1)::integer,(release#>>'{source,setId}')::uuid,(release#>>'{source,version}')::integer,
   (release#>>'{target,setId}')::uuid,(release#>>'{target,version}')::integer,v.item->>'sourceCode',v.item->>'targetCode',v.item->>'relation',v.item->>'method',
   v.item->>'methodDetails',v.item->>'transformationNotes',v.item->'confidence',(v.item->>'validFrom')::timestamptz,(v.item->>'validUntil')::timestamptz
  FROM jsonb_array_elements(release->'mappings') WITH ORDINALITY v(item,n);
 END IF;
 publication_result:=jsonb_build_object('binding','reference.structure.publish','structureId',r.resource_id,'version',expected+1,'publicationHash',public.gc_type_migration_hash(bundle),'publishedAt',public.gc_relation_utc(stamp),'effectiveFrom',public.gc_relation_utc(effective));
 UPDATE public.approval_requests SET status='succeeded',version=version+1,result=publication_result,updated_at=stamp WHERE tenant_id=r.tenant_id AND id=r.id;
 PERFORM public.gc_approval_journal('reference.structure_published',NULL,r.resource_id::text,expected+1,jsonb_build_object('approvalInstanceId',r.id,'publicationHash',public.gc_type_migration_hash(bundle),'proposalDigest',r.proposal_digest),'reference-structure:'||r.id::text);
 PERFORM public.gc_approval_journal('approval.succeeded',NULL,r.id::text,r.version+1,jsonb_build_object('binding','reference.structure.publish','structureId',r.resource_id,'version',expected+1,'proposalDigest',r.proposal_digest),'reference-structure:'||r.id::text);
 RETURN publication_result;
END $$;

CREATE FUNCTION public.gc_reference_structure_fail(request_identity uuid,ready_version integer,code text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE r public.approval_requests; BEGIN
 IF public.gc_actor() IS DISTINCT FROM 'site:local' OR code IS NULL OR code NOT IN('REFERENCE_STRUCTURE_AUTHORITY_REVOKED','REFERENCE_STRUCTURE_PRECONDITIONS_CHANGED','REFERENCE_STRUCTURE_EXPIRED','REFERENCE_STRUCTURE_APPROVAL_INVALID') THEN RAISE EXCEPTION 'reference structure forbidden' USING ERRCODE='42501';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(public.gc_tenant()::text,0));
 SELECT * INTO r FROM public.approval_requests WHERE tenant_id=public.gc_tenant() AND id=request_identity AND binding='reference.structure.publish' AND status='ready' AND version=ready_version;
 IF NOT FOUND THEN RETURN;END IF;
 UPDATE public.approval_requests SET status='failed',version=version+1,error_code=code,updated_at=date_trunc('milliseconds',clock_timestamp()) WHERE tenant_id=r.tenant_id AND id=r.id;
 PERFORM public.gc_approval_journal('approval.failed',NULL,r.id::text,r.version+1,jsonb_build_object('code',code,'proposalDigest',r.proposal_digest),'reference-structure:'||r.id::text);
END $$;

CREATE FUNCTION public.gc_approval_command_pre_structure(operation text,command_key text,body jsonb,correlation text) RETURNS jsonb
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
 SELECT * INTO old FROM public.idempotency WHERE tenant_id=tenant AND actor_id=actor::text AND idempotency.operation=gc_approval_command_pre_structure.operation AND key=command_key;
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

CREATE FUNCTION public.gc_approval_tick_pre_structure(request_identity uuid) RETURNS jsonb
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

CREATE OR REPLACE FUNCTION public.gc_approval_command(operation text,command_key text,body jsonb,correlation text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp SET row_security=on AS $$
DECLARE tenant uuid:=public.gc_tenant();actor uuid;r public.approval_requests;t public.approval_tasks;old public.idempotency;hash text;result jsonb;stamp timestamptz;reason text;decision_id uuid;required text[];BEGIN
 -- The binding comes only from the current canonical request. Neither generic
 -- submit nor an unknown operation can enter the classification effect family.
 IF operation NOT IN('approval.decide','approval.cancel') OR NOT public.gc_approval_uuid(body->>'requestId') OR NOT EXISTS(
  SELECT 1 FROM public.approval_requests WHERE tenant_id=tenant AND id=(body->>'requestId')::uuid AND binding='reference.structure.publish') THEN
  RETURN public.gc_approval_command_pre_structure(operation,command_key,body,correlation);
 END IF;
 IF command_key IS NULL OR length(command_key) NOT BETWEEN 8 AND 128 OR command_key ~ '[[:cntrl:]]' OR correlation IS NULL OR length(correlation) NOT BETWEEN 1 AND 128 OR correlation ~ '[[:cntrl:]]'
 OR body IS NULL OR octet_length(body::text)>16384 OR public.gc_relation_keys(body,CASE WHEN operation='approval.cancel' THEN ARRAY['requestId','proposalDigest','reason'] ELSE ARRAY['requestId','proposalDigest','taskId','taskVersion','decision','reason'] END) IS NOT TRUE
 OR jsonb_typeof(body->'proposalDigest') IS DISTINCT FROM 'string' OR body->>'proposalDigest' !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'reference structure request invalid' USING ERRCODE='22023';END IF;
 required:=ARRAY['catalog:read','reference:read',CASE WHEN operation='approval.cancel' THEN 'reference:write' ELSE 'reference:approve' END];
 PERFORM public.gc_relation_authorize(required);actor:=public.gc_actor()::uuid;
 r:=public.gc_reference_structure_lock_review((body->>'requestId')::uuid);PERFORM public.gc_relation_authorize(required);
 IF NOT public.gc_reference_structure_request_visible(r.id,actor) OR (r.requester_id<>actor AND NOT EXISTS(SELECT 1 FROM public.approval_tasks WHERE tenant_id=tenant AND request_id=r.id AND assigned_identity_id=actor))
 OR (operation='approval.cancel' AND r.requester_id<>actor) THEN RAISE EXCEPTION 'reference structure resource not found' USING ERRCODE='P0002';END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(tenant::text||actor::text||operation||command_key,0));hash:=public.gc_type_migration_hash(body);
 SELECT * INTO old FROM public.idempotency WHERE tenant_id=tenant AND actor_id=actor::text AND idempotency.operation=gc_approval_command.operation AND key=command_key;
 IF FOUND THEN IF old.request_hash<>hash THEN RAISE EXCEPTION 'IDEMPOTENCY_CONFLICT' USING ERRCODE='40001';END IF;RETURN old.response;END IF;
 stamp:=date_trunc('milliseconds',clock_timestamp());
 IF r.status<>'pending' OR r.expires_at<=stamp OR r.proposal_digest IS DISTINCT FROM body->>'proposalDigest' THEN RAISE EXCEPTION 'APPROVAL_STATE_CONFLICT' USING ERRCODE='40001';END IF;
 reason:=public.gc_classification_text(body->'reason',4096,'multiline');IF reason IS NULL THEN RAISE EXCEPTION 'reference structure request invalid' USING ERRCODE='22023';END IF;
 IF operation='approval.cancel' THEN
  UPDATE public.approval_requests SET status='cancelled',version=version+1,updated_at=stamp WHERE tenant_id=tenant AND id=r.id;
  UPDATE public.approval_tasks SET status='cancelled',version=version+1 WHERE tenant_id=tenant AND request_id=r.id AND status IN('open','waiting');
 ELSE
  IF NOT public.gc_approval_uuid(body->>'taskId') OR NOT public.gc_relation_positive_integer(body->'taskVersion') OR jsonb_typeof(body->'decision') IS DISTINCT FROM 'string' OR body->>'decision' NOT IN('approve','reject') THEN RAISE EXCEPTION 'reference structure request invalid' USING ERRCODE='22023';END IF;
  SELECT * INTO t FROM public.approval_tasks WHERE tenant_id=tenant AND request_id=r.id AND id=(body->>'taskId')::uuid;
  IF t.id IS NULL OR t.assigned_identity_id<>actor OR actor=r.requester_id OR t.version<>(body->>'taskVersion')::integer OR t.stage_index<>r.stage_index OR t.status<>'open' OR t.expires_at<=stamp THEN RAISE EXCEPTION 'APPROVAL_TASK_CONFLICT' USING ERRCODE='40001';END IF;
  IF NOT public.gc_reference_structure_review_authorized(r) THEN RAISE EXCEPTION 'reference structure forbidden' USING ERRCODE='42501';END IF;
  IF NOT public.gc_reference_structure_payload_current(r.payload) THEN RAISE EXCEPTION 'reference structure version conflict' USING ERRCODE='40001';END IF;
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
 IF NOT EXISTS(SELECT 1 FROM public.approval_requests WHERE tenant_id=public.gc_tenant() AND id=request_identity AND binding='reference.structure.publish') THEN RETURN public.gc_approval_tick_pre_structure(request_identity);END IF;
 r:=public.gc_reference_structure_lock_review(request_identity);
 IF r.status<>'pending' THEN RETURN jsonb_build_object('id',r.id,'status',r.status,'version',r.version,'nextWakeAt',NULL);END IF;
 SELECT definition INTO w FROM public.workflow_definition_versions WHERE tenant_id=r.tenant_id AND workflow_id=r.workflow_id AND version=r.workflow_version AND definition_hash=r.workflow_hash;
 s:=w->'stages'->r.stage_index;stamp:=date_trunc('milliseconds',clock_timestamp());
 SELECT min(expires_at) INTO deadline FROM public.approval_tasks WHERE tenant_id=r.tenant_id AND request_id=r.id AND stage_index=r.stage_index;
 IF stamp>=least(r.expires_at,deadline) THEN outcome:='expired';
 ELSIF NOT public.gc_reference_structure_review_authorized(r) THEN outcome:='cancelled';error:='REFERENCE_STRUCTURE_AUTHORITY_REVOKED';
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

-- SPDX-License-Identifier: Apache-2.0
CREATE FUNCTION public.gc_reference_structure_release_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE r public.approval_requests;h public.reference_structure_heads;prior public.reference_structure_releases;expected jsonb;BEGIN
 IF current_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.reference_structure_releases'::regclass)
 OR NEW.created_xid<>pg_current_xact_id() THEN RAISE EXCEPTION 'reference structure forbidden' USING ERRCODE='42501';END IF;
 SELECT * INTO r FROM public.approval_requests WHERE tenant_id=NEW.tenant_id AND id=NEW.approval_request_id;
 SELECT * INTO h FROM public.reference_structure_heads WHERE tenant_id=NEW.tenant_id AND id=NEW.structure_id;
 IF r.id IS NULL OR r.binding<>'reference.structure.publish' OR r.status<>'ready' OR r.resource_id<>NEW.structure_id
 OR coalesce(r.resource_version,0)<>NEW.version-1 OR r.payload IS DISTINCT FROM NEW.approved_payload OR r.proposal_digest IS DISTINCT FROM NEW.proposal_digest
 OR h.current_version IS DISTINCT FROM NEW.version OR h.kind IS DISTINCT FROM r.payload#>>'{release,kind}'
 OR h.reference_set_id IS DISTINCT FROM NEW.reference_set_id OR h.source_set_id IS DISTINCT FROM NEW.source_set_id OR h.target_set_id IS DISTINCT FROM NEW.target_set_id
 OR (r.payload->>'expectedVersion')::integer<>NEW.version-1 THEN RAISE EXCEPTION 'reference structure storage invalid' USING ERRCODE='23514';END IF;
 expected:=((r.payload->'release')-'activation')||jsonb_build_object('structureId',NEW.structure_id,'version',NEW.version,'publishedAt',public.gc_relation_utc(NEW.published_at),'effectiveFrom',public.gc_relation_utc(NEW.effective_from));
 IF expected IS DISTINCT FROM NEW.published_bundle
 OR (r.payload#>>'{release,activation,kind}'='on-publication' AND NEW.effective_from<>NEW.published_at)
 OR (r.payload#>>'{release,activation,kind}'='at' AND (NEW.effective_from IS DISTINCT FROM (r.payload#>>'{release,activation,at}')::timestamptz OR NEW.effective_from<=NEW.published_at))
 OR NOT public.gc_reference_structure_endpoints_valid(r.payload->'release',NEW.effective_from,NEW.valid_until)
 THEN RAISE EXCEPTION 'reference structure storage invalid' USING ERRCODE='23514';END IF;
 IF NEW.version>1 THEN
  SELECT * INTO prior FROM public.reference_structure_releases WHERE tenant_id=NEW.tenant_id AND structure_id=NEW.structure_id AND version=NEW.version-1;
  IF prior.structure_id IS NULL OR NEW.effective_from<=prior.effective_from OR NEW.published_at<prior.published_at THEN RAISE EXCEPTION 'reference structure storage invalid' USING ERRCODE='23514';END IF;
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER reference_structure_release_guard BEFORE INSERT ON public.reference_structure_releases FOR EACH ROW EXECUTE FUNCTION public.gc_reference_structure_release_guard();
CREATE FUNCTION public.gc_reference_structure_entry_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE r public.reference_structure_releases;projection jsonb;expected jsonb;BEGIN
 IF current_user<>(SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.reference_structure_releases'::regclass) THEN RAISE EXCEPTION 'reference structure forbidden' USING ERRCODE='42501';END IF;
 SELECT * INTO r FROM public.reference_structure_releases WHERE tenant_id=NEW.tenant_id AND structure_id=NEW.structure_id AND version=NEW.version;
 IF r.structure_id IS NULL OR r.created_xid<>pg_current_xact_id() THEN RAISE EXCEPTION 'reference structure storage invalid' USING ERRCODE='23514';END IF;
 IF TG_TABLE_NAME='reference_hierarchy_edges' THEN
  IF r.published_bundle->>'kind'<>'reference-hierarchy' OR NEW.reference_set_id IS DISTINCT FROM r.reference_set_id OR NEW.reference_version IS DISTINCT FROM r.reference_version
  THEN RAISE EXCEPTION 'reference structure storage invalid' USING ERRCODE='23514';END IF;
  projection:=jsonb_build_object('parentCode',NEW.parent_code,'childCode',NEW.child_code,'validFrom',public.gc_relation_utc(NEW.valid_from),'validUntil',public.gc_relation_utc(NEW.valid_until));
  expected:=r.published_bundle->'edges'->NEW.entry_index;
 ELSE
  IF TG_TABLE_NAME<>'reference_crosswalk_mappings' OR r.published_bundle->>'kind'<>'reference-crosswalk'
  OR NEW.source_set_id IS DISTINCT FROM r.source_set_id OR NEW.source_version IS DISTINCT FROM r.source_version
  OR NEW.target_set_id IS DISTINCT FROM r.target_set_id OR NEW.target_version IS DISTINCT FROM r.target_version
  THEN RAISE EXCEPTION 'reference structure storage invalid' USING ERRCODE='23514';END IF;
  projection:=jsonb_build_object('sourceCode',NEW.source_code,'targetCode',NEW.target_code,'relation',NEW.relation,'method',NEW.method,
   'methodDetails',NEW.method_details,'transformationNotes',NEW.transformation_notes,'confidence',NEW.confidence,
   'validFrom',public.gc_relation_utc(NEW.valid_from),'validUntil',public.gc_relation_utc(NEW.valid_until));
  expected:=r.published_bundle->'mappings'->NEW.entry_index;
 END IF;
 IF expected IS NULL OR projection IS DISTINCT FROM expected THEN RAISE EXCEPTION 'reference structure storage invalid' USING ERRCODE='23514';END IF;RETURN NEW;
END $$;
CREATE TRIGGER reference_structure_entry_guard BEFORE INSERT ON public.reference_hierarchy_edges FOR EACH ROW EXECUTE FUNCTION public.gc_reference_structure_entry_guard();
CREATE TRIGGER reference_structure_entry_guard BEFORE INSERT ON public.reference_crosswalk_mappings FOR EACH ROW EXECUTE FUNCTION public.gc_reference_structure_entry_guard();
CREATE FUNCTION public.gc_reference_structure_release_seal() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE r public.approval_requests;entries jsonb;expected jsonb;result jsonb;BEGIN
 SELECT * INTO r FROM public.approval_requests WHERE tenant_id=NEW.tenant_id AND id=NEW.approval_request_id;
 IF NEW.published_bundle->>'kind'='reference-hierarchy' THEN
  SELECT coalesce(jsonb_agg(jsonb_build_object('parentCode',e.parent_code,'childCode',e.child_code,'validFrom',public.gc_relation_utc(e.valid_from),'validUntil',public.gc_relation_utc(e.valid_until)) ORDER BY e.entry_index),'[]')
  INTO entries FROM public.reference_hierarchy_edges e WHERE e.tenant_id=NEW.tenant_id AND e.structure_id=NEW.structure_id AND e.version=NEW.version;
  expected:=NEW.published_bundle->'edges';
 ELSE
  SELECT coalesce(jsonb_agg(jsonb_build_object('sourceCode',e.source_code,'targetCode',e.target_code,'relation',e.relation,'method',e.method,
   'methodDetails',e.method_details,'transformationNotes',e.transformation_notes,'confidence',e.confidence,
   'validFrom',public.gc_relation_utc(e.valid_from),'validUntil',public.gc_relation_utc(e.valid_until)) ORDER BY e.entry_index),'[]')
  INTO entries FROM public.reference_crosswalk_mappings e WHERE e.tenant_id=NEW.tenant_id AND e.structure_id=NEW.structure_id AND e.version=NEW.version;
  expected:=NEW.published_bundle->'mappings';
 END IF;
 result:=jsonb_build_object('binding','reference.structure.publish','structureId',NEW.structure_id,'version',NEW.version,'publicationHash',NEW.publication_hash,'publishedAt',public.gc_relation_utc(NEW.published_at),'effectiveFrom',public.gc_relation_utc(NEW.effective_from));
 IF entries IS DISTINCT FROM expected OR r.binding IS DISTINCT FROM 'reference.structure.publish' OR r.status IS DISTINCT FROM 'succeeded'
 OR r.result IS DISTINCT FROM result OR r.payload IS DISTINCT FROM NEW.approved_payload OR r.proposal_digest IS DISTINCT FROM NEW.proposal_digest
 OR NOT EXISTS(SELECT 1 FROM public.reference_structure_heads h WHERE h.tenant_id=NEW.tenant_id AND h.id=NEW.structure_id AND h.current_version>=NEW.version)
 OR (SELECT count(*) FROM public.audit a JOIN public.outbox o ON o.tenant_id=a.tenant_id AND o.id=a.id
  WHERE a.tenant_id=NEW.tenant_id AND a.action='reference.structure_published' AND a.resource_id=NEW.structure_id::text AND o.event_type=a.action AND o.resource_id=a.resource_id AND o.resource_version=NEW.version
  AND a.changes=jsonb_build_object('approvalInstanceId',r.id,'publicationHash',NEW.publication_hash,'proposalDigest',r.proposal_digest,'resourceVersion',NEW.version))<>1
 OR (SELECT count(*) FROM public.audit a JOIN public.outbox o ON o.tenant_id=a.tenant_id AND o.id=a.id
  WHERE a.tenant_id=NEW.tenant_id AND a.action='approval.succeeded' AND a.resource_id=r.id::text AND o.event_type=a.action AND o.resource_id=a.resource_id AND o.resource_version=r.version
  AND a.changes=jsonb_build_object('binding','reference.structure.publish','structureId',NEW.structure_id,'version',NEW.version,'proposalDigest',r.proposal_digest,'resourceVersion',r.version))<>1
 THEN RAISE EXCEPTION 'reference structure storage invalid' USING ERRCODE='23514';END IF;RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER reference_structure_release_seal AFTER INSERT ON public.reference_structure_releases DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_reference_structure_release_seal();
CREATE FUNCTION public.gc_reference_structure_approval_seal() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$ BEGIN
 IF NEW.binding='reference.structure.publish' AND NEW.status='succeeded' AND NOT EXISTS(
 SELECT 1 FROM public.reference_structure_releases r WHERE r.tenant_id=NEW.tenant_id AND r.approval_request_id=NEW.id AND r.structure_id=NEW.resource_id
 AND r.proposal_digest=NEW.proposal_digest AND r.approved_payload=NEW.payload
 AND NEW.result=jsonb_build_object('binding','reference.structure.publish','structureId',r.structure_id,'version',r.version,'publicationHash',r.publication_hash,'publishedAt',public.gc_relation_utc(r.published_at),'effectiveFrom',public.gc_relation_utc(r.effective_from)))
 THEN RAISE EXCEPTION 'reference structure storage invalid' USING ERRCODE='23514';END IF;RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER reference_structure_approval_seal AFTER INSERT OR UPDATE ON public.approval_requests DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.gc_reference_structure_approval_seal();
-- SQL022's reference.% guards also protect this family; both tables share the
-- non-runtime migration owner. No public caller may forge its audit/idempotency.
REVOKE ALL ON FUNCTION public.gc_reference_structure_pin(jsonb),
 public.gc_reference_structure_release_normalize(jsonb),public.gc_reference_structure_payload_normalize(jsonb),
 public.gc_reference_structure_bundle_valid(jsonb),public.gc_reference_structure_endpoints(jsonb),
 public.gc_reference_structure_actor_can(jsonb,uuid,text),public.gc_reference_structure_visible(uuid,uuid),
 public.gc_reference_structure_request_visible(uuid,uuid),public.gc_reference_structure_authorize(uuid,boolean),
 public.gc_reference_structure_temporal_valid(jsonb,timestamptz,timestamptz),public.gc_reference_structure_endpoints_valid(jsonb,timestamptz,timestamptz),
 public.gc_reference_structure_payload_current(jsonb),public.gc_reference_structure_lock_review(uuid),
 public.gc_reference_structure_review_authorized(public.approval_requests),public.gc_reference_structure_command(text,text,jsonb,text),
 public.gc_reference_structure_publish(uuid),public.gc_reference_structure_fail(uuid,integer,text),
 public.gc_reference_structure_release_guard(),public.gc_reference_structure_entry_guard(),public.gc_reference_structure_release_seal(),public.gc_reference_structure_approval_seal(),
 public.gc_approval_command_pre_structure(text,text,jsonb,text),public.gc_approval_tick_pre_structure(uuid) FROM PUBLIC,gc_app;
GRANT EXECUTE ON FUNCTION public.gc_reference_structure_authorize(uuid,boolean),public.gc_reference_structure_visible(uuid,uuid),public.gc_reference_structure_request_visible(uuid,uuid),
 public.gc_reference_structure_payload_current(jsonb),public.gc_reference_structure_command(text,text,jsonb,text),public.gc_reference_structure_publish(uuid),public.gc_reference_structure_fail(uuid,integer,text) TO gc_app;
