-- SPDX-License-Identifier: Apache-2.0
-- Independent synthetic source integers for actual range-quality execution.
-- BEGIN RANGE_QUALITY_FIXTURE_V1
-- Also executed alone by runtime-install-quality-fixture.py for existing volumes.
-- Existing source data or revoked grants are never repaired implicitly.
BEGIN;
SET LOCAL search_path=pg_catalog,pg_temp;
SET LOCAL statement_timeout='15s';
SET LOCAL lock_timeout='2s';
SET LOCAL idle_in_transaction_session_timeout='5s';
DO $range_quality_fixture$
DECLARE target oid; source_owner oid; reader oid; columns jsonb; actual jsonb; expected jsonb;
BEGIN
 IF current_database()<>'harbor' OR session_user<>'source_admin' OR current_user<>'source_admin' THEN
  RAISE EXCEPTION 'RANGE_QUALITY_FIXTURE_CONTEXT_REJECTED';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('governance-commons:range_quality_fixture:v1',0));
 SELECT oid INTO source_owner FROM pg_roles WHERE rolname='source_admin';
 SELECT oid INTO reader FROM pg_roles WHERE rolname='harbor_reader' AND rolcanlogin
  AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls
  AND coalesce(rolconfig,'{}'::text[]) @> ARRAY['default_transaction_read_only=on'];
 IF (source_owner IS NOT NULL AND reader IS NOT NULL
  AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=reader)
  AND has_database_privilege(reader,current_database(),'CONNECT')
  AND NOT has_database_privilege(reader,current_database(),'CREATE')
  AND NOT has_database_privilege(reader,current_database(),'TEMP')
  AND has_schema_privilege(reader,'public','USAGE')
  AND NOT has_schema_privilege(reader,'public','CREATE')) IS NOT TRUE THEN
  RAISE EXCEPTION 'RANGE_QUALITY_FIXTURE_READER_REJECTED';
 END IF;
 target:=to_regclass('public.range_quality_fixture');
 IF target IS NULL THEN
  CREATE TABLE public.range_quality_fixture(id integer PRIMARY KEY,amount bigint,all_null bigint);
  COMMENT ON TABLE public.range_quality_fixture IS 'Governance Commons synthetic range quality fixture v1; amounts -1, 0, 5, 10, 11 and SQL NULL; 6 SQL NULL all_null values.';
  INSERT INTO public.range_quality_fixture(id,amount,all_null)
   VALUES (1,-1,NULL),(2,0,NULL),(3,5,NULL),(4,10,NULL),(5,11,NULL),(6,NULL,NULL);
  REVOKE ALL ON TABLE public.range_quality_fixture FROM PUBLIC;
  GRANT SELECT ON TABLE public.range_quality_fixture TO harbor_reader;
  target:=to_regclass('public.range_quality_fixture');
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_class WHERE oid=target AND relkind='r') THEN
  RAISE EXCEPTION 'RANGE_QUALITY_FIXTURE_SHAPE_REJECTED';
 END IF;
 LOCK TABLE public.range_quality_fixture IN SHARE MODE;
 IF NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE c.oid=target AND n.nspname='public' AND c.relname='range_quality_fixture' AND c.relowner=source_owner
   AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
   AND NOT c.relispartition AND NOT c.relhasrules
   AND obj_description(c.oid,'pg_class')='Governance Commons synthetic range quality fixture v1; amounts -1, 0, 5, 10, 11 and SQL NULL; 6 SQL NULL all_null values.') THEN
  RAISE EXCEPTION 'RANGE_QUALITY_FIXTURE_SHAPE_REJECTED';
 END IF;
 IF to_regclass('public.range_quality_fixture') IS DISTINCT FROM target
  OR EXISTS(SELECT 1 FROM pg_inherits WHERE inhrelid=target OR inhparent=target)
  OR EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=target AND NOT tgisinternal) THEN
  RAISE EXCEPTION 'RANGE_QUALITY_FIXTURE_SHAPE_REJECTED';
 END IF;
 SELECT jsonb_agg(jsonb_build_array(attnum,attname,atttypid,atttypmod,attnotnull,attidentity,attgenerated,atthasdef,attisdropped,attcollation) ORDER BY attnum)
 INTO columns FROM pg_attribute WHERE attrelid=target AND attnum>0;
 IF columns IS DISTINCT FROM jsonb_build_array(
  jsonb_build_array(1,'id','pg_catalog.int4'::regtype::oid,-1,true,'','',false,false,0::oid),
  jsonb_build_array(2,'amount','pg_catalog.int8'::regtype::oid,-1,false,'','',false,false,0::oid),
  jsonb_build_array(3,'all_null','pg_catalog.int8'::regtype::oid,-1,false,'','',false,false,0::oid)) THEN
  RAISE EXCEPTION 'RANGE_QUALITY_FIXTURE_SHAPE_REJECTED';
 END IF;
 IF (SELECT count(*) FROM pg_constraint WHERE conrelid=target)<>1
  OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=target AND contype='p' AND conkey=ARRAY[1]::smallint[] AND convalidated AND NOT condeferrable)
  OR (SELECT count(*) FROM pg_index WHERE indrelid=target)<>1
  OR NOT EXISTS(SELECT 1 FROM pg_index WHERE indrelid=target AND indisprimary AND indisunique AND indisvalid AND indisready
   AND indnkeyatts=1 AND indnatts=1 AND indexprs IS NULL AND indpred IS NULL) THEN
  RAISE EXCEPTION 'RANGE_QUALITY_FIXTURE_SHAPE_REJECTED';
 END IF;
 IF (has_table_privilege(reader,target,'SELECT')
  AND NOT has_table_privilege(reader,target,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_any_column_privilege(reader,target,'INSERT,UPDATE,REFERENCES')
  AND NOT EXISTS(SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) acl WHERE c.oid=target AND acl.grantee=0)
  AND NOT EXISTS(SELECT 1 FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) acl WHERE a.attrelid=target AND a.attnum>0 AND acl.grantee=0)) IS NOT TRUE THEN
  RAISE EXCEPTION 'RANGE_QUALITY_FIXTURE_GRANTS_REJECTED';
 END IF;
 -- Exact integer fixture, reading at most one row beyond the six expected rows.
 SELECT jsonb_agg(jsonb_build_array(id,amount,all_null) ORDER BY id)
 INTO actual FROM (SELECT id,amount,all_null FROM public.range_quality_fixture ORDER BY id LIMIT 7) bounded_fixture;
 SELECT jsonb_agg(jsonb_build_array(id,amount,NULL) ORDER BY id)
 INTO expected FROM (VALUES (1,-1::bigint),(2,0),(3,5),(4,10),(5,11),(6,NULL)) expected_fixture(id,amount);
 IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION 'RANGE_QUALITY_FIXTURE_ROWS_REJECTED'; END IF;
END $range_quality_fixture$;
COMMIT;
SELECT 'RANGE_QUALITY_FIXTURE_READY_V1';
-- END RANGE_QUALITY_FIXTURE_V1
