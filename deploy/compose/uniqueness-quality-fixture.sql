-- SPDX-License-Identifier: Apache-2.0
-- Independent synthetic source codes for actual uniqueness-quality execution.
-- BEGIN UNIQUENESS_QUALITY_FIXTURE_V1
-- Also executed alone by runtime-install-quality-fixture.py for existing volumes.
-- Existing source data or revoked grants are never repaired implicitly.
BEGIN;
SET LOCAL search_path=pg_catalog,pg_temp;
SET LOCAL statement_timeout='15s';
SET LOCAL lock_timeout='2s';
SET LOCAL idle_in_transaction_session_timeout='5s';
DO $uniqueness_quality_fixture$
DECLARE target oid; source_owner oid; reader oid; columns jsonb; actual jsonb; expected jsonb;
BEGIN
 IF current_database()<>'harbor' OR session_user<>'source_admin' OR current_user<>'source_admin' THEN
  RAISE EXCEPTION 'UNIQUENESS_QUALITY_FIXTURE_CONTEXT_REJECTED';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('governance-commons:uniqueness_quality_fixture:v1',0));
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
  RAISE EXCEPTION 'UNIQUENESS_QUALITY_FIXTURE_READER_REJECTED';
 END IF;
 target:=to_regclass('public.uniqueness_quality_fixture');
 IF target IS NULL THEN
  CREATE TABLE public.uniqueness_quality_fixture(id integer PRIMARY KEY,code text,all_null text);
  COMMENT ON TABLE public.uniqueness_quality_fixture IS 'Governance Commons synthetic uniqueness quality fixture v1; 4 A, 2 B, C through L, 4 SQL NULL codes and 20 SQL NULL all_null values.';
  INSERT INTO public.uniqueness_quality_fixture(id,code,all_null)
   SELECT i,CASE WHEN i<=4 THEN 'A' WHEN i<=6 THEN 'B' WHEN i<=16 THEN chr(i+60) ELSE NULL END,NULL FROM generate_series(1,20) i;
  REVOKE ALL ON TABLE public.uniqueness_quality_fixture FROM PUBLIC;
  GRANT SELECT ON TABLE public.uniqueness_quality_fixture TO harbor_reader;
  target:=to_regclass('public.uniqueness_quality_fixture');
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_class WHERE oid=target AND relkind='r') THEN
  RAISE EXCEPTION 'UNIQUENESS_QUALITY_FIXTURE_SHAPE_REJECTED';
 END IF;
 LOCK TABLE public.uniqueness_quality_fixture IN SHARE MODE;
 IF NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE c.oid=target AND n.nspname='public' AND c.relname='uniqueness_quality_fixture' AND c.relowner=source_owner
   AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
   AND NOT c.relispartition AND NOT c.relhasrules
   AND obj_description(c.oid,'pg_class')='Governance Commons synthetic uniqueness quality fixture v1; 4 A, 2 B, C through L, 4 SQL NULL codes and 20 SQL NULL all_null values.') THEN
  RAISE EXCEPTION 'UNIQUENESS_QUALITY_FIXTURE_SHAPE_REJECTED';
 END IF;
 IF to_regclass('public.uniqueness_quality_fixture') IS DISTINCT FROM target
  OR EXISTS(SELECT 1 FROM pg_inherits WHERE inhrelid=target OR inhparent=target)
  OR EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=target AND NOT tgisinternal) THEN
  RAISE EXCEPTION 'UNIQUENESS_QUALITY_FIXTURE_SHAPE_REJECTED';
 END IF;
 SELECT jsonb_agg(jsonb_build_array(attnum,attname,atttypid,atttypmod,attnotnull,attidentity,attgenerated,atthasdef,attisdropped,attcollation) ORDER BY attnum)
 INTO columns FROM pg_attribute WHERE attrelid=target AND attnum>0;
 IF columns IS DISTINCT FROM jsonb_build_array(
  jsonb_build_array(1,'id','pg_catalog.int4'::regtype::oid,-1,true,'','',false,false,0::oid),
  jsonb_build_array(2,'code','pg_catalog.text'::regtype::oid,-1,false,'','',false,false,(SELECT typcollation FROM pg_type WHERE oid='pg_catalog.text'::regtype)),
  jsonb_build_array(3,'all_null','pg_catalog.text'::regtype::oid,-1,false,'','',false,false,(SELECT typcollation FROM pg_type WHERE oid='pg_catalog.text'::regtype))) THEN
  RAISE EXCEPTION 'UNIQUENESS_QUALITY_FIXTURE_SHAPE_REJECTED';
 END IF;
 IF (SELECT count(*) FROM pg_constraint WHERE conrelid=target)<>1
  OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=target AND contype='p' AND conkey=ARRAY[1]::smallint[] AND convalidated AND NOT condeferrable)
  OR (SELECT count(*) FROM pg_index WHERE indrelid=target)<>1
  OR NOT EXISTS(SELECT 1 FROM pg_index WHERE indrelid=target AND indisprimary AND indisunique AND indisvalid AND indisready
   AND indnkeyatts=1 AND indnatts=1 AND indexprs IS NULL AND indpred IS NULL) THEN
  RAISE EXCEPTION 'UNIQUENESS_QUALITY_FIXTURE_SHAPE_REJECTED';
 END IF;
 IF (has_table_privilege(reader,target,'SELECT')
  AND NOT has_table_privilege(reader,target,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_any_column_privilege(reader,target,'INSERT,UPDATE,REFERENCES')
  AND NOT EXISTS(SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) acl WHERE c.oid=target AND acl.grantee=0)
  AND NOT EXISTS(SELECT 1 FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) acl WHERE a.attrelid=target AND a.attnum>0 AND acl.grantee=0)) IS NOT TRUE THEN
  RAISE EXCEPTION 'UNIQUENESS_QUALITY_FIXTURE_GRANTS_REJECTED';
 END IF;
 -- Inspect at most one row beyond the exact fixture and never aggregate a
 -- drifted unbounded text value. Extra rows or values fail the exact comparison.
 SELECT jsonb_agg(jsonb_build_array(id,CASE WHEN code IS NULL THEN NULL WHEN octet_length(code)<=64 THEN code ELSE '<oversized>' END,CASE WHEN all_null IS NULL THEN NULL ELSE '<unexpected>' END) ORDER BY id)
 INTO actual FROM (SELECT id,code,all_null FROM public.uniqueness_quality_fixture ORDER BY id LIMIT 21) bounded_fixture;
 SELECT jsonb_agg(jsonb_build_array(i,CASE WHEN i<=4 THEN 'A' WHEN i<=6 THEN 'B' WHEN i<=16 THEN chr(i+60) ELSE NULL END,NULL) ORDER BY i)
 INTO expected FROM generate_series(1,20) i;
 IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION 'UNIQUENESS_QUALITY_FIXTURE_ROWS_REJECTED'; END IF;
END $uniqueness_quality_fixture$;
COMMIT;
SELECT 'UNIQUENESS_QUALITY_FIXTURE_READY_V1';
-- END UNIQUENESS_QUALITY_FIXTURE_V1
