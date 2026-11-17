-- SPDX-License-Identifier: Apache-2.0
-- Independent synthetic source rows for real monitoring failure and recovery.
-- BEGIN MONITORING_QUALITY_FIXTURE_V1
-- Finite test-only operations; never callable through the product API.
-- Existing source data or revoked grants are never repaired implicitly.
BEGIN;
SET LOCAL search_path=pg_catalog,pg_temp;
SET LOCAL statement_timeout='15s';
SET LOCAL lock_timeout='2s';
SET LOCAL idle_in_transaction_session_timeout='5s';
SET LOCAL gc.monitoring_fixture_step = :'fixture_step';
DO $monitoring_quality_fixture$
DECLARE target oid; source_owner oid; reader oid; columns jsonb; actual jsonb; failed_rows jsonb; repaired_rows jsonb; step text;
BEGIN
 step:=current_setting('gc.monitoring_fixture_step');
 IF step NOT IN ('prepare','read','repair','fail') THEN RAISE EXCEPTION 'MONITORING_QUALITY_FIXTURE_STEP_REJECTED'; END IF;
 IF current_database()<>'harbor' OR session_user<>'source_admin' OR current_user<>'source_admin' THEN
  RAISE EXCEPTION 'MONITORING_QUALITY_FIXTURE_CONTEXT_REJECTED';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('governance-commons:monitoring_quality_fixture:v1',0));
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
  RAISE EXCEPTION 'MONITORING_QUALITY_FIXTURE_READER_REJECTED';
 END IF;
 target:=to_regclass('public.monitoring_quality_fixture');
 IF target IS NULL THEN
  IF step<>'prepare' THEN RAISE EXCEPTION 'MONITORING_QUALITY_FIXTURE_MISSING'; END IF;
  CREATE TABLE public.monitoring_quality_fixture(id integer PRIMARY KEY,amount bigint);
  COMMENT ON TABLE public.monitoring_quality_fixture IS 'Governance Commons synthetic monitoring quality fixture v1; six rows; id 6 alone switches between SQL NULL and 6.';
  INSERT INTO public.monitoring_quality_fixture(id,amount)
   VALUES (1,1),(2,2),(3,3),(4,4),(5,5),(6,NULL);
  REVOKE ALL ON TABLE public.monitoring_quality_fixture FROM PUBLIC;
  GRANT SELECT ON TABLE public.monitoring_quality_fixture TO harbor_reader;
  target:=to_regclass('public.monitoring_quality_fixture');
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_class WHERE oid=target AND relkind='r') THEN
  RAISE EXCEPTION 'MONITORING_QUALITY_FIXTURE_SHAPE_REJECTED';
 END IF;
 LOCK TABLE public.monitoring_quality_fixture IN SHARE ROW EXCLUSIVE MODE;
 IF NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE c.oid=target AND n.nspname='public' AND c.relname='monitoring_quality_fixture' AND c.relowner=source_owner
   AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
   AND NOT c.relispartition AND NOT c.relhasrules
   AND obj_description(c.oid,'pg_class')='Governance Commons synthetic monitoring quality fixture v1; six rows; id 6 alone switches between SQL NULL and 6.') THEN
  RAISE EXCEPTION 'MONITORING_QUALITY_FIXTURE_SHAPE_REJECTED';
 END IF;
 IF to_regclass('public.monitoring_quality_fixture') IS DISTINCT FROM target
  OR EXISTS(SELECT 1 FROM pg_inherits WHERE inhrelid=target OR inhparent=target)
  OR EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=target AND NOT tgisinternal) THEN
  RAISE EXCEPTION 'MONITORING_QUALITY_FIXTURE_SHAPE_REJECTED';
 END IF;
 SELECT jsonb_agg(jsonb_build_array(attnum,attname,atttypid,atttypmod,attnotnull,attidentity,attgenerated,atthasdef,attisdropped,attcollation) ORDER BY attnum)
 INTO columns FROM pg_attribute WHERE attrelid=target AND attnum>0;
 IF columns IS DISTINCT FROM jsonb_build_array(
  jsonb_build_array(1,'id','pg_catalog.int4'::regtype::oid,-1,true,'','',false,false,0::oid),
  jsonb_build_array(2,'amount','pg_catalog.int8'::regtype::oid,-1,false,'','',false,false,0::oid)) THEN
  RAISE EXCEPTION 'MONITORING_QUALITY_FIXTURE_SHAPE_REJECTED';
 END IF;
 IF (SELECT count(*) FROM pg_constraint WHERE conrelid=target)<>1
  OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=target AND contype='p' AND conkey=ARRAY[1]::smallint[] AND convalidated AND NOT condeferrable)
  OR (SELECT count(*) FROM pg_index WHERE indrelid=target)<>1
  OR NOT EXISTS(SELECT 1 FROM pg_index WHERE indrelid=target AND indisprimary AND indisunique AND indisvalid AND indisready
   AND indnkeyatts=1 AND indnatts=1 AND indexprs IS NULL AND indpred IS NULL) THEN
  RAISE EXCEPTION 'MONITORING_QUALITY_FIXTURE_SHAPE_REJECTED';
 END IF;
 IF (has_table_privilege(reader,target,'SELECT')
  AND NOT has_table_privilege(reader,target,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_any_column_privilege(reader,target,'INSERT,UPDATE,REFERENCES')
  AND NOT EXISTS(SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) acl WHERE c.oid=target AND acl.grantee=0)
  AND NOT EXISTS(SELECT 1 FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) acl WHERE a.attrelid=target AND a.attnum>0 AND acl.grantee=0)) IS NOT TRUE THEN
  RAISE EXCEPTION 'MONITORING_QUALITY_FIXTURE_GRANTS_REJECTED';
 END IF;
 -- Read at most one row beyond the finite synthetic dataset. The only two
 -- accepted states differ at id 6; no arbitrary source data is repaired.
 SELECT jsonb_agg(jsonb_build_array(id,amount) ORDER BY id)
 INTO actual FROM (SELECT id,amount FROM public.monitoring_quality_fixture ORDER BY id LIMIT 7) bounded_fixture;
 failed_rows:='[[1,1],[2,2],[3,3],[4,4],[5,5],[6,null]]'::jsonb;
 repaired_rows:='[[1,1],[2,2],[3,3],[4,4],[5,5],[6,6]]'::jsonb;
 IF actual IS DISTINCT FROM failed_rows AND actual IS DISTINCT FROM repaired_rows THEN
  RAISE EXCEPTION 'MONITORING_QUALITY_FIXTURE_ROWS_REJECTED';
 END IF;
 IF step='prepare' AND actual IS DISTINCT FROM failed_rows THEN
  RAISE EXCEPTION 'MONITORING_QUALITY_FIXTURE_PREPARE_REJECTED';
 END IF;
 IF step='repair' THEN UPDATE public.monitoring_quality_fixture SET amount=6 WHERE id=6 AND amount IS NULL;
 ELSIF step='fail' THEN UPDATE public.monitoring_quality_fixture SET amount=NULL WHERE id=6 AND amount=6;
 END IF;
END $monitoring_quality_fixture$;
SELECT jsonb_build_object('result','READY','rows',count(*),'nullRows',count(*) FILTER(WHERE amount IS NULL))
 FROM public.monitoring_quality_fixture;
COMMIT;
-- END MONITORING_QUALITY_FIXTURE_V1
