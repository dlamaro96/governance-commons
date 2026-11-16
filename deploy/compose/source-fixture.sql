-- SPDX-License-Identifier: Apache-2.0
-- Independently authored synthetic Harbor Retail dataset. No real people or business records.
REVOKE ALL ON DATABASE harbor FROM PUBLIC;
GRANT CONNECT ON DATABASE harbor TO harbor_reader;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE TABLE customers (
  customer_id integer PRIMARY KEY, display_name text NOT NULL,
  region text NOT NULL, contact_email text NOT NULL, joined_at date NOT NULL
);
COMMENT ON TABLE customers IS 'Synthetic customer directory for the Harbor Retail demonstration.';
COMMENT ON COLUMN customers.contact_email IS 'Synthetic example.invalid address; classification candidate for the demo.';
CREATE TABLE products (
  product_id integer PRIMARY KEY, product_name text NOT NULL,
  category text NOT NULL, unit_price numeric(12,2) NOT NULL CHECK (unit_price >= 0)
);
CREATE TABLE orders (
  order_id integer PRIMARY KEY, customer_id integer NOT NULL REFERENCES customers,
  ordered_at date NOT NULL, status text NOT NULL, total_amount numeric(12,2) NOT NULL
);
CREATE TABLE order_lines (
  order_id integer NOT NULL REFERENCES orders, line_number integer NOT NULL,
  product_id integer NOT NULL REFERENCES products, quantity integer NOT NULL,
  unit_price numeric(12,2) NOT NULL, PRIMARY KEY(order_id,line_number)
);
CREATE VIEW customer_order_summary AS
SELECT c.customer_id, c.display_name, c.region, count(o.order_id) AS order_count, coalesce(sum(o.total_amount),0) AS lifetime_value
FROM customers c LEFT JOIN orders o USING(customer_id) GROUP BY c.customer_id, c.display_name, c.region;
COMMENT ON VIEW customer_order_summary IS 'Synthetic customer order totals. No source rows are returned by metadata scanning.';
INSERT INTO customers SELECT i, 'Demo Customer ' || i, (ARRAY['North','South','East','West'])[(i%4)+1], 'person-' || i || '@example.invalid', DATE '2026-01-01' + i FROM generate_series(1,40) i;
INSERT INTO products SELECT i, 'Demo Product ' || i, (ARRAY['Home','Outdoor','Office'])[(i%3)+1], (i * 3.25)::numeric(12,2) FROM generate_series(1,12) i;
INSERT INTO orders SELECT i, (i%40)+1, DATE '2026-08-01' + (i%60), (ARRAY['complete','pending','returned'])[(i%3)+1], (i*4.75)::numeric(12,2) FROM generate_series(1,80) i;
INSERT INTO order_lines SELECT i, 1, (i%12)+1, (i%4)+1, (i*1.25)::numeric(12,2) FROM generate_series(1,80) i;
GRANT USAGE ON SCHEMA public TO harbor_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO harbor_reader;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO harbor_reader;

-- BEGIN QUALITY_FIXTURE_V1
-- Also executed alone by runtime-install-quality-fixture.py for existing volumes.
-- Existing source data or revoked grants are never repaired implicitly.
BEGIN;
SET LOCAL search_path=pg_catalog,pg_temp;
SET LOCAL statement_timeout='15s';
SET LOCAL lock_timeout='2s';
SET LOCAL idle_in_transaction_session_timeout='5s';
DO $quality_fixture$
DECLARE target oid; source_owner oid; reader oid; columns jsonb; actual jsonb; expected jsonb;
BEGIN
 IF current_database()<>'harbor' OR session_user<>'source_admin' OR current_user<>'source_admin' THEN
  RAISE EXCEPTION 'QUALITY_FIXTURE_CONTEXT_REJECTED';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('governance-commons:quality_fixture:v1',0));
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
  RAISE EXCEPTION 'QUALITY_FIXTURE_READER_REJECTED';
 END IF;
 target:=to_regclass('public.quality_fixture');
 IF target IS NULL THEN
  CREATE TABLE public.quality_fixture(id integer PRIMARY KEY,email text);
  COMMENT ON TABLE public.quality_fixture IS 'Governance Commons synthetic completeness fixture v1; 20 rows, 5 SQL NULL email values.';
  INSERT INTO public.quality_fixture(id,email)
   SELECT i,CASE WHEN i%4=0 THEN NULL ELSE 'quality-'||i::text||'@example.invalid' END FROM generate_series(1,20) i;
  REVOKE ALL ON TABLE public.quality_fixture FROM PUBLIC;
  GRANT SELECT ON TABLE public.quality_fixture TO harbor_reader;
  target:=to_regclass('public.quality_fixture');
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_class WHERE oid=target AND relkind='r') THEN
  RAISE EXCEPTION 'QUALITY_FIXTURE_SHAPE_REJECTED';
 END IF;
 LOCK TABLE public.quality_fixture IN SHARE MODE;
 IF NOT EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE c.oid=target AND n.nspname='public' AND c.relname='quality_fixture' AND c.relowner=source_owner
   AND c.relkind='r' AND c.relpersistence='p' AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity
   AND NOT c.relispartition AND NOT c.relhasrules
   AND obj_description(c.oid,'pg_class')='Governance Commons synthetic completeness fixture v1; 20 rows, 5 SQL NULL email values.') THEN
  RAISE EXCEPTION 'QUALITY_FIXTURE_SHAPE_REJECTED';
 END IF;
 IF to_regclass('public.quality_fixture') IS DISTINCT FROM target
  OR EXISTS(SELECT 1 FROM pg_inherits WHERE inhrelid=target OR inhparent=target)
  OR EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid=target AND NOT tgisinternal) THEN
  RAISE EXCEPTION 'QUALITY_FIXTURE_SHAPE_REJECTED';
 END IF;
 SELECT jsonb_agg(jsonb_build_array(attnum,attname,atttypid,atttypmod,attnotnull,attidentity,attgenerated,atthasdef,attisdropped,attcollation) ORDER BY attnum)
 INTO columns FROM pg_attribute WHERE attrelid=target AND attnum>0;
 IF columns IS DISTINCT FROM jsonb_build_array(
  jsonb_build_array(1,'id','pg_catalog.int4'::regtype::oid,-1,true,'','',false,false,0::oid),
  jsonb_build_array(2,'email','pg_catalog.text'::regtype::oid,-1,false,'','',false,false,(SELECT typcollation FROM pg_type WHERE oid='pg_catalog.text'::regtype))) THEN
  RAISE EXCEPTION 'QUALITY_FIXTURE_SHAPE_REJECTED';
 END IF;
 IF (SELECT count(*) FROM pg_constraint WHERE conrelid=target)<>1
  OR NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=target AND contype='p' AND conkey=ARRAY[1]::smallint[] AND convalidated AND NOT condeferrable)
  OR (SELECT count(*) FROM pg_index WHERE indrelid=target)<>1
  OR NOT EXISTS(SELECT 1 FROM pg_index WHERE indrelid=target AND indisprimary AND indisunique AND indisvalid AND indisready
   AND indnkeyatts=1 AND indnatts=1 AND indexprs IS NULL AND indpred IS NULL) THEN
  RAISE EXCEPTION 'QUALITY_FIXTURE_SHAPE_REJECTED';
 END IF;
 IF (has_table_privilege(reader,target,'SELECT')
  AND NOT has_table_privilege(reader,target,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
  AND NOT has_any_column_privilege(reader,target,'INSERT,UPDATE,REFERENCES')
  AND NOT EXISTS(SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) acl WHERE c.oid=target AND acl.grantee=0)
  AND NOT EXISTS(SELECT 1 FROM pg_attribute a CROSS JOIN LATERAL aclexplode(a.attacl) acl WHERE a.attrelid=target AND a.attnum>0 AND acl.grantee=0)) IS NOT TRUE THEN
  RAISE EXCEPTION 'QUALITY_FIXTURE_GRANTS_REJECTED';
 END IF;
 -- Inspect at most one row beyond the exact fixture and never aggregate a
 -- drifted unbounded text value. Extra rows or values fail the exact comparison.
 SELECT jsonb_agg(jsonb_build_array(id,CASE WHEN email IS NULL THEN NULL WHEN octet_length(email)<=64 THEN email ELSE '<oversized>' END) ORDER BY id)
 INTO actual FROM (SELECT id,email FROM public.quality_fixture ORDER BY id LIMIT 21) bounded_fixture;
 SELECT jsonb_agg(jsonb_build_array(i,CASE WHEN i%4=0 THEN NULL ELSE 'quality-'||i::text||'@example.invalid' END) ORDER BY i)
 INTO expected FROM generate_series(1,20) i;
 IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION 'QUALITY_FIXTURE_ROWS_REJECTED'; END IF;
END $quality_fixture$;
COMMIT;
SELECT 'QUALITY_FIXTURE_READY_V1';
-- END QUALITY_FIXTURE_V1
