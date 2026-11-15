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
