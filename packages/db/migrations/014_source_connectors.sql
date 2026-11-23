-- SPDX-License-Identifier: Apache-2.0
-- Existing tenant/RLS/FK/audit boundaries remain in force. No credential is stored here.
ALTER TABLE public.sources ADD COLUMN connector_id text NOT NULL DEFAULT 'postgresql';
ALTER TABLE public.sources ADD CONSTRAINT sources_connector_kind CHECK (connector_id IN ('postgresql','unity-catalog'));
ALTER TABLE public.sources ADD CONSTRAINT sources_unity_catalog_scope CHECK (
  connector_id <> 'unity-catalog' OR (
    port = 443 AND length(host) <= 247
    AND host ~ '^[a-z0-9][a-z0-9.-]*\.(azuredatabricks\.net|cloud\.databricks\.com|gcp\.databricks\.com)$'
    AND length(database_name) BETWEEN 1 AND 255 AND database_name !~ '[[:cntrl:] ./\\]'
    AND length(schema_name) BETWEEN 1 AND 255 AND schema_name !~ '[[:cntrl:] ./\\]'
    AND length(secret_ref) BETWEEN 1 AND 128 AND secret_ref ~ '^[a-zA-Z0-9][a-zA-Z0-9_.-]*$'
  )
);
