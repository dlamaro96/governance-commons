// SPDX-License-Identifier: Apache-2.0
import type { Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import { SourceInput } from '../../contracts/src/index.ts';
import { Problem } from '../../authz/src/index.ts';

export type SourceConfiguration = Static<typeof SourceInput>;

/** Union validation must not strip fields while trying a different connector branch. */
export function validateSourceInput(value: unknown) {
  // Connection/display fields must be searchable, single-line Unicode scalars.
  // Reject controls and unpaired UTF-16 before persistence.
  const valid = Value.Check(SourceInput, value) && Object.values(value).every(field =>
    typeof field !== 'string' || (!/[\x00-\x1f\x7f]/.test(field) && Buffer.from(field, 'utf8').toString('utf8') === field));
  return valid ? {value} : {error: new Problem(400, 'VALIDATION_FAILED', 'Check the submitted connection fields.')};
}

/** Explicit connector mapping keeps API/workflow inputs free of credential values. */
export function sourceStorage(input: SourceConfiguration) {
  const connection = input.connectorId === 'unity-catalog'
    ? { connector_id: 'unity-catalog', host: new URL(input.workspaceUrl).hostname, port: 443, database_name: input.catalog }
    : { connector_id: 'postgresql', host: input.host, port: input.port, database_name: input.database };
  return { ...connection, name: input.name, schema_name: input.schema, secret_ref: input.secretRef };
}

export function sourceConfiguration(row: {connector_id: string; host: string; port: number; database_name: string; schema_name: string; secret_ref: string}) {
  const shared = {schema: row.schema_name, secretRef: row.secret_ref};
  if (row.connector_id === 'unity-catalog') return {connectorId: 'unity-catalog' as const,
    workspaceUrl: `https://${row.host}`, catalog: row.database_name, ...shared};
  if (row.connector_id === 'postgresql') return {connectorId: 'postgresql' as const,
    host: row.host, port: row.port, database: row.database_name, ...shared};
  throw new Error('SOURCE_CONNECTOR_UNSUPPORTED');
}

/** Caller flags can restrict reconciliation, never grant it to an adapter. */
export function mayReconcileAbsence(connectorId: string, completion: {absenceReconciliation?: false}) {
  return connectorId === 'postgresql' && completion.absenceReconciliation !== false;
}
