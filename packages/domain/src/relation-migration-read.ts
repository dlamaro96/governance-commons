// SPDX-License-Identifier: Apache-2.0
import { sql, type Tx } from '../../db/src/index.ts';
import { Problem, type Principal } from '../../authz/src/index.ts';
import { modelPersistence } from './model-service.ts';
import { typeHash } from './asset-type-policy.ts';
import type { RelationMigrationReceipt, RelationPreparationView } from './relation-migration-contracts.ts';
import { RELATION_READ, iso, lockRelationScope, lockRelationPrincipals, relationQuery, uuid, profileLimit } from './relation-store.ts';

const receiptMissing = () => new Problem(404, 'RELATION_MIGRATION_NOT_FOUND', 'The relationship operation is unavailable.');
const preparationMissing = () => new Problem(404, 'RELATION_PREPARATION_NOT_FOUND', 'The relationship preparation is unavailable.');

/** Internal SQL predicate over protected normalized outcomes, never receipt JSON
 * supplied by a client. Callers supply a fixed query expression, not user SQL.
 * Every original asset and relation remains relevant after removal or replacement.
 * The scope is independent of the kind of an identically named audit subject. */
export function visibleRelationOperation(p: Principal, operationId: ReturnType<typeof sql>) {
  const member = JSON.stringify([p.id]);
  return sql<boolean>`${p.permissions.includes('models:read') && p.permissions.includes('catalog:read')}
    AND EXISTS (SELECT 1 FROM relation_graph_receipts operation
      WHERE operation.tenant_id=${p.tenantId}::uuid AND operation.id::text=(${operationId})::text
      AND NOT EXISTS (SELECT 1 FROM relation_graph_receipt_assets scope_asset
        LEFT JOIN assets a ON a.tenant_id=scope_asset.tenant_id AND a.id=scope_asset.asset_id
        WHERE scope_asset.tenant_id=operation.tenant_id AND scope_asset.operation_id=operation.id
          AND (a.id IS NULL OR NOT (a.visibility='tenant' OR a.allowed_identities @> ${member}::jsonb)))
      AND NOT EXISTS (SELECT 1 FROM relation_graph_receipt_edges scope_edge
        LEFT JOIN relations r ON r.tenant_id=scope_edge.tenant_id AND r.id=scope_edge.relation_id
        LEFT JOIN assets source ON source.tenant_id=r.tenant_id AND source.id=r.source_asset_id
        LEFT JOIN assets target ON target.tenant_id=r.tenant_id AND target.id=r.target_asset_id
        WHERE scope_edge.tenant_id=operation.tenant_id AND scope_edge.operation_id=operation.id
          AND (r.id IS NULL OR source.id IS NULL OR target.id IS NULL
            OR NOT (r.visibility='tenant' OR r.allowed_identities @> ${member}::jsonb)
            OR NOT (source.visibility='tenant' OR source.allowed_identities @> ${member}::jsonb)
            OR NOT (target.visibility='tenant' OR target.allowed_identities @> ${member}::jsonb)))
      AND NOT EXISTS (SELECT 1 FROM relation_graph_receipt_bindings scope_binding
        LEFT JOIN relation_participations b ON b.tenant_id=scope_binding.tenant_id AND b.id=scope_binding.binding_id
        LEFT JOIN assets a ON a.tenant_id=b.tenant_id AND a.id=b.asset_id
        WHERE scope_binding.tenant_id=operation.tenant_id AND scope_binding.operation_id=operation.id
          AND (b.id IS NULL OR a.id IS NULL OR NOT (a.visibility='tenant' OR a.allowed_identities @> ${member}::jsonb))))`;
}

/** The parent owns any write locks/deadline. This read never treats the original
 * actor, supplied receipt, or a hash as current authorization. */
export async function authorizeRelationOperation(tx: Tx, p: Principal, id: string): Promise<void> {
  if (!uuid(id)) throw receiptMissing();
  await authorizeRelationRepairReference(tx, p, id);
}

/** An optional predecessor is data, never a switch around authorization. Every
 * request rechecks current membership/actions and evaluates the same protected
 * receipt-scope predicate. Null explicitly means no predecessor; a supplied
 * reference must resolve to a currently visible complete original operation.
 * The caller still authorizes the full graph it is proposing to change. */
export async function authorizeRelationRepairReference(tx: Tx, p: Principal, id: string | null): Promise<void> {
  if (id !== null && !uuid(id)) throw receiptMissing();
  await relationQuery(tx, () => modelPersistence.authorize(tx, p, RELATION_READ));
  const allowed = await relationQuery(tx, () => sql<{ allowed: boolean }>`select
    (${id}::uuid IS NULL OR (${visibleRelationOperation(p, sql`${id}`)})) as allowed`.execute(tx));
  if (!allowed.rows[0]?.allowed) throw receiptMissing();
}

export async function getRelationMigrationReceipt(tx: Tx, p: Principal, id: string): Promise<{ receipt: RelationMigrationReceipt }> {
  await lockRelationScope(tx, p, RELATION_READ);
  await lockRelationPrincipals(tx, p, [], RELATION_READ);
  await authorizeRelationOperation(tx, p, id);
  const query = tx.selectFrom('relation_graph_receipts').where('tenant_id', '=', p.tenantId).where('id', '=', id);
  const size = await relationQuery(tx, () => query.select(sql<number>`octet_length(receipt::text)`.as('bytes')).executeTakeFirst());
  if (!size) throw receiptMissing(); if (size.bytes > 524288) throw profileLimit();
  const stored = await relationQuery(tx, () => query.select(['receipt', 'executed_by', 'executed_at']).executeTakeFirstOrThrow());
  const receipt = stored.receipt as RelationMigrationReceipt;
  if (receipt.id !== id || receipt.executedBy !== stored.executed_by || receipt.executedAt !== iso(stored.executed_at) ||
      receipt.formatVersion !== 1 || receipt.coverage !== 'complete-authorized-affected-graph' || typeHash(receipt.changeSet) !== receipt.changeSetHash)
    throw new Problem(500, 'RELATION_STORAGE_INVALID', 'The stored operation receipt could not be verified.');
  return { receipt };
}

/** Creator-only replay never renews a lease. Database time rejects an expired,
 * unconsumed preparation; completed consumption keeps its original evidence. */
export async function getRelationPreparation(tx: Tx, p: Principal, id: string): Promise<{ preparation: RelationPreparationView }> {
  if (!uuid(id)) throw preparationMissing();
  const actions = [...RELATION_READ, 'models:write', 'catalog:write'];
  await relationQuery(tx, () => modelPersistence.authorize(tx, p, actions));
  const row = await relationQuery(tx, () => tx.selectFrom('relation_type_preparations')
    .select(['id', 'type_id', 'definition_hash', 'created_at', 'expires_at', 'consumed_operation_id'])
    .select(sql<boolean>`expires_at <= clock_timestamp()`.as('expired'))
    .where('tenant_id', '=', p.tenantId).where('created_by', '=', p.id).where('id', '=', id).executeTakeFirst());
  if (!row) throw preparationMissing();
  if (row.expired && row.consumed_operation_id === null)
    throw new Problem(410, 'RELATION_PREPARATION_EXPIRED', 'Create a new preparation and run a fresh preview.');
  return { preparation: { id: row.id, relationTypeId: row.type_id, definitionHash: row.definition_hash,
    createdAt: iso(row.created_at), expiresAt: iso(row.expires_at) } };
}
