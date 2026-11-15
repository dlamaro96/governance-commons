// SPDX-License-Identifier: Apache-2.0
import { sql, type Tx } from '../../db/src/index.ts';
import { Problem, type Principal } from '../../authz/src/index.ts';
import type { ResolvedAssetType } from './asset-type.ts';
import type { RelationEndpointPolicyState, RelationEndpointProposal } from './relation-contracts.ts';
import { validateRelationEndpointChanges } from './relation.ts';
import { type Row, RELATION_READ, assetRows, constraintEdge, endpointState, hiddenScope, profileLimit, relationPolicies,
  visibleRelationPredicate, lockRelationRows, relationQuery, relationBudget, preflightEndpointPolicies, checkRelationDeadline } from './relation-store.ts';
import { modelPersistence } from './model-service.ts';

export interface ProposedRelationEndpointChange {
  assetId: string; expectedAssetVersion: number; modelId: string | null; modelVersion: number | null;
  state: string | null; policy: ResolvedAssetType | null;
}
/** Caller holds tenant ledger/model scope before invoking; all canonical asset locks must follow this union. */
async function incident(tx: Tx, p: Principal, ids: readonly string[]): Promise<Row[]> {
  if (!ids.length) return [];
  const query = tx.selectFrom('relations as r').where('r.tenant_id', '=', p.tenantId).where('r.status', '=', 'active')
    .where(eb => eb.or([eb('r.source_asset_id', 'in', [...ids]), eb('r.target_asset_id', 'in', [...ids])]));
  if (await relationQuery(tx, () => query.select('r.id').where(sql<boolean>`NOT (${visibleRelationPredicate(p)})`).limit(1).executeTakeFirst())) throw hiddenScope();
  const size = await relationQuery(tx, () => query.select([sql<string>`count(*)::text`.as('count'), sql<string>`coalesce(sum(octet_length(to_jsonb(r)::text)),0)::text`.as('bytes')]).executeTakeFirstOrThrow());
  if (Number(size.count) > 1000 || Number(size.bytes) > 524288) throw profileLimit();
  return relationQuery(tx, () => query.selectAll('r').orderBy('r.id').execute());
}
export async function lockRelationEndpointUnion(tx: Tx, p: Principal, proposedIds: readonly string[]): Promise<void> {
  if (!proposedIds.length) return;
  // Validate roots before inspecting their incident scope, including inaccessible/missing-root equivalence.
  await assetRows(tx, p, proposedIds);
  const rows = await incident(tx, p, proposedIds), union = [...new Set([...proposedIds, ...rows.flatMap(row => [row.source_asset_id, row.target_asset_id])])].sort();
  await assetRows(tx, p, union, true);
  await lockRelationRows(tx, p, rows);
}
/** Validate every affected pinned edge against one complete proposed endpoint set before any canonical write. */
export async function validateRelationsForEndpointChanges(tx: Tx, p: Principal, changes: readonly ProposedRelationEndpointChange[]): Promise<void> {
  if (!changes.length) return;
  await relationQuery(tx, () => modelPersistence.authorize(tx, p, RELATION_READ));
  const ids = changes.map(change => change.assetId);
  if (new Set(ids).size !== ids.length || ids.length > 1000) throw profileLimit();
  const rows = await incident(tx, p, ids); if (!rows.length) return;
  const currentRows = await assetRows(tx, p, [...ids, ...rows.flatMap(row => [row.source_asset_id, row.target_asset_id])]);
  // Hidden scope has already been refused. Bound repeated proposed/current policy copies before loading resolutions.
  let proposedBytes = 0;
  const policyBytes = new Map<ResolvedAssetType, number>();
  for (const change of changes) {
    checkRelationDeadline(tx);
    let bytes = change.policy ? policyBytes.get(change.policy) : 4;
    if (bytes === undefined) { bytes = Buffer.byteLength(JSON.stringify(change.policy)); if (Object.isFrozen(change.policy)) policyBytes.set(change.policy!, bytes); }
    proposedBytes += bytes + Buffer.byteLength(JSON.stringify({ ...change, policy: null }));
    if (proposedBytes > 524288) throw profileLimit();
  }
  await preflightEndpointPolicies(tx, p, currentRows, proposedBytes);
  const policies = await relationPolicies(tx, p, rows), constraints = rows.map(constraintEdge);
  const budget = relationBudget(tx, { policies, completeIncidentRelations: constraints });
  const current: RelationEndpointPolicyState[] = [];
  for (const row of currentRows) { const state = await endpointState(tx, p, row); budget.add(state); current.push(state); }
  const proposed: RelationEndpointProposal[] = [];
  const identitiesByPolicy = new Map<ResolvedAssetType, { typeId: string; ancestors: RelationEndpointPolicyState['ancestorTypes'] }>();
  for (const change of changes) {
    const prior = current.find(row => row.assetId === change.assetId);
    if (!prior || prior.assetVersion !== change.expectedAssetVersion) throw new Problem(409, 'VERSION_CONFLICT', 'An endpoint changed. Load the current state before saving.');
    let typeId: string | null = null, ancestors: RelationEndpointPolicyState['ancestorTypes'] = [];
    if (change.policy) {
      const cached = identitiesByPolicy.get(change.policy);
      if (cached) { typeId = cached.typeId; ancestors = cached.ancestors; }
      else {
        const keys = [change.policy.definition.id, ...change.policy.dependencies.map(pin => pin.id)];
        const identities = await relationQuery(tx, () => tx.selectFrom('governance_models').select(['id', 'type_id']).where('tenant_id', '=', p.tenantId).where('id', 'in', keys).execute());
        const mapping = new Map(identities.map(row => [row.id, row.type_id]));
        if (identities.length !== keys.length || identities.some(row => !row.type_id)) throw new Problem(422, 'RELATION_MIGRATION_REQUIRED', 'The proposed endpoint type identity is unavailable.');
        typeId = mapping.get(change.policy.definition.id)!;
        ancestors = change.policy.dependencies.map(pin => ({ typeId: mapping.get(pin.id)!, id: pin.id, version: pin.version }));
        if (Object.isFrozen(change.policy)) identitiesByPolicy.set(change.policy, { typeId: typeId!, ancestors });
      }
    }
    const proposal = { assetId: change.assetId, expectedAssetVersion: change.expectedAssetVersion, after: { assetId: change.assetId,
      assetVersion: change.expectedAssetVersion + 1, modelId: change.modelId, modelVersion: change.modelVersion, state: change.state,
      typeId, policy: change.policy, ancestorTypes: ancestors } };
    budget.add(proposal); proposed.push(proposal);
  }
  if (Buffer.byteLength(JSON.stringify({ current, proposed, policies, rows: constraints })) > 524288) throw profileLimit();
  const checked = validateRelationEndpointChanges({ currentEndpoints: current, proposedEndpoints: proposed, completeIncidentRelations: constraints, policies });
  checkRelationDeadline(tx);
  if (!checked.ok && checked.issues.some(issue => issue.code === 'limit')) throw profileLimit();
  if (!checked.ok) throw new Problem(422, 'RELATION_MIGRATION_REQUIRED', 'The proposed endpoint changes require an explicit relationship migration.', checked.issues);
}
