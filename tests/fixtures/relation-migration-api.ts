// SPDX-License-Identifier: Apache-2.0
/** Synthetic intent shared by real HTTP/browser journeys. No storage claims,
 * fabricated previews, UUID outcomes or mocked network responses live here. */
import type { AssetTypeDefinition } from '../../packages/domain/src/asset-type.ts';
import type { RelationTypeDefinitionV2 } from '../../packages/domain/src/relation-contracts.ts';
import type { GraphChangeSet, RelationMigrationContext, RelationMigrationContextRequest, RelationMigrationPlan,
  RelationMigrationValues, RelationPreparationView } from '../../packages/domain/src/relation-migration-contracts.ts';

export const lifecycle = { initial: 'draft', states: ['draft', 'active', 'retired'],
  transitions: [{ from: 'draft', to: 'active' }, { from: 'active', to: 'retired' }] };
export const exactAmount = '90071992547409931234567890.000000001';
export interface Endpoint { id: string; version: number; ownerId: string | null; modelId?: string | null }
export function authoredDefinition(id: string): AssetTypeDefinition {
  return { formatVersion: 1, id, version: 1, parents: [], attributes: {}, overrideAttributes: [], requiredOwner: false, lifecycle };
}
export function positiveDefinition(id: string, typeId: string): RelationTypeDefinitionV2 {
  return { formatVersion: 2, id, version: 1, label: 'Synthetic required dependency', inverseLabel: 'Synthetic required dependant',
    direction: 'directed', sourceTypes: [{ typeId, includeDescendants: false }], targetTypes: [{ typeId, includeDescendants: false }],
    sourceStates: null, targetStates: null, cardinality: { outgoing: { min: 1, max: 1 }, incoming: { min: 1, max: 1 } }, allowSelf: false,
    cycles: 'allow', attributes: { amount: { type: 'decimal', required: true }, note: { type: 'text' } }, requiredOwner: false, lifecycle };
}
export function values(changes: Partial<RelationMigrationValues> = {}): RelationMigrationValues {
  return { attributes: { amount: exactAmount, note: 'Synthetic graph assertion' }, ownerId: null, state: 'draft', validFrom: null,
    validTo: null, visibility: 'tenant', allowedIdentityIds: [], ...changes };
}
export const emptyChange = (): GraphChangeSet => ({ formatVersion: 1, relationTargets: [], assetChanges: [], assetTypeMigrations: [], repairsReceiptId: null });
export function plan(typeId: string, changes: Partial<RelationMigrationPlan> = {}): RelationMigrationPlan {
  return { formatVersion: 1, relationTypeId: typeId, sourceVersions: [], transform: null, edges: [], creations: [], bindings: [],
    enrollment: 'complete-eligible-assets', acknowledgedPolicyChanges: [], ...changes };
}
export function contextRequest(changeSet: GraphChangeSet): RelationMigrationContextRequest {
  return { formatVersion: 1, relationTargets: changeSet.relationTargets.map(({ plan, ...header }) => ({ ...header, relationTypeId: plan.relationTypeId })),
    assetChanges: changeSet.assetChanges, assetTypeMigrations: changeSet.assetTypeMigrations, repairsReceiptId: changeSet.repairsReceiptId };
}
export function jointCreation(preparation: RelationPreparationView, definition: RelationTypeDefinitionV2, modelId: string, endpoints: readonly Endpoint[]): GraphChangeSet {
  if (endpoints.length !== 2) throw Error('The synthetic reciprocal fixture requires exactly two endpoints.');
  return { ...emptyChange(), assetChanges: endpoints.map(asset => ({ kind: 'assign', assetId: asset.id, expectedVersion: asset.version,
    modelId, modelVersion: 1, attributes: {}, ownerId: asset.ownerId })), relationTargets: [{ kind: 'create', reservationId: preparation.id,
    expectedHeadVersion: null, definition, plan: plan(preparation.relationTypeId, { creations: endpoints.map((source, index) => {
      const target = endpoints[1 - index]; return { key: `required_${index}`, sourceAssetId: source.id, sourceAssetVersion: source.version,
        targetAssetId: target.id, targetAssetVersion: target.version, values: values() };
    }) }) }] };
}
export function repairChange(context: RelationMigrationContext, relationTypeId: string, repairsReceiptId: string | null = null): GraphChangeSet {
  const head = context.before.heads.find(row => row.relationTypeId === relationTypeId); if (!head) throw Error('Expected actual relation head.');
  const edges = context.before.edges.filter(row => row.relationTypeId === relationTypeId && row.status === 'active');
  const bindings = context.before.bindings.filter(row => row.relationTypeId === relationTypeId && row.status === 'active');
  return { ...emptyChange(), repairsReceiptId, relationTargets: [{ kind: 'repair', expectedHeadVersion: head.version, definition: null,
    plan: plan(relationTypeId, { sourceVersions: [...new Set([...edges, ...bindings].map(row => row.relationTypeVersion))].sort((a, b) => a - b),
      edges: edges.map(row => { if (row.key.kind !== 'existing') throw Error('Captured edges must exist.'); return { relationId: row.key.relationId, expectedVersion: row.version, action: 'preserve' }; }),
      bindings: bindings.map(row => { if (row.key.kind !== 'existing') throw Error('Captured bindings must exist.'); return { bindingId: row.key.bindingId, expectedVersion: row.version, action: 'preserve' }; }) }) }] };
}
export function samePairReplacement(context: RelationMigrationContext, relationTypeId: string, repairsReceiptId: string): GraphChangeSet {
  const change = repairChange(context, relationTypeId, repairsReceiptId), target = change.relationTargets[0];
  const predecessor = context.before.edges.find(row => row.relationTypeId === relationTypeId && row.status === 'active');
  if (!predecessor || predecessor.key.kind !== 'existing') throw Error('An actual predecessor is required.');
  const source = context.before.endpoints.find(row => row.assetId === predecessor.sourceAssetId)!;
  const destination = context.before.endpoints.find(row => row.assetId === predecessor.targetAssetId)!;
  const predecessorId = predecessor.key.relationId;
  target.plan = { ...target.plan, edges: target.plan.edges.map(row => row.relationId === predecessorId
    ? { relationId: predecessorId, expectedVersion: predecessor.version, action: 'replace', creationKey: 'same_pair_successor', reason: 'Synthetic forward repair with intact history' } : row),
  creations: [{ key: 'same_pair_successor', sourceAssetId: source.assetId, sourceAssetVersion: source.assetVersion,
    targetAssetId: destination.assetId, targetAssetVersion: destination.assetVersion,
    values: { ...predecessor.values, attributes: { ...predecessor.values.attributes, note: 'Synthetic replacement' } } }] };
  return change;
}
