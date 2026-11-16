// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { resolveAssetType } from '../../packages/domain/src/asset-type.ts';
import { resolveRelationDefinition } from '../../packages/domain/src/relation.ts';
import type { ValidationResult } from '../../packages/domain/src/model.ts';
import type { RelationDefinition, RelationEndpointPolicyState, RelationTypeDefinitionV2 } from '../../packages/domain/src/relation-contracts.ts';
import type { AuthorizedCompleteGraphChange, CompleteGraphSnapshot, GraphBindingSnapshot, GraphEdgeSnapshot, RelationMigrationPlan,
  RelationMigrationValues, RelationPolicySnapshot } from '../../packages/domain/src/relation-migration-contracts.ts';
export const id = (n: number) => `00000000-0000-0000-0000-${n.toString(16).padStart(12, '0')}`;
export const typeId = id(1), relationId = id(2), actor = id(3), a = id(10), b = id(11), c = id(12);
export const lifecycle = { initial: 'draft', states: ['draft', 'active', 'retired'], transitions: [{ from: 'draft', to: 'active' }, { from: 'active', to: 'retired' }] };
export function ok<T>(result: ValidationResult<T>): T { if (!result.ok) assert.fail(JSON.stringify(result.issues)); return result.value; }
export function fails(result: ValidationResult<unknown>, code: string, path?: string): void {
  assert.equal(result.ok, false); if (result.ok) return;
  assert.ok(result.issues.some(issue => issue.code === code && (path === undefined || issue.path === path)), JSON.stringify(result.issues));
  assert.ok(result.issues.length <= 100);
}
export function definition(changes: Partial<RelationTypeDefinitionV2> = {}): RelationTypeDefinitionV2 {
  return { formatVersion: 2, id: 'supports', version: 1, label: 'Supports', inverseLabel: 'Supported by', direction: 'directed', sourceTypes: [{ typeId, includeDescendants: false }], targetTypes: [{ typeId, includeDescendants: false }], sourceStates: null, targetStates: null,
    cardinality: { outgoing: { min: 0, max: null }, incoming: { min: 0, max: null } }, allowSelf: false, cycles: 'allow', attributes: {}, requiredOwner: false, lifecycle: structuredClone(lifecycle), ...changes };
}
export const policy = (value: RelationDefinition = definition(), type = relationId): RelationPolicySnapshot => ({ relationTypeId: type, ...ok(resolveRelationDefinition(value)) });
export function asset(assetId = a, changes: Partial<RelationEndpointPolicyState> = {}): RelationEndpointPolicyState {
  const authored = { formatVersion: 1 as const, id: 'Dataset', version: 1, parents: [], attributes: {}, overrideAttributes: [], requiredOwner: false, lifecycle };
  return { assetId, assetVersion: 1, modelId: 'Dataset', modelVersion: 1, typeId, state: 'draft', ancestorTypes: [], policy: ok(resolveAssetType(authored, [])), ...changes };
}
export const values = (changes: Partial<RelationMigrationValues> = {}): RelationMigrationValues => ({ attributes: {}, ownerId: null, state: 'draft', validFrom: null, validTo: null, visibility: 'tenant', allowedIdentityIds: [], ...changes });
export const edge = (source = a, target = b, changes: Partial<GraphEdgeSnapshot> = {}): GraphEdgeSnapshot => ({ key: { kind: 'existing', relationId: id(100) }, version: 1, relationTypeId: relationId, relationTypeVersion: 1, sourceAssetId: source, sourceAssetVersion: 1, targetAssetId: target, targetAssetVersion: 1, status: 'active', values: values(), ...changes });
export const binding = (assetId = a, side: GraphBindingSnapshot['side'] = 'source', changes: Partial<GraphBindingSnapshot> = {}): GraphBindingSnapshot => ({ key: { kind: 'existing', bindingId: id(200) }, version: 1, relationTypeId: relationId, relationTypeVersion: 1, assetId, assetVersion: 1, side, status: 'active', ...changes });
export const graph = (changes: Partial<CompleteGraphSnapshot> = {}): CompleteGraphSnapshot => ({ heads: [{ relationTypeId: relationId, version: 1 }], endpoints: [asset(a), asset(b)], edges: [edge()], bindings: [], ...changes });
export const plan = (changes: Partial<RelationMigrationPlan> = {}): RelationMigrationPlan => ({ formatVersion: 1, relationTypeId: relationId, sourceVersions: [1], transform: null, edges: [{ relationId: id(100), expectedVersion: 1, action: 'repair', values: values({ state: 'active' }) }], creations: [], bindings: [], enrollment: 'complete-eligible-assets', acknowledgedPolicyChanges: [], ...changes });
export function repair(changes: Partial<AuthorizedCompleteGraphChange> = {}): AuthorizedCompleteGraphChange {
  return { changeSet: { formatVersion: 1, relationTargets: [{ kind: 'repair', expectedHeadVersion: 1, definition: null, plan: plan() }], assetChanges: [], assetTypeMigrations: [], repairsReceiptId: null }, completeRelationTypeIds: [relationId], policies: [policy()], preparedAssets: { policies: [], changes: [], typeMigrations: [] }, before: graph(), proposed: graph({ edges: [edge(a, b, { version: 2, values: values({ state: 'active' }) })] }), activeOwnerIds: new Set([actor]), tenantMemberIds: new Set([actor]), actorId: actor, ...changes };
}
