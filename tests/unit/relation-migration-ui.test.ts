// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { AttributeDefinition } from '../../packages/domain/src/model.ts';
import type { GraphChangeSet, RelationCreationProposal, RelationMigrationContext, RelationMigrationTarget } from '../../packages/domain/src/relation-migration-contracts.ts';
import { a, b, c, id, relationId, definition, policy, asset, edge, binding, graph, plan, repair } from './relation-participation-fixtures.ts';

// These tests exercise authoring transformations only. They do not substitute
// for authenticated browser or database qualification of graph operations.
// Runtime paths keep the backend-only tsconfig from importing JSX into its build.
const editorModule = '../../apps/web/src/relations/MigrationPlanEditor.tsx';
const pageModule = '../../apps/web/src/pages/RelationMigrations.tsx';
const valueModule = '../../apps/web/src/models/ValueFields.tsx';
const { captureSourcePlan, clearGraphAcknowledgements, losslessAttributeDraft, serializeEditedAttributes, selectCreationEndpoint } = await import(editorModule) as {
  captureSourcePlan: (target: RelationMigrationTarget, context: RelationMigrationContext) => RelationMigrationTarget;
  clearGraphAcknowledgements: (value: GraphChangeSet) => GraphChangeSet;
  serializeEditedAttributes: (fields: Readonly<Record<string, AttributeDefinition>>, draft: Record<string,unknown>, original:Record<string,unknown>) => Record<string,unknown>;
  losslessAttributeDraft: (fields: Readonly<Record<string, AttributeDefinition>>, values: Record<string, unknown>) => Record<string, unknown>;
  selectCreationEndpoint: (creation: RelationCreationProposal, side: 'source' | 'target', assetId: string, context: RelationMigrationContext) => RelationCreationProposal;
};
const { graphContextRequest } = await import(pageModule) as { graphContextRequest: (value: GraphChangeSet) => RelationMigrationContext['request'] };
const { serializeAttributes } = await import(valueModule) as { serializeAttributes: (fields: Readonly<Record<string, AttributeDefinition>>, values: Record<string, unknown>) => Record<string, unknown> };
function context(before = graph()): RelationMigrationContext {
  return { coverage: 'complete-authorized-affected-graph', request: graphContextRequest(repair().changeSet), assetIdentities: [{ assetId: a, name: 'Source' }, { assetId: b, name: 'Target' }, { assetId: c, name: 'No edges' }], preparations: [], completeRelationTypeIds: [relationId], policies: [policy()], before, assetPreparation: null, proposedEndpoints: null, targets: [], sourceIssues: [], targetIssues: [] };
}
test('source capture includes zero-edge binding pins and every live source revision without selecting a page', () => {
  const target = repair().changeSet.relationTargets[0];
  const original = structuredClone(target);
  const before = graph({ endpoints: [asset(a), asset(b), asset(c)],
    edges: [edge(), edge(b, c, { key: { kind: 'existing', relationId: id(101) }, version: 4, relationTypeVersion: 2 }), edge(c, a, { key: { kind: 'existing', relationId: id(102) }, status: 'tombstoned' }), edge(c, b, { relationTypeId: id(999) })],
    bindings: [binding(c, 'source', { relationTypeVersion: 3 }), binding(b, 'target', { key: { kind: 'existing', bindingId: id(201) }, status: 'released' })],
  });
  const captured = captureSourcePlan(target, context(before));
  assert.deepEqual(captured.plan.sourceVersions, [1, 2, 3]);
  assert.equal(captured.plan.edges.length, 2); assert.equal(captured.plan.bindings.length, 1);
  assert.equal(captured.plan.edges[0].action, 'repair');
  assert.deepEqual(captured.plan.edges[1], { relationId: id(101), expectedVersion: 4, action: 'preserve' });
  assert.deepEqual(captured.plan.bindings[0], { bindingId: id(200), expectedVersion: 1, action: 'preserve' });
  assert.deepEqual(target, original);
});
test('source recapture does not carry a previous write decision across a changed revision', () => {
  const target = repair().changeSet.relationTargets[0];
  const captured = captureSourcePlan(target, context(graph({ edges: [edge(a, b, { version: 2 })] })));
  assert.deepEqual(captured.plan.edges, [{ relationId: id(100), expectedVersion: 2, action: 'preserve' }]);
});
test('transform source versions contain only migrated edge pins, not binding-only pins', () => {
  const target: RelationMigrationTarget = { kind: 'publish', expectedHeadVersion: 3, definition: definition({ version: 4 }), plan: plan({ acknowledgedPolicyChanges: ['cardinality_changed'], edges: [{ relationId: id(100), expectedVersion: 1, action: 'migrate' }], transform: { attributes: { formatVersion: 1, modelId: 'supports', targetVersion: 4, sourceVersions: [1, 3], operations: [], acknowledgedChanges: [{ code: 'attribute_removed', path: '/attributes/old' }] }, owner: { default: 'preserve', overrides: [] }, lifecycle: { onUnmapped: 'preserve', mappings: [] } } }) };
  const captured = captureSourcePlan(target, context(graph({ bindings: [binding(c, 'source', { relationTypeVersion: 3 })] })));
  assert.deepEqual(captured.plan.sourceVersions, [1, 3]);
  assert.deepEqual(captured.plan.transform?.attributes.sourceVersions, [1]);
  assert.deepEqual(captured.plan.acknowledgedPolicyChanges, []);
  assert.deepEqual(captured.plan.transform?.attributes.acknowledgedChanges, []);
});
test('editing invalidates relation and nested policy acknowledgements without changing intent or source objects', () => {
  const original: GraphChangeSet = { ...repair().changeSet,
    relationTargets: [{ kind: 'publish', expectedHeadVersion: 1, definition: definition({ version: 2 }), plan: plan({ acknowledgedPolicyChanges: ['cardinality_changed'], transform: { attributes: { formatVersion: 1, modelId: 'supports', targetVersion: 2, sourceVersions: [1], operations: [{ op: 'remove', path: ['old'], onMissing: 'skip' }], acknowledgedChanges: [{ code: 'attribute_removed', path: '/attributes/old' }] }, owner: { default: 'preserve', overrides: [{ relationId: id(100), ownerId: id(3) }] }, lifecycle: { onUnmapped: 'error', mappings: [{ sourceVersion: 1, from: 'draft', to: 'active' }] } } }) }],
    assetTypeMigrations: [{ expectedHeadVersion: 1, definition: { ...asset().policy!.definition, version: 2 }, plan: { formatVersion: 1, typeId: id(1), attributes: { formatVersion: 1, modelId: 'Dataset', targetVersion: 2, sourceVersions: [1], operations: [], acknowledgedChanges: [{ code: 'constraints_changed', path: '/attributes/size' }] }, owner: { default: 'preserve', overrides: [] }, lifecycle: { onUnmapped: 'preserve', mappings: [] }, acknowledgedPolicyChanges: ['required_owner_changed'] } }],
  };
  const before = structuredClone(original), cleared = clearGraphAcknowledgements(original);
  assert.deepEqual(cleared.relationTargets[0].plan.acknowledgedPolicyChanges, []);
  assert.deepEqual(cleared.relationTargets[0].plan.transform?.attributes.acknowledgedChanges, []);
  assert.deepEqual(cleared.assetTypeMigrations[0].plan.acknowledgedPolicyChanges, []);
  assert.deepEqual(cleared.assetTypeMigrations[0].plan.attributes.acknowledgedChanges, []);
  assert.deepEqual(cleared.relationTargets[0].plan.transform?.owner, original.relationTargets[0].plan.transform?.owner);
  assert.deepEqual(cleared.relationTargets[0].plan.transform?.attributes.operations, original.relationTargets[0].plan.transform?.attributes.operations);
  assert.deepEqual(original, before);
});
test('visual attribute edits retain unsupported nested fields and exact decimal strings until explicitly removed', () => {
  const fields: Record<string, AttributeDefinition> = { amount: { type: 'decimal' }, details: { type: 'object', properties: { count: { type: 'number' } } }, rows: { type: 'list', items: { type: 'object', properties: { value: { type: 'number' } } } } };
  const original = { amount: '123456789012345678901234567890.12345', details: { count: 3, oldField: { decimal: '999999999999999999999.1' } }, rows: [{ value: 4, oldField: ['kept'] }], oldRoot: 'explicitly retained' };
  const draft = losslessAttributeDraft(fields, original);
  assert.deepEqual(serializeAttributes(fields, draft), original);
  const changed = serializeAttributes(fields, { ...draft, amount: '0.125' });
  assert.deepEqual(changed, { ...original, amount: '0.125' });
  assert.equal((draft.details as Record<string, unknown>).count, '3');
});
test('context headers retain complete asset and repair intent while omitting edge and binding dispositions', () => {
  const value: GraphChangeSet = { ...repair().changeSet, repairsReceiptId: id(500), assetChanges: [{ kind: 'assign', assetId: c, expectedVersion: 8, modelId: 'Dataset', modelVersion: 2, attributes: { amount: '12345678901234567890.1' }, ownerId: id(3) }] };
  const request = graphContextRequest(value);
  assert.deepEqual(request.relationTargets, [{ kind: 'repair', expectedHeadVersion: 1, definition: null, relationTypeId: relationId }]);
  assert.deepEqual(request.assetChanges, value.assetChanges);
  assert.equal(request.repairsReceiptId, id(500));
  assert.equal(Object.hasOwn(request.relationTargets[0], 'plan'), false);
});

test('editing an independent field does not coerce untouched values under a changed target schema', () => {
  const fields:Record<string,AttributeDefinition>={count:{type:'number'},details:{type:'object',properties:{newField:{type:'text'}}},amount:{type:'decimal'}};
  const original={count:'25',details:123,amount:'99999999999999999999.125'};
  const draft=losslessAttributeDraft(fields,original);
  assert.deepEqual(serializeEditedAttributes(fields,{...draft,amount:'0.25'},original),{...original,amount:'0.25'});
  assert.deepEqual(serializeEditedAttributes(fields,{...draft,count:'30'},original),{...original,count:30});
});

test('joint first-edge authoring captures before endpoint revisions while leaving final revisions to the server', () => {
  const captured = context(graph({ endpoints: [asset(a, { assetVersion: 7 }), asset(b, { assetVersion: 11 })] }));
  captured.proposedEndpoints = [asset(a, { assetVersion: 8 }), asset(b, { assetVersion: 12 })];
  const original: RelationCreationProposal = { key: 'first_edge', sourceAssetId: '', targetAssetId: '', sourceAssetVersion: 1,
    targetAssetVersion: 1, values: edge().values };
  const selected = selectCreationEndpoint(selectCreationEndpoint(original, 'source', a, captured), 'target', b, captured);
  assert.equal(selected.sourceAssetVersion, 7); assert.equal(selected.targetAssetVersion, 11);
  assert.equal(JSON.parse(JSON.stringify(selected)).sourceAssetVersion, 7);
  assert.equal(original.sourceAssetId, ''); assert.equal(original.targetAssetId, '');
  assert.deepEqual(selectCreationEndpoint(selected, 'source', c, captured), selected);
  assert.equal(captured.proposedEndpoints[0].assetVersion, 8);
});
