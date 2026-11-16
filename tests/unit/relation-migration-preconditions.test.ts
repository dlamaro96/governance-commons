// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import { graphExpectedRevisionsMatch, graphInvalid } from '../../packages/domain/src/relation-migration-service.ts';
import { constructRelationGraphProposal } from '../../packages/domain/src/relation-migration.ts';
import { a, b, id, relationId, binding, graph, repair, values } from './relation-participation-fixtures.ts';

// Pure revision classification only. Actual capture authorization, HTTP error
// precedence and concurrent transaction serialization require the API gate.
test('edge disposition detects revision drift, missing/tombstoned members and wrong captured type', () => {
  const { changeSet, before } = repair();
  assert.equal(graphExpectedRevisionsMatch(changeSet, before), true);
  for (const edges of [[], [{ ...before.edges[0], version: 2 }], [{ ...before.edges[0], status: 'tombstoned' as const }],
    [{ ...before.edges[0], relationTypeId: id(90) }]]) assert.equal(graphExpectedRevisionsMatch(changeSet, { ...before, edges }), false);
  const reviewed = structuredClone(changeSet); reviewed.relationTargets[0].plan.edges[0].expectedVersion = 2;
  assert.equal(graphExpectedRevisionsMatch(reviewed, { ...before, edges: [{ ...before.edges[0], version: 2 }] }), true);
});

test('binding disposition detects repin/release drift and absence without comparing its observed asset version', () => {
  const { changeSet } = repair(), before = graph({ bindings: [binding()] });
  changeSet.relationTargets[0].plan.bindings = [{ bindingId: id(200), expectedVersion: 1, action: 'preserve' }];
  assert.equal(graphExpectedRevisionsMatch(changeSet, before), true);
  assert.equal(graphExpectedRevisionsMatch(changeSet, { ...before, bindings: [binding(a, 'source', { assetVersion: 3 })] }), true);
  for (const bindings of [[], [binding(a, 'source', { version: 2 })], [binding(a, 'source', { status: 'released' })],
    [binding(a, 'source', { relationTypeId: id(90) })]]) assert.equal(graphExpectedRevisionsMatch(changeSet, { ...before, bindings }), false);
});

test('direct assignment and transition bind captured before asset revisions', () => {
  const { changeSet, before } = repair();
  for (const change of [
    { kind: 'assign' as const, assetId: a, expectedVersion: 1, modelId: 'Dataset', modelVersion: 1, attributes: {}, ownerId: null },
    { kind: 'transition' as const, assetId: a, expectedVersion: 1, state: 'active' },
  ]) {
    changeSet.assetChanges = [change]; assert.equal(graphExpectedRevisionsMatch(changeSet, before), true);
    assert.equal(graphExpectedRevisionsMatch(changeSet, { ...before, endpoints: before.endpoints.map(row => row.assetId === a ? { ...row, assetVersion: 2 } : row) }), false);
    assert.equal(graphExpectedRevisionsMatch(changeSet, { ...before, endpoints: before.endpoints.filter(row => row.assetId !== a) }), false);
  }
});

test('new assertions bind both pre-operation endpoint versions even when the same intent advances an endpoint', () => {
  const { changeSet, before } = repair();
  changeSet.assetChanges = [{ kind: 'transition', assetId: a, expectedVersion: 1, state: 'active' }];
  changeSet.relationTargets[0].plan.creations = [{ key: 'additional', sourceAssetId: a, sourceAssetVersion: 1,
    targetAssetId: b, targetAssetVersion: 1, values: values() }];
  assert.equal(graphExpectedRevisionsMatch(changeSet, before), true);
  for (const assetId of [a, b]) {
    assert.equal(graphExpectedRevisionsMatch(changeSet, { ...before, endpoints: before.endpoints.map(row => row.assetId === assetId ? { ...row, assetVersion: 2 } : row) }), false);
    assert.equal(graphExpectedRevisionsMatch(changeSet, { ...before, endpoints: before.endpoints.filter(row => row.assetId !== assetId) }), false);
  }
  changeSet.relationTargets[0].plan.creations[0].sourceAssetVersion = 2;
  assert.equal(graphExpectedRevisionsMatch(changeSet, before), false);
});

test('semantic source-pin and policy intent failures remain validation errors rather than revision conflicts', () => {
  for (const mutate of [
    (input: ReturnType<typeof repair>) => { input.changeSet.relationTargets[0].plan.sourceVersions = [9]; },
    (input: ReturnType<typeof repair>) => { input.changeSet.relationTargets[0].plan.acknowledgedPolicyChanges = ['required_owner_changed']; },
  ]) {
    const input = repair(); mutate(input);
    assert.equal(graphExpectedRevisionsMatch(input.changeSet, input.before), true);
    const projected = constructRelationGraphProposal({ changeSet: input.changeSet, before: input.before, policies: input.policies,
      preparedAssets: input.preparedAssets, proposedEndpoints: input.proposed.endpoints });
    assert.equal(projected.ok, false); if (projected.ok) throw Error('Expected invalid semantic plan');
    const error = graphInvalid(projected.issues); assert.equal(error.status, 422); assert.equal(error.code, 'RELATION_MIGRATION_INVALID');
  }
  const input = repair(); input.changeSet.relationTargets[0].plan.edges = [{ relationId: id(100), expectedVersion: 1, action: 'repin',
    targetVersion: 99, values: values() }];
  assert.equal(graphExpectedRevisionsMatch(input.changeSet, input.before), true);
  assert.equal(graphInvalid([{ code: 'model_version', path: `/policies/${relationId}:99`, message: 'Exact target policy is missing.' }]).status, 422);
});
