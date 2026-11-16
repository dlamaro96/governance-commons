// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { resolveAssetType } from '../../packages/domain/src/asset-type.ts';
import { projectGraphAssetChanges } from '../../packages/domain/src/graph-asset-preparation.ts';
import { constructRelationGraphProposal, parseGraphChangeSet, parseGraphChangeSetFile, parseRelationMigrationContext, parseRelationMigrationPlan, relationPolicyChanges, validateRelationGraphChange } from '../../packages/domain/src/relation-migration.ts';
import type { AuthorizedCompleteGraphChange, GraphBindingSnapshot, GraphChangeSet, RelationMigrationPlan } from '../../packages/domain/src/relation-migration-contracts.ts';
import { a, b, c, id, typeId, relationId, actor, definition, policy, asset, edge, binding, graph, values, plan, repair, ok, fails } from './relation-participation-fixtures.ts';
function withPlan(input: AuthorizedCompleteGraphChange, next: RelationMigrationPlan): AuthorizedCompleteGraphChange {
  return { ...input, changeSet: { ...input.changeSet, relationTargets: [{ kind: 'repair', expectedHeadVersion: 1, definition: null, plan: next }] } };
}
function proposalInput(input: AuthorizedCompleteGraphChange) {
  return { changeSet: input.changeSet, before: input.before, policies: input.policies,
    preparedAssets: input.preparedAssets, proposedEndpoints: input.proposed.endpoints };
}
test('nested empty-cohort publication binds the actual target definition, not only its identity and version', () => {
  const original = { ...asset().policy!.definition, id: 'EmptyType' }, next = { ...original, version: 2 };
  const canonical = (value: any): string => Array.isArray(value) ? `[${value.map(canonical).join(',')}]` : value && typeof value === 'object'
    ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}` : JSON.stringify(value);
  const hash = (value: unknown) => createHash('sha256').update(canonical(value)).digest('hex');
  const evidence = (definition: typeof original) => {
    const resolution = ok(resolveAssetType(definition, []));
    return { kind: 'authored' as const, typeId: id(500), resolution, definitionHash: hash(resolution.definition), resolutionHash: hash(resolution), ancestorTypes: [] };
  };
  const migration = { typeId: id(500), modelId: 'EmptyType', expectedHeadVersion: 1,
    headPolicy: { modelId: 'EmptyType', modelVersion: 1 }, targetPolicy: { modelId: 'EmptyType', modelVersion: 2 }, sourcePolicies: [], assetIds: [],
    plan: { formatVersion: 1 as const, typeId: id(500), attributes: { formatVersion: 1 as const, modelId: 'EmptyType', targetVersion: 2, sourceVersions: [], acknowledgedChanges: [], operations: [] },
      owner: { default: 'preserve' as const, overrides: [] }, lifecycle: { onUnmapped: 'preserve' as const, mappings: [] }, acknowledgedPolicyChanges: [] } };
  const prepared = ok(projectGraphAssetChanges({ assetChanges: [], typeMigrations: [migration], before: [], policies: [evidence(original), evidence(next)], modelHeads: [{ modelId: 'EmptyType', version: 1 }], activeOwnerIds: new Set([actor]) }));
  const request = repair({ preparedAssets: prepared });
  request.changeSet = { ...request.changeSet, assetTypeMigrations: [{ expectedHeadVersion: 1, definition: next, plan: migration.plan }] };
  ok(validateRelationGraphChange(request));
  ok(constructRelationGraphProposal(proposalInput(request)));
  const changed = evidence({ ...next, requiredOwner: true });
  fails(validateRelationGraphChange({ ...request, preparedAssets: { ...prepared, policies: [evidence(original), changed] } }), 'invalid_definition', '/preparedAssets/typeMigrations/0/targetPolicy');
  fails(constructRelationGraphProposal(proposalInput({ ...request, preparedAssets: { ...prepared, policies: [evidence(original), changed] } })), 'invalid_definition', '/preparedAssets/typeMigrations/0/targetPolicy');
  fails(validateRelationGraphChange({ ...request, preparedAssets: { ...prepared, policies: [evidence(original)] } }), 'invalid_definition', '/preparedAssets/typeMigrations/0/targetPolicy');
});
test('migration plans and files normalize without mutation and reject malformed or duplicated intent', () => {
  const input = repair().changeSet, parsed = ok(parseGraphChangeSetFile(JSON.stringify(input)));
  assert.deepEqual(parsed, input); assert.ok(Object.isFrozen(parsed.relationTargets[0].plan.edges[0])); assert.equal(Object.isFrozen(input), false);
  fails(parseGraphChangeSetFile(JSON.stringify(input).replace('"repairsReceiptId":null', '"repairsReceiptId":null,"repairsReceipt\\u0049d":null')), 'duplicate');
  fails(parseRelationMigrationPlan({ ...plan(), sourceVersions: [1, 1] }), 'duplicate');
  fails(parseRelationMigrationPlan({ ...plan(), sourceVersions: ['1'] }), 'model_version');
  fails(parseRelationMigrationPlan({ ...plan(), enrollment: 'incident-only' }), 'enum');
  fails(parseRelationMigrationPlan({ ...plan(), edges: [{ relationId: id(100), expectedVersion: 1, action: 'tombstone', reason: 'bad\nreason' }] }), 'format');
  fails(parseRelationMigrationPlan({ ...plan(), edges: [{ relationId: id(100), expectedVersion: 1, action: 'tombstone', reason: ' ' }] }), 'format');
  fails(parseGraphChangeSet({ ...input, relationTargets: [], assetChanges: [] }), 'required');
});
test('context accepts complete intents without dispositions and rejects hidden envelope fields and accessors', () => {
  const source = repair().changeSet;
  const context = { ...source, relationTargets: source.relationTargets.map(({ plan, ...target }) => ({ ...target, relationTypeId: plan.relationTypeId })) };
  const parsed = ok(parseRelationMigrationContext(context));
  assert.deepEqual(parsed, context); assert.ok(Object.isFrozen(parsed.relationTargets));
  fails(parseRelationMigrationContext({ ...context, relationTargets: [{ ...context.relationTargets[0], plan: plan() }] }), 'unknown_field');
  fails(parseRelationMigrationContext({ ...context, relationTargets: [context.relationTargets[0], context.relationTargets[0]] }), 'duplicate');
  fails(parseRelationMigrationContext({ ...context, relationTargets: [{ ...context.relationTargets[0], relationTypeId: 'not-a-type-uuid' }] }), 'format');
  let touched = false; const accessor = { ...context };
  Object.defineProperty(accessor, 'assetChanges', { enumerable: true, get() { touched = true; return []; } });
  fails(parseRelationMigrationContext(accessor), 'invalid_json'); assert.equal(touched, false);
});
test('all new parsers reject accessors, prototype objects and unknown fields without executing code', () => {
  let touched = false; const input = repair().changeSet; Object.defineProperty(input, 'relationTargets', { enumerable: true, get() { touched = true; return []; } });
  fails(parseGraphChangeSet(input), 'invalid_json'); assert.equal(touched, false);
  fails(parseGraphChangeSet(Object.create(repair().changeSet)), 'invalid_json');
  fails(parseRelationMigrationPlan({ ...plan(), invented: true }), 'unknown_field');
  const accessor = repair(); Object.defineProperty(accessor, 'activeOwnerIds', { enumerable: true, get() { touched = true; return new Set(); } });
  fails(validateRelationGraphChange(accessor), 'invalid_json'); assert.equal(touched, false);
});
test('full explicit repair advances exactly once, retains identity/pin and freezes normalized result', () => {
  const result = ok(validateRelationGraphChange(repair()));
  assert.equal(result.changedEdges.length, 1); assert.equal(result.changedEdges[0].action, 'repair');
  assert.equal(result.final.edges[0].relationTypeVersion, 1); assert.equal(result.final.edges[0].version, 2);
  assert.ok(Object.isFrozen(result.final.edges[0].values));
});
test('complete scope, dispositions and proposed values cannot be shortened or forged', () => {
  const input = repair();
  fails(validateRelationGraphChange(withPlan(input, plan({ edges: [] }))), 'invalid_definition', '/migration/relationTargets/0/plan/edges');
  fails(validateRelationGraphChange({ ...input, completeRelationTypeIds: [] }), 'invalid_definition', '/completeRelationTypeIds');
  fails(validateRelationGraphChange({ ...input, proposed: graph() }), 'invalid_definition', '/migration/proposed');
  fails(validateRelationGraphChange(withPlan(input, plan({ sourceVersions: [] }))), 'model_version');
  fails(validateRelationGraphChange(withPlan(input, plan({ edges: [{ relationId: id(100), expectedVersion: 2, action: 'repair', values: values({ state: 'active' }) }] }))), 'model_version');
  fails(validateRelationGraphChange({ ...input, proposed: graph({ edges: [edge(a, c, { version: 2, values: values({ state: 'active' }) })] }) }), 'invalid_definition');
});
test('no-op repair cannot mint a receipt and repin only uses the actual committed head', () => {
  const input = withPlan(repair({ proposed: graph() }), plan({ edges: [{ relationId: id(100), expectedVersion: 1, action: 'preserve' }] }));
  fails(validateRelationGraphChange(input), 'invalid_definition', '/migration/relationTargets');
  fails(parseGraphChangeSet(withPlan(repair(), plan({ edges: [{ relationId: id(100), expectedVersion: 1, action: 'repin', targetVersion: 2, values: values() }] })).changeSet), 'model_version');
});
test('optional inactive owner may be preserved but never rewritten as a changed live migration result', () => {
  const owner = id(50), before = graph({ edges: [edge(a, b, { values: values({ ownerId: owner }) })] });
  const changed = withPlan(repair({ before, proposed: graph({ edges: [edge(a, b, { version: 2, values: values({ ownerId: owner, state: 'active' }) })] }), tenantMemberIds: new Set([actor, owner]) }), plan({ edges: [{ relationId: id(100), expectedVersion: 1, action: 'repair', values: values({ ownerId: owner, state: 'active' }) }] }));
  fails(validateRelationGraphChange(changed), 'required', '/migration/final/edges/0/ownerId');
  const next = definition({ version: 2, label: 'New display' });
  const preserved = { ...changed, changeSet: { ...changed.changeSet, relationTargets: [{ kind: 'publish' as const, expectedHeadVersion: 1, definition: next, plan: plan({ edges: [{ relationId: id(100), expectedVersion: 1, action: 'preserve' }] }) }] }, policies: [policy(), policy(next)], proposed: { ...before, heads: [{ relationTypeId: relationId, version: 2 }] } };
  ok(validateRelationGraphChange(preserved));
});
test('required inactive owner is a finite source issue repaired by active override or protected tombstone', () => {
  const owner = id(50), p = policy(definition({ requiredOwner: true })), before = graph({ edges: [edge(a, b, { values: values({ ownerId: owner }) })] });
  const tombstone = withPlan(repair({ policies: [p], before, proposed: graph({ edges: [edge(a, b, { version: 2, status: 'tombstoned', values: values({ ownerId: owner }) })] }), tenantMemberIds: new Set([actor, owner]) }), plan({ edges: [{ relationId: id(100), expectedVersion: 1, action: 'tombstone', reason: 'Retire assertion' }] }));
  assert.deepEqual(ok(validateRelationGraphChange(tombstone)).sourceIssues, [{ code: 'source_required_owner_inactive', relationId: id(100), ownerId: owner }]);
  const repaired = withPlan({ ...tombstone, proposed: graph({ edges: [edge(a, b, { version: 2, values: values({ ownerId: actor }) })] }) }, plan({ edges: [{ relationId: id(100), expectedVersion: 1, action: 'repair', values: values({ ownerId: actor }) }] }));
  ok(validateRelationGraphChange(repaired));
  fails(validateRelationGraphChange({ ...tombstone, before: graph({ edges: [edge()] }) }), 'required');
  fails(validateRelationGraphChange({ ...tombstone, tenantMemberIds: new Set([actor]) }), 'required');
});
test('source corruption cannot be hidden by replacing target values or tombstoning', () => {
  const input = repair({ before: graph({ edges: [edge(a, b, { values: values({ state: 'invented' }) })] }) });
  fails(validateRelationGraphChange(input), 'enum', '/migration/source/edges/0/state');
  const cycle = graph({ edges: [edge(), edge(b, a, { key: { kind: 'existing', relationId: id(101) } })] });
  fails(validateRelationGraphChange(repair({ policies: [policy(definition({ cycles: 'acyclic' }))], before: cycle })), 'cycle', '/migration/source/structure/0/cycles');
});
test('positive first publication derives exact-head zero-edge enrollments and first assertions atomically', () => {
  const proposedDefinition = definition({ sourceStates: ['draft'], cardinality: { outgoing: { min: 1, max: 1 }, incoming: { min: 0, max: 1 } } });
  const endpoints = [asset(a), asset(b, { state: 'active' })], before = graph({ heads: [], endpoints, edges: [] });
  const creation = { key: 'first', sourceAssetId: a, targetAssetId: b, sourceAssetVersion: 1, targetAssetVersion: 1, values: values() };
  const enrollment: GraphBindingSnapshot = binding(a, 'source', { key: { kind: 'enrollment', relationTypeId: relationId, assetId: a, side: 'source' } });
  const input = repair({ before, policies: [policy(proposedDefinition)], changeSet: { formatVersion: 1, relationTargets: [{ kind: 'create', expectedHeadVersion: null, reservationId: id(300), definition: proposedDefinition, plan: plan({ sourceVersions: [], edges: [], creations: [creation] }) }], assetChanges: [], assetTypeMigrations: [], repairsReceiptId: null }, proposed: graph({ endpoints, edges: [edge(a, b, { key: { kind: 'creation', relationTypeId: relationId, key: 'first' } })], bindings: [enrollment] }) });
  const output = ok(validateRelationGraphChange(input)); assert.equal(output.changedBindings[0].action, 'enroll'); assert.equal(output.changedEdges[0].action, 'create');
  assert.deepEqual(ok(constructRelationGraphProposal(proposalInput(input))), output.final);
  fails(validateRelationGraphChange({ ...input, proposed: { ...input.proposed, bindings: [] } }), 'invalid_definition', '/migration/proposed');
  const missingEdge = structuredClone(input.changeSet); missingEdge.relationTargets[0].plan.creations = [];
  fails(validateRelationGraphChange({ ...input, changeSet: missingEdge, proposed: { ...input.proposed, edges: [] } }), 'range', '/participation/0/minimum');
});
test('required binding cannot release or lose its last edge even when the client omits it', () => {
  const p = policy(definition({ sourceStates: ['draft'], cardinality: { outgoing: { min: 1, max: 1 }, incoming: { min: 0, max: 1 } } })), endpoints = [asset(a), asset(b, { state: 'active' })];
  const before = graph({ endpoints, bindings: [binding()] });
  const input = withPlan(repair({ before, policies: [p], proposed: { ...before, edges: [edge(a, b, { version: 2, status: 'tombstoned' })], bindings: [binding(a, 'source', { version: 2, status: 'released' })] } }), plan({ edges: [{ relationId: id(100), expectedVersion: 1, action: 'tombstone', reason: 'Remove' }], bindings: [{ bindingId: id(200), expectedVersion: 1, action: 'release', reason: 'Leave' }] }));
  fails(validateRelationGraphChange(input), 'invalid_definition', '/migration/relationTargets/0/plan/bindings/0');
  fails(validateRelationGraphChange(input), 'range', '/participation/0/minimum');
});
test('structural publication cannot grandfather any surviving old edge or binding', () => {
  const next = definition({ version: 2, cycles: 'acyclic' }), input = repair({ policies: [policy(), policy(next)], proposed: graph({ heads: [{ relationTypeId: relationId, version: 2 }] }) });
  input.changeSet.relationTargets = [{ kind: 'publish', expectedHeadVersion: 1, definition: next, plan: plan({ edges: [{ relationId: id(100), expectedVersion: 1, action: 'preserve' }], acknowledgedPolicyChanges: ['cycles_changed'] }) }];
  fails(validateRelationGraphChange(input), 'invalid_definition', '/structure/0/pins');
  const changedPlan = { ...input.changeSet.relationTargets[0].plan, edges: [{ relationId: id(100), expectedVersion: 1, action: 'repin' as const, targetVersion: 2, values: values() }] };
  input.changeSet.relationTargets = [{ kind: 'publish', expectedHeadVersion: 1, definition: next, plan: changedPlan }]; input.proposed.edges = [edge(a, b, { version: 2, relationTypeVersion: 2 })];
  ok(validateRelationGraphChange(input));
});
test('same-type replacement creates a new identity, allows explicit target-valid state and keeps predecessor tuple', () => {
  const creation = { key: 'replacement', sourceAssetId: a, targetAssetId: c, sourceAssetVersion: 1, targetAssetVersion: 1, values: values({ state: 'retired' }) };
  const before = graph({ endpoints: [asset(a), asset(b), asset(c)] }), input = withPlan(repair({ before, proposed: { ...before, edges: [edge(a, b, { version: 2, status: 'tombstoned' }), edge(a, c, { key: { kind: 'creation', relationTypeId: relationId, key: 'replacement' }, values: creation.values })] } }), plan({ edges: [{ relationId: id(100), expectedVersion: 1, action: 'replace', creationKey: 'replacement', reason: 'Correct endpoint' }], creations: [creation] }));
  assert.deepEqual(ok(validateRelationGraphChange(input)).replacements, [{ predecessorId: id(100), relationTypeId: relationId, creationKey: 'replacement' }]);
  fails(parseRelationMigrationPlan(plan({ edges: [{ relationId: id(100), expectedVersion: 1, action: 'replace', creationKey: 'absent', reason: 'Move' }] })), 'required');
  fails(validateRelationGraphChange({ ...input, proposed: { ...input.proposed, edges: [input.proposed.edges[0], { ...input.proposed.edges[1], relationTypeId: id(99) }] } }), 'model_identity');
});
test('independent creations cannot start in a noninitial state or assign duplicate predecessor keys', () => {
  const first = { key: 'new', sourceAssetId: b, targetAssetId: a, sourceAssetVersion: 1, targetAssetVersion: 1, values: values({ state: 'active' }) };
  const input = withPlan(repair(), plan({ creations: [first] }));
  fails(validateRelationGraphChange(input), 'enum');
  fails(parseRelationMigrationPlan(plan({ edges: [{ relationId: id(100), expectedVersion: 1, action: 'replace', creationKey: 'new', reason: 'One' }, { relationId: id(101), expectedVersion: 1, action: 'replace', creationKey: 'new', reason: 'Two' }], creations: [first] })), 'duplicate');
});
test('mixed-pin transformation preserves exact decimal digits, explicit owner repair and lifecycle mapping', () => {
  const old = definition({ attributes: { amount: { type: 'decimal', required: true } }, requiredOwner: true });
  const head = { ...old, version: 2, label: 'Head' }, target = { ...old, version: 3, attributes: { amount: { type: 'text' as const, required: true } } };
  const inactive = id(50), amount = '12345678901234567890.123456789', before = graph({ heads: [{ relationTypeId: relationId, version: 2 }], edges: [edge(a, b, { values: values({ attributes: { amount }, ownerId: inactive }) })] });
  const migrationPlan = plan({ edges: [{ relationId: id(100), expectedVersion: 1, action: 'migrate' }], transform: { attributes: { formatVersion: 1, modelId: 'supports', targetVersion: 3, sourceVersions: [1], acknowledgedChanges: [{ code: 'type_changed', path: '/attributes/amount' }], operations: [{ op: 'convert', path: ['amount'], conversion: 'decimalToText', onMissing: 'error' }] }, owner: { default: 'preserve', overrides: [{ relationId: id(100), ownerId: actor }] }, lifecycle: { onUnmapped: 'error', mappings: [{ sourceVersion: 1, from: 'draft', to: 'retired' }] } } });
  const input = repair({ before, policies: [policy(old), policy(head), policy(target)], tenantMemberIds: new Set([actor, inactive]), changeSet: { formatVersion: 1, relationTargets: [{ kind: 'publish', expectedHeadVersion: 2, definition: target, plan: migrationPlan }], assetChanges: [], assetTypeMigrations: [], repairsReceiptId: null }, proposed: graph({ heads: [{ relationTypeId: relationId, version: 3 }], edges: [edge(a, b, { version: 2, relationTypeVersion: 3, values: values({ attributes: { amount }, ownerId: actor, state: 'retired' }) })] }) });
  assert.equal(ok(validateRelationGraphChange(input)).final.edges[0].values.attributes.amount, amount);
  assert.equal(ok(constructRelationGraphProposal(proposalInput(input))).edges[0].values.attributes.amount, amount);
  const altered = structuredClone(input.changeSet); altered.relationTargets[0].plan.transform!.attributes = { ...altered.relationTargets[0].plan.transform!.attributes, sourceVersions: [1, 2] };
  fails(validateRelationGraphChange({ ...input, changeSet: altered }), 'model_version');
});
test('exact policy acknowledgements cannot be invented, omitted or replaced by attribute acknowledgements', () => {
  const next = definition({ version: 2, requiredOwner: true, cycles: 'acyclic' });
  assert.deepEqual(relationPolicyChanges(definition(), next), ['cycles_changed', 'required_owner_changed']);
  const input = repair({ policies: [policy(), policy(next)] }); input.changeSet.relationTargets = [{ kind: 'publish', expectedHeadVersion: 1, definition: next, plan: plan() }];
  fails(validateRelationGraphChange(input), 'invalid_definition', '/migration/relationTargets/0/plan/acknowledgedPolicyChanges');
});
test('prepared asset changes are independently compared to exact before/final endpoint pins and state', () => {
  const before = graph(), after = graph({ endpoints: [asset(a, { assetVersion: 2, state: 'active' }), asset(b)], edges: [edge(a, b, { version: 2, sourceAssetVersion: 2, values: values({ state: 'active' }) })] });
  const source = asset(), tuple = { modelId: 'Dataset', modelVersion: 1, attributes: {}, ownerId: null, state: 'draft' }, prepared = { policies: [{ kind: 'authored' as const, typeId, resolution: source.policy!, definitionHash: '0'.repeat(64), resolutionHash: '0'.repeat(64), ancestorTypes: [] }], changes: [{ kind: 'transition' as const, assetId: a, fromAssetVersion: 1, toAssetVersion: 2, before: tuple, after: { ...tuple, state: 'active' }, sourcePolicy: { modelId: 'Dataset', modelVersion: 1 }, targetPolicy: { modelId: 'Dataset', modelVersion: 1 }, sourceIssues: [] }], typeMigrations: [] };
  const input = repair({ before, proposed: after, preparedAssets: prepared }); input.changeSet.assetChanges = [{ kind: 'transition', assetId: a, expectedVersion: 1, state: 'active' }];
  ok(validateRelationGraphChange(input));
  fails(validateRelationGraphChange({ ...input, proposed: { ...after, endpoints: [asset(a, { assetVersion: 2, state: 'retired' }), asset(b)] } }), 'invalid_definition', '/preparedAssets/changes/0/after');
  fails(validateRelationGraphChange({ ...input, preparedAssets: { ...prepared, changes: [] } }), 'invalid_definition');
  fails(validateRelationGraphChange({ ...input, preparedAssets: { ...prepared, changes: [{ ...prepared.changes[0], after: { ...prepared.changes[0].after, ownerId: actor } }] } }), 'invalid_definition');
});
test('native set methods bypass hostile iterators and aggregate principals are bounded', () => {
  const input = repair(); let invoked = false;
  Object.defineProperty(input.activeOwnerIds, Symbol.iterator, { value() { invoked = true; throw new Error('must not run'); } });
  ok(validateRelationGraphChange(input)); assert.equal(invoked, false);
  fails(validateRelationGraphChange({ ...repair(), tenantMemberIds: new Set(Array.from({ length: 2002 }, (_, i) => id(i + 1000))) }), 'limit');
  fails(validateRelationGraphChange({ ...repair(), activeOwnerIds: { has: () => true } as any }), 'invalid_json');
});
test('unknown nested prepared fields, malformed tuples and oversized JSON cannot masquerade as valid projections', () => {
  fails(validateRelationGraphChange({ ...repair(), preparedAssets: { policies: [null], changes: [], typeMigrations: [] } as any }), 'type');
  fails(parseGraphChangeSetFile(' '.repeat(524289)), 'limit');
  fails(parseGraphChangeSet({ ...repair().changeSet, repairsReceiptId: 'bad' }), 'format');
});

test('publication preserve and old-pin repair must also satisfy the target own schema, owner and lifecycle', () => {
  const next = definition({ version: 2, requiredOwner: true }), before = graph();
  const input = repair({ before, policies: [policy(), policy(next)], proposed: { ...before, heads: [{ relationTypeId: relationId, version: 2 }] } });
  input.changeSet.relationTargets = [{ kind: 'publish', expectedHeadVersion: 1, definition: next, plan: plan({ edges: [{ relationId: id(100), expectedVersion: 1, action: 'preserve' }], acknowledgedPolicyChanges: ['required_owner_changed'] }) }];
  fails(validateRelationGraphChange(input), 'required', '/migration/targetCompatibility/edges/0/ownerId');
  const repairedValues = values({ ownerId: actor });
  input.changeSet.relationTargets = [{ kind: 'publish', expectedHeadVersion: 1, definition: next, plan: plan({ edges: [{ relationId: id(100), expectedVersion: 1, action: 'repair', values: repairedValues }], acknowledgedPolicyChanges: ['required_owner_changed'] }) }];
  input.proposed.edges = [edge(a, b, { version: 2, values: repairedValues })];
  const checked = ok(validateRelationGraphChange(input)); assert.equal(checked.final.edges[0].relationTypeVersion, 1);
  const attrTarget = definition({ version: 2, attributes: { name: { type: 'text', required: true } } });
  input.policies = [policy(), policy(attrTarget)]; input.changeSet.relationTargets = [{ kind: 'publish', expectedHeadVersion: 1, definition: attrTarget, plan: plan({ edges: [{ relationId: id(100), expectedVersion: 1, action: 'preserve' }] }) }];
  input.proposed.edges = before.edges;
  fails(validateRelationGraphChange(input), 'required', '/migration/targetCompatibility/edges/0/attributes/name');
});
test('full-value repin handles destructive attributes without an invented transform acknowledgement field', () => {
  const next = definition({ version: 2, attributes: { amount: { type: 'text', required: true } } }), nextValues = values({ attributes: { amount: 'explicit full replacement' } });
  const input = repair({ policies: [policy(), policy(next)], proposed: graph({ heads: [{ relationTypeId: relationId, version: 2 }], edges: [edge(a, b, { version: 2, relationTypeVersion: 2, values: nextValues })] }) });
  input.changeSet.relationTargets = [{ kind: 'publish', expectedHeadVersion: 1, definition: next, plan: plan({ edges: [{ relationId: id(100), expectedVersion: 1, action: 'repin', targetVersion: 2, values: nextValues }] }) }];
  ok(validateRelationGraphChange(input));
});
test('joint first assignment accepts current expected revisions and records final assertion revisions', () => {
  const required = definition({ cardinality: { outgoing: { min: 1, max: 1 }, incoming: { min: 0, max: 1 } } });
  const untyped = (assetId: string) => asset(assetId, { typeId: null, modelId: null, modelVersion: null, policy: null, state: null });
  const before = graph({ endpoints: [untyped(a), untyped(b)], edges: [] }), assigned = [asset(a, { assetVersion: 2 }), asset(b, { assetVersion: 2 })];
  const creations = [{ key: 'first', sourceAssetId: a, targetAssetId: b, sourceAssetVersion: 1, targetAssetVersion: 1, values: values() }, { key: 'second', sourceAssetId: b, targetAssetId: a, sourceAssetVersion: 1, targetAssetVersion: 1, values: values() }];
  const input = withPlan(repair({ before, policies: [policy(required)], proposed: graph({ endpoints: assigned, edges: creations.map(row => edge(row.sourceAssetId, row.targetAssetId, { key: { kind: 'creation', relationTypeId: relationId, key: row.key }, sourceAssetVersion: 2, targetAssetVersion: 2 })), bindings: [a, b].map(assetId => binding(assetId, 'source', { key: { kind: 'enrollment', relationTypeId: relationId, assetId, side: 'source' }, assetVersion: 2 })) }) }), plan({ sourceVersions: [], edges: [], creations }));
  input.changeSet.assetChanges = [a, b].map(assetId => ({ kind: 'assign', assetId, expectedVersion: 1, modelId: 'Dataset', modelVersion: 1, attributes: {}, ownerId: null }));
  const prior = { modelId: null, modelVersion: null, attributes: {}, ownerId: null, state: null }, next = { modelId: 'Dataset', modelVersion: 1, attributes: {}, ownerId: null, state: 'draft' };
  input.preparedAssets = { policies: [{ kind: 'authored', typeId, resolution: asset().policy!, definitionHash: '0'.repeat(64), resolutionHash: '0'.repeat(64), ancestorTypes: [] }], typeMigrations: [], changes: [a, b].map(assetId => ({ kind: 'assign', assetId, fromAssetVersion: 1, toAssetVersion: 2, before: prior, after: next, sourcePolicy: null, targetPolicy: { modelId: 'Dataset', modelVersion: 1 }, sourceIssues: [] })) };
  const result = ok(validateRelationGraphChange(input)); assert.equal(result.changedEdges.length, 2); assert.equal(result.changedBindings.length, 2);
  const projected = ok(constructRelationGraphProposal(proposalInput(input)));
  assert.ok(projected.edges.every(row => row.sourceAssetVersion === 2 && row.targetAssetVersion === 2));
  const finalInsteadOfExpected = structuredClone(input.changeSet);
  finalInsteadOfExpected.relationTargets[0].plan.creations[0].sourceAssetVersion = 2;
  fails(constructRelationGraphProposal({ ...proposalInput(input), changeSet: finalInsteadOfExpected }), 'model_version', '/migration/relationTargets/0/plan/creations/0');
  fails(validateRelationGraphChange({ ...input, proposed: { ...input.proposed, edges: [input.proposed.edges[0]] } }), 'invalid_definition', '/migration/proposed');
  const corrupt = structuredClone(input.preparedAssets); corrupt.changes[0].after.ownerId = actor;
  fails(validateRelationGraphChange({ ...input, preparedAssets: corrupt }), 'invalid_definition');
});
test('asset-only transition projects preserved incident rows to final endpoints without minting row revisions', () => {
  const before = graph({ bindings: [binding()] });
  const after = graph({ endpoints: [asset(a, { assetVersion: 2, state: 'active' }), asset(b)],
    edges: [edge(a, b, { sourceAssetVersion: 2 })], bindings: [binding(a, 'source', { assetVersion: 2 })] });
  const input = repair({ before, proposed: after });
  input.changeSet = { ...input.changeSet, relationTargets: [], assetChanges: [{ kind: 'transition', assetId: a, expectedVersion: 1, state: 'active' }] };
  const pin = { modelId: 'Dataset', modelVersion: 1 }, prior = { ...pin, attributes: {}, ownerId: null, state: 'draft' };
  input.preparedAssets = { policies: [{ kind: 'authored', typeId, resolution: asset().policy!, definitionHash: '0'.repeat(64), resolutionHash: '0'.repeat(64), ancestorTypes: [] }], typeMigrations: [],
    changes: [{ kind: 'transition', assetId: a, fromAssetVersion: 1, toAssetVersion: 2, before: prior, after: { ...prior, state: 'active' }, sourcePolicy: pin, targetPolicy: pin, sourceIssues: [] }] };
  const result = ok(validateRelationGraphChange(input));
  assert.deepEqual(result.changedEdges, []); assert.deepEqual(result.changedBindings, []);
  const projected = ok(constructRelationGraphProposal(proposalInput(input)));
  assert.equal(projected.edges[0].sourceAssetVersion, 2); assert.equal(projected.edges[0].version, 1);
  assert.equal(projected.bindings[0].assetVersion, 2); assert.equal(projected.bindings[0].version, 1);
  assert.equal(before.edges[0].sourceAssetVersion, 1); assert.equal(before.bindings[0].assetVersion, 1);
});
test('joint untyping captures current before endpoint revisions for tombstone/release without rewriting older observations', () => {
  const required = definition({ sourceStates: ['draft'], cardinality: { outgoing: { min: 1, max: 1 }, incoming: { min: 0, max: 1 } } });
  const before = graph({ endpoints: [asset(a, { assetVersion: 4 }), asset(b, { assetVersion: 2, state: 'active' })], bindings: [binding()] });
  const after = { ...before, endpoints: [asset(a, { assetVersion: 5, typeId: null, modelId: 'Unclassified', modelVersion: 1, state: null, policy: null }), before.endpoints[1]], edges: [edge(a, b, { version: 2, sourceAssetVersion: 4, targetAssetVersion: 2, status: 'tombstoned' })], bindings: [binding(a, 'source', { version: 2, assetVersion: 4, status: 'released' })] };
  const input = withPlan(repair({ before, proposed: after, policies: [policy(required)] }), plan({ edges: [{ relationId: id(100), expectedVersion: 1, action: 'tombstone', reason: 'Leave authored scope' }], bindings: [{ bindingId: id(200), expectedVersion: 1, action: 'release', reason: 'Assign attribute-only policy' }] }));
  input.changeSet.assetChanges = [{ kind: 'assign', assetId: a, expectedVersion: 4, modelId: 'Unclassified', modelVersion: 1, attributes: {}, ownerId: null }];
  input.preparedAssets = { policies: [{ kind: 'authored', typeId, resolution: asset().policy!, definitionHash: '0'.repeat(64), resolutionHash: '0'.repeat(64), ancestorTypes: [] }, { kind: 'attributes', model: { formatVersion: 1, id: 'Unclassified', version: 1, attributes: {} }, definitionHash: '0'.repeat(64) }], typeMigrations: [], changes: [{ kind: 'assign', assetId: a, fromAssetVersion: 4, toAssetVersion: 5, before: { modelId: 'Dataset', modelVersion: 1, attributes: {}, ownerId: null, state: 'draft' }, after: { modelId: 'Unclassified', modelVersion: 1, attributes: {}, ownerId: null, state: null }, sourcePolicy: { modelId: 'Dataset', modelVersion: 1 }, targetPolicy: { modelId: 'Unclassified', modelVersion: 1 }, sourceIssues: [] }] };
  const result = ok(validateRelationGraphChange(input)); assert.equal(result.final.edges[0].sourceAssetVersion, 4); assert.equal(before.edges[0].sourceAssetVersion, 1);
  assert.deepEqual(ok(constructRelationGraphProposal(proposalInput(input))), result.final);
  fails(validateRelationGraphChange({ ...input, proposed: { ...after, edges: [edge(a, b, { version: 2, status: 'tombstoned' })] } }), 'invalid_definition', '/migration/proposed');
});
test('directed opposite assertions need an explicit loss decision when becoming one undirected pair', () => {
  const target = definition({ version: 2, direction: 'undirected' }), before = graph({ edges: [edge(), edge(b, a, { key: { kind: 'existing', relationId: id(101) } })] });
  const input = repair({ before, policies: [policy(), policy(target)], proposed: graph({ heads: [{ relationTypeId: relationId, version: 2 }], edges: [edge(a, b, { version: 2, relationTypeVersion: 2 }), edge(b, a, { key: { kind: 'existing', relationId: id(101) }, version: 2, status: 'tombstoned' })] }) });
  input.changeSet.relationTargets = [{ kind: 'publish', expectedHeadVersion: 1, definition: target, plan: plan({ acknowledgedPolicyChanges: ['direction_changed'], edges: [{ relationId: id(100), expectedVersion: 1, action: 'repin', targetVersion: 2, values: values() }, { relationId: id(101), expectedVersion: 1, action: 'tombstone', reason: 'Explicitly retire opposite assertion' }] }) }];
  ok(validateRelationGraphChange(input));
  const nextPlan = structuredClone(input.changeSet.relationTargets[0].plan); nextPlan.edges = [nextPlan.edges[0], { relationId: id(101), expectedVersion: 1, action: 'replace', creationKey: 'opposite', reason: 'Preserve independently' }]; nextPlan.creations = [{ key: 'opposite', sourceAssetId: a, targetAssetId: b, sourceAssetVersion: 1, targetAssetVersion: 1, values: values() }];
  input.changeSet.relationTargets = [{ kind: 'publish', expectedHeadVersion: 1, definition: target, plan: nextPlan }]; input.proposed.edges = [...input.proposed.edges, edge(a, b, { key: { kind: 'creation', relationTypeId: relationId, key: 'opposite' }, relationTypeVersion: 2 })];
  fails(validateRelationGraphChange(input), 'duplicate', '/structure/0/pairs');
});

test('proposal construction is deterministic and defensive while validation independently checks immutable edge endpoints', () => {
  const before = graph({ endpoints: [asset(c), asset(b), asset(a)] }), input = repair({ before, proposed: { ...before, edges: [edge(a, b, { version: 2, values: values({ state: 'active' }) })] } });
  const supplied = proposalInput(input), snapshot = structuredClone(supplied);
  const proposed = ok(constructRelationGraphProposal(supplied));
  assert.deepEqual(supplied, snapshot); assert.equal(Object.isFrozen(supplied.before), false);
  assert.deepEqual(proposed.endpoints.map(row => row.assetId), [a, b, c]);
  assert.ok(Object.isFrozen(proposed.edges[0].values)); assert.ok(Object.isFrozen(proposed.endpoints[0].policy));
  assert.deepEqual(ok(validateRelationGraphChange({ ...input, proposed })).final, proposed);
  const tampered = { ...proposed, edges: [{ ...proposed.edges[0], targetAssetId: c }] };
  fails(validateRelationGraphChange({ ...input, proposed: tampered }), 'invalid_definition', '/migration/proposed');
  supplied.before.edges[0].values.state = 'retired';
  assert.equal(proposed.edges[0].values.state, 'active');
});

test('a complete proposal retains zero-edge required enrollments and lets validation report the unmet minimum', () => {
  const next = definition({ sourceStates: ['draft'], cardinality: { outgoing: { min: 1, max: 1 }, incoming: { min: 0, max: 1 } } });
  const before = graph({ heads: [], endpoints: [asset(a), asset(b, { state: 'active' })], edges: [] });
  const input = repair({ before, policies: [policy(next)], proposed: { ...before }, changeSet: { formatVersion: 1,
    relationTargets: [{ kind: 'create', expectedHeadVersion: null, reservationId: id(300), definition: next,
      plan: plan({ sourceVersions: [], edges: [], creations: [] }) }], assetChanges: [], assetTypeMigrations: [], repairsReceiptId: null } });
  const proposed = ok(constructRelationGraphProposal(proposalInput(input)));
  assert.equal(proposed.edges.length, 0); assert.equal(proposed.bindings.length, 1);
  assert.deepEqual(proposed.bindings[0].key, { kind: 'enrollment', relationTypeId: relationId, assetId: a, side: 'source' });
  assert.deepEqual(proposed.heads, [{ relationTypeId: relationId, version: 1 }]);
  fails(validateRelationGraphChange({ ...input, proposed }), 'range', '/participation/0/minimum');
});

test('complete proposed cardinality and cycle violations remain available without becoming validated outcomes', () => {
  const cases = [
    { current: definition({ cardinality: { outgoing: { min: 0, max: 1 }, incoming: { min: 0, max: null } } }),
      source: a, target: c, code: 'range', path: '/structure/0/maximum' },
    { current: definition({ cycles: 'acyclic' }), source: b, target: a, code: 'cycle', path: '/structure/0/cycles' },
  ];
  for (const scenario of cases) {
    const before = graph({ endpoints: [asset(a), asset(b), asset(c)] });
    const input = withPlan(repair({ before, policies: [policy(scenario.current)], proposed: before }), plan({ creations: [{ key: 'extra',
      sourceAssetId: scenario.source, targetAssetId: scenario.target, sourceAssetVersion: 1, targetAssetVersion: 1, values: values() }] }));
    const proposed = ok(constructRelationGraphProposal(proposalInput(input)));
    assert.equal(proposed.edges.length, 2);
    assert.ok(proposed.edges.some(row => row.key.kind === 'creation' && row.key.key === 'extra'));
    fails(validateRelationGraphChange({ ...input, proposed }), scenario.code, scenario.path);
  }
});

test('required release intent stays visible in the proposal while validation rejects that disposition and its deficit', () => {
  const current = definition({ sourceStates: ['draft'], cardinality: { outgoing: { min: 1, max: 1 }, incoming: { min: 0, max: 1 } } });
  const before = graph({ endpoints: [asset(a), asset(b, { state: 'active' })], bindings: [binding()] });
  const input = withPlan(repair({ before, proposed: before, policies: [policy(current)] }), plan({
    edges: [{ relationId: id(100), expectedVersion: 1, action: 'tombstone', reason: 'Retire assertion' }],
    bindings: [{ bindingId: id(200), expectedVersion: 1, action: 'release', reason: 'Release requested' }],
  }));
  const proposed = ok(constructRelationGraphProposal(proposalInput(input)));
  assert.equal(proposed.edges[0].status, 'tombstoned');
  assert.equal(proposed.bindings.find(row => row.key.kind === 'existing')!.status, 'released');
  assert.equal(proposed.bindings.find(row => row.key.kind === 'enrollment')!.status, 'active');
  const checked = validateRelationGraphChange({ ...input, proposed });
  fails(checked, 'invalid_definition', '/migration/relationTargets/0/plan/bindings/0');
  fails(checked, 'range', '/participation/0/minimum');
});

test('proposal construction fails for missing exact evidence and transformations that cannot produce a target value', () => {
  fails(constructRelationGraphProposal({ ...proposalInput(repair()), policies: [] }), 'required');
  const current = definition({ attributes: { amount: { type: 'text' } } });
  const next = definition({ version: 2, attributes: { amount: { type: 'decimal' } } });
  const before = graph({ edges: [edge(a, b, { values: values({ attributes: { amount: 'not a decimal' } }) })] });
  const input = repair({ before, proposed: before, policies: [policy(current), policy(next)] });
  input.changeSet.relationTargets = [{ kind: 'publish', expectedHeadVersion: 1, definition: next, plan: plan({
    edges: [{ relationId: id(100), expectedVersion: 1, action: 'migrate' }], transform: {
      attributes: { formatVersion: 1, modelId: 'supports', targetVersion: 2, sourceVersions: [1],
        acknowledgedChanges: [{ code: 'type_changed', path: '/attributes/amount' }],
        operations: [{ op: 'convert', path: ['amount'], conversion: 'textToDecimal', onMissing: 'error' }] },
      owner: { default: 'preserve', overrides: [] }, lifecycle: { onUnmapped: 'preserve', mappings: [] },
    },
  }) }];
  fails(constructRelationGraphProposal(proposalInput(input)), 'format');
  const bad = structuredClone(proposalInput(input));
  (bad.changeSet.relationTargets[0].plan.transform!.attributes.operations[0] as any).op = 'execute';
  assert.equal(constructRelationGraphProposal(bad).ok, false);
});

test('proposal envelopes never evaluate getters and cannot smuggle undeclared endpoint or preparation changes', () => {
  let invoked = false;
  const input = proposalInput(repair());
  Object.defineProperty(input, 'proposedEndpoints', { enumerable: true, get() { invoked = true; throw new Error('must not execute'); } });
  fails(constructRelationGraphProposal(input), 'invalid_json'); assert.equal(invoked, false);
  fails(constructRelationGraphProposal(Object.create(proposalInput(repair()))), 'invalid_json');
  fails(constructRelationGraphProposal({ ...proposalInput(repair()), invented: true } as any), 'unknown_field');
  const changed = { ...proposalInput(repair()), proposedEndpoints: [asset(a, { assetVersion: 2 }), asset(b)] };
  fails(constructRelationGraphProposal(changed), 'invalid_definition', '/migration/endpoints');
  fails(validateRelationGraphChange({ ...repair(), proposed: graph({ endpoints: changed.proposedEndpoints }) }), 'invalid_definition', '/migration/endpoints');
  const sparse = proposalInput(repair()); delete (sparse.before.endpoints as any)[0];
  fails(constructRelationGraphProposal(sparse), 'invalid_json');
});

test('proposal input and retained result share the aggregate byte budget and output revisions stay bounded', () => {
  const attributes = Object.fromEntries(['one', 'two', 'three', 'four'].map(key => [key, 'x'.repeat(50_000)]));
  const fields = Object.fromEntries(Object.keys(attributes).map(key => [key, { type: 'text' as const }]));
  const before = graph({ edges: [edge(a, b, { values: values({ attributes }) })] });
  const input = withPlan(repair({ before, proposed: before, policies: [policy(definition({ attributes: fields }))] }),
    plan({ edges: [{ relationId: id(100), expectedVersion: 1, action: 'repair', values: values({ attributes }) }] }));
  fails(constructRelationGraphProposal(proposalInput(input)), 'limit', '/migration/proposal');
  const exhausted = withPlan(repair({ before: graph({ edges: [edge(a, b, { version: 2_147_483_647 })] }) }),
    plan({ edges: [{ relationId: id(100), expectedVersion: 2_147_483_647, action: 'repair', values: values() }] }));
  fails(constructRelationGraphProposal(proposalInput(exhausted)), 'model_version');
});
