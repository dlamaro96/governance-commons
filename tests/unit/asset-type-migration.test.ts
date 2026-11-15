// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import { resolveAssetType, type AssetTypeDefinition, type ResolvedAssetType } from '../../packages/domain/src/asset-type.ts';
import { ASSET_TYPE_MIGRATION_LIMITS, applyAssetTypeMigrationPolicy, parseAssetTypeMigrationFile, parseAssetTypeMigrationPlan,
  validateAssetTypeMigrationPlan, type AssetTypeMigrationPlan, type AssetTypeMigrationScope } from '../../packages/domain/src/asset-type-migration.ts';
import { applyModelMigrationToAttributes } from '../../packages/domain/src/model-migration.ts';
import { type ValidationResult } from '../../packages/domain/src/model.ts';

const typeId = '11111111-1111-4111-8111-111111111111';
const assetA = 'aaaaaaaa-0000-4000-8000-000000000001', assetB = 'bbbbbbbb-0000-4000-8000-000000000002';
const ownerA = 'cccccccc-0000-4000-8000-000000000001', ownerB = 'dddddddd-0000-4000-8000-000000000002';
const lifecycle = { initial: 'draft', states: ['draft', 'active', 'retired'], transitions: [{ from: 'draft', to: 'active' }] };
function ok<T>(result: ValidationResult<T>): T {
  assert.equal(result.ok, true, result.ok ? 'Expected success' : JSON.stringify(result.issues));
  if (!result.ok) throw new Error('Expected success');
  return result.value;
}
function fails(result: ValidationResult<unknown>, code?: string, path?: string): void {
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.ok(result.issues.length <= ASSET_TYPE_MIGRATION_LIMITS.issues);
  if (code) assert.ok(result.issues.some(item => item.code === code && (path === undefined || item.path === path)), JSON.stringify(result.issues));
}
function definition(version: number, overrides: Partial<AssetTypeDefinition> = {}): AssetTypeDefinition {
  return { formatVersion: 1, id: 'Invoice', version, attributes: { title: { type: 'text' } }, parents: [], overrideAttributes: [], requiredOwner: false, lifecycle, ...overrides };
}
function resolved(version: number, overrides: Partial<AssetTypeDefinition> = {}, parents: AssetTypeDefinition[] = []): ResolvedAssetType {
  return ok(resolveAssetType(definition(version, overrides), parents));
}
function plan(overrides: Partial<AssetTypeMigrationPlan> = {}): AssetTypeMigrationPlan {
  return { formatVersion: 1, typeId, attributes: { formatVersion: 1, modelId: 'Invoice', targetVersion: 3, sourceVersions: [1, 2], acknowledgedChanges: [], operations: [] },
    owner: { default: 'preserve', overrides: [] }, lifecycle: { onUnmapped: 'preserve', mappings: [] }, acknowledgedPolicyChanges: [], ...overrides };
}
function scope(overrides: Partial<AssetTypeMigrationScope> = {}): AssetTypeMigrationScope {
  return { typeId, head: resolved(2), target: resolved(3), sources: [resolved(1), resolved(2)], cohort: [{ assetId: assetA, sourceVersion: 1 }, { assetId: assetB, sourceVersion: 2 }], ...overrides };
}
function apply(overrides: Partial<Parameters<typeof applyAssetTypeMigrationPolicy>[0]> = {}) {
  return applyAssetTypeMigrationPolicy({ source: resolved(1), target: resolved(3), plan: plan(),
    asset: { assetId: assetA, modelVersion: 1, ownerId: ownerA, state: 'draft' }, activeOwnerIds: new Set([ownerA, ownerB]), ...overrides });
}

test('nullable owner plans round-trip, sort explicit collections and deeply freeze defensive copies', () => {
  const input = plan({ owner: { default: 'preserve', overrides: [{ assetId: assetB, ownerId: null }, { assetId: assetA, ownerId: ownerA }] },
    lifecycle: { onUnmapped: 'error', mappings: [{ sourceVersion: 2, from: 'active', to: 'retired' }, { sourceVersion: 1, from: 'draft', to: 'active' }] },
    acknowledgedPolicyChanges: ['required_owner_changed', 'parents_changed'] });
  const result = ok(parseAssetTypeMigrationFile(JSON.stringify(input)));
  assert.deepEqual(result.owner.overrides.map(item => item.assetId), [assetA, assetB]);
  assert.deepEqual(result.lifecycle.mappings.map(item => item.sourceVersion), [1, 2]);
  assert.deepEqual(result.acknowledgedPolicyChanges, ['parents_changed', 'required_owner_changed']);
  assert.equal(result.owner.overrides[1].ownerId, null);
  assert.deepEqual(ok(parseAssetTypeMigrationPlan(result)), result);
  assert.deepEqual(ok(parseAssetTypeMigrationFile(JSON.stringify(result))), result);
  for (const item of [result, result.owner, result.owner.overrides, result.owner.overrides[0], result.attributes, result.lifecycle.mappings[0], result.acknowledgedPolicyChanges]) assert.ok(Object.isFrozen(item));
  assert.equal(Object.isFrozen(input), false); assert.equal(Object.isFrozen(input.owner.overrides), false);
});

test('all plan fields are mandatory and unrecognized versions, selectors and policy options fail', () => {
  for (const key of Object.keys(plan())) { const input = { ...plan() } as any; delete input[key]; fails(parseAssetTypeMigrationPlan(input), 'required', '/' + key); }
  fails(parseAssetTypeMigrationPlan({ ...plan(), formatVersion: 2 }), 'invalid_definition', '/formatVersion');
  fails(parseAssetTypeMigrationPlan({ ...plan(), selector: '*' }), 'unknown_field', '/selector');
  fails(parseAssetTypeMigrationPlan({ ...plan(), owner: { default: 'clear', overrides: [] } }), 'enum', '/owner/default');
  fails(parseAssetTypeMigrationPlan({ ...plan(), lifecycle: { onUnmapped: 'initial', mappings: [] } }), 'enum', '/lifecycle/onUnmapped');
  fails(parseAssetTypeMigrationPlan({ ...plan(), acknowledgedPolicyChanges: ['all'] }), 'enum');
  fails(parseAssetTypeMigrationPlan({ ...plan(), acknowledgedPolicyChanges: ['parents_changed', 'parents_changed'] }), 'duplicate');
  fails(parseAssetTypeMigrationPlan({ ...plan(), typeId: typeId.toUpperCase().replace('1111', 'AAAA') }), 'format', '/typeId');
});

test('nested attribute grammar stays strict, including null literals and 64-operation bound', () => {
  fails(parseAssetTypeMigrationPlan(plan({ attributes: { ...plan().attributes, operations: [{ op: 'set', path: ['title'], value: null as any, mode: 'replace' }] } })), 'type', '/attributes/operations/0/value');
  fails(parseAssetTypeMigrationPlan(plan({ attributes: { ...plan().attributes, sourceVersions: [2, 1] } })), 'invalid_definition');
  fails(parseAssetTypeMigrationPlan(plan({ attributes: { ...plan().attributes, operations: Array.from({ length: 65 }, () => ({ op: 'remove' as const, path: ['title'], onMissing: 'skip' as const })) } })), 'limit');
  ok(parseAssetTypeMigrationPlan(plan({ attributes: { ...plan().attributes, operations: Array.from({ length: 64 }, () => ({ op: 'remove' as const, path: ['title'], onMissing: 'skip' as const })) } })));
  fails(parseAssetTypeMigrationPlan(plan({ attributes: { ...plan().attributes, targetVersion: 2_147_483_648 } })), 'model_version', '/attributes/targetVersion');
});

test('overrides and source-state mappings reject duplicates, malformed IDs and incoherent pins', () => {
  fails(parseAssetTypeMigrationPlan(plan({ owner: { default: 'preserve', overrides: [{ assetId: assetA, ownerId: ownerA }, { assetId: assetA, ownerId: null }] } })), 'duplicate');
  for (const ownerId of [undefined, false, 'owner', 0]) fails(parseAssetTypeMigrationPlan({ ...plan(), owner: { default: 'preserve', overrides: [{ assetId: assetA, ownerId }] } }), ownerId === undefined ? 'invalid_json' : 'format');
  const mapping = { sourceVersion: 1, from: 'draft', to: 'active' };
  fails(parseAssetTypeMigrationPlan(plan({ lifecycle: { onUnmapped: 'preserve', mappings: [mapping, { ...mapping, to: 'retired' }] } })), 'duplicate');
  fails(parseAssetTypeMigrationPlan(plan({ lifecycle: { onUnmapped: 'preserve', mappings: [{ ...mapping, sourceVersion: 4 }] } })), 'model_version');
  fails(parseAssetTypeMigrationPlan(plan({ lifecycle: { onUnmapped: 'preserve', mappings: [{ ...mapping, from: '__proto__' }] } })), 'format');
  for (const sourceVersion of [0, -0, -1, 1.5, 2_147_483_648, Infinity]) fails(parseAssetTypeMigrationPlan(plan({ lifecycle: { onUnmapped: 'preserve', mappings: [{ ...mapping, sourceVersion }] } })));
});

test('file parser rejects duplicate escaped keys at every depth before overwrite', () => {
  const text = JSON.stringify(plan());
  fails(parseAssetTypeMigrationFile(text.replace('"typeId":', '"type\\u0049d":"00000000-0000-4000-8000-000000000000","typeId":')), 'duplicate', '/typeId');
  fails(parseAssetTypeMigrationFile(text.replace('"default":"preserve"', '"default":"preserve","defa\\u0075lt":"preserve"')), 'duplicate', '/owner/default');
  fails(parseAssetTypeMigrationFile(text.replace('"targetVersion":3', '"targetVersion":3,"targetVersion":4')), 'duplicate', '/attributes/targetVersion');
  for (const invalid of ['{', text + 'null', text.replace('"preserve"', 'undefined'), text.replace('"preserve"', '"unterminated')]) fails(parseAssetTypeMigrationFile(invalid), 'invalid_json');
});

test('getters, toJSON, symbol keys, prototypes, cycles and sparse arrays are rejected without execution', () => {
  let calls = 0;
  const getter = { ...plan() }; Object.defineProperty(getter, 'owner', { enumerable: true, get() { calls += 1; throw new Error('executed'); } });
  fails(parseAssetTypeMigrationPlan(getter), 'invalid_json', '/owner');
  const overrides: any[] = [{ assetId: assetA, ownerId: null }]; Object.defineProperty(overrides, '0', { enumerable: true, get() { calls += 1; return {}; } });
  fails(parseAssetTypeMigrationPlan({ ...plan(), owner: { default: 'preserve', overrides } }), 'invalid_json');
  fails(parseAssetTypeMigrationPlan({ ...plan(), toJSON() { calls += 1; return plan(); } }), 'invalid_json');
  fails(parseAssetTypeMigrationPlan({ ...plan(), [Symbol('hidden')]: true }), 'invalid_json');
  fails(parseAssetTypeMigrationPlan(Object.assign(Object.create({ hidden: true }), plan())), 'invalid_json');
  fails(parseAssetTypeMigrationPlan({ ...plan(), owner: { default: 'preserve', overrides: new Array(1) } }), 'invalid_json');
  const cycle: any = { ...plan() }; cycle.owner = cycle; fails(parseAssetTypeMigrationPlan(cycle), 'cycle');
  const array: any = []; array.extra = true; fails(parseAssetTypeMigrationPlan({ ...plan(), acknowledgedPolicyChanges: array }), 'invalid_json');
  const invisible = { ...plan() }; Object.defineProperty(invisible, 'hidden', { value: true, enumerable: false }); fails(parseAssetTypeMigrationPlan(invisible), 'invalid_json');
  const proto = JSON.parse(JSON.stringify(plan()).replace('"typeId":', '"__proto__":{},"typeId":')); fails(parseAssetTypeMigrationPlan(proto), 'invalid_json');
  assert.equal(calls, 0);
  ok(parseAssetTypeMigrationPlan(Object.assign(Object.create(null), plan())));
});

test('file, string, node, depth, byte and collection budgets fail without partial results', () => {
  fails(parseAssetTypeMigrationFile(' '.repeat(ASSET_TYPE_MIGRATION_LIMITS.bytes + 1)), 'limit');
  fails(parseAssetTypeMigrationFile('"' + '😀'.repeat(140_000) + '"'), 'limit');
  fails(parseAssetTypeMigrationPlan({ ...plan(), typeId: 'x'.repeat(65_537) }), 'limit');
  const overrides = Array.from({ length: 1_001 }, (_, index) => ({ assetId: `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`, ownerId: null }));
  fails(parseAssetTypeMigrationPlan(plan({ owner: { default: 'preserve', overrides } })), 'limit', '/owner/overrides');
  ok(parseAssetTypeMigrationPlan(plan({ owner: { default: 'preserve', overrides: overrides.slice(0, 1_000) } })));
  fails(parseAssetTypeMigrationPlan(plan({ lifecycle: { onUnmapped: 'preserve', mappings: Array.from({ length: 1_001 }, (_, index) => ({ sourceVersion: 1, from: `s${index}`, to: 'draft' })) } })), 'limit', '/lifecycle/mappings');
  let nested: unknown = true; for (let i = 0; i < 30; i += 1) nested = { next: nested };
  fails(parseAssetTypeMigrationPlan({ ...plan(), extra: nested }), 'limit');
  fails(parseAssetTypeMigrationFile(JSON.stringify({ ...plan(), extra: nested })), 'limit');
  const large = Array.from({ length: 10 }, () => ({ op: 'set', path: ['title'], value: '😀'.repeat(15_000), mode: 'replace' }));
  fails(parseAssetTypeMigrationPlan({ ...plan(), attributes: { ...plan().attributes, operations: large } }), 'limit');
  // 102,400 primitive values fit below the byte ceiling but exceed the aggregate node bound.
  fails(parseAssetTypeMigrationPlan({ ...plan(), extra: Array.from({ length: 100 }, () => Array(1_024).fill(0)) }), 'limit');
});

test('scope requires exact cohort pins, immutable identity, source completeness and unique assets', () => {
  ok(validateAssetTypeMigrationPlan(scope(), plan()));
  fails(validateAssetTypeMigrationPlan(scope({ typeId: ownerA }), plan()), 'model_identity', '/plan/typeId');
  fails(validateAssetTypeMigrationPlan(scope({ sources: [resolved(1)] }), plan()), 'required', '/sources');
  fails(validateAssetTypeMigrationPlan(scope({ sources: [resolved(1), resolved(2), resolved(2)] }), plan()), 'duplicate');
  fails(validateAssetTypeMigrationPlan(scope({ cohort: [{ assetId: assetA, sourceVersion: 1 }] }), plan()), 'model_version');
  fails(validateAssetTypeMigrationPlan(scope({ cohort: [{ assetId: assetA, sourceVersion: 1 }, { assetId: assetA, sourceVersion: 2 }] }), plan()), 'duplicate');
  fails(validateAssetTypeMigrationPlan(scope({ sources: [resolved(1, { id: 'Foreign' }), resolved(2)] }), plan()), 'model_identity');
  fails(validateAssetTypeMigrationPlan(scope({ sources: [resolved(1), resolved(2, { attributes: {} })] }), plan()), 'invalid_definition');
  fails(validateAssetTypeMigrationPlan(scope(), plan({ attributes: { ...plan().attributes, targetVersion: 4 } })), 'model_version');
});

test('zero-asset scopes still validate the whole schema and exact policy acknowledgements', () => {
  const empty = scope({ sources: [], cohort: [] }); const emptyPlan = plan({ attributes: { ...plan().attributes, sourceVersions: [] } });
  ok(validateAssetTypeMigrationPlan(empty, emptyPlan));
  fails(validateAssetTypeMigrationPlan({ ...empty, sources: [resolved(1)] }, emptyPlan), 'model_version');
  fails(validateAssetTypeMigrationPlan(empty, { ...emptyPlan, acknowledgedPolicyChanges: ['lifecycle_changed'] }), 'invalid_definition');
  const target = resolved(3, { requiredOwner: true, lifecycle: { initial: 'new', states: ['new'], transitions: [] }, attributes: {} });
  fails(validateAssetTypeMigrationPlan({ ...empty, target }, emptyPlan), 'required');
  ok(validateAssetTypeMigrationPlan({ ...empty, target }, { ...emptyPlan, attributes: { ...emptyPlan.attributes, acknowledgedChanges: [{ code: 'attribute_removed', path: '/attributes/title' }] }, acknowledgedPolicyChanges: ['required_owner_changed', 'lifecycle_changed'] }));
});

test('head-to-target parent pins and policy acknowledgement are exact and independent of old source policies', () => {
  const oldParent = definition(1, { id: 'Parent', attributes: {}, requiredOwner: true });
  const newParent = { ...oldParent, version: 2 };
  const head = resolved(2, { parents: [{ id: 'Parent', version: 1 }], requiredOwner: false, lifecycle: null }, [oldParent]);
  const target = resolved(3, { parents: [{ id: 'Parent', version: 2 }], lifecycle: null }, [newParent]);
  const current = scope({ head, target, sources: [resolved(1), head] });
  fails(validateAssetTypeMigrationPlan(current, plan()), 'required', '/plan/acknowledgedPolicyChanges');
  ok(validateAssetTypeMigrationPlan(current, plan({ acknowledgedPolicyChanges: ['parents_changed'] })));
  fails(validateAssetTypeMigrationPlan(current, plan({ acknowledgedPolicyChanges: ['parents_changed', 'required_owner_changed'] })), 'invalid_definition');
});

test('scope excludes non-cohort overrides, absent source states and illegal target states', () => {
  fails(validateAssetTypeMigrationPlan(scope(), plan({ owner: { default: 'preserve', overrides: [{ assetId: ownerA, ownerId: ownerB }] } })), 'invalid_definition');
  const target = resolved(3, { requiredOwner: true });
  fails(validateAssetTypeMigrationPlan(scope({ target }), plan({ owner: { default: 'preserve', overrides: [{ assetId: assetA, ownerId: null }] }, acknowledgedPolicyChanges: ['required_owner_changed'] })), 'required');
  for (const [from, to] of [['missing', 'draft'], ['draft', 'missing']]) fails(validateAssetTypeMigrationPlan(scope(), plan({ lifecycle: { onUnmapped: 'preserve', mappings: [{ sourceVersion: 1, from, to }] } })), 'enum');
});

test('mapping a historical lifecycle does not invent a head-to-target change or require an ordinary transition edge', () => {
  const old = resolved(1, { lifecycle: { initial: 'legacy', states: ['legacy'], transitions: [] } });
  const mappingPlan = plan({ lifecycle: { onUnmapped: 'preserve', mappings: [{ sourceVersion: 1, from: 'legacy', to: 'retired' }] } });
  ok(validateAssetTypeMigrationPlan(scope({ sources: [old, resolved(2)] }), mappingPlan));
  assert.deepEqual(ok(apply({ source: old, plan: mappingPlan, asset: { assetId: assetA, modelVersion: 1, ownerId: null, state: 'legacy' } })), { ownerId: null, state: 'retired', sourceIssues: [] });
  fails(validateAssetTypeMigrationPlan(scope({ sources: [old, resolved(2)] }), { ...mappingPlan, acknowledgedPolicyChanges: ['lifecycle_changed'] }), 'invalid_definition');
});

test('required owner repair succeeds only through an active replacement or acknowledged policy removal', () => {
  const source = resolved(1, { requiredOwner: true }); const target = resolved(3, { requiredOwner: true });
  const asset = { assetId: assetA, modelVersion: 1, ownerId: ownerA, state: 'draft' };
  const activeOwnerIds = new Set([ownerB]);
  fails(apply({ source, target, asset, activeOwnerIds }), 'required', '/source/ownerId');
  const replacement = plan({ owner: { default: 'preserve', overrides: [{ assetId: assetA, ownerId: ownerB }] } });
  const repaired = ok(apply({ source, target, asset, activeOwnerIds, plan: replacement }));
  assert.equal(repaired.ownerId, ownerB); assert.equal(repaired.sourceIssues.length, 1); assert.equal(repaired.sourceIssues[0].path, '/source/ownerId');
  const missing = ok(apply({ source, target, asset: { ...asset, ownerId: null }, activeOwnerIds, plan: replacement })); assert.equal(missing.ownerId, ownerB);
  const removed = ok(apply({ source, asset, activeOwnerIds, plan: plan({ acknowledgedPolicyChanges: ['required_owner_changed'] }) }));
  assert.equal(removed.ownerId, ownerA); assert.equal(removed.sourceIssues.length, 1);
  const cleared = ok(apply({ source, asset, activeOwnerIds, plan: plan({ acknowledgedPolicyChanges: ['required_owner_changed'], owner: { default: 'preserve', overrides: [{ assetId: assetA, ownerId: null }] } }) })); assert.equal(cleared.ownerId, null);
  fails(apply({ source, asset, activeOwnerIds }), 'required', '/source/ownerId');
});

test('optional target ownership never permits an inactive explicit non-null replacement', () => {
  const activeOwnerIds = new Set<string>();
  assert.equal(ok(apply({ activeOwnerIds })).ownerId, ownerA, 'Preserved inactive owner is legal for an optional source and target.');
  fails(apply({ activeOwnerIds, plan: plan({ owner: { default: 'preserve', overrides: [{ assetId: assetA, ownerId: ownerA }] } }) }), 'required', '/target/ownerId');
  assert.equal(ok(apply({ activeOwnerIds, plan: plan({ owner: { default: 'preserve', overrides: [{ assetId: assetA, ownerId: null }] } }) })).ownerId, null);
  fails(apply({ activeOwnerIds, target: resolved(3, { requiredOwner: true }) }), 'required', '/target/ownerId');
});

test('corrupt source states, mismatched pins and missing lifecycle mappings fail before policy repair', () => {
  for (const state of [null, 'unknown', '']) fails(apply({ asset: { assetId: assetA, modelVersion: 1, ownerId: ownerA, state } }), 'enum', '/asset/state');
  fails(apply({ asset: { assetId: assetA, modelVersion: 2, ownerId: ownerA, state: 'draft' } }), 'model_version');
  fails(apply({ plan: plan({ lifecycle: { onUnmapped: 'error', mappings: [] } }) }), 'required', '/target/state');
  const target = resolved(3, { lifecycle: { initial: 'other', states: ['other'], transitions: [] } });
  fails(apply({ target }), 'enum', '/target/state');
  assert.equal(ok(apply({ target, plan: plan({ lifecycle: { onUnmapped: 'error', mappings: [{ sourceVersion: 1, from: 'draft', to: 'other' }] } }) })).state, 'other');
});

test('combined historical pins, changed ancestry, attribute rename, ownership repair and state mapping compose exactly', () => {
  const oldParent = definition(1, { id: 'Parent', attributes: { title: { type: 'text', required: true } }, requiredOwner: true,
    lifecycle: { initial: 'legacy', states: ['legacy'], transitions: [] } });
  const newParent = definition(2, { id: 'Parent', attributes: { name: { type: 'text', required: true } }, requiredOwner: true });
  const source = resolved(1, { parents: [{ id: 'Parent', version: 1 }], attributes: {}, lifecycle: null }, [oldParent]);
  const head = resolved(2, { requiredOwner: true });
  const target = resolved(3, { parents: [{ id: 'Parent', version: 2 }], attributes: {}, lifecycle: null }, [newParent]);
  const migration = plan({ attributes: { ...plan().attributes, acknowledgedChanges: [{ code: 'attribute_removed', path: '/attributes/title' }], operations: [{ op: 'rename', from: ['title'], to: ['name'], onMissing: 'error' }] },
    owner: { default: 'preserve', overrides: [{ assetId: assetA, ownerId: ownerB }] }, lifecycle: { onUnmapped: 'preserve', mappings: [{ sourceVersion: 1, from: 'legacy', to: 'active' }] }, acknowledgedPolicyChanges: ['parents_changed'] });
  const checked = ok(validateAssetTypeMigrationPlan(scope({ head, target, sources: [source, head] }), migration));
  const before = JSON.stringify({ source, head, target, checked });
  const attributes = ok(applyModelMigrationToAttributes({ head: head.model, source: source.model, target: target.model, plan: checked.attributes, attributes: { title: 'Synthetic invoice' } }));
  const result = ok(apply({ source, target, plan: checked, asset: { assetId: assetA, modelVersion: 1, ownerId: ownerA, state: 'legacy' }, activeOwnerIds: new Set([ownerB]) }));
  assert.deepEqual(attributes, { name: 'Synthetic invoice' }); assert.equal(result.ownerId, ownerB); assert.equal(result.state, 'active'); assert.equal(result.sourceIssues.length, 1);
  assert.deepEqual(ok(apply({ source: head, target, plan: checked, asset: { assetId: assetB, modelVersion: 2, ownerId: ownerB, state: 'retired' } })), { ownerId: ownerB, state: 'retired', sourceIssues: [] });
  assert.equal(JSON.stringify({ source, head, target, checked }), before);
});

test('scope definitions share aggregate budgets and resolved-envelope corruption fails closed', () => {
  const large = resolved(1, { attributes: { large: { type: 'enum', values: Array.from({ length: 60 }, (_, index) => String(index).padStart(3, '0') + 'x'.repeat(997)) } } });
  const sources = Array.from({ length: 10 }, (_, index) => ({ ...large, definition: { ...large.definition, version: index + 1 }, model: { ...large.model, version: index + 1 } }));
  fails(validateAssetTypeMigrationPlan(scope({ sources }), plan()), 'limit');
  fails(validateAssetTypeMigrationPlan(scope({ target: { ...resolved(3, { requiredOwner: true }), requiredOwner: false } }), plan()), 'invalid_definition');
  fails(validateAssetTypeMigrationPlan(scope({ target: { ...resolved(3), model: { ...resolved(3).model, id: 'Other' } } }), plan()), 'model_identity');
  fails(validateAssetTypeMigrationPlan(scope({ target: { ...resolved(3), lifecycle: { initial: 'other', states: ['other'], transitions: [] } } }), plan()), 'invalid_definition');
  const bad: any = scope(); Object.defineProperty(bad, 'head', { enumerable: true, get() { throw new Error('must not execute'); } });
  fails(validateAssetTypeMigrationPlan(bad, plan()), 'invalid_json');
});

test('large malformed cohorts report bounded complete failure instead of partial accepted plans', () => {
  const cohort = Array.from({ length: 1_000 }, () => ({ assetId: 'invalid', sourceVersion: 0 }));
  const result = validateAssetTypeMigrationPlan(scope({ cohort }), plan());
  fails(result, 'limit');
  if (!result.ok) { assert.equal(result.issues.length, 1_000); assert.equal(result.issues.at(-1)?.code, 'limit'); }
});

test('policy transforms do not execute outer accessors or overridden set methods', () => {
  let calls = 0;
  const input: any = { source: resolved(1), target: resolved(3), plan: plan(), asset: { assetId: assetA, modelVersion: 1, ownerId: ownerA, state: 'draft' }, activeOwnerIds: new Set([ownerA]) };
  const getter = { ...input }; Object.defineProperty(getter, 'plan', { enumerable: true, get() { calls += 1; throw new Error('executed'); } });
  fails(applyAssetTypeMigrationPolicy(getter), 'invalid_json');
  const active = new Set([ownerA]); Object.defineProperty(active, 'has', { get() { calls += 1; throw new Error('executed'); } });
  assert.equal(ok(applyAssetTypeMigrationPolicy({ ...input, activeOwnerIds: active })).ownerId, ownerA);
  fails(applyAssetTypeMigrationPolicy({ ...input, activeOwnerIds: { has() { calls += 1; return true; } } }), 'invalid_json');
  assert.equal(calls, 0);
});
