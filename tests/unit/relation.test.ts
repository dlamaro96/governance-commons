// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { resolveAssetType, type AssetTypeDefinition } from '../../packages/domain/src/asset-type.ts';
import { validateAttributes, type ValidationResult } from '../../packages/domain/src/model.ts';
import { RELATION_LIMITS, parseRelationTypeDefinition, parseRelationTypeFile, resolveRelationType, parseRelationValidity,
  validateRelationEndpoints, validateRelationEndpointChanges, validateRelationStructure, previewRelationTypeUpgrade, traverseAuthorizedRelations } from '../../packages/domain/src/relation.ts';
import type { RelationTypeDefinition, RelationEndpointPolicyState, RelationConstraintEdge, RelationPolicyPin, RelationView,
  RelationEndpointView, AuthorizedRelationTraversalInput, RelationUpgradeBinding } from '../../packages/domain/src/relation-contracts.ts';

const id = (n: number) => `00000000-0000-0000-0000-${n.toString(16).padStart(12, '0')}`;
const typeA = id(1), typeB = id(2), relationType = id(3), actor = id(4);
const time = '2026-11-15T12:00:00.000Z';
const lifecycle = { initial: 'draft', states: ['draft', 'active', 'retired'], transitions: [{ from: 'draft', to: 'active' }, { from: 'active', to: 'retired' }] };
function ok<T>(result: ValidationResult<T>): T { if (!result.ok) assert.fail(JSON.stringify(result.issues)); return result.value; }
function fails(result: ValidationResult<unknown>, code: string, path?: string): void {
  assert.equal(result.ok, false); if (result.ok) return;
  assert.ok(result.issues.some(issue => issue.code === code && (path === undefined || issue.path === path)), JSON.stringify(result.issues));
  assert.ok(result.issues.length <= RELATION_LIMITS.issues);
}
function definition(change: Partial<RelationTypeDefinition> = {}): RelationTypeDefinition {
  return { formatVersion: 1, id: 'depends_on', version: 1, label: 'Depends on', inverseLabel: 'Supports', direction: 'directed',
    sourceTypes: [{ typeId: typeA, includeDescendants: false }], targetTypes: [{ typeId: typeA, includeDescendants: false }],
    sourceStates: null, targetStates: null, cardinality: { outgoing: { min: 0, max: null }, incoming: { min: 0, max: null } },
    allowSelf: false, cycles: 'allow', attributes: {}, requiredOwner: false, lifecycle: structuredClone(lifecycle), ...change };
}
const pin = (value = definition()) => ({ relationTypeId: relationType, policy: ok(resolveRelationType(value)) });
function asset(assetId = id(10), changes: Partial<RelationEndpointPolicyState> = {}): RelationEndpointPolicyState {
  const authored: AssetTypeDefinition = { formatVersion: 1, id: 'Dataset', version: 1, parents: [], attributes: {}, overrideAttributes: [], requiredOwner: false, lifecycle };
  return { assetId, assetVersion: 1, modelId: 'Dataset', modelVersion: 1, state: 'draft', typeId: typeA, policy: ok(resolveAssetType(authored, [])), ancestorTypes: [], ...changes };
}
function edge(source = id(10), target = id(11), changes: Partial<RelationConstraintEdge> = {}): RelationConstraintEdge {
  return { id: id(100), version: 1, relationTypeId: relationType, relationTypeVersion: 1, sourceAssetId: source, targetAssetId: target, ...changes };
}
function node(assetId: string): RelationEndpointView {
  return { assetId, assetVersion: 1, name: `Synthetic ${assetId}`, typeId: typeA, modelId: 'Dataset', modelVersion: 1, state: 'draft' };
}
function view(source: string, target: string, changes: Partial<RelationView> = {}): RelationView {
  return { id: id(100), version: 1, relationTypeId: relationType, relationTypeKey: 'depends_on', relationTypeVersion: 1,
    source: node(source), target: node(target), direction: 'directed', label: 'Depends on', inverseLabel: 'Supports', attributes: {}, ownerId: null, state: 'draft',
    validFrom: null, validTo: null, visibility: 'tenant', allowedIdentityIds: [], status: 'active',
    provenance: { origin: 'asserted', source: { kind: 'manual', identityId: actor }, authority: 'manual-assertion', precedence: null,
      actorId: actor, assertedAt: time, ingestedAt: time, sourceObservedAt: null, sourceVersion: null, sourceRunId: null, confidence: null },
    createdAt: time, createdBy: actor, updatedAt: time, updatedBy: actor, ...changes };
}
function graph(edges: RelationView[], change: Partial<AuthorizedRelationTraversalInput> = {}): AuthorizedRelationTraversalInput {
  const nodes = [...new Map(edges.flatMap(edge => [[edge.source.assetId, edge.source], [edge.target.assetId, edge.target]] as const)).values()];
  return { rootAssetId: id(10), direction: 'out', depth: 3, validAt: time, relationTypeId: null, nodes, edges, completeFrontierAssetIds: nodes.map(node => node.assetId), ...change };
}
function binding(item = edge(), changes: Partial<RelationUpgradeBinding> = {}): RelationUpgradeBinding {
  return { edge: item, attributes: {}, ownerId: null, state: 'draft', source: asset(item.sourceAssetId), target: asset(item.targetAssetId), ...changes };
}

test('relation definitions round-trip all typed fields, exact decimals and immutable normalized endpoint/state sets', () => {
  const authored = definition({ sourceTypes: [{ typeId: typeB, includeDescendants: true }, { typeId: typeA, includeDescendants: false }],
    sourceStates: ['retired', 'draft'], label: 'علاقة 📚', attributes: { amount: { type: 'decimal', precision: 50, scale: 20, required: true },
      metadata: { type: 'object', properties: { at: { type: 'timestamp' }, tags: { type: 'list', items: { type: 'text' } } } } } });
  const parsed = ok(parseRelationTypeFile(JSON.stringify(authored)));
  assert.deepEqual(parsed.sourceTypes.map(rule => rule.typeId), [typeA, typeB]); assert.deepEqual(parsed.sourceStates, ['draft', 'retired']);
  assert.deepEqual(ok(parseRelationTypeFile(JSON.stringify(parsed))), parsed);
  const resolved = ok(resolveRelationType(parsed));
  const exact = '12345678901234567890.1234567890123456789';
  assert.equal(ok(validateAttributes(resolved.model, { amount: exact })).amount, exact);
  assert.ok(Object.isFrozen(parsed) && Object.isFrozen(parsed.sourceTypes) && Object.isFrozen(parsed.sourceTypes[0]) && Object.isFrozen(resolved.model.attributes));
  assert.equal(Object.isFrozen(authored), false); assert.equal(authored.sourceTypes[0].typeId, typeB);
});

test('relation files reject duplicate escaped keys, UTF-8 overflow, invalid Unicode and raw JSON syntax', () => {
  const source = JSON.stringify(definition());
  fails(parseRelationTypeFile(source.replace('"cycles":"allow"', '"cycles":"allow","cyc\\u006ces":"acyclic"')), 'duplicate', '/cycles');
  fails(parseRelationTypeFile(source.replace('"min":0', '"min":0,"mi\\u006e":1')), 'duplicate');
  fails(parseRelationTypeFile('{'), 'invalid_json');
  fails(parseRelationTypeFile(' '.repeat(RELATION_LIMITS.definitionBytes + 1)), 'limit');
  const manyBytes = JSON.stringify(definition({ attributes: { value: { type: 'enum', values: Array.from({ length: 200 }, (_, n) => `${n}${'界'.repeat(500)}`) } } }));
  assert.ok(manyBytes.length < RELATION_LIMITS.definitionBytes); assert.ok(Buffer.byteLength(manyBytes) > RELATION_LIMITS.definitionBytes);
  fails(parseRelationTypeFile(manyBytes), 'limit'); fails(parseRelationTypeDefinition(definition({ label: '\uD800' })), 'format');
});

test('every relation field is required, unknowns and unsafe identities fail, cycle default is UI-only', () => {
  for (const name of Object.keys(definition())) { const input: any = definition(); delete input[name]; fails(parseRelationTypeDefinition(input), 'required', `/${name}`); }
  fails(parseRelationTypeDefinition({ ...definition(), code: 'return true' }), 'unknown_field', '/code');
  for (const key of ['__proto__', 'constructor', 'prototype', '0invalid', 'x'.repeat(65)]) fails(parseRelationTypeDefinition(definition({ id: key })), 'format', '/id');
  for (const v of [0, -0, -1, 1.2, 2147483648, Infinity, NaN]) assert.equal(parseRelationTypeDefinition(definition({ version: v })).ok, false);
  fails(parseRelationTypeDefinition({ ...definition(), allowSelf: 'false' }), 'type', '/allowSelf');
  fails(parseRelationTypeDefinition(definition({ label: ' ' })), 'format', '/label');
  ok(parseRelationTypeDefinition(definition({ label: '📚'.repeat(120) })));
  fails(parseRelationTypeDefinition(definition({ label: '📚'.repeat(121) })), 'format', '/label');
  fails(parseRelationTypeDefinition(definition({ sourceTypes: [{ typeId: 'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF', includeDescendants: false }] })), 'format');
});

test('definition parser never calls accessors, array getters, toJSON or prototype methods', () => {
  let calls = 0;
  const getter = Object.defineProperty(definition(), 'label', { enumerable: true, get() { calls++; throw Error('not JSON'); } });
  fails(parseRelationTypeDefinition(getter), 'invalid_json');
  const array: any[] = []; Object.defineProperty(array, '0', { enumerable: true, get() { calls++; return { typeId: typeA, includeDescendants: false }; } });
  fails(parseRelationTypeDefinition({ ...definition(), sourceTypes: array }), 'invalid_json');
  fails(parseRelationTypeDefinition({ ...definition(), toJSON() { calls++; return definition(); } }), 'invalid_json');
  fails(parseRelationTypeDefinition(Object.create(definition())), 'invalid_json');
  const sparse = Array(1); fails(parseRelationTypeDefinition({ ...definition(), sourceTypes: sparse }), 'invalid_json');
  const withSymbol = { ...definition(), [Symbol('hidden')]: true }; fails(parseRelationTypeDefinition(withSymbol), 'invalid_json');
  assert.equal(calls, 0);
  const cyclic: any = definition(); cyclic.attributes.self = cyclic; fails(parseRelationTypeDefinition(cyclic), 'cycle');
  const nullPrototype = Object.assign(Object.create(null), definition()); ok(parseRelationTypeDefinition(nullPrototype));
});

test('relation copying creates own data fields without invoking inherited setters or read-only properties', () => {
  const name = 'relation_inherited_copy_probe';
  const previous = Object.getOwnPropertyDescriptor(Object.prototype, name);
  let calls = 0;
  const hostile: PropertyDescriptor[] = [
    { configurable: true, set() { calls++; throw new Error('inherited setter must not execute'); } },
    { configurable: true, value: 'inherited read-only sentinel', writable: false },
  ];
  for (const descriptor of hostile) {
    const input = definition({ attributes: { [name]: { type: 'object', properties: {
      [name]: { type: 'text' as const }, toString: { type: 'text' as const }, hasOwnProperty: { type: 'text' as const },
    } } } });
    Object.defineProperty(Object.prototype, name, descriptor);
    try {
      const result = parseRelationTypeDefinition(input);
      assert.equal(calls, 0);
      const parsed = ok(result);
      assert.deepEqual(parsed.attributes, input.attributes);
      assert.equal(Object.getPrototypeOf(parsed.attributes), Object.prototype);
      assert.equal(Object.hasOwn(parsed.attributes, name), true);
      const schema = parsed.attributes[name]; assert.equal(schema.type, 'object');
      if (schema.type !== 'object') assert.fail('expected object schema');
      for (const key of [name, 'toString', 'hasOwnProperty']) {
        assert.equal(Object.hasOwn(schema.properties, key), true);
        assert.equal(Object.getOwnPropertyDescriptor(schema.properties, key)?.enumerable, true);
      }
      assert.equal(Object.isFrozen(parsed.attributes), true);
      assert.equal(Object.isFrozen(input.attributes), false);
      assert.equal(Object.getPrototypeOf(parsed.sourceTypes), Array.prototype);
      assert.equal(parsed.sourceTypes.length, 1);
    } finally {
      if (previous) Object.defineProperty(Object.prototype, name, previous);
      else Reflect.deleteProperty(Object.prototype, name);
    }
  }
  assert.equal(Object.getOwnPropertyDescriptor(Object.prototype, name), previous);
});

test('relation copying still rejects reserved prototype keys without changing shared prototypes', () => {
  const before = Object.getOwnPropertyDescriptors(Object.prototype);
  for (const name of ['__proto__', 'constructor', 'prototype']) {
    const input = definition({ attributes: JSON.parse(`{"${name}":{"type":"text"}}`) });
    fails(parseRelationTypeDefinition(input), 'invalid_json');
  }
  assert.deepEqual(Object.getOwnPropertyDescriptors(Object.prototype), before);
});

test('endpoint and state declaration sets are bounded and exact; undirected policies require symmetry', () => {
  fails(parseRelationTypeDefinition(definition({ sourceTypes: [] })), 'required', '/sourceTypes');
  fails(parseRelationTypeDefinition(definition({ sourceTypes: [...definition().sourceTypes, ...definition().sourceTypes] })), 'duplicate');
  fails(parseRelationTypeDefinition(definition({ sourceTypes: Array.from({ length: 33 }, (_, n) => ({ typeId: id(n + 10), includeDescendants: false })) })), 'limit');
  fails(parseRelationTypeDefinition(definition({ sourceStates: [] })), 'required');
  fails(parseRelationTypeDefinition(definition({ sourceStates: ['draft', 'draft'] })), 'duplicate');
  fails(parseRelationTypeDefinition(definition({ sourceStates: ['constructor'] })), 'format');
  ok(parseRelationTypeDefinition(definition({ sourceStates: ['future_descendant_state'] })));
  fails(parseRelationTypeDefinition(definition({ direction: 'undirected', sourceStates: ['draft'] })), 'invalid_definition', '/targetStates');
  fails(parseRelationTypeDefinition(definition({ direction: 'undirected', cardinality: { outgoing: { min: 0, max: 1 }, incoming: { min: 0, max: null } } })), 'invalid_definition', '/cardinality/incoming');
  ok(parseRelationTypeDefinition(definition({ direction: 'undirected', allowSelf: true })));
  fails(parseRelationTypeDefinition(definition({ cycles: 'acyclic', allowSelf: true })), 'invalid_definition', '/allowSelf');
});

test('positive minima stay explicitly unsupported; maximum, lifecycle and own-attribute constraints remain enforced', () => {
  for (const side of ['incoming', 'outgoing'] as const) fails(parseRelationTypeDefinition({ ...definition(), cardinality: { ...definition().cardinality, [side]: { min: 1, max: 5 } } }), 'unsupported', `/cardinality/${side}/min`);
  for (const max of [0, -1, 1.5, 1001, '2']) fails(parseRelationTypeDefinition({ ...definition(), cardinality: { outgoing: { min: 0, max }, incoming: { min: 0, max: null } } }), 'range');
  fails(parseRelationTypeDefinition({ ...definition(), lifecycle: null }), 'invalid_definition', '/lifecycle');
  fails(parseRelationTypeDefinition({ ...definition(), lifecycle: { ...lifecycle, initial: 'missing' } }), 'invalid_definition');
  fails(parseRelationTypeDefinition({ ...definition(), lifecycle: { ...lifecycle, transitions: [{ from: 'draft', to: 'missing' }] } }), 'invalid_definition');
  fails(parseRelationTypeDefinition({ ...definition(), attributes: { unsafe: { type: 'expression', code: '1+1' } } }), 'unknown_type');
});

test('validity is canonical millisecond UTC with strict Gregorian and half-open interval rules', () => {
  for (const validFrom of [null, '0001-01-01T00:00:00.000Z', '2000-02-29T00:00:00.000Z', time]) ok(parseRelationValidity({ validFrom, validTo: null }));
  ok(parseRelationValidity({ validFrom: time, validTo: '9999-12-31T23:59:59.999Z' }));
  for (const invalid of ['0000-01-01T00:00:00.000Z', '1900-02-29T00:00:00.000Z', '2026-02-30T00:00:00.000Z', '2026-01-01T24:00:00.000Z', '2026-01-01T00:00:60.000Z', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00.0000Z', '2026-01-01T00:00:00.000+00:00']) fails(parseRelationValidity({ validFrom: invalid, validTo: null }), 'format', '/validFrom');
  fails(parseRelationValidity({ validFrom: time, validTo: time }), 'range', '/validTo');
  fails(parseRelationValidity({ validFrom: time, validTo: '2026-11-14T00:00:00.000Z' }), 'range');
  let calls = 0; fails(parseRelationValidity(Object.defineProperty({ validTo: null }, 'validFrom', { enumerable: true, get() { calls++; return time; } }) as any), 'invalid_json'); assert.equal(calls, 0);
});

test('endpoint matching uses immutable nominal identity across versions and exact pinned ancestry', () => {
  const source = asset(), target = asset(id(11)); ok(validateRelationEndpoints({ edge: edge(), source, target, policies: [pin()] }));
  const versionTwo = asset(id(10), { modelVersion: 2, policy: ok(resolveAssetType({ ...source.policy!.definition, version: 2 }, [])) });
  ok(validateRelationEndpoints({ edge: edge(), source: versionTwo, target, policies: [pin()] }));
  const childDefinition: AssetTypeDefinition = { ...source.policy!.definition, id: 'Child', parents: [{ id: 'Dataset', version: 1 }], lifecycle: null };
  const child = asset(id(10), { typeId: typeB, modelId: 'Child', policy: ok(resolveAssetType(childDefinition, [source.policy!.definition])), ancestorTypes: [{ typeId: typeA, id: 'Dataset', version: 1 }] });
  fails(validateRelationEndpoints({ edge: edge(), source: child, target, policies: [pin()] }), 'invalid_definition', '/edge/source/typeId');
  const descendantPolicy = pin(definition({ sourceTypes: [{ typeId: typeA, includeDescendants: true }] }));
  ok(validateRelationEndpoints({ edge: edge(), source: child, target, policies: [descendantPolicy] }));
  fails(validateRelationEndpoints({ edge: edge(), source: { ...child, ancestorTypes: [{ typeId: typeA, id: 'Dataset', version: 2 }] }, target, policies: [descendantPolicy] }), 'invalid_definition');
  fails(validateRelationEndpoints({ edge: edge(), source: { ...child, ancestorTypes: [] }, target, policies: [descendantPolicy] }), 'invalid_definition');
  fails(validateRelationEndpoints({ edge: edge(), source: { ...child, typeId: typeA }, target, policies: [descendantPolicy] }), 'duplicate');
  fails(validateRelationEndpoints({ edge: edge(), source: { ...source, modelId: 'Wrong' }, target, policies: [pin()] }), 'model_identity');
});

test('null/untyped endpoints, invalid pinned states and missing exact relation policies fail closed', () => {
  const source = asset(), target = asset(id(11));
  fails(validateRelationEndpoints({ edge: edge(), source: { ...source, typeId: null, policy: null, state: null }, target, policies: [pin()] }), 'invalid_definition');
  fails(validateRelationEndpoints({ edge: edge(), source: { ...source, state: 'unknown' }, target, policies: [pin(definition({ sourceStates: ['unknown'] }))] }), 'enum');
  fails(validateRelationEndpoints({ edge: edge(), source, target, policies: [pin(definition({ sourceStates: ['active'] }))] }), 'enum', '/edge/source/state');
  fails(validateRelationEndpoints({ edge: edge(), source, target, policies: [] }), 'invalid_definition', '/edge');
  fails(validateRelationEndpoints({ edge: edge(id(10), id(10)), source, target: source, policies: [pin()] }), 'invalid_definition');
  ok(validateRelationEndpoints({ edge: edge(id(10), id(10)), source, target: source, policies: [pin(definition({ allowSelf: true }))] }));
});

test('complete proposed endpoint changes validate both final endpoints without mutating original pins', () => {
  const first = asset(), second = asset(id(11));
  const proposed = [first, second].map(before => ({ assetId: before.assetId, expectedAssetVersion: 1, after: { ...before, assetVersion: 2, state: 'active' } }));
  const input = { currentEndpoints: [first, second], proposedEndpoints: proposed, completeIncidentRelations: [edge()], policies: [pin()] };
  ok(validateRelationEndpointChanges(input)); assert.equal(first.state, 'draft'); assert.equal(second.assetVersion, 1);
  fails(validateRelationEndpointChanges({ ...input, proposedEndpoints: [proposed[0], { ...proposed[1], after: { ...proposed[1].after, typeId: null, policy: null, state: null } }] }), 'invalid_definition', '/completeIncidentRelations/0/target/typeId');
  fails(validateRelationEndpointChanges({ ...input, currentEndpoints: [first] }), 'model_version');
  fails(validateRelationEndpointChanges({ ...input, proposedEndpoints: [{ ...proposed[0], expectedAssetVersion: 2 }] }), 'model_version');
  fails(validateRelationEndpointChanges({ ...input, proposedEndpoints: [proposed[0], proposed[0]] }), 'duplicate');
  fails(validateRelationEndpointChanges({ ...input, completeIncidentRelations: [edge(id(12), id(13))] }), 'invalid_definition');
  fails(validateRelationEndpointChanges({ ...input, proposedEndpoints: [proposed[0]], currentEndpoints: [first] }), 'invalid_definition');
});

test('structural uniqueness spans versions and canonical undirected endpoint order', () => {
  const first = pin(), later = pin(definition({ version: 2 }));
  fails(validateRelationStructure({ relationTypeId: relationType, policies: [first, later], completeLiveRelations: [edge(), edge(id(10), id(11), { id: id(101), relationTypeVersion: 2 })] }), 'duplicate');
  ok(validateRelationStructure({ relationTypeId: relationType, policies: [first], completeLiveRelations: [edge(), edge(id(11), id(10), { id: id(101) })] }));
  fails(validateRelationStructure({ relationTypeId: relationType, policies: [pin(definition({ direction: 'undirected' }))], completeLiveRelations: [edge(), edge(id(11), id(10), { id: id(101) })] }), 'duplicate');
  fails(validateRelationStructure({ relationTypeId: relationType, policies: [first], completeLiveRelations: [edge(id(10), id(11), { relationTypeId: id(9) })] }), 'invalid_definition');
  fails(validateRelationStructure({ relationTypeId: relationType, policies: [first, first], completeLiveRelations: [edge()] }), 'duplicate');
});

test('every surviving pinned degree maximum applies and self-relations count exactly once', () => {
  const maximumOne = pin(definition({ cardinality: { outgoing: { min: 0, max: 1 }, incoming: { min: 0, max: null } } })), later = pin(definition({ version: 2 }));
  const relations = [edge(), edge(id(10), id(12), { id: id(101), relationTypeVersion: 2 })];
  fails(validateRelationStructure({ relationTypeId: relationType, policies: [maximumOne, later], completeLiveRelations: relations }), 'range');
  ok(validateRelationStructure({ relationTypeId: relationType, policies: [maximumOne, later], completeLiveRelations: relations.slice(1) }));
  const self = pin(definition({ allowSelf: true, cardinality: { outgoing: { min: 0, max: 1 }, incoming: { min: 0, max: 1 } } }));
  ok(validateRelationStructure({ relationTypeId: relationType, policies: [self], completeLiveRelations: [edge(id(10), id(10))] }));
  const undirected = pin({ ...self.policy.definition, direction: 'undirected' });
  fails(validateRelationStructure({ relationTypeId: relationType, policies: [undirected], completeLiveRelations: [edge(), edge(id(11), id(12), { id: id(101) })] }), 'range');
});

test('directed and undirected cycles obey old pins; long cohorts never use depth cutoff as proof', () => {
  const triangle = [edge(), edge(id(11), id(12), { id: id(101) }), edge(id(12), id(10), { id: id(102) })];
  ok(validateRelationStructure({ relationTypeId: relationType, policies: [pin()], completeLiveRelations: triangle }));
  fails(validateRelationStructure({ relationTypeId: relationType, policies: [pin(definition({ cycles: 'acyclic' }))], completeLiveRelations: triangle }), 'cycle');
  fails(validateRelationStructure({ relationTypeId: relationType, policies: [pin(definition({ cycles: 'acyclic' })), pin(definition({ version: 2 }))], completeLiveRelations: triangle.map((item, index) => ({ ...item, relationTypeVersion: index ? 2 : 1 })) }), 'cycle');
  const forest = pin(definition({ direction: 'undirected', cycles: 'acyclic' }));
  ok(validateRelationStructure({ relationTypeId: relationType, policies: [forest], completeLiveRelations: triangle.slice(0, 2) }));
  fails(validateRelationStructure({ relationTypeId: relationType, policies: [forest], completeLiveRelations: triangle }), 'cycle');
  const chain = Array.from({ length: 1000 }, (_, n) => edge(id(10000 + n), id(10001 + n), { id: id(20000 + n) }));
  const dag = pin(definition({ cycles: 'acyclic' }));
  ok(validateRelationStructure({ relationTypeId: relationType, policies: [dag], completeLiveRelations: chain }));
  fails(validateRelationStructure({ relationTypeId: relationType, policies: [dag], completeLiveRelations: [...chain.slice(0, -1), { ...chain.at(-1)!, targetAssetId: chain[0].sourceAssetId }] }), 'cycle');
  fails(validateRelationStructure({ relationTypeId: relationType, policies: [dag], completeLiveRelations: [...chain, edge()] }), 'limit');
});

test('upgrade preview checks mixed pinned values and preserves pins for compatible labels/optional fields', () => {
  const first = pin(definition({ attributes: { amount: { type: 'decimal', precision: 30, scale: 10, required: true } } }));
  const head = pin({ ...first.policy.definition, version: 2, attributes: { ...first.policy.definition.attributes, note: { type: 'text' } } });
  const target = ok(resolveRelationType({ ...head.policy.definition, version: 3, label: 'Updated label', attributes: { ...head.policy.definition.attributes, optional: { type: 'boolean' } } }));
  const exact = '12345678901234567890.123456789';
  const rows = [binding(edge(), { attributes: { amount: exact } }), binding(edge(id(11), id(12), { id: id(101), relationTypeVersion: 2 }), { attributes: { amount: exact, note: 'Synthetic note' } })];
  const result = ok(previewRelationTypeUpgrade({ relationTypeId: relationType, head: head.policy, target, policies: [first, head], completeLiveRelations: rows, activeOwnerIds: new Set() }));
  assert.equal(result.compatibleWithProvidedRelations, true); assert.equal(result.requiresExplicitMigration, false); assert.equal(result.pinsPreserved, true);
  assert.deepEqual(rows.map(row => row.edge.relationTypeVersion), [1, 2]); assert.ok(Object.isFrozen(result.relations));
  const removed = ok(resolveRelationType({ ...head.policy.definition, version: 3, attributes: {} }));
  const incompatible = ok(previewRelationTypeUpgrade({ relationTypeId: relationType, head: head.policy, target: removed, policies: [first, head], completeLiveRelations: rows, activeOwnerIds: new Set() }));
  assert.equal(incompatible.requiresExplicitMigration, true); assert.equal(incompatible.compatibleWithProvidedRelations, false);
});

test('policy changes require explicit migration even for currently valid rows; no-live publication is allowed', () => {
  const head = pin(), target = ok(resolveRelationType(definition({ version: 2, requiredOwner: true, cardinality: { outgoing: { min: 0, max: 5 }, incoming: { min: 0, max: null } } })));
  const input = { relationTypeId: relationType, head: head.policy, target, policies: [head], completeLiveRelations: [binding(edge(), { ownerId: actor })], activeOwnerIds: new Set([actor]) };
  const result = ok(previewRelationTypeUpgrade(input)); assert.equal(result.compatibleWithProvidedRelations, true); assert.equal(result.requiresExplicitMigration, true);
  assert.equal(ok(previewRelationTypeUpgrade({ ...input, completeLiveRelations: [] })).requiresExplicitMigration, false);
  const inactive = ok(previewRelationTypeUpgrade({ ...input, activeOwnerIds: new Set<string>() })); assert.equal(inactive.compatibleWithProvidedRelations, false); assert.ok(inactive.relations[0].proposedIssues.some(issue => issue.path === '/ownerId'));
  let calls = 0; const safeSet = new Set([actor]); Object.defineProperty(safeSet, 'values', { get() { calls++; throw Error('no getter'); } });
  ok(previewRelationTypeUpgrade({ ...input, activeOwnerIds: safeSet })); assert.equal(calls, 0);
});

test('upgrade structural failure and aggregate issue overflow are explicit', () => {
  const head = pin(), target = ok(resolveRelationType(definition({ version: 2, cycles: 'acyclic' })));
  const triangle = [edge(), edge(id(11), id(12), { id: id(101) }), edge(id(12), id(10), { id: id(102) })].map(item => binding(item));
  const preview = ok(previewRelationTypeUpgrade({ relationTypeId: relationType, head: head.policy, target, policies: [head], completeLiveRelations: triangle, activeOwnerIds: new Set() }));
  assert.equal(preview.requiresExplicitMigration, true); assert.ok(preview.relations.some(row => row.proposedIssues.some(issue => issue.code === 'cycle')));
  const required = ok(resolveRelationType(definition({ version: 2, attributes: Object.fromEntries(Array.from({ length: 101 }, (_, n) => [`required_${n}`, { type: 'text', required: true }])) })));
  fails(previewRelationTypeUpgrade({ relationTypeId: relationType, head: head.policy, target: required, policies: [head], completeLiveRelations: [binding(), binding(edge(id(11), id(12), { id: id(101) }))], activeOwnerIds: new Set() }), 'limit');
});

test('authorized BFS is deterministic, cycle-safe, depth bounded and includes edges from every expanded frontier', () => {
  const a = view(id(10), id(11)), b = view(id(11), id(12), { id: id(101) }), c = view(id(12), id(10), { id: id(102) });
  const one = ok(traverseAuthorizedRelations(graph([c, b, a], { depth: 1 })));
  assert.deepEqual(one.edges.map(item => item.id), [a.id]); assert.deepEqual(one.nodes.map(item => item.assetId), [id(10), id(11)]);
  const all = ok(traverseAuthorizedRelations(graph([c, b, a]))); assert.deepEqual(all.edges.map(item => item.id), [a.id, b.id, c.id]);
  assert.deepEqual(ok(traverseAuthorizedRelations(graph([a, b, c]))), all); assert.ok(Object.isFrozen(all.edges[0].source));
  assert.deepEqual(ok(traverseAuthorizedRelations(graph([a, b, c], { direction: 'in', depth: 1 }))).edges.map(item => item.id), [c.id]);
  assert.equal(ok(traverseAuthorizedRelations(graph([a], { rootAssetId: id(11), direction: 'both', depth: 1 }))).edges.length, 1);
  assert.equal(ok(traverseAuthorizedRelations(graph([{ ...a, direction: 'undirected' }], { rootAssetId: id(11), direction: 'out', depth: 1 }))).edges.length, 1);
  const self = view(id(10), id(10)); assert.equal(ok(traverseAuthorizedRelations(graph([self], { direction: 'in' }))).edges.length, 1);
});

test('validity, type and tombstone filters apply before expansion and hidden bridges are not synthesized', () => {
  const a = view(id(10), id(11)), b = view(id(11), id(12), { id: id(101) });
  for (const changed of [{ validTo: time }, { validFrom: '2026-11-16T00:00:00.000Z' }, { status: 'tombstoned' as const }]) {
    const result = ok(traverseAuthorizedRelations(graph([{ ...a, ...changed }, b]))); assert.equal(result.edges.length, 0); assert.deepEqual(result.nodes.map(item => item.assetId), [id(10)]);
  }
  assert.equal(ok(traverseAuthorizedRelations(graph([{ ...a, validFrom: time }, b]))).edges.length, 2);
  assert.equal(ok(traverseAuthorizedRelations(graph([{ ...a, relationTypeId: id(99) }, b], { relationTypeId: relationType }))).edges.length, 0);
  const root = node(id(10)), far = node(id(12));
  assert.deepEqual(ok(traverseAuthorizedRelations(graph([], { nodes: [root, far], completeFrontierAssetIds: [root.assetId], rootAssetId: root.assetId }))), { nodes: [root], edges: [] });
  const untyped = { ...root, modelId: null, modelVersion: null, typeId: null, state: null };
  assert.deepEqual(ok(traverseAuthorizedRelations(graph([], { nodes: [untyped], completeFrontierAssetIds: [untyped.assetId], rootAssetId: untyped.assetId }))).nodes, [untyped]);
});

test('traversal rejects incomplete frontiers, missing/version-mismatched endpoints and malformed views', () => {
  const a = view(id(10), id(11));
  fails(traverseAuthorizedRelations(graph([a], { completeFrontierAssetIds: [] })), 'invalid_definition', '/completeFrontierAssetIds');
  ok(traverseAuthorizedRelations(graph([a], { depth: 1, completeFrontierAssetIds: [id(10)] })));
  fails(traverseAuthorizedRelations(graph([a], { nodes: [node(id(10))], completeFrontierAssetIds: [id(10)] })), 'invalid_definition');
  fails(traverseAuthorizedRelations(graph([a], { nodes: [node(id(10)), { ...node(id(11)), assetVersion: 2 }] })), 'invalid_definition');
  fails(traverseAuthorizedRelations(graph([{ ...a, extra: true } as RelationView])), 'unknown_field');
  fails(traverseAuthorizedRelations(graph([{ ...a, provenance: { ...a.provenance, origin: 'derived' as 'asserted' } }])), 'enum');
  fails(traverseAuthorizedRelations(graph([a, a])), 'duplicate');
  for (const depth of [0, 7, 1.5]) fails(traverseAuthorizedRelations(graph([a], { depth })), 'range', '/depth');
});

test('graph node/edge and aggregate UTF-8 budgets fail explicitly without a partial result', () => {
  const nodes = Array.from({ length: RELATION_LIMITS.graphNodes + 1 }, (_, n) => node(id(10000 + n)));
  fails(traverseAuthorizedRelations(graph([], { rootAssetId: nodes[0].assetId, nodes, completeFrontierAssetIds: [] })), 'limit');
  const a = view(id(10), id(11)); fails(traverseAuthorizedRelations(graph(Array(RELATION_LIMITS.graphEdges + 1).fill(a))), 'limit');
  const huge = { ...a, attributes: Object.fromEntries(Array.from({ length: 4 }, (_, n) => [`large_${n}`, '界'.repeat(50000)])) };
  fails(traverseAuthorizedRelations(graph([huge])), 'limit');
  let calls = 0; const input = graph([a]); Object.defineProperty(input, 'edges', { enumerable: true, get() { calls++; throw Error('no'); } });
  fails(traverseAuthorizedRelations(input), 'invalid_json'); assert.equal(calls, 0);
});
