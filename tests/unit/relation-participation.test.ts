// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseRelationDefinition, parseRelationDefinitionFile, parseRelationTypeDefinition, resolveRelationDefinition } from '../../packages/domain/src/relation.ts';
import { deriveRequiredParticipation, relationStructuralPolicy, validateFinalRelationGraphConstraints } from '../../packages/domain/src/relation-participation.ts';
import { a, b, c, id, typeId, relationId, definition, policy, asset, edge, binding, graph, values, ok, fails } from './relation-participation-fixtures.ts';
const required = () => definition({ cardinality: { outgoing: { min: 1, max: 2 }, incoming: { min: 0, max: 2 } }, sourceStates: ['draft'] });

test('format two admits zero maximum and bounded positive minimum without changing format-one behavior', () => {
  const zero = definition({ cardinality: { outgoing: { min: 0, max: 0 }, incoming: { min: 0, max: 0 } } });
  assert.equal(ok(parseRelationDefinition(zero)).formatVersion, 2);
  fails(parseRelationTypeDefinition({ ...zero, formatVersion: 1 }), 'range');
  fails(parseRelationTypeDefinition({ ...required(), formatVersion: 1 }), 'unsupported');
  ok(parseRelationDefinition(required()));
  for (const min of [-1, 1.1, 1001, '1']) fails(parseRelationDefinition({ ...zero, cardinality: { ...zero.cardinality, outgoing: { min, max: 1000 } } }), 'range');
  fails(parseRelationDefinition({ ...zero, cardinality: { ...zero.cardinality, outgoing: { min: 2, max: 1 } } }), 'range');
  fails(parseRelationDefinition({ ...zero, direction: 'undirected', cardinality: { outgoing: { min: 1, max: 2 }, incoming: { min: 0, max: 2 } } }), 'invalid_definition');
});
test('V2 file parsing rejects duplicate escaped keys, getters, sparse arrays and malformed Unicode', () => {
  const json = JSON.stringify(definition());
  fails(parseRelationDefinitionFile(json.replace('"formatVersion":2', '"formatVersion":2,"format\\u0056ersion":2')), 'duplicate');
  let called = false; const input = definition(); Object.defineProperty(input, 'label', { enumerable: true, get() { called = true; return 'x'; } });
  fails(parseRelationDefinition(input), 'invalid_json'); assert.equal(called, false);
  fails(parseRelationDefinition({ ...definition(), label: '\uD800' }), 'format');
  const sparse = Array(2); sparse[1] = { typeId, includeDescendants: false };
  fails(parseRelationDefinition({ ...definition(), sourceTypes: sparse }), 'invalid_json');
  assert.ok(Object.isFrozen(ok(resolveRelationDefinition(required())).definition.cardinality));
});
test('structural semantic projection excludes own schema, labels and format but retains full policy', () => {
  const original = definition(); const first = ok(relationStructuralPolicy(original));
  assert.deepEqual(ok(relationStructuralPolicy({ ...original, formatVersion: 1 })), first);
  assert.deepEqual(ok(relationStructuralPolicy({ ...original, label: 'Changed', version: 8, requiredOwner: true, attributes: { score: { type: 'text' } } })), first);
  assert.notDeepEqual(ok(relationStructuralPolicy({ ...original, cycles: 'acyclic' })), first);
});
test('required participation derives zero-edge candidates using actual state and pinned nominal ancestry', () => {
  const p = policy(required()), endpoints = [asset(c, { state: 'retired' }), asset(b), asset(a)];
  const derived = ok(deriveRequiredParticipation({ admissionHeads: [{ relationTypeId: relationId, version: 1 }], policies: [p], completeEligibleEndpointCandidates: endpoints, currentBindings: [] }));
  assert.deepEqual(derived.map(row => row.assetId), [a, b]); assert.ok(derived.every(row => row.existingBindingId === null && row.min === 1));
  const invalid = validateFinalRelationGraphConstraints({ graph: graph({ endpoints, edges: [], bindings: [] }), policies: [p] });
  fails(invalid, 'required', '/participation/0/binding'); fails(invalid, 'range', '/participation/0/minimum');
});
test('directed incoming/outgoing obligations and self-edge counting are independent', () => {
  const p = policy(definition({ allowSelf: true, cardinality: { outgoing: { min: 1, max: 1 }, incoming: { min: 1, max: 1 } } }));
  const g = graph({ endpoints: [asset(a)], edges: [edge(a, a)], bindings: [binding(a), binding(a, 'target', { key: { kind: 'existing', bindingId: id(201) } })] });
  assert.equal(ok(validateFinalRelationGraphConstraints({ graph: g, policies: [p] })).length, 2);
});
test('undirected incident bindings count each self-edge once and require canonical endpoint ordering', () => {
  const p = policy(definition({ direction: 'undirected', allowSelf: true, cardinality: { outgoing: { min: 1, max: 1 }, incoming: { min: 1, max: 1 } } }));
  ok(validateFinalRelationGraphConstraints({ graph: graph({ endpoints: [asset(a)], edges: [edge(a, a)], bindings: [binding(a, 'incident')] }), policies: [p] }));
  fails(validateFinalRelationGraphConstraints({ graph: graph({ edges: [edge(b, a)], bindings: [binding(a, 'incident'), binding(b, 'incident', { key: { kind: 'existing', bindingId: id(201) } })] }), policies: [p] }), 'invalid_definition', '/structure/0/pairs');
});
test('expired and future edges count structurally while tombstones never satisfy required degree', () => {
  const p = policy(required()); const g = graph({ endpoints: [asset(a), asset(b, { state: 'active' })], bindings: [binding(a)] });
  for (const validity of [{ validFrom: null, validTo: '2000-01-01T00:00:00.000Z' }, { validFrom: '2099-01-01T00:00:00.000Z', validTo: null }])
    ok(validateFinalRelationGraphConstraints({ graph: { ...g, edges: [edge(a, b, { values: values(validity) })] }, policies: [p] }));
  fails(validateFinalRelationGraphConstraints({ graph: { ...g, edges: [edge(a, b, { status: 'tombstoned' })] }, policies: [p] }), 'range', '/participation/0/minimum');
});
test('uniform fingerprints reject weak old bindings and old acyclic pins under a permissive head', () => {
  const old = policy(definition({ cycles: 'acyclic' })), next = policy(definition({ version: 2 }));
  fails(validateFinalRelationGraphConstraints({ graph: graph({ heads: [{ relationTypeId: relationId, version: 2 }] }), policies: [old, next] }), 'invalid_definition', '/structure/0/pins');
  const oldZero = policy(), newRequired = policy({ ...required(), version: 2 });
  fails(validateFinalRelationGraphConstraints({ graph: graph({ heads: [{ relationTypeId: relationId, version: 2 }], bindings: [binding()] }), policies: [oldZero, newRequired] }), 'invalid_definition', '/bindings/0/relationTypeVersion');
});
test('compatible mixed exact pins remain valid with full degree and cycle checks', () => {
  const old = policy(definition({ cycles: 'acyclic' })), next = policy(definition({ version: 2, label: 'New label', cycles: 'acyclic' }));
  const g = graph({ heads: [{ relationTypeId: relationId, version: 2 }], endpoints: [asset(a), asset(b), asset(c)], edges: [edge(), edge(b, c, { key: { kind: 'existing', relationId: id(101) }, relationTypeVersion: 2 })] });
  ok(validateFinalRelationGraphConstraints({ graph: g, policies: [old, next] }));
  fails(validateFinalRelationGraphConstraints({ graph: { ...g, edges: [...g.edges, edge(c, a, { key: { kind: 'existing', relationId: id(102) }, relationTypeVersion: 2 })] }, policies: [old, next] }), 'cycle', '/structure/0/cycles');
});
test('max zero, duplicate pairs and nominal/state loss fail the same complete graph helper', () => {
  const zero = policy(definition({ cardinality: { outgoing: { min: 0, max: 0 }, incoming: { min: 0, max: null } } }));
  fails(validateFinalRelationGraphConstraints({ graph: graph(), policies: [zero] }), 'range', '/structure/0/maximum');
  fails(validateFinalRelationGraphConstraints({ graph: graph({ edges: [edge(), edge(a, b, { key: { kind: 'existing', relationId: id(101) } })] }), policies: [policy()] }), 'duplicate', '/structure/0/pairs');
  fails(validateFinalRelationGraphConstraints({ graph: graph({ endpoints: [asset(a, { typeId: null, policy: null, state: null }), asset(b)] }), policies: [policy()] }), 'invalid_definition', '/structure/0/endpoints');
});
test('structural helper deliberately does not impose migration owner activity or own state transitions', () => {
  ok(validateFinalRelationGraphConstraints({ graph: graph({ edges: [edge(a, b, { values: values({ ownerId: id(90), state: 'retired' }) })] }), policies: [policy()] }));
});
test('graph input rejects accessor execution, extra snapshot fields and exceeds bounds fail closed', () => {
  let invoked = false; const g = graph(); Object.defineProperty(g, 'edges', { enumerable: true, get() { invoked = true; return []; } });
  fails(validateFinalRelationGraphConstraints({ graph: g, policies: [policy()] }), 'invalid_json'); assert.equal(invoked, false);
  fails(validateFinalRelationGraphConstraints({ graph: { ...graph(), unexpected: true } as any, policies: [policy()] }), 'unknown_field');
  fails(validateFinalRelationGraphConstraints({ graph: graph({ endpoints: Array.from({ length: 2001 }, (_, i) => asset(id(i + 1000))) }), policies: [policy()] }), 'limit');
});
