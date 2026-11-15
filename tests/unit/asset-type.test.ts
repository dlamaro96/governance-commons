// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { MODEL_LIMITS, validateAttributes, type AttributeDefinition, type ValidationResult } from '../../packages/domain/src/model.ts';
import { ASSET_TYPE_LIMITS, parseAssetTypeDefinition, parseAssetTypeFile, resolveAssetType,
  type AssetTypeDefinition, type LifecycleDefinition } from '../../packages/domain/src/asset-type.ts';

const policy: LifecycleDefinition = { initial: 'draft', states: ['draft', 'active', 'retired'],
  transitions: [{ from: 'draft', to: 'active' }, { from: 'active', to: 'retired' }] };
function authored(id: string, changes: Partial<AssetTypeDefinition> = {}): AssetTypeDefinition {
  return { formatVersion: 1, id, version: 1, parents: [], attributes: {}, overrideAttributes: [], requiredOwner: false,
    lifecycle: structuredClone(policy), ...changes };
}
const pin = (id: string, version = 1) => ({ id, version });
function ok<T>(result: ValidationResult<T>): T {
  if (!result.ok) assert.fail(JSON.stringify(result.issues));
  return result.value;
}
function fails(result: ValidationResult<unknown>, code: string, path?: string): void {
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.ok(result.issues.some(issue => issue.code === code && (path === undefined || issue.path === path)), JSON.stringify(result.issues));
  assert.ok(result.issues.length <= MODEL_LIMITS.issues);
}

test('authored files round-trip without changing typed constraints or exact decimal bounds', () => {
  const input = authored('Invoice', { attributes: {
    amount: { type: 'decimal', precision: 60, scale: 20, minimum: '-99999999999999999999.000000001', required: true },
    notes: { type: 'richText', maxLength: 4096 }, flags: { type: 'list', items: { type: 'boolean' }, maxItems: 10 },
    metadata: { type: 'object', properties: { at: { type: 'timestamp' }, duration: { type: 'duration' }, link: { type: 'uri' } } },
  } });
  const parsed = ok(parseAssetTypeFile(JSON.stringify(input)));
  assert.deepEqual(parsed, input); assert.deepEqual(ok(parseAssetTypeFile(JSON.stringify(parsed))), parsed);
  const resolved = ok(resolveAssetType(parsed, []));
  assert.deepEqual(resolved.dependencies, []); assert.equal(resolved.model.id, input.id);
  const amount = '123456789012345678901234567890.123456789';
  assert.equal(ok(validateAttributes(resolved.model, { amount })).amount, amount);
});

test('every authored root field is mandatory and unknown formats, fields and invalid pins fail', () => {
  for (const key of Object.keys(authored('Root'))) {
    const input: any = authored('Root'); delete input[key];
    fails(parseAssetTypeDefinition(input), 'required', '/' + key);
  }
  fails(parseAssetTypeDefinition({ ...authored('Root'), extra: true }), 'unknown_field', '/extra');
  fails(parseAssetTypeDefinition({ ...authored('Root'), formatVersion: 2 }), 'invalid_definition', '/formatVersion');
  fails(parseAssetTypeDefinition({ ...authored('Root'), requiredOwner: 'true' }), 'type', '/requiredOwner');
  for (const id of ['__proto__', 'constructor', 'prototype', '0start', 'a'.repeat(65)]) fails(parseAssetTypeDefinition(authored(id)), 'format', '/id');
  for (const version of [0, -0, -1, 1.2, Number.MAX_SAFE_INTEGER + 1, Infinity, NaN]) {
    fails(parseAssetTypeDefinition(authored('Root', { version })), 'model_version', '/version');
  }
  fails(parseAssetTypeDefinition({ ...authored('Child'), parents: [{ id: 'Parent' }] }), 'required', '/parents/0/version');
  fails(parseAssetTypeDefinition({ ...authored('Child'), parents: [{ id: 'Parent', version: 1, extra: true }] }), 'unknown_field', '/parents/0/extra');
  fails(parseAssetTypeDefinition(authored('Child', { parents: [pin('Parent'), pin('Parent', 2)] })), 'duplicate', '/parents/1/id');
});

test('raw JSON rejects duplicate escaped keys before overwrite, malformed documents and oversized files', () => {
  const source = JSON.stringify(authored('Root'));
  fails(parseAssetTypeFile(source.replace('"requiredOwner":false', '"requiredOwner":false,"required\\u004fwner":true')), 'duplicate', '/requiredOwner');
  fails(parseAssetTypeFile(source.replace('"from":"draft"', '"from":"draft","fr\\u006fm":"retired"')), 'duplicate', '/lifecycle/transitions/0/from');
  fails(parseAssetTypeFile('{'), 'invalid_json');
  fails(parseAssetTypeFile(' '.repeat(MODEL_LIMITS.fileLength + 1)), 'limit');
});

test('lifecycle validates safe states, initial membership, unique directed edges and exact bounded shape', () => {
  const invalid = (lifecycle: unknown) => parseAssetTypeDefinition({ ...authored('Root'), lifecycle });
  fails(invalid(null), 'invalid_definition', '/lifecycle');
  fails(invalid({ ...policy, states: [] }), 'invalid_definition', '/lifecycle/states');
  fails(invalid({ ...policy, initial: 'missing' }), 'invalid_definition', '/lifecycle/initial');
  fails(invalid({ ...policy, states: ['draft', 'draft'] }), 'duplicate', '/lifecycle/states/1');
  fails(invalid({ ...policy, states: ['draft', '__proto__'] }), 'format', '/lifecycle/states/1');
  fails(invalid({ ...policy, transitions: [{ from: 'draft', to: 'missing' }] }), 'invalid_definition', '/lifecycle/transitions/0');
  fails(invalid({ ...policy, transitions: [{ from: 'draft', to: 'draft' }] }), 'invalid_definition', '/lifecycle/transitions/0');
  fails(invalid({ ...policy, transitions: [policy.transitions[0], policy.transitions[0]] }), 'duplicate', '/lifecycle/transitions/1');
  fails(invalid({ ...policy, transitions: [{ from: 'draft', to: 'active', code: 'user code' }] }), 'unknown_field', '/lifecycle/transitions/0/code');
  fails(invalid({ ...policy, states: Array.from({ length: 33 }, (_, index) => `s${index}`) }), 'limit', '/lifecycle/states');
  fails(invalid({ ...policy, transitions: Array(257).fill(policy.transitions[0]) }), 'limit', '/lifecycle/transitions');
  const reversible = { initial: 'a', states: ['a', 'b'], transitions: [{ from: 'a', to: 'b' }, { from: 'b', to: 'a' }] };
  assert.deepEqual(ok(invalid(reversible)).lifecycle, reversible, 'lifecycle cycles are valid; ancestry cycles are not');
});

test('shared exact-pin diamond coalesces equal inherited fields with deterministic dependency ordering', () => {
  const ancestor = authored('Ancestor', { attributes: { title: { type: 'text', required: true } }, requiredOwner: true });
  const left = authored('Left', { parents: [pin('Ancestor')], lifecycle: null, attributes: { left: { type: 'boolean' } } });
  const right = authored('Right', { parents: [pin('Ancestor')], lifecycle: null, attributes: { right: { type: 'date' } } });
  const child = authored('Child', { parents: [pin('Right'), pin('Left')], lifecycle: null });
  const result = ok(resolveAssetType(child, [right, ancestor, left]));
  assert.deepEqual(result.dependencies, [pin('Ancestor'), pin('Left'), pin('Right')]);
  assert.deepEqual(Object.keys(result.model.attributes), ['left', 'right', 'title']);
  assert.equal(result.requiredOwner, true); assert.deepEqual(result.lifecycle, policy);
  const reordered = ok(resolveAssetType({ ...child, parents: [...child.parents].reverse() }, [left, right, ancestor]));
  assert.deepEqual(reordered.model, result.model); assert.deepEqual(reordered.dependencies, result.dependencies);
  assert.deepEqual(reordered.lifecycle, result.lifecycle);
});

test('conflicting parents require a local field and an exact override declaration, including equal replacements', () => {
  const a = authored('A', { attributes: { value: { type: 'text' } } });
  const b = authored('B', { attributes: { value: { type: 'decimal' } } });
  const child = authored('Child', { parents: [pin('A'), pin('B')], lifecycle: null });
  fails(resolveAssetType(child, [a, b]), 'invalid_definition', '/attributes/value');
  const local = { ...child, attributes: { value: { type: 'number' as const } } };
  fails(resolveAssetType(local, [a, b]), 'invalid_definition', '/attributes/value');
  assert.equal(ok(resolveAssetType({ ...local, overrideAttributes: ['value'] }, [a, b])).model.attributes.value.type, 'number');
  const equal = authored('Child', { parents: [pin('A')], lifecycle: null, attributes: a.attributes });
  fails(resolveAssetType(equal, [a]), 'invalid_definition', '/attributes/value');
  assert.equal(ok(resolveAssetType({ ...equal, overrideAttributes: ['value'] }, [a])).model.attributes.value.type, 'text');
  fails(resolveAssetType({ ...equal, attributes: { other: { type: 'text' } }, overrideAttributes: ['other'] }, [a]), 'invalid_definition', '/overrideAttributes/0');
  fails(parseAssetTypeDefinition({ ...equal, overrideAttributes: ['missing'] }), 'invalid_definition', '/overrideAttributes/0');
  fails(parseAssetTypeDefinition({ ...equal, overrideAttributes: ['value', 'value'] }), 'duplicate', '/overrideAttributes/1');
});

test('required ownership cannot be weakened and explicit lifecycle replaces ambiguous inheritance', () => {
  const a = authored('A', { requiredOwner: true });
  const alternate = { initial: 'open', states: ['open', 'closed'], transitions: [{ from: 'open', to: 'closed' }] };
  const b = authored('B', { lifecycle: alternate });
  const child = authored('Child', { parents: [pin('A'), pin('B')], requiredOwner: false, lifecycle: null });
  fails(resolveAssetType(child, [a, b]), 'invalid_definition', '/lifecycle');
  const result = ok(resolveAssetType({ ...child, lifecycle: alternate }, [a, b]));
  assert.equal(result.requiredOwner, true); assert.deepEqual(result.lifecycle, alternate);
  assert.equal(ok(resolveAssetType(authored('Required', { requiredOwner: true }), [])).requiredOwner, true);
});

test('logical cycles, self ancestry and mixed pinned versions are rejected before resolution', () => {
  fails(parseAssetTypeDefinition(authored('A', { parents: [pin('A', 2)] })), 'cycle', '/parents/0');
  const a = authored('A', { parents: [pin('B')], lifecycle: null });
  const b = authored('B', { parents: [pin('A', 2)], lifecycle: null });
  fails(resolveAssetType(a, [b]), 'cycle', '/dependencies/0/parents/0');
  const ancestor = authored('Ancestor');
  const left = authored('Left', { parents: [pin('Ancestor')], lifecycle: null });
  const right = authored('Right', { parents: [pin('Ancestor', 2)], lifecycle: null });
  fails(resolveAssetType(authored('Root', { parents: [pin('Left'), pin('Right')], lifecycle: null }), [ancestor, left, right]), 'model_version');
  fails(resolveAssetType(a, [authored('B'), authored('B', { version: 2 })]), 'duplicate', '/dependencies/1/id');
  fails(resolveAssetType(a, [authored('B'), authored('B')]), 'duplicate', '/dependencies/1/id');
});

test('unknown or moved parent versions fail and unrelated validated dependencies do not enter resolved pins', () => {
  const root = authored('Child', { parents: [pin('Parent')], lifecycle: null });
  fails(resolveAssetType(root, []), 'invalid_definition', '/parents/0');
  fails(resolveAssetType(root, [authored('Parent', { version: 2 })]), 'model_version', '/parents/0');
  const first = authored('Parent', { attributes: { old: { type: 'text' } } });
  const resolved = ok(resolveAssetType(root, [authored('Unused'), first]));
  assert.deepEqual(resolved.dependencies, [pin('Parent')]); assert.ok(resolved.model.attributes.old);
  fails(resolveAssetType(root, [{ ...authored('Unused'), requiredOwner: 'yes' }, first]), 'type', '/dependencies/0/requiredOwner');
});

test('eight parent edges are accepted, including cached diamonds, and a ninth edge is rejected', () => {
  const chain = Array.from({ length: 8 }, (_, index) => authored(`a_tail${index}`, index === 7 ? {} : {
    parents: [pin(`a_tail${index + 1}`)], lifecycle: null,
  }));
  const root = authored('Root', { parents: [pin('a_tail0')], lifecycle: null });
  assert.equal(ok(resolveAssetType(root, chain)).dependencies.length, 8);
  const extra = authored('z_long', { parents: [pin('a_tail0')], lifecycle: null });
  // a_tail0 resolves through the short edge first; memoization must not hide
  // the later ninth edge through z_long.
  fails(resolveAssetType({ ...root, parents: [pin('a_tail0'), pin('z_long')] }, [...chain, extra]), 'limit');
  fails(resolveAssetType(authored('Root', { parents: [pin('z_long')], lifecycle: null }), [...chain, extra]), 'limit');
});

test('exact maximum ancestry breadth resolves while immediate parents and supplied dependencies stay bounded', () => {
  const leaves = Array.from({ length: 56 }, (_, index) => authored(`leaf_${index}`));
  const groups = Array.from({ length: 8 }, (_, index) => authored(`group_${index}`, {
    parents: leaves.slice(index * 7, index * 7 + 7).map(value => pin(value.id)), lifecycle: null,
  }));
  const root = authored('Root', { parents: groups.map(value => pin(value.id)), lifecycle: null });
  assert.equal(ok(resolveAssetType(root, [...groups, ...leaves])).dependencies.length, ASSET_TYPE_LIMITS.dependencies);
  fails(resolveAssetType(root, [...groups, ...leaves, authored('Unused')]), 'limit', '/dependencies');
  fails(parseAssetTypeDefinition({ ...root, parents: [...root.parents, pin('ninth')] }), 'limit', '/parents');
});

test('fully resolved schemas reapply property and total schema-node limits', () => {
  const fields = (prefix: string, count: number) => Object.fromEntries(Array.from({ length: count }, (_, index) => [`${prefix}_${index}`, { type: 'text' }])) as Record<string, AttributeDefinition>;
  const a = authored('A', { attributes: fields('a', 64) }); const b = authored('B', { attributes: fields('b', 64) });
  const root = authored('Root', { parents: [pin('A'), pin('B')], lifecycle: null });
  assert.equal(Object.keys(ok(resolveAssetType(root, [a, b])).model.attributes).length, 128);
  fails(resolveAssetType({ ...root, attributes: { extra: { type: 'text' } } }, [a, b]), 'limit', '/attributes');
  const large = (id: string, prefix: string) => authored(id, { attributes: Object.fromEntries(Array.from({ length: 8 }, (_, index) =>
    [`${prefix}_${index}`, { type: 'object', properties: fields('nested', 128) }])) as Record<string, AttributeDefinition> });
  const left = large('A', 'left'), right = large('B', 'right');
  ok(parseAssetTypeDefinition(left)); ok(parseAssetTypeDefinition(right));
  fails(resolveAssetType(root, [left, right]), 'limit');
});

test('aggregate inherited string limits hold even when each authored definition is valid', () => {
  const values = Array.from({ length: 256 }, (_, index) => String(index).padStart(4, '0') + 'x'.repeat(1020));
  const fields = (prefix: string): Record<string, AttributeDefinition> => ({ [`${prefix}0`]: { type: 'enum', values }, [`${prefix}1`]: { type: 'enum', values } });
  const a = authored('A', { attributes: fields('a') }), b = authored('B', { attributes: fields('b') });
  ok(parseAssetTypeDefinition(a)); ok(parseAssetTypeDefinition(b));
  fails(resolveAssetType(authored('Root', { parents: [pin('A'), pin('B')], lifecycle: null }), [a, b]), 'limit');
});

test('result definitions, constraints, pins and resolved models are deeply immutable copies', () => {
  const parent: any = authored('Parent', { requiredOwner: true, attributes: { amount: { type: 'decimal', precision: 60 } } });
  const root: any = authored('Root', { parents: [pin('Parent')], lifecycle: null, attributes: { note: { type: 'text' } } });
  const before = JSON.stringify([root, parent]); const resolved = ok(resolveAssetType(root, [parent]));
  assert.equal(JSON.stringify([root, parent]), before); assert.equal(Object.isFrozen(parent), false); assert.equal(Object.isFrozen(root.parents), false);
  parent.attributes.amount.precision = 1; parent.lifecycle.states[0] = 'changed'; root.parents[0].version = 99;
  assert.equal(resolved.model.attributes.amount.type, 'decimal'); assert.equal((resolved.model.attributes.amount as any).precision, 60);
  assert.equal(resolved.definition.parents[0].version, 1); assert.equal(resolved.lifecycle.states[0], 'draft');
  for (const value of [resolved, resolved.definition, resolved.dependencies, resolved.dependencies[0], resolved.model, resolved.model.attributes,
    resolved.model.attributes.amount, resolved.lifecycle, resolved.lifecycle.states, resolved.lifecycle.transitions[0]]) assert.equal(Object.isFrozen(value), true);
  assert.throws(() => { (resolved.model.attributes.amount as any).precision = 2; }, TypeError);
});

test('getters, prototypes, sparse arrays, symbols and cyclic payloads never become authored data', () => {
  let calls = 0;
  const trapped = Object.defineProperty({}, 'secret', { enumerable: true, get() { calls += 1; throw new Error('Getter executed'); } });
  for (const key of ['id', 'version', 'requiredOwner']) fails(parseAssetTypeDefinition({ ...authored('Root'), [key]: trapped }), key === 'requiredOwner' ? 'type' : key === 'version' ? 'model_version' : 'format');
  fails(parseAssetTypeDefinition({ ...authored('Root'), overrideAttributes: [trapped] }), 'format');
  const getter = { ...authored('Root') }; Object.defineProperty(getter, 'attributes', { enumerable: true, get() { calls += 1; return {}; } });
  fails(parseAssetTypeDefinition(getter), 'invalid_json', '/attributes');
  const schemaGetter: any = { type: 'text' }; Object.defineProperty(schemaGetter, 'label', { enumerable: true, get() { calls += 1; return 'hidden'; } });
  fails(parseAssetTypeDefinition(authored('Root', { attributes: { value: schemaGetter } })), 'invalid_json', '/attributes/value/label');
  fails(parseAssetTypeDefinition(Object.assign(Object.create({ inherited: true }), authored('Root'))), 'type');
  fails(parseAssetTypeDefinition({ ...authored('Root'), [Symbol('hidden')]: true }), 'invalid_json');
  fails(parseAssetTypeDefinition({ ...authored('Root'), parents: new Array(1) }), 'invalid_json', '/parents');
  const arrayGetter: any[] = [pin('Parent')]; Object.defineProperty(arrayGetter, '0', { enumerable: true, get() { calls += 1; return pin('Parent'); } });
  fails(parseAssetTypeDefinition({ ...authored('Root'), parents: arrayGetter }), 'invalid_json', '/parents/0');
  const cyclic: any = { type: 'object', properties: {} }; cyclic.properties.next = cyclic;
  fails(parseAssetTypeDefinition(authored('Root', { attributes: { value: cyclic } })), 'cycle');
  assert.equal(calls, 0);
});

test('schema errors retain stable dependency paths and issue lists are bounded', () => {
  fails(resolveAssetType(authored('Child', { parents: [pin('Parent')], lifecycle: null }), [authored('Parent', { attributes: { broken: { type: 'executable' } as any } })]),
    'unknown_type', '/dependencies/0/attributes/broken/type');
  const invalid = { ...authored('Root'), overrideAttributes: Array.from({ length: 128 }, () => 'bad/key') };
  fails(parseAssetTypeDefinition(invalid), 'limit');
  const safe: any = authored('Root'); safe.attributes = Object.assign(Object.create(null), { valid: { type: 'boolean' } });
  ok(parseAssetTypeDefinition(safe));
});
