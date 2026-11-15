// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  MODEL_LIMITS, parseModelDefinition, parseModelFile, previewModelUpgrade, validateAttributes,
  type AttributeDefinition, type ModelDefinition, type ValidationResult,
} from '../../packages/domain/src/model.ts';

function success<T>(result: ValidationResult<T>): T {
  if (!result.ok) assert.fail(JSON.stringify(result.issues));
  return result.value;
}
function failure<T>(result: ValidationResult<T>, code?: string, path?: string): void {
  assert.equal(result.ok, false);
  if (result.ok) return;
  if (code) assert.ok(result.issues.some(issue => issue.code === code && (path === undefined || issue.path === path)), JSON.stringify(result.issues));
  assert.ok(result.issues.length <= MODEL_LIMITS.issues);
}
function model(attributes: Record<string, AttributeDefinition>, version = 1): ModelDefinition {
  return success(parseModelDefinition({ formatVersion: 1, id: 'retail.asset', version, attributes }));
}

const fullModel = model({
  title: { type: 'text', required: true, minLength: 1, maxLength: 100, label: 'Title' },
  notes: { type: 'richText', maxLength: 1_000 },
  quantity: { type: 'number', integer: true, minimum: 0 },
  ratio: { type: 'number', minimum: 0, maximum: 1 },
  amount: { type: 'decimal', precision: 40, scale: 8 },
  enabled: { type: 'boolean' },
  date: { type: 'date' }, time: { type: 'timestamp' }, retention: { type: 'duration' },
  lifecycle: { type: 'enum', values: ['draft', 'approved'] },
  links: { type: 'list', minItems: 1, maxItems: 3, items: { type: 'uri', schemes: ['https', 'urn'] } },
  address: { type: 'object', properties: { city: { type: 'text', required: true }, codes: { type: 'list', items: { type: 'text' } } } },
});

test('all attribute types preserve JSON types and decimal/timestamp precision through a model and value round trip', () => {
  const attributes = {
    title: 'منتج Harbor 🧭', notes: '**Synthetic** documentation', quantity: 12, ratio: 0.125,
    amount: '9007199254740993123456789.12345678', enabled: false, date: '2000-02-29',
    time: '2026-11-15T12:34:56.123456789Z', retention: 'P1Y2M3DT4H5M6.123456789S',
    lifecycle: 'approved', links: ['https://example.invalid/catalog?q=one%20two', 'urn:gc:asset:1'],
    address: { city: 'Synthetic Harbour', codes: ['A', 'B'] },
  };
  const exportedModel = JSON.stringify(fullModel);
  assert.deepEqual(success(parseModelFile(exportedModel)), fullModel);
  const result = success(validateAttributes(fullModel, attributes));
  assert.deepEqual(JSON.parse(JSON.stringify(result)), attributes);
  assert.deepEqual(success(validateAttributes(success(parseModelFile(exportedModel)), JSON.parse(JSON.stringify(result)))), result);
  assert.ok(Object.isFrozen(fullModel.attributes.address));
  assert.notEqual(result, attributes);
  assert.notEqual(result.address, attributes.address);
});

test('strict schema definitions reject unsupported types, fields, invalid bounds, and unsafe names', () => {
  const invalidAttributes: unknown[] = [
    { score: { type: 'javascript', expression: 'process.exit()' } },
    { score: { type: 'number', expression: '1 + 1' } },
    { title: { type: 'text', minLength: 5, maxLength: 4 } },
    { score: { type: 'number', minimum: Infinity } },
    { score: { type: 'number', integer: true, minimum: 0.1, maximum: 0.2 } },
    { score: { type: 'decimal', precision: 2, scale: 3 } },
    { score: { type: 'decimal', minimum: '2', maximum: '1' } },
    { lifecycle: { type: 'enum', values: ['draft', 'draft'] } },
    { lifecycle: { type: 'enum', values: [] } },
    { link: { type: 'uri', schemes: ['javascript'] } },
    { items: { type: 'list', items: { type: 'text', required: true } } },
    { constructor: { type: 'text' } },
  ];
  for (const attributes of invalidAttributes) failure(parseModelDefinition({ formatVersion: 1, id: 'retail', version: 1, attributes }));
  failure(parseModelDefinition({ ...fullModel, sql: 'DROP TABLE assets' }), 'unknown_field', '/sql');
  failure(parseModelDefinition({ ...fullModel, version: '1' }), 'type', '/version');
  failure(parseModelDefinition({ ...fullModel, formatVersion: 2 }), 'invalid_definition', '/formatVersion');
  failure(parseModelDefinition({ ...fullModel, id: '../escape' }), 'invalid_definition', '/id');
});

test('missing fields, unknown attributes, and nested errors have stable JSON Pointer locations', () => {
  const result = validateAttributes(fullModel, { address: { city: 1, unexpected: true }, links: ['javascript:alert(1)'], 'other/~': 'hidden' });
  failure(result, 'required', '/title'); failure(result, 'type', '/address/city');
  failure(result, 'unknown_field', '/address/unexpected'); failure(result, 'format', '/links/0');
  failure(result, 'unknown_field', '/other~1~0');
  assert.deepEqual(result, validateAttributes(fullModel, { 'other/~': 'hidden', links: ['javascript:alert(1)'], address: { unexpected: true, city: 1 } }));
  if (!result.ok) assert.ok(result.issues.every(issue => !issue.message.includes('hidden')));
});

test('validation never coerces null, strings, booleans, or unsafe integer representations', () => {
  for (const [attribute, schema, values] of [
    ['value', { type: 'number' }, ['1', true, null, NaN, Infinity, -Infinity, -0]],
    ['value', { type: 'number', integer: true }, [0.1, Number.MAX_SAFE_INTEGER + 1]],
    ['value', { type: 'boolean' }, ['false', 0, null]],
    ['value', { type: 'text' }, [123, false, null]],
    ['value', { type: 'decimal' }, [1.2, null]],
  ] as const) {
    const definition = model({ [attribute]: schema });
    for (const value of values) failure(validateAttributes(definition, { value }), 'type', '/value');
  }
  assert.equal(success(validateAttributes(model({ value: { type: 'number' } }), { value: 1.5e100 })).value, 1.5e100);
});

test('decimal bounds compare arbitrary precision positive and negative values without Number conversion', () => {
  const definition = model({ value: { type: 'decimal', minimum: '-9007199254740993.000000000000000002', maximum: '9007199254740993.000000000000000002' } });
  for (const value of ['0', '-0.000000000000000001', '-9007199254740993.000000000000000002', '9007199254740993.000000000000000001']) {
    assert.equal(success(validateAttributes(definition, { value })).value, value);
  }
  for (const value of ['9007199254740993.000000000000000003', '-9007199254740993.000000000000000003']) failure(validateAttributes(definition, { value }), 'range');
  for (const value of ['+1', '01', '-0', '1.0', '0.00', '1e3', '.5', '1.', ' 1', 'NaN', 'Infinity']) failure(validateAttributes(definition, { value }), 'format');
  const limited = model({ value: { type: 'decimal', precision: 5, scale: 2 } });
  for (const value of ['1000.01', '0.001']) failure(validateAttributes(limited, { value }), 'range');
  success(validateAttributes(limited, { value: '123.45' }));
  const fractionalBoundary = `-0.${'0'.repeat(MODEL_LIMITS.decimalDigits - 1)}1`;
  success(validateAttributes(model({ value: { type: 'decimal' } }), { value: fractionalBoundary }));
});

test('dates and UTC timestamps validate Gregorian days, time ranges, and nanosecond precision', () => {
  for (const value of ['2000-02-29', '2024-02-29', '0001-01-01', '9999-12-31']) success(validateAttributes(model({ value: { type: 'date' } }), { value }));
  for (const value of ['1900-02-29', '2023-02-29', '2024-04-31', '0000-01-01', '2024-00-01', '2024-01-00', '24-01-01']) failure(validateAttributes(model({ value: { type: 'date' } }), { value }), 'format');
  for (const value of ['2024-02-29T23:59:59Z', '2024-01-01T00:00:00.000000001Z']) success(validateAttributes(model({ value: { type: 'timestamp' } }), { value }));
  for (const value of ['2024-01-01T24:00:00Z', '2024-01-01T23:60:00Z', '2024-01-01T23:59:60Z', '2023-02-29T00:00:00Z', '2024-01-01T00:00:00+04:00', '2024-01-01T00:00:00.1234567890Z']) failure(validateAttributes(model({ value: { type: 'timestamp' } }), { value }), 'format');
});

test('calendar durations retain their ISO components and reject ambiguous or malformed syntax', () => {
  const definition = model({ value: { type: 'duration' } });
  for (const value of ['P1Y', 'P2M', 'P3D', 'P12W', 'PT0S', 'P0D', 'PT1H30M', 'PT0.000000001S', 'P1Y2M3DT4H5M6S']) {
    assert.equal(success(validateAttributes(definition, { value })).value, value);
  }
  for (const value of ['P', 'PT', 'P1DT', 'P1W2D', '-PT1S', 'P1.5Y', 'PT1.2.3S', 'PT1S1M', 'P9999999999D', 'PT1.1234567890S']) failure(validateAttributes(definition, { value }), 'format');
});

test('URI fields reject executable schemes, credentials, invalid escapes, and parser normalization traps', () => {
  const definition = model({ value: { type: 'uri', schemes: ['https', 'urn'] } });
  for (const value of ['https://example.invalid/path#part', 'urn:example:asset:1']) success(validateAttributes(definition, { value }));
  for (const value of ['javascript:alert(1)', 'data:text/html,test', 'file:///private/secret', 'http://example.invalid', '/relative', 'https://user:secret@example.invalid/', 'https://example.invalid/%ZZ', 'https://example.invalid/a b', 'https:\\example.invalid', 'https://example.invalid/<script>']) failure(validateAttributes(definition, { value }), 'format');
});

test('accessors, prototypes, sparse arrays, symbols, and pollution keys never become accepted JSON', () => {
  let reads = 0;
  const getter = Object.defineProperty({}, 'title', { enumerable: true, get() { reads += 1; return 'secret'; } });
  failure(validateAttributes(fullModel, getter), 'invalid_json', '/title');
  const schemaGetter = Object.defineProperty({ ...fullModel }, 'id', { enumerable: true, get() { reads += 1; return 'secret'; } });
  failure(parseModelDefinition(schemaGetter), 'invalid_json', '/id');
  const arrayGetter = Object.defineProperty(['one'], '0', { enumerable: true, get() { reads += 1; return 'secret'; } });
  const lists = model({ values: { type: 'list', items: { type: 'text' } } });
  failure(validateAttributes(lists, { values: arrayGetter }), 'invalid_json');
  failure(validateAttributes(lists, { values: new Array(1) }), 'invalid_json');
  failure(validateAttributes(lists, { values: Object.assign(['x'], { extra: true }) }), 'invalid_json');
  failure(validateAttributes(fullModel, Object.create({ title: 'inherited' })), 'type');
  failure(validateAttributes(fullModel, { title: 'safe', [Symbol('x')]: true }), 'invalid_json');
  failure(parseModelFile('{"formatVersion":1,"id":"retail","version":1,"attributes":{"__proto__":{"type":"text"}}}'), 'invalid_definition');
  failure(validateAttributes(fullModel, JSON.parse('{"title":"safe","__proto__":{"polluted":true}}')), 'unknown_field');
  assert.equal(reads, 0);
  assert.equal(({} as { polluted?: boolean }).polluted, undefined);
});

test('cyclic definitions are rejected, repeated sibling references remain valid, and no input is mutated', () => {
  const cyclic: Record<string, unknown> = { type: 'list' }; cyclic.items = cyclic;
  failure(parseModelDefinition({ formatVersion: 1, id: 'cycle', version: 1, attributes: { value: cyclic } }), 'cycle');
  const sibling = { type: 'text' } as const;
  const definition = model({ a: sibling, b: sibling });
  assert.deepEqual(success(validateAttributes(definition, Object.freeze({ a: 'one', b: 'two' }))), { a: 'one', b: 'two' });
  const cyclicValue: unknown[] = []; cyclicValue.push(cyclicValue);
  const lists = model({ value: { type: 'list', items: { type: 'list', items: { type: 'text' } } } });
  failure(validateAttributes(lists, { value: cyclicValue }), 'cycle', '/value/0');
});

test('schema depth, property count, scalar size, array size, file size, and issue count have explicit bounds', () => {
  let schema: AttributeDefinition = { type: 'text' };
  for (let index = 0; index <= MODEL_LIMITS.schemaDepth; index += 1) schema = { type: 'list', items: schema };
  failure(parseModelDefinition({ formatVersion: 1, id: 'deep', version: 1, attributes: { value: schema } }), 'limit');
  failure(parseModelDefinition({ ...fullModel, attributes: Object.fromEntries(Array.from({ length: MODEL_LIMITS.properties + 1 }, (_, i) => [`f${i}`, { type: 'text' }])) }), 'limit');
  failure(validateAttributes(model({ value: { type: 'text' } }), { value: 'x'.repeat(MODEL_LIMITS.stringLength + 1) }), 'limit');
  failure(validateAttributes(model({ value: { type: 'text' } }), { value: '\ud800' }), 'format');
  failure(validateAttributes(model({ value: { type: 'list', items: { type: 'text' } } }), { value: Array(MODEL_LIMITS.listItems + 1).fill('x') }), 'limit');
  failure(parseModelFile(' '.repeat(MODEL_LIMITS.fileLength + 1)), 'limit');
  failure(parseModelFile('{ invalid }'), 'invalid_json');
  const many = model(Object.fromEntries(Array.from({ length: 128 }, (_, i) => [`f${i}`, { type: 'text', required: true }])));
  const errors = validateAttributes(many, {});
  failure(errors, 'limit');
  if (!errors.ok) assert.equal(errors.issues.length, MODEL_LIMITS.issues);
  failure(validateAttributes(fullModel, { ['x'.repeat(10_000)]: 'value' }), 'limit', '');
});

test('validation reparses structurally typed schemas instead of trusting a forged TypeScript cast', () => {
  const forged = { ...fullModel, attributes: { value: { type: 'number', minimum: 10, maximum: 1 } } } as ModelDefinition;
  failure(validateAttributes(forged, { value: 5 }), 'invalid_definition', '/model/attributes/value');
});

test('upgrade preview flags nested removals and type changes even when no asset examples are supplied', () => {
  const current = model({ object: { type: 'object', properties: { old: { type: 'text' } } }, amounts: { type: 'list', items: { type: 'decimal' } } });
  const proposed = model({ object: { type: 'object', properties: {} }, amounts: { type: 'list', items: { type: 'number' } } }, 2);
  const result = success(previewModelUpgrade(current, proposed, []));
  assert.equal(result.coverage, 'provided-assets-only');
  assert.equal(result.compatibleWithProvidedAssets, true);
  assert.equal(result.requiresExplicitMigration, true);
  assert.deepEqual(result.changes, [
    { code: 'type_changed', path: '/attributes/amounts/items', requiresMigration: true },
    { code: 'attribute_removed', path: '/attributes/object/properties/old', requiresMigration: true },
  ]);
});

test('upgrade preview identifies affected assets and invalid tightened constraints without applying changes', () => {
  const current = model({ title: { type: 'text' }, amount: { type: 'decimal' } });
  const proposed = model({ title: { type: 'text', required: true, maxLength: 3 }, amount: { type: 'decimal', precision: 5, scale: 2 } }, 2);
  const assets = [{ id: 'one', attributes: { title: 'too long', amount: '0.0001' } }, { id: 'two', attributes: { title: 'ok', amount: '1.5' } }];
  const original = JSON.stringify(assets);
  const result = success(previewModelUpgrade(current, proposed, assets));
  assert.equal(result.requiresExplicitMigration, true);
  assert.equal(result.compatibleWithProvidedAssets, false);
  assert.deepEqual(result.affectedAssetIds, ['one', 'two']);
  assert.deepEqual(result.assets[0].proposedIssues.map(issue => issue.path), ['/amount', '/title']);
  assert.equal(result.assets[1].proposedIssues.length, 0);
  assert.equal(JSON.stringify(assets), original);
});

test('additive upgrade compatibility is scoped to supplied assets and enum/URI removal requires migration', () => {
  const current = model({ title: { type: 'text', label: 'Old label' } });
  const proposed = model({ title: { type: 'text', label: 'New label' }, notes: { type: 'text' } }, 2);
  const result = success(previewModelUpgrade(current, proposed, [{ id: 'one', attributes: { title: 'one' } }]));
  assert.equal(result.requiresExplicitMigration, false);
  assert.equal(result.compatibleWithProvidedAssets, true);
  for (const [before, after] of [
    [{ type: 'enum', values: ['draft', 'approved'] }, { type: 'enum', values: ['approved'] }],
    [{ type: 'uri' }, { type: 'uri', schemes: ['https'] }],
  ] as const) {
    assert.equal(success(previewModelUpgrade(model({ value: before }), model({ value: after }, 2), [])).requiresExplicitMigration, true);
  }
});

test('upgrade preview rejects identity/version mismatch, duplicate assets, malformed assets, and oversize batches', () => {
  const current = model({ title: { type: 'text' } }); const proposed = model({ title: { type: 'text' } }, 2);
  failure(previewModelUpgrade(current, { ...proposed, id: 'other' }, []), 'model_identity');
  failure(previewModelUpgrade(current, { ...proposed, version: 3 }, []), 'model_version');
  failure(previewModelUpgrade(current, proposed, [{ id: 'one', attributes: {} }, { id: 'one', attributes: {} }]), 'duplicate');
  failure(previewModelUpgrade(current, proposed, [{ id: 'one', attributes: {}, extra: true }] as never), 'unknown_field');
  failure(previewModelUpgrade(current, proposed, Array(MODEL_LIMITS.previewAssets + 1).fill({ id: 'one', attributes: {} })), 'limit');
});

test('model JSON parser rejects duplicate and escaped duplicate keys instead of accepting last-write wins', () => {
  failure(parseModelFile('{"formatVersion":1,"id":"retail","version":1,"attributes":{"x":{"type":"text","type":"number"}}}'), 'duplicate', '/attributes/x/type');
  failure(parseModelFile('{"formatVersion":1,"id":"retail","version":1,"attributes":{"x":{"type":"text","t\\u0079pe":"number"}}}'), 'duplicate', '/attributes/x/type');
  for (const text of ['{"x":1,}', '[1,]', '{"x" 1}', '{"x":undefined}', '{} {}', '[', '"unterminated']) failure(parseModelFile(text), 'invalid_json');
  failure(parseModelFile('['.repeat(100) + ']'.repeat(100)), 'limit');
});

test('aggregate validation and preview budgets reject large nested workloads rather than returning partial success', () => {
  const definition = model({ values: { type: 'list', items: { type: 'text' } } });
  failure(validateAttributes(definition, { values: Array(20).fill('x'.repeat(MODEL_LIMITS.stringLength)) }), 'limit');
  const grid = model({ values: { type: 'list', items: { type: 'list', items: { type: 'boolean' } } } });
  failure(validateAttributes(grid, { values: Array.from({ length: 21 }, () => Array(1_000).fill(true)) }), 'limit');
  const required = model(Object.fromEntries(Array.from({ length: 99 }, (_, index) => [`f${index}`, { type: 'text', required: true }])));
  const next = model(required.attributes, 2);
  failure(previewModelUpgrade(required, next, Array.from({ length: 6 }, (_, index) => ({ id: String(index), attributes: {} }))), 'limit');
});
