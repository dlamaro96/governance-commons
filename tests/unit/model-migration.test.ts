// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  MODEL_LIMITS, parseModelDefinition, previewModelUpgrade,
  type AttributeDefinition, type ModelDefinition, type ValidationResult,
} from '../../packages/domain/src/model.ts';
import {
  MIGRATION_LIMITS, applyModelMigrationToAttributes, parseMigrationPlan, validateMigrationPlanForModels,
  type MigrationAcknowledgement, type MigrationOperation, type MigrationPlan,
} from '../../packages/domain/src/model-migration.ts';

function success<T>(result: ValidationResult<T>): T {
  if (!result.ok) assert.fail(JSON.stringify(result.issues));
  return result.value;
}
function failure<T>(result: ValidationResult<T>, code?: string, path?: string): void {
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.ok(result.issues.length > 0 && result.issues.length <= MIGRATION_LIMITS.issues);
  if (code) assert.ok(result.issues.some(issue => issue.code === code && (path === undefined || issue.path === path)), JSON.stringify(result.issues));
}
function model(attributes: Record<string, AttributeDefinition>, version = 1): ModelDefinition {
  return success(parseModelDefinition({ formatVersion: 1, id: 'harbor.asset', version, attributes }));
}
function plan(overrides: Partial<MigrationPlan> = {}): MigrationPlan {
  return { formatVersion: 1, modelId: 'harbor.asset', targetVersion: 2, sourceVersions: [1], acknowledgedChanges: [], operations: [], ...overrides };
}
function upgrade(head: ModelDefinition, target: ModelDefinition, operations: readonly MigrationOperation[], overrides: Partial<MigrationPlan> = {}): MigrationPlan {
  const changes = success(previewModelUpgrade(head, target, [])).changes.filter(change => change.requiresMigration);
  return plan({ targetVersion: target.version, sourceVersions: [head.version], operations,
    acknowledgedChanges: changes.map(({ code, path }) => ({ code, path })) as MigrationAcknowledgement[], ...overrides });
}
function freeze<T>(input: T): T {
  if (input && typeof input === 'object') { for (const value of Object.values(input)) freeze(value); Object.freeze(input); }
  return input;
}

test('migration plans round trip as immutable data without retaining caller-owned objects', () => {
  const input = plan({ operations: [{ op: 'set', path: ['configuration'], value: { enabled: true, amounts: ['12345678901234567890.123'] }, mode: 'replace' }] });
  const result = success(parseMigrationPlan(input));
  assert.deepEqual(result, input);
  assert.notEqual(result, input);
  assert.notEqual(result.operations, input.operations);
  assert.ok(Object.isFrozen(result) && Object.isFrozen(result.operations[0]));
  assert.deepEqual(success(parseMigrationPlan(JSON.parse(JSON.stringify(result)))), result);
  assert.equal(Object.isFrozen(input), false);
});

test('ordered operations migrate nested values, map enums and preserve unrelated types without mutating input', () => {
  const source = model({
    count: { type: 'number' }, amount: { type: 'decimal' }, obsolete: { type: 'text' },
    lifecycle: { type: 'enum', values: ['draft', 'published'] }, note: { type: 'text' },
    details: { type: 'object', properties: { oldCode: { type: 'text' }, enabled: { type: 'boolean' } } },
    links: { type: 'list', items: { type: 'uri' } },
  });
  const target = model({
    count: { type: 'decimal', required: true }, amount: { type: 'decimal' },
    lifecycle: { type: 'enum', values: ['review', 'published'] }, note: { type: 'text' },
    details: { type: 'object', properties: { code: { type: 'text', required: true }, enabled: { type: 'boolean' } } },
    links: { type: 'list', items: { type: 'uri' } },
  }, 2);
  const migration = freeze(upgrade(source, target, [
    { op: 'rename', from: ['details', 'oldCode'], to: ['details', 'code'], onMissing: 'error' },
    { op: 'remove', path: ['obsolete'], onMissing: 'error' },
    { op: 'set', path: ['note'], value: 'default', mode: 'ifMissing' },
    { op: 'set', path: ['details', 'enabled'], value: true, mode: 'replace' },
    { op: 'enumMap', path: ['lifecycle'], mappings: [{ from: 'draft', to: 'review' }], onMissing: 'error', onUnmapped: 'keep' },
    { op: 'convert', path: ['count'], conversion: 'safeIntegerToDecimal', onMissing: 'error' },
  ]));
  const attributes = freeze({ count: 42, amount: '90071992547409931234567890.123456789', obsolete: 'remove explicitly', lifecycle: 'draft', note: 'retain', details: { oldCode: 'A', enabled: false }, links: ['urn:harbor:synthetic:1'] });
  const before = JSON.stringify(attributes);
  const result = success(applyModelMigrationToAttributes({ head: source, source, target, plan: migration, attributes }));
  assert.deepEqual(result, { count: '42', amount: attributes.amount, lifecycle: 'review', note: 'retain', details: { code: 'A', enabled: true }, links: attributes.links });
  assert.equal(JSON.stringify(attributes), before);
  assert.notEqual(result.details, attributes.details);
  assert.notEqual(result.links, attributes.links);
});

test('decimal-to-text and text-to-decimal round trips never pass through floating-point numbers', () => {
  const decimal = model({ amount: { type: 'decimal' } });
  const text = model({ amount: { type: 'text' } }, 2);
  const restored = model({ amount: { type: 'decimal' } }, 3);
  for (const amount of ['0', '-90071992547409931234567890.123456789', `0.${'0'.repeat(MODEL_LIMITS.decimalDigits - 1)}1`, '9'.repeat(MODEL_LIMITS.decimalDigits)]) {
    const textValues = success(applyModelMigrationToAttributes({ head: decimal, source: decimal, target: text,
      plan: upgrade(decimal, text, [{ op: 'convert', path: ['amount'], conversion: 'decimalToText', onMissing: 'error' }]), attributes: { amount } }));
    const decimalValues = success(applyModelMigrationToAttributes({ head: text, source: text, target: restored,
      plan: upgrade(text, restored, [{ op: 'convert', path: ['amount'], conversion: 'textToDecimal', onMissing: 'error' }]), attributes: textValues }));
    assert.equal(decimalValues.amount, amount);
    assert.equal(JSON.parse(JSON.stringify(decimalValues)).amount, amount);
  }
});

test('safe-integer conversion rejects fractions and unsafe integers without rounding', () => {
  const source = model({ value: { type: 'number' } }); const target = model({ value: { type: 'decimal' } }, 2);
  const migration = upgrade(source, target, [{ op: 'convert', path: ['value'], conversion: 'safeIntegerToDecimal', onMissing: 'error' }]);
  for (const value of [0, 1, -1, Number.MAX_SAFE_INTEGER, Number.MIN_SAFE_INTEGER]) {
    assert.equal(success(applyModelMigrationToAttributes({ head: source, source, target, plan: migration, attributes: { value } })).value, String(value));
  }
  for (const value of [0.1, Number.MAX_SAFE_INTEGER + 1, Number.MIN_SAFE_INTEGER - 1, 1e30]) {
    failure(applyModelMigrationToAttributes({ head: source, source, target, plan: migration, attributes: { value } }), 'type', '/plan/operations/0');
  }
});

test('text-to-decimal rejects normalization, trimming, exponents and target precision loss', () => {
  const source = model({ value: { type: 'text' } }); const target = model({ value: { type: 'decimal', precision: 5, scale: 2 } }, 2);
  const migration = upgrade(source, target, [{ op: 'convert', path: ['value'], conversion: 'textToDecimal', onMissing: 'error' }]);
  for (const value of [' 1', '1 ', '+1', '-0', '01', '1.0', '1e2', '.5', 'NaN', 'Infinity']) {
    failure(applyModelMigrationToAttributes({ head: source, source, target, plan: migration, attributes: { value } }), 'format', '/plan/operations/0');
  }
  failure(applyModelMigrationToAttributes({ head: source, source, target, plan: migration, attributes: { value: '1234.56' } }), 'range', '/targetAttributes/value');
  assert.equal(success(applyModelMigrationToAttributes({ head: source, source, target, plan: migration, attributes: { value: '123.45' } })).value, '123.45');
});

test('destructive acknowledgements are exact and required even when no assets are supplied', () => {
  const head = model({ old: { type: 'text' }, value: { type: 'number' }, status: { type: 'enum', values: ['draft', 'ready'] } });
  const target = model({ value: { type: 'decimal' }, status: { type: 'enum', values: ['ready'] } }, 2);
  const acknowledgedChanges: MigrationAcknowledgement[] = [
    { code: 'attribute_removed', path: '/attributes/old' },
    { code: 'type_changed', path: '/attributes/value' },
    { code: 'constraints_changed', path: '/attributes/status' },
  ];
  const migration = plan({ acknowledgedChanges, sourceVersions: [] });
  success(validateMigrationPlanForModels(head, target, migration));
  failure(validateMigrationPlanForModels(head, target, plan()), 'required', '/plan/acknowledgedChanges');
  failure(validateMigrationPlanForModels(head, target, plan({ acknowledgedChanges: acknowledgedChanges.slice(1) })), 'required');
  failure(validateMigrationPlanForModels(head, target, plan({ acknowledgedChanges: [...acknowledgedChanges, { code: 'attribute_removed', path: '/attributes/nonexistent' }] })), 'invalid_definition', '/plan/acknowledgedChanges/3');
  failure(parseMigrationPlan(plan({ acknowledgedChanges: [...acknowledgedChanges, acknowledgedChanges[0]] })), 'duplicate', '/acknowledgedChanges/3');
  failure(validateMigrationPlanForModels(head, target, { ...migration, modelId: 'other.asset' }), 'model_identity', '/plan/modelId');
  failure(validateMigrationPlanForModels(head, target, { ...migration, targetVersion: 3 }), 'model_version', '/plan/targetVersion');
  failure(validateMigrationPlanForModels(head, { ...target, version: 3 }, migration), 'model_version');
});

test('historical pinned schemas validate independently from the current head and declared source versions', () => {
  const source = model({ title: { type: 'text' } });
  const head = model({ title: { type: 'text' }, note: { type: 'text' } }, 2);
  const target = model({ title: { type: 'text' }, note: { type: 'text', required: true } }, 3);
  const migration = upgrade(head, target, [{ op: 'set', path: ['note'], value: 'migrated', mode: 'ifMissing' }], { sourceVersions: [1, 2] });
  assert.deepEqual(success(applyModelMigrationToAttributes({ head, source, target, plan: migration, attributes: { title: 'Historic asset' } })), { title: 'Historic asset', note: 'migrated' });
  failure(applyModelMigrationToAttributes({ head, source, target, plan: { ...migration, sourceVersions: [2] }, attributes: {} }), 'model_version', '/source/version');
  failure(applyModelMigrationToAttributes({ head, source: { ...source, id: 'different' }, target, plan: migration, attributes: {} }), 'model_identity', '/source/id');
  failure(applyModelMigrationToAttributes({ head, source, target, plan: migration, attributes: { note: 'not declared in source' } }), 'unknown_field', '/sourceAttributes/note');
});

test('full source and target validation prevent dropping unknown data or silently reinterpreting values', () => {
  const source = model({ old: { type: 'text' }, value: { type: 'number' } });
  const target = model({ value: { type: 'decimal', required: true } }, 2);
  const migration = upgrade(source, target, []);
  failure(applyModelMigrationToAttributes({ head: source, source, target, plan: migration, attributes: { old: 'retained', value: 1 } }), 'unknown_field', '/targetAttributes/old');
  failure(applyModelMigrationToAttributes({ head: source, source, target, plan: migration, attributes: { value: 1 } }), 'type', '/targetAttributes/value');
  failure(applyModelMigrationToAttributes({ head: source, source, target, plan: migration, attributes: {} }), 'required', '/targetAttributes/value');
  failure(applyModelMigrationToAttributes({ head: source, source, target, plan: migration, attributes: { unknown: 'private' } }), 'unknown_field', '/sourceAttributes/unknown');
});

test('rename never overwrites a destination and failed operations leave the original value graph untouched', () => {
  const source = model({ obsolete: { type: 'text' }, from: { type: 'text' }, to: { type: 'text' } });
  const target = model({ to: { type: 'text' } }, 2);
  const migration = upgrade(source, target, [
    { op: 'remove', path: ['obsolete'], onMissing: 'error' },
    { op: 'rename', from: ['from'], to: ['to'], onMissing: 'error' },
  ]);
  const attributes = freeze({ obsolete: 'still here', from: 'source', to: 'destination' });
  failure(applyModelMigrationToAttributes({ head: source, source, target, plan: migration, attributes }), 'invalid_definition', '/plan/operations/1/to');
  assert.deepEqual(attributes, { obsolete: 'still here', from: 'source', to: 'destination' });
});

test('missing optional paths have explicit semantics and destination parents are never created implicitly', () => {
  const source = model({ old: { type: 'text' } });
  const target = model({ details: { type: 'object', properties: { name: { type: 'text' } } } }, 2);
  const operation: MigrationOperation = { op: 'rename', from: ['old'], to: ['details', 'name'], onMissing: 'skip' };
  const migration = upgrade(source, target, [operation]);
  assert.deepEqual(success(applyModelMigrationToAttributes({ head: source, source, target, plan: migration, attributes: {} })), {});
  failure(applyModelMigrationToAttributes({ head: source, source, target, plan: { ...migration, operations: [{ ...operation, onMissing: 'error' }] }, attributes: {} }), 'required', '/plan/operations/0');
  failure(applyModelMigrationToAttributes({ head: source, source, target, plan: migration, attributes: { old: 'A' } }), 'required', '/plan/operations/0/to');
  assert.deepEqual(success(applyModelMigrationToAttributes({ head: source, source, target,
    plan: { ...migration, operations: [{ op: 'set', path: ['details'], value: {}, mode: 'ifMissing' }, operation] }, attributes: { old: 'A' } })), { details: { name: 'A' } });
  failure(validateMigrationPlanForModels(source, target, { ...migration, operations: [{ ...operation, to: ['unknown'] }] }), 'invalid_definition', '/plan/operations/0/to');
  failure(applyModelMigrationToAttributes({ head: source, source, target,
    plan: { ...migration, operations: [{ op: 'remove', path: ['typo'], onMissing: 'skip' }] }, attributes: {} }), 'invalid_definition', '/plan/operations/0/path');
});

test('literal set values must match the target even when ifMissing would preserve an existing value', () => {
  const source = model({ enabled: { type: 'boolean' } }); const target = model(source.attributes, 2);
  for (const mode of ['replace', 'ifMissing'] as const) {
    const migration = upgrade(source, target, [{ op: 'set', path: ['enabled'], value: true, mode }]);
    assert.equal(success(applyModelMigrationToAttributes({ head: source, source, target, plan: migration, attributes: { enabled: false } })).enabled, mode === 'replace');
    assert.equal(success(applyModelMigrationToAttributes({ head: source, source, target, plan: migration, attributes: {} })).enabled, true);
  }
  failure(validateMigrationPlanForModels(source, target, upgrade(source, target, [{ op: 'set', path: ['enabled'], value: 'true', mode: 'ifMissing' }])), 'type', '/plan/operations/0/value');
});

test('enum mapping requires an explicit unmapped-value policy and validates every mapping destination', () => {
  const source = model({ status: { type: 'enum', values: ['old', 'keep'] } });
  const target = model({ status: { type: 'enum', values: ['new', 'keep'] } }, 2);
  const operation: MigrationOperation = { op: 'enumMap', path: ['status'], mappings: [{ from: 'old', to: 'new' }], onMissing: 'skip', onUnmapped: 'keep' };
  const migration = upgrade(source, target, [operation]);
  for (const status of ['old', 'keep']) assert.equal(success(applyModelMigrationToAttributes({ head: source, source, target, plan: migration, attributes: { status } })).status, status === 'old' ? 'new' : status);
  assert.deepEqual(success(applyModelMigrationToAttributes({ head: source, source, target, plan: migration, attributes: {} })), {});
  failure(applyModelMigrationToAttributes({ head: source, source, target, plan: { ...migration, operations: [{ ...operation, onUnmapped: 'error' }] }, attributes: { status: 'keep' } }), 'enum', '/plan/operations/0');
  failure(validateMigrationPlanForModels(source, target, { ...migration, operations: [{ ...operation, mappings: [{ from: 'unused', to: 'invalid' }] }] }), 'enum', '/plan/operations/0/mappings/0/to');
});

test('object paths cannot traverse lists or inherited properties, while replacing an entire typed list is explicit', () => {
  const source = model({ items: { type: 'list', items: { type: 'text' } } }); const target = model(source.attributes, 2);
  failure(parseMigrationPlan(plan({ operations: [{ op: 'remove', path: ['items', '0'], onMissing: 'skip' }] })), 'format', '/operations/0/path/1');
  for (const path of [['items', 'name'], ['toString'], ['hasOwnProperty']]) {
    failure(applyModelMigrationToAttributes({ head: source, source, target, plan: upgrade(source, target, [{ op: 'remove', path, onMissing: 'skip' }]), attributes: {} }), 'invalid_definition', '/plan/operations/0/path');
  }
  assert.deepEqual(success(applyModelMigrationToAttributes({ head: source, source, target,
    plan: upgrade(source, target, [{ op: 'set', path: ['items'], value: ['B', 'C'], mode: 'replace' }]), attributes: { items: ['A'] } })), { items: ['B', 'C'] });
});

test('conversion and enum operation types are checked even when optional values are absent', () => {
  const source = model({ value: { type: 'text' } }); const target = model(source.attributes, 2);
  failure(validateMigrationPlanForModels(source, target, upgrade(source, target, [{ op: 'convert', path: ['value'], conversion: 'safeIntegerToDecimal', onMissing: 'skip' }])), 'invalid_definition', '/plan/operations/0/conversion');
  failure(validateMigrationPlanForModels(source, target, upgrade(source, target, [{ op: 'enumMap', path: ['value'], mappings: [{ from: 'A', to: 'B' }], onMissing: 'skip', onUnmapped: 'keep' }])), 'invalid_definition', '/plan/operations/0/path');
});

test('strict plan shapes reject execution hooks, missing policies, ambiguous versions and unsafe names', () => {
  const invalid: unknown[] = [
    { ...plan(), sql: 'DROP TABLE assets' }, { ...plan(), formatVersion: 2 }, { ...plan(), modelId: '__proto__' },
    { ...plan(), operations: [{ op: 'evaluate', expression: 'process.exit()' }] },
    { ...plan(), operations: [{ op: 'remove', path: ['old'] }] },
    { ...plan(), operations: [{ op: 'set', path: ['value'], value: 1 }] },
    { ...plan(), operations: [{ op: 'convert', path: ['value'], conversion: 'round', onMissing: 'skip' }] },
    { ...plan(), operations: [{ op: 'rename', from: ['a'], to: ['a', 'b'], onMissing: 'skip' }] },
    { ...plan(), operations: [{ op: 'rename', from: ['a'], to: ['a'], onMissing: 'skip' }] },
    { ...plan(), operations: [{ op: 'remove', path: ['constructor'], onMissing: 'skip' }] },
    { ...plan(), operations: [{ op: 'remove', path: [], onMissing: 'skip' }] },
    { ...plan(), operations: [{ op: 'enumMap', path: ['status'], mappings: [{ from: 'a', to: 'b' }, { from: 'a', to: 'c' }], onMissing: 'skip', onUnmapped: 'keep' }] },
    { ...plan(), sourceVersions: [1, 1] }, { ...plan(), targetVersion: 4, sourceVersions: [2, 1] },
    { ...plan(), sourceVersions: [2] }, { ...plan(), targetVersion: Number.MAX_SAFE_INTEGER + 1 },
    { ...plan(), sourceVersions: ['1'] }, { ...plan(), acknowledgedChanges: [{ code: 'attribute_removed', path: '/attributes/a/constructor' }] },
  ];
  for (const input of invalid) failure(parseMigrationPlan(input));
});

test('plan parsing rejects accessors without invoking them and rejects prototype, cycle and non-JSON tricks', () => {
  let invoked = false;
  const getter = Object.defineProperty({ ...plan() }, 'operations', { enumerable: true, get() { invoked = true; throw new Error('must not run'); } });
  failure(parseMigrationPlan(getter), 'invalid_json', '/operations'); assert.equal(invoked, false);
  const cycle: Record<string, unknown> = {}; cycle.self = cycle;
  const literal = (value: unknown): unknown => ({ ...plan(), operations: [{ op: 'set', path: ['value'], value, mode: 'replace' }] });
  for (const value of [cycle, new Date(), new Map(), new Set(), Object.create({ inherited: true }), JSON.parse('{"__proto__":{"polluted":true}}'), { [Symbol('key')]: 'hidden' }, Object.defineProperty({}, 'hidden', { value: true }), null, undefined, NaN, Infinity, -0, 1n]) failure(parseMigrationPlan(literal(value)));
  failure(parseMigrationPlan({ ...plan(), operations: Array(1) }), 'invalid_json', '/operations');
  failure(parseMigrationPlan({ ...plan(), operations: Object.assign([], { extra: true }) }), 'invalid_json', '/operations');
  const arrayGetter = Object.defineProperty([true], '0', { enumerable: true, get() { invoked = true; return false; } });
  failure(parseMigrationPlan(literal(arrayGetter)), 'invalid_json'); assert.equal(invoked, false);
  const nullPrototype = Object.assign(Object.create(null), plan()); success(parseMigrationPlan(nullPrototype));
  assert.equal(Object.hasOwn(Object.prototype, 'polluted'), false);
});

test('plan operation, path, source-version and mapping cardinalities are bounded at their explicit limits', () => {
  const operation: MigrationOperation = { op: 'remove', path: ['value'], onMissing: 'skip' };
  success(parseMigrationPlan(plan({ operations: Array(MIGRATION_LIMITS.operations).fill(operation) })));
  failure(parseMigrationPlan(plan({ operations: Array(MIGRATION_LIMITS.operations + 1).fill(operation) })), 'limit', '/operations');
  success(parseMigrationPlan(plan({ operations: [{ ...operation, path: Array(MIGRATION_LIMITS.pathSegments).fill('value') }] })));
  failure(parseMigrationPlan(plan({ operations: [{ ...operation, path: Array(MIGRATION_LIMITS.pathSegments + 1).fill('value') }] })), 'limit', '/operations/0/path');
  const versions = Array.from({ length: MIGRATION_LIMITS.sourceVersions }, (_, index) => index + 1);
  success(parseMigrationPlan(plan({ targetVersion: versions.length + 2, sourceVersions: versions })));
  failure(parseMigrationPlan(plan({ targetVersion: versions.length + 2, sourceVersions: [...versions, versions.length + 1] })), 'limit', '/sourceVersions');
  const mapping: MigrationOperation = { op: 'enumMap', path: ['status'], mappings: Array.from({ length: MIGRATION_LIMITS.enumMappings }, (_, index) => ({ from: `from${index}`, to: `to${index}` })), onMissing: 'skip', onUnmapped: 'keep' };
  success(parseMigrationPlan(plan({ operations: [mapping] })));
  failure(parseMigrationPlan(plan({ operations: [{ ...mapping, mappings: [...mapping.mappings, { from: 'extra', to: 'extra' }] }] })), 'limit', '/operations/0/mappings');
});

test('defensive plan copying bounds node count, nesting, strings and issue output', () => {
  const literal = (value: unknown): unknown => ({ ...plan(), operations: [{ op: 'set', path: ['value'], value, mode: 'replace' }] });
  failure(parseMigrationPlan(literal('x'.repeat(MIGRATION_LIMITS.stringLength + 1))), 'limit', '/operations/0/value');
  failure(parseMigrationPlan(literal('\ud800')), 'format', '/operations/0/value');
  failure(parseMigrationPlan(literal(Array.from({ length: 17 }, () => 'x'.repeat(MIGRATION_LIMITS.stringLength)))), 'limit');
  failure(parseMigrationPlan(literal(Array.from({ length: 21 }, () => Array(1_000).fill(true)))), 'limit');
  let nested: unknown = true;
  for (let index = 0; index < MIGRATION_LIMITS.planDepth + 1; index += 1) nested = { child: nested };
  failure(parseMigrationPlan(literal(nested)), 'limit');
  const fields = Object.fromEntries(Array.from({ length: 110 }, (_, index) => [`unknown${index}`, 'private marker']));
  const result = parseMigrationPlan({ ...plan(), ...fields });
  failure(result, 'limit');
  if (!result.ok) assert.ok(result.issues.every(issue => !issue.message.includes('private marker')));
  assert.deepEqual(result, parseMigrationPlan({ ...fields, ...plan() }));
});
