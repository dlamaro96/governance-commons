// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { DOMAIN_TYPE_LIMITS, domainTypeAttributeModel, parseDomainTypeDefinition, parseDomainTypeFile, resolveDomainType } from '../../packages/domain/src/business-domain-type.ts';
import type { DomainTypeDefinition } from '../../packages/domain/src/business-domain-contracts.ts';
import { parseBoundedJSONFile, validateAttributes, type ValidationResult } from '../../packages/domain/src/model.ts';

const id = (number: number) => `00000000-0000-4000-8000-${number.toString(16).padStart(12, '0')}`;
const lifecycle = { initial: 'draft', states: ['draft', 'active'], transitions: [{ from: 'draft', to: 'active' }] };
function definition(number = 1, changes: Partial<DomainTypeDefinition> = {}): DomainTypeDefinition {
  return { formatVersion: 1, kind: 'domain-type', id: `domain_${number}`, version: 1, label: `Synthetic domain ${number}`,
    parents: [], attributes: {}, overrideAttributes: [], requiredOwner: false, lifecycle: structuredClone(lifecycle), ...changes };
}
const envelope = (number: number, changes: Partial<DomainTypeDefinition> = {}) => ({ typeId: id(number), definition: definition(number, changes) });
const pin = (number: number, version = 1) => ({ typeId: id(number), version });
function ok<T>(result: ValidationResult<T>): T { assert.ok(result.ok, JSON.stringify(result)); if (!result.ok) throw Error('Expected valid result'); return result.value; }
function fails(result: ValidationResult<unknown>, code: string, path?: string) {
  assert.equal(result.ok, false); if (result.ok) throw Error('Expected validation failure');
  assert.ok(result.issues.some(issue => issue.code === code && (path === undefined || issue.path === path)), JSON.stringify(result));
  assert.ok(result.issues.length <= 100);
}
const canonical = (value: any): string => Array.isArray(value) ? `[${value.map(canonical).join(',')}]` : value && typeof value === 'object'
  ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}` : JSON.stringify(value);
const hash = (value: unknown) => createHash('sha256').update(canonical(value)).digest('hex');

test('domain definition file roundtrip preserves Unicode, precise decimal constraints and canonical authored meaning without freezing input', () => {
  const source = definition(1, { label: 'حوكمة البيانات 🌊', attributes: { amount: { type: 'decimal', required: true,
    minimum: '90071992547409931234567890.000000001', scale: 9 }, tags: { type: 'list', items: { type: 'text' } } } });
  const parsed = ok(parseDomainTypeDefinition(source)), imported = ok(parseDomainTypeFile(JSON.stringify(parsed, null, 2)));
  assert.deepEqual(imported, parsed); assert.equal(hash(imported), hash(source)); assert.ok(Object.isFrozen(parsed.attributes.amount));
  assert.ok(Object.isFrozen(parsed.lifecycle!.transitions[0])); assert.equal(Object.isFrozen(source), false); assert.equal(Object.isFrozen(source.attributes.amount), false);
  const resolved = ok(resolveDomainType(id(1), parsed, [])), model = domainTypeAttributeModel(parsed, resolved);
  assert.equal(model.id, 'domain_1'); assert.equal(model.version, 1); assert.equal(model.formatVersion, 1); assert.ok(Object.isFrozen(model));
  assert.deepEqual(ok(validateAttributes(model, { amount: '90071992547409931234567890.000000001', tags: ['z', 'a', 'z'] })),
    { amount: '90071992547409931234567890.000000001', tags: ['z', 'a', 'z'] });
  fails(validateAttributes(model, { amount: 9007199254740992, tags: [] }), 'type');
});

test('shared typed values retain date, timestamp, duration, URI, object and safe numeric rules', () => {
  const source = definition(1, { attributes: { date: { type: 'date' }, instant: { type: 'timestamp' }, elapsed: { type: 'duration' },
    uri: { type: 'uri', schemes: ['https'] }, count: { type: 'number', integer: true }, object: { type: 'object', properties: { ready: { type: 'boolean', required: true } } } } });
  const parsed = ok(parseDomainTypeDefinition(source)), model = domainTypeAttributeModel(parsed, ok(resolveDomainType(id(1), parsed, [])));
  ok(validateAttributes(model, { date: '2024-02-29', instant: '2026-11-16T00:00:00Z', elapsed: 'PT1H', uri: 'https://example.org/domain', count: 42, object: { ready: true } }));
  for (const value of [{ date: '2025-02-29' }, { instant: '2026-11-16' }, { elapsed: 'one hour' }, { uri: 'javascript:alert(1)' },
    { count: Number.MAX_SAFE_INTEGER + 1 }, { object: { ready: 'true' } }]) assert.equal(validateAttributes(model, value).ok, false);
});

test('opaque UUID pins remain distinct from safe authored keys, kind and database versions', () => {
  ok(resolveDomainType(id(1), definition(), []));
  fails(resolveDomainType('domain_1', definition(), []), 'format', '/typeId');
  fails(resolveDomainType(id(10).toUpperCase(), definition(), []), 'format', '/typeId');
  for (const version of [0, -1, 1.5, '1', 2147483648, Infinity, -0]) assert.equal(parseDomainTypeDefinition({ ...definition(), version }).ok, false);
  ok(parseDomainTypeDefinition(definition(1, { version: 2147483647 })));
  for (const kind of ['asset-type', 'relation-type', undefined]) assert.equal(parseDomainTypeDefinition({ ...definition(), kind }).ok, false);
  fails(parseDomainTypeDefinition({ ...definition(), parents: [{ id: 'domain_2', version: 1 }] }), 'unknown_field');
  fails(parseDomainTypeDefinition(definition(1, { parents: [pin(2), pin(2, 2)], lifecycle: null })), 'duplicate');
  fails(parseDomainTypeDefinition({ ...definition(), extra: true }), 'unknown_field');
});

test('labels count Unicode code points, reject controls, empty labels, malformed Unicode and coercion', () => {
  ok(parseDomainTypeDefinition(definition(1, { label: '🌊'.repeat(200) })));
  for (const label of ['', '   ', '🌊'.repeat(201), 'bad\nlabel', 'bad\u007flabel', 'bad\u0085label', '\ud800', '\udc00', 42])
    assert.equal(parseDomainTypeDefinition({ ...definition(), label }).ok, false);
  for (const key of ['__proto__', 'constructor', 'prototype', 'domain key', id(1)]) assert.equal(parseDomainTypeDefinition({ ...definition(), id: key }).ok, false);
});

test('raw and escaped duplicate JSON keys fail before parsing; files do not coerce or accept suffix content', () => {
  const text = JSON.stringify(definition());
  fails(parseDomainTypeFile(text.replace('"version":1', '"version":1,"version":2')), 'duplicate');
  fails(parseDomainTypeFile(text.replace('"version":1', '"version":1,"ver\\u0073ion":2')), 'duplicate');
  fails(parseDomainTypeFile(text + '{}'), 'invalid_json');
  assert.equal(parseDomainTypeFile('null').ok, false);
  assert.equal(parseDomainTypeFile(text.replace('"version":1', '"version":1e999')).ok, false);
});

test('file import uses the same document node bounds as valid enum-heavy domain definitions', () => {
  for (const count of [64, 128]) {
    const attributes = Object.fromEntries(Array.from({ length: count }, (_, index) => [`field_${index}`,
      { type: 'enum' as const, values: Array.from({ length: 256 }, (_, item) => `v${String(item).padStart(3, '0')}`) }]));
    const parsed = ok(parseDomainTypeDefinition(definition(1, { attributes }))), text = JSON.stringify(parsed);
    assert.ok(Buffer.byteLength(text) < DOMAIN_TYPE_LIMITS.definitionBytes);
    const imported = ok(parseDomainTypeFile(text));
    assert.deepEqual(imported, parsed); assert.equal(hash(imported), hash(parsed));
    fails(parseDomainTypeFile(text.replace('"v255"]', '"v255"],"type":"text"')), 'duplicate');
    if (count === 64) ok(resolveDomainType(id(1), imported, []));
  }
});

test('the domain file profile enforces exact node, nesting and list bounds without widening historical profiles', () => {
  const boundary = Object.fromEntries(Array.from({ length: 100 }, (_, index) => [`field_${index}`, Array(index === 99 ? 998 : 999).fill(0)]));
  const text = JSON.stringify(boundary); // 1 object +100 lists +99,899 scalar nodes.
  ok(parseBoundedJSONFile(text, 'domain-type'));
  fails(parseBoundedJSONFile(text), 'limit'); fails(parseBoundedJSONFile(text, 'migration'), 'limit');
  boundary.field_99.push(0); fails(parseBoundedJSONFile(JSON.stringify(boundary), 'domain-type'), 'limit');
  fails(parseBoundedJSONFile(JSON.stringify(Array(1001).fill(0)), 'domain-type'), 'limit');
  let nested: unknown = 0; for (let depth = 0; depth < 32; depth += 1) nested = { child: nested };
  ok(parseBoundedJSONFile(JSON.stringify(nested), 'domain-type'));
  fails(parseBoundedJSONFile(JSON.stringify({ child: nested }), 'domain-type'), 'limit');
});

test('descriptor-only boundaries reject getters, toJSON, custom prototypes, symbols, cycles and sparse arrays without executing input code', () => {
  let touched = false; const getter = { ...definition() };
  Object.defineProperty(getter, 'label', { enumerable: true, get() { touched = true; return 'unsafe'; } });
  fails(parseDomainTypeDefinition(getter), 'invalid_json'); assert.equal(touched, false);
  const dependency = { typeId: id(2), get definition() { touched = true; return definition(2); } };
  fails(resolveDomainType(id(1), definition(1, { parents: [pin(2)] }), [dependency]), 'invalid_json'); assert.equal(touched, false);
  const attributes: any = { field: { type: 'text' } }; attributes.self = attributes;
  fails(parseDomainTypeDefinition({ ...definition(), attributes }), 'cycle');
  for (const value of [Object.create(definition()), { ...definition(), toJSON() { touched = true; return {}; } },
    { ...definition(), [Symbol('extra')]: true }, { ...definition(), parents: new Array(1) }]) assert.equal(parseDomainTypeDefinition(value).ok, false);
  assert.equal(touched, false);
  const hidden = { ...definition() }; Object.defineProperty(hidden, 'label', { value: 'Hidden', enumerable: false });
  fails(parseDomainTypeDefinition(hidden), 'invalid_json');
  const arrayGetter: any[] = []; Object.defineProperty(arrayGetter, '0', { enumerable: true, get() { touched = true; return pin(2); } });
  fails(parseDomainTypeDefinition({ ...definition(), parents: arrayGetter }), 'invalid_json'); assert.equal(touched, false);
});

test('domain parsing and inherited fields create own data properties without invoking inherited setters or read-only properties', () => {
  const name = 'domain_inherited_copy_probe', previous = Object.getOwnPropertyDescriptor(Object.prototype, name);
  let calls = 0;
  const hostile: PropertyDescriptor[] = [
    { configurable: true, set() { calls += 1; throw Error('Inherited setter must not execute'); } },
    { configurable: true, value: 'inherited read-only sentinel', writable: false },
  ];
  for (const descriptor of hostile) {
    const parent = envelope(2, { attributes: { [name]: { type: 'object', properties: {
      [name]: { type: 'text' as const }, toString: { type: 'text' as const }, hasOwnProperty: { type: 'text' as const },
    } } } }), child = definition(1, { parents: [pin(2)], lifecycle: null });
    Object.defineProperty(Object.prototype, name, descriptor);
    try {
      const parsed = ok(parseDomainTypeDefinition(parent.definition));
      const imported = ok(parseDomainTypeFile(JSON.stringify(parent.definition)));
      const resolved = ok(resolveDomainType(id(1), child, [parent]));
      assert.equal(calls, 0);
      for (const attributes of [parsed.attributes, imported.attributes, resolved.attributes]) {
        assert.deepEqual(attributes, parent.definition.attributes);
        assert.equal(Object.getPrototypeOf(attributes), Object.prototype); assert.equal(Object.hasOwn(attributes, name), true);
        assert.equal(Object.getOwnPropertyDescriptor(attributes, name)?.enumerable, true);
        const schema = attributes[name]; assert.equal(schema.type, 'object');
        if (schema.type !== 'object') assert.fail('Expected object schema');
        for (const key of [name, 'toString', 'hasOwnProperty']) {
          assert.equal(Object.hasOwn(schema.properties, key), true);
          assert.equal(Object.getOwnPropertyDescriptor(schema.properties, key)?.enumerable, true);
        }
        assert.equal(Object.isFrozen(attributes), true);
      }
      assert.equal(Object.isFrozen(parent.definition.attributes), false);
      assert.equal(Object.getPrototypeOf(parsed.parents), Array.prototype);
      assert.deepEqual(resolved.dependencies, [pin(2)]);
    } finally {
      if (previous) Object.defineProperty(Object.prototype, name, previous); else Reflect.deleteProperty(Object.prototype, name);
    }
  }
  assert.equal(Object.getOwnPropertyDescriptor(Object.prototype, name), previous);
});

test('reserved prototype keys are rejected without altering shared prototypes', () => {
  const before = Object.getOwnPropertyDescriptors(Object.prototype);
  for (const key of ['__proto__', 'constructor', 'prototype']) {
    const source = { ...definition(), attributes: { [key]: { type: 'text' } } };
    fails(parseDomainTypeDefinition(source), 'invalid_json'); fails(parseDomainTypeFile(JSON.stringify(source)), 'invalid_json');
    fails(resolveDomainType(id(1), source, []), 'invalid_json');
  }
  assert.deepEqual(Object.getOwnPropertyDescriptors(Object.prototype), before);
});

test('resolution requires every exact envelope once, rejects unused/wrong-kind/duplicate identities and tenant-unique key confusion', () => {
  const child = definition(1, { parents: [pin(2)], lifecycle: null });
  fails(resolveDomainType(id(1), child, []), 'invalid_definition');
  fails(resolveDomainType(id(1), child, [envelope(2, { version: 2 })]), 'model_version');
  fails(resolveDomainType(id(1), child, [envelope(2), envelope(2)]), 'duplicate');
  fails(resolveDomainType(id(1), child, [envelope(2), envelope(3)]), 'invalid_definition', '/dependencies/1/definition');
  fails(resolveDomainType(id(1), child, [{ typeId: id(2), definition: { ...definition(2), kind: 'asset-type' } }]), 'invalid_definition');
  fails(resolveDomainType(id(1), child, [envelope(2, { id: 'domain_1' })]), 'model_identity');
  const unknownEnvelope = { ...envelope(2), extra: true };
  fails(resolveDomainType(id(1), child, [unknownEnvelope]), 'unknown_field');
  assert.deepEqual(ok(resolveDomainType(id(1), child, [envelope(2)])).dependencies, [pin(2)]);
});

test('UUID self-cycles are checked by the resolver, independent of definition parser and version changes', () => {
  const self = definition(1, { parents: [pin(1, 9)], lifecycle: null });
  ok(parseDomainTypeDefinition(self)); fails(resolveDomainType(id(1), self, []), 'cycle');
  const child = definition(1, { parents: [pin(2)], lifecycle: null });
  fails(resolveDomainType(id(1), child, [envelope(2, { parents: [pin(1)] })]), 'cycle');
  fails(resolveDomainType(id(1), child, [envelope(1), envelope(2)]), 'duplicate');
});

test('exact inheritance diamonds coalesce equal values, sort dependency UUIDs and OR required owner deterministically', () => {
  const root = definition(1, { parents: [pin(3), pin(2)], lifecycle: null });
  const dependencies = [envelope(4, { requiredOwner: true, attributes: { region: { type: 'text', required: true } } }),
    envelope(3, { parents: [pin(4)], lifecycle: null }), envelope(2, { parents: [pin(4)], lifecycle: null })];
  const resolved = ok(resolveDomainType(id(1), root, dependencies));
  assert.deepEqual(resolved.dependencies, [pin(2), pin(3), pin(4)]); assert.equal(resolved.requiredOwner, true);
  assert.deepEqual(resolved.attributes, { region: { type: 'text', required: true } }); assert.deepEqual(resolved.lifecycle, lifecycle);
  const reordered = ok(resolveDomainType(id(1), { ...root, parents: [...root.parents].reverse() }, [...dependencies].reverse()));
  assert.deepEqual(reordered, resolved); assert.equal(hash(reordered), hash(resolved));
  assert.ok(Object.isFrozen(resolved.dependencies[0])); assert.ok(Object.isFrozen(resolved.lifecycle.states));
  assert.equal(Object.isFrozen(dependencies[0].definition.attributes), false);
});

test('conflicting ancestor versions fail even when inherited fields and lifecycles happen to match', () => {
  const root = definition(1, { parents: [pin(2), pin(3)], lifecycle: null });
  fails(resolveDomainType(id(1), root, [envelope(2, { parents: [pin(4)] }), envelope(3, { parents: [pin(4, 2)] }), envelope(4)]), 'model_version');
});

test('inherited attributes require exact explicit local replacements and reject ambiguous unhandled values', () => {
  const parents = [envelope(2, { attributes: { title: { type: 'text', maxLength: 20 } } }), envelope(3, { attributes: { title: { type: 'text', maxLength: 40 } } })];
  const root = definition(1, { parents: [pin(2), pin(3)], lifecycle: null });
  fails(resolveDomainType(id(1), root, parents), 'invalid_definition', '/attributes/title');
  fails(resolveDomainType(id(1), { ...root, attributes: { title: { type: 'text' } } }, parents), 'invalid_definition', '/attributes/title');
  const replacement = { ...root, attributes: { title: { type: 'text' as const, maxLength: 80 } }, overrideAttributes: ['title'] };
  assert.deepEqual(ok(resolveDomainType(id(1), replacement, parents)).attributes.title, { type: 'text', maxLength: 80 });
  fails(resolveDomainType(id(1), definition(1, { attributes: { local: { type: 'boolean' } }, overrideAttributes: ['local'] }), []), 'invalid_definition', '/overrideAttributes/0');
  fails(parseDomainTypeDefinition({ ...replacement, overrideAttributes: ['title', 'title'] }), 'duplicate');
  fails(parseDomainTypeDefinition({ ...replacement, overrideAttributes: ['missing'] }), 'invalid_definition');
});

test('explicit lifecycle replacement resolves ambiguity while inherited null requires exactly one policy', () => {
  const other = { initial: 'new', states: ['new', 'done'], transitions: [{ from: 'new', to: 'done' }] };
  const parents = [envelope(2), envelope(3, { lifecycle: other })], child = definition(1, { parents: [pin(2), pin(3)], lifecycle: null });
  fails(parseDomainTypeDefinition(definition(1, { lifecycle: null })), 'invalid_definition', '/lifecycle');
  fails(resolveDomainType(id(1), child, parents), 'invalid_definition', '/lifecycle');
  assert.deepEqual(ok(resolveDomainType(id(1), { ...child, lifecycle }, parents)).lifecycle, lifecycle);
  for (const invalid of [{ ...lifecycle, initial: 'unknown' }, { ...lifecycle, states: [] }, { ...lifecycle, states: ['draft', 'draft'] },
    { ...lifecycle, transitions: [{ from: 'draft', to: 'unknown' }] }, { ...lifecycle, transitions: [{ from: 'draft', to: 'draft' }] },
    { ...lifecycle, transitions: [...lifecycle.transitions, ...lifecycle.transitions] }]) assert.equal(parseDomainTypeDefinition({ ...definition(), lifecycle: invalid }).ok, false);
});

test('inheritance bounds reject a ninth parent hop including deeper reuse of a memoized ancestor', () => {
  const chain = (count: number) => Array.from({ length: count }, (_, index) => envelope(index + 2,
    index + 1 < count ? { parents: [pin(index + 3)], lifecycle: null } : {}));
  const root = definition(1, { parents: [pin(2)], lifecycle: null });
  assert.equal(ok(resolveDomainType(id(1), root, chain(8))).dependencies.length, 8);
  fails(resolveDomainType(id(1), root, chain(9)), 'limit');
  const reused = chain(8); reused.push(envelope(20, { parents: [pin(2)], lifecycle: null }));
  fails(resolveDomainType(id(1), definition(1, { parents: [pin(2), pin(20)], lifecycle: null }), reused), 'limit');
  fails(parseDomainTypeDefinition(definition(1, { parents: Array.from({ length: 9 }, (_, index) => pin(index + 2)) })), 'limit');
  fails(resolveDomainType(id(1), root, Array.from({ length: 65 }, (_, index) => envelope(index + 2))), 'limit');
});

test('the complete 64-pin boundary succeeds without silently ignoring or truncating dependencies', () => {
  const children = Array.from({ length: 8 }, (_, index) => index + 2), leaves = Array.from({ length: 56 }, (_, index) => index + 10);
  const dependencies = [...children.map((number, index) => envelope(number, { parents: leaves.slice(index * 7, index * 7 + 7).map(number => pin(number)), lifecycle: null })),
    ...leaves.map(number => envelope(number))];
  const result = ok(resolveDomainType(id(1), definition(1, { parents: children.map(number => pin(number)), lifecycle: null }), dependencies));
  assert.equal(result.dependencies.length, 64); assert.deepEqual(result.dependencies, [...children, ...leaves].map(number => pin(number)));
});

test('effective inherited schema is revalidated rather than assigning each parent its own property allowance', () => {
  const attributes = (prefix: string) => Object.fromEntries(Array.from({ length: 65 }, (_, index) => [`${prefix}_${index}`, { type: 'text' as const }]));
  const parents = [envelope(2, { attributes: attributes('first') }), envelope(3, { attributes: attributes('second') })];
  fails(resolveDomainType(id(1), definition(1, { parents: [pin(2), pin(3)], lifecycle: null }), parents), 'limit');
});

test('definition UTF-8, retained aggregate bytes, nesting and lifecycle bounds fail closed', () => {
  const large = definition(1, { attributes: { big: { type: 'enum', values: Array.from({ length: 100 }, (_, index) => `${String(index).padStart(3, '0')}${'界'.repeat(997)}`) } } });
  assert.ok(JSON.stringify(large).length < DOMAIN_TYPE_LIMITS.definitionBytes);
  fails(parseDomainTypeFile(JSON.stringify(large)), 'limit'); fails(parseDomainTypeDefinition(large), 'limit');
  const values = Array.from({ length: 200 }, (_, index) => `${String(index).padStart(3, '0')}${'a'.repeat(997)}`);
  const parents = [envelope(2, { attributes: { big: { type: 'enum', values } } }), envelope(3, { attributes: { big: { type: 'enum', values } } })];
  for (const parent of parents) ok(parseDomainTypeDefinition(parent.definition));
  fails(resolveDomainType(id(1), definition(1, { parents: [pin(2), pin(3)], lifecycle: null }), parents), 'limit');
  const deep: any = {}; let current = deep; for (let i = 0; i < 40; i += 1) { current.extra = {}; current = current.extra; }
  fails(parseDomainTypeDefinition({ ...definition(), attributes: deep }), 'limit');
  fails(parseDomainTypeDefinition({ ...definition(), lifecycle: { ...lifecycle, states: Array.from({ length: 33 }, (_, i) => `state_${i}`) } }), 'limit');
  fails(parseDomainTypeDefinition({ ...definition(), lifecycle: { ...lifecycle, transitions: Array.from({ length: 257 }, () => lifecycle.transitions[0]) } }), 'limit');
});
