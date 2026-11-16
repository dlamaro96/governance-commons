// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AUTHORITY_ADMISSION_LIMITS as limits, admitAuthorityInput, parseAuthorityInputFile,
  type AdmittedJSON, type AuthorityJSON } from '../../packages/authority/src/admission.ts';
import type { Parsed } from '../../packages/authority/src/types.ts';

function accepted(result: Parsed<AdmittedJSON>): AdmittedJSON {
  assert.equal(result.ok, true, result.ok ? 'Expected admitted JSON' : JSON.stringify(result));
  if (!result.ok) throw new Error('Expected admitted JSON');
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.value));
  assert.ok(Object.isFrozen(result.value.metrics));
  return result.value;
}
function refused(result: Parsed<AdmittedJSON>, code?: string): void {
  assert.equal(result.ok, false);
  if (result.ok) throw new Error('Expected refusal');
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.issues));
  assert.ok(result.issues.length > 0 && result.issues.length <= limits.issues);
  for (const issue of result.issues) {
    assert.ok(Object.isFrozen(issue));
    assert.ok(issue.path.length <= 1_024);
    assert.ok(issue.message.length <= 256);
  }
  if (code) assert.equal(result.issues[0].code, code);
}
function canonical(value: AuthorityJSON): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    return `{${Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
      .map(([key, child]) => `${JSON.stringify(key)}:${canonical(child)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
function frozen(value: AuthorityJSON): void {
  if (value !== null && typeof value === 'object') {
    assert.ok(Object.isFrozen(value));
    for (const child of Object.values(value)) frozen(child);
  }
}

test('authority admission exports the exact physical and proposed semantic limits without enforcing semantic claims', () => {
  assert.deepEqual(limits, {
    rawBytes: 8_388_608, canonicalBytes: 8_388_608, jsonNodes: 262_144, jsonDepth: 32, issues: 64,
    contexts: 128, dependencyEdges: 1_024, dependencyReferences: 4_096, dependencyDepth: 16,
    policyPins: 32, policyBytes: 2_097_152, policyRules: 4_096, expressionNodes: 4_096,
    bindingInstances: 512, roleInstances: 256, originGrants: 512, delegationRecords: 1_024,
    delegationDepth: 4, lineageEdgeOccurrences: 3_072, authorityPrincipals: 2_048,
    proofBytes: 2_097_152, directGroupsPerSubject: 1_024, approvedFactIds: 4_096,
    factBytes: 1_048_576, domainPathEntries: 33, catalogEntries: 16_384,
    catalogBytes: 131_072, fieldBytes: 256, ruleEvaluations: 65_536,
    predicateVisits: 65_536, matchWitnesses: 65_536, matchBytes: 33_554_432,
  });
  assert.ok(Object.isFrozen(limits));
  const unvalidatedSchema = { contexts: Array.from({ length: 129 }, () => null), issuerAllowed: true };
  accepted(admitAuthorityInput(unvalidatedSchema)); // Bounded JSON, not a decision or proof.
  const forged = accepted(admitAuthorityInput({ data: [], metrics: { nodes: 0 } }));
  assert.equal(forged.metrics.nodes, 4); // Supplied metrics do not replace measured counters.
});

test('authority admission counts scalars and containers at root depth one and keys only as bytes', () => {
  for (const value of [null, true, false, 0, -1, Number.MAX_SAFE_INTEGER, 'é😀\n']) {
    const result = accepted(admitAuthorityInput(value));
    assert.deepEqual(result.metrics, { rawBytes: null, canonicalBytes: Buffer.byteLength(JSON.stringify(value)), nodes: 1, depth: 1 });
  }
  for (const value of [{}, []]) assert.deepEqual(accepted(admitAuthorityInput(value)).metrics,
    { rawBytes: null, canonicalBytes: 2, nodes: 1, depth: 1 });
  const value = { veryLongPropertyName: 'x', nested: { a: [] } };
  const output = accepted(admitAuthorityInput(value));
  assert.equal(output.metrics.nodes, 4);
  assert.equal(output.metrics.depth, 3);
  assert.equal(output.metrics.canonicalBytes, Buffer.byteLength(canonical(value)));
});

test('authority raw admission preserves arrays, sorts canonical keys and measures normalized number spellings', () => {
  const text = ' \n {"z":[3,2,1],"2":1e3,"10":12.00,"a":true,"é":"e\\u0301"} \t';
  const result = accepted(parseAuthorityInputFile(text));
  assert.equal(canonical(result.data), '{"10":12,"2":1000,"a":true,"z":[3,2,1],"é":"é"}');
  assert.equal(result.metrics.rawBytes, Buffer.byteLength(text));
  assert.equal(result.metrics.canonicalBytes, Buffer.byteLength(canonical(result.data)));
  assert.equal(result.metrics.nodes, 9);
  assert.equal(result.metrics.depth, 3);
  frozen(result.data);
  assert.notEqual(canonical(accepted(parseAuthorityInputFile('"é"')).data), canonical(accepted(parseAuthorityInputFile('"é"')).data));
});

test('authority admission safely preserves literal prototype and constructor keys without inherited setters', () => {
  const input = JSON.parse('{"__proto__":{"polluted":true},"constructor":{"prototype":1},"toString":"literal"}') as Record<string, unknown>;
  for (const result of [admitAuthorityInput(input), parseAuthorityInputFile(JSON.stringify(input))]) {
    const value = accepted(result).data as Record<string, AuthorityJSON>;
    assert.equal(Object.getPrototypeOf(value), null);
    assert.ok(Object.hasOwn(value, '__proto__'));
    assert.equal((value.__proto__ as Record<string, AuthorityJSON>).polluted, true);
    assert.equal(({} as Record<string, unknown>).polluted, undefined);
    frozen(value);
  }
  const ordinaryReadOnly = Object.defineProperty({}, 'key', { value: 1, enumerable: true });
  assert.equal((accepted(admitAuthorityInput(ordinaryReadOnly)).data as Record<string, AuthorityJSON>).key, 1);
  const nullPrototype = Object.create(null) as Record<string, unknown>;
  nullPrototype.key = 2;
  accepted(admitAuthorityInput(nullPrototype));
});

test('authority admission copies repeated references per occurrence and freezes detached snapshots without mutating inputs', () => {
  const shared = { text: 'é', children: [1, 2] }, input = [shared, shared];
  const value = accepted(admitAuthorityInput(input));
  const output = value.data as readonly Record<string, AuthorityJSON>[];
  assert.notEqual(output, input);
  assert.notEqual(output[0], shared);
  assert.notEqual(output[0], output[1]);
  assert.notEqual(output[0].children, output[1].children);
  assert.equal(value.metrics.nodes, 11);
  assert.equal(value.metrics.depth, 4);
  assert.equal(value.metrics.canonicalBytes, Buffer.byteLength(canonical(input)));
  assert.equal(Object.isFrozen(input), false);
  assert.equal(Object.isFrozen(shared), false);
  shared.text = 'changed'; shared.children.push(3);
  assert.equal(output[0].text, 'é');
  assert.deepEqual(output[1].children, [1, 2]);
  frozen(value.data);
  assert.throws(() => { (output[0] as Record<string, AuthorityJSON>).text = 'write'; }, TypeError);
});

test('authority file admission rejects duplicate decoded keys before overwrite at any nesting level', () => {
  for (const text of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"x":[{"a/b":1,"a\\/b":2}]}',
    '{"__proto__":{},"\\u005f_proto__":{}}', '{"😀":1,"\\ud83d\\ude00":2}']) refused(parseAuthorityInputFile(text), 'duplicate');
  accepted(parseAuthorityInputFile('{"a":1,"A":2,"é":3,"e\\u0301":4}'));
});

test('authority file admission rejects malformed JSON and non-string calls without coercion', () => {
  for (const text of ['', ' ', '{', '[', '[1,]', '{"a":1,}', '{a:1}', '{"a" 1}', 'true false',
    '01', '+1', '.1', '1.', '1e', '1e+', '--1', 'NaN', 'Infinity', 'undefined', '/*x*/null', '\ufeffnull',
    '"unclosed', '"\\x00"', '"\\u123"', '"\\uZZZZ"', '"raw\nnewline"', '"raw\u0000nul"']) refused(parseAuthorityInputFile(text));
  let invoked = 0;
  refused(parseAuthorityInputFile({ toString() { invoked++; return 'null'; } } as unknown as string), 'type');
  assert.equal(invoked, 0);
});

test('authority numbers accept exact integral spellings but reject precision loss, fractional values and negative zero', () => {
  const pairs: [string, number][] = [['0', 0], ['0e99999999999999999999', 0], ['1.0', 1], ['1.2e1', 12],
    ['1200e-2', 12], ['-3.00', -3], ['9007199254740991', Number.MAX_SAFE_INTEGER],
    ['-9007199254740991', -Number.MAX_SAFE_INTEGER], ['900719925474099100e-2', Number.MAX_SAFE_INTEGER],
    ['1000000000000000.000000000000000000', 1_000_000_000_000_000]];
  for (const [text, value] of pairs) assert.equal(accepted(parseAuthorityInputFile(text)).data, value, text);
  for (const text of ['-0', '-0.0', '-0e999', '1.5', '1.0000000000000001', '9007199254740991.1',
    '9007199254740992', '-9007199254740992', '1e-999999999999999999999', '1e999999999999999999999',
    '10000000000000000000001e-22']) refused(parseAuthorityInputFile(text), 'invalid_json');
  for (const value of [NaN, Infinity, -Infinity, -0, 0.5, Number.MAX_SAFE_INTEGER + 1]) refused(admitAuthorityInput(value), 'invalid_json');
});

test('authority strings count JSON escapes and UTF-8 exactly and reject malformed Unicode in values and keys', () => {
  const strings = ['"\\/\b\t\n\f\r\u0000\u001f', 'ASCII', 'é', '中', '😀', '\u2028\u2029', 'e\u0301'];
  for (const value of strings) {
    const text = JSON.stringify(value), objectResult = accepted(admitAuthorityInput(value)), fileResult = accepted(parseAuthorityInputFile(text));
    assert.equal(objectResult.metrics.canonicalBytes, Buffer.byteLength(text));
    assert.equal(fileResult.metrics.canonicalBytes, objectResult.metrics.canonicalBytes);
    assert.equal(fileResult.data, value);
  }
  for (const text of ['"\\ud800"', '"\\udfff"', '"\\ud800a"', '{"\\ud800":0}', '"\ud800"']) refused(parseAuthorityInputFile(text), 'invalid_json');
  for (const value of ['\ud800', '\udfff', { ['\ud800']: 1 }]) refused(admitAuthorityInput(value), 'invalid_json');
  assert.equal(accepted(parseAuthorityInputFile('"\\ud83d\\ude00"')).data, '😀');
});

test('authority object admission rejects accessors, hidden and symbol properties without executing them', () => {
  let invoked = 0;
  const getter = Object.defineProperty({}, 'secret', { enumerable: true, get() { invoked++; return 'sensitive'; } });
  const setter = Object.defineProperty({}, 'secret', { enumerable: true, set(_value) { invoked++; } });
  const hidden = Object.defineProperty({}, 'hidden', { value: 1 });
  const toJSON = { toJSON() { invoked++; return {}; } };
  for (const value of [getter, setter, hidden, { [Symbol('x')]: 1 }, toJSON]) refused(admitAuthorityInput(value), 'invalid_json');
  assert.equal(invoked, 0);
});

test('authority object admission rejects proxies before every reflective operation including revoked and nested proxies', () => {
  let invoked = 0;
  const trap = (): never => { invoked++; throw new Error('trap must not run'); };
  const proxy = new Proxy({}, { get: trap, ownKeys: trap, getPrototypeOf: trap, getOwnPropertyDescriptor: trap });
  const arrayProxy = new Proxy([], { get: trap, ownKeys: trap, getPrototypeOf: trap, getOwnPropertyDescriptor: trap });
  const revoked = Proxy.revocable({}, {}); revoked.revoke();
  for (const value of [proxy, arrayProxy, revoked.proxy, { nested: proxy }]) refused(admitAuthorityInput(value), 'invalid_json');
  assert.equal(invoked, 0);
});

test('authority object admission rejects exotic, inherited, cyclic and unsupported data', () => {
  const cyclic: Record<string, unknown> = {}; cyclic.self = cyclic;
  const arrayCycle: unknown[] = []; arrayCycle.push(arrayCycle);
  class RecordSubclass { x = 1; }
  class ArraySubclass extends Array<unknown> {}
  for (const value of [new Date(), new Map(), new Set(), /x/, new Number(1), new Uint8Array([1]),
    new RecordSubclass(), new ArraySubclass(), Object.create({ x: 1 }), cyclic, arrayCycle,
    undefined, 1n, Symbol('x'), () => 1]) refused(admitAuthorityInput(value), 'invalid_json');
});

test('authority object admission rejects sparse and decorated arrays including accessor indices', () => {
  let invoked = 0;
  const sparse = Array(2); sparse[0] = 1;
  const decorated = Object.assign([1], { extra: 2 });
  const symbol = Object.assign([1], { [Symbol('x')]: 2 });
  const hidden = Object.defineProperty([1], '0', { value: 1, enumerable: false });
  const accessor = Object.defineProperty([1], '0', { enumerable: true, get() { invoked++; return 1; } });
  for (const value of [sparse, decorated, symbol, hidden, accessor]) refused(admitAuthorityInput(value), 'invalid_json');
  assert.equal(invoked, 0);
});

test('authority raw UTF-8 byte admission accepts exactly 8MiB including whitespace and refuses one byte more', () => {
  const text = `0${' '.repeat(limits.rawBytes - 1)}`;
  const result = accepted(parseAuthorityInputFile(text));
  assert.deepEqual(result.metrics, { rawBytes: limits.rawBytes, canonicalBytes: 1, nodes: 1, depth: 1 });
  refused(parseAuthorityInputFile(`${text} `), 'limit');
  const unicodeText = `"${'é'.repeat((limits.rawBytes - 2) / 2)}"`;
  assert.equal(unicodeText.length < limits.rawBytes, true);
  assert.equal(accepted(parseAuthorityInputFile(unicodeText)).metrics.rawBytes, limits.rawBytes);
  refused(parseAuthorityInputFile(`${unicodeText} `), 'limit');
});

test('authority canonical byte admission accepts the exact boundary and rejects escaped or normalized overflow', () => {
  const value = 'x'.repeat(limits.canonicalBytes - 2);
  assert.equal(accepted(admitAuthorityInput(value)).metrics.canonicalBytes, limits.canonicalBytes);
  refused(admitAuthorityInput(`${value}x`), 'limit');
  const escaped = '\u0000'.repeat(Math.floor((limits.canonicalBytes - 2) / 6));
  assert.equal(accepted(admitAuthorityInput(escaped)).metrics.canonicalBytes, limits.canonicalBytes);
  refused(admitAuthorityInput(`${escaped}\u0000`), 'limit');
  const prefix = '{"n":1e15,"x":"', suffix = '"}';
  const text = prefix + 'a'.repeat(limits.rawBytes - prefix.length - suffix.length) + suffix;
  assert.equal(Buffer.byteLength(text), limits.rawBytes);
  refused(parseAuthorityInputFile(text), 'limit'); // Normalized integer adds bytes.
});

test('authority node admission accepts 262144 value occurrences and rejects the next in object and raw APIs', () => {
  const array = Array.from({ length: limits.jsonNodes - 1 }, () => 0);
  const result = accepted(admitAuthorityInput(array));
  assert.equal(result.metrics.nodes, limits.jsonNodes);
  assert.equal(result.metrics.canonicalBytes, array.length * 2 + 1);
  assert.equal(result.metrics.depth, 2);
  refused(admitAuthorityInput([...array, 0]), 'limit');
  const text = `[${'0,'.repeat(array.length - 1)}0]`;
  assert.equal(accepted(parseAuthorityInputFile(text)).metrics.nodes, limits.jsonNodes);
  refused(parseAuthorityInputFile(`${text.slice(0, -1)},0]`), 'limit');
});

test('authority depth admission counts scalar leaves and accepts depth32 while refusing depth33', () => {
  function nested(count: number): unknown { let value: unknown = 0; while (count--) value = [value]; return value; }
  const exact = accepted(admitAuthorityInput(nested(31)));
  assert.equal(exact.metrics.depth, 32); assert.equal(exact.metrics.nodes, 32);
  refused(admitAuthorityInput(nested(32)), 'limit');
  assert.equal(accepted(parseAuthorityInputFile(`${'['.repeat(31)}0${']'.repeat(31)}`)).metrics.depth, 32);
  refused(parseAuthorityInputFile(`${'['.repeat(32)}0${']'.repeat(32)}`), 'limit');
});

test('authority diagnostics remain deterministic and bounded without exposing values or oversized submitted paths', () => {
  const secret = 'do-not-return-this-value';
  const input = Object.defineProperty({}, 'x'.repeat(2_000), { enumerable: true, get() { throw new Error(secret); } });
  const first = admitAuthorityInput(input), second = admitAuthorityInput(input);
  refused(first); assert.deepEqual(first, second);
  assert.equal(JSON.stringify(first).includes(secret), false);
  if (!first.ok) assert.equal(first.issues[0].path, '');
  const pointer = admitAuthorityInput({ 'a/b~c': undefined });
  refused(pointer);
  if (!pointer.ok) assert.equal(pointer.issues[0].path, '/a~1b~0c');
  const longNested = admitAuthorityInput({ ['x'.repeat(2_000)]: { short: undefined } });
  refused(longNested);
  if (!longNested.ok) assert.equal(longNested.issues[0].path, '');
});
