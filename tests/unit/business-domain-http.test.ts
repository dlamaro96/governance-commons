// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { FastifyRequest } from 'fastify';
import { Problem } from '../../packages/authz/src/index.ts';
import { domainHttp, domainSchemaCheck, parseDomainRequestJSON, checkDomainData, domainRawQuery, domainExpectedVersion, domainIdempotencyKey } from '../../apps/api/src/business-domain-http.ts';
const rejected = (code = 'DOMAIN_JSON_INVALID') => (error: unknown) => error instanceof Problem && error.code === code;
const request = (url: string, headers: Record<string, string> = {}) => ({ url, headers }) as FastifyRequest;
const valid = { name: 'Independent domain', description: '', ownerId: null, attributes: { precise: '900719925474099312345.12345' }, reason: 'Synthetic parser regression' };

test('domain raw JSON detects duplicate escaped keys reserved names and malformed data without leaking submitted literals', () => {
  const sentinel = 'PRIVATE_SYNTHETIC_SENTINEL';
  for (const raw of [`{"name":"${sentinel}","name":"duplicate"}`, `{"name":"${sentinel}","na\\u006de":"duplicate"}`,
    '{"__proto__":{}}', '{"a":{"constructor":true}}', '{"a":{"prototype":true}}', '{"a":-0}', '{"a":1e999}', '{"a":"\\ud800"}', '{"a":01}', '{"a":true,}', '[]', 'null', '{"a":1} trailing']) {
    assert.throws(() => parseDomainRequestJSON(raw), error => rejected()(error) && !(error as Error).message.includes(sentinel));
  }
  assert.deepEqual(parseDomainRequestJSON(JSON.stringify(valid)), valid); assert.deepEqual(parseDomainRequestJSON('{"a":"é😀","b":null}'), { a: 'é😀', b: null });
});

test('domain data guard rejects accessors exotic prototypes sparse arrays symbols cycles and invalid numbers without invoking getters', () => {
  let reads = 0; const accessor = Object.defineProperty({}, 'name', { enumerable: true, get() { reads++; return 'unsafe'; } });
  const cycle: any = {}; cycle.loop = cycle;
  const symbol = { name: 'symbol', [Symbol('private')]: true }, sparse = Array(1);
  const hidden = Object.defineProperty({}, 'name', { enumerable: false, value: 'hidden' });
  for (const value of [accessor, Object.create({ inherited: true }), { sparse }, symbol, cycle, hidden, { n: Infinity }, { n: NaN }, { n: -0 }, { fn() {} }, { date: new Date() }])
    assert.throws(() => checkDomainData(value), rejected());
  assert.equal(reads, 0); checkDomainData(valid); checkDomainData({ child: Object.assign(Object.create(null), { a: [true, 'x', 0] }) });
});

test('domain envelope bounds admit documented aggregate depth and reject overflow rather than truncating fields', () => {
  const nested = (depth: number) => { let value: any = 'leaf'; for (let i = 0; i < depth; i++) value = { child: value }; return value; };
  assert.deepEqual(parseDomainRequestJSON(JSON.stringify(nested(34))), nested(34));
  assert.throws(() => parseDomainRequestJSON(JSON.stringify(nested(35))), rejected());
  assert.throws(() => parseDomainRequestJSON(JSON.stringify({ text: 'x'.repeat(1048576) })), rejected());
  assert.throws(() => parseDomainRequestJSON(JSON.stringify({ values: Array(2049).fill(0) })), rejected());
  const many = Object.fromEntries(Array.from({ length: 129 }, (_, i) => ['field' + i, 0]));
  assert.throws(() => parseDomainRequestJSON(JSON.stringify(many)), rejected());
});

test('domain exact schemas forbid unknown fields and scalar coercion while retaining precise typed attribute data', () => {
  assert.equal(domainSchemaCheck(domainHttp.request.edit, valid), true);
  for (const value of [{ ...valid, extra: true }, { ...valid, ownerId: 1 }, { ...valid, reason: true }, { ...valid, attributes: { prototype: 'unsafe' } }])
    assert.equal(domainSchemaCheck(domainHttp.request.edit, value), false);
  const definition = { formatVersion: 1, kind: 'domain-type', id: 'synthetic', version: 1, label: 'Synthetic', parents: [], attributes: {}, overrideAttributes: [], requiredOwner: false,
    lifecycle: { initial: 'draft', states: ['draft'], transitions: [] } };
  assert.equal(domainSchemaCheck(domainHttp.request.definition, { definition, reason: valid.reason }), true);
  for (const changed of [{ ...definition, version: '1' }, { ...definition, requiredOwner: 'false' }, { ...definition, lifecycle: { ...definition.lifecycle, extra: true } }])
    assert.equal(domainSchemaCheck(domainHttp.request.definition, { definition: changed, reason: valid.reason }), false);
});

test('domain Unicode text lengths count characters consistently with the public JSON Schema and domain contract', () => {
  assert.equal(domainSchemaCheck(domainHttp.request.edit, { ...valid, name: '😀'.repeat(200), reason: '😀'.repeat(500), description: '😀'.repeat(4000) }), true);
  for (const value of [{ ...valid, name: '😀'.repeat(201) }, { ...valid, reason: '😀'.repeat(501) }, { ...valid, description: '😀'.repeat(4001) }, { ...valid, name: '\ud800' }, { ...valid, name: 'x\n' }])
    assert.equal(domainSchemaCheck(domainHttp.request.edit, value), false);
});

test('domain literal queries reject duplicate spelling unknown selectors invalid encoding and numeric coercion', () => {
  const allowed = ['q', 'cursor', 'limit', 'status', 'parentId'];
  assert.deepEqual(domainRawQuery(request('/domains?q=literal_%25&limit=100&parentId=root&status=all'), allowed), { q: 'literal_%', limit: 100, parentId: 'root', status: 'all' });
  for (const query of ['q=a&q=b', 'q=a&%71=b', 'offset=1', 'limit=01', 'limit=1e0', 'limit=1.0', 'limit=0', 'limit=101', 'limit=+1', 'q=%FF', 'q=%', 'q=%00', 'status=unknown', 'parentId=ROOT', 'cursor='])
    assert.throws(() => domainRawQuery(request('/domains?' + query), allowed), rejected('DOMAIN_PAGE_INVALID'));
  assert.throws(() => domainRawQuery(request('/resource?limit=1'), []), rejected('DOMAIN_PAGE_INVALID'));
});

test('domain version and idempotency headers preserve explicit placement zero and refuse ambiguous preconditions', () => {
  for (const value of ['1', '"1"', '2147483647']) assert.equal(domainExpectedVersion(request('/', { 'if-match': value })), Number(value.replaceAll('"', '')));
  assert.equal(domainExpectedVersion(request('/', { 'if-match': '0' }), true), 0);
  for (const value of ['', '*', '0', '01', '1e0', '1.0', '-1', '2147483648', '"1", "2"'])
    assert.throws(() => domainExpectedVersion(request('/', { 'if-match': value })), rejected('VERSION_REQUIRED'));
  assert.equal(domainIdempotencyKey(request('/', { 'idempotency-key': 'synthetic-key' })), 'synthetic-key');
  for (const value of ['', 'short', 'x'.repeat(129), 'unsafe\nkey']) assert.throws(() => domainIdempotencyKey(request('/', { 'idempotency-key': value })), rejected('IDEMPOTENCY_REQUIRED'));
});

test('domain response schemas retain explicit nulls and reject extra egress fields rather than silently stripping them', () => {
  const placement = { assetId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', version: 0, domainId: null, recordedAssetVersion: null, recordedDomainVersion: null, recordedAt: null, recordedBy: null };
  assert.equal(domainSchemaCheck(domainHttp.response.placement, { placement, domain: null }), true);
  assert.equal(domainSchemaCheck(domainHttp.response.placement, { placement: { ...placement, scopeEpoch: 1 }, domain: null }), false);
  assert.equal(domainSchemaCheck(domainHttp.response.placement, { placement }), false);
  assert.equal(domainSchemaCheck(domainHttp.response.domainPage, { items: [], nextCursor: null, total: 0 }), false);
});
