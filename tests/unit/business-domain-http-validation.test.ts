// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import Fastify from 'fastify';
import { Type } from '@sinclair/typebox';
import { domainHttp, domainParams, domainQuerySchema, installDomainHttpValidation } from '../../apps/api/src/business-domain-http.ts';

const id = '11111111-1111-4111-8111-111111111111';
const precise = '900719925474099312345.12345';
const creation = () => ({ name: 'Independent typed domain', description: '', parentId: null,
  type: { typeId: id, version: 1 }, ownerId: null, reason: 'Preserve original typed values',
  attributes: { amount: 7, flag: true, precise, numericText: '7',
    nested: { amount: 8, flag: false, precise }, values: [9, true, precise] } });
const definition = () => ({ definition: { formatVersion: 1, kind: 'domain-type', id: 'http_validation', version: 1,
  label: 'Independent validation policy', parents: [], overrideAttributes: [], requiredOwner: true,
  attributes: { amount: { type: 'number', integer: true, minimum: 0, maximum: 100, required: true },
    precise: { type: 'decimal', precision: 35, scale: 5, required: true }, flag: { type: 'boolean', required: true } },
  lifecycle: { initial: 'draft', states: ['draft', 'active'], transitions: [{ from: 'draft', to: 'active' }] } },
  reason: 'Preserve exact definition constraints' });

async function application() {
  const app = Fastify({ logger: false }); let handled = 0;
  const transport: { params: unknown; query: unknown; key: unknown }[] = [];
  await app.register(async child => {
    installDomainHttpValidation(child);
    child.post('/domains/:id', { schema: { params: domainParams(['id']), querystring: domainQuerySchema(['limit', 'q']),
      headers: Type.Object({ 'idempotency-key': Type.String({ minLength: 8, maxLength: 128 }) }, { additionalProperties: true }),
      body: domainHttp.request.create, response: { 200: domainHttp.request.create } } }, async req => { handled++; transport.push({ params: { ...(req.params as object) }, query: { ...(req.query as object) }, key: req.headers['idempotency-key'] }); return req.body; });
    child.post('/domain-types', { schema: { body: domainHttp.request.definition,
      response: { 200: domainHttp.request.definition } } }, async req => { handled++; return req.body; });
  });
  return { app, handled: () => handled, transport };
}
const headers = { 'idempotency-key': 'independent-validation', 'content-type': 'application/json' };

test('domain Fastify schema phase preserves numeric, boolean and precise decimal values and all definition constraints', async () => {
  const { app, handled, transport } = await application();
  try {
    const body = { ...creation(), name: '😀'.repeat(200) }, before = structuredClone(body);
    const result = await app.inject({ method: 'POST', url: `/domains/${id}?limit=10&q=independent`, headers, payload: body });
    assert.equal(result.statusCode, 200, result.body);
    assert.deepEqual(result.json(), before);
    assert.deepEqual(body, before);
    assert.deepEqual(transport, [{ params: { id }, query: { limit: '10', q: 'independent' }, key: headers['idempotency-key'] }]);
    const policy = definition();
    const published = await app.inject({ method: 'POST', url: '/domain-types', payload: policy });
    assert.equal(published.statusCode, 200, published.body);
    assert.deepEqual(published.json(), policy);
    assert.equal(handled(), 2);
  } finally { await app.close(); }
});

test('domain Fastify validation rejects coercion, unknown fields, malformed and duplicate JSON across actual HTTP parts', async () => {
  const { app, handled } = await application();
  try {
    const valid = creation();
    const cases = [
      { payload: { ...valid, type: { ...valid.type, version: '1' } } },
      { payload: { ...valid, unexpected: true } },
      { payload: { ...valid, name: '😀'.repeat(201) } },
      { payload: { ...valid, type: { ...valid.type, unexpected: true } } },
      { payload: { ...valid, ownerId: 1 } },
      { payload: { ...valid, reason: false } },
      { payload: JSON.stringify(valid).replace('"name":', '"name":"duplicate","name":') },
      { payload: '{"name":' },
      { url: '/domains/not-a-uuid', payload: valid },
      { url: `/domains/${id}?limit=01`, payload: valid },
      { url: `/domains/${id}?unknown=true`, payload: valid },
      { headers: { ...headers, 'idempotency-key': 'short' }, payload: valid },
      { headers: { 'content-type': 'application/json' }, payload: valid },
      { url: '/domain-types', payload: { ...definition(), definition: { ...definition().definition, requiredOwner: 'true' } } },
      { url: '/domain-types', payload: { ...definition(), definition: { ...definition().definition,
        attributes: { amount: { type: 'number', integer: 'true' } } } } },
      { url: '/domain-types', payload: { ...definition(), definition: { ...definition().definition,
        attributes: { amount: { type: 'number', integer: true, unexpected: 'must not disappear' } } } } },
    ];
    for (const candidate of cases) {
      const result = await app.inject({ method: 'POST', url: `/domains/${id}`, headers, ...candidate });
      assert.equal(result.statusCode, 400, result.body);
    }
    assert.equal(handled(), 0, 'No invalid request reached a handler');
  } finally { await app.close(); }
});

test('domain validator configuration stays within its Fastify child context', async () => {
  const app = Fastify({ logger: false });
  try {
    app.post('/existing', { schema: { body: Type.Object({ value: Type.String() }) } }, async req => req.body);
    await app.register(async child => {
      installDomainHttpValidation(child);
      child.post('/domain-probe', { schema: { body: Type.Object({ value: Type.String() }) } }, async req => req.body);
    });
    const scoped = await app.inject({ method: 'POST', url: '/domain-probe', payload: { value: 7 } });
    assert.equal(scoped.statusCode, 400);
    const existing = await app.inject({ method: 'POST', url: '/existing', payload: { value: 7 } });
    assert.equal(existing.statusCode, 200);
    assert.deepEqual(existing.json(), { value: '7' }, 'The existing parent compiler remains unchanged');
  } finally { await app.close(); }
});
