// SPDX-License-Identifier: Apache-2.0
import { pacedFetch as fetch } from '../fixtures/http-budget.ts';
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, createHash } from 'node:crypto';
import { db, scope } from '../../packages/db/src/index.ts';
import { Problem, type Principal } from '../../packages/authz/src/index.ts';
import { createModel, listModels } from '../../packages/domain/src/model-service.ts';
import { record, assetView } from '../../apps/api/src/repository.ts';

const tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const otherTenant = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const steward = '10000000-0000-4000-8000-000000000001';
const summit = '10000000-0000-4000-8000-000000000005';
const p: Principal = { id: steward, name: 'Synthetic pagination steward', tenantId: tenant,
  permissions: ['models:read', 'models:write', 'catalog:read', 'catalog:write'] };
const hooks = { record, assetSnapshot: assetView };
const id = () => 'page_' + randomUUID().replaceAll('-', '');
const definition = (id: string) => ({ formatVersion: 1, id, version: 1, attributes: {} });
const invalid = (error: unknown) => error instanceof Problem && error.code === 'MODEL_PAGE_INVALID';

test('model inventory traverses more than100 definitions with bounded unique pages and literal search', async () => {
  const prefix = id(), complete = new Error('Roll back only this synthetic pagination fixture');
  await assert.rejects(scope(tenant, steward, async tx => {
    const expected = Array.from({ length: 103 }, (_, i) => `${prefix}_${String(i).padStart(3, '0')}`);
    // Real service writes and production journals in a transaction deliberately
    // rolled back after assertions; existing immutable history is untouched.
    for (const modelId of expected) await createModel(tx, p, randomUUID(), definition(modelId), hooks);
    const first = await listModels(tx, p, { q: prefix, limit: 100 });
    assert.equal(first.items.length, 100); assert.ok(first.nextCursor);
    const second = await listModels(tx, p, { q: prefix, limit: 100, cursor: first.nextCursor });
    assert.equal(second.items.length, 3); assert.equal(second.nextCursor, null);
    assert.deepEqual([...first.items, ...second.items].map(row => row.id), expected);
    assert.equal((await listModels(tx, p, { q: prefix })).items.length, 50);
    const literal = await listModels(tx, p, { q: prefix + '_00', limit: 20 });
    assert.equal(literal.items.length, 10);
    assert.equal((await listModels(tx, p, { q: '%' })).items.length, 0);
    assert.equal((await listModels(tx, p, { q: '\\' })).items.length, 0);
    await assert.rejects(listModels(tx, p, { q: 'different', limit: 100, cursor: first.nextCursor }), invalid);
    await assert.rejects(listModels(tx, p, { q: prefix, limit: 99, cursor: first.nextCursor }), invalid);
    await assert.rejects(listModels(tx, p, { q: prefix, cursor: first.nextCursor }), invalid);
    for (const query of [{ limit: 0 }, { limit: 101 }, { limit: 1.5 }, { q: 'x'.repeat(65) }, { q: '\0' }, { cursor: '%' }, { cursor: '' }]) {
      await assert.rejects(listModels(tx, p, query), invalid);
    }
    throw complete;
  }), error => error === complete);
  assert.equal((await scope(tenant, steward, tx => listModels(tx, p, { q: prefix }))).items.length, 0);
});

async function session(actor = steward, organization = tenant) {
  const token = randomUUID() + randomUUID(), csrf = randomUUID();
  await db.insertInto('sessions').values({ id_hash: createHash('sha256').update(token).digest('hex'),
    identity_id: actor, tenant_id: organization, csrf, expires_at: new Date(Date.now() + 120_000) }).execute();
  return { Cookie: `gc_session=${token}`, 'X-CSRF-Token': csrf, Origin: process.env.PUBLIC_URL ?? 'http://localhost:4310' };
}
test('HTTP model pagination authenticates cursor payloads and binds search, page size, actor and tenant', async () => {
  const prefix = id();
  await scope(tenant, steward, async tx => {
    for (const suffix of ['a', 'b']) await createModel(tx, p, randomUUID(), definition(prefix + suffix), hooks);
  });
  const base = (process.env.TEST_BASE_URL ?? 'http://api:4310') + '/api/v1/models';
  const headers = await session();
  const first = await fetch(`${base}?limit=1&q=${prefix}`, { headers });
  assert.equal(first.status, 200); const one = await first.json() as any;
  assert.deepEqual(one.items.map((row: any) => row.id), [prefix + 'a']); assert.ok(one.nextCursor);
  const second = await fetch(`${base}?limit=1&q=${prefix}&cursor=${encodeURIComponent(one.nextCursor)}`, { headers });
  assert.equal(second.status, 200); const two = await second.json() as any;
  assert.deepEqual(two.items.map((row: any) => row.id), [prefix + 'b']); assert.equal(two.nextCursor, null);
  const next = (cursor: string, sessionHeaders: Record<string, string> = headers, query = { q: prefix, limit: '1' }) =>
    fetch(`${base}?${new URLSearchParams({ ...query, cursor })}`, { headers: sessionHeaders });
  for (const query of [{ q: 'different', limit: '1' }, { q: prefix, limit: '2' }, { q: '', limit: '1' }]) {
    const rejected = await next(one.nextCursor, headers, query);
    assert.equal(rejected.status, 400); assert.equal((await rejected.json() as any).code, 'MODEL_PAGE_INVALID');
  }
  assert.equal((await fetch(`${base}?q=${prefix}&cursor=${encodeURIComponent(one.nextCursor)}`, { headers })).status, 400);
  const otherActor = await session('10000000-0000-4000-8000-000000000003');
  assert.equal((await next(one.nextCursor, otherActor)).status, 400);
  // The other actor can read the inventory; rejecting the cursor is an actor
  // binding check, not a missing model-read permission or empty inventory.
  const actorInventory = await fetch(`${base}?limit=1&q=${prefix}`, { headers: otherActor });
  assert.equal(actorInventory.status, 200);
  assert.deepEqual((await actorInventory.json() as any).items.map((row: any) => row.id), [prefix + 'a']);
  const otherHeaders = await session(summit, otherTenant);
  const denied = await next(one.nextCursor, otherHeaders);
  assert.equal(denied.status, 400); assert.ok(!(await denied.text()).includes(prefix));
  const clean = await fetch(`${base}?q=${prefix}`, { headers: otherHeaders });
  assert.deepEqual(await clean.json(), { items: [], nextCursor: null });
  const [encodedPayload, signature, extra] = one.nextCursor.split('.');
  assert.equal(extra, undefined); assert.match(signature, /^[A-Za-z0-9_-]{43}$/);
  const payload = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString());
  assert.equal(payload.v, 2);
  const tampered = (changes: Record<string, unknown>) =>
    `${Buffer.from(JSON.stringify({ ...payload, ...changes })).toString('base64url')}.${signature}`;
  const consumer = '10000000-0000-4000-8000-000000000003';
  const mutations: { changes: Record<string, unknown>; actor?: Record<string, string>; query?: { q: string; limit: string } }[] = [
    { changes: { after: prefix + 'b' } },
    { changes: { q: 'different' }, query: { q: 'different', limit: '1' } },
    { changes: { limit: 2 }, query: { q: prefix, limit: '2' } },
    { changes: { sort: 'id:desc' } },
    { changes: { actorId: consumer }, actor: otherActor },
    { changes: { tenantId: otherTenant } },
    { changes: { tenantId: otherTenant, actorId: summit }, actor: otherHeaders },
    { changes: { v: 1 } },
  ];
  // Keep the genuine signature while altering selectors. Matching the changed
  // query/actor proves signature verification, not only envelope binding.
  for (const mutation of mutations) {
    const rejected = await next(tampered(mutation.changes), mutation.actor ?? headers, mutation.query ?? { q: prefix, limit: '1' });
    assert.equal(rejected.status, 400);
    const problem = await rejected.json() as any;
    assert.equal(problem.code, 'MODEL_PAGE_INVALID'); assert.equal(JSON.stringify(problem).includes(prefix), false);
  }
  for (const cursor of [encodedPayload, `${encodedPayload}.${'A'.repeat(43)}`, 'x'.repeat(1025)]) {
    assert.equal((await next(cursor)).status, 400);
  }
  const repeated = await next(one.nextCursor);
  assert.equal(repeated.status, 200); assert.deepEqual(await repeated.json(), two);
  assert.equal((await fetch(`${base}?limit=101`, { headers })).status, 400);
  assert.equal((await fetch(`${base}?limit=1`)).status, 401);
});

after(async () => { await db.destroy(); });
