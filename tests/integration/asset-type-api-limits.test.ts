// SPDX-License-Identifier: Apache-2.0
import { pacedFetch as fetch } from '../fixtures/http-budget.ts';
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { db } from '../../packages/db/src/index.ts';
import type { AssetTypeDefinition } from '../../packages/domain/src/asset-type.ts';

const tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', otherTenant = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const steward = '10000000-0000-4000-8000-000000000001', consumer = '10000000-0000-4000-8000-000000000003';
const summit = '10000000-0000-4000-8000-000000000005';
const base = process.env.TEST_BASE_URL ?? 'http://api:4310', origin = process.env.PUBLIC_URL ?? 'http://localhost:4310';
const unique = () => 'type_api_' + randomUUID().replaceAll('-', '');
function definition(id = unique()): AssetTypeDefinition {
  return { formatVersion: 1, id, version: 1, parents: [], attributes: {}, overrideAttributes: [], requiredOwner: false,
    lifecycle: { initial: 'draft', states: ['draft', 'active'], transitions: [{ from: 'draft', to: 'active' }] } };
}
async function session(actor = steward, organization = tenant) {
  const token = randomUUID() + randomUUID(), csrf = randomUUID();
  await db.insertInto('sessions').values({ id_hash: createHash('sha256').update(token).digest('hex'), identity_id: actor,
    tenant_id: organization, csrf, expires_at: new Date(Date.now() + 120_000) }).execute();
  return { Cookie: `gc_session=${token}`, 'X-CSRF-Token': csrf, Origin: origin, 'Content-Type': 'application/json' };
}
const request = (path: string, headers: Record<string, string>, method = 'GET', body?: unknown) =>
  fetch(base + '/api/v1' + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
const mutation = (headers: Record<string, string>) => ({ ...headers, 'Idempotency-Key': randomUUID(), 'If-Match': '1' });
const inventory = (kind: 'asset-types' | 'models', q: string, limit = 1, cursor?: string) =>
  `/${kind}?` + new URLSearchParams({ q, limit: String(limit), ...(cursor === undefined ? {} : { cursor }) });
async function page(path: string, headers: Record<string, string>) {
  const response = await request(path, headers); assert.equal(response.status, 200);
  return await response.json() as { items: { id: string; typeId: string | null; currentVersion: number }[]; nextCursor: string | null };
}
async function invalidPage(path: string, headers: Record<string, string>, code = 'ASSET_TYPE_PAGE_INVALID') {
  const response = await request(path, headers); assert.equal(response.status, 400);
  assert.equal((await response.json() as { code: string }).code, code);
}

test('asset-type HTTP version reads and parent integer bounds distinguish missing, malformed and unsupported input', async () => {
  const headers = await session(), current = definition();
  const created = await request('/asset-types', mutation(headers), 'POST', { definition: current }); assert.equal(created.status, 201);
  const versionPath = `/asset-types/${current.id}/versions/`;
  const existing = await request(versionPath + '1', headers); assert.equal(existing.status, 200);
  assert.deepEqual((await existing.json() as any).type.definition, current);
  const missing = await request(versionPath + '2', headers); assert.equal(missing.status, 404);
  assert.equal((await missing.json() as any).code, 'ASSET_TYPE_NOT_FOUND');
  for (const malformed of ['0', 'not-a-version', '2147483648']) {
    assert.equal((await request(versionPath + malformed, headers)).status, 400);
  }
  const unsupportedParent = { id: unique(), version: 2_147_483_648 };
  const invalidCreate = { ...definition(), parents: [unsupportedParent] };
  const createRejected = await request('/asset-types', mutation(headers), 'POST', { definition: invalidCreate });
  assert.equal(createRejected.status, 422); assert.equal((await createRejected.json() as any).code, 'ASSET_TYPE_LIMIT');
  const invalidPreview = { ...current, version: 2, parents: [unsupportedParent] };
  const previewRejected = await request(`/asset-types/${current.id}/previews`, mutation(headers), 'POST', { definition: invalidPreview });
  assert.equal(previewRejected.status, 422); assert.equal((await previewRejected.json() as any).code, 'ASSET_TYPE_LIMIT');
  const unchanged = await request(`/asset-types/${current.id}`, headers); assert.equal(unchanged.status, 200);
  assert.equal((await unchanged.json() as any).type.currentVersion, 1);
});

test('asset-type inventory pages use literal filters, exclude attribute-only models and bind signed cursors to their endpoint and caller', async () => {
  const headers = await session(), prefix = unique();
  const first = definition(prefix + '_a'), second = definition(prefix + '_b'), plainId = prefix + '_0plain';
  for (const input of [first, second]) {
    assert.equal((await request('/asset-types', mutation(headers), 'POST', { definition: input })).status, 201);
  }
  assert.equal((await request('/models', mutation(headers), 'POST', {
    definition: { formatVersion: 1, id: plainId, version: 1, attributes: {} },
  })).status, 201);
  const firstPage = await page(inventory('asset-types', prefix), headers);
  assert.deepEqual(firstPage.items.map(item => item.id), [first.id]);
  assert.match(firstPage.items[0].typeId!, /^[a-f0-9-]{36}$/i); assert.equal(firstPage.items[0].currentVersion, 1);
  assert.equal(typeof firstPage.nextCursor, 'string'); const cursor = firstPage.nextCursor!;
  const secondPage = await page(inventory('asset-types', prefix, 1, cursor), headers);
  assert.deepEqual(secondPage.items.map(item => item.id), [second.id]); assert.equal(secondPage.nextCursor, null);
  assert.match(secondPage.items[0].typeId!, /^[a-f0-9-]{36}$/i);
  // A wildcard implementation would match both suffixes for either filter.
  assert.deepEqual(await page(inventory('asset-types', prefix + '__'), headers), { items: [], nextCursor: null });
  assert.deepEqual(await page(inventory('asset-types', prefix + '%'), headers), { items: [], nextCursor: null });
  const models = await page(inventory('models', prefix), headers);
  assert.deepEqual(models.items.map(item => item.id), [plainId]); assert.equal(models.items[0].typeId, null);
  assert.equal(typeof models.nextCursor, 'string');
  await invalidPage(inventory('asset-types', prefix, 1, models.nextCursor!), headers);
  await invalidPage(inventory('models', prefix, 1, cursor), headers, 'MODEL_PAGE_INVALID');
  const otherActor = await session(consumer), otherOrganization = await session(summit, otherTenant);
  await invalidPage(inventory('asset-types', prefix, 1, cursor), otherActor);
  await invalidPage(inventory('asset-types', prefix, 1, cursor), otherOrganization);
  await invalidPage(inventory('asset-types', prefix + '_a', 1, cursor), headers);
  await invalidPage(inventory('asset-types', prefix, 2, cursor), headers);
  const [encoded, signature] = cursor.split('.');
  const decoded = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  const changedPayload = Buffer.from(JSON.stringify({ ...decoded, after: second.id })).toString('base64url');
  await invalidPage(inventory('asset-types', prefix, 1, changedPayload + '.' + signature), headers);
  assert.deepEqual(await page(inventory('asset-types', prefix), otherOrganization), { items: [], nextCursor: null });
});

after(async () => { await db.destroy(); });
