// SPDX-License-Identifier: Apache-2.0
/** Real HTTP, authenticated sessions and SQL011. These authored cases are not
 * qualification until executed against the matching runtime API/database. */
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { db, lockTenantLedger, scope, sql } from '../../packages/db/src/index.ts';
import { assetView, record } from '../../apps/api/src/repository.ts';
import type { Principal } from '../../packages/authz/src/index.ts';
import type { DomainTypeDefinition, DomainTypeView, DomainView, DomainRevision, DomainHierarchyChange, DomainHierarchyPreview,
  DomainPlacementView, DomainPlacementRevision, DomainTypeMigrationContext, DomainTypeMigrationPlan, DomainTypeMigrationReceipt, DomainTypePreview, Page } from '../../packages/domain/src/business-domain-contracts.ts';

const tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', foreign = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const steward = '10000000-0000-4000-8000-000000000001', analyst = '10000000-0000-4000-8000-000000000003';
const summit = '10000000-0000-4000-8000-000000000005', engineer = '10000000-0000-4000-8000-000000000006';
const principal: Principal = { id: steward, tenantId: tenant, name: 'Synthetic domain API steward', permissions: ['catalog:read', 'catalog:write', 'models:read', 'models:write', 'domains:read', 'domains:write', 'domains:assign', 'audit:read'] };
const base = process.env.TEST_BASE_URL ?? 'http://api:4310', origin = process.env.PUBLIC_URL ?? 'http://localhost:4310';
const reason = 'Independent synthetic domain HTTP qualification';
type Headers = Record<string, string>;
before(async () => {
  assert.ok(process.env.DATABASE_URL, 'A real runtime DATABASE_URL is required; no domain API cases ran.');
  const result = await sql<{ installed: boolean }>`SELECT to_regclass('public.asset_domain_placement_revisions') IS NOT NULL AS installed`.execute(db);
  assert.equal(result.rows[0]?.installed, true, 'SQL011 must be installed in the matching API/database.');
});
after(async () => { await db.destroy(); });
async function session(actor = steward, organization = tenant): Promise<Headers> {
  const token = randomUUID() + randomUUID(), csrf = randomUUID();
  await db.insertInto('sessions').values({ id_hash: createHash('sha256').update(token).digest('hex'), identity_id: actor,
    tenant_id: organization, csrf, expires_at: new Date(Date.now() + 600_000) }).execute();
  return { Cookie: `gc_session=${token}`, 'X-CSRF-Token': csrf, Origin: origin, 'Content-Type': 'application/json' };
}
function request(path: string, headers: Headers, method = 'GET', body?: unknown) {
  return fetch(`${base}/api/v1${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(45_000) });
}
const mutation = (headers: Headers, version?: number) => ({ ...headers, 'Idempotency-Key': randomUUID(), ...(version === undefined ? {} : { 'If-Match': String(version) }) });
async function response<T = any>(result: Response, status = 200): Promise<T> {
  const text = await result.text(); assert.equal(result.status, status, text); return JSON.parse(text);
}
async function failure(result: Response, status: number, code: string) {
  assert.match(result.headers.get('content-type') ?? '', /^application\/problem\+json/);
  const value = await response(result, status); assert.equal(value.code, code); assert.equal(value.status, status);
  assert.deepEqual(Object.keys(value).sort(), ['code', 'correlationId', 'detail', 'status', 'title', 'type', ...(value.issues ? ['issues'] : [])].sort());
  assert.equal(value.type, 'about:blank'); assert.equal(typeof value.correlationId, 'string');
  assert.doesNotMatch(JSON.stringify(value), /(?:SELECT |INSERT INTO |UPDATE |constraint|stackTrace|postgres|gc_domain_)/i);
  return value;
}
function definition(): DomainTypeDefinition {
  return { formatVersion: 1, kind: 'domain-type', id: 'domain_api_' + randomUUID().replaceAll('-', ''), version: 1,
    label: 'Independent synthetic domain policy', parents: [], attributes: { amount: { type: 'number', integer: true, required: true },
      precise: { type: 'decimal', precision: 35, scale: 5, required: true } }, overrideAttributes: [], requiredOwner: true,
    lifecycle: { initial: 'draft', states: ['draft', 'active'], transitions: [{ from: 'draft', to: 'active' }, { from: 'active', to: 'draft' }] } };
}
const values = { amount: 7, precise: '900719925474099312345.12345' };
async function createType(headers: Headers, value = definition()): Promise<DomainTypeView> {
  return (await response<{ type: DomainTypeView }>(await request('/domain-types', mutation(headers), 'POST', { definition: value, reason }), 201)).type;
}
async function createDomain(headers: Headers, type: DomainTypeView, name = 'Independent synthetic domain', parentId: string | null = null): Promise<DomainView> {
  return (await response<{ domain: DomainView }>(await request('/domains', mutation(headers), 'POST', { name, description: 'Synthetic public test fixture', parentId,
    type: { typeId: type.typeId, version: type.version }, attributes: values, ownerId: steward, reason }), 201)).domain;
}
async function getDomain(headers: Headers, id: string): Promise<DomainView> { return (await response<{ domain: DomainView }>(await request(`/domains/${id}`, headers))).domain; }
const edit = (row: DomainView, name = row.name) => ({ name, description: row.description, attributes: row.attributes, ownerId: row.ownerId, reason });
async function update(headers: Headers, row: DomainView, name: string): Promise<DomainView> {
  return (await response<{ domain: DomainView }>(await request(`/domains/${row.id}`, mutation(headers, row.version), 'PATCH', edit(row, name)))).domain;
}
async function hierarchyPreview(headers: Headers, row: DomainView, kind: DomainHierarchyChange['kind'], parentId = row.parentId) {
  const change: DomainHierarchyChange = { kind, domainId: row.id, expectedVersion: row.version, parentId, reason };
  const { preview } = await response<{ preview: DomainHierarchyPreview }>(await request(`/domains/${row.id}/hierarchy-previews`, { ...headers, 'If-Match': String(row.version) }, 'POST', { change }));
  return { change, preview };
}
async function hierarchy(headers: Headers, row: DomainView, kind: DomainHierarchyChange['kind'], parentId = row.parentId): Promise<DomainView> {
  const { change, preview } = await hierarchyPreview(headers, row, kind, parentId); assert.equal(preview.ready, true, JSON.stringify(preview.issues)); assert.ok(preview.previewDigest);
  return (await response<{ domain: DomainView }>(await request(`/domains/${row.id}/hierarchy-changes`, mutation(headers, row.version), 'POST', { change, previewDigest: preview.previewDigest }))).domain;
}
async function assetFixture() {
  return scope(tenant, steward, async tx => {
    await lockTenantLedger(tx, tenant); const id = randomUUID();
    const row = await tx.insertInto('assets').values({ tenant_id: tenant, id, external_id: id, name: 'Independent domain placement asset',
      qualified_name: `synthetic.domain-api.${id}`, type: 'dataset', observed_at: new Date() }).returningAll().executeTakeFirstOrThrow();
    await tx.insertInto('asset_revisions').values({ tenant_id: tenant, asset_id: id, version: row.version, snapshot: JSON.stringify(assetView(row)) }).execute();
    await record(tx, principal, 'asset.created', id, row.version, { syntheticFixture: true }, randomUUID());
    return { id: row.id as string, version: row.version as number };
  });
}
async function place(headers: Headers, asset: { id: string; version: number }, domain: DomainView | null, version: number, key = mutation(headers, version)) {
  const body = { assetVersion: asset.version, domainId: domain?.id ?? null, domainVersion: domain?.version ?? null, reason };
  const result = await response<{ placement: DomainPlacementView; domain: DomainView | null }>(await request(`/assets/${asset.id}/domain-placement`, key, 'PUT', body));
  return { ...result, body, key };
}
const page = <T>(path: string, headers: Headers) => request(path, headers).then(r => response<Page<T>>(r));

// The scanned source/browser journey exercises ingestion separately; this case
// compares real canonical asset rows and immutable legacy snapshots byte-for-byte.
test('domain HTTP type creation, placement, rename, move and history preserve asset identity and legacy snapshots', async () => {
  const headers = await session(), type = await createType(headers), parent = await createDomain(headers, type, 'Synthetic parent');
  const child = await createDomain(headers, type, '😀'.repeat(200)), asset = await assetFixture();
  const original = await response(await request(`/assets/${asset.id}`, headers));
  const saved = await scope(tenant, steward, tx => tx.selectFrom('asset_revisions').selectAll().where('asset_id', '=', asset.id).orderBy('version').execute());
  const absent = await response<{ placement: DomainPlacementView; domain: DomainView | null }>(await request(`/assets/${asset.id}/domain-placement`, headers));
  assert.deepEqual(absent, { placement: { assetId: asset.id, version: 0, domainId: null, recordedAssetVersion: null, recordedDomainVersion: null, recordedAt: null, recordedBy: null }, domain: null });
  assert.deepEqual(await page(`/assets/${asset.id}/domain-placement/history`, headers), { items: [], nextCursor: null });
  const assigned = await place(headers, asset, child, 0); assert.equal(assigned.placement.version, 1); assert.equal(assigned.placement.recordedDomainVersion, 1);
  const renamed = await update(headers, child, 'Renamed independent synthetic domain'), moved = await hierarchy(headers, renamed, 'move', parent.id);
  assert.equal(moved.parentId, parent.id); assert.equal(moved.version, 3); assert.equal(moved.attributes.precise, values.precise);
  const current = await response<{ placement: DomainPlacementView; domain: DomainView }>(await request(`/assets/${asset.id}/domain-placement`, headers));
  assert.deepEqual(current.placement, assigned.placement); assert.equal(current.domain.name, moved.name); assert.equal(current.domain.version, 3);
  const assets = await page<{ assetId: string; assetVersion: number; placementVersion: number }>(`/domains/${child.id}/assets`, headers);
  assert.equal(assets.items.length, 1); assert.equal(assets.items[0].assetId, asset.id); assert.equal(assets.items[0].assetVersion, asset.version); assert.equal(assets.items[0].placementVersion, 1);
  const history = await page<DomainRevision>(`/domains/${child.id}/history`, headers);
  assert.deepEqual(history.items.map(row => row.domain.version), [3, 2, 1]); assert.deepEqual(history.items.map(row => row.action), ['moved', 'updated', 'created']);
  assert.deepEqual(history.items[2].domain, child); assert.equal(history.items[0].domain.parentId, parent.id);
  assert.deepEqual(await response(await request(`/assets/${asset.id}`, headers)), original);
  assert.deepEqual(await scope(tenant, steward, tx => tx.selectFrom('asset_revisions').selectAll().where('asset_id', '=', asset.id).orderBy('version').execute()), saved);
  assert.equal(Object.hasOwn(original.asset, 'domainId'), false); assert.equal(Object.hasOwn(original.asset, 'placementVersion'), false);
  const replay = await response(await request(`/assets/${asset.id}/domain-placement`, assigned.key, 'PUT', assigned.body)); assert.deepEqual(replay, { placement: assigned.placement, domain: assigned.domain });
});

test('domain HTTP lifecycle, nonempty retirement, unassignment and restoration retain independent revision streams', async () => {
  const headers = await session(), type = await createType(headers), initial = await createDomain(headers, type), asset = await assetFixture();
  let domain = (await response<{ domain: DomainView }>(await request(`/domains/${initial.id}/state`, mutation(headers, 1), 'POST', { state: 'active', reason }))).domain;
  assert.equal(domain.state, 'active'); assert.equal(domain.status, 'active'); assert.equal(domain.version, 2);
  await failure(await request(`/domains/${domain.id}/state`, mutation(headers, domain.version), 'POST', { state: 'missing_state', reason }), 422, 'DOMAIN_INVALID');
  const assigned = await place(headers, asset, domain, 0), blocked = await hierarchyPreview(headers, domain, 'retire');
  assert.equal(blocked.preview.ready, false); assert.equal(blocked.preview.previewDigest, null); assert.ok(blocked.preview.issues.length);
  await failure(await request(`/domains/${domain.id}/hierarchy-changes`, mutation(headers, domain.version), 'POST', { change: blocked.change, previewDigest: '0'.repeat(64) }), 422, 'DOMAIN_IN_USE');
  await failure(await request(`/assets/${asset.id}/domain-placement`, mutation(headers, 1), 'PUT', assigned.body), 422, 'DOMAIN_NO_CHANGE');
  const unassigned = await place(headers, asset, null, 1); assert.equal(unassigned.placement.version, 2); assert.equal(unassigned.domain, null); assert.equal(unassigned.placement.recordedAssetVersion, asset.version);
  domain = await hierarchy(headers, domain, 'retire'); assert.equal(domain.status, 'retired'); assert.equal(domain.state, 'active');
  await failure(await request(`/domains/${domain.id}`, mutation(headers, domain.version), 'PATCH', edit(domain, 'Rejected retired edit')), 422, 'DOMAIN_RETIRED');
  const retired = domain; domain = await hierarchy(headers, domain, 'restore'); assert.equal(domain.status, 'active'); assert.equal(domain.state, 'active');
  const revisions = await page<DomainRevision>(`/domains/${domain.id}/history`, headers);
  assert.deepEqual(revisions.items.map(row => row.action), ['restored', 'retired', 'state-changed', 'created']); assert.deepEqual(revisions.items[1].domain, retired);
  const placements = await page<DomainPlacementRevision>(`/assets/${asset.id}/domain-placement/history`, headers);
  assert.deepEqual(placements.items.map(row => row.placement.version), [2, 1]); assert.deepEqual(placements.items[1].placement, assigned.placement);
  const replay = await response(await request(`/assets/${asset.id}/domain-placement`, assigned.key, 'PUT', assigned.body)); assert.equal(replay.placement.version, 1);
  assert.equal((await response(await request(`/assets/${asset.id}/domain-placement`, headers))).placement.version, 2);
});

test('domain HTTP compatible publication preserves exact pins and explicit migration covers mixed versions including retired domains', async () => {
  const headers = await session(), v1 = await createType(headers), old = await createDomain(headers, v1), retired = await hierarchy(headers, await createDomain(headers, v1), 'retire');
  const v2def: DomainTypeDefinition = { ...v1.definition, version: 2, attributes: { ...v1.definition.attributes, note: { type: 'text' } } };
  const preview = (await response<{ preview: DomainTypePreview }>(await request(`/domain-types/${v1.typeId}/previews`, { ...headers, 'If-Match': '1' }, 'POST', { definition: v2def, reason }))).preview;
  assert.equal(preview.mode, 'preserve-pins'); assert.equal(preview.pinsPreserved, true); assert.equal(preview.ready, true); assert.equal(preview.requiresMigration, false); assert.equal(preview.domains.length, 2);
  const v2 = (await response<{ type: DomainTypeView }>(await request(`/domain-types/${v1.typeId}/versions`, mutation(headers, 1), 'POST', { definition: v2def, reason, previewDigest: preview.previewDigest }), 201)).type;
  assert.equal(v2.version, 2); assert.deepEqual(await getDomain(headers, old.id), old); assert.deepEqual(await getDomain(headers, retired.id), retired);
  const latest = await createDomain(headers, v2), context = await response<DomainTypeMigrationContext>(await request(`/domain-types/${v1.typeId}/migration-context`, headers));
  assert.equal(context.coverage, 'complete-direct-domain-type-bindings'); assert.deepEqual(context.sources.map(row => row.version), [1, 2]); assert.equal(context.domains.length, 3);
  const target: DomainTypeDefinition = { ...v2def, version: 3, attributes: { ...v2def.attributes, migrated: { type: 'boolean', required: true } } };
  const plan: DomainTypeMigrationPlan = { formatVersion: 1, kind: 'domain-type-migration', typeId: v1.typeId,
    attributes: { formatVersion: 1, modelId: v1.key, targetVersion: 3, sourceVersions: [1, 2], acknowledgedChanges: [], operations: [{ op: 'set', path: ['migrated'], value: true, mode: 'ifMissing' }] },
    owner: { default: 'preserve', overrides: [] }, lifecycle: { onUnmapped: 'preserve', mappings: [] }, acknowledgedPolicyChanges: [] };
  assert.deepEqual((await response(await request('/domain-types/migration-plans/validate', headers, 'POST', { text: JSON.stringify(plan) }))).plan, plan);
  const input = { definition: target, plan, reason }, checked = (await response<{ preview: DomainTypePreview }>(await request(`/domain-types/${v1.typeId}/migration-previews`, { ...headers, 'If-Match': '2' }, 'POST', input))).preview;
  assert.equal(checked.mode, 'migrate'); assert.equal(checked.ready, true); assert.equal(checked.domains.length, 3); assert.equal(checked.pinsPreserved, false);
  const key = mutation(headers, 2), body = { ...input, previewDigest: checked.previewDigest };
  const executed = await response<{ type: DomainTypeView; receipt: DomainTypeMigrationReceipt }>(await request(`/domain-types/${v1.typeId}/migrations`, key, 'POST', body), 201);
  assert.equal(executed.type.version, 3); assert.equal(executed.receipt.outcomes.length, 3); assert.deepEqual(executed.receipt.sourcePolicies.map(row => row.pin.version), [1, 2]);
  assert.deepEqual((await response(await request(`/domain-types/${v1.typeId}/migrations/${executed.receipt.id}`, headers))).receipt, executed.receipt);
  for (const before of [old, retired, latest]) {
    const current = await getDomain(headers, before.id); assert.equal(current.type.version, 3); assert.equal(current.version, before.version + 1);
    assert.equal(current.attributes.migrated, true); assert.equal(current.attributes.precise, values.precise); assert.equal(current.status, before.status);
    const history = await page<DomainRevision>(`/domains/${before.id}/history`, headers); assert.deepEqual(history.items[1].domain, before); assert.equal(history.items[0].action, 'type-migrated');
  }
  assert.deepEqual(await response(await request(`/domain-types/${v1.typeId}/migrations`, key, 'POST', body), 201), executed);
  assert.deepEqual((await response(await request(`/domain-types/${v1.typeId}/versions/1`, headers))).type.definition, v1.definition);
});

test('domain HTTP rejects stale versions and consent, hierarchy cycles, reused intent and mismatched placement versions atomically', async () => {
  const headers = await session(), type = await createType(headers), root = await createDomain(headers, type), child = await createDomain(headers, type, 'Synthetic child', root.id);
  const cycle = await hierarchyPreview(headers, root, 'move', child.id); assert.equal(cycle.preview.ready, false); assert.ok(cycle.preview.issues.some(row => row.code === 'cycle'));
  await failure(await request(`/domains/${root.id}/hierarchy-changes`, mutation(headers, 1), 'POST', { change: cycle.change, previewDigest: '0'.repeat(64) }), 422, 'DOMAIN_HIERARCHY_CYCLE');
  const destination = await createDomain(headers, type), prepared = await hierarchyPreview(headers, child, 'move', destination.id);
  await update(headers, destination, 'Changed destination after preview');
  const execution = mutation(headers, child.version), intent = { change: prepared.change, previewDigest: prepared.preview.previewDigest };
  await failure(await request(`/domains/${child.id}/hierarchy-changes`, execution, 'POST', intent), 409, 'DOMAIN_PREVIEW_STALE');
  assert.deepEqual(await getDomain(headers, child.id), child);
  const fresh = await hierarchyPreview(headers, child, 'move', destination.id), moved = (await response<{ domain: DomainView }>(await request(`/domains/${child.id}/hierarchy-changes`, execution, 'POST', { change: fresh.change, previewDigest: fresh.preview.previewDigest }))).domain;
  await failure(await request(`/domains/${child.id}/hierarchy-changes`, execution, 'POST', intent), 409, 'IDEMPOTENCY_CONFLICT');
  await failure(await request(`/domains/${child.id}`, mutation(headers, 1), 'PATCH', edit(moved, 'Stale update')), 409, 'VERSION_CONFLICT');
  const asset = await assetFixture();
  await failure(await request(`/assets/${asset.id}/domain-placement`, mutation(headers, 0), 'PUT', { assetVersion: asset.version + 1, domainId: moved.id, domainVersion: moved.version, reason }), 409, 'VERSION_CONFLICT');
  await failure(await request(`/assets/${asset.id}/domain-placement`, mutation(headers, 0), 'PUT', { assetVersion: asset.version, domainId: moved.id, domainVersion: moved.version - 1, reason }), 409, 'VERSION_CONFLICT');
  await failure(await request(`/assets/${asset.id}/domain-placement`, mutation(headers, 0), 'PUT', { assetVersion: asset.version, domainId: null, domainVersion: moved.version, reason }), 422, 'DOMAIN_INVALID');
  assert.equal((await response(await request(`/assets/${asset.id}/domain-placement`, headers))).placement.version, 0);
  assert.equal((await page(`/assets/${asset.id}/domain-placement/history`, headers)).items.length, 0);
});

test('domain HTTP signed pages bind purpose actor tenant filters size and current scope without exposing counts', async () => {
  const headers = await session(), type = await createType(headers), needle = 'literal_%_' + randomUUID();
  const created = [await createDomain(headers, type, needle), await createDomain(headers, type, needle)];
  const path = `/domains?limit=1&q=${encodeURIComponent(needle)}&status=all`, first = await page<DomainView>(path, headers);
  assert.equal(first.items.length, 1); assert.ok(first.nextCursor); assert.deepEqual(Object.keys(first).sort(), ['items', 'nextCursor']);
  const cursor = encodeURIComponent(first.nextCursor!), second = await page<DomainView>(path + '&cursor=' + cursor, headers);
  assert.equal(second.nextCursor, null); assert.deepEqual([...first.items, ...second.items].map(row => row.id), created.map(row => row.id).sort());
  for (const invalid of [`/domains?limit=2&q=${encodeURIComponent(needle)}&status=all&cursor=${cursor}`, `/domains?limit=1&q=different&status=all&cursor=${cursor}`,
    `/domain-types?limit=1&cursor=${cursor}`, `/domains/${created[0].id}/history?limit=1&cursor=${cursor}`, `/domains/owner-candidates?limit=1&cursor=${cursor}`])
    await failure(await request(invalid, headers), 400, 'DOMAIN_PAGE_INVALID');
  await failure(await request(path + '&cursor=' + cursor, await session(engineer)), 400, 'DOMAIN_PAGE_INVALID');
  await failure(await request(path + '&cursor=' + cursor, await session(summit, foreign)), 400, 'DOMAIN_PAGE_INVALID');
  const payload = JSON.parse(Buffer.from(first.nextCursor!.split('.')[0], 'base64url').toString()); assert.match(payload.fence, /^[A-Za-z0-9_-]{43}$/); assert.equal(Object.hasOwn(payload, 'epoch'), false); assert.match(payload.filter, /^[a-f0-9]{64}$/);
  await update(headers, created[0], needle + ' changed'); await failure(await request(path + '&cursor=' + cursor, headers), 409, 'DOMAIN_PAGE_STALE');
  const owners = await page<{ id: string; name: string }>('/domains/owner-candidates?limit=1', headers); assert.equal(owners.items.length, 1); assert.deepEqual(Object.keys(owners.items[0]).sort(), ['id', 'name']);
  const foreignRows = await page<DomainView>(`/domains?q=${encodeURIComponent(needle)}`, await session(summit, foreign)); assert.deepEqual(foreignRows, { items: [], nextCursor: null });
  // Full Unicode search length must remain pageable within the independent
  // 1024-character signed cursor bound; normalized filters are digest-bound.
  const maximumSearch = '😀'.repeat(168) + randomUUID().replaceAll('-', ''); assert.equal([...maximumSearch].length, 200);
  const unicodeRows = [await createDomain(headers, type, maximumSearch), await createDomain(headers, type, maximumSearch)];
  const unicodePath = `/domains?limit=1&q=${encodeURIComponent(maximumSearch)}`, unicodeFirst = await page<DomainView>(unicodePath, headers);
  assert.ok(unicodeFirst.nextCursor); assert.ok(unicodeFirst.nextCursor!.length <= 1024);
  const unicodeSecond = await page<DomainView>(unicodePath + '&cursor=' + encodeURIComponent(unicodeFirst.nextCursor!), headers);
  assert.equal(unicodeSecond.nextCursor, null);
  assert.deepEqual([...unicodeFirst.items, ...unicodeSecond.items].map(row => row.id), unicodeRows.map(row => row.id).sort());
});

test('domain HTTP raw envelopes queries and headers reject duplicates prototype keys unknown fields and coercion before mutation', async () => {
  const headers = await session(), type = await createType(headers), row = await createDomain(headers, type), valid = edit(row, 'Uncommitted malformed change');
  for (const query of ['limit=01', 'limit=1.0', 'limit=1e0', 'limit=0', 'limit=101', 'limit=1&limit=2', 'status[]=active', 'status=unknown', 'q=%FF', 'offset=1', 'q=a&q=b', 'parentId=ROOT', 'cursor='])
    await failure(await request('/domains?' + query, headers), 400, 'DOMAIN_PAGE_INVALID');
  const encoded = JSON.stringify(valid), cases = [encoded.replace('"name":', '"name":"Duplicate raw name","name":'),
    encoded.replace('"name":', '"na\\u006de":"Duplicate escaped name","name":'), encoded.replace('{', '{"__proto__":{},'),
    encoded.replace('{', '{"constructor":{},'), encoded.replace('{', '{"extra":true,'), encoded.replace('"amount":7', '"amount":"7"'),
    encoded.replace('"amount":7', '"amount":-0'), encoded.replace('"amount":7', '"amount":1e999'), encoded.replace('"Uncommitted malformed change"', '"\\ud800"')];
  for (const raw of cases) {
    const result = await fetch(`${base}/api/v1/domains/${row.id}`, { method: 'PATCH', headers: mutation(headers, row.version), body: raw, signal: AbortSignal.timeout(45_000) });
    // A string attribute is valid JSON data, but the pinned number policy rejects
    // it semantically; it must never be coerced into a successful numeric write.
    await failure(result, raw.includes('"amount":"7"') ? 422 : 400, raw.includes('"amount":"7"') ? 'DOMAIN_INVALID' : 'DOMAIN_JSON_INVALID');
  }
  await failure(await request(`/domains/${row.id}`, headers, 'PATCH', valid), 428, 'VERSION_REQUIRED');
  await failure(await request(`/domains/${row.id}`, { ...headers, 'If-Match': '1' }, 'PATCH', valid), 400, 'IDEMPOTENCY_REQUIRED');
  for (const version of ['01', '1.0', '1e0', '*', '0', '2147483648', '"1", "2"'])
    await failure(await request(`/domains/${row.id}`, { ...mutation(headers), 'If-Match': version }, 'PATCH', valid), 428, 'VERSION_REQUIRED');
  const change = { kind: 'move', domainId: randomUUID(), expectedVersion: row.version, parentId: null, reason };
  await failure(await request(`/domains/${row.id}/hierarchy-previews`, { ...headers, 'If-Match': '1' }, 'POST', { change }), 400, 'DOMAIN_JSON_INVALID');
  await failure(await request(`/domain-types/${type.typeId}/migration-context?limit=1`, headers), 400, 'DOMAIN_PAGE_INVALID');
  await failure(await request('/domain-types/validate', headers, 'POST', { text: JSON.stringify({ ...type.definition, requiredOwner: 'true' }) }), 422, 'DOMAIN_TYPE_INVALID');
  assert.deepEqual(await getDomain(headers, row.id), row); assert.equal((await page(`/domains/${row.id}/history`, headers)).items.length, 1);
});

test('domain HTTP authorization scopes direct resources owners impacted assets historical placement and successful replay', async () => {
  const headers = await session(), type = await createType(headers), row = await createDomain(headers, type), asset = await assetFixture();
  const assigned = await place(headers, asset, row, 0), other = await session(summit, foreign), limited = await session(analyst);
  await failure(await request('/domains', {}), 401, 'SESSION_REQUIRED');
  await failure(await request('/domains', limited), 403, 'FORBIDDEN');
  await failure(await request(`/assets/${asset.id}/domain-placement`, limited), 403, 'FORBIDDEN');
  await failure(await request('/domains/owner-candidates', limited), 403, 'FORBIDDEN');
  for (const [path, code] of [[`/domains/${row.id}`, 'DOMAIN_NOT_FOUND'], [`/domain-types/${type.typeId}`, 'DOMAIN_TYPE_NOT_FOUND'], [`/assets/${asset.id}/domain-placement`, 'ASSET_NOT_FOUND']] as const)
    await failure(await request(path, other), 404, code);
  await failure(await request('/domains', { ...mutation(headers), Origin: 'https://untrusted.invalid' }, 'POST', { name: 'CSRF refusal' }), 403, 'CSRF_REJECTED');
  const foreignOwner = { ...edit(row, 'Foreign owner rejected'), ownerId: summit };
  await failure(await request(`/domains/${row.id}`, mutation(headers, row.version), 'PATCH', foreignOwner), 422, 'DOMAIN_INVALID');
  // Current asset visibility is changed through the same runtime-role fixture
  // path used by existing security tests; no membership/write privilege is added.
  await scope(tenant, steward, async tx => { await lockTenantLedger(tx, tenant); await tx.updateTable('assets').set({ visibility: 'restricted', allowed_identities: JSON.stringify([engineer]) }).where('id', '=', asset.id).execute(); });
  try {
    for (const path of [`/assets/${asset.id}/domain-placement`, `/assets/${asset.id}/domain-placement/history`]) await failure(await request(path, headers), 404, 'ASSET_NOT_FOUND');
    await failure(await request(`/assets/${asset.id}/domain-placement`, assigned.key, 'PUT', assigned.body), 403, 'DOMAIN_SCOPE_UNAVAILABLE');
    const hidden = await page(`/domains/${row.id}/assets`, headers); assert.deepEqual(hidden, { items: [], nextCursor: null });
    const impacted = await request(`/domains/${row.id}/hierarchy-previews`, { ...headers, 'If-Match': String(row.version) }, 'POST', { change: { kind: 'retire', domainId: row.id, expectedVersion: row.version, parentId: null, reason } });
    const denial = await failure(impacted, 403, 'DOMAIN_SCOPE_UNAVAILABLE'); assert.equal('issues' in denial, false); assert.equal(JSON.stringify(denial).includes(asset.id), false);
  } finally {
    await scope(tenant, steward, async tx => { await lockTenantLedger(tx, tenant); await tx.updateTable('assets').set({ visibility: 'tenant', allowed_identities: JSON.stringify([]) }).where('id', '=', asset.id).execute(); });
  }
  assert.equal((await response(await request(`/assets/${asset.id}/domain-placement`, headers))).placement.version, 1);
  const journal = await scope(tenant, steward, tx => tx.selectFrom('audit').selectAll().where('resource_id', '=', row.id).execute());
  assert.equal(journal.filter(event => event.action === 'domain.created').length, 1);
});

test('domain HTTP OpenAPI declares every route exact responses request bodies and required mutation preconditions', async () => {
  const document = await response(await request('/openapi', await session()));
  const routes: readonly [string, string, boolean, boolean, string][] = [
    ['/domain-types', 'get', false, false, '200'], ['/domain-types', 'post', true, false, '201'], ['/domain-types/validate', 'post', false, false, '200'],
    ['/domain-types/migration-plans/validate', 'post', false, false, '200'], ['/domain-types/{typeId}', 'get', false, false, '200'], ['/domain-types/{typeId}/versions/{version}', 'get', false, false, '200'],
    ['/domain-types/{typeId}/previews', 'post', false, true, '200'], ['/domain-types/{typeId}/versions', 'post', true, true, '201'], ['/domain-types/{typeId}/migration-context', 'get', false, false, '200'],
    ['/domain-types/{typeId}/migration-previews', 'post', false, true, '200'], ['/domain-types/{typeId}/migrations', 'post', true, true, '201'], ['/domain-types/{typeId}/migrations/{id}', 'get', false, false, '200'],
    ['/domains', 'get', false, false, '200'], ['/domains', 'post', true, false, '201'], ['/domains/owner-candidates', 'get', false, false, '200'], ['/domains/{id}', 'get', false, false, '200'], ['/domains/{id}', 'patch', true, true, '200'],
    ['/domains/{id}/state', 'post', true, true, '200'], ['/domains/{id}/hierarchy-previews', 'post', false, true, '200'], ['/domains/{id}/hierarchy-changes', 'post', true, true, '200'], ['/domains/{id}/history', 'get', false, false, '200'], ['/domains/{id}/assets', 'get', false, false, '200'],
    ['/assets/{id}/domain-placement', 'get', false, false, '200'], ['/assets/{id}/domain-placement', 'put', true, true, '200'], ['/assets/{id}/domain-placement/history', 'get', false, false, '200'],
  ];
  for (const [path, method, idempotency, version, status] of routes) {
    const operation = document.paths['/api/v1' + path]?.[method]; assert.ok(operation, `${method} ${path}`);
    const schema = operation.responses[status]?.content?.['application/json']?.schema; assert.ok(schema); assert.equal(schema.additionalProperties, false);
    assert.ok(Array.isArray(schema.required) && schema.required.length); assert.equal(JSON.stringify(schema).includes('"additionalProperties":true'), false);
    if (method !== 'get') { assert.equal(operation.requestBody.required, true); assert.equal(operation.requestBody.content['application/json'].schema.additionalProperties, false); }
    for (const [header, required] of [['idempotency-key', idempotency], ['if-match', version]] as const) if (required)
      assert.ok(operation.parameters.some((parameter: any) => parameter.in === 'header' && parameter.name === header && parameter.required === true), `${method} ${path} ${header}`);
  }
});
