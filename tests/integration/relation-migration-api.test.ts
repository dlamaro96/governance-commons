// SPDX-License-Identifier: Apache-2.0
/** Real HTTP + SQL009 integration. Authored tests are not execution evidence. */
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { db, lockTenantLedger, scope, sql } from '../../packages/db/src/index.ts';
import { assetView, record } from '../../apps/api/src/repository.ts';
import type { Principal } from '../../packages/authz/src/index.ts';
import type { RelationView } from '../../packages/domain/src/relation-contracts.ts';
import type { GraphChangeSet, ParticipationHistoryPage, ParticipationListPage, RelationMigrationContext,
  RelationMigrationPreview, RelationMigrationReceipt, RelationPreparationView } from '../../packages/domain/src/relation-migration-contracts.ts';
import { authoredDefinition, contextRequest, emptyChange, exactAmount, jointCreation, plan, positiveDefinition,
  repairChange, samePairReplacement, type Endpoint } from '../fixtures/relation-migration-api.ts';

const tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', foreign = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const steward = '10000000-0000-4000-8000-000000000001', analyst = '10000000-0000-4000-8000-000000000003';
const summit = '10000000-0000-4000-8000-000000000005', engineer = '10000000-0000-4000-8000-000000000006';
const principal: Principal = { id: steward, tenantId: tenant, name: 'Synthetic graph steward', permissions: ['models:read', 'models:write', 'catalog:read', 'catalog:write', 'audit:read'] };
const base = process.env.TEST_BASE_URL ?? 'http://api:4310', origin = process.env.PUBLIC_URL ?? 'http://localhost:4310';
type Headers = Record<string, string>;
before(async () => {
  assert.ok(process.env.DATABASE_URL, 'Real disposable runtime DATABASE_URL is required; no graph API checks ran.');
  const result = await sql<{ installed: boolean }>`SELECT to_regclass('public.relation_participations') IS NOT NULL AS installed`.execute(db);
  assert.equal(result.rows[0]?.installed, true, 'SQL009 must be applied to the isolated matching API/database before this suite runs.');
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
const mutation = (headers: Headers, version?: number) => ({ ...headers, 'Idempotency-Key': randomUUID(), ...(version ? { 'If-Match': String(version) } : {}) });
async function response<T = any>(result: Response, status: number): Promise<T> {
  const text = await result.text(); assert.equal(result.status, status, text); return JSON.parse(text);
}
async function failure(result: Response, status: number, codes: readonly string[]) {
  const body = await response(result, status); assert.ok(codes.includes(body.code), JSON.stringify(body)); return body;
}
async function untypedAsset(): Promise<Endpoint> {
  return scope(tenant, steward, async tx => {
    await lockTenantLedger(tx, tenant); const id = randomUUID();
    const row = await tx.insertInto('assets').values({ tenant_id: tenant, id, external_id: id, name: `Synthetic graph endpoint ${id}`,
      qualified_name: `synthetic.graph-api.${id}`, type: 'dataset', observed_at: new Date(), owner_id: steward }).returningAll().executeTakeFirstOrThrow();
    await tx.insertInto('asset_revisions').values({ tenant_id: tenant, asset_id: id, version: row.version, snapshot: JSON.stringify(assetView(row)) }).execute();
    await record(tx, principal, 'asset.created', id, row.version, { syntheticFixture: true }, randomUUID());
    return { id, version: row.version, ownerId: row.owner_id, modelId: null };
  });
}
async function currentAsset(headers: Headers, id: string) { return (await response(await request(`/assets/${id}`, headers), 200)).asset as Endpoint; }
async function context(headers: Headers, change: GraphChangeSet): Promise<RelationMigrationContext> {
  return (await response<{ context: RelationMigrationContext }>(await request('/relation-migrations/context', headers, 'POST', contextRequest(change)), 200)).context;
}
async function preview(headers: Headers, change: GraphChangeSet): Promise<RelationMigrationPreview> {
  return (await response<{ preview: RelationMigrationPreview }>(await request('/relation-migrations/previews', headers, 'POST', { changeSet: change }), 200)).preview;
}
async function execute(headers: Headers, change: GraphChangeSet, reviewed?: RelationMigrationPreview, executionHeaders = mutation(headers)) {
  const checked = reviewed ?? await preview(headers, change); assert.equal(checked.ready, true, JSON.stringify(checked.targetIssues));
  const body = { changeSet: change, previewDigest: checked.previewDigest };
  const receipt = (await response<{ receipt: RelationMigrationReceipt }>(await request('/relation-migrations', executionHeaders, 'POST', body), 201)).receipt;
  return { receipt, body, executionHeaders };
}
async function fixture() {
  const headers = await session(), key = randomUUID().replaceAll('-', '');
  const definition = authoredDefinition(`api_graph_asset_${key}`);
  const { type } = await response(await request('/asset-types', mutation(headers), 'POST', { definition }), 201);
  const assets = [await untypedAsset(), await untypedAsset()];
  const relation = positiveDefinition(`api_graph_${key}`, type.typeId), preparationHeaders = mutation(headers);
  const { preparation } = await response<{ preparation: RelationPreparationView }>(await request('/relation-migrations/preparations', preparationHeaders, 'POST', { definition: relation }), 201);
  return { headers, type, assets, definition: relation, preparation, preparationHeaders, change: jointCreation(preparation, relation, type.id, assets) };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
async function existingContext(f: Fixture, receiptId: string | null = null, headers = f.headers) {
  return context(headers, { ...emptyChange(), repairsReceiptId: receiptId,
    relationTargets: [{ kind: 'repair', expectedHeadVersion: 1, definition: null, plan: plan(f.preparation.relationTypeId) }] });
}
function repairValues(captured: RelationMigrationContext, typeId: string, note: string, receiptId: string | null = null): GraphChangeSet {
  const change = repairChange(captured, typeId, receiptId), first = captured.before.edges.find(row => row.status === 'active')!;
  assert.equal(first.key.kind, 'existing'); if (first.key.kind !== 'existing') throw Error('Expected persisted edge');
  const id = first.key.relationId;
  change.relationTargets[0].plan = { ...change.relationTargets[0].plan, edges: change.relationTargets[0].plan.edges.map(row => row.relationId === id
    ? { ...row, action: 'repair', values: { ...first.values, attributes: { ...first.values.attributes, note } } } : row) };
  return change;
}
async function storedState(typeId: string) {
  return scope(tenant, steward, async tx => ({
    edges: await tx.selectFrom('relations').selectAll().where('relation_type_id', '=', typeId).orderBy('id').execute(),
    bindings: await tx.selectFrom('relation_participations').selectAll().where('relation_type_id', '=', typeId).orderBy('id').execute(),
    versions: await tx.selectFrom('relation_type_versions').selectAll().where('relation_type_id', '=', typeId).orderBy('version').execute(),
  }));
}

test('REST preparation has fixed expiry and exact replay; complete invalid draft repairs into joint assignment and first mandatory assertions', async () => {
  const f = await fixture();
  const replay = await response<{ preparation: RelationPreparationView }>(await request('/relation-migrations/preparations', f.preparationHeaders, 'POST', { definition: f.definition }), 201);
  assert.deepEqual(replay.preparation, f.preparation); assert.notEqual(f.preparation.id, f.preparation.relationTypeId);
  assert.equal(Date.parse(f.preparation.expiresAt) - Date.parse(f.preparation.createdAt), 900000);
  await failure(await request('/relation-migrations/preparations', f.preparationHeaders, 'POST', { definition: { ...f.definition, label: 'Changed intent' } }), 409, ['IDEMPOTENCY_CONFLICT']);
  await failure(await request('/relation-migrations/context', await session(engineer), 'POST', contextRequest(f.change)), 404, ['RELATION_PREPARATION_NOT_FOUND']);
  const captured = await context(f.headers, f.change);
  assert.equal(captured.before.edges.length, 0); assert.equal(captured.before.bindings.length, 0);
  assert.deepEqual(captured.before.endpoints.map(row => row.assetId).sort(), f.assets.map(row => row.id).sort());
  assert.ok(captured.before.endpoints.every(row => row.modelId === null)); assert.ok(captured.proposedEndpoints?.every(row => row.assetVersion === 2));
  const executionHeadersAfterRefusal = mutation(f.headers), beforeRefusal = await storedState(f.preparation.relationTypeId);
  for (const body of [{ changeSet: f.change }, { changeSet: f.change, previewDigest: null }, { changeSet: f.change, previewDigest: 'unreviewed' }])
    await failure(await request('/relation-migrations', executionHeadersAfterRefusal, 'POST', body), 428, ['RELATION_MIGRATION_PREVIEW_REQUIRED']);
  for (const [path, body] of [
    ['/relation-migrations', { changeSet: f.change, previewDigest: '0'.repeat(64), consent: true }],
    ['/relation-migrations/previews', { changeSet: f.change, extra: true }],
    ['/relation-migrations/preparations', { definition: f.definition, extra: true }],
    ['/relation-migrations/validate', { text: JSON.stringify(f.change), extra: true }],
  ] as const) await failure(await request(path, executionHeadersAfterRefusal, 'POST', body), 400, ['RELATION_JSON_INVALID']);
  const missingResourceVersion = structuredClone(f.change) as any;
  delete missingResourceVersion.assetChanges[0].expectedVersion;
  await failure(await request('/relation-migrations/previews', f.headers, 'POST', { changeSet: missingResourceVersion }), 428, ['VERSION_REQUIRED']);
  const malformedResourceVersion = structuredClone(f.change) as any;
  malformedResourceVersion.assetChanges[0].expectedVersion = -1;
  await failure(await request('/relation-migrations/previews', f.headers, 'POST', { changeSet: malformedResourceVersion }), 422, ['RELATION_MIGRATION_INVALID']);
  assert.deepEqual(await storedState(f.preparation.relationTypeId), beforeRefusal);
  assert.deepEqual((await response<{ preparation: RelationPreparationView }>(await request('/relation-migrations/preparations',
    f.preparationHeaders, 'POST', { definition: f.definition }), 201)).preparation, f.preparation);
  const invalid = structuredClone(f.change); invalid.relationTargets[0].plan.creations = invalid.relationTargets[0].plan.creations.slice(0, 1);
  const blocked = await preview(f.headers, invalid);
  assert.equal(blocked.ready, false); assert.equal(blocked.previewDigest, null); assert.ok(blocked.projection);
  assert.ok(blocked.targetIssues.some(issue => issue.path.startsWith('/participation/') && issue.path.endsWith('/minimum')));
  await failure(await request('/relation-migrations', mutation(f.headers), 'POST', { changeSet: invalid, previewDigest: '0'.repeat(64) }), 422, ['RELATION_MIGRATION_INVALID']);
  for (const asset of f.assets) assert.equal((await currentAsset(f.headers, asset.id)).modelId, null);
  // Refused envelopes/consent never consume a successful idempotency binding.
  const { receipt, body, executionHeaders } = await execute(f.headers, f.change, undefined, executionHeadersAfterRefusal);
  assert.equal(receipt.creations.length, 2); assert.equal(receipt.enrollments.length, 4); assert.equal(receipt.assetRevisions.length, 2);
  assert.ok(receipt.assetRevisions.every(row => row.before.version === 1 && row.after.version === 2));
  assert.ok(receipt.after.edges.every(row => row.sourceAssetVersion === 2 && row.targetAssetVersion === 2 && row.values.attributes.amount === exactAmount));
  assert.ok(receipt.before.endpoints.every(row => row.assetVersion === 1));
  const retried = await response<{ receipt: RelationMigrationReceipt }>(await request('/relation-migrations', executionHeaders, 'POST', body), 201);
  assert.deepEqual(retried.receipt, receipt);
  const missingPublicationHead = { ...emptyChange(), relationTargets: [{ kind: 'publish',
    definition: { ...f.definition, version: 2 }, plan: plan(f.preparation.relationTypeId) }] };
  await failure(await request('/relation-migrations/previews', f.headers, 'POST', { changeSet: missingPublicationHead }), 428, ['VERSION_REQUIRED']);
  assert.deepEqual((await response<{ preparation: RelationPreparationView }>(await request('/relation-migrations/preparations', f.preparationHeaders,
    'POST', { definition: f.definition }), 201)).preparation, f.preparation);
  for (const endpoint of f.assets) {
    const list = await response<ParticipationListPage>(await request(`/assets/${endpoint.id}/relation-participation`, f.headers), 200);
    assert.equal(list.items.length, 2); assert.ok(list.items.every(row => row.minimum === 1 && row.maximum === 1 && row.currentDegree === 1));
  }
  const before = await storedState(f.preparation.relationTypeId);
  await failure(await request(`/relations/${receipt.creations[0].relationId}`, mutation(f.headers, 1), 'DELETE'), 422, ['RELATION_PARTICIPATION_REQUIRED', 'RELATION_MIGRATION_REQUIRED']);
  assert.deepEqual(await storedState(f.preparation.relationTypeId), before);
  const extra = await untypedAsset();
  await failure(await request(`/assets/${extra.id}/attributes`, mutation(f.headers, extra.version), 'PUT',
    { modelId: f.type.id, modelVersion: 1, attributes: {} }), 422, ['RELATION_PARTICIPATION_REQUIRED', 'RELATION_MIGRATION_REQUIRED']);
  assert.equal((await currentAsset(f.headers, extra.id)).modelId, null);
});

test('REST same-pair replacement atomically preserves minimum, predecessor history, actual revision references and forward repair link', async () => {
  const f = await fixture(), first = await execute(f.headers, f.change), captured = await existingContext(f, first.receipt.id);
  const change = samePairReplacement(captured, f.preparation.relationTypeId, first.receipt.id), result = await execute(f.headers, change);
  assert.equal(result.receipt.repairsReceiptId, first.receipt.id); assert.equal(result.receipt.replacements.length, 1);
  const mapping = result.receipt.replacements[0]; assert.notEqual(mapping.predecessorId, mapping.successorId);
  const predecessor = (await response(await request(`/relations/${mapping.predecessorId}`, f.headers), 200)).relation as RelationView;
  const successor = (await response(await request(`/relations/${mapping.successorId}`, f.headers), 200)).relation as RelationView;
  assert.equal(predecessor.status, 'tombstoned'); assert.equal(predecessor.version, 2); assert.equal(successor.version, 1);
  assert.equal(successor.source.assetId, predecessor.source.assetId); assert.equal(successor.target.assetId, predecessor.target.assetId);
  assert.equal(successor.attributes.amount, exactAmount);
  const revisions = await response(await request(`/relations/${mapping.predecessorId}/revisions`, f.headers), 200);
  assert.deepEqual(revisions.items.map((row: any) => row.version), [1, 2]);
  assert.equal(revisions.items[0].snapshot.status, 'active');
  assert.deepEqual((await response<{ receipt: RelationMigrationReceipt }>(await request(`/relation-migrations/${first.receipt.id}`, f.headers), 200)).receipt, first.receipt);
  const current = await storedState(f.preparation.relationTypeId);
  assert.equal(current.edges.filter(row => row.status === 'active').length, 2);
  assert.equal(current.bindings.filter(row => row.status === 'active').length, 4);
  for (const outcome of result.receipt.edgeOutcomes) {
    const revision = await scope(tenant, steward, tx => tx.selectFrom('relation_revisions').select('snapshot')
      .where('relation_id', '=', outcome.after.id).where('version', '=', outcome.after.version).executeTakeFirstOrThrow());
    assert.equal(revision.snapshot.id, outcome.after.id); assert.equal(revision.snapshot.version, outcome.after.version);
  }
});

test('REST participation paging and immutable history bind exact policies, current structural degree, opaque fences and all query selectors', async () => {
  const f = await fixture(), first = await execute(f.headers, f.change), assetId = f.assets[0].id;
  const path = `/assets/${assetId}/relation-participation`;
  const page = await response<ParticipationListPage>(await request(`${path}?limit=1`, f.headers), 200);
  assert.ok(page.nextCursor); assert.match(page.snapshotToken, /^[A-Za-z0-9_-]{43}$/);
  const next = await response<ParticipationListPage>(await request(`${path}?limit=1&cursor=${encodeURIComponent(page.nextCursor)}`, f.headers), 200);
  assert.equal(next.items.length, 1); assert.ok(page.items[0].binding.id < next.items[0].binding.id); assert.equal(next.snapshotToken, page.snapshotToken);
  const payload = JSON.parse(Buffer.from(page.nextCursor.split('.')[0], 'base64url').toString());
  assert.deepEqual(Object.keys(payload).sort(), ['binding', 'fence', 'last', 'v']); assert.equal(payload.fence, page.snapshotToken);
  await failure(await request(`${path}?limit=2&cursor=${encodeURIComponent(page.nextCursor)}`, f.headers), 400, ['RELATION_PAGE_INVALID']);
  await failure(await request(`${path}?limit=1&status=all&cursor=${encodeURIComponent(page.nextCursor)}`, f.headers), 400, ['RELATION_PAGE_INVALID']);
  const otherHeaders = await session(engineer);
  await failure(await request(`${path}?limit=1&cursor=${encodeURIComponent(page.nextCursor)}`, otherHeaders), 400, ['RELATION_PAGE_INVALID']);
  for (const query of ['limit=01', 'limit=1&limit=1', 'status=all&status=active', 'unknown=true']) await failure(await request(`${path}?${query}`, f.headers), 400, ['RELATION_PAGE_INVALID']);
  const captured = await existingContext(f), change = repairChange(captured, f.preparation.relationTypeId, first.receipt.id);
  const target = change.relationTargets[0], updated = { ...f.definition, version: 2, label: 'Synthetic revised label' };
  change.relationTargets = [{ kind: 'publish', expectedHeadVersion: 1, definition: updated, plan: { ...target.plan,
    bindings: target.plan.bindings.map(row => ({ ...row, action: 'repin', targetVersion: 2 })),
    edges: target.plan.edges.map((row, index) => { const before = captured.before.edges.find(edge => edge.key.kind === 'existing' && edge.key.relationId === row.relationId)!;
      return { ...row, action: 'repair', values: { ...before.values, validFrom: index ? '2099-01-01T00:00:00.000Z' : '2020-01-01T00:00:00.000Z', validTo: index ? null : '2020-01-02T00:00:00.000Z' } }; }) } }];
  const published = await execute(f.headers, change);
  await failure(await request(`${path}?limit=1&cursor=${encodeURIComponent(page.nextCursor)}`, f.headers), 409, ['RELATION_GRAPH_STALE']);
  const current = await response<ParticipationListPage>(await request(path, f.headers), 200);
  assert.ok(current.items.every(row => row.binding.relationTypeVersion === 2 && row.currentDegree === 1));
  const binding = current.items[0].binding, historyPath = `${path}/${binding.id}/history`;
  await failure(await request(`/assets/${f.assets[1].id}/relation-participation/${binding.id}/history`, f.headers), 404, ['RELATION_NOT_FOUND']);
  const history = await response<ParticipationHistoryPage>(await request(`${historyPath}?limit=1`, f.headers), 200);
  assert.ok(history.nextCursor); assert.equal(history.items[0].binding.version, 2); assert.equal(history.items[0].policy.definition.label, updated.label);
  assert.equal(history.items[0].operationId, published.receipt.id); assert.equal('currentDegree' in history.items[0], false);
  const old = await response<ParticipationHistoryPage>(await request(`${historyPath}?limit=1&cursor=${encodeURIComponent(history.nextCursor)}`, f.headers), 200);
  assert.equal(old.items[0].binding.version, 1); assert.equal(old.items[0].policy.definition.version, 1); assert.equal(old.items[0].assetRevision.version, 2);
  assert.equal(old.items[0].operationId, first.receipt.id);
});

test('REST complete scope and receipt/history replay are reauthorized after an original edge becomes restricted, with cross-tenant direct 404', async () => {
  const f = await fixture(), first = await execute(f.headers, f.change), otherHeaders = await session(engineer), readHeaders = await session(analyst);
  await response(await request(`/relation-migrations/${first.receipt.id}`, readHeaders), 200);
  const captured = await existingContext(f, first.receipt.id, otherHeaders), change = repairValues(captured, f.preparation.relationTypeId, 'Synthetic engineer repair', first.receipt.id);
  const repair = await execute(otherHeaders, change);
  const id = first.receipt.creations[0].relationId;
  const edge = (await response(await request(`/relations/${id}`, f.headers), 200)).relation as RelationView;
  await response(await request(`/relations/${id}`, mutation(f.headers, edge.version), 'PATCH', { attributes: edge.attributes, ownerId: edge.ownerId,
    validFrom: edge.validFrom, validTo: edge.validTo, visibility: 'restricted', allowedIdentityIds: [steward],
    sourceAssetVersion: edge.source.assetVersion, targetAssetVersion: edge.target.assetVersion }), 200);
  const own = await response<ParticipationListPage>(await request(`/assets/${f.assets[0].id}/relation-participation`, f.headers), 200);
  assert.ok(own.items.every(item => item.currentDegree === 1));
  const hidden = await failure(await request(`/assets/${f.assets[0].id}/relation-participation?limit=1`, readHeaders), 403, ['RELATION_SCOPE_UNAVAILABLE']);
  for (const field of ['items', 'count', 'total', 'issues', 'currentDegree', 'snapshotToken']) assert.equal(Object.hasOwn(hidden, field), false);
  // The implicit complete cohort is a scope403. Explicitly linking the now
  // inaccessible original operation instead invokes its direct-resource404.
  const scopeChange = { ...change, repairsReceiptId: null };
  await failure(await request('/relation-migrations/context', otherHeaders, 'POST', contextRequest(scopeChange)), 403, ['RELATION_SCOPE_UNAVAILABLE']);
  await failure(await request('/relation-migrations/previews', otherHeaders, 'POST', { changeSet: scopeChange }), 403, ['RELATION_SCOPE_UNAVAILABLE']);
  await failure(await request('/relation-migrations/context', otherHeaders, 'POST', contextRequest(change)), 404, ['RELATION_MIGRATION_NOT_FOUND']);
  await failure(await request('/relation-migrations/previews', otherHeaders, 'POST', { changeSet: change }), 404, ['RELATION_MIGRATION_NOT_FOUND']);
  await failure(await request(`/relation-migrations/${first.receipt.id}`, readHeaders), 404, ['RELATION_MIGRATION_NOT_FOUND']);
  await failure(await request('/relation-migrations', repair.executionHeaders, 'POST', repair.body), 404, ['RELATION_MIGRATION_NOT_FOUND']);
  await failure(await request(`/assets/${f.assets[0].id}/relation-participation/${own.items[0].binding.id}/history?limit=1`, readHeaders), 403, ['RELATION_SCOPE_UNAVAILABLE']);
  const foreignHeaders = await session(summit, foreign);
  await failure(await request(`/assets/${f.assets[0].id}/relation-participation`, foreignHeaders), 404, ['RELATION_NOT_FOUND']);
  await failure(await request(`/relation-migrations/${first.receipt.id}`, foreignHeaders), 404, ['RELATION_MIGRATION_NOT_FOUND']);
});

test('REST stale preview and concurrent identical expected revisions refuse partial writes and preserve exact successful replay', async () => {
  const f = await fixture(), first = await execute(f.headers, f.change), captured = await existingContext(f);
  const change = repairValues(captured, f.preparation.relationTypeId, 'Synthetic reviewed repair', first.receipt.id), checked = await preview(f.headers, change);
  assert.equal(checked.ready, true);
  const asset = await currentAsset(f.headers, f.assets[0].id);
  await response(await request(`/assets/${asset.id}`, mutation(f.headers, asset.version), 'PATCH', { description: 'Synthetic late metadata change' }), 200);
  const before = await storedState(f.preparation.relationTypeId);
  await failure(await request('/relation-migrations', mutation(f.headers), 'POST', { changeSet: change, previewDigest: checked.previewDigest }), 409, ['RELATION_PREVIEW_STALE']);
  assert.deepEqual(await storedState(f.preparation.relationTypeId), before);
  const fresh = await preview(f.headers, change); assert.equal(fresh.ready, true); assert.notEqual(fresh.previewDigest, checked.previewDigest);
  const body = { changeSet: change, previewDigest: fresh.previewDigest }, headers = [mutation(f.headers), mutation(f.headers)];
  const attempts = await Promise.all(headers.map(header => request('/relation-migrations', header, 'POST', body)));
  const winner = attempts.findIndex(result => result.status === 201); assert.notEqual(winner, -1);
  const loser = 1 - winner, refused = [409, 503].includes(attempts[loser].status);
  const unexpected = refused ? null : await attempts[loser].clone().json().catch(() => null);
  assert.ok(refused, JSON.stringify({ status: attempts[loser].status,
    code: typeof unexpected?.code === 'string' && /^[A-Z_]{1,80}$/.test(unexpected.code) ? unexpected.code : 'UNEXPECTED_RESPONSE' }));
  const receipt = (await response<{ receipt: RelationMigrationReceipt }>(attempts[winner], 201)).receipt;
  await failure(attempts[loser], attempts[loser].status, ['VERSION_CONFLICT', 'RELATION_PREVIEW_STALE', 'RELATION_RETRY']);
  await failure(await request('/relation-migrations', headers[loser], 'POST', body), 409, ['VERSION_CONFLICT', 'RELATION_PREVIEW_STALE']);
  assert.deepEqual((await response<{ receipt: RelationMigrationReceipt }>(await request('/relation-migrations', headers[winner], 'POST', body), 201)).receipt, receipt);
  const current = await storedState(f.preparation.relationTypeId);
  assert.equal(current.edges.filter(row => row.version === 2).length, 1); assert.equal(current.edges.filter(row => row.version === 1).length, 1);
  assert.equal(current.bindings.length, 4); assert.ok(current.bindings.every(row => row.version === 1));
});
