// SPDX-License-Identifier: Apache-2.0
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, createHash } from 'node:crypto';
import { db, scope } from '../../packages/db/src/index.ts';

const tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const otherTenant = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const steward = '10000000-0000-4000-8000-000000000001';
const base = process.env.TEST_BASE_URL ?? 'http://api:4310';
const origin = process.env.PUBLIC_URL ?? 'http://localhost:4310';
async function session(actor = steward, organization = tenant) {
  const raw = randomUUID() + randomUUID(), csrf = randomUUID();
  await db.insertInto('sessions').values({ id_hash: createHash('sha256').update(raw).digest('hex'), identity_id: actor,
    tenant_id: organization, csrf, expires_at: new Date(Date.now() + 120_000) }).execute();
  return { Cookie: `gc_session=${raw}`, 'X-CSRF-Token': csrf, Origin: origin, 'Content-Type': 'application/json' };
}
const request = (path: string, headers: Record<string, string>, method = 'GET', body?: unknown) =>
  fetch(base + '/api/v1' + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
const mutation = (headers: Record<string, string>, version = 1) => ({ ...headers, 'If-Match': String(version), 'Idempotency-Key': randomUUID() });
async function fixture() {
  const headers = await session(), id = 'migration_http_' + randomUUID().replaceAll('-', '');
  const definition = { formatVersion: 1, id, version: 1, attributes: { amount: { type: 'decimal', required: true } } };
  assert.equal((await request('/models', mutation(headers), 'POST', { definition })).status, 201);
  const assetId = randomUUID(), amount = '12345678901234567890.123456789';
  await scope(tenant, steward, tx => tx.insertInto('assets').values({ tenant_id: tenant, id: assetId, external_id: assetId,
    name: 'Synthetic migration API fixture', qualified_name: 'http.migration.' + assetId, type: 'dataset', observed_at: new Date() }).execute());
  assert.equal((await request('/assets/' + assetId + '/attributes', mutation(headers), 'PUT', { modelId: id, modelVersion: 1, attributes: { amount } })).status, 200);
  const target = { ...definition, version: 2, attributes: { budget: { type: 'decimal', required: true } } };
  const plan = { formatVersion: 1, modelId: id, targetVersion: 2, sourceVersions: [1],
    acknowledgedChanges: [{ code: 'attribute_removed', path: '/attributes/amount' }],
    operations: [{ op: 'rename', from: ['amount'], to: ['budget'], onMissing: 'error' }] };
  return { headers, id, assetId, amount, target, plan, path: '/models/' + id };
}

test('migration HTTP file/context boundaries reject ambiguous files, cross-tenant and hidden scope without disclosing values', async () => {
  const f = await fixture();
  const imported = await request('/models/migration-plans/validate', f.headers, 'POST', { text: JSON.stringify(f.plan) });
  assert.equal(imported.status, 200); assert.deepEqual((await imported.json() as any).plan, f.plan);
  const duplicate = await request('/models/migration-plans/validate', f.headers, 'POST', { text: '{"operations":[],"operati\\u006fns":[1]}' });
  assert.equal(duplicate.status, 422); assert.ok((await duplicate.json() as any).issues.some((issue: any) => issue.code === 'duplicate'));
  const context = await request(f.path + '/migration-context', f.headers); assert.equal(context.status, 200);
  assert.deepEqual(await context.json(), { modelId: f.id, currentVersion: 1, sourceVersions: [1], assetCount: 1 });
  const consumer = await session('10000000-0000-4000-8000-000000000003');
  assert.equal((await request(f.path + '/migration-context', consumer)).status, 403);
  assert.equal((await request('/models/migration-plans/validate', consumer, 'POST', { text: JSON.stringify(f.plan) })).status, 403);
  const summit = await session('10000000-0000-4000-8000-000000000005', otherTenant);
  assert.equal((await request(f.path + '/migration-context', summit)).status, 404);
  await scope(tenant, steward, tx => tx.updateTable('assets').set({ visibility: 'restricted', allowed_identities: '[]' }).where('id', '=', f.assetId).execute());
  const denied = await request(f.path + '/migration-context', f.headers); assert.equal(denied.status, 403);
  const problem = await denied.text(); assert.ok(!problem.includes(f.assetId) && !problem.includes(f.amount) && !problem.includes('assetCount'));
});

test('migration HTTP execution binds preview, records failure without values, retries, and reauthorizes cached receipts', async () => {
  const f = await fixture(), body = { definition: f.target, plan: f.plan };
  const previewResponse = await request(f.path + '/migration-previews', mutation(f.headers), 'POST', body);
  assert.equal(previewResponse.status, 200); const { preview } = await previewResponse.json() as any;
  assert.deepEqual(preview.assets[0].beforeAttributes, { amount: f.amount });
  assert.deepEqual(preview.assets[0].afterAttributes, { budget: f.amount });
  const headers = mutation(f.headers), execution = { ...body, previewDigest: preview.previewDigest };
  assert.equal((await request(f.path + '/migrations', { ...headers, Origin: 'https://invalid.example' }, 'POST', execution)).status, 403);
  const invalid = await request(f.path + '/migrations', headers, 'POST', { ...execution, plan: { ...f.plan, operations: [] } });
  assert.equal(invalid.status, 422);
  assert.equal((await (await request(f.path, f.headers)).json() as any).model.currentVersion, 1);
  assert.equal((await (await request('/assets/' + f.assetId + '/attributes', f.headers)).json() as any).modelVersion, 1);
  const failureAudit = await scope(tenant, steward, tx => tx.selectFrom('audit').selectAll().where('resource_id', '=', f.id).where('action', '=', 'model.migration_attempt_failed').execute());
  assert.equal(failureAudit.length, 1); assert.equal(failureAudit[0].changes.attemptResult, 'failed');
  assert.ok(!JSON.stringify(failureAudit).includes(f.amount));
  // The failed idempotency transaction leaves its key reusable for the corrected request.
  const saved = await request(f.path + '/migrations', headers, 'POST', execution); assert.equal(saved.status, 201);
  const result = await saved.json() as any; assert.equal(result.model.version, 2); assert.equal(result.receipt.assetCount, 1);
  const replay = await request(f.path + '/migrations', headers, 'POST', execution); assert.equal(replay.status, 201);
  assert.deepEqual(await replay.json(), result);
  const receipt = await request(f.path + '/migrations/' + result.receipt.id, f.headers); assert.equal(receipt.status, 200);
  assert.deepEqual((await receipt.json() as any).receipt, result.receipt);
  const asset = await (await request('/assets/' + f.assetId + '/attributes', f.headers)).json() as any;
  assert.equal(asset.modelVersion, 2); assert.equal(asset.assetVersion, 3); assert.deepEqual(asset.attributes, { budget: f.amount });
  assert.equal((await request(f.path + '/migrations', headers, 'POST', { ...execution, previewDigest: '0'.repeat(64) })).status, 409);
  await scope(tenant, steward, tx => tx.updateTable('assets').set({ visibility: 'restricted', allowed_identities: '[]' }).where('id', '=', f.assetId).execute());
  assert.equal((await request(f.path + '/migrations/' + result.receipt.id, f.headers)).status, 403);
  const deniedReplay = await request(f.path + '/migrations', headers, 'POST', execution); assert.equal(deniedReplay.status, 403);
  assert.ok(!(await deniedReplay.text()).includes(f.amount));
  const replayAudit = await scope(tenant, steward, tx => tx.selectFrom('audit').select('changes').where('resource_id', '=', f.id).where('action', '=', 'model.migration_attempt_failed').orderBy('sequence', 'desc').executeTakeFirstOrThrow());
  assert.equal(replayAudit.changes.attemptResult, 'failed'); assert.equal('mutationTransaction' in replayAudit.changes, false);
  assert.equal((await (await request(f.path, f.headers)).json() as any).model.currentVersion, 2);
});

test('migration HTTP execution rejects stale asset-bound preview with no head, receipt or attribute changes', async () => {
  const f = await fixture(), body = { definition: f.target, plan: f.plan };
  const response = await request(f.path + '/migration-previews', mutation(f.headers), 'POST', body); assert.equal(response.status, 200);
  const { preview } = await response.json() as any;
  assert.equal((await request('/assets/' + f.assetId + '/attributes', mutation(f.headers, 2), 'PUT', { modelId: f.id, modelVersion: 1, attributes: { amount: '77.25' } })).status, 200);
  const rejected = await request(f.path + '/migrations', mutation(f.headers), 'POST', { ...body, previewDigest: preview.previewDigest });
  assert.equal(rejected.status, 409); assert.equal((await rejected.json() as any).code, 'MODEL_MIGRATION_PREVIEW_STALE');
  assert.equal((await (await request(f.path, f.headers)).json() as any).model.currentVersion, 1);
  const receipts = await scope(tenant, steward, tx => tx.selectFrom('governance_model_migrations').select('id').where('model_id', '=', f.id).execute());
  assert.equal(receipts.length, 0);
  assert.deepEqual((await (await request('/assets/' + f.assetId + '/attributes', f.headers)).json() as any).attributes, { amount: '77.25' });
});

after(async () => { await db.destroy(); });
