// SPDX-License-Identifier: Apache-2.0
import {createProtectedCoreSession,closeProtectedCoreSessions} from '../fixtures/protected-core-authentication.ts';
import { pacedFetch as fetch } from '../fixtures/http-budget.ts';
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { db, scope, sql } from '../../packages/db/src/index.ts';
import { Problem, type Principal } from '../../packages/authz/src/index.ts';
import { previewModelUpgrade } from '../../packages/domain/src/model.ts';
import type { AssetTypeDefinition } from '../../packages/domain/src/asset-type.ts';
import type { AssetTypeMigrationPlan } from '../../packages/domain/src/asset-type-migration.ts';
import { assetTypePolicy } from '../../packages/domain/src/asset-type-policy.ts';
import { assetTypePersistence, assetTypePolicyChanges, createAssetType, getAssetType, previewAssetType, publishAssetType } from '../../packages/domain/src/asset-type-service.ts';
import { assignAssetModel, type ModelHooks } from '../../packages/domain/src/model-service.ts';
import { getMigrationReceipt } from '../../packages/domain/src/model-migration-service.ts';
import { configureTypeMigrationTransaction, executeTypeMigration, getTypeMigrationContext, getTypeMigrationReceipt, previewTypeMigration } from '../../packages/domain/src/asset-type-migration-service.ts';
import { assetView, once, record } from '../../apps/api/src/repository.ts';

const tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', otherTenant = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const steward = '10000000-0000-4000-8000-000000000001', owner = '10000000-0000-4000-8000-000000000002', summit = '10000000-0000-4000-8000-000000000005';
const p: Principal = { id: steward, name: 'Synthetic type migration steward', tenantId: tenant, permissions: ['models:read', 'models:write', 'catalog:read', 'catalog:write'] };
const hooks: ModelHooks = { record, assetSnapshot: assetView };
const amount = '123456789012345678901234567890.000000001';
const id = () => 'migrate_type_' + randomUUID().replaceAll('-', '');
const problem = (code: string) => (error: unknown) => error instanceof Problem && error.code === code;
const scoped = <T>(work: Parameters<typeof scope<T>>[2]) => scope(tenant, steward, work);
function definition(overrides: Partial<AssetTypeDefinition> = {}): AssetTypeDefinition {
  return { formatVersion: 1, id: id(), version: 1, parents: [], attributes: { amount: { type: 'decimal', required: true } },
    overrideAttributes: [], requiredOwner: false, lifecycle: { initial: 'draft', states: ['draft', 'active'], transitions: [{ from: 'draft', to: 'active' }] }, ...overrides };
}
const create = (d: AssetTypeDefinition) => scoped(tx => createAssetType(tx, p, randomUUID(), d, hooks));
async function publish(d: AssetTypeDefinition) {
  const preview = await scoped(tx => previewAssetType(tx, p, d.id, d.version - 1, d));
  return scoped(tx => publishAssetType(tx, p, randomUUID(), d.id, d.version - 1, d, preview.previewDigest, hooks));
}
async function asset(type: string, pin = 1, ownerId: string | null = null) {
  const assetId = randomUUID();
  await scoped(async tx => {
    const row = await tx.insertInto('assets').values({ tenant_id: tenant, id: assetId, external_id: assetId, name: 'Synthetic type migration asset', qualified_name: `synthetic.migration.${assetId}`,
      type: 'dataset', observed_at: new Date(), owner_id: ownerId }).returningAll().executeTakeFirstOrThrow();
    await tx.insertInto('asset_revisions').values({ tenant_id: tenant, asset_id: assetId, version: row.version, snapshot: JSON.stringify(assetView(row)) }).execute();
    await assignAssetModel(tx, p, randomUUID(), assetId, 1, { modelId: type, modelVersion: pin, attributes: { amount } }, hooks);
  });
  return assetId;
}
async function request(target: AssetTypeDefinition): Promise<{ definition: AssetTypeDefinition; plan: AssetTypeMigrationPlan }> {
  const context = await scoped(tx => getTypeMigrationContext(tx, p, target.id));
  const { head, resolved } = await scoped(async tx => ({ head: (await assetTypePolicy(tx, p, target.id, context.currentVersion))!, resolved: await assetTypePersistence.resolved(tx, p, target) }));
  const changes = previewModelUpgrade(head.model, resolved.model, []); assert.ok(changes.ok);
  return { definition: target, plan: { formatVersion: 1, typeId: context.typeId,
    attributes: { formatVersion: 1, modelId: target.id, targetVersion: target.version, sourceVersions: context.sourceVersions,
      acknowledgedChanges: changes.value.changes.filter(change => change.requiresMigration).map(({ code, path }) => {
        assert.ok(code === 'attribute_removed' || code === 'type_changed' || code === 'constraints_changed'); return { code, path };
      }), operations: [] },
    owner: { default: 'preserve', overrides: [] }, lifecycle: { onUnmapped: 'preserve', mappings: [] }, acknowledgedPolicyChanges: assetTypePolicyChanges(head, resolved) } };
}
const preview = (input: Awaited<ReturnType<typeof request>>) => scoped(tx => previewTypeMigration(tx, p, input.definition.id, input.definition.version - 1, input));
async function snapshot(modelId: string) {
  return scoped(async tx => ({
    head: await tx.selectFrom('governance_models').selectAll().where('id', '=', modelId).execute(),
    versions: await tx.selectFrom('asset_type_versions').selectAll().where('model_id', '=', modelId).orderBy('version').execute(),
    flat: await tx.selectFrom('governance_model_versions').selectAll().where('model_id', '=', modelId).orderBy('version').execute(),
    assets: await tx.selectFrom('assets').selectAll().where('model_id', '=', modelId).orderBy('id').execute(),
    receipts: await tx.selectFrom('asset_type_migrations').selectAll().where('model_id', '=', modelId).execute(),
    base: await tx.selectFrom('governance_model_migrations').selectAll().where('model_id', '=', modelId).execute(),
    normalized: await tx.selectFrom('asset_type_migration_assets').selectAll().where('model_id', '=', modelId).orderBy('asset_id').execute(),
    revisions: await tx.selectFrom('asset_revisions').innerJoin('assets', join => join.onRef('assets.id', '=', 'asset_revisions.asset_id').onRef('assets.tenant_id', '=', 'asset_revisions.tenant_id'))
      .select(['asset_revisions.asset_id', 'asset_revisions.version', 'asset_revisions.snapshot']).where('assets.model_id', '=', modelId).orderBy('asset_revisions.asset_id').orderBy('asset_revisions.version').execute(),
  }));
}

test('complete type migration combines mixed source pins, changed parents, owner repair and states while descendants remain pinned', async () => {
  const parent = definition(); await create(parent);
  const child = definition({ parents: [{ id: parent.id, version: 1 }], attributes: {}, lifecycle: null }); await create(child);
  const first = await asset(child.id);
  await publish({ ...child, version: 2, attributes: { note: { type: 'text' } } });
  const second = await asset(child.id, 2, owner);
  const descendant = definition({ parents: [{ id: child.id, version: 1 }], attributes: {}, lifecycle: null }); await create(descendant);
  await asset(descendant.id, 1, steward); const descendantBefore = await snapshot(descendant.id);
  const nextParent = definition({ attributes: { amount: { type: 'text', required: true } }, requiredOwner: true,
    lifecycle: { initial: 'review', states: ['review', 'published'], transitions: [{ from: 'review', to: 'published' }] } }); await create(nextParent);
  const target = { ...child, version: 3, parents: [{ id: nextParent.id, version: 1 }], attributes: { note: { type: 'text' as const, required: true } } };
  const input = await request(target);
  input.plan = { ...input.plan, attributes: { ...input.plan.attributes, operations: [
    { op: 'convert', path: ['amount'], conversion: 'decimalToText', onMissing: 'error' }, { op: 'set', path: ['note'], value: 'explicitly migrated', mode: 'ifMissing' }] },
    owner: { default: 'preserve', overrides: [{ assetId: first, ownerId: owner }] },
    lifecycle: { onUnmapped: 'error', mappings: [{ sourceVersion: 1, from: 'draft', to: 'review' }, { sourceVersion: 2, from: 'draft', to: 'published' }] } };
  const checked = await preview(input); assert.equal(checked.assets.length, 2);
  assert.equal(checked.assets.find(item => item.assetId === first)!.after.ownerId, owner);
  const result = await scoped(tx => executeTypeMigration(tx, p, randomUUID(), child.id, 2, { ...input, previewDigest: checked.previewDigest }, hooks));
  assert.equal(result.type.version, 3); assert.equal(result.receipt.assets.length, 2);
  assert.deepEqual(result.receipt.plan.attributes.sourceVersions, [1, 2]);
  assert.equal(result.receipt.assets.find(item => item.assetId === second)!.after.state, 'published');
  assert.ok(result.receipt.assets.every(item => item.after.attributes.amount === amount && item.toAssetVersion === 3));
  assert.deepEqual(await snapshot(descendant.id), descendantBefore);
  assert.deepEqual(await scoped(tx => getTypeMigrationReceipt(tx, p, child.id, result.receipt.id)), { receipt: result.receipt });
  await assert.rejects(scoped(tx => getMigrationReceipt(tx, p, child.id, result.receipt.id)), problem('ASSET_TYPE_REQUIRED'));
});

test('complete migration rejects stale state, plan, cohort, foreign owners and hidden scope without writing a target', async () => {
  const original = definition(); await create(original); const assetId = await asset(original.id, 1, owner);
  const input = await request({ ...original, version: 2 }); const checked = await preview(input);
  const changedPlan = { ...input, plan: { ...input.plan, owner: { default: 'preserve' as const, overrides: [{ assetId, ownerId: steward }] } } };
  await assert.rejects(scoped(tx => executeTypeMigration(tx, p, randomUUID(), original.id, 1, { ...changedPlan, previewDigest: checked.previewDigest }, hooks)), problem('ASSET_TYPE_MIGRATION_PREVIEW_STALE'));
  await assert.rejects(preview({ ...input, plan: { ...input.plan, owner: { default: 'preserve', overrides: [{ assetId, ownerId: summit }] } } }), problem('ASSET_TYPE_MIGRATION_INVALID'));
  await scoped(async tx => {
    const row = await tx.updateTable('assets').set({ type_state: 'active', version: 3 }).where('id', '=', assetId).returningAll().executeTakeFirstOrThrow();
    await tx.insertInto('asset_revisions').values({ tenant_id: tenant, asset_id: assetId, version: 3, snapshot: JSON.stringify(assetView(row)) }).execute();
  });
  await assert.rejects(scoped(tx => executeTypeMigration(tx, p, randomUUID(), original.id, 1, { ...input, previewDigest: checked.previewDigest }, hooks)), problem('ASSET_TYPE_MIGRATION_PREVIEW_STALE'));
  const latest = await preview(input); await asset(original.id, 1, owner);
  await assert.rejects(scoped(tx => executeTypeMigration(tx, p, randomUUID(), original.id, 1, { ...input, previewDigest: latest.previewDigest }, hooks)), problem('ASSET_TYPE_MIGRATION_PREVIEW_STALE'));
  await scoped(tx => tx.updateTable('assets').set({ visibility: 'restricted', allowed_identities: '[]' }).where('id', '=', assetId).execute());
  await assert.rejects(preview(input), problem('MODEL_SCOPE_UNAVAILABLE'));
  assert.equal((await scoped(tx => getAssetType(tx, p, original.id))).type.currentVersion, 1);
});

test('late journal failure rolls back owner/state/pins/values, normalized receipts and idempotency, then same key retries once', async () => {
  const original = definition(); await create(original); const assetId = await asset(original.id, 1, owner);
  const target = { ...original, version: 2, requiredOwner: true, lifecycle: { initial: 'review', states: ['review'], transitions: [] } };
  const input = await request(target); input.plan = { ...input.plan, owner: { default: 'preserve', overrides: [{ assetId, ownerId: steward }] }, lifecycle: { onUnmapped: 'error', mappings: [{ sourceVersion: 1, from: 'draft', to: 'review' }] } };
  const checked = await preview(input), before = await snapshot(original.id), correlation = randomUUID(), key = randomUUID();
  const body = { ...input, previewDigest: checked.previewDigest };
  const run = (testHooks: ModelHooks) => scoped(async tx => {
    await configureTypeMigrationTransaction(tx);
    const result = await once(tx, p, 'test.type-migration', key, body, () => executeTypeMigration(tx, p, correlation, original.id, 1, body, testHooks));
    await getTypeMigrationReceipt(tx, p, original.id, result.receipt.id, true); return result;
  });
  const broken: ModelHooks = { ...hooks, record: async (...args) => { await record(...args); if (args[2] === 'model.type_migrated') throw new Error('synthetic late typed journal failure'); } };
  await assert.rejects(run(broken), /synthetic late typed journal failure/);
  assert.deepEqual(await snapshot(original.id), before);
  const counts = await scoped(async tx => ({
    audit: await tx.selectFrom('audit').selectAll().where('correlation_id', '=', correlation).execute(),
    outbox: await tx.selectFrom('outbox').selectAll().where(sql<boolean>`payload->>'correlationId'=${correlation}`).execute(),
    idempotency: await tx.selectFrom('idempotency').selectAll().where('key', '=', key).execute(),
  })); assert.deepEqual(counts, { audit: [], outbox: [], idempotency: [] });
  const result = await run(hooks), again = await run(hooks); assert.deepEqual(again, result);
  const stored = await snapshot(original.id); assert.equal(stored.receipts.length, 1); assert.equal(stored.normalized.length, 1);
  assert.equal(stored.assets[0].owner_id, steward); assert.equal(stored.assets[0].type_state, 'review');
  await scoped(tx => tx.updateTable('assets').set({ visibility: 'restricted', allowed_identities: '[]' }).where('id', '=', assetId).execute());
  await assert.rejects(run(hooks), problem('MODEL_SCOPE_UNAVAILABLE'));
});

test('empty authored cohort binds the unpinned head resolution and still produces a complete immutable receipt', async () => {
  const original = definition(); await create(original);
  const input = await request({ ...original, version: 2 }); const checked = await preview(input);
  assert.equal(checked.assets.length, 0); assert.deepEqual(checked.sourceResolutions.map(item => item.version), [1]);
  const result = await scoped(tx => executeTypeMigration(tx, p, randomUUID(), original.id, 1, { ...input, previewDigest: checked.previewDigest }, hooks));
  assert.equal(result.receipt.assetCount, 0); assert.deepEqual(result.receipt.plan.attributes.sourceVersions, []);
  const foreign = { ...p, id: summit, tenantId: otherTenant };
  await assert.rejects(scope(otherTenant, summit, tx => getTypeMigrationReceipt(tx, foreign, original.id, result.receipt.id)), problem('ASSET_TYPE_NOT_FOUND'));
});

test('HTTP complete migration uses current authorization, exact preview, CSRF and immutable idempotent receipts', async () => {
  const original = definition(); await create(original); await asset(original.id, 1, owner);
  const input = await request({ ...original, version: 2 });
  const native = await createProtectedCoreSession(steward, tenant);
  const base = (process.env.TEST_BASE_URL ?? 'http://api:4310') + '/api/v1/asset-types/' + original.id;
  const headers = { ...native.headers, 'If-Match': '1', 'Idempotency-Key': randomUUID() };
  const previewResponse = await fetch(base + '/migration-previews', { method: 'POST', headers, body: JSON.stringify(input) });
  assert.equal(previewResponse.status, 200); const checked = await previewResponse.json() as any;
  const body = JSON.stringify({ ...input, previewDigest: checked.preview.previewDigest });
  const denied = await fetch(base + '/migrations', { method: 'POST', headers: { ...headers, 'X-CSRF-Token': 'invalid' }, body }); assert.equal(denied.status, 403);
  const executed = await fetch(base + '/migrations', { method: 'POST', headers, body }); assert.equal(executed.status, 201); const result = await executed.json() as any;
  const replay = await fetch(base + '/migrations', { method: 'POST', headers, body }); assert.equal(replay.status, 201); assert.deepEqual(await replay.json(), result);
  const history = await fetch(base + '/migrations/' + result.receipt.id, { headers }); assert.equal(history.status, 200); assert.deepEqual(await history.json(), { receipt: result.receipt });
});
after(async () => { await closeProtectedCoreSessions(); await db.destroy(); });
