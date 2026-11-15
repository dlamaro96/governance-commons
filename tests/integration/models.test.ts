// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { db, lockTenantLedger, scope, sql } from '../../packages/db/src/index.ts';
import { Problem, type Principal } from '../../packages/authz/src/index.ts';
import { parseModelDefinition, type ModelDefinition } from '../../packages/domain/src/model.ts';
import {
  MODEL_SERVICE_LIMITS, assignAssetModel, createModel, getAssetModel, getModel, previewModel, publishModel,
  type ModelHooks,
} from '../../packages/domain/src/model-service.ts';

const tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const otherTenant = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const steward = '10000000-0000-4000-8000-000000000001';
const consumer = '10000000-0000-4000-8000-000000000003';
const summit = '10000000-0000-4000-8000-000000000005';
const principal: Principal = { id: steward, name: 'Synthetic model test steward', tenantId: tenant,
  permissions: ['models:read', 'models:write', 'catalog:read', 'catalog:write'] };
const identity = (): string => `model_${randomUUID().replaceAll('-', '')}`;
const journalFailure = new Error('Synthetic journal failure');
const failingJournal: ModelHooks = {
  record: async () => { throw journalFailure; },
  assetSnapshot: row => ({ ...row }),
};

function canonical(value: any): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
function definition(id = identity(), version = 1): ModelDefinition {
  const parsed = parseModelDefinition({ formatVersion: 1, id, version, attributes: { amount: { type: 'decimal', required: true } } });
  if (!parsed.ok) throw new Error('Invalid test fixture definition');
  return parsed.value;
}
/** Direct SQL fixtures are setup only; production HTTP audit/idempotency are tested in model-api.test.ts. */
async function fixtureModel(): Promise<ModelDefinition> {
  const value = definition();
  await scope(tenant, steward, async tx => {
    await tx.insertInto('governance_models').values({ tenant_id: tenant, id: value.id, current_version: 1, created_by: steward }).execute();
    await tx.insertInto('governance_model_versions').values({ tenant_id: tenant, model_id: value.id, version: 1,
      definition: JSON.stringify(value), definition_hash: createHash('sha256').update(canonical(value)).digest('hex'), created_by: steward }).execute();
  });
  return value;
}
async function fixtureAsset(model?: ModelDefinition, options: { hidden?: boolean; attributes?: unknown; version?: number } = {}): Promise<string> {
  const id = randomUUID();
  await scope(tenant, steward, tx => tx.insertInto('assets').values({ tenant_id: tenant, id,
    external_id: id, name: `Synthetic model fixture ${id}`, qualified_name: `test.model.${id}`, type: 'dataset', observed_at: new Date(),
    visibility: options.hidden ? 'restricted' : 'tenant', allowed_identities: JSON.stringify(options.hidden ? [consumer] : []),
    model_id: model?.id ?? null, model_version: model?.version ?? null,
    attributes: JSON.stringify(options.attributes ?? (model ? { amount: '9007199254740993.000000001' } : {})), version: options.version ?? 1,
  }).execute());
  return id;
}
function problem(code: string, status?: number): (error: unknown) => boolean {
  return error => error instanceof Problem && error.code === code && (status === undefined || error.status === status);
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

test('model application service rejects forged permissions and cross-tenant reads outside the HTTP adapter', async () => {
  const forged: Principal = { ...principal, id: consumer };
  const proposed = definition();
  await assert.rejects(() => scope(tenant, consumer, tx => createModel(tx, forged, randomUUID(), proposed, failingJournal)), problem('FORBIDDEN', 403));
  assert.equal((await scope(tenant, steward, tx => tx.selectFrom('governance_models').select('id').where('id', '=', proposed.id).execute())).length, 0);
  const current = await fixtureModel();
  await assert.rejects(() => scope(otherTenant, summit, tx => getModel(tx, { ...principal, id: summit, tenantId: otherTenant }, current.id)), problem('MODEL_NOT_FOUND', 404));
});

test('failed model creation journal rolls back both head and immutable version in real PostgreSQL', async () => {
  const proposed = definition();
  await assert.rejects(() => scope(tenant, steward, tx => createModel(tx, principal, randomUUID(), proposed, failingJournal)), error => error === journalFailure);
  const persisted = await scope(tenant, steward, async tx => ({
    heads: await tx.selectFrom('governance_models').select('id').where('id', '=', proposed.id).execute(),
    versions: await tx.selectFrom('governance_model_versions').select('version').where('model_id', '=', proposed.id).execute(),
    audit: await tx.selectFrom('audit').select('id').where('resource_id', '=', proposed.id).execute(),
    outbox: await tx.selectFrom('outbox').select('id').where('resource_id', '=', proposed.id).execute(),
  }));
  assert.deepEqual(persisted, { heads: [], versions: [], audit: [], outbox: [] });
});

test('failed publication journal restores the previous head and leaves no new model version', async () => {
  const current = await fixtureModel();
  const proposed: ModelDefinition = { ...current, version: 2, attributes: { ...current.attributes, notes: { type: 'text' } } };
  const preview = await scope(tenant, steward, tx => previewModel(tx, principal, current.id, 1, proposed));
  await assert.rejects(() => scope(tenant, steward, tx => publishModel(tx, principal, randomUUID(), current.id, 1, proposed, preview.previewDigest, failingJournal)), error => error === journalFailure);
  const persisted = await scope(tenant, steward, tx => getModel(tx, principal, current.id));
  assert.equal(persisted.model.version, 1);
  assert.equal(persisted.model.currentVersion, 1);
  await assert.rejects(() => scope(tenant, steward, tx => getModel(tx, principal, current.id, 2)), problem('MODEL_NOT_FOUND', 404));
  assert.equal((await scope(tenant, steward, tx => tx.selectFrom('audit').select('id').where('resource_id', '=', current.id).execute())).length, 0);
});

test('failed asset journal rolls back attributes, pin, optimistic version and immutable revision together', async () => {
  const current = await fixtureModel(); const assetId = await fixtureAsset();
  await assert.rejects(() => scope(tenant, steward, tx => assignAssetModel(tx, principal, randomUUID(), assetId, 1,
    { modelId: current.id, modelVersion: 1, attributes: { amount: '12345678901234567890.000000001' } }, failingJournal)), error => error === journalFailure);
  const persisted = await scope(tenant, steward, tx => getAssetModel(tx, principal, assetId));
  assert.deepEqual(persisted, { assetId, assetVersion: 1, modelId: null, modelVersion: null, attributes: {}, definition: null });
  assert.equal((await scope(tenant, steward, tx => tx.selectFrom('asset_revisions').select('version').where('asset_id', '=', assetId).execute())).length, 0);
  assert.equal((await scope(tenant, steward, tx => tx.selectFrom('outbox').select('id').where('resource_id', '=', assetId).execute())).length, 0);
});

test('complete model preview refuses hidden bindings without exposing asset IDs, counts or typed values', async () => {
  const current = await fixtureModel();
  const hiddenId = await fixtureAsset(current, { hidden: true, attributes: { amount: '919191919191919191.123456789' } });
  await assert.rejects(() => scope(tenant, steward, tx => previewModel(tx, principal, current.id, 1, { ...current, version: 2 })), error => {
    assert.ok(error instanceof Problem);
    assert.equal(error.code, 'MODEL_SCOPE_UNAVAILABLE'); assert.equal(error.status, 403); assert.equal(error.issues, undefined);
    assert.equal(JSON.stringify(error).includes(hiddenId), false);
    assert.equal(JSON.stringify(error).includes('919191919191919191'), false);
    assert.equal(error.message.includes('count'), false);
    return true;
  });
});

test('cohort byte limit rejects the whole preview before materializing oversized stored attributes', async () => {
  const current = await fixtureModel();
  await fixtureAsset(current, { attributes: { amount: '1', unexpected: 'x'.repeat(MODEL_SERVICE_LIMITS.previewBytes + 1) } });
  await assert.rejects(() => scope(tenant, steward, tx => previewModel(tx, principal, current.id, 1, { ...current, version: 2 })), problem('MODEL_PREVIEW_LIMIT', 422));
  assert.equal((await scope(tenant, steward, tx => getModel(tx, principal, current.id))).model.currentVersion, 1);
});

test('preview locks canonical asset rows against concurrent non-model edits until its transaction completes', { timeout: 15_000 }, async () => {
  const current = await fixtureModel(); const assetId = await fixtureAsset(current);
  const locked = deferred<number>(); const release = deferred<void>(); const writerPid = deferred<number>();
  const reader = scope(tenant, steward, async tx => {
    const pid = await sql<{ pid: number }>`select pg_backend_pid() as pid`.execute(tx);
    const result = await previewModel(tx, principal, current.id, 1, { ...current, version: 2 });
    locked.resolve(pid.rows[0].pid);
    await release.promise;
    return result;
  });
  // Observe rejection immediately; cleanup below still awaits every transaction before propagating failures.
  const readerSettled = Promise.allSettled([reader]);
  let writer: Promise<void> | undefined;
  let writerSettled: Promise<PromiseSettledResult<void>[]> | undefined;
  try {
    const readerPid = await Promise.race([locked.promise, reader.then(() => { throw new Error('Preview completed before its release.'); })]);
    // SELECT bypasses the statement mutation fence, proving that preview also holds the canonical row lock.
    await assert.rejects(() => scope(tenant, steward, tx => sql`select id from assets
      where tenant_id = ${tenant} and id = ${assetId} for update nowait`.execute(tx)), { code: '55P03' });
    writer = scope(tenant, steward, async tx => {
      const pid = await sql<{ pid: number }>`select pg_backend_pid() as pid`.execute(tx);
      writerPid.resolve(pid.rows[0].pid);
      await lockTenantLedger(tx, tenant);
      await tx.updateTable('assets').set({ description: 'Synthetic concurrent edit', version: 2 })
        .where('tenant_id', '=', tenant).where('id', '=', assetId).execute();
    });
    writerSettled = Promise.allSettled([writer]);
    const prematureWriter = writer.then(() => { throw new Error('Writer completed before the preview transaction released its locks.'); });
    const pid = await Promise.race([writerPid.promise, prematureWriter]);
    let blocked = false;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      const waiters = await sql<{ blockers: number[] }>`select pg_blocking_pids(${pid}) as blockers`.execute(db);
      if (waiters.rows[0].blockers.includes(readerPid)) { blocked = true; break; }
      await Promise.race([delay(20), prematureWriter]);
    }
    assert.equal(blocked, true, 'The conforming PostgreSQL writer must wait for the preview transaction to release the tenant ledger.');
  } finally {
    release.resolve();
    await Promise.all([readerSettled, writerSettled]);
  }
  const before = await reader;
  await writer;
  const afterPreview = await scope(tenant, steward, tx => previewModel(tx, principal, current.id, 1, { ...current, version: 2 }));
  assert.notEqual(afterPreview.previewDigest, before.previewDigest);
});

test('direct assignment prevents integer version overflow before a write can begin', async () => {
  const current = await fixtureModel(); const assetId = await fixtureAsset(undefined, { version: MODEL_SERVICE_LIMITS.databaseVersion });
  await assert.rejects(() => scope(tenant, steward, tx => assignAssetModel(tx, principal, randomUUID(), assetId, MODEL_SERVICE_LIMITS.databaseVersion,
    { modelId: current.id, modelVersion: 1, attributes: { amount: '1' } }, failingJournal)), problem('ASSET_VERSION_LIMIT', 422));
  assert.equal((await scope(tenant, steward, tx => getAssetModel(tx, principal, assetId))).assetVersion, MODEL_SERVICE_LIMITS.databaseVersion);
});

after(async () => { await db.destroy(); });
