// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { db, scope, sql } from '../../packages/db/src/index.ts';
import { Problem, type Principal } from '../../packages/authz/src/index.ts';
import { parseModelDefinition, previewModelUpgrade, type AttributeDefinition, type ModelDefinition } from '../../packages/domain/src/model.ts';
import { type MigrationAcknowledgement, type MigrationOperation, type MigrationPlan } from '../../packages/domain/src/model-migration.ts';
import { assignAssetModel, getAssetModel, getModel, type ModelHooks } from '../../packages/domain/src/model-service.ts';
import { executeMigration, getMigrationContext, getMigrationReceipt, previewMigration, type MigrationRequest } from '../../packages/domain/src/model-migration-service.ts';
import { assetView, record, stableString } from '../../apps/api/src/repository.ts';

const tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const otherTenant = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const steward = '10000000-0000-4000-8000-000000000001';
const consumer = '10000000-0000-4000-8000-000000000003';
const summit = '10000000-0000-4000-8000-000000000005';
const principal: Principal = { id: steward, name: 'Synthetic migration test steward', tenantId: tenant,
  permissions: ['models:read', 'models:write', 'catalog:read', 'catalog:write'] };
const hooks: ModelHooks = { record, assetSnapshot: assetView };
const hash = (value: unknown): string => createHash('sha256').update(stableString(value)).digest('hex');
const modelId = (): string => `migration_${randomUUID().replaceAll('-', '')}`;
function definition(attributes: Record<string, AttributeDefinition>, version = 1, id = modelId()): ModelDefinition {
  const result = parseModelDefinition({ formatVersion: 1, id, version, attributes });
  if (!result.ok) throw new Error(JSON.stringify(result.issues));
  return result.value;
}
function request(head: ModelDefinition, target: ModelDefinition, operations: readonly MigrationOperation[], sourceVersions = [head.version]): MigrationRequest {
  const result = previewModelUpgrade(head, target, []);
  if (!result.ok) throw new Error('Invalid test model upgrade');
  const plan: MigrationPlan = { formatVersion: 1, modelId: head.id, targetVersion: target.version, sourceVersions,
    acknowledgedChanges: result.value.changes.filter(change => change.requiresMigration).map(({ code, path }) => ({ code, path })) as MigrationAcknowledgement[], operations };
  return { definition: target, plan };
}
function problem(code: string, status?: number): (error: unknown) => boolean {
  return error => error instanceof Problem && error.code === code && (status === undefined || error.status === status);
}
/** Direct SQL creates fixtures only; service execution uses the production journal/snapshot hooks. */
async function fixture(definitions: readonly ModelDefinition[], values: readonly { attributes: unknown; pin?: number; hidden?: boolean }[]): Promise<string[]> {
  const latest = definitions[definitions.length - 1]; const ids = values.map(() => randomUUID());
  await scope(tenant, steward, async tx => {
    await tx.insertInto('governance_models').values({ tenant_id: tenant, id: latest.id, current_version: latest.version, created_by: steward }).execute();
    await tx.insertInto('governance_model_versions').values(definitions.map(value => ({ tenant_id: tenant, model_id: value.id,
      version: value.version, definition: JSON.stringify(value), definition_hash: hash(value), created_by: steward }))).execute();
    if (values.length) {
      const assets = await tx.insertInto('assets').values(values.map((value, index) => ({ tenant_id: tenant, id: ids[index],
      external_id: ids[index], name: `Synthetic migration fixture ${ids[index]}`, qualified_name: `test.migration.${ids[index]}`,
      type: 'dataset', observed_at: new Date(), visibility: value.hidden ? 'restricted' : 'tenant',
      allowed_identities: JSON.stringify(value.hidden ? [consumer] : []), model_id: latest.id,
      model_version: value.pin ?? latest.version, attributes: JSON.stringify(value.attributes), version: 1,
      }))).returningAll().execute();
      await tx.insertInto('asset_revisions').values(assets.map(asset => ({ tenant_id: tenant, asset_id: asset.id,
        version: asset.version, snapshot: JSON.stringify(assetView(asset)) }))).execute();
    }
  });
  return ids;
}
async function persisted(id: string, correlationId?: string) {
  return scope(tenant, steward, async tx => ({
    head: await tx.selectFrom('governance_models').select('current_version').where('id', '=', id).executeTakeFirstOrThrow(),
    versions: await tx.selectFrom('governance_model_versions').select(['version', 'definition_hash']).where('model_id', '=', id).orderBy('version').execute(),
    assets: await tx.selectFrom('assets').select(['id', 'version', 'model_version', 'attributes']).where('model_id', '=', id).orderBy('id').execute(),
    receipts: await tx.selectFrom('governance_model_migrations').selectAll().where('model_id', '=', id).execute(),
    audit: correlationId ? await tx.selectFrom('audit').selectAll().where('correlation_id', '=', correlationId).orderBy('sequence').execute() : [],
    outbox: correlationId ? await tx.selectFrom('outbox').selectAll().where(sql<boolean>`payload->>'correlationId' = ${correlationId}`).execute() : [],
    revisions: await tx.selectFrom('asset_revisions').innerJoin('assets', join => join.onRef('assets.id', '=', 'asset_revisions.asset_id').onRef('assets.tenant_id', '=', 'asset_revisions.tenant_id'))
      .select(['asset_revisions.asset_id', 'asset_revisions.version', 'asset_revisions.snapshot']).where('assets.model_id', '=', id)
      .orderBy('asset_revisions.asset_id').orderBy('asset_revisions.version').execute(),
  }));
}

test('explicit migration atomically repins historic and current assets, preserving decimals and immutable history', async () => {
  const old = definition({ amount: { type: 'decimal', required: true }, obsolete: { type: 'text' } });
  const head = definition({ ...old.attributes, note: { type: 'text' } }, 2, old.id);
  const target = definition({ amount: { type: 'text', required: true }, note: { type: 'text', required: true } }, 3, old.id);
  const amounts = ['90071992547409931234567890.123456789', '-98765432109876543210.000000001'];
  const ids = await fixture([old, head], [{ pin: 1, attributes: { amount: amounts[0], obsolete: 'retired explicitly' } }, { pin: 2, attributes: { amount: amounts[1], note: 'preserved' } }]);
  assert.deepEqual(await scope(tenant, steward, tx => getMigrationContext(tx, principal, old.id)), {
    modelId: old.id, currentVersion: 2, sourceVersions: [1, 2], assetCount: 2,
  });
  const input = request(head, target, [
    { op: 'remove', path: ['obsolete'], onMissing: 'skip' },
    { op: 'convert', path: ['amount'], conversion: 'decimalToText', onMissing: 'error' },
    { op: 'set', path: ['note'], value: 'migrated', mode: 'ifMissing' },
  ], [1, 2]);
  const preview = await scope(tenant, steward, tx => previewMigration(tx, principal, old.id, 2, input));
  assert.equal(preview.coverage, 'complete-tenant-model-bindings'); assert.equal(preview.assetCount, 2);
  assert.deepEqual(preview.assets.map(asset => asset.assetId), [...ids].sort());
  assert.equal(preview.assets.find(asset => asset.assetId === ids[0])!.beforeAttributes.obsolete, 'retired explicitly');
  assert.equal(preview.assets.find(asset => asset.assetId === ids[0])!.afterAttributes.amount, amounts[0]);
  assert.equal((await persisted(old.id)).head.current_version, 2);
  const correlation = randomUUID();
  const result = await scope(tenant, steward, tx => executeMigration(tx, principal, correlation, old.id, 2, { ...input, previewDigest: preview.previewDigest }, hooks));
  assert.equal(result.model.currentVersion, 3); assert.equal(result.receipt.assetCount, 2);
  assert.equal(JSON.stringify(result.receipt.assets).includes(amounts[0]), false);
  const stored = await persisted(old.id, correlation);
  assert.equal(stored.head.current_version, 3); assert.deepEqual(stored.versions.map(row => row.version), [1, 2, 3]);
  assert.equal(stored.versions[0].definition_hash, hash(old)); assert.equal(stored.versions[1].definition_hash, hash(head));
  assert.deepEqual(stored.assets.map(row => [row.version, row.model_version]), [[2, 3], [2, 3]]);
  assert.equal(stored.assets.find(row => row.id === ids[0])!.attributes.amount, amounts[0]);
  assert.equal(stored.revisions.length, 4);
  assert.deepEqual(stored.revisions.filter(row => row.version === 2).map(row => row.snapshot.modelVersion), [3, 3]);
  assert.deepEqual(stored.revisions.filter(row => row.version === 1).map(row => row.snapshot.modelVersion).sort(), [1, 2]);
  assert.equal(stored.receipts.length, 1); assert.equal(stored.audit.length, 3); assert.equal(stored.outbox.length, 3);
  for (let index = 0; index < stored.audit.length; index += 1) {
    const entry = stored.audit[index]; assert.equal(entry.hash, hash(entry.envelope));
    if (index) assert.equal(entry.previous_hash, stored.audit[index - 1].hash);
    assert.equal(JSON.stringify(entry.changes).includes(amounts[0]), false);
  }
  const read = await scope(tenant, steward, tx => getMigrationReceipt(tx, principal, old.id, result.receipt.id));
  assert.deepEqual(read.receipt, result.receipt);
  const reader: Principal = { ...principal, id: consumer, permissions: ['models:read', 'catalog:read'] };
  assert.equal((await scope(tenant, consumer, tx => getMigrationReceipt(tx, reader, old.id, result.receipt.id))).receipt.id, result.receipt.id);
  await assert.rejects(() => scope(tenant, consumer, tx => getMigrationReceipt(tx, { ...principal, id: consumer }, old.id,
    result.receipt.id, { forExecutionReplay: true })), problem('FORBIDDEN', 403));
  await assert.rejects(() => scope(tenant, steward, tx => tx.updateTable('governance_model_migrations').set({ asset_count: 0 }).where('id', '=', result.receipt.id).execute()), (error: any) => ['42501', 'P0001'].includes(error.code));
});

test('late production-journal failure rolls back receipt, head, pins, revisions, audit and outbox, then the same preview can retry', async () => {
  const head = definition({ old: { type: 'text' } }); const target = definition({ title: { type: 'text' } }, 2, head.id);
  await fixture([head], [{ attributes: { old: 'A' } }, { attributes: { old: 'B' } }]);
  const input = request(head, target, [{ op: 'rename', from: ['old'], to: ['title'], onMissing: 'error' }]);
  const preview = await scope(tenant, steward, tx => previewMigration(tx, principal, head.id, 1, input));
  const before = await persisted(head.id); const correlation = randomUUID(); const injected = new Error('Synthetic late migration journal failure'); let calls = 0;
  const failureHooks: ModelHooks = { assetSnapshot: assetView, record: async (...args) => {
    await record(...args); calls += 1;
    if (args[2] === 'model.migrated') throw injected;
  } };
  await assert.rejects(() => scope(tenant, steward, tx => executeMigration(tx, principal, correlation, head.id, 1,
    { ...input, previewDigest: preview.previewDigest }, failureHooks)), error => error === injected);
  assert.equal(calls, 3);
  const afterFailure = await persisted(head.id, correlation);
  assert.deepEqual(afterFailure, { ...before, audit: [], outbox: [] });
  const retried = await scope(tenant, steward, tx => executeMigration(tx, principal, randomUUID(), head.id, 1,
    { ...input, previewDigest: preview.previewDigest }, hooks));
  assert.equal(retried.model.version, 2); assert.equal(retried.receipt.assetCount, 2);
});

test('preview digest binds the exact plan, canonical asset versions and complete model bindings', async () => {
  const head = definition({ title: { type: 'text' } }); const target = definition({ title: { type: 'text' }, note: { type: 'text' } }, 2, head.id);
  const [assetId] = await fixture([head], [{ attributes: { title: 'A' } }]);
  const input = request(head, target, [{ op: 'set', path: ['note'], value: 'A', mode: 'ifMissing' }]);
  const preview = await scope(tenant, steward, tx => previewMigration(tx, principal, head.id, 1, input));
  const changedPlan = request(head, target, [{ op: 'set', path: ['note'], value: 'B', mode: 'ifMissing' }]);
  await assert.rejects(() => scope(tenant, steward, tx => executeMigration(tx, principal, randomUUID(), head.id, 1,
    { ...changedPlan, previewDigest: preview.previewDigest }, hooks)), problem('MODEL_MIGRATION_PREVIEW_STALE', 409));
  await scope(tenant, steward, async tx => {
    const asset = await tx.updateTable('assets').set({ version: 2, description: 'Synthetic concurrent edit' }).where('id', '=', assetId).returningAll().executeTakeFirstOrThrow();
    await tx.insertInto('asset_revisions').values({ tenant_id: tenant, asset_id: asset.id, version: asset.version,
      snapshot: JSON.stringify(assetView(asset)) }).execute();
  });
  await assert.rejects(() => scope(tenant, steward, tx => executeMigration(tx, principal, randomUUID(), head.id, 1,
    { ...input, previewDigest: preview.previewDigest }, hooks)), problem('MODEL_MIGRATION_PREVIEW_STALE', 409));
  const next = await scope(tenant, steward, tx => previewMigration(tx, principal, head.id, 1, input));
  assert.notEqual(next.previewDigest, preview.previewDigest);
  await scope(tenant, steward, async tx => {
    const id = randomUUID();
    const asset = await tx.insertInto('assets').values({ tenant_id: tenant, id, external_id: id, name: 'Synthetic new binding', qualified_name: `test.migration.${id}`, type: 'dataset', observed_at: new Date(),
      model_id: head.id, model_version: 1, attributes: JSON.stringify({ title: 'B' }) }).returningAll().executeTakeFirstOrThrow();
    await tx.insertInto('asset_revisions').values({ tenant_id: tenant, asset_id: asset.id, version: asset.version,
      snapshot: JSON.stringify(assetView(asset)) }).execute();
  });
  await assert.rejects(() => scope(tenant, steward, tx => executeMigration(tx, principal, randomUUID(), head.id, 1,
    { ...input, previewDigest: next.previewDigest }, hooks)), problem('MODEL_MIGRATION_PREVIEW_STALE', 409));
  assert.equal((await persisted(head.id)).versions.length, 1);
});

test('migration and receipt authorization deny hidden cohorts, cross-tenant reads and later-hidden reassigned assets', async () => {
  const hiddenHead = definition({ value: { type: 'text' } }); const hiddenTarget = definition(hiddenHead.attributes, 2, hiddenHead.id);
  const [hiddenId] = await fixture([hiddenHead], [{ attributes: { value: 'private marker' }, hidden: true }]);
  await assert.rejects(() => scope(tenant, steward, tx => previewMigration(tx, principal, hiddenHead.id, 1, request(hiddenHead, hiddenTarget, []))), error => {
    assert.ok(error instanceof Problem); assert.equal(error.code, 'MODEL_SCOPE_UNAVAILABLE'); assert.equal(error.issues, undefined);
    assert.equal(JSON.stringify(error).includes(hiddenId), false); assert.equal(JSON.stringify(error).includes('private marker'), false); return true;
  });
  await assert.rejects(() => scope(tenant, steward, tx => getMigrationContext(tx, principal, hiddenHead.id)), problem('MODEL_SCOPE_UNAVAILABLE', 403));
  const head = definition({ value: { type: 'text' } }); const target = definition(head.attributes, 2, head.id);
  const [assetId] = await fixture([head], [{ attributes: { value: 'visible' } }]);
  const input = request(head, target, []); const preview = await scope(tenant, steward, tx => previewMigration(tx, principal, head.id, 1, input));
  const result = await scope(tenant, steward, tx => executeMigration(tx, principal, randomUUID(), head.id, 1, { ...input, previewDigest: preview.previewDigest }, hooks));
  await assert.rejects(() => scope(otherTenant, summit, tx => getMigrationReceipt(tx, { ...principal, id: summit, tenantId: otherTenant }, head.id, result.receipt.id)), problem('MODEL_NOT_FOUND', 404));
  const otherModel = definition({ value: { type: 'text' } }); await fixture([otherModel], []);
  await scope(tenant, steward, tx => assignAssetModel(tx, principal, randomUUID(), assetId, 2, { modelId: otherModel.id, modelVersion: 1, attributes: { value: 'reassigned' } }, hooks));
  await scope(tenant, steward, tx => tx.updateTable('assets').set({ visibility: 'restricted', allowed_identities: JSON.stringify([consumer]) }).where('id', '=', assetId).execute());
  await assert.rejects(() => scope(tenant, steward, tx => getMigrationReceipt(tx, principal, head.id, result.receipt.id)), problem('MODEL_SCOPE_UNAVAILABLE', 403));
  assert.equal((await scope(otherTenant, summit, tx => tx.selectFrom('governance_model_migrations').select('id').where('id', '=', result.receipt.id).execute())).length, 0);
});

test('migration service rechecks permissions and exact pinned-version scope outside the HTTP adapter', async () => {
  const head = definition({ value: { type: 'text' } }); const target = definition(head.attributes, 2, head.id);
  await fixture([head], [{ attributes: { value: 'A' } }]); const input = request(head, target, []);
  await assert.rejects(() => scope(tenant, consumer, tx => previewMigration(tx, { ...principal, id: consumer }, head.id, 1, input)), problem('FORBIDDEN', 403));
  await assert.rejects(() => scope(tenant, steward, tx => previewMigration(tx, { ...principal, permissions: principal.permissions.filter(permission => permission !== 'catalog:write') }, head.id, 1, input)), problem('FORBIDDEN', 403));
  await assert.rejects(() => scope(tenant, steward, tx => previewMigration(tx, principal, head.id, 1, request(head, target, [], []))), problem('MODEL_MIGRATION_INVALID', 422));
  await assert.rejects(() => scope(tenant, steward, tx => executeMigration(tx, principal, randomUUID(), head.id, 1, { ...input, previewDigest: '' }, hooks)), problem('MODEL_MIGRATION_PREVIEW_REQUIRED', 428));
  assert.equal((await persisted(head.id)).versions.length, 1);
  const emptyHead = definition({ old: { type: 'text' } }); const emptyTarget = definition({}, 2, emptyHead.id);
  await fixture([emptyHead], []);
  assert.deepEqual(await scope(tenant, steward, tx => getMigrationContext(tx, principal, emptyHead.id)), {
    modelId: emptyHead.id, currentVersion: 1, sourceVersions: [], assetCount: 0,
  });
  const emptyInput = request(emptyHead, emptyTarget, [], []);
  const emptyPreview = await scope(tenant, steward, tx => previewMigration(tx, principal, emptyHead.id, 1, emptyInput));
  const emptyResult = await scope(tenant, steward, tx => executeMigration(tx, principal, randomUUID(), emptyHead.id, 1,
    { ...emptyInput, previewDigest: emptyPreview.previewDigest }, hooks));
  assert.equal(emptyResult.receipt.assetCount, 0); assert.deepEqual(emptyResult.receipt.assets, []);
});

test('invalid values block every write and return stable paths without copying protected values into issues', async () => {
  const head = definition({ old: { type: 'text' } }); const target = definition({ value: { type: 'decimal', required: true } }, 2, head.id);
  const [assetId] = await fixture([head], [{ attributes: { old: 'private marker' } }]);
  const input = request(head, target, [{ op: 'remove', path: ['old'], onMissing: 'error' }]);
  await assert.rejects(() => scope(tenant, steward, tx => previewMigration(tx, principal, head.id, 1, input)), error => {
    assert.ok(error instanceof Problem); assert.equal(error.code, 'MODEL_MIGRATION_INVALID');
    assert.ok(error.issues?.some(issue => issue.code === 'required' && issue.path === '/assets/0/targetAttributes/value'));
    assert.equal(JSON.stringify(error.issues).includes('private marker'), false); return true;
  });
  assert.equal((await scope(tenant, steward, tx => getAssetModel(tx, principal, assetId))).attributes.old, 'private marker');
  const stored = await persisted(head.id); assert.equal(stored.head.current_version, 1); assert.equal(stored.receipts.length, 0); assert.equal(stored.revisions.length, 1);
});

test('migration output byte and node budgets reject expansion before any version or asset is written', async () => {
  const head = definition({}); const target = definition({ value: { type: 'text' } }, 2, head.id);
  await fixture([head], Array.from({ length: 9 }, () => ({ attributes: {} })));
  const input = request(head, target, [{ op: 'set', path: ['value'], value: 'x'.repeat(65_536), mode: 'replace' }]);
  await assert.rejects(() => scope(tenant, steward, tx => previewMigration(tx, principal, head.id, 1, input)), problem('MODEL_MIGRATION_LIMIT', 422));
  assert.equal((await persisted(head.id)).versions.length, 1);
  const nodesHead = definition({}); const nodesTarget = definition({ values: { type: 'list', items: { type: 'list', items: { type: 'number' } } } }, 2, nodesHead.id);
  await fixture([nodesHead], Array.from({ length: 11 }, () => ({ attributes: {} })));
  const manyNodes = request(nodesHead, nodesTarget, [{ op: 'set', path: ['values'], value: Array.from({ length: 10 }, () => Array(1_000).fill(0)), mode: 'replace' }]);
  await assert.rejects(() => scope(tenant, steward, tx => previewMigration(tx, principal, nodesHead.id, 1, manyNodes)), problem('MODEL_MIGRATION_LIMIT', 422));
  assert.equal((await persisted(nodesHead.id)).receipts.length, 0);
});

test('historic model definitions have an aggregate materialization budget independent of small asset values', async () => {
  const id = modelId();
  const attributes = Object.fromEntries(Array.from({ length: 128 }, (_, index) => [`field${index}`, { type: 'text', label: 'x'.repeat(256) }])) as Record<string, AttributeDefinition>;
  const definitions = Array.from({ length: 16 }, (_, index) => definition(attributes, index + 1, id));
  const head = definitions[15]; const target = definition(attributes, 17, id);
  await fixture(definitions, definitions.map(value => ({ attributes: {}, pin: value.version })));
  const input = request(head, target, [], definitions.map(value => value.version));
  await assert.rejects(() => scope(tenant, steward, tx => previewMigration(tx, principal, id, 16, input)), problem('MODEL_MIGRATION_LIMIT', 422));
  assert.equal((await scope(tenant, steward, tx => getModel(tx, principal, id))).model.currentVersion, 16);
});

after(async () => { await db.destroy(); });
