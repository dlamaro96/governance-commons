// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { db, scope, sql, type Tx } from '../../packages/db/src/index.ts';
import { Problem, type Principal } from '../../packages/authz/src/index.ts';
import { getMigrationReceipt } from '../../packages/domain/src/model-migration-service.ts';
import { assetView, stableString } from '../../apps/api/src/repository.ts';

const tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const otherTenant = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const steward = '10000000-0000-4000-8000-000000000001';
const summit = '10000000-0000-4000-8000-000000000005';
const principal: Principal = { id: steward, name: 'Synthetic storage test steward', tenantId: tenant,
  permissions: ['models:read', 'models:write', 'catalog:read', 'catalog:write'] };
const hash = (value: unknown): string => createHash('sha256').update(stableString(value)).digest('hex');
const code = (expected: string) => (error: any): boolean => error.code === expected;
interface Fixture { modelId: string; receipt: Record<string, any>; reference: Record<string, any> }

/** Deliberate direct SQL probes storage constraints, not an alternate domain ingress. */
async function fixture(options: { missingRevision?: number; missingModelPin?: boolean; tenantId?: string } = {}): Promise<Fixture> {
  const tenantId = options.tenantId ?? tenant; const actor = tenantId === tenant ? steward : summit;
  const modelId = `storage_${randomUUID().replaceAll('-', '')}`; const assetId = randomUUID(); const migrationId = randomUUID();
  const head = options.missingModelPin ? 3 : 1; const target = head + 1; const pin = options.missingModelPin ? 2 : 1;
  const plan = { formatVersion: 1, modelId, targetVersion: target, sourceVersions: [pin], acknowledgedChanges: [], operations: [] };
  const assetEntry = { assetId, fromAssetVersion: 1, toAssetVersion: 2, fromModelVersion: pin, toModelVersion: target,
    beforeHash: hash({ value: 'before' }), afterHash: hash({ value: 'after' }) };
  await scope(tenantId, actor, async tx => {
    await tx.insertInto('governance_models').values({ tenant_id: tenantId, id: modelId, current_version: target, created_by: actor }).execute();
    await tx.insertInto('governance_model_versions').values([head, target].map(version => {
      const definition = { formatVersion: 1, id: modelId, version, attributes: { value: { type: 'text' } } };
      return { tenant_id: tenantId, model_id: modelId, version, definition: JSON.stringify(definition), definition_hash: hash(definition), created_by: actor };
    })).execute();
    const asset = await tx.insertInto('assets').values({ tenant_id: tenantId, id: assetId, external_id: assetId,
      name: 'Synthetic receipt storage fixture', qualified_name: `test.storage.${assetId}`, type: 'dataset', observed_at: new Date(),
      model_id: modelId, model_version: target, attributes: JSON.stringify({ value: 'after' }), version: 2 }).returningAll().executeTakeFirstOrThrow();
    for (const version of [1, 2]) if (version !== options.missingRevision) {
      const snapshot = assetView({ ...asset, version, model_version: version === 1 ? pin : target,
        attributes: { value: version === 1 ? 'before' : 'after' } });
      await tx.insertInto('asset_revisions').values({ tenant_id: tenantId, asset_id: assetId, version, snapshot: JSON.stringify(snapshot) }).execute();
    }
  });
  return { modelId, receipt: { tenant_id: tenantId, id: migrationId, model_id: modelId, from_version: head, to_version: target,
    plan, plan_hash: hash(plan), preview_digest: hash('synthetic storage probe'), asset_count: 1, assets: [assetEntry], executed_by: actor },
  reference: { tenant_id: tenantId, migration_id: migrationId, asset_id: assetId, model_id: modelId,
    from_asset_version: 1, to_asset_version: 2, from_model_version: pin, to_model_version: target,
    before_hash: assetEntry.beforeHash, after_hash: assetEntry.afterHash } };
}
async function insertReceipt(tx: Tx, receipt: Record<string, any>) {
  return tx.insertInto('governance_model_migrations').values({ ...receipt, plan: JSON.stringify(receipt.plan), assets: JSON.stringify(receipt.assets) }).execute();
}
async function assertAbsent(input: Fixture): Promise<void> {
  await scope(tenant, steward, async tx => {
    for (const table of ['governance_model_migrations', 'governance_model_migration_assets', 'governance_model_migration_integrity_exceptions']) {
      const rows = await tx.selectFrom(table).selectAll().where(table === 'governance_model_migrations' ? 'id' : 'migration_id', '=', input.receipt.id).execute();
      assert.equal(rows.length, 0, `${table} must roll back`);
    }
  });
}

test('receipt insertion atomically normalizes exact immutable tenant-scoped revision references', async () => {
  const input = await fixture();
  await scope(tenant, steward, tx => insertReceipt(tx, input.receipt));
  const references = await scope(tenant, steward, tx => tx.selectFrom('governance_model_migration_assets').selectAll().where('migration_id', '=', input.receipt.id).execute());
  assert.deepEqual(references, [input.reference]);
  const read = await scope(tenant, steward, tx => getMigrationReceipt(tx, principal, input.modelId, input.receipt.id));
  assert.equal(read.receipt.assetCount, 1);
  assert.equal((await scope(otherTenant, summit, tx => tx.selectFrom('governance_model_migration_assets').selectAll().where('migration_id', '=', input.receipt.id).execute())).length, 0);
  const metadata = await scope(tenant, steward, tx => sql<{ relname: string; relrowsecurity: boolean; relforcerowsecurity: boolean; owner: string }>`
    SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity,r.rolname AS owner
    FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner
    WHERE c.relname IN ('governance_model_migration_assets','governance_model_migration_integrity_exceptions')`.execute(tx));
  assert.equal(metadata.rows.length, 2);
  for (const row of metadata.rows) { assert.equal(row.relrowsecurity, true); assert.equal(row.relforcerowsecurity, true); assert.notEqual(row.owner, 'gc_app'); }
});

test('receipt shape binds plan identity, bounded arrays, exact metadata and actual source pins', async () => {
  const input = await fixture();
  const mutations: ((receipt: Record<string, any>) => void)[] = [
    value => { value.plan.formatVersion = 2; }, value => { value.plan.modelId = 'another_model'; },
    value => { value.plan.targetVersion = 3; }, value => { delete value.plan.formatVersion; },
    value => { value.plan.extra = true; }, value => { value.plan.sourceVersions = []; },
    value => { value.plan.sourceVersions = [1, 1]; }, value => { value.plan.operations = Array(65).fill({ op: 'remove' }); },
    value => { value.plan.acknowledgedChanges = Array(2049).fill({ code: 'attribute_removed', path: '/attributes/old' }); },
    value => { value.plan.acknowledgedChanges = [{ code: 'not_a_change', path: '/attributes/old' }]; },
    value => { value.assets[0].beforeHash = null; }, value => { value.assets[0].toAssetVersion = 4; },
    value => { value.assets[0].fromModelVersion = 2; }, value => { value.assets[0].extra = 'not_allowed'; },
    value => { value.assets[0].assetId = 'not-a-uuid'; },
    value => { value.asset_count = 2; value.assets.push({ ...value.assets[0] }); },
  ];
  for (const mutate of mutations) {
    const receipt = structuredClone(input.receipt); mutate(receipt);
    await assert.rejects(() => scope(tenant, steward, tx => insertReceipt(tx, receipt)), code('23514'));
    await assertAbsent(input);
  }
});

test('new receipt foreign keys reject missing before/after revisions and missing historical model versions without exceptions', async () => {
  for (const options of [{ missingRevision: 1 }, { missingRevision: 2 }, { missingModelPin: true }]) {
    const input = await fixture(options);
    await assert.rejects(() => scope(tenant, steward, tx => insertReceipt(tx, input.receipt)), code('23503'));
    await assertAbsent(input);
  }
  const local = await fixture(); const foreign = await fixture({ tenantId: otherTenant });
  local.receipt.assets[0].assetId = foreign.receipt.assets[0].assetId;
  await assert.rejects(() => scope(tenant, steward, tx => insertReceipt(tx, local.receipt)), code('23503'));
  await assertAbsent(local);
});

test('app role cannot directly insert, mutate or truncate normalized references or historical exceptions', async () => {
  const input = await fixture(); await scope(tenant, steward, tx => insertReceipt(tx, input.receipt));
  await assert.rejects(() => scope(tenant, steward, tx => tx.insertInto('governance_model_migration_assets').values(input.reference).execute()), code('42501'));
  for (const table of ['governance_model_migration_assets', 'governance_model_migration_integrity_exceptions']) {
    await assert.rejects(() => scope(tenant, steward, tx => tx.updateTable(table).set({ migration_id: input.receipt.id }).where('migration_id', '=', input.receipt.id).execute()), code('42501'));
    await assert.rejects(() => scope(tenant, steward, tx => tx.deleteFrom(table).where('migration_id', '=', input.receipt.id).execute()), code('42501'));
    await assert.rejects(() => scope(tenant, steward, tx => sql`TRUNCATE TABLE ${sql.table(table)}`.execute(tx)), code('42501'));
  }
  await assert.rejects(() => scope(tenant, steward, tx => tx.insertInto('governance_model_migration_integrity_exceptions').values({
    tenant_id: tenant, migration_id: input.receipt.id, reason: 'missing_pre_005_asset_revision',
    missing_revisions: JSON.stringify([{ assetId: input.reference.asset_id, side: 'from', assetVersion: 1 }]),
  }).execute()), code('42501'));
});

test('runtime app cannot create a temporary table for an auxiliary trigger', async () => {
  const privileges = await scope(tenant, steward, tx => sql<{ role: string; temporary: boolean }>`
    SELECT current_user AS role, has_database_privilege(current_user,current_database(),'TEMP') AS temporary`.execute(tx));
  assert.equal(privileges.rows[0].role, 'gc_app');
  assert.equal(privileges.rows[0].temporary, false);
  await assert.rejects(() => scope(tenant, steward, tx =>
    sql`CREATE TEMP TABLE receipt_reference_probe(payload jsonb) ON COMMIT DROP`.execute(tx)), code('42501'));
  // The isolated owner-run upgrade harness prepares the auxiliary trigger and
  // probes its invoker behavior as gc_app without granting runtime CREATE/TEMP.
});

test('historical receipts are fully normalized or explicitly quarantined and the receipt getter fails closed for gaps', async t => {
  const observations = await scope(tenant, steward, async tx => {
    const receipts = await tx.selectFrom('governance_model_migrations').select(['id', 'model_id', 'asset_count', 'assets']).execute();
    const exceptions = await tx.selectFrom('governance_model_migration_integrity_exceptions').selectAll().execute();
    const references = await tx.selectFrom('governance_model_migration_assets').select(['migration_id', 'asset_id']).execute();
    for (const receipt of receipts) {
      const count = references.filter(reference => reference.migration_id === receipt.id).length;
      const exception = exceptions.find(item => item.migration_id === receipt.id);
      if (!exception) { assert.equal(count, receipt.asset_count); continue; }
      assert.equal(exception.reason, 'missing_pre_005_asset_revision'); assert.ok(exception.missing_revisions.length > 0);
      assert.ok(count < receipt.asset_count);
      for (const missing of exception.missing_revisions) {
        assert.ok(['from', 'to'].includes(missing.side));
        const entry = receipt.assets.find((asset: any) => asset.assetId === missing.assetId);
        assert.ok(entry); assert.equal(entry[missing.side === 'from' ? 'fromAssetVersion' : 'toAssetVersion'], missing.assetVersion);
        const revision = await tx.selectFrom('asset_revisions').select('version').where('asset_id', '=', missing.assetId).where('version', '=', missing.assetVersion).executeTakeFirst();
        assert.equal(revision, undefined, 'historical missing snapshots must not be fabricated');
      }
    }
    return { receipts, exceptions };
  });
  for (const exception of observations.exceptions) {
    const receipt = observations.receipts.find(item => item.id === exception.migration_id)!;
    await assert.rejects(() => scope(tenant, steward, tx => getMigrationReceipt(tx, principal, receipt.model_id, receipt.id)),
      error => error instanceof Problem && error.code === 'MODEL_MIGRATION_STORAGE_INVALID' && error.status === 500);
  }
  t.diagnostic(`Inspected ${observations.receipts.length} receipts and ${observations.exceptions.length} historical revision-gap exceptions. The isolated owner-run upgrade harness qualifies backfill on fresh CI.`);
});

after(async () => { await db.destroy(); });
