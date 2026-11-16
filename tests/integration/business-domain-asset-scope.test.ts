// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { db, lockTenantLedger, scope, sql, type Tx } from '../../packages/db/src/index.ts';
import { Problem, type Principal } from '../../packages/authz/src/index.ts';
import { assetView, record } from '../../apps/api/src/repository.ts';
import { authorizeDomain, domainAsset, DOMAIN_PLACEMENT_READ } from '../../packages/domain/src/business-domain-store.ts';
import { domainPlacement } from '../../packages/domain/src/business-domain-read.ts';

const tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const steward = '10000000-0000-4000-8000-000000000001';
const consumer = '10000000-0000-4000-8000-000000000003';
const principal: Principal = { id: steward, tenantId: tenant, name: 'Synthetic asset scope reader',
  permissions: ['catalog:read', 'domains:read'] };
before(async () => {
  assert.ok(process.env.DATABASE_URL, 'A real runtime DATABASE_URL is required; no asset scope cases ran.');
  const result = await sql<{ name: string; superuser: boolean; bypass: boolean }>`SELECT current_user AS name,
    rolsuper AS superuser, rolbypassrls AS bypass FROM pg_roles WHERE rolname=current_user`.execute(db);
  assert.deepEqual(result.rows, [{ name: 'gc_app', superuser: false, bypass: false }]);
});
after(async () => { await db.destroy(); });

function unavailable(error: unknown) {
  assert.ok(error instanceof Problem);
  assert.equal(error.status, 404); assert.equal(error.code, 'ASSET_NOT_FOUND');
  return true;
}
async function fixtureState(tx: Tx, ids: string[], correlation: string) {
  return {
    assets: await tx.selectFrom('assets').selectAll().where('id', 'in', ids).orderBy('id').execute(),
    revisions: await tx.selectFrom('asset_revisions').selectAll().where('asset_id', 'in', ids).orderBy('asset_id').orderBy('version').execute(),
    audit: await tx.selectFrom('audit').selectAll().where('correlation_id', '=', correlation).orderBy('sequence').execute(),
    outbox: await tx.selectFrom('outbox').selectAll().where('resource_id', 'in', ids).orderBy('id').execute(),
    placements: await tx.selectFrom('asset_domain_placements').selectAll().where('asset_id', 'in', ids).orderBy('asset_id').execute(),
    placementRevisions: await tx.selectFrom('asset_domain_placement_revisions').selectAll().where('asset_id', 'in', ids).orderBy('asset_id').orderBy('version').execute(),
  };
}

test('domain asset lookups bind the requested identity and version even when a different restricted asset explicitly permits the actor', async () => {
  const decoy = randomUUID(), requested = randomUUID(), hidden = randomUUID(), unknown = randomUUID();
  const ids = [decoy, requested, hidden, unknown], correlation = randomUUID();
  const rollback = new Error('Rollback every synthetic asset scope fixture');
  await assert.rejects(scope(tenant, steward, async tx => {
    await lockTenantLedger(tx, tenant);
    const current = await authorizeDomain(tx, principal, DOMAIN_PLACEMENT_READ);
    for (const [id, visibility, allowed] of [
      [decoy, 'restricted', [steward]], [requested, 'tenant', []], [hidden, 'restricted', [consumer]],
    ] as const) {
      const row = await tx.insertInto('assets').values({ tenant_id: tenant, id, external_id: id,
        name: 'Synthetic domain asset scope fixture', qualified_name: `synthetic.domain-scope.${id}`, type: 'dataset',
        observed_at: new Date(), visibility, allowed_identities: JSON.stringify(allowed) }).returningAll().executeTakeFirstOrThrow();
      await tx.insertInto('asset_revisions').values({ tenant_id: tenant, asset_id: id, version: row.version,
        snapshot: JSON.stringify(assetView(row)) }).execute();
      await record(tx, current, 'asset.created', id, row.version, { syntheticFixture: true }, correlation);
    }
    // Give the requested asset a real second revision; the permitted decoy
    // stays at version one. No existing asset or membership is changed.
    const updated = await tx.updateTable('assets').set({ version: 2, description: 'Second synthetic revision', updated_at: new Date() })
      .where('tenant_id', '=', tenant).where('id', '=', requested).where('version', '=', 1).returningAll().executeTakeFirstOrThrow();
    await tx.insertInto('asset_revisions').values({ tenant_id: tenant, asset_id: requested, version: updated.version,
      snapshot: JSON.stringify(assetView(updated)) }).execute();
    await record(tx, current, 'asset.updated', requested, updated.version, { syntheticFixture: true }, correlation);
    const beforeReads = await fixtureState(tx, ids, correlation);
    assert.equal(beforeReads.assets.length, 3); assert.equal(beforeReads.revisions.length, 4);
    assert.equal(beforeReads.audit.length, 4); assert.equal(beforeReads.outbox.length, 4);

    // Both denials must survive an explicitly ACL-visible unrelated row.
    // They fail with the original ungrouped SQL OR regardless of row order.
    await assert.rejects(() => domainAsset(tx, current, unknown), unavailable);
    await assert.rejects(() => domainAsset(tx, current, hidden), unavailable);
    await assert.rejects(() => domainPlacement(tx, current, unknown), unavailable);
    await assert.rejects(() => domainPlacement(tx, current, hidden), unavailable);
    assert.deepEqual(await domainAsset(tx, current, decoy), { id: decoy, version: 1 });
    assert.deepEqual(await domainAsset(tx, current, requested), { id: requested, version: 2 });
    assert.deepEqual(await fixtureState(tx, ids, correlation), beforeReads, 'Authorized and denied reads must persist no changes');
    throw rollback;
  }), error => error === rollback);
  await scope(tenant, steward, async tx => {
    assert.deepEqual(await fixtureState(tx, ids, correlation), {
      assets: [], revisions: [], audit: [], outbox: [], placements: [], placementRevisions: [],
    }, 'No fixture asset, history, placement or journal rows may remain after rollback');
  });
});
