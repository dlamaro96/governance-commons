// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { db, lockTenantLedger, scope, sql, type Tx } from '../../packages/db/src/index.ts';
import { Problem, type Principal } from '../../packages/authz/src/index.ts';
import { verifyAuditIntegritySnapshot } from '../../apps/api/src/audit-reader.ts';
import { assetView, record, stableString, visibleAudit } from '../../apps/api/src/repository.ts';

const tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const steward = '10000000-0000-4000-8000-000000000001';
const consumer = '10000000-0000-4000-8000-000000000003';
const principal: Principal = { id: steward, tenantId: tenant, name: 'Synthetic audit reader',
  permissions: ['audit:read', 'catalog:read', 'models:read'] };
before(async () => {
  assert.ok(process.env.DATABASE_URL, 'A real runtime DATABASE_URL is required; no audit reader cases ran.');
  const result = await sql<{ name: string; superuser: boolean; bypass: boolean }>`SELECT current_user AS name,
    rolsuper AS superuser, rolbypassrls AS bypass FROM pg_roles WHERE rolname=current_user`.execute(db);
  assert.deepEqual(result.rows, [{ name: 'gc_app', superuser: false, bypass: false }]);
});
after(async () => { await db.destroy(); });

async function rolledBack(work: (tx: Tx) => Promise<void>) {
  const rollback = new Error('Rollback the complete synthetic audit fixture');
  await assert.rejects(db.transaction().setIsolationLevel('repeatable read').execute(async tx => {
    await sql`SELECT set_config('gc.tenant_id', ${tenant}, true), set_config('gc.actor_id', ${steward}, true)`.execute(tx);
    await lockTenantLedger(tx, tenant);
    await work(tx);
    throw rollback;
  }), error => error === rollback);
}
async function syntheticSession(tx: Tx, actor: string) {
  const sessionHash = createHash('sha256').update(randomUUID()).digest('hex');
  await tx.insertInto('sessions').values({ id_hash: sessionHash, identity_id: actor, tenant_id: tenant,
    csrf: randomUUID(), expires_at: new Date(Date.now() + 600_000) }).execute();
  return sessionHash;
}
function problem(status: number, code: string) {
  return (error: unknown) => {
    assert.ok(error instanceof Problem); assert.equal(error.status, status); assert.equal(error.code, code);
    for (const key of ['checked', 'head', 'failedId', 'count', 'total']) assert.equal(Object.hasOwn(error, key), false);
    return true;
  };
}

test('audit integrity rejects hidden scope before the 10000-row profile using a completely rolled-back real ledger', async () => {
  const correlation = randomUUID(), assetId = randomUUID(); let sessionHash = '';
  await rolledBack(async tx => {
    sessionHash = await syntheticSession(tx, steward);
    const prior = await tx.selectFrom('audit').select('hash').orderBy('sequence', 'desc').executeTakeFirst();
    let previousHash = prior?.hash ?? '0'.repeat(64);
    // Hash-valid ordinary events use bounded batches, not 10001 persistent
    // fixture rows or an injected profile limit. Every row rolls back below.
    let batch: Record<string, unknown>[] = [];
    for (let index = 0; index < 10_001; index++) {
      const id = randomUUID(), occurredAt = new Date().toISOString(), changes = { synthetic: true };
      const envelope = { id, tenantId: tenant, actorId: steward, actorName: principal.name,
        action: 'source.synthetic', resourceId: `${correlation}:${index}`, version: 1,
        changes, correlationId: correlation, occurredAt, previousHash };
      const hash = createHash('sha256').update(stableString(envelope)).digest('hex');
      batch.push({ tenant_id: tenant, id, actor_id: steward, actor_name: principal.name,
        action: envelope.action, resource_id: envelope.resourceId, changes: JSON.stringify({ ...changes, resourceVersion: 1 }),
        correlation_id: correlation, occurred_at: occurredAt, previous_hash: previousHash, hash,
        envelope: JSON.stringify(envelope) });
      previousHash = hash;
      if (batch.length === 1000 || index === 10_000) { await tx.insertInto('audit').values(batch).execute(); batch = []; }
    }
    const asset = await tx.insertInto('assets').values({ tenant_id: tenant, id: assetId, external_id: assetId,
      name: 'Synthetic inaccessible audit fixture', qualified_name: `synthetic.audit.${assetId}`, type: 'dataset',
      observed_at: new Date(), visibility: 'restricted', allowed_identities: JSON.stringify([consumer]) })
      .returningAll().executeTakeFirstOrThrow();
    await tx.insertInto('asset_revisions').values({ tenant_id: tenant, asset_id: assetId, version: asset.version,
      snapshot: JSON.stringify(assetView(asset)) }).execute();
    await record(tx, principal, 'asset.observed', assetId, 1, { synthetic: true }, correlation);
    const size = await tx.selectFrom('audit').select(sql<string>`count(*)::text`.as('count')).executeTakeFirstOrThrow();
    assert.ok(BigInt(size.count) > 10_000n);
    const own = await tx.selectFrom('audit').select(sql<string>`count(*)::text`.as('count'))
      .where('correlation_id', '=', correlation).executeTakeFirstOrThrow();
    assert.equal(own.count, '10002');
    assert.equal(await visibleAudit(tx, principal).where('audit.resource_id', '=', assetId).executeTakeFirst(), undefined);
    await assert.rejects(() => verifyAuditIntegritySnapshot(tx, principal, sessionHash), problem(403, 'AUDIT_SCOPE_UNAVAILABLE'));
  });
  await scope(tenant, steward, async tx => {
    assert.equal(await tx.selectFrom('audit').select('id').where('correlation_id', '=', correlation).executeTakeFirst(), undefined);
    assert.equal(await tx.selectFrom('outbox').select('id').where('resource_id', '=', assetId).executeTakeFirst(), undefined);
    assert.equal(await tx.selectFrom('assets').select('id').where('id', '=', assetId).executeTakeFirst(), undefined);
    assert.equal(await tx.selectFrom('asset_revisions').select('asset_id').where('asset_id', '=', assetId).executeTakeFirst(), undefined);
  });
  assert.equal(await db.selectFrom('sessions').select('id_hash').where('id_hash', '=', sessionHash).executeTakeFirst(), undefined);
});

test('audit integrity reloads current membership permissions and binds the exact active session before reading the ledger', async () => {
  const hashes: string[] = [];
  await rolledBack(async tx => {
    const consumerSession = await syntheticSession(tx, consumer), stewardSession = await syntheticSession(tx, steward);
    hashes.push(consumerSession, stewardSession);
    const actual = await tx.selectFrom('memberships').select('permissions').where('tenant_id', '=', tenant)
      .where('identity_id', '=', consumer).where('active', '=', true).executeTakeFirstOrThrow();
    assert.equal(actual.permissions.includes('audit:read'), false);
    // The caller's earlier principal deliberately contains a now-untrusted
    // grant. Only the real current membership is allowed to authorize the read.
    await assert.rejects(() => verifyAuditIntegritySnapshot(tx, { ...principal, id: consumer }, consumerSession), problem(403, 'FORBIDDEN'));
    await assert.rejects(() => verifyAuditIntegritySnapshot(tx, principal, consumerSession), problem(401, 'SESSION_EXPIRED'));
    await assert.rejects(() => verifyAuditIntegritySnapshot(tx, { ...principal, tenantId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' }, stewardSession), problem(401, 'SESSION_EXPIRED'));
    await tx.updateTable('sessions').set({ expires_at: new Date(0) }).where('id_hash', '=', stewardSession).execute();
    await assert.rejects(() => verifyAuditIntegritySnapshot(tx, principal, stewardSession), problem(401, 'SESSION_EXPIRED'));
  });
  assert.deepEqual(await db.selectFrom('sessions').select('id_hash').where('id_hash', 'in', hashes).execute(), []);
});
