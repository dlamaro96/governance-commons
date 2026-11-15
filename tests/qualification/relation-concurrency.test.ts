// SPDX-License-Identifier: Apache-2.0
/** Disposable SQL001–008 database only. Owner credentials never target core. */
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { db, scope, sql, type Tx } from '../../packages/db/src/index.ts';
import { Problem, type Principal } from '../../packages/authz/src/index.ts';
import { createAssetType } from '../../packages/domain/src/asset-type-service.ts';
import { typeHash } from '../../packages/domain/src/asset-type-policy.ts';
import { assignAssetModel } from '../../packages/domain/src/model-service.ts';
import { createRelation, createRelationType, authorizeRelationReplay, tombstoneRelation } from '../../packages/domain/src/relation-service.ts';
import { getAssetGraph, listAssetRelations } from '../../packages/domain/src/relation-graph.ts';
import type { RelationTypeDefinition } from '../../packages/domain/src/relation-contracts.ts';
import { assetView, once, record } from '../../apps/api/src/repository.ts';

if (!process.env.RELATION_OWNER_DATABASE_URL || !process.env.DATABASE_URL) throw Error('Disposable qualification requires RELATION_OWNER_DATABASE_URL and DATABASE_URL; no checks ran.');
process.env.SESSION_KEY ??= 'synthetic-isolated-relation-cursor-key-0000000000000000';
const owner = new pg.Pool({ connectionString: process.env.RELATION_OWNER_DATABASE_URL, max: 6 });
const runtime = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 6 });
const permissions = ['catalog:read', 'catalog:write', 'models:read', 'models:write', 'audit:read'];
const hooks = { record, assetSnapshot: assetView };
function deferred<T = void>() { let resolve!: (value: T | PromiseLike<T>) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
const problem = (expected: string) => (error: unknown) => error instanceof Problem && error.code === expected;
async function session(pool: pg.Pool, tenant: string, actor: string, isolation = '') {
  const client = await pool.connect(); await client.query(`BEGIN ${isolation}`);
  await client.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true),set_config('lock_timeout','3s',true),set_config('statement_timeout','10s',true)", [tenant, actor]);
  return client;
}
async function blocking(waiter: number, blocker: number) {
  const deadline = Date.now() + 2500;
  while (Date.now() < deadline) {
    const result = await owner.query('SELECT $2::integer=ANY(pg_blocking_pids($1::integer)) AS waiting', [waiter, blocker]);
    if (result.rows[0].waiting) return;
    await new Promise(resolve => setTimeout(resolve, 15));
  }
  assert.fail('Expected database lock wait was not observed');
}
async function fixture(options: Partial<RelationTypeDefinition> = {}) {
  const tenantId = randomUUID(), actorId = randomUUID(), ownerId = randomUUID();
  const admin = await owner.connect();
  try {
    await admin.query('BEGIN');
    await admin.query('INSERT INTO tenants(id,name) VALUES($1,$2)', [tenantId, 'Synthetic isolated relation tenant']);
    for (const id of [actorId, ownerId]) await admin.query('INSERT INTO identities(id,issuer,subject,name) VALUES($1::uuid,$2,$1::text,$3)', [id, 'synthetic-relations-qualification', 'Synthetic relation principal']);
    await admin.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)", [tenantId, actorId]);
    for (const id of [actorId, ownerId]) await admin.query('INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,$3,$4)', [tenantId, id, 'synthetic-steward', JSON.stringify(permissions)]);
    await admin.query('COMMIT');
  } catch (error) { await admin.query('ROLLBACK'); throw error; } finally { admin.release(); }
  const principal: Principal = { tenantId, id: actorId, name: 'Synthetic relation steward', permissions };
  const modelId = 'relation_endpoint_' + randomUUID().replaceAll('-', '');
  const typed = await scope(tenantId, actorId, tx => createAssetType(tx, principal, randomUUID(), { formatVersion: 1, id: modelId, version: 1,
    parents: [], attributes: {}, overrideAttributes: [], requiredOwner: false,
    lifecycle: { initial: 'draft', states: ['draft', 'active'], transitions: [{ from: 'draft', to: 'active' }] } }, hooks));
  const assets: { id: string; version: number }[] = [];
  await scope(tenantId, actorId, async tx => {
    for (let index = 0; index < 4; index += 1) {
      const id = randomUUID(); const row = await tx.insertInto('assets').values({ tenant_id: tenantId, id, external_id: id, name: `Synthetic concurrent endpoint ${index}`,
        qualified_name: `synthetic.relations.${id}`, type: 'dataset', observed_at: new Date() }).returningAll().executeTakeFirstOrThrow();
      await tx.insertInto('asset_revisions').values({ tenant_id: tenantId, asset_id: id, version: 1, snapshot: JSON.stringify(assetView(row)) }).execute();
      await assignAssetModel(tx, principal, randomUUID(), id, 1, { modelId, modelVersion: 1, attributes: {} }, hooks); assets.push({ id, version: 2 });
    }
  });
  const definition: RelationTypeDefinition = { formatVersion: 1, id: 'concurrent_relation_' + randomUUID().replaceAll('-', ''), version: 1,
    label: 'Synthetic concurrent relationship', inverseLabel: 'Synthetic inverse', direction: 'directed',
    sourceTypes: [{ typeId: typed.type.typeId!, includeDescendants: false }], targetTypes: [{ typeId: typed.type.typeId!, includeDescendants: false }],
    sourceStates: null, targetStates: null, cardinality: { outgoing: { min: 0, max: null }, incoming: { min: 0, max: null } },
    allowSelf: false, cycles: 'allow', attributes: {}, requiredOwner: false,
    lifecycle: { initial: 'draft', states: ['draft', 'active'], transitions: [{ from: 'draft', to: 'active' }] }, ...options };
  const created = await scope(tenantId, actorId, tx => createRelationType(tx, principal, randomUUID(), definition, hooks));
  return { tenantId, actorId, ownerId, principal, assets, typeId: created.type.relationTypeId, definition };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
function input(f: Fixture, source = 0, target = 1) { return { relationTypeId: f.typeId, relationTypeVersion: 1,
  sourceAssetId: f.assets[source]!.id, sourceAssetVersion: f.assets[source]!.version, targetAssetId: f.assets[target]!.id, targetAssetVersion: f.assets[target]!.version,
  attributes: {}, ownerId: f.definition.requiredOwner ? f.ownerId : null, validFrom: null, validTo: null, visibility: 'tenant' as const, allowedIdentityIds: [] }; }
const create = (f: Fixture, source = 0, target = 1) => scope(f.tenantId, f.actorId, tx => createRelation(tx, f.principal, randomUUID(), input(f, source, target), hooks));
const counter = (f: Fixture) => scope(f.tenantId, f.actorId, async tx => (await tx.selectFrom('tenant_graph_revisions').select('revision').executeTakeFirstOrThrow()).revision);

test('new scoped tenant lazily receives a graph fence and runtime cannot forge the counter or protected validation work', async () => {
  const f = await fixture(); assert.ok(BigInt(await counter(f)) > 0n);
  const c = await session(runtime, f.tenantId, f.actorId);
  try {
    assert.equal((await c.query('SELECT current_user')).rows[0].current_user, 'gc_app');
    await assert.rejects(() => c.query('UPDATE tenant_graph_revisions SET revision=0'), (e: any) => e.code === '42501');
  } finally { await c.query('ROLLBACK'); c.release(); }
});

test('a preheld asset row cannot deadlock against ledger-first mutation because the trigger fails immediately', async () => {
  const f = await fixture(); const a = await session(runtime, f.tenantId, f.actorId), b = await session(runtime, f.tenantId, f.actorId); let waiting: Promise<pg.QueryResult> | undefined;
  try {
    const apid = (await a.query('SELECT pg_backend_pid() AS pid')).rows[0].pid, bpid = (await b.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
    await a.query('SELECT id FROM assets WHERE id=$1 FOR UPDATE', [f.assets[0]!.id]);
    await b.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [f.tenantId]);
    waiting = b.query('SELECT id FROM assets WHERE id=$1 FOR UPDATE', [f.assets[0]!.id]);
    await blocking(bpid, apid);
    const start = Date.now(); await assert.rejects(() => a.query('UPDATE assets SET description=$1 WHERE id=$2', ['Rejected lock inversion', f.assets[0]!.id]), (e: any) => e.code === '55P03');
    assert.ok(Date.now() - start < 1000, 'Trigger must not wait for deadlock detection or lock_timeout');
    await a.query('ROLLBACK'); await waiting;
  } finally { await a.query('ROLLBACK'); await b.query('ROLLBACK'); await waiting?.catch(() => {}); a.release(); b.release(); }
});

test('two simultaneous real service creates at max one serialize to exactly one committed edge', async () => {
  const f = await fixture({ cardinality: { outgoing: { min: 0, max: 1 }, incoming: { min: 0, max: null } } });
  const results = await Promise.allSettled([create(f, 0, 1), create(f, 0, 2)]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1); const rejected = results.find(r => r.status === 'rejected');
  assert.equal(rejected?.status, 'rejected'); if (rejected?.status === 'rejected') assert.equal(rejected.reason.code, 'RELATION_CARDINALITY');
  await scope(f.tenantId, f.actorId, async tx => { assert.equal((await tx.selectFrom('relations').selectAll().execute()).length, 1); assert.equal((await tx.selectFrom('relation_revisions').selectAll().execute()).length, 1); });
});

test('simultaneous opposing acyclic service writes serialize and never commit a cycle', async () => {
  const f = await fixture({ cycles: 'acyclic' }); const results = await Promise.allSettled([create(f, 0, 1), create(f, 1, 0)]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  const rejected = results.find(r => r.status === 'rejected'); if (rejected?.status === 'rejected') assert.equal(rejected.reason.code, 'RELATION_CYCLE'); else assert.fail('One cycle-forming operation must fail');
  assert.equal((await scope(f.tenantId, f.actorId, tx => tx.selectFrom('relations').selectAll().execute())).length, 1);
});

test('the counter write rejects stale Repeatable Read snapshots even when the tenant advisory lock is now free', async () => {
  const f = await fixture(), stale = await session(runtime, f.tenantId, f.actorId, 'ISOLATION LEVEL REPEATABLE READ');
  try {
    await stale.query('SELECT revision FROM tenant_graph_revisions');
    await scope(f.tenantId, f.actorId, tx => tx.updateTable('assets').set({ description: 'Committed newer canonical snapshot' }).where('id', '=', f.assets[0]!.id).execute());
    await assert.rejects(() => stale.query('UPDATE assets SET description=$1 WHERE id=$2', ['Stale writer must not commit', f.assets[1]!.id]), (e: any) => e.code === '40001');
  } finally { await stale.query('ROLLBACK'); stale.release(); }
});

test('real relation mutation holds owner identity and tenant membership activity stable until commit', async () => {
  for (const table of ['identities', 'memberships'] as const) {
    const f = await fixture({ requiredOwner: true }), held = deferred<number>(), release = deferred();
    const mutation = scope(f.tenantId, f.actorId, async tx => {
      const pid = (await sql<{ pid: number }>`SELECT pg_backend_pid() AS pid`.execute(tx)).rows[0]!.pid;
      const result = await createRelation(tx, f.principal, randomUUID(), input(f), hooks); held.resolve(pid); await release.promise; return result;
    });
    const pid = await Promise.race([held.promise, mutation.then(() => { throw Error('Mutation escaped hold barrier'); })]);
    const admin = await session(owner, f.tenantId, f.actorId); let revocation: Promise<pg.QueryResult> | undefined;
    try {
      const adminPid = (await admin.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
      revocation = table === 'identities' ? admin.query('UPDATE identities SET active=false WHERE id=$1', [f.ownerId]) : admin.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2', [f.tenantId, f.ownerId]);
      await blocking(adminPid, pid); release.resolve(); const result = await mutation; assert.equal(result.relation.ownerId, f.ownerId);
      await revocation; await admin.query('COMMIT');
    } finally { release.resolve(); await mutation.catch(() => {}); await revocation?.catch(() => {}); await admin.query('ROLLBACK'); admin.release(); }
  }
});

test('actor revocation first is reread after the service waits on its principal lock and leaves no relation writes', async () => {
  const f = await fixture(), admin = await session(owner, f.tenantId, f.actorId), reached = deferred<number>(); let operation: Promise<unknown> | undefined;
  try {
    await admin.query('UPDATE memberships SET permissions=$1 WHERE tenant_id=$2 AND identity_id=$3', [JSON.stringify(['catalog:read']), f.tenantId, f.actorId]);
    const adminPid = (await admin.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
    operation = scope(f.tenantId, f.actorId, async tx => { reached.resolve((await sql<{ pid: number }>`SELECT pg_backend_pid() AS pid`.execute(tx)).rows[0]!.pid); return createRelation(tx, f.principal, randomUUID(), input(f), hooks); });
    const pid = await reached.promise; await blocking(pid, adminPid); await admin.query('COMMIT');
    await assert.rejects(() => operation!, problem('FORBIDDEN'));
    await scope(f.tenantId, f.actorId, async tx => { assert.deepEqual(await tx.selectFrom('relations').selectAll().execute(), []); assert.deepEqual(await tx.selectFrom('relation_revisions').selectAll().execute(), []); });
  } finally { await admin.query('ROLLBACK'); await operation?.catch(() => {}); admin.release(); }
});

test('direct publication rechecks every required owner but preserves unchanged optional inactive owners', async () => {
  for (const requiredOwner of [true, false]) {
    const f = await fixture({ requiredOwner });
    await scope(f.tenantId, f.actorId, tx => createRelation(tx, f.principal, randomUUID(), { ...input(f), ownerId: f.ownerId }, hooks));
    const admin = await session(owner, f.tenantId, f.actorId);
    try { await admin.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2', [f.tenantId, f.ownerId]); await admin.query('COMMIT'); }
    finally { await admin.query('ROLLBACK'); admin.release(); }
    const proposal = { ...f.definition, version: 2, label: 'Compatible label with unchanged owner' }, before = await counter(f);
    const publish = () => scope(f.tenantId, f.actorId, async tx => {
      await tx.insertInto('relation_type_versions').values({ tenant_id: f.tenantId, relation_type_id: f.typeId, version: 2,
        definition: JSON.stringify(proposal), definition_hash: typeHash(proposal), created_by: f.actorId }).execute();
      await tx.updateTable('relation_types').set({ current_version: 2 }).where('type_id', '=', f.typeId).execute();
      await record(tx, f.principal, 'relation_type.published', proposal.id, 2, { definitionHash: typeHash(proposal) }, randomUUID());
    });
    if (requiredOwner) { await assert.rejects(publish, (e: any) => e.code === '23514' && e.message === 'RELATION_MIGRATION_REQUIRED'); assert.equal(await counter(f), before); }
    else await publish();
  }
});

test('membership, permission and identity revocation independently deny graph pages and cached tombstone replay without changing the fence', async () => {
  for (const revocation of ['membership', 'permissions', 'identity'] as const) {
    const f = await fixture(); const first = await create(f, 0, 1); await create(f, 0, 2); await create(f, 0, 3);
    const key = 'synthetic-replay-' + randomUUID(), body = { relationId: first.relation.id, expected: 1 };
    const cached = await scope(f.tenantId, f.actorId, tx => once(tx, f.principal, 'relation.delete', key, body,
      () => tombstoneRelation(tx, f.principal, randomUUID(), first.relation.id, 1, hooks)));
    assert.equal(cached.relation.status, 'tombstoned');
    const graph = await scope(f.tenantId, f.actorId, tx => getAssetGraph(tx, f.principal, f.assets[0]!.id, { limit: 1 }));
    const list = await scope(f.tenantId, f.actorId, tx => listAssetRelations(tx, f.principal, f.assets[0]!.id, { limit: 1 }));
    assert.ok(graph.nextCursor && list.nextCursor); const revision = await counter(f);
    const admin = await session(owner, f.tenantId, f.actorId);
    try {
      if (revocation === 'identity') await admin.query('UPDATE identities SET active=false WHERE id=$1', [f.actorId]);
      else if (revocation === 'membership') await admin.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2', [f.tenantId, f.actorId]);
      else await admin.query('UPDATE memberships SET permissions=$1 WHERE tenant_id=$2 AND identity_id=$3', ['[]', f.tenantId, f.actorId]);
      await admin.query('COMMIT');
    } finally { await admin.query('ROLLBACK'); admin.release(); }
    assert.equal(await counter(f), revision, 'Permission revocation must be independently enforced, not mistaken for a graph fence update');
    await assert.rejects(() => scope(f.tenantId, f.actorId, tx => getAssetGraph(tx, f.principal, f.assets[0]!.id, { limit: 1, cursor: graph.nextCursor! })), problem('FORBIDDEN'));
    await assert.rejects(() => scope(f.tenantId, f.actorId, tx => listAssetRelations(tx, f.principal, f.assets[0]!.id, { limit: 1, cursor: list.nextCursor! })), problem('FORBIDDEN'));
    let invoked = false;
    await assert.rejects(() => scope(f.tenantId, f.actorId, async tx => {
      const replay = await once<typeof cached>(tx, f.principal, 'relation.delete', key, body, async () => { invoked = true; throw Error('Cached handler must not execute'); });
      assert.deepEqual(replay, cached); await authorizeRelationReplay(tx, f.principal, replay.relation, ['catalog:read', 'catalog:write', 'models:read']);
    }), problem('FORBIDDEN'));
    assert.equal(invoked, false); assert.equal(await counter(f), revision);
  }
});

after(async () => { await Promise.all([db.destroy(), owner.end(), runtime.end()]); });
