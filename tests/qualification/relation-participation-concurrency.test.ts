// SPDX-License-Identifier: Apache-2.0
/** Disposable owner/runtime database only; no core or shared seeded identity mutation. */
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { db, scope, sql } from '../../packages/db/src/index.ts';
import type { Principal } from '../../packages/authz/src/index.ts';
import type { GraphChangeSet } from '../../packages/domain/src/relation-migration-contracts.ts';
import { parseGraphChangeSet } from '../../packages/domain/src/relation-migration.ts';
import { assetView, record } from '../../apps/api/src/repository.ts';
import { fixture, values, plan, execute, begin, bodyFor, emptyChange, candidate, insertEdge, writeDefinition, permissions, correlation, type Fixture } from '../fixtures/relation-participation.ts';
if (!process.env.RELATION_PARTICIPATION_OWNER_DATABASE_URL || !process.env.DATABASE_URL) throw Error('Disposable owner and runtime URLs are required; no concurrency checks ran.');
const owner = new pg.Pool({ connectionString: process.env.RELATION_PARTICIPATION_OWNER_DATABASE_URL, max: 6 });
const runtime = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 6 });
function deferred<T = void>() { let resolve!: (value: T | PromiseLike<T>) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
async function session(pool: pg.Pool, f: Fixture) {
  const client = await pool.connect(); await client.query('BEGIN');
  await client.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true),set_config('lock_timeout','4s',true),set_config('statement_timeout','10s',true)", [f.principal.tenantId, f.principal.id]); return client;
}
async function blocked(waiter: number, blocker: number) {
  const until = Date.now() + 3000;
  while (Date.now() < until) {
    if ((await owner.query('SELECT $2::integer=ANY(pg_blocking_pids($1::integer)) AS waiting', [waiter, blocker])).rows[0].waiting) return;
    await new Promise(resolve => setTimeout(resolve, 15));
  }
  assert.fail('The expected database lock wait was not observed');
}
async function isolated(requiredOwner = false) {
  const tenantId = randomUUID(), ids = [randomUUID(), randomUUID()].sort(), actorId = ids[1]!, ownerId = ids[0]!;
  const admin = await owner.connect();
  try {
    await admin.query('BEGIN'); await admin.query('INSERT INTO tenants(id,name) VALUES($1,$2)', [tenantId, 'Synthetic participation qualification']);
    for (const id of ids) await admin.query('INSERT INTO identities(id,issuer,subject,name) VALUES($1::uuid,$2,$1::text,$3)', [id, 'synthetic-participation', 'Synthetic graph principal']);
    await admin.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)", [tenantId, actorId]);
    for (const id of ids) await admin.query('INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,$3,$4)', [tenantId, id, 'synthetic-steward', JSON.stringify(permissions)]);
    await admin.query('COMMIT');
  } catch (error) { await admin.query('ROLLBACK'); throw error; } finally { admin.release(); }
  const p: Principal = { tenantId, id: actorId, name: 'Synthetic isolated graph actor', permissions };
  const f = await fixture({ principal: p, definition: { requiredOwner } });
  const edge = await scope(tenantId, actorId, tx => insertEdge(tx, f, candidate(f, 0, 1, values({}, requiredOwner ? ownerId : null))));
  const change: GraphChangeSet = { ...emptyChange(), relationTargets: [{ kind: 'repair', expectedHeadVersion: 1, definition: null,
    plan: plan(f.typeId, { sourceVersions: [1], edges: [{ relationId: edge.id, expectedVersion: 1, action: 'repair', values: values({}, requiredOwner ? ownerId : null) }] }) }] };
  return { f, ownerId, edge, change };
}

test('qualification uses a real non-bypass owner and restricted native runtime with forced RLS on every protected operation table', async () => {
  const { f } = await isolated(), c = await session(runtime, f);
  try {
    assert.equal((await c.query('SELECT current_user')).rows[0].current_user, 'gc_app');
    const role = (await owner.query('SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user')).rows[0]; assert.equal(role.rolsuper, false); assert.equal(role.rolbypassrls, false);
    const rows = (await c.query("SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity,r.rolname FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE c.relkind='r' AND (c.relname LIKE 'relation_graph_%' OR c.relname LIKE 'relation_participation%')")).rows;
    assert.ok(rows.length >= 15); for (const row of rows) { assert.ok(row.relrowsecurity && row.relforcerowsecurity); assert.notEqual(row.rolname, 'gc_app'); }
    const functions = ['gc_relation_graph_scope_tick(timestamptz,uuid)', 'gc_relation_graph_scope_eligible(uuid,uuid,jsonb,text,timestamptz)',
      'gc_relation_graph_scope_project(uuid,integer,text,integer,text,jsonb,timestamptz)', 'gc_relation_graph_capture_scope(uuid)',
      'gc_relation_graph_candidate_assets(uuid)', 'gc_relation_graph_candidate_types(uuid)'];
    for (const name of functions) assert.equal((await c.query("SELECT has_function_privilege(current_user,$1::regprocedure,'EXECUTE') AS permitted", [`public.${name}`])).rows[0].permitted, false, name);
    await assert.rejects(() => c.query('SELECT * FROM relation_graph_operations'), (e: any) => e.code === '42501');
  } finally { await c.query('ROLLBACK'); c.release(); }
});

test('independent SQL grammar normalization equals the pure parser while preserving operation and arbitrary user-array order', async () => {
  const { f, ownerId } = await isolated(), ids = [randomUUID(), randomUUID()].sort(), typeIds = [randomUUID(), randomUUID()].sort();
  const operations = [{ op: 'set', path: ['sequence'], value: ['z', 'a', 'z'], mode: 'replace' }, { op: 'set', path: ['sequence'], value: ['second', 'first'], mode: 'replace' }];
  const selectors = [...typeIds].reverse().map(typeId => ({ typeId, includeDescendants: false }));
  const target = (relationTypeId: string, modelId: string) => ({ kind: 'publish', expectedHeadVersion: 2,
    definition: { ...f.definition, formatVersion: 2, id: modelId, version: 3, sourceTypes: selectors, targetTypes: selectors, sourceStates: ['draft', 'active'], targetStates: ['draft', 'active'] },
    plan: plan(relationTypeId, { sourceVersions: [2, 1], edges: [...ids].reverse().map(relationId => ({ relationId, expectedVersion: 1, action: 'migrate' })),
      bindings: [...ids].reverse().map(bindingId => ({ bindingId, expectedVersion: 1, action: 'preserve' })),
      creations: ['z_creation', 'a_creation'].map(key => ({ key, sourceAssetId: ids[0]!, targetAssetId: ids[1]!, sourceAssetVersion: 1, targetAssetVersion: 1,
        values: { ...values({ ownerId: ['z', 'a'], allowedIdentityIds: ['not-an-identity', 'still-data'] }), visibility: 'restricted', allowedIdentityIds: [f.principal.id, ownerId] } })),
      acknowledgedPolicyChanges: ['required_owner_changed', 'cardinality_changed'], transform: {
        attributes: { formatVersion: 1, modelId, targetVersion: 3, sourceVersions: [1, 2], operations, acknowledgedChanges: [{ code: 'type_changed', path: '/attributes/z' }, { code: 'attribute_removed', path: '/attributes/a' }] },
        owner: { default: 'preserve', overrides: [...ids].reverse().map(relationId => ({ relationId, ownerId: null })) },
        lifecycle: { onUnmapped: 'preserve', mappings: [{ sourceVersion: 2, from: 'draft', to: 'active' }, { sourceVersion: 1, from: 'active', to: 'draft' }] } } } as any) });
  const raw = { ...emptyChange(), relationTargets: [...typeIds].reverse().map((id, index) => target(id, 'synthetic_norm_' + index)),
    assetChanges: [...ids].reverse().map(assetId => ({ kind: 'transition', assetId, expectedVersion: 1, state: 'active' })),
    assetTypeMigrations: ['z_nested', 'a_nested'].map(id => ({ expectedHeadVersion: 1,
      definition: { formatVersion: 1, id, version: 2, parents: [], attributes: {}, overrideAttributes: [], requiredOwner: false, lifecycle: f.definition.lifecycle },
      plan: { formatVersion: 1, typeId: randomUUID(), attributes: { formatVersion: 1, modelId: id, targetVersion: 2, sourceVersions: [1], operations, acknowledgedChanges: [] },
        owner: { default: 'preserve', overrides: [...ids].reverse().map(assetId => ({ assetId, ownerId: null })) },
        lifecycle: { onUnmapped: 'preserve', mappings: [{ sourceVersion: 1, from: 'draft', to: 'active' }, { sourceVersion: 1, from: 'active', to: 'draft' }] },
        acknowledgedPolicyChanges: ['required_owner_changed', 'lifecycle_changed'] } })) };
  const parsed = parseGraphChangeSet(raw); assert.ok(parsed.ok, JSON.stringify(parsed)); if (!parsed.ok) throw Error('Invalid normalization fixture');
  const c = await session(owner, f);
  try {
    const normalized = (await c.query('SELECT gc_relation_graph_normalize_change_set($1::jsonb) AS value', [JSON.stringify(raw)])).rows[0].value;
    assert.deepEqual(normalized, parsed.value);
    assert.deepEqual(normalized.relationTargets[0].plan.transform!.attributes.operations, operations);
    assert.deepEqual(normalized.relationTargets[0].plan.creations[0].values.attributes.ownerId, ['z', 'a']);
    const malformed = { ...raw, extra: true, assetChanges: [...raw.assetChanges, raw.assetChanges[0]] };
    const preserved = (await c.query('SELECT gc_relation_graph_normalize_change_set($1::jsonb) AS value', [JSON.stringify(malformed)])).rows[0].value;
    assert.equal(preserved.extra, true); assert.equal(preserved.assetChanges.length, 3); assert.equal(parseGraphChangeSet(preserved).ok, false);
  } finally { await c.query('ROLLBACK'); c.release(); }
});

test('membership revocation committed while begin waits for global identity is reread after the principal phase', async () => {
  const { f, change } = await isolated(), revoker = await session(owner, f), reader = await session(runtime, f);
  let pending: Promise<pg.QueryResult> | undefined;
  try {
    await revoker.query('SELECT id FROM identities WHERE id=$1 FOR UPDATE', [f.principal.id]);
    const rp = (await reader.query('SELECT pg_backend_pid() AS id')).rows[0].id, vp = (await revoker.query('SELECT pg_backend_pid() AS id')).rows[0].id;
    pending = reader.query('SELECT gc_relation_graph_begin($1,$2,$3,$4::jsonb,$5)', [randomUUID(), 'relation-migration.execute', randomUUID(), JSON.stringify(bodyFor(change)), correlation]);
    pending.catch(() => {}); await blocked(rp, vp);
    await revoker.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2', [f.principal.tenantId, f.principal.id]); await revoker.query('COMMIT');
    await assert.rejects(pending, (e: any) => e.code === '42501');
  } finally { await revoker.query('ROLLBACK'); await reader.query('ROLLBACK'); await pending?.catch(() => {}); revoker.release(); reader.release(); }
});

test('owner-injected source-history corruption is rejected before claiming even when false provenance matches the current snapshot base', async () => {
  for (const defect of ['endpoint', 'provenance', 'historical-model', 'historical-state', 'historical-state-array', 'historical-state-empty', 'historical-name'] as const) {
    const { f, edge, change } = await isolated();
    if (defect.startsWith('historical-')) await scope(f.principal.tenantId, f.principal.id, async tx => {
      const row = await tx.updateTable('assets').set({ version: 2, type_state: 'active', updated_at: new Date() }).where('id', '=', edge.source_asset_id).returningAll().executeTakeFirstOrThrow();
      await tx.insertInto('asset_revisions').values({ tenant_id: f.principal.tenantId, asset_id: row.id, version: 2, snapshot: JSON.stringify(assetView(row)) }).execute();
      await record(tx, f.principal, 'asset.type_transitioned', row.id, 2, {}, correlation);
    });
    const admin = await session(owner, f);
    try {
      // Deliberate corruption fixture under the non-bypass table owner, solely
      // in the disposable database; runtime retains every immutable guard.
      await admin.query('ALTER TABLE relation_revisions DISABLE TRIGGER USER');
      if (defect === 'endpoint') await admin.query("UPDATE relation_revisions SET snapshot=jsonb_set(snapshot,'{source,name}','\"Forged historic name\"') WHERE tenant_id=$1 AND relation_id=$2 AND version=1", [f.principal.tenantId, edge.id]);
      else if (defect === 'provenance') {
        await admin.query('ALTER TABLE relations DISABLE TRIGGER USER');
        await admin.query("UPDATE relations SET provenance=jsonb_set(provenance,'{authority}','\"forged-authority\"') WHERE tenant_id=$1 AND id=$2", [f.principal.tenantId, edge.id]);
        await admin.query("UPDATE relation_revisions SET snapshot=jsonb_set(snapshot,'{provenance,authority}','\"forged-authority\"') WHERE tenant_id=$1 AND relation_id=$2 AND version=1", [f.principal.tenantId, edge.id]);
        await admin.query('ALTER TABLE relations ENABLE TRIGGER USER');
      } else {
        // Corrupt matching old observations, leaving actual asset revision2 valid.
        // Historical authored pin/state/name checks must reject them independently.
        const field = defect === 'historical-model' ? 'modelVersion' : defect.startsWith('historical-state') ? 'typeState' : 'name';
        const endpointField = field === 'typeState' ? 'state' : field;
        const value = JSON.stringify(defect === 'historical-model' ? 999 : defect === 'historical-state' ? 'missing-state' :
          defect === 'historical-state-array' ? ['draft'] : defect === 'historical-state-empty' ? [] : 42);
        await admin.query('ALTER TABLE asset_revisions DISABLE TRIGGER USER');
        await admin.query('UPDATE asset_revisions SET snapshot=jsonb_set(snapshot,$3::text[],$4::jsonb) WHERE tenant_id=$1 AND asset_id=$2 AND version=1', [f.principal.tenantId, edge.source_asset_id, [field], value]);
        await admin.query('UPDATE relation_revisions SET snapshot=jsonb_set(snapshot,$3::text[],$4::jsonb) WHERE tenant_id=$1 AND relation_id=$2 AND version=1', [f.principal.tenantId, edge.id, ['source', endpointField], value]);
        await admin.query('ALTER TABLE asset_revisions ENABLE TRIGGER USER');
      }
      await admin.query('ALTER TABLE relation_revisions ENABLE TRIGGER USER'); await admin.query('COMMIT');
      await assert.rejects(() => execute(f, change), (error: any) => error.code === '23514' && error.message === 'Stored relation source is inconsistent');
      assert.deepEqual(await scope(f.principal.tenantId, f.principal.id, tx => tx.selectFrom('relation_graph_receipts').selectAll().execute()), []);
    } finally { await admin.query('ROLLBACK'); admin.release(); }
  }
});

test('one globally ordered principal phase locks lower owner identity before actor and locks complete asset union first', async () => {
  const { f, ownerId, change } = await isolated(true), blocker = await session(owner, f), reader = await session(runtime, f), observer = await session(owner, f);
  let pending: Promise<pg.QueryResult> | undefined;
  try {
    assert.ok(ownerId < f.principal.id); await blocker.query('SELECT id FROM identities WHERE id=$1 FOR UPDATE', [ownerId]);
    const rp = (await reader.query('SELECT pg_backend_pid() AS id')).rows[0].id, bp = (await blocker.query('SELECT pg_backend_pid() AS id')).rows[0].id;
    pending = reader.query('SELECT gc_relation_graph_begin($1,$2,$3,$4::jsonb,$5)', [randomUUID(), 'relation-migration.execute', randomUUID(), JSON.stringify(bodyFor(change)), correlation]); pending.catch(() => {});
    await blocked(rp, bp);
    // Actor identity remains unlocked while the lower owner is blocking.
    await observer.query('SELECT id FROM identities WHERE id=$1 FOR UPDATE NOWAIT', [f.principal.id]); await observer.query('ROLLBACK');
    await observer.query('BEGIN'); await observer.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)", [f.principal.tenantId, f.principal.id]);
    await assert.rejects(() => observer.query('SELECT id FROM assets WHERE id=$1 FOR UPDATE NOWAIT', [f.assets[1]!.id]), (e: any) => e.code === '55P03');
    await blocker.query('ROLLBACK'); await pending;
  } finally { await blocker.query('ROLLBACK'); await observer.query('ROLLBACK'); await reader.query('ROLLBACK'); await pending?.catch(() => {}); blocker.release(); observer.release(); reader.release(); }
});

test('a preheld asset row cannot deadlock with operation serialization and competing canonical DML fails fast', async () => {
  const { f, change } = await isolated(), a = await session(runtime, f), b = await session(runtime, f);
  try {
    await a.query('SELECT id FROM assets WHERE id=$1 FOR UPDATE', [f.assets[0]!.id]);
    await b.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [f.principal.tenantId]);
    await assert.rejects(() => a.query('SELECT gc_relation_graph_begin($1,$2,$3,$4::jsonb,$5)', [randomUUID(), 'relation-migration.execute', randomUUID(), JSON.stringify(bodyFor(change)), correlation]), (e: any) => e.code === '55P03');
    await a.query('ROLLBACK');
  } finally { await a.query('ROLLBACK'); await b.query('ROLLBACK'); a.release(); b.release(); }
});

test('SQL establishes its own remaining deadline before a competing canonical row lock even when caller timeouts are disabled', { timeout: 40000 }, async () => {
  const { f, change } = await isolated(), blocker = await session(owner, f), reader = await session(runtime, f);
  let pending: Promise<pg.QueryResult> | undefined;
  try {
    await blocker.query('SELECT id FROM assets WHERE id=$1 FOR UPDATE', [f.assets[0]!.id]);
    await reader.query("SET LOCAL lock_timeout='0'; SET LOCAL statement_timeout='0'");
    const rp = (await reader.query('SELECT pg_backend_pid() AS id')).rows[0].id, bp = (await blocker.query('SELECT pg_backend_pid() AS id')).rows[0].id;
    const started = Date.now();
    pending = reader.query('SELECT gc_relation_graph_begin($1,$2,$3,$4::jsonb,$5)', [randomUUID(), 'relation-migration.execute', randomUUID(), JSON.stringify(bodyFor(change)), correlation]); pending.catch(() => {});
    await blocked(rp, bp); await assert.rejects(pending, (error: any) => ['55P03', '57014'].includes(error.code));
    const elapsed = Date.now() - started; assert.ok(elapsed >= 25000 && elapsed < 35000, `Actual SQL-local deadline was ${elapsed} ms`);
    await reader.query('ROLLBACK');
    assert.deepEqual(await scope(f.principal.tenantId, f.principal.id, tx => tx.selectFrom('relation_graph_receipts').selectAll().execute()), []);
  } finally { await blocker.query('ROLLBACK'); await reader.query('ROLLBACK'); await pending?.catch(() => {}); blocker.release(); reader.release(); }
});

test('the operation window prevents a late eligible asset phantom and releases all locks after rollback', async () => {
  const { f, change } = await isolated(), held = await session(runtime, f), writer = await session(runtime, f); const id = randomUUID();
  try {
    await held.query('SELECT gc_relation_graph_begin($1,$2,$3,$4::jsonb,$5)', [randomUUID(), 'relation-migration.execute', randomUUID(), JSON.stringify(bodyFor(change)), correlation]);
    await assert.rejects(() => writer.query('INSERT INTO assets(tenant_id,id,external_id,name,qualified_name,type,model_id,model_version,type_state,attributes,observed_at) VALUES($1,$2::uuid,$2::text,$3,$2::text,$4,$5,1,$6,$7,now())',
      [f.principal.tenantId, id, 'Synthetic late participant', 'dataset', f.modelId, 'draft', '{}']), (e: any) => e.code === '55P03');
    await held.query('ROLLBACK'); await writer.query('ROLLBACK');
    const receipt = await execute(f, change); assert.equal(receipt.edgeOutcomes.length, 1);
  } finally { await held.query('ROLLBACK'); await writer.query('ROLLBACK'); held.release(); writer.release(); }
});

test('same-key concurrent execution waits and commits exactly one protected receipt with stable response', async () => {
  const { f, change } = await isolated(), ready = deferred(), release = deferred(), key = randomUUID(); let second: Promise<unknown> | undefined;
  const first = execute(f, change, { key, afterBegin: async () => { ready.resolve(); await release.promise; } });
  first.catch(() => {});
  try {
    await ready.promise; let finished = false;
    second = execute(f, change, { key }).then(value => { finished = true; return value; }); second.catch(() => {});
    await new Promise(resolve => setTimeout(resolve, 100)); assert.equal(finished, false); release.resolve();
    const [a, b] = await Promise.all([first, second]); assert.deepEqual(a, b);
    const rows = await scope(f.principal.tenantId, f.principal.id, tx => tx.selectFrom('relation_graph_receipts').selectAll().execute()); assert.equal(rows.length, 1);
  } finally { release.resolve(); await Promise.allSettled([first, ...(second ? [second] : [])]); }
});

test('inactive required relation owner can be explicitly tombstoned with exact historical owner and source issue preserved', async () => {
  const { f, ownerId, edge } = await isolated(true), admin = await session(owner, f);
  try { await admin.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2', [f.principal.tenantId, ownerId]); await admin.query('COMMIT'); }
  finally { await admin.query('ROLLBACK'); admin.release(); }
  const change: GraphChangeSet = { ...emptyChange(), relationTargets: [{ kind: 'repair', expectedHeadVersion: 1, definition: null,
    plan: plan(f.typeId, { sourceVersions: [1], edges: [{ relationId: edge.id, expectedVersion: 1, action: 'tombstone', reason: 'Synthetic inactive-owner forward repair' }] }) }] };
  const receipt = await execute(f, change); assert.deepEqual(receipt.sourceIssues, [{ kind: 'relation', issue: { code: 'source_required_owner_inactive', relationId: edge.id, ownerId } }]);
  const history = await scope(f.principal.tenantId, f.principal.id, tx => tx.selectFrom('relation_revisions').select('snapshot').where('relation_id', '=', edge.id).orderBy('version').execute());
  assert.deepEqual(history.map(r => r.snapshot.ownerId), [ownerId, ownerId]); assert.equal(history[1]!.snapshot.status, 'tombstoned');
});

test('actual principal activity cannot change until the graph operation finishes and failed transaction leaves no success', async () => {
  const { f, ownerId, change } = await isolated(true), held = await session(runtime, f), revoker = await session(owner, f); let pending: Promise<pg.QueryResult> | undefined;
  try {
    await held.query('SELECT gc_relation_graph_begin($1,$2,$3,$4::jsonb,$5)', [randomUUID(), 'relation-migration.execute', randomUUID(), JSON.stringify(bodyFor(change)), correlation]);
    const hp = (await held.query('SELECT pg_backend_pid() AS id')).rows[0].id, rp = (await revoker.query('SELECT pg_backend_pid() AS id')).rows[0].id;
    pending = revoker.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2', [f.principal.tenantId, ownerId]); pending.catch(() => {}); await blocked(rp, hp);
    await held.query('ROLLBACK'); await pending; await revoker.query('COMMIT');
    assert.deepEqual(await scope(f.principal.tenantId, f.principal.id, tx => tx.selectFrom('relation_graph_receipts').selectAll().execute()), []);
  } finally { await held.query('ROLLBACK'); await revoker.query('ROLLBACK'); await pending?.catch(() => {}); held.release(); revoker.release(); }
});

async function backgroundAssets(f: Fixture, untyped: number, typed = 0) {
  await scope(f.principal.tenantId, f.principal.id, async tx => {
    for (let offset = 0; offset < untyped + typed; offset += 100) {
      const input = Array.from({ length: Math.min(100, untyped + typed - offset) }, (_, index) => {
        const id = randomUUID(), authored = offset + index >= untyped;
        return { tenant_id: f.principal.tenantId, id, external_id: id, name: 'Synthetic scope background',
          qualified_name: `synthetic.scope.${id}`, type: 'dataset', observed_at: new Date(),
          model_id: authored ? f.modelId : null, model_version: authored ? 1 : null, type_state: authored ? 'draft' : null };
      });
      const rows = await tx.insertInto('assets').values(input).returningAll().execute();
      await tx.insertInto('asset_revisions').values(rows.map(row => ({ tenant_id: f.principal.tenantId, asset_id: row.id,
        version: row.version, snapshot: JSON.stringify(assetView(row)) }))).execute();
    }
  });
}

test('SQL010 captures an exact small graph once amid 3600 unrelated assets and 127 unrelated relation heads', async () => {
  const { f, change, edge } = await isolated();
  const background = await fixture({ principal: f.principal, count: 0, publish: false });
  await backgroundAssets(background, 3000, 600);
  // These are real canonical definitions under the runtime role. All have zero
  // minima and target only the background authored UUID, never the selected graph.
  for (let index = 0; index < 127; index += 1) {
    const other = { ...background, typeId: randomUUID(), definition: { ...background.definition, id: `scope_background_${index}_${randomUUID().replaceAll('-', '')}` } };
    await scope(f.principal.tenantId, f.principal.id, tx => writeDefinition(tx, other, other.definition, true));
  }
  const scale = await scope(f.principal.tenantId, f.principal.id, async tx => ({
    assets: Number((await tx.selectFrom('assets').select(sql<string>`count(*)::text`.as('n')).executeTakeFirstOrThrow()).n),
    types: Number((await tx.selectFrom('relation_types').select(sql<string>`count(*)::text`.as('n')).executeTakeFirstOrThrow()).n),
  }));
  assert.equal(scale.assets, 3602); assert.equal(scale.types, 128);
  const started = performance.now();
  const receipt = await execute(f, change);
  assert.ok(performance.now() - started < 30_000, 'The real complete operation must stay within its original deadline');
  assert.deepEqual(receipt.assetIdentities.map(row => row.assetId).sort(), f.assets.map(row => row.id).sort());
  assert.deepEqual(receipt.edgeOutcomes.map(row => row.after.id), [edge.id]);
  assert.equal(receipt.edgeOutcomes[0]!.after.version, 2);
  assert.deepEqual(receipt.bindingOutcomes, []);
});

test('SQL010 cooperative scan deadline interrupts direct begin with outer timeouts disabled during controlled expensive discovery', async () => {
  const { f, change } = await isolated(); await backgroundAssets(f, 500);
  const signature = 'public.gc_relation_graph_scope_eligible(uuid,uuid,jsonb,text,timestamp with time zone)';
  const original = (await owner.query('SELECT pg_get_functiondef($1::regprocedure) AS definition', [signature])).rows[0].definition as string;
  assert.ok(original.includes('PERFORM public.gc_relation_graph_scope_tick(started_at,asset);'));
  // Test-only isolated-owner instrumentation delays the real eligibility helper;
  // it retains both clock checks and all real policy/RLS queries. Always restored.
  await owner.query(original.replace('PERFORM public.gc_relation_graph_scope_tick(started_at,asset);',
    'PERFORM pg_sleep(0.02); PERFORM public.gc_relation_graph_scope_tick(started_at,asset);'));
  const reader = await session(runtime, f); let pending: Promise<pg.QueryResult> | undefined;
  let watchdog: ReturnType<typeof setTimeout> | undefined; let watchdogWork: Promise<unknown> | undefined;
  try {
    await reader.query("SET LOCAL statement_timeout=0; SET LOCAL lock_timeout=0");
    const pid = (await reader.query('SELECT pg_backend_pid() AS id')).rows[0].id;
    watchdog = setTimeout(() => { watchdogWork = runtime.query('SELECT pg_cancel_backend($1::integer)', [pid]); }, 36_000);
    const started = performance.now();
    pending = reader.query('SELECT gc_relation_graph_begin($1,$2,$3,$4::jsonb,$5)',
      [randomUUID(), 'relation-migration.execute', randomUUID(), JSON.stringify(bodyFor(change)), correlation]);
    await assert.rejects(pending, (error: any) => error.code === '57014' && error.message === 'Graph operation deadline exceeded');
    const elapsed = performance.now() - started;
    assert.ok(elapsed >= 29_000 && elapsed < 35_000, `Expected the original thirty-second SQL deadline; observed ${elapsed}ms`);
    assert.equal(watchdogWork, undefined, 'A watchdog cancellation must never be accepted as the SQL deadline');
  } finally {
    if (watchdog) clearTimeout(watchdog);
    await pending?.catch(() => {}); await watchdogWork; await reader.query('ROLLBACK'); reader.release();
    await owner.query(original);
    assert.equal((await owner.query('SELECT pg_get_functiondef($1::regprocedure) AS definition', [signature])).rows[0].definition, original);
  }
});

after(async () => { await db.destroy(); await owner.end(); await runtime.end(); });
