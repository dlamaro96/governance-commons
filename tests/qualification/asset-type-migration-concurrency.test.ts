// SPDX-License-Identifier: Apache-2.0
/** Requires a disposable database with SQL001–007. Never run against production. */
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { db, scope, sql, type Tx } from '../../packages/db/src/index.ts';
import { Problem, type Principal } from '../../packages/authz/src/index.ts';
import type { AssetTypeDefinition } from '../../packages/domain/src/asset-type.ts';
import { createAssetType } from '../../packages/domain/src/asset-type-service.ts';
import { assignAssetModel, type ModelHooks } from '../../packages/domain/src/model-service.ts';
import { executeTypeMigration, previewTypeMigration } from '../../packages/domain/src/asset-type-migration-service.ts';
import { assetView, record } from '../../apps/api/src/repository.ts';

if (!process.env.TYPE_MIGRATION_OWNER_DATABASE_URL || !process.env.DATABASE_URL) {
  throw new Error('Disposable qualification requires TYPE_MIGRATION_OWNER_DATABASE_URL and DATABASE_URL; no concurrency checks ran.');
}
const admin = new pg.Pool({ connectionString: process.env.TYPE_MIGRATION_OWNER_DATABASE_URL, max: 6 });
const hooks: ModelHooks = { record, assetSnapshot: assetView };
const permissions = ['models:read', 'models:write', 'catalog:read', 'catalog:write'];
function deferred<T = void>() { let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
const problem = (expected: string) => (error: unknown): boolean => error instanceof Problem && error.code === expected;
async function ownerSession(tenantId: string, actorId: string) {
  const client = await admin.connect();
  await client.query('BEGIN');
  await client.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)", [tenantId, actorId]);
  return client;
}
async function blocking(waiter: number, blocker: number) {
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    const result = await admin.query('SELECT $2::integer=ANY(pg_blocking_pids($1::integer)) AS blocked', [waiter, blocker]);
    if (result.rows[0].blocked) return;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  assert.fail('Expected PostgreSQL lock blocking was not observed within three seconds');
}
async function fixture(requiredOwner = false) {
  const tenantId = randomUUID(), foreignTenant = randomUUID(), actorId = randomUUID(), ownerId = randomUUID(), replacementId = randomUUID(), foreignId = randomUUID();
  const owner = await admin.connect();
  try {
    await owner.query('BEGIN');
    await owner.query('INSERT INTO tenants(id,name) VALUES($1,$2),($3,$4)', [tenantId, 'Synthetic concurrency tenant', foreignTenant, 'Synthetic foreign tenant']);
    for (const identity of [actorId, ownerId, replacementId, foreignId]) await owner.query(
      'INSERT INTO identities(id,issuer,subject,name) VALUES($1::uuid,$2,$1::text,$3)', [identity, 'synthetic-qualification', 'Synthetic concurrency principal']);
    for (const [organization, ids] of [[tenantId, [actorId, ownerId, replacementId]], [foreignTenant, [actorId, foreignId]]] as const) {
      await owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)", [organization, actorId]);
      for (const identity of ids) await owner.query('INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,$3,$4)',
        [organization, identity, 'synthetic-steward', JSON.stringify(permissions)]);
    }
    await owner.query('COMMIT');
  } catch (error) { await owner.query('ROLLBACK'); throw error; } finally { owner.release(); }
  const principal: Principal = { tenantId, id: actorId, name: 'Synthetic concurrency steward', permissions };
  const definition: AssetTypeDefinition = { formatVersion: 1, id: 'concurrent_' + randomUUID().replaceAll('-', ''), version: 1,
    parents: [], attributes: { value: { type: 'text' } }, overrideAttributes: [], requiredOwner,
    lifecycle: { initial: 'draft', states: ['draft', 'active'], transitions: [{ from: 'draft', to: 'active' }] } };
  const created = await scope(tenantId, actorId, tx => createAssetType(tx, principal, randomUUID(), definition, hooks));
  const assetId = randomUUID();
  await scope(tenantId, actorId, async tx => {
    const asset = await tx.insertInto('assets').values({ tenant_id: tenantId, id: assetId, external_id: assetId,
      name: 'Synthetic concurrency asset', qualified_name: `synthetic.concurrent.${assetId}`, type: 'dataset', owner_id: ownerId,
      observed_at: new Date() }).returningAll().executeTakeFirstOrThrow();
    await tx.insertInto('asset_revisions').values({ tenant_id: tenantId, asset_id: assetId, version: 1, snapshot: JSON.stringify(assetView(asset)) }).execute();
    await assignAssetModel(tx, principal, randomUUID(), assetId, 1, { modelId: definition.id, modelVersion: 1, attributes: { value: 'before' } }, hooks);
  });
  const request = { definition: { ...definition, version: 2 }, plan: { formatVersion: 1, typeId: created.type.typeId,
    attributes: { formatVersion: 1, modelId: definition.id, sourceVersions: [1], targetVersion: 2, acknowledgedChanges: [],
      operations: [{ op: 'set', path: ['value'], value: 'after', mode: 'replace' }] },
    owner: { default: 'preserve', overrides: [] as { assetId: string; ownerId: string | null }[] },
    lifecycle: { onUnmapped: 'preserve', mappings: [] }, acknowledgedPolicyChanges: [] } };
  const preview = await scope(tenantId, actorId, tx => previewTypeMigration(tx, principal, definition.id, 1, request));
  return { tenantId, foreignTenant, actorId, ownerId, replacementId, foreignId, principal, assetId, modelId: definition.id,
    request, execution: { ...request, previewDigest: preview.previewDigest } };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
const execute = (input: Fixture, tx: Tx, selectedHooks = hooks) => executeTypeMigration(tx, input.principal, randomUUID(), input.modelId, 1, input.execution, selectedHooks);
async function assertUnchanged(input: Fixture) {
  await scope(input.tenantId, input.actorId, async tx => {
    const head = await tx.selectFrom('governance_models').select('current_version').where('id', '=', input.modelId).executeTakeFirstOrThrow();
    assert.equal(head.current_version, 1);
    assert.deepEqual(await tx.selectFrom('asset_type_migrations').selectAll().where('model_id', '=', input.modelId).execute(), []);
    assert.equal((await tx.selectFrom('assets').select('model_version').where('id', '=', input.assetId).executeTakeFirstOrThrow()).model_version, 1);
  });
}

test('real migration holds global identity and scoped membership activity stable until commit', async () => {
  for (const table of ['identities', 'memberships'] as const) {
    const input = await fixture(), release = deferred(), reached = deferred<number>();
    const migration = scope(input.tenantId, input.actorId, async tx => {
      const pid = (await sql<{ pid: number }>`SELECT pg_backend_pid() AS pid`.execute(tx)).rows[0].pid;
      const result = await execute(input, tx); reached.resolve(pid); await release.promise; return result;
    });
    // Capture an early service failure without leaving a test hanging at its barrier.
    const migrationPid = await Promise.race([reached.promise, migration.then(() => { throw new Error('Migration unexpectedly left hold barrier'); })]);
    const writer = await ownerSession(input.tenantId, input.actorId);
    let updating: Promise<pg.QueryResult> | undefined;
    try {
      const writerPid = (await writer.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
      updating = table === 'identities'
        ? writer.query('UPDATE identities SET active=false WHERE id=$1', [input.ownerId])
        : writer.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2', [input.tenantId, input.ownerId]);
      await blocking(writerPid, migrationPid); release.resolve();
      const result = await migration; assert.equal(result.receipt.assets[0].after.ownerId, input.ownerId);
      assert.equal((await updating).rowCount, 1); await writer.query('COMMIT');
    } finally { release.resolve(); await migration.catch(() => {}); await updating?.catch(() => {}); await writer.query('ROLLBACK'); writer.release(); }
  }
});

test('revocation first forces fresh actor authorization after the migration waits on membership locks', async () => {
  const input = await fixture(), writer = await ownerSession(input.tenantId, input.actorId), started = deferred<number>();
  let operation: Promise<unknown> | undefined;
  try {
    const writerPid = (await writer.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
    await writer.query("UPDATE memberships SET permissions='[]'::jsonb WHERE tenant_id=$1 AND identity_id=$2", [input.tenantId, input.actorId]);
    operation = scope(input.tenantId, input.actorId, async tx => { started.resolve((await sql<{ pid: number }>`SELECT pg_backend_pid() AS pid`.execute(tx)).rows[0].pid); return execute(input, tx); });
    // Attach rejection before unblocking to avoid an unhandled rejection window.
    const rejected = assert.rejects(operation, problem('FORBIDDEN'));
    await blocking(await started.promise, writerPid); await writer.query('COMMIT'); await rejected;
    await assertUnchanged(input);
  } finally { await writer.query('ROLLBACK'); writer.release(); await operation?.catch(() => {}); }
});

test('owner revocation first changes the exact preview digest after the real migration lock wait', async () => {
  const input = await fixture(), writer = await ownerSession(input.tenantId, input.actorId), started = deferred<number>();
  let operation: Promise<unknown> | undefined;
  try {
    const writerPid = (await writer.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
    await writer.query('UPDATE identities SET active=false WHERE id=$1', [input.ownerId]);
    operation = scope(input.tenantId, input.actorId, async tx => { started.resolve((await sql<{ pid: number }>`SELECT pg_backend_pid() AS pid`.execute(tx)).rows[0].pid); return execute(input, tx); });
    const rejected = assert.rejects(operation, problem('ASSET_TYPE_MIGRATION_PREVIEW_STALE'));
    await blocking(await started.promise, writerPid); await writer.query('COMMIT'); await rejected; await assertUnchanged(input);
  } finally { await writer.query('ROLLBACK'); writer.release(); await operation?.catch(() => {}); }
});

test('principal locks omit foreign-only identities and the actor memberships in other tenants', async () => {
  const input = await fixture(), held = deferred(), release = deferred();
  const locking = scope(input.tenantId, input.actorId, async tx => {
    await sql`SELECT public.gc_lock_type_migration_principals(ARRAY[${input.foreignId}]::uuid[])`.execute(tx);
    held.resolve(); await release.promise;
  });
  await Promise.race([held.promise, locking.then(() => { throw new Error('Lock transaction left hold barrier'); })]);
  const writer = await ownerSession(input.foreignTenant, input.actorId);
  try {
    await writer.query("SET LOCAL lock_timeout='500ms'");
    assert.equal((await writer.query('UPDATE identities SET active=false WHERE id=$1', [input.foreignId])).rowCount, 1);
    assert.equal((await writer.query("UPDATE memberships SET permissions='[]' WHERE tenant_id=$1 AND identity_id=$2", [input.foreignTenant, input.actorId])).rowCount, 1);
    await writer.query('ROLLBACK');
  } finally { release.resolve(); await locking; await writer.query('ROLLBACK'); writer.release(); }
});

test('inactive required source owner can be explicitly repaired using a live scoped replacement', async () => {
  const input = await fixture(true), writer = await ownerSession(input.tenantId, input.actorId);
  try { await writer.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2', [input.tenantId, input.ownerId]); await writer.query('COMMIT'); }
  finally { await writer.query('ROLLBACK'); writer.release(); }
  input.request.plan.owner.overrides = [{ assetId: input.assetId, ownerId: input.replacementId }];
  const preview = await scope(input.tenantId, input.actorId, tx => previewTypeMigration(tx, input.principal, input.modelId, 1, input.request));
  assert.ok(preview.assets[0].sourceIssues.some(issue => issue.path === '/source/ownerId'));
  input.execution = { ...input.request, previewDigest: preview.previewDigest };
  const result = await scope(input.tenantId, input.actorId, tx => execute(input, tx));
  assert.equal(result.receipt.assets[0].before.ownerId, input.ownerId); assert.equal(result.receipt.assets[0].after.ownerId, input.replacementId);
});

test('late audited migration failure rolls back its changes and releases principal locks for the writer', async () => {
  const input = await fixture(), reached = deferred<number>(), release = deferred();
  const failing: ModelHooks = { ...hooks, record: async (tx, p, action, id, version, changes, correlation) => {
    await record(tx, p, action, id, version, changes, correlation);
    if (action === 'model.type_migrated') { reached.resolve((await sql<{ pid: number }>`SELECT pg_backend_pid() AS pid`.execute(tx)).rows[0].pid);
      await release.promise; throw new Error('Synthetic typed migration late rollback'); }
  } };
  const migration = scope(input.tenantId, input.actorId, tx => execute(input, tx, failing));
  const rejected = assert.rejects(migration, /Synthetic typed migration late rollback/);
  const migrationPid = await Promise.race([reached.promise, migration.then(() => { throw new Error('Expected injected failure point'); })]);
  const writer = await ownerSession(input.tenantId, input.actorId); let update: Promise<pg.QueryResult> | undefined;
  try {
    const writerPid = (await writer.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
    update = writer.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2', [input.tenantId, input.ownerId]);
    await blocking(writerPid, migrationPid); release.resolve(); await rejected; assert.equal((await update).rowCount, 1);
    await writer.query('ROLLBACK'); await assertUnchanged(input);
    const retried = await scope(input.tenantId, input.actorId, tx => execute(input, tx)); assert.equal(retried.receipt.assetCount, 1);
  } finally { release.resolve(); await rejected; await update?.catch(() => {}); await writer.query('ROLLBACK'); writer.release(); }
});

function amplifiedRequest(input: Fixture) {
  return { ...input.request,
    definition: { ...input.request.definition, attributes: { ...input.request.definition.attributes,
      samples: { type: 'list', items: { type: 'list', items: { type: 'number' } } } } },
    plan: { ...input.request.plan, attributes: { ...input.request.plan.attributes,
      operations: [...input.request.plan.attributes.operations,
        { op: 'set', path: ['samples'], value: Array.from({ length: 6 }, () => Array<number>(1000).fill(Number.MIN_VALUE)), mode: 'replace' }] } } };
}

test('real migration accepts bounded aggregate tiny numbers whose physical canonical plan exceeds one MiB', async () => {
  const input = await fixture(), request = amplifiedRequest(input);
  const sizes = await scope(input.tenantId, input.actorId, tx => sql<{ bytes: number }>`
    SELECT octet_length(${JSON.stringify(request.plan)}::jsonb::text) AS bytes`.execute(tx));
  assert.ok(sizes.rows[0].bytes > 1048576 && sizes.rows[0].bytes < 8388608);
  const preview = await scope(input.tenantId, input.actorId, tx => previewTypeMigration(tx, input.principal, input.modelId, 1, request));
  const result = await scope(input.tenantId, input.actorId, tx => executeTypeMigration(tx, input.principal, randomUUID(), input.modelId, 1,
    { ...request, previewDigest: preview.previewDigest }, hooks));
  assert.equal(result.receipt.assetCount, 1);
  assert.deepEqual(result.receipt.assets[0].after.attributes.samples, request.plan.attributes.operations.at(-1)!.value);
});

test('expanded typed receipt above eight MiB fails with a bounded 422 before preview or canonical writes', async () => {
  const input = await fixture(), request = amplifiedRequest(input), ids = [input.assetId];
  await scope(input.tenantId, input.actorId, async tx => {
    for (let index = 0; index < 5; index += 1) {
      const id = randomUUID(); ids.push(id);
      const asset = await tx.insertInto('assets').values({ tenant_id: input.tenantId, id, external_id: id,
        name: 'Synthetic expanded receipt asset', qualified_name: `synthetic.expanded.${id}`, type: 'dataset',
        owner_id: input.ownerId, observed_at: new Date() }).returningAll().executeTakeFirstOrThrow();
      await tx.insertInto('asset_revisions').values({ tenant_id: input.tenantId, asset_id: id, version: 1, snapshot: JSON.stringify(assetView(asset)) }).execute();
      await assignAssetModel(tx, input.principal, randomUUID(), id, 1, { modelId: input.modelId, modelVersion: 1, attributes: { value: 'before' } }, hooks);
    }
  });
  const samples = request.plan.attributes.operations.at(-1)!.value;
  const after = ids.map(() => ({ modelId: input.modelId, modelVersion: 2, attributes: { value: 'after', samples }, ownerId: input.ownerId, state: 'draft' }));
  const compact = JSON.stringify({ request, after });
  let nodes = 0; const pending: unknown[] = [JSON.parse(compact)];
  while (pending.length) { const value = pending.pop(); nodes += 1;
    if (value && typeof value === 'object') pending.push(...Object.values(value)); }
  assert.ok(Buffer.byteLength(compact) < 400000 && nodes < 50000,
    'Fixture must remain well inside logical512KiB/100k bounds so the physical guard is exercised');
  const expanded = await scope(input.tenantId, input.actorId, tx => sql<{ bytes: number }>`
    SELECT octet_length(${JSON.stringify(after)}::jsonb::text) AS bytes`.execute(tx));
  assert.ok(expanded.rows[0].bytes > 8388608, 'After-tuples alone must exceed the physical receipt bound');
  const limit = (error: unknown) => error instanceof Problem && error.status === 422 && error.code === 'ASSET_TYPE_MIGRATION_LIMIT';
  await assert.rejects(() => scope(input.tenantId, input.actorId, tx => previewTypeMigration(tx, input.principal, input.modelId, 1, request)), limit);
  await assert.rejects(() => scope(input.tenantId, input.actorId, tx => executeTypeMigration(tx, input.principal, randomUUID(), input.modelId, 1,
    { ...request, previewDigest: '0'.repeat(64) }, hooks)), limit);
  await assertUnchanged(input);
  await scope(input.tenantId, input.actorId, async tx => {
    const assets = await tx.selectFrom('assets').select(['model_version', 'attributes', 'version']).where('model_id', '=', input.modelId).execute();
    assert.equal(assets.length, 6);
    for (const asset of assets) { assert.equal(asset.model_version, 1); assert.equal(asset.version, 2); assert.deepEqual(asset.attributes, { value: 'before' }); }
    assert.equal((await tx.selectFrom('asset_type_versions').select('version').where('model_id', '=', input.modelId).execute()).length, 1);
    assert.deepEqual(await tx.selectFrom('governance_model_migrations').selectAll().where('model_id', '=', input.modelId).execute(), []);
  });
});

test('an owner-prepared auxiliary invoker trigger cannot forge nested typed normalized rows', async () => {
  const input = await fixture(), result = await scope(input.tenantId, input.actorId, tx => execute(input, tx));
  const stored = await scope(input.tenantId, input.actorId, tx => tx.selectFrom('asset_type_migration_assets').selectAll()
    .where('migration_id', '=', result.receipt.id).executeTakeFirstOrThrow());
  const suffix = randomUUID().replaceAll('-', ''), table = `synthetic_typed_probe_${suffix}`, fn = `synthetic_typed_probe_fn_${suffix}`;
  const writer = await admin.connect();
  try {
    await writer.query(`CREATE TABLE public.${table}(payload jsonb NOT NULL)`);
    await writer.query(`CREATE FUNCTION public.${fn}() RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$ BEGIN
      INSERT INTO public.asset_type_migration_assets SELECT (jsonb_populate_record(NULL::public.asset_type_migration_assets,NEW.payload)).*;
      RETURN NEW; END $$`);
    await writer.query(`CREATE TRIGGER synthetic_nested_probe AFTER INSERT ON public.${table} FOR EACH ROW EXECUTE FUNCTION public.${fn}()`);
    await writer.query(`GRANT INSERT ON public.${table} TO gc_app`);
    const forged = { ...stored, after_tuple: { ...stored.after_tuple, state: 'forged' } };
    await assert.rejects(() => scope(input.tenantId, input.actorId, tx => tx.insertInto(table).values({ payload: JSON.stringify(forged) }).execute()),
      (error: any) => error.code === '42501' && /immutable parent receipt/.test(error.message));
    assert.deepEqual(await scope(input.tenantId, input.actorId, tx => tx.selectFrom('asset_type_migration_assets').selectAll()
      .where('migration_id', '=', result.receipt.id).execute()), [stored]);
  } finally { await writer.query(`DROP TABLE IF EXISTS public.${table}`); await writer.query(`DROP FUNCTION IF EXISTS public.${fn}()`); writer.release(); }
});

after(async () => { await admin.end(); await db.destroy(); });
