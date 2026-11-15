// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { db, scope, sql, type Tx } from '../../packages/db/src/index.ts';
import { resolveAssetType, type AssetTypeDefinition } from '../../packages/domain/src/asset-type.ts';
import { assetView, stableString } from '../../apps/api/src/repository.ts';

const tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const foreignTenant = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const actor = '10000000-0000-4000-8000-000000000001';
const otherActor = '10000000-0000-4000-8000-000000000005';
const hash = (value: unknown) => createHash('sha256').update(stableString(value)).digest('hex');
const code = (expected: string) => (error: any): boolean => error.code === expected;
interface Fixture { base: Record<string, any>; typed: Record<string, any>; child: Record<string, any> }

/** Deliberate direct-runtime SQL tests, independently of the API/service validator. */
async function fixture(): Promise<Fixture> {
  const modelId = 'typed_receipt_' + randomUUID().replaceAll('-', ''), typeId = randomUUID();
  const assetId = randomUUID(), migrationId = randomUUID();
  const before = { modelId, modelVersion: 1, attributes: { value: 'before', quantity: 0.0000001 }, ownerId: actor, state: 'draft' };
  const after = { modelId, modelVersion: 2, attributes: { value: 'after', quantity: 1.25 }, ownerId: null, state: 'active' };
  const definitions = [1, 2].map(version => {
    const authored: AssetTypeDefinition = { formatVersion: 1, id: modelId, version, parents: [],
      attributes: { value: { type: 'text' }, quantity: { type: 'number' } }, overrideAttributes: [], requiredOwner: false,
      lifecycle: { initial: 'draft', states: ['draft', 'active'], transitions: [{ from: 'draft', to: 'active' }] } };
    const result = resolveAssetType(authored, []); assert.equal(result.ok, true);
    if (!result.ok) throw new Error('Invalid synthetic type'); return result.value;
  });
  await scope(tenant, actor, async tx => {
    await tx.insertInto('governance_models').values({ tenant_id: tenant, id: modelId, type_id: typeId, current_version: 2, created_by: actor }).execute();
    for (const resolved of definitions) {
      await tx.insertInto('governance_model_versions').values({ tenant_id: tenant, model_id: modelId, version: resolved.model.version,
        definition: JSON.stringify(resolved.model), definition_hash: hash(resolved.model), created_by: actor }).execute();
      await tx.insertInto('asset_type_versions').values({ tenant_id: tenant, model_id: modelId, version: resolved.model.version,
        definition: JSON.stringify(resolved.definition), definition_hash: hash(resolved.definition), resolved: JSON.stringify(resolved),
        resolution_hash: hash(resolved), created_by: actor }).execute();
    }
    const asset = await tx.insertInto('assets').values({ tenant_id: tenant, id: assetId, external_id: assetId,
      name: 'Synthetic full type receipt', qualified_name: `test.typed_receipt.${assetId}`, type: 'dataset', observed_at: new Date(),
      model_id: modelId, model_version: 2, type_state: after.state, owner_id: after.ownerId,
      attributes: JSON.stringify(after.attributes), version: 2 }).returningAll().executeTakeFirstOrThrow();
    for (const [index, tuple] of [before, after].entries()) {
      const snapshot = assetView({ ...asset, version: index + 1, model_version: tuple.modelVersion, attributes: tuple.attributes,
        owner_id: tuple.ownerId, type_state: tuple.state });
      await tx.insertInto('asset_revisions').values({ tenant_id: tenant, asset_id: assetId, version: index + 1, snapshot: JSON.stringify(snapshot) }).execute();
    }
  });
  const attributePlan = { formatVersion: 1, modelId, targetVersion: 2, sourceVersions: [1], acknowledgedChanges: [],
    operations: [{ op: 'set', path: ['value'], value: 'after', mode: 'replace' }, { op: 'set', path: ['quantity'], value: 1.25, mode: 'replace' }] };
  const plan = { formatVersion: 1, typeId, attributes: attributePlan, owner: { default: 'preserve', overrides: [{ assetId, ownerId: null }] },
    lifecycle: { onUnmapped: 'error', mappings: [{ sourceVersion: 1, from: 'draft', to: 'active' }] }, acknowledgedPolicyChanges: [] };
  const baseEntry = { assetId, fromAssetVersion: 1, toAssetVersion: 2, fromModelVersion: 1, toModelVersion: 2,
    beforeHash: hash(before.attributes), afterHash: hash(after.attributes) };
  const typedEntry = { ...baseEntry, before, after, beforeTupleHash: hash(before), afterTupleHash: hash(after) };
  const shared = { tenant_id: tenant, id: migrationId, model_id: modelId, from_version: 1, to_version: 2,
    preview_digest: hash('Synthetic typed storage preview'), asset_count: 1, executed_by: actor };
  return { base: { ...shared, plan: attributePlan, plan_hash: hash(attributePlan), assets: [baseEntry] },
    typed: { ...shared, type_id: typeId, plan, plan_hash: hash(plan), assets: [typedEntry],
      definition_hash: hash(definitions[1].definition), resolution_hash: hash(definitions[1]),
      source_resolutions: [{ version: 1, resolutionHash: hash(definitions[0]) }] },
    child: { tenant_id: tenant, migration_id: migrationId, asset_id: assetId, model_id: modelId, type_id: typeId,
      from_asset_version: 1, to_asset_version: 2, from_model_version: 1, to_model_version: 2,
      before_hash: baseEntry.beforeHash, after_hash: baseEntry.afterHash, before_tuple: before, after_tuple: after,
      before_tuple_hash: typedEntry.beforeTupleHash, after_tuple_hash: typedEntry.afterTupleHash } };
}
async function insertBase(tx: Tx, input: Fixture) {
  await tx.insertInto('governance_model_migrations').values({ ...input.base, plan: JSON.stringify(input.base.plan), assets: JSON.stringify(input.base.assets) }).execute();
}
async function insertTyped(tx: Tx, input: Fixture) {
  await tx.insertInto('asset_type_migrations').values({ ...input.typed, plan: JSON.stringify(input.typed.plan), assets: JSON.stringify(input.typed.assets),
    source_resolutions: JSON.stringify(input.typed.source_resolutions) }).execute();
}
async function insert(tx: Tx, input: Fixture) { await insertBase(tx, input); await insertTyped(tx, input); }
async function absent(input: Fixture) {
  await scope(tenant, actor, async tx => {
    for (const table of ['governance_model_migrations', 'governance_model_migration_assets', 'asset_type_migrations', 'asset_type_migration_assets']) {
      const field = table.endsWith('_assets') ? 'migration_id' : 'id';
      assert.deepEqual(await tx.selectFrom(table).selectAll().where(field, '=', input.base.id).execute(), [], `${table} rollback`);
    }
  });
}

test('typed receipt atomically derives exact full tuples and remains tenant-isolated and immutable', async () => {
  const input = await fixture(); await scope(tenant, actor, tx => insert(tx, input));
  const stored = await scope(tenant, actor, tx => tx.selectFrom('asset_type_migration_assets').selectAll().where('migration_id', '=', input.base.id).execute());
  assert.deepEqual(stored, [input.child]);
  for (const table of ['asset_type_migrations', 'asset_type_migration_assets']) {
    const field = table.endsWith('_assets') ? 'migration_id' : 'id';
    assert.deepEqual(await scope(foreignTenant, otherActor, tx => tx.selectFrom(table).selectAll().where(field, '=', input.base.id).execute()), []);
    await assert.rejects(() => scope(tenant, actor, tx => tx.updateTable(table).set({ model_id: input.base.model_id }).where(field, '=', input.base.id).execute()), code('42501'));
    await assert.rejects(() => scope(tenant, actor, tx => tx.deleteFrom(table).where(field, '=', input.base.id).execute()), code('42501'));
    await assert.rejects(() => scope(tenant, actor, tx => sql`TRUNCATE TABLE ${sql.table(table)}`.execute(tx)), code('42501'));
  }
  const metadata = await scope(tenant, actor, tx => sql<{ relname: string; relrowsecurity: boolean; relforcerowsecurity: boolean; owner: string }>`
    SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity,r.rolname AS owner FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner
    WHERE c.relname IN ('asset_type_migrations','asset_type_migration_assets')`.execute(tx));
  assert.equal(metadata.rows.length, 2);
  for (const row of metadata.rows) { assert.equal(row.relrowsecurity, true); assert.equal(row.relforcerowsecurity, true); assert.notEqual(row.owner, 'gc_app'); }
});

test('authored-type base receipts cannot commit without their complete typed companion', async () => {
  const input = await fixture(); let wroteBase = false;
  await assert.rejects(() => scope(tenant, actor, async tx => { await insertBase(tx, input); wroteBase = true; }), code('23514'));
  assert.equal(wroteBase, true); await absent(input);
});

test('typed receipt rejects wrong type, target/source hashes, base identity, digest, plan hashes and cohort shape', async () => {
  const input = await fixture();
  const mutations: ((value: Fixture) => void)[] = [
    value => { value.typed.type_id = randomUUID(); }, value => { value.typed.definition_hash = hash('forged'); },
    value => { value.typed.resolution_hash = hash('forged'); }, value => { value.typed.source_resolutions[0].resolutionHash = hash('forged'); },
    value => { value.typed.source_resolutions = []; }, value => { value.typed.source_resolutions.push(value.typed.source_resolutions[0]); },
    value => { value.typed.preview_digest = hash('other preview'); }, value => { value.typed.executed_by = '10000000-0000-4000-8000-000000000002'; },
    value => { value.typed.executed_at = new Date('2000-01-01T00:00:00Z'); }, value => { value.typed.plan_hash = hash('forged'); },
    value => { value.base.plan_hash = hash('forged'); }, value => { value.typed.plan.typeId = randomUUID(); value.typed.plan_hash = hash(value.typed.plan); },
    value => { value.typed.plan.extra = true; value.typed.plan_hash = hash(value.typed.plan); },
    value => { value.typed.plan.attributes.operations = []; value.typed.plan_hash = hash(value.typed.plan); },
    value => { value.typed.assets[0].extra = true; }, value => { value.typed.assets[0].afterHash = hash('forged'); },
    value => { value.typed.assets[0].beforeTupleHash = hash('forged'); }, value => { value.typed.assets = []; value.typed.asset_count = 0; },
  ];
  for (const mutate of mutations) {
    const forged = structuredClone(input); mutate(forged);
    await assert.rejects(() => scope(tenant, actor, tx => insert(tx, forged)), code('23514')); await absent(input);
  }
});

test('nested policy plans reject noncanonical UUIDs, malformed fields, duplicates, invalid pins and unknown acknowledgements', async () => {
  const input = await fixture();
  const mutations: ((plan: any) => void)[] = [
    plan => { plan.owner.overrides[0].assetId = randomUUID(); },
    plan => { plan.owner.overrides[0].ownerId = 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA'; },
    plan => { plan.owner.overrides[0].ownerId = 'not-a-uuid'; },
    plan => { plan.owner.overrides[0].ownerId = 42; },
    plan => { delete plan.owner.overrides[0].ownerId; },
    plan => { plan.owner.overrides[0].extra = true; },
    plan => { plan.owner.overrides.push(plan.owner.overrides[0]); },
    plan => { plan.lifecycle.mappings[0].sourceVersion = 2147483648; },
    plan => { plan.lifecycle.mappings[0].sourceVersion = 2; },
    plan => { plan.lifecycle.mappings[0].from = 'invalid state'; },
    plan => { plan.lifecycle.mappings[0].to = '__proto__'; },
    plan => { plan.lifecycle.mappings[0].from = null; },
    plan => { plan.lifecycle.mappings[0].extra = true; },
    plan => { plan.lifecycle.mappings.push(plan.lifecycle.mappings[0]); },
    plan => { plan.lifecycle.mappings = [{ sourceVersion: 1, from: 'draft', to: 'active' }, { sourceVersion: 1, from: 'active', to: 'draft' }]; },
    plan => { plan.acknowledgedPolicyChanges = ['unknown']; },
    plan => { plan.acknowledgedPolicyChanges = ['parents_changed', 'parents_changed']; },
    plan => { plan.acknowledgedPolicyChanges = ['required_owner_changed', 'lifecycle_changed']; },
  ];
  for (const mutate of mutations) {
    const forged = structuredClone(input); mutate(forged.typed.plan); forged.typed.plan_hash = hash(forged.typed.plan);
    await assert.rejects(() => scope(tenant, actor, tx => insert(tx, forged)), code('23514')); await absent(input);
  }
});

test('hash-consistent owner, state, attribute and pin forgeries fail against actual immutable revision snapshots', async () => {
  const input = await fixture();
  for (const side of ['before', 'after']) for (const field of ['ownerId', 'state', 'attributes', 'modelId', 'modelVersion']) {
    const forged = structuredClone(input), entry = forged.typed.assets[0];
    entry[side][field] = ({ ownerId: randomUUID(), state: 'forged', attributes: { value: 'forged' }, modelId: 'another_model', modelVersion: 9 } as any)[field];
    entry[side + 'TupleHash'] = hash(entry[side]);
    if (field === 'attributes') { entry[side + 'Hash'] = hash(entry[side].attributes); forged.base.assets[0][side + 'Hash'] = entry[side + 'Hash']; }
    await assert.rejects(() => scope(tenant, actor, tx => insert(tx, forged)), code('23514')); await absent(input);
  }
});

test('direct derived-row writes cannot exploit exact parent membership and late failures roll back both receipt layers', async () => {
  const input = await fixture(); await scope(tenant, actor, tx => insert(tx, input));
  await assert.rejects(() => scope(tenant, actor, tx => tx.insertInto('asset_type_migration_assets').values({ ...input.child,
    before_tuple: JSON.stringify(input.child.before_tuple), after_tuple: JSON.stringify(input.child.after_tuple) }).execute()), code('42501'));
  const late = await fixture();
  await assert.rejects(() => scope(tenant, actor, async tx => { await insert(tx, late); throw new Error('Synthetic late typed receipt rollback'); }), /Synthetic late typed receipt rollback/);
  await absent(late); await scope(tenant, actor, tx => insert(tx, late));
  assert.equal((await scope(tenant, actor, tx => tx.selectFrom('asset_type_migration_assets').selectAll().where('migration_id', '=', late.base.id).execute())).length, 1);
});

test('bounded canonical hash matches JS for supported numeric boundaries, nested data and Unicode string values', async () => {
  const values = [null, true, false, 0, 1, -1, 1.25, 1e-7, 1e-6, 1e20, 1e21, -1.2345e-20,
    Number.MIN_VALUE, Number.MAX_VALUE, Number.MAX_SAFE_INTEGER, 1.0000000000000002, 1000000000000000100,
    { z: ['Arabic العربية', 'emoji 😀', '\b\f\n\r\t"\\', '\u2028\u2029', 1.2e-6], a: { decimal: '12345678901234567890.123456789' } }];
  await scope(tenant, actor, async tx => {
    for (const value of values) {
      const actual = await sql<{ canonical: string; hash: string }>`SELECT public.gc_type_migration_canonical(${JSON.stringify(value)}::jsonb) AS canonical,
       public.gc_type_migration_hash(${JSON.stringify(value)}::jsonb) AS hash`.execute(tx);
      assert.equal(actual.rows[0].canonical, stableString(value)); assert.equal(actual.rows[0].hash, hash(value));
    }
  });
  await assert.rejects(() => scope(tenant, actor, tx => sql`SELECT public.gc_type_migration_hash('{"unsafe key":1}'::jsonb)`.execute(tx)), code('23514'));
});

test('canonical hashes preserve aggregated extreme numbers after JSONB expansion beyond one MiB', async () => {
  const value = { samples: Array.from({ length: 6 }, () => Array<number>(1000).fill(Number.MIN_VALUE)) };
  const compact = JSON.stringify(value);
  assert.ok(Buffer.byteLength(compact) < 524288);
  await scope(tenant, actor, async tx => {
    const actual = await sql<{ bytes: number; canonical: string; hash: string }>`
      SELECT octet_length(${compact}::jsonb::text) AS bytes,
       public.gc_type_migration_canonical(${compact}::jsonb) AS canonical,
       public.gc_type_migration_hash(${compact}::jsonb) AS hash`.execute(tx);
    assert.ok(actual.rows[0].bytes > 1048576 && actual.rows[0].bytes < 8388608,
      'The fixture must exercise physical JSONB expansion beyond the old helper cap');
    assert.equal(actual.rows[0].canonical, stableString(value)); assert.equal(actual.rows[0].hash, hash(value));
  });
});

test('principal lock function is narrowly owned, scoped, bounded and does not grant runtime identity writes', async () => {
  const result = await scope(tenant, actor, tx => sql<{ security_definer: boolean; volatile: string; parallel: string; config: string[];
    superuser: boolean; bypass: boolean; role_member: boolean; public_execute: boolean; app_execute: boolean }>`
    SELECT p.prosecdef AS security_definer,p.provolatile AS volatile,p.proparallel AS parallel,p.proconfig AS config,
     r.rolsuper AS superuser,r.rolbypassrls AS bypass,pg_has_role(current_user,r.oid,'MEMBER') AS role_member,
     EXISTS(SELECT 1 FROM aclexplode(p.proacl) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute,
     has_function_privilege(current_user,p.oid,'EXECUTE') AS app_execute
    FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.oid='public.gc_lock_type_migration_principals(uuid[])'::regprocedure`.execute(tx));
  assert.equal(result.rows.length, 1);
  const config = result.rows[0]; assert.equal(config.security_definer, true); assert.equal(config.volatile, 'v'); assert.equal(config.parallel, 'u');
  assert.equal(config.superuser, false); assert.equal(config.bypass, false); assert.equal(config.role_member, false);
  assert.equal(config.public_execute, false); assert.equal(config.app_execute, true);
  assert.ok(config.config.includes('search_path=pg_catalog, pg_temp')); assert.ok(config.config.includes('row_security=on'));
  for (const expression of [sql`NULL::uuid[]`, sql`ARRAY[NULL]::uuid[]`, sql`ARRAY[ARRAY[${actor}::uuid]]`,
    sql`array_fill(${actor}::uuid,ARRAY[2002])`]) {
    await assert.rejects(() => scope(tenant, actor, tx => sql`SELECT public.gc_lock_type_migration_principals(${expression})`.execute(tx)), code('22023'));
  }
  await scope(tenant, actor, async tx => { await sql`SELECT public.gc_lock_type_migration_principals('{}'::uuid[])`.execute(tx);
    await sql`SELECT public.gc_lock_type_migration_principals(ARRAY[${actor},${actor}]::uuid[])`.execute(tx); });
  await assert.rejects(() => scope(tenant, randomUUID(), tx => sql`SELECT public.gc_lock_type_migration_principals('{}'::uuid[])`.execute(tx)), code('42501'));
  await assert.rejects(() => scope(tenant, actor, tx => tx.updateTable('identities').set({ active: false }).where('id', '=', actor).execute()), code('42501'));
  await assert.rejects(() => scope(tenant, actor, tx => tx.updateTable('memberships').set({ active: false }).where('identity_id', '=', actor).execute()), code('42501'));
});

after(async () => { await db.destroy(); });
