// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { db, scope, type Tx } from '../../packages/db/src/index.ts';
import { resolveAssetType, type AssetTypeDefinition, type ResolvedAssetType } from '../../packages/domain/src/asset-type.ts';
import { assetView, stableString } from '../../apps/api/src/repository.ts';

const tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const steward = '10000000-0000-4000-8000-000000000001';
const key = () => 'storage_type_' + randomUUID().replaceAll('-', '');
const hash = (value: unknown) => createHash('sha256').update(stableString(value)).digest('hex');

function definition(changes: Partial<AssetTypeDefinition> = {}): AssetTypeDefinition {
  return { formatVersion: 1, id: key(), version: 1, parents: [], attributes: {}, overrideAttributes: [], requiredOwner: false,
    lifecycle: { initial: 'draft', states: ['draft', 'active'], transitions: [{ from: 'draft', to: 'active' }] }, ...changes };
}
function resolve(input: AssetTypeDefinition, parents: AssetTypeDefinition[] = []): ResolvedAssetType {
  const result = resolveAssetType(input, parents);
  assert.equal(result.ok, true, 'The unmodified synthetic type must satisfy the actual pure resolver');
  if (!result.ok) throw new Error('Invalid synthetic storage fixture');
  return structuredClone(result.value);
}

/** These helpers deliberately bypass services to exercise the runtime SQL role's
 * storage boundary. Hashes always match the submitted bytes, including forgeries. */
async function insertFlat(tx: Tx, resolved: ResolvedAssetType): Promise<void> {
  await tx.insertInto('governance_models').values({ tenant_id: tenant, id: resolved.model.id,
    current_version: resolved.model.version, type_id: randomUUID(), created_by: steward }).execute();
  await tx.insertInto('governance_model_versions').values({ tenant_id: tenant, model_id: resolved.model.id,
    version: resolved.model.version, definition: JSON.stringify(resolved.model), definition_hash: hash(resolved.model), created_by: steward }).execute();
}
function policyValues(resolved: ResolvedAssetType) {
  return { tenant_id: tenant, model_id: resolved.model.id, version: resolved.model.version,
    definition: JSON.stringify(resolved.definition), definition_hash: hash(resolved.definition), resolved: JSON.stringify(resolved),
    resolution_hash: hash(resolved), created_by: steward };
}
async function insertPolicy(tx: Tx, resolved: ResolvedAssetType): Promise<void> {
  await tx.insertInto('asset_type_versions').values(policyValues(resolved)).execute();
}
async function insertType(tx: Tx, resolved: ResolvedAssetType): Promise<void> {
  await insertFlat(tx, resolved); await insertPolicy(tx, resolved);
}
const persist = (input: AssetTypeDefinition, parents: AssetTypeDefinition[] = []) =>
  scope(tenant, steward, tx => insertType(tx, resolve(input, parents)));
const checkViolation = (message: RegExp) => (error: unknown): boolean => {
  const failure = error as { code?: string; message?: string };
  return failure.code === '23514' && typeof failure.message === 'string' && message.test(failure.message);
};
async function assertAbsent(modelId: string): Promise<void> {
  const actual = await scope(tenant, steward, async tx => ({
    heads: await tx.selectFrom('governance_models').select('id').where('id', '=', modelId).execute(),
    models: await tx.selectFrom('governance_model_versions').select('model_id').where('model_id', '=', modelId).execute(),
    policies: await tx.selectFrom('asset_type_versions').select('model_id').where('model_id', '=', modelId).execute(),
    dependencies: await tx.selectFrom('asset_type_dependencies').select('model_id').where('model_id', '=', modelId).execute(),
  }));
  assert.deepEqual(actual, { heads: [], models: [], policies: [], dependencies: [] });
}
async function rejectedPolicy(resolved: ResolvedAssetType, message: RegExp): Promise<void> {
  await assert.rejects(() => scope(tenant, steward, tx => insertType(tx, resolved)), checkViolation(message));
  await assertAbsent(resolved.model.id);
}

test('PostgreSQL rejects JSON-null authored identity fields with otherwise consistent hashes and flat models', async () => {
  for (const field of ['formatVersion', 'id', 'version'] as const) {
    const resolved = resolve(definition());
    // JSON null must fail a CHECK rather than turning equality into SQL UNKNOWN.
    Object.assign(resolved.definition, { [field]: null });
    await rejectedPolicy(resolved, /asset_type_versions.*check constraint|check constraint.*asset_type_versions/);
  }
});

test('PostgreSQL rejects a resolution that omits its directly authored parent dependency', async () => {
  const parent = definition(); await persist(parent);
  const child = definition({ parents: [{ id: parent.id, version: 1 }], lifecycle: null });
  const forged = { ...resolve(child, [parent]), dependencies: [] };
  await rejectedPolicy(forged, /complete authored parent closure/);
});

test('PostgreSQL rejects a resolution that lists its parent but omits the transitive ancestor', async () => {
  const ancestor = definition(); await persist(ancestor);
  const parent = definition({ parents: [{ id: ancestor.id, version: 1 }], lifecycle: null }); await persist(parent, [ancestor]);
  const child = definition({ parents: [{ id: parent.id, version: 1 }], lifecycle: null });
  const forged = { ...resolve(child, [parent, ancestor]), dependencies: [{ id: parent.id, version: 1 }] };
  await rejectedPolicy(forged, /complete authored parent closure/);
});

test('PostgreSQL rejects weakening the authored type own required-owner policy', async () => {
  const forged = { ...resolve(definition({ requiredOwner: true })), requiredOwner: false };
  await rejectedPolicy(forged, /ownership must retain every required parent owner/);
});

test('PostgreSQL rejects weakening a required-owner policy inherited from an exact parent pin', async () => {
  const parent = definition({ requiredOwner: true }); await persist(parent);
  const child = definition({ parents: [{ id: parent.id, version: 1 }], lifecycle: null });
  const resolved = resolve(child, [parent]); assert.equal(resolved.requiredOwner, true);
  const forged = { ...resolved, requiredOwner: false };
  await rejectedPolicy(forged, /ownership must retain every required parent owner/);
});

test('PostgreSQL refuses insert and update assignments before the authored policy exists in the same transaction', async () => {
  for (const operation of ['insert', 'update'] as const) {
    const resolved = resolve(definition()), assetId = randomUUID();
    const fixture = { tenant_id: tenant, id: assetId, external_id: assetId, name: 'Synthetic missing-policy storage fixture',
      qualified_name: `test.asset_type_storage.${assetId}`, type: 'dataset', observed_at: new Date(), owner_id: steward };
    if (operation === 'update') await scope(tenant, steward, async tx => {
      const row = await tx.insertInto('assets').values(fixture).returningAll().executeTakeFirstOrThrow();
      await tx.insertInto('asset_revisions').values({ tenant_id: tenant, asset_id: assetId, version: row.version,
        snapshot: JSON.stringify(assetView(row)) }).execute();
    });
    const before = await scope(tenant, steward, tx => tx.selectFrom('assets').selectAll().where('id', '=', assetId).execute());
    let reachedAssignment = false, assignmentSucceeded = false;
    await assert.rejects(() => scope(tenant, steward, async tx => {
      await insertFlat(tx, resolved);
      reachedAssignment = true;
      const binding = { model_id: resolved.model.id, model_version: 1, attributes: '{}', type_state: 'draft' };
      if (operation === 'insert') await tx.insertInto('assets').values({ ...fixture, ...binding }).execute();
      else await tx.updateTable('assets').set(binding).where('id', '=', assetId).execute();
      assignmentSucceeded = true;
      // If assignment were incorrectly allowed, this would satisfy the deferred
      // completeness check. The test therefore isolates the immediate asset guard.
      await insertPolicy(tx, resolved);
    }), checkViolation(/Authored asset constraints must exist before assignment/));
    assert.equal(reachedAssignment, true); assert.equal(assignmentSucceeded, false);
    await assertAbsent(resolved.model.id);
    const after = await scope(tenant, steward, tx => tx.selectFrom('assets').selectAll().where('id', '=', assetId).execute());
    assert.deepEqual(after, before);
  }
});

test('PostgreSQL deferred completeness check rejects a typed model version committed without its authored policy', async () => {
  const resolved = resolve(definition()); let flatWriteSucceeded = false;
  await assert.rejects(() => scope(tenant, steward, async tx => {
    await insertFlat(tx, resolved); flatWriteSucceeded = true;
  }), checkViolation(/Authored asset types require a matching immutable resolved version/));
  assert.equal(flatWriteSucceeded, true, 'The failure must occur at deferred transaction completion');
  await assertAbsent(resolved.model.id);
});

test('PostgreSQL accepts a complete diamond closure and derives one exact normalized row per ancestor', async () => {
  const ancestor = definition({ requiredOwner: true });
  const left = definition({ parents: [{ id: ancestor.id, version: 1 }], lifecycle: null });
  const right = definition({ parents: [{ id: ancestor.id, version: 1 }], lifecycle: null });
  const child = definition({ parents: [{ id: left.id, version: 1 }, { id: right.id, version: 1 }], lifecycle: null });
  const resolved = resolve(child, [left, right, ancestor]);
  await scope(tenant, steward, async tx => {
    await insertType(tx, resolve(ancestor));
    await insertType(tx, resolve(left, [ancestor]));
    await insertType(tx, resolve(right, [ancestor]));
    await insertType(tx, resolved);
  });
  const stored = await scope(tenant, steward, async tx => ({
    type: await tx.selectFrom('asset_type_versions').selectAll().where('model_id', '=', child.id).executeTakeFirstOrThrow(),
    dependencies: await tx.selectFrom('asset_type_dependencies').select(['dependency_model_id', 'dependency_version'])
      .where('model_id', '=', child.id).orderBy('dependency_model_id').execute(),
  }));
  assert.equal(stored.type.definition_hash, hash(child)); assert.equal(stored.type.resolution_hash, hash(resolved));
  assert.deepEqual(stored.type.resolved, resolved); assert.equal(stored.type.resolved.requiredOwner, true);
  assert.deepEqual(stored.dependencies, [ancestor, left, right].map(item => ({ dependency_model_id: item.id, dependency_version: 1 }))
    .sort((a, b) => a.dependency_model_id.localeCompare(b.dependency_model_id)));
  assert.equal(stored.dependencies.length, 3);
});

test('same-statement parent and child inserts cannot omit an ancestor before dependency projection triggers run', async () => {
  const ancestor = definition(); await persist(ancestor);
  const parent = definition({ parents: [{ id: ancestor.id, version: 1 }], lifecycle: null });
  const child = definition({ parents: [{ id: parent.id, version: 1 }], lifecycle: null });
  const parentResolved = resolve(parent, [ancestor]), childResolved = resolve(child, [parent, ancestor]);
  const forged = { ...childResolved, dependencies: [{ id: parent.id, version: 1 }] };
  const writePair = (childPolicy: ResolvedAssetType) => scope(tenant, steward, async tx => {
    await insertFlat(tx, parentResolved); await insertFlat(tx, childResolved);
    // Parent BEFORE/row insertion occurs before child BEFORE, while the parent's
    // AFTER-row normalized projection is not a safe source for closure validation.
    await tx.insertInto('asset_type_versions').values([policyValues(parentResolved), policyValues(childPolicy)]).execute();
  });
  await assert.rejects(() => writePair(forged), checkViolation(/complete authored parent closure/));
  await assertAbsent(parent.id); await assertAbsent(child.id);
  await writePair(childResolved);
  const dependencies = await scope(tenant, steward, tx => tx.selectFrom('asset_type_dependencies')
    .select(['dependency_model_id', 'dependency_version']).where('model_id', '=', child.id).orderBy('dependency_model_id').execute());
  assert.deepEqual(dependencies, [ancestor, parent].map(item => ({ dependency_model_id: item.id, dependency_version: 1 }))
    .sort((a, b) => a.dependency_model_id.localeCompare(b.dependency_model_id)));
});

after(async () => { await db.destroy(); });
