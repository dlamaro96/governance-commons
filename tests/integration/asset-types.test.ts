// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { db, scope, sql } from '../../packages/db/src/index.ts';
import { Problem, type Principal } from '../../packages/authz/src/index.ts';
import { resolveAssetType, type AssetTypeDefinition } from '../../packages/domain/src/asset-type.ts';
import {
  createAssetType, getAssetType, previewAssetType, publishAssetType,
  getAssetTypeState, transitionAssetTypeState,
} from '../../packages/domain/src/asset-type-service.ts';
import { assignAssetModel, getAssetModel, type ModelHooks } from '../../packages/domain/src/model-service.ts';
import { assetView, record, stableString } from '../../apps/api/src/repository.ts';

const tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const otherTenant = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const steward = '10000000-0000-4000-8000-000000000001';
const owner = '10000000-0000-4000-8000-000000000002';
const consumer = '10000000-0000-4000-8000-000000000003';
const summit = '10000000-0000-4000-8000-000000000005';
const principal: Principal = { id: steward, name: 'Synthetic inherited-type steward', tenantId: tenant,
  permissions: ['models:read', 'models:write', 'catalog:read', 'catalog:write'] };
const hooks: ModelHooks = { record, assetSnapshot: assetView };
const base = process.env.TEST_BASE_URL ?? 'http://api:4310';
const origin = process.env.PUBLIC_URL ?? 'http://localhost:4310';
const amount = '90071992547409931234567890.000000001';
const id = () => 'type_test_' + randomUUID().replaceAll('-', '');
const hash = (value: unknown) => createHash('sha256').update(stableString(value)).digest('hex');
const problem = (code: string, status?: number) => (error: unknown) =>
  error instanceof Problem && error.code === code && (status === undefined || error.status === status);

function definition(changes: Partial<AssetTypeDefinition> = {}): AssetTypeDefinition {
  return { formatVersion: 1, id: id(), version: 1, parents: [],
    attributes: { amount: { type: 'decimal', required: true } }, overrideAttributes: [], requiredOwner: false,
    lifecycle: { initial: 'draft', states: ['draft', 'active', 'retired'],
      transitions: [{ from: 'draft', to: 'active' }, { from: 'active', to: 'retired' }] }, ...changes };
}
const create = (input: AssetTypeDefinition, p = principal) =>
  scope(p.tenantId, p.id, tx => createAssetType(tx, p, randomUUID(), input, hooks));
const read = (modelId: string, version?: number) => scope(tenant, steward, tx => getAssetType(tx, principal, modelId, version));
const preview = (input: AssetTypeDefinition) =>
  scope(tenant, steward, tx => previewAssetType(tx, principal, input.id, input.version - 1, input));
async function publish(input: AssetTypeDefinition) {
  const check = await preview(input);
  return scope(tenant, steward, tx => publishAssetType(tx, principal, randomUUID(), input.id, input.version - 1, input, check.previewDigest, hooks));
}
async function session(actor = steward, organization = tenant) {
  const token = randomUUID() + randomUUID(), csrf = randomUUID();
  await db.insertInto('sessions').values({ id_hash: createHash('sha256').update(token).digest('hex'), identity_id: actor,
    tenant_id: organization, csrf, expires_at: new Date(Date.now() + 120_000) }).execute();
  return { Cookie: `gc_session=${token}`, 'X-CSRF-Token': csrf, Origin: origin, 'Content-Type': 'application/json' };
}
const request = (path: string, headers: Record<string, string>, method = 'GET', body?: unknown) =>
  fetch(base + '/api/v1' + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
const mutation = (headers: Record<string, string>, version = 1) =>
  ({ ...headers, 'If-Match': String(version), 'Idempotency-Key': randomUUID() });

/** Direct SQL supplies a synthetic untyped asset and its real initial revision only. */
async function fixtureAsset(ownerId: string | null = steward): Promise<string> {
  const assetId = randomUUID();
  await scope(tenant, steward, async tx => {
    const row = await tx.insertInto('assets').values({ tenant_id: tenant, id: assetId, external_id: assetId,
      name: `Synthetic inherited-type fixture ${assetId}`, qualified_name: `test.asset_type.${assetId}`,
      type: 'dataset', observed_at: new Date(), owner_id: ownerId }).returningAll().executeTakeFirstOrThrow();
    await tx.insertInto('asset_revisions').values({ tenant_id: tenant, asset_id: assetId, version: row.version,
      snapshot: JSON.stringify(assetView(row)) }).execute();
  });
  return assetId;
}
const assign = (assetId: string, modelId: string, modelVersion = 1, expectedAssetVersion = 1) =>
  scope(tenant, steward, tx => assignAssetModel(tx, principal, randomUUID(), assetId, expectedAssetVersion,
    { modelId, modelVersion, attributes: { amount } }, hooks));
const state = (assetId: string) => scope(tenant, steward, tx => getAssetTypeState(tx, principal, assetId));
async function typeSnapshot(modelId: string) {
  return scope(tenant, steward, async tx => ({
    heads: await tx.selectFrom('governance_models').selectAll().where('id', '=', modelId).execute(),
    models: await tx.selectFrom('governance_model_versions').selectAll().where('model_id', '=', modelId).orderBy('version').execute(),
    types: await tx.selectFrom('asset_type_versions').selectAll().where('model_id', '=', modelId).orderBy('version').execute(),
    dependencies: await tx.selectFrom('asset_type_dependencies').selectAll().where('model_id', '=', modelId)
      .orderBy('version').orderBy('dependency_model_id').orderBy('dependency_version').execute(),
    audit: await tx.selectFrom('audit').selectAll().where('resource_id', '=', modelId).orderBy('sequence').execute(),
    outbox: await tx.selectFrom('outbox').select(['id', 'event_type', 'resource_version', 'payload'])
      .where('resource_id', '=', modelId).orderBy('id').execute(),
  }));
}
async function assetSnapshot(assetId: string) {
  return scope(tenant, steward, async tx => ({
    asset: await tx.selectFrom('assets').selectAll().where('id', '=', assetId).executeTakeFirstOrThrow(),
    revisions: await tx.selectFrom('asset_revisions').selectAll().where('asset_id', '=', assetId).orderBy('version').execute(),
    audit: await tx.selectFrom('audit').selectAll().where('resource_id', '=', assetId).orderBy('sequence').execute(),
    outbox: await tx.selectFrom('outbox').select(['id', 'event_type', 'resource_version', 'payload'])
      .where('resource_id', '=', assetId).orderBy('id').execute(),
  }));
}

test('exact parent pins preserve child and asset behavior until an explicit compatible child upgrade', async () => {
  const parent = definition({ requiredOwner: true }); await create(parent);
  const child = definition({ parents: [{ id: parent.id, version: 1 }], attributes: { note: { type: 'text' } }, lifecycle: null });
  const original = (await create(child)).type;
  assert.match(original.typeId, /^[a-f0-9-]{36}$/i);
  assert.equal(original.resolved.requiredOwner, true);
  assert.deepEqual(original.resolved.dependencies, [{ id: parent.id, version: 1 }]);
  const assetId = await fixtureAsset(); await assign(assetId, child.id);
  await scope(tenant, steward, tx => transitionAssetTypeState(tx, principal, randomUUID(), assetId, 2, 'active', hooks));
  const nextParent: AssetTypeDefinition = { ...parent, version: 2,
    attributes: { ...parent.attributes, category: { type: 'text' } },
    lifecycle: { initial: 'draft', states: ['draft', 'active', 'retired', 'archived'],
      transitions: [...parent.lifecycle!.transitions, { from: 'retired', to: 'archived' }] } };
  await publish(nextParent);
  const unchanged = (await read(child.id)).type;
  assert.equal(unchanged.resolutionHash, original.resolutionHash);
  assert.deepEqual(unchanged.resolved.dependencies, original.resolved.dependencies);
  assert.equal('category' in unchanged.resolved.model.attributes, false);
  assert.equal((await state(assetId)).lifecycle!.states.includes('archived'), false);
  const nextChild: AssetTypeDefinition = { ...child, version: 2, parents: [{ id: parent.id, version: 2 }] };
  const check = await preview(nextChild);
  assert.equal(check.assetCount, 1); assert.equal(check.coverage, 'complete-tenant-model-bindings');
  assert.equal(check.compatibleWithProvidedAssets, true); assert.equal(check.requiresExplicitMigration, false); assert.equal(check.pinsPreserved, true);
  const updated = (await publish(nextChild)).type;
  assert.equal(updated.typeId, original.typeId); assert.notEqual(updated.resolutionHash, original.resolutionHash);
  assert.deepEqual(updated.resolved.dependencies, [{ id: parent.id, version: 2 }]);
  assert.equal('category' in updated.resolved.model.attributes, true);
  assert.equal((await state(assetId)).modelVersion, 1);
  await assign(assetId, child.id, 2, 3);
  const repinned = await state(assetId);
  assert.equal(repinned.modelVersion, 2); assert.equal(repinned.state, 'active'); assert.equal(repinned.requiredOwner, true);
  assert.equal(repinned.lifecycle!.states.includes('archived'), true);
  assert.equal((await scope(tenant, steward, tx => getAssetModel(tx, principal, assetId))).attributes.amount, amount);
  assert.equal((await read(child.id, 1)).type.resolutionHash, original.resolutionHash);
  const persisted = await typeSnapshot(child.id);
  assert.equal(persisted.models.length, 2); assert.equal(persisted.types.length, 2); assert.equal(persisted.dependencies.length, 2);
  for (const entry of persisted.audit) assert.equal(entry.hash, hash(entry.envelope));
});

test('inherited owner and lifecycle constraints apply to assignment, ordinary owner edits and replayed HTTP transitions', async () => {
  const parent = definition({ requiredOwner: true }); await create(parent);
  const child = definition({ parents: [{ id: parent.id, version: 1 }], attributes: {}, lifecycle: null }); await create(child);
  const headers = await session(), assetId = await fixtureAsset(null), path = '/assets/' + assetId;
  const body = { modelId: child.id, modelVersion: 1, attributes: { amount } };
  const denied = await request(path + '/attributes', mutation(headers), 'PUT', body);
  assert.equal(denied.status, 422); assert.equal((await denied.json() as any).code, 'ASSET_TYPE_OWNER_REQUIRED');
  assert.equal((await state(assetId)).assetVersion, 1);
  assert.equal((await request(path, mutation(headers), 'PATCH', { ownerId: steward })).status, 200);
  assert.equal((await request(path + '/attributes', mutation(headers, 2), 'PUT', body)).status, 200);
  const assigned = await state(assetId); assert.equal(assigned.state, 'draft'); assert.equal(assigned.requiredOwner, true);
  const before = await assetSnapshot(assetId);
  const clearOwner = await request(path, mutation(headers, 3), 'PATCH', { ownerId: null });
  assert.equal(clearOwner.status, 422); assert.equal((await clearOwner.json() as any).code, 'ASSET_TYPE_OWNER_REQUIRED');
  const invalidTransition = await request(path + '/type-state', mutation(headers, 3), 'POST', { state: 'retired' });
  assert.equal(invalidTransition.status, 422); assert.equal((await invalidTransition.json() as any).code, 'ASSET_TYPE_TRANSITION_INVALID');
  assert.deepEqual(await assetSnapshot(assetId), before);
  const foreignOwner = await request(path, mutation(headers, 3), 'PATCH', { ownerId: summit });
  assert.ok([400, 422].includes(foreignOwner.status)); assert.equal((await state(assetId)).assetVersion, 3);
  const transitionHeaders = mutation(headers, 3);
  assert.equal((await request(path + '/type-state', { ...transitionHeaders, Origin: 'https://invalid.example' }, 'POST', { state: 'active' })).status, 403);
  const changed = await request(path + '/type-state', transitionHeaders, 'POST', { state: 'active' });
  assert.equal(changed.status, 200); const result = await changed.json() as any;
  assert.equal(result.state, 'active'); assert.equal(result.assetVersion, 4);
  const repeated = await request(path + '/type-state', transitionHeaders, 'POST', { state: 'active' });
  assert.equal(repeated.status, 200); assert.deepEqual(await repeated.json(), result);
  assert.equal((await request(path + '/type-state', mutation(headers, 3), 'POST', { state: 'retired' })).status, 409);
  const consumerHeaders = await session(consumer);
  assert.equal((await request(path + '/type-state', mutation(consumerHeaders, 4), 'POST', { state: 'retired' })).status, 403);
  // Visibility changes are synthetic security setup, not a claimed product mutation.
  await scope(tenant, steward, tx => tx.updateTable('assets').set({ visibility: 'restricted', allowed_identities: '[]' }).where('id', '=', assetId).execute());
  assert.equal((await request(path + '/type-state', headers)).status, 404);
  assert.equal((await request(path + '/type-state', transitionHeaders, 'POST', { state: 'active' })).status, 404);
});

test('changing to another authored type initializes its lifecycle rather than retaining the previous type state', async () => {
  const first = definition(), second = definition({ lifecycle: { initial: 'open', states: ['open', 'closed'], transitions: [{ from: 'open', to: 'closed' }] } });
  await create(first); await create(second);
  const assetId = await fixtureAsset(); await assign(assetId, first.id);
  await scope(tenant, steward, tx => transitionAssetTypeState(tx, principal, randomUUID(), assetId, 2, 'active', hooks));
  await assign(assetId, second.id, 1, 3);
  const changed = await state(assetId); assert.equal(changed.modelId, second.id); assert.equal(changed.state, 'open');
  const history = await assetSnapshot(assetId);
  assert.equal(history.revisions.length, 4); assert.equal(history.asset.type_state, 'open');
});

test('asset-type file validation and legacy publication paths cannot bypass authored inheritance constraints', async () => {
  const headers = await session(), authored = definition({ requiredOwner: true });
  const imported = await request('/asset-types/validate', headers, 'POST', { text: JSON.stringify(authored) });
  assert.equal(imported.status, 200); assert.deepEqual((await imported.json() as any).definition, authored);
  const duplicate = await request('/asset-types/validate', headers, 'POST', { text: '{"parents":[],"par\\u0065nts":[]}' });
  assert.equal(duplicate.status, 422); assert.ok((await duplicate.json() as any).issues.some((issue: any) => issue.code === 'duplicate'));
  const createHeaders = mutation(headers);
  const saved = await request('/asset-types', createHeaders, 'POST', { definition: authored });
  assert.equal(saved.status, 201); const result = await saved.json() as any;
  const replay = await request('/asset-types', createHeaders, 'POST', { definition: authored });
  assert.equal(replay.status, 201); assert.deepEqual(await replay.json(), result);
  const changedBody = await request('/asset-types', createHeaders, 'POST', { definition: { ...authored, requiredOwner: false } });
  assert.equal(changedBody.status, 409);
  const resolved = result.type.resolved.model;
  const target = { ...resolved, version: 2, attributes: { ...resolved.attributes, note: { type: 'text' } } };
  const legacy = await request('/models/' + authored.id + '/versions', mutation(headers), 'POST', { definition: target, previewDigest: '0'.repeat(64) });
  assert.equal(legacy.status, 422); assert.equal((await legacy.json() as any).code, 'ASSET_TYPE_REQUIRED');
  const plan = { formatVersion: 1, modelId: authored.id, targetVersion: 2, sourceVersions: [], acknowledgedChanges: [], operations: [] };
  const migration = await request('/models/' + authored.id + '/migrations', mutation(headers), 'POST', { definition: target, plan, previewDigest: '0'.repeat(64) });
  assert.equal(migration.status, 422); assert.equal((await migration.json() as any).code, 'ASSET_TYPE_REQUIRED');
  const current = (await read(authored.id)).type;
  assert.equal(current.currentVersion, 1); assert.equal(current.resolved.requiredOwner, true);
});

test('type preview binds current owners and lifecycle and refuses hidden cohorts without disclosing values', async () => {
  const current = definition(); await create(current);
  const assetId = await fixtureAsset(); await assign(assetId, current.id);
  const proposal: AssetTypeDefinition = { ...current, version: 2, attributes: { ...current.attributes, note: { type: 'text' } } };
  const old = await preview(proposal), headers = await session();
  assert.equal((await request('/assets/' + assetId, mutation(headers, 2), 'PATCH', { ownerId: owner })).status, 200);
  await assert.rejects(() => scope(tenant, steward, tx => publishAssetType(tx, principal, randomUUID(), current.id, 1, proposal, old.previewDigest, hooks)), problem('ASSET_TYPE_PREVIEW_STALE', 409));
  const ownerPreview = await preview(proposal); assert.notEqual(ownerPreview.previewDigest, old.previewDigest);
  await scope(tenant, steward, tx => transitionAssetTypeState(tx, principal, randomUUID(), assetId, 3, 'active', hooks));
  await assert.rejects(() => scope(tenant, steward, tx => publishAssetType(tx, principal, randomUUID(), current.id, 1, proposal, ownerPreview.previewDigest, hooks)), problem('ASSET_TYPE_PREVIEW_STALE', 409));
  assert.equal((await read(current.id)).type.currentVersion, 1);
  await scope(tenant, steward, tx => tx.updateTable('assets').set({ visibility: 'restricted', allowed_identities: JSON.stringify([consumer]) }).where('id', '=', assetId).execute());
  await assert.rejects(() => preview(proposal), error => {
    assert.ok(error instanceof Problem); assert.equal(error.code, 'MODEL_SCOPE_UNAVAILABLE'); assert.equal(error.status, 403); assert.equal(error.issues, undefined);
    assert.equal(JSON.stringify(error).includes(assetId), false); assert.equal(JSON.stringify(error).includes(amount), false); return true;
  });
});

test('tightened owner and lifecycle constraints require explicit migration and preserve existing pins', async () => {
  const current = definition(); await create(current);
  const assetId = await fixtureAsset(null); await assign(assetId, current.id);
  await scope(tenant, steward, tx => transitionAssetTypeState(tx, principal, randomUUID(), assetId, 2, 'active', hooks));
  const ownerRequired = { ...current, version: 2, requiredOwner: true };
  const ownerPreview = await preview(ownerRequired);
  assert.equal(ownerPreview.requiresExplicitMigration, true); assert.equal(ownerPreview.compatibleWithProvidedAssets, false);
  assert.ok(ownerPreview.assets.some(asset => asset.assetId === assetId && asset.proposedIssues.length > 0));
  await assert.rejects(() => scope(tenant, steward, tx => publishAssetType(tx, principal, randomUUID(), current.id, 1, ownerRequired, ownerPreview.previewDigest, hooks)), problem('ASSET_TYPE_MIGRATION_REQUIRED', 422));
  const incompatibleState: AssetTypeDefinition = { ...current, version: 2, lifecycle: { initial: 'draft', states: ['draft'], transitions: [] } };
  const lifecyclePreview = await preview(incompatibleState);
  assert.equal(lifecyclePreview.requiresExplicitMigration, true); assert.equal(lifecyclePreview.compatibleWithProvidedAssets, false);
  await assert.rejects(() => scope(tenant, steward, tx => publishAssetType(tx, principal, randomUUID(), current.id, 1, incompatibleState, lifecyclePreview.previewDigest, hooks)), problem('ASSET_TYPE_MIGRATION_REQUIRED', 422));
  assert.equal((await read(current.id)).type.currentVersion, 1);
  const pinned = await state(assetId); assert.equal(pinned.modelVersion, 1); assert.equal(pinned.state, 'active'); assert.equal(pinned.requiredOwner, false);
});

test('application-service authorization, dependency resolution and PostgreSQL keys remain tenant scoped', async () => {
  const forged = { ...principal, id: consumer }, rejected = definition();
  await assert.rejects(() => scope(tenant, consumer, tx => createAssetType(tx, forged, randomUUID(), rejected, hooks)), problem('FORBIDDEN', 403));
  assert.equal((await typeSnapshot(rejected.id)).heads.length, 0);
  const parent = definition(); await create(parent);
  const child = definition({ parents: [{ id: parent.id, version: 1 }], attributes: {}, lifecycle: null }); await create(child);
  const otherPrincipal = { ...principal, id: summit, tenantId: otherTenant };
  await assert.rejects(() => scope(otherTenant, summit, tx => getAssetType(tx, otherPrincipal, parent.id)), problem('ASSET_TYPE_NOT_FOUND', 404));
  const foreignChild = definition({ parents: [{ id: parent.id, version: 1 }], attributes: {}, lifecycle: null });
  await assert.rejects(() => create(foreignChild, otherPrincipal), error => error instanceof Problem && [404, 422].includes(error.status));
  const independent = definition(); await create(independent, otherPrincipal);
  // Direct writes cannot forge the trigger-maintained dependency projection.
  await assert.rejects(() => scope(otherTenant, summit, tx => tx.insertInto('asset_type_dependencies').values({ tenant_id: otherTenant,
    model_id: independent.id, version: 1, dependency_model_id: parent.id, dependency_version: 1 }).execute()), (error: any) => error.code === '42501');
  // Separately exercise the actual composite FK through the legitimate AFTER
  // INSERT dependency derivation. Every authored/resolved hash and local model
  // reference is valid; only the dependency's tenant differs from its real row.
  const foreignResolution = resolveAssetType(foreignChild, [parent]);
  assert.equal(foreignResolution.ok, true);
  if (!foreignResolution.ok) throw new Error('Invalid synthetic cross-tenant resolution');
  const resolved = foreignResolution.value;
  await assert.rejects(() => scope(otherTenant, summit, async tx => {
    await tx.insertInto('governance_models').values({ tenant_id: otherTenant, id: foreignChild.id,
      current_version: 1, type_id: randomUUID(), created_by: summit }).execute();
    await tx.insertInto('governance_model_versions').values({ tenant_id: otherTenant, model_id: foreignChild.id,
      version: 1, definition: JSON.stringify(resolved.model), definition_hash: hash(resolved.model), created_by: summit }).execute();
    await tx.insertInto('asset_type_versions').values({ tenant_id: otherTenant, model_id: foreignChild.id, version: 1,
      definition: JSON.stringify(resolved.definition), definition_hash: hash(resolved.definition), resolved: JSON.stringify(resolved),
      resolution_hash: hash(resolved), created_by: summit }).execute();
  }), (error: any) => error.code === '23503' && error.table === 'asset_type_dependencies');
  assert.equal((await scope(otherTenant, summit, tx => tx.selectFrom('governance_models').select('id')
    .where('id', '=', foreignChild.id).execute())).length, 0);
  const invisible = await scope(otherTenant, summit, async tx => ({
    types: await tx.selectFrom('asset_type_versions').select('model_id').where('model_id', '=', child.id).execute(),
    dependencies: await tx.selectFrom('asset_type_dependencies').select('model_id').where('model_id', '=', child.id).execute(),
  }));
  assert.deepEqual(invisible, { types: [], dependencies: [] });
  const cyclic: AssetTypeDefinition = { ...parent, version: 2, parents: [{ id: child.id, version: 1 }], attributes: {}, lifecycle: null };
  await assert.rejects(() => preview(cyclic), problem('ASSET_TYPE_INVALID', 422));
  const assetId = await fixtureAsset(); await assign(assetId, child.id);
  await assert.rejects(() => scope(tenant, consumer, tx => transitionAssetTypeState(tx, forged, randomUUID(), assetId, 2, 'active', hooks)), problem('FORBIDDEN', 403));
  await assert.rejects(() => scope(otherTenant, summit, tx => getAssetTypeState(tx, otherPrincipal, assetId)), problem('ASSET_NOT_FOUND', 404));
  assert.equal((await state(assetId)).state, 'draft');
});

test('late creation and publication journal failures roll back authored definitions, resolved models, dependencies and outbox', async () => {
  const parent = definition(); await create(parent);
  const child = definition({ parents: [{ id: parent.id, version: 1 }], attributes: {}, lifecycle: null });
  const failure = new Error('Synthetic failure after the real type journal writes'); let calls = 0;
  const lateFailure: ModelHooks = { assetSnapshot: assetView, record: async (...args) => {
    await record(...args); calls += 1;
    // Prove the injected error occurs after the authored/resolved/dependency writes,
    // not merely before the mutation has done any work.
    const [tx] = args;
    const written = await tx.selectFrom('asset_type_versions').select('version').where('model_id', '=', child.id).orderBy('version').execute();
    assert.equal(written.length, calls);
    const dependencies = await tx.selectFrom('asset_type_dependencies').select('version').where('model_id', '=', child.id).execute();
    assert.equal(dependencies.length, calls);
    throw failure;
  } };
  const empty = await typeSnapshot(child.id);
  await assert.rejects(() => scope(tenant, steward, tx => createAssetType(tx, principal, randomUUID(), child, lateFailure)), error => error === failure);
  assert.equal(calls, 1); assert.deepEqual(await typeSnapshot(child.id), empty);
  await create(child);
  const proposal: AssetTypeDefinition = { ...child, version: 2, attributes: { note: { type: 'text' } } };
  const check = await preview(proposal), before = await typeSnapshot(child.id);
  await assert.rejects(() => scope(tenant, steward, tx => publishAssetType(tx, principal, randomUUID(), child.id, 1, proposal, check.previewDigest, lateFailure)), error => error === failure);
  assert.equal(calls, 2); assert.deepEqual(await typeSnapshot(child.id), before);
  const retried = await scope(tenant, steward, tx => publishAssetType(tx, principal, randomUUID(), child.id, 1, proposal, check.previewDigest, hooks));
  assert.equal(retried.type.version, 2);
  const stored = await typeSnapshot(child.id); assert.equal(stored.models.length, 2); assert.equal(stored.types.length, 2); assert.equal(stored.dependencies.length, 2);
});

test('late lifecycle journal failure restores the canonical state, optimistic version and every immutable journal', async () => {
  const current = definition(); await create(current);
  const assetId = await fixtureAsset(); await assign(assetId, current.id);
  const before = await assetSnapshot(assetId), correlation = randomUUID();
  const failure = new Error('Synthetic failure after the real lifecycle journal writes'); let recorded = false;
  const lateFailure: ModelHooks = { assetSnapshot: assetView, record: async (...args) => {
    await record(...args); recorded = true;
    const [tx] = args;
    const written = await tx.selectFrom('assets').select(['version', 'type_state']).where('id', '=', assetId).executeTakeFirstOrThrow();
    assert.deepEqual(written, { version: 3, type_state: 'active' });
    assert.ok(await tx.selectFrom('asset_revisions').select('version').where('asset_id', '=', assetId).where('version', '=', 3).executeTakeFirst());
    throw failure;
  } };
  await assert.rejects(() => scope(tenant, steward, tx => transitionAssetTypeState(tx, principal, correlation, assetId, 2, 'active', lateFailure)), error => error === failure);
  assert.equal(recorded, true); assert.deepEqual(await assetSnapshot(assetId), before);
  const journals = await scope(tenant, steward, async tx => ({
    audit: await tx.selectFrom('audit').select('id').where('correlation_id', '=', correlation).execute(),
    outbox: await tx.selectFrom('outbox').select('id').where(sql<boolean>`payload->>'correlationId' = ${correlation}`).execute(),
  }));
  assert.deepEqual(journals, { audit: [], outbox: [] });
  const result = await scope(tenant, steward, tx => transitionAssetTypeState(tx, principal, randomUUID(), assetId, 2, 'active', hooks));
  assert.equal(result.state, 'active'); assert.equal(result.assetVersion, 3);
});

after(async () => { await db.destroy(); });
