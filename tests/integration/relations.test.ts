// SPDX-License-Identifier: Apache-2.0
import {createProtectedCoreSession,closeProtectedCoreSessions} from '../fixtures/protected-core-authentication.ts';
import { pacedFetch as fetch } from '../fixtures/http-budget.ts';
import { createManualScanFixture } from '../fixtures/manual-scan.ts';
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { db, scope, sql, lockTenantLedger, type Tx } from '../../packages/db/src/index.ts';
import { Problem, type Principal } from '../../packages/authz/src/index.ts';
import type { AssetTypeDefinition } from '../../packages/domain/src/asset-type.ts';
import type { AssetTypeMigrationPlan } from '../../packages/domain/src/asset-type-migration.ts';
import { previewModelUpgrade } from '../../packages/domain/src/model.ts';
import { assetTypePolicy } from '../../packages/domain/src/asset-type-policy.ts';
import { assetTypePersistence, assetTypePolicyChanges, createAssetType, previewAssetType, publishAssetType, transitionAssetTypeState } from '../../packages/domain/src/asset-type-service.ts';
import { assignAssetModel, type ModelHooks } from '../../packages/domain/src/model-service.ts';
import { executeTypeMigration, getTypeMigrationContext, previewTypeMigration } from '../../packages/domain/src/asset-type-migration-service.ts';
import { configureRelationTransaction, createRelationType, getRelationType, previewRelationType, publishRelationType,
  createRelation, getRelation, editRelation, transitionRelation, tombstoneRelation, listRelationRevisions,
  getAssetGraph, listAssetRelations, authorizeRelationReplay } from '../../packages/domain/src/relation-service.ts';
import type { RelationCreate, RelationEdit, RelationTypeDefinition, RelationView } from '../../packages/domain/src/relation-contracts.ts';
import { assetView, record, once, visibleAudit } from '../../apps/api/src/repository.ts';

const tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', foreign = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const steward = '10000000-0000-4000-8000-000000000001', owner = '10000000-0000-4000-8000-000000000002';
const consumer = '10000000-0000-4000-8000-000000000003', auditor = '10000000-0000-4000-8000-000000000004', summit = '10000000-0000-4000-8000-000000000005';
const p: Principal = { id: steward, name: 'Synthetic relationship steward', tenantId: tenant,
  permissions: ['models:read', 'models:write', 'catalog:read', 'catalog:write', 'audit:read', 'sources:read', 'sources:write'] };
const analyst: Principal = { id: consumer, name: 'Synthetic analyst', tenantId: tenant, permissions: ['catalog:read', 'models:read'] };
const reviewer: Principal = { id: auditor, name: 'Synthetic auditor', tenantId: tenant, permissions: ['catalog:read', 'models:read', 'audit:read'] };
const external: Principal = { ...p, id: summit, tenantId: foreign, name: 'Synthetic foreign steward' };
const hooks: ModelHooks = { record, assetSnapshot: assetView };
const amount = '90071992547409931234567890.000000001';
const instant = '2026-11-15T12:00:00.000Z';
const base = process.env.TEST_BASE_URL ?? 'http://api:4310', origin = process.env.PUBLIC_URL ?? 'http://localhost:4310';
const key = (prefix: string) => prefix + randomUUID().replaceAll('-', '');
const problem = (code: string, status?: number) => (error: unknown) => error instanceof Problem && error.code === code && (status === undefined || error.status === status);
const scoped = <T>(work: (tx: Tx) => Promise<T>, principal = p) => scope(principal.tenantId, principal.id, async tx => {
  await configureRelationTransaction(tx); return work(tx);
});
async function session(actor = steward, organization = tenant) {
  return (await createProtectedCoreSession(actor, organization)).headers;
}
const request = (path: string, headers: Record<string, string>, method = 'GET', body?: unknown) =>
  fetch(base + '/api/v1' + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
const mutation = (headers: Record<string, string>, version = 1) => ({ ...headers, 'If-Match': String(version), 'Idempotency-Key': randomUUID() });
async function response(result: Response, status: number): Promise<any> {
  const text = await result.text(); assert.equal(result.status, status, text); return text ? JSON.parse(text) : null;
}
function assetDefinition(overrides: Partial<AssetTypeDefinition> = {}): AssetTypeDefinition {
  return { formatVersion: 1, id: key('relation_endpoint_'), version: 1, parents: [], attributes: {}, overrideAttributes: [], requiredOwner: false,
    lifecycle: { initial: 'draft', states: ['draft', 'active', 'retired'], transitions: [{ from: 'draft', to: 'active' }, { from: 'active', to: 'retired' }] }, ...overrides };
}
const createAssetDefinition = (definition: AssetTypeDefinition, principal = p) => scoped(tx => createAssetType(tx, principal, randomUUID(), definition, hooks), principal);
async function publishAssetDefinition(definition: AssetTypeDefinition) {
  const preview = await scoped(tx => previewAssetType(tx, p, definition.id, definition.version - 1, definition));
  return scoped(tx => publishAssetType(tx, p, randomUUID(), definition.id, definition.version - 1, definition, preview.previewDigest, hooks));
}
/** Real synthetic initial assets/revisions, then the production assignment service. */
async function asset(modelId?: string, pin = 1, options: { id?: string; name?: string; principal?: Principal } = {}) {
  const principal = options.principal ?? p, id = options.id ?? randomUUID();
  await scoped(async tx => {
    await lockTenantLedger(tx, principal.tenantId);
    const row = await tx.insertInto('assets').values({ tenant_id: principal.tenantId, id, external_id: id,
      name: options.name ?? `Synthetic relation endpoint ${id}`, qualified_name: `synthetic.relation.${id}`, type: 'dataset', observed_at: new Date(), owner_id: principal.id }).returningAll().executeTakeFirstOrThrow();
    await tx.insertInto('asset_revisions').values({ tenant_id: principal.tenantId, asset_id: id, version: row.version, snapshot: JSON.stringify(assetView(row)) }).execute();
    if (modelId) await assignAssetModel(tx, principal, randomUUID(), id, 1, { modelId, modelVersion: pin, attributes: {} }, hooks);
  }, principal); return id;
}
const assetRow = (id: string) => scoped(tx => tx.selectFrom('assets').selectAll().where('id', '=', id).executeTakeFirstOrThrow());
/** Security/metadata fixture setup still appends an actual immutable revision and audit. */
async function changeAsset(id: string, values: Record<string, unknown>) {
  return scoped(async tx => {
    await lockTenantLedger(tx, tenant);
    const prior = await tx.selectFrom('assets').selectAll().where('id', '=', id).forUpdate().executeTakeFirstOrThrow();
    const row = await tx.updateTable('assets').set({ ...values, version: prior.version + 1, updated_at: new Date() }).where('id', '=', id).returningAll().executeTakeFirstOrThrow();
    await tx.insertInto('asset_revisions').values({ tenant_id: tenant, asset_id: id, version: row.version, snapshot: JSON.stringify(assetView(row)) }).execute();
    await record(tx, p, 'asset.updated', id, row.version, { syntheticFixture: true }, randomUUID()); return row;
  });
}
function relationDefinition(typeId: string, changes: Partial<RelationTypeDefinition> = {}): RelationTypeDefinition {
  return { formatVersion: 1, id: key('asserted_relation_'), version: 1, label: 'Supports', inverseLabel: 'Supported by', direction: 'directed',
    sourceTypes: [{ typeId, includeDescendants: false }], targetTypes: [{ typeId, includeDescendants: false }], sourceStates: null, targetStates: null,
    cardinality: { outgoing: { min: 0, max: null }, incoming: { min: 0, max: null } }, allowSelf: false, cycles: 'allow',
    attributes: { amount: { type: 'decimal', required: true }, note: { type: 'text' } }, requiredOwner: true,
    lifecycle: { initial: 'draft', states: ['draft', 'active', 'retired'], transitions: [{ from: 'draft', to: 'active' }, { from: 'active', to: 'retired' }] }, ...changes };
}
async function fixture(count = 3, changes: Partial<RelationTypeDefinition> = {}) {
  const model = assetDefinition(), authored = (await createAssetDefinition(model)).type, assets: string[] = [];
  for (let index = 0; index < count; index++) assets.push(await asset(model.id));
  const type = (await scoped(tx => createRelationType(tx, p, randomUUID(), relationDefinition(authored.typeId, changes), hooks))).type;
  return { model, authored, assets, type, definition: type.definition };
}
type Fixture = Awaited<ReturnType<typeof fixture>>;
async function input(f: Fixture, source = 0, target = 1, changes: Partial<RelationCreate> = {}): Promise<RelationCreate> {
  const s = await assetRow(f.assets[source]), t = await assetRow(f.assets[target]);
  return { relationTypeId: f.type.relationTypeId, relationTypeVersion: f.type.version, sourceAssetId: s.id, targetAssetId: t.id,
    sourceAssetVersion: s.version, targetAssetVersion: t.version, attributes: { amount }, ownerId: owner,
    validFrom: null, validTo: null, visibility: 'tenant', allowedIdentityIds: [], ...changes };
}
const create = (value: RelationCreate) => scoped(tx => createRelation(tx, p, randomUUID(), value, hooks));
function editInput(row: RelationView, changes: Partial<RelationEdit> = {}): RelationEdit {
  return { sourceAssetVersion: row.source.assetVersion, targetAssetVersion: row.target.assetVersion, attributes: row.attributes,
    ownerId: row.ownerId, validFrom: row.validFrom, validTo: row.validTo, visibility: row.visibility, allowedIdentityIds: row.allowedIdentityIds, ...changes };
}
const read = (id: string, principal = p) => scoped(tx => getRelation(tx, principal, id), principal);
async function relationSnapshot(typeId: string) {
  return scoped(async tx => {
    const rows = await tx.selectFrom('relations').selectAll().where('relation_type_id', '=', typeId).orderBy('id').execute(), ids = rows.map(row => row.id);
    return { rows,
      revisions: ids.length ? await tx.selectFrom('relation_revisions').selectAll().where('relation_id', 'in', ids).orderBy('relation_id').orderBy('version').execute() : [],
      acl: ids.length ? await tx.selectFrom('relation_allowed_identities').selectAll().where('relation_id', 'in', ids).orderBy('relation_id').orderBy('version').orderBy('identity_id').execute() : [],
      audit: ids.length ? await tx.selectFrom('audit').selectAll().where('resource_id', 'in', ids).orderBy('sequence').execute() : [],
      outbox: ids.length ? await tx.selectFrom('outbox').select(['id', 'event_type', 'resource_id', 'resource_version', 'payload']).where('resource_id', 'in', ids).orderBy('id').execute() : [] };
  });
}
async function modelSnapshot(modelId: string) {
  return scoped(async tx => {
    const assets = await tx.selectFrom('assets').selectAll().where('model_id', '=', modelId).orderBy('id').execute(), ids = [modelId, ...assets.map(row => row.id)];
    return { assets, head: await tx.selectFrom('governance_models').selectAll().where('id', '=', modelId).execute(),
      versions: await tx.selectFrom('asset_type_versions').selectAll().where('model_id', '=', modelId).orderBy('version').execute(),
      flat: await tx.selectFrom('governance_model_versions').selectAll().where('model_id', '=', modelId).orderBy('version').execute(),
      receipts: await tx.selectFrom('asset_type_migrations').selectAll().where('model_id', '=', modelId).execute(),
      normalized: await tx.selectFrom('asset_type_migration_assets').selectAll().where('model_id', '=', modelId).orderBy('asset_id').execute(),
      revisions: await tx.selectFrom('asset_revisions').selectAll().where('asset_id', 'in', ids.slice(1)).orderBy('asset_id').orderBy('version').execute(),
      audit: await tx.selectFrom('audit').selectAll().where('resource_id', 'in', ids).orderBy('sequence').execute(),
      outbox: await tx.selectFrom('outbox').select(['id', 'event_type', 'resource_id', 'resource_version', 'payload']).where('resource_id', 'in', ids).orderBy('id').execute() };
  });
}
async function migrationRequest(target: AssetTypeDefinition): Promise<{ definition: AssetTypeDefinition; plan: AssetTypeMigrationPlan }> {
  const context = await scoped(tx => getTypeMigrationContext(tx, p, target.id));
  const { head, resolved } = await scoped(async tx => ({ head: (await assetTypePolicy(tx, p, target.id, context.currentVersion))!, resolved: await assetTypePersistence.resolved(tx, p, target) }));
  const changes = previewModelUpgrade(head.model, resolved.model, []); assert.ok(changes.ok);
  return { definition: target, plan: { formatVersion: 1, typeId: context.typeId,
    attributes: { formatVersion: 1, modelId: target.id, targetVersion: target.version, sourceVersions: context.sourceVersions,
      acknowledgedChanges: changes.value.changes.filter(change => change.requiresMigration).map(({ code, path }) => {
        assert.ok(code === 'attribute_removed' || code === 'type_changed' || code === 'constraints_changed'); return { code, path };
      }), operations: [] }, owner: { default: 'preserve', overrides: [] }, lifecycle: { onUnmapped: 'preserve', mappings: [] },
    acknowledgedPolicyChanges: assetTypePolicyChanges(head, resolved) } };
}

test('relation type inventory searches literal keys and labels with tenant-scoped stable pagination', async () => {
  const marker = key('Inventory_%_'), first = await fixture(0, { label: marker + ' first' });
  const second = (await scoped(tx => createRelationType(tx, p, randomUUID(),
    relationDefinition(first.authored.typeId, { label: marker + ' second' }), hooks))).type;
  const foreignModel = (await createAssetDefinition(assetDefinition(), external)).type;
  const foreignType = (await scoped(tx => createRelationType(tx, external, randomUUID(),
    relationDefinition(foreignModel.typeId, { label: marker + ' foreign' }), hooks), external)).type;
  const headers = await session(), query = '/relation-types?q=' + encodeURIComponent(marker.toLowerCase()) + '&limit=1';
  const page1 = await response(await request(query, headers), 200);
  assert.equal(page1.items.length, 1); assert.equal(typeof page1.nextCursor, 'string');
  const page2 = await response(await request(query + '&cursor=' + encodeURIComponent(page1.nextCursor), headers), 200);
  assert.deepEqual([...page1.items, ...page2.items].map((item: any) => item.id), [first.type.id, second.id].sort());
  assert.equal(page2.nextCursor, null);
  const keySearch = await response(await request('/relation-types?q=' + encodeURIComponent(first.type.id), headers), 200);
  assert.deepEqual(keySearch.items.map((item: any) => item.id), [first.type.id]);
  const outside = await response(await request(query, await session(summit, foreign)), 200);
  assert.deepEqual(outside.items.map((item: any) => item.id), [foreignType.id]);
  assert.equal(outside.nextCursor, null);
  await response(await request('/relation-types?q=changed&limit=1&cursor=' + encodeURIComponent(page1.nextCursor), headers), 400);
  assert.ok(Array.isArray((await response(await request('/relation-types?limit=1', headers), 200)).items));
});

test('relation HTTP authoring round-trips exact decimals, ownership, validity, lifecycle and immutable history through tombstone/reassert', async () => {
  const f = await fixture(), headers = await session(), values = await input(f, 0, 1, { validFrom: '2026-01-01T00:00:00.000Z', validTo: '2027-01-01T00:00:00.000Z' });
  const file = await response(await request('/relation-types/validate', headers, 'POST', { text: JSON.stringify(f.definition) }), 200);
  assert.deepEqual(file.definition, f.definition);
  const saved = await response(await request('/relations', mutation(headers), 'POST', values), 201), first: RelationView = saved.relation;
  assert.equal(first.attributes.amount, amount); assert.equal(first.ownerId, owner); assert.equal(first.state, 'draft');
  assert.equal(first.provenance.origin, 'asserted'); assert.equal(first.provenance.source.kind, 'manual'); assert.equal(first.provenance.precedence, null);
  for (const validAt of ['2025-12-31T23:59:59.999Z', '2027-01-01T00:00:00.000Z'])
    assert.deepEqual((await scoped(tx => getAssetGraph(tx, p, f.assets[0], { validAt }))).edges, []);
  assert.deepEqual((await scoped(tx => getAssetGraph(tx, p, f.assets[0], { validAt: '2026-01-01T00:00:00.000Z' }))).edges.map(edge => edge.id), [first.id]);
  const edited = await response(await request('/relations/' + first.id, mutation(headers), 'PATCH', editInput(first, { attributes: { amount, note: 'Curated assertion' }, ownerId: steward })), 200);
  const active = await response(await request('/relations/' + first.id + '/transitions', mutation(headers, 2), 'POST', { state: 'active', sourceAssetVersion: first.source.assetVersion, targetAssetVersion: first.target.assetVersion }), 200);
  assert.equal(active.relation.version, 3); assert.equal(active.relation.state, 'active');
  assert.deepEqual((await response(await request('/relations/' + first.id, headers), 200)).relation, active.relation);
  const history = await response(await request('/relations/' + first.id + '/revisions?limit=2', headers), 200);
  assert.deepEqual(history.items.map((row: any) => row.version), [1, 2]); assert.deepEqual(history.items[0].snapshot, first); assert.deepEqual(history.items[1].snapshot, edited.relation);
  const final = await response(await request('/relations/' + first.id + '/revisions?limit=2&cursor=' + encodeURIComponent(history.nextCursor), headers), 200);
  assert.deepEqual(final.items.map((row: any) => row.version), [3]); assert.equal(final.nextCursor, null);
  const tombstone = await response(await request('/relations/' + first.id, mutation(headers, 3), 'DELETE'), 200);
  assert.equal(tombstone.relation.status, 'tombstoned'); assert.equal(tombstone.relation.version, 4);
  assert.deepEqual((await scoped(tx => listAssetRelations(tx, p, f.assets[0]))).items, []);
  const replacement = await response(await request('/relations', mutation(headers), 'POST', values), 201);
  assert.notEqual(replacement.relation.id, first.id); assert.equal((await read(first.id)).relation.status, 'tombstoned');
  const stored = await relationSnapshot(f.type.relationTypeId); assert.equal(stored.rows.length, 2); assert.equal(stored.revisions.length, 5);
  assert.equal(stored.audit.length, 5); assert.equal(stored.outbox.length, 5);
});

test('relation publication previews complete scope, preserves old pins and blocks destructive policies and stale consent', async () => {
  const f = await fixture(), old = (await create(await input(f))).relation;
  const target = { ...f.definition, version: 2, label: 'Updated support', attributes: { ...f.definition.attributes, optional: { type: 'text' as const } } };
  const preview = await scoped(tx => previewRelationType(tx, p, target.id, 1, target));
  assert.equal(preview.coverage, 'complete-tenant-relation-type-bindings'); assert.equal(preview.relationCount, 1);
  assert.equal(preview.pinsPreserved, true); assert.equal(preview.requiresExplicitMigration, false);
  await scoped(tx => editRelation(tx, p, randomUUID(), old.id, 1, editInput(old, { attributes: { amount, note: 'Changed after preview' } }), hooks));
  await assert.rejects(scoped(tx => publishRelationType(tx, p, randomUUID(), target.id, 1, target, preview.previewDigest, hooks)), problem('RELATION_PREVIEW_STALE', 409));
  const fresh = await scoped(tx => previewRelationType(tx, p, target.id, 1, target));
  await scoped(tx => publishRelationType(tx, p, randomUUID(), target.id, 1, target, fresh.previewDigest, hooks));
  assert.equal((await read(old.id)).relation.relationTypeVersion, 1); assert.equal((await read(old.id)).relation.label, f.definition.label);
  const newer = (await create(await input(f, 0, 2, { relationTypeVersion: 2 }))).relation; assert.equal(newer.label, target.label); assert.equal(newer.relationTypeVersion, 2);
  const destructive = { ...target, version: 3, sourceStates: ['draft'] };
  const blocked = await scoped(tx => previewRelationType(tx, p, target.id, 2, destructive)); assert.equal(blocked.requiresExplicitMigration, true);
  const before = await relationSnapshot(f.type.relationTypeId);
  await assert.rejects(scoped(tx => publishRelationType(tx, p, randomUUID(), target.id, 2, destructive, blocked.previewDigest, hooks)), problem('RELATION_MIGRATION_REQUIRED', 422));
  assert.deepEqual(await relationSnapshot(f.type.relationTypeId), before); assert.equal((await scoped(tx => getRelationType(tx, p, target.id))).type.currentVersion, 2);
  const headers = await session();
  const versions = await response(await request('/relation-types/' + target.id + '/versions?limit=1', headers), 200);
  assert.deepEqual(versions.items.map((row: any) => row.version), [1]); assert.ok(versions.nextCursor);
  assert.deepEqual((await response(await request('/relation-types/' + target.id + '/versions/1', headers), 200)).type.definition, f.definition);
});

test('relation constraints reject foreign endpoints/owners, wrong nominal types, forbidden endpoint states and unsupported minima', async () => {
  const f = await fixture(3, { sourceStates: ['draft'], targetStates: ['draft'] }), values = await input(f);
  await assert.rejects(create({ ...values, ownerId: null }), problem('RELATION_OWNER_INVALID'));
  await assert.rejects(create({ ...values, ownerId: summit }), problem('RELATION_INVALID'));
  await assert.rejects(create({ ...values, attributes: {} }), problem('RELATION_INVALID'));
  const otherModel = assetDefinition(); await createAssetDefinition(otherModel); const wrong = await asset(otherModel.id);
  await assert.rejects(create({ ...values, targetAssetId: wrong, targetAssetVersion: 2 }), problem('RELATION_INVALID'));
  const foreignModel = assetDefinition(); await createAssetDefinition(foreignModel, external); const foreignAsset = await asset(foreignModel.id, 1, { principal: external });
  await assert.rejects(create({ ...values, targetAssetId: foreignAsset, targetAssetVersion: 2 }), problem('RELATION_NOT_FOUND', 404));
  await scoped(tx => transitionAssetTypeState(tx, p, randomUUID(), f.assets[1], 2, 'active', hooks));
  await assert.rejects(create({ ...values, targetAssetVersion: 3 }), problem('RELATION_INVALID'));
  const headers = await session(), definition = structuredClone(f.definition) as any;
  definition.id = key('minimum_'); definition.cardinality.incoming.min = 1;
  const minimum = await response(await request('/relation-types', mutation(headers), 'POST', { definition }), 422); assert.equal(minimum.code, 'RELATION_MINIMUM_UNSUPPORTED');
  const duplicate = await response(await request('/relation-types/validate', headers, 'POST', { text: '{"formatVersion":1,"formatVersi\\u006fn":1}' }), 422);
  assert.ok(duplicate.issues.some((issue: any) => issue.code === 'duplicate'));
  assert.deepEqual((await relationSnapshot(f.type.relationTypeId)).rows, []);
  await create(await input(f, 0, 2));
  const before = await modelSnapshot(f.model.id), edges = await relationSnapshot(f.type.relationTypeId);
  await assert.rejects(scoped(tx => transitionAssetTypeState(tx, p, randomUUID(), f.assets[2], 2, 'active', hooks)), problem('RELATION_MIGRATION_REQUIRED'));
  assert.deepEqual(await modelSnapshot(f.model.id), before); assert.deepEqual(await relationSnapshot(f.type.relationTypeId), edges);
});

test('complete structural checks enforce degree, cycles and undirected canonical uniqueness while allowing configured cycles', async () => {
  const f = await fixture(3, { cardinality: { outgoing: { min: 0, max: 1 }, incoming: { min: 0, max: null } }, cycles: 'acyclic' });
  await create(await input(f));
  await assert.rejects(create(await input(f, 0, 2)), problem('RELATION_CARDINALITY'));
  await assert.rejects(create(await input(f, 1, 0)), problem('RELATION_CYCLE'));
  assert.equal((await relationSnapshot(f.type.relationTypeId)).rows.length, 1);
  const undirected = await fixture(3, { direction: 'undirected', cycles: 'acyclic' });
  const first = (await create(await input(undirected, 1, 0))).relation;
  assert.ok(first.source.assetId < first.target.assetId);
  await assert.rejects(create(await input(undirected, 0, 1)), problem('RELATION_DUPLICATE'));
  await create(await input(undirected, 1, 2)); await assert.rejects(create(await input(undirected, 2, 0)), problem('RELATION_CYCLE'));
  const permissive = await fixture(2); await create(await input(permissive)); await create(await input(permissive, 1, 0));
  const graph = await scoped(tx => getAssetGraph(tx, p, permissive.assets[0], { direction: 'out', depth: 6, validAt: instant }));
  assert.equal(graph.edges.length, 2); assert.equal(graph.nodes.length, 2);
});

test('hidden endpoint bridges never enter graph, audit, history or foreign-tenant direct access', async () => {
  const f = await fixture(4), first = (await create(await input(f, 0, 1))).relation, bridge = (await create(await input(f, 1, 2))).relation;
  const visible = (await create(await input(f, 0, 3))).relation;
  const canary = key('hidden_endpoint_'); await changeAsset(f.assets[1], { name: canary, visibility: 'restricted', allowed_identities: JSON.stringify([steward]) });
  const graph = await scoped(tx => getAssetGraph(tx, analyst, f.assets[0], { depth: 6, direction: 'out', validAt: instant }), analyst);
  assert.deepEqual(graph.edges.map(edge => edge.id), [visible.id]); assert.equal(graph.nodes.some(node => node.assetId === f.assets[2]), false);
  for (const hidden of [canary, f.assets[1], f.assets[2], first.id, bridge.id]) assert.equal(JSON.stringify(graph).includes(hidden), false);
  const headers = await session(auditor), outside = await session(summit, foreign);
  for (const id of [first.id, randomUUID()]) {
    assert.equal((await response(await request('/relations/' + id, headers), 404)).code, 'RELATION_NOT_FOUND');
    assert.equal((await response(await request('/relations/' + id + '/revisions', headers), 404)).code, 'RELATION_NOT_FOUND');
  }
  await response(await request('/relations/' + visible.id, outside), 404);
  for (const path of ['/audit', '/overview']) {
    const body = await response(await request(path, headers), 200);
    for (const hidden of [canary, first.id, bridge.id]) assert.equal(JSON.stringify(body).includes(hidden), false);
  }
  const hiddenRoot = await response(await request('/assets/' + f.assets[1] + '/graph', headers), 404); assert.equal('nodes' in hiddenRoot, false);
});

test('restricted edges between visible assets stay private even with a matching visible asset UUID, and hidden cohorts disclose no counts', async () => {
  const f = await fixture(), edge = (await create(await input(f, 0, 1, { visibility: 'restricted', allowedIdentityIds: [steward] }))).relation;
  // Asset and relation UUIDs are separate storage namespaces. Exercise the audit OR-branch collision explicitly.
  await asset(undefined, 1, { id: edge.id, name: 'Visible unrelated cross-kind UUID fixture' });
  const list = await scoped(tx => listAssetRelations(tx, reviewer, f.assets[0]), reviewer); assert.deepEqual(list.items, []); assert.equal(list.nextCursor, null);
  const events = await scoped(tx => visibleAudit(tx, reviewer).where('audit.resource_id', '=', edge.id).where('audit.action', 'like', 'relation.%').execute(), reviewer);
  assert.deepEqual(events, []);
  await assert.rejects(scoped(tx => listRelationRevisions(tx, reviewer, edge.id), reviewer), problem('RELATION_NOT_FOUND', 404));
  const ownerPrincipal = { ...p, id: owner, permissions: ['catalog:read', 'catalog:write', 'models:read'] };
  await assert.rejects(scoped(tx => createRelation(tx, ownerPrincipal, randomUUID(), { ...edgeInput(edge), targetAssetId: f.assets[2], targetAssetVersion: 2 }, hooks), ownerPrincipal), error => {
    assert.ok(error instanceof Problem); assert.equal(error.code, 'RELATION_SCOPE_UNAVAILABLE'); assert.equal(error.issues, undefined);
    assert.equal(JSON.stringify(error).includes(edge.id), false); assert.equal(JSON.stringify(error).includes(amount), false); return true;
  });
});
function edgeInput(edge: RelationView): RelationCreate {
  return { ...editInput(edge), relationTypeId: edge.relationTypeId, relationTypeVersion: edge.relationTypeVersion,
    sourceAssetId: edge.source.assetId, targetAssetId: edge.target.assetId };
}

test('cached mutation replay and tombstoned history reauthorize current original endpoints', async () => {
  const f = await fixture(), headers = await session(), values = await input(f), originalHeaders = mutation(headers);
  const original = await response(await request('/relations', originalHeaders, 'POST', values), 201);
  assert.deepEqual(await response(await request('/relations', originalHeaders, 'POST', values), 201), original);
  await response(await request('/relations', originalHeaders, 'POST', { ...values, ownerId: steward }), 409);
  const deletion = mutation(headers); await response(await request('/relations/' + original.relation.id, deletion, 'DELETE'), 200);
  await changeAsset(f.assets[1], { visibility: 'restricted', allowed_identities: JSON.stringify([owner]) });
  await response(await request('/relations', originalHeaders, 'POST', values), 404);
  await response(await request('/relations/' + original.relation.id, deletion, 'DELETE'), 404);
  await response(await request('/relations/' + original.relation.id + '/revisions', headers), 404);
  assert.equal((await relationSnapshot(f.type.relationTypeId)).rows.length, 1);
});

test('graph pagination binds actor, root, purpose, filters and resolved default instant with opaque fences only', async () => {
  const f = await fixture(4); for (let index = 1; index < 4; index++) await create(await input(f, 0, index));
  const query = { limit: 1, depth: 2, direction: 'out' as const }, first = await scoped(tx => getAssetGraph(tx, p, f.assets[0], query));
  assert.ok(first.nextCursor); assert.match(first.graphRevision, /^[A-Za-z0-9_-]{43}$/); assert.match(first.validAt, /^\d{4}-.*\.\d{3}Z$/);
  const decoded = JSON.parse(Buffer.from(first.nextCursor.split('.')[0], 'base64url').toString());
  assert.deepEqual(Object.keys(decoded).sort(), ['binding', 'fence', 'last', 'v', 'validAt']); assert.equal(decoded.fence, first.graphRevision); assert.equal(decoded.validAt, first.validAt);
  // The UI carries the first page's resolved default instant explicitly on subsequent pages.
  const implicitNext = await scoped(tx => getAssetGraph(tx, p, f.assets[0], { ...query, cursor: first.nextCursor! }));
  const explicitNext = await scoped(tx => getAssetGraph(tx, p, f.assets[0], { ...query, validAt: first.validAt, cursor: first.nextCursor! }));
  assert.deepEqual(explicitNext, implicitNext); assert.equal(explicitNext.graphRevision, first.graphRevision);
  const headers = await session();
  const httpNext = await response(await request('/assets/' + f.assets[0] + '/graph?limit=1&depth=2&direction=out&validAt=' + encodeURIComponent(first.validAt) + '&cursor=' + encodeURIComponent(first.nextCursor), headers), 200);
  assert.deepEqual(httpNext, explicitNext);
  const seen = first.edges.map(edge => edge.id); let cursor: string | null = first.nextCursor;
  while (cursor) { const page = await scoped(tx => getAssetGraph(tx, p, f.assets[0], { ...query, cursor: cursor! }));
    assert.equal(page.validAt, first.validAt); assert.equal(page.graphRevision, first.graphRevision); assert.ok(page.nodes.length <= 3);
    seen.push(...page.edges.map(edge => edge.id)); cursor = page.nextCursor; }
  assert.equal(new Set(seen).size, 3); assert.deepEqual(seen, [...seen].sort());
  for (const changed of [{ ...query, limit: 2 }, { ...query, depth: 1 }, { ...query, direction: 'in' as const }, { ...query, relationTypeId: f.type.relationTypeId }, { ...query, validAt: instant }])
    await assert.rejects(scoped(tx => getAssetGraph(tx, p, f.assets[0], { ...changed, cursor: first.nextCursor! })), problem('RELATION_PAGE_INVALID', 400));
  await assert.rejects(scoped(tx => getAssetGraph(tx, analyst, f.assets[0], { ...query, cursor: first.nextCursor! }), analyst), problem('RELATION_PAGE_INVALID', 400));
  await assert.rejects(scoped(tx => getAssetGraph(tx, external, f.assets[0], { ...query, cursor: first.nextCursor! }), external), problem('RELATION_PAGE_INVALID', 400));
  await assert.rejects(scoped(tx => getAssetGraph(tx, p, f.assets[1], { ...query, cursor: first.nextCursor! })), problem('RELATION_PAGE_INVALID', 400));
  await assert.rejects(scoped(tx => listAssetRelations(tx, p, f.assets[0], { limit: 1, direction: 'out', cursor: first.nextCursor! })), problem('RELATION_PAGE_INVALID', 400));
  const tampered = first.nextCursor.slice(0, -2) + (first.nextCursor.at(-2) === 'a' ? 'b' : 'a') + first.nextCursor.at(-1);
  await assert.rejects(scoped(tx => getAssetGraph(tx, p, f.assets[0], { ...query, cursor: tampered })), problem('RELATION_PAGE_INVALID', 400));
  const actorPage = await scoped(tx => getAssetGraph(tx, analyst, f.assets[0], { ...query, validAt: instant }), analyst);
  const stewardPage = await scoped(tx => getAssetGraph(tx, p, f.assets[0], { ...query, validAt: instant }));
  const rootPage = await scoped(tx => getAssetGraph(tx, p, f.assets[1], { ...query, validAt: instant }));
  const list = await scoped(tx => listAssetRelations(tx, p, f.assets[0], { limit: 1, direction: 'out', validAt: instant }));
  const unfilteredList = await scoped(tx => listAssetRelations(tx, p, f.assets[0], { limit: 1, direction: 'out' })); assert.ok(unfilteredList.nextCursor);
  assert.equal(JSON.parse(Buffer.from(unfilteredList.nextCursor.split('.')[0], 'base64url').toString()).validAt, null);
  await assert.rejects(scoped(tx => listAssetRelations(tx, p, f.assets[0], { limit: 1, direction: 'out', validAt: instant, cursor: unfilteredList.nextCursor! })), problem('RELATION_PAGE_INVALID', 400));
  assert.notEqual(actorPage.graphRevision, stewardPage.graphRevision); assert.notEqual(rootPage.graphRevision, stewardPage.graphRevision); assert.notEqual(list.graphRevision, stewardPage.graphRevision);
  for (const view of [first, decoded, actorPage, list]) { assert.equal('revision' in view, false); assert.equal('counter' in view, false); assert.equal('total' in view, false); }
});

test('endpoint metadata/owner/version and relationship changes invalidate graph/list cursors with one generic stale response', async () => {
  const f = await fixture(), edge = (await create(await input(f))).relation; await create(await input(f, 0, 2));
  const headers = await session();
  const mutations = [
    () => changeAsset(f.assets[1], { name: key('renamed_') }),
    async () => { const a = await assetRow(f.assets[1]); await response(await request('/assets/' + a.id, mutation(headers, a.version), 'PATCH', { ownerId: owner }), 200); },
    () => changeAsset(f.assets[1], { description: 'New endpoint revision' }),
    async () => { const current = (await read(edge.id)).relation; await scoped(tx => editRelation(tx, p, randomUUID(), edge.id, current.version, editInput(current, { attributes: { amount, note: 'New edge revision' } }), hooks)); },
  ];
  for (const mutate of mutations) {
    const query = { limit: 1, validAt: instant }, graph = await scoped(tx => getAssetGraph(tx, p, f.assets[0], query)), list = await scoped(tx => listAssetRelations(tx, p, f.assets[0], query));
    assert.ok(graph.nextCursor); assert.ok(list.nextCursor); await mutate();
    for (const run of [() => getAssetGraphCursor(graph.nextCursor!), () => scoped(tx => listAssetRelations(tx, p, f.assets[0], { ...query, cursor: list.nextCursor! }))])
      await assert.rejects(run(), error => { assert.ok(error instanceof Problem); assert.equal(error.code, 'RELATION_GRAPH_STALE'); assert.equal(error.status, 409); assert.equal(error.issues, undefined); assert.equal(JSON.stringify(error).includes(edge.id), false); return true; });
    const fresh = await scoped(tx => getAssetGraph(tx, p, f.assets[0], query)); assert.notEqual(fresh.graphRevision, graph.graphRevision);
    function getAssetGraphCursor(cursor: string) { return scoped(tx => getAssetGraph(tx, p, f.assets[0], { ...query, cursor })); }
  }
});

test('complete mixed-pin endpoint migration uses the joint proposed set and rejects a later state-breaking plan without any writes', async () => {
  const f = await fixture(2, { sourceStates: ['active', 'draft'], targetStates: ['active', 'draft'] });
  await publishAssetDefinition({ ...f.model, version: 2, attributes: { note: { type: 'text' } } });
  await scoped(tx => assignAssetModel(tx, p, randomUUID(), f.assets[1], 2, { modelId: f.model.id, modelVersion: 2, attributes: {} }, hooks));
  const edge = (await create(await input(f))).relation;
  const target: AssetTypeDefinition = { ...f.model, version: 3, attributes: { note: { type: 'text' } }, lifecycle: { initial: 'active', states: ['active', 'draft'], transitions: [{ from: 'draft', to: 'active' }] } };
  const accepted = await migrationRequest(target); accepted.plan = { ...accepted.plan, lifecycle: { onUnmapped: 'error', mappings: [{ sourceVersion: 1, from: 'draft', to: 'active' }, { sourceVersion: 2, from: 'draft', to: 'active' }] } };
  const preview = await scoped(tx => previewTypeMigration(tx, p, target.id, 2, accepted));
  assert.deepEqual(preview.sourceResolutions.map(item => item.version), [1, 2]); assert.equal(preview.assets.length, 2);
  await scoped(tx => executeTypeMigration(tx, p, randomUUID(), target.id, 2, { ...accepted, previewDigest: preview.previewDigest }, hooks));
  const actual = (await read(edge.id)).relation; assert.equal(actual.source.state, 'active'); assert.equal(actual.target.state, 'active'); assert.equal(actual.relationTypeVersion, 1); assert.equal(actual.version, 1);
  const invalid: AssetTypeDefinition = { ...target, version: 4, lifecycle: { initial: 'review', states: ['review'], transitions: [] } };
  const rejected = await migrationRequest(invalid); rejected.plan = { ...rejected.plan, lifecycle: { onUnmapped: 'error', mappings: [{ sourceVersion: 3, from: 'active', to: 'review' }] } };
  const before = await modelSnapshot(target.id), edges = await relationSnapshot(f.type.relationTypeId), idempotency = randomUUID();
  await assert.rejects(scoped(tx => previewTypeMigration(tx, p, target.id, 3, rejected)), problem('RELATION_MIGRATION_REQUIRED'));
  await assert.rejects(scoped(tx => once(tx, p, 'test.relation-endpoint-migration', idempotency, rejected,
    () => executeTypeMigration(tx, p, randomUUID(), target.id, 3, { ...rejected, previewDigest: '0'.repeat(64) }, hooks))), problem('RELATION_MIGRATION_REQUIRED'));
  assert.deepEqual(await modelSnapshot(target.id), before); assert.deepEqual(await relationSnapshot(f.type.relationTypeId), edges);
  assert.deepEqual(await scoped(tx => tx.selectFrom('idempotency').selectAll().where('key', '=', idempotency).execute()), []);
});

test('removing a pinned allowed ancestor fails both singleton assignment and complete type migration without implicit relation repair', async () => {
  const parent = assetDefinition(), parentType = (await createAssetDefinition(parent)).type;
  const child = assetDefinition({ parents: [{ id: parent.id, version: 1 }], lifecycle: null }); const authored = (await createAssetDefinition(child)).type;
  const assets = [await asset(child.id), await asset(child.id)];
  const type = (await scoped(tx => createRelationType(tx, p, randomUUID(), relationDefinition(parentType.typeId, { sourceTypes: [{ typeId: parentType.typeId, includeDescendants: true }], targetTypes: [{ typeId: parentType.typeId, includeDescendants: true }] }), hooks))).type;
  const f: Fixture = { model: child, authored, assets, type, definition: type.definition }; await create(await input(f));
  const unrelated = assetDefinition(); await createAssetDefinition(unrelated);
  const before = await modelSnapshot(child.id), edges = await relationSnapshot(type.relationTypeId);
  await assert.rejects(scoped(tx => assignAssetModel(tx, p, randomUUID(), assets[0], 2, { modelId: unrelated.id, modelVersion: 1, attributes: {} }, hooks)), problem('RELATION_MIGRATION_REQUIRED'));
  const target = { ...child, version: 2, parents: [], lifecycle: parent.lifecycle };
  const change = await migrationRequest(target);
  await assert.rejects(scoped(tx => previewTypeMigration(tx, p, child.id, 1, change)), problem('RELATION_MIGRATION_REQUIRED'));
  assert.deepEqual(await modelSnapshot(child.id), before); assert.deepEqual(await relationSnapshot(type.relationTypeId), edges);
});

test('late relation journal failure rolls back canonical/revision/ACL/audit/outbox/idempotency together and identical retry commits once', async () => {
  const f = await fixture(), values = await input(f, 0, 1, { visibility: 'restricted', allowedIdentityIds: [steward, owner] }), correlation = randomUUID(), idem = randomUUID();
  let failedId = '';
  const broken: Pick<ModelHooks, 'record'> = { record: async (...args) => { await record(...args); if (args[2] === 'relation.created') { failedId = args[3]; throw Error('synthetic late relation journal failure'); } } };
  const run = (journal: Pick<ModelHooks, 'record'>) => scoped(async tx => {
    const result = await once(tx, p, 'test.relation.create', idem, values, () => createRelation(tx, p, correlation, values, journal));
    await authorizeRelationReplay(tx, p, result.relation, ['catalog:read', 'catalog:write', 'models:read']); return result;
  });
  const before = await relationSnapshot(f.type.relationTypeId);
  await assert.rejects(run(broken), /synthetic late relation journal failure/); assert.ok(failedId);
  assert.deepEqual(await relationSnapshot(f.type.relationTypeId), before);
  await scoped(async tx => {
    for (const [table, field] of [['relations', 'id'], ['relation_revisions', 'relation_id'], ['relation_allowed_identities', 'relation_id'], ['audit', 'resource_id'], ['outbox', 'resource_id']])
      assert.deepEqual(await tx.selectFrom(table).selectAll().where(field, '=', failedId).execute(), [], table);
    assert.deepEqual(await tx.selectFrom('audit').selectAll().where('correlation_id', '=', correlation).execute(), []);
    assert.deepEqual(await tx.selectFrom('outbox').selectAll().where(sql<boolean>`payload->>'correlationId'=${correlation}`).execute(), []);
    assert.deepEqual(await tx.selectFrom('idempotency').selectAll().where('key', '=', idem).execute(), []);
  });
  const saved = await run(hooks); assert.deepEqual(await run(hooks), saved);
  const stored = await relationSnapshot(f.type.relationTypeId); assert.equal(stored.rows.length, 1); assert.equal(stored.revisions.length, 1); assert.equal(stored.acl.length, 2); assert.equal(stored.audit.length, 1); assert.equal(stored.outbox.length, 1);
});

test('relation HTTP boundaries enforce authentication, CSRF, strict fields/queries, preconditions, stale versions and current roles', async () => {
  const f = await fixture(), headers = await session(), values = await input(f), edge = (await create(values)).relation;
  await response(await request('/relations/' + edge.id, {}), 401);
  await response(await request('/relations', { ...mutation(headers), Origin: 'https://untrusted.invalid' }, 'POST', values), 403);
  const noCsrf = { ...mutation(headers) } as Record<string, string>; delete noCsrf['X-CSRF-Token']; await response(await request('/relations', noCsrf, 'POST', values), 403);
  await response(await request('/relations/' + edge.id, { ...headers, 'Idempotency-Key': randomUUID() }, 'PATCH', editInput(edge)), 428);
  await response(await request('/relations', headers, 'POST', values), 400);
  await response(await request('/relations/' + edge.id, mutation(headers, 9), 'PATCH', editInput(edge)), 409);
  await response(await request('/relations/' + edge.id, mutation(headers), 'PATCH', editInput(edge, { sourceAssetVersion: 1 })), 409);
  await response(await request('/relations/' + edge.id, mutation(headers), 'PATCH', { ...editInput(edge), relationTypeVersion: 9 }), 400);
  const raw = (path: string, method: string, body: string) => fetch(base + '/api/v1' + path, { method, headers: mutation(headers), body });
  const duplicateDefinition = JSON.stringify({ definition: { ...f.definition, id: key('duplicate_definition_') } }).slice(0, -1) + ',"definiti\\u006fn":' + JSON.stringify(f.definition) + '}';
  const duplicateOwner = JSON.stringify(editInput(edge)).slice(0, -1) + ',"owner\\u0049d":' + JSON.stringify(steward) + '}';
  for (const result of [await raw('/relation-types', 'POST', duplicateDefinition), await raw('/relations/' + edge.id, 'PATCH', duplicateOwner)]) {
    const rejected = await response(result, 400); assert.equal(rejected.code, 'RELATION_JSON_INVALID');
    assert.ok(rejected.issues.some((issue: any) => issue.code === 'duplicate'));
  }
  for (const change of [{ sourceAssetVersion: String(edge.source.assetVersion) }, { targetAssetVersion: [edge.target.assetVersion] },
    { ownerId: false }, { validFrom: false }, { validTo: 0 }, { ownerId: '' }, { validFrom: '' }, { validTo: '' },
    { visibility: ['tenant'] }, { allowedIdentityIds: steward }])
    await response(await request('/relations/' + edge.id, mutation(headers), 'PATCH', { ...editInput(edge), ...change }), 400);
  await response(await request('/relations/' + edge.id + '/transitions', mutation(headers), 'POST', { state: 1, sourceAssetVersion: 2, targetAssetVersion: 2 }), 400);
  const invalidDefinition = await response(await request('/relation-types', mutation(headers), 'POST', { definition: { ...f.definition, id: key('noncoercion_'), requiredOwner: 'true' } }), 422);
  assert.equal(invalidDefinition.code, 'RELATION_INVALID');
  await response(await request('/relations/' + edge.id + '/transitions', mutation(headers), 'POST', { state: 'retired', sourceAssetVersion: 2, targetAssetVersion: 2 }), 422);
  for (const body of ['{}', 'null', '[]', ' ', '{'])
    await response(await raw('/relations/' + edge.id, 'DELETE', body), 400);
  await response(await raw('/relations', 'POST', ''), 400);
  for (const query of ['limit=01', 'limit=1&limit=2', 'depth=1e0', 'limit=101', 'sort=name', 'validAt=2026-02-30T00%3A00%3A00.000Z'])
    await response(await request('/assets/' + f.assets[0] + '/graph?' + query, headers), 400);
  const readOnly = await session(consumer); await response(await request('/relations/' + edge.id, readOnly), 200);
  await response(await request('/relations', mutation(readOnly), 'POST', values), 403); await response(await request('/relations/' + edge.id + '/revisions', readOnly), 403);
  const ownerHeaders = await session(owner); await response(await request('/relation-types', mutation(ownerHeaders), 'POST', { definition: { ...f.definition, id: key('forbidden_') } }), 403);
  const outside = await session(summit, foreign); await response(await request('/relation-types/' + f.definition.id, outside), 404); await response(await request('/assets/' + f.assets[0] + '/graph', outside), 404);
  assert.equal((await read(edge.id)).relation.version, 1);
});

test('real internal source completions preserve assertions through rename, empty, partial, failed, permission-reduced and unavailable results', async t => {
  assert.ok(process.env.SITE_TOKEN, 'The real internal-site credential is required for this gate.');
  const model = assetDefinition(), authored = (await createAssetDefinition(model)).type, sourceId = randomUUID();
  await scoped(tx => tx.insertInto('sources').values({ tenant_id: tenant, id: sourceId, name: 'Synthetic relationship scan preservation', host: 'source-postgres', port: 5432,
    database_name: 'harbor', schema_name: 'public', secret_ref: 'demo-postgres' }).execute());
  const workerHeaders = { Authorization: `Bearer ${process.env.SITE_TOKEN}`, 'X-Tenant-Id': tenant, 'Content-Type': 'application/json' };
  const records = [{ externalId: 'relation-source', name: 'Observed source', qualifiedName: 'synthetic.source', type: 'table', metadata: {} },
    { externalId: 'relation-target', name: 'Observed target', qualifiedName: 'synthetic.target', type: 'table', metadata: {} }];
  const manual = await createManualScanFixture(t, { tenantId: tenant, sourceId, actorId: steward, fetch });
  // Keep controlled Temporal reservations isolated while using the supported
  // claim route to allocate the generation required by every completion.
  const job = async () => {
    const id = await manual.job(), claimed = await response(await fetch(base + '/internal/jobs/' + id + '/claim', {
      method: 'POST', headers: workerHeaders, body: '{}', signal: AbortSignal.timeout(15_000) }), 200);
    assert.equal(claimed.job.id, id); assert.equal(claimed.job.sourceId, sourceId); assert.equal(claimed.job.status, 'running'); assert.equal(claimed.source.id, sourceId); return id;
  };
  const complete = (id: string, rows: typeof records, permissionFingerprint = 'wide', finished: boolean = true) => fetch(base + '/internal/jobs/' + id + '/complete', {
    method: 'POST', headers: workerHeaders, body: JSON.stringify({ observedAt: new Date().toISOString(), sourceVersion: 'synthetic-real-handler', permissionFingerprint, complete: finished, records: rows }) });
  await response(await complete(await job(), records), 200);
  const assets = await scoped(tx => tx.selectFrom('assets').selectAll().where('source_id', '=', sourceId).orderBy('external_id').execute()); assert.equal(assets.length, 2);
  for (const a of assets) await scoped(tx => assignAssetModel(tx, p, randomUUID(), a.id, a.version, { modelId: model.id, modelVersion: 1, attributes: {} }, hooks));
  const type = (await scoped(tx => createRelationType(tx, p, randomUUID(), relationDefinition(authored.typeId), hooks))).type;
  const f: Fixture = { model, authored, assets: assets.map(row => row.id), type, definition: type.definition };
  const edge = (await create(await input(f, 0, 1, { attributes: { amount, note: 'Steward assertion survives scans' }, validFrom: '2026-01-01T00:00:00.000Z', validTo: '2027-01-01T00:00:00.000Z' }))).relation;
  const before = await relationSnapshot(type.relationTypeId);
  const check = async () => { assert.deepEqual(await relationSnapshot(type.relationTypeId), before); const current = (await read(edge.id)).relation;
    assert.equal(current.ownerId, owner); assert.equal(current.attributes.amount, amount); assert.equal(current.attributes.note, 'Steward assertion survives scans');
    assert.deepEqual(current.provenance, edge.provenance); assert.equal(current.state, 'draft'); assert.equal(current.validFrom, edge.validFrom); };
  const renamed = records.map(row => ({ ...row, name: row.name + ' renamed', qualifiedName: row.qualifiedName + '_renamed' }));
  await response(await complete(await job(), renamed), 200); await check();
  assert.ok((await read(edge.id)).relation.source.name.endsWith('renamed'));
  const revision = await scoped(tx => listRelationRevisions(tx, p, edge.id)); assert.equal(revision.items[0].snapshot.source.name, edge.source.name);
  await response(await complete(await job(), []), 200); await check();
  const partial = await job(); await response(await complete(partial, [records[0]], 'wide', false), 400); await check();
  // A duplicate late record rolls back an earlier source update in the same real completion transaction.
  await response(await complete(partial, [records[0], records[0]]), 422); await check();
  await response(await fetch(base + '/internal/jobs/' + partial + '/fail', { method: 'POST', headers: workerHeaders, body: JSON.stringify({ code: 'SYNTHETIC_PARTIAL_SCAN' }) }), 200); await check();
  await response(await complete(await job(), [renamed[0]], 'reduced'), 200); await check();
  assert.equal((await assetRow(f.assets[1])).status, 'active');
  await response(await complete(await job(), [renamed[0]], 'reduced'), 200); await check();
  assert.equal((await assetRow(f.assets[1])).status, 'unavailable');
  const graph = await scoped(tx => getAssetGraph(tx, p, f.assets[0], { validAt: instant })); assert.deepEqual(graph.edges.map(item => item.id), [edge.id]);
});

test('oversized endpoint-policy cohorts fail before writes and hidden scope takes precedence over the size limit', async () => {
  const model = assetDefinition({ attributes: { code: { type: 'enum', values: Array.from({ length: 64 }, (_, index) => String(index).padStart(3, '0') + 'x'.repeat(997)) } } });
  const authored = (await createAssetDefinition(model)).type, assets: string[] = [];
  for (let index = 0; index < 5; index++) assets.push(await asset(model.id));
  const type = (await scoped(tx => createRelationType(tx, p, randomUUID(), relationDefinition(authored.typeId), hooks))).type;
  const f: Fixture = { model, authored, assets, type, definition: type.definition };
  // Each two-endpoint assertion is bounded; the complete five-endpoint publication/transition scope is not.
  for (let index = 1; index < assets.length; index++) await create(await input(f, 0, index));
  const target = { ...type.definition, version: 2, label: 'Updated large-policy support' }, headers = await session();
  const attempt = async (code: string, status: number) => {
    const before = await modelSnapshot(model.id), edges = await relationSnapshot(type.relationTypeId);
    await assert.rejects(scoped(tx => previewRelationType(tx, p, target.id, 1, target)), problem(code, status));
    await assert.rejects(scoped(tx => transitionAssetTypeState(tx, p, randomUUID(), assets[0], 2, 'active', hooks)), problem(code, status));
    for (const result of [
      await request('/relation-types/' + target.id + '/previews', mutation(headers), 'POST', { definition: target }),
      await request('/assets/' + assets[0] + '/type-state', mutation(headers, 2), 'POST', { state: 'active' }),
    ]) {
      const body = await response(result, status); assert.equal(body.code, code); assert.equal(body.issues, undefined);
      const serialized = JSON.stringify(body);
      for (const id of assets) assert.equal(serialized.includes(id), false);
      assert.equal(serialized.includes(model.attributes.code.type === 'enum' ? model.attributes.code.values[0] : 'unreachable'), false);
    }
    assert.deepEqual(await modelSnapshot(model.id), before); assert.deepEqual(await relationSnapshot(type.relationTypeId), edges);
    assert.equal((await scoped(tx => getRelationType(tx, p, target.id))).type.currentVersion, 1);
  };
  await attempt('RELATION_PROFILE_LIMIT', 422);
  await changeAsset(assets[4], { visibility: 'restricted', allowed_identities: JSON.stringify([owner]) });
  await attempt('RELATION_SCOPE_UNAVAILABLE', 403);
});

test('asset assignment and lifecycle HTTP mutations time out behind the tenant ledger with retry guidance and no writes', async () => {
  const f = await fixture(2); await create(await input(f));
  const headers = await session(), before = await modelSnapshot(f.model.id), relations = await relationSnapshot(f.type.relationTypeId);
  const assignmentHeaders = mutation(headers, 2), transitionHeaders = mutation(headers, 2);
  let acquired!: () => void, acquireFailed!: (error: unknown) => void, release!: () => void;
  const ready = new Promise<void>((resolve, reject) => { acquired = resolve; acquireFailed = reject; });
  const released = new Promise<void>(resolve => { release = resolve; });
  const holder = scope(tenant, steward, async tx => { await lockTenantLedger(tx, tenant); acquired(); await released; });
  void holder.catch(acquireFailed);
  try {
    await ready;
    // These independent requests share the same lock blocker, avoiding two serial five-second waits.
    const results = await Promise.all([
      fetch(base + '/api/v1/assets/' + f.assets[0] + '/attributes', { method: 'PUT', headers: assignmentHeaders,
        body: JSON.stringify({ modelId: f.model.id, modelVersion: 1, attributes: {} }), signal: AbortSignal.timeout(15_000) }),
      fetch(base + '/api/v1/assets/' + f.assets[1] + '/type-state', { method: 'POST', headers: transitionHeaders,
        body: JSON.stringify({ state: 'active' }), signal: AbortSignal.timeout(15_000) }),
    ]);
    for (const result of results) {
      assert.equal(result.headers.get('retry-after'), '5');
      const body = await response(result, 503); assert.equal(body.code, 'RELATION_RETRY');
    }
  } finally { release(); await holder; }
  assert.deepEqual(await modelSnapshot(f.model.id), before); assert.deepEqual(await relationSnapshot(f.type.relationTypeId), relations);
  assert.deepEqual(await scoped(tx => tx.selectFrom('idempotency').selectAll().where('key', 'in', [assignmentHeaders['Idempotency-Key'], transitionHeaders['Idempotency-Key']]).execute()), []);
});

after(async () => { await closeProtectedCoreSessions(); await db.destroy(); });
