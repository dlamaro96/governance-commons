// SPDX-License-Identifier: Apache-2.0
/** SQL009 qualification: no mocked claims, histories, journals or runtime roles. */
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { randomUUID } from 'node:crypto';
import { db, scope, sql } from '../../packages/db/src/index.ts';
import { typeHash } from '../../packages/domain/src/asset-type-policy.ts';
import { resolveAssetType } from '../../packages/domain/src/asset-type.ts';
import { parseGraphChangeSet } from '../../packages/domain/src/relation-migration.ts';
import { parseRelationDefinition } from '../../packages/domain/src/relation.ts';
import type { GraphChangeSet, RelationMigrationPlan } from '../../packages/domain/src/relation-migration-contracts.ts';
import type { RelationTypeDefinitionV2 } from '../../packages/domain/src/relation-contracts.ts';
import { assetView, once, record } from '../../apps/api/src/repository.ts';
import { actor, tenant, ownerId, principal, fixture, plan, values, prepare, begin, execute, persist, seal, bodyFor, emptyChange, correlation,
  candidate, insertEdge, sqlCode, type Fixture } from '../fixtures/relation-participation.ts';
if (!process.env.DATABASE_URL) throw Error('Real disposable DATABASE_URL is required; no storage checks ran.');
const foreign = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', other = '10000000-0000-4000-8000-000000000005';
async function positive() {
  const f = await fixture({ publish: false });
  const definition: RelationTypeDefinitionV2 = { ...f.definition, formatVersion: 2, cardinality: { outgoing: { min: 1, max: 2 }, incoming: { min: 0, max: null } } };
  const preparation = await prepare(f, definition); f.typeId = preparation.relationTypeId; f.definition = definition;
  const creations = f.assets.map((a, index) => ({ key: 'edge_' + index, sourceAssetId: a.id, sourceAssetVersion: a.version,
    targetAssetId: f.assets[1 - index]!.id, targetAssetVersion: f.assets[1 - index]!.version, values: values() }));
  const change: GraphChangeSet = { ...emptyChange(), relationTargets: [{ kind: 'create', reservationId: preparation.id, expectedHeadVersion: null,
    definition, plan: plan(f.typeId, { creations }) }] };
  return { f, preparation, change };
}
async function currentPlan(f: Fixture): Promise<RelationMigrationPlan> {
  return scope(f.principal.tenantId, f.principal.id, async tx => {
    const edges = await tx.selectFrom('relations').selectAll().where('relation_type_id', '=', f.typeId).where('status', '=', 'active').orderBy('id').execute();
    const bindings = await tx.selectFrom('relation_participations').selectAll().where('relation_type_id', '=', f.typeId).where('status', '=', 'active').orderBy('id').execute();
    return plan(f.typeId, { sourceVersions: [...new Set([...edges, ...bindings].map(r => r.relation_type_version as number))].sort((a, b) => a - b),
      edges: edges.map(r => ({ relationId: r.id, expectedVersion: r.version, action: 'preserve' as const })),
      bindings: bindings.map(r => ({ bindingId: r.id, expectedVersion: r.version, action: 'preserve' as const })) });
  });
}
async function counts(f: Fixture) {
  return scope(f.principal.tenantId, f.principal.id, async tx => ({
    heads: await tx.selectFrom('relation_types').selectAll().where('type_id', '=', f.typeId).execute(),
    edges: await tx.selectFrom('relations').selectAll().where('relation_type_id', '=', f.typeId).orderBy('id').execute(),
    bindings: await tx.selectFrom('relation_participations').selectAll().where('relation_type_id', '=', f.typeId).orderBy('id').execute(),
    fence: (await tx.selectFrom('tenant_graph_revisions').select('revision').executeTakeFirstOrThrow()).revision,
  }));
}

test('preparation reserves only opaque identity, exact fixed expiry and creator-scoped read with complete once/journal binding', async () => {
  const f = await fixture({ publish: false }), definition = { ...f.definition, formatVersion: 2, sourceStates: ['draft', 'active'] } as RelationTypeDefinitionV2, key = randomUUID();
  const prepared = await prepare(f, definition, key), replay = await prepare(f, definition, key);
  const normalized = parseRelationDefinition(definition); assert.ok(normalized.ok); if (!normalized.ok) throw Error('Invalid preparation intent');
  assert.equal(prepared.definitionHash, typeHash(normalized.value)); assert.notEqual(prepared.definitionHash, typeHash(definition));
  assert.deepEqual(replay, prepared); assert.notEqual(prepared.id, prepared.relationTypeId);
  assert.equal(Date.parse(prepared.expiresAt) - Date.parse(prepared.createdAt), 900000);
  assert.deepEqual((await counts(f)).heads, []);
  assert.deepEqual(await scope(tenant, ownerId, tx => tx.selectFrom('relation_type_preparations').selectAll().where('id', '=', prepared.id).execute()), []);
  assert.deepEqual(await scope(foreign, other, tx => tx.selectFrom('relation_type_preparations').selectAll().execute()), []);
  await assert.rejects(() => prepare(f, { ...definition, label: 'Different exact intent' }, key), (error: any) => error.code === 'IDEMPOTENCY_CONFLICT');
  await assert.rejects(() => scope(tenant, actor, tx => sql`SELECT gc_relation_graph_prepare(${randomUUID()},${JSON.stringify({ definition })}::jsonb,${correlation})`.execute(tx)), sqlCode('23514'));
});

test('unsorted valid request retains raw once hash but receipt binds normalized semantics without laundering duplicate or unknown fields', async () => {
  const f = await fixture({ definition: { attributes: { tags: { type: 'list', items: { type: 'text' } } } } });
  const edges = await scope(tenant, actor, async tx => [await insertEdge(tx, f, candidate(f, 0, 1)), await insertEdge(tx, f, candidate(f, 1, 0))]);
  const input: GraphChangeSet = { ...emptyChange(), assetChanges: [...f.assets].reverse().map(a => ({ kind: 'transition' as const, assetId: a.id, expectedVersion: 1, state: 'active' })),
    relationTargets: [{ kind: 'repair', expectedHeadVersion: 1, definition: null, plan: plan(f.typeId, { sourceVersions: [1],
      edges: edges.sort((a, b) => b.id.localeCompare(a.id)).map(e => ({ relationId: e.id, expectedVersion: 1, action: 'repair' as const,
        values: { ...values({ tags: ['z', 'a', 'z'] }), visibility: 'restricted' as const, allowedIdentityIds: [ownerId, actor] } })) }) }] };
  const parsed = parseGraphChangeSet(input); assert.ok(parsed.ok); if (!parsed.ok) throw Error('Invalid synthetic normalization intent');
  assert.notEqual(typeHash(input), typeHash(parsed.value)); const before = await counts(f);
  for (const malformed of [
    { ...input, unexpected: true },
    { ...input, relationTargets: [{ ...input.relationTargets[0]!, plan: { ...input.relationTargets[0]!.plan, edges: [...input.relationTargets[0]!.plan.edges, input.relationTargets[0]!.plan.edges[0]!] } }] },
    { ...input, relationTargets: [{ ...input.relationTargets[0]!, plan: { ...input.relationTargets[0]!.plan, unknown: [] } }] },
  ]) {
    await assert.rejects(() => execute(f, malformed as GraphChangeSet), sqlCode('23514'));
    assert.deepEqual(await counts(f), before);
  }
  const receipt = await execute(f, input, { persistChangeSet: parsed.value });
  assert.deepEqual(receipt.changeSet, parsed.value); assert.equal(receipt.changeSetHash, typeHash(parsed.value));
  assert.equal(receipt.requestHash, typeHash(bodyFor(input))); assert.notEqual(receipt.requestHash, typeHash(bodyFor(parsed.value)));
  for (const edge of receipt.after.edges) { assert.deepEqual(edge.values.attributes.tags, ['z', 'a', 'z']); assert.deepEqual(edge.values.allowedIdentityIds, [actor, ownerId]); }
});

test('protected claims, success namespaces, preparation and receipts deny direct runtime writes and fabricated GUC authority', async () => {
  const f = await fixture();
  await scope(tenant, actor, async tx => {
    const rows = await sql<{ relname: string; relrowsecurity: boolean; relforcerowsecurity: boolean; owner: string }>`SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity,r.rolname AS owner FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE c.relname LIKE 'relation_graph_%' OR c.relname IN ('relation_participations','relation_participation_revisions','relation_type_preparations')`.execute(tx);
    for (const row of rows.rows.filter(r => !r.relname.includes('pkey') && !r.relname.includes('key') && r.relrowsecurity)) { assert.ok(row.relforcerowsecurity); assert.notEqual(row.owner, 'gc_app'); }
  });
  for (const table of ['relation_graph_operations', 'relation_graph_operation_asset_scope', 'relation_graph_operation_edge_claims', 'relation_graph_operation_binding_claims']) {
    await assert.rejects(() => scope(tenant, actor, tx => tx.selectFrom(table).selectAll().execute()), sqlCode('42501'));
  }
  for (const table of ['relation_type_preparations', 'relation_graph_receipts', 'relation_graph_receipt_edges', 'relation_graph_receipt_bindings']) {
    await assert.rejects(() => scope(tenant, actor, tx => tx.deleteFrom(table).execute()), sqlCode('42501'));
  }
  await assert.rejects(() => scope(tenant, actor, async tx => {
    await sql`SELECT set_config('gc.graph_operation',${randomUUID()},true)`.execute(tx);
    await tx.insertInto('idempotency').values({ tenant_id: tenant, actor_id: actor, operation: 'relation-migration.execute', key: randomUUID(), request_hash: '0'.repeat(64), response: JSON.stringify({ receipt: {} }) }).execute();
  }), sqlCode('23514'));
  await assert.rejects(() => scope(tenant, actor, tx => sql`SELECT gc_relation_graph_charge(${randomUUID()}::uuid,'{}'::jsonb)`.execute(tx)), sqlCode('42501'));
  assert.deepEqual((await counts(f)).bindings, []);
});

test('positive first publication atomically enrolls every eligible zero-edge participant and produces normalized immutable receipt references', async () => {
  const { f, change } = await positive(); const receipt = await execute(f, change);
  assert.equal(receipt.coverage, 'complete-authorized-affected-graph');
  assert.equal(receipt.edgeOutcomes.length, 2); assert.equal(receipt.bindingOutcomes.length, 2); assert.equal(receipt.assetIdentities.length, 2);
  const state = await counts(f); assert.equal(state.heads[0]!.current_version, 1); assert.equal(state.bindings.length, 2);
  await scope(tenant, actor, async tx => {
    const edges = await tx.selectFrom('relation_graph_receipt_edges').selectAll().where('operation_id', '=', receipt.id).execute(); assert.equal(edges.length, 2);
    for (const edge of edges) {
      const h = await tx.selectFrom('relation_revisions').select('snapshot').where('relation_id', '=', edge.relation_id).where('version', '=', edge.after_version).executeTakeFirstOrThrow();
      // Tuple hashes bind the actual immutable snapshot, never graph endpoint projection.
      assert.equal(edge.after_tuple_hash, typeHash(h.snapshot)); assert.equal(edge.before_tuple_hash, null); assert.equal(edge.role, 'changed');
    }
    const bindings = await tx.selectFrom('relation_graph_receipt_bindings').selectAll().where('operation_id', '=', receipt.id).execute(); assert.equal(bindings.length, 2);
    for (const b of bindings) assert.equal(b.after_tuple_hash, typeHash((await tx.selectFrom('relation_participation_revisions').select('snapshot').where('binding_id', '=', b.binding_id).where('version', '=', b.after_version).executeTakeFirstOrThrow()).snapshot));
  });
  assert.deepEqual(await scope(foreign, other, tx => tx.selectFrom('relation_graph_receipts').selectAll().where('id', '=', receipt.id).execute()), []);
});

test('zero-degree minima reject missing creation and direct later typed asset INSERT atomically without admission bypass', async () => {
  const first = await positive(); const incomplete = structuredClone(first.change); (incomplete.relationTargets[0]!.plan.creations as unknown[]).pop();
  const before = await counts(first.f); await assert.rejects(() => execute(first.f, incomplete), sqlCode('23514')); assert.deepEqual(await counts(first.f), before);
  const { f, change } = await positive(); await execute(f, change); const original = await counts(f), id = randomUUID();
  await assert.rejects(() => scope(tenant, actor, async tx => {
    const row = await tx.insertInto('assets').values({ tenant_id: tenant, id, external_id: id, name: 'Synthetic forbidden zero-edge participant', qualified_name: id,
      type: 'dataset', observed_at: new Date(), model_id: f.modelId, model_version: 1, attributes: '{}', type_state: 'draft' }).returningAll().executeTakeFirstOrThrow();
    await tx.insertInto('asset_revisions').values({ tenant_id: tenant, asset_id: id, version: 1, snapshot: JSON.stringify(assetView(row)) }).execute();
  }), sqlCode('23514'));
  assert.deepEqual(await counts(f), original); assert.deepEqual(await scope(tenant, actor, tx => tx.selectFrom('assets').select('id').where('id', '=', id).execute()), []);
});

test('repinning retains stable identity and exact old policy/revision FKs while all active bindings move to the publication head', async () => {
  const { f, change } = await positive(); await execute(f, change); const source = await currentPlan(f), before = await counts(f);
  const definition = { ...f.definition, formatVersion: 2, version: 2, label: 'Revised synthetic label' } as RelationTypeDefinitionV2;
  const next = { ...source, edges: source.edges.map(e => ({ ...e, action: 'repin' as const, targetVersion: 2, values: values() })),
    bindings: source.bindings.map(b => ({ ...b, action: 'repin' as const, targetVersion: 2 })) };
  const receipt = await execute(f, { ...emptyChange(), relationTargets: [{ kind: 'publish', expectedHeadVersion: 1, definition, plan: next }] });
  assert.equal(receipt.bindingOutcomes.length, 2);
  await scope(tenant, actor, async tx => {
    for (const old of before.edges) {
      const rows = await tx.selectFrom('relation_revisions').selectAll().where('relation_id', '=', old.id).orderBy('version').execute();
      assert.deepEqual(rows.map(r => r.relation_type_version), [1, 2]); assert.equal(rows[0]!.snapshot.label, f.definition.label); assert.equal(rows[1]!.snapshot.label, definition.label);
    }
    for (const old of before.bindings) assert.deepEqual((await tx.selectFrom('relation_participation_revisions').selectAll().where('binding_id', '=', old.id).orderBy('version').execute()).map(r => r.relation_type_version), [1, 2]);
  });
});

test('governed attributes named ownerId and allowedIdentityIds never become lock principals or ACL authority', async () => {
  const attrs = { ownerId: { type: 'text' }, allowedIdentityIds: { type: 'object', properties: { ownerId: { type: 'text' }, allowedIdentityIds: { type: 'text' } } } } as const;
  const arbitrary = { ownerId: 'not-a-uuid', allowedIdentityIds: { ownerId: 'ordinary text', allowedIdentityIds: 'also not an array' } };
  const f = await fixture({ assetAttributes: attrs, assetValues: arbitrary, definition: { attributes: attrs } });
  const row = await scope(tenant, actor, tx => insertEdge(tx, f, candidate(f, 0, 1, values(arbitrary))));
  const change: GraphChangeSet = { ...emptyChange(), assetChanges: [{ kind: 'assign', assetId: f.assets[0]!.id, expectedVersion: 1, modelId: f.modelId, modelVersion: 1, attributes: arbitrary, ownerId: null }],
    relationTargets: [{ kind: 'repair', expectedHeadVersion: 1, definition: null, plan: plan(f.typeId, { sourceVersions: [1], edges: [{ relationId: row.id, expectedVersion: 1, action: 'repair', values: values(arbitrary) }] }) }] };
  const receipt = await execute(f, change); assert.equal(receipt.edgeOutcomes.length, 1);
  assert.deepEqual(receipt.after.edges[0]!.values.attributes, arbitrary);
  await assert.rejects(() => execute(f, { ...change, assetChanges: [], relationTargets: [{ kind: 'repair', expectedHeadVersion: 1, definition: null,
    plan: plan(f.typeId, { sourceVersions: [1], edges: [{ relationId: row.id, expectedVersion: 2, action: 'repair', values: { ...values(arbitrary), ownerId: other } }] }) }] }), sqlCode('23514'));
});

test('unconsumed or reused claims, early constraints and forged transformed values cannot commit', async () => {
  const { f, change } = await positive(), before = await counts(f);
  await assert.rejects(() => scope(tenant, actor, tx => begin(tx, change)), sqlCode('23514'));
  await assert.rejects(() => execute(f, change, { afterBegin: tx => sql`SET CONSTRAINTS ALL IMMEDIATE`.execute(tx).then(() => {}) }), sqlCode('23514'));
  await assert.rejects(() => execute(f, change, { beforeSeal: async tx => {
    const r = await tx.selectFrom('relations').selectAll().where('relation_type_id', '=', f.typeId).executeTakeFirstOrThrow();
    await tx.updateTable('relations').set({ version: r.version + 1, updated_at: new Date(), state: 'active' }).where('id', '=', r.id).execute();
  } }), sqlCode('23514'));
  assert.deepEqual(await counts(f), before);
});

test('sealed outcomes prohibit extra canonical/journal/idempotency writes and missing success rolls everything back', async () => {
  const { f, change } = await positive(), before = await counts(f), ordinaryKey = randomUUID();
  await scope(tenant, actor, tx => tx.insertInto('idempotency').values({ tenant_id: tenant, actor_id: actor, operation: 'unrelated.synthetic', key: ordinaryKey, request_hash: typeHash({}), response: '{}' }).execute());
  for (const mutate of [async (tx: any) => { await tx.updateTable('assets').set({ name: 'Unclaimed post-seal edit' }).where('id', '=', f.assets[0]!.id).execute(); },
    async (tx: any) => { await record(tx, principal, 'synthetic.after_seal', randomUUID(), 1, {}, correlation); },
    async (tx: any) => { await tx.deleteFrom('idempotency').where('key', '=', ordinaryKey).execute(); }]) {
    await assert.rejects(() => execute(f, change, { afterSeal: mutate }), sqlCode('23514'));
    assert.deepEqual(await counts(f), before);
  }
  await assert.rejects(() => scope(tenant, actor, async tx => { const started = await begin(tx, change); await persist(tx, f, change, started); await seal(tx, f, started.operation.id); }), sqlCode('23514'));
  assert.deepEqual(await counts(f), before);
});

test('exact idempotency response is immutable and same request retries only once after injected full rollback', async () => {
  const { f, change } = await positive(), before = await counts(f), key = randomUUID(), operationId = randomUUID();
  await assert.rejects(() => execute(f, change, { key, operationId, afterSeal: async () => { throw Error('synthetic receipt rollback'); } }), /synthetic receipt rollback/);
  assert.deepEqual(await counts(f), before);
  const receipt = await execute(f, change, { key, operationId }), replay = await execute(f, change, { key }); assert.deepEqual(replay, receipt);
  await scope(tenant, actor, async tx => { assert.equal((await tx.selectFrom('relation_graph_receipts').select('id').where('id', '=', operationId).execute()).length, 1); });
  const success = () => scope(tenant, actor, tx => tx.selectFrom('idempotency').selectAll()
    .where('tenant_id', '=', tenant).where('actor_id', '=', actor).where('operation', '=', 'relation-migration.execute').where('key', '=', key).executeTakeFirstOrThrow());
  const stored = await success();
  assert.equal(stored.key, key); assert.equal(stored.request_hash, receipt.requestHash); assert.deepEqual(stored.response, { receipt });
  // Target this graph success exactly: other immutable families deliberately use
  // their own rejection codes, independent of PostgreSQL's tenant-row order.
  await assert.rejects(() => scope(tenant, actor, tx => tx.deleteFrom('idempotency')
    .where('tenant_id', '=', tenant).where('actor_id', '=', actor).where('operation', '=', 'relation-migration.execute').where('key', '=', key).execute()), sqlCode('42501'));
  assert.deepEqual(await success(), stored, 'Rejected deletion preserves the exact graph success key and response');
  for (const table of ['relation_revisions', 'relation_participation_revisions', 'relation_graph_receipts']) {
    await assert.rejects(() => scope(tenant, actor, tx => tx.deleteFrom(table).execute()), sqlCode('42501'));
  }
});

test('complete dispositions, exact source pins and binding head requirements reject subset and downgrade forgeries', async () => {
  const { f, change } = await positive(); await execute(f, change); const base = await currentPlan(f), before = await counts(f);
  const definition = { ...f.definition, formatVersion: 2, version: 2 } as RelationTypeDefinitionV2;
  for (const malformed of [{ ...base, edges: base.edges.slice(1) }, { ...base, bindings: base.bindings.slice(1) }, { ...base, sourceVersions: [] },
    { ...base, bindings: base.bindings.map(b => ({ ...b, action: 'repin' as const, targetVersion: 1 })) }]) {
    await assert.rejects(() => execute(f, { ...emptyChange(), relationTargets: [{ kind: 'publish', expectedHeadVersion: 1, definition, plan: malformed }] }), sqlCode('23514'));
    assert.deepEqual(await counts(f), before);
  }
});

test('hidden complete scope refuses before size diagnostics and bounded source amplification rolls back claims', async () => {
  const large = { text: 'x'.repeat(45000), more: 'y'.repeat(45000) };
  const f = await fixture({ assetAttributes: { text: { type: 'text', maxLength: 65536 }, more: { type: 'text', maxLength: 65536 } }, assetValues: large });
  const change: GraphChangeSet = { ...emptyChange(), assetChanges: [{ kind: 'assign', assetId: f.assets[0]!.id, expectedVersion: 1,
    modelId: f.modelId, modelVersion: 1, ownerId: null, attributes: large }] };
  await scope(tenant, actor, tx => tx.updateTable('assets').set({ visibility: 'restricted', allowed_identities: JSON.stringify([ownerId]) }).where('id', '=', f.assets[1]!.id).execute());
  await assert.rejects(() => execute(f, change), (error: any) => error.code === '42501' && error.message === 'RELATION_SCOPE_UNAVAILABLE');
  await scope(tenant, actor, tx => tx.updateTable('assets').set({ visibility: 'tenant', allowed_identities: '[]' }).where('id', '=', f.assets[1]!.id).execute());
  const before = await counts(f); await assert.rejects(() => execute(f, change), (error: any) => error.code === '54000' && error.message === 'RELATION_PROFILE_LIMIT'); assert.deepEqual(await counts(f), before);
});

test('small governed intent cannot materialize oversized unrelated canonical metadata or its immutable revision', async () => {
  const f = await fixture({ count: 1, assetMetadata: { syntheticDescription: 'x'.repeat(280000) } });
  const change: GraphChangeSet = { ...emptyChange(), assetChanges: [{ kind: 'transition', assetId: f.assets[0]!.id, expectedVersion: 1, state: 'active' }] };
  assert.ok(Buffer.byteLength(JSON.stringify(bodyFor(change))) < 1024);
  const before = await counts(f);
  await assert.rejects(() => execute(f, change), (error: any) => error.code === '54000' && error.message === 'RELATION_PROFILE_LIMIT');
  assert.deepEqual(await counts(f), before);
  await scope(tenant, actor, async tx => {
    assert.equal((await tx.selectFrom('assets').select('version').where('id', '=', f.assets[0]!.id).executeTakeFirstOrThrow()).version, 1);
    assert.equal((await tx.selectFrom('asset_revisions').select('version').where('asset_id', '=', f.assets[0]!.id).execute()).length, 1);
  });
});

test('graph asset revision requires exact full canonical snapshot and rejects unrelated or future immutable rows', async () => {
  const f = await fixture(), asset = f.assets[0]!;
  const change: GraphChangeSet = { ...emptyChange(), assetChanges: [{ kind: 'transition', assetId: asset.id, expectedVersion: 1, state: 'active' }] };
  const before = await counts(f);
  for (const forged of [{ description: 'Invented description' }, { metadata: { invented: true } }, { status: 'deleted' },
    { sourceId: randomUUID() }, { observedAt: '2000-01-01T00:00:00.000Z' }, { updatedAt: '2000-01-01T00:00:00.000Z' },
    { ownerName: 'Invented display name' }, { sourceName: 'Invented source name' }]) {
    await assert.rejects(() => scope(tenant, actor, async tx => {
      await begin(tx, change);
      const row = await tx.updateTable('assets').set({ type_state: 'active', version: 2, updated_at: new Date() }).where('id', '=', asset.id).returningAll().executeTakeFirstOrThrow();
      await tx.insertInto('asset_revisions').values({ tenant_id: tenant, asset_id: asset.id, version: 2, snapshot: JSON.stringify({ ...assetView(row), ...forged }) }).execute();
    }), sqlCode('23514'));
    assert.deepEqual(await counts(f), before);
  }
  for (const [id, version] of [[asset.id, 3], [f.assets[1]!.id, 2]] as const) {
    await assert.rejects(() => scope(tenant, actor, async tx => {
      await begin(tx, change);
      await tx.insertInto('asset_revisions').values({ tenant_id: tenant, asset_id: id, version, snapshot: JSON.stringify({ ...assetView(asset), id, version }) }).execute();
    }), sqlCode('23514'));
  }
  const receipt = await execute(f, change); assert.equal(receipt.assetRevisions.find(row => row.assetId === asset.id)!.after.version, 2);
});

test('graph journals reject unrelated, wrong-action and duplicate pairs and require each changed asset journal', async () => {
  const f = await fixture(), asset = f.assets[0]!;
  const change: GraphChangeSet = { ...emptyChange(), assetChanges: [{ kind: 'transition', assetId: asset.id, expectedVersion: 1, state: 'active' }] }, before = await counts(f);
  for (const [action, id, version] of [['asset.type_transitioned', randomUUID(), 2], ['asset.model_assigned', asset.id, 2], ['asset.type_transitioned', asset.id, 99]] as const) {
    await assert.rejects(() => execute(f, change, { afterBegin: tx => record(tx, principal, action, id, version, {}, correlation) }), sqlCode('23514'));
    assert.deepEqual(await counts(f), before);
  }
  await assert.rejects(() => execute(f, change, { beforeSeal: tx => record(tx, principal, 'asset.type_transitioned', asset.id, 2, {}, correlation) }), sqlCode('23514'));
  await assert.rejects(() => scope(tenant, actor, async tx => {
    const started = await begin(tx, change);
    const row = await tx.updateTable('assets').set({ type_state: 'active', version: 2, updated_at: new Date() }).where('id', '=', asset.id).returningAll().executeTakeFirstOrThrow();
    await tx.insertInto('asset_revisions').values({ tenant_id: tenant, asset_id: asset.id, version: 2, snapshot: JSON.stringify(assetView(row)) }).execute();
    await seal(tx, f, started.operation.id);
  }), (error: any) => error.code === '23514' && /paired journal/.test(error.message));
  assert.deepEqual(await counts(f), before);
  const receipt = await execute(f, change); assert.equal(receipt.assetChanges.changes.length, 1);
});

test('empty nested authored migration still requires its model journal and exact legacy plus typed receipts before outer finalization', async () => {
  const f = await fixture({ count: 0 });
  const source = await scope(tenant, actor, tx => tx.selectFrom('asset_type_versions').selectAll().where('model_id', '=', f.modelId).where('version', '=', 1).executeTakeFirstOrThrow());
  const resolved = resolveAssetType({ ...source.definition, version: 2 }, []); assert.ok(resolved.ok); if (!resolved.ok) throw Error('Invalid nested target');
  const target = resolved.value;
  const nestedPlan = { formatVersion: 1 as const, typeId: f.assetTypeId,
    attributes: { formatVersion: 1 as const, modelId: f.modelId, targetVersion: 2, sourceVersions: [], operations: [], acknowledgedChanges: [] },
    owner: { default: 'preserve' as const, overrides: [] }, lifecycle: { onUnmapped: 'preserve' as const, mappings: [] }, acknowledgedPolicyChanges: [] };
  const change: GraphChangeSet = { ...emptyChange(), assetTypeMigrations: [{ expectedHeadVersion: 1, definition: target.definition, plan: nestedPlan }] };
  const run = (includeJournal: boolean) => scope(tenant, actor, async tx => {
    const key = randomUUID(), result = await once(tx, principal, 'relation-migration.execute', key, bodyFor(change), async () => {
      const started = await begin(tx, change, randomUUID(), key), id = started.typeMigrations[0]!.migrationId, digest = typeHash({ syntheticNested: id });
      await tx.insertInto('governance_model_versions').values({ tenant_id: tenant, model_id: f.modelId, version: 2, definition: JSON.stringify(target.model), definition_hash: typeHash(target.model), created_by: actor }).execute();
      await tx.insertInto('asset_type_versions').values({ tenant_id: tenant, model_id: f.modelId, version: 2, definition: JSON.stringify(target.definition), definition_hash: typeHash(target.definition), resolved: JSON.stringify(target), resolution_hash: typeHash(target), created_by: actor }).execute();
      await tx.updateTable('governance_models').set({ current_version: 2 }).where('id', '=', f.modelId).execute();
      await tx.insertInto('governance_model_migrations').values({ tenant_id: tenant, id, model_id: f.modelId, from_version: 1, to_version: 2, plan: JSON.stringify(nestedPlan.attributes), plan_hash: typeHash(nestedPlan.attributes), preview_digest: digest, asset_count: 0, assets: '[]', executed_by: actor }).execute();
      await tx.insertInto('asset_type_migrations').values({ tenant_id: tenant, id, model_id: f.modelId, type_id: f.assetTypeId, from_version: 1, to_version: 2,
        plan: JSON.stringify(nestedPlan), plan_hash: typeHash(nestedPlan), preview_digest: digest, definition_hash: typeHash(target.definition), resolution_hash: typeHash(target),
        source_resolutions: JSON.stringify([{ version: 1, resolutionHash: source.resolution_hash }]), asset_count: 0, assets: '[]', executed_by: actor }).execute();
      if (includeJournal) await record(tx, principal, 'model.type_migrated', f.modelId, 2, { migrationId: id }, correlation);
      return { receipt: await seal(tx, f, started.operation.id) };
    });
    await sql`SET CONSTRAINTS ALL IMMEDIATE`.execute(tx); return result.receipt;
  });
  await assert.rejects(() => run(false), (error: any) => error.code === '23514' && /paired journal/.test(error.message));
  assert.equal((await scope(tenant, actor, tx => tx.selectFrom('governance_models').select('current_version').where('id', '=', f.modelId).executeTakeFirstOrThrow())).current_version, 1);
  const receipt = await run(true); assert.equal(receipt.nestedTypeReceipts.length, 1); assert.equal(receipt.assetRevisions.length, 0);
});

test('direct ordinary edits keep exact old own-value pins while format2 structural admission remains shared', async () => {
  const f = await fixture({ definition: { attributes: { amount: { type: 'number', integer: true, maximum: 20 } } } });
  const row = await scope(tenant, actor, tx => insertEdge(tx, f, candidate(f, 0, 1, values({ amount: 5 }))));
  const definition = { ...f.definition, formatVersion: 2, version: 2, attributes: { amount: { type: 'number', integer: true, maximum: 10 } } } as RelationTypeDefinitionV2;
  const change: GraphChangeSet = { ...emptyChange(), relationTargets: [{ kind: 'publish', expectedHeadVersion: 1, definition,
    plan: plan(f.typeId, { sourceVersions: [1], edges: [{ relationId: row.id, expectedVersion: 1, action: 'preserve' }] }) }] };
  await execute(f, change);
  await assert.rejects(() => scope(tenant, actor, tx => tx.updateTable('relations').set({ relation_type_version: 2, version: 2, updated_at: new Date() }).where('id', '=', row.id).execute()), sqlCode('23514'));
  assert.equal((await counts(f)).edges[0]!.relation_type_version, 1);
});

test('SQL independently derives rename, enum and exact integer-to-decimal transforms and rejects target-valid invented values', async () => {
  const f = await fixture({ definition: { attributes: { amount: { type: 'number', integer: true }, kind: { type: 'enum', values: ['a'] }, name: { type: 'text' } } } });
  const edge = await scope(tenant, actor, tx => insertEdge(tx, f, candidate(f, 0, 1, values({ amount: 12, kind: 'a', name: 'Synthetic exact name' }))));
  const definition = { ...f.definition, formatVersion: 2, version: 2, attributes: { amount: { type: 'decimal' }, kind: { type: 'enum', values: ['b'] }, caption: { type: 'text' } } } as RelationTypeDefinitionV2;
  const migrationPlan = plan(f.typeId, { sourceVersions: [1], edges: [{ relationId: edge.id, expectedVersion: 1, action: 'migrate' }], transform: {
    attributes: { formatVersion: 1, modelId: f.definition.id, targetVersion: 2, sourceVersions: [1], acknowledgedChanges: [
      { code: 'type_changed', path: '/attributes/amount' }, { code: 'constraints_changed', path: '/attributes/kind' }, { code: 'attribute_removed', path: '/attributes/name' }],
      operations: [{ op: 'convert', path: ['amount'], conversion: 'safeIntegerToDecimal', onMissing: 'error' },
        { op: 'enumMap', path: ['kind'], mappings: [{ from: 'a', to: 'b' }], onMissing: 'error', onUnmapped: 'error' },
        { op: 'rename', from: ['name'], to: ['caption'], onMissing: 'error' }] }, owner: { default: 'preserve', overrides: [] }, lifecycle: { onUnmapped: 'preserve', mappings: [] } } });
  const change: GraphChangeSet = { ...emptyChange(), relationTargets: [{ kind: 'publish', expectedHeadVersion: 1, definition, plan: migrationPlan }] };
  const before = await counts(f), correct = values({ amount: '12', kind: 'b', caption: 'Synthetic exact name' });
  await assert.rejects(() => execute(f, change, { transformed: new Map([[edge.id, { ...correct, attributes: { ...correct.attributes, amount: '13' } }]]) }), sqlCode('23514'));
  assert.deepEqual(await counts(f), before);
  const receipt = await execute(f, change, { transformed: new Map([[edge.id, correct]]) });
  assert.deepEqual(receipt.after.edges[0]!.values, correct); assert.equal(receipt.after.edges[0]!.relationTypeVersion, 2);
});

test('asset-only transition projects preserved edges and bindings to final endpoints without changing their canonical or immutable histories', async () => {
  const { f, change } = await positive(); await execute(f, change);
  const before = await counts(f), changedAsset = f.assets[0]!.id;
  const history = () => scope(tenant, actor, async tx => ({
    edges: await tx.selectFrom('relation_revisions').selectAll().where('relation_type_id', '=', f.typeId).orderBy('relation_id').orderBy('version').execute(),
    bindings: await tx.selectFrom('relation_participation_revisions').selectAll().where('relation_type_id', '=', f.typeId).orderBy('binding_id').orderBy('version').execute(),
  }));
  const originalHistory = await history();
  const receipt = await execute(f, { ...emptyChange(), assetChanges: [{ kind: 'transition', assetId: changedAsset, expectedVersion: 1, state: 'active' }] });
  const after = await counts(f); assert.deepEqual(after.edges, before.edges); assert.deepEqual(after.bindings, before.bindings);
  assert.deepEqual(await history(), originalHistory);
  assert.equal(receipt.after.endpoints.find(e => e.assetId === changedAsset)!.assetVersion, 2);
  for (const edge of receipt.after.edges) {
    assert.equal(edge.version, 1);
    assert.equal(edge.sourceAssetVersion, edge.sourceAssetId === changedAsset ? 2 : 1);
    assert.equal(edge.targetAssetVersion, edge.targetAssetId === changedAsset ? 2 : 1);
  }
  for (const binding of receipt.after.bindings) {
    assert.equal(binding.version, 1); assert.equal(binding.assetVersion, binding.assetId === changedAsset ? 2 : 1);
  }
  for (const outcome of [...receipt.edgeOutcomes, ...receipt.bindingOutcomes]) {
    assert.equal(outcome.role, 'validation-only'); assert.equal(outcome.action, 'preserve');
    assert.equal(outcome.before!.version, 1); assert.equal(outcome.after.version, 1);
    assert.equal(outcome.beforeTupleHash, outcome.afterTupleHash);
  }
  for (const row of originalHistory.edges) {
    assert.equal(row.snapshot.source.assetVersion, 1); assert.equal(row.snapshot.target.assetVersion, 1);
    assert.equal(receipt.edgeOutcomes.find(e => e.after.id === row.relation_id)!.afterTupleHash, typeHash(row.snapshot));
  }
  for (const row of originalHistory.bindings) {
    assert.equal(row.snapshot.assetVersion, 1);
    assert.equal(receipt.bindingOutcomes.find(b => b.after.id === row.binding_id)!.afterTupleHash, typeHash(row.snapshot));
  }
});

test('joint endpoint transition, tombstone and release retain current-before endpoint revisions while receipt records actual after asset revision', async () => {
  const { f, change } = await positive(); await execute(f, change); const source = await currentPlan(f);
  const definition = { ...f.definition, formatVersion: 2, version: 2, cardinality: { outgoing: { min: 0, max: 2 }, incoming: { min: 0, max: null } } } as RelationTypeDefinitionV2;
  const proposal: GraphChangeSet = { ...emptyChange(), assetChanges: [{ kind: 'transition', assetId: f.assets[0]!.id, expectedVersion: 1, state: 'active' }],
    relationTargets: [{ kind: 'publish', expectedHeadVersion: 1, definition, plan: { ...source, acknowledgedPolicyChanges: ['cardinality_changed'],
      edges: source.edges.map(e => ({ ...e, action: 'tombstone' as const, reason: 'Synthetic joint retirement' })),
      bindings: source.bindings.map(b => ({ ...b, action: 'release' as const, reason: 'Explicit zero-minimum policy' })) } }] };
  const receipt = await execute(f, proposal); assert.equal(receipt.assetChanges.changes[0]!.toAssetVersion, 2);
  await scope(tenant, actor, async tx => {
    for (const outcome of receipt.edgeOutcomes) {
      const history = await tx.selectFrom('relation_revisions').select('snapshot').where('relation_id', '=', outcome.after.id).where('version', '=', 2).executeTakeFirstOrThrow();
      assert.equal(history.snapshot.source.assetVersion, 1); assert.equal(history.snapshot.target.assetVersion, 1);
      assert.equal(history.snapshot.status, 'tombstoned');
    }
    for (const outcome of receipt.bindingOutcomes) assert.equal((await tx.selectFrom('relation_participation_revisions').select('snapshot').where('binding_id', '=', outcome.after.id).where('version', '=', 2).executeTakeFirstOrThrow()).snapshot.assetVersion, 1);
    assert.equal((await tx.selectFrom('assets').select('version').where('id', '=', f.assets[0]!.id).executeTakeFirstOrThrow()).version, 2);
  });
});

after(async () => { await db.destroy(); });
