// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { db, scope, sql, type Tx } from '../../packages/db/src/index.ts';
import { resolveAssetType } from '../../packages/domain/src/asset-type.ts';
import type { RelationTypeDefinition } from '../../packages/domain/src/relation-contracts.ts';
import { assetView, record, stableString } from '../../apps/api/src/repository.ts';

const tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', foreign = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const actor = '10000000-0000-4000-8000-000000000001', other = '10000000-0000-4000-8000-000000000005';
const principal = { id: actor, name: 'Synthetic relation storage steward', tenantId: tenant, permissions: ['catalog:read', 'catalog:write', 'models:read', 'models:write', 'audit:read'] };
const hash = (value: unknown) => createHash('sha256').update(stableString(value)).digest('hex');
const code = (...expected: string[]) => (error: any) => expected.includes(error.code);
type Row = Record<string, any>;
interface Fixture { modelId: string; assetTypeId: string; assets: Row[]; typeId: string; definition: RelationTypeDefinition }

async function definition(tx: Tx, fixture: Fixture, proposed: RelationTypeDefinition, create = false) {
  if (create) await tx.insertInto('relation_types').values({ tenant_id: tenant, id: proposed.id, type_id: fixture.typeId, current_version: 1, created_by: actor }).execute();
  await tx.insertInto('relation_type_versions').values({ tenant_id: tenant, relation_type_id: fixture.typeId, version: proposed.version,
    definition: JSON.stringify(proposed), definition_hash: hash(proposed), created_by: actor }).execute();
  if (!create) await tx.updateTable('relation_types').set({ current_version: proposed.version }).where('type_id', '=', fixture.typeId).execute();
  await record(tx, principal, create ? 'relation_type.created' : 'relation_type.published', proposed.id, proposed.version, { definitionHash: hash(proposed) }, 'synthetic-relation-storage');
}
async function fixture(overrides: Partial<RelationTypeDefinition> = {}): Promise<Fixture> {
  const modelId = 'rel_endpoint_' + randomUUID().replaceAll('-', ''), assetTypeId = randomUUID(), typeId = randomUUID();
  const result = resolveAssetType({ formatVersion: 1, id: modelId, version: 1, parents: [], attributes: {}, overrideAttributes: [], requiredOwner: false,
    lifecycle: { initial: 'draft', states: ['draft', 'active'], transitions: [{ from: 'draft', to: 'active' }, { from: 'active', to: 'draft' }] } }, []);
  assert.equal(result.ok, true); if (!result.ok) throw Error('Invalid synthetic endpoint definition');
  const value: Fixture = { modelId, assetTypeId, typeId, assets: [], definition: { formatVersion: 1, id: 'relation_' + randomUUID().replaceAll('-', ''), version: 1,
    label: 'Synthetic dependency', inverseLabel: 'Synthetic inverse', direction: 'directed', sourceTypes: [{ typeId: assetTypeId, includeDescendants: false }],
    targetTypes: [{ typeId: assetTypeId, includeDescendants: false }], sourceStates: null, targetStates: null,
    cardinality: { outgoing: { min: 0, max: null }, incoming: { min: 0, max: null } }, allowSelf: false, cycles: 'allow',
    attributes: { amount: { type: 'decimal', required: true } }, requiredOwner: false,
    lifecycle: { initial: 'draft', states: ['draft', 'active'], transitions: [{ from: 'draft', to: 'active' }] }, ...overrides } };
  await scope(tenant, actor, async tx => {
    await tx.insertInto('governance_models').values({ tenant_id: tenant, id: modelId, type_id: assetTypeId, current_version: 1, created_by: actor }).execute();
    await tx.insertInto('governance_model_versions').values({ tenant_id: tenant, model_id: modelId, version: 1, definition: JSON.stringify(result.value.model), definition_hash: hash(result.value.model), created_by: actor }).execute();
    await tx.insertInto('asset_type_versions').values({ tenant_id: tenant, model_id: modelId, version: 1, definition: JSON.stringify(result.value.definition), definition_hash: hash(result.value.definition),
      resolved: JSON.stringify(result.value), resolution_hash: hash(result.value), created_by: actor }).execute();
    for (let index = 0; index < 4; index += 1) {
      const id = randomUUID(); const row = await tx.insertInto('assets').values({ tenant_id: tenant, id, external_id: id,
        name: `Synthetic endpoint ${index}`, qualified_name: `synthetic.relations.${id}`, type: 'dataset', observed_at: new Date(),
        model_id: modelId, model_version: 1, type_state: 'draft', attributes: '{}', version: 1 }).returningAll().executeTakeFirstOrThrow();
      await tx.insertInto('asset_revisions').values({ tenant_id: tenant, asset_id: id, version: 1, snapshot: JSON.stringify(assetView(row)) }).execute();
      value.assets.push(row);
    }
    value.assets.sort((a, b) => a.id.localeCompare(b.id));
    await definition(tx, value, value.definition, true);
  });
  return value;
}
function candidate(f: Fixture, source = 0, target = 1, values: Row = {}): Row {
  const time = new Date().toISOString();
  return { tenant_id: tenant, id: randomUUID(), relation_type_id: f.typeId, relation_type_version: f.definition.version,
    source_asset_id: f.assets[source].id, target_asset_id: f.assets[target].id, attributes: { amount: '12345678901234567890.123456789' },
    owner_id: null, state: f.definition.lifecycle.initial, version: 1, status: 'active', valid_from: null, valid_to: null,
    visibility: 'tenant', allowed_identities: [], created_by: actor, updated_by: actor, created_at: time, updated_at: time,
    provenance: { origin: 'asserted', source: { kind: 'manual', identityId: actor }, authority: 'manual-assertion', precedence: null,
      actorId: actor, assertedAt: time, ingestedAt: time, sourceObservedAt: null, sourceVersion: null, sourceRunId: null, confidence: null }, ...values };
}
async function revision(tx: Tx, f: Fixture, row: Row, mutate: (snapshot: Row) => void = () => {}) {
  const endpoint = async (id: string) => {
    const a = await tx.selectFrom('assets').selectAll().where('id', '=', id).executeTakeFirstOrThrow();
    const m = await tx.selectFrom('governance_models').select('type_id').where('id', '=', a.model_id).executeTakeFirstOrThrow();
    return { assetId: id, name: a.name, assetVersion: a.version, typeId: m.type_id, modelId: a.model_id, modelVersion: a.model_version, state: a.type_state };
  };
  const iso = (v: unknown) => v === null ? null : new Date(v as string).toISOString();
  const pin = await tx.selectFrom('relation_type_versions').select('definition').where('relation_type_id', '=', f.typeId).where('version', '=', row.relation_type_version).executeTakeFirstOrThrow();
  const snap: Row = { id: row.id, relationTypeId: row.relation_type_id, relationTypeKey: f.definition.id, relationTypeVersion: row.relation_type_version, version: row.version,
    source: await endpoint(row.source_asset_id), target: await endpoint(row.target_asset_id), direction: pin.definition.direction, label: pin.definition.label, inverseLabel: pin.definition.inverseLabel,
    attributes: row.attributes, ownerId: row.owner_id, state: row.state, validFrom: iso(row.valid_from), validTo: iso(row.valid_to),
    visibility: row.visibility, allowedIdentityIds: row.allowed_identities, status: row.status, provenance: row.provenance,
    createdAt: iso(row.created_at), createdBy: row.created_by, updatedAt: iso(row.updated_at), updatedBy: row.updated_by };
  mutate(snap);
  await tx.insertInto('relation_revisions').values({ tenant_id: tenant, relation_id: row.id, version: row.version, snapshot: JSON.stringify(snap), recorded_by: actor, recorded_at: row.updated_at }).execute();
}
async function insert(tx: Tx, f: Fixture, input: Row, options: { noRevision?: boolean; noJournal?: boolean; mutate?: (snapshot: Row) => void } = {}) {
  const row = await tx.insertInto('relations').values({ ...input, attributes: JSON.stringify(input.attributes), allowed_identities: JSON.stringify(input.allowed_identities), provenance: JSON.stringify(input.provenance) }).returningAll().executeTakeFirstOrThrow();
  if (!options.noRevision) await revision(tx, f, row, options.mutate);
  if (!options.noJournal) await record(tx, principal, 'relation.created', row.id, row.version, { relationTypeVersion: row.relation_type_version }, 'synthetic-relation-storage');
  return row;
}
async function mutate(tx: Tx, f: Fixture, row: Row, values: Row, action = 'relation.updated', noRevision = false) {
  const updated = await tx.updateTable('relations').set({ ...values, version: row.version + 1, updated_at: new Date(), updated_by: actor }).where('id', '=', row.id).returningAll().executeTakeFirstOrThrow();
  if (!noRevision) await revision(tx, f, updated);
  await record(tx, principal, action, row.id, updated.version, {}, 'synthetic-relation-storage'); return updated;
}
async function counter() { return scope(tenant, actor, async tx => (await tx.selectFrom('tenant_graph_revisions').select('revision').executeTakeFirstOrThrow()).revision); }
async function absent(id: string) {
  await scope(tenant, actor, async tx => {
    for (const [table, key] of [['relations', 'id'], ['relation_revisions', 'relation_id'], ['relation_allowed_identities', 'relation_id'], ['audit', 'resource_id'], ['outbox', 'resource_id']]) {
      assert.deepEqual(await tx.selectFrom(table).selectAll().where(key!, '=', id).execute(), [], `${table} rolled back`);
    }
  });
}

test('relation storage derives exact immutable revision ACLs, preserves tenant RLS and denies runtime history/counter writes', async () => {
  const f = await fixture(); const input = candidate(f, 0, 1, { visibility: 'restricted', allowed_identities: [actor] });
  const row = await scope(tenant, actor, tx => insert(tx, f, input));
  await scope(tenant, actor, async tx => {
    assert.deepEqual(await tx.selectFrom('relation_allowed_identities').selectAll().where('relation_id', '=', row.id).execute(), [{ tenant_id: tenant, relation_id: row.id, version: 1, identity_id: actor }]);
    const meta = await sql<{ relname: string; relrowsecurity: boolean; relforcerowsecurity: boolean; owner: string }>`SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity,r.rolname AS owner FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner WHERE c.relname IN ('relation_types','relation_type_versions','relation_type_endpoints','relations','relation_revisions','relation_allowed_identities','tenant_graph_revisions','relation_validation_work')`.execute(tx);
    assert.equal(meta.rows.length, 8); for (const item of meta.rows) { assert.ok(item.relrowsecurity && item.relforcerowsecurity); assert.notEqual(item.owner, 'gc_app'); }
  });
  assert.deepEqual(await scope(foreign, other, tx => tx.selectFrom('relations').selectAll().where('id', '=', row.id).execute()), []);
  for (const table of ['relation_type_versions', 'relation_type_endpoints', 'relation_revisions', 'relation_allowed_identities', 'tenant_graph_revisions']) {
    await assert.rejects(() => scope(tenant, actor, tx => tx.deleteFrom(table).execute()), code('42501'));
    await assert.rejects(() => scope(tenant, actor, tx => sql`TRUNCATE ${sql.table(table)}`.execute(tx)), code('42501'));
  }
  await assert.rejects(() => scope(tenant, actor, tx => tx.updateTable('tenant_graph_revisions').set({ revision: '0' }).execute()), code('42501'));
  await assert.rejects(() => scope(tenant, actor, tx => tx.insertInto('relation_allowed_identities').values({ tenant_id: tenant, relation_id: row.id, version: 1, identity_id: actor }).execute()), code('42501'));
  await assert.rejects(() => scope(tenant, actor, tx => tx.selectFrom('relation_validation_work').selectAll().execute()), code('42501'));
});

test('relation definition storage rejects strict shape, positive minima, invalid endpoints and hash forgery atomically', async () => {
  const f = await fixture();
  const changes: ((d: any) => void)[] = [d => { d.cardinality.outgoing.min = 1; }, d => { d.unrecognized = true; }, d => { d.sourceTypes[0].extra = true; },
    d => { d.sourceTypes[0].typeId = randomUUID(); }, d => { d.lifecycle.transitions.push({ from: 'active', to: 'missing' }); },
    d => { d.direction = 'undirected'; d.targetStates = ['draft']; }, d => { d.direction = null; }, d => { d.cycles = null; },
    d => { d.attributes.amount.type = 'executable'; }, d => { delete d.inverseLabel; }];
  for (const change of changes) {
    const proposal = structuredClone({ ...f.definition, version: 2 }); change(proposal);
    await assert.rejects(() => scope(tenant, actor, tx => definition(tx, f, proposal)), code('23514', '23503'));
  }
  await assert.rejects(() => scope(tenant, actor, tx => tx.insertInto('relation_type_versions').values({ tenant_id: tenant, relation_type_id: f.typeId, version: 2,
    definition: JSON.stringify({ ...f.definition, version: 2 }), definition_hash: '0'.repeat(64), created_by: actor }).execute()), code('23514'));
  await scope(tenant, actor, async tx => { assert.equal((await tx.selectFrom('relation_types').select('current_version').where('type_id', '=', f.typeId).executeTakeFirstOrThrow()).current_version, 1); });
});

test('relation revision and journal completeness reject forged snapshots, missing history and omitted intermediate revisions', async () => {
  const f = await fixture();
  for (const mutateSnapshot of [(s: Row) => { s.source.name = 'Forged historical name'; }, (s: Row) => { s.target.assetVersion = 2; },
    (s: Row) => { s.attributes.amount = '7'; }, (s: Row) => { s.label = 'Forged type label'; }, (s: Row) => { s.provenance.actorId = other; }, (s: Row) => { s.extra = true; }]) {
    const value = candidate(f); const before = await counter();
    await assert.rejects(() => scope(tenant, actor, tx => insert(tx, f, value, { mutate: mutateSnapshot })), code('23514', '23503'));
    await absent(value.id); assert.equal(await counter(), before);
  }
  for (const options of [{ noRevision: true }, { noJournal: true }]) { const value = candidate(f); await assert.rejects(() => scope(tenant, actor, tx => insert(tx, f, value, options)), code('23514', '23503')); await absent(value.id); }
  const inconsistentEndpoint = candidate(f);
  await assert.rejects(() => scope(tenant, actor, async tx => {
    await tx.updateTable('assets').set({ name: 'Unrecorded endpoint rename' }).where('id', '=', inconsistentEndpoint.source_asset_id).execute();
    await insert(tx, f, inconsistentEndpoint, { mutate: s => { s.source.name = f.assets[0]!.name; } });
  }), code('23514'));
  await absent(inconsistentEndpoint.id);
  const row = await scope(tenant, actor, tx => insert(tx, f, candidate(f)));
  await assert.rejects(() => scope(tenant, actor, async tx => { const second = await mutate(tx, f, row, { owner_id: actor }, 'relation.updated', true); await mutate(tx, f, second, { owner_id: null }); }), code('23514'));
  await scope(tenant, actor, async tx => { assert.equal((await tx.selectFrom('relations').select('version').where('id', '=', row.id).executeTakeFirstOrThrow()).version, 1); });
});

test('live uniqueness spans type pins and undirected orientation while tombstones preserve history and allow a distinct reassertion', async () => {
  const f = await fixture({ direction: 'undirected' }); const row = await scope(tenant, actor, tx => insert(tx, f, candidate(f)));
  await scope(tenant, actor, tx => definition(tx, f, { ...f.definition, version: 2, label: 'Compatible next label' }));
  await assert.rejects(() => scope(tenant, actor, tx => insert(tx, f, candidate(f, 0, 1, { relation_type_version: 2 }))), code('23505'));
  await assert.rejects(() => scope(tenant, actor, tx => insert(tx, f, candidate(f, 1, 0, { relation_type_version: 2 }))), code('23514'));
  const tombstone = await scope(tenant, actor, tx => mutate(tx, f, row, { status: 'tombstoned' }, 'relation.tombstoned'));
  await assert.rejects(() => scope(tenant, actor, tx => mutate(tx, f, tombstone, { status: 'active' })), code('23514'));
  const replacement = await scope(tenant, actor, tx => insert(tx, f, candidate(f, 0, 1, { relation_type_version: 2 })));
  assert.notEqual(replacement.id, row.id);
  await scope(tenant, actor, async tx => { const rows = await tx.selectFrom('relation_revisions').select('snapshot').where('relation_id', '=', row.id).orderBy('version').execute(); assert.equal(rows.length, 2); assert.equal(rows[0]!.snapshot.label, f.definition.label); assert.equal(rows[1]!.snapshot.status, 'tombstoned'); });
});

test('cardinality includes restricted, future and expired live edges across unchanged pins and ignores neither lifecycle nor validity', async () => {
  const f = await fixture({ cardinality: { outgoing: { min: 0, max: 1 }, incoming: { min: 0, max: 1 } } });
  const row = await scope(tenant, actor, tx => insert(tx, f, candidate(f, 0, 1, { visibility: 'restricted', allowed_identities: [actor], valid_from: '2000-01-01T00:00:00.000Z', valid_to: '2001-01-01T00:00:00.000Z' })));
  await scope(tenant, actor, tx => mutate(tx, f, row, { state: 'active' }, 'relation.transitioned'));
  await scope(tenant, actor, tx => definition(tx, f, { ...f.definition, version: 2, label: 'Same limits next pin' }));
  for (const [source, target] of [[0, 2], [2, 1]]) { const value = candidate(f, source, target, { relation_type_version: 2, valid_from: '2099-01-01T00:00:00.000Z' });
    await assert.rejects(() => scope(tenant, actor, tx => insert(tx, f, value)), code('23514')); await absent(value.id); }
  await assert.rejects(() => scope(tenant, actor, tx => definition(tx, f, { ...f.definition, version: 3, cardinality: { outgoing: { min: 0, max: 2 }, incoming: { min: 0, max: 2 } } })), code('23514'));
});

test('publication checks both the previous head and old pins while allowing scalar constraints satisfied by every live value', async () => {
  const f = await fixture(); await scope(tenant, actor, tx => insert(tx, f, candidate(f)));
  const second = { ...f.definition, version: 2, attributes: { ...f.definition.attributes, note: { type: 'text' as const, maxLength: 50 } } };
  await scope(tenant, actor, tx => definition(tx, f, second));
  // The only edge is still pinned to version one, but removing version two's
  // attribute must not bypass the previous-head migration requirement.
  await assert.rejects(() => scope(tenant, actor, tx => definition(tx, f, { ...f.definition, version: 3 })), code('23514'));
  await scope(tenant, actor, tx => definition(tx, f, { ...second, version: 3, attributes: { ...second.attributes, amount: { type: 'decimal', required: true, precision: 40, scale: 9 } } }));
  await assert.rejects(() => scope(tenant, actor, tx => definition(tx, f, { ...second, version: 4, attributes: { ...second.attributes, note: { type: 'text', required: true } } })), code('23514'));
});

test('ordinary edits retain old-pin scalar rules and every publication validates its own exact target', async () => {
  const f = await fixture({ attributes: { amount: { type: 'number', required: true } } });
  let row = await scope(tenant, actor, tx => insert(tx, f, candidate(f, 0, 1, { attributes: { amount: 1 } })));
  const bounded = { ...f.definition, version: 2, attributes: { amount: { type: 'number' as const, required: true, maximum: 10 } } };
  await scope(tenant, actor, tx => definition(tx, f, bounded));
  row = await scope(tenant, actor, tx => mutate(tx, f, row, { attributes: JSON.stringify({ amount: 20 }) }));
  assert.equal(row.relation_type_version, 1); assert.equal(row.attributes.amount, 20);
  await assert.rejects(() => scope(tenant, actor, tx => definition(tx, f, { ...bounded, version: 3, label: 'Still incompatible target maximum' })), code('23514'));
  await scope(tenant, actor, tx => definition(tx, f, { ...bounded, version: 3, attributes: { amount: { type: 'number', required: true, maximum: 30 } } }));
  // The final head would accept 20, but version four itself cannot be published
  // with maximum 10 and hidden behind a second publication in the same commit.
  const before = await counter();
  await assert.rejects(() => scope(tenant, actor, async tx => {
    await definition(tx, f, { ...bounded, version: 4 });
    await definition(tx, f, { ...bounded, version: 5, attributes: { amount: { type: 'number', required: true, maximum: 30 } } });
  }), code('23514')); assert.equal(await counter(), before);
  await scope(tenant, actor, async tx => { assert.equal((await tx.selectFrom('relation_types').select('current_version').where('type_id', '=', f.typeId).executeTakeFirstOrThrow()).current_version, 3); });
});

test('directed and undirected acyclic policies reject complete cycles and rollback both edges while allowed cycles persist', async () => {
  for (const direction of ['directed', 'undirected'] as const) {
    const f = await fixture({ direction, cycles: 'acyclic' });
    await scope(tenant, actor, async tx => { await insert(tx, f, candidate(f, 0, 1)); await insert(tx, f, candidate(f, 1, 2)); });
    const value = candidate(f, direction === 'directed' ? 2 : 0, direction === 'directed' ? 0 : 2);
    await assert.rejects(() => scope(tenant, actor, tx => insert(tx, f, value)), code('23514')); await absent(value.id);
    const pair = [candidate(f, 2, 3), candidate(f, direction === 'directed' ? 3 : 0, direction === 'directed' ? 0 : 3)];
    await assert.rejects(() => scope(tenant, actor, async tx => { for (const item of pair) await insert(tx, f, item); }), code('23514')); for (const item of pair) await absent(item.id);
  }
  const f = await fixture({ cycles: 'allow' }); await scope(tenant, actor, async tx => { await insert(tx, f, candidate(f, 0, 1)); await insert(tx, f, candidate(f, 1, 0)); });
  for (const direction of ['directed', 'undirected'] as const) {
    const self = await fixture({ direction, allowSelf: true, cardinality: { outgoing: { min: 0, max: 1 }, incoming: { min: 0, max: 1 } } });
    await scope(tenant, actor, tx => insert(tx, self, candidate(self, 0, 0)));
    await assert.rejects(() => scope(tenant, actor, tx => insert(tx, self, candidate(self, 0, 1))), code('23514'));
  }
});

test('endpoint guards see the final atomic proposed state and reject incompatible endpoint pins without journal or fence changes', async () => {
  const f = await fixture({ sourceStates: ['draft'], targetStates: ['draft'] }); const row = await scope(tenant, actor, tx => insert(tx, f, candidate(f)));
  const before = await counter();
  await assert.rejects(() => scope(tenant, actor, tx => tx.updateTable('assets').set({ type_state: 'active', version: 2 }).where('id', '=', row.source_asset_id).execute()), code('23514'));
  assert.equal(await counter(), before);
  await scope(tenant, actor, async tx => {
    // An intermediate state is not a proposed final state: all deferred checks
    // inspect both current canonical endpoints only when this transaction ends.
    await tx.updateTable('assets').set({ type_state: 'active' }).where('id', '=', row.source_asset_id).execute();
    await tx.updateTable('assets').set({ type_state: 'active' }).where('id', '=', row.target_asset_id).execute();
    await tx.updateTable('assets').set({ type_state: 'draft' }).where('id', 'in', [row.source_asset_id, row.target_asset_id]).execute();
  });
  await assert.rejects(() => scope(tenant, actor, tx => tx.updateTable('assets').set({ model_id: null, model_version: null, type_state: null }).where('id', '=', row.target_asset_id).execute()), code('23514'));
});

test('descendant matching uses the endpoint exact historical ancestry instead of the child current head or structural similarity', async () => {
  const f = await fixture(), childId = 'relation_child_' + randomUUID().replaceAll('-', ''), childTypeId = randomUUID();
  await scope(tenant, actor, async tx => {
    const parent = await tx.selectFrom('asset_type_versions').select('definition').where('model_id', '=', f.modelId).where('version', '=', 1).executeTakeFirstOrThrow();
    const child1 = resolveAssetType({ formatVersion: 1, id: childId, version: 1, parents: [{ id: f.modelId, version: 1 }], attributes: {}, overrideAttributes: [], requiredOwner: false, lifecycle: null }, [parent.definition]);
    const child2 = resolveAssetType({ formatVersion: 1, id: childId, version: 2, parents: [], attributes: {}, overrideAttributes: [], requiredOwner: false, lifecycle: parent.definition.lifecycle }, []);
    assert.ok(child1.ok && child2.ok); if (!child1.ok || !child2.ok) throw Error('Invalid synthetic historical ancestry');
    await tx.insertInto('governance_models').values({ tenant_id: tenant, id: childId, type_id: childTypeId, current_version: 1, created_by: actor }).execute();
    for (const resolved of [child1.value, child2.value]) {
      await tx.insertInto('governance_model_versions').values({ tenant_id: tenant, model_id: childId, version: resolved.definition.version,
        definition: JSON.stringify(resolved.model), definition_hash: hash(resolved.model), created_by: actor }).execute();
      await tx.insertInto('asset_type_versions').values({ tenant_id: tenant, model_id: childId, version: resolved.definition.version,
        definition: JSON.stringify(resolved.definition), definition_hash: hash(resolved.definition), resolved: JSON.stringify(resolved), resolution_hash: hash(resolved), created_by: actor }).execute();
    }
    await tx.updateTable('governance_models').set({ current_version: 2 }).where('id', '=', childId).execute();
    const changed = await tx.updateTable('assets').set({ model_id: childId, model_version: 1, version: 2 }).where('id', '=', f.assets[0]!.id).returningAll().executeTakeFirstOrThrow();
    await tx.insertInto('asset_revisions').values({ tenant_id: tenant, asset_id: changed.id, version: 2, snapshot: JSON.stringify(assetView(changed)) }).execute();
  });
  const nominalOnly = candidate(f);
  await assert.rejects(() => scope(tenant, actor, tx => insert(tx, f, nominalOnly)), code('23514')); await absent(nominalOnly.id);
  const descendantPolicy = { ...f.definition, version: 2, sourceTypes: [{ typeId: f.assetTypeId, includeDescendants: true }] };
  await scope(tenant, actor, tx => definition(tx, f, descendantPolicy)); f.definition = descendantPolicy;
  await scope(tenant, actor, tx => insert(tx, f, candidate(f)));
  // Child head two has no parent. Its endpoint remains eligible under pin one,
  // but advancing that endpoint to pin two would break its existing relation.
  const before = await counter();
  await assert.rejects(() => scope(tenant, actor, async tx => {
    const changed = await tx.updateTable('assets').set({ model_version: 2, version: 3 }).where('id', '=', f.assets[0]!.id).returningAll().executeTakeFirstOrThrow();
    await tx.insertInto('asset_revisions').values({ tenant_id: tenant, asset_id: changed.id, version: 3, snapshot: JSON.stringify(assetView(changed)) }).execute();
  }), code('23514')); assert.equal(await counter(), before);
});

test('source status and metadata changes invalidate graph fences while preserving asserted canonical values and immutable histories', async () => {
  const f = await fixture(); const row = await scope(tenant, actor, tx => insert(tx, f, candidate(f)));
  const original = await scope(tenant, actor, tx => tx.selectFrom('relation_revisions').selectAll().where('relation_id', '=', row.id).execute()); const before = await counter();
  await scope(tenant, actor, async tx => {
    const changed = await tx.updateTable('assets').set({ name: 'Synthetic source rename', status: 'unavailable', version: 2, updated_at: new Date() }).where('id', '=', row.source_asset_id).returningAll().executeTakeFirstOrThrow();
    await tx.insertInto('asset_revisions').values({ tenant_id: tenant, asset_id: changed.id, version: 2, snapshot: JSON.stringify(assetView(changed)) }).execute();
  });
  assert.notEqual(await counter(), before);
  await scope(tenant, actor, async tx => { assert.deepEqual(await tx.selectFrom('relations').selectAll().where('id', '=', row.id).execute(), [row]); assert.deepEqual(await tx.selectFrom('relation_revisions').selectAll().where('relation_id', '=', row.id).execute(), original); });
});

test('relation field storage rejects invalid typed values, intervals, transitions, provenance and cross-tenant membership references', async () => {
  const f = await fixture();
  for (const fields of [{ attributes: {} }, { attributes: { amount: 1 } }, { attributes: { amount: '1.00' } }, { attributes: { amount: '1', unknown: true } },
    { valid_from: '2026-01-01T00:00:00.000Z', valid_to: '2026-01-01T00:00:00.000Z' }, { valid_from: '2026-01-01T00:00:00.000001Z' },
    { state: 'active' }, { owner_id: other }, { visibility: 'restricted', allowed_identities: [actor, other] }, { provenance: { origin: 'imported' } }]) {
    const value = candidate(f, 0, 1, fields); await assert.rejects(() => scope(tenant, actor, tx => insert(tx, f, value)), code('23514', '23503')); await absent(value.id);
  }
  const row = await scope(tenant, actor, tx => insert(tx, f, candidate(f)));
  await assert.rejects(() => scope(tenant, actor, tx => mutate(tx, f, row, { source_asset_id: f.assets[2]!.id })), code('23514'));
});

after(async () => { await db.destroy(); });
