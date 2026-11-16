// SPDX-License-Identifier: Apache-2.0
/** Real SQL fixture/persistence only. Expected values are caller intent, never private claims. */
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { scope, sql, type Tx } from '../../packages/db/src/index.ts';
import type { Principal } from '../../packages/authz/src/index.ts';
import { resolveAssetType } from '../../packages/domain/src/asset-type.ts';
import { typeHash } from '../../packages/domain/src/asset-type-policy.ts';
import type { RelationDefinition, RelationTypeDefinitionV2 } from '../../packages/domain/src/relation-contracts.ts';
import type { GraphChangeSet, GraphOperationBeginResult, RelationMigrationPlan, RelationMigrationReceipt, RelationMigrationValues, RelationPreparationView } from '../../packages/domain/src/relation-migration-contracts.ts';
import { assetView, once, record } from '../../apps/api/src/repository.ts';
export const tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
export const actor = '10000000-0000-4000-8000-000000000001';
export const ownerId = '10000000-0000-4000-8000-000000000002';
export const permissions = ['catalog:read', 'catalog:write', 'models:read', 'models:write', 'audit:read'];
export const principal: Principal = { tenantId: tenant, id: actor, name: 'Synthetic participation steward', permissions };
export const correlation = 'synthetic-participation-storage';
export const sqlCode = (...values: string[]) => (error: any) => values.includes(error.code);
export type Row = Record<string, any>;
export interface Fixture { principal: Principal; modelId: string; assetTypeId: string; assets: Row[]; typeId: string; definition: RelationDefinition }
export const emptyChange = (): GraphChangeSet => ({ formatVersion: 1, relationTargets: [], assetChanges: [], assetTypeMigrations: [], repairsReceiptId: null });
export function values(attributes: RelationMigrationValues['attributes'] = {}, owner: string | null = null): RelationMigrationValues {
  return { attributes, ownerId: owner, state: 'draft', validFrom: null, validTo: null, visibility: 'tenant', allowedIdentityIds: [] };
}
export function plan(typeId: string, overrides: Partial<RelationMigrationPlan> = {}): RelationMigrationPlan {
  return { formatVersion: 1, relationTypeId: typeId, sourceVersions: [], transform: null, edges: [], creations: [], bindings: [],
    enrollment: 'complete-eligible-assets', acknowledgedPolicyChanges: [], ...overrides };
}
export async function writeDefinition(tx: Tx, f: Fixture, definition: RelationDefinition, create = false) {
  const p = f.principal;
  if (create) await tx.insertInto('relation_types').values({ tenant_id: p.tenantId, id: definition.id, type_id: f.typeId, current_version: 1, created_by: p.id }).execute();
  await tx.insertInto('relation_type_versions').values({ tenant_id: p.tenantId, relation_type_id: f.typeId, version: definition.version,
    definition: JSON.stringify(definition), definition_hash: typeHash(definition), created_by: p.id }).execute();
  if (!create) await tx.updateTable('relation_types').set({ current_version: definition.version }).where('type_id', '=', f.typeId).execute();
  await record(tx, p, create ? 'relation_type.created' : 'relation_type.published', definition.id, definition.version, { definitionHash: typeHash(definition) }, correlation);
}
export async function fixture(options: { principal?: Principal; count?: number; publish?: boolean; definition?: Partial<RelationDefinition>; assetAttributes?: Record<string, any>; assetValues?: Row; assetMetadata?: Row } = {}): Promise<Fixture> {
  const p = options.principal ?? principal, modelId = 'participation_endpoint_' + randomUUID().replaceAll('-', '');
  const assetTypeId = randomUUID(), typeId = randomUUID();
  const resolved = resolveAssetType({ formatVersion: 1, id: modelId, version: 1, parents: [], attributes: options.assetAttributes ?? {}, overrideAttributes: [], requiredOwner: false,
    lifecycle: { initial: 'draft', states: ['draft', 'active'], transitions: [{ from: 'draft', to: 'active' }, { from: 'active', to: 'draft' }] } }, []);
  assert.ok(resolved.ok); if (!resolved.ok) throw Error('Invalid synthetic authored fixture');
  const f: Fixture = { principal: p, modelId, assetTypeId, typeId, assets: [], definition: { formatVersion: 1,
    id: 'participation_' + randomUUID().replaceAll('-', ''), version: 1, label: 'Synthetic dependency', inverseLabel: 'Synthetic inverse',
    direction: 'directed', sourceTypes: [{ typeId: assetTypeId, includeDescendants: false }], targetTypes: [{ typeId: assetTypeId, includeDescendants: false }],
    sourceStates: null, targetStates: null, cardinality: { outgoing: { min: 0, max: null }, incoming: { min: 0, max: null } }, allowSelf: false,
    cycles: 'allow', attributes: {}, requiredOwner: false, lifecycle: { initial: 'draft', states: ['draft', 'active'], transitions: [{ from: 'draft', to: 'active' }] }, ...options.definition } as RelationDefinition };
  await scope(p.tenantId, p.id, async tx => {
    await tx.insertInto('governance_models').values({ tenant_id: p.tenantId, id: modelId, type_id: assetTypeId, current_version: 1, created_by: p.id }).execute();
    await tx.insertInto('governance_model_versions').values({ tenant_id: p.tenantId, model_id: modelId, version: 1, definition: JSON.stringify(resolved.value.model), definition_hash: typeHash(resolved.value.model), created_by: p.id }).execute();
    await tx.insertInto('asset_type_versions').values({ tenant_id: p.tenantId, model_id: modelId, version: 1, definition: JSON.stringify(resolved.value.definition), definition_hash: typeHash(resolved.value.definition), resolved: JSON.stringify(resolved.value), resolution_hash: typeHash(resolved.value), created_by: p.id }).execute();
    for (let index = 0; index < (options.count ?? 2); index += 1) {
      const id = randomUUID(); const row = await tx.insertInto('assets').values({ tenant_id: p.tenantId, id, external_id: id, name: `Synthetic participant ${index}`,
        qualified_name: `synthetic.participation.${id}`, type: 'dataset', observed_at: new Date(), model_id: modelId, model_version: 1,
        type_state: 'draft', attributes: JSON.stringify(options.assetValues ?? {}), metadata: JSON.stringify(options.assetMetadata ?? {}), version: 1 }).returningAll().executeTakeFirstOrThrow();
      await tx.insertInto('asset_revisions').values({ tenant_id: p.tenantId, asset_id: id, version: 1, snapshot: JSON.stringify(assetView(row)) }).execute(); f.assets.push(row);
    }
    f.assets.sort((a, b) => a.id.localeCompare(b.id));
    if (options.publish !== false) await writeDefinition(tx, f, f.definition, true);
  });
  return f;
}
export function candidate(f: Fixture, source = 0, target = 1, input: Partial<RelationMigrationValues> = {}, id: string = randomUUID()): Row {
  const p = f.principal, time = new Date().toISOString(), v = { ...values(), ...input };
  return { tenant_id: p.tenantId, id, relation_type_id: f.typeId, relation_type_version: f.definition.version,
    source_asset_id: f.assets[source]!.id, target_asset_id: f.assets[target]!.id, attributes: v.attributes, owner_id: v.ownerId, state: v.state,
    valid_from: v.validFrom, valid_to: v.validTo, visibility: v.visibility, allowed_identities: v.allowedIdentityIds, status: 'active', version: 1,
    created_by: p.id, updated_by: p.id, created_at: time, updated_at: time,
    provenance: { origin: 'asserted', source: { kind: 'manual', identityId: p.id }, authority: 'manual-assertion', precedence: null,
      actorId: p.id, assertedAt: time, ingestedAt: time, sourceObservedAt: null, sourceVersion: null, sourceRunId: null, confidence: null } };
}
export async function edgeRevision(tx: Tx, f: Fixture, row: Row, endpointVersions?: { source: number; target: number }, alter: (value: Row) => void = () => {}) {
  const p = f.principal, iso = (value: unknown) => value == null ? null : new Date(value as string).toISOString();
  const endpoint = async (id: string, version?: number) => {
    const a = await tx.selectFrom('assets').selectAll().where('id', '=', id).executeTakeFirstOrThrow();
    const h = await tx.selectFrom('asset_revisions').select('snapshot').where('asset_id', '=', id).where('version', '=', version ?? a.version).executeTakeFirstOrThrow();
    const m = await tx.selectFrom('governance_models').select('type_id').where('id', '=', h.snapshot.modelId).executeTakeFirstOrThrow();
    return { assetId: id, name: h.snapshot.name, assetVersion: h.snapshot.version, typeId: m.type_id, modelId: h.snapshot.modelId, modelVersion: h.snapshot.modelVersion, state: h.snapshot.typeState };
  };
  const pin = await tx.selectFrom('relation_type_versions').select('definition').where('relation_type_id', '=', row.relation_type_id).where('version', '=', row.relation_type_version).executeTakeFirstOrThrow();
  const snapshot: Row = { id: row.id, relationTypeId: row.relation_type_id, relationTypeKey: f.definition.id, relationTypeVersion: row.relation_type_version,
    version: row.version, source: await endpoint(row.source_asset_id, endpointVersions?.source), target: await endpoint(row.target_asset_id, endpointVersions?.target),
    direction: pin.definition.direction, label: pin.definition.label, inverseLabel: pin.definition.inverseLabel, attributes: row.attributes, ownerId: row.owner_id, state: row.state,
    validFrom: iso(row.valid_from), validTo: iso(row.valid_to), visibility: row.visibility, allowedIdentityIds: row.allowed_identities, status: row.status,
    provenance: row.provenance, createdAt: iso(row.created_at), createdBy: row.created_by, updatedAt: iso(row.updated_at), updatedBy: row.updated_by };
  alter(snapshot);
  await tx.insertInto('relation_revisions').values({ tenant_id: p.tenantId, relation_id: row.id, version: row.version, snapshot: JSON.stringify(snapshot), recorded_by: p.id, recorded_at: row.updated_at }).execute();
  return snapshot;
}
export async function insertEdge(tx: Tx, f: Fixture, input: Row) {
  const row = await tx.insertInto('relations').values({ ...input, attributes: JSON.stringify(input.attributes), allowed_identities: JSON.stringify(input.allowed_identities), provenance: JSON.stringify(input.provenance) }).returningAll().executeTakeFirstOrThrow();
  await edgeRevision(tx, f, row); await record(tx, f.principal, 'relation.created', row.id, row.version, { relationTypeVersion: row.relation_type_version }, correlation); return row;
}
export async function prepare(f: Fixture, definition: RelationTypeDefinitionV2, key: string = randomUUID()) {
  return scope(f.principal.tenantId, f.principal.id, async tx => {
    const response = await once(tx, f.principal, 'relation-migration.prepare', key, { definition }, async () => {
      const result = await sql<{ value: RelationPreparationView }>`SELECT public.gc_relation_graph_prepare(${key},${JSON.stringify({ definition })}::jsonb,${correlation}) AS value`.execute(tx);
      const preparation = result.rows[0]!.value;
      await record(tx, f.principal, 'relation_preparation.created', preparation.id, 1, { definitionHash: preparation.definitionHash }, correlation);
      return { preparation };
    });
    await sql`SET CONSTRAINTS ALL IMMEDIATE`.execute(tx); return response.preparation;
  });
}
export const bodyFor = (changeSet: GraphChangeSet) => ({ changeSet, previewDigest: typeHash({ synthetic: 'Storage tests have no browser consent', changeSet }) });
export async function begin(tx: Tx, changeSet: GraphChangeSet, operationId: string = randomUUID(), key: string = randomUUID()): Promise<GraphOperationBeginResult> {
  const result = await sql<{ value: GraphOperationBeginResult }>`SELECT public.gc_relation_graph_begin(${operationId}::uuid,'relation-migration.execute',${key},${JSON.stringify(bodyFor(changeSet))}::jsonb,${correlation}) AS value`.execute(tx);
  return result.rows[0]!.value;
}
/** Persist only explicitly provided intent. SQL independently validates every exact outcome. */
export async function persist(tx: Tx, f: Fixture, changeSet: GraphChangeSet, started: GraphOperationBeginResult, transformed: ReadonlyMap<string, RelationMigrationValues> = new Map()) {
  const p = f.principal, beforeAssets = new Map((await tx.selectFrom('assets').selectAll().execute()).map(a => [a.id, a]));
  for (const target of changeSet.relationTargets) {
    assert.equal(target.plan.relationTypeId, f.typeId, 'Fixture targets one synthetic logical relation');
    if (target.kind !== 'repair') await writeDefinition(tx, f, target.definition, target.kind === 'create');
  }
  for (const change of changeSet.assetChanges) {
    const old = beforeAssets.get(change.assetId)!;
    const updates = change.kind === 'transition' ? { type_state: change.state } : { model_id: change.modelId, model_version: change.modelVersion, attributes: JSON.stringify(change.attributes), owner_id: change.ownerId };
    const row = await tx.updateTable('assets').set({ ...updates, version: old.version + 1, updated_at: new Date() }).where('id', '=', old.id).returningAll().executeTakeFirstOrThrow();
    await tx.insertInto('asset_revisions').values({ tenant_id: p.tenantId, asset_id: row.id, version: row.version, snapshot: JSON.stringify(assetView(row)) }).execute();
    await record(tx, p, change.kind === 'transition' ? 'asset.type_transitioned' : 'asset.model_assigned', row.id, row.version, {}, correlation);
  }
  for (const target of changeSet.relationTargets) {
    const head = target.kind === 'repair' ? target.expectedHeadVersion : target.definition.version;
    for (const disposition of target.plan.edges) {
      if (disposition.action === 'preserve') continue;
      const old = await tx.selectFrom('relations').selectAll().where('id', '=', disposition.relationId).executeTakeFirstOrThrow();
      const tombstone = ['tombstone', 'replace'].includes(disposition.action);
      const v = disposition.action === 'repair' || disposition.action === 'repin' ? disposition.values : transformed.get(disposition.relationId);
      const row = await tx.updateTable('relations').set({ version: old.version + 1, updated_by: p.id, updated_at: new Date(),
        status: tombstone ? 'tombstoned' : 'active', relation_type_version: ['repin', 'migrate'].includes(disposition.action) ? head : old.relation_type_version,
        ...(v ? { attributes: JSON.stringify(v.attributes), owner_id: v.ownerId, state: v.state, valid_from: v.validFrom, valid_to: v.validTo,
          visibility: v.visibility, allowed_identities: JSON.stringify(v.allowedIdentityIds) } : {}) }).where('id', '=', old.id).returningAll().executeTakeFirstOrThrow();
      await edgeRevision(tx, f, row, tombstone ? { source: beforeAssets.get(old.source_asset_id)!.version, target: beforeAssets.get(old.target_asset_id)!.version } : undefined);
      await record(tx, p, tombstone ? 'relation.tombstoned' : old.state !== row.state ? 'relation.transitioned' : 'relation.updated', row.id, row.version, {}, correlation);
    }
    for (const creation of target.plan.creations) {
      const id = started.creations.find(item => item.relationTypeId === f.typeId && item.key === creation.key)!.relationId;
      const input = candidate(f, 0, 1, creation.values, id);
      await insertEdge(tx, f, { ...input, source_asset_id: creation.sourceAssetId, target_asset_id: creation.targetAssetId, relation_type_version: head });
    }
    for (const disposition of target.plan.bindings) {
      if (disposition.action === 'preserve') continue;
      const old = await tx.selectFrom('relation_participations').selectAll().where('id', '=', disposition.bindingId).executeTakeFirstOrThrow();
      const asset = await tx.selectFrom('assets').select('version').where('id', '=', old.asset_id).executeTakeFirstOrThrow();
      const row = await tx.updateTable('relation_participations').set({ version: old.version + 1, updated_by: p.id, updated_at: new Date(),
        status: disposition.action === 'release' ? 'released' : 'active', relation_type_version: disposition.action === 'repin' ? disposition.targetVersion : old.relation_type_version,
        asset_version: disposition.action === 'release' ? beforeAssets.get(old.asset_id)!.version : asset.version }).where('id', '=', old.id).returningAll().executeTakeFirstOrThrow();
      await bindingRevision(tx, f, row, started.operation.id);
      await record(tx, p, disposition.action === 'release' ? 'relation_participation.released' : 'relation_participation.repinned', row.id, row.version, {}, correlation);
    }
    for (const enrollment of started.enrollments.filter(item => item.relationTypeId === f.typeId)) {
      const asset = await tx.selectFrom('assets').select('version').where('id', '=', enrollment.assetId).executeTakeFirstOrThrow(), time = new Date();
      const row = await tx.insertInto('relation_participations').values({ tenant_id: p.tenantId, id: enrollment.bindingId, relation_type_id: f.typeId, relation_type_version: head,
        asset_id: enrollment.assetId, asset_version: asset.version, side: enrollment.side, status: 'active', version: 1,
        created_by: p.id, updated_by: p.id, created_at: time, updated_at: time }).returningAll().executeTakeFirstOrThrow();
      await bindingRevision(tx, f, row, started.operation.id); await record(tx, p, 'relation_participation.enrolled', row.id, 1, {}, correlation);
    }
  }
}
export async function bindingRevision(tx: Tx, f: Fixture, row: Row, operationId: string) {
  const snapshot = { id: row.id, version: row.version, relationTypeId: row.relation_type_id, relationTypeVersion: row.relation_type_version,
    assetId: row.asset_id, assetVersion: row.asset_version, side: row.side, status: row.status, createdBy: row.created_by,
    createdAt: new Date(row.created_at).toISOString(), updatedBy: row.updated_by, updatedAt: new Date(row.updated_at).toISOString() };
  await tx.insertInto('relation_participation_revisions').values({ tenant_id: f.principal.tenantId, binding_id: row.id, version: row.version,
    snapshot: JSON.stringify(snapshot), operation_id: operationId, recorded_by: f.principal.id, recorded_at: row.updated_at }).execute();
}
export async function seal(tx: Tx, f: Fixture, operationId: string) {
  await record(tx, f.principal, 'relation_migration.executed', operationId, 1, {}, correlation);
  return (await sql<{ value: RelationMigrationReceipt }>`SELECT public.gc_relation_graph_seal(${operationId}::uuid) AS value`.execute(tx)).rows[0]!.value;
}
export async function execute(f: Fixture, changeSet: GraphChangeSet, options: { key?: string; operationId?: string; transformed?: ReadonlyMap<string, RelationMigrationValues>; persistChangeSet?: GraphChangeSet;
  afterBegin?: (tx: Tx, started: GraphOperationBeginResult) => Promise<void>; beforeSeal?: (tx: Tx, started: GraphOperationBeginResult) => Promise<void>;
  afterSeal?: (tx: Tx, receipt: RelationMigrationReceipt) => Promise<void> } = {}) {
  const key = options.key ?? randomUUID(), operationId = options.operationId ?? randomUUID(), p = f.principal;
  return scope(p.tenantId, p.id, async tx => {
    const result = await once(tx, p, 'relation-migration.execute', key, bodyFor(changeSet), async () => {
      const started = await begin(tx, changeSet, operationId, key); await options.afterBegin?.(tx, started);
      await persist(tx, f, options.persistChangeSet ?? changeSet, started, options.transformed); await options.beforeSeal?.(tx, started);
      const receipt = await seal(tx, f, operationId); await options.afterSeal?.(tx, receipt); return { receipt };
    });
    await sql`SET CONSTRAINTS ALL IMMEDIATE`.execute(tx); return result.receipt;
  });
}
