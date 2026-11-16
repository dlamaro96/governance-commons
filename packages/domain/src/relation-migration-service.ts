// SPDX-License-Identifier: Apache-2.0
import { randomUUID } from 'node:crypto';
import { sql, type Tx } from '../../db/src/index.ts';
import { Problem, type Principal } from '../../authz/src/index.ts';
import { modelPersistence, type ModelHooks } from './model-service.ts';
import { typeHash } from './asset-type-policy.ts';
import { persistPreparedTypeMigration } from './asset-type-migration-service.ts';
import { persistPreparedGraphAssetChange } from './graph-asset-persistence.ts';
import { parseGraphChangeSet, parseRelationMigrationContext, constructRelationGraphProposal, validateRelationGraphChange } from './relation-migration.ts';
import { bindingKey, edgeKey, deriveRequiredParticipation, degreeFor } from './relation-participation.ts';
import { GRAPH_WRITE, captureRelationMigration, graphRequest, graphPhysicalBudget, graphStale, graphStorage } from './relation-migration-store.ts';
import { relationDefinition, endpointTypeIdentities, lockRelationScope, relationQuery, relationView, iso, profileLimit, type Row } from './relation-store.ts';
import type { GraphChangeSet, GraphOperationBeginResult, RelationMigrationPreview, RelationMigrationProjection,
  RelationMigrationReceipt, RelationPreparationView, ParticipationBindingView, CompleteGraphSnapshot } from './relation-migration-contracts.ts';
import type { ValidationIssue } from './model.ts';

export function graphInvalid(issues?: readonly ValidationIssue[]): Problem {
  if (issues?.some(issue => issue.code === 'limit')) return profileLimit();
  const precondition = /^\/(?:relationTargets\/\d+\/(?:expectedHeadVersion|plan\/(?:edges|bindings)\/\d+\/expectedVersion|plan\/creations\/\d+\/(?:sourceAssetVersion|targetAssetVersion))|assetChanges\/\d+\/expectedVersion|assetTypeMigrations\/\d+\/expectedHeadVersion)$/;
  if (issues?.some(issue => issue.code === 'required' && precondition.test(issue.path)))
    return new Problem(428, 'VERSION_REQUIRED', 'Provide every expected head and resource revision before preview or execution.', issues);
  return new Problem(422, 'RELATION_MIGRATION_INVALID', 'Correct the complete graph plan and blocking target issues.', issues);
}
export async function getRelationMigrationContext(tx: Tx, p: Principal, input: unknown) {
  const parsed = parseRelationMigrationContext(input); if (!parsed.ok) throw graphInvalid(parsed.issues);
  return { context: (await captureRelationMigration(tx, p, parsed.value)).context };
}
function projection(changeSet: GraphChangeSet, before: CompleteGraphSnapshot, proposed: CompleteGraphSnapshot, policies: Parameters<typeof deriveRequiredParticipation>[0]['policies']): RelationMigrationProjection {
  const required = deriveRequiredParticipation({ admissionHeads: proposed.heads, policies, completeEligibleEndpointCandidates: proposed.endpoints, currentBindings: proposed.bindings });
  if (!required.ok) throw graphInvalid(required.issues);
  const oldEdges = new Map(before.edges.map(row => [edgeKey(row), row])), oldBindings = new Map(before.bindings.map(row => [bindingKey(row), row]));
  return { proposed, participation: required.value.map(row => ({ ...row, beforeDegree: degreeFor(before, row.relationTypeId, row.assetId, row.side), proposedDegree: degreeFor(proposed, row.relationTypeId, row.assetId, row.side) })),
    changedEdges: proposed.edges.filter(row => oldEdges.get(edgeKey(row))?.version !== row.version).map(row => ({ key: row.key, beforeVersion: oldEdges.get(edgeKey(row))?.version ?? null, afterVersion: row.version,
      action: row.key.kind === 'creation' ? 'create' : row.status === 'tombstoned' ? 'tombstone' : oldEdges.get(edgeKey(row))?.relationTypeVersion !== row.relationTypeVersion ? 'repin' : 'repair' })),
    changedBindings: proposed.bindings.filter(row => oldBindings.get(bindingKey(row))?.version !== row.version).map(row => ({ key: row.key, beforeVersion: oldBindings.get(bindingKey(row))?.version ?? null,
      afterVersion: row.version, action: row.key.kind === 'enrollment' ? 'enroll' : row.status === 'released' ? 'release' : 'repin' })),
    replacements: changeSet.relationTargets.flatMap(target => target.plan.edges.flatMap(row => row.action === 'replace' ? [{ predecessorId: row.relationId, relationTypeId: target.plan.relationTypeId, creationKey: row.creationKey }] : [])) };
}
async function prepare(tx: Tx, p: Principal, input: unknown) {
  const parsed = parseGraphChangeSet(input); if (!parsed.ok) throw graphInvalid(parsed.issues);
  const changeSet = parsed.value, captured = await captureRelationMigration(tx, p, graphRequest(changeSet), changeSet), { context, activity } = captured;
  const base = { context, changeSetHash: typeHash(changeSet) };
  let preview: RelationMigrationPreview;
  if (!context.assetPreparation || !context.proposedEndpoints) preview = { ...base, ready: false, previewDigest: null, targetIssues: context.targetIssues, projection: null };
  else {
    const constructed = constructRelationGraphProposal({ changeSet, before: context.before, policies: context.policies,
      preparedAssets: context.assetPreparation, proposedEndpoints: context.proposedEndpoints });
    if (!constructed.ok) preview = { ...base, ready: false, previewDigest: null, targetIssues: constructed.issues, projection: null };
    else {
      const checked = validateRelationGraphChange({ changeSet, completeRelationTypeIds: context.completeRelationTypeIds, policies: context.policies,
        preparedAssets: context.assetPreparation, before: context.before, proposed: constructed.value, activeOwnerIds: activity.active,
        tenantMemberIds: activity.members, actorId: p.id });
      const proposed = projection(changeSet, context.before, constructed.value, context.policies);
      preview = checked.ok ? { ...base, ready: true, targetIssues: [], projection: { ...proposed, changedEdges: checked.value.changedEdges, changedBindings: checked.value.changedBindings, replacements: checked.value.replacements },
        previewDigest: typeHash({ purpose: 'complete-relation-graph-migration', tenantId: p.tenantId, actorId: p.id, changeSet, context, proposed: constructed.value,
          activity: [...activity.active].sort(), members: [...activity.members].sort() }) }
        : { ...base, ready: false, previewDigest: null, targetIssues: checked.issues, projection: proposed };
    }
  }
  await graphPhysicalBudget(tx, preview);
  return { ...captured, changeSet, preview };
}
export async function previewRelationMigration(tx: Tx, p: Principal, input: unknown) {
  return { preview: (await prepare(tx, p, input)).preview };
}
/** Revision comparison only, over parsed intent and the captured complete scope.
 * This is neither authorization nor graph validation. Execution calls it after
 * fully authorized preparation; capture already checked head preconditions.
 * Preview retains editable target diagnostics. */
export function graphExpectedRevisionsMatch(changeSet: GraphChangeSet, before: CompleteGraphSnapshot): boolean {
  const endpoints = new Map(before.endpoints.map(row => [row.assetId, row.assetVersion]));
  const edges = new Map(before.edges.flatMap(row => row.key.kind === 'existing' && row.status === 'active'
    ? [[`${row.relationTypeId}:${row.key.relationId}`, row.version] as const] : []));
  const bindings = new Map(before.bindings.flatMap(row => row.key.kind === 'existing' && row.status === 'active'
    ? [[`${row.relationTypeId}:${row.key.bindingId}`, row.version] as const] : []));
  if (changeSet.assetChanges.some(row => endpoints.get(row.assetId) !== row.expectedVersion)) return false;
  for (const { plan } of changeSet.relationTargets) {
    if (plan.edges.some(row => edges.get(`${plan.relationTypeId}:${row.relationId}`) !== row.expectedVersion) ||
        plan.bindings.some(row => bindings.get(`${plan.relationTypeId}:${row.bindingId}`) !== row.expectedVersion) ||
        plan.creations.some(row => endpoints.get(row.sourceAssetId) !== row.sourceAssetVersion ||
          endpoints.get(row.targetAssetId) !== row.targetAssetVersion)) return false;
  }
  return true;
}
export async function prepareRelationType(tx: Tx, p: Principal, correlationId: string, idempotencyKey: string, input: unknown, hooks: ModelHooks) {
  await lockRelationScope(tx, p, GRAPH_WRITE);
  const resolved = relationDefinition(input);
  if (resolved.definition.formatVersion !== 2 || resolved.definition.version !== 1) throw graphInvalid();
  await endpointTypeIdentities(tx, p, resolved); await graphPhysicalBudget(tx, resolved);
  const result = await relationQuery(tx, () => sql<{ value: RelationPreparationView }>`SELECT public.gc_relation_graph_prepare(${idempotencyKey},${JSON.stringify({ definition: input })}::jsonb,${correlationId}) AS value`.execute(tx));
  const preparation = result.rows[0].value;
  await relationQuery(tx, () => hooks.record(tx, p, 'relation_preparation.created', preparation.id, 1, { definitionHash: preparation.definitionHash }, correlationId));
  return { preparation };
}
export function participationView(row: Row): ParticipationBindingView {
  return { id: row.id, version: row.version, relationTypeId: row.relation_type_id, relationTypeVersion: row.relation_type_version,
    assetId: row.asset_id, assetVersion: row.asset_version, side: row.side, status: row.status, createdBy: row.created_by,
    createdAt: iso(row.created_at), updatedBy: row.updated_by, updatedAt: iso(row.updated_at) };
}
async function persist(tx: Tx, p: Principal, correlationId: string, started: GraphOperationBeginResult,
  prepared: Awaited<ReturnType<typeof prepare>>, hooks: ModelHooks): Promise<void> {
  const { changeSet, preview, context } = prepared;
  if (!preview.ready || !context.assetPreparation) throw graphStorage();
  const operationId = started.operation.id;
  for (const target of changeSet.relationTargets) {
    if (target.kind === 'repair') continue;
    const typeId = target.plan.relationTypeId, definition = target.definition;
    if (target.kind === 'create') await relationQuery(tx, () => tx.insertInto('relation_types').values({ tenant_id: p.tenantId, id: definition.id, type_id: typeId, current_version: 1, created_by: p.id }).execute());
    await relationQuery(tx, () => tx.insertInto('relation_type_versions').values({ tenant_id: p.tenantId, relation_type_id: typeId, version: definition.version,
      definition: JSON.stringify(definition), definition_hash: typeHash(definition), created_by: p.id }).execute());
    if (target.kind === 'publish') await relationQuery(tx, () => tx.updateTable('relation_types').set({ current_version: definition.version })
      .where('tenant_id', '=', p.tenantId).where('type_id', '=', typeId).where('current_version', '=', target.expectedHeadVersion).returning('type_id').executeTakeFirstOrThrow());
    await relationQuery(tx, () => hooks.record(tx, p, target.kind === 'create' ? 'relation_type.created' : 'relation_type.published', definition.id, definition.version,
      { relationTypeId: typeId, operationId, definitionHash: typeHash(definition) }, correlationId));
  }
  for (const migration of started.typeMigrations) await relationQuery(tx, () => persistPreparedTypeMigration(tx, p, correlationId, started.operation,
    migration.modelId, migration.migrationId, context.assetPreparation!, hooks));
  for (const change of context.assetPreparation.changes) if (change.kind !== 'type-migrate') await relationQuery(tx, () => persistPreparedGraphAssetChange(tx, p, correlationId, started.operation, change, hooks));
  const ids = prepared.assets.map(row => row.id), currentAssets: Row[] = ids.length ? await relationQuery(tx, () => tx.selectFrom('assets').selectAll()
    .where('tenant_id', '=', p.tenantId).where('id', 'in', ids).execute()) : [];
  // The live-pair uniqueness constraint is immediate. Retire predecessors before
  // inserting successors, including a replacement that retains both endpoints.
  const edgeWrites = [...preview.projection.changedEdges].sort((left, right) => Number(right.action === 'tombstone') - Number(left.action === 'tombstone'));
  for (const change of edgeWrites) {
    const row = preview.projection.proposed.edges.find(row => edgeKey(row) === (change.key.kind === 'existing' ? `existing:${change.key.relationId}` : `creation:${change.key.relationTypeId}:${change.key.key}`))!;
    const old = row.key.kind === 'existing' ? prepared.edges.find(edge => edge.id === (row.key as { relationId: string }).relationId) : null;
    const key = row.key;
    const id = key.kind === 'existing' ? key.relationId : started.creations.find(item => item.relationTypeId === key.relationTypeId && item.key === key.key)?.relationId;
    if (!id) throw graphStorage(); const now = new Date(), values = row.values;
    const columns = { relation_type_version: row.relationTypeVersion, attributes: JSON.stringify(values.attributes), owner_id: values.ownerId, state: values.state,
      valid_from: values.validFrom, valid_to: values.validTo, visibility: values.visibility, allowed_identities: JSON.stringify(values.allowedIdentityIds), status: row.status,
      version: row.version, updated_by: p.id, updated_at: now };
    let written: Row;
    if (old) written = await relationQuery(tx, () => tx.updateTable('relations').set(columns).where('tenant_id', '=', p.tenantId).where('id', '=', id).where('version', '=', old.version).returningAll().executeTakeFirstOrThrow());
    else written = await relationQuery(tx, () => tx.insertInto('relations').values({ ...columns, tenant_id: p.tenantId, id, relation_type_id: row.relationTypeId,
      source_asset_id: row.sourceAssetId, target_asset_id: row.targetAssetId, created_by: p.id, created_at: now,
      provenance: JSON.stringify({ origin: 'asserted', source: { kind: 'manual', identityId: p.id }, authority: 'manual-assertion', precedence: null,
        actorId: p.id, assertedAt: now.toISOString(), ingestedAt: now.toISOString(), sourceObservedAt: null, sourceVersion: null, sourceRunId: null, confidence: null }) }).returningAll().executeTakeFirstOrThrow());
    const snapshot = await relationView(tx, p, written, row.status === 'tombstoned' ? prepared.assets : currentAssets);
    await graphPhysicalBudget(tx, snapshot);
    await relationQuery(tx, () => tx.insertInto('relation_revisions').values({ tenant_id: p.tenantId, relation_id: id, version: row.version,
      snapshot: JSON.stringify(snapshot), recorded_by: p.id, recorded_at: now }).execute());
    const action = !old ? 'relation.created' : row.status === 'tombstoned' ? 'relation.tombstoned' : old.state !== row.values.state ? 'relation.transitioned' : 'relation.updated';
    await relationQuery(tx, () => hooks.record(tx, p, action, id, row.version, { operationId, revision: row.version, relationTypeId: row.relationTypeId,
      relationTypeVersion: row.relationTypeVersion, snapshotHash: typeHash(snapshot) }, correlationId));
  }
  for (const change of preview.projection.changedBindings) {
    const key = change.key, row = preview.projection.proposed.bindings.find(row => bindingKey(row) === (key.kind === 'existing' ? `existing:${key.bindingId}` : `enrollment:${key.relationTypeId}:${key.assetId}:${key.side}`))!;
    const id = key.kind === 'existing' ? key.bindingId : started.enrollments.find(item => item.relationTypeId === key.relationTypeId && item.assetId === key.assetId && item.side === key.side)?.bindingId;
    if (!id) throw graphStorage(); const now = new Date();
    const columns = { version: row.version, relation_type_version: row.relationTypeVersion, asset_version: row.assetVersion, status: row.status, updated_by: p.id, updated_at: now };
    const written = key.kind === 'existing' ? await relationQuery(tx, () => tx.updateTable('relation_participations').set(columns)
      .where('tenant_id', '=', p.tenantId).where('id', '=', id).where('version', '=', change.beforeVersion!).returningAll().executeTakeFirstOrThrow())
      : await relationQuery(tx, () => tx.insertInto('relation_participations').values({ ...columns, tenant_id: p.tenantId, id, relation_type_id: row.relationTypeId,
        asset_id: row.assetId, side: row.side, created_by: p.id, created_at: now }).returningAll().executeTakeFirstOrThrow());
    const snapshot = participationView(written);
    await relationQuery(tx, () => tx.insertInto('relation_participation_revisions').values({ tenant_id: p.tenantId, binding_id: id, version: row.version,
      snapshot: JSON.stringify(snapshot), operation_id: operationId, recorded_by: p.id, recorded_at: now }).execute());
    const action = change.action === 'enroll' ? 'enrolled' : change.action === 'repin' ? 'repinned' : 'released';
    await relationQuery(tx, () => hooks.record(tx, p, `relation_participation.${action}`, id, row.version,
      { operationId, revision: row.version, snapshotHash: typeHash(snapshot) }, correlationId));
  }
}
/** The ingress owns once() and its success write. This method never finalizes
 * constraints before that write; protected SQL independently proves every claim. */
export async function executeRelationMigration(tx: Tx, p: Principal, correlationId: string, key: string,
  body: { changeSet: unknown; previewDigest: string }, hooks: ModelHooks) {
  const prepared = await prepare(tx, p, body.changeSet);
  if (!graphExpectedRevisionsMatch(prepared.changeSet, prepared.context.before)) throw graphStale();
  if (!prepared.preview.ready) throw graphInvalid(prepared.preview.targetIssues);
  if (body.previewDigest !== prepared.preview.previewDigest) throw graphStale();
  const id = randomUUID();
  const result = await relationQuery(tx, () => sql<{ value: GraphOperationBeginResult }>`SELECT public.gc_relation_graph_begin(${id}::uuid,'relation-migration.execute',${key},${JSON.stringify(body)}::jsonb,${correlationId}) AS value`.execute(tx));
  const started = result.rows[0].value;
  await persist(tx, p, correlationId, started, prepared, hooks);
  await relationQuery(tx, () => hooks.record(tx, p, 'relation_migration.executed', started.operation.id, 1,
    { changeSetHash: prepared.preview.changeSetHash, previewDigest: prepared.preview.previewDigest }, correlationId));
  const sealed = await relationQuery(tx, () => sql<{ value: RelationMigrationReceipt }>`SELECT public.gc_relation_graph_seal(${started.operation.id}::uuid) AS value`.execute(tx));
  const receipt = sealed.rows[0].value;
  if (receipt.id !== id || receipt.changeSetHash !== prepared.preview.changeSetHash || receipt.previewDigest !== body.previewDigest) throw graphStorage();
  await modelPersistence.authorize(tx, p, GRAPH_WRITE);
  return { receipt };
}
