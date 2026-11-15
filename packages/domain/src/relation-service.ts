// SPDX-License-Identifier: Apache-2.0
import { randomUUID } from 'node:crypto';
import { sql, type Tx } from '../../db/src/index.ts';
import { Problem, type Principal } from '../../authz/src/index.ts';
import { modelPersistence as persistence } from './model-service.ts';
import { typeHash } from './asset-type-policy.ts';
import { validateAttributes } from './model.ts';
import { parseRelationValidity, previewRelationTypeUpgrade, validateRelationEndpoints, validateRelationStructure } from './relation.ts';
import { signedCursor } from './cursor.ts';
import type { RelationCreate, RelationEdit, RelationTransition, RelationTypeListQuery, RelationPageQuery,
  RelationTypePreview, RelationView, RelationUpgradeBinding, RelationEndpointPolicyState, ResolvedRelationType } from './relation-contracts.ts';
import { type Row, type RelationHooks, RELATION_READ, RELATION_WRITE, TYPE_WRITE, iso, uuid, unavailable, profileLimit,
  configureRelationTransaction, relationFailure, relationValidationFailure, lockRelationScope, relationDefinition, storedRelationType,
  relationTypeHead, relationTypeVersion, endpointTypeIdentities, relationTypeView, relationRow, assetRows, endpointState,
  relationView, lockRelationPrincipals, completeRelationRows, lockRelationRows, relationPolicies, constraintEdge,
  relationQuery, relationBudget, preflightEndpointPolicies, checkRelationDeadline } from './relation-store.ts';
export { configureRelationTransaction, relationFailure, relationValidationFailure };
export { listAssetRelations, getAssetGraph } from './relation-graph.ts';
export { lockRelationEndpointUnion, validateRelationsForEndpointChanges } from './relation-endpoint-guard.ts';

const invalidPage = () => new Problem(400, 'RELATION_PAGE_INVALID', 'The relationship cursor or query is invalid.');
const stale = () => new Problem(409, 'VERSION_CONFLICT', 'The relationship, endpoint or type changed. Load the current version before saving.');
function pageSize(query: RelationPageQuery): number {
  const limit = query.limit ?? 25; if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw invalidPage(); return limit;
}
function pageCursor(p: Principal, purpose: string, binding: unknown, input: string | undefined): { last: any; encode: (last: any) => string } {
  const cursor = signedCursor(process.env.SESSION_KEY, purpose), bound = typeHash([p.tenantId, p.id, binding]);
  let last: any = null;
  if (input !== undefined) try {
    const parsed = cursor.decode(input) as any;
    if (!parsed || Object.keys(parsed).sort().join('|') !== 'binding|last|v' || parsed.v !== 1 || parsed.binding !== bound) throw Error();
    last = parsed.last;
  } catch { throw invalidPage(); }
  return { last, encode: last => cursor.encode({ v: 1, binding: bound, last }) };
}
export async function listRelationTypes(tx: Tx, p: Principal, query: RelationTypeListQuery = {}) {
  await relationQuery(tx, () => persistence.authorize(tx, p, ['models:read'])); const limit = pageSize(query), q = query.q ?? '';
  if (typeof q !== 'string' || q.length > 64 || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(q)) throw invalidPage();
  const cursor = pageCursor(p, 'relation-types', { q, limit, sort: 'id:asc' }, query.cursor);
  if (cursor.last !== null && (typeof cursor.last !== 'string' || !/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(cursor.last))) throw invalidPage();
  let select = tx.selectFrom('relation_types as h').innerJoin('relation_type_versions as v', join => join.onRef('h.tenant_id', '=', 'v.tenant_id')
    .onRef('h.type_id', '=', 'v.relation_type_id').onRef('h.current_version', '=', 'v.version'))
    .selectAll('h').select(sql<string>`v.definition->>'label'`.as('label')).where('h.tenant_id', '=', p.tenantId)
    .where(sql<boolean>`(strpos(lower(h.id),lower(${q}))>0 OR strpos(lower(v.definition->>'label'),lower(${q}))>0)`);
  if (cursor.last !== null) select = select.where('h.id', '>', cursor.last);
  const rows = await relationQuery(tx, () => select.orderBy('h.id').limit(limit + 1).execute()), selected = rows.slice(0, limit);
  return { items: selected.map(row => ({ id: row.id, relationTypeId: row.type_id, currentVersion: row.current_version, label: row.label,
    createdAt: iso(row.created_at), createdBy: row.created_by })), nextCursor: rows.length > limit ? cursor.encode(selected.at(-1)!.id) : null };
}
export async function getRelationType(tx: Tx, p: Principal, id: string, version?: number) {
  await relationQuery(tx, () => persistence.authorize(tx, p, ['models:read'])); const head = await relationTypeHead(tx, p, id);
  return { type: await relationTypeView(tx, p, head, await relationTypeVersion(tx, p, head.type_id, version ?? head.current_version)) };
}
export async function listRelationTypeVersions(tx: Tx, p: Principal, id: string, query: RelationPageQuery = {}) {
  await relationQuery(tx, () => persistence.authorize(tx, p, ['models:read'])); const head = await relationTypeHead(tx, p, id), limit = pageSize(query);
  const cursor = pageCursor(p, 'relation-type-versions', { id, limit, sort: 'version:asc' }, query.cursor);
  if (cursor.last !== null && (!Number.isInteger(cursor.last) || cursor.last < 1 || cursor.last > 2147483647)) throw invalidPage();
  let select = tx.selectFrom('relation_type_versions').select(['version', 'definition_hash', 'created_at', 'created_by'])
    .where('tenant_id', '=', p.tenantId).where('relation_type_id', '=', head.type_id);
  if (cursor.last !== null) select = select.where('version', '>', cursor.last);
  const rows = await relationQuery(tx, () => select.orderBy('version').limit(limit + 1).execute()), selected = rows.slice(0, limit);
  return { items: selected.map(row => ({ version: row.version, definitionHash: row.definition_hash, createdAt: iso(row.created_at), createdBy: row.created_by })),
    nextCursor: rows.length > limit ? cursor.encode(selected.at(-1)!.version) : null };
}
async function physicalBudget(tx: Tx, value: unknown, limit = 524288): Promise<void> {
  if (Buffer.byteLength(JSON.stringify(value)) > limit) throw profileLimit();
  const result = await relationQuery(tx, () => sql<{ bytes: number }>`select octet_length(${JSON.stringify(value)}::jsonb::text) as bytes`.execute(tx));
  if (result.rows[0].bytes > limit) throw profileLimit();
}
async function insertTypeVersion(tx: Tx, p: Principal, typeId: string, policy: ResolvedRelationType) {
  await physicalBudget(tx, policy.definition, 262144);
  return relationQuery(tx, () => tx.insertInto('relation_type_versions').values({ tenant_id: p.tenantId, relation_type_id: typeId, version: policy.definition.version,
    definition: JSON.stringify(policy.definition), definition_hash: typeHash(policy.definition), created_by: p.id }).returningAll().executeTakeFirstOrThrow());
}
export async function createRelationType(tx: Tx, p: Principal, correlationId: string, input: unknown, hooks: RelationHooks) {
  await lockRelationScope(tx, p, TYPE_WRITE); const policy = relationDefinition(input);
  if (policy.definition.version !== 1) throw new Problem(422, 'RELATION_INVALID', 'A new relationship type starts at version one.');
  await endpointTypeIdentities(tx, p, policy); await lockRelationPrincipals(tx, p, [], TYPE_WRITE);
  const head = await relationQuery(tx, () => tx.insertInto('relation_types').values({ tenant_id: p.tenantId, id: policy.definition.id, type_id: randomUUID(), current_version: 1, created_by: p.id }).returningAll().executeTakeFirstOrThrow());
  const row = await insertTypeVersion(tx, p, head.type_id, policy);
  await relationQuery(tx, () => hooks.record(tx, p, 'relation_type.created', head.id, 1, { relationTypeId: head.type_id, definitionHash: row.definition_hash }, correlationId));
  await relationQuery(tx, () => sql`set constraints all immediate`.execute(tx)); return { type: await relationTypeView(tx, p, head, row) };
}
async function prepareType(tx: Tx, p: Principal, id: string, expected: number, input: unknown) {
  const actions = [...TYPE_WRITE, 'catalog:read']; await lockRelationScope(tx, p, actions);
  const head = await relationTypeHead(tx, p, id, false, true); persistence.checkVersion(expected);
  if (head.current_version !== expected) throw stale();
  const target = relationDefinition(input), current = storedRelationType(await relationTypeVersion(tx, p, head.type_id, expected));
  if (target.definition.id !== id || target.definition.version !== expected + 1) throw new Problem(422, 'RELATION_INVALID', 'Publication must retain the logical identity and advance by exactly one version.');
  await endpointTypeIdentities(tx, p, target); await physicalBudget(tx, target.definition, 262144);
  let rows = await completeRelationRows(tx, p, head.type_id);
  const assets = await assetRows(tx, p, rows.flatMap(row => [row.source_asset_id, row.target_asset_id]), true);
  await preflightEndpointPolicies(tx, p, assets);
  rows = await lockRelationRows(tx, p, rows); const policies = await relationPolicies(tx, p, rows);
  const activity = await lockRelationPrincipals(tx, p, rows.map(row => row.owner_id), actions), endpoints = new Map<string, RelationEndpointPolicyState>();
  const endpointBudget = relationBudget(tx);
  for (const asset of assets) { const state = await endpointState(tx, p, asset); endpointBudget.add(state); endpoints.set(asset.id, state); }
  const bindings: RelationUpgradeBinding[] = [], bindingBudget = relationBudget(tx, { head: current, target, policies });
  for (const row of rows) {
    const binding = { edge: constraintEdge(row), attributes: row.attributes, ownerId: row.owner_id, state: row.state,
      source: endpoints.get(row.source_asset_id)!, target: endpoints.get(row.target_asset_id)! };
    bindingBudget.add(binding); bindings.push(binding);
  }
  await physicalBudget(tx, { definitions: [current, target, ...policies.map(pin => pin.policy)], bindings });
  const result = previewRelationTypeUpgrade({ relationTypeId: head.type_id, head: current, target, policies, completeLiveRelations: bindings, activeOwnerIds: activity.active });
  checkRelationDeadline(tx);
  if (!result.ok) throw relationValidationFailure(result.issues);
  const digest = typeHash({ purpose: 'relation-type-preview', tenantId: p.tenantId, actorId: p.id, typeId: head.type_id, expected,
    target, current, rows, endpoints: [...endpoints.values()], ownerActivity: [...activity.active].sort() });
  const preview: RelationTypePreview = { relationTypeId: head.type_id, id, currentVersion: expected, proposedVersion: target.definition.version,
    coverage: 'complete-tenant-relation-type-bindings', relationCount: rows.length, ...result.value, previewDigest: digest };
  return { head, target, preview };
}
export async function previewRelationType(tx: Tx, p: Principal, id: string, expected: number, input: unknown) {
  return (await prepareType(tx, p, id, expected, input)).preview;
}
export async function publishRelationType(tx: Tx, p: Principal, correlationId: string, id: string, expected: number, input: unknown, digest: string, hooks: RelationHooks) {
  const { head, target, preview } = await prepareType(tx, p, id, expected, input);
  if (digest !== preview.previewDigest) throw new Problem(409, 'RELATION_PREVIEW_STALE', 'The type or complete bound scope changed. Run a fresh preview.');
  if (preview.requiresExplicitMigration || !preview.compatibleWithProvidedRelations) throw new Problem(422, 'RELATION_MIGRATION_REQUIRED', 'Existing relationships require an explicit migration before this policy change.');
  const row = await insertTypeVersion(tx, p, head.type_id, target);
  await relationQuery(tx, () => tx.updateTable('relation_types').set({ current_version: row.version }).where('tenant_id', '=', p.tenantId).where('id', '=', id).where('current_version', '=', expected).execute());
  await relationQuery(tx, () => hooks.record(tx, p, 'relation_type.published', id, row.version, { relationTypeId: head.type_id, previousVersion: expected, definitionHash: row.definition_hash }, correlationId));
  await relationQuery(tx, () => sql`set constraints all immediate`.execute(tx));
  return { type: await relationTypeView(tx, p, { ...head, current_version: row.version }, row) };
}
export async function getRelation(tx: Tx, p: Principal, id: string) {
  await relationQuery(tx, () => persistence.authorize(tx, p, RELATION_READ)); return { relation: await relationView(tx, p, await relationRow(tx, p, id)) };
}
export async function authorizeRelationReplay(tx: Tx, p: Principal, recorded: RelationView, actions: readonly string[]): Promise<void> {
  await relationQuery(tx, () => persistence.authorize(tx, p, actions));
  const row = await relationRow(tx, p, recorded.id);
  if (row.source_asset_id !== recorded.source.assetId || row.target_asset_id !== recorded.target.assetId || row.relation_type_id !== recorded.relationTypeId) throw unavailable();
  // Current edge ACL plus the original immutable endpoint identities govern every replay, including tombstones.
  await assetRows(tx, p, [recorded.source.assetId, recorded.target.assetId]);
}
export async function listRelationRevisions(tx: Tx, p: Principal, id: string, query: RelationPageQuery = {}) {
  await relationQuery(tx, () => persistence.authorize(tx, p, [...RELATION_READ, 'audit:read'])); await relationRow(tx, p, id);
  const limit = pageSize(query), cursor = pageCursor(p, 'relation-revisions', { id, limit, sort: 'version:asc' }, query.cursor);
  if (cursor.last !== null && (!Number.isInteger(cursor.last) || cursor.last < 1 || cursor.last > 2147483647)) throw invalidPage();
  let select = tx.selectFrom('relation_revisions').selectAll().where('tenant_id', '=', p.tenantId).where('relation_id', '=', id);
  if (cursor.last !== null) select = select.where('version', '>', cursor.last);
  const rows = await relationQuery(tx, () => select.orderBy('version').limit(limit + 1).execute()), selected = rows.slice(0, limit);
  for (const row of selected) await authorizeRelationReplay(tx, p, row.snapshot, [...RELATION_READ, 'audit:read']);
  return { items: selected.map(row => ({ relationId: row.relation_id, version: row.version, snapshot: row.snapshot, recordedAt: iso(row.recorded_at), recordedBy: row.recorded_by })),
    nextCursor: rows.length > limit ? cursor.encode(selected.at(-1)!.version) : null };
}
function editable(input: RelationEdit) {
  const parsed = parseRelationValidity({ validFrom: input.validFrom, validTo: input.validTo }); if (!parsed.ok) throw relationValidationFailure(parsed.issues);
  if ((input.ownerId !== null && !uuid(input.ownerId)) || !['tenant', 'restricted'].includes(input.visibility) || !Array.isArray(input.allowedIdentityIds) ||
    input.allowedIdentityIds.length > 100 || input.allowedIdentityIds.some(id => !uuid(id)) || new Set(input.allowedIdentityIds).size !== input.allowedIdentityIds.length ||
    (input.visibility === 'tenant' ? input.allowedIdentityIds.length !== 0 : input.allowedIdentityIds.length === 0)) throw new Problem(422, 'RELATION_INVALID', 'Choose valid ownership and relationship visibility.');
  return { ...parsed.value, ownerId: input.ownerId, visibility: input.visibility, allowedIdentityIds: [...input.allowedIdentityIds].sort() };
}
async function mutationContext(tx: Tx, p: Principal, typeId: string, extraAssets: readonly string[], oldId?: string) {
  await lockRelationScope(tx, p, RELATION_WRITE);
  const head = await relationTypeHead(tx, p, typeId, true, true);
  let rows = await completeRelationRows(tx, p, typeId);
  const assets = await assetRows(tx, p, [...extraAssets, ...rows.flatMap(row => [row.source_asset_id, row.target_asset_id])], true);
  rows = await lockRelationRows(tx, p, rows);
  const old = oldId ? rows.find(row => row.id === oldId) : undefined;
  if (oldId && !old) throw new Problem(409, 'RELATION_TOMBSTONED', 'This relationship has already been removed.');
  return { head, rows, assets, old, policies: await relationPolicies(tx, p, rows) };
}
function checkEndpointVersions(assets: readonly Row[], sourceId: string, targetId: string, input: { sourceAssetVersion: number; targetAssetVersion: number }) {
  const source = assets.find(asset => asset.id === sourceId), target = assets.find(asset => asset.id === targetId);
  if (!source || !target || source.version !== input.sourceAssetVersion || target.version !== input.targetAssetVersion) throw stale();
  return { source, target };
}
async function persistMutation(tx: Tx, p: Principal, correlationId: string, candidate: Row, context: Awaited<ReturnType<typeof mutationContext>>,
  policy: ResolvedRelationType, action: 'created' | 'updated' | 'transitioned' | 'tombstoned', explicitOwner: boolean, hooks: RelationHooks) {
  const finalRows = [...context.rows.filter(row => row.id !== candidate.id), ...(candidate.status === 'active' ? [candidate] : [])];
  const principalIds = [candidate.owner_id, context.old?.owner_id ?? null, ...candidate.allowed_identities];
  const activity = await lockRelationPrincipals(tx, p, principalIds, RELATION_WRITE);
  if (candidate.visibility === 'restricted' && !candidate.allowed_identities.includes(p.id)) throw new Problem(422, 'RELATION_INVALID', 'Relationship visibility must retain your access to the result.');
  if (candidate.allowed_identities.some((id: string) => !activity.members.has(id)) || candidate.owner_id !== null && !activity.members.has(candidate.owner_id)) throw new Problem(422, 'RELATION_INVALID', 'A referenced member is unavailable in this organization.');
  if ((policy.definition.requiredOwner && (!candidate.owner_id || !activity.active.has(candidate.owner_id))) || (explicitOwner && candidate.owner_id !== null && !activity.active.has(candidate.owner_id))) throw new Problem(422, 'RELATION_OWNER_INVALID', 'Choose an active owner in this organization.');
  const attributes = validateAttributes(policy.model, candidate.attributes); if (!attributes.ok) throw relationValidationFailure(attributes.issues);
  candidate.attributes = attributes.value;
  if (!policy.definition.lifecycle.states.includes(candidate.state)) throw new Problem(422, 'RELATION_INVALID', 'The state is not declared in the pinned relationship lifecycle.');
  const source = context.assets.find(asset => asset.id === candidate.source_asset_id)!, target = context.assets.find(asset => asset.id === candidate.target_asset_id)!;
  const policies = context.policies.some(pin => pin.relationTypeId === candidate.relation_type_id && pin.policy.definition.version === candidate.relation_type_version)
    ? context.policies : [...context.policies, { relationTypeId: candidate.relation_type_id, policy }];
  await preflightEndpointPolicies(tx, p, source.id === target.id ? [source] : [source, target], Buffer.byteLength(JSON.stringify(policies)));
  const endpoints = validateRelationEndpoints({ edge: constraintEdge(candidate), policies, source: await endpointState(tx, p, source), target: await endpointState(tx, p, target) });
  if (!endpoints.ok) throw relationValidationFailure(endpoints.issues);
  const structural = validateRelationStructure({ relationTypeId: candidate.relation_type_id, completeLiveRelations: finalRows.map(constraintEdge), policies });
  if (!structural.ok && structural.issues.some(issue => issue.code === 'limit')) throw profileLimit();
  if (!structural.ok) throw new Problem(422, structural.issues.some(issue => issue.code === 'cycle') ? 'RELATION_CYCLE' : structural.issues.some(issue => issue.code === 'duplicate') ? 'RELATION_DUPLICATE' : 'RELATION_CARDINALITY', 'The complete relationship cohort does not satisfy its pinned structural rules.', structural.issues);
  await physicalBudget(tx, { cohort: finalRows, policies, endpoints: context.assets.map(asset => ({ id: asset.id, version: asset.version, modelId: asset.model_id, modelVersion: asset.model_version, state: asset.type_state })) });
  let written: Row;
  if (action === 'created') written = await relationQuery(tx, () => tx.insertInto('relations').values({ ...candidate, attributes: JSON.stringify(candidate.attributes), allowed_identities: JSON.stringify(candidate.allowed_identities), provenance: JSON.stringify(candidate.provenance) }).returningAll().executeTakeFirstOrThrow());
  else written = await relationQuery(tx, () => tx.updateTable('relations').set({ attributes: JSON.stringify(candidate.attributes), owner_id: candidate.owner_id, state: candidate.state,
    valid_from: candidate.valid_from, valid_to: candidate.valid_to, visibility: candidate.visibility, allowed_identities: JSON.stringify(candidate.allowed_identities), status: candidate.status,
    version: candidate.version, updated_by: p.id, updated_at: candidate.updated_at }).where('tenant_id', '=', p.tenantId).where('id', '=', candidate.id)
    .where('version', '=', candidate.version - 1).returningAll().executeTakeFirstOrThrow());
  const snapshot = await relationView(tx, p, written, context.assets);
  await physicalBudget(tx, snapshot);
  await relationQuery(tx, () => tx.insertInto('relation_revisions').values({ tenant_id: p.tenantId, relation_id: written.id, version: written.version,
    snapshot: JSON.stringify(snapshot), recorded_by: p.id, recorded_at: written.updated_at }).execute());
  await relationQuery(tx, () => hooks.record(tx, p, `relation.${action}`, written.id, written.version, { relationTypeId: written.relation_type_id, relationTypeVersion: written.relation_type_version,
    revision: written.version, snapshotHash: typeHash(snapshot) }, correlationId));
  await relationQuery(tx, () => sql`set constraints all immediate`.execute(tx)); return { relation: snapshot };
}
export async function createRelation(tx: Tx, p: Principal, correlationId: string, input: RelationCreate, hooks: RelationHooks) {
  const edit = editable(input);
  if (![input.relationTypeId, input.sourceAssetId, input.targetAssetId].every(uuid)) throw new Problem(422, 'RELATION_INVALID', 'Provide valid relationship and endpoint identities.');
  const context = await mutationContext(tx, p, input.relationTypeId, [input.sourceAssetId, input.targetAssetId]);
  if (context.head.current_version !== input.relationTypeVersion) throw stale();
  const policy = storedRelationType(await relationTypeVersion(tx, p, input.relationTypeId, input.relationTypeVersion));
  checkEndpointVersions(context.assets, input.sourceAssetId, input.targetAssetId, input);
  let sourceId = input.sourceAssetId, targetId = input.targetAssetId;
  if (policy.definition.direction === 'undirected' && sourceId > targetId) [sourceId, targetId] = [targetId, sourceId];
  const now = new Date();
  const candidate = { tenant_id: p.tenantId, id: randomUUID(), relation_type_id: input.relationTypeId, relation_type_version: input.relationTypeVersion,
    source_asset_id: sourceId, target_asset_id: targetId, attributes: input.attributes, owner_id: edit.ownerId, state: policy.definition.lifecycle.initial, version: 1, status: 'active',
    valid_from: edit.validFrom, valid_to: edit.validTo, visibility: edit.visibility, allowed_identities: edit.allowedIdentityIds,
    provenance: { origin: 'asserted', source: { kind: 'manual', identityId: p.id }, authority: 'manual-assertion', precedence: null,
      actorId: p.id, assertedAt: now.toISOString(), ingestedAt: now.toISOString(), sourceObservedAt: null, sourceVersion: null, sourceRunId: null, confidence: null },
    created_by: p.id, updated_by: p.id, created_at: now, updated_at: now };
  return persistMutation(tx, p, correlationId, candidate, context, policy, 'created', true, hooks);
}
async function existingContext(tx: Tx, p: Principal, id: string, expected: number) {
  await lockRelationScope(tx, p, RELATION_WRITE); persistence.checkVersion(expected);
  const original = await relationRow(tx, p, id);
  const context = await mutationContext(tx, p, original.relation_type_id, [original.source_asset_id, original.target_asset_id], id), old = context.old!;
  if (old.version !== expected) throw stale(); if (old.version >= 2147483647) throw profileLimit();
  return { context, old, policy: storedRelationType(await relationTypeVersion(tx, p, old.relation_type_id, old.relation_type_version)) };
}
export async function editRelation(tx: Tx, p: Principal, correlationId: string, id: string, expected: number, input: RelationEdit, hooks: RelationHooks) {
  const edit = editable(input), { context, old, policy } = await existingContext(tx, p, id, expected);
  checkEndpointVersions(context.assets, old.source_asset_id, old.target_asset_id, input);
  return persistMutation(tx, p, correlationId, { ...old, attributes: input.attributes, owner_id: edit.ownerId, valid_from: edit.validFrom, valid_to: edit.validTo,
    visibility: edit.visibility, allowed_identities: edit.allowedIdentityIds, version: old.version + 1, updated_by: p.id, updated_at: new Date() }, context, policy, 'updated', true, hooks);
}
export async function transitionRelation(tx: Tx, p: Principal, correlationId: string, id: string, expected: number, input: RelationTransition, hooks: RelationHooks) {
  const { context, old, policy } = await existingContext(tx, p, id, expected); checkEndpointVersions(context.assets, old.source_asset_id, old.target_asset_id, input);
  if (!policy.definition.lifecycle.transitions.some(edge => edge.from === old.state && edge.to === input.state)) throw new Problem(422, 'RELATION_TRANSITION_INVALID', 'This transition is not allowed by the pinned relationship lifecycle.');
  return persistMutation(tx, p, correlationId, { ...old, state: input.state, version: old.version + 1, updated_by: p.id, updated_at: new Date() }, context, policy, 'transitioned', false, hooks);
}
export async function tombstoneRelation(tx: Tx, p: Principal, correlationId: string, id: string, expected: number, hooks: RelationHooks) {
  const { context, old, policy } = await existingContext(tx, p, id, expected);
  return persistMutation(tx, p, correlationId, { ...old, status: 'tombstoned', version: old.version + 1, updated_by: p.id, updated_at: new Date() }, context, policy, 'tombstoned', false, hooks);
}
