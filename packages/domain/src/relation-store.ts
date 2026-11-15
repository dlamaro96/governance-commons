// SPDX-License-Identifier: Apache-2.0
import { lockTenantLedger, sql, type Tx } from '../../db/src/index.ts';
import { canView, Problem, type Principal } from '../../authz/src/index.ts';
import { modelPersistence as persistence, type ModelHooks } from './model-service.ts';
import { storedAssetType, typeHash } from './asset-type-policy.ts';
import { resolveAssetType, type ResolvedAssetType } from './asset-type.ts';
import { resolveRelationType } from './relation.ts';
import type { ValidationIssue } from './model.ts';
import type { RelationTypeView, RelationView, RelationEndpointPolicyState, RelationEndpointView,
  RelationConstraintEdge, RelationPolicyPin, ResolvedRelationType } from './relation-contracts.ts';
export type Row = Record<string, any>;
export type RelationHooks = Pick<ModelHooks, 'record'>;
export const RELATION_READ = ['catalog:read', 'models:read'] as const;
export const RELATION_WRITE = [...RELATION_READ, 'catalog:write'] as const;
export const TYPE_WRITE = ['models:read', 'models:write'] as const;
export const unavailable = () => new Problem(404, 'RELATION_NOT_FOUND', 'The relationship or its endpoints are unavailable.');
export const profileLimit = () => new Problem(422, 'RELATION_PROFILE_LIMIT', 'The complete relationship scope exceeds this bounded development profile. No partial operation was performed.');
export const hiddenScope = () => new Problem(403, 'RELATION_SCOPE_UNAVAILABLE', 'The complete relationship scope is unavailable for this operation.');
export const iso = (value: string | Date): string => new Date(value).toISOString();
export const uuid = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
export function relationValidationFailure(issues: readonly ValidationIssue[]): Problem {
  if (issues.some(issue => issue.code === 'limit')) return profileLimit();
  return new Problem(422, issues.some(issue => issue.code === 'unsupported' && /^\/cardinality\/(incoming|outgoing)\/min$/.test(issue.path))
    ? 'RELATION_MINIMUM_UNSUPPORTED' : 'RELATION_INVALID', 'Correct the relationship definition or values.', issues);
}
const maximumBytes = 524288;
interface EndpointPolicy { policy: ResolvedAssetType | null; typeId: string | null; ancestorTypes: RelationEndpointPolicyState['ancestorTypes'] }
interface TransactionState { deadline: number; policyBytes: number; policies: Map<string, EndpointPolicy> }
const transactions = new WeakMap<Tx, TransactionState>();
function transactionState(tx: Tx): TransactionState {
  let state = transactions.get(tx);
  if (!state) { state = { deadline: performance.now() + 30000, policyBytes: 0, policies: new Map() }; transactions.set(tx, state); }
  return state;
}
export function checkRelationDeadline(tx: Tx): number {
  const remaining = Math.floor(transactionState(tx).deadline - performance.now());
  if (remaining < 1) throw new Problem(503, 'RELATION_RETRY', 'A stable execution window was unavailable. Retry with the same idempotency key.');
  return remaining;
}
/** Nested services share the original deadline; configuration never grants another thirty seconds. */
export async function configureRelationTransaction(tx: Tx): Promise<void> {
  const remaining = checkRelationDeadline(tx);
  await sql`select set_config('lock_timeout',${String(Math.min(5000, remaining))},true), set_config('statement_timeout',${String(remaining)},true)`.execute(tx);
}
export async function relationQuery<T>(tx: Tx, work: () => Promise<T>): Promise<T> {
  await configureRelationTransaction(tx); const result = await work(); checkRelationDeadline(tx); return result;
}
/** Charge before retaining each projected member; final exact/physical checks remain authoritative. */
export function relationBudget(tx: Tx, initial: unknown = null) {
  let bytes = Buffer.byteLength(JSON.stringify(initial));
  const addBytes = (size: number) => { checkRelationDeadline(tx); bytes += size; if (bytes > maximumBytes) throw profileLimit(); };
  addBytes(0);
  return { add: (value: unknown) => addBytes(Buffer.byteLength(JSON.stringify(value)) + 1), addBytes };
}
export function relationFailure(error: unknown): unknown {
  if (error instanceof Problem) return error;
  if (!error || typeof error !== 'object' || !('code' in error)) return error;
  const e = error as { code: string; message?: string; constraint?: string };
  if (['55P03', '40P01', '57014', '40001'].includes(e.code)) return new Problem(503, 'RELATION_RETRY', 'A stable execution window was unavailable. Retry with the same idempotency key.');
  if (e.code === '23505') return new Problem(409, 'RELATION_DUPLICATE', 'The relationship or definition already exists.');
  const known = ['RELATION_INVALID', 'RELATION_CARDINALITY', 'RELATION_CYCLE', 'RELATION_PROFILE_LIMIT', 'RELATION_MIGRATION_REQUIRED'];
  if (e.code === '23514' && known.includes(e.message ?? '')) return new Problem(422, e.message!, 'The proposed relationship change does not satisfy its pinned constraints.');
  if (e.code === '54000' && e.message === 'RELATION_PROFILE_LIMIT') return profileLimit();
  if (e.code === '23503') return new Problem(422, 'RELATION_INVALID', 'A referenced relationship identity or revision is unavailable.');
  return error;
}
export async function lockRelationScope(tx: Tx, p: Principal, actions: readonly string[]): Promise<void> {
  await relationQuery(tx, () => persistence.authorize(tx, p, actions));
  await relationQuery(tx, () => lockTenantLedger(tx, p.tenantId));
  await relationQuery(tx, () => sql`select pg_advisory_xact_lock(hashtextextended(${`governance-models:${p.tenantId}`},0))`.execute(tx));
  await relationQuery(tx, () => persistence.authorize(tx, p, actions));
}
export function relationDefinition(input: unknown): ResolvedRelationType {
  const parsed = resolveRelationType(input); if (!parsed.ok) throw relationValidationFailure(parsed.issues);
  if (Buffer.byteLength(JSON.stringify(parsed.value.definition)) > 262144) throw profileLimit();
  return parsed.value;
}
export function storedRelationType(row: Row): ResolvedRelationType {
  const parsed = relationDefinition(row.definition);
  if (parsed.definition.version !== row.version || typeHash(parsed.definition) !== row.definition_hash) throw new Problem(500, 'RELATION_STORAGE_INVALID', 'Stored relationship policy could not be verified.');
  return parsed;
}
export async function relationTypeHead(tx: Tx, p: Principal, id: string, byUuid = false, lock = false): Promise<Row> {
  let q = tx.selectFrom('relation_types').selectAll().where('tenant_id', '=', p.tenantId).where(byUuid ? 'type_id' : 'id', '=', id);
  if (lock) q = q.forUpdate(); const row = await relationQuery(tx, () => q.executeTakeFirst());
  if (!row) throw new Problem(404, 'RELATION_TYPE_NOT_FOUND', 'Relationship type is unavailable.'); return row;
}
export async function relationTypeVersion(tx: Tx, p: Principal, typeId: string, version: number): Promise<Row> {
  persistence.checkVersion(version, 'RELATION_VERSION_INVALID');
  const query = tx.selectFrom('relation_type_versions').where('tenant_id', '=', p.tenantId).where('relation_type_id', '=', typeId).where('version', '=', version);
  const size = await relationQuery(tx, () => query.select(sql<number>`octet_length(definition::text)`.as('bytes')).executeTakeFirst());
  if (size && size.bytes > 262144) throw profileLimit();
  const row = await relationQuery(tx, () => query.selectAll().executeTakeFirst());
  if (!row) throw new Problem(404, 'RELATION_TYPE_NOT_FOUND', 'Relationship type version is unavailable.'); return row;
}
export async function endpointTypeIdentities(tx: Tx, p: Principal, policy: ResolvedRelationType) {
  const ids = [...new Set([...policy.definition.sourceTypes, ...policy.definition.targetTypes].map(rule => rule.typeId))].sort();
  const rows = await relationQuery(tx, () => tx.selectFrom('governance_models').select(['id', 'type_id']).where('tenant_id', '=', p.tenantId).where('type_id', 'in', ids).orderBy('type_id').execute());
  if (rows.length !== ids.length) throw new Problem(422, 'RELATION_INVALID', 'An endpoint type identity is unavailable in this organization.');
  return rows.map(row => ({ typeId: row.type_id as string, id: row.id as string }));
}
export async function relationTypeView(tx: Tx, p: Principal, head: Row, row: Row): Promise<RelationTypeView> {
  const policy = storedRelationType(row), current = row.version === head.current_version ? policy : storedRelationType(await relationTypeVersion(tx, p, head.type_id, head.current_version));
  if (policy.definition.id !== head.id) throw new Problem(500, 'RELATION_STORAGE_INVALID', 'Stored relationship identity could not be verified.');
  return { id: head.id, relationTypeId: head.type_id, currentVersion: head.current_version, label: current.definition.label,
    createdAt: iso(head.created_at), createdBy: head.created_by, version: row.version, definition: policy.definition,
    definitionHash: row.definition_hash, versionCreatedAt: iso(row.created_at), versionCreatedBy: row.created_by,
    endpointTypeIdentities: await endpointTypeIdentities(tx, p, policy) };
}
export const assetVisible = (p: Principal, row: Row) => canView(p, { tenantId: row.tenant_id, visibility: row.visibility, allowedIdentities: row.allowed_identities });
/** Alias r is fixed by every caller. Authorization is applied in SQL before count/limit/page expansion. */
export function visibleRelationPredicate(p: Principal) {
  return sql<boolean>`(r.visibility='tenant' OR r.allowed_identities @> ${JSON.stringify([p.id])}::jsonb)
    AND EXISTS (SELECT 1 FROM assets s WHERE s.tenant_id=r.tenant_id AND s.id=r.source_asset_id AND (s.visibility='tenant' OR s.allowed_identities @> ${JSON.stringify([p.id])}::jsonb))
    AND EXISTS (SELECT 1 FROM assets t WHERE t.tenant_id=r.tenant_id AND t.id=r.target_asset_id AND (t.visibility='tenant' OR t.allowed_identities @> ${JSON.stringify([p.id])}::jsonb))`;
}
export async function relationRow(tx: Tx, p: Principal, id: string): Promise<Row> {
  if (!uuid(id)) throw unavailable();
  const row = await relationQuery(tx, () => tx.selectFrom('relations as r').selectAll('r').where('r.tenant_id', '=', p.tenantId).where('r.id', '=', id)
    .where(visibleRelationPredicate(p)).executeTakeFirst());
  if (!row) throw unavailable(); return row;
}
export function constraintEdge(row: Row): RelationConstraintEdge {
  return { id: row.id, version: row.version, relationTypeId: row.relation_type_id, relationTypeVersion: row.relation_type_version,
    sourceAssetId: row.source_asset_id, targetAssetId: row.target_asset_id };
}
export async function assetRows(tx: Tx, p: Principal, ids: readonly string[], lock = false): Promise<Row[]> {
  const unique = [...new Set(ids)].sort(); if (!unique.length) return [];
  if (unique.some(id => !uuid(id))) throw unavailable();
  // Check every requested identity without transferring any private values or exposing a size failure first.
  const hidden = await relationQuery(tx, () => sql`select 1 from unnest(${unique}::uuid[]) requested(id)
    left join assets a on a.tenant_id=${p.tenantId}::uuid and a.id=requested.id
      and (a.visibility='tenant' or a.allowed_identities @> ${JSON.stringify([p.id])}::jsonb)
    where a.id is null limit 1`.execute(tx));
  if (hidden.rows.length) throw unavailable();
  if (unique.length > 2000) throw profileLimit();
  const fields = ['tenant_id', 'id', 'name', 'version', 'model_id', 'model_version', 'type_state', 'visibility', 'allowed_identities'] as const;
  const query = tx.selectFrom('assets').where('tenant_id', '=', p.tenantId).where('id', 'in', unique)
    .where(sql<boolean>`(visibility='tenant' or allowed_identities @> ${JSON.stringify([p.id])}::jsonb)`);
  const size = await relationQuery(tx, () => query.select([sql<string>`count(*)::text`.as('count'), sql<string>`coalesce(sum(octet_length(jsonb_build_object(
    'tenant_id',tenant_id,'id',id,'name',name,'version',version,'model_id',model_id,'model_version',model_version,
    'type_state',type_state,'visibility',visibility,'allowed_identities',allowed_identities)::text)),0)::text`.as('bytes')]).executeTakeFirstOrThrow());
  if (Number(size.count) !== unique.length) throw unavailable();
  if (Number(size.bytes) > maximumBytes) throw profileLimit();
  let q = query.select(fields).orderBy('id'); if (lock) q = q.forUpdate();
  const rows = await relationQuery(tx, () => q.execute());
  if (rows.length !== unique.length || rows.some(row => !assetVisible(p, row))) throw unavailable(); return rows;
}
/** Caller has authorized/locked the endpoint union. Count policy copies before fetching even one resolved payload. */
export async function preflightEndpointPolicies(tx: Tx, p: Principal, assets: readonly Row[], additionalBytes = 0): Promise<void> {
  if (!assets.length) { if (additionalBytes > maximumBytes) throw profileLimit(); return; }
  const result = await relationQuery(tx, () => tx.selectFrom('assets as a').innerJoin('asset_type_versions as v', join => join
    .onRef('a.tenant_id', '=', 'v.tenant_id').onRef('a.model_id', '=', 'v.model_id').onRef('a.model_version', '=', 'v.version'))
    .select(sql<string>`coalesce(sum(octet_length(v.resolved::text)),0)::text`.as('bytes')).where('a.tenant_id', '=', p.tenantId)
    .where('a.id', 'in', assets.map(asset => asset.id)).executeTakeFirstOrThrow());
  if (Number(result.bytes) + additionalBytes > maximumBytes) throw profileLimit();
}
/** Resolve and verify each immutable exact pin once, with the same envelope/closure checks as assetTypePolicy. */
async function endpointPolicy(tx: Tx, p: Principal, modelId: string | null, version: number | null): Promise<EndpointPolicy> {
  if (modelId === null || version === null) return { policy: null, typeId: null, ancestorTypes: [] };
  const state = transactionState(tx), key = JSON.stringify([p.tenantId, modelId, version]), cached = state.policies.get(key); if (cached) return cached;
  const head = await relationQuery(tx, () => tx.selectFrom('governance_models').select('type_id').where('tenant_id', '=', p.tenantId).where('id', '=', modelId).executeTakeFirst());
  if (!head?.type_id) return { policy: null, typeId: null, ancestorTypes: [] };
  const fail = () => new Problem(500, 'ASSET_TYPE_STORAGE_INVALID', 'The stored asset type could not be verified.');
  const query = tx.selectFrom('asset_type_versions').where('tenant_id', '=', p.tenantId).where('model_id', '=', modelId).where('version', '=', version);
  const size = await relationQuery(tx, () => query.select([sql<number>`octet_length(resolved::text)`.as('resolved_bytes'), sql<number>`octet_length(definition::text)`.as('definition_bytes')]).executeTakeFirst());
  if (!size) throw fail(); if (state.policyBytes + size.resolved_bytes > maximumBytes || size.definition_bytes > 262144) throw profileLimit();
  const row = await relationQuery(tx, () => query.select(['model_id', 'version', 'definition', 'definition_hash', 'resolved', 'resolution_hash']).executeTakeFirstOrThrow());
  const stored = storedAssetType(row), definitions = []; let definitionBytes = size.definition_bytes;
  for (const pin of stored.dependencies) {
    const parentQuery = tx.selectFrom('asset_type_versions').where('tenant_id', '=', p.tenantId).where('model_id', '=', pin.id).where('version', '=', pin.version);
    const parentSize = await relationQuery(tx, () => parentQuery.select(sql<number>`octet_length(definition::text)`.as('bytes')).executeTakeFirst());
    if (!parentSize) throw fail(); definitionBytes += parentSize.bytes; if (definitionBytes > maximumBytes) throw profileLimit();
    const parent = await relationQuery(tx, () => parentQuery.select(['definition', 'definition_hash']).executeTakeFirstOrThrow());
    if (typeHash(parent.definition) !== parent.definition_hash) throw fail(); definitions.push(parent.definition);
  }
  const resolved = resolveAssetType(stored.definition, definitions);
  if (!resolved.ok || typeHash(resolved.value) !== row.resolution_hash) throw fail();
  const policy = resolved.value, keys = [policy.definition.id, ...policy.dependencies.map(pin => pin.id)];
  const identities = await relationQuery(tx, () => tx.selectFrom('governance_models').select(['id', 'type_id']).where('tenant_id', '=', p.tenantId).where('id', 'in', keys).execute());
  const mapping = new Map(identities.map(item => [item.id, item.type_id]));
  if (identities.length !== keys.length || identities.some(item => !item.type_id)) throw fail();
  const value: EndpointPolicy = Object.freeze({ policy, typeId: head.type_id,
    ancestorTypes: Object.freeze(policy.dependencies.map(pin => Object.freeze({ typeId: mapping.get(pin.id)!, id: pin.id, version: pin.version }))) });
  const bytes = Buffer.byteLength(JSON.stringify(value)); if (state.policyBytes + bytes > maximumBytes) throw profileLimit();
  checkRelationDeadline(tx); state.policyBytes += bytes; state.policies.set(key, value); return value;
}
export async function endpointState(tx: Tx, p: Principal, asset: Row): Promise<RelationEndpointPolicyState> {
  const resolved = await endpointPolicy(tx, p, asset.model_id ?? null, asset.model_version ?? null);
  return { assetId: asset.id, assetVersion: asset.version, modelId: asset.model_id ?? null, modelVersion: asset.model_version ?? null,
    state: asset.type_state ?? null, ...resolved };
}
export async function endpointView(tx: Tx, p: Principal, asset: Row): Promise<RelationEndpointView> {
  const type = asset.model_id ? await relationQuery(tx, () => tx.selectFrom('governance_models').select('type_id').where('tenant_id', '=', p.tenantId).where('id', '=', asset.model_id).executeTakeFirst()) : null;
  return { assetId: asset.id, name: asset.name, assetVersion: asset.version, typeId: type?.type_id ?? null,
    modelId: asset.model_id ?? null, modelVersion: asset.model_version ?? null, state: asset.type_state ?? null };
}
export async function relationView(tx: Tx, p: Principal, row: Row, providedAssets?: readonly Row[]): Promise<RelationView> {
  const assets = providedAssets ?? await assetRows(tx, p, [row.source_asset_id, row.target_asset_id]);
  const source = assets.find(asset => asset.id === row.source_asset_id), target = assets.find(asset => asset.id === row.target_asset_id);
  if (!source || !target || !assetVisible(p, source) || !assetVisible(p, target)) throw unavailable();
  const policy = storedRelationType(await relationTypeVersion(tx, p, row.relation_type_id, row.relation_type_version)).definition;
  return { id: row.id, relationTypeId: row.relation_type_id, relationTypeKey: policy.id, relationTypeVersion: row.relation_type_version, version: row.version,
    source: await endpointView(tx, p, source), target: await endpointView(tx, p, target), direction: policy.direction, label: policy.label, inverseLabel: policy.inverseLabel,
    attributes: row.attributes, ownerId: row.owner_id, state: row.state, validFrom: row.valid_from === null ? null : iso(row.valid_from), validTo: row.valid_to === null ? null : iso(row.valid_to),
    visibility: row.visibility, allowedIdentityIds: row.allowed_identities, status: row.status, provenance: row.provenance,
    createdAt: iso(row.created_at), createdBy: row.created_by, updatedAt: iso(row.updated_at), updatedBy: row.updated_by };
}
export async function lockRelationPrincipals(tx: Tx, p: Principal, requested: readonly (string | null)[], actions: readonly string[]) {
  const ids = [...new Set([p.id, ...requested.filter((id): id is string => id !== null)])].sort();
  if (ids.length > 2001 || ids.some(id => !uuid(id))) throw profileLimit();
  await relationQuery(tx, () => sql`select public.gc_lock_type_migration_principals(${ids}::uuid[])`.execute(tx));
  await relationQuery(tx, () => persistence.authorize(tx, p, actions));
  const members = await relationQuery(tx, () => tx.selectFrom('memberships').innerJoin('identities', 'identities.id', 'memberships.identity_id')
    .select(['memberships.identity_id', 'memberships.active', 'identities.active as identity_active']).where('memberships.tenant_id', '=', p.tenantId)
    .where('memberships.identity_id', 'in', ids).execute());
  return { members: new Set<string>(members.map(row => row.identity_id)), active: new Set<string>(members.filter(row => row.active && row.identity_active).map(row => row.identity_id)) };
}
export async function completeRelationRows(tx: Tx, p: Principal, typeId: string): Promise<Row[]> {
  const query = tx.selectFrom('relations as r').where('r.tenant_id', '=', p.tenantId).where('r.relation_type_id', '=', typeId).where('r.status', '=', 'active');
  if (await relationQuery(tx, () => query.select('r.id').where(sql<boolean>`NOT (${visibleRelationPredicate(p)})`).limit(1).executeTakeFirst())) throw hiddenScope();
  const size = await relationQuery(tx, () => query.select([sql<string>`count(*)::text`.as('count'), sql<string>`coalesce(sum(octet_length(to_jsonb(r)::text)),0)::text`.as('bytes')]).executeTakeFirstOrThrow());
  if (Number(size.count) > 1000 || Number(size.bytes) > 524288) throw profileLimit();
  return relationQuery(tx, () => query.selectAll('r').orderBy('r.id').execute());
}
export async function lockRelationRows(tx: Tx, p: Principal, rows: readonly Row[]): Promise<Row[]> {
  if (!rows.length) return [];
  return relationQuery(tx, () => tx.selectFrom('relations').selectAll().where('tenant_id', '=', p.tenantId).where('id', 'in', rows.map(row => row.id)).orderBy('id').forUpdate().execute());
}
export async function relationPolicies(tx: Tx, p: Principal, rows: readonly Row[]): Promise<RelationPolicyPin[]> {
  const policies: RelationPolicyPin[] = [], seen = new Set<string>(); let bytes = 0;
  for (const row of rows) {
    const key = `${row.relation_type_id}@${row.relation_type_version}`; if (seen.has(key)) continue; seen.add(key);
    const version = await relationTypeVersion(tx, p, row.relation_type_id, row.relation_type_version), policy = storedRelationType(version);
    bytes += Buffer.byteLength(JSON.stringify(policy)); if (bytes > 524288) throw profileLimit();
    policies.push({ relationTypeId: row.relation_type_id, policy });
  }
  return policies;
}
