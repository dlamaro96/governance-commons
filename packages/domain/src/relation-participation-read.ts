// SPDX-License-Identifier: Apache-2.0
import { createHmac, timingSafeEqual } from 'node:crypto';
import { sql, type Tx } from '../../db/src/index.ts';
import { Problem, type Principal } from '../../authz/src/index.ts';
import { signedCursor } from './cursor.ts';
import { typeHash } from './asset-type-policy.ts';
import { modelPersistence } from './model-service.ts';
import { structuralProjection } from './relation-participation.ts';
import { participationView } from './relation-migration-service.ts';
import { visibleRelationOperation } from './relation-migration-read.ts';
import { RELATION_READ, hiddenScope, iso, lockRelationPrincipals, lockRelationScope,
  profileLimit, relationQuery, storedRelationType, unavailable, uuid, visibleRelationPredicate, type Row } from './relation-store.ts';
import type { ParticipationBindingView, ParticipationHistoryPage, ParticipationItem, ParticipationListPage,
  ParticipationListQuery, ParticipationRevisionView, RelationPolicySnapshot } from './relation-migration-contracts.ts';

const invalid = () => new Problem(400, 'RELATION_PAGE_INVALID', 'The participation query or page cursor is invalid.');
const stale = () => new Problem(409, 'RELATION_GRAPH_STALE', 'The graph snapshot changed. Restart from the first page.');
const corrupt = () => new Problem(500, 'RELATION_STORAGE_INVALID', 'The stored participation could not be verified.');
const maxBytes = 524288;
const version = (value: unknown): value is number => Number.isInteger(value) && Number(value) > 0 && Number(value) <= 2147483647;
type HistoryQuery = Pick<ParticipationListQuery, 'limit' | 'cursor'>;
type Purpose = 'asset-participation' | 'binding-participation-history';
interface Cursor { v: 1; binding: string; fence: string; last: string | number }

function queryValues(query: ParticipationListQuery | HistoryQuery, history: boolean) {
  if (!query || typeof query !== 'object' || Array.isArray(query) || ![Object.prototype, null].includes(Object.getPrototypeOf(query))) throw invalid();
  const descriptors = Object.getOwnPropertyDescriptors(query), allowed = history ? ['limit', 'cursor'] : ['limit', 'cursor', 'status'];
  if (Reflect.ownKeys(query).some(key => typeof key !== 'string' || !allowed.includes(key)) ||
      Object.values(descriptors).some(value => !('value' in value) || !value.enumerable)) throw invalid();
  const limit = descriptors.limit?.value ?? 50, cursor = descriptors.cursor?.value;
  const status = descriptors.status?.value ?? 'active';
  if (!Number.isInteger(limit) || limit < 1 || limit > 100 ||
      cursor !== undefined && (typeof cursor !== 'string' || !cursor.length || cursor.length > 1024) ||
      !['active', 'released', 'all'].includes(status) || descriptors.limit?.value === null || descriptors.status?.value === null) throw invalid();
  return { limit: limit as number, cursor: cursor as string | undefined, status: status as 'active' | 'released' | 'all' };
}

/** The tenant ledger serializes graph/ACL writers. Principal locks additionally
 * serialize identity and membership revocation, which need not change the fence. */
async function start(tx: Tx, p: Principal, assetId: string) {
  await lockRelationScope(tx, p, RELATION_READ);
  await lockRelationPrincipals(tx, p, [], RELATION_READ);
  if (!uuid(assetId)) throw unavailable();
  const row = await relationQuery(tx, () => tx.selectFrom('assets').select(['id', 'version'])
    .where('tenant_id', '=', p.tenantId).where('id', '=', assetId)
    .where(sql<boolean>`(visibility='tenant' OR allowed_identities @> ${JSON.stringify([p.id])}::jsonb)`).executeTakeFirst());
  if (!row) throw unavailable(); if (!version(row.version)) throw corrupt();
  return row;
}

async function pageState(tx: Tx, p: Principal, assetId: string, purpose: Purpose, context: object, cursor?: string) {
  const signer = signedCursor(process.env.SESSION_KEY, purpose);
  const binding = typeHash([p.tenantId, p.id, assetId, purpose, context]);
  let decoded: Cursor | null = null;
  if (cursor !== undefined) {
    try {
      const value = signer.decode(cursor) as Cursor | null;
      if (!value || Object.keys(value).sort().join('|') !== 'binding|fence|last|v' || value.v !== 1 || value.binding !== binding ||
          typeof value.fence !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value.fence) ||
          !(purpose === 'asset-participation' ? uuid(value.last) : version(value.last))) throw invalid();
      decoded = value;
    } catch { throw invalid(); }
  }
  const row = await relationQuery(tx, () => tx.selectFrom('tenant_graph_revisions').select(sql<string>`revision::text`.as('value'))
    .where('tenant_id', '=', p.tenantId).executeTakeFirst());
  // Only this keyed token may leave the service; the internal counter is never
  // included in a signed payload, public response, error or audit detail.
  const snapshotToken = createHmac('sha256', process.env.SESSION_KEY!)
    .update('governance-commons:graph-fence:v1\0')
    .update(JSON.stringify([1, purpose, p.tenantId, p.id, assetId, context, row?.value ?? '0'])).digest('base64url');
  if (decoded && !timingSafeEqual(Buffer.from(decoded.fence), Buffer.from(snapshotToken))) throw stale();
  return { snapshotToken, last: decoded?.last, next: (last: string | number) => signer.encode({ v: 1, binding, fence: snapshotToken, last }) };
}

function bindingSnapshot(input: unknown): ParticipationBindingView {
  const keys = ['id', 'version', 'relationTypeId', 'relationTypeVersion', 'assetId', 'assetVersion', 'side', 'status', 'createdBy', 'createdAt', 'updatedBy', 'updatedAt'];
  if (!input || typeof input !== 'object' || Array.isArray(input) || ![Object.prototype, null].includes(Object.getPrototypeOf(input))) throw corrupt();
  const fields = Object.getOwnPropertyDescriptors(input);
  if (Reflect.ownKeys(input).length !== keys.length || keys.some(key => !fields[key] || !('value' in fields[key]) || !fields[key].enumerable)) throw corrupt();
  const row = input as ParticipationBindingView;
  if (![row.id, row.relationTypeId, row.assetId, row.createdBy, row.updatedBy].every(uuid) ||
      ![row.version, row.relationTypeVersion, row.assetVersion].every(version) || !['source', 'target', 'incident'].includes(row.side) ||
      !['active', 'released'].includes(row.status)) throw corrupt();
  try { if ([row.createdAt, row.updatedAt].some(value => typeof value !== 'string' || iso(value) !== value)) throw corrupt(); }
  catch { throw corrupt(); }
  return row;
}
function currentBinding(row: Row): ParticipationBindingView {
  try { return bindingSnapshot(participationView(row)); } catch { throw corrupt(); }
}
function policyView(row: Row, binding: ParticipationBindingView): RelationPolicySnapshot {
  if (row.policy_version !== binding.relationTypeVersion || row.relation_type_id !== binding.relationTypeId) throw corrupt();
  try {
    const resolved = storedRelationType({ definition: row.policy_definition, version: row.policy_version, definition_hash: row.policy_hash });
    if ((resolved.definition.direction === 'directed') === (binding.side === 'incident')) throw corrupt();
    return { relationTypeId: binding.relationTypeId, ...resolved };
  } catch (error) { if (error instanceof Problem && error.code === 'RELATION_PROFILE_LIMIT') throw error; throw corrupt(); }
}
async function boundedRows(tx: Tx, query: any): Promise<Row[]> {
  // Bound the complete physical rows and exact policy copies, including the
  // lookahead, before transferring any JSON snapshot/definition to the process.
  const size = await relationQuery(tx, () => tx.selectFrom(query.as('bounded'))
    .select(sql<string>`coalesce(sum(octet_length(to_jsonb(bounded)::text)),0)::text`.as('bytes')).executeTakeFirstOrThrow());
  if (!/^\d+$/.test(String(size.bytes)) || BigInt(size.bytes) > BigInt(maxBytes)) throw profileLimit();
  return relationQuery(tx, () => query.execute());
}
async function finish<T extends ParticipationListPage | ParticipationHistoryPage>(tx: Tx, p: Principal, page: T): Promise<T> {
  if (Buffer.byteLength(JSON.stringify(page)) > maxBytes) throw profileLimit();
  await relationQuery(tx, () => modelPersistence.authorize(tx, p, RELATION_READ));
  return page;
}

export async function listAssetParticipation(tx: Tx, p: Principal, assetId: string, query: ParticipationListQuery): Promise<ParticipationListPage> {
  const asset = await start(tx, p, assetId), { limit, cursor, status } = queryValues(query, false);
  // Check ALL matching bindings' complete structural degree scope before a
  // count, cursor fence or page. Hidden edges must never become a lower degree.
  const hidden = await relationQuery(tx, () => sql`SELECT 1 FROM relations r
    WHERE r.tenant_id=${p.tenantId}::uuid AND r.status='active'
      AND EXISTS (SELECT 1 FROM relation_participations b WHERE b.tenant_id=r.tenant_id
        AND b.asset_id=${assetId}::uuid AND (${status}='all' OR b.status=${status})
        AND b.relation_type_id=r.relation_type_id AND
        ((b.side='source' AND r.source_asset_id=b.asset_id) OR (b.side='target' AND r.target_asset_id=b.asset_id)
          OR (b.side='incident' AND (r.source_asset_id=b.asset_id OR r.target_asset_id=b.asset_id))))
      AND NOT (${visibleRelationPredicate(p)}) LIMIT 1`.execute(tx));
  if (hidden.rows.length) throw hiddenScope();
  const state = await pageState(tx, p, assetId, 'asset-participation', { status, limit, sort: 'id:asc' }, cursor);
  let rowsQuery = tx.selectFrom('relation_participations as b').leftJoin('relation_type_versions as v', join => join
    .onRef('b.tenant_id', '=', 'v.tenant_id').onRef('b.relation_type_id', '=', 'v.relation_type_id').onRef('b.relation_type_version', '=', 'v.version'))
    .selectAll('b').select(['v.definition as policy_definition', 'v.definition_hash as policy_hash', 'v.version as policy_version'])
    .select(sql<string>`(SELECT count(*)::text FROM relations r WHERE r.tenant_id=b.tenant_id
      AND r.relation_type_id=b.relation_type_id AND r.status='active'
      AND ((b.side='source' AND r.source_asset_id=b.asset_id) OR (b.side='target' AND r.target_asset_id=b.asset_id)
        OR (b.side='incident' AND (r.source_asset_id=b.asset_id OR r.target_asset_id=b.asset_id))))`.as('degree'))
    .where('b.tenant_id', '=', p.tenantId).where('b.asset_id', '=', assetId).orderBy('b.id', 'asc').limit(limit + 1);
  if (status !== 'all') rowsQuery = rowsQuery.where('b.status', '=', status);
  if (state.last !== undefined) rowsQuery = rowsQuery.where('b.id', '>', state.last);
  const rows = await boundedRows(tx, rowsQuery), items: ParticipationItem[] = rows.slice(0, limit).map(row => {
    const binding = currentBinding(row), policy = policyView(row, binding);
    if (binding.assetId !== assetId || !/^\d+$/.test(String(row.degree)) || !Number.isSafeInteger(Number(row.degree))) throw corrupt();
    const bounds = binding.side === 'target' ? policy.definition.cardinality.incoming : policy.definition.cardinality.outgoing;
    return { binding, currentAssetVersion: asset.version, policy, structuralFingerprint: typeHash(structuralProjection(policy.definition)),
      minimum: bounds.min, maximum: bounds.max, currentDegree: Number(row.degree) };
  });
  return finish(tx, p, { items, nextCursor: rows.length > limit ? state.next(items.at(-1)!.binding.id) : null, snapshotToken: state.snapshotToken });
}

export async function listParticipationRevisions(tx: Tx, p: Principal, assetId: string, bindingId: string, query: HistoryQuery): Promise<ParticipationHistoryPage> {
  await start(tx, p, assetId);
  if (!uuid(bindingId)) throw unavailable();
  const { limit, cursor } = queryValues(query, true);
  const bindingQuery = tx.selectFrom('relation_participations').where('tenant_id', '=', p.tenantId).where('asset_id', '=', assetId).where('id', '=', bindingId);
  if (!await relationQuery(tx, () => bindingQuery.select('id').executeTakeFirst())) throw unavailable();
  const history = tx.selectFrom('relation_participation_revisions as h').where('h.tenant_id', '=', p.tenantId).where('h.binding_id', '=', bindingId);
  // An inaccessible older operation denies the WHOLE history, even when it is
  // outside this page. Protected normalized outcome scope is the authority.
  if (await relationQuery(tx, () => history.select('h.binding_id')
    .where(sql<boolean>`NOT (${visibleRelationOperation(p, sql`h.operation_id`)})`).limit(1).executeTakeFirst())) throw hiddenScope();
  const state = await pageState(tx, p, assetId, 'binding-participation-history', { bindingId, limit, sort: 'version:desc' }, cursor);
  const currentRows = await boundedRows(tx, bindingQuery.selectAll());
  if (currentRows.length !== 1) throw corrupt();
  const current = currentBinding(currentRows[0]);
  if (current.id !== bindingId || current.assetId !== assetId) throw corrupt();
  let rowsQuery = history.leftJoin('relation_type_versions as v', join => join.onRef('h.tenant_id', '=', 'v.tenant_id')
    .onRef('h.relation_type_id', '=', 'v.relation_type_id').onRef('h.relation_type_version', '=', 'v.version'))
    .selectAll('h').select(['v.definition as policy_definition', 'v.definition_hash as policy_hash', 'v.version as policy_version'])
    .orderBy('h.version', 'desc').limit(limit + 1);
  if (state.last !== undefined) rowsQuery = rowsQuery.where('h.version', '<', state.last);
  const rows = await boundedRows(tx, rowsQuery), items: ParticipationRevisionView[] = rows.slice(0, limit).map(row => {
    const binding = bindingSnapshot(row.snapshot), policy = policyView(row, binding);
    let recordedAt: string; try { recordedAt = iso(row.recorded_at); } catch { throw corrupt(); }
    if (binding.id !== bindingId || row.binding_id !== bindingId || binding.assetId !== assetId || binding.version !== row.version || binding.relationTypeId !== row.relation_type_id ||
        binding.relationTypeVersion !== row.relation_type_version || binding.assetVersion !== row.asset_version || binding.assetId !== row.asset_id ||
        binding.side !== row.side || binding.relationTypeId !== current.relationTypeId || binding.side !== current.side ||
        binding.createdAt !== current.createdAt || binding.createdBy !== current.createdBy || binding.version > current.version ||
        binding.version === current.version && typeHash(binding) !== typeHash(current) || !uuid(row.operation_id) ||
        binding.updatedBy !== row.recorded_by || binding.updatedAt !== recordedAt) throw corrupt();
    return { binding, assetRevision: { id: binding.assetId, version: binding.assetVersion }, policy,
      operationId: row.operation_id, recordedBy: row.recorded_by, recordedAt };
  });
  return finish(tx, p, { items, nextCursor: rows.length > limit ? state.next(items.at(-1)!.binding.version) : null, snapshotToken: state.snapshotToken });
}
