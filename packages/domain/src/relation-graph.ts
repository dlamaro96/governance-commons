// SPDX-License-Identifier: Apache-2.0
import { createHmac, timingSafeEqual } from 'node:crypto';
import { lockTenantLedger, sql, type Tx } from '../../db/src/index.ts';
import { Problem, type Principal } from '../../authz/src/index.ts';
import { modelPersistence as persistence } from './model-service.ts';
import { typeHash } from './asset-type-policy.ts';
import { signedCursor } from './cursor.ts';
import { parseRelationValidity, traverseAuthorizedRelations } from './relation.ts';
import type { RelationGraphPage, RelationGraphQuery, RelationListPage, RelationListQuery, RelationEndpointView, RelationView } from './relation-contracts.ts';
import { RELATION_READ, configureRelationTransaction, relationQuery, profileLimit, unavailable, visibleRelationPredicate, assetVisible, storedRelationType, iso, uuid, type Row } from './relation-store.ts';

const invalid = () => new Problem(400, 'RELATION_PAGE_INVALID', 'The relationship query or page cursor is invalid.');
const stale = () => new Problem(409, 'RELATION_GRAPH_STALE', 'The graph snapshot changed. Restart from the first page.');
function stamp(input: unknown): string {
  const parsed = parseRelationValidity({ validFrom: input, validTo: null });
  if (!parsed.ok || parsed.value.validFrom === null) throw invalid(); return parsed.value.validFrom;
}
function fence(secret: string, p: Principal, root: string, purpose: string, context: unknown, counter: string): string {
  return createHmac('sha256', secret).update('governance-commons:graph-fence:v1\0')
    .update(JSON.stringify([1, purpose, p.tenantId, p.id, root, context, counter])).digest('base64url');
}
async function endpointViews(tx: Tx, p: Principal, ids: readonly string[]): Promise<RelationEndpointView[]> {
  if (!ids.length) return [];
  const rows = await tx.selectFrom('assets as a').leftJoin('governance_models as m', join => join.onRef('a.tenant_id', '=', 'm.tenant_id').onRef('a.model_id', '=', 'm.id'))
    .select(['a.id', 'a.tenant_id', 'a.name', 'a.version', 'a.model_id', 'a.model_version', 'a.type_state', 'a.visibility', 'a.allowed_identities', 'm.type_id'])
    .where('a.tenant_id', '=', p.tenantId).where('a.id', 'in', [...new Set(ids)]).orderBy('a.id').execute();
  if (rows.length !== new Set(ids).size || rows.some(row => !assetVisible(p, row))) throw unavailable();
  return rows.map(row => ({ assetId: row.id, name: row.name, assetVersion: row.version, typeId: row.type_id ?? null,
    modelId: row.model_id, modelVersion: row.model_version, state: row.type_state }));
}
function edgeView(row: Row, nodes: Map<string, RelationEndpointView>): RelationView {
  const definition = storedRelationType({ definition: row.type_definition, definition_hash: row.type_hash, version: row.relation_type_version }).definition;
  return { id: row.id, relationTypeId: row.relation_type_id, relationTypeKey: definition.id, relationTypeVersion: row.relation_type_version, version: row.version,
    source: nodes.get(row.source_asset_id)!, target: nodes.get(row.target_asset_id)!, direction: definition.direction, label: definition.label, inverseLabel: definition.inverseLabel,
    attributes: row.attributes, ownerId: row.owner_id, state: row.state, validFrom: row.valid_from === null ? null : iso(row.valid_from), validTo: row.valid_to === null ? null : iso(row.valid_to),
    visibility: row.visibility, allowedIdentityIds: row.allowed_identities, status: row.status, provenance: row.provenance,
    createdAt: iso(row.created_at), createdBy: row.created_by, updatedAt: iso(row.updated_at), updatedBy: row.updated_by };
}
async function graphPage(tx: Tx, p: Principal, rootId: string, query: RelationGraphQuery, purpose: 'asset-relations' | 'asset-graph'): Promise<RelationGraphPage | RelationListPage> {
  await relationQuery(tx, () => persistence.authorize(tx, p, RELATION_READ));
  await relationQuery(tx, () => lockTenantLedger(tx, p.tenantId));
  await relationQuery(tx, () => persistence.authorize(tx, p, RELATION_READ));
  const budget = () => configureRelationTransaction(tx);
  const limit = query.limit ?? 25, depth = purpose === 'asset-graph' ? query.depth ?? 1 : 1, direction = query.direction ?? 'both', typeId = query.relationTypeId ?? null;
  if (!uuid(rootId) || !Number.isInteger(limit) || limit < 1 || limit > 100 || !Number.isInteger(depth) || depth < 1 || depth > 6 ||
      !['in', 'out', 'both'].includes(direction) || typeId !== null && !uuid(typeId)) throw invalid();
  const signer = signedCursor(process.env.SESSION_KEY, purpose); // Also enforces a configured, sufficiently long server key.
  let decoded: any = null;
  if (query.cursor !== undefined) try {
    decoded = signer.decode(query.cursor);
    if (!decoded || Object.keys(decoded).sort().join('|') !== 'binding|fence|last|v|validAt' || decoded.v !== 1 || !uuid(decoded.last) ||
      typeof decoded.fence !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(decoded.fence)) throw Error();
  } catch { throw invalid(); }
  let validAt: string | null;
  if (query.validAt !== undefined) validAt = stamp(query.validAt);
  else if (purpose === 'asset-relations') validAt = null;
  else validAt = decoded ? stamp(decoded.validAt) : new Date().toISOString();
  // Bind the resolved instant, so clients may echo a defaulted first-page
  // instant or omit it on subsequent pages. Unfiltered lists retain null.
  const context = { direction, depth, relationTypeId: typeId, validAt, limit, sort: 'id:asc' };
  const binding = typeHash([p.tenantId, p.id, rootId, purpose, context]);
  if (decoded && (decoded.binding !== binding || decoded.validAt !== validAt)) throw invalid();
  await budget();
  const root = (await endpointViews(tx, p, [rootId]))[0];
  await budget();
  const counter = await tx.selectFrom('tenant_graph_revisions').select(sql<string>`revision::text`.as('value')).where('tenant_id', '=', p.tenantId).executeTakeFirst();
  const graphRevision = fence(process.env.SESSION_KEY!, p, rootId, purpose, context, counter?.value ?? '0');
  if (decoded && !timingSafeEqual(Buffer.from(decoded.fence), Buffer.from(graphRevision))) throw stale();
  const nodes = new Map<string, RelationEndpointView>([[rootId, root]]), rows = new Map<string, Row>(), visited = new Set<string>([rootId]), expanded: string[] = [];
  let frontier = [rootId];
  for (let level = 0; level < depth && frontier.length; level += 1) {
    await budget(); expanded.push(...frontier);
    let base = tx.selectFrom('relations as r').innerJoin('relation_type_versions as v', join => join.onRef('r.tenant_id', '=', 'v.tenant_id')
      .onRef('r.relation_type_id', '=', 'v.relation_type_id').onRef('r.relation_type_version', '=', 'v.version'))
      .where('r.tenant_id', '=', p.tenantId).where('r.status', '=', 'active').where(visibleRelationPredicate(p))
      .where(eb => eb.or([
        ...(direction !== 'in' ? [eb('r.source_asset_id', 'in', frontier)] : []),
        ...(direction !== 'out' ? [eb('r.target_asset_id', 'in', frontier)] : []),
        eb.and([sql<boolean>`v.definition->>'direction'='undirected'`, eb.or([eb('r.source_asset_id', 'in', frontier), eb('r.target_asset_id', 'in', frontier)])]),
      ]));
    if (typeId !== null) base = base.where('r.relation_type_id', '=', typeId);
    if (validAt !== null) base = base.where(sql<boolean>`(r.valid_from IS NULL OR r.valid_from <= ${validAt}::timestamptz) AND (r.valid_to IS NULL OR r.valid_to > ${validAt}::timestamptz)`);
    if (rows.size) base = base.where('r.id', 'not in', [...rows.keys()]);
    // Only matching authorized adjacency contributes to these bounds. Nothing about hidden/unrelated scope is returned.
    await budget();
    const size = await base.select([sql<string>`count(*)::text`.as('count'), sql<string>`coalesce(sum(octet_length(to_jsonb(r)::text)+octet_length(v.definition::text)),0)::text`.as('bytes')]).executeTakeFirstOrThrow();
    if (rows.size + Number(size.count) > 5000 || Number(size.bytes) > 524288) throw profileLimit();
    await budget();
    const batch = await base.selectAll('r').select(['v.definition as type_definition', 'v.definition_hash as type_hash']).orderBy('r.id').execute();
    for (const row of batch) rows.set(row.id, row);
    const missing = [...new Set(batch.flatMap(row => [row.source_asset_id, row.target_asset_id]))].filter(id => !nodes.has(id));
    if (nodes.size + missing.length > 1000) throw profileLimit();
    await budget();
    for (const node of await endpointViews(tx, p, missing)) nodes.set(node.assetId, node);
    const next = new Set<string>(), current = new Set(frontier);
    for (const row of rows.values()) {
      const undirected = row.type_definition.direction === 'undirected';
      if ((direction !== 'in' || undirected) && current.has(row.source_asset_id) && !visited.has(row.target_asset_id)) next.add(row.target_asset_id);
      if ((direction !== 'out' || undirected) && current.has(row.target_asset_id) && !visited.has(row.source_asset_id)) next.add(row.source_asset_id);
    }
    const projected = [...rows.values()].map(row => edgeView(row, nodes));
    if (Buffer.byteLength(JSON.stringify({ nodes: [...nodes.values()], edges: projected })) > 524288) throw profileLimit();
    for (const id of next) visited.add(id); frontier = [...next].sort();
  }
  await budget();
  let selected = [...rows.values()].map(row => edgeView(row, nodes)).sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  if (purpose === 'asset-graph') {
    const traversed = traverseAuthorizedRelations({ rootAssetId: rootId, direction, depth, validAt: validAt!, relationTypeId: typeId,
      nodes: [...nodes.values()], edges: selected, completeFrontierAssetIds: expanded });
    if (!traversed.ok) throw profileLimit(); selected = [...traversed.value.edges];
  }
  if (decoded) selected = selected.filter(edge => edge.id > decoded.last);
  const items = selected.slice(0, limit), nextCursor = selected.length > limit ? signer.encode({ v: 1, binding, fence: graphRevision, last: items.at(-1)!.id, validAt }) : null;
  await budget();
  await persistence.authorize(tx, p, RELATION_READ);
  await budget();
  if (purpose === 'asset-relations') return { items, nextCursor, graphRevision };
  const included = new Set([rootId, ...items.flatMap(edge => [edge.source.assetId, edge.target.assetId])]);
  return { rootAssetId: rootId, direction, depth, validAt: validAt!, graphRevision, nextCursor, edges: items,
    nodes: [...nodes.values()].filter(node => included.has(node.assetId)).sort((a, b) => a.assetId < b.assetId ? -1 : a.assetId > b.assetId ? 1 : 0) };
}
export async function listAssetRelations(tx: Tx, p: Principal, id: string, query: RelationListQuery = {}): Promise<RelationListPage> {
  return graphPage(tx, p, id, query, 'asset-relations') as Promise<RelationListPage>;
}
export async function getAssetGraph(tx: Tx, p: Principal, id: string, query: RelationGraphQuery = {}): Promise<RelationGraphPage> {
  return graphPage(tx, p, id, query, 'asset-graph') as Promise<RelationGraphPage>;
}
