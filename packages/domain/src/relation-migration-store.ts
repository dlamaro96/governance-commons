// SPDX-License-Identifier: Apache-2.0
import { sql, type Tx } from '../../db/src/index.ts';
import { Problem, type Principal } from '../../authz/src/index.ts';
import { modelPersistence as models } from './model-service.ts';
import { typeHash } from './asset-type-policy.ts';
import { previewModelUpgrade, validateAttributes, type ValidationIssue } from './model.ts';
import { discoverTypeMigration } from './asset-type-migration-service.ts';
import { projectGraphAssetChanges } from './graph-asset-preparation.ts';
import { relationPolicyChanges } from './relation-migration.ts';
import { parseGlossaryGraphSourceProof, validateGlossaryGraphSource, type GlossaryGraphSourceProof } from './relation-glossary-source.ts';
import { structuralProjection, validateFinalRelationGraphConstraints, policyKey } from './relation-participation.ts';
import { authorizeRelationRepairReference, getRelationPreparation } from './relation-migration-read.ts';
import { relationDefinition, relationQuery, lockRelationScope, lockRelationPrincipals, endpointState,
  storedRelationType, relationTypeVersion, endpointTypeIdentities, hiddenScope, profileLimit,
  unavailable, iso, type Row } from './relation-store.ts';
import type { GraphChangeSet, RelationMigrationContextRequest, RelationMigrationContext, GraphAssetPolicyEvidence,
  GraphAssetBefore, GraphEdgeSnapshot, GraphBindingSnapshot, RelationPolicySnapshot, RelationTargetEvidence } from './relation-migration-contracts.ts';
import type { RelationEndpointPolicyState } from './relation-contracts.ts';

export const GRAPH_WRITE = ['catalog:read', 'catalog:write', 'models:read', 'models:write'] as const;
export const graphStale = () => new Problem(409, 'RELATION_PREVIEW_STALE', 'The complete scope changed. Load it again and run a fresh preview.');
export const graphStorage = () => new Problem(500, 'RELATION_STORAGE_INVALID', 'The stored graph and its immutable history could not be verified.');
export async function graphPhysicalBudget(tx: Tx, value: unknown): Promise<void> {
  const text = JSON.stringify(value); if (Buffer.byteLength(text) > 524288) throw profileLimit();
  const result = await relationQuery(tx, () => sql<{ bytes: number }>`select octet_length(${text}::jsonb::text) as bytes`.execute(tx));
  if (result.rows[0].bytes > 524288) throw profileLimit();
}
export function graphRequest(changeSet: GraphChangeSet): RelationMigrationContextRequest {
  return { ...changeSet, relationTargets: changeSet.relationTargets.map(({ plan, ...target }) => ({ ...target, relationTypeId: plan.relationTypeId })) };
}

/** One SQL closure, reused for authorization, scalar bounds and capture. Scope
 * projection resolves only nominal pins/lifecycles; attribute transformation is
 * deliberately later, so an invalid repair cannot conceal zero-degree assets.
 * Materialized nominal candidates only avoid unrelated eligibility calls. Exact
 * eligibility still uses pinned ancestry/state; explicit and incident assets
 * enter independently, including untyped or currently ineligible endpoints. */
function scopeCTE(p: Principal, request: RelationMigrationContextRequest, changeSet?: GraphChangeSet, sourceProof?: GlossaryGraphSourceProof) {
  const targets = request.relationTargets, direct = request.assetChanges.map(row => row.assetId), models = request.assetTypeMigrations.map(row => row.definition.id);
  const body = JSON.stringify({ changeSet: { ...request, relationTargets: [] } });
  const extra = [...(changeSet?.relationTargets.flatMap(target => target.plan.creations.flatMap(row => [row.sourceAssetId, row.targetAssetId])) ?? []), ...(sourceProof ? [sourceProof.afterEndpoint.assetId] : [])];
  return sql`WITH explicit_targets AS MATERIALIZED (
    SELECT (x->>'relationTypeId')::uuid AS type_id, h.current_version,
      v.definition AS before_definition, CASE WHEN x->>'kind'='repair' THEN v.definition ELSE x->'definition' END AS after_definition
    FROM jsonb_array_elements(${JSON.stringify(targets)}::jsonb) e(x)
    LEFT JOIN relation_types h ON h.tenant_id=${p.tenantId}::uuid AND h.type_id=(x->>'relationTypeId')::uuid
    LEFT JOIN relation_type_versions v ON v.tenant_id=h.tenant_id AND v.relation_type_id=h.type_id AND v.version=h.current_version
  ), changed_assets AS MATERIALIZED (
    SELECT a.id, public.gc_relation_graph_project_endpoint(a,${body}::jsonb) AS proposed
    FROM assets a WHERE a.tenant_id=${p.tenantId}::uuid AND (a.id=ANY(${direct}::uuid[]) OR a.model_id=ANY(${models}::text[]))
  ), all_types AS MATERIALIZED (
    SELECT * FROM explicit_targets UNION ALL
    SELECT h.type_id,h.current_version,v.definition,v.definition FROM relation_types h
    JOIN relation_type_versions v ON v.tenant_id=h.tenant_id AND v.relation_type_id=h.type_id AND v.version=h.current_version
    WHERE h.tenant_id=${p.tenantId}::uuid AND NOT EXISTS(SELECT 1 FROM explicit_targets x WHERE x.type_id=h.type_id)
    AND (h.type_id=ANY(${sourceProof?.relationTypeIds ?? []}::uuid[]) OR EXISTS(SELECT 1 FROM changed_assets a WHERE
      public.gc_relation_endpoint_eligible(${p.tenantId}::uuid,a.id,v.definition,'source') OR public.gc_relation_endpoint_eligible(${p.tenantId}::uuid,a.id,v.definition,'target')
      OR public.gc_relation_projected_eligible(a.proposed,v.definition,'source') OR public.gc_relation_projected_eligible(a.proposed,v.definition,'target')
      OR EXISTS(SELECT 1 FROM relations r WHERE r.tenant_id=h.tenant_id AND r.relation_type_id=h.type_id AND r.status='active' AND a.id IN(r.source_asset_id,r.target_asset_id))
      OR EXISTS(SELECT 1 FROM relation_participations b WHERE b.tenant_id=h.tenant_id AND b.relation_type_id=h.type_id AND b.status='active' AND b.asset_id=a.id)))
  ), all_edges AS MATERIALIZED (
    SELECT r.id,r.source_asset_id,r.target_asset_id FROM relations r WHERE r.tenant_id=${p.tenantId}::uuid AND r.status='active' AND r.relation_type_id IN(SELECT type_id FROM all_types)
  ), all_bindings AS MATERIALIZED (
    SELECT b.id,b.asset_id FROM relation_participations b WHERE b.tenant_id=${p.tenantId}::uuid AND b.status='active' AND b.relation_type_id IN(SELECT type_id FROM all_types)
  ), eligibility_rules AS MATERIALIZED (
    SELECT DISTINCT (rule->>'typeId')::uuid AS type_id, rule->>'includeDescendants'='true' AS descendants
    FROM all_types t CROSS JOIN LATERAL jsonb_array_elements(
      coalesce(t.before_definition->'sourceTypes','[]'::jsonb) || coalesce(t.before_definition->'targetTypes','[]'::jsonb)
      || coalesce(t.after_definition->'sourceTypes','[]'::jsonb) || coalesce(t.after_definition->'targetTypes','[]'::jsonb)) rules(rule)
  ), nominal_assets AS MATERIALIZED (
    SELECT a.id FROM eligibility_rules r JOIN governance_models m ON m.tenant_id=${p.tenantId}::uuid AND m.type_id=r.type_id
      JOIN assets a ON a.tenant_id=m.tenant_id AND a.model_id=m.id
    UNION
    SELECT a.id FROM eligibility_rules r JOIN governance_models ancestor ON ancestor.tenant_id=${p.tenantId}::uuid AND ancestor.type_id=r.type_id
      JOIN asset_type_dependencies d ON d.tenant_id=ancestor.tenant_id AND d.dependency_model_id=ancestor.id
      JOIN assets a ON a.tenant_id=d.tenant_id AND a.model_id=d.model_id AND a.model_version=d.version WHERE r.descendants
  ), eligible_assets AS MATERIALIZED (
    SELECT n.id FROM nominal_assets n WHERE EXISTS(SELECT 1 FROM all_types t WHERE
      public.gc_relation_endpoint_eligible(${p.tenantId}::uuid,n.id,t.before_definition,'source') OR public.gc_relation_endpoint_eligible(${p.tenantId}::uuid,n.id,t.before_definition,'target')
      OR public.gc_relation_endpoint_eligible(${p.tenantId}::uuid,n.id,t.after_definition,'source') OR public.gc_relation_endpoint_eligible(${p.tenantId}::uuid,n.id,t.after_definition,'target'))
  ), all_assets AS MATERIALIZED (
    SELECT a.id FROM assets a WHERE a.tenant_id=${p.tenantId}::uuid AND (a.id IN(SELECT id FROM changed_assets)
      OR a.id=ANY(${extra}::uuid[]) OR a.id IN(SELECT source_asset_id FROM all_edges UNION SELECT target_asset_id FROM all_edges UNION SELECT asset_id FROM all_bindings)
      OR a.id IN(SELECT id FROM eligible_assets))
  )`;
}

function edgeSnapshot(row: Row, assets: Map<string, Row>): GraphEdgeSnapshot {
  return { key: { kind: 'existing', relationId: row.id }, version: row.version, relationTypeId: row.relation_type_id,
    relationTypeVersion: row.relation_type_version, sourceAssetId: row.source_asset_id, sourceAssetVersion: assets.get(row.source_asset_id)!.version,
    targetAssetId: row.target_asset_id, targetAssetVersion: assets.get(row.target_asset_id)!.version, status: row.status,
    values: { attributes: row.attributes, ownerId: row.owner_id, state: row.state, validFrom: row.valid_from === null ? null : iso(row.valid_from),
      validTo: row.valid_to === null ? null : iso(row.valid_to), visibility: row.visibility, allowedIdentityIds: row.allowed_identities } };
}
function bindingSnapshot(row: Row, assets: Map<string, Row>): GraphBindingSnapshot {
  return { key: { kind: 'existing', bindingId: row.id }, version: row.version, relationTypeId: row.relation_type_id,
    relationTypeVersion: row.relation_type_version, assetId: row.asset_id, assetVersion: assets.get(row.asset_id)!.version, side: row.side, status: row.status };
}
function referencedPrincipals(request: RelationMigrationContextRequest, changeSet?: GraphChangeSet): (string | null)[] {
  const ids: (string | null)[] = request.assetChanges.flatMap(row => row.kind === 'assign' ? [row.ownerId] : []);
  ids.push(...request.assetTypeMigrations.flatMap(row => row.plan.owner.overrides.map(item => item.ownerId)));
  for (const target of changeSet?.relationTargets ?? []) {
    ids.push(...(target.plan.transform?.owner.overrides.map(row => row.ownerId) ?? []));
    for (const row of [...target.plan.edges, ...target.plan.creations]) if ('values' in row) ids.push(row.values.ownerId, ...row.values.allowedIdentityIds);
  }
  return ids;
}

async function captureMigration(tx: Tx, p: Principal, request: RelationMigrationContextRequest, changeSet?: GraphChangeSet, sourceProof?: GlossaryGraphSourceProof) {
  await lockRelationScope(tx, p, GRAPH_WRITE);
  // Direct subjects have a uniform404; complete implicit cohorts have a uniform
  // scope refusal. Both precede target diagnostics or hidden materialization bounds.
  const direct = [...new Set([...(sourceProof ? [sourceProof.afterEndpoint.assetId] : []), ...request.assetChanges.map(row => row.assetId), ...(changeSet?.relationTargets.flatMap(row => row.plan.creations.flatMap(item => [item.sourceAssetId, item.targetAssetId])) ?? [])])];
  if (direct.length) {
    const absent = await relationQuery(tx, () => sql`select 1 from unnest(${direct}::uuid[]) x(id) LEFT JOIN assets a
      ON a.tenant_id=${p.tenantId}::uuid AND a.id=x.id AND (a.visibility='tenant' OR a.allowed_identities @> ${JSON.stringify([p.id])}::jsonb) WHERE a.id IS NULL LIMIT 1`.execute(tx));
    if (absent.rows.length) throw unavailable();
  }
  for (const target of request.assetTypeMigrations) await relationQuery(tx, () => models.authorizeModelCohort(tx, p, target.definition.id));
  await authorizeRelationRepairReference(tx, p, request.repairsReceiptId);
  const preparations: RelationMigrationContext['preparations'][number][] = [];
  for (const target of request.relationTargets) {
    if (target.kind === 'create') {
      const { preparation } = await getRelationPreparation(tx, p, target.reservationId);
      const available = await relationQuery(tx, () => tx.selectFrom('relation_type_preparations').select(['consumed_operation_id', sql<boolean>`expires_at>clock_timestamp()`.as('unexpired')])
        .where('tenant_id', '=', p.tenantId).where('created_by', '=', p.id).where('id', '=', preparation.id).executeTakeFirstOrThrow());
      if (available.consumed_operation_id || preparation.relationTypeId !== target.relationTypeId || preparation.definitionHash !== typeHash(target.definition))
        throw new Problem(409, 'RELATION_PREPARATION_CONFLICT', 'The preparation conflicts with its reserved definition or consumption.');
      if (!available.unexpired) throw new Problem(410, 'RELATION_PREPARATION_EXPIRED', 'Create a new preparation and run a fresh preview.');
      preparations.push(preparation);
    } else {
      const head = await relationQuery(tx, () => tx.selectFrom('relation_types').select(['id', 'current_version'])
        .where('tenant_id', '=', p.tenantId).where('type_id', '=', target.relationTypeId).executeTakeFirst());
      if (!head) throw unavailable(); if (head.current_version !== target.expectedHeadVersion) throw graphStale();
      if (target.definition && target.definition.id !== head.id) throw graphStale();
    }
    if (target.definition) await endpointTypeIdentities(tx, p, relationDefinition(target.definition));
  }
  const cte = scopeCTE(p, request, changeSet, sourceProof), member = JSON.stringify([p.id]);
  const hidden = await relationQuery(tx, () => sql`${cte} SELECT 1 FROM assets a JOIN all_assets s ON s.id=a.id
    WHERE a.tenant_id=${p.tenantId}::uuid AND NOT(a.visibility='tenant' OR a.allowed_identities @> ${member}::jsonb)
    UNION ALL SELECT 1 FROM relations r JOIN all_edges scope ON scope.id=r.id WHERE r.tenant_id=${p.tenantId}::uuid AND NOT(r.visibility='tenant' OR r.allowed_identities @> ${member}::jsonb) LIMIT 1`.execute(tx));
  if (hidden.rows.length) throw hiddenScope();
  const size = await relationQuery(tx, () => sql<{ assets: string; changes: string; edges: string; bindings: string; bytes: string }>`
    ${cte} SELECT (SELECT count(*) FROM all_assets)::text AS assets,(SELECT count(*) FROM changed_assets)::text AS changes,
      (SELECT count(*) FROM all_edges)::text AS edges,(SELECT count(*) FROM all_bindings)::text AS bindings,
      (coalesce((SELECT sum(octet_length(to_jsonb(a)::text)+coalesce(octet_length(h.snapshot::text),0)) FROM assets a JOIN all_assets s ON s.id=a.id
        LEFT JOIN asset_revisions h ON h.tenant_id=a.tenant_id AND h.asset_id=a.id AND h.version=a.version WHERE a.tenant_id=${p.tenantId}::uuid),0)
      +coalesce((SELECT sum(octet_length(to_jsonb(r)::text)+coalesce(octet_length(h.snapshot::text),0)) FROM relations r JOIN all_edges s ON s.id=r.id
        LEFT JOIN relation_revisions h ON h.tenant_id=r.tenant_id AND h.relation_id=r.id AND h.version=r.version WHERE r.tenant_id=${p.tenantId}::uuid),0)
      +coalesce((SELECT sum(octet_length(to_jsonb(b)::text)+coalesce(octet_length(h.snapshot::text),0)) FROM relation_participations b JOIN all_bindings s ON s.id=b.id
        LEFT JOIN relation_participation_revisions h ON h.tenant_id=b.tenant_id AND h.binding_id=b.id AND h.version=b.version WHERE b.tenant_id=${p.tenantId}::uuid),0)
      +coalesce((SELECT sum(coalesce(octet_length(before_definition::text),0)+octet_length(after_definition::text)) FROM all_types),0))::text AS bytes`.execute(tx));
  const counts = size.rows[0];
  if (Number(counts.assets) > 2000 || Number(counts.changes) > 1000 || Number(counts.edges) > 1000 || Number(counts.bindings) > 4000 || Number(counts.bytes) + Buffer.byteLength(JSON.stringify(sourceProof ? { request: changeSet ?? request, sourceProof } : changeSet ?? request)) > 524288) throw profileLimit();
  const ids = (await relationQuery(tx, () => sql<{ id: string }>`${cte} SELECT id FROM all_assets ORDER BY id`.execute(tx))).rows.map(row => row.id);
  const types = (await relationQuery(tx, () => sql<{ type_id: string; current_version: number | null }>`${cte} SELECT type_id,current_version FROM all_types ORDER BY type_id`.execute(tx))).rows;
  const typeIds = types.map(row => row.type_id);
  // Every canonical row lock is acquired before the single global principal phase.
  const modelIds = [...new Set([...request.assetTypeMigrations.map(row => row.definition.id), ...request.assetChanges.flatMap(row => row.kind === 'assign' ? [row.modelId] : [])])];
  await relationQuery(tx, () => sql`SELECT m.id FROM governance_models m WHERE m.tenant_id=${p.tenantId}::uuid
    AND (m.id=ANY(${modelIds}::text[]) OR m.id IN(SELECT a.model_id FROM assets a WHERE a.tenant_id=m.tenant_id AND a.id=ANY(${ids}::uuid[]))) ORDER BY m.id COLLATE "C" FOR UPDATE`.execute(tx));
  if (typeIds.length) await relationQuery(tx, () => tx.selectFrom('relation_types').select('type_id').where('tenant_id', '=', p.tenantId).where('type_id', 'in', typeIds).orderBy('id').forUpdate().execute());
  const assets: Row[] = ids.length ? await relationQuery(tx, () => tx.selectFrom('assets').selectAll().where('tenant_id', '=', p.tenantId).where('id', 'in', ids).orderBy('id').forUpdate().execute()) : [];
  const edges: Row[] = typeIds.length ? await relationQuery(tx, () => tx.selectFrom('relations').selectAll().where('tenant_id', '=', p.tenantId).where('relation_type_id', 'in', typeIds).where('status', '=', 'active').orderBy('id').forUpdate().execute()) : [];
  const bindings: Row[] = typeIds.length ? await relationQuery(tx, () => tx.selectFrom('relation_participations').selectAll().where('tenant_id', '=', p.tenantId).where('relation_type_id', 'in', typeIds).where('status', '=', 'active').orderBy('id').forUpdate().execute()) : [];
  const activity = await lockRelationPrincipals(tx, p, [...referencedPrincipals(request, changeSet), ...assets.flatMap(row => [row.owner_id, ...row.allowed_identities]), ...edges.flatMap(row => [row.owner_id, ...row.allowed_identities])], GRAPH_WRITE);
  const byAsset = new Map(assets.map(row => [row.id, row])), policyMap = new Map<string, RelationPolicySnapshot>();
  for (const pin of [...types.filter(row => row.current_version !== null).map(row => ({ type: row.type_id, version: row.current_version! })), ...[...edges, ...bindings].map(row => ({ type: row.relation_type_id, version: row.relation_type_version }))]) {
    const key = policyKey(pin.type, pin.version); if (policyMap.has(key)) continue;
    const resolved = storedRelationType(await relationTypeVersion(tx, p, pin.type, pin.version));
    policyMap.set(key, { relationTypeId: pin.type, ...resolved });
    await graphPhysicalBudget(tx, [...policyMap.values()]);
  }
  const targets: RelationTargetEvidence[] = [];
  for (const target of request.relationTargets) {
    const before = target.expectedHeadVersion === null ? null : policyMap.get(policyKey(target.relationTypeId, target.expectedHeadVersion))!;
    const after = target.definition ? { relationTypeId: target.relationTypeId, ...relationDefinition(target.definition) } : before!;
    policyMap.set(policyKey(after.relationTypeId, after.definition.version), after);
    const differences = before && target.kind === 'publish' ? previewModelUpgrade(before.model, after.model, []) : null;
    if (differences && !differences.ok) throw graphStorage();
    targets.push({ relationTypeId: target.relationTypeId, mode: target.kind, beforeVersion: before?.definition.version ?? null, afterVersion: after.definition.version,
      definitionHash: typeHash(after.definition), resolutionHash: typeHash({ definition: after.definition, model: after.model }),
      beforeStructuralFingerprint: before ? typeHash(structuralProjection(before.definition)) : null, afterStructuralFingerprint: typeHash(structuralProjection(after.definition)),
      policyChanges: before && target.kind === 'publish' ? relationPolicyChanges(before.definition, after.definition) : [], attributeChanges: differences?.ok ? differences.value.changes : [] });
  }
  const endpoints: RelationEndpointPolicyState[] = [];
  for (const asset of assets) { endpoints.push(await endpointState(tx, p, asset)); await graphPhysicalBudget(tx, endpoints); }
  // A graph transition preserves attributes; it cannot quietly carry a corrupt
  // source tuple into a ready preview that the protected SQL will later reject.
  for (const change of request.assetChanges) if (change.kind === 'transition') {
    const endpoint = endpoints.find(row => row.assetId === change.assetId), asset = byAsset.get(change.assetId)!;
    if (endpoint?.policy && !validateAttributes(endpoint.policy.model, asset.attributes).ok) throw graphStorage();
  }
  const before = { heads: types.filter(row => row.current_version !== null).map(row => ({ relationTypeId: row.type_id, version: row.current_version! })),
    endpoints, edges: edges.map(row => edgeSnapshot(row, byAsset)), bindings: bindings.map(row => bindingSnapshot(row, byAsset)) };
  const policies = [...policyMap.values()].sort((a, b) => a.relationTypeId.localeCompare(b.relationTypeId) || a.definition.version - b.definition.version);
  const sourceGraph = sourceProof ? validateGlossaryGraphSource({ before, policies, sourceProof }) : validateFinalRelationGraphConstraints({ graph: before, policies });
  if (!sourceGraph.ok) { if (sourceGraph.issues.some(row => row.code === 'limit')) throw profileLimit(); throw graphStorage(); }
  // A repair may fix a real inactive required owner. Corrupt source values,
  // fabricated provenance or missing immutable history are not repair consent.
  for (const edge of edges) {
    const policy = policyMap.get(policyKey(edge.relation_type_id, edge.relation_type_version))!;
    if (!validateAttributes(policy.model, edge.attributes).ok || !policy.definition.lifecycle.states.includes(edge.state) ||
        policy.definition.requiredOwner && edge.owner_id === null || edge.owner_id !== null && !activity.members.has(edge.owner_id) ||
        edge.allowed_identities.some((id: string) => !activity.members.has(id))) throw graphStorage();
    const provenance = { origin: 'asserted', source: { kind: 'manual', identityId: edge.created_by }, authority: 'manual-assertion', precedence: null,
      actorId: edge.created_by, assertedAt: iso(edge.created_at), ingestedAt: iso(edge.created_at), sourceObservedAt: null, sourceVersion: null, sourceRunId: null, confidence: null };
    if (typeHash(edge.provenance) !== typeHash(provenance)) throw graphStorage();
  }
  if (edges.length || bindings.length) {
    try {
      const corrupt = await relationQuery(tx, () => sql`SELECT 1 FROM relations r
        LEFT JOIN relation_revisions h ON h.tenant_id=r.tenant_id AND h.relation_id=r.id AND h.version=r.version
        WHERE r.tenant_id=${p.tenantId}::uuid AND r.id=ANY(${edges.map(row => row.id)}::uuid[]) AND
          (h.relation_id IS NULL OR h.recorded_by<>r.updated_by OR h.recorded_at<>r.updated_at
            OR jsonb_typeof(h.snapshot#>'{source,state}') IS DISTINCT FROM 'string'
            OR jsonb_typeof(h.snapshot#>'{target,state}') IS DISTINCT FROM 'string' OR h.snapshot IS DISTINCT FROM
            (public.gc_relation_snapshot_base(r)||jsonb_build_object(
              'source',public.gc_relation_endpoint_snapshot(r.tenant_id,r.source_asset_id,(h.snapshot#>>'{source,assetVersion}')::integer),
              'target',public.gc_relation_endpoint_snapshot(r.tenant_id,r.target_asset_id,(h.snapshot#>>'{target,assetVersion}')::integer))))
        UNION ALL SELECT 1 FROM relation_participations b
        LEFT JOIN relation_participation_revisions h ON h.tenant_id=b.tenant_id AND h.binding_id=b.id AND h.version=b.version
        WHERE b.tenant_id=${p.tenantId}::uuid AND b.id=ANY(${bindings.map(row => row.id)}::uuid[]) AND
          (h.binding_id IS NULL OR h.recorded_by<>b.updated_by OR h.recorded_at<>b.updated_at OR h.snapshot IS DISTINCT FROM public.gc_relation_binding_snapshot(b))
        LIMIT 1`.execute(tx));
      if (corrupt.rows.length) throw graphStorage();
    } catch (error) {
      if (error && typeof error === 'object' && 'code' in error && ['23514', '22P02', '22003', '22007', '22008'].includes(String(error.code))) throw graphStorage();
      throw error;
    }
  }
  // Validate exact immutable before history, including full governed asset tuples,
  // before a preview can become consent for their next revisions.
  for (const asset of assets) {
    const history = await relationQuery(tx, () => tx.selectFrom('asset_revisions').select('snapshot').where('tenant_id', '=', p.tenantId).where('asset_id', '=', asset.id).where('version', '=', asset.version).executeTakeFirst());
    const snapshot = history?.snapshot;
    if (!snapshot || snapshot.id !== asset.id || snapshot.version !== asset.version || typeHash({ modelId: snapshot.modelId ?? null, modelVersion: snapshot.modelVersion ?? null,
      attributes: snapshot.attributes, ownerId: snapshot.ownerId ?? null, state: snapshot.typeState ?? null }) !== typeHash({ modelId: asset.model_id, modelVersion: asset.model_version,
      attributes: asset.attributes, ownerId: asset.owner_id, state: asset.type_state })) throw graphStorage();
  }
  const evidence = new Map<string, GraphAssetPolicyEvidence>(), discovered = [], targetIssues: ValidationIssue[] = [];
  const addPolicy = (policy: GraphAssetPolicyEvidence) => { const model = policy.kind === 'authored' ? policy.resolution.model : policy.model; evidence.set(`${model.id}:${model.version}`, policy); };
  const changedIds = new Set(request.assetChanges.map(row => row.assetId)), migratedModels = new Set(request.assetTypeMigrations.map(row => row.definition.id));
  const changedAssets = assets.filter(row => changedIds.has(row.id) || migratedModels.has(row.model_id));
  const isChanged = new Set(changedAssets.map(row => row.id));
  for (const endpoint of endpoints) if (isChanged.has(endpoint.assetId) && endpoint.policy && endpoint.typeId) addPolicy({ kind: 'authored', typeId: endpoint.typeId, resolution: endpoint.policy,
    definitionHash: typeHash(endpoint.policy.definition), resolutionHash: typeHash(endpoint.policy), ancestorTypes: endpoint.ancestorTypes });
  const refs = [...changedAssets.filter(row => row.model_id).map(row => ({ modelId: row.model_id, modelVersion: row.model_version })), ...request.assetChanges.flatMap(row => row.kind === 'assign' ? [{ modelId: row.modelId, modelVersion: row.modelVersion }] : [])];
  for (const ref of refs) if (!evidence.has(`${ref.modelId}:${ref.modelVersion}`)) {
    const endpoint = await endpointState(tx, p, { id: '00000000-0000-0000-0000-000000000000', version: 1, model_id: ref.modelId, model_version: ref.modelVersion, type_state: null });
    if (endpoint.policy && endpoint.typeId) addPolicy({ kind: 'authored', typeId: endpoint.typeId, resolution: endpoint.policy,
      definitionHash: typeHash(endpoint.policy.definition), resolutionHash: typeHash(endpoint.policy), ancestorTypes: endpoint.ancestorTypes });
    else {
      const row = await relationQuery(tx, () => models.versionRow(tx, p, ref.modelId, ref.modelVersion));
      const model = models.storedDefinition(row); addPolicy({ kind: 'attributes', model, definitionHash: typeHash(model) });
    }
    await graphPhysicalBudget(tx, [...evidence.values()]);
  }
  for (const target of request.assetTypeMigrations) {
    try {
      const result = await relationQuery(tx, () => discoverTypeMigration(tx, p, target.definition.id, target.expectedHeadVersion, target));
      discovered.push(result.discovery); for (const policy of result.policies) addPolicy(policy);
      await graphPhysicalBudget(tx, { discovered, policies: [...evidence.values()] });
    } catch (error) {
      if (!(error instanceof Problem) || error.code !== 'ASSET_TYPE_MIGRATION_INVALID') throw error;
      targetIssues.push(...((error as Problem & { issues?: ValidationIssue[] }).issues ?? [{ code: 'invalid_definition' as const, path: '/assetTypeMigrations', message: 'Correct the complete authored type migration plan.' }]));
    }
  }
  const heads = await relationQuery(tx, () => tx.selectFrom('governance_models').select(['id', 'current_version']).where('tenant_id', '=', p.tenantId)
    .where('id', 'in', [...new Set([...refs.map(row => row.modelId), ...request.assetTypeMigrations.map(row => row.definition.id)])].concat(['__empty_graph_scope__'])).execute());
  const tuples: GraphAssetBefore[] = changedAssets.map(row => ({ assetId: row.id, assetVersion: row.version,
    tuple: { modelId: row.model_id, modelVersion: row.model_version, attributes: row.attributes, ownerId: row.owner_id, state: row.type_state },
    policy: row.model_id ? { modelId: row.model_id, modelVersion: row.model_version } : null }));
  const projected = targetIssues.length ? null : projectGraphAssetChanges({ assetChanges: request.assetChanges, typeMigrations: discovered,
    before: tuples, policies: [...evidence.values()], modelHeads: heads.map(row => ({ modelId: row.id, version: row.current_version })), activeOwnerIds: activity.active });
  if (projected && !projected.ok) targetIssues.push(...projected.issues);
  if (targetIssues.length > 100) throw profileLimit();
  const assetPreparation = projected?.ok ? projected.value : null;
  const proposedEndpoints = assetPreparation ? endpoints.map(endpoint => {
    const change = assetPreparation.changes.find(row => row.assetId === endpoint.assetId); if (!change) return endpoint;
    const policy = change.targetPolicy ? evidence.get(`${change.targetPolicy.modelId}:${change.targetPolicy.modelVersion}`) : null;
    return { assetId: endpoint.assetId, assetVersion: change.toAssetVersion, modelId: change.after.modelId, modelVersion: change.after.modelVersion,
      state: change.after.state, typeId: policy?.kind === 'authored' ? policy.typeId : null, policy: policy?.kind === 'authored' ? policy.resolution : null,
      ancestorTypes: policy?.kind === 'authored' ? policy.ancestorTypes : [] };
  }) : null;
  const sourceIssues: RelationMigrationContext['sourceIssues'][number][] = assetPreparation?.changes.flatMap(row => row.sourceIssues.map(issue => ({ kind: 'asset' as const, assetId: row.assetId, issue }))) ?? [];
  for (const edge of edges) if (policyMap.get(policyKey(edge.relation_type_id, edge.relation_type_version))!.definition.requiredOwner && edge.owner_id && activity.members.has(edge.owner_id) && !activity.active.has(edge.owner_id))
    sourceIssues.push({ kind: 'relation', issue: { code: 'source_required_owner_inactive', relationId: edge.id, ownerId: edge.owner_id } });
  const context: RelationMigrationContext = { coverage: 'complete-authorized-affected-graph', request, assetIdentities: assets.map(row => ({ assetId: row.id, name: row.name })),
    preparations, completeRelationTypeIds: typeIds, policies, before, assetPreparation, proposedEndpoints, targets, sourceIssues, targetIssues };
  if (request.repairsReceiptId) {
    const prior = await relationQuery(tx, () => sql`SELECT 1 FROM relation_graph_receipt_types WHERE tenant_id=${p.tenantId}::uuid AND operation_id=${request.repairsReceiptId}::uuid AND relation_type_id=ANY(${request.relationTargets.map(row => row.relationTypeId)}::uuid[])
      UNION ALL SELECT 1 FROM relation_graph_receipt_assets WHERE tenant_id=${p.tenantId}::uuid AND operation_id=${request.repairsReceiptId}::uuid AND asset_id=ANY(${request.assetChanges.map(row => row.assetId)}::uuid[])
      UNION ALL SELECT 1 FROM relation_graph_receipt_type_migrations linked JOIN asset_type_migrations migration ON migration.tenant_id=linked.tenant_id AND migration.id=linked.migration_id
        WHERE linked.tenant_id=${p.tenantId}::uuid AND linked.operation_id=${request.repairsReceiptId}::uuid AND migration.model_id=ANY(${request.assetTypeMigrations.map(row => row.definition.id)}::text[]) LIMIT 1`.execute(tx));
    if (!prior.rows.length) throw new Problem(422, 'RELATION_REPAIR_UNRELATED', 'Forward repair must explicitly target part of the original operation.');
  }
  await graphPhysicalBudget(tx, context);
  return { context, assets, edges, bindings, activity };
}

/** Ordinary graph API: invalid current source graphs remain inadmissible. */
export async function captureRelationMigration(tx: Tx, p: Principal, request: RelationMigrationContextRequest, changeSet?: GraphChangeSet) {
  return captureMigration(tx, p, request, changeSet);
}

/** Internal publication capture. There is no caller-supplied source proof; the
 * fixed SQL016 helper binds the same transaction, actor and publication. */
export async function captureGlossaryRelationMigration(tx: Tx, p: Principal, publicationId: string, request: RelationMigrationContextRequest, changeSet?: GraphChangeSet) {
  await lockRelationScope(tx, p, GRAPH_WRITE);
  const row = (await relationQuery(tx, () => sql<{ value: unknown }>`SELECT public.gc_glossary_graph_source_evidence(${publicationId}::uuid) AS value`.execute(tx))).rows[0];
  const parsed = parseGlossaryGraphSourceProof(row?.value);
  if (!parsed.ok) { if (parsed.issues.some(issue => issue.code === 'limit')) throw profileLimit(); throw graphStorage(); }
  const sourceProof = parsed.value;
  if (sourceProof.publicationId !== publicationId || sourceProof.tenantId !== p.tenantId || sourceProof.actorId !== p.id ||
      request.assetChanges.length || request.assetTypeMigrations.length || request.repairsReceiptId !== null ||
      request.relationTargets.some(target => target.kind !== 'repair' || !sourceProof.relationTypeIds.includes(target.relationTypeId))) throw graphStorage();
  const captured = await captureMigration(tx, p, request, changeSet, sourceProof);
  await graphPhysicalBudget(tx, { context: captured.context, sourceProof });
  return { ...captured, sourceProof };
}
