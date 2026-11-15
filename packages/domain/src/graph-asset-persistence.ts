// SPDX-License-Identifier: Apache-2.0
import type { Tx } from '../../db/src/index.ts';
import { Problem, type Principal } from '../../authz/src/index.ts';
import { MODEL_SERVICE_LIMITS, modelPersistence as models, type ModelHooks } from './model-service.ts';
import { assetTypePersistence as types } from './asset-type-service.ts';
import type { GraphAssetTuple, GraphOperationHandle, PreparedGraphAssetChange } from './relation-migration-contracts.ts';

type Row = Record<string, any>;
const invalid = () => new Problem(500, 'RELATION_GRAPH_PREPARATION_INVALID', 'The prepared asset operation could not be verified.');
const stale = () => new Problem(409, 'RELATION_PREVIEW_STALE', 'The graph or asset scope changed. Run a fresh preview.');
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function currentTuple(row: Row): GraphAssetTuple {
  return { modelId: row.model_id ?? null, modelVersion: row.model_version ?? null,
    attributes: row.attributes ?? {}, ownerId: row.owner_id ?? null, state: row.type_state ?? null };
}
function recordedTuple(snapshot: Row): GraphAssetTuple {
  // Missing nullable fields represent null, matching SQL's JSON extraction.
  // Attributes must exist exactly; no historical row is synthesized by this read.
  return { modelId: snapshot.modelId ?? null, modelVersion: snapshot.modelVersion ?? null,
    attributes: snapshot.attributes, ownerId: snapshot.ownerId ?? null, state: snapshot.typeState ?? null };
}

/** Internal graph-only adapter. The parent has already authorized and locked the
 * complete graph and principal unions, captured/projected every change, validated
 * the final graph and begun its protected SQL operation. This function neither
 * establishes those facts nor authorizes a caller using a handle or tuple.
 * SQL009 independently enforces the actual transaction's protected claims.
 *
 * Recapture uses no new row/principal locks. Shared standalone writers preserve
 * every unrelated column and journal the actual returned canonical row. The
 * parent alone owns the deadline, idempotency success and final constraints. */
export async function persistPreparedGraphAssetChange(tx: Tx, principal: Principal, correlationId: string,
  operation: GraphOperationHandle, change: PreparedGraphAssetChange, hooks: ModelHooks): Promise<void> {
  // Shape checks catch incorrect internal composition; they are not credentials.
  if (!operation || typeof operation.id !== 'string' || !uuid.test(operation.id) ||
      !change || !['assign', 'transition'].includes(change.kind) ||
      !Number.isInteger(change.fromAssetVersion) || change.fromAssetVersion < 1 ||
      change.fromAssetVersion >= MODEL_SERVICE_LIMITS.databaseVersion ||
      change.toAssetVersion !== change.fromAssetVersion + 1 || change.sourceIssues.length !== 0) throw invalid();

  const asset = await models.assetRow(tx, principal, change.assetId);
  if (asset.version !== change.fromAssetVersion || models.hash(currentTuple(asset)) !== models.hash(change.before)) throw stale();
  const revision = await tx.selectFrom('asset_revisions').select(['version', 'snapshot'])
    .where('tenant_id', '=', principal.tenantId).where('asset_id', '=', change.assetId)
    .where('version', '=', change.fromAssetVersion).executeTakeFirst();
  if (!revision || !revision.snapshot || typeof revision.snapshot !== 'object' || Array.isArray(revision.snapshot) ||
      revision.snapshot.id !== change.assetId || revision.snapshot.version !== change.fromAssetVersion ||
      !revision.snapshot.attributes || typeof revision.snapshot.attributes !== 'object' || Array.isArray(revision.snapshot.attributes) ||
      models.hash(recordedTuple(revision.snapshot)) !== models.hash(change.before)) throw invalid();

  // These adapters can never become a separate owner/attribute repair route.
  // Full policy and transition validation already ran in asset preparation.
  if (change.after.ownerId !== change.before.ownerId) throw invalid();
  let updated: Row;
  if (change.kind === 'assign') {
    if (change.after.modelId === null || change.after.modelVersion === null) throw invalid();
    updated = await models.persistAssignment(tx, principal, correlationId, asset,
      { modelId: change.after.modelId, modelVersion: change.after.modelVersion,
        attributes: change.after.attributes, state: change.after.state }, hooks);
  } else {
    if (change.after.state === null || change.after.modelId !== change.before.modelId ||
        change.after.modelVersion !== change.before.modelVersion ||
        models.hash(change.after.attributes) !== models.hash(change.before.attributes)) throw invalid();
    updated = await types.persistTransition(tx, principal, correlationId, asset, change.after.state, hooks);
  }
  if (updated.version !== change.toAssetVersion || models.hash(currentTuple(updated)) !== models.hash(change.after)) throw invalid();
}
