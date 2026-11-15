// SPDX-License-Identifier: Apache-2.0
import { createHash } from 'node:crypto';
import { lockTenantLedger, sql, type Tx } from '../../db/src/index.ts';
import { canView, Problem, requirePermission, type Principal } from '../../authz/src/index.ts';
import { signedCursor } from './cursor.ts';
import { assetTypePolicy, validateTypeOwner } from './asset-type-policy.ts';
import {
  MODEL_LIMITS, parseModelDefinition, previewModelUpgrade, validateAttributes,
  type AttributeValues, type ModelAssetPreview, type ModelChange, type ModelDefinition,
} from './model.ts';

export const MODEL_SERVICE_LIMITS = Object.freeze({ models: 100, previewBytes: 524_288, databaseVersion: 2_147_483_647 });
export interface ModelHooks {
  record: (tx: Tx, principal: Principal, action: string, resourceId: string, version: number, changes: unknown, correlationId: string) => Promise<unknown>;
  assetSnapshot: (row: any) => unknown;
}
export interface ModelSummary { id: string; currentVersion: number; createdAt: string; createdBy: string; typeId: string | null }
export interface ModelListQuery { limit?: number; cursor?: string; q?: string }
export interface ModelListPage { items: ModelSummary[]; nextCursor: string | null }
export interface ModelVersionView {
  id: string; version: number; currentVersion: number; definition: ModelDefinition;
  definitionHash: string; createdAt: string; createdBy: string;
  typeId: string | null;
}
export interface AssetModelView {
  assetId: string; assetVersion: number; modelId: string | null; modelVersion: number | null;
  attributes: AttributeValues; definition: ModelDefinition | null;
}
export interface AssetModelInput { modelId: string; modelVersion: number; attributes: unknown }
export interface ModelPreview {
  modelId: string; currentVersion: number; proposedVersion: number;
  coverage: 'complete-tenant-model-bindings'; assetCount: number;
  changes: readonly ModelChange[]; assets: readonly ModelAssetPreview[]; affectedAssetIds: readonly string[];
  compatibleWithProvidedAssets: boolean; requiresExplicitMigration: boolean; pinsPreserved: true; previewDigest: string;
}

type Row = Record<string, any>;
const modelIdPattern = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const reservedIds = new Set(['__proto__', 'prototype', 'constructor']);
const iso = (value: string | Date): string => new Date(value).toISOString();
function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stable((value as Row)[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
const hash = (value: unknown): string => createHash('sha256').update(stable(value)).digest('hex');
function checkId(id: string): void {
  if (typeof id !== 'string' || !modelIdPattern.test(id) || reservedIds.has(id)) throw new Problem(400, 'MODEL_ID_INVALID', 'Provide a valid model identifier.');
}
function checkVersion(version: number, code = 'VERSION_REQUIRED'): void {
  if (!Number.isInteger(version) || version < 1 || version > MODEL_SERVICE_LIMITS.databaseVersion) throw new Problem(428, code, 'Provide the current positive integer version.');
}
function definition(input: unknown): ModelDefinition {
  const parsed = parseModelDefinition(input);
  if (!parsed.ok) throw new Problem(422, 'MODEL_INVALID', 'Correct the model definition before continuing.', parsed.issues);
  return parsed.value;
}
function storedDefinition(row: Row): ModelDefinition {
  const parsed = parseModelDefinition(row.definition);
  if (!parsed.ok || parsed.value.id !== row.model_id || parsed.value.version !== row.version || hash(parsed.value) !== row.definition_hash) {
    throw new Problem(500, 'MODEL_STORAGE_INVALID', 'The stored model could not be verified.');
  }
  return parsed.value;
}
function view(row: Row, currentVersion: number, typeId: string | null = null): ModelVersionView {
  return { id: row.model_id, version: row.version, currentVersion, definition: storedDefinition(row),
    definitionHash: row.definition_hash, createdAt: iso(row.created_at), createdBy: row.created_by, typeId };
}

/** Services recheck the active membership so non-HTTP callers cannot rely on a stale role snapshot. */
async function authorize(tx: Tx, principal: Principal, actions: readonly string[]): Promise<void> {
  for (const action of actions) requirePermission(principal, action);
  const membership = await tx.selectFrom('memberships').innerJoin('identities', 'identities.id', 'memberships.identity_id')
    .select('memberships.permissions').where('memberships.tenant_id', '=', principal.tenantId)
    .where('memberships.identity_id', '=', principal.id).where('memberships.active', '=', true)
    .where('identities.active', '=', true).executeTakeFirst();
  if (!membership || !Array.isArray(membership.permissions) || actions.some(action => !membership.permissions.includes(action))) {
    throw new Problem(403, 'FORBIDDEN', 'Your current permissions do not allow this action.');
  }
}

/** Shared lock order: tenant ledger, tenant models, canonical rows. */
async function lockTenantModels(tx: Tx, principal: Principal): Promise<void> {
  await lockTenantLedger(tx, principal.tenantId);
  await sql`select pg_advisory_xact_lock(hashtextextended(${`governance-models:${principal.tenantId}`},0))`.execute(tx);
}
async function head(tx: Tx, principal: Principal, id: string, lock = false): Promise<Row> {
  checkId(id);
  let query = tx.selectFrom('governance_models').selectAll().where('tenant_id', '=', principal.tenantId).where('id', '=', id);
  if (lock) query = query.forUpdate();
  const row = await query.executeTakeFirst();
  if (!row) throw new Problem(404, 'MODEL_NOT_FOUND', 'Model is unavailable.');
  return row;
}
async function versionRow(tx: Tx, principal: Principal, id: string, version: number): Promise<Row> {
  checkVersion(version, 'MODEL_VERSION_INVALID');
  const row = await tx.selectFrom('governance_model_versions').selectAll().where('tenant_id', '=', principal.tenantId)
    .where('model_id', '=', id).where('version', '=', version).executeTakeFirst();
  if (!row) throw new Problem(404, 'MODEL_NOT_FOUND', 'Model version is unavailable.');
  return row;
}
function assertHead(current: Row, expected: number): void {
  checkVersion(expected);
  if (current.current_version !== expected) throw new Problem(409, 'VERSION_CONFLICT', 'The model changed. Load its current version and preview again.');
}
function assertVisible(principal: Principal, asset: Row): void {
  if (!canView(principal, { tenantId: asset.tenant_id, visibility: asset.visibility, allowedIdentities: asset.allowed_identities })) {
    throw new Problem(404, 'ASSET_NOT_FOUND', 'Asset is unavailable.');
  }
}
async function assetRow(tx: Tx, principal: Principal, assetId: string, lock = false): Promise<Row> {
  let query = tx.selectFrom('assets').selectAll().where('tenant_id', '=', principal.tenantId).where('id', '=', assetId);
  if (lock) query = query.forUpdate();
  const row = await query.executeTakeFirst();
  if (!row) throw new Problem(404, 'ASSET_NOT_FOUND', 'Asset is unavailable.');
  assertVisible(principal, row);
  return row;
}

export async function listModels(tx: Tx, principal: Principal, query: ModelListQuery = {}): Promise<ModelListPage> {
  await authorize(tx, principal, ['models:read']);
  const invalid = () => new Problem(400, 'MODEL_PAGE_INVALID', 'Provide a valid model search and page cursor.');
  if (!query || typeof query !== 'object' || Array.isArray(query) || Object.keys(query).some(key => !['limit', 'cursor', 'q'].includes(key))) throw invalid();
  const pageSize = query.limit ?? 50, search = query.q ?? '';
  if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > MODEL_SERVICE_LIMITS.models ||
      typeof search !== 'string' || search.length > 64 || /[\u0000-\u001f\u007f]/.test(search)) throw invalid();
  const codec = signedCursor(process.env.SESSION_KEY, 'model-inventory-v2');
  let after: string | undefined;
  if (query.cursor !== undefined) {
    try {
      const cursor = codec.decode(query.cursor) as Row;
      if (!cursor || typeof cursor !== 'object' || Object.keys(cursor).sort().join('|') !== 'actorId|after|limit|q|sort|tenantId|v' ||
          cursor.v !== 2 || cursor.tenantId !== principal.tenantId || cursor.actorId !== principal.id ||
          cursor.q !== search || cursor.sort !== 'id:asc' || cursor.limit !== pageSize ||
          typeof cursor.after !== 'string' || !modelIdPattern.test(cursor.after) || reservedIds.has(cursor.after)) throw invalid();
      after = cursor.after;
    } catch { throw invalid(); }
  }
  let selection = tx.selectFrom('governance_models').selectAll().where('tenant_id', '=', principal.tenantId);
  if (search) selection = selection.where('id', 'ilike', `%${search.replace(/[\\%_]/g, '\\$&')}%`);
  if (after) selection = selection.where('id', '>', after);
  const rows = await selection.orderBy('id').limit(pageSize + 1).execute();
  const page = rows.slice(0, pageSize);
  return { items: page.map(row => ({ id: row.id, currentVersion: row.current_version, createdAt: iso(row.created_at), createdBy: row.created_by, typeId: row.type_id ?? null })),
    nextCursor: rows.length > pageSize ? codec.encode({ v: 2, tenantId: principal.tenantId, actorId: principal.id,
      q: search, sort: 'id:asc', limit: pageSize, after: page.at(-1)!.id }) : null };
}

export async function getModel(tx: Tx, principal: Principal, id: string, version?: number): Promise<{ model: ModelVersionView }> {
  await authorize(tx, principal, ['models:read']);
  const current = await head(tx, principal, id);
  return { model: view(await versionRow(tx, principal, id, version ?? current.current_version), current.current_version, current.type_id) };
}

export async function createModel(tx: Tx, principal: Principal, correlationId: string, input: unknown, hooks: ModelHooks): Promise<{ model: ModelVersionView }> {
  await authorize(tx, principal, ['models:read', 'models:write']);
  const parsed = definition(input);
  if (parsed.version !== 1) throw new Problem(422, 'MODEL_INITIAL_VERSION', 'A new model must begin at version 1.');
  await lockTenantModels(tx, principal);
  await authorize(tx, principal, ['models:read', 'models:write']);
  const existing = await tx.selectFrom('governance_models').select('id').where('tenant_id', '=', principal.tenantId).where('id', '=', parsed.id).executeTakeFirst();
  if (existing) throw new Problem(409, 'MODEL_EXISTS', 'A model with this identifier already exists.');
  await tx.insertInto('governance_models').values({ tenant_id: principal.tenantId, id: parsed.id, current_version: 1, created_by: principal.id }).execute();
  const row = await tx.insertInto('governance_model_versions').values({ tenant_id: principal.tenantId, model_id: parsed.id,
    version: 1, definition: JSON.stringify(parsed), definition_hash: hash(parsed), created_by: principal.id }).returningAll().executeTakeFirstOrThrow();
  await hooks.record(tx, principal, 'model.created', parsed.id, 1, { definitionHash: row.definition_hash }, correlationId);
  return { model: view(row, 1) };
}

async function modelCohort(tx: Tx, principal: Principal, modelId: string): Promise<Row[]> {
  // Never expose even a count when complete validation requires inaccessible assets.
  const hidden = await tx.selectFrom('assets').select('id').where('tenant_id', '=', principal.tenantId).where('model_id', '=', modelId)
    .where(sql<boolean>`NOT (visibility = 'tenant' OR allowed_identities @> ${JSON.stringify([principal.id])}::jsonb)`).limit(1).executeTakeFirst();
  if (hidden) throw new Problem(403, 'MODEL_SCOPE_UNAVAILABLE', 'The complete model scope is unavailable for this operation.');
  const size = await sql<{ count: string; bytes: string }>`select count(*)::text as count,
    coalesce(sum(octet_length(attributes::text)),0)::text as bytes from assets
    where tenant_id=${principal.tenantId}::uuid and model_id=${modelId}`.execute(tx);
  if (Number(size.rows[0].count) > MODEL_LIMITS.previewAssets || Number(size.rows[0].bytes) > MODEL_SERVICE_LIMITS.previewBytes) {
    throw new Problem(422, 'MODEL_PREVIEW_LIMIT', 'This model exceeds the bounded synchronous preview profile. No partial preview or publication was performed.');
  }
  // Canonical asset locks also protect digest generation against scanner/normal PATCH changes.
  const rows = await tx.selectFrom('assets').select(['tenant_id', 'id', 'version', 'model_id', 'model_version', 'attributes', 'visibility', 'allowed_identities', 'owner_id', 'type_state'])
    .where('tenant_id', '=', principal.tenantId).where('model_id', '=', modelId).orderBy('id').forUpdate().execute();
  let nodes = 0;
  for (const row of rows) {
    if (!canView(principal, { tenantId: row.tenant_id, visibility: row.visibility, allowedIdentities: row.allowed_identities })) {
      throw new Problem(403, 'MODEL_SCOPE_UNAVAILABLE', 'The complete model scope is unavailable for this operation.');
    }
    const remaining: { value: unknown; depth: number }[] = [{ value: row.attributes, depth: 0 }];
    while (remaining.length) {
      const { value, depth } = remaining.pop()!; nodes += 2; // Current and proposed validations both consume a node budget.
      if (nodes > MODEL_LIMITS.previewNodes || depth > MODEL_LIMITS.valueDepth) throw new Problem(422, 'MODEL_PREVIEW_LIMIT', 'This model exceeds the bounded synchronous preview profile. No partial preview or publication was performed.');
      if (value && typeof value === 'object') for (const child of Object.values(value)) {
        if (remaining.length * 2 + nodes > MODEL_LIMITS.previewNodes) throw new Problem(422, 'MODEL_PREVIEW_LIMIT', 'This model exceeds the bounded synchronous preview profile. No partial preview or publication was performed.');
        remaining.push({ value: child, depth: depth + 1 });
      }
    }
  }
  return rows;
}

async function previewLocked(tx: Tx, principal: Principal, id: string, expectedVersion: number, input: unknown): Promise<ModelPreview> {
  const current = await head(tx, principal, id, true);
  if (current.type_id) throw new Problem(422, 'ASSET_TYPE_REQUIRED', 'Publish this authored asset type through its type editor.');
  assertHead(current, expectedVersion);
  const proposed = definition(input);
  const currentDefinition = storedDefinition(await versionRow(tx, principal, id, current.current_version));
  const schemaPreview = previewModelUpgrade(currentDefinition, proposed, []);
  if (!schemaPreview.ok) throw new Problem(422, 'MODEL_INVALID', 'Correct the proposed model upgrade.', schemaPreview.issues);
  if (proposed.version > MODEL_SERVICE_LIMITS.databaseVersion) throw new Problem(422, 'MODEL_VERSION_LIMIT', 'The supported persistent model version range has been exhausted.');
  const rows = await modelCohort(tx, principal, id);
  await authorize(tx, principal, ['models:read', 'models:write', 'catalog:read']);
  const definitions = new Map<number, ModelDefinition>([[current.current_version, currentDefinition]]);
  const results: ModelAssetPreview[] = [];
  let issueCount = 0;
  for (const row of rows) {
    if (!definitions.has(row.model_version)) definitions.set(row.model_version, storedDefinition(await versionRow(tx, principal, id, row.model_version)));
    const oldResult = validateAttributes(definitions.get(row.model_version)!, row.attributes);
    const proposedResult = validateAttributes(proposed, row.attributes);
    const currentIssues = oldResult.ok ? [] : oldResult.issues;
    const proposedIssues = proposedResult.ok ? [] : proposedResult.issues;
    issueCount += currentIssues.length + proposedIssues.length;
    if (issueCount > MODEL_LIMITS.previewIssues) throw new Problem(422, 'MODEL_PREVIEW_LIMIT', 'The preview issue budget was exceeded. No partial preview or publication was performed.');
    results.push({ assetId: row.id, currentIssues, proposedIssues });
  }
  const compatible = results.every(result => !result.currentIssues.length && !result.proposedIssues.length);
  const semanticChange = schemaPreview.value.changes.some(change => change.code !== 'metadata_changed');
  const digest = hash({ tenantId: principal.tenantId, modelId: id, currentVersion: current.current_version, definition: proposed,
    assets: rows.map(row => ({ id: row.id, version: row.version, modelId: row.model_id, modelVersion: row.model_version, attributes: row.attributes })) });
  return { modelId: id, currentVersion: current.current_version, proposedVersion: proposed.version,
    coverage: 'complete-tenant-model-bindings', assetCount: rows.length, changes: schemaPreview.value.changes,
    assets: results, affectedAssetIds: results.filter(result => semanticChange || result.currentIssues.length || result.proposedIssues.length).map(result => result.assetId),
    compatibleWithProvidedAssets: compatible, requiresExplicitMigration: !compatible || schemaPreview.value.requiresExplicitMigration,
    pinsPreserved: true, previewDigest: digest };
}

export async function previewModel(tx: Tx, principal: Principal, id: string, expectedVersion: number, input: unknown): Promise<ModelPreview> {
  await authorize(tx, principal, ['models:read', 'models:write', 'catalog:read']);
  await lockTenantModels(tx, principal);
  return previewLocked(tx, principal, id, expectedVersion, input);
}

export async function publishModel(tx: Tx, principal: Principal, correlationId: string, id: string, expectedVersion: number,
  input: unknown, expectedPreviewDigest: string, hooks: ModelHooks): Promise<{ model: ModelVersionView }> {
  await authorize(tx, principal, ['models:read', 'models:write', 'catalog:read']);
  if (typeof expectedPreviewDigest !== 'string' || !/^[a-f0-9]{64}$/.test(expectedPreviewDigest)) throw new Problem(428, 'MODEL_PREVIEW_REQUIRED', 'Run a complete model preview before publication.');
  await lockTenantModels(tx, principal);
  const preview = await previewLocked(tx, principal, id, expectedVersion, input);
  if (preview.previewDigest !== expectedPreviewDigest) throw new Problem(409, 'MODEL_PREVIEW_STALE', 'The model or its asset bindings changed. Run a new preview.');
  if (preview.requiresExplicitMigration) throw new Problem(422, 'MODEL_MIGRATION_REQUIRED', 'This upgrade requires the explicit migration workflow and a fresh transformation preview. No version was published.');
  const parsed = definition(input);
  const row = await tx.insertInto('governance_model_versions').values({ tenant_id: principal.tenantId, model_id: id,
    version: parsed.version, definition: JSON.stringify(parsed), definition_hash: hash(parsed), created_by: principal.id }).returningAll().executeTakeFirstOrThrow();
  const update = await tx.updateTable('governance_models').set({ current_version: parsed.version }).where('tenant_id', '=', principal.tenantId)
    .where('id', '=', id).where('current_version', '=', expectedVersion).executeTakeFirst();
  if (Number(update.numUpdatedRows) !== 1) throw new Problem(409, 'VERSION_CONFLICT', 'The model changed. Run a new preview.');
  await hooks.record(tx, principal, 'model.published', id, parsed.version,
    { previousVersion: expectedVersion, definitionHash: row.definition_hash, pinsPreserved: true }, correlationId);
  return { model: view(row, parsed.version) };
}

async function assetModelView(tx: Tx, principal: Principal, asset: Row): Promise<AssetModelView> {
  const parsed = asset.model_id === null ? null : storedDefinition(await versionRow(tx, principal, asset.model_id, asset.model_version));
  if (parsed) {
    const validated = validateAttributes(parsed, asset.attributes);
    if (!validated.ok) throw new Problem(500, 'ATTRIBUTE_STORAGE_INVALID', 'The stored typed attributes could not be verified.');
  }
  return { assetId: asset.id, assetVersion: asset.version, modelId: asset.model_id, modelVersion: asset.model_version,
    attributes: asset.attributes, definition: parsed };
}

export async function getAssetModel(tx: Tx, principal: Principal, assetId: string): Promise<AssetModelView> {
  await authorize(tx, principal, ['catalog:read', 'models:read']);
  return assetModelView(tx, principal, await assetRow(tx, principal, assetId));
}

export async function assignAssetModel(tx: Tx, principal: Principal, correlationId: string, assetId: string,
  expectedAssetVersion: number, input: AssetModelInput, hooks: ModelHooks): Promise<AssetModelView> {
  await authorize(tx, principal, ['catalog:read', 'catalog:write', 'models:read']);
  checkVersion(expectedAssetVersion);
  if (expectedAssetVersion === MODEL_SERVICE_LIMITS.databaseVersion) throw new Problem(422, 'ASSET_VERSION_LIMIT', 'The supported asset version range has been exhausted.');
  checkId(input.modelId); checkVersion(input.modelVersion, 'MODEL_VERSION_INVALID');
  await lockTenantModels(tx, principal);
  await head(tx, principal, input.modelId, true);
  const model = storedDefinition(await versionRow(tx, principal, input.modelId, input.modelVersion));
  const asset = await assetRow(tx, principal, assetId, true);
  await authorize(tx, principal, ['catalog:read', 'catalog:write', 'models:read']);
  if (asset.version !== expectedAssetVersion) throw new Problem(409, 'VERSION_CONFLICT', 'The asset changed. Load its current version before saving.');
  const parsed = validateAttributes(model, input.attributes);
  if (!parsed.ok) throw new Problem(422, 'ATTRIBUTES_INVALID', 'Correct the typed attribute values.', parsed.issues);
  const policy = await assetTypePolicy(tx, principal, input.modelId, input.modelVersion);
  const state = policy ? (asset.model_id === input.modelId && asset.type_state ? asset.type_state : policy.lifecycle.initial) : null;
  if (policy) {
    await validateTypeOwner(tx, principal, policy.requiredOwner, asset.owner_id);
    if (!policy.lifecycle.states.includes(state!)) throw new Problem(422, 'ASSET_TYPE_STATE_INVALID', 'The current state is not valid for the selected type version.');
  }
  if (Buffer.byteLength(JSON.stringify(parsed.value), 'utf8') > MODEL_SERVICE_LIMITS.previewBytes) throw new Problem(422, 'ATTRIBUTE_PROFILE_LIMIT', 'The typed attributes exceed this development storage profile.');
  // An explicit pin and full replacement are required; no source metadata is interpreted as governed attributes.
  const updated = await tx.updateTable('assets').set({ model_id: input.modelId, model_version: input.modelVersion,
    attributes: JSON.stringify(parsed.value), type_state: state, version: asset.version + 1, updated_at: new Date() })
    .where('tenant_id', '=', principal.tenantId).where('id', '=', assetId).where('version', '=', expectedAssetVersion)
    .returningAll().executeTakeFirst();
  if (!updated) throw new Problem(409, 'VERSION_CONFLICT', 'The asset changed. Load its current version before saving.');
  await tx.insertInto('asset_revisions').values({ tenant_id: principal.tenantId, asset_id: assetId,
    version: updated.version, snapshot: JSON.stringify(hooks.assetSnapshot(updated)) }).execute();
  await hooks.record(tx, principal, 'asset.model_assigned', assetId, updated.version, {
    before: { modelId: asset.model_id, modelVersion: asset.model_version, attributesHash: hash(asset.attributes) },
    after: { modelId: input.modelId, modelVersion: input.modelVersion, attributesHash: hash(parsed.value) },
    revision: updated.version,
  }, correlationId);
  return assetModelView(tx, principal, updated);
}

/** Internal persistence primitives for the guarded migration application service.
 * Ingress adapters must call complete services, never these individual helpers. */
export const modelPersistence = Object.freeze({
  authorize, lockTenantModels, head, assertHead, definition, storedDefinition,
  versionRow, modelCohort, hash, view, assetRow, checkVersion,
});
