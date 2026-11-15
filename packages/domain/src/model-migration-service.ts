// SPDX-License-Identifier: Apache-2.0
import { randomUUID } from 'node:crypto';
import { sql, type Tx } from '../../db/src/index.ts';
import { canView, Problem, type Principal } from '../../authz/src/index.ts';
import {
  MODEL_LIMITS, previewModelUpgrade, type AttributeValues, type ModelChange,
  type ModelDefinition, type ValidationIssue,
} from './model.ts';
import {
  applyModelMigrationToAttributes, parseMigrationPlan, validateMigrationPlanForModels,
  type MigrationPlan,
} from './model-migration.ts';
import { MODEL_SERVICE_LIMITS, modelPersistence as persistence, type ModelHooks, type ModelVersionView } from './model-service.ts';

/** A deliberately bounded synchronous development profile, not a bulk migration worker. */
export const MODEL_MIGRATION_SERVICE_LIMITS = Object.freeze({
  assets: MODEL_LIMITS.previewAssets, attributeBytes: MODEL_SERVICE_LIMITS.previewBytes,
  attributeNodes: MODEL_LIMITS.previewNodes, definitionBytes: MODEL_SERVICE_LIMITS.previewBytes,
  definitionNodes: MODEL_LIMITS.previewNodes, issues: MODEL_LIMITS.previewIssues,
});
export interface MigrationRequest { readonly definition: unknown; readonly plan: unknown }
export interface MigrationExecutionRequest extends MigrationRequest { readonly previewDigest: string }
export interface MigrationAssetReceipt {
  assetId: string; fromAssetVersion: number; toAssetVersion: number;
  fromModelVersion: number; toModelVersion: number; beforeHash: string; afterHash: string;
}
export interface MigrationAssetPreview extends MigrationAssetReceipt {
  beforeAttributes: AttributeValues; afterAttributes: AttributeValues;
}
export interface MigrationPreview {
  modelId: string; currentVersion: number; proposedVersion: number;
  coverage: 'complete-tenant-model-bindings'; assetCount: number;
  changes: readonly ModelChange[]; assets: readonly MigrationAssetPreview[];
  previewDigest: string; planHash: string; ready: true;
}
export interface ModelMigrationReceipt {
  id: string; modelId: string; fromVersion: number; toVersion: number;
  plan: MigrationPlan; planHash: string; previewDigest: string;
  assetCount: number; assets: readonly MigrationAssetReceipt[];
  executedBy: string; executedAt: string;
}
export interface MigrationContext { modelId: string; currentVersion: number; sourceVersions: readonly number[]; assetCount: number }
export interface MigrationReceiptOptions { readonly forExecutionReplay?: boolean }
type Row = Record<string, any>;
type Prepared = { preview: MigrationPreview; definition: ModelDefinition; plan: MigrationPlan };
const writePermissions = ['models:read', 'models:write', 'catalog:read', 'catalog:write'] as const;
const readPermissions = ['models:read', 'catalog:read'] as const;
const sha256 = /^[a-f0-9]{64}$/;
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const invalid = (issues?: Problem['issues']): Problem => new Problem(422, 'MODEL_MIGRATION_INVALID', 'Correct the migration plan or affected typed values before continuing.', issues);
const limit = (): Problem => new Problem(422, 'MODEL_MIGRATION_LIMIT', 'This migration exceeds the bounded synchronous development profile. No partial migration was performed.');
const storageInvalid = (): Problem => new Problem(500, 'MODEL_MIGRATION_STORAGE_INVALID', 'The stored migration receipt could not be verified.');
const unavailable = (): Problem => new Problem(403, 'MODEL_SCOPE_UNAVAILABLE', 'The complete model scope is unavailable for this operation.');

function countNodes(value: unknown, maximum: number): number {
  const remaining: unknown[] = [value]; let count = 0;
  while (remaining.length) {
    const item = remaining.pop(); count += 1;
    if (count > maximum) throw limit();
    if (item && typeof item === 'object') for (const child of Object.values(item)) {
      if (remaining.length + count >= maximum) throw limit();
      remaining.push(child);
    }
  }
  return count;
}
function sameVersions(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((version, index) => version === right[index]);
}
function receiptAssets(preview: MigrationPreview): MigrationAssetReceipt[] {
  return preview.assets.map(({ beforeAttributes: _before, afterAttributes: _after, ...asset }) => asset);
}

async function sourceDefinitions(tx: Tx, principal: Principal, modelId: string, versions: readonly number[]): Promise<Map<number, ModelDefinition>> {
  // Bound database bytes before materializing any historic definitions. The current
  // head is included even when no asset is pinned to it.
  const size = await tx.selectFrom('governance_model_versions')
    .select([sql<string>`count(*)::text`.as('count'), sql<string>`coalesce(sum(octet_length(definition::text)),0)::text`.as('bytes')])
    .where('tenant_id', '=', principal.tenantId).where('model_id', '=', modelId).where('version', 'in', [...versions]).executeTakeFirstOrThrow();
  if (Number(size.bytes) > MODEL_MIGRATION_SERVICE_LIMITS.definitionBytes) throw limit();
  if (Number(size.count) !== versions.length) throw new Problem(500, 'MODEL_STORAGE_INVALID', 'The stored model could not be verified.');
  const rows = await tx.selectFrom('governance_model_versions').selectAll().where('tenant_id', '=', principal.tenantId)
    .where('model_id', '=', modelId).where('version', 'in', [...versions]).orderBy('version').execute();
  const definitions = new Map<number, ModelDefinition>(); let nodes = 0;
  for (const row of rows) {
    nodes += countNodes(row.definition, MODEL_MIGRATION_SERVICE_LIMITS.definitionNodes - nodes);
    definitions.set(row.version, persistence.storedDefinition(row));
  }
  return definitions;
}

/** Must run only after the shared ledger → model lock order has been acquired. */
async function prepare(tx: Tx, principal: Principal, id: string, expectedVersion: number, input: MigrationRequest): Promise<Prepared> {
  await persistence.authorize(tx, principal, writePermissions);
  const current = await persistence.head(tx, principal, id, true);
  persistence.assertHead(current, expectedVersion);
  const head = persistence.storedDefinition(await persistence.versionRow(tx, principal, id, current.current_version));
  let proposed: ModelDefinition;
  try { proposed = persistence.definition(input.definition); }
  catch (error) {
    if (error instanceof Problem && error.code === 'MODEL_INVALID') throw invalid(error.issues);
    throw error;
  }
  const parsed = validateMigrationPlanForModels(head, proposed, input.plan as MigrationPlan);
  if (!parsed.ok) throw invalid(parsed.issues);
  const plan = parsed.value;
  if (proposed.version > MODEL_SERVICE_LIMITS.databaseVersion) throw limit();
  let rows: Row[];
  try { rows = await persistence.modelCohort(tx, principal, id); }
  catch (error) {
    if (error instanceof Problem && error.code === 'MODEL_PREVIEW_LIMIT') throw limit();
    throw error;
  }
  await persistence.authorize(tx, principal, writePermissions);
  const actualVersions = [...new Set<number>(rows.map(row => row.model_version))].sort((left, right) => left - right);
  if (!sameVersions(plan.sourceVersions, actualVersions)) throw invalid([{ code: 'model_version', path: '/plan/sourceVersions', message: 'Source versions must exactly identify the current complete cohort of pinned versions.' }]);
  const versions = [...new Set([...actualVersions, current.current_version])].sort((left, right) => left - right);
  const definitions = await sourceDefinitions(tx, principal, id, versions);
  const assets: MigrationAssetPreview[] = []; const issues: ValidationIssue[] = [];
  let beforeBytes = 0; let afterBytes = 0; let beforeNodes = 0; let afterNodes = 0;
  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index];
    if (row.version >= MODEL_SERVICE_LIMITS.databaseVersion) throw limit();
    beforeBytes += Buffer.byteLength(JSON.stringify(row.attributes), 'utf8');
    beforeNodes += countNodes(row.attributes, MODEL_MIGRATION_SERVICE_LIMITS.attributeNodes - beforeNodes);
    if (beforeBytes > MODEL_MIGRATION_SERVICE_LIMITS.attributeBytes) throw limit();
    const transformed = applyModelMigrationToAttributes({ head, source: definitions.get(row.model_version)!, target: proposed, plan, attributes: row.attributes });
    if (!transformed.ok) {
      for (const issue of transformed.issues) {
        if (issues.length >= MODEL_MIGRATION_SERVICE_LIMITS.issues) throw limit();
        issues.push({ ...issue, path: `/assets/${index}${issue.path}` });
      }
      continue;
    }
    afterBytes += Buffer.byteLength(JSON.stringify(transformed.value), 'utf8');
    afterNodes += countNodes(transformed.value, MODEL_MIGRATION_SERVICE_LIMITS.attributeNodes - afterNodes);
    if (afterBytes > MODEL_MIGRATION_SERVICE_LIMITS.attributeBytes) throw limit();
    assets.push({ assetId: row.id, fromAssetVersion: row.version, toAssetVersion: row.version + 1,
      fromModelVersion: row.model_version, toModelVersion: proposed.version,
      beforeHash: persistence.hash(row.attributes), afterHash: persistence.hash(transformed.value),
      beforeAttributes: row.attributes, afterAttributes: transformed.value });
  }
  if (issues.length) throw invalid(issues);
  const schema = previewModelUpgrade(head, proposed, []);
  if (!schema.ok) throw invalid(schema.issues);
  const planHash = persistence.hash(plan);
  const previewDigest = persistence.hash({ formatVersion: 1, purpose: 'model-migration', tenantId: principal.tenantId,
    modelId: id, currentVersion: current.current_version, definition: proposed, plan,
    sourceDefinitions: versions.map(version => ({ version, hash: persistence.hash(definitions.get(version)!) })),
    assets: assets.map(({ beforeAttributes: _before, afterAttributes: _after, ...asset }) => asset) });
  await persistence.authorize(tx, principal, writePermissions);
  return { definition: proposed, plan, preview: { modelId: id, currentVersion: current.current_version,
    proposedVersion: proposed.version, coverage: 'complete-tenant-model-bindings', assetCount: assets.length,
    changes: schema.value.changes, assets, previewDigest, planHash, ready: true } };
}

export async function getMigrationContext(tx: Tx, principal: Principal, id: string): Promise<MigrationContext> {
  await persistence.authorize(tx, principal, writePermissions);
  await persistence.lockTenantModels(tx, principal);
  await persistence.authorize(tx, principal, writePermissions);
  const current = await persistence.head(tx, principal, id, true);
  let rows: Row[];
  try { rows = await persistence.modelCohort(tx, principal, id); }
  catch (error) {
    if (error instanceof Problem && error.code === 'MODEL_PREVIEW_LIMIT') throw limit();
    throw error;
  }
  await persistence.authorize(tx, principal, writePermissions);
  return { modelId: id, currentVersion: current.current_version,
    sourceVersions: [...new Set<number>(rows.map(row => row.model_version))].sort((left, right) => left - right), assetCount: rows.length };
}

export async function previewMigration(tx: Tx, principal: Principal, id: string, expectedVersion: number, input: MigrationRequest): Promise<MigrationPreview> {
  await persistence.authorize(tx, principal, writePermissions);
  await persistence.lockTenantModels(tx, principal);
  return (await prepare(tx, principal, id, expectedVersion, input)).preview;
}

/** Caller supplies one transaction and its canonical audit/outbox hooks; errors must roll it back. */
export async function executeMigration(tx: Tx, principal: Principal, correlationId: string, id: string,
  expectedVersion: number, input: MigrationExecutionRequest, hooks: ModelHooks): Promise<{ model: ModelVersionView; receipt: ModelMigrationReceipt }> {
  await persistence.authorize(tx, principal, writePermissions);
  if (typeof input.previewDigest !== 'string' || !sha256.test(input.previewDigest)) throw new Problem(428, 'MODEL_MIGRATION_PREVIEW_REQUIRED', 'Run a complete migration preview before execution.');
  await persistence.lockTenantModels(tx, principal);
  const prepared = await prepare(tx, principal, id, expectedVersion, input);
  const { preview, definition, plan } = prepared;
  if (input.previewDigest !== preview.previewDigest) throw new Problem(409, 'MODEL_MIGRATION_PREVIEW_STALE', 'The model, plan or affected asset state changed. Run a new migration preview.');
  // No writes precede complete cohort validation and digest comparison.
  const version = await tx.insertInto('governance_model_versions').values({ tenant_id: principal.tenantId, model_id: id,
    version: definition.version, definition: JSON.stringify(definition), definition_hash: persistence.hash(definition), created_by: principal.id })
    .returningAll().executeTakeFirstOrThrow();
  const head = await tx.updateTable('governance_models').set({ current_version: definition.version }).where('tenant_id', '=', principal.tenantId)
    .where('id', '=', id).where('current_version', '=', expectedVersion).executeTakeFirst();
  if (Number(head.numUpdatedRows) !== 1) throw new Problem(409, 'VERSION_CONFLICT', 'The model changed. Run a new migration preview.');
  const migrationId = randomUUID();
  for (const asset of preview.assets) {
    const updated = await tx.updateTable('assets').set({ model_version: definition.version, attributes: JSON.stringify(asset.afterAttributes),
      version: asset.toAssetVersion, updated_at: new Date() }).where('tenant_id', '=', principal.tenantId).where('id', '=', asset.assetId)
      .where('model_id', '=', id).where('model_version', '=', asset.fromModelVersion).where('version', '=', asset.fromAssetVersion)
      .returningAll().executeTakeFirst();
    if (!updated) throw new Problem(409, 'MODEL_MIGRATION_PREVIEW_STALE', 'An affected asset changed. Run a new migration preview.');
    await tx.insertInto('asset_revisions').values({ tenant_id: principal.tenantId, asset_id: asset.assetId,
      version: asset.toAssetVersion, snapshot: JSON.stringify(hooks.assetSnapshot(updated)) }).execute();
    await hooks.record(tx, principal, 'asset.model_migrated', asset.assetId, asset.toAssetVersion, {
      migrationId, modelId: id, before: { modelVersion: asset.fromModelVersion, attributesHash: asset.beforeHash },
      after: { modelVersion: asset.toModelVersion, attributesHash: asset.afterHash }, revision: asset.toAssetVersion,
    }, correlationId);
  }
  const receipt = await tx.insertInto('governance_model_migrations').values({ tenant_id: principal.tenantId, id: migrationId,
    model_id: id, from_version: expectedVersion, to_version: definition.version, plan: JSON.stringify(plan), plan_hash: preview.planHash,
    preview_digest: preview.previewDigest, asset_count: preview.assetCount, assets: JSON.stringify(receiptAssets(preview)), executed_by: principal.id })
    .returningAll().executeTakeFirstOrThrow();
  // Model-level audit is visible independently of asset visibility. Keep asset IDs,
  // counts and plan literal values confined to the separately authorized receipt.
  await hooks.record(tx, principal, 'model.migrated', id, definition.version, { previousVersion: expectedVersion,
    definitionHash: version.definition_hash, migrationId, planHash: preview.planHash, previewDigest: preview.previewDigest }, correlationId);
  return { model: persistence.view(version, definition.version), receipt: receiptView(receipt) };
}

function receiptView(row: Row): ModelMigrationReceipt {
  const parsed = parseMigrationPlan(row.plan);
  if (!parsed.ok || parsed.value.modelId !== row.model_id || parsed.value.targetVersion !== row.to_version ||
      persistence.hash(parsed.value) !== row.plan_hash || !sha256.test(row.preview_digest) ||
      !Number.isInteger(row.from_version) || row.from_version < 1 || row.to_version !== row.from_version + 1 ||
      !Number.isInteger(row.asset_count) || row.asset_count < 0 || row.asset_count > MODEL_MIGRATION_SERVICE_LIMITS.assets ||
      !Array.isArray(row.assets) || row.assets.length !== row.asset_count) throw storageInvalid();
  const assets: MigrationAssetReceipt[] = []; let previousId = '';
  const fields = ['afterHash', 'assetId', 'beforeHash', 'fromAssetVersion', 'fromModelVersion', 'toAssetVersion', 'toModelVersion'];
  for (const asset of row.assets) {
    if (!asset || typeof asset !== 'object' || Array.isArray(asset) || Object.keys(asset).sort().join('|') !== fields.join('|') ||
        typeof asset.assetId !== 'string' || !uuid.test(asset.assetId) || asset.assetId <= previousId ||
        !Number.isInteger(asset.fromAssetVersion) || asset.fromAssetVersion < 1 || asset.toAssetVersion !== asset.fromAssetVersion + 1 ||
        asset.toAssetVersion > MODEL_SERVICE_LIMITS.databaseVersion || !Number.isInteger(asset.fromModelVersion) ||
        !parsed.value.sourceVersions.includes(asset.fromModelVersion) || asset.toModelVersion !== row.to_version ||
        typeof asset.beforeHash !== 'string' || !sha256.test(asset.beforeHash) || typeof asset.afterHash !== 'string' || !sha256.test(asset.afterHash)) throw storageInvalid();
    previousId = asset.assetId; assets.push({ ...asset });
  }
  if (!sameVersions(parsed.value.sourceVersions, [...new Set(assets.map(asset => asset.fromModelVersion))].sort((left, right) => left - right))) throw storageInvalid();
  return { id: row.id, modelId: row.model_id, fromVersion: row.from_version, toVersion: row.to_version,
    plan: parsed.value, planHash: row.plan_hash, previewDigest: row.preview_digest, assetCount: row.asset_count, assets,
    executedBy: row.executed_by, executedAt: new Date(row.executed_at).toISOString() };
}

/** Recheck the recorded cohort, including assets subsequently pinned to another model. */
export async function getMigrationReceipt(tx: Tx, principal: Principal, modelId: string, migrationId: string,
  options: MigrationReceiptOptions = {}): Promise<{ receipt: ModelMigrationReceipt }> {
  const actions = options.forExecutionReplay ? writePermissions : readPermissions;
  await persistence.authorize(tx, principal, actions);
  await persistence.head(tx, principal, modelId);
  if (typeof migrationId !== 'string' || !uuid.test(migrationId)) throw new Problem(400, 'MODEL_MIGRATION_ID_INVALID', 'Provide a valid migration identifier.');
  const row = await tx.selectFrom('governance_model_migrations').selectAll().where('tenant_id', '=', principal.tenantId)
    .where('model_id', '=', modelId).where('id', '=', migrationId).executeTakeFirst();
  if (!row) throw new Problem(404, 'MODEL_MIGRATION_NOT_FOUND', 'Migration receipt is unavailable.');
  const receipt = receiptView(row);
  const exception = await tx.selectFrom('governance_model_migration_integrity_exceptions').select('migration_id')
    .where('tenant_id', '=', principal.tenantId).where('migration_id', '=', migrationId).executeTakeFirst();
  const normalized = await tx.selectFrom('governance_model_migration_assets').select(tx.fn.countAll().as('count'))
    .where('tenant_id', '=', principal.tenantId).where('migration_id', '=', migrationId).executeTakeFirstOrThrow();
  // Pre-005 revision gaps remain visible to operators, but incomplete receipts
  // must never be returned as a successful execution/replay or a valid history.
  if (exception || Number(normalized.count) !== receipt.assetCount) throw storageInvalid();
  if (receipt.assets.length) {
    const assets = await tx.selectFrom('assets').select(['tenant_id', 'id', 'visibility', 'allowed_identities'])
      .where('tenant_id', '=', principal.tenantId).where('id', 'in', receipt.assets.map(asset => asset.assetId)).execute();
    if (assets.length !== receipt.assets.length || assets.some(asset => !canView(principal, {
      tenantId: asset.tenant_id, visibility: asset.visibility, allowedIdentities: asset.allowed_identities,
    }))) throw unavailable();
  }
  await persistence.authorize(tx, principal, actions);
  return { receipt };
}
