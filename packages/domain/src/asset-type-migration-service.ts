// SPDX-License-Identifier: Apache-2.0
import { randomUUID } from 'node:crypto';
import { sql, type Tx } from '../../db/src/index.ts';
import { canView, Problem, type Principal } from '../../authz/src/index.ts';
import { MODEL_LIMITS, previewModelUpgrade, type ValidationIssue } from './model.ts';
import { applyModelMigrationToAttributes } from './model-migration.ts';
import { parseAssetTypeMigrationPlan, validateAssetTypeMigrationPlan, applyAssetTypeMigrationPolicy } from './asset-type-migration.ts';
import { assetTypePolicy, typeHash } from './asset-type-policy.ts';
import { assetTypePersistence as types, assetTypePolicyChanges, getAssetType } from './asset-type-service.ts';
import { MODEL_SERVICE_LIMITS, modelPersistence as persistence, type ModelHooks } from './model-service.ts';
import type { ResolvedAssetType } from './asset-type.ts';
import type { TypeMigrationContext, TypeMigrationPreview, TypeMigrationRequest, TypeMigrationExecutionRequest,
  TypeMigrationTuple, TypeMigrationAssetReceipt, TypeMigrationReceipt } from './asset-type-migration-contracts.ts';

export const TYPE_MIGRATION_WRITE = ['models:read', 'models:write', 'catalog:read', 'catalog:write'] as const;
const readPermissions = ['models:read', 'catalog:read'] as const;
const invalid = (issues?: readonly ValidationIssue[]) => new Problem(422, 'ASSET_TYPE_MIGRATION_INVALID', 'Correct the complete type migration plan and affected values.', issues);
const limit = () => new Problem(422, 'ASSET_TYPE_MIGRATION_LIMIT', 'The complete migration exceeds this bounded development profile. No partial migration was performed.');
const storage = () => new Problem(500, 'ASSET_TYPE_MIGRATION_STORAGE_INVALID', 'The complete type migration receipt could not be verified.');
const unavailable = () => new Problem(403, 'MODEL_SCOPE_UNAVAILABLE', 'The complete model scope is unavailable for this operation.');
const sha256 = /^[a-f0-9]{64}$/;
type Row = Record<string, any>;

/** Call before idempotency/ledger locks, including cached HTTP execution. */
export async function configureTypeMigrationTransaction(tx: Tx): Promise<void> {
  await sql`select set_config('lock_timeout','5s',true), set_config('statement_timeout','30s',true)`.execute(tx);
}
export function typeMigrationFailure(error: unknown): unknown {
  if (error && typeof error === 'object' && 'code' in error && ['55P03', '40P01', '57014'].includes(String(error.code))) {
    return new Problem(503, 'ASSET_TYPE_MIGRATION_RETRY', 'The migration could not obtain a stable execution window. Retry with the same idempotency key; a changed scope requires a fresh preview.');
  }
  return error;
}
async function bounded<T>(tx: Tx, work: () => Promise<T>): Promise<T> {
  await configureTypeMigrationTransaction(tx);
  try { return await work(); } catch (error) { throw typeMigrationFailure(error); }
}
function budget(value: unknown, maximum: number = MODEL_LIMITS.previewNodes): number {
  const pending = [value]; let count = 0;
  while (pending.length) {
    const current = pending.pop(); if (++count > maximum) throw limit();
    if (current && typeof current === 'object') {
      for (const child of Object.values(current)) { if (pending.length + count >= maximum) throw limit(); pending.push(child); }
    }
  }
  return count;
}
async function policies(tx: Tx, p: Principal, id: string, versions: number[]) {
  // Bound full source envelopes before materializing them; policy() recomputes exact ancestry.
  const size = await sql<{ bytes: string; count: string }>`select count(*)::text as count,
    coalesce(sum(octet_length(resolved::text)),0)::text as bytes from asset_type_versions
    where tenant_id=${p.tenantId}::uuid and model_id=${id} and version=any(${versions}::integer[])`.execute(tx);
  if (Number(size.rows[0].bytes) > MODEL_SERVICE_LIMITS.previewBytes) throw limit();
  if (Number(size.rows[0].count) !== versions.length) throw storage();
  const result = new Map<number, ResolvedAssetType>(); let bytes = 0, nodes = 0;
  for (const version of versions) {
    const policy = await assetTypePolicy(tx, p, id, version); if (!policy) throw storage();
    bytes += Buffer.byteLength(JSON.stringify(policy)); nodes += budget(policy, MODEL_LIMITS.previewNodes - nodes);
    if (bytes > MODEL_SERVICE_LIMITS.previewBytes) throw limit(); result.set(version, policy);
  }
  return result;
}
async function lockPrincipals(tx: Tx, p: Principal, ids: (string | null)[]) {
  const requested = [...new Set([p.id, ...ids.filter((id): id is string => id !== null)])].sort();
  if (requested.length > 2001) throw limit();
  await sql`select public.gc_lock_type_migration_principals(${requested}::uuid[])`.execute(tx);
  await persistence.authorize(tx, p, TYPE_MIGRATION_WRITE);
  const active = await tx.selectFrom('memberships').innerJoin('identities', 'identities.id', 'memberships.identity_id')
    .select('memberships.identity_id').where('memberships.tenant_id', '=', p.tenantId).where('memberships.identity_id', 'in', requested)
    .where('memberships.active', '=', true).where('identities.active', '=', true).execute();
  const activeIds = new Set<string>(active.map(row => row.identity_id));
  return { activeIds, activity: requested.map(id => ({ id, active: activeIds.has(id) })) };
}
async function cohort(tx: Tx, p: Principal, id: string) {
  try { return await persistence.modelCohort(tx, p, id); }
  catch (error) { if (error instanceof Problem && error.code === 'MODEL_PREVIEW_LIMIT') throw limit(); throw error; }
}
async function prepare(tx: Tx, p: Principal, id: string, expected: number, input: TypeMigrationRequest) {
  await persistence.authorize(tx, p, TYPE_MIGRATION_WRITE);
  const headRow = await types.typeHead(tx, p, id, true); persistence.assertHead(headRow, expected);
  const parsed = parseAssetTypeMigrationPlan(input.plan); if (!parsed.ok) throw invalid(parsed.issues);
  const target = await types.resolved(tx, p, input.definition);
  const rows = await cohort(tx, p, id);
  const sourceVersions = [...new Set<number>(rows.map(row => row.model_version))].sort((a, b) => a - b);
  const versions = [...new Set([...sourceVersions, headRow.current_version])].sort((a, b) => a - b);
  const source = await policies(tx, p, id, versions), head = source.get(headRow.current_version)!;
  // The combined head/target/source materialization remains bounded, including an empty cohort.
  const definitions = [...source.values(), target];
  if (Buffer.byteLength(JSON.stringify(definitions)) > MODEL_SERVICE_LIMITS.previewBytes) throw limit(); budget(definitions);
  const valid = validateAssetTypeMigrationPlan({ typeId: headRow.type_id, head, target,
    sources: sourceVersions.map(version => source.get(version)!), cohort: rows.map(row => ({ assetId: row.id, sourceVersion: row.model_version })) }, parsed.value);
  if (!valid.ok) throw invalid(valid.issues);
  const plan = valid.value;
  const { activeIds, activity } = await lockPrincipals(tx, p, [...rows.map(row => row.owner_id ?? null), ...plan.owner.overrides.map(item => item.ownerId)]);
  const assets: TypeMigrationPreview['assets'] = [], issues: ValidationIssue[] = [];
  // One aggregate budget covers the complete plan, resolved definitions and both value tuples.
  let bytes = Buffer.byteLength(JSON.stringify({ definitions, plan })), nodes = budget({ definitions, plan });
  if (bytes > MODEL_SERVICE_LIMITS.previewBytes) throw limit();
  for (const [index, row] of rows.entries()) {
    if (row.version >= MODEL_SERVICE_LIMITS.databaseVersion) throw limit();
    const sourcePolicy = source.get(row.model_version)!;
    const values = applyModelMigrationToAttributes({ head: head.model, source: sourcePolicy.model,
      target: target.model, plan: plan.attributes, attributes: row.attributes });
    const policy = applyAssetTypeMigrationPolicy({ source: sourcePolicy, target, plan,
      asset: { assetId: row.id, modelVersion: row.model_version, ownerId: row.owner_id ?? null, state: row.type_state ?? null }, activeOwnerIds: activeIds });
    for (const checked of [values, policy]) if (!checked.ok) for (const issue of checked.issues) {
      if (issues.length >= MODEL_LIMITS.previewIssues) throw limit(); issues.push({ ...issue, path: `/assets/${index}${issue.path}` });
    }
    if (!values.ok || !policy.ok) continue;
    const before: TypeMigrationTuple = { modelId: id, modelVersion: row.model_version, attributes: row.attributes, ownerId: row.owner_id ?? null, state: row.type_state };
    const after: TypeMigrationTuple = { modelId: id, modelVersion: target.model.version, attributes: values.value, ownerId: policy.value.ownerId, state: policy.value.state };
    bytes += Buffer.byteLength(JSON.stringify([before, after])); nodes += budget([before, after], MODEL_LIMITS.previewNodes - nodes);
    if (bytes > MODEL_SERVICE_LIMITS.previewBytes) throw limit();
    assets.push({ assetId: row.id, fromAssetVersion: row.version, toAssetVersion: row.version + 1,
      fromModelVersion: row.model_version, toModelVersion: target.model.version, beforeHash: typeHash(before.attributes), afterHash: typeHash(after.attributes),
      before, after, beforeTupleHash: typeHash(before), afterTupleHash: typeHash(after), sourceIssues: policy.value.sourceIssues });
  }
  if (issues.length) throw invalid(issues);
  // PostgreSQL expands exponent notation in JSONB. Bound the actual persisted
  // representation too, before a preview can promise an executable migration.
  const storedAssets = assets.map(({ sourceIssues: _issues, ...asset }) => asset);
  const physical = await sql<{ plan_bytes: number; assets_bytes: number; definition_bytes: number; resolved_bytes: number }>`select
    octet_length(${JSON.stringify(plan)}::jsonb::text) as plan_bytes,
    octet_length(${JSON.stringify(storedAssets)}::jsonb::text) as assets_bytes,
    octet_length(${JSON.stringify(target.definition)}::jsonb::text) as definition_bytes,
    octet_length(${JSON.stringify(target)}::jsonb::text) as resolved_bytes`.execute(tx);
  const sizes = physical.rows[0];
  if (sizes.plan_bytes > 8_388_608 || sizes.assets_bytes > 8_388_608 || sizes.definition_bytes > 262_144 || sizes.resolved_bytes > 524_288) throw limit();
  const changes = previewModelUpgrade(head.model, target.model, []); if (!changes.ok) throw invalid(changes.issues);
  const sourceResolutions = versions.map(version => ({ version, resolutionHash: typeHash(source.get(version)!) }));
  const definitionHash = typeHash(target.definition), resolutionHash = typeHash(target), planHash = typeHash(plan);
  const previewDigest = typeHash({ formatVersion: 1, purpose: 'complete-asset-type-migration', tenantId: p.tenantId,
    typeId: headRow.type_id, modelId: id, expectedVersion: expected, plan, definitionHash, resolutionHash,
    dependencies: target.dependencies, sourceResolutions, activity, assets });
  const preview: TypeMigrationPreview = { typeId: headRow.type_id, modelId: id, currentVersion: expected, proposedVersion: target.model.version,
    coverage: 'complete-tenant-model-bindings', assetCount: assets.length, changes: changes.value.changes,
    policyChanges: assetTypePolicyChanges(head, target), sourceResolutions, definitionHash, resolutionHash,
    assets, previewDigest, planHash, ready: true };
  return { headRow, target, plan, preview };
}

export async function getTypeMigrationContext(tx: Tx, p: Principal, id: string): Promise<TypeMigrationContext> {
  return bounded(tx, async () => {
    await persistence.authorize(tx, p, TYPE_MIGRATION_WRITE); await persistence.lockTenantModels(tx, p);
    await persistence.authorize(tx, p, TYPE_MIGRATION_WRITE);
    const head = await types.typeHead(tx, p, id, true), rows = await cohort(tx, p, id);
    const sourceVersions = [...new Set<number>(rows.map(row => row.model_version))].sort((a, b) => a - b);
    const source = await policies(tx, p, id, sourceVersions);
    await lockPrincipals(tx, p, rows.map(row => row.owner_id ?? null));
    const names = rows.length ? await tx.selectFrom('assets').select(['id', 'name']).where('tenant_id', '=', p.tenantId).where('id', 'in', rows.map(row => row.id)).execute() : [];
    const nameById = new Map(names.map(row => [row.id, row.name]));
    return { typeId: head.type_id, modelId: id, currentVersion: head.current_version, sourceVersions, assetCount: rows.length,
      sources: sourceVersions.map(version => ({ version, resolution: source.get(version)!, resolutionHash: typeHash(source.get(version)!) })),
      assets: rows.map(row => ({ assetId: row.id, name: nameById.get(row.id) ?? row.id, assetVersion: row.version,
        modelVersion: row.model_version, ownerId: row.owner_id ?? null, state: row.type_state ?? null })) };
  });
}
export async function previewTypeMigration(tx: Tx, p: Principal, id: string, expected: number, input: TypeMigrationRequest): Promise<TypeMigrationPreview> {
  return bounded(tx, async () => {
    await persistence.authorize(tx, p, TYPE_MIGRATION_WRITE); await persistence.lockTenantModels(tx, p);
    return (await prepare(tx, p, id, expected, input)).preview;
  });
}
const receiptAssets = (preview: TypeMigrationPreview): TypeMigrationAssetReceipt[] => preview.assets.map(({ sourceIssues: _issues, ...asset }) => asset);
const baseAssets = (assets: TypeMigrationAssetReceipt[]) => assets.map(({ assetId, fromAssetVersion, toAssetVersion, fromModelVersion, toModelVersion, beforeHash, afterHash }) =>
  ({ assetId, fromAssetVersion, toAssetVersion, fromModelVersion, toModelVersion, beforeHash, afterHash }));

export async function executeTypeMigration(tx: Tx, p: Principal, correlationId: string, id: string, expected: number,
  input: TypeMigrationExecutionRequest, hooks: ModelHooks) {
  return bounded(tx, async () => {
    await persistence.authorize(tx, p, TYPE_MIGRATION_WRITE);
    if (typeof input.previewDigest !== 'string' || !sha256.test(input.previewDigest)) throw new Problem(428, 'ASSET_TYPE_MIGRATION_PREVIEW_REQUIRED', 'Run a complete type migration preview before execution.');
    await persistence.lockTenantModels(tx, p);
    const prepared = await prepare(tx, p, id, expected, input), { preview, target, plan } = prepared;
    if (preview.previewDigest !== input.previewDigest) throw new Problem(409, 'ASSET_TYPE_MIGRATION_PREVIEW_STALE', 'The type, plan, assets or owner eligibility changed. Run a fresh preview.');
    await types.insertVersion(tx, p, target);
    const changed = await tx.updateTable('governance_models').set({ current_version: target.model.version }).where('tenant_id', '=', p.tenantId)
      .where('id', '=', id).where('current_version', '=', expected).executeTakeFirst();
    if (Number(changed.numUpdatedRows) !== 1) throw new Problem(409, 'VERSION_CONFLICT', 'The type changed. Run a fresh preview.');
    const migrationId = randomUUID(), assets = receiptAssets(preview);
    for (const asset of assets) {
      const updated = await tx.updateTable('assets').set({ model_version: target.model.version, attributes: JSON.stringify(asset.after.attributes),
        owner_id: asset.after.ownerId, type_state: asset.after.state, version: asset.toAssetVersion, updated_at: new Date() })
        .where('tenant_id', '=', p.tenantId).where('id', '=', asset.assetId).where('model_id', '=', id)
        .where('model_version', '=', asset.fromModelVersion).where('version', '=', asset.fromAssetVersion).returningAll().executeTakeFirst();
      if (!updated) throw new Problem(409, 'ASSET_TYPE_MIGRATION_PREVIEW_STALE', 'An affected asset changed. Run a fresh preview.');
      await tx.insertInto('asset_revisions').values({ tenant_id: p.tenantId, asset_id: asset.assetId, version: asset.toAssetVersion,
        snapshot: JSON.stringify(hooks.assetSnapshot(updated)) }).execute();
      await hooks.record(tx, p, 'asset.type_migrated', asset.assetId, asset.toAssetVersion, { migrationId, modelId: id, typeId: preview.typeId,
        before: { modelVersion: asset.fromModelVersion, tupleHash: asset.beforeTupleHash },
        after: { modelVersion: asset.toModelVersion, tupleHash: asset.afterTupleHash }, revision: asset.toAssetVersion }, correlationId);
    }
    await tx.insertInto('governance_model_migrations').values({ tenant_id: p.tenantId, id: migrationId, model_id: id,
      from_version: expected, to_version: target.model.version, plan: JSON.stringify(plan.attributes), plan_hash: typeHash(plan.attributes),
      preview_digest: preview.previewDigest, asset_count: assets.length, assets: JSON.stringify(baseAssets(assets)), executed_by: p.id }).execute();
    await tx.insertInto('asset_type_migrations').values({ tenant_id: p.tenantId, id: migrationId, model_id: id, type_id: preview.typeId,
      from_version: expected, to_version: target.model.version, plan: JSON.stringify(plan), plan_hash: preview.planHash,
      preview_digest: preview.previewDigest, definition_hash: preview.definitionHash, resolution_hash: preview.resolutionHash,
      source_resolutions: JSON.stringify(preview.sourceResolutions), asset_count: assets.length, assets: JSON.stringify(assets),
      executed_by: p.id }).execute();
    await hooks.record(tx, p, 'model.type_migrated', id, target.model.version, { migrationId, typeId: preview.typeId, previousVersion: expected,
      definitionHash: preview.definitionHash, resolutionHash: preview.resolutionHash, planHash: preview.planHash, previewDigest: preview.previewDigest }, correlationId);
    // Force deferred companion/revision checks before returning to idempotency serialization.
    await sql`set constraints all immediate`.execute(tx);
    return { ...(await getAssetType(tx, p, id)), ...(await getTypeMigrationReceipt(tx, p, id, migrationId, true)) };
  });
}

function tupleFromSnapshot(snapshot: Row): TypeMigrationTuple {
  return { modelId: snapshot.modelId, modelVersion: snapshot.modelVersion, attributes: snapshot.attributes, ownerId: snapshot.ownerId, state: snapshot.typeState };
}
export async function getTypeMigrationReceipt(tx: Tx, p: Principal, modelId: string, migrationId: string, forReplay = false): Promise<{ receipt: TypeMigrationReceipt }> {
  return bounded(tx, async () => {
    const actions = forReplay ? TYPE_MIGRATION_WRITE : readPermissions;
    await persistence.authorize(tx, p, actions);
    const head = await types.typeHead(tx, p, modelId);
    const row = await tx.selectFrom('asset_type_migrations').selectAll().where('tenant_id', '=', p.tenantId).where('id', '=', migrationId).where('model_id', '=', modelId).executeTakeFirst();
    if (!row) throw new Problem(404, 'ASSET_TYPE_MIGRATION_NOT_FOUND', 'The complete type migration receipt is unavailable.');
    if (!Array.isArray(row.assets) || row.assets.length !== row.asset_count || row.asset_count > 1000 || row.type_id !== head.type_id) throw storage();
    if (Buffer.byteLength(JSON.stringify(row)) > 2_097_152) throw limit(); budget(row);
    const ids = row.assets.map((asset: Row) => asset.assetId);
    const currentAssets = ids.length ? await tx.selectFrom('assets').select(['tenant_id', 'id', 'visibility', 'allowed_identities'])
      .where('tenant_id', '=', p.tenantId).where('id', 'in', ids).execute() : [];
    if (currentAssets.length !== ids.length || currentAssets.some(asset => !canView(p, { tenantId: asset.tenant_id, visibility: asset.visibility, allowedIdentities: asset.allowed_identities }))) throw unavailable();
    const parsed = parseAssetTypeMigrationPlan(row.plan);
    const base = await tx.selectFrom('governance_model_migrations').selectAll().where('tenant_id', '=', p.tenantId).where('id', '=', migrationId).executeTakeFirst();
    if (!parsed.ok || !base || typeHash(parsed.value) !== row.plan_hash || parsed.value.typeId !== row.type_id ||
      parsed.value.attributes.modelId !== modelId || parsed.value.attributes.targetVersion !== row.to_version ||
      base.from_version !== row.from_version || base.to_version !== row.to_version || base.model_id !== modelId ||
      typeHash(base.plan) !== typeHash(parsed.value.attributes) || base.plan_hash !== typeHash(parsed.value.attributes) ||
      base.preview_digest !== row.preview_digest || !sha256.test(row.preview_digest) || base.asset_count !== row.asset_count ||
      base.executed_by !== row.executed_by || new Date(base.executed_at).getTime() !== new Date(row.executed_at).getTime() ||
      typeHash(base.assets) !== typeHash(baseAssets(row.assets))) throw storage();
    const target = await assetTypePolicy(tx, p, modelId, row.to_version);
    if (!target || typeHash(target) !== row.resolution_hash || typeHash(target.definition) !== row.definition_hash) throw storage();
    const versions = [...new Set<number>([row.from_version, ...parsed.value.attributes.sourceVersions])].sort((a, b) => a - b);
    const sources = await policies(tx, p, modelId, versions);
    if (typeHash(row.source_resolutions) !== typeHash(versions.map(version => ({ version, resolutionHash: typeHash(sources.get(version)!) })))) throw storage();
    const normalized = await tx.selectFrom('asset_type_migration_assets').select(tx.fn.countAll().as('count')).where('tenant_id', '=', p.tenantId).where('migration_id', '=', migrationId).executeTakeFirstOrThrow();
    if (Number(normalized.count) !== row.asset_count) throw storage();
    let previous = '';
    for (const asset of row.assets as TypeMigrationAssetReceipt[]) {
      if (asset.assetId <= previous || asset.fromAssetVersion + 1 !== asset.toAssetVersion || asset.toModelVersion !== row.to_version ||
        !parsed.value.attributes.sourceVersions.includes(asset.fromModelVersion) || typeHash(asset.before) !== asset.beforeTupleHash ||
        typeHash(asset.after) !== asset.afterTupleHash || typeHash(asset.before.attributes) !== asset.beforeHash || typeHash(asset.after.attributes) !== asset.afterHash ||
        asset.before.modelId !== modelId || asset.after.modelId !== modelId || asset.before.modelVersion !== asset.fromModelVersion || asset.after.modelVersion !== asset.toModelVersion) throw storage();
      previous = asset.assetId;
      const revisions = await tx.selectFrom('asset_revisions').select(['version', 'snapshot']).where('tenant_id', '=', p.tenantId).where('asset_id', '=', asset.assetId)
        .where('version', 'in', [asset.fromAssetVersion, asset.toAssetVersion]).orderBy('version').execute();
      if (revisions.length !== 2 || typeHash(tupleFromSnapshot(revisions[0].snapshot)) !== asset.beforeTupleHash || typeHash(tupleFromSnapshot(revisions[1].snapshot)) !== asset.afterTupleHash) throw storage();
    }
    await persistence.authorize(tx, p, actions);
    return { receipt: { id: row.id, typeId: row.type_id, modelId, fromVersion: row.from_version, toVersion: row.to_version,
      plan: parsed.value, planHash: row.plan_hash, previewDigest: row.preview_digest, definitionHash: row.definition_hash, resolutionHash: row.resolution_hash,
      sourceResolutions: row.source_resolutions, assetCount: row.asset_count, assets: row.assets, executedBy: row.executed_by, executedAt: new Date(row.executed_at).toISOString() } };
  });
}
