// SPDX-License-Identifier: Apache-2.0
import { randomUUID } from 'node:crypto';
import { sql, type Tx } from '../../db/src/index.ts';
import { Problem, type Principal } from '../../authz/src/index.ts';
import { MODEL_LIMITS, previewModelUpgrade, validateAttributes, type ValidationIssue } from './model.ts';
import { parseAssetTypeDefinition, resolveAssetType, type AssetTypeDefinition, type ResolvedAssetType, type TypePin } from './asset-type.ts';
import { assetTypePolicy, storedAssetType, typeHash, validatePinnedType } from './asset-type-policy.ts';
import { MODEL_SERVICE_LIMITS, modelPersistence as persistence, type ModelHooks, type ModelListQuery } from './model-service.ts';
import { signedCursor } from './cursor.ts';

const read = ['models:read'], write = ['models:read', 'models:write'], previewPermissions = [...write, 'catalog:read'];
const limit = () => new Problem(422, 'ASSET_TYPE_LIMIT', 'The complete asset type exceeds this bounded development profile.');
const invalid = (issues?: readonly ValidationIssue[]) => new Problem(422, 'ASSET_TYPE_INVALID', 'Correct the authored asset type definition.', issues);
const key = (pin: TypePin) => `${pin.id}@${pin.version}`;
function definition(input: unknown): AssetTypeDefinition {
  const parsed = parseAssetTypeDefinition(input);
  if (!parsed.ok) throw invalid(parsed.issues);
  if (parsed.value.version > MODEL_SERVICE_LIMITS.databaseVersion) throw limit();
  return parsed.value;
}
function view(row: any, head: any) {
  const resolved = storedAssetType(row);
  return { id: row.model_id, typeId: head.type_id, version: row.version, currentVersion: head.current_version,
    definition: resolved.definition, resolved: { model: resolved.model, requiredOwner: resolved.requiredOwner,
      lifecycle: resolved.lifecycle, dependencies: resolved.dependencies },
    definitionHash: row.definition_hash, resolutionHash: row.resolution_hash,
    createdAt: new Date(row.created_at).toISOString(), createdBy: row.created_by };
}
async function typeHead(tx: Tx, p: Principal, id: string, lock = false) {
  let head;
  try { head = await persistence.head(tx, p, id, lock); }
  catch (error) {
    if (error instanceof Problem && error.code === 'MODEL_NOT_FOUND') throw new Problem(404, 'ASSET_TYPE_NOT_FOUND', 'Asset type is unavailable.');
    throw error;
  }
  if (!head.type_id) throw new Problem(404, 'ASSET_TYPE_NOT_FOUND', 'Asset type is unavailable.');
  return head;
}
async function typeRow(tx: Tx, p: Principal, id: string, version: number) {
  persistence.checkVersion(version, 'MODEL_VERSION_INVALID');
  const row = await tx.selectFrom('asset_type_versions').selectAll().where('tenant_id', '=', p.tenantId)
    .where('model_id', '=', id).where('version', '=', version).executeTakeFirst();
  if (!row) throw new Problem(404, 'ASSET_TYPE_NOT_FOUND', 'Asset type version is unavailable.');
  return row;
}
async function resolved(tx: Tx, p: Principal, input: unknown): Promise<ResolvedAssetType> {
  const proposed = definition(input), definitions: AssetTypeDefinition[] = [], seen = new Set<string>();
  const queue = [...proposed.parents];
  let bytes = Buffer.byteLength(JSON.stringify(proposed)), nodes = 0;
  while (queue.length) {
    const pin = queue.shift()!;
    if (pin.version > MODEL_SERVICE_LIMITS.databaseVersion) throw limit();
    if (seen.has(key(pin))) continue;
    if (seen.size >= 64) throw limit();
    seen.add(key(pin));
    const row = await tx.selectFrom('asset_type_versions').select(['definition', 'definition_hash'])
      .where('tenant_id', '=', p.tenantId).where('model_id', '=', pin.id).where('version', '=', pin.version).executeTakeFirst();
    if (!row) throw new Problem(422, 'ASSET_TYPE_PARENT_UNAVAILABLE', 'An exact parent asset-type version is unavailable.');
    bytes += Buffer.byteLength(JSON.stringify(row.definition));
    if (bytes > MODEL_SERVICE_LIMITS.previewBytes) throw limit();
    const parsed = definition(row.definition);
    if (parsed.id !== pin.id || parsed.version !== pin.version || typeHash(parsed) !== row.definition_hash) throw new Problem(500, 'ASSET_TYPE_STORAGE_INVALID', 'The stored parent type could not be verified.');
    const stack: unknown[] = [parsed];
    while (stack.length) { const value = stack.pop(); if (++nodes > 100_000) throw limit(); if (value && typeof value === 'object') stack.push(...Object.values(value)); }
    definitions.push(parsed); queue.push(...parsed.parents);
  }
  const result = resolveAssetType(proposed, definitions);
  if (!result.ok) throw invalid(result.issues);
  if (Buffer.byteLength(JSON.stringify(result.value)) > MODEL_SERVICE_LIMITS.previewBytes) throw limit();
  return result.value;
}
async function insertVersion(tx: Tx, p: Principal, result: ResolvedAssetType) {
  const model = result.model;
  await tx.insertInto('governance_model_versions').values({ tenant_id: p.tenantId, model_id: model.id, version: model.version,
    definition: JSON.stringify(model), definition_hash: typeHash(model), created_by: p.id }).execute();
  return tx.insertInto('asset_type_versions').values({ tenant_id: p.tenantId, model_id: model.id, version: model.version,
    definition: JSON.stringify(result.definition), definition_hash: typeHash(result.definition), resolved: JSON.stringify(result),
    resolution_hash: typeHash(result), created_by: p.id }).returningAll().executeTakeFirstOrThrow();
}

export async function listAssetTypes(tx: Tx, p: Principal, query: ModelListQuery = {}) {
  await persistence.authorize(tx, p, read);
  const bad = () => new Problem(400, 'ASSET_TYPE_PAGE_INVALID', 'Provide a valid asset-type search and page cursor.');
  if (!query || typeof query !== 'object' || Array.isArray(query) || Object.keys(query).some(k => !['limit', 'cursor', 'q'].includes(k))) throw bad();
  const pageSize = query.limit ?? 50, search = query.q ?? '';
  if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > 100 || typeof search !== 'string' || search.length > 64 || /[\u0000-\u001f\u007f]/.test(search)) throw bad();
  const codec = signedCursor(process.env.SESSION_KEY, 'asset-type-inventory-v1'); let after: string | undefined;
  if (query.cursor !== undefined) {
    try {
      const cursor = codec.decode(query.cursor) as any;
      if (!cursor || Object.keys(cursor).sort().join('|') !== 'actorId|after|limit|q|sort|tenantId|v' || cursor.v !== 1 ||
        cursor.actorId !== p.id || cursor.tenantId !== p.tenantId || cursor.limit !== pageSize || cursor.q !== search || cursor.sort !== 'id:asc' ||
        typeof cursor.after !== 'string' || !/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(cursor.after)) throw bad();
      after = cursor.after;
    } catch { throw bad(); }
  }
  let selection = tx.selectFrom('governance_models').selectAll().where('tenant_id', '=', p.tenantId).where('type_id', 'is not', null);
  if (search) selection = selection.where('id', 'ilike', `%${search.replace(/[\\%_]/g, '\\$&')}%`);
  if (after) selection = selection.where('id', '>', after);
  const rows = await selection.orderBy('id').limit(pageSize + 1).execute(), page = rows.slice(0, pageSize);
  return { items: page.map(row => ({ id: row.id, currentVersion: row.current_version, typeId: row.type_id,
    createdBy: row.created_by, createdAt: new Date(row.created_at).toISOString() })),
    nextCursor: rows.length > pageSize ? codec.encode({ v: 1, tenantId: p.tenantId, actorId: p.id, q: search, limit: pageSize, sort: 'id:asc', after: page.at(-1)!.id }) : null };
}
export async function getAssetType(tx: Tx, p: Principal, id: string, version?: number) {
  await persistence.authorize(tx, p, read);
  const head = await typeHead(tx, p, id);
  const row = await typeRow(tx, p, id, version ?? head.current_version);
  await assetTypePolicy(tx, p, id, version ?? head.current_version);
  return { type: view(row, head) };
}
export async function createAssetType(tx: Tx, p: Principal, correlationId: string, input: unknown, hooks: ModelHooks) {
  await persistence.authorize(tx, p, write);
  const parsed = definition(input);
  if (parsed.version !== 1) throw new Problem(422, 'MODEL_INITIAL_VERSION', 'A new asset type must begin at version1.');
  await persistence.lockTenantModels(tx, p); await persistence.authorize(tx, p, write);
  if (await tx.selectFrom('governance_models').select('id').where('tenant_id', '=', p.tenantId).where('id', '=', parsed.id).executeTakeFirst()) {
    throw new Problem(409, 'MODEL_EXISTS', 'A model or asset type with this identifier already exists.');
  }
  const result = await resolved(tx, p, parsed);
  const head = await tx.insertInto('governance_models').values({ tenant_id: p.tenantId, id: parsed.id, type_id: randomUUID(), current_version: 1, created_by: p.id }).returningAll().executeTakeFirstOrThrow();
  const row = await insertVersion(tx, p, result);
  await hooks.record(tx, p, 'model.type_created', parsed.id, 1, { typeId: head.type_id, definitionHash: row.definition_hash, resolutionHash: row.resolution_hash }, correlationId);
  return { type: view(row, head) };
}

async function prepare(tx: Tx, p: Principal, id: string, expectedVersion: number, input: unknown) {
  const head = await typeHead(tx, p, id, true); persistence.assertHead(head, expectedVersion);
  const proposed = await resolved(tx, p, input);
  const current = storedAssetType(await typeRow(tx, p, id, head.current_version));
  const schema = previewModelUpgrade(current.model, proposed.model, []);
  if (!schema.ok) throw invalid(schema.issues);
  const cohort = await persistence.modelCohort(tx, p, id);
  await persistence.authorize(tx, p, previewPermissions);
  const pins = [...new Set<number>(cohort.map(row => row.model_version))];
  const historical = new Map<number, ResolvedAssetType>();
  if (pins.length) {
    const size = await sql<{ bytes: string }>`select coalesce(sum(octet_length(resolved::text)),0)::text as bytes from asset_type_versions where tenant_id=${p.tenantId}::uuid and model_id=${id} and version=any(${pins}::integer[])`.execute(tx);
    if (Number(size.rows[0].bytes) > MODEL_SERVICE_LIMITS.previewBytes) throw limit();
    const rows = await tx.selectFrom('asset_type_versions').selectAll().where('tenant_id', '=', p.tenantId).where('model_id', '=', id).where('version', 'in', pins).execute();
    for (const row of rows) historical.set(row.version, storedAssetType(row));
    if (historical.size !== pins.length) throw new Problem(500, 'ASSET_TYPE_STORAGE_INVALID', 'The historical asset type could not be verified.');
  }
  const ownerIds = [...new Set<string>(cohort.map(row => row.owner_id).filter(Boolean))];
  const activeOwners = new Set<string>(ownerIds.length ? (await tx.selectFrom('memberships').innerJoin('identities', 'identities.id', 'memberships.identity_id')
    .select('memberships.identity_id').where('memberships.tenant_id', '=', p.tenantId).where('memberships.identity_id', 'in', ownerIds)
    .where('memberships.active', '=', true).where('identities.active', '=', true).execute()).map(row => row.identity_id) : []);
  function issues(policy: ResolvedAssetType, asset: any): readonly ValidationIssue[] {
    const checked = validateAttributes(policy.model, asset.attributes); const found: ValidationIssue[] = checked.ok ? [] : [...checked.issues];
    if (policy.requiredOwner && !activeOwners.has(asset.owner_id)) found.push({ code: 'required', path: '/ownerId', message: 'An active organization owner is required.' });
    if (!policy.lifecycle.states.includes(asset.type_state)) found.push({ code: 'enum', path: '/state', message: 'The asset state is not in this lifecycle.' });
    return found;
  }
  let count = 0;
  const assets = cohort.map(asset => {
    const currentIssues = issues(historical.get(asset.model_version)!, asset), proposedIssues = issues(proposed, asset);
    count += currentIssues.length + proposedIssues.length; if (count > MODEL_LIMITS.previewIssues) throw limit();
    return { assetId: asset.id, currentIssues, proposedIssues };
  });
  const compatible = assets.every(asset => !asset.currentIssues.length && !asset.proposedIssues.length);
  const changes = [...schema.value.changes];
  if (current.requiredOwner !== proposed.requiredOwner) changes.push({ code: 'constraints_changed', path: '/requiredOwner', requiresMigration: !compatible });
  if (typeHash(current.lifecycle) !== typeHash(proposed.lifecycle)) changes.push({ code: 'constraints_changed', path: '/lifecycle', requiresMigration: !compatible });
  const policyChanges = assetTypePolicyChanges(current, proposed);
  const previewDigest = typeHash({ tenantId: p.tenantId, id, expectedVersion, resolution: proposed,
    assets: cohort.map(asset => ({ id: asset.id, version: asset.version, modelVersion: asset.model_version,
      attributes: asset.attributes, ownerId: asset.owner_id, ownerActive: activeOwners.has(asset.owner_id), state: asset.type_state })) });
  return { head, proposed, preview: { typeId: head.type_id, modelId: id, currentVersion: expectedVersion, proposedVersion: proposed.definition.version,
    coverage: 'complete-tenant-model-bindings' as const, assetCount: assets.length, changes, assets,
    requiresExplicitMigration: schema.value.requiresExplicitMigration || !compatible, compatibleWithProvidedAssets: compatible, pinsPreserved: true as const, previewDigest,
    target: proposed, policyChanges } };
}

export function assetTypePolicyChanges(head: ResolvedAssetType, target: ResolvedAssetType) {
  const changes: ('parents_changed' | 'required_owner_changed' | 'lifecycle_changed')[] = [];
  const pins = (value: ResolvedAssetType) => [...value.definition.parents].sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  if (typeHash(pins(head)) !== typeHash(pins(target))) changes.push('parents_changed');
  if (head.requiredOwner !== target.requiredOwner) changes.push('required_owner_changed');
  if (typeHash(head.lifecycle) !== typeHash(target.lifecycle)) changes.push('lifecycle_changed');
  return changes.sort();
}
/** Internal persistence shared by publication and complete type migration; not an authorization boundary. */
export const assetTypePersistence = { typeHead, typeRow, resolved, insertVersion, view };
export async function previewAssetType(tx: Tx, p: Principal, id: string, expectedVersion: number, input: unknown) {
  await persistence.authorize(tx, p, previewPermissions); await persistence.lockTenantModels(tx, p);
  return (await prepare(tx, p, id, expectedVersion, input)).preview;
}
export async function publishAssetType(tx: Tx, p: Principal, correlationId: string, id: string, expectedVersion: number,
  input: unknown, previewDigest: string, hooks: ModelHooks) {
  await persistence.authorize(tx, p, previewPermissions);
  if (typeof previewDigest !== 'string' || !/^[a-f0-9]{64}$/.test(previewDigest)) throw new Problem(428, 'MODEL_PREVIEW_REQUIRED', 'Run a complete type preview before publication.');
  await persistence.lockTenantModels(tx, p);
  const prepared = await prepare(tx, p, id, expectedVersion, input);
  if (prepared.preview.previewDigest !== previewDigest) throw new Problem(409, 'ASSET_TYPE_PREVIEW_STALE', 'The type or asset scope changed. Run a fresh preview.');
  if (prepared.preview.requiresExplicitMigration) throw new Problem(422, 'ASSET_TYPE_MIGRATION_REQUIRED', 'This change requires an explicit migration of the complete authored type. No version was published.');
  const row = await insertVersion(tx, p, prepared.proposed);
  await tx.updateTable('governance_models').set({ current_version: row.version }).where('tenant_id', '=', p.tenantId).where('id', '=', id).where('current_version', '=', expectedVersion).execute();
  await hooks.record(tx, p, 'model.type_published', id, row.version, { typeId: prepared.head.type_id, previousVersion: expectedVersion,
    definitionHash: row.definition_hash, resolutionHash: row.resolution_hash, pinsPreserved: true }, correlationId);
  return { type: view(row, { ...prepared.head, current_version: row.version }) };
}

export async function getAssetTypeState(tx: Tx, p: Principal, assetId: string) {
  await persistence.authorize(tx, p, ['catalog:read', 'models:read']);
  const asset = await persistence.assetRow(tx, p, assetId);
  const policy = await assetTypePolicy(tx, p, asset.model_id, asset.model_version);
  return { assetId, assetVersion: asset.version, modelId: asset.model_id, modelVersion: asset.model_version,
    state: asset.type_state ?? null, requiredOwner: policy?.requiredOwner ?? false, lifecycle: policy?.lifecycle ?? null };
}
export async function transitionAssetTypeState(tx: Tx, p: Principal, correlationId: string, assetId: string,
  expectedVersion: number, state: string, hooks: ModelHooks) {
  const permissions = ['catalog:read', 'catalog:write', 'models:read'];
  await persistence.authorize(tx, p, permissions); persistence.checkVersion(expectedVersion);
  if (expectedVersion === MODEL_SERVICE_LIMITS.databaseVersion) throw new Problem(422, 'ASSET_VERSION_LIMIT', 'The supported asset version range has been exhausted.');
  if (typeof state !== 'string' || !/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(state)) throw new Problem(422, 'ASSET_TYPE_STATE_INVALID', 'Choose a supported lifecycle state.');
  await persistence.lockTenantModels(tx, p);
  const asset = await persistence.assetRow(tx, p, assetId, true);
  await persistence.authorize(tx, p, permissions);
  if (asset.version !== expectedVersion) throw new Problem(409, 'VERSION_CONFLICT', 'The asset changed. Load its current version.');
  const policy = await assetTypePolicy(tx, p, asset.model_id, asset.model_version);
  if (!policy || !policy.lifecycle.transitions.some(step => step.from === asset.type_state && step.to === state)) {
    throw new Problem(422, 'ASSET_TYPE_TRANSITION_INVALID', 'This transition is not allowed by the pinned lifecycle.');
  }
  await validatePinnedType(tx, p, asset);
  const updated = await tx.updateTable('assets').set({ type_state: state, version: expectedVersion + 1, updated_at: new Date() })
    .where('tenant_id', '=', p.tenantId).where('id', '=', assetId).where('version', '=', expectedVersion).returningAll().executeTakeFirstOrThrow();
  await tx.insertInto('asset_revisions').values({ tenant_id: p.tenantId, asset_id: assetId, version: updated.version, snapshot: JSON.stringify(hooks.assetSnapshot(updated)) }).execute();
  await hooks.record(tx, p, 'asset.type_transitioned', assetId, updated.version,
    { modelId: asset.model_id, modelVersion: asset.model_version, before: asset.type_state, after: state }, correlationId);
  return getAssetTypeState(tx, p, assetId);
}
