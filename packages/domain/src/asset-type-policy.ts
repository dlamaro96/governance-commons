// SPDX-License-Identifier: Apache-2.0
import { createHash } from 'node:crypto';
import type { Tx } from '../../db/src/index.ts';
import { Problem, type Principal } from '../../authz/src/index.ts';
import { parseModelDefinition } from './model.ts';
import { parseAssetTypeDefinition, resolveAssetType, type ResolvedAssetType } from './asset-type.ts';

function canonical(value: any): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
export const typeHash = (value: unknown): string => createHash('sha256').update(canonical(value)).digest('hex');

/** Checks the immutable envelope; callers verify its exact resolution against pinned parents. */
export function storedAssetType(row: any): ResolvedAssetType {
  const fail = () => new Problem(500, 'ASSET_TYPE_STORAGE_INVALID', 'The stored asset type could not be verified.');
  const parsed = parseAssetTypeDefinition(row.definition), resolved = row.resolved;
  if (!parsed.ok || !resolved || typeHash(parsed.value) !== row.definition_hash || typeHash(resolved) !== row.resolution_hash ||
      typeHash(resolved.definition) !== row.definition_hash || parsed.value.id !== row.model_id || parsed.value.version !== row.version ||
      !Array.isArray(resolved.dependencies) || resolved.dependencies.length > 64) throw fail();
  const model = parseModelDefinition(resolved.model);
  const constraints = parseAssetTypeDefinition({ ...parsed.value, parents: [], attributes: {}, overrideAttributes: [],
    requiredOwner: resolved.requiredOwner, lifecycle: resolved.lifecycle });
  if (!model.ok || !constraints.ok || !constraints.value.lifecycle || model.value.id !== row.model_id || model.value.version !== row.version ||
      parsed.value.requiredOwner && !resolved.requiredOwner || parsed.value.lifecycle !== null && typeHash(parsed.value.lifecycle) !== typeHash(resolved.lifecycle)) throw fail();
  const seen = new Set<string>();
  for (const pin of resolved.dependencies) {
    if (!pin || Object.keys(pin).sort().join('|') !== 'id|version' || typeof pin.id !== 'string' || !/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(pin.id) ||
        !Number.isInteger(pin.version) || pin.version < 1 || pin.version > 2_147_483_647 || seen.has(pin.id) || pin.id === parsed.value.id) throw fail();
    seen.add(pin.id);
  }
  if (parsed.value.parents.some(pin => !resolved.dependencies.some((item: any) => item.id === pin.id && item.version === pin.version))) throw fail();
  return resolved as ResolvedAssetType;
}

export async function assetTypePolicy(tx: Tx, principal: Principal, modelId: string | null, version: number | null): Promise<ResolvedAssetType | null> {
  if (modelId === null || version === null) return null;
  const model = await tx.selectFrom('governance_models').select('type_id').where('tenant_id', '=', principal.tenantId).where('id', '=', modelId).executeTakeFirst();
  if (!model?.type_id) return null;
  const row = await tx.selectFrom('asset_type_versions').selectAll().where('tenant_id', '=', principal.tenantId)
    .where('model_id', '=', modelId).where('version', '=', version).executeTakeFirst();
  if (!row) throw new Problem(500, 'ASSET_TYPE_STORAGE_INVALID', 'The stored asset type could not be verified.');
  const result = storedAssetType(row), definitions = [];
  let bytes = Buffer.byteLength(JSON.stringify(row.definition));
  for (const pin of result.dependencies) {
    const parent = await tx.selectFrom('asset_type_versions').select(['definition', 'definition_hash']).where('tenant_id', '=', principal.tenantId)
      .where('model_id', '=', pin.id).where('version', '=', pin.version).executeTakeFirst();
    if (!parent || typeHash(parent.definition) !== parent.definition_hash) throw new Problem(500, 'ASSET_TYPE_STORAGE_INVALID', 'A pinned parent type could not be verified.');
    bytes += Buffer.byteLength(JSON.stringify(parent.definition));
    if (bytes > 524_288) throw new Problem(422, 'ASSET_TYPE_LIMIT', 'The complete type exceeds the supported materialization profile.');
    definitions.push(parent.definition);
  }
  const recomputed = resolveAssetType(result.definition, definitions);
  if (!recomputed.ok || typeHash(recomputed.value) !== row.resolution_hash) throw new Problem(500, 'ASSET_TYPE_STORAGE_INVALID', 'The stored type resolution could not be verified.');
  return recomputed.value;
}

export async function validateTypeOwner(tx: Tx, principal: Principal, required: boolean, ownerId: string | null): Promise<void> {
  if (!required) return;
  const owner = ownerId ? await tx.selectFrom('memberships').innerJoin('identities', 'identities.id', 'memberships.identity_id')
    .select('memberships.identity_id').where('memberships.tenant_id', '=', principal.tenantId)
    .where('memberships.identity_id', '=', ownerId).where('memberships.active', '=', true).where('identities.active', '=', true).executeTakeFirst() : null;
  if (!owner) throw new Problem(422, 'ASSET_TYPE_OWNER_REQUIRED', 'This asset type requires an active owner in this organization.');
}

export async function validatePinnedType(tx: Tx, principal: Principal, asset: any, ownerId: string | null = asset.owner_id): Promise<void> {
  const policy = await assetTypePolicy(tx, principal, asset.model_id, asset.model_version);
  if (!policy) return;
  await validateTypeOwner(tx, principal, policy.requiredOwner, ownerId);
  if (!policy.lifecycle.states.includes(asset.type_state)) throw new Problem(422, 'ASSET_TYPE_STATE_INVALID', 'The asset state is not valid for its pinned lifecycle.');
}
