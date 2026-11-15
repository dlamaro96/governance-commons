// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Problem } from '../../packages/authz/src/index.ts';
import { resolveAssetType, type AssetTypeDefinition } from '../../packages/domain/src/asset-type.ts';
import { storedAssetType, typeHash } from '../../packages/domain/src/asset-type-policy.ts';

const parent: AssetTypeDefinition = { formatVersion: 1, id: 'policy_parent', version: 1, parents: [], attributes: {},
  overrideAttributes: [], requiredOwner: true, lifecycle: { initial: 'draft', states: ['draft', 'active'], transitions: [{ from: 'draft', to: 'active' }] } };
function resolved(definition: AssetTypeDefinition, dependencies: AssetTypeDefinition[] = []) {
  const result = resolveAssetType(definition, dependencies);
  assert.equal(result.ok, true);
  if (!result.ok) throw Error('Synthetic policy fixture is invalid');
  return structuredClone(result.value);
}
function row(value: ReturnType<typeof resolved>) {
  return { model_id: value.definition.id, version: value.definition.version, definition: value.definition,
    definition_hash: typeHash(value.definition), resolved: value, resolution_hash: typeHash(value) };
}
const invalid = (error: unknown) => error instanceof Problem && error.code === 'ASSET_TYPE_STORAGE_INVALID';

test('stored type envelopes reject hash-consistent local ownership and lifecycle weakening', () => {
  const valid = resolved(parent);
  assert.deepEqual(storedAssetType(row(valid)), valid);
  const weakened = { ...valid, requiredOwner: false };
  assert.throws(() => storedAssetType(row(weakened)), invalid);
  const changed = { ...valid, lifecycle: { ...valid.lifecycle, initial: 'active' } };
  assert.throws(() => storedAssetType(row(changed)), invalid);
});

test('stored type envelopes require exact immediate parent membership and unique logical dependencies', () => {
  const child = resolved({ ...parent, id: 'policy_child', parents: [{ id: parent.id, version: 1 }], requiredOwner: false, lifecycle: null }, [parent]);
  assert.deepEqual(storedAssetType(row(child)), child);
  for (const pins of [[], [{ id: parent.id, version: 2 }], [{ id: parent.id, version: 1 }, { id: parent.id, version: 2 }]]) {
    const changed = { ...child, dependencies: pins };
    assert.throws(() => storedAssetType(row(changed)), invalid);
  }
});
