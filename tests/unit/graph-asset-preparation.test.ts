// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { projectGraphAssetChanges } from '../../packages/domain/src/graph-asset-preparation.ts';
import { resolveAssetType, type AssetTypeDefinition } from '../../packages/domain/src/asset-type.ts';
import type { GraphAssetPreparationInput, GraphAssetPolicyEvidence } from '../../packages/domain/src/relation-migration-contracts.ts';
import type { ValidationResult } from '../../packages/domain/src/model.ts';

const asset = 'aaaaaaaa-0000-4000-8000-000000000001', other = 'bbbbbbbb-0000-4000-8000-000000000002';
const typeId = '11111111-1111-4111-8111-111111111111';
const owner = 'cccccccc-0000-4000-8000-000000000001', replacement = 'dddddddd-0000-4000-8000-000000000002';
function canonical(value: any): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}
const hash = (value: unknown) => createHash('sha256').update(canonical(value)).digest('hex');
function ok<T>(result: ValidationResult<T>): T { assert.ok(result.ok, result.ok ? '' : JSON.stringify(result.issues)); return result.value; }
function bad(input: GraphAssetPreparationInput, code?: string) {
  const result = projectGraphAssetChanges(input); assert.equal(result.ok, false);
  if (!result.ok && code) assert.ok(result.issues.some(issue => issue.code === code), JSON.stringify(result.issues));
  return result;
}
function policy(version: number, requiredOwner = false, overrides: Partial<AssetTypeDefinition> = {}): GraphAssetPolicyEvidence {
  const resolution = ok(resolveAssetType({ formatVersion: 1, id: 'Invoice', version, parents: [], overrideAttributes: [],
    attributes: { amount: { type: 'decimal', precision: 30, scale: 8 } }, requiredOwner,
    lifecycle: { initial: 'draft', states: ['draft', 'active', 'retired'], transitions: [{ from: 'draft', to: 'active' }] }, ...overrides }, []));
  return { kind: 'authored', typeId, resolution, definitionHash: hash(resolution.definition), resolutionHash: hash(resolution), ancestorTypes: [] };
}
function input(): GraphAssetPreparationInput {
  return { assetChanges: [{ kind: 'assign', assetId: asset, expectedVersion: 4, modelId: 'Invoice', modelVersion: 1,
    attributes: { amount: '9999999999999999999999.00000001' }, ownerId: owner }], typeMigrations: [],
    before: [{ assetId: asset, assetVersion: 4, tuple: { modelId: null, modelVersion: null, attributes: {}, ownerId: owner, state: null }, policy: null }],
    policies: [policy(1)], modelHeads: [{ modelId: 'Invoice', version: 2 }], activeOwnerIds: new Set([owner, replacement]) };
}
function transition(requiredOwner = false): GraphAssetPreparationInput {
  const result = input(); result.assetChanges = [{ kind: 'transition', assetId: asset, expectedVersion: 4, state: 'active' }];
  result.before[0]!.tuple = { modelId: 'Invoice', modelVersion: 1, attributes: { amount: '12.5' }, ownerId: owner, state: 'draft' };
  result.before[0]!.policy = { modelId: 'Invoice', modelVersion: 1 }; result.policies = [policy(1, requiredOwner)]; return result;
}
function migration(): GraphAssetPreparationInput {
  const result = transition(true); result.assetChanges = []; result.modelHeads = [{ modelId: 'Invoice', version: 2 }];
  result.policies = [policy(1, true), policy(2, true), policy(3, true)];
  result.activeOwnerIds = new Set([replacement]);
  result.typeMigrations = [{ typeId, modelId: 'Invoice', expectedHeadVersion: 2,
    headPolicy: { modelId: 'Invoice', modelVersion: 2 }, targetPolicy: { modelId: 'Invoice', modelVersion: 3 },
    sourcePolicies: [{ modelId: 'Invoice', modelVersion: 1 }], assetIds: [asset],
    plan: { formatVersion: 1, typeId,
      attributes: { formatVersion: 1, modelId: 'Invoice', targetVersion: 3, sourceVersions: [1], acknowledgedChanges: [], operations: [] },
      owner: { default: 'preserve', overrides: [{ assetId: asset, ownerId: replacement }] },
      lifecycle: { onUnmapped: 'error', mappings: [{ sourceVersion: 1, from: 'draft', to: 'retired' }] }, acknowledgedPolicyChanges: [] } }];
  return result;
}

test('assignment preserves owner, exact historical target pin and decimal bytes in a frozen projection', () => {
  const request = input(), result = ok(projectGraphAssetChanges(request)), change = result.changes[0]!;
  assert.equal(change.after.modelVersion, 1); assert.equal(change.after.ownerId, owner); assert.equal(change.after.state, 'draft');
  assert.equal(change.after.attributes.amount, '9999999999999999999999.00000001');
  assert.equal(change.fromAssetVersion, 4); assert.equal(change.toAssetVersion, 5);
  assert.equal(change.sourcePolicy, null); assert.deepEqual(change.targetPolicy, { modelId: 'Invoice', modelVersion: 1 });
  assert.ok(Object.isFrozen(result)); assert.ok(Object.isFrozen(change.after.attributes)); assert.ok(!Object.isFrozen(request));
});

test('assignment cannot repair an owner or select an unpublished target', () => {
  const changed = input(); (changed.assetChanges[0] as any).ownerId = replacement; bad(changed, 'invalid_definition');
  const unpublished = input(); unpublished.modelHeads = [{ modelId: 'Invoice', version: 1 }];
  unpublished.policies = [policy(2)]; (unpublished.assetChanges[0] as any).modelVersion = 2; bad(unpublished, 'model_version');
});

test('assignment preserves same-model state and optional inactive ownership but enforces required owner', () => {
  const request = transition(); request.assetChanges = input().assetChanges; request.before[0]!.tuple.state = 'retired'; request.activeOwnerIds = new Set();
  assert.equal(ok(projectGraphAssetChanges(request)).changes[0]!.after.state, 'retired');
  request.policies = [policy(1, true)]; bad(request, 'required');
});

test('ordinary transition uses the exact lifecycle and never adds migration owner/state repair', () => {
  const request = transition(); request.activeOwnerIds = new Set();
  assert.equal(ok(projectGraphAssetChanges(request)).changes[0]!.after.ownerId, owner);
  request.assetChanges = [{ kind: 'transition', assetId: asset, expectedVersion: 4, state: 'retired' }]; bad(request, 'enum');
  const required = transition(true); required.activeOwnerIds = new Set(); bad(required, 'required');
});

test('ordinary transition preserves attributes without introducing an additional validation rule', () => {
  const request = transition(); request.before[0]!.tuple.attributes = { preserved: 'legacy observation' };
  assert.deepEqual(ok(projectGraphAssetChanges(request)).changes[0]!.after.attributes, { preserved: 'legacy observation' });
});

test('complete typed migration reuses source owner repair and explicit non-transition state mappings', () => {
  const result = ok(projectGraphAssetChanges(migration())), change = result.changes[0]!;
  assert.equal(change.kind, 'type-migrate'); assert.equal(change.after.modelVersion, 3); assert.equal(change.after.ownerId, replacement);
  assert.equal(change.after.state, 'retired'); assert.equal(change.sourceIssues.length, 1);
  assert.equal(change.sourceIssues[0]!.path, '/source/ownerId'); assert.deepEqual(result.typeMigrations[0]!.assetIds, [asset]);
  assert.equal(change.after.attributes.amount, '12.5');
});

test('complete migration refuses source corruption and an unrepaired inactive required owner', () => {
  const noRepair = migration(); noRepair.typeMigrations[0]!.plan = { ...noRepair.typeMigrations[0]!.plan, owner: { default: 'preserve', overrides: [] } }; bad(noRepair, 'required');
  const corruptState = migration(); corruptState.before[0]!.tuple.state = 'missing'; bad(corruptState, 'enum');
  const corruptValues = migration(); corruptValues.before[0]!.tuple.attributes = { amount: 'not-decimal' }; bad(corruptValues);
});

test('empty typed cohort still supplies exact head/target and real publication metadata', () => {
  const request = migration(); request.before = []; const m = request.typeMigrations[0]!;
  m.assetIds = []; m.sourcePolicies = []; m.plan = { ...m.plan, attributes: { ...m.plan.attributes, sourceVersions: [] },
    owner: { default: 'preserve', overrides: [] }, lifecycle: { onUnmapped: 'preserve', mappings: [] } };
  const result = ok(projectGraphAssetChanges(request)); assert.equal(result.changes.length, 0); assert.equal(result.typeMigrations.length, 1);
});

test('cohort overlap, missing before tuples, extra before tuples and stale revisions fail', () => {
  const overlap = migration(); overlap.assetChanges = transition().assetChanges; overlap.activeOwnerIds = new Set([owner, replacement]); bad(overlap, 'duplicate');
  const omitted = migration(); omitted.typeMigrations[0]!.assetIds = []; bad(omitted, 'invalid_definition');
  const missing = input(); missing.before = []; bad(missing, 'required');
  const extra = input(); extra.before = [...extra.before, { ...extra.before[0]!, assetId: other }]; bad(extra, 'invalid_definition');
  const stale = input(); (stale.assetChanges[0] as any).expectedVersion = 3; bad(stale, 'model_version');
});

test('exact source policy coverage and immutable policy hashes cannot be fabricated', () => {
  const pins = migration(); pins.typeMigrations[0]!.sourcePolicies = [{ modelId: 'Invoice', modelVersion: 2 }]; bad(pins, 'model_version');
  const hashMismatch = input(); hashMismatch.policies[0]!.definitionHash = '0'.repeat(64); bad(hashMismatch, 'invalid_definition');
  const missing = input(); missing.policies = []; bad(missing, 'required');
  const duplicate = input(); duplicate.policies = [duplicate.policies[0]!, duplicate.policies[0]!]; bad(duplicate, 'duplicate');
});

test('attribute-only assignment derives null lifecycle while preserving ownership', () => {
  const request = transition(); request.assetChanges = [{ kind: 'assign', assetId: asset, expectedVersion: 4, modelId: 'Annotation', modelVersion: 1, attributes: { title: 'Catalog' }, ownerId: owner }];
  const model = { formatVersion: 1 as const, id: 'Annotation', version: 1, attributes: { title: { type: 'text' as const } } };
  request.policies = [...request.policies, { kind: 'attributes', model, definitionHash: hash(model) }]; request.modelHeads = [...request.modelHeads, { modelId: 'Annotation', version: 1 }];
  const result = ok(projectGraphAssetChanges(request)); assert.equal(result.changes[0]!.after.state, null); assert.equal(result.changes[0]!.after.ownerId, owner);
});

test('data-only boundary rejects getters, custom prototypes and forged activity without executing them', () => {
  let called = 0; const request = input(); Object.defineProperty(request, 'before', { enumerable: true, get() { called++; return []; } }); bad(request, 'invalid_json');
  const nested = input(); Object.defineProperty(nested.before[0]!.tuple, 'attributes', { enumerable: true, get() { called++; return {}; } }); bad(nested, 'invalid_json');
  const forged = input(); forged.activeOwnerIds = { has() { called++; return true; } } as any; bad(forged, 'invalid_json');
  const native = input(); Object.defineProperty(native.activeOwnerIds, 'has', { get() { called++; throw Error('invoked'); } }); ok(projectGraphAssetChanges(native));
  bad(Object.assign(Object.create({ inherited: true }), input()), 'invalid_json'); assert.equal(called, 0);
});

test('aggregate byte, revision and principal limits reject without partial success', () => {
  const oversized = input(); (oversized.assetChanges[0] as any).attributes = { amount: 'x'.repeat(524_289) }; bad(oversized, 'limit');
  const exhausted = input(); exhausted.before[0]!.assetVersion = 2_147_483_647; bad(exhausted, 'limit');
  const owners = input(); owners.activeOwnerIds = new Set(Array.from({ length: 2002 }, (_, i) => `00000000-0000-4000-8000-${String(i).padStart(12, '0')}`)); bad(owners, 'limit');
});
