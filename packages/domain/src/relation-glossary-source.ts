// SPDX-License-Identifier: Apache-2.0
import type { ValidationResult } from './model.ts';
import { RELATION_LIMITS, relationValidationInternals as v } from './relation.ts';
import { checkFinalGraph, graphFromJSON, policiesFromJSON } from './relation-participation.ts';
import type { RelationEndpointPolicyState } from './relation-contracts.ts';
import type { CompleteGraphSnapshot, GraphChangeSet, RelationPolicySnapshot } from './relation-migration-contracts.ts';
const { Issues, copyJSON, fields, list, id, canonical, freeze, compare, endpoint } = v;
type Issues = InstanceType<typeof Issues>;

/** Internal SQL016 response, never an HTTP request field or authorization result.
 * The SQL producer independently binds this evidence to the live publication,
 * tenant, actor, transaction, original deadline and unchanged complete cohort. */
export interface GlossaryGraphSourceProof {
  readonly formatVersion: 1;
  readonly publicationId: string; readonly requestId: string;
  readonly tenantId: string; readonly actorId: string;
  readonly relationTypeIds: readonly string[];
  readonly beforeEndpoint: RelationEndpointPolicyState | null;
  readonly afterEndpoint: RelationEndpointPolicyState;
}

/** For a value already detached by the bounded descriptor-safe copier. */
export function glossarySourceFromJSON(input: unknown, issues: Issues): GlossaryGraphSourceProof | undefined {
  const path = '/sourceProof', row = fields(input, path, ['formatVersion', 'publicationId', 'requestId', 'tenantId', 'actorId', 'relationTypeIds', 'beforeEndpoint', 'afterEndpoint'], issues);
  if (!row) return;
  if (row.formatVersion !== 1) issues.add('invalid_definition', `${path}/formatVersion`, 'Only protected glossary source format 1 is supported.');
  for (const name of ['publicationId', 'requestId', 'tenantId', 'actorId']) id(row[name], `${path}/${name}`, issues);
  const types: string[] = [];
  for (const [i, value] of list(row.relationTypeIds, `${path}/relationTypeIds`, 5000, issues).entries()) {
    if (!id(value, `${path}/relationTypeIds/${i}`, issues)) continue;
    if (types.includes(value)) issues.add('duplicate', `${path}/relationTypeIds/${i}`, 'Protected scope identities occur once.');
    types.push(value);
  }
  if (canonical(types) !== canonical([...types].sort(compare))) issues.add('invalid_definition', `${path}/relationTypeIds`, 'Protected scope identities are in canonical order.');
  const before = row.beforeEndpoint === null ? null : endpoint(row.beforeEndpoint, `${path}/beforeEndpoint`, issues);
  const after = endpoint(row.afterEndpoint, `${path}/afterEndpoint`, issues);
  if (!after || before === undefined) return;
  if (after.typeId === null || after.policy === null || after.modelId === null || after.modelVersion === null || after.state === null)
    issues.add('invalid_definition', `${path}/afterEndpoint`, 'A glossary publication has an exact authored endpoint.');
  if (before === null) {
    if (after.assetVersion !== 1 || after.state !== after.policy?.lifecycle.initial)
      issues.add('model_version', `${path}/afterEndpoint`, 'A newly published term starts at revision one and its pinned initial state.');
  } else {
    if (after.assetId !== before.assetId || after.assetVersion !== before.assetVersion + 1)
      issues.add('model_version', `${path}/afterEndpoint`, 'The same term advances exactly one revision.');
    if (canonical({ ...after, assetVersion: before.assetVersion, state: before.state }) !== canonical(before))
      issues.add('invalid_definition', `${path}/afterEndpoint`, 'Publication preserves the exact authored pin, policy and ancestry.');
    if (before.state !== after.state && !after.policy?.lifecycle.transitions.some(change => change.from === before.state && change.to === after.state))
      issues.add('invalid_definition', `${path}/afterEndpoint/state`, 'Publication uses an actual pinned lifecycle transition.');
  }
  return { formatVersion: 1, publicationId: row.publicationId as string, requestId: row.requestId as string,
    tenantId: row.tenantId as string, actorId: row.actorId as string, relationTypeIds: types, beforeEndpoint: before, afterEndpoint: after };
}

export function parseGlossaryGraphSourceProof(input: unknown): ValidationResult<GlossaryGraphSourceProof> {
  try {
    const issues = new Issues(), copied = copyJSON(input, issues);
    if (issues.values.length) return issues.result(undefined as never);
    const result = glossarySourceFromJSON(copied, issues);
    return issues.result(result ? freeze(result) : undefined as never);
  } catch { return { ok: false, issues: [{ code: 'invalid_definition', path: '/sourceProof', message: 'Protected source evidence is malformed.' }] }; }
}

/** Restricts this internal path to the graph portion of one publication. */
export function checkGlossaryGraphIntent(changeSet: GraphChangeSet, proof: GlossaryGraphSourceProof, issues: Issues): void {
  if (changeSet.assetChanges.length || changeSet.assetTypeMigrations.length || changeSet.repairsReceiptId !== null ||
      changeSet.relationTargets.some(target => target.kind !== 'repair' || !proof.relationTypeIds.includes(target.plan.relationTypeId) || target.plan.transform !== null))
    issues.add('invalid_definition', '/sourceProof', 'Protected publication repairs only its current relation cohort; it cannot change assets or publish definitions.');
}

/** Reconstruct only the independently proved original endpoint. No edge,
 * binding, head or policy is omitted or repaired in this source check. */
export function checkGlossaryGraphSource(before: CompleteGraphSnapshot, policies: Map<string, RelationPolicySnapshot>, proof: GlossaryGraphSourceProof, issues: Issues): CompleteGraphSnapshot {
  const after = proof.afterEndpoint, old = proof.beforeEndpoint;
  if (canonical(before.heads.map(row => row.relationTypeId).sort(compare)) !== canonical(proof.relationTypeIds))
    issues.add('invalid_definition', '/sourceProof/relationTypeIds', 'The complete captured scope must equal the protected scope.');
  if (canonical(before.endpoints.find(row => row.assetId === after.assetId) ?? null) !== canonical(after))
    issues.add('invalid_definition', '/sourceProof/afterEndpoint', 'The protected after endpoint must equal the actual captured endpoint.');
  for (const edge of before.edges) {
    if (edge.key.kind !== 'existing' || edge.status !== 'active') issues.add('invalid_definition', '/before/edges', 'The captured source contains only actual active edges.');
    const source = edge.sourceAssetId === after.assetId, target = edge.targetAssetId === after.assetId;
    if ((source || target) && old === null) issues.add('invalid_definition', '/sourceProof/beforeEndpoint', 'A newly inserted term has no preexisting incident edges.');
    if (source && edge.sourceAssetVersion !== after.assetVersion || target && edge.targetAssetVersion !== after.assetVersion)
      issues.add('model_version', '/before/edges', 'Captured edge observations use the actual current term revision.');
  }
  for (const binding of before.bindings) {
    if (binding.key.kind !== 'existing' || binding.status !== 'active') issues.add('invalid_definition', '/before/bindings', 'The captured source contains only actual active bindings.');
    if (binding.assetId !== after.assetId) continue;
    if (old === null) issues.add('invalid_definition', '/sourceProof/beforeEndpoint', 'A newly inserted term has no preexisting participation.');
    if (binding.assetVersion !== after.assetVersion) issues.add('model_version', '/before/bindings', 'Captured binding observations use the actual current term revision.');
  }
  const restored: CompleteGraphSnapshot = {
    heads: before.heads,
    endpoints: before.endpoints.flatMap(row => row.assetId === after.assetId ? old ? [old] : [] : [row]),
    edges: before.edges.map(row => old ? { ...row,
      sourceAssetVersion: row.sourceAssetId === after.assetId ? old.assetVersion : row.sourceAssetVersion,
      targetAssetVersion: row.targetAssetId === after.assetId ? old.assetVersion : row.targetAssetVersion } : row),
    bindings: before.bindings.map(row => old && row.assetId === after.assetId ? { ...row, assetVersion: old.assetVersion } : row),
  };
  const baselineIssues = new Issues(); checkFinalGraph(restored, policies, baselineIssues);
  issues.append('/sourceProof/baseline', baselineIssues.values);
  return restored;
}

/** Predicate validation only. Database provenance, history, authorization,
 * cohort completeness and final proposed graph validation remain mandatory. */
export function validateGlossaryGraphSource(input: unknown): ValidationResult<CompleteGraphSnapshot> {
  try {
    const issues = new Issues(), copied = copyJSON(input, issues);
    if (issues.values.length) return issues.result(undefined as never);
    const row = fields(copied, '', ['before', 'policies', 'sourceProof'], issues);
    if (!row) return issues.result(undefined as never);
    const before = graphFromJSON(row.before, '/before', issues), policies = policiesFromJSON(row.policies, issues), proof = glossarySourceFromJSON(row.sourceProof, issues);
    if (!before || !proof || issues.values.length) return issues.result(undefined as never);
    const result = checkGlossaryGraphSource(before, policies, proof, issues);
    if (new TextEncoder().encode(canonical(copied)).length > RELATION_LIMITS.bytes) issues.add('limit', '/sourceProof', 'The retained source evidence exceeds the graph byte bound.');
    return issues.result(freeze(result));
  } catch { return { ok: false, issues: [{ code: 'invalid_definition', path: '/sourceProof', message: 'Protected source evidence is malformed.' }] }; }
}
