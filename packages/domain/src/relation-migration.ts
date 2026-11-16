// SPDX-License-Identifier: Apache-2.0
import { parseBoundedJSONEnvelope, validateAttributes, type ValidationResult } from './model.ts';
import { parseAssetTypeDefinition } from './asset-type.ts';
import { parseAssetTypeMigrationPlan } from './asset-type-migration.ts';
import { parseMigrationPlan, validateMigrationPlanForModels, applyModelMigrationToAttributes } from './model-migration.ts';
import { RELATION_LIMITS, parseRelationDefinition, relationValidationInternals as v } from './relation.ts';
import { policyKey, edgeKey, bindingKey, bindingIdentity, structuralProjection, policiesFromJSON, graphFromJSON,
  valuesFromJSON, eligible, deriveFromGraph, checkFinalGraph } from './relation-participation.ts';
import type { RelationDefinition, RelationEndpointPolicyState } from './relation-contracts.ts';
import type { AuthorizedCompleteGraphChange, BindingDisposition, CompleteGraphSnapshot, GraphAssetChange, GraphAssetPolicyEvidence,
  GraphAssetTuple, GraphBindingSnapshot, GraphChangeSet, GraphEdgeSnapshot, PreparedAssetChanges, RelationCreationProposal,
  RelationDisposition, RelationMigrationPlan, RelationMigrationTarget, RelationMigrationValues, RelationPolicyChange,
  RelationPolicySnapshot, RelationTransform, RepairableRelationSourceIssue, ValidatedGraphChange } from './relation-migration-contracts.ts';
const { Issues, copyJSON, fields, list, id, key, version, canonical, freeze, compare } = v;
type Issues = InstanceType<typeof Issues>;
type Fields = Record<string, unknown>;
const policyChanges = ['direction_changed', 'source_types_changed', 'target_types_changed', 'source_states_changed', 'target_states_changed', 'cardinality_changed', 'self_policy_changed', 'cycles_changed', 'required_owner_changed', 'lifecycle_changed'] as const;
const encoder = new TextEncoder();
function reason(input: unknown, path: string, issues: Issues): void {
  if (typeof input !== 'string' || !input.trim() || [...input].length > 500 || /[\u0000-\u001f\u007f-\u009f]/.test(input)) issues.add('format', path, 'A reason is 1–500 nonblank Unicode characters without controls.');
}
function versions(input: unknown, path: string, issues: Issues): number[] {
  const output: number[] = [], seen = new Set<number>();
  for (const [i, value] of list(input, path, 5000, issues).entries()) if (version(value, `${path}/${i}`, issues)) {
    if (seen.has(value)) issues.add('duplicate', `${path}/${i}`, 'Policy pins occur once.'); seen.add(value); output.push(value);
  }
  return output.sort((a, b) => a - b);
}
function transformFromJSON(input: unknown, path: string, issues: Issues): RelationTransform | null {
  if (input === null) return null;
  const value = fields(input, path, ['attributes', 'owner', 'lifecycle'], issues); if (!value) return null;
  const attributes = parseMigrationPlan(value.attributes); if (!attributes.ok) issues.append(`${path}/attributes`, attributes.issues);
  const owner = fields(value.owner, `${path}/owner`, ['default', 'overrides'], issues), lifecycle = fields(value.lifecycle, `${path}/lifecycle`, ['onUnmapped', 'mappings'], issues);
  if (owner?.default !== 'preserve') issues.add('enum', `${path}/owner/default`, 'Unspecified owners must be preserved.');
  if (lifecycle?.onUnmapped !== 'preserve' && lifecycle?.onUnmapped !== 'error') issues.add('enum', `${path}/lifecycle/onUnmapped`, 'Choose preserve or error.');
  const overrides: RelationTransform['owner']['overrides'][number][] = [], mappings: RelationTransform['lifecycle']['mappings'][number][] = [], owners = new Set<string>(), states = new Set<string>();
  for (const [i, raw] of list(owner?.overrides, `${path}/owner/overrides`, 1000, issues).entries()) {
    const p = `${path}/owner/overrides/${i}`, row = fields(raw, p, ['relationId', 'ownerId'], issues); if (!row) continue;
    if (!id(row.relationId, `${p}/relationId`, issues)) continue;
    if (row.ownerId !== null) id(row.ownerId, `${p}/ownerId`, issues);
    if (owners.has(row.relationId)) issues.add('duplicate', p, 'An edge has at most one owner override.'); owners.add(row.relationId);
    overrides.push({ relationId: row.relationId, ownerId: row.ownerId as string | null });
  }
  for (const [i, raw] of list(lifecycle?.mappings, `${path}/lifecycle/mappings`, 1000, issues).entries()) {
    const p = `${path}/lifecycle/mappings/${i}`, row = fields(raw, p, ['sourceVersion', 'from', 'to'], issues); if (!row) continue;
    if (!version(row.sourceVersion, `${p}/sourceVersion`, issues) || !key(row.from, `${p}/from`, issues) || !key(row.to, `${p}/to`, issues)) continue;
    const identity = `${row.sourceVersion}:${row.from}`; if (states.has(identity)) issues.add('duplicate', p, 'A pinned source state has at most one mapping.'); states.add(identity);
    if (attributes.ok && !attributes.value.sourceVersions.includes(row.sourceVersion)) issues.add('model_version', p, 'Mapping pin must occur in the transformed edge pins.');
    mappings.push({ sourceVersion: row.sourceVersion, from: row.from, to: row.to });
  }
  if (!attributes.ok) return null;
  return { attributes: attributes.value, owner: { default: 'preserve', overrides: overrides.sort((a, b) => compare(a.relationId, b.relationId)) }, lifecycle: { onUnmapped: lifecycle?.onUnmapped as 'preserve' | 'error', mappings: mappings.sort((a, b) => a.sourceVersion - b.sourceVersion || compare(a.from, b.from)) } };
}
function planFromJSON(input: unknown, path: string, issues: Issues): RelationMigrationPlan | undefined {
  const value = fields(input, path, ['formatVersion', 'relationTypeId', 'sourceVersions', 'transform', 'edges', 'creations', 'bindings', 'enrollment', 'acknowledgedPolicyChanges'], issues); if (!value) return;
  if (value.formatVersion !== 1) issues.add('invalid_definition', `${path}/formatVersion`, 'Only migration plan format 1 is supported.');
  id(value.relationTypeId, `${path}/relationTypeId`, issues);
  if (value.enrollment !== 'complete-eligible-assets') issues.add('enum', `${path}/enrollment`, 'Enrollment must cover all eligible assets.');
  const sourceVersions = versions(value.sourceVersions, `${path}/sourceVersions`, issues), transform = transformFromJSON(value.transform, `${path}/transform`, issues);
  const edges: RelationDisposition[] = [], creations: RelationCreationProposal[] = [], bindings: BindingDisposition[] = [], acknowledgements: RelationPolicyChange[] = [];
  const edgeIds = new Set<string>(), creationKeys = new Set<string>(), bindingIds = new Set<string>(), changes = new Set<string>();
  for (const [i, raw] of list(value.edges, `${path}/edges`, 1000, issues).entries()) {
    const p = `${path}/edges/${i}`, action = (raw as Fields | null)?.action;
    const extra = action === 'repair' ? ['values'] : action === 'repin' ? ['targetVersion', 'values'] : action === 'replace' ? ['creationKey', 'reason'] : action === 'tombstone' ? ['reason'] : [];
    const row = fields(raw, p, ['relationId', 'expectedVersion', 'action', ...extra], issues); if (!row) continue;
    id(row.relationId, `${p}/relationId`, issues); version(row.expectedVersion, `${p}/expectedVersion`, issues);
    if (!['preserve', 'migrate', 'repair', 'repin', 'tombstone', 'replace'].includes(action as string)) issues.add('enum', `${p}/action`, 'Unknown edge disposition.');
    if (edgeIds.has(row.relationId as string)) issues.add('duplicate', p, 'An edge has exactly one disposition.'); edgeIds.add(row.relationId as string);
    if (action === 'repair' || action === 'repin') row.values = valuesFromJSON(row.values, `${p}/values`, issues);
    if (action === 'repin') version(row.targetVersion, `${p}/targetVersion`, issues);
    if (action === 'replace') key(row.creationKey, `${p}/creationKey`, issues);
    if (action === 'replace' || action === 'tombstone') reason(row.reason, `${p}/reason`, issues);
    edges.push(row as unknown as RelationDisposition);
  }
  for (const [i, raw] of list(value.creations, `${path}/creations`, 1000, issues).entries()) {
    const p = `${path}/creations/${i}`, row = fields(raw, p, ['key', 'sourceAssetId', 'targetAssetId', 'sourceAssetVersion', 'targetAssetVersion', 'values'], issues); if (!row) continue;
    key(row.key, `${p}/key`, issues); id(row.sourceAssetId, `${p}/sourceAssetId`, issues); id(row.targetAssetId, `${p}/targetAssetId`, issues);
    version(row.sourceAssetVersion, `${p}/sourceAssetVersion`, issues); version(row.targetAssetVersion, `${p}/targetAssetVersion`, issues);
    if (creationKeys.has(row.key as string)) issues.add('duplicate', p, 'Creation keys are unique within the logical type.'); creationKeys.add(row.key as string);
    const values = valuesFromJSON(row.values, `${p}/values`, issues); if (values) creations.push({ ...row, values } as unknown as RelationCreationProposal);
  }
  if ((transform !== null) !== edges.some(edge => edge.action === 'migrate')) issues.add('invalid_definition', `${path}/transform`, 'A transform exists exactly when an edge has migrate disposition.');
  if (transform) {
    if (transform.attributes.sourceVersions.some(pin => !sourceVersions.includes(pin))) issues.add('model_version', `${path}/transform/attributes/sourceVersions`, 'Transformed pins must be declared source pins.');
    for (const override of transform.owner.overrides) if (!edges.some(edge => edge.relationId === override.relationId && edge.action === 'migrate')) issues.add('invalid_definition', `${path}/transform/owner/overrides`, 'Only migrated edges may receive transform owner overrides.');
  }
  const replacementKeys = new Set<string>();
  for (const [i, row] of edges.entries()) if (row.action === 'replace') {
    if (!creationKeys.has(row.creationKey)) issues.add('required', `${path}/edges/${i}/creationKey`, 'Replacement must identify an explicit same-type creation.');
    if (replacementKeys.has(row.creationKey)) issues.add('duplicate', `${path}/edges/${i}/creationKey`, 'A creation can replace only one predecessor.'); replacementKeys.add(row.creationKey);
  }
  for (const [i, raw] of list(value.bindings, `${path}/bindings`, 4000, issues).entries()) {
    const p = `${path}/bindings/${i}`, action = (raw as Fields | null)?.action, row = fields(raw, p, ['bindingId', 'expectedVersion', 'action', ...(action === 'repin' ? ['targetVersion'] : action === 'release' ? ['reason'] : [])], issues); if (!row) continue;
    id(row.bindingId, `${p}/bindingId`, issues); version(row.expectedVersion, `${p}/expectedVersion`, issues);
    if (!['preserve', 'repin', 'release'].includes(action as string)) issues.add('enum', `${p}/action`, 'Unknown binding disposition.');
    if (action === 'repin') version(row.targetVersion, `${p}/targetVersion`, issues);
    if (action === 'release') reason(row.reason, `${p}/reason`, issues);
    if (bindingIds.has(row.bindingId as string)) issues.add('duplicate', p, 'A binding has exactly one disposition.'); bindingIds.add(row.bindingId as string);
    bindings.push(row as unknown as BindingDisposition);
  }
  for (const [i, raw] of list(value.acknowledgedPolicyChanges, `${path}/acknowledgedPolicyChanges`, policyChanges.length, issues).entries()) {
    if (!(policyChanges as readonly unknown[]).includes(raw)) issues.add('enum', `${path}/acknowledgedPolicyChanges/${i}`, 'Unknown policy change acknowledgement.');
    else { if (changes.has(raw as string)) issues.add('duplicate', `${path}/acknowledgedPolicyChanges/${i}`, 'Acknowledgements occur once.'); changes.add(raw as string); acknowledgements.push(raw as RelationPolicyChange); }
  }
  return { formatVersion: 1, relationTypeId: value.relationTypeId as string, sourceVersions, transform,
    edges: edges.sort((a, b) => compare(a.relationId, b.relationId)), creations: creations.sort((a, b) => compare(a.key, b.key)),
    bindings: bindings.sort((a, b) => compare(a.bindingId, b.bindingId)), enrollment: 'complete-eligible-assets', acknowledgedPolicyChanges: acknowledgements.sort(compare) };
}
export function parseRelationMigrationPlan(input: unknown): ValidationResult<RelationMigrationPlan> {
  const issues = new Issues(), raw = copyJSON(input, issues); if (issues.values.length) return issues.result(undefined as never);
  const result = planFromJSON(raw, '', issues); return issues.result(freeze(result!));
}
function changeSetFromJSON(input: unknown, issues: Issues): GraphChangeSet | undefined {
  const value = fields(input, '', ['formatVersion', 'relationTargets', 'assetChanges', 'assetTypeMigrations', 'repairsReceiptId'], issues); if (!value) return;
  if (value.formatVersion !== 1) issues.add('invalid_definition', '/formatVersion', 'Only graph change-set format 1 is supported.');
  if (value.repairsReceiptId !== null) id(value.repairsReceiptId, '/repairsReceiptId', issues);
  const relationTargets: RelationMigrationTarget[] = [], assetChanges: GraphAssetChange[] = [], assetTypeMigrations: GraphChangeSet['assetTypeMigrations'][number][] = [];
  const types = new Set<string>(), assets = new Set<string>(), models = new Set<string>();
  for (const [i, raw] of list(value.relationTargets, '/relationTargets', 8, issues).entries()) {
    const p = `/relationTargets/${i}`, kind = (raw as Fields | null)?.kind, row = fields(raw, p, ['kind', 'expectedHeadVersion', 'definition', 'plan', ...(kind === 'create' ? ['reservationId'] : [])], issues); if (!row) continue;
    const plan = planFromJSON(row.plan, `${p}/plan`, issues); if (!plan) continue;
    if (types.has(plan.relationTypeId)) issues.add('duplicate', p, 'A type has one explicit target.'); types.add(plan.relationTypeId);
    if (!['create', 'repair', 'publish'].includes(kind as string)) issues.add('enum', `${p}/kind`, 'Choose create, repair or publish.');
    if (kind === 'create') { id(row.reservationId, `${p}/reservationId`, issues); if (row.expectedHeadVersion !== null) issues.add('model_version', `${p}/expectedHeadVersion`, 'Creation has no committed head.'); }
    else version(row.expectedHeadVersion, `${p}/expectedHeadVersion`, issues);
    if (kind === 'repair') {
      if (row.definition !== null || plan.transform !== null || plan.edges.some(edge => edge.action === 'migrate')) issues.add('invalid_definition', p, 'Repair publishes no definition and uses explicit full values instead of a transform.');
      if (plan.acknowledgedPolicyChanges.length) issues.add('invalid_definition', `${p}/plan/acknowledgedPolicyChanges`, 'Repair has no publication policy diff.');
      relationTargets.push({ kind: 'repair', expectedHeadVersion: row.expectedHeadVersion as number, definition: null, plan });
    } else {
      const definition = parseRelationDefinition(row.definition); if (!definition.ok) { issues.append(`${p}/definition`, definition.issues); continue; }
      if (definition.value.formatVersion !== 2) { issues.add('invalid_definition', `${p}/definition/formatVersion`, 'Graph publication requires a format-two definition.'); continue; }
      if (kind === 'create') {
        if (definition.value.version !== 1 || plan.sourceVersions.length || plan.edges.length || plan.bindings.length || plan.transform !== null || plan.acknowledgedPolicyChanges.length) issues.add('invalid_definition', p, 'Creation begins at version one without source dispositions, transformations or fictitious acknowledgements.');
        relationTargets.push({ kind: 'create', reservationId: row.reservationId as string, expectedHeadVersion: null, definition: definition.value, plan });
      } else {
        if (definition.value.version !== (row.expectedHeadVersion as number) + 1) issues.add('model_version', `${p}/definition/version`, 'Publication advances the expected head exactly once.');
        if ((plan.transform !== null) !== plan.edges.some(edge => edge.action === 'migrate')) issues.add('invalid_definition', `${p}/plan/transform`, 'A transform exists exactly when at least one edge migrates.');
        relationTargets.push({ kind: 'publish', expectedHeadVersion: row.expectedHeadVersion as number, definition: definition.value, plan });
      }
    }
    const destination = kind === 'repair' ? row.expectedHeadVersion : (row.definition as Fields | null)?.version;
    for (const [j, edge] of plan.edges.entries()) if (edge.action === 'repin' && edge.targetVersion !== destination) issues.add('model_version', `${p}/plan/edges/${j}/targetVersion`, 'Repin must use the exact final admission head.');
    for (const [j, binding] of plan.bindings.entries()) if (binding.action === 'repin' && binding.targetVersion !== destination) issues.add('model_version', `${p}/plan/bindings/${j}/targetVersion`, 'Binding repin must use the exact final admission head.');
  }
  for (const [i, raw] of list(value.assetChanges, '/assetChanges', 1000, issues).entries()) {
    const p = `/assetChanges/${i}`, kind = (raw as Fields | null)?.kind, row = fields(raw, p, ['kind', 'assetId', 'expectedVersion', ...(kind === 'assign' ? ['modelId', 'modelVersion', 'attributes', 'ownerId'] : ['state'])], issues); if (!row) continue;
    id(row.assetId, `${p}/assetId`, issues); version(row.expectedVersion, `${p}/expectedVersion`, issues);
    if (assets.has(row.assetId as string)) issues.add('duplicate', p, 'An asset has one direct change.'); assets.add(row.assetId as string);
    if (kind === 'assign') { key(row.modelId, `${p}/modelId`, issues); version(row.modelVersion, `${p}/modelVersion`, issues); if (row.ownerId !== null) id(row.ownerId, `${p}/ownerId`, issues); if (!row.attributes || typeof row.attributes !== 'object' || Array.isArray(row.attributes)) issues.add('type', `${p}/attributes`, 'Expected attributes.'); }
    else if (kind === 'transition') key(row.state, `${p}/state`, issues);
    else issues.add('enum', `${p}/kind`, 'Choose assignment or transition.');
    assetChanges.push(row as unknown as GraphAssetChange);
  }
  for (const [i, raw] of list(value.assetTypeMigrations, '/assetTypeMigrations', 8, issues).entries()) {
    const p = `/assetTypeMigrations/${i}`, row = fields(raw, p, ['expectedHeadVersion', 'definition', 'plan'], issues); if (!row) continue;
    version(row.expectedHeadVersion, `${p}/expectedHeadVersion`, issues);
    const definition = parseAssetTypeDefinition(row.definition), plan = parseAssetTypeMigrationPlan(row.plan);
    if (!definition.ok) issues.append(`${p}/definition`, definition.issues); if (!plan.ok) issues.append(`${p}/plan`, plan.issues);
    if (!definition.ok || !plan.ok) continue;
    if (models.has(definition.value.id)) issues.add('duplicate', p, 'An authored model has one publication.'); models.add(definition.value.id);
    if (definition.value.version !== (row.expectedHeadVersion as number) + 1 || plan.value.attributes.modelId !== definition.value.id || plan.value.attributes.targetVersion !== definition.value.version) issues.add('model_version', p, 'Nested migration must name its exact next model version.');
    assetTypeMigrations.push({ expectedHeadVersion: row.expectedHeadVersion as number, definition: definition.value, plan: plan.value });
  }
  if (!relationTargets.length && !assetChanges.length && !assetTypeMigrations.length) issues.add('required', '', 'An operation must contain a relation target or asset change.');
  return { formatVersion: 1, relationTargets: relationTargets.sort((a, b) => compare(a.plan.relationTypeId, b.plan.relationTypeId)), assetChanges: assetChanges.sort((a, b) => compare(a.assetId, b.assetId)), assetTypeMigrations: assetTypeMigrations.sort((a, b) => compare(a.definition.id, b.definition.id)), repairsReceiptId: value.repairsReceiptId as string | null };
}
export function parseGraphChangeSet(input: unknown): ValidationResult<GraphChangeSet> {
  const issues = new Issues(), raw = copyJSON(input, issues); if (issues.values.length) return issues.result(undefined as never);
  const result = changeSetFromJSON(raw, issues); return issues.result(freeze(result!));
}
export function parseGraphChangeSetFile(text: string): ValidationResult<GraphChangeSet> {
  if (typeof text !== 'string' || encoder.encode(text).length > RELATION_LIMITS.bytes) return { ok: false, issues: [{ code: 'limit', path: '', message: 'Graph change-set exceeds the shared UTF-8 byte budget.' }] };
  const parsed = parseBoundedJSONEnvelope(text); return parsed.ok ? parseGraphChangeSet(parsed.value) : parsed;
}
/** Context carries explicit target identities but no edge dispositions yet. Reuse
 * the exact graph grammar after checking the distinct context envelope, so a
 * context request cannot smuggle a plan or lose an unsupported field. */
export function parseRelationMigrationContext(input: unknown): ValidationResult<import('./relation-migration-contracts.ts').RelationMigrationContextRequest> {
  const issues = new Issues(), copied = copyJSON(input, issues);
  if (issues.values.length) return issues.result(undefined as never);
  const value = fields(copied, '', ['formatVersion', 'relationTargets', 'assetChanges', 'assetTypeMigrations', 'repairsReceiptId'], issues);
  if (!value) return issues.result(undefined as never);
  const targets = list(value.relationTargets, '/relationTargets', 8, issues).map((raw, i) => {
    const kind = (raw as Fields | null)?.kind, path = `/relationTargets/${i}`;
    const row = fields(raw, path, ['kind', 'relationTypeId', 'expectedHeadVersion', 'definition', ...(kind === 'create' ? ['reservationId'] : [])], issues);
    if (!row) return null;
    id(row.relationTypeId, `${path}/relationTypeId`, issues);
    const { relationTypeId, ...target } = row;
    return { ...target, plan: { formatVersion: 1, relationTypeId, sourceVersions: [], transform: null,
      edges: [], creations: [], bindings: [], enrollment: 'complete-eligible-assets', acknowledgedPolicyChanges: [] } };
  });
  if (issues.values.length) return issues.result(undefined as never);
  const parsed = parseGraphChangeSet({ ...value, relationTargets: targets });
  if (!parsed.ok) return parsed;
  const result = { ...parsed.value, relationTargets: parsed.value.relationTargets.map(({ plan, ...target }) => ({ ...target, relationTypeId: plan.relationTypeId })) };
  return { ok: true, value: freeze(result) };
}
export function relationPolicyChanges(head: RelationDefinition, target: RelationDefinition): RelationPolicyChange[] {
  const names = ['direction', 'sourceTypes', 'targetTypes', 'sourceStates', 'targetStates', 'cardinality', 'allowSelf', 'cycles', 'requiredOwner', 'lifecycle'] as const;
  return names.flatMap((name, i) => canonical(head[name]) === canonical(target[name]) ? [] : [policyChanges[i]]).sort(compare);
}
function endpointProjection(assetId: string, assetVersion: number, tuple: GraphAssetTuple, policies: readonly GraphAssetPolicyEvidence[], issues: Issues, path: string): RelationEndpointPolicyState | undefined {
  const raw = fields(tuple, path, ['modelId', 'modelVersion', 'attributes', 'ownerId', 'state'], issues); if (!raw) return;
  if (tuple.modelId === null) {
    if (tuple.modelVersion !== null || tuple.state !== null) issues.add('invalid_definition', path, 'Untyped tuples have no policy pin or state.');
    return { assetId, assetVersion, modelId: null, modelVersion: null, state: null, typeId: null, policy: null, ancestorTypes: [] };
  }
  const matches = policies.filter(row => row.kind === 'attributes' ? row.model.id === tuple.modelId && row.model.version === tuple.modelVersion : row.resolution.definition.id === tuple.modelId && row.resolution.definition.version === tuple.modelVersion);
  if (matches.length !== 1) { issues.add('required', path, 'Each prepared tuple needs exactly one exact policy evidence entry.'); return; }
  const policy = matches[0];
  return { assetId, assetVersion, modelId: tuple.modelId, modelVersion: tuple.modelVersion, state: tuple.state,
    typeId: policy.kind === 'authored' ? policy.typeId : null, policy: policy.kind === 'authored' ? policy.resolution : null, ancestorTypes: policy.kind === 'authored' ? policy.ancestorTypes : [] };
}
function checkPreparedAssets(raw: unknown, changeSet: GraphChangeSet, before: CompleteGraphSnapshot, proposed: CompleteGraphSnapshot, issues: Issues): void {
  const value = fields(raw, '/preparedAssets', ['policies', 'changes', 'typeMigrations'], issues); if (!value) return;
  const policies = list(value.policies, '/preparedAssets/policies', 5000, issues) as unknown as GraphAssetPolicyEvidence[], prepared = list(value.changes, '/preparedAssets/changes', 1000, issues) as unknown as PreparedAssetChanges['changes'];
  const migrations = list(value.typeMigrations, '/preparedAssets/typeMigrations', 8, issues) as unknown as PreparedAssetChanges['typeMigrations'];
  // The independent preparation function proves transformations. This boundary checks its exact coverage and endpoint projection.
  for (const [i, policy] of policies.entries()) {
    const p = `/preparedAssets/policies/${i}`, kind = (policy as unknown as Fields)?.kind;
    const row = fields(policy, p, kind === 'attributes' ? ['kind', 'model', 'definitionHash'] : ['kind', 'typeId', 'resolution', 'definitionHash', 'resolutionHash', 'ancestorTypes'], issues);
    if (!row) continue;
    if (kind !== 'attributes' && kind !== 'authored') issues.add('enum', `${p}/kind`, 'Expected attributes or authored policy evidence.');
    for (const name of kind === 'attributes' ? ['definitionHash'] : ['definitionHash', 'resolutionHash'])
      if (typeof row[name] !== 'string' || !/^[0-9a-f]{64}$/.test(row[name] as string)) issues.add('format', `${p}/${name}`, 'Expected a canonical SHA256 evidence hash.');
  }
  if (issues.values.length) return;
  const expected = new Map(changeSet.assetChanges.map(row => [row.assetId, row.kind as 'assign' | 'transition' | 'type-migrate']));
  for (const [i, migration] of migrations.entries()) {
    const p = `/preparedAssets/typeMigrations/${i}`, row = fields(migration, p, ['typeId', 'modelId', 'expectedHeadVersion', 'headPolicy', 'targetPolicy', 'sourcePolicies', 'plan', 'assetIds', 'changes', 'policyChanges'], issues); if (!row) continue;
    const intent = changeSet.assetTypeMigrations.find(item => item.definition.id === migration.modelId);
    if (!intent || canonical(intent.plan) !== canonical(migration.plan) || intent.expectedHeadVersion !== migration.expectedHeadVersion || migration.typeId !== intent.plan.typeId || canonical(migration.targetPolicy) !== canonical({ modelId: intent.definition.id, modelVersion: intent.definition.version }) || canonical(migration.headPolicy) !== canonical({ modelId: intent.definition.id, modelVersion: intent.expectedHeadVersion }))
      issues.add('invalid_definition', p, 'Prepared migration must match one declared complete authored migration exactly.');
    const targets = policies.filter(policy => policy.kind === 'authored' && policy.typeId === migration.typeId &&
      policy.resolution.definition.id === migration.modelId && policy.resolution.definition.version === migration.targetPolicy.modelVersion);
    if (!intent || targets.length !== 1 || targets[0]?.kind !== 'authored' || canonical(targets[0].resolution.definition) !== canonical(intent.definition))
      issues.add('invalid_definition', `${p}/targetPolicy`, 'The prepared target definition must equal the declared definition, including for an empty cohort.');
    if (canonical(before.endpoints.filter(asset => asset.modelId === migration.modelId).map(asset => asset.assetId).sort()) !== canonical([...migration.assetIds].sort())) issues.add('invalid_definition', `${p}/assetIds`, 'Nested preparation must cover every captured asset pinned to this logical model.');
    for (const [j, assetId] of list(row.assetIds, `${p}/assetIds`, 1000, issues).entries()) {
      if (!id(assetId, `${p}/assetIds/${j}`, issues)) continue;
      if (expected.has(assetId)) issues.add('duplicate', `${p}/assetIds/${j}`, 'Direct and nested asset cohorts cannot overlap.'); expected.set(assetId, 'type-migrate');
    }
  }
  if (migrations.length !== changeSet.assetTypeMigrations.length || new Set(migrations.map(row => row.modelId)).size !== migrations.length) issues.add('invalid_definition', '/preparedAssets/typeMigrations', 'Every declared migration has exactly one complete preparation.');
  const seen = new Set<string>(), beforeById = new Map(before.endpoints.map(row => [row.assetId, row])), finalById = new Map(proposed.endpoints.map(row => [row.assetId, row]));
  for (const [i, change] of prepared.entries()) {
    const p = `/preparedAssets/changes/${i}`, row = fields(change, p, ['kind', 'assetId', 'fromAssetVersion', 'toAssetVersion', 'before', 'after', 'sourcePolicy', 'targetPolicy', 'sourceIssues'], issues); if (!row) continue;
    if (seen.has(change.assetId) || expected.get(change.assetId) !== change.kind) issues.add('invalid_definition', p, 'Prepared changes exactly cover each declared asset once.'); seen.add(change.assetId);
    version(change.fromAssetVersion, `${p}/fromAssetVersion`, issues); version(change.toAssetVersion, `${p}/toAssetVersion`, issues);
    if (change.toAssetVersion !== change.fromAssetVersion + 1) issues.add('model_version', p, 'A changed asset advances exactly once.');
    const direct = changeSet.assetChanges.find(item => item.assetId === change.assetId);
    if (direct && direct.expectedVersion !== change.fromAssetVersion) issues.add('model_version', p, 'Prepared source revision must equal direct intent.');
    if (direct?.kind === 'assign' && (change.after.modelId !== direct.modelId || change.after.modelVersion !== direct.modelVersion || canonical(change.after.attributes) !== canonical(direct.attributes) || change.after.ownerId !== direct.ownerId || direct.ownerId !== change.before.ownerId)) issues.add('invalid_definition', p, 'Assignment preparation must equal declared attributes/pin and preserve the captured owner.');
    if (direct?.kind === 'transition' && (change.after.state !== direct.state || canonical({ ...change.after, state: change.before.state }) !== canonical(change.before))) issues.add('invalid_definition', p, 'Transition preparation changes only the declared state.');
    for (const [name, tuple, ref, revision, actual] of [['before', change.before, change.sourcePolicy, change.fromAssetVersion, beforeById.get(change.assetId)], ['after', change.after, change.targetPolicy, change.toAssetVersion, finalById.get(change.assetId)]] as const) {
      const projection = endpointProjection(change.assetId, revision, tuple, policies, issues, `${p}/${name}`);
      if (!projection) continue;
      const expectedRef = tuple.modelId === null ? null : { modelId: tuple.modelId, modelVersion: tuple.modelVersion };
      if (canonical(ref) !== canonical(expectedRef)) issues.add('invalid_definition', `${p}/${name}`, 'Policy reference and full governed tuple pin must agree.');
      if (canonical(projection) !== canonical(actual)) issues.add('invalid_definition', `${p}/${name}`, 'The endpoint projection must equal the independently prepared tuple, ancestry and exact revision.');
    }
  }
  if (canonical([...seen].sort()) !== canonical([...expected.keys()].sort())) issues.add('invalid_definition', '/preparedAssets/changes', 'Prepared asset coverage is incomplete.');
  if (before.endpoints.length !== proposed.endpoints.length) issues.add('invalid_definition', '/migration/endpoints', 'The complete current and proposed candidate identities must match.');
  for (const endpoint of before.endpoints) if (!seen.has(endpoint.assetId) && canonical(endpoint) !== canonical(finalById.get(endpoint.assetId))) issues.add('invalid_definition', '/migration/endpoints', 'An undeclared endpoint cannot change.');
}
function checkValues(edge: GraphEdgeSnapshot, policy: RelationPolicySnapshot, active: ReadonlySet<string>, members: ReadonlySet<string>, actor: string,
  issues: Issues, path: string, mode: 'source' | 'changed' | 'preserved', sourceIssues: RepairableRelationSourceIssue[]): void {
  const attributes = validateAttributes(policy.model, edge.values.attributes); if (!attributes.ok) issues.append(`${path}/attributes`, attributes.issues);
  if (!policy.definition.lifecycle.states.includes(edge.values.state)) issues.add('enum', `${path}/state`, 'State must belong to the exact pinned lifecycle.');
  const owner = edge.values.ownerId;
  if (owner !== null && !members.has(owner)) issues.add('required', `${path}/ownerId`, 'A non-null owner must remain a member of this tenant.');
  if (policy.definition.requiredOwner && owner === null) issues.add('required', `${path}/ownerId`, 'The pinned policy requires an owner.');
  if (mode === 'source' && policy.definition.requiredOwner && owner !== null && members.has(owner) && !active.has(owner) && edge.key.kind === 'existing')
    sourceIssues.push({ code: 'source_required_owner_inactive', relationId: edge.key.relationId, ownerId: owner });
  else if (owner !== null && !active.has(owner) && (mode === 'changed' || policy.definition.requiredOwner)) issues.add('required', `${path}/ownerId`, 'The changed live result requires an active eligible owner.');
  for (const member of edge.values.allowedIdentityIds) if (!members.has(member)) issues.add('required', `${path}/allowedIdentityIds`, 'ACL members must belong to this tenant.');
  if (mode === 'changed' && edge.values.visibility === 'restricted' && !edge.values.allowedIdentityIds.includes(actor)) issues.add('required', `${path}/allowedIdentityIds`, 'A changed result must retain the actor’s access.');
}
function transformEdge(edge: GraphEdgeSnapshot, head: RelationPolicySnapshot, source: RelationPolicySnapshot, target: RelationPolicySnapshot,
  transform: RelationTransform, issues: Issues, path: string): RelationMigrationValues | undefined {
  const attributes = applyModelMigrationToAttributes({ head: head.model, source: source.model, target: target.model, plan: transform.attributes, attributes: edge.values.attributes });
  if (!attributes.ok) { issues.append(`${path}/attributes`, attributes.issues); return; }
  const override = transform.owner.overrides.find(row => edge.key.kind === 'existing' && row.relationId === edge.key.relationId);
  const mapping = transform.lifecycle.mappings.find(row => row.sourceVersion === edge.relationTypeVersion && row.from === edge.values.state);
  if (!mapping && transform.lifecycle.onUnmapped === 'error') issues.add('required', `${path}/state`, 'The actual pinned source state needs an explicit mapping.');
  return { ...edge.values, attributes: attributes.value, ownerId: override ? override.ownerId : edge.values.ownerId, state: mapping?.to ?? edge.values.state };
}
/** These exact-policy and captured-shape checks are common to projection and validation.
 * They establish no access, source-asset preparation or principal eligibility. */
function checkCapturedGraph(before: CompleteGraphSnapshot, policies: Map<string, RelationPolicySnapshot>, issues: Issues): void {
  for (const row of before.edges) if (row.key.kind !== 'existing' || row.status !== 'active') issues.add('invalid_definition', '/before/edges', 'The captured before cohort contains only actual active edges.');
  for (const row of before.bindings) if (row.key.kind !== 'existing' || row.status !== 'active') issues.add('invalid_definition', '/before/bindings', 'The captured before cohort contains only actual active bindings.');
  const sourceConstraints = new Issues(); checkFinalGraph(before, policies, sourceConstraints); if (sourceConstraints.values.length) issues.append('/migration/source', sourceConstraints.values);
}

/** One deterministic ruleset reconstructs outcomes for both APIs. Validation-only
 * disposition issues remain separate so an invalid final graph is still available
 * to preview; neither a proposal nor this internal result is execution approval. */
function computeGraphProposal(changeSet: GraphChangeSet, before: CompleteGraphSnapshot,
  policies: Map<string, RelationPolicySnapshot>, proposedEndpoints: readonly RelationEndpointPolicyState[], issues: Issues) {
  const validationIssues = new Issues();
  const beforeHeads = new Map(before.heads.map(row => [row.relationTypeId, row.version])), finalHeads = new Map(before.heads.map(row => [row.relationTypeId, row.version]));
  const beforeEndpoints = new Map(before.endpoints.map(row => [row.assetId, row])), finalEndpoints = new Map(proposedEndpoints.map(row => [row.assetId, row]));
  // Graph projections observe the final endpoint revisions even when an edge or
  // binding itself is preserved. Their canonical revisions/history stay pinned.
  const expectedEdges = new Map(before.edges.map(row => [edgeKey(row), { ...row,
    sourceAssetVersion: finalEndpoints.get(row.sourceAssetId)?.assetVersion ?? row.sourceAssetVersion,
    targetAssetVersion: finalEndpoints.get(row.targetAssetId)?.assetVersion ?? row.targetAssetVersion }]));
  const expectedBindings = new Map(before.bindings.map(row => [bindingKey(row), { ...row,
    assetVersion: finalEndpoints.get(row.assetId)?.assetVersion ?? row.assetVersion }]));
  const changedEdges: ValidatedGraphChange['changedEdges'][number][] = [], changedBindings: ValidatedGraphChange['changedBindings'][number][] = [], replacements: ValidatedGraphChange['replacements'][number][] = [];
  for (const [targetIndex, target] of changeSet.relationTargets.entries()) {
    const path = `/migration/relationTargets/${targetIndex}`, type = target.plan.relationTypeId, headVersion = beforeHeads.get(type), plan = target.plan;
    const head = headVersion === undefined ? undefined : policies.get(policyKey(type, headVersion));
    if (target.kind === 'create' ? headVersion !== undefined : headVersion !== target.expectedHeadVersion) issues.add('model_version', `${path}/expectedHeadVersion`, 'The exact expected committed head must match.');
    const targetVersion = target.kind === 'repair' ? target.expectedHeadVersion : target.definition.version, destination = policies.get(policyKey(type, targetVersion));
    if (!destination || target.definition !== null && canonical(destination.definition) !== canonical(target.definition)) { issues.add('required', `${path}/definition`, 'The exact target policy evidence is required.'); continue; }
    if (head && destination.definition.id !== head.definition.id) issues.add('model_identity', `${path}/definition/id`, 'Publication preserves the immutable logical key.');
    finalHeads.set(type, targetVersion);
    const sourceEdges = before.edges.filter(row => row.relationTypeId === type), sourceBindings = before.bindings.filter(row => row.relationTypeId === type);
    const actualVersions = [...new Set([...sourceEdges, ...sourceBindings].map(row => row.relationTypeVersion))].sort((a, b) => a - b);
    if (canonical(actualVersions) !== canonical(plan.sourceVersions)) issues.add('model_version', `${path}/plan/sourceVersions`, 'Source pins must equal the complete live edge and active binding union.');
    if (canonical(sourceEdges.map(row => row.key.kind === 'existing' ? row.key.relationId : '').sort()) !== canonical(plan.edges.map(row => row.relationId))) issues.add('invalid_definition', `${path}/plan/edges`, 'Every current live edge needs exactly one disposition.');
    if (canonical(sourceBindings.map(row => row.key.kind === 'existing' ? row.key.bindingId : '').sort()) !== canonical(plan.bindings.map(row => row.bindingId))) issues.add('invalid_definition', `${path}/plan/bindings`, 'Every active binding needs exactly one disposition.');
    const expectedChanges = target.kind === 'publish' && head ? relationPolicyChanges(head.definition, destination.definition) : [];
    if (canonical(expectedChanges) !== canonical(plan.acknowledgedPolicyChanges)) issues.add('invalid_definition', `${path}/plan/acknowledgedPolicyChanges`, 'Acknowledgements must equal the exact head-to-target policy diff.');
    const migrating = sourceEdges.filter(edge => { const identity = edge.key; return identity.kind === 'existing' && plan.edges.some(row => row.relationId === identity.relationId && row.action === 'migrate'); });
    if (plan.transform) {
      if (!head) issues.add('required', `${path}/plan/transform`, 'Transformation requires an actual prior head.');
      else { const checked = validateMigrationPlanForModels(head.model, destination.model, plan.transform.attributes); if (!checked.ok) issues.append(`${path}/plan/transform/attributes`, checked.issues); }
      if (canonical([...new Set(migrating.map(row => row.relationTypeVersion))].sort((a, b) => a - b)) !== canonical(plan.transform.attributes.sourceVersions)) issues.add('model_version', `${path}/plan/transform/attributes/sourceVersions`, 'Transform pins equal only the migrated edge pins.');
      for (const override of plan.transform.owner.overrides) if (!migrating.some(row => row.key.kind === 'existing' && row.key.relationId === override.relationId)) issues.add('invalid_definition', `${path}/plan/transform/owner`, 'Overrides may name only transformed edges.');
      for (const mapping of plan.transform.lifecycle.mappings) if (!policies.get(policyKey(type, mapping.sourceVersion))?.definition.lifecycle.states.includes(mapping.from) || !destination.definition.lifecycle.states.includes(mapping.to)) issues.add('enum', `${path}/plan/transform/lifecycle`, 'Mappings must reference actual source and target lifecycle states.');
    }
    for (const [i, disposition] of plan.edges.entries()) {
      const p = `${path}/plan/edges/${i}`, old = sourceEdges.find(row => row.key.kind === 'existing' && row.key.relationId === disposition.relationId);
      if (!old) continue;
      if (old.version !== disposition.expectedVersion) issues.add('model_version', p, 'Disposition must match the exact current edge revision.');
      if (disposition.action === 'preserve') continue;
      const removed = disposition.action === 'tombstone' || disposition.action === 'replace';
      const source = (removed ? beforeEndpoints : finalEndpoints).get(old.sourceAssetId), endpoint = (removed ? beforeEndpoints : finalEndpoints).get(old.targetAssetId);
      if (!source || !endpoint) { issues.add('required', p, 'Both actual endpoint revisions are required.'); continue; }
      let values = old.values, pin = old.relationTypeVersion;
      if (disposition.action === 'repair' || disposition.action === 'repin') { values = disposition.values; if (disposition.action === 'repin') pin = disposition.targetVersion; }
      if (disposition.action === 'migrate') {
        const sourcePolicy = policies.get(policyKey(type, old.relationTypeVersion));
        if (!head || !sourcePolicy || !plan.transform) { issues.add('required', p, 'Migration requires all exact policies and its transform.'); continue; }
        const transformed = transformEdge(old, head, sourcePolicy, destination, plan.transform, issues, p); if (!transformed) continue;
        values = transformed; pin = targetVersion;
      }
      const after: GraphEdgeSnapshot = { ...old, version: old.version + 1, relationTypeVersion: pin, sourceAssetVersion: source.assetVersion, targetAssetVersion: endpoint.assetVersion, status: removed ? 'tombstoned' : 'active', values };
      expectedEdges.set(edgeKey(old), after);
      changedEdges.push({ key: old.key, beforeVersion: old.version, afterVersion: after.version, action: removed ? 'tombstone' : pin !== old.relationTypeVersion ? 'repin' : 'repair' });
      if (disposition.action === 'replace') replacements.push({ predecessorId: disposition.relationId, relationTypeId: type, creationKey: disposition.creationKey });
    }
    for (const [i, creation] of plan.creations.entries()) {
      const p = `${path}/plan/creations/${i}`, source = finalEndpoints.get(creation.sourceAssetId), endpoint = finalEndpoints.get(creation.targetAssetId);
      if (!source || !endpoint || beforeEndpoints.get(creation.sourceAssetId)?.assetVersion !== creation.sourceAssetVersion || beforeEndpoints.get(creation.targetAssetId)?.assetVersion !== creation.targetAssetVersion) issues.add('model_version', p, 'Creation must reference both exact pre-operation endpoint revisions.');
      const predecessor = plan.edges.find(row => row.action === 'replace' && row.creationKey === creation.key), old = predecessor && sourceEdges.find(row => row.key.kind === 'existing' && row.key.relationId === predecessor.relationId);
      if (!old && creation.values.state !== destination.definition.lifecycle.initial) issues.add('enum', `${p}/values/state`, 'An independent new assertion starts in the target initial state.');
      const edge: GraphEdgeSnapshot = { key: { kind: 'creation', relationTypeId: type, key: creation.key }, version: 1, relationTypeId: type, relationTypeVersion: targetVersion, sourceAssetId: creation.sourceAssetId, sourceAssetVersion: source?.assetVersion ?? creation.sourceAssetVersion, targetAssetId: creation.targetAssetId, targetAssetVersion: endpoint?.assetVersion ?? creation.targetAssetVersion, status: 'active', values: creation.values };
      expectedEdges.set(edgeKey(edge), edge); changedEdges.push({ key: edge.key, beforeVersion: null, afterVersion: 1, action: 'create' });
    }
    for (const [i, disposition] of plan.bindings.entries()) {
      const p = `${path}/plan/bindings/${i}`, old = sourceBindings.find(row => row.key.kind === 'existing' && row.key.bindingId === disposition.bindingId); if (!old) continue;
      if (old.version !== disposition.expectedVersion) issues.add('model_version', p, 'Disposition must match the exact current binding revision.');
      if (disposition.action === 'preserve') continue;
      const asset = (disposition.action === 'release' ? beforeEndpoints : finalEndpoints).get(old.assetId), finalAsset = finalEndpoints.get(old.assetId);
      if (!asset || !finalAsset) { issues.add('required', p, 'The actual binding asset revisions are required.'); continue; }
      const validSide = destination.definition.direction === 'directed' ? old.side !== 'incident' : old.side === 'incident';
      const minimum = old.side === 'target' ? destination.definition.cardinality.incoming.min : destination.definition.cardinality.outgoing.min;
      if (disposition.action === 'release' && validSide && minimum > 0 && eligible(finalAsset, destination.definition, old.side)) validationIssues.add('invalid_definition', p, 'An eligible required participant cannot release its obligation.');
      const after: GraphBindingSnapshot = { ...old, version: old.version + 1, relationTypeVersion: disposition.action === 'repin' ? disposition.targetVersion : old.relationTypeVersion, assetVersion: asset.assetVersion, status: disposition.action === 'release' ? 'released' : 'active' };
      expectedBindings.set(bindingKey(old), after); changedBindings.push({ key: old.key, beforeVersion: old.version, afterVersion: after.version, action: disposition.action });
    }
  }
  const computed: CompleteGraphSnapshot = { heads: [...finalHeads].map(([relationTypeId, version]) => ({ relationTypeId, version })).sort((a, b) => compare(a.relationTypeId, b.relationTypeId)), endpoints: proposedEndpoints, edges: [...expectedEdges.values()].sort((a, b) => compare(edgeKey(a), edgeKey(b))), bindings: [...expectedBindings.values()].sort((a, b) => compare(bindingKey(a), bindingKey(b))) };
  const required = deriveFromGraph(computed, policies, issues), targeted = new Set(changeSet.relationTargets.map(row => row.plan.relationTypeId));
  const activeIdentities = new Set(computed.bindings.filter(row => row.status === 'active').map(bindingIdentity));
  for (const row of required) if (!activeIdentities.has(bindingIdentity(row))) {
    if (!targeted.has(row.relationTypeId)) { validationIssues.add('required', '/migration/bindings', 'An untargeted type cannot be silently enrolled or repaired.'); continue; }
    const binding: GraphBindingSnapshot = { key: { kind: 'enrollment', relationTypeId: row.relationTypeId, assetId: row.assetId, side: row.side }, version: 1, relationTypeId: row.relationTypeId, relationTypeVersion: row.policyVersion, assetId: row.assetId, assetVersion: row.assetVersion, side: row.side, status: 'active' };
    expectedBindings.set(bindingKey(binding), binding); changedBindings.push({ key: binding.key, beforeVersion: null, afterVersion: 1, action: 'enroll' });
  }
  computed.bindings = [...expectedBindings.values()].sort((a, b) => compare(bindingKey(a), bindingKey(b)));
  return { computed, changedEdges, changedBindings, replacements, validationIssues: validationIssues.values };
}

type GraphProposalInput = {
  changeSet: GraphChangeSet; before: CompleteGraphSnapshot;
  policies: readonly RelationPolicySnapshot[]; preparedAssets: PreparedAssetChanges;
  proposedEndpoints: readonly RelationEndpointPolicyState[];
};
function constructGraphProposal(input: GraphProposalInput): ValidationResult<CompleteGraphSnapshot> {
  const issues = new Issues(), copied = copyJSON(input, issues);
  if (issues.values.length) return issues.result(undefined as never);
  const raw = fields(copied, '', ['changeSet', 'before', 'policies', 'preparedAssets', 'proposedEndpoints'], issues);
  if (!raw) return issues.result(undefined as never);
  const changeSet = changeSetFromJSON(raw.changeSet, issues), policies = policiesFromJSON(raw.policies, issues);
  const before = graphFromJSON(raw.before, '/before', issues);
  const projected = graphFromJSON({ heads: [], edges: [], bindings: [], endpoints: raw.proposedEndpoints }, '/proposed', issues);
  if (!changeSet || !before || !projected || issues.values.length) return issues.result(undefined as never);
  checkCapturedGraph(before, policies, issues);
  checkPreparedAssets(raw.preparedAssets, changeSet, before, projected, issues);
  if (issues.values.length) return issues.result(undefined as never);
  const { computed } = computeGraphProposal(changeSet, before, policies, projected.endpoints, issues);
  // Shape/version/retained resource bounds still apply even when final graph
  // cardinality, eligibility, participation or cycle constraints are unsatisfied.
  const result = graphFromJSON(computed, '/migration/proposal', issues);
  if (!result || issues.values.length) return issues.result(undefined as never);
  if (encoder.encode(canonical(copied)).length + encoder.encode(canonical(result)).length > RELATION_LIMITS.bytes)
    issues.add('limit', '/migration/proposal', 'The input and proposed graph exceed the aggregate UTF-8 budget.');
  return issues.result(freeze(result));
}

/** Construct a deterministic, tagged preview candidate. Success means only that
 * the complete proposal could be derived, never that it is valid or executable.
 * The service must independently prepare asset transformations and then call
 * validateRelationGraphChange with current authorization and principal evidence. */
export function constructRelationGraphProposal(input: GraphProposalInput): ValidationResult<CompleteGraphSnapshot> {
  try { return constructGraphProposal(input); }
  catch { return { ok: false, issues: [{ code: 'invalid_definition', path: '/migration/proposal', message: 'The complete proposal envelope is malformed.' }] }; }
}

function validateGraphChange(input: AuthorizedCompleteGraphChange): ValidationResult<ValidatedGraphChange> {
  const issues = new Issues(), copied = copyJSON(input, issues, RELATION_LIMITS.bytes, true);
  if (issues.values.length) return issues.result(undefined as never);
  const raw = fields(copied, '', ['changeSet', 'completeRelationTypeIds', 'policies', 'preparedAssets', 'before', 'proposed', 'activeOwnerIds', 'tenantMemberIds', 'actorId'], issues);
  if (!raw) return issues.result(undefined as never);
  const changeSet = changeSetFromJSON(raw.changeSet, issues), policies = policiesFromJSON(raw.policies, issues), before = graphFromJSON(raw.before, '/before', issues), proposed = graphFromJSON(raw.proposed, '/proposed', issues);
  const activity = new Set<string>(), members = new Set<string>(), complete = new Set<string>();
  for (const [name, destination] of [['activeOwnerIds', activity], ['tenantMemberIds', members], ['completeRelationTypeIds', complete]] as const) for (const [i, value] of list(raw[name], `/${name}`, name === 'completeRelationTypeIds' ? 5000 : 2001, issues).entries()) {
    if (!id(value, `/${name}/${i}`, issues)) continue;
    if (destination.has(value)) issues.add('duplicate', `/${name}/${i}`, 'Identities occur once.'); destination.add(value);
  }
  id(raw.actorId, '/actorId', issues);
  if (!changeSet || !before || !proposed || issues.values.length) return issues.result(undefined as never);
  if (!members.has(raw.actorId as string) || [...activity].some(owner => !members.has(owner))) issues.add('required', '/tenantMemberIds', 'The actor and active owners must occur in the established member set.');
  const principalUnion = new Set([raw.actorId as string, ...activity, ...members]);
  if (principalUnion.size > 2001) issues.add('limit', '/tenantMemberIds', 'The aggregate principal union exceeds its bound.');
  checkPreparedAssets(raw.preparedAssets, changeSet, before, proposed, issues);
  if (issues.values.length) return issues.result(undefined as never);
  const beforeHeads = new Map(before.heads.map(row => [row.relationTypeId, row.version]));
  const expectedTypes = new Set([...beforeHeads.keys(), ...changeSet.relationTargets.map(row => row.plan.relationTypeId)]);
  if (canonical([...expectedTypes].sort()) !== canonical([...complete].sort())) issues.add('invalid_definition', '/completeRelationTypeIds', 'Complete logical type scope must equal all current and explicit target types.');
  checkCapturedGraph(before, policies, issues);
  const sourceIssues: RepairableRelationSourceIssue[] = [];
  for (const [i, edge] of before.edges.entries()) {
    const policy = policies.get(policyKey(edge.relationTypeId, edge.relationTypeVersion));
    if (policy) checkValues(edge, policy, activity, members, raw.actorId as string, issues, `/migration/source/edges/${i}`, 'source', sourceIssues);
  }
  const { computed, changedEdges, changedBindings, replacements, validationIssues } =
    computeGraphProposal(changeSet, before, policies, proposed.endpoints, issues);
  issues.append('', validationIssues);
  if (canonical(computed) !== canonical(proposed)) issues.add('invalid_definition', '/migration/proposed', 'The proposed graph must exactly equal the complete deterministic plan and prepared endpoint projection.');
  const changedKeys = new Set(changedEdges.map(row => canonical(row.key)));
  for (const [i, edge] of computed.edges.entries()) if (edge.status === 'active') {
    const policy = policies.get(policyKey(edge.relationTypeId, edge.relationTypeVersion)); if (!policy) { issues.add('required', `/migration/final/edges/${i}`, 'Exact final pinned policy is required.'); continue; }
    checkValues(edge, policy, activity, members, raw.actorId as string, issues, `/migration/final/edges/${i}`, changedKeys.has(canonical(edge.key)) ? 'changed' : 'preserved', []);
    const publication = changeSet.relationTargets.find(target => target.kind === 'publish' && target.plan.relationTypeId === edge.relationTypeId);
    if (publication?.kind === 'publish' && edge.relationTypeVersion !== publication.definition.version) {
      const target = policies.get(policyKey(edge.relationTypeId, publication.definition.version));
      if (target) checkValues(edge, target, activity, members, raw.actorId as string, issues, `/migration/targetCompatibility/edges/${i}`, changedKeys.has(canonical(edge.key)) ? 'changed' : 'preserved', []);
    }

  }
  for (const target of changeSet.relationTargets) if (target.kind === 'repair' && !changedEdges.some(row => { const edge = computed.edges.find(edge => canonical(edge.key) === canonical(row.key)); return edge?.relationTypeId === target.plan.relationTypeId; }) && !changedBindings.some(row => { const binding = computed.bindings.find(binding => canonical(binding.key) === canonical(row.key)); return binding?.relationTypeId === target.plan.relationTypeId; })) issues.add('invalid_definition', '/migration/relationTargets', 'A repair with only preserved rows and no enrollment is a no-op.');
  const finalParticipation = checkFinalGraph(computed, policies, issues);
  if (computed.edges.filter(row => row.status === 'active').length > 1000 || computed.bindings.filter(row => row.status === 'active').length > 4000) issues.add('limit', '/migration/proposed', 'The final graph exceeds its active resource bound.');
  const result: ValidatedGraphChange = { final: computed, requiredParticipation: finalParticipation, sourceIssues: sourceIssues.sort((a, b) => compare(a.relationId, b.relationId)), changedEdges: changedEdges.sort((a, b) => compare(canonical(a.key), canonical(b.key))), changedBindings: changedBindings.sort((a, b) => compare(canonical(a.key), canonical(b.key))), replacements: replacements.sort((a, b) => compare(a.predecessorId, b.predecessorId)) };
  if (encoder.encode(canonical(copied)).length + encoder.encode(canonical(result)).length > RELATION_LIMITS.bytes) issues.add('limit', '/migration', 'The normalized result exceeds the aggregate UTF-8 budget.');
  return issues.result(freeze(result));
}

/** Malformed trusted-boundary envelopes still fail closed; no accessor is ever evaluated. */
export function validateRelationGraphChange(input: AuthorizedCompleteGraphChange): ValidationResult<ValidatedGraphChange> {
  try { return validateGraphChange(input); }
  catch { return { ok: false, issues: [{ code: 'invalid_definition', path: '/migration', message: 'The complete prepared graph envelope is malformed.' }] }; }
}
