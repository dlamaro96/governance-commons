// SPDX-License-Identifier: Apache-2.0
import { createHash } from 'node:crypto';
import { parseModelDefinition, previewModelUpgrade, validateAttributes,
  type ValidationIssue, type ValidationIssueCode, type ValidationResult } from './model.ts';
import { parseAssetTypeDefinition, type ResolvedAssetType } from './asset-type.ts';
import { validateAssetTypeMigrationPlan, applyAssetTypeMigrationPolicy } from './asset-type-migration.ts';
import { applyModelMigrationToAttributes } from './model-migration.ts';
import type { TypePolicyChange } from './asset-type-migration-contracts.ts';
import type { GraphAssetPreparationInput, GraphAssetBefore, GraphAssetPolicyEvidence, GraphAssetPolicyRef,
  PreparedAssetChanges, PreparedGraphAssetChange, PreparedTypeMigration } from './relation-migration-contracts.ts';

/** Deterministic projection only. The caller verifies stored ancestry, complete scope and locked activity. */
const LIMIT = { bytes: 524_288, nodes: 100_000, depth: 32, assets: 1_000, principals: 2_001, targets: 8 } as const;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const identifier = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const malformed = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const encoder = new TextEncoder();
class Invalid extends Error {
  constructor(readonly issues: readonly ValidationIssue[]) { super('Invalid graph asset preparation'); }
}
function fail(code: ValidationIssueCode, path: string, message: string): never { throw new Invalid([{ code, path, message }]); }
function need(ok: unknown, code: ValidationIssueCode, path: string, message: string): asserts ok { if (!ok) fail(code, path, message); }
function checked<T>(result: ValidationResult<T>, prefix: string): T {
  if (result.ok) return result.value;
  const issues = result.issues.slice(0, 99).map(issue => ({ ...issue, path: prefix + issue.path }));
  if (result.issues.length > 99) issues.push({ code: 'limit', path: prefix, message: 'The issue budget was exceeded.' });
  throw new Invalid(issues);
}
function canonical(value: any): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
const equal = (left: unknown, right: unknown): boolean => canonical(left) === canonical(right);
const hash = (value: unknown): string => createHash('sha256').update(canonical(value)).digest('hex');
const pin = (value: GraphAssetPolicyRef): string => `${value.modelId}:${value.modelVersion}`;
const compare = (a: string, b: string): number => a < b ? -1 : a > b ? 1 : 0;
function version(value: unknown, path: string): asserts value is number {
  need(Number.isInteger(value) && Number(value) >= 1 && Number(value) <= 2_147_483_647 && typeof value === 'number', 'model_version', path, 'Expected a positive database version.');
}
function id(value: unknown, path: string): asserts value is string { need(typeof value === 'string' && uuid.test(value), 'format', path, 'Expected a canonical UUID.'); }
function key(value: unknown, path: string): asserts value is string {
  need(typeof value === 'string' && identifier.test(value) && !['__proto__', 'constructor', 'prototype'].includes(value), 'format', path, 'Expected a safe identifier.');
}
function fields(value: any, names: readonly string[], path: string): void {
  need(value !== null && typeof value === 'object' && !Array.isArray(value), 'type', path, 'Expected an object.');
  for (const name of Object.keys(value)) need(names.includes(name), 'unknown_field', path + '/' + name, 'Unknown preparation field.');
  for (const name of names) need(Object.hasOwn(value, name), 'required', path + '/' + name, 'Required field is missing.');
}
function array(value: any, maximum: number, path: string): void {
  need(Array.isArray(value), 'type', path, 'Expected an array.');
  need(value.length <= maximum, 'limit', path, 'The complete projection exceeds its collection bound.');
}
function ref(value: any, path: string): asserts value is GraphAssetPolicyRef {
  fields(value, ['modelId', 'modelVersion'], path); key(value.modelId, path + '/modelId'); version(value.modelVersion, path + '/modelVersion');
}
function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

/** Never invoke accessors/toJSON or a supplied Set iterator/has method. */
function copyInput(input: unknown): { data: Omit<GraphAssetPreparationInput, 'activeOwnerIds'>; active: ReadonlySet<string> } {
  need(input && typeof input === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(input)), 'invalid_json', '', 'Expected plain input data.');
  const names = ['assetChanges', 'typeMigrations', 'before', 'policies', 'modelHeads', 'activeOwnerIds'];
  const outer = new Map<string, unknown>();
  for (const name of Reflect.ownKeys(input)) {
    need(typeof name === 'string' && names.includes(name), 'unknown_field', '', 'Unknown input field.');
    const descriptor = Object.getOwnPropertyDescriptor(input, name);
    need(descriptor?.enumerable && Object.hasOwn(descriptor, 'value'), 'invalid_json', '/' + name, 'Expected enumerable data properties.');
    outer.set(name, descriptor.value);
  }
  for (const name of names) need(outer.has(name), 'required', '/' + name, 'Required input is missing.');
  let size: number;
  try { size = Object.getOwnPropertyDescriptor(Set.prototype, 'size')!.get!.call(outer.get('activeOwnerIds')); }
  catch { return fail('invalid_json', '/activeOwnerIds', 'Expected a native owner-activity set.'); }
  need(size <= LIMIT.principals, 'limit', '/activeOwnerIds', 'The principal union exceeds its bound.');
  const active = new Set<string>();
  Set.prototype.forEach.call(outer.get('activeOwnerIds'), (value: unknown) => { id(value, '/activeOwnerIds'); active.add(value); });
  outer.delete('activeOwnerIds');
  let bytes = 0, nodes = 0; const visiting = new Set<object>();
  const charge = (n: number, path: string) => { bytes += n; need(bytes <= LIMIT.bytes, 'limit', path, 'The aggregate preparation byte budget was exceeded.'); };
  const copy = (value: unknown, path: string, depth: number): any => {
    need(++nodes <= LIMIT.nodes && depth <= LIMIT.depth, 'limit', path, 'The preparation node/depth budget was exceeded.');
    if (value === null || typeof value === 'boolean') { charge(value === null ? 4 : value ? 4 : 5, path); return value; }
    if (typeof value === 'number') {
      need(Number.isFinite(value) && !Object.is(value, -0), 'invalid_json', path, 'Expected a finite JSON number.'); charge(String(value).length, path); return value;
    }
    if (typeof value === 'string') {
      need(value.length <= LIMIT.bytes, 'limit', path, 'The string exceeds the aggregate byte budget.');
      need(!malformed.test(value), 'format', path, 'Expected well-formed Unicode.'); charge(encoder.encode(JSON.stringify(value)).length, path); return value;
    }
    need(value && typeof value === 'object', 'invalid_json', path, 'Expected JSON data.');
    need(!visiting.has(value), 'cycle', path, 'Cyclic input is not permitted.');
    const isArray = Array.isArray(value);
    need(isArray ? Object.getPrototypeOf(value) === Array.prototype : [Object.prototype, null].includes(Object.getPrototypeOf(value)), 'invalid_json', path, 'Expected a plain JSON container.');
    if (isArray) need(value.length <= LIMIT.nodes, 'limit', path, 'The array exceeds the node budget.');
    const keys = Reflect.ownKeys(value);
    need(keys.length <= LIMIT.nodes, 'limit', path, 'The property budget was exceeded.');
    if (isArray) need(keys.length === value.length + 1, 'invalid_json', path, 'Sparse arrays and extra properties are not permitted.');
    const output = new Map<string, unknown>(); visiting.add(value); charge(2 + Math.max(0, keys.length - (isArray ? 2 : 1)), path);
    for (const name of keys) {
      if (isArray && name === 'length') continue;
      need(typeof name === 'string' && !['__proto__', 'constructor', 'prototype'].includes(name), 'invalid_json', path, 'Unsafe JSON key.');
      need(name.length <= LIMIT.bytes, 'limit', path, 'The JSON key exceeds the byte budget.');
      if (isArray) need(/^(0|[1-9][0-9]*)$/.test(name) && Number(name) < value.length, 'invalid_json', path, 'Invalid array property.');
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      need(descriptor?.enumerable && Object.hasOwn(descriptor, 'value'), 'invalid_json', path + '/' + name, 'Expected enumerable data properties.');
      if (!isArray) charge(encoder.encode(JSON.stringify(name)).length + 1, path);
      output.set(name, copy(descriptor.value, path + '/' + name, depth + 1));
    }
    visiting.delete(value); return isArray ? Array.from(output.values()) : Object.fromEntries(output);
  };
  return { data: copy(Object.fromEntries(outer), '', 0), active };
}

function policyModel(policy: GraphAssetPolicyEvidence) { return policy.kind === 'authored' ? policy.resolution.model : policy.model; }
function validatePolicy(value: any, path: string): GraphAssetPolicyEvidence {
  need(value?.kind === 'attributes' || value?.kind === 'authored', 'enum', path + '/kind', 'Unknown asset policy kind.');
  if (value.kind === 'attributes') {
    fields(value, ['kind', 'model', 'definitionHash'], path);
    const model = checked(parseModelDefinition(value.model), path + '/model'); version(model.version, path + '/model/version');
    need(value.definitionHash === hash(model), 'invalid_definition', path + '/definitionHash', 'The exact model hash does not match.');
    return { kind: 'attributes', model, definitionHash: value.definitionHash };
  }
  fields(value, ['kind', 'typeId', 'resolution', 'definitionHash', 'resolutionHash', 'ancestorTypes'], path); id(value.typeId, path + '/typeId');
  fields(value.resolution, ['definition', 'dependencies', 'model', 'requiredOwner', 'lifecycle'], path + '/resolution');
  const r = value.resolution;
  const definition = checked(parseAssetTypeDefinition(r.definition), path + '/resolution/definition');
  const model = checked(parseModelDefinition(r.model), path + '/resolution/model'); version(model.version, path + '/resolution/model/version');
  const effective = checked(parseAssetTypeDefinition({ ...definition, parents: [], attributes: {}, overrideAttributes: [], requiredOwner: r.requiredOwner, lifecycle: r.lifecycle }), path + '/resolution');
  need(effective.lifecycle && definition.id === model.id && definition.version === model.version, 'model_identity', path, 'Resolved identity/policy is inconsistent.');
  need(!definition.requiredOwner || r.requiredOwner, 'invalid_definition', path, 'Required ownership was weakened in the resolution.');
  need(definition.lifecycle === null || equal(definition.lifecycle, effective.lifecycle), 'invalid_definition', path, 'An explicit lifecycle cannot change during resolution.');
  array(r.dependencies, 64, path + '/resolution/dependencies'); array(value.ancestorTypes, 64, path + '/ancestorTypes');
  const dependencies = new Map<string, number>();
  for (const dep of r.dependencies) {
    fields(dep, ['id', 'version'], path + '/resolution/dependencies'); key(dep.id, path); version(dep.version, path);
    need(dep.id !== model.id && !dependencies.has(dep.id), 'duplicate', path, 'The exact ancestor closure contains a duplicate or self pin.'); dependencies.set(dep.id, dep.version);
  }
  for (const parent of definition.parents) need(dependencies.get(parent.id) === parent.version, 'required', path, 'A direct parent is missing from exact dependencies.');
  const ancestors = new Set<string>(), identities = new Set<string>([value.typeId]);
  for (const ancestor of value.ancestorTypes) {
    fields(ancestor, ['typeId', 'id', 'version'], path + '/ancestorTypes'); id(ancestor.typeId, path); key(ancestor.id, path); version(ancestor.version, path);
    need(dependencies.get(ancestor.id) === ancestor.version && !ancestors.has(ancestor.id) && !identities.has(ancestor.typeId), 'invalid_definition', path + '/ancestorTypes', 'Ancestor identities must equal the exact dependency closure.');
    ancestors.add(ancestor.id); identities.add(ancestor.typeId);
  }
  need(ancestors.size === dependencies.size, 'required', path + '/ancestorTypes', 'Every pinned ancestor needs its nominal identity.');
  const resolution: ResolvedAssetType = { definition, dependencies: r.dependencies, model, requiredOwner: effective.requiredOwner, lifecycle: effective.lifecycle };
  need(value.definitionHash === hash(definition) && value.resolutionHash === hash(resolution), 'invalid_definition', path, 'The immutable policy hashes do not match their data.');
  return { kind: 'authored', typeId: value.typeId, resolution, definitionHash: value.definitionHash, resolutionHash: value.resolutionHash, ancestorTypes: value.ancestorTypes };
}

export function projectGraphAssetChanges(input: GraphAssetPreparationInput): ValidationResult<PreparedAssetChanges> {
  try {
    const { data, active } = copyInput(input);
    array(data.assetChanges, LIMIT.assets, '/assetChanges'); array(data.typeMigrations, LIMIT.targets, '/typeMigrations');
    array(data.before, LIMIT.assets, '/before'); array(data.policies, LIMIT.nodes, '/policies'); array(data.modelHeads, LIMIT.nodes, '/modelHeads');
    const heads = new Map<string, number>();
    for (const row of data.modelHeads) {
      fields(row, ['modelId', 'version'], '/modelHeads'); key(row.modelId, '/modelHeads'); version(row.version, '/modelHeads');
      need(!heads.has(row.modelId), 'duplicate', '/modelHeads', 'Each logical model has one current head.'); heads.set(row.modelId, row.version);
    }
    const policies = new Map<string, GraphAssetPolicyEvidence>(), identities = new Map<string, string>();
    for (const [index, candidate] of data.policies.entries()) {
      const policy = validatePolicy(candidate, `/policies/${index}`), model = policyModel(policy), name = `${model.id}:${model.version}`;
      need(!policies.has(name), 'duplicate', `/policies/${index}`, 'Each exact policy must occur once.');
      need(heads.has(model.id), 'required', `/policies/${index}`, 'The actual current head is required for each policy.');
      const identity = policy.kind === 'authored' ? policy.typeId : 'attributes';
      need(!identities.has(model.id) || identities.get(model.id) === identity, 'model_identity', `/policies/${index}`, 'Logical model identity cannot change between pins.');
      identities.set(model.id, identity); policies.set(name, policy);
    }
    const getPolicy = (reference: GraphAssetPolicyRef, path: string): GraphAssetPolicyEvidence => {
      ref(reference, path); const found = policies.get(pin(reference)); need(found, 'required', path, 'The exact immutable policy evidence is missing.'); return found;
    };
    const before = new Map<string, GraphAssetBefore>();
    for (const row of data.before) {
      fields(row, ['assetId', 'assetVersion', 'tuple', 'policy'], '/before'); id(row.assetId, '/before/assetId'); version(row.assetVersion, '/before/assetVersion');
      need(row.assetVersion < 2_147_483_647, 'limit', '/before/assetVersion', 'The asset revision range is exhausted.');
      need(!before.has(row.assetId), 'duplicate', '/before', 'The complete before cohort must contain each asset once.');
      fields(row.tuple, ['modelId', 'modelVersion', 'attributes', 'ownerId', 'state'], '/before/tuple');
      need(row.tuple.attributes && typeof row.tuple.attributes === 'object' && !Array.isArray(row.tuple.attributes), 'type', '/before/tuple/attributes', 'Expected an attribute object.');
      if (row.tuple.ownerId !== null) id(row.tuple.ownerId, '/before/tuple/ownerId');
      if (row.policy === null) need(row.tuple.modelId === null && row.tuple.modelVersion === null && row.tuple.state === null, 'model_identity', '/before/tuple', 'Untyped assets have null model and state pins.');
      else {
        const policy = getPolicy(row.policy, '/before/policy');
        need(row.policy.modelId === row.tuple.modelId && row.policy.modelVersion === row.tuple.modelVersion && row.policy.modelVersion <= heads.get(row.policy.modelId)!, 'model_identity', '/before/tuple', 'The actual before tuple must retain its exact source pin.');
        if (policy.kind === 'attributes') need(row.tuple.state === null, 'enum', '/before/tuple/state', 'Attribute-only models have no lifecycle state.');
        else key(row.tuple.state, '/before/tuple/state');
      }
      before.set(row.assetId, row);
    }
    const changes: PreparedGraphAssetChange[] = [], migrations: PreparedTypeMigration[] = [], claimed = new Set<string>(), migratedModels = new Set<string>();
    const claim = (assetId: string, path: string): GraphAssetBefore => {
      id(assetId, path); need(!claimed.has(assetId), 'duplicate', path, 'An asset may occur in only one direct change or complete typed cohort.');
      const row = before.get(assetId); need(row, 'required', path, 'An actual before tuple is required.'); claimed.add(assetId); return row;
    };
    for (const [index, change] of data.assetChanges.entries()) {
      const path = `/assetChanges/${index}`;
      need(change?.kind === 'assign' || change?.kind === 'transition', 'enum', path + '/kind', 'Unknown asset operation.');
      fields(change, change.kind === 'assign' ? ['kind', 'assetId', 'expectedVersion', 'modelId', 'modelVersion', 'attributes', 'ownerId'] : ['kind', 'assetId', 'expectedVersion', 'state'], path);
      const row = claim(change.assetId, path + '/assetId'); version(change.expectedVersion, path + '/expectedVersion');
      need(change.expectedVersion === row.assetVersion, 'model_version', path + '/expectedVersion', 'The expected asset revision is stale.');
      let after = { ...row.tuple }, targetPolicy = row.policy;
      if (change.kind === 'assign') {
        need(change.ownerId === row.tuple.ownerId, 'invalid_definition', path + '/ownerId', 'Assignment must preserve the actual current owner.');
        targetPolicy = { modelId: change.modelId, modelVersion: change.modelVersion }; const target = getPolicy(targetPolicy, path);
        need(change.modelVersion <= heads.get(change.modelId)!, 'model_version', path + '/modelVersion', 'Assignment requires an already published exact model pin.');
        const attributes = checked(validateAttributes(policyModel(target), change.attributes), path + '/attributes');
        const state = target.kind === 'authored' ? row.tuple.modelId === change.modelId && row.tuple.state ? row.tuple.state : target.resolution.lifecycle.initial : null;
        if (target.kind === 'authored') {
          need(!target.resolution.requiredOwner || row.tuple.ownerId !== null && active.has(row.tuple.ownerId), 'required', path + '/ownerId', 'The target requires an active owner.');
          need(target.resolution.lifecycle.states.includes(state!), 'enum', path + '/state', 'The preserved state must exist in the exact selected lifecycle.');
        }
        after = { modelId: change.modelId, modelVersion: change.modelVersion, attributes, ownerId: row.tuple.ownerId, state };
      } else {
        key(change.state, path + '/state'); need(row.policy, 'required', path, 'An authored type pin is required for a transition.');
        const policy = getPolicy(row.policy, path); need(policy.kind === 'authored', 'invalid_definition', path, 'Attribute-only models have no lifecycle transitions.');
        need(policy.resolution.lifecycle.states.includes(row.tuple.state!) && policy.resolution.lifecycle.transitions.some(step => step.from === row.tuple.state && step.to === change.state), 'enum', path + '/state', 'The requested pinned lifecycle transition is not allowed.');
        need(!policy.resolution.requiredOwner || row.tuple.ownerId !== null && active.has(row.tuple.ownerId), 'required', path + '/ownerId', 'Ordinary transitions cannot repair an invalid required owner.');
        after = { ...after, state: change.state };
      }
      changes.push({ kind: change.kind, assetId: row.assetId, fromAssetVersion: row.assetVersion, toAssetVersion: row.assetVersion + 1,
        before: row.tuple, after, sourcePolicy: row.policy, targetPolicy, sourceIssues: [] });
    }
    for (const [index, migration] of data.typeMigrations.entries()) {
      const path = `/typeMigrations/${index}`;
      fields(migration, ['typeId', 'modelId', 'expectedHeadVersion', 'headPolicy', 'targetPolicy', 'sourcePolicies', 'plan', 'assetIds'], path);
      id(migration.typeId, path + '/typeId'); key(migration.modelId, path + '/modelId'); version(migration.expectedHeadVersion, path + '/expectedHeadVersion');
      need(!migratedModels.has(migration.modelId), 'duplicate', path, 'Each logical type has at most one publication.'); migratedModels.add(migration.modelId);
      need(heads.get(migration.modelId) === migration.expectedHeadVersion, 'model_version', path, 'The current head changed.');
      const head = getPolicy(migration.headPolicy, path + '/headPolicy'), target = getPolicy(migration.targetPolicy, path + '/targetPolicy');
      need(head.kind === 'authored' && target.kind === 'authored' && head.typeId === migration.typeId && target.typeId === migration.typeId &&
        head.resolution.model.id === migration.modelId && target.resolution.model.id === migration.modelId &&
        head.resolution.model.version === migration.expectedHeadVersion && target.resolution.model.version === migration.expectedHeadVersion + 1,
      'model_identity', path, 'The head and successor must have the exact authored identity and versions.');
      array(migration.assetIds, LIMIT.assets, path + '/assetIds'); array(migration.sourcePolicies, LIMIT.assets, path + '/sourcePolicies');
      const expectedIds = [...before.values()].filter(row => row.tuple.modelId === migration.modelId).map(row => row.assetId).sort(compare);
      need(equal([...migration.assetIds].sort(compare), expectedIds), 'invalid_definition', path + '/assetIds', 'A complete typed cohort cannot omit a matching before asset or overlap a direct change.');
      const rows = migration.assetIds.map(assetId => claim(assetId, path + '/assetIds')).sort((a, b) => compare(a.assetId, b.assetId));
      for (const row of rows) need(row.policy?.modelId === migration.modelId, 'model_identity', path, 'Every cohort member must retain the migrated logical type.');
      const versions = [...new Set(rows.map(row => row.policy!.modelVersion))].sort((a, b) => a - b);
      need(equal(migration.sourcePolicies, versions.map(modelVersion => ({ modelId: migration.modelId, modelVersion }))), 'model_version', path + '/sourcePolicies', 'Source evidence references must exactly cover actual distinct cohort pins.');
      const sources = migration.sourcePolicies.map(reference => {
        const source = getPolicy(reference, path + '/sourcePolicies'); need(source.kind === 'authored' && source.typeId === migration.typeId, 'model_identity', path, 'Each source must preserve nominal type identity.'); return source.resolution;
      });
      const plan = checked(validateAssetTypeMigrationPlan({ typeId: migration.typeId, head: head.resolution, target: target.resolution, sources,
        cohort: rows.map(row => ({ assetId: row.assetId, sourceVersion: row.policy!.modelVersion })) }, migration.plan), path + '/plan');
      for (const row of rows) {
        const source = getPolicy(row.policy!, path) as Extract<GraphAssetPolicyEvidence, { kind: 'authored' }>;
        const attributes = checked(applyModelMigrationToAttributes({ head: head.resolution.model, source: source.resolution.model, target: target.resolution.model, plan: plan.attributes, attributes: row.tuple.attributes }), path + '/assets/' + row.assetId);
        const values = checked(applyAssetTypeMigrationPolicy({ source: source.resolution, target: target.resolution, plan,
          asset: { assetId: row.assetId, modelVersion: row.tuple.modelVersion!, ownerId: row.tuple.ownerId, state: row.tuple.state }, activeOwnerIds: active }), path + '/assets/' + row.assetId);
        changes.push({ kind: 'type-migrate', assetId: row.assetId, fromAssetVersion: row.assetVersion, toAssetVersion: row.assetVersion + 1,
          before: row.tuple, after: { modelId: migration.modelId, modelVersion: target.resolution.model.version, attributes, ownerId: values.ownerId, state: values.state },
          sourcePolicy: row.policy, targetPolicy: migration.targetPolicy, sourceIssues: values.sourceIssues });
      }
      const diff = checked(previewModelUpgrade(head.resolution.model, target.resolution.model, []), path);
      const policyChanges: TypePolicyChange[] = [];
      if (!equal(head.resolution.definition.parents, target.resolution.definition.parents)) policyChanges.push('parents_changed');
      if (head.resolution.requiredOwner !== target.resolution.requiredOwner) policyChanges.push('required_owner_changed');
      if (!equal(head.resolution.lifecycle, target.resolution.lifecycle)) policyChanges.push('lifecycle_changed');
      migrations.push({ ...migration, plan, assetIds: rows.map(row => row.assetId), changes: diff.changes, policyChanges: policyChanges.sort() });
    }
    need(claimed.size === before.size, 'invalid_definition', '/before', 'The before tuple set must exactly equal all declared affected assets.');
    need(changes.length <= LIMIT.assets, 'limit', '/changes', 'The aggregate changed-asset count exceeds the profile.');
    const output: PreparedAssetChanges = { policies: [...policies.values()].sort((a, b) => compare(policyModel(a).id, policyModel(b).id) || policyModel(a).version - policyModel(b).version),
      changes: changes.sort((a, b) => compare(a.assetId, b.assetId)), typeMigrations: migrations.sort((a, b) => compare(a.modelId, b.modelId)) };
    need(encoder.encode(JSON.stringify(output)).length <= LIMIT.bytes, 'limit', '', 'The complete prepared projection exceeds its byte bound.');
    return { ok: true, value: freeze(output) };
  } catch (error) {
    if (error instanceof Invalid) return { ok: false, issues: error.issues };
    return { ok: false, issues: [{ code: 'invalid_json', path: '', message: 'Preparation data could not be read safely.' }] };
  }
}
