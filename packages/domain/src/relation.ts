// SPDX-License-Identifier: Apache-2.0
import { MODEL_LIMITS, parseBoundedJSONFile, parseModelDefinition, previewModelUpgrade, validateAttributes,
  type ValidationIssue, type ValidationIssueCode, type ValidationResult } from './model.ts';
import { parseAssetTypeDefinition } from './asset-type.ts';
import type { AuthorizedRelationTraversalInput, RelationConstraintEdge, RelationEndpointChangesInput,
  RelationEndpointPolicyState, RelationEndpointRule, RelationEndpointValidationInput, RelationEndpointView,
  RelationNeighborhood, RelationPolicyPin, RelationStructureInput, RelationTypeDefinition, RelationUpgradeInput,
  RelationUpgradeResult, RelationView, ResolvedRelationType } from './relation-contracts.ts';
export type { RelationTypeDefinition } from './relation-contracts.ts';

/** Pure bounded checks only. Services establish current authority, locks and complete database scope. */
export const RELATION_LIMITS = Object.freeze({ definitionBytes: 262_144, bytes: 524_288, nodes: 100_000, depth: 32,
  issues: 100, endpointRules: 32, states: 32, maximumDegree: 1_000, mutationEdges: 1_000,
  endpointAssets: 2_000, graphNodes: 1_000, graphEdges: 5_000, graphDepth: 6 });
type Fields = Record<string, unknown>;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const identifier = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const reserved = new Set(['__proto__', 'constructor', 'prototype']);
const malformedUnicode = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const encoder = new TextEncoder();
const at = (path: string, key: string | number) => `${path}/${String(key).replaceAll('~', '~0').replaceAll('/', '~1')}`;
const compare = (a: string, b: string) => a < b ? -1 : a > b ? 1 : 0;
class Issues {
  readonly values: ValidationIssue[] = [];
  overflow = false;
  add(code: ValidationIssueCode, path: string, message: string): void {
    if (this.values.length < RELATION_LIMITS.issues - 1) this.values.push({ code, path, message }); else this.overflow = true;
  }
  append(prefix: string, values: readonly ValidationIssue[]): void { for (const issue of values) this.add(issue.code, prefix + issue.path, issue.message); }
  result<T>(value: T): ValidationResult<T> {
    if (this.overflow && this.values.length < RELATION_LIMITS.issues) this.values.push({ code: 'limit', path: '', message: 'The issue budget was exceeded.' });
    return this.values.length ? { ok: false, issues: this.values } : { ok: true, value };
  }
}
function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
}
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical((value as Fields)[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
/** Never invoke an input getter/toJSON. Sets are accepted only for the explicitly trusted activity input. */
function copyJSON(input: unknown, issues: Issues, maximumBytes: number = RELATION_LIMITS.bytes, ownerSet = false): unknown {
  const active = new Set<object>(); let nodes = 0, bytes = 0, exhausted = false;
  const charge = (size: number, path: string) => {
    bytes += size; if (bytes <= maximumBytes) return true;
    if (!exhausted) issues.add('limit', path, 'The aggregate UTF-8 JSON byte budget was exceeded.'); exhausted = true; return false;
  };
  const copy = (value: unknown, path: string, depth: number): unknown => {
    if (exhausted || issues.overflow) return;
    if (++nodes > RELATION_LIMITS.nodes || depth > RELATION_LIMITS.depth) { issues.add('limit', path, 'The aggregate node or depth budget was exceeded.'); exhausted = true; return; }
    if (value === null) { charge(4, path); return null; }
    if (typeof value === 'string') {
      if (value.length > MODEL_LIMITS.stringLength) { issues.add('limit', path, 'String length exceeds its supported bound.'); return; }
      if (malformedUnicode.test(value)) issues.add('format', path, 'Expected well-formed Unicode.');
      charge(encoder.encode(JSON.stringify(value)).length, path); return value;
    }
    if (typeof value === 'number') {
      if (!Number.isFinite(value) || Object.is(value, -0)) issues.add('type', path, 'Expected a finite JSON number without negative zero.');
      charge(String(value).length, path); return value;
    }
    if (typeof value === 'boolean') { charge(value ? 4 : 5, path); return value; }
    if (!value || typeof value !== 'object') { issues.add('invalid_json', path, 'Only JSON data properties are supported.'); return; }
    if (ownerSet && path === '/activeOwnerIds') {
      // Native methods avoid overridden iterators, has(), size or own getters.
      const size = Object.getOwnPropertyDescriptor(Set.prototype, 'size')!.get!.call(value) as number;
      if (size > RELATION_LIMITS.endpointAssets + 1) { issues.add('limit', path, 'The owner activity input exceeds its bound.'); return; }
      return copy(Array.from(Set.prototype.values.call(value) as SetIterator<unknown>), `${path}/values`, depth + 1);
    }
    if (active.has(value)) { issues.add('cycle', path, 'JSON data cannot contain cycles.'); return; }
    const isArray = Array.isArray(value);
    if (isArray ? Object.getPrototypeOf(value) !== Array.prototype : ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
      issues.add('invalid_json', path, 'Expected plain JSON objects and arrays.'); return;
    }
    const keys = Reflect.ownKeys(value);
    if (isArray && (value.length > RELATION_LIMITS.graphEdges || keys.length !== value.length + 1)) {
      issues.add(value.length > RELATION_LIMITS.graphEdges ? 'limit' : 'invalid_json', path, 'Array must be bounded, dense and have no extra properties.'); return;
    }
    if (!isArray && keys.length > MODEL_LIMITS.properties) { issues.add('limit', path, 'Object property count exceeds its bound.'); return; }
    const selected = isArray ? Array.from({ length: value.length }, (_, i) => String(i)) : keys;
    if (!charge(2 + Math.max(0, selected.length - 1), path)) return;
    const output: Fields | unknown[] = isArray ? [] : {}; active.add(value);
    try {
      for (const key of selected) {
        if (typeof key !== 'string' || !isArray && (!identifier.test(key) || reserved.has(key))) { issues.add('invalid_json', path, 'Object keys must be safe named fields.'); continue; }
        if (!isArray && !charge(encoder.encode(JSON.stringify(key)).length + 1, path)) break;
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) issues.add('invalid_json', at(path, key), 'Only enumerable data properties are supported.');
        else (output as Fields)[key] = copy(descriptor.value, at(path, key), depth + 1);
        if (exhausted || issues.overflow) break;
      }
    } finally { active.delete(value); }
    return output;
  };
  try { return copy(input, '', 0); } catch { issues.add('invalid_json', '', 'Data properties could not be inspected safely.'); return; }
}
function fields(input: unknown, path: string, keys: readonly string[], issues: Issues): Fields | undefined {
  if (!input || typeof input !== 'object' || Array.isArray(input)) { issues.add('type', path, 'Expected an object.'); return; }
  const result = input as Fields;
  for (const key of Object.keys(result)) if (!keys.includes(key)) issues.add('unknown_field', at(path, key), 'Unknown field.');
  for (const key of keys) if (!Object.hasOwn(result, key)) issues.add('required', at(path, key), 'Required field is missing.');
  return result;
}
function list(input: unknown, path: string, max: number, issues: Issues): unknown[] {
  if (!Array.isArray(input)) { issues.add('type', path, 'Expected an array.'); return []; }
  if (input.length > max) { issues.add('limit', path, 'Array exceeds its supported bound.'); return []; }
  return input;
}
function id(input: unknown, path: string, issues: Issues): input is string {
  if (typeof input === 'string' && uuid.test(input)) return true;
  issues.add('format', path, 'Expected a canonical lowercase UUID.'); return false;
}
function key(input: unknown, path: string, issues: Issues): input is string {
  if (typeof input === 'string' && identifier.test(input) && !reserved.has(input)) return true;
  issues.add('format', path, 'Expected a safe identifier of at most 64 characters.'); return false;
}
function version(input: unknown, path: string, issues: Issues): input is number {
  if (typeof input === 'number' && Number.isInteger(input) && input > 0 && input <= 2_147_483_647) return true;
  issues.add('model_version', path, 'Expected a positive PostgreSQL integer version.'); return false;
}
function label(input: unknown, path: string, issues: Issues): void {
  if (typeof input !== 'string' || [...input].length < 1 || [...input].length > 120 || !input.trim()) issues.add('format', path, 'Expected a nonblank label of 1–120 Unicode characters.');
}
function rules(input: unknown, path: string, issues: Issues): RelationEndpointRule[] {
  const items = list(input, path, RELATION_LIMITS.endpointRules, issues), seen = new Set<string>(), result: RelationEndpointRule[] = [];
  if (!items.length) issues.add('required', path, 'At least one allowed type is required.');
  for (const [index, item] of items.entries()) {
    const location = at(path, index), rule = fields(item, location, ['typeId', 'includeDescendants'], issues); if (!rule) continue;
    if (typeof rule.includeDescendants !== 'boolean') issues.add('type', `${location}/includeDescendants`, 'Expected a boolean.');
    if (!id(rule.typeId, `${location}/typeId`, issues)) continue;
    if (seen.has(rule.typeId)) issues.add('duplicate', `${location}/typeId`, 'An endpoint type may be declared only once.');
    seen.add(rule.typeId); result.push({ typeId: rule.typeId, includeDescendants: rule.includeDescendants as boolean });
  }
  return result.sort((a, b) => compare(a.typeId, b.typeId));
}
function states(input: unknown, path: string, issues: Issues): string[] | null {
  if (input === null) return null;
  const items = list(input, path, RELATION_LIMITS.states, issues), seen = new Set<string>();
  if (!items.length) issues.add('required', path, 'A state allowlist must not be empty.');
  items.forEach((value, index) => { if (key(value, at(path, index), issues)) { if (seen.has(value)) issues.add('duplicate', at(path, index), 'Duplicate state.'); seen.add(value); } });
  return [...seen].sort(compare);
}
function degree(input: unknown, path: string, issues: Issues): { min: 0; max: number | null } {
  const value = fields(input, path, ['min', 'max'], issues);
  if (!value) return { min: 0, max: null };
  if (typeof value.min === 'number' && Number.isFinite(value.min) && value.min > 0) issues.add('unsupported', `${path}/min`, 'Positive participation minima require explicit participation bindings and are not implemented in this increment.');
  else if (value.min !== 0) issues.add('range', `${path}/min`, 'The supported minimum is zero.');
  if (value.max !== null && (typeof value.max !== 'number' || !Number.isInteger(value.max) || value.max < 1 || value.max > RELATION_LIMITS.maximumDegree)) issues.add('range', `${path}/max`, 'Maximum must be null or an integer from 1 through 1000.');
  return { min: 0, max: value.max as number | null };
}
const definitionKeys = ['formatVersion', 'id', 'version', 'label', 'inverseLabel', 'direction', 'sourceTypes', 'targetTypes', 'sourceStates', 'targetStates', 'cardinality', 'allowSelf', 'cycles', 'attributes', 'requiredOwner', 'lifecycle'];
export function parseRelationTypeDefinition(input: unknown): ValidationResult<RelationTypeDefinition> {
  const issues = new Issues(), copied = copyJSON(input, issues, RELATION_LIMITS.definitionBytes);
  if (issues.values.length) return issues.result(undefined as never);
  const source = fields(copied, '', definitionKeys, issues); if (!source) return issues.result(undefined as never);
  if (source.formatVersion !== 1) issues.add('invalid_definition', '/formatVersion', 'Only relation format version 1 is supported.');
  key(source.id, '/id', issues); version(source.version, '/version', issues); label(source.label, '/label', issues); label(source.inverseLabel, '/inverseLabel', issues);
  if (!['directed', 'undirected'].includes(source.direction as string)) issues.add('enum', '/direction', 'Choose directed or undirected.');
  if (typeof source.allowSelf !== 'boolean') issues.add('type', '/allowSelf', 'Expected a boolean.');
  if (!['allow', 'acyclic'].includes(source.cycles as string)) issues.add('enum', '/cycles', 'Choose allow or acyclic.');
  if (source.cycles === 'acyclic' && source.allowSelf !== false) issues.add('invalid_definition', '/allowSelf', 'Acyclic types must prohibit self-relations.');
  const sourceTypes = rules(source.sourceTypes, '/sourceTypes', issues), targetTypes = rules(source.targetTypes, '/targetTypes', issues);
  const sourceStates = states(source.sourceStates, '/sourceStates', issues), targetStates = states(source.targetStates, '/targetStates', issues);
  const cardinality = fields(source.cardinality, '/cardinality', ['outgoing', 'incoming'], issues);
  const outgoing = degree(cardinality?.outgoing, '/cardinality/outgoing', issues), incoming = degree(cardinality?.incoming, '/cardinality/incoming', issues);
  const authored = parseAssetTypeDefinition({ formatVersion: 1, id: 'relation_validation', version: 1, parents: [], attributes: source.attributes,
    overrideAttributes: [], requiredOwner: source.requiredOwner, lifecycle: source.lifecycle });
  if (!authored.ok) issues.append('', authored.issues);
  if (source.direction === 'undirected') for (const [path, left, right] of [
    ['/targetTypes', sourceTypes, targetTypes], ['/targetStates', sourceStates, targetStates], ['/cardinality/incoming', outgoing, incoming],
  ] as const) if (canonical(left) !== canonical(right)) issues.add('invalid_definition', path, 'Undirected endpoints require symmetric rules, states and degree constraints.');
  if (issues.values.length || !authored.ok) return issues.result(undefined as never);
  return issues.result(freeze({ formatVersion: 1, id: source.id as string, version: source.version as number,
    label: source.label as string, inverseLabel: source.inverseLabel as string, direction: source.direction as 'directed' | 'undirected',
    sourceTypes, targetTypes, sourceStates, targetStates, cardinality: { outgoing, incoming }, allowSelf: source.allowSelf as boolean,
    cycles: source.cycles as 'allow' | 'acyclic', attributes: authored.value.attributes, requiredOwner: authored.value.requiredOwner, lifecycle: authored.value.lifecycle! }));
}
export function parseRelationTypeFile(text: string): ValidationResult<RelationTypeDefinition> {
  if (typeof text !== 'string' || encoder.encode(text).length > RELATION_LIMITS.definitionBytes) return { ok: false, issues: [{ code: 'limit', path: '', message: 'The model file exceeds its UTF-8 byte budget.' }] };
  const parsed = parseBoundedJSONFile(text); return parsed.ok ? parseRelationTypeDefinition(parsed.value) : parsed;
}
export function resolveRelationType(input: unknown): ValidationResult<ResolvedRelationType> {
  const parsed = parseRelationTypeDefinition(input); if (!parsed.ok) return parsed;
  const model = parseModelDefinition({ formatVersion: 1, id: parsed.value.id, version: parsed.value.version, attributes: parsed.value.attributes });
  return model.ok ? { ok: true, value: freeze({ definition: parsed.value, model: model.value }) } : model;
}
function instant(value: unknown, path: string, issues: Issues, nullable = true): value is string | null {
  if (nullable && value === null) return true;
  if (typeof value !== 'string' || !/^(?!0000)\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) {
    issues.add('format', path, 'Expected a canonical UTC millisecond timestamp in years 0001–9999.'); return false;
  }
  const date = new Date(value);
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== value) { issues.add('format', path, 'Timestamp contains an invalid calendar or time value.'); return false; }
  return true;
}
export function parseRelationValidity(input: { validFrom: unknown; validTo: unknown }): ValidationResult<{ validFrom: string | null; validTo: string | null }> {
  const issues = new Issues(), copied = copyJSON(input, issues);
  if (issues.values.length) return issues.result(undefined as never);
  const value = fields(copied, '', ['validFrom', 'validTo'], issues); if (!value) return issues.result(undefined as never);
  const from = instant(value.validFrom, '/validFrom', issues), to = instant(value.validTo, '/validTo', issues);
  if (from && to && value.validFrom !== null && value.validTo !== null && (value.validFrom as string) >= (value.validTo as string)) issues.add('range', '/validTo', 'Validity uses a nonempty half-open interval: validFrom must precede validTo.');
  return issues.result(freeze({ validFrom: value.validFrom as string | null, validTo: value.validTo as string | null }));
}
function resolved(input: unknown, path: string, issues: Issues): ResolvedRelationType | undefined {
  const raw = fields(input, path, ['definition', 'model'], issues); if (!raw) return;
  const result = resolveRelationType(raw.definition); if (!result.ok) { issues.append(`${path}/definition`, result.issues); return; }
  if (canonical(raw.model) !== canonical(result.value.model)) issues.add('invalid_definition', `${path}/model`, 'Resolved attributes must match the exact relation definition.');
  return result.value;
}
const policyKey = (typeId: string, version: number) => `${typeId}:${version}`;
function policyMap(input: unknown, issues: Issues): Map<string, ResolvedRelationType> {
  const result = new Map<string, ResolvedRelationType>(), logical = new Map<string, string>();
  for (const [index, item] of list(input, '/policies', RELATION_LIMITS.mutationEdges + 1, issues).entries()) {
    const path = `/policies/${index}`, pin = fields(item, path, ['relationTypeId', 'policy'], issues); if (!pin) continue;
    const policy = resolved(pin.policy, `${path}/policy`, issues); if (!id(pin.relationTypeId, `${path}/relationTypeId`, issues) || !policy) continue;
    const lookup = policyKey(pin.relationTypeId, policy.definition.version);
    if (result.has(lookup)) issues.add('duplicate', path, 'Duplicate pinned relation policy.');
    if (logical.has(pin.relationTypeId) && logical.get(pin.relationTypeId) !== policy.definition.id) issues.add('model_identity', path, 'An immutable relation type cannot change its logical key.');
    logical.set(pin.relationTypeId, policy.definition.id); result.set(lookup, policy);
  }
  return result;
}
const edgeKeys = ['id', 'version', 'relationTypeId', 'relationTypeVersion', 'sourceAssetId', 'targetAssetId'];
function edge(input: unknown, path: string, issues: Issues): RelationConstraintEdge | undefined {
  const value = fields(input, path, edgeKeys, issues); if (!value) return;
  for (const name of ['id', 'relationTypeId', 'sourceAssetId', 'targetAssetId']) id(value[name], at(path, name), issues);
  version(value.version, `${path}/version`, issues); version(value.relationTypeVersion, `${path}/relationTypeVersion`, issues);
  return value as unknown as RelationConstraintEdge;
}
function edges(input: unknown, path: string, issues: Issues): RelationConstraintEdge[] {
  const result: RelationConstraintEdge[] = [], seen = new Set<string>();
  for (const [index, raw] of list(input, path, RELATION_LIMITS.mutationEdges, issues).entries()) {
    const item = edge(raw, at(path, index), issues); if (!item) continue;
    if (seen.has(item.id)) issues.add('duplicate', at(path, index), 'Duplicate relation identity.'); seen.add(item.id); result.push(item);
  }
  return result;
}
const endpointKeys = ['assetId', 'assetVersion', 'modelId', 'modelVersion', 'state', 'typeId', 'policy', 'ancestorTypes'];
function endpoint(input: unknown, path: string, issues: Issues): RelationEndpointPolicyState | undefined {
  const value = fields(input, path, endpointKeys, issues); if (!value) return;
  id(value.assetId, `${path}/assetId`, issues); version(value.assetVersion, `${path}/assetVersion`, issues);
  if (value.modelId !== null) key(value.modelId, `${path}/modelId`, issues);
  if (value.modelVersion !== null) version(value.modelVersion, `${path}/modelVersion`, issues);
  if ((value.modelId === null) !== (value.modelVersion === null)) issues.add('model_version', path, 'Model identity and version must be present together.');
  const ancestors = list(value.ancestorTypes, `${path}/ancestorTypes`, 64, issues);
  if (value.typeId === null) {
    if (value.policy !== null || value.state !== null || ancestors.length) issues.add('invalid_definition', path, 'Untyped and attribute-only assets cannot have authored policies, states or ancestry.');
    return value as unknown as RelationEndpointPolicyState;
  }
  id(value.typeId, `${path}/typeId`, issues); key(value.state, `${path}/state`, issues);
  const policy = fields(value.policy, `${path}/policy`, ['definition', 'dependencies', 'model', 'requiredOwner', 'lifecycle'], issues);
  if (!policy) return;
  const authored = parseAssetTypeDefinition(policy.definition), model = parseModelDefinition(policy.model);
  const lifecycle = parseAssetTypeDefinition({ formatVersion: 1, id: 'relation_endpoint', version: 1, parents: [], attributes: {}, overrideAttributes: [], requiredOwner: policy.requiredOwner, lifecycle: policy.lifecycle });
  if (!authored.ok) issues.append(`${path}/policy/definition`, authored.issues);
  if (!model.ok) issues.append(`${path}/policy/model`, model.issues);
  if (!lifecycle.ok) issues.append(`${path}/policy`, lifecycle.issues);
  if (!authored.ok || !model.ok || !lifecycle.ok) return;
  if (authored.value.id !== value.modelId || authored.value.version !== value.modelVersion || model.value.id !== value.modelId || model.value.version !== value.modelVersion) issues.add('model_identity', path, 'Endpoint model fields must match its actual pinned authored resolution.');
  if (authored.value.requiredOwner && !policy.requiredOwner || authored.value.lifecycle !== null && canonical(authored.value.lifecycle) !== canonical(lifecycle.value.lifecycle)) issues.add('invalid_definition', `${path}/policy`, 'The resolved policy contradicts its authored definition.');
  if (!lifecycle.value.lifecycle!.states.includes(value.state as string)) issues.add('enum', `${path}/state`, 'Endpoint state is invalid in its pinned lifecycle.');
  const pins = new Map<string, number>(), identities = new Map<string, number>(), typeIds = new Set<string>();
  for (const [i, item] of list(policy.dependencies, `${path}/policy/dependencies`, 64, issues).entries()) {
    const location = `${path}/policy/dependencies/${i}`, pin = fields(item, location, ['id', 'version'], issues); if (!pin) continue;
    key(pin.id, `${location}/id`, issues); version(pin.version, `${location}/version`, issues);
    if (pins.has(pin.id as string) || pin.id === value.modelId) issues.add('duplicate', location, 'An ancestor logical identity must be unique and distinct from the endpoint type.');
    pins.set(pin.id as string, pin.version as number);
  }
  for (const [i, item] of ancestors.entries()) {
    const location = `${path}/ancestorTypes/${i}`, pin = fields(item, location, ['typeId', 'id', 'version'], issues); if (!pin) continue;
    id(pin.typeId, `${location}/typeId`, issues); key(pin.id, `${location}/id`, issues); version(pin.version, `${location}/version`, issues);
    if (identities.has(pin.id as string) || typeIds.has(pin.typeId as string) || pin.typeId === value.typeId) issues.add('duplicate', location, 'Ancestor identities must be unique and distinct from the endpoint type.');
    identities.set(pin.id as string, pin.version as number); typeIds.add(pin.typeId as string);
  }
  if (canonical([...pins].sort()) !== canonical([...identities].sort()) || authored.value.parents.some(pin => pins.get(pin.id) !== pin.version)) issues.add('invalid_definition', `${path}/ancestorTypes`, 'Ancestor UUID mappings must cover the exact pinned dependency closure.');
  return value as unknown as RelationEndpointPolicyState;
}
function checkEndpoints(item: RelationConstraintEdge, policy: ResolvedRelationType, source: RelationEndpointPolicyState, target: RelationEndpointPolicyState, issues: Issues, path: string): void {
  if (source.assetId !== item.sourceAssetId || target.assetId !== item.targetAssetId) { issues.add('model_identity', path, 'Endpoint identities do not match the relation.'); return; }
  if (!policy.definition.allowSelf && source.assetId === target.assetId) issues.add('invalid_definition', `${path}/targetAssetId`, 'This relation type prohibits self-relations.');
  for (const [name, asset, allowed, states] of [
    ['source', source, policy.definition.sourceTypes, policy.definition.sourceStates], ['target', target, policy.definition.targetTypes, policy.definition.targetStates],
  ] as const) {
    if (!asset.typeId || !asset.policy || !allowed.some(rule => rule.typeId === asset.typeId || rule.includeDescendants && asset.ancestorTypes.some(pin => pin.typeId === rule.typeId))) issues.add('invalid_definition', `${path}/${name}/typeId`, 'Endpoint does not match an allowed nominal type or pinned ancestor.');
    if (!asset.policy || asset.state === null || !asset.policy.lifecycle.states.includes(asset.state) || states !== null && !states.includes(asset.state)) issues.add('enum', `${path}/${name}/state`, 'Endpoint state is not valid for its pin and the relation state restriction.');
  }
}
function selectedPolicy(item: RelationConstraintEdge, policies: Map<string, ResolvedRelationType>, issues: Issues, path: string): ResolvedRelationType | undefined {
  const result = policies.get(policyKey(item.relationTypeId, item.relationTypeVersion));
  if (!result) issues.add('invalid_definition', path, 'The exact pinned relation policy is missing.'); return result;
}
export function validateRelationEndpoints(input: RelationEndpointValidationInput): ValidationResult<null> {
  const issues = new Issues(), raw = copyJSON(input, issues); if (issues.values.length) return issues.result(null);
  const value = fields(raw, '', ['edge', 'policies', 'source', 'target'], issues); if (!value) return issues.result(null);
  const policies = policyMap(value.policies, issues), item = edge(value.edge, '/edge', issues), source = endpoint(value.source, '/source', issues), target = endpoint(value.target, '/target', issues);
  if (!issues.values.length && item && source && target) { const policy = selectedPolicy(item, policies, issues, '/edge'); if (policy) checkEndpoints(item, policy, source, target, issues, '/edge'); }
  return issues.result(null);
}
export function validateRelationEndpointChanges(input: RelationEndpointChangesInput): ValidationResult<null> {
  const issues = new Issues(), raw = copyJSON(input, issues); if (issues.values.length) return issues.result(null);
  const value = fields(raw, '', ['currentEndpoints', 'proposedEndpoints', 'completeIncidentRelations', 'policies'], issues); if (!value) return issues.result(null);
  const policies = policyMap(value.policies, issues), relations = edges(value.completeIncidentRelations, '/completeIncidentRelations', issues), current = new Map<string, RelationEndpointPolicyState>();
  for (const [index, item] of list(value.currentEndpoints, '/currentEndpoints', RELATION_LIMITS.endpointAssets, issues).entries()) {
    const asset = endpoint(item, `/currentEndpoints/${index}`, issues); if (!asset) continue;
    if (current.has(asset.assetId)) issues.add('duplicate', `/currentEndpoints/${index}`, 'Duplicate current endpoint.'); current.set(asset.assetId, asset);
  }
  const proposed = new Map<string, RelationEndpointPolicyState>();
  for (const [index, item] of list(value.proposedEndpoints, '/proposedEndpoints', MODEL_LIMITS.previewAssets, issues).entries()) {
    const path = `/proposedEndpoints/${index}`, proposal = fields(item, path, ['assetId', 'expectedAssetVersion', 'after'], issues); if (!proposal) continue;
    id(proposal.assetId, `${path}/assetId`, issues); version(proposal.expectedAssetVersion, `${path}/expectedAssetVersion`, issues);
    const after = endpoint(proposal.after, `${path}/after`, issues), before = current.get(proposal.assetId as string);
    if (!after) continue;
    if (proposed.has(proposal.assetId as string)) issues.add('duplicate', path, 'Duplicate proposed endpoint.');
    if (!before || before.assetVersion !== proposal.expectedAssetVersion || after.assetVersion !== (proposal.expectedAssetVersion as number) + 1) issues.add('model_version', path, 'Endpoint proposal must advance its exact current revision by one.');
    if (after.assetId !== proposal.assetId) issues.add('model_identity', path, 'A proposed endpoint must preserve asset identity.');
    proposed.set(proposal.assetId as string, after);
  }
  if (issues.values.length) return issues.result(null);
  for (const [index, item] of relations.entries()) {
    const path = `/completeIncidentRelations/${index}`;
    if (!proposed.has(item.sourceAssetId) && !proposed.has(item.targetAssetId)) { issues.add('invalid_definition', path, 'Only relations incident to the proposed set belong in this closure.'); continue; }
    const source = proposed.get(item.sourceAssetId) ?? current.get(item.sourceAssetId), target = proposed.get(item.targetAssetId) ?? current.get(item.targetAssetId), policy = selectedPolicy(item, policies, issues, path);
    if (!source || !target) issues.add('invalid_definition', path, 'Both complete endpoint states are required.');
    else if (policy) checkEndpoints(item, policy, source, target, issues, path);
  }
  return issues.result(null);
}
function structure(typeId: string, relations: readonly RelationConstraintEdge[], policies: Map<string, ResolvedRelationType>, issues: Issues, path: string): void {
  const selected: { item: RelationConstraintEdge; definition: RelationTypeDefinition; path: string }[] = [], pairs = new Set<string>(), ids = new Set<string>(), nodeIds = new Set<string>();
  let direction: 'directed' | 'undirected' | undefined;
  for (const [index, item] of relations.entries()) {
    const location = at(path, index), policy = selectedPolicy(item, policies, issues, location); if (!policy) continue;
    if (item.relationTypeId !== typeId) issues.add('model_identity', location, 'A structural cohort must contain one logical relation type.');
    if (ids.has(item.id)) issues.add('duplicate', location, 'Duplicate relation identity.'); ids.add(item.id);
    if (direction && direction !== policy.definition.direction) issues.add('invalid_definition', location, 'Live pins of one logical type must have one direction.'); direction = policy.definition.direction;
    const pair = direction === 'undirected' ? [item.sourceAssetId, item.targetAssetId].sort(compare) : [item.sourceAssetId, item.targetAssetId];
    const pairKey = pair.join(':'); if (pairs.has(pairKey)) issues.add('duplicate', location, 'Only one live relation may connect this ordered or canonical unordered pair across all type versions.'); pairs.add(pairKey);
    if (!policy.definition.allowSelf && item.sourceAssetId === item.targetAssetId) issues.add('invalid_definition', location, 'The pinned relation policy prohibits self-relations.');
    nodeIds.add(item.sourceAssetId); nodeIds.add(item.targetAssetId); selected.push({ item, definition: policy.definition, path: location });
  }
  if (nodeIds.size > RELATION_LIMITS.endpointAssets) issues.add('limit', path, 'The structural endpoint budget was exceeded.');
  if (issues.values.length) return;
  const outgoing = new Map<string, number>(), incoming = new Map<string, number>();
  const increment = (map: Map<string, number>, id: string) => map.set(id, (map.get(id) ?? 0) + 1);
  for (const { item } of selected) {
    increment(outgoing, item.sourceAssetId); increment(incoming, item.targetAssetId);
    if (direction === 'undirected' && item.sourceAssetId !== item.targetAssetId) { increment(outgoing, item.targetAssetId); increment(incoming, item.sourceAssetId); }
  }
  for (const { item, definition, path: location } of selected) {
    if (definition.cardinality.outgoing.max !== null && outgoing.get(item.sourceAssetId)! > definition.cardinality.outgoing.max) issues.add('range', `${location}/sourceAssetId`, 'The source degree exceeds a surviving pinned outgoing maximum.');
    if (definition.cardinality.incoming.max !== null && incoming.get(item.targetAssetId)! > definition.cardinality.incoming.max) issues.add('range', `${location}/targetAssetId`, 'The target degree exceeds a surviving pinned incoming maximum.');
  }
  if (!selected.some(value => value.definition.cycles === 'acyclic')) return;
  if (direction === 'undirected') {
    const parent = new Map([...nodeIds].map(id => [id, id]));
    const find = (node: string): string => { let root = node; while (parent.get(root) !== root) root = parent.get(root)!; while (node !== root) { const next = parent.get(node)!; parent.set(node, root); node = next; } return root; };
    for (const { item, path: location } of selected) { const source = find(item.sourceAssetId), target = find(item.targetAssetId); if (source === target) { issues.add('cycle', location, 'The complete undirected cohort must be a forest.'); break; } parent.set(source, target); }
  } else {
    const adjacency = new Map([...nodeIds].map(id => [id, [] as string[]])), degree = new Map([...nodeIds].map(id => [id, 0]));
    for (const { item } of selected) { adjacency.get(item.sourceAssetId)!.push(item.targetAssetId); increment(degree, item.targetAssetId); }
    const pending = [...nodeIds].filter(id => degree.get(id) === 0); let visited = 0;
    for (let offset = 0; offset < pending.length; offset++) { const node = pending[offset]; visited++; for (const next of adjacency.get(node)!) { degree.set(next, degree.get(next)! - 1); if (!degree.get(next)) pending.push(next); } }
    if (visited !== nodeIds.size) issues.add('cycle', path, 'The complete directed cohort contains a cycle forbidden by a surviving pin.');
  }
}
export function validateRelationStructure(input: RelationStructureInput): ValidationResult<null> {
  const issues = new Issues(), raw = copyJSON(input, issues); if (issues.values.length) return issues.result(null);
  const value = fields(raw, '', ['relationTypeId', 'completeLiveRelations', 'policies'], issues); if (!value) return issues.result(null);
  id(value.relationTypeId, '/relationTypeId', issues); const policies = policyMap(value.policies, issues), relations = edges(value.completeLiveRelations, '/completeLiveRelations', issues);
  if (!issues.values.length) structure(value.relationTypeId as string, relations, policies, issues, '/completeLiveRelations');
  return issues.result(null);
}
export function previewRelationTypeUpgrade(input: RelationUpgradeInput): ValidationResult<RelationUpgradeResult> {
  const issues = new Issues(), raw = copyJSON(input, issues, RELATION_LIMITS.bytes, true); if (issues.values.length) return issues.result(undefined as never);
  const value = fields(raw, '', ['relationTypeId', 'head', 'target', 'policies', 'completeLiveRelations', 'activeOwnerIds'], issues); if (!value) return issues.result(undefined as never);
  id(value.relationTypeId, '/relationTypeId', issues);
  const head = resolved(value.head, '/head', issues), target = resolved(value.target, '/target', issues), policies = policyMap(value.policies, issues);
  const owners = new Set(list(value.activeOwnerIds, '/activeOwnerIds', RELATION_LIMITS.endpointAssets + 1, issues).filter((item, i): item is string => id(item, `/activeOwnerIds/${i}`, issues)));
  const bindings = list(value.completeLiveRelations, '/completeLiveRelations', RELATION_LIMITS.mutationEdges, issues);
  if (!head || !target || issues.values.length) return issues.result(undefined as never);
  const upgrade = previewModelUpgrade(head.model, target.model, []); if (!upgrade.ok) { issues.append('', upgrade.issues); return issues.result(undefined as never); }
  const changes: { code: string; path: string; requiresMigration: boolean }[] = [...upgrade.value.changes];
  for (const name of ['label', 'inverseLabel', 'direction', 'sourceTypes', 'targetTypes', 'sourceStates', 'targetStates', 'cardinality', 'allowSelf', 'cycles', 'requiredOwner', 'lifecycle'] as const) {
    if (canonical(head.definition[name]) !== canonical(target.definition[name])) changes.push({ code: `${name}_changed`, path: `/${name}`, requiresMigration: !['label', 'inverseLabel'].includes(name) });
  }
  const rows: RelationUpgradeResult['relations'][number][] = [], seen = new Set<string>(), currentEdges: RelationConstraintEdge[] = [], proposedEdges: RelationConstraintEdge[] = [];
  let returnedIssues = 0;
  for (const [index, item] of bindings.entries()) {
    const path = `/completeLiveRelations/${index}`, binding = fields(item, path, ['edge', 'attributes', 'ownerId', 'state', 'source', 'target'], issues); if (!binding) continue;
    const relation = edge(binding.edge, `${path}/edge`, issues), source = endpoint(binding.source, `${path}/source`, issues), destination = endpoint(binding.target, `${path}/target`, issues);
    if (binding.ownerId !== null) id(binding.ownerId, `${path}/ownerId`, issues); key(binding.state, `${path}/state`, issues);
    if (!relation || !source || !destination) continue;
    if (relation.relationTypeId !== value.relationTypeId || seen.has(relation.id)) issues.add(seen.has(relation.id) ? 'duplicate' : 'model_identity', `${path}/edge`, 'The complete cohort must contain unique relations of this logical type.'); seen.add(relation.id);
    const current = selectedPolicy(relation, policies, issues, `${path}/edge`); if (!current) continue;
    const validate = (policy: ResolvedRelationType): readonly ValidationIssue[] => {
      const checks = new Issues(), attributes = validateAttributes(policy.model, binding.attributes);
      if (!attributes.ok) checks.append('/attributes', attributes.issues);
      checkEndpoints(relation, policy, source, destination, checks, '');
      if (policy.definition.requiredOwner && (typeof binding.ownerId !== 'string' || !owners.has(binding.ownerId))) checks.add('required', '/ownerId', 'The pinned relation requires an active owner in this tenant.');
      if (!policy.definition.lifecycle.states.includes(binding.state as string)) checks.add('enum', '/state', 'The relation state is not valid in this lifecycle.');
      const result = checks.result(null); return result.ok ? [] : result.issues;
    };
    const currentIssues = validate(current), proposedIssues = validate(target); returnedIssues += currentIssues.length + proposedIssues.length;
    if (returnedIssues > RELATION_LIMITS.issues) { issues.add('limit', path, 'The aggregate preview issue budget was exceeded.'); break; }
    rows.push({ relationId: relation.id, relationVersion: relation.version, currentIssues, proposedIssues });
    currentEdges.push(relation); proposedEdges.push({ ...relation, relationTypeVersion: target.definition.version });
  }
  if (issues.values.length) return issues.result(undefined as never);
  rows.sort((a, b) => compare(a.relationId, b.relationId));
  currentEdges.sort((a, b) => compare(a.id, b.id)); proposedEdges.sort((a, b) => compare(a.id, b.id));
  const currentStructure = new Issues(), proposedStructure = new Issues();
  structure(value.relationTypeId as string, currentEdges, policies, currentStructure, '/relations');
  structure(value.relationTypeId as string, proposedEdges, new Map([[policyKey(value.relationTypeId as string, target.definition.version), target]]), proposedStructure, '/relations');
  // Structural problems are a cohort-wide migration requirement. Attach them to
  // the first stable row without inventing an unscoped top-level relation list.
  for (const [side, checked] of [['currentIssues', currentStructure], ['proposedIssues', proposedStructure]] as const) {
    const result = checked.result(null); if (!result.ok && rows.length) { returnedIssues += result.issues.length; rows[0] = { ...rows[0], [side]: [...rows[0][side], ...result.issues] }; }
  }
  if (returnedIssues > RELATION_LIMITS.issues) { issues.add('limit', '/relations', 'The aggregate preview issue budget was exceeded.'); return issues.result(undefined as never); }
  rows.sort((a, b) => compare(a.relationId, b.relationId));
  const compatible = rows.every(row => !row.currentIssues.length && !row.proposedIssues.length);
  return issues.result(freeze({ changes, relations: rows, compatibleWithProvidedRelations: compatible,
    requiresExplicitMigration: rows.length > 0 && (!compatible || changes.some(change => change.requiresMigration)), pinsPreserved: true }));
}
function graphNode(raw: unknown, path: string, issues: Issues): RelationEndpointView | undefined {
  const value = fields(raw, path, ['assetId', 'name', 'assetVersion', 'typeId', 'modelId', 'modelVersion', 'state'], issues); if (!value) return;
  id(value.assetId, `${path}/assetId`, issues); version(value.assetVersion, `${path}/assetVersion`, issues);
  if (typeof value.name !== 'string') issues.add('type', `${path}/name`, 'Expected a display name.');
  if (value.typeId !== null) id(value.typeId, `${path}/typeId`, issues);
  if (value.modelId !== null) key(value.modelId, `${path}/modelId`, issues);
  if (value.modelVersion !== null) version(value.modelVersion, `${path}/modelVersion`, issues);
  if (value.state !== null) key(value.state, `${path}/state`, issues);
  if ((value.modelId === null) !== (value.modelVersion === null) || (value.typeId === null) !== (value.state === null) || value.typeId !== null && value.modelId === null) issues.add('invalid_definition', path, 'Graph node type, model and state fields are inconsistent.');
  return value as unknown as RelationEndpointView;
}
export function traverseAuthorizedRelations(input: AuthorizedRelationTraversalInput): ValidationResult<RelationNeighborhood> {
  const issues = new Issues(), raw = copyJSON(input, issues); if (issues.values.length) return issues.result(undefined as never);
  const value = fields(raw, '', ['rootAssetId', 'direction', 'depth', 'validAt', 'relationTypeId', 'nodes', 'edges', 'completeFrontierAssetIds'], issues); if (!value) return issues.result(undefined as never);
  id(value.rootAssetId, '/rootAssetId', issues); if (value.relationTypeId !== null) id(value.relationTypeId, '/relationTypeId', issues);
  instant(value.validAt, '/validAt', issues, false);
  if (!['in', 'out', 'both'].includes(value.direction as string)) issues.add('enum', '/direction', 'Choose in, out or both.');
  if (typeof value.depth !== 'number' || !Number.isInteger(value.depth) || value.depth < 1 || value.depth > RELATION_LIMITS.graphDepth) issues.add('range', '/depth', 'Graph depth must be from 1 through 6.');
  const nodes = new Map<string, RelationEndpointView>();
  for (const [index, rawNode] of list(value.nodes, '/nodes', RELATION_LIMITS.graphNodes, issues).entries()) {
    const node = graphNode(rawNode, `/nodes/${index}`, issues); if (!node) continue;
    if (nodes.has(node.assetId)) issues.add('duplicate', `/nodes/${index}`, 'Duplicate graph node.'); nodes.set(node.assetId, node);
  }
  if (!nodes.has(value.rootAssetId as string)) issues.add('required', '/rootAssetId', 'The authorized root must be provided.');
  const complete = new Set<string>();
  for (const [index, nodeId] of list(value.completeFrontierAssetIds, '/completeFrontierAssetIds', RELATION_LIMITS.graphNodes, issues).entries()) if (id(nodeId, `/completeFrontierAssetIds/${index}`, issues)) {
    if (complete.has(nodeId)) issues.add('duplicate', `/completeFrontierAssetIds/${index}`, 'Duplicate complete frontier identity.');
    if (!nodes.has(nodeId)) issues.add('invalid_definition', `/completeFrontierAssetIds/${index}`, 'A frontier must refer to a supplied authorized node.'); complete.add(nodeId);
  }
  const adjacency = new Map([...nodes.keys()].map(id => [id, [] as { edge: RelationView; next: string }[]])), seen = new Set<string>();
  for (const [index, rawEdge] of list(value.edges, '/edges', RELATION_LIMITS.graphEdges, issues).entries()) {
    const path = `/edges/${index}`;
    // View metadata is already checked by the canonical service; still inspect
    // the traversal fields and endpoint copies before trusting adjacency.
    const rawView = fields(rawEdge, path, ['id', 'relationTypeId', 'relationTypeKey', 'relationTypeVersion', 'version', 'source', 'target', 'direction', 'label', 'inverseLabel', 'attributes', 'ownerId', 'state', 'validFrom', 'validTo', 'visibility', 'allowedIdentityIds', 'status', 'provenance', 'createdAt', 'createdBy', 'updatedAt', 'updatedBy'], issues);
    if (!rawView) continue;
    const item = rawView as unknown as RelationView;
    id(item.id, `${path}/id`, issues); id(item.relationTypeId, `${path}/relationTypeId`, issues); version(item.version, `${path}/version`, issues); version(item.relationTypeVersion, `${path}/relationTypeVersion`, issues);
    key(item.relationTypeKey, `${path}/relationTypeKey`, issues); key(item.state, `${path}/state`, issues);
    label(item.label, `${path}/label`, issues); label(item.inverseLabel, `${path}/inverseLabel`, issues);
    if (item.ownerId !== null) id(item.ownerId, `${path}/ownerId`, issues);
    if (!item.attributes || typeof item.attributes !== 'object' || Array.isArray(item.attributes)) issues.add('type', `${path}/attributes`, 'Relation attributes must be an object.');
    if (!['tenant', 'restricted'].includes(item.visibility)) issues.add('enum', `${path}/visibility`, 'Invalid relation visibility.');
    const allowed = new Set<string>();
    for (const [i, identity] of list(item.allowedIdentityIds, `${path}/allowedIdentityIds`, 100, issues).entries()) if (id(identity, `${path}/allowedIdentityIds/${i}`, issues)) {
      if (allowed.has(identity)) issues.add('duplicate', `${path}/allowedIdentityIds/${i}`, 'Duplicate visibility identity.'); allowed.add(identity);
    }
    if (item.visibility === 'tenant' && allowed.size || item.visibility === 'restricted' && !allowed.size) issues.add('invalid_definition', `${path}/allowedIdentityIds`, 'Visibility and allowed identities are inconsistent.');
    for (const field of ['createdAt', 'updatedAt'] as const) instant(item[field], `${path}/${field}`, issues, false);
    for (const field of ['createdBy', 'updatedBy'] as const) id(item[field], `${path}/${field}`, issues);
    const provenance = fields(item.provenance, `${path}/provenance`, ['origin', 'source', 'authority', 'precedence', 'actorId', 'assertedAt', 'ingestedAt', 'sourceObservedAt', 'sourceVersion', 'sourceRunId', 'confidence'], issues);
    if (provenance) {
      if (provenance.origin !== 'asserted' || provenance.authority !== 'manual-assertion') issues.add('enum', `${path}/provenance`, 'This increment supports asserted manual provenance only.');
      for (const field of ['precedence', 'sourceObservedAt', 'sourceVersion', 'sourceRunId', 'confidence']) if (provenance[field] !== null) issues.add('invalid_definition', `${path}/provenance/${field}`, 'External evidence and precedence must remain explicitly unknown.');
      id(provenance.actorId, `${path}/provenance/actorId`, issues);
      instant(provenance.assertedAt, `${path}/provenance/assertedAt`, issues, false); instant(provenance.ingestedAt, `${path}/provenance/ingestedAt`, issues, false);
      const source = fields(provenance.source, `${path}/provenance/source`, ['kind', 'identityId'], issues);
      if (source && (source.kind !== 'manual' || source.identityId !== provenance.actorId)) issues.add('invalid_definition', `${path}/provenance/source`, 'The manual provenance identity must match its actor.');
    }
    if (seen.has(item.id)) issues.add('duplicate', path, 'Duplicate graph relation.'); seen.add(item.id);
    if (!['active', 'tombstoned'].includes(item.status) || !['directed', 'undirected'].includes(item.direction)) issues.add('enum', path, 'Invalid graph relation status or direction.');
    const source = graphNode(item.source, `${path}/source`, issues), target = graphNode(item.target, `${path}/target`, issues);
    if (!source || !target) continue;
    if (source.typeId === null || target.typeId === null) issues.add('invalid_definition', path, 'Actual relation endpoints must have authored pins and states.');
    for (const endpoint of [source, target]) if (!nodes.has(endpoint.assetId) || canonical(nodes.get(endpoint.assetId)) !== canonical(endpoint)) issues.add('invalid_definition', path, 'An edge must refer to matching supplied authorized endpoint versions.');
    const validity = parseRelationValidity({ validFrom: item.validFrom, validTo: item.validTo }); if (!validity.ok) issues.append(path, validity.issues);
    if (issues.values.length) continue;
    if (item.status !== 'active' || value.relationTypeId !== null && item.relationTypeId !== value.relationTypeId || item.validFrom !== null && item.validFrom > (value.validAt as string) || item.validTo !== null && item.validTo <= (value.validAt as string)) continue;
    if (item.direction === 'undirected' || value.direction !== 'in') adjacency.get(source.assetId)!.push({ edge: item, next: target.assetId });
    if ((item.direction === 'undirected' || value.direction !== 'out') && source.assetId !== target.assetId) adjacency.get(target.assetId)!.push({ edge: item, next: source.assetId });
    if (source.assetId === target.assetId && item.direction === 'directed' && value.direction === 'in') adjacency.get(source.assetId)!.push({ edge: item, next: source.assetId });
  }
  if (issues.values.length) return issues.result(undefined as never);
  const root = value.rootAssetId as string, distances = new Map([[root, 0]]), queue = [root], selected = new Map<string, RelationView>();
  for (let offset = 0; offset < queue.length; offset++) {
    const current = queue[offset], distance = distances.get(current)!; if (distance >= (value.depth as number)) continue;
    if (!complete.has(current)) { issues.add('invalid_definition', '/completeFrontierAssetIds', 'The supplied neighborhood is incomplete at an expanded frontier.'); break; }
    for (const { edge, next } of adjacency.get(current)!) {
      selected.set(edge.id, edge); if (!distances.has(next)) { distances.set(next, distance + 1); queue.push(next); }
    }
  }
  if (issues.values.length) return issues.result(undefined as never);
  const used = new Set([root]); for (const edge of selected.values()) { used.add(edge.source.assetId); used.add(edge.target.assetId); }
  return issues.result(freeze({ nodes: [...used].sort(compare).map(id => nodes.get(id)!), edges: [...selected.values()].sort((a, b) => compare(a.id, b.id)) }));
}
