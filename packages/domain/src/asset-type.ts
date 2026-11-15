// SPDX-License-Identifier: Apache-2.0
import { MODEL_LIMITS, parseBoundedJSONFile, parseModelDefinition,
  type AttributeDefinition, type ModelDefinition, type ValidationIssue, type ValidationIssueCode, type ValidationResult } from './model.ts';

/** Pure authored-type parsing and pinned resolution; no IO, authorization or publication. */
export const ASSET_TYPE_LIMITS = Object.freeze({ parents: 8, dependencies: 64, ancestryEdges: 8, states: 32, transitions: 256 });
export interface TypePin { readonly id: string; readonly version: number }
export interface LifecycleDefinition {
  readonly initial: string;
  readonly states: readonly string[];
  readonly transitions: readonly { readonly from: string; readonly to: string }[];
}
export interface AssetTypeDefinition extends TypePin {
  readonly formatVersion: 1;
  readonly parents: readonly TypePin[];
  readonly attributes: Readonly<Record<string, AttributeDefinition>>;
  readonly overrideAttributes: readonly string[];
  readonly requiredOwner: boolean;
  readonly lifecycle: LifecycleDefinition | null;
}
export interface ResolvedAssetType {
  readonly definition: AssetTypeDefinition;
  readonly dependencies: readonly TypePin[];
  readonly model: ModelDefinition;
  readonly requiredOwner: boolean;
  readonly lifecycle: LifecycleDefinition;
}

type Fields = Record<string, unknown>;
const identifier = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const reserved = new Set(['__proto__', 'prototype', 'constructor']);
const at = (path: string, key: string | number): string => `${path}/${String(key).replaceAll('~', '~0').replaceAll('/', '~1')}`;
const compare = (left: string, right: string): number => left < right ? -1 : left > right ? 1 : 0;

class Issues {
  readonly values: ValidationIssue[] = [];
  overflow = false;
  add(code: ValidationIssueCode, path: string, message: string): void {
    if (this.values.length < MODEL_LIMITS.issues - 1) this.values.push({ code, path, message });
    else this.overflow = true;
  }
  append(prefix: string, values: readonly ValidationIssue[]): void {
    for (const issue of values) this.add(issue.code, prefix + issue.path, issue.message);
  }
  result<T>(value: T): ValidationResult<T> {
    if (this.overflow) this.values.push({ code: 'limit', path: '', message: 'Further asset-type issues were omitted.' });
    return this.values.length ? { ok: false, issues: this.values } : { ok: true, value };
  }
}

/** Read only descriptors: accessors, symbols and non-JSON prototypes never become data. */
function object(input: unknown, path: string, allowed: readonly string[], issues: Issues): Fields | undefined {
  if (!input || typeof input !== 'object' || Array.isArray(input) || ![Object.prototype, null].includes(Object.getPrototypeOf(input))) {
    issues.add('type', path, 'Expected a plain JSON object.'); return;
  }
  const keys = Reflect.ownKeys(input);
  if (keys.length > MODEL_LIMITS.properties) { issues.add('limit', path, 'The permitted property count was exceeded.'); return; }
  const output: Fields = Object.create(null);
  for (const key of keys) {
    if (typeof key !== 'string') { issues.add('invalid_json', path, 'Symbol keys are not JSON.'); continue; }
    if (!allowed.includes(key)) { issues.add('unknown_field', key.length <= 256 ? at(path, key) : path, 'Unknown asset-type field.'); continue; }
    const descriptor = Object.getOwnPropertyDescriptor(input, key)!;
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      issues.add('invalid_json', at(path, key), 'Only enumerable data properties are permitted.'); continue;
    }
    output[key] = descriptor.value;
  }
  for (const key of allowed) if (!Object.hasOwn(output, key)) issues.add('required', at(path, key), 'Required field is missing.');
  return output;
}
function array(input: unknown, path: string, maximum: number, issues: Issues): unknown[] | undefined {
  if (!Array.isArray(input) || Object.getPrototypeOf(input) !== Array.prototype) { issues.add('type', path, 'Expected a JSON array.'); return; }
  if (input.length > maximum) { issues.add('limit', path, 'The permitted array length was exceeded.'); return; }
  if (Reflect.ownKeys(input).length !== input.length + 1) { issues.add('invalid_json', path, 'Sparse arrays and extra array properties are not permitted.'); return; }
  const output: unknown[] = [];
  for (let index = 0; index < input.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      issues.add('invalid_json', at(path, index), 'Array entries must be enumerable data properties.'); return;
    }
    output.push(descriptor.value);
  }
  return output;
}
function safeId(input: unknown, path: string, issues: Issues): input is string {
  if (typeof input !== 'string' || !identifier.test(input) || reserved.has(input)) {
    issues.add('format', path, 'Expected a safe identifier of at most 64 characters.'); return false;
  }
  return true;
}
function version(input: unknown, path: string, issues: Issues): input is number {
  if (typeof input !== 'number' || !Number.isSafeInteger(input) || input < 1) {
    issues.add('model_version', path, 'Expected a positive safe integer version.'); return false;
  }
  return true;
}
function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
function lifecycle(input: unknown, issues: Issues): LifecycleDefinition | null | undefined {
  if (input === null) return null;
  const source = object(input, '/lifecycle', ['initial', 'states', 'transitions'], issues);
  if (!source) return;
  safeId(source.initial, '/lifecycle/initial', issues);
  const states = array(source.states, '/lifecycle/states', ASSET_TYPE_LIMITS.states, issues);
  const transitions = array(source.transitions, '/lifecycle/transitions', ASSET_TYPE_LIMITS.transitions, issues);
  if (!states || !transitions) return;
  if (!states.length) issues.add('invalid_definition', '/lifecycle/states', 'At least one lifecycle state is required.');
  const seen = new Set<string>();
  for (const [index, state] of states.entries()) if (safeId(state, `/lifecycle/states/${index}`, issues)) {
    if (seen.has(state)) issues.add('duplicate', `/lifecycle/states/${index}`, 'Duplicate lifecycle state.');
    seen.add(state);
  }
  if (!seen.has(source.initial as string)) issues.add('invalid_definition', '/lifecycle/initial', 'The initial state must be declared.');
  const edges = new Set<string>(); const accepted: { from: string; to: string }[] = [];
  for (const [index, transition] of transitions.entries()) {
    const path = `/lifecycle/transitions/${index}`;
    const edge = object(transition, path, ['from', 'to'], issues);
    if (!edge) continue;
    const validFrom = safeId(edge.from, at(path, 'from'), issues), validTo = safeId(edge.to, at(path, 'to'), issues);
    if (!validFrom || !validTo) continue;
    const from = edge.from as string, to = edge.to as string;
    if (!seen.has(from) || !seen.has(to)) issues.add('invalid_definition', path, 'Transition endpoints must be declared states.');
    if (from === to) issues.add('invalid_definition', path, 'Self transitions are not supported.');
    const key = `${from}\0${to}`;
    if (edges.has(key)) issues.add('duplicate', path, 'Duplicate lifecycle transition.');
    edges.add(key); accepted.push({ from, to });
  }
  return { initial: source.initial as string, states: states as string[], transitions: accepted };
}

export function parseAssetTypeDefinition(input: unknown): ValidationResult<AssetTypeDefinition> {
  const issues = new Issues();
  const source = object(input, '', ['formatVersion', 'id', 'version', 'parents', 'attributes', 'overrideAttributes', 'requiredOwner', 'lifecycle'], issues);
  if (!source) return issues.result(undefined as never);
  if (source.formatVersion !== 1) issues.add('invalid_definition', '/formatVersion', 'Only asset-type format version 1 is supported.');
  safeId(source.id, '/id', issues); version(source.version, '/version', issues);
  // Validate authored attributes through the existing grammar. Invalid identity
  // values must never be copied or frozen as if they were trusted JSON strings.
  const model = parseModelDefinition({ formatVersion: 1, id: 'asset_type_validation', version: 1, attributes: source.attributes });
  if (!model.ok) issues.append('', model.issues);
  const rawParents = array(source.parents, '/parents', ASSET_TYPE_LIMITS.parents, issues);
  const parents: TypePin[] = []; const parentIds = new Set<string>();
  for (const [index, raw] of (rawParents ?? []).entries()) {
    const path = `/parents/${index}`; const pin = object(raw, path, ['id', 'version'], issues);
    if (!pin) continue;
    const validId = safeId(pin.id, at(path, 'id'), issues), validVersion = version(pin.version, at(path, 'version'), issues);
    if (!validId || !validVersion) continue;
    const id = pin.id as string;
    if (parentIds.has(id)) issues.add('duplicate', at(path, 'id'), 'A logical parent can be pinned only once.');
    if (id === source.id) issues.add('cycle', path, 'An asset type cannot inherit from its own logical identity.');
    parentIds.add(id); parents.push({ id, version: pin.version as number });
  }
  const overrides = array(source.overrideAttributes, '/overrideAttributes', MODEL_LIMITS.properties, issues);
  const overrideIds = new Set<string>();
  for (const [index, key] of (overrides ?? []).entries()) if (safeId(key, `/overrideAttributes/${index}`, issues)) {
    if (overrideIds.has(key)) issues.add('duplicate', `/overrideAttributes/${index}`, 'Duplicate override declaration.');
    if (model.ok && !Object.hasOwn(model.value.attributes, key)) issues.add('invalid_definition', `/overrideAttributes/${index}`, 'An override requires a local attribute.');
    overrideIds.add(key);
  }
  if (typeof source.requiredOwner !== 'boolean') issues.add('type', '/requiredOwner', 'Expected a boolean.');
  const policy = lifecycle(source.lifecycle, issues);
  if (rawParents?.length === 0 && policy === null) issues.add('invalid_definition', '/lifecycle', 'A root asset type requires an explicit lifecycle.');
  if (issues.values.length) return issues.result(undefined as never);
  return issues.result(freeze({ formatVersion: 1, id: source.id as string, version: source.version as number,
    parents, attributes: model.ok ? model.value.attributes : {}, overrideAttributes: (overrides ?? []) as string[],
    requiredOwner: source.requiredOwner as boolean, lifecycle: policy as LifecycleDefinition | null }));
}

export function parseAssetTypeFile(text: string): ValidationResult<AssetTypeDefinition> {
  const parsed = parseBoundedJSONFile(text);
  return parsed.ok ? parseAssetTypeDefinition(parsed.value) : parsed;
}

/** Canonical structural equality preserves authored array ordering and all constraints. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical((value as Fields)[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
interface NodeResolution { model: ModelDefinition; requiredOwner: boolean; lifecycle: LifecycleDefinition; height: number }

export function resolveAssetType(input: unknown, dependencies: readonly unknown[]): ValidationResult<ResolvedAssetType> {
  const parsed = parseAssetTypeDefinition(input);
  if (!parsed.ok) return parsed;
  const definition = parsed.value; const issues = new Issues();
  const supplied = array(dependencies, '/dependencies', ASSET_TYPE_LIMITS.dependencies, issues);
  if (!supplied) return issues.result(undefined as never);
  const definitions = new Map<string, { definition: AssetTypeDefinition; path: string }>();
  definitions.set(definition.id, { definition, path: '' });
  for (const [index, item] of supplied.entries()) {
    const path = `/dependencies/${index}`; const dependency = parseAssetTypeDefinition(item);
    if (!dependency.ok) { issues.append(path, dependency.issues); continue; }
    if (definitions.has(dependency.value.id)) issues.add('duplicate', at(path, 'id'), 'Supplied logical type identities must be unique.');
    else definitions.set(dependency.value.id, { definition: dependency.value, path });
    if (issues.overflow) break;
  }
  if (issues.values.length) return issues.result(undefined as never);
  const active = new Set<string>(), used = new Map<string, TypePin>(), cache = new Map<string, NodeResolution>();
  const visit = (current: AssetTypeDefinition, path: string, depth: number): NodeResolution | undefined => {
    if (depth > ASSET_TYPE_LIMITS.ancestryEdges) { issues.add('limit', path, 'The permitted ancestry depth was exceeded.'); return; }
    if (active.has(current.id)) { issues.add('cycle', path, 'Logical asset-type ancestry cannot contain cycles.'); return; }
    const memo = cache.get(current.id);
    if (memo) {
      if (depth + memo.height > ASSET_TYPE_LIMITS.ancestryEdges) { issues.add('limit', path, 'The permitted ancestry depth was exceeded.'); return; }
      return memo;
    }
    active.add(current.id);
    try {
      const parents: NodeResolution[] = [];
      const sorted = current.parents.map((pin, index) => ({ pin, index })).sort((a, b) => compare(a.pin.id, b.pin.id) || a.pin.version - b.pin.version);
      for (const { pin, index } of sorted) {
        const pinPath = `${path}/parents/${index}`;
        if (active.has(pin.id)) { issues.add('cycle', pinPath, 'Logical asset-type ancestry cannot contain cycles.'); continue; }
        const prior = used.get(pin.id);
        if (prior && prior.version !== pin.version) { issues.add('model_version', pinPath, 'The same ancestor cannot have different pinned versions.'); continue; }
        const suppliedDefinition = definitions.get(pin.id);
        if (!suppliedDefinition) { issues.add('invalid_definition', pinPath, 'An exact parent dependency is missing.'); continue; }
        if (suppliedDefinition.definition.version !== pin.version) { issues.add('model_version', pinPath, 'The supplied dependency does not match its exact version pin.'); continue; }
        used.set(pin.id, { ...pin });
        const parent = visit(suppliedDefinition.definition, suppliedDefinition.path, depth + 1);
        if (parent) parents.push(parent);
      }
      if (parents.length !== current.parents.length) return;
      const inherited: Record<string, AttributeDefinition> = {};
      const conflicts = new Set<string>();
      for (const parent of parents) for (const [key, attribute] of Object.entries(parent.model.attributes)) {
        if (Object.hasOwn(inherited, key) && canonical(inherited[key]) !== canonical(attribute)) conflicts.add(key);
        else inherited[key] = attribute;
      }
      for (const key of [...conflicts].sort()) if (!Object.hasOwn(current.attributes, key)) issues.add('invalid_definition', `${path}/attributes/${key}`, 'Conflicting inherited attributes require an explicit local field.');
      const declared = new Set(current.overrideAttributes);
      for (const [index, key] of current.overrideAttributes.entries()) if (!Object.hasOwn(inherited, key)) issues.add('invalid_definition', `${path}/overrideAttributes/${index}`, 'An override must replace an inherited attribute.');
      for (const key of Object.keys(current.attributes).sort()) if (Object.hasOwn(inherited, key) && !declared.has(key)) issues.add('invalid_definition', `${path}/attributes/${key}`, 'Replacing an inherited attribute requires an explicit override declaration.');
      const model = parseModelDefinition({ formatVersion: 1, id: current.id, version: current.version, attributes: { ...inherited, ...current.attributes } });
      if (!model.ok) issues.append(path, model.issues);
      let policy = current.lifecycle;
      if (policy === null) {
        const candidates = new Map(parents.map(parent => [canonical(parent.lifecycle), parent.lifecycle]));
        if (candidates.size !== 1) issues.add('invalid_definition', at(path, 'lifecycle'), 'Inherited lifecycle is ambiguous; provide an explicit lifecycle.');
        else policy = [...candidates.values()][0];
      }
      if (!model.ok || !policy) return;
      const result = { model: model.value, requiredOwner: current.requiredOwner || parents.some(parent => parent.requiredOwner), lifecycle: policy,
        height: parents.length ? Math.max(...parents.map(parent => parent.height)) + 1 : 0 };
      cache.set(current.id, result);
      return result;
    } finally { active.delete(current.id); }
  };
  const resolved = visit(definition, '', 0);
  if (!resolved) return issues.result(undefined as never);
  return issues.result(freeze({ definition, dependencies: [...used.values()].sort((a, b) => compare(a.id, b.id) || a.version - b.version),
    model: resolved.model, requiredOwner: resolved.requiredOwner, lifecycle: resolved.lifecycle }));
}
