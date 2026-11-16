// SPDX-License-Identifier: Apache-2.0
import { MODEL_LIMITS, parseBoundedJSONFile, parseModelDefinition,
  type AttributeDefinition, type ModelDefinition, type ValidationIssue, type ValidationIssueCode, type ValidationResult } from './model.ts';
import type { LifecycleDefinition } from './asset-type.ts';
import type { DomainTypeDefinition, DomainTypePin, ResolvedDomainType } from './business-domain-contracts.ts';

/** Pure parsing/resolution only. Publication, tenant identity and authorization
 * remain service/storage obligations; no asset-type resolver or writer is used. */
export const DOMAIN_TYPE_LIMITS = Object.freeze({ parents: 8, dependencies: 64, ancestryEdges: 8,
  states: 32, transitions: 256, definitionBytes: 262_144, bytes: 524_288, nodes: 100_000, depth: 32, issues: 100 });
type Fields = Record<string, unknown>;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const identifier = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const reserved = new Set(['__proto__', 'prototype', 'constructor']);
const malformedUnicode = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const encoder = new TextEncoder();
const at = (path: string, key: string | number) => `${path}/${String(key).replaceAll('~', '~0').replaceAll('/', '~1')}`;
const compare = (left: string, right: string) => left < right ? -1 : left > right ? 1 : 0;
class Issues {
  readonly values: ValidationIssue[] = []; overflow = false;
  add(code: ValidationIssueCode, path: string, message: string) {
    if (this.values.length < DOMAIN_TYPE_LIMITS.issues - 1) this.values.push({ code, path, message }); else this.overflow = true;
  }
  append(path: string, issues: readonly ValidationIssue[]) { for (const issue of issues) this.add(issue.code, path + issue.path, issue.message); }
  result<T>(value: T): ValidationResult<T> {
    if (this.overflow && this.values.length < DOMAIN_TYPE_LIMITS.issues) this.values.push({ code: 'limit', path: '', message: 'Further domain-type issues were omitted.' });
    return this.values.length ? freeze({ ok: false, issues: this.values }) : freeze({ ok: true, value });
  }
}
function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}
/** Same canonical JSON grammar as model/type evidence: object keys sort;
 * authored arrays retain their meaning and order. Input here is already data. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical((value as Fields)[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
class Budget {
  bytes = 0; nodes = 0; exhausted = false;
  constructor(readonly issues: Issues, readonly maximumBytes: number) {}
  charge(bytes: number, nodes: number, path: string): boolean {
    this.bytes += bytes; this.nodes += nodes;
    if (this.bytes <= this.maximumBytes && this.nodes <= DOMAIN_TYPE_LIMITS.nodes) return true;
    if (!this.exhausted) this.issues.add('limit', path, 'The aggregate retained UTF-8 byte or node budget was exceeded.');
    this.exhausted = true; return false;
  }
  retain(value: unknown, path: string): boolean {
    let nodes = 0; const count = (item: unknown) => { nodes += 1; if (item && typeof item === 'object') for (const child of Object.values(item)) count(child); };
    count(value); return this.charge(encoder.encode(canonical(value)).length, nodes, path);
  }
}
/** Descriptor-only clone: never invoke an input getter, iterator or toJSON. */
function copyJSON(input: unknown, issues: Issues, budget: Budget): unknown {
  const active = new Set<object>();
  const copy = (value: unknown, path: string, depth: number): unknown => {
    if (budget.exhausted || issues.overflow) return;
    if (depth > DOMAIN_TYPE_LIMITS.depth) { issues.add('limit', path, 'JSON nesting exceeds the supported depth.'); return; }
    if (!budget.charge(0, 1, path)) return;
    if (value === null) { budget.charge(4, 0, path); return null; }
    if (typeof value === 'string') {
      if (value.length > MODEL_LIMITS.stringLength) { issues.add('limit', path, 'String length exceeds the supported bound.'); return; }
      if (malformedUnicode.test(value)) issues.add('format', path, 'Expected well-formed Unicode.');
      budget.charge(encoder.encode(JSON.stringify(value)).length, 0, path); return value;
    }
    if (typeof value === 'number') {
      if (!Number.isFinite(value) || Object.is(value, -0)) issues.add('type', path, 'Expected a finite JSON number without negative zero.');
      budget.charge(String(value).length, 0, path); return value;
    }
    if (typeof value === 'boolean') { budget.charge(value ? 4 : 5, 0, path); return value; }
    if (!value || typeof value !== 'object') { issues.add('invalid_json', path, 'Only JSON data properties are supported.'); return; }
    if (active.has(value)) { issues.add('cycle', path, 'JSON data cannot contain cycles.'); return; }
    const isArray = Array.isArray(value);
    if (isArray ? Object.getPrototypeOf(value) !== Array.prototype : ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
      issues.add('invalid_json', path, 'Expected plain JSON objects and arrays.'); return;
    }
    const keys = Reflect.ownKeys(value);
    if (isArray && (value.length > MODEL_LIMITS.listItems || keys.length !== value.length + 1)) {
      issues.add(value.length > MODEL_LIMITS.listItems ? 'limit' : 'invalid_json', path, 'Array must be bounded, dense and have no extra properties.'); return;
    }
    if (!isArray && keys.length > MODEL_LIMITS.properties) { issues.add('limit', path, 'Object property count exceeds its bound.'); return; }
    const selected = isArray ? Array.from({ length: value.length }, (_, index) => String(index)) : keys;
    if (!budget.charge(2 + Math.max(0, selected.length - 1), 0, path)) return;
    const output = new Map<string, unknown>(); active.add(value);
    try {
      for (const key of selected) {
        if (typeof key !== 'string' || !isArray && (!identifier.test(key) || reserved.has(key))) { issues.add('invalid_json', path, 'Object keys must be safe named fields.'); continue; }
        if (!isArray && !budget.charge(encoder.encode(JSON.stringify(key)).length + 1, 0, path)) break;
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) issues.add('invalid_json', at(path, key), 'Only enumerable data properties are supported.');
        else output.set(key, copy(descriptor.value, at(path, key), depth + 1));
        if (budget.exhausted || issues.overflow) break;
      }
    } finally { active.delete(value); }
    return isArray ? Array.from(output.values()) : Object.fromEntries(output);
  };
  try { return copy(input, '', 0); } catch { issues.add('invalid_json', '', 'Data properties could not be inspected safely.'); return; }
}
function fields(input: unknown, path: string, allowed: readonly string[], issues: Issues): Fields | undefined {
  if (!input || typeof input !== 'object' || Array.isArray(input)) { issues.add('type', path, 'Expected an object.'); return; }
  const source = input as Fields;
  for (const key of Object.keys(source)) if (!allowed.includes(key)) issues.add('unknown_field', at(path, key), 'Unknown domain-type field.');
  for (const key of allowed) if (!Object.hasOwn(source, key)) issues.add('required', at(path, key), 'Required field is missing.');
  return source;
}
function array(input: unknown, path: string, maximum: number, issues: Issues): readonly unknown[] {
  if (!Array.isArray(input)) { issues.add('type', path, 'Expected an array.'); return []; }
  if (input.length > maximum) { issues.add('limit', path, 'The permitted array length was exceeded.'); return []; }
  return input;
}
function safeKey(input: unknown, path: string, issues: Issues): input is string {
  if (typeof input !== 'string' || !identifier.test(input) || reserved.has(input)) { issues.add('format', path, 'Expected a safe identifier of at most 64 characters.'); return false; }
  return true;
}
function identity(input: unknown, path: string, issues: Issues): input is string {
  if (typeof input !== 'string' || !uuid.test(input)) { issues.add('format', path, 'Expected a canonical lowercase UUID.'); return false; }
  return true;
}
function version(input: unknown, path: string, issues: Issues): input is number {
  if (typeof input !== 'number' || !Number.isInteger(input) || input < 1 || input > 2147483647) {
    issues.add('model_version', path, 'Expected a positive database integer version.'); return false;
  }
  return true;
}
function lifecycle(input: unknown, issues: Issues): LifecycleDefinition | null | undefined {
  if (input === null) return null;
  const source = fields(input, '/lifecycle', ['initial', 'states', 'transitions'], issues); if (!source) return;
  safeKey(source.initial, '/lifecycle/initial', issues);
  const states = array(source.states, '/lifecycle/states', DOMAIN_TYPE_LIMITS.states, issues);
  const transitions = array(source.transitions, '/lifecycle/transitions', DOMAIN_TYPE_LIMITS.transitions, issues);
  const seen = new Set<string>();
  if (!states.length) issues.add('invalid_definition', '/lifecycle/states', 'At least one lifecycle state is required.');
  for (const [index, state] of states.entries()) if (safeKey(state, `/lifecycle/states/${index}`, issues)) {
    if (seen.has(state)) issues.add('duplicate', `/lifecycle/states/${index}`, 'Duplicate lifecycle state.'); seen.add(state);
  }
  if (!seen.has(source.initial as string)) issues.add('invalid_definition', '/lifecycle/initial', 'The initial state must be declared.');
  const seenEdges = new Set<string>(), accepted: { from: string; to: string }[] = [];
  for (const [index, input] of transitions.entries()) {
    const path = `/lifecycle/transitions/${index}`, edge = fields(input, path, ['from', 'to'], issues); if (!edge) continue;
    if (!safeKey(edge.from, at(path, 'from'), issues) || !safeKey(edge.to, at(path, 'to'), issues)) continue;
    if (!seen.has(edge.from) || !seen.has(edge.to)) issues.add('invalid_definition', path, 'Transition endpoints must be declared.');
    if (edge.from === edge.to) issues.add('invalid_definition', path, 'Self transitions are not supported.');
    const key = `${edge.from}\0${edge.to}`; if (seenEdges.has(key)) issues.add('duplicate', path, 'Duplicate lifecycle transition.');
    seenEdges.add(key); accepted.push({ from: edge.from, to: edge.to });
  }
  return { initial: source.initial as string, states: states as string[], transitions: accepted };
}
function parseDefinition(input: unknown): ValidationResult<DomainTypeDefinition> {
  const issues = new Issues(), source = fields(input, '', ['formatVersion', 'kind', 'id', 'version', 'label', 'parents', 'attributes', 'overrideAttributes', 'requiredOwner', 'lifecycle'], issues);
  if (!source) return issues.result(undefined as never);
  if (encoder.encode(canonical(source)).length > DOMAIN_TYPE_LIMITS.definitionBytes) issues.add('limit', '', 'Domain-type definition exceeds its UTF-8 byte bound.');
  if (source.formatVersion !== 1) issues.add('invalid_definition', '/formatVersion', 'Only domain-type format version 1 is supported.');
  if (source.kind !== 'domain-type') issues.add('invalid_definition', '/kind', 'Expected the domain-type kind.');
  safeKey(source.id, '/id', issues); version(source.version, '/version', issues);
  if (typeof source.label !== 'string') issues.add('type', '/label', 'Expected a label.');
  else if (!source.label.trim().length || [...source.label].length > 200 || /\p{Cc}/u.test(source.label))
    issues.add('format', '/label', 'Labels require 1–200 Unicode characters without control characters.');
  const model = parseModelDefinition({ formatVersion: 1, id: 'domain_type_validation', version: 1, attributes: source.attributes });
  if (!model.ok) issues.append('', model.issues);
  const rawParents = array(source.parents, '/parents', DOMAIN_TYPE_LIMITS.parents, issues), parents: DomainTypePin[] = [], parentIds = new Set<string>();
  for (const [index, input] of rawParents.entries()) {
    const path = `/parents/${index}`, pin = fields(input, path, ['typeId', 'version'], issues); if (!pin) continue;
    const validId = identity(pin.typeId, at(path, 'typeId'), issues), validVersion = version(pin.version, at(path, 'version'), issues);
    if (!validId || !validVersion) continue;
    if (parentIds.has(pin.typeId as string)) issues.add('duplicate', path, 'A domain parent UUID can be pinned only once.');
    parentIds.add(pin.typeId as string); parents.push({ typeId: pin.typeId as string, version: pin.version as number });
  }
  const overrides = array(source.overrideAttributes, '/overrideAttributes', MODEL_LIMITS.properties, issues), overrideIds = new Set<string>();
  for (const [index, key] of overrides.entries()) if (safeKey(key, `/overrideAttributes/${index}`, issues)) {
    if (overrideIds.has(key)) issues.add('duplicate', `/overrideAttributes/${index}`, 'Duplicate override declaration.');
    if (model.ok && !Object.hasOwn(model.value.attributes, key)) issues.add('invalid_definition', `/overrideAttributes/${index}`, 'An override requires a local attribute.');
    overrideIds.add(key);
  }
  if (typeof source.requiredOwner !== 'boolean') issues.add('type', '/requiredOwner', 'Expected a boolean.');
  const policy = lifecycle(source.lifecycle, issues);
  if (!rawParents.length && policy === null) issues.add('invalid_definition', '/lifecycle', 'A root domain type requires an explicit lifecycle.');
  if (issues.values.length || !model.ok) return issues.result(undefined as never);
  return issues.result({ formatVersion: 1, kind: 'domain-type', id: source.id as string, version: source.version as number,
    label: source.label as string, parents, attributes: model.value.attributes, overrideAttributes: overrides as string[],
    requiredOwner: source.requiredOwner as boolean, lifecycle: policy as LifecycleDefinition | null });
}
export function parseDomainTypeDefinition(input: unknown): ValidationResult<DomainTypeDefinition> {
  const issues = new Issues(), copied = copyJSON(input, issues, new Budget(issues, DOMAIN_TYPE_LIMITS.definitionBytes));
  return issues.values.length ? issues.result(undefined as never) : parseDefinition(copied);
}
export function parseDomainTypeFile(text: string): ValidationResult<DomainTypeDefinition> {
  if (typeof text !== 'string' || text.length > DOMAIN_TYPE_LIMITS.definitionBytes || encoder.encode(text).length > DOMAIN_TYPE_LIMITS.definitionBytes)
    return freeze({ ok: false, issues: [{ code: 'limit', path: '', message: 'Domain-type file exceeds its UTF-8 byte bound.' }] });
  const parsed = parseBoundedJSONFile(text, 'domain-type');
  return parsed.ok ? parseDomainTypeDefinition(parsed.value) : freeze(parsed);
}
interface NodeResolution { readonly model: ModelDefinition; readonly requiredOwner: boolean; readonly lifecycle: LifecycleDefinition; readonly height: number }
export function resolveDomainType(typeId: string, input: unknown,
  dependencies: readonly { typeId: string; definition: unknown }[]): ValidationResult<ResolvedDomainType> {
  const issues = new Issues(), budget = new Budget(issues, DOMAIN_TYPE_LIMITS.bytes);
  const copied = copyJSON({ typeId, input, dependencies }, issues, budget) as Fields;
  if (issues.values.length) return issues.result(undefined as never);
  identity(copied.typeId, '/typeId', issues);
  const parsed = parseDefinition(copied.input); if (!parsed.ok) issues.append('', parsed.issues);
  const supplied = array(copied.dependencies, '/dependencies', DOMAIN_TYPE_LIMITS.dependencies, issues);
  if (!parsed.ok || issues.values.length) return issues.result(undefined as never);
  const definition = parsed.value, definitions = new Map<string, { definition: DomainTypeDefinition; path: string }>([[typeId, { definition, path: '' }]]);
  const keys = new Map([[definition.id, typeId]]); budget.retain(definition, '');
  for (const [index, input] of supplied.entries()) {
    const path = `/dependencies/${index}`, envelope = fields(input, path, ['typeId', 'definition'], issues); if (!envelope) continue;
    const validId = identity(envelope.typeId, `${path}/typeId`, issues), dependency = parseDefinition(envelope.definition);
    if (!dependency.ok) { issues.append(`${path}/definition`, dependency.issues); continue; }
    if (!validId) continue;
    const id = envelope.typeId as string;
    if (definitions.has(id)) issues.add('duplicate', `${path}/typeId`, 'Supplied domain-type UUID identities must be unique.');
    else definitions.set(id, { definition: dependency.value, path: `${path}/definition` });
    if (keys.has(dependency.value.id) && keys.get(dependency.value.id) !== id) issues.add('model_identity', `${path}/definition/id`, 'Distinct domain-type UUIDs cannot reuse an immutable logical key.');
    keys.set(dependency.value.id, id); budget.retain(dependency.value, path);
    if (budget.exhausted || issues.overflow) break;
  }
  if (issues.values.length) return issues.result(undefined as never);
  const active = new Set<string>(), used = new Map<string, DomainTypePin>(), cache = new Map<string, NodeResolution>();
  const visit = (id: string, current: DomainTypeDefinition, path: string, depth: number): NodeResolution | undefined => {
    if (budget.exhausted || issues.overflow) return;
    if (depth > DOMAIN_TYPE_LIMITS.ancestryEdges) { issues.add('limit', path, 'The permitted ancestry depth was exceeded.'); return; }
    if (active.has(id)) { issues.add('cycle', path, 'Domain-type ancestry cannot contain UUID cycles.'); return; }
    const memo = cache.get(id);
    if (memo) {
      if (depth + memo.height > DOMAIN_TYPE_LIMITS.ancestryEdges) { issues.add('limit', path, 'The permitted ancestry depth was exceeded.'); return; }
      return memo;
    }
    active.add(id);
    try {
      const parents: NodeResolution[] = [];
      const sorted = current.parents.map((pin, index) => ({ pin, index })).sort((a, b) => compare(a.pin.typeId, b.pin.typeId) || a.pin.version - b.pin.version);
      for (const { pin, index } of sorted) {
        const pinPath = `${path}/parents/${index}`;
        if (active.has(pin.typeId)) { issues.add('cycle', pinPath, 'Domain-type ancestry cannot contain UUID cycles.'); continue; }
        const prior = used.get(pin.typeId);
        if (prior && prior.version !== pin.version) { issues.add('model_version', pinPath, 'An ancestor UUID cannot have conflicting pinned versions.'); continue; }
        const parent = definitions.get(pin.typeId);
        if (!parent) { issues.add('invalid_definition', pinPath, 'An exact domain parent dependency is missing.'); continue; }
        if (parent.definition.version !== pin.version) { issues.add('model_version', pinPath, 'The dependency does not match its exact version pin.'); continue; }
        used.set(pin.typeId, { ...pin });
        const resolved = visit(pin.typeId, parent.definition, parent.path, depth + 1); if (resolved) parents.push(resolved);
      }
      if (parents.length !== current.parents.length) return;
      const inherited = new Map<string, AttributeDefinition>(), conflicts = new Set<string>();
      for (const parent of parents) for (const [key, attribute] of Object.entries(parent.model.attributes)) {
        if (inherited.has(key) && canonical(inherited.get(key)) !== canonical(attribute)) conflicts.add(key);
        else inherited.set(key, attribute);
      }
      for (const key of [...conflicts].sort()) if (!Object.hasOwn(current.attributes, key)) issues.add('invalid_definition', `${path}/attributes/${key}`, 'Conflicting inherited attributes require an explicit local replacement.');
      const declared = new Set(current.overrideAttributes);
      for (const [index, key] of current.overrideAttributes.entries()) if (!inherited.has(key)) issues.add('invalid_definition', `${path}/overrideAttributes/${index}`, 'An override must replace an inherited attribute.');
      for (const key of Object.keys(current.attributes).sort()) if (inherited.has(key) && !declared.has(key)) issues.add('invalid_definition', `${path}/attributes/${key}`, 'Replacing an inherited attribute requires an explicit override declaration.');
      const model = parseModelDefinition({ formatVersion: 1, id: current.id, version: current.version, attributes: { ...Object.fromEntries(inherited), ...current.attributes } });
      if (!model.ok) issues.append(path, model.issues);
      let policy = current.lifecycle;
      if (policy === null) {
        const candidates = new Map(parents.map(parent => [canonical(parent.lifecycle), parent.lifecycle]));
        if (candidates.size !== 1) issues.add('invalid_definition', `${path}/lifecycle`, 'Inherited lifecycle is ambiguous; provide an explicit lifecycle.');
        else policy = [...candidates.values()][0];
      }
      if (!model.ok || !policy) return;
      const result = { model: model.value, requiredOwner: current.requiredOwner || parents.some(parent => parent.requiredOwner), lifecycle: policy,
        height: parents.length ? Math.max(...parents.map(parent => parent.height)) + 1 : 0 };
      if (!budget.retain(result, path)) return;
      cache.set(id, result); return result;
    } finally { active.delete(id); }
  };
  const resolved = visit(typeId, definition, '', 0);
  for (const [id, supplied] of definitions) if (id !== typeId && !used.has(id)) issues.add('invalid_definition', supplied.path, 'Unused dependency envelopes are not permitted.');
  if (!resolved || issues.values.length) return issues.result(undefined as never);
  const value: ResolvedDomainType = { attributes: resolved.model.attributes, requiredOwner: resolved.requiredOwner, lifecycle: resolved.lifecycle,
    dependencies: [...used.values()].sort((a, b) => compare(a.typeId, b.typeId) || a.version - b.version) };
  budget.retain(value, '/resolved'); return issues.result(value);
}
/** Adapter for already parsed definitions and successful domain resolution.
 * This does not establish a type pin, publication or permission. */
export function domainTypeAttributeModel(definition: DomainTypeDefinition, resolved: ResolvedDomainType): ModelDefinition {
  return Object.freeze({ formatVersion: 1, id: definition.id, version: definition.version, attributes: resolved.attributes });
}
