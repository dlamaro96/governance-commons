// SPDX-License-Identifier: Apache-2.0
import { MODEL_LIMITS, parseBoundedJSONFile, previewModelUpgrade, validateAttributes,
  type ModelChange, type ValidationIssue, type ValidationIssueCode, type ValidationResult } from './model.ts';
import { applyModelMigrationToAttributes, parseMigrationPlan, validateMigrationPlanForModels } from './model-migration.ts';
import { domainTypeAttributeModel, parseDomainTypeDefinition, resolveDomainType } from './business-domain-type.ts';
import type { DomainMigrationOutcome, DomainPolicyChange, DomainTuple, DomainTypeDefinition,
  DomainTypeMigrationPlan, DomainTypeView, DomainView, ResolvedDomainType } from './business-domain-contracts.ts';

/** Root-approved pure interface freeze. The caller supplies an authorized, locked,
 * complete directly bound cohort and actual stored history. These data fields,
 * hashes and coverage tag establish neither completeness nor authorization.
 * The dependency pool may contain historical versions of a UUID; each exact
 * resolver closure still permits only one version per UUID. */
export interface DomainTypeMigrationScope {
  readonly coverage: 'complete-direct-domain-type-bindings';
  readonly head: DomainTypeView;
  readonly sources: readonly DomainTypeView[];
  readonly target: { readonly definition: DomainTypeDefinition; readonly resolved: ResolvedDomainType };
  readonly domains: readonly DomainView[];
  readonly dependencies: readonly { readonly typeId: string; readonly definition: DomainTypeDefinition }[];
  /** Exact union of old and explicitly selected non-null owners, freshly read by the caller. */
  readonly ownerActivity: readonly { readonly identityId: string; readonly active: boolean }[];
}
export interface DomainTypeMigrationProjection {
  readonly plan: DomainTypeMigrationPlan;
  readonly changes: readonly ModelChange[];
  readonly policyChanges: readonly DomainPolicyChange[];
  readonly domains: readonly { readonly before: DomainView; readonly proposed: DomainTuple; readonly issues: readonly ValidationIssue[] }[];
  readonly issues: readonly ValidationIssue[];
  readonly valid: boolean;
}

export const DOMAIN_MIGRATION_LIMITS = Object.freeze({ domains: 1_000, principals: 2_001, ownerOverrides: 1_000,
  lifecycleMappings: 1_000, bytes: 524_288, nodes: 100_000, depth: 32, issues: 100 });

type Fields = Record<string, unknown>;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const identifier = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const reserved = new Set(['__proto__', 'constructor', 'prototype']);
const malformedUnicode = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const policyKinds: readonly DomainPolicyChange[] = ['parents_changed', 'required_owner_changed', 'lifecycle_changed'];
const encoder = new TextEncoder();
const at = (path: string, key: string | number) => `${path}/${String(key).replaceAll('~', '~0').replaceAll('/', '~1')}`;
const compare = (left: string, right: string) => left < right ? -1 : left > right ? 1 : 0;
const pinKey = (id: string, version: number) => `${id}/${version}`;
function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
}
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical((value as Fields)[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
class Issues {
  readonly values: ValidationIssue[] = []; count = 0; overflow = false;
  add(code: ValidationIssueCode, path: string, message: string, sink = this.values) {
    if (this.count < DOMAIN_MIGRATION_LIMITS.issues - 1) { sink.push({ code, path, message }); this.count += 1; }
    else this.overflow = true;
  }
  append(prefix: string, values: readonly ValidationIssue[], sink = this.values) { for (const value of values) this.add(value.code, prefix + value.path, value.message, sink); }
  finish() {
    if (this.overflow && this.count < DOMAIN_MIGRATION_LIMITS.issues) { this.values.push({ code: 'limit', path: '', message: 'Further domain migration issues were omitted.' }); this.count += 1; }
  }
  result<T>(value: T): ValidationResult<T> { this.finish(); return this.count ? freeze({ ok: false, issues: this.values }) : freeze({ ok: true, value }); }
}
class Budget {
  bytes = 0; nodes = 0; exhausted = false;
  constructor(readonly issues: Issues) {}
  charge(bytes: number, nodes: number, path: string): boolean {
    this.bytes += bytes; this.nodes += nodes;
    if (this.bytes <= DOMAIN_MIGRATION_LIMITS.bytes && this.nodes <= DOMAIN_MIGRATION_LIMITS.nodes) return true;
    if (!this.exhausted) this.issues.add('limit', path, 'The aggregate retained UTF-8 byte or node budget was exceeded.');
    this.exhausted = true; return false;
  }
  retain(value: unknown, path: string): boolean {
    let nodes = 0;
    const count = (item: unknown) => { nodes += 1; if (item && typeof item === 'object') for (const child of Object.values(item)) count(child); };
    count(value); return this.charge(encoder.encode(canonical(value)).length, nodes, path);
  }
}
function copyJSON(input: unknown, issues: Issues, budget: Budget): unknown {
  const active = new Set<object>();
  const copy = (value: unknown, path: string, depth: number): unknown => {
    if (budget.exhausted || issues.overflow) return;
    if (depth > DOMAIN_MIGRATION_LIMITS.depth) { issues.add('limit', path, 'JSON nesting exceeds the domain migration profile.'); return; }
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
    if (isArray && (value.length > 2_048 || keys.length !== value.length + 1)) { issues.add('limit', path, 'Array must be bounded, dense and contain no extra properties.'); return; }
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
function fields(input: unknown, path: string, names: readonly string[], issues: Issues): Fields | undefined {
  if (!input || typeof input !== 'object' || Array.isArray(input)) { issues.add('type', path, 'Expected an object.'); return; }
  const source = input as Fields;
  for (const key of Object.keys(source)) if (!names.includes(key)) issues.add('unknown_field', at(path, key), 'Unknown domain migration field.');
  for (const key of names) if (!Object.hasOwn(source, key)) issues.add('required', at(path, key), 'Required field is missing.');
  return source;
}
function list(input: unknown, path: string, maximum: number, issues: Issues): readonly unknown[] {
  if (!Array.isArray(input)) { issues.add('type', path, 'Expected an array.'); return []; }
  if (input.length > maximum) { issues.add('limit', path, 'Array length exceeds its bound.'); return []; }
  return input;
}
function id(input: unknown, path: string, issues: Issues): input is string {
  if (typeof input !== 'string' || !uuid.test(input)) { issues.add('format', path, 'Expected a canonical lowercase UUID.'); return false; } return true;
}
function version(input: unknown, path: string, issues: Issues): input is number {
  if (typeof input !== 'number' || !Number.isInteger(input) || input < 1 || input > 2147483647) { issues.add('model_version', path, 'Expected a positive database integer version.'); return false; } return true;
}
function key(input: unknown, path: string, issues: Issues): input is string {
  if (typeof input !== 'string' || !identifier.test(input) || reserved.has(input)) { issues.add('format', path, 'Expected a safe identifier.'); return false; } return true;
}
function choice(input: unknown, values: readonly string[], path: string, issues: Issues) {
  if (typeof input !== 'string' || !values.includes(input)) issues.add('enum', path, 'Unsupported domain migration option.');
}
function text(input: unknown, path: string, maximum: number, required: boolean, issues: Issues) {
  if (typeof input !== 'string') issues.add('type', path, 'Expected text.');
  else if (malformedUnicode.test(input) || /\p{Cc}/u.test(input) || [...input].length > maximum || required && !input.trim().length)
    issues.add('format', path, 'Text must be well-formed, bounded and contain no control characters.');
}
function timestamp(input: unknown, path: string, issues: Issues) {
  const checked = validateAttributes({ formatVersion: 1, id: 'domain_time', version: 1, attributes: { value: { type: 'timestamp', required: true } } }, { value: input });
  if (!checked.ok) issues.append(path, checked.issues.map(issue => ({ ...issue, path: issue.path.replace(/^\/value/, '') })));
}
function parsePlan(input: unknown, issues: Issues): DomainTypeMigrationPlan | undefined {
  const source = fields(input, '', ['formatVersion', 'kind', 'typeId', 'attributes', 'owner', 'lifecycle', 'acknowledgedPolicyChanges'], issues); if (!source) return;
  if (source.formatVersion !== 1) issues.add('invalid_definition', '/formatVersion', 'Only migration format version 1 is supported.');
  if (source.kind !== 'domain-type-migration') issues.add('invalid_definition', '/kind', 'Expected a domain-type-migration plan.');
  id(source.typeId, '/typeId', issues);
  const attributes = parseMigrationPlan(source.attributes);
  if (!attributes.ok) issues.append('/attributes', attributes.issues);
  else { version(attributes.value.targetVersion, '/attributes/targetVersion', issues); attributes.value.sourceVersions.forEach((value, index) => version(value, `/attributes/sourceVersions/${index}`, issues)); }
  const owner = fields(source.owner, '/owner', ['default', 'overrides'], issues);
  const owners = new Set<string>();
  if (owner) {
    choice(owner.default, ['preserve'], '/owner/default', issues);
    for (const [index, input] of list(owner.overrides, '/owner/overrides', DOMAIN_MIGRATION_LIMITS.ownerOverrides, issues).entries()) {
      const path = `/owner/overrides/${index}`, item = fields(input, path, ['domainId', 'ownerId'], issues); if (!item) continue;
      if (id(item.domainId, `${path}/domainId`, issues)) { if (owners.has(item.domainId)) issues.add('duplicate', path, 'A domain may have only one owner override.'); owners.add(item.domainId); }
      if (item.ownerId !== null) id(item.ownerId, `${path}/ownerId`, issues);
    }
  }
  const lifecycle = fields(source.lifecycle, '/lifecycle', ['onUnmapped', 'mappings'], issues), mappings = new Set<string>();
  if (lifecycle) {
    choice(lifecycle.onUnmapped, ['preserve', 'error'], '/lifecycle/onUnmapped', issues);
    for (const [index, input] of list(lifecycle.mappings, '/lifecycle/mappings', DOMAIN_MIGRATION_LIMITS.lifecycleMappings, issues).entries()) {
      const path = `/lifecycle/mappings/${index}`, item = fields(input, path, ['sourceVersion', 'from', 'to'], issues); if (!item) continue;
      version(item.sourceVersion, `${path}/sourceVersion`, issues); key(item.from, `${path}/from`, issues); key(item.to, `${path}/to`, issues);
      const identity = canonical([item.sourceVersion, item.from]);
      if (mappings.has(identity)) issues.add('duplicate', path, 'Each source-version/state mapping must be unique.'); mappings.add(identity);
    }
  }
  const acknowledgements = list(source.acknowledgedPolicyChanges, '/acknowledgedPolicyChanges', policyKinds.length, issues), seen = new Set<unknown>();
  for (const [index, value] of acknowledgements.entries()) {
    choice(value, policyKinds, `/acknowledgedPolicyChanges/${index}`, issues);
    if (seen.has(value)) issues.add('duplicate', `/acknowledgedPolicyChanges/${index}`, 'Duplicate policy acknowledgement.'); seen.add(value);
  }
  if (issues.count || !attributes.ok) return;
  return { ...(source as unknown as DomainTypeMigrationPlan), attributes: attributes.value };
}
export function parseDomainTypeMigrationPlan(input: unknown): ValidationResult<DomainTypeMigrationPlan> {
  const issues = new Issues(), budget = new Budget(issues), copied = copyJSON(input, issues, budget);
  if (issues.count) return issues.result(undefined as never);
  const parsed = parsePlan(copied, issues); if (parsed) budget.retain(parsed, '/plan');
  return issues.result(parsed as DomainTypeMigrationPlan);
}
export function parseDomainTypeMigrationFile(input: string): ValidationResult<DomainTypeMigrationPlan> {
  if (typeof input !== 'string' || input.length > DOMAIN_MIGRATION_LIMITS.bytes || encoder.encode(input).length > DOMAIN_MIGRATION_LIMITS.bytes)
    return freeze({ ok: false, issues: [{ code: 'limit', path: '', message: 'Migration file exceeds its UTF-8 byte bound.' }] });
  const parsed = parseBoundedJSONFile(input, 'domain-migration');
  return parsed.ok ? parseDomainTypeMigrationPlan(parsed.value) : freeze(parsed);
}

function parseScope(input: unknown, plan: DomainTypeMigrationPlan, issues: Issues, budget: Budget): DomainTypeMigrationScope | undefined {
  const scope = fields(input, '/scope', ['coverage', 'head', 'sources', 'target', 'domains', 'dependencies', 'ownerActivity'], issues); if (!scope) return;
  if (scope.coverage !== 'complete-direct-domain-type-bindings') issues.add('invalid_definition', '/scope/coverage', 'Expected a complete direct-domain scope supplied by the caller.');
  const pool = new Map<string, { typeId: string; definition: DomainTypeDefinition; path: string }>(), used = new Set<string>();
  const keyIds = new Map<string, string>(), idKeys = new Map<string, string>();
  const immutableKey = (typeId: string, authoredKey: string, path: string) => {
    if (idKeys.has(typeId) && idKeys.get(typeId) !== authoredKey || keyIds.has(authoredKey) && keyIds.get(authoredKey) !== typeId)
      issues.add('model_identity', path, 'UUID identities and immutable domain-type keys must remain one-to-one.');
    idKeys.set(typeId, authoredKey); keyIds.set(authoredKey, typeId);
  };
  for (const [index, input] of list(scope.dependencies, '/scope/dependencies', 2_048, issues).entries()) {
    const path = `/scope/dependencies/${index}`, item = fields(input, path, ['typeId', 'definition'], issues); if (!item) continue;
    const validId = id(item.typeId, `${path}/typeId`, issues), parsed = parseDomainTypeDefinition(item.definition);
    if (!parsed.ok) issues.append(`${path}/definition`, parsed.issues);
    if (!validId || !parsed.ok) continue;
    const typeId = item.typeId as string;
    immutableKey(typeId, parsed.value.id, `${path}/definition/id`);
    const identity = pinKey(typeId, parsed.value.version);
    if (pool.has(identity)) issues.add('duplicate', path, 'Each exact dependency UUID/version must occur once.');
    pool.set(identity, { typeId, definition: parsed.value, path }); budget.retain(parsed.value, path);
    if (budget.exhausted || issues.overflow) return;
  }
  const policy = (typeId: string, definitionInput: unknown, resolvedInput: unknown, path: string): { definition: DomainTypeDefinition; resolved: ResolvedDomainType } | undefined => {
    const parsed = parseDomainTypeDefinition(definitionInput);
    if (!parsed.ok) { issues.append(`${path}/definition`, parsed.issues); return; }
    immutableKey(typeId, parsed.value.id, `${path}/definition/id`);
    const selected = new Map<string, { typeId: string; definition: DomainTypeDefinition }>();
    const collect = (definition: DomainTypeDefinition, depth: number) => {
      if (depth > 8 || selected.size > 64) { issues.add('limit', `${path}/definition/parents`, 'Domain policy dependency closure exceeds its bounds.'); return; }
      for (const pin of definition.parents) {
        if (pin.typeId === typeId) continue; // The resolver reports root UUID cycles precisely.
        const identity = pinKey(pin.typeId, pin.version); if (selected.has(identity)) continue;
        const dependency = pool.get(identity);
        if (!dependency) { issues.add('required', `${path}/definition/parents`, 'An exact domain policy dependency is missing.'); continue; }
        selected.set(identity, { typeId: dependency.typeId, definition: dependency.definition }); used.add(identity); collect(dependency.definition, depth + 1);
      }
    };
    collect(parsed.value, 0);
    const resolved = resolveDomainType(typeId, parsed.value, [...selected.values()]);
    if (!resolved.ok) { issues.append(path, resolved.issues); return; }
    if (canonical(resolved.value) !== canonical(resolvedInput)) issues.add('invalid_definition', `${path}/resolved`, 'The recorded resolution must equal the recomputed exact dependency closure.');
    budget.retain(parsed.value, `${path}/definition`); budget.retain(resolved.value, `${path}/resolved`);
    return { definition: parsed.value, resolved: resolved.value };
  };
  const typeView = (input: unknown, path: string): DomainTypeView | undefined => {
    const view = fields(input, path, ['typeId', 'key', 'version', 'currentVersion', 'definition', 'resolved', 'definitionHash', 'resolutionHash', 'createdAt', 'createdBy'], issues); if (!view) return;
    const validId = id(view.typeId, `${path}/typeId`, issues); key(view.key, `${path}/key`, issues);
    version(view.version, `${path}/version`, issues); version(view.currentVersion, `${path}/currentVersion`, issues);
    if (typeof view.currentVersion === 'number' && typeof view.version === 'number' && view.currentVersion < view.version)
      issues.add('model_version', `${path}/currentVersion`, 'A stored version cannot exceed its current head.');
    for (const field of ['definitionHash', 'resolutionHash']) if (typeof view[field] !== 'string' || !/^[0-9a-f]{64}$/.test(view[field] as string)) issues.add('format', `${path}/${field}`, 'Expected a canonical SHA-256 digest; actual history binding remains a service obligation.');
    timestamp(view.createdAt, `${path}/createdAt`, issues); id(view.createdBy, `${path}/createdBy`, issues);
    if (!validId) return;
    const parsed = policy(view.typeId as string, view.definition, view.resolved, path); if (!parsed) return;
    if (view.key !== parsed.definition.id) issues.add('model_identity', `${path}/key`, 'The view key must equal its immutable authored key.');
    if (view.version !== parsed.definition.version) issues.add('model_version', `${path}/version`, 'The view must identify its exact authored version.');
    return { ...(view as unknown as DomainTypeView), ...parsed };
  };
  const head = typeView(scope.head, '/scope/head');
  if (!head || issues.count || budget.exhausted) return;
  if (head.version !== head.currentVersion) issues.add('model_version', '/scope/head/version', 'The supplied head must be current.');
  const targetInput = fields(scope.target, '/scope/target', ['definition', 'resolved'], issues);
  const target = targetInput && policy(head.typeId, targetInput.definition, targetInput.resolved, '/scope/target');
  const sources: DomainTypeView[] = [], byVersion = new Map<number, DomainTypeView>();
  for (const [index, input] of list(scope.sources, '/scope/sources', DOMAIN_MIGRATION_LIMITS.domains, issues).entries()) {
    const path = `/scope/sources/${index}`, view = typeView(input, path); if (!view) continue;
    if (view.typeId !== head.typeId || view.key !== head.key) issues.add('model_identity', path, 'All source policies must belong to the exact domain-type UUID and key.');
    if (view.version > head.version || view.currentVersion !== head.version) issues.add('model_version', path, 'Source policy versions must belong to the captured head.');
    if (byVersion.has(view.version)) issues.add('duplicate', path, 'Source policy versions must be unique.');
    if (view.version === head.version && canonical(view) !== canonical(head)) issues.add('invalid_definition', path, 'A source at the head version must equal the actual immutable head.');
    byVersion.set(view.version, view); sources.push(view);
    if (budget.exhausted || issues.overflow) return;
  }
  const domains: DomainView[] = [], identities = new Set<string>(), sourceVersions = new Set<number>(), ownerIds = new Set<string>();
  for (const [index, input] of list(scope.domains, '/scope/domains', DOMAIN_MIGRATION_LIMITS.domains, issues).entries()) {
    const path = `/scope/domains/${index}`, view = fields(input, path, ['id', 'version', 'name', 'description', 'parentId', 'type', 'attributes', 'ownerId', 'state', 'status', 'createdAt', 'createdBy', 'updatedAt', 'updatedBy'], issues); if (!view) continue;
    const validId = id(view.id, `${path}/id`, issues); version(view.version, `${path}/version`, issues);
    if (view.version === 2147483647) issues.add('limit', `${path}/version`, 'Domain revision cannot advance past the database integer limit.');
    if (validId) { if (identities.has(view.id as string)) issues.add('duplicate', `${path}/id`, 'The complete cohort must contain each domain once.'); identities.add(view.id as string); }
    text(view.name, `${path}/name`, 200, true, issues); text(view.description, `${path}/description`, 4_000, false, issues);
    if (view.parentId !== null) id(view.parentId, `${path}/parentId`, issues);
    if (view.parentId === view.id) issues.add('cycle', `${path}/parentId`, 'A stored domain cannot parent itself.');
    if (view.ownerId !== null && id(view.ownerId, `${path}/ownerId`, issues)) ownerIds.add(view.ownerId);
    key(view.state, `${path}/state`, issues); choice(view.status, ['active', 'retired'], `${path}/status`, issues);
    for (const field of ['createdAt', 'updatedAt']) timestamp(view[field], `${path}/${field}`, issues);
    for (const field of ['createdBy', 'updatedBy']) id(view[field], `${path}/${field}`, issues);
    if (typeof view.createdAt === 'string' && typeof view.updatedAt === 'string' && Date.parse(view.createdAt) > Date.parse(view.updatedAt))
      issues.add('invalid_definition', `${path}/updatedAt`, 'Update time cannot precede creation time.');
    const pin = fields(view.type, `${path}/type`, ['typeId', 'version'], issues);
    if (pin) {
      id(pin.typeId, `${path}/type/typeId`, issues); version(pin.version, `${path}/type/version`, issues);
      if (pin.typeId !== head.typeId) issues.add('model_identity', `${path}/type/typeId`, 'Every direct domain must retain the exact root domain-type UUID.');
      const source = byVersion.get(pin.version as number); sourceVersions.add(pin.version as number);
      if (!source) issues.add('required', `${path}/type`, 'The complete cohort requires its exact source policy.');
      else {
        const attributes = validateAttributes(domainTypeAttributeModel(source.definition, source.resolved), view.attributes);
        if (!attributes.ok) issues.append(`${path}/attributes`, attributes.issues);
        if (!source.resolved.lifecycle.states.includes(view.state as string)) issues.add('enum', `${path}/state`, 'The stored source state is invalid for its exact pinned lifecycle.');
      }
    }
    domains.push(view as unknown as DomainView); budget.retain(view, path);
    if (budget.exhausted || issues.overflow) return;
  }
  for (const source of sources) if (!sourceVersions.has(source.version)) issues.add('invalid_definition', '/scope/sources', 'Unused source policies are not permitted.');
  for (const [identity, dependency] of pool) if (!used.has(identity)) issues.add('invalid_definition', dependency.path, 'Unused dependency definitions are not permitted.');
  for (const override of plan.owner.overrides) if (override.ownerId !== null) ownerIds.add(override.ownerId);
  const ownerActivity: { identityId: string; active: boolean }[] = [], activityIds = new Set<string>();
  for (const [index, input] of list(scope.ownerActivity, '/scope/ownerActivity', DOMAIN_MIGRATION_LIMITS.principals, issues).entries()) {
    const path = `/scope/ownerActivity/${index}`, entry = fields(input, path, ['identityId', 'active'], issues); if (!entry) continue;
    if (id(entry.identityId, `${path}/identityId`, issues)) {
      if (activityIds.has(entry.identityId)) issues.add('duplicate', path, 'Owner activity identities must be unique.');
      if (!ownerIds.has(entry.identityId)) issues.add('invalid_definition', path, 'Unused owner activity entries are not permitted.');
      activityIds.add(entry.identityId);
    }
    if (typeof entry.active !== 'boolean') issues.add('type', `${path}/active`, 'Owner activity must be a freshly captured boolean.');
    ownerActivity.push(entry as unknown as { identityId: string; active: boolean });
  }
  for (const ownerId of ownerIds) if (!activityIds.has(ownerId)) issues.add('required', '/scope/ownerActivity', 'The complete old/new owner union requires explicit activity evidence.');
  if (!target || issues.count || budget.exhausted) return;
  return { coverage: 'complete-direct-domain-type-bindings', head, target, sources: sources.sort((a, b) => a.version - b.version),
    domains: domains.sort((a, b) => compare(a.id, b.id)), dependencies: [...pool.values()].map(({ typeId, definition }) => ({ typeId, definition })), ownerActivity };
}
function policyChanges(scope: DomainTypeMigrationScope): DomainPolicyChange[] {
  const changes: DomainPolicyChange[] = [];
  const pins = (definition: DomainTypeDefinition) => [...definition.parents].sort((a, b) => compare(a.typeId, b.typeId) || a.version - b.version);
  if (canonical(pins(scope.head.definition)) !== canonical(pins(scope.target.definition))) changes.push('parents_changed');
  if (scope.head.resolved.requiredOwner !== scope.target.resolved.requiredOwner) changes.push('required_owner_changed');
  if (canonical(scope.head.resolved.lifecycle) !== canonical(scope.target.resolved.lifecycle)) changes.push('lifecycle_changed');
  return changes;
}
function tuple(domain: DomainView): DomainTuple {
  return { name: domain.name, description: domain.description, parentId: domain.parentId, type: domain.type,
    attributes: domain.attributes, ownerId: domain.ownerId, state: domain.state, status: domain.status };
}

/** Actual computed proposals only. Missing transform acknowledgements or failed
 * attribute transforms return failure because the shared engine supplies no
 * transformed value. Policy drafts may be returned invalid, without consent. */
function project(scope: DomainTypeMigrationScope, input: unknown, fatal: Issues, budget: Budget): ValidationResult<DomainTypeMigrationProjection> {
  const copied = copyJSON({ scope, plan: input }, fatal, budget) as Fields;
  if (fatal.count) return fatal.result(undefined as never);
  const planIssues = new Issues(), plan = parsePlan(copied.plan, planIssues);
  if (!plan) { planIssues.finish(); fatal.append('/plan', planIssues.values); return fatal.result(undefined as never); }
  budget.retain(plan, '/plan');
  const captured = parseScope(copied.scope, plan, fatal, budget);
  if (!captured || fatal.count) return fatal.result(undefined as never);
  const head = domainTypeAttributeModel(captured.head.definition, captured.head.resolved);
  const target = domainTypeAttributeModel(captured.target.definition, captured.target.resolved);
  const checked = validateMigrationPlanForModels(head, target, plan.attributes);
  if (!checked.ok) { fatal.append('/plan/attributes', checked.issues); return fatal.result(undefined as never); }
  const preview = previewModelUpgrade(head, target, []);
  if (!preview.ok) { fatal.append('/target', preview.issues); return fatal.result(undefined as never); }
  const issues = new Issues(), changes = policyChanges(captured);
  if (plan.typeId !== captured.head.typeId) issues.add('model_identity', '/plan/typeId', 'The plan must identify the captured immutable domain-type UUID.');
  if (target.version !== head.version + 1) issues.add('model_version', '/target/definition/version', 'A migration must publish exactly the next head version.');
  const versions = [...new Set(captured.domains.map(domain => domain.type.version))].sort((a, b) => a - b);
  if (canonical(versions) !== canonical(plan.attributes.sourceVersions)) issues.add('model_version', '/plan/attributes/sourceVersions', 'Source versions must equal the entire direct cohort, including retired domains.');
  for (const change of changes) if (!plan.acknowledgedPolicyChanges.includes(change)) issues.add('required', '/plan/acknowledgedPolicyChanges', `Policy change ${change} requires exact acknowledgement.`);
  for (const [index, change] of plan.acknowledgedPolicyChanges.entries()) if (!changes.includes(change)) issues.add('invalid_definition', `/plan/acknowledgedPolicyChanges/${index}`, 'Acknowledgement must match a head-to-target policy change.');
  const sources = new Map(captured.sources.map(source => [source.version, source])), domains = new Set(captured.domains.map(domain => domain.id));
  const overrides = new Map(plan.owner.overrides.map(override => [override.domainId, override]));
  for (const [index, override] of plan.owner.overrides.entries()) if (!domains.has(override.domainId)) issues.add('invalid_definition', `/plan/owner/overrides/${index}/domainId`, 'An owner override must identify a domain in the complete cohort.');
  for (const [index, mapping] of plan.lifecycle.mappings.entries()) {
    const source = sources.get(mapping.sourceVersion), path = `/plan/lifecycle/mappings/${index}`;
    if (!source?.resolved.lifecycle.states.includes(mapping.from)) issues.add('enum', `${path}/from`, 'Mapping must start in its exact source-version lifecycle.');
    if (!captured.target.resolved.lifecycle.states.includes(mapping.to)) issues.add('enum', `${path}/to`, 'Mapping must end in the target lifecycle.');
  }
  const activity = new Map(captured.ownerActivity.map(owner => [owner.identityId, owner.active]));
  const active = (ownerId: string | null) => ownerId !== null && activity.get(ownerId) === true;
  const projected: { before: DomainView; proposed: DomainTuple; issues: ValidationIssue[] }[] = [];
  for (const domain of captured.domains) {
    const source = sources.get(domain.type.version)!;
    const attributes = applyModelMigrationToAttributes({ head, source: domainTypeAttributeModel(source.definition, source.resolved), target, plan: plan.attributes, attributes: domain.attributes });
    if (!attributes.ok) { fatal.append(`/domains/${domain.id}/attributes`, attributes.issues); return fatal.result(undefined as never); }
    const domainIssues: ValidationIssue[] = [], override = overrides.get(domain.id), ownerId = override ? override.ownerId : domain.ownerId;
    if (source.resolved.requiredOwner && !active(domain.ownerId)) {
      const replacement = !!override && active(override.ownerId);
      const policyRepair = !captured.target.resolved.requiredOwner && plan.acknowledgedPolicyChanges.includes('required_owner_changed');
      if (!replacement && !policyRepair) issues.add('required', '/ownerId', 'A missing or inactive required source owner needs explicit active replacement or acknowledged removal of required ownership.', domainIssues);
    }
    if (override && override.ownerId !== null && !active(override.ownerId)) issues.add('required', '/ownerId', 'An explicitly selected non-null owner must be active.', domainIssues);
    if (captured.target.resolved.requiredOwner && !active(ownerId)) issues.add('required', '/ownerId', 'The target policy requires an active owner.', domainIssues);
    const mapping = plan.lifecycle.mappings.find(item => item.sourceVersion === domain.type.version && item.from === domain.state);
    const state = mapping ? mapping.to : domain.state;
    if (!mapping && plan.lifecycle.onUnmapped === 'error') issues.add('required', '/state', 'This source state requires an explicit lifecycle mapping.', domainIssues);
    if (!captured.target.resolved.lifecycle.states.includes(state)) issues.add('enum', '/state', 'The proposed state is not in the target lifecycle.', domainIssues);
    const proposed: DomainTuple = { ...tuple(domain), type: { typeId: captured.head.typeId, version: target.version }, attributes: attributes.value, ownerId, state };
    budget.retain(attributes.value, `/domains/${domain.id}/attributes`);
    projected.push({ before: domain, proposed, issues: domainIssues });
    if (budget.exhausted) return fatal.result(undefined as never);
  }
  issues.finish();
  const result: DomainTypeMigrationProjection = { plan, changes: preview.value.changes, policyChanges: changes, domains: projected, issues: issues.values, valid: issues.count === 0 };
  budget.retain(result, '/projection');
  return fatal.count ? fatal.result(undefined as never) : freeze({ ok: true, value: result });
}
export function projectDomainTypeMigration(scope: DomainTypeMigrationScope, input: unknown): ValidationResult<DomainTypeMigrationProjection> {
  const issues = new Issues(); return project(scope, input, issues, new Budget(issues));
}
export function applyDomainTypeMigration(scope: DomainTypeMigrationScope, input: unknown): ValidationResult<readonly DomainMigrationOutcome[]> {
  const fatal = new Issues(), budget = new Budget(fatal), projected = project(scope, input, fatal, budget); if (!projected.ok) return projected;
  if (!projected.value.valid) {
    const issues = new Issues(); issues.append('', projected.value.issues);
    for (const domain of projected.value.domains) issues.append(`/domains/${domain.before.id}`, domain.issues);
    return issues.result(undefined as never);
  }
  const outcomes = projected.value.domains.map(({ before, proposed }) => ({ domainId: before.id,
    fromVersion: before.version, toVersion: before.version + 1, before: tuple(before), after: proposed }));
  budget.retain(outcomes, '/outcomes'); return fatal.result(outcomes);
}
