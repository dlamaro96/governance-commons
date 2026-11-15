// SPDX-License-Identifier: Apache-2.0
import { parseAssetTypeDefinition, type ResolvedAssetType, type LifecycleDefinition } from './asset-type.ts';
import { parseMigrationPlan, validateMigrationPlanForModels, type MigrationPlan } from './model-migration.ts';
import { MODEL_LIMITS, parseModelDefinition, type ValidationIssue, type ValidationIssueCode, type ValidationResult } from './model.ts';

/** Pure policy transformations. Persistence must recompute pinned resolutions and authorize the whole cohort. */
export const ASSET_TYPE_MIGRATION_LIMITS = Object.freeze({
  assets: 1_000, ownerOverrides: 1_000, lifecycleMappings: 1_000, bytes: 512 * 1_024,
  nodes: 100_000, depth: 26, issues: 1_000,
});
export type AssetTypePolicyChange = 'parents_changed' | 'required_owner_changed' | 'lifecycle_changed';
export interface AssetTypeMigrationPlan {
  readonly formatVersion: 1;
  readonly typeId: string;
  readonly attributes: MigrationPlan;
  readonly owner: { readonly default: 'preserve'; readonly overrides: readonly { readonly assetId: string; readonly ownerId: string | null }[] };
  readonly lifecycle: { readonly onUnmapped: 'preserve' | 'error'; readonly mappings: readonly { readonly sourceVersion: number; readonly from: string; readonly to: string }[] };
  readonly acknowledgedPolicyChanges: readonly AssetTypePolicyChange[];
}
export interface AssetTypeMigrationScope {
  readonly typeId: string;
  readonly head: ResolvedAssetType;
  readonly target: ResolvedAssetType;
  readonly sources: readonly ResolvedAssetType[];
  readonly cohort: readonly { readonly assetId: string; readonly sourceVersion: number }[];
}
export interface AssetTypePolicyMigrationInput {
  readonly source: ResolvedAssetType;
  readonly target: ResolvedAssetType;
  readonly plan: AssetTypeMigrationPlan;
  readonly asset: { readonly assetId: string; readonly modelVersion: number; readonly ownerId: string | null; readonly state: string | null };
  /** Membership and identity activity, already tenant-scoped and locked by the caller. */
  readonly activeOwnerIds: ReadonlySet<string>;
}

type Fields = Record<string, unknown>;
const identifier = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const reserved = new Set(['__proto__', 'constructor', 'prototype']);
const malformedUnicode = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const changes: readonly AssetTypePolicyChange[] = ['parents_changed', 'required_owner_changed', 'lifecycle_changed'];
const encoder = new TextEncoder();
const at = (path: string, key: string | number): string => `${path}/${String(key).replaceAll('~', '~0').replaceAll('/', '~1')}`;
const compare = (a: string, b: string): number => a < b ? -1 : a > b ? 1 : 0;
class Issues {
  readonly values: ValidationIssue[] = [];
  overflow = false;
  add(code: ValidationIssueCode, path: string, message: string): void {
    if (this.values.length < ASSET_TYPE_MIGRATION_LIMITS.issues - 1) this.values.push({ code, path, message });
    else this.overflow = true;
  }
  append(prefix: string, values: readonly ValidationIssue[]): void {
    for (const issue of values) this.add(issue.code, prefix + issue.path, issue.message);
  }
  result<T>(value: T): ValidationResult<T> {
    if (this.overflow && this.values.length < ASSET_TYPE_MIGRATION_LIMITS.issues) this.values.push({ code: 'limit', path: '', message: 'Further migration issues were omitted.' });
    return this.values.length ? { ok: false, issues: this.values } : { ok: true, value };
  }
}
function freeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
}

/** Defensive bounded copying never reads a supplied accessor or calls supplied toJSON methods. */
function copyJSON(input: unknown, issues: Issues): unknown {
  const active = new Set<object>(); let nodes = 0; let bytes = 0;
  const charge = (amount: number, path: string): boolean => {
    bytes += amount;
    if (bytes <= ASSET_TYPE_MIGRATION_LIMITS.bytes) return true;
    issues.add('limit', path, 'The aggregate JSON byte budget was exceeded.'); return false;
  };
  const copy = (value: unknown, path: string, depth: number): unknown => {
    if (++nodes > ASSET_TYPE_MIGRATION_LIMITS.nodes || depth > ASSET_TYPE_MIGRATION_LIMITS.depth || issues.overflow) {
      issues.add('limit', path, 'The aggregate node or nesting budget was exceeded.'); return;
    }
    if (value === null) { charge(4, path); return null; }
    if (typeof value === 'string') {
      if (value.length > MODEL_LIMITS.stringLength) { issues.add('limit', path, 'String length exceeds its permitted bound.'); return; }
      if (malformedUnicode.test(value)) issues.add('format', path, 'Strings must contain well-formed Unicode.');
      charge(encoder.encode(JSON.stringify(value)).length, path); return value;
    }
    if (typeof value === 'boolean') { charge(value ? 4 : 5, path); return value; }
    if (typeof value === 'number') {
      if (!Number.isFinite(value) || Object.is(value, -0)) issues.add('type', path, 'Expected a finite JSON number without negative zero.');
      charge(String(value).length, path); return value;
    }
    if (!value || typeof value !== 'object') { issues.add('invalid_json', path, 'Expected JSON data only.'); return; }
    if (active.has(value)) { issues.add('cycle', path, 'JSON data cannot contain cycles.'); return; }
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) { issues.add('invalid_json', path, 'Expected a plain JSON array.'); return; }
      if (value.length > MODEL_LIMITS.schemaNodes) { issues.add('limit', path, 'Array length exceeds its permitted bound.'); return; }
      if (Reflect.ownKeys(value).length !== value.length + 1) { issues.add('invalid_json', path, 'Sparse arrays and extra array properties are not permitted.'); return; }
      if (!charge(2 + Math.max(0, value.length - 1), path)) return;
      const output: unknown[] = []; active.add(value);
      try {
        for (let index = 0; index < value.length; index += 1) {
          const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
          if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) issues.add('invalid_json', at(path, index), 'Only enumerable data properties are permitted.');
          else output.push(copy(descriptor.value, at(path, index), depth + 1));
          if (issues.overflow || bytes > ASSET_TYPE_MIGRATION_LIMITS.bytes || nodes > ASSET_TYPE_MIGRATION_LIMITS.nodes) break;
        }
      } finally { active.delete(value); }
      return output;
    }
    if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) { issues.add('invalid_json', path, 'Expected a plain JSON object.'); return; }
    const keys = Reflect.ownKeys(value);
    if (keys.length > MODEL_LIMITS.properties) { issues.add('limit', path, 'Object property count exceeds its permitted bound.'); return; }
    if (!charge(2 + Math.max(0, keys.length - 1), path)) return;
    const output: Fields = {}; active.add(value);
    try {
      for (const key of keys) {
        if (typeof key !== 'string' || !identifier.test(key) || reserved.has(key)) { issues.add('invalid_json', path, 'JSON keys must be safe named fields.'); continue; }
        if (!charge(encoder.encode(JSON.stringify(key)).length + 1, path)) break;
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) issues.add('invalid_json', at(path, key), 'Only enumerable data properties are permitted.');
        else output[key] = copy(descriptor.value, at(path, key), depth + 1);
        if (issues.overflow || bytes > ASSET_TYPE_MIGRATION_LIMITS.bytes || nodes > ASSET_TYPE_MIGRATION_LIMITS.nodes) break;
      }
    } finally { active.delete(value); }
    return output;
  };
  try { return copy(input, '', 0); }
  catch { issues.add('invalid_json', '', 'Data properties could not be read safely.'); return; }
}
function fields(input: unknown, path: string, required: readonly string[], issues: Issues): Fields | undefined {
  if (!input || typeof input !== 'object' || Array.isArray(input)) { issues.add('type', path, 'Expected an object.'); return; }
  const value = input as Fields;
  for (const key of Object.keys(value)) if (!required.includes(key)) issues.add('unknown_field', at(path, key), 'Unknown migration field.');
  for (const key of required) if (!Object.hasOwn(value, key)) issues.add('required', at(path, key), 'Required migration field is missing.');
  return value;
}
function list(input: unknown, path: string, maximum: number, issues: Issues): unknown[] | undefined {
  if (!Array.isArray(input)) { issues.add('type', path, 'Expected an array.'); return; }
  if (input.length > maximum) { issues.add('limit', path, 'Array length exceeds its permitted bound.'); return; }
  return input;
}
function id(input: unknown, path: string, issues: Issues): input is string {
  if (typeof input === 'string' && uuid.test(input)) return true;
  issues.add('format', path, 'Expected a canonical lowercase UUID.'); return false;
}
function state(input: unknown, path: string, issues: Issues): input is string {
  if (typeof input === 'string' && identifier.test(input) && !reserved.has(input)) return true;
  issues.add('format', path, 'Expected a safe lifecycle state identifier.'); return false;
}
function version(input: unknown, path: string, issues: Issues): input is number {
  if (typeof input === 'number' && Number.isInteger(input) && input > 0 && input <= 2_147_483_647) return true;
  issues.add('model_version', path, 'Expected a positive PostgreSQL integer version.'); return false;
}
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical((value as Fields)[key])}`).join(',')}}`;
  return JSON.stringify(value);
}

export function parseAssetTypeMigrationPlan(input: unknown): ValidationResult<AssetTypeMigrationPlan> {
  const issues = new Issues(); const copied = copyJSON(input, issues);
  if (issues.values.length) return issues.result(undefined as never);
  const source = fields(copied, '', ['formatVersion', 'typeId', 'attributes', 'owner', 'lifecycle', 'acknowledgedPolicyChanges'], issues);
  if (!source) return issues.result(undefined as never);
  if (source.formatVersion !== 1) issues.add('invalid_definition', '/formatVersion', 'Only asset-type migration format version 1 is supported.');
  id(source.typeId, '/typeId', issues);
  const attributes = parseMigrationPlan(source.attributes);
  if (!attributes.ok) issues.append('/attributes', attributes.issues);
  else {
    version(attributes.value.targetVersion, '/attributes/targetVersion', issues);
    attributes.value.sourceVersions.forEach((item, index) => version(item, `/attributes/sourceVersions/${index}`, issues));
  }
  const owner = fields(source.owner, '/owner', ['default', 'overrides'], issues);
  const overrides: { assetId: string; ownerId: string | null }[] = [];
  if (owner) {
    if (owner.default !== 'preserve') issues.add('enum', '/owner/default', 'Ownership is preserved unless explicitly overridden.');
    const items = list(owner.overrides, '/owner/overrides', ASSET_TYPE_MIGRATION_LIMITS.ownerOverrides, issues);
    const seen = new Set<string>();
    for (const [index, item] of (items ?? []).entries()) {
      const path = `/owner/overrides/${index}`; const entry = fields(item, path, ['assetId', 'ownerId'], issues);
      if (!entry) continue;
      const assetValid = id(entry.assetId, `${path}/assetId`, issues);
      const ownerValid = entry.ownerId === null || id(entry.ownerId, `${path}/ownerId`, issues);
      if (assetValid) {
        if (seen.has(entry.assetId as string)) issues.add('duplicate', `${path}/assetId`, 'An asset may have only one ownership override.');
        seen.add(entry.assetId as string);
      }
      if (assetValid && ownerValid) overrides.push({ assetId: entry.assetId as string, ownerId: entry.ownerId as string | null });
    }
  }
  const lifecycle = fields(source.lifecycle, '/lifecycle', ['onUnmapped', 'mappings'], issues);
  const mappings: { sourceVersion: number; from: string; to: string }[] = [];
  if (lifecycle) {
    if (!['preserve', 'error'].includes(lifecycle.onUnmapped as string)) issues.add('enum', '/lifecycle/onUnmapped', 'Expected preserve or error.');
    const items = list(lifecycle.mappings, '/lifecycle/mappings', ASSET_TYPE_MIGRATION_LIMITS.lifecycleMappings, issues);
    const seen = new Set<string>();
    for (const [index, item] of (items ?? []).entries()) {
      const path = `/lifecycle/mappings/${index}`; const entry = fields(item, path, ['sourceVersion', 'from', 'to'], issues);
      if (!entry) continue;
      const validVersion = version(entry.sourceVersion, `${path}/sourceVersion`, issues);
      const validFrom = state(entry.from, `${path}/from`, issues), validTo = state(entry.to, `${path}/to`, issues);
      if (validVersion && validFrom && validTo) {
        const key = `${entry.sourceVersion}\0${entry.from}`;
        if (seen.has(key)) issues.add('duplicate', path, 'A source-version state may have only one mapping.');
        seen.add(key);
        if (attributes.ok && !attributes.value.sourceVersions.includes(entry.sourceVersion as number)) issues.add('model_version', `${path}/sourceVersion`, 'Mapping version is outside the declared source pins.');
        mappings.push({ sourceVersion: entry.sourceVersion as number, from: entry.from as string, to: entry.to as string });
      }
    }
  }
  const rawChanges = list(source.acknowledgedPolicyChanges, '/acknowledgedPolicyChanges', changes.length, issues);
  const acknowledged: AssetTypePolicyChange[] = []; const seenChanges = new Set<string>();
  for (const [index, item] of (rawChanges ?? []).entries()) {
    if (typeof item !== 'string' || !(changes as readonly string[]).includes(item)) issues.add('enum', `/acknowledgedPolicyChanges/${index}`, 'Unsupported policy acknowledgement.');
    else {
      if (seenChanges.has(item)) issues.add('duplicate', `/acknowledgedPolicyChanges/${index}`, 'Duplicate policy acknowledgement.');
      seenChanges.add(item); acknowledged.push(item as AssetTypePolicyChange);
    }
  }
  if (issues.values.length || !attributes.ok) return issues.result(undefined as never);
  return issues.result(freeze({ formatVersion: 1, typeId: source.typeId as string, attributes: attributes.value,
    owner: { default: 'preserve', overrides: overrides.sort((a, b) => compare(a.assetId, b.assetId)) },
    lifecycle: { onUnmapped: lifecycle!.onUnmapped as 'preserve' | 'error', mappings: mappings.sort((a, b) => a.sourceVersion - b.sourceVersion || compare(a.from, b.from)) },
    acknowledgedPolicyChanges: acknowledged.sort(compare) }));
}

/** Inspect object keys before JSON.parse can overwrite duplicates, including escaped spellings. */
export function parseAssetTypeMigrationFile(text: string): ValidationResult<AssetTypeMigrationPlan> {
  const issues = new Issues();
  if (typeof text !== 'string' || text.length > ASSET_TYPE_MIGRATION_LIMITS.bytes || encoder.encode(text).length > ASSET_TYPE_MIGRATION_LIMITS.bytes) {
    issues.add('limit', '', 'Migration JSON exceeds its UTF-8 file budget.'); return issues.result(undefined as never);
  }
  let offset = 0; let nodes = 0;
  const skip = (): void => { while (offset < text.length && /[\t\n\r ]/.test(text[offset])) offset += 1; };
  const string = (): string => {
    const start = offset;
    if (text[offset++] !== '"') throw new Error('syntax');
    while (offset < text.length) {
      const character = text[offset++];
      if (character === '\\') offset += 1;
      else if (character === '"') return JSON.parse(text.slice(start, offset)) as string;
    }
    throw new Error('syntax');
  };
  const visit = (path: string, depth: number): void => {
    if (++nodes > ASSET_TYPE_MIGRATION_LIMITS.nodes || depth > ASSET_TYPE_MIGRATION_LIMITS.depth || issues.overflow) {
      issues.add('limit', path, 'The file node or nesting budget was exceeded.'); throw new Error('limit');
    }
    skip(); const start = text[offset];
    if (start === '{') {
      offset += 1; skip(); if (text[offset] === '}') { offset += 1; return; }
      const keys = new Set<string>();
      while (offset < text.length) {
        skip(); const key = string();
        if (key.length > 64 || malformedUnicode.test(key)) { issues.add('format', path, 'Property names must be bounded, well-formed strings.'); throw new Error('format'); }
        if (keys.has(key)) issues.add('duplicate', at(path, key), 'Duplicate JSON object key.');
        keys.add(key);
        if (keys.size > MODEL_LIMITS.properties) { issues.add('limit', path, 'Property count exceeds its bound.'); throw new Error('limit'); }
        skip(); if (text[offset++] !== ':') throw new Error('syntax');
        visit(at(path, key), depth + 1); skip(); const delimiter = text[offset++];
        if (delimiter === '}') return;
        if (delimiter !== ',') throw new Error('syntax');
      }
      throw new Error('syntax');
    }
    if (start === '[') {
      offset += 1; skip(); if (text[offset] === ']') { offset += 1; return; }
      let index = 0;
      while (offset < text.length) {
        if (index >= MODEL_LIMITS.schemaNodes) { issues.add('limit', path, 'Array length exceeds its bound.'); throw new Error('limit'); }
        visit(at(path, index++), depth + 1); skip(); const delimiter = text[offset++];
        if (delimiter === ']') return;
        if (delimiter !== ',') throw new Error('syntax');
      }
      throw new Error('syntax');
    }
    if (start === '"') { string(); return; }
    const begin = offset;
    while (offset < text.length && !/[\t\n\r ,}\]]/.test(text[offset])) offset += 1;
    if (offset === begin) throw new Error('syntax');
    JSON.parse(text.slice(begin, offset));
  };
  try { visit('', 0); skip(); if (offset !== text.length) throw new Error('syntax'); }
  catch { if (!issues.values.length) issues.add('invalid_json', '', 'Expected a valid JSON migration document.'); }
  if (issues.values.length) return issues.result(undefined as never);
  try { return parseAssetTypeMigrationPlan(JSON.parse(text)); }
  catch { issues.add('invalid_json', '', 'Expected a valid JSON migration document.'); return issues.result(undefined as never); }
}

/** Validate the resolved envelope, not its database provenance. Full ancestry recomputation remains mandatory in the service. */
function resolved(input: unknown, path: string, issues: Issues): ResolvedAssetType | undefined {
  const entry = fields(input, path, ['definition', 'dependencies', 'model', 'requiredOwner', 'lifecycle'], issues);
  if (!entry) return;
  const authored = parseAssetTypeDefinition(entry.definition), model = parseModelDefinition(entry.model);
  if (!authored.ok) issues.append(`${path}/definition`, authored.issues);
  if (!model.ok) issues.append(`${path}/model`, model.issues);
  const lifecycle = parseAssetTypeDefinition({ formatVersion: 1, id: 'resolved_policy', version: 1, parents: [], attributes: {}, overrideAttributes: [], requiredOwner: false, lifecycle: entry.lifecycle });
  if (!lifecycle.ok) issues.append(path, lifecycle.issues);
  if (typeof entry.requiredOwner !== 'boolean') issues.add('type', `${path}/requiredOwner`, 'Expected resolved ownership policy.');
  const dependencies = list(entry.dependencies, `${path}/dependencies`, 64, issues); const pins = new Map<string, number>();
  for (const [index, item] of (dependencies ?? []).entries()) {
    const pinPath = `${path}/dependencies/${index}`; const pin = fields(item, pinPath, ['id', 'version'], issues);
    if (!pin) continue;
    const validId = state(pin.id, `${pinPath}/id`, issues), validVersion = version(pin.version, `${pinPath}/version`, issues);
    if (validId && validVersion) {
      if (pins.has(pin.id as string)) issues.add('duplicate', `${pinPath}/id`, 'Resolved dependencies have unique logical identities.');
      pins.set(pin.id as string, pin.version as number);
    }
  }
  if (!authored.ok || !model.ok || !lifecycle.ok) return;
  version(authored.value.version, `${path}/definition/version`, issues);
  if (authored.value.id !== model.value.id) issues.add('model_identity', `${path}/model/id`, 'Resolved and authored identities must match.');
  if (authored.value.version !== model.value.version) issues.add('model_version', `${path}/model/version`, 'Resolved and authored versions must match.');
  if (authored.value.requiredOwner && !entry.requiredOwner) issues.add('invalid_definition', `${path}/requiredOwner`, 'Resolution cannot weaken authored required ownership.');
  if (authored.value.lifecycle !== null && canonical(authored.value.lifecycle) !== canonical(lifecycle.value.lifecycle)) issues.add('invalid_definition', `${path}/lifecycle`, 'An explicit authored lifecycle must match its resolution.');
  for (const parent of authored.value.parents) if (pins.get(parent.id) !== parent.version) issues.add('invalid_definition', `${path}/dependencies`, 'Every immediate parent must retain its exact resolved pin.');
  if (pins.has(authored.value.id)) issues.add('cycle', `${path}/dependencies`, 'A resolved type cannot depend on itself.');
  return { definition: authored.value, model: model.value, dependencies: entry.dependencies as ResolvedAssetType['dependencies'], requiredOwner: entry.requiredOwner as boolean, lifecycle: lifecycle.value.lifecycle as LifecycleDefinition };
}
function policyChanges(head: ResolvedAssetType, target: ResolvedAssetType): AssetTypePolicyChange[] {
  const output: AssetTypePolicyChange[] = [];
  const pins = (value: ResolvedAssetType): unknown => [...value.definition.parents].sort((a, b) => compare(a.id, b.id));
  if (canonical(pins(head)) !== canonical(pins(target))) output.push('parents_changed');
  if (head.requiredOwner !== target.requiredOwner) output.push('required_owner_changed');
  if (canonical(head.lifecycle) !== canonical(target.lifecycle)) output.push('lifecycle_changed');
  return output;
}

export function validateAssetTypeMigrationPlan(scope: AssetTypeMigrationScope, input: unknown): ValidationResult<AssetTypeMigrationPlan> {
  const issues = new Issues();
  // One copier enforces a shared budget across the plan and every supplied definition.
  const copied = copyJSON({ scope, plan: input }, issues) as { scope: unknown; plan: unknown } | undefined;
  if (issues.values.length || !copied) return issues.result(undefined as never);
  const plan = parseAssetTypeMigrationPlan(copied.plan);
  if (!plan.ok) { issues.append('/plan', plan.issues); return issues.result(undefined as never); }
  const context = fields(copied.scope, '/scope', ['typeId', 'head', 'target', 'sources', 'cohort'], issues);
  if (!context) return issues.result(undefined as never);
  id(context.typeId, '/scope/typeId', issues);
  if (context.typeId !== plan.value.typeId) issues.add('model_identity', '/plan/typeId', 'The plan must identify the exact immutable asset type.');
  const head = resolved(context.head, '/head', issues), target = resolved(context.target, '/target', issues);
  const sources = list(context.sources, '/sources', ASSET_TYPE_MIGRATION_LIMITS.assets, issues);
  const cohort = list(context.cohort, '/cohort', ASSET_TYPE_MIGRATION_LIMITS.assets, issues);
  if (!head || !target || !sources || !cohort) return issues.result(undefined as never);
  const attributePlan = validateMigrationPlanForModels(head.model, target.model, plan.value.attributes);
  if (!attributePlan.ok) issues.append('/attributes', attributePlan.issues);
  const versions = new Set<number>(); const assets = new Set<string>();
  for (const [index, item] of cohort.entries()) {
    const path = `/cohort/${index}`, entry = fields(item, path, ['assetId', 'sourceVersion'], issues);
    if (!entry) continue;
    if (id(entry.assetId, `${path}/assetId`, issues)) {
      if (assets.has(entry.assetId as string)) issues.add('duplicate', `${path}/assetId`, 'The cohort must contain each asset exactly once.');
      assets.add(entry.assetId as string);
    }
    if (version(entry.sourceVersion, `${path}/sourceVersion`, issues)) versions.add(entry.sourceVersion as number);
  }
  if (canonical([...versions].sort((a, b) => a - b)) !== canonical(plan.value.attributes.sourceVersions)) issues.add('model_version', '/plan/attributes/sourceVersions', 'Declared source pins must equal the complete cohort pins.');
  const byVersion = new Map<number, ResolvedAssetType>();
  for (const [index, item] of sources.entries()) {
    const source = resolved(item, `/sources/${index}`, issues);
    if (!source) continue;
    if (source.model.id !== head.model.id) issues.add('model_identity', `/sources/${index}/model/id`, 'All sources must belong to the same authored type.');
    if (source.model.version > head.model.version || !versions.has(source.model.version)) issues.add('model_version', `/sources/${index}/model/version`, 'Supplied sources must exactly match cohort pins no later than the head.');
    if (byVersion.has(source.model.version)) issues.add('duplicate', `/sources/${index}`, 'Each pinned source resolution must occur once.');
    if (source.model.version === head.model.version && canonical(source) !== canonical(head)) issues.add('invalid_definition', `/sources/${index}`, 'A source at the head pin must equal the immutable head resolution.');
    byVersion.set(source.model.version, source);
  }
  for (const pin of versions) if (!byVersion.has(pin)) issues.add('required', '/sources', 'Every cohort pin requires its exact source resolution.');
  const expected = new Set(policyChanges(head, target)), acknowledged = new Set(plan.value.acknowledgedPolicyChanges);
  for (const change of expected) if (!acknowledged.has(change)) issues.add('required', '/plan/acknowledgedPolicyChanges', `Policy change ${change} requires acknowledgement.`);
  for (const [index, change] of plan.value.acknowledgedPolicyChanges.entries()) if (!expected.has(change)) issues.add('invalid_definition', `/plan/acknowledgedPolicyChanges/${index}`, 'Acknowledgement must match a head-to-target policy change.');
  for (const [index, override] of plan.value.owner.overrides.entries()) {
    if (!assets.has(override.assetId)) issues.add('invalid_definition', `/plan/owner/overrides/${index}/assetId`, 'Owner overrides are limited to the complete cohort.');
    if (override.ownerId === null && target.requiredOwner) issues.add('required', `/plan/owner/overrides/${index}/ownerId`, 'The target requires an active owner.');
  }
  for (const [index, mapping] of plan.value.lifecycle.mappings.entries()) {
    const source = byVersion.get(mapping.sourceVersion), path = `/plan/lifecycle/mappings/${index}`;
    if (!source?.lifecycle.states.includes(mapping.from)) issues.add('enum', `${path}/from`, 'The mapping must start in its exact pinned source lifecycle.');
    if (!target.lifecycle.states.includes(mapping.to)) issues.add('enum', `${path}/to`, 'The mapping must end in the target lifecycle.');
  }
  return issues.result(plan.value);
}

/** Apply policy independently from attribute transformations; corrupt source states never become a migration repair. */
export function applyAssetTypeMigrationPolicy(input: AssetTypePolicyMigrationInput): ValidationResult<{ ownerId: string | null; state: string; sourceIssues: readonly ValidationIssue[] }> {
  const issues = new Issues();
  // The active set is not JSON, so read the outer data descriptors separately.
  let activeOwnerIds: ReadonlySet<string>;
  const payload: Fields = {};
  try {
    if (!input || typeof input !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(input))) throw new Error('object');
    const names = ['source', 'target', 'plan', 'asset', 'activeOwnerIds'];
    for (const key of Reflect.ownKeys(input)) if (typeof key !== 'string' || !names.includes(key)) issues.add('unknown_field', '', 'Unknown policy transformation field.');
    for (const key of names) {
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) issues.add('invalid_json', at('', key), 'Expected an enumerable data property.');
      else payload[key] = descriptor.value;
    }
    activeOwnerIds = payload.activeOwnerIds as ReadonlySet<string>;
    // Use the built-in operation: supplied accessors or overridden has methods never execute.
    Set.prototype.has.call(activeOwnerIds, '');
  } catch { issues.add('invalid_json', '/activeOwnerIds', 'Expected data properties and a native set of active owner IDs.'); return issues.result(undefined as never); }
  delete payload.activeOwnerIds;
  const copied = copyJSON(payload, issues) as Fields | undefined;
  if (issues.values.length || !copied) return issues.result(undefined as never);
  const source = resolved(copied.source, '/source', issues), target = resolved(copied.target, '/target', issues);
  const parsed = parseAssetTypeMigrationPlan(copied.plan);
  if (!parsed.ok) issues.append('/plan', parsed.issues);
  const asset = fields(copied.asset, '/asset', ['assetId', 'modelVersion', 'ownerId', 'state'], issues);
  if (!source || !target || !parsed.ok || !asset) return issues.result(undefined as never);
  const plan = parsed.value;
  id(asset.assetId, '/asset/assetId', issues); version(asset.modelVersion, '/asset/modelVersion', issues);
  if (asset.ownerId !== null) id(asset.ownerId, '/asset/ownerId', issues);
  if (source.model.id !== plan.attributes.modelId || target.model.id !== plan.attributes.modelId) issues.add('model_identity', '/plan/attributes/modelId', 'The source and target must belong to the declared type.');
  if (asset.modelVersion !== source.model.version || !plan.attributes.sourceVersions.includes(source.model.version)) issues.add('model_version', '/asset/modelVersion', 'The asset must retain an exact declared source pin.');
  if (target.model.version !== plan.attributes.targetVersion) issues.add('model_version', '/target/model/version', 'The target must equal the declared target version.');
  if (typeof asset.state !== 'string' || !source.lifecycle.states.includes(asset.state)) issues.add('enum', '/asset/state', 'The existing state is corrupt for its pinned source lifecycle.');
  if (issues.values.length) return issues.result(undefined as never);
  const override = plan.owner.overrides.find(item => item.assetId === asset.assetId);
  const ownerId = override ? override.ownerId : asset.ownerId as string | null;
  const active = (value: string | null): boolean => value !== null && Set.prototype.has.call(activeOwnerIds, value);
  const sourceIssues: ValidationIssue[] = [];
  if (source.requiredOwner && !active(asset.ownerId as string | null)) {
    sourceIssues.push({ code: 'required', path: '/source/ownerId', message: 'The pinned source requires an active owner; this migration repairs that policy violation.' });
    const replacementRepairs = !!override && override.ownerId !== null && active(override.ownerId);
    const policyRepairs = !target.requiredOwner && plan.acknowledgedPolicyChanges.includes('required_owner_changed');
    if (!replacementRepairs && !policyRepairs) issues.add('required', '/source/ownerId', 'A missing or inactive required source owner needs an active explicit replacement or acknowledged removal of required ownership.');
  }
  if (override?.ownerId !== null && override !== undefined && !active(override.ownerId)) issues.add('required', '/target/ownerId', 'An explicit non-null owner replacement must be active in this tenant.');
  if (target.requiredOwner && !active(ownerId)) issues.add('required', '/target/ownerId', 'The target requires an active owner.');
  const mapping = plan.lifecycle.mappings.find(item => item.sourceVersion === asset.modelVersion && item.from === asset.state);
  for (const [index, item] of plan.lifecycle.mappings.entries()) {
    if (item.sourceVersion === source.model.version && !source.lifecycle.states.includes(item.from)) issues.add('enum', `/plan/lifecycle/mappings/${index}/from`, 'The mapping must start in its exact pinned source lifecycle.');
    if (!target.lifecycle.states.includes(item.to)) issues.add('enum', `/plan/lifecycle/mappings/${index}/to`, 'The mapping must end in the target lifecycle.');
  }
  const nextState = mapping?.to ?? asset.state as string;
  if (!mapping && plan.lifecycle.onUnmapped === 'error') issues.add('required', '/target/state', 'The current pinned state requires an explicit mapping.');
  if (!target.lifecycle.states.includes(nextState)) issues.add('enum', '/target/state', 'The migrated state must belong to the target lifecycle.');
  return issues.result(freeze({ ownerId, state: nextState, sourceIssues }));
}
