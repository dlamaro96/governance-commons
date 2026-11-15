// SPDX-License-Identifier: Apache-2.0
import {
  MODEL_LIMITS, parseModelDefinition, previewModelUpgrade, validateAttributes,
  type AttributeSchema, type AttributeValue, type AttributeValues, type ModelDefinition,
  type ValidationIssue, type ValidationIssueCode, type ValidationResult,
} from './model.ts';

/** Pure transformation only. No persistence, authorization, migration approval or execution receipt. */
export const MIGRATION_LIMITS = Object.freeze({
  operations: 64, pathSegments: 8, sourceVersions: 1_000, acknowledgements: MODEL_LIMITS.schemaNodes,
  enumMappings: MODEL_LIMITS.enumValues, planNodes: MODEL_LIMITS.valueNodes,
  planDepth: MODEL_LIMITS.valueDepth + 5, stringLength: MODEL_LIMITS.stringLength,
  totalStringLength: MODEL_LIMITS.totalStringLength, issues: MODEL_LIMITS.issues,
});
export type MigrationPath = readonly string[];
export type MissingPathBehavior = 'skip' | 'error';
export type MigrationConversion = 'safeIntegerToDecimal' | 'decimalToText' | 'textToDecimal';
export interface MigrationAcknowledgement {
  readonly code: 'attribute_removed' | 'type_changed' | 'constraints_changed';
  readonly path: string;
}
export type MigrationOperation =
  | { readonly op: 'rename'; readonly from: MigrationPath; readonly to: MigrationPath; readonly onMissing: MissingPathBehavior }
  | { readonly op: 'remove'; readonly path: MigrationPath; readonly onMissing: MissingPathBehavior }
  | { readonly op: 'set'; readonly path: MigrationPath; readonly value: AttributeValue; readonly mode: 'ifMissing' | 'replace' }
  | { readonly op: 'enumMap'; readonly path: MigrationPath; readonly mappings: readonly { readonly from: string; readonly to: string }[]; readonly onMissing: MissingPathBehavior; readonly onUnmapped: 'keep' | 'error' }
  | { readonly op: 'convert'; readonly path: MigrationPath; readonly conversion: MigrationConversion; readonly onMissing: MissingPathBehavior };
export interface MigrationPlan {
  readonly formatVersion: 1;
  readonly modelId: string;
  readonly targetVersion: number;
  readonly sourceVersions: readonly number[];
  readonly acknowledgedChanges: readonly MigrationAcknowledgement[];
  readonly operations: readonly MigrationOperation[];
}
export interface ModelMigrationInput {
  readonly head: ModelDefinition;
  readonly source: ModelDefinition;
  readonly target: ModelDefinition;
  readonly plan: MigrationPlan;
  readonly attributes: unknown;
}

type Fields = Record<string, unknown>;
type WorkingValue = string | number | boolean | WorkingValue[] | MutableValues;
type MutableValues = Map<string, WorkingValue>;
const identifier = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const reserved = new Set(['__proto__', 'constructor', 'prototype']);
const malformedUnicode = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const schemaPointer = /^\/attributes\/[A-Za-z_][A-Za-z0-9_.-]{0,63}(?:\/items|\/properties\/[A-Za-z_][A-Za-z0-9_.-]{0,63})*$/;
const has = (value: object, key: string): boolean => Object.hasOwn(value, key);
const at = (path: string, key: string | number): string => `${path}/${String(key).replaceAll('~', '~0').replaceAll('/', '~1')}`;
const prefixIssues = (prefix: string, issues: readonly ValidationIssue[]): ValidationIssue[] => issues.map(issue => ({ ...issue, path: prefix + issue.path }));

class Issues {
  readonly values: ValidationIssue[] = [];
  overflow = false;
  add(code: ValidationIssueCode, path: string, message: string): void {
    if (this.values.length < MIGRATION_LIMITS.issues - 1) this.values.push({ code, path, message });
    else this.overflow = true;
  }
  result<T>(value: T): ValidationResult<T> {
    if (this.overflow) this.values.push({ code: 'limit', path: '', message: 'Further migration issues were omitted.' });
    return this.values.length ? { ok: false, issues: this.values } : { ok: true, value };
  }
}

/** Read data descriptors before accessing values, so a getter is rejected without being executed. */
function copyPlanJSON(input: unknown, issues: Issues): unknown {
  const active = new Set<object>();
  let nodes = 0; let strings = 0;
  const copy = (value: unknown, path: string, depth: number): unknown => {
    nodes += 1;
    if (nodes > MIGRATION_LIMITS.planNodes || depth > MIGRATION_LIMITS.planDepth || issues.overflow) {
      issues.add('limit', path, 'The permitted plan node count or nesting depth was exceeded.'); return undefined;
    }
    if (typeof value === 'string') {
      strings += value.length;
      if (value.length > MIGRATION_LIMITS.stringLength || strings > MIGRATION_LIMITS.totalStringLength) issues.add('limit', path, 'The permitted plan string length was exceeded.');
      else if (malformedUnicode.test(value)) issues.add('format', path, 'Strings must contain well-formed Unicode.');
      return value;
    }
    if (typeof value === 'boolean') return value;
    if (typeof value === 'number') {
      if (!Number.isFinite(value) || Object.is(value, -0)) issues.add('type', path, 'Expected a finite JSON number without negative zero.');
      return value;
    }
    if (!value || typeof value !== 'object') { issues.add('type', path, 'Plans contain only non-null JSON data.'); return undefined; }
    if (active.has(value)) { issues.add('cycle', path, 'Migration plans cannot contain cycles.'); return undefined; }
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) { issues.add('invalid_json', path, 'Expected a plain JSON array.'); return undefined; }
      const maximum = path === '/acknowledgedChanges' ? MIGRATION_LIMITS.acknowledgements : Math.max(MODEL_LIMITS.listItems, MIGRATION_LIMITS.sourceVersions);
      if (value.length > maximum) { issues.add('limit', path, 'The permitted array length was exceeded.'); return undefined; }
      if (Reflect.ownKeys(value).length !== value.length + 1) { issues.add('invalid_json', path, 'Sparse arrays and extra array properties are not permitted.'); return undefined; }
      active.add(value);
      const output: unknown[] = [];
      try {
        for (let index = 0; index < value.length; index += 1) {
          const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
          if (!descriptor?.enumerable || !has(descriptor, 'value')) { issues.add('invalid_json', at(path, index), 'Array entries must be enumerable data properties.'); continue; }
          output.push(copy(descriptor.value, at(path, index), depth + 1));
          if (issues.overflow || nodes > MIGRATION_LIMITS.planNodes) break;
        }
      } finally { active.delete(value); }
      return output;
    }
    if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) { issues.add('invalid_json', path, 'Expected a plain JSON object.'); return undefined; }
    const keys = Reflect.ownKeys(value);
    if (keys.length > MODEL_LIMITS.properties) { issues.add('limit', path, 'The permitted property count was exceeded.'); return undefined; }
    if (keys.some(key => typeof key === 'symbol')) issues.add('invalid_json', path, 'Symbol keys are not JSON.');
    active.add(value);
    const output: Fields = {};
    try {
      for (const key of keys.filter((key): key is string => typeof key === 'string').sort()) {
        if (!identifier.test(key) || reserved.has(key)) { issues.add('invalid_definition', path, 'Object keys must be safe identifiers of at most 64 characters.'); continue; }
        const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
        if (!descriptor.enumerable || !has(descriptor, 'value')) { issues.add('invalid_json', at(path, key), 'Only enumerable data properties are permitted.'); continue; }
        output[key] = copy(descriptor.value, at(path, key), depth + 1);
        if (issues.overflow || nodes > MIGRATION_LIMITS.planNodes) break;
      }
    } finally { active.delete(value); }
    return output;
  };
  return copy(input, '', 0);
}

function fields(input: unknown, issues: Issues, path: string, required: readonly string[]): Fields | undefined {
  if (!input || typeof input !== 'object' || Array.isArray(input)) { issues.add('type', path, 'Expected an object.'); return undefined; }
  const value = input as Fields;
  for (const key of Object.keys(value)) if (!required.includes(key)) issues.add('unknown_field', at(path, key), 'Unknown migration field.');
  for (const key of required) if (!has(value, key)) issues.add('required', at(path, key), 'Required migration field is missing.');
  return value;
}
function enumeration<T extends string>(input: unknown, choices: readonly T[], issues: Issues, path: string): input is T {
  if (typeof input !== 'string' || !(choices as readonly string[]).includes(input)) { issues.add('enum', path, 'Unsupported migration option.'); return false; }
  return true;
}
function integer(input: unknown, issues: Issues, path: string): input is number {
  if (typeof input !== 'number' || !Number.isSafeInteger(input) || input < 1) { issues.add('type', path, 'Expected a positive safe integer.'); return false; }
  return true;
}
function list(input: unknown, issues: Issues, path: string, maximum: number, minimum = 0): unknown[] | undefined {
  if (!Array.isArray(input)) { issues.add('type', path, 'Expected an array.'); return undefined; }
  if (input.length > maximum || input.length < minimum) { issues.add('limit', path, 'Array length is outside its permitted bounds.'); return undefined; }
  return input;
}
function parsePath(input: unknown, issues: Issues, path: string): MigrationPath | undefined {
  const parts = list(input, issues, path, MIGRATION_LIMITS.pathSegments, 1);
  if (!parts) return undefined;
  for (let index = 0; index < parts.length; index += 1) {
    const part = parts[index];
    if (typeof part !== 'string' || !identifier.test(part) || reserved.has(part)) {
      issues.add('format', at(path, index), 'Paths contain safe named-object fields only; array indexes are not supported.');
    }
  }
  return parts as string[];
}
function pathPrefix(left: MigrationPath, right: MigrationPath): boolean { return left.every((part, index) => right[index] === part); }
function freeze<T>(value: T): T {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
}

export function parseMigrationPlan(input: unknown): ValidationResult<MigrationPlan> {
  const issues = new Issues();
  const copied = copyPlanJSON(input, issues);
  if (issues.values.length) return issues.result(undefined as never);
  const source = fields(copied, issues, '', ['formatVersion', 'modelId', 'targetVersion', 'sourceVersions', 'acknowledgedChanges', 'operations']);
  if (!source) return issues.result(undefined as never);
  if (source.formatVersion !== 1) issues.add('invalid_definition', '/formatVersion', 'Only migration plan format version 1 is supported.');
  if (typeof source.modelId !== 'string' || !identifier.test(source.modelId) || reserved.has(source.modelId)) issues.add('format', '/modelId', 'Expected a safe model identifier.');
  const validTargetVersion = integer(source.targetVersion, issues, '/targetVersion');
  const versions = list(source.sourceVersions, issues, '/sourceVersions', MIGRATION_LIMITS.sourceVersions);
  if (versions) for (let index = 0; index < versions.length; index += 1) {
    const version = versions[index];
    if (integer(version, issues, `/sourceVersions/${index}`)) {
      if (index > 0 && Number(versions[index - 1]) >= version) issues.add('invalid_definition', `/sourceVersions/${index}`, 'Source versions must be strictly increasing and unique.');
      if (validTargetVersion && version >= (source.targetVersion as number)) issues.add('model_version', `/sourceVersions/${index}`, 'Source versions must precede the target version.');
    }
  }
  const acknowledgements = list(source.acknowledgedChanges, issues, '/acknowledgedChanges', MIGRATION_LIMITS.acknowledgements);
  const seenAcknowledgements = new Set<string>();
  if (acknowledgements) acknowledgements.forEach((input, index) => {
    const path = `/acknowledgedChanges/${index}`;
    const item = fields(input, issues, path, ['code', 'path']);
    if (!item) return;
    enumeration(item.code, ['attribute_removed', 'type_changed', 'constraints_changed'], issues, `${path}/code`);
    if (typeof item.path !== 'string' || item.path.length > 1_024 || !schemaPointer.test(item.path) || item.path.split('/').some(part => reserved.has(part))) {
      issues.add('format', `${path}/path`, 'Expected a bounded model-schema JSON Pointer.');
    }
    const key = JSON.stringify([item.code, item.path]);
    if (seenAcknowledgements.has(key)) issues.add('duplicate', path, 'Duplicate destructive-change acknowledgement.');
    seenAcknowledgements.add(key);
  });
  const operations = list(source.operations, issues, '/operations', MIGRATION_LIMITS.operations);
  if (operations) operations.forEach((input, index) => {
    const path = `/operations/${index}`;
    if (!input || typeof input !== 'object' || Array.isArray(input)) { issues.add('type', path, 'Expected an operation object.'); return; }
    const op = (input as Fields).op;
    if (!enumeration(op, ['rename', 'remove', 'set', 'enumMap', 'convert'], issues, `${path}/op`)) return;
    const keys = op === 'rename' ? ['op', 'from', 'to', 'onMissing'] : op === 'set' ? ['op', 'path', 'value', 'mode']
      : op === 'enumMap' ? ['op', 'path', 'mappings', 'onMissing', 'onUnmapped'] : op === 'convert' ? ['op', 'path', 'conversion', 'onMissing'] : ['op', 'path', 'onMissing'];
    const value = fields(input, issues, path, keys)!;
    if (op === 'rename') {
      const from = parsePath(value.from, issues, `${path}/from`); const to = parsePath(value.to, issues, `${path}/to`);
      if (from && to && (pathPrefix(from, to) || pathPrefix(to, from))) issues.add('invalid_definition', path, 'Rename paths must be distinct and cannot contain one another.');
    } else parsePath(value.path, issues, `${path}/path`);
    if (op === 'set') enumeration(value.mode, ['ifMissing', 'replace'], issues, `${path}/mode`);
    else enumeration(value.onMissing, ['skip', 'error'], issues, `${path}/onMissing`);
    if (op === 'convert') enumeration(value.conversion, ['safeIntegerToDecimal', 'decimalToText', 'textToDecimal'], issues, `${path}/conversion`);
    if (op === 'enumMap') {
      enumeration(value.onUnmapped, ['keep', 'error'], issues, `${path}/onUnmapped`);
      const mappings = list(value.mappings, issues, `${path}/mappings`, MIGRATION_LIMITS.enumMappings, 1);
      const seen = new Set<string>();
      if (mappings) mappings.forEach((mapping, mappingIndex) => {
        const itemPath = `${path}/mappings/${mappingIndex}`;
        const item = fields(mapping, issues, itemPath, ['from', 'to']);
        if (!item) return;
        for (const key of ['from', 'to']) if (typeof item[key] !== 'string' || item[key].length > 1_024) issues.add('type', `${itemPath}/${key}`, 'Enum mappings require strings of at most 1024 characters.');
        if (typeof item.from === 'string') {
          if (seen.has(item.from)) issues.add('duplicate', `${itemPath}/from`, 'An enum source value may have only one mapping.');
          seen.add(item.from);
        }
      });
    }
  });
  return issues.result(freeze(copied as MigrationPlan));
}

/** Validate even a zero-asset plan; acknowledgement is not a substitute for migration approval. */
export function validateMigrationPlanForModels(head: ModelDefinition, target: ModelDefinition, input: MigrationPlan): ValidationResult<MigrationPlan> {
  const parsedPlan = parseMigrationPlan(input);
  if (!parsedPlan.ok) return { ok: false, issues: prefixIssues('/plan', parsedPlan.issues) };
  const current = parseModelDefinition(head); const proposed = parseModelDefinition(target);
  if (!current.ok) return { ok: false, issues: prefixIssues('/head', current.issues) };
  if (!proposed.ok) return { ok: false, issues: prefixIssues('/target', proposed.issues) };
  const preview = previewModelUpgrade(current.value, proposed.value, []);
  if (!preview.ok) return { ok: false, issues: prefixIssues('/target', preview.issues) };
  const plan = parsedPlan.value;
  const issues = new Issues();
  if (plan.modelId !== current.value.id || plan.modelId !== proposed.value.id) issues.add('model_identity', '/plan/modelId', 'The migration must retain the immutable model id.');
  if (plan.targetVersion !== proposed.value.version) issues.add('model_version', '/plan/targetVersion', 'The plan must identify the exact proposed model version.');
  const required = preview.value.changes.filter(change => change.requiresMigration).map(change => ({ code: change.code, path: change.path }));
  const key = (change: { code: string; path: string }): string => JSON.stringify([change.code, change.path]);
  const acknowledged = new Set(plan.acknowledgedChanges.map(key));
  const expected = new Set(required.map(key));
  for (const change of required) if (!acknowledged.has(key(change))) issues.add('required', '/plan/acknowledgedChanges', 'Every destructive schema change requires an exact acknowledgement.');
  plan.acknowledgedChanges.forEach((change, index) => {
    if (!expected.has(key(change))) issues.add('invalid_definition', `/plan/acknowledgedChanges/${index}`, 'Acknowledgement does not match a destructive change in this model upgrade.');
  });
  // Check destinations and literals without relying on the presence of an asset or
  // an optional source value. Otherwise onMissing/ifMissing could conceal a bad plan.
  plan.operations.forEach((operation, index) => {
    if (operation.op === 'remove') return;
    const operationPath = `/plan/operations/${index}`;
    const destinationPath = operation.op === 'rename' ? operation.to : operation.path;
    const destination = schemaAt(proposed.value, destinationPath);
    if (!destination) {
      issues.add('invalid_definition', `${operationPath}/${operation.op === 'rename' ? 'to' : 'path'}`, 'Destination must be a declared named-object field in the target model.');
      return;
    }
    if (operation.op === 'convert') {
      const targetType = operation.conversion === 'decimalToText' ? 'text' : 'decimal';
      if (destination.type !== targetType) issues.add('invalid_definition', `${operationPath}/conversion`, 'Conversion must produce the declared target type.');
    } else if (operation.op === 'enumMap') {
      if (destination.type !== 'enum') issues.add('invalid_definition', `${operationPath}/path`, 'Enum mapping requires an enumeration in the target model.');
      else operation.mappings.forEach((mapping, mappingIndex) => {
        if (!destination.values.includes(mapping.to)) issues.add('enum', `${operationPath}/mappings/${mappingIndex}/to`, 'Mapped values must belong to the target enumeration.');
      });
    } else if (operation.op === 'set') {
      const literal = validateAttributes({ formatVersion: 1, id: 'migration_literal', version: 1, attributes: { value: destination } }, { value: operation.value });
      if (!literal.ok) for (const issue of literal.issues) issues.add(issue.code, `${operationPath}${issue.path}`, issue.message);
    }
  });
  return issues.result(plan);
}

function schemaAt(model: ModelDefinition, path: MigrationPath): AttributeSchema | undefined {
  let properties = model.attributes;
  let schema: AttributeSchema | undefined;
  for (let index = 0; index < path.length; index += 1) {
    if (!has(properties, path[index])) return undefined;
    schema = properties[path[index]];
    if (!schema) return undefined;
    if (index < path.length - 1) {
      if (schema.type !== 'object') return undefined;
      properties = schema.properties;
    }
  }
  return schema;
}

function cloneObject(value: AttributeValues): MutableValues {
  return new Map(Object.keys(value).sort().map(key => [key, cloneValue(value[key])]));
}
function cloneValue(value: AttributeValue): WorkingValue {
  if (Array.isArray(value)) return value.map(cloneValue);
  if (value && typeof value === 'object') return cloneObject(value as AttributeValues);
  return value as string | number | boolean;
}
function toJSON(value: WorkingValue): AttributeValue {
  if (value instanceof Map) return Object.fromEntries([...value].map(([key, child]) => [key, toJSON(child)]));
  if (Array.isArray(value)) return value.map(toJSON);
  return value;
}
type Location = { parent: MutableValues; key: string; exists: boolean } | { absentParent: true } | { invalidParent: true };
function locate(values: MutableValues, path: MigrationPath): Location {
  let parent = values;
  for (let index = 0; index < path.length - 1; index += 1) {
    if (!parent.has(path[index])) return { absentParent: true };
    const next = parent.get(path[index]);
    if (!(next instanceof Map)) return { invalidParent: true };
    parent = next;
  }
  return { parent, key: path[path.length - 1], exists: parent.has(path[path.length - 1]) };
}
function mutableLocation(location: Location): location is Extract<Location, { parent: MutableValues }> { return 'parent' in location; }
const decimalModel: ModelDefinition = { formatVersion: 1, id: 'migration_decimal_value', version: 1, attributes: { value: { type: 'decimal', required: true } } };

/**
 * Operations apply in order to a defensive copy. Missing source paths obey onMissing;
 * destination parents must already exist. The first failed operation discards the copy.
 * This does not enumerate a tenant cohort or establish authorization/transaction safety.
 */
export function applyModelMigrationToAttributes(input: ModelMigrationInput): ValidationResult<AttributeValues> {
  const parsed = validateMigrationPlanForModels(input.head, input.target, input.plan);
  if (!parsed.ok) return parsed;
  const plan = parsed.value;
  const source = parseModelDefinition(input.source); const target = parseModelDefinition(input.target); const head = parseModelDefinition(input.head);
  if (!source.ok) return { ok: false, issues: prefixIssues('/source', source.issues) };
  if (!target.ok) return { ok: false, issues: prefixIssues('/target', target.issues) };
  if (!head.ok) return { ok: false, issues: prefixIssues('/head', head.issues) };
  const issues = new Issues();
  if (source.value.id !== plan.modelId) issues.add('model_identity', '/source/id', 'The pinned source must belong to this model.');
  if (!plan.sourceVersions.includes(source.value.version) || source.value.version > head.value.version) issues.add('model_version', '/source/version', 'The pinned source version is outside the declared migration scope.');
  if (issues.values.length) return issues.result(undefined as never);
  const current = validateAttributes(source.value, input.attributes);
  if (!current.ok) return { ok: false, issues: prefixIssues('/sourceAttributes', current.issues) };
  // Dynamic names live only in private Maps; no mutation can reach an object prototype.
  // Both inputs and returned values still pass through the shared strict JSON validator.
  const values = cloneObject(current.value);
  const knownSource = (path: MigrationPath): boolean => !!(schemaAt(source.value, path) || schemaAt(head.value, path) || schemaAt(target.value, path));
  for (let index = 0; index < plan.operations.length; index += 1) {
    const operation = plan.operations[index]; const operationPath = `/plan/operations/${index}`;
    const sourcePath = operation.op === 'rename' ? operation.from : operation.path;
    if (!(operation.op === 'set' ? schemaAt(target.value, sourcePath) : knownSource(sourcePath))) {
      issues.add('invalid_definition', `${operationPath}/${operation.op === 'rename' ? 'from' : 'path'}`, 'Path is not a declared named-object field in the applicable models.');
      break;
    }
    const location = locate(values, sourcePath);
    if ('invalidParent' in location) { issues.add('type', operationPath, 'Operation paths cannot traverse arrays or scalar values.'); break; }
    if (operation.op !== 'set' && (!mutableLocation(location) || !location.exists)) {
      if (operation.onMissing === 'skip') continue;
      issues.add('required', operationPath, 'The required source path is absent.'); break;
    }
    if (!mutableLocation(location)) {
      issues.add('required', operationPath, operation.op === 'set'
        ? 'Destination parent objects must already exist.' : 'Source parent objects must already exist.'); break;
    }
    const key = location.key;
    // Keep the mutation boundary independently safe if path parsing changes later.
    // These direct checks also make the safety condition visible to source analysis.
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      issues.add('format', operationPath, 'Reserved object fields cannot be mutated.'); break;
    }
    if (operation.op === 'set') {
      if (operation.mode === 'replace' || !location.exists) location.parent.set(key, cloneValue(operation.value));
      continue;
    }
    if (operation.op === 'remove') {
      if (!location.parent.delete(key)) {
        issues.add('invalid_json', operationPath, 'The defensive source property could not be removed.'); break;
      }
      continue;
    }
    if (operation.op === 'rename') {
      const destination = locate(values, operation.to);
      if (!mutableLocation(destination)) { issues.add('required', `${operationPath}/to`, 'Destination parent objects must already exist.'); break; }
      if (destination.exists) { issues.add('invalid_definition', `${operationPath}/to`, 'Rename cannot overwrite an existing value.'); break; }
      const destinationKey = destination.key;
      if (destinationKey === '__proto__' || destinationKey === 'constructor' || destinationKey === 'prototype') {
        issues.add('format', `${operationPath}/to`, 'Reserved object fields cannot be mutated.'); break;
      }
      destination.parent.set(destinationKey, location.parent.get(key)!);
      if (!location.parent.delete(key)) {
        issues.add('invalid_json', operationPath, 'The defensive source property could not be removed.'); break;
      }
      continue;
    }
    const value = location.parent.get(key)!;
    if (operation.op === 'enumMap') {
      if (typeof value !== 'string') { issues.add('type', operationPath, 'Enum mapping requires a string value.'); break; }
      const mapping = operation.mappings.find(item => item.from === value);
      if (mapping) location.parent.set(key, mapping.to);
      else if (operation.onUnmapped === 'error') { issues.add('enum', operationPath, 'The source value has no declared enum mapping.'); break; }
      continue;
    }
    if (operation.conversion === 'safeIntegerToDecimal') {
      if (typeof value !== 'number' || !Number.isSafeInteger(value) || Object.is(value, -0)) { issues.add('type', operationPath, 'Conversion requires a safe integer without rounding.'); break; }
      location.parent.set(key, String(value));
    } else {
      const decimal = validateAttributes(decimalModel, { value });
      if (!decimal.ok) { issues.add('format', operationPath, 'Conversion requires an existing canonical decimal string; no trimming or rounding is performed.'); break; }
      location.parent.set(key, value);
    }
  }
  if (issues.values.length) return issues.result(undefined as never);
  const result = validateAttributes(target.value, toJSON(values));
  return result.ok ? result : { ok: false, issues: prefixIssues('/targetAttributes', result.issues) };
}
