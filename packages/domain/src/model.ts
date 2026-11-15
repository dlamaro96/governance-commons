// SPDX-License-Identifier: Apache-2.0
/** Shared, non-executable attribute-model contract. All paths are RFC 6901 JSON Pointers. */
export const MODEL_LIMITS = Object.freeze({
  fileLength: 262_144,
  schemaDepth: 8,
  schemaNodes: 2_048,
  valueDepth: 16,
  valueNodes: 20_000,
  properties: 128,
  listItems: 1_000,
  stringLength: 65_536,
  totalStringLength: 1_048_576,
  enumValues: 256,
  decimalDigits: 1_000,
  issues: 100,
  previewAssets: 1_000,
  previewNodes: 100_000,
  previewIssues: 1_000,
});

export type ValidationIssueCode =
  | 'invalid_json' | 'unknown_field' | 'unknown_type' | 'invalid_definition'
  | 'type' | 'required' | 'format' | 'range' | 'enum' | 'duplicate'
  | 'limit' | 'cycle' | 'model_identity' | 'model_version' | 'unsupported';
export interface ValidationIssue { readonly code: ValidationIssueCode; readonly path: string; readonly message: string }
export type ValidationResult<T> = { readonly ok: true; readonly value: T } | { readonly ok: false; readonly issues: readonly ValidationIssue[] };

type LengthConstraints = { readonly minLength?: number; readonly maxLength?: number };
export type AttributeSchema =
  | ({ readonly type: 'text' | 'richText' } & LengthConstraints)
  | { readonly type: 'number'; readonly integer?: boolean; readonly minimum?: number; readonly maximum?: number }
  | { readonly type: 'decimal'; readonly precision?: number; readonly scale?: number; readonly minimum?: string; readonly maximum?: string }
  | { readonly type: 'boolean' | 'date' | 'timestamp' | 'duration' }
  | { readonly type: 'enum'; readonly values: readonly string[] }
  | { readonly type: 'list'; readonly items: AttributeSchema; readonly minItems?: number; readonly maxItems?: number }
  | { readonly type: 'uri'; readonly schemes?: readonly UriScheme[]; readonly maxLength?: number }
  | { readonly type: 'object'; readonly properties: Readonly<Record<string, AttributeDefinition>> };
export type AttributeDefinition = AttributeSchema & { readonly required?: boolean; readonly label?: string };
export interface ModelDefinition {
  readonly formatVersion: 1;
  readonly id: string;
  readonly version: number;
  readonly attributes: Readonly<Record<string, AttributeDefinition>>;
}
export type AttributeValue = string | number | boolean | readonly AttributeValue[] | { readonly [key: string]: AttributeValue };
export type AttributeValues = Readonly<Record<string, AttributeValue>>;
export const URI_SCHEMES = Object.freeze(['https', 'http', 'urn', 'mailto', 's3', 'gs', 'abfs', 'abfss'] as const);
export type UriScheme = (typeof URI_SCHEMES)[number];

export interface ModelAsset { readonly id: string; readonly attributes: unknown }
export interface ModelChange {
  readonly code: 'attribute_added' | 'attribute_removed' | 'type_changed' | 'constraints_changed' | 'metadata_changed';
  readonly path: string;
  readonly requiresMigration: boolean;
}
export interface ModelAssetPreview {
  readonly assetId: string;
  readonly currentIssues: readonly ValidationIssue[];
  readonly proposedIssues: readonly ValidationIssue[];
}
export interface ModelUpgradePreview {
  readonly coverage: 'provided-assets-only';
  readonly changes: readonly ModelChange[];
  readonly assets: readonly ModelAssetPreview[];
  readonly affectedAssetIds: readonly string[];
  readonly compatibleWithProvidedAssets: boolean;
  readonly requiresExplicitMigration: boolean;
}

type Fields = Record<string, unknown>;
const has = (value: object, key: string): boolean => Object.hasOwn(value, key);
const at = (path: string, key: string | number): string => `${path}/${String(key).replaceAll('~', '~0').replaceAll('/', '~1')}`;
const identifier = /^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const reservedKeys = new Set(['__proto__', 'prototype', 'constructor']);
const decimalPattern = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$/;
const malformedUnicode = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const schemaFields: Readonly<Record<AttributeSchema['type'], readonly string[]>> = {
  text: ['minLength', 'maxLength'], richText: ['minLength', 'maxLength'],
  number: ['integer', 'minimum', 'maximum'], decimal: ['precision', 'scale', 'minimum', 'maximum'],
  boolean: [], date: [], timestamp: [], duration: [], enum: ['values'],
  list: ['items', 'minItems', 'maxItems'], uri: ['schemes', 'maxLength'], object: ['properties'],
};

class Context {
  readonly issues: ValidationIssue[] = [];
  readonly active = new Set<object>();
  nodes = 0;
  strings = 0;
  overflow = false;
  constructor(readonly maxNodes: number) {}
  issue(code: ValidationIssueCode, path: string, message: string): void {
    if (this.issues.length < MODEL_LIMITS.issues - 1) this.issues.push({ code, path, message });
    else this.overflow = true;
  }
  node(path: string, depth: number, maxDepth: number): boolean {
    this.nodes += 1;
    if (this.nodes > this.maxNodes || depth > maxDepth) {
      this.issue('limit', path, 'The permitted node count or nesting depth was exceeded.');
      return false;
    }
    return !this.overflow;
  }
  string(value: unknown, path: string, maximum: number = MODEL_LIMITS.stringLength): value is string {
    if (typeof value !== 'string') { this.issue('type', path, 'Expected a string.'); return false; }
    this.strings += value.length;
    if (value.length > maximum || this.strings > MODEL_LIMITS.totalStringLength) {
      this.issue('limit', path, 'The permitted string length was exceeded.'); return false;
    }
    // Unpaired UTF-16 surrogates cannot round-trip through every JSON/UTF-8 store.
    if (malformedUnicode.test(value)) { this.issue('format', path, 'Strings must contain well-formed Unicode.'); return false; }
    return true;
  }
  result<T>(value: T): ValidationResult<T> {
    if (this.overflow) this.issues.push({ code: 'limit', path: '', message: 'Further validation issues were omitted.' });
    return this.issues.length ? { ok: false, issues: this.issues } : { ok: true, value };
  }
}

function fields(input: unknown, context: Context, path: string, maximum: number = MODEL_LIMITS.properties): Fields | undefined {
  if (input === null || typeof input !== 'object' || Array.isArray(input)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(input))) {
    context.issue('type', path, 'Expected a plain JSON object.'); return;
  }
  const keys = Reflect.ownKeys(input);
  if (keys.length > maximum) { context.issue('limit', path, 'The permitted property count was exceeded.'); return; }
  const result: Fields = Object.create(null);
  for (const key of keys.filter((key): key is string => typeof key === 'string').sort()) {
    if (key.length > 256 || malformedUnicode.test(key)) {
      context.issue('limit', path, 'Property names must be bounded, well-formed strings.'); continue;
    }
    const descriptor = Object.getOwnPropertyDescriptor(input, key)!;
    if (!descriptor.enumerable || !has(descriptor, 'value')) {
      context.issue('invalid_json', at(path, key), 'Only enumerable data properties are permitted.'); continue;
    }
    result[key] = descriptor.value;
  }
  if (keys.some(key => typeof key === 'symbol')) context.issue('invalid_json', path, 'Symbol keys are not JSON.');
  return result;
}

function array(input: unknown, context: Context, path: string, maximum: number): unknown[] | undefined {
  if (!Array.isArray(input) || Object.getPrototypeOf(input) !== Array.prototype) {
    context.issue('type', path, 'Expected a JSON array.'); return;
  }
  if (input.length > maximum) { context.issue('limit', path, 'The permitted array length was exceeded.'); return; }
  const keys = Reflect.ownKeys(input);
  if (keys.length !== input.length + 1) { context.issue('invalid_json', path, 'Sparse arrays and extra array properties are not permitted.'); return; }
  const values: unknown[] = [];
  for (let index = 0; index < input.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (!descriptor?.enumerable || !has(descriptor, 'value')) {
      context.issue('invalid_json', at(path, index), 'Array entries must be data properties.'); return;
    }
    values.push(descriptor.value);
  }
  return values;
}

function known(input: Fields, allowed: readonly string[], context: Context, path: string): void {
  for (const key of Object.keys(input)) if (!allowed.includes(key)) context.issue('unknown_field', at(path, key), 'Unknown field.');
}

function boundedInteger(input: unknown, context: Context, path: string, minimum: number, maximum: number): input is number {
  if (typeof input !== 'number' || !Number.isSafeInteger(input) || Object.is(input, -0)) {
    context.issue('type', path, 'Expected a safe integer.'); return false;
  }
  if (input < minimum || input > maximum) { context.issue('range', path, 'Integer is outside its permitted range.'); return false; }
  return true;
}

function canonicalDecimal(value: string): boolean {
  if (value === '-0' || value.length > MODEL_LIMITS.decimalDigits + 3 || !decimalPattern.test(value)) return false;
  const [whole, fraction = ''] = value.replace(/^-/, '').split('.');
  return Math.max(1, (whole === '0' ? 0 : whole.length) + fraction.length) <= MODEL_LIMITS.decimalDigits;
}

/** Compare already validated decimal strings without converting any digit to floating point. */
function compareDecimals(left: string, right: string): number {
  const negativeLeft = left.startsWith('-'); const negativeRight = right.startsWith('-');
  if (negativeLeft !== negativeRight) return negativeLeft ? -1 : 1;
  const [wholeLeft, fractionLeft = ''] = left.replace(/^-/, '').split('.');
  const [wholeRight, fractionRight = ''] = right.replace(/^-/, '').split('.');
  const size = Math.max(fractionLeft.length, fractionRight.length);
  const sign = negativeLeft ? -1 : 1;
  if (wholeLeft.length !== wholeRight.length) return Math.sign(wholeLeft.length - wholeRight.length) * sign;
  if (wholeLeft !== wholeRight) return (wholeLeft < wholeRight ? -1 : 1) * sign;
  const a = fractionLeft.padEnd(size, '0'); const b = fractionRight.padEnd(size, '0');
  return a === b ? 0 : (a < b ? -1 : 1) * sign;
}

function parseProperties(input: unknown, context: Context, path: string, depth: number): Record<string, AttributeDefinition> {
  const source = fields(input, context, path);
  const result: Record<string, AttributeDefinition> = {};
  if (!source) return result;
  for (const key of Object.keys(source)) {
    if (!identifier.test(key) || reservedKeys.has(key)) {
      context.issue('invalid_definition', at(path, key), 'Attribute names must be safe identifiers of at most 64 characters.'); continue;
    }
    const parsed = parseSchema(source[key], context, at(path, key), depth, true);
    if (parsed) Object.defineProperty(result, key, { value: parsed, enumerable: true, writable: true, configurable: true });
    if (context.overflow || context.nodes > context.maxNodes) break;
  }
  return result;
}

function parseSchema(input: unknown, context: Context, path: string, depth: number, named: boolean): AttributeDefinition | undefined {
  if (!context.node(path, depth, MODEL_LIMITS.schemaDepth)) return;
  const source = fields(input, context, path, 12);
  if (!source) return;
  if (context.active.has(input as object)) { context.issue('cycle', path, 'Definitions cannot contain cycles.'); return; }
  context.active.add(input as object);
  try {
    if (typeof source.type !== 'string' || !has(schemaFields, source.type)) {
      context.issue('unknown_type', at(path, 'type'), 'Unknown attribute type.'); return;
    }
    const type = source.type as AttributeSchema['type'];
    known(source, ['type', ...(named ? ['required', 'label'] : []), ...schemaFields[type]], context, path);
    const output: Fields = { type };
    if (named && has(source, 'required')) {
      if (typeof source.required !== 'boolean') context.issue('type', at(path, 'required'), 'Expected a boolean.');
      else output.required = source.required;
    }
    if (named && has(source, 'label') && context.string(source.label, at(path, 'label'), 256)) output.label = source.label;
    const integerOption = (key: string, minimum: number, maximum: number): void => {
      if (has(source, key) && boundedInteger(source[key], context, at(path, key), minimum, maximum)) output[key] = source[key];
    };
    const ordered = (minimum: string, maximum: string): void => {
      if (typeof output[minimum] === 'number' && typeof output[maximum] === 'number' && output[minimum] > output[maximum]) {
        context.issue('invalid_definition', path, 'Minimum must not exceed maximum.');
      }
    };
    if (type === 'text' || type === 'richText' || type === 'uri') {
      if (type !== 'uri') integerOption('minLength', 0, MODEL_LIMITS.stringLength);
      integerOption('maxLength', 0, MODEL_LIMITS.stringLength);
      ordered('minLength', 'maxLength');
    }
    if (type === 'number') {
      if (has(source, 'integer')) {
        if (typeof source.integer !== 'boolean') context.issue('type', at(path, 'integer'), 'Expected a boolean.');
        else output.integer = source.integer;
      }
      for (const key of ['minimum', 'maximum']) if (has(source, key)) {
        if (typeof source[key] !== 'number' || !Number.isFinite(source[key]) || Object.is(source[key], -0)) context.issue('type', at(path, key), 'Expected a finite JSON number.');
        else output[key] = source[key];
      }
      ordered('minimum', 'maximum');
      if (output.integer === true && typeof output.minimum === 'number' && typeof output.maximum === 'number'
        && Math.ceil(output.minimum) > Math.floor(output.maximum)) context.issue('invalid_definition', path, 'Integer constraints must admit an integer.');
    }
    if (type === 'decimal') {
      integerOption('precision', 1, MODEL_LIMITS.decimalDigits);
      integerOption('scale', 0, MODEL_LIMITS.decimalDigits);
      if (Number(output.scale ?? 0) > Number(output.precision ?? MODEL_LIMITS.decimalDigits)) context.issue('invalid_definition', at(path, 'scale'), 'Scale must not exceed precision.');
      for (const key of ['minimum', 'maximum']) if (has(source, key) && context.string(source[key], at(path, key), MODEL_LIMITS.decimalDigits + 3)) {
        if (!canonicalDecimal(source[key])) context.issue('format', at(path, key), 'Expected a canonical decimal string.');
        else output[key] = source[key];
      }
      if (typeof output.minimum === 'string' && typeof output.maximum === 'string' && compareDecimals(output.minimum, output.maximum) > 0) {
        context.issue('invalid_definition', path, 'Minimum must not exceed maximum.');
      }
    }
    if (type === 'enum' || type === 'uri') {
      const key = type === 'enum' ? 'values' : 'schemes';
      if (type === 'enum' || has(source, key)) {
        const values = array(source[key], context, at(path, key), type === 'enum' ? MODEL_LIMITS.enumValues : URI_SCHEMES.length);
        if (values) {
          if (!values.length) context.issue('invalid_definition', at(path, key), 'At least one value is required.');
          const seen = new Set<string>();
          const accepted: string[] = [];
          for (let index = 0; index < values.length; index += 1) {
            const value = values[index]; const itemPath = at(at(path, key), index);
            if (!context.string(value, itemPath, type === 'enum' ? 1_024 : 16)) continue;
            if (seen.has(value)) context.issue('duplicate', itemPath, 'Duplicate value.');
            if (type === 'uri' && !(URI_SCHEMES as readonly string[]).includes(value)) context.issue('enum', itemPath, 'Unsupported URI scheme.');
            seen.add(value); accepted.push(value);
          }
          output[key] = accepted;
        }
      }
    }
    if (type === 'list') {
      integerOption('minItems', 0, MODEL_LIMITS.listItems); integerOption('maxItems', 0, MODEL_LIMITS.listItems);
      ordered('minItems', 'maxItems');
      output.items = parseSchema(source.items, context, at(path, 'items'), depth + 1, false);
    }
    if (type === 'object') output.properties = parseProperties(source.properties, context, at(path, 'properties'), depth + 1);
    return output as AttributeDefinition;
  } finally { context.active.delete(input as object); }
}

function freeze<T>(value: T): T {
  if (value && typeof value === 'object') { for (const child of Object.values(value)) freeze(child); Object.freeze(value); }
  return value;
}

export function parseModelDefinition(input: unknown): ValidationResult<ModelDefinition> {
  const context = new Context(MODEL_LIMITS.schemaNodes);
  const source = fields(input, context, '', 8);
  if (!source) return context.result(undefined as never);
  known(source, ['formatVersion', 'id', 'version', 'attributes'], context, '');
  if (source.formatVersion !== 1) context.issue('invalid_definition', '/formatVersion', 'Only model format version 1 is supported.');
  if (context.string(source.id, '/id', 64) && (!identifier.test(source.id) || reservedKeys.has(source.id))) context.issue('invalid_definition', '/id', 'Model id must be a safe identifier.');
  boundedInteger(source.version, context, '/version', 1, Number.MAX_SAFE_INTEGER);
  const attributes = parseProperties(source.attributes, context, '/attributes', 1);
  return context.result(freeze({ formatVersion: 1, id: source.id as string, version: source.version as number, attributes }));
}

export function parseModelFile(text: string): ValidationResult<ModelDefinition> {
  const parsed = parseBoundedJSONFile(text);
  return parsed.ok ? parseModelDefinition(parsed.value) : parsed;
}

/** Shared declarative-file boundary: retain duplicate keys until inspection. */
export function parseBoundedJSONFile(text: string, profile: 'model' | 'migration' = 'model'): ValidationResult<unknown> {
  if (typeof text !== 'string' || text.length > MODEL_LIMITS.fileLength) return { ok: false, issues: [{ code: 'limit', path: '', message: 'Model JSON exceeds the permitted file length.' }] };
  const documentIssues = inspectModelJSON(text, profile);
  if (documentIssues.length) return { ok: false, issues: documentIssues };
  let value: unknown;
  try { value = JSON.parse(text); }
  catch { return { ok: false, issues: [{ code: 'invalid_json', path: '', message: 'Expected a valid JSON model document.' }] }; }
  return { ok: true, value };
}

/** Trusted HTTP adapter profile: duplicate-safe envelopes, independent of the authored-file limit. */
export function parseBoundedJSONEnvelope(text: string): ValidationResult<unknown> {
  if (typeof text !== 'string' || text.length > 1048576 || new TextEncoder().encode(text).length > 1048576) {
    return { ok: false, issues: [{ code: 'limit', path: '', message: 'JSON request exceeds the permitted envelope size.' }] };
  }
  const issues = inspectModelJSON(text, 'migration');
  if (issues.length) return { ok: false, issues };
  try { return { ok: true, value: JSON.parse(text) }; }
  catch { return { ok: false, issues: [{ code: 'invalid_json', path: '', message: 'Expected a valid JSON request.' }] }; }
}

/** Reject duplicate (including escaped) object keys before JSON.parse can overwrite them. */
function inspectModelJSON(text: string, profile: 'model' | 'migration'): readonly ValidationIssue[] {
  const context = new Context(profile === 'migration' ? MODEL_LIMITS.valueNodes : MODEL_LIMITS.schemaNodes * 8);
  const arrayItems = profile === 'migration' ? Math.max(MODEL_LIMITS.listItems, MODEL_LIMITS.schemaNodes) : MODEL_LIMITS.listItems;
  const depthLimit = profile === 'migration' ? MODEL_LIMITS.valueDepth + 5 : MODEL_LIMITS.schemaDepth * 3 + 4;
  let offset = 0;
  const skipSpace = (): void => { while (offset < text.length && /[\t\n\r ]/.test(text[offset])) offset += 1; };
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
    if (!context.node(path, depth, depthLimit)) throw new Error('limit');
    skipSpace();
    const start = text[offset];
    if (start === '{') {
      offset += 1; skipSpace();
      const keys = new Set<string>();
      if (text[offset] === '}') { offset += 1; return; }
      while (offset < text.length) {
        skipSpace(); const key = string();
        if (key.length > 256 || malformedUnicode.test(key)) { context.issue('limit', path, 'Property names must be bounded, well-formed strings.'); throw new Error('limit'); }
        if (keys.has(key)) context.issue('duplicate', at(path, key), 'Duplicate JSON object key.');
        keys.add(key);
        if (keys.size > MODEL_LIMITS.properties) { context.issue('limit', path, 'The permitted property count was exceeded.'); throw new Error('limit'); }
        skipSpace(); if (text[offset++] !== ':') throw new Error('syntax');
        visit(at(path, key), depth + 1); skipSpace();
        const delimiter = text[offset++];
        if (delimiter === '}') return;
        if (delimiter !== ',') throw new Error('syntax');
      }
      throw new Error('syntax');
    }
    if (start === '[') {
      offset += 1; skipSpace();
      if (text[offset] === ']') { offset += 1; return; }
      let index = 0;
      while (offset < text.length) {
        if (index >= arrayItems) { context.issue('limit', path, 'The permitted array length was exceeded.'); throw new Error('limit'); }
        visit(at(path, index++), depth + 1); skipSpace();
        const delimiter = text[offset++];
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
  try { visit('', 0); skipSpace(); if (offset !== text.length) throw new Error('syntax'); }
  catch { if (!context.issues.length) context.issue('invalid_json', '', 'Expected a valid JSON model document.'); }
  const result = context.result(null);
  return result.ok ? [] : result.issues;
}

function validDate(value: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!match) return false;
  const year = Number(match[1]); const month = Number(match[2]); const day = Number(match[3]);
  const days = [31, year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return year >= 1 && month >= 1 && month <= 12 && day >= 1 && day <= days[month - 1];
}

function validTimestamp(value: string): boolean {
  const match = /^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?Z$/.exec(value);
  return !!match && validDate(match[1]) && Number(match[2]) <= 23 && Number(match[3]) <= 59 && Number(match[4]) <= 59;
}

function validDuration(value: string): boolean {
  const whole = '(?:0|[1-9][0-9]{0,8})';
  if (new RegExp(`^P${whole}W$`).test(value)) return true;
  const match = new RegExp(`^P(${whole}Y)?(${whole}M)?(${whole}D)?(?:T(${whole}H)?(${whole}M)?(${whole}(?:\\.[0-9]{1,9})?S)?)?$`).exec(value);
  return !!match && match.slice(1).some(Boolean) && (!value.includes('T') || match.slice(4).some(Boolean));
}

function validUri(value: string, schemes: readonly UriScheme[]): boolean {
  if (!/^[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]+$/.test(value) || /%(?![0-9A-Fa-f]{2})/.test(value)) return false;
  const match = /^([a-z][a-z0-9+.-]*):(.+)$/.exec(value);
  if (!match || !(schemes as readonly string[]).includes(match[1])) return false;
  try { const parsed = new URL(value); return !parsed.username && !parsed.password; }
  catch { return false; }
}

function validateProperties(schema: Readonly<Record<string, AttributeDefinition>>, input: unknown, context: Context, path: string, depth: number): Record<string, AttributeValue> | undefined {
  const source = fields(input, context, path);
  if (!source) return;
  const output: Record<string, AttributeValue> = {};
  for (const key of Object.keys(source)) if (!has(schema, key)) context.issue('unknown_field', at(path, key), 'Unknown attribute.');
  for (const key of Object.keys(schema)) {
    if (!has(source, key)) {
      if (schema[key].required) context.issue('required', at(path, key), 'Required attribute is missing.');
      continue;
    }
    const value = validateValue(schema[key], source[key], context, at(path, key), depth);
    if (value !== undefined) Object.defineProperty(output, key, { value, enumerable: true, writable: true, configurable: true });
    if (context.overflow || context.nodes > context.maxNodes) break;
  }
  return output;
}

function validateValue(schema: AttributeSchema, input: unknown, context: Context, path: string, depth: number): AttributeValue | undefined {
  if (!context.node(path, depth, MODEL_LIMITS.valueDepth)) return;
  if (schema.type === 'number') {
    if (typeof input !== 'number' || !Number.isFinite(input) || Object.is(input, -0)) context.issue('type', path, 'Expected a finite JSON number.');
    else if (schema.integer && !Number.isSafeInteger(input)) context.issue('type', path, 'Expected a safe integer.');
    else if ((schema.minimum !== undefined && input < schema.minimum) || (schema.maximum !== undefined && input > schema.maximum)) context.issue('range', path, 'Number is outside its permitted range.');
    else return input;
    return;
  }
  if (schema.type === 'boolean') {
    if (typeof input === 'boolean') return input;
    context.issue('type', path, 'Expected a boolean.'); return;
  }
  if (schema.type === 'object' || schema.type === 'list') {
    if (input && typeof input === 'object' && context.active.has(input)) { context.issue('cycle', path, 'Attribute values cannot contain cycles.'); return; }
    if (input && typeof input === 'object') context.active.add(input);
    try {
      if (schema.type === 'object') return validateProperties(schema.properties, input, context, path, depth + 1);
      const values = array(input, context, path, MODEL_LIMITS.listItems);
      if (!values) return;
      if (values.length < (schema.minItems ?? 0) || values.length > (schema.maxItems ?? MODEL_LIMITS.listItems)) context.issue('range', path, 'List length is outside its permitted range.');
      const output: AttributeValue[] = [];
      for (let index = 0; index < values.length; index += 1) {
        const value = validateValue(schema.items, values[index], context, at(path, index), depth + 1);
        if (value !== undefined) output.push(value);
        if (context.overflow || context.nodes > context.maxNodes) break;
      }
      return output;
    } finally { if (input && typeof input === 'object') context.active.delete(input); }
  }
  if (!context.string(input, path)) return;
  if (schema.type === 'text' || schema.type === 'richText') {
    if (input.length < (schema.minLength ?? 0) || input.length > (schema.maxLength ?? MODEL_LIMITS.stringLength)) context.issue('range', path, 'Text length is outside its permitted range.');
    else return input;
  } else if (schema.type === 'decimal') {
    if (!canonicalDecimal(input)) { context.issue('format', path, 'Expected a canonical decimal string.'); return; }
    const [whole, fraction = ''] = input.replace(/^-/, '').split('.');
    const digits = Math.max(1, (whole === '0' ? 0 : whole.length) + fraction.length);
    if (digits > (schema.precision ?? MODEL_LIMITS.decimalDigits) || fraction.length > (schema.scale ?? schema.precision ?? MODEL_LIMITS.decimalDigits)) context.issue('range', path, 'Decimal exceeds its precision or scale.');
    else if ((schema.minimum !== undefined && compareDecimals(input, schema.minimum) < 0) || (schema.maximum !== undefined && compareDecimals(input, schema.maximum) > 0)) context.issue('range', path, 'Decimal is outside its permitted range.');
    else return input;
  } else if (schema.type === 'enum') {
    if (schema.values.includes(input)) return input;
    context.issue('enum', path, 'Value is not in the enumeration.');
  } else if (schema.type === 'uri') {
    if (input.length > (schema.maxLength ?? MODEL_LIMITS.stringLength)) context.issue('range', path, 'URI exceeds its permitted length.');
    else if (validUri(input, schema.schemes ?? URI_SCHEMES)) return input;
    else context.issue('format', path, 'Expected an absolute URI using a permitted scheme, without credentials.');
  } else {
    const valid = schema.type === 'date' ? validDate(input) : schema.type === 'timestamp' ? validTimestamp(input) : validDuration(input);
    if (valid) return input;
    context.issue('format', path, `Invalid ${schema.type} representation.`);
  }
  return;
}

function validateParsedAttributes(model: ModelDefinition, input: unknown, context = new Context(MODEL_LIMITS.valueNodes)): ValidationResult<AttributeValues> {
  const value = validateProperties(model.attributes, input, context, '', 1);
  return context.result(value ?? {});
}

export function validateAttributes(model: ModelDefinition, input: unknown): ValidationResult<AttributeValues> {
  const parsed = parseModelDefinition(model);
  if (!parsed.ok) return { ok: false, issues: parsed.issues.map(issue => ({ ...issue, path: `/model${issue.path}` })) };
  return validateParsedAttributes(parsed.value, input);
}

function differences(current: Readonly<Record<string, AttributeDefinition>>, proposed: Readonly<Record<string, AttributeDefinition>>, path: string, changes: ModelChange[]): void {
  for (const key of [...new Set([...Object.keys(current), ...Object.keys(proposed)])].sort()) {
    const location = at(path, key);
    if (!has(current, key)) changes.push({ code: 'attribute_added', path: location, requiresMigration: false });
    else if (!has(proposed, key)) changes.push({ code: 'attribute_removed', path: location, requiresMigration: true });
    else schemaDifference(current[key], proposed[key], location, changes);
  }
}

function schemaDifference(current: AttributeDefinition, proposed: AttributeDefinition, path: string, changes: ModelChange[]): void {
  if (current.type !== proposed.type) { changes.push({ code: 'type_changed', path, requiresMigration: true }); return; }
  if (current.label !== proposed.label) changes.push({ code: 'metadata_changed', path: at(path, 'label'), requiresMigration: false });
  const scalarOptions = (schema: AttributeDefinition): Fields => Object.fromEntries(Object.entries(schema).filter(([key]) => !['label', 'properties', 'items'].includes(key)));
  if (JSON.stringify(scalarOptions(current)) !== JSON.stringify(scalarOptions(proposed))) {
    const removesEnum = current.type === 'enum' && proposed.type === 'enum' && current.values.some(value => !proposed.values.includes(value));
    const removesScheme = current.type === 'uri' && proposed.type === 'uri' && (current.schemes ?? URI_SCHEMES).some(value => !(proposed.schemes ?? URI_SCHEMES).includes(value));
    changes.push({ code: 'constraints_changed', path, requiresMigration: removesEnum || removesScheme });
  }
  if (current.type === 'object' && proposed.type === 'object') differences(current.properties, proposed.properties, at(path, 'properties'), changes);
  if (current.type === 'list' && proposed.type === 'list') schemaDifference(current.items, proposed.items, at(path, 'items'), changes);
}

export function previewModelUpgrade(current: ModelDefinition, proposed: ModelDefinition, assets: readonly ModelAsset[]): ValidationResult<ModelUpgradePreview> {
  const before = parseModelDefinition(current); const after = parseModelDefinition(proposed);
  const context = new Context(MODEL_LIMITS.previewNodes);
  for (const [prefix, parsed] of [['current', before], ['proposed', after]] as const) {
    if (!parsed.ok) for (const issue of parsed.issues) context.issue(issue.code, `/${prefix}${issue.path}`, issue.message);
  }
  if (!before.ok || !after.ok) return context.result(undefined as never);
  if (before.value.id !== after.value.id) context.issue('model_identity', '/proposed/id', 'A model upgrade must retain its immutable id.');
  if (after.value.version !== before.value.version + 1) context.issue('model_version', '/proposed/version', 'A model upgrade must increment its version by exactly one.');
  const inputAssets = array(assets, context, '/assets', MODEL_LIMITS.previewAssets);
  if (!inputAssets || context.issues.length) return context.result(undefined as never);
  const changes: ModelChange[] = [];
  differences(before.value.attributes, after.value.attributes, '/attributes', changes);
  const results: ModelAssetPreview[] = [];
  const affected: string[] = [];
  const identifiers = new Set<string>();
  let nodes = 0;
  let strings = 0;
  let issues = 0;
  for (let index = 0; index < inputAssets.length; index += 1) {
    const path = `/assets/${index}`;
    const asset = fields(inputAssets[index], context, path, 4);
    if (!asset) continue;
    known(asset, ['id', 'attributes'], context, path);
    if (!context.string(asset.id, `${path}/id`, 256) || !asset.id.length) { context.issue('format', `${path}/id`, 'Asset id must be nonempty.'); continue; }
    if (identifiers.has(asset.id)) { context.issue('duplicate', `${path}/id`, 'Duplicate asset id.'); continue; }
    identifiers.add(asset.id);
    const oldContext = new Context(MODEL_LIMITS.valueNodes); const newContext = new Context(MODEL_LIMITS.valueNodes);
    const oldResult = validateParsedAttributes(before.value, asset.attributes, oldContext);
    const newResult = validateParsedAttributes(after.value, asset.attributes, newContext);
    nodes += oldContext.nodes + newContext.nodes;
    strings += oldContext.strings + newContext.strings;
    issues += oldResult.ok ? 0 : oldResult.issues.length;
    issues += newResult.ok ? 0 : newResult.issues.length;
    if (nodes > MODEL_LIMITS.previewNodes || strings > MODEL_LIMITS.totalStringLength || issues > MODEL_LIMITS.previewIssues) { context.issue('limit', path, 'The permitted preview input or result budget was exceeded.'); break; }
    results.push({ assetId: asset.id, currentIssues: oldResult.ok ? [] : oldResult.issues, proposedIssues: newResult.ok ? [] : newResult.issues });
    // Every supplied asset is affected by a semantic schema change, including a new required field.
    if (!oldResult.ok || !newResult.ok || changes.some(change => change.code !== 'metadata_changed')) affected.push(asset.id);
  }
  const compatible = results.every(asset => !asset.currentIssues.length && !asset.proposedIssues.length);
  return context.result({ coverage: 'provided-assets-only', changes, assets: results, affectedAssetIds: affected,
    compatibleWithProvidedAssets: compatible, requiresExplicitMigration: !compatible || changes.some(change => change.requiresMigration) });
}
