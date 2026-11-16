// SPDX-License-Identifier: Apache-2.0
/** Exact domain HTTP wire schemas. These schemas do not replace current service
 * authorization, complete-scope projection, or database integrity checks. */
import { Type, Kind, TypeRegistry, type TProperties, type TSchema } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import type { FastifyRequest } from 'fastify';
import { Problem } from '../../../packages/authz/src/index.ts';

const object = <T extends TProperties>(properties: T) => Type.Object(properties, { additionalProperties: false });
const choices = (...values: string[]) => Type.Union(values.map(value => Type.Literal(value)));
const nullable = <T extends TSchema>(schema: T) => Type.Union([schema, Type.Null()]);
const boundedInteger = (minimum = 1, maximum = 2147483647) => Type.Integer({ minimum, maximum });
const keyPattern = '^(?!(?:__proto__|prototype|constructor)$)[A-Za-z_][A-Za-z0-9_.-]{0,63}$';
const safeKey = new RegExp(keyPattern);
export const DomainUUID = Type.String({ pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' });
const key = Type.String({ pattern: keyPattern });
const version = boundedInteger();
const digest = Type.String({ pattern: '^[a-f0-9]{64}$' });
const utc = Type.String({ pattern: '^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$' });
// JSON Schema length counts Unicode characters; TypeBox's default checker
// counts UTF-16 units. Keep the published schema and strict ingress/egress
// checker consistent for names, descriptions, reasons and literal searches.
TypeRegistry.Set('DomainUnicodeText', (schema, value) => {
  const bounds = schema as { minLength: number; maxLength: number };
  if (typeof value !== 'string') return false;
  const length = [...value].length;
  return length >= bounds.minLength && length <= bounds.maxLength
    && !/\p{Cc}|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value);
});
const text = (minimum: number, maximum: number) => Type.Unsafe<string>({ [Kind]: 'DomainUnicodeText', type: 'string',
  minLength: minimum, maxLength: maximum, pattern: '^[^\\u0000-\\u001f\\u007f-\\u009f]*$' });
const reason = text(1, 500), name = text(1, 200), description = text(0, 4000);
const correlation = Type.String({ minLength: 1, maxLength: 128 });
const schemaRef = Type.Ref('DomainAttributeSchema'), definitionRef = Type.Ref('DomainAttributeDefinition');
const properties = (schema: TSchema) => Type.Record(key, schema, { maxProperties: 128, additionalProperties: false });
const definitions = properties(definitionRef);
function attribute(metadata: TProperties) {
  return Type.Union([
    ...['text', 'richText'].map(type => object({ type: Type.Literal(type), ...metadata, minLength: Type.Optional(boundedInteger(0, 65536)), maxLength: Type.Optional(boundedInteger(0, 65536)) })),
    object({ type: Type.Literal('number'), ...metadata, integer: Type.Optional(Type.Boolean()), minimum: Type.Optional(Type.Number()), maximum: Type.Optional(Type.Number()) }),
    object({ type: Type.Literal('decimal'), ...metadata, precision: Type.Optional(boundedInteger(1, 1000)), scale: Type.Optional(boundedInteger(0, 1000)), minimum: Type.Optional(Type.String({ maxLength: 1003 })), maximum: Type.Optional(Type.String({ maxLength: 1003 })) }),
    ...['boolean', 'date', 'timestamp', 'duration'].map(type => object({ type: Type.Literal(type), ...metadata })),
    object({ type: Type.Literal('enum'), ...metadata, values: Type.Array(Type.String({ maxLength: 65536 }), { minItems: 1, maxItems: 256, uniqueItems: true }) }),
    object({ type: Type.Literal('list'), ...metadata, items: schemaRef, minItems: Type.Optional(boundedInteger(0, 1000)), maxItems: Type.Optional(boundedInteger(0, 1000)) }),
    object({ type: Type.Literal('uri'), ...metadata, schemes: Type.Optional(Type.Array(choices('https', 'http', 'urn', 'mailto', 's3', 'gs', 'abfs', 'abfss'), { maxItems: 8, uniqueItems: true })), maxLength: Type.Optional(boundedInteger(0, 65536)) }),
    object({ type: Type.Literal('object'), ...metadata, properties: definitions }),
  ]);
}
const attributeSchema = { ...attribute({}), $id: 'DomainAttributeSchema' };
const attributeDefinition = { ...attribute({ required: Type.Optional(Type.Boolean()), label: Type.Optional(Type.String({ maxLength: 256 })) }), $id: 'DomainAttributeDefinition' };
const attributeValue = Type.Recursive(Self => Type.Union([
  Type.String({ maxLength: 65536 }), Type.Number(), Type.Boolean(),
  Type.Array(Self, { maxItems: 1000 }), properties(Self),
]), { $id: 'DomainAttributeValue' });
const attributes = properties(Type.Ref(attributeValue));
const pin = object({ typeId: DomainUUID, version });
const lifecycle = object({ initial: key, states: Type.Array(key, { minItems: 1, maxItems: 32, uniqueItems: true }),
  transitions: Type.Array(object({ from: key, to: key }), { maxItems: 256, uniqueItems: true }) });
const typeDefinition = object({ formatVersion: Type.Literal(1), kind: Type.Literal('domain-type'), id: key, version,
  label: name, parents: Type.Array(pin, { maxItems: 8, uniqueItems: true }), attributes: definitions,
  overrideAttributes: Type.Array(key, { maxItems: 128, uniqueItems: true }), requiredOwner: Type.Boolean(), lifecycle: nullable(lifecycle) });
const resolved = object({ attributes: definitions, requiredOwner: Type.Boolean(), lifecycle,
  dependencies: Type.Array(pin, { maxItems: 64, uniqueItems: true }) });
const typeFields = { typeId: DomainUUID, key, version, currentVersion: version, definition: typeDefinition, resolved, definitionHash: digest, resolutionHash: digest };
const typeView = object({ ...typeFields, createdAt: utc, createdBy: DomainUUID });
const tupleFields = { name, description, parentId: nullable(DomainUUID), type: pin, attributes, ownerId: nullable(DomainUUID), state: key, status: choices('active', 'retired') };
const tuple = object(tupleFields);
const domainView = object({ ...tupleFields, id: DomainUUID, version, createdAt: utc, createdBy: DomainUUID, updatedAt: utc, updatedBy: DomainUUID });
const domainRevision = object({ formatVersion: Type.Literal(1), domain: domainView,
  action: choices('created', 'updated', 'moved', 'state-changed', 'retired', 'restored', 'type-migrated'), reason, correlationId: correlation });
const placementView = object({ assetId: DomainUUID, version: boundedInteger(0), domainId: nullable(DomainUUID),
  recordedAssetVersion: nullable(version), recordedDomainVersion: nullable(version), recordedAt: nullable(utc), recordedBy: nullable(DomainUUID) });
const placementRevision = object({ formatVersion: Type.Literal(1), placement: placementView, reason, correlationId: correlation });
const path = Type.Array(key, { minItems: 1, maxItems: 8 });
const onMissing = choices('skip', 'error');
const operation = Type.Union([
  object({ op: Type.Literal('rename'), from: path, to: path, onMissing }),
  object({ op: Type.Literal('remove'), path, onMissing }),
  object({ op: Type.Literal('set'), path, value: Type.Ref(attributeValue), mode: choices('ifMissing', 'replace') }),
  object({ op: Type.Literal('enumMap'), path, mappings: Type.Array(object({ from: Type.String({ maxLength: 65536 }), to: Type.String({ maxLength: 65536 }) }), { maxItems: 256 }), onMissing, onUnmapped: choices('keep', 'error') }),
  object({ op: Type.Literal('convert'), path, conversion: choices('safeIntegerToDecimal', 'decimalToText', 'textToDecimal'), onMissing }),
]);
const changeCode = choices('attribute_added', 'attribute_removed', 'type_changed', 'constraints_changed', 'metadata_changed');
const policyChange = choices('parents_changed', 'required_owner_changed', 'lifecycle_changed');
const migrationPlan = object({ formatVersion: Type.Literal(1), kind: Type.Literal('domain-type-migration'), typeId: DomainUUID,
  attributes: object({ formatVersion: Type.Literal(1), modelId: key, targetVersion: version,
    sourceVersions: Type.Array(version, { maxItems: 1000, uniqueItems: true }),
    acknowledgedChanges: Type.Array(object({ code: choices('attribute_removed', 'type_changed', 'constraints_changed'), path: Type.String({ maxLength: 2048 }) }), { maxItems: 2048 }),
    operations: Type.Array(operation, { maxItems: 64 }) }),
  owner: object({ default: Type.Literal('preserve'), overrides: Type.Array(object({ domainId: DomainUUID, ownerId: nullable(DomainUUID) }), { maxItems: 1000 }) }),
  lifecycle: object({ onUnmapped: choices('preserve', 'error'), mappings: Type.Array(object({ sourceVersion: version, from: key, to: key }), { maxItems: 1000 }) }),
  acknowledgedPolicyChanges: Type.Array(policyChange, { maxItems: 3, uniqueItems: true }),
});
const issue = object({ code: choices('invalid_json', 'unknown_field', 'unknown_type', 'invalid_definition', 'type', 'required', 'format', 'range', 'enum', 'duplicate', 'limit', 'cycle', 'model_identity', 'model_version', 'unsupported'),
  path: Type.String({ maxLength: 4096 }), message: Type.String({ maxLength: 1000 }) });
const issues = Type.Array(issue, { maxItems: 100 });
const migrationPreview = object({ typeId: DomainUUID, expectedHeadVersion: version, target: object(typeFields),
  coverage: Type.Literal('complete-direct-domain-type-bindings'), mode: choices('preserve-pins', 'migrate'),
  changes: Type.Array(object({ code: changeCode, path: Type.String({ maxLength: 2048 }), requiresMigration: Type.Boolean() }), { maxItems: 4096 }),
  policyChanges: Type.Array(policyChange, { maxItems: 3, uniqueItems: true }),
  domains: Type.Array(object({ before: domainView, proposed: tuple, issues }), { maxItems: 1000 }),
  pinsPreserved: Type.Boolean(), requiresMigration: Type.Boolean(), ready: Type.Boolean(), previewDigest: nullable(digest) });
const migrationContext = object({ coverage: Type.Literal('complete-direct-domain-type-bindings'), type: typeView,
  sources: Type.Array(typeView, { maxItems: 1000 }), domains: Type.Array(domainView, { maxItems: 1000 }) });
const migrationReceipt = object({ formatVersion: Type.Literal(1), id: DomainUUID, typeId: DomainUUID,
  fromHeadVersion: version, targetVersion: version, plan: migrationPlan, planHash: digest, previewDigest: digest,
  sourcePolicies: Type.Array(object({ pin, definitionHash: digest, resolutionHash: digest }), { maxItems: 1000 }),
  targetDefinitionHash: digest, targetResolutionHash: digest,
  outcomes: Type.Array(object({ domainId: DomainUUID, fromVersion: version, toVersion: version, before: tuple, after: tuple }), { maxItems: 1000 }),
  actorId: DomainUUID, occurredAt: utc, reason, correlationId: correlation });
const hierarchyChange = object({ kind: choices('move', 'retire', 'restore'), domainId: DomainUUID, expectedVersion: version, parentId: nullable(DomainUUID), reason });
const hierarchyPreview = object({ coverage: Type.Literal('complete-affected-domain-subtree'), change: hierarchyChange,
  domains: Type.Array(object({ domainId: DomainUUID, version, parentId: nullable(DomainUUID) }), { maxItems: 1000 }),
  assets: Type.Array(object({ assetId: DomainUUID, assetVersion: version, placementVersion: version }), { maxItems: 1000 }),
  ready: Type.Boolean(), issues, previewDigest: nullable(digest) });
const page = (item: TSchema) => object({ items: Type.Array(item, { maxItems: 100 }), nextCursor: nullable(Type.String({ minLength: 1, maxLength: 1024 })) });
const definitionFields = { definition: typeDefinition, reason };
const editFields = { name, description, attributes, ownerId: nullable(DomainUUID), reason };
export const domainSharedSchemas: readonly TSchema[] = [attributeSchema, attributeDefinition, attributeValue];
export const domainHttp = {
  request: {
    file: object({ text: Type.String({ maxLength: 524288 }) }),
    definition: object(definitionFields), publication: object({ ...definitionFields, previewDigest: digest }),
    migrationPreview: object({ ...definitionFields, plan: migrationPlan }), migration: object({ ...definitionFields, plan: migrationPlan, previewDigest: digest }),
    create: object({ ...editFields, parentId: nullable(DomainUUID), type: pin }), edit: object(editFields), state: object({ state: key, reason }),
    hierarchyPreview: object({ change: hierarchyChange }), hierarchy: object({ change: hierarchyChange, previewDigest: digest }),
    placement: object({ assetVersion: version, domainId: nullable(DomainUUID), domainVersion: nullable(version), reason }),
  },
  response: {
    definition: object({ definition: typeDefinition }), plan: object({ plan: migrationPlan }), type: object({ type: typeView }),
    typePage: page(object({ typeId: DomainUUID, key, label: name, currentVersion: version })),
    typePreview: object({ preview: migrationPreview }), migrationContext, migration: object({ type: typeView, receipt: migrationReceipt }), receipt: object({ receipt: migrationReceipt }),
    domain: object({ domain: domainView }), domainPage: page(domainView), ownerPage: page(object({ id: DomainUUID, name })),
    hierarchyPreview: object({ preview: hierarchyPreview }), history: page(domainRevision),
    assets: page(object({ assetId: DomainUUID, name: Type.String({ minLength: 1, maxLength: 512 }), assetVersion: version, placementVersion: version })),
    placement: object({ placement: placementView, domain: nullable(domainView) }), placementHistory: page(placementRevision),
  },
};
export const domainProblemSchema = object({ type: Type.Literal('about:blank'), title: Type.String({ maxLength: 100 }), status: boundedInteger(400, 599),
  code: Type.String({ pattern: '^[A-Z][A-Z0-9_]{0,79}$' }), detail: Type.String({ maxLength: 1000 }), correlationId: correlation,
  issues: Type.Optional(issues) });
export const domainParams = (fields: readonly string[]) => object(Object.fromEntries(fields.map(field => [field,
  field === 'version' ? Type.String({ pattern: '^[1-9][0-9]{0,9}$' }) : DomainUUID])));
export const domainQuerySchema = (fields: readonly string[]) => object(Object.fromEntries(fields.map(field => [field, Type.Optional(
  field === 'limit' ? Type.String({ pattern: '^[1-9][0-9]{0,2}$' }) : field === 'cursor' ? Type.String({ minLength: 1, maxLength: 1024 }) :
  field === 'q' ? text(0, 200) : field === 'status' ? choices('active', 'retired', 'all') : Type.Union([DomainUUID, Type.Literal('root')]))])));

export const domainJSONInvalid = () => new Problem(400, 'DOMAIN_JSON_INVALID', 'Provide exactly the declared JSON fields and values without coercion.');
export const domainPageInvalid = () => new Problem(400, 'DOMAIN_PAGE_INVALID', 'The domain query or page cursor is invalid.');
/** No schema coercion/removal is used for the authoritative ingress check. */
export function domainSchemaCheck(schema: TSchema, input: unknown): boolean { return Value.Check(schema, [...domainSharedSchemas], input); }
export function domainExpectedVersion(req: FastifyRequest, placement = false): number {
  const raw = req.headers['if-match'];
  if (typeof raw !== 'string' || !/^(?:0|[1-9][0-9]*|"(?:0|[1-9][0-9]*)")$/.test(raw))
    throw new Problem(428, 'VERSION_REQUIRED', 'Send the current version using If-Match.');
  const value = Number(raw.replaceAll('"', ''));
  if (!Number.isInteger(value) || value < (placement ? 0 : 1) || value > 2147483647)
    throw new Problem(428, 'VERSION_REQUIRED', 'Send the current supported version using If-Match.');
  return value;
}
export function domainIdempotencyKey(req: FastifyRequest): string {
  const value = req.headers['idempotency-key'];
  if (typeof value !== 'string' || value.length < 8 || value.length > 128 || /[\u0000-\u001f\u007f-\u009f]/.test(value))
    throw new Problem(400, 'IDEMPOTENCY_REQUIRED', 'An Idempotency-Key of 8–128 characters is required.');
  return value;
}
export function domainRawQuery(req: FastifyRequest, allowed: readonly string[]): Record<string, string | number> {
  let search: URLSearchParams;
  try {
    const raw = req.url.split('?', 2)[1] ?? '';
    decodeURIComponent(raw.replaceAll('+', ' '));
    search = new URL(req.url, 'http://local.invalid').searchParams;
  } catch { throw domainPageInvalid(); }
  const values = new Map<string, string | number>();
  for (const [key, value] of search) {
    if (!allowed.includes(key) || values.has(key) || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value)) throw domainPageInvalid();
    if (key === 'limit' && (!/^[1-9][0-9]*$/.test(value) || Number(value) > 100)) throw domainPageInvalid();
    values.set(key, value);
  }
  const raw = Object.fromEntries(values);
  if (!domainSchemaCheck(domainQuerySchema(allowed), raw)) throw domainPageInvalid();
  if (values.has('limit')) values.set('limit', Number(values.get('limit')));
  return Object.fromEntries(values);
}

/** Inspect the original spelling before JSON.parse can erase repeated fields.
 * The envelope budget includes two wrapper levels beyond a domain document;
 * retained domain values keep the service's stricter shared 512 KiB profile. */
export function parseDomainRequestJSON(text: string): unknown {
  if (Buffer.byteLength(text, 'utf8') > 1048576) throw domainJSONInvalid();
  let offset = 0, nodes = 0;
  const malformed = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
  const space = () => { while (offset < text.length && /[\t\r\n ]/.test(text[offset])) offset += 1; };
  const string = (): string => {
    const start = offset;
    if (text[offset++] !== '"') throw domainJSONInvalid();
    while (offset < text.length) {
      const next = text[offset++];
      if (next === '\\') offset += 1;
      else if (next === '"') {
        const result: unknown = JSON.parse(text.slice(start, offset));
        if (typeof result !== 'string' || malformed.test(result)) throw domainJSONInvalid();
        return result;
      }
    }
    throw domainJSONInvalid();
  };
  const visit = (depth: number): void => {
    nodes += 1;
    if (nodes > 100010 || depth > 34) throw domainJSONInvalid();
    space();
    if (text[offset] === '{') {
      offset += 1; space(); const keys = new Set<string>();
      if (text[offset] === '}') { offset += 1; return; }
      while (offset < text.length) {
        space(); const key = string();
        if (keys.has(key) || !safeKey.test(key) || keys.size >= 128) throw domainJSONInvalid();
        keys.add(key); space();
        if (text[offset++] !== ':') throw domainJSONInvalid();
        visit(depth + 1); space(); const next = text[offset++];
        if (next === '}') return;
        if (next !== ',') throw domainJSONInvalid();
      }
      throw domainJSONInvalid();
    }
    if (text[offset] === '[') {
      offset += 1; space();
      if (text[offset] === ']') { offset += 1; return; }
      let items = 0;
      while (offset < text.length) {
        if (++items > 2048) throw domainJSONInvalid();
        visit(depth + 1); space(); const next = text[offset++];
        if (next === ']') return;
        if (next !== ',') throw domainJSONInvalid();
      }
      throw domainJSONInvalid();
    }
    if (text[offset] === '"') { string(); return; }
    const start = offset;
    while (offset < text.length && !/[\t\r\n ,}\]]/.test(text[offset])) offset += 1;
    if (offset === start) throw domainJSONInvalid();
    const value: unknown = JSON.parse(text.slice(start, offset));
    if (typeof value === 'number' && (!Number.isFinite(value) || Object.is(value, -0))) throw domainJSONInvalid();
  };
  try {
    visit(0); space(); if (offset !== text.length) throw domainJSONInvalid();
    const result: unknown = JSON.parse(text);
    if (result === null || typeof result !== 'object' || Array.isArray(result)) throw domainJSONInvalid();
    return result;
  } catch { throw domainJSONInvalid(); }
}

/** Fastify normally supplies parsed JSON. Keep injected or earlier-hook values
 * from introducing accessors, symbols, sparse arrays or exotic prototypes. */
export function checkDomainData(input: unknown): void {
  const active = new Set<object>(); let nodes = 0;
  const visit = (value: unknown, depth: number): void => {
    if (++nodes > 100010 || depth > 34) throw domainJSONInvalid();
    if (value === null || typeof value === 'boolean') return;
    if (typeof value === 'string') {
      if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value)) throw domainJSONInvalid();
      return;
    }
    if (typeof value === 'number') { if (!Number.isFinite(value) || Object.is(value, -0)) throw domainJSONInvalid(); return; }
    if (!value || typeof value !== 'object' || active.has(value)) throw domainJSONInvalid();
    const array = Array.isArray(value), keys = Reflect.ownKeys(value);
    if (array ? Object.getPrototypeOf(value) !== Array.prototype || value.length > 2048 || keys.length !== value.length + 1
      : ![Object.prototype, null].includes(Object.getPrototypeOf(value)) || keys.length > 128) throw domainJSONInvalid();
    active.add(value);
    try {
      const selected = array ? Array.from({ length: value.length }, (_, index) => String(index)) : keys;
      for (const key of selected) {
        if (typeof key !== 'string' || !array && !safeKey.test(key)) throw domainJSONInvalid();
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw domainJSONInvalid();
        visit(descriptor.value, depth + 1);
      }
    } finally { active.delete(value); }
  };
  visit(input, 0);
}
