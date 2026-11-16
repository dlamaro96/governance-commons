// SPDX-License-Identifier: Apache-2.0
import { createHash } from 'node:crypto';
import { types as utilTypes } from 'node:util';
import { parseBoundedJSONEnvelope } from '../../domain/src/model.ts';
import { ADMIN_ACTIONS, COMPATIBILITY_ACTIONS, FIELD_ACTIONS, SERVICE_ACTIONS, type ActionId } from './actions.ts';
import type { AuthorityIssue, Digest, FieldId, Parsed, PolicyDefinition, PolicyExpr, PolicyFieldCatalog, PolicyRule,
  ResourceKind, RolePin, SubjectRef, UTC, UUID, Validity, Version } from './types.ts';

export const POLICY_LIMITS = Object.freeze({ bytes: 65_536, nodes: 128, depth: 8, rules: 128,
  setEntries: 256, domainAncestors: 32, issues: 64, version: 2_147_483_647,
  catalogEntries: 16_384, catalogBytes: 131_072, fieldBytes: 256 });
const resourceKinds: readonly ResourceKind[] = [
  'tenant', 'tenant-member', 'source', 'scan-job', 'asset', 'model-definition', 'model-migration',
  'asset-type-migration', 'relation-type', 'relation', 'relation-participation', 'relation-operation',
  'relation-preparation', 'domain-type', 'domain', 'asset-domain-placement', 'domain-type-migration', 'audit-event',
  'authority-group', 'authority-role', 'authority-policy', 'authority-grant', 'responsibility-type',
  'responsibility-assignment', 'authority-delegation', 'authority-elevation', 'execution-site',
  'service-principal', 'authority-decision',
];
const actions = new Set<string>([...COMPATIBILITY_ACTIONS.flatMap(([ids]) => [...ids]), ...ADMIN_ACTIONS, ...FIELD_ACTIONS, ...SERVICE_ACTIONS]);
const fieldActions = new Set<string>(FIELD_ACTIONS);
const kinds = new Set<string>(resourceKinds);
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const utcPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const malformedUnicode = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const compare = (left: string, right: string): number => left < right ? -1 : left > right ? 1 : 0;
const pointer = (path: string, key: string | number): string => `${path}/${String(key).replaceAll('~', '~0').replaceAll('/', '~1')}`;
class InputIssue extends Error {
  constructor(readonly issue: AuthorityIssue) { super(issue.message); }
}
function invalid(code: AuthorityIssue['code'], path: string, message: string): never {
  throw new InputIssue(Object.freeze({ code, path, message }));
}
function failure(issue: AuthorityIssue): Parsed<never> { return { ok: false, issues: Object.freeze([issue]) }; }
function unicode(value: string, path: string): void {
  if (malformedUnicode.test(value)) invalid('format', path, 'Expected well-formed Unicode.');
}

/** Descriptor-only inspection precedes property reads. Proxies are rejected before
 * any reflection, so even their ownKeys/getPrototypeOf traps are never invoked.
 * Own-key enumeration scales with preexisting keys: object/catalog callers must
 * admit their inputs first. External documents enter through parsePolicyFile. */
function plainArray(input: unknown, path: string, maximum: number): readonly unknown[] {
  if (typeof input !== 'object' || input === null || utilTypes.isProxy(input)
      || !Array.isArray(input) || Object.getPrototypeOf(input) !== Array.prototype) {
    invalid('type', path, 'Expected a plain array.');
  }
  const length = Object.getOwnPropertyDescriptor(input, 'length')!.value as number;
  if (length > maximum) invalid('limit', path, 'Array exceeds the permitted entry count.');
  if (Reflect.ownKeys(input).length !== length + 1) invalid('invalid_json', path, 'Expected a dense array with no extra properties.');
  const entries: unknown[] = [];
  for (let index = 0; index < length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(input, String(index));
    if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) {
      invalid('invalid_json', pointer(path, index), 'Array entries must be own enumerable data properties.');
    }
    entries.push(descriptor.value);
  }
  return entries;
}

/** A bounded JSON snapshot after caller admission, not arbitrary structuredClone/JSON.stringify. The
 * raw in-memory size is its JSON representation before set normalization.
 * Structural preflight bounds exceed every valid 64KiB policy grammar shape. */
function snapshot(input: unknown): unknown {
  let bytes = 0, visited = 0;
  const active = new Set<object>();
  function charge(text: string): void {
    if (text.length > POLICY_LIMITS.bytes || (bytes += Buffer.byteLength(text, 'utf8')) > POLICY_LIMITS.bytes) {
      invalid('limit', '', 'Policy exceeds 64 KiB of UTF-8 JSON.');
    }
  }
  function copy(value: unknown, path: string, depth: number): unknown {
    if (++visited > 16_384 || depth > 21) invalid('limit', path, 'JSON traversal exceeds the bounded policy profile.');
    if (value === null || typeof value === 'boolean') { charge(JSON.stringify(value)); return value; }
    if (typeof value === 'string') {
      if (value.length > POLICY_LIMITS.bytes) invalid('limit', path, 'String exceeds the policy byte budget.');
      unicode(value, path); charge(JSON.stringify(value)); return value;
    }
    if (typeof value === 'number') {
      if (!Number.isSafeInteger(value) || Object.is(value, -0)) invalid('invalid_json', path, 'Expected a safe integer JSON number.');
      charge(JSON.stringify(value)); return value;
    }
    if (typeof value !== 'object' || utilTypes.isProxy(value)) invalid('invalid_json', path, 'Expected JSON data without proxies or executable values.');
    if (active.has(value)) invalid('invalid_json', path, 'Cyclic input is not JSON.');
    active.add(value);
    try {
      if (Array.isArray(value)) {
        const entries = plainArray(value, path, POLICY_LIMITS.setEntries);
        charge('[]');
        return Object.freeze(entries.map((entry, index) => {
          if (index) charge(',');
          return copy(entry, pointer(path, index), depth + 1);
        }));
      }
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) invalid('invalid_json', path, 'Expected a plain JSON object.');
      const keys = Reflect.ownKeys(value);
      if (keys.length > 16) invalid('limit', path, 'Object exceeds the bounded policy shape.');
      const entries = new Map<string, unknown>();
      charge('{}');
      for (const key of keys) {
        if (typeof key !== 'string') invalid('invalid_json', path, 'Symbol properties are not JSON.');
        if (key.length > POLICY_LIMITS.bytes) invalid('limit', path, 'Property name exceeds the policy byte budget.');
        unicode(key, path);
        const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
        if (!('value' in descriptor) || !descriptor.enumerable) invalid('invalid_json', path, 'Expected enumerable data properties without accessors.');
        if (entries.size) charge(',');
        charge(JSON.stringify(key)); charge(':');
        // Avoid copying caller-chosen keys through an ordinary object's setters.
        entries.set(key, copy(descriptor.value, key.length <= 128 ? pointer(path, key) : path, depth + 1));
      }
      return Object.freeze(Object.fromEntries(entries));
    } finally { active.delete(value); }
  }
  return copy(input, '', 0);
}

function catalogSet(input: PolicyFieldCatalog): ReadonlySet<string> {
  const entries = plainArray(input, '', POLICY_LIMITS.catalogEntries);
  let bytes = 0;
  const fields = new Set<string>();
  for (const field of entries) {
    // Catalog problems deliberately reveal no trusted registry contents.
    if (typeof field !== 'string' || !field.length) invalid('type', '', 'Invalid trusted field catalog.');
    if (field.length > POLICY_LIMITS.fieldBytes) invalid('limit', '', 'Trusted field identifier exceeds its byte limit.');
    unicode(field, '');
    const size = Buffer.byteLength(field, 'utf8');
    if (size > POLICY_LIMITS.fieldBytes || (bytes += size) > POLICY_LIMITS.catalogBytes) invalid('limit', '', 'Trusted field catalog exceeds its byte budget.');
    if (fields.has(field)) invalid('duplicate', '', 'Trusted field catalog contains duplicate entries.');
    fields.add(field);
  }
  return fields;
}
function object(value: unknown, expected: readonly string[], path: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) invalid('type', path, 'Expected an object.');
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) if (!expected.includes(key)) invalid('unknown_field', path, 'Object contains an unknown property.');
  for (const key of expected) if (!Object.hasOwn(record, key)) invalid('required', pointer(path, key), 'Required property is missing.');
  return record;
}
function uuid(value: unknown, path: string): UUID {
  if (typeof value !== 'string') invalid('type', path, 'Expected a UUID string.');
  if (!uuidPattern.test(value)) invalid('format', path, 'Expected a canonical lowercase UUID.');
  return value as UUID;
}
function version(value: unknown, path: string): Version {
  if (typeof value !== 'number') invalid('type', path, 'Expected a version number.');
  if (!Number.isSafeInteger(value) || value < 1 || value > POLICY_LIMITS.version) invalid('version', path, 'Expected a positive PostgreSQL integer version.');
  return value as Version;
}
function boolean(value: unknown, path: string): boolean {
  if (typeof value !== 'boolean') invalid('type', path, 'Expected a boolean.');
  return value;
}
function registered<T extends string>(value: unknown, registry: ReadonlySet<string>, path: string): T {
  if (typeof value !== 'string') invalid('type', path, 'Expected a registered identifier.');
  if (!registry.has(value)) invalid('unsupported', path, 'Identifier is not registered.');
  return value as T;
}
function set<T>(value: unknown, path: string, parse: (value: unknown, path: string) => T, comparator: (a: T, b: T) => number): readonly T[] {
  if (!Array.isArray(value)) invalid('type', path, 'Expected an array.');
  if (!value.length) invalid('required', path, 'A finite set must be nonempty.');
  if (value.length > POLICY_LIMITS.setEntries) invalid('limit', path, 'Finite set exceeds 256 entries.');
  const values = value.map((entry, index) => parse(entry, pointer(path, index))).sort(comparator);
  for (let index = 1; index < values.length; index++) if (comparator(values[index - 1], values[index]) === 0) invalid('duplicate', path, 'Finite set contains duplicate values.');
  return Object.freeze(values);
}
function validity(value: unknown, path: string): Validity {
  const row = object(value, ['notBefore', 'expiresAt'], path);
  function timestamp(value: unknown, at: string): UTC | null {
    if (value === null) return null;
    if (typeof value !== 'string') invalid('type', at, 'Expected a UTC timestamp or null.');
    if (!utcPattern.test(value) || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) {
      invalid('format', at, 'Expected a canonical millisecond UTC timestamp.');
    }
    return value as UTC;
  }
  const notBefore = timestamp(row.notBefore, pointer(path, 'notBefore')), expiresAt = timestamp(row.expiresAt, pointer(path, 'expiresAt'));
  if (notBefore !== null && expiresAt !== null && notBefore >= expiresAt) invalid('range', path, 'Validity must be a nonempty half-open interval.');
  return Object.freeze({ notBefore, expiresAt });
}

/** Syntax and trusted catalog membership only. No evaluation, publication,
 * active-member proof, policy provenance or resource-wide grant is performed.
 * In-memory input/catalog objects require trusted caller admission: exact unknown,
 * symbol and non-enumerable key rejection entails reflecting all existing keys.
 * External policy documents must use parsePolicyFile before materialization. */
export function parsePolicy(input: unknown, catalog: PolicyFieldCatalog = []): Parsed<PolicyDefinition> {
  try {
    let fields: ReadonlySet<string>;
    try { fields = catalogSet(catalog); }
    catch (error) {
      if (!(error instanceof InputIssue)) throw error;
      invalid(error.issue.code, '', 'Invalid trusted field catalog.');
    }
    const row = object(snapshot(input), ['formatVersion', 'id', 'version', 'rules'], '');
    if (row.formatVersion !== 1) invalid('unsupported', '/formatVersion', 'Only policy format version 1 is supported.');
    const id = uuid(row.id, '/id'), policyVersion = version(row.version, '/version');
    if (!Array.isArray(row.rules)) invalid('type', '/rules', 'Expected a rule array.');
    if (!row.rules.length) invalid('required', '/rules', 'At least one rule is required.');
    if (row.rules.length > POLICY_LIMITS.rules) invalid('limit', '/rules', 'Policy exceeds 128 rules.');
    let nodes = 0;
    function expression(value: unknown, path: string, depth: number): PolicyExpr {
      if (++nodes > POLICY_LIMITS.nodes || depth > POLICY_LIMITS.depth) invalid('limit', path, 'Expression exceeds the cumulative node or depth budget.');
      if (typeof value !== 'object' || value === null || Array.isArray(value)) invalid('type', path, 'Expected a policy expression.');
      if (!Object.hasOwn(value, 'op')) invalid('required', pointer(path, 'op'), 'Expression operator is required.');
      const op = (value as Record<string, unknown>).op;
      const action = (value: unknown, at: string) => registered<ActionId>(value, actions, at);
      switch (op) {
        case 'all': case 'any': {
          const source = object(value, ['op', 'children'], path);
          if (!Array.isArray(source.children)) invalid('type', pointer(path, 'children'), 'Expected an expression array.');
          if (!source.children.length) invalid('required', pointer(path, 'children'), 'Expression children must be nonempty.');
          if (source.children.length > POLICY_LIMITS.setEntries) invalid('limit', pointer(path, 'children'), 'Expression children exceed 256 entries.');
          return Object.freeze({ op, children: Object.freeze(source.children.map((child, index) => expression(child, pointer(pointer(path, 'children'), index), depth + 1))) });
        }
        case 'subject-in': {
          const source = object(value, ['op', 'subjects'], path);
          const subjects = set<SubjectRef>(source.subjects, pointer(path, 'subjects'), (entry, at) => {
            const subject = object(entry, ['kind', 'id'], at);
            if (subject.kind !== 'human' && subject.kind !== 'service') invalid('unsupported', pointer(at, 'kind'), 'Expected a human or service subject.');
            return Object.freeze({ kind: subject.kind, id: uuid(subject.id, pointer(at, 'id')) });
          }, (a, b) => compare(a.kind, b.kind) || compare(a.id, b.id));
          return Object.freeze({ op, subjects });
        }
        case 'role-any': {
          const source = object(value, ['op', 'roles'], path);
          return Object.freeze({ op, roles: set<RolePin>(source.roles, pointer(path, 'roles'), (entry, at) => {
            const role = object(entry, ['roleId', 'version'], at);
            return Object.freeze({ roleId: uuid(role.roleId, pointer(at, 'roleId')), version: version(role.version, pointer(at, 'version')) });
          }, (a, b) => compare(a.roleId, b.roleId) || a.version - b.version) });
        }
        case 'action-in': {
          const source = object(value, ['op', 'actions'], path);
          return Object.freeze({ op, actions: set(source.actions, pointer(path, 'actions'), action, compare) });
        }
        case 'resource-kind-in': {
          const source = object(value, ['op', 'kinds'], path);
          return Object.freeze({ op, kinds: set(source.kinds, pointer(path, 'kinds'), (value, at) => registered<ResourceKind>(value, kinds, at), compare) });
        }
        case 'domain-in': {
          const source = object(value, ['op', 'domainIds', 'includeAncestors'], path);
          return Object.freeze({ op, domainIds: set(source.domainIds, pointer(path, 'domainIds'), uuid, compare), includeAncestors: boolean(source.includeAncestors, pointer(path, 'includeAncestors')) });
        }
        case 'group-any': {
          const source = object(value, ['op', 'groupIds'], path);
          return Object.freeze({ op, groupIds: set(source.groupIds, pointer(path, 'groupIds'), uuid, compare) });
        }
        case 'classification-any': case 'approved-tag-any': case 'purpose-in': case 'environment-in': {
          const source = object(value, ['op', 'ids'], path);
          return Object.freeze({ op, ids: set(source.ids, pointer(path, 'ids'), uuid, compare) });
        }
        case 'time-within': {
          const source = object(value, ['op', 'validity'], path);
          return Object.freeze({ op, validity: validity(source.validity, pointer(path, 'validity')) });
        }
        default: return invalid('unsupported', pointer(path, 'op'), 'Policy operator is not supported.');
      }
    }
    const issues: AuthorityIssue[] = [], rules: PolicyRule[] = [], ruleIds = new Set<UUID>();
    for (let index = 0; index < row.rules.length && issues.length < POLICY_LIMITS.issues; index++) {
      const path = pointer('/rules', index);
      try {
        const source = object(row.rules[index], ['id', 'effect', 'actions', 'fields', 'when'], path);
        const ruleId = uuid(source.id, pointer(path, 'id'));
        if (ruleIds.has(ruleId)) invalid('duplicate', pointer(path, 'id'), 'Rule IDs must be unique.');
        ruleIds.add(ruleId);
        if (source.effect !== 'allow' && source.effect !== 'deny') invalid('unsupported', pointer(path, 'effect'), 'Expected an allow or deny effect.');
        const ruleActions = set(source.actions, pointer(path, 'actions'), (value, at) => registered<ActionId>(value, actions, at), compare);
        const ruleFields = source.fields === null ? null : set(source.fields, pointer(path, 'fields'), (value, at) => registered<FieldId>(value, fields, at), compare);
        if (ruleActions.some(action => fieldActions.has(action) !== (ruleFields !== null))) invalid('scope', pointer(path, 'actions'), 'Field actions require fields; non-field actions require null fields.');
        rules.push(Object.freeze({ id: ruleId, effect: source.effect, actions: ruleActions, fields: ruleFields, when: expression(source.when, pointer(path, 'when'), 1) }));
      } catch (error) {
        if (!(error instanceof InputIssue)) throw error;
        issues.push(error.issue);
      }
    }
    if (issues.length) return { ok: false, issues: Object.freeze(issues) };
    const value: PolicyDefinition = Object.freeze({ formatVersion: 1, id, version: policyVersion, rules: Object.freeze(rules) });
    if (Buffer.byteLength(canonical(value), 'utf8') > POLICY_LIMITS.bytes) invalid('limit', '', 'Normalized policy exceeds 64 KiB of UTF-8 JSON.');
    return { ok: true, value };
  } catch (error) {
    if (!(error instanceof InputIssue)) throw error;
    return failure(error.issue);
  }
}

/** External document boundary: raw UTF-8 size is checked before JSON parsing.
 * The separately supplied field catalog remains trusted caller-admitted input. */
export function parsePolicyFile(text: string, catalog: PolicyFieldCatalog = []): Parsed<PolicyDefinition> {
  if (typeof text !== 'string') return failure({ code: 'type', path: '', message: 'Expected a JSON policy string.' });
  if (text.length > POLICY_LIMITS.bytes || Buffer.byteLength(text, 'utf8') > POLICY_LIMITS.bytes) return failure({ code: 'limit', path: '', message: 'Policy file exceeds 64 KiB of UTF-8.' });
  if (malformedUnicode.test(text)) return failure({ code: 'format', path: '', message: 'Expected well-formed Unicode.' });
  // Existing duplicate-aware lexical parser runs before ordinary JSON.parse.
  // Its migration depth21/node20000 limits exceed all valid authority shapes.
  const parsed = parseBoundedJSONEnvelope(text);
  if (!parsed.ok) return { ok: false, issues: Object.freeze(parsed.issues.slice(0, POLICY_LIMITS.issues).map(issue => Object.freeze({
    code: (issue.code === 'duplicate' ? 'duplicate' : issue.code === 'limit' ? 'limit' : 'invalid_json') as AuthorityIssue['code'],
    path: issue.path.length <= 1024 ? issue.path : '', message: 'Policy JSON is malformed, duplicated or exceeds the bounded profile.',
  }))) };
  return parsePolicy(parsed.value, catalog);
}

/** Project-compatible canonical JSON: own object keys sorted by UTF-16 code
 * units, arrays in normalized order, JSON.stringify primitive escaping/number
 * formatting, no whitespace or Unicode normalization. Only validated copies
 * reach this private recursion. SQL equivalence is a separate, unrun gate. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
export function canonicalPolicyJSON(input: unknown, catalog: PolicyFieldCatalog = []): Parsed<string> {
  const parsed = parsePolicy(input, catalog);
  return parsed.ok ? { ok: true, value: canonical(parsed.value) } : parsed;
}
/** SHA-256 of the canonical UTF-8 bytes, lowercase hexadecimal; not a signature. */
export function policyHash(input: unknown, catalog: PolicyFieldCatalog = []): Parsed<Digest> {
  const parsed = canonicalPolicyJSON(input, catalog);
  return parsed.ok ? { ok: true, value: createHash('sha256').update(parsed.value, 'utf8').digest('hex') as Digest } : parsed;
}
