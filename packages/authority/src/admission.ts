// SPDX-License-Identifier: Apache-2.0
import { types as utilTypes } from 'node:util';
import type { AuthorityIssue, Parsed } from './types.ts';

export type AuthorityJSON = null | boolean | number | string
  | readonly AuthorityJSON[] | { readonly [key: string]: AuthorityJSON };
export type AdmissionMetrics = {
  readonly rawBytes: number | null;
  readonly canonicalBytes: number;
  readonly nodes: number;
  readonly depth: number;
};
export type AdmittedJSON = { readonly data: AuthorityJSON; readonly metrics: AdmissionMetrics };

/** Only the physical JSON counters are enforced here. The remaining proposed
 * semantic limits require the separate complete decision/proof schema. */
export const AUTHORITY_ADMISSION_LIMITS = Object.freeze({
  rawBytes: 8_388_608, canonicalBytes: 8_388_608, jsonNodes: 262_144, jsonDepth: 32, issues: 64,
  contexts: 128, dependencyEdges: 1_024, dependencyReferences: 4_096, dependencyDepth: 16,
  policyPins: 32, policyBytes: 2_097_152, policyRules: 4_096, expressionNodes: 4_096,
  bindingInstances: 512, roleInstances: 256, originGrants: 512, delegationRecords: 1_024,
  delegationDepth: 4, lineageEdgeOccurrences: 3_072, authorityPrincipals: 2_048,
  proofBytes: 2_097_152, directGroupsPerSubject: 1_024, approvedFactIds: 4_096,
  factBytes: 1_048_576, domainPathEntries: 33, catalogEntries: 16_384,
  catalogBytes: 131_072, fieldBytes: 256, ruleEvaluations: 65_536,
  predicateVisits: 65_536, matchWitnesses: 65_536, matchBytes: 33_554_432,
});

// A null path means the submitted path exceeded this diagnostic representation.
// Never copy a huge key into an error or restart a truncated path at a child.
type Path = string | null;
const pathLimit = 1_024;
function childPath(path: Path, key: string | number): Path {
  if (path === null) return null;
  const text = String(key);
  if (text.length > pathLimit) return null;
  const result = `${path}/${text.replaceAll('~', '~0').replaceAll('/', '~1')}`;
  return result.length <= pathLimit ? result : null;
}
class AdmissionError extends Error {
  constructor(readonly issue: AuthorityIssue) { super(issue.message); }
}
function invalid(code: AuthorityIssue['code'], path: Path, message: string): never {
  throw new AdmissionError(Object.freeze({ code, path: path ?? '', message }));
}
function failure(error: unknown): Parsed<never> {
  const issue = error instanceof AdmissionError ? error.issue
    : Object.freeze({ code: 'invalid_json' as const, path: '', message: 'Expected bounded JSON data.' });
  return Object.freeze({ ok: false as const, issues: Object.freeze([issue]) });
}
function define(target: object, key: string, value: AuthorityJSON): void {
  Object.defineProperty(target, key, { value, enumerable: true, writable: true, configurable: true });
}
function object(entries: Iterable<readonly [string, AuthorityJSON]>): AuthorityJSON {
  const result = Object.create(null) as Record<string, AuthorityJSON>;
  for (const [key, value] of entries) define(result, key, value);
  return Object.freeze(result);
}

class Budget {
  bytes = 0;
  nodes = 0;
  depth = 0;
  charge(bytes: number, path: Path): void {
    if (bytes > AUTHORITY_ADMISSION_LIMITS.canonicalBytes - this.bytes) {
      invalid('limit', path, 'Canonical authority JSON exceeds 8 MiB.');
    }
    this.bytes += bytes;
  }
  visit(depth: number, path: Path): void {
    if (depth > AUTHORITY_ADMISSION_LIMITS.jsonDepth || this.nodes === AUTHORITY_ADMISSION_LIMITS.jsonNodes) {
      invalid('limit', path, 'Authority JSON exceeds its node or depth limit.');
    }
    this.nodes++;
    this.depth = Math.max(this.depth, depth);
  }
  minimumChildren(length: number, path: Path): void {
    if (length > AUTHORITY_ADMISSION_LIMITS.jsonNodes - this.nodes) {
      invalid('limit', path, 'Authority JSON exceeds its node limit.');
    }
  }
  /** Count JSON escaping and UTF-8 without first allocating a serialized copy. */
  string(value: string, path: Path): void {
    this.charge(2, path);
    for (let index = 0; index < value.length; index++) {
      const code = value.charCodeAt(index);
      if (code === 34 || code === 92 || code === 8 || code === 9 || code === 10 || code === 12 || code === 13) {
        this.charge(2, path);
      } else if (code < 32) this.charge(6, path);
      else if (code < 128) this.charge(1, path);
      else if (code < 2_048) this.charge(2, path);
      else if (code >= 0xd800 && code <= 0xdbff) {
        const low = value.charCodeAt(++index);
        if (!(low >= 0xdc00 && low <= 0xdfff)) invalid('invalid_json', path, 'Strings and keys must be well-formed Unicode.');
        this.charge(4, path);
      } else {
        if (code >= 0xdc00 && code <= 0xdfff) invalid('invalid_json', path, 'Strings and keys must be well-formed Unicode.');
        this.charge(3, path);
      }
    }
  }
  finish(data: AuthorityJSON, rawBytes: number | null): Parsed<AdmittedJSON> {
    const metrics = Object.freeze({ rawBytes, canonicalBytes: this.bytes, nodes: this.nodes, depth: this.depth });
    return Object.freeze({ ok: true as const, value: Object.freeze({ data, metrics }) });
  }
}

/** Trusted, allocation-bounded producers only: own-key reflection necessarily
 * scales with already-materialized metadata. A result is not authority proof. */
export function admitAuthorityInput(input: unknown): Parsed<AdmittedJSON> {
  const budget = new Budget(), active = new Set<object>();
  function copy(value: unknown, path: Path, depth: number): AuthorityJSON {
    budget.visit(depth, path);
    if (value === null || typeof value === 'boolean') {
      budget.charge(value === null ? 4 : value ? 4 : 5, path); return value;
    }
    if (typeof value === 'string') { budget.string(value, path); return value; }
    if (typeof value === 'number') {
      if (!Number.isSafeInteger(value) || Object.is(value, -0)) invalid('invalid_json', path, 'Expected a finite safe integer without negative zero.');
      budget.charge(String(value).length, path); return value;
    }
    if (typeof value !== 'object' || utilTypes.isProxy(value)) invalid('invalid_json', path, 'Expected JSON data without proxies or executable values.');
    if (active.has(value)) invalid('invalid_json', path, 'Cyclic input is not JSON.');
    active.add(value);
    try {
      if (Array.isArray(value)) {
        if (Object.getPrototypeOf(value) !== Array.prototype) invalid('invalid_json', path, 'Expected an ordinary dense array.');
        const length = Object.getOwnPropertyDescriptor(value, 'length')!.value as number;
        budget.minimumChildren(length, path);
        if (Reflect.ownKeys(value).length !== length + 1) invalid('invalid_json', path, 'Array entries must be dense with no extra properties.');
        budget.charge(2, path);
        const result: AuthorityJSON[] = [];
        for (let index = 0; index < length; index++) {
          const at = childPath(path, index), descriptor = Object.getOwnPropertyDescriptor(value, String(index));
          if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) invalid('invalid_json', at, 'Expected own enumerable data properties.');
          if (index) budget.charge(1, path);
          define(result, String(index), copy(descriptor.value, at, depth + 1));
        }
        return Object.freeze(result);
      }
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== Object.prototype && prototype !== null) invalid('invalid_json', path, 'Expected an ordinary or null-prototype object.');
      const names = Reflect.ownKeys(value);
      budget.minimumChildren(names.length, path);
      for (const key of names) if (typeof key !== 'string') invalid('invalid_json', path, 'Symbol properties are not JSON.');
      // JS enumerates integer-like keys specially. Canonical serialization must
      // sort keys explicitly; insertion order is not its definition.
      const keys = (names as string[]).sort(), entries: [string, AuthorityJSON][] = [];
      budget.charge(2, path);
      for (const key of keys) {
        const at = childPath(path, key), descriptor = Object.getOwnPropertyDescriptor(value, key)!;
        if (!('value' in descriptor) || !descriptor.enumerable) invalid('invalid_json', at, 'Expected own enumerable data properties.');
        if (entries.length) budget.charge(1, path);
        budget.string(key, path); budget.charge(1, path);
        entries.push([key, copy(descriptor.value, at, depth + 1)]);
      }
      return object(entries);
    } finally { active.delete(value); }
  }
  try { return budget.finish(copy(input, '', 1), null); }
  catch (error) { return failure(error); }
}

class Reader {
  offset = 0;
  constructor(readonly text: string, readonly budget: Budget) {}
  syntax(path: Path): never { return invalid('invalid_json', path, 'Expected valid JSON syntax.'); }
  space(): void {
    while (this.offset < this.text.length && [32, 9, 10, 13].includes(this.text.charCodeAt(this.offset))) this.offset++;
  }
  string(path: Path): string {
    const start = this.offset++;
    while (this.offset < this.text.length) {
      const code = this.text.charCodeAt(this.offset++);
      if (code === 34) {
        const value = JSON.parse(this.text.slice(start, this.offset)) as string;
        this.budget.string(value, path); return value;
      }
      if (code < 32) this.syntax(path);
      if (code === 92) {
        const escaped = this.text[this.offset++];
        if (escaped === 'u') {
          for (let index = 0; index < 4; index++) {
            const hex = this.text[this.offset++];
            if (hex === undefined || !/[0-9a-fA-F]/.test(hex)) this.syntax(path);
          }
        } else if (escaped === undefined || !'"\\/bfnrt'.includes(escaped)) this.syntax(path);
      }
    }
    return this.syntax(path);
  }
  number(path: Path): number {
    const negative = this.text[this.offset] === '-';
    if (negative) this.offset++;
    const coefficientStart = this.offset;
    const digit = (): boolean => this.text[this.offset] >= '0' && this.text[this.offset] <= '9';
    if (this.text[this.offset] === '0') this.offset++;
    else {
      if (!(this.text[this.offset] >= '1' && this.text[this.offset] <= '9')) return this.syntax(path);
      while (digit()) this.offset++;
    }
    let fractionDigits = 0;
    if (this.text[this.offset] === '.') {
      this.offset++;
      const start = this.offset;
      if (!digit()) return this.syntax(path);
      while (digit()) this.offset++;
      fractionDigits = this.offset - start;
    }
    const coefficientEnd = this.offset;
    let exponent = 0;
    if (this.text[this.offset] === 'e' || this.text[this.offset] === 'E') {
      this.offset++;
      const exponentNegative = this.text[this.offset] === '-';
      if (exponentNegative || this.text[this.offset] === '+') this.offset++;
      if (!digit()) return this.syntax(path);
      // Saturation exceeds every possible coefficient length in admitted text.
      // It avoids huge integers/Infinity while preserving the range decision.
      while (digit()) {
        exponent = Math.min(AUTHORITY_ADMISSION_LIMITS.rawBytes + 17, exponent * 10 + Number(this.text[this.offset++]));
      }
      if (exponentNegative) exponent = -exponent;
    }
    let significant = 0, trailingZeros = 0, firstDigits = '';
    for (let index = coefficientStart; index < coefficientEnd; index++) {
      const char = this.text[index];
      if (char === '.' || (!significant && char === '0')) continue;
      significant++;
      trailingZeros = char === '0' ? trailingZeros + 1 : 0;
      if (firstDigits.length < 16) firstDigits += char;
    }
    let value = 0;
    if (!significant) {
      if (negative) invalid('invalid_json', path, 'Negative zero is not admitted.');
    } else {
      const digits = significant - trailingZeros, zeros = exponent - fractionDigits + trailingZeros;
      if (zeros < 0 || digits + zeros > 16) invalid('invalid_json', path, 'Expected a finite safe integer without rounding.');
      value = Number(firstDigits.slice(0, digits) + '0'.repeat(zeros)) * (negative ? -1 : 1);
      if (!Number.isSafeInteger(value)) invalid('invalid_json', path, 'Expected a finite safe integer without rounding.');
    }
    this.budget.charge(String(value).length, path); return value;
  }
  value(path: Path, depth: number): AuthorityJSON {
    this.budget.visit(depth, path); this.space();
    const char = this.text[this.offset];
    if (char === '"') return this.string(path);
    if (char === '{') {
      this.offset++; this.budget.charge(2, path); this.space();
      const entries = new Map<string, AuthorityJSON>();
      if (this.text[this.offset] === '}') { this.offset++; return object(entries); }
      for (;;) {
        if (this.text[this.offset] !== '"') return this.syntax(path);
        const key = this.string(path), at = childPath(path, key);
        if (entries.has(key)) invalid('duplicate', at, 'Duplicate decoded object property.');
        this.space();
        if (this.text[this.offset++] !== ':') return this.syntax(path);
        this.budget.charge(1, path);
        entries.set(key, this.value(at, depth + 1)); this.space();
        const delimiter = this.text[this.offset++];
        if (delimiter === '}') return object([...entries].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0));
        if (delimiter !== ',') return this.syntax(path);
        this.budget.charge(1, path); this.space();
      }
    }
    if (char === '[') {
      this.offset++; this.budget.charge(2, path); this.space();
      const result: AuthorityJSON[] = [];
      if (this.text[this.offset] === ']') { this.offset++; return Object.freeze(result); }
      for (;;) {
        const index = result.length;
        define(result, String(index), this.value(childPath(path, index), depth + 1)); this.space();
        const delimiter = this.text[this.offset++];
        if (delimiter === ']') return Object.freeze(result);
        if (delimiter !== ',') return this.syntax(path);
        this.budget.charge(1, path);
      }
    }
    for (const [literal, value] of [['null', null], ['true', true], ['false', false]] as const) {
      if (this.text.startsWith(literal, this.offset)) {
        this.offset += literal.length; this.budget.charge(literal.length, path); return value;
      }
    }
    return this.number(path);
  }
}

/** Raw external JSON boundary. Duplicate-aware parsing never first materializes
 * an unrestricted JSON object; this admission result does not authorize use. */
export function parseAuthorityInputFile(text: string): Parsed<AdmittedJSON> {
  try {
    if (typeof text !== 'string') invalid('type', '', 'Expected an authority JSON string.');
    if (text.length > AUTHORITY_ADMISSION_LIMITS.rawBytes) invalid('limit', '', 'Authority JSON file exceeds 8 MiB.');
    const rawBytes = Buffer.byteLength(text, 'utf8');
    if (rawBytes > AUTHORITY_ADMISSION_LIMITS.rawBytes) invalid('limit', '', 'Authority JSON file exceeds 8 MiB.');
    const budget = new Budget(), reader = new Reader(text, budget), data = reader.value('', 1);
    reader.space();
    if (reader.offset !== text.length) reader.syntax('');
    return budget.finish(data, rawBytes);
  } catch (error) { return failure(error); }
}
