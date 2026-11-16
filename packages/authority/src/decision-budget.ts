// SPDX-License-Identifier: Apache-2.0
import { types as utilTypes } from 'node:util';
import { AUTHORITY_ADMISSION_LIMITS as LIMITS } from './admission.ts';
import type { AdmissionMetrics } from './admission.ts';
import type { AuthorityIssue } from './types.ts';
import type { BudgetCounter, BudgetPort, DecisionMetrics, RetainedCategory } from './decision-types.ts';
import { DecisionInputError } from './decision-types.ts';

export type DecisionFailureOutcome = 'invalid' | 'unsupported' | 'profile_limit';
/** One typed failure crosses all internal stages; public evaluators erase partial decisions. */
export class DecisionFailure extends DecisionInputError {
  constructor(outcome: DecisionFailureOutcome, code: AuthorityIssue['code'], path: string, message: string) {
    const safeMessage = message.length <= 256 ? message : 'Authority input or derived evidence is invalid.';
    super(outcome, Object.freeze({ code, path: path.length <= 1_024 ? path : '', message: safeMessage }));
    this.name = 'DecisionFailure';
  }
}

const counterLimits: Record<BudgetCounter, number> = {
  contexts: LIMITS.contexts, dependencyEdges: LIMITS.dependencyEdges,
  dependencyReferences: LIMITS.dependencyReferences, dependencyDepth: LIMITS.dependencyDepth,
  policyPins: LIMITS.policyPins, policyBytes: LIMITS.policyBytes, policyRules: LIMITS.policyRules,
  expressionNodes: LIMITS.expressionNodes, bindingInstances: LIMITS.bindingInstances,
  roleInstances: LIMITS.roleInstances, originGrants: LIMITS.originGrants,
  delegationRecords: LIMITS.delegationRecords, lineageEdgeOccurrences: LIMITS.lineageEdgeOccurrences,
  authorityPrincipals: LIMITS.authorityPrincipals, proofBytes: LIMITS.proofBytes,
  factBytes: LIMITS.factBytes, actualRuleVisits: LIMITS.ruleEvaluations,
  actualPredicateCalls: LIMITS.predicateVisits, chargedPredicateNodeVisits: LIMITS.predicateVisits,
  // These are actual or conservatively charged work counters, not unadopted CPU limits.
  factValidationVisits: Number.MAX_SAFE_INTEGER, memoHits: Number.MAX_SAFE_INTEGER,
  matchWitnesses: LIMITS.matchWitnesses, outputBytes: LIMITS.matchBytes,
  approvedFactIds: LIMITS.approvedFactIds, catalogEntries: LIMITS.catalogEntries,
  catalogBytes: LIMITS.catalogBytes,
};
Object.freeze(counterLimits);
export const AUTHORITY_RETAINED_LIMITS: Readonly<Record<RetainedCategory, number>> = Object.freeze({
  raw: 8_388_608, normalized: 8_388_608, compiled: 8_388_608, memo: 8_388_608, output: 33_554_432,
});

function emptyMetrics(admission: AdmissionMetrics | null): DecisionMetrics {
  return {
    admission: admission === null ? null : Object.freeze({ ...admission }),
    contexts: 0, dependencyEdges: 0, dependencyReferences: 0, dependencyDepth: 0,
    policyPins: 0, policyBytes: 0, policyRules: 0, expressionNodes: 0,
    bindingInstances: 0, roleInstances: 0, originGrants: 0, delegationRecords: 0,
    lineageEdgeOccurrences: 0, authorityPrincipals: 0, proofBytes: 0, factBytes: 0,
    actualRuleVisits: 0, actualPredicateCalls: 0, chargedPredicateNodeVisits: 0,
    factValidationVisits: 0, memoHits: 0, matchWitnesses: 0, outputBytes: 0,
  };
}

/** A budget lives for the complete root/dependency bundle. Never create one per node. */
export class DecisionBudget implements BudgetPort {
  readonly metrics: DecisionMetrics;
  private readonly hidden = { approvedFactIds: 0, catalogEntries: 0, catalogBytes: 0 };
  private readonly retained: Record<RetainedCategory, number> = { raw: 0, normalized: 0, compiled: 0, memo: 0, output: 0 };

  constructor(admission: AdmissionMetrics | null = null) { this.metrics = emptyMetrics(admission); }

  fail(outcome: DecisionFailureOutcome, code: AuthorityIssue['code'], path: string, message: string): never {
    throw new DecisionFailure(outcome, code, path, message);
  }
  private amount(value: number, path: string): void {
    if (!Number.isSafeInteger(value) || value < 0 || Object.is(value, -0)) {
      this.fail('invalid', 'range', path, 'Authority accounting requires a nonnegative safe integer.');
    }
  }
  private current(counter: BudgetCounter): number {
    return counter === 'approvedFactIds' || counter === 'catalogEntries' || counter === 'catalogBytes'
      ? this.hidden[counter] : this.metrics[counter];
  }
  private set(counter: BudgetCounter, value: number): void {
    if (counter === 'approvedFactIds' || counter === 'catalogEntries' || counter === 'catalogBytes') this.hidden[counter] = value;
    else this.metrics[counter] = value;
  }
  charge(counter: BudgetCounter, amount: number, path = ''): void {
    this.amount(amount, path);
    if (!Object.hasOwn(counterLimits, counter)) this.fail('invalid', 'unsupported', path, 'Unknown authority counter.');
    const current = this.current(counter);
    if (amount > counterLimits[counter] - current) {
      this.fail('profile_limit', 'limit', path, 'The complete authority bundle exceeds its shared profile.');
    }
    this.set(counter, current + amount);
  }
  maximum(counter: BudgetCounter, value: number, path = ''): void {
    this.amount(value, path);
    if (!Object.hasOwn(counterLimits, counter)) this.fail('invalid', 'unsupported', path, 'Unknown authority counter.');
    this.charge(counter, Math.max(0, value - this.current(counter)), path);
  }
  retain(category: RetainedCategory, bytes: number, path = ''): void {
    this.amount(bytes, path);
    if (!Object.hasOwn(AUTHORITY_RETAINED_LIMITS, category)) this.fail('invalid', 'unsupported', path, 'Unknown authority representation category.');
    if (bytes > AUTHORITY_RETAINED_LIMITS[category] - this.retained[category]) {
      this.fail('profile_limit', 'limit', path, 'Retained authority representations exceed their accounted category.');
    }
    this.retained[category] += bytes;
  }
  release(category: RetainedCategory, bytes: number): void {
    this.amount(bytes, '');
    if (!Object.hasOwn(AUTHORITY_RETAINED_LIMITS, category) || bytes > this.retained[category]) {
      this.fail('invalid', 'range', '', 'Authority representation release exceeds retained bytes.');
    }
    this.retained[category] -= bytes;
  }
  retainedBytes(): Readonly<Record<RetainedCategory, number>> { return Object.freeze({ ...this.retained }); }
  snapshot(): DecisionMetrics { return Object.freeze({ ...this.metrics }); }
}

/** Bounded counting serialization of internal admitted values; no full JSON buffer.
 * Object reflection still assumes prior bounded materialization, as admission does. */
export function canonicalDecisionBytes(value: unknown, maximum: number = LIMITS.matchBytes): number {
  let bytes = 0;
  const active = new Set<object>();
  const invalid = (): never => { throw new DecisionFailure('invalid', 'type', '', 'Expected admitted canonical authority data.'); };
  function add(count: number): void {
    if (count > maximum - bytes) throw new DecisionFailure('profile_limit', 'limit', '', 'Authority representation exceeds its byte budget.');
    bytes += count;
  }
  function string(text: string): void {
    add(2);
    for (let i = 0; i < text.length; i++) {
      const c = text.charCodeAt(i);
      if (c === 34 || c === 92 || c === 8 || c === 9 || c === 10 || c === 12 || c === 13) add(2);
      else if (c < 32) add(6);
      else if (c < 128) add(1);
      else if (c < 2_048) add(2);
      else if (c >= 0xd800 && c <= 0xdbff) {
        const low = text.charCodeAt(++i); if (!(low >= 0xdc00 && low <= 0xdfff)) invalid(); add(4);
      } else { if (c >= 0xdc00 && c <= 0xdfff) invalid(); add(3); }
    }
  }
  function visit(input: unknown, depth: number): void {
    if (depth > 64) invalid();
    if (input === null) { add(4); return; }
    if (typeof input === 'boolean') { add(input ? 4 : 5); return; }
    if (typeof input === 'string') { string(input); return; }
    if (typeof input === 'number') {
      if (!Number.isSafeInteger(input) || Object.is(input, -0)) invalid(); add(String(input).length); return;
    }
    if (typeof input !== 'object' || utilTypes.isProxy(input)) invalid();
    const object = input as object;
    if (active.has(object)) invalid(); active.add(object);
    const names = Reflect.ownKeys(object);
    if (Array.isArray(object)) {
      if (Object.getPrototypeOf(object) !== Array.prototype || names.length !== object.length + 1) invalid();
      add(2);
      for (let i = 0; i < object.length; i++) {
        const descriptor = Object.getOwnPropertyDescriptor(object, String(i));
        if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) invalid();
        if (i) add(1); visit(descriptor!.value, depth + 1);
      }
    } else {
      const prototype = Object.getPrototypeOf(object);
      if (prototype !== Object.prototype && prototype !== null) invalid();
      add(2);
      for (let i = 0; i < names.length; i++) {
        const name = names[i]; if (typeof name !== 'string') invalid();
        const descriptor = Object.getOwnPropertyDescriptor(object, name!);
        if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) invalid();
        if (i) add(1); string(name as string); add(1); visit(descriptor!.value, depth + 1);
      }
    }
    active.delete(object);
  }
  if (!Number.isSafeInteger(maximum) || maximum < 0) invalid();
  visit(value, 1);
  return bytes;
}
