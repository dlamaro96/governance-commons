// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { DecisionBudget, DecisionFailure, AUTHORITY_RETAINED_LIMITS, canonicalDecisionBytes } from '../../packages/authority/src/decision-budget.ts';
import { DecisionInputError, type BudgetCounter, type RetainedCategory } from '../../packages/authority/src/decision-types.ts';

const limits: Partial<Record<BudgetCounter, number>> = {
  contexts: 128, dependencyEdges: 1_024, dependencyReferences: 4_096, dependencyDepth: 16,
  policyPins: 32, policyBytes: 2_097_152, policyRules: 4_096, expressionNodes: 4_096,
  bindingInstances: 512, roleInstances: 256, originGrants: 512, delegationRecords: 1_024,
  lineageEdgeOccurrences: 3_072, authorityPrincipals: 2_048, proofBytes: 2_097_152,
  factBytes: 1_048_576, actualRuleVisits: 65_536, actualPredicateCalls: 65_536,
  chargedPredicateNodeVisits: 65_536, matchWitnesses: 65_536, outputBytes: 33_554_432,
  approvedFactIds: 4_096, catalogEntries: 16_384, catalogBytes: 131_072,
};
function limited(action: () => void): void {
  assert.throws(action, error => error instanceof DecisionInputError && error.outcome === 'profile_limit' && error.issue.code === 'limit');
}

test('decision budget enforces each exact complete-bundle limit cumulatively and atomically', () => {
  for (const [name, limit] of Object.entries(limits)) {
    const counter = name as BudgetCounter, budget = new DecisionBudget();
    budget.charge(counter, limit! - 1); budget.charge(counter, 1);
    const before = budget.snapshot();
    limited(() => budget.charge(counter, 1));
    assert.deepEqual(budget.snapshot(), before, name);
    budget.charge(counter, 0);
  }
});

test('decision depth uses maximum across paths without resetting shared contexts', () => {
  const budget = new DecisionBudget();
  budget.charge('contexts', 64); budget.maximum('dependencyDepth', 12);
  budget.charge('contexts', 64); budget.maximum('dependencyDepth', 3);
  budget.maximum('dependencyDepth', 16);
  assert.equal(budget.metrics.contexts, 128); assert.equal(budget.metrics.dependencyDepth, 16);
  limited(() => budget.maximum('dependencyDepth', 17)); limited(() => budget.charge('contexts', 1));
});

test('conservative fact validation work remains separate from AST limits', () => {
  const budget = new DecisionBudget();
  budget.charge('factValidationVisits', 67_108_864); budget.charge('memoHits', 65_537);
  assert.equal(budget.metrics.factValidationVisits, 67_108_864);
  assert.equal(budget.metrics.chargedPredicateNodeVisits, 0);
  budget.maximum('factValidationVisits', Number.MAX_SAFE_INTEGER);
  limited(() => budget.charge('factValidationVisits', 1));
});

test('retained categories account every live copy, release exactly, and cannot borrow another category', () => {
  const budget = new DecisionBudget();
  for (const [name, bytes] of Object.entries(AUTHORITY_RETAINED_LIMITS)) {
    const category = name as RetainedCategory;
    budget.retain(category, bytes); limited(() => budget.retain(category, 1));
    budget.release(category, 1); budget.retain(category, 1);
  }
  assert.equal(Object.values(budget.retainedBytes()).reduce((a, b) => a + b, 0), 67_108_864);
  budget.release('memo', AUTHORITY_RETAINED_LIMITS.memo);
  assert.throws(() => budget.release('memo', 1), DecisionFailure);
  assert.equal(budget.retainedBytes().memo, 0);
  limited(() => budget.retain('compiled', 1));
});

test('invalid accounting is refused and admission/snapshots detach caller state', () => {
  const admission = { rawBytes: null, canonicalBytes: 2, nodes: 1, depth: 1 };
  const budget = new DecisionBudget(admission), snapshot = budget.snapshot();
  admission.nodes = 100;
  assert.equal(snapshot.admission!.nodes, 1);
  assert.ok(Object.isFrozen(snapshot)); assert.ok(Object.isFrozen(snapshot.admission));
  for (const amount of [-1, -0, 0.5, Infinity, NaN, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => budget.charge('contexts', amount), DecisionFailure);
    assert.throws(() => budget.retain('memo', amount), DecisionFailure);
    assert.throws(() => budget.maximum('dependencyDepth', amount), DecisionFailure);
  }
  assert.throws(() => budget.charge('__proto__' as BudgetCounter, 1), DecisionFailure);
  assert.equal(budget.metrics.contexts, 0);
});

test('bounded canonical byte counting matches UTF-8 escaping and repeated occurrences', () => {
  const repeated = { text: 'é😀\u0000\n\\"', value: -123 };
  for (const value of [null, true, false, 0, Number.MAX_SAFE_INTEGER, repeated,
    [repeated, repeated], { z: [1, null], '😀': '\t' }, Object.assign(Object.create(null), { a: 1 })]) {
    const expected = Buffer.byteLength(JSON.stringify(value));
    assert.equal(canonicalDecisionBytes(value), expected);
    assert.equal(canonicalDecisionBytes(value, expected), expected);
    limited(() => canonicalDecisionBytes(value, expected - 1));
  }
});

test('canonical counter never executes hostile objects and rejects non-JSON representations', () => {
  let called = 0;
  const accessor = Object.defineProperty({}, 'x', { enumerable: true, get() { called++; return 1; } });
  const proxy = new Proxy({}, { ownKeys() { called++; throw Error('executed'); } });
  const cycle: unknown[] = []; cycle.push(cycle);
  const hidden = Object.defineProperty({}, 'x', { value: 1 });
  for (const value of [accessor, proxy, cycle, hidden, new Date(), [, 1], { x: undefined }, { x: '\ud800' }, -0, 1.5,
    Object.assign([], { extra: 1 }), { [Symbol('x')]: 1 }]) assert.throws(() => canonicalDecisionBytes(value), DecisionFailure);
  assert.equal(called, 0);
});

test('typed failures bound private diagnostic strings and retain the shared error identity', () => {
  const error = new DecisionFailure('invalid', 'scope', 'x'.repeat(1_025), 'y'.repeat(257));
  assert.ok(error instanceof DecisionInputError); assert.equal(error.issue.path, '');
  assert.ok(error.issue.message.length <= 256); assert.ok(Object.isFrozen(error.issue));
});
