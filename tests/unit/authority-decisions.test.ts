// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { evaluateAuthority, evaluateAuthorityFile } from '../../packages/authority/src/decisions.ts';
import { canonicalDecisionBytes } from '../../packages/authority/src/decision-budget.ts';
import { evaluatePolicyExpression, type ExpressionFacts } from '../../packages/authority/src/expressions.ts';
import type { DecisionBundleResult } from '../../packages/authority/src/decision-types.ts';
import type { PolicyRule, UTC } from '../../packages/authority/src/types.ts';
import { makeDecisionFixture, sealDecisionFixture, makeWideBindingFixture, id, now, type DecisionFixture } from './fixtures/authority-decision.ts';
import { makeFourEdgeFieldFixture, appendJournalParents, makeWideContextFixture } from './fixtures/authority-decision-chain.ts';

function evaluated(fixture: DecisionFixture): DecisionBundleResult & { root: NonNullable<DecisionBundleResult['root']> } {
  const result = evaluateAuthority(fixture.bundle, fixture.registry);
  assert.equal(result.outcome, 'evaluated', JSON.stringify(result)); assert.ok(result.root);
  assert.equal(result.metrics.outputBytes, Buffer.byteLength(JSON.stringify(result)));
  assert.equal(result.metrics.outputBytes, canonicalDecisionBytes(result));
  return result as DecisionBundleResult & { root: NonNullable<DecisionBundleResult['root']> };
}
const rule = (n: number, effect: 'allow' | 'deny', truth: 'match' | 'no-match' | 'indeterminate'): PolicyRule => ({
  id: id(100 + n), effect, actions: ['asset:metadata.read'], fields: null,
  when: truth === 'indeterminate' ? { op: 'purpose-in', ids: [id(200)] }
    : { op: 'subject-in', subjects: [{ kind: 'human', id: id(truth === 'match' ? 2 : 201) }] },
});

// Straightforward independent aggregate oracle. It deliberately does not import
// the engine's ordering, reason, memo, binding or witness helpers.
function oracle(rules: readonly PolicyRule[], facts: ExpressionFacts): { allowed: boolean; reason: string; matched: string[] } {
  const results = rules.map(entry => ({ rule: entry, truth: evaluatePolicyExpression(entry.when, facts) }));
  const matching = results.filter(result => result.truth === 'match').map(result => result.rule);
  const reason = results.some(result => result.truth === 'indeterminate') ? 'indeterminate'
    : matching.some(entry => entry.effect === 'deny') ? 'explicit_deny'
    : matching.some(entry => entry.effect === 'allow') ? 'allowed' : 'no_allow';
  return { allowed: reason === 'allowed', reason, matched: matching.map(entry => entry.id).sort() };
}

test('pure authority evaluates a complete human root and guard with exact detached output metrics', () => {
  const fixture = makeDecisionFixture(), original = JSON.stringify(fixture), result = evaluated(fixture);
  assert.equal(result.root.allowed, true); assert.equal(result.root.reason, 'allowed');
  assert.equal(result.nodes.length, 2); assert.equal(result.metrics.contexts, 2);
  assert.equal(result.metrics.dependencyEdges, 1); assert.equal(result.metrics.dependencyReferences, 2);
  assert.equal(result.metrics.dependencyDepth, 2); assert.equal(result.metrics.policyPins, 1);
  assert.equal(result.root.matched.length, 1); assert.equal(result.metrics.actualPredicateCalls, 1);
  // Subject5 + request15 + now1 JSON values/own-data properties.
  assert.equal(result.metrics.factValidationVisits, 21);
  assert.equal(JSON.stringify(fixture), original); assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.root.matched)); assert.ok(Object.isFrozen(result.root.matched[0]));
  fixture.bundle.grants[0].ref.id = id(900);
  assert.equal(result.root.matched[0].grant.id, id(14));
});

test('three-valued deny aggregation agrees with an independent oracle across every two-rule effect/truth combination', () => {
  const truth = ['match', 'no-match', 'indeterminate'] as const;
  for (const a of truth) for (const b of truth) for (const ae of ['allow', 'deny'] as const) for (const be of ['allow', 'deny'] as const) {
    const rules = [rule(0, ae, a), rule(1, be, b)], fixture = makeDecisionFixture(rules), result = evaluated(fixture);
    const node = fixture.bundle.nodes.find(row => row.id === fixture.bundle.root)!;
    const facts: ExpressionFacts = { subject: node.subject, request: node.request, now,
      groups: { status: 'known', value: [] }, requestRoles: { status: 'known', value: { subject: node.subject, request: node.request, roles: [] } },
      domainPath: { status: 'known', value: [] }, classifications: { status: 'known', value: [] }, approvedTags: { status: 'known', value: [] },
      purpose: { status: 'unavailable' }, environment: { status: 'unavailable' } };
    const expected = oracle(rules, facts);
    assert.deepEqual({ allowed: result.root.allowed, reason: result.root.reason, matched: result.root.matched.map(row => row.ruleId).sort() }, expected);
    assert.equal(result.metrics.actualRuleVisits, 4); // Both complete bindings, including the guard's inapplicable rules.
  }
});

test('all identical matching instances are retained by grant while exact predicate work is memoized', () => {
  const fixture = makeDecisionFixture([rule(0, 'allow', 'match'), rule(1, 'allow', 'match')]);
  const grant = structuredClone(fixture.bundle.grants[0]); grant.ref.id = id(15); fixture.bundle.grants.push(grant);
  for (const row of fixture.bundle.candidates) row.candidates.push(grant.ref);
  const result = evaluated(sealDecisionFixture(fixture));
  assert.equal(result.root.matched.length, 4); assert.equal(result.metrics.matchWitnesses, 4);
  assert.equal(result.metrics.actualPredicateCalls, 1); assert.equal(result.metrics.memoHits, 3);
  assert.equal(result.metrics.actualRuleVisits, 8); assert.equal(result.metrics.bindingInstances, 4);
  assert.deepEqual(new Set(result.root.matched.map(row => row.grant.id)), new Set([id(14), id(15)]));
});

test('future time predicates bound both allow and denied decisions without short-circuit loss', () => {
  const start = '2026-11-16T07:00:00.000Z' as UTC;
  const futureDeny: PolicyRule = { ...rule(1, 'deny', 'match'), when: { op: 'time-within', validity: { notBefore: start, expiresAt: null } } };
  const fixture = makeDecisionFixture([rule(0, 'allow', 'match'), futureDeny]);
  assert.equal(evaluated(fixture).root.validUntil, start); assert.equal(evaluated(fixture).root.allowed, true);
  fixture.bundle.snapshot.now = start; sealDecisionFixture(fixture);
  const denied = evaluated(fixture); assert.equal(denied.root.reason, 'explicit_deny'); assert.equal(denied.root.validUntil, null);
  const nested = makeDecisionFixture([{ ...rule(2, 'allow', 'match'), when: { op: 'any', children: [rule(0, 'allow', 'match').when, futureDeny.when] } }]);
  assert.equal(evaluated(nested).root.validUntil, start);
});

test('input order cannot change normalized identity, semantic output, work or witnesses', () => {
  const fixture = makeDecisionFixture([rule(2, 'deny', 'no-match'), rule(1, 'allow', 'match')]);
  const initial = evaluated(fixture);
  for (const rows of Object.values(fixture.bundle)) if (Array.isArray(rows)) rows.reverse();
  for (const rows of Object.values(fixture.registry)) if (Array.isArray(rows)) rows.reverse();
  assert.deepEqual(evaluated(fixture), initial);
});

test('raw companion matches object semantics but measures raw input independently', () => {
  const fixture = makeDecisionFixture(), object = evaluated(fixture);
  const raw = evaluateAuthorityFile(JSON.stringify(fixture.bundle), fixture.registry);
  assert.equal(raw.outcome, 'evaluated'); assert.deepEqual(raw.root, object.root); assert.deepEqual(raw.nodes, object.nodes);
  assert.ok(raw.metrics.admission!.rawBytes! > 0); assert.equal(object.metrics.admission!.rawBytes, null);
  const duplicate = evaluateAuthorityFile('{"formatVersion":1,"formatVersion":1}', fixture.registry);
  assert.equal(duplicate.outcome, 'invalid'); assert.equal(duplicate.root, null); assert.deepEqual(duplicate.nodes, []);
});

test('missing, extra, cyclic and altered identity evidence refuses the entire decision deterministically', () => {
  for (const edit of [
    (fixture: DecisionFixture) => { fixture.bundle.nodes.pop(); },
    (fixture: DecisionFixture) => { fixture.bundle.nodes[0].intentGuard = fixture.bundle.root; },
    (fixture: DecisionFixture) => { fixture.bundle.nodes[0].factDigest = 'f'.repeat(64) as typeof fixture.bundle.root; },
    (fixture: DecisionFixture) => { fixture.bundle.grants.push({ ...structuredClone(fixture.bundle.grants[0]), ref: { ...fixture.bundle.grants[0].ref, id: id(999) } }); },
  ]) {
    const fixture = makeDecisionFixture(); edit(fixture);
    const first = evaluateAuthority(fixture.bundle, fixture.registry), second = evaluateAuthority(fixture.bundle, fixture.registry);
    assert.equal(first.outcome, 'invalid'); assert.equal(first.root, null); assert.deepEqual(first.nodes, []); assert.deepEqual(first, second);
    assert.equal(first.metrics.outputBytes, Buffer.byteLength(JSON.stringify(first)));
  }
});

test('public entrypoints defensively admit values without invoking accessors or proxy traps', () => {
  const fixture = makeDecisionFixture(); let calls = 0;
  const hostile = Object.defineProperty({}, 'nodes', { enumerable: true, get() { calls++; throw Error('getter'); } });
  for (const bundle of [hostile, new Proxy({}, { ownKeys() { calls++; throw Error('trap'); } }), { ...fixture.bundle, issuerAllowed: true }]) {
    const result = evaluateAuthority(bundle, fixture.registry); assert.equal(result.outcome, 'invalid'); assert.equal(result.root, null); assert.deepEqual(result.nodes, []);
  }
  assert.equal(calls, 0);
});

test('four real delegation edges fit with every live issuer guard and separately protected sensitive field prerequisites', () => {
  const chain = evaluated(makeFourEdgeFieldFixture(false));
  assert.equal(chain.root.allowed, true); assert.equal(chain.metrics.contexts, 10); assert.equal(chain.metrics.dependencyDepth, 10);
  const field = evaluated(makeFourEdgeFieldFixture());
  assert.equal(field.root.allowed, true); assert.equal(field.metrics.contexts, 14); assert.equal(field.metrics.dependencyDepth, 12);
  assert.equal(field.root.derivedOrdinaryFieldAllow, false);
  assert.equal(field.root.matched.length, 1);
});

test('a real complete DAG accepts depth16 and refuses depth17 without resetting dependency budgets', () => {
  const exact = evaluated(appendJournalParents(makeFourEdgeFieldFixture(), 4));
  assert.equal(exact.root.allowed, true); assert.equal(exact.metrics.dependencyDepth, 16); assert.equal(exact.nodes.length, 22);
  const fixture = appendJournalParents(makeFourEdgeFieldFixture(), 5), over = evaluateAuthority(fixture.bundle, fixture.registry);
  assert.equal(over.outcome, 'profile_limit', JSON.stringify(over)); assert.equal(over.root, null); assert.deepEqual(over.nodes, []);
  assert.equal(over.metrics.contexts, 24); assert.equal(over.metrics.dependencyDepth, 16);
});

test('policy pins and expanded bindings share one allowance across root and guard', () => {
  assert.equal(evaluated(makeWideBindingFixture(32, 1)).metrics.policyPins, 32);
  // Assemble33 without the public construction helper's own32-pin role limit.
  const overPins = makeWideBindingFixture(32, 1), extra = structuredClone(overPins.bundle.policies[0]);
  extra.pin.policyId = id(4_100); overPins.bundle.policies.push(extra);
  const rejectedPins = evaluateAuthority(overPins.bundle, overPins.registry);
  assert.equal(rejectedPins.outcome, 'profile_limit'); assert.equal(rejectedPins.root, null);
  const exact = evaluated(makeWideBindingFixture(2, 128));
  assert.equal(exact.metrics.bindingInstances, 512); assert.equal(exact.metrics.roleInstances, 256);
  const over = makeWideBindingFixture(2, 129), rejected = evaluateAuthority(over.bundle, over.registry);
  assert.equal(rejected.outcome, 'profile_limit'); assert.equal(rejected.root, null); assert.deepEqual(rejected.nodes, []);
});

test('all65536 matching witnesses survive complete shared-budget evaluation and exact output accounting', () => {
  const fixture = makeWideBindingFixture(2, 128, 128, true), result = evaluated(fixture);
  assert.equal(result.root.allowed, false); assert.equal(result.root.matched.length, 32_768);
  assert.equal(result.nodes.reduce((sum, node) => sum + node.matched.length, 0), 65_536);
  assert.equal(result.metrics.matchWitnesses, 65_536); assert.equal(result.metrics.actualRuleVisits, 65_536);
  assert.equal(result.metrics.bindingInstances, 512); assert.equal(result.metrics.actualPredicateCalls, 1);
  assert.equal(result.metrics.memoHits, 65_535); assert.ok(result.metrics.outputBytes < 33_554_432);
});

test('a complete128-context journal fanout shares nodes and refuses the129th context', () => {
  const fixture = makeWideContextFixture(), exact = evaluated(fixture);
  assert.equal(exact.metrics.contexts, 128); assert.equal(exact.nodes.length, 128); assert.equal(exact.root.allowed, true);
  assert.equal(exact.metrics.dependencyDepth, 4);
  const extra = structuredClone(fixture.bundle.nodes.find(node => node.mode === 'authorize' && node.subject.kind === 'service' && node.id !== fixture.bundle.root)!);
  const adapter = structuredClone(fixture.registry.adapters.find(row => row.id === extra.adapterId)!);
  adapter.id = 'journal.audit.alternate'; fixture.registry.adapters.push(adapter); extra.adapterId = adapter.id;
  extra.id = 'e'.repeat(64) as typeof extra.id; fixture.bundle.nodes.push(extra);
  const partition = structuredClone(fixture.bundle.candidates.find(row => row.nodeId === fixture.bundle.nodes.find(node => node.mode === 'authorize' && node.subject.kind === 'service')!.id)!);
  partition.nodeId = extra.id; fixture.bundle.candidates.push(partition);
  const final = fixture.bundle.journalClaims[fixture.bundle.journalClaims.length - 1]; final.parentDecisions.push(extra.id);
  sealDecisionFixture(fixture);
  const over = evaluateAuthority(fixture.bundle, fixture.registry);
  assert.equal(over.outcome, 'profile_limit'); assert.equal(over.root, null); assert.deepEqual(over.nodes, []);
});

test('a denied live issuer preserves its future activation horizon and an unknown issuer contaminates a later allow', () => {
  const fixture = makeFourEdgeFieldFixture(false), start = '2026-11-16T07:00:00.000Z' as UTC;
  const policy = JSON.parse(fixture.bundle.policies[0].document);
  policy.rules[0].when = { op: 'any', children: [
    { op: 'subject-in', subjects: [fixture.bundle.nodes.find(node => node.id === fixture.bundle.root)!.subject] },
    { op: 'time-within', validity: { notBefore: start, expiresAt: null } },
  ] };
  fixture.bundle.policies[0].document = JSON.stringify(policy); sealDecisionFixture(fixture);
  const denied = evaluated(fixture); assert.equal(denied.root.allowed, false); assert.equal(denied.root.validUntil, start);
  fixture.bundle.snapshot.now = start; sealDecisionFixture(fixture); assert.equal(evaluated(fixture).root.allowed, true);
  policy.rules[0].when = { op: 'purpose-in', ids: [id(200)] };
  fixture.bundle.policies[0].document = JSON.stringify(policy); sealDecisionFixture(fixture);
  const unknown = evaluated(fixture); assert.equal(unknown.root.reason, 'indeterminate'); assert.equal(unknown.root.allowed, false);
});

test('a real journal self-cycle and a disconnected node are invalid before any decision output', () => {
  const fixture = appendJournalParents(makeDecisionFixture(), 2), claim = fixture.bundle.journalClaims[1];
  claim.parentDecisions = [fixture.bundle.root];
  const cyclic = evaluateAuthority(fixture.bundle, fixture.registry);
  assert.equal(cyclic.outcome, 'invalid'); assert.equal(cyclic.root, null); assert.deepEqual(cyclic.nodes, []);
  const disconnected = appendJournalParents(makeDecisionFixture(), 2);
  disconnected.bundle.root = disconnected.bundle.nodes.find(node => node.mode === 'authorize' && node.subject.kind === 'human')!.id;
  const rejected = evaluateAuthority(disconnected.bundle, disconnected.registry);
  assert.equal(rejected.outcome, 'invalid'); assert.equal(rejected.root, null); assert.deepEqual(rejected.nodes, []);
});

test('whole-result output exhaustion erases all otherwise matching root witnesses', () => {
  // The guard has no marked resource-wide policies in this coherent catalog;
  // all512 expanded bindings belong to the root. Its repeated root/nodes output
  // crosses32MiB even though the complete65,536 logical witnesses fit their cap.
  const fixture = makeWideBindingFixture(2, 256, 128);
  fixture.bundle.candidates.find(row => row.nodeId !== fixture.bundle.root)!.candidates = [];
  const result = evaluateAuthority(fixture.bundle, fixture.registry);
  assert.equal(result.metrics.bindingInstances, 512); assert.equal(result.metrics.matchWitnesses, 65_536);
  assert.equal(result.outcome, 'profile_limit', JSON.stringify({ outcome: result.outcome, metrics: result.metrics }));
  assert.equal(result.root, null); assert.deepEqual(result.nodes, []);
  assert.equal(result.metrics.outputBytes, Buffer.byteLength(JSON.stringify(result)));
});

test('large unknown property diagnostics stay bounded after successful physical admission', () => {
  const fixture = makeDecisionFixture();
  const result = evaluateAuthority({ ...fixture.bundle, ['x'.repeat(2_000)]: true }, fixture.registry);
  assert.equal(result.outcome, 'invalid'); assert.ok(result.issues.length > 0 && result.issues.length <= 64);
  for (const issue of result.issues) { assert.ok(issue.path.length <= 1_024); assert.ok(issue.message.length <= 256); }
});

test('conservative used-fact validation counts each wrapper once per real call, including all unknown branches', () => {
  const fixture = makeDecisionFixture([{ ...rule(0, 'allow', 'match'), when: { op: 'any', children: [
    { op: 'group-any', groupIds: [id(600)] }, { op: 'purpose-in', ids: [id(200)] },
    { op: 'purpose-in', ids: [id(201)] },
  ] } }]);
  const result = evaluated(fixture);
  assert.equal(result.root.reason, 'indeterminate'); assert.equal(result.metrics.actualPredicateCalls, 1);
  assert.equal(result.metrics.chargedPredicateNodeVisits, 4);
  // Required21 + known-empty groups6 (including array length) + unavailable purpose3.
  assert.equal(result.metrics.factValidationVisits, 30);
});

test('memo eviction recomputes complete expressions and preserves all rule/work and witness semantics', () => {
  const fixture = makeWideBindingFixture(9, 2, 128);
  for (let p = 0; p < fixture.bundle.policies.length; p++) {
    const policy = JSON.parse(fixture.bundle.policies[p].document);
    for (let r = 0; r < policy.rules.length; r++) policy.rules[r].when = {
      op: 'subject-in', subjects: [{ kind: 'human', id: p === 0 && r === 0 ? id(2) : id(10_000 + p * 128 + r) }],
    };
    fixture.bundle.policies[p].document = JSON.stringify(policy);
  }
  const result = evaluated(sealDecisionFixture(fixture));
  assert.equal(result.root.allowed, true); assert.equal(result.root.matched.length, 2);
  assert.equal(result.metrics.actualRuleVisits, 4_608); assert.equal(result.metrics.actualPredicateCalls, 2_304);
  assert.equal(result.metrics.chargedPredicateNodeVisits, 2_304); assert.equal(result.metrics.memoHits, 0);
  assert.equal(result.metrics.factValidationVisits, 2_304 * 21);
});

test('protected visibility and creator provenance is charged without treating ACL populations as authority principals', () => {
  const fixture = makeDecisionFixture(), base = evaluated(fixture), node = fixture.bundle.nodes[0];
  fixture.registry.adapters[0].ceilings = [{ slot: 'acl', kind: 'visibility' }, { slot: 'creator', kind: 'creator' }];
  node.ceilingRefs = [{ slot: 'acl', recordId: 'acl' }, { slot: 'creator', recordId: 'creator' }];
  fixture.bundle.visibility.push({ id: 'acl', resource: node.request.resource, revision: node.request.revision,
    visibility: 'restricted', allowedIdentities: [node.subject.id, ...Array.from({ length: 4_096 }, (_, n) => id(20_000 + n))] });
  fixture.bundle.creators.push({ id: 'creator', resource: node.request.resource, creator: node.subject });
  const exactBytes = canonicalDecisionBytes(fixture.bundle.visibility[0]) + canonicalDecisionBytes(fixture.bundle.creators[0]);
  const result = evaluated(sealDecisionFixture(fixture));
  assert.equal(result.root.allowed, true); assert.equal(result.metrics.proofBytes - base.metrics.proofBytes, exactBytes);
  assert.equal(result.metrics.authorityPrincipals, base.metrics.authorityPrincipals);
});

test('the complete proof subtotal accepts exactly2MiB and refuses its next byte before returning a partial allow', () => {
  const fixture = makeDecisionFixture(), baseline = evaluated(fixture).metrics.proofBytes, node = fixture.bundle.nodes[0];
  fixture.registry.adapters[0].ceilings = [{ slot: 'acl', kind: 'visibility' }];
  const record = { id: 'acl', resource: node.request.resource, revision: node.request.revision,
    visibility: 'restricted' as const, allowedIdentities: [node.subject.id] };
  fixture.bundle.visibility.push(record); node.ceilingRefs = [{ slot: 'acl', recordId: record.id }];
  // A long registered record handle changes only this proof record's serialized
  // bytes; no new principal/group/field admission limit is invented to reach it.
  record.id += 'x'.repeat(2_097_152 - baseline - canonicalDecisionBytes(record));
  node.ceilingRefs[0].recordId = record.id; sealDecisionFixture(fixture);
  const exact = evaluated(fixture); assert.equal(exact.metrics.proofBytes, 2_097_152); assert.equal(exact.root.allowed, true);
  record.id += 'x'; node.ceilingRefs[0].recordId = record.id; sealDecisionFixture(fixture);
  const over = evaluateAuthority(fixture.bundle, fixture.registry);
  assert.equal(over.outcome, 'profile_limit'); assert.equal(over.root, null); assert.deepEqual(over.nodes, []);
});
