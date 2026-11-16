// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { evaluateAuthority } from '../../packages/authority/src/decisions.ts';
import { decisionHash } from '../../packages/authority/src/decision-schema.ts';
import { makeFieldFixture } from './fixtures/authority-field.ts';
import { makeDecisionFixture, sealDecisionFixture, id, v, type DecisionFixture } from './fixtures/authority-decision.ts';
function evaluate(f: DecisionFixture) { const r = evaluateAuthority(f.bundle, f.registry); assert.equal(r.outcome, 'evaluated', JSON.stringify(r)); return r; }
test('ordinary field derives allow from all registered prerequisites without any field grant', () => {
  for (const path of ['direct', 'registered-reference'] as const) {
    const f = makeFieldFixture(path), r = evaluate(f); assert.equal(r.root?.allowed, true); assert.equal(r.root?.derivedOrdinaryFieldAllow, true);
    assert.deepEqual(r.root?.matched, []);
    const parent = f.bundle.nodes.find(n => n.mode === 'authorize' && n.request.action === 'asset:metadata.read')!;
    f.bundle.candidates.find(c => c.nodeId === parent.id)!.candidates = [];
    // Its grant remains referenced by the parent's complete guard partition.
    const denied = evaluate(sealDecisionFixture(f)); assert.equal(denied.root?.allowed, false); assert.equal(denied.root?.reason, 'ceiling_denied');
  }
});
test('an explicit field deny wins over derived ordinary compatibility', () => {
  const f = makeFieldFixture(), root = f.bundle.nodes.find(n => n.id === f.bundle.root)!;
  const document = JSON.parse(f.bundle.policies[0].document); document.rules.push({ id: id(70), effect: 'deny', actions: ['field:read'], fields: [root.request.field], when: { op: 'subject-in', subjects: [root.subject] } });
  f.bundle.policies[0].document = JSON.stringify(document); f.bundle.grants[0].ceiling.actions.push('field:read');
  f.bundle.candidates.find(c => c.nodeId === root.id)!.candidates = [f.bundle.grants[0].ref];
  const r = evaluate(sealDecisionFixture(f)); assert.equal(r.root?.allowed, false); assert.equal(r.root?.reason, 'explicit_deny'); assert.equal(r.root?.derivedOrdinaryFieldAllow, true);
});
test('sensitive fields require explicit sensitive permission and reject backedges', () => {
  const f = makeFieldFixture('direct', true), root = f.bundle.nodes.find(n => n.id === f.bundle.root)!, sensitive = f.bundle.nodes.find(n => n.request.action === 'field:sensitive.read')!;
  const denied = evaluate(f); assert.equal(denied.root?.allowed, false); assert.equal(denied.nodes.find(n => n.nodeId === sensitive.id)?.reason, 'no_allow');
  sensitive.projection!.sensitiveDecision = root.id;
  assert.equal(evaluateAuthority(sealDecisionFixture(f).bundle, f.registry).outcome, 'invalid');
});
test('reference tuple and projection identity cannot substitute target, parent, revision, sensitivity or prerequisite', () => {
  for (const edit of [
    (f: DecisionFixture) => { f.bundle.references[0].target = { ...f.bundle.references[0].target, resource: { ...f.bundle.references[0].target.resource, id: id(999) } }; },
    (f: DecisionFixture) => { f.bundle.references[0].parent = { ...f.bundle.references[0].parent, revision: 2 as typeof v }; },
    (f: DecisionFixture) => { f.bundle.nodes.find(n => n.id === f.bundle.root)!.projection!.sensitivityRevision = '2' as typeof f.bundle.snapshot.generation; },
    (f: DecisionFixture) => { f.bundle.nodes.find(n => n.id === f.bundle.root)!.projection!.prerequisites = []; },
  ]) { const f = makeFieldFixture('registered-reference'); edit(f); sealDecisionFixture(f); assert.equal(evaluateAuthority(f.bundle, f.registry).outcome, 'invalid'); }
});
test('same field can have separately registered direct and reference projections without lookup ambiguity', () => {
  for (const path of ['direct', 'registered-reference'] as const) {
    const f = makeFieldFixture(path), first = f.registry.projections[0], other = { ...structuredClone(first), path: path === 'direct' ? 'registered-reference' as const : 'direct' as const,
      prerequisites: [{ action: 'asset:metadata.read' as const, resource: path === 'direct' ? 'reference-parent' as const : 'field-owner' as const }] };
    const { registrationHash: ignored, ...content } = other; void ignored; other.registrationHash = decisionHash(content); f.registry.projections.push(other);
    assert.equal(evaluate(sealDecisionFixture(f)).root?.allowed, true);
  }
});
test('ceiling slot identity order is deterministic across locale-sensitive Z/a order', () => {
  const f = makeDecisionFixture(), node = f.bundle.nodes[0]; f.registry.adapters[0].ceilings = [{ slot: 'a', kind: 'visibility' }, { slot: 'Z', kind: 'visibility' }];
  node.ceilingRefs = [{ slot: 'a', recordId: 'acl' }, { slot: 'Z', recordId: 'acl' }];
  f.bundle.visibility.push({ id: 'acl', resource: node.request.resource, revision: v, visibility: 'tenant', allowedIdentities: [] });
  const initial = evaluate(sealDecisionFixture(f)); f.registry.adapters[0].ceilings.reverse(); node.ceilingRefs.reverse();
  assert.deepEqual(evaluate(sealDecisionFixture(f)), initial);
});
