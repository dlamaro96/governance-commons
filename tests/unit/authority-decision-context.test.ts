// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { evaluateAuthority } from '../../packages/authority/src/decisions.ts';
import { makeDecisionFixture, sealDecisionFixture, id, v, validity, type DecisionFixture } from './fixtures/authority-decision.ts';
import { makeServiceFixture, type ServiceFixtureKind } from './fixtures/authority-service.ts';
import type { Counter, UTC } from '../../packages/authority/src/types.ts';
function evaluate(f: DecisionFixture) { return evaluateAuthority(f.bundle, f.registry); }
function allowed(f: DecisionFixture) {
  const result = evaluate(f); assert.equal(result.outcome, 'evaluated', JSON.stringify(result));
  assert.equal(result.root?.allowed, true, JSON.stringify(result)); return result;
}
function refused(f: DecisionFixture) { const result = evaluate(f); assert.notEqual(result.root?.allowed, true, JSON.stringify(result)); return result; }
const branches: ServiceFixtureKind[] = ['dispatch', 'claim', 'metadata', 'secret', 'complete', 'fail', 'terminal-replay', 'project-consume', 'project-write', 'audit', 'outbox'];
for (const kind of branches) test(`service ${kind} evaluates real parser, complete current context and policy`, () => { allowed(makeServiceFixture(kind)); });
test('every service branch rejects another assignment action, credential generation and tenant', () => {
  for (const kind of branches) for (const edit of [
    (f: DecisionFixture) => { f.bundle.serviceAssignments[0].actions = []; },
    (f: DecisionFixture) => { f.bundle.credentials[0].generation = '2' as Counter; },
    (f: DecisionFixture) => { f.bundle.credentials[0].tenantId = id(999); },
  ]) { const f = makeServiceFixture(kind); edit(f); refused(sealDecisionFixture(f)); }
});
test('metadata, secret and completion reject exact claim, lease, source, audience and original request substitution', () => {
  for (const kind of ['metadata', 'secret', 'complete'] as const) for (const edit of [
    (f: DecisionFixture) => { f.bundle.claims[0].claimVersion = '2' as Counter; },
    (f: DecisionFixture) => { f.bundle.leases[0].audienceServiceId = id(999); },
    (f: DecisionFixture) => { f.bundle.leases[0].sourceId = id(999); },
    (f: DecisionFixture) => { f.bundle.leases[0].requestHash = 'f'.repeat(64) as typeof f.bundle.root; },
    (f: DecisionFixture) => { f.bundle.leases[0].validity.expiresAt = '2026-11-16T06:03:00.000Z' as UTC; },
    (f: DecisionFixture) => { f.bundle.claims[0].state = 'sealed'; },
    (f: DecisionFixture) => { f.registry.leaseIssuers[0].state = 'revoked'; },
    (f: DecisionFixture) => { f.bundle.jobs[0].status = 'queued'; },
  ]) { const f = makeServiceFixture(kind); edit(f); refused(sealDecisionFixture(f)); }
});
test('initiator current denial prevents claim/content/completion but safe fail has no initiator or lease dependency', () => {
  for (const kind of ['claim', 'metadata', 'secret', 'complete', 'terminal-replay'] as const) {
    const f = makeServiceFixture(kind); const p = f.bundle.principals.find(p => p.kind === 'human')!;
    if (p.kind === 'human') p.active = false;
    const result = refused(sealDecisionFixture(f)); assert.equal(result.outcome, 'evaluated');
  }
  const f = makeServiceFixture('fail'); f.bundle.jobs[0].deadlineAt = '2026-11-16T05:00:00.000Z' as UTC;
  allowed(sealDecisionFixture(f)); assert.equal(f.bundle.leases.length, 0); assert.equal(f.bundle.nodes.length, 2);
});
test('journal claims bind all parents, actor, payload, operation and one-use state', () => {
  for (const kind of ['audit', 'outbox'] as const) for (const edit of [
    (f: DecisionFixture) => { f.bundle.journalClaims[0].state = 'consumed'; },
    (f: DecisionFixture) => { f.bundle.journalClaims[0].payloadHash = 'f'.repeat(64) as typeof f.bundle.root; },
    (f: DecisionFixture) => { f.bundle.journalClaims[0].actor = { kind: 'human', id: id(999) }; },
    (f: DecisionFixture) => { f.bundle.journalClaims[0].parentDecisions = [f.bundle.nodes.find(n => n.mode === 'resource-wide-deny' && n.subject.kind === 'human')!.id]; },
    (f: DecisionFixture) => { const human = f.bundle.principals.find(p => p.kind === 'human')!; if (human.kind === 'human') human.active = false; },
  ]) { const f = makeServiceFixture(kind); edit(f); refused(sealDecisionFixture(f)); }
});
test('visibility and creator ceiling slots cannot be omitted, swapped or bypassed by a matching policy', () => {
  const f = makeDecisionFixture(), node = f.bundle.nodes[0];
  f.registry.adapters[0].ceilings = [{ slot: 'acl', kind: 'visibility' }, { slot: 'creator', kind: 'creator' }];
  node.ceilingRefs = [{ slot: 'acl', recordId: 'acl' }, { slot: 'creator', recordId: 'creator' }];
  f.bundle.visibility.push({ id: 'acl', resource: node.request.resource, revision: v, visibility: 'restricted', allowedIdentities: [id(2)] });
  f.bundle.creators.push({ id: 'creator', resource: node.request.resource, creator: node.subject });
  allowed(sealDecisionFixture(f));
  f.bundle.visibility[0].allowedIdentities = []; assert.equal(refused(sealDecisionFixture(f)).root?.reason, 'ceiling_denied');
  f.bundle.visibility[0].allowedIdentities = [id(2)]; f.bundle.creators[0].creator = { kind: 'human', id: id(999) };
  assert.equal(refused(sealDecisionFixture(f)).root?.reason, 'ceiling_denied');
  node.ceilingRefs.pop(); assert.equal(refused(f).outcome, 'invalid');
});
test('future and expired authenticated sessions have exact exclusive horizons and required-expiry reason', () => {
  const f = makeDecisionFixture(); f.bundle.sessions[0].validity = { ...validity, expiresAt: '2026-11-16T06:01:00.000Z' as UTC };
  assert.equal(allowed(sealDecisionFixture(f)).root?.validUntil, '2026-11-16T06:01:00.000Z');
  f.bundle.snapshot.now = '2026-11-16T06:01:00.000Z' as UTC;
  assert.equal(refused(sealDecisionFixture(f)).root?.reason, 'expired');
});

test('approved facts include future boundaries and reject another field, security revision or producer kind', () => {
  const build = () => {
    const f = makeDecisionFixture([{ id: id(11), effect: 'allow', actions: ['asset:metadata.read'], fields: null,
      when: { op: 'classification-any', ids: [id(204)] } }]);
    const resource = f.bundle.nodes[0].request.resource, producer = { id: id(200), version: v }, ref = { id: id(201), version: v };
    f.registry.producers.push({ ref: producer, kind: 'classifications', tenantId: id(1), state: 'active', validity: { ...validity, expiresAt: '2026-11-16T06:05:00.000Z' as UTC } });
    f.bundle.approvedFacts.push({ ref, kind: 'classifications', provenance: { producer, tenantId: id(1), registryDigest: f.registry.digest,
      sourceRecordId: id(202), sourceRecordVersion: v }, resource, revision: v, fieldId: null, securityRevision: '1' as Counter,
      state: 'approved', validity: { notBefore: '2026-11-16T06:01:00.000Z' as UTC, expiresAt: null }, values: [id(204)] });
    for (const node of f.bundle.nodes) node.resource.classifications = { status: 'known', value: [ref] };
    return sealDecisionFixture(f);
  };
  const f = build(), result = refused(f); assert.equal(result.root?.reason, 'no_allow'); assert.equal(result.root?.validUntil, '2026-11-16T06:01:00.000Z');
  f.bundle.snapshot.now = '2026-11-16T06:01:00.000Z' as UTC;
  assert.equal(allowed(sealDecisionFixture(f)).root?.validUntil, '2026-11-16T06:05:00.000Z');
  for (const edit of [
    (x: DecisionFixture) => { x.bundle.approvedFacts[0].securityRevision = '2' as Counter; },
    (x: DecisionFixture) => { x.registry.producers[0].kind = 'approved-tags'; },
    (x: DecisionFixture) => { x.bundle.approvedFacts[0].fieldId = 'asset.description' as typeof x.registry.fields[number]; x.registry.fields.push(x.bundle.approvedFacts[0].fieldId!); },
  ]) { const x = build(); edit(x); assert.equal(refused(sealDecisionFixture(x)).outcome, 'invalid'); }
});

test('selected purpose binds exact request and guard origin while invalid context still retains producer start horizon', async () => {
  const { decisionHash } = await import('../../packages/authority/src/decision-schema.ts');
  const f = makeDecisionFixture([{ id: id(11), effect: 'allow', actions: ['asset:metadata.read'], fields: null,
    when: { op: 'purpose-in', ids: [id(213)] } }]), node = f.bundle.nodes[0];
  const producer = { id: id(210), version: v }, ref = { id: id(211), version: v };
  f.registry.producers.push({ ref: producer, kind: 'purpose', tenantId: id(1), state: 'active', validity });
  f.bundle.contextFacts.push({ ref, kind: 'purpose', provenance: { producer, tenantId: id(1), registryDigest: f.registry.digest,
    sourceRecordId: id(212), sourceRecordVersion: v }, subject: node.subject, request: structuredClone(node.request),
    containmentDigest: decisionHash(node.resource.containment), state: 'approved', validity, value: id(213) });
  for (const n of f.bundle.nodes) n.purpose = { status: 'known', value: ref };
  allowed(sealDecisionFixture(f));
  f.bundle.contextFacts[0].validity = { notBefore: null, expiresAt: '2026-11-16T05:59:00.000Z' as UTC };
  f.registry.producers[0].validity = { notBefore: '2026-11-16T06:01:00.000Z' as UTC, expiresAt: null };
  const denied = refused(sealDecisionFixture(f)); assert.equal(denied.root?.reason, 'indeterminate'); assert.equal(denied.root?.validUntil, '2026-11-16T06:01:00.000Z');
  f.bundle.contextFacts[0].request.action = 'asset:description.edit';
  assert.equal(refused(sealDecisionFixture(f)).outcome, 'invalid');
});

test('worker child leases retain the root job/claim and attenuate audience, credential, actions and validity', () => {
  const build = () => {
    const f = makeServiceFixture('metadata'), parent = f.bundle.leases[0], worker = id(50), credential = { id: id(51), version: v }, assignment = { id: id(52), version: v };
    f.bundle.principals.push({ kind: 'service', id: worker, tenantId: id(1), revision: '1' as Counter, state: 'active', validity });
    // Root service is provenance of the parent lease; only the worker is a decision subject.
    f.bundle.principalGroups = f.bundle.principalGroups.filter(p => p.subject.kind === 'human');
    f.bundle.principalGroups.push({ subject: { kind: 'service', id: worker }, memberships: { status: 'known', value: [] } });
    f.bundle.credentials.push({ ...structuredClone(f.bundle.credentials[0]), ...credential, serviceId: worker });
    f.bundle.serviceAssignments.push({ ...structuredClone(f.bundle.serviceAssignments[0]), ref: assignment, serviceId: worker });
    const child = { ...structuredClone(parent), ref: { id: id(53), version: v }, assignment, audienceServiceId: worker, serviceId: worker,
      credentialId: credential.id, credentialVersion: credential.version, parentLease: parent.ref,
      issuer: { kind: 'parent-service' as const, serviceId: parent.serviceId, credential: { id: parent.credentialId, version: parent.credentialVersion }, assignment: parent.assignment },
      validity: { notBefore: '2026-11-16T05:59:45.000Z' as UTC, expiresAt: '2026-11-16T06:01:30.000Z' as UTC } };
    f.bundle.leases.push(child);
    for (const node of f.bundle.nodes.filter(n => n.subject.kind === 'service')) {
      node.subject = { kind: 'service', id: worker }; node.authentication = { kind: 'service-credential', credentialId: credential.id, credentialVersion: credential.version };
      if (node.service?.kind === 'metadata') { node.service.assignment = assignment; node.service.lease = child.ref; }
    }
    const grant = f.bundle.grants.find(g => g.kind === 'service')!;
    if (grant.kind === 'service') { grant.beneficiary = { kind: 'service', id: worker }; grant.assignment = assignment; }
    const policy = f.bundle.policies.find(p => p.pin.policyId === id(40))!, document = JSON.parse(policy.document);
    document.rules[0].when.subjects = [{ kind: 'service', id: worker }]; policy.document = JSON.stringify(document);
    return sealDecisionFixture(f);
  };
  const f = build(); assert.equal(allowed(f).root?.validUntil, '2026-11-16T06:01:30.000Z');
  for (const edit of [
    (x: DecisionFixture) => { x.bundle.leases[1].validity.expiresAt = '2026-11-16T06:02:01.000Z' as UTC; },
    (x: DecisionFixture) => { x.bundle.leases[1].actions.push('secret:resolve'); },
    (x: DecisionFixture) => { x.bundle.credentials[0].state = 'revoked'; },
    (x: DecisionFixture) => { x.bundle.serviceAssignments[0].state = 'revoked'; },
    (x: DecisionFixture) => { const lease = x.bundle.leases[1]; if (lease.issuer.kind === 'parent-service') lease.issuer.assignment = x.bundle.serviceAssignments[1].ref; },
    (x: DecisionFixture) => { x.bundle.leases[1].audienceServiceId = id(999); },
    (x: DecisionFixture) => { x.bundle.leases[1].claimVersion = '2' as Counter; },
    (x: DecisionFixture) => { x.bundle.serviceAssignments[1].sourceId = id(999); },
  ]) { const x = build(); edit(x); refused(sealDecisionFixture(x)); }
});

test('proposed and original-scope four-edge decisions preserve command actor instead of replacing it with issuers', async () => {
  const { makeFourEdgeFieldFixture } = await import('./fixtures/authority-decision-chain.ts');
  for (const context of ['proposed', 'original-scope'] as const) {
    const f = makeFourEdgeFieldFixture(false), root = f.bundle.nodes.find(n => n.id === f.bundle.root)!;
    const operation = { id: id(220), version: v, tenantId: id(1), actor: root.subject, planHash: '7'.repeat(64) as typeof f.bundle.root,
      requestHash: '8'.repeat(64) as typeof f.bundle.root, state: 'prepared' as const, validity,
      members: [{ key: 'moving-asset', side: context === 'proposed' ? 'after' as const : 'original' as const,
        resource: root.request.resource, revision: v, securityRevision: '1' as Counter, domainPath: [id(221)] }] };
    f.bundle.operations.push(operation);
    for (const node of f.bundle.nodes) {
      node.resource.containment.context = context; node.resource.containment.domainPath = { status: 'known', value: [id(221)] };
      node.resource.containment.operation = { operationId: operation.id, version: v, planHash: operation.planHash, memberKey: 'moving-asset', side: operation.members[0].side };
    }
    allowed(sealDecisionFixture(f));
    f.bundle.operations[0].actor = { kind: 'human', id: id(999) };
    assert.equal(refused(sealDecisionFixture(f)).outcome, 'invalid');
  }
});

test('projector and terminal replay reject stale event/security/request/result or a reopened completion claim', () => {
  for (const kind of ['project-consume', 'project-write'] as const) for (const edit of [
    (f: DecisionFixture) => { f.bundle.projectionEvents[0].securityRevision = '2' as Counter; },
    (f: DecisionFixture) => { f.bundle.projectionEvents[0].family = 'different'; },
    (f: DecisionFixture) => { f.bundle.projectionEvents[0].generation = '2' as Counter; },
  ]) { const f = makeServiceFixture(kind); edit(f); assert.equal(refused(sealDecisionFixture(f)).outcome, 'invalid'); }
  for (const edit of [
    (f: DecisionFixture) => { f.bundle.terminals[0].requestHash = 'f'.repeat(64) as typeof f.bundle.root; },
    (f: DecisionFixture) => { f.bundle.terminals[0].result = 'failed'; },
    (f: DecisionFixture) => { f.bundle.claims[0].state = 'active'; },
  ]) { const f = makeServiceFixture('terminal-replay'); edit(f); assert.equal(refused(sealDecisionFixture(f)).outcome, 'invalid'); }
});

test('applied projection events require exact registered idempotent replay and immutable action request', () => {
  for (const kind of ['project-consume', 'project-write'] as const) {
    const f = makeServiceFixture(kind); f.bundle.projectionEvents[0].state = 'applied';
    assert.equal(refused(sealDecisionFixture(f)).root?.reason, 'ceiling_denied');
    const root = f.bundle.nodes.find(n => n.id === f.bundle.root)!;
    assert.ok(root.service?.kind === 'project-consume' || root.service?.kind === 'project-write'); root.service.mode = 'replay';
    allowed(sealDecisionFixture(f)); root.service.requestHash = 'f'.repeat(64) as typeof f.bundle.root;
    assert.equal(refused(sealDecisionFixture(f)).outcome, 'invalid');
  }
});

test('service ordinary fields keep the exact worker closure and actual non-field entitlement', async () => {
  const { decisionHash } = await import('../../packages/authority/src/decision-schema.ts');
  const f = makeServiceFixture('metadata'), parent = f.bundle.nodes.find(n => n.id === f.bundle.root)!;
  const fieldId = 'source.schema' as typeof f.registry.fields[number], projectionId = 'source.scan' as typeof f.registry.projections[number]['projectionId'];
  f.registry.fields.push(fieldId);
  const registration = { projectionId, version: v, fieldId, resourceKind: 'source' as const, path: 'direct' as const,
    prerequisites: [{ action: 'source:metadata.scan' as const, resource: 'field-owner' as const }] };
  f.registry.projections.push({ ...registration, registrationHash: decisionHash(registration) });
  f.registry.adapters.push({ ...structuredClone(f.registry.adapters.find(a => a.id === parent.adapterId)!), id: 'source.field', action: 'field:read', branch: 'field' });
  const field = { ...structuredClone(parent), id: 'a'.repeat(64) as typeof parent.id, intentGuard: 'b'.repeat(64) as typeof parent.id,
    adapterId: 'source.field', request: { ...parent.request, action: 'field:read' as const, field: fieldId },
    projection: { ...registration, registrationHash: decisionHash(registration), resource: parent.request.resource, revision: v,
      sensitivityRevision: parent.resource.containment.securityRevision, sensitivity: 'ordinary' as const, prerequisites: [parent.id],
      sensitiveDecision: null, path: { kind: 'direct' as const } } };
  // The registry prerequisite declaration belongs only to the registration.
  const { resourceKind: ignored, ...projection } = field.projection; void ignored; field.projection = projection as typeof field.projection;
  const guard = { ...structuredClone(field), id: field.intentGuard!, mode: 'resource-wide-deny' as const, adapterId: 'service.guard',
    request: { ...parent.request }, projection: null, service: null, intentGuard: null, guardOrigin: field.id };
  f.bundle.nodes.push(field, guard);
  for (const node of [field, guard]) f.bundle.candidates.push({ nodeId: node.id, snapshotDigest: f.bundle.snapshot.snapshotDigest,
    subject: node.subject, request: node.request, anchorDigest: '0'.repeat(64) as typeof parent.id, candidates: [] });
  f.bundle.root = field.id; const result = allowed(sealDecisionFixture(f)); assert.equal(result.root?.derivedOrdinaryFieldAllow, true);
  const currentField = f.bundle.nodes.find(n => n.id === f.bundle.root)!; assert.ok(currentField.service?.kind === 'metadata');
  currentField.service.requestHash = 'f'.repeat(64) as typeof parent.id;
  assert.equal(refused(sealDecisionFixture(f)).outcome, 'invalid');
});

test('claim and safe-failure terminal replay retain narrow current-service checks without completion authority', () => {
  for (const action of ['scan-job:claim', 'scan-job:fail'] as const) {
    const f = makeServiceFixture('fail'), root = f.bundle.nodes.find(n => n.id === f.bundle.root)!;
    assert.ok(root.service?.kind === 'fail'); const prior = root.service;
    root.service = { kind: 'terminal-replay', assignment: prior.assignment, job: prior.job, terminal: { id: id(250), version: v }, initiatingDecision: null, requestHash: prior.requestHash };
    for (const node of f.bundle.nodes) node.request.action = action;
    for (const adapter of f.registry.adapters.filter(a => a.id.startsWith('service.'))) { adapter.action = action; if (adapter.branch !== 'intent-guard') adapter.branch = 'service-terminal-replay'; }
    f.registry.intentContexts.find(c => c.subjectKind === 'service')!.denyContextAction = action;
    f.bundle.serviceAssignments[0].actions = [action]; f.bundle.grants[0].ceiling.actions = [action];
    const document = JSON.parse(f.bundle.policies[0].document); document.rules[0].actions = [action]; f.bundle.policies[0].document = JSON.stringify(document);
    f.bundle.jobs[0].status = 'failed';
    f.bundle.terminals.push({ ref: { id: id(250), version: v }, tenantId: id(1), jobId: prior.job.id, sourceId: f.bundle.jobs[0].sourceId,
      serviceId: root.subject.id, claim: null, generation: '1' as Counter, action, requestHash: prior.requestHash, result: 'failed' });
    allowed(sealDecisionFixture(f)); f.bundle.credentials[0].state = 'revoked'; refused(sealDecisionFixture(f));
  }
});
