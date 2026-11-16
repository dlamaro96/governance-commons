// SPDX-License-Identifier: Apache-2.0
import { makeDecisionFixture, sealDecisionFixture, id, v, zero, validity, type DecisionFixture, type Mutable } from './authority-decision.ts';
import type { ServiceUse, DecisionNode, AdapterBranch } from '../../../packages/authority/src/decision-types.ts';
import type { ActionId, ServiceActionId } from '../../../packages/authority/src/actions.ts';
import type { Counter, Digest, UTC } from '../../../packages/authority/src/types.ts';
export type ServiceFixtureKind = ServiceUse['kind'];
const actions: Record<ServiceFixtureKind, ServiceActionId> = {
  dispatch: 'scan-job:dispatch', claim: 'scan-job:claim', metadata: 'source:metadata.scan', secret: 'secret:resolve', complete: 'scan-job:complete',
  fail: 'scan-job:fail', 'terminal-replay': 'scan-job:complete', 'project-consume': 'projection:consume', 'project-write': 'projection:write', audit: 'audit:append', outbox: 'outbox:append',
};
export const serviceId = id(20), assignmentRef = { id: id(22), version: v };
export const leaseValidity = { notBefore: '2026-11-16T05:59:30.000Z' as UTC, expiresAt: '2026-11-16T06:02:00.000Z' as UTC };
export function makeServiceFixture(kind: ServiceFixtureKind): DecisionFixture {
  const fixture = makeDecisionFixture(), { bundle, registry } = fixture;
  const tenantId = id(1), human = bundle.nodes[0], humanGuard = bundle.nodes[1], service = { kind: 'service' as const, id: serviceId };
  const needHuman = ['claim', 'metadata', 'secret', 'complete', 'terminal-replay', 'audit', 'outbox'].includes(kind);
  const journal = kind === 'audit' || kind === 'outbox', project = kind === 'project-consume' || kind === 'project-write';
  const source = { ref: { id: id(30), version: v }, tenantId, siteId: id(31), securityRevision: '1' as Counter,
    secretBinding: { id: id(32), version: v, sourceId: id(30), siteId: id(31) } };
  const job = { ref: { id: id(33), version: v }, tenantId, sourceId: source.ref.id, siteId: source.siteId, serviceId,
    initiatingIdentityId: id(2), requestHash: '3'.repeat(64) as Digest, generation: '1' as Counter, claimVersion: '1' as Counter,
    status: (kind === 'terminal-replay' ? 'succeeded' : ['dispatch', 'claim'].includes(kind) ? 'queued' : 'running') as 'succeeded' | 'queued' | 'running',
    deadlineAt: '2026-11-16T06:15:00.000Z' as UTC };
  const assignment = { ref: assignmentRef, tenantId, serviceId, state: 'active' as const, validity,
    actions: [actions[kind]], siteId: project || journal ? null : source.siteId, sourceId: project || journal ? null : source.ref.id,
    indexId: project ? 'catalog' : null, eventFamilies: project ? ['asset'] : [] };
  const target = { tenantId, kind: (journal || project ? 'asset' : ['metadata', 'secret'].includes(kind) ? 'source' : 'scan-job') as 'asset' | 'source' | 'scan-job',
    id: journal || project ? id(3) : ['metadata', 'secret'].includes(kind) ? source.ref.id : job.ref.id };
  for (const action of registry.actions) action.resourceKinds = ['asset', 'source', 'scan-job'];
  const originalTemplate = structuredClone(human);
  if (needHuman && !journal) {
    for (const node of [human, humanGuard]) {
      node.request = { action: 'source:scan.request', resource: { tenantId, kind: 'source', id: source.ref.id }, revision: v, field: null };
      node.resource.requestResource = node.request.resource; node.resource.containment.resource = node.request.resource;
      node.authentication = { kind: 'scan-initiator', jobId: job.ref.id, jobVersion: v, elevationSession: null };
    }
    for (const adapter of registry.adapters) { adapter.action = 'source:scan.request'; adapter.resourceKinds = ['source']; adapter.containment = 'none'; }
    registry.intentContexts[0] = { resourceKind: 'source', subjectKind: 'human', denyContextAction: 'source:scan.request', guardAdapterId: 'asset.guard' };
    const policy = JSON.parse(bundle.policies[0].document); policy.rules[0].actions = ['source:scan.request']; bundle.policies[0].document = JSON.stringify(policy);
    bundle.grants[0].ceiling.actions = ['source:scan.request']; bundle.grants[0].ceiling.resourceKinds = ['source']; bundle.sessions = [];
  }
  if (!needHuman) {
    bundle.nodes = []; bundle.candidates = []; bundle.principals = []; bundle.principalGroups = []; bundle.sessions = [];
    bundle.grants = []; bundle.policies = []; bundle.definitions = [];
  }
  const node = structuredClone(originalTemplate);
  node.id = 'a'.repeat(64) as Digest; node.intentGuard = 'b'.repeat(64) as Digest; node.subject = service;
  node.request = { action: actions[kind], resource: target, revision: v, field: null };
  node.resource.requestResource = target; node.resource.containment.resource = target; node.resource.containment.domainPath = { status: 'known', value: [] };
  node.authentication = { kind: 'service-credential', credentialId: id(21), credentialVersion: v }; node.adapterId = `service.${kind}`;
  const base = { assignment: assignmentRef };
  const initiatingDecision = human.id;
  const actionHash = '4'.repeat(64) as Digest;
  if (kind === 'dispatch') node.service = { ...base, kind, source: source.ref, job: job.ref };
  else if (kind === 'claim') node.service = { ...base, kind, source: source.ref, job: job.ref, initiatingDecision };
  else if (kind === 'metadata' || kind === 'secret' || kind === 'complete') node.service = { ...base, kind, source: source.ref, job: job.ref,
    claim: { id: id(34), version: v }, lease: { id: id(35), version: v }, initiatingDecision, requestHash: actionHash,
    secretBinding: kind === 'secret' ? { id: source.secretBinding.id, version: source.secretBinding.version } : null };
  else if (kind === 'fail') node.service = { ...base, kind, job: job.ref, requestHash: actionHash, terminalAction: 'failed' };
  else if (kind === 'terminal-replay') node.service = { ...base, kind, job: job.ref, terminal: { id: id(36), version: v }, initiatingDecision, requestHash: actionHash };
  else if (kind === 'project-consume' || kind === 'project-write') node.service = { ...base, kind, mode: 'apply', event: { id: id(37), version: v }, requestHash: actionHash };
  else node.service = { ...base, kind, claim: { id: id(38), version: v }, payloadHash: actionHash };
  const guard: Mutable<DecisionNode> = { ...structuredClone(node), id: node.intentGuard!, mode: 'resource-wide-deny', adapterId: 'service.guard', intentGuard: null, guardOrigin: node.id, service: null };
  registry.adapters.push({ ...registry.adapters[0], id: node.adapterId, action: actions[kind], branch: `service-${kind}` as AdapterBranch,
    resourceKinds: [target.kind], containment: 'none', ceilings: [] },
  { ...registry.adapters[0], id: guard.adapterId, action: actions[kind], branch: 'intent-guard', resourceKinds: [target.kind], containment: 'none', ceilings: [] });
  registry.intentContexts.push({ resourceKind: target.kind, subjectKind: 'service', denyContextAction: actions[kind], guardAdapterId: guard.adapterId });
  bundle.nodes.push(node, guard); bundle.root = node.id;
  bundle.principals.push({ kind: 'service', id: serviceId, revision: '1' as Counter, tenantId, state: 'active', validity });
  bundle.principalGroups.push({ subject: service, memberships: { status: 'known', value: [] } });
  bundle.credentials.push({ id: id(21), version: v, serviceId, tenantId, generation: '1' as Counter, state: 'active', validity });
  bundle.serviceAssignments.push(assignment);
  const policyId = id(40), grantRef = { kind: 'grant' as const, id: id(41), version: v }, scope = { kind: 'tenant' as const, tenantId };
  const pin = { policyId, version: v, hash: zero };
  bundle.policies.push({ tenantId, currentHeadVersion: v, state: 'active', pin,
    document: JSON.stringify({ formatVersion: 1, id: policyId, version: v, rules: [{ id: id(42), effect: 'allow', actions: [actions[kind]], fields: null, when: { op: 'subject-in', subjects: [service] } }] }), resourceWideIntents: [] });
  bundle.grants.push({ ref: grantRef, kind: 'service', tenantId, state: 'active', issuer: service, beneficiary: service, policies: [pin], assignment: assignmentRef,
    scope, validity, ceiling: { actions: [actions[kind]], resourceKinds: [target.kind], fields: null, scope, validity } });
  for (const current of [node, guard]) bundle.candidates.push({ nodeId: current.id, snapshotDigest: bundle.snapshot.snapshotDigest,
    subject: service, request: current.request, anchorDigest: zero, candidates: [grantRef] });
  if (!project && !journal) bundle.jobs.push(job);
  if (['dispatch', 'claim', 'metadata', 'secret', 'complete'].includes(kind)) bundle.sources.push(source);
  if (['metadata', 'secret', 'complete', 'terminal-replay'].includes(kind)) bundle.claims.push({ ref: { id: id(34), version: v }, tenantId,
    jobId: job.ref.id, sourceId: source.ref.id, siteId: source.siteId, serviceId, credentialId: id(21), credentialVersion: v,
    generation: '1' as Counter, claimVersion: '1' as Counter, requestHash: job.requestHash, state: kind === 'terminal-replay' ? 'sealed' : 'active', validity });
  if (['metadata', 'secret', 'complete'].includes(kind)) {
    registry.leaseIssuers.push({ ref: { id: id(43), version: v }, tenantId, generation: '1' as Counter, state: 'active', validity });
    bundle.leases.push({ ref: { id: id(35), version: v }, tenantId, issuer: { kind: 'gateway', registration: { id: id(43), version: v } },
      assignment: assignmentRef, audienceServiceId: serviceId, serviceId, credentialId: id(21), credentialVersion: v,
      siteId: source.siteId, sourceId: source.ref.id, jobId: job.ref.id, initiatingIdentityId: id(2), claim: { id: id(34), version: v },
      claimVersion: '1' as Counter, generation: '1' as Counter, actions: [actions[kind]], requestHash: job.requestHash,
      state: 'active', validity: leaseValidity, parentLease: null });
  }
  if (kind === 'terminal-replay') bundle.terminals.push({ ref: { id: id(36), version: v }, tenantId, jobId: job.ref.id, sourceId: source.ref.id, serviceId,
    claim: { id: id(34), version: v }, generation: '1' as Counter, action: actions[kind] as 'scan-job:complete', requestHash: actionHash, result: 'succeeded' });
  if (project) bundle.projectionEvents.push({ ref: { id: id(37), version: v }, tenantId, family: 'asset', indexId: 'catalog', resource: target,
    revision: v, securityRevision: '1' as Counter, generation: '1' as Counter, state: 'pending', requestAction: actions[kind] as 'projection:consume' | 'projection:write', requestHash: actionHash, eventHash: '5'.repeat(64) as Digest });
  if (journal) {
    bundle.operations.push({ id: id(39), version: v, tenantId, actor: human.subject, planHash: '6'.repeat(64) as Digest, requestHash: actionHash,
      state: 'prepared', validity, members: [{ key: 'asset', side: 'after', resource: target, revision: v, securityRevision: '1' as Counter, domainPath: [] }] });
    bundle.journalClaims.push({ ref: { id: id(38), version: v }, tenantId, operationId: id(39), operationVersion: v, actor: human.subject,
      executorServiceId: serviceId, generation: '1' as Counter, action: actions[kind] as 'audit:append' | 'outbox:append', resource: target,
      revision: v, payloadHash: actionHash, state: 'unconsumed', validity, parentDecisions: [human.id] });
  }
  return sealDecisionFixture(JSON.parse(JSON.stringify(fixture)) as DecisionFixture);
}
