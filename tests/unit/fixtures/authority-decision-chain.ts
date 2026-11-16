// SPDX-License-Identifier: Apache-2.0
import { decisionHash } from '../../../packages/authority/src/decision-schema.ts';
import type { AuthorityGrant, DecisionNode, ProjectionFieldRegistration } from '../../../packages/authority/src/decision-types.ts';
import type { Digest, FieldId, ProjectionId, Counter } from '../../../packages/authority/src/types.ts';
import { makeDecisionFixture, sealDecisionFixture, id, v, zero, validity, type DecisionFixture, type Mutable } from './authority-decision.ts';
const temporary = (n: number): Digest => n.toString(16).padStart(64, '0') as Digest;
/** Complete four-edge lineage with a full live issuer decision and deny guard
 * at every edge. FIELD authority is separately held, never delegated. */
export function makeFourEdgeFieldFixture(includeField = true): DecisionFixture {
  const fixture = makeDecisionFixture([{ id: id(11), effect: 'allow', actions: ['asset:metadata.read'], fields: null,
    when: { op: 'action-in', actions: ['asset:metadata.read'] } }]);
  const { bundle, registry } = fixture, root = bundle.nodes.find(row => row.mode === 'authorize')!, guard = bundle.nodes.find(row => row.mode === 'resource-wide-deny')!;
  const origin = bundle.grants[0] as Mutable<Extract<AuthorityGrant, { kind: 'ordinary-role' }>>;
  const people = [0, 1, 2, 3].map(n => ({ kind: 'human' as const, id: id(1_000 + n) })); people.push(root.subject as typeof people[number]);
  origin.issuer = people[0]; origin.beneficiary = people[0]; origin.delegable = { actions: ['asset:metadata.read'], fields: null,
    scope: origin.scope, validity, remainingDepth: 4 };
  for (let n = 0; n < 4; n++) {
    bundle.principals.push({ kind: 'human', id: people[n].id, identityRevision: '1' as Counter, active: true,
      membership: { ref: { id: id(1_100 + n), version: v }, tenantId: bundle.snapshot.tenantId, identityId: people[n].id, state: 'active', validity } });
    bundle.principalGroups.push({ subject: people[n], memberships: { status: 'known', value: [] } });
    const previous = bundle.grants[n];
    bundle.grants.push({ kind: 'delegation', ref: { kind: 'delegation', id: id(1_200 + n), version: v },
      parent: previous.ref, tenantId: origin.tenantId, state: 'active', issuer: people[n], beneficiary: people[n + 1],
      scope: origin.scope, validity, ceiling: origin.ceiling,
      delegable: n === 3 ? null : { ...origin.delegable, remainingDepth: 3 - n } });
  }
  const issuers: Mutable<DecisionNode>[] = [];
  for (let n = 0; n < 4; n++) {
    const authorize: Mutable<DecisionNode> = { ...structuredClone(root), id: temporary(2_000 + n * 2), subject: people[n],
      authentication: { kind: 'live-issuer', childGrant: bundle.grants[n + 1].ref, elevationSession: null }, intentGuard: temporary(2_001 + n * 2) };
    const deny: Mutable<DecisionNode> = { ...structuredClone(guard), id: authorize.intentGuard!, subject: people[n],
      authentication: authorize.authentication, guardOrigin: authorize.id };
    issuers.push(authorize); bundle.nodes.push(authorize, deny);
    for (const node of [authorize, deny]) bundle.candidates.push({ nodeId: node.id, snapshotDigest: bundle.snapshot.snapshotDigest,
      subject: node.subject, request: node.request, anchorDigest: zero, candidates: [bundle.grants[n].ref] });
  }
  for (const partition of bundle.candidates.slice(0, 2)) partition.candidates = [bundle.grants[4].ref];
  function links(node: Mutable<DecisionNode>, edges: number): void {
    for (let n = 1; n <= edges; n++) bundle.chainLinks.push({ nodeId: node.id, child: bundle.grants[n].ref,
      parent: bundle.grants[n - 1].ref, issuerDecision: issuers[n - 1].id, viaMembership: null });
  }
  links(root, 4); links(guard, 4);
  for (let n = 0; n < issuers.length; n++) {
    links(issuers[n], n); links(bundle.nodes.find(node => node.id === issuers[n].intentGuard)!, n);
  }
  if (includeField) {
    const field = 'asset.description' as FieldId, projectionId = 'asset.detail' as ProjectionId;
    registry.fields.push(field);
    const content = { projectionId, version: v, fieldId: field, resourceKind: 'asset' as const, path: 'direct' as const,
      prerequisites: [{ action: 'asset:metadata.read' as const, resource: 'field-owner' as const }] };
    const registration: ProjectionFieldRegistration = { ...content, registrationHash: decisionHash(content) };
    registry.projections.push(registration as Mutable<ProjectionFieldRegistration>);
    for (const action of ['field:read', 'field:sensitive.read'] as const) registry.adapters.push({ ...structuredClone(registry.adapters[0]),
      id: action, action, branch: 'field' });
    const policy = { formatVersion: 1, id: id(1_300), version: v, rules: [{ id: id(1_301), effect: 'allow',
      actions: ['field:read', 'field:sensitive.read'], fields: [field], when: { op: 'subject-in', subjects: [root.subject] } }] };
    const pin = { policyId: policy.id, version: v, hash: zero };
    bundle.policies.push({ tenantId: origin.tenantId, currentHeadVersion: v, state: 'active', pin, document: JSON.stringify(policy), resourceWideIntents: [] });
    bundle.definitions.push({ formatVersion: 1, kind: 'role', id: id(1_302), version: v, tenantId: origin.tenantId, currentHeadVersion: v,
      state: 'active', hash: zero, content: { metadata: { key: 'protected_field', label: 'Protected field', description: '' }, policies: [pin] } });
    const fieldGrant: Mutable<AuthorityGrant> = { ...structuredClone(origin), ref: { kind: 'grant', id: id(1_303), version: v },
      beneficiary: root.subject as typeof people[number], role: { roleId: id(1_302), version: v }, delegable: null,
      ceiling: { ...origin.ceiling, actions: ['field:read', 'field:sensitive.read'], fields: [field] } };
    bundle.grants.push(fieldGrant);
    const projection = { projectionId, version: v, registrationHash: registration.registrationHash, fieldId: field,
      resource: root.request.resource, revision: v, sensitivityRevision: '1' as Counter, sensitivity: 'sensitive' as const,
      prerequisites: [root.id], sensitiveDecision: temporary(2_102), path: { kind: 'direct' as const } };
    const fieldRead: Mutable<DecisionNode> = { ...structuredClone(root), id: temporary(2_100), adapterId: 'field:read',
      request: { ...root.request, action: 'field:read', field }, projection, intentGuard: temporary(2_101) };
    const sensitive: Mutable<DecisionNode> = { ...structuredClone(fieldRead), id: temporary(2_102), adapterId: 'field:sensitive.read',
      request: { ...fieldRead.request, action: 'field:sensitive.read' }, projection: { ...projection, sensitiveDecision: null }, intentGuard: temporary(2_103) };
    for (const node of [fieldRead, sensitive]) {
      const deny: Mutable<DecisionNode> = { ...structuredClone(guard), id: node.intentGuard!, guardOrigin: node.id };
      bundle.nodes.push(node, deny); links(deny, 4);
      bundle.candidates.push({ nodeId: node.id, snapshotDigest: bundle.snapshot.snapshotDigest, subject: node.subject,
        request: node.request, anchorDigest: zero, candidates: [fieldGrant.ref] });
      bundle.candidates.push({ nodeId: deny.id, snapshotDigest: bundle.snapshot.snapshotDigest, subject: deny.subject,
        request: deny.request, anchorDigest: zero, candidates: [bundle.grants[4].ref] });
    }
    bundle.root = fieldRead.id;
  }
  return sealDecisionFixture(fixture);
}

/** Add real, separately claimed journal effects. Each consumes the preceding
 * exact actor decision; guards retain provenance without a false back-edge. */
export function appendJournalParents(fixture: DecisionFixture, count: number): DecisionFixture {
  const { bundle, registry } = fixture, tenantId = bundle.snapshot.tenantId;
  const service = { kind: 'service' as const, id: id(3_000) }, assignment = { id: id(3_001), version: v };
  const credential = { id: id(3_002), version: v };
  const template = structuredClone(bundle.nodes.find(row => row.id === bundle.root)!);
  const adapter = { version: v, action: 'audit:append' as const, resourceKinds: ['asset' as const], containment: 'asset-placement' as const,
    ceilings: [], dependencyElevation: 'forbidden' as const, ceilingFailure: 'ceiling_denied' as const };
  registry.adapters.push({ ...adapter, id: 'journal.audit', branch: 'service-audit' }, { ...adapter, id: 'journal.guard', branch: 'intent-guard' });
  registry.intentContexts.push({ resourceKind: 'asset', subjectKind: 'service', denyContextAction: 'audit:append', guardAdapterId: 'journal.guard' });
  bundle.principals.push({ kind: 'service', id: service.id, revision: '1' as Counter, tenantId, state: 'active', validity });
  bundle.principalGroups.push({ subject: service, memberships: { status: 'known', value: [] } });
  bundle.credentials.push({ ...credential, serviceId: service.id, tenantId, generation: '1' as Counter, state: 'active', validity });
  bundle.serviceAssignments.push({ ref: assignment, tenantId, serviceId: service.id, state: 'active', validity,
    actions: ['audit:append'], siteId: null, sourceId: null, indexId: null, eventFamilies: [] });
  const policy = { formatVersion: 1, id: id(3_003), version: v, rules: [{ id: id(3_004), effect: 'allow', actions: ['audit:append'],
    fields: null, when: { op: 'subject-in', subjects: [service] } }] };
  const pin = { policyId: policy.id, version: v, hash: zero };
  bundle.policies.push({ tenantId, currentHeadVersion: v, state: 'active', pin, document: JSON.stringify(policy), resourceWideIntents: [] });
  const scope = { kind: 'tenant' as const, tenantId }, grantRef = { kind: 'grant' as const, id: id(3_005), version: v };
  bundle.grants.push({ ref: grantRef, kind: 'service', tenantId, state: 'active', issuer: service, beneficiary: service,
    policies: [pin], assignment, scope, validity, ceiling: { actions: ['audit:append'], resourceKinds: ['asset'], fields: null, scope, validity } });
  for (let n = 0; n < count; n++) {
    const parent = bundle.nodes.find(row => row.id === bundle.root)!;
    const claim = { id: id(3_100 + n), version: v }, operationId = id(3_200 + n);
    bundle.operations.push({ id: operationId, version: v, tenantId, actor: parent.subject, planHash: zero, requestHash: zero,
      state: 'prepared', validity, members: [] });
    bundle.journalClaims.push({ ref: claim, tenantId, operationId, operationVersion: v, actor: parent.subject,
      executorServiceId: service.id, generation: '1' as Counter, action: 'audit:append', resource: template.request.resource,
      revision: template.request.revision, payloadHash: zero, state: 'unconsumed', validity, parentDecisions: [parent.id] });
    const authorize: Mutable<DecisionNode> = { ...structuredClone(template), id: temporary(3_300 + 2 * n), mode: 'authorize', subject: service,
      request: { ...template.request, action: 'audit:append', field: null }, projection: null, adapterId: 'journal.audit',
      authentication: { kind: 'service-credential', credentialId: credential.id, credentialVersion: v },
      service: { kind: 'audit', assignment, claim, payloadHash: zero }, intentGuard: temporary(3_301 + 2 * n), guardOrigin: null };
    const guard: Mutable<DecisionNode> = { ...structuredClone(authorize), id: authorize.intentGuard!, mode: 'resource-wide-deny',
      adapterId: 'journal.guard', service: null, intentGuard: null, guardOrigin: authorize.id };
    bundle.nodes.push(authorize, guard);
    for (const node of [authorize, guard]) bundle.candidates.push({ nodeId: node.id, snapshotDigest: bundle.snapshot.snapshotDigest,
      subject: service, request: node.request, anchorDigest: zero, candidates: [grantRef] });
    bundle.root = authorize.id;
  }
  return sealDecisionFixture(fixture);
}

export function makeWideContextFixture(): DecisionFixture {
  const fixture = appendJournalParents(makeDecisionFixture(), 63), { bundle } = fixture;
  const base = bundle.nodes.find(node => node.mode === 'authorize' && node.subject.kind === 'human')!;
  const journals = bundle.nodes.filter(node => node.mode === 'authorize' && node.service?.kind === 'audit');
  const final = bundle.journalClaims[bundle.journalClaims.length - 1];
  for (const claim of bundle.journalClaims) if (claim !== final) {
    claim.actor = base.subject; claim.parentDecisions = [base.id];
    bundle.operations.find(row => row.id === claim.operationId)!.actor = base.subject;
  }
  final.parentDecisions = journals.filter(node => node.id !== bundle.root).map(node => node.id);
  return sealDecisionFixture(fixture);
}
