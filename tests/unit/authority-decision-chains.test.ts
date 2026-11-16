// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { prepareChains, resolveChains } from '../../packages/authority/src/decision-chains.ts';
import { DecisionBudget, DecisionFailure } from '../../packages/authority/src/decision-budget.ts';
import { parsePolicyFile, policyHash } from '../../packages/authority/src/policy.ts';
import { chainLinkKey, definitionKey, grantKey, policyKey, scopeKey, subjectKey, versionKey } from '../../packages/authority/src/decision-types.ts';
import type { AuthorityGrant, DecisionBundle, DecisionIndexes, DecisionInput, DecisionNode, EffectCeiling,
  NodeDecision, PrincipalEvidence } from '../../packages/authority/src/decision-types.ts';
import type { Counter, Digest, Scope, UTC, UUID, Validity, Version } from '../../packages/authority/src/types.ts';

const id = (n: number): UUID => `00000000-0000-0000-0000-${n.toString(16).padStart(12, '0')}` as UUID;
const digest = (n: number): Digest => n.toString(16).padStart(64, '0') as Digest;
const version = 1 as Version, counter = '1' as Counter;
const now = '2026-11-16T12:00:00.000Z' as UTC, future = '2026-11-16T13:00:00.000Z' as UTC;
const past = '2026-11-16T11:00:00.000Z' as UTC;
const eternal: Validity = { notBefore: null, expiresAt: null };
const tenantId = id(1), subjectId = id(2), resource = { tenantId, kind: 'asset' as const, id: id(3) };
const tenantScope: Scope = { kind: 'tenant', tenantId };
const human = (n: UUID): PrincipalEvidence => ({ kind: 'human', id: n, identityRevision: counter, active: true,
  membership: { ref: { id: id(700 + Number.parseInt(n.slice(-3), 16)), version }, tenantId,
    identityId: n, state: 'active', validity: eternal } });
const effect = (): EffectCeiling => ({ actions: ['asset:discover'], resourceKinds: ['asset'], fields: null,
  scope: tenantScope, validity: eternal });

/** These exercise the internal schema-admitted chain seam with real policies and budget.
 * Full JSON admission, identity hashing and context authentication are separate engine tests. */
function fixture(): DecisionInput {
  const policy = { formatVersion: 1, id: id(20), version: 1,
    rules: [{ id: id(21), effect: 'allow', actions: ['asset:discover'], fields: null,
      when: { op: 'resource-kind-in', kinds: ['asset'] } }] };
  const document = JSON.stringify(policy), parsed = parsePolicyFile(document);
  assert.equal(parsed.ok, true); if (!parsed.ok) throw new Error('Fixture policy failed parsing');
  const hash = policyHash(parsed.value); if (!hash.ok) throw new Error('Fixture policy failed hashing');
  const pin = { policyId: id(20), version, hash: hash.value };
  const node: DecisionNode = { id: digest(10), mode: 'authorize', subject: { kind: 'human', id: subjectId },
    request: { action: 'asset:discover', resource, revision: version, field: null },
    authentication: { kind: 'human-session', sessionId: id(30), sessionVersion: version },
    resource: { requestResource: resource, requestedRevision: version, canonicalCurrentVersion: version,
      containment: { resource, revision: version, context: 'current', securityRevision: counter,
        domainPath: { status: 'known', value: [] }, operation: null },
      classifications: { status: 'known', value: [] }, approvedTags: { status: 'known', value: [] } },
    adapterId: 'fixture.asset.discover', projection: null, ceilingRefs: [], service: null,
    intentGuard: null, guardOrigin: null, purpose: { status: 'unavailable' }, environment: { status: 'unavailable' }, factDigest: digest(11) };
  const grant: AuthorityGrant = { kind: 'ordinary-role', ref: { kind: 'grant', id: id(40), version }, tenantId,
    state: 'active', issuer: { kind: 'human', id: id(99) }, beneficiary: { kind: 'human', id: subjectId },
    scope: tenantScope, validity: eternal, ceiling: effect(), role: { roleId: id(50), version }, delegable: null };
  const bundle: DecisionBundle = { formatVersion: 1,
    snapshot: { tenantId, generation: counter, authorityEpoch: counter, registryVersion: version,
      registryDigest: digest(1), snapshotDigest: digest(2), now }, root: node.id, nodes: [node],
    principals: [human(subjectId)], groups: [], memberships: [], principalGroups: [{ subject: node.subject, memberships: { status: 'known', value: [] } }],
    sessions: [{ id: id(30), version, identityId: subjectId, selectedTenantId: tenantId,
      generation: counter, state: 'active', validity: eternal }], credentials: [],
    definitions: [{ formatVersion: 1, kind: 'role', id: id(50), version, tenantId,
      currentHeadVersion: version, state: 'active', hash: digest(50), content: { metadata: { key: 'reader', label: 'Reader', description: '' }, policies: [pin] } }],
    policies: [{ tenantId, currentHeadVersion: version, state: 'active', pin, document, resourceWideIntents: [] }], grants: [grant],
    candidates: [{ nodeId: node.id, snapshotDigest: digest(2), subject: node.subject, request: node.request, anchorDigest: digest(3), candidates: [grant.ref] }],
    chainLinks: [], scopeAnchors: [], visibility: [], creators: [], serviceAssignments: [], approvedFacts: [], contextFacts: [],
    operations: [], references: [], sources: [], jobs: [], claims: [], leases: [], projectionEvents: [], journalClaims: [], terminals: [] };
  return reindex({ bundle, registry: { formatVersion: 1, version, digest: digest(1), actions: [], adapters: [], fields: [],
    projections: [], intentContexts: [], producers: [], leaseIssuers: [] },
    admission: { rawBytes: null, canonicalBytes: 0, nodes: 0, depth: 0 },
    parsedPolicies: new Map([[policyKey(pin), parsed.value]]), indexes: {} as DecisionIndexes });
}
function reindex(input: DecisionInput): DecisionInput {
  const b = input.bundle;
  const map = <T>(rows: readonly T[], key: (value: T) => string): Map<string, T> => new Map(rows.map(row => [key(row), row]));
  input.indexes = {
    nodes: map(b.nodes, n => n.id), principals: map(b.principals, subjectKey), groups: map(b.groups, n => n.id),
    memberships: map(b.memberships, n => versionKey(n.ref)), principalGroups: map(b.principalGroups, n => subjectKey(n.subject)),
    sessions: map(b.sessions, versionKey), credentials: map(b.credentials, versionKey),
    definitions: map(b.definitions, n => definitionKey(n.kind, n.id, n.version)), policies: map(b.policies, n => policyKey(n.pin)),
    grants: map(b.grants, n => grantKey(n.ref)), candidates: map(b.candidates, n => n.nodeId),
    chainLinks: map(b.chainLinks, n => chainLinkKey(n.nodeId, n.child)), scopeAnchors: map(b.scopeAnchors, n => scopeKey(n.scope)),
    visibility: map(b.visibility, n => n.id), creators: map(b.creators, n => n.id), serviceAssignments: map(b.serviceAssignments, n => versionKey(n.ref)),
    approvedFacts: map(b.approvedFacts, n => versionKey(n.ref)), contextFacts: map(b.contextFacts, n => versionKey(n.ref)),
    operations: map(b.operations, versionKey), references: map(b.references, versionKey), sources: map(b.sources, n => versionKey(n.ref)),
    jobs: map(b.jobs, n => versionKey(n.ref)), claims: map(b.claims, n => versionKey(n.ref)), leases: map(b.leases, n => versionKey(n.ref)),
    projectionEvents: map(b.projectionEvents, n => versionKey(n.ref)), journalClaims: map(b.journalClaims, n => versionKey(n.ref)),
    terminals: map(b.terminals, n => versionKey(n.ref)), adapters: map(input.registry.adapters, n => n.id),
    producers: map(input.registry.producers, n => versionKey(n.ref)), leaseIssuers: map(input.registry.leaseIssuers, n => versionKey(n.ref)),
  };
  return input;
}
function run(input: DecisionInput, decisions = new Map<Digest, NodeDecision>(), budget = new DecisionBudget()) {
  reindex(input); const plan = prepareChains(input, input.bundle.nodes[0], budget);
  return { plan, result: resolveChains(input, plan, decisions, budget), budget };
}
function refused(input: DecisionInput) { assert.throws(() => run(input), (error: unknown) => error instanceof DecisionFailure && error.outcome === 'invalid'); }
function delegated(edges: number) {
  const input = fixture(), b = input.bundle, node = b.nodes[0], root = b.grants[0];
  assert.equal(root.kind, 'ordinary-role'); if (root.kind !== 'ordinary-role') throw new Error('Expected root');
  root.beneficiary = { kind: 'human', id: id(100) };
  root.delegable = { actions: ['asset:discover'], fields: null, scope: tenantScope, validity: eternal, remainingDepth: 4 };
  const grants: AuthorityGrant[] = [root], nodes: DecisionNode[] = [node], decisions = new Map<Digest, NodeDecision>();
  b.principals = [human(id(100))];
  for (let i = 1; i <= edges; i++) {
    const child: AuthorityGrant = { kind: 'delegation', ref: { kind: 'delegation', id: id(1000 + i), version },
      parent: grants[i - 1].ref, tenantId, issuer: { kind: 'human', id: id(99 + i) }, beneficiary: { kind: 'human', id: id(100 + i) },
      scope: tenantScope, validity: eternal, ceiling: effect(), state: 'active',
      delegable: i === edges ? null : { actions: ['asset:discover'], fields: null, scope: tenantScope, validity: eternal, remainingDepth: 4 - i } };
    grants.push(child); b.principals = [...b.principals, human(child.beneficiary.id)];
    const issuer: DecisionNode = { ...structuredClone(node), id: digest(100 + i), subject: child.issuer,
      authentication: { kind: 'live-issuer', childGrant: child.ref, elevationSession: null } };
    nodes.push(issuer); b.chainLinks = [...b.chainLinks, { nodeId: node.id, child: child.ref, parent: child.parent, issuerDecision: issuer.id, viaMembership: null }];
    decisions.set(issuer.id, { mode: 'authorize', nodeId: issuer.id, allowed: true, reason: 'allowed',
      validUntil: null, matched: [], derivedOrdinaryFieldAllow: false });
  }
  node.subject = { kind: 'human', id: id(100 + edges) };
  b.sessions = [{ ...b.sessions[0], identityId: node.subject.id }];
  b.principalGroups = b.principals.map(p => ({ subject: { kind: p.kind, id: p.id }, memberships: { status: 'known', value: [] } }));
  b.candidates = [{ ...b.candidates[0], subject: node.subject, candidates: [grants[grants.length - 1].ref] }];
  b.grants = grants; b.nodes = nodes;
  return { input: reindex(input), decisions };
}

test('chains derive exact pinned bindings and role facts without requiring the historical ordinary issuer to stay active', () => {
  const input = fixture(), before = JSON.stringify(input.bundle);
  input.bundle.definitions[0].currentHeadVersion = 3 as Version;
  const { result, budget } = run(input);
  assert.equal(result.indeterminate, false); assert.equal(result.bindings.length, 1);
  assert.equal(result.bindings[0].policy.version, 1); assert.equal(result.requestRoles.status, 'known');
  assert.deepEqual(budget.metrics.bindingInstances, 1); assert.equal(budget.metrics.roleInstances, 1);
  // No lookup/creation of the old issuer is needed; the current subject remains mandatory.
  assert.equal(input.bundle.principals.some(p => p.id === id(99)), false);
  input.bundle.definitions[0].currentHeadVersion = version;
  assert.equal(JSON.stringify(input.bundle), before);
});

test('chains retain all future boundaries and distinguish revoked history from inconsistent live retired pins', () => {
  const input = fixture(); input.bundle.grants[0].validity = { notBefore: future, expiresAt: null };
  let out = run(input); assert.equal(out.result.bindings.length, 0); assert.deepEqual(out.result.boundaries, [future]);
  input.bundle.definitions[0].state = 'retired'; out = run(input); assert.equal(out.result.indeterminate, true);
  input.bundle.grants[0].state = 'revoked'; out = run(input); assert.equal(out.result.indeterminate, false); assert.equal(out.result.bindings.length, 0);
  // Revocation never bypasses structural exact-reference validation.
  input.bundle.definitions = []; refused(input);
});

test('documentation-only responsibilities derive no authority and mapped responsibilities require the exact association', () => {
  const input = fixture(), ordinary = input.bundle.grants[0];
  const { role: ignoredRole, delegable: ignoredDelegable, ...base } = ordinary as Extract<AuthorityGrant, { kind: 'ordinary-role' }>;
  void ignoredRole; void ignoredDelegable;
  const grant: AuthorityGrant = { ...base, kind: 'responsibility', type: { id: id(60), version }, mappedRole: null,
    assignmentId: id(61), assignmentVersion: version, effectiveGrantId: null, delegable: null };
  input.bundle.grants = [grant];
  input.bundle.definitions = [...input.bundle.definitions, { formatVersion: 1, kind: 'responsibility-type', id: id(60), version, tenantId,
    currentHeadVersion: version, state: 'active', hash: digest(60), content: { metadata: { key: 'owner', label: 'Owner', description: '' }, grantsRole: null } }];
  assert.equal(run(input).result.bindings.length, 0);
  grant.mappedRole = { roleId: id(50), version }; grant.effectiveGrantId = grant.ref.id;
  refused(input);
  const definition = input.bundle.definitions[1]; if (definition.kind !== 'responsibility-type') throw new Error('Expected type');
  definition.content.grantsRole = grant.mappedRole;
  assert.equal(run(input).result.bindings.length, 1);
  grant.effectiveGrantId = id(999); refused(input);
});

test('group grants use complete exact membership provenance including future starts and retired-group inconsistency', () => {
  const input = fixture(), grant = input.bundle.grants[0];
  if (grant.kind !== 'ordinary-role') throw new Error('Expected root'); grant.beneficiary = { kind: 'group', id: id(70) };
  const membership = { ref: { id: id(71), version }, tenantId, groupId: id(70), identityId: subjectId,
    state: 'active' as const, validity: { notBefore: future, expiresAt: null } };
  input.bundle.groups = [{ id: id(70), tenantId, revision: counter, state: 'active' }]; input.bundle.memberships = [membership];
  input.bundle.principalGroups = [{ subject: input.bundle.nodes[0].subject, memberships: { status: 'known', value: [membership.ref] } }];
  let out = run(input); assert.equal(out.result.bindings.length, 0); assert.deepEqual(out.result.boundaries, [future]);
  membership.validity.notBefore = past; assert.equal(run(input).result.bindings.length, 1);
  input.bundle.groups[0].state = 'retired'; assert.equal(run(input).result.indeterminate, true);
  input.bundle.groups[0].state = 'active'; membership.identityId = id(666); refused(input);
});

test('unavailable group or domain proof remains indeterminate rather than a proven empty negative', () => {
  const input = fixture(), grant = input.bundle.grants[0];
  if (grant.kind !== 'ordinary-role') throw new Error('Expected root'); grant.beneficiary = { kind: 'group', id: id(70) };
  input.bundle.principalGroups = [{ subject: input.bundle.nodes[0].subject, memberships: { status: 'unavailable' } }];
  let out = run(input); assert.equal(out.result.indeterminate, true); assert.equal(out.result.requestRoles.status, 'unavailable');
  grant.beneficiary = { kind: 'human', id: subjectId }; grant.scope = { kind: 'domain', tenantId, domainId: id(80), includeDescendants: true };
  input.bundle.nodes[0].resource.containment.domainPath = { status: 'unavailable' };
  out = run(input); assert.equal(out.result.indeterminate, true); assert.equal(out.result.bindings.length, 0);
});

test('four connected delegation edges preserve exact role origin, full current issuers and cumulative derived accounting', () => {
  const { input, decisions } = delegated(4), { plan, result, budget } = run(input, decisions);
  assert.equal(plan.dependencies.length, 4); assert.equal(result.bindings[0].path.length, 5);
  assert.equal(result.bindings[0].origin.id, id(40)); assert.equal(budget.metrics.lineageEdgeOccurrences, 8);
  assert.equal(result.requestRoles.status, 'known');
  const later = new DecisionBudget(); later.charge('bindingInstances', 512);
  assert.throws(() => run(input, decisions, later), (error: unknown) => error instanceof DecisionFailure && error.outcome === 'profile_limit');
});

test('issuer denial disables its path, indeterminate contaminates, and even denied issuer horizons propagate', () => {
  const { input, decisions } = delegated(1), key = input.bundle.chainLinks[0].issuerDecision;
  decisions.set(key, { mode: 'authorize', nodeId: key, allowed: false, reason: 'no_allow', validUntil: future, matched: [], derivedOrdinaryFieldAllow: false });
  let out = run(input, decisions); assert.equal(out.result.bindings.length, 0); assert.equal(out.result.indeterminate, false); assert.deepEqual(out.result.boundaries, [future]);
  decisions.set(key, { ...decisions.get(key)!, mode: 'authorize', allowed: false, reason: 'indeterminate', derivedOrdinaryFieldAllow: false });
  out = run(input, decisions); assert.equal(out.result.indeterminate, true); assert.equal(out.result.requestRoles.status, 'unavailable');
  decisions.clear(); assert.throws(() => run(input, decisions), DecisionFailure);
});

test('disconnected, cyclic, wrongly scoped and widened delegation evidence is rejected even when revoked', () => {
  const mutations: ((input: DecisionInput) => void)[] = [
    input => { const child = input.bundle.grants[1]; child.ref = { ...child.ref, kind: 'grant' }; input.bundle.candidates[0].candidates = [child.ref]; },
    input => { input.bundle.grants[1].issuer = { kind: 'human', id: id(777) }; },
    input => { const child = input.bundle.grants[1]; if (child.kind === 'delegation') child.parent = child.ref; },
    input => { input.bundle.grants[1].ceiling.actions = ['asset:description.edit']; },
    input => { input.bundle.grants[1].ceiling.resourceKinds = ['domain']; },
    input => { input.bundle.grants[0].ceiling.fields = [] as never[]; },
    input => { input.bundle.grants[1].beneficiary = { kind: 'human', id: id(100) }; },
    input => { input.bundle.nodes[1].request = { ...input.bundle.nodes[1].request, revision: 2 as Version }; },
    input => { input.bundle.grants[0].scope = { kind: 'resource', resource }; input.bundle.grants[0].ceiling.scope = input.bundle.grants[0].scope; },
    input => { input.bundle.chainLinks = []; },
  ];
  for (const mutate of mutations) { const { input } = delegated(1); input.bundle.grants[1].state = 'revoked'; mutate(input); refused(input); }
});

test('delegation to a group member requires the exact current parent-membership link and its future horizon', () => {
  const { input, decisions } = delegated(1), root = input.bundle.grants[0];
  if (root.kind !== 'ordinary-role') throw new Error('Expected root'); root.beneficiary = { kind: 'group', id: id(70) };
  const membership = { ref: { id: id(71), version }, tenantId, groupId: id(70), identityId: id(100),
    state: 'active' as const, validity: { notBefore: null, expiresAt: future } };
  input.bundle.groups = [{ id: id(70), tenantId, revision: counter, state: 'active' }]; input.bundle.memberships = [membership];
  input.bundle.principalGroups = input.bundle.principalGroups.map(p => p.subject.id === id(100)
    ? { ...p, memberships: { status: 'known', value: [membership.ref] } } : p);
  input.bundle.chainLinks[0].viaMembership = membership.ref;
  const out = run(input, decisions); assert.equal(out.result.bindings.length, 1); assert.equal(out.result.bindings[0].effectiveValidity.expiresAt, future);
  input.bundle.chainLinks[0].viaMembership = null; refused(input);
});

test('scope attenuation uses canonical domain ancestry and preserves direct-only domain meaning', () => {
  const { input, decisions } = delegated(1), root = input.bundle.grants[0], child = input.bundle.grants[1];
  const domain: Scope = { kind: 'domain', tenantId, domainId: id(80), includeDescendants: true };
  root.scope = domain; root.ceiling.scope = domain;
  if (root.kind !== 'ordinary-role' || root.delegable === null) throw new Error('Expected delegable root'); root.delegable.scope = domain;
  child.scope = { kind: 'resource', resource }; child.ceiling.scope = child.scope;
  const containment = { ...input.bundle.nodes[0].resource.containment, domainPath: { status: 'known' as const, value: [id(81), id(80)] } };
  input.bundle.scopeAnchors = [{ scope: child.scope, containment }];
  input.bundle.nodes.forEach(n => { n.resource.containment = structuredClone(containment); });
  assert.equal(run(input, decisions).result.bindings.length, 1);
  root.scope = { ...domain, includeDescendants: false }; root.ceiling.scope = root.scope; root.delegable.scope = root.scope; refused(input);
});

test('elevation is finite, terminal, compatibility-only and bound to the exact current use and session', () => {
  const { input, decisions } = delegated(1), delegatedGrant = input.bundle.grants[1];
  if (delegatedGrant.kind !== 'delegation') throw new Error('Expected child');
  const { delegable: ignored, ...base } = delegatedGrant; void ignored;
  const elevated: AuthorityGrant = { ...base, kind: 'elevation', ref: { ...base.ref, kind: 'elevation' },
    validity: { notBefore: now, expiresAt: future }, use: { id: id(2000), version, state: 'active', identityId: input.bundle.nodes[0].subject.id,
      sessionId: id(30), sessionVersion: version, generation: counter, validity: { notBefore: now, expiresAt: future } } };
  input.bundle.grants = [input.bundle.grants[0], elevated]; input.bundle.candidates[0].candidates = [elevated.ref];
  input.bundle.chainLinks[0].child = elevated.ref;
  input.bundle.nodes[1].authentication = { kind: 'live-issuer', childGrant: elevated.ref, elevationSession: null };
  let out = run(input, decisions); assert.equal(out.result.bindings.length, 1); assert.equal(out.result.bindings[0].effectiveValidity.expiresAt, future);
  elevated.use!.sessionId = id(999); input.bundle.sessions = [...input.bundle.sessions, { ...input.bundle.sessions[0], id: id(999) }];
  out = run(input, decisions); assert.equal(out.result.bindings.length, 0);
  elevated.ceiling.actions = ['authority:read']; refused(input);
});

test('service grants stay bound to their exact service assignment and service credential', () => {
  const input = fixture(), b = input.bundle, node = b.nodes[0], old = b.grants[0];
  node.subject = { kind: 'service', id: subjectId }; node.request.action = 'projection:consume';
  node.authentication = { kind: 'service-credential', credentialId: id(31), credentialVersion: version };
  const assignment = { id: id(81), version };
  node.service = { kind: 'project-consume', assignment, event: { id: id(82), version }, mode: 'apply', requestHash: digest(82) };
  b.principals = [{ kind: 'service', id: subjectId, revision: counter, tenantId, state: 'active', validity: eternal }];
  b.credentials = [{ id: id(31), version, serviceId: subjectId, tenantId, generation: counter, state: 'active', validity: eternal }];
  b.serviceAssignments = [{ ref: assignment, tenantId, serviceId: subjectId, state: 'active', validity: eternal,
    actions: ['projection:consume'], siteId: null, sourceId: null, indexId: 'fixture', eventFamilies: ['asset'] }];
  b.grants = [{ kind: 'service', ref: old.ref, tenantId, issuer: old.issuer, beneficiary: node.subject,
    state: 'active', scope: tenantScope, validity: eternal, ceiling: { ...effect(), actions: ['projection:consume'] },
    policies: [b.policies[0].pin], assignment }];
  b.candidates = [{ ...b.candidates[0], subject: node.subject, request: node.request }];
  assert.equal(run(input).result.bindings.length, 1);
  b.serviceAssignments[0].serviceId = id(666); refused(input);
});

test('resource-wide intent cannot survive a narrowed finite field or action ceiling', () => {
  const input = fixture(); input.bundle.policies[0].resourceWideIntents = [{ ruleId: id(21), registryVersion: version,
    registryDigest: digest(1), resourceKinds: ['asset'], expandedActions: ['asset:discover'] }];
  input.registry.actions = [{ action: 'asset:discover', family: 'human', resourceKinds: ['asset'] },
    { action: 'asset:metadata.read', family: 'human', resourceKinds: ['asset'] }];
  assert.equal(run(input).result.bindings.length, 1);
  input.bundle.grants[0].ceiling.fields = []; refused(input);
  input.bundle.grants[0].ceiling.fields = null; input.bundle.policies[0].resourceWideIntents[0].expandedActions = ['asset:metadata.read']; refused(input);
});

test('resource-wide expansion is kind-specific and unused onward fields do not narrow the current grant', () => {
  const input = fixture(), root = input.bundle.grants[0];
  if (root.kind !== 'ordinary-role') throw new Error('Expected root');
  root.delegable = { actions: ['asset:discover'], fields: [], scope: tenantScope, validity: eternal, remainingDepth: 1 };
  input.registry.actions = [{ action: 'asset:discover', family: 'human', resourceKinds: ['asset'] },
    { action: 'domain:metadata.read', family: 'human', resourceKinds: ['domain'] }];
  input.bundle.policies[0].resourceWideIntents = [{ ruleId: id(21), registryVersion: version, registryDigest: digest(1),
    resourceKinds: ['asset', 'domain'], expandedActions: ['asset:discover', 'domain:metadata.read'] }];
  assert.equal(run(input).result.bindings.length, 1);
  const delegatedFixture = delegated(1), parent = delegatedFixture.input.bundle.grants[0], child = delegatedFixture.input.bundle.grants[1];
  if (parent.kind !== 'ordinary-role' || parent.delegable === null) throw new Error('Expected parent');
  parent.delegable.fields = []; child.ceiling.fields = [];
  delegatedFixture.input.registry.actions = input.registry.actions;
  delegatedFixture.input.bundle.policies[0].resourceWideIntents = input.bundle.policies[0].resourceWideIntents;
  refused(delegatedFixture.input);
});

test('issuer contexts may use separately bound records but cannot substitute favorable purpose or provenance', () => {
  const { input, decisions } = delegated(1), consumer = input.bundle.nodes[0], issuer = input.bundle.nodes[1];
  const provenance = { producer: { id: id(3000), version }, tenantId, registryDigest: digest(1), sourceRecordId: id(3001), sourceRecordVersion: version };
  consumer.purpose = { status: 'known', value: { id: id(3002), version } };
  issuer.purpose = { status: 'known', value: { id: id(3003), version } };
  input.bundle.contextFacts = [consumer, issuer].map((node, index) => ({ ref: { id: id(3002 + index), version }, kind: 'purpose', provenance,
    subject: node.subject, request: node.request, containmentDigest: digest(3004), state: 'approved', validity: eternal, value: id(3005) }));
  assert.equal(run(input, decisions).result.bindings.length, 1);
  input.bundle.contextFacts[1].value = id(3006); refused(input);
  input.bundle.contextFacts[1].value = id(3005);
  input.bundle.contextFacts[1].provenance = { ...provenance, sourceRecordVersion: 2 as Version }; refused(input);
  input.bundle.contextFacts[1].provenance = provenance; issuer.purpose = { status: 'unavailable' }; refused(input);
});

test('all candidate paths are expanded and charged before inactivity, without mutating the input', () => {
  const input = fixture(), root = input.bundle.grants[0];
  const second = structuredClone(root); second.ref = { ...second.ref, id: id(41) }; second.state = 'revoked';
  input.bundle.grants = [root, second]; input.bundle.candidates[0].candidates = [root.ref, second.ref];
  const before = JSON.stringify(input.bundle), out = run(input);
  assert.equal(out.plan.paths.length, 2); assert.equal(out.result.bindings.length, 1);
  assert.equal(out.budget.metrics.bindingInstances, 2); assert.equal(out.budget.metrics.roleInstances, 2);
  assert.ok(out.budget.metrics.proofBytes > 0); assert.equal(JSON.stringify(input.bundle), before);
  const budget = new DecisionBudget(); budget.charge('bindingInstances', 510);
  assert.equal(run(input, new Map(), budget).budget.metrics.bindingInstances, 512);
});

test('current subject and edge issuer membership remain mandatory while future temporal ceilings stay visible', () => {
  const input = fixture(); const subject = input.bundle.principals[0];
  if (subject.kind !== 'human' || subject.membership === null) throw new Error('Expected human');
  subject.active = false; assert.equal(run(input).result.bindings.length, 0);
  subject.active = true; subject.membership.validity = { notBefore: future, expiresAt: null };
  const out = run(input); assert.equal(out.result.bindings.length, 0); assert.deepEqual(out.result.boundaries, [future]);
  const delegatedFixture = delegated(1), issuer = delegatedFixture.input.bundle.principals[0];
  if (issuer.kind !== 'human') throw new Error('Expected issuer'); issuer.active = false;
  assert.equal(run(delegatedFixture.input, delegatedFixture.decisions).result.bindings.length, 0);
  assert.throws(() => run(delegated(5).input), DecisionFailure);
});

function scopeOperationFixture(context: 'proposed' | 'original-scope' = 'proposed') {
  const f = delegated(1), { input } = f, root = input.bundle.grants[0], child = input.bundle.grants[1];
  if (root.kind !== 'ordinary-role' || root.delegable === null) throw new Error('Expected root');
  const domain: Scope = { kind: 'domain', tenantId, domainId: id(80), includeDescendants: true };
  root.scope = domain; root.ceiling.scope = domain; root.delegable.scope = domain;
  child.scope = { kind: 'resource', resource }; child.ceiling.scope = child.scope;
  const side = context === 'proposed' ? 'after' : 'original';
  const op = { operationId: id(4000), version, planHash: digest(4000), memberKey: 'target', side } as const;
  const containment = { ...input.bundle.nodes[0].resource.containment, context, operation: op,
    domainPath: { status: 'known' as const, value: [id(81), id(80)] } };
  input.bundle.nodes.forEach(n => { n.resource.containment = structuredClone(containment); });
  input.bundle.scopeAnchors = [{ scope: child.scope, containment: structuredClone(containment) }];
  input.bundle.operations = [{ id: op.operationId, version, tenantId, actor: input.bundle.nodes[0].subject,
    planHash: op.planHash, requestHash: digest(4001), state: 'prepared', validity: eternal,
    members: [{ key: op.memberKey, side, resource, revision: version, securityRevision: counter, domainPath: [id(81), id(80)] }] }];
  return f;
}

test('proposed and original attenuation anchors resolve the exact protected operation/member and keep original actor provenance', () => {
  for (const context of ['proposed', 'original-scope'] as const) {
    const { input, decisions } = scopeOperationFixture(context), result = run(input, decisions);
    assert.equal(result.result.bindings.length, 1);
    assert.notEqual(input.bundle.operations[0].actor.id, input.bundle.nodes[1].subject.id);
    assert.ok(result.plan.usedRecords.has(input.bundle.operations[0]));
  }
  const { input, decisions } = scopeOperationFixture();
  input.bundle.operations[0].validity = { notBefore: future, expiresAt: null };
  const out = run(input, decisions); assert.equal(out.result.indeterminate, true); assert.deepEqual(out.result.boundaries, [future]);
});

test('forged noncurrent attenuation anchors cannot bypass exact operation, member, revision or path provenance', () => {
  const mutations: ((input: DecisionInput) => void)[] = [
    input => { input.bundle.scopeAnchors[0].containment.operation!.operationId = id(4999); },
    input => { input.bundle.scopeAnchors[0].containment.operation!.version = 2 as Version; },
    input => { input.bundle.scopeAnchors[0].containment.operation!.planHash = digest(4999); },
    input => { input.bundle.scopeAnchors[0].containment.operation!.memberKey = 'not-the-target'; },
    input => { input.bundle.scopeAnchors[0].containment.operation!.side = 'before'; },
    input => { input.bundle.scopeAnchors[0].containment.revision = 2 as Version; },
    input => { input.bundle.scopeAnchors[0].containment.securityRevision = '2' as Counter; },
    input => { input.bundle.scopeAnchors[0].containment.domainPath = { status: 'known', value: [id(80)] }; },
    input => { input.bundle.operations = []; },
    input => { input.bundle.nodes.forEach(n => { n.resource.containment = { ...n.resource.containment, context: 'current', operation: null }; }); },
    input => { input.bundle.scopeAnchors[0].containment.context = 'current'; },
  ];
  for (const mutate of mutations) { const { input } = scopeOperationFixture(); mutate(input); refused(input); }
});

test('a resource child cannot outlive its consumed parent domain ceiling when the request moves outside that scope', () => {
  const { input, decisions } = scopeOperationFixture();
  // Current issuance containment is valid, but the proposed operation leaves the parent domain.
  input.bundle.scopeAnchors[0].containment = { ...input.bundle.scopeAnchors[0].containment, context: 'current', operation: null };
  input.bundle.nodes.forEach(node => { node.resource.containment.domainPath = { status: 'known', value: [id(99)] }; });
  input.bundle.operations[0].members[0].domainPath = [id(99)];
  const out = run(input, decisions);
  assert.equal(out.plan.paths[0].requestApplicable, false); assert.equal(out.result.bindings.length, 0);
});
