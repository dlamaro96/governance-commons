// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { ADMIN_ACTIONS, COMPATIBILITY_ACTIONS, FIELD_ACTIONS, SERVICE_ACTIONS } from '../../../packages/authority/src/actions.ts';
import { policyHash, parsePolicyFile } from '../../../packages/authority/src/policy.ts';
import { hashAuthorityRegistry, hashAuthorityDefinition, authorityAnchorDigest, authorityNodeIdentity } from '../../../packages/authority/src/decision-identity.ts';
import type { DecisionBundle, AuthorityDecisionRegistry, DecisionCatalogs, DecisionNode } from '../../../packages/authority/src/decision-types.ts';
import type { Parsed, UUID, Version, UTC, Digest, Counter, PolicyRule } from '../../../packages/authority/src/types.ts';
export type Mutable<T> = T extends string | number | boolean | null ? T : T extends readonly (infer E)[] ? Mutable<E>[] : T extends object ? { -readonly [P in keyof T]: Mutable<T[P]> } : T;
export const id = (n: number): UUID => `00000000-0000-0000-0000-${n.toString(16).padStart(12, '0')}` as UUID;
export const v = 1 as Version;
export const now = '2026-11-16T06:00:00.000Z' as UTC;
export const zero = '0'.repeat(64) as Digest;
export const validity = { notBefore: null, expiresAt: null };
export function parsed<T>(result: Parsed<T>): T {
  assert.equal(result.ok, true, result.ok ? '' : JSON.stringify(result.issues));
  if (!result.ok) throw new Error('Fixture helper refused data');
  return result.value;
}
export type DecisionFixture = { bundle: Mutable<DecisionBundle>; registry: Mutable<AuthorityDecisionRegistry> };
export function makeDecisionFixture(rules?: readonly PolicyRule[]): DecisionFixture {
  const tenantId = id(1), subject = { kind: 'human' as const, id: id(2) };
  const resource = { tenantId, kind: 'asset' as const, id: id(3) };
  const request = { action: 'asset:metadata.read' as const, resource, revision: v, field: null };
  const human = [...COMPATIBILITY_ACTIONS.flatMap(([actions]) => actions), ...ADMIN_ACTIONS];
  const adapter = { version: v, action: request.action, resourceKinds: ['asset' as const], containment: 'asset-placement' as const,
    ceilings: [], dependencyElevation: 'forbidden' as const, ceilingFailure: 'ceiling_denied' as const };
  const registry: AuthorityDecisionRegistry = {
    formatVersion: 1, version: v, digest: zero,
    actions: [...human.map(action => ({ action, family: 'human' as const, resourceKinds: ['asset' as const] })),
      ...FIELD_ACTIONS.map(action => ({ action, family: 'field' as const, resourceKinds: ['asset' as const] })),
      ...SERVICE_ACTIONS.map(action => ({ action, family: 'service' as const, resourceKinds: ['asset' as const] }))],
    adapters: [{ ...adapter, id: 'asset.read', branch: 'human-resource' }, { ...adapter, id: 'asset.guard', branch: 'intent-guard' }],
    fields: [], projections: [], intentContexts: [{ resourceKind: 'asset', subjectKind: 'human', denyContextAction: request.action, guardAdapterId: 'asset.guard' }],
    producers: [], leaseIssuers: [],
  };
  const definition = { formatVersion: 1 as const, id: id(10), version: v,
    rules: rules ?? [{ id: id(11), effect: 'allow' as const, actions: [request.action], fields: null,
      when: { op: 'subject-in' as const, subjects: [subject] } }] };
  const pin = { policyId: definition.id, version: v, hash: parsed(policyHash(definition, [])) };
  const role = { roleId: id(12), version: v };
  const containment = { resource, revision: v, context: 'current' as const, securityRevision: '1' as Counter,
    domainPath: { status: 'known' as const, value: [] }, operation: null };
  const evidence = { requestResource: resource, requestedRevision: v, canonicalCurrentVersion: v,
    containment, classifications: { status: 'known' as const, value: [] }, approvedTags: { status: 'known' as const, value: [] } };
  const node: DecisionNode = { id: zero, mode: 'authorize', subject, request,
    authentication: { kind: 'human-session', sessionId: id(4), sessionVersion: v }, resource: evidence,
    adapterId: 'asset.read', projection: null, ceilingRefs: [], service: null,
    intentGuard: '1'.repeat(64) as Digest, guardOrigin: null,
    purpose: { status: 'unavailable' }, environment: { status: 'unavailable' }, factDigest: zero };
  const guard: DecisionNode = { ...node, id: '1'.repeat(64) as Digest, mode: 'resource-wide-deny', adapterId: 'asset.guard', intentGuard: null, guardOrigin: node.id };
  const grantRef = { kind: 'grant' as const, id: id(14), version: v };
  const scope = { kind: 'tenant' as const, tenantId };
  const bundle: DecisionBundle = {
    formatVersion: 1, snapshot: { tenantId, generation: '1' as Counter, authorityEpoch: '1' as Counter,
      registryVersion: v, registryDigest: zero, snapshotDigest: '2'.repeat(64) as Digest, now }, root: node.id,
    nodes: [node, guard], principals: [{ kind: 'human', id: subject.id, identityRevision: '1' as Counter, active: true,
      membership: { ref: { id: id(5), version: v }, tenantId, identityId: subject.id, state: 'active', validity } }],
    groups: [], memberships: [], principalGroups: [{ subject, memberships: { status: 'known', value: [] } }],
    sessions: [{ id: id(4), version: v, identityId: subject.id, selectedTenantId: tenantId, generation: '1' as Counter, state: 'active', validity }],
    credentials: [], definitions: [{ formatVersion: 1, kind: 'role', id: role.roleId, version: v, content: {
      metadata: { key: 'reader', label: 'Reader', description: '' }, policies: [pin] }, tenantId, currentHeadVersion: v, state: 'active', hash: zero }],
    policies: [{ tenantId, currentHeadVersion: v, state: 'active', pin, document: JSON.stringify(definition), resourceWideIntents: [] }],
    grants: [{ ref: grantRef, kind: 'ordinary-role', tenantId, state: 'active', issuer: subject, beneficiary: subject,
      role, delegable: null, scope, validity, ceiling: { actions: [request.action], resourceKinds: ['asset'], fields: null, scope, validity } }],
    candidates: [node, guard].map(entry => ({ nodeId: entry.id, snapshotDigest: '2'.repeat(64) as Digest, subject,
      request, anchorDigest: zero, candidates: [grantRef] })), chainLinks: [], scopeAnchors: [], visibility: [], creators: [],
    serviceAssignments: [], approvedFacts: [], contextFacts: [], operations: [], references: [], sources: [], jobs: [],
    claims: [], leases: [], projectionEvents: [], journalClaims: [], terminals: [],
  };
  return sealDecisionFixture({ bundle, registry } as DecisionFixture);
}
/** Recompute construction hashes after an intentional coherent fixture edit.
 * Negative identity tests edit after sealing instead. This does not approve data. */
export function sealDecisionFixture(fixture: DecisionFixture): DecisionFixture {
  const { bundle, registry } = fixture;
  const { digest: _, ...registryContent } = registry;
  registry.digest = parsed(hashAuthorityRegistry(registryContent));
  bundle.snapshot.registryDigest = registry.digest; bundle.snapshot.registryVersion = registry.version;
  for (const evidence of bundle.policies) {
    const policy = parsed(parsePolicyFile(evidence.document, registry.fields));
    evidence.pin = { policyId: policy.id, version: policy.version, hash: parsed(policyHash(policy, registry.fields)) };
    for (const mark of evidence.resourceWideIntents) { mark.registryVersion = registry.version; mark.registryDigest = registry.digest; }
  }
  const pin = (old: { policyId: UUID; version: Version }) => bundle.policies.find(row => row.pin.policyId === old.policyId && row.pin.version === old.version)!.pin;
  for (const row of bundle.definitions) {
    if (row.kind === 'role') row.content.policies = row.content.policies.map(pin);
    row.hash = parsed(hashAuthorityDefinition({ formatVersion: row.formatVersion, kind: row.kind, id: row.id, version: row.version, content: row.content }));
  }
  for (const row of bundle.grants) if (row.kind === 'service') row.policies = row.policies.map(pin);
  for (const row of [...bundle.approvedFacts, ...bundle.contextFacts]) row.provenance.registryDigest = registry.digest;
  const { formatVersion: _format, snapshot: _snapshot, root: _root, nodes: _nodes, candidates: _candidates, chainLinks: _links, ...catalogs } = bundle;
  const oldNodes = new Map(bundle.nodes.map(node => [node.id, node]));
  const mapping = new Map<string, Digest>();
  for (const node of bundle.nodes) {
    const { id: oldId, factDigest: _fact, ...descriptor } = node;
    const origin = node.guardOrigin === null ? null : oldNodes.get(node.guardOrigin)!;
    const originDescriptor = origin === null ? null : (({ id: _id, factDigest: _digest, ...rest }) => rest)(origin);
    const identity = parsed(authorityNodeIdentity(bundle.snapshot, descriptor, catalogs as DecisionCatalogs, registry, originDescriptor));
    mapping.set(oldId, identity.nodeId); node.factDigest = identity.factDigest;
  }
  const mapped = (old: Digest): Digest => mapping.get(old) ?? old;
  bundle.root = mapped(bundle.root);
  for (const node of bundle.nodes) {
    node.id = mapped(node.id); if (node.intentGuard !== null) node.intentGuard = mapped(node.intentGuard);
    if (node.guardOrigin !== null) node.guardOrigin = mapped(node.guardOrigin);
    if (node.projection) {
      node.projection.prerequisites = node.projection.prerequisites.map(mapped);
      if (node.projection.sensitiveDecision !== null) node.projection.sensitiveDecision = mapped(node.projection.sensitiveDecision);
    }
    if (node.service && 'initiatingDecision' in node.service && node.service.initiatingDecision !== null) node.service.initiatingDecision = mapped(node.service.initiatingDecision);
  }
  for (const row of bundle.candidates) {
    row.nodeId = mapped(row.nodeId); const node = bundle.nodes.find(node => node.id === row.nodeId)!;
    row.subject = node.subject; row.request = node.request; row.snapshotDigest = bundle.snapshot.snapshotDigest;
    row.anchorDigest = parsed(authorityAnchorDigest(node.resource));
  }
  for (const row of bundle.chainLinks) { row.nodeId = mapped(row.nodeId); row.issuerDecision = mapped(row.issuerDecision); }
  for (const row of bundle.journalClaims) row.parentDecisions = row.parentDecisions.map(mapped);
  return fixture;
}

/** Each policy and grant is exact and connected in both the authorization and
 * guard partition. Distinct origins keep distinct output witnesses. */
export function makeWideBindingFixture(policies: number, grants: number, rulesPerPolicy = 1, markedDenies = false): DecisionFixture {
  const fixture = makeDecisionFixture(), { bundle, registry } = fixture;
  if (markedDenies) {
    // Only this literal human action applies to asset in this protected synthetic
    // registry, so the resource-wide expansion is exact and remains compact.
    for (const action of registry.actions) if (action.action !== 'asset:metadata.read') action.resourceKinds = ['tenant'];
  }
  const basePolicy = bundle.policies[0], baseGrant = bundle.grants[0];
  bundle.policies = [];
  for (let n = 0; n < policies; n++) {
    const rules = Array.from({ length: rulesPerPolicy }, (_, r): PolicyRule => ({ id: id(5_000 + r),
      effect: markedDenies ? 'deny' : 'allow', actions: ['asset:metadata.read'], fields: null,
      when: { op: 'subject-in', subjects: [bundle.nodes[0].subject] } }));
    const definition = { formatVersion: 1, id: id(4_000 + n), version: v, rules };
    bundle.policies.push({ ...basePolicy, pin: { policyId: definition.id, version: v, hash: zero }, document: JSON.stringify(definition),
      resourceWideIntents: markedDenies ? rules.map(rule => ({ ruleId: rule.id, registryVersion: v, registryDigest: zero,
        resourceKinds: ['asset'], expandedActions: ['asset:metadata.read'] })) : [] });
  }
  const role = bundle.definitions[0]; if (role.kind !== 'role') throw new Error('Fixture requires exact role');
  role.content.policies = bundle.policies.map(row => row.pin);
  bundle.grants = Array.from({ length: grants }, (_, n) => ({ ...structuredClone(baseGrant), ref: { kind: 'grant', id: id(6_000 + n), version: v } }));
  for (const partition of bundle.candidates) partition.candidates = bundle.grants.map(row => row.ref);
  return sealDecisionFixture(fixture);
}
