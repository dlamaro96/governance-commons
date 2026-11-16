// SPDX-License-Identifier: Apache-2.0
// Internal, schema-admitted chain derivation. These values are never capabilities.
import { isDeepStrictEqual } from 'node:util';
import { COMPATIBILITY_ACTIONS, FIELD_ACTIONS, SERVICE_ACTIONS } from './actions.ts';
import { AUTHORITY_ADMISSION_LIMITS as LIMITS } from './admission.ts';
import { canonicalDecisionBytes } from './decision-budget.ts';
import { chainLinkKey, definitionKey, grantKey, policyKey, roleKey, scopeKey, subjectKey, versionKey } from './decision-types.ts';
import type { AuthorityGrant, BudgetPort, ChainPlan, ContainmentEvidence, DecisionInput,
  DecisionNode, EffectCeiling, GroupMembershipEvidence, NodeDecision, NodeId,
  PreparedChain, ResolvedChains } from './decision-types.ts';
import type { ResourceRef, RolePin, Scope, SubjectRef, UTC, Validity } from './types.ts';

const serviceActions = new Set<string>(SERVICE_ACTIONS);
const fieldActions = new Set<string>(FIELD_ACTIONS);
const compatibleActions = new Set<string>(COMPATIBILITY_ACTIONS.flatMap(([actions]) => [...actions]));
const compare = (a: string, b: string): number => a < b ? -1 : a > b ? 1 : 0;
const sameResource = (a: ResourceRef, b: ResourceRef): boolean =>
  a.tenantId === b.tenantId && a.kind === b.kind && a.id === b.id;
const sameSubject = (a: { kind: string; id: string }, b: { kind: string; id: string }): boolean =>
  a.kind === b.kind && a.id === b.id;
const scopeTenant = (s: Scope): string => s.kind === 'resource' ? s.resource.tenantId : s.tenantId;
const nowValid = (v: Validity, now: UTC): boolean =>
  (v.notBefore === null || v.notBefore <= now) && (v.expiresAt === null || now < v.expiresAt);
const liveOrFuture = (g: AuthorityGrant, now: UTC): boolean =>
  g.state === 'active' && (g.validity.expiresAt === null || now < g.validity.expiresAt);
const intervalInside = (child: Validity, parent: Validity): boolean =>
  (parent.notBefore === null || (child.notBefore !== null && parent.notBefore <= child.notBefore)) &&
  (parent.expiresAt === null || (child.expiresAt !== null && child.expiresAt <= parent.expiresAt));
const setInside = <T>(child: readonly T[], parent: readonly T[]): boolean => {
  const permitted = new Set(parent); return child.every(value => permitted.has(value));
};
const fieldsInside = <T>(child: readonly T[] | null, parent: readonly T[] | null): boolean =>
  parent === null || (child !== null && setInside(child, parent));
function intersectIntervals(values: readonly Validity[]): Validity {
  let notBefore: UTC | null = null, expiresAt: UTC | null = null;
  for (const value of values) {
    if (value.notBefore !== null && (notBefore === null || value.notBefore > notBefore)) notBefore = value.notBefore;
    if (value.expiresAt !== null && (expiresAt === null || value.expiresAt < expiresAt)) expiresAt = value.expiresAt;
  }
  return { notBefore, expiresAt };
}

/** Complete candidates are structurally checked before any state/time filtering. */
export function prepareChains(input: DecisionInput, node: DecisionNode, budget: BudgetPort): ChainPlan {
  const { bundle, indexes } = input, now = bundle.snapshot.now;
  const used = new Set<object>(), boundaries = new Set<UTC>(), dependencies = new Set<NodeId>();
  let indeterminate = false;
  function invalid(message: string): never { return budget.fail('invalid', 'scope', '$.grants', message); }
  const record = <T extends object>(value: T | undefined, message: string): T => {
    if (value === undefined) return invalid(message); used.add(value); return value;
  };
  const interval = (value: Validity): void => {
    if (value.notBefore !== null && now < value.notBefore) boundaries.add(value.notBefore);
    if (value.expiresAt !== null && now < value.expiresAt) boundaries.add(value.expiresAt);
  };
  const sameSelections = (issuer: DecisionNode): void => {
    for (const kind of ['purpose', 'environment'] as const) {
      const left = node[kind], right = issuer[kind];
      if (left.status !== right.status) invalid('An issuer decision changes the approved operation context.');
      if (left.status === 'known' && right.status === 'known') {
        const a = record(indexes.contextFacts.get(versionKey(left.value)), 'A consuming context selection is missing.');
        const b = record(indexes.contextFacts.get(versionKey(right.value)), 'An issuer context selection is missing.');
        if (a.kind !== kind || b.kind !== kind || a.value !== b.value || a.state !== b.state ||
            !isDeepStrictEqual(a.validity, b.validity) || !isDeepStrictEqual(a.provenance, b.provenance)) {
          invalid('An issuer decision substitutes a different approved selection or provenance.');
        }
      }
    }
  };
  const principal = (subject: SubjectRef, intervals: Validity[]): boolean => {
    const p = record(indexes.principals.get(subjectKey(subject)), 'A chain principal is missing.');
    if (!sameSubject(p, subject)) return invalid('A chain principal does not match its subject.');
    if (p.kind === 'service') {
      if (p.tenantId !== bundle.snapshot.tenantId) return invalid('A service principal belongs to another tenant.');
      interval(p.validity); intervals.push(p.validity); return p.state === 'active' && nowValid(p.validity, now);
    }
    if (p.membership === null) return false;
    if (p.membership.tenantId !== bundle.snapshot.tenantId || p.membership.identityId !== p.id) {
      return invalid('A principal membership does not match its tenant and identity.');
    }
    interval(p.membership.validity); intervals.push(p.membership.validity);
    return p.active && p.membership.state === 'active' && nowValid(p.membership.validity, now);
  };
  const groupInventory = (subject: SubjectRef): readonly GroupMembershipEvidence[] | null => {
    const inventory = record(indexes.principalGroups.get(subjectKey(subject)), 'Complete direct-group evidence is missing.');
    if (!sameSubject(inventory.subject, subject)) return invalid('Direct-group evidence names a different subject.');
    if (inventory.memberships.status === 'unavailable') { indeterminate = true; return null; }
    const values: GroupMembershipEvidence[] = [];
    for (const ref of inventory.memberships.value) {
      const membership = record(indexes.memberships.get(versionKey(ref)), 'A direct-group membership is missing.');
      if (subject.kind !== 'human' || membership.identityId !== subject.id || membership.tenantId !== bundle.snapshot.tenantId) {
        return invalid('A direct-group membership is disconnected from its subject.');
      }
      const group = record(indexes.groups.get(membership.groupId), 'A group head is missing.');
      if (group.tenantId !== bundle.snapshot.tenantId) return invalid('A group belongs to another tenant.');
      interval(membership.validity);
      if (group.state === 'retired' && membership.state === 'active' &&
          (membership.validity.expiresAt === null || membership.validity.expiresAt > now)) indeterminate = true;
      values.push(membership);
    }
    return values;
  };
  const pathForScope = (scope: Scope): ContainmentEvidence | null => {
    if (scope.kind === 'tenant') return null;
    const anchor = record(indexes.scopeAnchors.get(scopeKey(scope)), 'A scope containment anchor is missing.');
    if (scopeKey(anchor.scope) !== scopeKey(scope)) return invalid('A scope anchor names a different scope.');
    const expected = scope.kind === 'resource' ? scope.resource :
      { tenantId: scope.tenantId, kind: 'domain' as const, id: scope.domainId };
    if (!sameResource(anchor.containment.resource, expected)) return invalid('A scope anchor names a different canonical resource.');
    const containment = anchor.containment;
    if (containment.context === 'current') {
      if (containment.operation !== null) invalid('A current scope anchor cannot borrow a prepared operation.');
    } else {
      const op = containment.operation, consuming = node.resource.containment;
      if (op === null || consuming.context !== containment.context || consuming.operation === null ||
          op.operationId !== consuming.operation.operationId || op.version !== consuming.operation.version ||
          op.planHash !== consuming.operation.planHash ||
          (containment.context === 'proposed' ? op.side !== 'after' : op.side !== 'before' && op.side !== 'original')) {
        invalid('A scope anchor does not belong to this exact prepared operation context.');
      }
      const operation = record(indexes.operations.get(versionKey({ id: op.operationId, version: op.version })), 'A protected scope operation is missing.');
      if (operation.tenantId !== bundle.snapshot.tenantId || operation.planHash !== op.planHash) invalid('A scope anchor changes its protected operation identity.');
      const members = operation.members.filter(member => member.key === op.memberKey && member.side === op.side);
      if (members.length !== 1 || !sameResource(members[0].resource, expected) ||
          members[0].revision !== containment.revision || members[0].securityRevision !== containment.securityRevision ||
          containment.domainPath.status !== 'known' || !isDeepStrictEqual(members[0].domainPath, containment.domainPath.value)) {
        invalid('A scope anchor changes its exact protected member projection.');
      }
      interval(operation.validity);
      if (!nowValid(operation.validity, now)) indeterminate = true;
      // Actor provenance is validated at the consuming context (including issuer ancestry),
      // never replaced by the delegated subject of this attenuation comparison.
    }
    if (anchor.containment.domainPath.status === 'unavailable') { indeterminate = true; return null; }
    if (scope.kind === 'domain' && anchor.containment.domainPath.value[0] !== scope.domainId) {
      return invalid('A domain scope anchor does not begin with its own domain.');
    }
    return anchor.containment;
  };
  const domainContains = (scope: Extract<Scope, { kind: 'domain' }>, resource: ResourceRef,
    containment: ContainmentEvidence): boolean | null => {
    if (!sameResource(resource, containment.resource)) return invalid('Containment evidence names a different resource.');
    if (containment.domainPath.status === 'unavailable') { indeterminate = true; return null; }
    const path = containment.domainPath.value;
    if (path.length > LIMITS.domainPathEntries || new Set(path).size !== path.length) invalid('A canonical domain path is cyclic or exceeds its bound.');
    if (resource.kind === 'domain' && path[0] !== resource.id) return invalid('A domain path does not begin with its own domain.');
    return scope.includeDescendants ? path.includes(scope.domainId) : path[0] === scope.domainId;
  };
  const contains = (parent: Scope, child: Scope): boolean | null => {
    if (scopeTenant(parent) !== scopeTenant(child) || scopeTenant(parent) !== bundle.snapshot.tenantId) return false;
    if (parent.kind === 'tenant') return true;
    if (parent.kind === 'resource') return child.kind === 'resource' && sameResource(parent.resource, child.resource);
    if (child.kind === 'tenant') return false;
    if (child.kind === 'domain' && child.domainId === parent.domainId) return parent.includeDescendants || !child.includeDescendants;
    if (!parent.includeDescendants && child.kind === 'domain') return false;
    const anchor = pathForScope(child);
    if (anchor === null) return null;
    return domainContains(parent, anchor.resource, anchor);
  };
  const attenuates = (parent: Scope, child: Scope): void => {
    if (contains(parent, child) === false) invalid('A child scope widens its connected parent ceiling.');
  };
  const applies = (scope: Scope): boolean => {
    if (scopeTenant(scope) !== node.request.resource.tenantId) return false;
    if (scope.kind === 'tenant') return true;
    if (scope.kind === 'resource') return sameResource(scope.resource, node.request.resource);
    return domainContains(scope, node.request.resource, node.resource.containment) === true;
  };
  const partition = record(indexes.candidates.get(node.id), 'A complete node candidate partition is missing.');
  if (partition.nodeId !== node.id || partition.snapshotDigest !== bundle.snapshot.snapshotDigest ||
      !sameSubject(partition.subject, node.subject) || !isDeepStrictEqual(partition.request, node.request)) {
    invalid('A candidate partition does not match its exact node and snapshot.');
  }
  const paths: PreparedChain[] = [];
  const candidateKeys = new Set<string>();
  for (const candidate of partition.candidates) {
    if (candidateKeys.has(grantKey(candidate))) invalid('A candidate grant occurs more than once.');
    candidateKeys.add(grantKey(candidate));
    const backwards: AuthorityGrant[] = [], seen = new Set<string>();
    let next = candidate;
    while (true) {
      const key = grantKey(next);
      if (seen.has(key)) invalid('A grant chain contains a cycle.');
      seen.add(key);
      const grant = record(indexes.grants.get(key), 'A connected grant record is missing.');
      if (grantKey(grant.ref) !== key || grant.tenantId !== bundle.snapshot.tenantId) invalid('A grant identity or tenant does not match.');
      const expectedKind = grant.kind === 'delegation' || grant.kind === 'elevation' ? grant.kind : 'grant';
      if (grant.ref.kind !== expectedKind) invalid('A grant reference kind does not match its canonical record family.');
      backwards.push(grant);
      if (backwards.length > LIMITS.delegationDepth + 2) budget.fail('profile_limit', 'limit', '$.grants', 'A connected lineage exceeds the admitted depth.');
      if (grant.kind !== 'delegation' && grant.kind !== 'elevation') break;
      next = grant.parent;
    }
    const path = backwards.reverse(), origin = path[0], terminal = path[path.length - 1];
    if (origin.kind === 'delegation' || origin.kind === 'elevation') invalid('A connected chain has no ordinary root.');
    const intervals: Validity[] = [], memberships: GroupMembershipEvidence[] = [], issuerDependencies: NodeId[] = [];
    let effective = principal(node.subject, intervals), role: RolePin | null = null;
    const policies = origin.kind === 'service' ? origin.policies : [];
    let resolvedPolicies = policies;
    const humanPath = origin.kind !== 'service';
    if ((humanPath && node.subject.kind !== 'human') || (!humanPath && node.subject.kind !== 'service')) {
      invalid('A grant origin crosses human and service authority.');
    }
    if (origin.kind === 'ordinary-role') role = origin.role;
    if (origin.kind === 'responsibility') {
      const definition = record(indexes.definitions.get(definitionKey('responsibility-type', origin.type.id, origin.type.version)), 'An exact responsibility type is missing.');
      if (definition.kind !== 'responsibility-type' || definition.tenantId !== bundle.snapshot.tenantId ||
          !isDeepStrictEqual(definition.content.grantsRole, origin.mappedRole)) invalid('A responsibility assignment changed its immutable role mapping.');
      if (definition.state === 'retired' && liveOrFuture(origin, now)) indeterminate = true;
      role = origin.mappedRole;
      if (role === null) {
        if (origin.effectiveGrantId !== null || origin.delegable !== null || path.length !== 1) invalid('Documentation-only responsibility cannot create a grant chain.');
      } else if (origin.effectiveGrantId !== origin.ref.id) invalid('A responsibility effective grant does not match its canonical association.');
    }
    if (role !== null) {
      const definition = record(indexes.definitions.get(roleKey(role)), 'An exact role definition is missing.');
      if (definition.kind !== 'role' || definition.tenantId !== bundle.snapshot.tenantId) invalid('A role pin resolves to the wrong definition.');
      if (definition.state === 'retired' && liveOrFuture(origin, now)) indeterminate = true;
      resolvedPolicies = definition.content.policies;
    }
    if (origin.kind === 'service') {
      if (origin.beneficiary.kind !== 'service' || !sameSubject(origin.beneficiary, node.subject) || path.length !== 1) {
        invalid('A service grant cannot become a human or delegated parent.');
      }
      const assignment = record(indexes.serviceAssignments.get(versionKey(origin.assignment)), 'A service grant assignment is missing.');
      if (assignment.tenantId !== bundle.snapshot.tenantId || assignment.serviceId !== node.subject.id) invalid('A service assignment belongs to another principal.');
      interval(assignment.validity); intervals.push(assignment.validity);
      effective = effective && assignment.state === 'active' && nowValid(assignment.validity, now);
      const consumer = node.mode === 'resource-wide-deny'
        ? record(indexes.nodes.get(node.guardOrigin ?? ''), 'A service deny guard origin is missing.') : node;
      if (consumer.service === null || versionKey(consumer.service.assignment) !== versionKey(origin.assignment)) {
        invalid('A service grant does not match the exact selected service assignment.');
      }
    }
    const membershipFor = (subject: SubjectRef, groupId: string, exact: string | null): boolean => {
      const inventory = groupInventory(subject);
      if (inventory === null) return false;
      const matches = inventory.filter(m => m.groupId === groupId && (exact === null || versionKey(m.ref) === exact));
      if (exact !== null && matches.length !== 1) invalid('A group-parent chain lacks its exact direct membership.');
      // Multiple historical memberships may be retained; each candidate validity remains visible.
      for (const m of matches) { if (!memberships.includes(m)) memberships.push(m); }
      const active = matches.filter(m => m.state === 'active' && nowValid(m.validity, now) && indexes.groups.get(m.groupId)?.state === 'active');
      if (exact !== null) intervals.push(matches[0].validity);
      else if (active.length === 1) intervals.push(active[0].validity);
      else if (active.length > 1) invalid('Overlapping direct memberships cannot ambiguously prove one grant path.');
      return active.length === 1;
    };
    if (terminal.beneficiary.kind === 'group') {
      effective = membershipFor(node.subject, terminal.beneficiary.id, null) && effective;
    } else if (!sameSubject(terminal.beneficiary, node.subject)) invalid('A terminal grant names a different beneficiary.');
    const people = new Set<string>();
    if (origin.beneficiary.kind === 'human') people.add(origin.beneficiary.id);
    let delegationDepth = 0;
    for (let i = 0; i < path.length; i++) {
      const grant = path[i];
      if ((grant.kind === 'ordinary-role' || grant.kind === 'responsibility') && grant.issuer.kind !== 'human') invalid('An ordinary human grant has nonhuman issuance provenance.');
      if (scopeTenant(grant.scope) !== bundle.snapshot.tenantId || scopeTenant(grant.ceiling.scope) !== bundle.snapshot.tenantId) invalid('A grant scope belongs to another tenant.');
      attenuates(grant.ceiling.scope, grant.scope);
      interval(grant.validity); interval(grant.ceiling.validity); intervals.push(grant.validity, grant.ceiling.validity);
      effective = grant.state === 'active' && nowValid(grant.validity, now) && nowValid(grant.ceiling.validity, now) && effective;
      if (grant.ceiling.actions.some(a => humanPath ? serviceActions.has(a) : !serviceActions.has(a) && !fieldActions.has(a))) {
        invalid('A grant effect ceiling crosses non-field action families.');
      }
      if ('delegable' in grant && grant.delegable !== null) {
        const d = grant.delegable;
        if (d.actions.some(a => serviceActions.has(a) || fieldActions.has(a)) || !setInside(d.actions, grant.ceiling.actions) ||
            !fieldsInside(d.fields, grant.ceiling.fields) || !intervalInside(d.validity, grant.validity) ||
            !intervalInside(d.validity, grant.ceiling.validity) || !Number.isInteger(d.remainingDepth) || d.remainingDepth < 0 || d.remainingDepth > LIMITS.delegationDepth) {
          invalid('An onward delegation ceiling widens its effective grant.');
        }
        attenuates(grant.scope, d.scope); attenuates(grant.ceiling.scope, d.scope); interval(d.validity);
      }
      if (i === 0) continue;
      const parent = path[i - 1];
      if ((grant.kind !== 'delegation' && grant.kind !== 'elevation') || parent.kind === 'elevation' || parent.kind === 'service' ||
          grantKey(grant.parent) !== grantKey(parent.ref) || !('delegable' in parent) || parent.delegable === null) {
        invalid('A child does not have an explicitly delegable ordinary parent.');
      }
      if (grant.issuer.kind !== 'human' || grant.beneficiary.kind !== 'human') invalid('Delegation and elevation require human endpoints.');
      const link = record(indexes.chainLinks.get(chainLinkKey(node.id, grant.ref)), 'An exact consuming-node issuer dependency is missing.');
      if (link.nodeId !== node.id || grantKey(link.child) !== grantKey(grant.ref) || grantKey(link.parent) !== grantKey(parent.ref)) invalid('A chain link has disconnected references.');
      if (parent.beneficiary.kind === 'group') {
        if (link.viaMembership === null) invalid('A group parent requires an exact direct membership.');
        effective = membershipFor(grant.issuer, parent.beneficiary.id, versionKey(link.viaMembership)) && effective;
        people.add(grant.issuer.id);
      } else if (!sameSubject(parent.beneficiary, grant.issuer) || link.viaMembership !== null) invalid('A child issuer is not its immediate parent beneficiary.');
      if (people.has(grant.beneficiary.id)) invalid('A connected lineage repeats an issuer or beneficiary.');
      people.add(grant.beneficiary.id);
      effective = principal(grant.issuer, intervals) && principal(grant.beneficiary, intervals) && effective;
      const issuer = record(indexes.nodes.get(link.issuerDecision), 'A full issuer decision is missing.');
      if (issuer.mode !== 'authorize' || !sameSubject(issuer.subject, grant.issuer) ||
          !isDeepStrictEqual(issuer.request, node.request) || !isDeepStrictEqual(issuer.resource.containment, node.resource.containment) ||
          issuer.authentication.kind !== 'live-issuer' || grantKey(issuer.authentication.childGrant) !== grantKey(grant.ref)) {
        invalid('An issuer decision does not match the complete consuming request and child grant.');
      }
      sameSelections(issuer);
      dependencies.add(issuer.id); issuerDependencies.push(issuer.id);
      if (!setInside(grant.ceiling.actions, parent.ceiling.actions) || !setInside(grant.ceiling.actions, parent.delegable.actions) ||
          !setInside(grant.ceiling.resourceKinds, parent.ceiling.resourceKinds) ||
          !fieldsInside(grant.ceiling.fields, parent.ceiling.fields) || !fieldsInside(grant.ceiling.fields, parent.delegable.fields) ||
          !intervalInside(grant.validity, parent.validity) || !intervalInside(grant.validity, parent.ceiling.validity) ||
          !intervalInside(grant.validity, parent.delegable.validity) || !intervalInside(grant.ceiling.validity, parent.ceiling.validity)) {
        invalid('A child widens its parent effect or explicit delegable ceiling.');
      }
      attenuates(parent.scope, grant.scope); attenuates(parent.ceiling.scope, grant.scope); attenuates(parent.delegable.scope, grant.scope);
      attenuates(parent.ceiling.scope, grant.ceiling.scope); attenuates(parent.delegable.scope, grant.ceiling.scope);
      intervals.push(parent.delegable.validity);
      if (grant.kind === 'delegation') {
        delegationDepth++;
        if (parent.delegable.remainingDepth < 1 || (grant.delegable !== null && grant.delegable.remainingDepth >= parent.delegable.remainingDepth)) {
          invalid('A delegation does not reduce the connected remaining depth.');
        }
      } else {
        if (i !== path.length - 1 || grant.ceiling.actions.some(a => !compatibleActions.has(a)) || grant.validity.expiresAt === null) {
          invalid('An elevation must be terminal, finite and compatibility-action-only.');
        }
        if (grant.use === null) effective = false;
        else {
          const use = grant.use, auth = node.authentication;
          const sessionRef = auth.kind === 'human-session' ? { id: auth.sessionId, version: auth.sessionVersion }
            : auth.kind === 'live-issuer' || auth.kind === 'scan-initiator' ? auth.elevationSession : null;
          if (use.identityId !== grant.beneficiary.id || use.generation !== bundle.snapshot.generation ||
              !intervalInside(use.validity, grant.validity)) invalid('An elevation use is disconnected or widens its grant.');
          interval(use.validity); intervals.push(use.validity);
          const session = record(indexes.sessions.get(versionKey({ id: use.sessionId, version: use.sessionVersion })), 'The exact elevation-use session is missing.');
          if (session.identityId !== use.identityId || session.selectedTenantId !== bundle.snapshot.tenantId || session.generation !== use.generation ||
              !intervalInside(use.validity, session.validity)) invalid('An elevation use does not match its exact current session.');
          interval(session.validity); intervals.push(session.validity);
          effective = effective && session.state === 'active' && nowValid(session.validity, now) &&
            sessionRef !== null && sessionRef.id === use.sessionId && sessionRef.version === use.sessionVersion;
          effective = effective && use.state === 'active' && nowValid(use.validity, now);
        }
      }
    }
    if (delegationDepth > LIMITS.delegationDepth) budget.fail('profile_limit', 'limit', '$.grants', 'A delegation path exceeds four edges.');
    for (const pin of resolvedPolicies) {
      const policy = record(indexes.policies.get(policyKey(pin)), 'An exact immutable policy pin is missing.');
      if (policy.tenantId !== bundle.snapshot.tenantId || policyKey(policy.pin) !== policyKey(pin) || !input.parsedPolicies.has(policyKey(pin))) {
        invalid('A policy pin does not resolve to its checked canonical definition.');
      }
      if (policy.state === 'retired' && liveOrFuture(origin, now)) indeterminate = true;
      for (const intent of policy.resourceWideIntents) {
        if (!intent.resourceKinds.includes(node.request.resource.kind)) continue;
        const requiredActions = intent.expandedActions.filter(action => {
          const registration = input.registry.actions.find(row => row.action === action);
          if (registration === undefined) return invalid('A marked intent action is not registered.');
          return registration.resourceKinds.includes(node.request.resource.kind);
        });
        for (let i = 0; i < path.length; i++) {
          const grant = path[i], consumed = i < path.length - 1 && 'delegable' in grant ? grant.delegable : null;
          if (grant.ceiling.fields !== null || (consumed !== null && consumed.fields !== null)) {
            invalid('A resource-wide intent cannot be restricted to a finite consumed lineage field set.');
          }
          if (grant.ceiling.resourceKinds.includes(node.request.resource.kind) && !setInside(requiredActions, grant.ceiling.actions)) {
            invalid('A resource-wide intent cannot be narrowed to a partial action ceiling on the applicable kind.');
          }
        }
      }
    }
    const auth = node.authentication;
    if (auth.kind === 'human-session') {
      const session = record(indexes.sessions.get(versionKey({ id: auth.sessionId, version: auth.sessionVersion })), 'A selected session is missing.');
      if (node.subject.kind !== 'human' || session.identityId !== node.subject.id || session.selectedTenantId !== bundle.snapshot.tenantId || session.generation !== bundle.snapshot.generation) invalid('A selected session does not match the chain subject.');
      interval(session.validity); intervals.push(session.validity); effective = effective && session.state === 'active' && nowValid(session.validity, now);
    } else if (auth.kind === 'service-credential') {
      const credential = record(indexes.credentials.get(versionKey({ id: auth.credentialId, version: auth.credentialVersion })), 'A selected service credential is missing.');
      if (node.subject.kind !== 'service' || credential.serviceId !== node.subject.id || credential.tenantId !== bundle.snapshot.tenantId || credential.generation !== bundle.snapshot.generation) invalid('A selected service credential does not match the chain subject.');
      interval(credential.validity); intervals.push(credential.validity); effective = effective && credential.state === 'active' && nowValid(credential.validity, now);
    }
    const ceiling: EffectCeiling = { ...terminal.ceiling, scope: terminal.scope,
      validity: intersectIntervals(intervals) };
    const consumedScopes = path.flatMap((grant, index) => [grant.scope, grant.ceiling.scope,
      ...(index < path.length - 1 && 'delegable' in grant && grant.delegable !== null ? [grant.delegable.scope] : [])]);
    // Structural issuance containment does not replace each live parent's ceiling in
    // the current/proposed/original request context, especially after a scope move.
    const allScopesApply = consumedScopes.map(applies).every(Boolean);
    const requestApplicable = allScopesApply && ceiling.actions.includes(node.request.action) &&
      ceiling.resourceKinds.includes(node.request.resource.kind) &&
      (node.request.field === null || ceiling.fields === null || ceiling.fields.includes(node.request.field));
    effective = requestApplicable && effective;
    // Charge the complete expansion, including future/inactive/nonmatching paths.
    budget.charge('bindingInstances', resolvedPolicies.length, '$.candidates');
    budget.charge('roleInstances', role === null ? 0 : 1, '$.candidates');
    budget.charge('lineageEdgeOccurrences', (path.length - 1) * (resolvedPolicies.length + (role === null ? 0 : 1)), '$.candidates');
    budget.charge('dependencyReferences', issuerDependencies.length * (resolvedPolicies.length + (role === null ? 0 : 1)), '$.candidates');
    const prepared: PreparedChain = { terminal, origin, path, role, policies: resolvedPolicies, memberships,
      issuerDependencies, effectiveScope: terminal.scope, effectiveValidity: ceiling.validity, ceiling, requestApplicable, currentlyEffective: effective };
    const preparedBytes = canonicalDecisionBytes({ terminal: terminal.ref, origin: origin.ref, path: path.map(g => g.ref),
      role, policies: resolvedPolicies, memberships: memberships.map(m => m.ref), issuerDependencies,
      effectiveScope: prepared.effectiveScope, effectiveValidity: prepared.effectiveValidity, ceiling, requestApplicable, currentlyEffective: effective });
    budget.retain('compiled', preparedBytes, '$.candidates'); budget.charge('proofBytes', preparedBytes, '$.candidates');
    paths.push(prepared);
  }
  return { nodeId: node.id, paths, dependencies: [...dependencies].sort(), indeterminate,
    boundaries: [...boundaries].sort(), usedRecords: used };
}

/** Issuer denials disable only their dependent path; unknown issuer results cannot allow. */
export function resolveChains(input: DecisionInput, plan: ChainPlan,
  decisions: ReadonlyMap<NodeId, NodeDecision>, budget: BudgetPort): ResolvedChains {
  const node = input.indexes.nodes.get(plan.nodeId);
  if (node === undefined) return budget.fail('invalid', 'required', '$.nodes', 'A prepared chain node is missing.');
  const boundaries = new Set(plan.boundaries), roles = new Map<string, RolePin>();
  const bindings: ResolvedChains['bindings'][number][] = [];
  let indeterminate = plan.indeterminate;
  for (const prepared of plan.paths) {
    let effective = prepared.currentlyEffective;
    for (const id of prepared.issuerDependencies) {
      const decision = decisions.get(id);
      if (decision === undefined || decision.nodeId !== id || decision.mode !== 'authorize') {
        return budget.fail('invalid', 'required', '$.chainLinks', 'A full issuer authorization result is missing.');
      }
      if (decision.validUntil !== null && decision.validUntil > input.bundle.snapshot.now) boundaries.add(decision.validUntil);
      if (decision.reason === 'indeterminate') indeterminate = true;
      if (!decision.allowed) effective = false;
    }
    if (!effective) continue;
    if (prepared.role !== null) roles.set(roleKey(prepared.role), prepared.role);
    for (const policy of prepared.policies) bindings.push({ nodeId: plan.nodeId, terminal: prepared.terminal.ref,
      origin: prepared.origin.ref, path: prepared.path.map(g => g.ref), role: prepared.role, policy,
      effectiveScope: prepared.effectiveScope, effectiveValidity: prepared.effectiveValidity, ceiling: prepared.ceiling });
  }
  bindings.sort((a, b) => compare(grantKey(a.terminal), grantKey(b.terminal)) || compare(policyKey(a.policy), policyKey(b.policy)));
  const requestRoles: ResolvedChains['requestRoles'] = indeterminate ? { status: 'unavailable' } :
    { status: 'known', value: { subject: node.subject, request: node.request, roles: [...roles.values()].sort((a, b) => compare(roleKey(a), roleKey(b))) } };
  const resolvedBytes = canonicalDecisionBytes({ bindings, requestRoles });
  budget.retain('compiled', resolvedBytes, '$.candidates'); budget.charge('proofBytes', resolvedBytes, '$.candidates');
  return { bindings, requestRoles, boundaries: [...boundaries].sort(), indeterminate };
}
