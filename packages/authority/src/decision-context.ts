// SPDX-License-Identifier: Apache-2.0
import { createHash } from 'node:crypto';
import { FIELD_ACTIONS, SERVICE_ACTIONS, type ActionId, type ServiceActionId } from './actions.ts';
import type { ExpressionFacts, Fact as ExpressionFact } from './expressions.ts';
import { DecisionInputError, subjectKey, versionKey } from './decision-types.ts';
import type { AdapterRegistration, AuthorityDecisionRegistry, BudgetPort, ContextPlan, DecisionCatalogs,
  DecisionInput, DecisionNode, DecisionReason, Fact, FactRef, NodeDescriptor, NodeId, OriginSelection,
  PrincipalEvidence, SelectedNodeEvidence, ServiceIdentity, ServiceUse, SnapshotRef, VersionRef,
  LeaseEvidence, ServiceAssignmentEvidence, ContextFact, ApprovedSetFact } from './decision-types.ts';
import type { Digest, ResourceRef, SubjectRef, UTC, UUID, Validity } from './types.ts';

const fields = new Set<string>(FIELD_ACTIONS), services = new Set<string>(SERVICE_ACTIONS);
function invalid(message: string, code: 'scope' | 'required' | 'duplicate' | 'version' | 'unsupported' = 'scope'): never {
  throw new DecisionInputError(code === 'unsupported' ? 'unsupported' : 'invalid', { code, path: '', message });
}
function requireValue(condition: unknown, message: string): asserts condition { if (!condition) invalid(message); }
function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(',')}}`;
}
const same = (a: unknown, b: unknown): boolean => canonical(a) === canonical(b);
const digest = (value: unknown): Digest => createHash('sha256').update(canonical(value)).digest('hex') as Digest;
const sameSubject = (a: SubjectRef, b: SubjectRef): boolean => a.kind === b.kind && a.id === b.id;
const sameResource = (a: ResourceRef, b: ResourceRef): boolean => a.tenantId === b.tenantId && a.kind === b.kind && a.id === b.id;
const live = (v: Validity, now: UTC): boolean => (v.notBefore === null || v.notBefore <= now) && (v.expiresAt === null || now < v.expiresAt);
function one<T>(rows: readonly T[], predicate: (row: T) => boolean, name: string): T {
  const found = rows.filter(predicate);
  if (found.length !== 1) invalid(`Expected one exact ${name} record.`, found.length ? 'duplicate' : 'required');
  return found[0];
}
function byRef<T extends { ref: VersionRef }>(rows: readonly T[], ref: VersionRef, name: string): T {
  return one(rows, row => versionKey(row.ref) === versionKey(ref), name);
}
function byVersion<T extends VersionRef>(rows: readonly T[], ref: VersionRef, name: string): T {
  return one(rows, row => versionKey(row) === versionKey(ref), name);
}
function sortedUnique<T>(values: readonly T[], key: (value: T) => string): readonly T[] {
  const found = new Map<string, T>();
  for (const value of values) {
    const k = key(value), prior = found.get(k);
    if (prior && !same(prior, value)) invalid('Conflicting selected evidence.', 'duplicate');
    found.set(k, value);
  }
  return [...found.entries()].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([, row]) => row);
}
function serviceIdentity(use: ServiceUse | null): ServiceIdentity | null {
  if (use === null) return null;
  if ('initiatingDecision' in use) { const { initiatingDecision: ignored, ...identity } = use; void ignored; return identity; }
  return use;
}
function originSelection(origin: NodeDescriptor): OriginSelection {
  return { subject: origin.subject, request: origin.request, authentication: origin.authentication,
    containment: origin.resource.containment, purpose: origin.purpose, environment: origin.environment,
    serviceIdentity: serviceIdentity(origin.service) };
}
function verifyOrigin(node: NodeDescriptor, origin: NodeDescriptor | null): void {
  if (node.mode === 'authorize') { requireValue(origin === null && node.guardOrigin === null, 'Authorize nodes cannot borrow a guard origin.'); return; }
  requireValue(origin !== null && origin.mode === 'authorize' && origin.guardOrigin === null, 'Guard origin must be an authorize context.');
  requireValue(sameSubject(node.subject, origin.subject) && same(node.authentication, origin.authentication)
    && sameResource(node.request.resource, origin.request.resource) && node.request.revision === origin.request.revision
    && same(node.resource.containment, origin.resource.containment) && same(node.purpose, origin.purpose)
    && same(node.environment, origin.environment) && node.request.field === null
    && node.projection === null && node.service === null && node.intentGuard === null, 'Guard origin remap changed protected context.');
}

/** Internal selector over schema-admitted records. No grants or decisions are
 * accepted here; the public identity helper performs defensive admission first. */
export function selectNodeEvidence(snapshot: SnapshotRef, node: NodeDescriptor, catalogs: DecisionCatalogs,
  registry: AuthorityDecisionRegistry, origin: NodeDescriptor | null): SelectedNodeEvidence {
  verifyOrigin(node, origin);
  const principal = one(catalogs.principals, row => row.kind === node.subject.kind && row.id === node.subject.id, 'principal');
  const groups = one(catalogs.principalGroups, row => sameSubject(row.subject, node.subject), 'principal group partition');
  const memberships = groups.memberships.status === 'known'
    ? groups.memberships.value.map(ref => byRef(catalogs.memberships, ref, 'group membership')) : [];
  const groupHeads = memberships.map(row => one(catalogs.groups, group => group.id === row.groupId, 'group head'));
  const authentication = node.authentication;
  const sessionRef = authentication.kind === 'human-session'
    ? { id: authentication.sessionId, version: authentication.sessionVersion }
    : authentication.kind === 'live-issuer' || authentication.kind === 'scan-initiator' ? authentication.elevationSession : null;
  const session = sessionRef === null ? null : byVersion(catalogs.sessions, sessionRef, 'session');
  const credential = authentication.kind === 'service-credential'
    ? [byVersion(catalogs.credentials, { id: authentication.credentialId, version: authentication.credentialVersion }, 'credential')] : [];
  const approvedSets: ApprovedSetFact[] = [];
  for (const [kind, partition] of [['classifications', node.resource.classifications], ['approved-tags', node.resource.approvedTags]] as const) {
    if (partition.status === 'known') for (const ref of partition.value) {
      const fact = byRef(catalogs.approvedFacts, ref, 'approved fact');
      requireValue(fact.kind === kind, 'Approved fact kind does not match its partition.'); approvedSets.push(fact);
    }
  }
  const contexts: ContextFact[] = [];
  for (const [kind, selection] of [['purpose', node.purpose], ['environment', node.environment]] as const) {
    if (selection.status === 'known') {
      const fact = byRef(catalogs.contextFacts, selection.value, 'context fact');
      requireValue(fact.kind === kind, 'Context fact kind does not match its selection.'); contexts.push(fact);
    }
  }
  const op = node.resource.containment.operation;
  const operation = op === null ? null : byVersion(catalogs.operations, { id: op.operationId, version: op.version }, 'operation');
  const path = node.projection?.path;
  const reference = path?.kind === 'registered-reference'
    ? byVersion(catalogs.references, { id: path.referenceId, version: path.referenceVersion }, 'reference') : null;
  const adapter = one(registry.adapters, row => row.id === node.adapterId, 'adapter');
  requireValue(node.ceilingRefs.length === adapter.ceilings.length, 'Incomplete ceiling selection.');
  const ceilingRecords = adapter.ceilings.map(slot => {
    const ref = one(node.ceilingRefs, row => row.slot === slot.slot, 'ceiling slot');
    return { slot: slot.slot, kind: slot.kind, record: slot.kind === 'visibility'
      ? one(catalogs.visibility, row => row.id === ref.recordId, 'visibility')
      : one(catalogs.creators, row => row.id === ref.recordId, 'creator') };
  }).sort((a, b) => a.slot < b.slot ? -1 : a.slot > b.slot ? 1 : 0);
  const selected: SelectedNodeEvidence = { principal, groupPartition: groups, ceilings: ceilingRecords, journalOperation: null, groupHeads: sortedUnique(groupHeads, row => row.id),
    groupMemberships: sortedUnique(memberships, row => versionKey(row.ref)), session, credential,
    approvedSets: sortedUnique(approvedSets, row => versionKey(row.ref)), contexts: sortedUnique(contexts, row => versionKey(row.ref)),
    operation, reference, sources: [], jobs: [], claims: [], leases: [], projectionEvents: [], journalClaim: null,
    terminal: null, originSelection: origin === null ? null : originSelection(origin), leaseIssuers: [], serviceAssignments: [], servicePrincipals: [] };
  const use = origin?.service ?? node.service;
  if (use !== null) {
    const assignments = [byRef(catalogs.serviceAssignments, use.assignment, 'service assignment')];
    const servicePrincipals: Extract<PrincipalEvidence, { kind: 'service' }>[] = [];
    const leaseIssuers: SelectedNodeEvidence['leaseIssuers'][number][] = [], leases: LeaseEvidence[] = [];
    if ('source' in use) selected.sources = [byRef(catalogs.sources, use.source, 'source')];
    if ('job' in use) selected.jobs = [byRef(catalogs.jobs, use.job, 'job')];
    if ('claim' in use && use.kind !== 'audit' && use.kind !== 'outbox') selected.claims = [byRef(catalogs.claims, use.claim, 'claim')];
    if ('lease' in use) {
      let ref: VersionRef | null = use.lease;
      const visited = new Set<string>();
      while (ref !== null) {
        const key = versionKey(ref); requireValue(!visited.has(key), 'Lease lineage contains a cycle.'); visited.add(key);
        const lease: LeaseEvidence = byRef(catalogs.leases, ref, 'lease'); leases.push(lease);
        assignments.push(byRef(catalogs.serviceAssignments, lease.assignment, 'lease assignment'));
        credential.push(byVersion(catalogs.credentials, { id: lease.credentialId, version: lease.credentialVersion }, 'lease credential'));
        if (lease.issuer.kind === 'gateway') leaseIssuers.push(byRef(registry.leaseIssuers, lease.issuer.registration, 'lease issuer'));
        else {
          assignments.push(byRef(catalogs.serviceAssignments, lease.issuer.assignment, 'parent assignment'));
          credential.push(byVersion(catalogs.credentials, lease.issuer.credential, 'parent credential'));
        }
        ref = lease.parentLease;
      }
    }
    if ('event' in use) selected.projectionEvents = [byRef(catalogs.projectionEvents, use.event, 'projection event')];
    if (use.kind === 'audit' || use.kind === 'outbox') {
      const claim = byRef(catalogs.journalClaims, use.claim, 'journal claim');
      const { parentDecisions: ignored, ...identity } = claim; void ignored; selected.journalClaim = identity;
      selected.journalOperation = byVersion(catalogs.operations, { id: claim.operationId, version: claim.operationVersion }, 'journal operation');
    }
    if (use.kind === 'terminal-replay') {
      const terminal = byRef(catalogs.terminals, use.terminal, 'terminal'); selected.terminal = terminal;
      if (terminal.claim !== null) selected.claims = [byRef(catalogs.claims, terminal.claim, 'terminal claim')];
    }
    for (const assignment of assignments) {
      const p = one(catalogs.principals, row => row.kind === 'service' && row.id === assignment.serviceId, 'assigned service');
      requireValue(p.kind === 'service', 'Assignment does not resolve a service principal.'); servicePrincipals.push(p);
    }
    selected.serviceAssignments = sortedUnique(assignments, row => versionKey(row.ref));
    selected.servicePrincipals = sortedUnique(servicePrincipals, row => row.id);
    selected.credential = sortedUnique(credential, row => versionKey(row));
    selected.leases = sortedUnique(leases, row => versionKey(row.ref));
    selected.leaseIssuers = sortedUnique(leaseIssuers, row => versionKey(row.ref));
  }
  requireValue(node.request.resource.tenantId === snapshot.tenantId, 'Node is outside the snapshot tenant.');
  for (const row of [...selected.groupHeads, ...selected.groupMemberships, ...selected.approvedSets.map(row => row.provenance),
    ...selected.contexts.map(row => row.provenance), ...selected.sources, ...selected.jobs, ...selected.claims,
    ...selected.leases, ...selected.projectionEvents, ...selected.serviceAssignments, ...selected.leaseIssuers]) {
    requireValue(row.tenantId === snapshot.tenantId, 'Selected evidence is outside the snapshot tenant.');
  }
  return selected;
}

class ContextWork {
  readonly reasons = new Set<DecisionReason>();
  readonly boundaries = new Set<UTC>();
  readonly used = new Set<object>();
  readonly dependencies: NodeId[] = [];
  constructor(readonly input: DecisionInput, readonly node: DecisionNode, readonly budget: BudgetPort) {}
  use<T extends object>(record: T): T { this.used.add(record); return record; }
  validity(value: Validity): boolean {
    for (const boundary of [value.notBefore, value.expiresAt]) if (boundary !== null && boundary > this.input.bundle.snapshot.now) this.boundaries.add(boundary);
    return live(value, this.input.bundle.snapshot.now);
  }
  deny(reason: DecisionReason): void { this.reasons.add(reason); }
  future(value: UTC): void { if (value > this.input.bundle.snapshot.now) this.boundaries.add(value); }
  require(condition: unknown, message: string): asserts condition { if (!condition) this.budget.fail('invalid', 'scope', '', message); }
  dependency(id: NodeId): DecisionNode {
    const node = this.input.indexes.nodes.get(id);
    if (!node) invalid('Required context dependency is missing.', 'required');
    requireValue(node.mode === 'authorize', 'A clear guard is not authorization.');
    this.dependencies.push(id); return node;
  }
}
function trackSelected(work: ContextWork, selected: SelectedNodeEvidence): void {
  for (const value of Object.values(selected)) {
    if (Array.isArray(value)) for (const record of value) work.use(record);
    else if (value !== null && typeof value === 'object' && value !== selected.originSelection && value !== selected.journalClaim) work.use(value);
  }
  for (const ceiling of selected.ceilings) work.use(ceiling.record);
  const partition = one(work.input.bundle.principalGroups, row => sameSubject(row.subject, work.node.subject), 'principal groups'); work.use(partition);
  const use = work.node.mode === 'resource-wide-deny'
    ? work.input.indexes.nodes.get(work.node.guardOrigin!)?.service : work.node.service;
  if (use?.kind === 'audit' || use?.kind === 'outbox') work.use(byRef(work.input.bundle.journalClaims, use.claim, 'journal claim'));
}
function authenticate(work: ContextWork, selected: SelectedNodeEvidence, adapter: AdapterRegistration, origin: DecisionNode | null): void {
  const { node, input } = work, { snapshot } = input.bundle, principal = selected.principal;
  const auth = node.authentication;
  if (principal.kind === 'human') {
    requireValue(node.subject.kind === 'human' && auth.kind !== 'service-credential', 'Human authentication kind mismatch.');
    if (!principal.active) work.deny('inactive_subject');
    if (principal.membership === null) work.deny('tenant_denied');
    else {
      requireValue(principal.membership.tenantId === snapshot.tenantId && principal.membership.identityId === principal.id,
        'Tenant membership association mismatch.');
      if (!work.validity(principal.membership.validity) || principal.membership.state !== 'active') work.deny('tenant_denied');
    }
    if (auth.kind === 'live-issuer') {
      const grant = one(input.bundle.grants, row => same(row.ref, auth.childGrant), 'issuer child grant'); work.use(grant);
      requireValue((grant.kind === 'delegation' || grant.kind === 'elevation') && sameSubject(grant.issuer, node.subject), 'Live issuer is unrelated to the child grant.');
    } else if (auth.kind === 'scan-initiator') {
      const job = byRef(input.bundle.jobs, { id: auth.jobId, version: auth.jobVersion }, 'initiator job'); work.use(job);
      requireValue(job.initiatingIdentityId === principal.id && job.tenantId === snapshot.tenantId
        && (origin ?? node).request.action === 'source:scan.request' && node.request.resource.kind === 'source'
        && node.request.resource.id === job.sourceId, 'Scan initiator context is not the current job actor/source.');
      work.future(job.deadlineAt);
    }
    if (auth.kind === 'human-session' || auth.elevationSession !== null) {
      const session = selected.session; requireValue(session !== null, 'Exact current session evidence is missing.');
      requireValue(session.identityId === principal.id && session.selectedTenantId === snapshot.tenantId, 'Session subject/tenant mismatch.');
      if (auth.kind !== 'human-session') requireValue(adapter.dependencyElevation === 'exact-live-session', 'This derived context cannot activate elevation.');
      const current = work.validity(session.validity);
      if (!current && session.validity.expiresAt !== null && session.validity.expiresAt <= snapshot.now) work.deny('expired');
      else if (!current || session.state !== 'active' || session.generation !== snapshot.generation) work.deny('ceiling_denied');
    }
  } else {
    requireValue(node.subject.kind === 'service' && auth.kind === 'service-credential', 'Service authentication kind mismatch.');
    requireValue(principal.tenantId === snapshot.tenantId, 'Service tenant mismatch.');
    if (!work.validity(principal.validity) || principal.state !== 'active') work.deny('inactive_subject');
    const credential = one(selected.credential, row => row.id === auth.credentialId && row.version === auth.credentialVersion, 'selected credential');
    requireValue(credential.serviceId === principal.id && credential.tenantId === snapshot.tenantId, 'Service credential owner mismatch.');
    const current = work.validity(credential.validity);
    if (!current && credential.validity.expiresAt !== null && credential.validity.expiresAt <= snapshot.now) work.deny('expired');
    else if (!current || credential.state !== 'active' || credential.generation !== snapshot.generation) work.deny('ceiling_denied');
  }
}
function groupFacts(work: ContextWork, selected: SelectedNodeEvidence): ExpressionFact<readonly UUID[]> {
  const partition = one(work.input.bundle.principalGroups, row => sameSubject(row.subject, work.node.subject), 'groups');
  if (partition.memberships.status === 'unavailable') return { status: 'unavailable' };
  requireValue(work.node.subject.kind === 'human' || partition.memberships.value.length === 0, 'Service principals do not inherit human groups.');
  const result = new Set<UUID>(), now = work.input.bundle.snapshot.now;
  for (const membership of selected.groupMemberships) {
    requireValue(membership.identityId === work.node.subject.id, 'Group membership subject mismatch.');
    const group = one(selected.groupHeads, row => row.id === membership.groupId, 'selected group');
    const current = work.validity(membership.validity);
    if (group.state === 'retired' && membership.state === 'active'
      && (membership.validity.expiresAt === null || membership.validity.expiresAt > now)) work.deny('indeterminate');
    if (current && membership.state === 'active' && group.state === 'active') result.add(group.id);
  }
  return { status: 'known', value: [...result].sort() };
}
function operationActor(work: ContextWork, context: DecisionNode, actor: SubjectRef, seen = new Set<NodeId>()): boolean {
  if (sameSubject(context.subject, actor)) return true;
  if (seen.has(context.id) || seen.size >= 128) return false;
  const next = new Set(seen).add(context.id);
  if (context.mode === 'resource-wide-deny') {
    const origin = context.guardOrigin === null ? undefined : work.input.indexes.nodes.get(context.guardOrigin);
    return origin !== undefined && origin.intentGuard === context.id && operationActor(work, origin, actor, next);
  }
  const auth = context.authentication;
  if (auth.kind !== 'live-issuer') return false;
  const links = work.input.bundle.chainLinks.filter(link => link.issuerDecision === context.id && same(link.child, auth.childGrant));
  return links.length > 0 && links.every(link => {
    const consumer = work.input.indexes.nodes.get(link.nodeId);
    return consumer !== undefined && same(consumer.resource.containment, context.resource.containment)
      && operationActor(work, consumer, actor, next);
  });
}
function containment(work: ContextWork, selected: SelectedNodeEvidence, adapter: AdapterRegistration): void {
  const { node } = work, resource = node.resource, anchor = resource.containment;
  requireValue(sameResource(resource.requestResource, node.request.resource) && resource.requestedRevision === node.request.revision
    && sameResource(anchor.resource, node.request.resource) && anchor.revision === node.request.revision, 'Resource/containment revision mismatch.');
  if (anchor.domainPath.status === 'unavailable') work.deny('indeterminate');
  else {
    const path = anchor.domainPath.value;
    requireValue(path.length <= 33 && new Set(path).size === path.length, 'Invalid domain containment path.');
    if (adapter.containment === 'domain-self') requireValue(node.request.resource.kind === 'domain' && path[0] === node.request.resource.id, 'Domain containment must begin at itself.');
    if (adapter.containment === 'none') requireValue(path.length === 0, 'No-domain resources require an empty domain path.');
    if (adapter.containment === 'asset-placement') requireValue(node.request.resource.kind === 'asset', 'Asset placement anchor kind mismatch.');
  }
  if (anchor.context === 'current') requireValue(anchor.operation === null && selected.operation === null, 'Current containment cannot borrow an operation.');
  else {
    const op = anchor.operation, record = selected.operation;
    requireValue(op !== null && record !== null && operationActor(work, node, record.actor)
      && record.tenantId === node.request.resource.tenantId && record.planHash === op.planHash, 'Prepared operation context mismatch.');
    const member = one(record.members, row => row.key === op.memberKey && row.side === op.side, 'operation member');
    requireValue(sameResource(member.resource, node.request.resource) && member.revision === node.request.revision
      && member.securityRevision === anchor.securityRevision && anchor.domainPath.status === 'known'
      && same(member.domainPath, anchor.domainPath.value), 'Operation member containment mismatch.');
    requireValue(anchor.context === 'proposed' ? op.side === 'after' : op.side === 'before' || op.side === 'original', 'Operation context side mismatch.');
    if (!work.validity(record.validity)) work.deny('ceiling_denied');
  }
}
function factValues(work: ContextWork, selected: SelectedNodeEvidence, kind: 'classifications' | 'approved-tags'): ExpressionFact<readonly UUID[]> {
  const node = work.node, partition = kind === 'classifications' ? node.resource.classifications : node.resource.approvedTags;
  if (partition.status === 'unavailable') return { status: 'unavailable' };
  const values = new Set<UUID>();
  for (const ref of partition.value) {
    const record = one(selected.approvedSets, row => versionKey(row.ref) === versionKey(ref), 'selected fact');
    requireValue(record.kind === kind && sameResource(record.resource, node.request.resource)
      && record.revision === node.request.revision && record.fieldId === node.request.field
      && record.securityRevision === node.resource.containment.securityRevision, 'Approved fact target mismatch.');
    const producer = byRef(work.input.registry.producers, record.provenance.producer, 'fact producer'); work.use(producer);
    requireValue(producer.kind === kind && producer.tenantId === node.request.resource.tenantId
      && record.provenance.registryDigest === work.input.registry.digest, 'Approved fact producer mismatch.');
    const current = work.validity(record.validity), producerCurrent = work.validity(producer.validity);
    if (producer.state !== 'active' || !producerCurrent) { work.deny('indeterminate'); continue; }
    if (record.state === 'approved' && current) for (const id of record.values) values.add(id);
  }
  return { status: 'known', value: [...values].sort() };
}
function contextValue(work: ContextWork, selected: SelectedNodeEvidence, kind: 'purpose' | 'environment', origin: DecisionNode | null): ExpressionFact<UUID | null> {
  const selection = kind === 'purpose' ? work.node.purpose : work.node.environment;
  if (selection.status === 'unavailable') return { status: 'unavailable' };
  const record = one(selected.contexts, row => versionKey(row.ref) === versionKey(selection.value), 'selected context');
  const consumer = origin ?? work.node;
  requireValue(record.kind === kind && sameSubject(record.subject, consumer.subject) && same(record.request, consumer.request)
    && record.containmentDigest === digest(consumer.resource.containment), 'Context selection provenance mismatch.');
  const producer = byRef(work.input.registry.producers, record.provenance.producer, 'context producer'); work.use(producer);
  requireValue(producer.kind === kind && producer.tenantId === consumer.request.resource.tenantId
    && record.provenance.registryDigest === work.input.registry.digest, 'Context producer mismatch.');
  if (kind === 'environment') requireValue(record.value !== null, 'Environment cannot be a no-purpose selection.');
  const recordCurrent = work.validity(record.validity), producerCurrent = work.validity(producer.validity);
  if (!recordCurrent || !producerCurrent || record.state !== 'approved' || producer.state !== 'active') {
    work.deny('indeterminate'); return { status: 'unavailable' };
  }
  return { status: 'known', value: record.value };
}
function ceilings(work: ContextWork, adapter: AdapterRegistration): void {
  const refs = work.node.ceilingRefs;
  requireValue(refs.length === adapter.ceilings.length && new Set(refs.map(row => row.slot)).size === refs.length,
    'Every exact ceiling slot must occur once.');
  for (const slot of adapter.ceilings) {
    const ref = one(refs, row => row.slot === slot.slot, 'ceiling slot');
    if (slot.kind === 'visibility') {
      const record = work.use(one(work.input.bundle.visibility, row => row.id === ref.recordId, 'visibility ceiling'));
      requireValue(sameResource(record.resource, work.node.request.resource) && record.revision === work.node.request.revision,
        'Visibility ceiling target/revision mismatch.');
      if (record.visibility === 'restricted' && work.node.subject.kind === 'human'
        && !record.allowedIdentities.includes(work.node.subject.id)) work.deny(adapter.ceilingFailure);
    } else {
      const record = work.use(one(work.input.bundle.creators, row => row.id === ref.recordId, 'creator ceiling'));
      requireValue(sameResource(record.resource, work.node.request.resource), 'Creator ceiling target mismatch.');
      if (!sameSubject(record.creator, work.node.subject)) work.deny(adapter.ceilingFailure);
    }
  }
}
function sameSelections(work: ContextWork, a: DecisionNode, b: DecisionNode): void {
  for (const kind of ['purpose', 'environment'] as const) {
    const left = a[kind], right = b[kind];
    requireValue(left.status === right.status, 'A field dependency changes context availability.');
    if (left.status === 'known' && right.status === 'known') {
      const x = byRef(work.input.bundle.contextFacts, left.value, 'consumer context');
      const y = byRef(work.input.bundle.contextFacts, right.value, 'dependency context');
      requireValue(x.kind === kind && y.kind === kind && x.value === y.value && x.state === y.state
        && same(x.provenance, y.provenance) && same(x.validity, y.validity), 'A field dependency changes the approved operation selection.');
    }
  }
}
function fieldContext(work: ContextWork, selected: SelectedNodeEvidence, adapter: AdapterRegistration): boolean {
  const { node, input } = work, projection = node.projection;
  if (!fields.has(node.request.action)) {
    requireValue(projection === null && node.request.field === null && adapter.branch !== 'field', 'Non-field context carries a field projection.');
    return false;
  }
  requireValue(adapter.branch === 'field' && projection !== null && node.request.field !== null, 'Field action requires its protected projection.');
  const registration = one(input.registry.projections, row => row.projectionId === projection.projectionId
    && row.version === projection.version && row.fieldId === projection.fieldId
    && row.resourceKind === node.request.resource.kind && row.path === projection.path.kind, 'field registration'); work.use(registration);
  requireValue(registration.registrationHash === projection.registrationHash && registration.resourceKind === node.request.resource.kind
    && registration.path === projection.path.kind && projection.fieldId === node.request.field
    && sameResource(projection.resource, node.request.resource) && projection.revision === node.request.revision
    && projection.sensitivityRevision === node.resource.containment.securityRevision, 'Field projection identity/currentness mismatch.');
  let owner = { resource: node.request.resource, revision: node.request.revision };
  if (projection.path.kind === 'registered-reference') {
    const ref = selected.reference; requireValue(ref !== null && ref.tenantId === node.request.resource.tenantId
      && ref.projectionId === projection.projectionId && ref.projectionVersion === projection.version
      && ref.registrationHash === projection.registrationHash && ref.fieldId === projection.fieldId
      && sameResource(ref.target.resource, node.request.resource) && ref.target.revision === node.request.revision,
    'Registered reference tuple mismatch.');
    requireValue(ref.parent.resource.tenantId === node.request.resource.tenantId, 'Reference parent is outside the snapshot tenant.');
    owner = ref.parent;
  }
  requireValue(projection.prerequisites.length === registration.prerequisites.length
    && new Set(projection.prerequisites).size === projection.prerequisites.length, 'Field prerequisites are incomplete or duplicated.');
  const remaining = [...registration.prerequisites];
  for (const id of projection.prerequisites) {
    const prerequisite = work.dependency(id);
    const index = remaining.findIndex(row => row.action === prerequisite.request.action);
    requireValue(index >= 0, 'Unregistered field prerequisite action.');
    const [expected] = remaining.splice(index, 1);
    requireValue((registration.path === 'direct' ? expected.resource === 'field-owner' : expected.resource === 'reference-parent'),
      'Field prerequisite path is not registered.');
    requireValue(sameSubject(prerequisite.subject, node.subject) && same(prerequisite.authentication, node.authentication)
      && sameResource(prerequisite.request.resource, owner.resource) && prerequisite.request.revision === owner.revision
      && prerequisite.request.field === null && !fields.has(prerequisite.request.action)
      && services.has(prerequisite.request.action) === (node.subject.kind === 'service'), 'Field prerequisite identity/family mismatch.');
    sameSelections(work, node, prerequisite);
    if (node.subject.kind === 'service') requireValue(same(prerequisite.service, node.service), 'Service field provenance differs from its prerequisite.');
  }
  requireValue(projection.prerequisites.length > 0, 'A projection must retain at least one non-field prerequisite.');
  if (node.request.action === 'field:read' && projection.sensitivity === 'sensitive') {
    requireValue(projection.sensitiveDecision !== null, 'Sensitive field requires its explicit sensitive decision.');
    const sensitive = work.dependency(projection.sensitiveDecision), companion = sensitive.projection;
    requireValue(sensitive.request.action === 'field:sensitive.read' && sameSubject(sensitive.subject, node.subject)
      && same(sensitive.authentication, node.authentication) && sameResource(sensitive.request.resource, node.request.resource)
      && sensitive.request.revision === node.request.revision && sensitive.request.field === node.request.field
      && same(sensitive.resource, node.resource)
      && same(sensitive.service, node.service) && companion !== null && companion.sensitiveDecision === null
      && same({ ...projection, sensitiveDecision: null }, companion), 'Sensitive field companion mismatch.');
    sameSelections(work, node, sensitive);
  } else requireValue(projection.sensitiveDecision === null, 'Unexpected sensitive decision or reciprocal field cycle.');
  return node.request.action === 'field:read' && projection.sensitivity === 'ordinary';
}
const branchActions = {
  dispatch: 'scan-job:dispatch', claim: 'scan-job:claim', metadata: 'source:metadata.scan', secret: 'secret:resolve',
  complete: 'scan-job:complete', fail: 'scan-job:fail', 'project-consume': 'projection:consume',
  'project-write': 'projection:write', audit: 'audit:append', outbox: 'outbox:append',
} as const;
function assignmentCurrent(work: ContextWork, record: ServiceAssignmentEvidence, serviceId: UUID): void {
  requireValue(record.tenantId === work.input.bundle.snapshot.tenantId && record.serviceId === serviceId, 'Service assignment owner/tenant mismatch.');
  const current = work.validity(record.validity);
  if (!current || record.state !== 'active') work.deny('ceiling_denied');
}
function serviceContext(work: ContextWork, selected: SelectedNodeEvidence, adapter: AdapterRegistration, origin: DecisionNode | null): void {
  const node = work.node, consumer = origin ?? node, { snapshot } = work.input.bundle;
  if (node.subject.kind !== 'service') {
    requireValue(consumer.service === null && !services.has(node.request.action), 'Human context contains service effect provenance.'); return;
  }
  const use = consumer.service;
  requireValue(use !== null && node.authentication.kind === 'service-credential', 'Service context requires exact effect provenance.');
  const assignment = byRef(selected.serviceAssignments, use.assignment, 'selected assignment');
  assignmentCurrent(work, assignment, node.subject.id);
  const provenanceOnly = origin !== null || fields.has(node.request.action);
  if (!provenanceOnly) {
    requireValue(adapter.branch === `service-${use.kind}`, 'Service branch discriminator mismatch.');
    if (use.kind !== 'terminal-replay') requireValue(node.request.action === branchActions[use.kind], 'Service action does not match its branch.');
    requireValue(assignment.actions.includes(node.request.action as ServiceActionId), 'Service action is outside the exact assignment.');
  }
  // Field and guard contexts retain all selected records and currentness. Their
  // real service entitlement and initiation edges belong to the actual consumer.
  for (const p of selected.servicePrincipals) {
    requireValue(p.tenantId === snapshot.tenantId, 'Parent service tenant mismatch.');
    const current = work.validity(p.validity); if (!current || p.state !== 'active') work.deny('inactive_subject');
  }
  for (const a of selected.serviceAssignments) assignmentCurrent(work, a, a.serviceId);
  for (const credential of selected.credential) {
    requireValue(credential.tenantId === snapshot.tenantId, 'Parent credential tenant mismatch.');
    const current = work.validity(credential.validity);
    if (!current || credential.state !== 'active' || credential.generation !== snapshot.generation) work.deny('ceiling_denied');
  }
  const source = selected.sources[0], job = selected.jobs[0], claim = selected.claims[0];
  if ('job' in use) {
    requireValue(job && job.tenantId === snapshot.tenantId && job.generation === snapshot.generation, 'Service job generation/tenant mismatch.');
    requireValue(assignment.siteId === job.siteId && assignment.sourceId === job.sourceId, 'Assignment does not cover the exact job site/source.');
    if (use.kind !== 'metadata' && use.kind !== 'secret' && use.kind !== 'complete') requireValue(job.serviceId === node.subject.id, 'Job is assigned to another service.');
    work.future(job.deadlineAt);
    if (source) requireValue(source.tenantId === snapshot.tenantId && source.ref.id === job.sourceId && source.siteId === job.siteId,
      'Service source does not match its job.');
    if (!provenanceOnly) {
      const target = node.request.resource;
      if (use.kind === 'metadata' || use.kind === 'secret') requireValue(target.kind === 'source' && target.id === job.sourceId
        && source && node.resource.containment.securityRevision === source.securityRevision, 'Source consumption target mismatch.');
      else requireValue(target.kind === 'scan-job' && target.id === job.ref.id, 'Service job target mismatch.');
    }
  }
  const initiation = (id: NodeId): void => {
    const initiator = work.dependency(id);
    requireValue(job && initiator.subject.kind === 'human' && initiator.subject.id === job.initiatingIdentityId
      && initiator.authentication.kind === 'scan-initiator' && initiator.authentication.jobId === job.ref.id
      && initiator.authentication.jobVersion === job.ref.version && initiator.request.action === 'source:scan.request'
      && initiator.request.resource.kind === 'source' && initiator.request.resource.id === job.sourceId
      && initiator.request.resource.tenantId === snapshot.tenantId, 'Service initiating decision is unrelated to the canonical job.');
  };
  if (use.kind === 'dispatch') {
    if (job.status !== 'queued' || job.deadlineAt <= snapshot.now) work.deny('ceiling_denied');
  } else if (use.kind === 'claim') {
    if (!['queued', 'running'].includes(job.status) || job.deadlineAt <= snapshot.now) work.deny('ceiling_denied');
    if (!provenanceOnly) initiation(use.initiatingDecision);
  } else if (use.kind === 'metadata' || use.kind === 'secret' || use.kind === 'complete') {
    requireValue(claim && claim.jobId === job.ref.id && claim.sourceId === job.sourceId && claim.siteId === job.siteId
      && claim.serviceId === job.serviceId && claim.claimVersion === job.claimVersion && claim.generation === snapshot.generation
      && claim.requestHash === job.requestHash, 'Canonical claim association mismatch.');
    const claimCurrent = work.validity(claim.validity);
    if (!claimCurrent || claim.state !== 'active' || job.status !== 'running' || job.deadlineAt <= snapshot.now) work.deny('ceiling_denied');
    const lease = byRef(selected.leases, use.lease, 'selected lease');
    requireValue(lease.serviceId === node.subject.id && same(lease.assignment, use.assignment)
      && lease.credentialId === node.authentication.credentialId && lease.credentialVersion === node.authentication.credentialVersion,
    'Selected lease audience/credential/assignment mismatch.');
    const action = branchActions[use.kind];
    requireValue(lease.actions.includes(action), 'Selected lease does not cover the consumption action.');
    for (const current of selected.leases) {
      requireValue(current.tenantId === snapshot.tenantId && current.siteId === job.siteId && current.sourceId === job.sourceId
        && current.jobId === job.ref.id && current.initiatingIdentityId === job.initiatingIdentityId && same(current.claim, claim.ref)
        && current.claimVersion === job.claimVersion && current.generation === snapshot.generation && current.requestHash === job.requestHash,
      'Lease job/claim/generation/original request association mismatch.');
      const currentAssignment = byRef(selected.serviceAssignments, current.assignment, 'lease assignment');
      const credential = byVersion(selected.credential, { id: current.credentialId, version: current.credentialVersion }, 'lease credential');
      requireValue(current.audienceServiceId === current.serviceId && credential.serviceId === current.serviceId
        && currentAssignment.serviceId === current.serviceId && currentAssignment.siteId === job.siteId && currentAssignment.sourceId === job.sourceId
        && current.actions.length > 0 && current.actions.every(a => ['source:metadata.scan', 'secret:resolve', 'scan-job:complete'].includes(a)
          && currentAssignment.actions.includes(a)), 'Lease audience/assignment/action ceiling mismatch.');
      const { notBefore, expiresAt } = current.validity;
      requireValue(notBefore !== null && expiresAt !== null && Date.parse(expiresAt) - Date.parse(notBefore) <= 180_000
        && expiresAt <= job.deadlineAt, 'Lease interval exceeds its immutable ceiling.');
      const leaseCurrent = work.validity(current.validity);
      if (!leaseCurrent || current.state !== 'active') work.deny('ceiling_denied');
      if (current.parentLease === null) {
        requireValue(current.issuer.kind === 'gateway' && current.serviceId === job.serviceId
          && current.credentialId === claim.credentialId && current.credentialVersion === claim.credentialVersion,
        'Root lease issuer/site service/claim credential mismatch.');
        const issuer = byRef(selected.leaseIssuers, current.issuer.registration, 'gateway issuer');
        requireValue(issuer.tenantId === snapshot.tenantId && issuer.generation === snapshot.generation, 'Gateway issuer tenant/generation mismatch.');
        const issuerCurrent = work.validity(issuer.validity);
        if (!issuerCurrent || issuer.state !== 'active') work.deny('ceiling_denied');
      } else {
        const parent = byRef(selected.leases, current.parentLease, 'parent lease');
        requireValue(current.issuer.kind === 'parent-service' && current.issuer.serviceId === parent.serviceId
          && current.serviceId !== parent.serviceId && same(current.issuer.assignment, parent.assignment)
          && current.issuer.credential.id === parent.credentialId && current.issuer.credential.version === parent.credentialVersion
          && parent.validity.notBefore !== null && parent.validity.expiresAt !== null
          && notBefore >= parent.validity.notBefore && expiresAt <= parent.validity.expiresAt
          && current.actions.every(a => parent.actions.includes(a)), 'Child lease widens or changes parent authority.');
      }
    }
    if (use.kind === 'secret') requireValue(use.secretBinding !== null && source && same(use.secretBinding,
      { id: source.secretBinding.id, version: source.secretBinding.version }) && source.secretBinding.sourceId === job.sourceId
      && source.secretBinding.siteId === job.siteId, 'Secret reference does not match the exact source binding.');
    else requireValue(use.secretBinding === null, 'Non-secret service use contains a secret selection.');
    if (!provenanceOnly) initiation(use.initiatingDecision);
  } else if (use.kind === 'fail') {
    if (!['queued', 'running'].includes(job.status)) work.deny('ceiling_denied');
  } else if (use.kind === 'terminal-replay') {
    const terminal = selected.terminal;
    requireValue(terminal && terminal.tenantId === snapshot.tenantId && terminal.jobId === job.ref.id && terminal.sourceId === job.sourceId
      && terminal.serviceId === node.subject.id && terminal.generation === snapshot.generation
      && terminal.requestHash === use.requestHash && terminal.result === job.status, 'Terminal replay record mismatch.');
    if (!provenanceOnly) requireValue(node.request.action === terminal.action && ['scan-job:claim', 'scan-job:complete', 'scan-job:fail'].includes(node.request.action), 'Terminal replay action mismatch.');
    if (terminal.action === 'scan-job:complete' && terminal.result === 'succeeded') {
      requireValue(use.initiatingDecision !== null && terminal.claim !== null && claim && same(claim.ref, terminal.claim)
        && claim.state === 'sealed' && claim.jobId === job.ref.id && claim.sourceId === job.sourceId && claim.siteId === job.siteId
        && claim.serviceId === job.serviceId && claim.generation === snapshot.generation && claim.claimVersion === job.claimVersion
        && claim.requestHash === job.requestHash, 'Completion replay lacks its exact sealed claim.');
      if (!provenanceOnly) initiation(use.initiatingDecision);
    } else requireValue(use.initiatingDecision === null, 'Narrow terminal replay cannot borrow a completion initiator.');
  } else if (use.kind === 'project-consume' || use.kind === 'project-write') {
    const event = selected.projectionEvents[0];
    requireValue(event && event.requestAction === branchActions[use.kind] && event.requestHash === use.requestHash, 'Projection consumption commitment mismatch.');
    if ((use.mode === 'apply' && event.state !== 'pending') || (use.mode === 'replay' && event.state !== 'applied')) work.deny('ceiling_denied');
    requireValue(event && event.tenantId === snapshot.tenantId && assignment.indexId === event.indexId
      && assignment.eventFamilies.includes(event.family) && event.generation === snapshot.generation,
    'Projection event assignment/generation mismatch.');
    if (!provenanceOnly) requireValue(sameResource(event.resource, node.request.resource) && event.revision === node.request.revision
      && event.securityRevision === node.resource.containment.securityRevision, 'Projection event target/security mismatch.');
  } else {
    requireValue(use.kind === 'audit' || use.kind === 'outbox', 'Unknown service branch.');
    const journal = byRef(work.input.bundle.journalClaims, use.claim, 'journal claim');
    requireValue(journal.tenantId === snapshot.tenantId && journal.executorServiceId === node.subject.id && journal.generation === snapshot.generation
      && journal.action === branchActions[use.kind] && journal.payloadHash === use.payloadHash, 'Journal effect claim mismatch.');
    if (!provenanceOnly) requireValue(sameResource(journal.resource, node.request.resource) && journal.revision === node.request.revision, 'Journal claim target mismatch.');
    const operation = work.use(byVersion(work.input.bundle.operations, { id: journal.operationId, version: journal.operationVersion }, 'journal operation'));
    requireValue(sameSubject(operation.actor, journal.actor) && operation.tenantId === snapshot.tenantId, 'Journal operation actor mismatch.');
    const current = work.validity(journal.validity), operationCurrent = work.validity(operation.validity);
    if (!current || !operationCurrent || journal.state !== 'unconsumed') work.deny('ceiling_denied');
    requireValue(journal.parentDecisions.length > 0, 'Journal effect requires authorized parents.');
    if (!provenanceOnly) for (const id of journal.parentDecisions) {
      const parent = work.dependency(id);
      requireValue(sameSubject(parent.subject, journal.actor), 'Journal parent actor mismatch.');
    }
  }
}

/** Prepare one exact request context. Aggregation evaluates every declared
 * authority dependency and supplies request-scoped roles separately. */
export function prepareContext(input: DecisionInput, node: DecisionNode, budget: BudgetPort): ContextPlan {
  const work = new ContextWork(input, node, budget), adapter = input.indexes.adapters.get(node.adapterId);
  requireValue(adapter && adapter.action === node.request.action && adapter.resourceKinds.includes(node.request.resource.kind), 'Adapter action/resource registration mismatch.');
  const action = one(input.registry.actions, row => row.action === node.request.action, 'action registration'); work.use(action); work.use(adapter);
  requireValue(action.resourceKinds.includes(node.request.resource.kind) && (action.family === 'field'
    || action.family === node.subject.kind), 'Action subject family/resource mismatch.');
  const intent = one(input.registry.intentContexts, row => row.resourceKind === node.request.resource.kind
    && row.subjectKind === node.subject.kind, 'intent context'); work.use(intent);
  let origin: DecisionNode | null = null;
  if (node.mode === 'resource-wide-deny') {
    requireValue(node.guardOrigin !== null && node.intentGuard === null && adapter.branch === 'intent-guard'
      && adapter.id === intent.guardAdapterId && node.request.action === intent.denyContextAction, 'Guard registration mismatch.');
    origin = input.indexes.nodes.get(node.guardOrigin) ?? null;
    requireValue(origin !== null && origin.intentGuard === node.id, 'Guard origin is not reciprocal.');
  } else {
    requireValue(node.guardOrigin === null && node.intentGuard !== null && adapter.branch !== 'intent-guard', 'Authorize context requires its exact guard.');
    const guard = input.indexes.nodes.get(node.intentGuard);
    requireValue(guard && guard.mode === 'resource-wide-deny' && guard.request.action === intent.denyContextAction
      && guard.adapterId === intent.guardAdapterId, 'Required guard is missing or uses another context.');
    verifyOrigin(guard, node);
    // Shared guards may name one canonical consumer; identity binds the same
    // exact origin selection even when a second consumer shares that guard.
    const actualOrigin = guard.guardOrigin === null ? undefined : input.indexes.nodes.get(guard.guardOrigin);
    requireValue(actualOrigin && same(originSelection(actualOrigin), originSelection(node)), 'Shared guard changed its origin provenance.');
  }
  const selected = selectNodeEvidence(input.bundle.snapshot, node, input.bundle, input.registry, origin);
  trackSelected(work, selected); authenticate(work, selected, adapter, origin); containment(work, selected, adapter); ceilings(work, adapter);
  const derivedOrdinaryFieldAllow = fieldContext(work, selected, adapter);
  serviceContext(work, selected, adapter, origin);
  const purpose = contextValue(work, selected, 'purpose', origin), environment = contextValue(work, selected, 'environment', origin);
  const facts: ContextPlan['facts'] = { subject: node.subject, request: node.request, now: input.bundle.snapshot.now,
    groups: groupFacts(work, selected), domainPath: node.resource.containment.domainPath,
    classifications: factValues(work, selected, 'classifications'), approvedTags: factValues(work, selected, 'approved-tags'), purpose,
    environment: environment.status === 'known' && environment.value !== null ? { status: 'known', value: environment.value } : { status: 'unavailable' } };
  return { facts, mandatoryDependencies: work.dependencies, intentGuard: node.intentGuard,
    denialReasons: [...work.reasons], derivedOrdinaryFieldAllow, validUntil: [...work.boundaries].sort()[0] ?? null, usedRecords: work.used };
}
