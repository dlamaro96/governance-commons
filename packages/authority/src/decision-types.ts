// SPDX-License-Identifier: Apache-2.0
// Exact adopted pure-decision DTOs. Internal plans are derived data, never caller capabilities.
import type { UUID, Version, UTC, Counter, Digest, FieldId, ProjectionId, ResourceKind, ResourceRef, SubjectRef, Scope, RolePin, PolicyPin, PolicyDefinition, Validity, AuthorityIssue } from './types.ts';
import type { ActionId, HumanActionId, ServiceActionId } from './actions.ts';
import type { AdmissionMetrics } from './admission.ts';
import type { ExpressionFacts, RequestRoleFacts } from './expressions.ts';

export type Fact<T> = { status: 'known'; value: T } | { status: 'unavailable' };
export type NodeId = Digest;
export type HumanOrGroup = { kind: 'human' | 'group'; id: UUID };
export type NonFieldActionId = HumanActionId | ServiceActionId;
export type DecisionReason = 'allowed' | 'no_allow' | 'explicit_deny' | 'inactive_subject'
  | 'tenant_denied' | 'ceiling_denied' | 'scope_unavailable' | 'expired'
  | 'indeterminate' | 'profile_limit' | 'unsupported';
export type RecordState = 'active' | 'revoked';
export type DefinitionState = 'active' | 'retired';
export type GrantRef = { kind: 'grant' | 'delegation' | 'elevation'; id: UUID; version: Version };
export type MembershipRef = { id: UUID; version: Version };
export type SnapshotRef = {
  tenantId: UUID; generation: Counter; authorityEpoch: Counter;
  registryVersion: Version; registryDigest: Digest; snapshotDigest: Digest; now: UTC;
};
export type AtomicRequest = {
  action: ActionId; resource: ResourceRef; revision: Version | null; field: FieldId | null;
};
export type PrincipalEvidence =
  | { kind: 'human'; id: UUID; identityRevision: Counter; active: boolean;
      membership: { ref: MembershipRef; tenantId: UUID; identityId: UUID;
        state: RecordState; validity: Validity } | null }
  | { kind: 'service'; id: UUID; revision: Counter; tenantId: UUID;
      state: RecordState; validity: Validity };
export type GroupEvidence = { id: UUID; tenantId: UUID; revision: Counter; state: DefinitionState };
export type GroupMembershipEvidence = {
  ref: MembershipRef; tenantId: UUID; groupId: UUID; identityId: UUID;
  state: RecordState; validity: Validity;
};
export type PrincipalGroups = {
  subject: SubjectRef; memberships: Fact<readonly MembershipRef[]>;
};
export type HumanSessionEvidence = {
  id: UUID; version: Version; identityId: UUID; selectedTenantId: UUID;
  generation: Counter; state: RecordState; validity: Validity;
};
export type ServiceCredentialEvidence = {
  id: UUID; version: Version; serviceId: UUID; tenantId: UUID;
  generation: Counter; state: RecordState; validity: Validity;
};

export type Metadata = { key: string; label: string; description: string };
export type DefinitionEvidence = {
  tenantId: UUID; currentHeadVersion: Version; state: DefinitionState; hash: Digest;
} & (
  | { formatVersion: 1; kind: 'role'; id: UUID; version: Version;
      content: { metadata: Metadata; policies: readonly PolicyPin[] } }
  | { formatVersion: 1; kind: 'responsibility-type'; id: UUID; version: Version;
      content: { metadata: Metadata; grantsRole: RolePin | null } }
);
export type PolicyEvidence = {
  tenantId: UUID; currentHeadVersion: Version; state: DefinitionState;
  pin: PolicyPin; document: string;
  resourceWideIntents: readonly ResourceWideIntentEvidence[];
};
export type ResourceWideIntentEvidence = {
  ruleId: UUID; registryVersion: Version; registryDigest: Digest;
  resourceKinds: readonly ResourceKind[]; expandedActions: readonly ActionId[];
};
export type EffectCeiling = {
  actions: readonly ActionId[]; resourceKinds: readonly ResourceKind[];
  fields: readonly FieldId[] | null; scope: Scope; validity: Validity;
};
export type DelegableCeiling = {
  actions: readonly HumanActionId[]; fields: readonly FieldId[] | null;
  scope: Scope; validity: Validity; remainingDepth: number;
};
export type GrantBase = {
  ref: GrantRef; tenantId: UUID; state: RecordState; issuer: SubjectRef;
  scope: Scope; validity: Validity; ceiling: EffectCeiling;
};
export type AuthorityGrant = GrantBase & (
  | { kind: 'ordinary-role'; beneficiary: HumanOrGroup; role: RolePin;
      delegable: DelegableCeiling | null }
  | { kind: 'responsibility'; beneficiary: HumanOrGroup;
      type: { id: UUID; version: Version }; mappedRole: RolePin | null;
      assignmentId: UUID; assignmentVersion: Version;
      effectiveGrantId: UUID | null; delegable: DelegableCeiling | null }
  | { kind: 'delegation'; parent: GrantRef; beneficiary: SubjectRef;
      delegable: DelegableCeiling | null }
  | { kind: 'elevation'; parent: GrantRef; beneficiary: SubjectRef;
      use: { id: UUID; version: Version; state: RecordState;
        identityId: UUID; sessionId: UUID; sessionVersion: Version;
        generation: Counter; validity: Validity } | null }
  | { kind: 'service'; beneficiary: SubjectRef;
      policies: readonly PolicyPin[]; assignment: ServiceAssignmentRef }
);
export type CandidatePartition = {
  nodeId: NodeId; snapshotDigest: Digest;
  subject: SubjectRef; request: AtomicRequest; anchorDigest: Digest;
  candidates: readonly GrantRef[];
};
export type ChainLink = {
  nodeId: NodeId; child: GrantRef; parent: GrantRef; issuerDecision: NodeId;
  viaMembership: MembershipRef | null;
};

export type ContainmentEvidence = {
  resource: ResourceRef; revision: Version | null;
  context: 'current' | 'proposed' | 'original-scope';
  securityRevision: Counter; domainPath: Fact<readonly UUID[]>;
  operation: OperationScopeRef | null;
};
export type ScopeAnchorEvidence = { scope: Scope; containment: ContainmentEvidence };
export type ResourceEvidence = {
  requestResource: ResourceRef; requestedRevision: Version | null;
  canonicalCurrentVersion: Version | null; containment: ContainmentEvidence;
  classifications: Fact<readonly FactRef[]>; approvedTags: Fact<readonly FactRef[]>;
};
export type NodeAuthentication =
  | { kind: 'human-session'; sessionId: UUID; sessionVersion: Version }
  | { kind: 'service-credential'; credentialId: UUID; credentialVersion: Version }
  | { kind: 'live-issuer'; childGrant: GrantRef; elevationSession: VersionRef | null }
  | { kind: 'scan-initiator'; jobId: UUID; jobVersion: Version; elevationSession: VersionRef | null };
export type DecisionNode = {
  id: NodeId; mode: 'authorize' | 'resource-wide-deny';
  subject: SubjectRef; request: AtomicRequest;
  authentication: NodeAuthentication; resource: ResourceEvidence;
  adapterId: string; projection: FieldProjectionEvidence | null;
  ceilingRefs: readonly { slot: string; recordId: string }[];
  service: ServiceUse | null; intentGuard: NodeId | null;
  guardOrigin: NodeId | null;
  purpose: Fact<FactRef>; environment: Fact<FactRef>; factDigest: Digest;
};
export type RequestScopedRoleEvidence = {
  nodeId: NodeId; subject: SubjectRef; request: AtomicRequest;
  origin: GrantRef; role: RolePin; path: readonly GrantRef[];
  memberships: readonly MembershipRef[];
  effectiveScope: Scope; effectiveValidity: Validity;
};
export type EffectiveBinding = {
  nodeId: NodeId; terminal: GrantRef; origin: GrantRef; path: readonly GrantRef[];
  role: RolePin | null; policy: PolicyPin;
  effectiveScope: Scope; effectiveValidity: Validity; ceiling: EffectCeiling;
};

export type FactRef = { id: UUID; version: Version };
export type ProducerRef = { id: UUID; version: Version };
export type FactProvenance = {
  producer: ProducerRef; tenantId: UUID; registryDigest: Digest;
  sourceRecordId: UUID; sourceRecordVersion: Version;
};
export type ApprovedSetFact = {
  ref: FactRef; kind: 'classifications' | 'approved-tags'; provenance: FactProvenance;
  resource: ResourceRef; revision: Version | null; fieldId: FieldId | null; securityRevision: Counter;
  state: 'approved' | 'withdrawn'; validity: Validity; values: readonly UUID[];
};
export type ContextFact = {
  ref: FactRef; kind: 'purpose' | 'environment'; provenance: FactProvenance;
  subject: SubjectRef; request: AtomicRequest; containmentDigest: Digest;
  state: 'approved' | 'revoked'; validity: Validity; value: UUID | null;
};
export type OperationScopeRef = {
  operationId: UUID; version: Version; planHash: Digest;
  memberKey: string; side: 'before' | 'after' | 'original';
};
export type OperationEvidence = {
  id: UUID; version: Version; tenantId: UUID; actor: SubjectRef;
  planHash: Digest; requestHash: Digest; state: 'prepared' | 'sealed'; validity: Validity;
  members: readonly { key: string; side: 'before' | 'after' | 'original';
    resource: ResourceRef; revision: Version | null; securityRevision: Counter;
    domainPath: readonly UUID[] }[];
};

export type VisibilityEvidence = {
  id: string; resource: ResourceRef; revision: Version | null;
  visibility: 'tenant' | 'restricted'; allowedIdentities: readonly UUID[];
};
export type CreatorEvidence = { id: string; resource: ResourceRef; creator: SubjectRef };
export type ServiceAssignmentRef = { id: UUID; version: Version };
export type ServiceAssignmentEvidence = {
  ref: ServiceAssignmentRef; tenantId: UUID; serviceId: UUID; state: RecordState;
  validity: Validity; actions: readonly ServiceActionId[];
  siteId: UUID | null; sourceId: UUID | null; indexId: string | null;
  eventFamilies: readonly string[];
};
export type FieldProjectionEvidence = {
  projectionId: ProjectionId; version: Version; registrationHash: Digest;
  fieldId: FieldId; resource: ResourceRef; revision: Version | null;
  sensitivityRevision: Counter; sensitivity: 'ordinary' | 'sensitive';
  prerequisites: readonly NodeId[]; sensitiveDecision: NodeId | null;
  path: { kind: 'direct' } | { kind: 'registered-reference'; referenceId: UUID; referenceVersion: Version };
};
export type RegistryAction = {
  action: ActionId; family: 'human' | 'field' | 'service';
  resourceKinds: readonly ResourceKind[];
};
export type ProjectionFieldRegistration = {
  projectionId: ProjectionId; version: Version; registrationHash: Digest;
  fieldId: FieldId; resourceKind: ResourceKind;
  path: 'direct' | 'registered-reference';
  prerequisites: readonly { action: NonFieldActionId; resource: 'field-owner' | 'reference-parent' }[];
};

export type AdapterBranch = 'human-resource' | 'human-create' | 'human-history'
  | 'human-creator' | 'human-submitted-file' | 'field' | 'intent-guard'
  | 'service-dispatch' | 'service-claim' | 'service-metadata' | 'service-secret'
  | 'service-complete' | 'service-fail' | 'service-terminal-replay'
  | 'service-project-consume' | 'service-project-write' | 'service-audit' | 'service-outbox';
export type AdapterRegistration = {
  id: string; version: Version; action: ActionId; branch: AdapterBranch;
  resourceKinds: readonly ResourceKind[];
  containment: 'domain-self' | 'asset-placement' | 'authority-scope' | 'none';
  ceilings: readonly { slot: string; kind: 'visibility' | 'creator' }[];
  dependencyElevation: 'forbidden' | 'exact-live-session';
  ceilingFailure: 'ceiling_denied' | 'scope_unavailable';
};
export type ProducerRegistration = {
  ref: ProducerRef; kind: 'classifications' | 'approved-tags' | 'purpose' | 'environment';
  tenantId: UUID; state: DefinitionState; validity: Validity;
};
export type LeaseIssuerRegistration = {
  ref: VersionRef; tenantId: UUID; generation: Counter;
  state: RecordState; validity: Validity;
};
export type IntentContextRegistration = {
  resourceKind: ResourceKind; subjectKind: 'human' | 'service';
  denyContextAction: NonFieldActionId; guardAdapterId: string;
};
export type RegisteredReferenceEvidence = {
  id: UUID; version: Version; tenantId: UUID;
  projectionId: ProjectionId; projectionVersion: Version; registrationHash: Digest;
  parent: { resource: ResourceRef; revision: Version | null };
  target: { resource: ResourceRef; revision: Version | null };
  fieldId: FieldId; sourceRecordId: UUID; sourceRecordVersion: Version;
};
export type AuthorityDecisionRegistry = {
  formatVersion: 1; version: Version; digest: Digest;
  actions: readonly RegistryAction[]; adapters: readonly AdapterRegistration[];
  fields: readonly FieldId[]; projections: readonly ProjectionFieldRegistration[];
  intentContexts: readonly IntentContextRegistration[];
  producers: readonly ProducerRegistration[];
  leaseIssuers: readonly LeaseIssuerRegistration[];
};

export type VersionRef = { id: UUID; version: Version };
export type SourceServiceEvidence = {
  ref: VersionRef; tenantId: UUID; siteId: UUID; securityRevision: Counter;
  secretBinding: { id: UUID; version: Version; sourceId: UUID; siteId: UUID };
};
export type JobEvidence = {
  ref: VersionRef; tenantId: UUID; sourceId: UUID; siteId: UUID; serviceId: UUID;
  initiatingIdentityId: UUID; requestHash: Digest; generation: Counter;
  claimVersion: Counter; status: 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled';
  deadlineAt: UTC;
};
export type ClaimEvidence = {
  ref: VersionRef; tenantId: UUID; jobId: UUID; sourceId: UUID; siteId: UUID;
  serviceId: UUID; credentialId: UUID; credentialVersion: Version;
  generation: Counter; claimVersion: Counter; requestHash: Digest;
  state: 'active' | 'sealed' | 'revoked'; validity: Validity;
};
export type LeaseEvidence = {
  ref: VersionRef; tenantId: UUID;
  issuer: { kind: 'gateway'; registration: VersionRef }
    | { kind: 'parent-service'; serviceId: UUID; credential: VersionRef; assignment: ServiceAssignmentRef };
  assignment: ServiceAssignmentRef; audienceServiceId: UUID;
  serviceId: UUID; credentialId: UUID; credentialVersion: Version;
  siteId: UUID; sourceId: UUID; jobId: UUID; initiatingIdentityId: UUID;
  claim: VersionRef; claimVersion: Counter; generation: Counter;
  actions: readonly ServiceActionId[]; requestHash: Digest;
  state: 'active' | 'sealed' | 'revoked'; validity: Validity; parentLease: VersionRef | null;
};
export type ProjectionEventEvidence = {
  ref: VersionRef; tenantId: UUID; family: string; indexId: string;
  resource: ResourceRef; revision: Version | null; securityRevision: Counter;
  generation: Counter; state: 'pending' | 'applied'; eventHash: Digest;
  requestAction: 'projection:consume' | 'projection:write'; requestHash: Digest;
};
export type JournalClaimEvidence = {
  ref: VersionRef; tenantId: UUID; operationId: UUID; operationVersion: Version;
  actor: SubjectRef; executorServiceId: UUID; generation: Counter;
  action: 'audit:append' | 'outbox:append'; resource: ResourceRef;
  revision: Version | null; payloadHash: Digest; state: 'unconsumed' | 'consumed';
  validity: Validity; parentDecisions: readonly NodeId[];
};
export type TerminalEvidence = {
  ref: VersionRef; tenantId: UUID; jobId: UUID; sourceId: UUID;
  serviceId: UUID; claim: VersionRef | null; generation: Counter;
  action: 'scan-job:claim' | 'scan-job:complete' | 'scan-job:fail';
  requestHash: Digest; result: 'succeeded' | 'failed' | 'cancelled';
};
export type ServiceUse =
  | { kind: 'dispatch'; assignment: ServiceAssignmentRef; source: VersionRef; job: VersionRef }
  | { kind: 'claim'; assignment: ServiceAssignmentRef; source: VersionRef; job: VersionRef;
      initiatingDecision: NodeId }
  | { kind: 'metadata' | 'secret' | 'complete'; assignment: ServiceAssignmentRef;
      source: VersionRef; job: VersionRef; claim: VersionRef; lease: VersionRef;
      initiatingDecision: NodeId; requestHash: Digest; secretBinding: VersionRef | null }
  | { kind: 'fail'; assignment: ServiceAssignmentRef; job: VersionRef;
      requestHash: Digest; terminalAction: 'failed' | 'cancelled' }
  | { kind: 'terminal-replay'; assignment: ServiceAssignmentRef; job: VersionRef;
      terminal: VersionRef; initiatingDecision: NodeId | null; requestHash: Digest }
  | { kind: 'project-consume' | 'project-write'; assignment: ServiceAssignmentRef;
      event: VersionRef; mode: 'apply' | 'replay'; requestHash: Digest }
  | { kind: 'audit' | 'outbox'; assignment: ServiceAssignmentRef;
      claim: VersionRef; payloadHash: Digest };

export type DecisionBundle = {
  formatVersion: 1; snapshot: SnapshotRef; root: NodeId;
  nodes: readonly DecisionNode[];
  principals: readonly PrincipalEvidence[];
  groups: readonly GroupEvidence[];
  memberships: readonly GroupMembershipEvidence[];
  principalGroups: readonly PrincipalGroups[];
  sessions: readonly HumanSessionEvidence[];
  credentials: readonly ServiceCredentialEvidence[];
  definitions: readonly DefinitionEvidence[];
  policies: readonly PolicyEvidence[];
  grants: readonly AuthorityGrant[];
  candidates: readonly CandidatePartition[];
  chainLinks: readonly ChainLink[];
  scopeAnchors: readonly ScopeAnchorEvidence[];
  visibility: readonly VisibilityEvidence[];
  creators: readonly CreatorEvidence[];
  serviceAssignments: readonly ServiceAssignmentEvidence[];
  approvedFacts: readonly ApprovedSetFact[]; contextFacts: readonly ContextFact[];
  operations: readonly OperationEvidence[]; references: readonly RegisteredReferenceEvidence[];
  sources: readonly SourceServiceEvidence[]; jobs: readonly JobEvidence[];
  claims: readonly ClaimEvidence[]; leases: readonly LeaseEvidence[];
  projectionEvents: readonly ProjectionEventEvidence[];
  journalClaims: readonly JournalClaimEvidence[]; terminals: readonly TerminalEvidence[];
};
export type MatchWitness = { policy: PolicyPin; ruleId: UUID; grant: GrantRef; effect: 'allow' | 'deny' };
export type NodeDecision = {
  nodeId: NodeId; validUntil: UTC | null;
  matched: readonly MatchWitness[];
} & (
  | { mode: 'authorize'; allowed: boolean; reason: DecisionReason; derivedOrdinaryFieldAllow: boolean }
  | { mode: 'resource-wide-deny'; clear: boolean;
      reason: Exclude<DecisionReason, 'allowed' | 'no_allow'> | 'clear' }
);
export type DecisionBundleResult = {
  outcome: 'evaluated' | 'invalid' | 'unsupported' | 'profile_limit';
  root: Extract<NodeDecision, { mode: 'authorize' }> | null; nodes: readonly NodeDecision[];
  issues: readonly AuthorityIssue[]; metrics: DecisionMetrics;
};
export type DecisionMetrics = {
  admission: AdmissionMetrics | null;
  contexts: number; dependencyEdges: number; dependencyReferences: number; dependencyDepth: number;
  policyPins: number; policyBytes: number; policyRules: number; expressionNodes: number;
  bindingInstances: number; roleInstances: number; originGrants: number; delegationRecords: number;
  lineageEdgeOccurrences: number; authorityPrincipals: number; proofBytes: number; factBytes: number;
  actualRuleVisits: number; actualPredicateCalls: number; chargedPredicateNodeVisits: number;
  factValidationVisits: number; memoHits: number; matchWitnesses: number; outputBytes: number;
};

export type BudgetCounter = Exclude<keyof DecisionMetrics, 'admission'>
  | 'approvedFactIds' | 'catalogEntries' | 'catalogBytes';
export type RetainedCategory = 'raw' | 'normalized' | 'compiled' | 'memo' | 'output';
export interface BudgetPort {
  readonly metrics: DecisionMetrics;
  charge(counter: BudgetCounter, amount: number, path?: string): void;
  maximum(counter: BudgetCounter, value: number, path?: string): void;
  retain(category: RetainedCategory, bytes: number, path?: string): void;
  release(category: RetainedCategory, bytes: number): void;
  fail(outcome: 'invalid' | 'unsupported' | 'profile_limit', code: AuthorityIssue['code'], path: string, message: string): never;
}
export type DecisionCatalogs = Omit<DecisionBundle, 'formatVersion' | 'snapshot' | 'root' | 'nodes' | 'candidates' | 'chainLinks'>;
export type NodeDescriptor = Omit<DecisionNode, 'id' | 'factDigest'>;
export type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;
export type ServiceIdentity = DistributiveOmit<ServiceUse, 'initiatingDecision'>;
export type OriginSelection = {
  subject: SubjectRef; request: AtomicRequest; authentication: NodeAuthentication;
  containment: ContainmentEvidence; purpose: Fact<FactRef>; environment: Fact<FactRef>;
  serviceIdentity: ServiceIdentity | null;
};
export type SelectedNodeEvidence = {
  principal: PrincipalEvidence; groupPartition: PrincipalGroups;
  ceilings: readonly { slot: string; kind: 'visibility' | 'creator'; record: VisibilityEvidence | CreatorEvidence }[];
  journalOperation: OperationEvidence | null;
  groupHeads: readonly GroupEvidence[]; groupMemberships: readonly GroupMembershipEvidence[];
  session: HumanSessionEvidence | null; credential: readonly ServiceCredentialEvidence[];
  approvedSets: readonly ApprovedSetFact[]; contexts: readonly ContextFact[];
  operation: OperationEvidence | null; reference: RegisteredReferenceEvidence | null;
  sources: readonly SourceServiceEvidence[]; jobs: readonly JobEvidence[];
  claims: readonly ClaimEvidence[]; leases: readonly LeaseEvidence[];
  projectionEvents: readonly ProjectionEventEvidence[];
  journalClaim: Omit<JournalClaimEvidence, 'parentDecisions'> | null;
  terminal: TerminalEvidence | null; originSelection: OriginSelection | null;
  leaseIssuers: readonly LeaseIssuerRegistration[];
  serviceAssignments: readonly ServiceAssignmentEvidence[];
  servicePrincipals: readonly Extract<PrincipalEvidence, { kind: 'service' }>[];
};
/** Keys are produced by the exact key helpers in decision-schema.ts. */
export type DecisionIndexes = {
  nodes: ReadonlyMap<string, DecisionNode>; principals: ReadonlyMap<string, PrincipalEvidence>;
  groups: ReadonlyMap<string, GroupEvidence>; memberships: ReadonlyMap<string, GroupMembershipEvidence>;
  principalGroups: ReadonlyMap<string, PrincipalGroups>; sessions: ReadonlyMap<string, HumanSessionEvidence>;
  credentials: ReadonlyMap<string, ServiceCredentialEvidence>; definitions: ReadonlyMap<string, DefinitionEvidence>;
  policies: ReadonlyMap<string, PolicyEvidence>; grants: ReadonlyMap<string, AuthorityGrant>;
  candidates: ReadonlyMap<string, CandidatePartition>; chainLinks: ReadonlyMap<string, ChainLink>;
  scopeAnchors: ReadonlyMap<string, ScopeAnchorEvidence>; visibility: ReadonlyMap<string, VisibilityEvidence>;
  creators: ReadonlyMap<string, CreatorEvidence>; serviceAssignments: ReadonlyMap<string, ServiceAssignmentEvidence>;
  approvedFacts: ReadonlyMap<string, ApprovedSetFact>; contextFacts: ReadonlyMap<string, ContextFact>;
  operations: ReadonlyMap<string, OperationEvidence>; references: ReadonlyMap<string, RegisteredReferenceEvidence>;
  sources: ReadonlyMap<string, SourceServiceEvidence>; jobs: ReadonlyMap<string, JobEvidence>;
  claims: ReadonlyMap<string, ClaimEvidence>; leases: ReadonlyMap<string, LeaseEvidence>;
  projectionEvents: ReadonlyMap<string, ProjectionEventEvidence>; journalClaims: ReadonlyMap<string, JournalClaimEvidence>;
  terminals: ReadonlyMap<string, TerminalEvidence>; adapters: ReadonlyMap<string, AdapterRegistration>;
  producers: ReadonlyMap<string, ProducerRegistration>; leaseIssuers: ReadonlyMap<string, LeaseIssuerRegistration>;
};
export type DecisionInput = {
  bundle: DecisionBundle; registry: AuthorityDecisionRegistry; admission: AdmissionMetrics;
  parsedPolicies: ReadonlyMap<string, PolicyDefinition>; indexes: DecisionIndexes;
};
export type PreparedChain = {
  terminal: AuthorityGrant; origin: AuthorityGrant; path: readonly AuthorityGrant[];
  role: RolePin | null; policies: readonly PolicyPin[];
  memberships: readonly GroupMembershipEvidence[]; issuerDependencies: readonly NodeId[];
  effectiveScope: Scope; effectiveValidity: Validity; ceiling: EffectCeiling;
  currentlyEffective: boolean; requestApplicable: boolean;
};
export type ChainPlan = {
  nodeId: NodeId; paths: readonly PreparedChain[]; dependencies: readonly NodeId[];
  indeterminate: boolean; boundaries: readonly UTC[]; usedRecords: ReadonlySet<object>;
};
export type ResolvedChains = {
  bindings: readonly EffectiveBinding[]; requestRoles: Fact<RequestRoleFacts>;
  boundaries: readonly UTC[]; indeterminate: boolean;
};
export type ContextPlan = {
  facts: Omit<ExpressionFacts, 'requestRoles'>;
  mandatoryDependencies: readonly NodeId[]; intentGuard: NodeId | null;
  denialReasons: readonly DecisionReason[]; derivedOrdinaryFieldAllow: boolean;
  validUntil: UTC | null; usedRecords: ReadonlySet<object>;
};
export type NodePlan = { node: DecisionNode; context: ContextPlan; chains: ChainPlan };

/** Internal typed refusal, never a caller-supplied approval or error override. */
export class DecisionInputError extends Error {
  constructor(readonly outcome: 'invalid' | 'unsupported' | 'profile_limit', readonly issue: AuthorityIssue) {
    super(issue.message); this.name = 'DecisionInputError';
  }
}
export const versionKey = (ref: { id: string; version: number }): string => `${ref.id}@${ref.version}`;
export const subjectKey = (subject: { kind: string; id: string }): string => `${subject.kind}:${subject.id}`;
export const grantKey = (ref: GrantRef): string => `${ref.kind}:${versionKey(ref)}`;
export const policyKey = (pin: PolicyPin): string => `${pin.policyId}@${pin.version}#${pin.hash}`;
export const roleKey = (pin: RolePin): string => `role:${pin.roleId}@${pin.version}`;
export const definitionKey = (kind: DefinitionEvidence['kind'], id: string, version: number): string => `${kind}:${id}@${version}`;
export const chainLinkKey = (nodeId: string, child: GrantRef): string => `${nodeId}/${grantKey(child)}`;
export function scopeKey(scope: Scope): string {
  if (scope.kind === 'tenant') return `tenant:${scope.tenantId}`;
  if (scope.kind === 'domain') return `domain:${scope.tenantId}:${scope.domainId}:${scope.includeDescendants}`;
  return `resource:${scope.resource.tenantId}:${scope.resource.kind}:${scope.resource.id}`;
}
