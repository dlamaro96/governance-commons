# Scoped authority pure decision candidate

Editorial revision (2026-11-17): coordination-only text was removed. Technical requirements and qualification scope are unchanged. Historical implementation and execution records retain the original contract SHA256 `34c23163379832af6d9486e7599f66cc03ff7d4f207560dd36f52e087ada935e`.

Historical design status: **DRAFT — NOT IMPLEMENTED, ACTIVATED OR VERIFIED AT THIS CHECKPOINT.** Prepared 2026-11-16 against `974105cdf571fac655a624335d387b165e7033f8`. This specifies the next pure engine, not a database capability, approved administration command, authenticated fact loader or release. The complete [BUILD_SPEC](../product/BUILD_SPEC.md) remains binding. Keep the existing parser/interpreter and their historical qualification unchanged.

This refines the `EvaluationInput`, `EffectiveBinding` and role-evidence sketches in [the authority candidate](SCOPED_AUTHORITY_CONTRACT_CANDIDATE.md), using the [administration](SCOPED_AUTHORITY_ADMIN_CANDIDATE.md), [storage](SCOPED_AUTHORITY_STORAGE_CANDIDATE.md), [projection](SCOPED_AUTHORITY_PROJECTIONS_CANDIDATE.md) and [expression](SCOPED_AUTHORITY_EXPRESSION_CONTRACT.md) contracts. Generic physical admission is adopted in [the admission contract](SCOPED_AUTHORITY_ADMISSION_CONTRACT.md); cumulative semantic numbers and accounting come from [the frozen admission candidate](SCOPED_AUTHORITY_ADMISSION_CANDIDATE.md), SHA256 `396c96fdef8dbdf5e969c7ed7ddf69fa0950044075bb0fd4bd530dd07a49b979`. The design selects full current issuer decisions, a shared acyclic dependency bundle, and derived ordinary-field compatibility; those choices are stated explicitly below.

## 1. Boundary and exports

The proposed public exports are `evaluateAuthority(bundle: unknown, registry: unknown): DecisionBundleResult` and `evaluateAuthorityFile(text: string, registry: unknown): DecisionBundleResult`, plus the exact types/helpers below. Every public evaluation invokes generic admission internally; forged admitted wrappers or caller metrics are not accepted. Object callers must already bound allocations before this function reflects on them, but that trusted admission duty does not bypass its own defensive admission. The engine then performs strict closed-schema and cross-record validation, evaluates the dependency graph and returns deterministic private decisions. Reuse `parsePolicyFile`, `policyHash` and `evaluatePolicyExpression`; do not implement another policy grammar or permit scripts, callbacks or database/network/time reads.

`registry` is a separately supplied, protected server catalog, not part of a submitted policy document. Its version/hash and every referenced registration must match the bundle. The future loader authenticates the caller and obtains current complete records from one primary snapshot. The engine checks all representable consistency, completeness-reference and attenuation obligations; it cannot prove that a producer omitted a database row or forged an entire coherent snapshot. A caller-authored `complete:true`, `issuerAllowed:true`, `ceilingsSatisfied:true` or a matching digest is never such proof. None is accepted in this schema.

The raw companion calls parseAuthorityInputFile before bundle materialization. The separate protected registry is never taken from this external document. Admit the combined `{bundle,registry}` envelope cumulatively under the one physical canonical8MiB/node/depth profile, including that envelope node. For file input, raw UTF-8 bundle bytes plus canonical registry bytes must fit the raw8MiB budget too; whitespace and the catalog cannot obtain separate uncharged allowances. Internal validated handoffs may avoid repeated copying, never semantic checks. Object APIs require trusted prior admission, then descriptor-safe validation. Admission, derived expansions, dependency work and output share one bundle budget, never a fresh allowance per recursive call. Exhaustion returns a complete denial, never a partial allow, truncated candidate list or incomplete explanation. The admission module's lexical/size approval does not establish this engine's semantic validity.

All objects are closed; every listed property is required, with explicit `null`/`unavailable` where shown. References are exact `(tenant, kind, id, version)` or exact immutable pins, never latest-version fallback. Arrays reject duplicate semantic keys. UUID, Version, UTC, Counter, Digest, ActionId, Scope, ResourceRef, RolePin, PolicyPin, PolicyDefinition and FieldId retain their existing definitions. Times are canonical millisecond UTC, intervals half-open. Registry strings below are exact registered handles, not runtime prefixes or free-form dispatch.

```ts
type Fact<T> = { status: 'known'; value: T } | { status: 'unavailable' };
type NodeId = Digest;
type HumanOrGroup = { kind: 'human' | 'group'; id: UUID };
type NonFieldActionId = HumanActionId | ServiceActionId;
type DecisionReason = 'allowed' | 'no_allow' | 'explicit_deny' | 'inactive_subject'
  | 'tenant_denied' | 'ceiling_denied' | 'scope_unavailable' | 'expired'
  | 'indeterminate' | 'profile_limit' | 'unsupported';
type RecordState = 'active' | 'revoked';
type DefinitionState = 'active' | 'retired';
type GrantRef = { kind: 'grant' | 'delegation' | 'elevation'; id: UUID; version: Version };
type MembershipRef = { id: UUID; version: Version };
type SnapshotRef = {
  tenantId: UUID; generation: Counter; authorityEpoch: Counter;
  registryVersion: Version; registryDigest: Digest; snapshotDigest: Digest; now: UTC;
};
type AtomicRequest = {
  action: ActionId; resource: ResourceRef; revision: Version | null; field: FieldId | null;
};
type PrincipalEvidence =
  | { kind: 'human'; id: UUID; identityRevision: Counter; active: boolean;
      membership: { ref: MembershipRef; tenantId: UUID; identityId: UUID;
        state: RecordState; validity: Validity } | null }
  | { kind: 'service'; id: UUID; revision: Counter; tenantId: UUID;
      state: RecordState; validity: Validity };
type GroupEvidence = { id: UUID; tenantId: UUID; revision: Counter; state: DefinitionState };
type GroupMembershipEvidence = {
  ref: MembershipRef; tenantId: UUID; groupId: UUID; identityId: UUID;
  state: RecordState; validity: Validity;
};
type PrincipalGroups = {
  subject: SubjectRef; memberships: Fact<readonly MembershipRef[]>;
};
type HumanSessionEvidence = {
  id: UUID; version: Version; identityId: UUID; selectedTenantId: UUID;
  generation: Counter; state: RecordState; validity: Validity;
};
type ServiceCredentialEvidence = {
  id: UUID; version: Version; serviceId: UUID; tenantId: UUID;
  generation: Counter; state: RecordState; validity: Validity;
};
```

The human principal's identity activity and current tenant membership are independent. Missing membership is a known tenant denial, not an empty permission array to repair. Services have their own current assignment/credential evidence; they do not inherit human membership or ten-string permissions. Group membership proves the exact human/group/tenant association, current state and validity. A group's population is not a list of identities required for a member's decision. The complete snapshot inventory of potentially current **and future** direct memberships of each decision subject and required chain issuer is required, including records whose future start could activate a group deny; no nested groups. An active current/future membership referring to a retired group is inconsistent and indeterminate, not a silently removed group; retirement requires those memberships to be revoked first. Properly revoked or past-expiry membership is ineffective, with applicable future boundaries retained.

## 2. Definitions, grants and complete connected evidence

Role/responsibility definitions are exact immutable administration-definition contents, including metadata and referenced pins, plus their separately versioned current active/retired head. Recompute the adopted definition hash from `{formatVersion:1,kind,id,version,content}`. PolicyEvidence carries the exact raw JSON `document` string. Run every document through `parsePolicyFile(document, protectedFieldCatalog)` before deriving its PolicyDefinition and recomputing policyHash. This independently preserves raw **and** normalized64KiB limits, whitespace accounting and duplicate-key rejection inside the outer8MiB envelope. Charge outer escaped string bytes, decoded raw documents and retained derived canonical definitions in their appropriate shared categories; a caller-declared raw-byte count is not accepted. A role pin resolves all of that role's policy pins. Require currentHeadVersion >= the immutable pin version and validate current state separately. Publishing a newer version never substitutes its policies for the pinned version.

```ts
type Metadata = { key: string; label: string; description: string };
type DefinitionEvidence = {
  tenantId: UUID; currentHeadVersion: Version; state: DefinitionState; hash: Digest;
} & (
  | { formatVersion: 1; kind: 'role'; id: UUID; version: Version;
      content: { metadata: Metadata; policies: readonly PolicyPin[] } }
  | { formatVersion: 1; kind: 'responsibility-type'; id: UUID; version: Version;
      content: { metadata: Metadata; grantsRole: RolePin | null } }
);
type PolicyEvidence = {
  tenantId: UUID; currentHeadVersion: Version; state: DefinitionState;
  pin: PolicyPin; document: string;
  resourceWideIntents: readonly ResourceWideIntentEvidence[];
};
type ResourceWideIntentEvidence = {
  ruleId: UUID; registryVersion: Version; registryDigest: Digest;
  resourceKinds: readonly ResourceKind[]; expandedActions: readonly ActionId[];
};
type EffectCeiling = {
  actions: readonly ActionId[]; resourceKinds: readonly ResourceKind[];
  fields: readonly FieldId[] | null; scope: Scope; validity: Validity;
};
type DelegableCeiling = {
  actions: readonly HumanActionId[]; fields: readonly FieldId[] | null;
  scope: Scope; validity: Validity; remainingDepth: number;
};
type GrantBase = {
  ref: GrantRef; tenantId: UUID; state: RecordState; issuer: SubjectRef;
  scope: Scope; validity: Validity; ceiling: EffectCeiling;
};
type AuthorityGrant = GrantBase & (
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
type CandidatePartition = {
  nodeId: NodeId; snapshotDigest: Digest;
  subject: SubjectRef; request: AtomicRequest; anchorDigest: Digest;
  candidates: readonly GrantRef[];
};
type ChainLink = {
  nodeId: NodeId; child: GrantRef; parent: GrantRef; issuerDecision: NodeId;
  viaMembership: MembershipRef | null;
};
```

`HumanOrGroup` is the administration candidate's exact human/group union. Grant discriminants constrain `ref.kind`: ordinary/responsibility/service use `grant`, delegation uses `delegation`, elevation uses `elevation`. Human ordinary/responsibility issuers are recorded human provenance; their later inactivity does **not** revoke those independent ordinary grants. Delegation/elevation issuers must be live human members **and** currently allowed the same atomic request through the dependency decision described below. A service grant comes from the separately provisioned service authority path; a human ADMIN definition cannot install SERVICE effects. Service and human action families never mix in an effective grant.

The literal finite `EffectCeiling` is protected issuance evidence, not an AST rewrite. It binds the registry version and limits every resulting action/resource kind/field, even if an immutable policy is broader. Its original provenance must be checked by storage; the engine checks the submitted canonical companion against every use. `fields:null` removes only that ceiling's additional field restriction; it does not create a field grant or sensitive permission. ADMIN control mandates are separate administration-effect evidence, not content allows. The ordinary administration-action decision never certifies that a proposed child grant is safe to issue.

Responsibility assignment/type/mapped-role/effective-grant association must agree exactly. `grantsRole:null` requires mappedRole/effectiveGrantId null and yields no binding or role fact. Documentation/ownership alone never grants authority. A mapped assignment resolves its exact type and role pins; no mutable label or newest type mapping is consulted. The separate assignment child revision must resolve to the canonical effective-grant association.

A candidate partition is a protected producer's exhaustive discovery result for this subject/request/anchor at this snapshot, including potentially applicable future grants/denies and not merely currently matching policies. The engine checks its identity, uniqueness and complete resolution against catalogs; it cannot verify absent database rows. Every node has exactly one partition. No caller-supplied filtered `EffectiveBinding[]` is accepted. From each candidate, the engine resolves its entire parent chain and **all** policy pins of the exact root role/service grant. Missing definitions, parents, group memberships or duplicates with conflicting records are indeterminate. Unreferenced grant/definition/proof records are rejected rather than silently used as fallback authority.

For each chain: require an actual root ordinary-role/mapped-responsibility grant; every child names the immediately preceding exact parent; no repeated record or issuer/beneficiary cycle; no elevation/service parent; parent beneficiary equals child issuer, or is a group with an exact live direct membership for that issuer. Validate human kinds, tenant, current edge issuer/beneficiary activity, grant state and interval at every step. This expressly excludes the historical issuer activity of an independent ordinary root grant; that issuer is provenance only. Each child scope/actions/kinds/fields/validity is a subset of the parent's effect and explicit delegable ceilings; delegation depth must decrease. An elevation is terminal, compatible-action-only, finite-expiry and nondelegable. It applies only with its exact current use, beneficiary/session/version/generation and expiry. There is no session-independent elevation activation.

Derive effective scope from the terminal most restrictive scope after proving containment, and effective interval by intersecting every grant, delegation/elevation, required membership, subject and applicable session/use/credential interval. Do not accept a claimed effective intersection. An invalid widening or disconnected edge is indeterminate. A well-formed revoked/expired/future record is currently ineffective; its future temporal boundaries still matter. Retirement cannot silently substitute a definition: a live referring grant with a retired required definition is inconsistent and indeterminate.

`ChainLink` is keyed by `(consuming nodeId, exact child ref)`; its parent and issuer decision must agree with that consuming node, allowing the same grant to be checked separately for field and non-field or old/proposed contexts. `ChainLink.issuerDecision` is mandatory for **every** delegation/elevation edge. It identifies a complete decision for that exact issuer on the same action/resource/revision/field and same containment context, not a bare liveness flag or a role name. Its complete current policies, groups, grants and any dependencies belong to this same bundle. A denied issuer makes that dependent binding ineffective; an indeterminate issuer makes the consuming decision indeterminate. No chain may justify itself through a dependency cycle. Different independent direct grants may still allow a subject after a delegated binding becomes ineffective; there is no special delegation override of deny-wins.

## 3. Resource anchors, facts and dependency nodes

```ts
type ContainmentEvidence = {
  resource: ResourceRef; revision: Version | null;
  context: 'current' | 'proposed' | 'original-scope';
  securityRevision: Counter; domainPath: Fact<readonly UUID[]>;
  operation: OperationScopeRef | null;
};
type ScopeAnchorEvidence = { scope: Scope; containment: ContainmentEvidence };
type ResourceEvidence = {
  requestResource: ResourceRef; requestedRevision: Version | null;
  canonicalCurrentVersion: Version | null; containment: ContainmentEvidence;
  classifications: Fact<readonly FactRef[]>; approvedTags: Fact<readonly FactRef[]>;
};
type NodeAuthentication =
  | { kind: 'human-session'; sessionId: UUID; sessionVersion: Version }
  | { kind: 'service-credential'; credentialId: UUID; credentialVersion: Version }
  | { kind: 'live-issuer'; childGrant: GrantRef; elevationSession: VersionRef | null }
  | { kind: 'scan-initiator'; jobId: UUID; jobVersion: Version; elevationSession: VersionRef | null };
type DecisionNode = {
  id: NodeId; mode: 'authorize' | 'resource-wide-deny';
  subject: SubjectRef; request: AtomicRequest;
  authentication: NodeAuthentication; resource: ResourceEvidence;
  adapterId: string; projection: FieldProjectionEvidence | null;
  ceilingRefs: readonly { slot: string; recordId: string }[];
  service: ServiceUse | null; intentGuard: NodeId | null;
  guardOrigin: NodeId | null;
  purpose: Fact<FactRef>; environment: Fact<FactRef>; factDigest: Digest;
};
type RequestScopedRoleEvidence = {
  nodeId: NodeId; subject: SubjectRef; request: AtomicRequest;
  origin: GrantRef; role: RolePin; path: readonly GrantRef[];
  memberships: readonly MembershipRef[];
  effectiveScope: Scope; effectiveValidity: Validity;
};
type EffectiveBinding = {
  nodeId: NodeId; terminal: GrantRef; origin: GrantRef; path: readonly GrantRef[];
  role: RolePin | null; policy: PolicyPin;
  effectiveScope: Scope; effectiveValidity: Validity; ceiling: EffectCeiling;
};
```

`RequestScopedRoleEvidence` and `EffectiveBinding` are **derived intermediate values**, not accepted caller assertions. The engine builds complete role facts from the same exact current assignment/chain evidence used for bindings, after scope/ceiling/liveness checks. The exact role-to-origin association and the whole request/node context must agree. A role fact grants no operation and need not itself contain an allow; policies still decide. Deduplicate the interpreter's role pins only after validating every contributing proof. A malformed later proof cannot be hidden by an earlier match.

Hashing is exact and nonrecursive. Let C sort object keys by JavaScript code-unit order, preserve declared ordered arrays, use ordinary JSON scalar escaping, accept safe integer numbers only and reject negative zero/invalid Unicode. Normalize set arrays first by their declared identity tuples: subject(kind,id), record(kind,id,version), policy(id,version,hash), field/action strings, registry handles/version, and candidate refs(kind,id,version). Preserve domain paths and policy rule/child order. H is lowercase SHA-256 of UTF-8 C. Existing policyHash remains unchanged.

snapshotDigest is a producer-supplied identity of its one authenticated read snapshot; the pure engine checks exact equality everywhere and **does not recursively compute it from nodes**. It is not authentication. For each node, recompute factDigest as H of `{principal,groupHeads,groupMemberships,session,credential,approvedSets,contexts,operation,reference,sources,jobs,claims,leases,projectionEvents,journalClaim,terminal,originSelection,leaseIssuers,serviceAssignments,servicePrincipals}`. Each key is required: scalar records use null when not selected, plural arrays use [] when none. Principal is the exact subject row. Group memberships are the complete current/future inventory from that subject's PrincipalGroups and groupHeads are exactly their referenced heads. Session is a scalar record for the selected human-session or explicit elevationSession; credential is always a sorted array containing the selected service credential plus required parent-lease credentials, or []. approvedSets/contexts are the exact records referenced by resource facts and purpose/environment. operation/reference are the exact selected provenance records. Service arrays are the complete selected service closure, including every parent lease/current credential; their selected credentials are included in the credential array. journalClaim excludes only its parentDecisions reference IDs; those are validated dependency edges, not fact identities. originSelection is null for authorize nodes and the exact guard origin descriptor defined in section4 for guard nodes. leaseIssuers/serviceAssignments/servicePrincipals include the exact selected root/child lease closure; no unselected record is hashed. All plural arrays are identity-sorted. Missing or extra selected closure records fail.

Node ID is H of `{snapshot,mode,subject,request,authentication,adapterId,resource,purpose,environment,factDigest,projectionIdentity,serviceIdentity}`. projectionIdentity is projection without prerequisites/sensitiveDecision; serviceIdentity is ServiceUse without initiatingDecision. No intentGuard, guardOrigin or dependency-node ID enters this descriptor. These excluded references must nevertheless equal the exact derived dependency contexts, and duplicate node IDs are forbidden. This avoids recursive hashes while including selected purpose/environment, actual fact contents/currentness, authentication and protected proposed/original-plan provenance. Node ID is a local context identity, **not** an operation memo key or proof that candidate bindings are complete; any operation memo must additionally bind full candidate/proof/policy/catalog digests and external fences as the admission contract requires. Catalog facts are separate, shared records and cannot conflict for the same exact identity. All nodes use the outer snapshot's tenant/time/generation/registry; node-specific time or unvalidated registry overrides are rejected. A node's requested resource and revision must equal its resource evidence. A historical revision uses its exact recorded revision with current security/containment obligations selected by the protected adapter, never a fabricated historical ACL. Proposed/original-scope containment requires an exact OperationScopeRef into a protected prepared OperationEvidence: operation ID/version, actor, plan hash, membership key, resource/revision, before/after/original side and exact path/security projection must match. Current containment has operation:null. Additional original scopes are separate mandatory nodes. Pure consistency does not authenticate the producer of an operation plan.

Canonical containment: a domain's path starts with **that domain's own ID**, then its current ancestors; a placed asset's path starts with its actual direct domain; a known unassigned asset is `known:[]` and inherits only tenant scope. Retired domains keep identity and applicable denies. The existing direct-plus-32-ancestors bound applies. Scope evidence includes the exact containing path for each domain/resource used in an attenuation comparison; a plausible UUID list alone is not producer provenance.

The catalog selects one canonical containment context for each atomic requirement. A relation with two endpoint obligations, a move with old/proposed obligations, or a receipt with many immutable references cannot be compressed into one chosen endpoint/domain path. The adapter decomposes it into complete separately required nodes. Reject a request with missing/ambiguous containment, a multi-path array or a resource kind without an adopted anchor rule. Tenant/resources explicitly registered as having no business-domain containment use known empty paths; do not invent paths from labels, owners, foreign references or unrelated type locations.

Containment comparison is literal: tenant contains only the same tenant; resource contains only the same canonical resource; a domain scope contains its own domain/direct placements and, only with includeDescendants, descendants proved by canonical paths. Parent domain without descendants cannot contain a child domain scope with descendants. A child resource may attenuate a domain scope only if its registered current containment lies within it. Resource scope never widens to domain scope. Registry changes and moves invalidate the corresponding security/authority fence.

Known empty groups/classifications/tags are complete empty facts; unavailable is not empty. Known purpose null is no approved purpose. Construct `ExpressionFacts` from the validated node and derived current role/group proofs. The interpreter's all/any indeterminate dominance remains unchanged. The full pure engine implements **all existing AST predicates**, including classifications, approved tags, purpose and environment. The typed provenance records below establish structural consistency and current validity in pure tests. Their actual authenticated canonical producers and publication/activation gates remain required runtime work; missing live infrastructure is not a reason to omit the implementation or relabel these predicates A2. Known unavailable used evidence yields indeterminate. No predicate disappears through boolean short-circuiting.

Typed fact and operation provenance is explicit:

```ts
type FactRef = { id: UUID; version: Version };
type ProducerRef = { id: UUID; version: Version };
type FactProvenance = {
  producer: ProducerRef; tenantId: UUID; registryDigest: Digest;
  sourceRecordId: UUID; sourceRecordVersion: Version;
};
type ApprovedSetFact = {
  ref: FactRef; kind: 'classifications' | 'approved-tags'; provenance: FactProvenance;
  resource: ResourceRef; revision: Version | null; fieldId: FieldId | null; securityRevision: Counter;
  state: 'approved' | 'withdrawn'; validity: Validity; values: readonly UUID[];
};
type ContextFact = {
  ref: FactRef; kind: 'purpose' | 'environment'; provenance: FactProvenance;
  subject: SubjectRef; request: AtomicRequest; containmentDigest: Digest;
  state: 'approved' | 'revoked'; validity: Validity; value: UUID | null;
};
type OperationScopeRef = {
  operationId: UUID; version: Version; planHash: Digest;
  memberKey: string; side: 'before' | 'after' | 'original';
};
type OperationEvidence = {
  id: UUID; version: Version; tenantId: UUID; actor: SubjectRef;
  planHash: Digest; requestHash: Digest; state: 'prepared' | 'sealed'; validity: Validity;
  members: readonly { key: string; side: 'before' | 'after' | 'original';
    resource: ResourceRef; revision: Version | null; securityRevision: Counter;
    domainPath: readonly UUID[] }[];
};
```

A known approved-set partition contains every potentially current/future canonical approval record for the exact resource/revision/fieldId/security identity. A normal node selects only records whose fieldId equals request.field (null for non-field requests); no field-A approval can satisfy field B. A resource-wide guard always selects the resource-level fieldId:null partition, independently of its consumer’s field-specific records. Resolve all records, reject wrong kind/producer/tenant/version, and derive current unique values only from approved and now-valid records. Withdrawn/currently out-of-window records do not contribute values; their future boundaries remain visible. Known empty partition derives known empty facts. An authorize context selection resolves the exact approved current subject/request/containment and registered producer; a guard uses only the explicit origin remapping below; purpose value:null is a proven no-purpose selection, while environment value:null is invalid. Revoked/expired/missing selected contexts produce indeterminate, not a default context. A supplied selection UUID or provenance digest alone is never authentication.

## 4. Registered ceilings, fields and services

Replace the old `ceilingsSatisfied` boolean with exact evidence plus a protected catalog describing which evidence each literal adapter requires. The engine implements a closed set of ceiling kinds: current subject/membership; exact session/credential; resource visibility ACL; creator-only access; service assignment; job/claim/lease association; projection event; exact command-journal claim. Unknown kind or missing required record is unsupported/indeterminate. The catalog cannot supply executable predicates or an `allow` value.

```ts
type VisibilityEvidence = {
  id: string; resource: ResourceRef; revision: Version | null;
  visibility: 'tenant' | 'restricted'; allowedIdentities: readonly UUID[];
};
type CreatorEvidence = { id: string; resource: ResourceRef; creator: SubjectRef };
type ServiceAssignmentRef = { id: UUID; version: Version };
type ServiceAssignmentEvidence = {
  ref: ServiceAssignmentRef; tenantId: UUID; serviceId: UUID; state: RecordState;
  validity: Validity; actions: readonly ServiceActionId[];
  siteId: UUID | null; sourceId: UUID | null; indexId: string | null;
  eventFamilies: readonly string[];
};
type FieldProjectionEvidence = {
  projectionId: ProjectionId; version: Version; registrationHash: Digest;
  fieldId: FieldId; resource: ResourceRef; revision: Version | null;
  sensitivityRevision: Counter; sensitivity: 'ordinary' | 'sensitive';
  prerequisites: readonly NodeId[]; sensitiveDecision: NodeId | null;
  path: { kind: 'direct' } | { kind: 'registered-reference'; referenceId: UUID; referenceVersion: Version };
};
type RegistryAction = {
  action: ActionId; family: 'human' | 'field' | 'service';
  resourceKinds: readonly ResourceKind[];
};
type ProjectionFieldRegistration = {
  projectionId: ProjectionId; version: Version; registrationHash: Digest;
  fieldId: FieldId; resourceKind: ResourceKind;
  path: 'direct' | 'registered-reference';
  prerequisites: readonly { action: NonFieldActionId; resource: 'field-owner' | 'reference-parent' }[];
};
```

The pure registry schema is complete below. Its contents are a separately trusted server input; synthetic exact registrations qualify pure behavior without pretending that a production catalog exists. Registration hashes cover the exact row excluding registrationHash; the outer digest covers the entire registry excluding digest. Require every literal action exactly once and its family to agree with the existing103/21/2/10 registry; kinds/branches are closed enums. Reject duplicate handles/pins, wrong branch/action families, incompatible resource kinds, unknown producer kinds and mismatched hashes. Literal strings identify registered records only.

```ts
type AdapterBranch = 'human-resource' | 'human-create' | 'human-history'
  | 'human-creator' | 'human-submitted-file' | 'field' | 'intent-guard'
  | 'service-dispatch' | 'service-claim' | 'service-metadata' | 'service-secret'
  | 'service-complete' | 'service-fail' | 'service-terminal-replay'
  | 'service-project-consume' | 'service-project-write' | 'service-audit' | 'service-outbox';
type AdapterRegistration = {
  id: string; version: Version; action: ActionId; branch: AdapterBranch;
  resourceKinds: readonly ResourceKind[];
  containment: 'domain-self' | 'asset-placement' | 'authority-scope' | 'none';
  ceilings: readonly { slot: string; kind: 'visibility' | 'creator' }[];
  dependencyElevation: 'forbidden' | 'exact-live-session';
  ceilingFailure: 'ceiling_denied' | 'scope_unavailable';
};
type ProducerRegistration = {
  ref: ProducerRef; kind: 'classifications' | 'approved-tags' | 'purpose' | 'environment';
  tenantId: UUID; state: DefinitionState; validity: Validity;
};
type LeaseIssuerRegistration = {
  ref: VersionRef; tenantId: UUID; generation: Counter;
  state: RecordState; validity: Validity;
};
type IntentContextRegistration = {
  resourceKind: ResourceKind; subjectKind: 'human' | 'service';
  denyContextAction: NonFieldActionId; guardAdapterId: string;
};
type RegisteredReferenceEvidence = {
  id: UUID; version: Version; tenantId: UUID;
  projectionId: ProjectionId; projectionVersion: Version; registrationHash: Digest;
  parent: { resource: ResourceRef; revision: Version | null };
  target: { resource: ResourceRef; revision: Version | null };
  fieldId: FieldId; sourceRecordId: UUID; sourceRecordVersion: Version;
};
type AuthorityDecisionRegistry = {
  formatVersion: 1; version: Version; digest: Digest;
  actions: readonly RegistryAction[]; adapters: readonly AdapterRegistration[];
  fields: readonly FieldId[]; projections: readonly ProjectionFieldRegistration[];
  intentContexts: readonly IntentContextRegistration[];
  producers: readonly ProducerRegistration[];
  leaseIssuers: readonly LeaseIssuerRegistration[];
};
```

Adapter ceilings are exact required slots. ceilingRefs is an explicit slot→recordId mapping: every declared slot occurs exactly once, its record resolves in the corresponding visibility/creator table, and no extra or duplicate slot is accepted. Record IDs are distinct within each table. Two declared slots may resolve the same record only when both independently require that same record kind and node resource/revision; slot identity, never list order, determines the requirement. These records bind the node's canonical resource/revision. Referenced resources needing independent ceilings are separate adapter-derived atomic obligations; this pure function does not discover business operation scope from a partial caller page. A source restriction/endpoint/history resource cannot be replaced by a self-resource ACL. Domain-self verifies direct ID equals resource ID; asset-placement and authority-scope require their registered canonical producer evidence; none requires a known empty path. Production proof of these canonical paths is the loader/storage obligation, while the engine rejects inconsistent paths and operation companions.

Resource-wide intent is a protected companion to the exact policy pin/rule and registry expansion. Verify it names a deny rule with fields:null and exactly the registered finite applicable non-field action expansion for its kinds/family. Reject action-in anywhere inside a newly marked rule: this deliberate additional constraint makes the declared intent action-independent, without changing ordinary action-specific policy syntax. No legacy marked rules exist to rewrite. Each target kind/subject family has one registered denyContextAction. Every ordinary operation, direct field and narrow reference checks the same pinned intent context on that canonical target, current facts and exact subject: request action=denyContextAction, field:null, same target/revision/containment. Its role facts are request-scoped to that context. It evaluates marked rules for deny/indeterminate only; absence of a target general-read allow is irrelevant. The guard cannot confer target access. Its action is a predicate context only: it does not invoke the corresponding business/service handler or require an unrelated general target-read allow. For a service subject, validate current service/credential and the originating consumer's exact assignment/source/job/site context records, but do not demand service effect authority or a ServiceUse branch for the artificial denyContextAction. The real consumer retains all of its normal assignment/lease/initiator/effect obligations. Human guard authentication likewise retains current subject/session or explicitly derived issuer/initiator context. Exact guard ceilings come from the registered guard adapter.

An authorize node has an exact intentGuard dependency and guardOrigin:null. A resource-wide-deny node uses the exact registered guardAdapterId with branch intent-guard, intentGuard:null, projection:null, service:null, the registered denyContextAction and no derived field allow. Its guardOrigin points to an actual authorize consumer whose intentGuard names it, with matching subject/authentication/target/revision/containment and the exact inherited purpose/environment selections described next. Resource-level guard facts and field-level consumer facts may be different exact partitions; neither is substituted for the other. guardOrigin is a structural provenance reference, NOT an authority dependency, and is excluded from node identity; count its reference work while avoiding a fake dependency cycle. Multiple consumers may share a guard only when their exact canonical guard context and required provenance agree. Its complete candidate partition includes every possibly relevant target-wide intent, even if the consumer's ordinary action candidate set differs. Every marked rule is validated, including complete expansion/registry provenance. Its effective grant and every lineage field ceiling must have fields:null, and its grant ceiling must cover the complete marked expansion on the applicable kind; a narrower action ceiling cannot silently reinterpret resource-wide intent as a partial deny. Future registry actions require reviewed forward expansion before activation. A guard result is a separate clear/refused result, never an allowed authorization node.

Guard origin remapping is closed: resolve the actual authorize consumer and first validate its ContextFact selections against that consumer’s exact request. The guard must use the identical purpose/environment FactRef or unavailable marker; compare tenant, actor, resource, revision, containment, producer and selection validity unchanged. The sole permitted request remap is action→registered denyContextAction and field→null for predicate evaluation. Do not require the stored origin ContextFact.request to equal that synthetic request, create a fresh guard selection, or remap source/target identity. Guard role facts still derive from the exact synthetic deny-context AtomicRequest. Direct and registered-reference consumers within one protected operation selection must reach the same target-wide selection/currentness context; aliasing cannot replace purpose/environment. Separately authenticated legitimate selections can differ. guardOrigin is validated as an actual reciprocal reference, while its ID is excluded from all hash descriptors; the selected origin records and a nonrecursive origin-selection descriptor `{subject,request,authentication,containment,purpose,environment,serviceIdentity}` bind provenance. This descriptor is included in the guard factDigest and prevents the origin pointer from being freely substituted without recursive node hashing.

A direct field path uses field-owner prerequisite nodes. A registered-reference path requires the exact protected reference tuple above and the declared reference-parent prerequisite action(s). This preserves existing narrow-reference responses without requiring unrelated general target-read authority. Target identity/field/revision, parent identity/revision, projection version/hash and reference source record must all agree. Current target-wide intent still applies through the exact guard, and any field-specific deny remains relevant. A parent allow cannot substitute for an undeclared field, change a target or expand a reference into general discovery.
 Visibility always binds the actual resource/revision. A restricted human-facing resource requires that exact human UUID in its canonical ACL. Source/endpoint/referenced-object ceilings are additional nodes, not a caller-stated `sourceAllowed`. Creator-only preparation requires exact subject identity, not merely a shared role. Native connector access restrictions remain independent execution guards; a pure decision cannot certify remote credentials or native privileges.

Field nodes are part of the A1 engine target. Their explicit projection companion must match the protected versioned registration, exact semantic field/resource/revision, current sensitivity evidence and **all** exact registered non-field prerequisite contexts. Each prerequisite has the same subject/authentication and exact catalog-selected resource/revision: field owner for direct paths, or the protected parent tuple for a registered narrow reference. Owner/parent containment is independently canonical for that node. No caller can select a cheaper prerequisite action or reuse a different target reference.

For ordinary `field:read`, all non-field prerequisites allowed plus exact projection membership supplies a **derived ordinary-field allow**. This deliberate compatibility rule preserves currently authorized ordinary fields without manufacturing independent resource authority. Applicable explicit field denies still win. An explicit field allow never bypasses a denied/missing prerequisite. For a service subject, the field node carries the exact same ServiceUse closure as every registered non-field prerequisite; all such closures must agree. Validate the actual service branch/action entitlement on those non-field prerequisite nodes, not against the FIELD action. The field node retains the closure only as current provenance and remains subject to the separate field decision. Its guard inherits this validated closure from the origin without creating a service effect. A service principal can have an explicit FIELD sensitive allow under its protected field ceiling; FIELD IDs are neither HUMAN nor SERVICE non-field IDs, and no human/admin action crosses through this companion. A current sensitive field additionally depends on an exact `field:sensitive.read` node with a matching explicit policy allow; that node shares the same non-field prerequisites and has no derived compatibility allow. The sensitive node does **not** depend back on field:read. A direct sensitive request still requires its non-field prerequisites. Thus sensitivity adds authority without creating a reciprocal cycle or automatic sensitive permission. Registry/projection changes require impact review; no wildcard covers future fields or actions.

Service decisions retain all ten literal SERVICE actions. Assignment record, current service principal and exact current generation credential are mandatory. Dispatch/claim resolve the actual pending job/source/site/service. Metadata/secret/complete additionally require exact current claim and live lease records, source/site/credential/generation/action/request associations and a mandatory full initiating-human `source:scan.request` decision node. Initiator decisions have current membership/content authority but do not require the original browser session to remain open. Lease bearer/hash/credential material never belongs in this pure bundle. Secret reference equality is checked inside the protected adapter; no credential value is a policy fact.

Safe fail/cancel is a separate registered branch requiring current assigned service and exact supplied job; initiating-human denial or expired metadata lease cannot block this minimal terminalization. It cannot derive metadata/secret/complete permission and returns only the already adopted minimal terminal result. Projection consume/write binds exact assigned tenant/index/event family/resource security revision and event identity. Audit/outbox append additionally requires the precise protected command/effect claim; service policy alone cannot mint a journal. Authenticity, unconsumed claims and temporal fencing still belong to protected storage. If a service branch's canonical record schema or adapter is not frozen, that branch is unsupported, never approximated by a generic service scope.

The service companions contain canonical records, never bearers or credentials:

```ts
type VersionRef = { id: UUID; version: Version };
type SourceServiceEvidence = {
  ref: VersionRef; tenantId: UUID; siteId: UUID; securityRevision: Counter;
  secretBinding: { id: UUID; version: Version; sourceId: UUID; siteId: UUID };
};
type JobEvidence = {
  ref: VersionRef; tenantId: UUID; sourceId: UUID; siteId: UUID; serviceId: UUID;
  initiatingIdentityId: UUID; requestHash: Digest; generation: Counter;
  claimVersion: Counter; status: 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled';
  deadlineAt: UTC;
};
type ClaimEvidence = {
  ref: VersionRef; tenantId: UUID; jobId: UUID; sourceId: UUID; siteId: UUID;
  serviceId: UUID; credentialId: UUID; credentialVersion: Version;
  generation: Counter; claimVersion: Counter; requestHash: Digest;
  state: 'active' | 'sealed' | 'revoked'; validity: Validity;
};
type LeaseEvidence = {
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
type ProjectionEventEvidence = {
  ref: VersionRef; tenantId: UUID; family: string; indexId: string;
  resource: ResourceRef; revision: Version | null; securityRevision: Counter;
  generation: Counter; state: 'pending' | 'applied'; eventHash: Digest;
};
type JournalClaimEvidence = {
  ref: VersionRef; tenantId: UUID; operationId: UUID; operationVersion: Version;
  actor: SubjectRef; executorServiceId: UUID; generation: Counter;
  action: 'audit:append' | 'outbox:append'; resource: ResourceRef;
  revision: Version | null; payloadHash: Digest; state: 'unconsumed' | 'consumed';
  validity: Validity; parentDecisions: readonly NodeId[];
};
type TerminalEvidence = {
  ref: VersionRef; tenantId: UUID; jobId: UUID; sourceId: UUID;
  serviceId: UUID; claim: VersionRef | null; generation: Counter;
  action: 'scan-job:claim' | 'scan-job:complete' | 'scan-job:fail';
  requestHash: Digest; result: 'succeeded' | 'failed' | 'cancelled';
};
type ServiceUse =
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
      event: VersionRef; requestHash: Digest }
  | { kind: 'audit' | 'outbox'; assignment: ServiceAssignmentRef;
      claim: VersionRef; payloadHash: Digest };
```

JobEvidence.ref.version is a new authority companion version; it does not add a version to an old job DTO or rewrite legacy job/audit bytes. Source evidence contains identifiers only. Compare all tenant/site/source/job/generation/claim/request associations by value and service/credential ownership using the root/child equations below; the selected action must match the exact service branch and assignment finite set. Dispatch requires queued job; initial claim requires queued/running unsealed job; content/complete requires current running job and exact active current claim/lease, unexpired original job deadline and current initiating decision. A root lease has parentLease:null and issuer.kind:gateway; the exact LeaseIssuerRegistration must be active, now-valid and match tenant/generation. Its audienceServiceId = serviceId = credential.serviceId = assignment.serviceId = job.serviceId = claim.serviceId; credential ref equals claim credential, assignment scopes cover the exact site/source and its actions cover the lease actions. A child lease has a non-null exact parent and issuer.kind:parent-service. Child issuer serviceId equals parent.serviceId; issuer credential and assignment equal the parent’s exact credential and assignment and resolve currently active, valid records. Child audienceServiceId = child.serviceId = child credential.serviceId = child assignment.serviceId. Child service differs from parent service and must be the separately registered worker assignment covering that exact tenant/site/source; no arbitrary transferred audience. Child claim/ref/version, job/site/source/initiator/generation/requestHash equal the parent’s; the canonical claim and job remain associated with the root site service, not rewritten to the worker. Child actions/validity are subsets of parent and its own assignment; all parent records/principals/credentials/assignments are included, validated and charged, with cycle rejection. A selected ServiceUse.assignment and authenticated credential equal the selected lease’s child-or-root assignment/credential; a service grant’s assignment must equal that selected assignment. No parent/site bearer is accepted as worker proof. Root and child lease validity require non-null bounds, at most180seconds, no later than job.deadlineAt and no later than parent expiry. Storage separately proves issuance/allocation counts and the original20minute job deadline; this pure companion cannot reconstruct omitted allocation history.

The initiating node must be the canonical job actor, human, source:scan.request on the exact canonical source and current reference/containment, with scan-initiator authentication naming this job. Its current membership/content policy is required, not the continued existence of the submitting browser session. A live-issuer node similarly uses its exact child grant, current identity/member and full content authority without requiring the historical issuer session. Neither context activates a session-bound elevation by default; explicit elevationSession must resolve the exact current use/session of this same subject and match the protected adapter's permitted authentication mode. A human-session root uses only its own session. No session is demanded for an ordinary grant or borrowed from a different principal.

Metadata/secret/complete lease actions are a finite subset of the adopted allowed lease actions; secret requires exact selected secretBinding and other branches require null. The job original requestHash must equal claim/lease original requestHash. ServiceUse.requestHash binds this current action/consumption, and storage additionally proves its exact command/claim record; it is not substituted for the original job request. Safe fail/cancel requires current assignment and queued/running exact job, while deliberately omitting live metadata lease and initiator permission. Terminal replay requires a matching immutable terminal record/action/request/result/job status and returns only its registered minimal projection. Successful-completion replay additionally has the current canonical initiating decision and exact sealed claim; it does not reactivate a sealed lease or permit another completion. Claim-terminal replay and safe-failure replay retain their narrower registered current-service checks.

Projector event tenant/index/family/resource/security/generation must match current assignment and node; consume/write are distinct exact actions. Applied events allow only registered idempotent replay, not arbitrary content replacement. A journal claim requires exact service/actor/operation/generation/resource/revision/payload and unconsumed state, and ALL parentDecisions must be allowed authorize nodes; a resource-wide guard can never fill that slot. Storage independently checks the actual payload and consumes once. These pure comparisons do not prove authenticated issuance, native-source privileges, actual successful delivery or SQL effect equality.

The service adapter mapping is closed: dispatch→scan-job:dispatch; claim→scan-job:claim; metadata→source:metadata.scan; secret→secret:resolve; complete→scan-job:complete; fail→scan-job:fail; project-consume→projection:consume; project-write→projection:write; audit→audit:append; outbox→outbox:append. terminal-replay permits only scan-job:claim/complete/fail and must equal TerminalEvidence.action. All service branch/action/subject-family mismatches are invalid. Human branches require a HumanActionId/human subject; field branches require a FieldActionId and prerequisite/deny-context NonFieldActionIds of that SAME subject family. Human and service grants may carry separately registered FIELD effects within their exact protected ceiling; this does not permit either family's non-field actions to cross. Sensitive permission is never implied by a service assignment or a ten-string compatibility grant.

## 5. Complete bundle and deterministic output

```ts
type DecisionBundle = {
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
type MatchWitness = { policy: PolicyPin; ruleId: UUID; grant: GrantRef; effect: 'allow' | 'deny' };
type NodeDecision = {
  nodeId: NodeId; validUntil: UTC | null;
  matched: readonly MatchWitness[];
} & (
  | { mode: 'authorize'; allowed: boolean; reason: DecisionReason; derivedOrdinaryFieldAllow: boolean }
  | { mode: 'resource-wide-deny'; clear: boolean;
      reason: Exclude<DecisionReason, 'allowed' | 'no_allow'> | 'clear' }
);
type DecisionBundleResult = {
  outcome: 'evaluated' | 'invalid' | 'unsupported' | 'profile_limit';
  root: Extract<NodeDecision, { mode: 'authorize' }> | null; nodes: readonly NodeDecision[];
  issues: readonly AuthorityIssue[]; metrics: DecisionMetrics;
};
type DecisionMetrics = {
  admission: AdmissionMetrics | null;
  contexts: number; dependencyEdges: number; dependencyReferences: number; dependencyDepth: number;
  policyPins: number; policyBytes: number; policyRules: number; expressionNodes: number;
  bindingInstances: number; roleInstances: number; originGrants: number; delegationRecords: number;
  lineageEdgeOccurrences: number; authorityPrincipals: number; proofBytes: number; factBytes: number;
  actualRuleVisits: number; actualPredicateCalls: number; chargedPredicateNodeVisits: number;
  factValidationVisits: number; memoHits: number; matchWitnesses: number; outputBytes: number;
};
```

Output byte accounting is exact: outputBytes equals the UTF-8 C length of the final entire DecisionBundleResult, including metrics. Compute it by bounded counting serialization: initialize the slot to0, count, replace with that count and repeat until the count is unchanged (at most20 iterations; failure is invalid). Reserve20 decimal bytes for this slot while accumulating bounded output; final real bytes must fit32MiB. This counts strings without retaining repeated serialized copies. Counters are nonnegative safe integers reflecting completed or charged work only, never invented success metrics.

This schema deliberately contains no decision UUID, opaque fence, execution lease, authentication bearer, approved write, SQL or serialized capability. It is private evaluation/simulation data. Explanation disclosure requires separate policy authorization. `matched` is exact and complete within admitted output limits; no first64-match truncation. Invalid/unsupported/profile-limit results have root null and no partial node decisions, with bounded deterministic issues. A complete evaluated bundle may contain denied dependency decisions; its root determines this one atomic outcome, not authorization of an entire business command.

Every ServiceUse branch and registry registration above is implemented in the pure engine with exact synthetic evidence; production assignment/issuer/record provisioning remains runtime work. No unknown JSON bag, arbitrary callback or omitted service branch is a complete implementation. The root node must be authorize mode; a clear target-wide deny guard is never returned or consumed as a general resource allow.

Deterministic algorithm:

1. Apply the shared admission profile to the raw and retained bundle; strictly validate all shapes/primitives, exact registry identity, uniqueness and references. Check policy content against every exact hash/pin and definition association. Reject cycles, disconnected parents, unexpected node references and conflicting duplicates. No partial successful output on malformed input.
2. Recompute node IDs and the required dependency edges from context-bound chain links, target-wide intent guards, field companions, service initiation and exact journal-parent records. Require exactly the reachable closure from root; no unexplained extra node, missing edge, self-edge or cycle. Multiple links to the same exact node share its single evaluation but all reference occurrences count. Stable topological ordering uses node ID lexical order only to break ties; semantics do not depend on input array order.
3. Prove subject/resource/tenant/request/registry agreement and every required ceiling. Missing authenticated provenance cannot be repaired by pure data; the loader's authentication is a prerequisite. Within admitted evidence, inactive subject, unavailable tenant membership and denied ACLs fail closed. Preserve exact subject kind, canonical model UUID aliases, revisions and registered action/kind applicability.
4. Discover derived bindings by expanding every candidate through its whole connected evidence, all exact role policy pins and finite ceilings. Build complete request-role and direct-group facts; missing needed facts are indeterminate. Validate every supplied proof even after a matching proof. No active definition/latest-policy fallback and no filtering out a deny because another policy already allows.
5. Evaluate each reachable dependency before its consumer under the same original `now` and shared budget. Mandatory field/service prerequisites must allow. For chain issuer dependencies, ordinary denial disables that dependent binding; indeterminate contaminates the consumer. Evaluate all relevant admitted rules without effect-based short-circuiting: rule action/field and proven scope select applicability, then the existing interpreter evaluates its expression. Unknown/missing required facts inside any applicable rule prevent an allow even if another rule matches. Every existing AST predicate is implemented; an unknown vocabulary or catalog branch is invalid/unsupported, never a permissive fallback.
6. Aggregate: a required ceiling/prerequisite or target-wide guard refusal denies; otherwise any applicable indeterminate denies; otherwise any matching explicit deny wins; otherwise an authorize node requires at least one matching allow, except the explicitly derived ordinary-field allow. A resource-wide-deny node is clear only when all applicable marked predicates are determinate and none denies; ordinary allows and no_allow do not determine that guard. An expired/future/revoked binding contributes neither allow nor deny at `now`, but a malformed binding never becomes harmless inactivity. A policy containing no action/field-applicable rule cannot create authority.
7. Derive the expiry horizon in section6, retaining dependency horizons. Emit exact stable witnesses sorted by policy ID/version/hash, rule ID, grant kind/ID/version/effect. Deduplicate only identical instances; do not merge different grants or pins. Emit all reachable node decisions sorted by node ID. Bounds apply to this derived representation as well as input.

Reason precedence is deterministic: malformed/unsupported/profile-limit yields the corresponding outer outcome, with bounded private issues and metrics accumulated before failure; for an evaluated authorize node, inactive_subject, tenant_denied, expired, ceiling_denied, indeterminate, explicit_deny, no_allow, then allowed. Known inaccessible complete scope uses scope_unavailable in the ceiling_denied position only when the registered adapter declares that concealment mode; otherwise preserve ceiling_denied. A guard uses the same negative precedence, then clear rather than no_allow/allowed. `expired` may be used only when the node's required authenticated session/credential/elevation use has a known past expiry; do not report it merely because an irrelevant candidate expired. Private reasons never override existing HTTP concealment rules; adapters map them without policy names/counts.

Work accounting is distinct from mathematical truth. Evaluate each dependency node once in topological order, retaining its compact result for the bundle independently of an evictable operation memo. Memoize an actual interpreter invocation by exact normalized expression plus the node's complete derived ExpressionFacts digest; cache only determinate/indeterminate results from that exact context. Charge every instantiated binding/rule visit even when an immutable parsed policy or result is shared.

The frozen interpreter can revalidate a complete used fact array for each distinct expression call. Record actualRuleVisits for each instantiated rule dispatched, actualPredicateCalls for each actual evaluatePolicyExpression invocation, chargedPredicateNodeVisits for its full AST node count before that invocation, and memoHits for exact reused results. PredicateCalls counts whole-expression invocations, not uninstrumented interior leaf calls. Define factValidationVisits deterministically as the admitted JSON value-node count plus own-data-property count of the complete used fact wrappers/payloads and required subject/request/now tuples for each actual call; charge each used fact once per call even if the interpreter exits earlier. These are conservative charged validations, not measured interior loop iterations. These charged counts are explicitly separate from actual AST/rule-call counters; they must not be described as instrumented exact interior loop counts. Memo hits charge lookup/key work and no fresh fact validation. With65,536 distinct calls and1,024 groups, group-element work alone can reach67,108,864; the AST counter does not bound it. No measured maximum-profile/30s capacity follows from these numbers. Future runtime loaders use the original deadline and the admission contract's checkpoints; no pure wall-clock interrupt is claimed. A separately adopted hard fact-validation visit ceiling or a qualified reusable validated-fact interpreter would be an explicit contract change, never an undocumented constant.

## 6. Future starts and validUntil

`validUntil` is an **exclusive time horizon**, not a guarantee against revocation or a portable cache capability. It is the earliest strictly future canonical timestamp at which any relevant part of this decision could change under the same snapshot: starts and expiries of candidate grants/chains, direct-group/tenant memberships, principal/service-assignment validity, sessions/credentials/elevation uses/service claims/leases, every used ProducerRegistration, LeaseIssuerRegistration and approved fact/context validity, and both endpoints of every action/field/scope-relevant time-within expression. Include currently inactive future candidates and denied/nonmatching rules, not only the winning allow. Include every dependency decision's horizon, even when that dependency currently disables a binding.

At exactly a boundary the decision must be recomputed. Examples: an unbounded current allow plus a deny starting at noon has validUntil noon; a current deny expiring at noon yields a denied result with that horizon; a future group membership can activate either kind of rule, so its start is a boundary. A nested any that is currently true still contributes a later time-within boundary; no truth-value shortcut removes it. A chain issuer becoming allowed later may activate a dependent deny, so its negative decision horizon is also retained.

Null means no scheduled future boundary exists in the complete admitted evidence. It never waives generation/epoch/security/session checks and never means a cached result is universally valid forever. Indeterminate/malformed/unsupported/limited results are not cacheable allows. No artificial clock read, refreshed deadline or policy-dependent wall time enters this pure function. Structural changes invalidate external fences independently of these timestamps.

Named helper APIs use this identical grammar; all invoke defensive admission/schema validation and return ordinary data, never authority:

```ts
function hashAuthorityRegistry(registry: Omit<AuthorityDecisionRegistry, 'digest'>): Parsed<Digest>;
function hashAuthorityDefinition(definition: Pick<DefinitionEvidence,
  'formatVersion' | 'kind' | 'id' | 'version' | 'content'>): Parsed<Digest>;
function authorityAnchorDigest(resource: ResourceEvidence): Parsed<Digest>;
function authorityNodeIdentity(snapshot: SnapshotRef,
  node: Omit<DecisionNode, 'id' | 'factDigest'>,
  catalogs: DecisionCatalogs, registry: AuthorityDecisionRegistry,
  origin: Omit<DecisionNode, 'id' | 'factDigest'> | null): Parsed<{ nodeId: NodeId; factDigest: Digest }>;
type DecisionCatalogs = Omit<DecisionBundle, 'formatVersion' | 'snapshot' | 'root'
  | 'nodes' | 'candidates' | 'chainLinks'>;
```

Definition hashing uses the exact discriminated definition content, excluding tenant/current-head/state/hash companions. Registry digest excludes its own digest. Projection registrationHash excludes itself. authorityAnchorDigest is H of `{resource:requestResource,revision:requestedRevision,containment}`; CandidatePartition.anchorDigest must equal it. Node identity helper obtains precisely the selected catalog records described in section3; it cannot accept a caller-stated factDigest. The origin argument is null for authorize nodes and the exact resolved authorize-consumer descriptor for a guard. The helper validates the permitted origin remap and selected records, but does not resolve an arbitrary guardOrigin pointer. Full evaluation additionally verifies that this descriptor is the actual reciprocal bundle node; helpers are construction tools, not a substitute for that check. Helpers cannot validate producer authentication, prove database completeness or approve a command.

The engine owns these cumulative semantic limits, using the admitted snapshot and all dependency nodes together. Count exact records/derived instances as defined above and in the frozen admission accounting; no per-node reset or first-N truncation. Registry and bundle physical input also share8MiB/262,144nodes/depth32; each policy independently remains64KiB raw and normalized.

| Counter | Limit |
| --- | ---: |
| contexts / dependencyEdges / dependencyReferences / dependencyDepth | 128 / 1,024 / 4,096 / 16 |
| exact policyPins / policyBytes / policyRules / expressionNodes | 32 / 2,097,152 / 4,096 / 4,096 |
| derived bindingInstances / roleInstances / originGrants | 512 / 256 / 512 |
| delegationRecords / delegationDepth / lineageEdgeOccurrences | 1,024 / 4 / 3,072 |
| authorityPrincipals / directGroupsPerSubject / proofBytes | 2,048 / 1,024 / 2,097,152 |
| approvedFactIds / factBytes / domainPathEntries | 4,096 / 1,048,576 / 33 |
| field catalogEntries / catalogBytes / fieldBytes | 16,384 / 131,072 / 256 |
| instantiated rule visits / charged predicate-node visits | 65,536 / 65,536 |
| complete matchWitnesses / final output bytes | 65,536 / 33,554,432 |
| private diagnostic issues | 64 |

The64MiB retained canonical-accounting profile remains8MiB raw,8MiB normalized,8MiB compiled/index records,8MiB memo and32MiB output. It is not a V8 heap/RSS guarantee. Semantic buffers, parsed policy definitions, repeated references and exact witnesses must be charged to their appropriate retained category; eviction never discards required evidence or changes completeness.

The adopted semantic override is dependencyDepth **16 total context nodes**, replacing only the earlier admission candidate's proposed8. All other cumulative context/edge/reference limits stay unchanged. Mandatory guards plus four delegation edges already require10 nodes; field/sensitive prerequisites must not make that supported path structurally impossible. Require real pure fixtures for a four-edge chain with guards and field/sensitive prerequisites, as well as exact16/17 depth. The four-edge fixture delegates the non-field prerequisite and uses a separately held protected explicit sensitive FIELD grant; it does not delegate FIELD actions through HumanActionId. Required protected field-companion administration remains later implementation work, not an optional activation exclusion. Counter capacity is not a promise that every independent maximum fits simultaneously or within a measured runtime deadline.

## 7. Required tests before an implementation claim

Use the real parser/interpreter and an independent straightforward reference oracle for decision aggregation. Cover every origin discriminant; exact role/policy/type pins; every altered tenant/subject/action/resource/revision/field/projection association; ordinary historical issuer inactivity versus live delegation/elevation revocation; group membership and parent beneficiary connectivity; widened scopes/actions/kinds/fields/validity/depth; duplicate/conflicting/missing records; documentation-only responsibility; no owner/name/legacy-label authority; complete deny discovery; all relevant future starts/expiries and negative dependency horizons; cyclic/missing/extra dependencies; canonical domain self/direct/ancestor/unassigned cases; old/proposed/multi-resource decomposition; ordinary derived fields, sensitive explicit allow, field denies and prerequisite denial; all ten service branches with no human/service crossover or general journal authority.

Exercise Known/Unavailable/empty/null and no short-circuit indeterminate propagation; exact input immutability and descriptor/proxy failures under admitted inputs; every shared admission boundary and cumulative counters across dependency nodes; final witness/output limit; shuffled set/catalog order invariance; deterministic diagnostics; byte-for-byte policy hash reuse. Preserve all1,024 compatibility subsets and prior parser/expression tests. Pure results cannot qualify producer completeness, authenticated canonical facts, SQL parity, OIDC/service bootstrap, concurrency/revocation, native connectors, HTTP/UI/worker/SQL cutover or release.

## 8. Freeze checklist and runtime separation

The exact DTOs, hash identities, closed registry branch semantics and cumulative semantic counters require joint adoption before implementation. Generic physical admission is already independently adopted. No API capability, SQL migration number, broad base-table privilege or runtime activation is created by that decision. The source action registry remains136 literal IDs; all AST predicates and both field actions are implemented by this full pure engine.

The supplied synthetic registry and canonical record fixtures can qualify this function's structural/decision behavior. Actual production catalog contents, producer authenticity, exact session/service bootstrap, complete database candidate discovery, canonical domain paths/proposed plans, publication/admission impact checks, native-source ceilings, SQL/OpenSearch equivalence and all-ingress cutover still require their separate real gates. Missing runtime infrastructure never converts an unimplemented required pure branch into an optional feature.

Before implementation, mechanically extract the TypeScript blocks into a temporary type-only check against the existing primitive imports, review every discriminant and required field, and design the reference-oracle cases for the declared semantic branches; executing engine cases follows implementation, not this schema-only checklist. This draft records no executed parser, evaluator, database or browser test.
