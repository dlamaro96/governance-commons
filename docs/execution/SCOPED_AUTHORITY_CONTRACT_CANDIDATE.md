# Scoped authority contract candidate

Editorial revision (2026-11-17): coordination-only text was removed. Technical requirements and qualification scope are unchanged. Historical implementation and execution records retain the original contract SHA256 `443a6b796354f6b8daf2dea3b98e83426faca19d4c57139e89a526c533433802`.

Status: **DESIGN CANDIDATE — NO IMPLEMENTATION, ACTIVATION OR VERIFICATION CLAIM.** Prepared 2026-11-16. The adopted design includes the five review recommendations on canonical model identity, exact compatibility predicates, protected SQL enforcement, preservation of integrity guards and old-executor fencing. It also selects the global-identity serialization strategy, request-scoped role evidence, finite administration actions, shared field identities and server-held opaque A1 leases below. The least-privilege database arrangement remains a proposed design requiring concrete privilege/context review. These selections do not supply the remaining projection catalog, aggregate budgets or administrator bootstrap provenance. This candidate specifies the shared interfaces for final review; it allocates no migration number and authorizes no tenant activation. Current execution status remains in [STATE](STATE.md).

Sources: complete [BUILD_SPEC](../product/BUILD_SPEC.md), SHA256 `8bde0eb8d185958cce46c217c01d7263f6708823a11bb1f45cec7a3a3cb24d61`; [earlier proposal](SCOPED_AUTHORITY_DRAFT.md), SHA256 `b08a9c13ca0d41acf843c55279ba56893218d681ef35506bfa358472e69be3f5`; [ingress inventory](SCOPED_AUTHORITY_INGRESS_INVENTORY.md), inspected SHA256 `20ac7e72eb3afefc9c9ec101efe190dc949cc08484d23c9a38ff2f535827e515`, inspected commit `6ff4afd47693a05b8baa2343d24321fcc3451361`. These identify source inspection, not test results.

## Required target and A1 boundary

The complete requirement remains configurable identities/groups/roles/responsibilities, organization/workspace/domain/asset scope, default deny, explicit denies, bounded ABAC and approved relationship grants, field sensitivity, delegation/elevation, policy-equivalent APIs/UI/workers/search, immediate current-authority revocation and auditable decisions. Relevant requirements are CORE-001/002/004/005/006/007, MOD-001, ACC-004, SYS-DATA-001/004/005, SYS-SEC-001/002/003/005, SYS-EDGE-001, SYS-API-001, UX-36/37, AT-TEN-01 and AT-AUD-01. Samples, exports, native access changes, approvals, AI/MCP, SCIM and all other baseline surfaces retain their own required implementation and qualification.

A1 implements the policy/roles/responsibilities/delegation core and cuts over **all existing ingress together**: catalog and search, fields and history, model/type publication/migrations, relation graphs/participation/repair, domain hierarchy/placement, audit/integrity, idempotent results, source/jobs and actual dispatcher/site/Python paths. A2 adds real organizational/workspace entities, approved bounded relationship-derived grants and the remaining provisioning/extensions. Unsupported A2 constructs are rejected by A1, not accepted and ignored. Optional activation never excuses required implementation. Neither increment claims the complete programme or release gates merely from adopting this document.

## 1. Canonical identities and immutable-history compatibility

Use one additive, protected `authority_model_resources` mapping with `(tenant_id, model_id text)` referencing the canonical governance-model row, unique `(tenant_id, resource_id uuid)` and immutable model key/resource UUID. Populate only from actual canonical rows; future creation derives the mapping transactionally from the actual inserted row. Runtime cannot register or rebind arbitrary identities. A repeated migration preserves the original UUID. All tenant-owned tables/FKs/uniques carry tenant scope and force RLS.

Both `/models` and `/asset-types` resolve to this **same `model-definition` authority object**. `governance_models.type_id`, when present, is a verified authored-type alias/subtype fact, never a second independent policy target. Action namespaces may distinguish the flat projection from the authored definition, but resource-wide denies and field restrictions apply to both projections. The type UUID is not rewritten or reused as an unrelated model key. Keys remain case-sensitive and retain their existing grammar; neither UUID-looking text nor display names choose a resource kind. Current model endpoints include authored rows, so a separate unlinked authority object would be an alternate route around a resource deny.

Other existing UUID identities retain their exact kind: relation types, relations, participation bindings, preparations, operations, domains, domain types, sources and jobs. Placement identity is the asset UUID **with kind `asset-domain-placement`**, and its version is the placement version. It is not an asset revision. Model migration receipts use their own operation UUID and resolve their text model key through the protected mapping. A type/version reference always resolves the exact immutable version, never a current-head substitute.

No changes to existing `assetView`, canonical snapshot JSON, SQL007–011 receipt JSON/hashes or audit envelopes are permitted for authority rollout. New protected decision/operation/history companions refer to existing exact revisions. Public egress may use separately declared filtered views; it never rewrites an immutable signed/hash-bearing receipt and presents it as original. If such a receipt contains a currently forbidden field/reference, deny disclosure of the whole receipt. For pre-authority history use recorded immutable references plus current authorization; do not fabricate earlier placement or policy decisions. Missing required historical scope/sensitivity evidence denies that disclosure.

## 2. Exact action registry and ten-string migration

The following TypeScript is an exact **contract declaration for review**, not executable repository implementation. `+` in surrounding prose means all permissions. Registry rows are closed and expand literally; there are no prefix or future-action grants. Each row additionally invokes the resource/field adapter in the ingress inventory. Actual active membership and identity are prerequisites for human compatibility grants.

```ts
export const LEGACY_PERMISSIONS = [
  'catalog:read', 'catalog:write', 'sources:read', 'sources:write', 'audit:read',
  'models:read', 'models:write', 'domains:read', 'domains:write', 'domains:assign',
] as const;
export type LegacyPermission = (typeof LEGACY_PERMISSIONS)[number];
const CR = 'catalog:read', CW = 'catalog:write', SR = 'sources:read', SW = 'sources:write';
const AR = 'audit:read', MR = 'models:read', MW = 'models:write';
const DR = 'domains:read', DW = 'domains:write', DA = 'domains:assign';

// [literal action IDs, exact legacy all-of predicate]. Empty all-of means
// authenticated active-member baseline ONLY for the first row.
export const COMPATIBILITY_ACTIONS = [
  [['session:self.read', 'session:tenant.select', 'schema:read', 'capability:read'], []],
  [['member:owner-candidates.read'], [CW]],
  [['asset:discover', 'asset:metadata.read', 'catalog:summary.read'], [CR]],
  [['asset:description.edit', 'asset:owner.assign'], [CR, CW]],
  [['asset:attributes.read', 'asset:type-state.read'], [CR, MR]],
  [['asset:model.assign', 'asset:attributes.edit', 'asset:type-state.transition'], [CR, CW, MR]],
  [['model:discover', 'model:definition.read'], [MR]],
  [['model:definition.validate', 'model:migration-plan.validate'], [MW]],
  [['model:create'], [MR, MW]],
  [['model:publication.preview', 'model:version.publish'], [MR, MW, CR]],
  [['model:migration.context', 'model:migration.preview', 'model:migration.execute'], [MR, MW, CR, CW]],
  [['model:migration.receipt.read'], [MR, CR]],
  [['asset-type:discover', 'asset-type:definition.read'], [MR]],
  [['asset-type:definition.validate', 'asset-type:create'], [MR, MW]],
  [['asset-type:publication.preview', 'asset-type:version.publish'], [MR, MW, CR]],
  [['asset-type:migration-plan.validate', 'asset-type:migration.context', 'asset-type:migration.preview', 'asset-type:migration.execute'], [MR, MW, CR, CW]],
  [['asset-type:migration.receipt.read'], [MR, CR]],
  [['relation-type:discover', 'relation-type:definition.read'], [MR]],
  [['relation-type:definition.validate', 'relation-type:create'], [MR, MW]],
  [['relation-type:publication.preview', 'relation-type:version.publish'], [MR, MW, CR]],
  [['relation:read', 'relation:discover', 'graph:traverse'], [CR, MR]],
  [['relation:history.read'], [CR, MR, AR]],
  [['relation:create', 'relation:attributes.edit', 'relation:owner.assign', 'relation:visibility.edit',
    'relation:validity.edit', 'relation:state.transition', 'relation:tombstone'], [CR, MR, CW]],
  [['relation-migration:validate', 'relation-migration:context', 'relation-migration:preview', 'relation-migration:execute',
    'relation-preparation:create', 'relation-preparation:replay'], [CR, CW, MR, MW]],
  [['relation-operation:receipt.read', 'participation:read', 'participation:history.read'], [CR, MR]],
  [['participation:enroll', 'participation:release', 'participation:repin'], [CR, CW, MR, MW]],
  [['domain-type:discover', 'domain-type:definition.read', 'domain-type:definition.validate', 'domain-type:migration-plan.validate'], [MR]],
  [['domain-type:create'], [MR, MW]],
  [['domain-type:publication.preview', 'domain-type:version.publish', 'domain-type:migration.preview'], [MR, MW, DR]],
  [['domain-type:migration.context', 'domain-type:migration.receipt.read'], [MR, DR]],
  [['domain-type:migration.execute'], [MR, MW, DR, DW]],
  [['domain:discover', 'domain:metadata.read', 'domain:history.read'], [DR]],
  [['domain:owner-candidates.read', 'domain:create', 'domain:metadata.edit', 'domain:owner.assign',
    'domain:state.transition', 'domain:hierarchy.preview', 'domain:move', 'domain:retire', 'domain:restore'], [DR, DW]],
  [['domain:assets.read', 'placement:read', 'placement:history.read'], [CR, DR]],
  [['placement:assign', 'placement:reassign', 'placement:unassign'], [CR, CW, DR, DA]],
  [['source:discover', 'source:configuration.read', 'scan-job:discover', 'scan-job:read'], [SR]],
  [['source:create', 'source:scan.request'], [SW]],
  [['audit:event.read', 'audit:chain.verify'], [AR]],
] as const;
export type CompatibleActionId = (typeof COMPATIBILITY_ACTIONS)[number][0][number];

export const ADMIN_ACTIONS = [
  'authority:read', 'authority:simulate', 'authority:manage-policy',
  'authority:assign-role', 'authority:assign-responsibility', 'authority:delegate', 'authority:revoke',
  'authority:group.create', 'authority:group.version.publish', 'authority:group.retire',
  'authority:group.member.assign', 'authority:group.member.revoke',
  'authority:role.create', 'authority:role.version.publish', 'authority:role.retire',
  'authority:responsibility-type.create', 'authority:responsibility-type.version.publish',
  'authority:responsibility-type.retire',
  'authority:elevation.issue', 'authority:elevation.use', 'authority:elevation.revoke',
] as const;
export const FIELD_ACTIONS = ['field:read', 'field:sensitive.read'] as const;
export const SERVICE_ACTIONS = [
  'scan-job:dispatch', 'scan-job:claim', 'source:metadata.scan', 'scan-job:complete', 'scan-job:fail',
  'secret:resolve', 'projection:consume', 'projection:write', 'audit:append', 'outbox:append',
] as const;
export type HumanActionId = CompatibleActionId | (typeof ADMIN_ACTIONS)[number];
export type FieldActionId = (typeof FIELD_ACTIONS)[number];
export type ServiceActionId = (typeof SERVICE_ACTIONS)[number];
export type ActionId = HumanActionId | FieldActionId | ServiceActionId;
```

The **21 ADMIN IDs** are finite new actions, all with **no automatic mapping from any of the ten legacy strings**. `authority:manage-policy` manages policy definitions/versions/retirement only; it is not a group, role, responsibility, elevation or content wildcard. The three definition families have explicit create, immutable-version publication and retirement actions. Group membership assign/revoke changes an exact direct membership; nested groups remain unsupported. `authority:assign-role` and `authority:assign-responsibility` assign existing exact definitions within an authorized scope. `authority:revoke` revokes the exact role/responsibility/delegation grant identified by its adapter; it does not replace the explicit group-member or elevation revocation actions. Read/simulation still require `authority:read`/`authority:simulate` on their exact protected objects. Retirement preserves immutable versions and has no implicit cascade or reassignment; its exact impact/active-binding rule must be frozen with the administration adapters.

Elevation issue, use and revoke are separate decisions. Issuance does not activate content access; use additionally requires the named human's current active membership and an exact valid elevation record. Delegation/elevation cannot manufacture authority: the effective action, resource scope, fields, expiry and onward-delegation ceiling must remain within the issuer's currently effective and explicitly delegable authority and every ancestor grant. Expiry is the earliest applicable deadline; revoking any ancestor defeats dependent uses. No ADMIN action, operator label or bootstrap identity confers content access by itself. Human delegation never includes SERVICE/internal append effects. Canonical bootstrap/recovery provenance and the finite delegation/elevation bounds remain explicit design decisions; these IDs alone are not a bootstrap grant.

Normative qualifications to these finite predicates:

- Domain hierarchy preview/move/retire/restore additionally require CR **when the actual complete captured subtree has placed assets**, and visibility of each such asset. Evaluate this before counts. Placement does not acquire DW. Participation/domain/placement history does not acquire AR.
- Audit requires each existing family predicate in the inventory. Legacy generic source/scan/model/type events have AR-only eligibility; preserve this as an explicit closed legacy family rule. New/unknown families, especially authority events, do not enter a permissive generic fallback. The integrity reader preserves fresh exact session binding, one read-only repeatable-read snapshot, hidden-event detection before limits and the current bounded verifier.
- Overview requires CR, but source/job counts additionally require SR and recent audit additionally AR plus its family predicates. Asset embedded attributes/type state already have CR eligibility; dedicated attribute/state routes require CR+MR. A field restriction applies to both projections.
- SW permits source-create/scan operation results without general SR discovery. Domain mutation results may carry an exact type reference without MR. Use action-specific egress; never grant SR/MR merely to make a shared loader convenient. File-only validators authorize a tenant capability and disclose submitted content, not arbitrary canonical resources named in that file.
- All complete mutations authorize affected and referenced resources. A graph execution grant does not replace subordinate publication, migration, relation-change and participation actions on their exact resources. Enroll/release/repin are graph-command subordinate actions, not new endpoints. Unchanged affected members require read authority. Moving/reassigning requires both old and proposed scope authority.
- `field:read` is derived only for fields disclosed by an already authorized action and its declared projection; it is never an independent resource grant. `field:sensitive.read`, every ADMIN action and every SERVICE action have **no automatic ten-string compatibility mapping**. New sensitivity facts/grants require an explicit impact-reviewed activation.

Generate compatibility grants once from actual current permissions, not starter role names, owners, old sessions or seed defaults. Preserve inactive/deleted memberships and revoked grants. A repeat migration/seed cannot restore them. Removing a broad tenant grant is a separate reviewed change; adding a narrower grant beside it does not restrict access.

Before implementation claims, enumerate all **1,024 subsets** of the ten strings for every registry row against an independent legacy predicate oracle, including empty membership permissions. Separately exercise identity/member activity, ACLs, own-creator preparation, expiry, original history scope, conditional hierarchy CR, exact response fields and unknown actions. Pure parity is necessary but not runtime qualification.

## 3. Pure types and bounded policy semantics

These are the proposed shared pure exports. Branded primitives are created only by strict parsers; branding is not authority. UUIDs use canonical lowercase generic 8-4-4-4-12 syntax. Versions are positive safe integers within the existing database bound. UTC timestamps are canonical millisecond ISO strings; validity intervals are half-open `[notBefore, expiresAt)`. Epochs/counters are canonical nonnegative decimal strings to avoid bigint precision loss. Strict JSON ingestion rejects duplicate keys, unknown fields, malformed Unicode, nonfinite/unsafe numbers, inherited properties and unsupported values before normalization.

```ts
export type UUID = string & { readonly __uuid: unique symbol };
export type Version = number & { readonly __version: unique symbol };
export type UTC = string & { readonly __utc: unique symbol };
export type Digest = string & { readonly __sha256: unique symbol };
export type Counter = string & { readonly __counter: unique symbol };
export type FieldId = string & { readonly __registeredField: unique symbol };
export type ProjectionId = string & { readonly __registeredProjection: unique symbol };
export type ResourceKind = 'tenant' | 'tenant-member' | 'source' | 'scan-job' | 'asset'
  | 'model-definition' | 'model-migration' | 'asset-type-migration' | 'relation-type' | 'relation'
  | 'relation-participation' | 'relation-operation' | 'relation-preparation'
  | 'domain-type' | 'domain' | 'asset-domain-placement' | 'domain-type-migration' | 'audit-event'
  | 'authority-group' | 'authority-role' | 'authority-policy' | 'authority-grant'
  | 'responsibility-type' | 'responsibility-assignment' | 'authority-delegation' | 'authority-elevation'
  | 'execution-site' | 'service-principal' | 'authority-decision';
export type ResourceRef = { readonly tenantId: UUID; readonly kind: ResourceKind; readonly id: UUID };
export type RevisionRef = { readonly resource: ResourceRef; readonly version: Version };
export type SubjectRef = { readonly kind: 'human' | 'service'; readonly id: UUID };
export type Scope =
  | { readonly kind: 'tenant'; readonly tenantId: UUID }
  | { readonly kind: 'domain'; readonly tenantId: UUID; readonly domainId: UUID; readonly includeDescendants: boolean }
  | { readonly kind: 'resource'; readonly resource: ResourceRef };
export type RolePin = { readonly roleId: UUID; readonly version: Version };
export type PolicyPin = { readonly policyId: UUID; readonly version: Version; readonly hash: Digest };
export type Validity = { readonly notBefore: UTC | null; readonly expiresAt: UTC | null };
export type AuthorityGrantEvidence = {
  readonly grantId: UUID; readonly grantVersion: Version; readonly issuer: SubjectRef;
  readonly beneficiary: SubjectRef | { readonly kind: 'group'; readonly id: UUID };
  readonly scope: Scope; readonly validity: Validity;
};
export type RoleDelegationEvidence = {
  readonly delegationId: UUID; readonly version: Version;
  readonly parent: { readonly kind: 'grant' | 'delegation'; readonly id: UUID; readonly version: Version };
  readonly issuer: SubjectRef; readonly beneficiary: SubjectRef;
  readonly scope: Scope; readonly validity: Validity;
  readonly actions: readonly HumanActionId[]; readonly fields: readonly FieldId[] | null;
};
export type RequestScopedRoleEvidence = {
  readonly role: RolePin; readonly assignmentId: UUID; readonly assignmentVersion: Version;
  readonly subject: SubjectRef; readonly request: AtomicRequest;
  readonly assignmentScope: Scope; readonly assignmentValidity: Validity;
  readonly origin: AuthorityGrantEvidence;
  readonly viaGroup: { readonly groupId: UUID; readonly membershipId: UUID;
    readonly membershipVersion: Version } | null;
  readonly delegations: readonly RoleDelegationEvidence[];
  readonly effectiveScope: Scope; readonly effectiveValidity: Validity;
};
export type PolicyExpr =
  | { readonly op: 'all' | 'any'; readonly children: readonly PolicyExpr[] }
  | { readonly op: 'subject-in'; readonly subjects: readonly SubjectRef[] }
  | { readonly op: 'group-any'; readonly groupIds: readonly UUID[] }
  | { readonly op: 'role-any'; readonly roles: readonly RolePin[] }
  | { readonly op: 'action-in'; readonly actions: readonly ActionId[] }
  | { readonly op: 'resource-kind-in'; readonly kinds: readonly ResourceKind[] }
  | { readonly op: 'domain-in'; readonly domainIds: readonly UUID[]; readonly includeAncestors: boolean }
  | { readonly op: 'classification-any' | 'approved-tag-any'; readonly ids: readonly UUID[] }
  | { readonly op: 'purpose-in' | 'environment-in'; readonly ids: readonly UUID[] }
  | { readonly op: 'time-within'; readonly validity: Validity };
export type PolicyRule = {
  readonly id: UUID; readonly effect: 'allow' | 'deny'; readonly actions: readonly ActionId[];
  readonly fields: readonly FieldId[] | null; readonly when: PolicyExpr;
};
export type PolicyDefinition = {
  readonly formatVersion: 1; readonly id: UUID; readonly version: Version;
  readonly rules: readonly PolicyRule[];
};
export type EffectiveBinding = {
  readonly grantId: UUID; readonly grantVersion: Version; readonly policy: PolicyPin;
  readonly subject: SubjectRef | { readonly kind: 'group'; readonly id: UUID };
  readonly scope: Scope; readonly validity: Validity; readonly delegationIds: readonly UUID[];
};
export type AuthorityIssue = {
  readonly code: 'invalid_json' | 'unknown_field' | 'type' | 'required' | 'duplicate'
    | 'format' | 'range' | 'limit' | 'unsupported' | 'scope' | 'version';
  readonly path: string; readonly message: string;
};
export type Parsed<T> = { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly issues: readonly AuthorityIssue[] };
```

The AST limits are fixed: **128 expression nodes across the entire definition, depth8 with root depth1, 64KiB UTF-8 definition size, 256 entries in each finite set, 32 canonical domain ancestors**. Rules are nonempty and at most128; all/any children and finite sets are nonempty. Bound both raw input and normalized serialization; limits apply cumulatively, not independently per rule. Count each expression node once. Reject duplicate rule IDs and duplicate set values; do not silently discard unknown/duplicate input. Normalize declared sets by their exact scalar/tuple comparator, preserve rule/child order for deterministic diagnostics, and use one specified canonical JSON hash implementation shared with SQL. No user script, SQL, regex, arithmetic, arbitrary metadata-path lookup, nested groups or unbounded graph traversal is supported.

`fields:null` is an **action-specific resource rule**: its `actions` array remains exact. It does not mean all actions on that resource. A **resource-wide deny** is a separately declared administration intent, expanded at publication into the complete finite applicable non-field action set for the canonical resource kind and pinned registry version. A field grant cannot defeat denial of its prerequisite resource action. For a `model-definition` this includes the applicable `model:*` and `asset-type:*` IDs together; no runtime wildcard or prefix expansion exists. Persist the expansion provenance in a protected companion without modifying this AST's action semantics. Adding a registry action requires an impact review and forward deny expansion before that action can activate; an old deny must not silently leave a newly introduced alias route open. An action-specific deny may intentionally target only one operation, and the administration UI/simulation must label that difference.

Field-targeted rules accept only registered field actions and nonempty declared field sets. Field IDs resolve through a trusted projection/schema catalog, not arbitrary client JSON paths. Approved tags/classifications come from canonical approved facts, never arbitrary source metadata or suggested classifications. Resource kind is canonical: an authored asset type is still `model-definition`; authored subtype/alias is validated by its adapter. Roles are exact version pins; publishing a new version does not rewrite old assignments. `role-any` evaluates **request-scoped canonical assignment evidence**, never a union of all roles held anywhere by the subject. Each evidence item must match the exact atomic subject/action/resource/revision/field, have a current active exact assignment and origin grant, a valid direct-group membership when applicable, and a fully connected current delegation chain. Every chain edge must name its actual parent grant/delegation and exact version, issuer and beneficiary, remain within inherited scope/actions/fields, and satisfy every validity interval; the effective scope and validity are their verified intersection. Domain-A-only evidence cannot match a Domain-B request. Evidence for one atomic request cannot be reused for another member of a complete scope. The loader and evaluator both reject mismatched evidence; a role fact itself grants no operation. Aggregate chain/principal bounds remain a contract-defined budget, never silent truncation.

Evaluate all relevant predicates with explicit three-way results `match | no-match | indeterminate`. An indeterminate input, missing required fact, unsupported construct, failed lookup or exceeded bound denies the whole request, including when encountered inside an otherwise matching `any`; it must not silently turn a deny into no-match. After activity/tenant/source/ACL ceilings, any matching explicit deny defeats all allows. Otherwise at least one applicable allow is required. Ancestor inheritance is explicit on each domain binding; a narrower allow never overrides an inherited deny. Unassigned assets inherit tenant scope only. Retired domains retain identity and applicable denies.

## 4. Evaluation, projections and application boundary

```ts
export type LoadedSubject = {
  readonly ref: SubjectRef; readonly active: boolean; readonly tenantEligible: boolean;
  readonly identityRevision: Counter; readonly membershipRevision: Counter | null;
  readonly groups: readonly UUID[];
  readonly requestRoles: readonly RequestScopedRoleEvidence[];
};
export type LoadedResource = {
  readonly ref: ResourceRef; readonly version: Version | null;
  readonly domainPath: readonly UUID[]; // current direct domain first, then ancestors
  readonly securityRevision: Counter;
  readonly classifications: readonly UUID[] | null; readonly approvedTags: readonly UUID[] | null;
};
export type AtomicRequest = {
  readonly action: ActionId; readonly resource: ResourceRef; readonly revision: Version | null;
  readonly field: FieldId | null;
};
export type EvaluationInput = {
  readonly tenantId: UUID; readonly subject: LoadedSubject; readonly now: UTC;
  readonly purposeId: UUID | null; readonly environmentId: UUID;
  readonly resource: LoadedResource; readonly request: AtomicRequest;
  readonly bindings: readonly EffectiveBinding[]; readonly policies: readonly PolicyDefinition[];
  readonly ceilingsSatisfied: boolean;
};
export type DecisionReason = 'allowed' | 'no_allow' | 'explicit_deny' | 'inactive_subject'
  | 'tenant_denied' | 'ceiling_denied' | 'scope_unavailable' | 'expired'
  | 'indeterminate' | 'profile_limit' | 'unsupported';
export type PureDecision = {
  readonly allowed: boolean; readonly reason: DecisionReason; readonly validUntil: UTC | null;
  readonly matched: readonly { readonly policy: PolicyPin; readonly ruleId: UUID; readonly grantId: UUID }[];
};
export type FieldProjection = {
  readonly projectionId: ProjectionId;
  readonly shape: 'complete' | 'filtered';
  readonly fields: readonly { readonly fieldId: FieldId; readonly access: 'include' | 'omit' }[];
  readonly hash: Digest;
};
export type AuthorityFence = {
  readonly generation: Counter; readonly tenantEpoch: Counter;
  readonly subjectRevision: Counter; readonly resourceSecurityDigest: Digest;
  readonly projectionHash: Digest; readonly validUntil: UTC | null;
};
export type AuthorizedResult = {
  readonly decisionId: UUID; readonly projection: FieldProjection;
  readonly opaqueFence: string; readonly validUntil: UTC | null;
};
export type CompleteScopeRequest = {
  readonly adapter: string; // closed server-owned ingress registry ID, never arbitrary user input
  readonly operation: string; readonly requestHash: Digest;
  readonly requirements: readonly AtomicRequest[];
  readonly purposeId: UUID | null; readonly delegationId: UUID | null;
};
export interface PureAuthority {
  parsePolicy(input: unknown): Parsed<PolicyDefinition>;
  parsePolicyFile(text: string): Parsed<PolicyDefinition>;
  evaluate(input: EvaluationInput): PureDecision;
  compatibilityActions(permissions: readonly LegacyPermission[]): readonly CompatibleActionId[];
}
export type AuthorityErrorCode = 'AUTHORITY_REQUIRED' | 'AUTHORITY_DENIED' | 'AUTHORITY_NOT_FOUND'
  | 'AUTHORITY_SCOPE_UNAVAILABLE' | 'AUTHORITY_INPUT_INVALID' | 'AUTHORITY_PROFILE_LIMIT'
  | 'AUTHORITY_UNSUPPORTED' | 'AUTHORITY_STALE' | 'AUTHORITY_EXPIRED'
  | 'AUTHORITY_RETRY' | 'AUTHORITY_STORAGE_INVALID' | 'AUTHORITY_GENERATION_UNAVAILABLE';
export type AuthorityProblem = {
  readonly correlationId: string; readonly issues?: readonly AuthorityIssue[];
} & (
  | { readonly code: 'AUTHORITY_INPUT_INVALID'; readonly status: 400 }
  | { readonly code: 'AUTHORITY_REQUIRED'; readonly status: 401 }
  | { readonly code: 'AUTHORITY_DENIED' | 'AUTHORITY_SCOPE_UNAVAILABLE'; readonly status: 403 }
  | { readonly code: 'AUTHORITY_NOT_FOUND'; readonly status: 404 }
  | { readonly code: 'AUTHORITY_STALE'; readonly status: 409 }
  | { readonly code: 'AUTHORITY_EXPIRED'; readonly status: 410 }
  | { readonly code: 'AUTHORITY_PROFILE_LIMIT' | 'AUTHORITY_UNSUPPORTED'; readonly status: 422 }
  | { readonly code: 'AUTHORITY_STORAGE_INVALID'; readonly status: 500 }
  | { readonly code: 'AUTHORITY_RETRY' | 'AUTHORITY_GENERATION_UNAVAILABLE'; readonly status: 503 }
);
```

`EvaluationInput` is a pure test/evaluator input, **not an HTTP request or DB capability**. Trusted adapters load its subject, groups, policies, domain ancestry, approved facts, database time and ceilings. SQL independently proves equivalent scope/facts/decisions for protected effects. Every pin must resolve its exact policy version/hash; missing/mismatched policy, tenant, resource, role or delegation evidence is indeterminate, never ignored. Role/delegation chains must already be validated against current canonical records, then checked for exact request binding by the evaluator; an arbitrary list of IDs in a pure input proves nothing. Group facts also require current canonical direct memberships, not body-supplied IDs. `purpose-in` and `environment-in` require explicitly defined trusted provenance adapters: an approved canonical context, its current version/validity, and its binding to this authenticated subject/request or executor environment. A submitted `purposeId`, header, label or environment string is only a selection request, never evidence. Until those exact adapters and their negative tests exist, publication/activation of rules using either predicate is rejected as unsupported; live evaluation without the required evidence fails closed, even inside `any`. Their declared AST vocabulary and pure test inputs are not activation authorization. Pure evaluation does not allocate a decision UUID, approve a change, lock a row or mint an execution lease.

Application services expose `authorizeOne`, `authorizeCompleteScope`, `compileAuthorizedRead`, `authorizeReplay`, `claimExecution` and `explainAuthorizedDecision`. The shared service derives `CompleteScopeRequest` from a closed adapter and canonical operation; callers cannot submit a filtered page as the complete scope. Requirements include both old/proposed containment for moves, all immutable references for history/replay, and each subordinate effect. Resource identity and action suitability must agree with the registry. Creation authorizes destination tenant/parent and existing referenced objects before deriving the new canonical ID.

Field IDs identify canonical semantic fields, not route-local JSON paths. A value reachable through model/type aliases, embedded asset attributes, joined labels, operation results, history/audit/receipts or search must resolve to the **same canonical field ID and current sensitivity facts**, with the projection adapter recording how that value is obtained. Different JSON paths do not create independent permission targets. Resource-wide denies and field denies therefore apply before every alias/embedded projection. Exact field enumeration and action/resource applicability remain a closed catalog to be frozen by root; these invariants are selected now, not a claim that that catalog exists.

Projection IDs identify versioned egress schemas. Required identity/structural fields cannot be omitted while returning the unchanged DTO: deny that object/response, or use a separately declared filtered/discovery DTO. For existing required-field DTOs the default is whole-object denial, applied before selection, pagination, counts and facets; complete-scope responses/receipts fail as a whole. Filtering an already paged result is not equivalent. Optional field omission is permitted only where its egress schema explicitly permits it; no placeholder, masked literal or null is invented to look like original data. Fields influencing search text, sort, ranking, facets or snippets are checked before those operations. Whole-resource allows do not imply sensitive-field permission. Field enumeration/hash and current security fence are part of cached decisions/cursors. Existing hash-bearing receipts require an entirely permitted projection.

Internal error reason/detail is private. Public mapping: malformed input400, missing authentication401, ordinary action denial403, undiscoverable individual resource404, hidden complete scope403, stale consent/fence409, expired creator-owned preparation410, authorized profile/unsupported policy422, retry/unavailable generation503, inconsistent storage500. No forbidden resource/policy names, counts, literals, rule matches or SQL diagnostics appear in errors. Established operation-specific codes may remain through an explicit adapter; mapping must not change the current403-before-limit and404 concealment contracts. Parser issue paths describe submitted input only. Simulation explains matching rules only when the caller can read those rules/resources; it has no execution capability.

The contract still requires an explicitly defined `AdapterId`/`ProjectionId`/`FieldId` catalog before independent adapters are implemented. The strings in the interface are registry handles, not permission to accept arbitrary identifiers. Projection inventories must include joined owner/source/type labels, embedded attributes, operation responses, canonical/history snapshots and search fields; partial field coverage cannot activate sensitivity policy.

## 5. SQL enforcement, concurrency and decision companions

Keep all existing applied migrations immutable. Forward changes add forced-RLS authority records, canonical UUID mapping, private decision/operation bindings and read/write guards. A decision companion binds actual tenant, authenticated actor/service, transaction ID, original start/deadline, generation, action, canonical resource/revision union, request hash, policy/grant/security versions, projection and outcome. Runtime cannot insert/update private decisions or turn a GUC, submitted JSON/hash or simulation result into an allow. Use least-privilege reviewed entrypoints and fixed search paths; runtime never owns tables or bypasses RLS.

Extend SQL009/010 graph and SQL011 domain prepared claims with additive protected decision companions. Preserve begin/claims/writes/seal/idempotent-success/deferred-finalize ordering, exact journals, normalized outcomes, no unclaimed extra writes, no early inner finalization, immutable nested SQL007 receipts, original-scope replay and family separation. Ordinary asset/model/source/job writes need equivalent action-bound evidence: replacing only `gc_relation_authorize(actions[])` or `gc_domain_authorize(actions[])` cannot establish resource authorization. Those old signatures lack the actual command/resource union. The separate `gc_domain_scope_epoch` MR-or-DR check must also be replaced by its adopted read adapter, not accidentally left as a legacy allow path.

Preserve complete structural visibility: hidden edges still constrain cycles, cardinality, required participation and endpoint validity. Scoped read filtering must never shrink protected validation cohorts. Conversely, current broad runtime SELECT plus tenant-only RLS is not proof of scoped direct-SQL read enforcement. The forward storage contract must separate scoped external read access from narrowly protected complete-scope integrity access, with no generally callable unrestricted data-returning helper. The concrete privilege/RLS/view/function arrangement must be defined before SQL implementation.

**Proposed least-privilege database arrangement — for concrete review, not finished SQL signatures:**

- Use a distinct authenticated runtime role for the new executor generation. It has no base-table `SELECT`, no session-table `SELECT`, no generic base-table writes and no right to mint/update private authority contexts or change roles into an integrity owner. Its allowed surface is an explicit finite set of reviewed protected reads/commands. Do not give it inherited access through `PUBLIC`, views, old helper functions, role membership or default privileges. Tenant RLS remains forced on tenant data; function owners remain non-runtime, with fixed search paths and narrowly enumerated access.
- A protected transaction-context entrypoint derives the human actor/tenant from the **exact live session hash**, verifies identity/member/session activity and expiry, and binds the approved executor generation, backend/transaction, original deadline and current authority. The runtime cannot substitute an actor/tenant or use a chosen `gc.*` value as evidence. For services it verifies the registered service credential plus exact current opaque lease/claim; dispatch, initial claim and safe cancellation use separately scoped service-bootstrap/terminal contexts because no valid metadata lease may yet exist. Those exceptions disclose no secret/content and cannot mint a general context.
- Keep a separate narrowly privileged login/session issuer role behind the OIDC authentication boundary. It may complete exact verified sign-in/session operations and revoke/select an eligible tenant through reviewed entrypoints, but cannot read tenant content, mint arbitrary authority decisions or expose session tables. The ordinary runtime cannot enumerate or issue sessions to impersonate another user. An exact hash is a bearer authentication input, not public metadata: protect it from logs/artifacts and validate it with the trusted issuer records. Freeze the precise issuer-to-context credential/session proof before SQL implementation.
- Separate scoped data-returning read adapters from private complete-integrity helpers. Integrity helpers see the full structural cohort only inside an authenticated protected operation; they return no generally callable raw rows and cannot be reached by an ordinary runtime function call or `SET ROLE`. Journal/replay/finalization helpers retain their current protected ordering and independently derive the complete command scope.
- During coordinated activation, revoke/fence old `gc_app` credentials and base-table/function privileges, prevent new old-generation connections, and drain or terminate outstanding old transactions before enabling scoped policy. Account for pooled sessions, prepared statements and already-open transactions; password rotation alone does not invalidate existing connections. Stale registrations/claims/contexts must fail even if an old process copies the new numeric generation. Cutover tests execute attempted raw reads/writes, forged sessions/GUCs and old live connections using the actual runtime roles. Recovery remains fail closed or forward repair, never regranting broad legacy access.

The exact roles, privilege matrix, authenticated context/issuer proof, protected read signatures and drain protocol still require design review and real upgrade/concurrency qualification. No new migration or verified enforcement follows from this design.

The fixed mutation lock order is existing idempotency reservation, tenant ledger, protected tenant authority fence, existing model/type/domain/canonical resource order, then **one globally UUID-sorted global-identity share-lock phase followed by UUID-sorted tenant-membership share locks**. Collect actor, owners, grant/group/delegation issuers/beneficiaries and other authority principals before locking; no later lower-UUID append. Re-read activity/current authority after locks and hold them through commit. Keep existing bounds and one original deadline; additional grant/principal fan-out requires an explicitly bounded complete union, never silent truncation. BEFORE STATEMENT conflict fences remain nonblocking/fail-fast when arbitrary row locks could already exist. Never acquire a waiting tenant advisory lock from a row trigger.

**Adopted global-identity strategy:** the global identity update itself is the serialization point. It must not hold an identity row while acquiring tenant ledgers, and it performs no synchronous tenant-lock fan-out. If a protected mutation acquired the identity share lock first, it may commit before deactivation; deactivation then commits and all later authorizations deny. If deactivation acquired its conflicting lock first, the mutation waits/rechecks or retries and cannot commit using stale activity. Reads use a fresh primary snapshot and current identity state; cached epochs alone cannot establish activity. Tenant grant/group/membership changes use the tenant ledger/authority fence before ordered principals. Time-only expiry needs a fresh database-clock check immediately before protected completion and cannot wait for a scheduled epoch bump. Pure approval/decision history remains historical evidence after revocation.

## 6. Sites, workers and internal action scopes

Human, service and transaction-internal actions are distinct. None of the ten legacy strings grants service actions. A human grant cannot contain service actions; a service grant cannot contain human administration/content actions. Field actions require a non-null registered field and an already authorized action-specific projection; non-field actions require `field:null`. Transaction-internal append actions require command claims even if a service policy allows the enclosing operation. A canonical service principal has explicit tenant/site/source bindings and independent active/revoked state. A source job resolves its source, initiating actor and execution site from canonical records; caller-provided associations are not trusted. Existing shared token/tenant allowlist configuration is authentication/bootstrap input only, not the final scoped evaluator or proof of rotating credentials.

| Internal action | Exact scope/effect |
|---|---|
| `scan-job:dispatch` | Assigned service + tenant + canonical pending job/source; exposes only dispatch identifiers. Temporal IDs are not grants. |
| `scan-job:claim`, `source:metadata.scan` | Assigned service/site/source and current initiating-human `source:scan.request`; acquire one fenced job claim and a current bounded metadata lease. Native source privileges and destination restrictions remain independent ceilings. |
| `scan-job:complete` | Exact claimed job, service/site/source, original request/lease generation, current initiating authority and complete reconciliation effect. Recheck before commit; reduced/incomplete scans cannot prove deletion. |
| `scan-job:fail` | Exact assigned job and narrowly allowed terminalization effect. Human revocation must not prevent safe cancellation/failure, but failure authority does not return source configuration or asset content. Terminal/retry branches still require current service authority and a minimal result projection. |
| `secret:resolve` | Canonical tenant/site/source/secret-reference binding and valid claim/lease, resolved at the authorized site. No human source-read/write response returns credential material. |
| `projection:consume`, `projection:write` | Exact assigned tenant/index/event family, current canonical resource/security revision and idempotent event identity. No content disclosure to the initiating user is inferred. Security events cannot be acknowledged without applying their defined security effect. |
| `audit:append`, `outbox:append` | Internal effects bound to the protected canonical command and exact expected journal claim. Never a general service entitlement to forge events, change past audit or bypass a missing business-action grant. |

**Selected A1 lease mechanism:** mint a cryptographically random **256-bit opaque value** at a protected current-authorized claim. Return it only over the authenticated direct API/site channel, retain it only in the executing process's bounded memory, and store only its SHA-256 hash in the protected server lease record. The value, its hash, service credentials and secret references must not enter Temporal workflow inputs, activity inputs/results, heartbeats, exception messages or history. Temporal carries only the non-secret tenant/job/site/service/lease/claim reference IDs required by the declared workflow; possessing those IDs does not authorize redemption. Activity loss/restart requires a fresh online claim or approved exact-claim renewal/reallocation, not recovering a bearer from workflow history.

The protected server record binds `{formatVersion:1, leaseId, issuerId, audienceId, tenantId, serviceId, credentialVersion, siteId, sourceId, jobId, initiatingIdentityId, actions, requestHash, generation, claimVersion, issuedAt, expiresAt, policyDigest, tokenHash, state}`. All identifiers/hash/counter/time fields use the primitives above; `actions` is a finite server-derived subset of `source:metadata.scan`, `secret:resolve`, `scan-job:complete` and `scan-job:fail`, never caller-selected. Exact canonical issuer, audience, current service/credential, tenant/site/source/job and claim generation must agree at each redemption. No unsigned object, client-stated association or hash comparison alone establishes authority. The service credential and live lease are both required for content/secret work; the bearer is not transferable to another service/site/job. Resolve references server-side and recheck current service, initiating authority, policy, expiry and native-source ceilings before protected work/commit.

Record each protected consumption against its exact action and request hash. Terminal completion seals the claim/lease and cannot execute twice; an exact retry is independently authorized for its minimal terminal result, while conflicting request content is rejected. Revocation, expiry or a replacement claim invalidates prior content/secret use; reallocation advances the canonical claim generation. No renewal silently extends the original operation deadline or revoked authority. Lease lifetime, renewal/reallocation bounds and hard-failure recovery remain explicit contract-defined budgets. Online claim/complete is mandatory for A1 current scans; there is no environment-variable or offline fallback.

**Separate terminal failure/cancellation projection:** successful safe terminalization and its exact authorized retry return only `{jobId, terminal:true}` for the already supplied exact job ID. They disclose no source configuration, secret reference, metadata, actor, timestamps, asset counts, stored result or error payload. This is a new internal DTO, not a rewrite of historical job/audit/receipt records. Current service assignment and `scan-job:fail` authority may permit narrow fail/cancel after initiating-human revocation or lease expiry; this exception cannot resolve secrets, claim metadata, complete successfully or gain content. A revoked service cannot invoke it; a separately authorized recovery service must take an explicit canonical assignment. Existing terminal claim/complete branches require their own current service/claim/egress checks before any return and cannot fall through to the old `jobView`. No denied caller learns terminal existence/state from this adapter.

Old immutable audit envelopes with actor text `site:local` retain those exact bytes. New canonical service UUIDs do not rewrite or reinterpret historical actors as current authenticated principals. Their historical display is an explicitly authorized legacy projection; it cannot establish a present service grant or lease.

Offline collection, credential rotation/mTLS and external effects retain their broader SYS-EDGE/SYS-SEC gates; a local metadata lease does not qualify them.

## 7. Atomic activation and mandatory qualification

Use one protected tenant authority generation/mode read by every ingress. Compatibility grants retain actual current reach while the new evaluator is compared diagnostically. Shadow allows never grant. No new scoped assignment, field restriction or deny is activated while any existing route, SQL path, replay, search reader, dispatcher/site/Python executor or projector can still use an old authority path.

Before activation, bind and enforce an executor generation across app/worker/site credentials or authenticated registrations, commands/leases and protected DB contexts. Stale executors and unfenced direct commands must fail closed, including reads and terminal result disclosure. A tenant flag plus cooperative process upgrade is insufficient. Old sessions can remain authentication sessions only if fresh requests resolve current generation/grants; their cached permission arrays are UI hints, not authority. Replace both passed-principal checks and freshly loaded legacy-array checks together. Generation rollback cannot restore a permissive evaluator; use fail-closed recovery or forward repair.

Activation requires an isolated forward-upgrade gate preserving all original revisions/receipts/checksums, 1,024-subset compatibility parity, pure/PostgreSQL/real OpenSearch policy equivalence, all current API/browser/worker regressions, current-authentication and pool-reset checks, direct-SQL forged/omitted/extra claim and journal attacks, both revocation lock orders, shared-model alias/resource-wide deny expansion, Domain-A-to-B role-scope isolation and delegation revocation, whole hidden-cohort refusal, field leakage through every projection, forged purpose/environment facts, original-scope replay after moves, stale-index/paused-projector revocation, lease expiry/duplicate/reallocation checks and real PostgreSQL scan revocation at claim/completion. Test actual runtime roles and role/grant tables; no fabricated decision rows or privileged bypass qualifies a runtime case. Retain failures and exact source/image/command evidence; no gate has run for this candidate.

## 8. Remaining design decisions and implementation boundaries

These decisions block the corresponding implementation; they are not TODO implementations concealed behind passing status:

1. Freeze the closed adapter/projection/field catalog, including action-to-resource-kind applicability and all required/optional fields. Decide which **new** filtered DTOs are warranted; preserve current DTOs and receipt formats. Freeze aggregate policy/grant/principal budgets across one operation in addition to the adopted AST limits, and define authorized fail-closed responses for larger scopes.
2. Freeze authority administration bootstrap/recovery provenance, the exact adapters for the selected 21 ADMIN IDs, retirement impact and aggregate delegation/elevation bounds. Their finite names and attenuation/current-membership requirements are selected above; none of the ten strings or an administrator role name supplies bootstrap authority or implicit content access. Define the exact canonical installation/recovery proof and its auditable scope/expiry before granting anything.
3. Review and freeze the proposed least-privilege DB arrangement above: actual role/privilege matrix, issuer/session/context proof, protected read/write signatures and old-generation connection/transaction drain protocol. Prove it prevents old binaries or direct raw reads from bypassing active scoped policy while preserving private complete integrity validation. The design is proposed; concrete SQL signatures/tables and migration allocation remain unchosen.
4. Freeze service principal/site bootstrap provenance, canonical issuer/audience records, lease lifetime/renewal/reallocation and hard-failure budgets for the selected opaque hashed A1 mechanism. The separate minimal fail/cancel projection and current-service requirement above are selected; the precise recovery-service assignment process still needs approval. Preserve source-native restrictions and no secrets/bearer hashes in Temporal history. These are security contracts, not environment-variable fallbacks.
5. Freeze approved classification/tag facts, shared canonical field catalog, sensitivity activation impact and legacy missing-history handling per projection. Freeze exact trusted purpose/environment provenance adapters before those predicates can publish/activate. No submitted purpose ID as evidence, fabricated old facts, permissive legacy-history escape or wholesale reseeding is allowed.

Implementation boundaries are shared contracts/registries; pure parsers, evaluator and compiler parity; forward SQL privilege separation and concurrency; application/worker/search adapters; and administration UI. Implementations must preserve existing receipts, applied migrations and one canonical authority source. This proposed contract does not itself modify runtime permissions, requirement status or verification evidence.