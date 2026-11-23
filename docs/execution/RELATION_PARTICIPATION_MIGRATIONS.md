# Required relation participation and explicit migration — implementation contract

Editorial revision (2026-11-17): coordination-only text was removed. Technical requirements and qualification scope are unchanged. Historical implementation and execution records retain the original contract SHA256 `8310400a3a5e406a0e2b36be8dc1302640cd0c83b977187d225eacad20ce81ae`.

Historical design status: **IMPLEMENTATION OPEN — NOT VERIFIED AT THIS CHECKPOINT.** Source basis: checked commit639d4c23954745a9acf83926432c55d35a462284. This design record does not advance any capability or milestone verification status. SQL001–008 remain immutable. Implementation, execution evidence and release readiness remain separate.

The governing sources are `docs/product/BUILD_SPEC.md` (MOD-001–004, CORE-002/006/007/009, SYS-DATA-001–005, SYS-SEC-002/003, AT-MOD-01 and E2E-06), `docs/product/requirements.yaml`, `docs/execution/PLAN.md`, and `docs/execution/CONSTRAINED_RELATIONS.md`. MOD/AT-MOD and related system requirements remain IN_PROGRESS; E2E-06 remains NOT_STARTED in the current register. This draft changes none of those statuses. Read the current STATE and actual evidence before describing SQL008 as applied or qualified.

## Existing implementation and proposed boundary

Current source implements asserted relation types and immutable revisions, live-edge uniqueness, pinned endpoint validation, structural maximum degree/cycle checks, complete proposed asset endpoint guards, and authorized bounded graph traversal. Positive minima are explicitly rejected; destructive relation publication requires a migration that is not implemented. Existing authored-type migration already transforms complete mixed-pin asset cohorts with normalized immutable receipts. Its schemas and historical receipts must remain readable.

This proposed increment supplies positive structural participation over eligible zero-edge assets, explicit complete relation migration and graph repair, visual/declarative plans, and receipts with actual before/after revision references. It includes the joint endpoint/edge changes necessary to enter or leave a required relation scope. A standalone positive-minimum parser without enrollment, deletion guards, first assignment and atomic repair is insufficient.

The first execution profile remains a bounded single PostgreSQL transaction. Durable larger-cohort migration, simultaneous-validity cardinality and the other obligations listed below remain required programme work. Refusing an oversized scope explicitly is a profile boundary, not completion of those obligations.

## Reviewed participation semantics

1. Introduce relation definition `formatVersion:2` for the participation semantics below. Minima are integers 0–1,000; finite maxima are integers 0–1,000 with `min <= max`. Null maximum means no declared upper bound. Thus 0..0 is supported and forbids any qualifying live edge. Preserve format1 parser/runtime behavior exactly: minima zero, finite maxima 1–1,000, positive minima explicitly unsupported. Do not reinterpret or rewrite a format1 definition/revision as format2. The model's ordinary version still advances exactly one when publishing a format2 successor; format and model versions are distinct.
2. The immutable relation-type version is the participation policy. Source/target nominal rules and the asset's actual exact-pinned ancestry/state define eligibility. Source scan availability, asset visibility, ownership and the existence of an edge do not define eligibility. An untyped/attribute-only asset is ineligible. Every eligible asset must be considered, including assets with no incident edge. Current type heads never substitute for an asset's actual pinned ancestry or lifecycle.
3. Directed policies have separate `source` and `target` participation. An asset eligible on both sides can have two bindings. Undirected policies have one `incident` binding, symmetrical eligibility/cardinality and canonical endpoint ordering. A self-edge counts once in each directed degree or once in undirected degree, matching the existing structural convention.
4. Persist one active binding per `(tenant, relationTypeUUID, assetUUID, side)`. A binding has immutable UUID/type/asset/side identity, own optimistic version, an exact relation-policy version, `active|released` status, actual asset revision at enrollment/changes, and immutable revisions. Release is a new revision, never deletion. A released binding is not resurrected; a later enrollment receives a new UUID. A direction change removing a source/target/incident side releases that old binding and enrolls the required new side; it cannot mutate a binding's immutable side through repin.
5. Define a canonical structural/participation fingerprint from `direction`, canonical `sourceTypes`, `targetTypes`, `sourceStates`, `targetStates`, full incoming/outgoing `cardinality`, `allowSelf` and `cycles`. It excludes label, own attributes, owner and own lifecycle; those retain their separate compatibility checks. Hash the normalized semantic projection, not raw authored ordering or format number. Identical-fingerprint publication may preserve exact old binding/edge pins. A fingerprint change requires every affected active binding to repin to the operation target or explicitly release where permitted. No weaker old binding may satisfy a new stronger admission policy. Every surviving edge pin of a logical type must have the same structural fingerprint as its final head: a structural change explicitly repins, replaces or tombstones the complete live cohort. Never validate cycles solely from a newer permissive head while old acyclic pins survive.
6. Enrollment is a synchronous invariant. For a positive-minimum side, every asset eligible under the current admission policy must have an active binding. A publication that changes selector, minima/maxima, direction or other destructive policy requires complete migration of affected bindings and edges, including currently bound assets outside the proposed selector. Publication with no live edges is still a migration when existing eligible/bound assets are affected.
7. A newly eligible asset is enrolled before commit at the exact final head. Binding repin in repair mode may target only the committed head; in publication mode it may target only that operation's publication target. An ordinary assignment/state transition succeeds only if its full final relation set satisfies the new binding. Leaving eligibility does not silently release an old obligation. An explicit graph plan must release/repin it and acknowledge the policy/scope change. Release is permitted only when the asset is no longer eligible under the final admission policy for that side, or that final side has minimum zero. It cannot be used as an exemption for an otherwise eligible required participant. The final check derives required membership independently of the plan.
8. All active edges of the logical relation type count, including restricted, expired and future-valid edges. Tombstones do not count. Relation lifecycle does not suppress degree. An edge may satisfy a binding pinned to another version of the same logical type only with the uniform structural fingerprint above; each still satisfies its own remaining pinned policy. Validity-filtered participation is a different required temporal feature and must not be implied here.
9. Existing zero-minimum types need no artificial mandatory bindings during SQL009 upgrade. Bindings are first materialized when a positive obligation is introduced. If a zero-minimum binding is retained after an explicit repin, its pinned maximum still applies until an explicit permitted release. SQL009 must not invent historical enrollment events or mutate SQL008 revisions.

Example: publishing a type requiring every eligible dataset to have one owner-association edge examines datasets A, B and C even if only A has an edge. The preview identifies B and C as unsatisfied within the authorized complete scope. Publication and the explicit new assertions commit together, or none of them commit. Removing A's last edge later fails unless the same atomic plan supplies a replacement or a permitted release.

## Proposed shared data contracts

The following names/shapes are the shared implementation contract. Exported types alone are not implemented endpoints or qualified behavior. All JSON fields shown are mandatory; nullable fields are explicit. UUIDs, versions, safe identifiers, UTC timestamps, typed values, duplicate-safe JSON and canonical collection ordering reuse current parsers. Creation keys use the safe64 logical-key grammar; reasons contain1–500 Unicode characters with the existing malformed-Unicode/control rejection. Unknown fields, getters/prototypes, duplicate escaped keys, malformed Unicode and numeric/string coercion fail closed.

```ts
// Existing RelationTypeDefinition is the unchanged format1 definition.
type RelationTypeDefinitionV2 = Omit<RelationTypeDefinition, 'formatVersion' | 'cardinality'> & {
  formatVersion: 2;
  cardinality: {
    outgoing: { min: number; max: number | null };
    incoming: { min: number; max: number | null };
  };
};
type RelationDefinition = RelationTypeDefinition | RelationTypeDefinitionV2;
type RelationPolicyChange = 'direction_changed' | 'source_types_changed' | 'target_types_changed'
  | 'source_states_changed' | 'target_states_changed' | 'cardinality_changed'
  | 'self_policy_changed' | 'cycles_changed' | 'required_owner_changed' | 'lifecycle_changed';
type ParticipationSide = 'source' | 'target' | 'incident';
interface ParticipationBindingView {
  id: string; version: number; relationTypeId: string; relationTypeVersion: number;
  assetId: string; assetVersion: number; side: ParticipationSide;
  status: 'active' | 'released'; createdBy: string; createdAt: string;
  updatedBy: string; updatedAt: string;
}
interface RelationMigrationValues {
  attributes: AttributeValues; ownerId: string | null; state: string;
  validFrom: string | null; validTo: string | null;
  visibility: 'tenant' | 'restricted'; allowedIdentityIds: readonly string[];
}
interface RelationTransform {
  attributes: MigrationPlan; // modelId is the relation's logical key; versions are relation policy versions.
  owner: { default: 'preserve'; overrides: readonly { relationId: string; ownerId: string | null }[] };
  lifecycle: { onUnmapped: 'preserve' | 'error'; mappings: readonly {
    sourceVersion: number; from: string; to: string;
  }[] };
}
type RelationDisposition =
  | { relationId: string; expectedVersion: number; action: 'preserve' }
  | { relationId: string; expectedVersion: number; action: 'migrate' }
  | { relationId: string; expectedVersion: number; action: 'repair'; values: RelationMigrationValues }
  | { relationId: string; expectedVersion: number; action: 'repin'; targetVersion: number; values: RelationMigrationValues }
  | { relationId: string; expectedVersion: number; action: 'tombstone'; reason: string }
  | { relationId: string; expectedVersion: number; action: 'replace'; creationKey: string; reason: string };
interface RelationCreationProposal {
  key: string; sourceAssetId: string; targetAssetId: string;
  sourceAssetVersion: number; targetAssetVersion: number;
  values: RelationMigrationValues;
}
type BindingDisposition =
  | { bindingId: string; expectedVersion: number; action: 'preserve' }
  | { bindingId: string; expectedVersion: number; action: 'repin'; targetVersion: number }
  | { bindingId: string; expectedVersion: number; action: 'release'; reason: string };
interface RelationMigrationPlan {
  formatVersion: 1; relationTypeId: string;
  sourceVersions: readonly number[]; // Exact distinct live edge/binding pins, not a client scope selector.
  transform: RelationTransform | null;
  edges: readonly RelationDisposition[];
  creations: readonly RelationCreationProposal[];
  bindings: readonly BindingDisposition[];
  enrollment: 'complete-eligible-assets';
  acknowledgedPolicyChanges: readonly RelationPolicyChange[];
}
type RelationMigrationTarget =
  | { kind: 'publish'; expectedHeadVersion: number; definition: RelationTypeDefinitionV2; plan: RelationMigrationPlan }
  | { kind: 'repair'; expectedHeadVersion: number; definition: null; plan: RelationMigrationPlan }
  | { kind: 'create'; reservationId: string; expectedHeadVersion: null; definition: RelationTypeDefinitionV2; plan: RelationMigrationPlan };
type GraphAssetChange =
  | { kind: 'assign'; assetId: string; expectedVersion: number;
      modelId: string; modelVersion: number; attributes: AttributeValues; ownerId: string | null }
  | { kind: 'transition'; assetId: string; expectedVersion: number; state: string };
interface GraphChangeSet {
  formatVersion: 1;
  relationTargets: readonly RelationMigrationTarget[];
  assetChanges: readonly GraphAssetChange[];
  assetTypeMigrations: readonly {
    expectedHeadVersion: number; definition: AssetTypeDefinition; plan: AssetTypeMigrationPlan;
  }[];
  repairsReceiptId: string | null;
}
```

`sourceVersions` is the exact union of edge and active binding pins in each server-derived complete relation-type cohort. The nested attribute plan contains only distinct pins of edges transformed by `migrate`, not binding-only versions. No extra/omitted/duplicate member or unrelated owner override is accepted. Every current live edge and active binding for an explicitly targeted type has exactly one disposition, including `preserve` entries. Newly required enrollments are server-derived; a client cannot omit them by shortening an array. Their concrete before/after rows appear in preview consent and the receipt. The change-set/plan wrapper formatVersion1 is a new plan grammar, independent of relation definition formatVersion2. Acknowledgements equal the exact head-to-target policy-diff set (and the nested attribute diff set); creation/repair has no fictitious head-to-target diff. State/owner overrides and release/tombstone reasons remain explicit intent even without a policy change.

`publish` advances the head exactly one version; `create` is version one; `repair` publishes no definition. `migrate` applies the transform to the target publication while retaining edge UUID and endpoints. Its owner/lifecycle rules use actual source pins, not the current head. `repair` keeps the existing pin and applies explicitly supplied full values. `repin` in repair mode may select only the current committed head, with explicitly supplied values; it cannot revive an obsolete policy as the admission policy. Ordinary API transition restrictions remain unchanged; a valid non-transition state mapping is permitted only through the explicit migration claim/receipt.

The mode matrix is exact. `create` has empty `sourceVersions`, `edges` and `bindings`, and null `transform`; it may supply creations and derives new enrollments. `repair` has null definition/transform and forbids `migrate`; it permits preserve, full-value repair, explicit repin to the committed head, tombstone and same-type replacement. `publish` permits `migrate` through a nonnull transform and explicit full-value `repin` only to its exact target version; full-value `repair` retains its source pin and remains subject to target compatibility. Its transform is nonnull if and only if at least one edge has `action:'migrate'`; nested source versions equal those transformed edges' pins. Preserve is legal only when own values/policies and the uniform final structural policy remain valid. Binding disposition rules follow the same repair-head/publication-target distinction. Every list is complete even when all its members are preserved. A graph request with no relation target and no asset change/type migration is invalid; asset-only proposals remain valid inputs to the shared invariant. A repair target containing only preserved rows and no derived enrollment is a no-op and cannot create a migration receipt.

`preserve` keeps all canonical edge fields and version unchanged. A preserved old pin must still coexist legally with the final policy/binding set; it cannot bypass destructive publication checks. `tombstone` preserves the prior tuple and adds a tombstone revision. `replace` tombstones the old identity and links it to exactly one creation key in the same logical relation-type UUID. Creation keys are scoped by `(targetRelationTypeUUID,key)`; no such pair is shared by two predecessors. Cross-type replacements/migrations are unsupported in this profile and fail explicitly; changing logical type is never an in-place repin. Distinct explicit creations may supply additional required edges. No default dropping, endpoint guessing, merging or deduplication is allowed. Conflicting final live pairs are a validation error before writes.

New assertion UUIDs are assigned by the server on execution and bound to creation keys in the receipt. Preview digests bind keys and proposed values, not invented persisted UUIDs. A retry returns the originally committed mapping. New assertions normally use initial lifecycle state; a migrated replacement may preserve/map another target-valid state only when its explicit migration receipt proves the predecessor and policy mapping. For a replacement, the creation proposal’s explicit full `values.state` is the mapping intent: any target-valid state is allowed once the protected receipt proves the exact predecessor/source policy/state and successor/target policy/state. It does not require a `transform.lifecycle` entry, because that transform and its source-version set cover only `migrate` dispositions. An unrelated creation still requires the initial state. Provenance remains server-assigned asserted/manual provenance. A successor records its actual new assertion actor/time; the predecessor link preserves the earlier assertion history without falsifying it.

`GraphAssetChange.assign` reuses assignment validation and initial/preserved-state rules; it is not an arbitrary asset patch. Assignment **preserves the actual current owner**: its mandatory proposed `ownerId` must equal the captured current owner, including null. It cannot repair an owner through a supplied replacement value. The target is the explicitly requested existing immutable model version, attributes must validate against that exact target, and state is derived by the existing assignment rules. Existing assignment permits an older valid model version; do not introduce a head-only restriction. This is distinct from new participation enrollment, which uses the final relation-policy head. `transition` preserves model pin, attributes and owner and requires an ordinary allowed pinned transition. Explicit non-transition state mapping, owner repair and inherited/attribute schema change use the existing complete `AssetTypeMigrationPlan` path. One asset cannot occur in two asset changes or also in an asset-type migration cohort. All proposals use pre-operation expected revisions. New/live edge snapshots reference actual final endpoint revisions. A tombstone/release accompanying endpoint untyping or loss of eligibility retains the captured exact **before** endpoint/asset revision in that historical outcome; the operation receipt separately references actual before and after asset revisions. Attribute-only migration/assignment adapters must invoke the same final guard, even when the resulting endpoint is ineligible for every authored relation.

The initial profile may operate on already persisted assets, including untyped source assets; it must support assigning both endpoints and creating their first mandatory edge together. A future typed-asset-create/import ingress must submit its new endpoint proposals to this same atomic invariant before commit. It may not first persist an invalid typed asset and enqueue later repair. Confirm the exact supported creation ingress in the implementation contract before claiming every-ingress acceptance.

## Pure validation and existing integration hooks

Pure boundaries use existing `ValidationResult<T>` and immutable normalized outputs. These are draft types, not executable exports:

```ts
interface RelationPolicySnapshot {
  relationTypeId: string; definition: RelationDefinition; model: ModelDefinition;
}
interface RelationAdmissionHead { relationTypeId: string; version: number }
type GraphEdgeKey = { kind: 'existing'; relationId: string }
  | { kind: 'creation'; relationTypeId: string; key: string };
type GraphBindingKey = { kind: 'existing'; bindingId: string }
  | { kind: 'enrollment'; relationTypeId: string; assetId: string; side: ParticipationSide };
interface GraphEdgeSnapshot {
  key: GraphEdgeKey; version: number; relationTypeId: string; relationTypeVersion: number;
  sourceAssetId: string; sourceAssetVersion: number;
  targetAssetId: string; targetAssetVersion: number;
  status: 'active' | 'tombstoned'; values: RelationMigrationValues;
}
interface GraphBindingSnapshot {
  key: GraphBindingKey; version: number; relationTypeId: string; relationTypeVersion: number;
  assetId: string; assetVersion: number; side: ParticipationSide; status: 'active' | 'released';
}
interface CompleteGraphSnapshot {
  heads: readonly RelationAdmissionHead[];
  endpoints: readonly RelationEndpointPolicyState[];
  edges: readonly GraphEdgeSnapshot[];
  bindings: readonly GraphBindingSnapshot[];
}
interface RequiredParticipation {
  relationTypeId: string; policyVersion: number; assetId: string; assetVersion: number;
  side: ParticipationSide; min: number; max: number | null; existingBindingId: string | null;
}
interface ParticipationDerivationInput {
  admissionHeads: readonly RelationAdmissionHead[];
  policies: readonly RelationPolicySnapshot[];
  completeEligibleEndpointCandidates: readonly RelationEndpointPolicyState[];
  currentBindings: readonly GraphBindingSnapshot[];
}
interface FinalRelationGraphConstraintsInput {
  graph: CompleteGraphSnapshot;
  policies: readonly RelationPolicySnapshot[];
}
interface RepairableRelationSourceIssue {
  code: 'source_required_owner_inactive'; relationId: string; ownerId: string;
}
// Full governed asset tuples, not just the subset used by relation eligibility.
// Exact actual immutable asset revisions additionally preserve all other fields.
interface GraphAssetTuple {
  modelId: string | null; modelVersion: number | null; attributes: AttributeValues;
  ownerId: string | null; state: string | null;
}
interface GraphAssetPolicyRef { modelId: string; modelVersion: number }
type GraphAssetPolicyEvidence =
  | { kind: 'attributes'; model: ModelDefinition; definitionHash: string }
  | { kind: 'authored'; typeId: string; resolution: ResolvedAssetType;
      definitionHash: string; resolutionHash: string;
      ancestorTypes: RelationEndpointPolicyState['ancestorTypes'] };
interface GraphAssetBefore {
  assetId: string; assetVersion: number; tuple: GraphAssetTuple;
  policy: GraphAssetPolicyRef | null;
}
interface TypeMigrationDiscovery {
  typeId: string; modelId: string; expectedHeadVersion: number;
  headPolicy: GraphAssetPolicyRef; targetPolicy: GraphAssetPolicyRef;
  sourcePolicies: readonly GraphAssetPolicyRef[];
  plan: AssetTypeMigrationPlan; assetIds: readonly string[];
}
interface GraphAssetPreparationInput {
  assetChanges: readonly GraphAssetChange[];
  typeMigrations: readonly TypeMigrationDiscovery[];
  before: readonly GraphAssetBefore[]; // Complete affected assets, captured under parent locks.
  policies: readonly GraphAssetPolicyEvidence[]; // Exact source, head and proposed target evidence.
  modelHeads: readonly { modelId: string; version: number }[];
  activeOwnerIds: ReadonlySet<string>;
}
interface PreparedGraphAssetChange {
  kind: 'assign' | 'transition' | 'type-migrate'; assetId: string;
  fromAssetVersion: number; toAssetVersion: number;
  before: GraphAssetTuple; after: GraphAssetTuple;
  sourcePolicy: GraphAssetPolicyRef | null; targetPolicy: GraphAssetPolicyRef | null;
  sourceIssues: readonly ValidationIssue[]; // Existing asset migration allowlist only.
}
interface PreparedTypeMigration extends TypeMigrationDiscovery {
  changes: readonly ModelChange[]; policyChanges: readonly TypePolicyChange[];
}
interface PreparedAssetChanges {
  policies: readonly GraphAssetPolicyEvidence[];
  changes: readonly PreparedGraphAssetChange[];
  typeMigrations: readonly PreparedTypeMigration[];
}
interface AuthorizedCompleteGraphChange {
  changeSet: GraphChangeSet;
  completeRelationTypeIds: readonly string[];
  policies: readonly RelationPolicySnapshot[]; // Every exact before/final/target pin.
  preparedAssets: PreparedAssetChanges; // Independently validated asset transformations.
  before: CompleteGraphSnapshot;
  proposed: CompleteGraphSnapshot;
  activeOwnerIds: ReadonlySet<string>;
  tenantMemberIds: ReadonlySet<string>;
  actorId: string;
}
interface ValidatedGraphChange {
  final: CompleteGraphSnapshot;
  requiredParticipation: readonly RequiredParticipation[];
  sourceIssues: readonly RepairableRelationSourceIssue[];
  changedEdges: readonly { key: GraphEdgeKey; beforeVersion: number | null;
    afterVersion: number; action: 'create' | 'repair' | 'repin' | 'tombstone' }[];
  changedBindings: readonly { key: GraphBindingKey; beforeVersion: number | null;
    afterVersion: number; action: 'enroll' | 'repin' | 'release' }[];
  replacements: readonly { predecessorId: string; relationTypeId: string; creationKey: string }[];
}
type RelationStructuralPolicy = Pick<RelationDefinition,
  'direction' | 'sourceTypes' | 'targetTypes' | 'sourceStates' | 'targetStates'
  | 'cardinality' | 'allowSelf' | 'cycles'>;
interface ResolvedRelationDefinition { definition: RelationDefinition; model: ModelDefinition }
parseRelationDefinition(input: unknown): ValidationResult<RelationDefinition>;
parseRelationDefinitionFile(text: string): ValidationResult<RelationDefinition>;
resolveRelationDefinition(input: unknown): ValidationResult<ResolvedRelationDefinition>;
parseRelationMigrationPlan(input: unknown): ValidationResult<RelationMigrationPlan>;
parseGraphChangeSet(input: unknown): ValidationResult<GraphChangeSet>;
parseGraphChangeSetFile(text: string): ValidationResult<GraphChangeSet>;
relationStructuralPolicy(input: unknown): ValidationResult<RelationStructuralPolicy>;
projectGraphAssetChanges(input: GraphAssetPreparationInput): ValidationResult<PreparedAssetChanges>;
deriveRequiredParticipation(input: ParticipationDerivationInput): ValidationResult<readonly RequiredParticipation[]>;
validateFinalRelationGraphConstraints(input: FinalRelationGraphConstraintsInput):
  ValidationResult<readonly RequiredParticipation[]>;
validateRelationGraphChange(input: AuthorizedCompleteGraphChange): ValidationResult<ValidatedGraphChange>;
```

The service supplies complete authorized before/proposed projections and exact policy snapshots under locks. `before.edges/bindings` contain the complete active cohorts; `proposed` also contains newly tombstoned/released outcomes so exact historical references can be verified. Endpoints contain the full current/final candidate set, including zero-edge assets. New keys are tagged plan/enrollment identities, never fabricated persisted UUIDs; the future structural validator must support those tagged keys without passing them to the current UUID-only edge validator. Existing UUID, endpoint and policy identity rules remain unchanged.

`projectGraphAssetChanges` is a separate asset-validation boundary. It validates the exact complete authored migration cohorts and plan acknowledgements, then reuses `applyModelMigrationToAttributes` and `applyAssetTypeMigrationPolicy` for each actual source pin. Assignment and ordinary transition use their existing policy semantics, including owner preservation above. It produces exact full before/after governed tuples, one version increment per changed asset, and source/target evidence references. Unchanged asset fields, source provenance and visibility are preserved in actual database rows/revision snapshots; this projection never replaces those rows with a reduced tuple. Complete before revision references and actual after snapshots are independently checked by storage.

The policy catalog is keyed once by exact `(modelId,modelVersion)` within the authenticated tenant operation. An untyped tuple has a null policy reference and null model/state fields; a typed or attribute-only tuple requires the exact corresponding entry. Attribute-only policy has null authored state/ancestry. Authored evidence includes the resolved immutable definition, exact dependencies, logical type UUID and pinned ancestor UUID mapping; the service verifies stored hashes/dependency resolution with the existing `storedAssetType`/`resolveAssetType` path. Proposed target evidence is resolved the same way without pretending that it is already published. Supplied hashes alone prove nothing. The catalog includes head and target definitions even for empty cohorts, and all retained copies share the aggregate byte budget. `PreparedTypeMigration.assetIds` references the single `changes` array; do not duplicate full asset tuples into each nested preparation. Its change/policy-diff metadata is sufficient for the service to construct the existing standalone preview/receipt fields and hashes without changing their schema.

The graph validator reparses relation policies/values and recomputes **relation transformations, binding dispositions and enrollment** from `changeSet` and `before`, then compares that result exactly to `proposed`. It does not independently reimplement authored asset migration. Instead it checks that `preparedAssets` covers exactly the declared direct asset changes and every independently discovered typed migration member, with no overlap/extra/missing asset; checks source/target policy-reference consistency; and requires exact before/final endpoint projection equality for each prepared asset, including version, pin, nominal identity, pinned ancestry and state. Unchanged endpoints must remain identical. Both asset preparation and graph validation must succeed; a service-created cast or caller-supplied prepared JSON is not evidence that either ran. The service calls them in that order within one locked operation. SQL independently verifies the permitted transformation semantics against actual tuples and claims. It derives structural fingerprints from normalized projections; a caller-supplied fingerprint is not authoritative. The service may hash the same projection for persisted evidence. New enrollment output selects the exact final head; preserved bindings retain their own pin only when its fingerprint equals the head. A changed surviving edge or binding advances exactly one version; creations/enrollments start at one; preserved rows keep their versions. A replacement produces two edge outcomes plus its explicit link.

Source/final endpoint versions are selected by outcome: new/live edges and active bindings use final endpoints when rewritten, while protected tombstone/release outcomes use captured before references. Unchanged edge/binding history remains an immutable earlier observation even when its endpoint later changes; current graph/participation views resolve current endpoint metadata separately. `ValidatedGraphChange` is a bounded semantic projection, not a storage receipt or authentication result. Pure input completeness and membership sets are service-established assumptions, never tenancy assertions inferred from client arrays. One full proposed graph is validated: eligibility, participation, degree, uniqueness, cycles, own values/owners/lifecycle, validity and migration coverage, with no sequential mix of endpoint states.

Reuse `parseMigrationPlan`, `validateMigrationPlanForModels`, `applyModelMigrationToAttributes`, `validateAttributes`, `resolveRelationType`, `validateRelationEndpoints`, `validateRelationStructure`, and the existing asset-type policy resolver. The existing attribute migration functions require head-to-target version +1. Use them directly for publication; same-pin repair must use full explicit values plus `validateAttributes`, not fabricated versions to satisfy that precondition. Relation lifecycle/owner transformations need relation-specific wrappers; do not cast relation rows into asset IDs or invent authored ancestry.

The new `parseRelationDefinition`/file/resolution functions dispatch by format1/2. Keep the current `parseRelationTypeDefinition`, `parseRelationTypeFile` and `resolveRelationType` exports and their format1 results unchanged. Runtime relation views and policy storage loaders must widen explicitly to `RelationDefinition`; do not make an old format1 type silently mean format2. A shared structural algorithm may be extracted behind the old UUID-only API and the new tagged-key graph API, preserving all old validation behavior and complete-cohort cycle checks. Traversal remains authorized current-graph traversal; participation migration does not turn it into a historical graph.

`validateFinalRelationGraphConstraints` is the shared final-state constraint boundary for both ordinary mutations and `validateRelationGraphChange`. It accepts one complete proposed graph with all exact head/edge/binding policies and zero-edge endpoint candidates. It parses bounded descriptor-safe data, validates every live edge's pinned endpoint eligibility and endpoint state, checks uniform structural fingerprints, derives required participation, verifies active binding eligibility/pins and minimum/maximum degrees, and checks all surviving edge maxima, uniqueness, self-edge and complete-cohort cycle rules. It counts all live edges regardless of temporal filtering. Released/tombstoned outcomes do not satisfy degree; their historical outcome validity is checked by the migration validator and storage, not waived by this helper. Its returned obligations are normalized semantic data, not a receipt or authority to enroll/repin/release.

The service must establish tenant/actor access, exact immutable policy evidence, whole-scope completeness and locks before calling this helper. The helper neither discovers scope nor authorizes it. It does **not** transform attributes/owners/states, approve an ordinary lifecycle transition, validate owner activity/ACL membership, authorize a historical tombstone exception, or prove migration disposition coverage. Ordinary callers retain their existing own-value/owner/transition checks; migration validation separately recomputes transforms, validates its stricter target owner rules, proves complete dispositions and exact prepared-asset projection equality, then invokes this same final constraint helper. New enrollment exact-head and repin provenance are verified through the operation/disposition path; a final graph alone cannot prove which preserved old pin was newly written.

This separation preserves a concrete existing behavior in `relation-service.ts`: `transitionRelation` and `tombstoneRelation` pass `explicitOwner:false` to `persistMutation`, so an unchanged **optional** inactive owner remains allowed; a required inactive owner still fails an ordinary mutation. Ordinary create/edit explicitly supplies ownership and requires a non-null supplied owner to be active. Explicit graph repair/migrate/repin/replacement uses the stricter migration target rules below. Do not disguise an ordinary transition as a full-value migration repair or silently impose that stricter owner rule on it. Conversely, do not apply the ordinary unchanged-owner exception to a changed migration result. Reuse the existing asset migration owner/state transformations unchanged; their separately allowed source issues and optional-owner preservation are not relation migration rules.

Keep the existing `ValidationResult`/`ValidationIssueCode` shape. New graph errors use stable paths: `/participation/<canonical-index>/binding` with `required` for a missing obligation; `/participation/<index>/minimum` with `range` for a degree deficit; `/structure/<logical-type-index>/maximum` with `range` for a maximum violation; `/structure/<index>/cycles` with `cycle`; `/structure/<index>/pairs` with `duplicate`; and `/migration/...` for plan/coverage/transform issues. Service mapping selects participation/cardinality/cycle/duplicate only from these graph-validation paths, not arbitrary attribute issues with the same generic code. Pure `limit` always maps to the profile-limit error after scope authorization. Format1 positive-minimum `unsupported` retains its existing dedicated mapping. Issues have deterministic canonical ordering and the shared100-issue bound; source issues are separate allowlisted evidence, never a waiver for target issues.

Extend the existing `lockRelationEndpointUnion` / `validateRelationsForEndpointChanges` hooks to the joint graph service. Admission must be enforced on **asset INSERT**, every nominal type/ancestry/state eligibility change including zero-degree assets, binding writes, and every relation policy publication. An incident-edge UPDATE trigger alone cannot enforce it. Every canonical writer queues the affected final validation scope. Existing single mutation APIs become singleton proposals; they continue to reject unsatisfied participation with a stable required-migration/participation error. Complete authored-type migration supplies its entire transformed cohort once. Future imports, workflow actions, MCP and source adapters reuse the same invariant rather than duplicating weakened validation.

## Prepared persistence and exact composition seam

The current `asset-type-migration-service.ts` private `prepare` acquires its own principal locks and validates against existing edges, while `executeTypeMigration` finishes with `SET CONSTRAINTS ALL IMMEDIATE`. Nesting that execution function unchanged would reject valid joint repairs or finalize before relation/binding writes. Split it into discovery, pure projection and prepared persistence. The refactor must preserve standalone context/preview/execute/receipt contracts and SQL007 receipt semantics.

Draft service/store signatures use existing `Tx`, `Principal`, `ModelHooks` and `TypeMigrationReceipt`. `GraphOperationHandle` is an internal opaque handle returned by protected begin; a TypeScript brand is not database authority.

```ts
interface TypeMigrationDiscoveryResult {
  discovery: TypeMigrationDiscovery; policies: readonly GraphAssetPolicyEvidence[];
}
interface RelationGraphExecutionRequest { changeSet: GraphChangeSet; previewDigest: string }
interface GraphOperationBinding {
  idempotencyOperation: string; idempotencyKey: string;
  request: RelationGraphExecutionRequest; correlationId: string;
}
interface GraphOperationHandle { readonly id: string } // Internal constructor; SQL verifies every claim.
interface GraphOperationBeginResult {
  operation: GraphOperationHandle;
  typeMigrations: readonly { modelId: string; migrationId: string }[];
  creations: readonly { relationTypeId: string; key: string; relationId: string }[];
  enrollments: readonly { relationTypeId: string; assetId: string;
    side: ParticipationSide; bindingId: string }[];
}
discoverTypeMigration(tx: Tx, principal: Principal, modelId: string,
  expectedHeadVersion: number, input: TypeMigrationRequest): Promise<TypeMigrationDiscoveryResult>;
persistPreparedTypeMigration(tx: Tx, principal: Principal, correlationId: string,
  operation: GraphOperationHandle, modelId: string, migrationId: string,
  prepared: PreparedAssetChanges, hooks: ModelHooks): Promise<TypeMigrationReceipt>;
beginRelationGraphOperation(tx: Tx, principal: Principal, operationId: string,
  binding: GraphOperationBinding): Promise<GraphOperationBeginResult>;
sealRelationGraphOperation(tx: Tx, principal: Principal,
  operation: GraphOperationHandle): Promise<RelationMigrationReceipt>;
```

Discovery runs after the parent holds the tenant ledger/model scope, but before the parent acquires the complete canonical row union. It resolves immutable head/source/target policies and discovers the full typed cohort without its own asset/relation/principal lock phase. The parent derives the least fixed-point graph scope, locks every relevant head and canonical row in the order below, then locks one principal union and rechecks current authorization. It captures actual before tuples/revisions and calls `projectGraphAssetChanges`; relation validation runs once against all final projected endpoints. Empty typed cohorts still have head/target evidence and a real publication/receipt when valid.

Prepared persistence accepts only the selected nested type's members from the parent preparation. It writes its target version/head, asset tuples, actual immutable revisions, existing model/type migration receipt children, audit and outbox. It does not rediscover a narrower cohort, relock principals, run an old-edge-only guard, start a new deadline, or force final constraints. Assignment/transition projection and write adapters are similarly extracted from `assignAssetModel` and `transitionAssetTypeState`; public ordinary APIs remain complete independently guarded transactions. No public `skipValidation` flag is introduced. The existing standalone typed-migration wrapper obtains its own complete operation scope and preserves its response schema; a graph migration cross-references the nested receipt instead of replacing or rewriting it.

The execution namespace is `relation-migration.execute`, with the exact outer `{changeSet,previewDigest}` body and `{receipt: RelationMigrationReceipt}` success envelope. Preparation uses `relation-migration.prepare`, exact `{definition}` body and `{preparation: RelationPreparationView}` success envelope. These reserved namespaces are not interchangeable with ordinary relation operations. The SQL preparation entry is `gc_relation_graph_prepare(idempotency_key text, request_body jsonb, correlation_id text) RETURNS jsonb`: it derives preparation/type IDs and the fixed15-minute expiry from database time, validates tenant/creator/current permissions, and returns the preparation view. Its success insertion must match the actual protected preparation and canonical request hash; an arbitrary runtime-written idempotency row cannot fabricate a preparation. Neither reserved namespace permits runtime UPDATE/DELETE of a committed success row. Ordinary unrelated idempotency rows retain their existing behavior.

Relation target `resolutionHash` means the canonical SHA256 of deterministic `ResolvedRelationDefinition {definition,model}` reconstructed from the exact immutable relation definition. SQL008 stores no relation resolution column. The new operation claims/receipts may store this derived evidence, verified using the existing canonical JSON hash implementation; no historical column or previously stored resolution is implied.

Preserve existing `relation_type.created`, `relation_type.published` and canonical `relation.created|updated|transitioned|tombstoned` event semantics. New actions are `relation_participation.enrolled|repinned|released` (binding UUID/version), `relation_migration.executed` (operation UUID, version1), and `relation_preparation.created|expired` (preparation UUID, version1/2). A graph outcome changing state uses the existing transitioned event even when other values also change; the operation receipt explains the combined change. Each new canonical binding/operation/preparation event needs its paired audit/outbox record. Explicit audit authorization excludes all three new prefixes from the generic branch: binding and operation history reauthorizes its complete recorded scope, while preparations remain creator-only with current permissions. Same-UUID subjects of different kinds cannot share an authorization match. Cleanup is future operator work until implemented and verified; naming an expiry event does not imply a running cleanup job.

The narrow SQL entry points are planned as `gc_relation_graph_begin(operation_id uuid, idempotency_operation text, idempotency_key text, request_body jsonb, correlation_id text)` and `gc_relation_graph_seal(operation_id uuid)`. Begin derives tenant/actor from the authenticated transaction, parses the exact canonical request bound by `once`, captures actual complete before scope, and installs independently verified private claims. It derives server IDs for creations/enrollments; it must not accept an arbitrary prepared-tuple JSON/hash as authority. SQL must recompute the bounded rename/remove/set/enumMap/convert and owner/lifecycle operations or independently prove exactly equivalent outcomes from the canonical plan and stored before tuples. A helper that only copies client tuples into claims is forbidden. Internal claim installation has no runtime/PUBLIC execute grant; no public finalize function is exposed.

Ordering with the existing `once` helper is significant: its callback begins the operation, persists all prepared asset/relation/binding writes and journals, then seals and returns the immutable receipt. `once` inserts its success row after that callback. **Only then** does the outer transaction perform the final deadline check and `SET CONSTRAINTS ALL IMMEDIATE`, so deferred finalization can require the matching idempotency success/key/hash/receipt. Check the remaining deadline again before commit. Nested persistence cannot force constraints early. An early caller attempt to finalize a not-yet-complete operation must fail and roll back, not leave partial canonical activation. Completed replay reauthorizes the recorded full cohort and returns the original IDs without opening another operation. The SQL begin request body is exactly the parsed outer body passed to `once`; do not substitute a differently ordered/normalized plan into its request-hash binding. The normalized change-set hash is separate evidence.

SQL001 currently grants runtime INSERT/UPDATE/DELETE on the tenant-scoped `idempotency` table; it is not immutable evidence by itself. SQL009 must add an operation-scoped insertion guard for the reserved graph-execution namespace: the new row must match the current transaction's sealed protected operation, authenticated tenant/actor, exact operation/key/request hash and complete sealed receipt response. An existing, fabricated or edited success row cannot satisfy deferred finalization. Once inserted, graph-execution idempotency rows must reject UPDATE/DELETE, including after commit; completed replay verifies their binding to the immutable operation receipt. Keep unrelated idempotency namespaces' existing behavior unchanged. The guarded namespace and exact response envelope must be frozen with the service contract before implementation; neither a caller-selected namespace nor an arbitrary receipt-ID field grants authority.

## Completeness, authorization, locks and budgets

The server derives a least fixed-point validation scope from explicit relation targets and asset proposals: every live edge and active binding of each targeted type; every currently bound or newly eligible zero-edge asset for proposed policies; all incident types/bindings of changed assets; and the complete logical-type structural cohorts required by those edges. Changes in nominal type/ancestry/state must examine newly matching policies as well as old incident edges. A zero-edge asset cannot escape this worklist. Untargeted types are validation context only; a plan may not silently repair them. If their final invariants fail, return an explicit plan issue and require another target in a fresh plan.

Authorize the actor freshly for models read/write and catalog read/write, then authorize every required asset, edge and binding before exposing any scope count, budget error, issue path, preview or digest. Binding visibility derives from current asset access; complete degree-dependent results also require all necessary edge/opposite-endpoint access. An inaccessible complete scope yields generic `RELATION_SCOPE_UNAVAILABLE` without identifiers/counts. Direct unknown/inaccessible receipt, edge, binding or asset identities share the relevant 404 behavior. Neither minimum deficits nor authorization failures identify a hidden edge.

Those combined write permissions apply to the graph migration endpoints. Existing ordinary assignment, transition, relation read/write and history routes retain their current permission contracts while sharing the final invariant. Internal singleton adapters and storage claims must check the permissions for their actual canonical mutations; sharing a validator/transaction wrapper neither grants model publication permission nor silently requires it for an unchanged ordinary catalog-only action. New read-only participation routes require catalog/model read and subject access, not model write.

Reuse idempotency → tenant ledger → model scope → relevant type heads in canonical kind/key order → complete asset UUID union → relation UUIDs → binding UUIDs → globally sorted identities → memberships. Derive one union of at most **2,001 distinct principals** across actor/delegated identities, every old/new relation and asset owner, ACL member and nested migration. Sort it once and lock the entire identity set, then membership set; never split it into batches or discover a lower UUID later. Reject an oversized union with `RELATION_PROFILE_LIMIT` after complete-scope authorization and before writes. Reauthorize after stabilization. Acquire the whole asset union before any relation/binding lock; do not add a lower-order asset after discovering another zero-edge participant. Never acquire the tenant ledger for the first time after a canonical row lock. Storage uses the reviewed fail-fast ledger fence before DML, private queued work and deferred final-state validation; caller-set GUCs or nested-trigger depth are not proof of authority.

Keep a single 30-second operation deadline from before the first wait, with remaining lock/statement budgets and a final precommit check; nested helpers never reset it. Reuse `configureRelationTransaction`, `relationQuery`, `relationBudget` and the tenant/exact-pin immutable cache. No cache of current actor access, owner activity, ACL or membership eligibility. Every query/materialization phase must honor the remaining budget, including journal helpers with multiple queries and final constraints.

Initial combined limits: eight explicit relation targets, eight authored asset-type migration targets, 1,000 live edges before and after, 2,000 distinct assets including zero-edge participants, 4,000 active bindings before and after, 1,000 changed assets, the single 2,001-principal union above, and 512 KiB aggregate canonical projected validation/plan/receipt data. Bound both retained copies and final serialized data; do not give each nested target an independent unlimited allowance. Return at most 100 authorized issues. Reuse SQL scalar byte/count preflight before large payload transfer, narrow projections and incremental retained-copy charging. Source definitions retain current parser limits. Hidden-scope refusal precedes limit reporting. These are engineering bounds awaiting execution qualification, not measured throughput claims.

## SQL009 and immutable history requirements

Never edit migrations001–008 after application, rewrite stored definitions, or rewrite old snapshots. SQL009 must be separately reviewed and upgrade-tested against the final qualified SQL008 checksum.

The current `relation_revisions` parent FK includes the canonical edge's **current relation_type_version**. Keeping that FK while repinning a canonical edge would invalidate its old revisions. Replace it in SQL009 with (a) a tenant-scoped stable edge identity reference containing edge UUID, logical type UUID and immutable source/target UUIDs, and (b) a separate exact FK from each revision to its immutable relation-type version. Add the corresponding stable unique key. Preserve every historical policy pin and endpoint revision FK; prove all old rows still join to their exact original definitions. The canonical current revision must still match the entire current tuple.

Ordinary UPDATE continues to forbid changing a relation's identity, logical type or endpoints, and ordinarily its policy pin. A repin requires an operation-specific, transaction-bound protected claim from the state machine below. It cannot be enabled by a session flag, user-supplied hash or directly writable claim table. A same-type direction change that reverses endpoint order or an explicit endpoint change requires tombstone plus a new UUID, with an immutable predecessor/successor receipt link. A direction change preserving endpoint identity/order may retain UUID only if explicitly acknowledged and every surviving edge is migrated to the uniform final structural policy. Changing logical relation-type UUID is forbidden in this profile, including replacement links. Never rewrite an old directed snapshot into an undirected one.

SQL009 must also narrowly replace SQL008's current-endpoint-only revision check for a claimed tombstone/release accompanying endpoint untyping. The new tombstone/release references the **exact current endpoint revisions captured under the operation's locks immediately before its writes**. Those references may be newer than the endpoint references in an already existing edge/binding revision; that earlier snapshot remains untouched. The new outcome's governed values must equal the captured actual before tuple, with only the stated tombstone/release attribution changes; arbitrary client-selected older snapshots are invalid. The receipt separately stores exact captured before and actual after asset revision references. New/live edges use final endpoint references. This is a protected historical-outcome rule, not a general exemption from current revision consistency. This precision is adopted and storage review confirmed the history choice is coherent; the isolated SQL009 gates must prove it.

New storage responsibilities are participation bindings, immutable binding revisions, a protected final-validation workset, protected migration operations/claims, immutable receipts, normalized edge transitions, normalized binding transitions, normalized touched asset references, replacement links and new-type reservations. Every tenant-owned unique key/FK includes tenant; all tables force RLS. Runtime roles cannot own/bypass RLS, alter history, hard-delete canonical bindings, or manufacture normalized protected claims. Security-definer functions have fixed search paths, narrow grants and non-bypass owners; PUBLIC execution is revoked. Revision-generated fields are not sufficient by themselves: exact tuple equality and authorized provenance must also be checked.

The protected operation sequence is **begin → claims → writes → immutable receipt → deferred finalize**, all within one transaction:

1. `begin`: a narrow authorized entry point creates the private operation row bound to tenant, authenticated actor, transaction ID, idempotency/request digest and captured complete before cohort under the ledger. At most one graph operation is active per tenant/transaction; nested asset migrations join it. A reservation is only identity preparation and cannot serve as an active operation claim.
2. `claims`: derive/verify normalized exact expected outcomes from the validated plan and actual stored before tuples. Claims cover every target definition/publication, exceptional repin, lifecycle mapping, migrated replacement initial state, binding enrollment/repin/release, historical tombstone/release endpoint reference, authorized inactive-owner removal/repair, and nested asset migration. Each claim binds resource identity, exact before/after version/pin/tuple and operation/transaction/actor. Runtime cannot directly INSERT/UPDATE/DELETE these rows. The entry point must enforce database-side coverage and policy checks; accepting arbitrary caller tuples or a hash is insufficient.
3. `writes`: row/statement guards look up the unique protected operation, match and consume each exact claim once, and record actual affected revisions in private work. Unclaimed or duplicate exceptional writes fail immediately. Ordinary writes still obey ordinary guards. New-type identities and definitions, head movement and normalized children remain checked. No session GUC grants a bypass.
4. `immutable receipt`: after all canonical/revision/audit/outbox writes, the sealing function constructs/verifies the immutable receipt and normalized outcomes from consumed claims and actual immutable revisions. Every claimed write must have occurred, with no extra write. The operation becomes sealed; subsequent canonical writes or further claims are forbidden. Only the prescribed idempotency-success/finalization bookkeeping may follow. Idempotency success is part of this same transaction and may reference only the sealed result.
5. `deferred finalize`: prove complete final admission/degree/cycle/owner/value constraints, exact membership and all receipt links, actual current heads and revisions, and matching audit/outbox effects; then mark the protected operation finalized. A transaction may commit only with finalized operations and an empty pending workset. Failure rolls back every state. A client-issued early `SET CONSTRAINTS` cannot make an incomplete operation valid; changes after sealing/finalization fail rather than escaping the queue.

Validate every publication event and head transition against its own exact operation claim and prior version, including intermediate events attempted inside a transaction. This profile declares at most one publication per logical type in a change set; an extra intermediate publication is unclaimed and fails even if a later head would be permissive. Do not validate only the final head or let a later relaxed policy authorize an earlier unclaimed write. Repin and release claims may target only the permitted final/committed head described above. Persisted immutable receipts replace private work as evidence; retain only necessary protected operation metadata after commit, without permitting history mutation.

Capture the complete before cohort under the ledger. Protected receipt claims bind exact before/after asset, edge and binding revisions, immutable policy definitions and hashes, original endpoints, tombstones, creation-key mappings and permitted enrollment/release reasons. Deferred validation proves every claimed write occurred, every actual exceptional write is claimed, every zero-edge obligation is covered, and no unclaimed row entered or left the cohort. A repeated hash is supplementary evidence; it cannot replace the actual immutable tuple/reference checks. Normalized receipt children must be derived/verified against the parent and exact revisions, not independently inserted assertions trusted from runtime code.

Canonical heads/definitions, asset changes and their receipts, edges, bindings, normalized references, graph fence, audit, outbox, migration receipt and idempotency success commit together. A late journal or constraint failure rolls back all of them. Direct SQL can neither bypass a positive minimum by deleting its binding nor release one through a forged receipt. Admission enrollment and final validation must serialize against concurrent assignment, new eligible assets, edges, binding releases, policy publication, owner/membership revocation and competing migrations.

## Preview, execution, repair and receipt APIs

Draft routes are `POST /relation-migrations/validate`, `POST /relation-migrations/context`, `POST /relation-migrations/preparations`, `POST /relation-migrations/previews`, `POST /relation-migrations`, `GET /relation-migrations/:id`, `GET /assets/:id/relation-participation`, and `GET /assets/:id/relation-participation/:bindingId/history`. They live under the existing `/api/v1` prefix and use the existing session/CSRF/error/idempotency rules. Validate parses a strict file/change set without claiming authoritative readiness. Preview accepts `{changeSet}`; execute accepts `{changeSet,previewDigest}`. Each targeted head and resource carries an exact expected version in the canonical change set. Stable outer error mappings are:

| HTTP | Code | Meaning |
| --- | --- | --- |
| 400 | `RELATION_JSON_INVALID` | Malformed/duplicate raw JSON, unknown outer field or noncoercion failure. |
| 400/409 | `RELATION_PAGE_INVALID` / `RELATION_GRAPH_STALE` | Invalid participation query/cursor binding or changed opaque page fence; reuse the existing relation paging codes. |
| 400/409 | `IDEMPOTENCY_REQUIRED` / `IDEMPOTENCY_CONFLICT` | Existing missing-key or changed-payload semantics. |
| 428 | `VERSION_REQUIRED` / `RELATION_MIGRATION_PREVIEW_REQUIRED` | Missing required expected head/resource version or execution consent. |
| 409 | `VERSION_CONFLICT` / `RELATION_PREVIEW_STALE` | Stale exact version or recomputed complete scope/digest mismatch. |
| 404 | `RELATION_MIGRATION_NOT_FOUND` / `RELATION_PREPARATION_NOT_FOUND` | Missing/inaccessible receipt or preparation, after current actor checks. |
| 403 | `RELATION_SCOPE_UNAVAILABLE` | Required complete scope inaccessible; no identifiers/counts/issues. |
| 422 | `RELATION_MIGRATION_INVALID` | Invalid plan, incomplete dispositions, mismatched pins, unsupported cross-type replacement or invalid repair values. |
| 422 | `RELATION_PARTICIPATION_REQUIRED` | Authorized complete final scope lacks a required binding or minimum degree. |
| 422 | `RELATION_MIGRATION_REQUIRED` | Ordinary mutation needs explicit joint repair, or attempted pin preservation conflicts with changed structural policy. |
| 422 | `RELATION_CARDINALITY` / `RELATION_CYCLE` | Authorized final maximum/cycle violation, including max zero. |
| 409 | `RELATION_DUPLICATE` | Duplicate final live pair or logical name collision. |
| 422 | `RELATION_PROFILE_LIMIT` | Any complete-scope/materialization/principal bound exceeded. |
| 409/410 | `RELATION_PREPARATION_CONFLICT` / `RELATION_PREPARATION_EXPIRED` | Creator-visible changed reservation binding/consumption or expired unconsumed reservation. |
| 503 | `RELATION_RETRY` | Deadline, lock timeout, deadlock or serialization failure; rollback and Retry-After 5. |
| 500 | `RELATION_STORAGE_INVALID` | Stored tuple/hash/reference inconsistency; sanitized correlation ID, no invented repair. |

Existing authenticated role denials retain the common authorization code. Existing direct edge/endpoint unavailability remains `RELATION_NOT_FOUND`. Format1 positive minima retain `RELATION_MINIMUM_UNSUPPORTED`. Errors never expose SQL, raw counters, hidden rows or plan literals.

Preview covers `complete-authorized-affected-graph`, including zero-edge participants and related validation-only cohorts. A complete, fully authorized but target-invalid preview may return `ready:false`, explicit target issues and `previewDigest:null`; it remains useful for draft repair and is never executable consent. Hidden, incomplete or oversized scope returns the corresponding generic error before any partial context, count, issue path or projection. Only a valid complete preview returns `ready:true` and a digest. Hash bindings include authenticated tenant/actor, all exact heads and pins, full canonical change set, expected resource revisions, derived enrollment set, current permissions/owner eligibility and proposed final tuples. A late eligible asset, zero-edge binding, ACL change or different operation order invalidates consent. The client supplies intent; the service recomputes scope and all invariants under locks at execution.

The following HTTP DTOs are the frozen engineering contracts for source work. Context, preview and receipt are complete bounded documents, **not paginated**; the entire response and all retained projections fit the shared512 KiB profile. They cannot produce a consent digest from one page of a larger cohort.

```ts
type RelationMigrationIntent =
  | { kind: 'publish'; relationTypeId: string; expectedHeadVersion: number;
      definition: RelationTypeDefinitionV2 }
  | { kind: 'repair'; relationTypeId: string; expectedHeadVersion: number; definition: null }
  | { kind: 'create'; relationTypeId: string; reservationId: string;
      expectedHeadVersion: null; definition: RelationTypeDefinitionV2 };
interface RelationMigrationContextRequest {
  formatVersion: 1; relationTargets: readonly RelationMigrationIntent[];
  assetChanges: GraphChangeSet['assetChanges'];
  assetTypeMigrations: GraphChangeSet['assetTypeMigrations'];
  repairsReceiptId: string | null;
}
interface RelationTargetEvidence {
  relationTypeId: string; mode: 'create' | 'publish' | 'repair';
  beforeVersion: number | null; afterVersion: number;
  definitionHash: string; resolutionHash: string;
  beforeStructuralFingerprint: string | null; afterStructuralFingerprint: string;
  policyChanges: readonly RelationPolicyChange[]; attributeChanges: readonly ModelChange[];
}
type GraphSourceIssue =
  | { kind: 'relation'; issue: RepairableRelationSourceIssue }
  | { kind: 'asset'; assetId: string; issue: ValidationIssue };
interface RelationMigrationContext {
  coverage: 'complete-authorized-affected-graph';
  request: RelationMigrationContextRequest;
  assetIdentities: readonly { assetId: string; name: string }[];
  preparations: readonly RelationPreparationView[];
  completeRelationTypeIds: readonly string[];
  policies: readonly RelationPolicySnapshot[];
  before: CompleteGraphSnapshot;
  assetPreparation: PreparedAssetChanges | null;
  proposedEndpoints: readonly RelationEndpointPolicyState[] | null;
  targets: readonly RelationTargetEvidence[];
  sourceIssues: readonly GraphSourceIssue[]; targetIssues: readonly ValidationIssue[];
}
interface ParticipationDegreePreview extends RequiredParticipation {
  beforeDegree: number; proposedDegree: number;
}
interface RelationMigrationProjection {
  proposed: CompleteGraphSnapshot;
  participation: readonly ParticipationDegreePreview[];
  changedEdges: ValidatedGraphChange['changedEdges'];
  changedBindings: ValidatedGraphChange['changedBindings'];
  replacements: ValidatedGraphChange['replacements'];
}
type RelationMigrationPreview = {
  context: RelationMigrationContext; changeSetHash: string;
} & (
  | { ready: true; previewDigest: string; targetIssues: readonly [];
      projection: RelationMigrationProjection }
  | { ready: false; previewDigest: null; targetIssues: readonly ValidationIssue[];
      projection: RelationMigrationProjection | null }
);
interface ActualRevisionReference { id: string; version: number }
interface RelationMigrationReceipt {
  id: string; formatVersion: 1; coverage: 'complete-authorized-affected-graph';
  executedBy: string; executedAt: string; correlationId: string;
  repairsReceiptId: string | null; changeSet: GraphChangeSet;
  requestHash: string; changeSetHash: string; previewDigest: string;
  policies: readonly RelationPolicySnapshot[]; targets: readonly RelationTargetEvidence[];
  before: CompleteGraphSnapshot; after: CompleteGraphSnapshot;
  assetIdentities: readonly { assetId: string; name: string }[];
  assetChanges: PreparedAssetChanges; sourceIssues: readonly GraphSourceIssue[];
  edgeOutcomes: readonly { key: GraphEdgeKey; role: 'changed' | 'validation-only';
    action: 'preserve' | 'create' | 'repair' | 'repin' | 'tombstone';
    before: ActualRevisionReference | null; after: ActualRevisionReference;
    beforeTupleHash: string | null; afterTupleHash: string }[];
  bindingOutcomes: readonly { key: GraphBindingKey; role: 'changed' | 'validation-only';
    action: 'preserve' | 'enroll' | 'repin' | 'release';
    before: ActualRevisionReference | null; after: ActualRevisionReference;
    beforeTupleHash: string | null; afterTupleHash: string }[];
  assetRevisions: readonly { assetId: string; role: 'changed' | 'validation-only';
    before: ActualRevisionReference; after: ActualRevisionReference }[];
  creations: GraphOperationBeginResult['creations'];
  enrollments: GraphOperationBeginResult['enrollments'];
  replacements: readonly { predecessorId: string; successorId: string;
    relationTypeId: string; creationKey: string }[];
  nestedTypeReceipts: readonly { modelId: string; typeId: string; migrationId: string;
    fromVersion: number; toVersion: number }[];
}
interface RelationPreparationView {
  id: string; relationTypeId: string; definitionHash: string;
  createdAt: string; expiresAt: string;
}
interface ParticipationItem {
  binding: ParticipationBindingView; currentAssetVersion: number;
  policy: RelationPolicySnapshot; structuralFingerprint: string;
  minimum: number; maximum: number | null; currentDegree: number;
}
interface ParticipationListQuery {
  limit?: number; cursor?: string; status?: 'active' | 'released' | 'all';
}
interface ParticipationListPage {
  items: readonly ParticipationItem[]; nextCursor: string | null; snapshotToken: string;
}
interface ParticipationRevisionView {
  binding: ParticipationBindingView; assetRevision: ActualRevisionReference;
  policy: RelationPolicySnapshot; operationId: string;
  recordedBy: string; recordedAt: string;
}
interface ParticipationHistoryPage {
  items: readonly ParticipationRevisionView[]; nextCursor: string | null; snapshotToken: string;
}
```

Responses use `{context}`, `{preview}`, `{receipt}` and `{preparation}` envelopes for their corresponding routes; participation list/history return the page directly. Validate accepts exactly `{text:string}`, bounds decoded UTF-8 file content within the shared512 KiB profile, uses duplicate-safe `parseGraphChangeSetFile`, and returns `{changeSet}` with a normalized valid plan; invalid syntax/semantics uses the existing bounded validation-error envelope. Context takes the request directly. It contains target headers/definitions/reservation references **without any edge/binding dispositions**, plus fully specified direct asset changes and typed migration plans. This allows the editor to obtain the complete source cohort before a migration plan exists. A create intent's UUID must equal its creator-owned reservation. The server returns all required current rows, exact pins and target policy/schema differences, so the UI can construct explicit preserve/repair/migrate/release dispositions. Context has no consent digest or readiness flag.

Context remains available for a syntactically valid, fully authorized draft whose asset transformation or target constraints fail: return separate bounded target issues and null asset preparation/proposed endpoints when a normalized complete projection cannot be constructed. Derive a conservative complete candidate closure from actual current scope plus proposed nominal policy targets; never shorten scope to only successfully projected assets. If that complete closure cannot be authorized or bounded, reject without partial context. A malformed definition/plan still fails parsing; the UI retains the draft and may reload valid current target headers through the existing type routes. Invalid preview may retain a normalized complete proposal when final participation/cardinality/cycle validation fails; otherwise projection is null. A source issue never makes an invalid live proposed owner/state/value acceptable.

Every graph snapshot carries the exact governed edge/binding tuples already defined above. Preview uses tagged creation/enrollment keys and planned next revision numbers. Receipt snapshots use actual persisted IDs in their keys; the explicit mapping arrays connect them to the original plan keys. `edgeOutcomes` and `bindingOutcomes` enumerate all before/after members, including validation-only preserved rows; their actual revision references must resolve to those exact tuples. `assetRevisions` covers every endpoint/candidate in the complete scope and references actual immutable revisions; full before/after governed tuples for changed assets are in `assetChanges`, with exact immutable policy evidence. Existing source metadata and earlier endpoint observations remain in their original immutable revisions. A tombstone/release's new recorded endpoint reference uses the captured current before revision, not an arbitrarily selected earlier observation. Nested asset migration receipts remain separately addressable through their existing route and immutable IDs. The receipt's request hash covers the exact outer idempotency body; the change-set hash covers its normalized plan. Definition/resolution/fingerprint hashes are canonical semantic hashes, never the internal tenant graph counter.

`repairsReceiptId`, when nonnull, identifies a currently readable same-tenant completed receipt. Any actor with the required current permissions may execute forward repair; being the original actor grants no exception. Reauthorize the original receipt's entire recorded scope, then require overlap through at least one explicitly targeted logical relation type, nested authored model or directly changed asset. An unrelated receipt cannot be attached as provenance. The link does not substitute for fresh expected versions, complete current discovery or new preview consent. The earlier receipt remains immutable.

Participation list normalizes `limit` to default50, integer1–100, and `status` to default`active`; reject unknown/repeated/coerced query fields. Sort by canonical binding UUID ascending, including released bindings when requested. A released row's `currentDegree` describes the currently authorized structural graph, not a degree recorded at release. History accepts only `limit`/`cursor`, defaults to50, and sorts immutable binding versions descending. It exposes recorded policy/asset references and no inferred historical degree or as-of graph. Missing/inaccessible asset or binding receives the same direct-resource404. Authorization for degree-dependent list entries requires the complete relevant relation/opposite-endpoint scope; inaccessible scope returns the generic scope refusal before counts or partial items. History and receipt links also reauthorize original recorded operation scope before revealing their rows.

Both participation cursors bind tenant, actor, purpose, asset UUID, normalized filters/page size, order, last key and an opaque fixed-length keyed fence token; history additionally binds binding UUID. Reuse HMAC-SHA256 with the existing43-character base64url fence representation and1024-character signed-cursor limit, with separate `asset-participation` and `binding-participation-history` purposes. Store only the opaque token in the signed payload, never a raw or base64-decoded counter. Recompute after locking and compare; stale pages return409 without identifying the changed object/count. Binding enrollment/repin/release and relevant policy/asset/edge changes bump the internal graph fence. Current identity/role/membership and original-scope access are reauthorized on every page even if no fence increment occurred. Conservative invalidation may follow unrelated changes and is not an existence/count indicator. No total counts, hidden degrees, hidden deficits or raw graph revisions appear in pages, errors or public audit.

First positive-type publication uses `POST /relation-migrations/preparations` with `{definition}` for a format2 version-one definition and an Idempotency-Key. It reserves an opaque preparation ID and immutable type UUID, bound to authenticated tenant, **creator only**, logical key, canonical definition hash and expiry exactly **15 minutes** after creation. It publishes no type/binding and holds no locks between requests. Preparation, preview, consumption and replay all require fresh permissions; same-tenant noncreators receive the same404 as missing. The preparation has its own ID, distinct from a later execution operation ID.

An identical preparation retry with the same idempotency key returns the same IDs and original expiry; it never extends the lease. Changed content on that key conflicts. A changed definition requires a new preparation/key. An expired unconsumed preparation returns410 only to its authorized creator; reusing its old key cannot renew it. Logical names are not indefinitely reserved: another legitimate publication may win, causing execution409. Consumption validates expiry with database time under lock immediately before consumption, verifies the exact definition hash/type UUID/creator and publishes all repairs atomically. Rollback restores unconsumed state; expiry may then require a new preparation and fresh preview. A committed execution retry returns its reauthorized receipt even after preparation expiry because it replays the completed idempotent operation, not a new consumption. A different execution key cannot consume an already consumed preparation. Expired preparation cleanup is audited, retains required idempotency evidence and cannot delete a completed receipt.

Receipts expose an immutable operation ID, each target's mode, actor/time/correlation, request/plan/preview hashes, prior receipt reference when repairing, and normalized before/after member references. Each edge outcome includes action, exact before/after revision/policy/tuple hashes, and a new-identity reference only for replacements/creations. Binding outcomes include exact prior/new revisions, policy pins, asset revision and enroll/repin/release action. Unchanged validation-context members retain their version and are explicitly distinguished from changed outcomes. Existing authored-type receipts are cross-referenced to the same atomic operation without changing their historical schema.

Source values must be structurally valid under their stored pins before transformation. The relation source-issue repair allowlist contains exactly **`source_required_owner_inactive`**: a non-null required owner still has an existing tenant membership/identity reference, but one or both activity flags is now false. Preview records that issue separately. The plan must explicitly replace the owner with an active eligible member, publish/repin to an explicitly acknowledged policy without required ownership and choose null, or tombstone/replace the old edge. A claimed tombstone may retain the inactive required owner **only for a currently active edge with valid immutable before history**. It preserves every old governed tuple value and before-endpoint reference, changing only tombstone status, version and actual update attribution/time. It removes that edge from the final live graph; no invented intermediate owner repair is required. This finite, receipt-bound exception never authorizes a target-invalid live edge.

Changed live, repinned and replacement outcomes require every non-null owner to be an active eligible tenant member, and required ownership additionally forbids null. An unchanged preserved edge with an optional inactive owner retains existing unchanged-value rules; it is not rewritten or presented as a changed active-owner outcome. No other source invariant is silently repairable.

Missing required owners, missing historical revisions, invalid stored hashes/attributes/states, malformed provenance, missing members, broken endpoint references, existing minimum/cycle violations or fabricated enrollment are storage corruption errors, not ordinary source warnings. New target minimum deficits are blocking target issues, not source corruption or an exception allowlist. Nested asset migrations retain their separately defined source-issue rules and receipt evidence; do not widen them implicitly. An acknowledged destructive change is not permission to accept a target failure.

Forward repair creates a new plan, fresh preview and new receipt referencing the earlier receipt. It never changes the original operation outcome. Restoring prior semantics is a new version and plan, subject to current authorization, references and constraints; no promise that deploying the old container reverses SQL009. A failed atomic execution leaves no success receipt. Restore/recovery qualification must include a disposable backup/restore or documented forward-repair exercise and actual history/tenant reconciliation; merely retaining rollback code is not evidence.

Full receipt, preview replay and history reads reauthorize the original and current edge/endpoints, every affected binding asset and linked asset-migration cohort, including tombstoned predecessors. Cached success is not authority. Mixed hidden history causes generic refusal before counts; no partial receipt is labelled complete. Type-level audit/events contain operation and version/hash references only, without plan literals, participant counts or hidden IDs. Relation/binding-specific events use current subject authorization and action-kind checks; the visible-asset/same-UUID hidden-edge regression remains mandatory. Public graph/operation cursors expose only purpose/tenant/actor/query-bound opaque fences, never raw tenant counters or mutation deltas.

## UI, subsystem map and release gates

The visual editor must expose positive minima, the complete participation scope including zero-degree assets, exact source pins, owner/state mappings, transformations and explicit preserve/repin/tombstone/replacement/release decisions. It must support creating the first required edge jointly with assignment. File import/export preserves the same normalized plan; unsupported fields cannot disappear on a visual round trip. Target/scope/plan edits clear affected acknowledgements and consent; refreshing scope remains possible from an invalid draft. Show source issues distinctly from blocking target issues, actual execution receipts and forward repair links. Provide keyboard/table alternatives, Arabic RTL, both themes and the existing responsive/accessibility gates. No static placeholder counts or disabled controls constitute implementation.

The subsystem map below records the planned integration boundaries at this design checkpoint. New filenames are proposed modules, not evidence of implementation. The exports, shared DTOs and integration seams define the common contracts.

| Subsystem | Files and exact integration seam | Required output before integration |
| --- | --- | --- |
| Shared contracts and asset composition | Existing `packages/domain/src/relation-contracts.ts`; new `relation-migration-contracts.ts` and `graph-asset-preparation.ts`; existing `asset-type-migration-service.ts`, `model-service.ts`, `model-migration-service.ts`, `asset-type-service.ts`, `asset-type-policy.ts`. Define the types above and `projectGraphAssetChanges`; split current private `prepare`/public `executeTypeMigration` into `discoverTypeMigration` and `persistPreparedTypeMigration`; reuse `applyModelMigrationToAttributes`, `validateAssetTypeMigrationPlan`, `applyAssetTypeMigrationPolicy`, `modelPersistence` and `assetTypePersistence`. Extract existing assignment/state projection and write stages without changing public semantics. | Exact frozen types, complete before/after projections, preserved standalone preview/receipt schema, no nested principal phase or final constraints; meaningful `tests/unit/graph-asset-preparation.test.ts` checks for assignment-owner equality, pinned version preservation and complete typed source repair. |
| Graph store/service/API and integration | Existing `packages/domain/src/relation-store.ts`, `relation-service.ts`, `relation-endpoint-guard.ts`, `relation-graph.ts`; new `relation-migration-store.ts`/`relation-migration-service.ts`; new `apps/api/src/relation-migrations.ts`; existing API `relations.ts`, `models.ts`, `asset-types.ts`, `index.ts`, `repository.ts`; shared DB typings and route/test configuration. Reuse `configureRelationTransaction`, `relationQuery`, `relationBudget`, `lockRelationScope`, `assetRows`, `preflightEndpointPolicies`, `endpointState`, `completeRelationRows`, `relationPolicies` and the exact-pin cache. Replace incident-only discovery with the complete eligibility/binding fixed point; call the new pure functions and SQL begin/seal. | Context/preview/execution/receipt and participation HTTP behavior; complete authorization before counts; one global principal phase; parent-only final guard; immutable operation receipts and source preservation. Qualification includes `tests/integration/relation-participation.test.ts`, rollout evidence, status records, CI and final integration. |
| Pure validation and transformation | Existing `packages/domain/src/relation.ts`; new `relation-participation.ts` and `relation-migration.ts`; `tests/unit/relation.test.ts` plus new `relation-participation.test.ts` and `relation-migration.test.ts`. Implement format dispatch, V2 validation, structural semantic projection, strict plan parser, relation transforms, participation derivation, `validateFinalRelationGraphConstraints` and `validateRelationGraphChange`. Consume shared prepared asset contracts; do not reimplement asset transformation or tenant authorization. | Descriptor-safe normalized immutable outputs, exact creation/enrollment keys, complete zero-edge obligations, all surviving pins/maxima/cycles, no budget exhaustion accepted as validity; adversarial boundaries, mixed pins/direction, ordinary-vs-migration owner separation, failed repair, projection mismatch and unchanged V1 unit coverage. |
| Storage | New `packages/db/migrations/009_relation_participation.sql`; new `tests/integration/relation-participation-storage.test.ts`, `tests/qualification/relation-participation-concurrency.test.ts`, `scripts/runtime-test-relation-participation-upgrade.py`. Extend/replace SQL008 `gc_relation_definition_valid`, row/revision guards, `gc_relation_enqueue`, `gc_relation_validate_final`, mutation/publication completeness and ledger fencing only through SQL009. Add protected begin/seal/private claims, bindings/revisions, normalized operation receipts and reservation storage. | Reviewed DDL/FKs/grants/RLS, independently verified deterministic transformations, historical FK preservation, asset INSERT/zero-degree admission, full final validation, every intermediate publication, one global principal order and exact idempotency linkage. Isolated008→009 plus concurrency gates execute only against exact frozen sources; SQL001–008 remain byte-identical. |
| Web UI | Existing `apps/web/src/pages/RelationTypes.tsx`, `relations/TypeEditor.tsx`, `relations/AssetRelations.tsx`, `pages/Relation.tsx`, `relations/shared.tsx` and `relations/messages.ts`; new `pages/RelationMigrations.tsx`, `relations/Participation.tsx`, `relations/MigrationPlanEditor.tsx`; new `tests/e2e/relation-participation.spec.ts`. Consume the frozen HTTP/pure types. Shared `App.tsx`, i18n, styles and routes form part of this integration. | Real context loading, visual/declarative plans, V2 min/max, joint first assignment/assertion, invalid-preview repair, fresh consent, receipt mappings and participation/history, accessible English/Arabic responsive flows and actual browser evidence after integration. |

Audit integration must classify new binding and graph-operation actions explicitly in `visibleAudit`; they must not fall through the current generic non-asset/non-relation branch. Binding actions authorize the current asset and required recorded scope; operation actions authorize the entire original edge/endpoint/binding cohort, including tombstones. Same-UUID subjects of different kinds remain distinct. Type-level public events contain policy/operation hashes rather than private affected-resource lists. The internal source scan path in `apps/api/src/index.ts` retains curator-owned asserted edges, bindings and values through rename, zero/partial/failed/reduced-permission scans; scan status cannot trigger release or invented edge creation.

The SQL entry signatures and parent transaction sequence above define the integration contract. Integrate pure and SQL results before real API execution, then rebuild for API/browser qualification. Source fixes during a qualification gate invalidate that gate's affected evidence and require the appropriate rerun. Previously qualified sources and runtime evidence remain separate.

Required acceptance gates before claiming this bounded increment verified:

1. Positive minima detect a zero-edge eligible asset. Initial positive publication with existing eligible assets plus required new edges commits atomically; missing repairs leave no published head/binding/edge. A foreign/restricted zero-edge participant produces no leaked count or issue. Empty eligible scope is valid and later eligibility is still guarded.
2. Assign both existing untyped endpoints and create their first mandatory edge together. A standalone assignment/transition into scope fails when unsatisfied. Leaving scope requires an explicit permitted binding release. Attempted release while still required, last-edge tombstone, endpoint substitution, state/ancestor change and source-unavailable status cannot bypass participation.
3. Format1 remains zero-min compatible and rejects positive minima/max zero; format2 validates 0..0, positive minima and full boundaries. Directed incoming/outgoing, dual-side eligibility, undirected incident degree, self-edge counting, structurally compatible mixed pins and expired/future edges work in pure, REST and SQL. New enrollment uses the exact final head; stronger participation cannot grandfather weaker old bindings. A changed fingerprint requires complete binding/edge migration. No hidden edge count is exposed.
4. A mixed-pin relation migration transforms exact decimals/attributes, repairs an inactive owner, maps lifecycle, preserves compatible unchanged identity/pins, explicitly repins permitted rows and replaces changed endpoints/orientation. Test opposing directed edges becoming undirected without implicit deduplication, acyclic→allow without preserving old structural pins, same-type creation-key scoping and rejected cross-type links. Old revision snapshots still resolve original definitions/endpoints. A claimed inactive-required-owner tombstone succeeds with intact valid before history and no invented owner; malformed history or a live invalid-owner result fails. Joint untyping retains exact before references for tombstones/releases and actual before/after asset references in the receipt.
5. Joint complete authored-type migration plus relation repair evaluates both final endpoints and all zero-edge bindings once. Untargeted relation types are checked but not silently changed. Current heads and source pins are never conflated. Ordinary assignment/attribute-only APIs cannot bypass the same guard.
6. Late eligible asset/edge/binding, target edits, owner/actor revocation, page/cursor/filter mismatch and expected-version changes invalidate consent or deny execution. Concurrency probes cover two operations competing for the last minimum/maximum slot, first enrollment vs publication, binding release vs insert, directed cycle repair and both revocation orderings.
7. Inject failure after canonical, revision, normalized receipt, audit and outbox writes; prove rollback of every head/resource/fence/claim/idempotency success. Identical retry commits once; changed payload conflicts. Forged normalized children, GUCs, hashes, nested triggers, reused/unconsumed claims, early constraint evaluation, writes after sealing, extra intermediate publications and cross-tenant references fail direct storage tests. Admission tests include direct asset INSERT and zero-degree eligibility changes, not only incident edges. Preparation tests prove the creator boundary, expiry after15 minutes without renewal, changed-definition conflict, competing name publication, rollback restoration and completed execution replay after expiry.
8. SQL008→009 upgrade preserves all old rows/definition hashes/revision references and mixed-pin relations, including tombstones. Runtime/RLS/pool reuse and immutable-history tests pass. Recovery/forward repair proves meaningful reconciliation; SQL008 and earlier bytes/checksums remain unchanged.
9. Real complete/failed/partial/zero/reduced-permission source scans preserve asserted edges, participation and curator values. Source status is not a lifecycle transition, release or deletion. Only governed endpoint policy changes can enter the joint operation; source ingestion cannot manufacture assertions to satisfy a minimum.
10. Boundaries fail before large payload retention or partial writes; caches are tenant/exact-pin only, nested deadlines do not extend, and hidden scope precedes limit reporting. The aggregate2,001-principal bound includes all nested operations/ACL/owners and never uses lock batches. Full receipt/replay/history/audit privacy tests include revoked access and same-UUID cross-kind subjects. Browser journeys execute real preview→joint repair→receipt→history→stale recovery→tenant denial and inspect rendered screenshots.

Evidence must identify actual source/image hashes, SQL checksums, tools, profile, commands, executed cases, original failures and limitations. No test execution or status advance is claimed by this document.

## Review disposition and remaining programme scope

The six storage review findings are resolved at the engineering-contract level: binding repins are head/operation-target constrained with no weaker-policy grandfathering; structural fingerprints include direction, endpoint selectors/state restrictions, full cardinality, allowSelf and cycles; replacements stay within a logical type with scoped keys; protected begin/claims/writes/seal/finalize covers every exceptional write and publication; principals are one globally sorted union of at most2,001; and joint tombstone/release history keeps exact captured before endpoint references. Storage explicitly confirmed the latter is coherent if the SQL009 exception is narrow and actual-before-tuple checked. The inactive-required-owner tombstone exception is finite and receipt bound. These decisions are not evidence that the implementation already enforces them.

The asset/graph composition gap is resolved at the contract level by independently validated `PreparedAssetChanges`, exact endpoint projection equality, and discover→project→persist-prepared stages under the parent lock/deadline/finalization boundary. Assignment preserves the current owner and allows the explicitly selected valid immutable model pin. Context, preview/receipt DTOs, invalid authorized preview behavior, mode rules and participation paging are specified above for design review. No unresolved semantic contradiction is identified; none of these decisions is source implementation or execution evidence.

The material engineering risk is proving the bounded SQL claim verifier equivalent to pure deterministic transformations without trusting hashes or prepared caller tuples, while preserving SQL007 historical receipts and SQL008 exact-pin behavior. The other qualification risks are complete zero-edge discovery under concurrent writes/revocations and the aggregate byte/deadline profile. These require direct adversarial/concurrency/upgrade execution before any claim of completion. The bounded asset ingress subset is existing-asset assignment/transition plus complete authored-type migrations. Source-side/direct asset insertion still receives database admission enforcement. A later new typed-asset UI/import route must participate atomically before every-ingress acceptance. A many-to-one relation merge and cross-type migration need separately designed receipts, provenance and conflict rules and are not disguised as same-type replacement.

Durable execution above the bounded transaction still needs real persisted staging, Temporal orchestration, cancellation/retry/checkpoints and an atomic canonical activation strategy under concurrent writes. A multi-transaction batch that temporarily violates minima is unacceptable. Capacity/large-profile design and measured evidence remain open; these are required programme follow-ons.

Still required beyond this bounded increment: relation/type inheritance and scoped overrides; domain/attribute/responsibility types and full responsibility rules; imported/derived claims and bounded rules with authority/precedence/conflict history; simultaneous-validity cardinality and transaction-time/as-of graphs; relation authorization grants and field sensitivity; complete form/import/export/workflow/MCP parity; semantic models, glossary and reference flows; technical/custom/OpenLineage ingestion and evidence; large-profile graph/migration execution; explicit cross-type migration/merge where required by model evolution; retention/legal-hold deletion and full backup/restore qualification; and all remaining M3–M10 and repository/release gates. This draft must not be used to mark MOD-001/002/004, AT-MOD-01, E2E-06 or M2 complete.

## UI metadata and composition decisions

Context and receipt `assetIdentities` cover exactly their complete authorized asset union; names are display metadata charged to the shared512KiB budget, not per-asset browser fetches. Context `preparations` matches exactly its create intents, retains the original fixed expiry and never renews a lease. `RelationRevisionView.operationId: string|null` is additive metadata outside the immutable snapshot, derived from protected receipt outcomes matching the exact relation/version; ordinary and historical pre-operation revisions return null.

Nested typed receipt digests retain the existing principal-activity/source-issue inputs. Prepared persistence constructs that private evidence from the parent’s stabilized principal snapshot (or reads already locked identities without another lock phase); it never substitutes the outer graph digest for the typed digest. Standalone response and receipt schemas remain unchanged.


Receipt hash clarification: edge/binding outcome `beforeTupleHash` and `afterTupleHash` hash the exact actual immutable revision snapshot (`RelationView` / `ParticipationBindingView`), not the graph projection. A preserved revision may contain older observed endpoint references while the operation graph resolves current captured endpoints. The exact revision foreign keys and verified snapshot hashes remain authoritative.

Compatibility clarification: preserve and source-pin repair under publication must validate own attributes, required ownership and lifecycle state against both the retained exact source policy and the target policy. Explicit full-value repair/repin intent needs no fictitious nested attribute plan; nested attribute acknowledgements are enforced only when a transform exists. Exact head-to-target policy acknowledgements remain mandatory.

Nested type migration IDs are allocated by SQL begin, returned in its exact `typeMigrations` mapping and bound to protected model claims. Prepared persistence uses the selected ID; it never generates an independent nested receipt identity. SQL004/007 companion receipt writes must match that exact claim, plan and cohort.
