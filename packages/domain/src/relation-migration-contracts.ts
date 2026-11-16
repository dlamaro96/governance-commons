// SPDX-License-Identifier: Apache-2.0
/** Shared bounded graph-operation contracts. A DTO is neither authorization nor execution evidence. */
import type { AttributeValues, ModelDefinition, ModelChange, ValidationIssue } from './model.ts';
import type { AssetTypeDefinition, ResolvedAssetType } from './asset-type.ts';
import type { MigrationPlan } from './model-migration.ts';
import type { AssetTypeMigrationPlan } from './asset-type-migration.ts';
import type { TypePolicyChange } from './asset-type-migration-contracts.ts';
import type { RelationDefinition, RelationTypeDefinitionV2, RelationEndpointPolicyState } from './relation-contracts.ts';

export type RelationPolicyChange = 'direction_changed' | 'source_types_changed' | 'target_types_changed'
  | 'source_states_changed' | 'target_states_changed' | 'cardinality_changed'
  | 'self_policy_changed' | 'cycles_changed' | 'required_owner_changed' | 'lifecycle_changed';
export type ParticipationSide = 'source' | 'target' | 'incident';
export interface ParticipationBindingView {
  id: string; version: number; relationTypeId: string; relationTypeVersion: number;
  assetId: string; assetVersion: number; side: ParticipationSide;
  status: 'active' | 'released'; createdBy: string; createdAt: string;
  updatedBy: string; updatedAt: string;
}
export interface RelationMigrationValues {
  attributes: AttributeValues; ownerId: string | null; state: string;
  validFrom: string | null; validTo: string | null;
  visibility: 'tenant' | 'restricted'; allowedIdentityIds: readonly string[];
}
export interface RelationTransform {
  attributes: MigrationPlan; // modelId is the relation's logical key; versions are relation policy versions.
  owner: { default: 'preserve'; overrides: readonly { relationId: string; ownerId: string | null }[] };
  lifecycle: { onUnmapped: 'preserve' | 'error'; mappings: readonly {
    sourceVersion: number; from: string; to: string;
  }[] };
}
export type RelationDisposition =
  | { relationId: string; expectedVersion: number; action: 'preserve' }
  | { relationId: string; expectedVersion: number; action: 'migrate' }
  | { relationId: string; expectedVersion: number; action: 'repair'; values: RelationMigrationValues }
  | { relationId: string; expectedVersion: number; action: 'repin'; targetVersion: number; values: RelationMigrationValues }
  | { relationId: string; expectedVersion: number; action: 'tombstone'; reason: string }
  | { relationId: string; expectedVersion: number; action: 'replace'; creationKey: string; reason: string };
export interface RelationCreationProposal {
  key: string; sourceAssetId: string; targetAssetId: string;
  sourceAssetVersion: number; targetAssetVersion: number;
  values: RelationMigrationValues;
}
export type BindingDisposition =
  | { bindingId: string; expectedVersion: number; action: 'preserve' }
  | { bindingId: string; expectedVersion: number; action: 'repin'; targetVersion: number }
  | { bindingId: string; expectedVersion: number; action: 'release'; reason: string };
export interface RelationMigrationPlan {
  formatVersion: 1; relationTypeId: string;
  sourceVersions: readonly number[]; // Exact distinct live edge/binding pins, not a client scope selector.
  transform: RelationTransform | null;
  edges: readonly RelationDisposition[];
  creations: readonly RelationCreationProposal[];
  bindings: readonly BindingDisposition[];
  enrollment: 'complete-eligible-assets';
  acknowledgedPolicyChanges: readonly RelationPolicyChange[];
}
export type RelationMigrationTarget =
  | { kind: 'publish'; expectedHeadVersion: number; definition: RelationTypeDefinitionV2; plan: RelationMigrationPlan }
  | { kind: 'repair'; expectedHeadVersion: number; definition: null; plan: RelationMigrationPlan }
  | { kind: 'create'; reservationId: string; expectedHeadVersion: null; definition: RelationTypeDefinitionV2; plan: RelationMigrationPlan };
export type GraphAssetChange =
  | { kind: 'assign'; assetId: string; expectedVersion: number;
      modelId: string; modelVersion: number; attributes: AttributeValues; ownerId: string | null }
  | { kind: 'transition'; assetId: string; expectedVersion: number; state: string };
export interface GraphChangeSet {
  formatVersion: 1;
  relationTargets: readonly RelationMigrationTarget[];
  assetChanges: readonly GraphAssetChange[];
  assetTypeMigrations: readonly {
    expectedHeadVersion: number; definition: AssetTypeDefinition; plan: AssetTypeMigrationPlan;
  }[];
  repairsReceiptId: string | null;
}

export interface RelationPolicySnapshot {
  relationTypeId: string; definition: RelationDefinition; model: ModelDefinition;
}
export interface RelationAdmissionHead { relationTypeId: string; version: number }
export type GraphEdgeKey = { kind: 'existing'; relationId: string }
  | { kind: 'creation'; relationTypeId: string; key: string };
export type GraphBindingKey = { kind: 'existing'; bindingId: string }
  | { kind: 'enrollment'; relationTypeId: string; assetId: string; side: ParticipationSide };
export interface GraphEdgeSnapshot {
  key: GraphEdgeKey; version: number; relationTypeId: string; relationTypeVersion: number;
  sourceAssetId: string; sourceAssetVersion: number;
  targetAssetId: string; targetAssetVersion: number;
  status: 'active' | 'tombstoned'; values: RelationMigrationValues;
}
export interface GraphBindingSnapshot {
  key: GraphBindingKey; version: number; relationTypeId: string; relationTypeVersion: number;
  assetId: string; assetVersion: number; side: ParticipationSide; status: 'active' | 'released';
}
export interface CompleteGraphSnapshot {
  heads: readonly RelationAdmissionHead[];
  endpoints: readonly RelationEndpointPolicyState[];
  edges: readonly GraphEdgeSnapshot[];
  bindings: readonly GraphBindingSnapshot[];
}
export interface RequiredParticipation {
  relationTypeId: string; policyVersion: number; assetId: string; assetVersion: number;
  side: ParticipationSide; min: number; max: number | null; existingBindingId: string | null;
}
export interface ParticipationDerivationInput {
  admissionHeads: readonly RelationAdmissionHead[];
  policies: readonly RelationPolicySnapshot[];
  completeEligibleEndpointCandidates: readonly RelationEndpointPolicyState[];
  currentBindings: readonly GraphBindingSnapshot[];
}
export interface FinalRelationGraphConstraintsInput {
  graph: CompleteGraphSnapshot;
  policies: readonly RelationPolicySnapshot[];
}
export interface RepairableRelationSourceIssue {
  code: 'source_required_owner_inactive'; relationId: string; ownerId: string;
}
// Full governed asset tuples, not just the subset used by relation eligibility.
// Exact actual immutable asset revisions additionally preserve all other fields.
export interface GraphAssetTuple {
  modelId: string | null; modelVersion: number | null; attributes: AttributeValues;
  ownerId: string | null; state: string | null;
}
export interface GraphAssetPolicyRef { modelId: string; modelVersion: number }
export type GraphAssetPolicyEvidence =
  | { kind: 'attributes'; model: ModelDefinition; definitionHash: string }
  | { kind: 'authored'; typeId: string; resolution: ResolvedAssetType;
      definitionHash: string; resolutionHash: string;
      ancestorTypes: RelationEndpointPolicyState['ancestorTypes'] };
export interface GraphAssetBefore {
  assetId: string; assetVersion: number; tuple: GraphAssetTuple;
  policy: GraphAssetPolicyRef | null;
}
export interface TypeMigrationDiscovery {
  typeId: string; modelId: string; expectedHeadVersion: number;
  headPolicy: GraphAssetPolicyRef; targetPolicy: GraphAssetPolicyRef;
  sourcePolicies: readonly GraphAssetPolicyRef[];
  plan: AssetTypeMigrationPlan; assetIds: readonly string[];
}
export interface GraphAssetPreparationInput {
  assetChanges: readonly GraphAssetChange[];
  typeMigrations: readonly TypeMigrationDiscovery[];
  before: readonly GraphAssetBefore[]; // Complete affected assets, captured under parent locks.
  policies: readonly GraphAssetPolicyEvidence[]; // Exact source, head and proposed target evidence.
  modelHeads: readonly { modelId: string; version: number }[];
  activeOwnerIds: ReadonlySet<string>;
}
export interface PreparedGraphAssetChange {
  kind: 'assign' | 'transition' | 'type-migrate'; assetId: string;
  fromAssetVersion: number; toAssetVersion: number;
  before: GraphAssetTuple; after: GraphAssetTuple;
  sourcePolicy: GraphAssetPolicyRef | null; targetPolicy: GraphAssetPolicyRef | null;
  sourceIssues: readonly ValidationIssue[]; // Existing asset migration allowlist only.
}
export interface PreparedTypeMigration extends TypeMigrationDiscovery {
  changes: readonly ModelChange[]; policyChanges: readonly TypePolicyChange[];
}
export interface PreparedAssetChanges {
  policies: readonly GraphAssetPolicyEvidence[];
  changes: readonly PreparedGraphAssetChange[];
  typeMigrations: readonly PreparedTypeMigration[];
}
export interface AuthorizedCompleteGraphChange {
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
export interface ValidatedGraphChange {
  final: CompleteGraphSnapshot;
  requiredParticipation: readonly RequiredParticipation[];
  sourceIssues: readonly RepairableRelationSourceIssue[];
  changedEdges: readonly { key: GraphEdgeKey; beforeVersion: number | null;
    afterVersion: number; action: 'create' | 'repair' | 'repin' | 'tombstone' }[];
  changedBindings: readonly { key: GraphBindingKey; beforeVersion: number | null;
    afterVersion: number; action: 'enroll' | 'repin' | 'release' }[];
  replacements: readonly { predecessorId: string; relationTypeId: string; creationKey: string }[];
}
export type RelationStructuralPolicy = Pick<RelationDefinition,
  'direction' | 'sourceTypes' | 'targetTypes' | 'sourceStates' | 'targetStates'
  | 'cardinality' | 'allowSelf' | 'cycles'>;

export interface TypeMigrationDiscoveryResult {
  discovery: TypeMigrationDiscovery; policies: readonly GraphAssetPolicyEvidence[];
}
export interface RelationGraphExecutionRequest { changeSet: GraphChangeSet; previewDigest: string }
export interface GraphOperationBinding {
  idempotencyOperation: string; idempotencyKey: string;
  request: RelationGraphExecutionRequest; correlationId: string;
}
export interface GraphOperationHandle { readonly id: string } // Internal constructor; SQL verifies every claim.
export interface GraphOperationBeginResult {
  operation: GraphOperationHandle;
  typeMigrations: readonly { modelId: string; migrationId: string }[];
  creations: readonly { relationTypeId: string; key: string; relationId: string }[];
  enrollments: readonly { relationTypeId: string; assetId: string;
    side: ParticipationSide; bindingId: string }[];
}

export type RelationMigrationIntent =
  | { kind: 'publish'; relationTypeId: string; expectedHeadVersion: number;
      definition: RelationTypeDefinitionV2 }
  | { kind: 'repair'; relationTypeId: string; expectedHeadVersion: number; definition: null }
  | { kind: 'create'; relationTypeId: string; reservationId: string;
      expectedHeadVersion: null; definition: RelationTypeDefinitionV2 };
export interface RelationMigrationContextRequest {
  formatVersion: 1; relationTargets: readonly RelationMigrationIntent[];
  assetChanges: GraphChangeSet['assetChanges'];
  assetTypeMigrations: GraphChangeSet['assetTypeMigrations'];
  repairsReceiptId: string | null;
}
export interface RelationTargetEvidence {
  relationTypeId: string; mode: 'create' | 'publish' | 'repair';
  beforeVersion: number | null; afterVersion: number;
  definitionHash: string; resolutionHash: string;
  beforeStructuralFingerprint: string | null; afterStructuralFingerprint: string;
  policyChanges: readonly RelationPolicyChange[]; attributeChanges: readonly ModelChange[];
}
export type GraphSourceIssue =
  | { kind: 'relation'; issue: RepairableRelationSourceIssue }
  | { kind: 'asset'; assetId: string; issue: ValidationIssue };
export interface RelationMigrationContext {
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
export interface ParticipationDegreePreview extends RequiredParticipation {
  beforeDegree: number; proposedDegree: number;
}
export interface RelationMigrationProjection {
  proposed: CompleteGraphSnapshot;
  participation: readonly ParticipationDegreePreview[];
  changedEdges: ValidatedGraphChange['changedEdges'];
  changedBindings: ValidatedGraphChange['changedBindings'];
  replacements: ValidatedGraphChange['replacements'];
}
export type RelationMigrationPreview = {
  context: RelationMigrationContext; changeSetHash: string;
} & (
  | { ready: true; previewDigest: string; targetIssues: readonly [];
      projection: RelationMigrationProjection }
  | { ready: false; previewDigest: null; targetIssues: readonly ValidationIssue[];
      projection: RelationMigrationProjection | null }
);
export interface ActualRevisionReference { id: string; version: number }
export interface RelationMigrationReceipt {
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
export interface RelationPreparationView {
  id: string; relationTypeId: string; definitionHash: string;
  createdAt: string; expiresAt: string;
}
export interface ParticipationItem {
  binding: ParticipationBindingView; currentAssetVersion: number;
  policy: RelationPolicySnapshot; structuralFingerprint: string;
  minimum: number; maximum: number | null; currentDegree: number;
}
export interface ParticipationListQuery {
  limit?: number; cursor?: string; status?: 'active' | 'released' | 'all';
}
export interface ParticipationListPage {
  items: readonly ParticipationItem[]; nextCursor: string | null; snapshotToken: string;
}
export interface ParticipationRevisionView {
  binding: ParticipationBindingView; assetRevision: ActualRevisionReference;
  policy: RelationPolicySnapshot; operationId: string;
  recordedBy: string; recordedAt: string;
}
export interface ParticipationHistoryPage {
  items: readonly ParticipationRevisionView[]; nextCursor: string | null; snapshotToken: string;
}
