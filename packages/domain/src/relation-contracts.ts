// SPDX-License-Identifier: Apache-2.0
import type { AttributeDefinition, AttributeValues, ModelDefinition, ValidationIssue } from './model.ts';
import type { LifecycleDefinition, ResolvedAssetType } from './asset-type.ts';

/** Authored, non-executable relation contracts. Logical keys and UUIDs are distinct. */
export interface RelationEndpointRule { readonly typeId: string; readonly includeDescendants: boolean }
export interface RelationTypeDefinition {
  readonly formatVersion: 1; readonly id: string; readonly version: number;
  readonly label: string; readonly inverseLabel: string;
  readonly direction: 'directed' | 'undirected';
  readonly sourceTypes: readonly RelationEndpointRule[]; readonly targetTypes: readonly RelationEndpointRule[];
  readonly sourceStates: readonly string[] | null; readonly targetStates: readonly string[] | null;
  readonly cardinality: { readonly outgoing: { readonly min: 0; readonly max: number | null }; readonly incoming: { readonly min: 0; readonly max: number | null } };
  readonly allowSelf: boolean; readonly cycles: 'allow' | 'acyclic';
  readonly attributes: Readonly<Record<string, AttributeDefinition>>;
  readonly requiredOwner: boolean; readonly lifecycle: LifecycleDefinition;
}
export interface RelationTypeSummary {
  id: string; relationTypeId: string; currentVersion: number; label: string; createdAt: string; createdBy: string;
}
export interface RelationTypeView extends RelationTypeSummary {
  version: number; definition: RelationTypeDefinition; definitionHash: string; versionCreatedAt: string; versionCreatedBy: string;
  endpointTypeIdentities: readonly { typeId: string; id: string }[];
}
export interface RelationEndpointView {
  assetId: string; name: string; assetVersion: number; typeId: string | null; modelId: string | null;
  modelVersion: number | null; state: string | null;
}
export interface RelationProvenance {
  origin: 'asserted'; source: { kind: 'manual'; identityId: string }; authority: 'manual-assertion'; precedence: null;
  actorId: string; assertedAt: string; ingestedAt: string; sourceObservedAt: null; sourceVersion: null; sourceRunId: null; confidence: null;
}
export interface RelationView {
  id: string; relationTypeId: string; relationTypeKey: string; relationTypeVersion: number; version: number;
  source: RelationEndpointView; target: RelationEndpointView; direction: 'directed' | 'undirected'; label: string; inverseLabel: string;
  attributes: AttributeValues; ownerId: string | null; state: string; validFrom: string | null; validTo: string | null;
  visibility: 'tenant' | 'restricted'; allowedIdentityIds: readonly string[]; status: 'active' | 'tombstoned';
  provenance: RelationProvenance; createdAt: string; createdBy: string; updatedAt: string; updatedBy: string;
}
export interface RelationEdit {
  sourceAssetVersion: number; targetAssetVersion: number; attributes: unknown; ownerId: string | null;
  validFrom: string | null; validTo: string | null; visibility: 'tenant' | 'restricted'; allowedIdentityIds: readonly string[];
}
export interface RelationCreate extends RelationEdit {
  relationTypeId: string; relationTypeVersion: number; sourceAssetId: string; targetAssetId: string;
}
export interface RelationTransition { state: string; sourceAssetVersion: number; targetAssetVersion: number }
export interface RelationTypePreview {
  relationTypeId: string; id: string; currentVersion: number; proposedVersion: number;
  coverage: 'complete-tenant-relation-type-bindings'; relationCount: number;
  changes: readonly { code: string; path: string; requiresMigration: boolean }[];
  relations: readonly { relationId: string; relationVersion: number; currentIssues: readonly ValidationIssue[]; proposedIssues: readonly ValidationIssue[] }[];
  requiresExplicitMigration: boolean; compatibleWithProvidedRelations: boolean; pinsPreserved: true; previewDigest: string;
}
export interface RelationRevisionView { relationId: string; version: number; snapshot: RelationView; recordedAt: string; recordedBy: string }
export interface RelationPageQuery { limit?: number; cursor?: string }
export interface RelationTypeListQuery extends RelationPageQuery { q?: string }
export interface RelationListQuery extends RelationPageQuery { direction?: 'in' | 'out' | 'both'; relationTypeId?: string; validAt?: string }
export interface RelationGraphQuery extends RelationListQuery { depth?: number }
export interface RelationGraphPage {
  rootAssetId: string; direction: 'in' | 'out' | 'both'; depth: number; validAt: string; graphRevision: string;
  nodes: readonly RelationEndpointView[]; edges: readonly RelationView[]; nextCursor: string | null;
}
export interface RelationListPage { items: readonly RelationView[]; nextCursor: string | null; graphRevision: string }

/** Pure validation inputs. Callers establish authorization and database completeness. */
export interface ResolvedRelationType { readonly definition: RelationTypeDefinition; readonly model: ModelDefinition }
export interface RelationPolicyPin { readonly relationTypeId: string; readonly policy: ResolvedRelationType }
export interface RelationConstraintEdge {
  readonly id: string; readonly version: number; readonly relationTypeId: string; readonly relationTypeVersion: number;
  readonly sourceAssetId: string; readonly targetAssetId: string;
}
export interface RelationEndpointPolicyState {
  readonly assetId: string; readonly assetVersion: number; readonly modelId: string | null; readonly modelVersion: number | null;
  readonly state: string | null; readonly typeId: string | null; readonly policy: ResolvedAssetType | null;
  readonly ancestorTypes: readonly { readonly typeId: string; readonly id: string; readonly version: number }[];
}
export interface RelationEndpointProposal {
  readonly assetId: string; readonly expectedAssetVersion: number; readonly after: RelationEndpointPolicyState;
}
export interface RelationUpgradeBinding {
  readonly edge: RelationConstraintEdge; readonly attributes: unknown; readonly ownerId: string | null; readonly state: string;
  readonly source: RelationEndpointPolicyState; readonly target: RelationEndpointPolicyState;
}
export interface RelationEndpointValidationInput {
  readonly edge: RelationConstraintEdge; readonly policies: readonly RelationPolicyPin[];
  readonly source: RelationEndpointPolicyState; readonly target: RelationEndpointPolicyState;
}
export interface RelationEndpointChangesInput {
  readonly currentEndpoints: readonly RelationEndpointPolicyState[]; readonly proposedEndpoints: readonly RelationEndpointProposal[];
  readonly completeIncidentRelations: readonly RelationConstraintEdge[]; readonly policies: readonly RelationPolicyPin[];
}
export interface RelationStructureInput {
  readonly relationTypeId: string; readonly completeLiveRelations: readonly RelationConstraintEdge[]; readonly policies: readonly RelationPolicyPin[];
}
export interface RelationUpgradeInput {
  readonly relationTypeId: string; readonly head: ResolvedRelationType; readonly target: ResolvedRelationType;
  readonly policies: readonly RelationPolicyPin[]; readonly completeLiveRelations: readonly RelationUpgradeBinding[];
  readonly activeOwnerIds: ReadonlySet<string>;
}
export type RelationUpgradeResult = Pick<RelationTypePreview, 'changes' | 'relations' | 'requiresExplicitMigration' | 'compatibleWithProvidedRelations' | 'pinsPreserved'>;
export interface AuthorizedRelationTraversalInput {
  readonly rootAssetId: string; readonly direction: 'in' | 'out' | 'both'; readonly depth: number;
  readonly validAt: string; readonly relationTypeId: string | null;
  readonly nodes: readonly RelationEndpointView[]; readonly edges: readonly RelationView[];
  /** Complete matching authorized adjacency for every node expanded below the requested depth. */
  readonly completeFrontierAssetIds: readonly string[];
}
export interface RelationNeighborhood { readonly nodes: readonly RelationEndpointView[]; readonly edges: readonly RelationView[] }
