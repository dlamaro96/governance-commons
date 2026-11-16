// SPDX-License-Identifier: Apache-2.0
import type { AttributeDefinition, AttributeValues, ModelChange, ValidationIssue } from './model.ts';
import type { LifecycleDefinition } from './asset-type.ts';
import type { MigrationPlan } from './model-migration.ts';

/** Frozen wire shapes from BUSINESS_DOMAINS.md. Types alone do not validate
 * UUIDs, safe keys, versions, timestamps, hashes, authority or completeness. */
export interface DomainTypePin { readonly typeId: string; readonly version: number }
export interface DomainTypeDefinition {
  readonly formatVersion: 1; readonly kind: 'domain-type'; readonly id: string; readonly version: number;
  readonly label: string; readonly parents: readonly DomainTypePin[];
  readonly attributes: Readonly<Record<string, AttributeDefinition>>;
  readonly overrideAttributes: readonly string[]; readonly requiredOwner: boolean;
  readonly lifecycle: LifecycleDefinition | null;
}
export interface ResolvedDomainType {
  readonly attributes: Readonly<Record<string, AttributeDefinition>>;
  readonly requiredOwner: boolean; readonly lifecycle: LifecycleDefinition;
  readonly dependencies: readonly DomainTypePin[];
}
export interface DomainTypeView {
  readonly typeId: string; readonly key: string; readonly version: number; readonly currentVersion: number;
  readonly definition: DomainTypeDefinition; readonly resolved: ResolvedDomainType;
  readonly definitionHash: string; readonly resolutionHash: string;
  readonly createdAt: string; readonly createdBy: string;
}
export interface DomainTuple {
  readonly name: string; readonly description: string; readonly parentId: string | null;
  readonly type: DomainTypePin; readonly attributes: AttributeValues;
  readonly ownerId: string | null; readonly state: string; readonly status: 'active' | 'retired';
}
export interface DomainView extends DomainTuple {
  readonly id: string; readonly version: number;
  readonly createdAt: string; readonly createdBy: string; readonly updatedAt: string; readonly updatedBy: string;
}
export interface DomainRevision {
  readonly formatVersion: 1; readonly domain: DomainView;
  readonly action: 'created' | 'updated' | 'moved' | 'state-changed' | 'retired' | 'restored' | 'type-migrated';
  readonly reason: string; readonly correlationId: string;
}
export interface DomainPlacementView {
  readonly assetId: string; readonly version: number; readonly domainId: string | null;
  readonly recordedAssetVersion: number | null; readonly recordedDomainVersion: number | null;
  readonly recordedAt: string | null; readonly recordedBy: string | null;
}
export interface DomainPlacementRevision {
  readonly formatVersion: 1; readonly placement: DomainPlacementView;
  readonly reason: string; readonly correlationId: string;
}
/** Internal authorization input, never a bearer credential/public tenant selector. */
export interface DomainScopeDescriptor {
  readonly formatVersion: 1; readonly kind: 'asset-domain-scope'; readonly tenantId: string;
  readonly assetId: string; readonly assetVersion: number; readonly placementVersion: number;
  readonly domainId: string | null;
  readonly ancestry: readonly { readonly domainId: string; readonly domainVersion: number }[];
  readonly scopeFence: string;
}
export interface Page<T> { readonly items: readonly T[]; readonly nextCursor: string | null }
export type DomainPolicyChange = 'parents_changed' | 'required_owner_changed' | 'lifecycle_changed';
export interface DomainTypeMigrationPlan {
  readonly formatVersion: 1; readonly kind: 'domain-type-migration'; readonly typeId: string;
  readonly attributes: MigrationPlan;
  readonly owner: { readonly default: 'preserve'; readonly overrides: readonly { readonly domainId: string; readonly ownerId: string | null }[] };
  readonly lifecycle: {
    readonly onUnmapped: 'preserve' | 'error';
    readonly mappings: readonly { readonly sourceVersion: number; readonly from: string; readonly to: string }[];
  };
  readonly acknowledgedPolicyChanges: readonly DomainPolicyChange[];
}
export interface DomainMigrationOutcome {
  readonly domainId: string; readonly fromVersion: number; readonly toVersion: number;
  readonly before: DomainTuple; readonly after: DomainTuple;
}
export interface DomainTypeMigrationContext {
  readonly coverage: 'complete-direct-domain-type-bindings';
  readonly type: DomainTypeView; readonly sources: readonly DomainTypeView[]; readonly domains: readonly DomainView[];
}
export interface DomainTypePreview {
  readonly typeId: string; readonly expectedHeadVersion: number;
  readonly target: Omit<DomainTypeView, 'createdAt' | 'createdBy'>;
  readonly coverage: 'complete-direct-domain-type-bindings'; readonly mode: 'preserve-pins' | 'migrate';
  readonly changes: readonly ModelChange[]; readonly policyChanges: readonly DomainPolicyChange[];
  readonly domains: readonly { readonly before: DomainView; readonly proposed: DomainTuple; readonly issues: readonly ValidationIssue[] }[];
  readonly pinsPreserved: boolean; readonly requiresMigration: boolean;
  readonly ready: boolean; readonly previewDigest: string | null;
}
export interface DomainTypeMigrationReceipt {
  readonly formatVersion: 1; readonly id: string; readonly typeId: string; readonly fromHeadVersion: number;
  readonly targetVersion: number; readonly plan: DomainTypeMigrationPlan;
  readonly planHash: string; readonly previewDigest: string;
  readonly sourcePolicies: readonly { readonly pin: DomainTypePin; readonly definitionHash: string; readonly resolutionHash: string }[];
  readonly targetDefinitionHash: string; readonly targetResolutionHash: string;
  readonly outcomes: readonly DomainMigrationOutcome[];
  readonly actorId: string; readonly occurredAt: string; readonly reason: string; readonly correlationId: string;
}
export interface DomainHierarchyChange {
  readonly kind: 'move' | 'retire' | 'restore'; readonly domainId: string; readonly expectedVersion: number;
  readonly parentId: string | null; readonly reason: string;
}
export interface DomainHierarchyPreview {
  readonly coverage: 'complete-affected-domain-subtree'; readonly change: DomainHierarchyChange;
  readonly domains: readonly { readonly domainId: string; readonly version: number; readonly parentId: string | null }[];
  readonly assets: readonly { readonly assetId: string; readonly assetVersion: number; readonly placementVersion: number }[];
  readonly ready: boolean; readonly issues: readonly ValidationIssue[]; readonly previewDigest: string | null;
}

/** Exact request bodies; concurrency headers remain separate HTTP preconditions. */
export interface DomainFileValidationRequest { readonly text: string }
export interface DomainTypeDefinitionRequest { readonly definition: DomainTypeDefinition; readonly reason: string }
export interface DomainTypePublicationRequest extends DomainTypeDefinitionRequest { readonly previewDigest: string }
export interface DomainTypeMigrationPreviewRequest extends DomainTypeDefinitionRequest { readonly plan: DomainTypeMigrationPlan }
export interface DomainTypeMigrationRequest extends DomainTypeMigrationPreviewRequest { readonly previewDigest: string }
export interface DomainCreateRequest {
  readonly name: string; readonly description: string; readonly parentId: string | null; readonly type: DomainTypePin;
  readonly attributes: AttributeValues; readonly ownerId: string | null; readonly reason: string;
}
export interface DomainEditRequest {
  readonly name: string; readonly description: string; readonly attributes: AttributeValues; readonly ownerId: string | null; readonly reason: string;
}
export interface DomainStateRequest { readonly state: string; readonly reason: string }
export interface DomainHierarchyPreviewRequest { readonly change: DomainHierarchyChange }
export interface DomainHierarchyRequest extends DomainHierarchyPreviewRequest { readonly previewDigest: string }
export interface DomainPlacementRequest {
  readonly assetVersion: number; readonly domainId: string | null; readonly domainVersion: number | null; readonly reason: string;
}

/** Exact event data only; atomic journal adds unchanged CloudEvents/audit envelopes. */
export interface DomainTypeEventData {
  readonly schemaVersion: 1; readonly resourceKind: 'domain-type'; readonly typeId: string;
  readonly previousVersion: number | null; readonly version: number; readonly definitionHash: string;
  readonly resolutionHash: string; readonly migrationId: string | null;
}
export interface DomainEventData {
  readonly schemaVersion: 1; readonly resourceKind: 'domain'; readonly domainId: string;
  readonly previousVersion: number | null; readonly version: number; readonly revisionHash: string; readonly migrationId: string | null;
}
export interface DomainPlacementEventData {
  readonly schemaVersion: 1; readonly resourceKind: 'asset-domain-placement'; readonly assetId: string;
  readonly previousVersion: number; readonly version: number; readonly recordedAssetVersion: number;
  readonly recordedDomainVersion: number | null; readonly domainId: string | null; readonly revisionHash: string;
}
export interface DomainTypeMigrationEventData {
  readonly schemaVersion: 1; readonly resourceKind: 'domain-type-migration'; readonly migrationId: string;
  readonly typeId: string; readonly fromHeadVersion: number; readonly targetVersion: number;
  readonly planHash: string; readonly previewDigest: string; readonly receiptHash: string;
}
export type DomainJournalEvent =
  | { readonly action: 'domain_type.created' | 'domain_type.published'; readonly data: DomainTypeEventData }
  | { readonly action: 'domain.created' | 'domain.updated' | 'domain.moved' | 'domain.state_changed' | 'domain.retired' | 'domain.restored' | 'domain.type_migrated'; readonly data: DomainEventData }
  | { readonly action: 'asset_domain_placement.assigned' | 'asset_domain_placement.reassigned' | 'asset_domain_placement.unassigned'; readonly data: DomainPlacementEventData }
  | { readonly action: 'domain_type_migration.executed'; readonly data: DomainTypeMigrationEventData };
