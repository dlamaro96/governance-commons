// SPDX-License-Identifier: Apache-2.0
import type { AttributeValues, ModelChange, ValidationIssue } from './model.ts';
import type { ResolvedAssetType } from './asset-type.ts';
import type { AssetTypeMigrationPlan } from './asset-type-migration.ts';
import type { MigrationAssetReceipt } from './model-migration-service.ts';

export type TypePolicyChange = 'parents_changed' | 'required_owner_changed' | 'lifecycle_changed';
export interface TypeMigrationTuple {
  modelId: string; modelVersion: number; attributes: AttributeValues; ownerId: string | null; state: string;
}
export interface TypeMigrationAssetReceipt extends MigrationAssetReceipt {
  before: TypeMigrationTuple; after: TypeMigrationTuple; beforeTupleHash: string; afterTupleHash: string;
}
export interface TypeMigrationAssetPreview extends TypeMigrationAssetReceipt { sourceIssues: readonly ValidationIssue[] }
export interface TypeMigrationContext {
  typeId: string; modelId: string; currentVersion: number; sourceVersions: number[]; assetCount: number;
  sources: { version: number; resolution: ResolvedAssetType; resolutionHash: string }[];
  assets: { assetId: string; name: string; assetVersion: number; modelVersion: number; ownerId: string | null; state: string | null }[];
}
export interface TypeMigrationPreview {
  typeId: string; modelId: string; currentVersion: number; proposedVersion: number;
  coverage: 'complete-tenant-model-bindings'; assetCount: number; changes: readonly ModelChange[];
  policyChanges: readonly TypePolicyChange[]; assets: TypeMigrationAssetPreview[];
  sourceResolutions: { version: number; resolutionHash: string }[];
  definitionHash: string; resolutionHash: string; previewDigest: string; planHash: string; ready: true;
}
export interface TypeMigrationReceipt {
  id: string; typeId: string; modelId: string; fromVersion: number; toVersion: number;
  plan: AssetTypeMigrationPlan; planHash: string; previewDigest: string;
  definitionHash: string; resolutionHash: string; sourceResolutions: { version: number; resolutionHash: string }[];
  assetCount: number; assets: TypeMigrationAssetReceipt[]; executedBy: string; executedAt: string;
}
export interface TypeMigrationRequest { definition: unknown; plan: unknown }
export interface TypeMigrationExecutionRequest extends TypeMigrationRequest { previewDigest: string }
