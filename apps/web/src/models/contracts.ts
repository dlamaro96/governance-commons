// SPDX-License-Identifier: Apache-2.0
import type { ModelDefinition, ModelUpgradePreview, ValidationIssue } from '../../../../packages/domain/src/model';
export type { ModelDefinition, AttributeDefinition, AttributeSchema, AttributeValues, ValidationIssue } from '../../../../packages/domain/src/model';
export interface ModelSummary { id: string; typeId: string | null; currentVersion: number; createdAt: string; createdBy: string }
export interface PublishedModel { id: string; typeId: string | null; version: number; currentVersion: number; definition: ModelDefinition; definitionHash: string; createdAt: string; createdBy: string }
export interface ModelPreview extends Omit<ModelUpgradePreview, 'coverage'> {
  modelId: string; currentVersion: number; proposedVersion: number; coverage: 'complete-tenant-model-bindings'; assetCount: number; pinsPreserved: true; previewDigest: string;
}
export interface AssetAttributes { assetId: string; assetVersion: number; modelId: string | null; modelVersion: number | null; attributes: Record<string, unknown>; definition: ModelDefinition | null }
export type Issues = readonly ValidationIssue[];
