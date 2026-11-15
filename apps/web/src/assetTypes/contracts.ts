// SPDX-License-Identifier: Apache-2.0
import type { AssetTypeDefinition, LifecycleDefinition, TypePin } from '../../../../packages/domain/src/asset-type';
import type { ModelDefinition, ModelPreview } from '../models/contracts';
export type { AssetTypeDefinition, LifecycleDefinition, TypePin } from '../../../../packages/domain/src/asset-type';

export interface PublishedAssetType {
  id: string; typeId: string; version: number; currentVersion: number;
  definition: AssetTypeDefinition;
  resolved: { model: ModelDefinition; requiredOwner: boolean; lifecycle: LifecycleDefinition; dependencies: TypePin[] };
  definitionHash: string; resolutionHash: string; createdAt: string; createdBy: string;
}
export interface AssetTypePreview extends Omit<ModelPreview, 'affectedAssetIds'> { typeId: string }
export interface AssetTypeState {
  assetId: string; assetVersion: number; modelId: string | null; modelVersion: number | null;
  state: string | null; requiredOwner: boolean; lifecycle: LifecycleDefinition | null;
}
