// SPDX-License-Identifier: Apache-2.0
import type { Tx } from '../../db/src/index.ts';
import type { Principal } from '../../authz/src/index.ts';
import type {
  DomainCreateRequest, DomainEditRequest, DomainStateRequest, DomainPlacementRequest, DomainTypeDefinitionRequest,
  DomainTypePublicationRequest, DomainTypeMigrationPreviewRequest, DomainTypeMigrationRequest, DomainHierarchyChange,
  DomainHierarchyRequest, DomainView, DomainTypeView, DomainTypeMigrationContext, DomainTypeMigrationReceipt,
  DomainTypePreview, DomainHierarchyPreview, DomainPlacementView, DomainRevision, DomainPlacementRevision, Page, DomainJournalEvent,
} from './business-domain-contracts.ts';

/** Service calls are already parsed, never HTTP request objects or tenant selectors.
 * Every entry point nevertheless rechecks current database authority and bounds. */
export interface DomainPageQuery { readonly limit?: number; readonly cursor?: string; readonly q?: string }
export interface DomainHistoryQuery { readonly limit?: number; readonly cursor?: string }
export interface DomainInventoryQuery extends DomainPageQuery { readonly parentId?: string; readonly status?: 'active' | 'retired' | 'all' }
export type DomainReadRequest =
  | { readonly kind: 'domain-types'; readonly page: DomainPageQuery }
  | { readonly kind: 'domain-type'; readonly typeId: string; readonly version?: number }
  | { readonly kind: 'migration-context'; readonly typeId: string }
  | { readonly kind: 'migration-receipt'; readonly typeId: string; readonly id: string }
  | { readonly kind: 'domains'; readonly page: DomainInventoryQuery }
  | { readonly kind: 'owner-candidates'; readonly page: DomainPageQuery }
  | { readonly kind: 'domain'; readonly id: string }
  | { readonly kind: 'domain-history'; readonly id: string; readonly page: DomainHistoryQuery }
  | { readonly kind: 'domain-assets'; readonly id: string; readonly page: DomainHistoryQuery }
  | { readonly kind: 'placement'; readonly assetId: string }
  | { readonly kind: 'placement-history'; readonly assetId: string; readonly page: DomainHistoryQuery };
export interface DomainReadResults {
  'domain-types': Page<{ typeId: string; key: string; label: string; currentVersion: number }>;
  'domain-type': { type: DomainTypeView };
  'migration-context': DomainTypeMigrationContext;
  'migration-receipt': { receipt: DomainTypeMigrationReceipt };
  domains: Page<DomainView>;
  'owner-candidates': Page<{ id: string; name: string }>;
  domain: { domain: DomainView };
  'domain-history': Page<DomainRevision>;
  'domain-assets': Page<{ assetId: string; name: string; assetVersion: number; placementVersion: number }>;
  placement: { placement: DomainPlacementView; domain: DomainView | null };
  'placement-history': Page<DomainPlacementRevision>;
}
export type DomainPreviewRequest =
  | ({ readonly kind: 'domain-type'; readonly typeId: string; readonly expectedHeadVersion: number } & DomainTypeDefinitionRequest)
  | ({ readonly kind: 'migration'; readonly typeId: string; readonly expectedHeadVersion: number } & DomainTypeMigrationPreviewRequest)
  | { readonly kind: 'hierarchy'; readonly change: DomainHierarchyChange };
export interface DomainPreviewResults {
  'domain-type': { preview: DomainTypePreview };
  migration: { preview: DomainTypePreview };
  hierarchy: { preview: DomainHierarchyPreview };
}
export type DomainMutationRequest =
  | ({ readonly kind: 'domain-type.create' } & DomainTypeDefinitionRequest)
  | ({ readonly kind: 'domain-type.publish'; readonly typeId: string; readonly expectedHeadVersion: number } & DomainTypePublicationRequest)
  | ({ readonly kind: 'domain.create' } & DomainCreateRequest)
  | ({ readonly kind: 'domain.update'; readonly domainId: string; readonly expectedVersion: number } & DomainEditRequest)
  | ({ readonly kind: 'domain.state'; readonly domainId: string; readonly expectedVersion: number } & DomainStateRequest)
  | ({ readonly kind: 'domain.hierarchy' } & DomainHierarchyRequest)
  | ({ readonly kind: 'domain.placement'; readonly assetId: string; readonly expectedPlacementVersion: number } & DomainPlacementRequest)
  | ({ readonly kind: 'domain-type-migration.execute'; readonly typeId: string; readonly expectedHeadVersion: number } & DomainTypeMigrationRequest);
export interface DomainMutationResults {
  'domain-type.create': { type: DomainTypeView };
  'domain-type.publish': { type: DomainTypeView };
  'domain.create': { domain: DomainView };
  'domain.update': { domain: DomainView };
  'domain.state': { domain: DomainView };
  'domain.hierarchy': { domain: DomainView };
  'domain.placement': DomainReadResults['placement'];
  'domain-type-migration.execute': { type: DomainTypeView; receipt: DomainTypeMigrationReceipt };
}
export type DomainQuery = <T>(work: () => Promise<T>) => Promise<T>;
export interface DomainOnceOptions<T> { readonly query: DomainQuery; readonly authorizeReplay: (response: T) => Promise<void> }
export interface DomainJournalOptions {
  readonly data: DomainJournalEvent['data']; readonly resourceKind: DomainJournalEvent['data']['resourceKind'];
  readonly occurredAt: string; readonly query: DomainQuery;
}
export interface DomainHooks {
  readonly once: <T>(tx: Tx, principal: Principal, operation: string, key: unknown, body: unknown,
    fn: () => Promise<T>, options: DomainOnceOptions<T>) => Promise<T>;
  readonly record: (tx: Tx, principal: Principal, action: string, resourceId: string, version: number,
    changes: unknown, correlationId: string, options: DomainJournalOptions) => Promise<unknown>;
}
