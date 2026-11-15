export interface Tenant { id: string; name: string; role: string }
export interface Session { user: { id: string; name: string }; tenant: Tenant; tenants: Tenant[]; permissions: string[]; csrfToken: string }
export interface Asset {
  id: string; name: string; qualifiedName: string; type: string;
  description: string | null; ownerId: string | null; ownerName: string | null;
  sourceId: string; sourceName: string; version: number; observedAt: string | null;
  updatedAt: string; status: string; metadata: Record<string, unknown>;
}
export interface Audit { id: string; action: string; resourceId: string; actorName: string; occurredAt: string; changes: Record<string, unknown>; hash: string; previousHash: string | null }
export interface Source { id: string; name: string; host: string; port: number; database: string; schema: string; secretRef: string; status: string; lastSuccessfulScan: string | null; capabilities: unknown }
export interface Job { id: string; sourceId: string; status: 'queued' | 'running' | 'succeeded' | 'failed' | 'cancelled'; createdAt: string; finishedAt: string | null; assetCount: number | null; errorCode: string | null }
export interface Member { id: string; name: string; role: string }
export interface AssetList { items: Asset[]; total: number; nextCursor: string | null; facets: {type: string; count: number}[] }
export interface AssetDetail { asset: Asset; columns: Asset[]; audit: Audit[] }
export interface Overview { assetCount: number; sourceCount: number; ownedCount: number; jobCount: number; recentAudit: Audit[] }
