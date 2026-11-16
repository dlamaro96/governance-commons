// SPDX-License-Identifier: Apache-2.0
/** Direct PostgreSQL catalog dependencies; referenced attributes are witnesses, never output mappings. */
export const LINEAGE_GAPS=['OPAQUE_ROUTINE_DEPENDENCY','OUT_OF_SCOPE_RELATION','UNSUPPORTED_RELATION_KIND'] as const;
export type LineageGap=typeof LINEAGE_GAPS[number];
export const LINEAGE_LIMITS=Object.freeze({views:1000,edges:5000,witnesses:10000,bytes:1048576,depth:6,page:100});
export interface PgViewLineage {
 formatVersion:1;kind:'postgresql-view-dependencies';adapterVersion:'1';queryTemplate:'postgresql-view-dependencies-v1';
 views:{viewExternalId:string;rewriteOid:string;dependencies:{referencedExternalId:string;referencedAttributeNumbers:number[]}[];gaps:LineageGap[]}[];
}
export interface LineageQuery {direction?:'upstream'|'downstream'|'both';depth?:number;limit?:number;cursor?:string}
export interface LineageNode {id:string;name:string;qualifiedName:string;type:string;version:number}
export interface LineageObservation {id:string;sourceId:string;generation:string;observedAt:string;recordedAt:string;sourceVersion:string;adapterVersion:'1';queryTemplate:'postgresql-view-dependencies-v1'}
export interface LineageEdge {id:string;upstreamAssetId:string;upstreamVersion:number;downstreamAssetId:string;downstreamVersion:number;
 evidenceType:'postgresql-catalog-view-dependency';scope:'table';confidence:null;sourceCodeReference:null;sourceCodeAvailability:'not-collected';
 evidencePointer:string;evidenceHash:string;referencedAttributeNumbers:number[];observation:LineageObservation;
}
export interface LineageView {assetId:string;coverage:'COLLECTED'|'NOT_COLLECTED'|'UNSUPPORTED';
 direction:'upstream'|'downstream'|'both';depth:number;nodes:LineageNode[];edges:LineageEdge[];
 gaps:{assetId:string;code:LineageGap}[];nextCursor:string|null;
 limitations:('COLUMN_MAPPINGS_NOT_COLLECTED'|'SQL_BODIES_NOT_ANALYZED')[];
}
