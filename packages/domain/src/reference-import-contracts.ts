// SPDX-License-Identifier: Apache-2.0
/** Advisory code-row reconciliation; canonical proposals retain independent authorization and approval. */
import type {ReferenceValue} from './reference-data-contracts.ts';
export type ImportMode='merge'|'replace';
export type ImportFormat='json'|'csv';
export interface ImportBase {readonly setId:string;readonly expectedVersion:number;readonly publicationHash:string|null}
export const IMPORT_FIELDS=Object.freeze(['code','labels.en.label','labels.en.description','labels.ar.label','labels.ar.description','ownerId','status','validFrom','validUntil'] as const);
export type ImportField=typeof IMPORT_FIELDS[number];
export interface ImportIssue {
 readonly code:'FORMAT'|'FIELDS'|'DUPLICATE'|'INTERVAL'|'LIMIT';
 readonly row:number|null;readonly field:ImportField|'';readonly relatedRow:number|null;
}
export interface ImportInvalid {readonly state:'invalid';readonly issues:readonly ImportIssue[];readonly issuesTruncated:boolean}
export interface ImportRows {readonly state:'parsed';readonly sourceSha256:string;readonly values:readonly ReferenceValue[]}
export interface ValueChange {
 readonly code:string;readonly kind:'added'|'changed'|'removed'|'unchanged';
 readonly before:ReferenceValue|null;readonly after:ReferenceValue|null;readonly changedFields:readonly ImportField[];
}
export interface ImportReady {
 readonly state:'ready';readonly base:ImportBase;readonly mode:ImportMode;readonly sourceSha256:string;
 readonly values:readonly ReferenceValue[];readonly changes:readonly ValueChange[];
 readonly counts:{readonly added:number;readonly changed:number;readonly removed:number;readonly unchanged:number};
}
export type ImportPreview=ImportInvalid|ImportReady;
export const IMPORT_LIMITS=Object.freeze({rawBytes:262144,rows:256,issues:128,changes:512,responseBytes:1048576});
export const IMPORT_CSV_HEADERS=Object.freeze(['code','label_en','description_en','label_ar','description_ar','owner_id','status','valid_from','valid_until'] as const);
// Pure server implementation in reference-import.ts:
// parseImportRows(raw:Uint8Array,format:ImportFormat):ImportRows|ImportInvalid
// reconcileImport(base:ImportBase,baseline:unknown,mode:ImportMode,rows:ImportRows):ImportPreview
// Raw byte view and all callable object inputs are validated before reflective reads.
// baseline=[] iff expectedVersion=0; populated baseline is the exact current authorized head.
// sourceSha256 hashes the original UTF-8 bytes; it is provenance, never authorization.
