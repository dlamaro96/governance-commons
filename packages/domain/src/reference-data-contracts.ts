// SPDX-License-Identifier: Apache-2.0
/** Closed reference-code publication contracts. Runtime qualification is tracked separately. */
export type Instant = string;
export type UUID = string;
export type Hash = string;
export interface LocalizedLabel {readonly label:string;readonly description:string}
export interface Labels {readonly en:LocalizedLabel;readonly ar:LocalizedLabel}
export interface ReferenceValue {
 readonly code:string;readonly labels:Labels;readonly ownerId:UUID;
 readonly status:'active'|'deprecated';readonly validFrom:Instant|null;readonly validUntil:Instant|null;
}
export interface ReleaseInput {
 readonly formatVersion:1;readonly kind:'reference-code-list';readonly labels:Labels;readonly ownerId:UUID;
 readonly status:'active'|'deprecated';readonly activation:{readonly kind:'on-publication'}|{readonly kind:'at';readonly at:Instant};
 readonly validUntil:Instant|null;readonly values:readonly ReferenceValue[];
}
export interface Audience {readonly visibility:'tenant'|'restricted';readonly allowedIdentityIds:readonly UUID[]}
export interface WorkflowPin {readonly id:string;readonly version:number;readonly definitionHash:Hash}
export interface Proposal {
 readonly id:UUID;readonly setId:UUID;readonly expectedVersion:number;readonly audience:Audience;
 readonly release:ReleaseInput;readonly workflow:WorkflowPin;readonly assignments:Readonly<Record<string,UUID>>;readonly expiresAt:Instant;
}
export interface ApprovalPayload {
 readonly formatVersion:1;readonly kind:'reference-publication';readonly setId:UUID;readonly expectedVersion:number;
 readonly audience:Audience;readonly release:ReleaseInput;
}
export interface ApprovalDigestPreimage {
 readonly id:UUID;readonly binding:'reference.publish';readonly payload:ApprovalPayload;
 readonly workflow:WorkflowPin;readonly assignments:Readonly<Record<string,UUID>>;readonly expiresAt:Instant;
}
export interface PublicationResult {
 readonly binding:'reference.publish';readonly setId:UUID;readonly version:number;readonly publicationHash:Hash;
 readonly publishedAt:Instant;readonly effectiveFrom:Instant;
}
export interface PublishedBundle {
 readonly formatVersion:1;readonly kind:'reference-code-list';readonly setId:UUID;readonly version:number;
 readonly labels:Labels;readonly ownerId:UUID;readonly status:'active'|'deprecated';readonly publishedAt:Instant;
 readonly effectiveFrom:Instant;readonly validUntil:Instant|null;readonly values:readonly ReferenceValue[];
}
export interface PublicationContext {
 readonly payload:ApprovalPayload;readonly publishedAt:Instant;
 readonly previous:PublishedBundle|null;readonly previousAudience:Audience|null;
}
export interface EffectiveSelection {
 readonly asOf:Instant;readonly phase:'NOT_EFFECTIVE'|'EFFECTIVE'|'DEPRECATED'|'EXPIRED';
 readonly version:number|null;readonly publicationHash:Hash|null;readonly effectiveFrom:Instant|null;
 readonly effectiveUntil:Instant|null;readonly values:readonly ReferenceValue[];
}
export interface Download {readonly body:string;readonly contentType:string;readonly etag:string;readonly byteLength:number}
export interface Issue {readonly code:'INVALID_JSON'|'LIMIT'|'FORMAT'|'FIELDS'|'DUPLICATE'|'INTERVAL'|'CONFLICT'|'NON_CANONICAL';readonly path:string;readonly message:string}
export type Result<T>={readonly ok:true;readonly value:T}|{readonly ok:false;readonly issues:readonly Issue[]};
export const LIMITS=Object.freeze({values:256,principals:64,assignments:64,code:128,label:240,description:2048,
 releaseBytes:245760,payloadBytes:262144,envelopeBytes:327680,downloadBytes:8388608,
 nodes:20000,depth:16,properties:128,array:256,totalUtf16:327680,stringUtf16:8192,
 // Pure history oracle only: production selects candidate release headers in SQL.
 // This helper rejects larger complete histories, never truncates them.
 historyVersions:128,version:2147483647});

export interface ReferencePage<T>{readonly items:readonly T[];readonly nextCursor:string|null}
export interface ReferencePageQuery{readonly limit?:number;readonly cursor?:string}
export interface ReferenceSetQuery extends ReferencePageQuery{readonly q?:string}
export interface ReferenceEffectiveQuery extends ReferencePageQuery{readonly asOf?:Instant}
export type ReferencePhase=EffectiveSelection['phase'];
export interface ReferenceReleaseSummary {
 readonly setId:UUID;readonly version:number;readonly labels:Labels;readonly ownerId:UUID;
 readonly status:'active'|'deprecated';readonly publishedAt:Instant;readonly effectiveFrom:Instant;
 readonly validUntil:Instant|null;readonly publicationHash:Hash;readonly valueCount:number;
}
export interface ReferenceEffectiveState {
 readonly asOf:Instant;readonly phase:ReferencePhase;readonly version:number|null;
 readonly publicationHash:Hash|null;readonly effectiveFrom:Instant|null;readonly effectiveUntil:Instant|null;
}
export interface ReferenceSetSummary {
 readonly id:UUID;readonly latest:ReferenceReleaseSummary;readonly effective:ReferenceEffectiveState;
}
export interface ReferenceEffectiveView extends ReferencePage<ReferenceValue> {
 readonly set:ReferenceSetSummary;readonly selection:ReferenceEffectiveState;
}
export interface ReferenceReleaseView{readonly release:PublishedBundle;readonly publicationHash:Hash}
export interface ReferenceAuthoringContext extends ReferenceReleaseView {
 readonly setId:UUID;readonly latestPublishedVersion:number;readonly audience:Audience;
}
export interface ReferenceProposalReceipt{readonly instance:{readonly id:UUID}}
