// SPDX-License-Identifier: Apache-2.0
/** Closed metadata classification family. Source-value and model detectors have
 * separate future versions; a metadata match is never a probability estimate. */
export interface ClassificationPin {id:string;version:number;definitionHash:string}
export interface ClassificationLabelPin {taxonomy:ClassificationPin;labelKey:string}
export interface ClassificationTaxonomy {
 formatVersion:1;name:string;description:string;
 labels:{key:string;name:string;description:string;status:'active'|'deprecated'}[];
}
export type ClassificationField='name'|'qualifiedName'|'dataType';
export interface ClassificationPredicate {
 field:ClassificationField;operator:'equals'|'contains'|'starts-with'|'ends-with';
 comparison:'exact'|'ascii-insensitive';literal:string;
}
export interface MetadataClassificationRule {
 formatVersion:1;kind:'metadata-literal';name:string;purpose:string;ownerId:string;status:'active'|'retired';
 assetTypes:('table'|'view'|'column')[];label:ClassificationLabelPin;all:ClassificationPredicate[];
}
export interface ClassificationAssetInput {
 id:string;version:number;type:string;name:string;qualifiedName:string;dataType:string|null;
}
export interface ClassificationEvidence {
 formatVersion:1;kind:'metadata-literal';assetId:string;observedAssetVersion:number;inputDigest:string;
 rule:ClassificationPin;label:ClassificationLabelPin;evaluatedAt:string;
 matches:{conditionIndex:number;field:ClassificationField;value:string;valueHash:string}[];
 confidence:{kind:'not-estimated';reason:'metadata-only'};
 samplePolicy:{kind:'metadata-only';sourceRowsRead:0;sourceSamplesStored:0};
}
export interface ClassificationEvaluation {
 outcome:'matched'|'not_matched'|'unsupported';evidence:ClassificationEvidence;
}
export interface ClassificationTaxonomyView extends ClassificationPin {
 currentVersion:number;definition:ClassificationTaxonomy;createdAt:string;createdBy:string;
}
export interface ClassificationRuleView extends ClassificationPin {
 currentVersion:number;definition:MetadataClassificationRule;createdAt:string;createdBy:string;
}
export interface ClassificationEvaluationView extends ClassificationEvaluation {
 id:string;createdBy:string;suggestionId:string|null;evidenceHash:string;
}
export interface ClassificationAssignmentView {
 id:string;assetId:string;label:ClassificationLabelPin;version:number;status:'active'|'withdrawn';
 suggestionId:string;approvalInstanceId:string;evidence:ClassificationEvidence;evidenceCurrent:boolean;
 createdAt:string;updatedAt:string;updatedBy:string;reason:string;
}
export interface ClassificationSuggestionView {
 id:string;assetId:string;evaluationId:string;evidence:ClassificationEvidence;evidenceHash:string;
 evidenceCurrent:boolean;currentAssignmentVersion:number;createdAt:string;createdBy:string;
}
export type ClassificationChange={kind:'apply';suggestionId:string;expectedAssignmentVersion:number}
 |{kind:'withdraw';assignmentId:string;expectedAssignmentVersion:number;reason:string};
export interface ClassificationProposal {
 id:string;change:ClassificationChange;workflow:ClassificationPin;assignments:Record<string,string>;expiresAt:string;
}
export interface ClassificationPage<T>{items:T[];nextCursor:string|null}
export interface ClassificationPublishInput<T>{id:string;expectedVersion:number;definition:T}
export interface ClassificationEvaluateInput {id:string;expectedAssetVersion:number;rule:ClassificationPin}
export const CLASSIFICATION_LIMITS=Object.freeze({labels:128,predicates:8,literal:256,field:2048,name:240,description:4096,definitionBytes:65536,evidenceBytes:32768,page:100});

/** Server-created, immutable approval payload. Callers submit a proposal command,
 * never this evidence envelope. Assignment identity/version are canonical. */
export interface ClassificationApprovalPayload {
 formatVersion:1;kind:'classification-review';change:'apply'|'withdraw';assetId:string;
 assignmentId:string;expectedAssignmentVersion:number;suggestionId:string;label:ClassificationLabelPin;
 evidence:ClassificationEvidence;evidenceHash:string;reason:string;
}
export interface ClassificationApprovalResult {
 binding:'classification.review';assetId:string;assignmentId:string;assignmentVersion:number;
 status:'active'|'withdrawn';evidenceHash:string;
}
export interface ClassificationProposalReceipt {instance:{id:string}}
