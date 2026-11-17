// SPDX-License-Identifier: Apache-2.0
/** Closed source-executed quality families. Each retains exact immutable inputs. */
export interface CompletenessRuleDefinition {
 formatVersion:1;kind:'completeness';target:{tableAssetId:string;columnAssetId:string};
 name:string;purpose:string;ownerId:string;severity:'info'|'warning'|'critical';maximumNullBasisPoints:number;
}
export interface ReferenceAllowedValuesRuleDefinition {
 formatVersion:1;kind:'reference-allowed-values';target:{tableAssetId:string;columnAssetId:string};
 name:string;purpose:string;ownerId:string;severity:'info'|'warning'|'critical';maximumInvalidBasisPoints:number;
 reference:{setId:string;selection:'effective-at-run';codeStatus:'active'};comparison:'utf8-exact';nullPolicy:'exclude';
}
export interface UniquenessRuleDefinition {
 formatVersion:1;kind:'uniqueness';target:{tableAssetId:string;columnAssetId:string};
 name:string;purpose:string;ownerId:string;severity:'info'|'warning'|'critical';maximumDuplicateBasisPoints:number;
 comparison:'utf8-exact';nullPolicy:'exclude';
}
export type QualityRuleDefinition=CompletenessRuleDefinition|ReferenceAllowedValuesRuleDefinition|UniquenessRuleDefinition;
export interface QualityReferenceMetadata {setId:string;version:number;publicationHash:string;asOf:string;codeStatus:'active';bindingHash:string}
export interface QualityReferenceBinding extends QualityReferenceMetadata {codes:string[]}
export interface QualityTarget {
 databaseOid:string;schemaOid:string;relationOid:string;attributeNumber:number;
 schemaName:string;tableName:string;columnName:string;dataType:string;
}
export interface QualityBudget {maximumRows:number;maximumSeconds:number;statementTimeoutMs:number;maximumEstimatedCost:number;maximumEstimatedBytes:number}
export const QUALITY_BUDGET:Readonly<QualityBudget>=Object.freeze({maximumRows:100000,maximumSeconds:30,statementTimeoutMs:15000,maximumEstimatedCost:1000000,maximumEstimatedBytes:67108864});
export interface QualityUniquenessBudget extends QualityBudget {maximumValueBytes:number;maximumTotalValueBytes:number}
export const QUALITY_UNIQUENESS_BUDGET:Readonly<QualityUniquenessBudget>=Object.freeze({...QUALITY_BUDGET,maximumValueBytes:4096,maximumTotalValueBytes:67108864});
export type QualityExecution={formatVersion:1;kind:'completeness';target:QualityTarget;budget:QualityBudget}
 |{formatVersion:1;kind:'reference-allowed-values';target:QualityTarget;budget:QualityBudget;reference:QualityReferenceBinding}
 |{formatVersion:1;kind:'uniqueness';target:QualityTarget;budget:QualityUniquenessBudget};
export interface CompletenessMeasurement {
 formatVersion:1;kind:'completeness';strategy:'exact-bounded-role-scope';rowCount:number;nullCount:number;
 observedStartedAt:string;observedFinishedAt:string;elapsedMs:number;sourceVersion:string;adapterVersion:'1';
 queryTemplate:'postgresql-completeness-v1';estimatedCost:number;estimatedBytes:number;
}
export interface ReferenceAllowedValuesMeasurement {
 formatVersion:1;kind:'reference-allowed-values';strategy:'exact-bounded-role-scope';rowCount:number;nullCount:number;invalidCount:number;referenceBindingHash:string;
 observedStartedAt:string;observedFinishedAt:string;elapsedMs:number;sourceVersion:string;adapterVersion:'1';
 queryTemplate:'postgresql-reference-allowed-values-v1';estimatedCost:number;estimatedBytes:number;
}
export interface UniquenessMeasurement {
 formatVersion:1;kind:'uniqueness';strategy:'exact-bounded-role-scope';rowCount:number;nullCount:number;
 distinctCount:number;duplicateGroupCount:number;duplicateRowCount:number;totalValueBytes:number;largestValueBytes:number;
 observedStartedAt:string;observedFinishedAt:string;elapsedMs:number;sourceVersion:string;adapterVersion:'1';
 queryTemplate:'postgresql-uniqueness-v1';estimatedCost:number;estimatedBytes:number;
}
export type QualityMeasurement=CompletenessMeasurement|ReferenceAllowedValuesMeasurement|UniquenessMeasurement;
export type QualityStatus='queued'|'running'|'succeeded'|'failed'|'cancelled';
export type QualityVerdict='PASS'|'FAIL'|'NO_DATA';
export const QUALITY_ERRORS=['QUALITY_RESOURCE_LIMIT','QUALITY_TARGET_STALE','QUALITY_TARGET_UNSUPPORTED','QUALITY_SOURCE_FAILED','QUALITY_DEADLINE_EXCEEDED','QUALITY_AUTHORITY_REVOKED','QUALITY_ATTEMPTS_EXHAUSTED','QUALITY_CANCELLED','QUALITY_REFERENCE_UNAVAILABLE'] as const;
export type QualityError=typeof QUALITY_ERRORS[number];
export interface QualityRuleView {id:string;version:number;currentVersion:number|null;definition:QualityRuleDefinition;definitionHash:string;createdAt:string;createdBy:string}
export interface QualityRunFields {
 id:string;ruleId:string;ruleVersion:number;ruleHash:string;requesterId:string;columnAssetId:string;tableAssetId:string;
 status:QualityStatus;version:number;attempt:number;createdAt:string;startedAt:string|null;finishedAt:string|null;expiresAt:string;
 measurement:QualityMeasurement|null;verdict:QualityVerdict|null;errorCode:QualityError|null;
}
export type QualityRunView=QualityRunFields & ({kind?:never;reference?:never}|{kind:'reference-allowed-values';reference:QualityReferenceMetadata}|{kind:'uniqueness';reference?:never});
export interface QualityPageQuery {limit?:number;cursor?:string}
export interface QualityPage<T>{items:T[];nextCursor:string|null}
export interface QualityAssetView extends QualityPage<QualityRuleView>{
 assetId:string;eligibility:{supported:boolean;reason:string|null;tableAssetId:string|null;columnAssetId:string|null};
}
export interface QualityPublishInput {id:string;expectedVersion:number;definition:QualityRuleDefinition}
export interface QualityRunInput {id:string;ruleVersion:number;ruleHash:string;referenceAsOf?:string}
export interface QualityWorkflowInput {tenantId:string;runId:string}
export interface QualitySource {connectorId:'postgresql';host:string;port:number;database:string;schema:string;secretRef:string}
export type QualityClaim={status:'claimed';runId:string;claimId:string;attempt:number;leaseExpiresAt:string;source:QualitySource;execution:QualityExecution}
 |{status:'busy';retryAt:string}|{status:'terminal';run:QualityRunView};
export type QualityCompletion={claimId:string;attempt:number;measurement:QualityMeasurement}|{claimId:string;attempt:number;errorCode:QualityError};
