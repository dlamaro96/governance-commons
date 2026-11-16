// SPDX-License-Identifier: Apache-2.0
/** Closed first execution family. Other quality families remain separate capabilities. */
export interface CompletenessRuleDefinition {
 formatVersion:1;kind:'completeness';target:{tableAssetId:string;columnAssetId:string};
 name:string;purpose:string;ownerId:string;severity:'info'|'warning'|'critical';maximumNullBasisPoints:number;
}
export interface QualityTarget {
 databaseOid:string;schemaOid:string;relationOid:string;attributeNumber:number;
 schemaName:string;tableName:string;columnName:string;dataType:string;
}
export interface QualityBudget {maximumRows:number;maximumSeconds:number;statementTimeoutMs:number;maximumEstimatedCost:number;maximumEstimatedBytes:number}
export const QUALITY_BUDGET:Readonly<QualityBudget>=Object.freeze({maximumRows:100000,maximumSeconds:30,statementTimeoutMs:15000,maximumEstimatedCost:1000000,maximumEstimatedBytes:67108864});
export interface QualityExecution {formatVersion:1;kind:'completeness';target:QualityTarget;budget:QualityBudget}
export interface QualityMeasurement {
 formatVersion:1;kind:'completeness';strategy:'exact-bounded-role-scope';rowCount:number;nullCount:number;
 observedStartedAt:string;observedFinishedAt:string;elapsedMs:number;sourceVersion:string;adapterVersion:'1';
 queryTemplate:'postgresql-completeness-v1';estimatedCost:number;estimatedBytes:number;
}
export type QualityStatus='queued'|'running'|'succeeded'|'failed'|'cancelled';
export type QualityVerdict='PASS'|'FAIL'|'NO_DATA';
export const QUALITY_ERRORS=['QUALITY_RESOURCE_LIMIT','QUALITY_TARGET_STALE','QUALITY_TARGET_UNSUPPORTED','QUALITY_SOURCE_FAILED','QUALITY_DEADLINE_EXCEEDED','QUALITY_AUTHORITY_REVOKED','QUALITY_ATTEMPTS_EXHAUSTED','QUALITY_CANCELLED'] as const;
export type QualityError=typeof QUALITY_ERRORS[number];
export interface QualityRuleView {id:string;version:number;currentVersion:number;definition:CompletenessRuleDefinition;definitionHash:string;createdAt:string;createdBy:string}
export interface QualityRunView {
 id:string;ruleId:string;ruleVersion:number;ruleHash:string;requesterId:string;columnAssetId:string;tableAssetId:string;
 status:QualityStatus;version:number;attempt:number;createdAt:string;startedAt:string|null;finishedAt:string|null;expiresAt:string;
 measurement:QualityMeasurement|null;verdict:QualityVerdict|null;errorCode:QualityError|null;
}
export interface QualityPageQuery {limit?:number;cursor?:string}
export interface QualityPage<T>{items:T[];nextCursor:string|null}
export interface QualityAssetView extends QualityPage<QualityRuleView>{
 assetId:string;eligibility:{supported:boolean;reason:string|null;tableAssetId:string|null;columnAssetId:string|null};
}
export interface QualityPublishInput {id:string;expectedVersion:number;definition:CompletenessRuleDefinition}
export interface QualityRunInput {id:string;ruleVersion:number;ruleHash:string}
export interface QualityWorkflowInput {tenantId:string;runId:string}
export interface QualitySource {connectorId:'postgresql';host:string;port:number;database:string;schema:string;secretRef:string}
export type QualityClaim={status:'claimed';runId:string;claimId:string;attempt:number;leaseExpiresAt:string;source:QualitySource;execution:QualityExecution}
 |{status:'busy';retryAt:string}|{status:'terminal';run:QualityRunView};
export type QualityCompletion={claimId:string;attempt:number;measurement:QualityMeasurement}|{claimId:string;attempt:number;errorCode:QualityError};
