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
export interface RangeRuleDefinition {
 formatVersion:1;kind:'range';target:{tableAssetId:string;columnAssetId:string};
 name:string;purpose:string;ownerId:string;severity:'info'|'warning'|'critical';maximumOutOfRangeBasisPoints:number;
 minimum:string;maximum:string;comparison:'int64-inclusive';nullPolicy:'exclude';
}
export interface QualityRangeBinding {minimum:string;maximum:string;comparison:'int64-inclusive';nullPolicy:'exclude';rangeHash:string}
/** Real Gregorian UTC timestamp, year0001..9999, exactly six fractional digits.
 * Convert calendar seconds and microseconds separately; Date.parse(value) loses
 * evidence precision and MUST NOT decide freshness or construct an age. */
export type QualityMicroInstant=string; // YYYY-MM-DDTHH:mm:ss.ffffffZ
/** Canonical signed base10 integer: no plus, leading zero, -0 or exponent.
 * Range -315537897599999999..315537897599999999; JSON string, not number. */
export type QualityAgeMicroseconds=string;
export const QUALITY_FRESHNESS_LIMITS=Object.freeze({
 minimumAgeSeconds:1, maximumAgeSeconds:31536000, // fixed365*86400; not a calendar year
 maximumFutureSkewSeconds:300, sourceWorkerClockAllowanceMs:5000,
 minimumEpochMicroseconds:'-62135596800000000',
 maximumEpochMicroseconds:'253402300799999999',
 maximumAbsoluteAgeMicroseconds:'315537897599999999',
} as const);
export interface QualityFreshnessSettings {
 maximumAgeSeconds:number; // integer1..31536000
 maximumFutureSkewSeconds:number; // integer0..300; UI default0
 comparison:'latest-timestamptz';clock:'source-statement-start';
 nullPolicy:'exclude';invalidTimestampPolicy:'fail';
}
export interface FreshnessRuleDefinition extends QualityFreshnessSettings {
 formatVersion:1;kind:'freshness';target:{tableAssetId:string;columnAssetId:string};
 name:string;purpose:string;ownerId:string;severity:'info'|'warning'|'critical';
}
/** Static settings are derived from the exact immutable rule, never from the
 * worker or caller. The source clock is measured, not included in this hash. */
export interface QualityFreshnessBinding extends QualityFreshnessSettings {freshnessHash:string}
export interface FreshnessExecution {
 formatVersion:1;kind:'freshness';target:QualityTarget;budget:QualityBudget;
 freshness:QualityFreshnessBinding;
}
export interface FreshnessMeasurement {
 formatVersion:1;kind:'freshness';strategy:'exact-bounded-role-scope';
 rowCount:number;nullCount:number;nonFiniteCount:number;unrepresentableCount:number;futureCount:number;
 sourceObservedAt:QualityMicroInstant;
 // MAX over finite timestamps in the representable interval, INCLUDING future
 // values. Null iff no such values exist. Invalid rows cannot be hidden by MAX.
 latestObservedAt:QualityMicroInstant|null;
 ageMicroseconds:QualityAgeMicroseconds|null; // sourceObservedAt-latestObservedAt
 freshnessHash:string;
 // Existing worker wall-clock observation envelope, still UTC millisecond precision.
 observedStartedAt:string;observedFinishedAt:string;elapsedMs:number;
 sourceVersion:string;adapterVersion:'1';queryTemplate:'postgresql-freshness-v1';
 estimatedCost:number;estimatedBytes:number;
}

/** Volume is a table family: no invented column identity or null-count metric.
 * Authored maximumRows is a verdict threshold. Only execution.budget.maximumRows
 * bounds the query/overflow probe: six rows/max5 is FAIL; 100001 is RESOURCE_LIMIT. */
export const QUALITY_VOLUME_LIMITS=Object.freeze({minimumRows:0,maximumRows:100000} as const);
export interface QualityVolumeSettings {
 minimumRows:number;maximumRows:number;comparison:'row-count-inclusive';scope:'entire-table';
}
export interface VolumeRuleDefinition extends QualityVolumeSettings {
 formatVersion:1;kind:'volume';target:{kind:'table';tableAssetId:string};
 name:string;purpose:string;ownerId:string;severity:'info'|'warning'|'critical';
}
/** Static canonical hash preimage: {formatVersion:1,kind:'volume',...settings}.
 * No target/clock/count is included; full definition/input hashes retain those pins. */
export interface QualityVolumeBinding extends QualityVolumeSettings {volumeHash:string}
export interface QualityTableTarget {
 kind:'table';databaseOid:string;schemaOid:string;relationOid:string;schemaName:string;tableName:string;
}
export interface VolumeExecution {
 formatVersion:1;kind:'volume';target:QualityTableTarget;budget:QualityBudget;volume:QualityVolumeBinding;
}
export interface VolumeMeasurement {
 formatVersion:1;kind:'volume';strategy:'exact-bounded-role-scope';rowCount:number;volumeHash:string;
 observedStartedAt:string;observedFinishedAt:string;elapsedMs:number;sourceVersion:string;adapterVersion:'1';
 queryTemplate:'postgresql-volume-v1';estimatedCost:number;estimatedBytes:number;
}

export type QualityRuleDefinition=CompletenessRuleDefinition|ReferenceAllowedValuesRuleDefinition|UniquenessRuleDefinition|RangeRuleDefinition|FreshnessRuleDefinition|VolumeRuleDefinition;
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
 |{formatVersion:1;kind:'uniqueness';target:QualityTarget;budget:QualityUniquenessBudget}
 |{formatVersion:1;kind:'range';target:QualityTarget;budget:QualityBudget;range:QualityRangeBinding}
 |FreshnessExecution|VolumeExecution;
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
export interface RangeMeasurement {
 formatVersion:1;kind:'range';strategy:'exact-bounded-role-scope';rowCount:number;nullCount:number;belowCount:number;aboveCount:number;rangeHash:string;
 observedStartedAt:string;observedFinishedAt:string;elapsedMs:number;sourceVersion:string;adapterVersion:'1';
 queryTemplate:'postgresql-range-v1';estimatedCost:number;estimatedBytes:number;
}
export type QualityMeasurement=CompletenessMeasurement|ReferenceAllowedValuesMeasurement|UniquenessMeasurement|RangeMeasurement|FreshnessMeasurement|VolumeMeasurement;
export type QualityStatus='queued'|'running'|'succeeded'|'failed'|'cancelled';
export type QualityVerdict='PASS'|'FAIL'|'NO_DATA';
export const QUALITY_ERRORS=['QUALITY_RESOURCE_LIMIT','QUALITY_TARGET_STALE','QUALITY_TARGET_UNSUPPORTED','QUALITY_SOURCE_FAILED','QUALITY_DEADLINE_EXCEEDED','QUALITY_AUTHORITY_REVOKED','QUALITY_ATTEMPTS_EXHAUSTED','QUALITY_CANCELLED','QUALITY_REFERENCE_UNAVAILABLE','QUALITY_CLOCK_SKEW'] as const;
export type QualityError=typeof QUALITY_ERRORS[number];
export interface QualityRuleView {id:string;version:number;currentVersion:number|null;definition:QualityRuleDefinition;definitionHash:string;createdAt:string;createdBy:string}
export interface QualityRunFields {
 id:string;ruleId:string;ruleVersion:number;ruleHash:string;requesterId:string;columnAssetId:string;tableAssetId:string;
 status:QualityStatus;version:number;attempt:number;createdAt:string;startedAt:string|null;finishedAt:string|null;expiresAt:string;
 measurement:QualityMeasurement|null;verdict:QualityVerdict|null;errorCode:QualityError|null;
}
export type QualityColumnRunView=Omit<QualityRunFields,'measurement'> & {measurement:Exclude<QualityMeasurement,VolumeMeasurement>|null} & ({kind?:never;volume?:never;reference?:never;range?:never;freshness?:never}|{kind:'reference-allowed-values';volume?:never;reference:QualityReferenceMetadata;range?:never;freshness?:never}|{kind:'uniqueness';volume?:never;reference?:never;range?:never;freshness?:never}|{kind:'range';volume?:never;range:QualityRangeBinding;reference?:never;freshness?:never;measurement:RangeMeasurement|null}|{kind:'freshness';volume?:never;freshness:QualityFreshnessBinding;reference?:never;range?:never;measurement:FreshnessMeasurement|null});
export type VolumeRunView=Omit<QualityRunFields,'columnAssetId'|'measurement'|'verdict'> & {
 kind:'volume';columnAssetId:null;volume:QualityVolumeBinding;measurement:VolumeMeasurement|null;
 verdict:'PASS'|'FAIL'|null;reference?:never;range?:never;freshness?:never;
};
export type QualityRunView=QualityColumnRunView|VolumeRunView;
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
