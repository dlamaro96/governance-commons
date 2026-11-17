// SPDX-License-Identifier: Apache-2.0
// ROOT-ADOPTED PRIVATE CONTRACT: not implemented or runtime-authority activation.
// All objects are closed own-data records; wire parsers must enforce the bounds below.
export type MonitorId = string; // canonical lower-case UUID
export type MonitorHash = string; // lower-case SHA-256 over existing canonical JSON
export type MonitorInstant = string; // real UTC YYYY-MM-DDTHH:mm:ss.sssZ; no coercion
export type QualityFamily = 'completeness'|'reference-allowed-values'|'uniqueness'|'range'|'freshness';
export interface MonitorRulePin {id:MonitorId;version:number;definitionHash:MonitorHash}
export const MONITOR_LIMITS = Object.freeze({
  definitionBytes:32768, textName:240, textPurpose:4096, textReason:4096,
  minimumIntervalSeconds:60, maximumIntervalSeconds:604800,
  maximumWindows:32, maximumRecipients:16, maximumAuthorizationSeconds:2678400,
  maximumRecoveryAgeSeconds:604800, maximumSlaSeconds:2678400,
  pageDefault:25, pageMaximum:100, workPageMaximum:50,
  maximumEnabledPerTenant:100, maximumScheduledActivePerTenant:8,
  maximumScheduledActivePerSource:2,
} as const);
export interface MonitorWindow {from:MonitorInstant;until:MonitorInstant} // half-open, sorted/disjoint per array
export interface FixedUtcSchedule {
  kind:'fixed-interval';timeZone:'UTC';startsAt:MonitorInstant;endsAt:MonitorInstant|null;
  intervalSeconds:number;lateGraceSeconds:number; // grace 0..min(intervalSeconds-1,300)
  missedSlots:'skip';overlap:'skip'; // current observations; never historical source backfill
}
export interface QualityMonitorDefinition {
  formatVersion:1;name:string;purpose:string;rule:MonitorRulePin;
  executorId:MonitorId; // immutable; equals authenticated author, never caller-selected delegation
  authorizationExpiresAt:MonitorInstant;
  schedule:FixedUtcSchedule;maintenance:MonitorWindow[];silences:MonitorWindow[];
  routing:{channel:'in-app';ownerId:MonitorId;recipientIds:MonitorId[]}; // sorted unique, owner included
  issue:{category:'data-quality';acknowledgeWithinSeconds:number;resolveWithinSeconds:number};
  recoveryMaximumAgeSeconds:number;
  retry:{policy:'quality-run-v1'}; // existing run: max3 attempts,120s lease,600s lifetime; no extra retry loops
}
export type MonitorState = 'enabled'|'paused'|'retired';
export type MonitorBlock = 'RULE_VERSION_CHANGED'|'AUTHORIZATION_EXPIRED'|'EXECUTOR_UNAVAILABLE'
  |'RULE_OWNER_UNAVAILABLE'|'TARGET_UNAVAILABLE'|'REFERENCE_UNAVAILABLE';
export interface MonitorDefinitionPin {monitorId:MonitorId;definitionVersion:number;definitionHash:MonitorHash}
export interface MonitorRunEvidence {
  occurrenceId:MonitorId;ordinal:number;runId:MonitorId;runVersion:number;completionHash:MonitorHash;
  comparisonScopeHash:MonitorHash;observedFinishedAt:MonitorInstant;
}
export type MonitorObservation =
  |{state:'unobserved'}
  |{state:'pending';occurrenceId:MonitorId;runId:MonitorId}
  |{state:'conclusive';verdict:'PASS'|'FAIL';evidence:MonitorRunEvidence}
  |{state:'unknown';reason:'NO_DATA'|'EXECUTION_FAILED'|'CANCELLED'|'SKIPPED'|'STALE'|'BLOCKED';occurrenceId:MonitorId|null};
export interface QualityMonitorView {
  id:MonitorId;revision:number;definitionVersion:number;definitionHash:MonitorHash;
  definition:QualityMonitorDefinition;state:MonitorState;blocked:MonitorBlock|null;
  nextSlotAt:MonitorInstant|null;lastAdmittedOrdinal:number;lastProjectedOrdinal:number;
  currentObservation:MonitorObservation;
  lastConclusive:{verdict:'PASS'|'FAIL';evidence:MonitorRunEvidence}|null;
  createdAt:MonitorInstant;createdBy:MonitorId;
}
// revision guards human mutations only; dispatcher cursors/observation updates do not consume it.
export interface PublishMonitorInput {id:MonitorId;expectedRevision:number;definition:QualityMonitorDefinition}
export interface MonitorStateInput {expectedRevision:number;action:'pause'|'resume'|'retire';reason:string}
export interface MonitorDefinitionView extends MonitorDefinitionPin {
  definition:QualityMonitorDefinition;createdAt:MonitorInstant;createdBy:MonitorId;
}
export interface MonitorSlotRange {firstAt:MonitorInstant;lastAt:MonitorInstant;count:number}
export type MonitorSkip = 'MISSED'|'MAINTENANCE'|'OVERLAP'|'CAPACITY'|'PAUSED'|MonitorBlock;
export type QualityOccurrence = MonitorDefinitionPin & {
  id:MonitorId;ordinal:number;rule:MonitorRulePin;executorId:MonitorId;
  origin:'schedule'|'recovery-request';slots:MonitorSlotRange|null;recordedAt:MonitorInstant;
} & (
  {disposition:'skipped';reason:MonitorSkip;runId:null;comparisonScopeHash:null}
  |{disposition:'enqueued';reason:null;runId:MonitorId;comparisonScopeHash:MonitorHash}
);
// Internal hash preimage only. No codes, credentials, source configuration, or native target
// names are added to public monitor/issue DTOs. Source config hash covers the existing inputs.
export interface QualityComparisonScope {
  formatVersion:1;monitorId:MonitorId;executorId:MonitorId;rule:MonitorRulePin;
  sourceId:MonitorId;sourceVersion:number;sourceConfigHash:MonitorHash;
  schemaAssetId:MonitorId;tableAssetId:MonitorId;columnAssetId:MonitorId;
  targetHash:MonitorHash; // canonical execution.target, including physical IDs and native type
  family: {kind:'completeness'}
    |{kind:'uniqueness';comparison:'utf8-exact';nullPolicy:'exclude'}
    |{kind:'range';rangeHash:MonitorHash}
    |{kind:'freshness';freshnessHash:MonitorHash} // immutable settings hash; clocks/age are observations, not scope
    |{kind:'reference-allowed-values';setId:MonitorId;version:number;publicationHash:MonitorHash;
      codeStatus:'active';codesHash:MonitorHash}; // exact sorted effective codes; EXCLUDES asOf only
}
export type QualityIssueStatus = 'open'|'acknowledged'|'resolved'|'superseded';
export interface QualityIssueView {
  id:MonitorId;version:number;monitorId:MonitorId;comparisonScopeHash:MonitorHash;rule:MonitorRulePin;
  category:'data-quality';severity:'info'|'warning'|'critical';tableAssetId:MonitorId;columnAssetId:MonitorId;
  status:QualityIssueStatus;episode:number;assignedOwnerId:MonitorId;ownerAvailable:boolean;
  openedAt:MonitorInstant;acknowledgeDueAt:MonitorInstant;resolveDueAt:MonitorInstant;
  opening:MonitorRunEvidence;lastFailure:MonitorRunEvidence;
  recovery:MonitorRunEvidence|null; // derived eligible evidence, not an asserted healthy flag
  resolution:{rootCause:string;remediation:string;reason:string;evidence:MonitorRunEvidence;at:MonitorInstant;by:MonitorId}|null;
  superseded:{reason:string;replacementMonitorId:MonitorId;replacementDefinitionVersion:number;at:MonitorInstant;by:MonitorId}|null;
}
export interface IssueVersionInput {expectedVersion:number;reason:string}
export interface AssignQualityIssueInput extends IssueVersionInput {ownerId:MonitorId}
export interface ResolveQualityIssueInput extends IssueVersionInput {
  recoveryOccurrenceId:MonitorId;recoveryRunId:MonitorId;recoveryRunVersion:number;
  rootCause:string;remediation:string;
}
export interface SupersedeQualityIssueInput extends IssueVersionInput {
  replacementMonitorId:MonitorId;replacementDefinitionVersion:number;
}
export interface RequestQualityRecoveryInput extends IssueVersionInput {id:MonitorId} // requested occurrence UUID
export interface QualityIssueEvent {
  id:MonitorId;issueId:MonitorId;version:number;episode:number;
  kind:'opened'|'failed-again'|'acknowledged'|'assigned'|'recovery-available'|'recovery-invalidated'|'resolved'|'reopened'|'superseded';
  monitor:MonitorDefinitionPin;occurrenceId:MonitorId|null;runId:MonitorId|null;
  actorId:MonitorId|'site:local';at:MonitorInstant;reason:string|null;
  resolution:QualityIssueView['resolution']; // nonnull iff resolved; immutable prior evidence/details remain readable after reopening
}
export interface QualityNotification {
  id:MonitorId;eventId:MonitorId;issueId:MonitorId;recipientId:MonitorId;
  template:'quality-issue-opened-v1'|'quality-issue-reopened-v1'|'quality-issue-assigned-v1'
    |'quality-recovery-available-v1'|'quality-issue-resolved-v1';
  createdAt:MonitorInstant;readAt:MonitorInstant|null;version:number;
  // IDs/template only; localized text is hydrated after current authorization, never copied source rows.
}
export interface MonitoringPageQuery {limit?:number;cursor?:string}
export interface MonitoringPage<T> {items:T[];nextCursor:string|null} // no pre-authorization total
export interface MonitorListQuery extends MonitoringPageQuery {ruleId?:MonitorId;state?:MonitorState}
export interface QualityIssueListQuery extends MonitoringPageQuery {monitorId?:MonitorId;status?:QualityIssueStatus;assignedToMe?:boolean}
export interface MonitoringWorkItem {tenantId:MonitorId;monitorId:MonitorId;work:'tick'|'reconcile'}
export interface MonitoringWorkResult {
  monitorId:MonitorId;state:'idle'|'advanced'|'blocked'|'retry';nextWakeAt:MonitorInstant|null;
  occurrenceId:MonitorId|null;runId:MonitorId|null;
}
// Adopted action names for explicit registry implementation, NOT implicit new grants.
export const QUALITY_MONITOR_ACTIONS = [
  'quality.monitor.read','quality.monitor.publish','quality.monitor.pause','quality.monitor.resume','quality.monitor.retire',
  'quality.occurrence.read','quality.issue.read','quality.issue.acknowledge','quality.issue.assign','quality.issue.resolve',
  'quality.issue.supersede','quality.issue.recovery.request','quality.notification.read','quality.notification.mark-read',
  'quality.monitor.tick','quality.monitor.reconcile',
] as const;
export type QualityMonitorAction = typeof QUALITY_MONITOR_ACTIONS[number];
