// SPDX-License-Identifier: Apache-2.0
import type {ValidationResult} from './model.ts';

/** The initial executable approval family. Later workflow families have distinct
 * format versions; publishing them must never reinterpret a pinned instance. */
export interface ApprovalDefinition {
 readonly formatVersion:1;
 readonly id:string;
 readonly version:number;
 readonly name:string;
 readonly separationOfDuties:boolean;
 readonly stages:readonly ApprovalStageDefinition[];
}
export interface ApprovalStageDefinition {
 readonly id:string;
 readonly name:string;
 /** Assignment keys are bound to current tenant identities when submitted. */
 readonly assignments:readonly string[];
 readonly quorum:number;
 readonly deadlineSeconds:number;
 /** Any canonical rejection terminates this initial approval family. */
 readonly rejection:'any';
}
export interface ApprovalDecision {
 readonly taskId:string;
 readonly taskVersion:number;
 readonly assignedIdentityId:string;
 readonly actorId:string;
 readonly decision:'approve'|'reject';
 readonly reason:string;
}
export interface ApprovalTask {
 readonly id:string;
 readonly version:number;
 readonly assignment:string;
 /** Each stage's task set binds assignments to distinct identities for quorum. */
 readonly assignedIdentityId:string;
}
export type ApprovalStageOutcome='pending'|'approved'|'rejected'|'expired';
export interface ApprovalEvaluation {
 readonly outcome:ApprovalStageOutcome;
 readonly approvals:number;
 readonly pending:number;
}
export interface ApprovalStageInput {
 readonly stage:ApprovalStageDefinition;
 readonly requesterId:string;
 readonly separationOfDuties:boolean;
 readonly tasks:readonly ApprovalTask[];
 readonly decisions:readonly ApprovalDecision[];
 /** Instants are supplied by the canonical transaction, never the browser. */
 readonly now:number;
 readonly expiresAt:number;
}
export const APPROVAL_LIMITS=Object.freeze({stages:16,assignments:16,bytes:65_536,
 name:240,reason:4096,maxDeadlineSeconds:31_536_000});
export type ApprovalDefinitionParser=(input:unknown)=>ValidationResult<ApprovalDefinition>;
export type ApprovalStageEvaluator=(input:ApprovalStageInput)=>ValidationResult<ApprovalEvaluation>;
