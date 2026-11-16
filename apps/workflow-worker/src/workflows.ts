// SPDX-License-Identifier: Apache-2.0
import { ApplicationFailure, condition, continueAsNew, defineSignal, isCancellation, proxyActivities, setHandler, sleep, workflowInfo } from '@temporalio/workflow';
import type {ApprovalInput,ApprovalTick} from './approval-activities.ts';
export interface ScanInput { tenantId: string; jobId: string }
const { executeScan } = proxyActivities<{ executeScan(input: ScanInput): Promise<{ status: string; assetCount?: number }> }>({
  taskQueue: 'gc-site', startToCloseTimeout: '3 minutes', scheduleToCloseTimeout: '20 minutes',
  retry: { initialInterval: '2 seconds', maximumInterval: '30 seconds', maximumAttempts: 5 },
});
export async function scanSourceWorkflow(input: ScanInput): Promise<{ status: string; assetCount?: number }> {
  // IDs only in Temporal history; metadata and credentials stay at the execution site.
  return executeScan(input);
}

const approvalIds=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const approvalChanged=defineSignal<[eventId:string]>('approvalChanged');
const {tickApproval}=proxyActivities<{tickApproval(input:ApprovalInput):Promise<ApprovalTick>}>({
  startToCloseTimeout:'50 seconds',scheduleToCloseTimeout:'3 minutes',
  retry:{initialInterval:'1 second',maximumInterval:'10 seconds',maximumAttempts:4},
});
/** Initial approval family only. The canonical transaction owns all decisions
 * and resource effects. In particular ready is not publication or success. */
export async function approvalWorkflow(input:ApprovalInput):Promise<ApprovalTick>{
  if(!input||Object.keys(input).length!==2||typeof input.tenantId!=='string'||typeof input.requestId!=='string'||!approvalIds.test(input.tenantId)||!approvalIds.test(input.requestId))
    throw ApplicationFailure.nonRetryable('APPROVAL_INPUT_INVALID');
  let changed=false,signals=0,checks=0;
  setHandler(approvalChanged,(eventId)=>{if(typeof eventId==='string'&&approvalIds.test(eventId)){changed=true;signals++;}});
  for(;;){
    changed=false;let wait=60_000;
    try{
      const current=await tickApproval({tenantId:input.tenantId,requestId:input.requestId});
      if(current.status!=='pending')return current;
      wait=Math.max(1,Math.min(60_000,Date.parse(current.nextWakeAt!)-Date.now()));
    }catch(error){
      if(isCancellation(error))throw error;
      // Transient transport/protocol failure never advances or completes approval.
      // Durable timer retries survive worker restarts and authorization changes.
    }
    checks++;
    if(checks>=256||signals>=256||workflowInfo().continueAsNewSuggested||workflowInfo().historyLength>=2048)
      return continueAsNew<typeof approvalWorkflow>({tenantId:input.tenantId,requestId:input.requestId});
    await condition(()=>changed,wait);
  }
}


import type {QualityWorkflowInput} from '../../../packages/domain/src/quality-contracts.ts';
import type {QualityActivityResult} from './quality-activities.ts';
const {executeQuality}=proxyActivities<{executeQuality(input:QualityWorkflowInput):Promise<QualityActivityResult>}>({
 taskQueue:'gc-site',startToCloseTimeout:'115 seconds',scheduleToCloseTimeout:'3 minutes',retry:{maximumAttempts:1},
});
export async function qualityWorkflow(input:QualityWorkflowInput):Promise<QualityActivityResult>{
 if(!input||Object.keys(input).length!==2||typeof input.tenantId!=='string'||typeof input.runId!=='string'||!approvalIds.test(input.tenantId)||!approvalIds.test(input.runId))
  throw ApplicationFailure.nonRetryable('QUALITY_INPUT_INVALID');
 let checks=0;
 for(;;){
  let wait=5000;
  try{const result=await executeQuality({tenantId:input.tenantId,runId:input.runId});
   if(result.status==='succeeded'||result.status==='failed'||result.status==='cancelled')return result;
   if(result.status==='busy'&&result.retryAt!==null)wait=Math.max(1000,Math.min(10000,Date.parse(result.retryAt)-Date.now()));
  }catch(error){if(isCancellation(error))throw error;}
  // Canonical storage owns the 600-second lifetime and attempt ceiling. A
  // transport outage cannot be translated into a false canonical completion.
  if(++checks>=128||workflowInfo().continueAsNewSuggested||workflowInfo().historyLength>=1024)
   return continueAsNew<typeof qualityWorkflow>({tenantId:input.tenantId,runId:input.runId});
  await sleep(wait);
 }
}
