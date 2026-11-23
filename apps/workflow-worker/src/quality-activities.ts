// SPDX-License-Identifier: Apache-2.0
import {createQualityTransport} from './quality-http.ts';
import {parseQualityWorkflowInput,qualityObject,qualityId} from '../../../packages/domain/src/quality.ts';
import type {QualityWorkflowInput,QualityStatus} from '../../../packages/domain/src/quality-contracts.ts';
/** Only these sanitized IDs/statuses/timers cross into workflow history. */
export interface QualityActivityResult {runId:string;status:QualityStatus|'busy';version:number|null;retryAt:string|null}
export function createQualityDispatcher(config:{apiUrl:string;token:string;fetch?:typeof fetch}){
 const request=createQualityTransport({url:config.apiUrl,token:config.token,fetch:config.fetch});
 return {async pendingQuality(tenantId:string):Promise<QualityWorkflowInput[]>{
  try{qualityId(tenantId);const response=await request('/internal/quality-runs/pending',{tenantId,maximum:16384,timeoutMs:10000});if(response.status!==200)throw 0;
   const body=qualityObject(response.body,['items']);if(!Array.isArray(body.items)||body.items.length>50)throw 0;
   const seen=new Set<string>();return body.items.map(item=>{const input=parseQualityWorkflowInput(item);if(input.tenantId!==tenantId||seen.has(input.runId))throw 0;seen.add(input.runId);return input;});
  }catch{throw new Error('QUALITY_DISPATCH_FAILED');}
 }};
}
