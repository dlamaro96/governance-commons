// SPDX-License-Identifier: Apache-2.0
import {randomUUID} from 'node:crypto';
import {createQualityTransport} from '../../workflow-worker/src/quality-http.ts';
import {parseQualityWorkflowInput,parseQualityClaim,parseQualityRunView,parseQualityMeasurement,qualityFreshnessVerdict,qualityObject} from '../../../packages/domain/src/quality.ts';
import type {QualityWorkflowInput,QualityError,QualityCompletion,QualityRunView} from '../../../packages/domain/src/quality-contracts.ts';
import type {QualityActivityResult} from '../../workflow-worker/src/quality-activities.ts';
const terminal=(run:QualityRunView):QualityActivityResult=>{
 if(!['succeeded','failed','cancelled'].includes(run.status))throw new Error('QUALITY_SITE_PROTOCOL_INVALID');
 return {runId:run.id,status:run.status,version:run.version,retryAt:null};
};
export function createQualityActivity(config:{apiUrl:string;apiToken:string;workerUrl:string;workerToken:string;tenants:ReadonlySet<string>;fetch?:typeof fetch;claimId?:()=>string}){
 const api=createQualityTransport({url:config.apiUrl,token:config.apiToken,fetch:config.fetch});
 const worker=createQualityTransport({url:config.workerUrl,token:config.workerToken,fetch:config.fetch});
 return async function executeQuality(raw:QualityWorkflowInput):Promise<QualityActivityResult>{
  try{
   const input=parseQualityWorkflowInput(raw);if(!config.tenants.has(input.tenantId))throw 0;
   const claimId=(config.claimId??randomUUID)();
   const response=await api(`/internal/quality-runs/${input.runId}/claim`,{tenantId:input.tenantId,body:{claimId},timeoutMs:35000,maximum:65536});
   if(response.status!==200)throw 0;const claim=parseQualityClaim(response.body);
   if(claim.status==='terminal'){if(claim.run.id!==input.runId)throw 0;return terminal(claim.run);}
   if(claim.status==='busy')return {runId:input.runId,status:'busy',version:null,retryAt:claim.retryAt};
   if(claim.runId!==input.runId||claim.claimId!==claimId)throw 0;
   // Never send a stale lease to the source. Canonical completion checks the
   // lease, attempt fence, current requester and current target authority again.
   let completion:QualityCompletion;
   if(Date.parse(claim.leaseExpiresAt)<Date.now()+40000)completion={claimId,attempt:claim.attempt,errorCode:'QUALITY_DEADLINE_EXCEEDED'};
   else{
    try{
     const result=await worker('/quality',{body:{tenantId:input.tenantId,source:claim.source,execution:claim.execution},timeoutMs:40000,maximum:32768});
     if(result.status===200){const body=qualityObject(result.body,['measurement']),measurement=parseQualityMeasurement(body.measurement);
      if(measurement.kind!==claim.execution.kind||measurement.kind==='reference-allowed-values'&&(claim.execution.kind!=='reference-allowed-values'||measurement.referenceBindingHash!==claim.execution.reference.bindingHash)||measurement.kind==='range'&&(claim.execution.kind!=='range'||measurement.rangeHash!==claim.execution.range.rangeHash))throw 0;
      if(measurement.kind==='freshness'){if(claim.execution.kind!=='freshness')throw 0;qualityFreshnessVerdict(measurement,claim.execution.freshness);}
      completion={claimId,attempt:claim.attempt,measurement};}
     else {const body=qualityObject(result.body,['code']);let code:QualityError='QUALITY_SOURCE_FAILED';
      if(['QUALITY_RESOURCE_LIMIT','QUALITY_TARGET_STALE','QUALITY_TARGET_UNSUPPORTED','QUALITY_DEADLINE_EXCEEDED'].includes(body.code as string))code=body.code as QualityError;
      else if(body.code==='QUALITY_CLOCK_SKEW'&&claim.execution.kind==='freshness')code='QUALITY_CLOCK_SKEW';
      else if(body.code==='SOURCE_DEADLINE_EXCEEDED'||body.code==='SOURCE_TIMEOUT')code='QUALITY_DEADLINE_EXCEEDED';
      completion={claimId,attempt:claim.attempt,errorCode:code};}
    }catch{completion={claimId,attempt:claim.attempt,errorCode:'QUALITY_SOURCE_FAILED'};}
   }
   const finished=await api(`/internal/quality-runs/${input.runId}/finish`,{tenantId:input.tenantId,body:completion,timeoutMs:35000,maximum:16384});
   if(finished.status!==200)throw 0;const run=parseQualityRunView(qualityObject(finished.body,['run']).run);if(run.id!==input.runId||(claim.execution.kind==='freshness'?run.kind!=='freshness'||run.freshness.freshnessHash!==claim.execution.freshness.freshnessHash:claim.execution.kind==='range'?run.kind!=='range'||run.range.rangeHash!==claim.execution.range.rangeHash:claim.execution.kind==='reference-allowed-values'?run.kind!=='reference-allowed-values'||run.reference.bindingHash!==claim.execution.reference.bindingHash:run.kind!==(claim.execution.kind==='uniqueness'?'uniqueness':undefined)))throw 0;return terminal(run);
  }catch{
   // No private source, measurements, secrets, remote response or exception can
   // enter the durable history. Retry obtains a fresh canonical claim or busy.
   throw new Error('QUALITY_SITE_UNAVAILABLE');
  }
 };
}
