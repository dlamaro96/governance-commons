// SPDX-License-Identifier: Apache-2.0
import {createQualityTransport} from './quality-http.ts';
import {qualityId,qualityObject} from '../../../packages/domain/src/quality.ts';
import type {MonitoringWorkItem,MonitoringWorkResult} from '../../../packages/domain/src/quality-monitoring-contracts.ts';

function readId(value:unknown):string{qualityId(value);return value;}

function workItem(value:unknown):MonitoringWorkItem{
 const o=qualityObject(value,['tenantId','monitorId','work']);
 const tenantId=readId(o.tenantId),monitorId=readId(o.monitorId);
 if(o.work!=='tick'&&o.work!=='reconcile')throw 0;
 return {tenantId,monitorId,work:o.work};
}
function workResult(value:unknown,monitorId:string):MonitoringWorkResult{
 const o=qualityObject(value,['monitorId','state','nextWakeAt','occurrenceId','runId']);
 if(readId(o.monitorId)!==monitorId||!['idle','advanced','blocked','retry'].includes(o.state as string))throw 0;
 if(o.nextWakeAt!==null&&(typeof o.nextWakeAt!=='string'||!/^(?!0000)\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(o.nextWakeAt)||!Number.isFinite(Date.parse(o.nextWakeAt))||new Date(o.nextWakeAt).toISOString()!==o.nextWakeAt))throw 0;
 const occurrenceId=o.occurrenceId===null?null:readId(o.occurrenceId),runId=o.runId===null?null:readId(o.runId);
 if(runId!==null&&occurrenceId===null)throw 0;
 return {monitorId,state:o.state as MonitoringWorkResult['state'],nextWakeAt:o.nextWakeAt as string|null,occurrenceId,runId};
}
/** DB-selected IDs only. Database time and atomic commands own due slots and
 * occurrence deduplication; this dispatcher neither observes source data nor
 * records a monitoring success after an unavailable/ambiguous HTTP outcome. */
export function createQualityMonitoringDispatcher(config:{apiUrl:string;token:string;fetch?:typeof fetch}){
 const request=createQualityTransport({url:config.apiUrl,token:config.token,fetch:config.fetch});
 const cursors=new Map<string,string>();
 const api={
  async pendingWork(tenantId:string):Promise<MonitoringWorkItem[]>{
   try{
    qualityId(tenantId);const response=await request('/internal/quality-monitors/work',{tenantId,maximum:16384,timeoutMs:10000});
    if(response.status!==200)throw 0;
    const body=qualityObject(response.body,['items']);if(!Array.isArray(body.items)||body.items.length>50)throw 0;
    const seen=new Set<string>();return body.items.map(value=>{
     const item=workItem(value),key=item.monitorId+':'+item.work;
     if(item.tenantId!==tenantId||seen.has(key))throw 0;seen.add(key);return item;
    });
   }catch{throw new Error('MONITOR_DISPATCH_FAILED');}
  },
  async dispatchWork(value:MonitoringWorkItem,timeoutMs=35000):Promise<MonitoringWorkResult>{
   try{
    if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>35000)throw 0;
    const input=workItem(value),response=await request('/internal/quality-monitors/'+input.monitorId+'/'+input.work,
     {tenantId:input.tenantId,body:{},maximum:16384,timeoutMs});
    if(response.status!==200)throw 0;return workResult(response.body,input.monitorId);
   }catch{throw new Error('MONITOR_DISPATCH_FAILED');}
  },
 };
 return {...api,async dispatchPass(tenantId:string,stopping:()=>boolean):Promise<void>{
  const deadline=performance.now()+45000;if(stopping())return;
  const items=await api.pendingWork(tenantId);if(stopping()||items.length===0)return;
  const key=(v:MonitoringWorkItem)=>v.monitorId+':'+v.work;
  const last=items.findIndex(v=>key(v)===cursors.get(tenantId));
  let failed=false;
  for(let n=0;n<Math.min(8,items.length);n++){
   const remaining=Math.floor(deadline-performance.now());if(stopping()||remaining<1)break;
   const input=items[(last+1+n)%items.length]!;cursors.set(tenantId,key(input));
   try{await api.dispatchWork(input,Math.min(35000,remaining));}catch{failed=true;}
  }
  // Preserve progress across repeated discovery of a failed head. This local
  // cursor grants no authority and never substitutes for durable DB ordinals.
  if(failed)throw new Error('MONITOR_DISPATCH_FAILED');
 }};
}
