// SPDX-License-Identifier: Apache-2.0
import {parseBoundedJSONEnvelope} from '../../../packages/domain/src/model.ts';

export interface ApprovalInput {tenantId:string;requestId:string}
export interface ApprovalDelivery extends ApprovalInput {eventId:string}
export type ApprovalStatus='pending'|'ready'|'rejected'|'cancelled'|'expired'|'succeeded'|'failed';
export interface ApprovalTick {id:string;status:ApprovalStatus;version:number;nextWakeAt:string|null}
export interface ApprovalProtocol {
  tickApproval(input:ApprovalInput):Promise<ApprovalTick>;
  approvalStatus(input:ApprovalInput):Promise<ApprovalTick>;
  pendingApprovals(tenantId:string):Promise<{items:ApprovalDelivery[]}>;
  ackApproval(input:ApprovalDelivery):Promise<void>;
}
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const STATUSES=new Set<ApprovalStatus>(['pending','ready','rejected','cancelled','expired','succeeded','failed']);
const object=(v:unknown):v is Record<string,unknown>=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const exact=(v:unknown,keys:readonly string[]):v is Record<string,unknown>=>object(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const uuid=(v:unknown):v is string=>typeof v==='string'&&UUID.test(v);
const invalid=()=>new Error('APPROVAL_PROTOCOL_INVALID');
function tick(value:unknown,id:string):ApprovalTick{
  if(!exact(value,['id','status','version','nextWakeAt'])||value.id!==id||!STATUSES.has(value.status as ApprovalStatus)||
    !Number.isInteger(value.version)||(value.version as number)<1||(value.version as number)>2_147_483_647||
    (value.status==='pending'?!instant(value.nextWakeAt):value.nextWakeAt!==null))throw invalid();
  return value as unknown as ApprovalTick;
}
function ids(input:ApprovalInput):void{if(!exact(input,['tenantId','requestId'])||!uuid(input.tenantId)||!uuid(input.requestId))throw invalid();}
function delivery(input:ApprovalDelivery):void{
  if(!exact(input,['tenantId','requestId','eventId'])||!uuid(input.tenantId)||!uuid(input.requestId)||!uuid(input.eventId))throw invalid();
}
function instant(value:unknown):value is string{
  if(typeof value!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value))return false;
  const parsed=Date.parse(value);return Number.isFinite(parsed)&&new Date(parsed).toISOString()===value;
}
/** Only canonical ID/status/version/timer envelopes may enter Temporal history.
 * Private API errors, task descriptions, decision reasons and tokens never do. */
export function createApprovalActivities(config:{apiUrl:string;token:string;fetch?:typeof fetch;timeoutMs?:number}):ApprovalProtocol{
  let url:URL;try{url=new URL(config.apiUrl);}catch{throw new Error('APPROVAL_CONFIG_INVALID');}
  const timeoutMs=config.timeoutMs??10_000;
  if(!['http:','https:'].includes(url.protocol)||url.username||url.password||url.search||url.hash||url.pathname!=='/'||
    typeof config.token!=='string'||!config.token||config.token.length>4096||/[\s\u0000-\u001f\u007f]/.test(config.token)||
    !Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>10_000)throw new Error('APPROVAL_CONFIG_INVALID');
  const base=url.origin,transport=config.fetch??fetch;
  async function request(tenantId:string,path:string,method:'GET'|'POST',maximum:number):Promise<unknown>{
    const controller=new AbortController();let reader:ReadableStreamDefaultReader<Uint8Array>|undefined;
    let expired=false,failure='APPROVAL_HTTP_UNAVAILABLE';
    const refuse=(code:string):never=>{failure=code;throw new Error(code);};
    let rejectTimeout!:(reason:Error)=>void;
    const timeout=new Promise<never>((_,reject)=>{rejectTimeout=reject;});
    const timer=setTimeout(()=>{expired=true;controller.abort();rejectTimeout(new Error('APPROVAL_HTTP_TIMEOUT'));},timeoutMs);
    const bounded=<T>(work:Promise<T>)=>Promise.race([work,timeout]);
    try{
      const response=await bounded(transport(`${base}${path}`,{method,redirect:'error',signal:controller.signal,
        headers:{Authorization:`Bearer ${config.token}`,'X-Tenant-Id':tenantId,Accept:'application/json','Accept-Encoding':'identity',...(method==='POST'?{'Content-Type':'application/json'}:{})},
        ...(method==='POST'?{body:'{}'}:{})}));
      if(response.status!==200)refuse('APPROVAL_HTTP_REFUSED');
      const contentType=response.headers.get('content-type'),encoding=response.headers.get('content-encoding'),length=response.headers.get('content-length');
      if(!contentType||!/^application\/json(?:;\s*charset=utf-8)?$/i.test(contentType)||encoding!==null&&encoding.toLowerCase()!=='identity'||
        length!==null&&(!/^(0|[1-9]\d*)$/.test(length)||!Number.isSafeInteger(Number(length))||Number(length)>maximum)||!response.body)refuse('APPROVAL_PROTOCOL_INVALID');
      reader=response.body!.getReader();const chunks:Uint8Array[]=[];let total=0;
      while(true){const part=await bounded(reader.read());if(part.done)break;
        total+=part.value.byteLength;if(total>maximum)refuse('APPROVAL_PROTOCOL_INVALID');chunks.push(part.value);
      }
      if(length!==null&&Number(length)!==total)refuse('APPROVAL_PROTOCOL_INVALID');
      const bytes=new Uint8Array(total);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
      const text=(()=>{try{return new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch{return refuse('APPROVAL_PROTOCOL_INVALID');}})();
      const parsed=parseBoundedJSONEnvelope(text);if(parsed.ok)return parsed.value;return refuse('APPROVAL_PROTOCOL_INVALID');
    }catch{
      // Only locally generated codes escape; never inspect a thrown transport object.
      throw new Error(expired?'APPROVAL_HTTP_TIMEOUT':failure);
    }finally{
      clearTimeout(timer);controller.abort();
      // Native fetch abort closes the transport. An adversarial cancellation hook
      // must not extend the original request deadline or leak a rejection.
      try{if(reader)void reader.cancel().catch(()=>{});}catch{/* Cleanup cannot replace the safe failure. */}
    }
  }
  return {
    async tickApproval(input){
      ids(input);const value=await request(input.tenantId,`/internal/approvals/${input.requestId}/tick`,'POST',2048);
      return tick(value,input.requestId);
    },
    async approvalStatus(input){
      ids(input);return tick(await request(input.tenantId,`/internal/approvals/${input.requestId}/status`,'GET',2048),input.requestId);
    },
    async pendingApprovals(tenantId){
      if(!uuid(tenantId))throw invalid();const value=await request(tenantId,'/internal/approvals/pending','GET',32_768);
      if(!exact(value,['items'])||!Array.isArray(value.items)||value.items.length>50)throw invalid();
      const seen=new Set<string>();for(const item of value.items){delivery(item);if(item.tenantId!==tenantId||seen.has(item.eventId))throw invalid();seen.add(item.eventId);}
      return value as unknown as {items:ApprovalDelivery[]};
    },
    async ackApproval(input){
      delivery(input);const value=await request(input.tenantId,`/internal/approvals/dispatch/${input.eventId}/ack`,'POST',512);
      if(!exact(value,['id','acknowledged'])||value.id!==input.eventId||value.acknowledged!==true)throw invalid();
    },
  };
}

/** Transport acceptance precedes acknowledgement. A closed logical execution can
 * only consume a replay once canonical storage confirms a terminal outcome. */
export async function dispatchApprovalEvent(event:ApprovalDelivery,protocol:ApprovalProtocol,
  signalWithStart:(input:ApprovalInput,eventId:string)=>Promise<'accepted'|'closed'>):Promise<void>{
  delivery(event);const input={tenantId:event.tenantId,requestId:event.requestId};
  const result=await signalWithStart(input,event.eventId);
  if(result==='closed'){
    const canonical=await protocol.approvalStatus(input);
    if(canonical.status==='pending')throw new Error('APPROVAL_CLOSED_PENDING');
  }else if(result!=='accepted')throw invalid();
  await protocol.ackApproval(event);
}
