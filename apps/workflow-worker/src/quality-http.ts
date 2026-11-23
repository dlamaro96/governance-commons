// SPDX-License-Identifier: Apache-2.0
import {parseBoundedJSONEnvelope} from '../../../packages/domain/src/model.ts';
import {qualityId,parseQualityClaim,parseQualityExecution,qualityObject} from '../../../packages/domain/src/quality.ts';
/** Bounded private transport. It never exposes response text, remote exceptions,
 * credentials or URLs through errors; callers admit a closed DTO afterwards. */
export function createQualityTransport(config:{url:string;token:string;fetch?:typeof fetch}){
 let url:URL;try{url=new URL(config.url);}catch{throw new Error('QUALITY_CONFIG_INVALID');}
 if(!['http:','https:'].includes(url.protocol)||url.username||url.password||url.search||url.hash||url.pathname!=='/'||
  typeof config.token!=='string'||!config.token||config.token.length>4096||/[\s\u0000-\u001f\u007f]/.test(config.token))throw new Error('QUALITY_CONFIG_INVALID');
 const base=url.origin,transport=config.fetch??fetch;
 return async function request(path:string,options:{tenantId?:string;body?:unknown;timeoutMs:number;maximum:number}):Promise<{status:number;body:unknown}>{
  if(!/^\/(?:internal\/quality-runs\/(?:pending|[a-f0-9-]{36}\/(?:claim|finish))|internal\/quality-monitors\/(?:work|[a-f0-9-]{36}\/(?:tick|reconcile))|quality)$/.test(path)||
   !Number.isInteger(options.timeoutMs)||options.timeoutMs<1||options.timeoutMs>40000||!Number.isInteger(options.maximum)||options.maximum<1||options.maximum>65536||options.maximum>32768&&!path.endsWith('/claim'))throw new Error('QUALITY_PROTOCOL_INVALID');
  if(options.tenantId!==undefined)try{qualityId(options.tenantId);}catch{throw new Error('QUALITY_PROTOCOL_INVALID');}
  const controller=new AbortController();let reader:ReadableStreamDefaultReader<Uint8Array>|undefined,expired=false,code='QUALITY_HTTP_UNAVAILABLE';
  let rejectTimeout!:(error:Error)=>void;const timeout=new Promise<never>((_,reject)=>{rejectTimeout=reject;});
  const timer=setTimeout(()=>{expired=true;controller.abort();rejectTimeout(new Error('QUALITY_HTTP_TIMEOUT'));},options.timeoutMs);
  const bounded=<T>(work:Promise<T>)=>Promise.race([work,timeout]);const refuse=():never=>{code='QUALITY_PROTOCOL_INVALID';throw new Error(code);};
  try{
   let requestBody:string|undefined;
   if(options.body!==undefined){
    // Only the private source execution frame can carry the retained codes.
    let maximum=16384;
    if(path==='/quality'){const frame=qualityObject(options.body,[],['tenantId','source','execution']);
     if(Object.hasOwn(frame,'execution')){const execution=parseQualityExecution(frame.execution);if(execution.kind==='reference-allowed-values')maximum=65536;}
    }
    requestBody=JSON.stringify(options.body);if(Buffer.byteLength(requestBody)>maximum)refuse();
   }
   const response=await bounded(transport(`${base}${path}`,{method:options.body===undefined?'GET':'POST',redirect:'error',signal:controller.signal,
    headers:{Authorization:`Bearer ${config.token}`,Accept:'application/json','Accept-Encoding':'identity',...(options.tenantId?{'X-Tenant-Id':options.tenantId}:{}),...(options.body===undefined?{}:{'Content-Type':'application/json'})},
    ...(options.body===undefined?{}:{body:requestBody})}));
   if(![200,400,401,403,404,409,413,422,429,500,502,503,504].includes(response.status))refuse();
   const type=response.headers.get('content-type'),encoding=response.headers.get('content-encoding'),length=response.headers.get('content-length');
   if(!type||!/^application\/(?:json|problem\+json)(?:;\s*charset=utf-8)?$/i.test(type)||encoding!==null&&encoding.toLowerCase()!=='identity'||
    length!==null&&(!/^(0|[1-9]\d*)$/.test(length)||!Number.isSafeInteger(Number(length))||Number(length)>options.maximum)||!response.body)refuse();
   reader=response.body!.getReader();let total=0;const chunks:Uint8Array[]=[];
   for(;;){const part=await bounded(reader.read());if(part.done)break;total+=part.value.byteLength;if(total>options.maximum)refuse();chunks.push(part.value);}
   if(length!==null&&Number(length)!==total)refuse();
   const bytes=new Uint8Array(total);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
   let text:string;try{text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch{return refuse();}
   const parsed=parseBoundedJSONEnvelope(text);if(!parsed.ok)return refuse();
   if(path.endsWith('/claim')){
    if(response.status===200){code='QUALITY_PROTOCOL_INVALID';const claim=parseQualityClaim(parsed.value),maximum=claim.status==='claimed'&&claim.execution.kind==='reference-allowed-values'?65536:16384;
     if(total>maximum)refuse();return {status:response.status,body:claim};}
    if(total>16384)refuse();
   }
   return {status:response.status,body:parsed.value};
  }catch{throw new Error(expired?'QUALITY_HTTP_TIMEOUT':code);}finally{
   clearTimeout(timer);controller.abort();try{if(reader)void reader.cancel().catch(()=>{});}catch{/* Cleanup cannot expose transport failures. */}
  }
 };
}
