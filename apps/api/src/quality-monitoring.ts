// SPDX-License-Identifier: Apache-2.0
import type {FastifyInstance,FastifyRequest,HTTPMethods} from 'fastify';
import {Type,type TSchema,type TProperties} from '@sinclair/typebox';
import {Value} from '@sinclair/typebox/value';
import {scope,type Tx} from '../../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../../packages/authz/src/index.ts';
import {authenticate,siteTenant} from './security.ts';
import {parseDomainRequestJSON,checkDomainData} from './business-domain-http.ts';
import {MONITOR_LIMITS as L} from '../../../packages/domain/src/quality-monitoring-contracts.ts';
import {monitoringInvalid} from '../../../packages/domain/src/quality-monitoring.ts';
import {monitoringQuery,monitoringFailure,listQualityMonitors,getQualityMonitor,listMonitorDefinitions,getMonitorDefinition,publishQualityMonitor,changeQualityMonitorState,listMonitorOccurrences,listQualityIssues,getQualityIssue,listQualityIssueEvents,commandQualityIssue,listQualityNotifications,markQualityNotificationRead,pendingMonitoringWork,dispatchMonitoringWork} from '../../../packages/domain/src/quality-monitoring-service.ts';
const object=<T extends TProperties>(p:T)=>Type.Object(p,{additionalProperties:false});
const choices=(...v:string[])=>Type.Union(v.map(x=>Type.Literal(x)));
const nullable=(v:TSchema)=>Type.Union([v,Type.Null()]);
const integer=(minimum=1,maximum=2147483647)=>Type.Integer({minimum,maximum});
const uuid=Type.String({pattern:'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'}),hash=Type.String({pattern:'^[a-f0-9]{64}$'});
const stamp=Type.String({pattern:'^(?!0000)\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$'}),text=(max:number)=>Type.String({minLength:1,maxLength:max});
const rulePin=object({id:uuid,version:integer(),definitionHash:hash}),definitionPin={monitorId:uuid,definitionVersion:integer(),definitionHash:hash};
const window=object({from:stamp,until:stamp});
const definition=object({formatVersion:Type.Literal(1),name:text(240),purpose:text(4096),rule:rulePin,executorId:uuid,authorizationExpiresAt:stamp,
 schedule:object({kind:Type.Literal('fixed-interval'),timeZone:Type.Literal('UTC'),startsAt:stamp,endsAt:nullable(stamp),intervalSeconds:integer(60,604800),lateGraceSeconds:integer(0,300),missedSlots:Type.Literal('skip'),overlap:Type.Literal('skip')}),
 maintenance:Type.Array(window,{maxItems:32}),silences:Type.Array(window,{maxItems:32}),routing:object({channel:Type.Literal('in-app'),ownerId:uuid,recipientIds:Type.Array(uuid,{minItems:1,maxItems:16,uniqueItems:true})}),
 issue:object({category:Type.Literal('data-quality'),acknowledgeWithinSeconds:integer(1,2678400),resolveWithinSeconds:integer(1,2678400)}),recoveryMaximumAgeSeconds:integer(1,604800),retry:object({policy:Type.Literal('quality-run-v1')})});
const evidence=object({occurrenceId:uuid,ordinal:integer(),runId:uuid,runVersion:integer(),completionHash:hash,comparisonScopeHash:hash,observedFinishedAt:stamp});
const observation=Type.Union([object({state:Type.Literal('unobserved')}),object({state:Type.Literal('pending'),occurrenceId:uuid,runId:uuid}),object({state:Type.Literal('conclusive'),verdict:choices('PASS','FAIL'),evidence}),object({state:Type.Literal('unknown'),reason:choices('NO_DATA','EXECUTION_FAILED','CANCELLED','SKIPPED','STALE','BLOCKED'),occurrenceId:nullable(uuid)})]);
const blocks=['RULE_VERSION_CHANGED','AUTHORIZATION_EXPIRED','EXECUTOR_UNAVAILABLE','RULE_OWNER_UNAVAILABLE','TARGET_UNAVAILABLE','REFERENCE_UNAVAILABLE'];
const monitor=object({id:uuid,revision:integer(),definitionVersion:integer(),definitionHash:hash,definition,state:choices('enabled','paused','retired'),blocked:nullable(choices(...blocks)),nextSlotAt:nullable(stamp),lastAdmittedOrdinal:integer(0),lastProjectedOrdinal:integer(0),currentObservation:observation,lastConclusive:nullable(object({verdict:choices('PASS','FAIL'),evidence})),createdAt:stamp,createdBy:uuid});
const definitionView=object({...definitionPin,definition,createdAt:stamp,createdBy:uuid});
const occurrenceFields={...definitionPin,id:uuid,ordinal:integer(),rule:rulePin,executorId:uuid,origin:choices('schedule','recovery-request'),slots:nullable(object({firstAt:stamp,lastAt:stamp,count:integer()})),recordedAt:stamp};
const occurrence=Type.Union([object({...occurrenceFields,disposition:Type.Literal('skipped'),reason:choices('MISSED','MAINTENANCE','OVERLAP','CAPACITY','PAUSED',...blocks),runId:Type.Null(),comparisonScopeHash:Type.Null()}),object({...occurrenceFields,disposition:Type.Literal('enqueued'),reason:Type.Null(),runId:uuid,comparisonScopeHash:hash})]);
const issue=object({id:uuid,version:integer(),monitorId:uuid,comparisonScopeHash:hash,rule:rulePin,category:Type.Literal('data-quality'),severity:choices('info','warning','critical'),tableAssetId:uuid,columnAssetId:uuid,status:choices('open','acknowledged','resolved','superseded'),episode:integer(),assignedOwnerId:uuid,ownerAvailable:Type.Boolean(),openedAt:stamp,acknowledgeDueAt:stamp,resolveDueAt:stamp,opening:evidence,lastFailure:evidence,recovery:nullable(evidence),resolution:nullable(object({rootCause:text(4096),remediation:text(4096),reason:text(4096),evidence,at:stamp,by:uuid})),superseded:nullable(object({reason:text(4096),replacementMonitorId:uuid,replacementDefinitionVersion:integer(),at:stamp,by:uuid}))});
const event=object({id:uuid,issueId:uuid,version:integer(),episode:integer(),kind:choices('opened','failed-again','acknowledged','assigned','recovery-available','recovery-invalidated','resolved','reopened','superseded'),monitor:object(definitionPin),occurrenceId:nullable(uuid),runId:nullable(uuid),actorId:Type.Union([uuid,Type.Literal('site:local')]),at:stamp,reason:nullable(text(4096)),resolution:nullable(object({rootCause:text(4096),remediation:text(4096),reason:text(4096),evidence,at:stamp,by:uuid}))});
const notification=object({id:uuid,eventId:uuid,issueId:uuid,recipientId:uuid,template:choices('quality-issue-opened-v1','quality-issue-reopened-v1','quality-issue-assigned-v1','quality-recovery-available-v1','quality-issue-resolved-v1'),createdAt:stamp,readAt:nullable(stamp),version:integer()});
const publish=object({id:uuid,expectedRevision:integer(0,2147483646),definition}),state=object({expectedRevision:integer(1,2147483646),action:choices('pause','resume','retire'),reason:text(4096)});
const issueFields={expectedVersion:integer(1,2147483646),reason:text(4096)};
const issueInputs={acknowledge:object(issueFields),assign:object({...issueFields,ownerId:uuid}),resolve:object({...issueFields,recoveryOccurrenceId:uuid,recoveryRunId:uuid,recoveryRunVersion:integer(),rootCause:text(4096),remediation:text(4096)}),supersede:object({...issueFields,replacementMonitorId:uuid,replacementDefinitionVersion:integer()}),'recovery.request':object({...issueFields,id:uuid})};
const page=(item:TSchema)=>object({items:Type.Array(item,{maxItems:100}),nextCursor:nullable(Type.String({maxLength:1024}))});
const workItem=object({tenantId:uuid,monitorId:uuid,work:choices('tick','reconcile')}),workResult=object({monitorId:uuid,state:choices('idle','advanced','blocked','retry'),nextWakeAt:nullable(stamp),occurrenceId:nullable(uuid),runId:nullable(uuid)});
const problem=object({type:Type.String(),title:Type.String(),status:Type.Integer(),code:Type.String(),detail:Type.String(),correlationId:Type.String()});
export const monitoringHttp={definition,monitor,definitionView,occurrence,issue,event,notification,publish,state,issueInputs,workItem,workResult,problem};
export function monitoringRawQuery(url:string,allowed:readonly string[]):Record<string,string|number|boolean>{
 const entries:[string,string|number|boolean][]=[],seen=new Set<string>(),raw=url.split('?').slice(1).join('?');if(!raw)return Object.fromEntries(entries);
 for(const pair of raw.split('&')){const equal=pair.indexOf('=');let key:string,value:string;try{key=decodeURIComponent((equal<0?pair:pair.slice(0,equal)).replaceAll('+',' '));value=decodeURIComponent((equal<0?'':pair.slice(equal+1)).replaceAll('+',' '));}catch{throw monitoringInvalid();}
  if(!allowed.includes(key)||seen.has(key)||!value||value.length>(key==='cursor'?1024:64))throw monitoringInvalid();seen.add(key);
  if(key==='limit'){if(!/^[1-9][0-9]{0,2}$/.test(value)||Number(value)>100)throw monitoringInvalid();entries.push([key,Number(value)]);}
  else if(key==='assignedToMe'){if(value!=='true'&&value!=='false')throw monitoringInvalid();entries.push([key,value==='true']);}
  else entries.push([key,value]);
 }return Object.fromEntries(entries);
}
export function parseMonitoringRequestJSON(raw:string):unknown{try{if(Buffer.byteLength(raw)>L.definitionBytes)throw 0;return parseDomainRequestJSON(raw,'domain');}catch{throw monitoringInvalid();}}
function idempotency(req:FastifyRequest):string{let count=0;for(let i=0;i<req.raw.rawHeaders.length;i+=2)if(req.raw.rawHeaders[i].toLowerCase()==='idempotency-key')count++;const key=req.headers['idempotency-key'];if(count!==1||typeof key!=='string'||key.length<8||key.length>128||/[\u0000-\u001f\u007f]/.test(key))throw new Problem(400,'IDEMPOTENCY_REQUIRED','Send one bounded Idempotency-Key.');return key;}
type State={tenant:string;principal?:Principal;key?:string;query:Record<string,string|number|boolean>};
type Spec={params?:TProperties;query?:readonly string[];body?:TSchema;response:TSchema;mutation?:boolean;status?:number;internal?:boolean};
export async function installQualityMonitoring(app:FastifyInstance):Promise<void>{await app.register(async child=>{
 const states=new WeakMap<FastifyRequest,State>();
 child.setValidatorCompiler(({schema})=>value=>Value.Check(schema as TSchema,value)?{value}:{error:monitoringInvalid()});
 child.removeContentTypeParser('application/json');child.addContentTypeParser('application/json',{parseAs:'string',bodyLimit:L.definitionBytes},(_req,raw,done)=>{try{done(null,parseMonitoringRequestJSON(String(raw)));}catch{done(monitoringInvalid());}});
 child.setErrorHandler((error,req,reply)=>{const e=error as {statusCode?:number;validation?:unknown},known=error instanceof Problem?monitoringFailure(error):e.statusCode===429?new Problem(429,'RATE_LIMITED','Too many requests. Retry later.'):e.validation||[400,413,415].includes(e.statusCode??0)?monitoringInvalid():monitoringFailure(error);
  if(known.status>=500)req.log.error({code:known.code,correlationId:req.id},'Monitoring request failed; details redacted');if(known.status===503)reply.header('Retry-After','5');
  reply.code(known.status).type('application/problem+json').send({type:'about:blank',title:known.status>=500?'Service unavailable':'Request rejected',status:known.status,code:known.code,detail:known.message,correlationId:req.id});
 });
 function route(method:HTTPMethods,url:string,spec:Spec,work:(req:FastifyRequest,tx:Tx,s:State)=>Promise<unknown>){
  const params=object(spec.params??{}),query=object(Object.fromEntries((spec.query??[]).map(k=>[k,Type.Optional(Type.String({maxLength:k==='cursor'?1024:64}))]))),status=spec.status??200;
  child.route({method,url,bodyLimit:L.definitionBytes,schema:{params,querystring:query,...(spec.body?{body:spec.body}:{}),response:{[status]:spec.response,'4xx':problem,'5xx':problem}},
   onRequest:async req=>{if(spec.internal)states.set(req,{tenant:siteTenant(req),query:{}});else{const {principal}=await authenticate(req);states.set(req,{tenant:principal.tenantId,principal,query:{}});}},
   preValidation:async req=>{const s=states.get(req)!;s.query=monitoringRawQuery(req.url,spec.query??[]);if(!Value.Check(params,req.params))throw monitoringInvalid();if(spec.mutation)s.key=idempotency(req);if(spec.body){try{checkDomainData(req.body,'domain');}catch{throw monitoringInvalid();}if(!Value.Check(spec.body,req.body))throw monitoringInvalid();}else if(req.body!==undefined)throw monitoringInvalid();},
   handler:async(req,reply)=>{const s=states.get(req)!;try{const result=await scope(s.tenant,s.principal?.id??'site:local',tx=>monitoringQuery(tx,async()=>{const value=await work(req,tx,s);if(!Value.Check(spec.response,value))throw new Problem(500,'MONITOR_STORAGE_INVALID','The monitoring operation could not be completed.');return value;}));reply.code(status);return result;}catch(e){throw monitoringFailure(e);}}
  });
 }
 const id=(r:FastifyRequest)=>(r.params as {id:string}).id;
 route('GET','/api/v1/quality/monitors',{query:['ruleId','state','limit','cursor'],response:page(monitor)},(r,tx,s)=>listQualityMonitors(tx,s.principal!,s.query));
 route('GET','/api/v1/quality/monitors/:id',{params:{id:uuid},response:object({monitor})},async(r,tx,s)=>({monitor:await getQualityMonitor(tx,s.principal!,id(r))}));
 route('GET','/api/v1/quality/monitors/:id/definitions',{params:{id:uuid},query:['limit','cursor'],response:page(definitionView)},(r,tx,s)=>listMonitorDefinitions(tx,s.principal!,id(r),s.query));
 route('GET','/api/v1/quality/monitors/:id/definitions/:version',{params:{id:uuid,version:Type.String({pattern:'^[1-9][0-9]{0,9}$'})},response:object({definition:definitionView})},async(r,tx,s)=>({definition:await getMonitorDefinition(tx,s.principal!,id(r),Number((r.params as {version:string}).version))}));
 route('POST','/api/v1/quality/monitors',{body:publish,response:object({monitor}),mutation:true,status:201},(r,tx,s)=>{if((r.body as {expectedRevision:number}).expectedRevision!==0)throw monitoringInvalid();return publishQualityMonitor(tx,s.principal!,r.body,s.key!,r.id);});
 route('POST','/api/v1/quality/monitors/:id/definitions',{params:{id:uuid},body:publish,response:object({monitor}),mutation:true,status:201},(r,tx,s)=>{const b=r.body as {id:string;expectedRevision:number};if(b.id!==id(r)||b.expectedRevision<1)throw monitoringInvalid();return publishQualityMonitor(tx,s.principal!,r.body,s.key!,r.id);});
 route('POST','/api/v1/quality/monitors/:id/state',{params:{id:uuid},body:state,response:object({monitor}),mutation:true},(r,tx,s)=>changeQualityMonitorState(tx,s.principal!,id(r),r.body,s.key!,r.id));
 route('GET','/api/v1/quality/monitors/:id/occurrences',{params:{id:uuid},query:['limit','cursor'],response:page(occurrence)},(r,tx,s)=>listMonitorOccurrences(tx,s.principal!,id(r),s.query));
 route('GET','/api/v1/quality/issues',{query:['monitorId','status','assignedToMe','limit','cursor'],response:page(issue)},(r,tx,s)=>listQualityIssues(tx,s.principal!,s.query));
 route('GET','/api/v1/quality/issues/:id',{params:{id:uuid},response:object({issue})},async(r,tx,s)=>({issue:await getQualityIssue(tx,s.principal!,id(r))}));
 route('GET','/api/v1/quality/issues/:id/events',{params:{id:uuid},query:['limit','cursor'],response:page(event)},(r,tx,s)=>listQualityIssueEvents(tx,s.principal!,id(r),s.query));
 for(const action of ['acknowledge','assign','resolve','supersede','recovery.request'] as const)route('POST','/api/v1/quality/issues/:id/'+(action==='recovery.request'?'recovery-runs':action),{params:{id:uuid},body:issueInputs[action],response:action==='recovery.request'?object({occurrence}):object({issue}),mutation:true,status:action==='recovery.request'?202:200},(r,tx,s)=>commandQualityIssue(tx,s.principal!,id(r),action,r.body,s.key!,r.id));
 route('GET','/api/v1/quality/notifications',{query:['limit','cursor'],response:page(notification)},(r,tx,s)=>listQualityNotifications(tx,s.principal!,s.query));
 route('POST','/api/v1/quality/notifications/:id/read',{params:{id:uuid},body:object({expectedVersion:integer(1,2147483646)}),response:object({notification}),mutation:true},(r,tx,s)=>markQualityNotificationRead(tx,s.principal!,id(r),r.body,s.key!,r.id));
 route('GET','/internal/quality-monitors/work',{internal:true,response:object({items:Type.Array(workItem,{maxItems:50})})},(_r,tx,s)=>pendingMonitoringWork(tx,s.tenant));
 for(const work of ['tick','reconcile'] as const)route('POST','/internal/quality-monitors/:id/'+work,{internal:true,params:{id:uuid},body:object({}),response:workResult},(r,tx)=>dispatchMonitoringWork(tx,id(r),work));
 });}
