// SPDX-License-Identifier: Apache-2.0
import {createHash} from 'node:crypto';
import {Problem} from '../../authz/src/index.ts';
import {QUALITY_FRESHNESS_LIMITS as FRESHNESS_LIMITS} from './quality-contracts.ts';
import {MONITOR_LIMITS as L,type QualityMonitorDefinition,type PublishMonitorInput,type MonitorStateInput,type MonitorRulePin,type MonitorDefinitionPin,type MonitorRunEvidence,type MonitorObservation,type QualityMonitorView,type MonitorDefinitionView,type QualityOccurrence,type QualityComparisonScope,type QualityIssueView,type QualityIssueEvent,type QualityNotification,type MonitoringPageQuery,type MonitorListQuery,type QualityIssueListQuery,type FixedUtcSchedule,type MonitorWindow,type MonitorSlotRange,type IssueVersionInput,type AssignQualityIssueInput,type ResolveQualityIssueInput,type SupersedeQualityIssueInput,type RequestQualityRecoveryInput} from './quality-monitoring-contracts.ts';
export const monitoringInvalid=()=>new Problem(400,'MONITOR_INPUT_INVALID','Provide exactly the declared monitoring fields and values.');
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const sha=/^[a-f0-9]{64}$/;
const badUnicode=/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const controls=/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/;
const states=['enabled','paused','retired'] as const;
const blocks=['RULE_VERSION_CHANGED','AUTHORIZATION_EXPIRED','EXECUTOR_UNAVAILABLE','RULE_OWNER_UNAVAILABLE','TARGET_UNAVAILABLE','REFERENCE_UNAVAILABLE'] as const;
const skipReasons=['MISSED','MAINTENANCE','OVERLAP','CAPACITY','PAUSED',...blocks] as const;
const issueStates=['open','acknowledged','resolved','superseded'] as const;
function need(value:unknown):asserts value {if(!value)throw monitoringInvalid();}
function obj(value:unknown,keys:readonly string[],optional:readonly string[]=[]):Record<string,unknown>{
 need(value!==null&&typeof value==='object'&&!Array.isArray(value));const v=value as Record<string,unknown>;
 need(keys.every(k=>Object.hasOwn(v,k))&&Object.keys(v).every(k=>keys.includes(k)||optional.includes(k)));return v;
}
function array(value:unknown,max:number):unknown[]{need(Array.isArray(value)&&value.length<=max);return value;}
function id(value:unknown):string {need(typeof value==='string'&&uuid.test(value));return value;}
function hash(value:unknown):string {need(typeof value==='string'&&sha.test(value));return value;}
function int(value:unknown,min=1,max=2147483647):number {need(typeof value==='number'&&Number.isSafeInteger(value)&&!Object.is(value,-0)&&value>=min&&value<=max);return value;}
function bool(value:unknown):boolean {need(typeof value==='boolean');return value;}
function choice<const T extends readonly string[]>(value:unknown,choices:T):T[number]{need(typeof value==='string'&&choices.includes(value));return value as T[number];}
function stamp(value:unknown):string {need(typeof value==='string'&&/^(?!0000)\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)&&Number.isFinite(Date.parse(value))&&new Date(value).toISOString()===value);return value;}
function text(value:unknown,max:number,multiline=true):string {need(typeof value==='string'&&value.length<=max&&!badUnicode.test(value)&&!controls.test(value)&&(multiline||!/[\t\n\r]/.test(value)));const normalized=value.normalize('NFC').trim();need(normalized.length>0&&normalized.length<=max);return normalized;}
function nullable<T>(value:unknown,parser:(x:unknown)=>T):T|null{return value===null?null:parser(value);}
/** Snapshot own enumerable data only; never read getters or inspect reflection-thrown values.
 * Both raw envelope and node/depth budgets apply before semantic normalization. */
function snapshot(input:unknown):unknown {
 let nodes=0,bytes=0;const active=new Set<object>();const spend=(n:number)=>{bytes+=n;need(bytes<=65536);};
 function visit(v:unknown,depth:number):unknown{
  need(++nodes<=4096&&depth<=24);spend(2);
  if(v===null||typeof v==='boolean')return v;
  if(typeof v==='number'){need(Number.isFinite(v)&&!Object.is(v,-0));return v;}
  if(typeof v==='string'){need(v.length<=65536&&!badUnicode.test(v));spend(Buffer.byteLength(v,'utf8'));return v;}
  need(typeof v==='object'&&v!==null&&!active.has(v));active.add(v);
  try{
   const isArray=Array.isArray(v),proto=Object.getPrototypeOf(v);need(isArray?proto===Array.prototype:proto===Object.prototype||proto===null);
   const keys=Reflect.ownKeys(v);need(keys.length<=1025&&keys.every(k=>typeof k==='string'));
   if(isArray){const length=Object.getOwnPropertyDescriptor(v,'length');need(length&&Object.hasOwn(length,'value'));const n=int(length.value,0,1024);need(keys.length===n+1);
    return Array.from({length:n},(_,i)=>{const d=Object.getOwnPropertyDescriptor(v,String(i));need(d?.enumerable&&Object.hasOwn(d,'value'));return visit(d.value,depth+1);});
   }
   return Object.fromEntries(keys.map(k=>{need(typeof k==='string'&&k.length<=65536&&k!=='__proto__'&&k!=='constructor'&&k!=='prototype'&&!badUnicode.test(k));spend(Buffer.byteLength(k,'utf8'));const d=Object.getOwnPropertyDescriptor(v,k);need(d?.enumerable&&Object.hasOwn(d,'value'));return [k,visit(d.value,depth+1)];}));
  }finally{active.delete(v);}
 }
 try{const result=visit(input,0);need(Buffer.byteLength(JSON.stringify(result),'utf8')<=65536);return result;}catch{throw monitoringInvalid();}
}
function checked<T>(input:unknown,parse:(value:unknown)=>T):T{return parse(snapshot(input));}
/** All keys are closed ASCII schema fields. Existing canonical JSON sorting/hash semantics. */
function canonical(value:unknown):string {if(value===null||typeof value!=='object')return JSON.stringify(value);if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical((value as Record<string,unknown>)[k])).join(',')+'}';}
function digest(value:unknown):string{return createHash('sha256').update(canonical(value),'utf8').digest('hex');}
function same(raw:unknown,normalized:unknown){need(canonical(raw)===canonical(normalized));}
function pin(input:unknown):MonitorRulePin {const v=obj(input,['id','version','definitionHash']);return {id:id(v.id),version:int(v.version),definitionHash:hash(v.definitionHash)};}
function definitionPin(input:unknown):MonitorDefinitionPin {const v=obj(input,['monitorId','definitionVersion','definitionHash']);return {monitorId:id(v.monitorId),definitionVersion:int(v.definitionVersion),definitionHash:hash(v.definitionHash)};}
function schedule(input:unknown):FixedUtcSchedule {
 const v=obj(input,['kind','timeZone','startsAt','endsAt','intervalSeconds','lateGraceSeconds','missedSlots','overlap']);
 need(v.kind==='fixed-interval'&&v.timeZone==='UTC'&&v.missedSlots==='skip'&&v.overlap==='skip');
 const startsAt=stamp(v.startsAt),endsAt=nullable(v.endsAt,stamp),intervalSeconds=int(v.intervalSeconds,L.minimumIntervalSeconds,L.maximumIntervalSeconds),lateGraceSeconds=int(v.lateGraceSeconds,0,Math.min(intervalSeconds-1,300));need(endsAt===null||endsAt>startsAt);
 return {kind:'fixed-interval',timeZone:'UTC',startsAt,endsAt,intervalSeconds,lateGraceSeconds,missedSlots:'skip',overlap:'skip'};
}
function windows(input:unknown):MonitorWindow[]{let previous:string|null=null;return array(input,L.maximumWindows).map(raw=>{const v=obj(raw,['from','until']),from=stamp(v.from),until=stamp(v.until);need(from<until&&(previous===null||previous<=from));previous=until;return {from,until};});}
function definition(input:unknown):QualityMonitorDefinition {
 need(Buffer.byteLength(JSON.stringify(input),'utf8')<=L.definitionBytes);
 const v=obj(input,['formatVersion','name','purpose','rule','executorId','authorizationExpiresAt','schedule','maintenance','silences','routing','issue','recoveryMaximumAgeSeconds','retry']);need(v.formatVersion===1);
 const s=schedule(v.schedule),routing=obj(v.routing,['channel','ownerId','recipientIds']),issue=obj(v.issue,['category','acknowledgeWithinSeconds','resolveWithinSeconds']),retry=obj(v.retry,['policy']);
 need(routing.channel==='in-app'&&issue.category==='data-quality'&&retry.policy==='quality-run-v1');const ownerId=id(routing.ownerId),recipientIds=array(routing.recipientIds,L.maximumRecipients).map(id);
 need(recipientIds.includes(ownerId)&&recipientIds.every((x,i)=>i===0||recipientIds[i-1]<x));
 const acknowledgeWithinSeconds=int(issue.acknowledgeWithinSeconds,1,L.maximumSlaSeconds),resolveWithinSeconds=int(issue.resolveWithinSeconds,acknowledgeWithinSeconds,L.maximumSlaSeconds);
 return {formatVersion:1,name:text(v.name,L.textName,false),purpose:text(v.purpose,L.textPurpose),rule:pin(v.rule),executorId:id(v.executorId),authorizationExpiresAt:stamp(v.authorizationExpiresAt),schedule:s,maintenance:windows(v.maintenance),silences:windows(v.silences),routing:{channel:'in-app',ownerId,recipientIds},issue:{category:'data-quality',acknowledgeWithinSeconds,resolveWithinSeconds},recoveryMaximumAgeSeconds:int(v.recoveryMaximumAgeSeconds,s.intervalSeconds,L.maximumRecoveryAgeSeconds),retry:{policy:'quality-run-v1'}};
}
export const parseMonitorDefinition=(input:unknown):QualityMonitorDefinition=>checked(input,definition);
export function monitorDefinitionHash(input:unknown):string{return digest(parseMonitorDefinition(input));}
export function validateMonitorPublication(input:unknown,actorId:unknown,now:unknown):QualityMonitorDefinition {
 const d=parseMonitorDefinition(input),actor=id(actorId),at=Date.parse(stamp(now)),expires=Date.parse(d.authorizationExpiresAt);need(d.executorId===actor&&expires>at&&expires-at<=L.maximumAuthorizationSeconds*1000);return d;
}
export function parsePublishMonitorInput(input:unknown):PublishMonitorInput{return checked(input,x=>{const v=obj(x,['id','expectedRevision','definition']);return {id:id(v.id),expectedRevision:int(v.expectedRevision,0,2147483646),definition:definition(v.definition)};});}
export function parseMonitorStateInput(input:unknown):MonitorStateInput{return checked(input,x=>{const v=obj(x,['expectedRevision','action','reason']);return {expectedRevision:int(v.expectedRevision,1,2147483646),action:choice(v.action,['pause','resume','retire']),reason:text(v.reason,L.textReason)};});}
export type IssueCommandInputs={acknowledge:IssueVersionInput;assign:AssignQualityIssueInput;resolve:ResolveQualityIssueInput;supersede:SupersedeQualityIssueInput;'recovery.request':RequestQualityRecoveryInput};
export function parseIssueCommandInput<A extends keyof IssueCommandInputs>(action:A,input:unknown):IssueCommandInputs[A]{return checked(input,x=>{
 choice(action,['acknowledge','assign','resolve','supersede','recovery.request']);
 const extras={acknowledge:[],assign:['ownerId'],resolve:['recoveryOccurrenceId','recoveryRunId','recoveryRunVersion','rootCause','remediation'],supersede:['replacementMonitorId','replacementDefinitionVersion'],'recovery.request':['id']} as const;
 const v=obj(x,['expectedVersion','reason',...extras[action]]),base={expectedVersion:int(v.expectedVersion,1,2147483646),reason:text(v.reason,L.textReason)};
 const out=action==='assign'?{...base,ownerId:id(v.ownerId)}:action==='resolve'?{...base,recoveryOccurrenceId:id(v.recoveryOccurrenceId),recoveryRunId:id(v.recoveryRunId),recoveryRunVersion:int(v.recoveryRunVersion),rootCause:text(v.rootCause,L.textReason),remediation:text(v.remediation,L.textReason)}:action==='supersede'?{...base,replacementMonitorId:id(v.replacementMonitorId),replacementDefinitionVersion:int(v.replacementDefinitionVersion)}:action==='recovery.request'?{...base,id:id(v.id)}:base;
 return out as IssueCommandInputs[A];
 });}
function page(v:Record<string,unknown>):MonitoringPageQuery {const out:MonitoringPageQuery={};if(Object.hasOwn(v,'limit'))out.limit=int(v.limit,1,L.pageMaximum);if(Object.hasOwn(v,'cursor')){need(typeof v.cursor==='string'&&v.cursor.length>0&&v.cursor.length<=1024&&/^[A-Za-z0-9_.-]+$/.test(v.cursor));out.cursor=v.cursor;}return out;}
export function parseMonitoringPageQuery(input:unknown):MonitoringPageQuery{return checked(input,x=>page(obj(x,[],['limit','cursor'])));}
export function parseMonitorListQuery(input:unknown):MonitorListQuery{return checked(input,x=>{const v=obj(x,[],['limit','cursor','ruleId','state']);return {...page(v),...(Object.hasOwn(v,'ruleId')?{ruleId:id(v.ruleId)}:{}),...(Object.hasOwn(v,'state')?{state:choice(v.state,states)}:{})};});}
export function parseQualityIssueListQuery(input:unknown):QualityIssueListQuery{return checked(input,x=>{const v=obj(x,[],['limit','cursor','monitorId','status','assignedToMe']);return {...page(v),...(Object.hasOwn(v,'monitorId')?{monitorId:id(v.monitorId)}:{}),...(Object.hasOwn(v,'status')?{status:choice(v.status,issueStates)}:{}),...(Object.hasOwn(v,'assignedToMe')?{assignedToMe:bool(v.assignedToMe)}:{})};});}
function evidence(x:unknown):MonitorRunEvidence{const v=obj(x,['occurrenceId','ordinal','runId','runVersion','completionHash','comparisonScopeHash','observedFinishedAt']);return {occurrenceId:id(v.occurrenceId),ordinal:int(v.ordinal),runId:id(v.runId),runVersion:int(v.runVersion),completionHash:hash(v.completionHash),comparisonScopeHash:hash(v.comparisonScopeHash),observedFinishedAt:stamp(v.observedFinishedAt)};}
function observation(x:unknown):MonitorObservation {
 const tag=obj(x,['state'],['occurrenceId','runId','verdict','evidence','reason']);
 if(tag.state==='unobserved'){obj(x,['state']);return {state:'unobserved'};}
 if(tag.state==='pending'){const v=obj(x,['state','occurrenceId','runId']);return {state:'pending',occurrenceId:id(v.occurrenceId),runId:id(v.runId)};}
 if(tag.state==='conclusive'){const v=obj(x,['state','verdict','evidence']);return {state:'conclusive',verdict:choice(v.verdict,['PASS','FAIL']),evidence:evidence(v.evidence)};}
 const v=obj(x,['state','reason','occurrenceId']);need(v.state==='unknown');return {state:'unknown',reason:choice(v.reason,['NO_DATA','EXECUTION_FAILED','CANCELLED','SKIPPED','STALE','BLOCKED']),occurrenceId:nullable(v.occurrenceId,id)};
}
function conclusive(x:unknown){const v=obj(x,['verdict','evidence']);return {verdict:choice(v.verdict,['PASS','FAIL']),evidence:evidence(v.evidence)};}
export function parseMonitorView(input:unknown):QualityMonitorView{return checked(input,x=>{
 const v=obj(x,['id','revision','definitionVersion','definitionHash','definition','state','blocked','nextSlotAt','lastAdmittedOrdinal','lastProjectedOrdinal','currentObservation','lastConclusive','createdAt','createdBy']);
 const d=definition(v.definition);same(v.definition,d);need(hash(v.definitionHash)===digest(d));const admitted=int(v.lastAdmittedOrdinal,0),projected=int(v.lastProjectedOrdinal,0,admitted),current=observation(v.currentObservation),last=nullable(v.lastConclusive,conclusive),state=choice(v.state,states),blocked=nullable(v.blocked,x=>choice(x,blocks));
 if(current.state==='conclusive'){need(projected===admitted&&last!==null);same(last,{verdict:current.verdict,evidence:current.evidence});need(current.evidence.ordinal===projected);}
 if(current.state==='pending')need(projected<admitted);if(last)need(last.evidence.ordinal<=projected);if(blocked!==null)need(current.state==='unknown'||current.state==='pending');
 const nextSlotAt=nullable(v.nextSlotAt,stamp);if(state==='retired')need(nextSlotAt===null);
 return {id:id(v.id),revision:int(v.revision),definitionVersion:int(v.definitionVersion),definitionHash:hash(v.definitionHash),definition:d,state,blocked,nextSlotAt,lastAdmittedOrdinal:admitted,lastProjectedOrdinal:projected,currentObservation:current,lastConclusive:last,createdAt:stamp(v.createdAt),createdBy:id(v.createdBy)};
 });}
export function parseMonitorDefinitionView(input:unknown):MonitorDefinitionView{return checked(input,x=>{const v=obj(x,['monitorId','definitionVersion','definitionHash','definition','createdAt','createdBy']),d=definition(v.definition);same(v.definition,d);need(hash(v.definitionHash)===digest(d));return {monitorId:id(v.monitorId),definitionVersion:int(v.definitionVersion),definitionHash:hash(v.definitionHash),definition:d,createdAt:stamp(v.createdAt),createdBy:id(v.createdBy)};});}
function slots(input:unknown):MonitorSlotRange{const v=obj(input,['firstAt','lastAt','count']),firstAt=stamp(v.firstAt),lastAt=stamp(v.lastAt),count=int(v.count);need(firstAt<=lastAt&&(count===1)===(firstAt===lastAt));return {firstAt,lastAt,count};}
export function parseOccurrence(input:unknown):QualityOccurrence{return checked(input,x=>{
 const v=obj(x,['monitorId','definitionVersion','definitionHash','id','ordinal','rule','executorId','origin','slots','recordedAt','disposition','reason','runId','comparisonScopeHash']);
 const origin=choice(v.origin,['schedule','recovery-request']),range=nullable(v.slots,slots);need((origin==='schedule')===(range!==null));
 const base={monitorId:id(v.monitorId),definitionVersion:int(v.definitionVersion),definitionHash:hash(v.definitionHash),id:id(v.id),ordinal:int(v.ordinal),rule:pin(v.rule),executorId:id(v.executorId),origin,slots:range,recordedAt:stamp(v.recordedAt)};
 if(v.disposition==='skipped'){need(v.runId===null&&v.comparisonScopeHash===null&&origin==='schedule');return {...base,disposition:'skipped',reason:choice(v.reason,skipReasons),runId:null,comparisonScopeHash:null};}
 need(v.disposition==='enqueued'&&v.reason===null&&(range===null||range.count===1));return {...base,disposition:'enqueued',reason:null,runId:id(v.runId),comparisonScopeHash:hash(v.comparisonScopeHash)};
 });}
function comparison(x:unknown):QualityComparisonScope {
 const v=obj(x,['formatVersion','monitorId','executorId','rule','sourceId','sourceVersion','sourceConfigHash','schemaAssetId','tableAssetId','columnAssetId','targetHash','family']);need(v.formatVersion===1);
 const f=obj(v.family,['kind'],['comparison','nullPolicy','rangeHash','freshnessHash','setId','version','publicationHash','codeStatus','codesHash']);let family:QualityComparisonScope['family'];
 if(f.kind==='completeness'){obj(f,['kind']);family={kind:'completeness'};}
 else if(f.kind==='uniqueness'){obj(f,['kind','comparison','nullPolicy']);need(f.comparison==='utf8-exact'&&f.nullPolicy==='exclude');family={kind:'uniqueness',comparison:'utf8-exact',nullPolicy:'exclude'};}
 else if(f.kind==='range'){obj(f,['kind','rangeHash']);family={kind:'range',rangeHash:hash(f.rangeHash)};}
 else if(f.kind==='freshness'){obj(f,['kind','freshnessHash']);family={kind:'freshness',freshnessHash:hash(f.freshnessHash)};}
 else{obj(f,['kind','setId','version','publicationHash','codeStatus','codesHash']);need(f.kind==='reference-allowed-values'&&f.codeStatus==='active');family={kind:'reference-allowed-values',setId:id(f.setId),version:int(f.version),publicationHash:hash(f.publicationHash),codeStatus:'active',codesHash:hash(f.codesHash)};}
 const schemaAssetId=id(v.schemaAssetId),tableAssetId=id(v.tableAssetId),columnAssetId=id(v.columnAssetId);need(new Set([schemaAssetId,tableAssetId,columnAssetId]).size===3);
 return {formatVersion:1,monitorId:id(v.monitorId),executorId:id(v.executorId),rule:pin(v.rule),sourceId:id(v.sourceId),sourceVersion:int(v.sourceVersion),sourceConfigHash:hash(v.sourceConfigHash),schemaAssetId,tableAssetId,columnAssetId,targetHash:hash(v.targetHash),family};
}
export const parseComparisonScope=(input:unknown):QualityComparisonScope=>checked(input,comparison);
/** Never hash unchecked caller data. asOf/config cadence cannot accidentally enter this closed preimage. */
export const comparisonScopeHash=(input:unknown):string=>digest(parseComparisonScope(input));
function resolutionValue(input:unknown):NonNullable<QualityIssueView['resolution']>{const r=obj(input,['rootCause','remediation','reason','evidence','at','by']);return {rootCause:text(r.rootCause,L.textReason),remediation:text(r.remediation,L.textReason),reason:text(r.reason,L.textReason),evidence:evidence(r.evidence),at:stamp(r.at),by:id(r.by)};}
export function parseIssueView(input:unknown):QualityIssueView{return checked(input,x=>{
 const v=obj(x,['id','version','monitorId','comparisonScopeHash','rule','category','severity','tableAssetId','columnAssetId','status','episode','assignedOwnerId','ownerAvailable','openedAt','acknowledgeDueAt','resolveDueAt','opening','lastFailure','recovery','resolution','superseded']);
 need(v.category==='data-quality');const opening=evidence(v.opening),lastFailure=evidence(v.lastFailure),recovery=nullable(v.recovery,evidence),scope=hash(v.comparisonScopeHash);need(opening.comparisonScopeHash===scope&&lastFailure.comparisonScopeHash===scope&&lastFailure.ordinal>=opening.ordinal);if(recovery)need(recovery.comparisonScopeHash===scope&&recovery.ordinal>lastFailure.ordinal);
 const resolution=nullable(v.resolution,resolutionValue);if(resolution)need(resolution.evidence.comparisonScopeHash===scope);
 const superseded=nullable(v.superseded,x=>{const r=obj(x,['reason','replacementMonitorId','replacementDefinitionVersion','at','by']);return {reason:text(r.reason,L.textReason),replacementMonitorId:id(r.replacementMonitorId),replacementDefinitionVersion:int(r.replacementDefinitionVersion),at:stamp(r.at),by:id(r.by)};});
 const status=choice(v.status,issueStates);need((status==='resolved')===(resolution!==null)&&(status==='superseded')===(superseded!==null));if(status==='resolved'||status==='superseded')need(recovery===null);
 if(resolution){same(v.resolution,resolution);need(resolution.evidence.ordinal>lastFailure.ordinal);}if(superseded)same(v.superseded,superseded);
 const openedAt=stamp(v.openedAt),acknowledgeDueAt=stamp(v.acknowledgeDueAt),resolveDueAt=stamp(v.resolveDueAt);need(openedAt<acknowledgeDueAt&&acknowledgeDueAt<=resolveDueAt);
 const tableAssetId=id(v.tableAssetId),columnAssetId=id(v.columnAssetId);need(tableAssetId!==columnAssetId);
 return {id:id(v.id),version:int(v.version),monitorId:id(v.monitorId),comparisonScopeHash:scope,rule:pin(v.rule),category:'data-quality',severity:choice(v.severity,['info','warning','critical']),tableAssetId,columnAssetId,status,episode:int(v.episode),assignedOwnerId:id(v.assignedOwnerId),ownerAvailable:bool(v.ownerAvailable),openedAt,acknowledgeDueAt,resolveDueAt,opening,lastFailure,recovery,resolution,superseded};
 });}
export function parseIssueEvent(input:unknown):QualityIssueEvent{return checked(input,x=>{
 const v=obj(x,['id','issueId','version','episode','kind','monitor','occurrenceId','runId','actorId','at','reason','resolution']);const reason=nullable(v.reason,x=>text(x,L.textReason));if(reason!==null)need(v.reason===reason);
 const occurrenceId=nullable(v.occurrenceId,id),runId=nullable(v.runId,id);need(runId===null||occurrenceId!==null);
 const kind=choice(v.kind,['opened','failed-again','acknowledged','assigned','recovery-available','recovery-invalidated','resolved','reopened','superseded']),actorId=v.actorId==='site:local'?'site:local':id(v.actorId),at=stamp(v.at),resolution=nullable(v.resolution,resolutionValue);
 need((kind==='resolved')===(resolution!==null));if(resolution){same(v.resolution,resolution);need(actorId===resolution.by&&occurrenceId===resolution.evidence.occurrenceId&&runId===resolution.evidence.runId&&at>=resolution.at);}
 return {id:id(v.id),issueId:id(v.issueId),version:int(v.version),episode:int(v.episode),kind,monitor:definitionPin(v.monitor),occurrenceId,runId,actorId,at,reason,resolution};
 });}
export function parseNotification(input:unknown):QualityNotification{return checked(input,x=>{const v=obj(x,['id','eventId','issueId','recipientId','template','createdAt','readAt','version']),createdAt=stamp(v.createdAt),readAt=nullable(v.readAt,stamp);need(readAt===null||readAt>=createdAt);return {id:id(v.id),eventId:id(v.eventId),issueId:id(v.issueId),recipientId:id(v.recipientId),template:choice(v.template,['quality-issue-opened-v1','quality-issue-reopened-v1','quality-issue-assigned-v1','quality-recovery-available-v1','quality-issue-resolved-v1']),createdAt,readAt,version:int(v.version)};});}
export function firstMonitorSlotAtOrAfter(input:unknown,at:unknown):string|null {
 const s=checked(input,schedule),clock=Date.parse(stamp(at)),start=Date.parse(s.startsAt),period=s.intervalSeconds*1000;
 const value=start+Math.max(0,Math.ceil((clock-start)/period))*period;
 if(value>253402300799999||s.endsAt!==null&&value>=Date.parse(s.endsAt))return null;
 return new Date(value).toISOString();
}
export interface DueMonitorSlot {slots:MonitorSlotRange;decision:'eligible'|'skipped';reason:'MISSED'|'MAINTENANCE'|null}
export interface DueMonitorPlan {records:DueMonitorSlot[];nextSlotAt:string|null}
/** Pure bounded scheduling oracle, not permission/capacity/overlap admission. Caller supplies DB clock.
 * Missed ranges are compressed arithmetically and split at maintenance boundaries, never per slot. */
export function planDueMonitorSlots(input:unknown):DueMonitorPlan {return checked(input,x=>{
 const v=obj(x,['schedule','maintenance','nextSlotAt','now'],['maximumRecords']),s=schedule(v.schedule),m=windows(v.maintenance),next=nullable(v.nextSlotAt,stamp),now=Date.parse(stamp(v.now)),maximum=Object.hasOwn(v,'maximumRecords')?int(v.maximumRecords,1,8):8;
 if(next===null)return {records:[],nextSlotAt:null};const start=Date.parse(s.startsAt),period=s.intervalSeconds*1000,first=Date.parse(next);need(first>=start&&(first-start)%period===0&&(s.endsAt===null||first<Date.parse(s.endsAt)));
 if(first>now)return {records:[],nextSlotAt:next};
 const end=s.endsAt===null?253402300800000:Date.parse(s.endsAt),last=Math.floor((Math.min(now,end-1)-start)/period);let index=(first-start)/period;const records:DueMonitorSlot[]=[];
 const maintenance=m.map(w=>({from:Math.max(0,Math.ceil((Date.parse(w.from)-start)/period)),until:Math.max(0,Math.ceil((Date.parse(w.until)-start)/period))}));
 const stampAt=(i:number)=>new Date(start+i*period).toISOString();
 while(index<=last&&records.length<maximum){const window=maintenance.find(w=>w.from<=index&&index<w.until);let through=last,reason:'MISSED'|'MAINTENANCE'|null;
  if(window){reason='MAINTENANCE';through=Math.min(last,window.until-1);}
  else{const future=maintenance.find(w=>w.from>index);if(future)through=Math.min(through,future.from-1);const eligible=now<end&&now-(start+last*period)<=s.lateGraceSeconds*1000;
   if(index===last&&eligible){reason=null;through=index;}else{reason='MISSED';if(eligible)through=Math.min(through,last-1);}}
  need(through>=index);const count=int(through-index+1);records.push({slots:{firstAt:stampAt(index),lastAt:stampAt(through),count},decision:reason===null?'eligible':'skipped',reason});index=through+1;
 }
 const after=start+index*period;return {records,nextSlotAt:after>=end||after>253402300799999?null:stampAt(index)};
 });}

/** Exact time-only oracle for scheduled freshness. This grants no current authority:
 * callers must also prove the immutable run/receipt and latest authorized scope.
 * UTC epoch microseconds are strings, never rounded JavaScript numbers. */
export interface MonitorFreshnessTimeDecision {
 valid:boolean;reason:'eligible'|'expired'|'clock-before-recorded-marker'|'evidence-unavailable';
 remainingAtObservationUs:string|null;validThroughUs:string|null;
}
export function monitorFreshnessTimeDecision(input:unknown):MonitorFreshnessTimeDecision{return checked(input,x=>{
 const v=obj(x,['claimedAtUs','finishedAtUs','projectedAtUs','observedFinishedAtUs','evaluatedAtUs','measuredAgeUs','maximumAgeSeconds','recoveryMaximumAgeSeconds']);
 const exact=(value:unknown,min:bigint,max:bigint):bigint=>{need(typeof value==='string'&&value.length<=19&&/^(?:0|-?[1-9][0-9]*)$/.test(value));const n=BigInt(value);need(n>=min&&n<=max);return n;};
 const instant=(value:unknown)=>exact(value,BigInt(FRESHNESS_LIMITS.minimumEpochMicroseconds),BigInt(FRESHNESS_LIMITS.maximumEpochMicroseconds));
 const C=instant(v.claimedAtUs),F=instant(v.finishedAtUs),P=instant(v.projectedAtUs),O=instant(v.observedFinishedAtUs),T=instant(v.evaluatedAtUs);
 const a=exact(v.measuredAgeUs,-BigInt(FRESHNESS_LIMITS.maximumAbsoluteAgeMicroseconds),BigInt(FRESHNESS_LIMITS.maximumAbsoluteAgeMicroseconds));
 const A=BigInt(int(v.maximumAgeSeconds,FRESHNESS_LIMITS.minimumAgeSeconds,FRESHNESS_LIMITS.maximumAgeSeconds))*1000000n,R=BigInt(int(v.recoveryMaximumAgeSeconds,L.minimumIntervalSeconds,L.maximumRecoveryAgeSeconds))*1000000n;
 const B=A-(a>0n?a:0n);
 if(B<0n||C>F)return {valid:false,reason:'evidence-unavailable',remainingAtObservationUs:null,validThroughUs:null};
 const D=C+B<O+R?C+B:O+R;
 // projected_at is retained at millisecond precision; never require F<=P.
 const reason=T<C||T<F||T<P||T<O?'clock-before-recorded-marker':T-C>B||T-O>R?'expired':'eligible';
 return {valid:reason==='eligible',reason,remainingAtObservationUs:String(B),validThroughUs:String(D)};
});}
