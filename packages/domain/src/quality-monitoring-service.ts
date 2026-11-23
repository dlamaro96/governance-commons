// SPDX-License-Identifier: Apache-2.0
import {createHash} from 'node:crypto';
import {sql,type Tx} from '../../db/src/index.ts';
import {Problem,type Principal} from '../../authz/src/index.ts';
import {modelPersistence} from './model-service.ts';
import {signedCursor} from './cursor.ts';
import {qualityObject,qualityId,qualityInteger} from './quality.ts';
import {monitoringInvalid,parsePublishMonitorInput,parseMonitorStateInput,parseIssueCommandInput,parseMonitoringPageQuery,parseMonitorListQuery,parseQualityIssueListQuery,parseMonitorView,parseMonitorDefinitionView,parseOccurrence,parseIssueView,parseIssueEvent,parseNotification,monitorDefinitionHash,type IssueCommandInputs} from './quality-monitoring.ts';
import type {QualityMonitorView,MonitorDefinitionView,QualityOccurrence,QualityIssueView,QualityIssueEvent,QualityNotification,MonitoringPage,MonitoringPageQuery,MonitorListQuery,QualityIssueListQuery,MonitoringWorkItem,MonitoringWorkResult} from './quality-monitoring-contracts.ts';
const unavailable=()=>new Problem(404,'MONITOR_UNAVAILABLE','The monitoring resource or its evidence is unavailable.');
const integrity=()=>new Problem(500,'MONITOR_STORAGE_INVALID','The monitoring operation could not be completed.');
const retry=()=>new Problem(503,'MONITOR_RETRY','A stable monitoring window was unavailable. Retry with the same idempotency key.');
const pageInvalid=()=>new Problem(400,'PAGE_INVALID','This monitoring page is invalid. Start a new listing.');
const forbidden=()=>new Problem(403,'MONITOR_FORBIDDEN','Your current permissions do not allow this monitoring operation.');
const deadlines=new WeakMap<Tx,number>();
/** One original command deadline; nested reads never reset it. No pre-authority locks. */
export async function monitoringQuery<T>(tx:Tx,work:()=>Promise<T>):Promise<T>{
 let deadline=deadlines.get(tx);if(deadline===undefined){deadline=performance.now()+30000;deadlines.set(tx,deadline);}
 const remaining=Math.floor(deadline-performance.now());if(remaining<1)throw retry();
 await sql`select set_config('statement_timeout',${String(Math.min(15000,remaining))},true),set_config('lock_timeout',${String(Math.min(2000,remaining))},true)`.execute(tx);
 const result=await work();if(performance.now()>=deadline)throw retry();return result;
}
export function monitoringFailure(error:unknown):Problem{
 if(error instanceof Problem){if(error.code==='FORBIDDEN')return forbidden();return error;}
 const e=error as {code?:unknown;message?:unknown}|null,code=typeof e?.code==='string'?e.code:'',message=typeof e?.message==='string'?e.message:'';
 if(['55P03','40P01','57014'].includes(code))return retry();
 if(code==='P0002')return unavailable();if(code==='42501')return forbidden();
 if(code==='40001')return ['VERSION_CONFLICT','IDEMPOTENCY_CONFLICT','MONITOR_PIN_STALE','RECOVERY_UNAVAILABLE'].includes(message)?new Problem(409,message,'The monitoring state changed. Reload before continuing.'):retry();
 if(['22023','22007','22008','22P02','22003'].includes(code))return monitoringInvalid();
 if(code==='0A000'&&message==='MONITOR_RULE_UNSUPPORTED')return new Problem(422,'MONITOR_RULE_UNSUPPORTED','Scheduled monitoring is not yet supported for this quality rule family.');
 if(code==='54000')return new Problem(422,'MONITOR_LIMIT','The monitoring operation exceeds its supported bounds.');
 return integrity();
}
function inputId(v:unknown):string{try{qualityId(v);return v;}catch{throw monitoringInvalid();}}
function integer(v:unknown,min=1,max=2147483647):number{try{qualityInteger(v,min,max);return v;}catch{throw monitoringInvalid();}}
function record(v:unknown,keys:readonly string[]):Record<string,unknown>{try{return qualityObject(v,keys);}catch{throw monitoringInvalid();}}
function stored<T>(work:()=>T):T{try{return work();}catch{throw integrity();}}
function bounded<T>(v:T):T{if(Buffer.byteLength(JSON.stringify(v))>524288)throw new Problem(422,'MONITOR_LIMIT','This monitoring page exceeds its supported bounds.');return v;}
async function authorize(tx:Tx,p:Principal,extra:readonly string[]=[]):Promise<void>{
 try{await monitoringQuery(tx,()=>modelPersistence.authorize(tx,p,['catalog:read','quality:read',...extra]));}catch(e){throw monitoringFailure(e);}
}
type Listing='monitors'|'definitions'|'occurrences'|'issues'|'events'|'notifications';
function paging(p:Principal,kind:Listing,parent:string|null,q:MonitoringPageQuery,filters:unknown=[]){
 const limit=q.limit??25,codec=signedCursor(process.env.SESSION_KEY,'quality-monitoring-v1');
 const binding=createHash('sha256').update(JSON.stringify([p.tenantId,p.id,kind,parent,filters,limit])).digest('hex');
 const numeric=['definitions','occurrences','events'].includes(kind);let after:string|number|null=null;
 if(q.cursor)try{const v=codec.decode(q.cursor);if(!Array.isArray(v)||v.length!==3||v[0]!==1||v[1]!==binding)throw 0;after=numeric?integer(v[2]):inputId(v[2]);}catch{throw pageInvalid();}
 return {limit,after,next:(key:string|number)=>codec.encode([1,binding,key])};
}
async function historicalParent(tx:Tx,p:Principal,id:string):Promise<void>{
 const row=(await monitoringQuery(tx,()=>sql`select 1 from public.quality_monitor_versions v where v.tenant_id=${p.tenantId}::uuid and v.monitor_id=${id}::uuid and public.gc_quality_monitor_visible(v.monitor_id,${p.id}::uuid,v.version) limit 1`.execute(tx))).rows[0];if(!row)throw unavailable();
}
// All fragments are fixed internal SQL. User-controlled IDs/filters remain parameters.
function listing(p:Principal,kind:Listing,parent:string|null,query:MonitorListQuery|QualityIssueListQuery){
 if(kind==='monitors')return {table:sql`public.quality_monitors r`,key:sql`r.id`,value:sql`public.gc_quality_monitor_view(r.id)`,predicate:sql`r.tenant_id=${p.tenantId}::uuid and public.gc_quality_monitor_visible(r.id,${p.id}::uuid) and (${(query as MonitorListQuery).ruleId??null}::uuid is null or r.rule_id=${(query as MonitorListQuery).ruleId??null}::uuid) and (${(query as MonitorListQuery).state??null}::text is null or r.state=${(query as MonitorListQuery).state??null})`};
 if(kind==='definitions')return {table:sql`public.quality_monitor_versions r`,key:sql`r.version`,value:sql`public.gc_quality_monitor_definition_view(r.monitor_id,r.version)`,predicate:sql`r.tenant_id=${p.tenantId}::uuid and r.monitor_id=${parent}::uuid and public.gc_quality_monitor_visible(r.monitor_id,${p.id}::uuid,r.version)`};
 if(kind==='occurrences')return {table:sql`public.quality_monitor_occurrences r`,key:sql`r.ordinal`,value:sql`public.gc_quality_occurrence_view(r.id)`,predicate:sql`r.tenant_id=${p.tenantId}::uuid and r.monitor_id=${parent}::uuid and public.gc_quality_occurrence_visible(r.id,${p.id}::uuid)`};
 if(kind==='issues')return {table:sql`public.quality_monitor_incidents r`,key:sql`r.id`,value:sql`public.gc_quality_issue_view(r.id)`,predicate:sql`r.tenant_id=${p.tenantId}::uuid and public.gc_quality_issue_visible(r.id,${p.id}::uuid) and (${(query as QualityIssueListQuery).monitorId??null}::uuid is null or r.monitor_id=${(query as QualityIssueListQuery).monitorId??null}::uuid) and (${(query as QualityIssueListQuery).status??null}::text is null or r.status=${(query as QualityIssueListQuery).status??null}) and (not ${(query as QualityIssueListQuery).assignedToMe??false}::boolean or r.assigned_owner_id=${p.id}::uuid)`};
 if(kind==='events')return {table:sql`public.quality_monitor_incident_events r`,key:sql`r.version`,value:sql`public.gc_quality_issue_event_view(r.id)`,predicate:sql`r.tenant_id=${p.tenantId}::uuid and r.issue_id=${parent}::uuid and public.gc_quality_issue_event_visible(r.id,${p.id}::uuid)`};
 return {table:sql`public.quality_monitor_notifications r`,key:sql`r.id`,value:sql`public.gc_quality_notification_view(r.id)`,predicate:sql`r.tenant_id=${p.tenantId}::uuid and r.recipient_id=${p.id}::uuid and r.suppressed is null and public.gc_quality_notification_visible(r.id,${p.id}::uuid)`};
}
async function list<T>(tx:Tx,p:Principal,kind:Listing,parent:string|null,q:MonitoringPageQuery,filters:unknown,parse:(v:unknown)=>T):Promise<MonitoringPage<T>>{
 const page=paging(p,kind,parent,q,filters),l=listing(p,kind,parent,q);await authorize(tx,p);
 if(kind==='definitions'||kind==='occurrences')await historicalParent(tx,p,parent!);
 if(kind==='events')await currentVisibility(tx,p,'issue',parent!);
 const numeric=['definitions','occurrences','events'].includes(kind),after=numeric?sql`${page.after}::integer`:sql`${page.after}::uuid`;
 const rows=(await monitoringQuery(tx,()=>sql<{key:unknown;value:unknown}>`select ${l.key} as key,${l.value} as value from ${l.table} where ${l.predicate} and (${after} is null or ${l.key}>${after}) order by ${l.key} limit ${page.limit+1}`.execute(tx))).rows;
 await authorize(tx,p);
 if(kind==='definitions'||kind==='occurrences')await historicalParent(tx,p,parent!);
 if(kind==='events')await currentVisibility(tx,p,'issue',parent!);
 // Recheck every selected key, including look-ahead, before parsing or emitting a cursor.
 const keys=stored(()=>{if(rows.length>page.limit+1)throw 0;return rows.map(r=>numeric?integer(r.key):inputId(r.key));});
 if(keys.length){const values=numeric?sql`${keys}::integer[]`:sql`${keys}::uuid[]`;
  const visible=(await monitoringQuery(tx,()=>sql<{key:unknown}>`select ${l.key} as key from ${l.table} where ${l.predicate} and ${l.key}=any(${values}) order by ${l.key}`.execute(tx))).rows;
  if(visible.length!==keys.length||visible.some((r,i)=>r.key!==keys[i]))throw unavailable();
 }
 const items=stored(()=>rows.map((r,i)=>{if(i&&keys[i]<=keys[i-1]||page.after!==null&&keys[i]<=page.after)throw 0;const v=parse(r.value);
  const expected=kind==='definitions'?(v as MonitorDefinitionView).definitionVersion:kind==='occurrences'?(v as QualityOccurrence).ordinal:kind==='events'?(v as QualityIssueEvent).version:(v as {id:string}).id;
  if(expected!==keys[i]||parent!==null&&(kind==='events'?(v as QualityIssueEvent).issueId:(v as MonitorDefinitionView|QualityOccurrence).monitorId)!==parent)throw 0;
  if(kind==='notifications'&&(v as QualityNotification).recipientId!==p.id)throw 0;return v;}));
 return bounded({items:items.slice(0,page.limit),nextCursor:items.length>page.limit?page.next(keys[page.limit-1]):null});
}
export function listQualityMonitors(tx:Tx,p:Principal,input:unknown={}):Promise<MonitoringPage<QualityMonitorView>>{const q=parseMonitorListQuery(input);return list(tx,p,'monitors',null,q,[q.ruleId??null,q.state??null],parseMonitorView);}
export function listMonitorDefinitions(tx:Tx,p:Principal,id:string,input:unknown={}):Promise<MonitoringPage<MonitorDefinitionView>>{inputId(id);const q=parseMonitoringPageQuery(input);return list(tx,p,'definitions',id,q,[],parseMonitorDefinitionView);}
export function listMonitorOccurrences(tx:Tx,p:Principal,id:string,input:unknown={}):Promise<MonitoringPage<QualityOccurrence>>{inputId(id);const q=parseMonitoringPageQuery(input);return list(tx,p,'occurrences',id,q,[],parseOccurrence);}
export function listQualityIssues(tx:Tx,p:Principal,input:unknown={}):Promise<MonitoringPage<QualityIssueView>>{const q=parseQualityIssueListQuery(input);return list(tx,p,'issues',null,q,[q.monitorId??null,q.status??null,q.assignedToMe??false],parseIssueView);}
export function listQualityIssueEvents(tx:Tx,p:Principal,id:string,input:unknown={}):Promise<MonitoringPage<QualityIssueEvent>>{inputId(id);const q=parseMonitoringPageQuery(input);return list(tx,p,'events',id,q,[],parseIssueEvent);}
export function listQualityNotifications(tx:Tx,p:Principal,input:unknown={}):Promise<MonitoringPage<QualityNotification>>{const q=parseMonitoringPageQuery(input);return list(tx,p,'notifications',null,q,[],parseNotification);}
async function currentVisibility(tx:Tx,p:Principal,kind:'monitor'|'definition'|'issue'|'notification'|'occurrence',id:string,version?:number):Promise<void>{
 const predicate=kind==='definition'?sql`public.gc_quality_monitor_visible(${id}::uuid,${p.id}::uuid,${version}::integer)`:kind==='monitor'?sql`public.gc_quality_monitor_visible(${id}::uuid,${p.id}::uuid)`:kind==='issue'?sql`public.gc_quality_issue_visible(${id}::uuid,${p.id}::uuid)`:kind==='notification'?sql`public.gc_quality_notification_visible(${id}::uuid,${p.id}::uuid)`:sql`public.gc_quality_occurrence_visible(${id}::uuid,${p.id}::uuid)`;
 const row=(await monitoringQuery(tx,()=>sql<{visible:boolean}>`select ${predicate} as visible`.execute(tx))).rows[0];if(row?.visible!==true)throw unavailable();
}
async function detail<T>(tx:Tx,p:Principal,kind:'monitor'|'definition'|'issue',id:string,parse:(v:unknown)=>T,version?:number):Promise<T>{
 inputId(id);if(version!==undefined)integer(version);await authorize(tx,p);await currentVisibility(tx,p,kind,id,version);
 const expression=kind==='monitor'?sql`public.gc_quality_monitor_view(${id}::uuid)`:kind==='definition'?sql`public.gc_quality_monitor_definition_view(${id}::uuid,${version}::integer)`:sql`public.gc_quality_issue_view(${id}::uuid)`;
 const raw=(await monitoringQuery(tx,()=>sql<{value:unknown}>`select ${expression} as value`.execute(tx))).rows[0]?.value;
 await authorize(tx,p);await currentVisibility(tx,p,kind,id,version);
 return stored(()=>{const v=parse(raw);if(kind==='definition'){const d=v as MonitorDefinitionView;if(d.monitorId!==id||d.definitionVersion!==version)throw 0;}else if((v as {id:string}).id!==id)throw 0;return v;});
}
export function getQualityMonitor(tx:Tx,p:Principal,id:string){return detail(tx,p,'monitor',id,parseMonitorView);}
export function getMonitorDefinition(tx:Tx,p:Principal,id:string,version:number){integer(version);return detail(tx,p,'definition',id,parseMonitorDefinitionView,version);}
export function getQualityIssue(tx:Tx,p:Principal,id:string){return detail(tx,p,'issue',id,parseIssueView);}
async function command(tx:Tx,operation:string,key:string,body:unknown,correlation:string,resultKey:string):Promise<unknown>{
 if(typeof key!=='string'||key.length<8||key.length>128||/[\u0000-\u001f\u007f]/.test(key)||typeof correlation!=='string'||!correlation||correlation.length>128||/[\u0000-\u001f\u007f]/.test(correlation))throw monitoringInvalid();
 const value=(await monitoringQuery(tx,()=>sql<{value:unknown}>`select public.gc_quality_monitor_command(${operation},${key},${JSON.stringify(body)}::jsonb,${correlation}) as value`.execute(tx))).rows[0]?.value;
 return stored(()=>record(value,[resultKey])[resultKey]);
}
export async function publishQualityMonitor(tx:Tx,p:Principal,input:unknown,key:string,correlation:string){
 const body=parsePublishMonitorInput(input);await authorize(tx,p,['quality:write','quality:execute']);
 const raw=await command(tx,'quality.monitor.publish',key,body,correlation,'monitor');
 await authorize(tx,p,['quality:write','quality:execute']);await currentVisibility(tx,p,'monitor',body.id);
 const monitor=stored(()=>parseMonitorView(raw));if(monitor.id!==body.id||monitor.revision!==body.expectedRevision+1||monitor.definitionHash!==monitorDefinitionHash(body.definition)||monitor.definition.executorId!==p.id)throw integrity();return {monitor};
}
export async function changeQualityMonitorState(tx:Tx,p:Principal,monitorId:string,input:unknown,key:string,correlation:string){
 inputId(monitorId);const body=parseMonitorStateInput(input),extra=body.action==='resume'?['quality:write','quality:execute']:['quality:write'];await authorize(tx,p,extra);
 const raw=await command(tx,'quality.monitor.state',key,{monitorId,...body},correlation,'monitor');
 await authorize(tx,p,extra);await currentVisibility(tx,p,'monitor',monitorId);
 const monitor=stored(()=>parseMonitorView(raw));if(monitor.id!==monitorId||monitor.revision!==body.expectedRevision+1||monitor.state!==({pause:'paused',resume:'enabled',retire:'retired'} as const)[body.action])throw integrity();return {monitor};
}
export async function commandQualityIssue<A extends keyof IssueCommandInputs>(tx:Tx,p:Principal,issueId:string,action:A,input:unknown,key:string,correlation:string):Promise<A extends 'recovery.request'?{occurrence:QualityOccurrence}:{issue:QualityIssueView}>{
 inputId(issueId);const body=parseIssueCommandInput(action,input),recovery=action==='recovery.request',extra=recovery?['quality:execute']:['quality:write'];await authorize(tx,p,extra);
 const raw=await command(tx,'quality.issue.'+action,key,{issueId,...body},correlation,recovery?'occurrence':'issue');
 await authorize(tx,p,extra);await currentVisibility(tx,p,'issue',issueId);
 if(recovery){const occurrence=stored(()=>parseOccurrence(raw));if(occurrence.id!==(body as IssueCommandInputs['recovery.request']).id||occurrence.origin!=='recovery-request'||occurrence.disposition!=='enqueued'||occurrence.executorId!==p.id)throw integrity();await currentVisibility(tx,p,'occurrence',occurrence.id);return {occurrence} as A extends 'recovery.request'?{occurrence:QualityOccurrence}:{issue:QualityIssueView};}
 const issue=stored(()=>parseIssueView(raw));if(issue.id!==issueId||issue.version!==body.expectedVersion+1)throw integrity();
 if(action==='acknowledge'&&issue.status!=='acknowledged'||action==='assign'&&issue.assignedOwnerId!==(body as IssueCommandInputs['assign']).ownerId||action==='resolve'&&(issue.status!=='resolved'||issue.resolution?.evidence.occurrenceId!==(body as IssueCommandInputs['resolve']).recoveryOccurrenceId||issue.resolution?.evidence.runId!==(body as IssueCommandInputs['resolve']).recoveryRunId||issue.resolution?.evidence.runVersion!==(body as IssueCommandInputs['resolve']).recoveryRunVersion)||action==='supersede'&&(issue.status!=='superseded'||issue.superseded?.replacementMonitorId!==(body as IssueCommandInputs['supersede']).replacementMonitorId||issue.superseded?.replacementDefinitionVersion!==(body as IssueCommandInputs['supersede']).replacementDefinitionVersion))throw integrity();
 return {issue} as A extends 'recovery.request'?{occurrence:QualityOccurrence}:{issue:QualityIssueView};
}
export async function markQualityNotificationRead(tx:Tx,p:Principal,notificationId:string,input:unknown,key:string,correlation:string){
 inputId(notificationId);const v=record(input,['expectedVersion']),expectedVersion=integer(v.expectedVersion,1,2147483646);await authorize(tx,p);
 const raw=await command(tx,'quality.notification.mark-read',key,{notificationId,expectedVersion},correlation,'notification');
 await authorize(tx,p);await currentVisibility(tx,p,'notification',notificationId);
 const notification=stored(()=>parseNotification(raw));if(notification.id!==notificationId||notification.recipientId!==p.id||notification.version!==expectedVersion+1||notification.readAt===null)throw integrity();return {notification};
}
function workResult(raw:unknown,monitorId:string):MonitoringWorkResult{return stored(()=>{const v=record(raw,['monitorId','state','nextWakeAt','occurrenceId','runId']);if(inputId(v.monitorId)!==monitorId||!['idle','advanced','blocked','retry'].includes(v.state as string))throw 0;
 if(v.nextWakeAt!==null&&(typeof v.nextWakeAt!=='string'||!/^(?!0000)\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(v.nextWakeAt)||!Number.isFinite(Date.parse(v.nextWakeAt))||new Date(v.nextWakeAt).toISOString()!==v.nextWakeAt))throw 0;
 const occurrenceId=v.occurrenceId===null?null:inputId(v.occurrenceId),runId=v.runId===null?null:inputId(v.runId);if(runId!==null&&occurrenceId===null)throw 0;
 return {monitorId,state:v.state as MonitoringWorkResult['state'],nextWakeAt:v.nextWakeAt as string|null,occurrenceId,runId};});}
export async function pendingMonitoringWork(tx:Tx,tenantId:string):Promise<{items:MonitoringWorkItem[]}>{
 inputId(tenantId);const raw=(await monitoringQuery(tx,()=>sql<{value:unknown}>`select public.gc_quality_monitor_work() as value`.execute(tx))).rows[0]?.value;
 return stored(()=>{const v=record(raw,['items']);if(!Array.isArray(v.items)||v.items.length>50)throw 0;const seen=new Set<string>();return {items:v.items.map(value=>{const item=record(value,['tenantId','monitorId','work']),monitorId=inputId(item.monitorId);if(item.tenantId!==tenantId||!['tick','reconcile'].includes(item.work as string)||seen.has(monitorId+':'+item.work))throw 0;seen.add(monitorId+':'+item.work);return {tenantId,monitorId,work:item.work as MonitoringWorkItem['work']};})};});
}
export async function dispatchMonitoringWork(tx:Tx,monitorId:string,work:'tick'|'reconcile'):Promise<MonitoringWorkResult>{
 inputId(monitorId);if(work!=='tick'&&work!=='reconcile')throw monitoringInvalid();const expression=work==='tick'?sql`public.gc_quality_monitor_tick(${monitorId}::uuid)`:sql`public.gc_quality_monitor_reconcile(${monitorId}::uuid)`;
 const raw=(await monitoringQuery(tx,()=>sql<{value:unknown}>`select ${expression} as value`.execute(tx))).rows[0]?.value;return workResult(raw,monitorId);
}
