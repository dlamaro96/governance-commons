// SPDX-License-Identifier: Apache-2.0
import {createHash} from 'node:crypto';
import {sql,lockTenantLedger,type Tx} from '../../db/src/index.ts';
import {Problem,type Principal} from '../../authz/src/index.ts';
import {modelPersistence} from './model-service.ts';
import {signedCursor} from './cursor.ts';
import {parseApprovalDefinition} from './approval.ts';
import {parseGlossaryPublication} from './glossary.ts';
import type {ApprovalDefinition} from './approval-contracts.ts';
import type {GlossaryPublicationInput} from './glossary-contracts.ts';
import type {GlossaryPublicationReceipt} from './glossary-publication-service.ts';
import type {ClassificationApprovalPayload,ClassificationApprovalResult} from './classification-contracts.ts';
import {parseClassificationApprovalPayload,parseClassificationApprovalResult} from './classification-service.ts';

const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const key=/^(?!(?:__proto__|constructor|prototype)$)[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const digest=/^[a-f0-9]{64}$/;
const statuses=['pending','ready','rejected','cancelled','expired','succeeded','failed'] as const;
export type ApprovalStatus=typeof statuses[number];
export interface ApprovalPage {limit?:number;cursor?:string;q?:string}
export interface ApprovalRequestPage {limit?:number;cursor?:string;status?:ApprovalStatus;assignedToMe?:boolean}
export interface ApprovalDefinitionView {definition:ApprovalDefinition;definitionHash:string;currentVersion:number;createdAt:string;createdBy:string}
export interface ApprovalTaskView {id:string;stageIndex:number;assignment:string;assignedIdentityId:string;version:number;status:'waiting'|'open'|'decided'|'cancelled';openedAt:string|null;expiresAt:string|null}
export interface ApprovalDecisionView {id:string;taskId:string;taskVersion:number;actorId:string;decision:'approve'|'reject';reason:string;decidedAt:string}
export interface ApprovalRequestSummary {
 id:string;binding:'glossary.publish'|'classification.review';resourceId:string;resourceVersion:number|null;proposalDigest:string;
 workflowId:string;workflowVersion:number;workflowHash:string;requesterId:string;stageIndex:number;version:number;status:ApprovalStatus;
 expiresAt:string;createdAt:string;updatedAt:string;preconditionsCurrent:boolean;
}
interface ApprovalRequestDetail extends Omit<ApprovalRequestSummary,'binding'> {
 workflow:ApprovalDefinitionView;tasks:ApprovalTaskView[];decisions:ApprovalDecisionView[];errorCode:string|null;
}
export type ApprovalRequestView=ApprovalRequestDetail & (
 {binding:'glossary.publish';payload:GlossaryPublicationInput;result:GlossaryPublicationReceipt|null}
 |{binding:'classification.review';payload:ClassificationApprovalPayload;result:ClassificationApprovalResult|null});
export interface ApprovalDecisionInput {proposalDigest:string;taskId:string;taskVersion:number;decision:'approve'|'reject';reason:string}
export interface ApprovalCancelInput {proposalDigest:string;reason:string}
type Row=Record<string,any>;
const read=['catalog:read','catalog:write'];
const unavailable=()=>new Problem(404,'APPROVAL_UNAVAILABLE','The approval request or its referenced resources are unavailable.');
const invalid=()=>new Problem(400,'APPROVAL_INPUT_INVALID','Provide exactly the declared approval fields and values.');
const pageInvalid=()=>new Problem(400,'APPROVAL_PAGE_INVALID','This approval page is invalid. Start a new listing.');
const integrity=()=>new Problem(500,'APPROVAL_STORAGE_INVALID','The approval operation could not be completed.');
const retry=()=>new Problem(503,'APPROVAL_RETRY','A stable execution window was unavailable. Retry with the same idempotency key.');
const deadlines=new WeakMap<Tx,number>();
/** All nested queries share one original budget; no per-query deadline reset. */
export async function approvalQuery<T>(tx:Tx,work:()=>Promise<T>):Promise<T>{
 let deadline=deadlines.get(tx);if(deadline===undefined){deadline=performance.now()+30000;deadlines.set(tx,deadline);}
 const remaining=Math.floor(deadline-performance.now());if(remaining<1)throw retry();
 await sql`select set_config('statement_timeout',${String(remaining)},true),set_config('lock_timeout',${String(Math.min(5000,remaining))},true)`.execute(tx);
 const value=await work();if(performance.now()>=deadline)throw retry();return value;
}
export function approvalFailure(error:unknown):Problem {
 if(error instanceof Problem)return error;
 const source=error as {code?:unknown;message?:unknown}|null;
 const code=typeof source?.code==='string'?source.code:'',message=typeof source?.message==='string'?source.message:'';
 if(['55P03','40P01','57014'].includes(code))return retry();
 if(code==='40001')return ['IDEMPOTENCY_CONFLICT','VERSION_CONFLICT','WORKFLOW_PIN_STALE','APPROVAL_STATE_CONFLICT','APPROVAL_TASK_CONFLICT'].includes(message)
  ?new Problem(409,message,'The approval state changed. Reload the request before continuing.'):retry();
 if(code==='P0002')return unavailable();
 if(code==='42501')return new Problem(403,'APPROVAL_FORBIDDEN','Your current permissions do not allow this approval operation.');
 if(code==='23505')return new Problem(409,'APPROVAL_CONFLICT','The approval command conflicts with an existing record.');
 if(['22023','22007','22008','22P02','22003'].includes(code))return invalid();
 if(code==='54000')return new Problem(422,'APPROVAL_LIMIT','The approval operation exceeds its supported bounds.');
 return integrity();
}
function exact(value:unknown,required:readonly string[],optional:readonly string[]=[]):Record<string,unknown>{
 try{
  if(!value||typeof value!=='object'||Array.isArray(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value)))throw 0;
  const keys=Reflect.ownKeys(value);if(keys.length>required.length+optional.length||required.some(k=>!keys.includes(k)))throw 0;
  const result:Record<string,unknown>=Object.create(null);
  for(const name of keys){if(typeof name!=='string'||![...required,...optional].includes(name))throw 0;
   const d=Object.getOwnPropertyDescriptor(value,name);if(!d?.enumerable||!Object.hasOwn(d,'value'))throw 0;result[name]=d.value;}
  return result;
 }catch{throw invalid();}
}
function id(value:unknown,pattern=uuid):asserts value is string {if(typeof value!=='string'||!pattern.test(value))throw invalid();}
function version(value:unknown,zero=false):asserts value is number {if(!Number.isInteger(value)||Object.is(value,-0)||(value as number)<(zero?0:1)||(value as number)>2147483647)throw invalid();}
export function normalizeApprovalReason(value:unknown):string {
 if(typeof value!=='string'||value.length>4096||/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value))throw invalid();
 const result=value.normalize('NFC').trim();if(!result||result.length>4096)throw invalid();return result;
}
function iso(value:unknown):string {const date=value instanceof Date?value:typeof value==='string'?new Date(value):null;if(!date||!Number.isFinite(date.getTime()))throw integrity();return date.toISOString();}
async function authorize(tx:Tx,p:Principal,actions:readonly string[]){await approvalQuery(tx,()=>modelPersistence.authorize(tx,p,actions));}
function storedDefinition(row:Row):ApprovalDefinitionView {
 const parsed=parseApprovalDefinition(row.definition);
 if(!parsed.ok||parsed.value.id!==row.workflow_id||parsed.value.version!==row.version||modelPersistence.hash(parsed.value)!==row.definition_hash)throw integrity();
 return {definition:parsed.value,definitionHash:row.definition_hash,currentVersion:row.current_version,createdAt:iso(row.created_at),createdBy:row.created_by};
}
function page(p:Principal,query:unknown,kind:'definitions'|'requests'){
 const value=exact(query,[],kind==='definitions'?['limit','cursor','q']:['limit','cursor','status','assignedToMe']);
 const limit=value.limit===undefined?25:value.limit;
 if(!Number.isInteger(limit)||(limit as number)<1||(limit as number)>100)throw pageInvalid();
 if(value.cursor!==undefined&&(typeof value.cursor!=='string'||!value.cursor.length||value.cursor.length>1024))throw pageInvalid();
 const q=value.q===undefined?'':value.q,status=value.status===undefined?'':value.status,assigned=value.assignedToMe===undefined?false:value.assignedToMe;
 if(typeof q!=='string'||q.length>120||/[\u0000-\u001f\u007f-\u009f]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(q)
  ||typeof status!=='string'||status!==''&&!statuses.includes(status as ApprovalStatus)||typeof assigned!=='boolean')throw pageInvalid();
 const codec=signedCursor(process.env.SESSION_KEY,`approval-${kind}-v1`);
 const binding=createHash('sha256').update(JSON.stringify([p.tenantId,p.id,kind,limit,q,status,assigned])).digest('hex');
 let after:string|null=null;
 if(value.cursor!==undefined)try{const cursor=codec.decode(value.cursor as string);
  if(!Array.isArray(cursor)||cursor.length!==3||cursor[0]!==1||cursor[1]!==binding||typeof cursor[2]!=='string'||!(kind==='definitions'?key:uuid).test(cursor[2]))throw 0;after=cursor[2];
 }catch{throw pageInvalid();}
 return {limit:limit as number,q,status,assigned,after,next:(last:string)=>codec.encode([1,binding,last])};
}
export async function listApprovalDefinitions(tx:Tx,p:Principal,query:ApprovalPage={}) {
 const options=page(p,query,'definitions');await authorize(tx,p,['models:read']);
 const after=options.after===null?sql`true`:sql`w.id COLLATE "C">${options.after} COLLATE "C"`;
 const search=options.q?sql`v.definition->>'name' ILIKE ${'%'+options.q.replace(/[\\%_]/g,'\\$&')+'%'} ESCAPE ${'\\'}`:sql`true`;
 const rows=(await approvalQuery(tx,()=>sql<Row>`select v.*,w.current_version from public.workflow_definitions w join public.workflow_definition_versions v
  on v.tenant_id=w.tenant_id and v.workflow_id=w.id and v.version=w.current_version
  where w.tenant_id=${p.tenantId}::uuid and ${after} and ${search} order by w.id COLLATE "C" limit ${options.limit+1}`.execute(tx))).rows;
 const items=rows.slice(0,options.limit).map(storedDefinition);
 return {items,nextCursor:rows.length>options.limit?options.next(items.at(-1)!.definition.id):null};
}
export async function getApprovalDefinition(tx:Tx,p:Principal,workflowId:string,requestedVersion?:number):Promise<ApprovalDefinitionView> {
 id(workflowId,key);if(requestedVersion!==undefined)version(requestedVersion);await authorize(tx,p,['models:read']);
 return definitionAt(tx,p,workflowId,requestedVersion);
}
async function definitionAt(tx:Tx,p:Principal,workflowId:string,requestedVersion?:number){
 const selected=requestedVersion===undefined?sql`v.version=w.current_version`:sql`v.version=${requestedVersion}`;
 const row=(await approvalQuery(tx,()=>sql<Row>`select v.*,w.current_version from public.workflow_definitions w join public.workflow_definition_versions v
  on v.tenant_id=w.tenant_id and v.workflow_id=w.id where w.tenant_id=${p.tenantId}::uuid and w.id=${workflowId} and ${selected}`.execute(tx))).rows[0];
 if(!row)throw new Problem(404,'WORKFLOW_UNAVAILABLE','The workflow definition is unavailable.');return storedDefinition(row);
}
function commandContext(commandKey:string,correlation:string):void{
 if(typeof commandKey!=='string'||commandKey.length<8||commandKey.length>128||/[\u0000-\u001f\u007f]/.test(commandKey)
  ||typeof correlation!=='string'||!correlation.length||correlation.length>128||/[\u0000-\u001f\u007f]/.test(correlation))throw invalid();
}
async function command(tx:Tx,operation:string,commandKey:string,body:unknown,correlation:string):Promise<Row>{
 commandContext(commandKey,correlation);
 const value=(await approvalQuery(tx,()=>sql<{value:Row}>`select public.gc_approval_command(${operation},${commandKey},${JSON.stringify(body)}::jsonb,${correlation}) as value`.execute(tx))).rows[0]?.value;
 if(!value||typeof value!=='object'||Array.isArray(value))throw integrity();return value;
}
export async function publishApprovalDefinition(tx:Tx,p:Principal,input:unknown,expectedVersion:number,commandKey:string,correlation:string):Promise<ApprovalDefinitionView>{
 version(expectedVersion,true);const parsed=parseApprovalDefinition(input);if(!parsed.ok)throw new Problem(422,'APPROVAL_DEFINITION_INVALID','Correct the workflow definition.',parsed.issues);
 if(parsed.value.version!==expectedVersion+1)throw new Problem(409,'VERSION_CONFLICT','Publish exactly the next workflow version.');
 await authorize(tx,p,['models:read','models:write']);
 const receipt=await command(tx,'approval.definition.publish',commandKey,{definition:parsed.value,expectedVersion},correlation);
 const returned=parseApprovalDefinition(receipt.definition);
 if(!returned.ok||modelPersistence.hash(returned.value)!==receipt.definitionHash||modelPersistence.hash(returned.value)!==modelPersistence.hash(parsed.value))throw integrity();
 return definitionAt(tx,p,parsed.value.id,parsed.value.version);
}
/** Participant and live-reference predicates run in SQL BEFORE LIMIT. No hidden
 * counts, payload filtering after pagination, or cached authorization are used. */
export function visibleApprovalRequest(p:Principal){return sql<boolean>`r.tenant_id=${p.tenantId}::uuid
 and (r.requester_id=${p.id}::uuid or exists(select 1 from public.approval_tasks participant where participant.tenant_id=r.tenant_id and participant.request_id=r.id and participant.assigned_identity_id=${p.id}::uuid))
 and ((r.binding='glossary.publish' and ${p.permissions.includes('catalog:write')}
 and ((r.resource_version is null and not exists(select 1 from public.assets base where base.tenant_id=r.tenant_id and base.id=r.resource_id))
  or exists(select 1 from public.assets base where base.tenant_id=r.tenant_id and base.id=r.resource_id and (base.visibility='tenant' or base.allowed_identities @> ${JSON.stringify([p.id])}::jsonb)))
 and jsonb_typeof(r.payload->'links')='array'
 and not exists(select 1 from jsonb_array_elements(case when jsonb_typeof(r.payload->'links')='array' then r.payload->'links' else '[]'::jsonb end) link
  where not exists(select 1 from public.assets target where target.tenant_id=r.tenant_id and target.id::text=link->>'targetAssetId'
   and (target.visibility='tenant' or target.allowed_identities @> ${JSON.stringify([p.id])}::jsonb))))
 or (r.binding='classification.review' and public.gc_classification_visible(r.resource_id,${p.id}::uuid)))`;}
function current(){return sql<boolean>`case when r.binding='classification.review' then public.gc_classification_payload_current(r.payload) when r.binding='glossary.publish' then ((r.resource_version is null and not exists(select 1 from public.assets base where base.tenant_id=r.tenant_id and base.id=r.resource_id))
 or exists(select 1 from public.assets base where base.tenant_id=r.tenant_id and base.id=r.resource_id and base.version=r.resource_version and base.status='active'))
 and not exists(select 1 from jsonb_array_elements(case when jsonb_typeof(r.payload->'links')='array' then r.payload->'links' else '[]'::jsonb end) link
 where not exists(select 1 from public.assets target where target.tenant_id=r.tenant_id and target.id::text=link->>'targetAssetId' and target.version::text=link->>'targetAssetVersion' and target.status='active')) else false end`;}
const summaryColumns=sql`r.id,r.binding,r.resource_id,r.resource_version,r.proposal_digest,r.workflow_id,r.workflow_version,r.workflow_hash,r.requester_id,r.stage_index,r.version,r.status,r.expires_at,r.created_at,r.updated_at`;
function summary(r:Row):ApprovalRequestSummary {
 if(!uuid.test(r.id)||!['glossary.publish','classification.review'].includes(r.binding)||!statuses.includes(r.status)||typeof r.preconditions_current!=='boolean')throw integrity();
 return {id:r.id,binding:r.binding,resourceId:r.resource_id,resourceVersion:r.resource_version,proposalDigest:r.proposal_digest,workflowId:r.workflow_id,
  workflowVersion:r.workflow_version,workflowHash:r.workflow_hash,requesterId:r.requester_id,stageIndex:r.stage_index,version:r.version,status:r.status,
  expiresAt:iso(r.expires_at),createdAt:iso(r.created_at),updatedAt:iso(r.updated_at),preconditionsCurrent:r.preconditions_current};
}
async function authorizeRequestRead(tx:Tx,p:Principal):Promise<Principal>{
 await authorize(tx,p,['catalog:read']);
 const member=await approvalQuery(tx,()=>tx.selectFrom('memberships').innerJoin('identities','identities.id','memberships.identity_id')
  .select('memberships.permissions').where('memberships.tenant_id','=',p.tenantId).where('memberships.identity_id','=',p.id)
  .where('memberships.active','=',true).where('identities.active','=',true).executeTakeFirst());
 if(!member||!Array.isArray(member.permissions)||!member.permissions.includes('catalog:read')||!['catalog:write','classification:read'].some(action=>member.permissions.includes(action)))
  throw new Problem(403,'FORBIDDEN','Your current permissions do not allow this action.');
 return {...p,permissions:member.permissions};
}
function requestPayload(row:Row):GlossaryPublicationInput|ClassificationApprovalPayload{
 if(row.binding==='glossary.publish'){const parsed=parseGlossaryPublication(row.payload);if(!parsed.ok)throw integrity();return parsed.value.input;}
 if(row.binding==='classification.review')try{const payload=parseClassificationApprovalPayload(row.payload);if(payload.assetId!==row.resource_id)throw 0;return payload;}catch{throw integrity();}
 throw integrity();
}
export async function listApprovalRequests(tx:Tx,p:Principal,query:ApprovalRequestPage={}) {
 const options=page(p,query,'requests');p=await authorizeRequestRead(tx,p);
 const after=options.after===null?sql`true`:sql`r.id>${options.after}::uuid`;
 const status=options.status?sql`r.status=${options.status}`:sql`true`;
 const assigned=options.assigned?sql`exists(select 1 from public.approval_tasks mine where mine.tenant_id=r.tenant_id and mine.request_id=r.id and mine.assigned_identity_id=${p.id}::uuid)`:sql`true`;
 const rows=(await approvalQuery(tx,()=>sql<Row>`select ${summaryColumns},(${current()}) as preconditions_current from public.approval_requests r
 where ${visibleApprovalRequest(p)} and ${after} and ${status} and ${assigned} order by r.id limit ${options.limit+1}`.execute(tx))).rows;
 const items=rows.slice(0,options.limit).map(summary);return {items,nextCursor:rows.length>options.limit?options.next(items.at(-1)!.id):null};
}
async function requestRow(tx:Tx,p:Principal,requestId:string):Promise<Row> {
 const row=(await approvalQuery(tx,()=>sql<Row>`select r.*,(${current()}) as preconditions_current from public.approval_requests r where r.id=${requestId}::uuid and ${visibleApprovalRequest(p)}`.execute(tx))).rows[0];
 if(!row)throw unavailable();requestPayload(row);return row;
}
async function detail(tx:Tx,p:Principal,row:Row):Promise<ApprovalRequestView>{
 const workflow=await definitionAt(tx,p,row.workflow_id,row.workflow_version);if(workflow.definitionHash!==row.workflow_hash)throw integrity();
 const tasks=(await approvalQuery(tx,()=>sql<Row>`select * from public.approval_tasks where tenant_id=${p.tenantId}::uuid and request_id=${row.id}::uuid order by stage_index,assignment collate "C" limit 257`.execute(tx))).rows;
 const decisions=(await approvalQuery(tx,()=>sql<Row>`select * from public.approval_decisions where tenant_id=${p.tenantId}::uuid and request_id=${row.id}::uuid order by decided_at,id limit 257`.execute(tx))).rows;
 if(tasks.length>256||decisions.length>256)throw integrity();
 const payload=requestPayload(row);let result=row.result;
 if(row.binding==='classification.review')try{if((row.status==='succeeded')!==(result!==null))throw 0;if(result!==null){result=parseClassificationApprovalResult(result);const proposal=payload as ClassificationApprovalPayload;
  if(result.assetId!==row.resource_id||result.assignmentId!==proposal.assignmentId||result.evidenceHash!==proposal.evidenceHash||result.assignmentVersion!==proposal.expectedAssignmentVersion+1||result.status!==(proposal.change==='apply'?'active':'withdrawn'))throw 0;}}catch{throw integrity();}
 return {...summary(row),payload,workflow,result,errorCode:row.error_code,
  tasks:tasks.map(t=>({id:t.id,stageIndex:t.stage_index,assignment:t.assignment,assignedIdentityId:t.assigned_identity_id,version:t.version,status:t.status,openedAt:t.opened_at===null?null:iso(t.opened_at),expiresAt:t.expires_at===null?null:iso(t.expires_at)})),
  decisions:decisions.map(d=>({id:d.id,taskId:d.task_id,taskVersion:d.task_version,actorId:d.actor_id,decision:d.decision,reason:d.reason,decidedAt:iso(d.decided_at)}))} as ApprovalRequestView;
}
export async function getApprovalRequest(tx:Tx,p:Principal,requestId:string):Promise<ApprovalRequestView>{id(requestId);p=await authorizeRequestRead(tx,p);return detail(tx,p,await requestRow(tx,p,requestId));}
async function lockRequest(tx:Tx,p:Principal,requestId:string,cancel:boolean):Promise<Row>{
 p=await authorizeRequestRead(tx,p);await approvalQuery(tx,()=>lockTenantLedger(tx,p.tenantId));
 // Gather every principal before taking the first identity lock: actor-only
 // prelocking would invert SQL015's global sorted requester/assignee lock order.
 const row=await requestRow(tx,p,requestId);
 const actions=row.binding==='classification.review'?['catalog:read','classification:read',cancel?'classification:write':'classification:approve']:read;
 await authorize(tx,p,actions);
 const payload=requestPayload(row);
 const ruleOwners=row.binding==='classification.review'?sql`union select owner_id from public.classification_rule_versions where tenant_id=${p.tenantId}::uuid and rule_id=${(payload as ClassificationApprovalPayload).evidence.rule.id}::uuid and version=${(payload as ClassificationApprovalPayload).evidence.rule.version}`:sql``;
 await approvalQuery(tx,()=>sql`select public.gc_lock_type_migration_principals(array(select distinct principal from (
  select ${p.id}::uuid as principal union select ${row.requester_id}::uuid union
  select assigned_identity_id from public.approval_tasks where tenant_id=${p.tenantId}::uuid and request_id=${requestId}::uuid
  ${ruleOwners}
 ) complete order by principal))`.execute(tx));
 const ids=row.binding==='classification.review'?[row.resource_id]:[...new Set([row.resource_id,...(payload as GlossaryPublicationInput).links.map(link=>link.targetAssetId)])].sort();
 await approvalQuery(tx,()=>sql`select id from public.assets where tenant_id=${p.tenantId}::uuid and id=any(${ids}::uuid[]) order by id for share`.execute(tx));
 await authorize(tx,p,actions);return requestRow(tx,p,requestId);
}
async function mutation(tx:Tx,p:Principal,requestId:string,input:unknown,commandKey:string,correlation:string,cancel:boolean):Promise<{request:ApprovalRequestView}>{
 id(requestId);const source=exact(input,cancel?['proposalDigest','reason']:['proposalDigest','taskId','taskVersion','decision','reason']);id(source.proposalDigest,digest);
 const reason=normalizeApprovalReason(source.reason);if(!cancel){id(source.taskId);version(source.taskVersion);if(source.decision!=='approve'&&source.decision!=='reject')throw invalid();}
 commandContext(commandKey,correlation);
 const currentRow=await lockRequest(tx,p,requestId,cancel);
 if(cancel&&currentRow.requester_id!==p.id)throw unavailable();
 const operation=cancel?'approval.cancel':'approval.decide',body={requestId,...source,reason};
 if(!cancel&&!currentRow.preconditions_current){
  // The tenant ledger and full current visibility/principal locks are already
  // held. Only an exact protected receipt can bypass a NEW decision's stale
  // precondition; the protected command still revalidates hash and authority.
  const retained=(await approvalQuery(tx,()=>sql<{request_hash:string}>`select request_hash from public.idempotency
   where tenant_id=${p.tenantId}::uuid and actor_id=${p.id} and operation=${operation} and key=${commandKey}`.execute(tx))).rows[0];
  if(!retained)throw new Problem(409,'APPROVAL_PRECONDITIONS_CHANGED','The proposed resource or a linked resource changed. Revise the proposal before deciding.');
  if(retained.request_hash!==modelPersistence.hash(body))throw new Problem(409,'IDEMPOTENCY_CONFLICT','The idempotency key belongs to a different approval command.');
 }
 const receipt=await command(tx,operation,commandKey,body,correlation);
 // Preserve SQL's retained response on replay; the immutable proposal is checked
 // against the currently authorized row, and the exact pinned definition is used.
 const value=receipt.request as Row|undefined;
 if(!value||value.id!==requestId||value.binding!==currentRow.binding||value.proposalDigest!==currentRow.proposal_digest||modelPersistence.hash(value.payload)!==modelPersistence.hash(currentRow.payload)
  ||value.workflowId!==currentRow.workflow_id||value.workflowVersion!==currentRow.workflow_version||value.workflowHash!==currentRow.workflow_hash
  ||!Array.isArray(value.tasks)||value.tasks.length>256||!Array.isArray(value.decisions)||value.decisions.length>256)throw integrity();
 if(currentRow.binding==='classification.review')try{const payload=parseClassificationApprovalPayload(value.payload);if((value.status==='succeeded')!==(value.result!==null))throw 0;if(value.result!==null){const result=parseClassificationApprovalResult(value.result);
  if(result.assetId!==payload.assetId||result.assignmentId!==payload.assignmentId||result.evidenceHash!==payload.evidenceHash||result.assignmentVersion!==payload.expectedAssignmentVersion+1||result.status!==(payload.change==='apply'?'active':'withdrawn'))throw 0;}}catch{throw integrity();}
 const workflow=await definitionAt(tx,p,currentRow.workflow_id,currentRow.workflow_version);if(workflow.definitionHash!==currentRow.workflow_hash)throw integrity();
 return {request:{...value,workflow,preconditionsCurrent:currentRow.preconditions_current} as ApprovalRequestView};
}
export const decideApprovalTask=(tx:Tx,p:Principal,requestId:string,input:ApprovalDecisionInput,commandKey:string,correlation:string)=>mutation(tx,p,requestId,input,commandKey,correlation,false);
export const cancelApprovalRequest=(tx:Tx,p:Principal,requestId:string,input:ApprovalCancelInput,commandKey:string,correlation:string)=>mutation(tx,p,requestId,input,commandKey,correlation,true);

/** Internal worker boundary: callers must establish the existing site tenant.
 * Only IDs leave pending dispatch; workers never supply decisions or outcomes. */
export async function pendingApprovals(tx:Tx,tenant:string){id(tenant);const rows=(await approvalQuery(tx,()=>sql<{request_id:string;event_id:string}>`
 select request_id,event_id from public.approval_dispatch where tenant_id=${tenant}::uuid and dispatched_at is null order by event_id limit 50`.execute(tx))).rows;
 return {items:rows.map(row=>({tenantId:tenant,requestId:row.request_id,eventId:row.event_id}))};}
export async function tickApproval(tx:Tx,requestId:string){id(requestId);const result=(await approvalQuery(tx,()=>sql<{value:unknown}>`select public.gc_approval_tick(${requestId}::uuid) as value`.execute(tx))).rows[0]?.value;
 const value=exact(result,['id','status','version','nextWakeAt']);if(value.id!==requestId||!statuses.includes(value.status as ApprovalStatus))throw integrity();version(value.version);return value;}
export async function approvalStatus(tx:Tx,tenant:string,requestId:string){id(tenant);id(requestId);
 const row=(await approvalQuery(tx,()=>sql<Row>`select r.id,r.status,r.version,
  case when r.status='pending' then least(r.expires_at,(select min(t.expires_at) from public.approval_tasks t
   where t.tenant_id=r.tenant_id and t.request_id=r.id and t.stage_index=r.stage_index)) end as next_wake_at
  from public.approval_requests r where r.tenant_id=${tenant}::uuid and r.id=${requestId}::uuid`.execute(tx))).rows[0];
 if(!row)throw unavailable();if(!statuses.includes(row.status))throw integrity();version(row.version);
 return {id:row.id,status:row.status as ApprovalStatus,version:row.version as number,nextWakeAt:row.next_wake_at===null?null:iso(row.next_wake_at)};
}
export async function acknowledgeApprovalDispatch(tx:Tx,eventId:string){id(eventId);await approvalQuery(tx,()=>sql`select public.gc_approval_dispatch_ack(${eventId}::uuid)`.execute(tx));return {id:eventId,acknowledged:true};}
