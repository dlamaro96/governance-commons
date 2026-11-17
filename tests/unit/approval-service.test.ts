// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {test} from 'node:test';
import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import {Kysely,DummyDriver,PostgresAdapter,PostgresIntrospector,PostgresQueryCompiler,type CompiledQuery,type DatabaseConnection,type QueryResult} from 'kysely';
import type {Tx} from '../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../packages/authz/src/index.ts';
import {modelPersistence} from '../../packages/domain/src/model-service.ts';
import {signedCursor} from '../../packages/domain/src/cursor.ts';
import {listApprovalDefinitions,getApprovalDefinition,publishApprovalDefinition,listApprovalRequests,getApprovalRequest,decideApprovalTask,cancelApprovalRequest,
 normalizeApprovalReason,approvalFailure,approvalStatus,pendingApprovals} from '../../packages/domain/src/approval-service.ts';
import {installApprovals,parseApprovalRequestJSON,approvalRawQuery,approvalHttp} from '../../apps/api/src/approvals.ts';
import {Value} from '@sinclair/typebox/value';

const tenant='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',actor='10000000-0000-4000-8000-000000000001',requestId='20000000-0000-4000-8000-000000000001',resource='30000000-0000-4000-8000-000000000001';
const taskId='40000000-0000-4000-8000-000000000001',other='10000000-0000-4000-8000-000000000002';
const p:Principal={tenantId:tenant,id:actor,name:'Synthetic reviewer',permissions:['catalog:read','catalog:write','models:read','models:write']};
const stamp='2026-11-16T00:00:00.000Z';
const definition={formatVersion:1 as const,id:'term_review',version:1,name:'Term review',separationOfDuties:true,
 stages:[{id:'review',name:'Review',assignments:['steward'],quorum:1,deadlineSeconds:300,rejection:'any' as const}]};
const hash=modelPersistence.hash(definition);
const workflow={workflow_id:definition.id,version:1,definition,definition_hash:hash,current_version:2,created_at:stamp,created_by:actor};
const payload={typePin:{typeId:resource,modelId:'term',version:1,definitionHash:'a'.repeat(64),resolutionHash:'b'.repeat(64)},primaryLocale:'en',ownerId:actor,visibility:'tenant',allowedIdentityIds:[],state:'active',
 attributes:{translations:[{locale:'en',name:'Synthetic term',definition:'Synthetic definition',synonyms:[],abbreviations:[],examples:[]}]},links:[]};
const row={id:requestId,binding:'glossary.publish',resource_id:resource,resource_version:1,payload,proposal_digest:'c'.repeat(64),workflow_id:definition.id,workflow_version:1,workflow_hash:hash,requester_id:actor,
 stage_index:0,version:2,status:'pending',result:null,error_code:null,expires_at:'2026-11-16T01:00:00.000Z',created_at:stamp,updated_at:stamp,preconditions_current:true};
const task={id:taskId,stage_index:0,assignment:'steward',assigned_identity_id:other,version:1,status:'open',opened_at:stamp,expires_at:'2026-11-16T00:05:00.000Z'};
type Query=CompiledQuery<unknown>;
function recording(respond:(q:Query)=>Record<string,unknown>[]=()=>[]){
 const calls:Query[]=[];
 const connection:DatabaseConnection={async executeQuery<R>(query:CompiledQuery):Promise<QueryResult<R>>{calls.push(query);return {rows:respond(query) as R[]};},async *streamQuery<R>():AsyncIterableIterator<QueryResult<R>>{throw new Error('Streaming is not part of this fixture');}};
 class Driver extends DummyDriver {override async acquireConnection(){return connection;}}
 const db=new Kysely<Record<string,any>>({dialect:{createAdapter:()=>new PostgresAdapter(),createDriver:()=>new Driver(),createIntrospector:db=>new PostgresIntrospector(db),createQueryCompiler:()=>new PostgresQueryCompiler()}});
 return {tx:db as unknown as Tx,calls,close:()=>db.destroy()};
}
function rows(q:Query,override:Record<string,unknown>={}){
 if(q.sql.includes('from "memberships"'))return [{permissions:p.permissions}];
 if(q.sql.includes('select v.*'))return [workflow];
 if(q.sql.includes('select r.*'))return [{...row,...override}];
 if(q.sql.includes('select * from public.approval_tasks'))return [task];
 return [];
}
const isCode=(code:string)=>(error:unknown)=>error instanceof Problem&&error.code===code;
test('approval ingress rejects duplicate fields, coercion, malformed scalars and getters without dropping data',async()=>{
 for(const raw of ['{"reason":"a","reason":"b"}','{"reason":"a","rea\\u0073on":"b"}','{"reason":"\\ud800"}','{"version":-0}','{"constructor":1}','[]','{"a":1} trailing'])assert.throws(()=>parseApprovalRequestJSON(raw),isCode('APPROVAL_INPUT_INVALID'));
 assert.deepEqual(parseApprovalRequestJSON('{"reason":"first\\nsecond"}'),{reason:'first\nsecond'});
 for(const suffix of ['?limit=01','?limit=101','?assignedToMe=1','?status=pending&status=ready','?%73tatus=pending&status=ready','?q=%FF','?q=%','?unknown=x'])assert.throws(()=>approvalRawQuery({url:'/x'+suffix},['limit','assignedToMe','status','q']),isCode('APPROVAL_INPUT_INVALID'));
 assert.equal(approvalRawQuery({url:'/x?limit=2&assignedToMe=false'},['limit','assignedToMe']).limit,2);
 assert.equal(normalizeApprovalReason('  cafe\u0301\nreviewed  '),'café\nreviewed');
 for(const value of [' \n\t ','x\u0001','\ud800','a'.repeat(4097),true])assert.throws(()=>normalizeApprovalReason(value),isCode('APPROVAL_INPUT_INVALID'));
 const tx=recording();let reads=0;
 try{const query=Object.defineProperty({},'limit',{enumerable:true,get(){reads++;return 2;}});
  await assert.rejects(listApprovalRequests(tx.tx,p,query),isCode('APPROVAL_INPUT_INVALID'));assert.equal(reads,0);assert.equal(tx.calls.length,0);
 }finally{await tx.close();}
});
test('signed approval cursors bind actor tenant exact filters and limit before SQL',async()=>{
 const previous=process.env.SESSION_KEY;process.env.SESSION_KEY='synthetic-approval-unit-cursor-secret-32';
 const tx=recording(q=>q.sql.includes('from public.approval_requests r')?[row,{...row,id:'20000000-0000-4000-8000-000000000002'}]:rows(q));
 try{
  const first=await listApprovalRequests(tx.tx,p,{limit:1,status:'pending',assignedToMe:true});assert.ok(first.nextCursor);
  const before=tx.calls.length;
  for(const [principal,query] of [[{...p,id:other},{limit:1,status:'pending',assignedToMe:true}],[{...p,tenantId:resource},{limit:1,status:'pending',assignedToMe:true}],
   [p,{limit:2,status:'pending',assignedToMe:true}],[p,{limit:1,status:'ready',assignedToMe:true}],[p,{limit:1,status:'pending',assignedToMe:false}]] as const)
   await assert.rejects(listApprovalRequests(tx.tx,principal,{...query,cursor:first.nextCursor}),isCode('APPROVAL_PAGE_INVALID'));
  const decoded=signedCursor(process.env.SESSION_KEY,'approval-requests-v1').decode(first.nextCursor) as unknown[];
  await assert.rejects(listApprovalRequests(tx.tx,p,{limit:1,status:'pending',assignedToMe:true,cursor:signedCursor(process.env.SESSION_KEY,'approval-requests-v1').encode([...decoded,'extra'])}),isCode('APPROVAL_PAGE_INVALID'));
  assert.equal(tx.calls.length,before);
  await listApprovalRequests(tx.tx,p,{limit:1,status:'pending',assignedToMe:true,cursor:first.nextCursor});
  const selection=tx.calls.filter(q=>q.sql.includes('from public.approval_requests r')).at(-1)!;
  assert.match(selection.sql,/participant\.assigned_identity_id/);assert.match(selection.sql,/target\.allowed_identities/);assert.match(selection.sql,/base\.allowed_identities/);
  assert.match(selection.sql,/not exists\(select 1 from jsonb_array_elements/);assert.match(selection.sql,/order by r\.id limit/);assert.ok(selection.parameters.includes(requestId));
  assert.ok(selection.sql.indexOf('participant.assigned_identity_id')<selection.sql.indexOf('order by r.id limit'));assert.doesNotMatch(selection.sql,/count\(\*\)/);
 }finally{await tx.close();if(previous===undefined)delete process.env.SESSION_KEY;else process.env.SESSION_KEY=previous;}
});
test('request detail retains visible stale proposal and interprets its pinned workflow version, never current head',async()=>{
 const tx=recording(q=>rows(q,{preconditions_current:false}));
 try{const value=await getApprovalRequest(tx.tx,p,requestId);
  assert.equal(value.preconditionsCurrent,false);assert.equal(value.workflow.definition.version,1);assert.equal(value.workflow.currentVersion,2);assert.deepEqual(value.payload,payload);
  assert.equal(Value.Check(approvalHttp.requestView,value),true);
  const definitionQuery=tx.calls.find(q=>q.sql.includes('select v.*'))!;assert.match(definitionQuery.sql,/v\.version=\$/);assert.doesNotMatch(definitionQuery.sql,/v\.version=w\.current_version/);assert.ok(definitionQuery.parameters.includes(1));
 }finally{await tx.close();}
});
test('current membership refusal and inaccessible references return no proposal payload',async()=>{
 const forbidden=recording();try{await assert.rejects(getApprovalRequest(forbidden.tx,p,requestId),isCode('FORBIDDEN'));assert.equal(forbidden.calls.some(q=>q.sql.includes('approval_requests')),false);}finally{await forbidden.close();}
 const hidden=recording(q=>q.sql.includes('from "memberships"')?[{permissions:p.permissions}]:[]);
 try{await assert.rejects(getApprovalRequest(hidden.tx,p,requestId),isCode('APPROVAL_UNAVAILABLE'));assert.equal(hidden.calls.some(q=>q.sql.includes('select * from public.approval_tasks')),false);}finally{await hidden.close();}
});
test('stale decision refuses before command; cancellation uses complete principal lock order and normalized reason',async()=>{
 const receipt={id:requestId,binding:'glossary.publish',resourceId:resource,resourceVersion:1,payload,proposalDigest:row.proposal_digest,workflowId:definition.id,workflowVersion:1,workflowHash:hash,requesterId:actor,
  stageIndex:0,version:3,status:'cancelled',result:null,errorCode:null,expiresAt:row.expires_at,createdAt:stamp,updatedAt:stamp,tasks:[],decisions:[]};
 const tx=recording(q=>q.sql.includes('gc_approval_command')?[{value:{request:receipt}}]:rows(q,{preconditions_current:false}));
 try{
  await assert.rejects(decideApprovalTask(tx.tx,p,requestId,{proposalDigest:row.proposal_digest,taskId,taskVersion:1,decision:'approve',reason:'review'},'decision-key',actor),isCode('APPROVAL_PRECONDITIONS_CHANGED'));
  assert.equal(tx.calls.some(q=>q.sql.includes('gc_approval_command')),false);tx.calls.length=0;
  const result=await cancelApprovalRequest(tx.tx,p,requestId,{proposalDigest:row.proposal_digest,reason:'  cafe\u0301\nreviewed  '},'cancel-command-key',actor);
  assert.equal(result.request.status,'cancelled');assert.equal(result.request.version,3);assert.equal(result.request.preconditionsCurrent,false);
  const ledger=tx.calls.findIndex(q=>q.sql.includes('pg_advisory_xact_lock')),principals=tx.calls.findIndex(q=>q.sql.includes('gc_lock_type_migration_principals')),
   assets=tx.calls.findIndex(q=>q.sql.includes('select id from public.assets')),command=tx.calls.findIndex(q=>q.sql.includes('gc_approval_command'));
  assert.ok(ledger>=0&&principals>ledger&&assets>principals&&command>assets);
  assert.match(tx.calls[principals].sql,/select assigned_identity_id from public\.approval_tasks/);assert.match(tx.calls[principals].sql,/order by principal/);assert.match(tx.calls[assets].sql,/order by id for share/);
  const body=JSON.parse(tx.calls[command].parameters[2] as string);assert.deepEqual(body,{requestId,proposalDigest:row.proposal_digest,reason:'café\nreviewed'});
  assert.equal(tx.calls[command].parameters[1],'cancel-command-key');assert.equal(tx.calls.filter(q=>q.sql.includes('gc_approval_command')).length,1);
 }finally{await tx.close();}
});
test('definition publication validates pure grammar and maps pinned publication without outer idempotency',async()=>{
 const tx=recording(q=>q.sql.includes('gc_approval_command')?[{value:{definition,definitionHash:hash}}]:rows(q));
 try{
  await assert.rejects(publishApprovalDefinition(tx.tx,p,{...definition,stages:[{...definition.stages[0],rejection:null}]},0,'publish-key',actor),isCode('APPROVAL_DEFINITION_INVALID'));
  assert.equal(tx.calls.length,0);const value=await publishApprovalDefinition(tx.tx,p,definition,0,'publish-key',actor);assert.equal(value.definition.version,1);
  const command=tx.calls.find(q=>q.sql.includes('gc_approval_command'))!;assert.deepEqual(JSON.parse(command.parameters[2] as string),{definition,expectedVersion:0});
  assert.equal(tx.calls.some(q=>q.sql.includes('insert into "idempotency"')),false);
  await assert.rejects(getApprovalDefinition(tx.tx,p,'term_review',2147483648),isCode('APPROVAL_INPUT_INVALID'));
 }finally{await tx.close();}
});
test('worker status is read-only and pending dispatch returns only scoped identities',async()=>{
 const tx=recording(q=>q.sql.includes('as next_wake_at')?[{id:requestId,status:'ready',version:5,next_wake_at:null}]:q.sql.includes('from public.approval_dispatch')?[{request_id:requestId,event_id:taskId}]:[]);
 try{assert.deepEqual(await approvalStatus(tx.tx,tenant,requestId),{id:requestId,status:'ready',version:5,nextWakeAt:null});
  assert.deepEqual(await pendingApprovals(tx.tx,tenant),{items:[{tenantId:tenant,requestId,eventId:taskId}]});
  assert.equal(tx.calls.some(q=>/gc_approval_tick|gc_approval_dispatch_ack|\bupdate\b/i.test(q.sql)),false);assert.match(tx.calls.find(q=>q.sql.includes('approval_dispatch'))!.sql,/limit 50/);
 }finally{await tx.close();}
});
test('closed SQL error mapping never reflects query details or unrecognized database messages',()=>{
 for(const code of ['XX000','23514','23503','unknown']){const e=approvalFailure({code,message:'PRIVATE_SENTINEL query and payload',detail:'PRIVATE_SENTINEL'});assert.equal(e.code,'APPROVAL_STORAGE_INVALID');assert.doesNotMatch(e.message,/PRIVATE_SENTINEL/);}
 assert.equal(approvalFailure({code:'40001',message:'APPROVAL_TASK_CONFLICT'}).status,409);assert.equal(approvalFailure({code:'40001',message:'PRIVATE_SENTINEL'}).code,'APPROVAL_RETRY');assert.equal(approvalFailure({code:'42501',message:'PRIVATE_SENTINEL'}).status,403);
});
test('route installer exposes no submission or effects and rejects missing session/site identity before database access',async()=>{
 const app=Fastify();await app.register(cookie);await installApprovals(app);
 try{
  for(const path of ['/api/v1/workflow-definitions','/api/v1/approval-requests',`/api/v1/approval-requests/${requestId}`])assert.equal((await app.inject({method:'GET',url:path})).statusCode,401);
  assert.equal((await app.inject({method:'GET',url:'/internal/approvals/pending'})).statusCode,401);
  assert.equal((await app.inject({method:'POST',url:'/api/v1/approval-requests',payload:{}})).statusCode,404);
  assert.equal((await app.inject({method:'POST',url:`/api/v1/approval-requests/${requestId}/execute`,payload:{}})).statusCode,404);
 }finally{await app.close();}
});


test('exact successful decision replay survives reference version drift while new or altered commands still refuse',async()=>{
 const input={proposalDigest:row.proposal_digest,taskId,taskVersion:1,decision:'approve' as const,reason:'  cafe\u0301 reviewed  '};
 const body={requestId,...input,reason:'café reviewed'},requestHash=modelPersistence.hash(body);
 const receipt={id:requestId,binding:'glossary.publish',resourceId:resource,resourceVersion:1,payload,proposalDigest:row.proposal_digest,workflowId:definition.id,
  workflowVersion:1,workflowHash:hash,requesterId:actor,stageIndex:0,version:3,status:'pending',result:null,errorCode:null,
  expiresAt:row.expires_at,createdAt:stamp,updatedAt:stamp,tasks:[],decisions:[]};
 for(const stored of [requestHash,'d'.repeat(64),null]){
  const tx=recording(q=>q.sql.includes('select request_hash from public.idempotency')?(stored===null?[]:[{request_hash:stored}]):
   q.sql.includes('gc_approval_command')?[{value:{request:receipt}}]:rows(q,{preconditions_current:false,version:9,status:'ready'}));
  try{
   if(stored===requestHash){
    const result=await decideApprovalTask(tx.tx,p,requestId,input,'retained-decision-key',actor);
    assert.equal(result.request.version,3);assert.equal(result.request.status,'pending');assert.equal(result.request.preconditionsCurrent,false);
    const replayIndex=tx.calls.findIndex(q=>q.sql.includes('select request_hash from public.idempotency')),
     commandIndex=tx.calls.findIndex(q=>q.sql.includes('gc_approval_command'));
    assert.ok(replayIndex>tx.calls.findIndex(q=>q.sql.includes('select id from public.assets')));assert.ok(commandIndex>replayIndex);
    assert.deepEqual(tx.calls[replayIndex].parameters,[tenant,actor,'approval.decide','retained-decision-key']);
    assert.deepEqual(JSON.parse(tx.calls[commandIndex].parameters[2] as string),body);
    assert.equal(tx.calls.filter(q=>q.sql.includes('gc_approval_command')).length,1);
   }else{
    await assert.rejects(decideApprovalTask(tx.tx,p,requestId,input,'retained-decision-key',actor),isCode(stored===null?'APPROVAL_PRECONDITIONS_CHANGED':'IDEMPOTENCY_CONFLICT'));
    assert.equal(tx.calls.some(q=>q.sql.includes('gc_approval_command')),false);
   }
  }finally{await tx.close();}
 }
 const hidden=recording(q=>q.sql.includes('from "memberships"')?[{permissions:p.permissions}]:[]);
 try{
  await assert.rejects(decideApprovalTask(hidden.tx,p,requestId,input,'retained-decision-key',actor),isCode('APPROVAL_UNAVAILABLE'));
  assert.equal(hidden.calls.some(q=>/select request_hash|gc_approval_command/.test(q.sql)),false);
 }finally{await hidden.close();}
});
