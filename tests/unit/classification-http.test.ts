// SPDX-License-Identifier: Apache-2.0
/** Host protocol/compiled SQL boundaries. This fixture does not execute PostgreSQL
 * or qualify canonical approval/assignment effects; the native gate owns those. */
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createHash} from 'node:crypto';
import Fastify from 'fastify';
import {Value} from '@sinclair/typebox/value';
import {Kysely,DummyDriver,PostgresAdapter,PostgresIntrospector,PostgresQueryCompiler,type CompiledQuery,type DatabaseConnection,type QueryResult} from 'kysely';
import type {Tx} from '../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../packages/authz/src/index.ts';
import {modelPersistence} from '../../packages/domain/src/model-service.ts';
import {classificationDefinitionHash} from '../../packages/domain/src/classification.ts';
import {signedCursor} from '../../packages/domain/src/cursor.ts';
import {classificationFailure,classificationQuery,classificationObject,parseClassificationProposal,parseClassificationEvidence,parseClassificationEvaluationView,parseClassificationSuggestionView,parseClassificationAssignmentView,parseClassificationTaxonomyView,listClassificationTaxonomies,listClassificationRules,listClassificationAssignments,listClassificationSuggestions,publishClassificationTaxonomy,evaluateClassificationAsset,proposeClassification} from '../../packages/domain/src/classification-service.ts';
import {getApprovalRequest,listApprovalRequests,decideApprovalTask,cancelApprovalRequest} from '../../packages/domain/src/approval-service.ts';
import {approvalHttp} from '../../apps/api/src/approvals.ts';
import {visibleAudit} from '../../apps/api/src/repository.ts';
import {createClassificationPublicationHandler,createApprovalPublicationDispatcher} from '../../apps/api/src/classification-publication.ts';
import {classificationHttp,classificationRawQuery,parseClassificationRequestJSON,installClassification,CLASSIFICATION_HTTP_BYTES,type ClassificationDependencies} from '../../apps/api/src/classification.ts';

const tenant='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',actor='10000000-0000-4000-8000-000000000001',other='10000000-0000-4000-8000-000000000002';
const asset='20000000-0000-4000-8000-000000000001',taxId='30000000-0000-4000-8000-000000000001',ruleId='40000000-0000-4000-8000-000000000001',evaluationId='50000000-0000-4000-8000-000000000001',instanceId='60000000-0000-4000-8000-000000000001';
const stamp='2026-11-17T00:00:00.000Z',key='classification-synthetic-key';
const p:Principal={tenantId:tenant,id:actor,name:'Synthetic author',permissions:['catalog:read','classification:read','classification:write','models:read','models:write']};
const definition={formatVersion:1 as const,name:'Sensitivity',description:'Metadata classification.',labels:[{key:'contact',name:'Contact',description:'Contact metadata.',status:'active' as const}]};
const taxonomy={id:taxId,version:1,definitionHash:classificationDefinitionHash(definition),currentVersion:1,definition,createdAt:stamp,createdBy:actor};
const rulePin={id:ruleId,version:1,definitionHash:'a'.repeat(64)};
const evidence={formatVersion:1 as const,kind:'metadata-literal' as const,assetId:asset,observedAssetVersion:3,inputDigest:'b'.repeat(64),rule:rulePin,label:{taxonomy:{id:taxId,version:1,definitionHash:taxonomy.definitionHash},labelKey:'contact'},evaluatedAt:stamp,
 matches:[{conditionIndex:0,field:'name' as const,value:'Email',valueHash:createHash('sha256').update('Email').digest('hex')}],confidence:{kind:'not-estimated' as const,reason:'metadata-only' as const},samplePolicy:{kind:'metadata-only' as const,sourceRowsRead:0 as const,sourceSamplesStored:0 as const}};
const evaluation={id:evaluationId,outcome:'matched' as const,evidence,createdBy:actor,suggestionId:evaluationId,evidenceHash:modelPersistence.hash(evidence)};
const suggestion={id:evaluationId,assetId:asset,evaluationId,evidence,evidenceHash:evaluation.evidenceHash,evidenceCurrent:true,currentAssignmentVersion:7,createdAt:stamp,createdBy:actor};
const proposal={id:instanceId,change:{kind:'apply' as const,suggestionId:evaluationId,expectedAssignmentVersion:7},workflow:{id:'classification_review',version:1,definitionHash:'c'.repeat(64)},assignments:{steward:other},expiresAt:'2026-11-18T00:00:00.000Z'};
type Query=CompiledQuery<unknown>;
function recording(respond:(q:Query)=>Record<string,unknown>[]=()=>[]){
 const calls:Query[]=[];
 const connection:DatabaseConnection={async executeQuery<R>(query:CompiledQuery):Promise<QueryResult<R>>{calls.push(query);return {rows:respond(query) as R[]};},async *streamQuery<R>():AsyncIterableIterator<QueryResult<R>>{throw new Error('No streaming in host SQL fixture');}};
 class Driver extends DummyDriver{override async acquireConnection(){return connection;}}
 const db=new Kysely<Record<string,any>>({dialect:{createAdapter:()=>new PostgresAdapter(),createDriver:()=>new Driver(),createIntrospector:db=>new PostgresIntrospector(db),createQueryCompiler:()=>new PostgresQueryCompiler()}});
 return {tx:db as unknown as Tx,calls,close:()=>db.destroy()};
}
const membership=(q:Query)=>q.sql.includes('from "memberships"')?[{permissions:p.permissions}]:[];
const isCode=(code:string)=>(e:unknown)=>e instanceof Problem&&e.code===code;

test('classification raw ingress refuses duplicate, malformed, oversized and dangerous JSON without coercion',()=>{
 for(const raw of ['{"id":1,"id":2}','{"id":1,"i\\u0064":2}','{"nested":{"a":1,"a":2}}','{"x":-0}','{"x":1e999}','{"x":"\\ud800"}','{"__proto__":{}}','[]','{"x":1} trailing','{"x":"'+('x'.repeat(CLASSIFICATION_HTTP_BYTES))+'"}'])
  assert.throws(()=>parseClassificationRequestJSON(raw),isCode('CLASSIFICATION_INPUT_INVALID'),raw.slice(0,70));
 assert.deepEqual(parseClassificationRequestJSON('{"reason":"first\\nsecond","number":1,"flag":false}'),{reason:'first\nsecond',number:1,flag:false});
 for(const bad of [{...proposal,extra:true},{...proposal,change:{...proposal.change,reason:'not allowed'}},{...proposal,change:{kind:'withdraw',assignmentId:instanceId,expectedAssignmentVersion:0,reason:'No longer applicable'}},{...proposal,workflow:{...proposal.workflow,id:'not a safe id'}}])assert.equal(Value.Check(classificationHttp.proposal,bad),false);
 assert.equal(Value.Check(classificationHttp.proposal,proposal),true);assert.deepEqual(parseClassificationProposal(proposal),proposal);
 const full={...proposal,assignments:Object.fromEntries(Array.from({length:256},(_,i)=>['reviewer_'+i,other]))};
 assert.equal(Value.Check(classificationHttp.proposal,parseClassificationRequestJSON(JSON.stringify(full))),true);assert.equal(Object.keys(parseClassificationProposal(full).assignments).length,256);
 assert.throws(()=>parseClassificationRequestJSON(JSON.stringify({...full,assignments:{...full.assignments,overflow:other}})),isCode('CLASSIFICATION_INPUT_INVALID'));
});

test('classification descriptor admission does not invoke accessors or inspect thrown reflection values',()=>{
 let reads=0;const v=Object.defineProperty({},'id',{enumerable:true,get(){reads++;return instanceId;}});
 assert.throws(()=>classificationObject(v,['id']),isCode('CLASSIFICATION_INPUT_INVALID'));assert.equal(reads,0);
 const thrown=new Proxy({}, {getPrototypeOf(){reads++;throw 1;}}),proxy=new Proxy({}, {ownKeys(){throw thrown;}});
 assert.throws(()=>classificationObject(proxy,[]),isCode('CLASSIFICATION_INPUT_INVALID'));assert.equal(reads,0);
 const body={...proposal,assignments:Object.defineProperty({},'steward',{enumerable:true,get(){reads++;return other;}})};
 assert.throws(()=>parseClassificationProposal(body),isCode('CLASSIFICATION_INPUT_INVALID'));assert.equal(reads,0);
});

test('classification selectors are exact and cannot smuggle duplicate or unsupported filters',()=>{
 for(const suffix of ['?limit=01','?limit=101','?limit=0','?limit=1&%6cimit=2','?version=2147483648','?cursor=','?q=hidden','?limit=%FF','?limit=%','?limit=1&','?cursor='+('a'.repeat(1025))])assert.throws(()=>classificationRawQuery('/x'+suffix,['limit','version','cursor']),isCode('CLASSIFICATION_INPUT_INVALID'));
 assert.deepEqual({...classificationRawQuery('/x?limit=100&version=2147483647',['limit','version'])},{limit:100,version:2147483647});
});

test('stored classification witnesses require actual value hashes, exact identity and closed metadata-only provenance',()=>{
 assert.deepEqual(parseClassificationEvaluationView(evaluation),evaluation);assert.deepEqual(parseClassificationSuggestionView(suggestion),suggestion);
 for(const bad of [{...evidence,matches:[{...evidence.matches[0],value:'Other'}]},{...evidence,matches:[evidence.matches[0],evidence.matches[0]]},{...evidence,confidence:{kind:'probability',value:1}},{...evidence,samplePolicy:{...evidence.samplePolicy,sourceRowsRead:1}},{...evidence,extra:'private'}])assert.throws(()=>parseClassificationEvidence(bad),isCode('CLASSIFICATION_INPUT_INVALID'));
 for(const bad of [{...evaluation,evidenceHash:'0'.repeat(64)},{...evaluation,suggestionId:other},{...evaluation,outcome:'not_matched'},{...evaluation,outcome:'unsupported',suggestionId:null}])assert.throws(()=>parseClassificationEvaluationView(bad),isCode('CLASSIFICATION_INPUT_INVALID'));
 for(const bad of [{...suggestion,evaluationId:other},{...suggestion,assetId:other},{...suggestion,currentAssignmentVersion:-1}])assert.throws(()=>parseClassificationSuggestionView(bad),isCode('CLASSIFICATION_INPUT_INVALID'));
 for(const control of ['\t','\n','\r']){const value='Email'+control;assert.throws(()=>parseClassificationEvidence({...evidence,matches:[{...evidence.matches[0],value,valueHash:createHash('sha256').update(value).digest('hex')}]}),isCode('CLASSIFICATION_INPUT_INVALID'));}
 assert.throws(()=>parseClassificationTaxonomyView({...taxonomy,definitionHash:'d'.repeat(64)}),isCode('CLASSIFICATION_INPUT_INVALID'));
 assert.throws(()=>parseClassificationTaxonomyView({...taxonomy,currentVersion:0}),isCode('CLASSIFICATION_INPUT_INVALID'));
});

test('signed classification pages bind actor tenant collection target and limit before SQL',async()=>{
 const previous=process.env.SESSION_KEY;process.env.SESSION_KEY='synthetic-classification-unit-cursor-32';
 const fixture=recording(q=>q.sql.includes('from public.classification_taxonomies')?[{value:taxonomy},{value:{...taxonomy,id:other}}]:membership(q));
 try{
  const first=await listClassificationTaxonomies(fixture.tx,p,{limit:1});assert.ok(first.nextCursor);const calls=fixture.calls.length;
  for(const principal of [{...p,id:other},{...p,tenantId:asset}])await assert.rejects(listClassificationTaxonomies(fixture.tx,principal,{limit:1,cursor:first.nextCursor}),isCode('CLASSIFICATION_PAGE_INVALID'));
  await assert.rejects(listClassificationTaxonomies(fixture.tx,p,{limit:2,cursor:first.nextCursor}),isCode('CLASSIFICATION_PAGE_INVALID'));
  await assert.rejects(listClassificationRules(fixture.tx,p,{limit:1,cursor:first.nextCursor}),isCode('CLASSIFICATION_PAGE_INVALID'));
  await assert.rejects(listClassificationAssignments(fixture.tx,p,asset,{limit:1,cursor:first.nextCursor}),isCode('CLASSIFICATION_PAGE_INVALID'));
  const codec=signedCursor(process.env.SESSION_KEY,'classification-taxonomies-v1'),decoded=codec.decode(first.nextCursor) as unknown[];
  for(const cursor of [first.nextCursor.slice(0,-1)+'!',codec.encode([...decoded,'extra']),codec.encode([1,decoded[1],'not-an-id'])])await assert.rejects(listClassificationTaxonomies(fixture.tx,p,{limit:1,cursor}),isCode('CLASSIFICATION_PAGE_INVALID'));
  assert.equal(fixture.calls.length,calls);
  await listClassificationTaxonomies(fixture.tx,p,{limit:1,cursor:first.nextCursor});
  const page=[...fixture.calls].reverse().find(q=>q.sql.includes('from public.classification_taxonomies'))!;assert.match(page.sql,/h\.id>\$\d+::uuid/);assert.deepEqual(page.parameters,[tenant,taxId,2]);
 }finally{await fixture.close();if(previous===undefined)delete process.env.SESSION_KEY;else process.env.SESSION_KEY=previous;}
});

test('asset list authorizes active membership then canonical visibility before bounded selection',async()=>{
 const previous=process.env.SESSION_KEY;process.env.SESSION_KEY='synthetic-classification-unit-cursor-32';
 const fixture=recording(q=>q.sql.includes('from public.assets')?[{visible:1}]:q.sql.includes('from public.classification_evaluations')?[{value:suggestion},{value:{...suggestion,id:other,evaluationId:other}}]:membership(q));
 try{
  const result=await listClassificationSuggestions(fixture.tx,p,asset,{limit:1});assert.equal(result.items[0].currentAssignmentVersion,7);assert.ok(result.nextCursor);
  const auth=fixture.calls.findIndex(q=>q.sql.includes('from "memberships"')),visible=fixture.calls.findIndex(q=>q.sql.includes('from public.assets')),page=fixture.calls.findIndex(q=>q.sql.includes('from public.classification_evaluations'));
  assert.ok(auth<visible&&visible<page);const q=fixture.calls[page];assert.match(q.sql,/r\.tenant_id=\$\d+::uuid and r\.asset_id=\$\d+::uuid and public\.gc_classification_visible\(r\.asset_id,\$\d+::uuid\) and r\.outcome='matched'.*order by r\.id limit/);
  assert.equal(q.sql.includes('count('),false);assert.equal(fixture.calls[visible].sql.includes("status='active'"),false);assert.deepEqual(q.parameters,[actor,tenant,asset,actor,2]);
  const before=fixture.calls.length;await assert.rejects(listClassificationSuggestions(fixture.tx,p,other,{limit:1,cursor:result.nextCursor}),isCode('CLASSIFICATION_PAGE_INVALID'));assert.equal(fixture.calls.length,before);
 }finally{await fixture.close();if(previous===undefined)delete process.env.SESSION_KEY;else process.env.SESSION_KEY=previous;}
});

test('revocation and hidden targets refuse before classification rows are queried',async()=>{
 const previous=process.env.SESSION_KEY;process.env.SESSION_KEY='synthetic-classification-unit-cursor-32';
 for(const revoked of [true,false]){
  const fixture=recording(q=>q.sql.includes('from "memberships"')?[{permissions:revoked?['catalog:read']:p.permissions}]:[]);
  try{await assert.rejects(listClassificationAssignments(fixture.tx,p,asset),isCode(revoked?'FORBIDDEN':'CLASSIFICATION_UNAVAILABLE'));assert.equal(fixture.calls.some(q=>q.sql.includes('from public.classification_assignments')),false);}finally{await fixture.close();}
 }if(previous===undefined)delete process.env.SESSION_KEY;else process.env.SESSION_KEY=previous;
});

test('definition publication normalizes only through pure parser then calls protected command and verifies receipt',async()=>{
 const fixture=recording(q=>q.sql.includes('gc_classification_command')?[{value:{taxonomy}}]:membership(q));
 try{const input={id:taxId,expectedVersion:0,definition:{...definition,name:'  Sensitivity  '}};const result=await publishClassificationTaxonomy(fixture.tx,p,input,key,actor);assert.deepEqual(result,{taxonomy});
  const command=fixture.calls.find(q=>q.sql.includes('gc_classification_command'))!;assert.deepEqual(command.parameters,['classification.taxonomy.publish',key,JSON.stringify({id:taxId,expectedVersion:0,definition}),actor]);
  assert.ok(fixture.calls.findIndex(q=>q.sql.includes('from "memberships"'))<fixture.calls.indexOf(command));
 }finally{await fixture.close();}
 const invalid=recording(q=>q.sql.includes('gc_classification_command')?[{value:{taxonomy:{...taxonomy,id:other}}}]:membership(q));
 try{await assert.rejects(publishClassificationTaxonomy(invalid.tx,p,{id:taxId,expectedVersion:0,definition},key,actor),isCode('CLASSIFICATION_STORAGE_INVALID'));}finally{await invalid.close();}
});

test('evaluation and proposals pass exact commands with required current reads and without local effect claims',async()=>{
 const writer={...p,permissions:['catalog:read','classification:read','classification:write']};
 const fixture=recording(q=>q.sql.includes('from "memberships"')?[{permissions:writer.permissions}]:q.sql.includes('gc_classification_command')?[{value:q.parameters[0]==='classification.evaluate'?{evaluation}:{instance:{id:instanceId}}}]:[]);
 try{assert.deepEqual(await evaluateClassificationAsset(fixture.tx,writer,asset,{id:evaluationId,expectedAssetVersion:3,rule:rulePin},key,actor),{evaluation});assert.deepEqual(await proposeClassification(fixture.tx,writer,proposal,key,actor),{instance:{id:instanceId}});
  const commands=fixture.calls.filter(q=>q.sql.includes('gc_classification_command'));assert.equal(commands.length,2);assert.deepEqual(JSON.parse(commands[0].parameters[2] as string),{assetId:asset,id:evaluationId,expectedAssetVersion:3,rule:rulePin});assert.deepEqual(JSON.parse(commands[1].parameters[2] as string),proposal);
  assert.equal(fixture.calls.some(q=>/insert into|update public|delete from/i.test(q.sql)),false);
 }finally{await fixture.close();}
});

test('classification errors disclose only finite documented failures and keep unknown SQL generic',()=>{
 for(const [code,message,expected] of [['22023','classification request invalid','CLASSIFICATION_INPUT_INVALID'],['40001','classification version conflict','VERSION_CONFLICT'],['40001','classification evidence stale','CLASSIFICATION_EVIDENCE_STALE'],['40001','classification pin stale','CLASSIFICATION_PIN_STALE'],['42501','classification forbidden','CLASSIFICATION_FORBIDDEN'],['P0002','classification resource not found','CLASSIFICATION_UNAVAILABLE'],['40001','private SQL detail','CLASSIFICATION_RETRY'],['42501','private SQL detail','CLASSIFICATION_STORAGE_INVALID'],['XX000','private SQL detail','CLASSIFICATION_STORAGE_INVALID']] as const){const error=classificationFailure({code,message});assert.equal(error.code,expected);assert.equal(error.message.includes('private'),false);}
});

test('classification transaction deadline is shared and cannot renew after a slow operation',async()=>{
 const fixture=recording();const original=Object.getOwnPropertyDescriptor(performance,'now');let clock=100;
 Object.defineProperty(performance,'now',{configurable:true,value:()=>clock});
 try{await classificationQuery(fixture.tx,async()=>{clock+=29000;});await classificationQuery(fixture.tx,async()=>{});assert.deepEqual(fixture.calls.map(q=>q.parameters),[['30000','5000'],['1000','1000']]);
  await assert.rejects(classificationQuery(fixture.tx,async()=>{clock+=1001;}),isCode('CLASSIFICATION_RETRY'));const before=fixture.calls.length;await assert.rejects(classificationQuery(fixture.tx,async()=>{}),isCode('CLASSIFICATION_RETRY'));assert.equal(fixture.calls.length,before);
 }finally{if(original)Object.defineProperty(performance,'now',original);else Reflect.deleteProperty(performance,'now');await fixture.close();}
});

async function appFixture(respond:(q:Query)=>Record<string,unknown>[]=membership,authError?:Problem){
 const fixture=recording(respond),app=Fastify({logger:false});let scopes=0,authentications=0;
 const dependencies:ClassificationDependencies={authenticate:async()=>{authentications++;if(authError)throw authError;return {principal:p,sessionHash:'synthetic',csrf:'synthetic',tenants:[]};},scope:(async(tenantId:string,actorId:string,work:(tx:Tx)=>Promise<unknown>)=>{scopes++;assert.equal(tenantId,tenant);assert.equal(actorId,actor);return work(fixture.tx);}) as ClassificationDependencies['scope']};
 await installClassification(app,dependencies);await app.ready();return {app,fixture,scopes:()=>scopes,authentications:()=>authentications,close:async()=>{await app.close();await fixture.close();}};
}

test('actual Fastify ingress preserves unknown/duplicate refusal before tenant SQL and demands idempotency',async()=>{
 const f=await appFixture();try{
  const inputs=[JSON.stringify({...proposal,extra:'secret'}),JSON.stringify(proposal).replace('"expectedAssignmentVersion":7','"expectedAssignmentVersion":"7"'),JSON.stringify(proposal).replace('"id":','"id":"'+other+'","id":'),JSON.stringify({...proposal,change:{...proposal.change,evidence}})];
  for(const payload of inputs){const r=await f.app.inject({method:'POST',url:'/api/v1/classification/proposals',headers:{'content-type':'application/json','idempotency-key':key},payload});assert.equal(r.statusCode,400,r.body);assert.equal(r.json().code,'CLASSIFICATION_INPUT_INVALID');}
  const missing=await f.app.inject({method:'POST',url:'/api/v1/classification/proposals',payload:proposal});assert.equal(missing.statusCode,400);assert.equal(missing.json().code,'IDEMPOTENCY_REQUIRED');
  for(const query of ['limit=01','limit=1&limit=2','q=secret'])assert.equal((await f.app.inject({url:'/api/v1/classification/taxonomies?'+query})).statusCode,400);
  assert.equal(f.scopes(),0);assert.equal(f.fixture.calls.length,0);assert.ok(f.authentications()>0);
 }finally{await f.close();}
});

test('actual Fastify routes use authenticated tenant scope, preserve envelopes and refuse bad stored receipts',async()=>{
 const previous=process.env.SESSION_KEY;process.env.SESSION_KEY='synthetic-classification-unit-cursor-32';
 const f=await appFixture(q=>q.sql.includes('from public.classification_taxonomies')?[{value:taxonomy}]:q.sql.includes('gc_classification_command')?[{value:{instance:{id:instanceId}}}]:membership(q));
 try{const list=await f.app.inject({url:'/api/v1/classification/taxonomies?limit=1'});assert.equal(list.statusCode,200,list.body);assert.deepEqual(list.json(),{items:[taxonomy],nextCursor:null});
  const propose=await f.app.inject({method:'POST',url:'/api/v1/classification/proposals',headers:{'idempotency-key':key},payload:proposal});assert.equal(propose.statusCode,201,propose.body);assert.deepEqual(propose.json(),{instance:{id:instanceId}});assert.equal(f.scopes(),2);
 }finally{await f.close();if(previous===undefined)delete process.env.SESSION_KEY;else process.env.SESSION_KEY=previous;}
 const bad=await appFixture(q=>q.sql.includes('gc_classification_command')?[{value:{instance:{id:other},secret:'must not be echoed'}}]:membership(q));
 try{const response=await bad.app.inject({method:'POST',url:'/api/v1/classification/proposals',headers:{'idempotency-key':key},payload:proposal});assert.equal(response.statusCode,500);assert.equal(response.json().code,'CLASSIFICATION_STORAGE_INVALID');assert.equal(response.body.includes('must not'),false);}finally{await bad.close();}
});

test('authentication and CSRF failures stop classification handling before JSON or SQL',async()=>{
 const f=await appFixture(membership,new Problem(403,'CSRF_REJECTED','The request could not be verified.'));
 try{const response=await f.app.inject({method:'POST',url:'/api/v1/classification/proposals',headers:{'content-type':'application/json'},payload:'malformed'});assert.equal(response.statusCode,403);assert.equal(response.json().code,'CSRF_REJECTED');assert.equal(f.scopes(),0);assert.equal(f.fixture.calls.length,0);}finally{await f.close();}
});

test('assignment and observed-array egress preserve the closed pure-data contract',()=>{
 const assignment={id:instanceId,assetId:asset,label:evidence.label,version:1,status:'active',suggestionId:evaluationId,approvalInstanceId:instanceId,evidence,evidenceCurrent:true,createdAt:stamp,updatedAt:stamp,updatedBy:actor,reason:''};
 assert.equal(parseClassificationAssignmentView(assignment).reason,'');assert.throws(()=>parseClassificationAssignmentView({...assignment,reason:null}),isCode('CLASSIFICATION_INPUT_INVALID'));
 let read=0;const matches=Object.defineProperty([],0,{enumerable:true,get(){read++;return evidence.matches[0];}});
 assert.throws(()=>parseClassificationEvidence({...evidence,matches}),isCode('CLASSIFICATION_INPUT_INVALID'));assert.equal(read,0);
});

const workflowDefinition={formatVersion:1 as const,id:'classification_review',version:1,name:'Classification review',separationOfDuties:true,stages:[{id:'review',name:'Review',assignments:['steward'],quorum:1,deadlineSeconds:300,rejection:'any' as const}]};
const workflowHash=modelPersistence.hash(workflowDefinition);
const approvalPayload={formatVersion:1,kind:'classification-review',change:'apply',assetId:asset,assignmentId:instanceId,expectedAssignmentVersion:0,suggestionId:evaluationId,label:evidence.label,evidence,evidenceHash:evaluation.evidenceHash,reason:''};
const classRow={id:instanceId,binding:'classification.review',resource_id:asset,resource_version:3,proposal_digest:modelPersistence.hash(approvalPayload),workflow_id:workflowDefinition.id,workflow_version:1,workflow_hash:workflowHash,requester_id:actor,stage_index:0,version:1,status:'pending',expires_at:proposal.expiresAt,created_at:stamp,updated_at:stamp,preconditions_current:true,payload:approvalPayload,result:null,error_code:null};
const taskId='70000000-0000-4000-8000-000000000001';
const classWorkflow={workflow_id:workflowDefinition.id,version:1,definition:workflowDefinition,definition_hash:workflowHash,current_version:1,created_at:stamp,created_by:actor};
function approvalRows(q:Query,permissions:readonly string[]){
 if(q.sql.includes('from "memberships"'))return [{permissions}];
 if(q.sql.includes('select r.*'))return [classRow];
 if(q.sql.includes('select v.*'))return [classWorkflow];
 if(q.sql.includes('select * from public.approval_tasks'))return [{id:taskId,stage_index:0,assignment:'steward',assigned_identity_id:other,version:1,status:'open',opened_at:stamp,expires_at:proposal.expiresAt}];
 return [];
}

test('classification approval reads need family read permission and participant/ACL predicates before LIMIT',async()=>{
 const previous=process.env.SESSION_KEY;process.env.SESSION_KEY='synthetic-classification-unit-cursor-32';
 const reader={...p,permissions:['catalog:read','classification:read']};
 const f=recording(q=>q.sql.includes('select r.id,r.binding')?[classRow]:approvalRows(q,reader.permissions));
 try{const detail=await getApprovalRequest(f.tx,reader,instanceId);assert.equal(detail.binding,'classification.review');assert.equal(Value.Check(approvalHttp.requestView,detail),true);
  if(detail.binding!=='classification.review')assert.fail();assert.equal(detail.payload.evidenceHash,evaluation.evidenceHash);
  const list=await listApprovalRequests(f.tx,reader,{limit:1});assert.equal(list.items[0].binding,'classification.review');
  const query=f.calls.find(q=>q.sql.includes('select r.id,r.binding'))!;assert.match(query.sql,/participant\.assigned_identity_id/);assert.match(query.sql,/r\.binding='classification.review' and public\.gc_classification_visible/);assert.match(query.sql,/gc_classification_payload_current\(r\.payload\)/);assert.ok(query.sql.indexOf('gc_classification_visible')<query.sql.indexOf('limit'));assert.ok(query.parameters.includes(false));
  assert.equal(Value.Check(approvalHttp.requestView,{...detail,binding:'glossary.publish'}),false);assert.equal(Value.Check(approvalHttp.requestView,{...detail,result:{binding:'classification.review',assetId:asset,assignmentId:instanceId,assignmentVersion:1,status:'active',evidenceHash:evaluation.evidenceHash,extra:true}}),false);
 }finally{await f.close();if(previous===undefined)delete process.env.SESSION_KEY;else process.env.SESSION_KEY=previous;}
});

test('classification decisions and cancellation use distinct current family permissions before protected command',async()=>{
 for(const cancel of [false,true])for(const granted of [false,true]){
  const permissions=['catalog:read','classification:read',...(granted?[cancel?'classification:write':'classification:approve']:[])],who={...p,permissions};
  const f=recording(q=>approvalRows(q,permissions));
  try{const operation=cancel?()=>cancelApprovalRequest(f.tx,who,instanceId,{proposalDigest:classRow.proposal_digest,reason:'Reviewed'},key,actor):()=>decideApprovalTask(f.tx,who,instanceId,{proposalDigest:classRow.proposal_digest,taskId,taskVersion:1,decision:'approve',reason:'Reviewed'},key,actor);
   await assert.rejects(operation,isCode(granted?'APPROVAL_STORAGE_INVALID':'FORBIDDEN'));
   const command=f.calls.findIndex(q=>q.sql.includes('gc_approval_command'));assert.equal(command>=0,granted);
   if(granted){const lock=f.calls.findIndex(q=>q.sql.includes('gc_lock_type_migration_principals'));assert.ok(lock>=0&&lock<command);assert.match(f.calls[lock].sql,/union select owner_id from public.classification_rule_versions/);assert.ok(f.calls[lock].parameters.includes(ruleId));assert.match(f.calls[lock].sql,/complete order by principal/);const resources=f.calls.find(q=>q.sql.includes('select id from public.assets'))!;assert.deepEqual(resources.parameters,[tenant,[asset]]);}
  }finally{await f.close();}
 }
});

test('classification audit has finite authorized branches and is excluded from generic fallback',async()=>{
 const f=recording();try{await visibleAudit(f.tx,p).execute();const query=f.calls[0];assert.match(query.sql,/classification\.taxonomy\.publish/);assert.match(query.sql,/classification\.applied/);assert.match(query.sql,/gc_classification_visible\(target\.id/);assert.ok(query.parameters.includes('classification.%'));assert.match(query.sql,/m\.permissions @> '\["catalog:read","classification:read"\]'/);}finally{await f.close();}
});

test('site classification publication resolves canonical requester and records only exact permanent failures after rollback',async()=>{
 const status={id:instanceId,status:'failed' as const,version:3,nextWakeAt:null};
 for(const failure of [{code:'42501',message:'classification forbidden'},{code:'40001',message:'classification evidence stale'},{code:'40001',message:'classification approval expired'},{code:'23514',message:'classification approval invalid'},{code:'40001',message:'unrecognized detail'},{code:'XX000',message:'private driver detail'}]){
  const order:string[]=[],connections:ReturnType<typeof recording>[]=[];
  const nativeScope=(async(tenantId:string,actorId:string,work:(tx:Tx)=>Promise<unknown>)=>{assert.equal(tenantId,tenant);assert.equal(actorId,'site:local');const index=connections.length;order.push('begin'+index);const f=recording(q=>{
   if(q.sql.includes('select r.requester_id'))return [{requester_id:actor,binding:'classification.review',status:'ready',version:2,member_active:true,identity_active:true}];
   if(q.sql.includes('gc_classification_publish'))throw failure;return [];
  });connections.push(f);try{const result=await work(f.tx);order.push('commit'+index);return result;}catch(e){order.push('rollback'+index);throw e;}}) as ClassificationDependencies['scope'];
  const publish=createClassificationPublicationHandler({scope:nativeScope,status:async()=>status});
  try{if(failure.message==='unrecognized detail'||failure.code==='XX000'){await assert.rejects(()=>publish(tenant,instanceId),isCode(failure.code==='40001'?'CLASSIFICATION_RETRY':'CLASSIFICATION_STORAGE_INVALID'));assert.deepEqual(order,['begin0','rollback0']);}
   else{assert.deepEqual(await publish(tenant,instanceId),status);assert.deepEqual(order,['begin0','rollback0','begin1','commit1']);assert.ok(connections[1].calls.some(q=>q.sql.includes('gc_classification_fail')&&q.parameters[0]===instanceId&&q.parameters[1]===2));}
   const change=connections[0].calls.find(q=>q.sql.includes("set_config('gc.actor_id'"))!;assert.deepEqual(change.parameters,[actor]);assert.equal(connections[0].calls.some(q=>q.sql.includes('gc_classification_fail')),false);
  }finally{for(const f of connections)await f.close();}
 }
});

test('site publication dispatcher accepts only canonical stored binding and never guesses an effect',async()=>{
 for(const binding of ['glossary.publish','classification.review','reference.publish','unknown']){
  const f=recording(()=>[{binding}]),calls:string[]=[],status={id:instanceId,status:'succeeded' as const,version:3,nextWakeAt:null};
  const run=createApprovalPublicationDispatcher({scope:(async(t:string,a:string,work:(tx:Tx)=>Promise<unknown>)=>{assert.equal(t,tenant);assert.equal(a,'site:local');const value=await work(f.tx);calls.push('lookup');return value;}) as ClassificationDependencies['scope'],
   glossary:async(t,r)=>{assert.deepEqual([t,r],[tenant,instanceId]);calls.push('glossary');return status;},
   classification:async(t,r)=>{assert.deepEqual([t,r],[tenant,instanceId]);calls.push('classification');return status;},
   reference:async(t,r)=>{assert.deepEqual([t,r],[tenant,instanceId]);calls.push('reference');return status;}});
  try{if(binding==='unknown')await assert.rejects(()=>run(tenant,instanceId),isCode('APPROVAL_STORAGE_INVALID'));else assert.deepEqual(await run(tenant,instanceId),status);
   assert.deepEqual(calls,binding==='unknown'?['lookup']:['lookup',binding==='glossary.publish'?'glossary':binding==='classification.review'?'classification':'reference']);
   assert.deepEqual(f.calls.find(q=>q.sql.includes('select binding'))?.parameters,[tenant,instanceId]);
  }finally{await f.close();}
 }
});

test('reference dispatch does not guess absent requests or accept malformed IDs before canonical lookup',async()=>{
 const f=recording(()=>[]);let lookups=0,effects=0;
 const effect=async()=>{effects++;return {id:instanceId,status:'succeeded' as const,version:3,nextWakeAt:null};};
 const run=createApprovalPublicationDispatcher({scope:(async(_t:string,_a:string,work:(tx:Tx)=>Promise<unknown>)=>{lookups++;return work(f.tx);}) as ClassificationDependencies['scope'],glossary:effect,classification:effect,reference:effect});
 try{for(const pair of [['bad',instanceId],[tenant,'bad']])await assert.rejects(run(pair[0],pair[1]),isCode('APPROVAL_INPUT_INVALID'));assert.equal(lookups,0);
  await assert.rejects(run(tenant,instanceId),isCode('APPROVAL_UNAVAILABLE'));assert.equal(lookups,1);assert.equal(effects,0);
 }finally{await f.close();}
});

test('reference publication failure propagates without invoking another family or inventing success',async()=>{
 const f=recording(()=>[{binding:'reference.publish'}]);const calls:string[]=[],failure=new Problem(503,'REFERENCE_RETRY','Retry the same canonical request.');
 const run=createApprovalPublicationDispatcher({scope:(async(_t:string,_a:string,work:(tx:Tx)=>Promise<unknown>)=>work(f.tx)) as ClassificationDependencies['scope'],
  glossary:async()=>{calls.push('glossary');throw new Error('Wrong family');},classification:async()=>{calls.push('classification');throw new Error('Wrong family');},reference:async(t,r)=>{assert.deepEqual([t,r],[tenant,instanceId]);calls.push('reference');throw failure;}});
 try{await assert.rejects(run(tenant,instanceId),error=>error===failure);assert.deepEqual(calls,['reference']);}finally{await f.close();}
});

test('site publication returns canonical terminal status only after a valid protected result',async()=>{
 const result={binding:'classification.review',assetId:asset,assignmentId:instanceId,assignmentVersion:1,status:'active',evidenceHash:evaluation.evidenceHash};
 for(const valid of [true,false]){
  const order:string[]=[],f=recording(q=>q.sql.includes('select r.requester_id')?[{requester_id:actor,binding:'classification.review',status:'ready',version:2,member_active:true,identity_active:true}]:q.sql.includes('gc_classification_publish')?[{value:valid?result:{...result,extra:'unrecognized'}}]:[]);
  const run=createClassificationPublicationHandler({scope:(async(_t:string,_a:string,work:(tx:Tx)=>Promise<unknown>)=>{try{const value=await work(f.tx);order.push('commit');return value;}catch(e){order.push('rollback');throw e;}}) as ClassificationDependencies['scope'],status:async()=>{order.push('status');return {id:instanceId,status:'succeeded',version:3,nextWakeAt:null};}});
  try{if(valid){const status=await run(tenant,instanceId);assert.equal(status.status,'succeeded');assert.deepEqual(order,['status','commit']);}else{await assert.rejects(()=>run(tenant,instanceId),isCode('CLASSIFICATION_STORAGE_INVALID'));assert.deepEqual(order,['rollback']);}assert.equal(f.calls.some(q=>q.sql.includes('gc_classification_fail')),false);}finally{await f.close();}
 }
});
