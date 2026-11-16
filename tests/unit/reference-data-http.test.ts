// SPDX-License-Identifier: Apache-2.0
/** Actual Fastify/compiled-SQL host boundaries. No PostgreSQL, approval effect,
 * or site runtime is simulated as native qualification by these tests. */
import assert from 'node:assert/strict';
import {test} from 'node:test';
import Fastify from 'fastify';
import {Value} from '@sinclair/typebox/value';
import {Kysely,DummyDriver,PostgresAdapter,PostgresIntrospector,PostgresQueryCompiler,type CompiledQuery,type DatabaseConnection,type QueryResult} from 'kysely';
import type {Tx} from '../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../packages/authz/src/index.ts';
import type {Proposal,PublishedBundle,ReferenceEffectiveState} from '../../packages/domain/src/reference-data-contracts.ts';
import {parseProposal,publicationHash,serializeBundle} from '../../packages/domain/src/reference-data.ts';
import {signedCursor} from '../../packages/domain/src/cursor.ts';
import {referenceFailure,referenceObject,referenceQuery,listReferenceSets,listReferenceReleases,getReferenceEffective,getReferenceRelease,getReferenceAuthoringContext,proposeReferenceRelease} from '../../packages/domain/src/reference-data-service.ts';
import {installReferenceData,referenceHttp,referenceRawQuery,referenceNotModified,parseReferenceRequestJSON,type ReferenceDependencies} from '../../apps/api/src/reference-data.ts';
import {createReferencePublicationHandler} from '../../apps/api/src/reference-data-publication.ts';
const tenant='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',actor='10000000-0000-4000-8000-000000000001',reviewer='10000000-0000-4000-8000-000000000002';
const setId='20000000-0000-4000-8000-000000000001',other='20000000-0000-4000-8000-000000000002',requestId='30000000-0000-4000-8000-000000000001';
const at='2026-11-17T00:00:00.000Z',later='2026-11-18T00:00:00.000Z',key='synthetic-reference-command';
const p:Principal={tenantId:tenant,id:actor,name:'Synthetic author',permissions:['catalog:read','reference:read','reference:write']};
const labels={en:{label:'Order state',description:'Reviewed order states.'},ar:{label:'حالة الطلب',description:'حالات الطلب المعتمدة.'}};
const values=['001','NEW','RETURNED'].map(code=>({code,labels,ownerId:actor,status:'active' as const,validFrom:null,validUntil:null}));
const proposal:Proposal={id:requestId,setId,expectedVersion:0,audience:{visibility:'tenant',allowedIdentityIds:[]},release:{formatVersion:1,kind:'reference-code-list',labels,ownerId:actor,status:'active',activation:{kind:'on-publication'},validUntil:null,values},workflow:{id:'reference_review',version:1,definitionHash:'a'.repeat(64)},assignments:{reviewer},expiresAt:later};
const bundle:PublishedBundle={formatVersion:1,kind:'reference-code-list',setId,version:1,labels,ownerId:actor,status:'active',publishedAt:at,effectiveFrom:at,validUntil:null,values};
const parsedHash=publicationHash(bundle);assert.ok(parsedHash.ok);const hash=parsedHash.value;
const releaseView={release:bundle,publicationHash:hash};
const summary={setId,version:1,labels,ownerId:actor,status:'active',publishedAt:at,effectiveFrom:at,validUntil:null,publicationHash:hash,valueCount:3};
const selection:ReferenceEffectiveState={asOf:at,phase:'EFFECTIVE',version:1,publicationHash:hash,effectiveFrom:at,effectiveUntil:null};
const set={id:setId,latest:summary,effective:selection};
type Query=CompiledQuery;
function recording(respond:(q:Query)=>Record<string,unknown>[]=()=>[]){
 const calls:Query[]=[];const connection:DatabaseConnection={async executeQuery<R>(q:CompiledQuery):Promise<QueryResult<R>>{calls.push(q);return {rows:respond(q) as R[]};},async *streamQuery<R>():AsyncIterableIterator<QueryResult<R>>{throw new Error('No streams in host fixture');}};
 class Driver extends DummyDriver{override async acquireConnection(){return connection;}}
 const db=new Kysely<Record<string,unknown>>({dialect:{createAdapter:()=>new PostgresAdapter(),createDriver:()=>new Driver(),createIntrospector:db=>new PostgresIntrospector(db),createQueryCompiler:()=>new PostgresQueryCompiler()}});
 return {tx:db as unknown as Tx,calls,close:()=>db.destroy()};
}
function rows(q:Query):Record<string,unknown>[] {
 if(q.sql.includes('from "memberships"'))return [{permissions:p.permissions}];
 if(q.sql.includes('clock_timestamp()'))return [{value:at}];
 if(q.sql.startsWith('select s.id'))return [{id:setId}];
 if(q.sql.startsWith('select s.current_version'))return [{version:1,audience:proposal.audience}];
 if(q.sql.includes('octet_length'))return [{body_bytes:Buffer.byteLength(JSON.stringify(bundle)),publication_hash:hash}];
 if(q.sql.startsWith('select r.published_bundle'))return [{value:bundle}];
 if(q.sql.includes('gc_reference_command'))return [{value:{instance:{id:requestId}}}];
 if(q.sql.includes("jsonb_build_object('id',s.id"))return [{value:set}];
 if(q.sql.startsWith('select jsonb_build_object'))return [{value:summary}];
 return [];
}
const hasCode=(code:string)=>(error:unknown)=>error instanceof Problem&&error.code===code;
const savedSecret=process.env.SESSION_KEY;process.env.SESSION_KEY='synthetic-reference-host-cursor-key-32';
test.after(()=>{if(savedSecret===undefined)delete process.env.SESSION_KEY;else process.env.SESSION_KEY=savedSecret;});

test('reference ingress refuses duplicate keys, malformed scalars and hostile descriptors without execution',()=>{
 for(const text of ['{"id":1,"id":2}','{"id":1,"i\\u0064":2}','{"x":{"a":1,"a":2}}','{"x":-0}','{"x":1e999}','{"x":"\\ud800"}','{"__proto__":1}','[]',JSON.stringify({x:'x'.repeat(327680)})])assert.throws(()=>parseReferenceRequestJSON(text),hasCode('REFERENCE_INPUT_INVALID'));
 assert.deepEqual(parseReferenceRequestJSON(JSON.stringify(proposal)),proposal);assert.equal(Value.Check(referenceHttp.proposal,proposal),true);
 for(const value of [{...proposal,extra:true},{...proposal,release:{...proposal.release,values:[{...values[0],secret:'not allowed'}]}},{...proposal,expectedVersion:'0'}])assert.equal(Value.Check(referenceHttp.proposal,value),false);
 let reads=0;const getter=Object.defineProperty({},'id',{enumerable:true,get(){reads++;return requestId;}});assert.throws(()=>referenceObject(getter,['id']),hasCode('REFERENCE_INPUT_INVALID'));
 assert.throws(()=>referenceObject(new Proxy({}, {ownKeys(){reads++;throw 1;}}),[]),hasCode('REFERENCE_INPUT_INVALID'));assert.equal(reads,0);
});

test('reference query grammar refuses duplicate decoded filters, noncanonical numbers and unknown formats',()=>{
 for(const query of ['limit=01','limit=101','limit=1&%6cimit=2','cursor=','asOf=bad&asOf=also','secret=x','q=%FF','limit=1&','format=xml'])assert.throws(()=>referenceRawQuery('/x?'+query,['q','limit','cursor','asOf','format']),hasCode('REFERENCE_INPUT_INVALID'));
 assert.deepEqual({...referenceRawQuery('/x?q=001%25_%5C&limit=25',['q','limit'])},{q:'001%_\\',limit:25});
 assert.equal(referenceNotModified('W/"'+hash+'", "'+'b'.repeat(64)+'"','"'+hash+'"'),true);assert.equal(referenceNotModified(undefined,'"'+hash+'"'),false);assert.throws(()=>referenceNotModified('"bad",*','"'+hash+'"'),hasCode('REFERENCE_INPUT_INVALID'));
});

test('set search filters current visibility before bounded page and escapes literal wildcard text',async()=>{
 const f=recording(q=>q.sql.includes("jsonb_build_object('id',s.id")?[{value:set},{value:{...set,id:other,latest:{...summary,setId:other}}}]:rows(q));
 try{const result=await listReferenceSets(f.tx,p,{q:'001%_\\',limit:1});assert.equal(result.items.length,1);assert.ok(result.nextCursor);
  const q=f.calls.find(q=>q.sql.includes("jsonb_build_object('id',s.id"))!;assert.ok(q.sql.indexOf('gc_reference_visible')<q.sql.indexOf('order by s.id limit'));assert.match(q.sql,/escape '\\'/);assert.ok(q.parameters.includes('%001\\%\\_\\\\%'));assert.equal(q.parameters.at(-1),2);assert.equal(/count\(/i.test(q.sql),false);
  const count=f.calls.length;for(const principal of [{...p,id:reviewer},{...p,tenantId:other}])await assert.rejects(listReferenceSets(f.tx,principal,{q:'001%_\\',limit:1,cursor:result.nextCursor}),hasCode('REFERENCE_PAGE_INVALID'));
  await assert.rejects(listReferenceSets(f.tx,p,{q:'other',limit:1,cursor:result.nextCursor}),hasCode('REFERENCE_PAGE_INVALID'));assert.equal(f.calls.length,count);
 }finally{await f.close();}
});

test('revoked membership and hidden sets refuse before any reference release body is read',async()=>{
 for(const revoked of [true,false]){const f=recording(q=>q.sql.includes('from "memberships"')?[{permissions:revoked?['catalog:read']:p.permissions}]:[]);
  try{await assert.rejects(getReferenceRelease(f.tx,p,setId,1),hasCode(revoked?'FORBIDDEN':'REFERENCE_UNAVAILABLE'));assert.equal(f.calls.some(q=>q.sql.includes('published_bundle')),false);}finally{await f.close();}}
});

test('immutable release read preflights bytes, validates identity and canonical hash and reauthorizes',async()=>{
 const f=recording(rows);try{assert.deepEqual(await getReferenceRelease(f.tx,p,setId,1),releaseView);const size=f.calls.findIndex(q=>q.sql.includes('octet_length')),body=f.calls.findIndex(q=>q.sql.startsWith('select r.published_bundle'));assert.ok(size>=0&&body>size);assert.equal(f.calls.filter(q=>q.sql.includes('from "memberships"')).length,2);assert.equal(f.calls.filter(q=>q.sql.startsWith('select s.id')).length,2);}finally{await f.close();}
 for(const corrupt of ['size','hash','identity']){const f=recording(q=>q.sql.includes('octet_length')?[{body_bytes:corrupt==='size'?524289:100,publication_hash:corrupt==='hash'?'b'.repeat(64):hash}]:q.sql.startsWith('select r.published_bundle')?[{value:corrupt==='identity'?{...bundle,setId:other}:bundle}]:rows(q));
  try{await assert.rejects(getReferenceRelease(f.tx,p,setId,1),hasCode('REFERENCE_STORAGE_INVALID'));if(corrupt==='size')assert.equal(f.calls.some(q=>q.sql.startsWith('select r.published_bundle')),false);}finally{await f.close();}}
});

test('history uses ascending version keysets and independently binds the set, actor and page limit',async()=>{
 const f=recording(q=>q.sql.startsWith('select jsonb_build_object')?[{value:summary},{value:{...summary,version:2}}]:rows(q));
 try{const first=await listReferenceReleases(f.tx,p,setId,{limit:1});assert.ok(first.nextCursor);await listReferenceReleases(f.tx,p,setId,{limit:1,cursor:first.nextCursor});const query=f.calls.filter(q=>q.sql.startsWith('select jsonb_build_object')).at(-1)!;assert.deepEqual(query.parameters,[tenant,setId,1,2]);assert.match(query.sql,/r\.version>\$\d+ order by r\.version limit/);
  await assert.rejects(listReferenceReleases(f.tx,p,other,{limit:1,cursor:first.nextCursor}),hasCode('REFERENCE_PAGE_INVALID'));await assert.rejects(listReferenceReleases(f.tx,p,setId,{limit:2,cursor:first.nextCursor}),hasCode('REFERENCE_PAGE_INVALID'));
 }finally{await f.close();}
});

test('effective values pin resolved clock and release while paginating and apply half-open value intervals',async()=>{
 const selected={...bundle,values:[values[0],{...values[1],validUntil:at},{...values[2],validFrom:at}]};const parsed=publicationHash(selected);assert.ok(parsed.ok);const selectedHash=parsed.value;
 let now=at;
 const f=recording(q=>q.sql.includes('clock_timestamp()')?[{value:now}]:q.sql.includes("jsonb_build_object('id',s.id")?[{value:{...set,latest:{...summary,publicationHash:selectedHash},effective:{...selection,publicationHash:selectedHash}}}]:q.sql.includes('octet_length')?[{body_bytes:100,publication_hash:selectedHash}]:q.sql.startsWith('select r.published_bundle')?[{value:selected}]:rows(q));
 try{const first=await getReferenceEffective(f.tx,p,setId,{limit:1});assert.deepEqual(first.items,[values[0]]);assert.ok(first.nextCursor);now=later;
  const second=await getReferenceEffective(f.tx,p,setId,{limit:1,cursor:first.nextCursor});assert.equal(second.selection.asOf,at);assert.deepEqual(second.items,[selected.values[2]]);assert.equal(second.nextCursor,null);
  const queries=f.calls.filter(q=>q.sql.includes('left join lateral'));assert.equal(queries.length,2);for(const q of queries){assert.ok(q.parameters.includes(at));assert.match(q.sql,/e\.published_at<=.*e\.effective_from<=/);assert.match(q.sql,/n\.published_at<=/);assert.match(q.sql,/order by e\.effective_from desc,e\.version desc limit 1/);}
  await assert.rejects(getReferenceEffective(f.tx,p,setId,{limit:1,asOf:later,cursor:first.nextCursor}),hasCode('REFERENCE_PAGE_INVALID'));
 }finally{await f.close();}
});

test('future instants and changed selected-release cursor pins refuse; expired release never falls back',async()=>{
 let mode='valid';const f=recording(q=>q.sql.includes("jsonb_build_object('id',s.id")?[{value:{...set,effective:mode==='expired'?{...selection,phase:'EXPIRED',effectiveUntil:at,effectiveFrom:'2026-11-16T00:00:00.000Z'}:mode==='changed'?{...selection,publicationHash:'b'.repeat(64)}:selection}}]:rows(q));
 try{await assert.rejects(getReferenceEffective(f.tx,p,setId,{asOf:'0000-01-01T00:00:00.000Z'}),hasCode('REFERENCE_INPUT_INVALID'));await assert.rejects(getReferenceEffective(f.tx,p,setId,{asOf:later}),hasCode('REFERENCE_INPUT_INVALID'));const first=await getReferenceEffective(f.tx,p,setId,{limit:1});assert.ok(first.nextCursor);mode='changed';await assert.rejects(getReferenceEffective(f.tx,p,setId,{limit:1,cursor:first.nextCursor}),hasCode('REFERENCE_PAGE_INVALID'));
  mode='expired';const before=f.calls.filter(q=>q.sql.startsWith('select r.published_bundle')).length;const result=await getReferenceEffective(f.tx,p,setId);assert.deepEqual(result.items,[]);assert.equal(result.nextCursor,null);assert.equal(f.calls.filter(q=>q.sql.startsWith('select r.published_bundle')).length,before);
 }finally{await f.close();}
});

test('authoring context requires write authority and preserves immutable audience and latest exact release',async()=>{
 const f=recording(rows);try{assert.deepEqual(await getReferenceAuthoringContext(f.tx,p,setId),{...releaseView,setId,latestPublishedVersion:1,audience:proposal.audience});await assert.rejects(getReferenceAuthoringContext(f.tx,{...p,permissions:['catalog:read','reference:read']},setId),hasCode('FORBIDDEN'));}finally{await f.close();}
});

test('proposal commands normalize through pure parser and leave retained replay order to protected SQL',async()=>{
 const f=recording(rows);try{const input={...proposal,release:{...proposal.release,labels:{...labels,en:{...labels.en,label:'  Order state  '}}}};assert.deepEqual(await proposeReferenceRelease(f.tx,p,input,key,requestId),{instance:{id:requestId}});
  const q=f.calls.find(q=>q.sql.includes('gc_reference_command'))!;const expected=parseProposal(input,actor);assert.ok(expected.ok);assert.deepEqual(q.parameters,[key,JSON.stringify(expected.value),requestId]);assert.equal(f.calls.some(q=>q.sql.includes('from public.reference_sets')),false);
  assert.equal(f.calls.some(q=>/insert into|delete from|update public/.test(q.sql)),false);
 }finally{await f.close();}
 const bad=recording(q=>q.sql.includes('gc_reference_command')?[{value:{instance:{id:other}}}]:rows(q));try{await assert.rejects(proposeReferenceRelease(bad.tx,p,proposal,key,requestId),hasCode('REFERENCE_STORAGE_INVALID'));}finally{await bad.close();}
});

async function appFixture(respond:(q:Query)=>Record<string,unknown>[]=rows,authError?:Problem){
 const f=recording(respond),app=Fastify({logger:false});let scopes=0,authentications=0;
 const dependencies:ReferenceDependencies={authenticate:async()=>{authentications++;if(authError)throw authError;return {principal:p,sessionHash:'synthetic',csrf:'synthetic',tenants:[]};},scope:(async(t:string,a:string,work:(tx:Tx)=>Promise<unknown>)=>{assert.equal(t,tenant);assert.equal(a,actor);scopes++;return work(f.tx);}) as ReferenceDependencies['scope']};
 await installReferenceData(app,dependencies);await app.ready();return {app,f,scopes:()=>scopes,authentications:()=>authentications,close:async()=>{await app.close();await f.close();}};
}

test('actual Fastify routes reject extra and duplicate wire fields before tenant SQL without coercion',async()=>{
 const f=await appFixture();try{
  const exact=JSON.stringify(proposal);assert.ok(exact.startsWith('{'));const duplicate='{"id":"'+other+'",'+exact.slice(1);
  for(const payload of [JSON.stringify({...proposal,extra:'private'}),duplicate,JSON.stringify({...proposal,expectedVersion:'0'})]){const r=await f.app.inject({method:'POST',url:'/api/v1/reference-data/proposals',headers:{'content-type':'application/json','idempotency-key':key},payload});assert.equal(r.statusCode,400,r.body);assert.equal(r.body.includes('private'),false);}
  assert.equal((await f.app.inject({method:'POST',url:'/api/v1/reference-data/proposals',payload:proposal})).json().code,'IDEMPOTENCY_REQUIRED');assert.equal(f.scopes(),0);assert.equal(f.f.calls.length,0);
  const good=await f.app.inject({method:'POST',url:'/api/v1/reference-data/proposals',headers:{'idempotency-key':key},payload:proposal});assert.equal(good.statusCode,201,good.body);assert.deepEqual(good.json(),{instance:{id:requestId}});assert.equal(f.scopes(),1);
 }finally{await f.close();}
});

test('download returns exact deterministic bytes and distinct strong tags; 304 still refreshes authorization',async()=>{
 const f=await appFixture();try{let jsonTag='';for(const format of ['json','csv'] as const){const expected=serializeBundle(bundle,format);assert.ok(expected.ok);const url=`/api/v1/reference-data/sets/${setId}/releases/1/download?format=${format}`;
  const response=await f.app.inject({url});assert.equal(response.statusCode,200,response.body);assert.equal(response.body,expected.value.body);assert.equal(response.headers.etag,expected.value.etag);assert.equal(Number(response.headers['content-length']),expected.value.byteLength);assert.equal(response.headers['cache-control'],'private, no-cache');assert.match(response.headers['content-disposition']!,/attachment; filename="reference-/);
  if(format==='json')jsonTag=String(response.headers.etag);else assert.notEqual(response.headers.etag,jsonTag);
  const before=f.f.calls.length,conditional=await f.app.inject({url,headers:{'if-none-match':response.headers.etag}});assert.equal(conditional.statusCode,304,conditional.body);assert.equal(conditional.body,'');assert.ok(f.f.calls.slice(before).some(q=>q.sql.includes('from "memberships"')));assert.ok(f.f.calls.slice(before).some(q=>q.sql.startsWith('select s.id')));
 }}finally{await f.close();}
});

test('hidden or revoked conditional downloads disclose no ETag, length or version existence',async()=>{
 for(const denied of ['hidden','revoked']){const f=await appFixture(q=>q.sql.includes('from "memberships"')?[{permissions:denied==='revoked'?['catalog:read']:p.permissions}]:[]);
  try{const r=await f.app.inject({url:`/api/v1/reference-data/sets/${setId}/releases/99/download?format=json`,headers:{'if-none-match':'*'}});assert.equal(r.statusCode,denied==='hidden'?404:403,r.body);assert.equal(r.headers.etag,undefined);assert.equal(r.headers['content-disposition'],undefined);assert.equal(f.f.calls.some(q=>q.sql.includes('published_bundle')),false);}finally{await f.close();}}
});

test('authentication and CSRF refuse before body parsing and no raw SQL errors enter HTTP responses',async()=>{
 const f=await appFixture(rows,new Problem(403,'CSRF_REJECTED','The request could not be verified.'));try{const r=await f.app.inject({method:'POST',url:'/api/v1/reference-data/proposals',headers:{'content-type':'application/json'},payload:'invalid'});assert.equal(r.statusCode,403);assert.equal(r.json().code,'CSRF_REJECTED');assert.equal(f.scopes(),0);}finally{await f.close();}
 const bad=await appFixture(q=>{if(q.sql.includes('gc_reference_command'))throw {code:'XX000',message:'private SQL body and credential'};return rows(q);});try{const r=await bad.app.inject({method:'POST',url:'/api/v1/reference-data/proposals',headers:{'idempotency-key':key},payload:proposal});assert.equal(r.statusCode,500);assert.equal(r.json().code,'REFERENCE_STORAGE_INVALID');assert.equal(r.body.includes('credential'),false);}finally{await bad.close();}
});

test('reference errors are finite and the transaction deadline never renews',async()=>{
 for(const [code,message,expected] of [['P0002','reference resource not found','REFERENCE_UNAVAILABLE'],['42501','reference forbidden','REFERENCE_FORBIDDEN'],['40001','reference version conflict','VERSION_CONFLICT'],['40001','reference schedule stale','REFERENCE_SCHEDULE_STALE'],['40001','IDEMPOTENCY_CONFLICT','IDEMPOTENCY_CONFLICT'],['40001','unknown','REFERENCE_RETRY'],['22023','reference request invalid','REFERENCE_DEFINITION_INVALID'],['23514','reference storage invalid','REFERENCE_STORAGE_INVALID'],['XX000','private','REFERENCE_STORAGE_INVALID']] as const)assert.equal(referenceFailure({code,message}).code,expected);
 const f=recording(),descriptor=Object.getOwnPropertyDescriptor(performance,'now');let now=100;Object.defineProperty(performance,'now',{configurable:true,value:()=>now});
 try{await referenceQuery(f.tx,async()=>{now+=29000;});await referenceQuery(f.tx,async()=>{});assert.deepEqual(f.calls.map(q=>q.parameters),[['30000','5000'],['1000','1000']]);await assert.rejects(referenceQuery(f.tx,async()=>{now+=1001;}),hasCode('REFERENCE_RETRY'));const before=f.calls.length;await assert.rejects(referenceQuery(f.tx,async()=>{}),hasCode('REFERENCE_RETRY'));assert.equal(f.calls.length,before);}finally{if(descriptor)Object.defineProperty(performance,'now',descriptor);else Reflect.deleteProperty(performance,'now');await f.close();}
});

test('site publication uses canonical requester and a separate exact-version fail transaction only for permanent errors',async()=>{
 for(const failure of [{code:'42501',message:'reference forbidden'},{code:'40001',message:'reference schedule stale'},{code:'40001',message:'reference approval expired'},{code:'23514',message:'reference approval invalid'},{code:'40001',message:'unrecognized'},{code:'XX000',message:'private'}]){
  const order:string[]=[],connections:ReturnType<typeof recording>[]=[];const status={id:requestId,status:'failed' as const,version:3,nextWakeAt:null};
  const scope=(async(t:string,a:string,work:(tx:Tx)=>Promise<unknown>)=>{assert.equal(t,tenant);assert.equal(a,'site:local');const index=connections.length;order.push('begin'+index);const f=recording(q=>{if(q.sql.includes('select r.requester_id'))return [{requester_id:actor,binding:'reference.publish',resource_id:setId,resource_version:null,status:'ready',version:2,member_active:true,identity_active:true}];if(q.sql.includes('gc_reference_publish'))throw failure;return [];});connections.push(f);try{const result=await work(f.tx);order.push('commit'+index);return result;}catch(error){order.push('rollback'+index);throw error;}}) as ReferenceDependencies['scope'];
  const publish=createReferencePublicationHandler({scope,status:async()=>status});try{if(['unrecognized','private'].includes(failure.message)){await assert.rejects(publish(tenant,requestId),hasCode(failure.code==='40001'?'REFERENCE_RETRY':'REFERENCE_STORAGE_INVALID'));assert.deepEqual(order,['begin0','rollback0']);}else{assert.deepEqual(await publish(tenant,requestId),status);assert.deepEqual(order,['begin0','rollback0','begin1','commit1']);assert.ok(connections[1].calls.some(q=>q.sql.includes('gc_reference_fail')&&q.parameters[0]===requestId&&q.parameters[1]===2));}
   assert.deepEqual(connections[0].calls.find(q=>q.sql.includes("set_config('gc.actor_id'"))?.parameters,[actor]);assert.equal(connections[0].calls.some(q=>q.sql.includes('gc_reference_fail')),false);
  }finally{for(const f of connections)await f.close();}
 }
});

test('publication receipt must match canonical request target/version before status and commit',async()=>{
 for(const change of ['valid','wrongSet','wrongVersion','extra']){const order:string[]=[],result={binding:'reference.publish',setId:change==='wrongSet'?other:setId,version:change==='wrongVersion'?2:1,publicationHash:hash,publishedAt:at,effectiveFrom:at,...(change==='extra'?{private:'not allowed'}:{})};
  const f=recording(q=>q.sql.includes('select r.requester_id')?[{requester_id:actor,binding:'reference.publish',resource_id:setId,resource_version:null,status:'ready',version:2,member_active:true,identity_active:true}]:q.sql.includes('gc_reference_publish')?[{value:result}]:[]);
  const publish=createReferencePublicationHandler({scope:(async(_t:string,_a:string,work:(tx:Tx)=>Promise<unknown>)=>{try{const value=await work(f.tx);order.push('commit');return value;}catch(error){order.push('rollback');throw error;}}) as ReferenceDependencies['scope'],status:async()=>{order.push('status');return {id:requestId,status:'succeeded',version:3,nextWakeAt:null};}});
  try{if(change==='valid'){assert.equal((await publish(tenant,requestId)).status,'succeeded');assert.deepEqual(order,['status','commit']);}else{await assert.rejects(publish(tenant,requestId),hasCode('REFERENCE_STORAGE_INVALID'));assert.deepEqual(order,['rollback']);}assert.equal(f.calls.some(q=>q.sql.includes('gc_reference_fail')),false);}finally{await f.close();}
 }
});
