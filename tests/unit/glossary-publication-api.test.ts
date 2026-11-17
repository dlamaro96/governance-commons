// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {Kysely,DummyDriver,PostgresAdapter,PostgresIntrospector,PostgresQueryCompiler,type CompiledQuery,type DatabaseConnection,type QueryResult} from 'kysely';
import {sql,type Tx} from '../../packages/db/src/index.ts';
import {Problem} from '../../packages/authz/src/index.ts';
import {createGlossaryPublicationHandler} from '../../apps/api/src/glossary-publication.ts';
import {approvalHttp} from '../../apps/api/src/approvals.ts';
import {Value} from '@sinclair/typebox/value';
const tenant='10000000-0000-4000-8000-000000000001',requestId='10000000-0000-4000-8000-000000000002',actor='10000000-0000-4000-8000-000000000003';
const ready={requester_id:actor,binding:'glossary.publish',status:'ready',version:7,name:'Synthetic requester',permissions:['catalog:read','catalog:write','models:read','models:write'],member_active:true,identity_active:true};
const succeeded={id:requestId,status:'succeeded' as const,version:8,nextWakeAt:null};
const receipt={id:requestId,assetId:tenant,assetVersion:1,proposalDigest:'a'.repeat(64),workflowPin:{id:'review',version:1,definitionHash:'b'.repeat(64)},graphReceiptId:null,executedBy:actor,executedAt:'2026-11-16T20:00:00.000Z'};
function fixture(row:Record<string,unknown>|null=ready){
 const queries:CompiledQuery[]=[],scopes:{tenant:string;actor:string}[]=[],events:string[]=[];
 const connection:DatabaseConnection={async executeQuery<R>(q:CompiledQuery):Promise<QueryResult<R>>{queries.push(q);events.push(q.sql);return {rows:(q.sql.includes('select r.requester_id')&&row?[row]:[]) as R[]};},async *streamQuery<R>():AsyncIterableIterator<QueryResult<R>>{throw new Error('No streaming');}};
 class Driver extends DummyDriver {override async acquireConnection(){return connection;}override async beginTransaction(){events.push('BEGIN');}override async commitTransaction(){events.push('COMMIT');}override async rollbackTransaction(){events.push('ROLLBACK');}}
 const db=new Kysely<Record<string,any>>({dialect:{createAdapter:()=>new PostgresAdapter(),createDriver:()=>new Driver(),createIntrospector:db=>new PostgresIntrospector(db),createQueryCompiler:()=>new PostgresQueryCompiler()}});
 const scope=async<T>(t:string,a:string,fn:(tx:Tx)=>Promise<T>)=>{scopes.push({tenant:t,actor:a});return db.transaction().execute(tx=>fn(tx));};
 return {db,scope,queries,scopes,events};
}
test('publication adapter derives exact requester/current membership and changes actor only inside its own transaction',async()=>{
 const f=fixture();let published=false;
 const run=createGlossaryPublicationHandler({scope:f.scope,status:async()=>{assert.equal(published,true);return succeeded;},publish:async(tx,p,id,hooks)=>{
  assert.equal(id,requestId);assert.deepEqual(p,{id:actor,tenantId:tenant,name:ready.name,permissions:ready.permissions});
  assert.deepEqual(Object.keys(hooks).sort(),['assetSnapshot','once','record']);
  const actorQuery=f.queries.find(q=>q.sql.includes("set_config('gc.actor_id'"));assert.deepEqual(actorQuery?.parameters,[actor]);
  await sql`select ${id}::uuid`.execute(tx);published=true;return {id,status:'succeeded',result:receipt};
 }});
 try{assert.deepEqual(await run(tenant,requestId),succeeded);assert.deepEqual(f.scopes,[{tenant,actor:'site:local'}]);
  assert.equal(f.events[0],'BEGIN');assert.equal(f.events.at(-1),'COMMIT');assert.ok(!f.events.includes('ROLLBACK'));
  const source=f.queries.find(q=>q.sql.includes('select r.requester_id'))!;assert.deepEqual(source.parameters,[tenant,requestId]);assert.ok(source.sql.includes('m.tenant_id=r.tenant_id'));assert.ok(!source.sql.includes('for update'));
 }finally{await f.db.destroy();}
});
test('publication rollback precedes a new site-scoped conditional failure and only a finite safe code is passed',async()=>{
 for(const [status,sourceCode,expected] of [[400,'ANY_DETAIL','GLOSSARY_INPUT_INVALID'],[403,'ANY_DETAIL','GLOSSARY_AUTHORITY_REVOKED'],[404,'ANY_DETAIL','GLOSSARY_AUTHORITY_REVOKED'],[409,'ANY_DETAIL','GLOSSARY_STATE_CONFLICT'],[422,'RELATION_PROFILE_LIMIT','GLOSSARY_LIMIT'],[422,'ANY_DETAIL','GLOSSARY_POLICY_INVALID']] as const){
  const f=fixture(),failed={...succeeded,status:'failed' as const};
  const run=createGlossaryPublicationHandler({scope:f.scope,status:async()=>failed,publish:async()=>{throw new Problem(status,sourceCode,'private SQL payload secret');}});
  try{assert.deepEqual(await run(tenant,requestId),failed);assert.deepEqual(f.scopes,[{tenant,actor:'site:local'},{tenant,actor:'site:local'}]);
   const failure=f.queries.find(q=>q.sql.includes('gc_glossary_fail'))!;assert.deepEqual(failure.parameters,[requestId,7,expected]);
   assert.ok(f.events.indexOf('ROLLBACK')<f.events.indexOf(failure.sql));assert.equal(f.events.at(-1),'COMMIT');assert.ok(!JSON.stringify(f.queries).includes('private SQL payload secret'));
  }finally{await f.db.destroy();}
 }
});
test('transient errors remain retryable without a failure transaction or false terminal result',async()=>{
 for(const error of [new Problem(500,'GLOSSARY_STORAGE_INVALID','private'),new Problem(503,'RELATION_RETRY','private'),{code:'40001',message:'unrelated serialization failure'}]){
  const f=fixture();const run=createGlossaryPublicationHandler({scope:f.scope,status:async()=>{throw new Error('No status after failure');},publish:async()=>{throw error;}});
  try{await assert.rejects(run(tenant,requestId),e=>e instanceof Problem&&[500,503].includes(e.status));assert.equal(f.scopes.length,1);assert.equal(f.events.at(-1),'ROLLBACK');assert.ok(!f.queries.some(q=>q.sql.includes('gc_glossary_fail')));}finally{await f.db.destroy();}
 }
});
test('inactive requester fails the recorded ready version without running publication; stale and absent requests cannot be relabelled',async()=>{
 const f=fixture({...ready,member_active:false});let calls=0;
 const run=createGlossaryPublicationHandler({scope:f.scope,status:async()=>({...succeeded,status:'failed'}),publish:async()=>{calls++;throw new Error('Must not publish');}});
 try{await run(tenant,requestId);assert.equal(calls,0);assert.deepEqual(f.queries.find(q=>q.sql.includes('gc_glossary_fail'))?.parameters,[requestId,7,'GLOSSARY_AUTHORITY_REVOKED']);}finally{await f.db.destroy();}
 for(const row of [null,{...ready,status:'cancelled'}]){
  const f=fixture(row);const run=createGlossaryPublicationHandler({scope:f.scope,status:async()=>({...succeeded,status:'cancelled'}),publish:async()=>{throw new Error('Must not publish');}});
  try{if(row)assert.equal((await run(tenant,requestId)).status,'cancelled');else await assert.rejects(run(tenant,requestId));assert.equal(f.scopes.length,1);assert.ok(!f.queries.some(q=>q.sql.includes('gc_glossary_fail')||q.sql.includes("set_config('gc.actor_id'")));}finally{await f.db.destroy();}
 }
});
test('publication receipt response is closed and complete while nullable request results remain representable',()=>{
 assert.equal(Value.Check(approvalHttp.publicationReceipt,receipt),true);
 for(const value of [{...receipt,assetVersion:'1'},{...receipt,secret:'forbidden'},{...receipt,workflowPin:{...receipt.workflowPin,other:1}},{...receipt,graphReceiptId:'wrong'}])assert.equal(Value.Check(approvalHttp.publicationReceipt,value),false);
 for(const key of Object.keys(receipt)){const value:any={...receipt};delete value[key];assert.equal(Value.Check(approvalHttp.publicationReceipt,value),false);}
});
