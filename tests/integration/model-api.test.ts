// SPDX-License-Identifier: Apache-2.0
import {createProtectedCoreSession,closeProtectedCoreSessions} from '../fixtures/protected-core-authentication.ts';
import { pacedFetch as fetch } from '../fixtures/http-budget.ts';
import {test,after} from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {db,scope} from '../../packages/db/src/index.ts';

const A='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',B='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const steward='10000000-0000-4000-8000-000000000001';
const base=process.env.TEST_BASE_URL??'http://api:4310',origin=process.env.PUBLIC_URL??'http://localhost:4310';
async function session(user=steward,tenant=A){return (await createProtectedCoreSession(user,tenant)).headers;}
const request=(path:string,headers:Record<string,string>,method='GET',body?:unknown)=>fetch(base+'/api/v1'+path,{method,headers,body:body===undefined?undefined:JSON.stringify(body)});
const key=()=>({'Idempotency-Key':randomUUID()});
const definition=(id:string)=>({formatVersion:1,id,version:1,attributes:{amount:{type:'decimal',required:true,precision:30,scale:10},status:{type:'enum',values:['draft','approved']}}});

test('model HTTP ingress rejects invalid imports, unauthorized writes and cross-tenant reads',async()=>{
 const headers=await session(),id='api_'+randomUUID().replaceAll('-',''),model=definition(id);
 const duplicate=await request('/models/validate',headers,'POST',{text:'{"formatVersion":1,"id":"x","id":"y","version":1,"attributes":{}}'});
 assert.equal(duplicate.status,422);const invalid=await duplicate.json() as any;assert.ok(invalid.issues.some((issue:any)=>issue.code==='duplicate'));
 assert.equal((await request('/models',{...headers,Origin:'https://invalid.example',...key()},'POST',{definition:model})).status,403);
 const consumer=await session('10000000-0000-4000-8000-000000000003');
 assert.equal((await request('/models',{...consumer,...key()},'POST',{definition:model})).status,403);
 const createHeaders={...headers,...key()};const created=await request('/models',createHeaders,'POST',{definition:model});assert.equal(created.status,201);
 const original=await created.json() as any;assert.equal(original.model.id,id);
 const repeated=await request('/models',createHeaders,'POST',{definition:model});assert.equal(repeated.status,201);assert.equal((await repeated.json() as any).model.definitionHash,original.model.definitionHash);
 assert.equal((await request('/models',createHeaders,'POST',{definition:{...model,attributes:{}}})).status,409);
 const summit=await session('10000000-0000-4000-8000-000000000005',B);
 assert.equal((await request('/models/'+id,summit)).status,404);
 const exported=await request('/models/'+id+'/versions/1',headers);assert.equal(exported.status,200);
 const parsed=await request('/models/validate',headers,'POST',{text:JSON.stringify((await exported.json() as any).model.definition)});assert.equal(parsed.status,200);assert.deepEqual((await parsed.json() as any).definition,model);
});

test('typed asset HTTP writes bind versions, preserve decimals and reauthorize idempotent responses',async()=>{
 const headers=await session(),id='api_'+randomUUID().replaceAll('-',''),model=definition(id),assetId=randomUUID();
 assert.equal((await request('/models',{...headers,...key()},'POST',{definition:model})).status,201);
 await scope(A,steward,tx=>tx.insertInto('assets').values({tenant_id:A,id:assetId,external_id:assetId,name:'Synthetic typed API asset',qualified_name:'api.'+assetId,type:'dataset',observed_at:new Date()}).execute());
 const path='/assets/'+assetId+'/attributes',amount='12345678901234567890.123456789';
 const firstHeaders={...headers,...key(),'If-Match':'1'},body={modelId:id,modelVersion:1,attributes:{amount,status:'approved'}};
 const saved=await request(path,firstHeaders,'PUT',body);assert.equal(saved.status,200);assert.equal(saved.headers.get('etag'),'2');assert.equal((await saved.json() as any).attributes.amount,amount);
 assert.equal((await request(path,{...headers,...key(),'If-Match':'1'},'PUT',body)).status,409);
 const bad=await request(path,{...headers,...key(),'If-Match':'2'},'PUT',{...body,attributes:{amount:123,status:'unknown'}});assert.equal(bad.status,422);assert.ok((await bad.json() as any).issues.length>=2);
 const current=await request(path,headers);assert.equal(current.status,200);assert.equal((await current.json() as any).assetVersion,2);
 await scope(A,steward,tx=>tx.updateTable('assets').set({visibility:'restricted',allowed_identities:'[]'}).where('id','=',assetId).execute());
 assert.equal((await request(path,firstHeaders,'PUT',body)).status,404);
 const lookup=await request('/assets/'+assetId,headers);assert.equal(lookup.status,404);
});

test('publication requires a fresh server preview and leaves existing version pins unchanged',async()=>{
 // Logical model identifiers may equal an asset UUID; audit resource kinds must remain distinct.
 const headers=await session(),assetId='a'+randomUUID().slice(1),id=assetId,model=definition(id);
 assert.equal((await request('/models',{...headers,...key()},'POST',{definition:model})).status,201);
 await scope(A,steward,tx=>tx.insertInto('assets').values({tenant_id:A,id:assetId,external_id:assetId,name:'Synthetic versioned model asset',qualified_name:'api.'+assetId,type:'dataset',observed_at:new Date()}).execute());
 const assigned={modelId:id,modelVersion:1,attributes:{amount:'42.5'}};
 assert.equal((await request('/assets/'+assetId+'/attributes',{...headers,...key(),'If-Match':'1'},'PUT',assigned)).status,200);
 const proposed={...model,version:2,attributes:{...model.attributes,note:{type:'text'}}};
 const preview=async()=>{const result=await request('/models/'+id+'/previews',{...headers,'If-Match':'1'},'POST',{definition:proposed});assert.equal(result.status,200);return (await result.json() as any).preview;};
 const old=await preview();assert.equal(old.assetCount,1);assert.equal(old.pinsPreserved,true);
 assert.equal((await request('/assets/'+assetId+'/attributes',{...headers,...key(),'If-Match':'2'},'PUT',{...assigned,attributes:{amount:'43.5'}})).status,200);
 assert.equal((await request('/models/'+id+'/versions',{...headers,...key(),'If-Match':'1'},'POST',{definition:proposed,previewDigest:old.previewDigest})).status,409);
 const fresh=await preview();assert.notEqual(old.previewDigest,fresh.previewDigest);
 const published=await request('/models/'+id+'/versions',{...headers,...key(),'If-Match':'1'},'POST',{definition:proposed,previewDigest:fresh.previewDigest});assert.equal(published.status,201);
 assert.equal((await (await request('/assets/'+assetId+'/attributes',headers)).json() as any).modelVersion,1);
 assert.deepEqual((await (await request('/models/'+id+'/versions/1',headers)).json() as any).model.definition,model);
 const destructive={...proposed,version:3,attributes:{}};
 const candidate=await request('/models/'+id+'/previews',{...headers,'If-Match':'2'},'POST',{definition:destructive});assert.equal(candidate.status,200);const blocked=(await candidate.json() as any).preview;assert.equal(blocked.requiresExplicitMigration,true);
 const rejected=await request('/models/'+id+'/versions',{...headers,...key(),'If-Match':'2'},'POST',{definition:destructive,previewDigest:blocked.previewDigest});assert.ok([409,422].includes(rejected.status));
 assert.equal((await (await request('/models/'+id,headers)).json() as any).model.currentVersion,2);
 const history=await (await request('/assets/'+assetId,headers)).json() as any;assert.ok(history.audit.length>0);assert.ok(history.audit.every((event:any)=>event.action.startsWith('asset.')));
});
after(async()=>{await closeProtectedCoreSessions(); await db.destroy();});
