// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import Fastify from 'fastify';
import {Kysely,DummyDriver,PostgresAdapter,PostgresIntrospector,PostgresQueryCompiler} from 'kysely';
import {Problem,type Principal} from '../../packages/authz/src/index.ts';
import type {Tx} from '../../packages/db/src/index.ts';
import {installReferenceImport,importQuery,importContentType,type ImportDependencies} from '../../apps/api/src/reference-import.ts';
import {importBase} from '../../packages/domain/src/reference-import-service.ts';
import {IMPORT_LIMITS} from '../../packages/domain/src/reference-import-contracts.ts';
const setId='20000000-0000-4000-8000-000000000001';
const p:Principal={id:'10000000-0000-4000-8000-000000000001',tenantId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',name:'Synthetic author',permissions:['catalog:read','reference:read','reference:write']};
const path='/api/v1/reference-data/sets/'+setId+'/import-preview?mode=merge&expectedVersion=0';
const invalid={state:'invalid' as const,issues:[{code:'FORMAT' as const,row:null,field:'' as const,relatedRow:null}],issuesTruncated:false};
const code=(expected:string)=>(e:unknown)=>e instanceof Problem&&e.code===expected;
// Native tenant/SQL semantics are qualified separately. This fixture exercises
// real Fastify parsing/auth order/body bounds/headers and route dispatch only.
async function fixture(t:test.TestContext,options:{denied?:boolean;failure?:unknown;scannerFailure?:Problem}={}){
 const calls:{auth:number;scope:number;preview:number;scan:number;raw?:Buffer;format?:string}={auth:0,scope:0,preview:0,scan:0};
 const db=new Kysely<Record<string,unknown>>({dialect:{createAdapter:()=>new PostgresAdapter(),createDriver:()=>new DummyDriver(),createIntrospector:db=>new PostgresIntrospector(db),createQueryCompiler:()=>new PostgresQueryCompiler()}});
 const tx=db as unknown as Tx;t.after(()=>db.destroy());
 const dependencies:ImportDependencies={
  scan:async()=>{assert.equal(calls.scope,calls.scan);calls.scan++;if(options.scannerFailure)throw options.scannerFailure;},
  authenticate:(async()=>{calls.auth++;if(options.denied)throw new Problem(403,'CSRF_INVALID','CSRF check failed.');return {principal:p,sessionHash:'synthetic-session-hash',csrf:'synthetic-csrf',tenants:[]};}) as ImportDependencies['authenticate'],
  scope:(async(tenant,actor,work)=>{assert.equal(tenant,p.tenantId);assert.equal(actor,p.id);calls.scope++;return work(tx);}) as ImportDependencies['scope'],
  preview:async(_tx,principal,base,format,mode,raw)=>{assert.equal(principal,p);assert.deepEqual(base,{setId,expectedVersion:0,publicationHash:null});assert.equal(mode,'merge');calls.preview++;calls.raw=Buffer.from(raw);calls.format=format;if(options.failure)throw options.failure;return invalid;}
 };
 const app=Fastify({logger:false});await installReferenceImport(app,dependencies);await app.ready();t.after(()=>app.close());return {app,calls};
}
test('import query accepts only exact bounded base and explicit reconciliation mode',()=>{
 assert.deepEqual(importQuery(path,setId),{base:{setId,expectedVersion:0,publicationHash:null},mode:'merge'});
 const h='a'.repeat(64);assert.equal(importQuery(path.replace('expectedVersion=0','expectedVersion=3&publicationHash='+h),setId).base.publicationHash,h);
 for(const q of ['mode=merge&expectedVersion=01','mode=merge&expectedVersion=-0','mode=replace&expectedVersion=1','mode=replace&expectedVersion=2147483647&publicationHash='+h,'mode=replace&expectedVersion=0&publicationHash='+h,'mode=merge&expectedVersion=0&%6dode=replace','mode=merge&expectedVersion=0&other=x','mode=merge&expectedVersion=0&','mode=merge&expectedVersion=0&x=%FF'])assert.throws(()=>importQuery('/x?'+q,setId),code('REFERENCE_INPUT_INVALID'));
});
test('import base does not invoke hostile accessors or proxy traps',()=>{
 let invoked=0;const getter=Object.defineProperty({},'setId',{enumerable:true,get(){invoked++;return setId;}});
 const proxy=new Proxy({},{ownKeys(){invoked++;return [];}});
 for(const x of [getter,proxy,{setId,expectedVersion:0,publicationHash:null,extra:true},{setId,expectedVersion:-0,publicationHash:null}])assert.throws(()=>importBase(x),code('REFERENCE_INPUT_INVALID'));
 assert.equal(invoked,0);
});
test('import transport only accepts JSON or CSV with explicit UTF-8 compatibility',()=>{
 assert.equal(importContentType('application/json'),'json');assert.equal(importContentType('text/csv; charset=utf-8'),'csv');
 for(const x of [undefined,['text/csv'],'text/plain','text/csv; charset=latin1','text/csv; charset=utf-8; secret=x','application/json;charset="utf-8"'])assert.throws(()=>importContentType(x),code('REFERENCE_INPUT_INVALID'));
});
test('raw JSON and CSV bytes reach the preview unchanged and responses cannot be cached',async t=>{
 const f=await fixture(t);
 for(const type of ['application/json','text/csv; charset=utf-8']){
  const raw=Buffer.from([0x7b,0xff,0x7d]);const res=await f.app.inject({method:'POST',url:path,headers:{'content-type':type},payload:raw});
  assert.equal(res.statusCode,200,res.body);assert.deepEqual(f.calls.raw,raw);assert.equal(f.calls.format,type.startsWith('text/')?'csv':'json');assert.equal(res.headers['cache-control'],'no-store');assert.deepEqual(res.json(),invalid);
 }
 assert.equal(f.calls.auth,2);assert.equal(f.calls.preview,2);
});
test('authentication and CSRF refusal precede parser or preview effects',async t=>{
 const f=await fixture(t,{denied:true});const res=await f.app.inject({method:'POST',url:path,headers:{'content-type':'application/json'},payload:'not-json'});
 assert.equal(res.statusCode,403);assert.equal(res.json().code,'CSRF_INVALID');assert.equal(f.calls.scope,0);assert.equal(f.calls.preview,0);assert.equal(f.calls.scan,0);
});
test('oversized body and unrecognized query never reach preview',async t=>{
 const f=await fixture(t);
 for(const [url,payload] of [[path,Buffer.alloc(IMPORT_LIMITS.rawBytes+1,97)],[path+'&mode=replace','{}']]){
  const res=await f.app.inject({method:'POST',url:url as string,headers:{'content-type':'application/json'},payload});assert.equal(res.statusCode,400);assert.equal(res.json().code,'REFERENCE_INPUT_INVALID');
 }
 assert.equal(f.calls.preview,0);assert.equal(f.calls.scope,0);
});
test('preview failures redact unknown driver values and preserve known stale errors',async t=>{
 for(const failure of [new Error('private-driver-content'),new Problem(409,'REFERENCE_IMPORT_STALE','Reload the current reference head.')]){
  const f=await fixture(t,{failure});const res=await f.app.inject({method:'POST',url:path,headers:{'content-type':'application/json'},payload:'{}'});
  assert.equal(res.statusCode,failure instanceof Problem?409:500);assert.equal(res.body.includes('private-driver-content'),false);assert.equal(res.headers['cache-control'],'no-store');
 }
});

test('enabled scanner rejection or outage stops before database and preview effects',async t=>{
 for(const failure of [new Problem(422,'UPLOAD_REJECTED','The uploaded content was rejected.'),new Problem(503,'UPLOAD_SCANNER_UNAVAILABLE','The upload scanner is unavailable. Retry later.')]){
  const f=await fixture(t,{scannerFailure:failure});const res=await f.app.inject({method:'POST',url:path,headers:{'content-type':'application/json'},payload:'{}'});
  assert.equal(res.statusCode,failure.status);assert.equal(res.json().code,failure.code);assert.equal(f.calls.scan,1);assert.equal(f.calls.scope,0);assert.equal(f.calls.preview,0);assert.equal(res.headers['cache-control'],'no-store');
  if(failure.status===503)assert.equal(res.headers['retry-after'],'5');
 }
});
