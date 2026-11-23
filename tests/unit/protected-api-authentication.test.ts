// SPDX-License-Identifier: Apache-2.0
/** Fastify transport and compiled-SQL protocol coverage with an explicit fake
 * driver. Native SQL037 authorization and real browser execution have separate gates. */
import assert from 'node:assert/strict';
import {after,before,test,type TestContext} from 'node:test';
import type {IncomingHttpHeaders} from 'node:http';
import Fastify from 'fastify';
import {Kysely,DummyDriver,PostgresAdapter,PostgresIntrospector,PostgresQueryCompiler,
 type CompiledQuery,type DatabaseConnection,type QueryResult,type TransactionSettings} from 'kysely';
import {db} from '../../packages/db/src/index.ts';
import {authenticate,installAuth} from '../../apps/api/src/security.ts';
import {apiErrorHandler} from '../../apps/api/src/http-errors.ts';
import {sha256} from '../../packages/authn/src/transport.ts';

const origin='http://localhost:4310',actor='10000000-0000-4000-8000-000000000001',tenant='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const token='A'.repeat(43),csrf='B'.repeat(43),cookie=`gc_authn_session=${token}; gc_authn_csrf=${csrf}`;
const envKeys=['AUTHN_ENVIRONMENT','PUBLIC_AUTHN_ORIGIN','PUBLIC_URL','AUTHN_LOGIN_DATABASE_URL','AUTHN_API_DATABASE_URL','MIGRATION_DATABASE_URL','OWNER_DATABASE_URL','DATABASE_OWNER_URL','OIDC_CLIENT_SECRET'] as const;
const original=Object.fromEntries(envKeys.map(key=>[key,process.env[key]]));
before(()=>{for(const key of envKeys)delete process.env[key];process.env.AUTHN_ENVIRONMENT='isolated-test';process.env.PUBLIC_AUTHN_ORIGIN=origin;process.env.PUBLIC_URL=origin;});
after(async()=>{for(const key of envKeys){const value=original[key];if(value===undefined)delete process.env[key];else process.env[key]=value;}await db.destroy();});
const descriptor=()=>({format_version:1,session_id:'20000000-0000-4000-8000-000000000001',session_version:7,
 identity_id:actor,selected_tenant_id:tenant,issuer_id:'30000000-0000-4000-8000-000000000001',
 identity_binding_id:'40000000-0000-4000-8000-000000000001',authenticated_at:new Date(Date.now()-60_000).toISOString(),
 expires_at:new Date(Date.now()+60_000).toISOString(),generation:1,tenant_fence_epoch:2,authority_mode:'inactive',content_authority:false});
async function fixture(t:TestContext,options:{bridge?:()=>Record<string,unknown>[];permissions?:unknown;live?:boolean;withinProfile?:boolean}={}){
 const calls:CompiledQuery[]=[],transactions:TransactionSettings[]=[];let commits=0,rollbacks=0;
 const connection:DatabaseConnection={async executeQuery<R>(query:CompiledQuery):Promise<QueryResult<R>>{
  calls.push(query);let rows:unknown[]=[];
  if(query.sql.includes('gc_app_protected_session_v1'))rows=options.bridge?.()??[descriptor()];
  else if(query.sql.includes('from "identities"'))rows=[{name:'Synthetic protected member'}];
  else if(query.sql.includes('from "memberships"'))rows=[{id:tenant,name:'Synthetic tenant',role:'consumer',permissions:options.permissions??['catalog:read']}];
  else if(query.sql.includes('AS within_profile'))rows=[{live:options.live??true,within_profile:options.withinProfile??true}];
  return {rows:rows as R[]};
 },async *streamQuery<R>():AsyncIterableIterator<QueryResult<R>>{throw Error('No protocol fixture streaming');}};
 class Driver extends DummyDriver{
  override async acquireConnection(){return connection;}
  override async beginTransaction(_connection?:DatabaseConnection,settings?:TransactionSettings){assert.ok(settings);transactions.push(settings);}
  override async commitTransaction(){commits++;}
  override async rollbackTransaction(){rollbacks++;}
 }
 const unitDb=new Kysely<Record<string,any>>({dialect:{createAdapter:()=>new PostgresAdapter(),createDriver:()=>new Driver(),createIntrospector:value=>new PostgresIntrospector(value),createQueryCompiler:()=>new PostgresQueryCompiler()}});
 t.mock.method(db,'transaction',()=>unitDb.transaction());
 const app=Fastify({logger:false});app.setErrorHandler(apiErrorHandler);await installAuth(app);
 app.route({method:['GET','POST'],url:'/api/v1/probe',handler:async request=>{
  const auth=await authenticate(request);return {principal:auth.principal,sessionVersion:auth.sessionVersion,csrfToken:auth.csrf,tenants:auth.tenants};
 }});
 t.after(async()=>{await app.close();await unitDb.destroy();});
 return {app,calls,transactions,commits:()=>commits,rollbacks:()=>rollbacks};
}

test('core authentication derives identity and permissions in one RR read-only snapshot and verifies the returned raw CSRF',async t=>{
 const f=await fixture(t);const response=await f.app.inject({url:'/api/v1/probe',headers:{cookie}});
 assert.equal(response.statusCode,200,response.body);assert.equal(response.json().sessionVersion,7);assert.equal(response.json().csrfToken,csrf);
 assert.deepEqual(response.json().principal,{id:actor,tenantId:tenant,name:'Synthetic protected member',permissions:['catalog:read']});
 assert.deepEqual(f.transactions,[{isolationLevel:'repeatable read',accessMode:'read only'}]);
 const bridge=f.calls.find(query=>query.sql.includes('gc_app_protected_session_v1'))!;
 assert.deepEqual(bridge.parameters,[sha256(token),sha256(csrf)]);
 const context=f.calls.find(query=>query.sql.includes("set_config('gc.tenant_id'"))!;
 assert.deepEqual(context.parameters,[tenant,actor]);assert.ok(f.calls.indexOf(bridge)<f.calls.indexOf(context));
 assert.equal(f.calls.some(query=>/FROM sessions|"sessions"|login_states/.test(query.sql)),false);
 assert.equal(f.commits(),1);assert.equal(f.rollbacks(),0);
});

test('core rejects legacy-only, missing, malformed and duplicate protected credentials before database acquisition',async t=>{
 const f=await fixture(t);
 for(const [value,status] of [[undefined,401],[`gc_session=${token}`,401],[`gc_authn_session=${token}`,401],
  [`${cookie}; gc_authn_session=${token}`,400],[`gc_authn_session=short; gc_authn_csrf=${csrf}`,400],
  [`__Host-gc_authn_session=${token}; gc_authn_csrf=${csrf}`,400]] as const){
  const result=await f.app.inject({url:'/api/v1/probe',headers:value?{cookie:value}:{}});assert.equal(result.statusCode,status,result.body);
 }
 assert.equal(f.calls.length,0);assert.equal(f.transactions.length,0);
});

test('core mutation verifies exact origin and duplicate-aware CSRF before any content or authentication query',async t=>{
 const f=await fixture(t);
 for(const [headers,status] of [[{cookie,origin:'https://wrong.invalid','x-csrf-token':csrf},403],
  [{cookie,origin,'x-csrf-token':'C'.repeat(43)},403],[{cookie,origin},403],
  [{cookie,origin:[origin,origin],'x-csrf-token':csrf},400],
  [{cookie,origin,'x-csrf-token':[csrf,csrf]},400]] as const){
  const result=await f.app.inject({method:'POST',url:'/api/v1/probe',headers:headers as unknown as IncomingHttpHeaders,payload:{}});
  assert.equal(result.statusCode,status,result.body);
 }
 assert.equal(f.calls.length,0);
 const valid=await f.app.inject({method:'POST',url:'/api/v1/probe',headers:{cookie,origin,'x-csrf-token':csrf},payload:{}});
 assert.equal(valid.statusCode,200,valid.body);assert.equal(f.commits(),1);
});

test('core protected SQL rejections and malformed descriptors stay closed and redact driver details',async t=>{
 const conditions=[{bridge:()=>{throw Object.assign(Error('private SQL credential'),{code:'28000'});},status:401,code:'SESSION_EXPIRED'},
  {bridge:()=>{throw Object.assign(Error('private SQL credential'),{code:'42501'});},status:503,code:'AUTHN_UNAVAILABLE'},
  {bridge:()=>[{...descriptor(),content_authority:true}],status:503,code:'AUTHN_UNAVAILABLE'},
  {bridge:()=>[{...descriptor(),permissions:['catalog:write']}],status:503,code:'AUTHN_UNAVAILABLE'}];
 for(const condition of conditions)await t.test(condition.code+' '+condition.status,async child=>{
  const f=await fixture(child,condition);const result=await f.app.inject({url:'/api/v1/probe',headers:{cookie}});
  assert.equal(result.statusCode,condition.status,result.body);assert.equal(result.json().code,condition.code);
  assert.equal(result.body.includes('private SQL credential'),false);assert.equal(f.calls.some(query=>query.sql.includes('from "memberships"')),false);
  assert.equal(f.commits(),0);assert.equal(f.rollbacks(),1);
 });
});

test('core held authentication cannot return expired or over-profile results and does not invent permissions',async t=>{
 for(const [options,status] of [[{live:false},401],[{withinProfile:false},503],[{permissions:'catalog:write'},503]] as const)await t.test(JSON.stringify(options),async child=>{
  const f=await fixture(child,options);const result=await f.app.inject({url:'/api/v1/probe',headers:{cookie}});
  assert.equal(result.statusCode,status,result.body);assert.equal(f.commits(),0);assert.equal(f.rollbacks(),1);
 });
});

test('core keeps only a fixed login navigation alias and refuses legacy lifecycle routes',async t=>{
 const f=await fixture(t);const login=await f.app.inject('/auth/login');assert.equal(login.statusCode,302);assert.equal(login.headers.location,'/authn/login');
 assert.equal((await f.app.inject('/auth/login?redirect=https%3A%2F%2Fwrong.invalid')).statusCode,400);
 for(const [method,url] of [['GET','/auth/callback'],['POST','/auth/logout'],['POST','/api/v1/session/tenant']] as const)
  assert.equal((await f.app.inject({method,url,payload:method==='POST'?{}:undefined})).statusCode,404);
 assert.equal(f.calls.length,0);
});

test('core startup requires explicit consistent protected configuration and excludes privileged executor credentials',async()=>{
 const app=Fastify({logger:false});
 try{
  const saved=process.env.PUBLIC_AUTHN_ORIGIN;delete process.env.PUBLIC_AUTHN_ORIGIN;
  try{await assert.rejects(installAuth(app),{code:'AUTHN_UNAVAILABLE'});}finally{process.env.PUBLIC_AUTHN_ORIGIN=saved;}
  process.env.PUBLIC_URL='http://localhost:9999';try{await assert.rejects(installAuth(app),{code:'AUTHN_UNAVAILABLE'});}finally{process.env.PUBLIC_URL=origin;}
  for(const key of ['AUTHN_LOGIN_DATABASE_URL','AUTHN_API_DATABASE_URL','MIGRATION_DATABASE_URL','OWNER_DATABASE_URL','DATABASE_OWNER_URL'] as const){
   process.env[key]='synthetic-forbidden';try{await assert.rejects(installAuth(app),{code:'AUTHN_UNAVAILABLE'});}finally{delete process.env[key];}
  }
 }finally{await app.close();}
});
