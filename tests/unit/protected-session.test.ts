// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { Script } from 'node:vm';
import { AUTHENTICATION_SCALARS as scalar, AuthenticationError, type AuthenticatedSession, type SessionRevokeRequest, type SessionSelectRequest } from '../../packages/authority/src/authentication.ts';
import { AUTHN_LIMITS, type SessionAuthentication } from '../../packages/authn/src/contracts.ts';
import { createSessionApp } from '../../apps/session-api/src/server.ts';
import { randomSecret,sha256 } from '../../packages/authn/src/transport.ts';
import { PAGE,SCRIPT,STYLE } from '../../apps/session-api/src/ui.ts';
const config={publicOrigin:'http://localhost:4314',environment:'isolated-test' as const};
const uuid=(n:number)=>scalar.uuid(`10000000-0000-4000-8000-${n.toString().padStart(12,'0')}`);
function fixture(){const session=randomSecret(),csrf=randomSecret();const descriptor:AuthenticatedSession={formatVersion:1,sessionId:uuid(1),sessionVersion:1,selectedTenantId:uuid(2),identityId:uuid(3),issuerId:uuid(4),identityBindingId:uuid(5),authenticatedAt:scalar.time(new Date(Date.now()-1000).toISOString()),expiresAt:scalar.time(new Date(Date.now()+600_000).toISOString()),generation:1,tenantFenceEpoch:1,authorityMode:'inactive',contentAuthority:false};const calls:{kind:string;value:unknown}[]=[];const auth:SessionAuthentication={async sessionInspect(input){calls.push({kind:'inspect',value:input});return descriptor;},async sessionSelect(input){calls.push({kind:'select',value:input});return {formatVersion:1,sessionId:descriptor.sessionId,sessionVersion:input.expectedSessionVersion+1,selectedTenantId:input.tenantId,tenantFenceEpoch:1,authorityMode:'inactive'};},async sessionRevoke(input){calls.push({kind:'revoke',value:input});return {formatVersion:1,sessionId:descriptor.sessionId,sessionVersion:input.expectedSessionVersion+1,loggedOut:true};}};const headers={host:'localhost:4314',origin:config.publicOrigin,'content-type':'application/json','x-csrf-token':csrf,cookie:`gc_authn_session=${session}; gc_authn_csrf=${csrf}`};return {session,csrf,descriptor,calls,auth,headers};}

test('protected session exposes only actual descriptor plus transportCSRF and ignores legacycookies',async()=>{
 const f=fixture(),app=await createSessionApp(config,f.auth,async()=>{});try{const response=await app.inject({url:'/authn/session',headers:f.headers});assert.equal(response.statusCode,200);assert.deepEqual(response.json(),{session:f.descriptor,csrfToken:f.csrf});assert.deepEqual(f.calls,[{kind:'inspect',value:{sessionHash:sha256(f.session)}}]);assert.equal(response.headers['set-cookie'],undefined);const denied=await app.inject({url:'/authn/session',headers:{host:'localhost:4314',cookie:'gc_session=legacy'}});assert.equal(denied.statusCode,401);assert.equal(f.calls.length,1);assert.equal((await app.inject({url:'/authn/session?tenant=other',headers:f.headers})).statusCode,400);}finally{await app.close();}
});
test('closed selection performs one select and rotates onlycsrf after confirmed completion',async()=>{
 const f=fixture();let release!:()=>void;const original=f.auth.sessionSelect;f.auth.sessionSelect=async input=>{await new Promise<void>(resolve=>release=resolve);return original(input);};const app=await createSessionApp(config,f.auth,async()=>{});try{const pending=app.inject({method:'POST',url:'/authn/tenant',headers:f.headers,payload:{tenantId:uuid(6),expectedSessionVersion:1}});while(!release)await new Promise(resolve=>setImmediate(resolve));assert.equal(f.calls.length,1);release();const response=await pending;assert.equal(response.statusCode,200);assert.equal(f.calls.filter(x=>x.kind==='select').length,1);const input=f.calls.find(x=>x.kind==='select')!.value as SessionSelectRequest;assert.equal(input.sessionHash,sha256(f.session));assert.equal(input.csrfHash,sha256(f.csrf));assert.notEqual(input.replacementCsrfHash,input.csrfHash);const raw=response.headers['set-cookie'];const set=Array.isArray(raw)?raw:[raw as string];assert.equal(set.length,1);assert.match(set[0]!,/^gc_authn_csrf=/);const value=set[0]!.split(';')[0]!.split('=')[1]!;assert.equal(sha256(value),input.replacementCsrfHash);assert.equal(response.json().session.sessionVersion,2);}finally{await app.close();}
});
test('invalidOrigin CSRF duplicatecookies malformed andextraJSON neverinvokeDB orclearcookies',async()=>{
 const f=fixture(),app=await createSessionApp(config,f.auth,async()=>{});const body=JSON.stringify({expectedSessionVersion:1});try{const cases=[{headers:{...f.headers,origin:'null'},payload:body},{headers:Object.fromEntries(Object.entries(f.headers).filter(([name])=>name!=='origin')),payload:body},{headers:{...f.headers,'x-csrf-token':randomSecret()},payload:body},{headers:{...f.headers,cookie:f.headers.cookie+'; gc_authn_csrf='+f.csrf},payload:body},{headers:f.headers,payload:'{"expectedSessionVersion":1,"expectedSessionVersion":2}'},{headers:f.headers,payload:'{"expectedSessionVersion":"1"}'},{headers:f.headers,payload:'{"expectedSessionVersion":1,"identityId":"forged"}'}];for(const item of cases){const response=await app.inject({method:'POST',url:'/authn/logout',...item});assert.ok([400,403].includes(response.statusCode));assert.equal(response.headers['set-cookie'],undefined);assert.equal(response.json().browserCredentialsCleared,undefined);}assert.equal(f.calls.length,0);}finally{await app.close();}
});
test('logout useslastknownversion withoutinspect and onlyconfirms actualrevoke',async()=>{
 const f=fixture();f.auth.sessionInspect=async()=>{throw Error('membership was revoked');};const app=await createSessionApp(config,f.auth,async()=>{});try{const response=await app.inject({method:'POST',url:'/authn/logout',headers:f.headers,payload:{expectedSessionVersion:7}});assert.equal(response.statusCode,200);assert.deepEqual(response.json(),{loggedOut:true,serverRevocationConfirmed:true,browserCredentialsCleared:true});assert.deepEqual(f.calls,[{kind:'revoke',value:{sessionHash:sha256(f.session),csrfHash:sha256(f.csrf),expectedSessionVersion:7} satisfies SessionRevokeRequest}]);const set=response.headers['set-cookie'] as string[];assert.equal(set.length,3);assert.ok(set.every(v=>v.includes('Max-Age=0')&&v.includes('Path=/authn')&&v.includes('HttpOnly')));}finally{await app.close();}
});
test('admitted logout clearscookies onDBfailure uncertaincommit andversionconflict without false success',async()=>{
 for(const [code,status]of [['AUTHN_TRANSPORT_FAILED',503],['AUTHN_EXECUTOR_REJECTED',503],['AUTHN_VERSION_CONFLICT',409],['AUTHN_REJECTED',401]]as const){const f=fixture();let calls=0;f.auth.sessionRevoke=async()=>{calls++;throw new AuthenticationError(code);};const app=await createSessionApp(config,f.auth,async()=>{});try{const response=await app.inject({method:'POST',url:'/authn/logout',headers:f.headers,payload:{expectedSessionVersion:1}});assert.equal(response.statusCode,status);assert.equal(calls,1);assert.equal(response.json().loggedOut,undefined);assert.equal(response.json().browserCredentialsCleared,true);assert.equal(response.json().serverRevocationConfirmed,false);assert.equal((response.headers['set-cookie']as string[]).length,3);}finally{await app.close();}}
});
test('stale selection and failedcommit neverrotatecookies orretry',async()=>{
 for(const [code,status]of [['AUTHN_VERSION_CONFLICT',409],['AUTHN_TRANSPORT_FAILED',503],['AUTHN_REJECTED',403]]as const){const f=fixture();let calls=0;f.auth.sessionSelect=async()=>{calls++;throw new AuthenticationError(code);};const app=await createSessionApp(config,f.auth,async()=>{});try{const response=await app.inject({method:'POST',url:'/authn/tenant',headers:f.headers,payload:{tenantId:uuid(6),expectedSessionVersion:1}});assert.equal(response.statusCode,status);assert.equal(calls,1);assert.equal(response.headers['set-cookie'],undefined);}finally{await app.close();}}
});
test('lifecyclepage serves selfhosted ENAR assets withsame protection andstrictfixedroutes',async()=>{
 const f=fixture(),app=await createSessionApp(config,f.auth,async()=>{});try{for(const [url,mime]of [['/authn/','text/html'],['/authn/ui.js','application/javascript'],['/authn/ui.css','text/css']]){const response=await app.inject({url,headers:{host:'localhost:4314'}});assert.equal(response.statusCode,200);assert.ok(String(response.headers['content-type']).startsWith(mime!));assert.equal(response.headers['cache-control'],'no-store');}assert.equal((await app.inject({url:'/authn/unknown',headers:f.headers})).statusCode,404);assert.equal((await app.inject({method:'HEAD',url:'/authn/session',headers:f.headers})).statusCode,404);assert.equal(f.calls.length,0);assert.doesNotThrow(()=>new Script(SCRIPT));assert.ok(PAGE.includes('aria-live="polite"'));assert.ok(SCRIPT.includes("document.documentElement.dir=language==='ar'?'rtl':'ltr'"));assert.ok(STYLE.includes('@media(max-width:420px)'));assert.equal(/localStorage|sessionStorage|innerHTML/.test(SCRIPT),false);}finally{await app.close();}
});
test('readiness reports onlyfixedstate and neverrawdatabasefailure',async()=>{const f=fixture(),app=await createSessionApp(config,f.auth,async()=>{throw Error('private database secret');});try{const response=await app.inject({url:'/health/ready',headers:{host:'localhost:4314'}});assert.equal(response.statusCode,503);assert.equal(response.body.includes('private database secret'),false);assert.equal(f.calls.length,0);}finally{await app.close();}});

test('original20second deadline aborts andretains occupiedslots; admittedlogout timesout withcookiesclear butnoconfirmedrevoke',async()=>{
 const f=fixture();let started=0;const releases:(()=>void)[]=[];
 f.auth.sessionRevoke=async input=>{started++;if(started<=16)await new Promise<void>(resolve=>releases.push(resolve));return {formatVersion:1,sessionId:uuid(1),sessionVersion:input.expectedSessionVersion+1,loggedOut:true};};
 const app=await createSessionApp(config,f.auth,async()=>{});const begin=performance.now();
 const pending=Array.from({length:16},()=>app.inject({method:'POST',url:'/authn/logout',headers:f.headers,payload:{expectedSessionVersion:1}}));
 try{while(started<16)await new Promise(resolve=>setImmediate(resolve));const responses=await Promise.all(pending);const elapsed=performance.now()-begin;assert.ok(elapsed>=19_000&&elapsed<25_000);for(const response of responses){assert.equal(response.statusCode,503);assert.equal(response.json().browserCredentialsCleared,true);assert.equal(response.json().serverRevocationConfirmed,false);assert.equal(response.json().loggedOut,undefined);assert.equal((response.headers['set-cookie']as string[]).length,3);}assert.equal(started,16);const stillBusy=await app.inject({method:'POST',url:'/authn/logout',headers:f.headers,payload:{expectedSessionVersion:1}});assert.equal(stillBusy.statusCode,503);assert.equal(stillBusy.headers['set-cookie'],undefined);assert.equal(started,16);releases.forEach(resolve=>resolve());await new Promise(resolve=>setImmediate(resolve));const next=await app.inject({method:'POST',url:'/authn/logout',headers:f.headers,payload:{expectedSessionVersion:1}});assert.equal(next.statusCode,200);assert.equal(started,17);}finally{releases.forEach(resolve=>resolve());await app.close();}
});


test('session rate limit blocks further inspection and mutations before database calls or cookie changes', async () => {
 const f = fixture(), app = await createSessionApp(config, f.auth, async () => {});
 try {
  for (let index = 0; index < AUTHN_LIMITS.requestsPerMinute; index++) {
   const response = await app.inject({ url: '/authn/session', headers: { ...f.headers, 'x-forwarded-for': `203.0.113.${index}` } });
   assert.equal(response.statusCode, 200);
  }
  assert.equal(f.calls.length, AUTHN_LIMITS.requestsPerMinute);
  for (const request of [
   { method: 'GET' as const, url: '/authn/session' },
   { method: 'POST' as const, url: '/authn/tenant', payload: { tenantId: uuid(6), expectedSessionVersion: 1 } },
   { method: 'POST' as const, url: '/authn/logout', payload: { expectedSessionVersion: 1 } },
  ]) {
   const response = await app.inject({ ...request, headers: f.headers });
   assert.equal(response.statusCode, 429);
   assert.equal(response.json().code, 'AUTHN_RATE_LIMITED');
   assert.equal(response.headers['set-cookie'], undefined);
   assert.equal(response.json().serverRevocationConfirmed, undefined);
  }
  assert.equal(f.calls.length, AUTHN_LIMITS.requestsPerMinute);
 } finally { await app.close(); }
});
