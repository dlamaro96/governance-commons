// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {api,ApiError,setCsrfToken,switchProtectedTenant,revokeProtectedSession} from '../../apps/web/src/api.ts';

/** Fetch-boundary unit coverage only; the real browser/core gate is separate. */
test('main client selects protected routes and submits exact current session versions',async t=>{
 const calls:{url:string;options:RequestInit}[]=[];
 t.mock.method(globalThis,'fetch',async(input:RequestInfo|URL,options:RequestInit={})=>{
  calls.push({url:String(input),options});return Response.json(String(input)==='/authn/logout'?{loggedOut:true,browserCredentialsCleared:true,serverRevocationConfirmed:true}:{ready:true});
 });
 setCsrfToken('synthetic-current-csrf');
 await api('/me');await switchProtectedTenant('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',7);await revokeProtectedSession(8);await api('/example',{method:'POST',body:'{}'});
 assert.deepEqual(calls.map(x=>x.url),['/api/v1/me','/authn/tenant','/authn/logout','/api/v1/example']);
 assert.deepEqual(JSON.parse(String(calls[1]!.options.body)),{tenantId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',expectedSessionVersion:7});
 assert.deepEqual(JSON.parse(String(calls[2]!.options.body)),{expectedSessionVersion:8});
 for(const call of calls){assert.equal(call.options.credentials,'same-origin');assert.equal(new Headers(call.options.headers).get('accept'),'application/json');}
 for(const index of [1,2]){assert.equal(new Headers(calls[index]!.options.headers).get('x-csrf-token'),'synthetic-current-csrf');assert.equal(new Headers(calls[index]!.options.headers).get('content-type'),'application/json');}
 assert.equal(new Headers(calls[3]!.options.headers).get('x-csrf-token'),'');
});
test('tenant conflict preserves its explicit code and never retries a mutation automatically',async t=>{
 let calls=0;t.mock.method(globalThis,'fetch',async()=>{calls++;return Response.json({code:'AUTHN_VERSION_CONFLICT'},{status:409});});
 await assert.rejects(switchProtectedTenant('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',2),error=>error instanceof ApiError&&error.status===409&&error.code==='AUTHN_VERSION_CONFLICT');assert.equal(calls,1);
});
test('uncertain logout remains a failure and clears in-memory CSRF without claiming revocation',async t=>{
 const seen:string[]=[];let logout=true;
 t.mock.method(globalThis,'fetch',async(_input:RequestInfo|URL,options:RequestInit={})=>{
  seen.push(new Headers(options.headers).get('x-csrf-token')??'');
  if(logout)return Response.json({code:'AUTHN_UNAVAILABLE',browserCredentialsCleared:true,serverRevocationConfirmed:false},{status:503});
  return Response.json({ready:true});
 });
 setCsrfToken('synthetic-current-csrf');
 await assert.rejects(revokeProtectedSession(3),error=>error instanceof ApiError&&error.browserCredentialsCleared===true&&error.serverRevocationConfirmed===false);
 logout=false;await api('/example',{method:'POST',body:'{}'});assert.deepEqual(seen,['synthetic-current-csrf','']);
});
test('logout refuses incomplete success responses and transport failures without inventing confirmation',async t=>{
 let value:unknown={loggedOut:true};let failure=false;
 t.mock.method(globalThis,'fetch',async()=>{if(failure)throw new TypeError('synthetic transport failure');return Response.json(value);});
 for(value of [{loggedOut:true},{loggedOut:true,browserCredentialsCleared:true,serverRevocationConfirmed:false},null])await assert.rejects(revokeProtectedSession(1),error=>error instanceof ApiError&&error.code==='AUTHN_UNAVAILABLE');
 failure=true;await assert.rejects(revokeProtectedSession(1),TypeError);
});
test('protected browser mutations require a positive bounded session version before fetch',async t=>{
 let calls=0;t.mock.method(globalThis,'fetch',async()=>{calls++;return Response.json({});});
 for(const version of [undefined,null,0,-1,1.5,2_147_483_648,NaN]){
  await assert.rejects(switchProtectedTenant('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',version as number),error=>error instanceof ApiError&&error.code==='AUTHN_REQUEST_INVALID');
  await assert.rejects(revokeProtectedSession(version as number),error=>error instanceof ApiError&&error.code==='AUTHN_REQUEST_INVALID');
 }
 assert.equal(calls,0);
});
