// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {buildLoginBroker} from '../../apps/login-broker/src/app.ts';
import {createAuthenticationClient,type AuthenticationPool} from '../../packages/authority/src/authentication.ts';
import type {BrokerOidcConfig} from '../../packages/authn/src/contracts.ts';
import type {OidcClient} from '../../packages/authn/src/oidc.ts';
import type {UTC} from '../../packages/authority/src/types.ts';
import {AuthnHttpError,sha256} from '../../packages/authn/src/transport.ts';

const config:BrokerOidcConfig={publicOrigin:'http://localhost:4314',environment:'isolated-test',issuer:'http://localhost:4315/realms/governance',clientId:'governance-protected-web',redirectUri:'http://localhost:4314/authn/callback',authorizationEndpoint:'http://localhost:4315/realms/governance/protocol/openid-connect/auth',tokenEndpoint:'http://localhost:4315/realms/governance/protocol/openid-connect/token',jwksUri:'http://localhost:4315/realms/governance/protocol/openid-connect/certs'};
const id='10000000-0000-0000-0000-000000000001';
/** A controlled pg-compatible protocol fixture tests HTTP/commit sequencing; it is not database qualification. */
async function setup(options:{consumeFailure?:boolean;consumeCommitFailure?:boolean;issueCommitFailure?:boolean;tokenFailure?:boolean;readinessFailure?:boolean}={}){
 const events:string[]=[],inputs:unknown[][]=[];let stateHash='',nonceHash='',verifier='',consumed=false;
 const expires=new Date(Date.now()+299_000).toISOString(),sessionExpires=new Date(Date.now()+900_000).toISOString();
 const pool:AuthenticationPool={async connect(){let phase='transaction';return {
  async query(sql,values=[]){
   if(sql.includes('gc_authn_attempt_begin')){phase='begin';stateHash=String(values[0]);verifier=String(values[1]);nonceHash=String(values[2]);inputs.push(values);events.push('begin:query');return {rows:[{format_version:1,attempt_id:id,expires_at:expires}]};}
   if(sql.includes('gc_authn_attempt_consume')){phase='consume';events.push('consume:query');assert.equal(values[0],id);assert.equal(values[1],stateHash);if(consumed||options.consumeFailure)throw {code:'28000'};consumed=true;return {rows:[{format_version:1,attempt_id:id,verifier,issuer_id:id,issuer:config.issuer,client_id:config.clientId,redirect_uri:config.redirectUri,nonce_hash:nonceHash,expires_at:expires}]};}
   if(sql.includes('gc_authn_session_issue')){phase='issue';events.push('issue:query');inputs.push(values);return {rows:[{format_version:1,session_id:id,session_version:1,selected_tenant_id:id,expires_at:sessionExpires}]};}
   events.push(`${phase}:${sql}`);if(sql==='COMMIT'&&(phase==='consume'&&options.consumeCommitFailure||phase==='issue'&&options.issueCommitFailure))throw {code:'08006'};return {rows:[]};
  },release(){events.push(`${phase}:release`);},
 };}};
 const oidc:OidcClient={async initialize(){},authorizationUrl({state,nonce,verifier:rawVerifier}){assert.equal(sha256(state),stateHash);assert.equal(sha256(nonce),nonceHash);assert.equal(rawVerifier,verifier);return `${config.authorizationEndpoint}?state=${state}&nonce=${nonce}`;},async exchangeAndVerify(attempt,code,{signal}={}){
  events.push('token:exchange');assert.ok(events.includes('consume:COMMIT'));assert.equal(attempt.verifier,verifier);assert.equal(code,'synthetic-code');assert.equal(signal?.aborted,false);if(options.tokenFailure)throw new AuthnHttpError('AUTHN_LOGIN_INVALID');
  const now=new Date().toISOString() as UTC;return {issuer:config.issuer,subject:'synthetic-subject',audience:config.clientId,nonceHash:attempt.nonceHash,idTokenHash:sha256('synthetic-unit-token'),authenticatedAt:now,tokenIssuedAt:now,tokenExpiresAt:sessionExpires as UTC};
 }};
 const app=await buildLoginBroker({config,authentication:createAuthenticationClient(pool),oidc,readiness:async()=>{events.push('readiness');if(options.readinessFailure)throw Error('synthetic readiness failure');}});
 async function login(){const response=await app.inject({method:'GET',url:'/authn/login',headers:{host:'localhost:4314'}});assert.equal(response.statusCode,302);const url=new URL(String(response.headers.location));const cookie=values(response.headers)[0]!.split(';')[0]!;return {response,state:url.searchParams.get('state')!,nonce:url.searchParams.get('nonce')!,cookie};}
 return {app,events,inputs,login};
}
function values(headers:Record<string,unknown>):string[]{const value=headers['set-cookie'];return Array.isArray(value)?value.map(String):value===undefined?[]:[String(value)];}

test('protected broker commits attempt before redirect and emits only the selected HttpOnly local attempt cookie',async t=>{
 const fixture=await setup();t.after(()=>fixture.app.close());const {response,state,nonce,cookie}=await fixture.login();assert.match(state,/^[A-Za-z0-9_-]{43}$/);assert.notEqual(state,nonce);assert.equal(cookie,`gc_authn_attempt=${id}.${state}`);assert.ok(fixture.events.includes('begin:COMMIT'));
 const raw=values(response.headers)[0]!;assert.match(raw,/Path=\/authn; HttpOnly; SameSite=Lax/);assert.doesNotMatch(raw,/Domain=|Secure/);assert.equal(values(response.headers).length,1);assert.equal(response.headers['cache-control'],'no-store');assert.equal(response.headers['referrer-policy'],'no-referrer');
});

test('protected broker consumes and commits before exchange, commits issue before both independent session cookies',async t=>{
 const fixture=await setup();t.after(()=>fixture.app.close());const {state,cookie}=await fixture.login();
 const response=await fixture.app.inject({method:'GET',url:`/authn/callback?code=synthetic-code&state=${state}&iss=${encodeURIComponent(config.issuer)}`,headers:{host:'localhost:4314',cookie}});
 assert.equal(response.statusCode,302);assert.equal(response.headers.location,'/authn/');assert.ok(fixture.events.indexOf('consume:COMMIT')<fixture.events.indexOf('token:exchange'));assert.ok(fixture.events.indexOf('token:exchange')<fixture.events.indexOf('issue:COMMIT'));
 const cookies=values(response.headers);assert.equal(cookies.length,3);assert.match(cookies[0]!,/^gc_authn_attempt=;.*Max-Age=0/);
 const session=/^gc_authn_session=([A-Za-z0-9_-]{43});/.exec(cookies[1]!)![1]!,csrf=/^gc_authn_csrf=([A-Za-z0-9_-]{43});/.exec(cookies[2]!)![1]!;assert.notEqual(session,csrf);assert.notEqual(session,state);
 const issue=fixture.inputs[1]!;assert.equal(issue[9],sha256(session));assert.equal(issue[10],sha256(csrf));assert.equal(response.body,'');
 const replay=await fixture.app.inject({method:'GET',url:`/authn/callback?code=synthetic-code&state=${state}`,headers:{host:'localhost:4314',cookie}});assert.equal(replay.statusCode,401);assert.equal(fixture.events.filter(x=>x==='token:exchange').length,1);
});

test('protected broker rejects malformed, duplicate and unexpected callback fields without consumption',async t=>{
 const fixture=await setup();t.after(()=>fixture.app.close());const {state,cookie}=await fixture.login();
 for(const query of [`code=synthetic-code&state=${state}&state=${state}`,`code=synthetic-code&state=${state}&returnTo=/`, `code=synthetic-code&state=${state}&error=denied`,`code=%C3%28&state=${state}`,`code=${'a'.repeat(4097)}&state=${state}`,`code=synthetic-code&state=${state}&unknown=x`]){
  const response=await fixture.app.inject({url:`/authn/callback?${query}`,headers:{host:'localhost:4314',cookie}});assert.equal(response.statusCode,400);assert.equal(values(response.headers).length,0);
 }
 assert.equal(fixture.events.includes('consume:query'),false);
});

test('protected broker mismatched state, issuer, missing and duplicated cookies cannot consume another login',async t=>{
 const fixture=await setup();t.after(()=>fixture.app.close());const {state,cookie}=await fixture.login();
 const requests=[{url:`/authn/callback?code=synthetic-code&state=${'x'.repeat(43)}`,cookie},{url:`/authn/callback?code=synthetic-code&state=${state}&iss=https%3A%2F%2Fother.invalid`,cookie},{url:`/authn/callback?code=synthetic-code&state=${state}`,cookie:''},{url:`/authn/callback?code=synthetic-code&state=${state}`,cookie:`${cookie}; ${cookie}`}];
 for(const item of requests){const response=await fixture.app.inject({url:item.url,headers:{host:'localhost:4314',...(item.cookie?{cookie:item.cookie}:{})}});assert.ok([400,401].includes(response.statusCode));assert.equal(values(response.headers).length,0);}
 assert.equal(fixture.events.includes('consume:query'),false);
});

test('protected broker matched provider error consumes once and never emits IdP description or URI',async t=>{
 const fixture=await setup();t.after(()=>fixture.app.close());const {state,cookie}=await fixture.login();
 const response=await fixture.app.inject({url:`/authn/callback?error=access_denied&state=${state}&error_description=private-provider-message&error_uri=https%3A%2F%2Fattacker.invalid`,headers:{host:'localhost:4314',cookie}});assert.equal(response.statusCode,401);assert.ok(fixture.events.includes('consume:COMMIT'));assert.equal(fixture.events.includes('token:exchange'),false);assert.equal(fixture.events.includes('issue:query'),false);assert.doesNotMatch(response.body,/private-provider-message|attacker/);assert.equal(values(response.headers).length,1);
});

test('protected broker uncertain consume commit never exchanges and uncertain issue commit never sets credentials',async t=>{
 for(const options of [{consumeCommitFailure:true},{issueCommitFailure:true},{consumeFailure:true},{tokenFailure:true}]){
  const fixture=await setup(options);t.after(()=>fixture.app.close());const {state,cookie}=await fixture.login();
  const response=await fixture.app.inject({url:`/authn/callback?code=synthetic-code&state=${state}`,headers:{host:'localhost:4314',cookie}});assert.equal(response.statusCode,options.consumeFailure||options.tokenFailure?401:503);assert.equal(values(response.headers).length,1);assert.match(values(response.headers)[0]!,/^gc_authn_attempt=;/);
  if(options.consumeCommitFailure||options.consumeFailure)assert.equal(fixture.events.includes('token:exchange'),false);
  assert.ok(fixture.events.filter(x=>x==='issue:query').length<=1);assert.doesNotMatch(response.body,/08006|28000|COMMIT/);
 }
});

test('protected broker has no HEAD side effects, open redirects, legacy session fallback or alternate host trust',async t=>{
 const fixture=await setup();t.after(()=>fixture.app.close());
 for(const request of [{method:'HEAD' as const,url:'/authn/login',headers:{host:'localhost:4314'}},{method:'GET' as const,url:'/authn/login?returnTo=https://attacker.invalid',headers:{host:'localhost:4314'}},{method:'GET' as const,url:'/authn/login',headers:{host:'attacker.invalid','x-forwarded-host':'localhost:4314'}},{method:'GET' as const,url:'/auth/login',headers:{host:'localhost:4314'}}]){const response=await fixture.app.inject(request);assert.ok([400,404].includes(response.statusCode));}
 assert.equal(fixture.events.includes('begin:query'),false);
});

test('protected broker readiness checks native health without creating attempts or spending login rate quota',async t=>{
 const fixture=await setup();t.after(()=>fixture.app.close());for(let index=0;index<35;index++){const result=await fixture.app.inject({url:'/health/ready',headers:{host:'localhost:4314'}});assert.equal(result.statusCode,200);assert.deepEqual(result.json(),{ready:true});}
 assert.equal(fixture.events.includes('begin:query'),false);await fixture.login();
 assert.equal((await fixture.app.inject({url:'/health/ready?x=1',headers:{host:'localhost:4314'}})).statusCode,400);
 assert.equal((await fixture.app.inject({url:'/health/ready',headers:{host:'wrong.invalid'}})).statusCode,400);
 const failed=await setup({readinessFailure:true});t.after(()=>failed.app.close());const result=await failed.app.inject({url:'/health/ready',headers:{host:'localhost:4314'}});assert.equal(result.statusCode,503);assert.doesNotMatch(result.body,/synthetic readiness/);
});
