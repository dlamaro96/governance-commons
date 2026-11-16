// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import type pg from 'pg';
import {AuthenticationError,createAuthenticationClient,parseAttemptBegin,parseAttemptConsume,parseSessionIssue,parseSessionInspect,parseSessionRevoke,parseSessionSelect,parseAttemptStarted,parseAttemptExchange,parseSessionIssued,parseAuthenticatedSession,parseSessionRevoked,parseSessionSelected,attemptBeginQuery,attemptConsumeQuery,sessionIssueQuery,sessionInspectQuery,sessionRevokeQuery,sessionSelectQuery,safeAuthenticationError,type AuthenticationPool,type AuthenticationSQLValue} from '../../packages/authority/src/authentication.ts';
import type {Parsed} from '../../packages/authority/src/types.ts';
const uuid=(n:number)=>`10000000-0000-4000-8000-${n.toString().padStart(12,'0')}`;
const digest=(n:string)=>n.repeat(64);
const time='2026-11-16T07:00:00.000Z',expiry='2026-11-16T07:30:00.000Z';
function accepted<T>(x:Parsed<T>):T {assert.equal(x.ok,true);if(!x.ok)throw Error('invalid fixture');return x.value;}
const begin=()=>accepted(parseAttemptBegin({stateHash:digest('a'),verifier:'v'.repeat(43),nonceHash:digest('b')}));
const consume=()=>accepted(parseAttemptConsume({attemptId:uuid(1),stateHash:digest('a')}));
const issue=()=>accepted(parseSessionIssue({attemptId:uuid(1),issuer:'https://issuer.example/realm',subject:'subject',audience:'web',nonceHash:digest('b'),idTokenHash:digest('c'),authenticatedAt:time,tokenIssuedAt:time,tokenExpiresAt:expiry,sessionHash:digest('d'),csrfHash:digest('e')}));
const inspect=()=>accepted(parseSessionInspect({sessionHash:digest('d')}));
const revoke=()=>accepted(parseSessionRevoke({sessionHash:digest('d'),csrfHash:digest('e'),expectedSessionVersion:1}));
const select=()=>accepted(parseSessionSelect({...revoke(),tenantId:uuid(5),replacementCsrfHash:digest('f')}));
const started={format_version:1,attempt_id:uuid(1),expires_at:expiry};
const exchanged={...started,verifier:'v'.repeat(43),issuer_id:uuid(2),issuer:'https://issuer.example/realm',client_id:'web',redirect_uri:'https://app.example/auth/callback',nonce_hash:digest('b')};
const issued={format_version:1,session_id:uuid(3),session_version:1,selected_tenant_id:uuid(5),expires_at:expiry};
const authenticated={...issued,identity_id:uuid(4),issuer_id:uuid(2),identity_binding_id:uuid(6),authenticated_at:time,generation:1,tenant_fence_epoch:1,authority_mode:'inactive',content_authority:false};
const revoked={format_version:1,session_id:uuid(3),session_version:2,logged_out:true};
const selected={format_version:1,session_id:uuid(3),session_version:2,selected_tenant_id:uuid(5),tenant_fence_epoch:1,authority_mode:'inactive'};
function connectionFixture(response:unknown){
 const calls:{text:string;values:AuthenticationSQLValue[]|undefined}[]=[],released:boolean[]=[];
 const connection={async query(text:string,values?:AuthenticationSQLValue[]){calls.push({text,values});return {rows:text.startsWith('SELECT')?[response]:[]};},release(error?:boolean){released.push(error??false);}};
 const pool:AuthenticationPool={async connect(){return connection;}};
 return {pool,connection,calls,released};
}
// Compile-time structural check; it makes no connection.
const acceptsNativePool=(pool:pg.Pool):AuthenticationPool=>pool;
void acceptsNativePool;

test('six fixed scalar SQL signatures never interpolate authentication material',()=>{
 const pairs=[
  [attemptBeginQuery(begin()),'gc_authn_attempt_begin',[digest('a'),'v'.repeat(43),digest('b')]],
  [attemptConsumeQuery(consume()),'gc_authn_attempt_consume',[uuid(1),digest('a')]],
  [sessionIssueQuery(issue()),'gc_authn_session_issue',[uuid(1),'https://issuer.example/realm','subject','web',digest('b'),digest('c'),time,time,expiry,digest('d'),digest('e')]],
  [sessionInspectQuery(inspect()),'gc_authn_session_inspect',[digest('d')]],
  [sessionRevokeQuery(revoke()),'gc_authn_session_revoke',[digest('d'),digest('e'),1]],
  [sessionSelectQuery(select()),'gc_authn_session_select',[digest('d'),digest('e'),1,uuid(5),digest('f')]],
 ] as const;
 for(const [query,name,values] of pairs){assert.ok(query.text.includes(`FROM public.${name}(`));assert.deepEqual(query.values,values);assert.equal(query.text.includes(digest('d')),false);assert.equal(Object.isFrozen(query.values),true);assert.equal(Object.isFrozen(query),true);}
 assert.ok(sessionInspectQuery(inspect()).text.includes('AT TIME ZONE \'UTC\''));
});
test('strict request DTOs reject unknown identity/permissions, malformed values and stale-CSRF reuse',()=>{
 assert.equal(parseAttemptBegin({...begin(),identityId:uuid(4)}).ok,false);
 assert.equal(parseSessionIssue({...issue(),permissions:['all']}).ok,false);
 assert.equal(parseSessionIssue({...issue(),authenticatedAt:expiry}).ok,false);
 assert.equal(parseSessionIssue({...issue(),tokenExpiresAt:time}).ok,false);
 assert.equal(parseSessionIssue({...issue(),subject:'x'.repeat(1025)}).ok,false);
 assert.equal(parseSessionIssue({...issue(),subject:'é'.repeat(512)}).ok,true);
 assert.equal(parseSessionIssue({...issue(),subject:'é'.repeat(513)}).ok,false);
 assert.equal(parseSessionRevoke({...revoke(),expectedSessionVersion:'1'}).ok,false);
 assert.equal(parseSessionRevoke({...revoke(),expectedSessionVersion:2_147_483_648}).ok,false);
 assert.equal(parseSessionSelect({...select(),replacementCsrfHash:digest('e')}).ok,false);
 assert.equal(parseSessionInspect({...inspect(),sessionHash:'D'.repeat(64)}).ok,false);
 assert.equal(parseAttemptBegin({...begin(),verifier:'v'.repeat(42)}).ok,false);
 assert.equal(parseAttemptBegin({...begin(),verifier:'v'.repeat(128)}).ok,true);
 assert.equal(parseAttemptBegin({...begin(),verifier:'v'.repeat(129)}).ok,false);
});
test('protocol admission rejects proxies/accessors/cycles and returns detached frozen values',()=>{
 let accessed=0;const request={...inspect()};Object.defineProperty(request,'sessionHash',{get(){accessed++;return digest('d');},enumerable:true});
 assert.equal(parseSessionInspect(request).ok,false);assert.equal(accessed,0);
 assert.equal(parseSessionInspect(new Proxy({}, {ownKeys(){accessed++;throw Error('private');}})).ok,false);assert.equal(accessed,0);
 const input={sessionHash:digest('d')};const parsed=accepted(parseSessionInspect(input));input.sessionHash=digest('e');assert.equal(parsed.sessionHash,digest('d'));assert.equal(Object.isFrozen(parsed),true);
 const cyclic:Record<string,unknown>={sessionHash:digest('d')};cyclic.self=cyclic;assert.equal(parseSessionInspect(cyclic).ok,false);
});
test('six exact SQL response schemas forbid activation, extra disclosures and implicit native-Date coercion',()=>{
 const cases=[ [parseAttemptStarted,started],[parseAttemptExchange,exchanged],[parseSessionIssued,issued],[parseAuthenticatedSession,authenticated],[parseSessionRevoked,revoked],[parseSessionSelected,selected] ] as const;
 for(const [parse,row] of cases){assert.equal(parse(row).ok,true);assert.equal(parse({...row,permissions:[]}).ok,false);assert.equal(parse({...row,format_version:'1'}).ok,false);}
 assert.equal(parseAuthenticatedSession({...authenticated,authority_mode:'scoped'}).ok,false);
 assert.equal(parseAuthenticatedSession({...authenticated,content_authority:true}).ok,false);
 assert.equal(parseAuthenticatedSession({...authenticated,authenticated_at:expiry}).ok,false);
 assert.equal(parseSessionIssued({...issued,expires_at:new Date(expiry)}).ok,false);
 assert.equal(parseSessionRevoked({...revoked,logged_out:'true'}).ok,false);
 const row=accepted(parseAuthenticatedSession(authenticated));assert.equal(row.contentAuthority,false);assert.equal(row.authorityMode,'inactive');assert.equal(Object.isFrozen(row),true);assert.equal('permissions'in row,false);
});
test('inspector opens a fresh real-protocol READ ONLY RR transaction and no write or row-lock query',async()=>{
 const f=connectionFixture(authenticated),client=createAuthenticationClient(f.pool);
 const result=await client.sessionInspect(inspect());assert.equal(result.identityId,uuid(4));
 assert.deepEqual(f.calls.map(c=>c.text),['BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY',sessionInspectQuery(inspect()).text,'COMMIT']);assert.deepEqual(f.released,[false]);
 await client.sessionInspect(inspect());assert.equal(f.calls.filter(c=>c.text.startsWith('BEGIN')).length,2);
 assert.equal(f.calls.some(c=>/FOR (UPDATE|SHARE)|INSERT|UPDATE|DELETE|set_config/i.test(c.text)),false);
});
test('consume owns and completes a READ COMMITTED transaction before returning verifier',async()=>{
 const f=connectionFixture(exchanged);const original=f.connection.query.bind(f.connection);let releaseCommit!:()=>void,committing=false;
 f.connection.query=async(text,values)=>{if(text==='COMMIT'){committing=true;await new Promise<void>(r=>{releaseCommit=r;});}return original(text,values);};
 let delivered=false;const promise=createAuthenticationClient(f.pool).attemptConsume(consume()).then(x=>{delivered=true;return x;});
 for(let i=0;i<10&&!committing;i++)await Promise.resolve();assert.equal(committing,true);assert.equal(delivered,false);assert.deepEqual(f.released,[]);
 releaseCommit();const response=await promise;assert.equal(response.verifier,'v'.repeat(43));assert.equal(delivered,true);
 assert.equal(f.calls[0]!.text,'BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE');assert.equal(f.calls.at(-1)!.text,'COMMIT');assert.deepEqual(f.released,[false]);
});
test('all mutation clients commit exact validated responses and expose no arbitrary query method',async()=>{
 const a=connectionFixture(started);assert.equal((await createAuthenticationClient(a.pool).attemptBegin(begin())).attemptId,uuid(1));
 const i=connectionFixture(issued);assert.equal((await createAuthenticationClient(i.pool).sessionIssue(issue())).sessionVersion,1);
 const r=connectionFixture(revoked);assert.equal((await createAuthenticationClient(r.pool).sessionRevoke(revoke())).loggedOut,true);
 const s=connectionFixture(selected);assert.equal((await createAuthenticationClient(s.pool).sessionSelect(select())).selectedTenantId,uuid(5));
 assert.deepEqual(Object.keys(createAuthenticationClient(s.pool)).sort(),['attemptBegin','attemptConsume','sessionInspect','sessionIssue','sessionRevoke','sessionSelect']);
 for(const f of [a,i,r,s]){assert.equal(f.calls[0]!.text,'BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE');assert.equal(f.calls.at(-1)!.text,'COMMIT');}
});
test('invalid, extra or duplicate result rows roll back and never expose a success DTO',async()=>{
 for(const response of [{...authenticated,content_authority:true},{...authenticated,privateHash:digest('a')},null]){
  const f=connectionFixture(response);await assert.rejects(createAuthenticationClient(f.pool).sessionInspect(inspect()),(e:unknown)=>e instanceof AuthenticationError&&e.code==='AUTHN_RESPONSE_INVALID');
  assert.equal(f.calls.at(-1)!.text,'ROLLBACK');assert.equal(f.calls.some(c=>c.text==='COMMIT'),false);
 }
 const f=connectionFixture(authenticated);const original=f.connection.query.bind(f.connection);f.connection.query=async(text,values)=>{const r=await original(text,values);return text.startsWith('SELECT')?{rows:[authenticated,authenticated]}:r;};
 await assert.rejects(createAuthenticationClient(f.pool).sessionInspect(inspect()),{code:'AUTHN_RESPONSE_INVALID'});assert.equal(f.calls.at(-1)!.text,'ROLLBACK');
});
test('well-shaped mismatched attempt, tenant or lifecycle-version responses still roll back',async()=>{
 const wrongAttempt=connectionFixture({...exchanged,attempt_id:uuid(9)});
 await assert.rejects(createAuthenticationClient(wrongAttempt.pool).attemptConsume(consume()),{code:'AUTHN_RESPONSE_INVALID'});
 const wrongInitial=connectionFixture({...issued,session_version:2});
 await assert.rejects(createAuthenticationClient(wrongInitial.pool).sessionIssue(issue()),{code:'AUTHN_RESPONSE_INVALID'});
 const wrongRevoke=connectionFixture({...revoked,session_version:1});
 await assert.rejects(createAuthenticationClient(wrongRevoke.pool).sessionRevoke(revoke()),{code:'AUTHN_RESPONSE_INVALID'});
 const wrongTenant=connectionFixture({...selected,selected_tenant_id:uuid(9)});
 await assert.rejects(createAuthenticationClient(wrongTenant.pool).sessionSelect(select()),{code:'AUTHN_RESPONSE_INVALID'});
 const wrongVersion=connectionFixture({...selected,session_version:3});
 await assert.rejects(createAuthenticationClient(wrongVersion.pool).sessionSelect(select()),{code:'AUTHN_RESPONSE_INVALID'});
 for(const f of [wrongAttempt,wrongInitial,wrongRevoke,wrongTenant,wrongVersion])assert.equal(f.calls.at(-1)!.text,'ROLLBACK');
});
test('driver failures produce bounded safe codes, rollback and never retain raw causes',async()=>{
 const secret='private-password-and-session-'+digest('a');
 const f=connectionFixture(authenticated);const original=f.connection.query.bind(f.connection);f.connection.query=async(text,values)=>{if(text.startsWith('SELECT'))throw Object.assign(new Error(secret),{code:'28000',detail:secret});return original(text,values);};
 await assert.rejects(createAuthenticationClient(f.pool).sessionInspect(inspect()),(e:unknown)=>{assert.ok(e instanceof AuthenticationError);assert.equal(e.code,'AUTHN_REJECTED');assert.equal(String(e).includes(secret),false);assert.equal('cause'in e,false);return true;});
 assert.equal(f.calls.at(-1)!.text,'ROLLBACK');assert.deepEqual(f.released,[false]);
 let read=0;const hostile={get code(){read++;throw Error(secret);}};assert.equal(safeAuthenticationError(hostile).code,'AUTHN_TRANSPORT_FAILED');assert.equal(read,0);
 assert.equal(safeAuthenticationError(new Proxy({}, {getPrototypeOf(){read++;throw Error(secret);}})).code,'AUTHN_TRANSPORT_FAILED');assert.equal(read,0);
 const spoof=Object.create(AuthenticationError.prototype);Object.defineProperty(spoof,'code',{get(){read++;throw Error(secret);}});
 assert.equal(safeAuthenticationError(spoof).code,'AUTHN_TRANSPORT_FAILED');assert.equal(read,0);
 assert.equal(safeAuthenticationError(new AuthenticationError(secret as never)).code,'AUTHN_TRANSPORT_FAILED');
});
test('BEGIN/COMMIT ambiguity and rollback failure destroy the connection without retrying the operation',async()=>{
 for(const failAt of ['BEGIN','COMMIT','ROLLBACK']){
  const f=connectionFixture(authenticated);const original=f.connection.query.bind(f.connection);let selectedCalls=0;
  f.connection.query=async(text,values)=>{if(text.startsWith('SELECT')){selectedCalls++;if(failAt==='ROLLBACK')throw Error('private');}if(text.startsWith(failAt))throw Error('private');return original(text,values);};
  await assert.rejects(createAuthenticationClient(f.pool).sessionInspect(inspect()),{code:'AUTHN_TRANSPORT_FAILED'});
  assert.deepEqual(f.released,[true]);assert.ok(selectedCalls<=1);
 }
});
test('invalid caller input performs no pool acquisition',()=>{
 let connected=0;const pool:AuthenticationPool={async connect(){connected++;throw Error('must not connect');}};
 assert.throws(()=>createAuthenticationClient(pool).sessionInspect({sessionHash:'bad'} as never),{code:'AUTHN_INPUT_INVALID'});assert.equal(connected,0);
});
