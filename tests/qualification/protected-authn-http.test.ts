// SPDX-License-Identifier: Apache-2.0
/** Actual HTTP + native SCRAM SQL. Synthetic signed probes are separate from Keycloak/browser acceptance. */
import assert from 'node:assert/strict';
import test,{after,type TestContext} from 'node:test';
import {randomUUID} from 'node:crypto';
import pg from 'pg';
import {Problem} from '../../packages/authz/src/index.ts';
import {applicationBridgeQuery,applicationBridgeHash,parseApplicationBridgeManifest} from '../../packages/authn/src/application-installation.ts';
import {createAuthenticationClient} from '../../packages/authority/src/authentication.ts';
import {createNativeAuthenticationPool,verifyNativeAuthenticationPool} from '../../packages/authn/src/pool.ts';
import {fixture,provider,broker,sessionApp,loggedIn,start,callback,request,responseCookies,hash,random,query,scalar,tx,install,counts,activeMember,config,origin,type TokenMode} from './protected-authn-fixture.ts';

// The application singleton remains live through every test in this process.
let closeApplicationDatabase:(()=>Promise<void>)|undefined;
after(async()=>{await closeApplicationDatabase?.();});
async function applicationBridge(t:TestContext,f:Awaited<ReturnType<typeof fixture>>){
 const state=await scalar(f.owner,`SELECT
  (SELECT oid::int8 FROM pg_database WHERE datname=current_database()) database_oid,
  session_user::regrole::oid::int8 owner_oid, 'gc_app'::regrole::oid::int8 app_oid,
  (SELECT manifest_hash FROM gc_authn.application_bridge_receipts ORDER BY sequence DESC LIMIT 1) predecessor,
  (SELECT coalesce(max(bridge_generation),0)::int+1 FROM gc_authn.application_bridge_installations) generation`);
 const base={formatVersion:1,releaseReference:'synthetic-protected-http',deploymentOperatorReference:'synthetic-qualified-owner',expectedDatabaseOid:Number(state.database_oid),expectedOwnerRoleOid:Number(state.owner_oid)};
 const installInput=parseApplicationBridgeManifest({...base,requestId:randomUUID(),predecessorManifestHash:state.predecessor,
  operation:{type:'application-bridge-install',bridgeId:randomUUID(),expectedAppRoleOid:Number(state.app_oid),apiRegistrationId:f.apiId,bridgeGeneration:Number(state.generation),authenticationGeneration:1,expiresAt:f.expiry}});
 assert.ok(installInput.ok);const installQuery=applicationBridgeQuery(installInput.value),installed=await scalar(f.owner,installQuery.text,[...installQuery.values]);
 let revoked=false;
 const revoke=async()=>{
  if(revoked)return;
  // Earlier fixture hooks may already have closed their clients. Own this connection.
  const owner=new pg.Client({connectionString:config.owner,connectionTimeoutMillis:5000,statement_timeout:5000,lock_timeout:2000});await owner.connect();
  try{
   const chain=await scalar(owner,'SELECT manifest_hash FROM gc_authn.application_bridge_receipts ORDER BY sequence DESC LIMIT 1');
   const parsed=parseApplicationBridgeManifest({...base,requestId:randomUUID(),predecessorManifestHash:chain.manifest_hash,operation:{type:'application-bridge-revoke',bridgeId:installed.target_id,expectedManifestHash:installed.manifest_hash}});assert.ok(parsed.ok);
   const q=applicationBridgeQuery(parsed.value),receipt=await scalar(owner,q.text,[...q.values]);revoked=true;assert.equal(receipt.manifest_hash,applicationBridgeHash(parsed.value));
  }finally{await owner.end();}
 };
 t.after(revoke);assert.equal(installed.manifest_hash,applicationBridgeHash(installInput.value));return revoke;
}

test('native executor pools prearm timeouts and refuse credential families and direct legacy/protected storage',async t=>{
 for(const kind of ['login','api'] as const){const pool=createNativeAuthenticationPool(kind,config[kind],'isolated-test');t.after(()=>pool.end());await verifyNativeAuthenticationPool(pool,kind);const c=await pool.connect();try{
  await assert.rejects(c.query('SELECT * FROM gc_authn.sessions'),e=>(e as {code:string}).code==='42501');
  await assert.rejects(c.query('SELECT * FROM public.sessions'),e=>(e as {code:string}).code==='42501');
  await assert.rejects(c.query(kind==='api'?'SELECT * FROM public.gc_authn_attempt_begin($1,$2,$3)':'SELECT * FROM public.gc_authn_session_inspect($1)',kind==='api'?[hash(random()),random(),hash(random())]:[hash(random())]),e=>(e as {code:string}).code==='42501');
 }finally{c.release();}}
 assert.throws(()=>createNativeAuthenticationPool('login',config.api,'isolated-test'));
 assert.throws(()=>createNativeAuthenticationPool('api',config.login,'isolated-test'));
});

test('HTTP exchange sees committed consumption and issues one detached session/provenance/event; replay is refused',async t=>{
 const f=await fixture(t),before=await counts(f.owner),p=await provider(t,f),b=await broker(t,f,p.oidc),a=await start(b.url,p);
 const response=await callback(b.url,a);assert.equal(response.status,302);assert.equal(response.headers.get('location'),'/authn/');assert.equal(response.headers.getSetCookie().length,5);
 const after=await counts(f.owner);assert.equal(after.sessions-before.sessions,1);assert.equal(after.provenance-before.provenance,1);assert.equal(after.events-before.events,1);assert.equal(after.legacy,before.legacy);
 assert.deepEqual(p.stats(),{exchanges:1,observedCommitted:1});assert.equal((await callback(b.url,a)).status,401);assert.deepEqual(await counts(f.owner),after);assert.equal(p.stats().exchanges,1);
 const s=await sessionApp(t,f),r=await request(s.url,'/authn/session',{headers:{cookie:responseCookies(response)}});assert.equal(r.status,200);const body=await r.json();assert.equal(body.session.authorityMode,'inactive');assert.equal(body.session.sessionVersion,1);assert.equal(body.session.selectedTenantId,f.tenant);assert.ok(!('permissions' in body.session));
});

test('wrong state and duplicate callback state do not consume a matching attempt; concurrent correct callback has one winner',async t=>{
 const f=await fixture(t),p=await provider(t,f),b=await broker(t,f,p.oidc),a=await start(b.url,p),before=await counts(f.owner);
 assert.equal((await callback(b.url,{...a,state:random()})).status,401);
 assert.equal((await request(b.url,'/authn/callback?code=x&state='+a.state+'&state='+a.state,{headers:{cookie:a.cookie}})).status,400);
 assert.deepEqual(await counts(f.owner),before);assert.equal(p.stats().exchanges,0);
 const replies=await Promise.all([callback(b.url,a),callback(b.url,a)]);assert.deepEqual(replies.map(r=>r.status).sort(),[302,401]);assert.equal(p.stats().exchanges,1);
});

test('actual RS256 validation refuses nonce issuer audience azp signature algorithm auth_time and time defects without issuance',async t=>{
 const f=await fixture(t),p=await provider(t,f),b=await broker(t,f,p.oidc),before=await counts(f.owner);
 const modes:TokenMode[]=['nonce','issuer','audience','azp','signature','algorithm','missing_auth_time','stale_auth_time','expiry','future_iat'];
 for(const mode of modes){p.setMode(mode);const a=await start(b.url,p),r=await callback(b.url,a);assert.equal(r.status,401,mode);assert.ok(!responseCookies(r).includes('gc_authn_session='));assert.deepEqual(await counts(f.owner),before);assert.equal((await callback(b.url,a)).status,401);}
 assert.equal(p.stats().exchanges,modes.length);
});

test('unprovisioned subject is not JIT-created or admitted',async t=>{
 const f=await fixture(t),unknown=randomUUID(),p=await provider(t,f),b=await broker(t,f,p.oidc),before=await counts(f.owner);p.setSubject(unknown);
 const population=await scalar(f.owner,'SELECT (SELECT count(*) FROM identities) identities,(SELECT count(*) FROM gc_authn.identity_bindings) bindings');
 const a=await start(b.url,p);assert.equal((await callback(b.url,a)).status,401);assert.deepEqual(await counts(f.owner),before);
 assert.deepEqual(await scalar(f.owner,'SELECT (SELECT count(*) FROM identities) identities,(SELECT count(*) FROM gc_authn.identity_bindings) bindings'),population);
 assert.equal((await scalar(f.owner,'SELECT count(*)::int n FROM identities WHERE subject=$1',[unknown])).n,0);
});

test('binding and canonical identity/member revocation between consume and issue prevent sessions',async t=>{
 for(const kind of ['binding','identity','member'] as const){const f=await fixture(t),p=await provider(t,f),b=await broker(t,f,p.oidc),before=await counts(f.owner);p.onExchange(async()=>{
  if(kind==='binding')await install(f.owner,'revoke-binding',[f.bindingId]);
  else if(kind==='identity')await query(f.owner,'UPDATE identities SET active=false WHERE id=$1',[f.identity]);
  else {await activeMember(f,false);await tx(f.owner,async()=>{await query(f.owner,"SELECT set_config('gc.tenant_id',$1,true)",[f.otherTenant]);await query(f.owner,'UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2',[f.otherTenant,f.identity]);});}
 });const a=await start(b.url,p);assert.equal((await callback(b.url,a)).status,401,kind);assert.deepEqual(await counts(f.owner),before);}
});

test('issuer and executor revocation between consume and issue prevent sessions on an existing login connection',async t=>{
 for(const kind of ['issuer','executor'] as const){const f=await fixture(t),p=await provider(t,f),b=await broker(t,f,p.oidc),before=await counts(f.owner);p.onExchange(async()=>{await install(f.owner,kind==='issuer'?'revoke-issuer':'revoke-executor',[kind==='issuer'?f.issuerId:f.loginId]);});const a=await start(b.url,p);assert.equal((await callback(b.url,a)).status,kind==='executor'?503:401);assert.deepEqual(await counts(f.owner),before);}
});

test('token endpoint failure after committed consume does not create a reusable attempt',async t=>{
 const f=await fixture(t),p=await provider(t,f),b=await broker(t,f,p.oidc),before=await counts(f.owner);p.setMode('network');const a=await start(b.url,p);assert.equal((await callback(b.url,a)).status,401);p.setMode('valid');assert.equal((await callback(b.url,a)).status,401);assert.equal(p.stats().exchanges,1);assert.deepEqual(await counts(f.owner),before);
});

test('uncertain consume and issue commits never return protected cookies or retry effects',async t=>{
 for(const phase of ['consume','issue'] as const){const f=await fixture(t),real=createAuthenticationClient(f.loginPool),p=await provider(t,f),before=await counts(f.owner);const auth={...real,
  attemptConsume:async(args:Parameters<typeof real.attemptConsume>[0])=>{const value=await real.attemptConsume(args);if(phase==='consume')throw Error('SYNTHETIC_LOST_COMMIT_RESPONSE');return value;},
  sessionIssue:async(args:Parameters<typeof real.sessionIssue>[0])=>{const value=await real.sessionIssue(args);if(phase==='issue')throw Error('SYNTHETIC_LOST_COMMIT_RESPONSE');return value;}};
 const b=await broker(t,f,p.oidc,auth),a=await start(b.url,p),r=await callback(b.url,a);assert.equal(r.status,503);assert.equal((await r.clone().json()).code,'AUTHN_UNAVAILABLE');assert.ok(!responseCookies(r).includes('gc_authn_session='));assert.equal(p.stats().exchanges,phase==='consume'?0:1);const after=await counts(f.owner);assert.equal(after.sessions-before.sessions,phase==='issue'?1:0);assert.equal((await callback(b.url,a)).status,401);assert.deepEqual(await counts(f.owner),after);}
});

test('Origin CSRF content type duplicate and closed-body failures leave session and cookies unchanged',async t=>{
 const f=await fixture(t),l=await loggedIn(t,f),s=await sessionApp(t,f),before=await counts(f.owner),body=JSON.stringify({tenantId:f.otherTenant,expectedSessionVersion:1});
 const valid={origin,cookie:l.cookie,'content-type':'application/json','x-csrf-token':l.csrf};
 for(const [headers,status,code] of [[{...valid,origin:'http://wrong.invalid'},403,'AUTHN_CSRF_REJECTED'],[{cookie:l.cookie,'content-type':'application/json','x-csrf-token':l.csrf},403,'AUTHN_CSRF_REJECTED'],[{...valid,'x-csrf-token':random()},403,'AUTHN_CSRF_REJECTED'],[{...valid,cookie:l.cookie+'; gc_authn_csrf='+l.csrf},400,'AUTHN_REQUEST_INVALID'],[{...valid,'content-type':'text/plain'},400,'AUTHN_REQUEST_INVALID']] as const){
  const r=await request(s.url,'/authn/tenant',{method:'POST',headers,body});assert.equal(r.status,status);assert.equal((await r.clone().json()).code,code);assert.equal(r.headers.getSetCookie().length,0);assert.deepEqual(await counts(f.owner),before);
 }
 for(const invalid of ['{"tenantId":"'+f.otherTenant+'","tenantId":"'+f.tenant+'","expectedSessionVersion":1}',JSON.stringify({tenantId:f.otherTenant,expectedSessionVersion:'1'}),JSON.stringify({tenantId:f.otherTenant,expectedSessionVersion:1,extra:true})]){const r=await request(s.url,'/authn/tenant',{method:'POST',headers:valid,body:invalid});assert.equal(r.status,400);assert.equal(r.headers.getSetCookie().length,0);assert.deepEqual(await counts(f.owner),before);}
});

test('tenant selection rotates CSRF exactly once and concurrent stale select/logout cannot add another event',async t=>{
 const f=await fixture(t),l=await loggedIn(t,f),s=await sessionApp(t,f),before=await counts(f.owner),headers={origin,cookie:l.cookie,'content-type':'application/json','x-csrf-token':l.csrf};
 const [selected,logout]=await Promise.all([request(s.url,'/authn/tenant',{method:'POST',headers,body:JSON.stringify({tenantId:f.otherTenant,expectedSessionVersion:1})}),request(s.url,'/authn/logout',{method:'POST',headers,body:'{"expectedSessionVersion":1}'})]);
 assert.equal([selected,logout].filter(r=>r.status===200).length,1);if(selected.status===200)assert.equal(selected.headers.getSetCookie().length,4);else assert.equal(logout.headers.getSetCookie().length,5);assert.ok([selected,logout].some(r=>[403,409].includes(r.status)));const after=await counts(f.owner);assert.equal(after.events-before.events,1);
 const stale=await request(s.url,'/authn/tenant',{method:'POST',headers,body:JSON.stringify({tenantId:f.otherTenant,expectedSessionVersion:1})});assert.ok([403,409].includes(stale.status));assert.deepEqual(await counts(f.owner),after);
});

test('logout after canonical member revocation clears credentials and confirms one protected revocation',async t=>{
 const f=await fixture(t),l=await loggedIn(t,f),s=await sessionApp(t,f);await activeMember(f,false);
 assert.equal((await request(s.url,'/authn/session',{headers:{cookie:l.cookie}})).status,401);
 const r=await request(s.url,'/authn/logout',{method:'POST',headers:{origin,cookie:l.cookie,'content-type':'application/json','x-csrf-token':l.csrf},body:'{"expectedSessionVersion":1}'});assert.equal(r.status,200);assert.deepEqual(await r.json(),{loggedOut:true,serverRevocationConfirmed:true,browserCredentialsCleared:true});assert.equal(r.headers.getSetCookie().length,5);assert.ok(r.headers.getSetCookie().every(x=>x.includes('Max-Age=0')));
});

test('real expiry and service restart do not renew a protected session',async t=>{
 const f=await fixture(t,8000),l=await loggedIn(t,f),s=await sessionApp(t,f),before=await request(s.url,'/authn/session',{headers:{cookie:l.cookie}});assert.equal(before.status,200);const descriptor=(await before.json()).session;
 await s.app.close();const restarted=await sessionApp(t,f),after=await request(restarted.url,'/authn/session',{headers:{cookie:l.cookie}});assert.equal(after.status,200);assert.deepEqual((await after.json()).session,descriptor);
 await query(f.owner,'SELECT pg_sleep(greatest(0,extract(epoch FROM $1::timestamptz-clock_timestamp()))+0.05)',[f.expiry]);assert.equal((await request(restarted.url,'/authn/session',{headers:{cookie:l.cookie}})).status,401);
});

test('current and newly opened native API connections reject revoked executor authority',async t=>{
 const f=await fixture(t),l=await loggedIn(t,f),client=createAuthenticationClient(f.apiPool);await client.sessionInspect({sessionHash:hash(l.session) as never});await install(f.owner,'revoke-executor',[f.apiId]);await assert.rejects(client.sessionInspect({sessionHash:hash(l.session) as never}));
 const fresh=new pg.Client({connectionString:f.apiUrl,connectionTimeoutMillis:5000,statement_timeout:5000,lock_timeout:2000});
 await fresh.connect();try{await fresh.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');await assert.rejects(fresh.query('SELECT * FROM public.gc_authn_session_inspect($1)',[hash(l.session)]),e=>(e as {code:string}).code==='42501');await fresh.query('ROLLBACK');}finally{await fresh.end();}
});

test('real legacy authentication and protected HTTP routes do not accept the other session family',async t=>{
 const f=await fixture(t),l=await loggedIn(t,f),s=await sessionApp(t,f);
 process.env.DATABASE_URL=config.legacy;process.env.PUBLIC_URL=origin;process.env.PUBLIC_AUTHN_ORIGIN=origin;process.env.AUTHN_ENVIRONMENT='isolated-test';
 const [{default:Fastify},{default:cookiePlugin},{authenticate},{db}]=await Promise.all([import('fastify'),import('@fastify/cookie'),import('../../apps/api/src/security.ts'),import('../../packages/db/src/index.ts')]);
 closeApplicationDatabase=()=>db.destroy();
 // Real HTTP exercises the actual application authenticate boundary; this local
 // route does not claim qualification of every separately tested content handler.
 const app=Fastify({logger:false});await app.register(cookiePlugin);
 const read=async(req:Parameters<typeof authenticate>[0],reply:import('fastify').FastifyReply)=>{
  try{const auth=await authenticate(req);return {identityId:auth.principal.id,tenantId:auth.principal.tenantId,sessionVersion:auth.sessionVersion};}
  catch(error){if(error instanceof Problem)return reply.code(error.status).send({code:error.code});throw error;}
 };
 app.get('/api/me',read);app.post('/api/me',read);
 const url=await app.listen({port:0,host:'127.0.0.1'});t.after(()=>app.close());
 assert.equal((await request(url,'/api/me',{headers:{cookie:l.cookie}})).status,503);
 const revoke=await applicationBridge(t,f);
 const accepted=await request(url,'/api/me',{headers:{cookie:l.cookie}});assert.equal(accepted.status,200);assert.deepEqual(await accepted.json(),{identityId:f.identity,tenantId:f.tenant,sessionVersion:1});
 assert.equal((await request(url,'/api/me',{method:'POST',headers:{cookie:l.cookie,origin,'x-csrf-token':l.csrf}})).status,200);
 assert.equal((await request(url,'/api/me',{method:'POST',headers:{cookie:l.cookie,origin,'x-csrf-token':random()}})).status,403);
 assert.equal((await request(url,'/api/me',{headers:{cookie:'gc_session='+l.session}})).status,401);
 const legacy=random(),csrf=random();await query(f.owner,"INSERT INTO public.sessions(id_hash,identity_id,tenant_id,csrf,expires_at) VALUES($1,$2,$3,$4,clock_timestamp()+interval '5 minutes')",[hash(legacy),f.identity,f.tenant,csrf]);
 assert.equal((await request(url,'/api/me',{headers:{cookie:'gc_session='+legacy}})).status,401);
 assert.equal((await request(s.url,'/authn/session',{headers:{cookie:'gc_session='+legacy}})).status,401);
 assert.equal((await request(s.url,'/authn/session',{headers:{cookie:'gc_authn_session='+legacy+'; gc_authn_csrf='+csrf}})).status,401);
 const selected=await request(s.url,'/authn/tenant',{method:'POST',headers:{cookie:l.cookie,origin,'content-type':'application/json','x-csrf-token':l.csrf},body:JSON.stringify({tenantId:f.otherTenant,expectedSessionVersion:1})});assert.equal(selected.status,200);assert.equal(selected.headers.getSetCookie().length,4);
 const currentCookie=responseCookies(selected);assert.equal((await request(url,'/api/me',{headers:{cookie:l.cookie}})).status,401);
 const changed=await request(url,'/api/me',{headers:{cookie:currentCookie}});assert.equal(changed.status,200);assert.deepEqual(await changed.json(),{identityId:f.identity,tenantId:f.otherTenant,sessionVersion:2});
 await revoke();assert.equal((await request(url,'/api/me',{headers:{cookie:currentCookie}})).status,503);
});
