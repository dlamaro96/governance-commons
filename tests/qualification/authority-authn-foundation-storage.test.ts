// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import pg from 'pg';
import {createAuthenticationClient,parseAttemptBegin,parseAttemptConsume,parseSessionIssue,parseSessionInspect,parseSessionSelect,parseSessionRevoke,AuthenticationError} from '../../packages/authority/src/authentication.ts';
import type {Parsed} from '../../packages/authority/src/types.ts';
import {fixture,query,scalar,tx,inspect,begin,consume,session,issueArgs,issueSQL,install,extra,config,connect,rejected,digest,uuid,iso,counts,dbNow} from '../fixtures/authority-authn-foundation.ts';

test('native executor credentials, finite legacy census and private storage privileges are exact',async t=>{
 const f=await fixture(t),unknown=await extra(f,'unregistered');
 const census=JSON.parse(readFileSync('docs/execution/authentication-legacy-function-census.json','utf8')).functions as {signature:string;legacy_runtime_execute:boolean}[];
 assert.equal(census.length,155);
 for(const [client,name] of [[f.api,f.roles.api.name],[f.login,f.roles.login.name],[unknown,config.unregistered.name]] as const){
  const identity=await scalar(client,'SELECT session_user::text original,current_user::text effective');assert.equal(identity.original,name);assert.equal(identity.effective,name);
  const flags=await scalar(f.owner,'SELECT rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolinherit,rolreplication FROM pg_roles WHERE rolname=$1',[name]);assert.ok(Object.values(flags).every(v=>v===false));
  for(const forbidden of ['gc_owner','gc_authn_definer',f.roles.login.name===name?f.roles.api.name:f.roles.login.name])await assert.rejects(query(client,`SET ROLE "${forbidden}"`),rejected('42501'));
  const privileges=await scalar(f.owner,`SELECT has_database_privilege($1,current_database(),'TEMP') temporary,has_schema_privilege($1,'public','CREATE') create_schema,
   EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN('public','gc_authn') AND c.relkind IN('r','p','v','m') AND (c.relowner=(SELECT oid FROM pg_roles WHERE rolname=$1) OR has_table_privilege($1,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES') OR has_any_column_privilege($1,c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))) raw_access`,[name]);
  assert.deepEqual(privileges,{temporary:false,create_schema:false,raw_access:false});
  for(const row of census)assert.equal((await scalar(f.owner,'SELECT has_function_privilege($1,$2,\'EXECUTE\') allowed',[name,'public.'+row.signature])).allowed,false);
 }
 for(const row of census)assert.equal((await scalar(f.owner,"SELECT has_function_privilege('gc_app',$1,'EXECUTE') allowed",['public.'+row.signature])).allowed,row.legacy_runtime_execute);
 const rls=await scalar(f.owner,"SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid='gc_authn.tenant_fences'::regclass");assert.deepEqual(rls,{relrowsecurity:true,relforcerowsecurity:true});
 assert.equal((await scalar(f.owner,"SELECT current_setting('max_prepared_transactions') AS max_prepared_transactions")).max_prepared_transactions,'0');
 await query(f.api,'BEGIN');await query(f.api,'SELECT pg_current_xact_id()');await assert.rejects(query(f.api,"PREPARE TRANSACTION 'synthetic-authn-refusal'"),rejected('55000'));await query(f.api,'ROLLBACK');
 const bad=new URL(f.roles.api.url);bad.password='intentionally-wrong-private-fixture-password';await assert.rejects(connect(bad.toString()),rejected('CONNECTION_FAILURE'));
});

test('installation receipts use independently reproduced bytes and exact replay with no regrant',async t=>{
 const f=await fixture(t),tenant=uuid();await query(f.owner,'INSERT INTO tenants(id,name) VALUES($1,$2)',[tenant,'Synthetic independent installation']);
 const before=await scalar(f.owner,'SELECT count(*)::int n FROM gc_authn.installation_receipts');
 const entry=await install(f.owner,'initialize-tenant',[tenant,1]);
 const replay=await scalar(f.owner,entry.sql,entry.values);assert.deepEqual(replay,entry.row);
 assert.equal((await scalar(f.owner,'SELECT count(*)::int n FROM gc_authn.installation_receipts')).n,before.n+1);
 const different=[...entry.values];different[different.length-1]=2;await assert.rejects(query(f.owner,entry.sql,different),rejected('23505'));
 const bytes=await scalar(f.owner,'SELECT manifest_encoding,manifest_hash FROM gc_authn.installation_receipts WHERE id=$1',[entry.row.installation_id]);assert.ok(createHash('sha256').update(bytes.manifest_encoding).digest('hex')===bytes.manifest_hash);
 await assert.rejects(query(f.api,entry.sql,entry.values),rejected('42501'));
 await assert.rejects(query(f.owner,'UPDATE gc_authn.installation_receipts SET release_reference=$2 WHERE id=$1',[entry.row.installation_id,'forged']),rejected('23514','42501'));
 const registered=await scalar(f.owner,"SELECT r.request_id,e.role_oid::int8 oid FROM gc_authn.installation_receipts r JOIN gc_authn.executor_registrations e ON e.installation_id=r.id WHERE e.id=$1",[f.loginId]);
 await assert.rejects(install(f.owner,'register-executor',[f.loginId,f.loginChannel,f.roles.login.name,Number(registered.oid),'login',1,f.expiry.slice(0,-1)+'1Z'],registered.request_id),rejected('22023'));
});

test('native issuer endpoint admission preserves accepted bytes and rolls back malformed independent endpoints',async t=>{
 const f=await fixture(t);
 // Literal contract vectors are independent of the TypeScript endpoint parser.
 const accepted=[
  'https://example.test','https://a-b.example.test:1/','https://example.test:65535?x=%2f%2F',
  'https://0.0.0.0/','https://255.255.255.255/','https://[::1]:443/a',
  `https://${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(61)}/`,
  "https://example.test/a!$&'()*+,;=:@/~_-.?q=/?:@%2f",
  'http://localhost:4310/auth/callback','http://127.0.0.1/','http://[::1]:65535?state=x',
 ];
 const refused=[
  'HTTPS://example.test','https://Example.test','https://user@example.test/','https://example.test/#fragment',
  'https://example.test/a b','https://example.test/a\nb','https://example.test/a\\b',
  'https://éxample.test/','https://example.test/é','https://example.test/%2','https://example.test/%GG',
  'https://example.test:0/','https://example.test:01/','https://example.test:65536/',
  'https://01.2.3.4/','https://256.0.0.1/','https://127.0.1/','https://example.test./',
  'https://a..test/','https://-a.test/','https://a-.test/',`https://${'a'.repeat(64)}.test/`,
  `https://${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(62)}/`,
  'https://example.9test/','https://[2001:db8::1]/','https://::1/','http://example.test/',
 ];
 for(const endpoint of accepted)assert.equal((await scalar(f.owner,'SELECT gc_authn.valid_endpoint($1,$2) valid',[endpoint,'isolated-test'])).valid,true,endpoint);
 for(const endpoint of refused)assert.equal((await scalar(f.owner,'SELECT gc_authn.valid_endpoint($1,$2) valid',[endpoint,'isolated-test'])).valid,false,endpoint);
 for(const endpoint of ['http://localhost/','http://127.0.0.1/','http://[::1]/'])assert.equal((await scalar(f.owner,'SELECT gc_authn.valid_endpoint($1,$2) valid',[endpoint,'production'])).valid,false);
 assert.equal((await scalar(f.owner,'SELECT gc_authn.valid_endpoint($1,$2) valid',['https://example.test/','unknown-environment'])).valid,false);
 await assert.rejects(query(f.api,'SELECT gc_authn.valid_endpoint($1,$2)',['https://example.test/','production']),rejected('42501'));
 const snapshot=()=>scalar(f.owner,`SELECT (SELECT count(*)::int FROM gc_authn.issuer_registrations) issuers,(SELECT count(*)::int FROM gc_authn.installation_receipts) receipts`);
 const before=await snapshot();
 for(const [issuer,callback,environment] of [
  ['https://Example.test/','http://127.0.0.1/callback','isolated-test'],
  ['https://example.test/','http://127.0.0.1/%GG','isolated-test'],
  ['https://example.test/','http://127.0.0.1/callback','production'],
 ]){
  // Existing registration would otherwise conflict; invalid scalar admission
  // must reject first and append neither issuer nor installation receipt.
  await assert.rejects(install(f.owner,'register-issuer',[uuid(),f.loginId,1,issuer,'synthetic-client',callback,environment,f.expiry]),rejected('22023'));
  assert.deepEqual(await snapshot(),before);
 }
 const registration=uuid(),channel=uuid(),issuerId=uuid(),role=f.roles.nextLogin;
 const oid=Number((await scalar(f.owner,'SELECT oid::int8 oid FROM pg_roles WHERE rolname=$1',[role.name])).oid);
 await install(f.owner,'register-executor',[registration,channel,role.name,oid,'login',1,f.expiry]);
 await install(f.owner,'advance-generation',['login',channel,registration,null,null]);
 const issuer='https://issuer.example:443/path%2f?x=%2F',callback='http://[::1]:4310/callback%2F?x=%2f';
 await install(f.owner,'register-issuer',[issuerId,registration,1,issuer,'synthetic-client',callback,'isolated-test',f.expiry]);
 assert.deepEqual(await scalar(f.owner,'SELECT issuer,redirect_uri FROM gc_authn.issuer_registrations WHERE id=$1',[issuerId]),{issuer,redirect_uri:callback});
});

test('begin and committed consumption bind the exact native broker and clear verifier',async t=>{
 const f=await fixture(t),a=await begin(f);
 const row=await scalar(f.owner,'SELECT expires_at-created_at lifetime,extract(epoch FROM expires_at-created_at)::int seconds FROM gc_authn.login_attempts WHERE id=$1',[a.id]);assert.equal(row.seconds,300);
 await assert.rejects(query(f.api,'SELECT * FROM public.gc_authn_attempt_consume($1,$2)',[a.id,a.state]),rejected('42501'));
 await assert.rejects(query(f.login,'SELECT * FROM public.gc_authn_attempt_consume($1,$2)',[a.id,digest()]),rejected('28000'));
 const exchange=await consume(f,a);assert.equal(exchange.attempt_id,a.id);assert.ok(exchange.verifier===a.verifier);assert.ok(exchange.nonce_hash===a.nonce);assert.equal(exchange.issuer_id,f.issuerId);
 assert.equal((await scalar(f.owner,'SELECT verifier FROM gc_authn.login_attempts WHERE id=$1',[a.id])).verifier,null);
 await assert.rejects(consume(f,a),rejected('28000'));
 const c=await scalar(f.owner,'SELECT extract(epoch FROM issue_deadline_at-consumed_at)::int seconds FROM gc_authn.attempt_consumptions WHERE attempt_id=$1',[a.id]);assert.equal(c.seconds,60);
});

test('rolled-back and same-transaction consumption cannot mint a protected session',async t=>{
 const f=await fixture(t),a=await begin(f),args=await issueArgs(f,a),before=await counts(f.owner);
 await query(f.login,'BEGIN');await consume(f,a);await assert.rejects(query(f.login,issueSQL,args),rejected('28000'));await query(f.login,'ROLLBACK');
 assert.equal((await scalar(f.owner,'SELECT count(*)::int n FROM gc_authn.attempt_consumptions WHERE attempt_id=$1',[a.id])).n,0);
 await assert.rejects(query(f.login,issueSQL,args),rejected('28000'));assert.deepEqual(await counts(f.owner),before);
 await consume(f,a);const issued=await scalar(f.login,issueSQL,args);assert.equal(issued.session_version,1);
 await assert.rejects(query(f.login,issueSQL,args),rejected('28000'));assert.equal((await counts(f.owner)).sessions,before.sessions+1);
});

test('private issuance has exact immutable provenance and an inactive-only bounded descriptor',async t=>{
 const f=await fixture(t),before=await counts(f.owner),s=await session(f),view=await inspect(f.api,s.hash);
 assert.deepEqual(Object.keys(view).sort(),['format_version','session_id','session_version','identity_id','selected_tenant_id','issuer_id','identity_binding_id','authenticated_at','expires_at','generation','tenant_fence_epoch','authority_mode','content_authority'].sort());
 assert.equal(view.identity_id,f.identity);assert.equal(view.selected_tenant_id,f.tenant);assert.equal(view.session_id,s.row.session_id);assert.equal(view.session_version,1);assert.equal(view.authority_mode,'inactive');assert.equal(view.content_authority,false);assert.equal(view.identity_binding_id,f.bindingId);
 const after=await counts(f.owner);assert.deepEqual(after,{sessions:before.sessions+1,provenance:before.provenance+1,events:before.events+1,legacy:before.legacy});
 const proof=await scalar(f.owner,`SELECT s.id=s2.session_id AND s.identity_id=s2.identity_id AND s.session_hash=s2.session_hash AND s.csrf_hash=s2.initial_csrf_hash AND s.issued_at=s2.issued_at AND s.expires_at=s2.expires_at AND s.version=e.version AND e.kind='issued' AND e.selected_tenant_id=s.selected_tenant_id AND e.csrf_hash=s.csrf_hash exact,extract(epoch FROM s.expires_at-s.issued_at)::int seconds
 FROM gc_authn.sessions s JOIN gc_authn.session_provenance s2 ON s2.session_id=s.id JOIN gc_authn.session_events e ON e.session_id=s.id WHERE s.id=$1`,[s.row.session_id]);assert.equal(proof.exact,true);assert.equal(proof.seconds,1800);
 for(const table of ['sessions','session_provenance','session_events'])await assert.rejects(query(f.api,`SELECT * FROM gc_authn.${table}`),rejected('42501'));
 await assert.rejects(query(f.owner,"UPDATE gc_authn.tenant_fences SET mode='active' WHERE tenant_id=$1",[f.tenant]),rejected('23514','42501'));
});

test('legacy forged, colliding, changed and deleted sessions cannot authenticate or retarget private sessions',async t=>{
 const f=await fixture(t),fake=digest();
 await query(f.legacy,'INSERT INTO public.sessions(id_hash,identity_id,tenant_id,csrf,expires_at) VALUES($1,$2,$3,$4,clock_timestamp()+interval \'1 hour\')',[fake,f.identity,f.tenant,digest()]);
 await assert.rejects(inspect(f.api,fake),rejected('28000'));
 const a=await begin(f);await consume(f,a);const args=await issueArgs(f,a);args[9]=fake;const before=await counts(f.owner);await assert.rejects(query(f.login,issueSQL,args),rejected('28000','23505'));assert.deepEqual(await counts(f.owner),before);
 const s=await session(f);await query(f.legacy,'UPDATE public.sessions SET tenant_id=$2 WHERE id_hash=$1',[fake,f.otherTenant]);await query(f.legacy,'DELETE FROM public.sessions WHERE id_hash=$1',[fake]);
 const result=await inspect(f.api,s.hash);assert.equal(result.session_id,s.row.session_id);assert.equal(result.selected_tenant_id,f.tenant);
});

test('claim substitutions, invalid clocks and unknown subject fail atomically without leaked rows',async t=>{
 const f=await fixture(t),a=await begin(f);await consume(f,a);const original=await issueArgs(f,a),before=await counts(f.owner);
 for(const [index,value] of [[1,f.issuer+'/wrong'],[2,'unknown-subject'],[3,'wrong-audience'],[4,digest()],[6,new Date(Date.now()+60000).toISOString()],[7,new Date(Date.now()+60000).toISOString()],[8,new Date(Date.now()-60000).toISOString()]] as const){
  const args=[...original];args[index]=value;await assert.rejects(query(f.login,issueSQL,args),rejected('28000'));assert.deepEqual(await counts(f.owner),before);
 }
 await query(f.owner,'UPDATE identities SET active=false WHERE id=$1',[f.identity]);await assert.rejects(query(f.login,issueSQL,original),rejected('28000'));assert.deepEqual(await counts(f.owner),before);
});

test('input grammar and executor family checks reject without token details or state change',async t=>{
 const f=await fixture(t),unknown=await extra(f,'unregistered');
 for(const values of [[null,'x'.repeat(43),digest()],['A'.repeat(64),'x'.repeat(43),digest()],[digest(),'x'.repeat(42),digest()],[digest(),'x'.repeat(129),digest()],[digest(),'x'.repeat(43),null]])await assert.rejects(query(f.login,'SELECT * FROM gc_authn_attempt_begin($1,$2,$3)',values),rejected('22023'));
 await assert.rejects(inspect(unknown,digest()),rejected('42501'));
 await assert.rejects(query(f.login,'SELECT * FROM gc_authn_session_inspect($1)',[digest()]),rejected('42501'));
 const before=await scalar(f.owner,'SELECT count(*)::int n FROM gc_authn.login_attempts');await query(f.api,"SET gc.actor_id='10000000-0000-4000-8000-000000000001'; SET application_name='gc_owner'");
 await assert.rejects(query(f.api,'SELECT * FROM gc_authn_attempt_begin($1,$2,$3)',[digest(),'x'.repeat(43),digest()]),rejected('42501'));
 assert.deepEqual(await scalar(f.owner,'SELECT count(*)::int n FROM gc_authn.login_attempts'),before);
});

test('inspection restores caller GUCs in read-only snapshots and emits no writes',async t=>{
 const f=await fixture(t),s=await session(f),before=await counts(f.owner);
 await tx(f.api,async()=>{
  await query(f.api,"SELECT set_config('gc.actor_id',$1,true),set_config('gc.tenant_id',$2,true)",[uuid(),uuid()]);
  const original=await scalar(f.api,"SELECT current_setting('gc.actor_id') actor,current_setting('gc.tenant_id') tenant");
  const result=await scalar(f.api,'SELECT * FROM gc_authn_session_inspect($1)',[s.hash]);assert.equal(result.identity_id,f.identity);
  assert.deepEqual(await scalar(f.api,"SELECT current_setting('gc.actor_id') actor,current_setting('gc.tenant_id') tenant"),original);
  assert.equal((await scalar(f.api,"SELECT count(*)::int n FROM pg_locks WHERE pid=pg_backend_pid() AND mode IN('RowShareLock','RowExclusiveLock','ShareRowExclusiveLock')")).n,0);
 },'REPEATABLE READ READ ONLY');assert.deepEqual(await counts(f.owner),before);
 await query(f.api,'BEGIN READ ONLY ISOLATION LEVEL REPEATABLE READ');await query(f.api,"SELECT set_config('gc.actor_id',$1,true)",[f.identity]);await query(f.api,'SAVEPOINT rejected');
 await assert.rejects(query(f.api,'SELECT * FROM gc_authn_session_inspect($1)',[digest()]),rejected('28000'));await query(f.api,'ROLLBACK TO rejected');assert.equal((await scalar(f.api,"SELECT current_setting('gc.actor_id') actor")).actor,f.identity);await query(f.api,'ROLLBACK');
});

test('tenant selection rotates exact CSRF/version without renewal and rejects stale or nonmember targets',async t=>{
 const f=await fixture(t),s=await session(f),fresh=digest(),before=await counts(f.owner);
 await assert.rejects(query(f.api,'SELECT * FROM gc_authn_session_select($1,$2,$3,$4,$5)',[s.hash,s.csrf,1,uuid(),fresh]),rejected('28000'));
 const selected=await scalar(f.api,'SELECT * FROM gc_authn_session_select($1,$2,$3,$4,$5)',[s.hash,s.csrf,1,f.otherTenant,fresh]);assert.equal(selected.session_version,2);assert.equal(selected.selected_tenant_id,f.otherTenant);
 const actual=await inspect(f.api,s.hash);assert.equal(iso(actual.expires_at),iso(s.row.expires_at));assert.equal(actual.selected_tenant_id,f.otherTenant);
 await assert.rejects(query(f.api,'SELECT * FROM gc_authn_session_select($1,$2,$3,$4,$5)',[s.hash,fresh,1,f.tenant,digest()]),rejected('40001'));
 await assert.rejects(query(f.api,'SELECT * FROM gc_authn_session_revoke($1,$2,$3)',[s.hash,s.csrf,2]),rejected('28000'));
 assert.equal((await counts(f.owner)).events,before.events+1);
 const proof=await scalar(f.owner,'SELECT previous_tenant_id,selected_tenant_id,version FROM gc_authn.session_events WHERE session_id=$1 ORDER BY version DESC LIMIT 1',[s.row.session_id]);assert.deepEqual(proof,{previous_tenant_id:f.tenant,selected_tenant_id:f.otherTenant,version:2});
});

test('exact logout is append-only and works after canonical membership revocation',async t=>{
 const f=await fixture(t),s=await session(f);await tx(f.owner,async()=>{await query(f.owner,"SELECT set_config('gc.tenant_id',$1,true)",[f.tenant]);await query(f.owner,'UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.identity]);});
 await assert.rejects(inspect(f.api,s.hash),rejected('28000'));
 const revoked=await scalar(f.api,'SELECT * FROM gc_authn_session_revoke($1,$2,$3)',[s.hash,s.csrf,1]);assert.equal(revoked.logged_out,true);assert.equal(revoked.session_version,2);
 await assert.rejects(query(f.api,'SELECT * FROM gc_authn_session_revoke($1,$2,$3)',[s.hash,s.csrf,2]),rejected('28000'));
 await assert.rejects(query(f.owner,'DELETE FROM gc_authn.session_provenance WHERE session_id=$1',[s.row.session_id]),rejected('23514','42501'));
 assert.equal((await scalar(f.owner,'SELECT count(*)::int n FROM gc_authn.session_events WHERE session_id=$1',[s.row.session_id])).n,2);
});

test('executor and issuer revocation invalidate already-open native connections with no reactivation by replay',async t=>{
 const f=await fixture(t),s=await session(f),entry=await install(f.owner,'revoke-issuer',[f.issuerId]);
 await assert.rejects(begin(f),rejected('28000'));await assert.rejects(inspect(f.api,s.hash),rejected('28000'));
 const replay=await scalar(f.owner,entry.sql,entry.values);assert.deepEqual(replay,entry.row);
 await install(f.owner,'revoke-executor',[f.apiId]);await assert.rejects(inspect(f.api,s.hash),rejected('42501'));
});

test('identity binding revocation and canonical issuer substitution cannot preserve authentication',async t=>{
 const f=await fixture(t),s=await session(f);await query(f.owner,'UPDATE identities SET issuer=$2 WHERE id=$1',[f.identity,f.issuer+'/changed']);await assert.rejects(inspect(f.api,s.hash),rejected('28000'));
 await query(f.owner,'UPDATE identities SET issuer=$2 WHERE id=$1',[f.identity,f.issuer]);await install(f.owner,'revoke-binding',[f.bindingId]);await assert.rejects(inspect(f.api,s.hash),rejected('28000'));
});

test('runtime role rename and unsafe flag changes refuse the registered OID without trusting name prefixes',async t=>{
 const f=await fixture(t),s=await session(f),name=f.roles.api.name,renamed=name+'_renamed';
 try{await query(f.admin,`ALTER ROLE "${name}" RENAME TO "${renamed}"`);await assert.rejects(inspect(f.api,s.hash),rejected('42501'));}
 finally{await query(f.admin,`ALTER ROLE "${renamed}" RENAME TO "${name}"`);}
 try{await query(f.admin,`ALTER ROLE "${name}" INHERIT`);await assert.rejects(inspect(f.api,s.hash),rejected('42501'));}
 finally{await query(f.admin,`ALTER ROLE "${name}" NOINHERIT`);}
 assert.equal((await inspect(f.api,s.hash)).identity_id,f.identity);
});

test('real hard registration expiry is clamped into sessions and does not renew on inspection',async t=>{
 const f=await fixture(t,{expiryMs:2500}),s=await session(f);assert.equal(iso(s.row.expires_at),f.expiry);
 const deadline=Date.parse(f.expiry);while(Date.parse(await dbNow(f.owner))<=deadline)await new Promise(r=>setTimeout(r,35));
 await assert.rejects(inspect(f.api,s.hash),rejected('42501','28000'));
 const saved=await scalar(f.owner,'SELECT expires_at,version FROM gc_authn.sessions WHERE id=$1',[s.row.session_id]);assert.equal(iso(saved.expires_at),f.expiry);assert.equal(saved.version,1);
});

test('incompatible isolation is rejected for mutation while fresh RR inspection succeeds',async t=>{
 const f=await fixture(t),s=await session(f);
 await query(f.api,'BEGIN ISOLATION LEVEL REPEATABLE READ');await assert.rejects(query(f.api,'SELECT * FROM gc_authn_session_select($1,$2,$3,$4,$5)',[s.hash,s.csrf,1,f.otherTenant,digest()]),rejected('28000'));await query(f.api,'ROLLBACK');
 assert.equal((await inspect(f.api,s.hash)).session_version,1);
});

test('independent issuer channels cannot consume or issue each other\'s bound attempts',async t=>{
 const first=await fixture(t),second=await fixture(t),a=await begin(first);
 await assert.rejects(consume(second,a),rejected('28000'));await consume(first,a);
 const args=await issueArgs(first,a);await assert.rejects(query(second.login,issueSQL,args),rejected('28000'));
 const s=await scalar(first.login,issueSQL,args);assert.equal(s.selected_tenant_id,first.tenant);
 assert.equal((await inspect(second.api,args[9] as string)).identity_id,first.identity,'A separately registered current API channel of the same generation can inspect the exact proved session');
});

test('strict generation advance invalidates old sessions and preserves inactive tenant state/history',async t=>{
 const f=await fixture(t),old=await session(f);const loginId=uuid(),apiId=uuid(),issuerId=uuid(),bindingId=uuid();
 for(const [kind,role,id,channel,previous] of [['login',f.roles.nextLogin,loginId,f.loginChannel,f.loginId],['api',f.roles.nextApi,apiId,f.apiChannel,f.apiId]] as const){
  const oid=Number((await scalar(f.owner,'SELECT oid::int8 oid FROM pg_roles WHERE rolname=$1',[role.name])).oid);
  await install(f.owner,'register-executor',[id,channel,role.name,oid,kind,2,f.expiry]);await install(f.owner,'advance-generation',[kind,channel,id,previous,1]);
 }
 await install(f.owner,'register-issuer',[issuerId,loginId,2,f.issuer,'synthetic-client','http://127.0.0.1:4310/auth/callback','isolated-test',f.expiry]);
 await install(f.owner,'bind-identity',[bindingId,issuerId,f.identity,f.issuer,f.subject,f.expiry]);
 await install(f.owner,'advance-tenant-generation',[f.tenant,1,1,2]);
 await assert.rejects(inspect(f.api,old.hash),rejected('42501'));
 const api=await extra(f,'nextApi'),login=await extra(f,'nextLogin');await assert.rejects(inspect(api,old.hash),rejected('28000'));
 const next={...f,api,login,issuerId,bindingId};const s=await session(next);const view=await inspect(api,s.hash);assert.equal(view.generation,2);assert.equal(view.tenant_fence_epoch,2);assert.equal(view.authority_mode,'inactive');
 await assert.rejects(install(f.owner,'advance-tenant-generation',[f.tenant,2,2,1]),rejected('22023','23505','28000'));
 assert.equal((await scalar(f.owner,'SELECT count(*)::int n FROM gc_authn.session_provenance WHERE session_id=$1',[old.row.session_id])).n,1);
});

test('a recreated same-name login cannot inherit the old registered executor OID',async t=>{
 const f=await fixture(t),s=await session(f),role=f.roles.api;
 const before=Number((await scalar(f.owner,'SELECT oid::int8 oid FROM pg_roles WHERE rolname=$1',[role.name])).oid);
 await f.api.end();f.clients.splice(f.clients.indexOf(f.api),1);
 await query(f.admin,`DROP OWNED BY "${role.name}"; DROP ROLE "${role.name}"`);
 const password=new URL(role.url).password;assert.match(password,/^[0-9a-f]{48}$/);
 await query(f.admin,`CREATE ROLE "${role.name}" LOGIN PASSWORD '${password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS NOREPLICATION; GRANT CONNECT ON DATABASE gc_authn_qualification TO "${role.name}"; GRANT USAGE ON SCHEMA public TO "${role.name}"; GRANT USAGE ON TYPE public.gc_authn_authenticated_session TO "${role.name}"; GRANT EXECUTE ON FUNCTION public.gc_authn_session_inspect(text) TO "${role.name}"`);
 const after=Number((await scalar(f.owner,'SELECT oid::int8 oid FROM pg_roles WHERE rolname=$1',[role.name])).oid);assert.notEqual(after,before);
 const replacement=await extra(f,'api');await assert.rejects(inspect(replacement,s.hash),rejected('42501'));
 assert.equal(Number((await scalar(f.owner,'SELECT role_oid::int8 oid FROM gc_authn.executor_registrations WHERE id=$1',[f.apiId])).oid),before);
});

test('the actual typed client commits consumption and roundtrips all six native SCRAM operations',async t=>{
 const f=await fixture(t),loginPool=new pg.Pool({connectionString:f.roles.login.url,max:1,connectionTimeoutMillis:5000,statement_timeout:8000}),apiPool=new pg.Pool({connectionString:f.roles.api.url,max:1,connectionTimeoutMillis:5000,statement_timeout:8000});
 t.after(async()=>{await loginPool.end();await apiPool.end();});
 const login=createAuthenticationClient(loginPool),api=createAuthenticationClient(apiPool);
 const value=<T>(parsed:Parsed<T>):T=>{assert.equal(parsed.ok,true);if(!parsed.ok)throw Error('Synthetic typed fixture rejected');return parsed.value;};
 const state=digest(),nonce=digest(),verifier='s'.repeat(64),started=await login.attemptBegin(value(parseAttemptBegin({stateHash:state,nonceHash:nonce,verifier})));
 const consumed=await login.attemptConsume(value(parseAttemptConsume({attemptId:started.attemptId,stateHash:state})));assert.equal(consumed.verifier,verifier);assert.equal(consumed.issuerId,f.issuerId);
 const now=await dbNow(f.owner),hash=digest(),csrf=digest();
 const issued=await login.sessionIssue(value(parseSessionIssue({attemptId:started.attemptId,issuer:f.issuer,subject:f.subject,audience:'synthetic-client',nonceHash:nonce,idTokenHash:digest(),authenticatedAt:now,tokenIssuedAt:now,tokenExpiresAt:new Date(Date.parse(now)+600000).toISOString(),sessionHash:hash,csrfHash:csrf})));
 const view=await api.sessionInspect(value(parseSessionInspect({sessionHash:hash})));assert.equal(view.sessionId,issued.sessionId);assert.equal(view.identityId,f.identity);assert.equal(view.authorityMode,'inactive');assert.equal(view.contentAuthority,false);
 const next=digest(),selected=await api.sessionSelect(value(parseSessionSelect({sessionHash:hash,csrfHash:csrf,expectedSessionVersion:1,tenantId:f.otherTenant,replacementCsrfHash:next})));assert.equal(selected.sessionVersion,2);assert.equal(selected.selectedTenantId,f.otherTenant);
 const revoked=await api.sessionRevoke(value(parseSessionRevoke({sessionHash:hash,csrfHash:next,expectedSessionVersion:2})));assert.equal(revoked.loggedOut,true);assert.equal(revoked.sessionVersion,3);
 await assert.rejects(api.sessionInspect(value(parseSessionInspect({sessionHash:hash}))),e=>e instanceof AuthenticationError&&e.code==='AUTHN_REJECTED');
 assert.equal((await scalar(f.owner,'SELECT count(*)::int n FROM gc_authn.session_events WHERE session_id=$1',[issued.sessionId])).n,3);
});
