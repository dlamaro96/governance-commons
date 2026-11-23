// SPDX-License-Identifier: Apache-2.0
/** Native SQL qualification, sequential because the application bridge is one
 * deployment-wide binding. This suite does not claim browser or OIDC evidence. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {applicationBridgeEncoding,applicationBridgeHash} from '../../packages/authn/src/application-installation.ts';
import {applyApplicationBridgeManifest} from '../../scripts/application-authentication-install.ts';
import {readApplicationSession} from '../../packages/authn/src/application-bridge.ts';
import type {Digest} from '../../packages/authority/src/types.ts';
import {config,query,scalar,tx,session,inspect,extra,install,rejected,uuid,digest,iso,counts,dbNow,setMembership,waitBlocked,SqlFailure} from '../fixtures/authority-authn-foundation.ts';
import {bridgeFixture,prepareBridge,prepareRevoke,installBridge,revokeBridge,applicationSession,bridgeSQL,bridgeState,bridgeChain,bridgeEncoding,bridgeManifest,verifyBridgeReceipt,denyRequest,type BridgeRequest} from '../fixtures/application-authn-bridge.ts';
const changed=(request:BridgeRequest,index:number,value:unknown):BridgeRequest=>({...request,values:request.values.map((v,i)=>i===index?value:v)});
const settled=<T>(promise:Promise<T>)=>promise.then(value=>({ok:true as const,value}),error=>({ok:false as const,error}));

// 1. The function grant deliberately exists before activation; it alone cannot authenticate.
test('application bridge grant is inert without an explicitly installed native binding',async t=>{
 const f=await bridgeFixture(t,{install:false}),s=await session(f),before=await bridgeState(f.owner);
 assert.deepEqual(await scalar(f.legacy,'SELECT session_user::text original,current_user::text effective'),{original:'gc_app',effective:'gc_app'});
 assert.equal((await scalar(f.legacy,"SELECT has_function_privilege(current_user,'public.gc_app_protected_session_v1(text,text)','EXECUTE') allowed")).allowed,true);
 await assert.rejects(applicationSession(f.legacy,s.hash),rejected('42501'));
 assert.deepEqual(await bridgeState(f.owner),before);
 for(const name of ['gc_authn_session_inspect(text)','gc_authn_session_revoke(text,text,integer)','gc_authn_session_select(text,text,integer,uuid,text)','gc_authn_attempt_begin(text,text,text)'])assert.equal((await scalar(f.legacy,"SELECT has_function_privilege(current_user,$1,'EXECUTE') allowed",['public.'+name])).allowed,false);
});

// 2. The first success checks both independent retained bytes and the actual reader.
test('application bridge installs exact independent receipt bytes and replays without renewal or regrant',async t=>{
 const f=await bridgeFixture(t),entry=f.activeBridge!,s=await session(f),before=await bridgeState(f.owner);
 await verifyBridgeReceipt(f.owner,entry);assert.deepEqual(await scalar(f.owner,entry.sql,entry.values),entry.row);
 const manifest=bridgeManifest(entry);
 assert.deepEqual(Buffer.from(applicationBridgeEncoding(manifest)),bridgeEncoding(entry));
 assert.equal(applicationBridgeHash(manifest),entry.row.manifest_hash);
 const receipt=await applyApplicationBridgeManifest(manifest,config.owner);
 assert.deepEqual(receipt,{installationId:entry.row.installation_id,manifestHash:entry.row.manifest_hash,targetId:entry.row.target_id,recordedAt:iso(entry.row.recorded_at)});

 assert.deepEqual(await bridgeState(f.owner),before);
 const result=await applicationSession(f.legacy,s.hash,s.csrf),protectedResult=await inspect(f.api,s.hash);
 assert.deepEqual(result,protectedResult);assert.equal(result.authority_mode,'inactive');assert.equal(result.content_authority,false);
 const typed=await tx(f.legacy,()=>readApplicationSession(f.legacy,{sessionHash:s.hash as Digest,csrfHash:s.csrf as Digest}),'REPEATABLE READ READ ONLY');
 assert.deepEqual(typed,{formatVersion:1,sessionId:result.session_id,sessionVersion:result.session_version,identityId:result.identity_id,selectedTenantId:result.selected_tenant_id,issuerId:result.issuer_id,identityBindingId:result.identity_binding_id,authenticatedAt:iso(result.authenticated_at),expiresAt:iso(result.expires_at),generation:result.generation,tenantFenceEpoch:result.tenant_fence_epoch,authorityMode:'inactive',contentAuthority:false});
 assert.equal(typed.sessionVersion,1);assert.equal(typed.contentAuthority,false);assert.equal(Object.isFrozen(typed),true);
 assert.equal((await scalar(f.owner,'SELECT authn_generation,bridge_generation FROM gc_authn.application_bridge_installations WHERE id=$1',[entry.row.target_id])).authn_generation,1);
 // A receipt replay is not permission reconciliation.
 await query(f.admin,'REVOKE EXECUTE ON FUNCTION public.gc_app_protected_session_v1(text,text) FROM gc_app');
 try{assert.deepEqual(await scalar(f.owner,entry.sql,entry.values),entry.row);await assert.rejects(applicationSession(f.legacy,s.hash),rejected('42501'));}
 finally{await query(f.admin,'GRANT EXECUTE ON FUNCTION public.gc_app_protected_session_v1(text,text) TO gc_app');}
 assert.deepEqual(await bridgeState(f.owner),before);
});

// 3. Every rejected scalar request is rolled back before comparing exact state.
test('application bridge rejects malformed installation values atomically',async t=>{
 const f=await bridgeFixture(t,{install:false}),request=await prepareBridge(f),before=await bridgeState(f.owner);
 const invalid:Array<[number,unknown]>=[[0,'00000000-0000-0000-0000-000000000000'],[1,''],[1,'x'.repeat(257)],[2,'non-ascii-\u00e9'],[3,Number(request.values[3])+1],[4,Number(request.values[4])+1],[5,'A'.repeat(64)],[6,'00000000-0000-0000-0000-000000000000'],[7,null],[8,'00000000-0000-0000-0000-000000000000'],[9,0],[10,0],[11,'2000-01-01T00:00:00.000Z'],[11,f.expiry.slice(0,-1)+'1Z']];
 for(const [index,value] of invalid){await denyRequest(f.owner,changed(request,index,value),rejected('22023'));assert.deepEqual(await bridgeState(f.owner),before);}
 await denyRequest(f.owner,changed(request,5,digest()),rejected('23505'));assert.deepEqual(await bridgeState(f.owner),before);
});

// 4. Installer admission is the original native installation owner, not SET ROLE.
test('application bridge installer refuses foreign callers wrong application OIDs and noncurrent API registrations',async t=>{
 const f=await bridgeFixture(t,{install:false}),request=await prepareBridge(f),unknown=await extra(f,'unregistered'),before=await bridgeState(f.owner);
 for(const client of [f.legacy,f.login,f.api,unknown,f.admin])await assert.rejects(query(client,request.sql,request.values),rejected('42501'));
 for(const client of [f.admin,f.owner]){
  await query(client,'BEGIN');
  try{await query(client,'SET LOCAL ROLE gc_owner');await assert.rejects(query(client,request.sql,request.values),rejected('42501'));}finally{await query(client,'ROLLBACK');}
 }
 const foreignOid=Number((await scalar(f.owner,'SELECT oid::int8 oid FROM pg_roles WHERE rolname=$1',[f.roles.api.name])).oid);
 await denyRequest(f.owner,changed(request,7,foreignOid),rejected('42501'));
 await denyRequest(f.owner,changed(request,8,f.loginId),rejected('42501'));
 await denyRequest(f.owner,changed(request,8,uuid()),rejected('42501'));
 await denyRequest(f.owner,changed(request,10,2),rejected('22023'));
 await install(f.owner,'revoke-executor',[f.apiId]);await denyRequest(f.owner,request,rejected('42501'));
 assert.deepEqual(await bridgeState(f.owner),before);
});

// 5. Bridge generation advances globally, independently of authn generation1.
test('application bridge replacement requires explicit revocation and old exact replay cannot reactivate it',async t=>{
 const f=await bridgeFixture(t),first=f.activeBridge!,s=await session(f),next=await prepareBridge(f),liveState=await bridgeState(f.owner);
 await denyRequest(f.owner,next,rejected('23505'));assert.deepEqual(await bridgeState(f.owner),liveState);
 const revocation=await revokeBridge(f),revokedState=await bridgeState(f.owner);
 await assert.rejects(applicationSession(f.legacy,s.hash),rejected('42501'));
 assert.deepEqual(await scalar(f.owner,first.sql,first.values),first.row);assert.deepEqual(await scalar(f.owner,revocation.sql,revocation.values),revocation.row);
 assert.deepEqual(await bridgeState(f.owner),revokedState);await assert.rejects(applicationSession(f.legacy,s.hash),rejected('42501'));
 await denyRequest(f.owner,changed(first,1,'different-release'),rejected('23505'));
 const replacement=await prepareBridge(f);await denyRequest(f.owner,changed(replacement,9,first.values[9]),rejected('23505'));
 await denyRequest(f.owner,changed(replacement,5,first.row.manifest_hash),rejected('23505'));
 const installed=await installBridge(f,replacement);assert.equal(Number(installed.values[9]),Number(first.values[9])+1);assert.equal(installed.values[10],1);
 assert.equal((await applicationSession(f.legacy,s.hash)).session_id,s.row.session_id);
 assert.deepEqual(await scalar(f.owner,first.sql,first.values),first.row);assert.equal((await applicationSession(f.legacy,s.hash)).session_id,s.row.session_id);
});

// 6. The revoke request binds both the exact installation and chain predecessor.
test('application bridge revoke rejects forged manifests predecessors and changed request replays without effects',async t=>{
 const f=await bridgeFixture(t),entry=f.activeBridge!,s=await session(f),request=await prepareRevoke(f.owner,entry),before=await bridgeState(f.owner);
 for(const invalid of [changed(request,6,uuid()),changed(request,7,digest()),changed(request,5,digest())]){await denyRequest(f.owner,invalid,rejected('23505'));assert.deepEqual(await bridgeState(f.owner),before);}
 for(const invalid of [changed(request,0,null),changed(request,7,'not-a-digest'),changed(request,1,'')])await denyRequest(f.owner,invalid,rejected('22023'));
 for(const client of [f.legacy,f.login,f.api,f.admin])await assert.rejects(query(client,request.sql,request.values),rejected('42501'));
 assert.equal((await applicationSession(f.legacy,s.hash)).session_id,s.row.session_id);
 const revoked=await revokeBridge(f),after=await bridgeState(f.owner);await denyRequest(f.owner,changed(revoked,2,'changed-operator'),rejected('23505'));assert.deepEqual(await bridgeState(f.owner),after);
});

// 7. Direct owner writes are still checked by immutable/deferred native guards.
test('application bridge storage is private immutable and refuses an orphan receipt at deferred validation',async t=>{
 const f=await bridgeFixture(t),entry=f.activeBridge!,before=await bridgeState(f.owner);
 for(const client of [f.legacy,f.login,f.api])for(const table of ['application_bridge_receipts','application_bridge_installations'])await assert.rejects(query(client,`SELECT * FROM gc_authn.${table}`),rejected('42501'));
 for(const sql of [
  'UPDATE gc_authn.application_bridge_receipts SET release_reference=release_reference',
  'DELETE FROM gc_authn.application_bridge_receipts WHERE id=$1',
  'TRUNCATE gc_authn.application_bridge_receipts',
  'UPDATE gc_authn.application_bridge_installations SET expires_at=expires_at WHERE installed_by=$1',
  'DELETE FROM gc_authn.application_bridge_installations WHERE installed_by=$1',
  'TRUNCATE gc_authn.application_bridge_installations',
 ]){await query(f.owner,'BEGIN');try{await assert.rejects(query(f.owner,sql,sql.includes('$1')?[entry.row.installation_id]:[]),rejected('23514','0A000'));}finally{await query(f.owner,'ROLLBACK');}}
 const orphan=await prepareBridge(f),bytes=bridgeEncoding(orphan),hash=createHash('sha256').update(bytes).digest('hex');
 await query(f.owner,'BEGIN');
 try{
  await query(f.owner,`INSERT INTO gc_authn.application_bridge_receipts(id,request_id,sequence,operation,target_id,manifest_hash,manifest_encoding,predecessor_hash,release_reference,operator_reference,database_oid,owner_role_oid,recorded_at)
   SELECT $1,$2,(SELECT max(sequence)+1 FROM gc_authn.application_bridge_receipts),'application-bridge-install',$3,$4,$5,$6,$7,$8,$9,$10,date_trunc('milliseconds',clock_timestamp())`,[uuid(),orphan.values[0],orphan.values[6],hash,bytes,orphan.values[5],orphan.values[1],orphan.values[2],orphan.values[3],orphan.values[4]]);
  await assert.rejects(query(f.owner,'SET CONSTRAINTS ALL IMMEDIATE'),rejected('23514'));
 }finally{await query(f.owner,'ROLLBACK');}
 assert.deepEqual(await bridgeState(f.owner),before);
});

// 8. No protected executor is granted legacy application privileges in return.
test('application bridge reader requires the original safe native application role and rejects impersonation',async t=>{
 const f=await bridgeFixture(t),s=await session(f),unknown=await extra(f,'unregistered');
 for(const client of [f.owner,f.admin,f.login,f.api,unknown])await assert.rejects(applicationSession(client,s.hash),rejected('42501'));
 for(const client of [f.legacy,f.admin]){
  await query(client,'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try{await query(client,'SET LOCAL ROLE gc_app');await assert.rejects(query(client,bridgeSQL,[s.hash,null]),rejected('42501'));}finally{await query(client,'ROLLBACK');}
 }
 await query(f.admin,'ALTER ROLE gc_app INHERIT');
 try{await assert.rejects(applicationSession(f.legacy,s.hash),rejected('42501'));}finally{await query(f.admin,'ALTER ROLE gc_app NOINHERIT');}
 assert.equal((await applicationSession(f.legacy,s.hash)).identity_id,f.identity);
 await assert.rejects(query(f.legacy,'SELECT * FROM public.gc_authn_session_inspect($1)',[s.hash]),rejected('42501'));
 await assert.rejects(query(f.legacy,'SELECT * FROM public.gc_authn_session_revoke($1,$2,$3)',[s.hash,s.csrf,1]),rejected('42501'));
 await assert.rejects(query(f.legacy,'SELECT * FROM public.gc_authn_session_select($1,$2,$3,$4,$5)',[s.hash,s.csrf,1,f.otherTenant,digest()]),rejected('42501'));
});

// 9. NULL means read authentication; an explicitly supplied CSRF must be exact.
test('application bridge enforces canonical hash grammar and exact optional CSRF without exposing either',async t=>{
 const f=await bridgeFixture(t),s=await session(f),before=await counts(f.owner);
 for(const hash of [null,'','A'.repeat(64),s.hash.slice(1),'0'.repeat(65)])await assert.rejects(applicationSession(f.legacy,hash),rejected('22023'));
 for(const csrf of ['','A'.repeat(64),s.csrf.slice(1)])await assert.rejects(applicationSession(f.legacy,s.hash,csrf),rejected('22023'));
 await assert.rejects(applicationSession(f.legacy,digest()),rejected('28000'));await assert.rejects(applicationSession(f.legacy,s.hash,digest()),rejected('28000'));
 const result=await applicationSession(f.legacy,s.hash,s.csrf);assert.deepEqual(result,await applicationSession(f.legacy,s.hash));
 const defaultResult=await tx(f.legacy,()=>scalar(f.legacy,'SELECT * FROM public.gc_app_protected_session_v1($1)',[s.hash]),'REPEATABLE READ READ ONLY');assert.deepEqual(defaultResult,result);
 assert.ok(!JSON.stringify(result).includes(s.hash)&&!JSON.stringify(result).includes(s.csrf));assert.deepEqual(await counts(f.owner),before);
});

// 10. A connection cannot widen the reader into a mutating authentication transaction.
test('application bridge reader and installer reject incompatible native transaction modes',async t=>{
 const f=await bridgeFixture(t),s=await session(f),request=await prepareBridge(f);
 for(const mode of ['READ COMMITTED','READ COMMITTED READ ONLY','REPEATABLE READ','SERIALIZABLE READ ONLY'])await assert.rejects(tx(f.legacy,()=>scalar(f.legacy,bridgeSQL,[s.hash,null]),mode),rejected('28000'));
 for(const mode of ['READ COMMITTED READ ONLY','REPEATABLE READ','REPEATABLE READ READ ONLY','SERIALIZABLE'])await assert.rejects(tx(f.owner,()=>scalar(f.owner,request.sql,request.values),mode),rejected('28000'));
 assert.equal((await applicationSession(f.legacy,s.hash)).session_id,s.row.session_id);
});

// 11. Ambient tenant/actor GUCs neither choose identity nor survive internal scope changes.
test('application bridge returns the exact inert descriptor restores GUCs and emits no session or bridge writes',async t=>{
 const f=await bridgeFixture(t),s=await session(f),before=await counts(f.owner),bridgeBefore=await bridgeState(f.owner);
 await tx(f.legacy,async()=>{
  await query(f.legacy,"SELECT set_config('gc.actor_id',$1,true),set_config('gc.tenant_id',$2,true),set_config('application_name','gc_owner',true)",[uuid(),uuid()]);
  const original=await scalar(f.legacy,"SELECT current_setting('gc.actor_id') actor,current_setting('gc.tenant_id') tenant");
  const result=await scalar(f.legacy,bridgeSQL,[s.hash,s.csrf]);
  assert.deepEqual(Object.keys(result).sort(),['format_version','session_id','session_version','identity_id','selected_tenant_id','issuer_id','identity_binding_id','authenticated_at','expires_at','generation','tenant_fence_epoch','authority_mode','content_authority'].sort());
  assert.equal(result.format_version,1);assert.equal(result.session_id,s.row.session_id);assert.equal(result.session_version,1);assert.equal(result.identity_id,f.identity);assert.equal(result.selected_tenant_id,f.tenant);assert.equal(result.issuer_id,f.issuerId);assert.equal(result.identity_binding_id,f.bindingId);assert.equal(result.generation,1);assert.equal(result.tenant_fence_epoch,1);assert.equal(result.authority_mode,'inactive');assert.equal(result.content_authority,false);
  assert.deepEqual(await scalar(f.legacy,"SELECT current_setting('gc.actor_id') actor,current_setting('gc.tenant_id') tenant"),original);
  assert.equal((await scalar(f.legacy,"SELECT count(*)::int n FROM pg_locks WHERE pid=pg_backend_pid() AND mode IN('RowShareLock','RowExclusiveLock','ShareRowExclusiveLock')")).n,0);
  await query(f.legacy,'SAVEPOINT rejected_bridge');await assert.rejects(query(f.legacy,bridgeSQL,[s.hash,digest()]),rejected('28000'));await query(f.legacy,'ROLLBACK TO rejected_bridge');
  assert.deepEqual(await scalar(f.legacy,"SELECT current_setting('gc.actor_id') actor,current_setting('gc.tenant_id') tenant"),original);
 },'REPEATABLE READ READ ONLY');
 assert.deepEqual(await counts(f.owner),before);assert.deepEqual(await bridgeState(f.owner),bridgeBefore);
});

// 12. No lookup of the legacy session table can supply protected identity.
test('application bridge ignores forged colliding and retargeted legacy session rows',async t=>{
 const f=await bridgeFixture(t),s=await session(f),fake=digest();
 await query(f.legacy,"INSERT INTO public.sessions(id_hash,identity_id,tenant_id,csrf,expires_at) VALUES($1,$2,$3,$4,clock_timestamp()+interval '1 hour')",[fake,f.identity,f.otherTenant,digest()]);
 await assert.rejects(applicationSession(f.legacy,fake),rejected('28000'));
 await query(f.legacy,"INSERT INTO public.sessions(id_hash,identity_id,tenant_id,csrf,expires_at) VALUES($1,$2,$3,$4,clock_timestamp()+interval '1 hour')",[s.hash,f.identity,f.otherTenant,digest()]);
 const result=await applicationSession(f.legacy,s.hash,s.csrf);assert.equal(result.selected_tenant_id,f.tenant);assert.equal(result.session_id,s.row.session_id);
 await query(f.legacy,'UPDATE public.sessions SET tenant_id=$2 WHERE id_hash=$1',[s.hash,f.tenant]);await query(f.legacy,'DELETE FROM public.sessions WHERE id_hash=$1',[s.hash]);assert.deepEqual(await applicationSession(f.legacy,s.hash),result);
});

// 13. Only the protected API executor changes session tenant/version/CSRF.
test('application bridge follows canonical tenant selection and CSRF rotation without renewing expiry',async t=>{
 const f=await bridgeFixture(t),s=await session(f),before=await applicationSession(f.legacy,s.hash),replacement=digest();
 await scalar(f.api,'SELECT * FROM public.gc_authn_session_select($1,$2,$3,$4,$5)',[s.hash,s.csrf,1,f.otherTenant,replacement]);
 await assert.rejects(applicationSession(f.legacy,s.hash,s.csrf),rejected('28000'));
 const result=await applicationSession(f.legacy,s.hash,replacement);assert.equal(result.selected_tenant_id,f.otherTenant);assert.equal(result.session_version,2);assert.equal(result.session_id,before.session_id);assert.equal(iso(result.expires_at),iso(before.expires_at));
 assert.equal((await scalar(f.owner,'SELECT count(*)::int n FROM gc_authn.session_events WHERE session_id=$1',[s.row.session_id])).n,2);
});

// 14. Neither the other active membership nor ambient scope rescues the selected one.
test('application bridge checks current selected membership and canonical identity activation',async t=>{
 const f=await bridgeFixture(t),s=await session(f);
 await tx(f.owner,()=>setMembership(f,f.owner,f.tenant,false));await assert.rejects(applicationSession(f.legacy,s.hash),rejected('28000'));
 await tx(f.owner,()=>setMembership(f,f.owner,f.tenant,true));assert.equal((await applicationSession(f.legacy,s.hash)).selected_tenant_id,f.tenant);
 await query(f.owner,'UPDATE public.identities SET active=false WHERE id=$1',[f.identity]);await assert.rejects(applicationSession(f.legacy,s.hash),rejected('28000'));
});

// 15. A session cannot outlive its exact immutable issuer/subject binding.
test('application bridge refuses a revoked exact identity binding',async t=>{
 const f=await bridgeFixture(t),s=await session(f);await install(f.owner,'revoke-binding',[f.bindingId]);
 await assert.rejects(applicationSession(f.legacy,s.hash),rejected('28000'));
 assert.equal((await scalar(f.owner,'SELECT count(*)::int n FROM gc_authn.session_provenance WHERE session_id=$1',[s.row.session_id])).n,1);
});

// 16. Issuer revocation is checked independently of a still-live bridge/API.
test('application bridge refuses a revoked original issuer',async t=>{
 const f=await bridgeFixture(t),s=await session(f);await install(f.owner,'revoke-issuer',[f.issuerId]);await assert.rejects(applicationSession(f.legacy,s.hash),rejected('28000'));
});

// 17. Provenance binds the original issuing executor, including its current head.
test('application bridge refuses a revoked original login executor',async t=>{
 const f=await bridgeFixture(t),s=await session(f);await install(f.owner,'revoke-executor',[f.loginId]);await assert.rejects(applicationSession(f.legacy,s.hash),rejected('42501'));
});

// 18. A different current API registration is never chosen as a fallback.
test('application bridge refuses a revoked pinned API even when another API generation becomes current',async t=>{
 const f=await bridgeFixture(t),s=await session(f);await install(f.owner,'revoke-executor',[f.apiId]);await assert.rejects(applicationSession(f.legacy,s.hash),rejected('42501'));
 const next=uuid(),oid=Number((await scalar(f.owner,'SELECT oid::int8 oid FROM pg_roles WHERE rolname=$1',[f.roles.nextApi.name])).oid);
 await install(f.owner,'register-executor',[next,f.apiChannel,f.roles.nextApi.name,oid,'api',2,f.expiry]);await install(f.owner,'advance-generation',['api',f.apiChannel,next,f.apiId,1]);
 await assert.rejects(applicationSession(f.legacy,s.hash),rejected('42501'));assert.equal((await scalar(f.owner,'SELECT api_registration_id FROM gc_authn.application_bridge_installations WHERE id=$1',[f.activeBridge!.row.target_id])).api_registration_id,f.apiId);
});

// 19. Separate generation2 channels let this case isolate the tenant fence check.
test('application bridge refuses a generation-mismatched tenant fence while original executors remain current',async t=>{
 const f=await bridgeFixture(t),s=await session(f),nextLogin=uuid(),nextApi=uuid(),nextIssuer=uuid();
 for(const [kind,role,id] of [['login',f.roles.nextLogin,nextLogin],['api',f.roles.nextApi,nextApi]] as const){
  const channel=uuid(),oid=Number((await scalar(f.owner,'SELECT oid::int8 oid FROM pg_roles WHERE rolname=$1',[role.name])).oid);
  await install(f.owner,'register-executor',[id,channel,role.name,oid,kind,2,f.expiry]);await install(f.owner,'advance-generation',[kind,channel,id,null,null]);
 }
 await install(f.owner,'register-issuer',[nextIssuer,nextLogin,2,f.issuer,'synthetic-client','http://127.0.0.1:4310/auth/callback','isolated-test',f.expiry]);
 await install(f.owner,'advance-tenant-generation',[f.tenant,1,1,2]);
 await assert.rejects(applicationSession(f.legacy,s.hash),rejected('28000'));
 assert.deepEqual(await scalar(f.owner,'SELECT generation,epoch,mode FROM gc_authn.tenant_fences WHERE tenant_id=$1',[f.tenant]),{generation:2,epoch:2,mode:'inactive'});
});

// 20. Logout retains provenance but closes application authentication immediately.
test('application bridge refuses a protected session after exact canonical logout',async t=>{
 const f=await bridgeFixture(t),s=await session(f);const revoked=await scalar(f.api,'SELECT * FROM public.gc_authn_session_revoke($1,$2,$3)',[s.hash,s.csrf,1]);
 assert.equal(revoked.logged_out,true);await assert.rejects(applicationSession(f.legacy,s.hash),rejected('28000'));
 assert.deepEqual(await scalar(f.owner,`SELECT (SELECT count(*)::int FROM gc_authn.session_provenance WHERE session_id=$1) provenance,(SELECT count(*)::int FROM gc_authn.session_events WHERE session_id=$1) events`,[s.row.session_id]),{provenance:1,events:2});
});

// 21. Snapshot behavior is proved with a committed write between two real reads.
test('application bridge holds one RR membership snapshot and a fresh snapshot sees committed revocation',async t=>{
 const f=await bridgeFixture(t),s=await session(f);await query(f.legacy,'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 try{const first=await scalar(f.legacy,bridgeSQL,[s.hash,s.csrf]);await tx(f.owner,()=>setMembership(f,f.owner,f.tenant,false));assert.deepEqual(await scalar(f.legacy,bridgeSQL,[s.hash,s.csrf]),first);}
 finally{await query(f.legacy,'ROLLBACK');}
 await assert.rejects(applicationSession(f.legacy,s.hash),rejected('28000'));
});

// 22. Revoking the installation does not rewrite an already-held MVCC snapshot.
test('application bridge holds one RR installation snapshot and a fresh snapshot sees explicit bridge revocation',async t=>{
 const f=await bridgeFixture(t),s=await session(f);await query(f.legacy,'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 try{const first=await scalar(f.legacy,bridgeSQL,[s.hash,s.csrf]);await revokeBridge(f);assert.deepEqual(await scalar(f.legacy,bridgeSQL,[s.hash,s.csrf]),first);}
 finally{await query(f.legacy,'ROLLBACK');}
 await assert.rejects(applicationSession(f.legacy,s.hash),rejected('42501'));
});

// 23. Held metadata/CSRF are never assembled from different session versions.
test('application bridge holds exact tenant version and CSRF while a concurrent protected selection commits',async t=>{
 const f=await bridgeFixture(t),s=await session(f),replacement=digest();await query(f.legacy,'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 try{const first=await scalar(f.legacy,bridgeSQL,[s.hash,s.csrf]);await scalar(f.api,'SELECT * FROM public.gc_authn_session_select($1,$2,$3,$4,$5)',[s.hash,s.csrf,1,f.otherTenant,replacement]);assert.deepEqual(await scalar(f.legacy,bridgeSQL,[s.hash,s.csrf]),first);}
 finally{await query(f.legacy,'ROLLBACK');}
 await assert.rejects(applicationSession(f.legacy,s.hash,s.csrf),rejected('28000'));const fresh=await applicationSession(f.legacy,s.hash,replacement);assert.equal(fresh.selected_tenant_id,f.otherTenant);assert.equal(fresh.session_version,2);
});

// 24. Wall-clock expiry is deliberately not frozen by the MVCC snapshot.
test('application bridge expiry is real wall-clock bounded even in a held RR snapshot and replay cannot renew it',async t=>{
 const f=await bridgeFixture(t,{install:false}),s=await session(f),expiry=new Date(Date.parse(await dbNow(f.owner))+1200).toISOString();
 const entry=await installBridge(f,await prepareBridge(f,{expiresAt:expiry}));await query(f.legacy,'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 try{
  const first=await scalar(f.legacy,bridgeSQL,[s.hash,null]);assert.equal(iso(first.expires_at),expiry);
  const deadline=performance.now()+5000;let expired=false;
  while(performance.now()<deadline){expired=(await scalar(f.owner,'SELECT clock_timestamp()>=$1::timestamptz expired',[expiry])).expired;if(expired)break;await new Promise(resolve=>setTimeout(resolve,25));}
  assert.equal(expired,true,'Database clock did not reach the actual configured bridge expiry');
  await assert.rejects(query(f.legacy,bridgeSQL,[s.hash,null]),rejected('42501'));
 }finally{await query(f.legacy,'ROLLBACK');}
 const before=await bridgeState(f.owner);assert.deepEqual(await scalar(f.owner,entry.sql,entry.values),entry.row);assert.deepEqual(await bridgeState(f.owner),before);await assert.rejects(applicationSession(f.legacy,s.hash),rejected('42501'));
});

// 25. A real lock observation establishes competing owner installation ordering.
test('application bridge concurrent installations serialize with exactly one committed receipt and binding',async t=>{
 const f=await bridgeFixture(t,{install:false}),other=await extra(f,'owner'),first=await prepareBridge(f),second=await prepareBridge(f),before=await bridgeState(f.owner);
 await query(f.owner,'BEGIN');let pending:ReturnType<typeof settled>|undefined,committed=false;
 try{
  await installBridge(f,first);pending=settled(scalar(other,second.sql,second.values));await waitBlocked(f.admin,other,f.owner);
  await query(f.owner,'COMMIT');committed=true;const losing=await pending;assert.equal(losing.ok,false);if(!losing.ok)assert.ok(losing.error instanceof SqlFailure&&losing.error.code==='23505');
 }finally{await query(f.owner,'ROLLBACK');if(pending)await pending;if(!committed)f.activeBridge=undefined;}
 const after=await bridgeState(f.owner);assert.equal(after.receipts.length,before.receipts.length+1);assert.equal(after.installations.length,before.installations.length+1);
 const chain=await bridgeChain(f.owner);assert.equal(chain.predecessor,f.activeBridge!.row.manifest_hash);assert.equal(chain.generation,Number(first.values[9])+1);
 assert.equal((await scalar(f.owner,'SELECT count(*)::int n FROM gc_authn.application_bridge_installations WHERE revoked_at IS NULL')).n,1);
});
