// SPDX-License-Identifier: Apache-2.0
/** Actual independent native-role PostgreSQL connections. Lock observations, not
 * sleep durations, establish ordering. Every pending transaction is released. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture,query,scalar,begin,consume,issueArgs,issueSQL,session,inspect,extra,waitBlocked,setMembership,install,rejected,digest,SqlFailure} from '../fixtures/authority-authn-foundation.ts';
const settled=<T>(p:Promise<T>)=>p.then(value=>({ok:true as const,value}),error=>({ok:false as const,error}));
function denied(value:Awaited<ReturnType<typeof settled>>,codes:string[]){assert.equal(value.ok,false);if(!value.ok)assert.ok(value.error instanceof SqlFailure&&codes.includes(value.error.code),'Expected exact safe denial after blocked native operation');}
const selectSQL='SELECT * FROM gc_authn_session_select($1,$2,$3,$4,$5)';
const revokeSQL='SELECT * FROM gc_authn_session_revoke($1,$2,$3)';

test('concurrent attempt consumption has exactly one committed winner',async t=>{
 const f=await fixture(t),a=await begin(f),other=await extra(f,'login');await query(f.login,'BEGIN');let pending:ReturnType<typeof settled>|undefined;
 try{await consume(f,a);pending=settled(consume(f,a,other));await waitBlocked(f.admin,other,f.login);await query(f.login,'COMMIT');denied(await pending,['28000']);}
 finally{await query(f.login,'ROLLBACK');if(pending)await pending;}
 assert.equal((await scalar(f.owner,'SELECT count(*)::int n FROM gc_authn.attempt_consumptions WHERE attempt_id=$1',[a.id])).n,1);
});

test('concurrent issuance has one immutable session/provenance/event and no retry duplicate',async t=>{
 const f=await fixture(t),a=await begin(f);await consume(f,a);const args=await issueArgs(f,a),other=await extra(f,'login');await query(f.login,'BEGIN');let pending:ReturnType<typeof settled>|undefined;
 try{const first=await scalar(f.login,issueSQL,args);pending=settled(scalar(other,issueSQL,args));await waitBlocked(f.admin,other,f.login);await query(f.login,'COMMIT');denied(await pending,['28000']);assert.equal((await scalar(f.owner,'SELECT count(*)::int n FROM gc_authn.session_events WHERE session_id=$1',[first.session_id])).n,1);}
 finally{await query(f.login,'ROLLBACK');if(pending)await pending;}
 assert.equal((await scalar(f.owner,'SELECT count(*)::int n FROM gc_authn.session_provenance WHERE attempt_id=$1',[a.id])).n,1);
});

test('identity revocation winning first forces issuance to reread and deny',async t=>{
 const f=await fixture(t),a=await begin(f);await consume(f,a);const args=await issueArgs(f,a);await query(f.owner,'BEGIN');let pending:ReturnType<typeof settled>|undefined;
 try{await query(f.owner,'UPDATE identities SET active=false WHERE id=$1',[f.identity]);pending=settled(scalar(f.login,issueSQL,args));await waitBlocked(f.admin,f.login,f.owner);await query(f.owner,'COMMIT');denied(await pending,['28000']);}
 finally{await query(f.owner,'ROLLBACK');if(pending)await pending;}
 assert.equal((await scalar(f.owner,'SELECT count(*)::int n FROM gc_authn.session_provenance WHERE attempt_id=$1',[a.id])).n,0);
});

test('issuance winning first holds the identity lock through commit, then new reads see revocation',async t=>{
 const f=await fixture(t),a=await begin(f);await consume(f,a);const args=await issueArgs(f,a);await query(f.login,'BEGIN');let pending:ReturnType<typeof settled>|undefined;
 try{await scalar(f.login,issueSQL,args);pending=settled(query(f.owner,'UPDATE identities SET active=false WHERE id=$1',[f.identity]));await waitBlocked(f.admin,f.owner,f.login);await query(f.login,'COMMIT');assert.equal((await pending).ok,true);}
 finally{await query(f.login,'ROLLBACK');if(pending)await pending;}
 await assert.rejects(inspect(f.api,args[9] as string),rejected('28000'));
});

test('destination membership revocation winning first blocks and rejects tenant selection',async t=>{
 const f=await fixture(t),s=await session(f);await query(f.owner,'BEGIN');let pending:ReturnType<typeof settled>|undefined;
 try{await setMembership(f,f.owner,f.otherTenant,false);pending=settled(scalar(f.api,selectSQL,[s.hash,s.csrf,1,f.otherTenant,digest()]));await waitBlocked(f.admin,f.api,f.owner);await query(f.owner,'COMMIT');denied(await pending,['28000']);}
 finally{await query(f.owner,'ROLLBACK');if(pending)await pending;}
 assert.equal((await inspect(f.api,s.hash)).selected_tenant_id,f.tenant);
});

test('tenant selection winning first holds selected membership until commit',async t=>{
 const f=await fixture(t),s=await session(f);await query(f.api,'BEGIN');await query(f.owner,'BEGIN');let pending:ReturnType<typeof settled>|undefined;
 try{await scalar(f.api,selectSQL,[s.hash,s.csrf,1,f.otherTenant,digest()]);pending=settled(setMembership(f,f.owner,f.otherTenant,false));await waitBlocked(f.admin,f.owner,f.api);await query(f.api,'COMMIT');assert.equal((await pending).ok,true);await query(f.owner,'COMMIT');}
 finally{await query(f.api,'ROLLBACK');await query(f.owner,'ROLLBACK');if(pending)await pending;}
 await assert.rejects(inspect(f.api,s.hash),rejected('28000'));
});

test('session logout winning first blocks and invalidates a waiting selection',async t=>{
 const f=await fixture(t),s=await session(f),other=await extra(f,'api');await query(f.api,'BEGIN');let pending:ReturnType<typeof settled>|undefined;
 try{await scalar(f.api,revokeSQL,[s.hash,s.csrf,1]);pending=settled(scalar(other,selectSQL,[s.hash,s.csrf,1,f.otherTenant,digest()]));await waitBlocked(f.admin,other,f.api);await query(f.api,'COMMIT');denied(await pending,['28000','40001']);}
 finally{await query(f.api,'ROLLBACK');if(pending)await pending;}
 assert.equal((await scalar(f.owner,'SELECT count(*)::int n FROM gc_authn.session_events WHERE session_id=$1',[s.row.session_id])).n,2);
});

test('session selection winning first invalidates waiting old-version/old-CSRF logout',async t=>{
 const f=await fixture(t),s=await session(f),other=await extra(f,'api');await query(f.api,'BEGIN');let pending:ReturnType<typeof settled>|undefined;
 try{await scalar(f.api,selectSQL,[s.hash,s.csrf,1,f.otherTenant,digest()]);pending=settled(scalar(other,revokeSQL,[s.hash,s.csrf,1]));await waitBlocked(f.admin,other,f.api);await query(f.api,'COMMIT');denied(await pending,['28000','40001']);}
 finally{await query(f.api,'ROLLBACK');if(pending)await pending;}
 assert.equal((await inspect(f.api,s.hash)).session_version,2);
});

test('executor revocation winning first rejects a waiting broker attempt after the lock',async t=>{
 const f=await fixture(t);await query(f.owner,'BEGIN');let pending:ReturnType<typeof settled>|undefined;
 try{await install(f.owner,'revoke-executor',[f.loginId]);pending=settled(begin(f));await waitBlocked(f.admin,f.login,f.owner);await query(f.owner,'COMMIT');denied(await pending,['42501']);}
 finally{await query(f.owner,'ROLLBACK');if(pending)await pending;}
});

test('broker attempt winning first holds configuration locks until commit then loses authority',async t=>{
 const f=await fixture(t);await query(f.login,'BEGIN');let pending:ReturnType<typeof settled>|undefined;
 try{const a=await begin(f);pending=settled(install(f.owner,'revoke-executor',[f.loginId]));await waitBlocked(f.admin,f.owner,f.login);await query(f.login,'COMMIT');assert.equal((await pending).ok,true);await assert.rejects(consume(f,a),rejected('42501'));}
 finally{await query(f.login,'ROLLBACK');if(pending)await pending;}
});

test('RR authentication is snapshot-consistent and the next snapshot observes identity revocation',async t=>{
 const f=await fixture(t),s=await session(f);await query(f.api,'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 try{const first=await scalar(f.api,'SELECT * FROM gc_authn_session_inspect($1)',[s.hash]);await query(f.owner,'UPDATE identities SET active=false WHERE id=$1',[f.identity]);const second=await scalar(f.api,'SELECT * FROM gc_authn_session_inspect($1)',[s.hash]);assert.deepEqual(second,first);}
 finally{await query(f.api,'ROLLBACK');}
 await assert.rejects(inspect(f.api,s.hash),rejected('28000'));
});

test('prearmed native lock timeout interrupts contention and rolls back the entire attempted issue',async t=>{
 const f=await fixture(t),a=await begin(f);await consume(f,a);const args=await issueArgs(f,a);await query(f.owner,'BEGIN');
 try{await query(f.owner,'UPDATE identities SET active=false WHERE id=$1',[f.identity]);await query(f.login,"SET lock_timeout='120ms'; SET statement_timeout='800ms'");const started=performance.now();await assert.rejects(query(f.login,issueSQL,args),rejected('28000'));assert.ok(performance.now()-started<2000,'Prearmed native timeout did not interrupt contention');}
 finally{await query(f.owner,'ROLLBACK');}
 assert.equal((await scalar(f.owner,'SELECT count(*)::int n FROM gc_authn.session_provenance WHERE attempt_id=$1',[a.id])).n,0);
 assert.equal((await scalar(f.login,issueSQL,args)).session_version,1);
});

test('issuer revocation winning first makes waiting issuance reject with no partial provenance',async t=>{
 const f=await fixture(t),a=await begin(f);await consume(f,a);const args=await issueArgs(f,a);await query(f.owner,'BEGIN');let pending:ReturnType<typeof settled>|undefined;
 try{await install(f.owner,'revoke-issuer',[f.issuerId]);pending=settled(scalar(f.login,issueSQL,args));await waitBlocked(f.admin,f.login,f.owner);await query(f.owner,'COMMIT');denied(await pending,['28000']);}
 finally{await query(f.owner,'ROLLBACK');if(pending)await pending;}
 assert.equal((await scalar(f.owner,'SELECT count(*)::int n FROM gc_authn.session_provenance WHERE attempt_id=$1',[a.id])).n,0);
});

test('issuance winning first holds issuer configuration until commit and next inspection observes revocation',async t=>{
 const f=await fixture(t),a=await begin(f);await consume(f,a);const args=await issueArgs(f,a);await query(f.login,'BEGIN');let pending:ReturnType<typeof settled>|undefined;
 try{await scalar(f.login,issueSQL,args);pending=settled(install(f.owner,'revoke-issuer',[f.issuerId]));await waitBlocked(f.admin,f.owner,f.login);await query(f.login,'COMMIT');assert.equal((await pending).ok,true);}
 finally{await query(f.login,'ROLLBACK');if(pending)await pending;}
 await assert.rejects(inspect(f.api,args[9] as string),rejected('28000'));
});
