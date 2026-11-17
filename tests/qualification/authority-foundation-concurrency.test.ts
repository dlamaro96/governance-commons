// SPDX-License-Identifier: Apache-2.0
/** Actual independent native TCP transactions. pg_blocking_pids establishes
 * ordering; elapsed sleeps never stand in for a PostgreSQL lock observation. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture,query,scalar,extra,tx,epoch,startWrite,complete,addGroup,addMembership,addPerson,readerGraph,mutate,revoke,load,rawLoad,selectors,waitBlocked,rejected,SqlFailure,digest,setMembership} from '../fixtures/authority-foundation.ts';
const settled=<T>(p:Promise<T>)=>p.then(value=>({ok:true as const,value}),error=>({ok:false as const,error}));
const denied=(result:Awaited<ReturnType<typeof settled>>,codes:string[])=>{assert.equal(result.ok,false);if(!result.ok)assert.ok(result.error instanceof SqlFailure&&codes.includes(result.error.code),'Exact native PostgreSQL refusal required');};
const readSQL='SELECT gc_authority.load_human_closure_v1($1::text,$2::text) closure';

test('two native writers serialize on the tenant ledger; stale expected epoch loses atomically',async t=>{
 const f=await fixture(t),other=await extra(f,'owner'),before=await epoch(f);await query(f.owner,'BEGIN');await query(other,'BEGIN');let pending:ReturnType<typeof settled>|undefined;
 try{await startWrite(f);await addGroup(f);await complete(f);pending=settled(query(other,'SELECT gc_authority.foundation_write_begin_v1($1,$2)',[f.tenant,before]));await waitBlocked(f.admin,other,f.owner);await query(f.owner,'COMMIT');denied(await pending,['40001']);}
 finally{await query(f.owner,'ROLLBACK');await query(other,'ROLLBACK');if(pending)await pending;f.pending=[];}
 assert.equal(BigInt(await epoch(f)),BigInt(before)+1n);assert.equal((await scalar(f.owner,'SELECT count(*)::int n FROM gc_authority.definition_heads WHERE tenant_id=$1',[f.tenant])).n,1);
});

test('rollback releases the tenant ledger and allows the waiting original epoch without partial rows',async t=>{
 const f=await fixture(t),other=await extra(f,'owner'),before=await epoch(f);await query(f.owner,'BEGIN');await query(other,'BEGIN');let pending:ReturnType<typeof settled>|undefined;
 try{await startWrite(f);await addGroup(f);pending=settled(query(other,'SELECT gc_authority.foundation_write_begin_v1($1,$2)',[f.tenant,before]));await waitBlocked(f.admin,other,f.owner);await query(f.owner,'ROLLBACK');assert.equal((await pending).ok,true);}
 finally{await query(f.owner,'ROLLBACK');await query(other,'ROLLBACK');if(pending)await pending;f.pending=[];}
 assert.equal(await epoch(f),before);assert.equal((await scalar(f.owner,'SELECT count(*)::int n FROM gc_authority.definition_heads WHERE tenant_id=$1',[f.tenant])).n,0);
});

test('read-only repeatable-read closure stays coherent across concurrent revocation and next snapshot changes',async t=>{
 const f=await fixture(t),g=await readerGraph(f),reader=await extra(f,'owner');await query(reader,'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 try{const first=(await scalar(reader,readSQL,[f.hash,JSON.stringify(selectors(f))])).closure;await mutate(f,()=>revoke(f,'grant',g.ref.id));const second=(await scalar(reader,readSQL,[f.hash,JSON.stringify(selectors(f))])).closure;assert.deepEqual(second,first);assert.equal(first.grants.length,1);}
 finally{await query(reader,'ROLLBACK');}
 const fresh=await load(f);assert.deepEqual(fresh.grants,[]);assert.equal(fresh.snapshot.authorityEpoch,await epoch(f));
});

test('precommitted revocation is visible to a fresh native owner connection',async t=>{
 const f=await fixture(t),g=await readerGraph(f);await mutate(f,()=>revoke(f,'grant',g.ref.id));const reader=await extra(f,'owner');assert.deepEqual((await rawLoad(f,reader)).grants,[]);
});

test('foundation principal plan holds canonical identity until commit; next bridge denies revoked identity',async t=>{
 const f=await fixture(t),revoker=await extra(f,'owner');await query(f.owner,'BEGIN');let pending:ReturnType<typeof settled>|undefined;
 try{await startWrite(f);await addGroup(f);await complete(f);pending=settled(query(revoker,'UPDATE public.identities SET active=false WHERE id=$1',[f.identity]));await waitBlocked(f.admin,revoker,f.owner);await query(f.owner,'COMMIT');assert.equal((await pending).ok,true);}
 finally{await query(f.owner,'ROLLBACK');if(pending)await pending;f.pending=[];}
 await assert.rejects(rawLoad(f),rejected('28000'));
});

test('identity change winning first blocks the fixture plan and its committed revision is reread',async t=>{
 const f=await fixture(t),writer=await extra(f,'owner');await query(f.owner,'BEGIN');await query(writer,'BEGIN');let pending:ReturnType<typeof settled>|undefined;
 try{await query(f.owner,'UPDATE public.identities SET active=false WHERE id=$1',[f.identity]);pending=settled(startWrite(f,writer));await waitBlocked(f.admin,writer,f.owner);await query(f.owner,'COMMIT');assert.equal((await pending).ok,true);const row=await scalar(writer,'SELECT active FROM gc_authority.identity_heads WHERE identity_id=$1',[f.identity]);assert.equal(row.active,false);}
 finally{await query(f.owner,'ROLLBACK');await query(writer,'ROLLBACK');if(pending)await pending;}
 await assert.rejects(rawLoad(f),rejected('28000'));
});

test('foundation principal plan holds canonical membership against concurrent revocation',async t=>{
 const f=await fixture(t),revoker=await extra(f,'owner');await query(f.owner,'BEGIN');await query(revoker,'BEGIN');let pending:ReturnType<typeof settled>|undefined;
 try{await startWrite(f);await addGroup(f);await complete(f);pending=settled(setMembership(f,revoker,f.tenant,false));await waitBlocked(f.admin,revoker,f.owner);await query(f.owner,'COMMIT');assert.equal((await pending).ok,true);await query(revoker,'COMMIT');}
 finally{await query(f.owner,'ROLLBACK');await query(revoker,'ROLLBACK');if(pending)await pending;f.pending=[];}
 await assert.rejects(rawLoad(f),rejected('28000'));
});

test('membership revocation winning first is observed after the waiting principal plan resumes',async t=>{
 const f=await fixture(t),writer=await extra(f,'owner');await query(f.owner,'BEGIN');await query(writer,'BEGIN');let pending:ReturnType<typeof settled>|undefined;
 try{await setMembership(f,f.owner,f.tenant,false);pending=settled(startWrite(f,writer));await waitBlocked(f.admin,writer,f.owner);await query(f.owner,'COMMIT');assert.equal((await pending).ok,true);assert.equal((await scalar(writer,'SELECT active FROM gc_authority.tenant_member_heads WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.identity])).active,false);}
 finally{await query(f.owner,'ROLLBACK');await query(writer,'ROLLBACK');if(pending)await pending;}
 await assert.rejects(rawLoad(f),rejected('28000'));
});

test('exact session plan blocks native tenant selection until canonical fixture commit',async t=>{
 const f=await fixture(t);await query(f.owner,'BEGIN');let pending:ReturnType<typeof settled>|undefined;
 try{await startWrite(f,f.owner,undefined,[f.protectedSession.session_id]);await addGroup(f);await complete(f);pending=settled(query(f.api,'SELECT * FROM public.gc_authn_session_select($1,$2,$3,$4,$5)',[f.hash,f.csrf,1,f.otherTenant,digest()]));await waitBlocked(f.admin,f.api,f.owner);await query(f.owner,'COMMIT');assert.equal((await pending).ok,true);}
 finally{await query(f.owner,'ROLLBACK');if(pending)await pending;f.pending=[];}
 const changed=await tx(f.owner,()=>scalar(f.owner,'SELECT * FROM gc_authn.foundation_session_v1($1)',[f.hash]),'REPEATABLE READ READ ONLY');assert.equal(changed.tenant_id,f.otherTenant);assert.equal(changed.session_version,2);
});

test('selection winning first invalidates the originally discovered session configuration tuple',async t=>{
 const f=await fixture(t),writer=await extra(f,'owner');await query(f.api,'BEGIN');await query(writer,'BEGIN');let pending:ReturnType<typeof settled>|undefined;
 try{await query(f.api,'SELECT * FROM public.gc_authn_session_select($1,$2,$3,$4,$5)',[f.hash,f.csrf,1,f.otherTenant,digest()]);pending=settled(startWrite(f,writer,undefined,[f.protectedSession.session_id]));await waitBlocked(f.admin,writer,f.api);await query(f.api,'COMMIT');denied(await pending,['40001']);}
 finally{await query(f.api,'ROLLBACK');await query(writer,'ROLLBACK');if(pending)await pending;}
});

test('no lock plan, late principal discovery and plan expansion all refuse before child commit',async t=>{
 const f=await fixture(t),other=await addPerson(f),before=await epoch(f);
 await assert.rejects(tx(f.owner,async()=>{await query(f.owner,'SELECT gc_authority.foundation_write_begin_v1($1,$2)',[f.tenant,before]);await addGroup(f);}),rejected('23514'));f.pending=[];
 await assert.rejects(tx(f.owner,async()=>{await query(f.owner,'SELECT gc_authority.foundation_write_begin_v1($1,$2)',[f.tenant,before]);await query(f.owner,'SELECT gc_authority.foundation_write_locks_v1($1,$2)',[[f.identity],[]]);const group=await addGroup(f);await addMembership(f,group,other);}),rejected('23514'));f.pending=[];
 await assert.rejects(tx(f.owner,async()=>{await startWrite(f);await query(f.owner,'SELECT gc_authority.foundation_write_locks_v1($1,$2)',[[...f.people].sort(),[]]);}),rejected('23514'));assert.equal(await epoch(f),before);
});

test('native lock timeout aborts the waiting ledger operation without resetting or committing its epoch',async t=>{
 const f=await fixture(t),writer=await extra(f,'owner'),before=await epoch(f);await query(f.owner,'BEGIN');await query(writer,'BEGIN');
 try{await startWrite(f);await query(writer,"SET LOCAL statement_timeout='3s'");const begun=performance.now();await assert.rejects(query(writer,'SELECT gc_authority.foundation_write_begin_v1($1,$2)',[f.tenant,before]),rejected('55P03'));assert.ok(performance.now()-begun<4500,'Bounded native lock timeout exceeded');}
 finally{await query(f.owner,'ROLLBACK');await query(writer,'ROLLBACK');}
 assert.equal(await epoch(f),before);
});

test('original transaction deadline is not reset by a later loader invocation',async t=>{
 const f=await fixture(t),reader=await extra(f,'owner');await query(reader,"SET statement_timeout='35s'");await query(reader,'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 try{await scalar(reader,readSQL,[f.hash,JSON.stringify(selectors(f))]);await query(reader,'SELECT pg_sleep(30.05)');await assert.rejects(query(reader,readSQL,[f.hash,JSON.stringify(selectors(f))]),rejected('57014'));}
 finally{await query(reader,'ROLLBACK');}
 assert.equal((await load(f)).contentAuthority,false);
});

test('read-only loader acquires no row-write, advisory or tuple lock and creates no transaction binding',async t=>{
 const f=await fixture(t),reader=await extra(f,'owner');await readerGraph(f);await query(reader,'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
 try{await scalar(reader,readSQL,[f.hash,JSON.stringify(selectors(f))]);const locks=await query(reader,"SELECT locktype,mode FROM pg_locks WHERE pid=pg_backend_pid() AND (locktype IN('tuple','advisory') OR mode IN('RowExclusiveLock','ShareRowExclusiveLock','ExclusiveLock','AccessExclusiveLock')) AND locktype<>'virtualxid'");assert.deepEqual(locks.rows,[]);assert.equal((await scalar(reader,'SELECT count(*)::int n FROM gc_authority.write_bindings WHERE backend_pid=pg_backend_pid()')).n,0);}
 finally{await query(reader,'ROLLBACK');}
});
