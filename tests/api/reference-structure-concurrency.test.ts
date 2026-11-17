// SPDX-License-Identifier: Apache-2.0
/** Native SQL024 races. Every race observes pg_blocking_pids before release.
 * No runtime claim until the owned PostgreSQL gate executes this exact file. */
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import test from 'node:test';
import {sql,type Tx} from '../../packages/db/src/index.ts';
import {Problem} from '../../packages/authz/src/index.ts';
import {decideApprovalTask} from '../../packages/domain/src/approval-service.ts';
import {proposeReferenceStructure,getStructureRelease,downloadStructureRelease,structureQuery} from '../../packages/domain/src/reference-structure-service.ts';
import {hierarchy,crosswalk,stateCode,labels} from '../fixtures/reference-structure.ts';
import {concurrencyFixture} from '../fixtures/reference-structure-concurrency.ts';

const forbidden=(e:unknown)=>stateCode('42501')(e)||e instanceof Problem&&e.status===403;
const effect=(tx:Tx,id:string)=>structureQuery(tx,async()=>(await sql<{value:any}>`select public.gc_reference_structure_publish(${id}::uuid) as value`.execute(tx)).rows[0].value);

test('structure proposal observes blocked owner revocation and leaves no request or receipt',async t=>{
 const f=await concurrencyFixture(t),e=await f.endpoint(),p=f.structureProposal(hierarchy(f.reader,e.pin));
 await f.refused(f.actor,()=>f.membership(f.reader,['catalog:read']),tx=>proposeReferenceStructure(tx,f.principal(),p,randomUUID(),'structure-race'),e=>stateCode('40001')(e)&&e instanceof Error&&e.message==='reference structure version conflict');
});

test('structure decision observes blocked reviewer revocation without recording a vote',async t=>{
 const f=await concurrencyFixture(t),e=await f.endpoint(),p=f.structureProposal(hierarchy(f.actor,e.pin));await f.structureCommand(p);
 const r=await f.request(p.id),task=r.tasks.find(x=>x.assigned_identity_id===f.reviewer);assert.ok(task);
 await f.refused(f.reviewer,()=>f.membership(f.reviewer,['catalog:read','reference:read']),tx=>decideApprovalTask(tx,f.principal(f.reviewer),p.id,{proposalDigest:r.row.proposal_digest,taskId:task.id,taskVersion:task.version,decision:'approve',reason:'Review exact retained evidence'},randomUUID(),'structure-race'),forbidden);
});

test('structure final effect observes blocked reviewer revocation and leaves ready history unchanged',async t=>{
 const f=await concurrencyFixture(t),e=await f.endpoint(),p=f.structureProposal(hierarchy(f.actor,e.pin));await f.structureReady(p);
 await f.refused(f.actor,()=>f.membership(f.second,['catalog:read','reference:read']),tx=>effect(tx,p.id),forbidden);
 assert.equal((await f.request(p.id)).row.status,'ready');
});

test('structure final effect waits for a concurrent endpoint successor and refuses the now stale pin',async t=>{
 const f=await concurrencyFixture(t),e=await f.endpoint(),p=f.structureProposal(hierarchy(f.actor,e.pin));await f.structureReady(p);
 const next=f.proposal({setId:e.pin.setId,expectedVersion:1,release:{...e.proposal.release,labels:labels('Endpoint successor')}});await f.ready(next);
 const lock=await f.refused(f.actor,()=>f.blocker.query('SELECT public.gc_reference_publish($1::uuid)',[next.id]),tx=>effect(tx,p.id),stateCode('40001'));
 assert.ok(lock.waits.includes('advisory'),'The concurrent supported endpoint command owns the tenant ledger');
 assert.equal((await f.request(p.id)).row.status,'ready');
});

test('structure exact release read observes blocked current reader revocation before returning bytes',async t=>{
 const f=await concurrencyFixture(t),e=await f.endpoint(),p=f.structureProposal(hierarchy(f.actor,e.pin));await f.structureReady(p);await f.structurePublish(p.id);
 await f.refused(f.reader,()=>f.membership(f.reader,['catalog:read']),tx=>getStructureRelease(tx,f.principal(f.reader),p.structureId,1),forbidden);
});

test('structure CSV download observes blocked current reader revocation before returning body or ETag',async t=>{
 const f=await concurrencyFixture(t),e=await f.endpoint(),p=f.structureProposal(hierarchy(f.actor,e.pin));await f.structureReady(p);await f.structurePublish(p.id);
 await f.refused(f.reader,()=>f.membership(f.reader,['catalog:read']),tx=>downloadStructureRelease(tx,f.principal(f.reader),p.structureId,1,'csv'),forbidden);
});

test('structure locks the complete sorted principal union before sorted endpoints without locking unrelated endpoint owners',async t=>{
 const f=await concurrencyFixture(t),owners=[randomUUID(),randomUUID()];
 for(const owner of owners){await f.owner.query('INSERT INTO identities(id,issuer,subject,name) VALUES($1::uuid,$2,$1::uuid::text,$3)',[owner,'https://structure-race.invalid/owned','Synthetic endpoint owner']);await f.ownerTx(()=>f.owner.query('INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,$3,$4::jsonb)',[f.tenant,owner,'synthetic',JSON.stringify(['catalog:read','reference:read'])]));}
 const endpoints=[];
 for(const ownerId of owners){const p=f.proposal();endpoints.push(await f.endpoint({release:{...p.release,ownerId,values:p.release.values.map(x=>({...x,ownerId}))}}));}
 const release=crosswalk(f.reader,endpoints[0].pin,endpoints[1].pin),principals=[f.actor,f.reviewer,f.second,f.reader].sort();
 // Hold the LAST principal identity: all earlier identities must be locked,
 // while no memberships or endpoint heads may yet be locked.
 await f.begin();await f.blocker.query('SELECT id FROM identities WHERE id=$1 FOR UPDATE',[principals.at(-1)]);
 let run=f.operation(f.actor,tx=>proposeReferenceStructure(tx,f.principal(),f.structureProposal(release),randomUUID(),'structure-order'));
 try{await f.observed(run);for(const id of principals.slice(0,-1))await f.probeLock('identities',id,true);for(const id of principals)await f.probeLock('memberships',id,false);for(const id of owners)await f.probeLock('identities',id,false);await f.blocker.query('COMMIT');assert.equal((await run.outcome).ok,true);}finally{await f.blocker.query('ROLLBACK');await run.outcome;}
 // Hold the LAST endpoint: all principal phases and the lower endpoint must
 // already be locked; endpoint owner identities are deliberately not checked.
 const ids=endpoints.map(x=>x.pin.setId).sort();await f.begin();await f.blocker.query('SELECT id FROM reference_sets WHERE tenant_id=$1 AND id=$2 FOR UPDATE',[f.tenant,ids[1]]);
 run=f.operation(f.actor,tx=>proposeReferenceStructure(tx,f.principal(),f.structureProposal(release),randomUUID(),'structure-order'));
 try{await f.observed(run);for(const id of principals){await f.probeLock('identities',id,true);await f.probeLock('memberships',id,true);}await f.probeLock('reference_sets',ids[0],true);for(const id of owners)await f.probeLock('identities',id,false);await f.blocker.query('COMMIT');assert.equal((await run.outcome).ok,true);}finally{await f.blocker.query('ROLLBACK');await run.outcome;}
});

test('structure remaining original deadline becomes a real PostgreSQL lock timeout instead of a renewed budget',async t=>{
 const f=await concurrencyFixture(t),e=await f.endpoint(),p=f.structureProposal(hierarchy(f.actor,e.pin)),before=await f.state();
 await f.begin();await f.blocker.query('SELECT identity_id FROM memberships WHERE tenant_id=$1 AND identity_id=$2 FOR UPDATE',[f.tenant,f.actor]);
 const now=performance.now.bind(performance);let aged=false,settings:{statement:string;lock:string}|undefined;
 // The elapsed clock is controlled; the SQL lock and timeout are real. This
 // avoids a 30-second sleep while proving nested work uses its original end.
 t.mock.method(performance,'now',()=>now()+(aged?29500:0));
 const started=Date.now(),run=f.operation(f.actor,async tx=>{
  await structureQuery(tx,()=>sql`select 1`.execute(tx));aged=true;
  return structureQuery(tx,async()=>{settings=(await sql<{statement:string;lock:string}>`select current_setting('statement_timeout') as statement,current_setting('lock_timeout') as lock`.execute(tx)).rows[0];return proposeReferenceStructure(tx,f.principal(),p,randomUUID(),'structure-budget');});
 });
 try{await f.observed(run,400);const outcome=await run.outcome;assert.equal(outcome.ok,false);if(outcome.ok)throw Error('Unexpected deadline success');assert.ok(stateCode('55P03')(outcome.error)||stateCode('57014')(outcome.error));assert.ok(settings);const ms=(s:string)=>s.endsWith('ms')?Number(s.slice(0,-2)):s.endsWith('s')?Number(s.slice(0,-1))*1000:Number(s);assert.ok(ms(settings.statement)>0&&ms(settings.statement)<=500);assert.ok(ms(settings.lock)>0&&ms(settings.lock)<=500);assert.ok(Date.now()-started<2000,'Aged deadline must not renew the normal two-second lock budget');}
 finally{aged=false;t.mock.restoreAll();await f.blocker.query('ROLLBACK');await run.outcome;}
 assert.deepEqual(await f.state(),before);
});
