// SPDX-License-Identifier: Apache-2.0
/** Actual independent runtime/owner sessions, advisory waits and original clocks. */
import assert from 'node:assert/strict';
import {after,test} from 'node:test';
import {randomUUID} from 'node:crypto';
import pg from 'pg';
import {db,scope,sql} from '../../packages/db/src/index.ts';
import type {Principal} from '../../packages/authz/src/index.ts';
import type {DomainMutationRequest} from '../../packages/domain/src/business-domain-service-contracts.ts';
import {assetView} from '../../apps/api/src/repository.ts';
import {fixture,execute,begin,project,persist,seal,bodyFor,permissions,reason,digest,correlation,sqlCode,migrationPlan,snapshot,type Row} from '../fixtures/business-domains.ts';
if(!process.env.BUSINESS_DOMAINS_OWNER_DATABASE_URL||!process.env.DATABASE_URL)throw Error('Actual disposable owner/runtime URLs required; no concurrency qualification ran.');
const owner=new pg.Pool({connectionString:process.env.BUSINESS_DOMAINS_OWNER_DATABASE_URL,max:6});
const runtime=new pg.Pool({connectionString:process.env.DATABASE_URL,max:8});
const sleep=(ms:number)=>new Promise(resolve=>setTimeout(resolve,ms));
async function isolated(){
 const tenantId=randomUUID(),actorId=randomUUID(),otherId=randomUUID(),admin=await owner.connect();
 try{await admin.query('BEGIN');await admin.query('INSERT INTO tenants(id,name) VALUES($1,$2)',[tenantId,'Synthetic isolated domain tenant']);
  for(const id of [actorId,otherId])await admin.query('INSERT INTO identities(id,issuer,subject,name) VALUES($1,$2,$3,$4)',[id,'synthetic-domain',id,'Synthetic isolated domain member']);
  await admin.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[tenantId,actorId]);
  for(const id of [actorId,otherId])await admin.query('INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,$3,$4)',[tenantId,id,'synthetic-member',JSON.stringify(permissions)]);
  await admin.query('COMMIT');
 }catch(e){await admin.query('ROLLBACK');throw e;}finally{admin.release();}
 const principal:Principal={tenantId,id:actorId,name:'Synthetic isolated domain member',permissions};
 return {f:await fixture({principal}),otherId};
}
async function session(p:Principal,pool=runtime){const c=await pool.connect();await c.query('BEGIN');await c.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true),set_config('statement_timeout','35s',true),set_config('lock_timeout','4s',true)",[p.tenantId,p.id]);return c;}
function latch(){let resolve!:()=>void;const promise=new Promise<void>(r=>{resolve=r;});return {promise,resolve};}
async function awaitSignal(signal:ReturnType<typeof latch>,operation:Promise<unknown>){await Promise.race([signal.promise,operation.then(()=>{throw Error('Operation completed before the expected concurrency signal');})]);}
async function waitBlocked(pid:number){for(let n=0;n<150;n++){const row=(await runtime.query('SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1',[pid])).rows[0];if(row?.wait_event_type==='Lock')return;await sleep(10);}assert.fail('Expected actual PostgreSQL lock wait was not observed');}
const place=(f:Awaited<ReturnType<typeof fixture>>,domain=f.domains[0]!):DomainMutationRequest=>({kind:'domain.placement',assetId:f.asset.id,expectedPlacementVersion:0,assetVersion:f.asset.version,domainId:domain.id,domainVersion:domain.version,reason});
const hierarchy=(d:Row,kind:'move'|'retire'|'restore',parentId:string|null):DomainMutationRequest=>({kind:'domain.hierarchy',change:{kind,domainId:d.id,expectedVersion:d.version,parentId,reason},previewDigest:digest});
const edit=(d:Row):DomainMutationRequest=>({kind:'domain.update',domainId:d.id,expectedVersion:d.version,name:d.name+' revised',description:d.description,attributes:d.attributes,ownerId:d.ownerId,reason});

test('concurrent first placement serializes on actual ledger and the losing expected-zero mutation has no partial history',async()=>{
 const {f}=await isolated(),held=latch(),release=latch(),pidReady=latch();let pid=0;
 const first=execute(place(f),{principal:f.principal,afterBegin:async()=>{held.resolve();await release.promise;}});await awaitSignal(held,first);
 const second=execute(place(f),{principal:f.principal,beforeBegin:async tx=>{pid=(await sql<{pid:number}>`SELECT pg_backend_pid() pid`.execute(tx)).rows[0]!.pid;pidReady.resolve();}}).then(value=>({value,error:null}),error=>({value:null,error}));
 try{await awaitSignal(pidReady,second);await waitBlocked(pid);}finally{release.resolve();}
 assert.equal((await first).placement.version,1);assert.equal((await second).error?.message,'VERSION_CONFLICT');
 assert.equal((await scope(f.principal.tenantId,f.principal.id,tx=>tx.selectFrom('asset_domain_placement_revisions').selectAll().where('asset_id','=',f.asset.id).execute())).length,1);
});

test('placement versus retirement and opposite hierarchy moves recheck after waits instead of committing invalid state',async()=>{
 const {f}=await isolated(),p=f.principal,a=f.domains[0]!;
 const b=(await execute({kind:'domain.create',name:'Synthetic sibling',description:'',parentId:null,type:a.type,attributes:{},ownerId:null,reason},{principal:p})).domain;
 const runRace=async(firstRequest:DomainMutationRequest,secondRequest:DomainMutationRequest,expected:string)=>{
  const held=latch(),release=latch(),pidReady=latch();let pid=0;
  const first=execute(firstRequest,{principal:p,afterBegin:async()=>{held.resolve();await release.promise;}});await awaitSignal(held,first);
  const second=execute(secondRequest,{principal:p,beforeBegin:async tx=>{pid=(await sql<{pid:number}>`SELECT pg_backend_pid() pid`.execute(tx)).rows[0]!.pid;pidReady.resolve();}}).then(value=>({value,error:null}),error=>({value:null,error}));
  try{await awaitSignal(pidReady,second);await waitBlocked(pid);}finally{release.resolve();}await first;assert.equal((await second).error?.message,expected);
 };
 await runRace(place(f),hierarchy(a,'retire',null),'DOMAIN_IN_USE');
 await runRace(hierarchy(a,'move',b.id),hierarchy(b,'move',a.id),'DOMAIN_HIERARCHY_CYCLE');
});

test('publication versus new binding stabilizes the complete direct cohort and preserves exact old pins',async()=>{
 const {f}=await isolated(),held=latch(),release=latch(),pidReady=latch();let pid=0;
 const publish:DomainMutationRequest={kind:'domain-type.publish',typeId:f.type.typeId,expectedHeadVersion:1,definition:{...f.type.definition,version:2,label:'Concurrent synthetic publication'},previewDigest:digest,reason};
 const first=execute(publish,{principal:f.principal,afterBegin:async()=>{held.resolve();await release.promise;}});await awaitSignal(held,first);
 const second=execute({kind:'domain.create',name:'Synthetic exact old pin',description:'',parentId:null,type:{typeId:f.type.typeId,version:1},attributes:{},ownerId:null,reason},{principal:f.principal,beforeBegin:async tx=>{pid=(await sql<{pid:number}>`SELECT pg_backend_pid() pid`.execute(tx)).rows[0]!.pid;pidReady.resolve();}});
 try{await awaitSignal(pidReady,second);await waitBlocked(pid);}finally{release.resolve();}assert.equal((await first).type.version,2);assert.equal((await second).domain.type.version,1);
});

test('both membership revocation orderings follow ledger then principal locks and recheck current activity',async()=>{
 const first=await isolated(),p=first.f.principal,held=latch(),release=latch(),revokeReady=latch();
 const writer=execute(edit(first.f.domains[0]!),{principal:p,afterBegin:async()=>{held.resolve();await release.promise;}});await awaitSignal(held,writer);
 const admin=await session(p,owner);const revocation=admin.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[p.tenantId]);
 try{await sleep(100);release.resolve();await writer;await revocation;await admin.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2',[p.tenantId,p.id]);await admin.query('COMMIT');}
 finally{release.resolve();await admin.query('ROLLBACK');admin.release();}
 const second=await isolated(),q=second.f.principal,revoker=await session(q,owner);let pid=0;
 try{await revoker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[q.tenantId]);await revoker.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2',[q.tenantId,q.id]);
  const attempt=execute(edit(second.f.domains[0]!),{principal:q,beforeBegin:async tx=>{pid=(await sql<{pid:number}>`SELECT pg_backend_pid() pid`.execute(tx)).rows[0]!.pid;revokeReady.resolve();}}).then(value=>({value,error:null}),error=>({value:null,error}));
  await awaitSignal(revokeReady,attempt);await waitBlocked(pid);await revoker.query('COMMIT');assert.equal((await attempt).error?.code,'42501');
 }finally{await revoker.query('ROLLBACK');revoker.release();}
});

test('legacy-first begin rejects before competing idempotency wait, avoiding ledger/idempotency lock inversion',async()=>{
 const {f}=await isolated(),p=f.principal,legacy=await session(p),other=await session(p),key=randomUUID(),request=edit(f.domains[0]!);
 try{
  await legacy.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[p.tenantId]);await legacy.query('UPDATE assets SET name=name WHERE false');
  await other.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[p.tenantId+p.id+request.kind+key]);
  const waiting=other.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[p.tenantId]);
  await assert.rejects(()=>legacy.query('SELECT gc_domain_write_begin($1,$2,$3,$4)',[randomUUID(),key,JSON.stringify(bodyFor(request)),correlation]),(e:any)=>e.code==='23514'&&e.message==='DOMAIN_STORAGE_INVALID');
  await legacy.query('ROLLBACK');await waiting;
 }finally{await legacy.query('ROLLBACK');await other.query('ROLLBACK');legacy.release();other.release();}
});

test('original transaction clock expires before begin, before seal and during deferred finalization with complete rollback',async()=>{
 const {f}=await isolated(),p=f.principal,request=edit(f.domains[0]!),before=await snapshot(p);
 for(const phase of ['before-begin','before-seal','before-finalize'] as const){
  const delay=async(tx:any)=>{await sql`SET LOCAL statement_timeout=0`.execute(tx);await sql`SET LOCAL lock_timeout=0`.execute(tx);await sql`SELECT pg_sleep(30.05)`.execute(tx);};
  const options=phase==='before-begin'?{beforeBegin:delay}:phase==='before-seal'?{beforeSeal:delay}:{afterSuccess:delay};
  await assert.rejects(()=>execute(request,{principal:p,...options}),sqlCode('57014'));assert.deepEqual(await snapshot(p),before);
 }
});

test('separately prearmed statement timer interrupts a blocked begin while direct zero-timer path still rejects expired original ledger wait',async()=>{
 const {f}=await isolated(),p=f.principal,request=edit(f.domains[0]!),blocker=await session(p),reader=await session(p);
 try{
  await blocker.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[p.tenantId]);
  await reader.query("SET LOCAL statement_timeout='150ms';SET LOCAL lock_timeout=0");
  const started=performance.now();await assert.rejects(()=>reader.query('SELECT gc_domain_write_begin($1,$2,$3,$4)',[randomUUID(),randomUUID(),JSON.stringify(bodyFor(request)),correlation]),sqlCode('57014'));
  assert.ok(performance.now()-started<3000);await reader.query('ROLLBACK');
  await reader.query('BEGIN');await reader.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true),set_config('statement_timeout','0',true),set_config('lock_timeout','0',true)",[p.tenantId,p.id]);
  const pending=reader.query('SELECT gc_domain_write_begin($1,$2,$3,$4)',[randomUUID(),randomUUID(),JSON.stringify(bodyFor(request)),correlation]).then(value=>({value,error:null}),error=>({value:null,error}));
  await sleep(30100);await blocker.query('ROLLBACK');assert.equal((await pending).error?.code,'57014');
 }finally{await blocker.query('ROLLBACK');await reader.query('ROLLBACK');blocker.release();reader.release();}
});

test('denied current asset scope precedes physical overflow and original hierarchy replay rechecks moved descendants assets',async()=>{
 const {f,otherId}=await isolated(),p=f.principal,root=f.domains[0]!;
 const child=(await execute({kind:'domain.create',name:'Synthetic original child',description:'',parentId:root.id,type:root.type,attributes:{},ownerId:null,reason},{principal:p})).domain;
 await execute(place(f,child),{principal:p});const key=randomUUID();
 await execute(hierarchy(root,'move',null),{principal:p,key}).catch((e:any)=>{assert.equal(e.message,'DOMAIN_NO_CHANGE');});
 const destination=(await execute({kind:'domain.create',name:'Synthetic destination',description:'',parentId:null,type:root.type,attributes:{},ownerId:null,reason},{principal:p})).domain;
 await execute(hierarchy(root,'move',destination.id),{principal:p,key});
 await execute(hierarchy(child,'move',null),{principal:p});
 await scope(p.tenantId,p.id,async tx=>{
  const row=await tx.updateTable('assets').set({visibility:'restricted',allowed_identities:JSON.stringify([otherId]),metadata:JSON.stringify({synthetic:'x'.repeat(600000)}),version:2,updated_at:new Date()}).where('id','=',f.asset.id).returningAll().executeTakeFirstOrThrow();
  await tx.insertInto('asset_revisions').values({tenant_id:p.tenantId,asset_id:row.id,version:row.version,snapshot:JSON.stringify(assetView(row))}).execute();
 });
 await assert.rejects(()=>execute(hierarchy({...child,version:2},'retire',null),{principal:p}),(e:any)=>e.code==='42501'&&e.message==='DOMAIN_SCOPE_UNAVAILABLE');
 await scope(p.tenantId,p.id,async tx=>{assert.equal((await sql<{value:boolean}>`SELECT gc_domain_replay_authorize('domain.hierarchy',${key}) value`.execute(tx)).rows[0]!.value,false);});
 const admin=await session(p,owner);try{await admin.query('UPDATE memberships SET permissions=$1 WHERE tenant_id=$2 AND identity_id=$3',[JSON.stringify(permissions.filter(v=>v!=='catalog:read')),p.tenantId,p.id]);await admin.query('COMMIT');}finally{await admin.query('ROLLBACK');admin.release();}
 await assert.rejects(()=>execute(hierarchy({...child,version:2},'retire',null),{principal:p}),sqlCode('42501'));
});

test('complete aggregate retained migration budget rejects a large authorized cohort without any type/domain/journal writes',async()=>{
 const {f}=await isolated(),p=f.principal;
 for(let n=0;n<28;n++)await execute({kind:'domain.create',name:'Synthetic retained cohort '+n,description:'x'.repeat(4000),parentId:null,type:{typeId:f.type.typeId,version:1},attributes:{},ownerId:null,reason},{principal:p});
 const before=await snapshot(p),plan=migrationPlan(f.type,[1]);
 await assert.rejects(()=>execute({kind:'domain-type-migration.execute',typeId:f.type.typeId,expectedHeadVersion:1,definition:{...f.type.definition,version:2},plan,previewDigest:digest,reason},{principal:p}),sqlCode('54000'));
 assert.deepEqual(await snapshot(p),before);
});

after(async()=>{await db.destroy();await owner.end();await runtime.end();});
