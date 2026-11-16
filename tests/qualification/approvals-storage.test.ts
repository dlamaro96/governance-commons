// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import test, {type TestContext} from 'node:test';
import pg from 'pg';
import {Kysely,PostgresDialect,sql,type Transaction} from 'kysely';
import {listApprovalRequests,getApprovalRequest,decideApprovalTask,cancelApprovalRequest,listApprovalDefinitions,getApprovalDefinition} from '../../packages/domain/src/approval-service.ts';
import {visibleAudit} from '../../apps/api/src/repository.ts';
process.env.SESSION_KEY=randomUUID()+randomUUID();
const config=JSON.parse(readFileSync(process.env.AUTHN_FOUNDATION_CONFIG!,'utf8'));
const permissions=['catalog:read','catalog:write','models:read','models:write','audit:read'];
const definition=(id:string,stages=1)=>({formatVersion:1,id,version:1,name:'Term approval',separationOfDuties:true,stages:Array.from({length:stages},(_,i)=>({id:`stage_${i}`,name:`Review ${i+1}`,assignments:['steward','owner'],quorum:2,deadlineSeconds:3600,rejection:'any'}))});
async function fixture(t:TestContext){
 const owner=new pg.Client({connectionString:config.owner}),app=new pg.Client({connectionString:config.legacy});
 await owner.connect();await app.connect();t.after(async()=>{await app.end();await owner.end();});
 const store=new Kysely<Record<string,any>>({dialect:new PostgresDialect({pool:new pg.Pool({connectionString:config.legacy,max:1})})});t.after(()=>store.destroy());
 const tenant=randomUUID(),foreign=randomUUID(),requester=randomUUID(),reviewer=randomUUID(),second=randomUUID(),workflowId='terms_'+randomUUID().replaceAll('-','');
 await owner.query('INSERT INTO tenants(id,name) VALUES($1,$2),($3,$4)',[tenant,'Synthetic Harbor',foreign,'Synthetic Orchard']);
 for(const [id,name] of [[requester,'Requester'],[reviewer,'Steward'],[second,'Owner']])await owner.query('INSERT INTO identities(id,issuer,subject,name) VALUES($1,$2,$4,$3)',[id,'synthetic-approval',name,id]);
 await owner.query('BEGIN');await owner.query("SELECT set_config('gc.tenant_id',$1,true)",[tenant]);
 for(const id of [requester,reviewer,second])await owner.query('INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,$3,$4::jsonb)',[tenant,id,'synthetic',JSON.stringify(permissions)]);
 await owner.query('COMMIT');
 async function as<T>(actor:string,fn:(client:pg.Client)=>Promise<T>,tenantId=tenant):Promise<T>{await app.query('BEGIN');try{await app.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[tenantId,actor]);const r=await fn(app);await app.query('COMMIT');return r;}catch(e){await app.query('ROLLBACK');throw e;}}
 const principal=(actor:string)=>({id:actor,name:'Synthetic reviewer',tenantId:tenant,permissions});
 const domain=<T>(actor:string,fn:(tx:Transaction<Record<string,any>>)=>Promise<T>)=>store.transaction().execute(async tx=>{await sql`select set_config('gc.tenant_id',${tenant},true),set_config('gc.actor_id',${actor},true)`.execute(tx);return fn(tx);});
 const command=(actor:string,operation:string,body:unknown,key=randomUUID())=>as(actor,async c=>(await c.query('SELECT gc_approval_command($1,$2,$3::jsonb,$4) AS result',[operation,key,JSON.stringify(body),'synthetic-correlation'])).rows[0].result);
 async function publish(stages=1){return command(requester,'approval.definition.publish',{definition:definition(workflowId,stages),expectedVersion:0});}
 async function submit(pin:any,extra:Record<string,unknown>={},key=randomUUID()){
  const body={id:randomUUID(),binding:'glossary.publish',resourceId:randomUUID(),resourceVersion:null,payload:{synthetic:'proposal'},workflowId,workflowVersion:1,workflowHash:pin.definitionHash,assignments:{steward:reviewer,owner:second},expiresAt:new Date(Date.now()+7200_000).toISOString(),...extra};
  return {body,key,response:await command(requester,'approval.submit',body,key)};
 }
 const tick=(id:string)=>as(requester,async c=>(await c.query('SELECT gc_approval_tick($1) AS result',[id])).rows[0].result);
 const decide=(request:any,actor:string,decision='approve',reason='Reviewed against evidence',key=randomUUID())=>{const task=request.tasks.find((x:any)=>x.assignedIdentityId===actor&&x.stageIndex===request.stageIndex);return command(actor,'approval.decide',{requestId:request.id,proposalDigest:request.proposalDigest,taskId:task.id,taskVersion:task.version,decision,reason},key);};
 const read=(table:string)=>as(requester,async c=>(await c.query(`SELECT * FROM ${table} ORDER BY id`)).rows);
 return {owner,app,tenant,foreign,requester,reviewer,second,workflowId,as,command,publish,submit,tick,decide,read,domain,principal};
}
const rejected=async(fn:()=>Promise<unknown>,code:string)=>assert.rejects(fn,(e:any)=>e.code===code);

test('forced RLS, runtime nonownership and private approval writers prevent bypass',async t=>{
 const f=await fixture(t),pin=await f.publish(),{response}=await f.submit(pin);
 const rows=(await f.owner.query("SELECT relname,relrowsecurity,relforcerowsecurity,relowner='gc_app'::regrole runtime_owner FROM pg_class WHERE relname=ANY($1)",[['workflow_definitions','workflow_definition_versions','approval_requests','approval_tasks','approval_decisions','approval_dispatch']])).rows;
 assert.equal(rows.length,6);for(const r of rows){assert.ok(r.relrowsecurity&&r.relforcerowsecurity);assert.equal(r.runtime_owner,false);}
 assert.equal((await f.as(f.requester,c=>c.query('SELECT * FROM approval_requests'),f.foreign)).rowCount,0);
 await rejected(()=>f.as(f.requester,c=>c.query("UPDATE approval_requests SET status='ready'")),'42501');
 await rejected(()=>f.as(f.requester,c=>c.query('SELECT gc_approval_request_view($1)',[response.request.id])),'42501');
 await rejected(()=>f.as(f.requester,c=>c.query("INSERT INTO idempotency(tenant_id,actor_id,operation,key,request_hash,response) VALUES($1,$2,'approval.submit','synthetic-forgery',repeat('0',64),'{}')",[f.tenant,f.requester])),'42501');
 await rejected(()=>f.as(f.requester,c=>c.query("UPDATE outbox SET event_type='ordinary.event' WHERE event_type='approval.submitted'")),'42501');
 const acknowledged=await f.as(f.requester,c=>c.query("UPDATE outbox SET processed_at=clock_timestamp(),attempts=attempts+1 WHERE event_type='approval.submitted' RETURNING id"));assert.equal(acknowledged.rowCount,1);
});

test('parallel quorum advances ordered stages with immutable pins and no implicit publication',async t=>{
 const f=await fixture(t),pin=await f.publish(2),{response}=await f.submit(pin);let request=response.request;
 assert.equal(request.tasks.filter((x:any)=>x.status==='open').length,2);assert.equal(request.tasks.filter((x:any)=>x.status==='waiting').length,2);
 const next={...definition(f.workflowId,2),version:2,name:'Changed for future requests'};
 await f.command(f.requester,'approval.definition.publish',{definition:next,expectedVersion:1});
 await f.decide(request,f.reviewer);assert.equal((await f.tick(request.id)).status,'pending');await f.decide(request,f.second);
 const stage=await f.tick(request.id);assert.equal(stage.status,'pending');assert.ok(stage.nextWakeAt);
 request=(await f.as(f.requester,async c=>(await c.query('SELECT * FROM approval_tasks WHERE request_id=$1 ORDER BY assignment',[request.id])).rows)).filter((x:any)=>x.stage_index===1).reduce((r:any,x:any)=>({...r,tasks:[...r.tasks,{id:x.id,stageIndex:x.stage_index,assignedIdentityId:x.assigned_identity_id,version:x.version}]}),{...request,stageIndex:1,tasks:[]});
 await f.decide(request,f.reviewer);await f.decide(request,f.second);
 const ready=await f.tick(request.id);assert.equal(ready.status,'ready');assert.equal(ready.nextWakeAt,null);assert.deepEqual(await f.tick(request.id),ready);
 const saved=(await f.read('approval_requests'))[0];assert.equal(saved.workflow_version,1);assert.equal(saved.workflow_hash,pin.definitionHash);assert.equal(saved.result,null);
 assert.equal((await f.as(f.requester,c=>c.query('SELECT * FROM assets'))).rowCount,0);
 assert.equal((await f.as(f.requester,c=>c.query('SELECT * FROM approval_dispatch'))).rowCount,5,'Only submitted/decision commands dispatch, never tick progress');
 assert.equal((await f.as(f.requester,c=>c.query('SELECT * FROM approval_decisions'))).rowCount,4);
});

test('exact idempotent command replay is inert; changed proposal and stale task fail',async t=>{
 const f=await fixture(t),pin=await f.publish(),s=await f.submit(pin),r=s.response.request;
 assert.deepEqual(await f.command(f.requester,'approval.submit',s.body,s.key),s.response);
 await rejected(()=>f.command(f.requester,'approval.submit',{...s.body,payload:{changed:true}},s.key),'40001');
 const key=randomUUID(),first=await f.decide(r,f.reviewer,'approve','  Evidence reviewed  ',key);
 assert.equal(first.request.decisions[0].reason,'Evidence reviewed');assert.deepEqual(await f.decide(r,f.reviewer,'approve','  Evidence reviewed  ',key),first);
 await rejected(()=>f.decide(r,f.reviewer),'40001');
 const task=r.tasks.find((x:any)=>x.assignedIdentityId===f.second);
 await rejected(()=>f.command(f.second,'approval.decide',{requestId:r.id,proposalDigest:'0'.repeat(64),taskId:task.id,taskVersion:task.version,decision:'approve',reason:'Checked'}),'40001');
 assert.equal((await f.as(f.requester,c=>c.query('SELECT * FROM approval_decisions'))).rowCount,1);
});

test('separation of duties and distinct reviewers reject invalid requests without partial rows',async t=>{
 const f=await fixture(t),pin=await f.publish();
 await rejected(()=>f.submit(pin,{assignments:{steward:f.requester,owner:f.second}}),'42501');
 await rejected(()=>f.submit(pin,{assignments:{steward:f.reviewer,owner:f.reviewer}}),'22023');
 await rejected(()=>f.submit(pin,{assignments:{steward:f.reviewer,owner:randomUUID()}}),'42501');
 assert.equal((await f.read('approval_requests')).length,0);assert.equal((await f.as(f.requester,c=>c.query('SELECT * FROM approval_tasks'))).rowCount,0);
});

test('reject and cancellation preserve decision reasons, audit and separate delivery acknowledgments',async t=>{
 const f=await fixture(t),pin=await f.publish(),s=await f.submit(pin);
 await f.decide(s.response.request,f.reviewer,'reject','Definition conflicts with approved policy');assert.equal((await f.tick(s.body.id)).status,'rejected');
 const another=await f.submit(pin);await rejected(()=>f.command(f.reviewer,'approval.cancel',{requestId:another.body.id,proposalDigest:another.response.request.proposalDigest,reason:'No longer needed'}),'42501');
 const cancelled=await f.command(f.requester,'approval.cancel',{requestId:another.body.id,proposalDigest:another.response.request.proposalDigest,reason:'No longer needed'});assert.equal(cancelled.request.status,'cancelled');
 const entries=(await f.as(f.requester,c=>c.query('SELECT * FROM approval_dispatch'))).rows;assert.equal(entries.length,4);
 await f.as(f.requester,c=>c.query('SELECT gc_approval_dispatch_ack($1)',[entries[0].event_id]));await f.as(f.requester,c=>c.query('SELECT gc_approval_dispatch_ack($1)',[entries[0].event_id]));
 const ack=(await f.as(f.requester,c=>c.query('SELECT * FROM approval_dispatch WHERE event_id=$1',[entries[0].event_id]))).rows[0];assert.ok(ack.dispatched_at);assert.equal(ack.attempts,2);
 await rejected(()=>f.as(f.requester,c=>c.query("UPDATE approval_decisions SET reason='Changed'")),'42501');
 assert.ok((await f.as(f.requester,c=>c.query("SELECT * FROM audit WHERE action='approval.rejected'"))).rowCount);
});

test('revoked membership blocks replay and canonical tick cancels pending work',async t=>{
 const f=await fixture(t),pin=await f.publish(),s=await f.submit(pin);
 await f.owner.query('BEGIN');await f.owner.query("SELECT set_config('gc.tenant_id',$1,true)",[f.tenant]);await f.owner.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.reviewer]);await f.owner.query('COMMIT');
 assert.equal((await f.tick(s.body.id)).status,'cancelled');assert.equal((await f.read('approval_requests'))[0].error_code,'REQUEST_AUTHORITY_REVOKED');
 await f.owner.query('BEGIN');await f.owner.query("SELECT set_config('gc.tenant_id',$1,true)",[f.tenant]);await f.owner.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.requester]);await f.owner.query('COMMIT');
 await rejected(()=>f.command(f.requester,'approval.submit',s.body,s.key),'42501');
});

test('native deadlines take precedence and expiry cannot publish approved work',async t=>{
 const f=await fixture(t),pin=await f.publish(),s=await f.submit(pin,{expiresAt:new Date(Date.now()+2000).toISOString()});
 await f.decide(s.response.request,f.reviewer);await f.decide(s.response.request,f.second);
 await new Promise(resolve=>setTimeout(resolve,2100));const result=await f.tick(s.body.id);assert.equal(result.status,'expired');assert.equal(result.nextWakeAt,null);
 assert.equal((await f.as(f.requester,c=>c.query('SELECT * FROM assets'))).rowCount,0);
});

test('SQL definition validation enforces strings, canonical Unicode and bounded names',async t=>{
 const f=await fixture(t),valid=definition(f.workflowId);
 for(const bad of [{...valid,id:123},{...valid,name:' trailing '},{...valid,name:'e\u0301'},{...valid,name:'x'.repeat(241)},{...valid,stages:[{...valid.stages[0],rejection:null}]},{...valid,stages:[{...valid.stages[0],quorum:3}]}])await rejected(()=>f.command(f.requester,'approval.definition.publish',{definition:bad,expectedVersion:0}),'22023');
 const good=await f.publish();assert.equal(good.definition.id,f.workflowId);
});

const proposal=(owner:string,links:unknown[]=[])=>({typePin:{typeId:randomUUID(),modelId:'business_term',version:1,definitionHash:'a'.repeat(64),resolutionHash:'b'.repeat(64)},primaryLocale:'en',ownerId:owner,visibility:'tenant',allowedIdentityIds:[],state:'active',attributes:{translations:[{locale:'en',name:'Net revenue',definition:'Sales after agreed adjustments.',synonyms:[],abbreviations:[],examples:[]}]},links});

test('native service pagination and audit hide unauthorized linked proposals before limiting',async t=>{
 const f=await fixture(t),pin=await f.publish(),target=randomUUID();
 await f.as(f.requester,c=>c.query("INSERT INTO assets(tenant_id,id,external_id,name,qualified_name,type,observed_at,visibility,allowed_identities) VALUES($1,$2,$4,'Restricted table','synthetic.restricted','table',clock_timestamp(),'restricted',$3::jsonb)",[f.tenant,target,JSON.stringify([f.requester]),target]));
 const link={kind:'defines',typePin:{relationTypeId:randomUUID(),version:1,definitionHash:'c'.repeat(64)},targetAssetId:target,targetAssetVersion:1};
 const hidden=await f.submit(pin,{id:'00000000-0000-4000-8000-000000000001',payload:proposal(f.requester,[link])});
 const visible=await f.submit(pin,{id:'ffffffff-ffff-4fff-8fff-ffffffffffff',payload:proposal(f.requester)});
 const page=await f.domain(f.reviewer,tx=>listApprovalRequests(tx,f.principal(f.reviewer),{limit:1}));assert.equal(page.items.length,1);assert.equal(page.items[0].id,visible.body.id);assert.equal(page.nextCursor,null);
 await assert.rejects(()=>f.domain(f.reviewer,tx=>getApprovalRequest(tx,f.principal(f.reviewer),hidden.body.id)),(e:any)=>e.status===404);
 const audit=await f.domain(f.reviewer,tx=>visibleAudit(tx,f.principal(f.reviewer)).where('audit.action','like','approval.%').execute());assert.equal(audit.length,1);assert.equal(audit[0].resource_id,visible.body.id);
 const request=await f.domain(f.reviewer,tx=>getApprovalRequest(tx,f.principal(f.reviewer),visible.body.id));assert.equal(request.payload.attributes.translations instanceof Array,true);assert.equal(request.workflow.definitionHash,pin.definitionHash);
 const outsider=randomUUID();await f.owner.query('INSERT INTO identities(id,issuer,subject,name) VALUES($1,$2,$3,$4)',[outsider,'synthetic-approval',outsider,'Other member']);
 await f.owner.query('BEGIN');await f.owner.query("SELECT set_config('gc.tenant_id',$1,true)",[f.tenant]);await f.owner.query('INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,$3,$4::jsonb)',[f.tenant,outsider,'synthetic',JSON.stringify(permissions)]);await f.owner.query('COMMIT');
 assert.equal((await f.domain(outsider,tx=>listApprovalRequests(tx,f.principal(outsider)))).items.length,0);
 const first=await f.domain(f.requester,tx=>listApprovalRequests(tx,f.principal(f.requester),{limit:1}));assert.ok(first.nextCursor);
 await assert.rejects(()=>f.domain(f.reviewer,tx=>listApprovalRequests(tx,f.principal(f.reviewer),{limit:1,cursor:first.nextCursor!})),(e:any)=>e.status===400);
});

test('native service replays an authorized decision after reference drift, while refusing new stale decisions',async t=>{
 const f=await fixture(t),pin=await f.publish(),target=randomUUID();
 await f.as(f.requester,c=>c.query("INSERT INTO assets(tenant_id,id,external_id,name,qualified_name,type,observed_at) VALUES($1,$2,$3,'Table','synthetic.table','table',clock_timestamp())",[f.tenant,target,target]));
 const link={kind:'defines',typePin:{relationTypeId:randomUUID(),version:1,definitionHash:'c'.repeat(64)},targetAssetId:target,targetAssetVersion:1};
 const s=await f.submit(pin,{payload:proposal(f.requester,[link])}),request=s.response.request,task=request.tasks.find((x:any)=>x.assignedIdentityId===f.reviewer);
 const input={proposalDigest:request.proposalDigest,taskId:task.id,taskVersion:task.version,decision:'approve' as const,reason:'Reviewed evidence'},key=randomUUID();
 const first=await f.domain(f.reviewer,tx=>decideApprovalTask(tx,f.principal(f.reviewer),request.id,input,key,'synthetic-service'));
 assert.equal(first.request.preconditionsCurrent,true);
 await f.as(f.requester,c=>c.query('UPDATE assets SET version=version+1 WHERE id=$1',[target]));
 const repeated=await f.domain(f.reviewer,tx=>decideApprovalTask(tx,f.principal(f.reviewer),request.id,input,key,'synthetic-service'));
 assert.deepEqual({...repeated.request,preconditionsCurrent:true},first.request);assert.equal(repeated.request.preconditionsCurrent,false);
 const second=request.tasks.find((x:any)=>x.assignedIdentityId===f.second);
 await assert.rejects(()=>f.domain(f.second,tx=>decideApprovalTask(tx,f.principal(f.second),request.id,{...input,taskId:second.id,taskVersion:second.version},randomUUID(),'synthetic-service')),(e:any)=>e.status===409);
 const cancelled=await f.domain(f.requester,tx=>cancelApprovalRequest(tx,f.principal(f.requester),request.id,{proposalDigest:request.proposalDigest,reason:'Revise stale proposal'},randomUUID(),'synthetic-service'));assert.equal(cancelled.request.status,'cancelled');
});

test('native definition reads preserve pinned history and tenant-scoped signed pages',async t=>{
 const f=await fixture(t),first=await f.publish();
 await f.command(f.requester,'approval.definition.publish',{definition:{...first.definition,version:2,name:'Future approval'},expectedVersion:1});
 const old=await f.domain(f.requester,tx=>getApprovalDefinition(tx,f.principal(f.requester),f.workflowId,1));assert.equal(old.currentVersion,2);assert.equal(old.definition.version,1);assert.equal(old.definitionHash,first.definitionHash);
 const rows=await f.domain(f.requester,tx=>listApprovalDefinitions(tx,f.principal(f.requester),{q:'Future'}));assert.equal(rows.items.length,1);assert.equal(rows.items[0].definition.version,2);
 const notMatched=await f.domain(f.requester,tx=>listApprovalDefinitions(tx,f.principal(f.requester),{q:'%'}));assert.equal(notMatched.items.length,0,'Wildcards are literal search text');
});

async function peer(t:TestContext,tenant:string,actor:string){
 const client=new pg.Client({connectionString:config.legacy});await client.connect();t.after(()=>client.end());
 const pid=(await client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
 const command=async(body:unknown,key:string)=>{await client.query('BEGIN');try{await client.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true),set_config('statement_timeout','10000',true)",[tenant,actor]);const value=(await client.query("SELECT gc_approval_command('approval.decide',$1,$2::jsonb,'synthetic-race') AS result",[key,JSON.stringify(body)])).rows[0].result;await client.query('COMMIT');return value;}catch(e){await client.query('ROLLBACK');throw e;}};
 return {client,pid,command};
}
async function waitBlocked(client:pg.Client,pid:number){const end=Date.now()+5000;for(;;){const row=(await client.query('SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1',[pid])).rows[0];if(row?.wait_event_type==='Lock')return;assert.ok(Date.now()<end,'Expected exact peer to wait on a real lock');await new Promise(r=>setTimeout(r,20));}}

test('real concurrent duplicate deliveries produce one decision and one retained response',async t=>{
 const f=await fixture(t),pin=await f.publish(),s=await f.submit(pin),r=s.response.request,task=r.tasks.find((x:any)=>x.assignedIdentityId===f.reviewer);
 const one=await peer(t,f.tenant,f.reviewer),two=await peer(t,f.tenant,f.reviewer),body={requestId:r.id,proposalDigest:r.proposalDigest,taskId:task.id,taskVersion:task.version,decision:'approve',reason:'Concurrent decision'},key=randomUUID();
 const [a,b]=await Promise.all([one.command(body,key),two.command(body,key)]);assert.deepEqual(a,b);
 assert.equal((await f.as(f.requester,c=>c.query('SELECT * FROM approval_decisions'))).rowCount,1);
 assert.equal((await f.as(f.requester,c=>c.query("SELECT * FROM audit WHERE action='approval.decided'"))).rowCount,1);
});

test('membership revocation committed during a real lock wait prevents the pending decision',async t=>{
 const f=await fixture(t),pin=await f.publish(),s=await f.submit(pin),r=s.response.request,task=r.tasks.find((x:any)=>x.assignedIdentityId===f.reviewer),review=await peer(t,f.tenant,f.reviewer);
 await f.owner.query('BEGIN');await f.owner.query("SELECT set_config('gc.tenant_id',$1,true)",[f.tenant]);await f.owner.query('SELECT identity_id FROM memberships WHERE tenant_id=$1 AND identity_id=$2 FOR UPDATE',[f.tenant,f.reviewer]);
 const result=review.command({requestId:r.id,proposalDigest:r.proposalDigest,taskId:task.id,taskVersion:task.version,decision:'approve',reason:'Decision after wait'},randomUUID()).then(value=>({value,error:null as any}),error=>({value:null,error}));
 try{await waitBlocked(f.app,review.pid);await f.owner.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.reviewer]);await f.owner.query('COMMIT');}catch(e){await f.owner.query('ROLLBACK');throw e;}
 const settled=await result;assert.equal(settled.error?.code,'42501');assert.equal((await f.as(f.requester,c=>c.query('SELECT * FROM approval_decisions'))).rowCount,0);
});

test('deadline elapsed during a real lock wait refuses a formerly timely decision',async t=>{
 const f=await fixture(t),pin=await f.publish(),s=await f.submit(pin,{expiresAt:new Date(Date.now()+1500).toISOString()}),r=s.response.request,task=r.tasks.find((x:any)=>x.assignedIdentityId===f.reviewer),review=await peer(t,f.tenant,f.reviewer);
 await f.owner.query('BEGIN');await f.owner.query("SELECT set_config('gc.tenant_id',$1,true)",[f.tenant]);await f.owner.query('SELECT identity_id FROM memberships WHERE tenant_id=$1 AND identity_id=$2 FOR UPDATE',[f.tenant,f.reviewer]);
 const result=review.command({requestId:r.id,proposalDigest:r.proposalDigest,taskId:task.id,taskVersion:task.version,decision:'approve',reason:'Decision after deadline'},randomUUID()).then(value=>({value,error:null as any}),error=>({value:null,error}));
 try{await waitBlocked(f.app,review.pid);await new Promise(r=>setTimeout(r,1600));await f.owner.query('COMMIT');}catch(e){await f.owner.query('ROLLBACK');throw e;}
 const settled=await result;assert.equal(settled.error?.code,'40001');assert.equal((await f.as(f.requester,c=>c.query('SELECT * FROM approval_decisions'))).rowCount,0);assert.equal((await f.tick(r.id)).status,'expired');
});
