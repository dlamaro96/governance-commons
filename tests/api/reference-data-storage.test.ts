// SPDX-License-Identifier: Apache-2.0
/** Native SQL022 reference publication/service qualification in a disposable DB.
 * Uses real protected commands and independent approvals. No Temporal, HTTP/304,
 * browser, external source, crosswalk or source-validation execution is claimed. */
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import test,{type TestContext} from 'node:test';
import pg from 'pg';
import {Kysely,PostgresDialect} from 'kysely';
import {lockTenantLedger,sql,type Tx} from '../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../packages/authz/src/index.ts';
import {decideApprovalTask} from '../../packages/domain/src/approval-service.ts';
import {configureRelationTransaction} from '../../packages/domain/src/relation-store.ts';
import {parseRelease,parseProposal,proposalDigest,preparePublication,publicationHash} from '../../packages/domain/src/reference-data.ts';
import type {Audience,Labels,Proposal,PublishedBundle,ReleaseInput,Result} from '../../packages/domain/src/reference-data-contracts.ts';
import {listReferenceSets,getReferenceEffective,listReferenceReleases,getReferenceRelease,getReferenceAuthoringContext,downloadReferenceRelease,proposeReferenceRelease} from '../../packages/domain/src/reference-data-service.ts';

const configFile=process.env.AUTHN_FOUNDATION_CONFIG;
assert.ok(configFile,'AUTHN_FOUNDATION_CONFIG is required; no shared runtime fallback');
const config=JSON.parse(readFileSync(configFile,'utf8')) as {owner:string;legacy:string};
assert.equal(typeof config.owner,'string');assert.equal(typeof config.legacy,'string');
process.env.SESSION_KEY=randomUUID()+randomUUID();
const permissions=['catalog:read','catalog:write','models:read','models:write','reference:read','reference:write','reference:approve','audit:read'];
const tables=['reference_sets','reference_releases','reference_values'] as const;
const snapshots=[...tables,'approval_requests','approval_tasks','approval_decisions','approval_dispatch','workflow_definitions','workflow_definition_versions','audit','outbox','idempotency'] as const;
const stateCode=(expected:string)=>(e:unknown)=>!!e&&typeof e==='object'&&'code'in e&&e.code===expected;
const problem=(status:number)=>(e:unknown)=>e instanceof Problem&&e.status===status;
const guarded=(e:unknown)=>stateCode('42501')(e)||stateCode('23514')(e);
function good<T>(result:Result<T>):T{assert.equal(result.ok,true,JSON.stringify(result));if(!result.ok)throw Error('Invalid fixture');return result.value;}
function canonical(value:any):string{
 if(value instanceof Date)return JSON.stringify(value.toISOString());
 if(value===null||typeof value!=='object')return JSON.stringify(value);
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
}
const hash=(value:unknown)=>createHash('sha256').update(canonical(value)).digest('hex');
const labels=(name='State'):Labels=>({en:{label:name,description:'A complete reviewed reference snapshot.'},ar:{label:'الحالة',description:'قائمة مرجعية معتمدة.'}});
const release=(ownerId:string):ReleaseInput=>({formatVersion:1,kind:'reference-code-list',labels:labels(),ownerId,status:'active',activation:{kind:'on-publication'},validUntil:null,
 values:['a','001','A'].map(code=>({code,labels:labels('Value '+code),ownerId,status:'active',validFrom:null,validUntil:null}))});

async function fixture(t:TestContext){
 const owner=new pg.Client({connectionString:config.owner,connectionTimeoutMillis:5000});
 const db=new Kysely<Record<string,any>>({dialect:new PostgresDialect({pool:new pg.Pool({connectionString:config.legacy,max:1,connectionTimeoutMillis:5000})})});
 t.after(async()=>{await db.destroy();await owner.end();});await owner.connect();
 await owner.query("SET statement_timeout='15s';SET lock_timeout='2s'");
 const tenant=randomUUID(),foreign=randomUUID(),actor=randomUUID(),reviewer=randomUUID(),second=randomUUID(),reader=randomUUID(),outsider=randomUUID();
 const ownerTx=async<T>(work:()=>Promise<T>,scope=tenant,who=actor)=>{await owner.query('BEGIN');try{
  await owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true),pg_advisory_xact_lock(hashtextextended($1,0))",[scope,who]);
  const value=await work();await owner.query('COMMIT');return value;
 }catch(e){await owner.query('ROLLBACK');throw e;}};
 await owner.query('INSERT INTO tenants(id,name) VALUES($1,$3),($2,$3)',[tenant,foreign,'Synthetic reference qualification']);
 for(const who of [actor,reviewer,second,reader,outsider])await owner.query('INSERT INTO identities(id,issuer,subject,name) VALUES($1::uuid,$2,$1::uuid::text,$3)',[who,'https://reference-fixture.invalid/owned','Synthetic reference participant']);
 for(const [scope,ids]of [[tenant,[actor,reviewer,second,reader]],[foreign,[outsider]]] as const)await ownerTx(async()=>{
  for(const who of ids)await owner.query('INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,$3,$4::jsonb)',[scope,who,'synthetic',JSON.stringify(who===reader?['catalog:read','reference:read']:permissions)]);
 },scope,ids[0]);
 const principal=(who=actor,scope=tenant):Principal=>({id:who,tenantId:scope,name:'Synthetic reference participant',permissions});
 const as=<T>(work:(tx:Tx)=>Promise<T>,who:string=actor,scope:string=tenant)=>db.transaction().execute(async tx=>{
  await sql`select set_config('gc.tenant_id',${scope},true),set_config('gc.actor_id',${who},true)`.execute(tx);
  await configureRelationTransaction(tx);await lockTenantLedger(tx,scope);return work(tx);
 });
 const command=(body:unknown,key=randomUUID(),who=actor,scope=tenant)=>as(async tx=>(await sql<{value:any}>`select public.gc_reference_command('reference.propose',${key},${JSON.stringify(body)}::jsonb,'reference-native') as value`.execute(tx)).rows[0].value,who,scope);
 const approval=(operation:string,body:unknown,key=randomUUID(),who=actor)=>as(async tx=>(await sql<{value:any}>`select public.gc_approval_command(${operation},${key},${JSON.stringify(body)}::jsonb,'reference-native') as value`.execute(tx)).rows[0].value,who);
 const workflowId='reference_'+randomUUID().replaceAll('-','');
 const definition=(version=1)=>({formatVersion:1,id:workflowId,version,name:'Independent reference publication review',separationOfDuties:true,stages:[{id:'review',name:'Independent review',assignments:['first','second'],quorum:2,deadlineSeconds:3600,rejection:'any'}]});
 const w=await approval('approval.definition.publish',{definition:definition(),expectedVersion:0});
 const workflow={id:workflowId,version:1,definitionHash:w.definitionHash as string};
 const proposal=(extra:Partial<Proposal>={}):Proposal=>({id:randomUUID(),setId:randomUUID(),expectedVersion:0,audience:{visibility:'tenant',allowedIdentityIds:[]},release:release(actor),workflow,assignments:{first:reviewer,second},expiresAt:new Date(Date.now()+3600000).toISOString(),...extra});
 const request=(id:string)=>as(async tx=>({row:await tx.selectFrom('approval_requests').selectAll().where('id','=',id).executeTakeFirstOrThrow(),tasks:await tx.selectFrom('approval_tasks').selectAll().where('request_id','=',id).orderBy('assignment').execute()}));
 const decide=async(id:string,who=reviewer,decision:'approve'|'reject'='approve')=>{const current=await request(id),task=current.tasks.find(r=>r.assigned_identity_id===who);assert.ok(task);
  return as(tx=>decideApprovalTask(tx,principal(who),id,{proposalDigest:current.row.proposal_digest,taskId:task.id,taskVersion:task.version,decision,reason:'Reviewed complete reference release'},randomUUID(),'reference-native'),who);};
 const tick=(id:string)=>as(async tx=>(await sql<{value:any}>`select public.gc_approval_tick(${id}::uuid) as value`.execute(tx)).rows[0].value,'site:local');
 const publish=(id:string,who=actor,scope=tenant)=>as(async tx=>(await sql<{value:any}>`select public.gc_reference_publish(${id}::uuid) as value`.execute(tx)).rows[0].value,who,scope);
 const ready=async(p:Proposal)=>{await command(p);await decide(p.id);await decide(p.id,second);const result=await tick(p.id);assert.equal(result.status,'ready');return result;};
 const complete=async(p=proposal())=>{await ready(p);const result=await publish(p.id);return {proposal:p,result,view:await as(tx=>getReferenceRelease(tx,principal(),p.setId,p.expectedVersion+1))};};
 const state=()=>ownerTx(async()=>{const result:Record<string,any[]>={};for(const table of snapshots)result[table]=(await owner.query('SELECT * FROM public."'+table+'" WHERE tenant_id=$1',[tenant])).rows.sort((a,b)=>canonical(a).localeCompare(canonical(b)));return result;});
 const unchanged=async(work:()=>Promise<unknown>,predicate:(e:unknown)=>boolean)=>{const before=await state();await assert.rejects(work,predicate);assert.deepEqual(await state(),before,'Refusal leaves canonical data, approval, history, journals and idempotency unchanged');};
 const revoke=(who:string,grants:string[])=>ownerTx(()=>owner.query('UPDATE memberships SET permissions=$3::jsonb WHERE tenant_id=$1 AND identity_id=$2',[tenant,who,JSON.stringify(grants)]));
 const now=async()=>String((await owner.query("SELECT public.gc_relation_utc(clock_timestamp()) AS value")).rows[0].value);
 const waitUntil=async(at:string)=>{const delay=Date.parse(at)-Date.parse(await now());assert.ok(delay<10000,'Fixture wait must stay bounded');await owner.query('SELECT pg_sleep(greatest(extract(epoch FROM $1::timestamptz-clock_timestamp()),0)+0.02)',[at]);};
 return {owner,ownerTx,tenant,foreign,actor,reviewer,second,reader,outsider,principal,as,command,approval,workflow,definition,proposal,request,decide,tick,publish,ready,complete,state,unchanged,revoke,now,waitUntil};
}

// Independent RFC4180 parser; it does not call the production serializer.
function csvRows(body:string):string[][]{
 const rows:string[][]=[];let row:string[]=[],cell='',quoted=false,closed=false;
 for(let i=0;i<body.length;i++){const c=body[i];if(quoted){if(c==='"'){if(body[i+1]==='"'){cell+='"';i++;}else{quoted=false;closed=true;}}else cell+=c;continue;}
  if(c==='"'){assert.equal(cell,'');assert.equal(closed,false);quoted=true;}else if(c===','){row.push(cell);cell='';closed=false;}
  else if(c==='\r'){assert.equal(body[++i],'\n');row.push(cell);rows.push(row);row=[];cell='';closed=false;}
  else{assert.equal(closed,false);assert.notEqual(c,'\n');cell+=c;}}
 assert.equal(quoted,false);assert.equal(cell,'');assert.deepEqual(row,[]);return rows;
}
function csvBundle(body:string):PublishedBundle{
 const [header,...rows]=csvRows(body);assert.deepEqual(header,['format_version','kind','set_id','version','set_labels_json','set_owner_id','set_status','published_at','effective_from','set_valid_until','code','value_labels_json','value_owner_id','value_status','value_valid_from','value_valid_until']);
 assert.ok(rows.length);const head=rows[0].slice(0,10);
 return {formatVersion:1,kind:'reference-code-list',setId:head[2],version:Number(head[3]),labels:JSON.parse(head[4]),ownerId:head[5],status:head[6] as PublishedBundle['status'],publishedAt:head[7],effectiveFrom:head[8],validUntil:head[9]||null,
  values:rows.map(r=>{assert.equal(r.length,16);assert.deepEqual(r.slice(0,10),head);return {code:r[10],labels:JSON.parse(r[11]),ownerId:r[12],status:r[13] as 'active'|'deprecated',validFrom:r[14]||null,validUntil:r[15]||null};})};
}

test('reference native normalization agrees with pure text padding, controls, exact codes and canonical hashes',async t=>{
 const f=await fixture(t),base=release(f.actor),withLabel=(label:string,description='Description')=>({...base,labels:{...base.labels,en:{label,description}}});
 const cases:[unknown,boolean][]=[[base,true],[withLabel(' \uFEFF Cafe\u0301 \u00a0'),true],[withLabel(' '.repeat(239)+'X'),true],[withLabel(' '.repeat(240)+'X'),false],[withLabel('😀'.repeat(120)),true],[withLabel('😀'.repeat(121)),false],[withLabel('\nLabel'),false],[withLabel('Label','\t\nLine\r\nSecond\tline\n'),true],[withLabel('Label','\vDescription'),false],[{...base,values:[base.values[0],base.values[0]]},false],[{...base,values:[{...base.values[0],code:' A'}]},false],[{...base,extra:true},false],[{...base,values:[]},false]];
 for(const [input,accepted]of cases){const parsed=parseRelease(input);assert.equal(parsed.ok,accepted);const row=(await f.owner.query('SELECT public.gc_reference_release_normalize($1::jsonb) AS value',[JSON.stringify(input)])).rows[0];
  if(parsed.ok){assert.deepEqual(row.value,JSON.parse(JSON.stringify(parsed.value)));assert.equal((await f.owner.query('SELECT public.gc_type_migration_hash($1::jsonb) AS hash',[JSON.stringify(row.value)])).rows[0].hash,hash(parsed.value));}else assert.equal(row.value,null);}
 const p=f.proposal(),normalized=good(parseProposal(p,f.actor));await f.command(p);assert.equal((await f.request(p.id)).row.proposal_digest,good(proposalDigest(normalized,f.actor)));
});

test('reference native tables force tenant RLS and deny direct writes and reserved receipt namespace forgery',async t=>{
 const f=await fixture(t);await f.complete();
 const flags=(await f.owner.query("SELECT relname,relrowsecurity,relforcerowsecurity,relowner='gc_app'::regrole AS owned,has_table_privilege('gc_app',oid,'INSERT,UPDATE,DELETE,TRUNCATE') AS write FROM pg_class WHERE oid=ANY($1::regclass[]) ORDER BY relname",[tables.map(x=>'public.'+x)])).rows;
 assert.equal(flags.length,3);for(const row of flags)assert.deepEqual([row.relrowsecurity,row.relforcerowsecurity,row.owned,row.write],[true,true,false,false]);
 for(const table of tables){assert.equal((await f.as(tx=>sql`select * from ${sql.table(table)}`.execute(tx),f.outsider,f.foreign)).rows.length,0);
  await f.unchanged(()=>f.as(tx=>sql`delete from ${sql.table(table)} where tenant_id=${f.tenant}::uuid`.execute(tx)),stateCode('42501'));}
 await f.unchanged(()=>f.as(tx=>sql`insert into public.idempotency(tenant_id,actor_id,operation,key,request_hash,response) values(${f.tenant}::uuid,${f.actor},'reference.propose','forged-reference-key',${'0'.repeat(64)},'{}'::jsonb)`.execute(tx)),stateCode('42501'));
 await f.unchanged(()=>f.as(tx=>sql`insert into public.outbox(tenant_id,id,event_type,resource_id,resource_version,payload) values(${f.tenant}::uuid,${randomUUID()}::uuid,'reference.published',${randomUUID()},1,'{}'::jsonb)`.execute(tx)),stateCode('42501'));
});

test('reference independent quorum publishes exact version one bundle, value projection and paired journals only after ready',async t=>{
 const f=await fixture(t),p=f.proposal();await f.as(tx=>proposeReferenceRelease(tx,f.principal(),p,randomUUID(),'reference-native'));
 assert.equal((await f.state()).reference_sets.length,0);await f.unchanged(()=>f.publish(p.id),stateCode('40001'));
 await f.decide(p.id);assert.equal((await f.tick(p.id)).status,'pending');assert.equal((await f.state()).reference_releases.length,0);
 await f.decide(p.id,f.second);assert.equal((await f.tick(p.id)).status,'ready');await f.unchanged(()=>f.publish(p.id,f.reviewer),stateCode('42501'));
 const result=await f.publish(p.id),view=await f.as(tx=>getReferenceRelease(tx,f.principal(),p.setId,1)),normalized=good(parseProposal(p,f.actor));
 const payload={formatVersion:1 as const,kind:'reference-publication' as const,setId:p.setId,expectedVersion:0,audience:normalized.audience,release:normalized.release};
 assert.deepEqual(view.release,JSON.parse(JSON.stringify(good(preparePublication({payload,publishedAt:result.publishedAt,previous:null,previousAudience:null})))));
 assert.deepEqual(result,{binding:'reference.publish',setId:p.setId,version:1,publicationHash:hash(view.release),publishedAt:view.release.publishedAt,effectiveFrom:view.release.effectiveFrom});
 assert.equal(view.publicationHash,good(publicationHash(view.release)));assert.deepEqual(view.release.values.map(v=>v.code),['001','A','a']);
 const stored=await f.state();assert.equal(stored.reference_sets.length,1);assert.equal(stored.reference_releases.length,1);assert.equal(stored.reference_values.length,3);
 const values=stored.reference_values.map(r=>({code:r.code,labels:r.labels,ownerId:r.owner_id,status:r.status,validFrom:r.valid_from?.toISOString()??null,validUntil:r.valid_until?.toISOString()??null})).sort((a,b)=>a.code<b.code?-1:1);
 assert.deepEqual(values,view.release.values);assert.equal((await f.request(p.id)).row.status,'succeeded');assert.deepEqual((await f.request(p.id)).row.result,result);
 const audits=stored.audit.filter(r=>r.action.startsWith('reference.')||r.action.startsWith('approval.')),events=stored.outbox.filter(r=>r.event_type.startsWith('reference.')||r.event_type.startsWith('approval.'));
 assert.deepEqual(audits.map(r=>r.id).sort(),events.map(r=>r.id).sort());assert.equal(audits.filter(r=>r.action==='reference.published').length,1);
});

test('reference self review, duplicate assignees, rejection and cancellation never produce a release',async t=>{
 const f=await fixture(t);
 for(const assignments of [{first:f.actor,second:f.second},{first:f.reviewer,second:f.reviewer}])await f.unchanged(()=>f.command(f.proposal({assignments})),stateCode('42501'));
 const rejected=f.proposal();await f.command(rejected);await f.decide(rejected.id,f.reviewer,'reject');assert.equal((await f.tick(rejected.id)).status,'rejected');await f.unchanged(()=>f.publish(rejected.id),stateCode('40001'));
 const cancelled=f.proposal();await f.command(cancelled);const row=(await f.request(cancelled.id)).row;await f.approval('approval.cancel',{requestId:cancelled.id,proposalDigest:row.proposal_digest,reason:'Withdraw proposed reference release'});
 assert.equal((await f.tick(cancelled.id)).status,'cancelled');await f.unchanged(()=>f.publish(cancelled.id),stateCode('40001'));assert.equal((await f.state()).reference_releases.length,0);
});

test('reference review retains its immutable workflow quorum after a new workflow head is published',async t=>{
 const f=await fixture(t),p=f.proposal();await f.command(p);const original=await f.request(p.id);
 await f.approval('approval.definition.publish',{definition:{...f.definition(2),stages:[{...f.definition(2).stages[0],quorum:1}]},expectedVersion:1});
 await f.decide(p.id);assert.equal((await f.tick(p.id)).status,'pending');await f.decide(p.id,f.second);assert.equal((await f.tick(p.id)).status,'ready');await f.publish(p.id);
 const final=await f.request(p.id);assert.equal(final.row.workflow_version,1);assert.equal(final.row.workflow_hash,f.workflow.definitionHash);
 assert.deepEqual(final.tasks.map(r=>[r.id,r.assignment,r.assigned_identity_id]),original.tasks.map(r=>[r.id,r.assignment,r.assigned_identity_id]));
});

test('reference exact proposal and publication retries survive head drift but never revoked current write authority',async t=>{
 const f=await fixture(t),p=f.proposal(),key=randomUUID(),receipt=await f.command(p,key);await f.decide(p.id);await f.decide(p.id,f.second);await f.tick(p.id);const published=await f.publish(p.id);
 await f.complete(f.proposal({setId:p.setId,expectedVersion:1,release:{...release(f.actor),labels:labels('Second')}}));const before=await f.state();
 assert.deepEqual(await f.command(p,key),receipt);assert.deepEqual(await f.publish(p.id),published);assert.deepEqual(await f.state(),before);
 await f.unchanged(()=>f.command({...p,release:{...p.release,labels:labels('Different')}},key),stateCode('40001'));
 await f.revoke(f.actor,permissions.filter(x=>x!=='reference:write'));
 await f.unchanged(()=>f.command(p,key),stateCode('42501'));await f.unchanged(()=>f.publish(p.id),stateCode('42501'));
});

test('reference final publication rechecks requester, independent reviewers and every active owner',async t=>{
 for(const changed of ['requester','reviewer','owner'] as const){const f=await fixture(t),p=f.proposal({release:{...release(f.actor),values:release(f.actor).values.map(v=>({...v,ownerId:f.reader}))}});await f.ready(p);
  if(changed==='requester')await f.revoke(f.actor,permissions.filter(v=>v!=='reference:write'));
  if(changed==='reviewer')await f.revoke(f.reviewer,permissions.filter(v=>v!=='reference:approve'));
  if(changed==='owner')await f.ownerTx(()=>f.owner.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.reader]));
  await f.unchanged(()=>f.publish(p.id),stateCode(changed==='owner'?'40001':'42501'));assert.equal((await f.state()).reference_releases.length,0);
 }
});

test('reference reads and downloads hide foreign or restricted releases and recheck current read permissions',async t=>{
 const f=await fixture(t),audience:Audience={visibility:'restricted',allowedIdentityIds:[f.actor,f.reviewer,f.second].sort()},ids=[randomUUID(),randomUUID(),randomUUID()].sort(),done=await f.complete(f.proposal({setId:ids[0],audience}));
 const missing=randomUUID();for(const id of [done.proposal.setId,missing]){
  await f.unchanged(()=>f.as(tx=>getReferenceRelease(tx,f.principal(f.reader),id,1),f.reader),problem(404));
  await f.unchanged(()=>f.as(tx=>downloadReferenceRelease(tx,f.principal(f.reader),id,1,'json'),f.reader),problem(404));}
 await f.unchanged(()=>f.as(tx=>getReferenceRelease(tx,f.principal(f.outsider,f.foreign),done.proposal.setId,1),f.outsider,f.foreign),problem(404));
 assert.deepEqual(await f.as(tx=>listReferenceSets(tx,f.principal(f.reader)),f.reader),{items:[],nextCursor:null});
 await f.complete(f.proposal({setId:ids[1],audience}));await f.complete(f.proposal({setId:ids[2]}));
 const visiblePage=await f.as(tx=>listReferenceSets(tx,f.principal(f.reader),{limit:1}),f.reader);assert.deepEqual(visiblePage.items.map(x=>x.id),[ids[2]],'Audience predicate runs before LIMIT+1, even with two earlier hidden sets');assert.equal(visiblePage.nextCursor,null);
 const downloaded=await f.as(tx=>downloadReferenceRelease(tx,f.principal(),done.proposal.setId,1,'json'));assert.ok(downloaded.etag);
 await f.revoke(f.actor,permissions.filter(v=>v!=='reference:read'));
 await f.unchanged(()=>f.as(tx=>downloadReferenceRelease(tx,f.principal(),done.proposal.setId,1,'json')),problem(403));
 await f.unchanged(()=>f.command(f.proposal()),stateCode('42501'));
});

test('reference scheduled first release succeeds now while effective reads remain empty and exact versions downloadable',async t=>{
 const f=await fixture(t),scheduled=new Date(Date.parse(await f.now())+3600000).toISOString(),done=await f.complete(f.proposal({release:{...release(f.actor),activation:{kind:'at',at:scheduled}}}));
 const view=await f.as(tx=>getReferenceEffective(tx,f.principal(),done.proposal.setId));assert.equal(view.selection.phase,'NOT_EFFECTIVE');assert.equal(view.selection.version,null);assert.deepEqual(view.items,[]);
 assert.equal(done.result.effectiveFrom,scheduled);assert.equal((await f.request(done.proposal.id)).row.status,'succeeded');
 const download=await f.as(tx=>downloadReferenceRelease(tx,f.principal(),done.proposal.setId,1,'json'));assert.deepEqual(JSON.parse(download.body),done.view.release);
 await f.unchanged(()=>f.as(tx=>getReferenceEffective(tx,f.principal(),done.proposal.setId,{asOf:scheduled})),problem(400));
});

test('reference historical selection and exact half-open effective boundaries never revive an expired predecessor',async t=>{
 const f=await fixture(t),first=await f.complete(),historical=await f.now(),old=await f.as(tx=>getReferenceEffective(tx,f.principal(),first.proposal.setId,{asOf:historical}));
 await f.waitUntil(new Date(Date.parse(historical)+1).toISOString());
 const start=new Date(Date.parse(historical)+6000).toISOString(),end=new Date(Date.parse(start)+250).toISOString();
 const next=f.proposal({setId:first.proposal.setId,expectedVersion:1,release:{...release(f.actor),activation:{kind:'at',at:start},validUntil:end,values:[{...release(f.actor).values[0],code:'BEFORE',validUntil:start},{...release(f.actor).values[0],code:'AT',validFrom:start}]}});
 const second=await f.complete(next);assert.ok(second.result.publishedAt>historical);
 assert.deepEqual((await f.as(tx=>getReferenceEffective(tx,f.principal(),first.proposal.setId,{asOf:historical}))).selection,old.selection,'Later publication cannot change prior logical history');
 await f.waitUntil(start);
 const justBefore=new Date(Date.parse(start)-1).toISOString(),before=await f.as(tx=>getReferenceEffective(tx,f.principal(),first.proposal.setId,{asOf:justBefore})),at=await f.as(tx=>getReferenceEffective(tx,f.principal(),first.proposal.setId,{asOf:start}));
 assert.equal(before.selection.version,1);assert.equal(before.selection.effectiveUntil,start);assert.equal(at.selection.version,2);assert.deepEqual(at.items.map(v=>v.code),['AT']);
 await f.waitUntil(end);const expired=await f.as(tx=>getReferenceEffective(tx,f.principal(),first.proposal.setId,{asOf:end}));assert.equal(expired.selection.phase,'EXPIRED');assert.equal(expired.selection.version,2);assert.deepEqual(expired.items,[]);
 assert.equal((await f.as(tx=>getReferenceRelease(tx,f.principal(),first.proposal.setId,1))).publicationHash,first.view.publicationHash);
});

test('reference competing reviewed proposals and elapsed scheduled publication refuse without partial effects',async t=>{
 const f=await fixture(t),one=f.proposal(),two=f.proposal({setId:one.setId});await f.ready(one);await f.ready(two);await f.publish(one.id);await f.unchanged(()=>f.publish(two.id),stateCode('40001'));
 const at=new Date(Date.parse(await f.now())+4000).toISOString(),elapsed=f.proposal({release:{...release(f.actor),activation:{kind:'at',at}}});await f.ready(elapsed);await f.waitUntil(at);await f.unchanged(()=>f.publish(elapsed.id),stateCode('40001'));
});

test('reference scheduled head cannot be silently reordered and published audience is immutable',async t=>{
 const f=await fixture(t),start=new Date(Date.parse(await f.now())+3600000).toISOString(),first=await f.complete(f.proposal({release:{...release(f.actor),activation:{kind:'at',at:start}}}));
 const immediate=f.proposal({setId:first.proposal.setId,expectedVersion:1});await f.ready(immediate);await f.unchanged(()=>f.publish(immediate.id),stateCode('40001'));
 await f.unchanged(()=>f.command(f.proposal({setId:first.proposal.setId,expectedVersion:1,audience:{visibility:'restricted',allowedIdentityIds:[f.actor,f.reviewer,f.second].sort()}})),stateCode('40001'));
 const context=await f.as(tx=>getReferenceAuthoringContext(tx,f.principal(),first.proposal.setId));assert.equal(context.latestPublishedVersion,1);assert.deepEqual(context.audience,first.proposal.audience);
});

test('reference signed value cursors bind actor, tenant, set, limit and resolved immutable time across new publications',async t=>{
 const f=await fixture(t),first=await f.complete(),page=await f.as(tx=>getReferenceEffective(tx,f.principal(),first.proposal.setId,{limit:1}));assert.equal(page.items.length,1);assert.ok(page.nextCursor);
 await f.complete(f.proposal({setId:first.proposal.setId,expectedVersion:1,release:{...release(f.actor),values:[{...release(f.actor).values[0],code:'NEW'}]}}));
 const second=await f.as(tx=>getReferenceEffective(tx,f.principal(),first.proposal.setId,{limit:1,cursor:page.nextCursor!}));assert.equal(second.selection.version,1);assert.equal(second.selection.asOf,page.selection.asOf);assert.equal(second.items[0].code,'A');
 for(const query of [{limit:2,cursor:page.nextCursor!},{limit:1,cursor:page.nextCursor!+'x'},{limit:1,cursor:page.nextCursor!,asOf:new Date(Date.parse(page.selection.asOf)-1).toISOString()}])await f.unchanged(()=>f.as(tx=>getReferenceEffective(tx,f.principal(),first.proposal.setId,query)),problem(400));
 await f.unchanged(()=>f.as(tx=>getReferenceEffective(tx,f.principal(f.reader),first.proposal.setId,{limit:1,cursor:page.nextCursor!}),f.reader),problem(400));
 await f.unchanged(()=>f.as(tx=>getReferenceEffective(tx,f.principal(f.outsider,f.foreign),first.proposal.setId,{limit:1,cursor:page.nextCursor!}),f.outsider,f.foreign),problem(400));
 await f.unchanged(()=>f.as(tx=>getReferenceEffective(tx,f.principal(),randomUUID(),{limit:1,cursor:page.nextCursor!})),problem(400));
 const history=await f.as(tx=>listReferenceReleases(tx,f.principal(),first.proposal.setId,{limit:1}));assert.equal(history.items[0].version,1);assert.ok(history.nextCursor);assert.equal((await f.as(tx=>listReferenceReleases(tx,f.principal(),first.proposal.setId,{limit:1,cursor:history.nextCursor!}))).items[0].version,2);
});

test('reference exact JSON and RFC4180 CSV downloads retain all256 codes and representation-specific ETags',async t=>{
 const f=await fixture(t),r=release(f.actor);const done=await f.complete(f.proposal({release:{...r,labels:labels('=SUM(A1:A2)'),values:Array.from({length:256},(_,i)=>({...r.values[0],code:String(i).padStart(3,'0'),status:i%2?'active':'deprecated',labels:{en:{label:'Comma, "quote"',description:'First\r\nSecond'},ar:labels().ar},validUntil:i===0?'2000-01-01T00:00:00.000Z':null}))}}));
 const json=await f.as(tx=>downloadReferenceRelease(tx,f.principal(),done.proposal.setId,1,'json')),csv=await f.as(tx=>downloadReferenceRelease(tx,f.principal(),done.proposal.setId,1,'csv'));
 assert.deepEqual(JSON.parse(json.body),done.view.release);assert.deepEqual(csvBundle(csv.body),done.view.release);assert.equal(csvRows(csv.body).length,257);assert.equal(done.view.release.values[0].code,'000');
 assert.notEqual(json.etag,csv.etag);assert.equal(json.byteLength,Buffer.byteLength(json.body));assert.equal(csv.byteLength,Buffer.byteLength(csv.body));assert.equal(hash(JSON.parse(json.body)),done.view.publicationHash);
 assert.equal((await f.as(tx=>downloadReferenceRelease(tx,f.principal(),done.proposal.setId,1,'csv'))).etag,csv.etag);
 const effective=await f.as(tx=>getReferenceEffective(tx,f.principal(),done.proposal.setId,{limit:100}));assert.equal(effective.items.length,100);assert.ok(effective.nextCursor);assert.equal(effective.items[0].code,'001');
});

test('reference forced rollback after protected publication removes all paired data, success, journals and receipts',async t=>{
 const f=await fixture(t),p=f.proposal();await f.ready(p);const rollback=new Error('Synthetic rollback after complete publication');
 await f.unchanged(()=>f.as(async tx=>{const result=(await sql<{value:any}>`select public.gc_reference_publish(${p.id}::uuid) as value`.execute(tx)).rows[0].value;assert.equal(result.version,1);await sql`set constraints all immediate`.execute(tx);throw rollback;}),e=>e===rollback);
 assert.equal((await f.request(p.id)).row.status,'ready');await f.publish(p.id);assert.equal((await f.state()).reference_releases.length,1);
});

test('reference early constraint flush cannot admit a late value into a just-sealed publication',async t=>{
 const f=await fixture(t),p=f.proposal();await f.ready(p);let sealed=false;
 await f.unchanged(()=>f.ownerTx(async()=>{const result=(await f.owner.query('SELECT public.gc_reference_publish($1::uuid) AS value',[p.id])).rows[0].value;assert.equal(result.version,1);await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');sealed=true;
  await f.owner.query("INSERT INTO reference_values(tenant_id,set_id,version,code,labels,owner_id,status,valid_from,valid_until) VALUES($1,$2,1,'LATE',$3::jsonb,$4,'active',NULL,NULL)",[f.tenant,p.setId,JSON.stringify(labels()),f.actor]);
 }),guarded);assert.equal(sealed,true,'The test must reach the successful early constraint flush');assert.equal((await f.request(p.id)).row.status,'ready');
});

test('reference committed projection rejects owner late insert, mutation and head tampering without changing history',async t=>{
 const f=await fixture(t),done=await f.complete();
 await f.unchanged(()=>f.ownerTx(()=>f.owner.query("INSERT INTO reference_values(tenant_id,set_id,version,code,labels,owner_id,status) VALUES($1,$2,1,'LATE',$3::jsonb,$4,'active')",[f.tenant,done.proposal.setId,JSON.stringify(labels()),f.actor])),guarded);
 await f.unchanged(()=>f.ownerTx(()=>f.owner.query('UPDATE reference_values SET labels=labels WHERE tenant_id=$1 AND set_id=$2',[f.tenant,done.proposal.setId])),stateCode('P0001'));
 await f.unchanged(()=>f.ownerTx(()=>f.owner.query('UPDATE reference_sets SET current_version=current_version+2 WHERE tenant_id=$1 AND id=$2',[f.tenant,done.proposal.setId])),stateCode('42501'));
});


test('reference failed publication recording requires site actor, a closed code and the exact ready version',async t=>{
 const f=await fixture(t),p=f.proposal(),ready=await f.ready(p);
 const fail=(who:string,version:number,reason:string|null)=>f.as(tx=>sql`select public.gc_reference_fail(${p.id}::uuid,${version},${reason})`.execute(tx),who);
 await f.unchanged(()=>fail(f.actor,ready.version,'REFERENCE_PRECONDITIONS_CHANGED'),stateCode('42501'));
 for(const reason of [null,'arbitrary private detail'])await f.unchanged(()=>fail('site:local',ready.version,reason),stateCode('42501'));
 const before=await f.state();await fail('site:local',ready.version+1,'REFERENCE_PRECONDITIONS_CHANGED');assert.deepEqual(await f.state(),before);
 await fail('site:local',ready.version,'REFERENCE_PRECONDITIONS_CHANGED');const current=await f.request(p.id);assert.equal(current.row.status,'failed');assert.equal(current.row.error_code,'REFERENCE_PRECONDITIONS_CHANGED');
 const sealed=await f.state();assert.equal(sealed.reference_releases.length,0);assert.equal(sealed.audit.filter(r=>r.action==='approval.failed').length,1);assert.equal(sealed.outbox.filter(r=>r.event_type==='approval.failed').length,1);
 await fail('site:local',ready.version,'REFERENCE_PRECONDITIONS_CHANGED');assert.deepEqual(await f.state(),sealed);assert.equal((await f.tick(p.id)).status,'failed');await f.unchanged(()=>f.publish(p.id),stateCode('40001'));
});
