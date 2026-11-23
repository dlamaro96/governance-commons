// SPDX-License-Identifier: Apache-2.0
/** Native SQL024 fixture candidate, only in an owned disposable database.
 * Uses real protected commands and independent approvals. No Temporal, HTTP/304,
 * browser, external source or source-validation execution is claimed. */
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import type {TestContext} from 'node:test';
import pg from 'pg';
import {Kysely,PostgresDialect} from 'kysely';
import {lockTenantLedger,sql,type Tx} from '../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../packages/authz/src/index.ts';
import {decideApprovalTask} from '../../packages/domain/src/approval-service.ts';
import {configureRelationTransaction} from '../../packages/domain/src/relation-store.ts';
import {parseRelease,parseProposal,proposalDigest,preparePublication,publicationHash} from '../../packages/domain/src/reference-data.ts';
import type {Audience,Labels,Proposal,PublishedBundle,ReleaseInput,Result} from '../../packages/domain/src/reference-data-contracts.ts';
import {listReferenceSets,getReferenceEffective,listReferenceReleases,getReferenceRelease,getReferenceAuthoringContext,downloadReferenceRelease,proposeReferenceRelease} from '../../packages/domain/src/reference-data-service.ts';

import type {StructureProposal,StructureDefinition,ReferenceReleasePin,HierarchyDefinition,CrosswalkDefinition} from '../../packages/domain/src/reference-structure-contracts.ts';

export const hierarchy=(ownerId:string,pin:ReferenceReleasePin):HierarchyDefinition=>({formatVersion:1,kind:'reference-hierarchy',labels:labels('Hierarchy'),ownerId,status:'active',activation:{kind:'on-publication'},validUntil:null,reference:pin,multiParent:'forbid',edges:[{parentCode:'A',childCode:'a',validFrom:null,validUntil:null}]});
export const crosswalk=(ownerId:string,source:ReferenceReleasePin,target:ReferenceReleasePin):CrosswalkDefinition=>({formatVersion:1,kind:'reference-crosswalk',labels:labels('Crosswalk'),ownerId,status:'active',activation:{kind:'on-publication'},validUntil:null,source,target,cardinality:'many-to-many',overlapPolicy:'reject-overlapping-pair',mappings:[{sourceCode:'A',targetCode:'a',relation:'equivalent',method:'steward-asserted',methodDetails:'Reviewed by steward',transformationNotes:'No executable transformation',confidence:{kind:'not-assessed'},validFrom:null,validUntil:null}]});

const configFile=process.env.AUTHN_FOUNDATION_CONFIG;
assert.ok(configFile,'AUTHN_FOUNDATION_CONFIG is required; no shared runtime fallback');
const config=JSON.parse(readFileSync(configFile,'utf8')) as {owner:string;legacy:string};
assert.equal(typeof config.owner,'string');assert.equal(typeof config.legacy,'string');
process.env.SESSION_KEY=randomUUID()+randomUUID();
const permissions=['catalog:read','catalog:write','models:read','models:write','reference:read','reference:write','reference:approve','audit:read'];
export const structureTables=['reference_structure_heads','reference_structure_releases','reference_hierarchy_edges','reference_crosswalk_mappings'] as const;
const tables=['reference_sets','reference_releases','reference_values',...structureTables] as const;
const snapshots=[...tables,'approval_requests','approval_tasks','approval_decisions','approval_dispatch','workflow_definitions','workflow_definition_versions','audit','outbox','idempotency'] as const;
export const stateCode=(expected:string)=>(e:unknown)=>!!e&&typeof e==='object'&&'code'in e&&e.code===expected;
export const problem=(status:number)=>(e:unknown)=>e instanceof Problem&&e.status===status;
export const guarded=(e:unknown)=>stateCode('42501')(e)||stateCode('23514')(e);
export function good<T>(result:Result<T>):T{assert.equal(result.ok,true,JSON.stringify(result));if(!result.ok)throw Error('Invalid fixture');return result.value;}
export function canonical(value:any):string{
 if(value instanceof Date)return JSON.stringify(value.toISOString());
 if(value===null||typeof value!=='object')return JSON.stringify(value);
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}';
}
export const hash=(value:unknown)=>createHash('sha256').update(canonical(value)).digest('hex');
export const labels=(name='State'):Labels=>({en:{label:name,description:'A complete reviewed reference snapshot.'},ar:{label:'الحالة',description:'قائمة مرجعية معتمدة.'}});
const release=(ownerId:string):ReleaseInput=>({formatVersion:1,kind:'reference-code-list',labels:labels(),ownerId,status:'active',activation:{kind:'on-publication'},validUntil:null,
 values:['a','001','A'].map(code=>({code,labels:labels('Value '+code),ownerId,status:'active',validFrom:null,validUntil:null}))});

export async function structureFixture(t:TestContext){
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
  return as(tx=>decideApprovalTask(tx,principal(who),id,{proposalDigest:current.row.proposal_digest,taskId:task.id,taskVersion:task.version,decision,reason:'Reviewed complete reference release'},randomUUID(),'structure-native'),who);};
 const tick=(id:string)=>as(async tx=>(await sql<{value:any}>`select public.gc_approval_tick(${id}::uuid) as value`.execute(tx)).rows[0].value,'site:local');
 const publish=(id:string,who=actor,scope=tenant)=>as(async tx=>(await sql<{value:any}>`select public.gc_reference_publish(${id}::uuid) as value`.execute(tx)).rows[0].value,who,scope);
 const ready=async(p:Proposal)=>{await command(p);await decide(p.id);await decide(p.id,second);const result=await tick(p.id);assert.equal(result.status,'ready');return result;};
 const complete=async(p=proposal())=>{await ready(p);const result=await publish(p.id);return {proposal:p,result,view:await as(tx=>getReferenceRelease(tx,principal(),p.setId,p.expectedVersion+1))};};
 const state=()=>ownerTx(async()=>{const result:Record<string,any[]>={};for(const table of snapshots)result[table]=(await owner.query('SELECT * FROM public."'+table+'" WHERE tenant_id=$1',[tenant])).rows.sort((a,b)=>canonical(a).localeCompare(canonical(b)));return result;});
 const unchanged=async(work:()=>Promise<unknown>,predicate:(e:unknown)=>boolean)=>{const before=await state();await assert.rejects(work,predicate);assert.deepEqual(await state(),before,'Refusal leaves canonical data, approval, history, journals and idempotency unchanged');};
 const revoke=(who:string,grants:string[])=>ownerTx(()=>owner.query('UPDATE memberships SET permissions=$3::jsonb WHERE tenant_id=$1 AND identity_id=$2',[tenant,who,JSON.stringify(grants)]));
 const now=async()=>String((await owner.query("SELECT public.gc_relation_utc(clock_timestamp()) AS value")).rows[0].value);
 const waitUntil=async(at:string)=>{const delay=Date.parse(at)-Date.parse(await now());assert.ok(delay<10000,'Fixture wait must stay bounded');await owner.query('SELECT pg_sleep(greatest(extract(epoch FROM $1::timestamptz-clock_timestamp()),0)+0.02)',[at]);};
 const structureCommand=(body:unknown,key=randomUUID(),who=actor,scope=tenant)=>as(async tx=>(await sql<{value:any}>`select public.gc_reference_structure_command('reference.structure.propose',${key},${JSON.stringify(body)}::jsonb,'structure-native') as value`.execute(tx)).rows[0].value,who,scope);
 const structurePublish=(id:string,who=actor,scope=tenant)=>as(async tx=>(await sql<{value:any}>`select public.gc_reference_structure_publish(${id}::uuid) as value`.execute(tx)).rows[0].value,who,scope);
 const structureReady=async(p:StructureProposal)=>{await structureCommand(p);await decide(p.id);await decide(p.id,second);const result=await tick(p.id);assert.equal(result.status,'ready');return result;};
 const structureProposal=(release:StructureDefinition,extra:Partial<StructureProposal>={}):StructureProposal=>({id:randomUUID(),structureId:randomUUID(),expectedVersion:0,release,workflow,assignments:{first:reviewer,second},expiresAt:new Date(Date.now()+3600000).toISOString(),...extra});
 const endpoint=async(extra:Partial<Proposal>={})=>{const done=await complete(proposal(extra));return {...done,pin:{setId:done.proposal.setId,version:done.view.release.version,publicationHash:done.view.publicationHash}};};
 return {structureCommand,structurePublish,structureReady,structureProposal,endpoint,owner,ownerTx,tenant,foreign,actor,reviewer,second,reader,outsider,principal,as,command,approval,workflow,definition,proposal,request,decide,tick,publish,ready,complete,state,unchanged,revoke,now,waitUntil};
}
