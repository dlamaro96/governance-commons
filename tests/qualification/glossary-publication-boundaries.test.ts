// SPDX-License-Identifier: Apache-2.0
/** Hostile native SQL016 boundaries. These tests use the ordinary runtime role;
 * owner access only creates isolated synthetic tenants, identities and membership.
 * No imported test module, mocked DB, forged approval or raw business-term setup. */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import test,{type TestContext} from 'node:test';
import pg from 'pg';
import {Kysely,PostgresDialect} from 'kysely';
import {sql,type Tx} from '../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../packages/authz/src/index.ts';
import {record,once,assetView} from '../../apps/api/src/repository.ts';
import {glossaryStarterType} from '../../packages/domain/src/glossary.ts';
import {createAssetType} from '../../packages/domain/src/asset-type-service.ts';
import {createRelationType,tombstoneRelation} from '../../packages/domain/src/relation-service.ts';
import {publishApprovalDefinition,decideApprovalTask,tickApproval} from '../../packages/domain/src/approval-service.ts';
import {submitGlossaryProposal,type GlossaryProposalInput} from '../../packages/domain/src/glossary-service.ts';
import {publishApprovedGlossary,type GlossaryPublicationHooks} from '../../packages/domain/src/glossary-publication-service.ts';
import {configureRelationTransaction} from '../../packages/domain/src/relation-store.ts';
import type {GlossaryPublicationInput} from '../../packages/domain/src/glossary-contracts.ts';

const config=JSON.parse(readFileSync(process.env.AUTHN_FOUNDATION_CONFIG!,'utf8')) as {owner:string;legacy:string};
process.env.SESSION_KEY=randomUUID()+randomUUID();
const permissions=['catalog:read','catalog:write','models:read','models:write','audit:read'];
const hooks:GlossaryPublicationHooks={record,assetSnapshot:assetView,once};
const denied=(status:number)=>(e:unknown)=>e instanceof Problem&&e.status===status;
const stateCode=(...codes:string[])=>(e:unknown)=>!!e&&typeof e==='object'&&'code'in e&&codes.includes(String(e.code));

async function fixture(t:TestContext){
 const owner=new pg.Client({connectionString:config.owner});
 const database=new Kysely<Record<string,any>>({dialect:new PostgresDialect({pool:new pg.Pool({connectionString:config.legacy,max:1,connectionTimeoutMillis:5000})})});
 t.after(async()=>{await database.destroy();await owner.end();});await owner.connect();
 const tenant=randomUUID(),author=randomUUID(),reviewer=randomUUID(),workflowId='boundary_'+randomUUID().replaceAll('-','');
 await owner.query('BEGIN');try{
  await owner.query('INSERT INTO tenants(id,name) VALUES($1,$2)',[tenant,'Synthetic glossary boundary tenant']);
  await owner.query("SELECT set_config('gc.tenant_id',$1,true)",[tenant]);
  for(const id of [author,reviewer]){
   await owner.query('INSERT INTO identities(id,issuer,subject,name) VALUES($1::uuid,$2,$1::uuid::text,$3)',[id,'https://glossary-boundary.invalid/owned','Synthetic boundary participant']);
   await owner.query('INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,$3,$4::jsonb)',[tenant,id,'synthetic',JSON.stringify(permissions)]);
  }
  await owner.query('COMMIT');
 }catch{await owner.query('ROLLBACK');throw new Error('Synthetic boundary fixture setup failed.');}
 const principal=(id=author):Principal=>({id,tenantId:tenant,name:'Synthetic boundary participant',permissions});
 const as=async<T>(fn:(tx:Tx)=>Promise<T>,actor:string=author):Promise<T>=>{
  try{return await database.transaction().execute(async tx=>{
   await sql`select set_config('gc.tenant_id',${tenant},true),set_config('gc.actor_id',${actor},true)`.execute(tx);
   await configureRelationTransaction(tx);return fn(tx);
  });}catch(error){
   // Keep native diagnostics closed: no SQL, payload, driver detail or cause.
   if(error instanceof Problem)throw new Problem(error.status,error.code,error.message,error.issues);
   const code=error&&typeof error==='object'&&'code'in error&&typeof error.code==='string'&&/^[0-9A-Z]{5}$/.test(error.code)?error.code:'NATIVE_FAILURE';
   throw Object.assign(new Error('Native glossary boundary refused the transaction.'),{code});
  }
 };
 const type=(await as(tx=>createAssetType(tx,principal(),randomUUID(),glossaryStarterType(),hooks))).type;
 const workflow=await as(tx=>publishApprovalDefinition(tx,principal(),{formatVersion:1,id:workflowId,version:1,name:'Boundary approval',separationOfDuties:true,
  stages:[{id:'review',name:'Review',assignments:['reviewer'],quorum:1,deadlineSeconds:3600,rejection:'any'}]},0,randomUUID(),'boundary-workflow'));
 const publication=(extra:Partial<GlossaryPublicationInput>={}):GlossaryPublicationInput=>({typePin:{typeId:type.typeId,modelId:type.id,version:type.version,definitionHash:type.definitionHash,resolutionHash:type.resolutionHash},
  primaryLocale:'en',ownerId:reviewer,visibility:'tenant',allowedIdentityIds:[],state:'active',attributes:{translations:[{locale:'en',name:'Synthetic boundary term',definition:'A synthetic governed definition.',synonyms:[],abbreviations:[],examples:[]}]},links:[],...extra});
 const input=(extra:Partial<GlossaryProposalInput>={}):GlossaryProposalInput=>({requestId:randomUUID(),resourceId:randomUUID(),resourceVersion:null,publication:publication(),
  workflowPin:{id:workflowId,version:1,definitionHash:workflow.definitionHash},assignments:{reviewer},expiresAt:new Date(Date.now()+60000).toISOString(),...extra});
 const ready=async(value=input())=>{
  const {request}=await as(tx=>submitGlossaryProposal(tx,principal(),'boundary-submit',randomUUID(),value));
  assert.equal(request.tasks.length,1);const task=request.tasks[0];
  await as(tx=>decideApprovalTask(tx,principal(reviewer),request.id,{proposalDigest:request.proposalDigest,taskId:task.id,taskVersion:task.version,decision:'approve',reason:'Reviewed synthetic boundary.'},randomUUID(),'boundary-review'),reviewer);
  const current=await as(tx=>tickApproval(tx,request.id));assert.equal(current.status,'ready');
  const version=current.version;if(typeof version!=='number'||!Number.isInteger(version)||version<1)throw new Error('The native ready version was invalid.');return {value,version};
 };
 const publish=(value:GlossaryProposalInput)=>as(tx=>publishApprovedGlossary(tx,principal(),value.requestId,hooks));
 const makeTerm=async(extra:Partial<GlossaryPublicationInput>={})=>{const {value}=await ready(input({publication:publication(extra)}));return {value,result:await publish(value)};};
 const relation=async()=>(await as(tx=>createRelationType(tx,principal(),randomUUID(),{formatVersion:1,id:'boundary_links_'+randomUUID().replaceAll('-',''),version:1,label:'Boundary related',inverseLabel:'Boundary related',direction:'directed',
  sourceTypes:[{typeId:type.typeId,includeDescendants:true}],targetTypes:[{typeId:type.typeId,includeDescendants:true}],sourceStates:null,targetStates:null,
  cardinality:{outgoing:{min:0,max:null},incoming:{min:0,max:null}},allowSelf:false,cycles:'allow',attributes:{},requiredOwner:true,lifecycle:{initial:'active',states:['active'],transitions:[]}},hooks))).type;
 const tables=['assets','asset_revisions','relations','relation_revisions','relation_participations','relation_participation_revisions','glossary_terms','glossary_publications','glossary_publication_links',
  'approval_requests','approval_tasks','approval_decisions','approval_dispatch','relation_graph_operations','relation_graph_receipts','relation_graph_operation_type_claims','relation_graph_operation_asset_scope',
  'relation_graph_operation_asset_claims','relation_graph_operation_model_claims','relation_graph_operation_edge_claims','relation_graph_operation_binding_claims','relation_graph_operation_journal_claims','idempotency','audit','outbox'] as const;
 const state=async()=>{
  // Private graph claims are deliberately unreadable by gc_app. The fixture's
  // native owner performs only this exact tenant-scoped, read-only inspection;
  // every action under test still runs through the ordinary runtime connection.
  await owner.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try{
   await owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[tenant,author]);
   const result:Record<string,unknown[]>={};
   for(const table of tables){const {rows}=await owner.query('SELECT * FROM public."'+table+'" WHERE tenant_id=$1',[tenant]);result[table]=rows.sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));}
   await owner.query('COMMIT');return result;
  }catch{await owner.query('ROLLBACK');throw new Error('Native glossary boundary readback failed.');}
 };
 const unchanged=async(work:()=>Promise<unknown>,predicate:(e:unknown)=>boolean)=>{const before=await state();await assert.rejects(work,predicate);assert.deepEqual(await state(),before,'Refusal preserves all canonical, publication, graph, approval, journal and once rows');};
 return {tenant,author,reviewer,principal,as,publication,input,ready,publish,makeTerm,relation,state,unchanged};
}

test('native glossary boundaries deny sealed replay by another actor and another tenant without effects',async t=>{
 const a=await fixture(t),term=await a.makeTerm(),before=await a.state();
 await a.unchanged(()=>a.as(tx=>publishApprovedGlossary(tx,a.principal(a.reviewer),term.value.requestId,hooks),a.reviewer),denied(404));
 const b=await fixture(t);
 await b.unchanged(()=>b.as(tx=>publishApprovedGlossary(tx,b.principal(),term.value.requestId,hooks)),denied(404));
 assert.deepEqual(await a.state(),before);
});

test('native glossary boundaries reject generic service and raw DML edits of an owned relationship',async t=>{
 const f=await fixture(t),target=await f.makeTerm(),relation=await f.relation();
 const source=await f.makeTerm({links:[{kind:'related',typePin:{relationTypeId:relation.relationTypeId,version:relation.version,definitionHash:relation.definitionHash},targetAssetId:target.result.result.assetId,targetAssetVersion:1}]});
 const current=await f.state(),links=current.glossary_publication_links as Array<{publication_id:string;relation_id:string}>;
 const edge=links.find(row=>row.publication_id===source.value.requestId)!;assert.ok(edge);
 await f.unchanged(()=>f.as(tx=>tombstoneRelation(tx,f.principal(),'boundary-generic',edge.relation_id,1,hooks)),stateCode('42501'));
 await f.unchanged(()=>f.as(tx=>sql`update public.relations set updated_by=${f.author}::uuid where tenant_id=${f.tenant}::uuid and id=${edge.relation_id}::uuid`.execute(tx)),stateCode('42501'));
});

test('native glossary boundaries require a nonnull exact ready version and site actor for failure recording',async t=>{
 const f=await fixture(t),{value,version}=await f.ready();
 await f.unchanged(()=>f.as(tx=>sql`select public.gc_glossary_fail(${value.requestId}::uuid,null::integer,'GLOSSARY_INPUT_INVALID')`.execute(tx),'site:local'),stateCode('42501'));
 await f.unchanged(()=>f.as(tx=>sql`select public.gc_glossary_fail(${value.requestId}::uuid,${version}::integer,'GLOSSARY_INPUT_INVALID')`.execute(tx)),stateCode('42501'));
 const before=await f.state();
 await f.as(tx=>sql`select public.gc_glossary_fail(${value.requestId}::uuid,${version+1}::integer,'GLOSSARY_INPUT_INVALID')`.execute(tx),'site:local');
 assert.deepEqual(await f.state(),before,'Stale failure commands are no-ops and cannot relabel a current request');
});

test('native glossary boundaries refuse forged publication context actor and post-stage asset state',async t=>{
 const f=await fixture(t),{value}=await f.ready();
 const staged=async(tx:Tx)=>{await sql`select public.gc_glossary_prepare(${value.requestId}::uuid)`.execute(tx);await sql`select public.gc_glossary_stage(${value.requestId}::uuid)`.execute(tx);};
 await f.unchanged(()=>f.as(async tx=>{await sql`select public.gc_glossary_prepare(${value.requestId}::uuid)`.execute(tx);await sql`update public.glossary_publications set baseline='{}'::jsonb where tenant_id=${f.tenant}::uuid and id=${value.requestId}::uuid`.execute(tx);}),stateCode('42501'));
 await f.unchanged(()=>f.as(async tx=>{await staged(tx);await sql`select public.gc_glossary_graph_source_evidence(${randomUUID()}::uuid)`.execute(tx);}),stateCode('42501'));
 await f.unchanged(()=>f.as(async tx=>{await staged(tx);await sql`select set_config('gc.actor_id',${f.reviewer},true)`.execute(tx);await sql`select public.gc_glossary_graph_source_evidence(${value.requestId}::uuid)`.execute(tx);}),stateCode('42501'));
 await f.unchanged(()=>f.as(async tx=>{await staged(tx);await sql`update public.assets set metadata='{}'::jsonb where tenant_id=${f.tenant}::uuid and id=${value.resourceId}::uuid`.execute(tx);}),stateCode('42501'));
});

test('native glossary boundaries roll back normal deferred completion when approval expires after seal',async t=>{
 const f=await fixture(t),{value}=await f.ready(f.input({expiresAt:new Date(Date.now()+5000).toISOString()}));
 const before=await f.state();let sealed=false;
 await assert.rejects(()=>f.as(async tx=>{
  await sql`select public.gc_glossary_prepare(${value.requestId}::uuid)`.execute(tx);
  await sql`select public.gc_glossary_stage(${value.requestId}::uuid)`.execute(tx);
  const result=(await sql<{receipt:{id:string}}>`select public.gc_glossary_finish(${value.requestId}::uuid,null::uuid) as receipt`.execute(tx)).rows[0].receipt;
  assert.equal(result.id,value.requestId);sealed=true;
  // Actual wall-clock passage, without changing canonical expiry. This covers
  // normal deferred completion; SET CONSTRAINTS IMMEDIATE has different timing.
  await sql`select pg_sleep(greatest(0,extract(epoch from (${value.expiresAt}::timestamptz-clock_timestamp())))+0.05)`.execute(tx);
 }),stateCode('40001'));
 assert.equal(sealed,true,'The test must reach a sealed publication before expiry, not pass on earlier admission refusal');
 assert.deepEqual(await f.state(),before,'Expired completion leaves no term, revision, receipt, success audit or partial graph');
});
