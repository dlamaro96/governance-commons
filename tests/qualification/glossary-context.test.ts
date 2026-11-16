// SPDX-License-Identifier: Apache-2.0
/** Native glossary context qualification against SQL001–016. Synthetic subjects, real production services,
 * protected SQL writers and ordinary runtime privileges; no mocked repository. */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import test,{type TestContext} from 'node:test';
import pg from 'pg';
import {Kysely,PostgresDialect} from 'kysely';
import {lockTenantLedger,sql,type Tx} from '../../packages/db/src/index.ts';
import {getAssetGlossaryContext,type GlossaryContextQuery} from '../../packages/domain/src/glossary-context.ts';
import {assignAssetModel} from '../../packages/domain/src/model-service.ts';
import {Problem,type Principal} from '../../packages/authz/src/index.ts';
import {assetView,record,once} from '../../apps/api/src/repository.ts';
import {glossaryStarterType} from '../../packages/domain/src/glossary.ts';
import {submitGlossaryProposal,type GlossaryProposalInput} from '../../packages/domain/src/glossary-service.ts';
import {publishApprovedGlossary,getGlossaryTerm,type GlossaryPublicationHooks} from '../../packages/domain/src/glossary-publication-service.ts';
import type {GlossaryPublicationInput,GlossaryLink} from '../../packages/domain/src/glossary-contracts.ts';
import {createAssetType,previewAssetType,publishAssetType} from '../../packages/domain/src/asset-type-service.ts';
import type {AssetTypeDefinition} from '../../packages/domain/src/asset-type.ts';
import {configureRelationTransaction,createRelationType,createRelation} from '../../packages/domain/src/relation-service.ts';
import type {RelationTypeDefinition,RelationTypeDefinitionV2} from '../../packages/domain/src/relation-contracts.ts';
import {prepareRelationType,previewRelationMigration,executeRelationMigration} from '../../packages/domain/src/relation-migration-service.ts';
import type {GraphChangeSet} from '../../packages/domain/src/relation-migration-contracts.ts';
import {getApprovalRequest,publishApprovalDefinition,decideApprovalTask,tickApproval} from '../../packages/domain/src/approval-service.ts';
import type {ApprovalDefinition} from '../../packages/domain/src/approval-contracts.ts';

const config=JSON.parse(readFileSync(process.env.AUTHN_FOUNDATION_CONFIG!,'utf8')) as {owner:string;legacy:string};
process.env.SESSION_KEY=randomUUID()+randomUUID();
const permissions=['catalog:read','catalog:write','models:read','models:write','audit:read'];
const hooks:GlossaryPublicationHooks={record,assetSnapshot:assetView,once};
const issue=(status:number)=>(e:unknown)=>e instanceof Problem&&e.status===status;
const sqlCode=(code:string)=>(e:unknown)=>!!e&&typeof e==='object'&&'code'in e&&e.code===code;
type TypeView=Awaited<ReturnType<typeof createAssetType>>['type'];
type RelationView=Awaited<ReturnType<typeof createRelationType>>['type'];
const typePin=(t:TypeView)=>({typeId:t.typeId,modelId:t.id,version:t.version,definitionHash:t.definitionHash,resolutionHash:t.resolutionHash});
const attributes=(name='Net revenue')=>({translations:[{locale:'en',name,definition:'Sales after approved adjustments.',synonyms:['Adjusted revenue'],abbreviations:['NR'],examples:['Synthetic quarterly revenue.']}]});
async function fixture(t:TestContext){
 const owner=new pg.Client({connectionString:config.owner});
 const store=new Kysely<Record<string,any>>({dialect:new PostgresDialect({pool:new pg.Pool({connectionString:config.legacy,max:1,connectionTimeoutMillis:5000})})});
 t.after(async()=>{await store.destroy();await owner.end();});await owner.connect();
 const tenant=randomUUID(),author=randomUUID(),reviewer=randomUUID(),second=randomUUID(),reader=randomUUID(),workflowId='publish_'+randomUUID().replaceAll('-','');
 await owner.query('BEGIN');try{
  await owner.query('INSERT INTO tenants(id,name) VALUES($1,$2)',[tenant,'Synthetic glossary publication']);
  for(const id of [author,reviewer,second,reader])await owner.query('INSERT INTO identities(id,issuer,subject,name) VALUES($1::uuid,$2,$1::uuid::text,$3)',[id,'https://glossary-publication.invalid/owned','Synthetic glossary participant']);
  await owner.query("SELECT set_config('gc.tenant_id',$1,true)",[tenant]);
  for(const id of [author,reviewer,second,reader])await owner.query('INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,$3,$4::jsonb)',[tenant,id,'synthetic',JSON.stringify(id===reader?['catalog:read','models:read']:permissions)]);
  await owner.query('COMMIT');
 }catch(e){await owner.query('ROLLBACK');throw e;}
 const principal=(id=author):Principal=>({id,tenantId:tenant,name:'Synthetic glossary participant',permissions:id===reader?['catalog:read','models:read']:permissions});
 const as=async<T>(fn:(tx:Tx)=>Promise<T>,actor=author):Promise<T>=>{
  try{return await store.transaction().execute(async tx=>{
   await sql`select set_config('gc.tenant_id',${tenant},true),set_config('gc.actor_id',${actor},true)`.execute(tx);
   await configureRelationTransaction(tx);return fn(tx);
  });}catch(error){
   // Never serialize a PostgreSQL error, SQL text, payload or driver detail.
   const codes=new Set<string>(),locations=new Set<string>(),missingTables=new Set<string>();let cause:unknown=error;
   for(let depth=0;depth<4&&cause&&typeof cause==='object';depth++){
    const e=cause as {code?:unknown;where?:unknown;message?:unknown;cause?:unknown};
    if(typeof e.code==='string'&&/^[0-9A-Z]{5}$/.test(e.code))codes.add(e.code);
    if(typeof e.where==='string')for(const match of e.where.slice(0,16384).matchAll(/PL\/pgSQL function (?:public\.)?(gc_[a-z0-9_]{1,96})\([^\n]{0,512}?\) line ([0-9]{1,6})/g))locations.add(`${match[1]}:${match[2]}`);
    if(typeof e.message==='string'){const missing=/^missing FROM-clause entry for table "([a-z_]{1,64})"$/.exec(e.message);if(missing)missingTables.add(missing[1]);}
    cause=e.cause;
   }
   t.diagnostic(JSON.stringify({sqlstates:[...codes].sort().slice(0,8),sqlLocations:[...locations].sort().slice(0,8),missingFromTables:[...missingTables].sort().slice(0,8)}));
   // Node's test error formatter may inspect even a non-enumerable Error.cause.
   // Preserve the production cause, but rethrow only its safe outer test shape.
   if(error instanceof Problem)throw new Problem(error.status,error.code,error.message,error.issues);
   throw Object.assign(new Error('Native glossary qualification failed.'),{code:[...codes][0]??'NATIVE_FAILURE'});
  }
 };
 const type=async(d:AssetTypeDefinition)=>(await as(tx=>createAssetType(tx,principal(),randomUUID(),d,hooks))).type;
 const term=await type(glossaryStarterType());
 const physical=await type({formatVersion:1,id:'physical_table',version:1,parents:[],attributes:{},overrideAttributes:[],requiredOwner:false,
  lifecycle:{initial:'active',states:['active'],transitions:[]}});
 const asset=async(options:{id?:string;restricted?:readonly string[]}={})=>as(async tx=>{
  await lockTenantLedger(tx,tenant);const id=options.id??randomUUID(),sourceId=randomUUID();
  await tx.insertInto('sources').values({tenant_id:tenant,id:sourceId,name:'Synthetic context source',host:'source.invalid',port:5432,database_name:'synthetic',schema_name:'public',secret_ref:'synthetic-unused'}).execute();
  const row=await tx.insertInto('assets').values({tenant_id:tenant,id,external_id:id,name:'Synthetic table',qualified_name:`synthetic.context.${id}`,type:'table',source_id:sourceId,
   owner_id:second,observed_at:new Date(),visibility:options.restricted?'restricted':'tenant',allowed_identities:JSON.stringify(options.restricted??[])}).returningAll().executeTakeFirstOrThrow();
  await tx.insertInto('asset_revisions').values({tenant_id:tenant,asset_id:id,version:row.version,snapshot:JSON.stringify(assetView(row))}).execute();
  const assigned=await assignAssetModel(tx,principal(),randomUUID(),id,1,{modelId:physical.id,modelVersion:physical.version,attributes:{}},hooks);
  return {id,version:assigned.assetVersion};
 });
 const workflowDefinition:ApprovalDefinition={formatVersion:1,id:workflowId,version:1,name:'Synthetic publication approval',separationOfDuties:true,
  stages:[{id:'review',name:'Review',assignments:['steward','owner'],quorum:2,deadlineSeconds:3600,rejection:'any'}]};
 const workflow=await as(tx=>publishApprovalDefinition(tx,principal(),workflowDefinition,0,randomUUID(),'synthetic-workflow'));
 const publication=(extra:Partial<GlossaryPublicationInput>={}):GlossaryPublicationInput=>({typePin:typePin(term),primaryLocale:'en',ownerId:second,
  visibility:'tenant',allowedIdentityIds:[],state:'active',attributes:attributes(),links:[],...extra});
 const input=(extra:Partial<GlossaryProposalInput>={}):GlossaryProposalInput=>({requestId:randomUUID(),resourceId:randomUUID(),resourceVersion:null,publication:publication(),
  workflowPin:{id:workflowId,version:1,definitionHash:workflow.definitionHash},assignments:{steward:reviewer,owner:second},expiresAt:new Date(Date.now()+7200000).toISOString(),...extra});
 const ready=async(value=input())=>{
  const {request}=await as(tx=>submitGlossaryProposal(tx,principal(),'synthetic-submit',randomUUID(),value));
  for(const actor of [reviewer,second]){
   const task=request.tasks.find(x=>x.assignedIdentityId===actor)!;
   await as(tx=>decideApprovalTask(tx,principal(actor),request.id,{proposalDigest:request.proposalDigest,taskId:task.id,taskVersion:task.version,decision:'approve',reason:'Reviewed synthetic publication.'},randomUUID(),'synthetic-review'),actor);
  }
  assert.equal((await as(tx=>tickApproval(tx,request.id))).status,'ready');return value;
 };
 const publish=(value:GlossaryProposalInput,selected=hooks)=>as(tx=>publishApprovedGlossary(tx,principal(),value.requestId,selected));
 const makeTerm=async(extra:Partial<GlossaryPublicationInput>={})=>{const proposal=await ready(input({publication:publication(extra)}));const result=await publish(proposal);return {id:result.result.assetId,version:result.result.assetVersion,proposal,result};};
 const relationDefinition=(extra:Partial<RelationTypeDefinition>={}):RelationTypeDefinition=>({formatVersion:1,id:'links_'+randomUUID().replaceAll('-',''),version:1,label:'Related term',inverseLabel:'Related term',direction:'directed',
  sourceTypes:[{typeId:term.typeId,includeDescendants:true}],targetTypes:[{typeId:term.typeId,includeDescendants:true}],sourceStates:null,targetStates:null,
  cardinality:{outgoing:{min:0,max:null},incoming:{min:0,max:null}},allowSelf:false,cycles:'allow',attributes:{},requiredOwner:true,
  lifecycle:{initial:'active',states:['active'],transitions:[]},...extra});
 const relation=async(extra:Partial<RelationTypeDefinition>={})=>(await as(tx=>createRelationType(tx,principal(),randomUUID(),relationDefinition(extra),hooks))).type;
 const link=(r:Pick<RelationView,'relationTypeId'|'version'|'definitionHash'>,a:{id:string;version:number}):GlossaryLink=>({kind:'related',typePin:{relationTypeId:r.relationTypeId,version:r.version,definitionHash:r.definitionHash},targetAssetId:a.id,targetAssetVersion:a.version});
 const state=()=>as(async tx=>({
  assets:await tx.selectFrom('assets').selectAll().orderBy('id').execute(),revisions:await tx.selectFrom('asset_revisions').selectAll().orderBy('asset_id').orderBy('version').execute(),
  edges:await tx.selectFrom('relations').selectAll().orderBy('id').execute(),edgeRevisions:await tx.selectFrom('relation_revisions').selectAll().orderBy('relation_id').orderBy('version').execute(),
  bindings:await tx.selectFrom('relation_participations').selectAll().orderBy('id').execute(),bindingRevisions:await tx.selectFrom('relation_participation_revisions').selectAll().orderBy('binding_id').orderBy('version').execute(),
  terms:await tx.selectFrom('glossary_terms').selectAll().orderBy('asset_id').execute(),publications:await tx.selectFrom('glossary_publications').selectAll().orderBy('id').execute(),links:await tx.selectFrom('glossary_publication_links').selectAll().orderBy('publication_id').orderBy('ordinal').execute(),
  requests:await tx.selectFrom('approval_requests').selectAll().orderBy('id').execute(),once:await tx.selectFrom('idempotency').selectAll().orderBy('operation').orderBy('key').execute(),
  audit:await tx.selectFrom('audit').selectAll().orderBy('sequence').execute(),outbox:await tx.selectFrom('outbox').selectAll().orderBy('id').execute(),
 }));
 const revoke=async(id:string)=>{await owner.query('BEGIN');try{await owner.query("SELECT set_config('gc.tenant_id',$1,true)",[tenant]);await owner.query("UPDATE memberships SET permissions='[\"catalog:read\",\"models:read\"]'::jsonb WHERE tenant_id=$1 AND identity_id=$2",[tenant,id]);await owner.query('COMMIT');}catch(e){await owner.query('ROLLBACK');throw e;}};
 const reject=async(value:GlossaryProposalInput,status:number)=>{const before=await state();await assert.rejects(()=>publish(value),issue(status));assert.deepEqual(await state(),before,'Failed publication rolls back canonical data, graph/history, request state, once, audit and outbox');};
 return {owner,tenant,author,reviewer,second,reader,principal,as,type,term,physical,asset,workflowDefinition,publication,input,ready,publish,makeTerm,relationDefinition,relation,link,state,revoke,reject};
}


const translation=(locale:string,name:string,definition:string)=>({locale,name,definition,synonyms:[],abbreviations:[],examples:[]});
const read=(f:Awaited<ReturnType<typeof fixture>>,id:string,query:GlossaryContextQuery={},actor=f.reader)=>
 f.as(tx=>getAssetGlossaryContext(tx,f.principal(actor),id,query),actor);
const defines=(f:Awaited<ReturnType<typeof fixture>>,r:RelationView,a:{id:string;version:number}):GlossaryLink=>({...f.link(r,a),kind:'defines'});
const physicalPolicy=(f:Awaited<ReturnType<typeof fixture>>,extra:Partial<RelationTypeDefinition>={})=>{
 const endpoints=[f.term.typeId,f.physical.typeId].sort().map(typeId=>({typeId,includeDescendants:true}));
 return f.relation({...extra.direction&&extra.direction==='undirected'?{sourceTypes:endpoints,targetTypes:endpoints}:{targetTypes:[{typeId:f.physical.typeId,includeDescendants:true}]},...extra});
};

test('native glossary context selects the requested translation or primary fallback without revealing a hidden sibling',async t=>{
 const f=await fixture(t),target=await f.asset(),hidden=await f.asset({restricted:[f.author,f.reviewer,f.second].sort()}),r=await physicalPolicy(f);
 const translations=[translation('en','Revenue','Approved sales definition.'),translation('ar','الإيرادات','تعريف المبيعات المعتمد.')];
 const term=await f.makeTerm({attributes:{translations},links:[defines(f,r,target),defines(f,r,hidden)]});
 await assert.rejects(()=>f.as(tx=>getGlossaryTerm(tx,f.principal(f.reader),term.id),f.reader),issue(404));
 const en=await read(f,target.id),ar=await read(f,target.id,{locale:'ar'}),fallback=await read(f,target.id,{locale:'fr-CA'});
 assert.deepEqual(Object.keys(en).sort(),['assetId','items','nextCursor']);assert.equal(en.nextCursor,null);assert.equal(en.items.length,1);
 assert.deepEqual(en.items[0],{termId:term.id,termVersion:1,relationId:en.items[0].relationId,locale:'en',name:translations[0].name,definition:translations[0].definition,state:'active'});
 assert.equal(ar.items[0].locale,'ar');assert.equal(ar.items[0].name,translations[1].name);assert.equal(ar.items[0].definition,translations[1].definition);
 assert.deepEqual(fallback.items,en.items);assert.equal(JSON.stringify(en).includes(hidden.id),false);assert.equal(JSON.stringify(en).includes(f.author),false);
 await assert.rejects(()=>read(f,hidden.id),issue(404));
 // A physical resource can acquire a newer canonical revision without changing
 // the approved link's historical endpoint observation or publication pin.
 const assigned=await f.as(tx=>assignAssetModel(tx,f.principal(),'context-target-revision',target.id,target.version,
  {modelId:f.physical.id,modelVersion:f.physical.version,attributes:{}},hooks));
 assert.equal(assigned.assetVersion,target.version+1);assert.deepEqual(await read(f,target.id),en);
});

test('native glossary context authorizes before UUID pagination and binds every cursor selector',async t=>{
 const f=await fixture(t),target=await f.asset(),other=await f.asset(),r=await physicalPolicy(f),ids:string[]=[];
 const hiddenId='00000001'+randomUUID().slice(8),hidden=await f.ready(f.input({resourceId:hiddenId,publication:f.publication({visibility:'restricted',allowedIdentityIds:[f.author,f.reviewer,f.second].sort(),links:[defines(f,r,target)]})}));
 await f.publish(hidden);
 for(let i=0;i<3;i++)ids.push((await f.makeTerm({links:[defines(f,r,target)]})).id);ids.sort();
 const first=await read(f,target.id,{limit:2});assert.deepEqual(first.items.map(x=>x.termId),ids.slice(0,2));assert.ok(first.nextCursor);
 const second=await read(f,target.id,{limit:2,cursor:first.nextCursor!});assert.deepEqual(second.items.map(x=>x.termId),ids.slice(2));assert.equal(second.nextCursor,null);
 for(const query of [{limit:1},{limit:2,locale:'ar'}])await assert.rejects(()=>read(f,target.id,{...query,cursor:first.nextCursor!}),issue(400));
 await assert.rejects(()=>read(f,other.id,{limit:2,cursor:first.nextCursor!}),issue(400));
 await assert.rejects(()=>read(f,target.id,{limit:2,cursor:first.nextCursor!},f.author),issue(400));
 for(const query of [{limit:0},{limit:26},{limit:1.5},{locale:'en-x-private'},{locale:'en_US'},{cursor:''},{cursor:'altered'}])await assert.rejects(()=>read(f,target.id,query),issue(400));
 assert.deepEqual((await read(f,other.id)).items,[]);
});

test('native glossary context follows only sealed current publications and removes superseded defines links',async t=>{
 const f=await fixture(t),target=await f.asset(),r=await physicalPolicy(f),term=await f.makeTerm({links:[defines(f,r,target)]});
 const longLocale='en-'+Array.from({length:24},(_,i)=>'a'+String(i).padStart(4,'0')).join('-');assert.equal(Intl.getCanonicalLocales(longLocale)[0],longLocale);
 const before=await read(f,target.id),amendment=await f.ready(f.input({resourceId:term.id,resourceVersion:1,publication:f.publication({primaryLocale:longLocale,attributes:{translations:[translation(longLocale,'Approved replacement','Approved definition.')]},links:[defines(f,r,target)]})}));
 assert.deepEqual(await read(f,target.id),before,'Ready proposals do not change published context');await f.publish(amendment);
 const updated=await read(f,target.id);assert.equal(updated.items[0].name,'Approved replacement');assert.equal(updated.items[0].termVersion,2);assert.equal(updated.items[0].locale,longLocale);assert.notEqual(updated.items[0].relationId,before.items[0].relationId);
 const removed=await f.ready(f.input({resourceId:term.id,resourceVersion:2,publication:f.publication({links:[]})}));await f.publish(removed);
 assert.deepEqual(await read(f,target.id),{assetId:target.id,items:[],nextCursor:null});
});

test('native glossary context accepts exactly pinned undirected defines orientation',async t=>{
 const f=await fixture(t),target=await f.asset({id:'00000001'+randomUUID().slice(8)}),r=await physicalPolicy(f,{direction:'undirected'});
 const termId='fffffffe'+randomUUID().slice(8),proposal=await f.ready(f.input({resourceId:termId,publication:f.publication({links:[defines(f,r,target)]})}));
 await f.publish(proposal);const page=await read(f,target.id);assert.equal(page.items.length,1);assert.equal(page.items[0].termId,termId);
 const edge=(await f.as(tx=>tx.selectFrom('relations').selectAll().where('id','=',page.items[0].relationId).executeTakeFirstOrThrow()));
 assert.equal(edge.source_asset_id,target.id);assert.equal(edge.target_asset_id,termId);
});

test('native glossary context refuses stale membership and hidden foreign or inactive requested resources',async t=>{
 const f=await fixture(t),target=await f.asset(),r=await physicalPolicy(f);await f.makeTerm({links:[defines(f,r,target)]});
 const inactive=await f.asset(),foreign=await fixture(t),other=await foreign.asset();await assert.rejects(()=>read(f,other.id),issue(404));await assert.rejects(()=>read(f,randomUUID()),issue(404));await assert.rejects(()=>read(f,'invalid'),issue(404));
 await f.owner.query('BEGIN');try{await f.owner.query("SELECT set_config('gc.tenant_id',$1,true)",[f.tenant]);await f.owner.query("UPDATE memberships SET permissions=$3::jsonb WHERE tenant_id=$1 AND identity_id=$2",[f.tenant,f.reader,JSON.stringify(["catalog:read"])]);await f.owner.query('COMMIT');}catch(e){await f.owner.query('ROLLBACK');throw e;}
 await assert.rejects(()=>read(f,target.id),issue(403));
 await f.as(async tx=>{await lockTenantLedger(tx,f.tenant);const row=await tx.updateTable('assets').set({status:'unavailable',version:inactive.version+1}).where('id','=',inactive.id).returningAll().executeTakeFirstOrThrow();
  await tx.insertInto('asset_revisions').values({tenant_id:f.tenant,asset_id:inactive.id,version:row.version,snapshot:JSON.stringify(assetView(row))}).execute();});
 await assert.rejects(()=>read(f,inactive.id,{},f.author),issue(404));
});

test('native glossary context refuses oversized complete pages before returning any partial summary',async t=>{
 const f=await fixture(t),target=await f.asset(),definition='界'.repeat(16384),termIds:string[]=[],policyIds:string[]=[];
 // Each genuine publication has an independent exact typed relation scope.
 // A single broad policy would charge every prior large term to every graph
 // operation and correctly hit that separate budget before the read is tested.
 for(let i=0;i<11;i++){
  const child=await f.type({formatVersion:1,id:`bounded_context_${i}`,version:1,parents:[{id:'business_term',version:1}],attributes:{},overrideAttributes:[],requiredOwner:false,lifecycle:null});
  const r=await physicalPolicy(f,{sourceTypes:[{typeId:child.typeId,includeDescendants:false}]});policyIds.push(r.relationTypeId);
  const term=await f.makeTerm({typePin:typePin(child),attributes:{translations:[translation('en',`Bounded term ${i}`,definition)]},links:[defines(f,r,target)]});termIds.push(term.id);
 }
 assert.equal(new Set(policyIds).size,11);termIds.sort();
 const admitted=await read(f,target.id,{limit:10});assert.deepEqual(admitted.items.map(item=>item.termId),termIds.slice(0,10));assert.ok(admitted.nextCursor);assert.ok(Buffer.byteLength(JSON.stringify(admitted))<=524288);
 const last=await read(f,target.id,{limit:10,cursor:admitted.nextCursor!});assert.deepEqual(last.items.map(item=>item.termId),termIds.slice(10));assert.equal(last.nextCursor,null);
 await assert.rejects(()=>read(f,target.id,{limit:11}),(error:unknown)=>error instanceof Problem&&error.status===422&&error.code==='GLOSSARY_CONTEXT_LIMIT');
});
