// SPDX-License-Identifier: Apache-2.0
/** Native SQL001–017 scope qualification. Synthetic subjects, real production services,
 * Copied fixture setup from immutable514ddee scope test; no production assertion is replaced. */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import test,{type TestContext} from 'node:test';
import pg from 'pg';
import {Kysely,PostgresDialect} from 'kysely';
import {lockTenantLedger,sql,type Tx} from '../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../packages/authz/src/index.ts';
import {assetView,record,once} from '../../apps/api/src/repository.ts';
import {glossaryStarterType} from '../../packages/domain/src/glossary.ts';
import {submitGlossaryProposal,type GlossaryProposalInput} from '../../packages/domain/src/glossary-service.ts';
import {publishApprovedGlossary,getGlossaryTerm,type GlossaryPublicationHooks} from '../../packages/domain/src/glossary-publication-service.ts';
import type {GlossaryPublicationInput,GlossaryLink} from '../../packages/domain/src/glossary-contracts.ts';
import {createAssetType,previewAssetType,publishAssetType,transitionAssetTypeState} from '../../packages/domain/src/asset-type-service.ts';
import type {AssetTypeDefinition} from '../../packages/domain/src/asset-type.ts';
import {configureRelationTransaction,createRelationType,createRelation} from '../../packages/domain/src/relation-service.ts';
import type {RelationTypeDefinition,RelationTypeDefinitionV2} from '../../packages/domain/src/relation-contracts.ts';
import {prepareRelationType,previewRelationMigration,executeRelationMigration} from '../../packages/domain/src/relation-migration-service.ts';
import {assignAssetModel} from '../../packages/domain/src/model-service.ts';
import {captureRelationMigration,graphRequest} from '../../packages/domain/src/relation-migration-store.ts';
import type {GraphChangeSet,RelationMigrationContextRequest} from '../../packages/domain/src/relation-migration-contracts.ts';
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
export async function fixture(t:TestContext){
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
 return {owner,tenant,author,reviewer,second,reader,principal,as,type,term,workflowDefinition,publication,input,ready,publish,makeTerm,relationDefinition,relation,link,state,revoke,reject};
}

export type Fixture=Awaited<ReturnType<typeof fixture>>;
export const plainType=(id:string):AssetTypeDefinition=>({formatVersion:1,id,version:1,parents:[],attributes:{},overrideAttributes:[],requiredOwner:false,
 lifecycle:{initial:'active',states:['active','inactive'],transitions:[{from:'active',to:'inactive'}]}});
export async function asset(f:Fixture,type:TypeView|null,actor=f.author,hidden=false){
 return f.as(async tx=>{
  await lockTenantLedger(tx,f.tenant);const id=randomUUID();
  const row=await tx.insertInto('assets').values({tenant_id:f.tenant,id,external_id:id,name:'Synthetic scope asset',qualified_name:`synthetic.scope.${id}`,type:'dataset',
   owner_id:f.second,observed_at:new Date(),visibility:hidden?'restricted':'tenant',allowed_identities:JSON.stringify(hidden?[actor]:[])}).returningAll().executeTakeFirstOrThrow();
  await tx.insertInto('asset_revisions').values({tenant_id:f.tenant,asset_id:id,version:row.version,snapshot:JSON.stringify(assetView(row))}).execute();
  const assigned=type?await assignAssetModel(tx,f.principal(actor),randomUUID(),id,1,{modelId:type.id,modelVersion:type.version,attributes:{}},hooks):null;
  return {id,version:assigned?.assetVersion??1};
 },actor);
}
