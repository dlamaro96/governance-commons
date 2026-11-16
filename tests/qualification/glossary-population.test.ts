// SPDX-License-Identifier: Apache-2.0
/** Native multi-policy glossary population qualification. Synthetic subjects, real production services,
 * protected SQL writers and ordinary runtime privileges; no mocked repository. */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import test,{type TestContext} from 'node:test';
import pg from 'pg';
import {Kysely,PostgresDialect} from 'kysely';
import {sql,type Tx} from '../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../packages/authz/src/index.ts';
import {assetView,record,once} from '../../apps/api/src/repository.ts';
import {glossaryStarterType} from '../../packages/domain/src/glossary.ts';
import {submitGlossaryProposal,type GlossaryProposalInput} from '../../packages/domain/src/glossary-service.ts';
import {publishApprovedGlossary,getGlossaryTerm,type GlossaryPublicationHooks} from '../../packages/domain/src/glossary-publication-service.ts';
import type {GlossaryPublicationInput,GlossaryLink} from '../../packages/domain/src/glossary-contracts.ts';
import {createAssetType} from '../../packages/domain/src/asset-type-service.ts';
import type {AssetTypeDefinition} from '../../packages/domain/src/asset-type.ts';
import {configureRelationTransaction,createRelationType} from '../../packages/domain/src/relation-service.ts';
import type {RelationTypeDefinition} from '../../packages/domain/src/relation-contracts.ts';
import {publishApprovalDefinition,decideApprovalTask,tickApproval} from '../../packages/domain/src/approval-service.ts';
import type {ApprovalDefinition} from '../../packages/domain/src/approval-contracts.ts';

const config=JSON.parse(readFileSync(process.env.AUTHN_FOUNDATION_CONFIG!,'utf8')) as {owner:string;legacy:string};
process.env.SESSION_KEY=randomUUID()+randomUUID();
const permissions=['catalog:read','catalog:write','models:read','models:write','audit:read'];
const hooks:GlossaryPublicationHooks={record,assetSnapshot:assetView,once};
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
 return {owner,tenant,author,principal,as,type,term,publication,input,ready,publish,makeTerm,relation,link};
}

type Fixture=Awaited<ReturnType<typeof fixture>>;
async function persistedScope(f:Fixture,operationId:string){
 // Owner reads protected persisted output only after ordinary gc_app committed.
 // No role/permission changes, fabricated operation rows or trigger bypasses.
 await f.owner.query('BEGIN');try{
  await f.owner.query("SELECT set_config('gc.tenant_id',$1,true)",[f.tenant]);
  const result=await f.owner.query('SELECT asset_id,action FROM relation_graph_operation_asset_scope WHERE tenant_id=$1 AND operation_id=$2 ORDER BY asset_id',[f.tenant,operationId]);
  await f.owner.query('COMMIT');return result.rows as {asset_id:string;action:string}[];
 }catch(error){await f.owner.query('ROLLBACK');throw error;}
}
async function receiptAssetIds(f:Fixture,operationId:string){return f.as(async tx=>(await tx.selectFrom('relation_graph_receipt_assets').select('asset_id').where('operation_id','=',operationId).orderBy('asset_id').execute()).map(r=>r.asset_id as string));}

/** Real population outside the selected graph. Fixtures are inserted by the
 * migration owner with normal constraints/triggers and immutable revisions;
 * execution still uses the ordinary application role and original deadline. */
async function seedUnrelatedPopulation(f:Fixture,model:TypeView){
 await f.owner.query('BEGIN');try{
  await f.owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[f.tenant,f.author]);
  const inserted=await f.owner.query(`INSERT INTO assets(tenant_id,id,external_id,name,qualified_name,type,owner_id,observed_at,model_id,model_version,type_state)
   SELECT $1,gen_random_uuid(),'noise-'||n,'Synthetic unrelated asset','synthetic.unrelated.'||n,'dataset',$2,clock_timestamp(),
    CASE WHEN n<=5382 THEN $3 ELSE NULL END,CASE WHEN n<=5382 THEN 1 ELSE NULL END,CASE WHEN n<=5382 THEN 'active' ELSE NULL END
   FROM generate_series(1,11176) n RETURNING *`,[f.tenant,f.author,model.id]);
  const revisions=inserted.rows.map(row=>({asset_id:row.id,version:row.version,snapshot:assetView(row)}));
  await f.owner.query(`INSERT INTO asset_revisions(tenant_id,asset_id,version,snapshot)
   SELECT $1,x.asset_id,x.version,x.snapshot FROM jsonb_to_recordset($2::jsonb) AS x(asset_id uuid,version integer,snapshot jsonb)`,[f.tenant,JSON.stringify(revisions)]);
  await f.owner.query('COMMIT');return revisions.length;
 }catch(error){await f.owner.query('ROLLBACK');throw error;}
}

test('native glossary publication retains all twelve affected policies with 11176 unrelated assets within its original budget',async t=>{
 const f=await fixture(t),noise=await f.type({formatVersion:1,id:'population_noise',version:1,parents:[],attributes:{},overrideAttributes:[],requiredOwner:false,
  lifecycle:{initial:'active',states:['active'],transitions:[]}});
 assert.equal(await seedUnrelatedPopulation(f,noise),11176);
 // The target is created before the policies. All twelve policies then admit
 // the staged new business term, including eleven with no requested/live edge.
 const target=await f.makeTerm(),policies:RelationView[]=[];
 for(let index=0;index<12;index++)policies.push(await f.relation({id:`population_link_${index}`,label:`Synthetic relation ${index}`}));
 const typeIds=policies.map(p=>p.relationTypeId).sort();assert.equal(new Set(typeIds).size,12);
 const proposal=await f.ready(f.input({publication:f.publication({links:[f.link(policies[0],target)]})}));
 assert.equal((await f.as(tx=>tx.selectFrom('relations').select(sql<string>`count(*)::text`.as('count')).executeTakeFirstOrThrow())).count,'0');
 const started=performance.now(),result=await f.publish(proposal),elapsedMs=performance.now()-started;
 assert.equal(result.status,'succeeded');assert.ok(result.result.graphReceiptId);
 assert.ok(elapsedMs<30000,'Successful publication must retain the unchanged thirty-second transaction budget');
 const graphId=result.result.graphReceiptId!,assetIds=[target.id,proposal.resourceId].sort();
 const receipt=await f.as(tx=>tx.selectFrom('relation_graph_receipts').select('receipt').where('id','=',graphId).executeTakeFirstOrThrow());
 assert.deepEqual(receipt.receipt.before.heads.map((r:any)=>r.relationTypeId).sort(),typeIds);
 assert.deepEqual(receipt.receipt.after.heads.map((r:any)=>r.relationTypeId).sort(),typeIds);
 assert.deepEqual(receipt.receipt.targets.map((r:any)=>r.relationTypeId),[policies[0].relationTypeId]);
 assert.deepEqual(receipt.receipt.policies.map((r:any)=>r.relationTypeId).sort(),typeIds);
 assert.deepEqual(receipt.receipt.before.endpoints.map((r:any)=>r.assetId).sort(),assetIds);
 assert.deepEqual(receipt.receipt.after.endpoints.map((r:any)=>r.assetId).sort(),assetIds);
 assert.equal(receipt.receipt.before.edges.length,0);assert.equal(receipt.receipt.after.edges.length,1);
 assert.equal(receipt.receipt.after.edges[0].relationTypeId,policies[0].relationTypeId);
 assert.deepEqual(await receiptAssetIds(f,graphId),assetIds);
 assert.deepEqual((await persistedScope(f,graphId)).map(r=>r.asset_id),assetIds);
 const recordedTypes=await f.as(tx=>tx.selectFrom('relation_graph_receipt_types').select('relation_type_id').where('operation_id','=',graphId).orderBy('relation_type_id').execute());
 assert.deepEqual(recordedTypes.map(r=>r.relation_type_id),[policies[0].relationTypeId]);
 await f.owner.query('BEGIN');try{
  await f.owner.query("SELECT set_config('gc.tenant_id',$1,true)",[f.tenant]);
  const claims=(await f.owner.query('SELECT relation_type_id,mode FROM relation_graph_operation_type_claims WHERE tenant_id=$1 AND operation_id=$2 ORDER BY relation_type_id',[f.tenant,graphId])).rows;
  assert.deepEqual(claims,typeIds.map(relation_type_id=>({relation_type_id,mode:relation_type_id===policies[0].relationTypeId?'repair':'validation'})));
  assert.equal(claims.filter(r=>r.mode==='validation').length,11);await f.owner.query('COMMIT');
 }catch(error){await f.owner.query('ROLLBACK');throw error;}
 const publication=await f.as(tx=>tx.selectFrom('glossary_publications').select(['state','relation_type_ids']).where('id','=',proposal.requestId).executeTakeFirstOrThrow());
 assert.equal(publication.state,'sealed');assert.deepEqual(publication.relation_type_ids,typeIds);
 assert.equal((await f.as(tx=>getGlossaryTerm(tx,f.principal(),proposal.resourceId))).publication.links[0].targetAssetId,target.id);
 const state=()=>f.as(async tx=>({counts:(await sql<Record<string,string>>`select
  (select count(*)::text from assets where model_id=${noise.id}) as typed,
  (select count(*)::text from assets where model_id is null) as untyped,
  (select count(*)::text from relations where status='active') as edges,
  (select count(*)::text from relation_participations) as bindings,
  (select count(*)::text from relation_graph_receipts) as receipts,
  (select count(*)::text from audit) as audit,
  (select count(*)::text from outbox) as outbox,
  (select count(*)::text from idempotency) as idempotency,
  (select count(*)::text from asset_revisions) as revisions`.execute(tx)).rows[0],
  request:await tx.selectFrom('approval_requests').select(['status','version','result']).where('id','=',proposal.requestId).executeTakeFirstOrThrow(),
  asset:await tx.selectFrom('assets').select(['id','version','name']).where('id','=',proposal.resourceId).executeTakeFirstOrThrow()}));
 const beforeReplay=await state();assert.equal(beforeReplay.counts.typed,'5382');assert.equal(beforeReplay.counts.untyped,'5794');
 assert.equal(beforeReplay.counts.edges,'1');assert.equal(beforeReplay.counts.bindings,'0');assert.equal(beforeReplay.counts.receipts,'1');
 assert.equal(beforeReplay.request.status,'succeeded');assert.equal(beforeReplay.asset.version,1);
 const replayStarted=performance.now();assert.deepEqual(await f.publish(proposal),result);
 assert.deepEqual(await state(),beforeReplay,'Exact sealed replay leaves all canonical revisions, journals and graph receipts unchanged');
 assert.deepEqual((await f.as(tx=>tx.selectFrom('relation_graph_receipts').select('receipt').where('id','=',graphId).executeTakeFirstOrThrow())).receipt,receipt.receipt);
 t.diagnostic(JSON.stringify({population:11176,typed:5382,untyped:5794,affectedPolicies:12,publicationMs:Math.round(elapsedMs),replayMs:Math.round(performance.now()-replayStarted)}));
});
