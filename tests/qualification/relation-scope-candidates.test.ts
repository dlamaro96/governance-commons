// SPDX-License-Identifier: Apache-2.0
/** Native SQL001–017 scope qualification. Synthetic subjects, real production services,
 * protected SQL writers and ordinary runtime privileges; no mocked repository. */
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

type Fixture=Awaited<ReturnType<typeof fixture>>;
const plainType=(id:string):AssetTypeDefinition=>({formatVersion:1,id,version:1,parents:[],attributes:{},overrideAttributes:[],requiredOwner:false,
 lifecycle:{initial:'active',states:['active','inactive'],transitions:[{from:'active',to:'inactive'}]}});
async function asset(f:Fixture,type:TypeView|null,actor=f.author,hidden=false){
 return f.as(async tx=>{
  await lockTenantLedger(tx,f.tenant);const id=randomUUID();
  const row=await tx.insertInto('assets').values({tenant_id:f.tenant,id,external_id:id,name:'Synthetic scope asset',qualified_name:`synthetic.scope.${id}`,type:'dataset',
   owner_id:f.second,observed_at:new Date(),visibility:hidden?'restricted':'tenant',allowed_identities:JSON.stringify(hidden?[actor]:[])}).returningAll().executeTakeFirstOrThrow();
  await tx.insertInto('asset_revisions').values({tenant_id:f.tenant,asset_id:id,version:row.version,snapshot:JSON.stringify(assetView(row))}).execute();
  const assigned=type?await assignAssetModel(tx,f.principal(actor),randomUUID(),id,1,{modelId:type.id,modelVersion:type.version,attributes:{}},hooks):null;
  return {id,version:assigned?.assetVersion??1};
 },actor);
}
const repair=(relationTypeId:string):RelationMigrationContextRequest=>({formatVersion:1,relationTargets:[{kind:'repair',relationTypeId,expectedHeadVersion:1,definition:null}],assetChanges:[],assetTypeMigrations:[],repairsReceiptId:null});
/** Independent SQL016 oracle: exact predicates over every tenant asset, with
 * no nominal CTE/type-head shortcut. Explicit and live incident arms remain
 * independent; compare IDs rather than just cardinality. */
async function exhaustive(f:Fixture,definitions:readonly unknown[],typeIds:readonly string[],explicit:readonly string[]=[]){
 return f.as(async tx=>(await sql<{id:string}>`select a.id from assets a where a.tenant_id=${f.tenant}::uuid and (
  a.id=any(${explicit}::uuid[]) or exists(select 1 from jsonb_array_elements(${JSON.stringify(definitions)}::jsonb) e(d)
   where public.gc_relation_endpoint_eligible(${f.tenant}::uuid,a.id,d,'source') or public.gc_relation_endpoint_eligible(${f.tenant}::uuid,a.id,d,'target'))
  or exists(select 1 from relations r where r.tenant_id=a.tenant_id and r.relation_type_id=any(${typeIds}::uuid[]) and r.status='active' and a.id in(r.source_asset_id,r.target_asset_id))
  or exists(select 1 from relation_participations b where b.tenant_id=a.tenant_id and b.relation_type_id=any(${typeIds}::uuid[]) and b.status='active' and b.asset_id=a.id)
 ) order by a.id`.execute(tx)).rows.map(r=>r.id));
}
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

test('native scope candidates preserve historical ancestry before/after union and an explicitly assigned untyped asset',async t=>{
 const f=await fixture(t),a=await f.type(plainType('scope_a')),b=await f.type(plainType('scope_b')),unrelated=await f.type(plainType('scope_unrelated'));
 const childDefinition:AssetTypeDefinition={...plainType('scope_child'),parents:[{id:a.id,version:1}],lifecycle:null};
 const child1=await f.type(childDefinition),next={...childDefinition,version:2,parents:[{id:b.id,version:1}]};
 const typePreview=await f.as(tx=>previewAssetType(tx,f.principal(),next.id,1,next));
 const child2=(await f.as(tx=>publishAssetType(tx,f.principal(),randomUUID(),next.id,1,next,typePreview.previewDigest,hooks))).type;
 const direct=await asset(f,a),oldPin=await asset(f,child1),newPin=await asset(f,child2),nextDirect=await asset(f,b),inactive=await asset(f,a),explicit=await asset(f,null);
 await f.as(tx=>transitionAssetTypeState(tx,f.principal(),randomUUID(),inactive.id,inactive.version,'inactive',hooks));
 const unrelatedTyped=await asset(f,unrelated),unrelatedUntyped=await asset(f,null);
 const before=f.relationDefinition({sourceTypes:[{typeId:a.typeId,includeDescendants:true}],targetTypes:[{typeId:a.typeId,includeDescendants:false}],sourceStates:['active'],targetStates:['active']});
 const relation=(await f.as(tx=>createRelationType(tx,f.principal(),randomUUID(),before,hooks))).type;
 const after:RelationTypeDefinitionV2={...before,formatVersion:2,version:2,sourceTypes:[{typeId:b.typeId,includeDescendants:true}]};
 const changeSet:GraphChangeSet={formatVersion:1,assetTypeMigrations:[],repairsReceiptId:null,
  assetChanges:[{kind:'assign',assetId:explicit.id,expectedVersion:1,modelId:unrelated.id,modelVersion:1,attributes:{},ownerId:f.second}],
  relationTargets:[{kind:'publish',expectedHeadVersion:1,definition:after,plan:{formatVersion:1,relationTypeId:relation.relationTypeId,sourceVersions:[],transform:null,
   edges:[],creations:[],bindings:[],enrollment:'complete-eligible-assets',acknowledgedPolicyChanges:['source_types_changed']}}]};
 const expected=await exhaustive(f,[before,after],[relation.relationTypeId],[explicit.id]);
 assert.deepEqual(expected,[direct.id,oldPin.id,newPin.id,nextDirect.id,explicit.id].sort());
 for(const excluded of [inactive,unrelatedTyped,unrelatedUntyped])assert.ok(!expected.includes(excluded.id));
 const captured=await f.as(tx=>captureRelationMigration(tx,f.principal(),graphRequest(changeSet),changeSet));
 assert.deepEqual(captured.context.before.endpoints.map(e=>e.assetId).sort(),expected);
 assert.deepEqual(captured.context.completeRelationTypeIds,[relation.relationTypeId]);
 assert.equal(captured.context.before.endpoints.find(e=>e.assetId===explicit.id)!.policy,null);
 const {preview}=await f.as(tx=>previewRelationMigration(tx,f.principal(),changeSet));
 assert.equal(preview.ready,true);if(!preview.ready)throw Error('Synthetic scope preview failed.');
 const body={changeSet,previewDigest:preview.previewDigest},key=randomUUID();
 const {receipt}=await f.as(tx=>once(tx,f.principal(),'relation-migration.execute',key,body,()=>executeRelationMigration(tx,f.principal(),'scope-equivalence',key,body,hooks)));
 assert.deepEqual(receipt.before.endpoints.map(e=>e.assetId).sort(),expected);
 assert.deepEqual(receipt.after.endpoints.map(e=>e.assetId).sort(),expected);
 assert.deepEqual(await receiptAssetIds(f,receipt.id),expected);
 assert.deepEqual(await persistedScope(f,receipt.id),expected.map(asset_id=>({asset_id,action:asset_id===explicit.id?'assign':'preserve'})));
 assert.equal(receipt.assetChanges.changes.find(c=>c.assetId===explicit.id)!.after.modelId,unrelated.id);
});

test('native exact-only candidates exclude descendant pins and unrelated hidden assets while hidden zero-degree eligible pins refuse the whole scope',async t=>{
 const f=await fixture(t),base=await f.type(plainType('exact_base')),other=await f.type(plainType('exact_other'));
 const child=await f.type({...plainType('exact_child'),parents:[{id:base.id,version:1}],lifecycle:null});
 const direct=await asset(f,base),descendant=await asset(f,child),hiddenUnrelated=await asset(f,other,f.reviewer,true);
 const definition=f.relationDefinition({sourceTypes:[{typeId:base.typeId,includeDescendants:false}],targetTypes:[{typeId:base.typeId,includeDescendants:false}]});
 const exact=(await f.as(tx=>createRelationType(tx,f.principal(),randomUUID(),definition,hooks))).type;
 const expected=await exhaustive(f,[definition],[exact.relationTypeId]);assert.deepEqual(expected,[direct.id]);
 assert.ok(!expected.includes(descendant.id));assert.ok(!expected.includes(hiddenUnrelated.id));
 assert.deepEqual((await f.as(tx=>captureRelationMigration(tx,f.principal(),repair(exact.relationTypeId)))).context.before.endpoints.map(e=>e.assetId),expected);
 const inclusiveDefinition=f.relationDefinition({sourceTypes:[{typeId:base.typeId,includeDescendants:true}],targetTypes:[{typeId:base.typeId,includeDescendants:false}]});
 const inclusive=(await f.as(tx=>createRelationType(tx,f.principal(),randomUUID(),inclusiveDefinition,hooks))).type;
 const hidden=await asset(f,child,f.reviewer,true);
 assert.ok((await exhaustive(f,[inclusiveDefinition],[inclusive.relationTypeId])).includes(hidden.id));
 const before=await f.state();
 await assert.rejects(()=>f.as(tx=>captureRelationMigration(tx,f.principal(),repair(inclusive.relationTypeId))),e=>e instanceof Problem&&e.status===403&&e.code==='RELATION_SCOPE_UNAVAILABLE');
 assert.deepEqual(await f.state(),before);
});

/** Real population outside the selected graph. Fixtures are inserted by the
 * migration owner with normal constraints/triggers and immutable revisions;
 * execution still uses the ordinary application role and original deadline. */
async function seedUnrelatedPopulation(f:Fixture,model:TypeView){
 await f.owner.query('BEGIN');try{
  await f.owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[f.tenant,f.author]);
  const inserted=await f.owner.query(`INSERT INTO assets(tenant_id,id,external_id,name,qualified_name,type,owner_id,observed_at,model_id,model_version,type_state)
   SELECT $1,gen_random_uuid(),'noise-'||n,'Synthetic unrelated asset','synthetic.unrelated.'||n,'dataset',$2,clock_timestamp(),
    CASE WHEN n<=5382 THEN $3 ELSE NULL END,CASE WHEN n<=5382 THEN 1 ELSE NULL END,CASE WHEN n<=5382 THEN 'active' ELSE NULL END
   FROM generate_series(1,11176) n RETURNING *`,[f.tenant,f.second,model.id]);
  const revisions=inserted.rows.map(row=>({asset_id:row.id,version:row.version,snapshot:assetView(row)}));
  await f.owner.query(`INSERT INTO asset_revisions(tenant_id,asset_id,version,snapshot)
   SELECT $1,x.asset_id,x.version,x.snapshot FROM jsonb_to_recordset($2::jsonb) AS x(asset_id uuid,version integer,snapshot jsonb)`,[f.tenant,JSON.stringify(revisions)]);
  await f.owner.query('COMMIT');return revisions.length;
 }catch(error){await f.owner.query('ROLLBACK');throw error;}
}

test('native linked glossary publication completes with 11176 unrelated typed and untyped assets under the original budget',async t=>{
 const f=await fixture(t),noise=await f.type(plainType('population_noise'));
 assert.equal(await seedUnrelatedPopulation(f,noise),11176);
 const target=await f.makeTerm(),relation=await f.relation();
 const proposal=await f.ready(f.input({publication:f.publication({links:[f.link(relation,target)]})}));
 const started=performance.now(),result=await f.publish(proposal),elapsedMs=performance.now()-started;
 assert.equal(result.status,'succeeded');assert.ok(result.result.graphReceiptId);assert.ok(elapsedMs<30000,'Actual publication retains its original thirty-second budget');
 const graphId=result.result.graphReceiptId!;
 assert.deepEqual(await receiptAssetIds(f,graphId),[target.id,proposal.resourceId].sort());
 assert.deepEqual((await persistedScope(f,graphId)).map(r=>r.asset_id),[target.id,proposal.resourceId].sort());
 assert.equal((await f.as(tx=>getGlossaryTerm(tx,f.principal(),proposal.resourceId))).publication.links[0].targetAssetId,target.id);
 const after=await f.as(async tx=>({counts:(await sql<{typed:string;untyped:string}>`select count(*) filter(where model_id=${noise.id})::text as typed,count(*) filter(where model_id is null)::text as untyped from assets`.execute(tx)).rows[0],
  edges:await tx.selectFrom('relations').select('id').where('status','=','active').execute(),audit:await tx.selectFrom('audit').select('id').where('action','=','asset.glossary_published').where('resource_id','=',proposal.resourceId).execute()}));
 assert.deepEqual(after.counts,{typed:'5382',untyped:'5794'});assert.equal(after.edges.length,1);assert.equal(after.audit.length,1);
 assert.deepEqual(await f.publish(proposal),result);assert.deepEqual(await receiptAssetIds(f,graphId),[target.id,proposal.resourceId].sort());
 t.diagnostic(JSON.stringify({population:11176,typed:5382,untyped:5794,publicationMs:Math.round(elapsedMs)}));
});

test('native staged source remains in protected scope when lifecycle removal releases its incident edge and binding',async t=>{
 const f=await fixture(t),target=await f.makeTerm();
 const child=await f.type({formatVersion:1,id:'staged_required_term',version:1,parents:[{id:'business_term',version:1}],attributes:{},overrideAttributes:[],requiredOwner:false,lifecycle:null});
 const definition:RelationTypeDefinitionV2={...f.relationDefinition(),formatVersion:2,
  sourceTypes:[{typeId:child.typeId,includeDescendants:true}],targetTypes:[{typeId:f.term.typeId,includeDescendants:false}],sourceStates:['active'],targetStates:['active'],
  cardinality:{outgoing:{min:1,max:2},incoming:{min:0,max:null}}};
 const preparationKey=randomUUID();
 const {preparation}=await f.as(tx=>once(tx,f.principal(),'relation-migration.prepare',preparationKey,{definition},()=>prepareRelationType(tx,f.principal(),'staged-prepare',preparationKey,definition,hooks)));
 const changeSet:GraphChangeSet={formatVersion:1,assetChanges:[],assetTypeMigrations:[],repairsReceiptId:null,relationTargets:[{kind:'create',reservationId:preparation.id,expectedHeadVersion:null,definition,
  plan:{formatVersion:1,relationTypeId:preparation.relationTypeId,sourceVersions:[],transform:null,edges:[],creations:[],bindings:[],enrollment:'complete-eligible-assets',acknowledgedPolicyChanges:[]}}]};
 const {preview}=await f.as(tx=>previewRelationMigration(tx,f.principal(),changeSet));assert.equal(preview.ready,true);if(!preview.ready)throw Error('Synthetic staged fixture failed.');
 const body={changeSet,previewDigest:preview.previewDigest},key=randomUUID();
 await f.as(tx=>once(tx,f.principal(),'relation-migration.execute',key,body,()=>executeRelationMigration(tx,f.principal(),'staged-type',key,body,hooks)));
 const link:GlossaryLink={kind:'related',typePin:{relationTypeId:preparation.relationTypeId,version:1,definitionHash:preparation.definitionHash},targetAssetId:target.id,targetAssetVersion:target.version};
 const first=await f.makeTerm({typePin:typePin(child),links:[link]}),other=await f.makeTerm({typePin:typePin(child),links:[link]});
 const before=await f.state(),original=before.bindings.find(b=>b.asset_id===first.id&&b.status==='active')!,preserved=before.bindings.find(b=>b.asset_id===other.id&&b.status==='active')!;
 const expected=await exhaustive(f,[definition],[preparation.relationTypeId]);assert.deepEqual(expected,[first.id,other.id,target.id].sort());
 const direct=await f.as(tx=>captureRelationMigration(tx,f.principal(),repair(preparation.relationTypeId)));
 assert.deepEqual(direct.context.before.endpoints.map(e=>e.assetId).sort(),expected);assert.equal(direct.context.before.edges.length,2);assert.equal(direct.context.before.bindings.length,2);
 const deprecated=await f.ready(f.input({resourceId:first.id,resourceVersion:1,publication:f.publication({typePin:typePin(child),state:'deprecated',links:[]})}));
 const result=await f.publish(deprecated),graphId=result.result.graphReceiptId!;assert.ok(graphId);
 assert.deepEqual(await receiptAssetIds(f,graphId),expected);assert.deepEqual((await persistedScope(f,graphId)).map(r=>r.asset_id),expected);
 const after=await f.state();assert.equal(after.bindings.find(b=>b.id===original.id)!.status,'released');assert.deepEqual(after.bindings.find(b=>b.id===preserved.id),preserved);
 assert.deepEqual(after.bindingRevisions.filter(b=>b.binding_id===preserved.id),before.bindingRevisions.filter(b=>b.binding_id===preserved.id));
 assert.deepEqual(await exhaustive(f,[definition],[preparation.relationTypeId]),[other.id,target.id].sort(),'Deprecated source is now outside all live eligibility/incident/binding arms');
 const receipt=await f.as(tx=>tx.selectFrom('relation_graph_receipts').select('receipt').where('id','=',graphId).executeTakeFirstOrThrow());
 assert.equal(receipt.receipt.before.edges.length,2);assert.equal(receipt.receipt.before.bindings.length,2);
 assert.equal(receipt.receipt.bindingOutcomes.find((b:any)=>b.before?.id===original.id)?.action,'release');
 assert.equal(receipt.receipt.bindingOutcomes.find((b:any)=>b.before?.id===preserved.id)?.action,'preserve');
});
