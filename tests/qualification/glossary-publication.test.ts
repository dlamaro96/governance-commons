// SPDX-License-Identifier: Apache-2.0
/** Native SQL001–016 qualification. Synthetic subjects, real production services,
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

test('native glossary publication atomically creates the first canonical term and exact sealed replay has no second effect',async t=>{
 const f=await fixture(t),proposal=await f.ready(),before=await f.state();assert.equal(before.assets.length,0);
 const result=await f.publish(proposal);assert.equal(result.id,proposal.requestId);assert.equal(result.status,'succeeded');
 assert.equal(result.result.assetId,proposal.resourceId);assert.equal(result.result.assetVersion,1);assert.equal(result.result.graphReceiptId,null);
 const after=await f.state();assert.equal(after.assets.length,1);assert.equal(after.revisions.length,1);assert.equal(after.publications.length,1);assert.equal(after.terms.length,1);assert.equal(after.edges.length,0);
 assert.equal(after.assets[0].source_id,null);assert.equal(after.assets[0].observed_at,null);assert.equal(after.assets[0].name,'Net revenue');assert.equal(after.assets[0].model_version,1);
 assert.equal(after.requests[0].status,'succeeded');assert.deepEqual(after.requests[0].result,result.result);
 assert.equal(after.audit.filter(a=>a.action==='asset.glossary_published').length,1);assert.equal(after.audit.filter(a=>a.action==='approval.succeeded').length,1);
 assert.equal(after.outbox.filter(o=>o.event_type==='asset.glossary_published').length,1);assert.equal(after.outbox.filter(o=>o.event_type==='approval.succeeded').length,1);
 assert.deepEqual(await f.as(tx=>getGlossaryTerm(tx,f.principal(),proposal.resourceId)),{resourceId:proposal.resourceId,resourceVersion:1,publication:proposal.publication});
 assert.deepEqual(await f.publish(proposal),result);assert.deepEqual(await f.state(),after);
 await f.as(tx=>publishApprovalDefinition(tx,f.principal(),{...f.workflowDefinition,version:2,name:'Future requests'},1,randomUUID(),'workflow-advance'));
 const advanced=await f.state();assert.deepEqual(await f.publish(proposal),result);assert.deepEqual(await f.state(),advanced);
});

test('native glossary revision replaces only prior owned links and preserves unrelated edge histories',async t=>{
 const f=await fixture(t),a=await f.makeTerm(),b=await f.makeTerm(),c=await f.makeTerm(),relation=await f.relation();
 const first=await f.makeTerm({links:[f.link(relation,a)]});
 const unrelated=await f.as(tx=>createRelation(tx,f.principal(),'unrelated-link',{relationTypeId:relation.relationTypeId,relationTypeVersion:1,
  sourceAssetId:first.id,targetAssetId:c.id,sourceAssetVersion:1,targetAssetVersion:c.version,attributes:{},ownerId:f.second,validFrom:null,validTo:null,visibility:'tenant',allowedIdentityIds:[]},hooks));
 const before=await f.state(),owned=before.links.find(l=>l.publication_id===first.proposal.requestId)!;
 const proposal=await f.ready(f.input({resourceId:first.id,resourceVersion:1,publication:f.publication({attributes:attributes('Approved revenue'),links:[f.link(relation,b)]})}));
 const result=await f.publish(proposal);assert.equal(result.result.assetVersion,2);assert.ok(result.result.graphReceiptId);
 const after=await f.state(),old=after.edges.find(e=>e.id===owned.relation_id)!;assert.equal(old.status,'tombstoned');assert.equal(old.version,2);
 assert.deepEqual(after.edges.find(e=>e.id===unrelated.relation.id),before.edges.find(e=>e.id===unrelated.relation.id));
 assert.deepEqual(after.edgeRevisions.filter(e=>e.relation_id===unrelated.relation.id),before.edgeRevisions.filter(e=>e.relation_id===unrelated.relation.id));
 const current=after.links.find(l=>l.publication_id===proposal.requestId)!;assert.equal(current.target_asset_id,b.id);assert.notEqual(current.relation_id,owned.relation_id);
 assert.deepEqual(await f.as(tx=>getGlossaryTerm(tx,f.principal(),first.id)),{resourceId:first.id,resourceVersion:2,publication:proposal.publication});
});

test('native glossary publication refuses stale approved type and target revisions without partial effects',async t=>{
 const f=await fixture(t),proposal=await f.ready();
 const next={...glossaryStarterType(),version:2},preview=await f.as(tx=>previewAssetType(tx,f.principal(),next.id,1,next));
 await f.as(tx=>publishAssetType(tx,f.principal(),randomUUID(),next.id,1,next,preview.previewDigest,hooks));await f.reject(proposal,409);
 const g=await fixture(t),target=await g.makeTerm(),relation=await g.relation();
 const stale=await g.ready(g.input({publication:g.publication({links:[g.link(relation,target)]})}));
 await g.publish(await g.ready(g.input({resourceId:target.id,resourceVersion:target.version,publication:g.publication({attributes:attributes('Changed target')})})));
 await g.reject(stale,409);
});

test('native glossary publication and sealed replay require current requester and reviewer authority',async t=>{
 const f=await fixture(t),proposal=await f.ready();await f.revoke(f.reviewer);await f.reject(proposal,403);
 const g=await fixture(t),term=await g.makeTerm();await g.revoke(g.author);const before=await g.state();
 await assert.rejects(()=>g.publish(term.proposal),issue(403));assert.deepEqual(await g.state(),before);
});

test('native glossary graph journal failure rolls back staged asset and every graph or approval effect',async t=>{
 const f=await fixture(t),target=await f.makeTerm(),relation=await f.relation(),proposal=await f.ready(f.input({publication:f.publication({links:[f.link(relation,target)]})}));
 const before=await f.state();let called=false;
 await assert.rejects(()=>f.publish(proposal,{...hooks,record:async(...args)=>{called=true;await record(...args);throw new Error('Synthetic transaction failure.');}}),issue(500));
 assert.equal(called,true);assert.deepEqual(await f.state(),before);assert.equal((await f.as(tx=>getApprovalRequest(tx,f.principal(),proposal.requestId))).status,'ready');
});

test('native glossary storage refuses raw publication bypass and incomplete prepared or staged commits',async t=>{
 const f=await fixture(t),proposal=await f.ready(),before=await f.state();
 await assert.rejects(()=>f.as(tx=>sql`select public.gc_glossary_prepare(${proposal.requestId}::uuid)`.execute(tx)),(e:unknown)=>sqlCode('23503')(e)||sqlCode('23514')(e));assert.deepEqual(await f.state(),before);
 await assert.rejects(()=>f.as(async tx=>{await sql`select public.gc_glossary_prepare(${proposal.requestId}::uuid)`.execute(tx);await sql`select public.gc_glossary_stage(${proposal.requestId}::uuid)`.execute(tx);}),(e:unknown)=>sqlCode('23503')(e)||sqlCode('23514')(e));assert.deepEqual(await f.state(),before);
 const term=await f.publish(proposal),published=await f.state();
 await assert.rejects(()=>f.as(tx=>sql`update public.assets set name='Bypassed' where id=${term.result.assetId}::uuid`.execute(tx)),sqlCode('42501'));
 await assert.rejects(()=>f.as(tx=>sql`update public.glossary_terms set current_publication_id=${randomUUID()}::uuid`.execute(tx)),sqlCode('42501'));assert.deepEqual(await f.state(),published);
});

test('native glossary read requires current visibility of the whole owned link set and base term',async t=>{
 const f=await fixture(t),audience=[f.author,f.reviewer,f.second].sort(),hidden=await f.makeTerm({visibility:'restricted',allowedIdentityIds:audience}),relation=await f.relation();
 const source=await f.makeTerm({links:[f.link(relation,hidden)]});
 assert.equal((await f.as(tx=>getGlossaryTerm(tx,f.principal(),source.id))).publication.links.length,1);
 await assert.rejects(()=>f.as(tx=>getGlossaryTerm(tx,f.principal(f.reader),source.id),f.reader),issue(404));
 await assert.rejects(()=>f.as(tx=>getGlossaryTerm(tx,f.principal(f.reader),hidden.id),f.reader),issue(404));
 const plain=await f.makeTerm();assert.equal((await f.as(tx=>getGlossaryTerm(tx,f.principal(f.reader),plain.id),f.reader)).resourceId,plain.id);
});

test('native glossary creation enrolls positive-minimum source participation and rejects missing final degree',async t=>{
 const f=await fixture(t),target=await f.makeTerm();
 const child=await f.type({formatVersion:1,id:'required_term',version:1,parents:[{id:'business_term',version:1}],attributes:{},overrideAttributes:[],requiredOwner:false,lifecycle:null});
 const definition:RelationTypeDefinitionV2={...f.relationDefinition(),formatVersion:2,sourceTypes:[{typeId:child.typeId,includeDescendants:true}],cardinality:{outgoing:{min:1,max:2},incoming:{min:0,max:null}}};
 const preparationKey=randomUUID();
 const {preparation}=await f.as(tx=>once(tx,f.principal(),'relation-migration.prepare',preparationKey,{definition},
  ()=>prepareRelationType(tx,f.principal(),'positive-prepare',preparationKey,definition,hooks)));
 const changeSet:GraphChangeSet={formatVersion:1,assetChanges:[],assetTypeMigrations:[],repairsReceiptId:null,relationTargets:[{kind:'create',reservationId:preparation.id,expectedHeadVersion:null,definition,
  plan:{formatVersion:1,relationTypeId:preparation.relationTypeId,sourceVersions:[],transform:null,edges:[],creations:[],bindings:[],enrollment:'complete-eligible-assets',acknowledgedPolicyChanges:[]}}]};
 const {preview}=await f.as(tx=>previewRelationMigration(tx,f.principal(),changeSet));assert.equal(preview.ready,true);if(!preview.ready)throw Error('Positive fixture preview was refused.');
 const body={changeSet,previewDigest:preview.previewDigest},key=randomUUID();
 await f.as(tx=>once(tx,f.principal(),'relation-migration.execute',key,body,()=>executeRelationMigration(tx,f.principal(),'positive-type',key,body,hooks)));
 const missing=await f.ready(f.input({publication:f.publication({typePin:typePin(child)})}));await f.reject(missing,422);
 const link:GlossaryLink={kind:'related',typePin:{relationTypeId:preparation.relationTypeId,version:1,definitionHash:preparation.definitionHash},targetAssetId:target.id,targetAssetVersion:target.version};
 const valid=await f.ready(f.input({publication:f.publication({typePin:typePin(child),links:[link]})}));
 const result=await f.publish(valid);assert.ok(result.result.graphReceiptId);
 const state=await f.state(),bindings=state.bindings.filter(b=>b.asset_id===result.result.assetId&&b.relation_type_id===preparation.relationTypeId);
 assert.equal(bindings.length,1);assert.equal(bindings[0].side,'source');assert.equal(bindings[0].status,'active');assert.equal(bindings[0].asset_version,1);
 assert.equal(state.edges.filter(e=>e.status==='active'&&e.source_asset_id===result.result.assetId&&e.target_asset_id===target.id).length,1);
});


test('native glossary undirected links retain canonical endpoint versions through creation amendment and read',async t=>{
 const f=await fixture(t),relation=await f.relation({direction:'undirected'});
 const targetId='00000001'+randomUUID().slice(8),termId='fffffffe'+randomUUID().slice(8);
 const target=await f.ready(f.input({resourceId:targetId}));await f.publish(target);
 // Unequal endpoint versions prove that normalization swaps observations too.
 await f.publish(await f.ready(f.input({resourceId:targetId,resourceVersion:1,publication:f.publication({attributes:attributes('Target revision two')})})));
 const first=await f.ready(f.input({resourceId:termId,publication:f.publication({links:[f.link(relation,{id:targetId,version:2})]})}));
 await f.publish(first);const before=await f.state(),owned=before.links.find(l=>l.publication_id===first.requestId)!;
 const edge=before.edges.find(e=>e.id===owned.relation_id)!;
 assert.equal(edge.source_asset_id,targetId);assert.equal(edge.target_asset_id,termId);
 const recorded=before.edgeRevisions.find(r=>r.relation_id===edge.id&&r.version===edge.version)!;
 assert.equal(recorded.source_asset_version,2);assert.equal(recorded.target_asset_version,1);
 assert.deepEqual(await f.as(tx=>getGlossaryTerm(tx,f.principal(),termId)),{resourceId:termId,resourceVersion:1,publication:first.publication});
 const amendment=await f.ready(f.input({resourceId:termId,resourceVersion:1,publication:f.publication({attributes:attributes('Amended term'),links:[f.link(relation,{id:targetId,version:2})]})}));
 await f.publish(amendment);const after=await f.state(),current=after.links.find(l=>l.publication_id===amendment.requestId)!;
 assert.equal(after.edges.find(e=>e.id===owned.relation_id)!.status,'tombstoned');assert.notEqual(current.relation_id,owned.relation_id);
 const revised=after.edges.find(e=>e.id===current.relation_id)!;
 assert.equal(revised.source_asset_id,targetId);assert.equal(revised.target_asset_id,termId);
 const recordedAmendment=after.edgeRevisions.find(r=>r.relation_id===revised.id&&r.version===revised.version)!;
 assert.equal(recordedAmendment.source_asset_version,2);assert.equal(recordedAmendment.target_asset_version,2);
 assert.deepEqual(await f.as(tx=>getGlossaryTerm(tx,f.principal(),termId)),{resourceId:termId,resourceVersion:2,publication:amendment.publication});
});


test('native glossary lifecycle releases only its ineligible pinned binding and reactivation enrolls again',async t=>{
 const f=await fixture(t),target=await f.makeTerm();
 const child=await f.type({formatVersion:1,id:'active_required_term',version:1,parents:[{id:'business_term',version:1}],attributes:{},overrideAttributes:[],requiredOwner:false,lifecycle:null});
 const definition:RelationTypeDefinitionV2={...f.relationDefinition(),formatVersion:2,sourceTypes:[{typeId:child.typeId,includeDescendants:true}],sourceStates:['active'],cardinality:{outgoing:{min:1,max:2},incoming:{min:0,max:null}}};
 const preparationKey=randomUUID();
 const {preparation}=await f.as(tx=>once(tx,f.principal(),'relation-migration.prepare',preparationKey,{definition},
  ()=>prepareRelationType(tx,f.principal(),'lifecycle-prepare',preparationKey,definition,hooks)));
 const changeSet:GraphChangeSet={formatVersion:1,assetChanges:[],assetTypeMigrations:[],repairsReceiptId:null,relationTargets:[{kind:'create',reservationId:preparation.id,expectedHeadVersion:null,definition,
  plan:{formatVersion:1,relationTypeId:preparation.relationTypeId,sourceVersions:[],transform:null,edges:[],creations:[],bindings:[],enrollment:'complete-eligible-assets',acknowledgedPolicyChanges:[]}}]};
 const {preview}=await f.as(tx=>previewRelationMigration(tx,f.principal(),changeSet));assert.equal(preview.ready,true);if(!preview.ready)throw Error('Lifecycle fixture preview was refused.');
 const body={changeSet,previewDigest:preview.previewDigest},key=randomUUID();
 await f.as(tx=>once(tx,f.principal(),'relation-migration.execute',key,body,()=>executeRelationMigration(tx,f.principal(),'lifecycle-type',key,body,hooks)));
 const link:GlossaryLink={kind:'related',typePin:{relationTypeId:preparation.relationTypeId,version:1,definitionHash:preparation.definitionHash},targetAssetId:target.id,targetAssetVersion:target.version};
 const first=await f.makeTerm({typePin:typePin(child),links:[link]}),other=await f.makeTerm({typePin:typePin(child),links:[link]});
 const before=await f.state(),original=before.bindings.find(b=>b.asset_id===first.id&&b.status==='active')!,otherBinding=before.bindings.find(b=>b.asset_id===other.id&&b.status==='active')!;
 assert.ok(original);assert.ok(otherBinding);
 const deprecated=await f.ready(f.input({resourceId:first.id,resourceVersion:1,publication:f.publication({typePin:typePin(child),state:'deprecated',links:[]})}));
 await f.publish(deprecated);const after=await f.state(),released=after.bindings.find(b=>b.id===original.id)!;
 assert.equal(released.status,'released');assert.equal(released.version,original.version+1);assert.equal(released.relation_type_version,original.relation_type_version);
 assert.deepEqual(after.bindings.find(b=>b.id===otherBinding.id),otherBinding);
 assert.deepEqual(after.bindingRevisions.filter(b=>b.binding_id===otherBinding.id),before.bindingRevisions.filter(b=>b.binding_id===otherBinding.id));
 assert.equal((await f.as(tx=>getGlossaryTerm(tx,f.principal(),first.id))).publication.state,'deprecated');
 const active=await f.ready(f.input({resourceId:first.id,resourceVersion:2,publication:f.publication({typePin:typePin(child),links:[link]})}));
 await f.publish(active);const restored=await f.state(),current=restored.bindings.filter(b=>b.asset_id===first.id&&b.status==='active');
 assert.equal(current.length,1);assert.notEqual(current[0].id,original.id);assert.equal(current[0].relation_type_version,1);assert.equal(current[0].asset_version,3);
 assert.deepEqual(restored.bindings.find(b=>b.id===original.id),released);assert.deepEqual(restored.bindings.find(b=>b.id===otherBinding.id),otherBinding);
});
