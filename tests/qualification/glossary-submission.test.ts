// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import test, {type TestContext} from 'node:test';
import pg from 'pg';
import {Kysely,PostgresDialect} from 'kysely';
import {lockTenantLedger,sql,type Tx} from '../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../packages/authz/src/index.ts';
import {assetView,record} from '../../apps/api/src/repository.ts';
import {glossaryStarterType,parseGlossaryPublication} from '../../packages/domain/src/glossary.ts';
import {submitGlossaryProposal,type GlossaryProposalInput} from '../../packages/domain/src/glossary-service.ts';
import type {GlossaryLink,GlossaryPublicationInput} from '../../packages/domain/src/glossary-contracts.ts';
import type {AssetTypeDefinition} from '../../packages/domain/src/asset-type.ts';
import {createAssetType,previewAssetType,publishAssetType} from '../../packages/domain/src/asset-type-service.ts';
import {assignAssetModel,modelPersistence,type ModelHooks} from '../../packages/domain/src/model-service.ts';
import {configureRelationTransaction,createRelationType,previewRelationType,publishRelationType} from '../../packages/domain/src/relation-service.ts';
import type {RelationTypeDefinition} from '../../packages/domain/src/relation-contracts.ts';
import {getApprovalRequest,publishApprovalDefinition} from '../../packages/domain/src/approval-service.ts';
import type {ApprovalDefinition} from '../../packages/domain/src/approval-contracts.ts';

// Only the isolated qualification harness supplies native owner/runtime URLs.
// No API, OIDC, Temporal, source connector or mocked repository is involved.
const config=JSON.parse(readFileSync(process.env.AUTHN_FOUNDATION_CONFIG!,'utf8')) as {owner:string;legacy:string};
process.env.SESSION_KEY=randomUUID()+randomUUID();
const permissions=['catalog:read','catalog:write','models:read','models:write','audit:read'];
const hooks:ModelHooks={record,assetSnapshot:assetView};
const translation=()=>({translations:[{locale:'en',name:'Net revenue',definition:'Sales after approved adjustments.',synonyms:['Adjusted revenue'],abbreviations:['NR'],examples:['Synthetic quarterly revenue.']}]});
const problem=(code:string,status:number)=>(error:unknown)=>error instanceof Problem&&error.code===code&&error.status===status;
type TypeView=Awaited<ReturnType<typeof createAssetType>>['type'];
type RelationView=Awaited<ReturnType<typeof createRelationType>>['type'];
const typePin=(view:TypeView)=>({typeId:view.typeId,modelId:view.id,version:view.version,definitionHash:view.definitionHash,resolutionHash:view.resolutionHash});
const relationPin=(view:RelationView)=>({relationTypeId:view.relationTypeId,version:view.version,definitionHash:view.definitionHash});
const definition=(id:string):ApprovalDefinition=>({formatVersion:1,id,version:1,name:'Synthetic term approval',separationOfDuties:true,
 stages:[{id:'review',name:'Parallel review',assignments:['steward','owner'],quorum:2,deadlineSeconds:3600,rejection:'any'}]});

async function fixture(t:TestContext){
 const owner=new pg.Client({connectionString:config.owner});
 const store=new Kysely<Record<string,any>>({dialect:new PostgresDialect({pool:new pg.Pool({connectionString:config.legacy,max:1,connectionTimeoutMillis:5000})})});
 t.after(async()=>{await store.destroy();await owner.end();});await owner.connect();
 const tenant=randomUUID(),requester=randomUUID(),reviewer=randomUUID(),second=randomUUID(),workflowId='terms_'+randomUUID().replaceAll('-','');
 await owner.query('BEGIN');
 try{
  await owner.query('INSERT INTO tenants(id,name) VALUES($1,$2)',[tenant,'Synthetic glossary submission']);
  for(const [id,name]of [[requester,'Synthetic author'],[reviewer,'Synthetic steward'],[second,'Synthetic owner']])
   await owner.query('INSERT INTO identities(id,issuer,subject,name) VALUES($1::uuid,$2,$1::uuid::text,$3)',[id,'https://glossary-fixture.invalid/owned',name]);
  await owner.query("SELECT set_config('gc.tenant_id',$1,true)",[tenant]);
  for(const id of [requester,reviewer,second])await owner.query('INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,$3,$4::jsonb)',[tenant,id,'synthetic',JSON.stringify(permissions)]);
  await owner.query('COMMIT');
 }catch(error){await owner.query('ROLLBACK');throw error;}
 const principal=(actor=requester):Principal=>({id:actor,name:'Synthetic glossary participant',tenantId:tenant,permissions});
 const domain=<T>(actor:string,work:(tx:Tx)=>Promise<T>)=>store.transaction().execute(async tx=>{
  await sql`select set_config('gc.tenant_id',${tenant},true),set_config('gc.actor_id',${actor},true)`.execute(tx);
  await configureRelationTransaction(tx);return work(tx);
 });
 const as=<T>(work:(tx:Tx)=>Promise<T>)=>domain(requester,work);
 const createType=async(input:AssetTypeDefinition)=>(await as(tx=>createAssetType(tx,principal(),randomUUID(),input,hooks))).type;
 const publishType=async(input:AssetTypeDefinition)=>{
  const preview=await as(tx=>previewAssetType(tx,principal(),input.id,input.version-1,input));
  return (await as(tx=>publishAssetType(tx,principal(),randomUUID(),input.id,input.version-1,input,preview.previewDigest,hooks))).type;
 };
 const term=await createType(glossaryStarterType());
 const workflow=await as(tx=>publishApprovalDefinition(tx,principal(),definition(workflowId),0,randomUUID(),'synthetic-workflow'));
 const publication=(selected=term,extra:Partial<GlossaryPublicationInput>={}):GlossaryPublicationInput=>({typePin:typePin(selected),primaryLocale:'en',ownerId:second,
  visibility:'tenant',allowedIdentityIds:[],state:'active',attributes:translation(),links:[],...extra});
 const input=(extra:Partial<GlossaryProposalInput>={}):GlossaryProposalInput=>({requestId:randomUUID(),resourceId:randomUUID(),resourceVersion:null,publication:publication(),
  workflowPin:{id:workflowId,version:workflow.definition.version,definitionHash:workflow.definitionHash},assignments:{steward:reviewer,owner:second},expiresAt:new Date(Date.now()+7200000).toISOString(),...extra});
 const submit=(value:GlossaryProposalInput,key=randomUUID(),actor=requester)=>domain(actor,tx=>submitGlossaryProposal(tx,principal(actor),'synthetic-submission',key,value));
 const relation=async(sourceType=term.typeId,targetType=term.typeId,extra:Partial<RelationTypeDefinition>={})=>{
  const d:RelationTypeDefinition={formatVersion:1,id:'links_'+randomUUID().replaceAll('-',''),version:1,label:'Broader term',inverseLabel:'Narrower term',direction:'directed',
   sourceTypes:[{typeId:sourceType,includeDescendants:true}],targetTypes:[{typeId:targetType,includeDescendants:true}],sourceStates:null,targetStates:null,
   cardinality:{outgoing:{min:0,max:1},incoming:{min:0,max:null}},allowSelf:false,cycles:'acyclic',attributes:{},requiredOwner:false,
   lifecycle:{initial:'active',states:['active'],transitions:[]},...extra};
  return (await as(tx=>createRelationType(tx,principal(),randomUUID(),d,hooks))).type;
 };
 // Direct SQL creates only the synthetic initial untyped resource and real v1
 // revision. All model assignment, type/version publication and journaling then
 // use the same production services/hooks as the API.
 const asset=async(selected=term,options:{type?:string;restricted?:readonly string[];source?:boolean}={})=>as(async tx=>{
  await lockTenantLedger(tx,tenant);const id=randomUUID();let sourceId:string|null=null;
  if(options.source){sourceId=randomUUID();await tx.insertInto('sources').values({tenant_id:tenant,id:sourceId,name:'Synthetic observed source',host:'source.invalid',port:5432,database_name:'synthetic',schema_name:'public',secret_ref:'synthetic-unused'}).execute();}
  const row=await tx.insertInto('assets').values({tenant_id:tenant,id,external_id:id,name:'Synthetic existing term',qualified_name:`synthetic.glossary.${id}`,
   type:options.type??'business_term',source_id:sourceId,owner_id:second,observed_at:new Date(),visibility:options.restricted?'restricted':'tenant',allowed_identities:JSON.stringify(options.restricted??[])}).returningAll().executeTakeFirstOrThrow();
  await tx.insertInto('asset_revisions').values({tenant_id:tenant,asset_id:id,version:row.version,snapshot:JSON.stringify(assetView(row))}).execute();
  const assigned=await assignAssetModel(tx,principal(),randomUUID(),id,1,{modelId:selected.id,modelVersion:selected.version,attributes:translation()},hooks);
  return {id,version:assigned.assetVersion};
 });
 const link=(type:RelationView,target:{id:string;version:number},kind:GlossaryLink['kind']='broader'):GlossaryLink=>({kind,typePin:relationPin(type),targetAssetId:target.id,targetAssetVersion:target.version});
 const resources=()=>as(async tx=>({
  assets:await tx.selectFrom('assets').selectAll().orderBy('id').execute(),revisions:await tx.selectFrom('asset_revisions').selectAll().orderBy('asset_id').orderBy('version').execute(),
  relations:await tx.selectFrom('relations').selectAll().orderBy('id').execute(),relationRevisions:await tx.selectFrom('relation_revisions').selectAll().orderBy('relation_id').orderBy('version').execute(),
 }));
 const journal=()=>as(async tx=>({
  requests:await tx.selectFrom('approval_requests').selectAll().orderBy('id').execute(),tasks:await tx.selectFrom('approval_tasks').selectAll().orderBy('id').execute(),
  decisions:await tx.selectFrom('approval_decisions').selectAll().orderBy('id').execute(),dispatch:await tx.selectFrom('approval_dispatch').selectAll().orderBy('event_id').execute(),
  audit:await tx.selectFrom('audit').selectAll().where('action','like','approval.%').orderBy('sequence').execute(),
  outbox:await tx.selectFrom('outbox').selectAll().where('event_type','like','approval.%').orderBy('id').execute(),
  once:await tx.selectFrom('idempotency').selectAll().where('operation','=','approval.submit').orderBy('key').execute(),
 }));
 const reject=async(value:GlossaryProposalInput,code:string,status:number,key=randomUUID())=>{
  const before=await journal(),prior=await resources();await assert.rejects(()=>submit(value,key),problem(code,status));
  assert.deepEqual(await journal(),before,'Refused proposal must not create partial approval, task, once, dispatch or journal rows');
  assert.deepEqual(await resources(),prior,'Refused proposal must not change canonical resources or history');
 };
 const revoke=async(actor:string,remaining:readonly string[])=>{
  await owner.query('BEGIN');try{await owner.query("SELECT set_config('gc.tenant_id',$1,true)",[tenant]);
   await owner.query('UPDATE memberships SET permissions=$3::jsonb WHERE tenant_id=$1 AND identity_id=$2',[tenant,actor,JSON.stringify(remaining)]);await owner.query('COMMIT');
  }catch(error){await owner.query('ROLLBACK');throw error;}
 };
 return {owner,tenant,requester,reviewer,second,workflowId,term,workflow,principal,domain,as,createType,publishType,publication,input,submit,relation,asset,link,resources,journal,reject,revoke};
}

test('native glossary submission creates pinned tasks and one atomic journal without creating the proposed term or links',async t=>{
 const f=await fixture(t),target=await f.asset(),relation=await f.relation(),value=f.input({publication:f.publication(f.term,{links:[f.link(relation,target)]})});
 const before=await f.resources(),result=await f.submit(value),r=result.request;
 assert.equal(r.id,value.requestId);assert.equal(r.resourceId,value.resourceId);assert.equal(r.resourceVersion,null);assert.equal(r.status,'pending');assert.equal(r.result,null);
 assert.equal(r.workflowHash,f.workflow.definitionHash);assert.equal(r.workflowVersion,1);assert.equal(r.preconditionsCurrent,true);assert.deepEqual(r.payload,value.publication);
 assert.deepEqual(r.tasks.map(x=>[x.assignment,x.assignedIdentityId,x.status]).sort(),[['owner',f.second,'open'],['steward',f.reviewer,'open']]);assert.deepEqual(r.decisions,[]);
 assert.deepEqual(await f.resources(),before,'Submission is an approval request, not resource publication');
 const j=await f.journal();assert.equal(j.requests.length,1);assert.equal(j.tasks.length,2);assert.equal(j.decisions.length,0);assert.equal(j.once.length,1);
 assert.equal(j.audit.length,1);assert.equal(j.outbox.length,1);assert.equal(j.dispatch.length,1);assert.equal(j.audit[0].id,j.outbox[0].id);assert.equal(j.dispatch[0].event_id,j.outbox[0].id);
 assert.equal(j.audit[0].action,'approval.submitted');assert.equal(j.audit[0].resource_id,value.requestId);assert.equal(j.once[0].request_hash,r.proposalDigest);
 const parsed=parseGlossaryPublication(value.publication);assert.ok(parsed.ok);
 assert.equal(r.proposalDigest,modelPersistence.hash({id:value.requestId,binding:'glossary.publish',resourceId:value.resourceId,resourceVersion:null,payload:parsed.value.input,
  workflowId:value.workflowPin.id,workflowVersion:1,workflowHash:value.workflowPin.definitionHash,assignments:value.assignments,expiresAt:value.expiresAt}));
 assert.equal((await f.domain(f.reviewer,tx=>getApprovalRequest(tx,f.principal(f.reviewer),r.id))).proposalDigest,r.proposalDigest);
});

test('native exact replay preserves the original response and receipts after definition drift; changed content conflicts',async t=>{
 const f=await fixture(t),value=f.input(),key=randomUUID(),first=await f.submit(value,key),before=await f.journal();
 assert.deepEqual(await f.submit(value,key),first);assert.deepEqual(await f.journal(),before);
 await f.publishType({...glossaryStarterType(),version:2,attributes:{...glossaryStarterType().attributes,note:{type:'text'}}});
 await f.as(tx=>publishApprovalDefinition(tx,f.principal(),{...f.workflow.definition,version:2,name:'Future term approval'},1,randomUUID(),'synthetic-workflow'));
 const drifted=await f.submit(value,key);assert.deepEqual({...drifted.request,workflow:first.request.workflow},first.request);
 assert.equal(drifted.request.workflow.currentVersion,2);assert.equal(drifted.request.workflow.definition.version,1);assert.deepEqual(await f.journal(),before);
 await f.reject({...value,publication:{...value.publication,attributes:{...translation(),translations:[{...translation().translations[0],name:'Changed term'}]}}},'IDEMPOTENCY_CONFLICT',409,key);
});

test('native replay and new submission require current reviewer permission despite a previously authorized request',async t=>{
 const f=await fixture(t),value=f.input(),key=randomUUID();await f.submit(value,key);
 await f.revoke(f.reviewer,['catalog:read','models:read']);
 await f.reject(value,'GLOSSARY_PARTICIPANT_UNAVAILABLE',403,key);await f.reject(f.input(),'GLOSSARY_PARTICIPANT_UNAVAILABLE',403);
});

test('native submission refreshes requester authority rather than trusting the supplied principal permissions',async t=>{
 const f=await fixture(t);await f.revoke(f.requester,['catalog:read','models:read']);
 await f.reject(f.input(),'FORBIDDEN',403);
});

test('native glossary type pins require exact current version, identity, definition and resolved lineage',async t=>{
 const f=await fixture(t),old=f.input();
 for(const change of [{definitionHash:'0'.repeat(64)},{resolutionHash:'0'.repeat(64)},{typeId:randomUUID()}])
  await f.reject({...old,publication:{...old.publication,typePin:{...old.publication.typePin,...change}}},'GLOSSARY_PIN_STALE',409);
 const next=await f.publishType({...glossaryStarterType(),version:2,attributes:{...glossaryStarterType().attributes,note:{type:'text'}}});
 await f.reject(old,'GLOSSARY_PIN_STALE',409);
 const current=await f.submit(f.input({publication:f.publication(next)}));assert.equal(current.request.payload.typePin.version,2);
});

test('native real inherited term type is accepted while an unrelated lookalike type is refused',async t=>{
 const f=await fixture(t),child=await f.createType({formatVersion:1,id:'financial_term',version:1,parents:[{id:'business_term',version:1}],attributes:{note:{type:'text'}},overrideAttributes:[],requiredOwner:false,lifecycle:null});
 assert.equal(child.resolved.requiredOwner,true);assert.deepEqual(child.resolved.dependencies,[{id:'business_term',version:1}]);
 const target=await f.asset(),relation=await f.relation();
 const accepted=await f.submit(f.input({publication:f.publication(child,{links:[f.link(relation,target)]})}));assert.equal(accepted.request.payload.typePin.modelId,'financial_term');
 const lookalike=await f.createType({...glossaryStarterType(),id:'unrelated_term'});
 await f.reject(f.input({publication:f.publication(lookalike)}),'GLOSSARY_POLICY_INVALID',422);
});

test('native proposed restricted audience must include every reviewer and hidden references remain unavailable',async t=>{
 const f=await fixture(t),relation=await f.relation(),hidden=await f.asset(f.term,{restricted:[f.requester]});
 await f.reject(f.input({publication:f.publication(f.term,{visibility:'restricted',allowedIdentityIds:[f.requester,f.second]})}),'GLOSSARY_REVIEW_VISIBILITY',422);
 await f.reject(f.input({publication:f.publication(f.term,{links:[f.link(relation,hidden)]})}),'GLOSSARY_REFERENCE_UNAVAILABLE',404);
 await f.reject(f.input({publication:f.publication(f.term,{links:[f.link(relation,{id:randomUUID(),version:1})]})}),'GLOSSARY_REFERENCE_UNAVAILABLE',404);
 const visible=await f.asset(f.term,{restricted:[f.requester,f.reviewer,f.second]});
 const accepted=await f.submit(f.input({publication:f.publication(f.term,{visibility:'restricted',allowedIdentityIds:[f.requester,f.reviewer,f.second],links:[f.link(relation,visible)]})}));
 assert.equal(accepted.request.payload.visibility,'restricted');assert.equal(accepted.request.tasks.length,2);
});

test('native links require current exact target and relation definition pins before creating approval rows',async t=>{
 const f=await fixture(t),target=await f.asset(),relation=await f.relation(),good=f.link(relation,target);
 await f.reject(f.input({publication:f.publication(f.term,{links:[{...good,targetAssetVersion:target.version-1}]})}),'VERSION_CONFLICT',409);
 await f.reject(f.input({publication:f.publication(f.term,{links:[{...good,typePin:{...good.typePin,definitionHash:'0'.repeat(64)}}]})}),'GLOSSARY_PIN_STALE',409);
 const nextDefinition={...relation.definition,version:2,label:'Current broader term'},preview=await f.as(tx=>previewRelationType(tx,f.principal(),relation.id,1,nextDefinition));
 const next=(await f.as(tx=>publishRelationType(tx,f.principal(),randomUUID(),relation.id,1,nextDefinition,preview.previewDigest,hooks))).type;
 await f.reject(f.input({publication:f.publication(f.term,{links:[good]})}),'GLOSSARY_PIN_STALE',409);
 const accepted=await f.submit(f.input({publication:f.publication(f.term,{links:[f.link(next,target)]})}));assert.equal(accepted.request.payload.links[0].typePin.version,2);
});

test('native existing authored term updates require exact asset version and leave canonical state and revisions unchanged',async t=>{
 const f=await fixture(t),base=await f.asset(),value=f.input({resourceId:base.id,resourceVersion:base.version,publication:f.publication(f.term,{state:'deprecated'})});
 const before=await f.resources();await f.reject({...value,resourceVersion:base.version-1},'VERSION_CONFLICT',409);
 await f.reject({...value,resourceVersion:null},'VERSION_CONFLICT',409);
 const result=await f.submit(value);assert.equal(result.request.resourceVersion,base.version);assert.equal(result.request.payload.state,'deprecated');assert.deepEqual(await f.resources(),before);
});

test('native submission refuses nonterm or source-observed resources even when they carry the real term model',async t=>{
 const f=await fixture(t),nonterm=await f.asset(f.term,{type:'dataset'}),observed=await f.asset(f.term,{source:true});
 for(const base of [nonterm,observed])await f.reject(f.input({resourceId:base.id,resourceVersion:base.version}),'GLOSSARY_POLICY_INVALID',422);
});

test('native broader and related links enforce term origin, graph policy and exact endpoint eligibility',async t=>{
 const f=await fixture(t),term=await f.asset(),nonterm=await f.asset(f.term,{type:'dataset'}),broader=await f.relation();
 await f.reject(f.input({publication:f.publication(f.term,{links:[f.link(broader,nonterm,'related')]})}),'GLOSSARY_POLICY_INVALID',422);
 const broad=await f.relation(f.term.typeId,f.term.typeId,{cycles:'allow',cardinality:{outgoing:{min:0,max:null},incoming:{min:0,max:null}}});
 await f.reject(f.input({publication:f.publication(f.term,{links:[f.link(broad,term)]})}),'GLOSSARY_POLICY_INVALID',422);
 const other=await f.createType({...glossaryStarterType(),id:'physical_dataset'}),wrong=await f.relation(f.term.typeId,other.typeId);
 await f.reject(f.input({publication:f.publication(f.term,{links:[f.link(wrong,term,'defines')]})}),'GLOSSARY_LINK_INVALID',422);
 const physical=await f.asset(other,{type:'dataset'}),before=await f.resources();
 const accepted=await f.submit(f.input({publication:f.publication(f.term,{links:[f.link(wrong,physical,'defines')]})}));
 assert.equal(accepted.request.payload.links[0].kind,'defines');assert.deepEqual(await f.resources(),before);
});

test('native workflow pins, complete assignments and separation of duties are checked without partial submission',async t=>{
 const f=await fixture(t),value=f.input();
 await f.reject({...value,workflowPin:{...value.workflowPin,definitionHash:'0'.repeat(64)}},'WORKFLOW_PIN_STALE',409);
 await f.reject({...value,assignments:{steward:f.reviewer}},'GLOSSARY_POLICY_INVALID',422);
 await f.reject({...value,assignments:{steward:f.requester,owner:f.second}},'GLOSSARY_POLICY_INVALID',422);
 await f.reject({...value,assignments:{steward:f.reviewer,owner:f.reviewer}},'GLOSSARY_POLICY_INVALID',422);
 await f.as(tx=>publishApprovalDefinition(tx,f.principal(),{...f.workflow.definition,version:2,name:'Future review'},1,randomUUID(),'synthetic-workflow'));
 await f.reject(value,'WORKFLOW_PIN_STALE',409);
});
