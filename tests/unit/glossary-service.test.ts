// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {Kysely,DummyDriver,PostgresAdapter,PostgresIntrospector,PostgresQueryCompiler,type CompiledQuery,type DatabaseConnection,type QueryResult} from 'kysely';
import type {Tx} from '../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../packages/authz/src/index.ts';
import {submitGlossaryProposal,type GlossaryProposalInput} from '../../packages/domain/src/glossary-service.ts';
import {glossaryStarterType,parseGlossaryPublication} from '../../packages/domain/src/glossary.ts';
import {resolveAssetType} from '../../packages/domain/src/asset-type.ts';
import {resolveRelationDefinition} from '../../packages/domain/src/relation.ts';
import {modelPersistence} from '../../packages/domain/src/model-service.ts';
import type {ValidationResult} from '../../packages/domain/src/model.ts';
const id=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const tenant=id(1),actor=id(2),reviewer=id(3),owner=id(4),resource=id(5),request=id(6),typeId=id(7),target=id(8),relationId=id(9);
const p:Principal={tenantId:tenant,id:actor,name:'Synthetic requester',permissions:['catalog:read','catalog:write','models:read','models:write']};
const stamp='2026-11-16T00:00:00.000Z';
const ok=<T>(r:ValidationResult<T>):T=>{if(!r.ok)assert.fail(JSON.stringify(r.issues));return r.value;};
const definition={formatVersion:1 as const,id:'review',version:1,name:'Review',separationOfDuties:true,stages:[{id:'owners',name:'Owners',assignments:['owner'],quorum:1,deadlineSeconds:300,rejection:'any' as const}]};
const workflowHash=modelPersistence.hash(definition);
function fixture(){
 const authored=glossaryStarterType(),resolved=ok(resolveAssetType(authored,[]));
 const row={model_id:authored.id,version:1,definition:authored,resolved,definition_hash:modelPersistence.hash(authored),resolution_hash:modelPersistence.hash(resolved)};
 const input:GlossaryProposalInput={requestId:request,resourceId:resource,resourceVersion:null,publication:{typePin:{typeId,modelId:'business_term',version:1,definitionHash:row.definition_hash,resolutionHash:row.resolution_hash},
  primaryLocale:'en',ownerId:owner,visibility:'tenant',allowedIdentityIds:[],state:'active',attributes:{translations:[{locale:'en',name:'Revenue',definition:'Synthetic earned amount.',synonyms:[],abbreviations:[],examples:[]}]},links:[]},
  workflowPin:{id:'review',version:1,definitionHash:workflowHash},assignments:{owner:reviewer},expiresAt:'2026-11-17T00:00:00.000Z'};
 const relation=ok(resolveRelationDefinition({formatVersion:1,id:'broader',version:1,label:'Broader',inverseLabel:'Narrower',direction:'directed',sourceTypes:[{typeId,includeDescendants:true}],targetTypes:[{typeId,includeDescendants:true}],sourceStates:null,targetStates:null,
  cardinality:{outgoing:{min:0,max:1},incoming:{min:0,max:null}},allowSelf:false,cycles:'acyclic',attributes:{},requiredOwner:false,lifecycle:{initial:'active',states:['active'],transitions:[]}})).definition;
 return {input,row,rootRow:row,relation,assets:[] as Record<string,any>[],headVersion:1,workflowVersion:1,actorAllowed:true,inactive:false,hidden:false,replay:null as string|null,bytes:'0',relationBytes:100};
}
type Fixture=ReturnType<typeof fixture>;type Query=CompiledQuery<unknown>;
function body(input:GlossaryProposalInput){return {id:input.requestId,binding:'glossary.publish',resourceId:input.resourceId,resourceVersion:input.resourceVersion,payload:ok(parseGlossaryPublication(input.publication)).input,
 workflowId:input.workflowPin.id,workflowVersion:input.workflowPin.version,workflowHash:input.workflowPin.definitionHash,assignments:input.assignments,expiresAt:input.expiresAt};}
function database(f:Fixture,override?:(q:Query)=>Record<string,unknown>[]|undefined){
 const calls:Query[]=[];let submitted:ReturnType<typeof body>|undefined;
 const respond=(q:Query):Record<string,unknown>[]=>{
  const change=override?.(q);if(change!==undefined)return change;
  if(q.sql.includes('from "memberships"'))return f.actorAllowed?[{permissions:p.permissions}]:[];
  if(q.sql.includes('select m.identity_id'))return [...new Set([actor,owner,...Object.values(f.input.assignments),...f.input.publication.allowedIdentityIds])].map(identity_id=>({identity_id,active:!f.inactive,identity_active:true,can_review:true}));
  if(q.sql.includes('from unnest('))return f.hidden?[{hidden:1}]:[];
  if(q.sql.includes('coalesce(sum(octet_length'))return [{bytes:f.bytes}];
  if(q.sql.includes('select id,version,model_id'))return f.assets;
  if(q.sql.includes('select request_hash'))return f.replay?[{request_hash:f.replay}]:[];
  if(q.sql.includes('select id,type_id,current_version from public.governance_models'))return [{id:'business_term',type_id:typeId,current_version:f.headVersion},...(f.row.model_id==='business_term'?[]:[{id:f.row.model_id,type_id:id(70),current_version:1}])];
  if(q.sql.includes('select octet_length(v.definition::text)'))return [{bytes:Buffer.byteLength(JSON.stringify(f.rootRow.definition))}];
  if(q.sql.includes('select v.definition,v.definition_hash,m.type_id'))return [{definition:f.rootRow.definition,definition_hash:f.rootRow.definition_hash,type_id:typeId}];
  if(q.sql.includes('octet_length(definition::text)+'))return [{bytes:Buffer.byteLength(JSON.stringify(f.row))}];
  if(q.sql.includes('select model_id,version,definition,resolved'))return [f.row];
  if(q.sql.includes('select id,type_id,current_version from public.relation_types'))return [{id:f.relation.id,type_id:relationId,current_version:1}];
  if(q.sql.includes('octet_length(definition::text) as bytes from public.relation_type_versions'))return [{bytes:f.relationBytes}];
  if(q.sql.includes('select definition,definition_hash from public.relation_type_versions'))return [{definition:f.relation,definition_hash:modelPersistence.hash(f.relation)}];
  if(q.sql.includes('select v.*,w.current_version'))return [{workflow_id:'review',version:1,definition,definition_hash:workflowHash,current_version:f.workflowVersion,created_at:stamp,created_by:actor}];
  const receipt=()=>({id:request,binding:'glossary.publish',resourceId:resource,resourceVersion:f.input.resourceVersion,payload:(submitted??body(f.input)).payload,proposalDigest:modelPersistence.hash(submitted??body(f.input)),workflowId:'review',workflowVersion:1,workflowHash,
   requesterId:actor,stageIndex:0,version:1,status:'pending',expiresAt:f.input.expiresAt,createdAt:stamp,updatedAt:stamp,result:null,errorCode:null,tasks:[],decisions:[]});
  if(q.sql.includes('gc_approval_command')){submitted=JSON.parse(q.parameters[1] as string);return [{value:{request:receipt()}}];}
  if(q.sql.includes('select r.*')){const r=receipt();return [{id:r.id,binding:r.binding,resource_id:r.resourceId,resource_version:r.resourceVersion,payload:r.payload,proposal_digest:r.proposalDigest,
   workflow_id:r.workflowId,workflow_version:r.workflowVersion,workflow_hash:r.workflowHash,requester_id:actor,stage_index:0,version:8,status:'ready',expires_at:r.expiresAt,created_at:stamp,updated_at:stamp,result:null,error_code:null,preconditions_current:!f.replay}];}
  return [];
 };
 const connection:DatabaseConnection={async executeQuery<R>(q:CompiledQuery):Promise<QueryResult<R>>{calls.push(q);return {rows:respond(q) as R[]};},async *streamQuery<R>():AsyncIterableIterator<QueryResult<R>>{throw new Error('No streaming in unit boundary');}};
 class Driver extends DummyDriver{override async acquireConnection(){return connection;}}
 const db=new Kysely<Record<string,any>>({dialect:{createAdapter:()=>new PostgresAdapter(),createDriver:()=>new Driver(),createIntrospector:db=>new PostgresIntrospector(db),createQueryCompiler:()=>new PostgresQueryCompiler()}});
 return {tx:db as unknown as Tx,calls,close:()=>db.destroy()};
}
const code=(expected:string)=>(error:unknown)=>error instanceof Problem&&error.code===expected;
const submit=(db:ReturnType<typeof database>,f:Fixture)=>submitGlossaryProposal(db.tx,p,actor,'synthetic-submit-key',f.input);
const targetAsset=(changes:Record<string,unknown>={})=>({id:target,version:1,model_id:'business_term',model_version:1,type_state:'active',type:'business_term',source_id:null,status:'active',visibility:'tenant',allowed_identities:[],...changes});
function linked(f:Fixture,kind:'broader'|'related'|'defines'='broader'){
 f.assets=[targetAsset()];f.input.publication={...f.input.publication,links:[{kind,typePin:{relationTypeId:relationId,version:1,definitionHash:modelPersistence.hash(f.relation)},targetAssetId:target,targetAssetVersion:1}]};return f;
}
async function refused(f:Fixture,expected:string,override?:Parameters<typeof database>[1]){const db=database(f,override);try{await assert.rejects(submit(db,f),code(expected));assert.equal(db.calls.some(q=>q.sql.includes('gc_approval_command')),false);}finally{await db.close();}}

test('glossary submission rejects executable/extra/malformed outer fields before SQL or property evaluation',async()=>{
 const f=fixture(),db=database(f);let reads=0;
 try{for(const input of [{...f.input,extra:true},{...f.input,resourceVersion:0},{...f.input,workflowPin:{...f.input.workflowPin,version:'1'}},{...f.input,expiresAt:'2026-02-30T00:00:00.000Z'},
  {...f.input,assignments:{owner:reviewer,constructor:actor}},Object.defineProperty({...f.input},'publication',{get(){reads++;return f.input.publication;}})])
  await assert.rejects(submitGlossaryProposal(db.tx,p,actor,'synthetic-submit-key',input as GlossaryProposalInput),code('GLOSSARY_INPUT_INVALID'));
  assert.equal(reads,0);assert.equal(db.calls.length,0);
 }finally{await db.close();}
});
test('real compiled boundary uses complete ordered locks and protected submit only, retaining normalized exact command',async()=>{
 const f=fixture();(f.input.publication.attributes.translations as any[])[0].name='  Cafe\u0301  ';const db=database(f);
 try{const result=await submit(db,f);assert.equal(result.request.version,1);assert.equal(result.request.status,'pending');
  const command=db.calls.find(q=>q.sql.includes('gc_approval_command'))!;assert.deepEqual(JSON.parse(command.parameters[1] as string),body(f.input));assert.equal((result.request.payload.attributes.translations as any[])[0].name,'Café');
  const index=(text:string)=>db.calls.findIndex(q=>q.sql.includes(text));assert.ok(index('pg_advisory_xact_lock')<index('gc_lock_type_migration_principals'));
  assert.ok(index('gc_lock_type_migration_principals')<index('select id from public.assets'));assert.ok(index('select id from public.assets')<index('select id,type_id,current_version from public.governance_models'));
  assert.deepEqual(db.calls[index('gc_lock_type_migration_principals')].parameters[0],[actor,reviewer,owner]);
  const hidden=db.calls.find(q=>q.sql.includes('from unnest('))!;assert.match(hidden.sql,/a\.tenant_id=\$/);assert.match(hidden.sql,/unnest\(\$\d+::uuid\[\]\) viewer/);assert.ok(index('from unnest(')<index('coalesce(sum(octet_length'));
  assert.equal(db.calls.filter(q=>q.sql.includes('gc_approval_command')).length,1);assert.equal(db.calls.some(q=>/\binsert into|\bupdate public|\bdelete from/i.test(q.sql)),false);
  const timeouts=db.calls.filter(q=>q.sql.includes("set_config('statement_timeout'"));assert.ok(timeouts.length>12);for(let i=1;i<timeouts.length;i++)assert.ok(Number(timeouts[i].parameters[0])<=Number(timeouts[i-1].parameters[0]));
 }finally{await db.close();}
});
test('current authority, complete active participants and proposed reviewer ACL deny before protected command',async()=>{
 const noAuthority=fixture();noAuthority.actorAllowed=false;await refused(noAuthority,'FORBIDDEN');
 const inactive=fixture();inactive.inactive=true;await refused(inactive,'GLOSSARY_PARTICIPANT_UNAVAILABLE');
 const hidden=fixture();hidden.hidden=true;await refused(hidden,'GLOSSARY_REFERENCE_UNAVAILABLE');
 const acl=fixture();acl.input.publication={...acl.input.publication,visibility:'restricted',allowedIdentityIds:[actor]};await refused(acl,'GLOSSARY_REVIEW_VISIBILITY');
 const noReviewPermission=fixture();await refused(noReviewPermission,'GLOSSARY_PARTICIPANT_UNAVAILABLE',q=>q.sql.includes('select m.identity_id')?[actor,owner,reviewer].map(identity_id=>({identity_id,active:true,identity_active:true,can_review:identity_id!==reviewer})):undefined);
});
test('new submission enforces resource existence, authored provenance, exact versions and no implicit migration',async()=>{
 const cases:[Record<string,unknown>,string][]=[[{version:2},'VERSION_CONFLICT'],[{source_id:id(99)},'GLOSSARY_POLICY_INVALID'],[{type:'table'},'GLOSSARY_POLICY_INVALID'],[{model_version:2},'GLOSSARY_POLICY_INVALID'],[{status:'missing'},'GLOSSARY_POLICY_INVALID']];
 for(const [change,expected] of cases){const f=fixture();f.input.resourceVersion=1;f.assets=[targetAsset({id:resource,...change})];await refused(f,expected);}
 const duplicate=fixture();duplicate.assets=[targetAsset({id:resource})];await refused(duplicate,'VERSION_CONFLICT');
 const absent=fixture();absent.input.resourceVersion=1;await refused(absent,'GLOSSARY_REFERENCE_UNAVAILABLE');
});
test('exact stored type pins, model attributes and lifecycle are mandatory before approval',async()=>{
 const stale=fixture();stale.headVersion=2;await refused(stale,'GLOSSARY_PIN_STALE');
 const hash=fixture();hash.input.publication={...hash.input.publication,typePin:{...hash.input.publication.typePin,definitionHash:'f'.repeat(64)}};await refused(hash,'GLOSSARY_PIN_STALE');
 const attrs=fixture();attrs.input.publication={...attrs.input.publication,attributes:{...attrs.input.publication.attributes,unregistered:true}};await refused(attrs,'GLOSSARY_ATTRIBUTES_INVALID');
 const lifecycle=fixture();lifecycle.input.publication={...lifecycle.input.publication,state:'deprecated'};await refused(lifecycle,'GLOSSARY_POLICY_INVALID');
 const corrupt=fixture();corrupt.row.resolution_hash='a'.repeat(64);await refused(corrupt,'ASSET_TYPE_STORAGE_INVALID');
});
test('typed broader links require directed acyclic single-parent semantics and authored term endpoints',async()=>{
 const f=linked(fixture()),db=database(f);try{await submit(db,f);assert.equal(db.calls.filter(q=>q.sql.includes('gc_approval_command')).length,1);}finally{await db.close();}
 for(const change of [{direction:'undirected',cardinality:{outgoing:{min:0,max:1},incoming:{min:0,max:1}}},{cycles:'allow'},{cardinality:{outgoing:{min:0,max:2},incoming:{min:0,max:null}}}]){
  const item=linked(fixture());item.relation={...item.relation,...change} as typeof item.relation;item.input.publication={...item.input.publication,links:[{...item.input.publication.links[0],typePin:{...item.input.publication.links[0].typePin,definitionHash:modelPersistence.hash(item.relation)}}]};await refused(item,'GLOSSARY_POLICY_INVALID');
 }
 const physical=linked(fixture(),'related');physical.assets=[targetAsset({source_id:id(99)})];await refused(physical,'GLOSSARY_POLICY_INVALID');
 const hidden=linked(fixture());hidden.assets=[targetAsset({visibility:'restricted',allowed_identities:[actor]})];await refused(hidden,'GLOSSARY_REFERENCE_UNAVAILABLE');
 const missing=linked(fixture());missing.assets=[targetAsset({status:'missing'})];await refused(missing,'GLOSSARY_REFERENCE_UNAVAILABLE');
 const changed=linked(fixture());changed.assets=[targetAsset({version:2})];await refused(changed,'VERSION_CONFLICT');
});
test('actual endpoint validator refuses a relation with incompatible registered target type or state',async()=>{
 for(const patch of [{targetTypes:[{typeId:id(90),includeDescendants:false}]},{targetStates:['deprecated']}]){
  const f=linked(fixture(),'defines');f.relation={...f.relation,...patch};f.input.publication={...f.input.publication,links:[{...f.input.publication.links[0],typePin:{...f.input.publication.links[0].typePin,definitionHash:modelPersistence.hash(f.relation)}}]};await refused(f,'GLOSSARY_LINK_INVALID');
 }
 const self=fixture();self.input.publication={...self.input.publication,links:[{kind:'related',typePin:{relationTypeId:relationId,version:1,definitionHash:modelPersistence.hash(self.relation)},targetAssetId:resource,targetAssetVersion:1}]};await refused(self,'GLOSSARY_POLICY_INVALID');
});
test('workflow current pin, exact assignment coverage and separation of duties remain enforced',async()=>{
 const stale=fixture();stale.workflowVersion=2;await refused(stale,'WORKFLOW_PIN_STALE');
 const extra=fixture();extra.input.assignments={owner:reviewer,unbound:owner};await refused(extra,'GLOSSARY_POLICY_INVALID');
 const self=fixture();self.input.assignments={owner:actor};await refused(self,'GLOSSARY_POLICY_INVALID');
});
test('physical preflight rejects oversized canonical rows and policy before materialization',async()=>{
 const f=fixture();f.bytes='524289';await refused(f,'GLOSSARY_LIMIT');
 const db=database(f);try{await assert.rejects(submit(db,f),code('GLOSSARY_LIMIT'));assert.equal(db.calls.some(q=>q.sql.includes('select id,version,model_id')),false);}finally{await db.close();}
 const type=fixture();const oversized=database(type,q=>q.sql.includes('octet_length(definition::text)+')?[{bytes:524289}]:undefined);
 try{await assert.rejects(submit(oversized,type),code('GLOSSARY_LIMIT'));assert.equal(oversized.calls.some(q=>q.sql.includes('select model_id,version,definition,resolved')),false);}finally{await oversized.close();}
});
test('exact successful replay survives head/version drift while altered key reuse and current hidden scope refuse',async()=>{
 const f=linked(fixture());f.replay=modelPersistence.hash(body(f.input));f.headVersion=2;f.workflowVersion=2;f.assets=[targetAsset({version:9}),targetAsset({id:resource,version:3})];
 const db=database(f);try{const result=await submit(db,f);assert.equal(result.request.version,1);assert.equal(result.request.status,'pending');assert.equal(result.request.preconditionsCurrent,false);assert.equal(result.request.workflow.currentVersion,2);
  assert.equal(db.calls.some(q=>q.sql.includes('select model_id,version,definition,resolved')),false);assert.equal(db.calls.filter(q=>q.sql.includes('gc_approval_command')).length,1);
 }finally{await db.close();}
 f.replay='a'.repeat(64);await refused(f,'IDEMPOTENCY_CONFLICT');f.replay=modelPersistence.hash(body(f.input));f.hidden=true;await refused(f,'GLOSSARY_REFERENCE_UNAVAILABLE');f.hidden=false;f.inactive=true;await refused(f,'GLOSSARY_PARTICIPANT_UNAVAILABLE');
});


test('registered authored business-term descendants resolve exact ancestry rather than trusting model labels',async()=>{
 const f=fixture(),authored={formatVersion:1 as const,id:'regional_term',version:1,parents:[{id:'business_term',version:1}],attributes:{},overrideAttributes:[],requiredOwner:false,lifecycle:null};
 const resolved=ok(resolveAssetType(authored,[f.rootRow.definition]));f.row={model_id:authored.id,version:1,definition:authored,resolved,definition_hash:modelPersistence.hash(authored),resolution_hash:modelPersistence.hash(resolved)};
 f.input.publication={...f.input.publication,typePin:{modelId:authored.id,typeId:id(70),version:1,definitionHash:f.row.definition_hash,resolutionHash:f.row.resolution_hash}};
 const db=database(f);try{await submit(db,f);assert.ok(db.calls.some(q=>q.sql.includes('for share of m')));}finally{await db.close();}
 const fake=fixture(),unrelated={...fake.row.definition,id:'unrelated'};const unrelatedResolved=ok(resolveAssetType(unrelated,[]));
 fake.row={model_id:unrelated.id,version:1,definition:unrelated,resolved:unrelatedResolved,definition_hash:modelPersistence.hash(unrelated),resolution_hash:modelPersistence.hash(unrelatedResolved)};
 fake.input.publication={...fake.input.publication,typePin:{modelId:unrelated.id,typeId:id(70),version:1,definitionHash:fake.row.definition_hash,resolutionHash:fake.row.resolution_hash}};
 await refused(fake,'GLOSSARY_POLICY_INVALID');
});
