// SPDX-License-Identifier: Apache-2.0
/** Real isolated native fixtures. Registries and producer bindings use the
 * owner installer; reviewed assignments use canonical gc_app commands. Source
 * completions below are synthetic authored metadata, not a connector scan. */
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import type {TestContext} from 'node:test';
import pg from 'pg';
import {Kysely,PostgresDialect} from 'kysely';
import {db as unusedDefaultDb,sql,lockTenantLedger,type Tx} from '../../packages/db/src/index.ts';
import {configureRelationTransaction} from '../../packages/domain/src/relation-store.ts';
import {claimSourceScan,completeSourceScan} from '../../apps/api/src/source-scans.ts';
import {assetView} from '../../apps/api/src/repository.ts';
import {createAuthorityFoundationRepository} from '../../packages/authority-storage/src/repository.ts';
import {AuthorityFoundationError,type NativeOwnerPool} from '../../packages/authority-storage/src/contracts.ts';
import type {InactiveClassifiedAssetContext} from '../../packages/authority-runtime/src/classified-asset-context.ts';
import {hashAuthorityRegistry} from '../../packages/authority/src/decision-identity.ts';
import {decisionHash,canonicalDecisionJSON} from '../../packages/authority/src/decision-schema.ts';
import type {ProducerRegistration,ProducerRef} from '../../packages/authority/src/decision-types.ts';
import type {Counter,Digest,UUID,UTC,Version} from '../../packages/authority/src/types.ts';
import type {ClassificationPin,ClassificationTaxonomy,MetadataClassificationRule,ClassificationEvaluationView,ClassificationApprovalResult} from '../../packages/domain/src/classification-contracts.ts';
import type {ApprovalDefinition} from '../../packages/domain/src/approval-contracts.ts';
import {makeDecisionFixture,parsed,type Mutable} from '../unit/fixtures/authority-decision.ts';
import {foundationInstall,type FoundationFixture} from './authority-foundation.ts';
import * as authn from './authority-authn-foundation.ts';

export {query,scalar,tx,extra,rejected,SqlFailure,uuid,dbNow,waitBlocked,config,connect} from './authority-authn-foundation.ts';
const {query,scalar,tx,uuid,dbNow,config}=authn;
export const closeDefaultDb=()=>unusedDefaultDb.destroy();
export const permissions=['catalog:read','catalog:write','models:read','models:write','classification:read','classification:write','classification:approve','sources:read','sources:write','audit:read'];
export const implementation='reviewed-metadata-classification-v1';
export const failure=(code:string)=>(e:unknown)=>e instanceof AuthorityFoundationError&&e.code==='AUTHORITY_FOUNDATION_'+code;
export const zero='0'.repeat(64) as Digest;
type DefinitionView<T>={id:string;version:number;definitionHash:string;definition:T};
export type TaxonomyView=DefinitionView<ClassificationTaxonomy>;
export type RuleView=DefinitionView<MetadataClassificationRule>;
export interface ProducerReceipt {
 formatVersion:1;installationId:string;tenantId:string;version:number;operation:'bind'|'revoke';implementation:typeof implementation;
 producer:{id:string;version:number};authorityEpochAfter:string;manifestHash:string;recordedAt:string;
}
export interface ProducerSnapshot {
 formatVersion:1;tenantId:string;generation:string;authorityEpoch:string;registryId:string;registryVersion:number;registryDigest:string;asOf:string;
 binding:null|{installationId:string;version:number;operation:'bind'|'revoke';implementation:typeof implementation;producer:{id:string;version:number};authorityEpochAfter:string;manifestHash:string};
}
export interface ProducerCall {sql:string;values:unknown[];operation:'bind'|'revoke';tenant:string}
const stringScalar=(value:string)=>`S${Buffer.byteLength(value,'utf8')}:${value}`;
const field=(name:string,value:unknown,kind:'S'|'I'|'U')=>stringScalar(name)+(value===null?'N;':kind==='S'?stringScalar(String(value)):`${kind}${value};`);
/** Independent codec: never calls a SQL encoding/hash function. */
export function requestEncoding(call:ProducerCall):Buffer{
 const names=['request_id','release_ref','operator_ref','expected_db_oid','expected_owner_oid','tenant_id','expected_generation','expected_authn_fence_epoch','expected_authority_epoch','expected_binding_version','expected_previous_installation_id','registry_id','registry_version','registry_digest','producer_id','producer_version'];
 const kinds=['U','S','S','I','I','U','I','I','I','I','U','U','I','S','U','I'] as const,values=call.operation==='bind'?call.values:[...call.values,null,null];assert.equal(values.length,names.length);
 return Buffer.from('gc-reviewed-classification-producer-request/v1;'+stringScalar(call.operation)+field('implementation',implementation,'S')+names.map((name,i)=>field(name,values[i],kinds[i]!)).join(''),'utf8');
}
export function receiptEncoding(call:ProducerCall,receipt:ProducerReceipt,previousManifestHash:string|null):Buffer{
 return Buffer.from('gc-reviewed-classification-producer-receipt/v1;'+field('request_encoding',requestEncoding(call).toString('utf8'),'S')+field('installation_id',receipt.installationId,'U')+field('version',receipt.version,'I')+field('previous_manifest_hash',previousManifestHash,'S')+field('producer_id',receipt.producer.id,'U')+field('producer_version',receipt.producer.version,'I')+field('recorded_at',receipt.recordedAt,'S')+field('authority_epoch_after',receipt.authorityEpochAfter,'I'),'utf8');
}
export interface Fixture extends FoundationFixture {
 database:Kysely<Record<string,any>>;sourceId:string;assetId:string;reviewers:string[];
 producers:{primary:Mutable<ProducerRegistration>;nextVersion:Mutable<ProducerRegistration>;alternative:Mutable<ProducerRegistration>;foreign:Mutable<ProducerRegistration>;wrongKind:Mutable<ProducerRegistration>;retired:Mutable<ProducerRegistration>;future:Mutable<ProducerRegistration>;expired:Mutable<ProducerRegistration>};
}
export const pin=(view:ClassificationPin):ClassificationPin=>({id:view.id,version:view.version,definitionHash:view.definitionHash});
export const taxonomy=(keys=['contact']):ClassificationTaxonomy=>({formatVersion:1,name:'Synthetic metadata sensitivity',description:'Synthetic independently reviewed classifications.',labels:keys.map(key=>({key,name:'Synthetic '+key,description:'Requires independent review.',status:'active'}))});
export const rule=(f:Fixture,tax:ClassificationPin,key='contact'):MetadataClassificationRule=>({formatVersion:1,kind:'metadata-literal',name:'Synthetic email-name rule',purpose:'Classify metadata only after independent review.',ownerId:f.identity,status:'active',assetTypes:['column'],label:{taxonomy:pin(tax),labelKey:key},all:[{field:'name',operator:'contains',comparison:'ascii-insensitive',literal:'email'}]});

export async function scope(client:pg.Client,f:Fixture,tenant=f.tenant,actor=f.identity){await query(client,"SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[tenant,actor]);}
export async function fixture(t:TestContext,options:{bind?:boolean;source?:boolean;producerLifetimeMs?:number;emptyRegistry?:boolean}={}):Promise<Fixture>{
 const base=await authn.fixture(t),s=await authn.session(base),registry=makeDecisionFixture().registry,now=await dbNow(base.owner),primaryId=uuid() as UUID;
 // Qualification fixtures are serial. A fresh real version keeps an empty
 // producer document distinct from the predecessor's globally unique digest.
 const registryVersion=Number((await scalar(base.owner,'SELECT coalesce(max(version),0)::bigint+1 version FROM gc_authority.registries')).version);
 assert.ok(Number.isSafeInteger(registryVersion)&&registryVersion>0&&registryVersion<=2147483647);registry.version=registryVersion as Version;
 const registration=(id:UUID=uuid() as UUID,version=1,extra:Partial<Mutable<ProducerRegistration>>={}):Mutable<ProducerRegistration>=>({ref:{id,version:version as Version},kind:'classifications',tenantId:base.tenant as UUID,state:'active',validity:{notBefore:null,expiresAt:null},...extra});
 const producers={primary:registration(primaryId,1,options.producerLifetimeMs===undefined?{}:{validity:{notBefore:null,expiresAt:new Date(Date.parse(now)+options.producerLifetimeMs).toISOString() as UTC}}),nextVersion:registration(primaryId,2),alternative:registration(),foreign:registration(undefined,1,{tenantId:base.otherTenant as UUID}),wrongKind:registration(undefined,1,{kind:'approved-tags'}),retired:registration(undefined,1,{state:'retired'}),future:registration(undefined,1,{validity:{notBefore:new Date(Date.parse(now)+3600000).toISOString() as UTC,expiresAt:null}}),expired:registration(undefined,1,{validity:{notBefore:null,expiresAt:new Date(Date.parse(now)-1000).toISOString() as UTC}})};
 registry.producers=options.emptyRegistry?[]:Object.values(producers);const {digest:_digest,...body}=registry;registry.digest=parsed(hashAuthorityRegistry(body));
 const registryId=uuid();await foundationInstall(base.owner,'registry-install',[registryId,registry.version,JSON.stringify(registry),registry.digest]);
 for(const tenant of [base.tenant,base.otherTenant])await foundationInstall(base.owner,'tenant-initialize',[tenant,'1',1,registryId,registry.version,registry.digest]);
 const database=new Kysely<Record<string,any>>({dialect:new PostgresDialect({pool:new pg.Pool({connectionString:config.legacy,max:2,connectionTimeoutMillis:5000})})});t.after(()=>database.destroy());
 const assetId=uuid(),f:Fixture={...base,hash:s.hash,csrf:s.csrf,protectedSession:s.row,registry,registryId,now:now as UTC,pending:[],people:new Set([base.identity as UUID]),request:{action:'asset:metadata.read',resource:{tenantId:base.tenant as UUID,kind:'asset',id:assetId as UUID},revision:1 as Version,field:null},model:{grants:[],policies:[],definitions:[],memberships:[],parents:new Map(),uses:[]},database,sourceId:uuid(),assetId,reviewers:[uuid(),uuid(),uuid()],producers};
 for(const reviewer of f.reviewers)await query(f.owner,'INSERT INTO public.identities(id,issuer,subject,name) VALUES($1::uuid,$2,$1::uuid::text,$3)',[reviewer,f.issuer,'Synthetic independent reviewer']);
 for(const tenant of [f.tenant,f.otherTenant])await tx(f.owner,async()=>{
  await scope(f.owner,f,tenant);await query(f.owner,'UPDATE public.memberships SET permissions=$3::jsonb WHERE tenant_id=$1 AND identity_id=$2',[tenant,f.identity,JSON.stringify(permissions)]);
  for(const reviewer of f.reviewers)await query(f.owner,"INSERT INTO public.memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,'synthetic',$3::jsonb)",[tenant,reviewer,JSON.stringify(permissions)]);
 });
 await query(f.owner,"SELECT set_config('gc.tenant_id',$1,false),set_config('gc.actor_id',$2,false)",[f.tenant,f.identity]);
 if(options.source!==false){
  await tx(f.owner,async()=>{await scope(f.owner,f);await query(f.owner,'INSERT INTO public.sources(tenant_id,id,name,host,port,database_name,schema_name,secret_ref,connector_id) VALUES($1,$2,$3,$4,5432,$5,$6,$7,$8)',[f.tenant,f.sourceId,'Synthetic reviewed classification source','classification-source.invalid','synthetic','owned','synthetic-unused','postgresql']);});
  await observe(f);const selected=await scalar(f.owner,"SELECT id FROM public.assets WHERE tenant_id=$1 AND source_id=$2 AND type='column'",[f.tenant,f.sourceId]);f.assetId=selected.id;f.request={...f.request,resource:{...f.request.resource,id:selected.id as UUID}};
 }
 if(options.bind!==false)await bind(f);
 return f;
}

export async function as<T>(f:Fixture,work:(transaction:Tx)=>Promise<T>,actor=f.identity,tenant=f.tenant):Promise<T>{
 return f.database.transaction().execute(async transaction=>{await sql`SELECT set_config('gc.tenant_id',${tenant},true),set_config('gc.actor_id',${actor},true)`.execute(transaction);await configureRelationTransaction(transaction);await lockTenantLedger(transaction,tenant);return work(transaction);});
}
export async function command(f:Fixture,operation:string,body:unknown,key=uuid(),actor=f.identity){return as(f,async transaction=>(await sql<{value:any}>`SELECT public.gc_classification_command(${operation},${key},${JSON.stringify(body)}::jsonb,'reviewed-classification-native') value`.execute(transaction)).rows[0]!.value,actor);}
export async function approval(f:Fixture,operation:string,body:unknown,key=uuid(),actor=f.identity){return as(f,async transaction=>(await sql<{value:any}>`SELECT public.gc_approval_command(${operation},${key},${JSON.stringify(body)}::jsonb,'reviewed-classification-native') value`.execute(transaction)).rows[0]!.value,actor);}
export async function observe(f:Fixture,name='email_address',dataType='text'){
 const jobId=uuid();await as(f,transaction=>transaction.insertInto('jobs').values({tenant_id:f.tenant,id:jobId,source_id:f.sourceId,actor_id:f.identity,status:'queued'}).execute());
 await as(f,transaction=>claimSourceScan(transaction,f.tenant,jobId,'reviewed-classification-native'),'site:local');
 await as(f,transaction=>completeSourceScan(transaction,f.tenant,jobId,{observedAt:new Date().toISOString(),sourceVersion:'17 synthetic fixture',permissionFingerprint:'synthetic-reviewed-metadata',complete:true,records:[
  {externalId:'pg:42:schema:10',name:'owned',qualifiedName:'synthetic.owned',type:'schema',metadata:{oid:'10',provenance:'source-observed'}},
  {externalId:'pg:42:relation:101',name:'contacts',qualifiedName:'synthetic.owned.contacts',type:'table',parentExternalId:'pg:42:schema:10',metadata:{oid:'101',relationKind:'r',schema:'owned',table:'contacts',provenance:'source-observed'}},
  {externalId:'pg:42:relation:101:column:1',name,qualifiedName:'synthetic.owned.contacts.'+name,type:'column',parentExternalId:'pg:42:relation:101',metadata:{dataType,ordinalPosition:1,nullable:true,provenance:'source-observed'}}]},'reviewed-classification-native'),'site:local');
}
export async function asset(f:Fixture){return tx(f.owner,async()=>{await scope(f.owner,f);return scalar(f.owner,'SELECT * FROM public.assets WHERE tenant_id=$1 AND id=$2',[f.tenant,f.assetId]);});}
export async function reviseDescription(f:Fixture,description='Synthetic unselected description change'){
 return tx(f.owner,async()=>{await scope(f.owner,f);const row=await scalar(f.owner,'UPDATE public.assets SET description=$3,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND id=$2 RETURNING *',[f.tenant,f.assetId,description]);await query(f.owner,'INSERT INTO public.asset_revisions(tenant_id,asset_id,version,snapshot) VALUES($1,$2,$3,$4::jsonb)',[f.tenant,f.assetId,row.version,JSON.stringify(assetView(row))]);return row;});
}
export async function publishTaxonomy(f:Fixture,definition=taxonomy(),id:string=uuid(),expectedVersion=0):Promise<TaxonomyView>{return (await command(f,'classification.taxonomy.publish',{id,expectedVersion,definition})).taxonomy;}
export async function publishRule(f:Fixture,definition:MetadataClassificationRule,id:string=uuid(),expectedVersion=0):Promise<RuleView>{return (await command(f,'classification.rule.publish',{id,expectedVersion,definition})).rule;}
export async function setup(f:Fixture,key='contact'){const tax=await publishTaxonomy(f,taxonomy([key])),selected=await publishRule(f,rule(f,tax,key));return {taxonomy:tax,rule:selected};}
export async function evaluate(f:Fixture,selected:ClassificationPin):Promise<ClassificationEvaluationView>{return (await command(f,'classification.evaluate',{id:uuid(),assetId:f.assetId,expectedAssetVersion:(await asset(f)).version,rule:pin(selected)})).evaluation;}
export async function workflow(f:Fixture,options:{stages?:number;quorum?:number;assignments?:number;deadlineSeconds?:number}={}){
 const stageCount=options.stages??1,assignmentCount=options.assignments??2,quorum=options.quorum??assignmentCount;assert.ok(stageCount>=1&&stageCount<=16&&assignmentCount>=1&&assignmentCount<=f.reviewers.length);
 const keys=Array.from({length:assignmentCount},(_,i)=>'reviewer_'+i),id='classification_'+uuid().replaceAll('-','');
 const definition:ApprovalDefinition={formatVersion:1,id,version:1,name:'Synthetic independent classification review',separationOfDuties:true,stages:Array.from({length:stageCount},(_,i)=>({id:'stage_'+i,name:'Independent stage '+i,assignments:keys,quorum,deadlineSeconds:options.deadlineSeconds??3600,rejection:'any'}))};
 const result=await approval(f,'approval.definition.publish',{definition,expectedVersion:0});return {pin:{id,version:1,definitionHash:result.definitionHash} as ClassificationPin,definition,assignments:Object.fromEntries(keys.map((key,i)=>[key,f.reviewers[i]!]))};
}
export type Workflow=Awaited<ReturnType<typeof workflow>>;
export async function propose(f:Fixture,evaluation:ClassificationEvaluationView,w:Workflow,expectedAssignmentVersion=0){
 const id=uuid();await command(f,'classification.propose',{id,change:{kind:'apply',suggestionId:evaluation.id,expectedAssignmentVersion},workflow:w.pin,assignments:w.assignments,expiresAt:new Date(Date.parse(await dbNow(f.owner))+3600000).toISOString()});return id;
}
export async function request(f:Fixture,id:string){return tx(f.owner,async()=>{await scope(f.owner,f);return {row:await scalar(f.owner,'SELECT * FROM public.approval_requests WHERE tenant_id=$1 AND id=$2',[f.tenant,id]),tasks:(await query(f.owner,'SELECT * FROM public.approval_tasks WHERE tenant_id=$1 AND request_id=$2 ORDER BY stage_index,assignment',[f.tenant,id])).rows,decisions:(await query(f.owner,'SELECT * FROM public.approval_decisions WHERE tenant_id=$1 AND request_id=$2 ORDER BY id',[f.tenant,id])).rows};});}
export async function decide(f:Fixture,id:string,reviewer=f.reviewers[0]!,decision:'approve'|'reject'='approve'){
 const current=await request(f,id),task=current.tasks.find(row=>row.stage_index===current.row.stage_index&&row.assigned_identity_id===reviewer);assert.ok(task);
 return approval(f,'approval.decide',{requestId:id,proposalDigest:current.row.proposal_digest,taskId:task.id,taskVersion:task.version,decision,reason:'Reviewed synthetic metadata evidence independently'},uuid(),reviewer);
}
export async function tick(f:Fixture,id:string){return as(f,async transaction=>(await sql<{value:any}>`SELECT public.gc_approval_tick(${id}::uuid) value`.execute(transaction)).rows[0]!.value,'site:local');}
export async function ready(f:Fixture,id:string,w:Workflow){
 for(let stage=0;stage<w.definition.stages.length;stage++){
  for(let reviewer=0;reviewer<w.definition.stages[stage]!.quorum;reviewer++)await decide(f,id,f.reviewers[reviewer]!);
  const result=await tick(f,id);assert.equal(result.status,stage===w.definition.stages.length-1?'ready':'pending');
 }
}
export async function publish(f:Fixture,id:string):Promise<ClassificationApprovalResult>{return as(f,async transaction=>(await sql<{value:ClassificationApprovalResult}>`SELECT public.gc_classification_publish(${id}::uuid) value`.execute(transaction)).rows[0]!.value);}
export async function apply(f:Fixture,options:{key?:string;workflow?:Workflow;selected?:RuleView;expectedAssignmentVersion?:number}={}){
 const definitions=options.selected?null:await setup(f,options.key),selected=options.selected??definitions!.rule,w=options.workflow??await workflow(f),evaluation=await evaluate(f,selected),requestId=await propose(f,evaluation,w,options.expectedAssignmentVersion??0);
 await ready(f,requestId,w);const result=await publish(f,requestId);return {taxonomy:definitions?.taxonomy,rule:selected,workflow:w,evaluation,requestId,result};
}
export async function withdraw(f:Fixture,assignment:ClassificationApprovalResult,w?:Workflow){
 const selected=w??await workflow(f),id=uuid();await command(f,'classification.propose',{id,change:{kind:'withdraw',assignmentId:assignment.assignmentId,expectedAssignmentVersion:assignment.assignmentVersion,reason:'Withdraw after independent synthetic review'},workflow:selected.pin,assignments:selected.assignments,expiresAt:new Date(Date.parse(await dbNow(f.owner))+3600000).toISOString()});await ready(f,id,selected);return {requestId:id,result:await publish(f,id)};
}

export async function producerCall(f:Fixture,operation:'bind'|'revoke',options:{tenant?:string;producer?:ProducerRef;requestId?:string;overrides?:Record<number,unknown>}={}):Promise<ProducerCall>{
 const tenant=options.tenant??f.tenant,identity=await scalar(f.owner,"SELECT (SELECT oid::text FROM pg_database WHERE datname=current_database()) db,(SELECT oid::text FROM pg_roles WHERE rolname=session_user) owner");
 const current=await tx(f.owner,async()=>{await scope(f.owner,f,tenant);return scalar(f.owner,`SELECT h.generation::text,h.authority_epoch::text,a.epoch::text authn_fence_epoch,
 coalesce(p.version,0) binding_version,p.installation_id FROM gc_authority.tenant_heads h JOIN gc_authn.tenant_fences a USING(tenant_id)
 LEFT JOIN gc_authority.classification_producer_heads p USING(tenant_id) WHERE h.tenant_id=$1`,[tenant]);});
 const values:unknown[]=[options.requestId??uuid(),'synthetic-reviewed-classification-release','synthetic-native-qualification',identity.db,identity.owner,tenant,current.generation,current.authn_fence_epoch,current.authority_epoch,current.binding_version,current.installation_id??null,f.registryId,f.registry.version,f.registry.digest];
 if(operation==='bind'){const producer=options.producer??f.producers.primary.ref;values.push(producer.id,producer.version);}
 for(const [index,value]of Object.entries(options.overrides??{}))values[Number(index)]=value;
 const casts=['uuid','text','text','oid','oid','uuid','bigint','bigint','bigint','integer','uuid','uuid','integer','text',...(operation==='bind'?['uuid','integer']:[])];
 const name=operation==='bind'?'install_reviewed_classification_producer_v1':'revoke_reviewed_classification_producer_v1';
 return {operation,tenant,values,sql:`SELECT gc_authority.${name}(${values.map((_,i)=>'$'+(i+1)+'::'+casts[i]).join(',')}) receipt`};
}
export async function executeProducer(f:Fixture,call:ProducerCall,client=f.owner):Promise<ProducerReceipt>{
 let result:pg.QueryResult;
 try{result=await client.query(call.sql,call.values);}catch(error){
  const e=error&&typeof error==='object'?error as {code?:unknown;where?:unknown}:{};
  const code=typeof e.code==='string'&&/^[0-9A-Z]{5}$/.test(e.code)?e.code:'CONNECTION_FAILURE';
  // Retain only bounded function names and line numbers. PostgreSQL's raw
  // context can contain statements and arguments and must never enter logs.
  const frames=typeof e.where==='string'?[...e.where.matchAll(/PL\/pgSQL function ([a-z_][a-z_0-9.]{0,90})\([^\n]*?\) line ([0-9]{1,6})\b/g)].slice(0,12).map(match=>match[1]+':'+match[2]):[];
  throw new authn.SqlFailure(code,frames.length?' frames='+frames.join(','):'');
 }
 assert.equal(result.rowCount,1);const receipt=result.rows[0]!.receipt as ProducerReceipt;
 assert.equal(receipt.formatVersion,1);assert.equal(receipt.implementation,implementation);assert.equal(receipt.tenantId,call.tenant);assert.equal(receipt.operation,call.operation);
 assert.deepEqual(Object.keys(receipt).sort(),['formatVersion','installationId','tenantId','version','operation','implementation','producer','authorityEpochAfter','manifestHash','recordedAt'].sort());assert.equal(BigInt(receipt.authorityEpochAfter),BigInt(String(call.values[8]))+1n);assert.equal(receipt.version,Number(call.values[9])+1);assert.equal(new Date(receipt.recordedAt).toISOString(),receipt.recordedAt);
 const previous=call.values[10]===null?null:await scalar(f.admin,'SELECT manifest_hash,producer_id,producer_version FROM gc_authority.classification_producer_installations WHERE tenant_id=$1 AND id=$2',[call.tenant,call.values[10]]);
 assert.deepEqual(receipt.producer,call.operation==='bind'?{id:call.values[14],version:call.values[15]}:{id:previous!.producer_id,version:previous!.producer_version});
 const saved=await scalar(f.admin,'SELECT request_encoding,manifest_encoding,manifest_hash FROM gc_authority.classification_producer_installations WHERE tenant_id=$1 AND id=$2',[call.tenant,receipt.installationId]),request=requestEncoding(call),manifest=receiptEncoding(call,receipt,previous?.manifest_hash??null);
 assert.ok(request.length>0&&request.length<=4096&&manifest.length>0&&manifest.length<=4096);assert.equal(Buffer.isBuffer(saved.request_encoding)?saved.request_encoding.toString('utf8'):saved.request_encoding,request.toString('utf8'));assert.ok(Buffer.isBuffer(saved.manifest_encoding)&&saved.manifest_encoding.equals(manifest),'Stored receipt must equal the independently encoded typed manifest');assert.equal(createHash('sha256').update(manifest).digest('hex'),receipt.manifestHash);assert.equal(saved.manifest_hash,receipt.manifestHash);
 return receipt;
}
export async function bind(f:Fixture,producer=f.producers.primary.ref,client=f.owner){const call=await producerCall(f,'bind',{producer});return {call,receipt:await executeProducer(f,call,client)};}
export async function revokeProducer(f:Fixture,client=f.owner){const call=await producerCall(f,'revoke');return {call,receipt:await executeProducer(f,call,client)};}
export async function producerLookup(f:Fixture,client=f.owner,hash=f.hash):Promise<ProducerSnapshot>{return tx(client,async()=>(await scalar(client,'SELECT gc_authority.load_reviewed_classification_producer_v1($1::text) value',[hash])).value as ProducerSnapshot,'REPEATABLE READ READ ONLY');}
export async function heads(f:Fixture,tenant=f.tenant){return scalar(f.admin,'SELECT h.authority_epoch::text authority,c.revision::text content FROM gc_authority.tenant_heads h JOIN gc_authority.content_security_heads c USING(tenant_id) WHERE h.tenant_id=$1',[tenant]);}
export async function snapshot(f:Fixture,tenant=f.tenant){
 const tables=['gc_authority.classification_producer_heads','gc_authority.classification_producer_installations','gc_authority.tenant_heads','gc_authority.content_security_heads','gc_authority.write_bindings','gc_authority.write_lock_claims','gc_authority.lifecycle_revisions','public.classification_assignments','public.classification_assignment_revisions','public.classification_evaluations','public.approval_requests','public.approval_tasks','public.approval_decisions','public.audit','public.outbox','public.idempotency'];
 return (await query(f.admin,tables.map(table=>`SELECT '${table}' name,count(*)::text rows,encode(sha256(coalesce(string_agg(row_hash,''::bytea ORDER BY row_hash),''::bytea)),'hex') digest FROM (SELECT sha256(convert_to(to_jsonb(r)::text,'UTF8')) row_hash FROM ${table} r WHERE tenant_id=$1) s`).join(' UNION ALL ')+' ORDER BY name',[tenant])).rows;
}
export async function unchanged(f:Fixture,work:()=>Promise<unknown>,codes=['23514']){const before=await snapshot(f);await assert.rejects(work,authn.rejected(...codes));assert.deepEqual(await snapshot(f),before);}
export function readInput(f:Fixture,expectedVersion=1){return {sessionHash:f.hash as Digest,assetId:f.assetId as UUID,expectedVersion:expectedVersion as Version};}
export async function read(f:Fixture,expectedVersion=1,poolOverride?:NativeOwnerPool):Promise<InactiveClassifiedAssetContext>{
 const pool=poolOverride??new pg.Pool({connectionString:config.owner,max:1,connectionTimeoutMillis:5000});
 try{return await createAuthorityFoundationRepository(pool).loadClassifiedHumanAssetContext(readInput(f,expectedVersion));}
 finally{if(!poolOverride){await (pool as pg.Pool).end();assert.equal((pool as pg.Pool).totalCount,0);}}
}
export async function labelId(f:Fixture,taxonomyId:string,labelKey:string){return (await scalar(f.admin,'SELECT id FROM gc_authority.classification_label_identities WHERE tenant_id=$1 AND taxonomy_id=$2 AND label_key=$3',[f.tenant,taxonomyId,labelKey])).id as UUID;}
export {decisionHash,canonicalDecisionJSON};

/** Derived by the upgrade harness from a real pre032 reviewed publication,
 * then preserved across033–035. No synthetic assignment or backdated mapping. */
export interface PreBaselineFixture {
 formatVersion:1;tenantId:string;assetId:string;assetVersion:number;assignmentId:string;assignmentVersion:1;
 suggestionId:string;approvalRequestId:string;taxonomyId:string;labelKey:string;
 historicalTaxonomyVersion:1;historicalTaxonomyHash:string;baselineVersion:2;baselineHash:string;
 requesterId:string;ruleId:string;ruleVersion:1;
}
export function preBaselineFixtureMarker():PreBaselineFixture{
 const value=(config as typeof config&{reviewedClassificationPreBaselineFixture?:unknown}).reviewedClassificationPreBaselineFixture;
 assert.ok(value&&typeof value==='object'&&!Array.isArray(value),'Real upgrade assignment marker is required');
 const raw=value as Record<string,unknown>;
 for(const key of ['tenantId','assetId','assignmentId','suggestionId','approvalRequestId','taxonomyId','requesterId','ruleId']){
  assert.equal(typeof raw[key],'string');assert.match(raw[key] as string,/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);assert.notEqual(raw[key],'00000000-0000-0000-0000-000000000000');
 }
 assert.equal(raw.formatVersion,1);assert.equal(raw.assignmentVersion,1);assert.equal(raw.historicalTaxonomyVersion,1);assert.equal(raw.baselineVersion,2);assert.equal(raw.ruleVersion,1);
 assert.ok(typeof raw.assetVersion==='number'&&Number.isSafeInteger(raw.assetVersion)&&raw.assetVersion>0);
 assert.equal(typeof raw.labelKey,'string');assert.match(raw.labelKey as string,/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/);
 for(const key of ['historicalTaxonomyHash','baselineHash']){assert.equal(typeof raw[key],'string');assert.match(raw[key] as string,/^[0-9a-f]{64}$/);}
 return raw as unknown as PreBaselineFixture;
}
export async function adoptPreBaselineFixture(t:TestContext,marker:PreBaselineFixture):Promise<Fixture>{
 const f=await fixture(t,{bind:false,source:false});
 assert.deepEqual(await scalar(f.admin,`SELECT
  (SELECT count(*)::int FROM gc_authn.tenant_fences WHERE tenant_id=$1) authn,
  (SELECT count(*)::int FROM gc_authority.tenant_heads WHERE tenant_id=$1) authority`,[marker.tenantId]),{authn:0,authority:0});
 await tx(f.owner,async()=>{await scope(f.owner,f,marker.tenantId);await query(f.owner,
  "INSERT INTO public.memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,'synthetic-preserved-reader',$3::jsonb)",
  [marker.tenantId,f.identity,JSON.stringify(['catalog:read','classification:read'])]);});
 await authn.install(f.owner,'initialize-tenant',[marker.tenantId,1]);
 // Install a fresh actual-tenant registry; never amend the fixture's previous
 // immutable registry or either of its already initialized tenant pins.
 const originalTenant=f.tenant,registry=structuredClone(f.registry),producers=structuredClone(f.producers);
 for(const producer of Object.values(producers))if(producer.tenantId===originalTenant)producer.tenantId=marker.tenantId as UUID;
 registry.producers=Object.values(producers);const {digest:_digest,...body}=registry;registry.digest=parsed(hashAuthorityRegistry(body));
 const registryId=uuid();await foundationInstall(f.owner,'registry-install',[registryId,registry.version,JSON.stringify(registry),registry.digest]);
 await foundationInstall(f.owner,'tenant-initialize',[marker.tenantId,'1',1,registryId,registry.version,registry.digest]);
 const csrf=authn.digest(),selected=await scalar(f.api,'SELECT * FROM public.gc_authn_session_select($1,$2,$3,$4,$5)',
  [f.hash,f.csrf,f.protectedSession.session_version,marker.tenantId,csrf]);
 assert.equal(selected.selected_tenant_id,marker.tenantId);assert.equal(selected.session_version,f.protectedSession.session_version+1);
 f.tenant=marker.tenantId;f.assetId=marker.assetId;f.registry=registry;f.registryId=registryId;f.producers=producers;f.csrf=csrf;f.protectedSession=selected;
 f.request={...f.request,resource:{...f.request.resource,tenantId:f.tenant as UUID,id:f.assetId as UUID},revision:marker.assetVersion as Version};
 await query(f.owner,"SELECT set_config('gc.tenant_id',$1,false),set_config('gc.actor_id',$2,false)",[f.tenant,f.identity]);
 const stored=await asset(f);assert.equal(stored.version,marker.assetVersion);assert.equal(stored.status,'active');assert.equal(typeof stored.source_id,'string');f.sourceId=stored.source_id;
 await bind(f);return f;
}
