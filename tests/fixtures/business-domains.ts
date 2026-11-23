// SPDX-License-Identifier: Apache-2.0
/** Real runtime-role SQL fixtures. Expected projections come from public rows and
 * the independent pure engine; tests never read/write private operation claims. */
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import type { OperationNodeSource } from 'kysely';
import { scope, sql, type Tx } from '../../packages/db/src/index.ts';
import type { Principal } from '../../packages/authz/src/index.ts';
import { resolveDomainType } from '../../packages/domain/src/business-domain-type.ts';
import { applyDomainTypeMigration } from '../../packages/domain/src/business-domain-migration.ts';
import { typeHash } from '../../packages/domain/src/asset-type-policy.ts';
import type { DomainTypeDefinition, DomainTypeView, DomainView, DomainRevision, DomainPlacementView, DomainPlacementRevision,
 DomainTypeMigrationPlan, DomainMigrationOutcome, DomainTypeMigrationReceipt } from '../../packages/domain/src/business-domain-contracts.ts';
import type { DomainMutationRequest } from '../../packages/domain/src/business-domain-service-contracts.ts';
import { assetView, once } from '../../apps/api/src/repository.ts';
export const tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
export const actor = '10000000-0000-4000-8000-000000000001';
export const ownerId = '10000000-0000-4000-8000-000000000002';
export const permissions = ['catalog:read','catalog:write','models:read','models:write','domains:read','domains:write','domains:assign','audit:read'];
export const principal: Principal = {tenantId:tenant,id:actor,name:'Synthetic domain steward',permissions};
export const correlation = 'synthetic-domain-storage';
export const reason = 'Synthetic domain qualification';
export const sqlCode = (...values:string[]) => (e:any) => values.includes(e.code);
export type Row = Record<string,any>;
export interface Begin {operationId:string;occurredAt:string;projectionHash:string;receiptHash?:string}
export interface Projection {response:Row;domainRevisions:DomainRevision[];placementRevision?:DomainPlacementRevision;outcomes?:readonly DomainMigrationOutcome[];type?:DomainTypeView}
export const digest = typeHash({synthetic:'Consent is independently qualified at the service boundary'});
export function definition(overrides:Partial<DomainTypeDefinition> = {}):DomainTypeDefinition {
 return {formatVersion:1,kind:'domain-type',id:'domain_'+randomUUID().replaceAll('-',''),version:1,label:'Synthetic business domain',parents:[],attributes:{},overrideAttributes:[],requiredOwner:false,
 lifecycle:{initial:'draft',states:['draft','active'],transitions:[{from:'draft',to:'active'},{from:'active',to:'draft'}]},...overrides};
}
export function migrationPlan(type:DomainTypeView,sourceVersions:number[],overrides:Partial<DomainTypeMigrationPlan> = {}):DomainTypeMigrationPlan {
 return {formatVersion:1,kind:'domain-type-migration',typeId:type.typeId,attributes:{formatVersion:1,modelId:type.key,targetVersion:type.currentVersion+1,sourceVersions,acknowledgedChanges:[],operations:[]},
 owner:{default:'preserve',overrides:[]},lifecycle:{onUnmapped:'preserve',mappings:[]},acknowledgedPolicyChanges:[],...overrides};
}
const iso=(v:unknown)=>new Date(v as string).toISOString();
export function domainView(row:Row):DomainView {
 return {id:row.id,name:row.name,description:row.description,parentId:row.parent_id,type:{typeId:row.type_id,version:row.type_version},attributes:row.attributes,ownerId:row.owner_id,
 state:row.state,status:row.status,version:row.version,createdAt:iso(row.created_at),createdBy:row.created_by,updatedAt:iso(row.updated_at),updatedBy:row.updated_by};
}
export function placementView(row:Row):DomainPlacementView {
 return {assetId:row.asset_id,version:row.version,domainId:row.domain_id,recordedAssetVersion:row.recorded_asset_version,recordedDomainVersion:row.recorded_domain_version,recordedAt:iso(row.recorded_at),recordedBy:row.recorded_by};
}
export async function typeView(tx:Tx,id:string,version?:number):Promise<DomainTypeView> {
 const head=await tx.selectFrom('domain_types').selectAll().where('id','=',id).executeTakeFirstOrThrow();
 const row=await tx.selectFrom('domain_type_versions').selectAll().where('type_id','=',id).where('version','=',version??head.current_version).executeTakeFirstOrThrow();
 return {typeId:id,key:head.key,version:row.version,currentVersion:head.current_version,definition:row.definition,resolved:row.resolved,definitionHash:row.definition_hash,resolutionHash:row.resolution_hash,createdAt:iso(row.created_at),createdBy:row.created_by};
}
async function dependencies(tx:Tx,definitions:readonly DomainTypeDefinition[]):Promise<{typeId:string;definition:DomainTypeDefinition}[]> {
 const result=new Map<string,{typeId:string;definition:DomainTypeDefinition}>();
 const visit=async(d:DomainTypeDefinition)=>{for(const pin of d.parents){const key=pin.typeId+'/'+pin.version;if(result.has(key))continue;
  assert.ok(result.size<64);const parent=await typeView(tx,pin.typeId,pin.version);result.set(key,{typeId:pin.typeId,definition:parent.definition});await visit(parent.definition);}};
 for(const d of definitions)await visit(d);return [...result.values()];
}
export const bodyFor=(request:DomainMutationRequest):Row=>{if(request.kind==='domain-type-migration.execute'){const {kind,...body}=request;return body;}return request;};
export async function begin(tx:Tx,request:DomainMutationRequest,id:string=randomUUID(),key:string=randomUUID()):Promise<Begin>{
 const body=bodyFor(request); const result=request.kind==='domain-type-migration.execute'
  ?await sql<{value:Begin}>`SELECT gc_domain_type_migration_begin(${id}::uuid,${key},${JSON.stringify(body)}::jsonb,${correlation}) value`.execute(tx)
  :await sql<{value:Begin}>`SELECT gc_domain_write_begin(${id}::uuid,${key},${JSON.stringify(body)}::jsonb,${correlation}) value`.execute(tx);
 return result.rows[0]!.value;
}
export async function project(tx:Tx,p:Principal,request:DomainMutationRequest,started:Begin):Promise<Projection>{
 const time=started.occurredAt,id=started.operationId,result:Projection={response:{},domainRevisions:[]};
 const why=request.kind==='domain.hierarchy'?request.change.reason:request.reason;
 const revision=(domain:DomainView,action:DomainRevision['action'])=>({formatVersion:1 as const,domain,action,reason:why,correlationId:correlation});
 if(request.kind==='domain-type.create'||request.kind==='domain-type.publish'||request.kind==='domain-type-migration.execute'){
  assert.ok('definition' in request);const proposed=request.definition;
  const typeId=request.kind==='domain-type.create'?id:('typeId' in request?request.typeId:'');
  const resolved=resolveDomainType(typeId,proposed,await dependencies(tx,[proposed]));assert.ok(resolved.ok);if(!resolved.ok)throw Error('Pure target resolution failed');
  const type:DomainTypeView={typeId,key:proposed.id,version:proposed.version,currentVersion:proposed.version,definition:proposed,resolved:resolved.value,definitionHash:typeHash(proposed),resolutionHash:typeHash(resolved.value),createdAt:time,createdBy:p.id};
  result.type=type;result.response={type};
  if(request.kind==='domain-type-migration.execute'){
   const head=await typeView(tx,typeId),domains=(await tx.selectFrom('domains').selectAll().where('type_id','=',typeId).orderBy('id').execute()).map(domainView);
   const sources=await Promise.all([...new Set(domains.map(d=>d.type.version))].sort((a,b)=>a-b).map(v=>typeView(tx,typeId,v)));
   const owners=[...new Set([...domains.map(d=>d.ownerId),...request.plan.owner.overrides.map(o=>o.ownerId)].filter((v):v is string=>v!==null))].sort();
   const ownerActivity=await Promise.all(owners.map(async identityId=>({identityId,active:!!(await tx.selectFrom('memberships as m').innerJoin('identities as i','i.id','m.identity_id')
    .select('m.identity_id').where('m.identity_id','=',identityId).where('m.active','=',true).where('i.active','=',true).executeTakeFirst())})));
   const projected=applyDomainTypeMigration({coverage:'complete-direct-domain-type-bindings',head,sources,target:{definition:proposed,resolved:resolved.value},domains,
    dependencies:await dependencies(tx,[head.definition,proposed,...sources.map(s=>s.definition)]),ownerActivity},request.plan);
   if(!projected.ok)throw Error('Pure migration projection failed: '+JSON.stringify(projected.issues));result.outcomes=projected.value;
   for(const outcome of projected.value){const before=domains.find(d=>d.id===outcome.domainId)!;result.domainRevisions.push(revision({...before,...outcome.after,version:outcome.toVersion,updatedAt:time,updatedBy:p.id},'type-migrated'));}
   const receipt:DomainTypeMigrationReceipt={formatVersion:1,id,typeId,fromHeadVersion:head.currentVersion,targetVersion:type.version,plan:request.plan,planHash:typeHash(request.plan),previewDigest:request.previewDigest,
    sourcePolicies:sources.map(s=>({pin:{typeId,version:s.version},definitionHash:s.definitionHash,resolutionHash:s.resolutionHash})),targetDefinitionHash:type.definitionHash,targetResolutionHash:type.resolutionHash,
    outcomes:projected.value,actorId:p.id,occurredAt:time,reason:why,correlationId:correlation};
   result.response={type,receipt};
   assert.equal(started.receiptHash,typeHash(receipt));
   assert.equal(started.projectionHash,typeHash({formatVersion:1,kind:'domain-type-migration-projection',typeId,fromHeadVersion:head.currentVersion,targetVersion:type.version,planHash:receipt.planHash,
    sourcePolicies:receipt.sourcePolicies,targetDefinitionHash:type.definitionHash,targetResolutionHash:type.resolutionHash,outcomes:receipt.outcomes}));
  }
 }else if(request.kind==='domain.placement'){
  const prior=await tx.selectFrom('asset_domain_placements').selectAll().where('asset_id','=',request.assetId).executeTakeFirst();
  const domain=request.domainId?domainView(await tx.selectFrom('domains').selectAll().where('id','=',request.domainId).executeTakeFirstOrThrow()):null;
  const placement:DomainPlacementView={assetId:request.assetId,version:(prior?.version??0)+1,domainId:request.domainId,recordedAssetVersion:request.assetVersion,recordedDomainVersion:request.domainVersion,recordedAt:time,recordedBy:p.id};
  result.placementRevision={formatVersion:1,placement,reason:why,correlationId:correlation};result.response={placement,domain};
 }else{
  let domain:DomainView,action:DomainRevision['action'];
  if(request.kind==='domain.create'){
   const policy=await typeView(tx,request.type.typeId,request.type.version);
   const {kind,reason:_,...tuple}=request;domain={id,...tuple,state:policy.resolved.lifecycle.initial,status:'active',version:1,createdAt:time,createdBy:p.id,updatedAt:time,updatedBy:p.id};action='created';
  }else{
   const domainId=request.kind==='domain.hierarchy'?request.change.domainId:request.domainId;
   const old=domainView(await tx.selectFrom('domains').selectAll().where('id','=',domainId).executeTakeFirstOrThrow());
   domain={...old,version:old.version+1,updatedAt:time,updatedBy:p.id};
   if(request.kind==='domain.update'){domain={...domain,name:request.name,description:request.description,attributes:request.attributes,ownerId:request.ownerId};action='updated';}
   else if(request.kind==='domain.state'){domain={...domain,state:request.state};action='state-changed';}
   else if(request.kind==='domain.hierarchy'&&request.change.kind==='move'){domain={...domain,parentId:request.change.parentId};action='moved';}
   else if(request.kind==='domain.hierarchy'){domain={...domain,status:request.change.kind==='retire'?'retired':'active'};action=request.change.kind==='retire'?'retired':'restored';}
   else throw Error('Unrecognized synthetic domain intent');
  }
  result.response={domain};result.domainRevisions=[revision(domain,action)];
 }
 if(request.kind!=='domain-type-migration.execute')assert.equal(started.projectionHash,typeHash({formatVersion:1,kind:'domain-write-projection',request:bodyFor(request),response:result.response}));
 return result;
}
export interface Faults {skipRevision?:boolean;skipJournal?:boolean;outboxFirst?:boolean;alterRow?:(row:Row)=>void;alterRevision?:(revision:Row)=>void;alterEvent?:(event:Row)=>void;omitDomain?:string}
export async function journal(tx:Tx,p:Principal,started:Begin,action:string,id:string,version:number,data:Row,why:string,faults:Faults={}){
 const eventId=randomUUID(),name=(await tx.selectFrom('identities').select('name').where('id','=',p.id).executeTakeFirstOrThrow()).name;
 const previous=(await tx.selectFrom('audit').select('hash').orderBy('sequence','desc').executeTakeFirst())?.hash??'0'.repeat(64);
 const changes={...data,reason:why,resourceVersion:version};
 const envelope:Row={id:eventId,tenantId:p.tenantId,actorId:p.id,actorName:name,action,resourceId:id,version,changes,correlationId:correlation,occurredAt:started.occurredAt,previousHash:previous};
 const outbox:Row={tenant_id:p.tenantId,id:eventId,event_type:action,resource_id:id,resource_version:version,created_at:started.occurredAt,
  payload:{specversion:'1.0',id:eventId,type:action,source:'governance-commons',subject:id,time:started.occurredAt,tenantId:p.tenantId,resourceVersion:version,actorId:p.id,correlationId:correlation,resourceKind:data.resourceKind,data}};
 faults.alterEvent?.(outbox);
 const audit=()=>tx.insertInto('audit').values({tenant_id:p.tenantId,id:eventId,actor_id:p.id,actor_name:name,action,resource_id:id,changes:JSON.stringify(changes),correlation_id:correlation,
  occurred_at:started.occurredAt,previous_hash:previous,hash:typeHash(envelope),envelope:JSON.stringify(envelope)}).execute();
 const event=()=>tx.insertInto('outbox').values({...outbox,payload:JSON.stringify(outbox.payload)}).execute();
 if(faults.outboxFirst){await event();await audit();}else{await audit();await event();}
}
export async function persist(tx:Tx,p:Principal,request:DomainMutationRequest,started:Begin,projection:Projection,faults:Faults={}){
 const why=request.kind==='domain.hierarchy'?request.change.reason:request.reason;
 if(projection.type){const t=projection.type;
  if(request.kind==='domain-type.create')await tx.insertInto('domain_types').values({tenant_id:p.tenantId,id:t.typeId,key:t.key,current_version:t.version,created_at:t.createdAt,created_by:p.id}).execute();
  else await tx.updateTable('domain_types').set({current_version:t.version}).where('id','=',t.typeId).execute();
  const row:Row={tenant_id:p.tenantId,type_id:t.typeId,version:t.version,definition:JSON.stringify(t.definition),resolved:JSON.stringify(t.resolved),definition_hash:t.definitionHash,resolution_hash:t.resolutionHash,created_at:t.createdAt,created_by:p.id};
  faults.alterRow?.(row);await tx.insertInto('domain_type_versions').values(row).execute();
  if(!faults.skipJournal)await journal(tx,p,started,request.kind==='domain-type.create'?'domain_type.created':'domain_type.published',t.typeId,t.version,
   {schemaVersion:1,resourceKind:'domain-type',typeId:t.typeId,previousVersion:request.kind==='domain-type.create'?null:t.version-1,version:t.version,definitionHash:t.definitionHash,resolutionHash:t.resolutionHash,migrationId:request.kind==='domain-type-migration.execute'?started.operationId:null},why,faults);
 }
 for(const r of projection.domainRevisions){const d=r.domain;if(d.id===faults.omitDomain)continue;
  const row:Row={tenant_id:p.tenantId,id:d.id,name:d.name,description:d.description,parent_id:d.parentId,type_id:d.type.typeId,type_version:d.type.version,attributes:JSON.stringify(d.attributes),owner_id:d.ownerId,state:d.state,status:d.status,
   version:d.version,created_at:d.createdAt,created_by:d.createdBy,updated_at:d.updatedAt,updated_by:d.updatedBy};faults.alterRow?.(row);
  if(r.action==='created')await tx.insertInto('domains').values(row).execute();else await tx.updateTable('domains').set(row).where('id','=',d.id).execute();
  const copied:Row=structuredClone(r);faults.alterRevision?.(copied);
  if(!faults.skipRevision)await tx.insertInto('domain_revisions').values({tenant_id:p.tenantId,domain_id:d.id,version:d.version,snapshot:JSON.stringify(copied)}).execute();
  if(!faults.skipJournal)await journal(tx,p,started,'domain.'+r.action.replaceAll('-','_'),d.id,d.version,{schemaVersion:1,resourceKind:'domain',domainId:d.id,previousVersion:d.version===1?null:d.version-1,version:d.version,revisionHash:typeHash(r),migrationId:request.kind==='domain-type-migration.execute'?started.operationId:null},why,faults);
 }
 if(projection.placementRevision){const r=projection.placementRevision,v=r.placement;
  const prior=await tx.selectFrom('asset_domain_placements').selectAll().where('asset_id','=',v.assetId).executeTakeFirst();
  const row:Row={tenant_id:p.tenantId,asset_id:v.assetId,version:v.version,domain_id:v.domainId,recorded_asset_version:v.recordedAssetVersion,recorded_domain_version:v.recordedDomainVersion,recorded_at:v.recordedAt,recorded_by:v.recordedBy};faults.alterRow?.(row);
  if(prior)await tx.updateTable('asset_domain_placements').set(row).where('asset_id','=',v.assetId).execute();else await tx.insertInto('asset_domain_placements').values(row).execute();
  const copied:Row=structuredClone(r);faults.alterRevision?.(copied);
  if(!faults.skipRevision)await tx.insertInto('asset_domain_placement_revisions').values({tenant_id:p.tenantId,asset_id:v.assetId,version:v.version,snapshot:JSON.stringify(copied)}).execute();
  if(!faults.skipJournal)await journal(tx,p,started,'asset_domain_placement.'+(v.domainId===null?'unassigned':prior?.domain_id?'reassigned':'assigned'),v.assetId,v.version,
   {schemaVersion:1,resourceKind:'asset-domain-placement',assetId:v.assetId,previousVersion:v.version-1,version:v.version,recordedAssetVersion:v.recordedAssetVersion,recordedDomainVersion:v.recordedDomainVersion,domainId:v.domainId,revisionHash:typeHash(r)},why,faults);
 }
 if(request.kind==='domain-type-migration.execute'&&!faults.skipJournal){const r=projection.response.receipt as DomainTypeMigrationReceipt;
  await journal(tx,p,started,'domain_type_migration.executed',r.id,1,{schemaVersion:1,resourceKind:'domain-type-migration',migrationId:r.id,typeId:r.typeId,fromHeadVersion:r.fromHeadVersion,targetVersion:r.targetVersion,planHash:r.planHash,previewDigest:r.previewDigest,receiptHash:typeHash(r)},why,faults);
 }
}
export async function seal(tx:Tx,request:DomainMutationRequest,id:string){return (request.kind==='domain-type-migration.execute'
 ?await sql<{value:Row}>`SELECT gc_domain_type_migration_seal(${id}::uuid) value`.execute(tx):await sql<{value:Row}>`SELECT gc_domain_write_seal(${id}::uuid) value`.execute(tx)).rows[0]!.value;}
export interface ExecuteOptions extends Faults {principal?:Principal;key?:string;operationId?:string;beforeBegin?:(tx:Tx)=>Promise<void>;afterBegin?:(tx:Tx,started:Begin)=>Promise<void>;
 beforeSeal?:(tx:Tx,started:Begin,projection:Projection)=>Promise<void>;afterSeal?:(tx:Tx,started:Begin,response:Row)=>Promise<void>;afterSuccess?:(tx:Tx)=>Promise<void>;alterSuccess?:(response:Row)=>Row}
export async function execute(request:DomainMutationRequest,options:ExecuteOptions={}):Promise<Row>{
 const p=options.principal??principal,key=options.key??randomUUID();
 return scope(p.tenantId,p.id,async tx=>{
  await options.beforeBegin?.(tx);
  const response=await once(tx,p,request.kind,key,bodyFor(request),async()=>{
   const started=await begin(tx,request,options.operationId??randomUUID(),key);await options.afterBegin?.(tx,started);
   const projection=await project(tx,p,request,started);await persist(tx,p,request,started,projection,options);await options.beforeSeal?.(tx,started,projection);
   const value=await seal(tx,request,started.operationId);assert.deepEqual(value,projection.response);await options.afterSeal?.(tx,started,value);return options.alterSuccess?.(value)??value;
  });await options.afterSuccess?.(tx);await sql`SET CONSTRAINTS ALL IMMEDIATE`.execute(tx);return response;
 });
}
export async function fixture(options:{principal?:Principal;definition?:Partial<DomainTypeDefinition>;parentId?:string|null;attributes?:Row;ownerId?:string|null;count?:number}={}){
 const p=options.principal??principal;const type=(await execute({kind:'domain-type.create',definition:definition(options.definition),reason},{principal:p})).type as DomainTypeView;
 const domains:DomainView[]=[];
 for(let index=0;index<(options.count??1);index++)domains.push((await execute({kind:'domain.create',name:'Synthetic domain '+index,description:'Independent synthetic fixture',parentId:options.parentId??null,
  type:{typeId:type.typeId,version:type.version},attributes:options.attributes??{},ownerId:options.ownerId??null,reason},{principal:p})).domain);
 const id=randomUUID();const asset=await scope(p.tenantId,p.id,async tx=>{
  const row=await tx.insertInto('assets').values({tenant_id:p.tenantId,id,external_id:id,name:'Synthetic placed dataset',qualified_name:'synthetic.domain.'+id,type:'dataset',observed_at:new Date()}).returningAll().executeTakeFirstOrThrow();
  await tx.insertInto('asset_revisions').values({tenant_id:p.tenantId,asset_id:id,version:row.version,snapshot:JSON.stringify(assetView(row))}).execute();return row;
 });return {principal:p,type,domains,asset};
}
/** Cache each full-row digest once; stable hash ties retain the original query order. */
export function sortSnapshotRows<T>(rows:readonly T[],hash:(row:T)=>string=typeHash):T[]{
 return rows.map(row=>({row,key:hash(row)})).sort((a,b)=>a.key.localeCompare(b.key)).map(entry=>entry.row);
}
/** Hash each complete selected row inside PostgreSQL. Only fixed-size digests cross
 * the client boundary; duplicate rows remain duplicate digests. No tenant-visible
 * rows are filtered, sampled or truncated. This helper changes test snapshots only. */
export async function snapshotRowDigests(tx:Tx,rows:OperationNodeSource):Promise<string[]>{
 const result=await sql<{digest:string}>`
  SELECT snapshot_digest.digest FROM (
   SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.to_jsonb(snapshot_row)::text,'UTF8')),'hex') digest
   FROM (${rows}) AS snapshot_row
  ) AS snapshot_digest ORDER BY snapshot_digest.digest COLLATE "C"`.execute(tx);
 return result.rows.map(row=>row.digest);
}
export const snapshotTables=['domain_types','domain_type_versions','domain_type_dependencies','domains','domain_revisions','asset_domain_placements','asset_domain_placement_revisions','domain_type_migrations','domain_type_migration_domains','audit','outbox','idempotency'] as const;
export type SnapshotTable=typeof snapshotTables[number];
export function snapshotTableDigests(tx:Tx,table:SnapshotTable):Promise<string[]>{
 // Delivery bookkeeping changes independently in the live outbox worker. Compare
 // every immutable event field so rollback checks still detect inserts or edits.
 const rows=table==='outbox'
  ?tx.selectFrom(table).select(['tenant_id','id','event_type','resource_id','resource_version','payload','created_at'])
  :tx.selectFrom(table).selectAll();
 return snapshotRowDigests(tx,rows);
}
export async function snapshot(p=principal){return scope(p.tenantId,p.id,async tx=>{
 const result:Row={};for(const table of snapshotTables)result[table]=await snapshotTableDigests(tx,table);
 result.epoch=(await sql<{value:string}>`SELECT gc_domain_scope_epoch() value`.execute(tx)).rows[0]!.value;return result;
});}
