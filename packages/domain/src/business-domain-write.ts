// SPDX-License-Identifier: Apache-2.0
import { randomUUID } from 'node:crypto';
import { sql, type Tx } from '../../db/src/index.ts';
import { Problem, type Principal } from '../../authz/src/index.ts';
import { typeHash } from './asset-type-policy.ts';
import { validateAttributes } from './model.ts';
import { domainTypeAttributeModel } from './business-domain-type.ts';
import { applyDomainTypeMigration } from './business-domain-migration.ts';
import { captureDomainTypePreview, captureDomainHierarchyPreview, prepareDomainType } from './business-domain-preview.ts';
import { domainPlacement } from './business-domain-read.ts';
import { authorizeDomain, domainQuery, domainText, domainVersion, domainValidation, domainStorage, domainStale, domainConflict,
  domainOwnerActivity, domainTuple, storedDomainType, storedDomain, domainAsset, domainPhysicalBudget, checkDomainDeadline,
  DOMAIN_TYPE_WRITE, DOMAIN_WRITE, DOMAIN_PLACEMENT_WRITE } from './business-domain-store.ts';
import type { DomainMutationRequest, DomainMutationResults, DomainHooks } from './business-domain-service-contracts.ts';
import type { DomainView, DomainTypeView, DomainRevision, DomainPlacementView, DomainPlacementRevision, DomainTypeMigrationReceipt,
  DomainJournalEvent, DomainTypeEventData, DomainEventData, DomainPlacementEventData } from './business-domain-contracts.ts';

export function domainMutationActions(request:DomainMutationRequest):readonly string[]{
  switch(request.kind){
    case 'domain-type.create':return DOMAIN_TYPE_WRITE;
    case 'domain-type.publish':return [...DOMAIN_TYPE_WRITE,'domains:read'];
    case 'domain-type-migration.execute':return [...DOMAIN_TYPE_WRITE,...DOMAIN_WRITE];
    case 'domain.placement':return DOMAIN_PLACEMENT_WRITE;
    default:return DOMAIN_WRITE;
  }
}
interface Begin {operationId:string;occurredAt:string;projectionHash:string;receiptHash?:string}
function authoredType(id:string,currentVersion:number,target:Awaited<ReturnType<typeof prepareDomainType>>,p:Principal,at:string):DomainTypeView{
  return {typeId:id,key:target.definition.id,version:target.definition.version,currentVersion,definition:target.definition,resolved:target.resolved,
    definitionHash:typeHash(target.definition),resolutionHash:typeHash(target.resolved),createdAt:at,createdBy:p.id};
}
async function typeWrite(tx:Tx,p:Principal,type:DomainTypeView,created:boolean){
  if(created)await domainQuery(tx,()=>tx.insertInto('domain_types').values({tenant_id:p.tenantId,id:type.typeId,key:type.key,current_version:type.version,created_at:type.createdAt,created_by:p.id}).execute());
  else await domainQuery(tx,()=>tx.updateTable('domain_types').set({current_version:type.version}).where('tenant_id','=',p.tenantId).where('id','=',type.typeId).execute());
  await domainQuery(tx,()=>tx.insertInto('domain_type_versions').values({tenant_id:p.tenantId,type_id:type.typeId,version:type.version,definition:JSON.stringify(type.definition),resolved:JSON.stringify(type.resolved),
    definition_hash:type.definitionHash,resolution_hash:type.resolutionHash,created_at:type.createdAt,created_by:p.id}).execute());
}
async function domainWrite(tx:Tx,p:Principal,view:DomainView,action:DomainRevision['action'],reason:string,correlationId:string){
  const values={name:view.name,description:view.description,parent_id:view.parentId,type_id:view.type.typeId,type_version:view.type.version,attributes:JSON.stringify(view.attributes),
    owner_id:view.ownerId,state:view.state,status:view.status,version:view.version,created_at:view.createdAt,created_by:view.createdBy,updated_at:view.updatedAt,updated_by:view.updatedBy};
  if(action==='created')await domainQuery(tx,()=>tx.insertInto('domains').values({tenant_id:p.tenantId,id:view.id,...values}).execute());
  else await domainQuery(tx,()=>tx.updateTable('domains').set(values).where('tenant_id','=',p.tenantId).where('id','=',view.id).execute());
  const revision:DomainRevision={formatVersion:1,domain:view,action,reason,correlationId};
  await domainQuery(tx,()=>tx.insertInto('domain_revisions').values({tenant_id:p.tenantId,domain_id:view.id,version:view.version,snapshot:JSON.stringify(revision)}).execute());
  return revision;
}
async function journal(tx:Tx,p:Principal,hooks:DomainHooks,event:DomainJournalEvent,id:string,version:number,reason:string,correlationId:string,at:string){
  await hooks.record(tx,p,event.action,id,version,{reason},correlationId,{data:event.data,resourceKind:event.data.resourceKind,occurredAt:at,query:work=>domainQuery(tx,work)});
}
const typeData=(type:DomainTypeView,previousVersion:number|null,migrationId:string|null):DomainTypeEventData=>({schemaVersion:1,resourceKind:'domain-type',typeId:type.typeId,previousVersion,version:type.version,definitionHash:type.definitionHash,resolutionHash:type.resolutionHash,migrationId});
const domainData=(revision:DomainRevision,previousVersion:number|null,migrationId:string|null):DomainEventData=>({schemaVersion:1,resourceKind:'domain',domainId:revision.domain.id,previousVersion,version:revision.domain.version,revisionHash:typeHash(revision),migrationId});
async function validateTuple(tx:Tx,p:Principal,view:DomainView,selectedOwner:boolean){
  const policy=await storedDomainType(tx,p,view.type.typeId,view.type.version),attrs=validateAttributes(domainTypeAttributeModel(policy.definition,policy.resolved),view.attributes);
  if(!attrs.ok)throw domainValidation('DOMAIN_INVALID',attrs.issues);
  if(!policy.resolved.lifecycle.states.includes(view.state))throw domainValidation('DOMAIN_INVALID');
  const activity=await domainOwnerActivity(tx,p,[view.ownerId]),active=view.ownerId!==null&&activity[0]?.active===true;
  if(policy.resolved.requiredOwner&&!active||selectedOwner&&view.ownerId!==null&&!active)throw domainValidation('DOMAIN_INVALID');
}
async function ordinaryProjection(tx:Tx,p:Principal,request:Exclude<DomainMutationRequest,{kind:'domain-type-migration.execute'}>,begin:Begin){
  const at=begin.occurredAt;
  switch(request.kind){
    case 'domain-type.create':{
      const target=await prepareDomainType(tx,p,begin.operationId,request.definition);
      if(target.definition.version!==1)throw domainValidation('DOMAIN_TYPE_INVALID');
      return {type:authoredType(begin.operationId,1,target,p,at)};
    }
    case 'domain-type.publish':{
      const captured=await captureDomainTypePreview(tx,p,{kind:'domain-type',typeId:request.typeId,expectedHeadVersion:request.expectedHeadVersion,definition:request.definition,reason:request.reason},true);
      if(!captured.preview.ready)throw domainValidation('DOMAIN_MIGRATION_REQUIRED');
      if(captured.preview.previewDigest!==request.previewDigest)throw domainStale();
      const target=captured.preview.target;return {type:{...target,currentVersion:target.version,createdAt:at,createdBy:p.id}};
    }
    case 'domain.create':{
      if(!domainText(request.name,200,true)||!domainText(request.description,4000))throw domainValidation('DOMAIN_INVALID');
      const policy=await storedDomainType(tx,p,request.type.typeId,request.type.version);
      if(request.parentId!==null&&(await storedDomain(tx,p,request.parentId)).status!=='active')throw domainValidation('DOMAIN_RETIRED');
      const domain:DomainView={id:begin.operationId,name:request.name,description:request.description,parentId:request.parentId,type:request.type,attributes:request.attributes,ownerId:request.ownerId,
        state:policy.resolved.lifecycle.initial,status:'active',version:1,createdAt:at,createdBy:p.id,updatedAt:at,updatedBy:p.id};
      await validateTuple(tx,p,domain,true);return {domain};
    }
    case 'domain.update':case 'domain.state':{
      const before=await storedDomain(tx,p,request.domainId);
      if(before.version!==request.expectedVersion||before.version===2147483647)throw domainConflict();
      if(before.status!=='active')throw domainValidation('DOMAIN_RETIRED');
      let after:DomainView;
      if(request.kind==='domain.update'){
        if(!domainText(request.name,200,true)||!domainText(request.description,4000))throw domainValidation('DOMAIN_INVALID');
        after={...before,name:request.name,description:request.description,attributes:request.attributes,ownerId:request.ownerId,version:before.version+1,updatedAt:at,updatedBy:p.id};
      }else{
        const policy=await storedDomainType(tx,p,before.type.typeId,before.type.version);
        if(!policy.resolved.lifecycle.transitions.some(t=>t.from===before.state&&t.to===request.state))throw domainValidation('DOMAIN_INVALID');
        after={...before,state:request.state,version:before.version+1,updatedAt:at,updatedBy:p.id};
      }
      if(typeHash(domainTuple(before))===typeHash(domainTuple(after)))throw domainValidation('DOMAIN_NO_CHANGE');
      await validateTuple(tx,p,after,before.ownerId!==after.ownerId);return {domain:after};
    }
    case 'domain.hierarchy':{
      const captured=await captureDomainHierarchyPreview(tx,p,request.change,true);
      if(!captured.preview.ready)throw domainValidation('DOMAIN_INVALID',captured.preview.issues);
      if(captured.preview.previewDigest!==request.previewDigest)throw domainStale();
      const before=captured.selected,domain:DomainView={...before,parentId:request.change.parentId,
        status:request.change.kind==='retire'?'retired':request.change.kind==='restore'?'active':before.status,version:before.version+1,updatedAt:at,updatedBy:p.id};
      return {domain};
    }
    case 'domain.placement':{
      const asset=await domainAsset(tx,p,request.assetId),prior=await domainPlacement(tx,p,request.assetId);
      if(asset.version!==request.assetVersion||prior.placement.version!==request.expectedPlacementVersion||prior.placement.version===2147483647)throw domainConflict();
      if(prior.placement.domainId===request.domainId)throw domainValidation('DOMAIN_NO_CHANGE');
      const domain=request.domainId===null?null:await storedDomain(tx,p,request.domainId);
      if(domain?domain.version!==request.domainVersion:request.domainVersion!==null)throw domainConflict();
      if(domain&&domain.status!=='active')throw domainValidation('DOMAIN_RETIRED');
      const placement:DomainPlacementView={assetId:request.assetId,version:prior.placement.version+1,domainId:request.domainId,recordedAssetVersion:asset.version,
        recordedDomainVersion:domain?.version??null,recordedAt:at,recordedBy:p.id};return {placement,domain};
    }
  }
}
/** Only the non-replay branch allocates IDs and enters SQL's protected claims.
 * SQL independently computes every outcome; the service proves consent and
 * compares the complete pure projection before writing any canonical row. */
export async function executeDomainMutation<R extends DomainMutationRequest>(tx:Tx,p:Principal,key:string,request:R,correlationId:string,hooks:DomainHooks):Promise<DomainMutationResults[R['kind']]> {
  const migration=request.kind==='domain-type-migration.execute';
  const reason=request.kind==='domain.hierarchy'?request.change.reason:request.reason;
  if(!domainText(reason,500,true)||!/^[A-Za-z0-9._:-]{1,128}$/.test(correlationId))throw domainValidation('DOMAIN_INVALID');
  const {kind,...rest}=request,body=migration?rest:request,operationId=randomUUID();
  const begun=await domainQuery(tx,()=>migration
    ?sql<{result:Begin}>`select public.gc_domain_type_migration_begin(${operationId}::uuid,${key},${JSON.stringify(body)}::jsonb,${correlationId}) as result`.execute(tx)
    :sql<{result:Begin}>`select public.gc_domain_write_begin(${operationId}::uuid,${key},${JSON.stringify(body)}::jsonb,${correlationId}) as result`.execute(tx));
  const begin=begun.rows[0]?.result;if(!begin||begin.operationId!==operationId)throw domainStorage();
  const current=await authorizeDomain(tx,p,domainMutationActions(request));let expected:DomainMutationResults[keyof DomainMutationResults];
  if(request.kind==='domain-type-migration.execute'){
    const captured=await captureDomainTypePreview(tx,current,{kind:'migration',typeId:request.typeId,expectedHeadVersion:request.expectedHeadVersion,definition:request.definition,plan:request.plan,reason:request.reason},true);
    if(!captured.preview.ready)throw domainValidation('DOMAIN_MIGRATION_INVALID');
    if(captured.preview.previewDigest!==request.previewDigest)throw domainStale();
    const transformed=applyDomainTypeMigration(captured.scope,request.plan);if(!transformed.ok)throw domainValidation('DOMAIN_MIGRATION_INVALID',transformed.issues);
    const target=captured.preview.target,type:DomainTypeView={...target,currentVersion:target.version,createdAt:begin.occurredAt,createdBy:current.id};
    const sourcePolicies=captured.scope.sources.map(source=>({pin:{typeId:source.typeId,version:source.version},definitionHash:source.definitionHash,resolutionHash:source.resolutionHash}));
    const receipt:DomainTypeMigrationReceipt={formatVersion:1,id:operationId,typeId:request.typeId,fromHeadVersion:request.expectedHeadVersion,targetVersion:type.version,
      plan:request.plan,planHash:typeHash(request.plan),previewDigest:request.previewDigest,sourcePolicies,targetDefinitionHash:type.definitionHash,targetResolutionHash:type.resolutionHash,
      outcomes:transformed.value,actorId:current.id,occurredAt:begin.occurredAt,reason,correlationId};
    const projection={formatVersion:1,kind:'domain-type-migration-projection',typeId:request.typeId,fromHeadVersion:request.expectedHeadVersion,targetVersion:type.version,
      planHash:receipt.planHash,sourcePolicies,targetDefinitionHash:type.definitionHash,targetResolutionHash:type.resolutionHash,outcomes:transformed.value};
    await domainPhysicalBudget(tx,{body,scope:captured.scope,projection,receipt});
    if(typeHash(projection)!==begin.projectionHash||typeHash(receipt)!==begin.receiptHash)throw domainStorage();
    await typeWrite(tx,current,type,false);
    await journal(tx,current,hooks,{action:'domain_type.published',data:typeData(type,request.expectedHeadVersion,operationId)},type.typeId,type.version,reason,correlationId,begin.occurredAt);
    const before=new Map(captured.scope.domains.map(domain=>[domain.id,domain]));
    for(const outcome of transformed.value){checkDomainDeadline(tx);const prior=before.get(outcome.domainId);if(!prior)throw domainStorage();
      const domain:DomainView={...prior,...outcome.after,version:outcome.toVersion,updatedAt:begin.occurredAt,updatedBy:current.id};
      const revision=await domainWrite(tx,current,domain,'type-migrated',reason,correlationId);
      await journal(tx,current,hooks,{action:'domain.type_migrated',data:domainData(revision,outcome.fromVersion,operationId)},domain.id,domain.version,reason,correlationId,begin.occurredAt);
    }
    await journal(tx,current,hooks,{action:'domain_type_migration.executed',data:{schemaVersion:1,resourceKind:'domain-type-migration',migrationId:operationId,typeId:request.typeId,
      fromHeadVersion:request.expectedHeadVersion,targetVersion:type.version,planHash:receipt.planHash,previewDigest:receipt.previewDigest,receiptHash:typeHash(receipt)}},operationId,1,reason,correlationId,begin.occurredAt);
    expected={type,receipt};
  }else{
    const response=await ordinaryProjection(tx,current,request,begin);if(!response)throw domainStorage();
    await domainPhysicalBudget(tx,{body,response});
    if(typeHash({formatVersion:1,kind:'domain-write-projection',request:body,response})!==begin.projectionHash)throw domainStorage();
    if('type'in response&&response.type){const type=response.type;
      await typeWrite(tx,current,type,request.kind==='domain-type.create');
      await journal(tx,current,hooks,{action:request.kind==='domain-type.create'?'domain_type.created':'domain_type.published',data:typeData(type,request.kind==='domain-type.create'?null:type.version-1,null)},type.typeId,type.version,reason,correlationId,begin.occurredAt);
    }else if('placement'in response&&response.placement){
      const placement=response.placement,prior=await domainPlacement(tx,current,placement.assetId);
      const values={version:placement.version,domain_id:placement.domainId,recorded_asset_version:placement.recordedAssetVersion,recorded_domain_version:placement.recordedDomainVersion,recorded_at:placement.recordedAt,recorded_by:placement.recordedBy};
      if(prior.placement.version===0)await domainQuery(tx,()=>tx.insertInto('asset_domain_placements').values({tenant_id:current.tenantId,asset_id:placement.assetId,...values}).execute());
      else await domainQuery(tx,()=>tx.updateTable('asset_domain_placements').set(values).where('tenant_id','=',current.tenantId).where('asset_id','=',placement.assetId).execute());
      const revision:DomainPlacementRevision={formatVersion:1,placement,reason,correlationId};
      await domainQuery(tx,()=>tx.insertInto('asset_domain_placement_revisions').values({tenant_id:current.tenantId,asset_id:placement.assetId,version:placement.version,snapshot:JSON.stringify(revision)}).execute());
      const data:DomainPlacementEventData={schemaVersion:1,resourceKind:'asset-domain-placement',assetId:placement.assetId,previousVersion:prior.placement.version,version:placement.version,
        recordedAssetVersion:placement.recordedAssetVersion!,recordedDomainVersion:placement.recordedDomainVersion,domainId:placement.domainId,revisionHash:typeHash(revision)};
      await journal(tx,current,hooks,{action:placement.domainId===null?'asset_domain_placement.unassigned':prior.placement.domainId===null?'asset_domain_placement.assigned':'asset_domain_placement.reassigned',data},placement.assetId,placement.version,reason,correlationId,begin.occurredAt);
    }else{
      const domain=response.domain;if(!domain)throw domainStorage();
      const action:DomainRevision['action']=request.kind==='domain.create'?'created':request.kind==='domain.update'?'updated':request.kind==='domain.state'?'state-changed':
        request.kind==='domain.hierarchy'?(request.change.kind==='move'?'moved':request.change.kind==='retire'?'retired':'restored'):'updated';
      const revision=await domainWrite(tx,current,domain,action,reason,correlationId);
      const actions={created:'domain.created',updated:'domain.updated','state-changed':'domain.state_changed',moved:'domain.moved',retired:'domain.retired',restored:'domain.restored','type-migrated':'domain.type_migrated'} as const;
      await journal(tx,current,hooks,{action:actions[action],data:domainData(revision,action==='created'?null:domain.version-1,null)},domain.id,domain.version,reason,correlationId,begin.occurredAt);
    }
    expected=response;
  }
  const sealed=await domainQuery(tx,()=>migration?sql<{result:unknown}>`select public.gc_domain_type_migration_seal(${operationId}::uuid) as result`.execute(tx):sql<{result:unknown}>`select public.gc_domain_write_seal(${operationId}::uuid) as result`.execute(tx));
  if(typeHash(sealed.rows[0]?.result)!==typeHash(expected))throw domainStorage();return expected as DomainMutationResults[R['kind']];
}
