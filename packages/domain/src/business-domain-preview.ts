// SPDX-License-Identifier: Apache-2.0
import { sql, type Tx } from '../../db/src/index.ts';
import type { Principal } from '../../authz/src/index.ts';
import { typeHash } from './asset-type-policy.ts';
import { previewModelUpgrade, validateAttributes, type ValidationIssue } from './model.ts';
import { parseDomainTypeDefinition, resolveDomainType, domainTypeAttributeModel } from './business-domain-type.ts';
import { parseDomainTypeMigrationPlan, projectDomainTypeMigration, type DomainTypeMigrationScope } from './business-domain-migration.ts';
import { domainMigrationContext } from './business-domain-read.ts';
import { domainQuery, domainUUID, domainVersion, domainText, domainValidation, domainStorage, domainLimit, domainConflict,
  domainScopeMissing, domainMissing, domainTuple, domainView, domainOwnerActivity, lockDomainPrincipals, domainPhysicalBudget,
  domainScopeFence, domainConsent, storedDomainType, storedDomain, DOMAIN_WRITE, type DomainRow } from './business-domain-store.ts';
import type { DomainPreviewRequest } from './business-domain-service-contracts.ts';
import type { DomainTypeDefinition, DomainTypeView, DomainView, DomainTypePreview, DomainPolicyChange, DomainHierarchyChange, DomainHierarchyPreview } from './business-domain-contracts.ts';

export async function prepareDomainType(tx:Tx,p:Principal,typeId:string,input:unknown,retained:unknown=null) {
  const parsed=parseDomainTypeDefinition(input);if(!parsed.ok)throw domainValidation('DOMAIN_TYPE_INVALID',parsed.issues);
  const definition=parsed.value,dependencies=new Map<string,{typeId:string;definition:DomainTypeDefinition}>();
  const budget=()=>domainPhysicalBudget(tx,{retained,definition,dependencies:[...dependencies.values()]});
  let retainedBytes=await budget();
  const add=async(item:DomainTypeView)=>{
    const existing=dependencies.get(item.typeId);
    if(existing&&existing.definition.version!==item.version)throw domainValidation('DOMAIN_TYPE_INVALID');
    if(!existing){if(dependencies.size>=64)throw domainLimit();dependencies.set(item.typeId,{typeId:item.typeId,definition:item.definition});}
    retainedBytes=await budget();
  };
  for(const pin of definition.parents){
    const parent=await storedDomainType(tx,p,pin.typeId,pin.version,retainedBytes);await add(parent);
    // Do not retain a second unbounded array of complete parent views.
    for(const dep of parent.resolved.dependencies){
      const prior=dependencies.get(dep.typeId);
      if(prior){if(prior.definition.version!==dep.version)throw domainValidation('DOMAIN_TYPE_INVALID');continue;}
      const held=await domainPhysicalBudget(tx,{retained,definition,parent,dependencies:[...dependencies.values()]});
      await add(await storedDomainType(tx,p,dep.typeId,dep.version,held));
    }
  }
  const values=[...dependencies.values()].sort((a,b)=>a.typeId.localeCompare(b.typeId));
  await domainPhysicalBudget(tx,{retained,definition,dependencies:values});
  const resolved=resolveDomainType(typeId,definition,values);if(!resolved.ok)throw domainValidation('DOMAIN_TYPE_INVALID',resolved.issues);
  return {definition,resolved:resolved.value,dependencies:values};
}
export async function domainPolicyPool(tx:Tx,p:Principal,views:readonly DomainTypeView[],extra:readonly {typeId:string;definition:DomainTypeDefinition}[],retained:unknown=null) {
  const pool=new Map(extra.map(item=>[`${item.typeId}@${item.definition.version}`,item]));
  const budget=()=>domainPhysicalBudget(tx,{retained,views,dependencies:[...pool.values()]});
  let retainedBytes=await budget();
  for(const view of views)for(const pin of view.resolved.dependencies){
    const key=`${pin.typeId}@${pin.version}`;if(pool.has(key))continue;
    const parent=await storedDomainType(tx,p,pin.typeId,pin.version,retainedBytes);pool.set(key,{typeId:pin.typeId,definition:parent.definition});
    retainedBytes=await budget();
  }
  return [...pool.values()].sort((a,b)=>a.typeId.localeCompare(b.typeId)||a.definition.version-b.definition.version);
}
function changedPolicy(before:DomainTypeView,target:Awaited<ReturnType<typeof prepareDomainType>>):DomainPolicyChange[]{
  const changes:DomainPolicyChange[]=[];
  const pins=(d:DomainTypeDefinition)=>[...d.parents].sort((a,b)=>a.typeId.localeCompare(b.typeId)||a.version-b.version);
  if(typeHash(pins(before.definition))!==typeHash(pins(target.definition)))changes.push('parents_changed');
  if(before.resolved.requiredOwner!==target.resolved.requiredOwner)changes.push('required_owner_changed');
  if(typeHash(before.resolved.lifecycle)!==typeHash(target.resolved.lifecycle))changes.push('lifecycle_changed');return changes;
}
export async function captureDomainTypePreview(tx:Tx,p:Principal,request:Exclude<DomainPreviewRequest,{kind:'hierarchy'}>,locked=false) {
  if(!domainVersion(request.expectedHeadVersion)||!domainText(request.reason,500,true))throw domainValidation('DOMAIN_TYPE_INVALID');
  const context=await domainMigrationContext(tx,p,request.typeId),head=context.type;
  if(head.currentVersion!==request.expectedHeadVersion||head.currentVersion===2147483647)throw domainConflict();
  const target=await prepareDomainType(tx,p,request.typeId,request.definition,context);
  if(target.definition.id!==head.key||target.definition.version!==head.currentVersion+1)throw domainValidation('DOMAIN_TYPE_INVALID');
  const plan=request.kind==='migration'?parseDomainTypeMigrationPlan(request.plan):null;
  if(plan&&!plan.ok)throw domainValidation('DOMAIN_MIGRATION_INVALID',plan.issues);
  const owners=[...context.domains.map(d=>d.ownerId),...(plan?.ok?plan.value.owner.overrides.map(o=>o.ownerId):[])];
  const dependencies=await domainPolicyPool(tx,p,[head,...context.sources],target.dependencies,{context,target});
  if(!locked){
    const typeIds=[...new Set([head.typeId,...dependencies.map(d=>d.typeId)])].sort();
    await domainQuery(tx,()=>tx.selectFrom('domain_types').select('id').where('tenant_id','=',p.tenantId).where('id','in',typeIds).orderBy('id').forUpdate().execute());
    if(context.domains.length)await domainQuery(tx,()=>tx.selectFrom('domains').select('id').where('tenant_id','=',p.tenantId).where('id','in',context.domains.map(d=>d.id)).orderBy('id').forUpdate().execute());
  }
  const actions=['models:read','models:write','domains:read'];
  const current=await lockDomainPrincipals(tx,p,owners,actions),ownerActivity=await domainOwnerActivity(tx,current,owners);
  const scope:DomainTypeMigrationScope={coverage:'complete-direct-domain-type-bindings',head,sources:context.sources,
    target:{definition:target.definition,resolved:target.resolved},domains:context.domains,dependencies,ownerActivity};
  const proposed:DomainTypePreview['target']={typeId:head.typeId,key:head.key,version:target.definition.version,currentVersion:head.currentVersion,
    definition:target.definition,resolved:target.resolved,definitionHash:typeHash(target.definition),resolutionHash:typeHash(target.resolved)};
  let preview:DomainTypePreview;
  if(plan?.ok){
    const projection=projectDomainTypeMigration(scope,plan.value);if(!projection.ok)throw domainValidation('DOMAIN_MIGRATION_INVALID',projection.issues);
    preview={typeId:head.typeId,expectedHeadVersion:head.currentVersion,target:proposed,coverage:scope.coverage,mode:'migrate',
      changes:projection.value.changes,policyChanges:projection.value.policyChanges,domains:projection.value.domains,
      pinsPreserved:false,requiresMigration:true,ready:projection.value.valid,previewDigest:null};
  }else{
    const targetModel=domainTypeAttributeModel(target.definition,target.resolved),checked=previewModelUpgrade(domainTypeAttributeModel(head.definition,head.resolved),targetModel,[]);
    if(!checked.ok)throw domainValidation('DOMAIN_TYPE_INVALID',checked.issues);
    const active=new Map(ownerActivity.map(o=>[o.identityId,o.active]));let totalIssues=0;
    const domains=context.domains.map(before=>{
      const issues:ValidationIssue[]=[],attributes=validateAttributes(targetModel,before.attributes);
      if(!attributes.ok)issues.push(...attributes.issues);
      if(target.resolved.requiredOwner&&(before.ownerId===null||!active.get(before.ownerId)))issues.push({code:'required',path:'/ownerId',message:'The target policy requires an active owner.'});
      if(!target.resolved.lifecycle.states.includes(before.state))issues.push({code:'enum',path:'/state',message:'The current state is outside the target lifecycle.'});
      totalIssues+=issues.length;if(totalIssues>100)throw domainLimit();
      return {before,proposed:{...domainTuple(before),type:{typeId:head.typeId,version:target.definition.version}},issues};
    });
    const policyChanges=changedPolicy(head,target),requiresMigration=policyChanges.length>0||checked.value.changes.some(c=>c.requiresMigration)||totalIssues>0;
    preview={typeId:head.typeId,expectedHeadVersion:head.currentVersion,target:proposed,coverage:scope.coverage,mode:'preserve-pins',
      changes:checked.value.changes,policyChanges,domains,pinsPreserved:true,requiresMigration,ready:!requiresMigration,previewDigest:null};
  }
  const fence=await domainScopeFence(tx,current),consent={tenantId:current.tenantId,actorId:current.id,permissions:[...current.permissions].sort(),
    request,scope,fence,preview};
  await domainPhysicalBudget(tx,{request,scope,preview});
  if(preview.ready)preview={...preview,previewDigest:domainConsent(request.kind,consent)};
  return {preview,scope,current};
}
function subtree(p:Principal,id:string){return sql`WITH RECURSIVE tree(id) AS (
  SELECT id FROM domains WHERE tenant_id=${p.tenantId}::uuid AND id=${id}::uuid UNION
  SELECT d.id FROM domains d JOIN tree t ON d.parent_id=t.id WHERE d.tenant_id=${p.tenantId}::uuid
), placed AS MATERIALIZED (SELECT x.asset_id,x.version FROM asset_domain_placements x WHERE x.tenant_id=${p.tenantId}::uuid AND x.domain_id IN(SELECT id FROM tree))`;}
async function ancestors(tx:Tx,p:Principal,id:string|null,retained:unknown=null):Promise<DomainView[]>{
  const rows:DomainView[]=[],seen=new Set<string>();let next=id,retainedBytes=await domainPhysicalBudget(tx,{retained,rows});
  while(next!==null){if(seen.has(next))throw domainStorage();if(rows.length>=32)throw domainLimit();seen.add(next);
    const view=await storedDomain(tx,p,next,retainedBytes);rows.push(view);next=view.parentId;retainedBytes=await domainPhysicalBudget(tx,{retained,rows});}
  return rows;
}
export async function captureDomainHierarchyPreview(tx:Tx,p:Principal,change:DomainHierarchyChange,locked=false){
  if(!['move','retire','restore'].includes(change.kind)||!domainUUID(change.domainId)||!domainVersion(change.expectedVersion)
    ||change.parentId!==null&&!domainUUID(change.parentId)||!domainText(change.reason,500,true))throw domainValidation('DOMAIN_INVALID');
  const selected=await storedDomain(tx,p,change.domainId);if(selected.version!==change.expectedVersion||selected.version===2147483647)throw domainConflict();
  const destination=await ancestors(tx,p,change.parentId,{selected,change}),origin=await ancestors(tx,p,selected.parentId,{selected,change,destination});
  // Complete asset authorization precedes every count/size result. No names or
  // partial subtree are returned when even one placement is inaccessible.
  const denied=await domainQuery(tx,()=>sql`${subtree(p,selected.id)} SELECT 1 FROM placed x LEFT JOIN assets a ON a.tenant_id=${p.tenantId}::uuid AND a.id=x.asset_id
    WHERE NOT ${p.permissions.includes('catalog:read')} OR a.id IS NULL OR NOT(a.visibility='tenant' OR a.allowed_identities @> ${JSON.stringify([p.id])}::jsonb) LIMIT 1`.execute(tx));
  if(denied.rows.length)throw domainScopeMissing();
  const size=await domainQuery(tx,()=>sql<{domains:number;assets:number;bytes:number}>`${subtree(p,selected.id)} SELECT
    (SELECT count(*) FROM tree)::integer AS domains,(SELECT count(*) FROM placed)::integer AS assets,
    (SELECT coalesce(sum(octet_length(to_jsonb(d)::text)),0) FROM domains d WHERE d.tenant_id=${p.tenantId}::uuid AND d.id IN(SELECT id FROM tree))::integer AS bytes`.execute(tx));
  if(size.rows[0].domains>1000||size.rows[0].assets>1000||size.rows[0].bytes>524288)throw domainLimit();
  const domains=(await domainQuery(tx,()=>sql<DomainRow>`${subtree(p,selected.id)} SELECT d.* FROM domains d WHERE d.tenant_id=${p.tenantId}::uuid AND d.id IN(SELECT id FROM tree) ORDER BY d.id`.execute(tx))).rows.map(domainView);
  const assets=(await domainQuery(tx,()=>sql<{assetId:string;assetVersion:number;placementVersion:number;domainId:string}>`${subtree(p,selected.id)} SELECT a.id AS "assetId",a.version AS "assetVersion",x.version AS "placementVersion",d.domain_id AS "domainId"
    FROM placed x JOIN assets a ON a.tenant_id=${p.tenantId}::uuid AND a.id=x.asset_id JOIN asset_domain_placements d ON d.tenant_id=a.tenant_id AND d.asset_id=a.id ORDER BY a.id`.execute(tx))).rows;
  const union=[...new Map([...domains,...destination,...origin].map(d=>[d.id,d])).values()].sort((a,b)=>a.id.localeCompare(b.id));
  if(!locked){
    const types=[...new Set(union.map(d=>d.type.typeId))].sort();
    if(types.length)await domainQuery(tx,()=>tx.selectFrom('domain_types').select('id').where('tenant_id','=',p.tenantId).where('id','in',types).orderBy('id').forUpdate().execute());
    await domainQuery(tx,()=>tx.selectFrom('domains').select('id').where('tenant_id','=',p.tenantId).where('id','in',union.map(d=>d.id)).orderBy('id').forUpdate().execute());
    if(assets.length){const ids=assets.map(a=>a.assetId);
      await domainQuery(tx,()=>tx.selectFrom('assets').select('id').where('tenant_id','=',p.tenantId).where('id','in',ids).orderBy('id').forUpdate().execute());
      await domainQuery(tx,()=>tx.selectFrom('asset_domain_placements').select('asset_id').where('tenant_id','=',p.tenantId).where('asset_id','in',ids).orderBy('asset_id').forUpdate().execute());}
  }
  const current=await lockDomainPrincipals(tx,p,union.map(d=>d.ownerId),[...DOMAIN_WRITE,...(assets.length?['catalog:read']:[])]),activity=await domainOwnerActivity(tx,current,union.map(d=>d.ownerId));
  const policy=await storedDomainType(tx,current,selected.type.typeId,selected.type.version),issues:ValidationIssue[]=[];
  const issue=(code:ValidationIssue['code'],path:string,message:string)=>issues.push({code,path,message});
  if(change.kind==='move'){
    if(change.parentId===selected.parentId)issue('invalid_definition','/parentId','Choose a different parent.');
    if(selected.status!=='active'||destination.some(d=>d.status!=='active'))issue('invalid_definition','/parentId','The domain and destination ancestors must be active.');
    if(destination.some(d=>d.id===selected.id))issue('cycle','/parentId','A domain cannot be moved into its own subtree.');
    const byId=new Map(domains.map(d=>[d.id,d]));let max=0;
    for(const domain of domains){let depth=1,currentId=domain.id;const seen=new Set<string>();
      while(currentId!==selected.id){if(seen.has(currentId)||!byId.has(currentId))throw domainStorage();seen.add(currentId);const parent=byId.get(currentId)!.parentId;if(parent===null)throw domainStorage();currentId=parent;if(++depth>32)throw domainLimit();}max=Math.max(max,depth);}
    if(destination.length+max>32)issue('limit','/parentId','The proposed hierarchy exceeds thirty-two levels.');
  }else{
    if(change.parentId!==selected.parentId)issue('invalid_definition','/parentId','This status change must retain the current parent.');
    if(change.kind==='retire'){
      if(selected.status!=='active')issue('invalid_definition','/kind','The domain is already retired.');
      if(domains.some(d=>d.parentId===selected.id&&d.status==='active')||assets.some(a=>a.domainId===selected.id))issue('invalid_definition','/kind','Remove direct placements and active children before retirement.');
    }else{
      if(selected.status!=='retired')issue('invalid_definition','/kind','The domain is already active.');
      if(destination.some(d=>d.status!=='active'))issue('invalid_definition','/parentId','The current parent ancestors must be active.');
      const attrs=validateAttributes(domainTypeAttributeModel(policy.definition,policy.resolved),selected.attributes);if(!attrs.ok)throw domainStorage();
      if(policy.resolved.requiredOwner&&!activity.some(a=>a.identityId===selected.ownerId&&a.active))issue('required','/ownerId','Restoring this domain requires an active owner.');
    }
  }
  let preview:DomainHierarchyPreview={coverage:'complete-affected-domain-subtree',change,domains:domains.map(d=>({domainId:d.id,version:d.version,parentId:d.parentId})),
    assets:assets.map(({domainId,...asset})=>asset),ready:issues.length===0,issues,previewDigest:null};
  const fence=await domainScopeFence(tx,current),evidence={change,domains,assets,origin,destination,policy,activity,fence,permissions:[...current.permissions].sort(),tenantId:p.tenantId,actorId:p.id};
  await domainPhysicalBudget(tx,{evidence,preview});
  if(preview.ready)preview={...preview,previewDigest:domainConsent('hierarchy',evidence)};
  return {preview,selected,current};
}
