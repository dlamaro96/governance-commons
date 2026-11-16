// SPDX-License-Identifier: Apache-2.0
import { sql, type Tx } from '../../db/src/index.ts';
import { Problem, type Principal } from '../../authz/src/index.ts';
import { typeHash } from './asset-type-policy.ts';
import { signedCursor } from './cursor.ts';
import { domainQuery, domainPhysicalBudget, domainRowsBudget, domainScopeFence, domainMissing, domainScopeMissing, domainTypeMissing,
  domainStorage, domainLimit, domainUUID, domainVersion, domainText, domainView, domainTuple, placementView,
  storedDomainType, storedDomain, domainAsset, type DomainRow } from './business-domain-store.ts';
import type { DomainReadRequest, DomainReadResults, DomainPageQuery, DomainHistoryQuery, DomainInventoryQuery } from './business-domain-service-contracts.ts';
import type { DomainTypeMigrationContext, DomainTypeMigrationReceipt, DomainRevision, DomainPlacementRevision, DomainView, DomainTypeView } from './business-domain-contracts.ts';

const pageInvalid = () => new Problem(400,'DOMAIN_PAGE_INVALID','Provide a valid page selector for this view.');
const like = (value: string) => `%${value.replace(/[\\%_]/g,'\\$&')}%`;
/** No epoch or permission list enters the public cursor. The signed selector
 * binds purpose and actor; fresh action/resource checks are still mandatory. */
async function selector(tx: Tx,p: Principal,purpose: string,input: DomainPageQuery | DomainHistoryQuery,binding: unknown,descending = false) {
  const limit = input.limit ?? 50;
  if (!Number.isInteger(limit) || limit < 1 || limit > 100 || 'q' in input && !domainText(input.q,200)) throw pageInvalid();
  const fence = await domainScopeFence(tx,p), codec = signedCursor(process.env.SESSION_KEY,purpose);
  const fixed = {v:1,tenant:p.tenantId,actor:p.id,purpose,filter:typeHash(binding),limit,order:descending?'version-desc':'uuid-asc'};
  let last: string|number|null = null;
  if (input.cursor !== undefined) {
    let parsed: any; try { parsed=codec.decode(input.cursor); } catch { throw pageInvalid(); }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)
      || Object.keys(parsed).sort().join(',') !== 'actor,fence,filter,last,limit,order,purpose,tenant,v'
      || typeHash(Object.fromEntries(Object.entries(parsed).filter(([k])=>!['last','fence'].includes(k)))) !== typeHash(fixed)
      || typeof parsed.fence !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(parsed.fence)
      || !(descending?domainVersion(parsed.last):domainUUID(parsed.last))) throw pageInvalid();
    if (parsed.fence !== fence) throw new Problem(409,'DOMAIN_PAGE_STALE','The page scope changed. Reload this view.');
    last=parsed.last;
  }
  return { limit,last,finish<T>(rows: readonly T[],key:(row:T)=>string|number) {
    const items=rows.slice(0,limit); return {items,nextCursor:rows.length>limit?codec.encode({...fixed,fence,last:key(items[items.length-1])}):null};
  } };
}
export async function domainMigrationContext(tx:Tx,p:Principal,typeId:string):Promise<DomainTypeMigrationContext> {
  const type=await storedDomainType(tx,p,typeId);
  // Domain read is tenant-wide in this increment. Keep the complete existence
  // check ahead of scalar/materialization bounds; scoped authority plugs in here.
  const size=await domainQuery(tx,()=>sql<{n:number;bytes:number}>`select count(*)::integer as n,
    coalesce(sum(octet_length(to_jsonb(d)::text)),0)::double precision as bytes from domains d
    where d.tenant_id=${p.tenantId}::uuid and d.type_id=${typeId}::uuid`.execute(tx));
  if(size.rows[0].n>1000||size.rows[0].bytes>524288)throw domainLimit();
  const rows=await domainQuery(tx,()=>tx.selectFrom('domains').select('id').where('tenant_id','=',p.tenantId).where('type_id','=',typeId).orderBy('id').execute());
  const domains:DomainView[]=[],sources:DomainTypeView[]=[];let retainedBytes=await domainPhysicalBudget(tx,{type,domains,sources});
  for(const row of rows){const value=await storedDomain(tx,p,row.id,retainedBytes);domains.push(value);
    retainedBytes=await domainPhysicalBudget(tx,{type,domains,sources});}
  for(const version of [...new Set(domains.map(d=>d.type.version))].sort((a,b)=>a-b)){
    sources.push(await storedDomainType(tx,p,typeId,version,retainedBytes));
    retainedBytes=await domainPhysicalBudget(tx,{type,domains,sources});
  }
  const result={coverage:'complete-direct-domain-type-bindings' as const,type,sources,domains};await domainPhysicalBudget(tx,result);return result;
}
export function visibleDomainMigration(p:Principal,reference:ReturnType<typeof sql>) {
  return sql<boolean>`${p.permissions.includes('models:read')&&p.permissions.includes('domains:read')}
    AND EXISTS(SELECT 1 FROM domain_type_migrations m WHERE m.tenant_id=${p.tenantId}::uuid AND m.id::text=(${reference})::text
      AND NOT EXISTS(SELECT 1 FROM domain_type_migration_domains member LEFT JOIN domains d ON d.tenant_id=member.tenant_id AND d.id=member.domain_id
        WHERE member.tenant_id=m.tenant_id AND member.migration_id=m.id AND d.id IS NULL))`;
}
export async function domainMigrationReceipt(tx:Tx,p:Principal,typeId:string,id:string):Promise<{receipt:DomainTypeMigrationReceipt}> {
  const missing=()=>new Problem(404,'DOMAIN_MIGRATION_NOT_FOUND','The domain migration is unavailable.');
  if(!domainUUID(id)||!domainUUID(typeId))throw missing();
  const allowed=await domainQuery(tx,()=>sql<{allowed:boolean}>`select (${visibleDomainMigration(p,sql`${id}`)}) as allowed`.execute(tx));
  if(!allowed.rows[0].allowed)throw missing();
  const q=tx.selectFrom('domain_type_migrations').where('tenant_id','=',p.tenantId).where('type_id','=',typeId).where('id','=',id);
  const bytes=await domainQuery(tx,()=>q.select(sql<number>`octet_length(receipt::text)`.as('bytes')).executeTakeFirst());
  if(!bytes)throw missing();if(bytes.bytes>524288)throw domainLimit();
  const receiptBytes=await domainRowsBudget(tx,q.selectAll());
  const row=await domainQuery(tx,()=>q.selectAll().executeTakeFirstOrThrow()),receipt=row.receipt as DomainTypeMigrationReceipt;
  if(receipt.formatVersion!==1||receipt.id!==id||receipt.typeId!==typeId||receipt.planHash!==typeHash(receipt.plan)||receipt.planHash!==row.plan_hash
    ||receipt.previewDigest!==row.preview_digest||receipt.actorId!==row.executed_by||receipt.occurredAt!==new Date(row.executed_at).toISOString()
    ||receipt.targetVersion!==row.target_version||receipt.fromHeadVersion!==row.from_head_version||typeHash(receipt.sourcePolicies)!==typeHash(row.source_policies)
    ||receipt.targetDefinitionHash!==row.target_definition_hash||receipt.targetResolutionHash!==row.target_resolution_hash
    ||!Array.isArray(receipt.outcomes)||receipt.outcomes.length>1000)throw domainStorage();
  const memberQuery=tx.selectFrom('domain_type_migration_domains as m')
    .innerJoin('domain_revisions as b',j=>j.onRef('b.tenant_id','=','m.tenant_id').onRef('b.domain_id','=','m.domain_id').onRef('b.version','=','m.from_version'))
    .innerJoin('domain_revisions as a',j=>j.onRef('a.tenant_id','=','m.tenant_id').onRef('a.domain_id','=','m.domain_id').onRef('a.version','=','m.to_version'))
    .selectAll('m').select(['b.snapshot as before','a.snapshot as after']).where('m.tenant_id','=',p.tenantId).where('m.migration_id','=',id).orderBy('m.domain_id').limit(1001);
  const retainedBytes=await domainRowsBudget(tx,memberQuery,receiptBytes);
  const members=await domainQuery(tx,()=>memberQuery.execute());
  if(members.length!==receipt.outcomes.length)throw domainStorage();
  const actual=members.map(m=>({domainId:m.domain_id,fromVersion:m.from_version,toVersion:m.to_version,before:domainTuple(m.before.domain),after:domainTuple(m.after.domain)}));
  for(let i=0;i<members.length;i++)if(typeHash(actual[i].before)!==members[i].before_tuple_hash||typeHash(actual[i].after)!==members[i].after_tuple_hash)throw domainStorage();
  if(typeHash(actual)!==typeHash(receipt.outcomes))throw domainStorage();
  const target=await storedDomainType(tx,p,typeId,receipt.targetVersion,retainedBytes);
  if(target.definitionHash!==receipt.targetDefinitionHash||target.resolutionHash!==receipt.targetResolutionHash)throw domainStorage();
  await domainPhysicalBudget(tx,{receipt,actual});return {receipt};
}
export async function domainPlacement(tx:Tx,p:Principal,assetId:string):Promise<DomainReadResults['placement']> {
  await domainAsset(tx,p,assetId);
  const query=tx.selectFrom('asset_domain_placements as p').leftJoin('asset_domain_placement_revisions as r',j=>j.onRef('r.tenant_id','=','p.tenant_id')
    .onRef('r.asset_id','=','p.asset_id').onRef('r.version','=','p.version')).selectAll('p').select('r.snapshot as revision')
    .where('p.tenant_id','=',p.tenantId).where('p.asset_id','=',assetId);
  await domainRowsBudget(tx,query);
  const row=await domainQuery(tx,()=>query.executeTakeFirst());
  const placement=placementView(assetId,row),domain=placement.domainId===null?null:await storedDomain(tx,p,placement.domainId);
  if(row&&(!row.revision||typeHash(row.revision.placement)!==typeHash(placement)))throw domainStorage();
  return {placement,domain};
}
async function referencedDomains(tx:Tx,p:Principal,ids:readonly(string|null)[]):Promise<void>{
  const unique=[...new Set(ids.filter((id):id is string=>id!==null))];if(!unique.length)return;
  if(unique.some(id=>!domainUUID(id)))throw domainStorage();
  const rows=await domainQuery(tx,()=>tx.selectFrom('domains').select('id').where('tenant_id','=',p.tenantId).where('id','in',unique).execute());
  if(rows.length!==unique.length)throw domainScopeMissing();
}
export async function readDomainResource<R extends DomainReadRequest>(tx:Tx,p:Principal,request:R):Promise<DomainReadResults[R['kind']]> {
  let result:DomainReadResults[keyof DomainReadResults];
  switch(request.kind){
    case 'domain-type':result={type:await storedDomainType(tx,p,request.typeId,request.version)};break;
    case 'migration-context':result=await domainMigrationContext(tx,p,request.typeId);break;
    case 'migration-receipt':result=await domainMigrationReceipt(tx,p,request.typeId,request.id);break;
    case 'domain':result={domain:await storedDomain(tx,p,request.id)};break;
    case 'placement':result=await domainPlacement(tx,p,request.assetId);break;
    case 'domain-types':{
      const q=request.page.q??'',page=await selector(tx,p,'domain-types',request.page,{q});
      let query=tx.selectFrom('domain_types as h').innerJoin('domain_type_versions as v',j=>j.onRef('v.tenant_id','=','h.tenant_id').onRef('v.type_id','=','h.id').onRef('v.version','=','h.current_version'))
        .select(['h.id','h.key','h.current_version',sql<string>`v.definition->>'label'`.as('label')]).where('h.tenant_id','=',p.tenantId);
      if(q)query=query.where(sql<boolean>`(h.key ILIKE ${like(q)} OR v.definition->>'label' ILIKE ${like(q)})`);
      if(page.last!==null)query=query.where('h.id','>',page.last);
      const selected=query.orderBy('h.id').limit(page.limit+1);await domainRowsBudget(tx,selected);
      const rows=await domainQuery(tx,()=>selected.execute());
      result=page.finish(rows.map(row=>({typeId:row.id,key:row.key,label:row.label,currentVersion:row.current_version})),row=>row.typeId);break;
    }
    case 'domains':{
      const q=request.page.q??'',status=request.page.status??'active',parent=request.page.parentId??null;
      if(!['active','retired','all'].includes(status))throw pageInvalid();
      if(parent!==null&&parent!=='root')await storedDomain(tx,p,parent);
      const page=await selector(tx,p,'domains',request.page,{q,status,parent});
      let query=tx.selectFrom('domains').selectAll().where('tenant_id','=',p.tenantId);
      if(q)query=query.where(sql<boolean>`(name ILIKE ${like(q)} OR description ILIKE ${like(q)})`);
      if(status!=='all')query=query.where('status','=',status);
      if(parent==='root')query=query.where('parent_id','is',null);else if(parent!==null)query=query.where('parent_id','=',parent);
      if(page.last!==null)query=query.where('id','>',page.last);
      const selected=query.orderBy('id').limit(page.limit+1);await domainRowsBudget(tx,selected);
      const rows=await domainQuery(tx,()=>selected.execute());result=page.finish(rows.map(domainView),row=>row.id);break;
    }
    case 'owner-candidates':{
      const q=request.page.q??'',page=await selector(tx,p,'domain-owner-candidates',request.page,{q});
      let query=tx.selectFrom('memberships as m').innerJoin('identities as i','i.id','m.identity_id').select(['i.id','i.name'])
        .where('m.tenant_id','=',p.tenantId).where('m.active','=',true).where('i.active','=',true);
      if(q)query=query.where('i.name','ilike',like(q));if(page.last!==null)query=query.where('i.id','>',page.last);
      const selected=query.orderBy('i.id').limit(page.limit+1);await domainRowsBudget(tx,selected);
      result=page.finish(await domainQuery(tx,()=>selected.execute()),row=>row.id);break;
    }
    case 'domain-assets':{
      await storedDomain(tx,p,request.id);const page=await selector(tx,p,'domain-assets',request.page,{id:request.id});
      let query=tx.selectFrom('asset_domain_placements as d').innerJoin('assets as a',j=>j.onRef('a.tenant_id','=','d.tenant_id').onRef('a.id','=','d.asset_id'))
        .select(['a.id','a.name','a.version','d.version as placement_version']).where('d.tenant_id','=',p.tenantId).where('d.domain_id','=',request.id)
        .where(sql<boolean>`(a.visibility='tenant' OR a.allowed_identities @> ${JSON.stringify([p.id])}::jsonb)`);
      if(page.last!==null)query=query.where('a.id','>',page.last);
      const selected=query.orderBy('a.id').limit(page.limit+1);await domainRowsBudget(tx,selected);
      const rows=await domainQuery(tx,()=>selected.execute());
      result=page.finish(rows.map(row=>({assetId:row.id,name:row.name,assetVersion:row.version,placementVersion:row.placement_version})),row=>row.assetId);break;
    }
    case 'domain-history':{
      await storedDomain(tx,p,request.id);const page=await selector(tx,p,'domain-history',request.page,{id:request.id},true);
      let query=tx.selectFrom('domain_revisions').select(['version','snapshot']).where('tenant_id','=',p.tenantId).where('domain_id','=',request.id);
      if(page.last!==null)query=query.where('version','<',page.last);
      const selected=query.orderBy('version','desc').limit(page.limit+1);await domainRowsBudget(tx,selected);
      const rows=await domainQuery(tx,()=>selected.execute());
      const values=rows.map(row=>{const value=row.snapshot as DomainRevision;if(value.formatVersion!==1||value.domain.id!==request.id||value.domain.version!==row.version||!domainText(value.reason,500,true))throw domainStorage();return value;});
      await referencedDomains(tx,p,values.map(value=>value.domain.parentId));result=page.finish(values,row=>row.domain.version);break;
    }
    case 'placement-history':{
      await domainPlacement(tx,p,request.assetId);const page=await selector(tx,p,'domain-placement-history',request.page,{assetId:request.assetId},true);
      let query=tx.selectFrom('asset_domain_placement_revisions').select(['version','snapshot']).where('tenant_id','=',p.tenantId).where('asset_id','=',request.assetId);
      if(page.last!==null)query=query.where('version','<',page.last);
      const selected=query.orderBy('version','desc').limit(page.limit+1);await domainRowsBudget(tx,selected);
      const rows=await domainQuery(tx,()=>selected.execute());
      const values=rows.map(row=>{const value=row.snapshot as DomainPlacementRevision;if(value.formatVersion!==1||value.placement.assetId!==request.assetId||value.placement.version!==row.version||!domainText(value.reason,500,true))throw domainStorage();return value;});
      await referencedDomains(tx,p,values.map(value=>value.placement.domainId));result=page.finish(values,row=>row.placement.version);break;
    }
  }
  await domainPhysicalBudget(tx,result!);return result! as DomainReadResults[R['kind']];
}
