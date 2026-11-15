// SPDX-License-Identifier: Apache-2.0
import {randomUUID,createHash} from 'node:crypto';
import {sql,lockTenantLedger,type Tx} from '../../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../../packages/authz/src/index.ts';
export function assetView(r:any){return {id:r.id,name:r.name,qualifiedName:r.qualified_name,type:r.type,description:r.description,ownerId:r.owner_id??null,ownerName:r.owner_name??null,sourceId:r.source_id??null,sourceName:r.source_name??null,version:r.version,observedAt:r.observed_at,updatedAt:r.updated_at,status:r.status,metadata:r.metadata,modelId:r.model_id??null,modelVersion:r.model_version??null,attributes:r.attributes??{}};}
export function sourceView(r:any){return {id:r.id,name:r.name,host:r.host,port:r.port,database:r.database_name,schema:r.schema_name,secretRef:r.secret_ref,status:r.status,lastSuccessfulScan:r.last_successful_scan,capabilities:{metadata:{implemented:true,verification:'NOT_RUN'},columnLineage:{implemented:false,reason:'Parser qualification remains pending.'}}};}
export function jobView(r:any){return {id:r.id,sourceId:r.source_id,status:r.status,createdAt:r.created_at,finishedAt:r.finished_at,assetCount:r.asset_count,errorCode:r.error_code};}
export function auditView(r:any){return {id:r.id,action:r.action,resourceId:r.resource_id,actorName:r.actor_name,occurredAt:r.occurred_at,changes:r.changes,hash:r.hash,previousHash:r.previous_hash,correlationId:r.correlation_id};}
export function visibleAssets(tx:Tx,p:Principal){return tx.selectFrom('assets').leftJoin('identities as owners','owners.id','assets.owner_id').leftJoin('sources',j=>j.onRef('sources.id','=','assets.source_id').onRef('sources.tenant_id','=','assets.tenant_id')).selectAll('assets').select(['owners.name as owner_name','sources.name as source_name']).where('assets.tenant_id','=',p.tenantId).where(eb=>eb.or([eb('assets.visibility','=','tenant'),sql<boolean>`assets.allowed_identities @> ${JSON.stringify([p.id])}::jsonb`]));}
export function visibleAudit(tx:Tx,p:Principal){return tx.selectFrom('audit').selectAll().where('audit.tenant_id','=',p.tenantId).where(eb=>eb.or([
 eb('audit.action','not like','asset.%'),
 sql<boolean>`${p.permissions.includes('catalog:read')} AND EXISTS (SELECT 1 FROM assets WHERE assets.tenant_id=audit.tenant_id AND assets.id::text=audit.resource_id AND (assets.visibility='tenant' OR assets.allowed_identities @> ${JSON.stringify([p.id])}::jsonb))`
]));}
export function stableString(value:unknown):string{if(Array.isArray(value))return '['+value.map(stableString).join(',')+']';if(value&&typeof value==='object')return '{'+Object.keys(value as object).sort().map(k=>JSON.stringify(k)+':'+stableString((value as any)[k])).join(',')+'}';return JSON.stringify(value);}
export async function record(tx:Tx,p:Principal,action:string,resourceId:string,version:number,changes:any,correlationId:string){
 await lockTenantLedger(tx,p.tenantId);
 const prior=await tx.selectFrom('audit').select('hash').orderBy('sequence','desc').executeTakeFirst();
 const id=randomUUID(), occurredAt=new Date().toISOString(),previousHash=prior?.hash??'0'.repeat(64);
 const envelope={id,tenantId:p.tenantId,actorId:p.id,actorName:p.name,action,resourceId,version,changes,correlationId,occurredAt,previousHash};
 const hash=createHash('sha256').update(stableString(envelope)).digest('hex');
 await tx.insertInto('audit').values({tenant_id:p.tenantId,id,actor_id:p.id,actor_name:p.name,action,resource_id:resourceId,changes:{...changes,resourceVersion:version},correlation_id:correlationId,occurred_at:occurredAt,previous_hash:previousHash,hash,envelope:JSON.stringify(envelope)}).execute();
 await tx.insertInto('outbox').values({tenant_id:p.tenantId,id,event_type:action,resource_id:resourceId,resource_version:version,payload:{specversion:'1.0',id,type:action,source:'governance-commons',subject:resourceId,time:occurredAt,tenantId:p.tenantId,resourceVersion:version,actorId:p.id,correlationId}}).execute();
}
export async function once<T>(tx:Tx,p:Principal,operation:string,key:unknown,body:unknown,fn:()=>Promise<T>):Promise<T>{
 if(typeof key!=='string'||key.length<8||key.length>128)throw new Problem(400,'IDEMPOTENCY_REQUIRED','An Idempotency-Key of 8–128 characters is required.');
 const digest=createHash('sha256').update(stableString(body)).digest('hex');
 await sql`select pg_advisory_xact_lock(hashtextextended(${p.tenantId+p.id+operation+key},0))`.execute(tx);
 const old=await tx.selectFrom('idempotency').selectAll().where('actor_id','=',p.id).where('operation','=',operation).where('key','=',key).executeTakeFirst();
 if(old){if(old.request_hash!==digest)throw new Problem(409,'IDEMPOTENCY_CONFLICT','This key was used with different content.');return old.response as T;}
 await lockTenantLedger(tx,p.tenantId);
 const response=await fn();await tx.insertInto('idempotency').values({tenant_id:p.tenantId,actor_id:p.id,operation,key,request_hash:digest,response:JSON.stringify(response)}).execute();return response;
}
