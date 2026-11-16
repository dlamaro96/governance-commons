// SPDX-License-Identifier: Apache-2.0
import {randomUUID,createHash} from 'node:crypto';
import {sql,lockTenantLedger,type Tx} from '../../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../../packages/authz/src/index.ts';
import type {DomainJournalOptions,DomainOnceOptions} from '../../../packages/domain/src/business-domain-service-contracts.ts';
import {visibleDomainMigration} from '../../../packages/domain/src/business-domain-read.ts';
import {visibleRelationOperation} from '../../../packages/domain/src/relation-migration-read.ts';
import {visibleApprovalRequest} from '../../../packages/domain/src/approval-service.ts';
import {sourceConfiguration} from '../../../packages/connectors/src/sources.ts';
import {connectorCapabilities} from '../../../packages/connectors/src/capabilities.ts';
export function assetView(r:any){return {id:r.id,name:r.name,qualifiedName:r.qualified_name,type:r.type,description:r.description,ownerId:r.owner_id??null,ownerName:r.owner_name??null,sourceId:r.source_id??null,sourceName:r.source_name??null,version:r.version,observedAt:r.observed_at,updatedAt:r.updated_at,status:r.status,metadata:r.metadata,modelId:r.model_id??null,modelVersion:r.model_version??null,attributes:r.attributes??{},typeState:r.type_state??null};}
export function sourceView(r:any){return {id:r.id,name:r.name,...sourceConfiguration(r),status:r.status,lastSuccessfulScan:r.last_successful_scan,capabilities:connectorCapabilities(r.connector_id)};}
export function jobView(r:any){return {id:r.id,sourceId:r.source_id,status:r.status,createdAt:r.created_at,finishedAt:r.finished_at,assetCount:r.asset_count,errorCode:r.error_code};}
export function auditView(r:any){return {id:r.id,action:r.action,resourceId:r.resource_id,actorName:r.actor_name,occurredAt:r.occurred_at,changes:r.changes,hash:r.hash,previousHash:r.previous_hash,correlationId:r.correlation_id};}
export function visibleAssets(tx:Tx,p:Principal){return tx.selectFrom('assets').leftJoin('identities as owners','owners.id','assets.owner_id').leftJoin('sources',j=>j.onRef('sources.id','=','assets.source_id').onRef('sources.tenant_id','=','assets.tenant_id')).selectAll('assets').select(['owners.name as owner_name','sources.name as source_name']).where('assets.tenant_id','=',p.tenantId).where(eb=>eb.or([eb('assets.visibility','=','tenant'),sql<boolean>`assets.allowed_identities @> ${JSON.stringify([p.id])}::jsonb`]));}
export function visibleAudit(tx:Tx,p:Principal){return tx.selectFrom('audit').selectAll().where('audit.tenant_id','=',p.tenantId).where(eb=>eb.or([
 sql<boolean>`${p.permissions.includes('models:read')} AND audit.action LIKE 'workflow.%' AND EXISTS(SELECT 1 FROM workflow_definitions w WHERE w.tenant_id=audit.tenant_id AND w.id=audit.resource_id)`,
 sql<boolean>`${p.permissions.includes('catalog:read')&&p.permissions.includes('catalog:write')} AND audit.action LIKE 'approval.%' AND EXISTS(SELECT 1 FROM approval_requests r WHERE r.tenant_id=audit.tenant_id AND r.id::text=audit.resource_id AND (${visibleApprovalRequest(p)}))`,
 sql<boolean>`audit.action LIKE 'quality.%' AND EXISTS(SELECT 1 FROM assets quality_target WHERE quality_target.tenant_id=audit.tenant_id AND quality_target.id::text=audit.resource_id AND public.gc_quality_visible(quality_target.id,${p.id}::uuid))`,
 eb.and(['quality.%','approval.%','workflow.%','glossary.%','asset.%','relation.%','relation_participation.%','participation.%','relation_migration.%','relation_preparation.%','domain_type.%','domain.%','asset_domain_placement.%','domain_type_migration.%'].map(pattern=>eb('audit.action','not like',pattern))),
 sql<boolean>`${p.permissions.includes('models:read')} AND audit.action LIKE 'domain_type.%' AND audit.changes->>'resourceKind'='domain-type'
  AND EXISTS(SELECT 1 FROM domain_types d WHERE d.tenant_id=audit.tenant_id AND d.id::text=audit.resource_id)`,
 sql<boolean>`${p.permissions.includes('domains:read')} AND audit.action LIKE 'domain.%' AND audit.changes->>'resourceKind'='domain'
  AND EXISTS(SELECT 1 FROM domains d WHERE d.tenant_id=audit.tenant_id AND d.id::text=audit.resource_id)`,
 sql<boolean>`audit.action LIKE 'domain_type_migration.%' AND audit.changes->>'resourceKind'='domain-type-migration' AND (${visibleDomainMigration(p,sql`audit.resource_id`)})`,
 sql<boolean>`${p.permissions.includes('domains:read')&&p.permissions.includes('catalog:read')} AND audit.action LIKE 'asset_domain_placement.%'
  AND audit.changes->>'resourceKind'='asset-domain-placement' AND EXISTS(SELECT 1 FROM asset_domain_placement_revisions r
   JOIN assets a ON a.tenant_id=r.tenant_id AND a.id=r.asset_id
   WHERE r.tenant_id=audit.tenant_id AND r.asset_id::text=audit.resource_id AND r.version::text=audit.changes->>'resourceVersion'
   AND (a.visibility='tenant' OR a.allowed_identities @> ${JSON.stringify([p.id])}::jsonb)
   AND (r.snapshot->'placement'->'domainId'='null'::jsonb OR EXISTS(SELECT 1 FROM domains d WHERE d.tenant_id=r.tenant_id AND d.id::text=r.snapshot->'placement'->>'domainId')))`,
 sql<boolean>`audit.action LIKE 'relation_migration.%' AND (${visibleRelationOperation(p,sql`audit.resource_id`)})`,
 sql<boolean>`${p.permissions.includes('models:read') && p.permissions.includes('catalog:read')} AND audit.action LIKE 'relation_preparation.%' AND EXISTS (
   SELECT 1 FROM relation_type_preparations preparation WHERE preparation.tenant_id=audit.tenant_id
    AND preparation.id::text=audit.resource_id AND preparation.created_by=${p.id}::uuid)`,
 sql<boolean>`audit.action LIKE 'relation_participation.%' AND EXISTS (
   SELECT 1 FROM relation_graph_receipt_bindings outcome JOIN relation_participations binding
    ON binding.tenant_id=outcome.tenant_id AND binding.id=outcome.binding_id
   WHERE outcome.tenant_id=audit.tenant_id AND outcome.binding_id::text=audit.resource_id AND outcome.role='changed'
    AND outcome.after_version::text=audit.changes->>'resourceVersion'
    AND (${visibleRelationOperation(p,sql`outcome.operation_id`)}))`,
 sql<boolean>`${p.permissions.includes('catalog:read')} AND audit.action LIKE 'asset.%' AND EXISTS (SELECT 1 FROM assets WHERE assets.tenant_id=audit.tenant_id AND assets.id::text=audit.resource_id AND (assets.visibility='tenant' OR assets.allowed_identities @> ${JSON.stringify([p.id])}::jsonb))`,
 sql<boolean>`${p.permissions.includes('catalog:read') && p.permissions.includes('models:read')} AND audit.action LIKE 'relation.%' AND EXISTS (SELECT 1 FROM relations r JOIN assets s ON s.tenant_id=r.tenant_id AND s.id=r.source_asset_id JOIN assets t ON t.tenant_id=r.tenant_id AND t.id=r.target_asset_id WHERE r.tenant_id=audit.tenant_id AND r.id::text=audit.resource_id AND (r.visibility='tenant' OR r.allowed_identities @> ${JSON.stringify([p.id])}::jsonb) AND (s.visibility='tenant' OR s.allowed_identities @> ${JSON.stringify([p.id])}::jsonb) AND (t.visibility='tenant' OR t.allowed_identities @> ${JSON.stringify([p.id])}::jsonb))`
]));}
export function stableString(value:unknown):string{if(Array.isArray(value))return '['+value.map(stableString).join(',')+']';if(value&&typeof value==='object')return '{'+Object.keys(value as object).sort().map(k=>JSON.stringify(k)+':'+stableString((value as any)[k])).join(',')+'}';return JSON.stringify(value);}
export async function record(tx:Tx,p:Principal,action:string,resourceId:string,version:number,changes:any,correlationId:string,options?:DomainJournalOptions){
 const query=options?.query??(<T>(work:()=>Promise<T>)=>work());
 await query(()=>lockTenantLedger(tx,p.tenantId));
 const prior=await query(()=>tx.selectFrom('audit').select('hash').orderBy('sequence','desc').executeTakeFirst());
 const id=randomUUID(),occurredAt=options?.occurredAt??new Date().toISOString(),previousHash=prior?.hash??'0'.repeat(64);
 if(options&&(!changes||typeof changes!=='object'||Object.keys(changes).join(',')!=='reason'||typeof changes.reason!=='string'||options.resourceKind!==options.data.resourceKind))
  throw new Problem(500,'DOMAIN_STORAGE_INVALID','The domain journal could not be verified.');
 const recordedChanges=options?{...options.data,reason:changes.reason,resourceVersion:version}:changes;
 const envelope={id,tenantId:p.tenantId,actorId:p.id,actorName:p.name,action,resourceId,version,changes:recordedChanges,correlationId,occurredAt,previousHash};
 const hash=createHash('sha256').update(stableString(envelope)).digest('hex');
 await query(()=>tx.insertInto('audit').values({tenant_id:p.tenantId,id,actor_id:p.id,actor_name:p.name,action,resource_id:resourceId,changes:{...recordedChanges,resourceVersion:version},correlation_id:correlationId,occurred_at:occurredAt,previous_hash:previousHash,hash,envelope:JSON.stringify(envelope)}).execute());
 const payload={specversion:'1.0',id,type:action,source:'governance-commons',subject:resourceId,time:occurredAt,tenantId:p.tenantId,resourceVersion:version,actorId:p.id,correlationId,...(options?{resourceKind:options.resourceKind,data:options.data}:{})};
 await query(()=>tx.insertInto('outbox').values({tenant_id:p.tenantId,id,event_type:action,resource_id:resourceId,resource_version:version,payload,...(options?{created_at:occurredAt}:{})}).execute());
}
export async function once<T>(tx:Tx,p:Principal,operation:string,key:unknown,body:unknown,fn:()=>Promise<T>,options?:DomainOnceOptions<T>):Promise<T>{
 if(typeof key!=='string'||key.length<8||key.length>128)throw new Problem(400,'IDEMPOTENCY_REQUIRED','An Idempotency-Key of 8–128 characters is required.');
 const query=options?.query??(<V>(work:()=>Promise<V>)=>work());
 const digest=createHash('sha256').update(stableString(body)).digest('hex');
 await query(()=>sql`select pg_advisory_xact_lock(hashtextextended(${p.tenantId+p.id+operation+key},0))`.execute(tx));
 const old=await query(()=>tx.selectFrom('idempotency').selectAll().where('tenant_id','=',p.tenantId).where('actor_id','=',p.id).where('operation','=',operation).where('key','=',key).executeTakeFirst());
 if(old){if(old.request_hash!==digest)throw new Problem(409,'IDEMPOTENCY_CONFLICT','This key was used with different content.');if(options)await options.authorizeReplay(old.response as T);return old.response as T;}
 await query(()=>lockTenantLedger(tx,p.tenantId));
 const response=await fn();await query(()=>tx.insertInto('idempotency').values({tenant_id:p.tenantId,actor_id:p.id,operation,key,request_hash:digest,response:JSON.stringify(response)}).execute());return response;
}
