// SPDX-License-Identifier: Apache-2.0
import {scope,sql} from '../../../packages/db/src/index.ts';
import {Problem} from '../../../packages/authz/src/index.ts';
import {approvalStatus} from '../../../packages/domain/src/approval-service.ts';
import {referenceFailure,referenceQuery,parseReferencePublicationResult} from '../../../packages/domain/src/reference-data-service.ts';
const uuid=/^(?!00000000-0000-0000-0000-000000000000$)[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
type FailureCode='REFERENCE_AUTHORITY_REVOKED'|'REFERENCE_PRECONDITIONS_CHANGED'|'REFERENCE_EXPIRED'|'REFERENCE_APPROVAL_INVALID';
function permanent(error:unknown):FailureCode|null{
 if(error instanceof Problem)return error.code==='REFERENCE_AUTHORITY_REVOKED'?'REFERENCE_AUTHORITY_REVOKED':null;
 const e=error as {code?:unknown;message?:unknown}|null;
 if(e?.code==='42501'&&e.message==='reference forbidden')return 'REFERENCE_AUTHORITY_REVOKED';
 if(e?.code==='40001'&&e.message==='reference approval expired')return 'REFERENCE_EXPIRED';
 if(e?.code==='40001'&&['reference version conflict','reference schedule stale','WORKFLOW_PIN_STALE'].includes(String(e.message)))return 'REFERENCE_PRECONDITIONS_CHANGED';
 if(e?.code==='23514'&&e.message==='reference approval invalid')return 'REFERENCE_APPROVAL_INVALID';return null;
}
interface Dependencies{scope:typeof scope;status:typeof approvalStatus}
/** Site receives only canonical IDs. Publication runs as the stored requester;
 * a permanent failure is recorded only after the failed effect rolled back. */
export function createReferencePublicationHandler(dependencies:Dependencies={scope,status:approvalStatus}){
 return async(tenantId:string,requestId:string)=>{
  if(!uuid.test(tenantId)||!uuid.test(requestId))throw new Problem(400,'REFERENCE_INPUT_INVALID','Provide a valid reference approval identifier.');
  let readyVersion:number|undefined;
  try{return await dependencies.scope(tenantId,'site:local',async tx=>{
   const row=(await referenceQuery(tx,()=>sql<{requester_id:string;binding:string;resource_id:string;resource_version:number|null;status:string;version:number;member_active:boolean|null;identity_active:boolean|null}>`
    select r.requester_id,r.binding,r.resource_id,r.resource_version,r.status,r.version,m.active as member_active,i.active as identity_active from public.approval_requests r
    left join public.memberships m on m.tenant_id=r.tenant_id and m.identity_id=r.requester_id left join public.identities i on i.id=r.requester_id
    where r.tenant_id=${tenantId}::uuid and r.id=${requestId}::uuid`.execute(tx))).rows[0];
   if(!row)throw new Problem(404,'REFERENCE_UNAVAILABLE','The approval request is unavailable.');
   if(row.binding!=='reference.publish'||!uuid.test(row.requester_id)||!uuid.test(row.resource_id)||!Number.isInteger(row.version)||row.version<1||row.version>2147483647||row.resource_version!==null&&(!Number.isInteger(row.resource_version)||row.resource_version<1||row.resource_version>2147483646))throw new Problem(500,'REFERENCE_STORAGE_INVALID','The approval request could not be verified.');
   if(row.status!=='ready')return dependencies.status(tx,tenantId,requestId);readyVersion=row.version;
   if(row.member_active!==true||row.identity_active!==true)throw new Problem(403,'REFERENCE_AUTHORITY_REVOKED','The requester no longer has reference-data authority.');
   await referenceQuery(tx,()=>sql`select set_config('gc.actor_id',${row.requester_id},true)`.execute(tx));
   const raw=(await referenceQuery(tx,()=>sql<{value:unknown}>`select public.gc_reference_publish(${requestId}::uuid) as value`.execute(tx))).rows[0]?.value;
   try{const result=parseReferencePublicationResult(raw);if(result.setId!==row.resource_id||result.version!==(row.resource_version??0)+1)throw 0;}catch{throw new Problem(500,'REFERENCE_STORAGE_INVALID','The reference publication result could not be verified.');}
   return dependencies.status(tx,tenantId,requestId);
  });}catch(error){
   const failure=permanent(error);if(readyVersion===undefined||failure===null)throw referenceFailure(error);
   return dependencies.scope(tenantId,'site:local',async tx=>{
    await referenceQuery(tx,()=>sql`select public.gc_reference_fail(${requestId}::uuid,${readyVersion}::integer,${failure}::text)`.execute(tx));return dependencies.status(tx,tenantId,requestId);
   }).catch(error=>{throw referenceFailure(error);});
  }
 };
}
export const publishReferenceFromSite=createReferencePublicationHandler();
