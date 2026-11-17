// SPDX-License-Identifier: Apache-2.0
import {scope,sql} from '../../../packages/db/src/index.ts';
import {Problem} from '../../../packages/authz/src/index.ts';
import {approvalStatus} from '../../../packages/domain/src/approval-service.ts';
import {structureFailure,structureQuery,parseStructurePublicationResult} from '../../../packages/domain/src/reference-structure-service.ts';
const uuid=/^(?!00000000-0000-0000-0000-000000000000$)[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
type FailureCode='REFERENCE_STRUCTURE_AUTHORITY_REVOKED'|'REFERENCE_STRUCTURE_PRECONDITIONS_CHANGED'|'REFERENCE_STRUCTURE_EXPIRED'|'REFERENCE_STRUCTURE_APPROVAL_INVALID';
function permanent(error:unknown):FailureCode|null{
 if(error instanceof Problem)return error.code==='REFERENCE_STRUCTURE_AUTHORITY_REVOKED'?'REFERENCE_STRUCTURE_AUTHORITY_REVOKED':null;
 const e=error as {code?:unknown;message?:unknown}|null;
 if(e?.code==='42501'&&e.message==='reference structure forbidden')return 'REFERENCE_STRUCTURE_AUTHORITY_REVOKED';
 if(e?.code==='40001'&&e.message==='reference structure approval expired')return 'REFERENCE_STRUCTURE_EXPIRED';
 if(e?.code==='40001'&&['reference structure version conflict','reference structure schedule stale','reference structure endpoint changed','WORKFLOW_PIN_STALE'].includes(String(e.message)))return 'REFERENCE_STRUCTURE_PRECONDITIONS_CHANGED';
 if(e?.code==='23514'&&e.message==='reference structure approval invalid')return 'REFERENCE_STRUCTURE_APPROVAL_INVALID';return null;
}
interface Dependencies{scope:typeof scope;status:typeof approvalStatus}
/** Site receives only canonical IDs. Publication runs as the stored requester;
 * a permanent failure is recorded only after the failed effect rolled back. */
export function createStructurePublicationHandler(dependencies:Dependencies={scope,status:approvalStatus}){
 return async(tenantId:string,requestId:string)=>{
  if(!uuid.test(tenantId)||!uuid.test(requestId))throw new Problem(400,'REFERENCE_STRUCTURE_INPUT_INVALID','Provide a valid structure approval identifier.');
  let readyVersion:number|undefined;
  try{return await dependencies.scope(tenantId,'site:local',async tx=>{
   const row=(await structureQuery(tx,()=>sql<{requester_id:string;binding:string;resource_id:string;resource_version:number|null;status:string;version:number;member_active:boolean|null;identity_active:boolean|null}>`
    select r.requester_id,r.binding,r.resource_id,r.resource_version,r.status,r.version,m.active as member_active,i.active as identity_active from public.approval_requests r
    left join public.memberships m on m.tenant_id=r.tenant_id and m.identity_id=r.requester_id left join public.identities i on i.id=r.requester_id
    where r.tenant_id=${tenantId}::uuid and r.id=${requestId}::uuid`.execute(tx))).rows[0];
   if(!row)throw new Problem(404,'REFERENCE_STRUCTURE_UNAVAILABLE','The approval request is unavailable.');
   if(row.binding!=='reference.structure.publish'||!uuid.test(row.requester_id)||!uuid.test(row.resource_id)||!Number.isInteger(row.version)||row.version<1||row.version>2147483647||row.resource_version!==null&&(!Number.isInteger(row.resource_version)||row.resource_version<1||row.resource_version>2147483646))throw new Problem(500,'REFERENCE_STRUCTURE_STORAGE_INVALID','The approval request could not be verified.');
   if(row.status!=='ready')return dependencies.status(tx,tenantId,requestId,structureQuery);readyVersion=row.version;
   if(row.member_active!==true||row.identity_active!==true)throw new Problem(403,'REFERENCE_STRUCTURE_AUTHORITY_REVOKED','The requester no longer has structure authority.');
   await structureQuery(tx,()=>sql`select set_config('gc.actor_id',${row.requester_id},true)`.execute(tx));
   const raw=(await structureQuery(tx,()=>sql<{value:unknown}>`select public.gc_reference_structure_publish(${requestId}::uuid) as value`.execute(tx))).rows[0]?.value;
   try{const result=parseStructurePublicationResult(raw);if(result.structureId!==row.resource_id||result.version!==(row.resource_version??0)+1)throw 0;}catch{throw new Problem(500,'REFERENCE_STRUCTURE_STORAGE_INVALID','The structure publication result could not be verified.');}
   return dependencies.status(tx,tenantId,requestId,structureQuery);
  });}catch(error){
   const failure=permanent(error);if(readyVersion===undefined||failure===null)throw structureFailure(error);
   return dependencies.scope(tenantId,'site:local',async tx=>{
    await structureQuery(tx,()=>sql`select public.gc_reference_structure_fail(${requestId}::uuid,${readyVersion}::integer,${failure}::text)`.execute(tx));return dependencies.status(tx,tenantId,requestId,structureQuery);
   }).catch(error=>{throw structureFailure(error);});
  }
 };
}
export const publishStructureFromSite=createStructurePublicationHandler();
