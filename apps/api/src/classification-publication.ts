// SPDX-License-Identifier: Apache-2.0
import {scope,sql} from '../../../packages/db/src/index.ts';
import {Problem} from '../../../packages/authz/src/index.ts';
import {approvalQuery,approvalRequestQuery,approvalStatus} from '../../../packages/domain/src/approval-service.ts';
import {classificationFailure,parseClassificationApprovalResult} from '../../../packages/domain/src/classification-service.ts';
import {publishGlossaryFromSite} from './glossary-publication.ts';
import {publishReferenceFromSite} from './reference-data-publication.ts';
import {publishStructureFromSite} from './reference-structure-publication.ts';

const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
type FailureCode='CLASSIFICATION_AUTHORITY_REVOKED'|'CLASSIFICATION_PRECONDITIONS_CHANGED'|'CLASSIFICATION_EXPIRED'|'CLASSIFICATION_APPROVAL_INVALID';
function permanent(error:unknown):FailureCode|null{
 if(error instanceof Problem)return error.code==='CLASSIFICATION_AUTHORITY_REVOKED'?'CLASSIFICATION_AUTHORITY_REVOKED':null;
 const value=error as {code?:unknown;message?:unknown}|null;
 if(value?.code==='42501'&&value.message==='classification forbidden')return 'CLASSIFICATION_AUTHORITY_REVOKED';
 if(value?.code==='40001'&&value.message==='classification approval expired')return 'CLASSIFICATION_EXPIRED';
 if(value?.code==='40001'&&['classification evidence stale','classification pin stale','classification version conflict'].includes(String(value.message)))return 'CLASSIFICATION_PRECONDITIONS_CHANGED';
 if(value?.code==='23514'&&value.message==='classification approval invalid')return 'CLASSIFICATION_APPROVAL_INVALID';
 return null;
}
interface Dependencies{scope:typeof scope;status:typeof approvalStatus}
/** Site-authenticated ID-only entry. The current requester is loaded from the
 * canonical request; no identity, evidence, result or failure is worker input. */
export function createClassificationPublicationHandler(dependencies:Dependencies={scope,status:approvalStatus}){
 return async(tenantId:string,requestId:string)=>{
  if(!uuid.test(tenantId)||!uuid.test(requestId))throw new Problem(400,'CLASSIFICATION_INPUT_INVALID','Provide a valid classification identifier.');
  let readyVersion:number|undefined;
  try{return await dependencies.scope(tenantId,'site:local',async tx=>{
   const row=(await approvalQuery(tx,()=>sql<{requester_id:string;binding:string;status:string;version:number;member_active:boolean|null;identity_active:boolean|null}>`
    select r.requester_id,r.binding,r.status,r.version,m.active as member_active,i.active as identity_active
    from public.approval_requests r left join public.memberships m on m.tenant_id=r.tenant_id and m.identity_id=r.requester_id
    left join public.identities i on i.id=r.requester_id where r.tenant_id=${tenantId}::uuid and r.id=${requestId}::uuid`.execute(tx))).rows[0];
   if(!row)throw new Problem(404,'CLASSIFICATION_UNAVAILABLE','The approval request is unavailable.');
   if(row.binding!=='classification.review'||!uuid.test(row.requester_id)||!Number.isInteger(row.version)||row.version<1||row.version>2147483647)
    throw new Problem(500,'CLASSIFICATION_STORAGE_INVALID','The approval request could not be verified.');
   if(row.status!=='ready')return dependencies.status(tx,tenantId,requestId);
   readyVersion=row.version;
   if(row.member_active!==true||row.identity_active!==true)throw new Problem(403,'CLASSIFICATION_AUTHORITY_REVOKED','The requester no longer has classification authority.');
   await approvalQuery(tx,()=>sql`select set_config('gc.actor_id',${row.requester_id},true)`.execute(tx));
   const result=(await approvalQuery(tx,()=>sql<{value:unknown}>`select public.gc_classification_publish(${requestId}::uuid) as value`.execute(tx))).rows[0]?.value;
   try{parseClassificationApprovalResult(result);}catch{throw new Problem(500,'CLASSIFICATION_STORAGE_INVALID','The classification result could not be verified.');}
   return dependencies.status(tx,tenantId,requestId);
  });}catch(error){
   const code=permanent(error);if(readyVersion===undefined||code===null)throw classificationFailure(error);
   // Failed publication has rolled back. Only an exact documented permanent
   // failure may now advance this same ready version under site authority.
   return dependencies.scope(tenantId,'site:local',async tx=>{
    await approvalQuery(tx,()=>sql`select public.gc_classification_fail(${requestId}::uuid,${readyVersion}::integer,${code}::text)`.execute(tx));
    return dependencies.status(tx,tenantId,requestId);
   });
  }
 };
}
export const publishClassificationFromSite=createClassificationPublicationHandler();
interface DispatchDependencies{scope:typeof scope;glossary:typeof publishGlossaryFromSite;classification:typeof publishClassificationFromSite;reference:typeof publishReferenceFromSite;structure?:typeof publishStructureFromSite}
export function createApprovalPublicationDispatcher(dependencies:DispatchDependencies={scope,glossary:publishGlossaryFromSite,classification:publishClassificationFromSite,reference:publishReferenceFromSite,structure:publishStructureFromSite}){
 return async(tenantId:string,requestId:string)=>{
  if(!uuid.test(tenantId)||!uuid.test(requestId))throw new Problem(400,'APPROVAL_INPUT_INVALID','Provide a valid approval identifier.');
  const binding=await dependencies.scope(tenantId,'site:local',async tx=>(await approvalRequestQuery(tx,()=>sql<{binding:string}>`
   select binding from public.approval_requests where tenant_id=${tenantId}::uuid and id=${requestId}::uuid`.execute(tx))).rows[0]?.binding);
  if(binding===undefined)throw new Problem(404,'APPROVAL_UNAVAILABLE','The approval request is unavailable.');
  if(binding==='glossary.publish')return dependencies.glossary(tenantId,requestId);
  if(binding==='classification.review')return dependencies.classification(tenantId,requestId);
  if(binding==='reference.publish')return dependencies.reference(tenantId,requestId);
  if(binding==='reference.structure.publish')return (dependencies.structure??publishStructureFromSite)(tenantId,requestId);
  throw new Problem(500,'APPROVAL_STORAGE_INVALID','The approval request could not be verified.');
 };
}
export const publishApprovalFromSite=createApprovalPublicationDispatcher();
