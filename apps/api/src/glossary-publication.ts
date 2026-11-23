// SPDX-License-Identifier: Apache-2.0
import {scope,sql} from '../../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../../packages/authz/src/index.ts';
import {approvalStatus} from '../../../packages/domain/src/approval-service.ts';
import {publishApprovedGlossary,glossaryPublicationFailure} from '../../../packages/domain/src/glossary-publication-service.ts';
import {configureRelationTransaction,relationQuery,uuid} from '../../../packages/domain/src/relation-store.ts';
import {record,assetView,once} from './repository.ts';

type FailureCode='GLOSSARY_AUTHORITY_REVOKED'|'GLOSSARY_STATE_CONFLICT'|'GLOSSARY_POLICY_INVALID'|'GLOSSARY_INPUT_INVALID'|'GLOSSARY_LIMIT';
const limits=new Set(['GLOSSARY_LIMIT','RELATION_PROFILE_LIMIT','MODEL_LIMIT','APPROVAL_LIMIT']);
function permanent(error:Problem):FailureCode|null {
 if(error.status===403||error.status===404)return 'GLOSSARY_AUTHORITY_REVOKED';
 if(error.status===409)return 'GLOSSARY_STATE_CONFLICT';
 if(error.status===400)return 'GLOSSARY_INPUT_INVALID';
 if(error.status===422)return limits.has(error.code)?'GLOSSARY_LIMIT':'GLOSSARY_POLICY_INVALID';
 return null;
}
interface Dependencies {scope:typeof scope;publish:typeof publishApprovedGlossary;status:typeof approvalStatus}
/** Site authentication happens at the route. No requester, permissions, payload,
 * publication outcome or error details are accepted from the worker. Separate
 * scopes guarantee a failed publication rolls back before recording failure. */
export function createGlossaryPublicationHandler(dependencies:Dependencies={scope,publish:publishApprovedGlossary,status:approvalStatus}) {
 return async (tenantId:string,requestId:string)=>{
  if(!uuid(tenantId)||!uuid(requestId))throw new Problem(400,'GLOSSARY_INPUT_INVALID','Provide a valid glossary identifier.');
  let readyVersion:number|undefined;
  try {
   return await dependencies.scope(tenantId,'site:local',async tx=>{
    await configureRelationTransaction(tx);
    const row=(await relationQuery(tx,()=>sql<{requester_id:string;binding:string;status:string;version:number;name:string|null;permissions:unknown;member_active:boolean|null;identity_active:boolean|null}>`
     select r.requester_id,r.binding,r.status,r.version,i.name,m.permissions,m.active as member_active,i.active as identity_active
     from public.approval_requests r left join public.memberships m on m.tenant_id=r.tenant_id and m.identity_id=r.requester_id
     left join public.identities i on i.id=r.requester_id where r.tenant_id=${tenantId}::uuid and r.id=${requestId}::uuid`.execute(tx))).rows[0];
    if(!row)throw new Problem(404,'GLOSSARY_UNAVAILABLE','The approval request is unavailable.');
    if(row.binding!=='glossary.publish'||!uuid(row.requester_id)||!Number.isInteger(row.version)||row.version<1||row.version>2147483647)
     throw new Problem(500,'GLOSSARY_STORAGE_INVALID','The approval request could not be verified.');
    if(row.status!=='ready')return dependencies.status(tx,tenantId,requestId);
    readyVersion=row.version;
    if(row.member_active!==true||row.identity_active!==true||typeof row.name!=='string'||!Array.isArray(row.permissions)||row.permissions.some(v=>typeof v!=='string'))
     throw new Problem(403,'GLOSSARY_AUTHORITY_REVOKED','The requester no longer has publication authority.');
    const principal:Principal={id:row.requester_id,name:row.name,tenantId,permissions:row.permissions};
    await relationQuery(tx,()=>sql`select set_config('gc.actor_id',${principal.id},true)`.execute(tx));
    await dependencies.publish(tx,principal,requestId,{record,assetSnapshot:assetView,once});
    return dependencies.status(tx,tenantId,requestId);
   });
  } catch(error) {
   const failure=glossaryPublicationFailure(error),code=permanent(failure);
   if(readyVersion===undefined||code===null)throw failure;
   return dependencies.scope(tenantId,'site:local',async tx=>{
    await configureRelationTransaction(tx);
    await relationQuery(tx,()=>sql`select public.gc_glossary_fail(${requestId}::uuid,${readyVersion}::integer,${code}::text)`.execute(tx));
    return dependencies.status(tx,tenantId,requestId);
   });
  }
 };
}
export const publishGlossaryFromSite=createGlossaryPublicationHandler();
