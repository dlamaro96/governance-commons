// SPDX-License-Identifier: Apache-2.0
import { sql, type Tx } from '../../db/src/index.ts';
import { Problem, type Principal } from '../../authz/src/index.ts';
import { authorizeDomain, lockDomainScope, lockDomainPrincipals, domainQuery, checkDomainDeadline, domainScopeMissing,
  domainPhysicalBudget, DOMAIN_READ, DOMAIN_WRITE, DOMAIN_TYPE_READ, DOMAIN_TYPE_WRITE, DOMAIN_PLACEMENT_READ } from './business-domain-store.ts';
import { readDomainResource } from './business-domain-read.ts';
import { captureDomainTypePreview, captureDomainHierarchyPreview } from './business-domain-preview.ts';
import { executeDomainMutation, domainMutationActions } from './business-domain-write.ts';
import type { DomainReadRequest, DomainReadResults, DomainPreviewRequest, DomainPreviewResults,
  DomainMutationRequest, DomainMutationResults, DomainHooks } from './business-domain-service-contracts.ts';

function readActions(request:DomainReadRequest):readonly string[]{
  switch(request.kind){
    case 'domain-types':case 'domain-type':return DOMAIN_TYPE_READ;
    case 'migration-context':case 'migration-receipt':return [...DOMAIN_TYPE_READ,...DOMAIN_READ];
    case 'owner-candidates':return DOMAIN_WRITE;
    case 'domain-assets':case 'placement':case 'placement-history':return DOMAIN_PLACEMENT_READ;
    default:return DOMAIN_READ;
  }
}
export async function domainRead<R extends DomainReadRequest>(tx:Tx,p:Principal,request:R):Promise<DomainReadResults[R['kind']]> {
  const actions=readActions(request),scoped=await lockDomainScope(tx,p,actions),current=await lockDomainPrincipals(tx,scoped,[],actions);
  return readDomainResource(tx,current,request);
}
export async function domainPreview<R extends DomainPreviewRequest>(tx:Tx,p:Principal,request:R):Promise<DomainPreviewResults[R['kind']]> {
  const actions=request.kind==='hierarchy'?DOMAIN_WRITE:[...DOMAIN_TYPE_WRITE,...DOMAIN_READ];
  const current=await lockDomainScope(tx,p,actions);
  const result=request.kind==='hierarchy'?await captureDomainHierarchyPreview(tx,current,request.change):await captureDomainTypePreview(tx,current,request);
  await domainPhysicalBudget(tx,{preview:result.preview});
  return {preview:result.preview} as DomainPreviewResults[R['kind']];
}
export async function domainMutate<R extends DomainMutationRequest>(tx:Tx,p:Principal,key:unknown,request:R,correlationId:string,hooks:DomainHooks):Promise<DomainMutationResults[R['kind']]> {
  if(typeof key!=='string'||key.length<8||key.length>128)throw new Problem(400,'IDEMPOTENCY_REQUIRED','An Idempotency-Key of 8–128 characters is required.');
  const actions=domainMutationActions(request),current=await authorizeDomain(tx,p,actions);
  const {kind,...withoutKind}=request,body=kind==='domain-type-migration.execute'?withoutKind:request;
  const response=await hooks.once(tx,current,kind,key,body,()=>executeDomainMutation(tx,current,key,request,correlationId,hooks),{
    query:work=>domainQuery(tx,work),
    authorizeReplay:async()=>{
      const fresh=await lockDomainScope(tx,current,actions);await lockDomainPrincipals(tx,fresh,[],actions);
      // Storage consults the finalized original private scope and exact success.
      // Today's subtree, a request hash and the cached response are not authority.
      const allowed=await domainQuery(tx,()=>sql<{allowed:boolean}>`select public.gc_domain_replay_authorize(${kind},${key}) as allowed`.execute(tx));
      if(!allowed.rows[0]?.allowed)throw domainScopeMissing();
    },
  });
  await domainQuery(tx,()=>sql`SET CONSTRAINTS ALL IMMEDIATE`.execute(tx));checkDomainDeadline(tx);return response;
}
