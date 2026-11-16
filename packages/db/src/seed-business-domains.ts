// SPDX-License-Identifier: Apache-2.0
/** Synthetic domain examples use the same runtime role, protected service,
 * immutable revisions and atomic journal as HTTP requests. No fixture bypass. */
import {randomUUID} from 'node:crypto';
import {db,scope} from './index.ts';
import {record,once} from '../../../apps/api/src/repository.ts';
import {domainMutate} from '../../domain/src/business-domain-service.ts';
import type {Principal} from '../../authz/src/index.ts';
import type {DomainTypeDefinition} from '../../domain/src/business-domain-contracts.ts';
import type {DomainMutationRequest,DomainMutationResults} from '../../domain/src/business-domain-service-contracts.ts';
const definition:DomainTypeDefinition={formatVersion:1,kind:'domain-type',id:'business_area',version:1,label:'Business area',parents:[],overrideAttributes:[],requiredOwner:true,
 attributes:{criticality:{type:'enum',values:['standard','high'],required:true,label:'Operational criticality'}},
 lifecycle:{initial:'draft',states:['draft','active'],transitions:[{from:'draft',to:'active'},{from:'active',to:'draft'}]}};
export async function seedBusinessDomains():Promise<void>{
 try {
  for(const example of [
   {tenantId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',id:'10000000-0000-4000-8000-000000000001',name:'Harbor Steward',root:'Retail operations',children:['Customer services','Supply operations']},
   {tenantId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',id:'10000000-0000-4000-8000-000000000005',name:'Summit Administrator',root:'Logistics operations',children:['Fleet services','Delivery operations']},
  ]) {
   const p:Principal={id:example.id,name:example.name,tenantId:example.tenantId,permissions:[]};
   const mutate=<R extends DomainMutationRequest>(key:string,request:R):Promise<DomainMutationResults[R['kind']]>=>
    scope(p.tenantId,p.id,tx=>domainMutate(tx,p,'harbor-demo.domains.v1.'+key,request,randomUUID(),{record,once}));
   const {type}=await mutate('type',{kind:'domain-type.create',definition,reason:'Initialize independent synthetic business-area examples.'});
   const create=(name:string,parentId:string|null)=>({kind:'domain.create' as const,name,description:'Independent synthetic example for local development.',parentId,
    type:{typeId:type.typeId,version:type.version},attributes:{criticality:'standard'},ownerId:p.id,reason:'Initialize independent synthetic domain examples.'});
   const {domain:root}=await mutate('root',create(example.root,null));
   for(let index=0;index<example.children.length;index++)await mutate('child.'+index,create(example.children[index]!,root.id));
  }
  console.log('Seeded two typed synthetic domain trees with real revisions and audit. No scans or placements were inferred.');
 } finally {await db.destroy();}
}
