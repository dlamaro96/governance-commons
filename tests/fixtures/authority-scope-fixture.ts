// SPDX-License-Identifier: Apache-2.0
// Existing sealed addGrant mechanics, with an
// independently supplied effect ceiling solely to exercise literal bounds.
import assert from 'node:assert/strict';
import {uid,query,version,forever,type FoundationFixture,type GrantOptions,type HumanGrant} from './authority-foundation.ts';
import type {UUID,Version} from '../../packages/authority/src/types.ts';
import type {EffectCeiling,GrantRef} from '../../packages/authority/src/decision-types.ts';
export async function addAlignedGrant(f:FoundationFixture,role:{roleId:UUID;version:Version},options:GrantOptions & {effect?:EffectCeiling}={}):Promise<HumanGrant>{
 const id=uid(),kind=options.kind??'ordinary-role',issuer={kind:'human' as const,id:options.issuer??f.identity as UUID},beneficiary=options.beneficiary??{kind:'human' as const,id:f.identity as UUID};
 const scope=options.scope??{kind:'tenant' as const,tenantId:f.tenant as UUID},validity=options.validity??forever,actions=options.actions??[f.request.action],ceiling:EffectCeiling=options.effect??{actions,resourceKinds:['asset'],fields:null,scope,validity};
 const scopeParts=scope.kind==='tenant'?[null,null,null,null]:scope.kind==='domain'?[scope.domainId,scope.includeDescendants,null,null]:[null,null,scope.resource.kind,scope.resource.id];
 await query(f.owner,`INSERT INTO gc_authority.grant_heads(tenant_id,id,issuance_version,kind,issuer_identity_id,beneficiary_kind,beneficiary_id,scope_kind,scope_tenant_id,domain_id,include_descendants,resource_kind,resource_id,not_before,expires_at,effect_ceiling,delegable_ceiling,control_ceiling,registry_id,registry_version,registry_digest,created_at,created_by,head_version,state,changed_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$1,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$4,1,'active',$20)`,[f.tenant,id,kind,issuer.id,beneficiary.kind,beneficiary.id,scope.kind,...scopeParts,validity.notBefore,validity.expiresAt,JSON.stringify(ceiling),options.delegable?JSON.stringify(options.delegable):null,options.control?JSON.stringify(options.control):null,f.registryId,f.registry.version,f.registry.digest,f.now]);
 if(beneficiary.kind==='human')await query(f.owner,'INSERT INTO gc_authority.grant_human_beneficiaries(tenant_id,grant_id,grant_version,identity_id) VALUES($1,$2,1,$3)',[f.tenant,id,beneficiary.id]);
 else await query(f.owner,"INSERT INTO gc_authority.grant_group_beneficiaries(tenant_id,grant_id,grant_version,group_id,group_kind) VALUES($1,$2,1,$3,'group')",[f.tenant,id,beneficiary.id]);
 const base={ref:{kind:kind==='delegation'||kind==='elevation'?kind:'grant',id,version} as GrantRef,kind,tenantId:f.tenant as UUID,state:'active' as const,issuer,beneficiary,scope,validity,ceiling};
 let grant:HumanGrant;
 if(kind==='ordinary-role'){
  if(!options.omitOrigin)await query(f.owner,"INSERT INTO gc_authority.ordinary_role_origins(tenant_id,grant_id,grant_version,role_id,role_version,role_kind) VALUES($1,$2,1,$3,$4,'role')",[f.tenant,id,role.roleId,role.version]);
  grant={...base,kind,role,delegable:options.delegable??null};
 }else if(kind==='responsibility'){
  assert.ok(options.responsibility);const type=options.responsibility,assignmentId=uid();
  await query(f.owner,"INSERT INTO gc_authority.responsibility_origins(tenant_id,grant_id,grant_version,assignment_id,assignment_version,type_id,type_version,type_kind,mapped_role_id,mapped_role_version,effective_grant_id) VALUES($1,$2,1,$3,1,$4,1,'responsibility-type',$5,$6,$7)",[f.tenant,id,assignmentId,type.typeId,type.mappedRole?.roleId??null,type.mappedRole?.version??null,type.mappedRole?id:null]);
  grant={...base,kind,type:{id:type.typeId,version},mappedRole:type.mappedRole,assignmentId,assignmentVersion:version,effectiveGrantId:type.mappedRole?id:null,delegable:options.delegable??null};
 }else{
  assert.ok(options.parent);const parent=options.parent.ref;
  await query(f.owner,'INSERT INTO gc_authority.connected_parents(tenant_id,child_id,child_version,parent_id,parent_version,parent_kind,via_group_membership_id,via_group_membership_version) VALUES($1,$2,1,$3,$4,$5,$6,$7)',[f.tenant,id,parent.id,parent.version,parent.kind,options.via??null,options.via?1:null]);
  f.model.parents.set(id,{parent,via:options.via??null});
  assert.equal(beneficiary.kind,'human');grant=kind==='delegation'?{...base,kind,beneficiary:{kind:'human',id:beneficiary.id},parent,delegable:options.delegable??null}:{...base,kind,beneficiary:{kind:'human',id:beneficiary.id},parent,use:null};
 }
 f.pending.push({family:'grant',id,kind:null,version:1,head:1,actor:issuer.id});f.model.grants.push(grant);return grant;
}
