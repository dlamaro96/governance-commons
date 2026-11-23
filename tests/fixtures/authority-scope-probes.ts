// SPDX-License-Identifier: Apache-2.0
// Shared qualification probes; importing this file registers no test.
import assert from 'node:assert/strict';
import {query,scalar,tx,rejected,mutate,addPolicy,addRole,addPerson,forever,type FoundationFixture,type GrantOptions} from './authority-foundation.ts';
import type {Scope,UUID,Validity,UTC} from '../../packages/authority/src/types.ts';
import type {EffectCeiling,DelegableCeiling} from '../../packages/authority/src/decision-types.ts';
import {addAlignedGrant} from './authority-scope-fixture.ts';
export const tenant=(f:FoundationFixture):Scope=>({kind:'tenant',tenantId:f.tenant as UUID});
export const resource=(f:FoundationFixture):Scope=>({kind:'resource',resource:f.request.resource});
export const domain=(f:FoundationFixture,includeDescendants=true):Scope=>({kind:'domain',tenantId:f.tenant as UUID,domainId:f.request.resource.id,includeDescendants});
export const ceiling=(f:FoundationFixture,scope:Scope=tenant(f),validity:Validity=forever):EffectCeiling=>({actions:[f.request.action],resourceKinds:['asset'],fields:null,scope,validity});
export const onward=(f:FoundationFixture,scope:Scope=tenant(f),validity:Validity=forever):DelegableCeiling=>({actions:['asset:metadata.read'],fields:null,scope,validity,remainingDepth:4});
export const interval=(f:FoundationFixture,start:number|null,end:number|null):Validity=>({notBefore:start===null?null:new Date(Date.parse(f.now)+start).toISOString() as UTC,expiresAt:end===null?null:new Date(Date.parse(f.now)+end).toISOString() as UTC});
export const readonly=<T>(f:FoundationFixture,work:()=>Promise<T>)=>tx(f.owner,async()=>{await query(f.owner,"SET LOCAL statement_timeout='25s';SET LOCAL lock_timeout='2s'");await query(f.owner,"SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[f.tenant,f.identity]);return work();},'REPEATABLE READ READ ONLY');
export async function validateBoth(f:FoundationFixture,ids:string[]){await readonly(f,async()=>{for(const id of ids)await query(f.owner,'SELECT gc_authority.validate_grant($1,$2,true)',[f.tenant,id]);await query(f.owner,'SELECT gc_authority.validate_read_grants_v1($1,$2::uuid[])',[f.tenant,ids]);});}
export async function snapshot(f:FoundationFixture){return tx(f.admin,async()=>{const rows:Record<string,unknown>={};for(const table of ['tenant_heads','definition_heads','definition_versions','policy_versions','role_policy_pins','grant_heads','grant_human_beneficiaries','grant_group_beneficiaries','ordinary_role_origins','responsibility_origins','connected_parents','lifecycle_revisions','projection_measures','write_bindings','write_lock_claims'])rows[table]=(await query(f.admin,`SELECT to_jsonb(h) body FROM gc_authority.${table} h WHERE tenant_id=$1 ORDER BY to_jsonb(h)::text`,[f.tenant])).rows;return rows;},'REPEATABLE READ READ ONLY');}
export async function refuses(f:FoundationFixture,work:()=>Promise<unknown>){const before=await snapshot(f);await assert.rejects(mutate(f,work),rejected('23514'));assert.deepEqual(await snapshot(f),before,'Refused write must preserve heads, ledger, measures, bindings and epoch');}
export async function root(f:FoundationFixture,options:GrantOptions & {effect?:EffectCeiling}){return mutate(f,async()=>addAlignedGrant(f,await addRole(f,[await addPolicy(f)]),options));}
export async function pair(f:FoundationFixture,parent:GrantOptions & {effect?:EffectCeiling},child:GrantOptions & {effect?:EffectCeiling}){const issuer=await addPerson(f);return mutate(f,async()=>{const role=await addRole(f,[await addPolicy(f)]),p=await addAlignedGrant(f,role,{...parent,beneficiary:{kind:'human',id:issuer}}),c=await addAlignedGrant(f,role,{...child,kind:'delegation',issuer,parent:p});return {p,c};});}

