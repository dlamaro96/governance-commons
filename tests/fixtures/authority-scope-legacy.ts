// SPDX-License-Identifier: Apache-2.0
// Private SQL035 setup and preservation probes. Does not execute a migration.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {query,scalar,tx,uid,mutate,addPolicy,addRole,addPerson,revoke,type FoundationFixture,type HumanGrant} from './authority-foundation.ts';
import {addAlignedGrant} from './authority-scope-fixture.ts';
import {tenant,resource,ceiling,onward,interval,validateBoth} from './authority-scope-probes.ts';
export type LegacyKind='reverse-own'|'future-reverse-own'|'expired-reverse-own'|'child-effect-lifetime'|'child-onward-lifetime'|'revoked-bad-ancestor';
export const legacyKinds:readonly LegacyKind[]=['reverse-own','future-reverse-own','expired-reverse-own','child-effect-lifetime','child-onward-lifetime','revoked-bad-ancestor'];
export async function legacyGraph(f:FoundationFixture,kind:LegacyKind):Promise<HumanGrant[]>{
 const issuer=await addPerson(f),grants:HumanGrant[]=[];
 await mutate(f,async()=>{
  const role=await addRole(f,[await addPolicy(f)]),scope=resource(f);
  if(kind.endsWith('reverse-own')||kind==='reverse-own'){
   const validity=kind==='future-reverse-own'?interval(f,60000,120000):kind==='expired-reverse-own'?interval(f,-120000,-60000):{notBefore:null,expiresAt:null};
   grants.push(await addAlignedGrant(f,role,{scope:tenant(f),validity,effect:ceiling(f,scope,validity)}));
  }else if(kind==='revoked-bad-ancestor'){
   const p=await addAlignedGrant(f,role,{beneficiary:{kind:'human',id:issuer},scope:tenant(f),effect:ceiling(f,scope),delegable:onward(f,scope)});grants.push(p);
   grants.push(await addAlignedGrant(f,role,{kind:'delegation',issuer,parent:p,scope,effect:ceiling(f,scope)}));
  }else{
   const wide=interval(f,-60000,600000),narrow=interval(f,-30000,300000);
   const p=await addAlignedGrant(f,role,{beneficiary:{kind:'human',id:issuer},validity:wide,effect:ceiling(f,tenant(f),kind==='child-effect-lifetime'?narrow:wide),delegable:onward(f,tenant(f),narrow)});grants.push(p);
   grants.push(await addAlignedGrant(f,role,{kind:'delegation',issuer,parent:p,validity:wide,effect:ceiling(f,tenant(f),narrow)}));
  }
 });
 if(kind==='revoked-bad-ancestor')await mutate(f,async()=>revoke(f,'grant',grants[0]!.ref.id));
 // Prove old SQL035 canonical admission, including revoked retained ancestors;
 // no disabled trigger, fake seal, owner corruption or forged measure is used.
 await validateBoth(f,grants.map(g=>g.ref.id));return grants;
}
export async function remediate(f:FoundationFixture,grants:HumanGrant[]){
 const active=grants.filter(g=>g.state==='active');if(active.length)await mutate(f,async()=>{for(const g of [...active].reverse())await revoke(f,'grant',g.ref.id);});
 const actual=(await query(f.owner,"SELECT id,state FROM gc_authority.grant_heads WHERE tenant_id=$1 AND id=ANY($2::uuid[]) ORDER BY id",[f.tenant,grants.map(g=>g.ref.id)])).rows;assert.equal(actual.length,grants.length);assert.ok(actual.every(g=>g.state==='revoked'));
}
export async function allCanonicalState(f:FoundationFixture){
 return tx(f.admin,async()=>{
  const tables=(await query(f.admin,"SELECT n.nspname schema,c.relname name FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='r' AND n.nspname IN('public','gc_authn','gc_authority') ORDER BY n.nspname,c.relname")).rows;
  const rows:Record<string,unknown>={};for(const table of tables){assert.match(table.schema,/^[a-z_][a-z_0-9]*$/);assert.match(table.name,/^[a-z_][a-z_0-9]*$/);rows[`${table.schema}.${table.name}`]=await scalar(f.admin,`SELECT count(*)::text rows,encode(sha256(convert_to(coalesce(string_agg(to_jsonb(h)::text,E'\\n' ORDER BY to_jsonb(h)::text),''),'UTF8')),'hex') sha256 FROM "${table.schema}"."${table.name}" h`);}
  const definitions=(await query(f.admin,"SELECT p.oid::text oid,n.nspname,p.proname,pg_get_function_identity_arguments(p.oid) args,pg_get_functiondef(p.oid) body,p.proowner::text owner,p.proacl::text acl,p.prosecdef,p.proconfig FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN('public','gc_authn','gc_authority') AND p.prokind='f' ORDER BY p.oid")).rows;
  const relations=(await query(f.admin,"SELECT c.oid::text oid,n.nspname,c.relname,c.relowner::text owner,c.relacl::text acl,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN('public','gc_authn','gc_authority') ORDER BY c.oid")).rows;
  const triggers=(await query(f.admin,"SELECT t.oid::text oid,t.tgname,t.tgenabled,t.tgfoid::text function,pg_get_triggerdef(t.oid) definition FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN('public','gc_authn','gc_authority') ORDER BY t.oid")).rows;
  const policies=(await query(f.admin,"SELECT to_jsonb(p) body FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN('public','gc_authn','gc_authority') ORDER BY p.oid")).rows;
  const roles=(await query(f.admin,'SELECT to_jsonb(r) body FROM pg_roles r ORDER BY oid')).rows;
  const schemas=(await query(f.admin,"SELECT to_jsonb(n) body FROM pg_namespace n WHERE n.nspname IN('public','gc_authn','gc_authority') ORDER BY oid")).rows;
  const types=(await query(f.admin,"SELECT t.oid::text oid,t.typowner::text owner,t.typacl::text acl FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname IN('public','gc_authn','gc_authority') ORDER BY t.oid")).rows;
  const defaults=(await query(f.admin,'SELECT to_jsonb(a) body FROM pg_default_acl a ORDER BY oid')).rows;
  const digest=(v:unknown)=>createHash('sha256').update(JSON.stringify(v)).digest('hex');return {rows,functions:digest(definitions),relations:digest(relations),triggers:digest(triggers),policies:digest(policies),roles:digest(roles),schemas:digest(schemas),types:digest(types),defaultAcls:digest(defaults)};
 },'REPEATABLE READ READ ONLY');
}
export interface ScopeLegacyMarker {formatVersion:1;profile:'scope-alignment-sql035-legacy';tenantId:string;grants:Array<{id:string;kind:LegacyKind;mustRefuse:boolean;headSha256:string}>}
export async function seedLegacyScopeHistory(f:FoundationFixture):Promise<ScopeLegacyMarker>{
 const records:ScopeLegacyMarker['grants']=[];
 for(const kind of legacyKinds){const grants=await legacyGraph(f,kind);await remediate(f,grants);for(const [index,g] of grants.entries()){const row=await scalar(f.owner,"SELECT encode(sha256(convert_to(to_jsonb(h)::text,'UTF8')),'hex') digest FROM gc_authority.grant_heads h WHERE tenant_id=$1 AND id=$2",[f.tenant,g.ref.id]);records.push({id:g.ref.id,kind,mustRefuse:!kind.startsWith('child-')||index>0,headSha256:row.digest});}}
 return {formatVersion:1,profile:'scope-alignment-sql035-legacy',tenantId:f.tenant,grants:records};
}
