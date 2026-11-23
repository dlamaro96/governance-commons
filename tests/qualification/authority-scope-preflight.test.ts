// SPDX-License-Identifier: Apache-2.0
// Execute on the populated SQL035 database before applying036.
// Every successful migration probe rolls back; the harness alone installs036.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import {fixture,query,extra,type FoundationFixture} from '../fixtures/authority-foundation.ts';
import {legacyGraph,remediate,allCanonicalState,legacyKinds} from '../fixtures/authority-scope-legacy.ts';
const migration=readFileSync(new URL('../../packages/db/migrations/036_authority_scope_alignment.sql',import.meta.url),'utf8');
async function probe(f:FoundationFixture,expected:'23514'|'55P03'|null){
 const before=await allCanonicalState(f);let actual:string|null=null;
 await query(f.owner,'BEGIN');try{
  try{await f.owner.query(migration);}catch(error){const e=error as {code?:unknown;message?:unknown};assert.ok(e.code==='23514'||e.code==='55P03','Unexpected migration refusal class');assert.equal(e.message,e.code==='55P03'?'AUTHORITY_SCOPE_UPGRADE_BUSY':'AUTHORITY_SCOPE_UPGRADE_INCOMPATIBLE');actual=e.code;}
  assert.equal(actual,expected,'Exact expected migration refusal or successful rollback probe');
 }finally{await query(f.owner,'ROLLBACK');}
 assert.deepEqual(await allCanonicalState(f),before,'All canonical rows, functions, ACLs, RLS policies, triggers and migration ledger must remain exact');
 return {expected,actual,rolledBack:true as const};
}
test('SQL036 preflight refuses SQL035 reverse-own then accepts explicit native revocation without rewriting history',async t=>{
 const f=await fixture(t),grants=await legacyGraph(f,'reverse-own');await probe(f,'23514');await remediate(f,grants);await probe(f,null);
});
test('SQL036 preflight refuses SQL035 future-reverse-own then accepts explicit native revocation without rewriting history',async t=>{
 const f=await fixture(t),grants=await legacyGraph(f,'future-reverse-own');await probe(f,'23514');await remediate(f,grants);await probe(f,null);
});
test('SQL036 preflight refuses SQL035 expired-reverse-own then accepts explicit native revocation without rewriting history',async t=>{
 const f=await fixture(t),grants=await legacyGraph(f,'expired-reverse-own');await probe(f,'23514');await remediate(f,grants);await probe(f,null);
});
test('SQL036 preflight refuses SQL035 child-effect-lifetime then accepts explicit native revocation without rewriting history',async t=>{
 const f=await fixture(t),grants=await legacyGraph(f,'child-effect-lifetime');await probe(f,'23514');await remediate(f,grants);await probe(f,null);
});
test('SQL036 preflight refuses SQL035 child-onward-lifetime then accepts explicit native revocation without rewriting history',async t=>{
 const f=await fixture(t),grants=await legacyGraph(f,'child-onward-lifetime');await probe(f,'23514');await remediate(f,grants);await probe(f,null);
});
test('SQL036 preflight refuses SQL035 revoked-bad-ancestor then accepts explicit native revocation without rewriting history',async t=>{
 const f=await fixture(t),grants=await legacyGraph(f,'revoked-bad-ancestor');await probe(f,'23514');await remediate(f,grants);await probe(f,null);
});
test('SQL036 preflight refuses an active protected-table writer without deadlock or partial replacement',async t=>{
 const f=await fixture(t),writer=await extra(f,'owner');await query(writer,'BEGIN');try{await query(writer,'LOCK TABLE gc_authority.grant_heads IN ROW EXCLUSIVE MODE');await probe(f,'55P03');}finally{await query(writer,'ROLLBACK');}await probe(f,null);
});
test('SQL036 preflight scans an incompatible second tenant despite the callers initial tenant context',async t=>{
 const f=await fixture(t),other={...f,tenant:f.otherTenant,request:{...f.request,resource:{...f.request.resource,tenantId:f.otherTenant as typeof f.request.resource.tenantId}}};
 await query(f.owner,"SELECT set_config('gc.tenant_id',$1,false)",[other.tenant]);
 const grants=await legacyGraph(other,'reverse-own');
 await query(f.owner,"SELECT set_config('gc.tenant_id',$1,false)",[f.tenant]);
 await probe(f,'23514');
 await query(f.owner,"SELECT set_config('gc.tenant_id',$1,false)",[other.tenant]);
 await remediate(other,grants);
 await query(f.owner,"SELECT set_config('gc.tenant_id',$1,false)",[f.tenant]);
 await probe(f,null);
});
