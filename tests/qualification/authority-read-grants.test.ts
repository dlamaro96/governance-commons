// SPDX-License-Identifier: Apache-2.0
/** Real isolated SQL031; owner tampering/instrumentation is restored exactly.
 * This supplements, never replaces, the original authority native suites. */
import assert from 'node:assert/strict';
import {createHash,randomInt} from 'node:crypto';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import {fixture,query,scalar,tx,rejected,uid,mutate,addPolicy,addRole,addGrant,fourEdge,selectors,assertOracle,foundationInstall,setMembership,load} from '../fixtures/authority-foundation.ts';
import {hashAuthorityRegistry} from '../../packages/authority/src/decision-identity.ts';
import {parsed} from '../unit/fixtures/authority-decision.ts';
import type {Version} from '../../packages/authority/src/types.ts';
type Fixture=Awaited<ReturnType<typeof fixture>>;
const originalSQL=readFileSync(new URL('../../packages/db/migrations/013_authority_foundation.sql',import.meta.url),'utf8');
assert.equal(createHash('sha256').update(originalSQL).digest('hex'),'4a9304cf02ab51fc085a6018cd22980e948bc6cd1167b3595ccb817b2cf41fbf');
function originalFunction(name:string){const begin=originalSQL.indexOf('CREATE FUNCTION gc_authority.'+name+'(');assert.ok(begin>=0);const end=originalSQL.indexOf('END $$;',begin);assert.ok(end>begin);return originalSQL.slice(begin,end+7);}
const readonly=<T>(f:Fixture,work:()=>Promise<T>,tenant=f.tenant)=>tx(f.owner,async()=>{await query(f.owner,"SET LOCAL statement_timeout='25s';SET LOCAL lock_timeout='2s'");await query(f.owner,"SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[tenant,f.identity]);return work();},'REPEATABLE READ READ ONLY');
const batch=(f:Fixture,ids:unknown,t=f.tenant)=>readonly(f,()=>query(f.owner,'SELECT gc_authority.validate_read_grants_v1($1::uuid,$2::uuid[])',[t,ids]));
async function graph(f:Fixture,count=4){let role:Awaited<ReturnType<typeof addRole>>;const ids:string[]=[];await mutate(f,async()=>{role=await addRole(f,[await addPolicy(f)]);for(let i=0;i<count;i++)ids.push((await addGrant(f,role)).ref.id);});return {ids,role:role!};}
async function functionState(f:Fixture,name:string){return scalar(f.owner,"SELECT pg_get_functiondef(p.oid) definition,p.proowner::text owner,p.proacl::text acl,p.prosecdef,p.provolatile,p.proisstrict,p.proleakproof,p.proparallel,p.proconfig FROM pg_proc p WHERE p.oid=$1::regprocedure",[name]);}
async function withOriginalLoader(f:Fixture,work:()=>Promise<void>){const name='qualification_load_human_closure_sql013';assert.equal((await scalar(f.owner,'SELECT to_regprocedure($1) IS NULL absent',['gc_authority.'+name+'(text,text)'])).absent,true);await query(f.owner,originalFunction('load_human_closure_v1').replace('gc_authority.load_human_closure_v1(','gc_authority.'+name+'('));try{await work();}finally{await query(f.owner,'DROP FUNCTION gc_authority.'+name+'(text,text)');}}
async function withRegistryCounter(f:Fixture,work:()=>Promise<void>){
 const before=await functionState(f,'gc_authority.registry(text)'),alias='qualification_registry_sql013';assert.equal((await scalar(f.owner,'SELECT to_regprocedure($1) IS NULL absent',['gc_authority.'+alias+'(text)'])).absent,true);
 await query(f.owner,originalFunction('registry').replace('gc_authority.registry(','gc_authority.'+alias+'('));
 try{await query(f.owner,`CREATE OR REPLACE FUNCTION gc_authority.registry(raw text) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $probe$ BEGIN PERFORM set_config('gc.qualification_registry_calls',(coalesce(nullif(current_setting('gc.qualification_registry_calls',true),''),'0')::integer+1)::text,true);RETURN gc_authority.qualification_registry_sql013(raw);END $probe$`);await work();}
 finally{await query(f.owner,before.definition);await query(f.owner,'DROP FUNCTION gc_authority.'+alias+'(text)');assert.deepEqual(await functionState(f,'gc_authority.registry(text)'),before);}
}
async function counted(f:Fixture,groups:string[][]){return readonly(f,async()=>{await query(f.owner,"SELECT set_config('gc.qualification_registry_calls','0',true)");for(const ids of groups)await query(f.owner,'SELECT gc_authority.validate_read_grants_v1($1::uuid,$2::uuid[])',[f.tenant,ids]);return Number((await scalar(f.owner,"SELECT current_setting('gc.qualification_registry_calls') n")).n);});}
async function alternate(f:Fixture,role:Awaited<ReturnType<typeof addRole>>){
 const previous={registry:f.registry,registryId:f.registryId},registry=structuredClone(f.registry);registry.version=randomInt(1000,1000000000) as Version;const {digest:_,...preimage}=registry;registry.digest=parsed(hashAuthorityRegistry(preimage));const id=uid();await foundationInstall(f.owner,'registry-install',[id,registry.version,JSON.stringify(registry),registry.digest]);
 let grant:string;try{f.registry=registry;f.registryId=id;await mutate(f,async()=>{grant=(await addGrant(f,role)).ref.id;});}finally{Object.assign(f,previous);}return {id,registry,grant:grant!};
}
async function corrupt(f:Fixture,table:'registries'|'policy_versions'|'grant_heads',key:string,values:unknown[],field:'registry_document'|'policy_document'|'beneficiary_id',bad:unknown,work:()=>Promise<void>){
 // Fixed table/column allowlist, existing-row equality and exact finally restoration.
 const before=(await query(f.admin,`SELECT * FROM gc_authority.${table} WHERE ${key}`,values)).rows;assert.equal(before.length,1);const triggerState=(await query(f.admin,'SELECT tgname,tgenabled FROM pg_trigger WHERE tgrelid=$1::regclass ORDER BY tgname',['gc_authority.'+table])).rows;
 const write=(value:unknown)=>tx(f.admin,async()=>{await query(f.admin,`ALTER TABLE gc_authority.${table} DISABLE TRIGGER ALL`);assert.equal((await query(f.admin,`UPDATE gc_authority.${table} SET ${field}=$${values.length+1} WHERE ${key}`,[...values,value])).rowCount,1);await query(f.admin,`ALTER TABLE gc_authority.${table} ENABLE TRIGGER ALL`);});
 await write(bad);try{await work();}finally{await write(before[0]![field]);assert.deepEqual((await query(f.admin,`SELECT * FROM gc_authority.${table} WHERE ${key}`,values)).rows,before);assert.deepEqual((await query(f.admin,'SELECT tgname,tgenabled FROM pg_trigger WHERE tgrelid=$1::regclass ORDER BY tgname',['gc_authority.'+table])).rows,triggerState);}
}
const bothReject=async(f:Fixture,ids:string[],...codes:string[])=>{for(const id of ids)await assert.rejects(readonly(f,()=>query(f.owner,'SELECT gc_authority.validate_grant($1,$2,true)',[f.tenant,id])),rejected(...codes));await assert.rejects(batch(f,ids),rejected(...codes));};

test('read optimization returns byte-identical complete SQL013 closure in one repeatable-read snapshot',async t=>{
 const f=await fixture(t);await fourEdge(f);await graph(f,3);await withOriginalLoader(f,()=>readonly(f,async()=>{const old=(await scalar(f.owner,'SELECT gc_authority.qualification_load_human_closure_sql013($1,$2) value',[f.hash,JSON.stringify(selectors(f))])).value,current=(await scalar(f.owner,'SELECT gc_authority.load_human_closure_v1($1,$2) value',[f.hash,JSON.stringify(selectors(f))])).value;assert.deepEqual(current,old);assertOracle(f,current);}));
});
test('same exact registry is parsed once while every unique grant retains validation',async t=>{
 const f=await fixture(t),{ids}=await graph(f);await withRegistryCounter(f,async()=>assert.equal(await counted(f,[ids]),1));
 await corrupt(f,'grant_heads','tenant_id=$1 AND id=$2',[f.tenant,ids[3]],'beneficiary_id',uid(),async()=>{await assert.rejects(batch(f,ids),rejected('23514'));});await batch(f,ids);
});
test('distinct alternating retained registry tuples replace the sole cache entry',async t=>{
 const f=await fixture(t),{ids,role}=await graph(f,3),other=await alternate(f,role);await withRegistryCounter(f,async()=>{assert.equal(await counted(f,[[ids[0]!,other.grant,ids[1]!]]),3);assert.equal(await counted(f,[[ids[0]!,ids[1]!,other.grant]]),2);});
});
test('registry reuse never survives the end of an invocation even in the same transaction',async t=>{
 const f=await fixture(t),{ids}=await graph(f,2);await withRegistryCounter(f,async()=>assert.equal(await counted(f,[[ids[0]!],[ids[1]!]]),2));
});
test('corrupt retained registry document refuses both old and batch validation then exact restoration succeeds',async t=>{
 const f=await fixture(t),{ids,role}=await graph(f,1),other=await alternate(f,role);await corrupt(f,'registries','id=$1',[other.id],'registry_document','{}',async()=>{await bothReject(f,[other.grant],'22023');await assert.rejects(batch(f,[ids[0]!,other.grant]),rejected('22023'));});await batch(f,[ids[0]!,other.grant]);
});
test('corrupt root policy is still parsed and refused for every registry cache hit',async t=>{
 const f=await fixture(t),{ids}=await graph(f,1);let bad:string,policy:string;await mutate(f,async()=>{const pin=await addPolicy(f);policy=pin.policyId;bad=(await addGrant(f,await addRole(f,[pin]))).ref.id;});await corrupt(f,'policy_versions','tenant_id=$1 AND policy_id=$2 AND version=1',[f.tenant,policy!],'policy_document','{}',async()=>{await bothReject(f,[bad!],'22023');await assert.rejects(batch(f,[ids[0]!,bad!]),rejected('22023'));});await batch(f,[ids[0]!,bad!]);
});
test('batch capability remains owner-only readonly repeatable-read and exact tenant scoped',async t=>{
 const f=await fixture(t),{ids}=await graph(f,1);for(const client of [f.login,f.api,f.legacy])await assert.rejects(tx(client,()=>query(client,'SELECT gc_authority.validate_read_grants_v1($1,$2)',[f.tenant,ids]),'REPEATABLE READ READ ONLY'),rejected('42501'));
 await assert.rejects(query(f.owner,'SELECT gc_authority.validate_read_grants_v1($1,$2)',[f.tenant,ids]),rejected('42501'));await assert.rejects(batch(f,ids,f.otherTenant),rejected('42501'));
 await assert.rejects(readonly(f,()=>query(f.owner,'SELECT gc_authority.validate_read_grants_v1($1,$2)',[f.otherTenant,ids]),f.otherTenant),rejected('23514'));await batch(f,ids);
});
test('batch UUID array bounds reject null duplicates multidimensional and oversize inputs without partial return',async t=>{
 const f=await fixture(t),{ids}=await graph(f,1);for(const input of [null,[null],[ids[0],ids[0]],[[ids[0]]],Array.from({length:1537},()=>uid())])await assert.rejects(batch(f,input),rejected('54000'));await batch(f,[]);await batch(f,ids);
});
test('fresh current membership revocation cannot reuse a previously successful closure',async t=>{
 const f=await fixture(t);await graph(f);const first=await load(f);assertOracle(f,first);await setMembership(f,f.owner,f.tenant,false);await assert.rejects(load(f),e=>e instanceof Error&&'code'in e&&e.code==='AUTHORITY_FOUNDATION_SESSION_REJECTED');await setMembership(f,f.owner,f.tenant,true);assertOracle(f,await load(f));
});
test('original write validator body remains immutable and rejected writes preserve the authority epoch',async t=>{
 const f=await fixture(t),expected=originalFunction('validate_grant').split(' AS $$')[1]!.slice(0,-3),row=await scalar(f.owner,"SELECT prosrc FROM pg_proc WHERE oid='gc_authority.validate_grant(uuid,uuid,boolean)'::regprocedure");assert.equal(row.prosrc,expected);
 const before=(await scalar(f.owner,'SELECT authority_epoch::text n FROM gc_authority.tenant_heads WHERE tenant_id=$1',[f.tenant])).n;await assert.rejects(mutate(f,async()=>{await addGrant(f,await addRole(f,[await addPolicy(f)]),{omitOrigin:true});}),rejected('23514'));assert.equal((await scalar(f.owner,'SELECT authority_epoch::text n FROM gc_authority.tenant_heads WHERE tenant_id=$1',[f.tenant])).n,before);
});
