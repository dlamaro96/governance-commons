// SPDX-License-Identifier: Apache-2.0
// Native SQL036 structural and retained-history regression qualification.
import assert from 'node:assert/strict';
import test from 'node:test';
import {fixture,query,scalar,tx,rejected,uid,mutate,addPolicy,addRole,addPerson,forever,fourEdge,rawLoad,assertOracle,type FoundationFixture,type GrantOptions} from '../fixtures/authority-foundation.ts';
import type {Scope,UUID,Validity,UTC} from '../../packages/authority/src/types.ts';
import type {EffectCeiling,DelegableCeiling} from '../../packages/authority/src/decision-types.ts';
import {parseAuthorityHumanClosure} from '../../packages/authority-storage/src/loader.ts';
import {addAlignedGrant} from '../fixtures/authority-scope-fixture.ts';
import {tenant,resource,domain,ceiling,onward,interval,readonly,validateBoth,snapshot,refuses,root,pair} from '../fixtures/authority-scope-probes.ts';

test('SQL036 own resource and domain scope may narrow a tenant effect ceiling with complete parser parity',async t=>{
 const f=await fixture(t);for(const scope of [resource(f),domain(f)]){const g=await root(f,{scope,effect:ceiling(f)});await validateBoth(f,[g.ref.id]);}const raw=await rawLoad(f);assertOracle(f,raw);assert.equal(parseAuthorityHumanClosure(raw,JSON.stringify(f.registry)).ok,true);
});
test('SQL036 reversed own scope refuses without a partial issuance or epoch advance',async t=>{
 const f=await fixture(t);for(const scope of [resource(f),domain(f)])await refuses(f,async()=>addAlignedGrant(f,await addRole(f,[await addPolicy(f)]),{scope:tenant(f),effect:ceiling(f,scope)}));
});
test('SQL036 exact same-domain descendant direction remains asymmetric',async t=>{
 const f=await fixture(t);const g=await root(f,{scope:domain(f,false),effect:ceiling(f,domain(f,true))});await validateBoth(f,[g.ref.id]);await refuses(f,async()=>addAlignedGrant(f,await addRole(f,[await addPolicy(f)]),{scope:domain(f,true),effect:ceiling(f,domain(f,false))}));
});
test('SQL036 onward scope must fit the grant even when it fits the wider effect ceiling',async t=>{
 const f=await fixture(t),scope=resource(f);const g=await root(f,{scope,effect:ceiling(f),delegable:onward(f,scope)});await validateBoth(f,[g.ref.id]);await refuses(f,async()=>addAlignedGrant(f,await addRole(f,[await addPolicy(f)]),{scope,effect:ceiling(f),delegable:onward(f)}));
});
test('SQL036 child effect cannot exceed parent onward scope despite a narrow child grant',async t=>{
 const f=await fixture(t),issuer=await addPerson(f),scope=resource(f);await refuses(f,async()=>{const role=await addRole(f,[await addPolicy(f)]),p=await addAlignedGrant(f,role,{beneficiary:{kind:'human',id:issuer},delegable:onward(f,scope)});await addAlignedGrant(f,role,{kind:'delegation',issuer,parent:p,scope,effect:ceiling(f)});});
});
test('SQL036 child effect cannot exceed parent effect scope despite a narrow child grant',async t=>{
 const f=await fixture(t),issuer=await addPerson(f),scope=resource(f);await refuses(f,async()=>{const role=await addRole(f,[await addPolicy(f)]),p=await addAlignedGrant(f,role,{beneficiary:{kind:'human',id:issuer},scope,effect:ceiling(f,scope),delegable:onward(f,scope)});await addAlignedGrant(f,role,{kind:'delegation',issuer,parent:p,scope,effect:ceiling(f)});});
});
test('SQL036 valid narrowed connected effect and onward scopes are preserved',async t=>{
 const f=await fixture(t),scope=resource(f),{p,c}=await pair(f,{scope,effect:ceiling(f),delegable:onward(f,scope)},{scope,effect:ceiling(f,scope)});await validateBoth(f,[p.ref.id,c.ref.id]);const raw=await rawLoad(f);assertOracle(f,raw);assert.equal(parseAuthorityHumanClosure(raw,JSON.stringify(f.registry)).ok,true);
});
test('SQL036 child grant lifetime must fit parent effect lifetime independently of its own narrow effect',async t=>{
 const f=await fixture(t),issuer=await addPerson(f),wide=interval(f,-60000,600000),narrow=interval(f,-30000,300000);await refuses(f,async()=>{const role=await addRole(f,[await addPolicy(f)]),p=await addAlignedGrant(f,role,{beneficiary:{kind:'human',id:issuer},validity:wide,effect:ceiling(f,tenant(f),narrow),delegable:onward(f,tenant(f),narrow)});await addAlignedGrant(f,role,{kind:'delegation',issuer,parent:p,validity:wide,effect:ceiling(f,tenant(f),narrow)});});
});
test('SQL036 child grant lifetime must fit parent onward lifetime when parent effect is wider',async t=>{
 const f=await fixture(t),issuer=await addPerson(f),wide=interval(f,-60000,600000),narrow=interval(f,-30000,300000);await refuses(f,async()=>{const role=await addRole(f,[await addPolicy(f)]),p=await addAlignedGrant(f,role,{beneficiary:{kind:'human',id:issuer},validity:wide,delegable:onward(f,tenant(f),narrow)});await addAlignedGrant(f,role,{kind:'delegation',issuer,parent:p,validity:wide,effect:ceiling(f,tenant(f),narrow)});});
});
test('SQL036 equal finite child boundaries pass and null endpoints cannot widen them',async t=>{
 const f=await fixture(t),finite=interval(f,-30000,300000),{p,c}=await pair(f,{validity:finite,delegable:onward(f,tenant(f),finite)},{validity:finite});await validateBoth(f,[c.ref.id,p.ref.id]);for(const validity of [{...finite,notBefore:null},{...finite,expiresAt:null},forever])await refuses(f,async()=>{if(p.kind!=='ordinary-role')throw Error('fixture');await addAlignedGrant(f,p.role,{kind:'delegation',issuer:p.beneficiary.id,parent:p,validity,effect:ceiling(f,tenant(f),finite)});});
});
test('SQL036 canonical own effect lifetime remains within the own grant lifetime',async t=>{
 const f=await fixture(t),finite=interval(f,-30000,300000);await refuses(f,async()=>addAlignedGrant(f,await addRole(f,[await addPolicy(f)]),{validity:finite,effect:ceiling(f,tenant(f),forever)}));
});
test('SQL036 onward lifetime cannot widen the finite effect or own grant interval',async t=>{
 const f=await fixture(t),finite=interval(f,-30000,300000);await refuses(f,async()=>addAlignedGrant(f,await addRole(f,[await addPolicy(f)]),{validity:finite,delegable:onward(f,tenant(f),forever)}));
});
test('SQL036 old four-edge sealed chain still validates in complete readonly closure',async t=>{
 const f=await fixture(t);await fourEdge(f);const raw=await rawLoad(f);assertOracle(f,raw);await validateBoth(f,raw.grants.map(g=>g.ref.id));assert.equal(parseAuthorityHumanClosure(raw,JSON.stringify(f.registry)).ok,true);
});
test('SQL036 corrected grants validate in multiple exact-registry input and invocation orders',async t=>{
 const f=await fixture(t),grants:Array<Awaited<ReturnType<typeof root>>>=[];for(const scope of [tenant(f),resource(f),domain(f)])grants.push(await root(f,{scope,effect:ceiling(f)}));for(const ids of [grants.map(g=>g.ref.id),grants.map(g=>g.ref.id).reverse(),[grants[1]!.ref.id,grants[2]!.ref.id,grants[0]!.ref.id]])await validateBoth(f,ids);
 // Multiple invocations exercise the preserved callable path; cache parse-count
 // isolation remains a separate historical031 instrumented qualification.
 await readonly(f,async()=>{for(let n=0;n<2;n++)await query(f.owner,'SELECT gc_authority.validate_read_grants_v1($1,$2::uuid[])',[f.tenant,grants.map(g=>g.ref.id)]);});
});
test('SQL036 batch validator keeps native-owner and readonly snapshot guards',async t=>{
 const f=await fixture(t),g=await root(f,{});for(const client of [f.api,f.login,f.legacy])await assert.rejects(tx(client,()=>query(client,'SELECT gc_authority.validate_read_grants_v1($1,$2::uuid[])',[f.tenant,[g.ref.id]]),'REPEATABLE READ READ ONLY'),rejected('42501'));await assert.rejects(query(f.owner,'SELECT gc_authority.validate_read_grants_v1($1,$2::uuid[])',[f.tenant,[g.ref.id]]),rejected('42501'));await validateBoth(f,[g.ref.id]);
});
test('SQL036 retained incompatible revoked history refuses for both validators and every cache order without changing rows',async t=>{
 const f=await fixture(t),config=(await import('../fixtures/authority-authn-foundation.ts')).config as unknown as {authorityScopeLegacyFixtures:unknown};
 const markers=config.authorityScopeLegacyFixtures;assert.ok(Array.isArray(markers)&&markers.length>0,'Harness must supply the private source-bound SQL035 legacy marker');const before=await (await import('../fixtures/authority-scope-legacy.ts')).allCanonicalState(f);
 for(const marker of markers){assert.deepEqual(Object.keys(marker).sort(),['formatVersion','profile','tenantId','grants'].sort());assert.equal(marker.formatVersion,1);assert.equal(marker.profile,'scope-alignment-sql035-legacy');assert.match(marker.tenantId,/^[0-9a-f-]{36}$/);assert.ok(Array.isArray(marker.grants)&&marker.grants.length===9);assert.equal(new Set(marker.grants.map((g:{id:string})=>g.id)).size,9);assert.deepEqual([...new Set(marker.grants.map((g:{kind:string})=>g.kind))].sort(),[...(await import('../fixtures/authority-scope-legacy.ts')).legacyKinds].sort());
  const singles=async(ids:string[],batch:boolean)=>tx(f.owner,async()=>{await query(f.owner,"SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id','',true)",[marker.tenantId]);if(batch)await query(f.owner,'SELECT gc_authority.validate_read_grants_v1($1,$2::uuid[])',[marker.tenantId,ids]);else for(const id of ids)await query(f.owner,'SELECT gc_authority.validate_grant($1,$2,true)',[marker.tenantId,id]);},'REPEATABLE READ READ ONLY');
  for(const record of marker.grants){assert.deepEqual(Object.keys(record).sort(),['id','kind','mustRefuse','headSha256'].sort());assert.equal(typeof record.mustRefuse,'boolean');assert.match(record.headSha256,/^[0-9a-f]{64}$/);const row=await scalar(f.admin,"SELECT state,encode(sha256(convert_to(to_jsonb(h)::text,'UTF8')),'hex') digest FROM gc_authority.grant_heads h WHERE tenant_id=$1 AND id=$2",[marker.tenantId,record.id]);assert.equal(row.state,'revoked');assert.equal(row.digest,record.headSha256);for(const batch of [false,true])if(record.mustRefuse)await assert.rejects(singles([record.id],batch),rejected('23514'));else await singles([record.id],batch);}
  const good=marker.grants.find((g:{mustRefuse:boolean})=>!g.mustRefuse),bad=marker.grants.find((g:{mustRefuse:boolean})=>g.mustRefuse);assert.ok(good&&bad);for(const ids of [[good.id,bad.id],[bad.id,good.id]])await assert.rejects(singles(ids,true),rejected('23514'));
 }
 assert.deepEqual(await (await import('../fixtures/authority-scope-legacy.ts')).allCanonicalState(f),before);
});
