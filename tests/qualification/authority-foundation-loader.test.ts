// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture,query,scalar,tx,rejected,uuid,uid,load,rawLoad,selectors,readerGraph,mutate,addPolicy,addRole,addGrant,addGroup,addMembership,addPerson,addResponsibilityType,addElevationUse,revoke,fourEdge,assertOracle,expectedCandidates,syntheticAssembly,forever,version,publishRole,retireDefinition,issuerDepthGraph} from '../fixtures/authority-foundation.ts';
import {session} from '../fixtures/authority-authn-foundation.ts';
import {parseAuthorityHumanClosure} from '../../packages/authority-storage/src/loader.ts';
import {evaluateAuthority} from '../../packages/authority/src/decisions.ts';
import type {UUID,UTC,PolicyPin} from '../../packages/authority/src/types.ts';
import type {AuthorityGrant} from '../../packages/authority/src/decision-types.ts';

const decision=(f:Awaited<ReturnType<typeof fixture>>,c:Awaited<ReturnType<typeof load>>)=>{const assembled=syntheticAssembly(f,c);const result=evaluateAuthority(assembled.bundle,assembled.registry);assert.equal(result.outcome,'evaluated',result.issues.map(i=>i.code+':'+i.path).join(';'));assert.ok(result.root&&result.root.mode==='authorize');return result.root;};

test('empty exact owner closure authenticates privately without inventing grants or content authority',async t=>{
 const f=await fixture(t),c=await load(f);assertOracle(f,c);assert.equal(c.kind,'inactive-human-candidate-closure');assert.equal(c.contentAuthority,false);
 assert.equal(c.partitions.length,1);assert.equal(c.principals.length,1);const groups=c.principalGroups[0]!.memberships;assert.equal(groups.status,'known');if(groups.status!=='known')throw Error('Expected complete empty group proof');assert.deepEqual(groups.value,[]);assert.deepEqual(c.grants,[]);
 assert.ok(!('allowed'in c)&&!('permissions'in c)&&!('sessionHash'in c.session));
});

test('equal role pins through distinct grants are preserved and synthetic complete assembly allows',async t=>{
 const f=await fixture(t);await mutate(f,async()=>{const role=await addRole(f,[await addPolicy(f)]);await addGrant(f,role);await addGrant(f,role);});const c=await load(f);assertOracle(f,c);
 assert.equal(c.grants.length,2);assert.equal(c.definitions.length,1);assert.equal(c.policies.length,1);assert.equal(decision(f,c).allowed,true);
});

test('complete direct groups include unrelated and future memberships; group grant activates only at its time',async t=>{
 const f=await fixture(t);const future=new Date(Date.parse(f.now)+60000).toISOString() as UTC;await mutate(f,async()=>{const role=await addRole(f,[await addPolicy(f)]),current=await addGroup(f),later=await addGroup(f),unrelated=await addGroup(f);await addMembership(f,current);await addMembership(f,later,undefined,{notBefore:future,expiresAt:null});await addMembership(f,unrelated);await addGrant(f,role,{beneficiary:{kind:'group',id:later}});});
 const c=await load(f);assertOracle(f,c);assert.equal(c.groups.length,3);assert.equal(c.memberships.length,3);assert.equal(c.grants.length,1);assert.equal(decision(f,c).allowed,false);
});

test('conservative selection retains disjoint scopes and future grants without using policy conditions',async t=>{
 const f=await fixture(t);await mutate(f,async()=>{const role=await addRole(f,[await addPolicy(f,{effect:'deny'})]);await addGrant(f,role,{scope:{kind:'resource',resource:{tenantId:f.tenant as UUID,kind:'asset',id:uid()}},validity:{notBefore:new Date(Date.parse(f.now)+60000).toISOString() as UTC,expiresAt:null}});});
 const c=await load(f);assertOracle(f,c);assert.equal(c.grants.length,1);assert.equal(c.policies.length,1);assert.equal(decision(f,c).allowed,false);
});

test('null responsibility remains documentation only; mapped responsibility carries its exact pinned role',async t=>{
 const f=await fixture(t);await mutate(f,async()=>{const role=await addRole(f,[await addPolicy(f)]),mapped=await addResponsibilityType(f,role),documentation=await addResponsibilityType(f,null);await addGrant(f,role,{kind:'responsibility',responsibility:{typeId:mapped,mappedRole:role}});await addGrant(f,role,{kind:'responsibility',responsibility:{typeId:documentation,mappedRole:null}});});
 const c=await load(f);assertOracle(f,c);assert.equal(c.grants.length,2);const records=c.grants.filter((g):g is Extract<AuthorityGrant,{kind:'responsibility'}>=>g.kind==='responsibility');assert.equal(records.filter(g=>g.mappedRole===null&&g.effectiveGrantId===null).length,1);assert.equal(decision(f,c).allowed,true);
});

test('complete four-edge delegation graph retains every issuer partition and all immutable parent pins',async t=>{
 const f=await fixture(t),chain=await fourEdge(f),c=await load(f);assertOracle(f,c);assert.equal(c.grants.length,5);assert.equal(c.parents.length,4);assert.equal(c.partitions.length,5);assert.ok(c.grants.some(g=>g.ref.id===chain.terminal.ref.id));assert.equal(decision(f,c).allowed,true);
});

test('revoked issuance-one parent remains exact required history and makes live child ineffective',async t=>{
 const f=await fixture(t),chain=await fourEdge(f);const old=await scalar(f.owner,'SELECT to_jsonb(g)-\'head_version\'-\'state\'-\'changed_at\' body FROM gc_authority.grant_heads g WHERE tenant_id=$1 AND id=$2',[f.tenant,chain.origin.ref.id]);
 await mutate(f,()=>revoke(f,'grant',chain.origin.ref.id));const c=await load(f);assertOracle(f,c);const parent=c.grants.find(g=>g.ref.id===chain.origin.ref.id)!;assert.equal(parent.ref.version,1);assert.equal(parent.state,'revoked');assert.equal(c.lifecycleHeads.find(h=>h.id===parent.ref.id)!.headVersion,2);assert.equal(decision(f,c).allowed,false);
 assert.deepEqual((await scalar(f.owner,'SELECT to_jsonb(g)-\'head_version\'-\'state\'-\'changed_at\' body FROM gc_authority.grant_heads g WHERE tenant_id=$1 AND id=$2',[f.tenant,chain.origin.ref.id])).body,old.body);
});

test('revoked via-group membership remains in the complete issuer PrincipalGroups proof',async t=>{
 const f=await fixture(t),issuer=await addPerson(f);let membership=uid();await mutate(f,async()=>{const role=await addRole(f,[await addPolicy(f)]),group=await addGroup(f);membership=await addMembership(f,group,issuer);const parent=await addGrant(f,role,{beneficiary:{kind:'group',id:group},delegable:{actions:['asset:metadata.read'],fields:null,scope:{kind:'tenant',tenantId:f.tenant as UUID},validity:forever,remainingDepth:4}});await addGrant(f,role,{kind:'delegation',issuer,parent,via:membership});});
 await mutate(f,()=>revoke(f,'group-membership',membership));const c=await load(f);assertOracle(f,c);const refs=c.principalGroups.find(p=>p.subject.id===issuer)!.memberships;assert.equal(refs.status,'known');if(refs.status!=='known')throw Error('Required complete proof');assert.ok(refs.value.some(r=>r.id===membership));assert.equal(c.memberships.find(m=>m.ref.id===membership)!.state,'revoked');assert.equal(decision(f,c).allowed,false);
});

test('ordinary issuer activity is attribution and does not create an extra live issuer partition',async t=>{
 const f=await fixture(t),issuer=await addPerson(f);await readerGraph(f,{issuer});await query(f.owner,'UPDATE public.identities SET active=false WHERE id=$1',[issuer]);const c=await load(f);assertOracle(f,c);assert.equal(c.partitions.length,1);assert.equal(c.principals.find(p=>p.id===issuer)?.active,false);const assembled=syntheticAssembly(f,c);assert.equal(assembled.bundle.principals.some(p=>p.id===issuer),false);assert.deepEqual(assembled.bundle.grants.map(g=>g.issuer.kind+':'+g.issuer.id),c.grants.map(g=>g.issuer.kind+':'+g.issuer.id));assert.equal(decision(f,c).allowed,true);
});

test('role publication does not repin existing grants; retirement-only head keeps publication version',async t=>{
 const f=await fixture(t),grant=await readerGraph(f);assert.equal(grant.kind,'ordinary-role');if(grant.kind!=='ordinary-role')throw Error('Exact role required');
 await mutate(f,async()=>publishRole(f,grant.role.roleId,[await addPolicy(f,{effect:'deny'})]));const c=await load(f);const role=c.definitions.find(d=>d.id===grant.role.roleId)!;assert.equal(role.version,1);assert.equal(role.currentHeadVersion,2);assert.equal(c.policies.length,1);assert.equal(decision(f,c).allowed,true);
 let unbound=uid();await mutate(f,async()=>{unbound=(await addRole(f,[await addPolicy(f)])).roleId;});await mutate(f,()=>retireDefinition(f,unbound));
 const p=(await scalar(f.owner,"SELECT gc_authority.projection_v1($1,'definition',$2,1,2,NULL,'dto') value",[f.tenant,unbound])).value;assert.equal(p.version,1);assert.equal(p.currentHeadVersion,1);assert.equal(p.state,'retired');
});

test('elevation current and earliest future selection is exact-session and independently charged',async t=>{
 const f=await fixture(t),issuer=await addPerson(f),other=await session(f);let elevation:Awaited<ReturnType<typeof readerGraph>>=null as never;
 const at=(ms:number)=>new Date(Date.parse(f.now)+ms).toISOString() as UTC;
 await mutate(f,async()=>{const role=await addRole(f,[await addPolicy(f)]),parent=await addGrant(f,role,{issuer,beneficiary:{kind:'human',id:issuer},delegable:{actions:['asset:metadata.read'],fields:null,scope:{kind:'tenant',tenantId:f.tenant as UUID},validity:forever,remainingDepth:4}});elevation=await addGrant(f,role,{kind:'elevation',issuer,parent,validity:{notBefore:null,expiresAt:at(300000)}});});
 let current=uid(),later=uid(),earlier=uid(),second=uid();await mutate(f,async()=>{later=await addElevationUse(f,elevation,{notBefore:at(120000),expiresAt:at(180000)});earlier=await addElevationUse(f,elevation,{notBefore:at(60000),expiresAt:at(120000)});current=await addElevationUse(f,elevation,{notBefore:f.now,expiresAt:at(60000)});second=await addElevationUse(f,elevation,{notBefore:f.now,expiresAt:at(180000)},other.row);},f.owner,[f.protectedSession.session_id,other.row.session_id]);
 const first=await load(f),g=first.grants.find(g=>g.kind==='elevation');assert.equal(g?.kind,'elevation');if(g?.kind!=='elevation')throw Error('Expected elevation');assert.equal(g.use?.id,current);assertOracle(f,first);assert.equal(decision(f,first).allowed,true);assert.ok(first.elevationUses.some(u=>u.ref.id===later));
 await mutate(f,()=>revoke(f,'elevation-use',current),f.owner,[f.protectedSession.session_id]);const future=await load(f),next=future.grants.find(g=>g.kind==='elevation');assert.equal(next?.kind==='elevation'?next.use?.id:null,earlier);assertOracle(f,future);assert.equal(decision(f,future).allowed,false);
 const original=f.hash;f.hash=other.hash;try{const otherClosure=await load(f),otherGrant=otherClosure.grants.find(g=>g.kind==='elevation');assert.equal(otherGrant?.kind==='elevation'?otherGrant.use?.id:null,second);assert.notEqual(otherClosure.snapshot.closureDigest,future.snapshot.closureDigest);}finally{f.hash=original;}
 const forms=(await query(f.owner,'SELECT projection_form FROM gc_authority.projection_measures WHERE tenant_id=$1 AND object_id=$2',[f.tenant,second])).rows.map(r=>r.projection_form).sort();assert.deepEqual(forms,['dto','elevation-use-embedded']);
});

test('unknown selector keys, duplicates, cross-tenant roots and malformed graph outputs fail closed',async t=>{
 const f=await fixture(t);await readerGraph(f);const raw=JSON.stringify(selectors(f));assert.equal(raw[0],'{');
 for(const text of ['{"formatVersion":1,'+raw.slice(1),JSON.stringify({...selectors(f),actor:uid()}),JSON.stringify({formatVersion:1,requests:[{...f.request,resource:{...f.request.resource,tenantId:f.otherTenant}}]})])await assert.rejects(rawLoad(f,f.owner,text),rejected('22023','28000'));
 const c=await load(f);for(const bad of [{...c,contentAuthority:true},{...c,grants:[]},{...c,unexpected:true},{...c,session:{...c.session,identityId:uid()}}])assert.equal(parseAuthorityHumanClosure(bad,f.registry).ok,false);
});

test('128 complete root partitions are accepted and the 129th is refused without first-N output',async t=>{
 const f=await fixture(t),requests=Array.from({length:128},()=>({...f.request,resource:{...f.request.resource,id:uid()}})).sort((a,b)=>a.resource.id.localeCompare(b.resource.id));
 const c=await rawLoad(f,f.owner,JSON.stringify({formatVersion:1,requests}));assert.equal(c.partitions.length,128);assert.equal(c.metrics.partitions,128);
 requests.push({...f.request,resource:{...f.request.resource,id:uid()}});await assert.rejects(rawLoad(f,f.owner,JSON.stringify({formatVersion:1,requests})),rejected('54000'));
});

test('32 complete policy pins fit and the 33rd policy refuses the whole closure',async t=>{
 const f=await fixture(t),pins:PolicyPin[]=[];await mutate(f,async()=>{for(let i=0;i<32;i++)pins.push(await addPolicy(f,{document:{formatVersion:1,id:uid(),version,rules:Array.from({length:128},()=>({id:uid(),effect:'allow' as const,actions:['asset:metadata.read' as const],fields:null,when:{op:'action-in' as const,actions:['asset:metadata.read' as const]}}))}}));await addGrant(f,await addRole(f,pins));});
 const c=await load(f);assert.equal(c.policies.length,32);assert.equal(c.metrics.policies,32);assert.equal(c.metrics.policyRules,4096);assert.equal(c.metrics.expressionNodes,4096);
 await mutate(f,async()=>{await addGrant(f,await addRole(f,[await addPolicy(f)]));});await assert.rejects(rawLoad(f),rejected('54000'));
});

test('complete direct group union accepts1024 and refuses1025 without a tenant-population cap',async t=>{
 const f=await fixture(t);for(let batch=0;batch<32;batch++)await mutate(f,async()=>{for(let n=0;n<32;n++)await addMembership(f,await addGroup(f));});
 const c=await load(f);assert.equal(c.groups.length,1024);assert.equal(c.memberships.length,1024);assert.equal(c.metrics.directGroupsMaximum,1024);
 await mutate(f,async()=>{await addMembership(f,await addGroup(f));});await assert.rejects(rawLoad(f),rejected('54000'));
});

test('readonly graph loading adds no authority, audit, outbox, session or idempotency rows',async t=>{
 const f=await fixture(t);await readerGraph(f);const count=()=>scalar(f.owner,`SELECT (SELECT count(*)::text FROM gc_authority.write_bindings) writes,(SELECT count(*)::text FROM gc_authn.session_events) session_events,(SELECT count(*)::text FROM public.audit) audit,(SELECT count(*)::text FROM public.outbox) outbox,(SELECT count(*)::text FROM public.idempotency) idempotency`);
 const before=await count();await load(f);await rawLoad(f);assert.deepEqual(await count(),before);
});


test('resource-wide deny intent and action-disjoint roots retain exact complete registry expansion',async t=>{
 const f=await fixture(t),grantIds:string[]=[];
 const expanded=f.registry.actions.filter(a=>a.family==='human'&&a.resourceKinds.includes('asset')).map(a=>a.action).sort();
 await mutate(f,async()=>{
  const allow=await addRole(f,[await addPolicy(f)]);grantIds.push((await addGrant(f,allow)).ref.id);
  const disjoint=await addRole(f,[await addPolicy(f,{effect:'deny',action:'asset:description.edit'})]);grantIds.push((await addGrant(f,disjoint,{actions:['asset:description.edit']})).ref.id);
  const wide=await addRole(f,[await addPolicy(f,{effect:'deny',resourceWide:true})]);
  // The synthetic registry also admits ADMIN actions on assets. Preserve their
  // required explicit control companion rather than narrowing the deny intent.
  grantIds.push((await addGrant(f,wide,{actions:expanded,control:{actions:expanded,resourceKinds:['asset'],scope:{kind:'tenant',tenantId:f.tenant},fields:null,validity:forever,allowSelfBenefit:false}})).ref.id);
 });
 const c=await load(f);assertOracle(f,c);assert.deepEqual(c.grants.map(g=>g.ref.id).sort(),[grantIds[0]!,grantIds[2]!].sort());
 const disjoint=f.model.grants.find(g=>g.ref.id===grantIds[1]);assert.ok(disjoint);assert.deepEqual(disjoint.ceiling.actions,['asset:description.edit']);assert.ok(!disjoint.ceiling.actions.includes(f.request.action));assert.ok(!c.grants.some(g=>g.ref.id===disjoint.ref.id));
 const intent=c.policies.flatMap(p=>p.resourceWideIntents);assert.equal(intent.length,1);assert.deepEqual([...intent[0]!.expandedActions],expanded);assert.ok(intent[0]!.expandedActions.includes('asset:metadata.read'));assert.equal(decision(f,c).allowed,false);
 // One complete load, with two roots in the same snapshot, retains the union.
 // This is candidate selection evidence, not composition of authorization calls.
 const combinedRaw=await rawLoad(f,f.owner,JSON.stringify({formatVersion:1,requests:[f.request,{...f.request,action:'asset:description.edit'}]}));
 const combined=parseAuthorityHumanClosure(combinedRaw,JSON.stringify(f.registry));assert.equal(combined.ok,true);if(!combined.ok)throw Error('Complete two-root closure must parse');
 assertOracle(f,combined.value);assert.equal(combined.value.partitions.length,2);assert.deepEqual(combined.value.grants.map(g=>g.ref.id).sort(),[...grantIds].sort());
});

test('issuer dependency depth16 fits and17 refuses despite every individual lineage having one edge',async t=>{
 const exact=await fixture(t);await issuerDepthGraph(exact,16);const c=await load(exact);assertOracle(exact,c);assert.equal(c.metrics.dependencyDepth,16);assert.equal(c.partitions.length,16);
 const over=await fixture(t);await issuerDepthGraph(over,17);await assert.rejects(rawLoad(over),rejected('54000'));
});

test('512 distinct ordinary origins fit and513 refuse the entire closure before materialized return',async t=>{
 const f=await fixture(t);let role:Awaited<ReturnType<typeof addRole>>;await mutate(f,async()=>{role=await addRole(f,[await addPolicy(f)]);});
 for(let batch=0;batch<16;batch++)await mutate(f,async()=>{for(let i=0;i<32;i++)await addGrant(f,role);});
 const c=await load(f);assertOracle(f,c);assert.equal(c.grants.length,512);assert.equal(c.metrics.ordinaryOrigins,512);
 await mutate(f,async()=>{await addGrant(f,role);});await assert.rejects(rawLoad(f),rejected('54000'));
});

test('unknown purpose facts produce a real interpreter indeterminate denial without dropping a policy',async t=>{
 const f=await fixture(t),id=uid();await mutate(f,async()=>{const policy=await addPolicy(f,{document:{formatVersion:1,id,version,rules:[{id:uid(),effect:'allow',actions:['asset:metadata.read'],fields:null,when:{op:'purpose-in',ids:[uid()]}}]}});await addGrant(f,await addRole(f,[policy]));});
 const c=await load(f);assertOracle(f,c);const result=decision(f,c);assert.equal(result.allowed,false);assert.equal(result.reason,'indeterminate');
});


test('valid large aggregate refuses before projection materialization; isolated sentinel is restored exactly',async t=>{
 const control=await fixture(t);await readerGraph(control);const f=await fixture(t),pins:PolicyPin[]=[];
 await mutate(f,async()=>{for(let i=0;i<32;i++){const id=uid(),document={formatVersion:1 as const,id,version,rules:[{id:uid(),effect:'allow' as const,actions:['asset:metadata.read' as const],fields:null,when:{op:'action-in' as const,actions:['asset:metadata.read' as const]}}]},base=JSON.stringify(document);pins.push(await addPolicy(f,{id,document,raw:base+'\t'.repeat(65536-Buffer.byteLength(base))}));}});
 for(let batch=0;batch<16;batch++)await mutate(f,async()=>{for(let i=0;i<32;i++)await addGrant(f,await addRole(f,[pins[(batch*32+i)%32]!],'d'.repeat(4000)));});
 const sum=await scalar(f.owner,'SELECT sum(canonical_bytes+raw_bytes)::text n FROM gc_authority.projection_measures WHERE tenant_id=$1',[f.tenant]);assert.ok(BigInt(sum.n)>8388608n,'Valid selected measure aggregate must independently exceed the physical cap');
 const signature='gc_authority.projection_v1(uuid,text,uuid,integer,integer,uuid,text)';
 const inventory=()=>scalar(f.owner,"SELECT pg_get_functiondef(p.oid) definition,encode(sha256(convert_to(pg_get_functiondef(p.oid),'UTF8')),'hex') hash,p.proowner::text owner,p.proacl::text acl,p.prosecdef,p.provolatile,p.proisstrict,p.proleakproof,p.proparallel,p.proconfig FROM pg_proc p WHERE p.oid=$1::regprocedure",[signature]);
 const before=await inventory();
 // Approved test-only instrumentation in the disposable DB. A fresh native-owner
 // readonly transaction must see the committed sentinel; no trigger/data bypass.
 try{await query(f.owner,"CREATE OR REPLACE FUNCTION gc_authority.projection_v1(p_tenant uuid,p_family text,p_id uuid,p_version integer,p_head integer,p_sub uuid,p_form text) RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path=pg_catalog,gc_authority,pg_temp SET row_security=on AS $sentinel$ BEGIN RAISE EXCEPTION 'QUALIFICATION_PROJECTION_REACHED' USING ERRCODE='ZX001'; END $sentinel$");
  await assert.rejects(rawLoad(control),rejected('ZX001'));
  await assert.rejects(rawLoad(f),rejected('54000'));
 }finally{await query(f.owner,before.definition);assert.deepEqual(await inventory(),before,'Exact private function definition/owner/ACL/config restoration');}
 assert.equal((await load(control)).grants.length,1);await assert.rejects(rawLoad(f),rejected('54000'));
});
