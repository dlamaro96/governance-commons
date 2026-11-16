// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {fixture,query,scalar,tx,extra,rejected,uuid,digest,load,rawLoad,selectors,foundationInstall,epoch,startWrite,mutate,readerGraph,revoke,uid,addGroup,addMembership,addPolicy,addRole,addGrant,complete,jsonMeasure,retireDefinition} from '../fixtures/authority-foundation.ts';
import {decisionHash,canonicalDecisionJSON} from '../../packages/authority/src/decision-schema.ts';
import {parsePolicyFile} from '../../packages/authority/src/policy.ts';
import {admitAuthorityInput} from '../../packages/authority/src/admission.ts';

test('new private storage, functions and types have no runtime capability; tenant tables force RLS',async t=>{
 const f=await fixture(t),roles=[f.roles.login.name,f.roles.api.name,'gc_app'];
 for(const role of roles){
  assert.equal((await scalar(f.owner,"SELECT has_schema_privilege($1,'gc_authority','USAGE') allowed",[role])).allowed,false);
  assert.equal((await scalar(f.owner,"SELECT count(*)::int n FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='gc_authority' AND CASE WHEN c.relkind='S' THEN has_sequence_privilege($1,c.oid,'USAGE,SELECT,UPDATE') ELSE false END",[role])).n,0);
  const rows=(await query(f.owner,`SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='gc_authority' AND CASE WHEN c.relkind='r' THEN (has_table_privilege($1,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege($1,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')) ELSE false END`,[role])).rows;assert.deepEqual(rows,[]);
  assert.equal((await scalar(f.owner,"SELECT count(*)::int n FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='gc_authority' AND has_function_privilege($1,p.oid,'EXECUTE')",[role])).n,0);
  assert.equal((await scalar(f.owner,"SELECT count(*)::int n FROM pg_type p JOIN pg_namespace n ON n.oid=p.typnamespace WHERE n.nspname='gc_authority' AND has_type_privilege($1,p.oid,'USAGE')",[role])).n,0);
 }
 const tenantTables=(await query(f.owner,"SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='gc_authority' AND c.relkind='r' AND EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attname='tenant_id' AND NOT a.attisdropped)")).rows;
 assert.ok(tenantTables.length>=15);assert.ok(tenantTables.every(r=>r.relrowsecurity&&r.relforcerowsecurity));
 const owner=await scalar(f.owner,"SELECT rolsuper,rolcreatedb,rolcreaterole,rolbypassrls,rolreplication FROM pg_roles WHERE rolname=session_user");assert.ok(Object.values(owner).every(x=>x===false));
 await assert.rejects(query(f.api,'SELECT * FROM gc_authority.grant_heads'),rejected('42501'));
 const allowed=(await query(f.owner,"SELECT proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND proname LIKE 'gc_authn_%' AND has_function_privilege($1,p.oid,'EXECUTE') ORDER BY proname",[f.roles.api.name])).rows.map(r=>r.proname);
 assert.deepEqual(allowed,['gc_authn_session_inspect','gc_authn_session_revoke','gc_authn_session_select']);
});

test('owner-only session bridge requires original native owner and fresh readonly repeatable read',async t=>{
 const f=await fixture(t);const bridge=await tx(f.owner,()=>scalar(f.owner,'SELECT * FROM gc_authn.foundation_session_v1($1)',[f.hash]),'REPEATABLE READ READ ONLY');
 assert.equal(bridge.identity_id,f.identity);assert.equal(bridge.session_id,f.protectedSession.session_id);
 for(const client of [f.login,f.api,f.legacy])await assert.rejects(tx(client,()=>query(client,'SELECT * FROM gc_authn.foundation_session_v1($1)',[f.hash]),'REPEATABLE READ READ ONLY'),rejected('42501'));
 await assert.rejects(query(f.owner,'SELECT * FROM gc_authn.foundation_session_v1($1)',[f.hash]),rejected('28000'));
 await query(f.admin,'SET ROLE gc_owner');try{await assert.rejects(tx(f.admin,()=>query(f.admin,'SELECT * FROM gc_authn.foundation_session_v1($1)',[f.hash]),'REPEATABLE READ READ ONLY'),rejected('42501'));}finally{await query(f.admin,'RESET ROLE');}
});

test('forged hash, public legacy session and caller GUCs cannot replace protected provenance',async t=>{
 const f=await fixture(t),forged=digest();await query(f.owner,'INSERT INTO public.sessions(id_hash,identity_id,tenant_id,csrf,expires_at) VALUES($1,$2,$3,$4,clock_timestamp()+interval \'1 hour\')',[forged,f.identity,f.tenant,digest()]);
 await assert.rejects(tx(f.owner,async()=>{await query(f.owner,"SELECT set_config('gc.actor_id',$1,true),set_config('gc.tenant_id',$2,true)",[f.identity,f.tenant]);return query(f.owner,'SELECT * FROM gc_authn.foundation_session_v1($1)',[forged]);},'REPEATABLE READ READ ONLY'),rejected('28000'));
 assert.equal((await rawLoad(f)).session.identityId,f.identity);
});

test('installation receipt replays exact raw manifest and rejects changed request bytes',async t=>{
 const f=await fixture(t),tenant=uuid();await query(f.owner,'INSERT INTO public.tenants(id,name) VALUES($1,$2)',[tenant,'Synthetic independent replay']);
 const auth=await import('../fixtures/authority-authn-foundation.ts');await auth.install(f.owner,'initialize-tenant',[tenant,1]);
 const first=await foundationInstall(f.owner,'tenant-initialize',[tenant,'1',1,f.registryId,f.registry.version,f.registry.digest]);
 assert.deepEqual((await scalar(f.owner,first.sql,first.values)).receipt,first.receipt);
 const changed=[...first.values];changed[1]='different-release';await assert.rejects(query(f.owner,first.sql,changed),rejected('40001'));
 assert.equal((await scalar(f.owner,'SELECT count(*)::int n FROM gc_authority.installation_receipts WHERE request_id=$1',[first.values[0]])).n,1);
});

test('duplicate JSON, unknown fields and mismatched canonical registry digests refuse before installation',async t=>{
 const f=await fixture(t),raw=JSON.stringify(f.registry);assert.equal(raw[0],'{');
 for(const document of ['{"formatVersion":1,'+raw.slice(1),JSON.stringify({...f.registry,unexpected:true})])await assert.rejects(foundationInstall(f.owner,'registry-install',[uuid(),f.registry.version,document,f.registry.digest]),rejected('22023'));
 await assert.rejects(foundationInstall(f.owner,'registry-install',[uuid(),f.registry.version,raw,digest()]),rejected('22023','23514'));
});

test('canonical Unicode ordering, integer normalization and hashes agree across real SQL and TypeScript',async t=>{
 const f=await fixture(t);for(const value of [{z:'é',a:'مرحبا',emoji:'😀'}, {'\u{10000}':'a','\ue000':'b'},[null,true,false,9007199254740991],{n:1,nested:[{b:2,a:1}]}]){
  const row=await scalar(f.owner,'SELECT gc_authority.canonical($1::jsonb) canonical,gc_authority.hash($1::jsonb) hash',[JSON.stringify(value)]);assert.equal(row.canonical,canonicalDecisionJSON(value));assert.equal(row.hash,decisionHash(value));
 }
 assert.equal((await scalar(f.owner,"SELECT gc_authority.canonical('1e0'::jsonb) value")).value,'1');
 await assert.rejects(query(f.owner,"SELECT gc_authority.canonical('1.5'::jsonb)"),rejected('22023'));
 const bad={formatVersion:1.5,id:uuid(),version:1,rules:[]};assert.equal(parsePolicyFile(JSON.stringify(bad),[]).ok,false);
 // Physical root depth is1, including a scalar. Both raw admission and measured
 // projection depth must enforce the same exact32 boundary as TypeScript.
 for(const depth of [1,32,33]){
  let value:unknown=null;for(let level=1;level<depth;level++)value=[value];
  const admitted=admitAuthorityInput(value),raw=JSON.stringify(value);assert.equal(admitted.ok,depth<=32);
  if(admitted.ok){
   assert.equal(admitted.value.metrics.depth,depth);assert.equal(jsonMeasure(value).depth,depth);
   const measured=await scalar(f.owner,'SELECT (gc_authority.json_measure($1::text::jsonb))[1]::int nodes,(gc_authority.json_measure($1::text::jsonb))[2]::int depth,gc_authority.parse($1::text) parsed',[raw]);
   assert.deepEqual(measured,{nodes:admitted.value.metrics.nodes,depth,parsed:value});
  }else{
   await assert.rejects(query(f.owner,'SELECT gc_authority.json_measure($1::jsonb)',[raw]),rejected('54000'));
   await assert.rejects(query(f.owner,'SELECT gc_authority.parse($1)',[raw]),rejected('54000'));
  }
 }

});

test('canonical identity and membership revisions change only with protected source semantics',async t=>{
 const f=await fixture(t),read=()=>scalar(f.owner,'SELECT i.revision::text identity_revision,m.revision member_revision,m.membership_id FROM gc_authority.identity_heads i JOIN gc_authority.tenant_member_heads m USING(identity_id) WHERE i.identity_id=$1 AND m.tenant_id=$2',[f.identity,f.tenant]);
 const before=await read();await query(f.owner,'UPDATE public.identities SET name=$2 WHERE id=$1',[f.identity,'Renamed synthetic subject']);
 await tx(f.owner,async()=>{await query(f.owner,"SELECT set_config('gc.tenant_id',$1,true)",[f.tenant]);await query(f.owner,"UPDATE public.memberships SET role='different-label',permissions='[\"catalog:read\"]' WHERE tenant_id=$1 AND identity_id=$2",[f.tenant,f.identity]);});assert.deepEqual(await read(),before);
 await query(f.owner,'UPDATE public.identities SET active=false WHERE id=$1',[f.identity]);assert.equal(BigInt((await read()).identity_revision),BigInt(before.identity_revision)+1n);
 await assert.rejects(rawLoad(f),rejected('28000'));await query(f.owner,'UPDATE public.identities SET active=true WHERE id=$1',[f.identity]);assert.equal((await rawLoad(f)).session.identityId,f.identity);
});

test('delete/reinsert an unreferenced canonical membership preserves stable tombstone identity and advances revisions',async t=>{
 // SQL012 deliberately restricts deletion of memberships referenced by session history.
 // Use a second unreferenced principal to qualify the tombstone path without weakening those FKs.
 const f=await fixture(t),person=await (await import('../fixtures/authority-foundation.ts')).addPerson(f),read=()=>scalar(f.owner,'SELECT membership_id,revision,present,active FROM gc_authority.tenant_member_heads WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,person]),before=await read();
 await tx(f.owner,async()=>{await query(f.owner,"SELECT set_config('gc.tenant_id',$1,true)",[f.tenant]);await query(f.owner,'DELETE FROM public.memberships WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,person]);});
 const gone=await read();assert.equal(gone.membership_id,before.membership_id);assert.equal(gone.revision,before.revision+1);assert.equal(gone.present,false);assert.equal((await rawLoad(f)).session.identityId,f.identity);
 await tx(f.owner,async()=>{await query(f.owner,"SELECT set_config('gc.tenant_id',$1,true)",[f.tenant]);await query(f.owner,"INSERT INTO public.memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,'synthetic','[]')",[f.tenant,person]);});
 const restored=await read();assert.equal(restored.membership_id,before.membership_id);assert.equal(restored.revision,before.revision+2);assert.equal(restored.active,true);
});

test('write guard rejects missing begin, empty commit, tenant switch and forged transaction binding',async t=>{
 const f=await fixture(t),before=await epoch(f);
 await assert.rejects(tx(f.owner,()=>addGroup(f)),rejected('23514','42501'));f.pending=[];
 await assert.rejects(tx(f.owner,()=>startWrite(f)),rejected('23514'));
 await assert.rejects(tx(f.owner,async()=>{await startWrite(f);await query(f.owner,'SELECT gc_authority.foundation_write_begin_v1($1,$2)',[f.otherTenant,'1']);}),rejected('23514','40001'));
 await assert.rejects(tx(f.owner,()=>query(f.owner,`INSERT INTO gc_authority.write_bindings(transaction_id,backend_pid,owner_role_oid,tenant_id,started_at,deadline_at,epoch_before,epoch_after) SELECT pg_current_xact_id(),pg_backend_pid()+1,session_user::regrole::oid,$1,transaction_timestamp(),transaction_timestamp()+interval '30 seconds',1,2`,[f.tenant])),rejected('23514','42501'));
 assert.equal(await epoch(f),before);assert.equal((await scalar(f.owner,'SELECT count(*)::int n FROM gc_authority.write_bindings WHERE tenant_id=$1',[f.tenant])).n,0);
});

test('missing lifecycle revision and projection measures abort all rows and epoch changes',async t=>{
 const f=await fixture(t),before=await epoch(f);await assert.rejects(tx(f.owner,async()=>{await startWrite(f);await addGroup(f);}),rejected('23514'));f.pending=[];
 assert.equal(await epoch(f),before);assert.equal((await scalar(f.owner,'SELECT count(*)::int n FROM gc_authority.definition_heads WHERE tenant_id=$1',[f.tenant])).n,0);
});

test('immutable issuance and projection rows cannot be amended or deleted',async t=>{
 const f=await fixture(t),grant=await readerGraph(f);const before=await epoch(f);
 await assert.rejects(tx(f.owner,async()=>{await startWrite(f);await query(f.owner,"UPDATE gc_authority.grant_heads SET effect_ceiling=jsonb_set(effect_ceiling,'{actions}','[\"asset:description.edit\"]') WHERE tenant_id=$1 AND id=$2",[f.tenant,grant.ref.id]);}),rejected('23514'));
 await assert.rejects(tx(f.owner,async()=>{await startWrite(f);await query(f.owner,'DELETE FROM gc_authority.projection_measures WHERE tenant_id=$1',[f.tenant]);}),rejected('23514'));
 assert.equal(await epoch(f),before);assert.equal((await load(f)).grants[0]!.ref.id,grant.ref.id);
});

test('exact group interval overlap fails while an adjacent half-open interval is retained',async t=>{
 const f=await fixture(t);const end=new Date(Date.parse(f.now)+120000).toISOString() as typeof f.now;let group=uid();
 await mutate(f,async()=>{group=await addGroup(f);await addMembership(f,group,undefined,{notBefore:null,expiresAt:end});});
 await assert.rejects(mutate(f,async()=>{await addMembership(f,group,undefined,{notBefore:null,expiresAt:end});}),rejected('23514'));
 await mutate(f,async()=>{await addMembership(f,group,undefined,{notBefore:end,expiresAt:null});});
 assert.equal((await load(f)).principalGroups[0]!.memberships.status,'known');assert.equal((await load(f)).memberships.length,2);
});

test('finite ceiling attenuation refuses widened connected action sets and ADMIN without control',async t=>{
 const f=await fixture(t),person=await (await import('../fixtures/authority-foundation.ts')).addPerson(f);let role:{roleId:ReturnType<typeof uid>;version:import('../../packages/authority/src/types.ts').Version}=null as never;let origin:Awaited<ReturnType<typeof readerGraph>>=null as never;
 await mutate(f,async()=>{role=await addRole(f,[await addPolicy(f)]) as typeof role;origin=await addGrant(f,role,{beneficiary:{kind:'human',id:person},issuer:person,delegable:{actions:['asset:metadata.read'],fields:null,scope:{kind:'tenant',tenantId:f.tenant as ReturnType<typeof uid>},validity:{notBefore:null,expiresAt:null},remainingDepth:4}});});
 await assert.rejects(mutate(f,async()=>{await addGrant(f,role,{kind:'delegation',parent:origin,issuer:person,actions:['asset:metadata.read','asset:description.edit']});}),rejected('23514'));
 await assert.rejects(mutate(f,async()=>{const adminRole=await addRole(f,[await addPolicy(f,{action:'authority:assign-role'})]);await addGrant(f,adminRole,{actions:['authority:assign-role']});}),rejected('23514'));
});

test('retirement refuses current or future reverse dependencies and never cascades assignments',async t=>{
 const f=await fixture(t),grant=await readerGraph(f,{validity:{notBefore:new Date(Date.parse(f.now)+60000).toISOString() as typeof f.now,expiresAt:null}});assert.equal(grant.kind,'ordinary-role');if(grant.kind!=='ordinary-role')throw Error('Exact ordinary fixture required');
 const before=await epoch(f);await assert.rejects(mutate(f,()=>retireDefinition(f,grant.role.roleId)),rejected('23514'));
 assert.equal(await epoch(f),before);assert.equal((await load(f)).grants.length,1);
});

test('repeated revocation refuses without a new lifecycle head or epoch',async t=>{
 const f=await fixture(t),grant=await readerGraph(f);await mutate(f,()=>revoke(f,'grant',grant.ref.id));const before=await epoch(f);
 await assert.rejects(mutate(f,()=>revoke(f,'grant',grant.ref.id)),rejected('23514'));assert.equal(await epoch(f),before);
 assert.equal((await scalar(f.owner,'SELECT head_version,issuance_version FROM gc_authority.grant_heads WHERE tenant_id=$1 AND id=$2',[f.tenant,grant.ref.id])).head_version,2);
 assert.deepEqual((await load(f)).grants,[]);
});


test('policy raw64KiB,128rules/nodes and depth8 agree at exact limits; each next value refuses',async t=>{
 const f=await fixture(t),id=uid(),leaf={op:'action-in',actions:['asset:metadata.read']},rule={id:uid(),effect:'allow',actions:['asset:metadata.read'],fields:null,when:leaf};
 const document={formatVersion:1,id,version:1,rules:[rule]},body=JSON.stringify(document),exact=body+' '.repeat(65536-Buffer.byteLength(body));
 const sql='SELECT gc_authority.policy($1,$2::jsonb) value';
 assert.equal(parsePolicyFile(exact,[]).ok,true);assert.equal((await scalar(f.owner,sql,[exact,'[]'])).value.id,id);
 assert.equal(parsePolicyFile(exact+' ',[]).ok,false);await assert.rejects(query(f.owner,sql,[exact+' ','[]']),rejected('54000'));
 const rules=Array.from({length:128},()=>({...rule,id:uid()})),full={...document,rules};assert.equal(parsePolicyFile(JSON.stringify(full),[]).ok,true);await scalar(f.owner,sql,[JSON.stringify(full),'[]']);
 const over={...document,rules:[...rules,{...rule,id:uid()}]};assert.equal(parsePolicyFile(JSON.stringify(over),[]).ok,false);await assert.rejects(query(f.owner,sql,[JSON.stringify(over),'[]']),rejected('54000'));
 const expr=(levels:number):unknown=>levels===1?leaf:{op:'all',children:[expr(levels-1)]};for(const levels of [8,9]){const text=JSON.stringify({...document,rules:[{...rule,when:expr(levels)}]});assert.equal(parsePolicyFile(text,[]).ok,levels===8);if(levels===8)await scalar(f.owner,sql,[text,'[]']);else await assert.rejects(query(f.owner,sql,[text,'[]']),rejected('54000'));}
 const nodeText=(children:number)=>JSON.stringify({...document,rules:[{...rule,when:{op:'all',children:Array.from({length:children},()=>leaf)}}]});assert.equal(parsePolicyFile(nodeText(127),[]).ok,true);await scalar(f.owner,sql,[nodeText(127),'[]']);assert.equal(parsePolicyFile(nodeText(128),[]).ok,false);await assert.rejects(query(f.owner,sql,[nodeText(128),'[]']),rejected('54000'));
 const admitted=parsePolicyFile(exact,[]);assert.ok(admitted.ok);if(!admitted.ok)throw Error('Exact fixture parser failed');await mutate(f,async()=>{await addPolicy(f,{id,document:admitted.value,raw:exact});});
 assert.equal((await scalar(f.owner,"SELECT raw_bytes FROM gc_authority.projection_measures WHERE tenant_id=$1 AND object_id=$2 AND family='policy'",[f.tenant,id])).raw_bytes,'65536');
});

test('missing origin companion, foreign tenant membership and fabricated projection measure all roll back',async t=>{
 const f=await fixture(t),before=await epoch(f);
 await assert.rejects(tx(f.owner,async()=>{await startWrite(f);const group=await addGroup(f);const pending=f.pending.pop()!;assert.equal(pending.id,group);const projected=(await scalar(f.owner,"SELECT gc_authority.projection_v1($1,'group',$2,1,1,NULL,'dto') v",[f.tenant,group])).v,m=jsonMeasure(projected);await query(f.owner,"INSERT INTO gc_authority.projection_measures(id,tenant_id,family,projection_form,object_id,definition_kind,issuance_or_definition_version,head_version,sub_id,canonical_bytes,raw_bytes,json_nodes,json_depth,projection_hash) VALUES($1,$2,'group','dto',$3,'group',1,1,NULL,$4,0,$5,$6,$7)",[uuid(),f.tenant,group,m.bytes+1,m.nodes,m.depth,m.hash]);}),rejected('23514'));f.pending=[];
 // A role origin companion is mandatory even when the human-beneficiary FK is valid.
 await assert.rejects(tx(f.owner,async()=>{await startWrite(f);await addGrant(f,await addRole(f,[await addPolicy(f)]),{omitOrigin:true});await query(f.owner,'SET CONSTRAINTS ALL IMMEDIATE');}),rejected('23514'));f.pending=[];
 await assert.rejects(tx(f.owner,async()=>{await startWrite(f);const group=await addGroup(f);await query(f.owner,"INSERT INTO gc_authority.group_memberships(tenant_id,id,issuance_version,group_id,group_kind,identity_id,not_before,expires_at,created_by,created_at,head_version,state,changed_at) VALUES($1,$2,1,$3,'group',$4,NULL,NULL,$4,$5,1,'active',$5)",[f.otherTenant,uuid(),group,f.identity,f.now]);}),rejected('23514','42501'));f.pending=[];
 assert.equal(await epoch(f),before);
});


test('future private function overload, type, table and sequence do not inherit runtime defaults',async t=>{
 const f=await fixture(t);
 for(const creator of ['gc_owner','gc_authn_definer'])for(const kind of ['f','T']){const defaults=await scalar(f.owner,"SELECT count(*)::int n FROM pg_roles r CROSS JOIN LATERAL aclexplode(coalesce((SELECT defaclacl FROM pg_default_acl d WHERE d.defaclrole=r.oid AND d.defaclnamespace=0 AND d.defaclobjtype=$2::\"char\"),acldefault($2::\"char\",r.oid))) a WHERE r.rolname=$1 AND (a.grantee=0 OR a.grantee IN(SELECT oid FROM pg_roles WHERE rolname=ANY($3::text[])))",[creator,kind,[f.roles.login.name,f.roles.api.name,'gc_app']]);assert.equal(defaults.n,0,'Creator-specific global defaults must refuse PUBLIC/runtime access');}
 await query(f.owner,'BEGIN');
 try{await query(f.owner,"CREATE FUNCTION gc_authority.qualification_future(integer) RETURNS integer LANGUAGE sql AS 'SELECT 1'");await query(f.owner,"CREATE TYPE gc_authority.qualification_future_type AS ENUM('synthetic')");await query(f.owner,'CREATE TABLE gc_authority.qualification_future_table(id integer)');await query(f.owner,'CREATE SEQUENCE gc_authority.qualification_future_sequence');
  for(const role of [f.roles.login.name,f.roles.api.name,'gc_app']){const p=await scalar(f.owner,"SELECT has_function_privilege($1,'gc_authority.qualification_future(integer)','EXECUTE') f,has_type_privilege($1,'gc_authority.qualification_future_type','USAGE') t,has_table_privilege($1,'gc_authority.qualification_future_table','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') r,has_sequence_privilege($1,'gc_authority.qualification_future_sequence','USAGE,SELECT,UPDATE') s",[role]);assert.ok(Object.values(p).every(v=>v===false),'Future private objects inherited an unintended effective runtime privilege');}
 }finally{await query(f.owner,'ROLLBACK');}
 assert.equal((await scalar(f.owner,"SELECT to_regprocedure('gc_authority.qualification_future(integer)') IS NULL missing")).missing,true);
});
