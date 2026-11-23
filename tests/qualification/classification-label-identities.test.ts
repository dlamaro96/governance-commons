// SPDX-License-Identifier: Apache-2.0
/** Real isolated SQL034 qualification. The public command runs as gc_app; private
 * sidecars are inspected through separately authenticated owner/admin clients.
 * This does not activate classification facts or canonical content authority. */
import assert from 'node:assert/strict';
import {test, type TestContext} from 'node:test';
import type pg from 'pg';
import {fixture, query, scalar, tx, uid, extra, rejected, waitBlocked} from '../fixtures/authority-foundation.ts';
import {config, connect} from '../fixtures/authority-authn-foundation.ts';
import type {ClassificationTaxonomy} from '../../packages/domain/src/classification-contracts.ts';

type Fixture=Awaited<ReturnType<typeof fixture>>;
type Label=ClassificationTaxonomy['labels'][number];
interface BaselineFixture {tenantId:string;taxonomyId:string;baselineVersion:number;retainedKey:string;absentKey:string;deprecatedKey:string;reusedKey:string}
const permissions=['catalog:read','classification:read','classification:write','models:read','models:write'];
const privateTables=['classification_label_baselines','classification_label_identities','classification_label_version_bindings'] as const;
const snapshotTables=[...privateTables.map(name=>'gc_authority.'+name),'gc_authority.content_security_heads','gc_authority.tenant_heads',
 'public.classification_taxonomies','public.classification_taxonomy_versions','public.classification_rules','public.classification_rule_versions',
 'public.classification_assignments','public.classification_assignment_revisions','public.audit','public.outbox','public.idempotency'];
const label=(key='contact',status:Label['status']='active',name='Contact metadata'):Label=>({key,name,description:'Synthetic reviewed metadata label.',status});
const definition=(labels:Label[]=[label()],description='Synthetic isolated identity qualification.'):ClassificationTaxonomy=>({formatVersion:1,name:'Synthetic classification identities',description,labels});
async function prepared(t:TestContext){
 const f=await fixture(t);
 for(const tenant of [f.tenant,f.otherTenant])await tx(f.owner,async()=>{
  await scope(f.owner,f,tenant);
  await query(f.owner,'UPDATE public.memberships SET permissions=$3::jsonb WHERE tenant_id=$1 AND identity_id=$2',[tenant,f.identity,JSON.stringify(permissions)]);
 });
 return f;
}
async function scope(client:pg.Client,f:Fixture,tenant=f.tenant,actor=f.identity){
 await query(client,"SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[tenant,actor]);
}
async function command(client:pg.Client,taxonomyId:string,expectedVersion:number,value:ClassificationTaxonomy,key:string=uid()){
 return (await scalar(client,"SELECT public.gc_classification_command('classification.taxonomy.publish',$1,$2::jsonb,'classification-label-native') value",[key,JSON.stringify({id:taxonomyId,expectedVersion,definition:value})])).value.taxonomy as {id:string;version:number;definitionHash:string;definition:ClassificationTaxonomy};
}
async function publish(f:Fixture,value=definition(),taxonomyId:string=uid(),expectedVersion=0,key:string=uid(),tenant=f.tenant,client=f.legacy){
 return tx(client,async()=>{await scope(client,f,tenant);return command(client,taxonomyId,expectedVersion,value,key);});
}
async function snapshot(f:Fixture,tenant=f.tenant,client=f.admin){
 return (await query(client,snapshotTables.map(table=>`SELECT '${table}' name,count(*)::text rows,encode(sha256(coalesce(string_agg(row_hash,''::bytea ORDER BY row_hash),''::bytea)),'hex') digest FROM (SELECT sha256(convert_to(to_jsonb(r)::text,'UTF8')) row_hash FROM ${table} r WHERE tenant_id=$1) s`).join(' UNION ALL ')+' ORDER BY name',[tenant])).rows;
}
async function unchanged(f:Fixture,work:()=>Promise<unknown>,codes:string[]=['23514'],tenant=f.tenant){
 const before=await snapshot(f,tenant);await assert.rejects(work,rejected(...codes));assert.deepEqual(await snapshot(f,tenant),before,'Refusal must preserve identities, canonical rows, audit, outbox, idempotency and both authority/content heads');
}
async function identities(f:Fixture,taxonomyId:string,tenant=f.tenant,client=f.admin){
 return (await query(client,'SELECT id,taxonomy_id,label_key,first_registered_version,retired_at_version FROM gc_authority.classification_label_identities WHERE tenant_id=$1 AND taxonomy_id=$2 ORDER BY label_key',[tenant,taxonomyId])).rows;
}
async function bindings(f:Fixture,taxonomyId:string,tenant=f.tenant,client=f.admin){
 return (await query(client,'SELECT taxonomy_version,label_key,label_id,label_status FROM gc_authority.classification_label_version_bindings WHERE tenant_id=$1 AND taxonomy_id=$2 ORDER BY taxonomy_version,label_key',[tenant,taxonomyId])).rows;
}
async function baseline(f:Fixture,taxonomyId:string,tenant=f.tenant){
 return scalar(f.admin,'SELECT baseline_version,baseline_hash,registered_at FROM gc_authority.classification_label_baselines WHERE tenant_id=$1 AND taxonomy_id=$2',[tenant,taxonomyId]);
}
async function heads(f:Fixture){
 return scalar(f.admin,'SELECT c.revision::text content,a.authority_epoch::text authority FROM gc_authority.content_security_heads c JOIN gc_authority.tenant_heads a USING(tenant_id) WHERE c.tenant_id=$1',[f.tenant]);
}
function baselineMarkers():BaselineFixture[]{
 const markers=(config as typeof config&{classificationLabelBaselineFixtures?:BaselineFixture[]}).classificationLabelBaselineFixtures;
 assert.ok(Array.isArray(markers)&&markers.length>0&&markers.length<=8,'A populated pre-SQL034 baseline fixture is required; never skip or fabricate migration evidence');
 for(const marker of markers){assert.equal(marker.baselineVersion,3);for(const field of ['tenantId','taxonomyId'] as const)assert.match(marker[field],/^[a-f0-9-]{36}$/);assert.equal(new Set([marker.retainedKey,marker.absentKey,marker.deprecatedKey,marker.reusedKey]).size,4);}
 return markers;
}

test('fresh taxonomy creates a complete version-one private baseline with distinct label UUIDs',async t=>{
 const f=await prepared(t),value=definition([label('contact'),label('restricted')]),tax=await publish(f,value),rows=await identities(f,tax.id),pins=await bindings(f,tax.id),base=await baseline(f,tax.id);
 assert.equal(base.baseline_version,1);assert.equal(base.baseline_hash,tax.definitionHash);assert.ok(Number.isFinite(Date.parse(String(base.registered_at))));
 assert.equal(rows.length,2);assert.equal(new Set(rows.map(r=>r.id)).size,2);assert.ok(rows.every(r=>r.first_registered_version===1&&r.retired_at_version===null));
 assert.deepEqual(pins,rows.map(r=>({taxonomy_version:1,label_key:r.label_key,label_id:r.id,label_status:'active'})));
});

test('retained active keys keep their UUID through display-name and description changes',async t=>{
 const f=await prepared(t),tax=await publish(f),before=await identities(f,tax.id),base=await baseline(f,tax.id);
 await publish(f,definition([{...label(),name:'Renamed contact',description:'Updated synthetic explanation.'}],'Updated taxonomy explanation.'),tax.id,1);
 assert.deepEqual(await identities(f,tax.id),before);assert.deepEqual(await baseline(f,tax.id),base);
 assert.deepEqual((await bindings(f,tax.id)).map(r=>[r.taxonomy_version,r.label_id,r.label_status]),[[1,before[0]!.id,'active'],[2,before[0]!.id,'active']]);
});

test('the same key receives independent identities across tenant and taxonomy boundaries',async t=>{
 const f=await prepared(t),id=uid(),a=await publish(f,definition(),id),b=await publish(f),c=await publish(f,definition(),id,0,uid(),f.otherTenant);
 const rows=[...(await identities(f,a.id)),...(await identities(f,b.id)),...(await identities(f,c.id,f.otherTenant))];
 assert.equal(rows.length,3);assert.equal(new Set(rows.map(r=>r.id)).size,3);assert.ok(rows.every(r=>r.label_key==='contact'));
});

test('omitting an active key retires it permanently and resurrection rolls back all publication effects',async t=>{
 const f=await prepared(t),tax=await publish(f,definition([label(),label('retained')])),original=(await identities(f,tax.id)).find(r=>r.label_key==='contact')!;
 await publish(f,definition([label('retained')]),tax.id,1);const retired=(await identities(f,tax.id)).find(r=>r.label_key==='contact')!;
 assert.equal(retired.id,original.id);assert.equal(retired.retired_at_version,2);
 await unchanged(f,()=>publish(f,definition([label(),label('retained')]),tax.id,2));
 assert.deepEqual((await bindings(f,tax.id)).filter(r=>r.label_key==='contact').map(r=>r.taxonomy_version),[1]);
});

test('deprecation is terminal while later deprecated references preserve the original identity and retirement',async t=>{
 const f=await prepared(t),tax=await publish(f,definition([label(),label('retained')])),original=(await identities(f,tax.id)).find(r=>r.label_key==='contact')!;
 await publish(f,definition([label('contact','deprecated'),label('retained')]),tax.id,1);
 await publish(f,definition([label('retained')]),tax.id,2);
 await publish(f,definition([label('contact','deprecated','Archived contact'),label('retained')]),tax.id,3);
 const current=(await identities(f,tax.id)).find(r=>r.label_key==='contact')!;assert.equal(current.id,original.id);assert.equal(current.retired_at_version,2);
 assert.deepEqual((await bindings(f,tax.id)).filter(r=>r.label_key==='contact').map(r=>[r.taxonomy_version,r.label_status,r.label_id]),[[1,'active',original.id],[2,'deprecated',original.id],[4,'deprecated',original.id]]);
 await unchanged(f,()=>publish(f,definition([label(),label('retained')]),tax.id,4));
});

test('a label first published as deprecated cannot subsequently become active',async t=>{
 const f=await prepared(t),tax=await publish(f,definition([label('archived','deprecated')])),row=(await identities(f,tax.id))[0]!;
 assert.equal(row.first_registered_version,1);assert.equal(row.retired_at_version,1);
 await unchanged(f,()=>publish(f,definition([label('archived')]),tax.id,1));
});

test('a genuinely new key after retirement creates a new UUID without rewriting historical bindings',async t=>{
 const f=await prepared(t),tax=await publish(f),original=(await identities(f,tax.id))[0]!,oldPins=await bindings(f,tax.id);
 await publish(f,definition([label('contact_v2')]),tax.id,1);const rows=await identities(f,tax.id),old=rows.find(r=>r.label_key==='contact')!,fresh=rows.find(r=>r.label_key==='contact_v2')!;
 assert.equal(old.id,original.id);assert.equal(old.retired_at_version,2);assert.notEqual(fresh.id,old.id);assert.equal(fresh.first_registered_version,2);assert.equal(fresh.retired_at_version,null);
 assert.deepEqual((await bindings(f,tax.id)).filter(r=>r.taxonomy_version===1),oldPins);
});

test('exact publication replay changes no identity or journal and conflicting idempotency reuse fails',async t=>{
 const f=await prepared(t),id=uid(),key=uid(),value=definition(),first=await publish(f,value,id,0,key),before=await snapshot(f);
 assert.deepEqual(await publish(f,value,id,0,key),first);assert.deepEqual(await snapshot(f),before);
 await unchanged(f,()=>publish(f,definition([label('different')]),id,0,key),['40001']);
});

test('revoked publication permission leaves private identity and canonical publication state unchanged',async t=>{
 const f=await prepared(t),tax=await publish(f);
 await tx(f.owner,async()=>{await scope(f.owner,f);await query(f.owner,"UPDATE public.memberships SET permissions='[\"catalog:read\",\"classification:read\",\"models:read\"]'::jsonb WHERE tenant_id=$1 AND identity_id=$2",[f.tenant,f.identity]);});
 await unchanged(f,()=>publish(f,definition([label('second')]),tax.id,1),['42501']);
});

test('multiple sequential publications in one transaction validate their final head and retain every version binding',async t=>{
 const f=await prepared(t),id=uid(),before=await heads(f);
 await tx(f.legacy,async()=>{await scope(f.legacy,f);await command(f.legacy,id,0,definition());await command(f.legacy,id,1,definition([label('contact','active','Renamed')]));await command(f.legacy,id,2,definition([label('contact','deprecated')]));await query(f.legacy,'SET CONSTRAINTS ALL IMMEDIATE');});
 const rows=await identities(f,id),pins=await bindings(f,id),after=await heads(f);assert.equal(rows.length,1);assert.equal(rows[0]!.retired_at_version,3);
 assert.deepEqual(pins.map(r=>[r.taxonomy_version,r.label_status]),[[1,'active'],[2,'active'],[3,'deprecated']]);assert.equal(new Set(pins.map(r=>r.label_id)).size,1);
 assert.equal(BigInt(after.content),BigInt(before.content)+3n);assert.equal(after.authority,before.authority);
});

test('a later resurrection inside one transaction rolls back earlier successful publications in that transaction',async t=>{
 const f=await prepared(t),tax=await publish(f);
 await unchanged(f,()=>tx(f.legacy,async()=>{await scope(f.legacy,f);await command(f.legacy,tax.id,1,definition([label('contact','deprecated')]));await command(f.legacy,tax.id,2,definition());}));
 assert.equal((await identities(f,tax.id))[0]!.retired_at_version,null);assert.equal((await bindings(f,tax.id)).length,1);
});

test('concurrent publications serialize on the real tenant lock and publish one complete winning version',async t=>{
 const f=await prepared(t),tax=await publish(f),second=await connect(config.legacy),before=await heads(f);f.clients.push(second);let pending:Promise<{value?:unknown;error?:unknown}>|undefined;
 await query(f.legacy,'BEGIN');
 try{
  await scope(f.legacy,f);await command(f.legacy,tax.id,1,definition([label(),label('winner')]));
  pending=publish(f,definition([label(),label('loser')]),tax.id,1,uid(),f.tenant,second).then(value=>({value}),error=>({error}));
  await waitBlocked(f.admin,second,f.legacy);assert.equal((await bindings(f,tax.id)).length,1);await query(f.legacy,'COMMIT');
  const result=await pending;assert.ok(rejected('40001')(result.error),'The second exact-version writer must fail after the first commit');
 }finally{await query(f.legacy,'ROLLBACK');if(pending)await pending;}
 assert.deepEqual((await identities(f,tax.id)).map(r=>r.label_key),['contact','winner']);assert.deepEqual((await bindings(f,tax.id)).map(r=>[r.taxonomy_version,r.label_key]),[[1,'contact'],[2,'contact'],[2,'winner']]);
 const after=await heads(f);assert.equal(BigInt(after.content),BigInt(before.content)+1n);assert.equal(after.authority,before.authority);
});

test('a held repeatable-read snapshot sees identities bindings and content revision from one atomic publication state',async t=>{
 const f=await prepared(t),tax=await publish(f),reader=await extra(f,'owner');
 await tx(reader,async()=>{await scope(reader,f);const before=await snapshot(f,f.tenant,reader),pins=await bindings(f,tax.id,f.tenant,reader);
  await publish(f,definition([label('contact','deprecated'),label('new_key')]),tax.id,1);
  assert.deepEqual(await snapshot(f,f.tenant,reader),before);assert.deepEqual(await bindings(f,tax.id,f.tenant,reader),pins);
 },'REPEATABLE READ READ ONLY');
 await tx(reader,async()=>{await scope(reader,f);const rows=await identities(f,tax.id,f.tenant,reader);assert.equal(rows.find(r=>r.label_key==='contact')!.retired_at_version,2);assert.equal(rows.find(r=>r.label_key==='new_key')!.first_registered_version,2);assert.equal((await bindings(f,tax.id,f.tenant,reader)).length,3);},'REPEATABLE READ READ ONLY');
});

test('all private sidecars force owner RLS and expose only the selected tenant',async t=>{
 const f=await prepared(t);await publish(f);await publish(f,definition(),uid(),0,uid(),f.otherTenant);
 for(const name of privateTables){const metadata=await scalar(f.admin,'SELECT relrowsecurity,relforcerowsecurity,pg_get_userbyid(relowner) owner FROM pg_class WHERE oid=$1::regclass',['gc_authority.'+name]);assert.deepEqual(metadata,{relrowsecurity:true,relforcerowsecurity:true,owner:'gc_owner'});
  for(const tenant of [f.tenant,f.otherTenant])await tx(f.owner,async()=>{await scope(f.owner,f,tenant);const rows=(await query(f.owner,'SELECT DISTINCT tenant_id FROM gc_authority.'+name)).rows;assert.deepEqual(rows,[{tenant_id:tenant}]);});
  await tx(f.owner,async()=>{await query(f.owner,"SELECT set_config('gc.tenant_id','',true)");assert.equal((await query(f.owner,'SELECT * FROM gc_authority.'+name)).rowCount,0);});
 }
});

test('all runtime credentials refuse sidecar reads and writes despite forged tenant actor and owner settings',async t=>{
 const f=await prepared(t);await publish(f);const before=await snapshot(f),clients=[f.legacy,f.api,f.login,await extra(f,'nextApi'),await extra(f,'nextLogin'),await extra(f,'unregistered')];
 for(const client of clients)for(const table of privateTables)for(const statement of ['SELECT * FROM gc_authority.'+table,'DELETE FROM gc_authority.'+table,'TRUNCATE gc_authority.'+table]){
  await assert.rejects(tx(client,async()=>{await scope(client,f);await query(client,"SELECT set_config('gc.authn_owner','gc_owner',true),set_config('gc.classification_label_maintenance','true',true)");await query(client,statement);}),rejected('42501'));
 }
 assert.deepEqual(await snapshot(f),before);
});

test('direct ordinary-owner insert update delete and truncate cannot create reset or rewrite sidecars',async t=>{
 const f=await prepared(t),tax=await publish(f),identity=(await identities(f,tax.id))[0]!;
 const inserts:Array<[string,unknown[]]>=[
  ['INSERT INTO gc_authority.classification_label_baselines(tenant_id,taxonomy_id,baseline_version,baseline_hash,registered_at) VALUES($1,$2,1,$3,clock_timestamp())',[f.tenant,tax.id,tax.definitionHash]],
  ['INSERT INTO gc_authority.classification_label_identities(tenant_id,id,taxonomy_id,label_key,first_registered_version,retired_at_version) VALUES($1,$2,$3,$4,1,NULL)',[f.tenant,uid(),tax.id,'forged']],
  ['INSERT INTO gc_authority.classification_label_version_bindings(tenant_id,taxonomy_id,taxonomy_version,label_key,label_id,label_status) VALUES($1,$2,1,$3,$4,\'active\')',[f.tenant,tax.id,'contact',identity.id]],
 ];
 for(const [statement,args] of inserts)await unchanged(f,()=>tx(f.owner,async()=>{await scope(f.owner,f);await query(f.owner,statement,args);}));
 for(const table of privateTables)for(const statement of ['UPDATE gc_authority.'+table+' SET tenant_id=tenant_id WHERE tenant_id=$1','DELETE FROM gc_authority.'+table+' WHERE tenant_id=$1','TRUNCATE gc_authority.'+table+' CASCADE']){
  await unchanged(f,()=>tx(f.owner,async()=>{await scope(f.owner,f);await query(f.owner,statement,statement.includes('$1')?[f.tenant]:[]);}));
 }
});

test('a canonical head advanced without its version cannot commit or leave partial identity state',async t=>{
 const f=await prepared(t),tax=await publish(f);
 await unchanged(f,()=>tx(f.owner,async()=>{await scope(f.owner,f);await query(f.owner,'UPDATE public.classification_taxonomies SET current_version=current_version+1 WHERE tenant_id=$1 AND id=$2',[f.tenant,tax.id]);}),['23503','23514']);
});

test('an out-of-order canonical version refuses publication without changing identities or existing history',async t=>{
 const f=await prepared(t),tax=await publish(f),value=definition([label('unexpected')]);
 await unchanged(f,()=>tx(f.owner,async()=>{await scope(f.owner,f);await query(f.owner,'INSERT INTO public.classification_taxonomy_versions(tenant_id,taxonomy_id,version,definition,definition_hash,created_by,created_at) VALUES($1,$2,2,$3::jsonb,public.gc_type_migration_hash($3::jsonb),$4,clock_timestamp())',[f.tenant,tax.id,JSON.stringify(value),f.identity]);}));
});

test('the supported 128-label publication boundary creates a complete unique binding set and excess labels roll back',async t=>{
 const f=await prepared(t),labels=Array.from({length:128},(_,i)=>label('label_'+String(i).padStart(3,'0'))),tax=await publish(f,definition(labels)),rows=await identities(f,tax.id),pins=await bindings(f,tax.id);
 assert.equal(rows.length,128);assert.equal(pins.length,128);assert.equal(new Set(rows.map(r=>r.id)).size,128);assert.deepEqual(pins.map(r=>r.label_key),labels.map(r=>r.key));
 await unchanged(f,()=>publish(f,definition([...labels,label('overflow')]),tax.id,1),['22023']);
});

test('one taxonomy publication advances only its original canonical content revision and not authority epoch',async t=>{
 const f=await prepared(t),before=await heads(f),tax=await publish(f,definition([label(),label('second'),label('archived','deprecated')])),created=await heads(f);
 assert.equal(BigInt(created.content),BigInt(before.content)+1n);assert.equal(created.authority,before.authority);
 await publish(f,definition([label('contact','deprecated'),label('new_key')]),tax.id,1);const changed=await heads(f);
 assert.equal(BigInt(changed.content),BigInt(created.content)+1n);assert.equal(changed.authority,created.authority);assert.equal((await identities(f,tax.id)).length,4);
});

test('publication and deferred validation restore the callers prior tenant and actor settings within the same transaction',async t=>{
 const f=await prepared(t),id=uid(),value=definition(),before=await heads(f),priorActor=uid();
 // A native owner fixture uses its permitted tenant and a distinct existing
 // actor setting. Check before COMMIT; transaction reset cannot prove this.
 await tx(f.owner,async()=>{
  await scope(f.owner,f,f.tenant,priorActor);
  const settings=()=>scalar(f.owner,"SELECT current_setting('gc.tenant_id') tenant,current_setting('gc.actor_id') actor");
  const prior=await settings();assert.deepEqual(prior,{tenant:f.tenant,actor:priorActor});
  await query(f.owner,'INSERT INTO public.classification_taxonomies(tenant_id,id,current_version,created_by,created_at) VALUES($1,$2,1,$3,clock_timestamp())',[f.tenant,id,f.identity]);
  assert.deepEqual(await settings(),prior);
  await query(f.owner,'INSERT INTO public.classification_taxonomy_versions(tenant_id,taxonomy_id,version,definition,definition_hash,created_by,created_at) VALUES($1,$2,1,$3::jsonb,public.gc_type_migration_hash($3::jsonb),$4,clock_timestamp())',[f.tenant,id,JSON.stringify(value),f.identity]);
  assert.deepEqual(await settings(),prior,'AFTER publication must restore scope before the next statement, not merely at transaction end');
  await query(f.owner,'SET CONSTRAINTS ALL IMMEDIATE');assert.deepEqual(await settings(),prior,'Deferred validation must restore caller scope in the still-open transaction');
 });
 assert.equal((await identities(f,id)).length,1);assert.equal((await bindings(f,id)).length,1);const after=await heads(f);assert.equal(BigInt(after.content),BigInt(before.content)+1n);assert.equal(after.authority,before.authority);
});

test('populated migration binds only the current pin and reserves historical keys without inventing historical identity continuity',async t=>{
 const f=await prepared(t);
 for(const marker of baselineMarkers()){
  const rows=await identities(f,marker.taxonomyId,marker.tenantId),pins=await bindings(f,marker.taxonomyId,marker.tenantId),base=await baseline(f,marker.taxonomyId,marker.tenantId);
  const version=await scalar(f.admin,'SELECT definition_hash,definition FROM public.classification_taxonomy_versions WHERE tenant_id=$1 AND taxonomy_id=$2 AND version=$3',[marker.tenantId,marker.taxonomyId,marker.baselineVersion]);
  assert.equal(base.baseline_version,3);assert.equal(base.baseline_hash,version.definition_hash);assert.equal(rows.length,4);assert.equal(new Set(rows.map(r=>r.id)).size,4);assert.ok(rows.every(r=>r.first_registered_version===3));
  for(const key of [marker.absentKey,marker.deprecatedKey])assert.equal(rows.find(r=>r.label_key===key)!.retired_at_version,3);
  for(const key of [marker.retainedKey,marker.reusedKey])assert.equal(rows.find(r=>r.label_key===key)!.retired_at_version,null);
  assert.ok(pins.every(r=>r.taxonomy_version===3));assert.deepEqual(pins.map(r=>r.label_key),[marker.retainedKey,marker.deprecatedKey,marker.reusedKey].sort());
  const historic=(await query(f.admin,'SELECT version,definition FROM public.classification_taxonomy_versions WHERE tenant_id=$1 AND taxonomy_id=$2 ORDER BY version',[marker.tenantId,marker.taxonomyId])).rows;
  assert.deepEqual(historic.map(r=>r.version),[1,2,3]);assert.ok(historic[0]!.definition.labels.some((l:Label)=>l.key===marker.reusedKey));assert.ok(!historic[1]!.definition.labels.some((l:Label)=>l.key===marker.reusedKey));assert.ok(historic[2]!.definition.labels.some((l:Label)=>l.key===marker.reusedKey));
 }
});

test('a historically omitted key reserved by migration cannot be resurrected and failed publication preserves the entire tenant',async t=>{
 const f=await prepared(t);
 for(const marker of baselineMarkers()){
  const head=await scalar(f.admin,'SELECT created_by,current_version FROM public.classification_taxonomies WHERE tenant_id=$1 AND id=$2',[marker.tenantId,marker.taxonomyId]);
  const row=await scalar(f.admin,'SELECT definition FROM public.classification_taxonomy_versions WHERE tenant_id=$1 AND taxonomy_id=$2 AND version=$3',[marker.tenantId,marker.taxonomyId,head.current_version]);
  const value=row.definition as ClassificationTaxonomy;
  await unchanged(f,()=>tx(f.legacy,async()=>{await scope(f.legacy,f,marker.tenantId,head.created_by);return command(f.legacy,marker.taxonomyId,head.current_version,{...value,labels:[...value.labels,label(marker.absentKey)]});}),['23514'],marker.tenantId);
 }
});
