// SPDX-License-Identifier: Apache-2.0
/** Real SQL035 installer/lookup qualification. No runtime activation. */
import assert from 'node:assert/strict';
import {after,test} from 'node:test';
import {fixture,closeDefaultDb,producerCall,executeProducer,bind,revokeProducer,producerLookup,heads,snapshot,unchanged,scope,query,scalar,tx,uuid,extra,rejected,implementation,requestEncoding,receiptEncoding,type ProducerReceipt} from '../fixtures/reviewed-classification-facts.ts';
import {createHash} from 'node:crypto';
import {mutate,addGroup} from '../fixtures/authority-foundation.ts';

after(closeDefaultDb);
const tables=['gc_authority.classification_producer_heads','gc_authority.classification_producer_installations'];

test('explicit installer selects the exact classification producer version among multiple registered alternatives',async t=>{
 const f=await fixture(t,{bind:false,source:false}),before=await heads(f),installed=await bind(f,f.producers.nextVersion.ref),value=await producerLookup(f),after=await heads(f);
 assert.equal(installed.receipt.version,1);assert.deepEqual(installed.receipt.producer,f.producers.nextVersion.ref);
 assert.deepEqual(value.binding,{installationId:installed.receipt.installationId,version:1,operation:'bind',implementation,producer:f.producers.nextVersion.ref,authorityEpochAfter:after.authority,manifestHash:installed.receipt.manifestHash});
 assert.equal(value.tenantId,f.tenant);assert.equal(value.registryId,f.registryId);assert.equal(value.registryVersion,f.registry.version);assert.equal(value.registryDigest,f.registry.digest);assert.equal(value.generation,'1');assert.equal(value.authorityEpoch,after.authority);
 assert.equal(BigInt(after.authority),BigInt(before.authority)+1n);assert.equal(after.content,before.content);
});

test('replacement revoke and explicit rebind retain immutable predecessors and each consume exactly one authority epoch',async t=>{
 const f=await fixture(t,{bind:false,source:false}),before=await heads(f),first=await bind(f),second=await bind(f,f.producers.alternative.ref),revoked=await revokeProducer(f),last=await bind(f,f.producers.primary.ref);
 const rows=(await query(f.admin,'SELECT id,version,operation,expected_previous_installation_id previous_installation_id,CASE WHEN version=1 THEN NULL ELSE expected_binding_version END previous_version,previous_manifest_hash,expected_authority_epoch::text epoch_before,authority_epoch_after::text epoch_after FROM gc_authority.classification_producer_installations WHERE tenant_id=$1 ORDER BY version',[f.tenant])).rows;
 const receipts=[first.receipt,second.receipt,revoked.receipt,last.receipt];assert.equal(rows.length,4);
 rows.forEach((row,i)=>{assert.equal(row.id,receipts[i]!.installationId);assert.equal(row.version,i+1);assert.equal(row.operation,i===2?'revoke':'bind');assert.equal(row.previous_installation_id,i?receipts[i-1]!.installationId:null);assert.equal(row.previous_version,i||null);assert.equal(row.previous_manifest_hash,i?receipts[i-1]!.manifestHash:null);assert.equal(BigInt(row.epoch_after),BigInt(before.authority)+BigInt(i+1));});
 const after=await heads(f);assert.equal(BigInt(after.authority),BigInt(before.authority)+4n);assert.equal(after.content,before.content);assert.equal((await producerLookup(f)).binding!.installationId,last.receipt.installationId);
});

test('historical exact bind replay returns its original receipt without reactivating a revoked head',async t=>{
 const f=await fixture(t,{bind:false,source:false}),first=await bind(f),revoked=await revokeProducer(f),before=await snapshot(f);
 assert.deepEqual(await executeProducer(f,first.call),first.receipt);assert.deepEqual(await snapshot(f),before);
 assert.equal((await producerLookup(f)).binding!.installationId,revoked.receipt.installationId);assert.equal((await producerLookup(f)).binding!.operation,'revoke');
});

test('historical exact revoke replay remains stable after a later explicit replacement',async t=>{
 const f=await fixture(t,{source:false}),revoked=await revokeProducer(f),last=await bind(f,f.producers.alternative.ref),before=await snapshot(f);
 assert.deepEqual(await executeProducer(f,revoked.call),revoked.receipt);assert.deepEqual(await snapshot(f),before);assert.equal((await producerLookup(f)).binding!.installationId,last.receipt.installationId);
});

test('conflicting reuse of a tenant request id refuses without changing the current binding or epoch',async t=>{
 const f=await fixture(t,{bind:false,source:false}),first=await bind(f),conflict={...first.call,values:[...first.call.values]};conflict.values[14]=f.producers.alternative.ref.id;
 await unchanged(f,()=>executeProducer(f,conflict),['40001']);
});

test('foreign wrong-kind retired future expired missing and wrong-version producers all refuse atomically',async t=>{
 const f=await fixture(t,{bind:false,source:false});
 for(const producer of [f.producers.foreign.ref,f.producers.wrongKind.ref,f.producers.retired.ref,f.producers.future.ref,f.producers.expired.ref,{id:uuid(),version:1},{...f.producers.primary.ref,version:99}]){
  const call=await producerCall(f,'bind',{producer:producer as typeof f.producers.primary.ref});await unchanged(f,()=>executeProducer(f,call),['22023','23514']);
 }
 assert.equal((await producerLookup(f)).binding,null);
});

test('an initialized registry without producers cannot be silently amended or switched by binding',async t=>{
 const f=await fixture(t,{bind:false,source:false,emptyRegistry:true}),before=await scalar(f.admin,'SELECT registry_document,digest FROM gc_authority.registries WHERE id=$1 AND version=$2',[f.registryId,f.registry.version]),call=await producerCall(f,'bind');
 await unchanged(f,()=>executeProducer(f,call),['22023','23514']);assert.deepEqual(await scalar(f.admin,'SELECT registry_document,digest FROM gc_authority.registries WHERE id=$1 AND version=$2',[f.registryId,f.registry.version]),before);assert.equal((await producerLookup(f)).binding,null);
});

test('wrong registry generation authn fence authority epoch and predecessor CAS each roll back their attempted write',async t=>{
 const f=await fixture(t,{source:false});
 const changes:Record<number,unknown>[]=[{6:'2'},{7:'2'},{8:'1'},{9:0,10:null},{10:uuid()},{11:uuid()},{12:2},{13:'0'.repeat(64)}];
 for(const overrides of changes){const call=await producerCall(f,'bind',{producer:f.producers.alternative.ref,overrides});await unchanged(f,()=>executeProducer(f,call),['40001','23514','22023']);}
});

test('native install admission rejects incorrect owner or database identity and invalid scalar calls',async t=>{
 const f=await fixture(t,{bind:false,source:false});
 for(const overrides of [{3:0},{4:0},{0:'00000000-0000-0000-0000-000000000000'},{1:''},{2:'invalid\noperator'}]){
  const call=await producerCall(f,'bind',{overrides});await unchanged(f,()=>executeProducer(f,call),['22023','42501']);
 }
});

test('ordinary real authority lifecycle writes still complete and a later epoch preserves the installed producer',async t=>{
 const f=await fixture(t,{source:false}),before=await producerLookup(f),content=(await heads(f)).content;
 await mutate(f,()=>addGroup(f));const after=await producerLookup(f);assert.equal(BigInt(after.authorityEpoch),BigInt(before.authorityEpoch)+1n);assert.deepEqual(after.binding,before.binding);assert.equal((await heads(f)).content,content);
});

test('a genuine sealed foundation write without a lifecycle or producer receipt still cannot commit',async t=>{
 const f=await fixture(t,{source:false}),before=await heads(f);
 await unchanged(f,()=>tx(f.owner,async()=>{await query(f.owner,'SELECT gc_authority.foundation_write_begin_v1($1::uuid,$2::bigint)',[f.tenant,before.authority]);await query(f.owner,"SELECT gc_authority.foundation_write_locks_v1('{}'::uuid[],'{}'::uuid[])");}));
});

test('ordinary direct owner mutations cannot rewrite delete truncate or clone private producer records',async t=>{
 const f=await fixture(t,{source:false});
 for(const table of tables)for(const statement of [`UPDATE ${table} SET tenant_id=tenant_id WHERE tenant_id=$1`,`DELETE FROM ${table} WHERE tenant_id=$1`,`TRUNCATE ${table} CASCADE`,`INSERT INTO ${table} SELECT * FROM ${table} WHERE tenant_id=$1`]){
  await unchanged(f,()=>tx(f.owner,async()=>{await scope(f.owner,f);await query(f.owner,statement,statement.includes('$1')?[f.tenant]:[]);}),['23514','42501']);
 }
});

test('every native runtime credential refuses installers lookup and private tables despite forged GUCs',async t=>{
 const f=await fixture(t,{source:false}),call=await producerCall(f,'bind'),revoke=await producerCall(f,'revoke'),before=await snapshot(f),clients=[f.legacy,f.api,f.login,await extra(f,'nextApi'),await extra(f,'nextLogin'),await extra(f,'unregistered')];
 for(const client of clients){
  for(const operation of [()=>query(client,call.sql,call.values),()=>query(client,revoke.sql,revoke.values),...tables.flatMap(table=>[()=>query(client,`SELECT * FROM ${table}`),()=>query(client,`DELETE FROM ${table}`),()=>query(client,`TRUNCATE ${table}`)])]){
   await assert.rejects(tx(client,async()=>{await scope(client,f);await query(client,"SELECT set_config('gc.authn_owner','gc_owner',true),set_config('gc.classification_producer_install','true',true)");await operation();}),rejected('42501'));
  }
  await assert.rejects(tx(client,async()=>{await scope(client,f);await query(client,'SELECT gc_authority.load_reviewed_classification_producer_v1($1)',[f.hash]);},'REPEATABLE READ READ ONLY'),rejected('42501'));
 }
 assert.deepEqual(await snapshot(f),before);
});

test('an administrative SET ROLE connection does not become the native installation executor',async t=>{
 const f=await fixture(t,{source:false}),call=await producerCall(f,'bind');
 await unchanged(f,()=>tx(f.admin,async()=>{await query(f.admin,'SET LOCAL ROLE gc_owner');await query(f.admin,call.sql,call.values);}),['42501']);
 await assert.rejects(tx(f.admin,async()=>{await query(f.admin,'SET LOCAL ROLE gc_owner');await query(f.admin,'SELECT gc_authority.load_reviewed_classification_producer_v1($1)',[f.hash]);},'REPEATABLE READ READ ONLY'),rejected('42501'));
});

test('private producer tables force owner RLS and keep same-registry tenant bindings distinct',async t=>{
 const f=await fixture(t,{source:false}),foreignCall=await producerCall(f,'bind',{tenant:f.otherTenant,producer:f.producers.foreign.ref});await executeProducer(f,foreignCall);
 for(const table of tables){assert.deepEqual(await scalar(f.admin,'SELECT relrowsecurity,relforcerowsecurity,pg_get_userbyid(relowner) owner FROM pg_class WHERE oid=$1::regclass',[table]),{relrowsecurity:true,relforcerowsecurity:true,owner:'gc_owner'});
  for(const tenant of [f.tenant,f.otherTenant])await tx(f.owner,async()=>{await scope(f.owner,f,tenant);assert.deepEqual((await query(f.owner,`SELECT DISTINCT tenant_id FROM ${table}`)).rows,[{tenant_id:tenant}]);});
  await tx(f.owner,async()=>{await query(f.owner,"SELECT set_config('gc.tenant_id','',true)");assert.equal((await query(f.owner,`SELECT * FROM ${table}`)).rowCount,0);});
 }
});

test('lookup derives its actual tenant and exact pin from the session and restores foreign scope before commit',async t=>{
 const f=await fixture(t,{source:false}),actor=uuid();
 await tx(f.owner,async()=>{await scope(f.owner,f,f.otherTenant,actor);const before=await scalar(f.owner,"SELECT current_setting('gc.tenant_id') tenant,current_setting('gc.actor_id') actor"),value=(await scalar(f.owner,'SELECT gc_authority.load_reviewed_classification_producer_v1($1) value',[f.hash])).value;
  assert.equal(value.tenantId,f.tenant);assert.equal(value.registryId,f.registryId);assert.equal(value.registryDigest,f.registry.digest);assert.deepEqual(await scalar(f.owner,"SELECT current_setting('gc.tenant_id') tenant,current_setting('gc.actor_id') actor"),before);
 },'REPEATABLE READ READ ONLY');
});

test('producer lookup requires the real readonly repeatable-read session boundary and refuses malformed or revoked sessions',async t=>{
 const f=await fixture(t,{source:false});
 for(const mode of ['READ COMMITTED','REPEATABLE READ'])await assert.rejects(tx(f.owner,()=>query(f.owner,'SELECT gc_authority.load_reviewed_classification_producer_v1($1)',[f.hash]),mode),rejected('28000','42501'));
 await assert.rejects(producerLookup(f,f.owner,'not-a-session'),rejected('28000','22023'));await query(f.api,'SELECT * FROM public.gc_authn_session_revoke($1,$2,1)',[f.hash,f.csrf]);await assert.rejects(producerLookup(f),rejected('28000'));
});

test('one held readonly snapshot retains the prior binding and authority epoch through a concurrent revoke',async t=>{
 const f=await fixture(t,{source:false}),reader=await extra(f,'owner');let before:any,revoked:any;
 await tx(reader,async()=>{before=(await scalar(reader,'SELECT gc_authority.load_reviewed_classification_producer_v1($1) value',[f.hash])).value;revoked=await revokeProducer(f);const held=(await scalar(reader,'SELECT gc_authority.load_reviewed_classification_producer_v1($1) value',[f.hash])).value;assert.deepEqual(held,before);},'REPEATABLE READ READ ONLY');
 const fresh=await producerLookup(f,reader);assert.equal(fresh.binding!.installationId,revoked.receipt.installationId);assert.equal(fresh.binding!.operation,'revoke');assert.equal(BigInt(fresh.authorityEpoch),BigInt(before.authorityEpoch)+1n);
});

test('racing exact-CAS installers publish one complete winner and the loser leaves no partial receipt',async t=>{
 const f=await fixture(t,{bind:false,source:false}),second=await extra(f,'owner'),a=await producerCall(f,'bind'),b=await producerCall(f,'bind',{producer:f.producers.alternative.ref}),before=await heads(f);await query(f.owner,'BEGIN');
 try{await query(f.owner,a.sql,a.values);const started=performance.now();await assert.rejects(query(second,b.sql,b.values),rejected('55P03','57014','40001'));assert.ok(performance.now()-started<3500);assert.equal((await producerLookup(f,await extra(f,'owner'))).binding,null);await query(f.owner,'COMMIT');}catch(error){await query(f.owner,'ROLLBACK');throw error;}
 await unchanged(f,()=>executeProducer(f,b,second),['40001']);assert.equal((await producerLookup(f)).binding!.producer.id,f.producers.primary.ref.id);assert.equal((await scalar(f.admin,'SELECT count(*)::int n FROM gc_authority.classification_producer_installations WHERE tenant_id=$1',[f.tenant])).n,1);assert.equal(BigInt((await heads(f)).authority),BigInt(before.authority)+1n);
});

test('a contended request-id replay lock has a finite budget before the foundation write begins',async t=>{
 const f=await fixture(t,{bind:false,source:false}),second=await extra(f,'owner'),call=await producerCall(f,'bind');await query(f.owner,'BEGIN');
 try{await query(f.owner,call.sql,call.values);const started=performance.now();await assert.rejects(query(second,call.sql,call.values),rejected('55P03','57014','40001'));assert.ok(performance.now()-started<3500,'Request-id lock must not wait for the client statement timeout');await query(f.owner,'COMMIT');}catch(error){await query(f.owner,'ROLLBACK');throw error;}
 const before=await snapshot(f);await executeProducer(f,call,second);assert.deepEqual(await snapshot(f),before);
});

test('installer restores caller tenant actor and lock timeout while deferred completion validates its own actual tenant',async t=>{
 const f=await fixture(t,{bind:false,source:false}),call=await producerCall(f,'bind'),actor=uuid();
 await tx(f.owner,async()=>{
  await scope(f.owner,f,f.otherTenant,actor);await query(f.owner,"SET LOCAL lock_timeout='137ms'");
  const before=await scalar(f.owner,"SELECT current_setting('gc.tenant_id') tenant,current_setting('gc.actor_id') actor,current_setting('lock_timeout') timeout");
  await query(f.owner,call.sql,call.values);assert.deepEqual(await scalar(f.owner,"SELECT current_setting('gc.tenant_id') tenant,current_setting('gc.actor_id') actor,current_setting('lock_timeout') timeout"),before);
  // The installer's EXCEPTION block uses a real PostgreSQL subtransaction.
  // Both rows must share that writer xmin while the immutable receipt binds
  // the enclosing top-level transaction and actual backend independently.
  await scope(f.owner,f);
  assert.deepEqual(await scalar(f.owner,`SELECT h.xmin=r.xmin same_writer,
   h.xmin<>pg_current_xact_id()::xid subtransaction_writer,
   r.transaction_id=pg_current_xact_id() top_transaction,r.backend_pid=pg_backend_pid() same_backend
   FROM gc_authority.classification_producer_heads h JOIN gc_authority.classification_producer_installations r
   ON (r.tenant_id,r.id,r.version)=(h.tenant_id,h.installation_id,h.version)
   WHERE h.tenant_id=$1::uuid AND h.version=1`,[f.tenant]),
   {same_writer:true,subtransaction_writer:true,top_transaction:true,same_backend:true});
  await scope(f.owner,f,f.otherTenant,actor);
  assert.deepEqual(await scalar(f.owner,"SELECT current_setting('gc.tenant_id') tenant,current_setting('gc.actor_id') actor,current_setting('lock_timeout') timeout"),before);
  await query(f.owner,'SET CONSTRAINTS ALL IMMEDIATE');assert.deepEqual(await scalar(f.owner,"SELECT current_setting('gc.tenant_id') tenant,current_setting('gc.actor_id') actor,current_setting('lock_timeout') timeout"),before);
 });
 assert.equal((await producerLookup(f)).binding!.version,1);
});

test('another tenant installs independently while the first tenant holds an uncommitted producer write',async t=>{
 const f=await fixture(t,{bind:false,source:false}),second=await extra(f,'owner'),a=await producerCall(f,'bind'),b=await producerCall(f,'bind',{tenant:f.otherTenant,producer:f.producers.foreign.ref});await query(f.owner,'BEGIN');
 try{await query(f.owner,a.sql,a.values);const receipt=await executeProducer(f,b,second);assert.equal(receipt.tenantId,f.otherTenant);assert.equal((await scalar(f.admin,'SELECT count(*)::int n FROM gc_authority.classification_producer_installations WHERE tenant_id=$1',[f.tenant])).n,0);}finally{await query(f.owner,'ROLLBACK');}
 assert.equal((await producerLookup(f)).binding,null);assert.equal((await scalar(f.admin,'SELECT count(*)::int n FROM gc_authority.classification_producer_installations WHERE tenant_id=$1',[f.otherTenant])).n,1);
});

test('a forged sealed write binding plus independently valid receipt cannot omit the actual authority epoch update',async t=>{
 const f=await fixture(t,{bind:false,source:false}),call=await producerCall(f,'bind');
 await unchanged(f,()=>tx(f.owner,async()=>{
  await scope(f.owner,f);await query(f.owner,`INSERT INTO gc_authority.write_bindings
   SELECT pg_current_xact_id(),pg_backend_pid(),session_user::regrole::oid,$1::uuid,transaction_timestamp(),transaction_timestamp()+interval '30 seconds',$2::bigint,$2::bigint+1`,[f.tenant,call.values[8]]);
  await query(f.owner,"SELECT gc_authority.foundation_write_locks_v1('{}'::uuid[],'{}'::uuid[])");
  const actual=await scalar(f.owner,"SELECT pg_current_xact_id()::text transaction_id,pg_backend_pid() backend_pid,gc_authority.utc(date_trunc('milliseconds',clock_timestamp())) recorded_at");
  const receipt:ProducerReceipt={formatVersion:1,installationId:uuid(),tenantId:f.tenant,version:1,operation:'bind',implementation,producer:f.producers.primary.ref,authorityEpochAfter:String(BigInt(String(call.values[8]))+1n),manifestHash:'0'.repeat(64),recordedAt:actual.recorded_at};
  const request=requestEncoding(call),manifest=receiptEncoding(call,receipt,null);receipt.manifestHash=createHash('sha256').update(manifest).digest('hex');
  const stored={tenant_id:f.tenant,id:receipt.installationId,version:1,request_id:call.values[0],operation:'bind',implementation,expected_generation:call.values[6],expected_authn_fence_epoch:call.values[7],expected_authority_epoch:call.values[8],authority_epoch_after:receipt.authorityEpochAfter,expected_binding_version:0,expected_previous_installation_id:null,previous_manifest_hash:null,registry_id:call.values[11],registry_version:call.values[12],registry_digest:call.values[13],producer_id:receipt.producer.id,producer_version:receipt.producer.version,database_oid:call.values[3],owner_role_oid:call.values[4],release_reference:call.values[1],operator_reference:call.values[2],recorded_at:receipt.recordedAt,transaction_id:actual.transaction_id,backend_pid:actual.backend_pid,request_encoding:'\\x'+request.toString('hex'),manifest_encoding:'\\x'+manifest.toString('hex'),manifest_hash:receipt.manifestHash};
  // The exact same independently encoded row passes structural validation.
  // It is not the codec/predecessor/registry shape that causes the refusal.
  await query(f.owner,'SELECT gc_authority.validate_classification_producer_receipt_v1(jsonb_populate_record(NULL::gc_authority.classification_producer_installations,$1::jsonb))',[JSON.stringify(stored)]);
  assert.equal((await scalar(f.owner,'SELECT authority_epoch::text epoch FROM gc_authority.tenant_heads WHERE tenant_id=$1',[f.tenant])).epoch,String(call.values[8]));
  await query(f.owner,'INSERT INTO gc_authority.classification_producer_installations SELECT * FROM jsonb_populate_record(NULL::gc_authority.classification_producer_installations,$1::jsonb)',[JSON.stringify(stored)]);
 }));
});
