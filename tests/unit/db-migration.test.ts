// SPDX-License-Identifier: Apache-2.0
/** Transaction orchestration controls only; the fake client does not qualify SQL. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {applyMigration,type MigrationClient} from '../../packages/db/src/migrate.ts';
const name='037_application_authentication_bridge.sql';
const bridge=await readFile(new URL('../../packages/db/migrations/'+name,import.meta.url),'utf8');
const foundation=await readFile(new URL('../../packages/db/migrations/012_authentication_foundation.sql',import.meta.url),'utf8');
const hash=(body:string)=>createHash('sha256').update(body).digest('hex');
type Phase='lookup'|'begin'|'grant'|'body'|'revoke'|'ledger'|'commit'|'rollback';
class Client implements MigrationClient{
 readonly events:Phase[]=[];readonly calls:Array<{text:string;values?:unknown[]}>=[];
 ledger=new Map<string,string>();createPrivilege=false;installed=false;
 fail?:Phase;rollbackFails=false;readonly error=Error('synthetic migration refusal');
 private before?:{ledger:Map<string,string>;createPrivilege:boolean;installed:boolean};
 async query(text:string,values?:unknown[]){
  const phase:Phase=text.startsWith('SELECT checksum')?'lookup':text==='BEGIN'?'begin':text==='COMMIT'?'commit':text==='ROLLBACK'?'rollback':text.startsWith('DO $migration_transfer$ DECLARE')?'grant':text.startsWith('REVOKE CREATE ON SCHEMA public')?'revoke':text.startsWith('INSERT INTO schema_migrations')?'ledger':'body';
  this.events.push(phase);this.calls.push({text,values});
  if(phase==='rollback'){
   if(this.rollbackFails)throw Error('synthetic lost connection');
   assert.ok(this.before);Object.assign(this,{...this.before,ledger:new Map(this.before.ledger)});this.before=undefined;
  }else if(this.fail===phase)throw this.error;
  else if(phase==='lookup'){const checksum=this.ledger.get(values![0] as string);return {rowCount:checksum===undefined?0:1,rows:checksum===undefined?[]:[{checksum}]};}
  else if(phase==='begin'){assert.equal(this.before,undefined);this.before={ledger:new Map(this.ledger),createPrivilege:this.createPrivilege,installed:this.installed};}
  else if(phase==='grant'){assert.ok(this.before);this.createPrivilege=true;}
  else if(phase==='body'){
   assert.ok(this.before);
   if(text===foundation)this.createPrivilege=false;
   if(text===bridge){assert.equal(this.createPrivilege,true,'ownership transfer requires CREATE');this.installed=true;}
  }else if(phase==='revoke'){assert.ok(this.before);this.createPrivilege=false;}
  else if(phase==='ledger'){assert.ok(this.before);this.ledger.set(values![0] as string,values![1] as string);}
  else if(phase==='commit'){assert.ok(this.before);this.before=undefined;}
  return {rowCount:0,rows:[]};
 }
}
test('fresh SQL012 then SQL037 restages only the transaction-local transfer prerequisite',async()=>{
 const client=new Client();client.createPrivilege=true;
 await applyMigration(client,'012_authentication_foundation.sql',foundation);assert.equal(client.createPrivilege,false);
 client.events.length=0;
 assert.equal(await applyMigration(client,name,bridge),true);
 assert.deepEqual(client.events,['lookup','begin','grant','body','revoke','ledger','commit']);
 assert.equal(client.createPrivilege,false);assert.equal(client.installed,true);assert.equal(client.ledger.get(name),hash(bridge));
 assert.equal(client.calls.filter(x=>x.text===bridge).length,1);
});
test('SQL036 upgrade with pre-staged CREATE still revokes it before recording SQL037',async()=>{
 const client=new Client();client.createPrivilege=true;
 assert.equal(await applyMigration(client,name,bridge),true);assert.equal(client.createPrivilege,false);
 assert.ok(client.events.indexOf('revoke')<client.events.indexOf('ledger'));
});
test('applied exact SQL037 replay performs no transaction, grant or role repair',async()=>{
 const client=new Client();client.ledger.set(name,hash(bridge));
 assert.equal(await applyMigration(client,name,bridge),false);assert.deepEqual(client.events,['lookup']);assert.equal(client.createPrivilege,false);
});
test('applied checksum conflict and modified pending SQL037 refuse before grant',async()=>{
 for(const installed of [false,true]){
  const client=new Client();if(installed)client.ledger.set(name,hash(bridge));
  await assert.rejects(applyMigration(client,name,bridge+'\n-- changed'),installed?/Applied migration changed/:/checksum rejected/);
  assert.deepEqual(client.events,['lookup']);assert.equal(client.createPrivilege,false);
 }
});
test('every SQL037 transactional failure rolls back the new privilege, body and ledger',async()=>{
 for(const phase of ['grant','body','revoke','ledger','commit'] as const){
  const client=new Client();client.fail=phase;
  await assert.rejects(applyMigration(client,name,bridge),error=>error===client.error);
  assert.equal(client.events.at(-1),'rollback');assert.equal(client.createPrivilege,false);assert.equal(client.installed,false);assert.equal(client.ledger.has(name),false);
  assert.equal(client.events.filter(x=>x==='commit').length,phase==='commit'?1:0);
 }
});
test('rollback restores pre-existing deployment grant without inventing role repair',async()=>{
 const client=new Client();client.createPrivilege=true;client.fail='body';
 await assert.rejects(applyMigration(client,name,bridge));assert.equal(client.createPrivilege,true);
 assert.equal(client.installed,false);assert.equal(client.ledger.has(name),false);
 // The existing administrator finish phase owns removal of this prior grant.
 assert.deepEqual(client.events,['lookup','begin','grant','body','rollback']);
});
test('rollback connection failure retains the original migration failure',async()=>{
 const client=new Client();client.fail='body';client.rollbackFails=true;
 await assert.rejects(applyMigration(client,name,bridge),error=>error===client.error);assert.equal(client.events.at(-1),'rollback');
});
test('other migration names never acquire the SQL037 temporary privilege',async()=>{
 const client=new Client();assert.equal(await applyMigration(client,'038_future.sql','SELECT 1;'),true);
 assert.deepEqual(client.events,['lookup','begin','body','ledger','commit']);assert.equal(client.createPrivilege,false);
});
test('transfer admission requires unchanged native role invariants and cleanup verifies absence',async()=>{
 const client=new Client();await applyMigration(client,name,bridge);
 const grant=client.calls.find(x=>x.text.startsWith('DO $migration_transfer$ DECLARE'))!.text;
 for(const required of ["current_user<>session_user","current_setting('role')<>'none'",'gc_authn.installation_root',"nspname='public' AND nspowner=owner_role.oid",'set_option AND NOT inherit_option AND NOT admin_option',"rolname='gc_authn_definer'",'GRANT CREATE ON SCHEMA public TO gc_authn_definer'])assert.ok(grant.includes(required));
 for(const role of ['owner_role','definer_role'])for(const flag of ['rolsuper','rolcreatedb','rolcreaterole','rolinherit','rolreplication','rolbypassrls'])assert.ok(grant.includes(role+'.'+flag));
 assert.ok(!grant.includes('CREATE ROLE'));assert.ok(!grant.includes('GRANT gc_authn_definer'));
 const cleanup=client.calls.find(x=>x.text.startsWith('REVOKE CREATE ON SCHEMA public'))!.text;
 assert.ok(cleanup.includes("has_schema_privilege('gc_authn_definer','public','CREATE')"));
});
