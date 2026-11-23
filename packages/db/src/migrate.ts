// SPDX-License-Identifier: Apache-2.0
import pg from 'pg';
import {readFile,readdir} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

export type MigrationClient={query(text:string,values?:unknown[]):Promise<{rowCount:number|null;rows:Array<{checksum:string}>}>};
const AUTHN_BRIDGE_MIGRATION='037_application_authentication_bridge.sql';
const SQL037_SHA256='fe5dae5d1be5067bcbc99edb349d97f9d7898e12810d278afdd93594de0e317d';
// SQL012 removes the initial deployment CREATE grant. A fresh 001–037 run
// therefore needs this exact transfer prerequisite again at SQL037, while the
// SET-only membership remains managed by the deployment prepare/finish pair.
const AUTHN_BRIDGE_TRANSFER=`DO $migration_transfer$ DECLARE owner_role pg_catalog.pg_roles; definer_role pg_catalog.pg_roles; BEGIN
 SELECT * INTO owner_role FROM pg_catalog.pg_roles WHERE rolname=session_user;
 SELECT * INTO definer_role FROM pg_catalog.pg_roles WHERE rolname='gc_authn_definer';
 IF current_user<>session_user OR current_setting('role')<>'none'
 OR owner_role.oid IS NULL OR NOT owner_role.rolcanlogin OR owner_role.rolsuper OR owner_role.rolcreatedb OR owner_role.rolcreaterole OR owner_role.rolinherit OR owner_role.rolreplication OR owner_role.rolbypassrls
 OR definer_role.oid IS NULL OR definer_role.rolcanlogin OR definer_role.rolsuper OR definer_role.rolcreatedb OR definer_role.rolcreaterole OR definer_role.rolinherit OR definer_role.rolreplication OR definer_role.rolbypassrls
 OR NOT EXISTS(SELECT 1 FROM gc_authn.installation_root r WHERE r.singleton AND r.owner_role_oid=owner_role.oid AND r.owner_role_name=session_user AND r.database_oid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database() AND datdba=owner_role.oid))
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname='public' AND nspowner=owner_role.oid)
 OR (SELECT count(*) FROM pg_catalog.pg_auth_members WHERE member=owner_role.oid OR roleid=owner_role.oid)<>1
 OR (SELECT count(*) FROM pg_catalog.pg_auth_members WHERE member=definer_role.oid OR roleid=definer_role.oid)<>1
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members WHERE member=owner_role.oid AND roleid=definer_role.oid AND set_option AND NOT inherit_option AND NOT admin_option)
 THEN RAISE EXCEPTION 'MIGRATION_AUTHN_TRANSFER_REJECTED' USING ERRCODE='42501'; END IF;
END $migration_transfer$;
GRANT CREATE ON SCHEMA public TO gc_authn_definer;`;
const AUTHN_BRIDGE_REVOKE=`REVOKE CREATE ON SCHEMA public FROM gc_authn_definer;
DO $migration_transfer$ BEGIN
 IF pg_catalog.has_schema_privilege('gc_authn_definer','public','CREATE') THEN
  RAISE EXCEPTION 'MIGRATION_AUTHN_TRANSFER_NOT_REMOVED' USING ERRCODE='42501';
 END IF;
END $migration_transfer$;`;

/** Apply one immutable migration on the caller's held migration connection. */
export async function applyMigration(client:MigrationClient,name:string,body:string):Promise<boolean>{
 const checksum=createHash('sha256').update(body).digest('hex');
 const old=await client.query('SELECT checksum FROM schema_migrations WHERE name=$1',[name]);
 if(old.rowCount){if(old.rows[0]!.checksum!==checksum)throw Error('Applied migration changed: '+name);return false;}
 const transfer=name===AUTHN_BRIDGE_MIGRATION;
 if(transfer&&checksum!==SQL037_SHA256)throw Error('Authentication bridge migration checksum rejected');
 await client.query('BEGIN');
 try{
  if(transfer)await client.query(AUTHN_BRIDGE_TRANSFER);
  await client.query(body);
  if(transfer)await client.query(AUTHN_BRIDGE_REVOKE);
  await client.query('INSERT INTO schema_migrations(name,checksum) VALUES($1,$2)',[name,checksum]);
  await client.query('COMMIT');return true;
 }catch(error){await client.query('ROLLBACK').catch(()=>undefined);throw error;}
}

async function main(){
 if(!process.env.MIGRATION_DATABASE_URL)throw Error('MIGRATION_DATABASE_URL required (separate migration owner)');
 const client=new pg.Client({connectionString:process.env.MIGRATION_DATABASE_URL});
 await client.connect();
 try{
  await client.query("SET lock_timeout='15s'; SET statement_timeout='60s'");
  await client.query('SELECT pg_advisory_lock(947301)');
  await client.query('CREATE TABLE IF NOT EXISTS schema_migrations (name text primary key, checksum text not null, applied_at timestamptz not null default now())');
  for(const name of (await readdir('packages/db/migrations')).filter(x=>x.endsWith('.sql')).sort()){
   const body=await readFile('packages/db/migrations/'+name,'utf8');
   if(await applyMigration(client,name,body))console.log('Applied',name);
  }
 }finally{await client.end();}
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))await main();
