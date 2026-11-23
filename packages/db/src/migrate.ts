// SPDX-License-Identifier: Apache-2.0
import pg from 'pg';
import {readFile,readdir} from 'node:fs/promises';
import {applyMigration} from './migration-runner.ts';

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
// Existing native qualification imports this module after setting the owner URL.
await main();
