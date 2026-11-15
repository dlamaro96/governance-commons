// SPDX-License-Identifier: Apache-2.0
import pg from 'pg';
import {readFile,readdir} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const client=new pg.Client({connectionString:process.env.MIGRATION_DATABASE_URL});
if(!process.env.MIGRATION_DATABASE_URL) throw Error('MIGRATION_DATABASE_URL required (separate migration owner)');
await client.connect();
try {
 await client.query("SET lock_timeout='15s'; SET statement_timeout='60s'");
 await client.query('SELECT pg_advisory_lock(947301)');
 await client.query('CREATE TABLE IF NOT EXISTS schema_migrations (name text primary key, checksum text not null, applied_at timestamptz not null default now())');
 for(const name of (await readdir('packages/db/migrations')).filter(x=>x.endsWith('.sql')).sort()) {
  const body=await readFile('packages/db/migrations/'+name,'utf8'),checksum=createHash('sha256').update(body).digest('hex');
  const old=await client.query('SELECT checksum FROM schema_migrations WHERE name=$1',[name]);
  if(old.rowCount) { if(old.rows[0].checksum!==checksum) throw Error('Applied migration changed: '+name);continue; }
  await client.query('BEGIN');
  try {await client.query(body);await client.query('INSERT INTO schema_migrations(name,checksum) VALUES($1,$2)',[name,checksum]);await client.query('COMMIT');console.log('Applied',name);}catch(e){await client.query('ROLLBACK');throw e;}
 }
} finally {await client.end();}
