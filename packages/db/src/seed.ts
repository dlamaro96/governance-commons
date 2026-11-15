// SPDX-License-Identifier: Apache-2.0
import pg from 'pg';
const client=new pg.Client({connectionString:process.env.MIGRATION_DATABASE_URL});
if(!process.env.MIGRATION_DATABASE_URL) throw Error('MIGRATION_DATABASE_URL required for explicit synthetic seed');
await client.connect();
const harbor='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',summit='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const all=['catalog:read','catalog:write','sources:read','sources:write','audit:read'];
const personas=[['steward','Harbor Steward',harbor,all],['owner','Harbor Owner',harbor,['catalog:read','catalog:write','audit:read']],['consumer','Harbor Analyst',harbor,['catalog:read']],['auditor','Harbor Auditor',harbor,['catalog:read','audit:read']],['summit','Summit Administrator',summit,all],['engineer','Harbor Engineer',harbor,all]] as const;
try {
 await client.query('BEGIN');
 await client.query('INSERT INTO tenants(id,name) VALUES($1,$2),($3,$4) ON CONFLICT DO NOTHING',[harbor,'Harbor Retail',summit,'Summit Logistics']);
 for(let i=0;i<personas.length;i++) {
  const [role,name,tenant,permissions]=personas[i], id='10000000-0000-4000-8000-'+String(i+1).padStart(12,'0');
  await client.query("SELECT set_config('gc.tenant_id',$1,true)",[tenant]);
  await client.query('INSERT INTO identities(id,issuer,subject,name) VALUES($1::uuid,$2,$1::text,$3) ON CONFLICT DO NOTHING',[id,process.env.OIDC_ISSUER??'http://localhost:4311/realms/governance',name]);
  await client.query('INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING',[tenant,id,role,JSON.stringify(permissions)]);
 }
 await client.query('COMMIT');console.log('Seeded two synthetic tenants and six personas; no source scan or verification inferred.');
} catch(e){await client.query('ROLLBACK');throw e;} finally{await client.end();}
