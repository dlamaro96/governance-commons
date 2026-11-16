// SPDX-License-Identifier: Apache-2.0
import pg from 'pg';
import {typeHash} from '../../domain/src/asset-type-policy.ts';
const client=new pg.Client({connectionString:process.env.MIGRATION_DATABASE_URL});
if(!process.env.MIGRATION_DATABASE_URL) throw Error('MIGRATION_DATABASE_URL required for explicit synthetic seed');
await client.connect();
const harbor='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',summit='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const all=['catalog:read','catalog:write','sources:read','sources:write','audit:read','models:read','models:write','domains:read','domains:write','domains:assign'];
const personas=[['steward','Harbor Steward',harbor,all],['owner','Harbor Owner',harbor,['catalog:read','catalog:write','audit:read','models:read','domains:read','domains:write','domains:assign']],['consumer','Harbor Analyst',harbor,['catalog:read','models:read']],['auditor','Harbor Auditor',harbor,['catalog:read','audit:read','models:read','domains:read']],['summit','Summit Administrator',summit,all],['engineer','Harbor Engineer',harbor,all]] as const;
try {
 await client.query('BEGIN');
 await client.query('INSERT INTO tenants(id,name) VALUES($1,$2),($3,$4) ON CONFLICT DO NOTHING',[harbor,'Harbor Retail',summit,'Summit Logistics']);
 for(let i=0;i<personas.length;i++) {
  const [role,name,tenant,permissions]=personas[i], id='10000000-0000-4000-8000-'+String(i+1).padStart(12,'0');
  await client.query("SELECT set_config('gc.tenant_id',$1,true)",[tenant]);
  const inserted=await client.query('INSERT INTO identities(id,issuer,subject,name) VALUES($1::uuid,$2,$1::text,$3) ON CONFLICT DO NOTHING RETURNING id',[id,process.env.OIDC_ISSUER??'http://localhost:4311/realms/governance',name]);
  if(inserted.rowCount===1)await client.query('INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING',[tenant,id,role,JSON.stringify(permissions)]);
  // Existing membership authority is preserved exactly. Fresh inserts declare
  // this version's baseline; repeated seed never infers that a missing model
  // action should be restored from a retained catalog action.
 }
 await client.query('COMMIT');
 // An explicit, one-time upgrade of these known synthetic personas. The durable
 // marker prevents repeated seed from restoring subsequently revoked authority.
 // One actor per transaction preserves the storage family/identity binding.
 for(let i=0;i<personas.length;i++) {
  const [role,,tenant,permissions]=personas[i],id='10000000-0000-4000-8000-'+String(i+1).padStart(12,'0');
  const grants=permissions.filter(value=>value.startsWith('domains:'));
  const baseline=permissions.filter(value=>!value.startsWith('domains:'));
  if(!grants.length)continue;
  const operation='bootstrap.domain-permissions.v1',key='harbor-demo';
  const hash=typeHash({dataset:key,identityId:id,role,permissions:grants});
  await client.query('BEGIN');
  await client.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[tenant,id]);
  await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[tenant]);
  await client.query('SELECT gc_lock_type_migration_principals($1::uuid[])',[[id]]);
  const prior=await client.query('SELECT request_hash,response FROM idempotency WHERE tenant_id=$1 AND actor_id=$2 AND operation=$3 AND key=$4',[tenant,id,operation,key]);
  if(prior.rows.length) {
   const row=prior.rows[0];
   if(row.request_hash!==hash||Object.keys(row.response??{}).sort().join(',')!=='applied,dataset,version'||row.response?.dataset!==key||row.response?.version!==1||typeof row.response?.applied!=='boolean')throw Error('Synthetic permission marker conflicts with the declared seed.');
  } else {
   const changed=await client.query(`UPDATE memberships m SET permissions=(SELECT jsonb_agg(DISTINCT value ORDER BY value)
    FROM jsonb_array_elements_text(m.permissions || $4::jsonb))
    WHERE m.tenant_id=$1 AND m.identity_id=$2 AND m.role=$3 AND m.active AND m.permissions @> $5::jsonb
    AND EXISTS(SELECT 1 FROM identities i WHERE i.id=m.identity_id AND i.active) RETURNING m.identity_id`,[tenant,id,role,JSON.stringify(grants),JSON.stringify(baseline)]);
   await client.query('INSERT INTO idempotency(tenant_id,actor_id,operation,key,request_hash,response) VALUES($1,$2,$3,$4,$5,$6)',
    [tenant,id,operation,key,hash,JSON.stringify({dataset:key,version:1,applied:changed.rowCount===1})]);
  }
  await client.query('COMMIT');
 }
 console.log('Seeded two synthetic tenants and six personas; no source scan or verification inferred.');
} catch(e){await client.query('ROLLBACK');throw e;} finally{await client.end();}

const {seedBusinessDomains}=await import('./seed-business-domains.ts');
await seedBusinessDomains();

const {seedGlossary}=await import('./seed-glossary.ts');
await seedGlossary();
