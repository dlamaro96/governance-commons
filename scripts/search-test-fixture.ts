// SPDX-License-Identifier: Apache-2.0
/** Owner-only preparation of a fixed, nonlogin synthetic search qualification
 * scope. SQL013 retains canonical identity/member tombstones, so these tenants
 * are persistent. Tests clean only their own assets, index entries and sessions.
 * Existing authority is verified, never reset or repaired by this helper. */
import {Client} from 'pg';
import {SEARCH_TEST_FIXTURE as fixture} from '../tests/fixtures/search-tenants.ts';

const name='Synthetic search qualification';
const issuer='https://search-fixture.invalid/owned';
const people=[fixture.steward,fixture.consumer,fixture.summit].sort();
const tenants=[fixture.tenant,fixture.foreign].sort();
const ids=[...tenants,...people].sort();
const memberships=[
  {tenant:fixture.tenant,identity:fixture.steward,role:'steward'},
  {tenant:fixture.tenant,identity:fixture.consumer,role:'consumer'},
  {tenant:fixture.foreign,identity:fixture.summit,role:'steward'},
];
function require(value:unknown):asserts value {if(!value)throw Error('FIXTURE_NOT_CONFIRMED');}

async function main(){
  require(process.argv.length===3&&process.argv[2]==='prepare');
  require(ids.length===5&&new Set(ids).size===5&&ids.every(id=>/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id)));
  const connectionString=process.env.MIGRATION_DATABASE_URL;
  require(connectionString);
  const client=new Client({connectionString,application_name:'gc-search-fixture',connectionTimeoutMillis:5000,
    statement_timeout:15000,lock_timeout:2000,idle_in_transaction_session_timeout:15000,query_timeout:16000});
  let transaction=false;
  try {
    await client.connect();
    await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');transaction=true;
    // This checks original native session_user/current_user and the installed
    // database/owner tuple. Neither app credentials nor SET ROLE are accepted.
    await client.query('SELECT gc_authority.owner_check()');
    await client.query("SELECT set_config('gc.actor_id','',true),set_config('gc.tenant_id','',true)");
    // Tenant ledgers precede principal rows. The fixed-ID locks also serialize
    // initial absence checks between concurrent invocations of this helper.
    for(const tenant of tenants)await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[tenant]);
    for(const id of ids)await client.query("SELECT pg_advisory_xact_lock(hashtextextended('gc-search-fixture:'||$1::text,0))",[id]);
    const existingTenants=await client.query('SELECT id,name FROM public.tenants WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE',[ids]);
    const existingPeople=await client.query('SELECT id,issuer,subject,name,active FROM public.identities WHERE id=ANY($1::uuid[]) OR (issuer=$2 AND subject=ANY($3::text[])) ORDER BY id FOR UPDATE',[ids,issuer,people]);
    const existingHeads=await client.query('SELECT identity_id FROM gc_authority.identity_heads WHERE identity_id=ANY($1::uuid[]) ORDER BY identity_id FOR UPDATE',[ids]);
    const created=existingTenants.rows.length===0&&existingPeople.rows.length===0&&existingHeads.rows.length===0;
    if(created){
      await client.query('INSERT INTO public.tenants(id,name) SELECT id,$2 FROM unnest($1::uuid[]) id',[tenants,name]);
      await client.query('INSERT INTO public.identities(id,issuer,subject,name,active) SELECT id,$2,id::text,$3,true FROM unnest($1::uuid[]) id',[people,issuer,name]);
      for(const member of memberships){
        await client.query("SELECT set_config('gc.tenant_id',$1,true)",[member.tenant]);
        await client.query("INSERT INTO public.memberships(tenant_id,identity_id,role,permissions,active) VALUES($1::uuid,$2::uuid,$3,'[\"catalog:read\"]'::jsonb,true)",[member.tenant,member.identity,member.role]);
      }
    } else {
      // Partial setup, collisions or deleted/revoked fixture state are failures.
      // In particular, no ON CONFLICT or UPDATE can resurrect a former identity.
      require(existingTenants.rows.length===2&&existingTenants.rows.every(row=>tenants.includes(row.id)&&row.name===name));
      require(existingPeople.rows.length===3&&existingPeople.rows.every(row=>people.includes(row.id)&&row.issuer===issuer&&row.subject===row.id&&row.name===name&&row.active===true));
      require(existingHeads.rows.length===3&&existingHeads.rows.every(row=>people.includes(row.identity_id)));
    }
    const identityHeads=await client.query(`SELECT h.identity_id,h.revision::text,h.present,h.active,
      h.canonical_issuer,h.canonical_subject,
      h.row_digest=gc_authority.hash(jsonb_build_object('identityId',h.identity_id,'present',h.present,
        'canonicalIssuer',h.canonical_issuer,'canonicalSubject',h.canonical_subject,'active',h.active)) AS digest_valid
      FROM gc_authority.identity_heads h WHERE h.identity_id=ANY($1::uuid[]) ORDER BY h.identity_id FOR UPDATE`,[people]);
    require(identityHeads.rows.length===3&&identityHeads.rows.every(row=>row.revision==='1'&&row.present===true&&row.active===true
      &&row.canonical_issuer===issuer&&row.canonical_subject===row.identity_id&&row.digest_valid===true));
    // A protected binding would make a supposed nonlogin persona usable outside
    // this test protocol. Never remove/revoke one to make fixture setup succeed.
    require((await client.query('SELECT 1 FROM gc_authn.identity_bindings WHERE identity_id=ANY($1::uuid[]) LIMIT 1',[people])).rows.length===0);
    for(const tenant of tenants){
      await client.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id','',true)",[tenant]);
      const expected=memberships.filter(member=>member.tenant===tenant);
      const actual=await client.query('SELECT tenant_id,identity_id,role,permissions,active FROM public.memberships WHERE tenant_id=$1::uuid ORDER BY identity_id LIMIT 4 FOR UPDATE',[tenant]);
      require(actual.rows.length===expected.length&&actual.rows.every(row=>{
        const member=expected.find(value=>value.identity===row.identity_id);
        return member&&row.role===member.role&&row.active===true&&JSON.stringify(row.permissions)==='["catalog:read"]';
      }));
      const heads=await client.query(`SELECT h.identity_id,h.revision,h.present,h.active,
        h.row_digest=gc_authority.hash(jsonb_build_object('tenantId',h.tenant_id,'identityId',h.identity_id,'present',h.present,'active',h.active)) AS digest_valid
        FROM gc_authority.tenant_member_heads h WHERE h.tenant_id=$1::uuid ORDER BY h.identity_id LIMIT 4 FOR UPDATE`,[tenant]);
      require(heads.rows.length===expected.length&&heads.rows.every(row=>expected.some(member=>member.identity===row.identity_id)
        &&row.revision===1&&row.present===true&&row.active===true&&row.digest_valid===true));
      require((await client.query('SELECT 1 FROM gc_authn.tenant_fences WHERE tenant_id=$1::uuid LIMIT 1',[tenant])).rows.length===0);
      require((await client.query('SELECT 1 FROM gc_authority.tenant_heads WHERE tenant_id=$1::uuid LIMIT 1',[tenant])).rows.length===0);
    }
    // Actor-scoped membership RLS deliberately exposes all memberships of the
    // selected exact identity, including unexpected membership in another tenant.
    for(const identity of people){
      await client.query("SELECT set_config('gc.actor_id',$1,true),set_config('gc.tenant_id','',true)",[identity]);
      const rows=(await client.query('SELECT tenant_id,identity_id FROM public.memberships WHERE identity_id=$1::uuid ORDER BY tenant_id LIMIT 2 FOR UPDATE',[identity])).rows;
      require(rows.length===1&&rows[0].tenant_id===memberships.find(member=>member.identity===identity)!.tenant);
    }
    await client.query('COMMIT');transaction=false;
    console.log(JSON.stringify({result:'PREPARED',created,tenants:2,identities:3,memberships:3,persistent:true}));
  } catch {
    if(transaction)try{await client.query('ROLLBACK');}catch{/* Discard the native connection below. */}
    throw Error('FIXTURE_NOT_CONFIRMED');
  } finally {await client.end().catch(()=>undefined);}
}

main().catch(()=>{
  // Do not expose native SQL errors, connection strings, credentials or input.
  console.error('SEARCH_FIXTURE_NOT_CONFIRMED: owner preparation refused; existing authority was not reset.');
  process.exitCode=1;
});
