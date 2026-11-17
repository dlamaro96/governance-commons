// SPDX-License-Identifier: Apache-2.0
/** Test-fixture regression on real PostgreSQL; no source tables or product budgets change. */
import assert from 'node:assert/strict';
import {after,test} from 'node:test';
import {createHash} from 'node:crypto';
import {db,scope,sql,type Tx} from '../../packages/db/src/index.ts';
import type {OperationNodeSource} from 'kysely';
import {actor,tenant,fixture,snapshot,snapshotRowDigests,snapshotTableDigests,snapshotTables} from '../fixtures/business-domains.ts';
if(!process.env.DATABASE_URL)throw Error('Real PostgreSQL DATABASE_URL required; no snapshot regression ran.');
const digest=(value:string)=>createHash('sha256').update(value,'utf8').digest('hex');
async function originalRows(tx:Tx,rows:OperationNodeSource):Promise<string[]>{
 // Independent full-row oracle. These bounded synthetic rows alone are materialized
 // in Node; the live accumulated tenant histories are never fetched here.
 return (await sql<{canonical:string}>`SELECT pg_catalog.to_jsonb(original_row)::text canonical FROM (${rows}) original_row`.execute(tx)).rows.map(row=>row.canonical);
}
const syntheticRows=(changed=false,reverse=false)=>sql`
 SELECT CASE WHEN ${changed} AND n=4096 THEN 'late mutation' ELSE (n%17)::text END AS label,
  jsonb_build_object('opaque',jsonb_build_object('constructor','ordinary data','nested',jsonb_build_array(NULL,true,n%17,'مرحبا 漢字')),
   'retained',repeat('Synthetic full row ',16)) AS payload,
  12345678901234567890.123456789::numeric exact_decimal,
  '2026-11-17 00:00:00.123456+00'::timestamptz exact_time,NULL::text nullable
 FROM generate_series(1,4096) input(n) ORDER BY CASE WHEN ${reverse} THEN -n ELSE n END`;

test('database snapshots equal complete full-row multisets, retaining duplicates and detecting a late-row change',async()=>{
 await scope(tenant,actor,async tx=>{
  const source=syntheticRows(),before=await originalRows(tx,source),actual=await snapshotRowDigests(tx,source);
  assert.equal(before.length,4096);assert.equal(actual.length,before.length);
  assert.equal(new Set(actual).size,17);assert.deepEqual(actual,before.map(digest).sort());
  const reversed=await originalRows(tx,syntheticRows(false,true));
  assert.notDeepEqual(reversed,before);assert.deepEqual([...reversed].sort(),[...before].sort());
  assert.deepEqual(await snapshotRowDigests(tx,syntheticRows(false,true)),actual);
  const changed=await originalRows(tx,syntheticRows(true));
  assert.deepEqual(changed.slice(0,-1),before.slice(0,-1));assert.notEqual(changed.at(-1),before.at(-1));
  const after=await snapshotRowDigests(tx,syntheticRows(true));
  assert.deepEqual(after,changed.map(digest).sort());assert.notDeepEqual(after,actual);
  const remaining=[...actual];for(const value of after){const index=remaining.indexOf(value);if(index>=0)remaining.splice(index,1);}
  assert.equal(remaining.length,1,'exactly one occurrence changed, with all duplicates retained');
  assert.deepEqual(await snapshotRowDigests(tx,sql`SELECT * FROM (${source}) empty_rows WHERE false`),[]);
 });
});

test('each immutable outbox field changes the database digest and row structure is never omitted',async()=>{
 await scope(tenant,actor,async tx=>{
  const event={tenant_id:tenant,id:'30000000-0000-4000-8000-000000000001',event_type:'synthetic.snapshot',
   resource_id:'40000000-0000-4000-8000-000000000001',resource_version:1,payload:{late:'retained',nested:[null,'مرحبا']},created_at:'2026-11-17T00:00:00.123456Z'};
  const rows=(value:unknown)=>sql`SELECT * FROM jsonb_to_record(${JSON.stringify(value)}::jsonb) AS event(tenant_id uuid,id uuid,event_type text,resource_id text,resource_version integer,payload jsonb,created_at timestamptz)`;
  const baseline=await snapshotRowDigests(tx,rows(event));assert.equal(baseline.length,1);
  assert.deepEqual(baseline,(await originalRows(tx,rows(event))).map(digest));
  const alternatives={tenant_id:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',id:'30000000-0000-4000-8000-000000000002',event_type:'synthetic.changed',
   resource_id:'40000000-0000-4000-8000-000000000002',resource_version:2,payload:{...event.payload,late:'changed'},created_at:'2026-11-17T00:00:00.123457Z'};
  for(const [field,value] of Object.entries(alternatives))assert.notDeepEqual(await snapshotRowDigests(tx,rows({...event,[field]:value})),baseline,field);
  const extended=sql`SELECT event.*,NULL::text added_immutable_field FROM (${rows(event)}) event`;
  assert.notDeepEqual(await snapshotRowDigests(tx,extended),baseline,'new selected fields are automatically included');
 });
});

test('live snapshot keeps all twelve tenant-scoped row counts and excludes only outbox delivery bookkeeping',async()=>{
 const f=await fixture();const current=await snapshot();
 assert.deepEqual(Object.keys(current).sort(),[...snapshotTables,'epoch'].sort());
 await scope(tenant,actor,async tx=>{
  for(const table of snapshotTables){
   const count=await tx.selectFrom(table).select(eb=>eb.fn.countAll<string>().as('count')).executeTakeFirstOrThrow();
   assert.equal(current[table].length,Number(count.count),table);
   assert.ok(current[table].every((value:unknown)=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value)),table);
  }
  assert.equal(current.epoch,(await sql<{value:string}>`SELECT gc_domain_scope_epoch() value`.execute(tx)).rows[0]!.value);
 });
 const rollback=new Error('Rollback synthetic delivery metadata');
 await assert.rejects(()=>scope(tenant,actor,async tx=>{
  const before=await snapshotTableDigests(tx,'outbox');
  const event=await tx.selectFrom('outbox').select(['id','attempts','processed_at']).where('resource_id','=',f.domains[0]!.id).executeTakeFirstOrThrow();
  const updated=await tx.updateTable('outbox').set({attempts:event.attempts+1,processed_at:new Date('2026-11-17T01:02:03.000Z')}).where('id','=',event.id)
   .returning(['attempts','processed_at']).executeTakeFirstOrThrow();
  assert.equal(updated.attempts,event.attempts+1);assert.equal(new Date(updated.processed_at).toISOString(),'2026-11-17T01:02:03.000Z');
  assert.deepEqual(await snapshotTableDigests(tx,'outbox'),before);
  throw rollback;
 }),error=>error===rollback);
 assert.deepEqual(await snapshot(),current,'rolled-back bookkeeping preserves the whole snapshot');
});
after(()=>db.destroy());
