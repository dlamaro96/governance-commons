// SPDX-License-Identifier: Apache-2.0
/** Native SQL qualification of the actual scan handlers and lineage reader.
 * Completion observations are authored fixtures, not worker/catalog extraction
 * evidence. Only the disposable harness supplies native owner/runtime URLs.
 * Owned fixture history is retained until the entire disposable DB is removed. */
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import test,{type TestContext} from 'node:test';
import pg from 'pg';
import {Kysely,PostgresDialect} from 'kysely';
import {lockTenantLedger,sql,type Tx} from '../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../packages/authz/src/index.ts';
import {configureRelationTransaction} from '../../packages/domain/src/relation-store.ts';
import {getAssetLineage} from '../../packages/domain/src/lineage-read.ts';
import type {PgViewLineage,LineageQuery} from '../../packages/domain/src/lineage-contracts.ts';
import {claimSourceScan,completeSourceScan,failSourceScan} from '../../apps/api/src/source-scans.ts';

const configPath=process.env.AUTHN_FOUNDATION_CONFIG;
assert.ok(configPath,'AUTHN_FOUNDATION_CONFIG is required; no shared runtime fallback');
const config=JSON.parse(readFileSync(configPath,'utf8')) as {owner:string;legacy:string};
assert.equal(typeof config.owner,'string');assert.equal(typeof config.legacy,'string');
process.env.SESSION_KEY=randomUUID()+randomUUID();
const permissions=['catalog:read','sources:read','sources:write'];
const protectedTables=['lineage_observations','lineage_edge_observations'] as const;
const snapshotTables=[...protectedTables,'assets','asset_revisions','sources','jobs','audit','outbox'] as const;
const graphTables=[...protectedTables,'assets','asset_revisions','sources'] as const;
const problem=(status:number,code:string)=>(error:unknown)=>error instanceof Problem&&error.status===status&&error.code===code;
const sqlstate=(code:string)=>(error:unknown)=>!!error&&typeof error==='object'&&'code'in error&&error.code===code;
const refusal=(message:string)=>(error:unknown)=>sqlstate('23514')(error)&&error instanceof Error&&error.message===message;
const external=(oid:number)=>`pg:42:relation:${oid}`;
/** Independent fixture hashing: no product hash/canonicalizer is imported. */
function canonical(value:any):string{
 if(value===null||typeof value!=='object')return JSON.stringify(value);
 if(value instanceof Date)return JSON.stringify(value.toISOString());
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 return '{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+canonical(value[key])).join(',')+'}';
}
const digest=(value:unknown)=>createHash('sha256').update(canonical(value)).digest('hex');
interface FixtureRecord {externalId:string;name:string;qualifiedName:string;type:'schema'|'table'|'view'|'column';parentExternalId?:string;metadata:Record<string,unknown>}
function completion(){
 const schema='pg:42:schema:10',records:FixtureRecord[]=[{externalId:schema,name:'owned',qualifiedName:'synthetic.owned',type:'schema',metadata:{oid:'10',provenance:'source-observed'}}];
 for(const [oid,name,kind]of [[101,'left_table','r'],[102,'right_table','r'],[201,'combined_view','v'],[202,'empty_view','m']] as const){
  records.push({externalId:external(oid),name,qualifiedName:'synthetic.owned.'+name,type:kind==='r'?'table':'view',
   parentExternalId:schema,metadata:{oid:String(oid),relationKind:kind,schema:'owned',table:name,provenance:'source-observed'}});
 }
 for(const [oid,number,name]of [[101,1,'left_value'],[102,2,'right_value']] as const)records.push({externalId:external(oid)+':column:'+number,
  name,qualifiedName:'synthetic.owned.'+(oid===101?'left_table':'right_table')+'.'+name,type:'column',parentExternalId:external(oid),
  metadata:{dataType:'integer',ordinalPosition:number,nullable:true,provenance:'source-observed'}});
 const lineage:PgViewLineage={formatVersion:1,kind:'postgresql-view-dependencies',adapterVersion:'1',queryTemplate:'postgresql-view-dependencies-v1',views:[
  {viewExternalId:external(201),rewriteOid:'301',dependencies:[{referencedExternalId:external(101),referencedAttributeNumbers:[0,1]},
   {referencedExternalId:external(102),referencedAttributeNumbers:[2]}],gaps:['OPAQUE_ROUTINE_DEPENDENCY']},
  {viewExternalId:external(202),rewriteOid:'302',dependencies:[],gaps:[]}]};
 return {observedAt:new Date().toISOString(),sourceVersion:'17.6 synthetic observation',permissionFingerprint:'owned-fixture-permissions',complete:true as const,
  records,lineage};
}
type Completion=ReturnType<typeof completion>;

async function fixture(t:TestContext){
 const owner=new pg.Client({connectionString:config.owner,connectionTimeoutMillis:5000});
 const database=new Kysely<Record<string,any>>({dialect:new PostgresDialect({pool:new pg.Pool({connectionString:config.legacy,max:1,connectionTimeoutMillis:5000})})});
 t.after(async()=>{await database.destroy();await owner.end();});await owner.connect();
 await owner.query("SET statement_timeout='15s'; SET lock_timeout='2s'");
 const tenant=randomUUID(),foreign=randomUUID(),actor=randomUUID(),reader=randomUUID(),outsider=randomUUID(),sourceId=randomUUID(),foreignSourceId=randomUUID(),foreignJobId=randomUUID();
 const principal=(id=actor,scope=tenant):Principal=>({id,tenantId:scope,name:'Synthetic lineage participant',permissions});
 const ownerTx=async<T>(work:()=>Promise<T>,scope=tenant,id=actor)=>{
  await owner.query('BEGIN');try{
   await owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true),pg_advisory_xact_lock(hashtextextended($1,0))",[scope,id]);
   const result=await work();await owner.query('COMMIT');return result;
  }catch(error){await owner.query('ROLLBACK');throw error;}
 };
 await owner.query('INSERT INTO tenants(id,name) VALUES($1,$3),($2,$3)',[tenant,foreign,'Synthetic lineage qualification']);
 for(const id of [actor,reader,outsider])await owner.query('INSERT INTO identities(id,issuer,subject,name) VALUES($1::uuid,$2,$1::uuid::text,$3)',
  [id,'https://lineage-fixture.invalid/owned','Synthetic lineage participant']);
 for(const [scope,ids,source]of [[tenant,[actor,reader],sourceId],[foreign,[outsider],foreignSourceId]] as const)await ownerTx(async()=>{
  for(const id of ids)await owner.query('INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,$3,$4::jsonb)',
   [scope,id,'synthetic',JSON.stringify(id===actor?permissions:['catalog:read'])]);
  await owner.query('INSERT INTO sources(tenant_id,id,name,host,port,database_name,schema_name,secret_ref,connector_id) VALUES($1,$2,$3,$4,5432,$5,$6,$7,$8)',
   [scope,source,'Synthetic lineage source','lineage-source.invalid','synthetic','owned','synthetic-lineage-unused','postgresql']);
  if(scope===foreign)await owner.query('INSERT INTO jobs(tenant_id,id,source_id,actor_id) VALUES($1,$2,$3,$4)',[scope,foreignJobId,source,outsider]);
 },scope,ids[0]);
 const as=<T>(work:(tx:Tx)=>Promise<T>,id:string=actor,scope:string=tenant)=>database.transaction().execute(async tx=>{
  await sql`select set_config('gc.tenant_id',${scope},true),set_config('gc.actor_id',${id},true)`.execute(tx);
  await configureRelationTransaction(tx);await lockTenantLedger(tx,scope);return work(tx);
 });
 const site=<T>(work:(tx:Tx)=>Promise<T>)=>as(work,'site:local');
 const newJob=async(status='queued')=>{const id=randomUUID();await as(tx=>tx.insertInto('jobs').values({tenant_id:tenant,id,source_id:sourceId,actor_id:actor,status}).execute());return id;};
 const claim=(id:string)=>site(tx=>claimSourceScan(tx,tenant,id,'lineage-native'));
 const complete=(id:string,body:Completion|Omit<Completion,'lineage'>=completion())=>site(tx=>completeSourceScan(tx,tenant,id,body,'lineage-native'));
 const fail=(id:string)=>site(tx=>failSourceScan(tx,tenant,id,'SOURCE_DATABASE_ERROR','lineage-native'));
 const assets=()=>as(tx=>tx.selectFrom('assets').selectAll().where('source_id','=',sourceId).execute());
 const accepted=async()=>{const id=await newJob();await claim(id);const body=completion();const result=await complete(id,body);
  assert.equal(result.job.status,'succeeded');const rows=await assets();const ids=Object.fromEntries(rows.map(row=>[row.external_id,row.id as string]));return {id,body,rows,ids};};
 const read=(id:string,query:LineageQuery={},who=actor)=>as(tx=>getAssetLineage(tx,principal(who),id,query),who);
 const state=(tables:readonly string[]=snapshotTables)=>ownerTx(async()=>{
  const result:Record<string,any[]>={};for(const name of tables){assert.ok((snapshotTables as readonly string[]).includes(name));
   result[name]=(await owner.query('SELECT * FROM public."'+name+'" WHERE tenant_id=$1',[tenant])).rows.sort((a,b)=>canonical(a).localeCompare(canonical(b)));}return result;
 });
 const unchanged=async(action:()=>Promise<unknown>,predicate:(error:unknown)=>boolean)=>{
  const before=await state();await assert.rejects(action,predicate);assert.deepEqual(await state(),before,'Refusal must not alter canonical data, evidence, revisions, audit or outbox');
 };
 const restrict=(id:string,allowed:string[])=>ownerTx(()=>owner.query("UPDATE assets SET visibility='restricted',allowed_identities=$3::jsonb WHERE tenant_id=$1 AND id=$2",[tenant,id,JSON.stringify(allowed)]));
 return {owner,database,tenant,foreign,actor,reader,outsider,sourceId,foreignSourceId,foreignJobId,principal,ownerTx,as,site,newJob,claim,complete,fail,accepted,read,state,unchanged,restrict};
}

test('native lineage stores exactly two reproducible edges and includes the empty view',async t=>{
 const f=await fixture(t),a=await f.accepted(),saved=await f.state(),observation=saved.lineage_observations[0];
 assert.equal(saved.lineage_observations.length,1);assert.deepEqual(observation.payload,a.body.lineage);assert.equal(observation.payload_hash,digest(a.body.lineage));
 assert.equal(observation.id,a.id);assert.equal(observation.source_id,f.sourceId);assert.equal(observation.scan_generation,'1');assert.equal(observation.source_version,a.body.sourceVersion);
 assert.equal(saved.lineage_edge_observations.length,2);
 for(const dependency of a.body.lineage.views[0].dependencies){
  const upstream=a.ids[dependency.referencedExternalId],downstream=a.ids[external(201)],edge=saved.lineage_edge_observations.find(row=>row.upstream_asset_id===upstream);
  assert.ok(edge);assert.equal(edge.id,digest({jobId:a.id,upstream,downstream}));assert.equal(edge.downstream_asset_id,downstream);
  assert.equal(edge.upstream_version,1);assert.equal(edge.downstream_version,1);assert.equal(edge.source_id,f.sourceId);assert.equal(edge.observation_id,a.id);
  assert.deepEqual(edge.referenced_attribute_numbers,dependency.referencedAttributeNumbers);
  assert.equal(edge.evidence_hash,digest({viewExternalId:external(201),rewriteOid:'301',...dependency}));
 }
 const graph=await f.read(a.ids[external(201)]);assert.equal(graph.coverage,'COLLECTED');assert.equal(graph.edges.length,2);assert.equal(graph.nodes.length,3);assert.equal(graph.nextCursor,null);
 for(const edge of graph.edges){assert.equal(edge.scope,'table');assert.equal(edge.sourceCodeReference,null);assert.equal(edge.confidence,null);assert.equal(edge.sourceCodeAvailability,'not-collected');assert.equal(edge.observation.id,a.id);}
 assert.deepEqual(graph.gaps,[{assetId:a.ids[external(201)],code:'OPAQUE_ROUTINE_DEPENDENCY'}]);
 const empty=await f.read(a.ids[external(202)]);assert.equal(empty.coverage,'COLLECTED');assert.deepEqual(empty.edges,[]);assert.equal(empty.nodes.length,1);assert.deepEqual(empty.gaps,[]);
 assert.deepEqual(graph.limitations,['COLUMN_MAPPINGS_NOT_COLLECTED','SQL_BODIES_NOT_ANALYZED']);
});

test('native lineage enforces tenant RLS, tenant-bound FKs and append-only observations',async t=>{
 const f=await fixture(t),a=await f.accepted();
 const properties=await f.as(tx=>sql<{relname:string;relrowsecurity:boolean;relforcerowsecurity:boolean;owns:boolean;superuser:boolean;bypass:boolean;write:boolean}>`
  select c.relname,c.relrowsecurity,c.relforcerowsecurity,c.relowner=r.oid as owns,r.rolsuper as superuser,r.rolbypassrls as bypass,
   has_table_privilege(current_user,c.oid,'UPDATE,DELETE,TRUNCATE') as write
  from pg_class c cross join pg_roles r where c.oid=any(${protectedTables.map(name=>'public.'+name)}::regclass[]) and r.rolname=current_user order by c.relname`.execute(tx));
 assert.equal(properties.rows.length,2);for(const row of properties.rows){assert.equal(row.relrowsecurity,true);assert.equal(row.relforcerowsecurity,true);assert.equal(row.owns,false);assert.equal(row.superuser,false);assert.equal(row.bypass,false);assert.equal(row.write,false);}
 for(const name of protectedTables){
  assert.equal((await f.as(tx=>sql`select * from ${sql.table(name)}`.execute(tx),f.outsider,f.foreign)).rows.length,0);
  await f.unchanged(()=>f.as(tx=>sql`delete from ${sql.table(name)} where tenant_id=${f.tenant}::uuid`.execute(tx)),sqlstate('42501'));
  await f.unchanged(()=>f.ownerTx(()=>f.owner.query('UPDATE public."'+name+'" SET tenant_id=tenant_id WHERE tenant_id=$1',[f.tenant])),sqlstate('P0001'));
 }
 await f.unchanged(()=>f.as(tx=>sql`insert into lineage_observations(tenant_id,id,source_id,scan_generation,payload,payload_hash,source_version,observed_at)
  values(${f.foreign}::uuid,${randomUUID()}::uuid,${f.foreignSourceId}::uuid,1,'{}'::jsonb,${'0'.repeat(64)},'fixture',clock_timestamp())`.execute(tx)),sqlstate('42501'));
 await f.unchanged(()=>f.as(tx=>sql`insert into lineage_observations(tenant_id,id,source_id,scan_generation,payload,payload_hash,source_version,observed_at)
  values(${f.tenant}::uuid,${f.foreignJobId}::uuid,${f.foreignSourceId}::uuid,1,'{}'::jsonb,${'0'.repeat(64)},'fixture',clock_timestamp())`.execute(tx)),sqlstate('23503'));
 await f.unchanged(()=>f.as(tx=>sql`insert into lineage_edge_observations(tenant_id,id,observation_id,source_id,upstream_asset_id,upstream_version,downstream_asset_id,downstream_version,referenced_attribute_numbers,evidence_hash)
  values(${f.tenant}::uuid,${'1'.repeat(64)},${a.id}::uuid,${f.sourceId}::uuid,${a.ids[external(101)]}::uuid,1,${a.ids[external(202)]}::uuid,1,ARRAY[1]::smallint[],${'2'.repeat(64)})`.execute(tx)),refusal('LINEAGE_SCOPE_INVALID'));
});

test('native lineage exact successful replay is unchanged and conflicting evidence is refused',async t=>{
 const f=await fixture(t),a=await f.accepted(),before=await f.state();
 assert.equal((await f.complete(a.id,a.body)).job.status,'succeeded');assert.deepEqual(await f.state(),before);
 const changed=structuredClone(a.body);changed.lineage.views[0].rewriteOid='303';
 await f.unchanged(()=>f.complete(a.id,changed),problem(409,'SCAN_REPLAY_CONFLICT'));
 const {lineage:omitted,...legacy}=a.body;assert.ok(omitted);
 await f.unchanged(()=>f.complete(a.id,legacy),problem(409,'SCAN_REPLAY_CONFLICT'));
 const malformed=structuredClone(a.body);malformed.lineage.views[0].dependencies[0].referencedExternalId=external(999);
 await f.unchanged(()=>f.complete(a.id,malformed),problem(422,'LINEAGE_INVALID'));
});

test('native lineage first claim assigns one generation and repeated claim does not advance it',async t=>{
 const f=await fixture(t),one=await f.newJob();assert.equal((await f.claim(one)).job.status,'running');
 const before=await f.state();assert.equal(before.jobs[0].scan_generation,'1');assert.equal(before.sources[0].next_scan_generation,'2');
 assert.equal((await f.claim(one)).job.status,'running');assert.deepEqual(await f.state(),before);
 const two=await f.newJob();await f.claim(two);const after=await f.state();assert.equal(after.jobs.find(row=>row.id===two).scan_generation,'2');assert.equal(after.sources[0].next_scan_generation,'3');
});

test('native lineage older completion and failure cannot downgrade a newer accepted generation',async t=>{
 const f=await fixture(t),oldComplete=await f.newJob(),oldFail=await f.newJob(),latest=await f.newJob();
 for(const id of [oldComplete,oldFail,latest])await f.claim(id);
 assert.equal((await f.complete(latest)).job.status,'succeeded');const before=await f.state(graphTables);
 const stale=await f.complete(oldComplete);assert.equal(stale.job.status,'cancelled');assert.equal(stale.job.errorCode,'SCAN_SUPERSEDED');
 assert.deepEqual(await f.state(graphTables),before);
 assert.equal((await f.fail(oldFail)).job.status,'failed');assert.deepEqual(await f.state(graphTables),before);
 assert.equal(before.sources[0].status,'healthy');assert.equal(before.sources[0].accepted_scan_generation,'3');
});

test('native lineage queued or unclaimed running jobs cannot accept observations',async t=>{
 const f=await fixture(t),queued=await f.newJob(),running=await f.newJob('running');
 await f.unchanged(()=>f.complete(queued),problem(409,'JOB_STATE_CONFLICT'));
 await f.unchanged(()=>f.complete(running),problem(409,'SCAN_CLAIM_REQUIRED'));
 await f.claim(running);assert.equal((await f.complete(running)).job.status,'succeeded');
});

test('native lineage failed rescan retains accepted graph and success restores source health',async t=>{
 const f=await fixture(t),a=await f.accepted(),before=await f.state(),view=await f.read(a.ids[external(201)]),failed=await f.newJob();
 await f.claim(failed);assert.equal((await f.fail(failed)).job.status,'failed');const after=await f.state();
 for(const name of [...protectedTables,'assets','asset_revisions'])assert.deepEqual(after[name],before[name]);
 assert.equal(after.sources[0].status,'failed');assert.deepEqual(after.sources[0].last_successful_scan,before.sources[0].last_successful_scan);
 assert.equal(after.sources[0].accepted_scan_generation,'1');assert.deepEqual(await f.read(a.ids[external(201)]),view);
 const recovered=await f.newJob();await f.claim(recovered);await f.complete(recovered);
 const final=await f.state();assert.equal(final.sources[0].status,'healthy');assert.equal(final.sources[0].accepted_scan_generation,'3');
 assert.equal(final.lineage_observations.length,2);assert.equal(final.lineage_edge_observations.length,4);
});

test('native lineage rename retains OID identity and immutable prior revision and evidence',async t=>{
 const f=await fixture(t),a=await f.accepted(),before=await f.state(),body=completion();
 const renamed=body.records.find(row=>row.externalId===external(101))!;renamed.name='renamed_table';renamed.qualifiedName='synthetic.owned.renamed_table';
 (renamed.metadata as Record<string,unknown>).table='renamed_table';
 for(const column of body.records.filter(row=>row.parentExternalId===external(101)))column.qualifiedName='synthetic.owned.renamed_table.'+column.name;
 const next=await f.newJob();await f.claim(next);await f.complete(next,body);const after=await f.state();
 const current=after.assets.find(row=>row.external_id===external(101));assert.equal(current.id,a.ids[external(101)]);assert.equal(current.version,2);assert.equal(current.name,'renamed_table');
 assert.deepEqual(current.metadata.aliases,['synthetic.owned.left_table']);
 for(const old of before.asset_revisions)assert.deepEqual(after.asset_revisions.find(row=>row.asset_id===old.asset_id&&row.version===old.version),old);
 for(const old of before.lineage_edge_observations)assert.deepEqual(after.lineage_edge_observations.find(row=>row.id===old.id),old);
 assert.deepEqual(after.lineage_observations.find(row=>row.id===a.id),before.lineage_observations[0]);
 const graph=await f.read(a.ids[external(201)]);assert.equal(graph.edges.length,2);assert.ok(graph.edges.every(edge=>edge.observation.id===next&&edge.upstreamVersion===2&&edge.downstreamVersion===2));
 assert.equal(graph.nodes.find(row=>row.id===current.id)?.name,'renamed_table');
});

test('native lineage authorizes both endpoints and gaps before pagination and hides foreign roots',async t=>{
 const f=await fixture(t),a=await f.accepted();await f.restrict(a.ids[external(102)],[f.actor]);
 const graph=await f.read(a.ids[external(201)],{limit:1},f.reader);assert.equal(graph.edges.length,1);assert.equal(graph.nextCursor,null);
 assert.deepEqual(graph.nodes.map(row=>row.id).sort(),[a.ids[external(101)],a.ids[external(201)]].sort());
 assert.equal(JSON.stringify(graph).includes(a.ids[external(102)]),false);assert.equal(Object.hasOwn(graph,'total'),false);
 await f.restrict(a.ids[external(201)],[f.actor]);
 const upstream=await f.read(a.ids[external(101)],{direction:'downstream',depth:6,limit:1},f.reader);
 assert.deepEqual(upstream.edges,[]);assert.deepEqual(upstream.gaps,[]);assert.equal(upstream.nextCursor,null);assert.equal(upstream.nodes.length,1);
 await assert.rejects(()=>f.read(a.ids[external(201)],{},f.reader),problem(404,'LINEAGE_ASSET_NOT_FOUND'));
 await assert.rejects(()=>f.as(tx=>getAssetLineage(tx,f.principal(f.outsider,f.foreign),a.ids[external(101)]),f.outsider,f.foreign),problem(404,'LINEAGE_ASSET_NOT_FOUND'));
});

test('native lineage cursors recheck current membership and reject actor or visibility changes',async t=>{
 const f=await fixture(t),a=await f.accepted(),first=await f.read(a.ids[external(201)],{limit:1},f.reader);assert.ok(first.nextCursor);
 const next=await f.read(a.ids[external(201)],{limit:1,cursor:first.nextCursor},f.reader);assert.equal(next.edges.length,1);assert.equal(next.nextCursor,null);assert.notEqual(next.edges[0].id,first.edges[0].id);
 await assert.rejects(()=>f.read(a.ids[external(201)],{limit:1,cursor:first.nextCursor!},f.actor),problem(400,'LINEAGE_PAGE_INVALID'));
 await f.ownerTx(()=>f.owner.query("UPDATE memberships SET permissions='[]'::jsonb WHERE tenant_id=$1 AND identity_id=$2",[f.tenant,f.reader]));
 await assert.rejects(()=>f.read(a.ids[external(201)],{limit:1,cursor:first.nextCursor!},f.reader),problem(403,'FORBIDDEN'));
 await f.ownerTx(()=>f.owner.query('UPDATE memberships SET permissions=$3::jsonb,active=false WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.reader,JSON.stringify(['catalog:read'])]));
 await assert.rejects(()=>f.read(a.ids[external(201)],{limit:1,cursor:first.nextCursor!},f.reader),problem(403,'FORBIDDEN'));
 await f.ownerTx(()=>f.owner.query('UPDATE memberships SET active=true WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.reader]));
 await f.restrict(a.ids[external(102)],[f.actor]);
 await assert.rejects(()=>f.read(a.ids[external(201)],{limit:1,cursor:first.nextCursor!},f.reader),problem(409,'LINEAGE_GRAPH_STALE'));
});

test('native lineage generation fences old cursors and legacy observations do not reuse old graphs',async t=>{
 const f=await fixture(t),a=await f.accepted(),first=await f.read(a.ids[external(201)],{limit:1});assert.ok(first.nextCursor);
 const newer=await f.newJob();await f.claim(newer);await f.complete(newer);
 await assert.rejects(()=>f.read(a.ids[external(201)],{limit:1,cursor:first.nextCursor!}),problem(409,'LINEAGE_GRAPH_STALE'));
 const {lineage:omitted,...oldClient}=completion();assert.ok(omitted);const legacy=await f.newJob();await f.claim(legacy);await f.complete(legacy,oldClient);
 const graph=await f.read(a.ids[external(201)]);assert.equal(graph.coverage,'NOT_COLLECTED');assert.deepEqual(graph.edges,[]);assert.deepEqual(graph.gaps,[]);assert.equal(graph.nextCursor,null);
 const retained=await f.state();assert.equal(retained.lineage_observations.length,2);assert.equal(retained.lineage_edge_observations.length,4);
});

test('native lineage completion rolls back assets, evidence, audit and outbox as one transaction',async t=>{
 const f=await fixture(t),id=await f.newJob();await f.claim(id);
 await f.unchanged(()=>f.site(async tx=>{await completeSourceScan(tx,f.tenant,id,completion(),'lineage-native');await sql`select 1/0`.execute(tx);}),sqlstate('22012'));
 assert.equal((await f.complete(id)).job.status,'succeeded');const final=await f.state();
 assert.equal(final.assets.length,7);assert.equal(final.asset_revisions.length,7);assert.equal(final.audit.length,8);assert.equal(final.outbox.length,8);
 assert.deepEqual(final.audit.map(row=>row.id).sort(),final.outbox.map(row=>row.id).sort());
 assert.equal(final.audit.filter(row=>row.action==='scan.completed').length,1);assert.equal(final.audit.filter(row=>row.action==='asset.observed').length,7);
 const body=completion(),bad=await f.newJob();await f.claim(bad);
 // These actual INSERT attempts exercise deferred COMMIT rejection. They do
 // not disable triggers or rewrite an already committed immutable observation.
 for(const variant of ['missing-edges','forged-payload-hash','prior-scan-pins','nonexistent-version'] as const){
  await f.unchanged(()=>f.site(async tx=>{
   const job=await tx.selectFrom('jobs').selectAll().where('id','=',bad).executeTakeFirstOrThrow();
   await tx.insertInto('lineage_observations').values({tenant_id:f.tenant,id:bad,source_id:f.sourceId,scan_generation:job.scan_generation,
    payload:JSON.stringify(body.lineage),payload_hash:variant==='forged-payload-hash'?'0'.repeat(64):digest(body.lineage),
    source_version:body.sourceVersion,observed_at:new Date(body.observedAt)}).execute();
   if(variant==='prior-scan-pins'||variant==='nonexistent-version')for(const dependency of body.lineage.views[0].dependencies){
    const upstream=final.assets.find(row=>row.external_id===dependency.referencedExternalId).id,
     downstream=final.assets.find(row=>row.external_id===external(201)).id;
    await tx.insertInto('lineage_edge_observations').values({tenant_id:f.tenant,id:digest({jobId:bad,upstream,downstream}),observation_id:bad,source_id:f.sourceId,
     upstream_asset_id:upstream,upstream_version:variant==='nonexistent-version'?999:1,downstream_asset_id:downstream,downstream_version:1,
     referenced_attribute_numbers:dependency.referencedAttributeNumbers,evidence_hash:digest({viewExternalId:external(201),rewriteOid:'301',...dependency})}).execute();
   }
  }),refusal(variant==='forged-payload-hash'?'LINEAGE_EVIDENCE_INVALID':'LINEAGE_PROJECTION_INVALID'));
 }
});


test('native lineage rejects extra same-transaction edges after deferred checks are flushed',async t=>{
 const f=await fixture(t),id=await f.newJob(),body=completion();await f.claim(id);let flushed=false;
 await f.unchanged(()=>f.site(async tx=>{
  assert.equal((await completeSourceScan(tx,f.tenant,id,body,'lineage-native')).job.status,'succeeded');
  await sql`SET CONSTRAINTS ALL IMMEDIATE`.execute(tx);flushed=true;
  const assets=await tx.selectFrom('assets').selectAll().where('source_id','=',f.sourceId).execute();
  const upstream=assets.find(row=>row.external_id===external(101))!,downstream=assets.find(row=>row.external_id===external(202))!;
  assert.ok(upstream);assert.ok(downstream);
  // Valid identity, hashes, source, revision pins and transaction; this edge is
  // absent from the immutable empty view observation already checked above.
  const dependency={referencedExternalId:external(101),referencedAttributeNumbers:[1]};
  await tx.insertInto('lineage_edge_observations').values({tenant_id:f.tenant,id:digest({jobId:id,upstream:upstream.id,downstream:downstream.id}),
   observation_id:id,source_id:f.sourceId,upstream_asset_id:upstream.id,upstream_version:upstream.version,
   downstream_asset_id:downstream.id,downstream_version:downstream.version,referenced_attribute_numbers:dependency.referencedAttributeNumbers,
   evidence_hash:digest({viewExternalId:external(202),rewriteOid:'302',...dependency})}).execute();
 }),refusal('LINEAGE_PROJECTION_INVALID'));
 assert.equal(flushed,true,'The regression must reach insertion after a successful constraint flush');
});
