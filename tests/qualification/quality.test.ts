// SPDX-License-Identifier: Apache-2.0
/** Native canonical quality storage/service boundaries. Each fixture owns a real
 * synthetic PostgreSQL table and catalog observations. Measurements below are
 * explicit test inputs to protected completion, not a worker/pushdown assertion.
 * Only the disposable harness supplies owner/runtime URLs; no network source,
 * HTTP, Temporal, source credentials, mocked database or forced lease expiry. */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {randomUUID} from 'node:crypto';
import test,{type TestContext} from 'node:test';
import pg from 'pg';
import {Kysely,PostgresDialect} from 'kysely';
import {sql,type Tx} from '../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../packages/authz/src/index.ts';
import {assetView} from '../../apps/api/src/repository.ts';
import {configureRelationTransaction} from '../../packages/domain/src/relation-store.ts';
import {getQualityAsset,getQualityRule,getQualityRun,listQualityRuns,publishQualityRule,requestQualityRun,cancelQualityRun,claimQualityRun,finishQualityRun} from '../../packages/domain/src/quality-service.ts';
import type {CompletenessRuleDefinition,QualityRuleView,CompletenessMeasurement,QualityColumnRunView,QualityClaim} from '../../packages/domain/src/quality-contracts.ts';

const config=JSON.parse(readFileSync(process.env.AUTHN_FOUNDATION_CONFIG!,'utf8')) as {owner:string;legacy:string};
process.env.SESSION_KEY=randomUUID()+randomUUID();
const permissions=['catalog:read','quality:read','quality:write','quality:execute'];
const status=(expected:number)=>(e:unknown)=>e instanceof Problem&&e.status===expected;
const stateCode=(expected:string)=>(e:unknown)=>!!e&&typeof e==='object'&&'code'in e&&e.code===expected;
const protectedTables=['quality_rules','quality_rule_versions','quality_runs'] as const;
const snapshotTables=[...protectedTables,'assets','asset_revisions','sources','audit','outbox','idempotency'] as const;
function measurement(rows=20,nulls=5):CompletenessMeasurement{
 const at=new Date().toISOString();return {formatVersion:1,kind:'completeness',strategy:'exact-bounded-role-scope',rowCount:rows,nullCount:nulls,
 observedStartedAt:at,observedFinishedAt:at,elapsedMs:0,sourceVersion:'170006',adapterVersion:'1',queryTemplate:'postgresql-completeness-v1',estimatedCost:1,estimatedBytes:80};
}
function claimed(value:QualityClaim):asserts value is Extract<QualityClaim,{status:'claimed'}>{assert.equal(value.status,'claimed');}

async function fixture(t:TestContext){
 const owner=new pg.Client({connectionString:config.owner});
 const database=new Kysely<Record<string,any>>({dialect:new PostgresDialect({pool:new pg.Pool({connectionString:config.legacy,max:1,connectionTimeoutMillis:5000})})});
 t.after(async()=>{await database.destroy();await owner.end();});await owner.connect();
 const tenant=randomUUID(),actor=randomUUID(),steward=randomUUID(),reader=randomUUID(),sourceId=randomUUID(),schemaId=randomUUID(),tableId=randomUUID(),columnId=randomUUID();
 const namespace='quality_'+randomUUID().replaceAll('-',''); // generated ASCII identifier only
 let target:{databaseOid:string;schemaOid:string;relationOid:string;attributeNumber:number;databaseName:string};
 await owner.query('BEGIN');try{
  await owner.query('INSERT INTO tenants(id,name) VALUES($1,$2)',[tenant,'Synthetic quality tenant']);
  await owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[tenant,actor]);
  for(const id of [actor,steward,reader]){
   await owner.query('INSERT INTO identities(id,issuer,subject,name) VALUES($1::uuid,$2,$1::uuid::text,$3)',[id,'https://quality-fixture.invalid/owned','Synthetic quality participant']);
   await owner.query('INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,$3,$4::jsonb)',[tenant,id,'synthetic',JSON.stringify(id===reader?['catalog:read','quality:read']:permissions)]);
  }
  await owner.query(`CREATE SCHEMA "${namespace}"`);
  await owner.query(`CREATE TABLE "${namespace}".observations(value integer)`);
  await owner.query(`INSERT INTO "${namespace}".observations SELECT CASE WHEN i<=5 THEN NULL ELSE i END FROM generate_series(1,20) i`);
  const canonical=(await owner.query(`SELECT d.oid::text AS "databaseOid",d.datname AS "databaseName",n.oid::text AS "schemaOid",c.oid::text AS "relationOid",a.attnum AS "attributeNumber"
   FROM pg_database d CROSS JOIN pg_namespace n JOIN pg_class c ON c.relnamespace=n.oid JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='value'
   WHERE d.datname=current_database() AND n.nspname=$1 AND c.relname='observations'`,[namespace])).rows[0];
  assert.ok(canonical);target=canonical;
  const counts=(await owner.query(`SELECT count(*)::integer AS rows,count(*) FILTER(WHERE value IS NULL)::integer AS nulls FROM "${namespace}".observations`)).rows[0];
  assert.deepEqual(counts,{rows:20,nulls:5});
  await owner.query('INSERT INTO sources(tenant_id,id,name,host,port,database_name,schema_name,secret_ref,connector_id) VALUES($1,$2,$3,$4,5432,$5,$6,$7,$8)',
   [tenant,sourceId,'Synthetic quality source','quality-source.invalid',target.databaseName,namespace,'synthetic-quality-unused','postgresql']);
  const prefix='pg:'+target.databaseOid,tableExternal=prefix+':relation:'+target.relationOid,schemaExternal=prefix+':schema:'+target.schemaOid;
  const rows=[{id:schemaId,type:'schema',name:namespace,external:schemaExternal,parent:null,metadata:{oid:target.schemaOid,provenance:'source-observed'}},
   {id:tableId,type:'table',name:'observations',external:tableExternal,parent:schemaExternal,metadata:{oid:target.relationOid,relationKind:'r',schema:namespace,table:'observations',provenance:'source-observed'}},
   {id:columnId,type:'column',name:'value',external:tableExternal+':column:'+target.attributeNumber,parent:tableExternal,metadata:{dataType:'integer',ordinalPosition:target.attributeNumber,nullable:true,provenance:'source-observed'}}];
  for(const r of rows){
   const row=(await owner.query('INSERT INTO assets(tenant_id,id,source_id,external_id,name,qualified_name,type,parent_external_id,metadata,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,clock_timestamp()) RETURNING *',
    [tenant,r.id,sourceId,r.external,r.name,namespace+'.'+r.type,r.type,r.parent,JSON.stringify(r.metadata)])).rows[0];
   await owner.query('INSERT INTO asset_revisions(tenant_id,asset_id,version,snapshot) VALUES($1,$2,1,$3::jsonb)',[tenant,r.id,JSON.stringify(assetView(row))]);
  }
  await owner.query('COMMIT');
 }catch(error){await owner.query('ROLLBACK');throw error;}
 const principal=(id=actor):Principal=>({id,tenantId:tenant,name:'Synthetic quality participant',permissions});
 const as=<T>(work:(tx:Tx)=>Promise<T>,id:string=actor,scope:string=tenant)=>database.transaction().execute(async tx=>{
  await sql`select set_config('gc.tenant_id',${scope},true),set_config('gc.actor_id',${id},true)`.execute(tx);
  await configureRelationTransaction(tx);return work(tx);
 });
 const site=<T>(work:(tx:Tx)=>Promise<T>)=>as(work,'site:local');
 const ownerTx=async<T>(work:()=>Promise<T>)=>{await owner.query('BEGIN');try{
  await owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[tenant,actor]);const result=await work();await owner.query('COMMIT');return result;
 }catch(error){await owner.query('ROLLBACK');throw error;}};
 const definition=(threshold=0):CompletenessRuleDefinition=>({formatVersion:1,kind:'completeness',target:{tableAssetId:tableId,columnAssetId:columnId},
  name:'Synthetic exact completeness',purpose:'Count SQL NULL values within the current source role scope.',ownerId:steward,severity:'warning',maximumNullBasisPoints:threshold});
 const publish=(value=definition(),id:string=randomUUID(),expectedVersion=0,key=randomUUID())=>as(tx=>publishQualityRule(tx,principal(),{id,expectedVersion,definition:value},key,'quality-native'));
 const request=(rule:QualityRuleView,id=randomUUID(),key=randomUUID())=>as(tx=>requestQualityRun(tx,principal(),rule.id,{id,ruleVersion:rule.version,ruleHash:rule.definitionHash},key,'quality-native'));
 const claim=(id:string,claimId:string=randomUUID())=>site(tx=>claimQualityRun(tx,id,{claimId}));
 const finish=(id:string,c:Extract<QualityClaim,{status:'claimed'}>,value:CompletenessMeasurement=measurement())=>site(tx=>finishQualityRun(tx,id,{claimId:c.claimId,attempt:c.attempt,measurement:value})) as Promise<{run:QualityColumnRunView}>;
 const state=()=>ownerTx(async()=>{
  const result:Record<string,unknown[]>={};for(const name of snapshotTables){const rows=(await owner.query('SELECT * FROM public."'+name+'" WHERE tenant_id=$1',[tenant])).rows;
   result[name]=rows.sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));}return result;
 });
 const unchanged=async(work:()=>Promise<unknown>,predicate:(e:unknown)=>boolean)=>{const before=await state();await assert.rejects(work,predicate);assert.deepEqual(await state(),before,'Refusal leaves canonical tables, revisions, journal, outbox and idempotency unchanged');};
 const restrict=(id:string,allowed:string[])=>ownerTx(()=>owner.query("UPDATE assets SET visibility='restricted',allowed_identities=$3::jsonb WHERE tenant_id=$1 AND id=$2",[tenant,id,JSON.stringify(allowed)]));
 const open=(id:string)=>ownerTx(()=>owner.query("UPDATE assets SET visibility='tenant',allowed_identities='[]'::jsonb WHERE tenant_id=$1 AND id=$2",[tenant,id]));
 const revoke=(id:string,remaining:string[])=>ownerTx(()=>owner.query('UPDATE memberships SET permissions=$3::jsonb WHERE tenant_id=$1 AND identity_id=$2',[tenant,id,JSON.stringify(remaining)]));
 return {owner,tenant,actor,steward,reader,sourceId,schemaId,tableId,columnId,target:target!,principal,as,site,ownerTx,definition,publish,request,claim,finish,state,unchanged,restrict,open,revoke};
}

test('native quality stores protected tenant-scoped rules and runs; runtime DML and reserved namespace fabrication refuse',async t=>{
 const f=await fixture(t),{rule}=await f.publish(),{run}=await f.request(rule),foreign=randomUUID();
 const schema=await f.owner.query("SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity,has_table_privilege('gc_app',c.oid,'SELECT') AS can_read,has_table_privilege('gc_app',c.oid,'INSERT,UPDATE,DELETE,TRUNCATE') AS can_write FROM pg_class c WHERE c.oid=ANY($1::regclass[]) ORDER BY c.relname",[protectedTables.map(n=>'public.'+n)]);
 assert.equal(schema.rows.length,3);for(const row of schema.rows){assert.equal(row.relrowsecurity,true);assert.equal(row.relforcerowsecurity,true);assert.equal(row.can_read,true);assert.equal(row.can_write,false);}
 for(const name of protectedTables){
  assert.equal((await f.as(tx=>sql`select * from ${sql.table(name)}`.execute(tx),f.actor,foreign)).rows.length,0);
  await f.unchanged(()=>f.as(tx=>sql`insert into ${sql.table(name)} select * from ${sql.table(name)} where tenant_id=${f.tenant}::uuid`.execute(tx)),stateCode('42501'));
  await f.unchanged(()=>f.as(tx=>sql`delete from ${sql.table(name)} where tenant_id=${f.tenant}::uuid`.execute(tx)),stateCode('42501'));
 }
 await f.unchanged(()=>f.as(tx=>sql`update public.quality_runs set version=version+1 where tenant_id=${f.tenant}::uuid and id=${run.id}::uuid`.execute(tx)),stateCode('42501'));
 await f.unchanged(()=>f.as(tx=>sql`insert into public.idempotency(tenant_id,actor_id,operation,key,request_hash,response) values(${f.tenant}::uuid,${f.actor},'quality.run.request','fabricated-key',${'0'.repeat(64)},'{}'::jsonb)`.execute(tx)),stateCode('42501'));
 await f.unchanged(()=>f.as(tx=>sql`insert into public.outbox(tenant_id,id,event_type,resource_id,resource_version,payload) values(${f.tenant}::uuid,${randomUUID()}::uuid,'quality.run_finished',${f.columnId},1,'{}'::jsonb)`.execute(tx)),stateCode('42501'));
 await f.unchanged(()=>f.as(tx=>sql`select public.gc_quality_terminal(${run.id}::uuid,'QUALITY_SOURCE_FAILED')`.execute(tx)),stateCode('42501'));
});

test('native quality exact rule versions retain old FAIL and new PASS with paired immutable journals',async t=>{
 const f=await fixture(t),key=randomUUID(),id=randomUUID(),first=await f.publish(f.definition(),id,0,key),before=await f.state();
 assert.deepEqual(await f.publish(f.definition(),id,0,key),first);assert.deepEqual(await f.state(),before);
 const requested=await f.request(first.rule),c=await f.claim(requested.run.id);claimed(c);
 assert.deepEqual(c.execution.target,{databaseOid:f.target.databaseOid,schemaOid:f.target.schemaOid,relationOid:f.target.relationOid,attributeNumber:f.target.attributeNumber,
  schemaName:c.source.schema,tableName:'observations',columnName:'value',dataType:'integer'});
 assert.equal(c.source.secretRef,'synthetic-quality-unused');assert.equal(c.attempt,1);
 const failedThreshold=await f.finish(requested.run.id,c);assert.equal(failedThreshold.run.status,'succeeded');assert.equal(failedThreshold.run.verdict,'FAIL');
 assert.deepEqual(failedThreshold.run.measurement?.rowCount,20);assert.equal(failedThreshold.run.measurement?.nullCount,5);
 const next=await f.publish(f.definition(3000),id,1);assert.equal(next.rule.version,2);assert.notEqual(next.rule.definitionHash,first.rule.definitionHash);
 await f.unchanged(()=>f.request(first.rule),stateCode('40001'));
 const requested2=await f.request(next.rule),c2=await f.claim(requested2.run.id);claimed(c2);assert.equal((await f.finish(requested2.run.id,c2)).run.verdict,'PASS');
 const historical=await f.as(tx=>getQualityRule(tx,f.principal(),id,1));assert.equal(historical.version,1);assert.equal(historical.currentVersion,2);assert.equal(historical.definitionHash,first.rule.definitionHash);
 const oldRun=await f.as(tx=>getQualityRun(tx,f.principal(),requested.run.id));assert.equal(oldRun.ruleVersion,1);assert.equal(oldRun.verdict,'FAIL');
 assert.equal((await f.as(tx=>listQualityRuns(tx,f.principal(),id))).items.length,2);
 const snapshot=await f.state(),audit=snapshot.audit as Array<{id:string;action:string}>,outbox=snapshot.outbox as Array<{id:string;event_type:string}>;
 assert.equal(audit.length,8);assert.equal(outbox.length,8);assert.deepEqual(audit.map(a=>a.id).sort(),outbox.map(a=>a.id).sort());
 assert.ok(audit.every(a=>a.action.startsWith('quality.')));assert.equal(snapshot.quality_rule_versions.length,2);
});

test('native quality zero rows yields NO_DATA without inventing PASS',async t=>{
 const f=await fixture(t),{rule}=await f.publish(),{run}=await f.request(rule),c=await f.claim(run.id);claimed(c);
 const done=await f.finish(run.id,c,measurement(0,0));assert.equal(done.run.status,'succeeded');assert.equal(done.run.verdict,'NO_DATA');assert.equal(done.run.measurement?.nullCount,0);
});

test('native quality requires current active owner and current requester permissions despite stale principal data',async t=>{
 const f=await fixture(t);
 await f.unchanged(()=>f.publish({...f.definition(),ownerId:randomUUID()}),stateCode('42501'));
 await f.ownerTx(()=>f.owner.query('UPDATE identities SET active=false WHERE id=$1',[f.steward]));
 await f.unchanged(()=>f.publish(),stateCode('42501'));
 await f.ownerTx(()=>f.owner.query('UPDATE identities SET active=true WHERE id=$1',[f.steward]));
 await f.revoke(f.actor,['catalog:read','quality:read']);
 await f.unchanged(()=>f.publish(),status(403));
 await f.unchanged(()=>f.as(tx=>publishQualityRule(tx,f.principal(f.reader),{id:randomUUID(),expectedVersion:0,definition:f.definition()},randomUUID(),'quality-native'),f.reader),status(403));
});

test('native quality checks column and both parent ACLs before create, read, request and successful replay',async t=>{
 const f=await fixture(t),key=randomUUID(),id=randomUUID(),{rule}=await f.publish(f.definition(),id,0,key),{run}=await f.request(rule);
 for(const hidden of [f.columnId,f.tableId,f.schemaId]){
  await f.restrict(hidden,[f.steward]);
  await f.unchanged(()=>f.publish(),stateCode('P0002'));
  await f.unchanged(()=>f.publish(f.definition(),id,0,key),stateCode('P0002'));
  await f.unchanged(()=>f.request(rule),stateCode('P0002'));
  await f.unchanged(()=>f.as(tx=>getQualityRule(tx,f.principal(),rule.id)),status(404));
  await f.unchanged(()=>f.as(tx=>getQualityRun(tx,f.principal(),run.id)),status(404));
  await f.open(hidden);
 }
 assert.equal((await f.as(tx=>getQualityAsset(tx,f.principal(),f.columnId))).eligibility.supported,true);
 await f.revoke(f.actor,['catalog:read']);await f.unchanged(()=>f.as(tx=>getQualityRun(tx,f.principal(),run.id)),status(403));
});

test('native quality hidden rule identity remains unavailable when publication substitutes a visible column',async t=>{
 const f=await fixture(t),{rule}=await f.publish(),otherId=randomUUID();
 await f.ownerTx(async()=>{
  const src=(await f.owner.query('SELECT schema_name FROM sources WHERE tenant_id=$1 AND id=$2',[f.tenant,f.sourceId])).rows[0];
  assert.match(src.schema_name,/^quality_[a-f0-9]{32}$/);
  await f.owner.query('ALTER TABLE "'+src.schema_name+'".observations ADD COLUMN alternate integer');
  const row=(await f.owner.query(`INSERT INTO assets(tenant_id,id,source_id,external_id,name,qualified_name,type,parent_external_id,metadata,observed_at)
   SELECT tenant_id,$3,source_id,parent_external_id||':column:2','alternate',qualified_name||'.alternate',type,parent_external_id,
    jsonb_set(metadata,'{ordinalPosition}','2'::jsonb),clock_timestamp() FROM assets WHERE tenant_id=$1 AND id=$2 RETURNING *`,[f.tenant,f.columnId,otherId])).rows[0];
  await f.owner.query('INSERT INTO asset_revisions(tenant_id,asset_id,version,snapshot) VALUES($1,$2,1,$3::jsonb)',[f.tenant,otherId,JSON.stringify(assetView(row))]);
 });
 const replacement={...f.definition(),target:{tableAssetId:f.tableId,columnAssetId:otherId}};
 assert.equal((await f.as(tx=>getQualityAsset(tx,f.principal(),otherId))).eligibility.supported,true);
 await f.restrict(f.columnId,[f.steward]);
 for(const version of [0,1,99])await f.unchanged(()=>f.publish(replacement,rule.id,version),stateCode('P0002'));
 await f.unchanged(()=>f.publish(replacement,randomUUID(),1),stateCode('P0002'));
 await f.open(f.columnId);
 await f.unchanged(()=>f.publish(replacement,rule.id,1),stateCode('40001'));
});

test('native quality foreign tenants cannot discover or mutate rule/run identifiers',async t=>{
 const a=await fixture(t),b=await fixture(t),{rule}=await a.publish(),{run}=await a.request(rule),before=await a.state();
 await b.unchanged(()=>b.as(tx=>getQualityRule(tx,b.principal(),rule.id)),status(404));
 await b.unchanged(()=>b.as(tx=>getQualityRun(tx,b.principal(),run.id)),status(404));
 await b.unchanged(()=>b.request(rule),stateCode('P0002'));
 await b.unchanged(()=>b.claim(run.id),stateCode('P0002'));
 assert.deepEqual(await a.state(),before);
});

test('native quality claim rechecks permission and parent ACL revocation and becomes canonically cancelled',async t=>{
 for(const revoke of ['permission','acl'] as const){
  const f=await fixture(t),{rule}=await f.publish(),{run}=await f.request(rule);
  if(revoke==='permission')await f.revoke(f.actor,['catalog:read','quality:read']);else await f.restrict(f.schemaId,[f.steward]);
  const c=await f.claim(run.id);assert.equal(c.status,'terminal');if(c.status!=='terminal')throw new Error('Expected terminal quality run.');
  assert.equal(c.run.status,'cancelled');assert.equal(c.run.errorCode,'QUALITY_AUTHORITY_REVOKED');assert.equal(c.run.attempt,0);assert.equal(c.run.measurement,null);
 }
});

test('native quality completion rechecks current ACL and never retains a result after revocation',async t=>{
 const f=await fixture(t),{rule}=await f.publish(),{run}=await f.request(rule),c=await f.claim(run.id);claimed(c);
 await f.restrict(f.columnId,[f.steward]);const done=await f.finish(run.id,c);
 assert.equal(done.run.status,'cancelled');assert.equal(done.run.errorCode,'QUALITY_AUTHORITY_REVOKED');assert.equal(done.run.measurement,null);assert.equal(done.run.verdict,null);
 await f.unchanged(()=>f.finish(run.id,c),stateCode('42501'));
});

test('native quality changed source or asset pins invalidate queued and in-flight work',async t=>{
 for(const phase of ['claim','finish'] as const)for(const target of ['source','column'] as const){
  const f=await fixture(t),{rule}=await f.publish(),{run}=await f.request(rule),c=phase==='finish'?await f.claim(run.id):null;
  if(c)claimed(c);
  if(target==='source')await f.ownerTx(()=>f.owner.query('UPDATE sources SET version=version+1 WHERE tenant_id=$1 AND id=$2',[f.tenant,f.sourceId]));
  else await f.ownerTx(async()=>{const row=(await f.owner.query('UPDATE assets SET version=version+1 WHERE tenant_id=$1 AND id=$2 RETURNING *',[f.tenant,f.columnId])).rows[0];
   await f.owner.query('INSERT INTO asset_revisions(tenant_id,asset_id,version,snapshot) VALUES($1,$2,$3,$4::jsonb)',[f.tenant,f.columnId,row.version,JSON.stringify(assetView(row))]);});
  const done=c?(await f.finish(run.id,c)).run:await f.claim(run.id).then(v=>{assert.equal(v.status,'terminal');if(v.status!=='terminal')throw new Error('Expected terminal quality run.');return v.run;});
  assert.equal(done.status,'failed');assert.equal(done.errorCode,'QUALITY_TARGET_STALE');assert.equal(done.measurement,null);
 }
});

test('native quality site-only claims fence concurrent claim IDs and exact completion replay',async t=>{
 const f=await fixture(t),{rule}=await f.publish(),{run}=await f.request(rule);
 await f.unchanged(()=>f.as(tx=>claimQualityRun(tx,run.id,{claimId:randomUUID()})),stateCode('42501'));
 const c=await f.claim(run.id);claimed(c);const afterClaim=await f.state();assert.deepEqual(await f.claim(run.id,c.claimId),c);assert.deepEqual(await f.state(),afterClaim);
 const busy=await f.claim(run.id);assert.equal(busy.status,'busy');assert.deepEqual(await f.state(),afterClaim);
 await f.unchanged(()=>f.site(tx=>finishQualityRun(tx,run.id,{claimId:randomUUID(),attempt:c.attempt,measurement:measurement()})),stateCode('40001'));
 const value=measurement(),first=await f.finish(run.id,c,value),after=await f.state();assert.deepEqual(await f.finish(run.id,c,value),first);assert.deepEqual(await f.state(),after);
 await f.unchanged(()=>f.finish(run.id,c,{...value,nullCount:4}),stateCode('40001'));
 await f.unchanged(()=>f.as(tx=>finishQualityRun(tx,run.id,{claimId:c.claimId,attempt:c.attempt,measurement:value})),stateCode('42501'));
});

test('native quality cancellation wins over a late worker and preserves its canonical result',async t=>{
 const f=await fixture(t),{rule}=await f.publish(),{run}=await f.request(rule),c=await f.claim(run.id);claimed(c);
 const current=await f.as(tx=>getQualityRun(tx,f.principal(),run.id));
 const cancelled=await f.as(tx=>cancelQualityRun(tx,f.principal(),run.id,{expectedVersion:current.version,reason:'Synthetic cancellation.'},randomUUID(),'quality-native'));
 assert.equal(cancelled.run.status,'cancelled');assert.equal(cancelled.run.errorCode,'QUALITY_CANCELLED');
 await f.unchanged(()=>f.finish(run.id,c),stateCode('40001'));const final=await f.claim(run.id);assert.equal(final.status,'terminal');
});

test('native quality source failures retain only closed errors and paired terminal journals',async t=>{
 const f=await fixture(t),{rule}=await f.publish();
 for(const errorCode of ['QUALITY_RESOURCE_LIMIT','QUALITY_TARGET_STALE','QUALITY_TARGET_UNSUPPORTED','QUALITY_SOURCE_FAILED','QUALITY_DEADLINE_EXCEEDED'] as const){
  const {run}=await f.request(rule),c=await f.claim(run.id);claimed(c);
  const done=await f.site(tx=>finishQualityRun(tx,run.id,{claimId:c.claimId,attempt:c.attempt,errorCode}));
  assert.equal(done.run.status,'failed');assert.equal(done.run.errorCode,errorCode);assert.equal(done.run.measurement,null);assert.equal(done.run.verdict,null);
 }
 const state=await f.state(),finished=(state.audit as Array<{action:string}>).filter(a=>a.action==='quality.run_finished');assert.equal(finished.length,5);
});

test('native quality SQL validates exact measurement bounds and observation freshness without partial effects',async t=>{
 const f=await fixture(t),{rule}=await f.publish(),{run}=await f.request(rule),c=await f.claim(run.id);claimed(c);const base=measurement();
 for(const changed of [{rowCount:100001},{nullCount:21},{estimatedBytes:0.5},{estimatedCost:1000001},{sourceVersion:'17.6'},
  {elapsedMs:30001},{privateRow:'must not persist'},{observedStartedAt:'2000-01-01T00:00:00.000Z',observedFinishedAt:'2000-01-01T00:00:00.000Z'}]){
  await f.unchanged(()=>f.site(tx=>sql`select public.gc_quality_finish(${run.id}::uuid,${JSON.stringify({claimId:c.claimId,attempt:c.attempt,measurement:{...base,...changed}})}::jsonb)`.execute(tx)),stateCode('22023'));
 }
 await f.unchanged(()=>f.site(tx=>sql`select public.gc_quality_finish(${run.id}::uuid,${JSON.stringify({claimId:c.claimId,attempt:0,measurement:base})}::jsonb)`.execute(tx)),stateCode('22023'));
 assert.equal((await f.finish(run.id,c)).run.status,'succeeded');
});

test('native quality command and completion journals roll back atomically with the transaction',async t=>{
 const f=await fixture(t);
 await f.unchanged(()=>f.as(async tx=>{await publishQualityRule(tx,f.principal(),{id:randomUUID(),expectedVersion:0,definition:f.definition()},randomUUID(),'quality-native');await sql`select 1/0`.execute(tx);}),stateCode('22012'));
 const {rule}=await f.publish(),{run}=await f.request(rule),c=await f.claim(run.id);claimed(c);
 await f.unchanged(()=>f.site(async tx=>{await finishQualityRun(tx,run.id,{claimId:c.claimId,attempt:c.attempt,measurement:measurement()});await sql`select 1/0`.execute(tx);}),stateCode('22012'));
 assert.equal((await f.as(tx=>getQualityRun(tx,f.principal(),run.id))).status,'running');
});
