// SPDX-License-Identifier: Apache-2.0
/** Real API/storage tests with synthetic legacy sessions and controlled worker
 * observations. These cases do not authenticate with or extract from Databricks. */
import assert from 'node:assert/strict';
import {createHash, randomUUID} from 'node:crypto';
import {after, before, test, type TestContext} from 'node:test';
import {db, scope, sql} from '../../packages/db/src/index.ts';
import {pacedFetch as fetch} from '../fixtures/http-budget.ts';
import {createManualScanFixture} from '../fixtures/manual-scan.ts';

const tenant='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',foreign='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const steward='10000000-0000-4000-8000-000000000001',consumer='10000000-0000-4000-8000-000000000003',summit='10000000-0000-4000-8000-000000000005';
const base=process.env.TEST_BASE_URL??'http://api:4310',origin=process.env.PUBLIC_URL??'http://localhost:4310';
type Headers=Record<string,string>;
type Source={id:string;name:string;connectorId:string;workspaceUrl:string;catalog:string;schema:string;secretRef:string};
type Job={id:string;sourceId:string;status:string;assetCount:number|null;errorCode:string|null};
const input=()=>({connectorId:'unity-catalog' as const,name:'000-uc-'+randomUUID(),workspaceUrl:'https://adb-123.1.azuredatabricks.net',catalog:'harbor',schema:'commerce',secretRef:'synthetic-uc-reader'});
const scoped=<T>(fn:Parameters<typeof scope<T>>[2])=>scope(tenant,steward,fn);
const request=(path:string,headers:Headers,method='GET',body?:unknown)=>fetch(base+'/api/v1'+path,{method,headers,body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(15_000)});
async function response<T>(result:Response,status:number):Promise<T>{const body=await result.text();assert.equal(result.status,status,'Unexpected real API status');return JSON.parse(body) as T;}
async function session(t:TestContext,identity=steward,organization=tenant):Promise<Headers>{
 const raw=randomUUID()+randomUUID(),csrf=randomUUID(),hash=createHash('sha256').update(raw).digest('hex');
 await db.insertInto('sessions').values({id_hash:hash,identity_id:identity,tenant_id:organization,csrf,expires_at:new Date(Date.now()+300_000)}).execute();
 t.after(async()=>{await db.deleteFrom('sessions').where('id_hash','=',hash).execute();});
 return {Cookie:'gc_session='+raw,'X-CSRF-Token':csrf,Origin:origin,'Content-Type':'application/json'};
}
async function create(t:TestContext){const headers=await session(t),body=input(),key=randomUUID();const result=await response<{source:Source}>(await request('/sources',{...headers,'Idempotency-Key':key},'POST',body),201);return {headers,body,key,source:result.source};}
// Delivery status is owned by the live projector. Compare the complete immutable
// event body, excluding only attempts/processed_at that legitimately change.
const outboxFields=['tenant_id','id','event_type','resource_id','resource_version','payload','created_at'] as const;
async function assetsSnapshot(sourceId:string){return scoped(async tx=>{
 const assets=await tx.selectFrom('assets').selectAll().where('source_id','=',sourceId).orderBy('id').execute(),ids=assets.map(a=>a.id);
 return {assets,revisions:ids.length?await tx.selectFrom('asset_revisions').selectAll().where('asset_id','in',ids).orderBy('asset_id').orderBy('version').execute():[],
  audit:ids.length?await tx.selectFrom('audit').selectAll().where('resource_id','in',ids).orderBy('id').execute():[],
  outbox:ids.length?await tx.selectFrom('outbox').select([...outboxFields]).where('resource_id','in',ids).orderBy('id').execute():[]};
});}
async function journal(resourceId:string){return scoped(async tx=>({audit:await tx.selectFrom('audit').selectAll().where('resource_id','=',resourceId).orderBy('id').execute(),outbox:await tx.selectFrom('outbox').select([...outboxFields]).where('resource_id','=',resourceId).orderBy('id').execute()}));}
before(async()=>{
 assert.ok(process.env.DATABASE_URL,'Real runtime database is required');
 const role=await sql<{name:string;superuser:boolean;bypass:boolean}>`SELECT current_user name,rolsuper superuser,rolbypassrls bypass FROM pg_roles WHERE rolname=current_user`.execute(db);
 assert.deepEqual(role.rows,[{name:'gc_app',superuser:false,bypass:false}]);
 const migration=await db.selectFrom('schema_migrations').select('name').where('name','=','014_source_connectors.sql').executeTakeFirst();assert.ok(migration,'SQL014 must be applied before this gate');
});
after(async()=>{await db.destroy();});

test('UC registration binds exact configuration and replay atomically without accepting credential values',async t=>{
 const f=await create(t);assert.equal(f.source.connectorId,'unity-catalog');
 for(const field of ['name','workspaceUrl','catalog','schema','secretRef'] as const)assert.equal(f.source[field],f.body[field]);
 for(const field of ['host','port','database','password','token','clientSecret','credentials'])assert.equal(Object.hasOwn(f.source,field),false);
 const replay=await response<{source:Source}>(await request('/sources',{...f.headers,'Idempotency-Key':f.key},'POST',f.body),200);assert.deepEqual(replay.source,f.source);
 assert.equal((await response<{code:string}>(await request('/sources',{...f.headers,'Idempotency-Key':f.key},'POST',{...f.body,catalog:'different'}),409)).code,'IDEMPOTENCY_CONFLICT');
 const stored=await scoped(tx=>tx.selectFrom('sources').selectAll().where('id','=',f.source.id).executeTakeFirstOrThrow());
 assert.equal(stored.tenant_id,tenant);assert.equal(stored.connector_id,'unity-catalog');assert.equal(stored.host,'adb-123.1.azuredatabricks.net');assert.equal(stored.port,443);assert.equal(stored.database_name,'harbor');assert.equal(stored.schema_name,'commerce');assert.equal(stored.secret_ref,f.body.secretRef);
 const events=await journal(f.source.id);assert.equal(events.audit.length,1);assert.equal(events.outbox.length,1);assert.equal(events.audit[0]!.action,'source.created');assert.equal(events.outbox[0]!.event_type,'source.created');assert.equal(events.audit[0]!.id,events.outbox[0]!.id);
 const receipts=await scoped(tx=>tx.selectFrom('idempotency').selectAll().where('actor_id','=',steward).where('operation','=','source.create').where('key','=',f.key).execute());assert.equal(receipts.length,1);assert.equal(receipts[0]!.response.source.id,f.source.id);
 const canary='SYNTHETIC_NEVER_A_CREDENTIAL_'+randomUUID(),keys:string[]=[];
 for(const extra of [{password:canary},{token:canary},{clientSecret:canary},{credentials:{value:canary}},{tenantId:foreign}]){
  const key=randomUUID();keys.push(key);const rejected=await request('/sources',{...f.headers,'Idempotency-Key':key},'POST',{...f.body,...extra});const text=await rejected.text();assert.equal(rejected.status,400);assert.equal(text.includes(canary),false);
 }
 assert.equal((await scoped(tx=>tx.selectFrom('sources').select('id').where('name','=',f.body.name).execute())).length,1);
 assert.equal((await scoped(tx=>tx.selectFrom('idempotency').select('key').where('key','in',keys).execute())).length,0);assert.deepEqual(await journal(f.source.id),events);
});

test('UC registration and scan boundaries reject read-only and foreign-tenant callers without creating jobs',async t=>{
 const f=await create(t),readOnly=await session(t,consumer),outside=await session(t,summit,foreign);
 const denied=await response<{code:string}>(await request('/sources',{...readOnly,'Idempotency-Key':randomUUID()},'POST',input()),403);assert.equal(denied.code,'FORBIDDEN');
 assert.equal((await response<{code:string}>(await request('/sources',readOnly),403)).code,'FORBIDDEN');
 assert.equal((await response<{code:string}>(await request('/sources/'+f.source.id+'/scans',{...readOnly,'Idempotency-Key':randomUUID()},'POST',{}),403)).code,'FORBIDDEN');
 assert.equal((await response<{code:string}>(await request('/sources/'+f.source.id+'/scans',{...outside,'Idempotency-Key':randomUUID()},'POST',{}),404)).code,'SOURCE_NOT_FOUND');
 const own=await response<{items:Source[]}>(await request('/sources?q='+encodeURIComponent(f.body.name),f.headers),200);assert.ok(own.items.some(s=>s.id===f.source.id));
 const other=await response<{items:Source[]}>(await request('/sources?q='+encodeURIComponent(f.body.name),outside),200);assert.ok(!other.items.some(s=>s.id===f.source.id));
 assert.equal((await scoped(tx=>tx.selectFrom('jobs').select('id').where('source_id','=',f.source.id).execute())).length,0);
 assert.deepEqual(await scope(foreign,summit,tx=>tx.selectFrom('sources').select('id').where('id','=',f.source.id).execute()),[]);
});

test('real UC completion persists canonical history and events while reduced, invalid and failed scans preserve assets',async t=>{
 assert.ok(process.env.SITE_TOKEN,'Controlled completions require the real internal-site credential');
 const f=await create(t),workerHeaders={Authorization:'Bearer '+process.env.SITE_TOKEN,'X-Tenant-Id':tenant,'Content-Type':'application/json'};
 const {job}=await createManualScanFixture(t,{tenantId:tenant,sourceId:f.source.id,actorId:steward,fetch});
 const rows=[{externalId:'synthetic-uc-orders',name:'Orders',qualifiedName:'harbor.commerce.orders',type:'table',metadata:{tableId:randomUUID()}},{externalId:'synthetic-uc-customers',name:'Customers',qualifiedName:'harbor.commerce.customers',type:'table',metadata:{tableId:randomUUID()}}];
 const complete=(id:string,records:typeof rows)=>fetch(base+'/internal/jobs/'+id+'/complete',{method:'POST',headers:workerHeaders,body:JSON.stringify({observedAt:new Date().toISOString(),sourceVersion:'synthetic-uc-real-handler',permissionFingerprint:'unchanged-uc-principal',complete:true,records}),signal:AbortSignal.timeout(15_000)});
 const fail=(id:string,code:string)=>fetch(base+'/internal/jobs/'+id+'/fail',{method:'POST',headers:workerHeaders,body:JSON.stringify({code}),signal:AbortSignal.timeout(15_000)});
 const firstJob=await job(),first=await response<{job:Job}>(await complete(firstJob,rows),200);assert.equal(first.job.status,'succeeded');assert.equal(first.job.assetCount,2);
 const initial=await assetsSnapshot(f.source.id);assert.equal(initial.assets.length,2);assert.equal(initial.revisions.length,2);assert.equal(initial.audit.length,2);assert.equal(initial.outbox.length,2);
 for(const row of initial.assets){assert.equal(row.status,'active');assert.equal(row.version,1);assert.equal(row.metadata.provenance,'source-observed');assert.equal(row.metadata.scanId,firstJob);assert.equal(row.metadata.sourceVersion,'synthetic-uc-real-handler');const revision=initial.revisions.find(r=>r.asset_id===row.id);assert.ok(revision);assert.equal(revision.snapshot.id,row.id);assert.equal(revision.snapshot.metadata.tableId,row.metadata.tableId);const audit=initial.audit.find(a=>a.resource_id===row.id);assert.ok(audit);assert.equal(audit.action,'asset.observed');assert.equal(audit.changes.scanId,firstJob);assert.ok(initial.outbox.some(o=>o.id===audit.id&&o.event_type==='asset.observed'&&o.resource_version===row.version));}
 const completed=await journal(firstJob);assert.equal(completed.audit.length,1);assert.equal(completed.audit[0]!.action,'scan.completed');assert.equal(completed.outbox.length,1);assert.equal(completed.outbox[0]!.id,completed.audit[0]!.id);
 const omitted=initial.assets.find(a=>a.external_id===rows[1]!.externalId)!;
 // Deliberately omit absenceReconciliation: UC cannot gain deletion authority
 // from this caller, even with the same permission fingerprint as the first scan.
 const renamed=[{...rows[0]!,name:'Orders renamed',qualifiedName:'harbor.commerce.orders_renamed'}];
 for(const observations of [renamed,renamed,[]]){const result=await response<{job:Job}>(await complete(await job(),observations),200);assert.equal(result.job.status,'succeeded');assert.equal(result.job.assetCount,observations.length);const current=await assetsSnapshot(f.source.id);assert.equal(current.assets.length,2);assert.deepEqual(current.assets.find(a=>a.id===omitted.id),omitted);assert.ok(current.assets.every(a=>a.status==='active'));assert.ok(current.audit.every(a=>a.action!=='asset.unavailable'));}
 const before=await assetsSnapshot(f.source.id),changed=before.assets.find(a=>a.external_id===rows[0]!.externalId)!;assert.equal(changed.id,initial.assets.find(a=>a.external_id===rows[0]!.externalId)!.id);assert.equal(changed.version,3);assert.ok(changed.metadata.aliases.includes(rows[0]!.qualifiedName));
 const sourceState=()=>scoped(tx=>tx.selectFrom('sources').selectAll().where('id','=',f.source.id).executeTakeFirstOrThrow()),successfulSource=await sourceState();assert.equal(successfulSource.status,'healthy');assert.ok(successfulSource.last_successful_scan);
 const invalid=await job();assert.equal((await response<{code:string}>(await complete(invalid,[{...rows[0]!,name:'Must roll back'},rows[0]!]),422)).code,'DUPLICATE_SOURCE_ID');assert.deepEqual(await assetsSnapshot(f.source.id),before);assert.deepEqual(await journal(invalid),{audit:[],outbox:[]});
 const failed=await response<{job:Job}>(await fail(invalid,'SYNTHETIC_UC_UNAVAILABLE'),200);assert.equal(failed.job.status,'failed');assert.equal(failed.job.errorCode,'SYNTHETIC_UC_UNAVAILABLE');assert.deepEqual(await assetsSnapshot(f.source.id),before);
 const failedSource=await sourceState();assert.equal(failedSource.status,'failed');assert.deepEqual(failedSource.last_successful_scan,successfulSource.last_successful_scan);assert.equal(failedSource.permission_fingerprint,successfulSource.permission_fingerprint);
 const failedEvents=await journal(invalid);assert.equal(failedEvents.audit.length,1);assert.equal(failedEvents.audit[0]!.action,'scan.failed');assert.equal(failedEvents.outbox.length,1);assert.equal(failedEvents.outbox[0]!.id,failedEvents.audit[0]!.id);
 assert.deepEqual((await response<{job:Job}>(await fail(invalid,'SYNTHETIC_LATE_FAILURE'),200)).job,failed.job);assert.equal((await response<{code:string}>(await complete(invalid,rows),409)).code,'JOB_STATE_CONFLICT');
 assert.deepEqual((await response<{job:Job}>(await complete(firstJob,rows),200)).job,first.job);assert.deepEqual(await assetsSnapshot(f.source.id),before);assert.deepEqual(await journal(invalid),failedEvents);assert.deepEqual(await journal(firstJob),completed);
 assert.deepEqual(await sourceState(),failedSource,'Terminal replays must not falsely restore source health');
 assert.equal((await response<{job:Job}>(await complete(await job(),renamed),200)).job.status,'succeeded');
 const source=await sourceState();assert.equal(source.status,'healthy');assert.equal(source.permission_fingerprint,'unchanged-uc-principal');assert.ok(source.last_successful_scan>successfulSource.last_successful_scan);assert.deepEqual((await assetsSnapshot(f.source.id)).assets.find(a=>a.id===omitted.id),omitted);
});
