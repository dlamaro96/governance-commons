// SPDX-License-Identifier: Apache-2.0
import {createProtectedCoreSession,closeProtectedCoreSessions} from '../fixtures/protected-core-authentication.ts';
/** Real HTTP/PostgreSQL registration boundaries. Registering a destination does
 * not authorize worker network access; the isolated TLS gate tests that policy. */
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {after, before, test, type TestContext} from 'node:test';
import {db, scope, sql} from '../../packages/db/src/index.ts';
import {pacedFetch as fetch} from '../fixtures/http-budget.ts';

const tenant='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', foreign='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const engineer='10000000-0000-4000-8000-000000000006', owner='10000000-0000-4000-8000-000000000002';
const summit='10000000-0000-4000-8000-000000000005';
const base=process.env.TEST_BASE_URL??'http://api:4310', origin=process.env.PUBLIC_URL??'http://localhost:4310';
type Headers=Record<string,string>;
type Configuration={connectorId:'postgresql';name:string;host:string;port:number;database:string;schema:string;secretRef:string};
type Source=Configuration&{id:string;status:string;lastSuccessfulScan:string|null;capabilities:unknown};
const input=():Configuration=>({connectorId:'postgresql',name:'00 PG configuration '+randomUUID(),
  host:'warehouse.example.invalid',port:6432,database:'Analytics archive',schema:'Reporting',secretRef:'missing-pg-'+randomUUID()});
const scoped=<T>(fn:Parameters<typeof scope<T>>[2])=>scope(tenant,engineer,fn);
const request=(path:string,headers:Headers,method='GET',body?:unknown)=>fetch(base+'/api/v1'+path,
  {method,headers,body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(15_000)});
async function body<T>(response:Response,status:number):Promise<T>{
  const text=await response.text();assert.equal(response.status,status,'Unexpected real API status');return JSON.parse(text) as T;
}
async function session(t:TestContext,identity=engineer,organization=tenant):Promise<Headers>{
  const native=await createProtectedCoreSession(identity,organization);t.after(()=>native.revoke());
  const headers=native.headers;
  const me=await body<{user:{id:string};tenant:{id:string};permissions:string[]}>(await request('/me',headers),200);
  assert.equal(me.user.id,identity);assert.equal(me.tenant.id,organization);
  assert.equal(me.permissions.includes('sources:write'),identity!==owner,'Seeded persona authority differs');
  return headers;
}
// The live projector may change delivery bookkeeping, never these event bytes.
const outboxFields=['tenant_id','id','event_type','resource_id','resource_version','payload','created_at'] as const;
async function journal(id:string){return scoped(async tx=>({
  audit:await tx.selectFrom('audit').selectAll().where('resource_id','=',id).orderBy('id').execute(),
  outbox:await tx.selectFrom('outbox').select([...outboxFields]).where('resource_id','=',id).orderBy('id').execute(),
}));}
async function assertRefusedWrites(keys:string[],correlations:string[],name:string){
  await scoped(async tx=>{
    assert.deepEqual(await tx.selectFrom('sources').select('id').where('name','=',name).execute(),[]);
    assert.deepEqual(await tx.selectFrom('idempotency').select('key').where('key','in',keys).execute(),[]);
    assert.deepEqual(await tx.selectFrom('audit').select('id').where('correlation_id','in',correlations).execute(),[]);
    assert.deepEqual((await sql<{id:string}>`SELECT id FROM outbox WHERE payload->>'correlationId'=ANY(${correlations}::text[])`.execute(tx)).rows,[]);
  });
}
before(async()=>{
  assert.ok(process.env.DATABASE_URL,'Real runtime database is required');
  const role=await sql<{name:string;superuser:boolean;bypass:boolean}>`SELECT current_user name,rolsuper superuser,rolbypassrls bypass FROM pg_roles WHERE rolname=current_user`.execute(db);
  assert.deepEqual(role.rows,[{name:'gc_app',superuser:false,bypass:false}]);
  assert.ok(await db.selectFrom('schema_migrations').select('name').where('name','=','014_source_connectors.sql').executeTakeFirst());
});
after(async()=>{await closeProtectedCoreSessions(); await db.destroy();});

test('configurable PostgreSQL registration stores exact scope and one immutable journal/receipt across replay',async t=>{
  const headers=await session(t),configuration=input(),key=randomUUID();
  const created=await request('/sources',{...headers,'Idempotency-Key':key},'POST',configuration);
  const correlation=created.headers.get('x-correlation-id');assert.ok(correlation);
  const {source}=await body<{source:Source}>(created,201);
  for(const field of ['connectorId','name','host','port','database','schema','secretRef'] as const)assert.equal(source[field],configuration[field]);
  assert.equal(source.status,'unconfigured');assert.equal(source.lastSuccessfulScan,null);
  for(const field of ['password','username','token','clientSecret','credentials','tls','allowedCidrs'])assert.equal(Object.hasOwn(source,field),false);
  const stored=await scoped(tx=>tx.selectFrom('sources').selectAll().where('id','=',source.id).executeTakeFirstOrThrow());
  assert.equal(stored.tenant_id,tenant);assert.equal(stored.connector_id,'postgresql');assert.equal(stored.host,configuration.host);
  assert.equal(stored.port,configuration.port);assert.equal(stored.database_name,configuration.database);assert.equal(stored.schema_name,configuration.schema);assert.equal(stored.secret_ref,configuration.secretRef);
  const events=await journal(source.id);assert.equal(events.audit.length,1);assert.equal(events.outbox.length,1);
  assert.equal(events.audit[0]!.action,'source.created');assert.equal(events.audit[0]!.actor_id,engineer);assert.equal(events.audit[0]!.correlation_id,correlation);
  assert.equal(events.outbox[0]!.event_type,'source.created');assert.equal(events.outbox[0]!.id,events.audit[0]!.id);
  assert.equal(events.outbox[0]!.payload.correlationId,correlation);assert.equal(events.outbox[0]!.payload.actorId,engineer);
  for(const field of ['name','connectorId','host','port','database','schema','secretRef'] as const)assert.equal(events.audit[0]!.changes[field],configuration[field]);
  const receipts=()=>scoped(tx=>tx.selectFrom('idempotency').selectAll().where('actor_id','=',engineer).where('operation','=','source.create').where('key','=',key).execute());
  const originalReceipts=await receipts();assert.equal(originalReceipts.length,1);assert.equal(originalReceipts[0]!.response.source.id,source.id);
  assert.deepEqual((await body<{source:Source}>(await request('/sources',{...headers,'Idempotency-Key':key},'POST',configuration),200)).source,source);
  assert.equal((await body<{code:string}>(await request('/sources',{...headers,'Idempotency-Key':key},'POST',{...configuration,port:6433}),409)).code,'IDEMPOTENCY_CONFLICT');
  assert.deepEqual(await receipts(),originalReceipts);assert.deepEqual(await journal(source.id),events);
  assert.deepEqual((await body<{source:Source}>(await request('/sources/'+source.id,headers),200)).source,source);
  assert.deepEqual(await scoped(tx=>tx.selectFrom('jobs').select('id').where('source_id','=',source.id).execute()),[],'Registration must not dispatch a connector');
});

test('configurable PostgreSQL HTTP grammar rejects DSNs, ambiguous hosts, malformed Unicode and credential fields without writes',async t=>{
  const headers=await session(t),configuration=input(),keys:string[]=[],correlations:string[]=[];
  const canary='SYNTHETIC_FIELD_MUST_NOT_BE_ECHOED_'+randomUUID();
  const patches:Record<string,unknown>[]=[
    ...['/tmp/postgresql','pg.example.invalid,other.invalid','pg.example.invalid:5432','PG.example.invalid','pg.example.invalid.',
      '0x7f000001','0x7f.0.0.1','0177.0.0.1','127.1','[2001:db8::1]','fe80::1%eth0','bad\u0000host','bad\ud800host'].map(host=>({host})),
    ...[0,65536,1.5,'5432',true].map(port=>({port})),
    ...['host=elsewhere dbname=x','Postgres://example.invalid/db','POSTGRESQL://example.invalid/db','é'.repeat(32),'bad\u007fdb','bad\udc00db'].map(database=>({database})),
    ...['é'.repeat(32),'bad\nschema','bad\ud800schema'].map(schema=>({schema})),
    ...['../reader','reader/name','reader token','x'.repeat(129)].map(secretRef=>({secretRef})),
    {password:canary},{username:canary},{credentials:{password:canary}},{tls:{mode:'disable'}},{allowedCidrs:['0.0.0.0/0']},
    {tenantId:foreign},{workspaceUrl:'https://synthetic.cloud.databricks.com'},
  ];
  for(const patch of patches){
    const key=randomUUID();keys.push(key);
    const response=await request('/sources',{...headers,'Idempotency-Key':key},'POST',{...configuration,...patch});
    const text=await response.text();assert.equal(response.status,400,'Host/port/scope/credential grammar must fail before persistence');
    const problem=JSON.parse(text) as {code:string;correlationId:string};assert.equal(problem.code,'VALIDATION_FAILED');assert.ok(problem.correlationId);
    assert.equal(text.includes(canary),false);correlations.push(problem.correlationId);
  }
  await assertRefusedWrites(keys,correlations,configuration.name);
});

test('PostgreSQL configuration honors engineer, owner and tenant authority at exact accepted byte/port boundaries',async t=>{
  const headers=await session(t),noWrite=await session(t,owner),outside=await session(t,summit,foreign);
  // Canonical IPv6 and exactly63 UTF-8 bytes are configuration, not an attempted
  // connection to this documentation-only address. Only two sources persist in this file.
  const configuration={...input(),host:'2001:db8::1',port:65535,database:'é'.repeat(31)+'a',schema:'é'.repeat(31)+'b'};
  assert.equal(Buffer.byteLength(configuration.database),63);assert.equal(Buffer.byteLength(configuration.schema),63);
  const {source}=await body<{source:Source}>(await request('/sources',{...headers,'Idempotency-Key':randomUUID()},'POST',configuration),201);
  assert.equal(source.host,configuration.host);assert.equal(source.port,65535);assert.equal(source.database,configuration.database);assert.equal(source.schema,configuration.schema);
  const events=await journal(source.id),forbiddenName='00 PG forbidden '+randomUUID(),keys:string[]=[],correlations:string[]=[];
  const attempts:[Headers,string,string,unknown,number,string][]=[
    [noWrite,'/sources','POST',{...input(),name:forbiddenName},403,'FORBIDDEN'],
    [noWrite,'/sources/'+source.id,'GET',undefined,403,'FORBIDDEN'],
    [noWrite,'/sources/'+source.id+'/scans','POST',{},403,'FORBIDDEN'],
    [outside,'/sources/'+source.id,'GET',undefined,404,'SOURCE_NOT_FOUND'],
    [outside,'/sources/'+source.id+'/scans','POST',{},404,'SOURCE_NOT_FOUND'],
  ];
  for(const [actor,path,method,payload,status,code] of attempts){
    const key=randomUUID();keys.push(key);
    const response=await request(path,{...actor,'Idempotency-Key':key},method,payload);
    const problem=await body<{code:string;correlationId:string}>(response,status);assert.equal(problem.code,code);assert.ok(problem.correlationId);correlations.push(problem.correlationId);
  }
  await assertRefusedWrites(keys,correlations,forbiddenName);
  await scope(foreign,summit,async tx=>{
    assert.deepEqual(await tx.selectFrom('sources').select('id').where('id','=',source.id).execute(),[]);
    assert.deepEqual(await tx.selectFrom('idempotency').select('key').where('key','in',keys).execute(),[]);
    assert.deepEqual(await tx.selectFrom('audit').select('id').where('correlation_id','in',correlations).execute(),[]);
    assert.deepEqual((await sql<{id:string}>`SELECT id FROM outbox WHERE payload->>'correlationId'=ANY(${correlations}::text[])`.execute(tx)).rows,[]);
  });
  assert.deepEqual((await body<{items:Source[]}>(await request('/sources?q='+encodeURIComponent(configuration.name),outside),200)).items,[]);
  assert.deepEqual(await journal(source.id),events);
  assert.deepEqual(await scoped(tx=>tx.selectFrom('jobs').select('id').where('source_id','=',source.id).execute()),[]);
});
