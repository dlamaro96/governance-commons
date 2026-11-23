// SPDX-License-Identifier: Apache-2.0
/** Real core HTTP/PostgreSQL overview qualification. Run without concurrent
 * catalog mutations. Fresh native protected issuance uses private endpoints;
 * this does not qualify a live OIDC exchange. No owner credential, persisted
 * API-suite session or legacy session is consumed. */
import assert from 'node:assert/strict';
import {after,before,test} from 'node:test';
import {createHash,randomUUID} from 'node:crypto';
import {Pool} from 'pg';
import {db,scope,sql} from '../../packages/db/src/index.ts';
import {record} from '../../apps/api/src/repository.ts';
import type {Principal} from '../../packages/authz/src/index.ts';
import {AUTHENTICATION_SCALARS as S,createAuthenticationClient} from '../../packages/authority/src/authentication.ts';
import {issueProtectedCoreSession,inspectProtectedCoreSession,protectedHeaders,readProtectedPrivateJson,
 validateProtectedCoreEndpoints,type ProtectedCoreEndpointConfig,type PersistedProtectedSession} from '../fixtures/protected-core-authentication.ts';
import {pacedFetch as fetch} from '../fixtures/http-budget.ts';

const harbor='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',summit='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const ids={steward:'10000000-0000-4000-8000-000000000001',consumer:'10000000-0000-4000-8000-000000000003',
 auditor:'10000000-0000-4000-8000-000000000004',foreign:'10000000-0000-4000-8000-000000000005'};
type Persona=keyof typeof ids;
type Overview={assetCount:number;sourceCount:number;ownedCount:number;jobCount:number;
 recentAudit:{id:string;resourceId:string;changes:Record<string,unknown>}[]};
type Session={value:PersistedProtectedSession;headers:Record<string,string>;principal:Principal;baseline:Overview};
const sessions=new Map<Persona,Session>(),issued:PersistedProtectedSession[]=[];
const base=process.env.TEST_BASE_URL??'http://api:4310';
const marker='overview-native-'+randomUUID();
const assets=Object.fromEntries(['publicUnowned','publicOwned','stewardOnly','consumerOnly','auditorOnly','nobody','missing','shared','foreignOwned','foreignUnowned'].map(key=>[key,randomUUID()]));
const sources={harbor:[randomUUID(),randomUUID()],summit:[randomUUID()]};
const jobs={harbor:[randomUUID(),randomUUID(),randomUUID()],summit:[randomUUID(),randomUUID()]};
let config:ProtectedCoreEndpointConfig;
let fixturesStarted=false;
const commonAudit:string[]=[],foreignAudit:string[]=[];
let stewardAudit='',consumerAudit='',auditorAudit='',hiddenAudit='';

async function endpoints():Promise<ProtectedCoreEndpointConfig>{
 const dedicated=process.env.AUTHN_OVERVIEW_CONFIG;
 const value=await readProtectedPrivateJson(dedicated??process.env.AUTHN_PROTECTED_CORE_CONFIG??'') as Record<string,unknown>;
 assert.ok(value&&typeof value==='object'&&!Array.isArray(value));
 const keys=['formatVersion','loginDatabaseUrl','apiDatabaseUrl','issuer','clientId','publicOrigin','environment'];
 assert.deepEqual(Object.keys(value).sort(),[...keys,...(dedicated?[]:['membershipLossSession','expiredSession'])].sort());
 // The normal API harness already supplies these endpoints. Deliberately do
 // not inspect, reuse, refresh or copy its persisted negative-control sessions.
 const result={formatVersion:value.formatVersion,loginDatabaseUrl:value.loginDatabaseUrl,apiDatabaseUrl:value.apiDatabaseUrl,
  issuer:value.issuer,clientId:value.clientId,publicOrigin:value.publicOrigin,environment:value.environment} as ProtectedCoreEndpointConfig;
 validateProtectedCoreEndpoints(result);
 if(process.env.PUBLIC_AUTHN_ORIGIN)assert.equal(result.publicOrigin,process.env.PUBLIC_AUTHN_ORIGIN);
 if(process.env.PUBLIC_URL)assert.equal(result.publicOrigin,process.env.PUBLIC_URL);
 return result;
}

async function body<T>(path:string,headers?:Record<string,string>,status=200):Promise<T>{
 const response=await fetch(base+path,{headers,signal:AbortSignal.timeout(15000)});
 assert.equal(response.status,status,'Unexpected HTTP status for '+path);
 return response.json() as Promise<T>;
}
async function overview(persona:Persona){
 const result=await body<Overview>('/api/v1/overview',sessions.get(persona)!.headers);
 assert.deepEqual(Object.keys(result).sort(),['assetCount','sourceCount','ownedCount','jobCount','recentAudit'].sort());
 for(const key of ['assetCount','sourceCount','ownedCount','jobCount'] as const)assert.ok(Number.isSafeInteger(result[key])&&result[key]>=0);
 assert.ok(result.recentAudit.length<=8);return result;
}
function asset(id:string,tenantId:string,sourceId:string,ownerId:string|null,visibility='tenant',allowed:string[]=[],status='active'){
 return {tenant_id:tenantId,id,source_id:sourceId,external_id:id,name:marker+'-'+id,qualified_name:marker+'.'+id,
  type:'dataset',owner_id:ownerId,visibility,allowed_identities:JSON.stringify(allowed),status,observed_at:new Date()};
}
function source(id:string,tenantId:string){return {tenant_id:tenantId,id,name:marker+'-'+id,connector_id:'postgresql',
 host:'source-postgres',port:5432,database_name:'harbor',schema_name:'public',secret_ref:'demo-postgres'};}
async function audit(persona:Persona,resource:string,ordinal:number){
 const p=sessions.get(persona)!.principal,correlation=randomUUID();
 return scope(p.tenantId,p.id,async tx=>{
  await record(tx,p,'asset.observed',resource,1,{overviewFixture:marker,ordinal},correlation);
  const row=await tx.selectFrom('audit').select('id').where('correlation_id','=',correlation).executeTakeFirstOrThrow();
  return row.id as string;
 });
}

before(async()=>{
 assert.ok(process.env.DATABASE_URL,'Native gc_app DATABASE_URL is required');
 assert.ok(!process.env.MIGRATION_DATABASE_URL&&!process.env.AUTHN_OWNER_DATABASE_URL&&!process.env.AUTHN_ADMIN_DATABASE_URL,
  'Overview tests must not receive an owner credential');
 const role=await sql<{name:string;superuser:boolean;bypass:boolean}>`SELECT current_user name,rolsuper superuser,rolbypassrls bypass FROM pg_roles WHERE rolname=current_user`.execute(db);
 assert.deepEqual(role.rows,[{name:'gc_app',superuser:false,bypass:false}]);
 config=await endpoints();
 for(const persona of Object.keys(ids) as Persona[]){
  const tenant=persona==='foreign'?summit:harbor,value=await issueProtectedCoreSession(config,ids[persona]);issued.push(value);
  assert.equal(value.selectedTenantId,tenant);
  const descriptor=await inspectProtectedCoreSession(config,value);assert.equal(descriptor.identityId,ids[persona]);assert.equal(descriptor.selectedTenantId,tenant);
  const headers=protectedHeaders(config,value),me=await body<{user:{id:string;name:string};tenant:{id:string};permissions:string[]}>('/api/v1/me',headers);
  assert.equal(me.user.id,ids[persona]);assert.equal(me.tenant.id,tenant);assert.ok(me.permissions.includes('catalog:read'));
  const principal={id:me.user.id,name:me.user.name,tenantId:tenant,permissions:me.permissions};
  sessions.set(persona,{value,headers,principal,baseline:await body<Overview>('/api/v1/overview',headers)});
 }
 assert.ok(sessions.get('steward')!.principal.permissions.includes('sources:read'));
 assert.ok(sessions.get('steward')!.principal.permissions.includes('audit:read'));
 assert.ok(!sessions.get('consumer')!.principal.permissions.includes('sources:read'));
 assert.ok(!sessions.get('consumer')!.principal.permissions.includes('audit:read'));
 assert.ok(!sessions.get('auditor')!.principal.permissions.includes('sources:read'));
 assert.ok(sessions.get('auditor')!.principal.permissions.includes('audit:read'));
 assert.ok(sessions.get('foreign')!.principal.permissions.includes('sources:read'));
 assert.ok(sessions.get('foreign')!.principal.permissions.includes('audit:read'));
 fixturesStarted=true;
 await scope(harbor,ids.steward,async tx=>{
  await tx.insertInto('sources').values(sources.harbor.map(id=>source(id,harbor))).execute();
  await tx.insertInto('jobs').values(jobs.harbor.map((id,index)=>({tenant_id:harbor,id,source_id:sources.harbor[index%2],actor_id:ids.steward,
   status:['succeeded','failed','cancelled'][index],finished_at:new Date()}))).execute();
  await tx.insertInto('assets').values([
   asset(assets.publicUnowned!,harbor,sources.harbor[0]!,null),
   asset(assets.publicOwned!,harbor,sources.harbor[0]!,ids.consumer),
   asset(assets.stewardOnly!,harbor,sources.harbor[0]!,ids.consumer,'restricted',[ids.steward]),
   asset(assets.consumerOnly!,harbor,sources.harbor[0]!,ids.steward,'restricted',[ids.consumer]),
   asset(assets.auditorOnly!,harbor,sources.harbor[0]!,null,'restricted',[ids.auditor]),
   asset(assets.nobody!,harbor,sources.harbor[0]!,ids.steward,'restricted'),
   asset(assets.missing!,harbor,sources.harbor[1]!,ids.steward,'tenant',[],'missing'),
   asset(assets.shared!,harbor,sources.harbor[1]!,null,'restricted',[ids.steward,ids.consumer]),
  ]).execute();
 });
 await scope(summit,ids.foreign,async tx=>{
  await tx.insertInto('sources').values(sources.summit.map(id=>source(id,summit))).execute();
  await tx.insertInto('jobs').values(jobs.summit.map(id=>({tenant_id:summit,id,source_id:sources.summit[0],actor_id:ids.foreign,status:'cancelled',finished_at:new Date()}))).execute();
  await tx.insertInto('assets').values([asset(assets.foreignOwned!,summit,sources.summit[0]!,ids.foreign),asset(assets.foreignUnowned!,summit,sources.summit[0]!,null)]).execute();
 });
});

test('real overview counts active visible assets and any assigned owner; tenant RLS and source permissions constrain totals',async()=>{
 for(const [persona,expected] of [
  ['steward',{assetCount:4,ownedCount:2,sourceCount:2,jobCount:3}],
  ['consumer',{assetCount:4,ownedCount:2,sourceCount:0,jobCount:0}],
  ['auditor',{assetCount:3,ownedCount:1,sourceCount:0,jobCount:0}],
  ['foreign',{assetCount:2,ownedCount:1,sourceCount:1,jobCount:2}],
 ] as const){
  const actual=await overview(persona),prior=sessions.get(persona)!.baseline;
  for(const key of ['assetCount','ownedCount'] as const)assert.equal(actual[key]-prior[key],expected[key],persona+' '+key);
  if(persona==='consumer'||persona==='auditor')assert.deepEqual({sourceCount:actual.sourceCount,jobCount:actual.jobCount},{sourceCount:0,jobCount:0});
  else for(const key of ['sourceCount','jobCount'] as const)assert.equal(actual[key]-prior[key],expected[key],persona+' '+key);
  if(persona==='consumer')assert.deepEqual(actual.recentAudit,[]);
 }
 // An ACL change affects the next aggregate without requiring a projection refresh.
 await scope(harbor,ids.steward,tx=>tx.updateTable('assets').set({allowed_identities:JSON.stringify([ids.consumer])}).where('id','=',assets.stewardOnly!).execute());
 assert.equal((await overview('steward')).assetCount-sessions.get('steward')!.baseline.assetCount,3);
 assert.equal((await overview('consumer')).assetCount-sessions.get('consumer')!.baseline.assetCount,5);
 await scope(harbor,ids.steward,tx=>tx.updateTable('assets').set({allowed_identities:JSON.stringify([ids.steward])}).where('id','=',assets.stewardOnly!).execute());
});

test('real overview returns exactly eight latest permitted audit events and no audit without permission',async()=>{
 for(let ordinal=0;ordinal<10;ordinal++)commonAudit.push(await audit('steward',assets.publicOwned!,ordinal));
 hiddenAudit=await audit('steward',assets.nobody!,10);
 stewardAudit=await audit('steward',assets.stewardOnly!,11);
 consumerAudit=await audit('steward',assets.consumerOnly!,12);
 auditorAudit=await audit('steward',assets.auditorOnly!,13);
 for(let ordinal=0;ordinal<10;ordinal++)foreignAudit.push(await audit('foreign',assets.foreignOwned!,ordinal));
 const steward=await overview('steward'),auditor=await overview('auditor'),foreign=await overview('foreign');
 assert.deepEqual(steward.recentAudit.map(row=>row.id),[stewardAudit,...commonAudit.slice(-7).reverse()]);
 assert.deepEqual(auditor.recentAudit.map(row=>row.id),[auditorAudit,...commonAudit.slice(-7).reverse()]);
 assert.deepEqual(foreign.recentAudit.map(row=>row.id),foreignAudit.slice(-8).reverse());
 assert.deepEqual((await overview('consumer')).recentAudit,[]);
 for(const view of [steward,auditor,foreign])assert.ok(!view.recentAudit.some(row=>[hiddenAudit,consumerAudit].includes(row.id)));
 const unauthorized=await fetch(base+'/api/v1/overview',{signal:AbortSignal.timeout(15000)});assert.equal(unauthorized.status,401);
});

after(async()=>{
 try{
  if(fixturesStarted)for(const [tenant,actor,sourceIds,jobIds] of [[harbor,ids.steward,sources.harbor,jobs.harbor],[summit,ids.foreign,sources.summit,jobs.summit]] as const){
   await scope(tenant,actor,async tx=>{
    await tx.deleteFrom('assets').where('id','in',Object.values(assets)).execute();
    await tx.deleteFrom('jobs').where('id','in',[...jobIds]).execute();
    await tx.deleteFrom('sources').where('id','in',[...sourceIds]).execute();
   });
  }
 }finally{
  try{
   if(issued.length){
    const pool=new Pool({connectionString:config.apiDatabaseUrl,max:1,connectionTimeoutMillis:5000,statement_timeout:5000});
    try{const client=createAuthenticationClient(pool);for(const session of issued)await client.sessionRevoke({sessionHash:S.digest(session.sessionHash),
     csrfHash:S.digest(createHash('sha256').update(session.csrfToken).digest('hex')),expectedSessionVersion:S.integer(session.sessionVersion)});}
    finally{await pool.end();}
   }
  }finally{await db.destroy();}
 }
});
