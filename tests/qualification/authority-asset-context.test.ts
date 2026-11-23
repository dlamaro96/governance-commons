// SPDX-License-Identifier: Apache-2.0
/** Real, isolated, inactive-owner asset context. Domain writes use the existing
 * SQL011 projection/seal fixture; no HTTP policy or runtime activation claim. */
import assert from 'node:assert/strict';
import {after, test, type TestContext} from 'node:test';
import pg from 'pg';
import {Kysely, PostgresDialect} from 'kysely';
import {db as unusedDefaultDb, sql} from '../../packages/db/src/index.ts';
import {fixture, query, scalar, tx, uid, setMembership, mutate, addPolicy, addRole, addGrant} from '../fixtures/authority-foundation.ts';
import {config} from '../fixtures/authority-authn-foundation.ts';
import {begin, project, persist, seal, bodyFor, definition, digest as previewDigest, permissions, reason} from '../fixtures/business-domains.ts';
import {once, assetView} from '../../apps/api/src/repository.ts';
import type {DomainMutationRequest} from '../../packages/domain/src/business-domain-service-contracts.ts';
import type {DomainTypeView, DomainView} from '../../packages/domain/src/business-domain-contracts.ts';
import type {Principal} from '../../packages/authz/src/index.ts';
import {createAuthorityFoundationRepository} from '../../packages/authority-storage/src/repository.ts';
import {AuthorityFoundationError, type NativeOwnerPool} from '../../packages/authority-storage/src/contracts.ts';
import {decisionHash, decisionShapes} from '../../packages/authority/src/decision-schema.ts';
import type {Digest, UUID, Version} from '../../packages/authority/src/types.ts';
import type {HumanAssetContext} from '../../packages/authority-runtime/src/asset-context.ts';

type Fixture=Awaited<ReturnType<typeof fixture>>;
const failure=(code:string)=>(e:unknown)=>e instanceof AuthorityFoundationError&&e.code==='AUTHORITY_FOUNDATION_'+code;
const dataDb=new Kysely<Record<string,any>>({dialect:new PostgresDialect({pool:new pg.Pool({connectionString:config.legacy,max:2,connectionTimeoutMillis:5000})})});
after(async()=>{await dataDb.destroy();await unusedDefaultDb.destroy();});
async function prepared(t:TestContext){const f=await fixture(t);await query(f.owner,'UPDATE memberships SET permissions=$3::jsonb WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.identity,JSON.stringify(permissions)]);return f;}
const principal=(f:Fixture):Principal=>({tenantId:f.tenant,id:f.identity,name:'Synthetic context steward',permissions});
async function write(f:Fixture,request:DomainMutationRequest){
 const p=principal(f),key=uid();return dataDb.transaction().execute(async transaction=>{
  await sql`SELECT set_config('gc.tenant_id',${f.tenant},true),set_config('gc.actor_id',${f.identity},true)`.execute(transaction);
  const response=await once(transaction,p,request.kind,key,bodyFor(request),async()=>{const started=await begin(transaction,request,uid(),key),projection=await project(transaction,p,request,started);await persist(transaction,p,request,started,projection);const result=await seal(transaction,request,started.operationId);assert.deepEqual(result,projection.response);return result;});
  await sql`SET CONSTRAINTS ALL IMMEDIATE`.execute(transaction);return response;
 });
}
async function asset(f:Fixture,options:{tenant?:string;version?:number;allowed?:string[];status?:'active'|'retired'|'unavailable'}={}){
 const tenant=options.tenant??f.tenant,id=uid();await tx(f.owner,async()=>{await query(f.owner,"SELECT set_config('gc.tenant_id',$1,true)",[tenant]);const row=await scalar(f.owner,"INSERT INTO assets(tenant_id,id,external_id,name,qualified_name,type,observed_at,version,allowed_identities,visibility,status) VALUES($1::uuid,$2::uuid,$2::text,'Synthetic context asset',$2::text,'dataset',clock_timestamp(),$3,$4::jsonb,$5,$6) RETURNING *",[tenant,id,options.version??1,JSON.stringify(options.allowed??[]),options.allowed?'restricted':'tenant',options.status??'active']);await query(f.owner,'INSERT INTO asset_revisions(tenant_id,asset_id,version,snapshot) VALUES($1,$2,$3,$4::jsonb)',[tenant,id,row.version,JSON.stringify(assetView(row))]);});return id;
}
async function type(f:Fixture){return (await write(f,{kind:'domain-type.create',definition:definition(),reason})).type as DomainTypeView;}
async function domain(f:Fixture,kind:DomainTypeView,parent:DomainView|null=null){return (await write(f,{kind:'domain.create',name:'Synthetic context domain',description:'Synthetic isolated qualification',parentId:parent?.id??null,type:{typeId:kind.typeId,version:kind.version},attributes:{},ownerId:null,reason})).domain as DomainView;}
async function place(f:Fixture,id:string,d:DomainView|null,placementVersion=0,assetVersion=1){return write(f,{kind:'domain.placement',assetId:id,assetVersion,expectedPlacementVersion:placementVersion,domainId:d?.id??null,domainVersion:d?.version??null,reason});}
async function move(f:Fixture,d:DomainView,parent:DomainView|null){return (await write(f,{kind:'domain.hierarchy',change:{kind:'move',domainId:d.id,expectedVersion:d.version,parentId:parent?.id??null,reason},previewDigest})).domain as DomainView;}
function request(f:Fixture,id:string,expectedVersion=1){return {sessionHash:f.hash as Digest,assetId:id as UUID,expectedVersion:expectedVersion as Version};}
async function read(f:Fixture,id:string,expectedVersion=1,url=config.owner){const pool=new pg.Pool({connectionString:url,max:1,connectionTimeoutMillis:5000});try{return await createAuthorityFoundationRepository(pool).loadHumanAssetContext(request(f,id,expectedVersion));}finally{await pool.end();assert.equal(pool.totalCount,0);}}
function context(c:HumanAssetContext,f:Fixture,id:string,version=1){assert.equal(c.formatVersion,1);assert.equal(c.kind,'inactive-human-asset-context');assert.equal(c.contentAuthority,false);assert.equal(c.asset.tenantId,f.tenant);assert.equal(c.asset.id,id);assert.equal(c.asset.version,version);assert.deepEqual(c.registry,decisionShapes.registry(f.registry,'/registry'));assert.equal(c.registry.digest,f.registry.digest);assert.equal(c.registry.version,f.registry.version);assert.equal(c.closure.snapshot.registryId,f.registryId);assert.equal(c.closure.snapshot.registryDigest,f.registry.digest);assert.equal(c.closure.snapshot.registryVersion,f.registry.version);assert.deepEqual(c.unavailableFacts,['classification','approved-tags','purpose','environment']);assert.deepEqual(c.closure.selectors,[{action:'asset:metadata.read',resource:{kind:'asset',tenantId:f.tenant,id},revision:version,field:null}]);assert.equal(c.closure.session.identityId,f.identity);assert.equal(c.contextDigest,decisionHash({...c,contextDigest:'0'.repeat(64)}));assert.match(c.domainEpoch,/^(0|[1-9][0-9]*)$/);}
async function snapshot(f:Fixture){
 const tables=(await query(f.admin,"SELECT n.nspname||'.'||c.relname name FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind='r' AND n.nspname IN('public','gc_authn','gc_authority') ORDER BY 1")).rows.map(r=>r.name as string);assert.ok(tables.length>100&&tables.length<=512);assert.ok(tables.every(x=>/^(public|gc_authn|gc_authority)\.[a-z_]+$/.test(x)));
 return (await query(f.admin,tables.map(table=>`SELECT '${table}' name,count(*)::text rows,encode(sha256(coalesce(string_agg(row_hash,''::bytea ORDER BY row_hash),''::bytea)),'hex') digest FROM (SELECT sha256(convert_to(to_jsonb(r)::text,'UTF8')) row_hash FROM ${table} r) s`).join(' UNION ALL ')+' ORDER BY name')).rows;
}
async function tamper(f:Fixture,table:'public.assets'|'public.domains'|'gc_authn.sessions',id:string,changes:Record<string,unknown>,work:()=>Promise<void>){
 const allowed=table==='public.assets'?['allowed_identities','version','status']:table==='public.domains'?['parent_id']:['authenticated_at','issued_at','expires_at'];assert.ok(Object.keys(changes).every(k=>allowed.includes(k)));
 const where=table==='gc_authn.sessions'?'id=$1':'tenant_id=$1 AND id=$2',params=table==='gc_authn.sessions'?[id]:[f.tenant,id],before=await scalar(f.admin,`SELECT * FROM ${table} WHERE ${where}`,params);
 const triggers=(await query(f.admin,'SELECT tgname,tgenabled FROM pg_trigger WHERE tgrelid=$1::regclass ORDER BY tgname',[table])).rows;
 const replace=async(values:Record<string,unknown>)=>tx(f.admin,async()=>{await query(f.admin,`ALTER TABLE ${table} DISABLE TRIGGER ALL`);const keys=Object.keys(changes);assert.equal((await query(f.admin,`UPDATE ${table} SET ${keys.map((k,i)=>k+'=$'+(params.length+i+1)).join(',')} WHERE ${where}`,[...params,...keys.map(k=>k==='allowed_identities'?JSON.stringify(values[k]):values[k])])).rowCount,1);await query(f.admin,`ALTER TABLE ${table} ENABLE TRIGGER ALL`);});
 await replace(changes);try{await work();}finally{await replace(before);assert.deepEqual(await scalar(f.admin,`SELECT * FROM ${table} WHERE ${where}`,params),before);assert.deepEqual((await query(f.admin,'SELECT tgname,tgenabled FROM pg_trigger WHERE tgrelid=$1::regclass ORDER BY tgname',[table])).rows,triggers);}
}

test('native unplaced context binds the session tenant exact registry and sole asset read selector without writes',async t=>{
 const f=await prepared(t),id=await asset(f);let grantId:string|undefined;await mutate(f,async()=>{grantId=(await addGrant(f,await addRole(f,[await addPolicy(f)]))).ref.id;});const before=await snapshot(f),c=await read(f,id);context(c,f,id);assert.deepEqual(c.closure.grants.map(g=>g.ref.id),[grantId]);assert.deepEqual(c.closure.partitions[0]?.candidates.map(g=>g.id),[grantId]);assert.equal(c.placement,null);assert.deepEqual(c.domainPath,[]);assert.equal(c.asset.visibility,'tenant');assert.deepEqual(c.asset.allowedIdentities,[]);assert.deepEqual(await snapshot(f),before);
});
test('real placed and explicitly unassigned contexts retain distinct placement heads and nearest-first domains',async t=>{
 const f=await prepared(t),id=await asset(f),kind=await type(f),root=await domain(f,kind),leaf=await domain(f,kind,root);await place(f,id,leaf);const c=await read(f,id);context(c,f,id);assert.deepEqual(c.placement,{version:1,domainId:leaf.id,recordedAssetVersion:1,recordedDomainVersion:1});assert.deepEqual(c.domainPath.map(x=>x.id),[leaf.id,root.id]);assert.deepEqual(c.domainPath[0],{id:leaf.id,version:1,parentId:root.id,typeId:kind.typeId,typeVersion:1,status:'active'});await place(f,id,null,1);const unassigned=await read(f,id);assert.deepEqual(unassigned.placement,{version:2,domainId:null,recordedAssetVersion:1,recordedDomainVersion:null});assert.deepEqual(unassigned.domainPath,[]);assert.ok(BigInt(unassigned.domainEpoch)>BigInt(c.domainEpoch));
});
test('historical placement pins do not replace the current moved domain or current asset revision',async t=>{
 const f=await prepared(t),id=await asset(f),kind=await type(f),oldRoot=await domain(f,kind),newRoot=await domain(f,kind),leaf=await domain(f,kind,oldRoot);await place(f,id,leaf);await move(f,leaf,newRoot);
 await tx(f.owner,async()=>{const row=await scalar(f.owner,'UPDATE assets SET version=2 WHERE tenant_id=$1 AND id=$2 RETURNING *',[f.tenant,id]);await query(f.owner,'INSERT INTO asset_revisions(tenant_id,asset_id,version,snapshot) VALUES($1,$2,2,$3::jsonb)',[f.tenant,id,JSON.stringify(assetView(row))]);});const c=await read(f,id,2);context(c,f,id,2);assert.equal(c.placement?.recordedAssetVersion,1);assert.equal(c.placement?.recordedDomainVersion,1);assert.equal(c.domainPath[0]?.version,2);assert.deepEqual(c.domainPath.map(d=>d.id),[leaf.id,newRoot.id]);
});
test('one held native repeatable-read snapshot cannot mix a concurrent committed domain move',async t=>{
 const f=await prepared(t),id=await asset(f),kind=await type(f),oldRoot=await domain(f,kind),newRoot=await domain(f,kind),leaf=await domain(f,kind,oldRoot);await place(f,id,leaf);const before=await read(f,id),pool=new pg.Pool({connectionString:config.owner,max:1,connectionTimeoutMillis:5000});let moved=false;const statements:string[]=[];
 const observed:NativeOwnerPool={async connect(){const c=await pool.connect();return {async query(text,values){statements.push(text);const result=await c.query(text,values);if(text.includes('AS native_owner')){assert.equal(moved,false);await move(f,leaf,newRoot);moved=true;}return result;},release(destroy){c.release(destroy);}};}};
 try{const held=await createAuthorityFoundationRepository(observed).loadHumanAssetContext(request(f,id));assert.equal(moved,true);assert.deepEqual(held.domainPath,before.domainPath);assert.equal(held.domainEpoch,before.domainEpoch);assert.equal(statements.filter(x=>x==='BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY').length,1);assert.equal(statements.filter(x=>x.includes('load_human_closure_v1')).length,1);assert.equal(statements.filter(x=>x==='COMMIT').length,1);const fresh=await read(f,id);assert.deepEqual(fresh.domainPath.map(d=>d.id),[leaf.id,newRoot.id]);assert.ok(BigInt(fresh.domainEpoch)>BigInt(held.domainEpoch));}finally{await pool.end();assert.equal(pool.totalCount,0);}
});
test('missing foreign and stale assets all refuse with version conflict before returning context',async t=>{
 const f=await prepared(t),id=await asset(f),foreign=await asset(f,{tenant:f.otherTenant}),before=await snapshot(f);for(const [assetId,version] of [[uid(),1],[foreign,1],[id,2]] as const)await assert.rejects(read(f,assetId,version),failure('VERSION_CONFLICT'));assert.deepEqual(await snapshot(f),before);context(await read(f,id),f,id);
});
test('every runtime executor refuses the inactive owner loader even with forged session GUCs',async t=>{
 const f=await prepared(t),id=await asset(f);for(const url of [config.legacy,f.roles.api.url,f.roles.login.url,f.roles.nextApi.url,f.roles.nextLogin.url,config.unregistered.url]){const pool=new pg.Pool({connectionString:url,max:1,connectionTimeoutMillis:5000});try{const connection=await pool.connect();await connection.query("SELECT set_config('gc.tenant_id',$1,false),set_config('gc.actor_id',$2,false)",[f.tenant,f.identity]);connection.release();await assert.rejects(createAuthorityFoundationRepository(pool).loadHumanAssetContext(request(f,id)),failure('EXECUTOR_REJECTED'));}finally{await pool.end();assert.equal(pool.totalCount,0);}}context(await read(f,id),f,id);
});
test('revoked private sessions and inactive canonical membership cannot reuse earlier contexts',async t=>{
 const f=await prepared(t),id=await asset(f);context(await read(f,id),f,id);await setMembership(f,f.owner,f.tenant,false);await assert.rejects(read(f,id),failure('SESSION_REJECTED'));await setMembership(f,f.owner,f.tenant,true);context(await read(f,id),f,id);await query(f.api,'SELECT * FROM public.gc_authn_session_revoke($1,$2,1)',[f.hash,f.csrf]);await assert.rejects(read(f,id),failure('SESSION_REJECTED'));
});
test('an expired private session fixture is refused and exact owner restoration recovers the original session',async t=>{
 const f=await prepared(t),id=await asset(f),now=Date.now();await tamper(f,'gc_authn.sessions',f.protectedSession.session_id,{authenticated_at:new Date(now-3600000),issued_at:new Date(now-3600000),expires_at:new Date(now-1800000)},async()=>{await assert.rejects(read(f,id),failure('SESSION_REJECTED'));});context(await read(f,id),f,id);
});
test('forged owner GUCs cannot retarget context and pooled success restores their exact prior values',async t=>{
 const f=await prepared(t),id=await asset(f),pool=new pg.Pool({connectionString:config.owner,max:1,connectionTimeoutMillis:5000}),actor=uid();let connection=await pool.connect();await connection.query("SELECT set_config('gc.tenant_id',$1,false),set_config('gc.actor_id',$2,false)",[f.otherTenant,actor]);const pid=(await connection.query('SELECT pg_backend_pid() pid')).rows[0].pid;connection.release();try{context(await createAuthorityFoundationRepository(pool).loadHumanAssetContext(request(f,id)),f,id);connection=await pool.connect();assert.deepEqual((await connection.query("SELECT pg_backend_pid() pid,current_setting('gc.tenant_id') tenant,current_setting('gc.actor_id') actor,current_setting('transaction_read_only') readonly")).rows,[{pid,tenant:f.otherTenant,actor,readonly:'off'}]);connection.release();await assert.rejects(createAuthorityFoundationRepository(pool).loadHumanAssetContext(request(f,id,2)),failure('VERSION_CONFLICT'));context(await createAuthorityFoundationRepository(pool).loadHumanAssetContext(request(f,id)),f,id);}finally{await pool.end();assert.equal(pool.totalCount,0);}
});
test('restricted retired and source-unavailable metadata remain facts with canonical sorted identities',async t=>{
 const f=await prepared(t),allowed=[f.identity,uid()].sort();for(const status of ['retired','unavailable'] as const){const id=await asset(f,{allowed:[...allowed].reverse(),status}),c=await read(f,id);context(c,f,id);assert.equal(c.asset.status,status);assert.equal(c.asset.visibility,'restricted');assert.deepEqual(c.asset.allowedIdentities,allowed);assert.equal(c.contentAuthority,false);}
});
test('malformed duplicate and noncanonical ACLs and invalid stored asset versions fail closed',async t=>{
 const f=await prepared(t),id=await asset(f);for(const value of [{},['not-a-uuid'],[f.identity,f.identity],[f.identity.toUpperCase()]])await tamper(f,'public.assets',id,{allowed_identities:value},async()=>{await assert.rejects(read(f,id),failure('INTEGRITY'));});await tamper(f,'public.assets',id,{version:0},async()=>{await assert.rejects(read(f,id),failure('INTEGRITY'));});await tamper(f,'public.assets',id,{status:'unknown-status'},async()=>{await assert.rejects(read(f,id),failure('INTEGRITY'));});context(await read(f,id),f,id);
});
test('ACL physical overflow fails at the declared bound without partial context',async t=>{
 const f=await prepared(t),id=await asset(f);await tamper(f,'public.assets',id,{allowed_identities:Array.from({length:4097},()=>uid())},async()=>{await assert.rejects(read(f,id),failure('PROFILE_LIMIT'));});context(await read(f,id),f,id);
});
test('native SQL011 accepts thirty-two domain nodes while excess depth and corrupted cycles are refused',async t=>{
 const f=await prepared(t),id=await asset(f),kind=await type(f),chain:DomainView[]=[];for(let i=0;i<32;i++)chain.push(await domain(f,kind,chain.at(-1)??null));await place(f,id,chain.at(-1)!);const c=await read(f,id);assert.equal(c.domainPath.length,32);assert.deepEqual(c.domainPath.map(x=>x.id),chain.map(x=>x.id).reverse());await assert.rejects(domain(f,kind,chain.at(-1)!),e=>e!==null&&typeof e==='object'&&'code'in e&&['23514','54000'].includes(String(e.code)));const extraRoot=await domain(f,kind);
 await tamper(f,'public.domains',chain[0]!.id,{parent_id:extraRoot.id},async()=>{await assert.rejects(read(f,id),failure('PROFILE_LIMIT'));});await tamper(f,'public.domains',chain[0]!.id,{parent_id:chain[1]!.id},async()=>{await assert.rejects(read(f,id),failure('INTEGRITY'));});assert.deepEqual((await read(f,id)).domainPath,c.domainPath);
});
