// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {after,before,test,type TestContext} from 'node:test';
import {db,scope,sql} from '../../packages/db/src/index.ts';
import {Problem} from '../../packages/authz/src/index.ts';
import {listSources} from '../../packages/connectors/src/source-list.ts';
import {pacedFetch as fetch} from '../fixtures/http-budget.ts';

const tenant='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',foreign='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const steward='10000000-0000-4000-8000-000000000001',engineer='10000000-0000-4000-8000-000000000002',consumer='10000000-0000-4000-8000-000000000003',summit='10000000-0000-4000-8000-000000000005';
const principal={tenantId:tenant,id:steward};
const row=(id:string,name:string,tenantId=tenant)=>({tenant_id:tenantId,id,name,connector_id:'postgresql',host:'source-postgres',port:5432,database_name:'harbor',schema_name:'public',secret_ref:'demo-postgres'});
const invalid=(error:unknown)=>error instanceof Problem&&error.status===400&&error.code==='SOURCE_PAGE_INVALID';
before(async()=>{
 assert.ok(process.env.DATABASE_URL&&process.env.SESSION_KEY,'Real database and cursor key are required');
 const result=await sql<{name:string;superuser:boolean;bypass:boolean}>`SELECT current_user name,rolsuper superuser,rolbypassrls bypass FROM pg_roles WHERE rolname=current_user`.execute(db);
 assert.deepEqual(result.rows,[{name:'gc_app',superuser:false,bypass:false}]);
});
after(async()=>{await db.destroy();});

test('real source keysets traverse101 identical names, preserve literal search and reject invalid bindings without persistent fixtures',async()=>{
 const ids=Array.from({length:101},()=>randomUUID()).sort(),name='source-page-'+randomUUID(),literalIds=[randomUUID(),randomUUID()],astralIds=[randomUUID(),randomUUID()].sort(),controlIds=[randomUUID(),randomUUID()].sort(),controlPrefix=randomUUID().slice(0,12),controlName=controlPrefix+'\u0001'.repeat(108);
 const allIds=[...ids,...literalIds,...astralIds,...controlIds],rollback=new Error('Rollback source pagination fixtures');
 await assert.rejects(scope(tenant,steward,async tx=>{
  await tx.insertInto('sources').values([...ids.map(id=>row(id,name)),row(literalIds[0],name+'_%\\'),row(literalIds[1],name+'AXz'),...astralIds.map(id=>row(id,'😀'.repeat(120))),...controlIds.map(id=>row(id,controlName))]).execute();
  // Exact names span the default page boundary; the similarly prefixed rows
  // sort later and are read separately below using a larger complete oracle.
  const expected=await tx.selectFrom('sources').selectAll().where('tenant_id','=',tenant).where('id','in',allIds).where('name','like',name+'%').orderBy('name').orderBy('id').execute();
  const first=await listSources(tx,principal,{q:name});assert.equal(first.items.length,100);assert.ok(first.nextCursor);
  const second=await listSources(tx,principal,{q:name,cursor:first.nextCursor});assert.equal(second.items.length,3);assert.equal(second.nextCursor,null);
  assert.deepEqual([...first.items,...second.items].map(r=>r.id),expected.map(r=>r.id));assert.equal(new Set([...first.items,...second.items].map(r=>r.id)).size,103);
  assert.deepEqual((await listSources(tx,principal,{q:name+'_%\\'})).items.map(r=>r.id),[literalIds[0]]);
  assert.deepEqual((await listSources(tx,{...principal,tenantId:foreign},{q:name})).items,[],'Explicit tenant scope must not escape the current forced-RLS tenant');
  for(const [p,query] of [[{...principal,id:engineer},{q:name,cursor:first.nextCursor}],[{...principal,tenantId:foreign},{q:name,cursor:first.nextCursor}],[principal,{q:name+'x',cursor:first.nextCursor}],[principal,{q:name,limit:99,cursor:first.nextCursor}]] as const)
   await assert.rejects(listSources(tx,p,query),invalid);
  await assert.rejects(listSources(tx,principal,{q:name,cursor:'forged.cursor'}),invalid);
  const astral=await listSources(tx,principal,{q:'😀'.repeat(120),limit:1});assert.ok(astral.nextCursor);assert.ok(astral.nextCursor.length<=1024);
  const astralNext=await listSources(tx,principal,{q:'😀'.repeat(120),limit:1,cursor:astral.nextCursor});
  assert.deepEqual([...astral.items,...astralNext.items].map(r=>r.id),astralIds);assert.equal(astralNext.nextCursor,null);
  const controls=await listSources(tx,principal,{q:controlPrefix,limit:1});assert.ok(controls.nextCursor);assert.ok(controls.nextCursor.length<=1024);
  const controlsNext=await listSources(tx,principal,{q:controlPrefix,limit:1,cursor:controls.nextCursor});
  assert.deepEqual([...controls.items,...controlsNext.items].map(r=>({id:r.id,name:r.name})),controlIds.map(id=>({id,name:controlName})));assert.equal(controlsNext.nextCursor,null);
  throw rollback;
 }),error=>error===rollback);
 assert.deepEqual(await scope(tenant,steward,tx=>tx.selectFrom('sources').select('id').where('id','in',allIds).execute()),[]);
});

async function session(t:TestContext,identity:string,tenantId=tenant){
 const token=randomUUID()+randomUUID(),hash=createHash('sha256').update(token).digest('hex');
 await db.insertInto('sessions').values({id_hash:hash,identity_id:identity,tenant_id:tenantId,csrf:randomUUID(),expires_at:new Date(Date.now()+300_000)}).execute();
 t.after(async()=>{await db.deleteFrom('sessions').where('id_hash','=',hash).execute();});
 return {Cookie:'gc_session='+token};
}
test('real source list/detail HTTP pages expose101 rows and conceal unavailable tenant resources and cursor reuse',async t=>{
 const name='source-http-page-'+randomUUID(),ids=Array.from({length:101},()=>randomUUID()).sort(),other=randomUUID();
 t.after(async()=>{
  await scope(tenant,steward,tx=>tx.deleteFrom('sources').where('tenant_id','=',tenant).where('id','in',ids).execute());
  await scope(foreign,summit,tx=>tx.deleteFrom('sources').where('tenant_id','=',foreign).where('id','=',other).execute());
 });
 await scope(tenant,steward,tx=>tx.insertInto('sources').values(ids.map(id=>row(id,name))).execute());
 await scope(foreign,summit,tx=>tx.insertInto('sources').values(row(other,name,foreign)).execute());
 const own=await session(t,steward),another=await session(t,engineer),denied=await session(t,consumer),outside=await session(t,summit,foreign);
 const base=process.env.TEST_BASE_URL??'http://api:4310';
 const get=async(path:string,headers=own,status=200)=>{const response=await fetch(base+'/api/v1'+path,{headers,signal:AbortSignal.timeout(15_000)});assert.equal(response.status,status);return await response.json() as any;};
 const prefix='/sources?q='+encodeURIComponent(name),first=await get(prefix);assert.equal(first.items.length,100);assert.equal(typeof first.nextCursor,'string');
 const second=await get(prefix+'&cursor='+encodeURIComponent(first.nextCursor));assert.deepEqual([...first.items,...second.items].map(r=>r.id),ids);assert.equal(second.nextCursor,null);
 const detail=await get('/sources/'+ids[100]);assert.equal(detail.source.id,ids[100]);assert.equal(detail.source.name,name);
 assert.equal((await get('/sources/'+ids[100],outside,404)).code,'SOURCE_NOT_FOUND');
 assert.equal((await get('/sources/'+other,own,404)).code,'SOURCE_NOT_FOUND');
 assert.equal((await get('/sources/'+randomUUID(),own,404)).code,'SOURCE_NOT_FOUND');
 assert.equal((await get('/sources/'+ids[0],denied,403)).code,'FORBIDDEN');
 assert.equal((await get(prefix,denied,403)).code,'FORBIDDEN');
 assert.deepEqual((await get(prefix,outside)).items.map((r:any)=>r.id),[other]);
 for(const [suffix,headers] of [['&cursor='+encodeURIComponent(first.nextCursor),another],['&cursor='+encodeURIComponent(first.nextCursor),outside],['&limit=99&cursor='+encodeURIComponent(first.nextCursor),own],['x&cursor='+encodeURIComponent(first.nextCursor),own],['&cursor=forged.cursor',own]] as const)
  assert.equal((await get(prefix+suffix,headers,400)).code,'SOURCE_PAGE_INVALID');
});
