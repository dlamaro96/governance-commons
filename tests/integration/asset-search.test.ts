// SPDX-License-Identifier: Apache-2.0
/** Real native PostgreSQL, OpenSearch PIT and HTTP qualification. These owned,
 * unbound fixture assets never create or modify immutable history/audit rows.
 * Projection writes are deliberate test inputs, not a projector-health claim. */
import assert from 'node:assert/strict';
import {createHash, randomUUID} from 'node:crypto';
import {after, before, test, type TestContext} from 'node:test';
import {db, lockTenantLedger, pool, scope, sql} from '../../packages/db/src/index.ts';
import {Problem, type Principal} from '../../packages/authz/src/index.ts';
import {createAssetSearch, searchAssets, type AssetSearchQuery} from '../../apps/api/src/asset-search.ts';
import {pacedFetch} from '../fixtures/http-budget.ts';
import {SEARCH_TEST_FIXTURE} from '../fixtures/search-tenants.ts';

// The owner harness alone provisions these dedicated non-login fixtures. Their
// tenant/member rows persist; this test never resets or expands their authority.
const {tenant,foreign,steward,consumer,summit}=SEARCH_TEST_FIXTURE;
const base=process.env.TEST_BASE_URL??'http://api:4310';
const searchUrl=process.env.OPENSEARCH_URL??'http://opensearch:9200', index='gc-assets-v1';
const token=()=>randomUUID().replaceAll('-','');
const broad='searchbulk'+token(), narrow='searchneedle'+token(), filler='searchother'+token();
type Asset={id:string; tenantId:string; name:string; qualifiedName:string; type:string; description:string;
  status:string; visibility:'tenant'|'restricted'; allowed:string[]; metadata:{fixture:string}};
type Page={items:Array<{id:string;name:string;qualifiedName:string;type:string;description:string;status:string;
  version:number;metadata:unknown;sourceId:string|null;ownerId:string|null}>;
  total:number;facets:{type:string;count:number}[];nextCursor:string|null};
const owned:Asset[]=[], indexed=new Set<string>();
function asset(name:string, type='table', overrides:Partial<Asset>={}):Asset {
  const id=randomUUID();
  const value:Asset={id,tenantId:tenant,name,qualifiedName:name,type,description:'Synthetic search qualification',
    status:'active',visibility:'tenant',allowed:[],metadata:{fixture:'asset-search'},...overrides};
  owned.push(value); return value;
}
const bulkRows=Array.from({length:9_101},(_,i)=>asset(`${broad} ${String(i).padStart(5,'0')}`,i%2?'view':'table'));
const narrowRows=Array.from({length:5},(_,i)=>asset(`${narrow} ${i}`));
const fillerRows=Array.from({length:899},(_,i)=>asset(`${filler} ${i}`));
const document=(a:Asset, change:Record<string,unknown>={})=>({tenantId:a.tenantId,id:a.id,name:a.name,
  qualifiedName:a.qualifiedName,type:a.type,description:a.description,status:a.status,version:1,...change});
const batches=<T>(rows:readonly T[],size=500)=>Array.from({length:Math.ceil(rows.length/size)},(_,i)=>rows.slice(i*size,(i+1)*size));

async function searchRequest(path:string,method:string,body?:string,ndjson=false):Promise<any> {
  const response=await globalThis.fetch(searchUrl+path,{method,redirect:'error',headers:{'Content-Type':ndjson?'application/x-ndjson':'application/json'},
    body,signal:AbortSignal.timeout(20_000)});
  assert.equal(response.ok,true,`OpenSearch fixture request failed: ${method} ${path} (${response.status})`);
  return response.json();
}
async function project(rows:Array<{id:string;value:Record<string,unknown>}>) {
  for(const batch of batches(rows)) {
    // Register exact IDs before sending, so an ambiguous response is cleaned too.
    for(const row of batch) indexed.add(row.id);
    const lines=batch.flatMap(row=>[JSON.stringify({index:{_index:index,_id:row.id}}),JSON.stringify(row.value)]).join('\n')+'\n';
    const result=await searchRequest('/_bulk?refresh=true','POST',lines,true);
    assert.equal(result.errors,false); assert.equal(result.items.length,batch.length);
    assert.ok(result.items.every((item:any,i:number)=>[200,201].includes(item.index?.status)&&item.index?._id===batch[i]!.id));
  }
}
async function insert(rows:Asset[]) {
  for(const tenantId of [...new Set(rows.map(row=>row.tenantId))]) {
    await scope(tenantId,tenantId===tenant?steward:summit,async tx=>{
      await sql`SELECT set_config('statement_timeout','20000',true),set_config('lock_timeout','2000',true)`.execute(tx);
      await lockTenantLedger(tx,tenantId);
      for(const batch of batches(rows.filter(row=>row.tenantId===tenantId))) await tx.insertInto('assets').values(batch.map(row=>({
        tenant_id:row.tenantId,id:row.id,external_id:row.id,name:row.name,qualified_name:row.qualifiedName,type:row.type,
        description:row.description,status:row.status,visibility:row.visibility,allowed_identities:JSON.stringify(row.allowed),
        metadata:JSON.stringify(row.metadata),observed_at:new Date()}))).execute();
    });
  }
}
async function cleanup() {
  const errors:unknown[]=[];
  try {
    for(const batch of batches([...indexed])) {
      const result=await searchRequest('/_bulk?refresh=true','POST',batch.map(id=>JSON.stringify({delete:{_index:index,_id:id}})).join('\n')+'\n',true);
      assert.equal(result.items.length,batch.length);
      assert.ok(result.items.every((item:any,i:number)=>[200,404].includes(item.delete?.status)&&item.delete?._id===batch[i]));
    }
  } catch(error) {errors.push(error);}
  for(const tenantId of [...new Set(owned.map(row=>row.tenantId))]) {
    try {
      await scope(tenantId,tenantId===tenant?steward:summit,async tx=>{
        await sql`SELECT set_config('statement_timeout','20000',true),set_config('lock_timeout','2000',true)`.execute(tx);
        await lockTenantLedger(tx,tenantId);
        for(const batch of batches(owned.filter(row=>row.tenantId===tenantId).map(row=>row.id))) {
          // Refuse accidental fixture scope expansion rather than deleting any
          // history, journal or real source-created resource to make cleanup pass.
          assert.deepEqual(await tx.selectFrom('asset_revisions').select('asset_id').where('asset_id','in',batch).execute(),[]);
          assert.deepEqual(await tx.selectFrom('outbox').select('resource_id').where('resource_id','in',batch).execute(),[]);
          assert.deepEqual(await tx.selectFrom('audit').select('resource_id').where('resource_id','in',batch).execute(),[]);
          await tx.deleteFrom('assets').where('tenant_id','=',tenantId).where('id','in',batch).where('source_id','is',null).execute();
          assert.deepEqual(await tx.selectFrom('assets').select('id').where('id','in',batch).execute(),[]);
        }
      });
    } catch(error) {errors.push(error);}
  }
  if(errors.length) throw new AggregateError(errors,'Owned asset-search fixture cleanup failed');
}
before(async()=>{
  assert.ok(process.env.DATABASE_URL&&process.env.SESSION_KEY,'Actual runtime database and cursor key are required; no native search test ran.');
  assert.deepEqual((await sql<{name:string;superuser:boolean;bypass:boolean}>`SELECT current_user name,rolsuper superuser,rolbypassrls bypass
    FROM pg_roles WHERE rolname=current_user`.execute(db)).rows,[{name:'gc_app',superuser:false,bypass:false}]);
  for(const [tenantId,actors] of [[tenant,[steward,consumer]],[foreign,[summit]]] as const) {
    await scope(tenantId,actors[0],async tx=>{
      assert.deepEqual(await tx.selectFrom('assets').select('id').where('tenant_id','=',tenantId).limit(1).execute(),[],'Owner fixture must start without preexisting assets');
      assert.deepEqual(await tx.selectFrom('relation_types').select('type_id').where('tenant_id','=',tenantId).limit(1).execute(),[],'Search qualification requires its isolated tenant, not a populated model fixture');
      const members=await tx.selectFrom('memberships').innerJoin('identities','identities.id','memberships.identity_id')
        .select(['memberships.identity_id','memberships.permissions']).where('memberships.tenant_id','=',tenantId)
        .where('memberships.active','=',true).where('identities.active','=',true).orderBy('memberships.identity_id').execute();
      assert.deepEqual(members.map(row=>row.identity_id),[...actors].sort());
      for(const row of members) assert.deepEqual(row.permissions,['catalog:read'],'Dedicated search fixtures must retain their exact minimal authority');
    });
  }
  await insert([...bulkRows,...narrowRows,...fillerRows]);
  await project([...bulkRows,...narrowRows].map(row=>({id:row.id,value:document(row)})));
  const count=await searchRequest('/'+index+'/_count','POST',JSON.stringify({query:{terms:{id:bulkRows.map(row=>row.id)}}}));
  assert.equal(count.count,bulkRows.length,'Bulk refresh must expose every exact owned document before assertions');
}, {timeout:120_000});
after(async()=>{try {await cleanup();} finally {await db.destroy();}}, {timeout:120_000});

async function session(t:TestContext,actor:string=consumer,tenantId:string=tenant) {
  const raw=token()+token(),hash=createHash('sha256').update(raw).digest('hex');
  await db.insertInto('sessions').values({id_hash:hash,identity_id:actor,tenant_id:tenantId,csrf:randomUUID(),expires_at:new Date(Date.now()+900_000)}).execute();
  t.after(async()=>{await db.deleteFrom('sessions').where('id_hash','=',hash).execute();});
  const principal:Principal={id:actor,tenantId,name:'Synthetic native search caller',permissions:['catalog:read']};
  return {headers:{Cookie:'gc_session='+raw},auth:{principal,sessionHash:hash}};
}
async function http(query:AssetSearchQuery,headers:Record<string,string>,status=200,signal?:AbortSignal) {
  const params=new URLSearchParams();
  for(const [key,value] of Object.entries(query)) if(value!==undefined) params.set(key,String(value));
  const response=await pacedFetch(base+'/api/v1/assets?'+params,{headers,signal:signal
    ?AbortSignal.any([signal,AbortSignal.timeout(20_000)]):AbortSignal.timeout(20_000)});
  const value=await response.json();assert.equal(response.status,status,`Unexpected asset-search HTTP status: ${JSON.stringify(value)}`);
  return value as Page&{code?:string};
}
function facets(rows:Asset[]) {
  const result=new Map<string,number>();for(const row of rows) result.set(row.type,(result.get(row.type)??0)+1);
  return [...result].map(([type,count])=>({type,count})).sort((a,b)=>b.count-a.count||Buffer.compare(Buffer.from(a.type),Buffer.from(b.type)));
}
function checkPage(value:Page,rows:Asset[],all:Asset[]) {
  assert.deepEqual(value.items.map(row=>row.id),rows.map(row=>row.id));assert.equal(value.total,all.length);assert.deepEqual(value.facets,facets(all));
  value.items.forEach((row,i)=>{
    const expected=rows[i]!;
    assert.deepEqual({name:row.name,qualifiedName:row.qualifiedName,type:row.type,description:row.description,status:row.status,metadata:row.metadata},
      {name:expected.name,qualifiedName:expected.qualifiedName,type:expected.type,description:expected.description,status:expected.status,metadata:expected.metadata});
    assert.equal(row.version,1);assert.equal(row.sourceId,null);assert.equal(row.ownerId,null);
  });
}

test('narrow real search succeeds above10000 tenant assets and materializes only its selected canonical page', {timeout:40_000},async t=>{
  const current=await session(t);
  const size=await scope(tenant,consumer,tx=>tx.selectFrom('assets').select(sql<string>`count(*)::text`.as('count'))
    .where('tenant_id','=',tenant).where('status','=','active').where('visibility','=','tenant').executeTakeFirstOrThrow());
  assert.ok(Number(size.count)>10_000);
  checkPage(await http({q:narrow,limit:100},current.headers,200,t.signal),narrowRows,narrowRows);
  const trace:{text:string;rows:number;keys:string[];ids:string[]}[]=[];
  const native=createAssetSearch({searchUrl,cursorKey:process.env.SESSION_KEY!,fetch:globalThis.fetch,connect:async()=>{
    const client=await pool.connect();return {release:(destroy?:boolean)=>client.release(destroy),query:async config=>{
      const result=await client.query(config);
      trace.push({text:config.text,rows:result.rows.length,keys:Object.keys(result.rows[0]??{}),
        ids:Array.isArray(config.values?.[1])?[...config.values[1]]:[]});return result;
    }};
  }});
  // Native dependency wrappers observe real SQL/results; they neither supply
  // canned rows nor replace PostgreSQL/OpenSearch behavior.
  checkPage(await native({...current.auth,principal:{...current.auth.principal,permissions:[]}},{q:narrow,limit:100}),narrowRows,narrowRows);
  const reads=trace.filter(row=>/FROM assets\b/.test(row.text));assert.ok(reads.length>=3);
  assert.ok(reads.every(row=>row.ids.length>0&&row.ids.length<=5&&row.ids.every(id=>narrowRows.some(a=>a.id===id))));
  const hydrated=reads.filter(row=>row.keys.includes('metadata'));
  assert.equal(hydrated.length,1);assert.equal(hydrated[0]!.rows,5);
  assert.ok(reads.filter(row=>!row.keys.includes('metadata')).every(row=>row.keys.every(key=>['id','type','bytes'].includes(key))));
});

test('real catalog empty query type and cursor return the same authorized first page as omitted fields', {timeout:60_000},async t=>{
  const visible=asset('0-ui-empty-cursor-visible','dataset',{visibility:'restricted',allowed:[consumer]});
  const hidden=asset('1-ui-empty-cursor-hidden','hidden-cursor-type',{visibility:'restricted',allowed:[steward]});
  const foreignRow=asset('2-ui-empty-cursor-foreign','foreign-cursor-type',{tenantId:foreign});
  await insert([visible,hidden,foreignRow]);
  // Even a stale document claiming the requesting tenant cannot establish
  // canonical visibility, counts or facets for a foreign asset.
  await project([visible,hidden,foreignRow].map(row=>({id:row.id,value:document(row,{tenantId:tenant})})));
  const current=await session(t),outside=await session(t,summit,foreign);
  const first=await http({limit:2},current.headers,200,t.signal);
  const ui=await http({q:'',type:'',limit:2,cursor:''},current.headers,200,t.signal);
  assert.deepEqual(ui,first);checkPage(ui,[visible,bulkRows[0]!],[visible,...bulkRows,...narrowRows]);
  assert.ok(ui.nextCursor);assert.equal(JSON.stringify(ui).includes(hidden.id),false);assert.equal(JSON.stringify(ui).includes(foreignRow.id),false);
  checkPage(await http({q:'',type:'',limit:2,cursor:ui.nextCursor},current.headers,200,t.signal),
    bulkRows.slice(1,3),[visible,...bulkRows,...narrowRows]);
  assert.deepEqual(await http({q:'',type:'',limit:2,cursor:''},outside.headers,200,t.signal),{items:[],total:0,nextCursor:null,facets:[]});
  assert.equal((await http({q:'',type:'',limit:2,cursor:' '},current.headers,400,t.signal)).code,'CURSOR_INVALID');
});

test('real HTTP cursors traverse all9101 authorized matches beyond9000 with canonical totals and facets', {timeout:300_000},async t=>{
  const current=await session(t),seen:string[]=[],cursors=new Set<string>();let cursor:string|undefined;
  for(let page=0;page<92;page++) {
    const value=await http({q:broad,limit:100,...(cursor?{cursor}:{})},current.headers,200,t.signal);
    checkPage(value,bulkRows.slice(page*100,(page+1)*100),bulkRows);seen.push(...value.items.map(row=>row.id));
    if(page<91) {assert.equal(typeof value.nextCursor,'string');assert.ok(value.nextCursor);assert.equal(cursors.has(value.nextCursor),false);
      cursors.add(value.nextCursor);cursor=value.nextCursor;
      const payload=JSON.parse(Buffer.from(cursor.split('.')[0]!,'base64url').toString('utf8'));
      assert.equal(payload.offset,(page+1)*100);
      if(page===90) assert.equal(payload.offset,9100,'The API must generate a usable cursor beyond9000');
    } else assert.equal(value.nextCursor,null);
  }
  assert.equal(seen.length,9_101);assert.equal(new Set(seen).size,9_101);assert.deepEqual(seen,bulkRows.map(row=>row.id));
});

test('stale indexed tenant ACL type and status never establish canonical rows counts or facets', {timeout:60_000},async t=>{
  const q='searchstale'+token(),label=(n:number)=>`${q} ${String(n).padStart(2,'0')}`;
  const table=asset(label(0),'table'),view=asset(label(1),'view'),allowed=asset(label(2),'table',{visibility:'restricted',allowed:[consumer]});
  const changed=asset(label(3),'dataset'),hidden=asset(label(4),'secret-only-type',{visibility:'restricted',allowed:[steward]});
  const retired=asset(label(5),'retired-only-type',{status:'retired'}),foreignRow=asset(label(6),'foreign-only-type',{tenantId:foreign});
  const orphan=randomUUID(),rows=[table,view,allowed,changed,hidden,retired,foreignRow];await insert(rows);
  await project(rows.map(row=>({id:row.id,value:document(row,{tenantId:tenant,
    type:row===table?'wrong-index-type':'table',status:row===table?'retired':'active',description:'Stale index text must not replace canonical metadata'})})));
  await project([{id:orphan,value:{tenantId:tenant,id:orphan,name:label(7),qualifiedName:label(7),type:'orphan-only-type',description:'',status:'active',version:1}}]);
  const current=await session(t),outside=await session(t,summit,foreign);
  checkPage(await http({q,limit:100},current.headers,200,t.signal),[table,view,allowed,changed],[table,view,allowed,changed]);
  // Only this unbound synthetic row changes. No seeded ACL, revision or journal
  // is altered; the deliberately stale index remains untouched after this step.
  await scope(tenant,steward,async tx=>{
    await lockTenantLedger(tx,tenant);
    await tx.updateTable('assets').set({visibility:'restricted',allowed_identities:JSON.stringify([steward])}).where('id','=',changed.id).execute();
  });
  const visible=[table,view,allowed],result=await http({q,limit:100},current.headers,200,t.signal);checkPage(result,visible,visible);
  for(const row of [changed,hidden,retired,foreignRow]) assert.equal(JSON.stringify(result).includes(row.id),false);
  for(const type of ['secret-only-type','retired-only-type','foreign-only-type','orphan-only-type','wrong-index-type']) {
    assert.equal(result.facets.some(row=>row.type===type),false);
    assert.deepEqual(await http({q,type,limit:100},current.headers,200,t.signal),{items:[],total:0,nextCursor:null,facets:[]});
  }
  checkPage(await http({q,type:'table',limit:100},current.headers,200,t.signal),[table,allowed],[table,allowed]);
  checkPage(await http({q,type:'view',limit:100},current.headers,200,t.signal),[view],[view]);
  assert.deepEqual(await http({q,limit:100},outside.headers,200,t.signal),{items:[],total:0,nextCursor:null,facets:[]});
  assert.deepEqual(await scope(tenant,consumer,tx=>tx.selectFrom('assets').select('id').where('id','=',foreignRow.id).execute()),[]);
});

test('real cursor continuation reauthenticates deleted expired and missing-membership sessions', {timeout:40_000},async t=>{
  const removed=await session(t),expired=await session(t),noMember=await session(t,consumer,foreign);
  assert.deepEqual(await scope(foreign,summit,tx=>tx.selectFrom('memberships').select('identity_id')
    .where('tenant_id','=',foreign).where('identity_id','=',consumer).execute()),[],'Missing membership is an actual database fact, not injected authority');
  const first=await http({q:narrow,limit:1},removed.headers,200,t.signal);assert.ok(first.nextCursor);checkPage(first,narrowRows.slice(0,1),narrowRows);
  await db.deleteFrom('sessions').where('id_hash','=',removed.auth.sessionHash).execute();
  const deleted=await http({q:narrow,limit:1,cursor:first.nextCursor},removed.headers,401,t.signal);assert.equal(deleted.code,'SESSION_EXPIRED');
  const beforeExpiry=await http({q:narrow,limit:1},expired.headers,200,t.signal);assert.ok(beforeExpiry.nextCursor);
  await db.updateTable('sessions').set({expires_at:new Date(0)}).where('id_hash','=',expired.auth.sessionHash).execute();
  const ended=await http({q:narrow,limit:1,cursor:beforeExpiry.nextCursor},expired.headers,401,t.signal);assert.equal(ended.code,'SESSION_EXPIRED');
  const missing=await http({q:narrow,limit:1},noMember.headers,401,t.signal);assert.equal(missing.code,'MEMBERSHIP_REVOKED');
  for(const value of [deleted,ended,missing]) for(const key of ['items','total','facets','nextCursor']) assert.equal(Object.hasOwn(value,key),false);
  for(const auth of [removed.auth,expired.auth,noMember.auth]) await assert.rejects(searchAssets(auth,{q:narrow,limit:1}),
    error=>error instanceof Problem&&error.status===401&&error.code==='SESSION_EXPIRED');
});

test('real glossary-text search retains canonical visibility before counts and facets', {timeout:40_000},async t=>{
 // These deliberately projected ordinary fixture rows isolate query/ACL behavior;
 // actual approved-term publication/projector execution has its own native gate.
 const alias='approvedalias'+token(),abbreviation='abbreviation'+token(),translation='ترجمة'+token();
 const visible=asset('Visible glossary search fixture'),hidden=asset('Restricted glossary search fixture','view',{visibility:'restricted',allowed:[steward]}),other=asset('Foreign glossary search fixture','view',{tenantId:foreign});
 await insert([visible,hidden,other]);
 await project([visible,hidden,other].map(a=>({id:a.id,value:document(a,{glossaryText:[alias,abbreviation,translation].join('\n')})})));
 const current=await session(t);
 for(const q of [alias,abbreviation,translation]){
  const result=await http({q,limit:100},current.headers,200,t.signal);checkPage(result,[visible],[visible]);assert.equal(result.nextCursor,null);
 }
});
