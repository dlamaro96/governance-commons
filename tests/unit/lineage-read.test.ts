// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {Kysely,DummyDriver,PostgresAdapter,PostgresIntrospector,PostgresQueryCompiler,type CompiledQuery,type DatabaseConnection,type QueryResult} from 'kysely';
import type {Tx} from '../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../packages/authz/src/index.ts';
import {signedCursor} from '../../packages/domain/src/cursor.ts';
import {getAssetLineage,parseLineageQuery,lineageReadFailure} from '../../packages/domain/src/lineage-read.ts';
import type {LineageQuery} from '../../packages/domain/src/lineage-contracts.ts';

const ids={tenant:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',actor:'10000000-0000-4000-8000-000000000001',source:'20000000-0000-4000-8000-000000000001',run:'30000000-0000-4000-8000-000000000001',a:'40000000-0000-4000-8000-000000000001',b:'40000000-0000-4000-8000-000000000002',c:'40000000-0000-4000-8000-000000000003'};
const principal:Principal={tenantId:ids.tenant,id:ids.actor,name:'Synthetic reader',permissions:['catalog:read']};
const asset=(id:string,type='view')=>({id,name:`asset-${id.slice(-1)}`,qualified_name:`synthetic.public.asset_${id.slice(-1)}`,type,version:4,source_id:ids.source,connector_id:'postgresql',accepted_scan_generation:'2'});
const observed={id:ids.run,source_id:ids.source,scan_generation:'2',source_version:'17.11',observed_at:'2026-01-01T00:00:00.000Z',recorded_at:'2026-01-01T00:00:01.000Z'};
const edge=(n:number,up:string,down:string)=>({id:n.toString(16).padStart(64,'0'),upstream_asset_id:up,upstream_version:2,downstream_asset_id:down,downstream_version:3,referenced_attribute_numbers:[0,2],evidence_hash:'d'.repeat(64)});
const code=(expected:string)=>(error:unknown)=>error instanceof Problem&&error.code===expected;
const unused={} as Tx;

/** Real SQL compilation with controlled rows; this is not PostgreSQL/RLS qualification. */
function fixture(options:{root?:ReturnType<typeof asset>|null;observation?:typeof observed|null;edges?:ReturnType<typeof edge>[];gaps?:{asset_id:string;gaps:unknown}[];revokeAt?:number}={}){
 const calls:CompiledQuery[]=[],root=options.root===undefined?asset(ids.a):options.root;let authorizations=0;
 const connection:DatabaseConnection={async executeQuery<R>(query:CompiledQuery):Promise<QueryResult<R>>{
  calls.push(query);let rows:unknown[]=[];
  if(query.sql.includes('from "memberships"'))rows=++authorizations===(options.revokeAt??-1)?[]:[{permissions:['catalog:read']}];
  else if(query.sql.includes('LEFT JOIN public.sources'))rows=root?[root]:[];
  else if(query.sql.includes('FROM public.lineage_edge_observations'))rows=options.edges??[edge(1,ids.a,ids.b),edge(2,ids.b,ids.c)];
  else if(query.sql.includes('CROSS JOIN LATERAL'))rows=options.gaps??[];
  else if(query.sql.includes('FROM public.lineage_observations'))rows=options.observation===null?[]:[options.observation??observed];
  else if(query.sql.includes('FROM public.assets a')){
   const wanted=query.parameters.find(p=>Array.isArray(p)) as string[];
   rows=wanted.map(id=>root?.id===id?root:asset(id));
  }
  return {rows:rows as R[]};
 },async *streamQuery<R>():AsyncIterableIterator<QueryResult<R>>{throw new Error('No streaming in this unit fixture');}};
 class Driver extends DummyDriver{override async acquireConnection(){return connection;}}
 const db=new Kysely<Record<string,any>>({dialect:{createAdapter:()=>new PostgresAdapter(),createDriver:()=>new Driver(),createIntrospector:db=>new PostgresIntrospector(db),createQueryCompiler:()=>new PostgresQueryCompiler()}});
 return {calls,run:(query:LineageQuery={},p=principal,id=ids.a)=>db.transaction().execute(tx=>getAssetLineage(tx,p,id,query)),close:()=>db.destroy()};
}
async function secret<T>(fn:()=>Promise<T>){const old=process.env.SESSION_KEY;process.env.SESSION_KEY='synthetic-lineage-reader-test-key-at-least-32';try{return await fn();}finally{if(old===undefined)delete process.env.SESSION_KEY;else process.env.SESSION_KEY=old;}}

test('lineage rejects ambiguous raw URL selectors and non-data query properties',async()=>{
 for(const query of ['?depth=01','?depth=1&depth=2','?direction=upstream&direction=both','?limit=1.0','?limit=1e2','?depth=-1','?depth=7','?limit=101','?cursor=','?unknown=true','?direction=in','?limit=Infinity'])assert.throws(()=>parseLineageQuery('/api/v1/assets/x/lineage'+query),code('LINEAGE_PAGE_INVALID'));
 assert.deepEqual(parseLineageQuery('/api/v1/assets/x/lineage?depth=2&direction=upstream&limit=10'),{depth:2,direction:'upstream',limit:10});
 for(const query of [null,[],{depth:'1'},{depth:null},{limit:0},{direction:null},{cursor:'x'.repeat(1025)},{unknown:1}])await assert.rejects(getAssetLineage(unused,principal,ids.a,query as LineageQuery),code('LINEAGE_PAGE_INVALID'));
 let getter=0;const query=Object.defineProperty({},'depth',{enumerable:true,get(){getter++;return 1;}});
 await assert.rejects(getAssetLineage(unused,principal,ids.a,query),code('LINEAGE_PAGE_INVALID'));assert.equal(getter,0);
});

test('lineage traverses only authorized adjacency with exact direction, depth and cycle bounds',()=>secret(async()=>{
 const f=fixture({edges:[edge(1,ids.a,ids.b),edge(2,ids.b,ids.c),edge(3,ids.c,ids.a)]});
 try{
  const down=await f.run({direction:'downstream',depth:1});assert.deepEqual(down.edges.map(e=>e.id),[edge(1,ids.a,ids.b).id]);assert.deepEqual(down.nodes.map(n=>n.id),[ids.a,ids.b]);
  const up=await f.run({direction:'upstream',depth:1});assert.deepEqual(up.edges.map(e=>e.id),[edge(3,ids.c,ids.a).id]);
  const cycle=await f.run({direction:'downstream',depth:6});assert.equal(cycle.edges.length,3);assert.equal(cycle.nodes.length,3);assert.equal(cycle.nextCursor,null);
  assert.equal(cycle.edges[0].evidencePointer,`lineage:${ids.run}:${cycle.edges[0].id}`);assert.equal(cycle.edges[0].confidence,null);assert.equal(cycle.edges[0].sourceCodeAvailability,'not-collected');assert.equal(cycle.edges[0].upstreamVersion,2);assert.equal(cycle.nodes[0].version,4);
 }finally{await f.close();}
}));

test('lineage SQL binds tenant, source, current generation and both endpoint ACLs before graph assembly',()=>secret(async()=>{
 const f=fixture({gaps:[{asset_id:ids.a,gaps:['OUT_OF_SCOPE_RELATION']}]});
 try{
  const result=await f.run({depth:2,limit:1});assert.equal(result.edges.length,1);assert.ok(result.nextCursor);assert.deepEqual(result.gaps,[{assetId:ids.a,code:'OUT_OF_SCOPE_RELATION'}]);
  const edges=f.calls.find(q=>q.sql.includes('FROM public.lineage_edge_observations'))!;
  for(const clause of ['u.tenant_id=e.tenant_id','d.tenant_id=e.tenant_id','u.source_id=e.source_id','d.source_id=e.source_id',"u.status='active'","d.status='active'",'"u"."allowed_identities"','"d"."allowed_identities"'])assert.ok(edges.sql.includes(clause),clause);
  assert.ok(edges.parameters.includes(ids.tenant));assert.ok(edges.parameters.includes(ids.source));assert.equal(edges.parameters.filter(v=>v===JSON.stringify([ids.actor])).length,2);assert.equal(edges.parameters.at(-1),5001);
  const observation=f.calls.find(q=>q.sql.includes('s.accepted_scan_generation=o.scan_generation'))!;assert.ok(observation);
  const gaps=f.calls.find(q=>q.sql.includes('CROSS JOIN LATERAL'))!;assert.ok(gaps.sql.includes('"a"."allowed_identities"'));assert.ok(gaps.sql.includes('a.source_id=o.source_id'));
  assert.equal('payload'in result,false);assert.equal(JSON.stringify(result).includes('viewExternalId'),false);assert.equal(JSON.stringify(result).includes('rewriteOid'),false);
 }finally{await f.close();}
}));

test('lineage paginates without duplicating edges and refuses cursor selector or signature changes',()=>secret(async()=>{
 const f=fixture();
 try{
  const first=await f.run({depth:2,limit:1}),cursor=first.nextCursor!;assert.ok(cursor.length<=1024);
  const second=await f.run({depth:2,limit:1,cursor});assert.deepEqual(second.edges.map(e=>e.id),[edge(2,ids.b,ids.c).id]);assert.equal(second.nextCursor,null);
  for(const [p,id,query]of [[{...principal,id:ids.b},ids.a,{depth:2,limit:1,cursor}],[{...principal,tenantId:ids.b},ids.a,{depth:2,limit:1,cursor}],[principal,ids.b,{depth:2,limit:1,cursor}],[principal,ids.a,{depth:1,limit:1,cursor}],[principal,ids.a,{depth:2,limit:2,cursor}],[principal,ids.a,{direction:'upstream',depth:2,limit:1,cursor}]] as const)
   await assert.rejects(getAssetLineage(unused,p,id,query),code('LINEAGE_PAGE_INVALID'));
  const codec=signedCursor(process.env.SESSION_KEY,'postgresql-lineage-v1'),payload=codec.decode(cursor) as Record<string,unknown>;
  for(const value of [{...payload,extra:1},{...payload,v:2},{...payload,generation:'02'},{...payload,last:'A'.repeat(64)},{...payload,fence:'x'},Object.values(payload)])await assert.rejects(getAssetLineage(unused,principal,ids.a,{depth:2,limit:1,cursor:codec.encode(value)}),code('LINEAGE_PAGE_INVALID'));
  const altered=cursor.slice(0,-1)+(cursor.at(-1)==='A'?'B':'A');await assert.rejects(getAssetLineage(unused,principal,ids.a,{depth:2,limit:1,cursor:altered}),code('LINEAGE_PAGE_INVALID'));
 }finally{await f.close();}
}));

test('lineage cursor rechecks current generation and visible graph after grant changes',()=>secret(async()=>{
 const first=fixture(),next=fixture({observation:{...observed,scan_generation:'3'}}),revoked=fixture({edges:[edge(1,ids.a,ids.b)]}),legacy=fixture({observation:null});
 try{
  const cursor=(await first.run({depth:2,limit:1})).nextCursor!;
  for(const f of [next,revoked,legacy])await assert.rejects(f.run({depth:2,limit:1,cursor}),code('LINEAGE_GRAPH_STALE'));
 }finally{for(const f of [first,next,revoked,legacy])await f.close();}
}));

test('lineage distinguishes missing collection and unsupported roots; hidden roots disclose no observations',()=>secret(async()=>{
 const absent=fixture({observation:null}),unsupported=fixture({root:asset(ids.a,'column')}),hidden=fixture({root:null});
 try{
  assert.equal((await absent.run()).coverage,'NOT_COLLECTED');assert.equal((await unsupported.run()).coverage,'UNSUPPORTED');
  await assert.rejects(hidden.run(),code('LINEAGE_ASSET_NOT_FOUND'));
  for(const f of [unsupported,hidden])assert.equal(f.calls.some(q=>q.sql.includes('FROM public.lineage_observations')),false);
 }finally{for(const f of [absent,unsupported,hidden])await f.close();}
}));

test('lineage refuses current membership revocation both before reads and before response',()=>secret(async()=>{
 for(const revokeAt of [1,3]){const f=fixture({revokeAt});try{await assert.rejects(f.run(),code('FORBIDDEN'));if(revokeAt===1)assert.equal(f.calls.some(q=>q.sql.includes('FROM public.assets')),false);}finally{await f.close();}}
}));

test('lineage refuses oversized or corrupt visible evidence instead of truncating it',()=>secret(async()=>{
 const oversized=fixture({edges:Array.from({length:5001},(_,i)=>edge(i+1,ids.a,ids.b))}),corrupt=fixture({edges:[{...edge(1,ids.a,ids.b),referenced_attribute_numbers:[2,1]}]}),badGap=fixture({gaps:[{asset_id:ids.a,gaps:['untrusted secret text']}]}),hiddenGap=fixture({gaps:[{asset_id:ids.c,gaps:['OUT_OF_SCOPE_RELATION']}]});
 try{
  await assert.rejects(oversized.run(),code('LINEAGE_PROFILE_LIMIT'));await assert.rejects(corrupt.run(),code('LINEAGE_STORAGE_INVALID'));await assert.rejects(badGap.run(),code('LINEAGE_STORAGE_INVALID'));await assert.rejects(hiddenGap.run(),code('LINEAGE_STORAGE_INVALID'));
  assert.equal(oversized.calls.some(q=>q.sql.includes('CROSS JOIN LATERAL')),false);
 }finally{for(const f of [oversized,corrupt,badGap,hiddenGap])await f.close();}
}));

test('lineage returns only page endpoints and their gap codes',()=>secret(async()=>{
 const f=fixture({gaps:[{asset_id:ids.a,gaps:[]},{asset_id:ids.b,gaps:['OPAQUE_ROUTINE_DEPENDENCY']},{asset_id:ids.c,gaps:['OUT_OF_SCOPE_RELATION']}]});
 try{const page=await f.run({depth:2,limit:1});assert.deepEqual(page.nodes.map(n=>n.id),[ids.a,ids.b]);assert.deepEqual(page.gaps,[{assetId:ids.b,code:'OPAQUE_ROUTINE_DEPENDENCY'}]);assert.equal(JSON.stringify(page).includes('OUT_OF_SCOPE_RELATION'),false);}finally{await f.close();}
}));

test('lineage translates bounded SQL contention without exposing driver diagnostics',()=>{
 for(const sqlCode of ['57014','55P03','40P01','40001']){const mapped=lineageReadFailure({code:sqlCode,message:'private driver text'});assert.ok(code('LINEAGE_RETRY')(mapped));assert.equal(String(mapped).includes('private driver text'),false);}
 const original=new Problem(404,'LINEAGE_ASSET_NOT_FOUND','Unavailable');assert.equal(lineageReadFailure(original),original);
});
