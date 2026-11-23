// SPDX-License-Identifier: Apache-2.0
/** Functional protocol tests with explicit fake dependencies. These do not
 * qualify PostgreSQL RLS, OpenSearch PIT behavior, HTTP routes or browser use. */
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createHmac} from 'node:crypto';
import {createAssetSearch,ASSET_SEARCH_LIMITS,type AssetSearchClient} from '../../apps/api/src/asset-search.ts';
const id=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const auth={principal:{id:id(1),tenantId:id(2),name:'Synthetic',permissions:['catalog:read']},sessionHash:'a'.repeat(64)};
const key='synthetic-cursor-key-for-unit-tests-only',shards={total:1,successful:1,skipped:0,failed:0};
const hit=(n:number,name=String(n).padStart(8,'0'))=>({_index:'gc-assets-v1',_id:id(n),sort:[name,id(n)]});
const reply=(hits:unknown[]=[],extra:Record<string,unknown>={})=>({_shards:shards,timed_out:false,hits:{hits},...extra});
const json=(value:unknown,status=200)=>new Response(JSON.stringify(value),{status,headers:{'Content-Type':'application/json'}});
type Hit=ReturnType<typeof hit>;
function fixture(options:{hits?:Hit[];allow?:(id:string)=>boolean;type?:(id:string)=>string;permissions?:string[];
  search?:(body:any,index:number)=>unknown|Response;create?:unknown;close?:unknown;expires?:boolean;measure?:number;orderedIds?:string[]}={}){
  const sql:{text:string;values:any[]}[]=[],requests:{path:string;method:string;body:any;signal:AbortSignal;headers:Headers}[]=[],releases:boolean[]=[];
  let now=0,searches=0;
  const client:AssetSearchClient={release(destroy){releases.push(!!destroy);},async query(config){
    sql.push({text:config.text,values:config.values??[]});
    if(config.text.includes('FROM sessions'))return {rows:options.expires===false?[]:[{permissions:options.permissions??['catalog:read'],expires_ms:Date.now()+60000}]};
    if(config.text.startsWith('SELECT $1::double'))return {rows:[{live:true}]};
    if(config.text.startsWith('SELECT a.id,a.type'))return {rows:config.values![1].filter((value:string)=>options.allow?.(value)??true)
      .map((value:string)=>({id:value,type:options.type?.(value)??'table'})).filter((row:{type:string})=>!config.values![3]||row.type===config.values![3])};
    if(config.text.startsWith('SELECT a.id FROM assets'))return {rows:(options.orderedIds??config.values![1]).slice(config.values![5],config.values![5]+config.values![4]).map((id:string)=>({id}))};
    if(config.text.includes('octet_length'))return {rows:config.values![1].map((value:string)=>({id:value,bytes:options.measure??500}))};
    if(config.text.startsWith('SELECT a.*'))return {rows:[...config.values![1]].reverse().map((value:string)=>({id:value,name:value,type:'table',status:'active',metadata:{},version:1}))};
    return {rows:[]};
  }};
  const fetcher:typeof fetch=async(url,init)=>{
    const path=new URL(String(url)).pathname,body=init?.body?JSON.parse(String(init.body)):undefined;
    requests.push({path,method:init?.method??'GET',body,signal:init!.signal as AbortSignal,headers:new Headers(init?.headers)});
    if(init?.method==='DELETE')return options.close instanceof Response?options.close:json(options.close??{pits:[{pit_id:'owned-pit',successful:true}]});
    if(path.endsWith('/point_in_time'))return options.create instanceof Response?options.create:json(options.create??{pit_id:'owned-pit',_shards:shards});
    let response:unknown;
    if(options.search)response=options.search(body,searches++);
    else {const all=options.hits??[];const start=body.search_after?all.findIndex(h=>h._id===body.search_after[1])+1:0;response=reply(all.slice(start,start+body.size));}
    return response instanceof Response?response:json(response);
  };
  return {run:createAssetSearch({connect:async()=>client,fetch:fetcher,searchUrl:'http://search.invalid:9200',cursorKey:key,now:()=>now}),
    client,fetcher,sql,requests,releases,setNow:(v:number)=>{now=v;}};
}
function error(code:string){return (value:any)=>value?.code===code&&!/secret|hidden-name|raw-database-error/.test(value.message);}

test('current snapshot authorization precedes PIT; canonical SQL scopes batches and final hydration retains database order',async()=>{
  const f=fixture({hits:[hit(10),hit(11),hit(12)],allow:value=>value!==id(11),type:value=>value===id(12)?'view':'table'});
  const result=await f.run(auth,{limit:1,q:'orders'});
  assert.equal(result.total,2);assert.deepEqual(result.items.map(x=>x.id),[id(10)]);
  assert.deepEqual(result.facets,[{type:'table',count:1},{type:'view',count:1}]);assert.ok(result.nextCursor);
  assert.match(f.sql[0]!.text,/BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY/);
  const check=f.sql.find(q=>q.text.includes('FROM sessions'))!;assert.deepEqual(check.values,[auth.sessionHash,auth.principal.id,auth.principal.tenantId]);
  const batch=f.sql.find(q=>q.text.startsWith('SELECT a.id,a.type'))!;
  assert.match(batch.text,/a\.tenant_id=\$1::uuid/);assert.match(batch.text,/a\.status='active'/);assert.match(batch.text,/a\.allowed_identities @>/);
  assert.deepEqual(batch.values,[auth.principal.tenantId,[id(10),id(11),id(12)],JSON.stringify([auth.principal.id]),'']);
  const search=f.requests.find(r=>r.path==='/_search')!.body;
  assert.deepEqual(search.query.bool.must[0].multi_match.fields,['name^3','qualifiedName^2','description','glossaryText']);
  assert.equal(search._source,false);assert.equal(search.track_total_hits,false);assert.equal('aggs' in search,false);assert.equal('from' in search,false);
  assert.deepEqual(search.query.bool.filter,[{term:{tenantId:auth.principal.tenantId}}]);assert.deepEqual(f.releases,[false]);
  assert.deepEqual(f.requests.at(-1)?.body,{pit_id:['owned-pit']});
});

test('caller permissions cannot grant revoked membership and unauthorized snapshots never contact search',async()=>{
  for(const options of [{permissions:[]},{expires:false}]){
    const f=fixture(options);await assert.rejects(f.run(auth,{}),error(options.expires===false?'SESSION_EXPIRED':'FORBIDDEN'));
    assert.equal(f.requests.length,0);assert.deepEqual(f.releases,[true]);
  }
  const f=fixture({hits:[hit(10)]});assert.equal((await f.run({...auth,principal:{...auth.principal,permissions:[]}},{})).total,1);
});

test('hidden-only and mixed candidates never enter total, facets or hydrated page',async()=>{
  const f=fixture({hits:[hit(10),hit(11),hit(12)],allow:value=>value===id(12)});
  const value=await f.run(auth,{});assert.equal(value.total,1);assert.deepEqual(value.facets,[{type:'table',count:1}]);assert.deepEqual(value.items.map(x=>x.id),[id(12)]);
  const hidden=fixture({hits:[hit(10)],allow:()=>false});assert.deepEqual(await hidden.run(auth,{}),{items:[],total:0,nextCursor:null,facets:[]});
  assert.equal(hidden.sql.some(q=>q.text.startsWith('SELECT a.*')),false);
});

test('type filtering uses canonical values rather than stale indexed type or raw search aggregations',async()=>{
  const f=fixture({hits:[hit(10),hit(11)],type:value=>value===id(10)?'table':'view'});
  const value=await f.run(auth,{type:'view'});assert.equal(value.total,1);assert.deepEqual(value.items.map(x=>x.id),[id(11)]);
  assert.deepEqual(value.facets,[{type:'view',count:1}]);
});

test('empty UI query fields and cursor select the same authorized first page as absent fields',async()=>{
  const f=fixture({hits:[hit(10),hit(11),hit(12)],allow:value=>value!==id(11),type:value=>value===id(12)?'view':'table'});
  const first=await f.run(auth,{limit:1});
  const ui=await f.run(auth,{q:'',type:'',limit:1,cursor:''});
  assert.deepEqual(ui,first);assert.equal(ui.total,2);assert.deepEqual(ui.items.map(row=>row.id),[id(10)]);
  assert.deepEqual(ui.facets,[{type:'table',count:1},{type:'view',count:1}]);assert.ok(ui.nextCursor);
  const next=await f.run(auth,{q:'',type:'',limit:1,cursor:ui.nextCursor});
  assert.deepEqual(next.items.map(row=>row.id),[id(12)]);assert.equal(next.nextCursor,null);
  assert.equal(next.total,2);assert.deepEqual(next.facets,first.facets);
  const acquisitions=f.sql.length;
  for(const cursor of [' ','\t','\n','.',ui.nextCursor+' '])await assert.rejects(f.run(auth,{q:'',type:'',limit:1,cursor}),error('CURSOR_INVALID'));
  assert.equal(f.sql.length,acquisitions,'Nonempty malformed cursors still refuse before database acquisition');
});

test('complete10001 matching traversal and logical offset beyond9000 preserve complete totals and usable pagination',async()=>{
  const f=fixture({hits:Array.from({length:10001},(_,i)=>hit(i+10))});
  const first=await f.run(auth,{limit:100});assert.equal(first.total,10001);assert.equal(first.items.length,100);
  const encoded=first.nextCursor!.split('.')[0]!,payload=JSON.parse(Buffer.from(encoded,'base64url').toString());payload.offset=9001;
  const raw=Buffer.from(JSON.stringify(payload)).toString('base64url'),cursor=raw+'.'+createHmac('sha256',key).update(raw).digest('base64url');
  const page=await f.run(auth,{limit:100,cursor});assert.equal(page.total,10001);assert.equal(page.items[0]!.id,id(9011));assert.ok(page.nextCursor);
  assert.ok(f.requests.filter(r=>r.path==='/_search').length>20);assert.ok(f.sql.filter(q=>q.text.startsWith('SELECT a.id,a.type')).every(q=>q.values[1].length<=500));
  assert.ok(f.sql.filter(q=>q.text.startsWith('SELECT a.*')).every(q=>q.values[1].length<=100));
});

test('a narrow query has no authorized tenant population enumeration',async()=>{
  const f=fixture({hits:[hit(10)]});assert.equal((await f.run(auth,{q:'unique-name'})).total,1);
  assert.ok(f.sql.filter(q=>q.text.includes('FROM assets')).every(q=>q.text.includes('a.id=ANY($2::uuid[])')));
});

test('exact100000 candidates permit one terminal probe;100001 refuses without counts',async()=>{
  for(const extra of [false,true]){
    const f=fixture({allow:()=>false,search:(body,index)=>index===200?reply(extra?[hit(100010)]:[]):reply(Array.from({length:500},(_,j)=>hit(index*500+j+10)))});
    if(extra)await assert.rejects(f.run(auth,{}),error('SEARCH_PROFILE_LIMIT'));
    else assert.equal((await f.run(auth,{})).total,0);
    assert.equal(f.requests.filter(r=>r.path==='/_search').length,201);
    assert.equal(f.requests.filter(r=>r.path==='/_search').at(-1)!.body.size,1);
    assert.equal(f.requests.at(-1)!.method,'DELETE');
  }
});

test('strict cursors reject tampering, unknown fields, noncanonical encoding and every binding change before acquisition',async()=>{
  const f=fixture({hits:[hit(10),hit(11)]});const first=await f.run(auth,{q:'orders',type:'table',limit:1});const good=first.nextCursor!;
  const p=JSON.parse(Buffer.from(good.split('.')[0]!,'base64url').toString());
  const sign=(raw:string)=>{const b=Buffer.from(raw).toString('base64url');return b+'.'+createHmac('sha256',key).update(b).digest('base64url');};
  for(const cursor of [good+'x',good+'.extra',good.replace('.','=.'),sign(JSON.stringify({...p,extra:1})),sign('{"v":1,"v":1,"binding":'+JSON.stringify(p.binding)+',"offset":1}'),
    sign(JSON.stringify({...p,offset:-1})),sign(JSON.stringify({...p,offset:1.5})),sign(JSON.stringify({...p,offset:Number.MAX_SAFE_INTEGER+1})),sign(' '+JSON.stringify(p))]){
    await assert.rejects(f.run(auth,{q:'orders',type:'table',limit:1,cursor}),error('CURSOR_INVALID'));
  }
  for(const changed of [{q:'different',type:'table',limit:1},{q:'orders',type:'view',limit:1},{q:'orders',type:'table',limit:2},{q:'orders',type:'table',limit:1,sort:'name-desc' as const},{q:'orders',type:'table',limit:1,sort:'updated' as const}])await assert.rejects(f.run(auth,{...changed,cursor:good}),error('CURSOR_INVALID'));
  for(const principal of [{...auth.principal,id:id(3)},{...auth.principal,tenantId:id(3)}])await assert.rejects(f.run({...auth,principal},{q:'orders',type:'table',limit:1,cursor:good}),error('CURSOR_INVALID'));
  assert.equal(f.requests.filter(r=>r.method==='POST'&&r.path.endsWith('/point_in_time')).length,1);
});

test('partial/timed-out/early search, malformed hits, duplicate IDs and nonadvancing sort all refuse and close owned PIT',async()=>{
  const invalid=[reply([],{timed_out:true}),reply([],{terminated_early:true}),reply([],{_shards:{...shards,failed:1}}),
    reply([{...hit(10),_source:{name:'hidden-name'}}]),reply([{...hit(10),_index:'other-tenant-index'}]),
    reply([hit(10),hit(10)]),reply([hit(11),hit(10)]),reply([{...hit(10),sort:['name',id(11)]}]),
    reply([{...hit(10),sort:['name',id(10),1]}]),reply(Array.from({length:501},(_,i)=>hit(i+10)))];
  for(const response of invalid){const f=fixture({search:()=>response});await assert.rejects(f.run(auth,{}),error('SEARCH_UNAVAILABLE'));assert.equal(f.requests.at(-1)?.method,'DELETE');assert.deepEqual(f.releases,[true]);}
});

test('partial PIT creation is closed and failed or mismatched deletion never returns a successful answer',async()=>{
  const partial=fixture({create:{pit_id:'owned-pit',_shards:{...shards,failed:1}}});await assert.rejects(partial.run(auth,{}),error('SEARCH_UNAVAILABLE'));assert.equal(partial.requests.at(-1)?.method,'DELETE');
  for(const close of [{pits:[{pit_id:'owned-pit',successful:false}]},{pits:[{pit_id:'unrelated',successful:true}]},{pits:[]}]){
    const f=fixture({close});await assert.rejects(f.run(auth,{}),error('SEARCH_UNAVAILABLE'));
  }
});

test('PIT creation search and cleanup request identity encoding and accept exact identity byte lengths',async()=>{
  const encoded=(value:unknown,encoding?:string)=>{
    const body=JSON.stringify(value);return new Response(body,{headers:{'Content-Type':'application/json',
      'Content-Length':String(Buffer.byteLength(body)),...(encoding?{'Content-Encoding':encoding}:{})}});
  };
  for(const encoding of [undefined,'identity','IDENTITY']){
    const f=fixture({create:encoded({pit_id:'owned-pit',_shards:shards},encoding),
      search:()=>encoded(reply([hit(10,'مبيعات')]),encoding),close:encoded({pits:[{pit_id:'owned-pit',successful:true}]},encoding)});
    assert.equal((await f.run(auth,{})).total,1);assert.equal(f.requests.length,3);
    assert.ok(f.requests.every(request=>request.headers.get('Accept-Encoding')==='identity'));
  }
});

test('unexpected response encodings refuse before reading any body in every PIT phase',async()=>{
  for(const phase of ['create','search','close'] as const)for(const encoding of ['gzip','br','deflate','identity, gzip','']){
    let reads=0,cancelled=false;
    // A decoded fetch body may retain a compressed wire Content-Length. It
    // must be refused by encoding, before size checks or JSON materialization.
    const response=new Response(new ReadableStream<Uint8Array>({pull(){reads++;},cancel(){cancelled=true;}},{highWaterMark:0}),
      {headers:{'Content-Type':'application/json','Content-Encoding':encoding,'Content-Length':'252'}});
    const f=fixture(phase==='search'?{search:()=>response}:{[phase]:response});
    await assert.rejects(f.run(auth,{}),error('SEARCH_UNAVAILABLE'));
    assert.equal(reads,0);assert.equal(cancelled,true);
    if(phase==='create')assert.equal(f.requests.length,1,'An unparsed PIT identifier cannot safely be invented for cleanup');
    else assert.equal(f.requests.at(-1)?.method,'DELETE');
    assert.deepEqual(f.releases,[phase!=='close']);
  }
});

test('identity responses still reject declared length mismatch and actual streamed byte overflow',async()=>{
  const body=JSON.stringify(reply([]));
  const mismatch=fixture({search:()=>new Response(body,{headers:{'Content-Type':'application/json',
    'Content-Encoding':'identity','Content-Length':String(Buffer.byteLength(body)-1)}})});
  await assert.rejects(mismatch.run(auth,{}),error('SEARCH_UNAVAILABLE'));
  const overflow=fixture({search:()=>new Response(new Uint8Array(ASSET_SEARCH_LIMITS.responseBytes+1),
    {headers:{'Content-Type':'application/json','Content-Encoding':'identity'}})});
  await assert.rejects(overflow.run(auth,{}),error('SEARCH_PROFILE_LIMIT'));
  assert.equal(mismatch.requests.at(-1)?.method,'DELETE');assert.equal(overflow.requests.at(-1)?.method,'DELETE');
});

test('response byte, strict JSON/UTF8 and facet/hydration budgets fail without partial output',async()=>{
  for(const response of [new Response('x',{headers:{'Content-Type':'application/json','Content-Length':'1048577'}}),
    new Response(new Uint8Array([0xff]),{headers:{'Content-Type':'application/json'}}),
    new Response('{"timed_out":false,"timed_out":true}',{headers:{'Content-Type':'application/json'}}),
    new Response('hidden-name',{status:503,headers:{'Content-Type':'text/plain'}})]){
    const f=fixture({search:()=>response});await assert.rejects(f.run(auth,{}),(e:any)=>['SEARCH_PROFILE_LIMIT','SEARCH_UNAVAILABLE'].includes(e.code)&&!e.message.includes('hidden-name'));
  }
  const facet=fixture({hits:Array.from({length:257},(_,i)=>hit(i+10)),type:value=>value});await assert.rejects(facet.run(auth,{}),error('SEARCH_PROFILE_LIMIT'));
  const large=fixture({hits:[hit(10)],measure:ASSET_SEARCH_LIMITS.hydrationBytes+1});await assert.rejects(large.run(auth,{}),error('SEARCH_PROFILE_LIMIT'));
  assert.equal(large.sql.some(q=>q.text.startsWith('SELECT a.*')),false);
});

test('original deadline is not reset per page and query failures destroy the client instead of returning active work to pool',async()=>{
  let f:ReturnType<typeof fixture>;f=fixture({search:()=>{f.setNow(15001);return reply([]);}});
  await assert.rejects(f.run(auth,{}),error('SEARCH_PROFILE_LIMIT'));assert.deepEqual(f.releases,[true]);assert.equal(f.requests.at(-1)?.method,'DELETE');
  const g=fixture();g.client.query=async()=>{throw new Error('raw-database-error');};await assert.rejects(g.run(auth,{}),error('SEARCH_UNAVAILABLE'));assert.deepEqual(g.releases,[true]);
});

test('aborted response cancellation cannot hang on a never-settling stream hook',async()=>{
  let cancelled=false;
  const response=new Response(new ReadableStream<Uint8Array>({cancel(){cancelled=true;return new Promise(()=>{});}}),{headers:{'Content-Type':'text/plain'}});
  const f=fixture({search:()=>response});
  await assert.rejects(f.run(auth,{}),error('SEARCH_UNAVAILABLE'));assert.equal(cancelled,true);
  assert.equal(f.requests.find(r=>r.path==='/_search')!.signal.aborted,true);assert.deepEqual(f.releases,[true]);
});

test('owned PIT deletion has a separate actual bounded deadline and cannot turn timeout into success',async()=>{
  const f=fixture();let aborted=false;
  const actual=createAssetSearch({connect:async()=>f.client,searchUrl:'http://search.invalid:9200',cursorKey:key,fetch:async(input,init)=>{
    if(init?.method!=='DELETE')return f.fetcher(input,init);
    return new Promise<Response>((_,reject)=>{init.signal!.addEventListener('abort',()=>{aborted=true;reject(new Error('synthetic cleanup abort'));},{once:true});});
  }});
  const started=performance.now();await assert.rejects(actual(auth,{}),error('SEARCH_UNAVAILABLE'));
  assert.equal(aborted,true);assert.ok(performance.now()-started<4000);assert.deepEqual(f.releases,[false]);
});

test('late pool acquisition is disposed after original deadline, without opening a transaction',async()=>{
  const f=fixture();
  // A clock that advances during the actual acquisition, not a shorter test profile.
  let tick=0;const actual=createAssetSearch({connect:async()=>{tick=15001;return f.client;},fetch:f.fetcher,searchUrl:'http://search.invalid:9200',cursorKey:key,now:()=>tick});
  await assert.rejects(actual(auth,{}),error('SEARCH_PROFILE_LIMIT'));assert.deepEqual(f.releases,[true]);assert.equal(f.sql.length,0);assert.equal(f.requests.length,0);
});


test('canonical page order wins over index order and unexpected ordered identifiers fail closed',async()=>{
  const f=fixture({hits:[hit(10),hit(11),hit(12)],orderedIds:[id(12),id(10),id(11)]});
  const page=await f.run(auth,{sort:'updated',limit:2});assert.deepEqual(page.items.map(r=>r.id),[id(12),id(10)]);
  const ordered=f.sql.find(q=>q.text.startsWith('SELECT a.id FROM assets'))!;
  assert.match(ordered.text,/ORDER BY a.updated_at DESC,a.id ASC LIMIT \$5::integer OFFSET \$6::integer/);
  assert.deepEqual(ordered.values,[auth.principal.tenantId,[id(10),id(11),id(12)],JSON.stringify([auth.principal.id]),'',2,0]);
  for(const orderedIds of [[id(99)],[id(10),id(10)],[]]){
    const bad=fixture({hits:[hit(10),hit(11)],orderedIds});await assert.rejects(bad.run(auth,{}),error('SEARCH_UNAVAILABLE'));
    assert.equal(bad.sql.some(q=>q.text.startsWith('SELECT a.*')),false);
  }
  for(const sort of ['', 'random', 'name; DROP TABLE assets', [], {}]){
    const invalid=fixture();await assert.rejects(invalid.run(auth,{sort:sort as never}),error('VALIDATION_FAILED'));
    assert.equal(invalid.sql.length,0);assert.equal(invalid.requests.length,0);
  }
});
