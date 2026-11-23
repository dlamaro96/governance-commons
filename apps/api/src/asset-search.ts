// SPDX-License-Identifier: Apache-2.0
import {createHash,createHmac,timingSafeEqual} from 'node:crypto';
import {pool} from '../../../packages/db/src/index.ts';
import {Problem} from '../../../packages/authz/src/index.ts';
import {parseBoundedJSONEnvelope} from '../../../packages/domain/src/model.ts';
import {readProtectedSession,type Auth} from './security.ts';
import {assetView} from './repository.ts';

export type AssetSearchQuery={q?:string;type?:string;limit?:number;cursor?:string;sort?:'name'|'name-desc'|'updated'};
type SearchAuth=Pick<Auth,'principal'|'sessionHash'>;
type Result={items:ReturnType<typeof assetView>[];total:number;nextCursor:string|null;facets:{type:string;count:number}[]};
/** Per-query execution profile, not a maximum tenant population or capacity claim. */
export const ASSET_SEARCH_LIMITS=Object.freeze({batch:500,candidates:100_000,pages:200,
  responseBytes:1_048_576,hydrationBytes:4_194_304,facetKeys:256,facetResults:30,
  wallMs:15_000,cleanupMs:2_000,pitBytes:16_384,retainedPitBytes:262_144});
const INDEX='gc-assets-v1',UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const unavailable=()=>new Problem(503,'SEARCH_UNAVAILABLE','Search is temporarily unavailable. Direct asset links remain available.');
const limited=()=>new Problem(422,'SEARCH_PROFILE_LIMIT','This search exceeds the current bounded execution profile. Narrow the search and try again.');
const badCursor=()=>new Problem(400,'CURSOR_INVALID','This page cursor is invalid or belongs to another search.');
const object=(v:unknown):v is Record<string,any>=>v!==null&&typeof v==='object'&&!Array.isArray(v);
const text=(v:unknown,max:number):v is string=>typeof v==='string'&&Buffer.byteLength(v)<=max&&Buffer.from(v,'utf8').toString('utf8')===v;
const integer=(v:unknown):v is number=>typeof v==='number'&&Number.isSafeInteger(v)&&v>=0;

/** Trusted construction seam for protocol unit tests. No request/config value
 * can supply these capabilities; the exported production function binds them. */
export interface AssetSearchClient {
  query(config:{text:string;values?:any[];query_timeout:number}):Promise<{rows:any[]}>;
  release(destroy?:boolean):void;
}
export interface AssetSearchDependencies {
  connect():Promise<AssetSearchClient>;
  fetch:typeof fetch;
  searchUrl:string;
  cursorKey:string;
  now?:()=>number;
}

class Budget {
  readonly controller=new AbortController();
  readonly until:number;
  private readonly timer:ReturnType<typeof setTimeout>;
  constructor(readonly now:()=>number,ms:number){this.until=now()+ms;this.timer=setTimeout(()=>this.controller.abort(),ms);}
  remaining(){const left=this.until-this.now();if(left<=0||this.controller.signal.aborted){this.controller.abort();throw limited();}return Math.max(1,Math.floor(left));}
  async wait<T>(promise:Promise<T>):Promise<T>{
    // Observe even a synchronously expired acquisition; its owner handles late
    // resource disposal. Never leave a rejected underlying promise unobserved.
    promise.catch(()=>{});
    this.remaining();
    const signal=this.controller.signal;
    let rejectAbort:()=>void=()=>{};
    const abort=new Promise<never>((_,reject)=>{rejectAbort=()=>reject(limited());signal.addEventListener('abort',rejectAbort,{once:true});});
    try {const value=await Promise.race([promise,abort]);this.remaining();return value;}
    finally {signal.removeEventListener('abort',rejectAbort);}
  }
  stop(){clearTimeout(this.timer);}
}

function queryInput(query:AssetSearchQuery){
  if(!object(query)||Object.keys(query).some(k=>!['q','type','limit','cursor','sort'].includes(k))
    ||query.q!==undefined&&(!text(query.q,800)||Array.from(query.q).length>200)
    ||query.type!==undefined&&(!text(query.type,256)||Array.from(query.type).length>64)
    ||query.limit!==undefined&&(!integer(query.limit)||query.limit<1||query.limit>100)
    ||query.cursor!==undefined&&!text(query.cursor,2048)
    ||query.sort!==undefined&&!['name','name-desc','updated'].includes(query.sort))throw new Problem(400,'VALIDATION_FAILED','Check the submitted search fields.');
  // The catalog serializes its first page as cursor=. Only that exact empty
  // value is absence; every nonempty cursor still requires its bound signature.
  return {q:query.q??'',type:query.type??'',limit:query.limit??50,cursor:query.cursor===''?undefined:query.cursor,sort:query.sort??'name'};
}
function binding(auth:SearchAuth,q:ReturnType<typeof queryInput>){
  return createHash('sha256').update(JSON.stringify([auth.principal.tenantId,auth.principal.id,q.q,q.type,q.limit,q.sort])).digest('hex');
}
function cursorRead(input:string|undefined,bound:string,key:string){
  if(input===undefined)return 0;
  try {
    const parts=input.split('.');if(parts.length!==2||parts.some(s=>!s||!/^[A-Za-z0-9_-]+$/.test(s)))throw badCursor();
    const [encoded,signature]=parts,bytes=Buffer.from(encoded!,'base64url'),sig=Buffer.from(signature!,'base64url');
    if(bytes.toString('base64url')!==encoded||sig.toString('base64url')!==signature||sig.length!==32)throw badCursor();
    const expected=createHmac('sha256',key).update(encoded!).digest();if(!timingSafeEqual(sig,expected))throw badCursor();
    const raw=new TextDecoder('utf-8',{fatal:true}).decode(bytes),v=JSON.parse(raw);
    if(!object(v)||v.v!==1||v.binding!==bound||!integer(v.offset)||Object.is(v.offset,-0)
      ||JSON.stringify({v:1,binding:bound,offset:v.offset})!==raw)throw badCursor();
    return v.offset as number;
  } catch {throw badCursor();}
}
function cursorWrite(offset:number,bound:string,key:string){
  const payload=Buffer.from(JSON.stringify({v:1,binding:bound,offset})).toString('base64url');
  return payload+'.'+createHmac('sha256',key).update(payload).digest('base64url');
}
function shards(v:unknown){
  if(!object(v)||!integer(v.total)||v.total<1||v.total>1024||!integer(v.successful)
    ||v.successful!==v.total||v.failed!==0||!integer(v.skipped)||v.skipped>v.total)throw unavailable();
}
type Hit={id:string;sort:[string,string]};
function compare(a:[string,string],b:[string,string]){return Buffer.compare(Buffer.from(a[0]),Buffer.from(b[0]))||Buffer.compare(Buffer.from(a[1]),Buffer.from(b[1]));}

export function createAssetSearch(deps:AssetSearchDependencies){
  return async function run(auth:SearchAuth,query:AssetSearchQuery):Promise<Result>{
    const now=deps.now??(()=>performance.now()),budget=new Budget(now,ASSET_SEARCH_LIMITS.wallMs);
    let client:AssetSearchClient|undefined,released=false,committed=false,failed:unknown,result:Result|undefined;
    const pits=new Set<string>();let pitBytes=0;
    const release=(destroy:boolean)=>{if(client&&!released){released=true;client.release(destroy);}};
    const abortClient=()=>release(true);budget.controller.signal.addEventListener('abort',abortClient,{once:true});
    function pit(value:unknown){
      if(!text(value,ASSET_SEARCH_LIMITS.pitBytes)||!value||!/^[A-Za-z0-9_+/=-]+$/.test(value))throw unavailable();
      if(!pits.has(value)){pits.add(value);pitBytes+=Buffer.byteLength(value);if(pitBytes>ASSET_SEARCH_LIMITS.retainedPitBytes)throw limited();}
      return value;
    }
    let base:URL;
    async function request(path:string,method:string,body:unknown,clock:Budget){
      clock.remaining();
      const response=await clock.wait(deps.fetch(new URL(path,base),{method,redirect:'error',
        headers:{'Content-Type':'application/json','Accept':'application/json','Accept-Encoding':'identity'},
        body:body===undefined?undefined:JSON.stringify(body),signal:clock.controller.signal}));
      let reader:ReadableStreamDefaultReader<Uint8Array>|undefined,complete=false;
      try {
        if(!response.ok||response.redirected||!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type')??''))throw unavailable();
        // Fetch transparently decodes compressed bodies while retaining wire
        // Content-Length. Require identity so byte admission and equality refer
        // to the same representation; never read an unexpected encoding.
        const encoding=response.headers.get('content-encoding');
        if(encoding!==null&&encoding.toLowerCase()!=='identity')throw unavailable();
        const declared=response.headers.get('content-length');
        if(declared!==null&&(!/^\d+$/.test(declared)||!Number.isSafeInteger(Number(declared))||Number(declared)>ASSET_SEARCH_LIMITS.responseBytes))throw limited();
        if(!response.body)throw unavailable();reader=response.body.getReader();
        const chunks:Uint8Array[]=[];let bytes=0;
        for(;;){const row=await clock.wait(reader.read());if(row.done)break;bytes+=row.value.byteLength;if(bytes>ASSET_SEARCH_LIMITS.responseBytes)throw limited();chunks.push(row.value);}
        complete=true;if(declared!==null&&Number(declared)!==bytes)throw unavailable();
        const raw=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks)),parsed=parseBoundedJSONEnvelope(raw);
        if(!parsed.ok)throw unavailable();clock.remaining();return parsed.value;
      } finally {
        if(!complete){
          // Abort owns the native fetch/socket. Do not await a custom stream's
          // cancellation hook forever after the original deadline has elapsed.
          clock.controller.abort();
          const cancellation=reader?reader.cancel():response.body?.cancel();
          if(cancellation)await clock.wait(cancellation).catch(()=>{});
        }
        reader?.releaseLock();
      }
    }
    async function sql(statement:string,values:any[]=[]){
      if(!client||released)throw unavailable();
      const rows=(await budget.wait(client.query({text:statement,values,query_timeout:budget.remaining()}))).rows;
      if(!Array.isArray(rows))throw unavailable();return rows;
    }
    try {
      if(!auth||!UUID.test(auth.principal?.id)||!UUID.test(auth.principal?.tenantId)||!/^[0-9a-f]{64}$/.test(auth.sessionHash)
        ||typeof deps.cursorKey!=='string'||deps.cursorKey.length<32)throw unavailable();
      base=new URL(deps.searchUrl);if(!['http:','https:'].includes(base.protocol)||base.username||base.password||base.search||base.hash||base.pathname!=='/')throw unavailable();
      const q=queryInput(query),bound=binding(auth,q),offset=cursorRead(q.cursor,bound,deps.cursorKey),tenant=auth.principal.tenantId,actor=auth.principal.id;
      const acquisition=deps.connect().then(value=>{client=value;if(budget.controller.signal.aborted||now()>=budget.until){release(true);throw limited();}return value;});
      await budget.wait(acquisition);
      await sql('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
      await sql("SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout','2000',true),set_config('idle_in_transaction_session_timeout','15000',true)",[String(budget.remaining())]);
      // Authenticate again inside this exact primary snapshot; caller permissions
      // and indexed ACLs never establish authority. Concurrent reads linearize here.
      const session=await readProtectedSession({query:async(text,values)=>({rows:await sql(text,values)})},auth.sessionHash);
      if(session.identityId!==actor||session.selectedTenantId!==tenant)throw new Problem(401,'SESSION_EXPIRED','Your session has expired. Sign in again.');
      await sql("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[session.selectedTenantId,session.identityId]);
      const memberships=await sql(`SELECT permissions FROM memberships
        WHERE tenant_id=$1::uuid AND identity_id=$2::uuid AND active`,[session.selectedTenantId,session.identityId]);
      if(memberships.length!==1)throw new Problem(401,'SESSION_EXPIRED','Your session has expired. Sign in again.');
      if(!Array.isArray(memberships[0].permissions)||!memberships[0].permissions.includes('catalog:read'))throw new Problem(403,'FORBIDDEN','Your current permissions do not allow this action.');
      const created=await request('/'+INDEX+'/_search/point_in_time?keep_alive=30s&allow_partial_pit_creation=false','POST',undefined,budget);
      if(!object(created))throw unavailable();let currentPit=pit(created.pit_id);shards(created._shards);
      const seen=new Set<string>(),facets=new Map<string,number>(),eligible:string[]=[];
      let after:[string,string]|undefined,total=0,visits=0,pages=0;
      for(;;){
        // One final size1 probe proves exact-full-cap completeness. It cannot
        // authorize/count a100001st candidate or return a partial answer.
        const terminal=visits===ASSET_SEARCH_LIMITS.candidates;
        if(!terminal&&pages>=ASSET_SEARCH_LIMITS.pages)throw limited();
        const size=terminal?1:ASSET_SEARCH_LIMITS.batch;
        const response=await request('/_search?allow_partial_search_results=false','POST',{
          size,_source:false,stored_fields:[],track_total_hits:false,pit:{id:currentPit,keep_alive:'30s'},
          timeout:Math.max(1,budget.remaining())+'ms',query:{bool:{filter:[{term:{tenantId:tenant}}],
            must:q.q?[{multi_match:{query:q.q,fields:['name^3','qualifiedName^2','description','glossaryText'],fuzziness:'AUTO'}}]:[{match_all:{}}]}},
          sort:[{'name.exact':'asc'},{id:'asc'}],...(after?{search_after:after}:{})},budget);
        if(!object(response))throw unavailable();if(response.pit_id!==undefined)currentPit=pit(response.pit_id);
        shards(response._shards);
        if(response.timed_out!==false||response.terminated_early===true||!object(response.hits)||!Array.isArray(response.hits.hits)||response.hits.hits.length>size)throw unavailable();
        const hits:Hit[]=[];
        for(const h of response.hits.hits){
          if(!object(h)||!UUID.test(h._id)||h._index!==INDEX||h._source!==undefined||h.fields!==undefined
            ||!Array.isArray(h.sort)||h.sort.length!==2||!text(h.sort[0],2048)||h.sort[1]!==h._id||seen.has(h._id)
            ||after&&compare(after,h.sort as [string,string])>=0)throw unavailable();
          after=[h.sort[0],h.sort[1]];seen.add(h._id);hits.push({id:h._id,sort:after});
        }
        if(terminal){if(hits.length)throw limited();break;}
        pages++;visits+=hits.length;
        if(hits.length){
          const ids=hits.map(h=>h.id),rows=await sql(`SELECT a.id,a.type FROM assets a
            WHERE a.tenant_id=$1::uuid AND a.id=ANY($2::uuid[]) AND a.status='active'
              AND (a.visibility='tenant' OR a.allowed_identities @> $3::jsonb)
              AND ($4::text='' OR a.type=$4)`,[tenant,ids,JSON.stringify([actor]),q.type]);
          const allowed=new Map<string,string>();
          for(const row of rows){if(!ids.includes(row.id)||allowed.has(row.id)||!text(row.type,256)||Array.from(row.type).length>64)throw unavailable();allowed.set(row.id,row.type);}
          for(const hit of hits){const type=allowed.get(hit.id);if(type===undefined)continue;
            eligible.push(hit.id);total++;
            if(!facets.has(type)&&facets.size>=ASSET_SEARCH_LIMITS.facetKeys)throw limited();facets.set(type,(facets.get(type)??0)+1);
          }
        }
        if(hits.length<size)break;
      }
      // OpenSearch discovers candidates; the same primary authorization snapshot
      // orders the complete eligible set. Stale projected names/timestamps cannot
      // choose a page, and no hidden row influences its ordering or counts.
      // Only UUIDs are retained (at most100000); metadata hydration remains100.
      // These are closed SQL fragments, never interpolated request expressions.
      const order=q.sort==='updated'?'a.updated_at DESC,a.id ASC':q.sort==='name-desc'?'a.name COLLATE "C" DESC,a.id ASC':'a.name COLLATE "C" ASC,a.id ASC';
      let selected:string[]=[];
      if(offset<total){
        const ordered=await sql(`SELECT a.id FROM assets a
          WHERE a.tenant_id=$1::uuid AND a.id=ANY($2::uuid[]) AND a.status='active'
            AND (a.visibility='tenant' OR a.allowed_identities @> $3::jsonb)
            AND ($4::text='' OR a.type=$4)
          ORDER BY ${order} LIMIT $5::integer OFFSET $6::integer`,[tenant,eligible,JSON.stringify([actor]),q.type,q.limit,offset]);
        const allowed=new Set(eligible);
        if(ordered.length!==Math.min(q.limit,total-offset)||new Set(ordered.map(r=>r.id)).size!==ordered.length
          ||ordered.some(r=>!allowed.has(r.id)))throw unavailable();
        selected=ordered.map(r=>r.id);
      }
      let items:ReturnType<typeof assetView>[]=[];
      if(selected.length){
        const measured=await sql(`SELECT a.id,octet_length(to_jsonb(a)::text)+octet_length(coalesce(o.name,''))+octet_length(coalesce(s.name,''))+128 AS bytes
          FROM assets a LEFT JOIN identities o ON o.id=a.owner_id
          LEFT JOIN sources s ON s.tenant_id=a.tenant_id AND s.id=a.source_id
          WHERE a.tenant_id=$1::uuid AND a.id=ANY($2::uuid[]) AND a.status='active'
            AND (a.visibility='tenant' OR a.allowed_identities @> $3::jsonb)`,[tenant,selected,JSON.stringify([actor])]);
        if(measured.length!==selected.length||new Set(measured.map(r=>r.id)).size!==selected.length||measured.some(r=>!selected.includes(r.id)||!integer(r.bytes)))throw unavailable();
        if(measured.reduce((n,r)=>n+r.bytes,0)>ASSET_SEARCH_LIMITS.hydrationBytes)throw limited();
        const hydrated=await sql(`SELECT a.*,o.name AS owner_name,s.name AS source_name FROM assets a
          LEFT JOIN identities o ON o.id=a.owner_id LEFT JOIN sources s ON s.tenant_id=a.tenant_id AND s.id=a.source_id
          WHERE a.tenant_id=$1::uuid AND a.id=ANY($2::uuid[]) AND a.status='active'
            AND (a.visibility='tenant' OR a.allowed_identities @> $3::jsonb)`,[tenant,selected,JSON.stringify([actor])]);
        const map=new Map(hydrated.map(row=>[row.id,row]));if(hydrated.length!==selected.length||map.size!==selected.length||selected.some(id=>!map.has(id)))throw unavailable();
        items=selected.map(id=>assetView(map.get(id)));if(Buffer.byteLength(JSON.stringify(items))>ASSET_SEARCH_LIMITS.hydrationBytes)throw limited();
      }
      const expiry=await sql('SELECT $1::timestamptz > clock_timestamp() AS live',[session.expiresAt]);
      if(expiry.length!==1||expiry[0].live!==true)throw new Problem(401,'SESSION_EXPIRED','Your session has expired. Sign in again.');
      result={items,total,nextCursor:offset+items.length<total?cursorWrite(offset+items.length,bound,deps.cursorKey):null,
        facets:[...facets].map(([type,count])=>({type,count})).sort((a,b)=>b.count-a.count||Buffer.compare(Buffer.from(a.type),Buffer.from(b.type))).slice(0,ASSET_SEARCH_LIMITS.facetResults)};
      await sql('COMMIT');committed=true;
    } catch(error){failed=error instanceof Problem?error:budget.controller.signal.aborted?limited():unavailable();}
    finally {
      budget.stop();budget.controller.signal.removeEventListener('abort',abortClient);release(!committed);
      if(pits.size){const cleanup=new Budget(now,ASSET_SEARCH_LIMITS.cleanupMs);
        try {const closed=await request('/_search/point_in_time','DELETE',{pit_id:[...pits]},cleanup);
          if(!object(closed)||!Array.isArray(closed.pits)||closed.pits.length!==pits.size
            ||new Set(closed.pits.map(p=>p.pit_id)).size!==pits.size||closed.pits.some(p=>!object(p)||p.successful!==true||!pits.has(p.pit_id)))throw unavailable();
        } catch {failed??=unavailable();} finally {cleanup.stop();}
      }
    }
    if(failed)throw failed;if(!result)throw unavailable();return result;
  };
}

export async function searchAssets(auth:SearchAuth,query:AssetSearchQuery):Promise<Result>{
  return createAssetSearch({connect:()=>pool.connect(),fetch:globalThis.fetch,
    searchUrl:process.env.OPENSEARCH_URL??'http://localhost:9200',cursorKey:process.env.SESSION_KEY??''})(auth,query);
}
