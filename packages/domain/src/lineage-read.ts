// SPDX-License-Identifier: Apache-2.0
import {createHash,createHmac} from 'node:crypto';
import {lockTenantLedger,sql,type Tx} from '../../db/src/index.ts';
import {Problem,type Principal} from '../../authz/src/index.ts';
import {modelPersistence} from './model-service.ts';
import {signedCursor} from './cursor.ts';
import {LINEAGE_GAPS,LINEAGE_LIMITS,type LineageEdge,type LineageNode,type LineageObservation,type LineageQuery,type LineageView} from './lineage-contracts.ts';

const invalid=()=>new Problem(400,'LINEAGE_PAGE_INVALID','Provide a valid lineage query or restart from the first page.');
const missing=()=>new Problem(404,'LINEAGE_ASSET_NOT_FOUND','The asset is unavailable.');
const stale=()=>new Problem(409,'LINEAGE_GRAPH_STALE','The authorized lineage graph changed. Restart from the first page.');
const limit=()=>new Problem(422,'LINEAGE_PROFILE_LIMIT','This graph exceeds the bounded lineage profile. Reduce the exploration depth.');
const corrupt=()=>new Problem(500,'LINEAGE_STORAGE_INVALID','Stored lineage evidence could not be verified.');
const uuid=(v:unknown):v is string=>typeof v==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v)&&v!=='00000000-0000-0000-0000-000000000000';
const hash=(v:unknown):v is string=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const generation=(v:unknown):v is string=>typeof v==='string'&&/^[1-9][0-9]{0,18}$/.test(v)&&BigInt(v)<=9223372036854775807n;
function keys(value:unknown,allowed:readonly string[],exact=false):value is Record<string,unknown>{
 if(!value||typeof value!=='object'||Array.isArray(value))return false;
 const own=Reflect.ownKeys(value);
 return (!exact||own.length===allowed.length)&&own.every(k=>typeof k==='string'&&allowed.includes(k)&&Object.getOwnPropertyDescriptor(value,k)?.enumerable&&Object.hasOwn(Object.getOwnPropertyDescriptor(value,k)!,'value'));
}
type Selected={direction:'upstream'|'downstream'|'both';depth:number;limit:number;cursor?:string};
function selectors(query:LineageQuery):Selected {
 if(!keys(query,['direction','depth','limit','cursor']))throw invalid();
 const direction=query.direction??'both',depth=query.depth??1,count=query.limit??25;
 if(query.direction===null||query.depth===null||query.limit===null||typeof direction!=='string'||!['upstream','downstream','both'].includes(direction)||typeof depth!=='number'||!Number.isInteger(depth)||depth<1||depth>LINEAGE_LIMITS.depth||typeof count!=='number'||!Number.isInteger(count)||count<1||count>LINEAGE_LIMITS.page||
  query.cursor!==undefined&&(typeof query.cursor!=='string'||!query.cursor.length||query.cursor.length>1024))throw invalid();
 return {direction:direction as Selected['direction'],depth,limit:count,...(query.cursor===undefined?{}:{cursor:query.cursor})};
}
/** Inspect the original URL: numeric coercion and repeated keys must not choose a graph. */
export function parseLineageQuery(url:string):LineageQuery {
 const fields:Record<string,string>={},params=new URL(url,'http://local.invalid').searchParams;
 for(const [key,value]of params){
  if(!['direction','depth','limit','cursor'].includes(key)||Object.hasOwn(fields,key)||(['depth','limit'].includes(key)&&!/^[1-9][0-9]*$/.test(value)))throw invalid();
  fields[key]=value;
 }
 const value={...fields,...('depth'in fields?{depth:Number(fields.depth)}:{}),...('limit'in fields?{limit:Number(fields.limit)}:{})} as LineageQuery;
 selectors(value);return value;
}
interface AssetRow {id:string;name:string;qualified_name:string;type:string;version:number;source_id:string|null;connector_id?:string|null;accepted_scan_generation?:string}
interface EdgeRow {id:string;upstream_asset_id:string;upstream_version:number;downstream_asset_id:string;downstream_version:number;referenced_attribute_numbers:number[];evidence_hash:string}
interface ObservationRow {id:string;source_id:string;scan_generation:string;source_version:string;observed_at:Date|string;recorded_at:Date|string}
function node(row:AssetRow):LineageNode{return {id:row.id,name:row.name,qualifiedName:row.qualified_name,type:row.type,version:row.version};}
function iso(value:Date|string){const result=new Date(value).toISOString();if(!Number.isFinite(Date.parse(result)))throw corrupt();return result;}
function visible(p:Principal,alias:'a'|'u'|'d'){
 return sql<boolean>`(${sql.ref(`${alias}.visibility`)}='tenant' OR ${sql.ref(`${alias}.allowed_identities`)} @> ${JSON.stringify([p.id])}::jsonb)`;
}
function edge(row:EdgeRow,observation:LineageObservation):LineageEdge {
 if(!hash(row.id)||!hash(row.evidence_hash)||!uuid(row.upstream_asset_id)||!uuid(row.downstream_asset_id)||
  ![row.upstream_version,row.downstream_version].every(v=>Number.isInteger(v)&&v>0)||!Array.isArray(row.referenced_attribute_numbers)||!row.referenced_attribute_numbers.length||row.referenced_attribute_numbers.length>LINEAGE_LIMITS.witnesses||
  row.referenced_attribute_numbers.some((v,i,all)=>!Number.isInteger(v)||v<0||v>32767||(i>0&&all[i-1]>=v)))throw corrupt();
 return {id:row.id,upstreamAssetId:row.upstream_asset_id,upstreamVersion:row.upstream_version,downstreamAssetId:row.downstream_asset_id,downstreamVersion:row.downstream_version,
  evidenceType:'postgresql-catalog-view-dependency',scope:'table',confidence:null,sourceCodeReference:null,sourceCodeAvailability:'not-collected',
  evidencePointer:`lineage:${observation.id}:${row.id}`,evidenceHash:row.evidence_hash,referencedAttributeNumbers:row.referenced_attribute_numbers,observation};
}
/** SQL has already authorized both endpoints. Hidden adjacency is never traversed. */
function neighborhood(root:string,rows:readonly EdgeRow[],query:Selected){
 const visited=new Set([root]),selected=new Map<string,EdgeRow>();let frontier=new Set([root]);
 for(let depth=0;depth<query.depth&&frontier.size;depth++){
  const next=new Set<string>();
  for(const row of rows){
   const down=query.direction!=='upstream'&&frontier.has(row.upstream_asset_id),up=query.direction!=='downstream'&&frontier.has(row.downstream_asset_id);
   if(!down&&!up)continue;
   selected.set(row.id,row);
   for(const id of [row.upstream_asset_id,row.downstream_asset_id])if(!visited.has(id))next.add(id);
  }
  for(const id of next)visited.add(id);
  if(visited.size>1000||selected.size>LINEAGE_LIMITS.edges)throw limit();
  frontier=next;
 }
 return {ids:[...visited].sort(),edges:[...selected.values()].sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0)};
}
export function lineageReadFailure(error:unknown):unknown {
 if(error instanceof Problem)return error;
 if(error&&typeof error==='object'&&'code'in error&&['57014','55P03','40P01','40001'].includes(String(error.code)))return new Problem(503,'LINEAGE_RETRY','A stable lineage view was unavailable. Try again.');
 return error;
}
/** Reauthorization and canonical ACLs run on every page. The signed cursor is only a selector. */
export async function getAssetLineage(tx:Tx,p:Principal,assetId:string,query:LineageQuery={}):Promise<LineageView>{
 const selected=selectors(query);
 if(!uuid(p.id)||!uuid(p.tenantId)||!uuid(assetId))throw invalid();
 const codec=signedCursor(process.env.SESSION_KEY,'postgresql-lineage-v1');
 const binding=createHash('sha256').update(JSON.stringify([p.tenantId,p.id,assetId,selected.direction,selected.depth,selected.limit])).digest('hex');
 let continuation:Record<string,unknown>|null=null;
 if(selected.cursor!==undefined)try{
  const value=codec.decode(selected.cursor);
  if(!keys(value,['v','binding','observationId','generation','fence','last'],true)||value.v!==1||value.binding!==binding||!uuid(value.observationId)||!generation(value.generation)||!hash(value.fence)||!hash(value.last))throw invalid();
  continuation=value;
 }catch{throw invalid();}
 const deadline=performance.now()+30000;
 async function budget(){const remaining=Math.floor(deadline-performance.now());if(remaining<1)throw new Problem(503,'LINEAGE_RETRY','A stable lineage view was unavailable. Try again.');
  await sql`select set_config('statement_timeout',${String(remaining)},true),set_config('lock_timeout',${String(Math.min(remaining,5000))},true)`.execute(tx);}
 await budget();await modelPersistence.authorize(tx,p,['catalog:read']);
 await budget();await lockTenantLedger(tx,p.tenantId);
 await budget();await modelPersistence.authorize(tx,p,['catalog:read']);
 const root=(await sql<AssetRow>`SELECT a.id,a.name,a.qualified_name,a.type,a.version,a.source_id,s.connector_id,s.accepted_scan_generation::text
  FROM public.assets a LEFT JOIN public.sources s ON s.tenant_id=a.tenant_id AND s.id=a.source_id
  WHERE a.tenant_id=${p.tenantId}::uuid AND a.id=${assetId}::uuid AND a.status='active' AND ${visible(p,'a')}`.execute(tx)).rows[0];
 if(!root)throw missing();
 const result:LineageView={assetId,coverage:'NOT_COLLECTED',direction:selected.direction,depth:selected.depth,nodes:[node(root)],edges:[],gaps:[],nextCursor:null,
  limitations:['COLUMN_MAPPINGS_NOT_COLLECTED','SQL_BODIES_NOT_ANALYZED']};
 const finish=async()=>{await budget();await modelPersistence.authorize(tx,p,['catalog:read']);if(Buffer.byteLength(JSON.stringify(result))>524288)throw limit();return result;};
 if(!root.source_id||root.connector_id!=='postgresql'||!['table','view'].includes(root.type)){
  if(continuation)throw stale();result.coverage='UNSUPPORTED';return finish();
 }
 await budget();
 const observed=(await sql<ObservationRow>`SELECT o.id,o.source_id,o.scan_generation::text,o.source_version,o.observed_at,o.recorded_at
  FROM public.lineage_observations o JOIN public.sources s ON s.tenant_id=o.tenant_id AND s.id=o.source_id AND s.accepted_scan_generation=o.scan_generation
  WHERE o.tenant_id=${p.tenantId}::uuid AND o.source_id=${root.source_id}::uuid LIMIT 2`.execute(tx)).rows;
 if(observed.length>1)throw corrupt();
 const current=observed[0];
 if(!current){if(continuation)throw stale();return finish();}
 if(!uuid(current.id)||current.source_id!==root.source_id||!generation(current.scan_generation))throw corrupt();
 if(continuation&&(continuation.observationId!==current.id||continuation.generation!==current.scan_generation))throw stale();
 const observation:LineageObservation={id:current.id,sourceId:current.source_id,generation:current.scan_generation,observedAt:iso(current.observed_at),recordedAt:iso(current.recorded_at),sourceVersion:current.source_version,adapterVersion:'1',queryTemplate:'postgresql-view-dependencies-v1'};
 await budget();
 const rows=(await sql<EdgeRow>`SELECT e.id,e.upstream_asset_id,e.upstream_version,e.downstream_asset_id,e.downstream_version,e.referenced_attribute_numbers,e.evidence_hash
  FROM public.lineage_edge_observations e
  JOIN public.assets u ON u.tenant_id=e.tenant_id AND u.id=e.upstream_asset_id AND u.source_id=e.source_id
  JOIN public.assets d ON d.tenant_id=e.tenant_id AND d.id=e.downstream_asset_id AND d.source_id=e.source_id
  WHERE e.tenant_id=${p.tenantId}::uuid AND e.observation_id=${current.id}::uuid AND e.source_id=${root.source_id}::uuid
   AND u.status='active' AND d.status='active' AND ${visible(p,'u')} AND ${visible(p,'d')}
  ORDER BY e.id LIMIT ${LINEAGE_LIMITS.edges+1}`.execute(tx)).rows;
 if(rows.length>LINEAGE_LIMITS.edges||Buffer.byteLength(JSON.stringify(rows))>2*1048576)throw limit();
 const nearby=neighborhood(assetId,rows,selected);
 await budget();
 const assets=(await sql<AssetRow>`SELECT a.id,a.name,a.qualified_name,a.type,a.version,a.source_id FROM public.assets a
  WHERE a.tenant_id=${p.tenantId}::uuid AND a.source_id=${root.source_id}::uuid AND a.id=ANY(${nearby.ids}::uuid[]) AND a.status='active' AND ${visible(p,'a')} ORDER BY a.id LIMIT 1001`.execute(tx)).rows;
 if(assets.length!==nearby.ids.length||assets.some(a=>!nearby.ids.includes(a.id)))throw stale();
 const nodes=assets.map(node);
 if(Buffer.byteLength(JSON.stringify(nodes))>1048576)throw limit();
 await budget();
 // Select only gap codes for authorized visible views. No payload, outside object
 // identity, array position or hidden graph count crosses this read boundary.
 const gapRows=(await sql<{asset_id:string;gaps:unknown}>`SELECT a.id AS asset_id,v.value->'gaps' AS gaps
  FROM public.lineage_observations o CROSS JOIN LATERAL jsonb_array_elements(o.payload->'views') v(value)
  JOIN public.assets a ON a.tenant_id=o.tenant_id AND a.source_id=o.source_id AND a.external_id=v.value->>'viewExternalId'
  WHERE o.tenant_id=${p.tenantId}::uuid AND o.id=${current.id}::uuid AND o.source_id=${root.source_id}::uuid
   AND a.id=ANY(${nearby.ids}::uuid[]) AND a.status='active' AND a.type='view' AND ${visible(p,'a')}
  ORDER BY a.id LIMIT ${LINEAGE_LIMITS.views+1}`.execute(tx)).rows;
 if(gapRows.length>LINEAGE_LIMITS.views)throw limit();
 const gaps:LineageView['gaps']=[],seen=new Set<string>();
 for(const row of gapRows){
  if(!nearby.ids.includes(row.asset_id)||seen.has(row.asset_id)||!Array.isArray(row.gaps)||row.gaps.length>LINEAGE_GAPS.length||row.gaps.some((v,i,all)=>!LINEAGE_GAPS.includes(v)||all.indexOf(v)!==i))throw corrupt();
  seen.add(row.asset_id);for(const code of row.gaps)gaps.push({assetId:row.asset_id,code});
 }
 const fence=createHmac('sha256',process.env.SESSION_KEY!).update('governance-commons:lineage-visible-graph:v1\0').update(JSON.stringify([binding,current.id,current.scan_generation,nodes,nearby.edges,gaps])).digest('hex');
 if(continuation&&continuation.fence!==fence)throw stale();
 if(continuation&&!nearby.edges.some(row=>row.id===continuation.last))throw invalid();
 const remaining=continuation?nearby.edges.filter(e=>e.id>(continuation.last as string)):nearby.edges,page=remaining.slice(0,selected.limit);
 const included=new Set([assetId,...page.flatMap(e=>[e.upstream_asset_id,e.downstream_asset_id])]);
 result.coverage='COLLECTED';result.nodes=nodes.filter(n=>included.has(n.id));result.edges=page.map(row=>edge(row,observation));result.gaps=gaps.filter(g=>included.has(g.assetId));
 if(remaining.length>selected.limit)result.nextCursor=codec.encode({v:1,binding,observationId:current.id,generation:current.scan_generation,fence,last:page.at(-1)!.id});
 return finish();
}
