// SPDX-License-Identifier: Apache-2.0
import {createHash} from 'node:crypto';
import {sql,type Tx} from '../../db/src/index.ts';
import {Problem,type Principal} from '../../authz/src/index.ts';
import {modelPersistence} from './model-service.ts';
import {approvalQuery,approvalFailure} from './approval-service.ts';
import {signedCursor} from './cursor.ts';
import {uuid} from './relation-store.ts';
import {GLOSSARY_LIMITS} from './glossary-contracts.ts';
import type {AssetGlossaryContextItem,AssetGlossaryContextPage} from './glossary-context-contracts.ts';

export interface GlossaryContextQuery {locale?:string;limit?:number;cursor?:string}
export const GLOSSARY_CONTEXT_PAGE_BYTES=524_288;
const invalid=()=>new Problem(400,'GLOSSARY_CONTEXT_PAGE_INVALID','Provide a valid glossary context page.');
const unavailable=()=>new Problem(404,'GLOSSARY_CONTEXT_UNAVAILABLE','The asset is unavailable.');
const changed=()=>new Problem(503,'GLOSSARY_CONTEXT_UNAVAILABLE','A stable glossary context could not be read. Retry the page.');
const limit=()=>new Problem(422,'GLOSSARY_CONTEXT_LIMIT','The complete context page exceeds its supported bounds.');
function options(p:Principal,assetId:string,query:GlossaryContextQuery){
 if(!uuid(assetId))throw unavailable();
 if(!query||typeof query!=='object'||Array.isArray(query)||Object.keys(query).some(k=>!['locale','limit','cursor'].includes(k)))throw invalid();
 const size=query.limit??10,requested=query.locale??'en';let locale:string;
 if(!Number.isInteger(size)||size<1||size>25||typeof requested!=='string'||requested.length>120||!requested||requested.split('-').some(s=>s.length===1))throw invalid();
 try{locale=Intl.getCanonicalLocales(requested)[0]!;if(!locale)throw 0;}catch{throw invalid();}
 const codec=signedCursor(process.env.SESSION_KEY,'asset-glossary-context-v1');
 const binding=createHash('sha256').update(JSON.stringify([p.tenantId,p.id,assetId,locale,size])).digest('hex');
 let after:string|null=null;
 if(query.cursor!==undefined)try{
  const value=codec.decode(query.cursor);
  if(!Array.isArray(value)||value.length!==3||value[0]!==1||value[1]!==binding||!uuid(value[2])||codec.encode(value)!==query.cursor)throw 0;after=value[2];
 }catch{throw invalid();}
 return {size,locale,after,next:(id:string)=>codec.encode([1,binding,id])};
}
type Measure={term_id:string;publication_id:string;term_version:number;relation_id:string;relation_version:number;asset_version:number;valid:boolean;payload_bytes:number;item_bytes:number};
/** A deliberately narrow read model: only one independently visible owned
 * defines edge and its term's translation. Sibling links are never selected. */
export async function getAssetGlossaryContext(tx:Tx,p:Principal,assetId:string,query:GlossaryContextQuery={}):Promise<AssetGlossaryContextPage>{
 const o=options(p,assetId,query),audience=JSON.stringify([p.id]);
 const authorize=()=>approvalQuery(tx,()=>modelPersistence.authorize(tx,p,['catalog:read','models:read']));
 const asset=async()=>{
  const row=(await approvalQuery(tx,()=>sql<{version:number}>`select version from public.assets where tenant_id=${p.tenantId}::uuid and id=${assetId}::uuid
   and status='active' and (visibility='tenant' or allowed_identities @> ${audience}::jsonb)`.execute(tx))).rows[0];
  if(!row)throw unavailable();return row.version;
 };
 try{
  await authorize();const assetVersion=await asset();
  const after=o.after===null?sql`true`:sql`g.asset_id>${o.after}::uuid`;
  // All visibility predicates precede ORDER/LIMIT. Canonical integrity is a
  // separate boolean so visible drift refuses the page instead of hiding it.
  const selection=sql`with chosen as (
   select g.asset_id as term_id,pub.id as publication_id,a.version as term_version,r.id as relation_id,r.version as relation_version,target.version as asset_version,
    octet_length(pub.payload::text) as payload_bytes,
    coalesce(pub.asset_id=g.asset_id and pub.asset_version=a.version and pub.state='sealed'
     and a.model_id=pub.payload#>>'{typePin,modelId}' and a.model_version::text=pub.payload#>>'{typePin,version}'
     and model.type_id::text=pub.payload#>>'{typePin,typeId}' and av.definition_hash=pub.payload#>>'{typePin,definitionHash}'
     and av.resolution_hash=pub.payload#>>'{typePin,resolutionHash}'
     and a.owner_id::text=pub.payload->>'ownerId' and a.visibility=pub.payload->>'visibility' and a.allowed_identities=pub.payload->'allowedIdentityIds'
     and a.type_state=pub.payload->>'state' and a.attributes=pub.payload->'attributes'
     and a.name=primary_text.value->>'name' and a.description=primary_text.value->>'definition'
     and r.relation_type_id=l.relation_type_id and r.relation_type_id::text=pub.payload->'links'->l.ordinal#>>'{typePin,relationTypeId}'
     and r.relation_type_version::text=pub.payload->'links'->l.ordinal#>>'{typePin,version}'
     and policy.definition_hash=pub.payload->'links'->l.ordinal#>>'{typePin,definitionHash}'
     and pub.payload->'links'->l.ordinal->>'kind'='defines' and pub.payload->'links'->l.ordinal->>'targetAssetId'=target.id::text
     and ((policy.definition->>'direction'='directed' and r.source_asset_id=a.id and r.target_asset_id=target.id)
      or (policy.definition->>'direction'='undirected' and r.source_asset_id<r.target_asset_id
       and ((r.source_asset_id=a.id and r.target_asset_id=target.id) or (r.target_asset_id=a.id and r.source_asset_id=target.id))))
     and r.owner_id=a.owner_id and r.visibility=a.visibility and r.allowed_identities=a.allowed_identities
     and r.attributes='{}'::jsonb and r.state=policy.definition#>>'{lifecycle,initial}' and r.valid_from is null and r.valid_to is null
     and translated.value is not null,false) as valid,
    jsonb_build_object('termId',a.id,'termVersion',a.version,'relationId',r.id,'locale',translated.value->>'locale',
     'name',translated.value->>'name','definition',translated.value->>'definition','state',a.type_state) as item
   from public.glossary_terms g join public.glossary_publications pub on pub.tenant_id=g.tenant_id and pub.id=g.current_publication_id
   join public.assets a on a.tenant_id=g.tenant_id and a.id=g.asset_id
   join public.glossary_publication_links l on l.tenant_id=g.tenant_id and l.publication_id=pub.id and l.kind='defines' and l.target_asset_id=${assetId}::uuid
   join public.relations r on r.tenant_id=l.tenant_id and r.id=l.relation_id
   join public.assets target on target.tenant_id=l.tenant_id and target.id=l.target_asset_id
   left join public.governance_models model on model.tenant_id=a.tenant_id and model.id=a.model_id
   left join public.asset_type_versions av on av.tenant_id=a.tenant_id and av.model_id=a.model_id and av.version=a.model_version
   left join public.relation_type_versions policy on policy.tenant_id=r.tenant_id and policy.relation_type_id=r.relation_type_id and policy.version=r.relation_type_version
   left join lateral (select value from jsonb_array_elements(pub.payload#>'{attributes,translations}') where value->>'locale'=pub.payload->>'primaryLocale' limit 1) primary_text on true
   left join lateral (select value from jsonb_array_elements(pub.payload#>'{attributes,translations}')
    where value->>'locale' in (${o.locale},pub.payload->>'primaryLocale') order by (value->>'locale'=${o.locale}) desc limit 1) translated on true
   where g.tenant_id=${p.tenantId}::uuid and a.type='business_term' and a.source_id is null and a.status='active' and r.status='active' and target.status='active'
    and (a.visibility='tenant' or a.allowed_identities @> ${audience}::jsonb)
    and (r.visibility='tenant' or r.allowed_identities @> ${audience}::jsonb)
    and (target.visibility='tenant' or target.allowed_identities @> ${audience}::jsonb)
    and ${after} order by g.asset_id limit ${o.size+1})`;
  const measure=()=>approvalQuery(tx,()=>sql<Measure>`${selection} select term_id,publication_id,term_version,relation_id,relation_version,asset_version,valid,payload_bytes,octet_length(item::text) as item_bytes from chosen order by term_id`.execute(tx));
  const measured=(await measure()).rows;
  if(measured.some((r,i)=>!r.valid||r.asset_version!==assetVersion||r.payload_bytes>GLOSSARY_LIMITS.bytes||!uuid(r.term_id)||!uuid(r.relation_id)||i>0&&measured[i-1].term_id>=r.term_id))throw changed();
  // Include exact JSON framing/cursor allowance, without fetching any payload or
  // translation text until the entire selected page is admitted.
  if(measured.slice(0,o.size).reduce((sum,r)=>sum+r.item_bytes+1,1280)>GLOSSARY_CONTEXT_PAGE_BYTES)throw limit();
  const rows=(await approvalQuery(tx,()=>sql<{term_id:string;publication_id:string;item:AssetGlossaryContextItem}>`${selection}
   select term_id,publication_id,item from chosen order by term_id limit ${o.size}`.execute(tx))).rows;
  if(rows.length!==Math.min(measured.length,o.size)||rows.some((r,i)=>r.term_id!==measured[i].term_id||r.publication_id!==measured[i].publication_id
   ||r.item.termId!==r.term_id||r.item.termVersion!==measured[i].term_version||r.item.relationId!==measured[i].relation_id))throw changed();
  const result:AssetGlossaryContextPage={assetId,items:rows.map(r=>r.item),nextCursor:measured.length>o.size?o.next(rows.at(-1)!.term_id):null};
  if(Buffer.byteLength(JSON.stringify(result))>GLOSSARY_CONTEXT_PAGE_BYTES)throw limit();
  await authorize();if(await asset()!==assetVersion||JSON.stringify((await measure()).rows)!==JSON.stringify(measured))throw changed();
  return result;
 }catch(error){throw approvalFailure(error);}
}
