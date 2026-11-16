// SPDX-License-Identifier: Apache-2.0
import {scope,sql,type Tx} from '../../../packages/db/src/index.ts';
import {Problem} from '../../../packages/authz/src/index.ts';
import {parseGlossaryPublication} from '../../../packages/domain/src/glossary.ts';
import {GLOSSARY_LIMITS} from '../../../packages/domain/src/glossary-contracts.ts';
import {typeHash} from '../../../packages/domain/src/asset-type-policy.ts';
const base=process.env.OPENSEARCH_URL??'http://localhost:9200';
export const index='gc-assets-v1';
const unavailable=()=>new Problem(503,'SEARCH_UNAVAILABLE','Search is temporarily unavailable. Direct asset links remain available.');
const glossaryMapping={properties:{glossaryText:{type:'text'}}};
export async function searchRequest(path:string,body?:unknown,method?:string){
 const response=await fetch(base+path,{method:method??(body?'POST':'GET'),headers:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(10000)});
 if(!response.ok)throw unavailable();
 return response.json() as Promise<any>;
}
/** Add the new field to existing strict indexes before consuming any outbox
 * event. Mapping failures leave initialization incomplete and events untouched. */
export async function initializeSearchIndex(request=searchRequest,fetcher:typeof fetch=fetch){
 const r=await fetcher(base+'/'+index,{signal:AbortSignal.timeout(5000)});
 if(r.status===404){const created=await request('/'+index,{settings:{number_of_shards:1,number_of_replicas:0},mappings:{dynamic:'strict',properties:{tenantId:{type:'keyword'},id:{type:'keyword'},name:{type:'text',fields:{exact:{type:'keyword'}}},qualifiedName:{type:'text'},type:{type:'keyword'},description:{type:'text'},status:{type:'keyword'},version:{type:'integer'},...glossaryMapping.properties}}},'PUT');if(created?.acknowledged!==true)throw unavailable();}
 else if(!r.ok)throw unavailable();
 const mapped=await request('/'+index+'/_mapping',glossaryMapping,'PUT');if(mapped?.acknowledged!==true)throw unavailable();
}
/** Trusted database rows only. The complete current publication must agree with
 * its canonical asset. Related targets never contribute terms to this document. */
export function assetSearchDocument(tenant:string,a:Record<string,any>,publication?:{asset_id:string;asset_version:number;state:string;payload:unknown}){
 if(a.tenant_id!==tenant)throw unavailable();
 let glossaryText='';
 if(a.type==='business_term'&&a.source_id===null){
  if(!publication||publication.state!=='sealed'||publication.asset_id!==a.id||publication.asset_version!==a.version)throw unavailable();
  const parsed=parseGlossaryPublication(publication.payload);if(!parsed.ok)throw unavailable();
  const p=parsed.value.input;
  if(a.model_id!==p.typePin.modelId||a.model_version!==p.typePin.version||a.owner_id!==p.ownerId||a.visibility!==p.visibility
   ||a.type_state!==p.state||a.name!==parsed.value.name||a.description!==parsed.value.description
   ||typeHash(a.attributes)!==typeHash(p.attributes)||typeHash(a.allowed_identities)!==typeHash(p.allowedIdentityIds))throw unavailable();
  glossaryText=parsed.value.translations.flatMap(t=>[t.name,t.definition,...t.synonyms,...t.abbreviations,...t.examples]).join('\n');
  if(Buffer.byteLength(glossaryText,'utf8')>GLOSSARY_LIMITS.bytes)throw unavailable();
 }
 return {tenantId:tenant,id:a.id,name:a.name,qualifiedName:a.qualified_name,type:a.type,description:a.description,status:a.status,version:a.version,glossaryText};
}
async function projection(tx:Tx,tenant:string,a:Record<string,any>){
 let publication:{asset_id:string;asset_version:number;state:string;payload:unknown}|undefined;
 if(a.type==='business_term'&&a.source_id===null){
  // Measure before fetching the payload; publication changes between these reads
  // refuse this attempt and leave its outbox event available for a fresh retry.
  const size=(await sql<{id:string;bytes:number}>`select p.id,octet_length(p.payload::text) as bytes from public.glossary_terms g
   join public.glossary_publications p on p.tenant_id=g.tenant_id and p.id=g.current_publication_id
   where g.tenant_id=${tenant}::uuid and g.asset_id=${a.id}::uuid and p.asset_id=g.asset_id and p.asset_version=${a.version} and p.state='sealed'`.execute(tx)).rows[0];
  if(!size||size.bytes>GLOSSARY_LIMITS.bytes)throw unavailable();
  publication=(await sql<{asset_id:string;asset_version:number;state:string;payload:unknown}>`select p.asset_id,p.asset_version,p.state,p.payload
   from public.glossary_terms g join public.glossary_publications p on p.tenant_id=g.tenant_id and p.id=g.current_publication_id
   where g.tenant_id=${tenant}::uuid and g.asset_id=${a.id}::uuid and p.asset_id=g.asset_id and p.id=${size.id}::uuid
   and p.asset_version=${a.version} and octet_length(p.payload::text)<=${GLOSSARY_LIMITS.bytes}`.execute(tx)).rows[0];
 }
 return assetSearchDocument(tenant,a,publication);
}
export async function projectTenant(tenant:string){
 await scope(tenant,'site',async tx=>{
  const events=await tx.selectFrom('outbox').selectAll().where('processed_at','is',null).orderBy('created_at').limit(100).forUpdate().skipLocked().execute();
  for(const e of events){
   if(e.event_type.startsWith('asset.')){
    const a=await tx.selectFrom('assets').selectAll().where('id','=',e.resource_id).executeTakeFirst();
    if(a)await searchRequest('/'+index+'/_doc/'+a.id+'?version='+a.version+'&version_type=external_gte',await projection(tx,tenant,a),'PUT');
   }
   await tx.updateTable('outbox').set({processed_at:new Date()}).where('id','=',e.id).execute();
  }
 });
}
export async function startProjector(){
 let ready=false,busy=false;
 const tick=async()=>{if(busy)return;busy=true;try{
  if(!ready){await initializeSearchIndex();ready=true;}
  for(const tenant of (process.env.SITE_TENANTS??'').split(',').filter(Boolean))await projectTenant(tenant);
 }catch{console.warn(JSON.stringify({event:'search_projection_degraded'}));}finally{busy=false;}};
 await tick();return setInterval(()=>void tick(),1000);
}
