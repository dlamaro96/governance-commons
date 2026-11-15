// SPDX-License-Identifier: Apache-2.0
import {scope,sql} from '../../../packages/db/src/index.ts';
import {Problem} from '../../../packages/authz/src/index.ts';
const base=process.env.OPENSEARCH_URL??'http://localhost:9200';
export const index='gc-assets-v1';
export async function searchRequest(path:string,body?:unknown,method?:string){
 const response=await fetch(base+path,{method:method??(body?'POST':'GET'),headers:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(10000)});
 if(!response.ok)throw new Problem(503,'SEARCH_UNAVAILABLE','Search is temporarily unavailable. Direct asset links remain available.');
 return response.json() as Promise<any>;
}
export async function projectTenant(tenant:string){
 await scope(tenant,'site',async tx=>{
  const events=await tx.selectFrom('outbox').selectAll().where('processed_at','is',null).orderBy('created_at').limit(100).forUpdate().skipLocked().execute();
  for(const e of events){
   if(e.event_type.startsWith('asset.')){
    const a=await tx.selectFrom('assets').selectAll().where('id','=',e.resource_id).executeTakeFirst();
    if(a) await searchRequest('/'+index+'/_doc/'+a.id+'?version='+a.version+'&version_type=external_gte',{tenantId:tenant,id:a.id,name:a.name,qualifiedName:a.qualified_name,type:a.type,description:a.description,status:a.status,version:a.version},'PUT');
   }
   await tx.updateTable('outbox').set({processed_at:new Date()}).where('id','=',e.id).execute();
  }
 });
}
export async function startProjector(){
 let ready=false,busy=false;
 const tick=async()=>{if(busy)return;busy=true;try{
  if(!ready){const r=await fetch(base+'/'+index,{signal:AbortSignal.timeout(5000)});if(r.status===404)await searchRequest('/'+index,{settings:{number_of_shards:1,number_of_replicas:0},mappings:{dynamic:'strict',properties:{tenantId:{type:'keyword'},id:{type:'keyword'},name:{type:'text',fields:{exact:{type:'keyword'}}},qualifiedName:{type:'text'},type:{type:'keyword'},description:{type:'text'},status:{type:'keyword'},version:{type:'integer'}}}},'PUT');else if(!r.ok)throw Error('Search initialization unavailable');ready=true;}
  for(const tenant of (process.env.SITE_TENANTS??'').split(',').filter(Boolean))await projectTenant(tenant);
 }catch{console.warn(JSON.stringify({event:'search_projection_degraded'}));}finally{busy=false;}};
 await tick();return setInterval(()=>void tick(),1000);
}
