// SPDX-License-Identifier: Apache-2.0
/** Explicit synthetic starter definitions through the ordinary runtime role and
 * protected services. Existing definitions and membership authority are retained. */
import pg from 'pg';
import {Kysely,PostgresDialect,sql} from 'kysely';
import type {Principal} from '../../authz/src/index.ts';
import {record,once,assetView} from '../../../apps/api/src/repository.ts';
import {glossaryStarterType} from '../../domain/src/glossary.ts';
import {createAssetType,getAssetType} from '../../domain/src/asset-type-service.ts';
import {modelPersistence} from '../../domain/src/model-service.ts';
import {getApprovalDefinition,publishApprovalDefinition} from '../../domain/src/approval-service.ts';
import type {ApprovalDefinition} from '../../domain/src/approval-contracts.ts';
import {configureRelationTransaction,relationQuery} from '../../domain/src/relation-store.ts';

const workflow:ApprovalDefinition={formatVersion:1,id:'glossary_review',version:1,name:'Glossary term review',separationOfDuties:true,
 stages:[{id:'meaning_review',name:'Review meaning and audience',assignments:['reviewer'],quorum:1,deadlineSeconds:86400,rejection:'any'}]};
const examples=[
 {tenantId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',identityId:'10000000-0000-4000-8000-000000000001'},
 {tenantId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',identityId:'10000000-0000-4000-8000-000000000005'},
] as const;

export async function seedGlossary():Promise<void>{
 const connectionString=process.env.DATABASE_URL;
 if(!connectionString)throw new Error('DATABASE_URL is required for the explicit synthetic glossary seed.');
 // seedBusinessDomains closes the global DB. This independently owned pool is
 // never replaced with the migration-owner connection and always closes here.
 const pool=new pg.Pool({connectionString,max:1,connectionTimeoutMillis:5000,idleTimeoutMillis:5000});
 const database=new Kysely<Record<string,any>>({dialect:new PostgresDialect({pool})});
 try{
  for(const example of examples)await database.transaction().execute(async tx=>{
   await configureRelationTransaction(tx);
   await relationQuery(tx,()=>sql`select set_config('gc.tenant_id',${example.tenantId},true),set_config('gc.actor_id',${example.identityId},true)`.execute(tx));
   const role=(await relationQuery(tx,()=>sql<{safe:boolean}>`select not(r.rolsuper or r.rolbypassrls or r.rolcreaterole)
    and current_user=session_user
    and not exists(select 1 from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid=c.relnamespace
      where c.relowner=r.oid and n.nspname in ('public','gc_authn','gc_authority')) as safe
    from pg_catalog.pg_roles r where r.rolname=session_user`.execute(tx))).rows[0];
   if(role?.safe!==true)throw new Error('The glossary seed requires the nonowning runtime database role.');
   const member=await relationQuery(tx,()=>tx.selectFrom('memberships').innerJoin('identities','identities.id','memberships.identity_id')
    .select(['identities.name','memberships.permissions']).where('memberships.tenant_id','=',example.tenantId)
    .where('memberships.identity_id','=',example.identityId).where('memberships.active','=',true).where('identities.active','=',true).executeTakeFirst());
   if(!member||typeof member.name!=='string'||!Array.isArray(member.permissions)||member.permissions.some(value=>typeof value!=='string'))
    throw new Error('The synthetic glossary actor is unavailable.');
   const principal:Principal={id:example.identityId,tenantId:example.tenantId,name:member.name,permissions:member.permissions};
   await relationQuery(tx,()=>modelPersistence.authorize(tx,principal,['models:read']));
   const type=await relationQuery(tx,()=>tx.selectFrom('governance_models').select('id').where('tenant_id','=',principal.tenantId).where('id','=','business_term').executeTakeFirst());
   if(type){
    // This also rejects a colliding ordinary model or broken stored pin. Never
    // convert, repair or overwrite an operator-authored existing definition.
    await relationQuery(tx,()=>getAssetType(tx,principal,'business_term'));
   }else{
    await relationQuery(tx,()=>modelPersistence.authorize(tx,principal,['models:read','models:write']));
    const definition=glossaryStarterType();
    const created=await once(tx,principal,'asset-type.create','harbor-demo.glossary.v1.type',{definition},
     ()=>createAssetType(tx,principal,'harbor-demo.glossary.v1.type',definition,{record,assetSnapshot:assetView}),{
      query:work=>relationQuery(tx,work),
      authorizeReplay:async result=>{
       await relationQuery(tx,()=>modelPersistence.authorize(tx,principal,['models:read','models:write']));
       await relationQuery(tx,()=>getAssetType(tx,principal,result.type.id,result.type.version));
      },
     });
    await relationQuery(tx,()=>getAssetType(tx,principal,created.type.id,created.type.version));
    await relationQuery(tx,()=>modelPersistence.authorize(tx,principal,['models:read','models:write']));
   }
   const current=await relationQuery(tx,()=>tx.selectFrom('workflow_definitions').select('id').where('tenant_id','=',principal.tenantId).where('id','=',workflow.id).executeTakeFirst());
   if(current)await getApprovalDefinition(tx,principal,workflow.id);
   else await publishApprovalDefinition(tx,principal,workflow,0,'harbor-demo.glossary.v1.workflow','harbor-demo.glossary.v1.workflow');
   await relationQuery(tx,()=>sql`set constraints all immediate`.execute(tx));
  });
  console.log('Initialized missing glossary type and review workflow for two synthetic tenants; existing definitions were preserved. No terms, requests or approvals were created.');
 }catch{
  // Driver diagnostics can contain connection details. Keep seed errors closed;
  // callers qualify exact state separately instead of printing raw DB errors.
  throw new Error('Synthetic glossary initialization failed; existing definitions and authority were not replaced.');
 }finally{
  try{await database.destroy();}catch{throw new Error('Synthetic glossary runtime-pool cleanup failed.');}
 }
}
