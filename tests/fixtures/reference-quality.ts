// SPDX-License-Identifier: Apache-2.0
/** Disposable native fixture only. No credentials, source rows or SQL diagnostics are printed. */
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {readFileSync} from 'node:fs';
import type {TestContext} from 'node:test';
import pg from 'pg';
import {Kysely,PostgresDialect} from 'kysely';
import {sql,type Tx} from '../../packages/db/src/index.ts';
import type {Principal} from '../../packages/authz/src/index.ts';
import {assetView} from '../../apps/api/src/repository.ts';
import {configureRelationTransaction} from '../../packages/domain/src/relation-store.ts';
import {decideApprovalTask} from '../../packages/domain/src/approval-service.ts';
import type {Proposal,ReleaseInput} from '../../packages/domain/src/reference-data-contracts.ts';
import type {QualityClaim,QualityMeasurement,QualityReferenceBinding,QualityRuleView,QualityRuleDefinition,QualityRunView,ReferenceAllowedValuesRuleDefinition} from '../../packages/domain/src/quality-contracts.ts';

const configPath=process.env.AUTHN_FOUNDATION_CONFIG;
assert.ok(configPath,'Disposable native configuration is required; no shared runtime fallback');
const config=JSON.parse(readFileSync(configPath,'utf8')) as {owner:string;legacy:string};
assert.equal(typeof config.owner,'string');assert.equal(typeof config.legacy,'string');
process.env.SESSION_KEY=randomUUID()+randomUUID();
export const permissions=['catalog:read','catalog:write','models:read','models:write','reference:read','reference:write','reference:approve','quality:read','quality:write','quality:execute','audit:read'];
export const bindings=['quality_rule_reference_bindings','quality_run_reference_bindings'] as const;
const tables=['quality_rules','quality_rule_versions','quality_runs',...bindings,'reference_sets','reference_releases','reference_values','approval_requests','approval_tasks','approval_decisions','approval_dispatch','workflow_definitions','workflow_definition_versions','assets','asset_revisions','sources','audit','outbox','idempotency'];
export const code=(expected:string)=>(e:unknown)=>!!e&&typeof e==='object'&&'code'in e&&e.code===expected;
export const denied=(e:unknown)=>code('42501')(e)||code('P0002')(e);
export const sealFailure=(e:unknown)=>code('42501')(e)||code('23514')(e)||code('P0001')(e);
export function canonical(v:any):string{
 if(v instanceof Date)return JSON.stringify(v.toISOString());if(v===null||typeof v!=='object')return JSON.stringify(v);
 return Array.isArray(v)?'['+v.map(canonical).join(',')+']':'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}';
}
export const hash=(v:unknown)=>createHash('sha256').update(canonical(v),'utf8').digest('hex');
export function claimed(v:QualityClaim):asserts v is Extract<QualityClaim,{status:'claimed'}>{assert.equal(v.status,'claimed');}
export function resolved(v:QualityClaim):QualityReferenceBinding{claimed(v);assert.equal(v.execution.kind,'reference-allowed-values');if(v.execution.kind!=='reference-allowed-values')throw Error('Wrong native execution family');return v.execution.reference;}
export function referenceRun(v:QualityRunView):asserts v is QualityRunView & {kind:'reference-allowed-values';reference:Omit<QualityReferenceBinding,'codes'>}{assert.equal(v.kind,'reference-allowed-values');assert.ok(v.reference);assert.equal(Object.hasOwn(v.reference,'codes'),false);}
export const labels=(label='Reviewed codes')=>({en:{label,description:'Synthetic exact code-list qualification.'},ar:{label:'قائمة الرموز',description:'قائمة رموز اصطناعية للاختبار.'}});

export async function fixture(t:TestContext){
 const owner=new pg.Client({connectionString:config.owner,connectionTimeoutMillis:5000});
 const db=new Kysely<Record<string,any>>({dialect:new PostgresDialect({pool:new pg.Pool({connectionString:config.legacy,max:1,connectionTimeoutMillis:5000})})});
 t.after(async()=>{await db.destroy();await owner.end();});await owner.connect();await owner.query("SET statement_timeout='15s';SET lock_timeout='2s'");
 const tenant=randomUUID(),foreign=randomUUID();
 // Deliberate sort order supports the actual principal lock-order witness.
 const [ruleOwner,actor]=[randomUUID(),randomUUID()].sort();const reviewer=randomUUID(),reader=randomUUID(),outsider=randomUUID();
 const sourceId=randomUUID(),schemaId=randomUUID(),tableId=randomUUID(),columnId=randomUUID(),namespace='ref_quality_'+randomUUID().replaceAll('-','');
 const ownerTx=async<T>(work:()=>Promise<T>,scope=tenant,who=actor)=>{await owner.query('BEGIN');try{
  await owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[scope,who]);const value=await work();await owner.query('COMMIT');return value;
 }catch(e){await owner.query('ROLLBACK');throw e;}};
 await ownerTx(async()=>{
  await owner.query('INSERT INTO tenants(id,name) VALUES($1,$3),($2,$3)',[tenant,foreign,'Synthetic reference quality tenant']);
  for(const who of [actor,ruleOwner,reviewer,reader,outsider])await owner.query('INSERT INTO identities(id,issuer,subject,name) VALUES($1::uuid,$2,$1::uuid::text,$3)',[who,'https://reference-quality.invalid/owned','Synthetic participant']);
  for(const who of [actor,ruleOwner,reviewer,reader])await owner.query('INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,$3,$4::jsonb)',[tenant,who,'synthetic',JSON.stringify(who===reader?['catalog:read','quality:read','reference:read','audit:read']:permissions)]);
  await owner.query(`CREATE SCHEMA "${namespace}"`);await owner.query(`CREATE TABLE "${namespace}".observations(code text)`);
  await owner.query(`INSERT INTO "${namespace}".observations SELECT CASE WHEN i<=4 THEN NULL WHEN i<=10 THEN 'A' WHEN i<=16 THEN '01' ELSE 'invalid-'||i END FROM generate_series(1,20) i`);
 });
 await ownerTx(()=>owner.query('INSERT INTO memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,$3,$4::jsonb)',[foreign,outsider,'synthetic',JSON.stringify(permissions)]),foreign,outsider);
 const target=(await owner.query(`SELECT d.oid::text AS "databaseOid",d.datname AS "databaseName",n.oid::text AS "schemaOid",c.oid::text AS "relationOid",a.attnum AS "attributeNumber" FROM pg_database d CROSS JOIN pg_namespace n JOIN pg_class c ON c.relnamespace=n.oid JOIN pg_attribute a ON a.attrelid=c.oid AND a.attname='code' WHERE d.datname=current_database() AND n.nspname=$1 AND c.relname='observations'`,[namespace])).rows[0];assert.ok(target);
 await ownerTx(async()=>{
  await owner.query('INSERT INTO sources(tenant_id,id,name,host,port,database_name,schema_name,secret_ref,connector_id) VALUES($1,$2,$3,$4,5432,$5,$6,$7,$8)',[tenant,sourceId,'Synthetic reference quality source','reference-quality.invalid',target.databaseName,namespace,'synthetic-unresolved-reference-quality','postgresql']);
  const prefix='pg:'+target.databaseOid,schemaExternal=prefix+':schema:'+target.schemaOid,tableExternal=prefix+':relation:'+target.relationOid;
  const rows=[{id:schemaId,type:'schema',name:namespace,external:schemaExternal,parent:null,metadata:{oid:target.schemaOid,provenance:'source-observed'}},
   {id:tableId,type:'table',name:'observations',external:tableExternal,parent:schemaExternal,metadata:{oid:target.relationOid,relationKind:'r',schema:namespace,table:'observations',provenance:'source-observed'}},
   {id:columnId,type:'column',name:'code',external:tableExternal+':column:'+target.attributeNumber,parent:tableExternal,metadata:{dataType:'text',ordinalPosition:target.attributeNumber,nullable:true,provenance:'source-observed'}}];
  for(const r of rows){const row=(await owner.query('INSERT INTO assets(tenant_id,id,source_id,external_id,name,qualified_name,type,parent_external_id,metadata,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,clock_timestamp()) RETURNING *',[tenant,r.id,sourceId,r.external,r.name,namespace+'.'+r.type,r.type,r.parent,JSON.stringify(r.metadata)])).rows[0];
   await owner.query('INSERT INTO asset_revisions(tenant_id,asset_id,version,snapshot) VALUES($1,$2,1,$3::jsonb)',[tenant,r.id,JSON.stringify(assetView(row))]);}
 });
 const principal=(who=actor,scope=tenant):Principal=>({id:who,tenantId:scope,name:'Synthetic participant',permissions});
 const as=<T>(work:(tx:Tx)=>Promise<T>,who:string=actor,scope=tenant)=>db.transaction().execute(async tx=>{
  await sql`select set_config('gc.tenant_id',${scope},true),set_config('gc.actor_id',${who},true)`.execute(tx);await configureRelationTransaction(tx);return work(tx);
 });
 const call=async<T=any>(tx:Tx,functionName:'gc_quality_command'|'gc_reference_command'|'gc_approval_command',operation:string,body:unknown,key:string=randomUUID()):Promise<T>=>
  (await sql<{value:T}>`select ${sql.ref('public.'+functionName)}(${operation},${key},${JSON.stringify(body)}::jsonb,'reference-quality-native') as value`.execute(tx)).rows[0].value;
 const quality=<T=any>(operation:string,body:unknown,key:string=randomUUID(),who=actor,scope=tenant)=>as(tx=>call<T>(tx,'gc_quality_command',operation,body,key),who,scope);
 const workflowId='reference_quality_'+randomUUID().replaceAll('-','');
 const w=await as(tx=>call(tx,'gc_approval_command','approval.definition.publish',{expectedVersion:0,definition:{formatVersion:1,id:workflowId,version:1,name:'Independent code review',separationOfDuties:true,stages:[{id:'review',name:'Review',assignments:['reviewer'],quorum:1,deadlineSeconds:3600,rejection:'any'}]}}));
 const workflow={id:workflowId,version:1,definitionHash:w.definitionHash as string};
 const release=(codes=['01','A']):ReleaseInput=>({formatVersion:1,kind:'reference-code-list',labels:labels(),ownerId:actor,status:'active',activation:{kind:'on-publication'},validUntil:null,values:codes.map(code=>({code,labels:labels('Code '+code.slice(0,30)),ownerId:actor,status:'active',validFrom:null,validUntil:null}))});
 const proposal=(extra:Partial<Proposal>={}):Proposal=>({id:randomUUID(),setId:randomUUID(),expectedVersion:0,audience:{visibility:'tenant',allowedIdentityIds:[]},release:release(),workflow,assignments:{reviewer},expiresAt:new Date(Date.now()+3600000).toISOString(),...extra});
 const ready=async(p:Proposal)=>{
  await as(tx=>call(tx,'gc_reference_command','reference.propose',p));
  const stored=await as(async tx=>({request:await tx.selectFrom('approval_requests').selectAll().where('id','=',p.id).executeTakeFirstOrThrow(),task:await tx.selectFrom('approval_tasks').selectAll().where('request_id','=',p.id).executeTakeFirstOrThrow()}));
  await as(tx=>decideApprovalTask(tx,principal(reviewer),p.id,{proposalDigest:stored.request.proposal_digest,taskId:stored.task.id,taskVersion:stored.task.version,decision:'approve',reason:'Reviewed exact code list'},randomUUID(),'reference-quality-native'),reviewer);
  const tick=await as(async tx=>(await sql<{value:any}>`select public.gc_approval_tick(${p.id}::uuid) as value`.execute(tx)).rows[0].value,'site:local');assert.equal(tick.status,'ready');return p;
 };
 const publishReference=async(p=proposal())=>{await ready(p);const result=await as(async tx=>(await sql<{value:any}>`select public.gc_reference_publish(${p.id}::uuid) as value`.execute(tx)).rows[0].value);return {proposal:p,result};};
 const definition=(setId:string,maximumInvalidBasisPoints=0):ReferenceAllowedValuesRuleDefinition=>({formatVersion:1,kind:'reference-allowed-values',target:{tableAssetId:tableId,columnAssetId:columnId},name:'Exact code membership',purpose:'Compare current source observations with a retained reviewed reference release.',ownerId:ruleOwner,severity:'warning',maximumInvalidBasisPoints,reference:{setId,selection:'effective-at-run',codeStatus:'active'},comparison:'utf8-exact',nullPolicy:'exclude'});
 const publish=(definition:QualityRuleDefinition,id:string=randomUUID(),expectedVersion=0,key:string=randomUUID())=>quality<{rule:QualityRuleView}>('quality.rule.publish',{id,expectedVersion,definition},key);
 const requestBody=(rule:QualityRuleView,id:string=randomUUID(),asOf?:string)=>({ruleId:rule.id,id,ruleVersion:rule.version,ruleHash:rule.definitionHash,...(asOf===undefined?{}:{referenceAsOf:asOf})});
 const request=(rule:QualityRuleView,id:string=randomUUID(),asOf?:string,key:string=randomUUID())=>quality<{run:QualityRunView}>('quality.run.request',requestBody(rule,id,asOf),key);
 const claim=(runId:string,claimId=randomUUID())=>as(async tx=>(await sql<{value:QualityClaim}>`select public.gc_quality_claim(${runId}::uuid,${claimId}::uuid) as value`.execute(tx)).rows[0].value,'site:local');
 const finish=(runId:string,claim:Extract<QualityClaim,{status:'claimed'}>,measurement:QualityMeasurement)=>as(async tx=>(await sql<{value:{run:QualityRunView}}>`select public.gc_quality_finish(${runId}::uuid,${JSON.stringify({claimId:claim.claimId,attempt:claim.attempt,measurement})}::jsonb) as value`.execute(tx)).rows[0].value,'site:local');
 const now=async()=>String((await owner.query('SELECT public.gc_relation_utc(clock_timestamp()) AS value')).rows[0].value);
 const measurement=async(c:QualityClaim,rowCount=20,nullCount=4,invalidCount=4):Promise<QualityMeasurement>=>{const reference=resolved(c),at=await now();return {formatVersion:1,kind:'reference-allowed-values',strategy:'exact-bounded-role-scope',rowCount,nullCount,invalidCount,referenceBindingHash:reference.bindingHash,observedStartedAt:at,observedFinishedAt:at,elapsedMs:0,sourceVersion:'170006',adapterVersion:'1',queryTemplate:'postgresql-reference-allowed-values-v1',estimatedCost:1,estimatedBytes:160};};
 const state=()=>ownerTx(async()=>{const out:Record<string,any[]>={};for(const name of tables)out[name]=(await owner.query('SELECT * FROM public."'+name+'" WHERE tenant_id=$1',[tenant])).rows.sort((a,b)=>canonical(a)<canonical(b)?-1:1);return out;});
 const unchanged=async(work:()=>Promise<unknown>,predicate:(e:unknown)=>boolean)=>{const before=await state();await assert.rejects(work,predicate);assert.deepEqual(await state(),before,'Rejected operation preserves canonical data, history, bindings, journals and receipts');};
 const revoke=(who:string,grants:string[])=>ownerTx(()=>owner.query('UPDATE memberships SET permissions=$3::jsonb WHERE tenant_id=$1 AND identity_id=$2',[tenant,who,JSON.stringify(grants)]));
 const waitUntil=async(at:string)=>{const delay=Date.parse(at)-Date.parse(await now());assert.ok(delay<5000);await owner.query('SELECT pg_sleep(greatest(extract(epoch FROM $1::timestamptz-clock_timestamp()),0)+0.01)',[at]);};
 const connection=async()=>{const c=new pg.Client({connectionString:config.owner,connectionTimeoutMillis:5000});await c.connect();await c.query("SET statement_timeout='3s';SET lock_timeout='1s'");t.after(()=>c.end());return c;};
 return {owner,db,ownerTx,tenant,foreign,actor,ruleOwner,reviewer,reader,outsider,sourceId,schemaId,tableId,columnId,namespace,target,principal,as,call,quality,workflow,release,proposal,ready,publishReference,definition,publish,requestBody,request,claim,finish,now,measurement,state,unchanged,revoke,waitUntil,connection};
}
