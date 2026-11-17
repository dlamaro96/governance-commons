// SPDX-License-Identifier: Apache-2.0
import {createHash} from 'node:crypto';
import {sql,type Tx} from '../../db/src/index.ts';
import {Problem,type Principal} from '../../authz/src/index.ts';
import {modelPersistence} from './model-service.ts';
import {signedCursor} from './cursor.ts';
import {qualityObject,qualityId,qualityInteger,qualityText,qualityInvalid,parseQualityPublish,parseQualityRunInput,parseQualityRuleView,parseQualityRunView,parseQualityClaim,parseQualityCompletion} from './quality.ts';
import type {QualityAssetView,QualityPage,QualityPageQuery,QualityRuleView,QualityRunView,QualityClaim,QualityWorkflowInput} from './quality-contracts.ts';
const unavailable=()=>new Problem(404,'QUALITY_UNAVAILABLE','The quality resource or its target is unavailable.');
const integrity=()=>new Problem(500,'QUALITY_STORAGE_INVALID','The quality operation could not be completed.');
const retry=()=>new Problem(503,'QUALITY_RETRY','A stable execution window was unavailable. Retry with the same idempotency key.');
const deadlines=new WeakMap<Tx,number>();
export async function qualityQuery<T>(tx:Tx,work:()=>Promise<T>):Promise<T>{
 let deadline=deadlines.get(tx);if(deadline===undefined){deadline=performance.now()+30000;deadlines.set(tx,deadline);}
 const remaining=Math.floor(deadline-performance.now());if(remaining<1)throw retry();
 await sql`select set_config('statement_timeout',${String(remaining)},true),set_config('lock_timeout',${String(Math.min(5000,remaining))},true)`.execute(tx);
 const result=await work();if(performance.now()>=deadline)throw retry();return result;
}
export function qualityFailure(error:unknown):Problem {
 if(error instanceof Problem)return error;const e=error as {code?:unknown;message?:unknown}|null;
 const code=typeof e?.code==='string'?e.code:'',message=typeof e?.message==='string'?e.message:'';
 if(['55P03','40P01','57014'].includes(code))return retry();
 if(code==='P0002')return unavailable();
 if(code==='42501')return new Problem(403,'QUALITY_FORBIDDEN','Your current permissions do not allow this quality operation.');
 if(code==='40001')return ['IDEMPOTENCY_CONFLICT','VERSION_CONFLICT','QUALITY_RULE_PIN_STALE','QUALITY_STATE_CONFLICT','QUALITY_CLAIM_STALE','QUALITY_TARGET_STALE','QUALITY_TARGET_IMMUTABLE','QUALITY_CLAIM_EXPIRED','QUALITY_CLAIM_CONFLICT','QUALITY_COMPLETION_CONFLICT'].includes(message)
  ?new Problem(409,message,'The quality state changed. Reload before continuing.'):retry();
 if(code==='23505')return new Problem(409,'QUALITY_CONFLICT','The quality command conflicts with an existing record.');
 if(['22023','22007','22008','22P02','22003'].includes(code))return qualityInvalid();
 if(code==='54000')return new Problem(422,'QUALITY_LIMIT','The quality operation exceeds its supported bounds.');
 if(code==='0A000')return new Problem(422,'QUALITY_TARGET_UNSUPPORTED','This target is not supported by this execution family.');
 return integrity();
}
async function authorize(tx:Tx,p:Principal,extra:readonly string[]=[]){await qualityQuery(tx,()=>modelPersistence.authorize(tx,p,['catalog:read','quality:read',...extra]));}
function checked<T>(parse:(v:unknown)=>T,value:unknown):T {try{return parse(value);}catch{throw integrity();}}
function ruleView(value:unknown):QualityRuleView {const rule=checked(parseQualityRuleView,value);if(modelPersistence.hash(rule.definition)!==rule.definitionHash)throw integrity();return rule;}
function bounded<T>(value:T):T{if(Buffer.byteLength(JSON.stringify(value))>524288)throw new Problem(422,'QUALITY_LIMIT','This quality page exceeds its supported bounds.');return value;}
function options(p:Principal,scopeId:string,kind:'rules'|'runs',query:QualityPageQuery){
 const v=qualityObject(query,[],['limit','cursor']),limit=v.limit??25;qualityInteger(limit,1,100);
 const codec=signedCursor(process.env.SESSION_KEY,`quality-${kind}-v1`),binding=createHash('sha256').update(JSON.stringify([p.tenantId,p.id,scopeId,kind,limit])).digest('hex');
 let after:string|null=null;if(v.cursor!==undefined)try{if(typeof v.cursor!=='string')throw 0;const decoded=codec.decode(v.cursor);
  if(!Array.isArray(decoded)||decoded.length!==3||decoded[0]!==1||decoded[1]!==binding)throw 0;qualityId(decoded[2]);after=decoded[2];
 }catch{throw new Problem(400,'QUALITY_PAGE_INVALID','This quality page is invalid. Start a new listing.');}
 return {limit,after,next:(last:string)=>codec.encode([1,binding,last])};
}
async function visibleRule(tx:Tx,p:Principal,id:string):Promise<void>{
 const row=(await qualityQuery(tx,()=>sql`select 1 from public.quality_rules r where r.tenant_id=${p.tenantId}::uuid and r.id=${id}::uuid
  and public.gc_quality_visible(r.column_asset_id,${p.id}::uuid)`.execute(tx))).rows[0];if(!row)throw unavailable();
}
export async function getQualityAsset(tx:Tx,p:Principal,assetId:string,query:QualityPageQuery={}):Promise<QualityAssetView>{
 qualityId(assetId);const page=options(p,assetId,'rules',query);await authorize(tx,p);
 // General asset visibility precedes eligibility; the SQL helper additionally
 // checks all parent targets before returning their IDs or an actionable result.
 const asset=(await qualityQuery(tx,()=>sql`select id from public.assets where tenant_id=${p.tenantId}::uuid and id=${assetId}::uuid
  and (visibility='tenant' or allowed_identities @> ${JSON.stringify([p.id])}::jsonb)`.execute(tx))).rows[0];if(!asset)throw unavailable();
 const eligibility=(await qualityQuery(tx,()=>sql<{value:QualityAssetView['eligibility']}>`select public.gc_quality_eligibility(${assetId}::uuid,${p.id}::uuid) as value`.execute(tx))).rows[0]?.value;
 if(!eligibility||typeof eligibility.supported!=='boolean')throw integrity();
 const after=page.after===null?sql`true`:sql`r.id>${page.after}::uuid`;
 const rows=(await qualityQuery(tx,()=>sql<{value:unknown}>`select public.gc_quality_rule_view(r.id,r.current_version) as value from public.quality_rules r
  where r.tenant_id=${p.tenantId}::uuid and r.column_asset_id=${assetId}::uuid and public.gc_quality_visible(r.column_asset_id,${p.id}::uuid)
  and ${after} order by r.id limit ${page.limit+1}`.execute(tx))).rows;
 const items=rows.slice(0,page.limit).map(r=>ruleView(r.value));return bounded({assetId,eligibility,items,nextCursor:rows.length>page.limit?page.next(items.at(-1)!.id):null});
}
export async function getQualityRule(tx:Tx,p:Principal,ruleId:string,version?:number):Promise<QualityRuleView>{
 qualityId(ruleId);if(version!==undefined)qualityInteger(version);await authorize(tx,p);await visibleRule(tx,p,ruleId);
 const value=(await qualityQuery(tx,()=>sql<{value:unknown}>`select public.gc_quality_rule_view(r.id,${version===undefined?sql`r.current_version`:sql`${version}`}) as value
  from public.quality_rules r where r.tenant_id=${p.tenantId}::uuid and r.id=${ruleId}::uuid and public.gc_quality_visible(r.column_asset_id,${p.id}::uuid)`.execute(tx))).rows[0]?.value;
 if(!value)throw unavailable();return ruleView(value);
}
export async function listQualityRuns(tx:Tx,p:Principal,ruleId:string,query:QualityPageQuery={}):Promise<QualityPage<QualityRunView>>{
 qualityId(ruleId);const page=options(p,ruleId,'runs',query);await authorize(tx,p);await visibleRule(tx,p,ruleId);
 const after=page.after===null?sql`true`:sql`q.id>${page.after}::uuid`;
 const rows=(await qualityQuery(tx,()=>sql<{value:unknown}>`select public.gc_quality_run_view(q.id) as value from public.quality_runs q
  join public.quality_rules r on r.tenant_id=q.tenant_id and r.id=q.rule_id
  where q.tenant_id=${p.tenantId}::uuid and q.rule_id=${ruleId}::uuid and public.gc_quality_visible(r.column_asset_id,${p.id}::uuid)
  and ${after} order by q.id limit ${page.limit+1}`.execute(tx))).rows;
 const items=rows.slice(0,page.limit).map(r=>checked(parseQualityRunView,r.value));return bounded({items,nextCursor:rows.length>page.limit?page.next(items.at(-1)!.id):null});
}
export async function getQualityRun(tx:Tx,p:Principal,runId:string):Promise<QualityRunView>{
 qualityId(runId);await authorize(tx,p);
 const value=(await qualityQuery(tx,()=>sql<{value:unknown}>`select public.gc_quality_run_view(q.id) as value from public.quality_runs q
  join public.quality_rules r on r.tenant_id=q.tenant_id and r.id=q.rule_id
  where q.tenant_id=${p.tenantId}::uuid and q.id=${runId}::uuid and public.gc_quality_visible(r.column_asset_id,${p.id}::uuid)`.execute(tx))).rows[0]?.value;
 if(!value)throw unavailable();return checked(parseQualityRunView,value);
}
async function command(tx:Tx,operation:string,key:string,body:unknown,correlation:string):Promise<Record<string,unknown>>{
 if(typeof key!=='string'||key.length<8||key.length>128||/[\u0000-\u001f\u007f]/.test(key)||typeof correlation!=='string'||!correlation||correlation.length>128||/[\u0000-\u001f\u007f]/.test(correlation))throw qualityInvalid();
 const value=(await qualityQuery(tx,()=>sql<{value:unknown}>`select public.gc_quality_command(${operation},${key},${JSON.stringify(body)}::jsonb,${correlation}) as value`.execute(tx))).rows[0]?.value;
 return checked(v=>qualityObject(v,[operation==='quality.rule.publish'?'rule':'run']),value);
}
export async function publishQualityRule(tx:Tx,p:Principal,input:unknown,key:string,correlation:string){
 const body=parseQualityPublish(input);await authorize(tx,p,['quality:write']);const result=await command(tx,'quality.rule.publish',key,body,correlation);
 const rule=ruleView(result.rule);if(rule.id!==body.id||rule.version!==body.expectedVersion+1||rule.definitionHash!==modelPersistence.hash(body.definition))throw integrity();return {rule};
}
export async function requestQualityRun(tx:Tx,p:Principal,ruleId:string,input:unknown,key:string,correlation:string){
 qualityId(ruleId);const body=parseQualityRunInput(input);await authorize(tx,p,['quality:execute']);const result=await command(tx,'quality.run.request',key,{ruleId,...body},correlation);
 const run=checked(parseQualityRunView,result.run);if(run.id!==body.id||run.ruleId!==ruleId||run.ruleVersion!==body.ruleVersion||run.ruleHash!==body.ruleHash)throw integrity();return {run};
}
export async function cancelQualityRun(tx:Tx,p:Principal,runId:string,input:unknown,key:string,correlation:string){
 qualityId(runId);const body=qualityObject(input,['expectedVersion','reason']);qualityInteger(body.expectedVersion);const reason=qualityText(body.reason,4096);
 await authorize(tx,p,['quality:execute']);const result=await command(tx,'quality.run.cancel',key,{runId,expectedVersion:body.expectedVersion,reason},correlation);
 const run=checked(parseQualityRunView,result.run);if(run.id!==runId||run.version!==body.expectedVersion+1||run.status!=='cancelled')throw integrity();return {run};
}
/** Canonical pending rows drive dispatch independently of search's outbox ack. */
export async function pendingQualityRuns(tx:Tx,tenantId:string):Promise<{items:QualityWorkflowInput[]}>{
 qualityId(tenantId);const rows=(await qualityQuery(tx,()=>sql<{id:string;tenant_id:string}>`select id,tenant_id from public.quality_runs
 where tenant_id=${tenantId}::uuid and status in ('queued','running') order by created_at,id limit 50`.execute(tx))).rows;
 return {items:rows.map(r=>({tenantId:r.tenant_id,runId:r.id}))};
}
export async function claimQualityRun(tx:Tx,runId:string,input:unknown):Promise<QualityClaim>{
 qualityId(runId);const body=qualityObject(input,['claimId']);qualityId(body.claimId);
 const value=(await qualityQuery(tx,()=>sql<{value:unknown}>`select public.gc_quality_claim(${runId}::uuid,${body.claimId}::uuid) as value`.execute(tx))).rows[0]?.value;
 const claim=checked(parseQualityClaim,value);if(claim.status==='claimed'&&(claim.runId!==runId||claim.claimId!==body.claimId)||claim.status==='terminal'&&claim.run.id!==runId)throw integrity();return claim;
}
export async function finishQualityRun(tx:Tx,runId:string,input:unknown){
 qualityId(runId);const body=parseQualityCompletion(input);
 const value=(await qualityQuery(tx,()=>sql<{value:unknown}>`select public.gc_quality_finish(${runId}::uuid,${JSON.stringify(body)}::jsonb) as value`.execute(tx))).rows[0]?.value;
 const result=checked(v=>qualityObject(v,['run']),value),run=checked(parseQualityRunView,result.run);if(run.id!==runId)throw integrity();return {run};
}
