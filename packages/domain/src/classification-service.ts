// SPDX-License-Identifier: Apache-2.0
import {createHash} from 'node:crypto';
import {sql,type Tx} from '../../db/src/index.ts';
import {Problem,type Principal} from '../../authz/src/index.ts';
import {modelPersistence} from './model-service.ts';
import {signedCursor} from './cursor.ts';
import {parseClassificationTaxonomy,parseMetadataClassificationRule,classificationDefinitionHash} from './classification.ts';
import type {ClassificationTaxonomy,MetadataClassificationRule,ClassificationPin,ClassificationEvidence,ClassificationTaxonomyView,ClassificationRuleView,ClassificationEvaluationView,ClassificationAssignmentView,ClassificationSuggestionView,ClassificationProposal,ClassificationProposalReceipt,ClassificationPage,ClassificationApprovalPayload,ClassificationApprovalResult} from './classification-contracts.ts';

const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const safeKey=/^(?!(?:__proto__|constructor|prototype)$)[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const digest=/^[a-f0-9]{64}$/;
const malformed=/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
export const classificationInvalid=()=>new Problem(400,'CLASSIFICATION_INPUT_INVALID','Provide exactly the declared classification fields and values.');
const unavailable=()=>new Problem(404,'CLASSIFICATION_UNAVAILABLE','The classification resource or its target is unavailable.');
const integrity=()=>new Problem(500,'CLASSIFICATION_STORAGE_INVALID','The classification operation could not be completed.');
const retry=()=>new Problem(503,'CLASSIFICATION_RETRY','A stable execution window was unavailable. Retry with the same idempotency key.');
const deadlines=new WeakMap<Tx,number>();
export async function classificationQuery<T>(tx:Tx,work:()=>Promise<T>):Promise<T>{
 let end=deadlines.get(tx);if(end===undefined){end=performance.now()+30000;deadlines.set(tx,end);}
 const remaining=Math.floor(end-performance.now());if(remaining<1)throw retry();
 await sql`select set_config('statement_timeout',${String(remaining)},true),set_config('lock_timeout',${String(Math.min(5000,remaining))},true)`.execute(tx);
 const result=await work();if(performance.now()>=end)throw retry();return result;
}
export function classificationFailure(error:unknown):Problem{
 if(error instanceof Problem)return error;
 const e=error as {code?:unknown;message?:unknown}|null,code=typeof e?.code==='string'?e.code:'',message=typeof e?.message==='string'?e.message:'';
 if(['55P03','40P01','57014'].includes(code))return retry();
 if(code==='P0002'&&message==='classification resource not found')return unavailable();
 if(code==='42501'&&message==='classification forbidden')return new Problem(403,'CLASSIFICATION_FORBIDDEN','Your current permissions do not allow this classification operation.');
 if(code==='40001'){const conflict:Record<string,string>={'classification version conflict':'VERSION_CONFLICT','classification evidence stale':'CLASSIFICATION_EVIDENCE_STALE','classification pin stale':'CLASSIFICATION_PIN_STALE'};
  return Object.hasOwn(conflict,message)?new Problem(409,conflict[message],'The classification state changed. Reload before continuing.'):retry();}
 if(code==='23514'&&message==='classification label key retired')return new Problem(422,'CLASSIFICATION_LABEL_RETIRED','This label key has been retired. Publish a new key for a new classification.');
 if(code==='23505')return new Problem(409,'CLASSIFICATION_CONFLICT','The classification command conflicts with an existing record.');
 if(code==='22023'&&message==='classification request invalid')return classificationInvalid();
 if(code==='54000')return new Problem(422,'CLASSIFICATION_LIMIT','This classification operation exceeds its supported bounds.');
 if(code==='0A000')return new Problem(422,'CLASSIFICATION_UNSUPPORTED','This asset is not supported by this classification family.');
 return integrity();
}
export function classificationObject(value:unknown,required:readonly string[],optional:readonly string[]=[]):Record<string,unknown>{
 try{
  if(!value||typeof value!=='object'||Array.isArray(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value)))throw 0;
  const keys=Reflect.ownKeys(value);if(keys.length>required.length+optional.length||required.some(k=>!keys.includes(k)))throw 0;
  return Object.fromEntries(keys.map(k=>{if(typeof k!=='string'||![...required,...optional].includes(k))throw 0;
   const d=Object.getOwnPropertyDescriptor(value,k);if(!d?.enumerable||!Object.hasOwn(d,'value'))throw 0;return [k,d.value];}));
 }catch{throw classificationInvalid();}
}
function id(v:unknown,pattern=uuid):asserts v is string{if(typeof v!=='string'||!pattern.test(v))throw classificationInvalid();}
function integer(v:unknown,minimum=1,maximum=2147483647):asserts v is number{if(typeof v!=='number'||!Number.isInteger(v)||Object.is(v,-0)||v<minimum||v>maximum)throw classificationInvalid();}
function text(v:unknown,max:number,empty=false):asserts v is string{if(typeof v!=='string'||(!empty&&!v.length)||v.length>max||malformed.test(v)||/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/.test(v))throw classificationInvalid();}
function stamp(v:unknown):asserts v is string{if(typeof v!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(v)||!Number.isFinite(Date.parse(v))||new Date(v).toISOString()!==v)throw classificationInvalid();}
function pin(v:unknown,workflow=false):ClassificationPin{const x=classificationObject(v,['id','version','definitionHash']);id(x.id,workflow?safeKey:uuid);integer(x.version);id(x.definitionHash,digest);return x as unknown as ClassificationPin;}
function label(v:unknown){const x=classificationObject(v,['taxonomy','labelKey']);id(x.labelKey,safeKey);return {taxonomy:pin(x.taxonomy),labelKey:x.labelKey};}
function boolean(v:unknown):asserts v is boolean{if(typeof v!=='boolean')throw classificationInvalid();}
function choice(v:unknown,values:readonly string[]):asserts v is string{if(typeof v!=='string'||!values.includes(v))throw classificationInvalid();}
function bounded<T>(value:T,max=524288):T{if(Buffer.byteLength(JSON.stringify(value))>max)throw new Problem(422,'CLASSIFICATION_LIMIT','This classification response exceeds its supported bounds.');return value;}
function stored<T>(work:()=>T):T{try{return work();}catch{throw integrity();}}
export function parseClassificationEvidence(value:unknown):ClassificationEvidence{
 const e=classificationObject(value,['formatVersion','kind','assetId','observedAssetVersion','inputDigest','rule','label','evaluatedAt','matches','confidence','samplePolicy']);
 if(e.formatVersion!==1||e.kind!=='metadata-literal')throw classificationInvalid();id(e.assetId);integer(e.observedAssetVersion);id(e.inputDigest,digest);stamp(e.evaluatedAt);
 const confidence=classificationObject(e.confidence,['kind','reason']),sample=classificationObject(e.samplePolicy,['kind','sourceRowsRead','sourceSamplesStored']);
 if(confidence.kind!=='not-estimated'||confidence.reason!=='metadata-only'||sample.kind!=='metadata-only'||sample.sourceRowsRead!==0||sample.sourceSamplesStored!==0)throw classificationInvalid();
 let ownMatches:unknown[];try{if(!Array.isArray(e.matches)||Object.getPrototypeOf(e.matches)!==Array.prototype)throw 0;const length=Object.getOwnPropertyDescriptor(e.matches,'length')?.value;
  if(!Number.isInteger(length)||length<0||length>8||Reflect.ownKeys(e.matches).length!==length+1)throw 0;ownMatches=Array.from({length},(_,i)=>{const d=Object.getOwnPropertyDescriptor(e.matches,String(i));if(!d?.enumerable||!Object.hasOwn(d,'value'))throw 0;return d.value;});
 }catch{throw classificationInvalid();}let last=-1;
 const matches=ownMatches.map(v=>{const m=classificationObject(v,['conditionIndex','field','value','valueHash']);integer(m.conditionIndex,0,7);if(m.conditionIndex<=last)throw classificationInvalid();last=m.conditionIndex;
  choice(m.field,['name','qualifiedName','dataType']);text(m.value,2048);if(/[\u0000-\u001f\u007f-\u009f]/.test(m.value))throw classificationInvalid();id(m.valueHash,digest);if(createHash('sha256').update(m.value).digest('hex')!==m.valueHash)throw classificationInvalid();return m;});
 return bounded({...e,rule:pin(e.rule),label:label(e.label),matches,confidence,samplePolicy:sample} as unknown as ClassificationEvidence,32768);
}
export function parseClassificationTaxonomyView(value:unknown):ClassificationTaxonomyView{
 const v=classificationObject(value,['id','version','definitionHash','currentVersion','definition','createdAt','createdBy']);id(v.id);integer(v.version);integer(v.currentVersion);id(v.definitionHash,digest);id(v.createdBy);stamp(v.createdAt);
 const definition=parseClassificationTaxonomy(v.definition);if(!definition.ok||v.currentVersion<v.version||classificationDefinitionHash(definition.value)!==v.definitionHash)throw classificationInvalid();
 return {...v,definition:definition.value} as unknown as ClassificationTaxonomyView;
}
export function parseClassificationRuleView(value:unknown):ClassificationRuleView{
 const v=classificationObject(value,['id','version','definitionHash','currentVersion','definition','createdAt','createdBy']);id(v.id);integer(v.version);integer(v.currentVersion);id(v.definitionHash,digest);id(v.createdBy);stamp(v.createdAt);
 const definition=parseMetadataClassificationRule(v.definition);if(!definition.ok||v.currentVersion<v.version||classificationDefinitionHash(definition.value)!==v.definitionHash)throw classificationInvalid();
 return {...v,definition:definition.value} as unknown as ClassificationRuleView;
}
export function parseClassificationEvaluationView(value:unknown):ClassificationEvaluationView{
 const v=classificationObject(value,['id','outcome','evidence','createdBy','suggestionId','evidenceHash']);id(v.id);id(v.createdBy);id(v.evidenceHash,digest);choice(v.outcome,['matched','not_matched','unsupported']);
 if(v.suggestionId!==null)id(v.suggestionId);if((v.outcome==='matched')!==(v.suggestionId!==null)||v.suggestionId!==null&&v.suggestionId!==v.id)throw classificationInvalid();
 const evidence=parseClassificationEvidence(v.evidence);if(modelPersistence.hash(evidence)!==v.evidenceHash||v.outcome==='unsupported'&&evidence.matches.length)throw classificationInvalid();
 bounded({outcome:v.outcome,evidence},32768);return {...v,evidence} as unknown as ClassificationEvaluationView;
}
export function parseClassificationAssignmentView(value:unknown):ClassificationAssignmentView{
 const v=classificationObject(value,['id','assetId','label','version','status','suggestionId','approvalInstanceId','evidence','evidenceCurrent','createdAt','updatedAt','updatedBy','reason']);
 for(const k of ['id','assetId','suggestionId','approvalInstanceId','updatedBy'])id(v[k]);integer(v.version);choice(v.status,['active','withdrawn']);boolean(v.evidenceCurrent);stamp(v.createdAt);stamp(v.updatedAt);text(v.reason,4096,true);
 const evidence=parseClassificationEvidence(v.evidence),selected=label(v.label);if(evidence.assetId!==v.assetId||modelPersistence.hash(evidence.label)!==modelPersistence.hash(selected))throw classificationInvalid();
 return {...v,label:selected,evidence} as unknown as ClassificationAssignmentView;
}
export function parseClassificationSuggestionView(value:unknown):ClassificationSuggestionView{
 const v=classificationObject(value,['id','assetId','evaluationId','evidence','evidenceHash','evidenceCurrent','currentAssignmentVersion','createdAt','createdBy']);
 for(const k of ['id','assetId','evaluationId','createdBy'])id(v[k]);id(v.evidenceHash,digest);integer(v.currentAssignmentVersion,0);boolean(v.evidenceCurrent);stamp(v.createdAt);
 const evidence=parseClassificationEvidence(v.evidence);if(v.id!==v.evaluationId||evidence.assetId!==v.assetId||modelPersistence.hash(evidence)!==v.evidenceHash)throw classificationInvalid();return {...v,evidence} as unknown as ClassificationSuggestionView;
}
export function parseClassificationProposal(value:unknown):ClassificationProposal{
 const v=classificationObject(value,['id','change','workflow','assignments','expiresAt']);id(v.id);stamp(v.expiresAt);
 const raw=classificationObject(v.change,['kind'],['suggestionId','assignmentId','expectedAssignmentVersion','reason']);
 let change:ClassificationProposal['change'];
 if(raw.kind==='apply'){const c=classificationObject(raw,['kind','suggestionId','expectedAssignmentVersion']);id(c.suggestionId);integer(c.expectedAssignmentVersion,0);change=c as unknown as ClassificationProposal['change'];}
 else if(raw.kind==='withdraw'){const c=classificationObject(raw,['kind','assignmentId','expectedAssignmentVersion','reason']);id(c.assignmentId);integer(c.expectedAssignmentVersion);text(c.reason,4096);const reason=c.reason.normalize('NFC').trim();if(!reason)throw classificationInvalid();change={kind:'withdraw',assignmentId:c.assignmentId,expectedAssignmentVersion:c.expectedAssignmentVersion,reason};}
 else throw classificationInvalid();
 let keys:string[];try{if(!v.assignments||typeof v.assignments!=='object'||Array.isArray(v.assignments))throw 0;keys=Object.getOwnPropertyNames(v.assignments);}catch{throw classificationInvalid();}
 if(!keys.length||keys.length>256||keys.some(k=>!safeKey.test(k)))throw classificationInvalid();const assignments=classificationObject(v.assignments,keys);for(const member of Object.values(assignments))id(member);
 return {id:v.id,change,workflow:pin(v.workflow,true),assignments:assignments as Record<string,string>,expiresAt:v.expiresAt};
}
export function parseClassificationApprovalPayload(value:unknown):ClassificationApprovalPayload{
 const v=classificationObject(value,['formatVersion','kind','change','assetId','assignmentId','expectedAssignmentVersion','suggestionId','label','evidence','evidenceHash','reason']);
 if(v.formatVersion!==1||v.kind!=='classification-review')throw classificationInvalid();choice(v.change,['apply','withdraw']);
 for(const k of ['assetId','assignmentId','suggestionId'])id(v[k]);integer(v.expectedAssignmentVersion,v.change==='apply'?0:1);id(v.evidenceHash,digest);text(v.reason,4096,v.change==='apply');
 if(v.change==='apply'&&v.reason!==''||v.change==='withdraw'&&!(v.reason as string).trim())throw classificationInvalid();
 const evidence=parseClassificationEvidence(v.evidence),selected=label(v.label);
 if(evidence.assetId!==v.assetId||modelPersistence.hash(evidence)!==v.evidenceHash||modelPersistence.hash(evidence.label)!==modelPersistence.hash(selected))throw classificationInvalid();
 return bounded({...v,evidence,label:selected} as unknown as ClassificationApprovalPayload,65536);
}
export function parseClassificationApprovalResult(value:unknown):ClassificationApprovalResult{
 const v=classificationObject(value,['binding','assetId','assignmentId','assignmentVersion','status','evidenceHash']);
 if(v.binding!=='classification.review')throw classificationInvalid();id(v.assetId);id(v.assignmentId);integer(v.assignmentVersion);choice(v.status,['active','withdrawn']);id(v.evidenceHash,digest);
 return v as unknown as ClassificationApprovalResult;
}
export interface ClassificationPageQuery{limit?:number;cursor?:string}
function options(p:Principal,collection:string,assetId:string|null,query:ClassificationPageQuery){
 const q=classificationObject(query,[],['limit','cursor']),limit=q.limit??25;integer(limit,1,100);
 const codec=signedCursor(process.env.SESSION_KEY,'classification-'+collection+'-v1'),binding=createHash('sha256').update(JSON.stringify([p.tenantId,p.id,collection,assetId,limit])).digest('hex');let after:string|null=null;
 if(q.cursor!==undefined)try{if(typeof q.cursor!=='string'||!q.cursor||q.cursor.length>1024)throw 0;const c=codec.decode(q.cursor);if(!Array.isArray(c)||c.length!==3||c[0]!==1||c[1]!==binding)throw 0;id(c[2]);after=c[2];}catch{throw new Problem(400,'CLASSIFICATION_PAGE_INVALID','This classification page is invalid. Start a new listing.');}
 return {limit,after,next:(last:string)=>codec.encode([1,binding,last])};
}
const read=['catalog:read','classification:read'];
async function authorize(tx:Tx,p:Principal,actions:readonly string[]){await classificationQuery(tx,()=>modelPersistence.authorize(tx,p,actions));}
async function visibleAsset(tx:Tx,p:Principal,assetId:string){const row=(await classificationQuery(tx,()=>sql`select 1 from public.assets a where a.tenant_id=${p.tenantId}::uuid and a.id=${assetId}::uuid and public.gc_classification_visible(a.id,${p.id}::uuid)`.execute(tx))).rows[0];if(!row)throw unavailable();}
async function definitions(tx:Tx,p:Principal,kind:'taxonomies'|'rules',query:ClassificationPageQuery){
 const page=options(p,kind,null,query);await authorize(tx,p,read);const table=kind==='taxonomies'?sql`public.classification_taxonomies`:sql`public.classification_rules`,after=page.after===null?sql`true`:sql`h.id>${page.after}::uuid`;
 const view=kind==='taxonomies'?sql`public.gc_classification_taxonomy_view(h.id,h.current_version)`:sql`public.gc_classification_rule_view(h.id,h.current_version)`;
 const rows=(await classificationQuery(tx,()=>sql<{value:unknown}>`select ${view} as value from ${table} h where h.tenant_id=${p.tenantId}::uuid and ${after} order by h.id limit ${page.limit+1}`.execute(tx))).rows;
 const items=rows.slice(0,page.limit).map(r=>stored(()=>kind==='taxonomies'?parseClassificationTaxonomyView(r.value):parseClassificationRuleView(r.value)));
 return bounded({items,nextCursor:rows.length>page.limit?page.next(items.at(-1)!.id):null});
}
export const listClassificationTaxonomies=(tx:Tx,p:Principal,q:ClassificationPageQuery={})=>definitions(tx,p,'taxonomies',q) as Promise<ClassificationPage<ClassificationTaxonomyView>>;
export const listClassificationRules=(tx:Tx,p:Principal,q:ClassificationPageQuery={})=>definitions(tx,p,'rules',q) as Promise<ClassificationPage<ClassificationRuleView>>;
async function definition(tx:Tx,p:Principal,kind:'taxonomies'|'rules',identity:string,selected?:number){
 id(identity);if(selected!==undefined)integer(selected);await authorize(tx,p,read);const table=kind==='taxonomies'?sql`public.classification_taxonomies`:sql`public.classification_rules`,revision=selected===undefined?sql`h.current_version`:sql`${selected}::integer`;
 const view=kind==='taxonomies'?sql`public.gc_classification_taxonomy_view(h.id,${revision})`:sql`public.gc_classification_rule_view(h.id,${revision})`;
 const value=(await classificationQuery(tx,()=>sql<{value:unknown}>`select ${view} as value from ${table} h where h.tenant_id=${p.tenantId}::uuid and h.id=${identity}::uuid`.execute(tx))).rows[0]?.value;if(value===undefined||value===null)throw unavailable();
 const parsed=stored(()=>kind==='taxonomies'?parseClassificationTaxonomyView(value):parseClassificationRuleView(value));if(parsed.id!==identity||selected!==undefined&&parsed.version!==selected)throw integrity();return bounded(parsed);
}
export const getClassificationTaxonomy=(tx:Tx,p:Principal,id:string,v?:number)=>definition(tx,p,'taxonomies',id,v) as Promise<ClassificationTaxonomyView>;
export const getClassificationRule=(tx:Tx,p:Principal,id:string,v?:number)=>definition(tx,p,'rules',id,v) as Promise<ClassificationRuleView>;
async function assetPage(tx:Tx,p:Principal,assetId:string,kind:'assignments'|'suggestions',query:ClassificationPageQuery){
 id(assetId);const page=options(p,kind,assetId,query);await authorize(tx,p,read);await visibleAsset(tx,p,assetId);
 const table=kind==='assignments'?sql`public.classification_assignments`:sql`public.classification_evaluations`,view=kind==='assignments'?sql`public.gc_classification_assignment_view(r.id,${p.id}::uuid)`:sql`public.gc_classification_suggestion_view(r.id,${p.id}::uuid)`;
 const after=page.after===null?sql`true`:sql`r.id>${page.after}::uuid`,matched=kind==='suggestions'?sql`r.outcome='matched'`:sql`true`;
 const rows=(await classificationQuery(tx,()=>sql<{value:unknown}>`select ${view} as value from ${table} r where r.tenant_id=${p.tenantId}::uuid and r.asset_id=${assetId}::uuid and public.gc_classification_visible(r.asset_id,${p.id}::uuid) and ${matched} and ${after} order by r.id limit ${page.limit+1}`.execute(tx))).rows;
 const items=rows.slice(0,page.limit).map(r=>stored(()=>kind==='assignments'?parseClassificationAssignmentView(r.value):parseClassificationSuggestionView(r.value)));
 if(items.some(v=>v.assetId!==assetId))throw integrity();return bounded({items,nextCursor:rows.length>page.limit?page.next(items.at(-1)!.id):null});
}
export const listClassificationAssignments=(tx:Tx,p:Principal,a:string,q:ClassificationPageQuery={})=>assetPage(tx,p,a,'assignments',q) as Promise<ClassificationPage<ClassificationAssignmentView>>;
export const listClassificationSuggestions=(tx:Tx,p:Principal,a:string,q:ClassificationPageQuery={})=>assetPage(tx,p,a,'suggestions',q) as Promise<ClassificationPage<ClassificationSuggestionView>>;
async function command(tx:Tx,operation:string,key:string,body:unknown,correlation:string):Promise<Record<string,unknown>>{
 if(typeof key!=='string'||key.length<8||key.length>128||/[\u0000-\u001f\u007f]/.test(key)||typeof correlation!=='string'||!correlation||correlation.length>128||/[\u0000-\u001f\u007f]/.test(correlation))throw classificationInvalid();
 const value=(await classificationQuery(tx,()=>sql<{value:unknown}>`select public.gc_classification_command(${operation},${key},${JSON.stringify(body)}::jsonb,${correlation}) as value`.execute(tx))).rows[0]?.value;
 return stored(()=>classificationObject(value,[operation==='classification.taxonomy.publish'?'taxonomy':operation==='classification.rule.publish'?'rule':operation==='classification.evaluate'?'evaluation':'instance']));
}
async function publish(tx:Tx,p:Principal,input:unknown,key:string,correlation:string,kind:'taxonomy'|'rule'){
 const body=classificationObject(input,['id','expectedVersion','definition']);id(body.id);integer(body.expectedVersion,0,2147483646);
 const parsed=kind==='taxonomy'?parseClassificationTaxonomy(body.definition):parseMetadataClassificationRule(body.definition);if(!parsed.ok)throw new Problem(422,'CLASSIFICATION_DEFINITION_INVALID','Correct the classification definition.',parsed.issues);
 await authorize(tx,p,['catalog:read','classification:read','models:read','models:write','classification:write']);const result=await command(tx,'classification.'+kind+'.publish',key,{...body,definition:parsed.value},correlation);
 const view=stored(()=>kind==='taxonomy'?parseClassificationTaxonomyView(result.taxonomy):parseClassificationRuleView(result.rule));
 if(view.id!==body.id||view.version!==body.expectedVersion+1||view.definitionHash!==classificationDefinitionHash(parsed.value))throw integrity();return kind==='taxonomy'?{taxonomy:view as ClassificationTaxonomyView}:{rule:view as ClassificationRuleView};
}
export const publishClassificationTaxonomy=(tx:Tx,p:Principal,i:unknown,k:string,c:string)=>publish(tx,p,i,k,c,'taxonomy');
export const publishClassificationRule=(tx:Tx,p:Principal,i:unknown,k:string,c:string)=>publish(tx,p,i,k,c,'rule');
export async function evaluateClassificationAsset(tx:Tx,p:Principal,assetId:string,input:unknown,key:string,correlation:string){
 id(assetId);const body=classificationObject(input,['id','expectedAssetVersion','rule']);id(body.id);integer(body.expectedAssetVersion);const selected=pin(body.rule);await authorize(tx,p,['catalog:read','classification:read','classification:write']);
 const result=await command(tx,'classification.evaluate',key,{assetId,...body,rule:selected},correlation),evaluation=stored(()=>parseClassificationEvaluationView(result.evaluation));
 if(evaluation.id!==body.id||evaluation.evidence.assetId!==assetId||evaluation.evidence.observedAssetVersion!==body.expectedAssetVersion||modelPersistence.hash(evaluation.evidence.rule)!==modelPersistence.hash(selected))throw integrity();return {evaluation};
}
export async function proposeClassification(tx:Tx,p:Principal,input:unknown,key:string,correlation:string):Promise<ClassificationProposalReceipt>{
 const body=parseClassificationProposal(input);await authorize(tx,p,['catalog:read','classification:read','classification:write']);const result=await command(tx,'classification.propose',key,body,correlation);
 const instance=stored(()=>classificationObject(result.instance,['id']));if(instance.id!==body.id)throw integrity();return {instance:{id:body.id}};
}
