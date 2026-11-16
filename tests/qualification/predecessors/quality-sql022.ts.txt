// SPDX-License-Identifier: Apache-2.0
import {Problem} from '../../authz/src/index.ts';
import {QUALITY_BUDGET,QUALITY_ERRORS,type CompletenessRuleDefinition,type QualityPublishInput,type QualityRunInput,type QualityMeasurement,type QualityRuleView,type QualityRunView,type QualityClaim,type QualityCompletion,type QualityWorkflowInput,type QualityExecution} from './quality-contracts.ts';
export const QUALITY_UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const hash=/^[a-f0-9]{64}$/;
export const qualityInvalid=()=>new Problem(400,'QUALITY_INPUT_INVALID','Provide exactly the declared quality fields and values.');
export function qualityObject(value:unknown,keys:readonly string[],optional:readonly string[]=[]):Record<string,unknown>{
 try{if(!value||typeof value!=='object'||Array.isArray(value)||![Object.prototype,null].includes(Object.getPrototypeOf(value)))throw 0;
  const own=Reflect.ownKeys(value);if(own.length>keys.length+optional.length||keys.some(k=>!own.includes(k)))throw 0;
  const out:Record<string,unknown>=Object.create(null);for(const name of own){if(typeof name!=='string'||![...keys,...optional].includes(name))throw 0;
   const d=Object.getOwnPropertyDescriptor(value,name);if(!d?.enumerable||!Object.hasOwn(d,'value'))throw 0;out[name]=d.value;}return out;
 }catch{throw qualityInvalid();}
}
export function qualityId(value:unknown):asserts value is string {if(typeof value!=='string'||!QUALITY_UUID.test(value))throw qualityInvalid();}
export function qualityInteger(value:unknown,min=1,max=2147483647):asserts value is number {if(!Number.isSafeInteger(value)||Object.is(value,-0)||(value as number)<min||(value as number)>max)throw qualityInvalid();}
function digest(value:unknown):asserts value is string {if(typeof value!=='string'||!hash.test(value))throw qualityInvalid();}
export function qualityText(value:unknown,max:number):string {
 if(typeof value!=='string'||value.length>max||/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value))throw qualityInvalid();
 const normalized=value.normalize('NFC').trim();if(!normalized||normalized.length>max)throw qualityInvalid();return normalized;
}
function instant(value:unknown):asserts value is string {
 if(typeof value!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)||!Number.isFinite(Date.parse(value))||new Date(value).toISOString()!==value)throw qualityInvalid();
}
function finite(value:unknown,max:number):asserts value is number {if(typeof value!=='number'||!Number.isFinite(value)||Object.is(value,-0)||value<0||value>max)throw qualityInvalid();}
export function parseQualityDefinition(value:unknown):CompletenessRuleDefinition {
 const v=qualityObject(value,['formatVersion','kind','target','name','purpose','ownerId','severity','maximumNullBasisPoints']);
 const target=qualityObject(v.target,['tableAssetId','columnAssetId']);qualityId(target.tableAssetId);qualityId(target.columnAssetId);qualityId(v.ownerId);
 if(v.formatVersion!==1||v.kind!=='completeness'||!['info','warning','critical'].includes(v.severity as string)||target.tableAssetId===target.columnAssetId)throw qualityInvalid();
 qualityInteger(v.maximumNullBasisPoints,0,10000);if(typeof v.name==='string'&&/[\t\r\n]/.test(v.name))throw qualityInvalid();
 return {formatVersion:1,kind:'completeness',target:{tableAssetId:target.tableAssetId,columnAssetId:target.columnAssetId},name:qualityText(v.name,240),purpose:qualityText(v.purpose,4096),ownerId:v.ownerId,severity:v.severity as CompletenessRuleDefinition['severity'],maximumNullBasisPoints:v.maximumNullBasisPoints};
}
export function parseQualityPublish(value:unknown):QualityPublishInput {
 const v=qualityObject(value,['id','expectedVersion','definition']);qualityId(v.id);qualityInteger(v.expectedVersion,0,2147483646);
 return {id:v.id,expectedVersion:v.expectedVersion,definition:parseQualityDefinition(v.definition)};
}
export function parseQualityRunInput(value:unknown):QualityRunInput {
 const v=qualityObject(value,['id','ruleVersion','ruleHash']);qualityId(v.id);qualityInteger(v.ruleVersion);digest(v.ruleHash);
 return {id:v.id,ruleVersion:v.ruleVersion,ruleHash:v.ruleHash};
}
export function parseQualityMeasurement(value:unknown):QualityMeasurement {
 const v=qualityObject(value,['formatVersion','kind','strategy','rowCount','nullCount','observedStartedAt','observedFinishedAt','elapsedMs','sourceVersion','adapterVersion','queryTemplate','estimatedCost','estimatedBytes']);
 if(v.formatVersion!==1||v.kind!=='completeness'||v.strategy!=='exact-bounded-role-scope'||v.adapterVersion!=='1'||v.queryTemplate!=='postgresql-completeness-v1')throw qualityInvalid();
 qualityInteger(v.rowCount,0,QUALITY_BUDGET.maximumRows);qualityInteger(v.nullCount,0,v.rowCount);qualityInteger(v.elapsedMs,0,QUALITY_BUDGET.maximumSeconds*1000);
 instant(v.observedStartedAt);instant(v.observedFinishedAt);const elapsed=Date.parse(v.observedFinishedAt)-Date.parse(v.observedStartedAt);
 if(elapsed<0||elapsed>31000||Math.abs(elapsed-v.elapsedMs)>1000||typeof v.sourceVersion!=='string'||!/^\d{5,16}$/.test(v.sourceVersion))throw qualityInvalid();
 finite(v.estimatedCost,QUALITY_BUDGET.maximumEstimatedCost);qualityInteger(v.estimatedBytes,0,QUALITY_BUDGET.maximumEstimatedBytes);
 return {...v} as unknown as QualityMeasurement;
}
export function qualityVerdict(measurement:QualityMeasurement,maximumNullBasisPoints:number):'PASS'|'FAIL'|'NO_DATA'{
 const checked=parseQualityMeasurement(measurement);qualityInteger(maximumNullBasisPoints,0,10000);
 return checked.rowCount===0?'NO_DATA':BigInt(checked.nullCount)*10000n<=BigInt(checked.rowCount)*BigInt(maximumNullBasisPoints)?'PASS':'FAIL';
}
export function parseQualityRuleView(value:unknown):QualityRuleView {
 const v=qualityObject(value,['id','version','currentVersion','definition','definitionHash','createdAt','createdBy']);qualityId(v.id);qualityId(v.createdBy);qualityInteger(v.version);qualityInteger(v.currentVersion);digest(v.definitionHash);instant(v.createdAt);
 if(v.version>v.currentVersion)throw qualityInvalid();const definition=parseQualityDefinition(v.definition);
 if(JSON.stringify(definition)!==JSON.stringify(v.definition)){
  // JSON object order is immaterial; normalization must not repair stored text.
  const raw=v.definition as CompletenessRuleDefinition;if(raw.name!==definition.name||raw.purpose!==definition.purpose)throw qualityInvalid();
 }
 return {...v,definition} as unknown as QualityRuleView;
}
export function parseQualityRunView(value:unknown):QualityRunView {
 const v=qualityObject(value,['id','ruleId','ruleVersion','ruleHash','requesterId','columnAssetId','tableAssetId','status','version','attempt','createdAt','startedAt','finishedAt','expiresAt','measurement','verdict','errorCode']);
 for(const key of ['id','ruleId','requesterId','columnAssetId','tableAssetId'])qualityId(v[key]);qualityInteger(v.ruleVersion);digest(v.ruleHash);qualityInteger(v.version);qualityInteger(v.attempt,0,3);
 instant(v.createdAt);instant(v.expiresAt);if(v.startedAt!==null)instant(v.startedAt);if(v.finishedAt!==null)instant(v.finishedAt);
 if(!['queued','running','succeeded','failed','cancelled'].includes(v.status as string))throw qualityInvalid();
 const terminal=['succeeded','failed','cancelled'].includes(v.status as string);if(terminal!==(v.finishedAt!==null))throw qualityInvalid();
 if(v.status==='succeeded'){parseQualityMeasurement(v.measurement);if(!['PASS','FAIL','NO_DATA'].includes(v.verdict as string)||v.errorCode!==null||((v.measurement as QualityMeasurement).rowCount===0)!==(v.verdict==='NO_DATA'))throw qualityInvalid();}
 else {if(v.measurement!==null||v.verdict!==null)throw qualityInvalid();if(terminal?!QUALITY_ERRORS.includes(v.errorCode as never):v.errorCode!==null)throw qualityInvalid();}
 return {...v,measurement:v.measurement===null?null:parseQualityMeasurement(v.measurement)} as unknown as QualityRunView;
}
export function parseQualityCompletion(value:unknown):QualityCompletion {
 const v=qualityObject(value,['claimId','attempt'],['measurement','errorCode']);qualityId(v.claimId);qualityInteger(v.attempt,1,3);
 if(Object.hasOwn(v,'measurement')===Object.hasOwn(v,'errorCode'))throw qualityInvalid();
 if(Object.hasOwn(v,'measurement'))return {claimId:v.claimId,attempt:v.attempt,measurement:parseQualityMeasurement(v.measurement)};
 if(!QUALITY_ERRORS.includes(v.errorCode as never))throw qualityInvalid();return {claimId:v.claimId,attempt:v.attempt,errorCode:v.errorCode as (typeof QUALITY_ERRORS)[number]};
}
export function parseQualityWorkflowInput(value:unknown):QualityWorkflowInput {const v=qualityObject(value,['tenantId','runId']);qualityId(v.tenantId);qualityId(v.runId);return {tenantId:v.tenantId,runId:v.runId};}
/** PostgreSQL quoted names are exact data, including whitespace/control characters.
 * Match worker UTF-8 admission without normalization or replacement decoding. */
function postgresText(value:unknown,maximum:number,bytes=false):asserts value is string {
 if(typeof value!=='string'||!value||/\u0000|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value)
  ||(bytes?Buffer.byteLength(value):[...value].length)>maximum)throw qualityInvalid();
}
export function parseQualityExecution(value:unknown):QualityExecution {
 const v=qualityObject(value,['formatVersion','kind','target','budget']);if(v.formatVersion!==1||v.kind!=='completeness')throw qualityInvalid();
 const t=qualityObject(v.target,['databaseOid','schemaOid','relationOid','attributeNumber','schemaName','tableName','columnName','dataType']);
 for(const k of ['databaseOid','schemaOid','relationOid'])if(typeof t[k]!=='string'||!/^[1-9]\d{0,9}$/.test(t[k] as string)||Number(t[k])>4294967295)throw qualityInvalid();
 qualityInteger(t.attributeNumber,1,32767);for(const k of ['schemaName','tableName','columnName'])postgresText(t[k],63,true);postgresText(t.dataType,256);
 const b=qualityObject(v.budget,Object.keys(QUALITY_BUDGET));for(const k of Object.keys(QUALITY_BUDGET))if(b[k]!==QUALITY_BUDGET[k as keyof typeof QUALITY_BUDGET])throw qualityInvalid();
 return {...v,target:{...t},budget:{...b}} as unknown as QualityExecution;
}
export function parseQualityClaim(value:unknown):QualityClaim {
 const tag=qualityObject(value,['status'],['runId','claimId','attempt','leaseExpiresAt','source','execution','retryAt','run']);
 if(tag.status==='terminal'){const v=qualityObject(value,['status','run']);const run=parseQualityRunView(v.run);if(!['succeeded','failed','cancelled'].includes(run.status))throw qualityInvalid();return {status:'terminal',run};}
 if(tag.status==='busy'){const v=qualityObject(value,['status','retryAt']);instant(v.retryAt);return {status:'busy',retryAt:v.retryAt};}
 const v=qualityObject(value,['status','runId','claimId','attempt','leaseExpiresAt','source','execution']);if(v.status!=='claimed')throw qualityInvalid();
 qualityId(v.runId);qualityId(v.claimId);qualityInteger(v.attempt,1,3);instant(v.leaseExpiresAt);const source=qualityObject(v.source,['connectorId','host','port','database','schema','secretRef']);
 if(source.connectorId!=='postgresql')throw qualityInvalid();qualityInteger(source.port,1,65535);
 postgresText(source.host,253,true);if(/[\u0000-\u001f\u007f-\u009f]/.test(source.host))throw qualityInvalid();
 for(const k of ['database','schema'])postgresText(source[k],63,true);
 if(typeof source.secretRef!=='string'||!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(source.secretRef))throw qualityInvalid();
 const execution=parseQualityExecution(v.execution);if(execution.target.schemaName!==source.schema)throw qualityInvalid();
 return {...v,execution} as unknown as QualityClaim;
}
