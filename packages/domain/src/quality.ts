// SPDX-License-Identifier: Apache-2.0
import {createHash} from 'node:crypto';
import {Problem} from '../../authz/src/index.ts';
import {QUALITY_BUDGET,QUALITY_UNIQUENESS_BUDGET,QUALITY_FRESHNESS_LIMITS,QUALITY_ERRORS,type CompletenessRuleDefinition,type QualityRuleDefinition,type QualityReferenceMetadata,type QualityReferenceBinding,type QualitySource,type QualityPublishInput,type QualityRunInput,type QualityMeasurement,type QualityRuleView,type QualityRunView,type QualityClaim,type QualityCompletion,type QualityWorkflowInput,type QualityExecution,type QualityRangeBinding,type QualityFreshnessBinding,type QualityFreshnessSettings,type FreshnessMeasurement} from './quality-contracts.ts';
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
export function parseQualityDefinition(value:unknown):QualityRuleDefinition {
 const common=['formatVersion','kind','target','name','purpose','ownerId','severity'];
 const tag=qualityObject(value,common,['maximumNullBasisPoints','maximumInvalidBasisPoints','maximumDuplicateBasisPoints','maximumOutOfRangeBasisPoints','minimum','maximum','reference','comparison','nullPolicy','maximumAgeSeconds','maximumFutureSkewSeconds','clock','invalidTimestampPolicy']);
 const reference=tag.kind==='reference-allowed-values',unique=tag.kind==='uniqueness',range=tag.kind==='range',freshness=tag.kind==='freshness';
 const v=qualityObject(value,[...common,...(freshness?['maximumAgeSeconds','maximumFutureSkewSeconds','comparison','clock','nullPolicy','invalidTimestampPolicy']:range?['maximumOutOfRangeBasisPoints','minimum','maximum','comparison','nullPolicy']:reference?['maximumInvalidBasisPoints','reference','comparison','nullPolicy']:unique?['maximumDuplicateBasisPoints','comparison','nullPolicy']:['maximumNullBasisPoints'])]);
 const target=qualityObject(v.target,['tableAssetId','columnAssetId']);qualityId(target.tableAssetId);qualityId(target.columnAssetId);qualityId(v.ownerId);
 if(v.formatVersion!==1||!['completeness','reference-allowed-values','uniqueness','range','freshness'].includes(v.kind as string)||!['info','warning','critical'].includes(v.severity as string)||target.tableAssetId===target.columnAssetId)throw qualityInvalid();
 if(typeof v.name==='string'&&/[\t\r\n]/.test(v.name))throw qualityInvalid();
 const shared={formatVersion:1 as const,target:{tableAssetId:target.tableAssetId,columnAssetId:target.columnAssetId},name:qualityText(v.name,240),purpose:qualityText(v.purpose,4096),ownerId:v.ownerId,severity:v.severity as CompletenessRuleDefinition['severity']};
 if(freshness)return {...shared,kind:'freshness',...freshnessFields({maximumAgeSeconds:v.maximumAgeSeconds,maximumFutureSkewSeconds:v.maximumFutureSkewSeconds,comparison:v.comparison,clock:v.clock,nullPolicy:v.nullPolicy,invalidTimestampPolicy:v.invalidTimestampPolicy})};
 if(range){qualityInteger(v.maximumOutOfRangeBasisPoints,0,10000);const bounds=rangeFields({minimum:v.minimum,maximum:v.maximum,comparison:v.comparison,nullPolicy:v.nullPolicy});return {...shared,kind:'range',maximumOutOfRangeBasisPoints:v.maximumOutOfRangeBasisPoints,...bounds};}
 if(unique){qualityInteger(v.maximumDuplicateBasisPoints,0,10000);if(v.comparison!=='utf8-exact'||v.nullPolicy!=='exclude')throw qualityInvalid();return {...shared,kind:'uniqueness',maximumDuplicateBasisPoints:v.maximumDuplicateBasisPoints,comparison:'utf8-exact',nullPolicy:'exclude'};}
 if(!reference){qualityInteger(v.maximumNullBasisPoints,0,10000);return {...shared,kind:'completeness',maximumNullBasisPoints:v.maximumNullBasisPoints};}
 qualityInteger(v.maximumInvalidBasisPoints,0,10000);const ref=qualityObject(v.reference,['setId','selection','codeStatus']);qualityId(ref.setId);if(ref.setId==='00000000-0000-0000-0000-000000000000')throw qualityInvalid();
 if(ref.selection!=='effective-at-run'||ref.codeStatus!=='active'||v.comparison!=='utf8-exact'||v.nullPolicy!=='exclude')throw qualityInvalid();
 return {...shared,kind:'reference-allowed-values',maximumInvalidBasisPoints:v.maximumInvalidBasisPoints,reference:{setId:ref.setId,selection:'effective-at-run',codeStatus:'active'},comparison:'utf8-exact',nullPolicy:'exclude'};
}
export function parseQualityPublish(value:unknown):QualityPublishInput {
 const v=qualityObject(value,['id','expectedVersion','definition']);qualityId(v.id);qualityInteger(v.expectedVersion,0,2147483646);
 return {id:v.id,expectedVersion:v.expectedVersion,definition:parseQualityDefinition(v.definition)};
}
export function parseQualityRunInput(value:unknown):QualityRunInput {
 const v=qualityObject(value,['id','ruleVersion','ruleHash'],['referenceAsOf']);qualityId(v.id);qualityInteger(v.ruleVersion);digest(v.ruleHash);
 if(Object.hasOwn(v,'referenceAsOf')){instant(v.referenceAsOf);if(v.referenceAsOf.startsWith('0000'))throw qualityInvalid();}
 // Omission is deliberately retained: SQL hashes this unresolved request before resolving its clock.
 return {id:v.id,ruleVersion:v.ruleVersion,ruleHash:v.ruleHash,...(Object.hasOwn(v,'referenceAsOf')?{referenceAsOf:v.referenceAsOf as string}:{})};
}
export function parseQualityMeasurement(value:unknown):QualityMeasurement {
 const common=['formatVersion','kind','strategy','rowCount','nullCount','observedStartedAt','observedFinishedAt','elapsedMs','sourceVersion','adapterVersion','queryTemplate','estimatedCost','estimatedBytes'];
 const uniqueFields=['distinctCount','duplicateGroupCount','duplicateRowCount','totalValueBytes','largestValueBytes'];
 const freshFields=['nonFiniteCount','unrepresentableCount','futureCount','sourceObservedAt','latestObservedAt','ageMicroseconds','freshnessHash'];
 const tag=qualityObject(value,common,['invalidCount','referenceBindingHash','belowCount','aboveCount','rangeHash',...uniqueFields,...freshFields]),reference=tag.kind==='reference-allowed-values',unique=tag.kind==='uniqueness',range=tag.kind==='range',freshness=tag.kind==='freshness';
 const v=qualityObject(value,[...common,...(freshness?freshFields:range?['belowCount','aboveCount','rangeHash']:reference?['invalidCount','referenceBindingHash']:unique?uniqueFields:[])]);
 if(v.formatVersion!==1||!['completeness','reference-allowed-values','uniqueness','range','freshness'].includes(v.kind as string)||v.strategy!=='exact-bounded-role-scope'||v.adapterVersion!=='1'||v.queryTemplate!==(freshness?'postgresql-freshness-v1':range?'postgresql-range-v1':reference?'postgresql-reference-allowed-values-v1':unique?'postgresql-uniqueness-v1':'postgresql-completeness-v1'))throw qualityInvalid();
 qualityInteger(v.rowCount,0,QUALITY_BUDGET.maximumRows);qualityInteger(v.nullCount,0,v.rowCount);qualityInteger(v.elapsedMs,0,QUALITY_BUDGET.maximumSeconds*1000);
 if(range){qualityInteger(v.belowCount,0,v.rowCount-v.nullCount);qualityInteger(v.aboveCount,0,v.rowCount-v.nullCount);if(v.belowCount+v.aboveCount>v.rowCount-v.nullCount)throw qualityInvalid();digest(v.rangeHash);}
 if(reference){qualityInteger(v.invalidCount,0,v.rowCount-v.nullCount);digest(v.referenceBindingHash);}
 if(unique){
  const n=v.rowCount-v.nullCount;qualityInteger(v.distinctCount,0,n);qualityInteger(v.duplicateGroupCount,0,n);qualityInteger(v.duplicateRowCount,0,n);
  qualityInteger(v.totalValueBytes,0,QUALITY_UNIQUENESS_BUDGET.maximumTotalValueBytes);qualityInteger(v.largestValueBytes,0,QUALITY_UNIQUENESS_BUDGET.maximumValueBytes);
  if(v.distinctCount!==n-v.duplicateRowCount+v.duplicateGroupCount||v.duplicateRowCount<2*v.duplicateGroupCount||
   (v.duplicateRowCount===0)!==(v.duplicateGroupCount===0)||(v.distinctCount===0)!==(n===0)||
   v.largestValueBytes>v.totalValueBytes||v.totalValueBytes>n*v.largestValueBytes)throw qualityInvalid();
 }

 instant(v.observedStartedAt);instant(v.observedFinishedAt);const elapsed=Date.parse(v.observedFinishedAt)-Date.parse(v.observedStartedAt);
 if(elapsed<0||elapsed>31000||Math.abs(elapsed-v.elapsedMs)>1000||typeof v.sourceVersion!=='string'||!/^\d{5,16}$/.test(v.sourceVersion))throw qualityInvalid();
 if(freshness)checkFreshnessMeasurement(v);
 finite(v.estimatedCost,QUALITY_BUDGET.maximumEstimatedCost);qualityInteger(v.estimatedBytes,0,QUALITY_BUDGET.maximumEstimatedBytes);
 return {...v} as unknown as QualityMeasurement;
}
export function qualityVerdict(measurement:QualityMeasurement,maximumBasisPoints:number):'PASS'|'FAIL'|'NO_DATA'{
 const checked=parseQualityMeasurement(measurement);if(checked.kind==='freshness')throw qualityInvalid();qualityInteger(maximumBasisPoints,0,10000);
 const denominator=checked.kind==='completeness'?checked.rowCount:checked.rowCount-checked.nullCount;
 const failures=checked.kind==='completeness'?checked.nullCount:checked.kind==='uniqueness'?checked.duplicateRowCount:checked.kind==='range'?checked.belowCount+checked.aboveCount:checked.invalidCount;
 return denominator===0?'NO_DATA':BigInt(failures)*10000n<=BigInt(denominator)*BigInt(maximumBasisPoints)?'PASS':'FAIL';
}
export function parseQualityRuleView(value:unknown):QualityRuleView {
 const v=qualityObject(value,['id','version','currentVersion','definition','definitionHash','createdAt','createdBy']);qualityId(v.id);qualityId(v.createdBy);qualityInteger(v.version);if(v.currentVersion!==null)qualityInteger(v.currentVersion);digest(v.definitionHash);instant(v.createdAt);
 if(v.currentVersion!==null&&v.version>v.currentVersion)throw qualityInvalid();const definition=parseQualityDefinition(v.definition);
 // Read only descriptor-admitted text; never stringify the untrusted input.
 const raw=qualityObject(v.definition,Object.keys(definition));if(raw.name!==definition.name||raw.purpose!==definition.purpose)throw qualityInvalid();
 return {...v,definition} as unknown as QualityRuleView;
}
export function parseQualityRunView(value:unknown):QualityRunView {
 const common=['id','ruleId','ruleVersion','ruleHash','requesterId','columnAssetId','tableAssetId','status','version','attempt','createdAt','startedAt','finishedAt','expiresAt','measurement','verdict','errorCode'];
 const tag=qualityObject(value,common,['kind','reference','range','freshness']),reference=tag.kind==='reference-allowed-values',unique=tag.kind==='uniqueness',range=tag.kind==='range',freshness=tag.kind==='freshness';
 const v=qualityObject(value,[...common,...(freshness?['kind','freshness']:range?['kind','range']:reference?['kind','reference']:unique?['kind']:[])]);
 const metadata=reference?parseQualityReferenceMetadata(v.reference):undefined,bounds=range?parseQualityRangeBinding(v.range):undefined,fresh=freshness?parseQualityFreshnessBinding(v.freshness):undefined;
 for(const key of ['id','ruleId','requesterId','columnAssetId','tableAssetId'])qualityId(v[key]);qualityInteger(v.ruleVersion);digest(v.ruleHash);qualityInteger(v.version);qualityInteger(v.attempt,0,3);
 instant(v.createdAt);instant(v.expiresAt);if(v.startedAt!==null)instant(v.startedAt);if(v.finishedAt!==null)instant(v.finishedAt);
 if(!['queued','running','succeeded','failed','cancelled'].includes(v.status as string))throw qualityInvalid();
 const terminal=['succeeded','failed','cancelled'].includes(v.status as string);if(terminal!==(v.finishedAt!==null))throw qualityInvalid();
 if(v.status==='succeeded'){const m=parseQualityMeasurement(v.measurement);
  if(freshness?m.kind!=='freshness'||m.freshnessHash!==fresh!.freshnessHash:range?m.kind!=='range'||m.rangeHash!==bounds!.rangeHash:reference?m.kind!=='reference-allowed-values'||m.referenceBindingHash!==metadata!.bindingHash:m.kind!==(unique?'uniqueness':'completeness'))throw qualityInvalid();
  const denominator=m.kind==='completeness'?m.rowCount:m.rowCount-m.nullCount;
  if(!['PASS','FAIL','NO_DATA'].includes(v.verdict as string)||v.errorCode!==null||(denominator===0)!==(v.verdict==='NO_DATA'))throw qualityInvalid();if(freshness&&qualityFreshnessVerdict(m,fresh)!==v.verdict)throw qualityInvalid();}
 else {if(v.measurement!==null||v.verdict!==null)throw qualityInvalid();if(terminal?!QUALITY_ERRORS.includes(v.errorCode as never):v.errorCode!==null)throw qualityInvalid();}
 if(v.errorCode==='QUALITY_CLOCK_SKEW'&&!freshness)throw qualityInvalid();
 return {...v,...(metadata?{reference:metadata}:{}),...(bounds?{range:bounds}:{}),...(fresh?{freshness:fresh}:{}),measurement:v.measurement===null?null:parseQualityMeasurement(v.measurement)} as unknown as QualityRunView;
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
 const tag=qualityObject(value,['formatVersion','kind','target','budget'],['reference','range','freshness']),reference=tag.kind==='reference-allowed-values',unique=tag.kind==='uniqueness',range=tag.kind==='range',freshness=tag.kind==='freshness';
 const v=qualityObject(value,['formatVersion','kind','target','budget',...(freshness?['freshness']:range?['range']:reference?['reference']:[])]);if(v.formatVersion!==1||!['completeness','reference-allowed-values','uniqueness','range','freshness'].includes(v.kind as string))throw qualityInvalid();
 const t=qualityObject(v.target,['databaseOid','schemaOid','relationOid','attributeNumber','schemaName','tableName','columnName','dataType']);
 for(const k of ['databaseOid','schemaOid','relationOid'])if(typeof t[k]!=='string'||!/^[1-9]\d{0,9}$/.test(t[k] as string)||Number(t[k])>4294967295)throw qualityInvalid();
 qualityInteger(t.attributeNumber,1,32767);for(const k of ['schemaName','tableName','columnName'])postgresText(t[k],63,true);postgresText(t.dataType,256);
 const budget=unique?QUALITY_UNIQUENESS_BUDGET:QUALITY_BUDGET;const b=qualityObject(v.budget,Object.keys(budget));for(const [k,expected] of Object.entries(budget))if(b[k]!==expected)throw qualityInvalid();
 return {...v,target:{...t},budget:{...b},...(freshness?{freshness:parseQualityFreshnessBinding(v.freshness)}:range?{range:parseQualityRangeBinding(v.range)}:reference?{reference:parseQualityReferenceBinding(v.reference)}:{})} as unknown as QualityExecution;
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
 return {...v,source:{...source},execution} as unknown as QualityClaim;
}

/** Hash preimage is the six retained fields other than bindingHash, with sorted
 * JSON object keys and exact ASCII codes. No current release is reselected here. */
function referenceFields(value:unknown,withCodes:boolean):Omit<QualityReferenceBinding,'bindingHash'> & {bindingHash?:string} {
 const v=qualityObject(value,['setId','version','publicationHash','asOf','codeStatus',...(withCodes?['codes']:[])],['bindingHash']);
 qualityId(v.setId);if(v.setId==='00000000-0000-0000-0000-000000000000')throw qualityInvalid();qualityInteger(v.version);digest(v.publicationHash);instant(v.asOf);
 if(v.asOf.startsWith('0000')||v.codeStatus!=='active')throw qualityInvalid();if(Object.hasOwn(v,'bindingHash'))digest(v.bindingHash);
 const codes:string[]=[];
 if(withCodes)try{
  if(!Array.isArray(v.codes)||Object.getPrototypeOf(v.codes)!==Array.prototype)throw 0;
  const length=Object.getOwnPropertyDescriptor(v.codes,'length');if(!length||!Object.hasOwn(length,'value'))throw 0;qualityInteger(length.value,0,256);
  if(Reflect.ownKeys(v.codes).length!==length.value+1)throw 0;
  for(let i=0;i<length.value;i++){
   const d=Object.getOwnPropertyDescriptor(v.codes,String(i));if(!d?.enumerable||!Object.hasOwn(d,'value')||typeof d.value!=='string'||!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(d.value)||i>0&&codes[i-1]>=d.value)throw 0;
   codes.push(d.value);
  }
 }catch{throw qualityInvalid();}
 return {setId:v.setId,version:v.version,publicationHash:v.publicationHash,asOf:v.asOf,codeStatus:'active',codes,...(Object.hasOwn(v,'bindingHash')?{bindingHash:v.bindingHash as string}:{})};
}
export function qualityReferenceBindingHash(value:unknown):string {
 const v=referenceFields(value,true);
 return createHash('sha256').update(JSON.stringify({asOf:v.asOf,codeStatus:v.codeStatus,codes:v.codes,publicationHash:v.publicationHash,setId:v.setId,version:v.version}),'utf8').digest('hex');
}
export function parseQualityReferenceBinding(value:unknown):QualityReferenceBinding {
 const v=referenceFields(value,true);if(!v.bindingHash||qualityReferenceBindingHash(v)!==v.bindingHash)throw qualityInvalid();return v as QualityReferenceBinding;
}
export function parseQualityReferenceMetadata(value:unknown):QualityReferenceMetadata {
 const v=referenceFields(value,false);if(!v.bindingHash)throw qualityInvalid();const {codes:_,...metadata}=v;return metadata as QualityReferenceMetadata;
}

/** Exact integer bounds stay strings at JSON boundaries, including values beyond
 * JavaScript's safe-number range. At most20 characters reach BigInt parsing. */
export function qualityInt64(value:unknown):string {
 if(typeof value!=='string'||value.length>20||!/^(?:0|-?[1-9][0-9]*)$/.test(value))throw qualityInvalid();
 const integer=BigInt(value);if(integer< -9223372036854775808n||integer>9223372036854775807n)throw qualityInvalid();return value;
}
function rangeFields(value:unknown):Omit<QualityRangeBinding,'rangeHash'> {
 const v=qualityObject(value,['minimum','maximum','comparison','nullPolicy'],['rangeHash']);
 const minimum=qualityInt64(v.minimum),maximum=qualityInt64(v.maximum);
 if(BigInt(minimum)>BigInt(maximum)||v.comparison!=='int64-inclusive'||v.nullPolicy!=='exclude')throw qualityInvalid();
 if(Object.hasOwn(v,'rangeHash'))digest(v.rangeHash);
 return {minimum,maximum,comparison:'int64-inclusive',nullPolicy:'exclude'};
}
export function qualityRangeBindingHash(value:unknown):string {
 const v=rangeFields(value);return createHash('sha256').update(JSON.stringify({comparison:v.comparison,formatVersion:1,kind:'range',maximum:v.maximum,minimum:v.minimum,nullPolicy:v.nullPolicy}),'utf8').digest('hex');
}
export function parseQualityRangeBinding(value:unknown):QualityRangeBinding {
 const v=qualityObject(value,['minimum','maximum','comparison','nullPolicy','rangeHash']),bounds=rangeFields(v);digest(v.rangeHash);
 if(qualityRangeBindingHash(bounds)!==v.rangeHash)throw qualityInvalid();return {...bounds,rangeHash:v.rangeHash};
}

/** Validate calendar seconds independently of the retained six-digit fraction.
 * No Date ever parses or rounds the source's microsecond evidence. */
export function qualityMicroInstant(value:unknown):{canonical:string;epochMicroseconds:bigint}{
 if(typeof value!=='string'||value.length!==27||!/^(?!0000)[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$/.test(value))throw qualityInvalid();
 const seconds=value.slice(0,19)+'.000Z',millis=Date.parse(seconds);
 if(!Number.isFinite(millis)||new Date(millis).toISOString()!==seconds)throw qualityInvalid();
 const epochMicroseconds=BigInt(millis)*1000n+BigInt(value.slice(20,26));
 if(epochMicroseconds<BigInt(QUALITY_FRESHNESS_LIMITS.minimumEpochMicroseconds)||epochMicroseconds>BigInt(QUALITY_FRESHNESS_LIMITS.maximumEpochMicroseconds))throw qualityInvalid();
 return {canonical:value,epochMicroseconds};
}
function freshnessFields(value:unknown):QualityFreshnessSettings{
 const v=qualityObject(value,['maximumAgeSeconds','maximumFutureSkewSeconds','comparison','clock','nullPolicy','invalidTimestampPolicy'],['freshnessHash']);
 qualityInteger(v.maximumAgeSeconds,1,QUALITY_FRESHNESS_LIMITS.maximumAgeSeconds);qualityInteger(v.maximumFutureSkewSeconds,0,QUALITY_FRESHNESS_LIMITS.maximumFutureSkewSeconds);
 if(v.comparison!=='latest-timestamptz'||v.clock!=='source-statement-start'||v.nullPolicy!=='exclude'||v.invalidTimestampPolicy!=='fail')throw qualityInvalid();
 if(Object.hasOwn(v,'freshnessHash'))digest(v.freshnessHash);
 return {maximumAgeSeconds:v.maximumAgeSeconds,maximumFutureSkewSeconds:v.maximumFutureSkewSeconds,comparison:'latest-timestamptz',clock:'source-statement-start',nullPolicy:'exclude',invalidTimestampPolicy:'fail'};
}
export function qualityFreshnessBindingHash(value:unknown):string{
 const v=freshnessFields(value);return createHash('sha256').update(JSON.stringify({clock:v.clock,comparison:v.comparison,formatVersion:1,invalidTimestampPolicy:v.invalidTimestampPolicy,kind:'freshness',maximumAgeSeconds:v.maximumAgeSeconds,maximumFutureSkewSeconds:v.maximumFutureSkewSeconds,nullPolicy:v.nullPolicy}),'utf8').digest('hex');
}
export function parseQualityFreshnessBinding(value:unknown):QualityFreshnessBinding{
 const v=qualityObject(value,['maximumAgeSeconds','maximumFutureSkewSeconds','comparison','clock','nullPolicy','invalidTimestampPolicy','freshnessHash']),fields=freshnessFields(v);digest(v.freshnessHash);
 if(qualityFreshnessBindingHash(fields)!==v.freshnessHash)throw qualityInvalid();return {...fields,freshnessHash:v.freshnessHash};
}
function checkFreshnessMeasurement(v:Record<string,unknown>):void{
 const n=(v.rowCount as number)-(v.nullCount as number);qualityInteger(v.nonFiniteCount,0,n);qualityInteger(v.unrepresentableCount,0,n);
 const representable=n-v.nonFiniteCount-v.unrepresentableCount;if(representable<0)throw qualityInvalid();qualityInteger(v.futureCount,0,representable);digest(v.freshnessHash);
 const source=qualityMicroInstant(v.sourceObservedAt).epochMicroseconds;
 if((representable===0)!==(v.latestObservedAt===null)||(v.latestObservedAt===null)!==(v.ageMicroseconds===null))throw qualityInvalid();
 if(v.latestObservedAt!==null){const latest=qualityMicroInstant(v.latestObservedAt).epochMicroseconds;
  if(typeof v.ageMicroseconds!=='string'||v.ageMicroseconds.length>19||!/^(?:0|-?[1-9][0-9]{0,17})$/.test(v.ageMicroseconds))throw qualityInvalid();
  const age=BigInt(v.ageMicroseconds),limit=BigInt(QUALITY_FRESHNESS_LIMITS.maximumAbsoluteAgeMicroseconds);if(age< -limit||age>limit||age!==source-latest)throw qualityInvalid();
 }
 const allowance=BigInt(QUALITY_FRESHNESS_LIMITS.sourceWorkerClockAllowanceMs)*1000n;
 if(source<BigInt(Date.parse(v.observedStartedAt as string))*1000n-allowance||source>BigInt(Date.parse(v.observedFinishedAt as string))*1000n+allowance)throw qualityInvalid();
}
/** Duration semantics remain separate from the older families' basis points. */
export function qualityFreshnessVerdict(measurement:unknown,binding:unknown):'PASS'|'FAIL'|'NO_DATA'{
 const m=parseQualityMeasurement(measurement),b=parseQualityFreshnessBinding(binding);if(m.kind!=='freshness'||m.freshnessHash!==b.freshnessHash)throw qualityInvalid();
 const source=qualityMicroInstant(m.sourceObservedAt).epochMicroseconds,latest=m.latestObservedAt===null?null:qualityMicroInstant(m.latestObservedAt).epochMicroseconds;
 if((m.futureCount>0)!==(latest!==null&&latest>source+BigInt(b.maximumFutureSkewSeconds)*1000000n))throw qualityInvalid();
 if(m.rowCount===m.nullCount)return 'NO_DATA';if(m.nonFiniteCount>0||m.unrepresentableCount>0||m.futureCount>0)return 'FAIL';
 if(m.ageMicroseconds===null)throw qualityInvalid();return BigInt(m.ageMicroseconds)<=BigInt(b.maximumAgeSeconds)*1000000n?'PASS':'FAIL';
}
