// SPDX-License-Identifier: Apache-2.0
import {createHash} from 'node:crypto';
import {MODEL_LIMITS,parseBoundedJSONEnvelope,type ValidationIssue,type ValidationIssueCode,type ValidationResult} from './model.ts';
import {CLASSIFICATION_LIMITS as limits,type ClassificationTaxonomy,type MetadataClassificationRule,
  type ClassificationAssetInput,type ClassificationPin,type ClassificationEvaluation} from './classification-contracts.ts';

/** Pure metadata semantics only: no membership, visibility, current-head or
 * retirement authority is inferred here. Stored evidence can be re-evaluated
 * after a rule is retired; the application authorizes each new operation. */
type Fields=Record<string,unknown>;
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const sha256=/^[0-9a-f]{64}$/;
const identifier=/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const reserved=new Set(['__proto__','constructor','prototype']);
const malformed=/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const controls=/[\u0000-\u001f\u007f-\u009f]/;
const multilineControls=/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/;
const encoder=new TextEncoder();
const at=(path:string,key:string|number)=>`${path}/${String(key).replaceAll('~','~0').replaceAll('/','~1')}`;
const invalid=():never=>{throw new TypeError('Invalid classification data.');};
class Issues {
  readonly values:ValidationIssue[]=[];
  add(code:ValidationIssueCode,path:string,message:string){
    if(this.values.length<MODEL_LIMITS.issues-1)this.values.push({code,path,message});
    else if(this.values.length===MODEL_LIMITS.issues-1)this.values.push({code:'limit',path:'',message:'Further classification issues were omitted.'});
  }
  result<T>(value:T):ValidationResult<T>{return this.values.length?{ok:false,issues:this.values}:{ok:true,value};}
}

/** Reflect descriptors before serializing. Getters/toJSON are never invoked.
 * Reflection of an already materialized object's keys is proportional to its
 * keys, not a hostile-proxy sandbox; raw HTTP admission remains separate. */
function snapshot(input:unknown,maximum:number):ValidationResult<unknown>{
  const active=new Set<object>();let nodes=0,bytes=0;let failure:ValidationIssue|undefined;
  function fail(code:ValidationIssueCode,path:string,message:string):never{failure={code,path,message};throw new Error('Invalid classification data.');}
  const charge=(amount:number,path:string)=>{bytes+=amount;if(bytes>maximum)fail('limit',path,'Classification JSON exceeds its byte budget.');};
  const copy=(value:unknown,path:string,depth:number):unknown=>{
    if(++nodes>MODEL_LIMITS.valueNodes||depth>MODEL_LIMITS.valueDepth+5)fail('limit',path,'JSON node or nesting budget exceeded.');
    if(value===null){charge(4,path);return null;}
    if(typeof value==='string'){
      if(value.length>MODEL_LIMITS.stringLength)fail('limit',path,'String length exceeds its permitted bound.');
      if(malformed.test(value))fail('format',path,'Strings must contain well-formed Unicode.');
      charge(encoder.encode(JSON.stringify(value)).length,path);return value;
    }
    if(typeof value==='boolean'){charge(value?4:5,path);return value;}
    if(typeof value==='number'){
      if(!Number.isFinite(value)||Object.is(value,-0))fail('type',path,'Expected a finite JSON number without negative zero.');
      charge(String(value).length,path);return value;
    }
    if(typeof value!=='object')fail('invalid_json',path,'Expected JSON data.');
    if(active.has(value))fail('cycle',path,'JSON values cannot contain cycles.');
    const array=Array.isArray(value),prototype=Object.getPrototypeOf(value);
    if(array?prototype!==Array.prototype:prototype!==Object.prototype&&prototype!==null)fail('invalid_json',path,'Expected a plain object or array.');
    const keys=Reflect.ownKeys(value),length=array?Object.getOwnPropertyDescriptor(value,'length')?.value:keys.length;
    if(array&&(!Number.isSafeInteger(length)||length<0||length>MODEL_LIMITS.listItems))fail('limit',path,'Array length exceeds its permitted bound.');
    if(!array&&keys.length>MODEL_LIMITS.properties)fail('limit',path,'Object property count exceeds its permitted bound.');
    if(array&&keys.length!==length+1)fail('invalid_json',path,'Sparse arrays and extra array properties are not permitted.');
    charge(2+Math.max(0,length-1),path);active.add(value);
    try{
      const entries=new Map<string,unknown>();
      for(const name of array?Array.from({length},(_,i)=>String(i)):keys){
        if(typeof name!=='string')fail('invalid_json',path,'Symbol keys are not JSON.');
        if(name.length>256||malformed.test(name))fail('limit',path,'Property names must be bounded, well-formed strings.');
        const child=at(path,name),descriptor=Object.getOwnPropertyDescriptor(value,name);
        if(!descriptor?.enumerable||!Object.hasOwn(descriptor,'value'))fail('invalid_json',child,'Only enumerable data properties are permitted.');
        if(!array)charge(encoder.encode(JSON.stringify(name)).length+1,path);
        entries.set(name,copy(descriptor.value,child,depth+1));
      }
      return array?Array.from({length},(_,i)=>entries.get(String(i))):Object.fromEntries(entries);
    }finally{active.delete(value);}
  };
  try{return parseBoundedJSONEnvelope(canonical(copy(input,'',0)));}
  // Never inspect a value thrown by user-controlled reflection traps.
  catch{return {ok:false,issues:[failure??{code:'invalid_json',path:'',message:'Classification JSON could not be read safely.'}]};}
}
function fields(value:unknown,path:string,names:readonly string[],issues:Issues):Fields|undefined{
  if(!value||typeof value!=='object'||Array.isArray(value)){issues.add('type',path,'Expected an object.');return;}
  for(const name of Object.keys(value))if(!names.includes(name))issues.add('unknown_field',at(path,name),'Unknown classification field.');
  for(const name of names)if(!Object.hasOwn(value,name))issues.add('required',at(path,name),'Required classification field is missing.');
  return value as Fields;
}
function list(value:unknown,path:string,maximum:number,issues:Issues):unknown[]{
  if(!Array.isArray(value)){issues.add('type',path,'Expected an array.');return [];}
  if(value.length>maximum){issues.add('limit',path,'Array length exceeds its permitted bound.');return [];}
  if(!value.length)issues.add('required',path,'At least one item is required.');return value;
}
function text(value:unknown,path:string,maximum:number,issues:Issues,mode:'display'|'multiline'|'literal'|'observed'='display'):string{
  if(typeof value!=='string'){issues.add('type',path,'Expected text.');return '';}
  if((mode==='multiline'?multilineControls:controls).test(value))issues.add('format',path,'Text contains a prohibited control character.');
  const normalized=mode==='observed'?value:value.normalize('NFC');
  const result=mode==='display'||mode==='multiline'?normalized.trim():normalized;
  if(value.length>maximum||result.length>maximum)issues.add('limit',path,'Text exceeds its permitted length.');
  if(!result.length||(mode==='display'||mode==='multiline')&&!result.trim())issues.add('required',path,'Text must not be empty.');
  return result;
}
function choice<T extends string>(value:unknown,path:string,choices:readonly T[],issues:Issues):T{
  if(typeof value!=='string'||!choices.includes(value as T))issues.add('enum',path,'Unsupported classification value.');return value as T;
}
function safeKey(value:unknown,path:string,issues:Issues):string{
  if(typeof value!=='string'||!identifier.test(value)||reserved.has(value))issues.add('format',path,'Expected a safe identifier of at most 64 characters.');return value as string;
}
function id(value:unknown,path:string,issues:Issues):string{
  if(typeof value!=='string'||!uuid.test(value))issues.add('format',path,'Expected a canonical lowercase UUID.');return value as string;
}
function version(value:unknown,path:string,issues:Issues):number{
  if(typeof value!=='number'||!Number.isInteger(value)||value<1||value>2147483647)issues.add('model_version',path,'Expected a positive 32-bit integer version.');return value as number;
}
function pin(value:unknown,path:string,issues:Issues):ClassificationPin{
  const source=fields(value,path,['id','version','definitionHash'],issues);
  if(!source)return {id:'',version:0,definitionHash:''};
  id(source.id,at(path,'id'),issues);version(source.version,at(path,'version'),issues);
  if(typeof source.definitionHash!=='string'||!sha256.test(source.definitionHash))issues.add('format',at(path,'definitionHash'),'Expected a lowercase SHA-256 digest.');
  return {id:source.id as string,version:source.version as number,definitionHash:source.definitionHash as string};
}
function freeze<T>(value:T):T{if(value&&typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;}
function canonical(value:unknown):string{
  if(Array.isArray(value))return `[${value.map(canonical).join(',')}]`;
  if(value&&typeof value==='object')return `{${Object.keys(value).sort().map(key=>`${JSON.stringify(key)}:${canonical((value as Fields)[key])}`).join(',')}}`;
  return JSON.stringify(value);
}
const hash=(value:unknown)=>createHash('sha256').update(canonical(value)).digest('hex');
function complete<T>(value:T,issues:Issues,maximum:number):ValidationResult<T>{
  if(!issues.values.length&&encoder.encode(canonical(value)).length>maximum)issues.add('limit','','Normalized classification JSON exceeds its byte budget.');
  return issues.result(issues.values.length?undefined as never:freeze(value));
}

export function parseClassificationTaxonomy(input:unknown):ValidationResult<ClassificationTaxonomy>{
  const copied=snapshot(input,limits.definitionBytes);if(!copied.ok)return copied;
  const issues=new Issues(),source=fields(copied.value,'',['formatVersion','name','description','labels'],issues);
  if(!source)return issues.result(undefined as never);
  if(source.formatVersion!==1)issues.add('invalid_definition','/formatVersion','Only classification format version 1 is supported.');
  const name=text(source.name,'/name',limits.name,issues),description=text(source.description,'/description',limits.description,issues,'multiline');
  const labels:ClassificationTaxonomy['labels']=[],seen=new Set<string>();
  for(const[index,value]of list(source.labels,'/labels',limits.labels,issues).entries()){
    const path=at('/labels',index),row=fields(value,path,['key','name','description','status'],issues);if(!row)continue;
    const key=safeKey(row.key,at(path,'key'),issues);
    if(seen.has(key))issues.add('duplicate',at(path,'key'),'Duplicate taxonomy label key.');seen.add(key);
    labels.push({key,name:text(row.name,at(path,'name'),limits.name,issues),description:text(row.description,at(path,'description'),limits.description,issues,'multiline'),status:choice(row.status,at(path,'status'),['active','deprecated'],issues)});
  }
  return complete({formatVersion:1,name,description,labels},issues,limits.definitionBytes);
}
export function parseMetadataClassificationRule(input:unknown):ValidationResult<MetadataClassificationRule>{
  const copied=snapshot(input,limits.definitionBytes);if(!copied.ok)return copied;
  const issues=new Issues(),source=fields(copied.value,'',['formatVersion','kind','name','purpose','ownerId','status','assetTypes','label','all'],issues);
  if(!source)return issues.result(undefined as never);
  if(source.formatVersion!==1)issues.add('invalid_definition','/formatVersion','Only classification format version 1 is supported.');
  if(source.kind!=='metadata-literal')issues.add('enum','/kind','Only literal metadata rules are supported.');
  const name=text(source.name,'/name',limits.name,issues),purpose=text(source.purpose,'/purpose',limits.description,issues,'multiline'),ownerId=id(source.ownerId,'/ownerId',issues);
  const status=choice(source.status,'/status',['active','retired'],issues),assetTypes:MetadataClassificationRule['assetTypes']=[],seen=new Set<string>();
  for(const[index,value]of list(source.assetTypes,'/assetTypes',3,issues).entries()){
    const path=at('/assetTypes',index),type=choice(value,path,['table','view','column'],issues);
    if(seen.has(type))issues.add('duplicate',path,'Duplicate rule asset type.');seen.add(type);assetTypes.push(type);
  }
  const label=fields(source.label,'/label',['taxonomy','labelKey'],issues);
  const taxonomy=pin(label?.taxonomy,'/label/taxonomy',issues),labelKey=safeKey(label?.labelKey,'/label/labelKey',issues);
  const all:MetadataClassificationRule['all']=[];
  for(const[index,value]of list(source.all,'/all',limits.predicates,issues).entries()){
    const path=at('/all',index),row=fields(value,path,['field','operator','comparison','literal'],issues);if(!row)continue;
    all.push({field:choice(row.field,at(path,'field'),['name','qualifiedName','dataType'],issues),operator:choice(row.operator,at(path,'operator'),['equals','contains','starts-with','ends-with'],issues),
      comparison:choice(row.comparison,at(path,'comparison'),['exact','ascii-insensitive'],issues),literal:text(row.literal,at(path,'literal'),limits.literal,issues,'literal')});
  }
  return complete({formatVersion:1,kind:'metadata-literal',name,purpose,ownerId,status,assetTypes,label:{taxonomy,labelKey},all},issues,limits.definitionBytes);
}

function assetInput(input:unknown):ValidationResult<ClassificationAssetInput>{
  const copied=snapshot(input,limits.evidenceBytes);if(!copied.ok)return copied;
  const issues=new Issues(),source=fields(copied.value,'',['id','version','type','name','qualifiedName','dataType'],issues);if(!source)return issues.result(undefined as never);
  const asset={id:id(source.id,'/id',issues),version:version(source.version,'/version',issues),type:safeKey(source.type,'/type',issues),
    name:text(source.name,'/name',limits.field,issues,'observed'),qualifiedName:text(source.qualifiedName,'/qualifiedName',limits.field,issues,'observed'),
    dataType:source.dataType===null?null:text(source.dataType,'/dataType',limits.field,issues,'observed')};
  return complete(asset,issues,limits.evidenceBytes);
}

/** SHA-256 of normalized parsed taxonomy/rule JSON, recursively sorted object
 * keys, exact JSON primitive encoding and authored array order. No raw input
 * getter, toJSON, ignored field or executable object participates in hashing. */
export function classificationDefinitionHash(input:unknown):string{
  const copied=snapshot(input,limits.definitionBytes);if(!copied.ok)return invalid();
  const value=copied.value;
  const parsed=value&&typeof value==='object'&&Object.hasOwn(value,'kind')?parseMetadataClassificationRule(value):parseClassificationTaxonomy(value);
  return parsed.ok?hash(parsed.value):invalid();
}

/** Normative preimage: {formatVersion:1,assetId,assetType,fields}, with distinct
 * selected field names as keys and exact observed string/null values. Object
 * keys sort recursively. Excludes revision, rule identity and unselected fields;
 * includes null for missing dataType. NFC/ASCII comparison does not alter proof. */
function inputDigest(rule:MetadataClassificationRule,asset:ClassificationAssetInput):string{
  const fields=Object.fromEntries([...new Set(rule.all.map(predicate=>predicate.field))].sort().map(field=>[field,asset[field]]));
  return hash({formatVersion:1,assetId:asset.id,assetType:asset.type,fields});
}
export function classificationInputDigest(rule:unknown,asset:unknown):string{
  const definition=parseMetadataClassificationRule(rule),observed=assetInput(asset);
  return definition.ok&&observed.ok?inputDigest(definition.value,observed.value):invalid();
}
const asciiFold=(value:string)=>value.replace(/[A-Z]/g,letter=>String.fromCharCode(letter.charCodeAt(0)+32));
function matches(value:string,predicate:MetadataClassificationRule['all'][number]):boolean{
  let observed=value.normalize('NFC'),literal=predicate.literal;
  if(predicate.comparison==='ascii-insensitive'){observed=asciiFold(observed);literal=asciiFold(literal);}
  switch(predicate.operator){case 'equals':return observed===literal;case 'contains':return observed.includes(literal);case 'starts-with':return observed.startsWith(literal);case 'ends-with':return observed.endsWith(literal);}
}
export function evaluateMetadataClassification(rule:unknown,rulePin:unknown,asset:unknown,evaluatedAt:unknown):ValidationResult<ClassificationEvaluation>{
  const definition=parseMetadataClassificationRule(rule);if(!definition.ok)return definition;
  const observed=assetInput(asset);if(!observed.ok)return observed;
  const copiedPin=snapshot(rulePin,1024);if(!copiedPin.ok)return copiedPin;
  const issues=new Issues(),selected=pin(copiedPin.value,'/rule',issues);
  if(selected.definitionHash!==hash(definition.value))issues.add('invalid_definition','/rule/definitionHash','Rule pin must match the exact normalized definition.');
  if(typeof evaluatedAt!=='string'||!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(evaluatedAt)
    ||!Number.isFinite(Date.parse(evaluatedAt))||new Date(evaluatedAt).toISOString()!==evaluatedAt)issues.add('format','/evaluatedAt','Expected an exact UTC millisecond timestamp.');
  if(issues.values.length)return issues.result(undefined as never);
  const source=observed.value,parsed=definition.value,supported=parsed.assetTypes.includes(source.type as MetadataClassificationRule['assetTypes'][number]);
  const evidenceMatches:ClassificationEvaluation['evidence']['matches']=[];
  if(supported)for(const[index,predicate]of parsed.all.entries()){
    const value=source[predicate.field];
    if(value!==null&&matches(value,predicate))evidenceMatches.push({conditionIndex:index,field:predicate.field,value,valueHash:createHash('sha256').update(value).digest('hex')});
  }
  const outcome=supported?(evidenceMatches.length===parsed.all.length?'matched':'not_matched'):'unsupported';
  // evidenceBytes bounds the complete {outcome,evidence} JSON envelope, so
  // oversized proof refuses the whole evaluation rather than truncating it.
  return complete({outcome,evidence:{formatVersion:1,kind:'metadata-literal',assetId:source.id,observedAssetVersion:source.version,inputDigest:inputDigest(parsed,source),
    rule:selected,label:parsed.label,evaluatedAt:evaluatedAt as string,matches:evidenceMatches,confidence:{kind:'not-estimated',reason:'metadata-only'},samplePolicy:{kind:'metadata-only',sourceRowsRead:0,sourceSamplesStored:0}}},issues,limits.evidenceBytes);
}
