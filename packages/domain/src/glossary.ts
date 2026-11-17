// SPDX-License-Identifier: Apache-2.0
import {MODEL_LIMITS, parseBoundedJSONEnvelope, type AttributeValues, type ValidationIssue,
  type ValidationIssueCode, type ValidationResult} from './model.ts';
import {parseAssetTypeDefinition, type AssetTypeDefinition} from './asset-type.ts';
import {GLOSSARY_LIMITS, type GlossaryPublicationParser, type GlossaryStarterTypeFactory,
  type GlossaryTranslation, type GlossaryTypePin, type GlossaryLink,
  type ParsedGlossaryPublication} from './glossary-contracts.ts';

/** Pure publication parsing. No stored-term lookup, authorization or model-pin resolution. */
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const hash=/^[0-9a-f]{64}$/;
const identifier=/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/;
const reserved=new Set(['__proto__','constructor','prototype']);
const malformedUnicode=/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const controls=/[\u0000-\u001f\u007f-\u009f]/;
const multilineControls=/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/;
const encoder=new TextEncoder();
type Fields=Record<string,unknown>;
const at=(path:string,key:string|number)=>`${path}/${String(key).replaceAll('~','~0').replaceAll('/','~1')}`;
const plain=(value:unknown):value is Fields=>value!==null&&typeof value==='object'&&!Array.isArray(value);
const compare=(a:string,b:string)=>a<b?-1:a>b?1:0;

class Issues {
  readonly values:ValidationIssue[]=[];
  add(code:ValidationIssueCode,path:string,message:string){
    if(this.values.length<MODEL_LIMITS.issues-1)this.values.push({code,path,message});
    else if(this.values.length===MODEL_LIMITS.issues-1)this.values.push({code:'limit',path:'',message:'Further glossary issues were omitted.'});
  }
  result<T>(value:T):ValidationResult<T>{return this.values.length?{ok:false,issues:this.values}:{ok:true,value};}
}

/** Copy descriptors before serialization, so getters and toJSON are never data.
 * As in the shared model parser, reflecting a materialized object's own keys is
 * proportional to that object's existing keys; this is not a hostile-proxy sandbox. */
function snapshot(input:unknown):ValidationResult<unknown>{
  let nodes=0,bytes=0;
  const active=new Set<object>();
  let failure:ValidationIssue|undefined;
  function fail(code:ValidationIssueCode,path:string,message:string):never{failure={code,path,message};throw new Error('Invalid glossary data.');}
  const charge=(amount:number,path:string)=>{bytes+=amount;if(bytes>GLOSSARY_LIMITS.bytes)fail('limit',path,'Glossary JSON exceeds the permitted byte budget.');};
  const string=(value:string,path:string)=>{
    if(value.length>MODEL_LIMITS.stringLength)fail('limit',path,'String length exceeds its permitted bound.');
    if(malformedUnicode.test(value))fail('format',path,'Strings must contain well-formed Unicode.');
    charge(encoder.encode(JSON.stringify(value)).length,path);return value;
  };
  const copy=(value:unknown,path:string,depth:number):unknown=>{
    if(++nodes>MODEL_LIMITS.valueNodes||depth>MODEL_LIMITS.valueDepth+5)fail('limit',path,'JSON node or nesting budget exceeded.');
    if(typeof value==='string')return string(value,path);
    if(typeof value==='boolean'){charge(value?4:5,path);return value;}
    if(typeof value==='number'){
      if(!Number.isFinite(value)||Object.is(value,-0))fail('type',path,'Expected a finite JSON number without negative zero.');
      charge(String(value).length,path);return value;
    }
    if(value===null||typeof value!=='object')fail('invalid_json',path,'Expected non-null JSON data.');
    if(active.has(value))fail('cycle',path,'JSON values cannot contain cycles.');
    const array=Array.isArray(value),prototype=Object.getPrototypeOf(value);
    if(array?prototype!==Array.prototype:prototype!==Object.prototype&&prototype!==null)fail('invalid_json',path,'Expected a plain JSON object or array.');
    const keys=Reflect.ownKeys(value);
    const length=array?Object.getOwnPropertyDescriptor(value,'length')?.value:keys.length;
    if(array&&(!Number.isSafeInteger(length)||length<0||length>MODEL_LIMITS.listItems))fail('limit',path,'Array length exceeds its permitted bound.');
    if(!array&&keys.length>MODEL_LIMITS.properties)fail('limit',path,'Object property count exceeds its permitted bound.');
    if(array&&keys.length!==length+1)fail('invalid_json',path,'Sparse arrays and extra array properties are not permitted.');
    charge(2+Math.max(0,length-1),path);active.add(value);
    try {
      const output=new Map<string,unknown>();
      const names=array?Array.from({length},(_,index)=>String(index)):keys;
      for(const key of names){
        if(typeof key!=='string')fail('invalid_json',path,'Symbol keys are not JSON.');
        if(key.length>256||malformedUnicode.test(key))fail('limit',path,'Property names must be bounded, well-formed strings.');
        const childPath=at(path,key),descriptor=Object.getOwnPropertyDescriptor(value,key);
        if(!descriptor?.enumerable||!Object.hasOwn(descriptor,'value'))fail('invalid_json',childPath,'Only enumerable data properties are permitted.');
        if(!array)charge(encoder.encode(JSON.stringify(key)).length+1,path);
        output.set(key,copy(descriptor.value,childPath,depth+1));
      }
      return array?Array.from({length},(_,index)=>output.get(String(index))):Object.fromEntries(output);
    } finally {active.delete(value);}
  };
  try {
    const copied=copy(input,'',0);
    // Reuse the shared duplicate-aware JSON grammar and its structural limits.
    return parseBoundedJSONEnvelope(JSON.stringify(copied));
  } catch{
    return {ok:false,issues:[failure??{code:'invalid_json',path:'',message:'JSON data could not be read safely.'}]};
  }
}

function fields(value:unknown,path:string,expected:readonly string[],issues:Issues):Fields|undefined{
  if(!plain(value)){issues.add('type',path,'Expected an object.');return;}
  for(const key of Object.keys(value))if(!expected.includes(key))issues.add('unknown_field',at(path,key),'Unknown glossary field.');
  for(const key of expected)if(!Object.hasOwn(value,key))issues.add('required',at(path,key),'Required glossary field is missing.');
  return value;
}
function list(value:unknown,path:string,maximum:number,issues:Issues):unknown[]{
  if(!Array.isArray(value)){issues.add('type',path,'Expected an array.');return [];}
  if(value.length>maximum){issues.add('limit',path,'Array length exceeds its permitted bound.');return [];}
  return value;
}
function id(value:unknown,path:string,issues:Issues):value is string{
  if(typeof value==='string'&&uuid.test(value))return true;
  issues.add('format',path,'Expected a canonical lowercase UUID.');return false;
}
function digest(value:unknown,path:string,issues:Issues):value is string{
  if(typeof value==='string'&&hash.test(value))return true;
  issues.add('format',path,'Expected a lowercase SHA-256 digest.');return false;
}
function version(value:unknown,path:string,issues:Issues):value is number{
  if(typeof value==='number'&&Number.isInteger(value)&&value>=1&&value<=2_147_483_647)return true;
  issues.add('model_version',path,'Expected a positive 32-bit integer version.');return false;
}
function locale(value:unknown,path:string,issues:Issues):string{
  if(typeof value==='string'&&value&&!value.split('-').some(part=>part.length===1)){
    try {const result=Intl.getCanonicalLocales(value);if(result.length===1)return result[0]!;} catch {/* A closed validation issue follows. */}
  }
  issues.add('format',path,'Expected a BCP 47 locale without extensions or private-use subtags.');return '';
}
function display(value:unknown,path:string,maximum:number,multiline:boolean,issues:Issues):string{
  if(typeof value!=='string'){issues.add('type',path,'Expected a display string.');return '';}
  if((multiline?multilineControls:controls).test(value))issues.add('format',path,'Display text contains a prohibited control character.');
  const normalized=value.normalize('NFC').trim();
  if(value.length>maximum||normalized.length>maximum)issues.add('limit',path,'Display text exceeds its permitted length.');
  if(!normalized)issues.add('required',path,'Display text must not be empty.');
  return normalized;
}
function freeze<T>(value:T):T{
  if(value&&typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;
}

export const parseGlossaryPublication:GlossaryPublicationParser=(input)=>{
  const copied=snapshot(input);if(!copied.ok)return copied;
  const issues=new Issues(),source=fields(copied.value,'',['typePin','primaryLocale','ownerId','visibility','allowedIdentityIds','state','attributes','links'],issues);
  if(!source)return issues.result(undefined as never);
  const pin=fields(source.typePin,'/typePin',['typeId','modelId','version','definitionHash','resolutionHash'],issues);
  if(pin){
    id(pin.typeId,'/typePin/typeId',issues);version(pin.version,'/typePin/version',issues);
    digest(pin.definitionHash,'/typePin/definitionHash',issues);digest(pin.resolutionHash,'/typePin/resolutionHash',issues);
    if(typeof pin.modelId!=='string'||!identifier.test(pin.modelId)||reserved.has(pin.modelId))issues.add('format','/typePin/modelId','Expected a safe model identifier.');
  }
  id(source.ownerId,'/ownerId',issues);
  if(!['tenant','restricted'].includes(source.visibility as string))issues.add('enum','/visibility','Expected tenant or restricted visibility.');
  if(!['active','deprecated'].includes(source.state as string))issues.add('enum','/state','Expected active or deprecated state.');
  const allowed:string[]=[],seenIds=new Set<string>();
  for(const [index,value]of list(source.allowedIdentityIds,'/allowedIdentityIds',GLOSSARY_LIMITS.allowedIdentities,issues).entries()){
    const path=at('/allowedIdentityIds',index);
    if(id(value,path,issues)){if(seenIds.has(value))issues.add('duplicate',path,'Duplicate allowed identity.');seenIds.add(value);allowed.push(value);}
  }
  if(source.visibility==='tenant'&&allowed.length)issues.add('invalid_definition','/allowedIdentityIds','Tenant visibility requires an empty identity list.');
  // As with restricted relations, the authored ACL must be nonempty. Owner
  // identity alone never grants visibility; membership/access are checked later.
  if(source.visibility==='restricted'&&!allowed.length)issues.add('required','/allowedIdentityIds','Restricted visibility requires at least one allowed identity.');
  const primaryLocale=locale(source.primaryLocale,'/primaryLocale',issues);
  const attributes=plain(source.attributes)?source.attributes:undefined;
  if(!attributes)issues.add('type','/attributes','Expected typed attributes.');
  else if(!Object.hasOwn(attributes,'translations'))issues.add('required','/attributes/translations','Translations are required.');
  const translations:GlossaryTranslation[]=[],aliases:ParsedGlossaryPublication['aliases'][number][]=[],seenLocales=new Set<string>();
  const rawTranslations=list(attributes?.translations,'/attributes/translations',GLOSSARY_LIMITS.translations,issues);
  if(!rawTranslations.length)issues.add('required','/attributes/translations','At least one translation is required.');
  for(const [index,raw]of rawTranslations.entries()){
    const path=at('/attributes/translations',index),translation=fields(raw,path,['locale','name','definition','synonyms','abbreviations','examples'],issues);
    if(!translation)continue;
    const tag=locale(translation.locale,at(path,'locale'),issues);
    if(tag&&seenLocales.has(tag))issues.add('duplicate',at(path,'locale'),'Duplicate canonical locale.');
    seenLocales.add(tag);
    const name=display(translation.name,at(path,'name'),GLOSSARY_LIMITS.name,false,issues);
    const definition=display(translation.definition,at(path,'definition'),GLOSSARY_LIMITS.definition,true,issues);
    const strings=(key:'synonyms'|'abbreviations'|'examples')=>list(translation[key],at(path,key),key==='examples'?GLOSSARY_LIMITS.examples:GLOSSARY_LIMITS.aliases,issues)
      .map((value,item)=>display(value,at(at(path,key),item),key==='examples'?GLOSSARY_LIMITS.example:GLOSSARY_LIMITS.name,key==='examples',issues));
    const synonyms=strings('synonyms'),abbreviations=strings('abbreviations'),examples=strings('examples');
    const seenAliases=new Set<string>();
    const alias=(value:string,kind:'name'|'synonym'|'abbreviation',aliasPath:string)=>{
      const key=value.normalize('NFKC').toLowerCase();
      if(seenAliases.has(key))issues.add('duplicate',aliasPath,'Duplicate normalized alias within this locale.');
      seenAliases.add(key);aliases.push({locale:tag,kind,value,key});
    };
    alias(name,'name',at(path,'name'));
    synonyms.forEach((value,item)=>alias(value,'synonym',at(at(path,'synonyms'),item)));
    abbreviations.forEach((value,item)=>alias(value,'abbreviation',at(at(path,'abbreviations'),item)));
    translations.push({locale:tag,name,definition,synonyms,abbreviations,examples});
  }
  const primary=translations.find(row=>row.locale===primaryLocale);
  if(!primary)issues.add('required','/primaryLocale','The primary locale must have a translation.');
  const links:GlossaryLink[]=[],seenLinks=new Set<string>();let broader=0;
  for(const [index,raw]of list(source.links,'/links',GLOSSARY_LIMITS.links,issues).entries()){
    const path=at('/links',index),link=fields(raw,path,['kind','typePin','targetAssetId','targetAssetVersion'],issues);
    if(!link)continue;
    if(!['broader','related','defines'].includes(link.kind as string))issues.add('enum',at(path,'kind'),'Unknown glossary link kind.');
    if(link.kind==='broader'&&++broader>1)issues.add('limit',at(path,'kind'),'At most one broader term is permitted.');
    id(link.targetAssetId,at(path,'targetAssetId'),issues);version(link.targetAssetVersion,at(path,'targetAssetVersion'),issues);
    const relation=fields(link.typePin,at(path,'typePin'),['relationTypeId','version','definitionHash'],issues);
    if(relation){id(relation.relationTypeId,at(at(path,'typePin'),'relationTypeId'),issues);version(relation.version,at(at(path,'typePin'),'version'),issues);digest(relation.definitionHash,at(at(path,'typePin'),'definitionHash'),issues);}
    const key=JSON.stringify([link.kind,link.targetAssetId]);
    if(seenLinks.has(key))issues.add('duplicate',path,'Duplicate target and link kind.');seenLinks.add(key);
    links.push(link as unknown as GlossaryLink);
  }
  if(issues.values.length)return issues.result(undefined as never);
  const normalized={typePin:pin as unknown as GlossaryTypePin,primaryLocale,ownerId:source.ownerId as string,
    visibility:source.visibility as 'tenant'|'restricted',allowedIdentityIds:allowed.sort(compare),state:source.state as 'active'|'deprecated',
    attributes:{...attributes,translations} as unknown as AttributeValues,links};
  if(encoder.encode(JSON.stringify(normalized)).length>GLOSSARY_LIMITS.bytes){issues.add('limit','','Normalized glossary JSON exceeds the permitted byte budget.');return issues.result(undefined as never);}
  return issues.result(freeze({input:normalized,translations,name:primary!.name,description:primary!.definition,aliases}));
};

/** Each call returns an independent frozen model suitable for explicit publication. */
export const glossaryStarterType:GlossaryStarterTypeFactory=()=>{
  const definition:AssetTypeDefinition={formatVersion:1,id:'business_term',version:1,parents:[],overrideAttributes:[],requiredOwner:true,
    lifecycle:{initial:'active',states:['active','deprecated'],transitions:[{from:'active',to:'deprecated'},{from:'deprecated',to:'active'}]},
    attributes:{translations:{type:'list',required:true,minItems:1,maxItems:GLOSSARY_LIMITS.translations,items:{type:'object',properties:{
      locale:{type:'text',required:true,minLength:1},name:{type:'text',required:true,minLength:1,maxLength:GLOSSARY_LIMITS.name},
      definition:{type:'text',required:true,minLength:1,maxLength:GLOSSARY_LIMITS.definition},
      synonyms:{type:'list',required:true,maxItems:GLOSSARY_LIMITS.aliases,items:{type:'text',minLength:1,maxLength:GLOSSARY_LIMITS.name}},
      abbreviations:{type:'list',required:true,maxItems:GLOSSARY_LIMITS.aliases,items:{type:'text',minLength:1,maxLength:GLOSSARY_LIMITS.name}},
      examples:{type:'list',required:true,maxItems:GLOSSARY_LIMITS.examples,items:{type:'text',minLength:1,maxLength:GLOSSARY_LIMITS.example}},
    }}}}};
  const parsed=parseAssetTypeDefinition(definition);
  if(!parsed.ok)throw new Error('The built-in glossary type is invalid.');
  return parsed.value;
};
