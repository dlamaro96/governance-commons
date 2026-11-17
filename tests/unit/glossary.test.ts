// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {parseGlossaryPublication,glossaryStarterType} from '../../packages/domain/src/glossary.ts';
import {GLOSSARY_LIMITS} from '../../packages/domain/src/glossary-contracts.ts';
import {MODEL_LIMITS,validateAttributes,type ValidationResult} from '../../packages/domain/src/model.ts';
import {parseAssetTypeDefinition,resolveAssetType} from '../../packages/domain/src/asset-type.ts';

const id=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const translation=(locale='en')=>({locale,name:'Revenue',definition:'Value earned from ordinary activities.',synonyms:['Income'],abbreviations:['REV'],examples:['An invoice contributes to revenue.']});
function input():any{return {typePin:{typeId:id(1),modelId:'business_term',version:1,definitionHash:'a'.repeat(64),resolutionHash:'b'.repeat(64)},
  primaryLocale:'en',ownerId:id(2),visibility:'tenant',allowedIdentityIds:[],state:'active',attributes:{translations:[translation()]},links:[]};}
const link=(kind='related',target=3)=>({kind,typePin:{relationTypeId:id(4),version:1,definitionHash:'c'.repeat(64)},targetAssetId:id(target),targetAssetVersion:1});
function ok<T>(result:ValidationResult<T>):T{if(!result.ok)assert.fail(JSON.stringify(result.issues));return result.value;}
function fails(value:unknown,code?:string,path?:string){
  const result=parseGlossaryPublication(value);assert.equal(result.ok,false);
  if(result.ok)return;
  assert.ok(result.issues.length>0&&result.issues.length<=MODEL_LIMITS.issues);
  if(code)assert.ok(result.issues.some(issue=>issue.code===code&&(path===undefined||issue.path===path)),JSON.stringify(result.issues));
  return result.issues;
}

test('starter type resolves as a required-owner typed model with reversible active/deprecated lifecycle',()=>{
  const starter=glossaryStarterType(),parsed=ok(parseAssetTypeDefinition(starter)),resolved=ok(resolveAssetType(starter,[]));
  assert.equal(parsed.id,'business_term');assert.equal(parsed.version,1);assert.equal(resolved.requiredOwner,true);
  assert.deepEqual(resolved.lifecycle,{initial:'active',states:['active','deprecated'],transitions:[{from:'active',to:'deprecated'},{from:'deprecated',to:'active'}]});
  const publication=ok(parseGlossaryPublication(input()));
  assert.deepEqual(ok(validateAttributes(resolved.model,publication.input.attributes)),publication.input.attributes);
  assert.equal(validateAttributes(resolved.model,{translations:[]}).ok,false);
  assert.equal(validateAttributes(resolved.model,{translations:[{...translation(),extra:true}]}).ok,false);
  assert.equal(validateAttributes(resolved.model,{translations:[{...translation(),synonyms:'Income'}]}).ok,false);
  assert.equal(Object.isFrozen(starter.attributes.translations),true);
  const again=glossaryStarterType();assert.notEqual(starter,again);assert.deepEqual(starter,again);
});

test('primary locale drives canonical display; typed multilingual values normalize without flattening custom attributes',()=>{
  const value=input();value.primaryLocale='EN-us';
  value.attributes.translations=[{locale:'en-US',name:'  Cafe\u0301  ',definition:'\n Net income\tfrom operations.\r\n',synonyms:['  Earnings  '],abbreviations:['CF'],examples:['  First line\nsecond line.  ']},
    {locale:'ar',name:'الإيرادات',definition:'القيمة الناتجة عن الأنشطة العادية.',synonyms:['الدخل'],abbreviations:['إيراد'],examples:['قيمة فاتورة.']}];
  value.attributes.custom={amount:'12345678901234567890.001',ratio:0.25,enabled:true,nested:['  unchanged  ',{decomposed:'e\u0301'}]};
  const original=structuredClone(value),result=ok(parseGlossaryPublication(value));
  assert.equal(result.name,'Café');assert.equal(result.description,'Net income\tfrom operations.');assert.equal(result.input.primaryLocale,'en-US');
  assert.equal(result.translations[0]!.locale,'en-US');assert.deepEqual(result.translations[0]!.synonyms,['Earnings']);
  assert.deepEqual(result.translations[0]!.examples,['First line\nsecond line.']);
  assert.deepEqual(result.input.attributes.custom,original.attributes.custom);
  assert.deepEqual(value,original,'The caller object is never rewritten or frozen');
  assert.equal(Object.isFrozen(value.attributes),false);assert.equal(Object.isFrozen(result.input.attributes),true);
  value.attributes.custom.nested[1].decomposed='changed';assert.deepEqual(result.input.attributes.custom,original.attributes.custom);
  assert.deepEqual(ok(parseGlossaryPublication(result.input)),result,'Normalized publications are idempotent');
});

test('locale aliases canonicalize and locale-qualified aliases do not merge distinct translations or terms',()=>{
  const value=input();value.primaryLocale='iw';value.attributes.translations=[translation('he'),translation('en')];
  const result=ok(parseGlossaryPublication(value));assert.equal(result.input.primaryLocale,'he');assert.equal(result.translations.length,2);
  assert.deepEqual(result.aliases.filter(row=>row.kind==='name'),[{locale:'he',kind:'name',value:'Revenue',key:'revenue'},{locale:'en',kind:'name',value:'Revenue',key:'revenue'}]);
  assert.deepEqual(ok(parseGlossaryPublication(input())).aliases,ok(parseGlossaryPublication(input())).aliases,'Pure parsing does not look up or merge another term');
  value.attributes.translations.push(translation('iw'));fails(value,'duplicate','/attributes/translations/2/locale');
  for(const tag of ['en-u-ca-gregory','en-t-fr','en-x-private','x-private','en_US',' en','', 'en--US']){
    const invalid=input();invalid.primaryLocale=tag;fails(invalid,'format','/primaryLocale');
    invalid.primaryLocale='en';invalid.attributes.translations[0].locale=tag;fails(invalid,'format','/attributes/translations/0/locale');
  }
  const absent=input();absent.primaryLocale='ar';fails(absent,'required','/primaryLocale');
});

test('NFKC and lower-case alias collisions produce explicit paths without dropping any authored alias',()=>{
  for(const [name,synonym]of [['Revenue','Ｒｅｖｅｎｕｅ'],['Café','Cafe\u0301'],['OFFICE','Oﬃce']]){
    const value=input();Object.assign(value.attributes.translations[0],{name,synonyms:[synonym]});
    const issues=fails(value,'duplicate','/attributes/translations/0/synonyms/0')!;
    assert.ok(issues.every(issue=>!issue.message.includes(name)&&!issue.message.includes(synonym)),'Diagnostics do not echo term content');
  }
  const cross=input();cross.attributes.translations[0].abbreviations=['rev','income'];
  fails(cross,'duplicate','/attributes/translations/0/abbreviations/1');
  const repeated=input();repeated.attributes.translations[0].synonyms=['Income','income'];
  fails(repeated,'duplicate','/attributes/translations/0/synonyms/1');
  const distinct=input();distinct.attributes.translations[0].synonyms=['Income  stream','Income stream'];
  assert.equal(ok(parseGlossaryPublication(distinct)).aliases.length,4,'Whitespace inside a name is not silently collapsed');
});

test('envelope, type pins, translations, relation links and relation pins require every exact field',()=>{
  const variants:Array<{value:any;path:string;object:any}>=[];
  for(const section of ['envelope','typePin','translation','link','relationPin']){
    const value=input();value.links=[link()];
    const [object,path]=section==='envelope'?[value,'']:section==='typePin'?[value.typePin,'/typePin']:section==='translation'?[value.attributes.translations[0],'/attributes/translations/0']:
      section==='link'?[value.links[0],'/links/0']:[value.links[0].typePin,'/links/0/typePin'];
    variants.push({value,path,object});
  }
  for(const {value,path,object}of variants){
    for(const key of Object.keys(object)){
      const saved=object[key];delete object[key];fails(value,'required',`${path}/${key}`);object[key]=saved;
    }
    object['extra/key~']=true;fails(value,'unknown_field',`${path}/extra~1key~0`);delete object['extra/key~'];
  }
  const missing=input();delete missing.attributes.translations;fails(missing,'required','/attributes/translations');
  for(const empty of [[],{},'translations']){const value=input();value.attributes.translations=empty;fails(value);}
});

test('UUIDs, exact digests, model identifiers and database integer versions never coerce',()=>{
  for(const bad of ['ABC00000-0000-4000-8000-000000000001','not-a-uuid',1,null]){
    const value=input();value.ownerId=bad;fails(value);
    value.ownerId=id(2);value.typePin.typeId=bad;fails(value);
  }
  for(const bad of ['A'.repeat(64),'a'.repeat(63),'g'.repeat(64),64]){const value=input();value.typePin.definitionHash=bad;fails(value,'format','/typePin/definitionHash');}
  for(const bad of ['__proto__','constructor','bad id','1model','x'.repeat(65)]){const value=input();value.typePin.modelId=bad;fails(value,'format','/typePin/modelId');}
  for(const bad of [0,-0,-1,1.5,2_147_483_648,'1',Infinity,NaN]){const value=input();value.typePin.version=bad;fails(value);}
  const maximum=input();maximum.typePin.version=2_147_483_647;maximum.links=[link()];maximum.links[0].targetAssetVersion=2_147_483_647;
  assert.equal(ok(parseGlossaryPublication(maximum)).input.typePin.version,2_147_483_647);
  for(const field of ['version','targetAssetVersion']){const value=input();value.links=[link()];(field==='version'?value.links[0].typePin:value.links[0])[field]='1';fails(value,'model_version');}
  const badState=input();badState.state='retired';fails(badState,'enum','/state');badState.state='deprecated';assert.equal(ok(parseGlossaryPublication(badState)).input.state,'deprecated');
});

test('restricted ACLs remain explicit sorted unique nonempty UUID sets and tenant ACLs remain empty',()=>{
  const value=input();value.visibility='restricted';value.allowedIdentityIds=[id(9),id(2),id(7)];
  assert.deepEqual(ok(parseGlossaryPublication(value)).input.allowedIdentityIds,[id(2),id(7),id(9)]);
  value.allowedIdentityIds.push(id(2));fails(value,'duplicate','/allowedIdentityIds/3');
  value.allowedIdentityIds=[];fails(value,'required','/allowedIdentityIds');
  value.visibility='tenant';value.allowedIdentityIds=[id(9)];fails(value,'invalid_definition','/allowedIdentityIds');
  value.visibility='public';fails(value,'enum','/visibility');
  value.visibility='restricted';value.allowedIdentityIds=Array.from({length:100},(_,i)=>id(i+1));assert.equal(ok(parseGlossaryPublication(value)).input.allowedIdentityIds.length,100);
  value.allowedIdentityIds.push(id(101));fails(value,'limit','/allowedIdentityIds');
});

test('relation full target sets preserve pins and ordering but reject duplicate target-kind pairs and a second broader',()=>{
  const value=input();value.links=[link('related'),link('defines'),link('broader',7)];
  assert.deepEqual(ok(parseGlossaryPublication(value)).input.links,value.links);
  value.links.push({...link('related'),typePin:{...link().typePin,relationTypeId:id(8)}});fails(value,'duplicate','/links/3');
  value.links=[link('broader',3),link('broader',7)];fails(value,'limit','/links/1/kind');
  value.links=[link('unknown')];fails(value,'enum','/links/0/kind');
  value.links=Array.from({length:100},(_,i)=>link('related',i+100));assert.equal(ok(parseGlossaryPublication(value)).input.links.length,100);
  value.links.push(link('related',999));fails(value,'limit','/links');
});

test('display text rejects malformed Unicode, controls and empty normalized values while preserving permitted multiline text',()=>{
  for(const bad of ['\ud800','\udc00','name\u0000','name\u007f','name\u0085','name\t','name\n','   ']){
    const value=input();value.attributes.translations[0].name=bad;fails(value);
  }
  for(const field of ['definition','examples'])for(const bad of ['bad\u0000','bad\u000b','bad\u0085','  ']){
    const value=input();value.attributes.translations[0][field]=field==='examples'?[bad]:bad;fails(value);
  }
  const value=input();value.attributes.translations[0].definition='Line one\r\nLine two\tend';value.attributes.translations[0].examples=['First\tsecond\nthird'];
  assert.equal(ok(parseGlossaryPublication(value)).description,value.attributes.translations[0].definition);
  value.attributes.custom='\ud800';fails(value,'format','/attributes/custom');
});

test('translation and per-list limits accept exact boundaries and refuse one more without truncation',()=>{
  const value=input();value.primaryLocale='en-001';value.attributes.translations=Array.from({length:32},(_,i)=>translation(`en-${String(i+1).padStart(3,'0')}`));
  assert.equal(ok(parseGlossaryPublication(value)).translations.length,32);
  value.attributes.translations.push(translation('en-033'));fails(value,'limit','/attributes/translations');
  for(const key of ['synonyms','abbreviations','examples']as const){
    const row=input(),maximum=key==='examples'?16:32;row.attributes.translations[0][key]=Array.from({length:maximum},(_,i)=>`Value ${i}`);
    assert.equal((ok(parseGlossaryPublication(row)).translations[0]![key]).length,maximum);
    row.attributes.translations[0][key].push('One more');fails(row,'limit',`/attributes/translations/0/${key}`);
  }
});

test('display limits match the starter model in UTF-16 units and refuse oversized input before normalization can hide it',()=>{
  for(const [key,maximum]of [['name',240],['definition',16_384],['examples',4096],['synonyms',240],['abbreviations',240]]as const){
    const value=input(),array=['examples','synonyms','abbreviations'].includes(key);
    value.attributes.translations[0][key]=array?['x'.repeat(maximum)]:'x'.repeat(maximum);
    const parsed=ok(parseGlossaryPublication(value));assert.equal(validateAttributes(ok(resolveAssetType(glossaryStarterType(),[])).model,parsed.input.attributes).ok,true);
    value.attributes.translations[0][key]=array?['x'.repeat(maximum+1)]:'x'.repeat(maximum+1);fails(value,'limit');
  }
  const value=input();value.attributes.translations[0].name='😀'.repeat(120);assert.equal(ok(parseGlossaryPublication(value)).name.length,240);
  value.attributes.translations[0].name=' '.repeat(240)+'x';fails(value,'limit','/attributes/translations/0/name');
});

test('aggregate UTF-8 JSON bytes accept exactly262144 and refuse excess including multibyte custom data',()=>{
  const value=input();value.attributes.custom={a:'x'.repeat(65_536),b:'x'.repeat(65_536),c:'x'.repeat(65_536),d:''};
  const current=Buffer.byteLength(JSON.stringify(value)),remaining=GLOSSARY_LIMITS.bytes-current;
  assert.ok(remaining>0&&remaining<65_536);value.attributes.custom.d='x'.repeat(remaining);
  assert.equal(Buffer.byteLength(JSON.stringify(value)),GLOSSARY_LIMITS.bytes);ok(parseGlossaryPublication(value));
  value.attributes.custom.d+='x';fails(value,'limit');
  const unicode=input();unicode.attributes.custom={a:'😀'.repeat(16_384),b:'😀'.repeat(16_384),c:'😀'.repeat(16_384),d:'😀'.repeat(16_384)};fails(unicode,'limit');
});

test('descriptor snapshot rejects accessors, toJSON, sparse or decorated arrays and non-JSON prototypes without invoking getters',()=>{
  let called=0;const getter=()=>{called++;throw new Error('Accessor must not execute');};
  const root=input();Object.defineProperty(root,'ownerId',{enumerable:true,get:getter});fails(root,'invalid_json','/ownerId');
  const nested=input();Object.defineProperty(nested.attributes,'custom',{enumerable:true,get:getter});fails(nested,'invalid_json','/attributes/custom');
  const json=input();json.toJSON=()=>{called++;return input();};fails(json,'invalid_json');
  const hidden=input();Object.defineProperty(hidden,'hidden',{value:true});fails(hidden,'invalid_json','/hidden');
  const symbol=input();symbol[Symbol('hidden')]=true;fails(symbol,'invalid_json');
  const sparse=input();sparse.attributes.translations[0].synonyms=Array(2);fails(sparse,'invalid_json');
  const decorated=input();decorated.links.extra=true;fails(decorated,'invalid_json');
  const arrayGetter=input();Object.defineProperty(arrayGetter.attributes.translations,'0',{enumerable:true,get:getter});fails(arrayGetter,'invalid_json');
  const prototype=input();Object.setPrototypeOf(prototype.attributes,new Date());fails(prototype,'invalid_json');
  assert.equal(called,0);
});

test('cycles, unsupported scalar values, reflective failures and aggregate structural excess fail closed',()=>{
  const cycle=input();cycle.attributes.loop=cycle;fails(cycle,'cycle');
  for(const bad of [null,undefined,1n,()=>{},Symbol('value'),NaN,-0,Infinity,new Date(),new Map()]){
    const value=input();value.attributes.custom=bad;fails(value);
  }
  const revoked=Proxy.revocable(input(),{});revoked.revoke();fails(revoked.proxy,'invalid_json');
  let inspected=0;const thrown=new Proxy({},{getPrototypeOf(){inspected++;throw new Error('Do not inspect untrusted thrown objects');}});
  fails(new Proxy(input(),{getPrototypeOf(){throw thrown;}}),'invalid_json');assert.equal(inspected,0);
  const value=input();value.attributes.custom=Object.fromEntries(Array.from({length:129},(_,i)=>[`key${i}`,i]));fails(value,'limit');
  const deep=input();let child=deep.attributes;for(let i=0;i<23;i++){child.child={};child=child.child;}fails(deep,'limit');
  const many=input();many.attributes.custom=Array.from({length:25},()=>Array(900).fill(false));fails(many,'limit');
  const wide=input();wide.attributes.custom=Array(1001).fill(false);fails(wide,'limit');
});

test('additional fields remain byte-equivalent data for later pinned-model validation and cannot exploit prototype assignment',()=>{
  const value=input();value.attributes.extra={text:'  E\u0301  ',number:1.25,bool:false,list:[{amount:'99999999999999999.0001'}]};
  Object.defineProperty(value.attributes,'__proto__',{value:{data:'preserved'},enumerable:true,writable:true});
  const result=ok(parseGlossaryPublication(value));assert.deepEqual(result.input.attributes.extra,value.attributes.extra);
  assert.equal(Object.hasOwn(result.input.attributes,'__proto__'),true);assert.deepEqual(result.input.attributes.__proto__,{data:'preserved'});
  assert.equal(Object.getPrototypeOf(result.input.attributes),Object.prototype);
  assert.equal(validateAttributes(ok(resolveAssetType(glossaryStarterType(),[])).model,result.input.attributes).ok,false,'Exact model validation still rejects unpublished custom attributes');
});

test('diagnostics are bounded and malformed inputs never return partial translations or aliases',()=>{
  const value=input();value.attributes.translations=Array.from({length:32},()=>({locale:'en',name:' ',definition:' ',synonyms:['',''],abbreviations:[''],examples:['']}));
  const result=parseGlossaryPublication(value);assert.equal(result.ok,false);
  if(!result.ok){assert.equal(result.issues.length,100);assert.equal(result.issues.at(-1)!.code,'limit');assert.equal(Object.hasOwn(result,'value'),false);}
});


test('descriptor materialization preserves inherited setter and read-only literal names as own data',()=>{
  const setterName='glossaryInheritedSetter',readonlyName='glossaryInheritedReadonly';let calls=0;
  const value=input();value.attributes.custom=JSON.parse(`{"${setterName}":{"${readonlyName}":["first","second"]},"__proto__":{"literal":true}}`);
  const expected=structuredClone(value.attributes.custom);
  Object.defineProperty(Object.prototype,setterName,{configurable:true,set(){calls++;throw new Error('Inherited setter must not run');}});
  Object.defineProperty(Object.prototype,readonlyName,{configurable:true,writable:false,value:'inherited'});
  try{
    const result=ok(parseGlossaryPublication(value));const actual=result.input.attributes.custom as Record<string,any>;
    assert.deepEqual(actual,expected);assert.equal(Object.hasOwn(actual,setterName),true);
    assert.equal(Object.hasOwn(actual[setterName],readonlyName),true);assert.equal(Object.hasOwn(actual,'__proto__'),true);
    assert.deepEqual(actual[setterName][readonlyName],['first','second']);assert.equal(calls,0);
  }finally{delete (Object.prototype as any)[setterName];delete (Object.prototype as any)[readonlyName];}
});
