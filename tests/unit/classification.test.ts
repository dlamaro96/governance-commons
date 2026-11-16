// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {test} from 'node:test';
import {parseClassificationTaxonomy,parseMetadataClassificationRule,classificationDefinitionHash,classificationInputDigest,evaluateMetadataClassification} from '../../packages/domain/src/classification.ts';
import {CLASSIFICATION_LIMITS as limits,type ClassificationAssetInput,type ClassificationPin,type MetadataClassificationRule,type ClassificationTaxonomy} from '../../packages/domain/src/classification-contracts.ts';
import {MODEL_LIMITS,type ValidationResult} from '../../packages/domain/src/model.ts';

const id=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const when='2026-11-17T10:00:00.000Z';
const taxonomy=():ClassificationTaxonomy=>({formatVersion:1,name:'Contact metadata',description:'Labels document reviewed business meaning.',labels:[{key:'contact',name:'Contact information',description:'A reviewed contact field.',status:'active'}]});
const rule=():MetadataClassificationRule=>({formatVersion:1,kind:'metadata-literal',name:'Contact column name',purpose:'Suggest contact labels from explicit names.',ownerId:id(1),status:'active',assetTypes:['column'],label:{taxonomy:{id:id(2),version:1,definitionHash:classificationDefinitionHash(taxonomy())},labelKey:'contact'},all:[{field:'name',operator:'contains',comparison:'ascii-insensitive',literal:'email'}]});
const asset=():ClassificationAssetInput=>({id:id(3),version:7,type:'column',name:'Customer EMAIL',qualifiedName:'example.public.contacts.email',dataType:'text'});
const pin=(r:MetadataClassificationRule):ClassificationPin=>({id:id(4),version:1,definitionHash:classificationDefinitionHash(r)});
const sha=(value:string)=>createHash('sha256').update(value).digest('hex');
function ok<T>(value:ValidationResult<T>):T{if(!value.ok)assert.fail(JSON.stringify(value.issues));return value.value;}
function bad(value:ValidationResult<unknown>,code?:string,path?:string){
  assert.equal(value.ok,false);if(value.ok)return;
  assert.equal(Object.hasOwn(value,'value'),false);assert.ok(value.issues.length>0&&value.issues.length<=MODEL_LIMITS.issues);
  if(code)assert.ok(value.issues.some(issue=>issue.code===code&&(path===undefined||issue.path===path)),JSON.stringify(value.issues));
}
const evaluate=(r=rule(),a=asset())=>evaluateMetadataClassification(r,pin(r),a,when);

test('taxonomy parsing normalizes display text and preserves ordered unique stable label keys',()=>{
  const input=taxonomy();input.name='  Cafe\u0301 labels  ';input.description='  Reviewed\n\tmetadata.  ';
  input.labels.push({key:'private',name:' Prive\u0301 ',description:' Review before use. ',status:'deprecated'});
  const before=structuredClone(input),parsed=ok(parseClassificationTaxonomy(input));
  assert.equal(parsed.name,'Café labels');assert.equal(parsed.description,'Reviewed\n\tmetadata.');
  assert.deepEqual(parsed.labels.map(label=>label.key),['contact','private']);assert.equal(parsed.labels[1]!.name,'Privé');
  assert.ok(Object.isFrozen(parsed)&&Object.isFrozen(parsed.labels)&&Object.isFrozen(parsed.labels[1]));
  assert.deepEqual(input,before);input.labels[0]!.name='Changed';assert.equal(parsed.labels[0]!.name,'Contact information');
  assert.deepEqual(ok(parseClassificationTaxonomy(parsed)),parsed);
});

test('rule parsing is closed and detached, preserves literal whitespace, and normalizes only NFC',()=>{
  const input=rule();input.name='  Re\u0301vision  ';input.all[0]!.literal='  Cafe\u0301  ';input.assetTypes=['view','column'];
  const before=structuredClone(input),parsed=ok(parseMetadataClassificationRule(input));
  assert.equal(parsed.name,'Révision');assert.equal(parsed.all[0]!.literal,'  Café  ');
  assert.deepEqual(parsed.assetTypes,['view','column']);assert.ok(Object.isFrozen(parsed.all[0])&&Object.isFrozen(parsed.label.taxonomy));
  assert.deepEqual(input,before);input.all[0]!.literal='other';assert.equal(parsed.all[0]!.literal,'  Café  ');
  assert.deepEqual(ok(parseMetadataClassificationRule(parsed)),parsed);
});

test('every authored object rejects missing and unknown fields instead of discarding them',()=>{
  const cases:[()=>any,(v:any)=>any,(v:unknown)=>ValidationResult<unknown>,string][]=[
    [taxonomy,v=>v,parseClassificationTaxonomy,''],[taxonomy,v=>v.labels[0],parseClassificationTaxonomy,'/labels/0'],
    [rule,v=>v,parseMetadataClassificationRule,''],[rule,v=>v.label,parseMetadataClassificationRule,'/label'],
    [rule,v=>v.label.taxonomy,parseMetadataClassificationRule,'/label/taxonomy'],[rule,v=>v.all[0],parseMetadataClassificationRule,'/all/0'],
  ];
  for(const[make,select,parse,path]of cases){
    const input=make(),target=select(input);
    for(const key of Object.keys(target)){const prior=target[key];delete target[key];bad(parse(input),'required',`${path}/${key}`);target[key]=prior;}
    target['unexpected/field~']=1;bad(parse(input),'unknown_field',`${path}/unexpected~1field~0`);
  }
});

test('safe keys, exact enums, UUID pins and positive versions never coerce',()=>{
  for(const key of ['',1,'__proto__','prototype','constructor','bad key','1start','x'.repeat(65)]){
    const t:any=taxonomy();t.labels[0].key=key;bad(parseClassificationTaxonomy(t),'format','/labels/0/key');
    const r:any=rule();r.label.labelKey=key;bad(parseMetadataClassificationRule(r),'format','/label/labelKey');
  }
  const r:any=rule();r.label.labelKey='x'.repeat(64);ok(parseMetadataClassificationRule(r));
  for(const value of ['NOT-UUID',id(1).toUpperCase().replace('10000000','ABCDEF00'),'',1,null]){
    const input:any=rule();input.ownerId=value;bad(parseMetadataClassificationRule(input),'format','/ownerId');
    input.ownerId=id(1);input.label.taxonomy.id=value;bad(parseMetadataClassificationRule(input),'format','/label/taxonomy/id');
  }
  for(const value of [0,-0,-1,'1',1.5,2147483648,NaN,Infinity]){const input:any=rule();input.label.taxonomy.version=value;bad(parseMetadataClassificationRule(input));}
  const maximum=rule();maximum.label.taxonomy.version=2147483647;ok(parseMetadataClassificationRule(maximum));
  for(const value of ['a'.repeat(63),'A'.repeat(64),'g'.repeat(64),1]){const input:any=rule();input.label.taxonomy.definitionHash=value;bad(parseMetadataClassificationRule(input),'format');}
  for(const[field,value]of [['formatVersion','1'],['kind','javascript'],['status','approved']] as const){const input:any=rule();input[field]=value;bad(parseMetadataClassificationRule(input));}
  for(const[field,value]of [['field','metadata.secret'],['operator','regex'],['comparison','locale-insensitive']] as const){const input:any=rule();input.all[0][field]=value;bad(parseMetadataClassificationRule(input),'enum');}
  const t:any=taxonomy();t.labels[0].status='retired';bad(parseClassificationTaxonomy(t),'enum');
});

test('collection limits are inclusive and duplicates are rejected without silent deduplication',()=>{
  const t=taxonomy();t.labels=Array.from({length:128},(_,i)=>({key:`label_${i}`,name:'Label',description:'Reviewed.',status:'active'}));
  assert.equal(ok(parseClassificationTaxonomy(t)).labels.length,128);
  t.labels.push({...t.labels[0]!,key:'extra'});bad(parseClassificationTaxonomy(t),'limit','/labels');
  t.labels=[t.labels[0]!,{...t.labels[0]!}];bad(parseClassificationTaxonomy(t),'duplicate','/labels/1/key');
  t.labels=[];bad(parseClassificationTaxonomy(t),'required','/labels');
  const r=rule();r.assetTypes=['table','view','column'];r.all=Array.from({length:8},()=>({...r.all[0]!}));
  assert.equal(ok(parseMetadataClassificationRule(r)).all.length,8,'Authored condition occurrences are preserved.');
  r.all.push({...r.all[0]!});bad(parseMetadataClassificationRule(r),'limit','/all');r.all=[];bad(parseMetadataClassificationRule(r),'required','/all');
  r.all=rule().all;r.assetTypes=['column','column'];bad(parseMetadataClassificationRule(r),'duplicate','/assetTypes/1');
  r.assetTypes=[];bad(parseMetadataClassificationRule(r),'required','/assetTypes');
});

test('text endpoints, well-formed Unicode and prohibited controls are checked before normalization',()=>{
  for(const value of ['', '  ', 'x\u0000', 'x\n', 'x\u007f', '\ud800', '\udc00', 'x'.repeat(limits.name+1)]){const r=rule();r.name=value;bad(parseMetadataClassificationRule(r));}
  const r=rule();r.name='😀'.repeat(limits.name/2);r.purpose='x'.repeat(limits.description);r.all[0]!.literal='x'.repeat(limits.literal);ok(parseMetadataClassificationRule(r));
  r.all[0]!.literal='x'.repeat(limits.literal+1);bad(parseMetadataClassificationRule(r),'limit','/all/0/literal');
  for(const value of ['', '\ud800', '\udc00', 'x\u0000', 'x\t', 'x\n']){r.all[0]!.literal=value;bad(parseMetadataClassificationRule(r));}
  r.all[0]!.literal='  ';assert.equal(ok(parseMetadataClassificationRule(r)).all[0]!.literal,'  ','Spaces are matching data, not trimmed display text.');
  const t=taxonomy();t.description='\n\t';bad(parseClassificationTaxonomy(t),'required');
});

test('definition byte admission enforces exact UTF-8 endpoints independently of character limits',()=>{
  const t=taxonomy();t.labels=Array.from({length:15},(_,i)=>({key:`label_${i}`,name:'Label',description:'x'.repeat(4096),status:'active'}));t.description='x';
  const missing=limits.definitionBytes-Buffer.byteLength(JSON.stringify(t));assert.ok(missing>0&&missing<4096);
  t.description+='x'.repeat(missing);assert.equal(Buffer.byteLength(JSON.stringify(t)),limits.definitionBytes);ok(parseClassificationTaxonomy(t));
  t.description+='x';bad(parseClassificationTaxonomy(t),'limit');
  t.description='x';t.labels.forEach(label=>{label.description='ا'.repeat(2300);});
  assert.ok(JSON.stringify(t).length<limits.definitionBytes);assert.ok(Buffer.byteLength(JSON.stringify(t))>limits.definitionBytes);bad(parseClassificationTaxonomy(t),'limit');
});

test('definition hash is canonical over parsed data and authored array order, refusing ignored fields',()=>{
  const t=taxonomy(),parsed=ok(parseClassificationTaxonomy(t));
  const expected=`{"description":${JSON.stringify(parsed.description)},"formatVersion":1,"labels":[{"description":${JSON.stringify(parsed.labels[0]!.description)},"key":"contact","name":"Contact information","status":"active"}],"name":"Contact metadata"}`;
  assert.equal(classificationDefinitionHash(t),sha(expected));
  const reordered=Object.fromEntries(Object.entries(t).reverse());assert.equal(classificationDefinitionHash(reordered),classificationDefinitionHash(t));
  t.name='  Cafe\u0301  ';const normalized={...t,name:'Café'};assert.equal(classificationDefinitionHash(t),classificationDefinitionHash(normalized));
  t.labels.push({key:'other',name:'Other',description:'Other.',status:'active'});
  assert.notEqual(classificationDefinitionHash(t),classificationDefinitionHash({...t,labels:[...t.labels].reverse()}));
  assert.throws(()=>classificationDefinitionHash({...t,unknown:true}),{name:'TypeError',message:'Invalid classification data.'});
  assert.throws(()=>classificationDefinitionHash({arbitrary:'data'}),TypeError);
});

test('literal operators and ASCII comparison evaluate actual metadata without interpreting expressions',()=>{
  const cases:[MetadataClassificationRule['all'][number]['operator'],string,string,boolean][]=[
    ['equals','email','email',true],['equals','email','email_address',false],['contains','email','customer_email_address',true],['contains','email','customer_name',false],
    ['starts-with','email','email_address',true],['starts-with','email','customer_email',false],['ends-with','email','customer_email',true],['ends-with','email','email_address',false],
    ['contains','.*','customer_email',false],['equals','${name}','${name}',true],['contains',"' OR 1=1",'email',false],
  ];
  for(const[operator,literal,value,expected]of cases){const r=rule(),a=asset();r.all=[{field:'name',operator,comparison:'exact',literal}];a.name=value;
    assert.equal(ok(evaluate(r,a)).outcome,expected?'matched':'not_matched',`${operator}: ${literal}`);
  }
  const r=rule(),a=asset();r.all[0]!.operator='equals';r.all[0]!.literal='EMAIL';a.name='email';
  assert.equal(ok(evaluate(r,a)).outcome,'matched');r.all[0]!.comparison='exact';assert.equal(ok(evaluate(r,a)).outcome,'not_matched');
});

test('NFC matching and ASCII-only folding preserve exact observed values and their raw UTF-8 hashes',()=>{
  const r=rule(),a=asset();r.all[0]={field:'name',operator:'equals',comparison:'ascii-insensitive',literal:'café'};a.name='CAFE\u0301';
  const value=ok(evaluate(r,a));assert.equal(value.outcome,'not_matched','ASCII folding does not fold É.');
  a.name='CAFé';const matched=ok(evaluate(r,a));assert.equal(matched.outcome,'matched');
  r.all[0]!.literal='Café';r.all[0]!.comparison='exact';a.name='Cafe\u0301';const exact=ok(evaluate(r,a));
  assert.equal(exact.outcome,'matched');assert.equal(exact.evidence.matches[0]!.value,'Cafe\u0301');assert.equal(exact.evidence.matches[0]!.valueHash,sha('Cafe\u0301'));
  assert.notEqual(exact.evidence.matches[0]!.valueHash,sha('Café'));
  for(const[observed,literal]of [['Ä','ä'],['İ','i'],['ß','ss']]){a.name=observed!;r.all[0]!.literal=literal!;r.all[0]!.comparison='ascii-insensitive';assert.equal(ok(evaluate(r,a)).outcome,'not_matched');}
  a.name=' email ';r.all[0]!.literal=' email ';assert.equal(ok(evaluate(r,a)).outcome,'matched');
  r.all[0]!.literal='email';assert.equal(ok(evaluate(r,a)).outcome,'not_matched');
});

test('all predicates participate, missing dataType never matches, and evidence includes only observed successful conditions',()=>{
  const r=rule(),a=asset();r.all=[
    {field:'dataType',operator:'equals',comparison:'exact',literal:'text'},
    {field:'name',operator:'contains',comparison:'ascii-insensitive',literal:'email'},
    {field:'qualifiedName',operator:'starts-with',comparison:'exact',literal:'example.'},
  ];a.dataType=null;
  const result=ok(evaluate(r,a));assert.equal(result.outcome,'not_matched');assert.deepEqual(result.evidence.matches.map(match=>match.conditionIndex),[1,2]);
  assert.deepEqual(result.evidence.matches.map(match=>match.value),[a.name,a.qualifiedName]);
  a.dataType='text';assert.equal(ok(evaluate(r,a)).outcome,'matched');
  assert.deepEqual(Object.keys(result.evidence).sort(),['assetId','confidence','evaluatedAt','formatVersion','inputDigest','kind','label','matches','observedAssetVersion','rule','samplePolicy'].sort());
  assert.deepEqual(result.evidence.confidence,{kind:'not-estimated',reason:'metadata-only'});
  assert.deepEqual(result.evidence.samplePolicy,{kind:'metadata-only',sourceRowsRead:0,sourceSamplesStored:0});
});

test('wrong asset types are unsupported with empty matches, without hiding malformed inputs',()=>{
  const r=rule(),a=asset();a.type='business_term';const result=ok(evaluate(r,a));assert.equal(result.outcome,'unsupported');assert.deepEqual(result.evidence.matches,[]);
  assert.equal(result.evidence.inputDigest,classificationInputDigest(r,a));
  const malformed:any={...a,version:0};bad(evaluateMetadataClassification(r,pin(r),malformed,when),'model_version');
  const hidden:any={...a,secret:'not admitted'};bad(evaluateMetadataClassification(r,pin(r),hidden,when),'unknown_field','/secret');
});

test('retirement does not change pure metadata semantics or pretend to grant new-operation authority',()=>{
  const active=rule(),retired={...active,status:'retired' as const};
  assert.equal(ok(evaluate(retired)).outcome,'matched');assert.equal(classificationInputDigest(active,asset()),classificationInputDigest(retired,asset()));
  assert.notEqual(classificationDefinitionHash(active),classificationDefinitionHash(retired));
});

test('input digest has an explicit independent preimage and excludes revision and unselected fields',()=>{
  const r=rule(),a=asset();const preimage=`{"assetId":"${a.id}","assetType":"column","fields":{"name":"Customer EMAIL"},"formatVersion":1}`;
  assert.equal(classificationInputDigest(r,a),sha(preimage));
  const changed={...a,version:8,qualifiedName:'renamed.context',dataType:'varchar'};
  assert.equal(classificationInputDigest(r,a),classificationInputDigest(r,changed));
  assert.equal(ok(evaluate(r,changed)).evidence.observedAssetVersion,8);
  for(const delta of [{id:id(99)},{type:'view'},{name:'customer email'}])assert.notEqual(classificationInputDigest(r,a),classificationInputDigest(r,{...a,...delta}));
  const changedRule={...r,name:'Other name',purpose:'Other purpose',ownerId:id(10)};assert.equal(classificationInputDigest(r,a),classificationInputDigest(changedRule,a));
});

test('selected field union is ordered and deduplicated only for digest, including explicit missing null',()=>{
  const r=rule(),a=asset();r.all.push({field:'dataType',operator:'equals',comparison:'exact',literal:'text'});a.dataType=null;
  const preimage=`{"assetId":"${a.id}","assetType":"column","fields":{"dataType":null,"name":"Customer EMAIL"},"formatVersion":1}`;
  assert.equal(classificationInputDigest(r,a),sha(preimage));
  const reordered={...r,all:[...r.all].reverse()};assert.equal(classificationInputDigest(r,a),classificationInputDigest(reordered,a));
  reordered.all.push({...r.all[0]!});assert.equal(classificationInputDigest(r,a),classificationInputDigest(reordered,a));
  assert.notEqual(classificationInputDigest(r,a),classificationInputDigest(r,{...a,dataType:'text'}));
  assert.notEqual(classificationInputDigest(r,{...a,name:'Café'}),classificationInputDigest(r,{...a,name:'Cafe\u0301'}),'Proof retains exact observed text even when NFC matching is equivalent.');
});

test('evaluation validates complete pins, exact normalized rule hash and UTC millisecond timestamps',()=>{
  const r=rule(),p=pin(r),a=asset();
  for(const field of Object.keys(p)){const missing:any={...p};delete missing[field];bad(evaluateMetadataClassification(r,missing,a,when),'required',`/rule/${field}`);}
  bad(evaluateMetadataClassification(r,{...p,extra:true},a,when),'unknown_field','/rule/extra');
  bad(evaluateMetadataClassification(r,{...p,id:'bad'},a,when),'format','/rule/id');
  bad(evaluateMetadataClassification(r,{...p,version:0},a,when),'model_version','/rule/version');
  bad(evaluateMetadataClassification(r,{...p,definitionHash:'a'.repeat(64)},a,when),'invalid_definition','/rule/definitionHash');
  bad(evaluateMetadataClassification({...r,name:'Changed'},p,a,when),'invalid_definition','/rule/definitionHash');
  for(const value of ['2026-02-30T10:00:00.000Z','2026-11-17T10:00:00Z','2026-11-17T10:00:00.000+00:00','2026-11-17T10:00:00.0000Z','not time',0,new Date(when)])bad(evaluateMetadataClassification(r,p,a,value),'format','/evaluatedAt');
  assert.equal(ok(evaluateMetadataClassification(r,p,a,'2024-02-29T23:59:59.999Z')).evidence.evaluatedAt,'2024-02-29T23:59:59.999Z');
});

test('asset input is exact and bounded, with null as the only missing dataType representation',()=>{
  const r=rule(),p=pin(r),a=asset();
  for(const field of Object.keys(a)){const missing:any={...a};delete missing[field];bad(evaluateMetadataClassification(r,p,missing,when),'required',`/${field}`);}
  for(const value of ['',1,undefined,[],{},'\ud800','x\u0000','x'.repeat(limits.field+1)]){bad(evaluateMetadataClassification(r,p,{...a,name:value},when));bad(evaluateMetadataClassification(r,p,{...a,dataType:value},when));}
  const bounded={...a,name:'x'.repeat(limits.field),qualifiedName:'q'.repeat(limits.field),dataType:'d'.repeat(limits.field)};ok(evaluate(r,bounded));
  assert.throws(()=>classificationInputDigest(r,{...a,secret:'extra'}),{name:'TypeError',message:'Invalid classification data.'});
  assert.throws(()=>classificationInputDigest({...r,code:'arbitrary'},a),TypeError);
});

test('evidence byte budget refuses the entire result rather than truncating observed matches',()=>{
  const r=rule(),a=asset();r.all=Array.from({length:8},()=>({field:'name',operator:'contains',comparison:'exact',literal:'😀'}));a.name='😀'.repeat(1024);
  bad(evaluate(r,a),'limit');
  a.name='😀'.repeat(800);const result=ok(evaluate(r,a));assert.equal(result.evidence.matches.length,8);
  assert.ok(Buffer.byteLength(JSON.stringify(result))<=limits.evidenceBytes);assert.equal(result.evidence.matches[7]!.value,a.name);
});

test('all entry points reject accessors and executable toJSON without invoking them',()=>{
  let calls=0;const getter=()=>{calls++;throw new Error('must not run');};
  const t=taxonomy();Object.defineProperty(t,'name',{enumerable:true,get:getter});bad(parseClassificationTaxonomy(t),'invalid_json');
  const r=rule();Object.defineProperty(r.all[0]!,'literal',{enumerable:true,get:getter});bad(parseMetadataClassificationRule(r),'invalid_json');
  const p=pin(rule());Object.defineProperty(p,'definitionHash',{enumerable:true,get:getter});bad(evaluateMetadataClassification(rule(),p,asset(),when),'invalid_json');
  const a=asset();Object.defineProperty(a,'name',{enumerable:true,get:getter});assert.throws(()=>classificationInputDigest(rule(),a),TypeError);
  const json:any=taxonomy();json.toJSON=()=>{calls++;return taxonomy();};bad(parseClassificationTaxonomy(json),'invalid_json');assert.throws(()=>classificationDefinitionHash(json),TypeError);
  assert.equal(calls,0);
});

test('plain own-data admission rejects prototypes, symbols, non-enumerable fields and irregular arrays',()=>{
  const inherited=Object.assign(Object.create({secret:1}),taxonomy());bad(parseClassificationTaxonomy(inherited),'invalid_json');
  const nullPrototype=Object.assign(Object.create(null),taxonomy());ok(parseClassificationTaxonomy(nullPrototype));
  for(const modify of [(v:any)=>{v[Symbol('hidden')]=1;},(v:any)=>{Object.defineProperty(v,'hidden',{value:1});}]){const t=taxonomy();modify(t);bad(parseClassificationTaxonomy(t),'invalid_json');}
  const sparse:any=rule();sparse.all.length=2;bad(parseMetadataClassificationRule(sparse),'invalid_json');
  const extra:any=rule();extra.all.named=true;bad(parseMetadataClassificationRule(extra),'invalid_json');
  const symbol:any=rule();symbol.all[Symbol('x')]=true;bad(parseMetadataClassificationRule(symbol),'invalid_json');
  for(const value of [()=>null,Symbol('x'),undefined,BigInt(1),new Date(),JSON.stringify(taxonomy())])bad(parseClassificationTaxonomy(value));
});

test('inherited setters, read-only properties and toJSON cannot affect detached snapshot construction',()=>{
  const r=rule();let calls=0;let result:ValidationResult<MetadataClassificationRule>|undefined;
  const previous=['literal','ownerId','toJSON'].map(key=>[key,Object.getOwnPropertyDescriptor(Object.prototype,key)] as const);
  try{
    Object.defineProperty(Object.prototype,'literal',{configurable:true,value:'inherited',writable:false});
    Object.defineProperty(Object.prototype,'ownerId',{configurable:true,set(){calls++;}});
    Object.defineProperty(Object.prototype,'toJSON',{configurable:true,get(){calls++;throw new Error('must not run');}});
    result=parseMetadataClassificationRule(r);
  }finally{for(const[key,descriptor]of previous){if(descriptor)Object.defineProperty(Object.prototype,key,descriptor);else Reflect.deleteProperty(Object.prototype,key);}}
  assert.equal(calls,0);assert.deepEqual(ok(result!),r);
});

test('cycles and excess structural budgets refuse safely; shared ordinary data remains detached',()=>{
  const cycle:any=taxonomy();cycle.extra=cycle;bad(parseClassificationTaxonomy(cycle),'cycle');
  const deep:any=taxonomy();let tail:any={};deep.extra=tail;for(let i=0;i<30;i++){tail.next={};tail=tail.next;}bad(parseClassificationTaxonomy(deep),'limit');
  const long:any=taxonomy();long.extra=Array.from({length:1001},()=>0);bad(parseClassificationTaxonomy(long),'limit');
  const keys:any=taxonomy();for(let i=0;i<129;i++)keys[`x${i}`]=0;bad(parseClassificationTaxonomy(keys),'limit');
  const r=rule();r.all.push(r.all[0]!);const parsed=ok(parseMetadataClassificationRule(r));assert.notEqual(parsed.all[0],parsed.all[1]);
});

test('reflection exceptions do not execute error properties, and diagnostics remain bounded and static',()=>{
  let inspected=0;const thrown=new Proxy({}, {get(){inspected++;throw new Error('must not inspect');}});
  const hostile=new Proxy({}, {ownKeys(){throw thrown;}});bad(parseClassificationTaxonomy(hostile),'invalid_json');bad(parseMetadataClassificationRule(hostile),'invalid_json');
  assert.throws(()=>classificationDefinitionHash(hostile),{name:'TypeError',message:'Invalid classification data.'});
  assert.throws(()=>classificationInputDigest(rule(),hostile),TypeError);bad(evaluateMetadataClassification(rule(),pin(rule()),hostile,when),'invalid_json');assert.equal(inspected,0);
  const many:any=taxonomy();for(let i=0;i<115;i++)many[`extra_${i}`]=`untrusted_${i}`;const issues=parseClassificationTaxonomy(many);bad(issues);
  if(!issues.ok){assert.equal(issues.issues.length,MODEL_LIMITS.issues);assert.equal(issues.issues.at(-1)!.code,'limit');assert.ok(issues.issues.every(issue=>!issue.message.includes('untrusted_')));}
});

test('evaluation returns an immutable detached evidence snapshot without mutating any input',()=>{
  const r=rule(),p=pin(r),a=asset(),before=structuredClone({r,p,a}),result=ok(evaluateMetadataClassification(r,p,a,when));
  assert.deepEqual({r,p,a},before);assert.ok(Object.isFrozen(result)&&Object.isFrozen(result.evidence.matches)&&Object.isFrozen(result.evidence.matches[0])&&Object.isFrozen(result.evidence.label.taxonomy));
  a.name='different';p.version=2;r.label.labelKey='other';
  assert.equal(result.evidence.matches[0]!.value,'Customer EMAIL');assert.equal(result.evidence.rule.version,1);assert.equal(result.evidence.label.labelKey,'contact');
});
