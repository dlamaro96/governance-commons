// SPDX-License-Identifier: Apache-2.0
// Pure parsing/reconciliation controls; no database, authorization or browser qualification.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {parseImportRows,reconcileImport} from '../../packages/domain/src/reference-import.ts';
import {parseReferenceValue,parseRelease} from '../../packages/domain/src/reference-data.ts';
import {IMPORT_CSV_HEADERS,IMPORT_FIELDS,IMPORT_LIMITS,type ImportBase,type ImportInvalid,type ImportPreview,type ImportRows} from '../../packages/domain/src/reference-import-contracts.ts';
import type {ReferenceValue} from '../../packages/domain/src/reference-data-contracts.ts';
const owner='10000000-0000-4000-8000-000000000001',setId='20000000-0000-4000-8000-000000000001';
const base:ImportBase={setId,expectedVersion:1,publicationHash:'a'.repeat(64)};
const fresh:ImportBase={setId,expectedVersion:0,publicationHash:null};
type Mutable<T>={-readonly [K in keyof T]:T[K] extends object?Mutable<T[K]>:T[K]};
const row=(code='A'):Mutable<ReferenceValue>=>({code,labels:{en:{label:'State',description:'English description'},ar:{label:'حالة',description:'وصف الحالة'}},ownerId:owner,status:'active',validFrom:null,validUntil:null});
const json=(values:unknown[])=>JSON.stringify({formatVersion:1,kind:'reference-code-rows',values});
const bytes=(text:string)=>Buffer.from(text,'utf8');
function parsed(input:ImportRows|ImportInvalid):ImportRows{assert.equal(input.state,'parsed',JSON.stringify(input));if(input.state!=='parsed')throw Error('Expected parsed fixture');return input;}
const load=(values:unknown[])=>parsed(parseImportRows(bytes(json(values)),'json'));
function ready(input:ImportPreview){assert.equal(input.state,'ready',JSON.stringify(input));if(input.state!=='ready')throw Error('Expected ready fixture');return input;}
function bad(input:ImportRows|ImportPreview,code?:string){assert.equal(input.state,'invalid');if(input.state!=='invalid')throw Error('Expected refusal');if(code)assert.equal(input.issues[0].code,code);for(const e of input.issues){assert.deepEqual(Object.keys(e).sort(),['code','field','relatedRow','row']);assert.ok(IMPORT_FIELDS.includes(e.field as never)||e.field==='');}return input;}
const encodeCell=(v:string)=>/[",\r\n]/.test(v)?'"'+v.replaceAll('"','""')+'"':v;
function csv(values:ReferenceValue[],newline='\r\n'){return [IMPORT_CSV_HEADERS,...values.map(v=>[v.code,v.labels.en.label,v.labels.en.description,v.labels.ar.label,v.labels.ar.description,v.ownerId,v.status,v.validFrom??'',v.validUntil??''])].map(r=>r.map(encodeCell).join(',')).join(newline)+newline;}

test('JSON returns exact-code sorted detached rows and original-byte provenance',()=>{
 const original=['a','A','1','001','2','10'].map(row),raw=bytes(json(original));
 const result=parsed(parseImportRows(raw,'json'));
 assert.deepEqual(result.values.map(v=>v.code),['001','1','10','2','A','a']);
 assert.equal(result.sourceSha256,createHash('sha256').update(raw).digest('hex'));
 const spaced=parsed(parseImportRows(bytes(' \n'+json(original)+'\t'),'json'));
 assert.deepEqual(spaced.values,result.values);assert.notEqual(spaced.sourceSha256,result.sourceSha256);
 original[0].labels.en.label='Changed';raw.fill(0);
 assert.equal(result.values[5].labels.en.label,'State');assert.ok(Object.isFrozen(result.values[0].labels.en));
});

test('shared row parser preserves existing grammar and normalization',()=>{
 const v=row('001');v.labels.en.label=' Cafe\u0301 ';v.labels.en.description=' first\nsecond\tline ';
 const single=parseReferenceValue(v);assert.ok(single.ok);if(!single.ok)return;
 assert.equal(single.value.labels.en.label,'Café');assert.equal(single.value.labels.en.description,'first\nsecond\tline');
 assert.deepEqual(load([v]).values,[single.value]);
 const release=parseRelease({formatVersion:1,kind:'reference-code-list',labels:row().labels,ownerId:owner,status:'active',activation:{kind:'on-publication'},validUntil:null,values:[v]});
 assert.ok(release.ok);if(release.ok)assert.deepEqual(release.value.values,[single.value]);
 for(const code of [' 001','001 ','=FORMULA','+1','é',''])bad(parseImportRows(bytes(json([row(code)])),'json'),'FORMAT');
});

test('fatal UTF8, BOM and malformed Unicode never turn into replacement data',()=>{
 for(const raw of [new Uint8Array([0xc3,0x28]),new Uint8Array([0xed,0xa0,0x80]),bytes('\ufeff'+json([row()])),bytes(json([{...row(),labels:{...row().labels,en:{label:'\ud800',description:'Valid'}}}]))])bad(parseImportRows(raw,'json'),'FORMAT');
 bad(parseImportRows(new Uint8Array(),'json'),'LIMIT');
 bad(parseImportRows(new Uint8Array(IMPORT_LIMITS.rawBytes+1),'json'),'LIMIT');
});

test('only the supplied byte-view window is parsed and hashed',()=>{
 const raw=bytes(json([row()])),backing=Buffer.concat([bytes('NOT JSON'),raw,bytes('TAIL')]);
 const view=new Uint8Array(backing.buffer,backing.byteOffset+8,raw.length);
 const actual=parsed(parseImportRows(view,'json'));assert.equal(actual.sourceSha256,createHash('sha256').update(raw).digest('hex'));
 const exact=Buffer.concat([raw,Buffer.alloc(IMPORT_LIMITS.rawBytes-raw.length,0x20)]);
 assert.equal(parsed(parseImportRows(exact,'json')).values.length,1);
});

test('hostile byte views cannot invoke getters, iterators, species or proxy traps',()=>{
 let calls=0;const trap=()=>{calls++;throw Error('Must not execute');};
 const proxy=new Proxy(bytes(json([row()])),{get:trap,getPrototypeOf:trap,ownKeys:trap});
 bad(parseImportRows(proxy,'json'));assert.equal(calls,0);
 for(const property of ['buffer','byteLength','constructor']){const raw=bytes(json([row()]));Object.defineProperty(raw,property,{get:trap});bad(parseImportRows(raw,'json'));}
 const raw=bytes(json([row()]));Object.defineProperty(raw,Symbol.iterator,{value:trap});bad(parseImportRows(raw,'json'));
 class Derived extends Uint8Array{}bad(parseImportRows(new Derived(bytes(json([row()]))),'json'));
 bad(parseImportRows(new DataView(new ArrayBuffer(10)) as unknown as Uint8Array,'json'));
 const shared=new Uint8Array(new SharedArrayBuffer(10));bad(parseImportRows(shared,'json'));
 const resize=Reflect.construct(ArrayBuffer,[10,{maxByteLength:20}]) as ArrayBuffer;bad(parseImportRows(new Uint8Array(resize),'json'));
 const detached=new Uint8Array(10);structuredClone(detached.buffer,{transfer:[detached.buffer]});bad(parseImportRows(detached,'json'));
 assert.equal(calls,0);
});

test('duplicate JSON keys including escaped keys are rejected before materialization',()=>{
 const raw=json([row()]);
 const variants=[raw.replace('"formatVersion":1','"formatVersion":1,"formatVersion":1'),raw.replace('"code":"A"','"code":"A","c\\u006fde":"B"'),raw.replace('"label":"State"','"label":"State","label":"Hidden"')];
 for(const source of variants)bad(parseImportRows(bytes(source),'json'),'DUPLICATE');
 const diagnostic=bad(parseImportRows(bytes(variants[1]),'json'));
 assert.deepEqual(diagnostic.issues[0],{code:'DUPLICATE',row:1,field:'code',relatedRow:null});
});

test('closed code-row envelope rejects exports, metadata, wrong kinds and reserved keys',()=>{
 for(const source of [{formatVersion:1,kind:'reference-code-list',values:[row()]},{formatVersion:1,kind:'reference-code-rows',values:[row()],publishedAt:'2026-11-17T00:00:00.000Z'},[row()],{formatVersion:1,kind:'reference-code-rows',values:[{...row(),sourceMetadata:'private'}]}])bad(parseImportRows(bytes(JSON.stringify(source)),'json'));
 for(const key of ['__proto__','constructor','prototype','toJSON']){
  const value=JSON.parse(json([row()]));Object.defineProperty(value.values[0],key,{value:'private',enumerable:true});bad(parseImportRows(bytes(JSON.stringify(value)),'json'));
 }
 bad(parseImportRows(bytes(json([row()])),'yaml' as 'json'));
});

test('CSV RFC4180 multiline, doubled quotes and exact strings share JSON row normalization',()=>{
 const v=row('001');v.labels.en.description='First, "quoted"\r\nSecond\nThird';v.labels.ar.description='أول\nثان';
 for(const newline of ['\r\n','\n'])assert.deepEqual(parsed(parseImportRows(bytes(csv([v],newline)),'csv')).values,load([v]).values);
 const withoutTerminator=csv([v]).slice(0,-2);assert.deepEqual(parsed(parseImportRows(bytes(withoutTerminator),'csv')).values,load([v]).values);
 const literal=row('A');literal.labels.en.label='=SUM(A1:A2)';assert.equal(parsed(parseImportRows(bytes(csv([literal])),'csv')).values[0].labels.en.label,'=SUM(A1:A2)');
});

test('CSV closed ordered header refuses duplicates, reordered/historical columns and extra cells',()=>{
 const good=csv([row()]),header=IMPORT_CSV_HEADERS.join(',');
 for(const h of [header.replace('label_en','code'),header.replace('code,label_en','label_en,code'),header+',published_at','format_version,kind,set_id,version,set_labels_json'])bad(parseImportRows(bytes(good.replace(header,h)),'csv'),'FIELDS');
 bad(parseImportRows(bytes(good.trimEnd()+',extra\r\n'),'csv'),'FIELDS');
 bad(parseImportRows(bytes(header+'\nA,Label\n'),'csv'),'FIELDS');
});

test('CSV malformed quotes, blank records, standalone CR and postquote junk refuse whole input',()=>{
 const header=IMPORT_CSV_HEADERS.join(',')+'\n';
 for(const text of ['"A','A"B,x','"A"junk,x','A\rB','\n',csv([row()])+'\n'])bad(parseImportRows(bytes(text.startsWith('code,')?text:header+text),'csv'));
 const v=row();v.validFrom='null';bad(parseImportRows(bytes(csv([v])),'csv'),'FORMAT');
 const empty=csv([row()]).replace(',active,',',,');bad(parseImportRows(bytes(empty),'csv'),'FORMAT');
});

test('exact duplicate rows report first related logical row without deduplication',()=>{
 const rows=[row('B'),row('A'),row('B')];rows[0].labels.en.description='First\nSecond';
 for(const [format,raw] of [['json',json(rows)],['csv',csv(rows)]] as const){
  const actual=bad(parseImportRows(bytes(raw),format),'DUPLICATE');assert.deepEqual(actual.issues,[{code:'DUPLICATE',row:3,field:'code',relatedRow:1}]);
 }
 assert.equal(load([row('A'),row('a'),row('001'),row('1')]).values.length,4);
});

test('row limit is checked before duplicate reduction and issues are explicitly truncated',()=>{
 const good=Array.from({length:256},(_,i)=>row(String(i).padStart(3,'0')));assert.equal(load(good).values.length,256);
 for(const format of ['json','csv'] as const){const source=format==='json'?json(Array.from({length:257},()=>row())):csv(Array.from({length:257},()=>row()));bad(parseImportRows(bytes(source),format),'LIMIT');}
 const malformedRows=Array.from({length:256},()=>({...row(),ownerId:'private-not-uuid'}));
 const result=bad(parseImportRows(bytes(json(malformedRows)),'json'));assert.equal(result.issues.length,128);assert.equal(result.issuesTruncated,true);assert.ok(!JSON.stringify(result).includes('private-not-uuid'));
});

test('all existing row bounds and interval rules apply before normalization can hide invalid data',()=>{
 const variants=[{...row(),ownerId:'00000000-0000-0000-0000-000000000000'},{...row(),status:'ACTIVE'},{...row(),validFrom:'2026-02-30T00:00:00.000Z'},{...row(),validUntil:'2026-11-17T00:00:00Z'},{...row(),validFrom:'2026-11-18T00:00:00.000Z',validUntil:'2026-11-18T00:00:00.000Z'}];
 for(const v of variants)bad(parseImportRows(bytes(json([v])),'json'));
 for(const label of [' '.repeat(240)+'X','\tState','\u0000State','\udfff',''])bad(parseImportRows(bytes(json([{...row(),labels:{...row().labels,en:{label,description:'Description'}}}])),'json'));
 const v=row();v.labels.en.description=' '.repeat(2048)+'X';bad(parseImportRows(bytes(json([v])),'json'),'FORMAT');
});

test('aggregate value budget refuses a small-enough raw file when normalized rows exceed release budget',()=>{
 const values=Array.from({length:62},(_,i)=>{const v=row(String(i));v.labels.en.description='X'.repeat(1900);v.labels.ar.description='Y'.repeat(1900);return v;});
 const raw=bytes(json(values));assert.ok(raw.length<IMPORT_LIMITS.rawBytes);bad(parseImportRows(raw,'json'),'LIMIT');
});

test('merge has full-row replacement, complete exact-code diff and stable untouched rows',()=>{
 const a=row('A'),b=row('B');const changed={...b,ownerId:'10000000-0000-4000-8000-000000000002',status:'deprecated' as const,validFrom:'2026-11-17T00:00:00.000Z',validUntil:'2026-11-18T00:00:00.000Z',labels:{en:{label:'Changed',description:'Other'},ar:{label:'جديد',description:'وصف آخر'}}};
 const result=ready(reconcileImport(base,[a,b],'merge',load([row('C'),changed])));
 assert.deepEqual(result.values,[a,changed,row('C')]);assert.deepEqual(result.counts,{added:1,changed:1,removed:0,unchanged:1});
 assert.deepEqual(result.changes.map(v=>[v.code,v.kind]),[['A','unchanged'],['B','changed'],['C','added']]);
 assert.deepEqual(result.changes[1].changedFields,IMPORT_FIELDS.filter(f=>f!=='code'));
 assert.deepEqual(result.changes[0].changedFields,[]);assert.equal(result.changes[2].before,null);assert.deepEqual(result.changes[2].changedFields,IMPORT_FIELDS);
 a.labels.en.label='Later';assert.equal(result.values[0].labels.en.label,'State');assert.ok(Object.isFrozen(result.changes[1].before!.labels));
});

test('replace explicitly lists every removal, with no unchanged baseline silently merged',()=>{
 const result=ready(reconcileImport(base,[row('A'),row('B')],'replace',load([row('B'),row('C')])));
 assert.deepEqual(result.values,[row('B'),row('C')]);assert.deepEqual(result.counts,{added:1,changed:0,removed:1,unchanged:1});
 assert.deepEqual(result.changes[0],{code:'A',kind:'removed',before:row('A'),after:null,changedFields:IMPORT_FIELDS});
 const newSet=ready(reconcileImport(fresh,[],'merge',load([row()])));assert.deepEqual(newSet.counts,{added:1,changed:0,removed:0,unchanged:0});
});

test('complete reconciliation reaches exact 512-change bound while merge beyond256 refuses',()=>{
 const previous=Array.from({length:256},(_,i)=>row('A'+String(i).padStart(3,'0'))),incoming=Array.from({length:256},(_,i)=>row('B'+String(i).padStart(3,'0')));
 const result=ready(reconcileImport(base,previous,'replace',load(incoming)));assert.equal(result.changes.length,512);assert.deepEqual(result.counts,{added:256,changed:0,removed:256,unchanged:0});
 bad(reconcileImport(base,previous,'merge',load([row('New')])),'LIMIT');
 assert.ok(Buffer.byteLength(JSON.stringify(result))<=IMPORT_LIMITS.responseBytes);
});

test('untrusted baseline must be complete canonical sorted unique values',()=>{
 const incoming=load([row('C')]);
 for(const baseline of [null,{},[],[row('B'),row('A')],[row('A'),row('A')],[{...row(),labels:{...row().labels,en:{label:' State ',description:'Description'}}}],[{...row(),source:'ignored'}]])bad(reconcileImport(base,baseline,'merge',incoming));
 bad(reconcileImport(fresh,[row()],'merge',incoming));
});

test('all callable envelopes reject extras, stale-shaped pins and noncanonical parsed rows',()=>{
 const incoming=load([row()]);
 for(const b of [{...base,setId:'invalid'},{...base,expectedVersion:0},{...base,publicationHash:null},{...base,expectedVersion:2147483647},{...base,expectedVersion:1.5},{...base,extra:'private'}])bad(reconcileImport(b as ImportBase,[row()],'merge',incoming));
 for(const r of [{...incoming,state:'ready'},{...incoming,sourceSha256:'A'.repeat(64)},{...incoming,extra:1},{...incoming,values:[row('B'),row('A')]},{...incoming,values:[row('A'),row('A')]}])bad(reconcileImport(base,[row()],'merge',r as ImportRows));
 bad(reconcileImport(base,[row()],'upsert' as 'merge',incoming));
});

test('callable getters, proxies, symbols, inherited setters and cyclic inputs cannot execute',()=>{
 let calls=0;const trap=()=>{calls++;throw new Proxy({}, {get:()=>{calls++;throw Error('Never inspect thrown data');}});};
 const incoming=load([row()]);const hostile=new Proxy({}, {get:trap,getPrototypeOf:trap,ownKeys:trap});
 bad(reconcileImport(hostile as ImportBase,[row()],'merge',incoming));bad(reconcileImport(base,hostile,'merge',incoming));
 const accessor={...row()};Object.defineProperty(accessor,'ownerId',{get:trap,enumerable:true});bad(reconcileImport(base,[accessor],'merge',incoming));
 const symbol={...row(),[Symbol('hidden')]:1};bad(reconcileImport(base,[symbol],'merge',incoming));
 const cycle:unknown[]=[];cycle.push(cycle);bad(reconcileImport(base,cycle,'merge',incoming));
 const custom=Object.create({get code(){return trap();}});bad(reconcileImport(base,[custom],'merge',incoming));
 assert.equal(calls,0);
 Object.defineProperty(Object.prototype,'unrelatedInheritedSetter',{set:trap,configurable:true});
 try{assert.equal(ready(reconcileImport(base,[row()],'merge',incoming)).counts.unchanged,1);}finally{delete (Object.prototype as Record<string,unknown>).unrelatedInheritedSetter;}
 assert.equal(calls,0);
});

test('inputs and outputs stay immutable and previews remain deterministic without authority claims',()=>{
 const baseline=[row()],incoming=load([row('B')]),before=JSON.stringify({base,baseline,incoming});
 const a=ready(reconcileImport(base,baseline,'replace',incoming)),b=ready(reconcileImport(base,baseline,'replace',incoming));
 assert.deepEqual(a,b);assert.equal(JSON.stringify({base,baseline,incoming}),before);
 assert.deepEqual(Object.keys(a).sort(),['base','changes','counts','mode','sourceSha256','state','values']);
 assert.ok(Object.isFrozen(a)&&Object.isFrozen(a.base)&&Object.isFrozen(a.counts));
});
