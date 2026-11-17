// SPDX-License-Identifier: Apache-2.0
// Advisory reconciliation only: source digests and parsed values establish no authority.
import {createHash} from 'node:crypto';
import {types} from 'node:util';
import {parseBoundedJSONEnvelope} from './model.ts';
import {parseReferenceValue} from './reference-data.ts';
import {LIMITS,type ReferenceValue} from './reference-data-contracts.ts';
import {IMPORT_CSV_HEADERS,IMPORT_FIELDS,IMPORT_LIMITS,type ImportBase,type ImportField,type ImportFormat,type ImportInvalid,
 type ImportIssue,type ImportMode,type ImportPreview,type ImportReady,type ImportRows,type ValueChange} from './reference-import-contracts.ts';

type Json=null|boolean|number|string|Json[]|{[key:string]:Json};
const malformed=/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const digest=/^[0-9a-f]{64}$/;
const reserved=new Set(['__proto__','prototype','constructor','toJSON']);
const compare=(a:string,b:string)=>a<b?-1:a>b?1:0;
const ownFailures=new WeakMap<object,ImportIssue>();
const issue=(code:ImportIssue['code'],row:number|null=null,field:ImportIssue['field']='',relatedRow:number|null=null):ImportIssue=>({code,row,field,relatedRow});
function fail(code:ImportIssue['code'],row:number|null=null,field:ImportIssue['field']=''):never{const marker=Object.freeze(Object.create(null));ownFailures.set(marker,issue(code,row,field));throw marker;}
function need(condition:unknown,code:ImportIssue['code']='FORMAT',row:number|null=null,field:ImportIssue['field']=''):asserts condition{if(!condition)fail(code,row,field);}
function freeze<T>(value:T):T{if(value!==null&&typeof value==='object'){for(const child of Object.values(value))freeze(child);Object.freeze(value);}return value;}
const invalid=(issues:readonly ImportIssue[],issuesTruncated=false):ImportInvalid=>freeze({state:'invalid',issues,issuesTruncated});
function guarded<T>(work:()=>T):T|ImportInvalid{try{return work();}catch(error){return invalid([ownFailures.get(error as object)??issue('FORMAT')]);}}

/** Never call user iterators, getters, coercions, toJSON or species constructors.
 * Shared/resizable buffers cannot provide a stable caller-owned byte snapshot. */
function byteSnapshot(input:unknown):Uint8Array {
 need(input!==null&&typeof input==='object'&&!types.isProxy(input)&&types.isUint8Array(input));
 const prototype=Object.getPrototypeOf(input);need(prototype===Uint8Array.prototype||prototype===Buffer.prototype);
 const typed=Object.getPrototypeOf(Uint8Array.prototype);
 const get=(key:string)=>Reflect.apply(Object.getOwnPropertyDescriptor(typed,key)!.get!,input,[]);
 const length=get('byteLength') as number,offset=get('byteOffset') as number,buffer=get('buffer') as ArrayBuffer;
 need(length>0&&length<=IMPORT_LIMITS.rawBytes,'LIMIT');
 need(!types.isSharedArrayBuffer(buffer)&&types.isArrayBuffer(buffer));
 const resizable=Object.getOwnPropertyDescriptor(ArrayBuffer.prototype,'resizable')?.get;
 need(!resizable||!Reflect.apply(resizable,buffer,[]));
 const keys=Reflect.ownKeys(input);need(keys.length===length);
 for(let index=0;index<length;index++){
  need(keys[index]===String(index));const d=Object.getOwnPropertyDescriptor(input,String(index));
  need(d?.enumerable&&Object.hasOwn(d,'value'));
 }
 const out=new Uint8Array(length);Uint8Array.prototype.set.call(out,new Uint8Array(buffer,offset,length));return out;
}

/** One bounded detached snapshot covers callable base, baseline and parsed rows.
 * Reflective checks precede every read; owned tuple materialization avoids setters. */
function snapshot(input:unknown):Json {
 let nodes=0,bytes=0;const active=new Set<object>();
 const charge=(n:number)=>{bytes+=n;need(bytes<=IMPORT_LIMITS.responseBytes,'LIMIT');};
 function text(value:string){need(value.length<=LIMITS.stringUtf16&&!malformed.test(value),'FORMAT');charge(Buffer.byteLength(JSON.stringify(value),'utf8'));return value;}
 function copy(value:unknown,depth:number):Json {
  need(++nodes<=LIMITS.nodes&&depth<=LIMITS.depth,'LIMIT');
  if(value===null){charge(4);return null;}if(typeof value==='string')return text(value);
  if(typeof value==='boolean'){charge(value?4:5);return value;}
  if(typeof value==='number'){need(Number.isFinite(value)&&!Object.is(value,-0));charge(String(value).length);return value;}
  need(typeof value==='object'&&!types.isProxy(value));need(!active.has(value));
  const array=Array.isArray(value),prototype=Object.getPrototypeOf(value);
  need(array?prototype===Array.prototype:prototype===Object.prototype||prototype===null);
  const keys=Reflect.ownKeys(value),length=array?Object.getOwnPropertyDescriptor(value,'length')?.value:keys.length;
  need(Number.isInteger(length)&&length>=0&&length<=(array?IMPORT_LIMITS.rows:LIMITS.properties),'LIMIT');
  need(!array||keys.length===length+1);charge(2+Math.max(0,length-1));active.add(value);
  try{
   const entries:[string,Json][]=[],items:Json[]=[];
   for(const key of array?Array.from({length},(_,i)=>String(i)):keys){
    need(typeof key==='string'&&key.length<=256&&!reserved.has(key));const d=Object.getOwnPropertyDescriptor(value,key);
    need(d?.enumerable&&Object.hasOwn(d,'value'));
    if(!array){text(key);charge(1);}const child=copy(d.value,depth+1);
    if(array)items.push(child);else entries.push([key,child]);
   }
   return array?items:Object.fromEntries(entries);
  }finally{active.delete(value);}
 }
 return copy(input,0);
}
function fields(value:Json,keys:readonly string[]):Record<string,Json>{need(value!==null&&typeof value==='object'&&!Array.isArray(value),'FIELDS');need(Object.keys(value).length===keys.length&&keys.every(k=>Object.hasOwn(value,k)),'FIELDS');return value;}
function canonical(value:unknown):string {
 if(value===null||typeof value!=='object')return JSON.stringify(value);
 if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
 return '{'+Object.keys(value).sort(compare).map(k=>JSON.stringify(k)+':'+canonical((value as Record<string,unknown>)[k])).join(',')+'}';
}
function safeField(path:string):ImportIssue['field'] {const field=path.replace(/^\//,'').replaceAll('/','.');return (IMPORT_FIELDS as readonly string[]).includes(field)?field as ImportField:'';}
function issueCode(code:string):ImportIssue['code']{return code==='DUPLICATE'||code==='INTERVAL'||code==='LIMIT'||code==='FIELDS'?code:'FORMAT';}

function csv(text:string):Json[] {
 const records:string[][]=[];let row:string[]=[],cell='',quoted=false,closed=false,started=false;
 const finishCell=()=>{row.push(cell);cell='';closed=false;need(row.length<=IMPORT_CSV_HEADERS.length,'FIELDS',records.length||null);};
 const finishRow=()=>{finishCell();records.push(row);row=[];started=false;need(records.length<=IMPORT_LIMITS.rows+1,'LIMIT');};
 for(let i=0;i<text.length;i++){
  const c=text[i];started=true;
  if(quoted){if(c==='"'){if(text[i+1]==='"'){cell+='"';i++;}else{quoted=false;closed=true;}}else cell+=c;}
  else if(c==='"'){need(!closed&&cell.length===0,'FORMAT',records.length||null);quoted=true;}
  else if(c===','){finishCell();}
  else if(c==='\n'||c==='\r'){
   if(c==='\r'){need(text[i+1]==='\n','FORMAT',records.length||null);i++;}finishRow();
  }else{need(!closed,'FORMAT',records.length||null);cell+=c;}
  need(cell.length<=LIMITS.stringUtf16,'LIMIT',records.length||null);
 }
 need(!quoted,'FORMAT',records.length||null);if(started||row.length||cell.length||closed)finishRow();
 need(records.length>=2,'LIMIT');const headers=records.shift()!;
 need(headers.length===IMPORT_CSV_HEADERS.length&&headers.every((v,i)=>v===IMPORT_CSV_HEADERS[i]),'FIELDS');
 return records.map((r,index)=>{
  need(r.length===IMPORT_CSV_HEADERS.length,'FIELDS',index+1);
  return {code:r[0],labels:{en:{label:r[1],description:r[2]},ar:{label:r[3],description:r[4]}},ownerId:r[5],status:r[6],validFrom:r[7]===''?null:r[7],validUntil:r[8]===''?null:r[8]};
 });
}
function validateRows(input:Json,requireCanonical=false):ReferenceValue[]|ImportInvalid {
 need(Array.isArray(input)&&input.length>=1&&input.length<=IMPORT_LIMITS.rows,'LIMIT');
 const issues:ImportIssue[]=[],values:ReferenceValue[]=[],seen=new Map<string,number>();let truncated=false;
 const add=(i:ImportIssue)=>{if(issues.length<IMPORT_LIMITS.issues)issues.push(i);else truncated=true;};
 for(let index=0;index<input.length;index++){
  const row=input[index],number=index+1;
  // Check duplicate exact keys before row validation, never silently deduplicate.
  if(row!==null&&typeof row==='object'&&!Array.isArray(row)&&typeof row.code==='string'){
   const prior=seen.get(row.code);if(prior!==undefined)add(issue('DUPLICATE',number,'code',prior));else seen.set(row.code,number);
  }
  const parsed=parseReferenceValue(row);
  if(!parsed.ok){for(const e of parsed.issues)add(issue(issueCode(e.code),number,safeField(e.path)));}
  else if(requireCanonical&&canonical(row)!==canonical(parsed.value))add(issue('FORMAT',number));
  else values.push(parsed.value);
 }
 if(issues.length)return invalid(issues,truncated);
 values.sort((a,b)=>compare(a.code,b.code));
 if(requireCanonical)need(canonical(input)===canonical(values));
 // The complete release's metadata, principal union and envelope are validated again at proposal submission.
 need(Buffer.byteLength(canonical(values),'utf8')<=LIMITS.releaseBytes,'LIMIT');return values;
}

export function parseImportRows(raw:Uint8Array,format:ImportFormat):ImportRows|ImportInvalid{return guarded(()=>{
 need(format==='json'||format==='csv');const bytes=byteSnapshot(raw);
 need(!(bytes[0]===0xef&&bytes[1]===0xbb&&bytes[2]===0xbf));
 const text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);let rows:Json;
 if(format==='csv')rows=csv(text);
 else{
  const parsed=parseBoundedJSONEnvelope(text);
  if(!parsed.ok){
   const issues=parsed.issues.map(e=>{const path=/^\/values\/(0|[1-9][0-9]*)(\/.*)?$/.exec(e.path);return issue(e.code==='duplicate'?'DUPLICATE':e.code==='limit'?'LIMIT':'FORMAT',path&&Number(path[1])<IMPORT_LIMITS.rows?Number(path[1])+1:null,path?safeField(path[2]??''):'');});
   return invalid(issues.slice(0,IMPORT_LIMITS.issues),issues.length>IMPORT_LIMITS.issues||parsed.issues.some(e=>e.message==='Further validation issues were omitted.'));
  }
  const envelope=fields(snapshot(parsed.value),['formatVersion','kind','values']);
  need(envelope.formatVersion===1&&envelope.kind==='reference-code-rows');rows=envelope.values;
 }
 const values=validateRows(rows);if(!Array.isArray(values))return values;
 return freeze({state:'parsed' as const,sourceSha256:createHash('sha256').update(bytes).digest('hex'),values});
});}

export function reconcileImport(base:ImportBase,baseline:unknown,mode:ImportMode,rows:ImportRows):ImportPreview{return guarded(()=>{
 const input=fields(snapshot({base,baseline,mode,rows}),['base','baseline','mode','rows']);
 const b=fields(input.base,['setId','expectedVersion','publicationHash']);
 need(typeof b.setId==='string'&&uuid.test(b.setId)&&b.setId!=='00000000-0000-0000-0000-000000000000');
 need(typeof b.expectedVersion==='number'&&Number.isInteger(b.expectedVersion)&&b.expectedVersion>=0&&b.expectedVersion<LIMITS.version);
 need(b.expectedVersion===0?b.publicationHash===null:typeof b.publicationHash==='string'&&digest.test(b.publicationHash));
 need(input.mode==='merge'||input.mode==='replace');const p=fields(input.rows,['state','sourceSha256','values']);
 need(p.state==='parsed'&&typeof p.sourceSha256==='string'&&digest.test(p.sourceSha256));
 const incoming=validateRows(p.values,true);if(!Array.isArray(incoming))return incoming;
 let previous:ReferenceValue[];
 if(b.expectedVersion===0){need(Array.isArray(input.baseline)&&input.baseline.length===0);previous=[];}
 else{const parsed=validateRows(input.baseline,true);if(!Array.isArray(parsed))return parsed;previous=parsed;}
 const before=new Map(previous.map(v=>[v.code,v]));
 const after=new Map((input.mode==='merge'?previous:[]).map(v=>[v.code,v]));for(const v of incoming)after.set(v.code,v);
 need(after.size>=1&&after.size<=IMPORT_LIMITS.rows,'LIMIT');const values=[...after.values()].sort((a,b)=>compare(a.code,b.code));
 need(Buffer.byteLength(canonical(values),'utf8')<=LIMITS.releaseBytes,'LIMIT');
 const counts={added:0,changed:0,removed:0,unchanged:0};const changes:ValueChange[]=[];
 const fieldValue=(v:ReferenceValue,f:ImportField)=>f.startsWith('labels.')?v.labels[f.split('.')[1] as 'en'|'ar'][f.split('.')[2] as 'label'|'description']:v[f as Exclude<ImportField,`labels.${string}`>];
 for(const code of [...new Set([...before.keys(),...after.keys()])].sort(compare)){
  const old=before.get(code)??null,next=after.get(code)??null;
  const changedFields=old&&next?IMPORT_FIELDS.filter(f=>fieldValue(old,f)!==fieldValue(next,f)):[...IMPORT_FIELDS];
  const kind=!old?'added':!next?'removed':changedFields.length?'changed':'unchanged';counts[kind]++;
  changes.push({code,kind,before:old,after:next,changedFields});
 }
 need(changes.length<=IMPORT_LIMITS.changes,'LIMIT');
 const result:ImportReady={state:'ready',base:{setId:b.setId,expectedVersion:b.expectedVersion,publicationHash:b.publicationHash as string|null},mode:input.mode,sourceSha256:p.sourceSha256,values,changes,counts};
 need(Buffer.byteLength(canonical(result),'utf8')<=IMPORT_LIMITS.responseBytes,'LIMIT');return freeze(result);
});}
