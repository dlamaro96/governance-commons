// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import {parseApprovalDefinition} from '../../packages/domain/src/approval.ts';
import {parseRelease} from '../../packages/domain/src/reference-data.ts';

const approval=()=>({formatVersion:1,id:'review',version:1,name:'Review',separationOfDuties:true,stages:[{id:'review',name:'Review',assignments:['reviewer'],quorum:1,deadlineSeconds:60,rejection:'any'}]});
const labels=()=>({en:{label:'Status',description:'Exact code.'},ar:{label:'حالة',description:'وصف الحالة'}});
const reference=()=>({formatVersion:1,kind:'reference-code-list',labels:labels(),ownerId:'10000000-0000-4000-8000-000000000001',status:'active',activation:{kind:'on-publication'},validUntil:null,values:[{code:'001',labels:labels(),ownerId:'10000000-0000-4000-8000-000000000001',status:'active',validFrom:null,validUntil:null}]});
const parsers=[{build:approval,parse:parseApprovalDefinition},{build:reference,parse:parseRelease}] as const;

test('snapshot construction retains array order and returns detached immutable approved shapes',()=>{
 const a=approval();a.stages[0].assignments=['first','second'];const parsed=parseApprovalDefinition(a);assert.equal(parsed.ok,true);if(!parsed.ok)throw Error('Expected approval');
 assert.deepEqual(parsed.value.stages[0].assignments,['first','second']);a.stages[0].assignments.reverse();assert.deepEqual(parsed.value.stages[0].assignments,['first','second']);assert.ok(Object.isFrozen(parsed.value.stages[0].assignments));
 const r=reference(),out=parseRelease(r);assert.equal(out.ok,true);if(!out.ok)throw Error('Expected reference');r.values[0].labels.en.label='Changed';assert.equal(out.value.values[0].labels.en.label,'Status');assert.ok(Object.isFrozen(out.value.values[0].labels.en));
});

test('prototype and serializer key payloads at nested object boundaries reject without pollution',()=>{
 for(const parser of parsers)for(const key of ['__proto__','constructor','prototype','toJSON']){
  const value=parser.build();Object.defineProperty(value,key,{value:{polluted:'injected'},enumerable:true,writable:true,configurable:true});
  assert.equal(parser.parse(value).ok,false,key);assert.equal(Object.hasOwn(Object.prototype,'polluted'),false);
 }
 const a=approval();Object.defineProperty(a.stages[0],'__proto__',{value:{polluted:'nested'},enumerable:true});assert.equal(parseApprovalDefinition(a).ok,false);
 const r=reference();Object.defineProperty(r.values[0].labels.en,'constructor',{value:{prototype:{polluted:'nested'}},enumerable:true});assert.equal(parseRelease(r).ok,false);assert.equal(Object.hasOwn(Object.prototype,'polluted'),false);
});

test('snapshot rejects accessors and callable own serializer without executing user code',()=>{
 for(const parser of parsers){
  let calls=0;const accessor=parser.build();Object.defineProperty(accessor,'name',{enumerable:true,get(){calls++;throw Error('getter executed');}});assert.equal(parser.parse(accessor).ok,false);assert.equal(calls,0);
  const custom=parser.build();Object.defineProperty(custom,'toJSON',{enumerable:true,value(){calls++;throw Error('toJSON executed');}});assert.equal(parser.parse(custom).ok,false);assert.equal(calls,0);
 }
});

test('null-prototype request records parse while inherited serializer hooks remain ignored',()=>{
 for(const parser of parsers){const value=Object.assign(Object.create(null),parser.build());const out=parser.parse(value);assert.equal(out.ok,true);}
 let calls=0;Object.defineProperty(Object.prototype,'toJSON',{configurable:true,value(){calls++;throw Error('inherited serializer executed');}});
 try{const r=parseRelease(Object.assign(Object.create(null),reference()));assert.equal(r.ok,true);assert.equal(calls,0);}
 finally{delete (Object.prototype as {toJSON?:unknown}).toJSON;}
});

test('sparse arrays, added array keys and symbol properties retain closed JSON refusal',()=>{
 for(const parser of parsers){const v=parser.build();Object.defineProperty(v,Symbol('hidden'),{value:'value',enumerable:true});assert.equal(parser.parse(v).ok,false);}
 const a=approval();delete (a.stages as (unknown|undefined)[])[0];assert.equal(parseApprovalDefinition(a).ok,false);
 const r=reference();Object.defineProperty(r.values,'extra',{value:'value',enumerable:true});assert.equal(parseRelease(r).ok,false);
});

test('reference snapshot rejects proxies without inspecting their traps',()=>{
 let calls=0;const proxy=new Proxy(reference(),{ownKeys(){calls++;throw Error('trap');},getPrototypeOf(){calls++;throw Error('trap');}});assert.equal(parseRelease(proxy).ok,false);assert.equal(calls,0);
});
