// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {Value} from '@sinclair/typebox/value';
import {Problem} from '../../packages/authz/src/index.ts';
import {parseDomainRequestJSON,checkDomainData} from '../../apps/api/src/business-domain-http.ts';
import {parseApprovalRequestJSON,approvalHttp} from '../../apps/api/src/approvals.ts';
import {parseGlossaryPublication} from '../../packages/domain/src/glossary.ts';

const id='10000000-0000-4000-8000-000000000001';
const map=(count:number)=>Object.fromEntries(Array.from({length:count},(_,index)=>['reviewer_'+index,id]));
const denied=(error:unknown)=>error instanceof Problem&&error.status===400;
const publication=()=>({typePin:{typeId:id,modelId:'business_term',version:1,definitionHash:'a'.repeat(64),resolutionHash:'b'.repeat(64)},
 primaryLocale:'en',ownerId:id,visibility:'tenant',allowedIdentityIds:[],state:'active',attributes:{translations:[{locale:'en',name:'Synthetic term',definition:'Synthetic meaning.',synonyms:[],abbreviations:[],examples:[]}]},links:[]});
const proposal=()=>({requestId:id,resourceId:id,resourceVersion:null,publication:publication(),workflowPin:{id:'review',version:1,definitionHash:'c'.repeat(64)},
 assignments:{owner:id},expiresAt:'2026-11-17T00:00:00.000Z'});

test('glossary ingress admits the complete 256-key root assignment map without expanding any other object or route',()=>{
 const full={assignments:map(256)};
 assert.deepEqual(parseDomainRequestJSON(JSON.stringify(full),'glossary-proposal'),full);
 checkDomainData(full,'glossary-proposal');
 assert.throws(()=>parseDomainRequestJSON(JSON.stringify(full)),denied);assert.throws(()=>checkDomainData(full),denied);
 for(const value of [{assignments:map(257)},{other:map(129)},{nested:{assignments:map(129)}},{assignments:{nested:map(129)}},{assignments:[map(129)]},map(129)]){
  assert.throws(()=>parseDomainRequestJSON(JSON.stringify(value),'glossary-proposal'),denied);
  assert.throws(()=>checkDomainData(value,'glossary-proposal'),denied);
 }
 const boundary={other:map(128),assignments:map(256)};
 assert.deepEqual(parseDomainRequestJSON(JSON.stringify(boundary),'glossary-proposal'),boundary);checkDomainData(boundary,'glossary-proposal');
});

test('assignment exception retains duplicate, reserved-key, accessor and profile rejection without executing input',()=>{
 for(const raw of ['{"assignments":{"owner":1,"owne\\u0072":2}}','{"assignments":{},"assignments":{}}','{"assignments":{"constructor":true}}','{"assignments":{"owner":"\\ud800"}}'])
  assert.throws(()=>parseDomainRequestJSON(raw,'glossary-proposal'),denied);
 let reads=0;const accessor=Object.defineProperty({},'assignments',{enumerable:true,get(){reads++;return map(256);}});
 assert.throws(()=>checkDomainData(accessor,'glossary-proposal'),denied);
 const nested=Object.defineProperty(map(255),'last',{enumerable:true,get(){reads++;return id;}});
 assert.throws(()=>checkDomainData({assignments:nested},'glossary-proposal'),denied);assert.equal(reads,0);
 for(const profile of ['unknown',null,true]){
  assert.throws(()=>parseDomainRequestJSON('{}',profile as never),denied);
  assert.throws(()=>checkDomainData({},profile as never),denied);
 }
});

test('glossary wire schema is closed at every authored boundary while preserving typed custom attributes for pinned validation',()=>{
 const value=proposal();
 Object.assign(value.publication.attributes,{custom:{amount:'9007199254740993.25',flags:[true,false]}});
 const before=JSON.stringify(value);assert.equal(Value.Check(approvalHttp.glossaryProposal,value),true);assert.equal(JSON.stringify(value),before);
 for(const changed of [{...value,extra:true},{...value,resourceVersion:'1'},{...value,workflowPin:{...value.workflowPin,extra:true}},
  {...value,assignments:{owner:1}},{...value,assignments:{}},{...value,assignments:map(257)},
  {...value,publication:{...value.publication,extra:true}},
  {...value,publication:{...value.publication,typePin:{...value.publication.typePin,extra:true}}},
  {...value,publication:{...value.publication,attributes:{translations:[{...value.publication.attributes.translations[0],extra:true}]}}},
  {...value,publication:{...value.publication,links:[{kind:'defines',typePin:{relationTypeId:id,version:1,definitionHash:'a'.repeat(64),extra:true},targetAssetId:id,targetAssetVersion:1}]}}])
  assert.equal(Value.Check(approvalHttp.glossaryProposal,changed),false);
 assert.equal(Value.Check(approvalHttp.glossaryProposal,{...value,assignments:map(256)}),true);
 const locale='en-abcde-bcdef-cdefg-defgh-efghi-fghij-ghijk-hijkl-ijklm-jklmn-klmno';
 assert.ok(locale.length>64);assert.equal(Intl.getCanonicalLocales(locale)[0],locale);
 const multilingual=proposal();multilingual.publication.primaryLocale=locale;multilingual.publication.attributes.translations[0].locale=locale;
 assert.ok(parseGlossaryPublication(multilingual.publication).ok);assert.equal(Value.Check(approvalHttp.glossaryProposal,multilingual),true);
});

test('glossary envelope uses its finite 320 KiB ingress cap while ordinary approval routes retain 96 KiB',()=>{
 const value=proposal();Object.assign(value.publication.attributes,{first:'x'.repeat(40_000),second:'y'.repeat(40_000),third:'z'.repeat(40_000)});
 const raw=JSON.stringify(value);assert.ok(Buffer.byteLength(raw)>98_304);assert.ok(parseGlossaryPublication(value.publication).ok);
 assert.deepEqual(parseApprovalRequestJSON(raw,327_680),value);assert.throws(()=>parseApprovalRequestJSON(raw),denied);
 const full={...value,assignments:map(256)};assert.deepEqual(parseApprovalRequestJSON(JSON.stringify(full),327_680),full);
 for(const maximum of [98_304,327_680] as const){
  const exact='{}'.padEnd(maximum,' ');assert.deepEqual(parseApprovalRequestJSON(exact,maximum),{});
  assert.throws(()=>parseApprovalRequestJSON(exact+' ',maximum),denied);
 }
 assert.throws(()=>parseApprovalRequestJSON('{}',1_048_576 as never),denied);
});
