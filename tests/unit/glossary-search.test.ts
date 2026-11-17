// SPDX-License-Identifier: Apache-2.0
/** Pure projection and mapping protocol checks; native indexing is separate. */
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {assetSearchDocument,initializeSearchIndex} from '../../apps/api/src/search.ts';
const id=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
function fixture(){
 const payload={typePin:{typeId:id(3),modelId:'business_term',version:1,definitionHash:'a'.repeat(64),resolutionHash:'b'.repeat(64)},primaryLocale:'en',ownerId:id(4),visibility:'tenant',allowedIdentityIds:[],state:'active',
  attributes:{translations:[{locale:'en',name:'Revenue',definition:'Approved income.',synonyms:['Turnover'],abbreviations:['REV'],examples:['Quarterly amount.']},
   {locale:'ar',name:'الإيرادات',definition:'دخل معتمد.',synonyms:['الدخل'],abbreviations:['إر'],examples:['مبلغ ربع سنوي.']}]},links:[]};
 const asset={tenant_id:id(1),id:id(2),source_id:null,type:'business_term',version:2,model_id:'business_term',model_version:1,owner_id:id(4),visibility:'tenant',allowed_identities:[],type_state:'active',
  name:'Revenue',qualified_name:'glossary.revenue',description:'Approved income.',attributes:payload.attributes,status:'active'};
 return {asset,payload,publication:{asset_id:asset.id,asset_version:2,state:'sealed',payload}};
}
const refused=(e:unknown)=>!!e&&typeof e==='object'&&'code'in e&&e.code==='SEARCH_UNAVAILABLE';
test('approved own translations aliases abbreviations and examples project without related target context',()=>{
 const f=fixture();f.payload.links.push({kind:'defines',typePin:{relationTypeId:id(9),version:1,definitionHash:'c'.repeat(64)},targetAssetId:id(10),targetAssetVersion:1} as never);
 const result=assetSearchDocument(id(1),f.asset,f.publication);
 assert.equal(result.glossaryText,'Revenue\nApproved income.\nTurnover\nREV\nQuarterly amount.\nالإيرادات\nدخل معتمد.\nالدخل\nإر\nمبلغ ربع سنوي.');
 assert.equal(JSON.stringify(result).includes(id(10)),false);assert.equal('allowedIdentityIds' in result,false);assert.equal('ownerId'in result,false);
});
test('ordinary and scanned resources cannot inject translations through source metadata or attributes',()=>{
 const f=fixture();
 for(const asset of [{...f.asset,type:'table'},{...f.asset,source_id:id(5)}])assert.equal(assetSearchDocument(id(1),asset,f.publication).glossaryText,'');
 assert.throws(()=>assetSearchDocument(id(99),f.asset,f.publication),refused);
});
test('authored projection refuses missing unsealed stale and mismatched canonical publications',()=>{
 const f=fixture();assert.throws(()=>assetSearchDocument(id(1),f.asset),refused);
 for(const change of [{state:'staged'},{asset_id:id(9)},{asset_version:1}])assert.throws(()=>assetSearchDocument(id(1),f.asset,{...f.publication,...change}),refused);
 for(const change of [{name:'Unapproved'},{description:'Unapproved'},{owner_id:id(8)},{model_version:2},{model_id:'other'},
  {type_state:'deprecated'},{attributes:{}},{visibility:'restricted'},{allowed_identities:[id(8)]}])assert.throws(()=>assetSearchDocument(id(1),{...f.asset,...change},f.publication),refused);
});
test('malformed oversized and extra publication data never becomes index text',()=>{
 const f=fixture();
 for(const payload of [{},{...f.payload,unknown:'hidden'}, {...f.payload,attributes:{translations:[{...f.payload.attributes.translations[0],name:'\ud800'}]}},
  {...f.payload,attributes:{translations:[{...f.payload.attributes.translations[0],definition:'x'.repeat(262145)}]}}])assert.throws(()=>assetSearchDocument(id(1),f.asset,{...f.publication,payload}),refused);
});
test('existing strict index receives additive glossary mapping before initialization completes',async()=>{
 const calls:unknown[]=[];await initializeSearchIndex(async(...args)=>{calls.push(args);return {acknowledged:true};},async()=>new Response('{}',{status:200}));
 assert.deepEqual(calls,[['/gc-assets-v1/_mapping',{properties:{glossaryText:{type:'text'}}},'PUT']]);
 await assert.rejects(initializeSearchIndex(async()=>({acknowledged:false}),async()=>new Response('{}',{status:200})),refused);
 await assert.rejects(initializeSearchIndex(async()=>{throw new Error('Mapping unavailable');},async()=>new Response('{}',{status:200})),/Mapping unavailable/);
});
test('new strict index includes glossary mapping and failed index admission cannot create or update mappings',async()=>{
 const calls:any[]=[];await initializeSearchIndex(async(...args)=>{calls.push(args);return {acknowledged:true};},async()=>new Response('{}',{status:404}));
 assert.equal(calls[0][1].mappings.dynamic,'strict');assert.deepEqual(calls[0][1].mappings.properties.glossaryText,{type:'text'});assert.equal(calls[1][0],'/gc-assets-v1/_mapping');
 let writes=0;await assert.rejects(initializeSearchIndex(async()=>{writes++;},async()=>new Response('{}',{status:503})),refused);assert.equal(writes,0);
});
