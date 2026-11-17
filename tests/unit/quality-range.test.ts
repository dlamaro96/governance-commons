// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {test} from 'node:test';
import Fastify from 'fastify';
import {Value} from '@sinclair/typebox/value';
import {Problem} from '../../packages/authz/src/index.ts';
import {QUALITY_BUDGET,type RangeMeasurement,type RangeRuleDefinition} from '../../packages/domain/src/quality-contracts.ts';
import {parseQualityDefinition,parseQualityMeasurement,parseQualityExecution,parseQualityClaim,parseQualityRunView,parseQualityCompletion,qualityVerdict,qualityInt64,qualityRangeBindingHash,parseQualityRangeBinding} from '../../packages/domain/src/quality.ts';
import {qualityHttp,parseQualityRequestJSON} from '../../apps/api/src/quality.ts';
import {createQualityActivity} from '../../apps/site-runner/src/quality-activity.ts';
import {createQualityTransport} from '../../apps/workflow-worker/src/quality-http.ts';
const id=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const at='2026-11-17T00:00:00.000Z';
const definition:RangeRuleDefinition={formatVersion:1,kind:'range',target:{tableAssetId:id(1),columnAssetId:id(2)},name:'Inclusive integer range',purpose:'Count nonnull observations outside exact bounds.',ownerId:id(3),severity:'warning',maximumOutOfRangeBasisPoints:2500,minimum:'0',maximum:'10',comparison:'int64-inclusive',nullPolicy:'exclude'};
const bounds={minimum:'0',maximum:'10',comparison:'int64-inclusive',nullPolicy:'exclude'} as const;
const range={...bounds,rangeHash:'d9d1c5de1d8da97b52234be367e92343b365e59e7f3bde85748db969b857d161'};
const measurement:RangeMeasurement={formatVersion:1,kind:'range',strategy:'exact-bounded-role-scope',rowCount:20,nullCount:4,belowCount:2,aboveCount:2,rangeHash:range.rangeHash,observedStartedAt:at,observedFinishedAt:at,elapsedMs:0,sourceVersion:'170006',adapterVersion:'1',queryTemplate:'postgresql-range-v1',estimatedCost:1,estimatedBytes:160};
const target={databaseOid:'16384',schemaOid:'2200',relationOid:'16385',attributeNumber:1,schemaName:'public',tableName:'observations',columnName:'code',dataType:'bigint'};
const execution={formatVersion:1,kind:'range',target,budget:{...QUALITY_BUDGET},range};
const queued={id:id(4),ruleId:id(5),ruleVersion:1,ruleHash:'a'.repeat(64),requesterId:id(3),columnAssetId:id(2),tableAssetId:id(1),status:'queued',version:1,attempt:0,createdAt:at,startedAt:null,finishedAt:null,expiresAt:'2026-11-17T00:10:00.000Z',measurement:null,verdict:null,errorCode:null,kind:'range',range};
const succeeded={...queued,status:'succeeded',version:3,attempt:1,startedAt:at,finishedAt:at,measurement,verdict:'PASS'};
const claim={status:'claimed',runId:id(4),claimId:id(7),attempt:1,leaseExpiresAt:new Date(Date.now()+120000).toISOString(),source:{connectorId:'postgresql',host:'private-source',port:5432,database:'private-db',schema:'public',secretRef:'synthetic-private-reference'},execution};
const invalid=(f:()=>unknown)=>assert.throws(f,e=>e instanceof Problem&&e.code==='QUALITY_INPUT_INVALID');
const json=(body:unknown)=>new Response(JSON.stringify(body),{headers:{'content-type':'application/json'}});

test('range exact signed int64 bounds never round or coerce and preserve both inclusive extrema',()=>{
 for(const value of ['0','1','-1','9007199254740993','-9223372036854775808','9223372036854775807'])assert.equal(qualityInt64(value),value);
 for(const value of [0,1n,true,null,'','-0','+1','01','-01',' 1','1 ','1\n','1.0','1e3','9223372036854775808','-9223372036854775809','１'])invalid(()=>qualityInt64(value));
 for(const [minimum,maximum] of [['-9223372036854775808','9223372036854775807'],['9007199254740993','9007199254740993']])assert.deepEqual(parseQualityDefinition({...definition,minimum,maximum}),{...definition,minimum,maximum});
 invalid(()=>parseQualityDefinition({...definition,minimum:'9007199254740993',maximum:'9007199254740992'}));
});
test('range fixed canonical vectors hash compact exact string bounds and reject substituted retained hashes',()=>{
 for(const [minimum,maximum,expected] of [['0','10',range.rangeHash],['-9223372036854775808','9223372036854775807','0834cdeae46a46f1b6859649b262c0a5eeb23b019d513dbabfe889fa657829f1'],['9007199254740993','9007199254740993','d79dbdaffccf16bd9c113a103e3ec9e6c018392d7974daa5c5c8cbce1a43dab4']]){
  const b={...bounds,minimum,maximum};assert.equal(qualityRangeBindingHash(b),expected);assert.deepEqual(parseQualityRangeBinding({...b,rangeHash:expected}),{...b,rangeHash:expected});
 }
 for(const b of [{...range,maximum:'11'},{...range,rangeHash:'a'.repeat(64)},{...range,extra:true},{...range,minimum:0}])invalid(()=>parseQualityRangeBinding(b));
});
test('range definition admits only its family fields and normalizes human text without changing bounds',()=>{
 assert.deepEqual(parseQualityDefinition({...definition,name:' Cafe\u0301 '}),{...definition,name:'Café'});
 for(const patch of [{reference:{}},{maximumNullBasisPoints:0},{maximumDuplicateBasisPoints:0},{maximumOutOfRangeBasisPoints:-0},{maximumOutOfRangeBasisPoints:1.5},{maximumOutOfRangeBasisPoints:10001},{comparison:'float'},{nullPolicy:'include'},{sql:'SELECT code'}])invalid(()=>parseQualityDefinition({...definition,...patch}));
 assert.ok(Value.Check(qualityHttp.definition,definition));assert.equal(Value.Check(qualityHttp.definition,{...definition,minimum:0}),false);
 let called=0;const hostile={...definition};Object.defineProperty(hostile,'minimum',{enumerable:true,get(){called++;return '0';}});invalid(()=>parseQualityDefinition(hostile));assert.equal(called,0);
});
test('range independent integer oracle counts strict tails with inclusive bounds and exact threshold',()=>{
 const values:Array<bigint|null>=[-2n,-1n,0n,1n,2n,3n,4n,5n,6n,7n,8n,9n,10n,10n,11n,12n,null,null,null,null];
 const below=values.filter(x=>x!==null&&x<0n).length,above=values.filter(x=>x!==null&&x>10n).length;
 assert.deepEqual([values.length,values.filter(x=>x===null).length,below,above],[20,4,2,2]);
 assert.deepEqual(parseQualityMeasurement(measurement),measurement);assert.equal(qualityVerdict(measurement,2499),'FAIL');assert.equal(qualityVerdict(measurement,2500),'PASS');
 for(const minimum of [-9223372036854775808n,-1n,0n,9007199254740993n,9223372036854775807n]){
  const sample=[minimum-1n,minimum,minimum+1n,null];const n=sample.filter(x=>x!==null).length;
  const m={...measurement,rowCount:4,nullCount:1,belowCount:sample.filter(x=>x!==null&&x<minimum).length,aboveCount:sample.filter(x=>x!==null&&x>minimum).length};
  assert.equal(m.belowCount+m.aboveCount,2);assert.equal(qualityVerdict(m,6666),'FAIL');assert.equal(qualityVerdict(m,6667),'PASS');assert.equal(n,3);
 }
});
test('range NO_DATA excludes nulls and impossible tail counts cannot produce a result',()=>{
 for(const [rowCount,nullCount] of [[0,0],[20,20]])assert.equal(qualityVerdict({...measurement,rowCount,nullCount,belowCount:0,aboveCount:0},0),'NO_DATA');
 for(const patch of [{belowCount:15},{aboveCount:17},{belowCount:-0},{belowCount:0.5},{aboveCount:NaN},{rangeHash:'X'.repeat(64)},{queryTemplate:'postgresql-completeness-v1'},{invalidCount:1},{distinctCount:12},{values:['private']}])invalid(()=>parseQualityMeasurement({...measurement,...patch}));
});
test('range execution retains exact constant budgets and binding with no reference selector or hidden SQL',()=>{
 assert.deepEqual(parseQualityExecution(execution),execution);assert.deepEqual(parseQualityClaim(claim),claim);
 for(const patch of [{reference:{}},{referenceAsOf:at},{range:{...range,minimum:'-1'}},{budget:{...QUALITY_BUDGET,maximumRows:99999}},{budget:{...QUALITY_BUDGET,maximumValueBytes:4096}}])invalid(()=>parseQualityExecution({...execution,...patch}));
 assert.ok(Value.Check(qualityHttp.execution,execution));assert.equal(Value.Check(qualityHttp.execution,{...execution,reference:{}}),false);
});
test('range run states retain exact selected bounds and reject cross-family or mismatched measurements',()=>{
 for(const run of [queued,succeeded,{...queued,status:'failed',finishedAt:at,errorCode:'QUALITY_SOURCE_FAILED'}]){assert.deepEqual(parseQualityRunView(run),run);assert.ok(Value.Check(qualityHttp.run,run));}
 for(const patch of [{range:{...range,maximum:'11'}},{measurement:{...measurement,rangeHash:'a'.repeat(64)}},{reference:{}},{kind:'uniqueness'},{verdict:'NO_DATA'}])invalid(()=>parseQualityRunView({...succeeded,...patch}));
});
test('actual Fastify completion parsing retains range fields and refuses duplicate or invalid count bodies',async()=>{
 const app=Fastify({logger:false});app.removeContentTypeParser('application/json');app.addContentTypeParser('application/json',{parseAs:'string'},(_req,body,done)=>{try{done(null,parseQualityRequestJSON(String(body)));}catch(e){done(e as Error);}});
 app.post('/complete',{schema:{response:{200:qualityHttp.run}}},async req=>{parseQualityCompletion(req.body);return succeeded;});await app.ready();
 try{const body={claimId:id(7),attempt:1,measurement};const response=await app.inject({method:'POST',url:'/complete',payload:body});assert.equal(response.statusCode,200);assert.deepEqual(response.json(),succeeded);
  for(const payload of [JSON.stringify(body).replace('"belowCount":2','"belowCount":2,"belowCount":2'),JSON.stringify({...body,measurement:{...measurement,aboveCount:17}})])assert.equal((await app.inject({method:'POST',url:'/complete',payload,headers:{'content-type':'application/json'}})).statusCode,400);
 }finally{await app.close();}
});
test('site sends exact range execution privately and converts wrong source hash or family to safe failure',async()=>{
 for(const patch of [null,{rangeHash:'a'.repeat(64)},{kind:'uniqueness'}]){const calls:{url:string;body:any}[]=[];
  const execute=createQualityActivity({apiUrl:'http://canonical.test',apiToken:'synthetic',workerUrl:'http://worker.test',workerToken:'synthetic',tenants:new Set([id(8)]),claimId:()=>id(7),fetch:async(url,init)=>{
   calls.push({url:String(url),body:JSON.parse(String(init?.body))});if(String(url).endsWith('/claim'))return json(claim);
   if(String(url).endsWith('/quality'))return json({measurement:{...measurement,...patch}});
   return json({run:patch?{...succeeded,status:'failed',measurement:null,verdict:null,errorCode:'QUALITY_SOURCE_FAILED'}:succeeded});
  }});
  assert.deepEqual(await execute({tenantId:id(8),runId:id(4)}),{runId:id(4),status:patch?'failed':'succeeded',version:3,retryAt:null});
  assert.deepEqual(calls[1].body,{tenantId:id(8),source:claim.source,execution});assert.deepEqual(calls[2].body,patch?{claimId:id(7),attempt:1,errorCode:'QUALITY_SOURCE_FAILED'}:{claimId:id(7),attempt:1,measurement});
 }
});
test('site refuses a self-consistent final range from different bounds after the exact claimed observation',async()=>{
 const other={...bounds,maximum:'11'},changed={...other,rangeHash:qualityRangeBindingHash(other)};
 const execute=createQualityActivity({apiUrl:'http://canonical.test',apiToken:'synthetic',workerUrl:'http://worker.test',workerToken:'synthetic',tenants:new Set([id(8)]),claimId:()=>id(7),fetch:async url=>String(url).endsWith('/claim')?json(claim):String(url).endsWith('/quality')?json({measurement}):json({run:{...succeeded,range:changed,measurement:{...measurement,rangeHash:changed.rangeHash}}})});
 await assert.rejects(execute({tenantId:id(8),runId:id(4)}),/QUALITY_SITE_UNAVAILABLE/);
});
test('range transport keeps the original 16KiB ceiling and does not dispatch oversized private frames',async()=>{
 let called=false;const request=createQualityTransport({url:'http://worker.test',token:'synthetic',fetch:async()=>{called=true;return json({measurement});}});
 await assert.rejects(request('/quality',{body:{tenantId:id(8),source:{...claim.source,host:'a'.repeat(16384)},execution},maximum:32768,timeoutMs:500}),/QUALITY_PROTOCOL_INVALID/);assert.equal(called,false);
});
