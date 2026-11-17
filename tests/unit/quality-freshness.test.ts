// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import Fastify from 'fastify';
import {Value} from '@sinclair/typebox/value';
import {Problem} from '../../packages/authz/src/index.ts';
import {QUALITY_BUDGET,type FreshnessMeasurement,type FreshnessRuleDefinition,type QualityFreshnessSettings} from '../../packages/domain/src/quality-contracts.ts';
import {qualityMicroInstant,qualityFreshnessBindingHash,qualityRangeBindingHash,parseQualityFreshnessBinding,qualityFreshnessVerdict,parseQualityDefinition,parseQualityMeasurement,parseQualityExecution,parseQualityClaim,parseQualityRunView,parseQualityCompletion,qualityVerdict} from '../../packages/domain/src/quality.ts';
import {qualityHttp,parseQualityRequestJSON} from '../../apps/api/src/quality.ts';
import {createQualityActivity} from '../../apps/site-runner/src/quality-activity.ts';
import {createQualityTransport} from '../../apps/workflow-worker/src/quality-http.ts';
const id=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const at='2026-11-17T00:00:00.000Z';
const settings={maximumAgeSeconds:3600,maximumFutureSkewSeconds:0,comparison:'latest-timestamptz',clock:'source-statement-start',nullPolicy:'exclude',invalidTimestampPolicy:'fail'} as const;
const freshness={...settings,freshnessHash:'b7cd429cfbc4669fdd7ddd36964234b7ec458affbe757af28de26030f063faf9'};
const definition:FreshnessRuleDefinition={formatVersion:1,kind:'freshness',target:{tableAssetId:id(1),columnAssetId:id(2)},name:'Latest timestamp freshness',purpose:'Evaluate the newest bounded timestamp, not ingestion or every row age.',ownerId:id(3),severity:'warning',...settings};
const measurement:FreshnessMeasurement={formatVersion:1,kind:'freshness',strategy:'exact-bounded-role-scope',rowCount:6,nullCount:1,nonFiniteCount:0,unrepresentableCount:0,futureCount:0,sourceObservedAt:'2026-11-17T00:00:00.000000Z',latestObservedAt:'2026-11-16T23:00:00.000000Z',ageMicroseconds:'3600000000',freshnessHash:freshness.freshnessHash,observedStartedAt:at,observedFinishedAt:at,elapsedMs:0,sourceVersion:'170006',adapterVersion:'1',queryTemplate:'postgresql-freshness-v1',estimatedCost:1,estimatedBytes:160};
const target={databaseOid:'16384',schemaOid:'2200',relationOid:'16385',attributeNumber:1,schemaName:'public',tableName:'observations',columnName:'observed_at',dataType:'timestamp with time zone'};
const execution={formatVersion:1,kind:'freshness',target,budget:{...QUALITY_BUDGET},freshness};
const queued={id:id(4),ruleId:id(5),ruleVersion:1,ruleHash:'a'.repeat(64),requesterId:id(3),columnAssetId:id(2),tableAssetId:id(1),status:'queued',version:1,attempt:0,createdAt:at,startedAt:null,finishedAt:null,expiresAt:'2026-11-17T00:10:00.000Z',measurement:null,verdict:null,errorCode:null,kind:'freshness',freshness};
const succeeded={...queued,status:'succeeded',version:3,attempt:1,startedAt:at,finishedAt:at,measurement,verdict:'PASS'};
const claim={status:'claimed',runId:id(4),claimId:id(7),attempt:1,leaseExpiresAt:new Date(Date.now()+120000).toISOString(),source:{connectorId:'postgresql',host:'synthetic-source.invalid',port:5432,database:'synthetic-db',schema:'public',secretRef:'synthetic-private-reference'},execution};
const invalid=(f:()=>unknown)=>assert.throws(f,e=>e instanceof Problem&&e.code==='QUALITY_INPUT_INVALID');
const json=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers:{'content-type':'application/json'}});
const failed=(code='QUALITY_SOURCE_FAILED')=>({...succeeded,status:'failed',measurement:null,verdict:null,errorCode:code});
const bind=(patch:Partial<QualityFreshnessSettings>)=>{const fields={...settings,...patch};return {...fields,freshnessHash:qualityFreshnessBindingHash(fields)};};

test('freshness UTC6 retains exact extrema and pre-epoch fractions without parsing microseconds as Date',()=>{
 for(const [value,expected] of [['0001-01-01T00:00:00.000000Z','-62135596800000000'],['9999-12-31T23:59:59.999999Z','253402300799999999'],['1970-01-01T00:00:00.000001Z','1'],['1969-12-31T23:59:59.999999Z','-1']])assert.deepEqual(qualityMicroInstant(value),{canonical:value,epochMicroseconds:BigInt(expected)});
 const original=Date.parse,seen:string[]=[];Date.parse=value=>{seen.push(value);assert.match(value,/\.000Z$/);return original(value);};try{qualityMicroInstant('2026-11-17T00:00:00.123456Z');assert.deepEqual(seen,['2026-11-17T00:00:00.000Z']);}finally{Date.parse=original;}
});

test('freshness UTC6 rejects impossible Gregorian dates offsets leap seconds truncation and nonstrings',()=>{
 for(const good of ['0004-02-29T00:00:00.000001Z','2000-02-29T23:59:59.999999Z','2400-02-29T00:00:00.000000Z'])assert.equal(qualityMicroInstant(good).canonical,good);
 for(const value of ['0000-01-01T00:00:00.000000Z','1900-02-29T00:00:00.000000Z','2100-02-29T00:00:00.000000Z','2026-04-31T00:00:00.000000Z','2026-11-17T24:00:00.000000Z','2026-11-17T00:00:60.000000Z','2026-11-17T00:00:00.00000Z','2026-11-17T00:00:00.0000000Z','2026-11-17T00:00:00.000000+00:00',measurement.sourceObservedAt+'\n',measurement.sourceObservedAt+' ',null,new Date(),1])invalid(()=>qualityMicroInstant(value));
});

test('freshness binding uses the independently frozen sorted preimage and admits no source clock or caller mode',()=>{
 assert.equal(qualityFreshnessBindingHash(settings),freshness.freshnessHash);assert.deepEqual(parseQualityFreshnessBinding(freshness),freshness);
 for(const patch of [{maximumAgeSeconds:0},{maximumAgeSeconds:31536001},{maximumAgeSeconds:-0},{maximumFutureSkewSeconds:301},{maximumFutureSkewSeconds:1.5},{clock:'worker'},{comparison:'oldest'},{nullPolicy:'include'},{invalidTimestampPolicy:'skip'},{sourceObservedAt:measurement.sourceObservedAt},{freshnessHash:'a'.repeat(64)}])invalid(()=>parseQualityFreshnessBinding({...freshness,...patch}));
});

test('freshness definition preserves normalized text and refuses mixed families getters and unknown executable fields',()=>{
 assert.deepEqual(parseQualityDefinition({...definition,name:'  Cafe\u0301  '}),{...definition,name:'Café'});assert.ok(Value.Check(qualityHttp.definition,definition));
 for(const patch of [{maximumNullBasisPoints:0},{maximumInvalidBasisPoints:0},{maximumDuplicateBasisPoints:0},{minimum:'0'},{maximum:'10'},{reference:{}},{freshnessHash:freshness.freshnessHash},{sourceObservedAt:measurement.sourceObservedAt},{sql:'select current_timestamp'},{maximumAgeSeconds:'3600'}])invalid(()=>parseQualityDefinition({...definition,...patch}));
 let calls=0;const getter={...definition};Object.defineProperty(getter,'maximumAgeSeconds',{enumerable:true,get(){calls++;return 3600;}});invalid(()=>parseQualityDefinition(getter));assert.equal(calls,0);
 const proxy=new Proxy(definition,{ownKeys(){throw new Error('private-reflection');}});invalid(()=>parseQualityDefinition(proxy));
});

test('freshness canonical signed age is exact and forged or numeric age evidence is rejected',()=>{
 assert.deepEqual(parseQualityMeasurement(measurement),measurement);
 for(const age of ['3600000001','03600000000','+3600000000','3.6e9','3600000000.0','3600000000\n',3600000000,-0,NaN,'-0'])invalid(()=>parseQualityMeasurement({...measurement,ageMicroseconds:age}));
 const extreme={...measurement,sourceObservedAt:'9999-12-31T23:59:59.999999Z',latestObservedAt:'0001-01-01T00:00:00.000000Z',ageMicroseconds:'315537897599999999',observedStartedAt:'9999-12-31T23:59:59.999Z',observedFinishedAt:'9999-12-31T23:59:59.999Z'};
 assert.deepEqual(parseQualityMeasurement(extreme),extreme);assert.equal(qualityFreshnessVerdict(extreme,freshness),'FAIL');
});

test('freshness count partitions cannot conceal invalid rows or invent a maximum timestamp',()=>{
 for(const patch of [{nonFiniteCount:6},{unrepresentableCount:6},{nonFiniteCount:3,unrepresentableCount:3},{futureCount:6},{nonFiniteCount:5},{latestObservedAt:null},{ageMicroseconds:null},{futureCount:-0},{nonFiniteCount:0.5},{unrepresentableCount:Infinity},{queryTemplate:'postgresql-completeness-v1'},{invalidCount:1},{rangeHash:'a'.repeat(64)},{values:['private']}])invalid(()=>parseQualityMeasurement({...measurement,...patch}));
 const none={...measurement,nonFiniteCount:3,unrepresentableCount:2,latestObservedAt:null,ageMicroseconds:null};assert.deepEqual(parseQualityMeasurement(none),none);assert.equal(qualityFreshnessVerdict(none,freshness),'FAIL');
 invalid(()=>parseQualityMeasurement({...none,futureCount:1}));
});

test('freshness maximum-age equality passes and exactly one older microsecond fails',()=>{
 assert.equal(qualityFreshnessVerdict(measurement,freshness),'PASS');assert.equal(qualityFreshnessVerdict({...measurement,latestObservedAt:'2026-11-16T22:59:59.999999Z',ageMicroseconds:'3600000001'},freshness),'FAIL');
 assert.equal(qualityFreshnessVerdict({...measurement,latestObservedAt:'2026-11-16T23:00:00.000001Z',ageMicroseconds:'3599999999'},freshness),'PASS');
 invalid(()=>qualityVerdict(measurement,10000));
});

test('freshness future equality and one-microsecond excess obey retained tolerance without clamping negative age',()=>{
 const b=bind({maximumFutureSkewSeconds:5}),m={...measurement,freshnessHash:b.freshnessHash,latestObservedAt:'2026-11-17T00:00:05.000000Z',ageMicroseconds:'-5000000'};
 assert.equal(qualityFreshnessVerdict(m,b),'PASS');assert.equal(qualityFreshnessVerdict({...m,latestObservedAt:'2026-11-17T00:00:05.000001Z',ageMicroseconds:'-5000001',futureCount:1},b),'FAIL');
 invalid(()=>qualityFreshnessVerdict({...m,futureCount:1},b));invalid(()=>qualityFreshnessVerdict({...m,latestObservedAt:'2026-11-17T00:00:05.000001Z',ageMicroseconds:'-5000001'},b));
});

test('freshness invalid values force FAIL even with a timely maximum and empty or all-null alone mean NO_DATA',()=>{
 for(const patch of [{nonFiniteCount:1},{unrepresentableCount:1}])assert.equal(qualityFreshnessVerdict({...measurement,...patch},freshness),'FAIL');
 for(const [rowCount,nullCount] of [[0,0],[6,6]])assert.equal(qualityFreshnessVerdict({...measurement,rowCount,nullCount,latestObservedAt:null,ageMicroseconds:null},freshness),'NO_DATA');
 const invalidOnly={...measurement,rowCount:2,nullCount:1,nonFiniteCount:1,latestObservedAt:null,ageMicroseconds:null};assert.equal(qualityFreshnessVerdict(invalidOnly,freshness),'FAIL');
});

test('freshness gross source-worker clock allowance includes exact boundaries and rejects one extra microsecond',()=>{
 for(const [sourceObservedAt,ageMicroseconds] of [['2026-11-16T23:59:55.000000Z','3595000000'],['2026-11-17T00:00:05.000000Z','3605000000']])assert.ok(parseQualityMeasurement({...measurement,sourceObservedAt,ageMicroseconds}));
 for(const [sourceObservedAt,ageMicroseconds] of [['2026-11-16T23:59:54.999999Z','3594999999'],['2026-11-17T00:00:05.000001Z','3605000001']])invalid(()=>parseQualityMeasurement({...measurement,sourceObservedAt,ageMicroseconds}));
 invalid(()=>parseQualityMeasurement({...measurement,observedFinishedAt:'2026-11-16T23:59:59.999Z'}));
});

test('freshness execution is closed and carries the immutable binding with original fixed budgets',()=>{
 assert.deepEqual(parseQualityExecution(execution),execution);assert.deepEqual(parseQualityClaim(claim),claim);assert.ok(Value.Check(qualityHttp.execution,execution));
 for(const patch of [{range:{}},{reference:{}},{sourceObservedAt:measurement.sourceObservedAt},{freshness:{...freshness,maximumAgeSeconds:1}},{budget:{...QUALITY_BUDGET,maximumRows:99999}},{budget:{...QUALITY_BUDGET,maximumValueBytes:4096}}])invalid(()=>parseQualityExecution({...execution,...patch}));
});

test('freshness immutable run parsing recomputes verdict and refuses inconsistent family or pinned evidence',()=>{
 for(const run of [queued,succeeded,failed('QUALITY_CLOCK_SKEW')]){assert.deepEqual(parseQualityRunView(run),run);assert.ok(Value.Check(qualityHttp.run,run));}
 for(const patch of [{verdict:'FAIL'},{verdict:'NO_DATA'},{freshness:{...freshness,maximumAgeSeconds:10}},{measurement:{...measurement,freshnessHash:'a'.repeat(64)}},{reference:{}},{range:{}},{kind:'range'}])invalid(()=>parseQualityRunView({...succeeded,...patch}));
 const completion=parseQualityCompletion({claimId:id(7),attempt:1,errorCode:'QUALITY_CLOCK_SKEW'});assert.ok('errorCode' in completion);assert.equal(completion.errorCode,'QUALITY_CLOCK_SKEW');
});

test('clock-skew terminal evidence is decoded only for freshness while older failures retain their exact shapes',()=>{
 const {kind,freshness:removed,...common}=failed();
 const rangeFields={minimum:'0',maximum:'10',comparison:'int64-inclusive',nullPolicy:'exclude'} as const;
 const older=[common,{...common,kind:'uniqueness'},{...common,kind:'range',range:{...rangeFields,rangeHash:qualityRangeBindingHash(rangeFields)}},{...common,kind:'reference-allowed-values',reference:{setId:id(9),version:1,publicationHash:'b'.repeat(64),asOf:at,codeStatus:'active',bindingHash:'c'.repeat(64)}}];
 for(const run of older){assert.deepEqual(parseQualityRunView(run),run);invalid(()=>parseQualityRunView({...run,errorCode:'QUALITY_CLOCK_SKEW'}));}
 assert.deepEqual(parseQualityRunView(failed('QUALITY_CLOCK_SKEW')),failed('QUALITY_CLOCK_SKEW'));
});

test('actual Fastify serialization preserves UTC6 and age strings and duplicate or forged completion evidence refuses',async()=>{
 const app=Fastify({logger:false});app.removeContentTypeParser('application/json');app.addContentTypeParser('application/json',{parseAs:'string'},(_req,body,done)=>{try{done(null,parseQualityRequestJSON(String(body)));}catch(e){done(e as Error);}});app.post('/finish',{schema:{response:{200:qualityHttp.run}}},async req=>{parseQualityCompletion(req.body);return succeeded;});await app.ready();
 try{const body={claimId:id(7),attempt:1,measurement};const response=await app.inject({method:'POST',url:'/finish',payload:body});assert.equal(response.statusCode,200);assert.deepEqual(response.json(),succeeded);
  for(const payload of [JSON.stringify(body).replace('"futureCount":0','"futureCount":0,"futureCount":0'),JSON.stringify({...body,measurement:{...measurement,ageMicroseconds:'3600000001'}})])assert.equal((await app.inject({method:'POST',url:'/finish',payload,headers:{'content-type':'application/json'}})).statusCode,400);
 }finally{await app.close();}
});

test('freshness API schemas reject numeric ages and mixed fields without widening old family shapes',()=>{
 assert.ok(Value.Check(qualityHttp.measurement,measurement));assert.equal(Value.Check(qualityHttp.measurement,{...measurement,ageMicroseconds:3600000000}),false);assert.equal(Value.Check(qualityHttp.definition,{...definition,maximumNullBasisPoints:0}),false);
 for(const value of [{...execution,kind:'completeness'},{...queued,kind:'uniqueness'},{...measurement,kind:'range',queryTemplate:'postgresql-range-v1'}]){const schema='target'in value?qualityHttp.execution:'status'in value?qualityHttp.run:qualityHttp.measurement;assert.equal(Value.Check(schema,value),false);}
});

test('site sends only exact private freshness execution and returns only finite lifecycle metadata',async()=>{
 const calls:{url:string;body:any}[]=[];const execute=createQualityActivity({apiUrl:'http://canonical.test',apiToken:'synthetic',workerUrl:'http://worker.test',workerToken:'synthetic',tenants:new Set([id(8)]),claimId:()=>id(7),fetch:async(url,init)=>{calls.push({url:String(url),body:JSON.parse(String(init?.body))});return String(url).endsWith('/claim')?json(claim):String(url).endsWith('/quality')?json({measurement}):json({run:succeeded});}});
 assert.deepEqual(await execute({tenantId:id(8),runId:id(4)}),{runId:id(4),status:'succeeded',version:3,retryAt:null});assert.deepEqual(calls[1].body,{tenantId:id(8),source:claim.source,execution});assert.deepEqual(calls[2].body,{claimId:id(7),attempt:1,measurement});
});

test('site rejects substituted freshness hash forged age future algebra or wrong source family safely',async()=>{
 for(const patch of [{freshnessHash:'a'.repeat(64)},{ageMicroseconds:'1'},{futureCount:1},{kind:'completeness'}]){let completion:unknown;const execute=createQualityActivity({apiUrl:'http://canonical.test',apiToken:'synthetic',workerUrl:'http://worker.test',workerToken:'synthetic',tenants:new Set([id(8)]),claimId:()=>id(7),fetch:async(url,init)=>{
  if(String(url).endsWith('/claim'))return json(claim);if(String(url).endsWith('/quality'))return json({measurement:{...measurement,...patch}});completion=JSON.parse(String(init?.body));return json({run:failed()});
 }});assert.equal((await execute({tenantId:id(8),runId:id(4)})).status,'failed');assert.deepEqual(completion,{claimId:id(7),attempt:1,errorCode:'QUALITY_SOURCE_FAILED'});}
});

test('site preserves explicit gross clock-skew execution failure without storing a measurement or verdict',async()=>{
 let completion:unknown;const execute=createQualityActivity({apiUrl:'http://canonical.test',apiToken:'synthetic',workerUrl:'http://worker.test',workerToken:'synthetic',tenants:new Set([id(8)]),claimId:()=>id(7),fetch:async(url,init)=>{if(String(url).endsWith('/claim'))return json(claim);if(String(url).endsWith('/quality'))return json({code:'QUALITY_CLOCK_SKEW'},422);completion=JSON.parse(String(init?.body));return json({run:failed('QUALITY_CLOCK_SKEW')});}});
 assert.equal((await execute({tenantId:id(8),runId:id(4)})).status,'failed');assert.deepEqual(completion,{claimId:id(7),attempt:1,errorCode:'QUALITY_CLOCK_SKEW'});
});

test('site treats a source clock-skew code on completeness as a generic source failure',async()=>{
 const {freshness:removed,kind,...commonRun}=failed();
 const oldClaim={...claim,execution:{formatVersion:1,kind:'completeness',target,budget:{...QUALITY_BUDGET}}};
 let completion:unknown;const execute=createQualityActivity({apiUrl:'http://canonical.test',apiToken:'synthetic',workerUrl:'http://worker.test',workerToken:'synthetic',tenants:new Set([id(8)]),claimId:()=>id(7),fetch:async(url,init)=>{
  if(String(url).endsWith('/claim'))return json(oldClaim);if(String(url).endsWith('/quality'))return json({code:'QUALITY_CLOCK_SKEW'},422);completion=JSON.parse(String(init?.body));return json({run:commonRun});
 }});assert.equal((await execute({tenantId:id(8),runId:id(4)})).status,'failed');assert.deepEqual(completion,{claimId:id(7),attempt:1,errorCode:'QUALITY_SOURCE_FAILED'});
});

test('site refuses a self-consistent final freshness result for settings different from its retained claim',async()=>{
 const other=bind({maximumAgeSeconds:7200});const execute=createQualityActivity({apiUrl:'http://canonical.test',apiToken:'synthetic',workerUrl:'http://worker.test',workerToken:'synthetic',tenants:new Set([id(8)]),claimId:()=>id(7),fetch:async url=>String(url).endsWith('/claim')?json(claim):String(url).endsWith('/quality')?json({measurement}):json({run:{...succeeded,freshness:other,measurement:{...measurement,freshnessHash:other.freshnessHash}}})});await assert.rejects(execute({tenantId:id(8),runId:id(4)}),/QUALITY_SITE_UNAVAILABLE/);
});

test('freshness transport keeps the non-reference 16KiB request ceiling and original failure privacy',async()=>{
 let called=false;const request=createQualityTransport({url:'http://worker.test',token:'synthetic',fetch:async()=>{called=true;return json({measurement});}});await assert.rejects(request('/quality',{body:{tenantId:id(8),source:{...claim.source,host:'a'.repeat(16384)},execution},maximum:32768,timeoutMs:500}),/QUALITY_PROTOCOL_INVALID/);assert.equal(called,false);
});
