// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import Fastify from 'fastify';
import {Value} from '@sinclair/typebox/value';
import {Problem} from '../../packages/authz/src/index.ts';
import {QUALITY_BUDGET,type VolumeRuleDefinition,type VolumeMeasurement} from '../../packages/domain/src/quality-contracts.ts';
import {parseQualityDefinition,parseQualityMeasurement,parseQualityExecution,parseQualityRunView,parseQualityCompletion,qualityVolumeBindingHash,parseQualityVolumeBinding,qualityVolumeVerdict,qualityVerdict} from '../../packages/domain/src/quality.ts';
import {parseComparisonScope} from '../../packages/domain/src/quality-monitoring.ts';
import {qualityHttp,parseQualityRequestJSON} from '../../apps/api/src/quality.ts';
import {createQualityActivity} from '../../apps/site-runner/src/quality-activity.ts';
const id=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const at='2026-11-17T00:00:00.000Z';
const settings={minimumRows:6,maximumRows:6,comparison:'row-count-inclusive',scope:'entire-table'} as const;
const volume={...settings,volumeHash:'08d5c181809ded58cf68240b793f9e54f7a372b32b9fd0bf16cce1fcd993f421'};
const definition:VolumeRuleDefinition={formatVersion:1,kind:'volume',target:{kind:'table',tableAssetId:id(1)},name:'Expected table rows',purpose:'Count the entire authorized table.',ownerId:id(3),severity:'warning',...settings};
const measurement:VolumeMeasurement={formatVersion:1,kind:'volume',strategy:'exact-bounded-role-scope',rowCount:6,volumeHash:volume.volumeHash,observedStartedAt:at,observedFinishedAt:at,elapsedMs:0,sourceVersion:'170006',adapterVersion:'1',queryTemplate:'postgresql-volume-v1',estimatedCost:1,estimatedBytes:160};
const target={kind:'table',databaseOid:'16384',schemaOid:'2200',relationOid:'16385',schemaName:'public',tableName:'synthetic_volume'};
const execution={formatVersion:1,kind:'volume',target,budget:{...QUALITY_BUDGET},volume};
const queued={id:id(4),ruleId:id(5),ruleVersion:1,ruleHash:'a'.repeat(64),requesterId:id(3),columnAssetId:null,tableAssetId:id(1),status:'queued',version:1,attempt:0,createdAt:at,startedAt:null,finishedAt:null,expiresAt:'2026-11-17T00:10:00.000Z',measurement:null,verdict:null,errorCode:null,kind:'volume',volume};
const succeeded={...queued,status:'succeeded',version:3,attempt:1,startedAt:at,finishedAt:at,measurement,verdict:'PASS'};
const claim={status:'claimed',runId:id(4),claimId:id(7),attempt:1,leaseExpiresAt:new Date(Date.now()+120000).toISOString(),source:{connectorId:'postgresql',host:'synthetic-source.invalid',port:5432,database:'synthetic-db',schema:'public',secretRef:'synthetic-private-reference'},execution};
const invalid=(f:()=>unknown)=>assert.throws(f,e=>e instanceof Problem&&e.code==='QUALITY_INPUT_INVALID');
const binding=(minimumRows:number,maximumRows:number)=>{const v={...settings,minimumRows,maximumRows};return {...v,volumeHash:qualityVolumeBindingHash(v)};};
const json=(body:unknown)=>new Response(JSON.stringify(body),{headers:{'content-type':'application/json'}});

test('volume static canonical six-field binding has independent frozen digest and no target or observation clock',()=>{
 assert.equal(qualityVolumeBindingHash(settings),volume.volumeHash);for(const [lo,hi,hash] of [[0,5,'3b2199a5b4d34da6e2408b6fe7f6158434cad02517ee08b2c24ad06551a51219'],[0,0,'84f12349cdd0d6377677ea35694d2c074ed49c6f70e73fa085bd0c6b005219bd'],[100000,100000,'aaed04bc354ccdaf5ef948e5bd1a213331eb37059b433ea2dbf66759ee2eb0eb']] as const)assert.equal(binding(lo,hi).volumeHash,hash);assert.deepEqual(parseQualityVolumeBinding(volume),volume);
 for(const patch of [{minimumRows:-0},{maximumRows:100001},{minimumRows:7},{maximumRows:'6'},{minimumRows:1.1},{comparison:'estimated'},{scope:'partition'},{volumeHash:'a'.repeat(64)},{observedAt:at},{tableAssetId:id(1)}])invalid(()=>parseQualityVolumeBinding({...volume,...patch}));
});
test('volume definition uses a real table discriminant and never accepts an anchor column or arbitrary predicate',()=>{
 assert.deepEqual(parseQualityDefinition({...definition,name:'  Cafe\u0301  '}),{...definition,name:'Café'});
 assert.ok(Value.Check(qualityHttp.definition,definition));
 for(const target of [{tableAssetId:id(1)},{kind:'column',tableAssetId:id(1)},{kind:'table',tableAssetId:id(1),columnAssetId:null},{kind:'table',tableAssetId:id(1),columnAssetId:id(2)}])invalid(()=>parseQualityDefinition({...definition,target}));
 for(const patch of [{nullPolicy:'exclude'},{maximumNullBasisPoints:0},{volumeHash:volume.volumeHash},{where:'true'},{reference:{}},{name:'x\ny'}])invalid(()=>parseQualityDefinition({...definition,...patch}));
 let calls=0;const accessor={...definition};Object.defineProperty(accessor,'maximumRows',{enumerable:true,get(){calls++;return 6;}});invalid(()=>parseQualityDefinition(accessor));assert.equal(calls,0);
 invalid(()=>parseQualityDefinition(new Proxy(definition,{ownKeys(){throw new Error('untrusted');}})));
});
test('volume six rows above authored maximum five is exact FAIL rather than an execution limit',()=>{
 const b=binding(0,5),m={...measurement,volumeHash:b.volumeHash};assert.deepEqual(parseQualityMeasurement(m),m);assert.equal(qualityVolumeVerdict(m,b),'FAIL');
 assert.equal(qualityVolumeVerdict(measurement,volume),'PASS');assert.equal(qualityVolumeVerdict({...measurement,rowCount:5},volume),'FAIL');assert.equal(qualityVolumeVerdict({...measurement,rowCount:7},volume),'FAIL');
});
test('volume exact empty table is valid PASS or FAIL and cannot become NO_DATA',()=>{
 for(const [minimum,expected] of [[0,'PASS'],[1,'FAIL']] as const){const b=binding(minimum,6),m={...measurement,rowCount:0,volumeHash:b.volumeHash};assert.equal(qualityVolumeVerdict(m,b),expected);assert.deepEqual(parseQualityRunView({...succeeded,volume:b,measurement:m,verdict:expected}).measurement,m);invalid(()=>parseQualityRunView({...succeeded,volume:b,measurement:m,verdict:'NO_DATA'}));}
 invalid(()=>qualityVerdict(measurement,0));
});
test('volume count budget is independent and no values null counts or fabricated column evidence are admitted',()=>{
 const b=binding(100000,100000),m={...measurement,rowCount:100000,volumeHash:b.volumeHash};assert.equal(qualityVolumeVerdict(m,b),'PASS');
 for(const patch of [{rowCount:100001},{rowCount:-0},{rowCount:6.1},{nullCount:0},{columnName:'private'},{values:[]},{totalValueBytes:0},{queryTemplate:'postgresql-completeness-v1'},{volumeHash:'bad'}])invalid(()=>parseQualityMeasurement({...measurement,...patch}));
 invalid(()=>qualityVolumeVerdict({...measurement,volumeHash:'b'.repeat(64)},volume));
});
test('volume execution retains fixed resource budget regardless of authored thresholds and closes table target',()=>{
 assert.deepEqual(parseQualityExecution(execution),execution);assert.ok(Value.Check(qualityHttp.execution,execution));
 for(const patch of [{target:{...target,attributeNumber:1}},{target:{...target,columnName:'private'}},{target:{...target,dataType:'bigint'}},{target:{...target,relationOid:'4294967296'}},{budget:{...QUALITY_BUDGET,maximumRows:6}},{reference:{}},{range:{}},{volume:{...volume,maximumRows:7}}])invalid(()=>parseQualityExecution({...execution,...patch}));
});
test('volume run parser requires null column and recomputes its retained inclusive verdict and binding',()=>{
 for(const v of [queued,succeeded]){assert.deepEqual(parseQualityRunView(v),v);assert.ok(Value.Check(qualityHttp.run,v));}
 for(const patch of [{columnAssetId:id(2)},{verdict:'FAIL'},{verdict:'NO_DATA'},{measurement:{...measurement,volumeHash:'a'.repeat(64)}},{reference:{}},{kind:'completeness'},{volume:undefined}])invalid(()=>parseQualityRunView({...succeeded,...patch}));
 const failed={...succeeded,status:'failed',measurement:null,verdict:null,errorCode:'QUALITY_RESOURCE_LIMIT'};assert.deepEqual(parseQualityRunView(failed),failed);invalid(()=>parseQualityRunView({...failed,errorCode:'QUALITY_CLOCK_SKEW'}));
});
test('volume HTTP schema and actual response serialization preserve exact old and new family distinctions',async()=>{
 assert.ok(Value.Check(qualityHttp.measurement,measurement));assert.equal(Value.Check(qualityHttp.measurement,{...measurement,nullCount:0}),false);assert.equal(Value.Check(qualityHttp.run,{...succeeded,columnAssetId:id(2)}),false);
 const app=Fastify({logger:false});app.removeContentTypeParser('application/json');app.addContentTypeParser('application/json',{parseAs:'string'},(_req,raw,done)=>{try{done(null,parseQualityRequestJSON(String(raw)));}catch(e){done(e as Error);}});app.post('/finish',{schema:{response:{200:qualityHttp.run}}},async req=>{parseQualityCompletion(req.body);return succeeded;});await app.ready();
 try{const body={claimId:id(7),attempt:1,measurement};const response=await app.inject({method:'POST',url:'/finish',payload:body});assert.equal(response.statusCode,200);assert.deepEqual(response.json(),succeeded);for(const payload of [JSON.stringify(body).replace('"rowCount":6','"rowCount":6,"rowCount":6'),JSON.stringify({...body,measurement:{...measurement,nullCount:0}})])assert.equal((await app.inject({method:'POST',url:'/finish',payload,headers:{'content-type':'application/json'}})).statusCode,400);}finally{await app.close();}
});
test('volume site activity forwards the closed table execution and verifies canonical terminal binding',async()=>{
 const calls:{url:string;body:any}[]=[];const execute=createQualityActivity({apiUrl:'http://canonical.test',apiToken:'synthetic',workerUrl:'http://worker.test',workerToken:'synthetic',tenants:new Set([id(8)]),claimId:()=>id(7),fetch:async(url,init)=>{calls.push({url:String(url),body:JSON.parse(String(init?.body))});return String(url).endsWith('/claim')?json(claim):String(url).endsWith('/quality')?json({measurement}):json({run:succeeded});}});
 assert.deepEqual(await execute({tenantId:id(8),runId:id(4)}),{runId:id(4),status:'succeeded',version:3,retryAt:null});assert.deepEqual(calls[1].body,{tenantId:id(8),source:claim.source,execution});assert.deepEqual(calls[2].body,{claimId:id(7),attempt:1,measurement});
});
test('volume site activity refuses substituted family or hash without persisting source evidence',async()=>{
 for(const patch of [{volumeHash:'b'.repeat(64)},{nullCount:0},{kind:'completeness'}]){let completion:unknown;const failed={...succeeded,status:'failed',measurement:null,verdict:null,errorCode:'QUALITY_SOURCE_FAILED'};const execute=createQualityActivity({apiUrl:'http://canonical.test',apiToken:'synthetic',workerUrl:'http://worker.test',workerToken:'synthetic',tenants:new Set([id(8)]),claimId:()=>id(7),fetch:async(url,init)=>{if(String(url).endsWith('/claim'))return json(claim);if(String(url).endsWith('/quality'))return json({measurement:{...measurement,...patch}});completion=JSON.parse(String(init?.body));return json({run:failed});}});assert.equal((await execute({tenantId:id(8),runId:id(4)})).status,'failed');assert.deepEqual(completion,{claimId:id(7),attempt:1,errorCode:'QUALITY_SOURCE_FAILED'});}
});
test('volume monitor comparison scope is explicitly table scoped and refuses mixed family anchors',()=>{
 const scope={formatVersion:1,targetKind:'table',monitorId:id(8),executorId:id(3),rule:{id:id(5),version:1,definitionHash:'a'.repeat(64)},sourceId:id(9),sourceVersion:1,sourceConfigHash:'b'.repeat(64),schemaAssetId:id(10),tableAssetId:id(1),columnAssetId:null,targetHash:'c'.repeat(64),family:{kind:'volume',volumeHash:volume.volumeHash}};
 assert.deepEqual(parseComparisonScope(scope),scope);
 for(const patch of [{targetKind:undefined},{columnAssetId:id(2)},{schemaAssetId:id(1)},{family:{kind:'volume',volumeHash:volume.volumeHash,nullPolicy:'exclude'}},{family:{kind:'completeness',maximumNullBasisPoints:0}}])assert.throws(()=>parseComparisonScope({...scope,...patch}));
});
