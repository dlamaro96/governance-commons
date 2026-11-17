// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {test} from 'node:test';
import Fastify from 'fastify';
import {Value} from '@sinclair/typebox/value';
import {Problem} from '../../packages/authz/src/index.ts';
import {QUALITY_BUDGET,QUALITY_UNIQUENESS_BUDGET,type UniquenessMeasurement,type UniquenessRuleDefinition} from '../../packages/domain/src/quality-contracts.ts';
import {parseQualityDefinition,parseQualityMeasurement,parseQualityExecution,parseQualityClaim,parseQualityRunView,parseQualityCompletion,qualityVerdict} from '../../packages/domain/src/quality.ts';
import {qualityHttp,parseQualityRequestJSON} from '../../apps/api/src/quality.ts';
import {createQualityActivity} from '../../apps/site-runner/src/quality-activity.ts';
import {createQualityTransport} from '../../apps/workflow-worker/src/quality-http.ts';
const id=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const at='2026-11-17T00:00:00.000Z';
const definition:UniquenessRuleDefinition={formatVersion:1,kind:'uniqueness',target:{tableAssetId:id(1),columnAssetId:id(2)},name:'Exact uniqueness',purpose:'Count all observations in duplicate groups.',ownerId:id(3),severity:'warning',maximumDuplicateBasisPoints:3750,comparison:'utf8-exact',nullPolicy:'exclude'};
const measurement:UniquenessMeasurement={formatVersion:1,kind:'uniqueness',strategy:'exact-bounded-role-scope',rowCount:20,nullCount:4,distinctCount:12,duplicateGroupCount:2,duplicateRowCount:6,totalValueBytes:16,largestValueBytes:1,observedStartedAt:at,observedFinishedAt:at,elapsedMs:0,sourceVersion:'170006',adapterVersion:'1',queryTemplate:'postgresql-uniqueness-v1',estimatedCost:1,estimatedBytes:160};
const target={databaseOid:'16384',schemaOid:'2200',relationOid:'16385',attributeNumber:1,schemaName:'public',tableName:'observations',columnName:'code',dataType:'text'};
const execution={formatVersion:1,kind:'uniqueness',target,budget:{...QUALITY_UNIQUENESS_BUDGET}};
const queued={id:id(4),ruleId:id(5),ruleVersion:1,ruleHash:'a'.repeat(64),requesterId:id(3),columnAssetId:id(2),tableAssetId:id(1),status:'queued',version:1,attempt:0,createdAt:at,startedAt:null,finishedAt:null,expiresAt:'2026-11-17T00:10:00.000Z',measurement:null,verdict:null,errorCode:null,kind:'uniqueness'};
const succeeded={...queued,status:'succeeded',version:3,attempt:1,startedAt:at,finishedAt:at,measurement,verdict:'PASS'};
const claim={status:'claimed',runId:id(4),claimId:id(7),attempt:1,leaseExpiresAt:new Date(Date.now()+120000).toISOString(),source:{connectorId:'postgresql',host:'private-source',port:5432,database:'private-db',schema:'public',secretRef:'synthetic-private-reference'},execution};
const invalid=(f:()=>unknown)=>assert.throws(f,e=>e instanceof Problem&&e.code==='QUALITY_INPUT_INVALID');
const json=(body:unknown)=>new Response(JSON.stringify(body),{headers:{'content-type':'application/json'}});

test('uniqueness definition is closed, normalizes only human text and cannot carry reference or SQL inputs',()=>{
 assert.deepEqual(parseQualityDefinition({...definition,name:'  Cafe\u0301  '}),{...definition,name:'Café'});
 for(const value of [{...definition,reference:{}},{...definition,maximumNullBasisPoints:0},{...definition,maximumInvalidBasisPoints:0},{...definition,maximumDuplicateBasisPoints:'3750'},{...definition,maximumDuplicateBasisPoints:3750.5},{...definition,maximumDuplicateBasisPoints:-0},{...definition,maximumDuplicateBasisPoints:10001},{...definition,comparison:'casefold'},{...definition,nullPolicy:'include'},{...definition,sql:'SELECT code'}])invalid(()=>parseQualityDefinition(value));
 assert.ok(Value.Check(qualityHttp.definition,definition));assert.equal(Value.Check(qualityHttp.definition,{...definition,reference:{}}),false);
});
test('twenty-row oracle counts all six duplicate rows, with exact 3749/3750 threshold and null-excluded denominator',()=>{
 assert.deepEqual(parseQualityMeasurement(measurement),measurement);assert.equal(qualityVerdict(measurement,3749),'FAIL');assert.equal(qualityVerdict(measurement,3750),'PASS');
 const empty={...measurement,rowCount:0,nullCount:0,distinctCount:0,duplicateGroupCount:0,duplicateRowCount:0,totalValueBytes:0,largestValueBytes:0};
 assert.equal(qualityVerdict(empty,0),'NO_DATA');assert.equal(qualityVerdict({...empty,rowCount:20,nullCount:20},10000),'NO_DATA');
});
test('independent byte-key multiset oracle satisfies count and logical-byte algebra including empty strings and Unicode',()=>{
 const alphabet=[null,'','A','a','é','e\u0301'];
 for(let value=0;value<6**4;value++){
  let remaining=value;const rows:Array<string|null>=[];for(let i=0;i<4;i++){rows.push(alphabet[remaining%6]);remaining=Math.floor(remaining/6);}
  const groups=new Map<string,number>();const lengths:number[]=[];for(const row of rows)if(row!==null){const key=Buffer.from(row).toString('hex');groups.set(key,(groups.get(key)??0)+1);lengths.push(Buffer.byteLength(row));}
  const duplicateGroups=[...groups.values()].filter(n=>n>1),duplicateRows=duplicateGroups.reduce((a,b)=>a+b,0);
  const m={...measurement,rowCount:rows.length,nullCount:rows.filter(v=>v===null).length,distinctCount:groups.size,duplicateGroupCount:duplicateGroups.length,duplicateRowCount:duplicateRows,totalValueBytes:lengths.reduce((a,b)=>a+b,0),largestValueBytes:Math.max(0,...lengths)};
  assert.deepEqual(parseQualityMeasurement(m),m);
  const expected=lengths.length===0?'NO_DATA':duplicateRows*10000<=lengths.length*3750?'PASS':'FAIL';assert.equal(qualityVerdict(m,3750),expected);
 }
});
test('uniqueness refuses impossible counts, inconsistent byte bounds and family substitutions',()=>{
 const patches=[{distinctCount:11},{distinctCount:0},{duplicateRowCount:5},{duplicateGroupCount:4},{duplicateGroupCount:0},{duplicateRowCount:17},{duplicateRowCount:6.5},{largestValueBytes:17},{totalValueBytes:17},{largestValueBytes:4097},{totalValueBytes:67108865},{totalValueBytes:-0},{totalValueBytes:NaN},{nullCount:21},{queryTemplate:'postgresql-completeness-v1'},{referenceBindingHash:'a'.repeat(64)},{invalidCount:0},{rows:['private']}];
 for(const patch of patches)invalid(()=>parseQualityMeasurement({...measurement,...patch}));
 let invoked=0;const value={...measurement};Object.defineProperty(value,'distinctCount',{enumerable:true,get(){invoked++;return 12;}});invalid(()=>parseQualityMeasurement(value));assert.equal(invoked,0);
});
test('zero-length duplicate values are valid while all-null counts must zero every uniqueness field',()=>{
 const emptyValues={...measurement,rowCount:3,nullCount:0,distinctCount:1,duplicateGroupCount:1,duplicateRowCount:3,totalValueBytes:0,largestValueBytes:0};
 assert.equal(qualityVerdict(emptyValues,9999),'FAIL');assert.equal(qualityVerdict(emptyValues,10000),'PASS');
 for(const field of ['distinctCount','duplicateGroupCount','duplicateRowCount','totalValueBytes','largestValueBytes'])invalid(()=>parseQualityMeasurement({...measurement,rowCount:3,nullCount:3,distinctCount:0,duplicateGroupCount:0,duplicateRowCount:0,totalValueBytes:0,largestValueBytes:0,[field]:1}));
});
test('uniqueness execution requires exact logical-byte budgets and no reference frame',()=>{
 assert.deepEqual(parseQualityExecution(execution),execution);assert.deepEqual(parseQualityClaim(claim),claim);
 for(const value of [{...execution,budget:QUALITY_BUDGET},{...execution,budget:{...QUALITY_UNIQUENESS_BUDGET,maximumValueBytes:4095}},{...execution,budget:{...QUALITY_UNIQUENESS_BUDGET,maximumTotalValueBytes:67108865}},{...execution,reference:{}},{...execution,referenceAsOf:at},{...execution,budget:{...QUALITY_UNIQUENESS_BUDGET,physicalByteLimit:1}}])invalid(()=>parseQualityExecution(value));
 assert.ok(Value.Check(qualityHttp.execution,execution));assert.equal(Value.Check(qualityHttp.execution,{...execution,budget:QUALITY_BUDGET}),false);
});
test('unique run discriminator survives every state and cannot be confused with legacy or reference measurements',()=>{
 for(const run of [queued,succeeded,{...queued,status:'failed',finishedAt:at,errorCode:'QUALITY_SOURCE_FAILED'}]){assert.deepEqual(parseQualityRunView(run),run);assert.ok(Value.Check(qualityHttp.run,run));}
 const {kind,...legacy}=queued;assert.deepEqual(parseQualityRunView(legacy),legacy);
 for(const value of [{...queued,reference:{}},{...queued,kind:'completeness'},{...succeeded,kind:undefined},{...succeeded,verdict:'NO_DATA'},{...succeeded,measurement:{...measurement,kind:'completeness'}},{...succeeded,measurement:{...measurement,distinctCount:11}}])invalid(()=>parseQualityRunView(value));
});
test('actual Fastify completion parser refuses duplicate/algebra errors and serializer retains every aggregate',async()=>{
 const app=Fastify({logger:false});app.removeContentTypeParser('application/json');app.addContentTypeParser('application/json',{parseAs:'string'},(_req,body,done)=>{try{done(null,parseQualityRequestJSON(String(body)));}catch(e){done(e as Error);}});
 app.post('/complete',{schema:{response:{200:qualityHttp.run}}},async req=>{parseQualityCompletion(req.body);return succeeded;});await app.ready();
 try{const body={claimId:id(7),attempt:1,measurement};const response=await app.inject({method:'POST',url:'/complete',payload:body});assert.equal(response.statusCode,200);assert.deepEqual(response.json(),succeeded);
  for(const payload of [JSON.stringify(body).replace('"distinctCount":12','"distinctCount":12,"distinctCount":12'),JSON.stringify({...body,measurement:{...measurement,duplicateRowCount:5}})])assert.equal((await app.inject({method:'POST',url:'/complete',payload,headers:{'content-type':'application/json'}})).statusCode,400);
 }finally{await app.close();}
});
test('uniqueness site exchange returns only canonical ID/status and rejects wrong-family source output',async()=>{
 for(const substituted of [false,true]){const calls:{url:string;body:any}[]=[];
  const execute=createQualityActivity({apiUrl:'http://canonical.test',apiToken:'synthetic',workerUrl:'http://worker.test',workerToken:'synthetic',tenants:new Set([id(8)]),claimId:()=>id(7),fetch:async(url,init)=>{
   calls.push({url:String(url),body:JSON.parse(String(init?.body))});if(String(url).endsWith('/claim'))return json(claim);
   if(String(url).endsWith('/quality'))return json({measurement:substituted?{...measurement,distinctCount:11}:measurement});
   return json({run:substituted?{...succeeded,status:'failed',measurement:null,verdict:null,errorCode:'QUALITY_SOURCE_FAILED'}:succeeded});
  }});
  assert.deepEqual(await execute({tenantId:id(8),runId:id(4)}),{runId:id(4),status:substituted?'failed':'succeeded',version:3,retryAt:null});
  assert.deepEqual(calls[1].body,{tenantId:id(8),source:claim.source,execution});assert.equal(Object.hasOwn(calls[2].body,'source'),false);
  assert.deepEqual(calls[2].body,substituted?{claimId:id(7),attempt:1,errorCode:'QUALITY_SOURCE_FAILED'}:{claimId:id(7),attempt:1,measurement});
 }
});
test('site cannot accept a canonical completion from a different family even after a valid uniqueness measurement',async()=>{
 const {distinctCount,duplicateGroupCount,duplicateRowCount,totalValueBytes,largestValueBytes,...common}=measurement;
 const {kind,...legacy}=succeeded;
 const execute=createQualityActivity({apiUrl:'http://canonical.test',apiToken:'synthetic',workerUrl:'http://worker.test',workerToken:'synthetic',tenants:new Set([id(8)]),claimId:()=>id(7),fetch:async url=>String(url).endsWith('/claim')?json(claim):String(url).endsWith('/quality')?json({measurement}):json({run:{...legacy,measurement:{...common,kind:'completeness',queryTemplate:'postgresql-completeness-v1'}}})});
 await assert.rejects(execute({tenantId:id(8),runId:id(4)}),/QUALITY_SITE_UNAVAILABLE/);
});
test('uniqueness claim and private source request retain the original 16KiB transport ceiling',async()=>{
 const request=createQualityTransport({url:'http://canonical.test',token:'synthetic',fetch:async()=>new Response(' '.repeat(16384)+JSON.stringify(claim),{headers:{'content-type':'application/json'}})});
 await assert.rejects(request(`/internal/quality-runs/${id(4)}/claim`,{body:{claimId:id(7)},maximum:65536,timeoutMs:500}),/QUALITY_PROTOCOL_INVALID/);
 let called=false;const outgoing=createQualityTransport({url:'http://worker.test',token:'synthetic',fetch:async()=>{called=true;return json({measurement});}});
 await assert.rejects(outgoing('/quality',{body:{tenantId:id(8),source:{...claim.source,host:'a'.repeat(16384)},execution},maximum:32768,timeoutMs:500}),/QUALITY_PROTOCOL_INVALID/);assert.equal(called,false);
});
