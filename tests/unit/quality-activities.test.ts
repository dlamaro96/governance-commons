// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {createServer,type IncomingMessage,type ServerResponse} from 'node:http';
import {test,type TestContext} from 'node:test';
import {createQualityActivity} from '../../apps/site-runner/src/quality-activity.ts';
import {createQualityDispatcher} from '../../apps/workflow-worker/src/quality-activities.ts';
import {createQualityTransport} from '../../apps/workflow-worker/src/quality-http.ts';
import {QUALITY_BUDGET} from '../../packages/domain/src/quality-contracts.ts';
const id=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const tenant=id(1),runId=id(2),claimId=id(3),input={tenantId:tenant,runId};
const now=Date.now(),stamp=(delta:number)=>new Date(now+delta).toISOString();
const measurement={formatVersion:1,kind:'completeness',strategy:'exact-bounded-role-scope',rowCount:20,nullCount:5,observedStartedAt:stamp(0),observedFinishedAt:stamp(100),elapsedMs:100,sourceVersion:'180001',adapterVersion:'1',queryTemplate:'postgresql-completeness-v1',estimatedCost:3.5,estimatedBytes:100};
const run={id:runId,ruleId:id(4),ruleVersion:1,ruleHash:'a'.repeat(64),requesterId:id(5),columnAssetId:id(6),tableAssetId:id(7),status:'succeeded',version:3,attempt:1,createdAt:stamp(-1000),startedAt:stamp(0),finishedAt:stamp(100),expiresAt:stamp(600000),measurement,verdict:'FAIL',errorCode:null};
const claim={status:'claimed',runId,claimId,attempt:1,leaseExpiresAt:stamp(120000),source:{connectorId:'postgresql',host:'private-source',port:5432,database:'private-database',schema:'public',secretRef:'demo-postgres'},
 execution:{formatVersion:1,kind:'completeness',target:{databaseOid:'16384',schemaOid:'2200',relationOid:'16385',attributeNumber:2,schemaName:'public',tableName:'quality_fixture',columnName:'email',dataType:'text'},budget:{...QUALITY_BUDGET}}};
const json=(body:unknown,status=200,headers:Record<string,string>={})=>new Response(JSON.stringify(body),{status,headers:{'content-type':'application/json',...headers}});
const base={apiUrl:'http://canonical.test',apiToken:'synthetic-api-token',workerUrl:'http://worker.test',workerToken:'synthetic-worker-token',tenants:new Set([tenant]),claimId:()=>claimId};
const reject=(work:Promise<unknown>,code='QUALITY_SITE_UNAVAILABLE')=>assert.rejects(work,error=>error instanceof Error&&error.message===code);
async function server(t:TestContext,handler:(req:IncomingMessage,res:ServerResponse)=>void){const http=createServer(handler);await new Promise<void>(resolve=>http.listen(0,'127.0.0.1',resolve));
 t.after(async()=>{http.closeAllConnections();await new Promise<void>((resolve,reject)=>http.close(error=>error?reject(error):resolve()));});const address=http.address();assert.ok(address&&typeof address==='object');return `http://127.0.0.1:${address.port}`;}

test('real HTTP site run carries private execution only to worker and returns ID/status to Temporal',async t=>{
 const seen:{path:string;body:any}[]=[];
 const url=await server(t,(req,res)=>{let raw='';req.on('data',chunk=>raw+=chunk);req.on('end',()=>{
  const body=JSON.parse(raw),path=req.url!;seen.push({path,body});assert.equal(req.headers.authorization,path==='/quality'?'Bearer synthetic-worker-token':'Bearer synthetic-api-token');
  assert.equal(req.headers.accept,'application/json');assert.equal(req.headers['accept-encoding'],'identity');if(path!=='/quality')assert.equal(req.headers['x-tenant-id'],tenant);
  res.setHeader('content-type','application/json');res.end(JSON.stringify(path.endsWith('/claim')?claim:path==='/quality'?{measurement}:{run}));
 });});
 const result=await createQualityActivity({...base,apiUrl:url,workerUrl:url})(input);
 assert.deepEqual(result,{runId,status:'succeeded',version:3,retryAt:null});assert.equal(JSON.stringify(result).includes('private'),false);assert.equal(JSON.stringify(result).includes('rowCount'),false);
 assert.deepEqual(seen,[{path:`/internal/quality-runs/${runId}/claim`,body:{claimId}},{path:'/quality',body:{tenantId:tenant,source:claim.source,execution:claim.execution}},
  {path:`/internal/quality-runs/${runId}/finish`,body:{claimId,attempt:1,measurement}}]);
});
test('busy and terminal claims never start or repeat a source observation',async()=>{
 for(const value of [{status:'busy',retryAt:stamp(120000)},{status:'terminal',run}]){let calls=0;const result=await createQualityActivity({...base,fetch:async()=>{calls++;return json(value);}})(input);
  assert.equal(calls,1);assert.equal(result.status,value.status==='busy'?'busy':'succeeded');assert.equal(Object.hasOwn(result,'measurement'),false);}
});
test('worker resource exhaustion is distinct from a measured data-quality failure',async()=>{
 let completion:unknown;const failed={...run,status:'failed',measurement:null,verdict:null,errorCode:'QUALITY_RESOURCE_LIMIT'};
 const result=await createQualityActivity({...base,fetch:async(url,init)=>{
  if(String(url).endsWith('/claim'))return json(claim);if(String(url).endsWith('/quality'))return json({code:'QUALITY_RESOURCE_LIMIT'},422);
  completion=JSON.parse(String(init?.body));return json({run:failed});
 }})(input);assert.equal(result.status,'failed');assert.deepEqual(completion,{claimId,attempt:1,errorCode:'QUALITY_RESOURCE_LIMIT'});
});
test('malformed worker output is a safe source failure with no private text forwarded',async()=>{
 for(const body of [{measurement:{...measurement,rawRows:['private']}},{measurement,secret:'private'},{code:'private-database-error',details:'private'}]){
  let completion:unknown;await createQualityActivity({...base,fetch:async(url,init)=>{
   if(String(url).endsWith('/claim'))return json(claim);if(String(url).endsWith('/quality'))return json(body,Object.hasOwn(body,'code')?500:200);
   completion=JSON.parse(String(init?.body));return json({run:{...run,status:'failed',measurement:null,verdict:null,errorCode:'QUALITY_SOURCE_FAILED'}});
  }})(input);assert.deepEqual(completion,{claimId,attempt:1,errorCode:'QUALITY_SOURCE_FAILED'});
 }
});
test('scope, substituted claim, and canonical completion failure cannot report success',async()=>{
 let calls=0;await reject(createQualityActivity({...base,fetch:async()=>{calls++;return json(claim);}})({...input,tenantId:id(9)}));assert.equal(calls,0);
 await reject(createQualityActivity({...base,fetch:async()=>json({...claim,claimId:id(9)})})(input));
 await reject(createQualityActivity({...base,fetch:async(url)=>String(url).endsWith('/claim')?json(claim):String(url).endsWith('/quality')?json({measurement}):json({code:'QUALITY_CLAIM_STALE'},409)})(input));
 await reject(createQualityActivity({...base,fetch:async()=>{throw new Error('private secret');}})(input));
});
test('expired claim never enters the source and reports only safe deadline completion',async()=>{
 let completion:unknown,calls=0;await createQualityActivity({...base,fetch:async(url,init)=>{calls++;
  if(String(url).endsWith('/claim'))return json({...claim,leaseExpiresAt:stamp(-1)});assert.ok(!String(url).endsWith('/quality'));
  completion=JSON.parse(String(init?.body));return json({run:{...run,status:'failed',measurement:null,verdict:null,errorCode:'QUALITY_DEADLINE_EXCEEDED'}});
 }})(input);assert.equal(calls,2);assert.deepEqual(completion,{claimId,attempt:1,errorCode:'QUALITY_DEADLINE_EXCEEDED'});
});
test('canonical pending dispatcher refuses duplicated, foreign and oversized ID lists',async()=>{
 assert.deepEqual(await createQualityDispatcher({...base,token:base.apiToken,fetch:async()=>json({items:[input]})}).pendingQuality(tenant),[input]);
 for(const body of [{items:[input,input]},{items:[{...input,tenantId:id(9)}]},{items:[{...input,source:'private'}]},{items:Array(51).fill(input)},{items:[],nextCursor:'unexpected'}])
  await reject(createQualityDispatcher({...base,token:base.apiToken,fetch:async()=>json(body)}).pendingQuality(tenant),'QUALITY_DISPATCH_FAILED');
});
test('bounded private transport rejects duplicate keys, invalid UTF-8 and response expansion',async()=>{
 for(const body of ['{"measurement":1,"measurement":2}',new Uint8Array([0xff]),'x'.repeat(101)]){
  const request=createQualityTransport({url:base.workerUrl,token:base.workerToken,fetch:async()=>new Response(body,{headers:{'content-type':'application/json'}})});
  await reject(request('/quality',{body:{},maximum:100,timeoutMs:500}),'QUALITY_PROTOCOL_INVALID');
 }
 for(const headers of [{'content-type':'text/html'},{'content-type':'application/json','content-encoding':'gzip'},{'content-type':'application/json','content-length':'101'},{'content-type':'application/json','content-length':'01'}] as Record<string,string>[]){
  let pulls=0;const request=createQualityTransport({url:base.workerUrl,token:base.workerToken,fetch:async()=>new Response(new ReadableStream({pull(){pulls++;}},{highWaterMark:0}),{headers})});
  await reject(request('/quality',{body:{},maximum:100,timeoutMs:500}),'QUALITY_PROTOCOL_INVALID');assert.equal(pulls,0);
 }
});
test('original transport deadline covers stalled headers and stalled body without secret exceptions',async()=>{
 for(const transport of [async()=>new Promise<Response>(()=>{}),async()=>new Response(new ReadableStream({pull(){}},{highWaterMark:0}),{headers:{'content-type':'application/json'}})]){
  const start=performance.now();await reject(createQualityTransport({url:base.workerUrl,token:base.workerToken,fetch:transport})('/quality',{body:{},maximum:100,timeoutMs:25}),'QUALITY_HTTP_TIMEOUT');assert.ok(performance.now()-start<1000);
 }
});
