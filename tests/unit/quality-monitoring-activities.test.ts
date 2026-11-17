// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {test} from 'node:test';
import {createQualityMonitoringDispatcher} from '../../apps/workflow-worker/src/quality-monitoring-activities.ts';
import {createQualityTransport} from '../../apps/workflow-worker/src/quality-http.ts';
const id=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const tenantId=id(1),monitorId=id(2),item={tenantId,monitorId,work:'tick' as const};
const result={monitorId,state:'advanced',nextWakeAt:'2026-11-17T05:00:00.000Z',occurrenceId:id(3),runId:id(4)};
const json=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers:{'content-type':'application/json'}});
const config={apiUrl:'http://canonical.test',token:'synthetic-token'};
const rejects=(p:Promise<unknown>)=>assert.rejects(p,e=>e instanceof Error&&e.message==='MONITOR_DISPATCH_FAILED');

test('real HTTP monitor dispatcher carries only scoped IDs and an empty tick body',async t=>{
 const seen:{path:string;body:string}[]=[];
 const server=createServer((req,res)=>{let raw='';req.on('data',c=>raw+=c);req.on('end',()=>{
  assert.equal(req.headers.authorization,'Bearer synthetic-token');assert.equal(req.headers['x-tenant-id'],tenantId);
  seen.push({path:req.url!,body:raw});res.setHeader('content-type','application/json');
  res.end(JSON.stringify(req.method==='GET'?{items:[item]}:result));
 });});
 await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
 t.after(async()=>{server.closeAllConnections();await new Promise<void>((r,j)=>server.close(e=>e?j(e):r()));});
 const address=server.address();assert.ok(address&&typeof address==='object');
 const api=createQualityMonitoringDispatcher({...config,apiUrl:`http://127.0.0.1:${address.port}`});
 assert.deepEqual(await api.pendingWork(tenantId),[item]);assert.deepEqual(await api.dispatchWork(item),result);
 assert.deepEqual(seen,[{path:'/internal/quality-monitors/work',body:''},{path:'/internal/quality-monitors/'+monitorId+'/tick',body:'{}'}]);
});
test('work discovery refuses cross-tenant, duplicate, extra-field and oversized work before dispatch',async()=>{
 for(const body of [{items:[item,item]},{items:[{...item,tenantId:id(9)}]},{items:[{...item,source:'private'}]},
  {items:[{...item,work:'execute'}]},{items:Array(51).fill(item)},{items:[],nextCursor:'unadmitted'}]){
  await rejects(createQualityMonitoringDispatcher({...config,fetch:async()=>json(body)}).pendingWork(tenantId));
 }
 assert.deepEqual(await createQualityMonitoringDispatcher({...config,fetch:async()=>json({items:[item,{...item,work:'reconcile'}]})}).pendingWork(tenantId),[item,{...item,work:'reconcile'}]);
});
test('dispatch validates closed ID work before any HTTP and binds exact returned monitor',async()=>{
 let calls=0;const api=createQualityMonitoringDispatcher({...config,fetch:async()=>{calls++;return json(result);}});
 for(const value of [{...item,monitorId:'../other'},{...item,work:'finish'},{...item,measurement:{rowCount:20}}])await rejects(api.dispatchWork(value as typeof item));
 assert.equal(calls,0);
 for(const body of [{...result,monitorId:id(9)},{...result,state:'succeeded'},{...result,occurrenceId:null},
  {...result,nextWakeAt:'0000-01-01T00:00:00.000Z'},{...result,nextWakeAt:'2026-02-30T00:00:00.000Z'},{...result,nextWakeAt:'2026-11-17T05:00:00Z'},{...result,secret:'private'}])
  await rejects(createQualityMonitoringDispatcher({...config,fetch:async()=>json(body)}).dispatchWork(item));
});
test('logical idle, blocked and retry are distinct; transport failure never returns success or loops',async()=>{
 for(const state of ['idle','blocked','retry']){
  const body={monitorId,state,nextWakeAt:null,occurrenceId:null,runId:null};
  assert.deepEqual(await createQualityMonitoringDispatcher({...config,fetch:async()=>json(body)}).dispatchWork({...item,work:'reconcile'}),body);
 }
 for(const status of [400,401,403,404,409,429,500,503]){
  let calls=0;await rejects(createQualityMonitoringDispatcher({...config,fetch:async()=>{calls++;return json({private:'untrusted'},status);}}).dispatchWork(item));assert.equal(calls,1);
 }
 await rejects(createQualityMonitoringDispatcher({...config,fetch:async()=>{throw new Error('private');}}).pendingWork(tenantId));
});
test('monitor transport keeps finite route and body boundaries',async()=>{
 let calls=0;const transport=createQualityTransport({url:config.apiUrl,token:config.token,fetch:async()=>{calls++;return json(result);}});
 for(const path of ['/internal/quality-monitors','/internal/quality-monitors/'+monitorId+'/finish','/internal/quality-monitors/../work','/internal/quality-monitors/work?tenant=other'])
  await assert.rejects(transport(path,{tenantId,maximum:16384,timeoutMs:1000}),/QUALITY_PROTOCOL_INVALID/);
 assert.equal(calls,0);
 await assert.rejects(createQualityMonitoringDispatcher({...config,fetch:async()=>new Response('{"items":[],"items":[]}',{headers:{'content-type':'application/json'}})}).pendingWork(tenantId),/MONITOR_DISPATCH_FAILED/);
});
test('bounded passes rotate beyond a failed head and preserve the eight-command cap',async()=>{
 const items=Array.from({length:20},(_,i)=>({...item,monitorId:id(i+20)}));
 const seen:string[]=[];
 const api=createQualityMonitoringDispatcher({...config,fetch:async(input)=>{
  const path=new URL(String(input)).pathname;
  if(path.endsWith('/work'))return json({items});
  const current=path.split('/')[3]!;seen.push(current);
  if(current===items[0]!.monitorId)return json({error:'unavailable'},503);
  return json({...result,monitorId:current});
 }});
 await rejects(api.dispatchPass(tenantId,()=>false));
 assert.deepEqual(seen,items.slice(0,8).map(v=>v.monitorId));
 await api.dispatchPass(tenantId,()=>false);
 assert.deepEqual(seen,items.slice(0,16).map(v=>v.monitorId));
 await rejects(api.dispatchPass(tenantId,()=>false));
 assert.deepEqual(seen,[...items,...items.slice(0,4)].map(v=>v.monitorId));
});
test('shutdown admits no work and stops further commands after an in-flight result',async()=>{
 let stopping=true,calls=0;
 const api=createQualityMonitoringDispatcher({...config,fetch:async(input)=>{
  calls++;
  if(new URL(String(input)).pathname.endsWith('/work'))return json({items:[item,{...item,monitorId:id(5)}]});
  stopping=true;return json(result);
 }});
 await api.dispatchPass(tenantId,()=>stopping);assert.equal(calls,0);
 stopping=false;await api.dispatchPass(tenantId,()=>stopping);assert.equal(calls,2);
});
test('one original pass deadline includes discovery and stops new work when exhausted',async t=>{
 let clock=100,calls=0;t.mock.method(performance,'now',()=>clock);
 const api=createQualityMonitoringDispatcher({...config,fetch:async(input)=>{
  calls++;
  if(new URL(String(input)).pathname.endsWith('/work')){clock+=9999;return json({items:[item,{...item,monitorId:id(5)}]});}
  clock+=35002;return json(result);
 }});
 await api.dispatchPass(tenantId,()=>false);assert.equal(calls,2);
});
test('work request timeouts remain finite and validated before HTTP',async()=>{
 let calls=0;const api=createQualityMonitoringDispatcher({...config,fetch:async()=>{calls++;return json(result);}});
 for(const timeout of [0,-1,35001,NaN,Infinity,1.5])await rejects(api.dispatchWork(item,timeout));
 assert.equal(calls,0);
});
