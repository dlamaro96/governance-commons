// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {createServer,type IncomingMessage,type ServerResponse} from 'node:http';
import {test,type TestContext} from 'node:test';
import {createApprovalActivities,dispatchApprovalEvent,type ApprovalProtocol,type ApprovalStatus,type ApprovalTick} from '../../apps/workflow-worker/src/approval-activities.ts';
const tenant='10000000-0000-4000-8000-000000000001',request='10000000-0000-4000-8000-000000000002',event='10000000-0000-4000-8000-000000000003';
const other='10000000-0000-4000-8000-000000000004';
const input={tenantId:tenant,requestId:request},delivery={...input,eventId:event};
const pending:ApprovalTick={id:request,status:'pending',version:1,nextWakeAt:'2026-11-16T19:00:00.000Z'};
const ready:ApprovalTick={id:request,status:'ready',version:2,nextWakeAt:null};
const json=(value:unknown,headers:Record<string,string>={})=>new Response(JSON.stringify(value),{headers:{'content-type':'application/json',...headers}});
function api(value:unknown){return createApprovalActivities({apiUrl:'http://127.0.0.1:4310',token:'synthetic-test-token',fetch:async()=>json(value)});}
async function server(t:TestContext,handler:(req:IncomingMessage,res:ServerResponse)=>void){
  const http=createServer(handler);await new Promise<void>(resolve=>http.listen(0,'127.0.0.1',resolve));
  t.after(async()=>{http.closeAllConnections();await new Promise<void>((resolve,reject)=>http.close(error=>error?reject(error):resolve()));});
  const address=http.address();assert.ok(address&&typeof address==='object');return `http://127.0.0.1:${address.port}`;
}
const reject=(work:Promise<unknown>,code='APPROVAL_PROTOCOL_INVALID')=>assert.rejects(work,error=>error instanceof Error&&error.message===code);

test('actual HTTP protocol carries only tenant/request/event IDs, strict headers and empty POST bodies',async t=>{
  const seen:{method:string|undefined;path:string|undefined;body:string}[]=[];
  const url=await server(t,(req,res)=>{
    assert.equal(req.headers.authorization,'Bearer synthetic-test-token');assert.equal(req.headers['x-tenant-id'],tenant);
    assert.equal(req.headers.accept,'application/json');assert.equal(req.headers['accept-encoding'],'identity');
    let body='';req.on('data',chunk=>body+=chunk);req.on('end',()=>{
      seen.push({method:req.method,path:req.url,body});res.setHeader('Content-Type','application/json');
      res.end(JSON.stringify(req.url?.endsWith('/pending')?{items:[delivery]}:req.url?.endsWith('/ack')?{id:event,acknowledged:true}:req.url?.endsWith('/status')?ready:pending));
    });
  });
  const protocol=createApprovalActivities({apiUrl:url,token:'synthetic-test-token'});
  assert.deepEqual(await protocol.pendingApprovals(tenant),{items:[delivery]});assert.deepEqual(await protocol.tickApproval(input),pending);
  assert.deepEqual(await protocol.approvalStatus(input),ready);await protocol.ackApproval(delivery);
  assert.deepEqual(seen,[{method:'GET',path:'/internal/approvals/pending',body:''},{method:'POST',path:`/internal/approvals/${request}/tick`,body:'{}'},
    {method:'GET',path:`/internal/approvals/${request}/status`,body:''},{method:'POST',path:`/internal/approvals/dispatch/${event}/ack`,body:'{}'}]);
});

test('documented terminal states retain their exact meaning and only pending carries a timer',async()=>{
  for(const status of ['rejected','cancelled','expired','succeeded','failed'] as const){
    const value={...ready,status};assert.deepEqual(await api(value).tickApproval(input),value);assert.deepEqual(await api(value).approvalStatus(input),value);
  }
  assert.equal((await api(ready).approvalStatus(input)).status,'ready');
  await reject(api(ready).tickApproval(input));
  assert.deepEqual(await api({...pending,version:2_147_483_647}).tickApproval(input),{...pending,version:2_147_483_647});
});

test('status DTO refuses missing unknown substituted coerced and impossible fields',async()=>{
  const invalid:unknown[]=[null,[],{...pending,id:other},{...pending,tenantId:tenant},{...pending,version:0},{...pending,version:2_147_483_648},
    {...pending,version:'1'},{...pending,version:1.5},{...pending,status:'published'},{...pending,status:'approved'},
    {...pending,nextWakeAt:null},{...pending,nextWakeAt:'2026-02-30T00:00:00.000Z'},{...pending,nextWakeAt:'2026-11-16T19:00:00Z'},
    {...pending,nextWakeAt:'2026-11-16T19:00:00.000+00:00'},{...ready,nextWakeAt:pending.nextWakeAt}];
  for(const key of Object.keys(pending)){const value:any={...pending};delete value[key];invalid.push(value);}
  for(const value of invalid){await reject(api(value).tickApproval(input));await reject(api(value).approvalStatus(input));}
});

test('pending delivery requires exact tenant IDs, unique events and the complete bounded envelope',async()=>{
  for(const value of [{items:[{...delivery,tenantId:other}]},{items:[{...delivery,eventId:'wrong'}]},{items:[{...delivery,requestId:other,private:'reason'}]},
    {items:[delivery,delivery]},{items:Array.from({length:51},(_,i)=>({...delivery,eventId:`10000000-0000-4000-8000-${String(i).padStart(12,'0')}`}))},
    {items:[],next:'unknown'},{items:null},[]])await reject(api(value).pendingApprovals(tenant));
  assert.deepEqual(await api({items:[]}).pendingApprovals(tenant),{items:[]});
  const items=Array.from({length:50},(_,i)=>({...delivery,eventId:`10000000-0000-4000-8000-${String(i).padStart(12,'0')}`}));
  assert.deepEqual(await api({items}).pendingApprovals(tenant),{items});
});

test('acknowledgement binds the exact delivery and refuses false or extra acknowledgements',async()=>{
  for(const value of [{id:other,acknowledged:true},{id:event,acknowledged:false},{id:event,acknowledged:'true'},{id:event},
    {id:event,acknowledged:true,requestId:request}])await reject(api(value).ackApproval(delivery));
  await api({id:event,acknowledged:true}).ackApproval(delivery);
});

test('JSON duplicate keys and malformed UTF-8 refuse without private response echoes',async()=>{
  for(const body of ['{"id":"'+other+'","id":"'+request+'","status":"ready","version":1,"nextWakeAt":null}',
    '{"items":[],"\\u0069tems":[]}','not JSON private-response',new Uint8Array([0xff,0xfe])]){
    const protocol=createApprovalActivities({apiUrl:'http://127.0.0.1',token:'synthetic',fetch:async()=>new Response(body,{headers:{'content-type':'application/json'}})});
    await reject(protocol.tickApproval(input));
  }
});

test('header admission refuses unsupported representations before pulling body bytes',async()=>{
  for(const headers of [{'content-type':'text/html'},{'content-type':'application/json','content-encoding':'gzip'},
    {'content-type':'application/json','content-encoding':''},{'content-type':'application/json','content-length':'2049'},
    {'content-type':'application/json','content-length':'1e2'},{'content-type':'application/json','content-length':'01'}] as Record<string,string>[]){
    let pulls=0,signal:AbortSignal|undefined;
    const protocol=createApprovalActivities({apiUrl:'http://127.0.0.1',token:'synthetic',fetch:async(_url,init)=>{
      signal=init?.signal as AbortSignal;return new Response(new ReadableStream({pull(){pulls++;}},{highWaterMark:0}),{headers});
    }});
    await reject(protocol.tickApproval(input));assert.equal(pulls,0);assert.equal(signal?.aborted,true);
  }
});

test('decoded stream bytes and declared lengths remain bounded without truncating responses',async()=>{
  for(const response of [new Response('x'.repeat(2049),{headers:{'content-type':'application/json'}}),
    json(pending,{'content-length':'1'}),json(pending,{'content-length':String(Buffer.byteLength(JSON.stringify(pending))+1)})]){
    const protocol=createApprovalActivities({apiUrl:'http://127.0.0.1',token:'synthetic',fetch:async()=>response});await reject(protocol.tickApproval(input));
  }
  const body=JSON.stringify(pending);assert.deepEqual(await createApprovalActivities({apiUrl:'http://127.0.0.1',token:'synthetic',
    fetch:async()=>new Response(new ReadableStream({start(c){c.enqueue(new TextEncoder().encode(body.slice(0,20)));c.enqueue(new TextEncoder().encode(body.slice(20)));c.close();}}),
      {headers:{'content-type':'application/json; charset=utf-8','content-encoding':'IDENTITY','content-length':String(Buffer.byteLength(body))}})}).tickApproval(input),pending);
});

test('HTTP refusal never reads or returns private error details',async()=>{
  for(const status of [301,400,401,404,409,429,500,503]){
    let pulls=0;const protocol=createApprovalActivities({apiUrl:'http://127.0.0.1',token:'synthetic',fetch:async()=>new Response(
      new ReadableStream({pull(){pulls++;}},{highWaterMark:0}),{status,headers:{'content-type':'application/problem+json'}})});
    await reject(protocol.tickApproval(input),'APPROVAL_HTTP_REFUSED');assert.equal(pulls,0);
  }
});

test('actual delayed HTTP headers are interrupted by the original deadline',async t=>{
  let timer:ReturnType<typeof setTimeout>|undefined;
  const url=await server(t,(_req,res)=>{timer=setTimeout(()=>{res.setHeader('Content-Type','application/json');res.end(JSON.stringify(pending));},2000);});
  t.after(()=>{clearTimeout(timer);});
  const started=Date.now();await reject(createApprovalActivities({apiUrl:url,token:'synthetic',timeoutMs:40}).tickApproval(input),'APPROVAL_HTTP_TIMEOUT');
  assert.ok(Date.now()-started<1000);
});

test('one deadline covers fetch and body and does not wait for nonsettling cancellation',async()=>{
  let signal:AbortSignal|undefined,cancelled=0;
  const protocol=createApprovalActivities({apiUrl:'http://127.0.0.1',token:'synthetic',timeoutMs:60,fetch:async(_url,init)=>{
    signal=init?.signal as AbortSignal;await new Promise(resolve=>setTimeout(resolve,30));
    return new Response(new ReadableStream({cancel(){cancelled++;return new Promise(()=>{});}},{highWaterMark:0}),{headers:{'content-type':'application/json'}});
  }});
  const started=Date.now();await reject(protocol.tickApproval(input),'APPROVAL_HTTP_TIMEOUT');const elapsed=Date.now()-started;
  assert.ok(elapsed>=45&&elapsed<500);assert.equal(signal?.aborted,true);assert.equal(cancelled,1);
});

test('transport exceptions including hostile thrown objects reduce to fixed safe codes',async()=>{
  let inspected=0;const thrown=new Proxy({},{getPrototypeOf(){inspected++;throw new Error('Must not inspect thrown value');}});
  for(const error of [thrown,new Error('private-response secret token'),null]){
    const protocol=createApprovalActivities({apiUrl:'http://127.0.0.1',token:'synthetic',fetch:async()=>{throw error;}});
    await reject(protocol.tickApproval(input),'APPROVAL_HTTP_UNAVAILABLE');
  }
  assert.equal(inspected,0);
});

test('configuration and ID admission refuse before network activity',async()=>{
  for(const apiUrl of ['file:///tmp/private','http://user:pass@api','http://api/path','http://api?x=y','http://api/#fragment'])
    assert.throws(()=>createApprovalActivities({apiUrl,token:'synthetic'}),/APPROVAL_CONFIG_INVALID/);
  for(const token of ['', 'bad\nheader','a'.repeat(4097)])assert.throws(()=>createApprovalActivities({apiUrl:'http://api',token}),/APPROVAL_CONFIG_INVALID/);
  for(const timeoutMs of [0,10001,0.5])assert.throws(()=>createApprovalActivities({apiUrl:'http://api',token:'synthetic',timeoutMs}),/APPROVAL_CONFIG_INVALID/);
  let called=0;const protocol=createApprovalActivities({apiUrl:'http://api',token:'synthetic',fetch:async()=>{called++;return json(pending);}});
  for(const value of [{...input,requestId:'bad'},{...input,tenantId:tenant.toUpperCase().replace('1000','AAAA')},{...input,extra:true}])await reject(protocol.tickApproval(value));
  await reject(protocol.pendingApprovals('not-uuid'));await reject(protocol.ackApproval({...delivery,eventId:'bad'}));assert.equal(called,0);
});

function dispatchFixture(status:ApprovalStatus='ready'){
  const calls:string[]=[];const protocol:ApprovalProtocol={pendingApprovals:async()=>({items:[]}),tickApproval:async value=>{assert.deepEqual(value,input);calls.push('tick-publish');return {...ready,status:'succeeded',version:3};},
    approvalStatus:async value=>{assert.deepEqual(value,input);calls.push('status');return {...ready,status,nextWakeAt:status==='pending'?pending.nextWakeAt:null};},
    ackApproval:async value=>{assert.deepEqual(value,delivery);calls.push('ack');}};
  return {calls,protocol};
}
test('accepted signal-with-start is acknowledged only after acceptance without a mutating readback',async()=>{
  const {calls,protocol}=dispatchFixture();await dispatchApprovalEvent(delivery,protocol,async(value,id)=>{
    assert.deepEqual(value,input);assert.equal(id,event);calls.push('signal');return 'accepted';
  });assert.deepEqual(calls,['signal','ack']);
});

test('closed executions acknowledge only canonical non-pending states and never implicitly restart',async()=>{
  for(const status of ['ready','rejected','cancelled','expired','succeeded','failed'] as const){
    const {calls,protocol}=dispatchFixture(status);await dispatchApprovalEvent(delivery,protocol,async()=>{calls.push('signal');return 'closed';});
    assert.deepEqual(calls,status==='ready'?['signal','status','tick-publish','ack']:['signal','status','ack']);
  }
  const {calls,protocol}=dispatchFixture('pending');await reject(dispatchApprovalEvent(delivery,protocol,async()=>{calls.push('signal');return 'closed';}),'APPROVAL_CLOSED_PENDING');
  assert.deepEqual(calls,['signal','status']);
});

test('transient signal/status failures and unknown acceptance never acknowledge; ack failures remain visible',async()=>{
  const f=dispatchFixture();await assert.rejects(dispatchApprovalEvent(delivery,f.protocol,async()=>{throw new Error('unavailable');}));assert.deepEqual(f.calls,[]);
  await reject(dispatchApprovalEvent(delivery,f.protocol,async()=>'unknown' as any));assert.deepEqual(f.calls,[]);
  f.protocol.approvalStatus=async()=>{throw new Error('readback unavailable');};await assert.rejects(dispatchApprovalEvent(delivery,f.protocol,async()=>'closed'));assert.deepEqual(f.calls,[]);
  f.protocol.ackApproval=async()=>{throw new Error('ack unavailable');};await assert.rejects(dispatchApprovalEvent(delivery,f.protocol,async()=>'accepted'));
});


test('actual HTTP ready tick commits before a separate ID-only publication and returns only canonical terminal status',async t=>{
 const seen:{path:string|undefined;body:string}[]=[];
 const succeeded={...ready,status:'succeeded',version:3};
 const url=await server(t,(req,res)=>{let body='';req.on('data',chunk=>body+=chunk);req.on('end',()=>{
  seen.push({path:req.url,body});res.setHeader('Content-Type','application/json');
  res.end(JSON.stringify(req.url?.endsWith('/publish')?succeeded:ready));
 });});
 const protocol=createApprovalActivities({apiUrl:url,token:'synthetic'});
 assert.deepEqual(await protocol.tickApproval(input),succeeded);
 assert.deepEqual(seen,[{path:`/internal/approvals/${request}/tick`,body:'{}'},{path:`/internal/approvals/${request}/publish`,body:'{}'}]);
});

test('publication refusal and nonterminal or stale output never become completed approval',async()=>{
 for(const value of [ready,pending,{...ready,status:'succeeded',version:1},{...ready,status:'failed',id:other}]){
  const paths:string[]=[];const protocol=createApprovalActivities({apiUrl:'http://127.0.0.1',token:'synthetic',fetch:async url=>{paths.push(String(url));return json(paths.length===1?ready:value);}});
  await reject(protocol.tickApproval(input));assert.equal(paths.length,2);assert.ok(paths[1].endsWith('/publish'));
 }
 for(const status of [409,500,503]){
  let count=0;const protocol=createApprovalActivities({apiUrl:'http://127.0.0.1',token:'synthetic',fetch:async()=>++count===1?json(ready):new Response('private failure',{status})});
  await reject(protocol.tickApproval(input),'APPROVAL_HTTP_REFUSED');assert.equal(count,2);
 }
});

test('publication has a separate bounded HTTP deadline and aborts the stalled request',async()=>{
 let count=0,signal:AbortSignal|undefined;
 const protocol=createApprovalActivities({apiUrl:'http://127.0.0.1',token:'synthetic',timeoutMs:100,publicationTimeoutMs:30,fetch:async(_url,init)=>{
  if(++count===1)return json(ready);signal=init?.signal as AbortSignal;return new Promise(()=>{});
 }});
 const started=Date.now();await reject(protocol.tickApproval(input),'APPROVAL_HTTP_TIMEOUT');assert.ok(Date.now()-started<1000);assert.equal(signal?.aborted,true);
 for(const publicationTimeoutMs of [0,35001,0.5])assert.throws(()=>createApprovalActivities({apiUrl:'http://api',token:'synthetic',publicationTimeoutMs}),/APPROVAL_CONFIG_INVALID/);
});

test('closed ready recovery uses actual status tick and publication requests before acknowledgement',async t=>{
 const paths:string[]=[];const url=await server(t,(req,res)=>{req.resume();req.on('end',()=>{
  paths.push(req.url!);res.setHeader('Content-Type','application/json');res.end(JSON.stringify(req.url?.endsWith('/ack')?{id:event,acknowledged:true}:req.url?.endsWith('/publish')?{...ready,status:'succeeded',version:3}:ready));
 });});
 const protocol=createApprovalActivities({apiUrl:url,token:'synthetic'});await dispatchApprovalEvent(delivery,protocol,async()=> 'closed');
 assert.deepEqual(paths,[`/internal/approvals/${request}/status`,`/internal/approvals/${request}/tick`,`/internal/approvals/${request}/publish`,`/internal/approvals/dispatch/${event}/ack`]);
});

test('closed ready recovery never acknowledges transient publication errors or ready/pending readback',async()=>{
 for(const status of ['ready','pending'] as const){const f=dispatchFixture();f.protocol.tickApproval=async()=>({...ready,status,nextWakeAt:status==='pending'?pending.nextWakeAt:null});
  await reject(dispatchApprovalEvent(delivery,f.protocol,async()=> 'closed'),'APPROVAL_CLOSED_READY');assert.deepEqual(f.calls,['status']);}
 const f=dispatchFixture();f.protocol.tickApproval=async()=>{throw new Error('APPROVAL_HTTP_UNAVAILABLE');};
 await reject(dispatchApprovalEvent(delivery,f.protocol,async()=> 'closed'),'APPROVAL_HTTP_UNAVAILABLE');assert.deepEqual(f.calls,['status']);
});
