// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { createAuthnEdge, edgeRoute } from '../../apps/authn-edge/src/server.ts';

const origin='http://localhost:4314';
async function listen(server:http.Server){await new Promise<void>((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;}
async function close(server:http.Server){server.closeAllConnections();await new Promise<void>(resolve=>server.close(()=>resolve()));}
async function request(base:string,path:string,headers:http.OutgoingHttpHeaders={},body='',method='GET'){
 return new Promise<{status:number;headers:http.IncomingHttpHeaders;body:string}>((resolve,reject)=>{
  const req=http.request(base,{path,method,headers:{host:'localhost:4314',...headers}},res=>{let value='';res.setEncoding('utf8');res.on('data',part=>value+=part);res.on('end',()=>resolve({status:res.statusCode!,headers:res.headers,body:value}));});
  req.on('error',reject);req.end(body);
 });
}

test('edge routes only exact protected paths and methods; ambiguous forms never use legacy',()=>{
 for(const [method,path,route] of [['GET','/authn/login','login'],['GET','/authn/callback?code=x&state=y','login'],['GET','/authn/','session'],['POST','/authn/logout','session'],['GET','/catalog','legacy'],['POST','/api/v1/sites/heartbeat','legacy']])assert.equal(edgeRoute(method!,path!),route);
 for(const path of ['http://localhost:4314/authn/login','//authn/login','/authn','/authn/unknown','/a/../authn/login','/a/%2e%2e/authn/login','/%61uthn/login','/authn%2flogin','/authn\\login','/authn//login','/authn/login#fragment'])assert.equal(edgeRoute('GET',path),'missing',path);
 assert.equal(edgeRoute('POST','/authn/login'),'missing');
 assert.equal(edgeRoute('HEAD','/authn/session'),'missing');
});

test('real edge keeps protected and legacy cookie families separate and fixes trusted Host',async()=>{
 const observed:{url:string;headers:http.IncomingHttpHeaders;body:string}[]=[];
 const backend=http.createServer((req,res)=>{let body='';req.on('data',chunk=>body+=chunk);req.on('end',()=>{observed.push({url:req.url!,headers:req.headers,body});res.end('ok');});});
 const target=await listen(backend),edge=createAuthnEdge({publicOrigin:origin,environment:'isolated-test',loginUpstream:target,sessionUpstream:target,legacyUpstream:target});
 const address=await listen(edge);
 try {
  const token=randomBytes(32).toString('base64url');
  const cookie=`gc_session=legacy; gc_authn_session=${token}; __Host-gc_authn_session=${token}`;
  assert.equal((await request(address,'/authn/session',{cookie,authorization:'Bearer synthetic','x-forwarded-host':'attacker.invalid','x-authn-principal':'invented'})).status,200);
  assert.equal(observed[0]!.headers.host,'localhost:4314');
  assert.equal(observed[0]!.headers.cookie,`gc_authn_session=${token}`);
  assert.equal(observed[0]!.headers.authorization,undefined);assert.equal(observed[0]!.headers['x-forwarded-host'],undefined);assert.equal(observed[0]!.headers['x-authn-principal'],undefined);
  assert.equal((await request(address,'/api/v1/example',{cookie,authorization:'Bearer synthetic','x-tenant-id':'synthetic-tenant','x-original-url':'/authn/session'},'body','POST')).status,200);
  assert.equal(observed[1]!.headers.cookie,'gc_session=legacy');
  assert.equal(observed[1]!.headers.authorization,'Bearer synthetic');assert.equal(observed[1]!.headers['x-tenant-id'],'synthetic-tenant');assert.equal(observed[1]!.headers['x-original-url'],undefined);assert.equal(observed[1]!.body,'body');
 }finally{await close(edge);await close(backend);}
});

test('real edge rejects wrong Host, oversized protected body and duplicate critical headers before upstream',async()=>{
 let calls=0;const backend=http.createServer((_req,res)=>{calls++;res.end('ok');});const target=await listen(backend);
 const edge=createAuthnEdge({publicOrigin:origin,environment:'isolated-test',loginUpstream:target,sessionUpstream:target});const address=await listen(edge);
 try{
  assert.equal((await request(address,'/authn/',{host:'attacker.invalid'})).status,400);
  assert.equal((await request(address,'/authn/logout',{'content-type':'application/json'},'x'.repeat(2049),'POST')).status,400);
  assert.equal((await request(address,'/authn/logout',{'x-csrf-token':['one','two']},'{}','POST')).status,400);
  assert.equal((await request(address,'/authn/unknown')).status,404);
  const oversized=await request(address,'/authn/',{'x-oversized':'x'.repeat(17_000)});
  assert.equal(oversized.status,400);assert.equal(JSON.parse(oversized.body).code,'AUTHN_REQUEST_INVALID');
  assert.equal(oversized.headers['cache-control'],'no-store');
  assert.equal(calls,0);
 }finally{await close(edge);await close(backend);}
});

test('edge enforces upstream cookie scope and preserves valid cookies, no CORS expansion',async()=>{
 let setCookie='gc_session=wrong; Path=/; HttpOnly';
 const backend=http.createServer((_req,res)=>{res.setHeader('set-cookie',setCookie);res.setHeader('access-control-allow-origin','*');res.end('ok');});const target=await listen(backend);
 const edge=createAuthnEdge({publicOrigin:origin,environment:'isolated-test',loginUpstream:target,sessionUpstream:target,legacyUpstream:target});const address=await listen(edge);
 try{
  assert.equal((await request(address,'/authn/session')).status,503);
  const token=randomBytes(32).toString('base64url');setCookie=`gc_authn_session=${token}; Path=/authn; HttpOnly; SameSite=Lax; Max-Age=300`;
  const good=await request(address,'/authn/session');assert.equal(good.status,200);assert.deepEqual(good.headers['set-cookie'],[setCookie]);assert.equal(good.headers['access-control-allow-origin'],undefined);
  assert.equal((await request(address,'/api/v1/example')).status,503);
  for(const attribute of ['; Domain=localhost','; Path=/','; Secure','; SameSite=None']){setCookie=`gc_authn_session=${token}; Path=/authn; HttpOnly; SameSite=Lax${attribute}`;assert.equal((await request(address,'/authn/session')).status,503);}
 }finally{await close(edge);await close(backend);}
});

test('legacy payloads stream past the small protected-body cap',async()=>{
 const backend=http.createServer((req,res)=>{let size=0;req.on('data',chunk=>size+=chunk.length);req.on('end',()=>res.end(String(size)));});const target=await listen(backend);
 const edge=createAuthnEdge({publicOrigin:origin,environment:'isolated-test',loginUpstream:target,sessionUpstream:target,legacyUpstream:target});const address=await listen(edge);
 try{const result=await request(address,'/api/v1/example',{},'x'.repeat(65536),'POST');assert.equal(result.status,200);assert.equal(result.body,'65536');}finally{await close(edge);await close(backend);}
});


test('protected edge uses one original wall deadline across slow body and upstream', {timeout:30_000}, async()=>{
 let upstreamCalls=0;
 const backend=http.createServer((req,_res)=>{upstreamCalls++;req.resume();});
 const target=await listen(backend);
 const edge=createAuthnEdge({publicOrigin:origin,environment:'isolated-test',loginUpstream:target,sessionUpstream:target});
 const address=await listen(edge);
 let bodyTimer:ReturnType<typeof setTimeout>|undefined;
 try {
  const started=performance.now();
  const result=await new Promise<{status:number;body:string}>((resolve,reject)=>{
   const req=http.request(address,{path:'/authn/logout',method:'POST',headers:{host:'localhost:4314','content-type':'application/json','content-length':'2'}},res=>{
    let body='';res.setEncoding('utf8');res.on('data',part=>body+=part);
    res.on('end',()=>resolve({status:res.statusCode!,body}));
   });
   req.on('error',reject);req.write('{');
   bodyTimer=setTimeout(()=>req.end('}'),12_000);
  });
  const elapsed=performance.now()-started;
  assert.equal(result.status,503);assert.equal(JSON.parse(result.body).code,'AUTHN_UNAVAILABLE');
  assert.equal(upstreamCalls,1);assert.ok(elapsed>=19_000 && elapsed<27_000,`original wall deadline elapsed ${elapsed}`);
 }finally{clearTimeout(bodyTimer);await close(edge);await close(backend);}
});
