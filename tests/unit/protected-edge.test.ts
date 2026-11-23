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
  const token=randomBytes(32).toString('base64url');setCookie=`gc_authn_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`;
  const good=await request(address,'/authn/session');assert.equal(good.status,200);assert.deepEqual(good.headers['set-cookie'],[setCookie]);assert.equal(good.headers['access-control-allow-origin'],undefined);
  assert.equal((await request(address,'/api/v1/example')).status,503);
  for(const attribute of ['; Domain=localhost','; Path=/authn','; Secure','; SameSite=None']){setCookie=`gc_authn_session=${token}; Path=/; HttpOnly; SameSite=Lax${attribute}`;assert.equal((await request(address,'/authn/session')).status,503);}
 }finally{await close(edge);await close(backend);}
});

test('legacy and application payloads stream past the small authentication-body cap',async()=>{
 for(const mode of ['legacyUpstream','applicationUpstream'] as const){
 const backend=http.createServer((req,res)=>{let size=0;req.on('data',chunk=>size+=chunk.length);req.on('end',()=>res.end(String(size)));});const target=await listen(backend);
 const edge=createAuthnEdge({publicOrigin:origin,environment:'isolated-test',loginUpstream:target,sessionUpstream:target,[mode]:target});const address=await listen(edge);
 try{const result=await request(address,'/api/v1/example',{},'x'.repeat(65536),'POST');assert.equal(result.status,200);assert.equal(result.body,'65536');}finally{await close(edge);await close(backend);}
 }
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

 test('application and legacy upstreams are mutually exclusive, including empty supplied values',()=>{
 for(const legacyUpstream of ['http://127.0.0.1:4310',''])assert.throws(()=>createAuthnEdge({publicOrigin:origin,environment:'isolated-test',loginUpstream:'http://127.0.0.1:4312',sessionUpstream:'http://127.0.0.1:4313',applicationUpstream:'http://127.0.0.1:4310',legacyUpstream}),/AUTHN_EDGE_CONFIG_INVALID/);
});
 test('application forwarding admits only exact session and CSRF cookies and rejects duplicate credentials',async()=>{
 const observed:http.IncomingHttpHeaders[]=[];
 const backend=http.createServer((req,res)=>{observed.push(req.headers);req.resume();res.end('ok');});const target=await listen(backend);
 const edge=createAuthnEdge({publicOrigin:origin,environment:'isolated-test',loginUpstream:target,sessionUpstream:target,applicationUpstream:target});const address=await listen(edge);
 const session=randomBytes(32).toString('base64url'),csrf=randomBytes(32).toString('base64url');
 try{
  const cookie=`gc_session=legacy; gc_authn_attempt=synthetic-attempt; __Host-gc_authn_session=${session}; gc_authn_session=${session}; gc_authn_csrf=${csrf}; preference=dark`;
  assert.equal((await request(address,'/api/v1/me',{cookie,'x-authenticated-user':'forged','x-principal-id':'forged','x-user-id':'forged','x-identity-id':'forged','x-roles':'forged','x-permissions':'forged','remote-user':'forged','x-forwarded-host':'forged','x-gc-authn-session':'forged','x-csrf-token':csrf})).status,200);
  assert.equal(observed[0]!.cookie,`gc_authn_session=${session}; gc_authn_csrf=${csrf}`);assert.equal(observed[0]!['x-csrf-token'],csrf);
  for(const header of ['x-authenticated-user','x-principal-id','x-user-id','x-identity-id','x-roles','x-permissions','remote-user','x-forwarded-host','x-gc-authn-session'])assert.equal(observed[0]![header],undefined);
  for(const cookie of [`gc_authn_session=${session}; gc_authn_session=${session}`,`gc_authn_csrf=${csrf}; gc_authn_csrf=${csrf}`,'gc_authn_session=bad%20token','malformed'])assert.equal((await request(address,'/api/v1/me',{cookie})).status,400);
  assert.equal((await request(address,'/api/v1/me',{'x-csrf-token':['one','two']})).status,400);assert.equal(observed.length,1);
  assert.equal((await request(address,'/api/v1/me',{cookie:'gc_session=legacy'})).status,200);assert.equal(observed[1]!.cookie,undefined);
 }finally{await close(edge);await close(backend);}
});
 test('application cannot mint protected cookies and old path clears are narrowly admitted from authn only',async()=>{
 let value='';const backend=http.createServer((_req,res)=>{res.setHeader('set-cookie',value);res.end('ok');});const target=await listen(backend);
 const edge=createAuthnEdge({publicOrigin:origin,environment:'isolated-test',loginUpstream:target,sessionUpstream:target,applicationUpstream:target});const address=await listen(edge);
 try{
  for(const name of ['session','csrf']){
   value=`gc_authn_${name}=; Path=/authn; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
   assert.equal((await request(address,'/authn/session')).status,200);assert.equal((await request(address,'/api/v1/me')).status,503);
   for(const bad of [value.replace('=;','=x;'),value.replace('Max-Age=0','Max-Age=1'),value.replace('1970','2099'),value.replace('; Expires=Thu, 01 Jan 1970 00:00:00 GMT','')]){
    const valid=value;value=bad;assert.equal((await request(address,'/authn/session')).status,503);value=valid;
   }
  }
  value=`gc_authn_session=${randomBytes(32).toString('base64url')}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300`;
  assert.equal((await request(address,'/api/v1/me')).status,503);assert.equal((await request(address,'/authn/session')).status,200);
 }finally{await close(edge);await close(backend);}
});

 test('production application forwarding accepts only __Host session and CSRF cookies',async()=>{
 const observed:http.IncomingHttpHeaders[]=[];let setCookie:string|undefined;
 const backend=http.createServer((req,res)=>{observed.push(req.headers);if(setCookie)res.setHeader('set-cookie',setCookie);res.end('ok');});const target=await listen(backend);
 const edge=createAuthnEdge({publicOrigin:'https://governance.example',environment:'production',loginUpstream:target,sessionUpstream:target,applicationUpstream:target});const address=await listen(edge);
 const token=randomBytes(32).toString('base64url');
 try{
  assert.equal((await request(address,'/api/v1/me',{host:'governance.example',cookie:`gc_authn_session=${token}; __Host-gc_authn_attempt=synthetic; __Host-gc_authn_session=${token}; __Host-gc_authn_csrf=${token}`})).status,200);
  assert.equal(observed[0]!.cookie,`__Host-gc_authn_session=${token}; __Host-gc_authn_csrf=${token}`);
  setCookie=`__Host-gc_authn_session=${token}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=300`;
  assert.equal((await request(address,'/authn/session',{host:'governance.example'})).status,200);
  assert.equal((await request(address,'/api/v1/me',{host:'governance.example'})).status,503);
  setCookie='__Host-gc_authn_session=; Path=/authn; HttpOnly; SameSite=Lax; Secure; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT';
  assert.equal((await request(address,'/authn/session',{host:'governance.example'})).status,503);
 }finally{await close(edge);await close(backend);}
});
