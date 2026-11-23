// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import { request as httpRequest, type IncomingHttpHeaders } from 'node:http';
import assert from 'node:assert/strict';
import { AUTHN_LIMITS } from '../../packages/authn/src/contracts.ts';
import { strictJson, strictQuery, createAuthnApp, cookies, cookieNames, setAuthnCookie, clearAuthnCookies,
 validatePublicAuthnConfig, randomSecret, sha256, equalSecret, requestAbortSignal } from '../../packages/authn/src/transport.ts';
import { nativePoolOptions } from '../../packages/authn/src/pool.ts';
const config = { publicOrigin: 'http://localhost:4314', environment: 'isolated-test' as const };
const host = { host: 'localhost:4314' };

test('protected JSON rejects duplicate keys, invalid UTF8, depth, nodes and byte excess', () => {
 assert.deepEqual(JSON.parse(JSON.stringify(strictJson('{"n":1,"b":false,"empty":null}', 2048))), { n:1, b:false, empty:null });
 for (const input of ['{"n":1,"n":2}', '{"n":1,"\\u006e":2}', '{"nested":{"n":1,"n":2}}', '{"n":1e999}', '[[[[[[[[0]]]]]]]]', '"\\ud800"']) assert.throws(() => strictJson(input, 2048));
 assert.throws(() => strictJson(Uint8Array.from([0xc3,0x28]), 2048));
 assert.throws(() => strictJson('"'+'é'.repeat(1024)+'"', 2048));
 assert.throws(() => strictJson(JSON.stringify(Array(2048).fill(null)), AUTHN_LIMITS.jwksBytes));
 assert.equal((strictJson(JSON.stringify(Array(2047).fill(null)), AUTHN_LIMITS.jwksBytes) as unknown[]).length, 2047);
 assert.throws(() => strictJson('{"__proto__":{"polluted":true},"__proto__":1}', 2048));
 assert.equal(({} as {polluted?:boolean}).polluted, undefined);
});
test('protected query checks original encoding, duplicate decoded keys and bounds', () => {
 assert.deepEqual(strictQuery('/authn/callback?code=a%2Bb&state=xyz'), { code:'a+b', state:'xyz' });
 assert.deepEqual(strictQuery('/authn/login'), {});
 for (const url of ['/authn/callback?', '/authn/callback?a=1&a=2', '/authn/callback?state=1&%73tate=2', '/authn/callback?a=%C3%28', '/authn/callback?a=%00', '/authn/callback?a=%', '/authn/callback?a=1&&b=2', '/authn/callback?x', '//evil.invalid/?a=1', '/authn/callback?a='+ 'x'.repeat(8192)]) assert.throws(() => strictQuery(url));
});
test('protected config and native pools reject origin/credential fallback and pin timeout settings', () => {
 assert.deepEqual(cookieNames(config), {session:'gc_authn_session',csrf:'gc_authn_csrf',attempt:'gc_authn_attempt'});
 assert.equal(cookieNames({publicOrigin:'https://app.example',environment:'production'}).session,'__Host-gc_authn_session');
 for (const publicOrigin of ['http://remote.example','https://remote.example','https://localhost:4314','http://localhost:4314/','http://user@localhost:4314','HTTP://localhost:4314','http://localhost:4314#x','http://localhost:4314/path']) assert.throws(()=>validatePublicAuthnConfig({...config,publicOrigin}));
 assert.throws(()=>validatePublicAuthnConfig({publicOrigin:'http://localhost:4314',environment:'production'}));
 const options=nativePoolOptions('api','postgresql://gc_authn_api:synthetic%2Dpassword@postgres:5432/governance','isolated-test');
 assert.equal(options.user,'gc_authn_api'); assert.equal(options.max,4); assert.equal(options.connectionTimeoutMillis,5000);
 assert.equal(options.statement_timeout,5000); assert.equal(options.lock_timeout,2000); assert.equal(options.idle_in_transaction_session_timeout,5000);
 assert.equal(options.options,'-c statement_timeout=5000 -c lock_timeout=2000 -c idle_in_transaction_session_timeout=5000');
 assert.deepEqual(nativePoolOptions('login','postgres://gc_authn_login:synthetic@db.example/governance','production').ssl,{rejectUnauthorized:true});
 for(const url of ['', 'postgres://gc_app:synthetic@postgres/governance','postgres://gc_owner:synthetic@postgres/governance','postgres://gc_authn_api:synthetic@postgres/governance?options=-crole%3Dgc_owner','postgres://gc_authn_api@postgres/governance','postgres://gc_authn_api:synthetic@postgres/','file:///tmp/socket']) assert.throws(()=>nativePoolOptions('api',url,'isolated-test'));
});
test('real Fastify transport enforces host, duplicate headers, raw body and safe failure redaction', async () => {
 const app=await createAuthnApp(config);let calls=0;app.post('/authn/probe',async(request,reply)=>{calls++;return reply.type('application/json').send({body:request.body});});app.get('/authn/error',async()=>{throw Error('private credential must not appear');});
 try {
  const valid=await app.inject({method:'POST',url:'/authn/probe',headers:{...host,'content-type':'application/json'},payload:'{"n":1}'});assert.equal(valid.statusCode,200);assert.deepEqual(valid.json(),{body:{n:1}});
  for(const payload of ['{"x":1,"x":2}','{"x":1,"\\u0078":2}','x'.repeat(2049)]) {const response=await app.inject({method:'POST',url:'/authn/probe',headers:{...host,'content-type':'application/json'},payload});assert.equal(response.statusCode,400);}
  for(const headers of [{host:'wrong.invalid'},{...host,origin:['https://one.invalid','https://two.invalid']},{...host,'x-csrf-token':['a','b']},{...host,cookie:['a=b','c=d']}]) {const response=await app.inject({method:'POST',url:'/authn/probe',headers:{...headers,'content-type':'application/json'} as unknown as IncomingHttpHeaders,payload:'{}'});assert.equal(response.statusCode,400);}
  assert.equal(calls,1);
  const error=await app.inject({url:'/authn/error',headers:host});assert.equal(error.statusCode,503);assert.equal(error.body.includes('private credential'),false);assert.match(error.json().correlationId,/^[0-9a-f-]{36}$/);assert.equal(error.headers['cache-control'],'no-store');assert.equal(error.headers['referrer-policy'],'no-referrer');assert.match(String(error.headers['content-security-policy']),/frame-ancestors 'none'/);assert.equal(error.headers['access-control-allow-origin'],undefined);
  assert.equal((await app.inject({method:'HEAD',url:'/authn/error',headers:host})).statusCode,404);
 } finally {await app.close();}
});
test('cookie families reject duplicates and serialize matching secure clear attributes',async()=>{
 for(const selected of [config,{publicOrigin:'https://app.example',environment:'production' as const}]){
  const app=await createAuthnApp(selected);const names=cookieNames(selected);const value=randomSecret();app.get('/authn/cookies',async(request,reply)=>{const jar=cookies(request,selected);setAuthnCookie(reply,selected,'session',value,new Date(Date.now()+100_000).toISOString());clearAuthnCookies(reply,selected,['csrf','attempt']);return jar;});
  try {const h={host:new URL(selected.publicOrigin).host};const response=await app.inject({url:'/authn/cookies',headers:{...h,cookie:names.session+'='+value}});assert.equal(response.statusCode,200);const set=response.headers['set-cookie']as string[];assert.equal(set.length,selected.environment==='production'?3:5);assert.ok(set.every(x=>x.includes('HttpOnly')&&x.includes('SameSite=Lax')&&!x.includes('Domain=')));assert.ok(set.every(x=>x.includes('; Secure')===(selected.environment==='production')));if(selected.environment==='production')assert.ok(set.every(x=>x.includes('Path=/;')));else{assert.equal(set.filter(x=>x.includes('Path=/authn;')).length,3);assert.equal(set.filter(x=>x.includes('Path=/;')).length,2);assert.match(set[0]!,/^gc_authn_session=; Path=\/authn;.*Max-Age=0/);assert.match(set[1]!,/^gc_authn_session=[A-Za-z0-9_-]{43}; Path=\/;/);}assert.ok(set.at(-1)!.includes('Max-Age=0'));assert.equal(response.json().session,value);
   for(const cookie of [names.session+'='+value+'; '+names.session+'='+value,names.session+'=percent%2Dvalue','__Host-gc_authn_session='+value+'; gc_authn_session='+value]) assert.equal((await app.inject({url:'/authn/cookies',headers:{...h,cookie}})).statusCode,400);
  }finally{await app.close();}
 }
});
test('real process admission retains16 occupied handlers and refuses excess',async()=>{
 const app=await createAuthnApp(config);let started=0;const releases:(()=>void)[]=[];app.get('/authn/wait',async request=>{started++;await new Promise<void>(resolve=>releases.push(resolve));assert.equal(requestAbortSignal(request).aborted,false);return {done:true};});
 const pending=Array.from({length:16},()=>app.inject({url:'/authn/wait',headers:host}));
 try{while(started!==16)await new Promise(resolve=>setImmediate(resolve));assert.equal((await app.inject({url:'/authn/wait',headers:host})).statusCode,503);assert.equal(started,16);releases.forEach(resolve=>resolve());assert.ok((await Promise.all(pending)).every(x=>x.statusCode===200));}finally{releases.forEach(resolve=>resolve());await app.close();}
});
test('login rate identity ignores forged forwarding headers and request IDs',async()=>{
 const app=await createAuthnApp(config,{loginRateLimit:true});app.get('/authn/login',async()=>({ready:true}));app.get('/health/ready',async()=>({ready:true}));try{for(let i=0;i<35;i++)assert.equal((await app.inject({url:'/health/ready',headers:host})).statusCode,200);for(let i=0;i<30;i++){const response=await app.inject({url:'/authn/login',headers:{...host,'x-forwarded-for':'203.0.113.'+i,'x-request-id':'attacker'}});assert.equal(response.statusCode,200);assert.notEqual(response.headers['x-correlation-id'],'attacker');}assert.equal((await app.inject({url:'/authn/login',headers:{...host,'x-forwarded-for':'different'}})).statusCode,429);}finally{await app.close();}
});
test('transport secrets are independent32byte values with exact constant-time equality',()=>{
 const a=randomSecret(),b=randomSecret();assert.match(a,/^[A-Za-z0-9_-]{43}$/);assert.notEqual(a,b);assert.equal(Buffer.from(a,'base64url').length,32);assert.equal(equalSecret(a,a),true);assert.equal(equalSecret(a,b),false);assert.equal(equalSecret(a,a+'x'),false);assert.match(sha256(a),/^[0-9a-f]{64}$/);
});

test('actual HTTP parser oversizedheaders failclosed withsafeJSON correlation andnoprivateecho',async()=>{
 const app=await createAuthnApp(config);let calls=0;app.get('/authn/session',async()=>{calls++;return {unsafe:true};});
 try{const address=await app.listen({host:'127.0.0.1',port:0});const result=await new Promise<{status:number|undefined;headers:IncomingHttpHeaders;body:string}>((resolve,reject)=>{const req=httpRequest(address+'/authn/session',{headers:{...host,'x-private-probe':'do-not-echo-'+ 'x'.repeat(17_000)}},response=>{let body='';response.setEncoding('utf8');response.on('data',part=>{body+=part;});response.on('end',()=>resolve({status:response.statusCode,headers:response.headers,body}));});req.on('error',reject);req.end();});assert.equal(result.status,400);assert.equal(result.headers['content-type'],'application/problem+json');assert.equal(result.headers['cache-control'],'no-store');assert.equal(result.body.includes('do-not-echo'),false);const body=JSON.parse(result.body);assert.equal(body.code,'AUTHN_REQUEST_INVALID');assert.match(body.correlationId,/^[0-9a-f-]{36}$/);assert.equal(result.headers['x-correlation-id'],body.correlationId);assert.equal(calls,0);}finally{await app.close();}
});


test('shared rate budget covers all routes and refuses before handler work with safe errors', async () => {
 const app = await createAuthnApp(config);
 let calls = 0;
 app.get('/authn/one', async () => { calls++; return { ready: true }; });
 app.post('/authn/two', async () => { calls++; return { ready: true }; });
 try {
  for (let index = 0; index < AUTHN_LIMITS.requestsPerMinute; index++) {
   const response = await app.inject({ method: index % 2 ? 'POST' : 'GET', url: index % 2 ? '/authn/two' : '/authn/one',
    remoteAddress: '192.0.2.1', headers: { ...host, 'x-forwarded-for': `203.0.113.${index}`, 'x-request-id': 'forged' } });
   assert.equal(response.statusCode, 200);
  }
  for (const url of ['/authn/one', '/authn/two']) {
   const response = await app.inject({ method: url.endsWith('two') ? 'POST' : 'GET', url, remoteAddress: '192.0.2.1',
    headers: { ...host, 'x-forwarded-for': '198.51.100.2', forwarded: 'for=198.51.100.3' } });
   assert.equal(response.statusCode, 429);
   assert.equal(response.json().code, 'AUTHN_RATE_LIMITED');
   assert.equal(response.json().status, 429);
   assert.equal(response.headers['cache-control'], 'no-store');
   assert.equal(response.headers['content-type'], 'application/problem+json; charset=utf-8');
   assert.equal(response.headers['x-content-type-options'], 'nosniff');
   assert.match(response.json().correlationId, /^[0-9a-f-]{36}$/);
   assert.equal(response.headers['x-correlation-id'], response.json().correlationId);
   assert.ok(Number(response.headers['retry-after']) > 0);
   assert.equal(response.headers['set-cookie'], undefined);
  }
  assert.equal(calls, AUTHN_LIMITS.requestsPerMinute);
  assert.equal((await app.inject({ url: '/authn/one', remoteAddress: '192.0.2.2', headers: host })).statusCode, 200);
  assert.equal(calls, AUTHN_LIMITS.requestsPerMinute + 1);
 } finally { await app.close(); }
});

test('JSON transport fixture cannot reflect a submitted HTML string as an HTML document', async () => {
 const app = await createAuthnApp(config);
 app.post('/authn/probe', async (request, reply) => reply.type('application/json').send({ body: request.body }));
 try {
  const value = '<script>syntheticProbe()</script>';
  const response = await app.inject({ method: 'POST', url: '/authn/probe', headers: { ...host, 'content-type': 'application/json' }, payload: JSON.stringify(value) });
  assert.equal(response.statusCode, 200);
  assert.equal(response.headers['content-type'], 'application/json; charset=utf-8');
  assert.equal(response.headers['x-content-type-options'], 'nosniff');
  assert.deepEqual(response.json(), { body: value });
 } finally { await app.close(); }
});
