// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import Fastify from 'fastify';
import rateLimit from '@fastify/rate-limit';
import {apiErrorHandler} from '../../apps/api/src/http-errors.ts';
import {Problem} from '../../packages/authz/src/index.ts';
const internal='private-diagnostic-must-not-escape';
const safe429={type:'about:blank',title:'Too many requests',status:429,code:'RATE_LIMITED',detail:'Too many requests. Please wait, then retry.',correlationId:'synthetic-correlation'};
const app=()=>{const value=Fastify({logger:false,trustProxy:false,genReqId:()=> 'synthetic-correlation'});value.setErrorHandler(apiErrorHandler);return value;};
const headers=['retry-after','x-ratelimit-limit','x-ratelimit-remaining','x-ratelimit-reset'] as const;
test('actual global limiter returns safe actionable429 with exact plugin retry/quota headers before route effects',async()=>{
 const f=app();let calls=0,before:Record<string,unknown>|null=null;
 await f.register(rateLimit,{max:2,timeWindow:'1 minute'});
 f.addHook('onError',async(_req,reply,error)=>{if(error.statusCode===429)before=Object.fromEntries(headers.map(name=>[name,reply.getHeader(name)]));});
 f.get('/first',async()=>{calls++;return {ok:true};});f.post('/second',async()=>{calls++;return {ok:true};});
 try{assert.equal((await f.inject('/first')).statusCode,200);assert.equal((await f.inject({method:'POST',url:'/second'})).statusCode,200);const r=await f.inject('/first');assert.equal(r.statusCode,429);assert.deepEqual(r.json(),safe429);assert.match(String(r.headers['content-type']),/^application\/problem\+json/);assert.equal(calls,2);assert.ok(before);for(const name of headers)assert.equal(String(r.headers[name]),String(before[name]));assert.equal(String(r.headers['x-ratelimit-limit']),'2');assert.equal(String(r.headers['x-ratelimit-remaining']),'0');const retry=Number(r.headers['retry-after']);assert.ok(Number.isInteger(retry)&&retry>=1&&retry<=60);assert.equal(retry,Number(r.headers['x-ratelimit-reset']));}finally{await f.close();}
});
test('a limiter-specific internal message and code cannot escape the stable429 problem',async()=>{
 const f=app();await f.register(rateLimit,{max:1,timeWindow:'1 minute',errorResponseBuilder:()=>Object.assign(new Error(internal),{statusCode:429,code:internal,detail:internal})});f.get('/limited',async()=>({ok:true}));
 try{assert.equal((await f.inject('/limited')).statusCode,200);const r=await f.inject('/limited');assert.equal(r.statusCode,429);assert.deepEqual(r.json(),safe429);assert.equal(r.body.includes(internal),false);assert.ok(Number(r.headers['retry-after'])>=1);}finally{await f.close();}
});
test('unexpected4xx and500 retain prior generic redaction and status mapping',async()=>{
 const f=app();for(const status of [401,422,500,503])f.get('/unexpected/'+status,async()=>{throw Object.assign(new Error(internal),{statusCode:status,code:internal,detail:internal});});
 try{for(const status of [401,422,500,503]){const expected=status<500?status:500,r=await f.inject('/unexpected/'+status);assert.equal(r.statusCode,expected);assert.deepEqual(r.json(),{type:'about:blank',title:expected>=500?'Service unavailable':'Request rejected',status:expected,code:'INTERNAL_ERROR',detail:'The request could not be completed. Use the correlation ID for support.',correlationId:'synthetic-correlation'});assert.equal(r.body.includes(internal),false);assert.equal(r.headers['retry-after'],undefined);}}finally{await f.close();}
});
test('actual Fastify schema validation stays generic without echoing input or schema internals',async()=>{
 const f=app();f.post('/validate',{schema:{body:{type:'object',required:['count'],properties:{count:{type:'integer',minimum:1}},additionalProperties:false}}},async()=>({ok:true}));
 try{const r=await f.inject({method:'POST',url:'/validate',payload:{count:internal}});assert.equal(r.statusCode,400);assert.deepEqual(r.json(),{type:'about:blank',title:'Request rejected',status:400,code:'VALIDATION_FAILED',detail:'Check the submitted fields.',correlationId:'synthetic-correlation'});assert.equal(r.body.includes(internal),false);assert.equal(r.body.includes('minimum'),false);}finally{await f.close();}
});
test('known application problems preserve intended issues and relation retry guidance',async()=>{
 const f=app(),issues=[{code:'FORMAT',path:'/name',message:'Provide a name.'}];f.get('/known',async()=>{throw new Problem(422,'INPUT_INVALID','Check the name.',issues);});f.get('/retry',async()=>{throw new Problem(503,'RELATION_RETRY','Retry the same request.');});
 try{const r=await f.inject('/known');assert.equal(r.statusCode,422);assert.deepEqual(r.json(),{type:'about:blank',title:'Request rejected',status:422,code:'INPUT_INVALID',detail:'Check the name.',correlationId:'synthetic-correlation',issues});const retry=await f.inject('/retry');assert.equal(retry.statusCode,503);assert.equal(retry.headers['retry-after'],'5');assert.equal(retry.json().code,'RELATION_RETRY');assert.equal(retry.json().detail,'Retry the same request.');}finally{await f.close();}
});
test('application429 also gets the closed response, preserving existing retry header and hiding incidental issues',async()=>{
 const f=app();f.get('/application-limit',async(_req,reply)=>{reply.header('Retry-After','9');throw new Problem(429,internal,internal,[{code:internal,path:'/'+internal,message:internal}]);});
 try{const r=await f.inject('/application-limit');assert.equal(r.statusCode,429);assert.deepEqual(r.json(),safe429);assert.equal(r.headers['retry-after'],'9');assert.equal(r.body.includes(internal),false);}finally{await f.close();}
});
