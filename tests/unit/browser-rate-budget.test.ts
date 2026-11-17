// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test,{type TestContext} from 'node:test';
import type {APIRequestContext,APIResponse} from '@playwright/test';
import {waitForBrowserRateBudget} from '../fixtures/browser-rate-budget.ts';

/** Controlled host protocol only. These tests neither call a product service
 * nor claim that a real server window or a browser journey has been qualified. */
function harness(t:TestContext,steps:{status:number;remaining:string;reset:string;limit?:string;headers?:Record<string,string>}[]){
 let now=0,index=0;const calls:{path:string;timeout:number}[]=[],waits:number[]=[],disposed:number[]=[];
 t.mock.method(performance,'now',()=>now);
 t.mock.method(globalThis,'setTimeout',(callback:()=>void,delay:number)=>{waits.push(delay);now+=delay;queueMicrotask(callback);return {} as ReturnType<typeof setTimeout>;});
 const request={get:async(path:string,options:{timeout:number})=>{
  calls.push({path,timeout:options.timeout});const n=index++,step=steps[n];assert.ok(step,'No undeclared probe');
  return {status:()=>step.status,headers:()=>step.headers??{'x-ratelimit-limit':step.limit??'300','x-ratelimit-remaining':step.remaining,'x-ratelimit-reset':step.reset},dispose:async()=>{disposed.push(n);}} as unknown as APIResponse;
 }} as unknown as APIRequestContext;
 return {request,calls,waits,disposed,advance:(ms:number)=>{now+=ms;}};
}
test('browser admission requires the requested real headroom and uses only one disposed health probe when available',async t=>{
 const h=harness(t,[{status:200,remaining:'295',reset:'58'}]);await waitForBrowserRateBudget(h.request,295);
 assert.deepEqual(h.calls,[{path:'/health/live',timeout:5000}]);assert.deepEqual(h.waits,[]);assert.deepEqual(h.disposed,[0]);
});
test('browser admission waits the advertised reset before starting a heavy journey without replaying product work',async t=>{
 const h=harness(t,[{status:200,remaining:'294',reset:'1'},{status:200,remaining:'299',reset:'60'}]);await waitForBrowserRateBudget(h.request,295);
 assert.deepEqual(h.waits,[2000]);assert.deepEqual(h.disposed,[0,1]);assert.deepEqual(h.calls,[{path:'/health/live',timeout:5000},{path:'/health/live',timeout:5000}]);
});
test('browser admission handles a real limiter refusal with bounded reset chunks and preserves the legacy minimum',async t=>{
 const h=harness(t,[{status:429,remaining:'0',reset:'60'},{status:200,remaining:'40',reset:'60'}]);await waitForBrowserRateBudget(h.request);
 assert.deepEqual(h.waits,[30000,30000,1000]);assert.deepEqual(h.disposed,[0,1]);assert.equal(h.calls.length,2);
});
test('browser admission refuses invalid budgets before any network or timer operation',async t=>{
 const h=harness(t,[]);for(const value of [0,-1,296,1.5,NaN,Infinity])await assert.rejects(()=>waitForBrowserRateBudget(h.request,value),/Invalid browser rate admission budget/);
 assert.deepEqual(h.calls,[]);assert.deepEqual(h.waits,[]);assert.deepEqual(h.disposed,[]);
});
test('browser admission rejects malformed quota or contradictory refusal headers and always disposes responses',async t=>{
 const values=[{status:500,remaining:'0',reset:'1'},{status:200,remaining:'300',reset:'1',limit:'301'},{status:200,remaining:'301',reset:'1'},{status:200,remaining:'-1',reset:'1'},{status:200,remaining:'1.5',reset:'1'},{status:200,remaining:'0',reset:'61'},{status:200,remaining:'0',reset:'-1'},{status:200,remaining:'0',reset:'1',headers:{}},{status:429,remaining:'295',reset:'1'}];
 const h=harness(t,values);for(const _ of values)await assert.rejects(()=>waitForBrowserRateBudget(h.request,295));
 assert.deepEqual(h.disposed,values.map((_,i)=>i));assert.equal(h.calls.length,values.length);assert.deepEqual(h.waits,[]);
});
test('browser admission retains its original 130-second deadline across multiple advertised resets',async t=>{
 const h=harness(t,Array.from({length:3},()=>({status:200,remaining:'1',reset:'60'})));
 await assert.rejects(()=>waitForBrowserRateBudget(h.request,295),/Browser rate admission timed out/);
 assert.equal(h.calls.length,3);assert.deepEqual(h.disposed,[0,1,2]);assert.deepEqual(h.waits,[30000,30000,1000,30000,30000,1000]);assert.ok(h.calls.every(x=>x.timeout===5000));
});
test('browser admission caps probes and surfaces transport failures without retrying an application request',async t=>{
 const h=harness(t,Array.from({length:4},()=>({status:429,remaining:'0',reset:'0'})));
 await assert.rejects(()=>waitForBrowserRateBudget(h.request,295),/Browser rate admission unavailable/);assert.equal(h.calls.length,4);assert.deepEqual(h.disposed,[0,1,2,3]);assert.deepEqual(h.waits,[1000,1000,1000,1000]);
 const failure=new Error('Synthetic transport failure');let calls=0;
 const request={get:async()=>{calls++;throw failure;}} as unknown as APIRequestContext;
 await assert.rejects(()=>waitForBrowserRateBudget(request,295),error=>error===failure);assert.equal(calls,1);
});
