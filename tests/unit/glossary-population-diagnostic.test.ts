// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import type {PostgresPool,PostgresPoolClient} from 'kysely';
import {observePopulationPool} from '../fixtures/glossary-population-diagnostic.ts';
function pool(query:PostgresPoolClient['query'],release:(destroy?:boolean)=>void=()=>{}):PostgresPool{return {options:{},end:async()=>{},connect:async()=>({query,release})};}
test('population observation delegates exact native arguments results and release',async()=>{
 const result={rows:[{private:'PRIVATE_RESULT'}]},values=['PRIVATE_PARAMETER'];const calls:unknown[]=[];let now=0;
 const o=observePopulationPool(pool((async(...args:unknown[])=>{calls.push(args);now+=5;return result;}) as unknown as PostgresPoolClient['query'],v=>calls.push(v)),()=>now);
 const c=await o.pool.connect();o.phase('publication');now=10;assert.equal(await c.query('select public.gc_glossary_stage($1) as value',values),result);c.release(true);
 assert.deepEqual(calls,[['select public.gc_glossary_stage($1) as value',values],true]);assert.equal(o.snapshot().queries.at(-1)?.query,'stage');assert.equal(o.snapshot().queries.at(-1)?.elapsedMs,5);assert.ok(!JSON.stringify(o.snapshot()).includes('PRIVATE'));
});
test('population observation preserves rejected identity and only exports finite error metadata',async()=>{
 const error=Object.assign(new Error('PRIVATE_ERROR'),{code:'57014',detail:'PRIVATE_DETAIL'});
 const o=observePopulationPool(pool((async()=>{throw error;}) as unknown as PostgresPoolClient['query'])),c=await o.pool.connect();
 await assert.rejects(c.query('PRIVATE_SQL',['PRIVATE_VALUES']),e=>e===error);const snapshot=o.snapshot(error);assert.equal(snapshot.sqlstate,'57014');assert.equal(snapshot.queries.at(-1)?.sqlstate,'57014');assert.equal(snapshot.code,'UNCLASSIFIED');assert.ok(!o.failure(error).message.includes('PRIVATE'));
});
test('population observations retain latest failures with explicit truncation and detached bounded snapshots',async()=>{
 let now=0;const o=observePopulationPool(pool((async()=>{now++;return {rows:[]};}) as unknown as PostgresPoolClient['query']),()=>now),c=await o.pool.connect();
 for(let i=0;i<80;i++)await c.query('COMMIT',[]);o.phase('replay');const s=o.snapshot();assert.equal(s.queryCount,81);assert.equal(s.omittedQueries,17);assert.equal(s.queries.length,64);s.queries.length=0;assert.equal(o.snapshot().queries.length,64);assert.equal(o.snapshot().phase,'replay');
});
test('population diagnostics do not invoke error getters or expose arbitrary codes',()=>{
 let calls=0;const e=Object.defineProperty({},'code',{get(){calls++;throw Error('PRIVATE');}});const o=observePopulationPool(pool((async()=>({rows:[]})) as unknown as PostgresPoolClient['query']));assert.equal(o.snapshot(e).code,'UNCLASSIFIED');assert.equal(calls,0);assert.equal(o.snapshot({code:'PRIVATE'}).sqlstate,null);
});
test('native cursor overload passes through unchanged rather than becoming a Promise',async()=>{
 const cursor={read:async()=>[],close:async()=>{}},o=observePopulationPool(pool(((value:unknown)=>value) as unknown as PostgresPoolClient['query'])),c=await o.pool.connect();assert.equal(c.query(cursor),cursor);assert.equal(o.snapshot().queryCount,1);
});
test('population observer preserves cancellation constructor options and pooled client identity',async()=>{
 let ended=0,released=0;const options={application_name:'population-test'},client:PostgresPoolClient={processID:42,query:(async()=>({rows:[]})) as unknown as PostgresPoolClient['query'],release(){released++;}};
 const Client=function NativeControlClient(){} as unknown as NonNullable<PostgresPool['Client']>;
 const original:PostgresPool={Client,options,connect:async()=>client,end:async()=>{ended++;}};
 const o=observePopulationPool(original),first=await o.pool.connect();first.release();const second=await o.pool.connect();
 assert.equal(second,first);assert.equal(first.processID,42);assert.equal(o.pool.Client,Client);assert.equal(o.pool.options,options);assert.equal(released,1);await o.pool.end();assert.equal(ended,1);assert.equal(o.snapshot().queryCount,2);
});
