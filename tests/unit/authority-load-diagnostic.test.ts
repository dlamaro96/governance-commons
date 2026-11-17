// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {observeOwnerPool} from '../fixtures/authority-load-diagnostic.ts';

test('diagnostic forwards exact connection/query/parameters/result and release without adding SQL',async()=>{
 const values=['PRIVATE_SESSION','PRIVATE_SELECTORS'];const calls:unknown[]=[];const result={rows:[{privateValue:'PRIVATE_RESULT'}]};let clock=0;
 const observed=observeOwnerPool({async connect(){calls.push('connect');return {async query(text,parameters){calls.push([text,parameters]);clock+=7;return result;},release(error){calls.push(['release',error]);}}; }},()=>clock);
 const client=await observed.pool.connect();clock=11;
 assert.equal(await client.query('SELECT gc_authority.load_human_closure_v1($1::text,$2::text) AS closure',values),result);
 client.release(true);assert.deepEqual(calls,['connect',['SELECT gc_authority.load_human_closure_v1($1::text,$2::text) AS closure',values],['release',true]]);
 assert.deepEqual(observed.snapshot(),{elapsedMs:18,phases:[{phase:'connect',startedMs:0,elapsedMs:0,outcome:'fulfilled'},{phase:'closure',startedMs:11,elapsedMs:7,outcome:'fulfilled'}]});
 assert.ok(!JSON.stringify(observed.snapshot()).includes('PRIVATE'));
});
test('original rejection identity is preserved; arbitrary SQL and error details are never emitted',async()=>{
 const error=Object.assign(new Error('PRIVATE_ERROR'),{code:'PRIVATE_CODE'});let now=0;
 const o=observeOwnerPool({async connect(){return {async query(){now=9;throw error;},release(){}};}},()=>now),c=await o.pool.connect();
 await assert.rejects(c.query('PRIVATE_SQL',['PRIVATE_PARAM']),e=>e===error);
 assert.deepEqual(o.snapshot().phases.at(-1),{phase:'unclassified',startedMs:0,elapsedMs:9,outcome:'rejected'});
 assert.ok(!JSON.stringify(o.snapshot()).includes('PRIVATE'));
});
test('inter-query validation gaps stay visible without synthetic waits, timer resets or retry',async()=>{
 let now=0,calls=0;const o=observeOwnerPool({async connect(){return {async query(){calls++;now+=3;return {rows:[]};},release(){}};}},()=>now),c=await o.pool.connect();
 await c.query('SELECT registry_document FROM gc_authority.registries WHERE id=$1::uuid');now+=6000;await c.query('COMMIT');
 const rows=o.snapshot().phases;assert.equal(rows[2]!.startedMs-rows[1]!.startedMs-rows[1]!.elapsedMs,6000);assert.equal(calls,2);
});
test('capture remains finite, detached and metadata-only after repeated queries',async()=>{
 let now=0;const o=observeOwnerPool({async connect(){return {async query(){now++;return {rows:[]};},release(){}};}},()=>now),c=await o.pool.connect();
 for(let i=0;i<40;i++)await c.query('COMMIT');assert.equal(o.snapshot().phases.length,32);
 const snapshot=o.snapshot();snapshot.phases.length=0;assert.equal(o.snapshot().phases.length,32);
});
