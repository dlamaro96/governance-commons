// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {sortSnapshotRows} from '../fixtures/business-domains.ts';
import {typeHash} from '../../packages/domain/src/asset-type-policy.ts';
const previous=<T>(rows:readonly T[],hash:(row:T)=>string=typeHash)=>[...rows].sort((a,b)=>hash(a).localeCompare(hash(b)));

test('cached snapshot sort preserves complete opaque row bytes and original row identities',()=>{
 const rows=[
  {id:'b',payload:{constructor:'ordinary data','source/key':[null,true,2,{label:'مرحبا'}]},at:new Date('2026-11-17T00:00:00.000Z')},
  {id:'a',payload:{constructor:'ordinary data','source/key':[null,false,2,{label:'漢字'}]},at:new Date('2026-11-16T00:00:00.000Z')},
  {id:'c',payload:{constructor:'ordinary data','source/key':[null,true,200,{label:'retained'.repeat(500)}]},at:new Date('2026-11-15T00:00:00.000Z')},
 ];
 const inputBefore=JSON.stringify(rows),expected=previous(rows),actual=sortSnapshotRows(rows);
 assert.equal(JSON.stringify(actual),JSON.stringify(expected));
 assert.equal(JSON.stringify(rows),inputBefore);
 for(let i=0;i<rows.length;i++)assert.equal(actual[i],expected[i]);
});

test('duplicate occurrences and genuine hash ties keep stable input order without deduplication',()=>{
 const first={value:'duplicate'},second={value:'duplicate'},third={value:'different'};
 const rows=[first,second,first,third,second];let calls=0;
 const actual=sortSnapshotRows(rows,()=>{calls++;return 'same controlled digest';});
 assert.equal(calls,rows.length);assert.equal(actual.length,rows.length);
 assert.deepEqual(actual,previous(rows,()=> 'same controlled digest'));
 for(let i=0;i<rows.length;i++)assert.equal(actual[i],rows[i]);
 const sameDigest=[first,second,first];assert.equal(typeHash(first),typeHash(second));
 assert.deepEqual(sortSnapshotRows(sameDigest),sameDigest);
});

test('large full-row snapshot hashes once per occurrence with byte-identical former ordering',()=>{
 const rows=Array.from({length:4096},(_,i)=>({id:String((i*1543)%4096),version:i%17,
  envelope:{changes:{opaque:{'source/name':String(i),nested:[i,null,{'full-text':'Synthetic evidence '.repeat(12)}]}},actor:'synthetic',sequence:i}}));
 let beforeCalls=0,afterCalls=0;
 const expected=previous(rows,row=>{beforeCalls++;return typeHash(row);});
 const actual=sortSnapshotRows(rows,row=>{afterCalls++;return typeHash(row);});
 assert.equal(afterCalls,rows.length);assert.ok(beforeCalls>rows.length*2);
 assert.equal(JSON.stringify(actual),JSON.stringify(expected));
 assert.equal(new Set(actual).size,rows.length);
 for(let i=0;i<rows.length;i++)assert.equal(actual[i],expected[i]);
});

test('empty and singleton snapshots preserve rows and invoke no unnecessary hash',()=>{
 let calls=0;const hash=(row:{id:string})=>{calls++;return row.id;};
 assert.deepEqual(sortSnapshotRows([],hash),[]);assert.equal(calls,0);
 const row={id:'one'};assert.equal(sortSnapshotRows([row],hash)[0],row);assert.equal(calls,1);
});

test('hash failures propagate without silently returning an incomplete snapshot',()=>{
 const failure=new Error('controlled hash refusal'),rows=[{id:1},{id:2},{id:3}];
 assert.throws(()=>sortSnapshotRows(rows,row=>{if(row.id===2)throw failure;return String(row.id);}),error=>error===failure);
 assert.deepEqual(rows,[{id:1},{id:2},{id:3}]);
});
