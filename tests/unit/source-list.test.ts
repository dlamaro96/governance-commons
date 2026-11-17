// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {test} from 'node:test';
import type {Tx} from '../../packages/db/src/index.ts';
import {Problem} from '../../packages/authz/src/index.ts';
import {signedCursor} from '../../packages/domain/src/cursor.ts';
import {listSources,type SourceListQuery} from '../../packages/connectors/src/source-list.ts';

const principal={tenantId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',id:'10000000-0000-4000-8000-000000000001'};
const unusedTx={selectFrom(){assert.fail('Invalid page must fail before database selection');}} as unknown as Tx;
const invalid=(error:unknown)=>error instanceof Problem&&error.status===400&&error.code==='SOURCE_PAGE_INVALID';
test('source pages refuse malformed selectors before any database query',async()=>{
 for(const value of [{limit:0},{limit:101},{limit:1.5},{limit:'1'},{limit:null},{q:null},{q:'x\n'},{q:'\u007f'},{q:'\ud800'},{q:'😀'.repeat(121)},{cursor:''},{cursor:'x'.repeat(1025)},{unknown:true},null,[]])
  await assert.rejects(listSources(unusedTx,principal,value as SourceListQuery),invalid);
 let reads=0;const query=Object.defineProperty({},'q',{enumerable:true,get(){reads++;return '';}});
 await assert.rejects(listSources(unusedTx,principal,query),invalid);assert.equal(reads,0);
});
test('source cursors require exact authenticated selectors and reject tampering or noncanonical payloads',async()=>{
 const previous=process.env.SESSION_KEY;process.env.SESSION_KEY='synthetic-source-list-unit-secret-32-bytes';
 try {
  const codec=signedCursor(process.env.SESSION_KEY,'source-inventory-v1');
  const binding=createHash('sha256').update(JSON.stringify({tenantId:principal.tenantId,actorId:principal.id,q:'review',limit:2,sort:'name:asc,id:asc'})).digest('base64url');
  const id='abcdefab-abcd-4abc-8abc-abcdefabcdef',encodedName=Buffer.from('review').toString('base64url');
  const value=[1,binding,encodedName,id],cursor=codec.encode(value);
  for(const [p,query] of [[{...principal,id:randomUUID()},{q:'review',limit:2,cursor}],[{...principal,tenantId:randomUUID()},{q:'review',limit:2,cursor}],[principal,{q:'changed',limit:2,cursor}],[principal,{q:'review',limit:3,cursor}]] as const)
   await assert.rejects(listSources(unusedTx,p,query),invalid);
  for(const payload of [[...value,true],value.slice(0,3),[2,binding,encodedName,id],[1,binding,encodedName,id.toUpperCase()],[1,binding,encodedName,'00000000-0000-0000-0000-000000000000'],[1,binding,'',id],[1,binding,'YQ==',id],[1,binding,'YR',id],[1,binding,'_w',id],[1,binding,Buffer.from('x'.repeat(121)).toString('base64url'),id],[1,binding,Buffer.from('\0').toString('base64url'),id],{binding,name:'review',id}])
   await assert.rejects(listSources(unusedTx,principal,{q:'review',limit:2,cursor:codec.encode(payload)}),invalid);
  const parts=cursor.split('.');parts[0]=(parts[0][0]==='A'?'B':'A')+parts[0].slice(1);
  await assert.rejects(listSources(unusedTx,principal,{q:'review',limit:2,cursor:parts.join('.')}),invalid);
  await assert.rejects(listSources(unusedTx,principal,{q:'review',limit:2,cursor:signedCursor(process.env.SESSION_KEY,'another-purpose').encode(value)}),invalid);
 }finally{if(previous===undefined)delete process.env.SESSION_KEY;else process.env.SESSION_KEY=previous;}
});

// These unit rows exercise the real codec through listSources; SQL keyset and
// forced-RLS semantics are covered separately by the real integration cases.
function rowsTx(rows:{id:string;name:string}[]):Tx {
 const selection={selectAll(){return this;},where(){return this;},orderBy(){return this;},limit(){return this;},async execute(){return rows;}};
 return {selectFrom(){return selection;}} as unknown as Tx;
}
test('source cursors fit and round-trip maximum legacy control and four-byte Unicode names',async()=>{
 const previous=process.env.SESSION_KEY;process.env.SESSION_KEY='synthetic-source-list-unit-secret-32-bytes';
 try {
  const id='abcdefab-abcd-4abc-8abc-abcdefabcdef';
  for(const name of ['\u0001'.repeat(120),'\u007f'.repeat(120),'😀'.repeat(120)]){
   const first=await listSources(rowsTx([{id,name},{id:randomUUID(),name}]),principal,{limit:1});
   assert.ok(first.nextCursor);assert.ok(first.nextCursor.length<=1024);
   const payload=signedCursor(process.env.SESSION_KEY,'source-inventory-v1').decode(first.nextCursor) as unknown[];
   assert.equal(payload[0],1);assert.equal(payload.length,4);
   assert.equal(Buffer.from(payload[2] as string,'base64url').toString('utf8'),name);
   const next=await listSources(rowsTx([]),principal,{limit:1,cursor:first.nextCursor});
   assert.deepEqual(next,{items:[],nextCursor:null});
  }
 }finally{if(previous===undefined)delete process.env.SESSION_KEY;else process.env.SESSION_KEY=previous;}
});
