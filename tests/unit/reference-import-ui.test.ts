// SPDX-License-Identifier: Apache-2.0
/** Host-only request/binding controls. Browser acceptance is a separate real journey. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {api,ApiError,setCsrfToken} from '../../apps/web/src/api.ts';
import {importPath,importContentType,importTemplate,sameImportPreview} from '../../apps/web/src/referenceData/import-state.ts';
import {parseImportRows,reconcileImport} from '../../packages/domain/src/reference-import.ts';
import type {ImportBase,ImportReady} from '../../packages/domain/src/reference-import-contracts.ts';
const owner='10000000-0000-4000-8000-000000000001',base:ImportBase={setId:'20000000-0000-4000-8000-000000000001',expectedVersion:4,publicationHash:'a'.repeat(64)};
const value=JSON.parse(importTemplate('json',owner)).values[0];
const ready:ImportReady={state:'ready',base,mode:'merge',sourceSha256:'b'.repeat(64),values:[value],changes:[{code:'001',kind:'added',before:null,after:value,changedFields:['code']}],counts:{added:1,changed:0,removed:0,unchanged:0}};
test('preview URL binds the exact head, preserving null only for a new set',()=>{
 const url=new URL(importPath(base,'replace'),'https://example.invalid');assert.equal(url.pathname,'/reference-data/sets/'+base.setId+'/import-preview');assert.deepEqual([...url.searchParams],[['mode','replace'],['expectedVersion','4'],['publicationHash',base.publicationHash!]]);
 assert.equal(new URL(importPath({...base,expectedVersion:0,publicationHash:null},'merge'),'https://example.invalid').searchParams.has('publicationHash'),false);
});
test('preview consent basis refuses another file, mode, set, version or publication hash',()=>{
 const request={base,mode:'merge' as const,sourceSha256:ready.sourceSha256};assert.equal(sameImportPreview(ready,request),true);
 for(const patch of [{sourceSha256:'c'.repeat(64)},{mode:'replace' as const},{base:{...base,setId:owner}},{base:{...base,expectedVersion:5}},{base:{...base,publicationHash:'c'.repeat(64)}}])assert.equal(sameImportPreview(ready,{...request,...patch}),false);
 assert.equal(sameImportPreview({...ready,values:[]},request),false);assert.equal(sameImportPreview({...ready,values:Array(257).fill(value)},request),false);assert.equal(sameImportPreview({...ready,changes:Array(513).fill(ready.changes[0])},request),false);
});
test('templates are code rows with exact codes, localized descriptions, current owner and empty CSV intervals',()=>{
 const json=JSON.parse(importTemplate('json',owner));assert.deepEqual(Object.keys(json),['formatVersion','kind','values']);assert.equal(json.kind,'reference-code-rows');assert.equal(json.values[0].code,'001');assert.equal(json.values[0].ownerId,owner);assert.equal(json.values[0].validFrom,null);assert.equal(json.values[0].validUntil,null);assert.match(json.values[0].labels.ar.label,/رمز/);
 const csv=importTemplate('csv',owner);assert.equal(csv.split('\r\n')[0],'code,label_en,description_en,label_ar,description_ar,owner_id,status,valid_from,valid_until');assert.equal(csv.split('\r\n').length,3);assert.match(csv,/\r\n"001",/);assert.ok(csv.endsWith(',"active","",""\r\n'));assert.equal(csv.includes('publicationHash'),false);
});
test('API preserves supplied CSV content type, original bytes and existing CSRF/session transport',async t=>{
 const bytes=new Uint8Array([0xef,0xbb,0xbf,0xff,0x0a]).buffer;setCsrfToken('synthetic-csrf');
 t.mock.method(globalThis,'fetch',async(input:RequestInfo|URL,options:RequestInit)=>{assert.equal(input,'/api/v1'+importPath(base,'merge'));assert.equal(options.body,bytes);const headers=new Headers(options.headers);assert.equal(headers.get('content-type'),importContentType('csv'));assert.equal(headers.get('accept'),'application/json');assert.equal(headers.get('x-csrf-token'),'synthetic-csrf');assert.equal(options.credentials,'same-origin');return new Response(JSON.stringify({state:'invalid',issues:[],issuesTruncated:false}),{status:200,headers:{'Content-Type':'application/json'}});});
 assert.deepEqual(await api(importPath(base,'merge'),{method:'POST',headers:{'content-type':importContentType('csv')},body:bytes}),{state:'invalid',issues:[],issuesTruncated:false});
});
test('API keeps JSON default, explicit UTF-8 JSON and bodyless GET semantics',async t=>{
 let count=0;t.mock.method(globalThis,'fetch',async(_input:RequestInfo|URL,options:RequestInit)=>{const headers=new Headers(options.headers);assert.equal(headers.get('content-type'),['application/json','application/json; charset=utf-8',null][count++]);if(options.method==='GET')assert.equal(headers.has('x-csrf-token'),false);return new Response(null,{status:204});});
 await api('/reference-data/proposals',{method:'POST',body:'{}'});await api('/preview',{method:'POST',headers:{'Content-Type':importContentType('json')},body:new ArrayBuffer(2)});assert.equal(await api('/me'),undefined);assert.equal(count,3);
});
test('API preserves closed errors and session-expiry event without weakening raw import transport',async t=>{
 const events:string[]=[],prior=Object.getOwnPropertyDescriptor(globalThis,'window');Object.defineProperty(globalThis,'window',{configurable:true,value:{dispatchEvent:(event:Event)=>{events.push(event.type);return true;}}});t.after(()=>{if(prior)Object.defineProperty(globalThis,'window',prior);else Reflect.deleteProperty(globalThis,'window');});
 t.mock.method(globalThis,'fetch',async()=>new Response(JSON.stringify({code:'SESSION_EXPIRED',detail:'Session expired'}),{status:401,headers:{'Content-Type':'application/json'}}));
 await assert.rejects(api('/preview',{method:'POST',body:'{}'}),(error:unknown)=>error instanceof ApiError&&error.status===401&&error.code==='SESSION_EXPIRED');assert.deepEqual(events,['gc:session-expired']);
 await assert.rejects(api('/me'),ApiError);assert.deepEqual(events,['gc:session-expired']);
});

test('both generated templates pass the actual strict importer and produce a canonical new-set preview',()=>{
 for(const format of ['json','csv'] as const){const parsed=parseImportRows(new TextEncoder().encode(importTemplate(format,owner)),format);assert.equal(parsed.state,'parsed');if(parsed.state!=='parsed')throw new Error('Template refused by strict importer');assert.deepEqual(parsed.values,[value]);const preview=reconcileImport({...base,expectedVersion:0,publicationHash:null},[],'merge',parsed);assert.equal(preview.state,'ready');if(preview.state!=='ready')throw new Error('Template reconciliation refused');assert.equal(sameImportPreview(preview,{base:{...base,expectedVersion:0,publicationHash:null},mode:'merge',sourceSha256:parsed.sourceSha256}),true);assert.deepEqual(preview.counts,{added:1,changed:0,removed:0,unchanged:0});}
});
