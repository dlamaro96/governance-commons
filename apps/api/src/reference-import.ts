// SPDX-License-Identifier: Apache-2.0
import type {FastifyInstance, FastifyRequest} from 'fastify';
import {scope} from '../../../packages/db/src/index.ts';
import {Problem, requirePermission, type Principal} from '../../../packages/authz/src/index.ts';
import {authenticate} from './security.ts';
import {scanUploadedBytes} from './upload-scanner.ts';
import {referenceFailure, referenceInvalid, referenceQuery} from '../../../packages/domain/src/reference-data-service.ts';
import {importBase, previewReferenceImport} from '../../../packages/domain/src/reference-import-service.ts';
import {IMPORT_LIMITS, type ImportBase, type ImportFormat, type ImportMode} from '../../../packages/domain/src/reference-import-contracts.ts';

export function importQuery(url:string,setId:unknown):{base:ImportBase;mode:ImportMode}{
 if(url.length>2048)throw referenceInvalid();
 const raw=url.split('?').slice(1).join('?'),pairs=new Map<string,string>();
 for(const part of raw.split('&')){
  const pos=part.indexOf('=');let key:string,value:string;
  try{key=decodeURIComponent(part.slice(0,pos).replaceAll('+',' '));value=decodeURIComponent(part.slice(pos+1).replaceAll('+',' '));}catch{throw referenceInvalid();}
  if(pos<1||!['mode','expectedVersion','publicationHash'].includes(key)||pairs.has(key)||!value)throw referenceInvalid();
  pairs.set(key,value);
 }
 const mode=pairs.get('mode'),version=pairs.get('expectedVersion');
 if(!mode||!['merge','replace'].includes(mode)||!version||! /^(0|[1-9][0-9]{0,9})$/.test(version))throw referenceInvalid();
 const expectedVersion=Number(version);
 if(expectedVersion===0&&pairs.has('publicationHash'))throw referenceInvalid();
 return {base:importBase({setId,expectedVersion,publicationHash:pairs.get('publicationHash')??null}),mode:mode as ImportMode};
}
export function importContentType(value:unknown):ImportFormat {
 if(typeof value!=='string'||value.length>100)throw referenceInvalid();
 const match=/^(application\/json|text\/csv)(?:\s*;\s*charset=utf-8)?$/i.exec(value);
 if(!match)throw referenceInvalid();
 return match[1].toLowerCase()==='text/csv'?'csv':'json';
}
export interface ImportDependencies {authenticate:typeof authenticate;scope:typeof scope;preview:typeof previewReferenceImport;scan:typeof scanUploadedBytes}
interface State {principal:Principal;format:ImportFormat}
export async function installReferenceImport(app:FastifyInstance,dependencies:ImportDependencies={authenticate,scope,preview:previewReferenceImport,scan:scanUploadedBytes}):Promise<void>{
 await app.register(async child=>{
  const states=new WeakMap<FastifyRequest,State>();
  child.removeContentTypeParser('application/json');
  for(const type of ['application/json','text/csv'])child.addContentTypeParser(type,{parseAs:'buffer',bodyLimit:IMPORT_LIMITS.rawBytes},(_req,body,done)=>done(null,body));
  child.setErrorHandler((error,req,reply)=>{
   const e=error as {statusCode?:number;validation?:unknown};
   const known=error instanceof Problem?error:e.statusCode===429?new Problem(429,'RATE_LIMITED','Too many requests. Retry later.'):e.validation||[400,413,415].includes(e.statusCode??0)?referenceInvalid():referenceFailure(error);
   if(known.status>=500)req.log.error({code:known.code,correlationId:req.id},'Reference import preview failed; details redacted');
   if(known.status===503)reply.header('Retry-After','5');
   reply.header('Cache-Control','no-store').code(known.status).type('application/problem+json').send({type:'about:blank',title:known.status>=500?'Service unavailable':'Request rejected',status:known.status,code:known.code,detail:known.message,correlationId:req.id});
  });
  child.post('/api/v1/reference-data/sets/:id/import-preview',{
   bodyLimit:IMPORT_LIMITS.rawBytes,
   onRequest:async req=>{
    const {principal}=await dependencies.authenticate(req);
    for(const permission of ['catalog:read','reference:read','reference:write'])requirePermission(principal,permission);
    let count=0;for(let i=0;i<req.raw.rawHeaders.length;i+=2)if(req.raw.rawHeaders[i].toLowerCase()==='content-type')count++;
    if(count!==1)throw referenceInvalid();
    states.set(req,{principal,format:importContentType(req.headers['content-type'])});
   },
  },async(req,reply)=>{
   const state=states.get(req)!;
   const query=importQuery(req.url,(req.params as {id:string}).id);
   if(!Buffer.isBuffer(req.body))throw referenceInvalid();
   try{
    await dependencies.scan(req.body);
    const result=await dependencies.scope(state.principal.tenantId,state.principal.id,tx=>referenceQuery(tx,()=>dependencies.preview(tx,state.principal,query.base,state.format,query.mode,req.body as Buffer)));
    return reply.header('Cache-Control','no-store').code(200).send(result);
   }catch(error){throw referenceFailure(error);}
  });
 });
}
