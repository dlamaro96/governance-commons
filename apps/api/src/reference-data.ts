// SPDX-License-Identifier: Apache-2.0
import type {FastifyInstance,FastifyRequest,HTTPMethods} from 'fastify';
import {Type,type TProperties,type TSchema} from '@sinclair/typebox';
import {Value} from '@sinclair/typebox/value';
import {scope,type Tx} from '../../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../../packages/authz/src/index.ts';
import {authenticate} from './security.ts';
import {parseDomainRequestJSON,checkDomainData} from './business-domain-http.ts';
import {LIMITS,type Download,type ReferencePageQuery,type ReferenceSetQuery,type ReferenceEffectiveQuery} from '../../../packages/domain/src/reference-data-contracts.ts';
import {referenceInvalid,referenceFailure,referenceQuery,listReferenceSets,listReferenceReleases,getReferenceEffective,getReferenceRelease,getReferenceAuthoringContext,downloadReferenceRelease,proposeReferenceRelease} from '../../../packages/domain/src/reference-data-service.ts';

const object=<T extends TProperties>(properties:T)=>Type.Object(properties,{additionalProperties:false});
const nullable=(s:TSchema)=>Type.Union([s,Type.Null()]);
const choices=(...values:string[])=>Type.Union(values.map(v=>Type.Literal(v)));
const integer=(minimum=1,maximum=2147483647)=>Type.Integer({minimum,maximum});
const text=(maxLength:number,minLength=1)=>Type.String({minLength,maxLength});
const uuid=Type.String({pattern:'^(?!00000000-0000-0000-0000-000000000000$)[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'});
const digest=Type.String({pattern:'^[a-f0-9]{64}$'}),stamp=Type.String({pattern:'^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$'});
const key=Type.String({pattern:'^(?!(?:__proto__|constructor|prototype)$)[A-Za-z_][A-Za-z0-9_.-]{0,63}$'});
const localized=object({label:text(LIMITS.label),description:text(LIMITS.description)}),labels=object({en:localized,ar:localized});
const value=object({code:Type.String({pattern:'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'}),labels,ownerId:uuid,status:choices('active','deprecated'),validFrom:nullable(stamp),validUntil:nullable(stamp)});
const audience=object({visibility:choices('tenant','restricted'),allowedIdentityIds:Type.Array(uuid,{maxItems:LIMITS.principals,uniqueItems:true})});
const release=object({formatVersion:Type.Literal(1),kind:Type.Literal('reference-code-list'),labels,ownerId:uuid,status:choices('active','deprecated'),activation:Type.Union([object({kind:Type.Literal('on-publication')}),object({kind:Type.Literal('at'),at:stamp})]),validUntil:nullable(stamp),values:Type.Array(value,{minItems:1,maxItems:LIMITS.values})});
const workflow=object({id:key,version:integer(),definitionHash:digest});
const proposal=object({id:uuid,setId:uuid,expectedVersion:integer(0,2147483646),audience,release,workflow,assignments:Type.Record(key,uuid,{minProperties:1,maxProperties:LIMITS.assignments,additionalProperties:false}),expiresAt:stamp});
const approvalPayload=object({formatVersion:Type.Literal(1),kind:Type.Literal('reference-publication'),setId:uuid,expectedVersion:integer(0,2147483646),audience,release});
const approvalResult=object({binding:Type.Literal('reference.publish'),setId:uuid,version:integer(),publicationHash:digest,publishedAt:stamp,effectiveFrom:stamp});
const bundle=object({formatVersion:Type.Literal(1),kind:Type.Literal('reference-code-list'),setId:uuid,version:integer(),labels,ownerId:uuid,status:choices('active','deprecated'),publishedAt:stamp,effectiveFrom:stamp,validUntil:nullable(stamp),values:Type.Array(value,{minItems:1,maxItems:LIMITS.values})});
const summary=object({setId:uuid,version:integer(),labels,ownerId:uuid,status:choices('active','deprecated'),publishedAt:stamp,effectiveFrom:stamp,validUntil:nullable(stamp),publicationHash:digest,valueCount:integer(1,LIMITS.values)});
const effective=object({asOf:stamp,phase:choices('NOT_EFFECTIVE','EFFECTIVE','DEPRECATED','EXPIRED'),version:nullable(integer()),publicationHash:nullable(digest),effectiveFrom:nullable(stamp),effectiveUntil:nullable(stamp)});
const set=object({id:uuid,latest:summary,effective});
const page=(schema:TSchema)=>object({items:Type.Array(schema,{maxItems:100}),nextCursor:nullable(text(1024))});
const releaseView=object({release:bundle,publicationHash:digest});
const context=object({release:bundle,publicationHash:digest,setId:uuid,latestPublishedVersion:integer(),audience});
const effectiveView=object({set,selection:effective,items:Type.Array(value,{maxItems:100}),nextCursor:nullable(text(1024))});
const receipt=object({instance:object({id:uuid})});
const problem=object({type:Type.String(),title:Type.String(),status:Type.Integer(),code:Type.String(),detail:Type.String(),correlationId:Type.String()});
export const referenceHttp={approvalPayload,approvalResult,release,proposal,bundle,summary,effective,set,releaseView,context,effectiveView,receipt,problem};
export function parseReferenceRequestJSON(raw:string):unknown{
 try{if(Buffer.byteLength(raw)>LIMITS.envelopeBytes)throw 0;return parseDomainRequestJSON(raw);}catch{throw referenceInvalid();}
}
export function referenceRawQuery(url:string,allowed:readonly string[]):Record<string,string|number>{
 const result:Record<string,string|number>=Object.create(null);if(url.length>16384)throw referenceInvalid();const raw=url.split('?').slice(1).join('?');if(!raw)return result;
 for(const pair of raw.split('&')){const position=pair.indexOf('=');let key:string,v:string;
  try{key=decodeURIComponent((position<0?pair:pair.slice(0,position)).replaceAll('+',' '));v=decodeURIComponent((position<0?'':pair.slice(position+1)).replaceAll('+',' '));}catch{throw referenceInvalid();}
  if(!allowed.includes(key)||Object.hasOwn(result,key)||(!v&&key!=='q'))throw referenceInvalid();
  if(key==='limit'){if(!/^[1-9][0-9]{0,2}$/.test(v)||Number(v)>100)throw referenceInvalid();result[key]=Number(v);}
  else{if(v.length>(key==='q'?200:key==='cursor'?1024:key==='asOf'?24:4))throw referenceInvalid();if(key==='format'&&v!=='json'&&v!=='csv')throw referenceInvalid();result[key]=v;}
 }return result;
}
function idempotency(req:FastifyRequest):string{
 let count=0;for(let i=0;i<req.raw.rawHeaders.length;i+=2)if(req.raw.rawHeaders[i].toLowerCase()==='idempotency-key')count++;
 const key=req.headers['idempotency-key'];if(count>1||typeof key!=='string'||key.length<8||key.length>128||/[\u0000-\u001f\u007f]/.test(key))throw new Problem(400,'IDEMPOTENCY_REQUIRED','Send one bounded Idempotency-Key.');return key;
}
/** Conditional GET is evaluated only after the protected release read completes. */
export function referenceNotModified(header:unknown,etag:string):boolean{
 if(header===undefined)return false;if(typeof header!=='string'||header.length>2048)throw referenceInvalid();if(header.trim()==='*')return true;
 const tags=header.split(',').map(v=>v.trim());if(!tags.length||tags.length>16||tags.some(v=>! /^(W\/)?"[\x21\x23-\x7e]*"$/.test(v)))throw referenceInvalid();return tags.some(v=>v.replace(/^W\//,'')===etag);
}
interface State{principal:Principal;query:Record<string,string|number>;key?:string}
interface Spec{params?:TProperties;query?:readonly string[];body?:TSchema;response?:TSchema;mutation?:boolean;download?:boolean;status?:number}
export interface ReferenceDependencies{authenticate:typeof authenticate;scope:typeof scope}
/** Dependency injection is a host protocol-test seam. Production uses the
 * existing OIDC/CSRF authentication and native tenant transaction unchanged. */
export async function installReferenceData(app:FastifyInstance,dependencies:ReferenceDependencies={authenticate,scope}):Promise<void>{
 await app.register(async child=>{
  const states=new WeakMap<FastifyRequest,State>();
  child.setValidatorCompiler(({schema})=>value=>Value.Check(schema as TSchema,value)?{value}:{error:referenceInvalid()});
  child.removeContentTypeParser('application/json');child.addContentTypeParser('application/json',{parseAs:'string',bodyLimit:LIMITS.envelopeBytes},(_req,raw,done)=>{try{done(null,parseReferenceRequestJSON(String(raw)));}catch{done(referenceInvalid());}});
  child.setErrorHandler((error,req,reply)=>{const e=error as {statusCode?:number;validation?:unknown};const known=error instanceof Problem?error:e.statusCode===429?new Problem(429,'RATE_LIMITED','Too many requests. Retry later.'):e.validation||[400,413,415].includes(e.statusCode??0)?referenceInvalid():referenceFailure(error);
   if(known.status>=500)req.log.error({code:known.code,correlationId:req.id},'Reference-data request failed; details redacted');if(known.status===503)reply.header('Retry-After','5');reply.code(known.status).type('application/problem+json').send({type:'about:blank',title:known.status>=500?'Service unavailable':'Request rejected',status:known.status,code:known.code,detail:known.message,correlationId:req.id});
  });
  function route(method:HTTPMethods,url:string,spec:Spec,work:(req:FastifyRequest,tx:Tx,state:State)=>Promise<unknown>){
   const params=object(spec.params??{}),query=object(Object.fromEntries((spec.query??[]).map(k=>[k,Type.Optional(text(k==='cursor'?1024:k==='q'?200:k==='asOf'?24:4,k==='q'?0:1))]))),status=spec.status??200;
   child.route({method,url,bodyLimit:LIMITS.envelopeBytes,schema:{params,querystring:query,...(spec.body?{body:spec.body}:{}),response:{...(spec.response?{[status]:spec.response}:{}),'4xx':problem,'5xx':problem}},
    onRequest:async req=>{const {principal}=await dependencies.authenticate(req);states.set(req,{principal,query:{}});},
    preValidation:async req=>{const s=states.get(req)!;s.query=referenceRawQuery(req.url,spec.query??[]);if(!Value.Check(params,req.params))throw referenceInvalid();if(spec.mutation)s.key=idempotency(req);
     if(spec.body){try{checkDomainData(req.body);}catch{throw referenceInvalid();}if(!Value.Check(spec.body,req.body))throw referenceInvalid();}else if(req.body!==undefined)throw referenceInvalid();},
    handler:async(req,reply)=>{const s=states.get(req)!;try{const result=await dependencies.scope(s.principal.tenantId,s.principal.id,tx=>referenceQuery(tx,async()=>{const value=await work(req,tx,s);if(spec.response&&!Value.Check(spec.response,value))throw new Problem(500,'REFERENCE_STORAGE_INVALID','The reference-data response could not be verified.');return value;}));
     if(spec.download){const d=result as Download;const unchanged=referenceNotModified(req.headers['if-none-match'],d.etag);reply.header('Cache-Control','private, no-cache').header('Vary','Cookie').header('ETag',d.etag);
      if(unchanged)return reply.code(304).send();const p=req.params as {id:string;version:string};reply.header('Content-Disposition',`attachment; filename="reference-${p.id}-v${p.version}.${s.query.format}"`).header('Content-Length',d.byteLength).type(d.contentType);return reply.code(200).send(d.body);}
     return reply.code(status).send(result);
    }catch(error){throw referenceFailure(error);}}
   });
  }
  const id=(r:FastifyRequest)=>(r.params as {id:string}).id;
  const version=(r:FastifyRequest)=>{const v=(r.params as {version:string}).version;if(!/^[1-9][0-9]{0,9}$/.test(v)||Number(v)>LIMITS.version)throw referenceInvalid();return Number(v);};
  const versionParam=Type.String({pattern:'^[1-9][0-9]{0,9}$'});
  route('GET','/api/v1/reference-data/sets',{query:['q','limit','cursor'],response:page(set)},(_r,tx,s)=>listReferenceSets(tx,s.principal,s.query as ReferenceSetQuery));
  route('GET','/api/v1/reference-data/sets/:id/effective',{params:{id:uuid},query:['asOf','limit','cursor'],response:effectiveView},(r,tx,s)=>getReferenceEffective(tx,s.principal,id(r),s.query as ReferenceEffectiveQuery));
  route('GET','/api/v1/reference-data/sets/:id/releases',{params:{id:uuid},query:['limit','cursor'],response:page(summary)},(r,tx,s)=>listReferenceReleases(tx,s.principal,id(r),s.query as ReferencePageQuery));
  route('GET','/api/v1/reference-data/sets/:id/releases/:version',{params:{id:uuid,version:versionParam},response:releaseView},(r,tx,s)=>getReferenceRelease(tx,s.principal,id(r),version(r)));
  route('GET','/api/v1/reference-data/sets/:id/authoring-context',{params:{id:uuid},response:context},(r,tx,s)=>getReferenceAuthoringContext(tx,s.principal,id(r)));
  route('GET','/api/v1/reference-data/sets/:id/releases/:version/download',{params:{id:uuid,version:versionParam},query:['format'],download:true},(r,tx,s)=>{if(s.query.format!=='json'&&s.query.format!=='csv')throw referenceInvalid();return downloadReferenceRelease(tx,s.principal,id(r),version(r),s.query.format);});
  route('POST','/api/v1/reference-data/proposals',{body:proposal,response:receipt,mutation:true,status:201},(r,tx,s)=>proposeReferenceRelease(tx,s.principal,r.body,s.key!,r.id));
 });
}
