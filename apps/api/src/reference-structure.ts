// SPDX-License-Identifier: Apache-2.0
import type {FastifyInstance,FastifyRequest,HTTPMethods} from 'fastify';
import {Type,type TProperties,type TSchema} from '@sinclair/typebox';
import {Value} from '@sinclair/typebox/value';
import {scope,type Tx} from '../../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../../packages/authz/src/index.ts';
import {authenticate} from './security.ts';
import {parseDomainRequestJSON,checkDomainData} from './business-domain-http.ts';
import {referenceNotModified} from './reference-data.ts';
import type {Download} from '../../../packages/domain/src/reference-data-contracts.ts';
import {STRUCTURE_LIMITS as L,type StructurePageQuery,type StructureListQuery,type StructureEffectiveQuery} from '../../../packages/domain/src/reference-structure-contracts.ts';
import {structureInvalid,structureFailure,structureQuery,listReferenceStructures,listStructureReleases,getStructureEffective,getStructureRelease,getStructureAuthoringContext,downloadStructureRelease,proposeReferenceStructure} from '../../../packages/domain/src/reference-structure-service.ts';

const object=<T extends TProperties>(properties:T)=>Type.Object(properties,{additionalProperties:false});
const nullable=(s:TSchema)=>Type.Union([s,Type.Null()]);
const choices=(...values:string[])=>Type.Union(values.map(v=>Type.Literal(v)));
const integer=(minimum=1,maximum=2147483647)=>Type.Integer({minimum,maximum});
const text=(maxLength:number,minLength=1)=>Type.String({minLength,maxLength});
const uuid=Type.String({pattern:'^(?!00000000-0000-0000-0000-000000000000$)[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'});
const hash=Type.String({pattern:'^[a-f0-9]{64}$'}),stamp=Type.String({pattern:'^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$'});
const key=Type.String({pattern:'^(?!(?:__proto__|constructor|prototype)$)[A-Za-z_][A-Za-z0-9_.-]{0,63}$'});
const code=Type.String({pattern:'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'});
const localized=object({label:text(L.label),description:text(L.description)}),labels=object({en:localized,ar:localized});
const pin=object({setId:uuid,version:integer(),publicationHash:hash});
const interval={validFrom:nullable(stamp),validUntil:nullable(stamp)};
const edge=object({parentCode:code,childCode:code,...interval});
const confidence=Type.Union([object({kind:Type.Literal('not-assessed')}),object({kind:Type.Literal('declared'),basisPoints:integer(0,10000),basis:text(L.confidenceBasis)})]);
const mapping=object({sourceCode:code,targetCode:code,relation:choices('equivalent','source-broader','source-narrower','related'),method:choices('steward-asserted','source-reported','rule-described'),methodDetails:text(L.methodDetails),transformationNotes:text(L.transformationNotes),confidence,...interval});
const common={formatVersion:Type.Literal(1),labels,ownerId:uuid,status:choices('active','deprecated'),validUntil:nullable(stamp)};
const hierarchy={kind:Type.Literal('reference-hierarchy'),reference:pin,multiParent:choices('forbid','allow'),edges:Type.Array(edge,{maxItems:L.hierarchyEdges})};
const crosswalk={kind:Type.Literal('reference-crosswalk'),source:pin,target:pin,cardinality:Type.Literal('many-to-many'),overlapPolicy:Type.Literal('reject-overlapping-pair'),mappings:Type.Array(mapping,{maxItems:L.crosswalkMappings})};
const activation=Type.Union([object({kind:Type.Literal('on-publication')}),object({kind:Type.Literal('at'),at:stamp})]);
const release=Type.Union([object({...common,...hierarchy,activation}),object({...common,...crosswalk,activation})]);
const coordinates={structureId:uuid,version:integer(),publishedAt:stamp,effectiveFrom:stamp};
const bundle=Type.Union([object({...common,...hierarchy,...coordinates}),object({...common,...crosswalk,...coordinates})]);
const identity=Type.Union([object({kind:Type.Literal('reference-hierarchy'),referenceSetId:uuid}),object({kind:Type.Literal('reference-crosswalk'),sourceSetId:uuid,targetSetId:uuid})]);
const summary=object({...coordinates,identity,labels,ownerId:uuid,status:choices('active','deprecated'),validUntil:nullable(stamp),publicationHash:hash,entryCount:integer(0,L.array)});
const workflow=object({id:key,version:integer(),definitionHash:hash});
const proposal=object({id:uuid,structureId:uuid,expectedVersion:integer(0,L.expectedVersion),release,workflow,assignments:Type.Record(key,uuid,{minProperties:1,maxProperties:L.assignments,additionalProperties:false}),expiresAt:stamp});
const approvalPayload=object({formatVersion:Type.Literal(1),kind:Type.Literal('reference-structure-publication'),structureId:uuid,expectedVersion:integer(0,L.expectedVersion),release});
const approvalResult=object({...coordinates,binding:Type.Literal('reference.structure.publish'),publicationHash:hash});
const releaseView=object({release:bundle,publicationHash:hash});
const context=object({release:bundle,publicationHash:hash,identity,latestPublishedVersion:integer(),audiencePolicy:Type.Literal('intersection-of-current-endpoint-audiences')});
const selected={asOf:stamp,version:integer(),publicationHash:hash,effectiveFrom:stamp,effectiveUntil:nullable(stamp)};
const noGaps=Type.Array(Type.Never(),{maxItems:0}),emptyItems=Type.Array(Type.Never(),{maxItems:0});
const unavailable=Type.Union([
 object({phase:Type.Literal('NOT_EFFECTIVE'),asOf:stamp,version:Type.Null(),publicationHash:Type.Null(),effectiveFrom:Type.Null(),effectiveUntil:Type.Null(),gaps:noGaps}),
 object({...selected,phase:choices('EXPIRED','DEPRECATED'),gaps:noGaps}),
 object({...selected,phase:Type.Literal('ENDPOINT_PIN_NOT_EFFECTIVE'),gaps:Type.Array(object({endpoint:choices('reference','source','target'),reason:choices('NOT_EFFECTIVE','EXPIRED','DEPRECATED','PIN_SUPERSEDED')}),{minItems:1,maxItems:2})}),
]);
const effectiveSelection=object({...selected,phase:Type.Literal('EFFECTIVE'),gaps:noGaps});
const effectiveView=Type.Union([
 object({structure:summary,selection:unavailable,items:emptyItems,nextCursor:Type.Null()}),
 object({structure:summary,selection:effectiveSelection,kind:hierarchy.kind,reference:pin,multiParent:hierarchy.multiParent,items:Type.Array(edge,{maxItems:100}),nextCursor:nullable(text(1024))}),
 object({structure:summary,selection:effectiveSelection,kind:crosswalk.kind,source:pin,target:pin,cardinality:crosswalk.cardinality,overlapPolicy:crosswalk.overlapPolicy,items:Type.Array(mapping,{maxItems:100}),nextCursor:nullable(text(1024))}),
]);
const receipt=object({instance:object({id:uuid})});
const page=(item:TSchema)=>object({items:Type.Array(item,{maxItems:100}),nextCursor:nullable(text(1024))});
const problem=object({type:Type.String(),title:Type.String(),status:Type.Integer(),code:Type.String(),detail:Type.String(),correlationId:Type.String()});
export const structureHttp={approvalPayload,approvalResult,release,proposal,bundle,summary,releaseView,context,effectiveView,receipt,problem};
export function parseStructureRequestJSON(raw:string):unknown{try{if(Buffer.byteLength(raw)>L.envelopeBytes)throw 0;return parseDomainRequestJSON(raw);}catch{throw structureInvalid();}}
export function structureRawQuery(url:string,allowed:readonly string[]):Record<string,string|number>{
 const result:Record<string,string|number>=Object.create(null);if(url.length>16384)throw structureInvalid();const raw=url.split('?').slice(1).join('?');if(!raw)return result;
 for(const pair of raw.split('&')){const pos=pair.indexOf('=');let key:string,v:string;try{key=decodeURIComponent((pos<0?pair:pair.slice(0,pos)).replaceAll('+',' '));v=decodeURIComponent((pos<0?'':pair.slice(pos+1)).replaceAll('+',' '));}catch{throw structureInvalid();}
  if(!allowed.includes(key)||Object.hasOwn(result,key)||(!v&&key!=='q'))throw structureInvalid();
  if(key==='limit'){if(!/^[1-9][0-9]{0,2}$/.test(v)||Number(v)>100)throw structureInvalid();result[key]=Number(v);}
  else{const max=key==='q'?L.search:key==='cursor'?L.cursor:key==='asOf'?24:key==='setId'?36:key==='kind'?19:4;if(v.length>max)throw structureInvalid();if(key==='format'&&v!=='json'&&v!=='csv')throw structureInvalid();result[key]=v;}
 }return result;
}
function idempotency(req:FastifyRequest):string{let count=0;for(let i=0;i<req.raw.rawHeaders.length;i+=2)if(req.raw.rawHeaders[i].toLowerCase()==='idempotency-key')count++;const key=req.headers['idempotency-key'];if(count!==1||typeof key!=='string'||key.length<8||key.length>128||/[\u0000-\u001f\u007f]/.test(key))throw new Problem(400,'IDEMPOTENCY_REQUIRED','Send one bounded Idempotency-Key.');return key;}
interface State{principal:Principal;query:Record<string,string|number>;key?:string}
interface Spec{params?:TProperties;query?:readonly string[];body?:TSchema;response?:TSchema;mutation?:boolean;download?:boolean;status?:number}
export interface StructureDependencies{authenticate:typeof authenticate;scope:typeof scope}
export async function installReferenceStructures(app:FastifyInstance,dependencies:StructureDependencies={authenticate,scope}):Promise<void>{
 await app.register(async child=>{
  const states=new WeakMap<FastifyRequest,State>();
  child.setValidatorCompiler(({schema})=>value=>Value.Check(schema as TSchema,value)?{value}:{error:structureInvalid()});
  child.removeContentTypeParser('application/json');child.addContentTypeParser('application/json',{parseAs:'string',bodyLimit:L.envelopeBytes},(_req,raw,done)=>{try{done(null,parseStructureRequestJSON(String(raw)));}catch{done(structureInvalid());}});
  child.setErrorHandler((error,req,reply)=>{const e=error as {statusCode?:number;validation?:unknown};const known=error instanceof Problem?error:e.statusCode===429?new Problem(429,'RATE_LIMITED','Too many requests. Retry later.'):e.validation||[400,413,415].includes(e.statusCode??0)?structureInvalid():structureFailure(error);
   if(known.status>=500)req.log.error({code:known.code,correlationId:req.id},'Structure request failed; details redacted');if(known.status===503)reply.header('Retry-After','5');reply.code(known.status).type('application/problem+json').send({type:'about:blank',title:known.status>=500?'Service unavailable':'Request rejected',status:known.status,code:known.code,detail:known.message,correlationId:req.id});
  });
  function route(method:HTTPMethods,url:string,spec:Spec,work:(req:FastifyRequest,tx:Tx,state:State)=>Promise<unknown>){
   const params=object(spec.params??{}),query=object(Object.fromEntries((spec.query??[]).map(k=>[k,Type.Optional(text(k==='cursor'?L.cursor:k==='q'?L.search:k==='asOf'?24:k==='setId'?36:k==='kind'?19:4,k==='q'?0:1))]))),status=spec.status??200;
   child.route({method,url,bodyLimit:L.envelopeBytes,schema:{params,querystring:query,...(spec.body?{body:spec.body}:{}),response:{...(spec.response?{[status]:spec.response}:{}),'4xx':problem,'5xx':problem}},
    onRequest:async(req,reply)=>{reply.header('Cache-Control','no-store');const {principal}=await dependencies.authenticate(req);states.set(req,{principal,query:{}});},
    preValidation:async req=>{const s=states.get(req)!;s.query=structureRawQuery(req.url,spec.query??[]);if(!Value.Check(params,req.params))throw structureInvalid();if(spec.mutation)s.key=idempotency(req);if(spec.body){try{checkDomainData(req.body);}catch{throw structureInvalid();}if(!Value.Check(spec.body,req.body))throw structureInvalid();}else if(req.body!==undefined)throw structureInvalid();},
    handler:async(req,reply)=>{const s=states.get(req)!;try{const result=await dependencies.scope(s.principal.tenantId,s.principal.id,tx=>structureQuery(tx,async()=>{const value=await work(req,tx,s);if(spec.response&&!Value.Check(spec.response,value))throw new Problem(500,'REFERENCE_STRUCTURE_STORAGE_INVALID','The structure response could not be verified.');return value;}));
     if(spec.download){const d=result as Download;const unchanged=referenceNotModified(req.headers['if-none-match'],d.etag);reply.header('Cache-Control','private, no-cache').header('Vary','Cookie').header('ETag',d.etag);if(unchanged)return reply.code(304).send();const p=req.params as {id:string;version:string};reply.header('Content-Disposition',`attachment; filename="reference-structure-${p.id}-v${p.version}.${s.query.format}"`).header('Content-Length',d.byteLength).type(d.contentType);return reply.code(200).send(d.body);}
     return reply.code(status).send(result);
    }catch(error){throw structureFailure(error);}}
   });
  }
  const id=(r:FastifyRequest)=>(r.params as {id:string}).id;
  const version=(r:FastifyRequest)=>{const v=(r.params as {version:string}).version;if(!/^[1-9][0-9]{0,9}$/.test(v)||Number(v)>L.version)throw structureInvalid();return Number(v);};
  const versionParam=Type.String({pattern:'^[1-9][0-9]{0,9}$'});
  route('GET','/api/v1/reference-data/structures',{query:['q','kind','setId','limit','cursor'],response:page(summary)},(_r,tx,s)=>listReferenceStructures(tx,s.principal,s.query as StructureListQuery));
  route('GET','/api/v1/reference-data/structures/:id/effective',{params:{id:uuid},query:['asOf','limit','cursor'],response:effectiveView},(r,tx,s)=>getStructureEffective(tx,s.principal,id(r),s.query as StructureEffectiveQuery));
  route('GET','/api/v1/reference-data/structures/:id/releases',{params:{id:uuid},query:['limit','cursor'],response:page(summary)},(r,tx,s)=>listStructureReleases(tx,s.principal,id(r),s.query as StructurePageQuery));
  route('GET','/api/v1/reference-data/structures/:id/releases/:version',{params:{id:uuid,version:versionParam},response:releaseView},(r,tx,s)=>getStructureRelease(tx,s.principal,id(r),version(r)));
  route('GET','/api/v1/reference-data/structures/:id/authoring-context',{params:{id:uuid},response:context},(r,tx,s)=>getStructureAuthoringContext(tx,s.principal,id(r)));
  route('GET','/api/v1/reference-data/structures/:id/releases/:version/download',{params:{id:uuid,version:versionParam},query:['format'],download:true},(r,tx,s)=>{if(s.query.format!=='json'&&s.query.format!=='csv')throw structureInvalid();return downloadStructureRelease(tx,s.principal,id(r),version(r),s.query.format);});
  route('POST','/api/v1/reference-data/structure-proposals',{body:proposal,response:receipt,mutation:true,status:201},(r,tx,s)=>proposeReferenceStructure(tx,s.principal,r.body,s.key!,r.id));
 });
}
