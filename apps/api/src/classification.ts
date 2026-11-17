// SPDX-License-Identifier: Apache-2.0
import type {FastifyInstance,FastifyRequest,HTTPMethods} from 'fastify';
import {Type,type TSchema,type TProperties} from '@sinclair/typebox';
import {Value} from '@sinclair/typebox/value';
import {scope,type Tx} from '../../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../../packages/authz/src/index.ts';
import {authenticate} from './security.ts';
import {parseDomainRequestJSON,checkDomainData} from './business-domain-http.ts';
import {classificationInvalid,classificationFailure,classificationQuery,listClassificationTaxonomies,listClassificationRules,getClassificationTaxonomy,getClassificationRule,publishClassificationTaxonomy,publishClassificationRule,listClassificationAssignments,listClassificationSuggestions,evaluateClassificationAsset,proposeClassification,type ClassificationPageQuery} from '../../../packages/domain/src/classification-service.ts';
const object=<T extends TProperties>(properties:T)=>Type.Object(properties,{additionalProperties:false});
const choices=(...v:string[])=>Type.Union(v.map(value=>Type.Literal(value)));
const nullable=(s:TSchema)=>Type.Union([s,Type.Null()]);
const integer=(minimum=1,maximum=2147483647)=>Type.Integer({minimum,maximum});
const uuid=Type.String({pattern:'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'}),digest=Type.String({pattern:'^[a-f0-9]{64}$'});
const key=Type.String({pattern:'^(?!(?:__proto__|constructor|prototype)$)[A-Za-z_][A-Za-z0-9_.-]{0,63}$'});
const stamp=Type.String({pattern:'^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$'}),text=(maxLength:number,minLength=1)=>Type.String({minLength,maxLength});
const pin=object({id:uuid,version:integer(),definitionHash:digest}),workflow=object({id:key,version:integer(),definitionHash:digest});
const label=object({taxonomy:pin,labelKey:key});
const taxonomyDefinition=object({formatVersion:Type.Literal(1),name:text(240),description:text(4096),labels:Type.Array(object({key,name:text(240),description:text(4096),status:choices('active','deprecated')}),{minItems:1,maxItems:128})});
const predicate=object({field:choices('name','qualifiedName','dataType'),operator:choices('equals','contains','starts-with','ends-with'),comparison:choices('exact','ascii-insensitive'),literal:text(256)});
const ruleDefinition=object({formatVersion:Type.Literal(1),kind:Type.Literal('metadata-literal'),name:text(240),purpose:text(4096),ownerId:uuid,status:choices('active','retired'),assetTypes:Type.Array(choices('table','view','column'),{minItems:1,maxItems:3,uniqueItems:true}),label,all:Type.Array(predicate,{minItems:1,maxItems:8})});
const view=(definition:TSchema)=>object({id:uuid,version:integer(),definitionHash:digest,currentVersion:integer(),definition,createdAt:stamp,createdBy:uuid});
const taxonomy=view(taxonomyDefinition),rule=view(ruleDefinition);
const evidence=object({formatVersion:Type.Literal(1),kind:Type.Literal('metadata-literal'),assetId:uuid,observedAssetVersion:integer(),inputDigest:digest,rule:pin,label,evaluatedAt:stamp,
 matches:Type.Array(object({conditionIndex:integer(0,7),field:choices('name','qualifiedName','dataType'),value:text(2048),valueHash:digest}),{maxItems:8}),
 confidence:object({kind:Type.Literal('not-estimated'),reason:Type.Literal('metadata-only')}),samplePolicy:object({kind:Type.Literal('metadata-only'),sourceRowsRead:Type.Literal(0),sourceSamplesStored:Type.Literal(0)})});
const evaluation=object({id:uuid,outcome:choices('matched','not_matched','unsupported'),evidence,createdBy:uuid,suggestionId:nullable(uuid),evidenceHash:digest});
const assignment=object({id:uuid,assetId:uuid,label,version:integer(),status:choices('active','withdrawn'),suggestionId:uuid,approvalInstanceId:uuid,evidence,evidenceCurrent:Type.Boolean(),createdAt:stamp,updatedAt:stamp,updatedBy:uuid,reason:text(4096,0)});
const suggestion=object({id:uuid,assetId:uuid,evaluationId:uuid,evidence,evidenceHash:digest,evidenceCurrent:Type.Boolean(),currentAssignmentVersion:integer(0),createdAt:stamp,createdBy:uuid});
const publication=(definition:TSchema)=>object({id:uuid,expectedVersion:integer(0,2147483646),definition});
const evaluate=object({id:uuid,expectedAssetVersion:integer(),rule:pin});
const proposal=object({id:uuid,change:Type.Union([object({kind:Type.Literal('apply'),suggestionId:uuid,expectedAssignmentVersion:integer(0)}),object({kind:Type.Literal('withdraw'),assignmentId:uuid,expectedAssignmentVersion:integer(),reason:text(4096)})]),workflow,
 assignments:Type.Record(key,uuid,{minProperties:1,maxProperties:256,additionalProperties:false}),expiresAt:stamp});
const page=(schema:TSchema)=>object({items:Type.Array(schema,{maxItems:100}),nextCursor:nullable(text(1024))});
const problem=object({type:Type.String(),title:Type.String(),status:Type.Integer(),code:Type.String(),detail:Type.String(),correlationId:Type.String()});
const approvalPayload=object({formatVersion:Type.Literal(1),kind:Type.Literal('classification-review'),change:choices('apply','withdraw'),assetId:uuid,assignmentId:uuid,expectedAssignmentVersion:integer(0),suggestionId:uuid,label,evidence,evidenceHash:digest,reason:text(4096,0)});
const approvalResult=object({binding:Type.Literal('classification.review'),assetId:uuid,assignmentId:uuid,assignmentVersion:integer(),status:choices('active','withdrawn'),evidenceHash:digest});
export const classificationHttp={approvalPayload,approvalResult,taxonomyDefinition,ruleDefinition,taxonomy,rule,evidence,evaluation,assignment,suggestion,evaluate,proposal,publishTaxonomy:publication(taxonomyDefinition),publishRule:publication(ruleDefinition),problem};
export const CLASSIFICATION_HTTP_BYTES=98304;
export function parseClassificationRequestJSON(raw:string):unknown{
 try{if(Buffer.byteLength(raw)>CLASSIFICATION_HTTP_BYTES)throw 0;
  // Reuse the existing bounded duplicate-aware grammar and its root-only 256
  // assignment-map allowance. Closed route schemas still admit exact fields.
  return parseDomainRequestJSON(raw,'glossary-proposal');
 }catch{throw classificationInvalid();}
}
export function classificationRawQuery(url:string,allowed:readonly string[]):Record<string,string|number>{
 const output:Record<string,string|number>=Object.create(null),raw=url.split('?').slice(1).join('?');if(!raw)return output;
 for(const part of raw.split('&')){const equals=part.indexOf('=');let key:string,value:string;
  try{key=decodeURIComponent((equals<0?part:part.slice(0,equals)).replaceAll('+',' '));value=decodeURIComponent((equals<0?'':part.slice(equals+1)).replaceAll('+',' '));}catch{throw classificationInvalid();}
  if(!allowed.includes(key)||Object.hasOwn(output,key)||!value)throw classificationInvalid();
  if(key==='limit'||key==='version'){if(!/^[1-9][0-9]{0,9}$/.test(value)||Number(value)>(key==='limit'?100:2147483647))throw classificationInvalid();output[key]=Number(value);}
  else{if(value.length>1024)throw classificationInvalid();output[key]=value;}
 }return output;
}
function idempotency(req:FastifyRequest):string{
 let count=0;for(let i=0;i<req.raw.rawHeaders.length;i+=2)if(req.raw.rawHeaders[i].toLowerCase()==='idempotency-key')count++;
 const key=req.headers['idempotency-key'];if(count>1||typeof key!=='string'||key.length<8||key.length>128||/[\u0000-\u001f\u007f]/.test(key))throw new Problem(400,'IDEMPOTENCY_REQUIRED','Send one bounded Idempotency-Key.');return key;
}
interface State{principal:Principal;query:Record<string,string|number>;key?:string}
interface Spec{params?:TProperties;query?:readonly string[];body?:TSchema;response:TSchema;mutation?:boolean;status?:number}
/** Optional dependency seam is for host protocol tests; production always uses
 * authenticate (including CSRF) and the native tenant transaction scope. */
export interface ClassificationDependencies{authenticate:typeof authenticate;scope:typeof scope}
export async function installClassification(app:FastifyInstance,dependencies:ClassificationDependencies={authenticate,scope}):Promise<void>{
 await app.register(async child=>{
  const states=new WeakMap<FastifyRequest,State>();
  child.setValidatorCompiler(({schema})=>value=>Value.Check(schema as TSchema,value)?{value}:{error:classificationInvalid()});
  child.removeContentTypeParser('application/json');child.addContentTypeParser('application/json',{parseAs:'string',bodyLimit:CLASSIFICATION_HTTP_BYTES},(_req,raw,done)=>{try{done(null,parseClassificationRequestJSON(String(raw)));}catch{done(classificationInvalid());}});
  child.setErrorHandler((error,req,reply)=>{const e=error as {statusCode?:number;validation?:unknown};const known=error instanceof Problem?error:e.statusCode===429?new Problem(429,'RATE_LIMITED','Too many requests. Retry later.')
   :e.validation||[400,413,415].includes(e.statusCode??0)?classificationInvalid():classificationFailure(error);
   if(known.status>=500)req.log.error({code:known.code,correlationId:req.id},'Classification request failed; details redacted');if(known.status===503)reply.header('Retry-After','5');
   reply.code(known.status).type('application/problem+json').send({type:'about:blank',title:known.status>=500?'Service unavailable':'Request rejected',status:known.status,code:known.code,detail:known.message,correlationId:req.id});
  });
  function route(method:HTTPMethods,url:string,spec:Spec,work:(req:FastifyRequest,tx:Tx,state:State)=>Promise<unknown>){
   const params=object(spec.params??{}),query=object(Object.fromEntries((spec.query??[]).map(k=>[k,Type.Optional(text(k==='cursor'?1024:10))]))),status=spec.status??200;
   child.route({method,url,bodyLimit:CLASSIFICATION_HTTP_BYTES,schema:{params,querystring:query,...(spec.body?{body:spec.body}:{}),response:{[status]:spec.response,'4xx':problem,'5xx':problem}},
    onRequest:async req=>{const {principal}=await dependencies.authenticate(req);states.set(req,{principal,query:{}});},
    preValidation:async req=>{const state=states.get(req)!;state.query=classificationRawQuery(req.url,spec.query??[]);if(!Value.Check(params,req.params))throw classificationInvalid();if(spec.mutation)state.key=idempotency(req);
     if(spec.body){try{checkDomainData(req.body,'glossary-proposal');}catch{throw classificationInvalid();}if(!Value.Check(spec.body,req.body))throw classificationInvalid();}else if(req.body!==undefined)throw classificationInvalid();},
    handler:async(req,reply)=>{const state=states.get(req)!;try{const result=await dependencies.scope(state.principal.tenantId,state.principal.id,tx=>classificationQuery(tx,async()=>{
      const value=await work(req,tx,state);if(!Value.Check(spec.response,value))throw new Problem(500,'CLASSIFICATION_STORAGE_INVALID','The classification operation could not be completed.');return value;
     }));reply.code(status);return result;}catch(error){throw classificationFailure(error);}}
   });
  }
  const id=(r:FastifyRequest)=>(r.params as {id:string}).id;
  for(const kind of ['taxonomies','rules'] as const){
   const taxonomy=kind==='taxonomies',view=taxonomy?classificationHttp.taxonomy:classificationHttp.rule,body=taxonomy?classificationHttp.publishTaxonomy:classificationHttp.publishRule,response=object({[taxonomy?'taxonomy':'rule']:view});
   route('GET','/api/v1/classification/'+kind,{query:['limit','cursor'],response:page(view)},(_r,tx,s)=>taxonomy?listClassificationTaxonomies(tx,s.principal,s.query as ClassificationPageQuery):listClassificationRules(tx,s.principal,s.query as ClassificationPageQuery));
   route('GET','/api/v1/classification/'+kind+'/:id',{params:{id:uuid},query:['version'],response},async(r,tx,s)=>taxonomy?{taxonomy:await getClassificationTaxonomy(tx,s.principal,id(r),s.query.version as number|undefined)}:{rule:await getClassificationRule(tx,s.principal,id(r),s.query.version as number|undefined)});
   route('POST','/api/v1/classification/'+kind,{body,response,mutation:true,status:201},(r,tx,s)=>{if((r.body as {expectedVersion:number}).expectedVersion!==0)throw classificationInvalid();return taxonomy?publishClassificationTaxonomy(tx,s.principal,r.body,s.key!,r.id):publishClassificationRule(tx,s.principal,r.body,s.key!,r.id);});
   route('POST','/api/v1/classification/'+kind+'/:id/versions',{params:{id:uuid},body,response,mutation:true,status:201},(r,tx,s)=>{const b=r.body as {id:string;expectedVersion:number};if(b.id!==id(r)||b.expectedVersion<1)throw classificationInvalid();return taxonomy?publishClassificationTaxonomy(tx,s.principal,r.body,s.key!,r.id):publishClassificationRule(tx,s.principal,r.body,s.key!,r.id);});
  }
  route('GET','/api/v1/assets/:id/classifications',{params:{id:uuid},query:['limit','cursor'],response:page(assignment)},(r,tx,s)=>listClassificationAssignments(tx,s.principal,id(r),s.query as ClassificationPageQuery));
  route('GET','/api/v1/assets/:id/classification-suggestions',{params:{id:uuid},query:['limit','cursor'],response:page(suggestion)},(r,tx,s)=>listClassificationSuggestions(tx,s.principal,id(r),s.query as ClassificationPageQuery));
  route('POST','/api/v1/assets/:id/classification-evaluations',{params:{id:uuid},body:evaluate,response:object({evaluation}),mutation:true,status:201},(r,tx,s)=>evaluateClassificationAsset(tx,s.principal,id(r),r.body,s.key!,r.id));
  route('POST','/api/v1/classification/proposals',{body:proposal,response:object({instance:object({id:uuid})}),mutation:true,status:201},(r,tx,s)=>proposeClassification(tx,s.principal,r.body,s.key!,r.id));
 });
}
