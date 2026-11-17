// SPDX-License-Identifier: Apache-2.0
import type {FastifyInstance,FastifyRequest,HTTPMethods} from 'fastify';
import {Type,type TSchema,type TProperties} from '@sinclair/typebox';
import {Value} from '@sinclair/typebox/value';
import {scope,type Tx} from '../../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../../packages/authz/src/index.ts';
import {authenticate,siteTenant} from './security.ts';
import {parseDomainRequestJSON,checkDomainData} from './business-domain-http.ts';
import {QUALITY_BUDGET,QUALITY_UNIQUENESS_BUDGET,QUALITY_ERRORS,type QualityPageQuery} from '../../../packages/domain/src/quality-contracts.ts';
import {qualityInvalid} from '../../../packages/domain/src/quality.ts';
import {qualityQuery,qualityFailure,getQualityAsset,getQualityRule,publishQualityRule,requestQualityRun,listQualityRuns,getQualityRun,cancelQualityRun,pendingQualityRuns,claimQualityRun,finishQualityRun} from '../../../packages/domain/src/quality-service.ts';
const object=<T extends TProperties>(properties:T)=>Type.Object(properties,{additionalProperties:false});
const choices=(...values:string[])=>Type.Union(values.map(value=>Type.Literal(value)));
const nullable=(schema:TSchema)=>Type.Union([schema,Type.Null()]);
const integer=(minimum=1,maximum=2147483647)=>Type.Integer({minimum,maximum});
const uuid=Type.String({pattern:'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'}),digest=Type.String({pattern:'^[a-f0-9]{64}$'});
const stamp=Type.String({pattern:'^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$'});
const definitionFields={formatVersion:Type.Literal(1),target:object({tableAssetId:uuid,columnAssetId:uuid}),name:Type.String({minLength:1,maxLength:240}),purpose:Type.String({minLength:1,maxLength:4096}),ownerId:uuid,severity:choices('info','warning','critical')};
const int64=Type.String({pattern:'^(0|-?[1-9][0-9]*)$',maxLength:20});
const rangeFields={minimum:int64,maximum:int64,comparison:Type.Literal('int64-inclusive'),nullPolicy:Type.Literal('exclude')};
const rangeBinding=object({...rangeFields,rangeHash:digest});
const definition=Type.Union([
 object({...definitionFields,kind:Type.Literal('range'),maximumOutOfRangeBasisPoints:integer(0,10000),...rangeFields}),
 object({...definitionFields,kind:Type.Literal('uniqueness'),maximumDuplicateBasisPoints:integer(0,10000),comparison:Type.Literal('utf8-exact'),nullPolicy:Type.Literal('exclude')}),
 object({...definitionFields,kind:Type.Literal('completeness'),maximumNullBasisPoints:integer(0,10000)}),
 object({...definitionFields,kind:Type.Literal('reference-allowed-values'),maximumInvalidBasisPoints:integer(0,10000),reference:object({setId:uuid,selection:Type.Literal('effective-at-run'),codeStatus:Type.Literal('active')}),comparison:Type.Literal('utf8-exact'),nullPolicy:Type.Literal('exclude')})]);
const rule=object({id:uuid,version:integer(),currentVersion:nullable(integer()),definition,definitionHash:digest,createdAt:stamp,createdBy:uuid});
const referenceFields={setId:uuid,version:integer(),publicationHash:digest,asOf:stamp,codeStatus:Type.Literal('active'),bindingHash:digest};
const referenceMetadata=object(referenceFields),referenceBinding=object({...referenceFields,codes:Type.Array(Type.String({pattern:'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'}),{maxItems:256,uniqueItems:true})});
const measurementFields={formatVersion:Type.Literal(1),strategy:Type.Literal('exact-bounded-role-scope'),rowCount:integer(0,QUALITY_BUDGET.maximumRows),nullCount:integer(0,QUALITY_BUDGET.maximumRows),observedStartedAt:stamp,observedFinishedAt:stamp,elapsedMs:integer(0,30000),sourceVersion:Type.String({pattern:'^\\d{5,16}$'}),adapterVersion:Type.Literal('1'),estimatedCost:Type.Number({minimum:0,maximum:QUALITY_BUDGET.maximumEstimatedCost}),estimatedBytes:Type.Number({minimum:0,maximum:QUALITY_BUDGET.maximumEstimatedBytes})};
const completenessMeasurement=object({...measurementFields,kind:Type.Literal('completeness'),queryTemplate:Type.Literal('postgresql-completeness-v1')});
const referenceMeasurement=object({...measurementFields,kind:Type.Literal('reference-allowed-values'),queryTemplate:Type.Literal('postgresql-reference-allowed-values-v1'),invalidCount:integer(0,QUALITY_BUDGET.maximumRows),referenceBindingHash:digest});
const uniquenessMeasurement=object({...measurementFields,kind:Type.Literal('uniqueness'),queryTemplate:Type.Literal('postgresql-uniqueness-v1'),distinctCount:integer(0,QUALITY_BUDGET.maximumRows),duplicateGroupCount:integer(0,QUALITY_BUDGET.maximumRows),duplicateRowCount:integer(0,QUALITY_BUDGET.maximumRows),totalValueBytes:integer(0,QUALITY_UNIQUENESS_BUDGET.maximumTotalValueBytes),largestValueBytes:integer(0,QUALITY_UNIQUENESS_BUDGET.maximumValueBytes)});
const rangeMeasurement=object({...measurementFields,kind:Type.Literal('range'),queryTemplate:Type.Literal('postgresql-range-v1'),belowCount:integer(0,QUALITY_BUDGET.maximumRows),aboveCount:integer(0,QUALITY_BUDGET.maximumRows),rangeHash:digest});
const measurement=Type.Union([completenessMeasurement,referenceMeasurement,uniquenessMeasurement,rangeMeasurement]);
const runFields={id:uuid,ruleId:uuid,ruleVersion:integer(),ruleHash:digest,requesterId:uuid,columnAssetId:uuid,tableAssetId:uuid,status:choices('queued','running','succeeded','failed','cancelled'),version:integer(),attempt:integer(0,3),createdAt:stamp,startedAt:nullable(stamp),finishedAt:nullable(stamp),expiresAt:stamp,verdict:nullable(choices('PASS','FAIL','NO_DATA')),errorCode:nullable(choices(...QUALITY_ERRORS))};
const run=Type.Union([object({...runFields,kind:Type.Literal('range'),range:rangeBinding,measurement:nullable(rangeMeasurement)}),object({...runFields,kind:Type.Literal('uniqueness'),measurement:nullable(uniquenessMeasurement)}),object({...runFields,measurement:nullable(completenessMeasurement)}),object({...runFields,kind:Type.Literal('reference-allowed-values'),reference:referenceMetadata,measurement:nullable(referenceMeasurement)})]);
const page=(schema:TSchema)=>object({items:Type.Array(schema,{maxItems:100}),nextCursor:nullable(Type.String({maxLength:1024}))});
const eligibility=object({supported:Type.Boolean(),reason:nullable(Type.String({maxLength:120})),tableAssetId:nullable(uuid),columnAssetId:nullable(uuid)});
const executionFields={formatVersion:Type.Literal(1),target:object({databaseOid:Type.String({pattern:'^[1-9]\\d{0,9}$'}),schemaOid:Type.String({pattern:'^[1-9]\\d{0,9}$'}),relationOid:Type.String({pattern:'^[1-9]\\d{0,9}$'}),attributeNumber:integer(1,32767),schemaName:Type.String({minLength:1,maxLength:255}),tableName:Type.String({minLength:1,maxLength:255}),columnName:Type.String({minLength:1,maxLength:255}),dataType:Type.String({minLength:1,maxLength:256})}),budget:object(Object.fromEntries(Object.entries(QUALITY_BUDGET).map(([k,v])=>[k,Type.Literal(v)])))};
const execution=Type.Union([object({...executionFields,kind:Type.Literal('range'),range:rangeBinding}),object({...executionFields,kind:Type.Literal('uniqueness'),budget:object(Object.fromEntries(Object.entries(QUALITY_UNIQUENESS_BUDGET).map(([k,v])=>[k,Type.Literal(v)])))}),object({...executionFields,kind:Type.Literal('completeness')}),object({...executionFields,kind:Type.Literal('reference-allowed-values'),reference:referenceBinding})]);
const claim=Type.Union([object({status:Type.Literal('busy'),retryAt:stamp}),object({status:Type.Literal('terminal'),run}),object({status:Type.Literal('claimed'),runId:uuid,claimId:uuid,attempt:integer(1,3),leaseExpiresAt:stamp,
 source:object({connectorId:Type.Literal('postgresql'),host:Type.String({minLength:1,maxLength:1024}),port:integer(1,65535),database:Type.String({minLength:1,maxLength:1024}),schema:Type.String({minLength:1,maxLength:1024}),secretRef:Type.String({minLength:1,maxLength:1024})}),execution})]);
const completion=Type.Union([object({claimId:uuid,attempt:integer(1,3),measurement}),object({claimId:uuid,attempt:integer(1,3),errorCode:choices(...QUALITY_ERRORS)})]);
const publish=object({id:uuid,expectedVersion:integer(0,2147483646),definition});
const problem=object({type:Type.String(),title:Type.String(),status:Type.Integer(),code:Type.String(),detail:Type.String(),correlationId:Type.String()});
export const qualityHttp={definition,rule,measurement,run,eligibility,execution,claim,completion,publish,problem,referenceMetadata,referenceBinding,rangeBinding};
export function qualityRawQuery(url:string,allowed:readonly string[]):Record<string,string|number>{
 const out:Record<string,string|number>=Object.create(null),raw=url.split('?').slice(1).join('?');if(!raw)return out;
 for(const pair of raw.split('&')){const equal=pair.indexOf('=');let key:string,value:string;
  try{key=decodeURIComponent((equal<0?pair:pair.slice(0,equal)).replaceAll('+',' '));value=decodeURIComponent((equal<0?'':pair.slice(equal+1)).replaceAll('+',' '));}catch{throw qualityInvalid();}
  if(!allowed.includes(key)||Object.hasOwn(out,key)||!value)throw qualityInvalid();
  if(key==='limit'||key==='version'){if(!/^[1-9][0-9]{0,9}$/.test(value)||Number(value)>(key==='limit'?100:2147483647))throw qualityInvalid();out[key]=Number(value);}else out[key]=value;
 }return out;
}
export function parseQualityRequestJSON(raw:string):unknown {try{if(Buffer.byteLength(raw)>16384)throw 0;return parseDomainRequestJSON(raw,'domain');}catch{throw qualityInvalid();}}
function idempotency(req:FastifyRequest):string {let count=0;for(let i=0;i<req.raw.rawHeaders.length;i+=2)if(req.raw.rawHeaders[i].toLowerCase()==='idempotency-key')count++;
 const value=req.headers['idempotency-key'];if(count>1||typeof value!=='string'||value.length<8||value.length>128||/[\u0000-\u001f\u007f]/.test(value))throw new Problem(400,'IDEMPOTENCY_REQUIRED','Send one bounded Idempotency-Key.');return value;}
type State={tenant:string;principal?:Principal;key?:string;query:Record<string,string|number>};
type Spec={params?:TProperties;query?:readonly string[];body?:TSchema;response:TSchema;mutation?:boolean;status?:number;internal?:boolean};
export async function installQuality(app:FastifyInstance):Promise<void>{
 await app.register(async child=>{
  const states=new WeakMap<FastifyRequest,State>();
  child.setValidatorCompiler(({schema})=>value=>Value.Check(schema as TSchema,value)?{value}:{error:qualityInvalid()});
  child.removeContentTypeParser('application/json');child.addContentTypeParser('application/json',{parseAs:'string',bodyLimit:16384},(_req,raw,done)=>{try{done(null,parseQualityRequestJSON(String(raw)));}catch{done(qualityInvalid());}});
  child.setErrorHandler((error,req,reply)=>{const e=error as {statusCode?:number;validation?:unknown};const known=error instanceof Problem?error:e.statusCode===429?new Problem(429,'RATE_LIMITED','Too many requests. Retry later.')
   :e.validation||[400,413,415].includes(e.statusCode??0)?qualityInvalid():qualityFailure(error);
   if(known.status>=500)req.log.error({code:known.code,correlationId:req.id},'Quality request failed; details redacted');if(known.status===503)reply.header('Retry-After','5');
   reply.code(known.status).type('application/problem+json').send({type:'about:blank',title:known.status>=500?'Service unavailable':'Request rejected',status:known.status,code:known.code,detail:known.message,correlationId:req.id});
  });
  function route(method:HTTPMethods,url:string,spec:Spec,work:(req:FastifyRequest,tx:Tx,state:State)=>Promise<unknown>){
   const params=object(spec.params??{}),query=object(Object.fromEntries((spec.query??[]).map(k=>[k,Type.Optional(Type.String({maxLength:k==='cursor'?1024:10}))]))),status=spec.status??200;
   child.route({method,url,bodyLimit:16384,schema:{params,querystring:query,...(spec.body?{body:spec.body}:{}),response:{[status]:spec.response,'4xx':problem,'5xx':problem}},
    onRequest:async req=>{if(spec.internal)states.set(req,{tenant:siteTenant(req),query:{}});else{const {principal}=await authenticate(req);states.set(req,{tenant:principal.tenantId,principal,query:{}});}},
    preValidation:async req=>{const state=states.get(req)!;state.query=qualityRawQuery(req.url,spec.query??[]);if(!Value.Check(params,req.params))throw qualityInvalid();if(spec.mutation)state.key=idempotency(req);
     if(spec.body){try{checkDomainData(req.body,'domain');}catch{throw qualityInvalid();}if(!Value.Check(spec.body,req.body))throw qualityInvalid();}else if(req.body!==undefined)throw qualityInvalid();},
    handler:async(req,reply)=>{const state=states.get(req)!;try{const result=await scope(state.tenant,state.principal?.id??'site:local',tx=>qualityQuery(tx,async()=>{
      const value=await work(req,tx,state);if(!Value.Check(spec.response,value))throw new Problem(500,'QUALITY_STORAGE_INVALID','The quality operation could not be completed.');return value;
     }));reply.code(status);return result;}catch(error){throw qualityFailure(error);}}
   });
  }
  const id=(req:FastifyRequest)=>(req.params as {id:string}).id;
  route('GET','/api/v1/assets/:id/quality',{params:{id:uuid},query:['limit','cursor'],response:object({assetId:uuid,eligibility,items:Type.Array(rule,{maxItems:100}),nextCursor:nullable(Type.String({maxLength:1024}))})},(r,tx,s)=>getQualityAsset(tx,s.principal!,id(r),s.query as QualityPageQuery));
  route('POST','/api/v1/quality/rules',{body:publish,response:object({rule}),mutation:true,status:201},(r,tx,s)=>{if((r.body as {expectedVersion:number}).expectedVersion!==0)throw qualityInvalid();return publishQualityRule(tx,s.principal!,r.body,s.key!,r.id);});
  route('GET','/api/v1/quality/rules/:id',{params:{id:uuid},query:['version'],response:object({rule})},async(r,tx,s)=>({rule:await getQualityRule(tx,s.principal!,id(r),s.query.version as number|undefined)}));
  route('POST','/api/v1/quality/rules/:id/versions',{params:{id:uuid},body:publish,response:object({rule}),mutation:true,status:201},(r,tx,s)=>{const b=r.body as {id:string;expectedVersion:number};if(b.id!==id(r)||b.expectedVersion<1)throw qualityInvalid();return publishQualityRule(tx,s.principal!,r.body,s.key!,r.id);});
  route('POST','/api/v1/quality/rules/:id/runs',{params:{id:uuid},body:object({id:uuid,ruleVersion:integer(),ruleHash:digest,referenceAsOf:Type.Optional(stamp)}),response:object({run}),mutation:true,status:202},(r,tx,s)=>requestQualityRun(tx,s.principal!,id(r),r.body,s.key!,r.id));
  route('GET','/api/v1/quality/rules/:id/runs',{params:{id:uuid},query:['limit','cursor'],response:page(run)},(r,tx,s)=>listQualityRuns(tx,s.principal!,id(r),s.query as QualityPageQuery));
  route('GET','/api/v1/quality/runs/:id',{params:{id:uuid},response:object({run})},async(r,tx,s)=>({run:await getQualityRun(tx,s.principal!,id(r))}));
  route('POST','/api/v1/quality/runs/:id/cancel',{params:{id:uuid},body:object({expectedVersion:integer(),reason:Type.String({minLength:1,maxLength:4096})}),response:object({run}),mutation:true},(r,tx,s)=>cancelQualityRun(tx,s.principal!,id(r),r.body,s.key!,r.id));
  route('GET','/internal/quality-runs/pending',{internal:true,response:object({items:Type.Array(object({tenantId:uuid,runId:uuid}),{maxItems:50})})},(_r,tx,s)=>pendingQualityRuns(tx,s.tenant));
  route('POST','/internal/quality-runs/:id/claim',{internal:true,params:{id:uuid},body:object({claimId:uuid}),response:claim},(r,tx)=>claimQualityRun(tx,id(r),r.body));
  route('POST','/internal/quality-runs/:id/finish',{internal:true,params:{id:uuid},body:completion,response:object({run})},(r,tx)=>finishQualityRun(tx,id(r),r.body));
 });
}
