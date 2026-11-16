// SPDX-License-Identifier: Apache-2.0
import type {FastifyInstance,FastifyRequest,HTTPMethods} from 'fastify';
import {Type,type TSchema,type TProperties} from '@sinclair/typebox';
import {Value} from '@sinclair/typebox/value';
import {scope,type Tx} from '../../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../../packages/authz/src/index.ts';
import {authenticate,siteTenant} from './security.ts';
import {parseDomainRequestJSON,checkDomainData} from './business-domain-http.ts';
import {approvalFailure,approvalQuery,listApprovalDefinitions,getApprovalDefinition,publishApprovalDefinition,
 listApprovalRequests,getApprovalRequest,decideApprovalTask,cancelApprovalRequest,pendingApprovals,tickApproval,approvalStatus,acknowledgeApprovalDispatch,
 type ApprovalPage,type ApprovalRequestPage,type ApprovalDecisionInput,type ApprovalCancelInput} from '../../../packages/domain/src/approval-service.ts';
import {submitGlossaryProposal,type GlossaryProposalInput} from '../../../packages/domain/src/glossary-service.ts';
import {GLOSSARY_LIMITS} from '../../../packages/domain/src/glossary-contracts.ts';
import {MODEL_LIMITS} from '../../../packages/domain/src/model.ts';
import {getGlossaryTerm} from '../../../packages/domain/src/glossary-publication-service.ts';
import {publishGlossaryFromSite} from './glossary-publication.ts';

const object=<T extends TProperties>(properties:T)=>Type.Object(properties,{additionalProperties:false});
const choices=(...values:string[])=>Type.Union(values.map(value=>Type.Literal(value)));
const uuid=Type.String({pattern:'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'});
const key=Type.String({pattern:'^(?!(?:__proto__|constructor|prototype)$)[A-Za-z_][A-Za-z0-9_.-]{0,63}$'});
const positive=Type.Integer({minimum:1,maximum:2147483647});
const digest=Type.String({pattern:'^[a-f0-9]{64}$'});
const stamp=Type.String({pattern:'^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$'});
const nullable=(schema:TSchema)=>Type.Union([schema,Type.Null()]);
const status=choices('pending','ready','rejected','cancelled','expired','succeeded','failed');
const definition=object({formatVersion:Type.Literal(1),id:key,version:positive,name:Type.String({minLength:1,maxLength:240}),separationOfDuties:Type.Boolean(),
 stages:Type.Array(object({id:key,name:Type.String({minLength:1,maxLength:240}),assignments:Type.Array(key,{minItems:1,maxItems:16,uniqueItems:true}),
  quorum:Type.Integer({minimum:1,maximum:16}),deadlineSeconds:Type.Integer({minimum:1,maximum:31536000}),rejection:Type.Literal('any')}),{minItems:1,maxItems:16})});
const definitionView=object({definition,definitionHash:digest,currentVersion:positive,createdAt:stamp,createdBy:uuid});
const translation=object({locale:Type.String({minLength:1,maxLength:MODEL_LIMITS.stringLength}),name:Type.String({minLength:1,maxLength:GLOSSARY_LIMITS.name}),
 definition:Type.String({minLength:1,maxLength:GLOSSARY_LIMITS.definition}),synonyms:Type.Array(Type.String({minLength:1,maxLength:GLOSSARY_LIMITS.name}),{maxItems:GLOSSARY_LIMITS.aliases}),
 abbreviations:Type.Array(Type.String({minLength:1,maxLength:GLOSSARY_LIMITS.name}),{maxItems:GLOSSARY_LIMITS.aliases}),
 examples:Type.Array(Type.String({minLength:1,maxLength:GLOSSARY_LIMITS.example}),{maxItems:GLOSSARY_LIMITS.examples})});
// Only additional governed attributes remain open JSON; the pure publication
// parser and exact pinned model validate their complete values without stripping.
const publication=object({typePin:object({typeId:uuid,modelId:key,version:positive,definitionHash:digest,resolutionHash:digest}),
 primaryLocale:Type.String({minLength:1,maxLength:MODEL_LIMITS.stringLength}),ownerId:uuid,visibility:choices('tenant','restricted'),
 allowedIdentityIds:Type.Array(uuid,{maxItems:GLOSSARY_LIMITS.allowedIdentities,uniqueItems:true}),state:choices('active','deprecated'),
 attributes:Type.Object({translations:Type.Array(translation,{minItems:1,maxItems:GLOSSARY_LIMITS.translations})},{additionalProperties:Type.Unknown(),maxProperties:128}),
 links:Type.Array(object({kind:choices('broader','related','defines'),typePin:object({relationTypeId:uuid,version:positive,definitionHash:digest}),
  targetAssetId:uuid,targetAssetVersion:positive}),{maxItems:GLOSSARY_LIMITS.links})});
const glossaryProposal=object({requestId:uuid,resourceId:uuid,resourceVersion:nullable(positive),publication,
 workflowPin:object({id:key,version:positive,definitionHash:digest}),assignments:Type.Record(key,uuid,{minProperties:1,maxProperties:256,additionalProperties:false}),expiresAt:stamp});
const summary={id:uuid,binding:Type.Literal('glossary.publish'),resourceId:uuid,resourceVersion:nullable(positive),proposalDigest:digest,workflowId:key,
 workflowVersion:positive,workflowHash:digest,requesterId:uuid,stageIndex:Type.Integer({minimum:0,maximum:15}),version:positive,status,
 expiresAt:stamp,createdAt:stamp,updatedAt:stamp,preconditionsCurrent:Type.Boolean()};
// Typed custom attributes are interpreted only by the pure glossary/model
// parsers. Their open JSON value shape is not an additional command language.
const publicationReceipt=object({id:uuid,assetId:uuid,assetVersion:positive,proposalDigest:digest,workflowPin:object({id:key,version:positive,definitionHash:digest}),
 graphReceiptId:nullable(uuid),executedBy:uuid,executedAt:stamp});
const requestView=object({...summary,payload:Type.Unknown(),workflow:definitionView,result:nullable(publicationReceipt),errorCode:nullable(Type.String({maxLength:80})),
 tasks:Type.Array(object({id:uuid,stageIndex:Type.Integer({minimum:0,maximum:15}),assignment:key,assignedIdentityId:uuid,version:positive,
  status:choices('waiting','open','decided','cancelled'),openedAt:nullable(stamp),expiresAt:nullable(stamp)}),{maxItems:256}),
 decisions:Type.Array(object({id:uuid,taskId:uuid,taskVersion:positive,actorId:uuid,decision:choices('approve','reject'),reason:Type.String({minLength:1,maxLength:4096}),decidedAt:stamp}),{maxItems:256})});
const pageOf=(schema:TSchema)=>object({items:Type.Array(schema,{maxItems:100}),nextCursor:nullable(Type.String({maxLength:1024}))});
const invalid=()=>new Problem(400,'APPROVAL_INPUT_INVALID','Provide exactly the declared approval fields and values.');
const problem=object({type:Type.String(),title:Type.String(),status:Type.Integer(),code:Type.String(),detail:Type.String(),correlationId:Type.String(),
 issues:Type.Optional(Type.Array(object({code:Type.String(),path:Type.String(),message:Type.String()})))});
export const approvalHttp={definition,definitionView,requestView,summary:object(summary),publication,glossaryProposal,publicationReceipt,problem};
const APPROVAL_BODY_BYTES=98_304,GLOSSARY_BODY_BYTES=327_680;
export function parseApprovalRequestJSON(raw:string,maximum:typeof APPROVAL_BODY_BYTES|typeof GLOSSARY_BODY_BYTES=APPROVAL_BODY_BYTES):unknown {
 try{if(![APPROVAL_BODY_BYTES,GLOSSARY_BODY_BYTES].includes(maximum)||Buffer.byteLength(raw)>maximum)throw 0;
  return parseDomainRequestJSON(raw,maximum===GLOSSARY_BODY_BYTES?'glossary-proposal':'domain');
 }catch{throw invalid();}
}
export function approvalRawQuery(req:Pick<FastifyRequest,'url'>,allowed:readonly string[]):Record<string,string|number|boolean>{
 const out:Record<string,string|number|boolean>=Object.create(null),raw=req.url.split('?').slice(1).join('?');
 if(!raw)return out;
 for(const pair of raw.split('&')){
  const equal=pair.indexOf('='),rawKey=equal<0?pair:pair.slice(0,equal),rawValue=equal<0?'':pair.slice(equal+1);
  let name:string,value:string;try{name=decodeURIComponent(rawKey.replaceAll('+',' '));value=decodeURIComponent(rawValue.replaceAll('+',' '));}catch{throw invalid();}
  if(!allowed.includes(name)||Object.hasOwn(out,name)||!value)throw invalid();
  if(name==='limit'){if(!/^[1-9][0-9]?$|^100$/.test(value))throw invalid();out[name]=Number(value);}
  else if(name==='assignedToMe'){if(value!=='true'&&value!=='false')throw invalid();out[name]=value==='true';}
  else out[name]=value;
 }
 return out;
}
function idempotency(req:FastifyRequest):string {
 let count=0;for(let i=0;i<req.raw.rawHeaders.length;i+=2)if(req.raw.rawHeaders[i].toLowerCase()==='idempotency-key')count++;
 const value=req.headers['idempotency-key'];if(count>1||typeof value!=='string'||value.length<8||value.length>128||/[\u0000-\u001f\u007f]/.test(value))throw new Problem(400,'IDEMPOTENCY_REQUIRED','Send one bounded Idempotency-Key.');return value;
}
type Spec={params?:TProperties;query?:readonly string[];body?:TSchema;response:TSchema;mutation?:boolean;created?:boolean;internal?:boolean;independentScope?:(req:FastifyRequest,state:State)=>Promise<unknown>;bodyLimit?:typeof GLOSSARY_BODY_BYTES};
type State={principal?:Principal;tenant:string;query:Record<string,string|number|boolean>;commandKey?:string};
/** The glossary application transaction validates submission references. Resource
 * publication is a separate protected effect and is not performed by this route. */
export async function installApprovals(app:FastifyInstance):Promise<void>{
 await app.register(async child=>{
  const states=new WeakMap<FastifyRequest,State>();
  child.setValidatorCompiler(({schema})=>value=>Value.Check(schema as TSchema,value)?{value}:{error:invalid()});
  child.removeContentTypeParser('application/json');
  child.addContentTypeParser('application/json',{parseAs:'string',bodyLimit:GLOSSARY_BODY_BYTES},(req,raw,done)=>{try{
   done(null,parseApprovalRequestJSON(String(raw),req.routeOptions.bodyLimit===GLOSSARY_BODY_BYTES?GLOSSARY_BODY_BYTES:APPROVAL_BODY_BYTES));
  }catch{done(invalid());}});
  child.setErrorHandler((error,req,reply)=>{
   const e=error as {statusCode?:number;validation?:unknown};
   const known=error instanceof Problem?error:e.statusCode===429?new Problem(429,'RATE_LIMITED','Too many requests. Retry later.')
    :e.validation||[400,413,415].includes(e.statusCode??0)?invalid():approvalFailure(error);
   if(known.status>=500)req.log.error({code:known.code,correlationId:req.id},'Approval request failed; details redacted');
   if(known.status===503)reply.header('Retry-After','5');
   reply.code(known.status).type('application/problem+json').send({type:'about:blank',title:known.status>=500?'Service unavailable':'Request rejected',
    status:known.status,code:known.code,detail:known.message,correlationId:req.id,...(known.issues&&known.status===422?{issues:known.issues}:{})});
  });
  function route(method:HTTPMethods,path:string,spec:Spec,work?:(req:FastifyRequest,tx:Tx,state:State)=>Promise<unknown>){
   const paramsSchema=object(spec.params??{}),querySchema=object(Object.fromEntries((spec.query??[]).map(name=>[name,Type.Optional(Type.String({maxLength:name==='cursor'?1024:120}))])));
   const statusCode=spec.created?201:200;
   child.route({method,url:path,bodyLimit:spec.bodyLimit??APPROVAL_BODY_BYTES,schema:{params:paramsSchema,querystring:querySchema,...(spec.body?{body:spec.body}:{}),
    response:{[statusCode]:spec.response,'4xx':problem,'5xx':problem}},
    onRequest:async req=>{if(spec.internal)states.set(req,{tenant:siteTenant(req),query:{}});else{const {principal}=await authenticate(req);states.set(req,{tenant:principal.tenantId,principal,query:{}});}},
    preValidation:async req=>{
     const state=states.get(req)!;state.query=approvalRawQuery(req,spec.query??[]);
     if(!Value.Check(paramsSchema,req.params))throw invalid();
     if(spec.mutation)state.commandKey=idempotency(req);
     if(spec.body){try{checkDomainData(req.body,spec.bodyLimit===GLOSSARY_BODY_BYTES?'glossary-proposal':'domain');}catch{throw invalid();}if(!Value.Check(spec.body,req.body))throw invalid();}
     else if(req.body!==undefined)throw invalid();
    },
    handler:async(req,reply)=>{const state=states.get(req)!;
     try{const checked=(value:unknown)=>{if(!Value.Check(spec.response,value))throw new Problem(500,'APPROVAL_STORAGE_INVALID','The approval operation could not be completed.');return value;};
      const value=spec.independentScope?checked(await spec.independentScope(req,state)):await scope(state.tenant,state.principal?.id??'site:local',tx=>approvalQuery(tx,async()=>checked(await work!(req,tx,state))));
      reply.code(statusCode);return value;}catch(error){throw approvalFailure(error);}
    }});
  }
  const params=(req:FastifyRequest)=>req.params as Record<string,string>;
  route('GET','/api/v1/glossary/terms/:id',{params:{id:uuid},response:object({resourceId:uuid,resourceVersion:positive,publication})},(req,tx,s)=>getGlossaryTerm(tx,s.principal!,params(req).id));
  route('POST','/api/v1/glossary/proposals',{body:glossaryProposal,response:object({request:requestView}),mutation:true,created:true,bodyLimit:GLOSSARY_BODY_BYTES},
   (req,tx,s)=>submitGlossaryProposal(tx,s.principal!,req.id,s.commandKey!,req.body as GlossaryProposalInput));
  route('GET','/api/v1/workflow-definitions',{query:['q','limit','cursor'],response:pageOf(definitionView)},(_req,tx,s)=>listApprovalDefinitions(tx,s.principal!,s.query as ApprovalPage));
  route('POST','/api/v1/workflow-definitions',{body:object({definition}),response:object({workflow:definitionView}),mutation:true,created:true},async(req,tx,s)=>({workflow:await publishApprovalDefinition(tx,s.principal!,(req.body as {definition:unknown}).definition,0,s.commandKey!,req.id)}));
  route('GET','/api/v1/workflow-definitions/:id',{params:{id:key},response:object({workflow:definitionView})},async(req,tx,s)=>({workflow:await getApprovalDefinition(tx,s.principal!,params(req).id)}));
  route('GET','/api/v1/workflow-definitions/:id/versions/:version',{params:{id:key,version:Type.String({pattern:'^[1-9][0-9]{0,9}$'})},response:object({workflow:definitionView})},async(req,tx,s)=>({workflow:await getApprovalDefinition(tx,s.principal!,params(req).id,Number(params(req).version))}));
  route('POST','/api/v1/workflow-definitions/:id/versions',{params:{id:key},body:object({definition,expectedVersion:positive}),response:object({workflow:definitionView}),mutation:true,created:true},async(req,tx,s)=>{
   const body=req.body as {definition:{id:string};expectedVersion:number};if(body.definition.id!==params(req).id)throw invalid();
   return {workflow:await publishApprovalDefinition(tx,s.principal!,body.definition,body.expectedVersion,s.commandKey!,req.id)};
  });
  route('GET','/api/v1/approval-requests',{query:['limit','cursor','status','assignedToMe'],response:pageOf(object(summary))},(_req,tx,s)=>listApprovalRequests(tx,s.principal!,s.query as ApprovalRequestPage));
  route('GET','/api/v1/approval-requests/:id',{params:{id:uuid},response:object({request:requestView})},async(req,tx,s)=>({request:await getApprovalRequest(tx,s.principal!,params(req).id)}));
  route('POST','/api/v1/approval-requests/:id/decisions',{params:{id:uuid},body:object({proposalDigest:digest,taskId:uuid,taskVersion:positive,decision:choices('approve','reject'),reason:Type.String({minLength:1,maxLength:4096})}),response:object({request:requestView}),mutation:true},
   (req,tx,s)=>decideApprovalTask(tx,s.principal!,params(req).id,req.body as ApprovalDecisionInput,s.commandKey!,req.id));
  route('POST','/api/v1/approval-requests/:id/cancel',{params:{id:uuid},body:object({proposalDigest:digest,reason:Type.String({minLength:1,maxLength:4096})}),response:object({request:requestView}),mutation:true},
   (req,tx,s)=>cancelApprovalRequest(tx,s.principal!,params(req).id,req.body as ApprovalCancelInput,s.commandKey!,req.id));
  route('GET','/internal/approvals/pending',{internal:true,response:object({items:Type.Array(object({tenantId:uuid,requestId:uuid,eventId:uuid}),{maxItems:50})})},(_req,tx,s)=>pendingApprovals(tx,s.tenant));
  route('GET','/internal/approvals/:id/status',{internal:true,params:{id:uuid},response:object({id:uuid,status,version:positive,nextWakeAt:nullable(stamp)})},(req,tx,s)=>approvalStatus(tx,s.tenant,params(req).id));
  route('POST','/internal/approvals/:id/publish',{internal:true,independentScope:(req,s)=>publishGlossaryFromSite(s.tenant,params(req).id),params:{id:uuid},body:object({}),response:object({id:uuid,status,version:positive,nextWakeAt:nullable(stamp)})});
  route('POST','/internal/approvals/:id/tick',{internal:true,params:{id:uuid},body:object({}),response:object({id:uuid,status,version:positive,nextWakeAt:nullable(stamp)})},(req,tx)=>tickApproval(tx,params(req).id));
  route('POST','/internal/approvals/dispatch/:id/ack',{internal:true,params:{id:uuid},body:object({}),response:object({id:uuid,acknowledged:Type.Literal(true)})},(req,tx)=>acknowledgeApprovalDispatch(tx,params(req).id));
 });
}
