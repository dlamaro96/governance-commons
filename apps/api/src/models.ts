// SPDX-License-Identifier: Apache-2.0
import type {FastifyInstance} from 'fastify';
import {Type} from '@sinclair/typebox';
import {scope} from '../../../packages/db/src/index.ts';
import {Problem, requirePermission} from '../../../packages/authz/src/index.ts';
import {Id} from '../../../packages/contracts/src/index.ts';
import {parseModelFile} from '../../../packages/domain/src/model.ts';
import {listModels,getModel,createModel,previewModel,publishModel,getAssetModel,assignAssetModel,modelPersistence} from '../../../packages/domain/src/model-service.ts';
import {authenticate} from './security.ts';
import {record,once,assetView} from './repository.ts';
import {ModelId,modelParams,version} from './model-http.ts';

const definitionBody=Type.Object({definition:Type.Unknown()},{additionalProperties:false});
const hooks={record,assetSnapshot:assetView};

/** Every ingress delegates typed validation and mutations to one application service. */
export async function installModels(app:FastifyInstance):Promise<void> {
 app.get('/api/v1/models',{schema:{querystring:Type.Object({limit:Type.Optional(Type.Integer({minimum:1,maximum:100})),cursor:Type.Optional(Type.String({maxLength:1024})),q:Type.Optional(Type.String({maxLength:64}))},{additionalProperties:false})}},async req=>{
  const {principal:p}=await authenticate(req);
  return scope(p.tenantId,p.id,tx=>listModels(tx,p,req.query as {limit?:number;cursor?:string;q?:string}));
 });
 app.get('/api/v1/models/:id',{schema:{params:modelParams}},async req=>{
  const {principal:p}=await authenticate(req);
  return scope(p.tenantId,p.id,tx=>getModel(tx,p,(req.params as {id:string}).id));
 });
 app.get('/api/v1/models/:id/versions/:version',{schema:{params:Type.Object({id:ModelId,version:Type.Integer({minimum:1,maximum:2_147_483_647})},{additionalProperties:false})}},async req=>{
  const {principal:p}=await authenticate(req),params=req.params as {id:string;version:number};
  return scope(p.tenantId,p.id,tx=>getModel(tx,p,params.id,params.version));
 });
 app.post('/api/v1/models/validate',{bodyLimit:1_048_576,schema:{body:Type.Object({text:Type.String({maxLength:262_144})},{additionalProperties:false})}},async req=>{
  const {principal:p}=await authenticate(req);requirePermission(p,'models:write');
  const parsed=parseModelFile((req.body as {text:string}).text);
  if(!parsed.ok)throw new Problem(422,'MODEL_INVALID','Check the model definition.',parsed.issues);
  return {definition:parsed.value};
 });
 app.post('/api/v1/models',{bodyLimit:1_048_576,schema:{body:definitionBody}},async(req,reply)=>{
  const {principal:p}=await authenticate(req);requirePermission(p,'models:write');requirePermission(p,'models:read');
  const body=req.body as {definition:unknown};
  const result=await scope(p.tenantId,p.id,async tx=>{
   const result=await once(tx,p,'model.create',req.headers['idempotency-key'],body,()=>createModel(tx,p,req.id,body.definition,hooks));
   await modelPersistence.authorize(tx,p,['models:read','models:write']);
   return result;
  });
  reply.code(201);return result;
 });
 app.post('/api/v1/models/:id/previews',{bodyLimit:1_048_576,schema:{params:modelParams,body:definitionBody}},async req=>{
  const {principal:p}=await authenticate(req),id=(req.params as {id:string}).id,expected=version(req);
  return scope(p.tenantId,p.id,async tx=>({preview:await previewModel(tx,p,id,expected,(req.body as {definition:unknown}).definition)}));
 });
 app.post('/api/v1/models/:id/versions',{bodyLimit:1_048_576,schema:{params:modelParams,body:Type.Object({definition:Type.Unknown(),previewDigest:Type.String({pattern:'^[a-f0-9]{64}$'})},{additionalProperties:false})}},async(req,reply)=>{
  const {principal:p}=await authenticate(req);requirePermission(p,'models:read');requirePermission(p,'models:write');requirePermission(p,'catalog:read');
  const id=(req.params as {id:string}).id,expected=version(req),body=req.body as {definition:unknown;previewDigest:string};
  const result=await scope(p.tenantId,p.id,async tx=>{
   const result=await once(tx,p,'model.publish',req.headers['idempotency-key'],{id,expected,...body},()=>publishModel(tx,p,req.id,id,expected,body.definition,body.previewDigest,hooks));
   await modelPersistence.authorize(tx,p,['models:read','models:write','catalog:read']);
   return result;
  });
  reply.code(201);return result;
 });
 app.get('/api/v1/assets/:id/attributes',{schema:{params:Type.Object({id:Id},{additionalProperties:false})}},async req=>{
  const {principal:p}=await authenticate(req);
  return scope(p.tenantId,p.id,tx=>getAssetModel(tx,p,(req.params as {id:string}).id));
 });
 app.put('/api/v1/assets/:id/attributes',{bodyLimit:1_048_576,schema:{params:Type.Object({id:Id},{additionalProperties:false}),body:Type.Object({modelId:ModelId,modelVersion:Type.Integer({minimum:1,maximum:2_147_483_647}),attributes:Type.Unknown()},{additionalProperties:false})}},async(req,reply)=>{
  const {principal:p}=await authenticate(req);requirePermission(p,'catalog:read');requirePermission(p,'catalog:write');requirePermission(p,'models:read');
  const id=(req.params as {id:string}).id,expected=version(req),body=req.body as {modelId:string;modelVersion:number;attributes:unknown};
  const result=await scope(p.tenantId,p.id,async tx=>{
   // A cached response must never bypass a later asset visibility revocation.
   await getAssetModel(tx,p,id);
   const result=await once(tx,p,'asset.model.assign',req.headers['idempotency-key'],{id,expected,...body},()=>assignAssetModel(tx,p,req.id,id,expected,body,hooks));
   await modelPersistence.authorize(tx,p,['catalog:read','catalog:write','models:read']);
   await getAssetModel(tx,p,id);
   return result;
  });
  reply.header('ETag',String(result.assetVersion));return result;
 });
}
