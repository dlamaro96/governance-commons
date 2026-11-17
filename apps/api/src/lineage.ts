// SPDX-License-Identifier: Apache-2.0
import type {FastifyInstance} from 'fastify';
import {Type} from '@sinclair/typebox';
import {scope} from '../../../packages/db/src/index.ts';
import {Id} from '../../../packages/contracts/src/index.ts';
import {getAssetLineage,lineageReadFailure,parseLineageQuery} from '../../../packages/domain/src/lineage-read.ts';
import {authenticate} from './security.ts';

export async function installLineage(app:FastifyInstance):Promise<void>{
 app.get('/api/v1/assets/:id/lineage',{schema:{params:Type.Object({id:Id},{additionalProperties:false}),querystring:Type.Object({direction:Type.Optional(Type.Union([Type.Literal('upstream'),Type.Literal('downstream'),Type.Literal('both')])),depth:Type.Optional(Type.Integer({minimum:1,maximum:6})),limit:Type.Optional(Type.Integer({minimum:1,maximum:100})),cursor:Type.Optional(Type.String({minLength:1,maxLength:1024}))},{additionalProperties:false})}},async req=>{
  const {principal}=await authenticate(req);
  const query=parseLineageQuery(req.url);
  try{return await scope(principal.tenantId,principal.id,tx=>getAssetLineage(tx,principal,(req.params as {id:string}).id,query));}
  catch(error){throw lineageReadFailure(error);}
 });
}
