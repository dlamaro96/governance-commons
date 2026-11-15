// SPDX-License-Identifier: Apache-2.0
import type { FastifyInstance } from 'fastify';
import { Type } from '@sinclair/typebox';
import { boundedModelScope as scope } from './model-http.ts';
import { Problem } from '../../../packages/authz/src/index.ts';
import { Id } from '../../../packages/contracts/src/index.ts';
import { parseAssetTypeFile } from '../../../packages/domain/src/asset-type.ts';
import { configureRelationTransaction, relationFailure } from '../../../packages/domain/src/relation-store.ts';
import { modelPersistence } from '../../../packages/domain/src/model-service.ts';
import { createAssetType, getAssetType, listAssetTypes, previewAssetType, publishAssetType,
  getAssetTypeState, transitionAssetTypeState } from '../../../packages/domain/src/asset-type-service.ts';
import { authenticate } from './security.ts';
import { record, once, assetView } from './repository.ts';
import { ModelId, modelParams, version } from './model-http.ts';

const hooks = { record, assetSnapshot: assetView };
const definitionBody = Type.Object({ definition: Type.Unknown() }, { additionalProperties: false });
export async function installAssetTypes(app: FastifyInstance): Promise<void> {
  app.get('/api/v1/asset-types', { schema: { querystring: Type.Object({ limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 100 })),
    q: Type.Optional(Type.String({ maxLength: 64 })), cursor: Type.Optional(Type.String({ maxLength: 1024 })) }, { additionalProperties: false }) } }, async req => {
    const { principal: p } = await authenticate(req);
    return scope(p.tenantId, p.id, tx => listAssetTypes(tx, p, req.query as any));
  });
  app.post('/api/v1/asset-types/validate', { bodyLimit: 1_048_576, schema: { body: Type.Object({ text: Type.String({ maxLength: 262144 }) }, { additionalProperties: false }) } }, async req => {
    const { principal: p } = await authenticate(req);
    return scope(p.tenantId, p.id, async tx => {
      await modelPersistence.authorize(tx, p, ['models:read', 'models:write']);
      const parsed = parseAssetTypeFile((req.body as { text: string }).text);
      if (!parsed.ok) throw new Problem(422, 'ASSET_TYPE_INVALID', 'Correct the authored asset type file.', parsed.issues);
      return { definition: parsed.value };
    });
  });
  app.get('/api/v1/asset-types/:id', { schema: { params: modelParams } }, async req => {
    const { principal: p } = await authenticate(req);
    return scope(p.tenantId, p.id, tx => getAssetType(tx, p, (req.params as any).id));
  });
  app.get('/api/v1/asset-types/:id/versions/:version', { schema: { params: Type.Object({ id: ModelId, version: Type.Integer({ minimum: 1, maximum: 2147483647 }) }, { additionalProperties: false }) } }, async req => {
    const { principal: p } = await authenticate(req), params = req.params as any;
    return scope(p.tenantId, p.id, tx => getAssetType(tx, p, params.id, params.version));
  });
  app.post('/api/v1/asset-types', { schema: { body: definitionBody } }, async (req, reply) => {
    const { principal: p } = await authenticate(req), input = (req.body as any).definition;
    return scope(p.tenantId, p.id, async tx => {
      await modelPersistence.authorize(tx, p, ['models:read', 'models:write']);
      const result = await once(tx, p, 'asset-type.create', req.headers['idempotency-key'], req.body,
        () => createAssetType(tx, p, req.id, input, hooks));
      await modelPersistence.authorize(tx, p, ['models:read', 'models:write']);
      await getAssetType(tx, p, result.type.id, result.type.version);
      reply.code(201); return result;
    });
  });
  app.post('/api/v1/asset-types/:id/previews', { schema: { params: modelParams, body: definitionBody } }, async req => {
    const { principal: p } = await authenticate(req);
    return scope(p.tenantId, p.id, async tx => ({ preview: await previewAssetType(tx, p, (req.params as any).id, version(req), (req.body as any).definition) }));
  });
  app.post('/api/v1/asset-types/:id/versions', { schema: { params: modelParams, body: Type.Object({ definition: Type.Unknown(), previewDigest: Type.String({ pattern: '^[a-f0-9]{64}$' }) }, { additionalProperties: false }) } }, async (req, reply) => {
    const { principal: p } = await authenticate(req), id = (req.params as any).id, expected = version(req), body = req.body as any;
    return scope(p.tenantId, p.id, async tx => {
      await modelPersistence.authorize(tx, p, ['models:read', 'models:write', 'catalog:read']);
      const result = await once(tx, p, 'asset-type.publish', req.headers['idempotency-key'], { id, expected, ...body },
        () => publishAssetType(tx, p, req.id, id, expected, body.definition, body.previewDigest, hooks));
      await modelPersistence.authorize(tx, p, ['models:read', 'models:write', 'catalog:read']);
      await getAssetType(tx, p, id, result.type.version);
      reply.code(201); return result;
    });
  });
  app.get('/api/v1/assets/:id/type-state', { schema: { params: Type.Object({ id: Id }, { additionalProperties: false }) } }, async req => {
    const { principal: p } = await authenticate(req);
    return scope(p.tenantId, p.id, tx => getAssetTypeState(tx, p, (req.params as any).id));
  });
  app.post('/api/v1/assets/:id/type-state', { schema: { params: Type.Object({ id: Id }, { additionalProperties: false }), body: Type.Object({ state: Type.String({ minLength: 1, maxLength: 64 }) }, { additionalProperties: false }) } }, async req => {
    const { principal: p } = await authenticate(req), id = (req.params as any).id, expected = version(req), state = (req.body as any).state;
    return scope(p.tenantId, p.id, async tx => {
      await configureRelationTransaction(tx);
      await modelPersistence.authorize(tx, p, ['catalog:read', 'catalog:write', 'models:read']);
      const result = await once(tx, p, 'asset.type-transition', req.headers['idempotency-key'], { id, expected, state },
        () => transitionAssetTypeState(tx, p, req.id, id, expected, state, hooks));
      // Cached outcomes remain subject to current endpoint visibility and role.
      await modelPersistence.authorize(tx, p, ['catalog:read', 'catalog:write', 'models:read']);
      await getAssetTypeState(tx, p, id);
      return result;
    }).catch(error => { throw relationFailure(error); });
  });
}
