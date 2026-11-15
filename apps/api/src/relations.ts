// SPDX-License-Identifier: Apache-2.0
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { Type } from '@sinclair/typebox';
import { scope, type Tx } from '../../../packages/db/src/index.ts';
import { Problem, type Principal } from '../../../packages/authz/src/index.ts';
import { Id } from '../../../packages/contracts/src/index.ts';
import { modelPersistence } from '../../../packages/domain/src/model-service.ts';
import { parseRelationTypeFile } from '../../../packages/domain/src/relation.ts';
import { parseBoundedJSONEnvelope } from '../../../packages/domain/src/model.ts';
import { relationQuery } from '../../../packages/domain/src/relation-store.ts';
import { configureRelationTransaction, relationFailure, relationValidationFailure,
  createRelationType, getRelationType, listRelationTypes, listRelationTypeVersions, previewRelationType, publishRelationType,
  createRelation, getRelation, editRelation, transitionRelation, tombstoneRelation, listRelationRevisions,
  listAssetRelations, getAssetGraph, authorizeRelationReplay } from '../../../packages/domain/src/relation-service.ts';
import { authenticate } from './security.ts';
import { record, once } from './repository.ts';
import { ModelId, modelParams, version } from './model-http.ts';

const object = (properties: Record<string, any>) => Type.Object(properties, { additionalProperties: false });
const positive = Type.Integer({ minimum: 1, maximum: 2147483647 });
const stamp = Type.Union([Type.Null(), Type.String({ pattern: '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$' })]);
const editable = { sourceAssetVersion: positive, targetAssetVersion: positive, attributes: Type.Unknown(), ownerId: Type.Union([Id, Type.Null()]),
  validFrom: stamp, validTo: stamp, visibility: Type.Union([Type.Literal('tenant'), Type.Literal('restricted')]), allowedIdentityIds: Type.Array(Id, { maxItems: 100, uniqueItems: true }) };
const edgeParams = object({ id: Id });
const page = { limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 100 })), cursor: Type.Optional(Type.String({ maxLength: 1024 })) };
const filters = { ...page, direction: Type.Optional(Type.Union([Type.Literal('in'), Type.Literal('out'), Type.Literal('both')])),
  relationTypeId: Type.Optional(Id), validAt: Type.Optional(Type.String({ maxLength: 24 })) };
const read = ['catalog:read', 'models:read'], write = [...read, 'catalog:write'], typeWrite = ['models:read', 'models:write'];
const hooks = { record };
async function request<T>(req: FastifyRequest, callback: (tx: Tx, p: Principal) => Promise<T>): Promise<T> {
  const { principal } = await authenticate(req);
  try { return await scope(principal.tenantId, principal.id, tx => relationQuery(tx, () => callback(tx, principal))); }
  catch (original) {
    const error = relationFailure(original), route = req.routeOptions.url ?? '';
    const mutation = ['POST', 'PATCH', 'DELETE'].includes(req.method) && !route.endsWith('/validate') && !route.endsWith('/previews');
    if (mutation) {
      const typeEvent = route.startsWith('/api/v1/relation-types');
      const resource = (req.params as { id?: string })?.id ?? 'unavailable';
      const code = error instanceof Problem ? error.code : 'RELATION_MUTATION_FAILED';
      try { await scope(principal.tenantId, principal.id, async tx => {
        await configureRelationTransaction(tx);
        await modelPersistence.authorize(tx, principal, typeEvent ? typeWrite : write);
        await record(tx, principal, typeEvent ? 'relation_type.attempt_failed' : 'relation.attempt_failed', resource, 0,
          { code, attemptResult: 'failed' }, req.id);
      }); } catch { req.log.error({ correlationId: req.id, event: 'relation_failure_audit_unavailable' }, 'Failure audit unavailable; details redacted'); }
    }
    throw error;
  }
}
/** Inspect original query spellings before Fastify's numeric coercion; repeated keys are never selectors. */
function query(req: FastifyRequest, allowed: string[]): any {
  const raw = new URL(req.url, 'http://local.invalid').searchParams, seen = new Set<string>();
  for (const [key, value] of raw) {
    if (!allowed.includes(key) || seen.has(key) || (['limit', 'depth'].includes(key) && !/^[1-9][0-9]*$/.test(value))) {
      throw new Problem(400, 'RELATION_PAGE_INVALID', 'Provide one canonical value for each supported query field.');
    }
    seen.add(key);
  }
  return req.query;
}
async function relationRoutes(app: FastifyInstance): Promise<void> {
  app.addHook('preValidation', async req => {
    if (req.body === undefined) return;
    const route = req.routeOptions.url, method = req.method;
    let allowed: string[];
    if (route === '/api/v1/relation-types/validate') allowed = ['text'];
    else if (route === '/api/v1/relation-types/:id/versions') allowed = ['definition', 'previewDigest'];
    else if (route?.startsWith('/api/v1/relation-types')) allowed = ['definition'];
    else if (method === 'DELETE') allowed = [];
    else if (route?.endsWith('/transitions')) allowed = ['state', 'sourceAssetVersion', 'targetAssetVersion'];
    else allowed = [...Object.keys(editable), ...(method === 'POST' ? ['relationTypeId', 'relationTypeVersion', 'sourceAssetId', 'targetAssetId'] : [])];
    const body = req.body as Record<string, unknown>;
    if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(key => !allowed.includes(key)) ||
      ['sourceAssetVersion', 'targetAssetVersion', 'relationTypeVersion'].some(key => key in body && typeof body[key] !== 'number') ||
      ['text', 'state', 'previewDigest', 'sourceAssetId', 'targetAssetId', 'relationTypeId'].some(key => key in body && typeof body[key] !== 'string') ||
      ['ownerId', 'validFrom', 'validTo'].some(key => key in body && body[key] !== null && (typeof body[key] !== 'string' || body[key] === '')) ||
      ('visibility' in body && typeof body.visibility !== 'string') ||
      ('allowedIdentityIds' in body && (!Array.isArray(body.allowedIdentityIds) || body.allowedIdentityIds.some(value => typeof value !== 'string')))) {
      throw new Problem(400, 'RELATION_INVALID', 'Provide only the declared JSON fields with their exact types.');
    }
  });
  app.post('/api/v1/relation-types/validate', { bodyLimit: 1048576, schema: { body: object({ text: Type.String({ maxLength: 262144 }) }) } }, req => request(req, async (tx, p) => {
    await modelPersistence.authorize(tx, p, typeWrite);
    const parsed = parseRelationTypeFile((req.body as any).text); if (!parsed.ok) throw relationValidationFailure(parsed.issues);
    return { definition: parsed.value };
  }));
  app.get('/api/v1/relation-types', { schema: { querystring: object({ ...page, q: Type.Optional(Type.String({ maxLength: 64 })) }) } }, req => request(req, (tx, p) => listRelationTypes(tx, p, query(req, ['q', 'limit', 'cursor']))));
  app.get('/api/v1/relation-types/:id', { schema: { params: modelParams } }, req => request(req, (tx, p) => getRelationType(tx, p, (req.params as any).id)));
  app.get('/api/v1/relation-types/:id/versions/:version', { schema: { params: object({ id: ModelId, version: positive }) } }, req => request(req, (tx, p) => getRelationType(tx, p, (req.params as any).id, (req.params as any).version)));
  app.get('/api/v1/relation-types/:id/versions', { schema: { params: modelParams, querystring: object(page) } }, req => request(req, (tx, p) => listRelationTypeVersions(tx, p, (req.params as any).id, query(req, ['limit', 'cursor']))));
  app.post('/api/v1/relation-types', { schema: { body: object({ definition: Type.Unknown() }) } }, async (req, reply) => {
    const result = await request(req, async (tx, p) => {
      await modelPersistence.authorize(tx, p, typeWrite);
      const result = await once(tx, p, 'relation-type.create', req.headers['idempotency-key'], req.body,
        () => createRelationType(tx, p, req.id, (req.body as any).definition, hooks));
      await modelPersistence.authorize(tx, p, typeWrite); await getRelationType(tx, p, result.type.id, result.type.version); return result;
    }); reply.code(201); return result;
  });
  app.post('/api/v1/relation-types/:id/previews', { schema: { params: modelParams, body: object({ definition: Type.Unknown() }) } }, req => request(req, async (tx, p) => ({ preview: await previewRelationType(tx, p, (req.params as any).id, version(req), (req.body as any).definition) })));
  app.post('/api/v1/relation-types/:id/versions', { schema: { params: modelParams, body: object({ definition: Type.Unknown(), previewDigest: Type.String({ pattern: '^[a-f0-9]{64}$' }) }) } }, async (req, reply) => {
    const result = await request(req, async (tx, p) => {
      const id = (req.params as any).id, expected = version(req), body = req.body as any;
      await modelPersistence.authorize(tx, p, [...typeWrite, 'catalog:read']);
      const result = await once(tx, p, 'relation-type.publish', req.headers['idempotency-key'], { id, expected, ...body },
        () => publishRelationType(tx, p, req.id, id, expected, body.definition, body.previewDigest, hooks));
      await modelPersistence.authorize(tx, p, [...typeWrite, 'catalog:read']); await getRelationType(tx, p, id, result.type.version); return result;
    }); reply.code(201); return result;
  });
  app.get('/api/v1/relations/:id', { schema: { params: edgeParams } }, req => request(req, (tx, p) => getRelation(tx, p, (req.params as any).id)));
  app.get('/api/v1/relations/:id/revisions', { schema: { params: edgeParams, querystring: object(page) } }, req => request(req, (tx, p) => listRelationRevisions(tx, p, (req.params as any).id, query(req, ['limit', 'cursor']))));
  app.post('/api/v1/relations', { schema: { body: object({ ...editable, relationTypeId: Id, relationTypeVersion: positive, sourceAssetId: Id, targetAssetId: Id }) } }, async (req, reply) => {
    const result = await request(req, async (tx, p) => {
      await modelPersistence.authorize(tx, p, write);
      const result = await once(tx, p, 'relation.create', req.headers['idempotency-key'], req.body,
        () => createRelation(tx, p, req.id, req.body as any, hooks));
      await authorizeRelationReplay(tx, p, result.relation, write); return result;
    }); reply.code(201); return result;
  });
  app.patch('/api/v1/relations/:id', { schema: { params: edgeParams, body: object(editable) } }, req => request(req, async (tx, p) => {
    const id = (req.params as any).id, expected = version(req), body = req.body as any;
    await modelPersistence.authorize(tx, p, write);
    const result = await once(tx, p, 'relation.edit', req.headers['idempotency-key'], { id, expected, ...body },
      () => editRelation(tx, p, req.id, id, expected, body, hooks));
    await authorizeRelationReplay(tx, p, result.relation, write); return result;
  }));
  app.post('/api/v1/relations/:id/transitions', { schema: { params: edgeParams, body: object({ state: ModelId, sourceAssetVersion: positive, targetAssetVersion: positive }) } }, req => request(req, async (tx, p) => {
    const id = (req.params as any).id, expected = version(req), body = req.body as any;
    await modelPersistence.authorize(tx, p, write);
    const result = await once(tx, p, 'relation.transition', req.headers['idempotency-key'], { id, expected, ...body },
      () => transitionRelation(tx, p, req.id, id, expected, body, hooks));
    await authorizeRelationReplay(tx, p, result.relation, write); return result;
  }));
  app.delete('/api/v1/relations/:id', { schema: { params: edgeParams } }, req => request(req, async (tx, p) => {
    if (req.body !== undefined) throw new Problem(400, 'RELATION_INVALID', 'This operation does not accept a body.');
    const id = (req.params as any).id, expected = version(req);
    await modelPersistence.authorize(tx, p, write);
    const result = await once(tx, p, 'relation.tombstone', req.headers['idempotency-key'], { id, expected },
      () => tombstoneRelation(tx, p, req.id, id, expected, hooks));
    await authorizeRelationReplay(tx, p, result.relation, write); return result;
  }));
  app.get('/api/v1/assets/:id/relations', { schema: { params: edgeParams, querystring: object(filters) } }, req => request(req, (tx, p) => listAssetRelations(tx, p, (req.params as any).id, query(req, ['limit', 'cursor', 'direction', 'relationTypeId', 'validAt']))));
  app.get('/api/v1/assets/:id/graph', { schema: { params: edgeParams, querystring: object({ ...filters, depth: Type.Optional(Type.Integer({ minimum: 1, maximum: 6 })) }) } }, req => request(req, (tx, p) => getAssetGraph(tx, p, (req.params as any).id, query(req, ['limit', 'cursor', 'direction', 'relationTypeId', 'validAt', 'depth']))));
}

/** Encapsulation keeps the strict relation JSON boundary local to these ingress adapters. */
export async function installRelations(app: FastifyInstance): Promise<void> {
  await app.register(async child => {
    child.removeContentTypeParser('application/json');
    child.addContentTypeParser('application/json', { parseAs: 'string', bodyLimit: 1048576 }, (req, body, done) => {
      // The tombstone route is bodyless, including clients that retain a JSON content type.
      // Any nonempty payload still passes through strict parsing and is rejected by that route.
      if (req.method === 'DELETE' && body === '') { done(null, undefined); return; }
      const parsed = parseBoundedJSONEnvelope(String(body));
      if (!parsed.ok) { done(new Problem(400, 'RELATION_JSON_INVALID', 'Provide bounded JSON without duplicate object keys.', parsed.issues)); return; }
      done(null, parsed.value);
    });
    await relationRoutes(child);
  });
}
