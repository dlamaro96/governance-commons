// SPDX-License-Identifier: Apache-2.0
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { Type } from '@sinclair/typebox';
import { scope, sql, type Tx } from '../../../packages/db/src/index.ts';
import { Problem, type Principal } from '../../../packages/authz/src/index.ts';
import { Id } from '../../../packages/contracts/src/index.ts';
import { modelPersistence } from '../../../packages/domain/src/model-service.ts';
import { typeHash } from '../../../packages/domain/src/asset-type-policy.ts';
import { parseBoundedJSONEnvelope } from '../../../packages/domain/src/model.ts';
import { parseGraphChangeSetFile } from '../../../packages/domain/src/relation-migration.ts';
import { getRelationMigrationContext, previewRelationMigration, prepareRelationType, executeRelationMigration, graphInvalid } from '../../../packages/domain/src/relation-migration-service.ts';
import { getRelationMigrationReceipt, getRelationPreparation } from '../../../packages/domain/src/relation-migration-read.ts';
import { listAssetParticipation, listParticipationRevisions } from '../../../packages/domain/src/relation-participation-read.ts';
import type { ParticipationListQuery } from '../../../packages/domain/src/relation-migration-contracts.ts';
import { GRAPH_WRITE } from '../../../packages/domain/src/relation-migration-store.ts';
import { relationQuery, relationFailure } from '../../../packages/domain/src/relation-store.ts';
import { authenticate } from './security.ts';
import { record, once, assetView } from './repository.ts';

const hooks = { record, assetSnapshot: assetView };
const params = Type.Object({ id: Id }, { additionalProperties: false });
const participationPage = { limit: Type.Optional(Type.Integer({ minimum: 1, maximum: 100 })), cursor: Type.Optional(Type.String({ minLength: 1, maxLength: 1024 })) };
function participationQuery(allowed: readonly string[]) {
  return async (req: FastifyRequest) => {
    // preValidation runs before AJV coercion; the raw spelling also catches
    // repeats and unknown fields before removeAdditional can erase evidence.
    const seen = new Set<string>();
    for (const [key, value] of new URL(req.url, 'http://local.invalid').searchParams) {
      if (!allowed.includes(key) || seen.has(key) || key === 'limit' && (!/^[1-9][0-9]*$/.test(value) || Number(value) > 100) ||
          key === 'status' && !['active', 'released', 'all'].includes(value) || key === 'cursor' && (!value.length || value.length > 1024))
        throw new Problem(400, 'RELATION_PAGE_INVALID', 'The participation query or page cursor is invalid.');
      seen.add(key);
    }
  };
}
function envelope(req: FastifyRequest, keys: string[]): Record<string, any> {
  const value = req.body;
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join('|') !== [...keys].sort().join('|'))
    throw new Problem(400, 'RELATION_JSON_INVALID', 'Provide exactly the declared request fields.');
  return value as Record<string, any>;
}
async function request<T>(req: FastifyRequest, work: (tx: Tx, p: Principal) => Promise<T>, mutation = false): Promise<T> {
  const { principal } = await authenticate(req);
  try { return await scope(principal.tenantId, principal.id, tx => relationQuery(tx, () => work(tx, principal))); }
  catch (original) {
    const error = relationFailure(original);
    if (mutation) try {
      await scope(principal.tenantId, principal.id, tx => relationQuery(tx, async () => {
        await modelPersistence.authorize(tx, principal, GRAPH_WRITE);
        await record(tx, principal, 'relation_migration.attempt_failed', 'unavailable', 0,
          { code: error instanceof Problem ? error.code : 'RELATION_MIGRATION_FAILED', attemptResult: 'failed' }, req.id);
      }));
    } catch { req.log.error({ correlationId: req.id, event: 'relation_migration_failure_audit_unavailable' }, 'Failure audit unavailable; details redacted'); }
    throw error;
  }
}
export async function installRelationMigrations(app: FastifyInstance): Promise<void> {
  await app.register(async child => {
    child.removeContentTypeParser('application/json');
    child.addContentTypeParser('application/json', { parseAs: 'string', bodyLimit: 1048576 }, (_req, body, done) => {
      const parsed = parseBoundedJSONEnvelope(String(body));
      if (!parsed.ok) { done(new Problem(400, 'RELATION_JSON_INVALID', 'Provide bounded JSON without duplicate object keys.', parsed.issues)); return; }
      done(null, parsed.value);
    });
    child.post('/api/v1/relation-migrations/validate', { bodyLimit: 1048576 }, req => request(req, async (tx, p) => {
      await modelPersistence.authorize(tx, p, GRAPH_WRITE);
      const body = envelope(req, ['text']); if (typeof body.text !== 'string') throw graphInvalid();
      const parsed = parseGraphChangeSetFile(body.text); if (!parsed.ok) throw graphInvalid(parsed.issues);
      return { changeSet: parsed.value };
    }));
    child.post('/api/v1/relation-migrations/context', req => request(req, (tx, p) => getRelationMigrationContext(tx, p, req.body)));
    child.post('/api/v1/relation-migrations/previews', req => request(req, (tx, p) => previewRelationMigration(tx, p, envelope(req, ['changeSet']).changeSet)));
    child.post('/api/v1/relation-migrations/preparations', async (req, reply) => {
      const result = await request(req, async (tx, p) => {
        const body = envelope(req, ['definition']); await modelPersistence.authorize(tx, p, GRAPH_WRITE);
        const stored = await once(tx, p, 'relation-migration.prepare', req.headers['idempotency-key'], req.body,
          () => prepareRelationType(tx, p, req.id, req.headers['idempotency-key'] as string, body.definition, hooks));
        // Replay reauthorizes the creator and returns the same original expiry.
        const response = await getRelationPreparation(tx, p, stored.preparation.id);
        const binding = await relationQuery(tx, () => tx.selectFrom('relation_type_preparations').select(['idempotency_key', 'request_hash'])
          .where('tenant_id', '=', p.tenantId).where('created_by', '=', p.id).where('id', '=', response.preparation.id).executeTakeFirst());
        if (!binding || binding.idempotency_key !== req.headers['idempotency-key'] || binding.request_hash !== typeHash(req.body))
          throw new Problem(500, 'RELATION_STORAGE_INVALID', 'The stored preparation binding could not be verified.');
        await relationQuery(tx, () => sql`SET CONSTRAINTS ALL IMMEDIATE`.execute(tx)); return response;
      }, true);
      reply.code(201); return result;
    });
    child.post('/api/v1/relation-migrations', async (req, reply) => {
      const result = await request(req, async (tx, p) => {
        await modelPersistence.authorize(tx, p, GRAPH_WRITE);
        if (req.body && typeof req.body === 'object' && !Array.isArray(req.body) &&
            Object.keys(req.body).every(key => ['changeSet', 'previewDigest'].includes(key)) &&
            !Object.hasOwn(req.body, 'previewDigest'))
          throw new Problem(428, 'RELATION_MIGRATION_PREVIEW_REQUIRED', 'Review a ready preview before execution.');
        const body = envelope(req, ['changeSet', 'previewDigest']);
        if (typeof body.previewDigest !== 'string' || !/^[a-f0-9]{64}$/.test(body.previewDigest))
          throw new Problem(428, 'RELATION_MIGRATION_PREVIEW_REQUIRED', 'Review a ready preview before execution.');
        const stored = await once(tx, p, 'relation-migration.execute', req.headers['idempotency-key'], req.body,
          () => executeRelationMigration(tx, p, req.id, req.headers['idempotency-key'] as string, { changeSet: body.changeSet, previewDigest: body.previewDigest }, hooks));
        await modelPersistence.authorize(tx, p, GRAPH_WRITE);
        // Current complete authorization also applies to an old successful retry.
        const response = await getRelationMigrationReceipt(tx, p, stored.receipt.id);
        if (response.receipt.executedBy !== p.id || response.receipt.requestHash !== typeHash(req.body))
          throw new Problem(500, 'RELATION_STORAGE_INVALID', 'The stored operation binding could not be verified.');
        await relationQuery(tx, () => sql`SET CONSTRAINTS ALL IMMEDIATE`.execute(tx)); return response;
      }, true);
      reply.code(201); return result;
    });
    child.get('/api/v1/relation-migrations/:id', { schema: { params } }, req => request(req, (tx, p) => getRelationMigrationReceipt(tx, p, (req.params as { id: string }).id)));
    child.get('/api/v1/assets/:id/relation-participation', {
      preValidation: participationQuery(['limit', 'cursor', 'status']),
      schema: { params, querystring: Type.Object({ ...participationPage,
        status: Type.Optional(Type.Union([Type.Literal('active'), Type.Literal('released'), Type.Literal('all')])) }, { additionalProperties: false }) },
    // Fastify's parsed nonempty query has a custom empty prototype. Copy the
    // validated own fields at this boundary; the domain still rejects exotic
    // caller objects and raw spelling checks still precede schema coercion.
    }, req => request(req, (tx, p) => listAssetParticipation(tx, p, (req.params as { id: string }).id, { ...(req.query as ParticipationListQuery) })));
    child.get('/api/v1/assets/:id/relation-participation/:bindingId/history', {
      preValidation: participationQuery(['limit', 'cursor']),
      schema: { params: Type.Object({ id: Id, bindingId: Id }, { additionalProperties: false }),
        querystring: Type.Object(participationPage, { additionalProperties: false }) },
    }, req => request(req, (tx, p) => {
      const { id, bindingId } = req.params as { id: string; bindingId: string };
      return listParticipationRevisions(tx, p, id, bindingId, { ...(req.query as Pick<ParticipationListQuery, 'limit' | 'cursor'>) });
    }));
  });
}
