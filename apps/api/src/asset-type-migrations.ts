// SPDX-License-Identifier: Apache-2.0
import type { FastifyInstance } from 'fastify';
import { Type } from '@sinclair/typebox';
import { scope } from '../../../packages/db/src/index.ts';
import { Problem } from '../../../packages/authz/src/index.ts';
import { Id } from '../../../packages/contracts/src/index.ts';
import { modelPersistence } from '../../../packages/domain/src/model-service.ts';
import { parseAssetTypeMigrationFile } from '../../../packages/domain/src/asset-type-migration.ts';
import { configureTypeMigrationTransaction, typeMigrationFailure, TYPE_MIGRATION_WRITE,
  getTypeMigrationContext, previewTypeMigration, executeTypeMigration, getTypeMigrationReceipt } from '../../../packages/domain/src/asset-type-migration-service.ts';
import type { TypeMigrationRequest, TypeMigrationExecutionRequest } from '../../../packages/domain/src/asset-type-migration-contracts.ts';
import { authenticate } from './security.ts';
import { record, once, assetView } from './repository.ts';
import { ModelId, modelParams, version } from './model-http.ts';

const hooks = { record, assetSnapshot: assetView };
const bodySchema = Type.Object({ definition: Type.Unknown(), plan: Type.Unknown() }, { additionalProperties: false });
export async function installAssetTypeMigrations(app: FastifyInstance): Promise<void> {
  app.post('/api/v1/asset-types/migration-plans/validate', { bodyLimit: 1_048_576,
    schema: { body: Type.Object({ text: Type.String({ maxLength: 524288 }) }, { additionalProperties: false }) } }, async req => {
    const { principal: p } = await authenticate(req);
    return scope(p.tenantId, p.id, async tx => {
      await modelPersistence.authorize(tx, p, TYPE_MIGRATION_WRITE);
      const parsed = parseAssetTypeMigrationFile((req.body as { text: string }).text);
      if (!parsed.ok) throw new Problem(422, 'ASSET_TYPE_MIGRATION_INVALID', 'Correct the complete type migration plan file.', parsed.issues);
      return { plan: parsed.value };
    });
  });
  app.get('/api/v1/asset-types/:id/migration-context', { schema: { params: modelParams } }, async req => {
    const { principal: p } = await authenticate(req);
    return scope(p.tenantId, p.id, tx => getTypeMigrationContext(tx, p, (req.params as { id: string }).id));
  });
  app.post('/api/v1/asset-types/:id/migration-previews', { bodyLimit: 1_048_576, schema: { params: modelParams, body: bodySchema } }, async req => {
    const { principal: p } = await authenticate(req);
    return scope(p.tenantId, p.id, async tx => ({ preview: await previewTypeMigration(tx, p, (req.params as { id: string }).id, version(req), req.body as TypeMigrationRequest) }));
  });
  app.post('/api/v1/asset-types/:id/migrations', { bodyLimit: 1_048_576, schema: { params: modelParams,
    body: Type.Object({ definition: Type.Unknown(), plan: Type.Unknown(), previewDigest: Type.String({ pattern: '^[a-f0-9]{64}$' }) }, { additionalProperties: false }) } }, async (req, reply) => {
    const { principal: p } = await authenticate(req), id = (req.params as { id: string }).id, expected = version(req), body = req.body as TypeMigrationExecutionRequest;
    try {
      const result = await scope(p.tenantId, p.id, async tx => {
        await configureTypeMigrationTransaction(tx);
        await modelPersistence.authorize(tx, p, TYPE_MIGRATION_WRITE);
        const executed = await once(tx, p, 'asset-type.migrate', req.headers['idempotency-key'], { id, expected, ...body },
          () => executeTypeMigration(tx, p, req.id, id, expected, body, hooks));
        // Replayed values require current role and visibility of the original recorded cohort.
        const authorized = await getTypeMigrationReceipt(tx, p, id, executed.receipt.id, true);
        return { type: executed.type, receipt: authorized.receipt };
      });
      reply.code(201); return result;
    } catch (original) {
      const error = typeMigrationFailure(original), code = error instanceof Problem ? error.code : 'TYPE_MIGRATION_EXECUTION_FAILED';
      // The failed canonical transaction has ended. A separate bounded audit never stores plan literals.
      try { await scope(p.tenantId, p.id, async tx => {
        await configureTypeMigrationTransaction(tx);
        await modelPersistence.authorize(tx, p, TYPE_MIGRATION_WRITE);
        await record(tx, p, 'model.type_migration_attempt_failed', id, expected, { code, attemptResult: 'failed', proposedVersion: expected + 1 }, req.id);
      }); } catch { req.log.error({ correlationId: req.id, event: 'type_migration_failure_audit_unavailable' }, 'Failure audit unavailable; details redacted'); }
      if (error instanceof Problem && error.status === 503) reply.header('Retry-After', '5');
      throw error;
    }
  });
  app.get('/api/v1/asset-types/:id/migrations/:migrationId', { schema: { params: Type.Object({ id: ModelId, migrationId: Id }, { additionalProperties: false }) } }, async req => {
    const { principal: p } = await authenticate(req), params = req.params as { id: string; migrationId: string };
    return scope(p.tenantId, p.id, tx => getTypeMigrationReceipt(tx, p, params.id, params.migrationId));
  });
}
