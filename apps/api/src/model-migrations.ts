// SPDX-License-Identifier: Apache-2.0
import type { FastifyInstance } from 'fastify';
import { Type } from '@sinclair/typebox';
import { boundedModelScope as scope } from './model-http.ts';
import { Problem, requirePermission } from '../../../packages/authz/src/index.ts';
import { Id } from '../../../packages/contracts/src/index.ts';
import { parseBoundedJSONFile } from '../../../packages/domain/src/model.ts';
import { parseMigrationPlan } from '../../../packages/domain/src/model-migration.ts';
import { getMigrationContext, previewMigration, executeMigration, getMigrationReceipt, type MigrationRequest, type MigrationExecutionRequest } from '../../../packages/domain/src/model-migration-service.ts';
import { authenticate } from './security.ts';
import { record, once, assetView } from './repository.ts';
import { ModelId, modelParams, version } from './model-http.ts';

const hooks = { record, assetSnapshot: assetView };
const requestBody = Type.Object({ definition: Type.Unknown(), plan: Type.Unknown() }, { additionalProperties: false });
const writePermissions = ['models:read', 'models:write', 'catalog:read', 'catalog:write'];

export async function installModelMigrations(app: FastifyInstance): Promise<void> {
  app.post('/api/v1/models/migration-plans/validate', {
    bodyLimit: 1_048_576, schema: { body: Type.Object({ text: Type.String({ maxLength: 262_144 }) }, { additionalProperties: false }) },
  }, async req => {
    const { principal } = await authenticate(req); requirePermission(principal, 'models:write');
    const document = parseBoundedJSONFile((req.body as { text: string }).text, 'migration');
    const parsed = document.ok ? parseMigrationPlan(document.value) : document;
    if (!parsed.ok) throw new Problem(422, 'MODEL_MIGRATION_INVALID', 'Correct the migration plan file.', parsed.issues);
    return { plan: parsed.value };
  });
  app.get('/api/v1/models/:id/migration-context', { schema: { params: modelParams } }, async req => {
    const { principal: p } = await authenticate(req);
    return scope(p.tenantId, p.id, tx => getMigrationContext(tx, p, (req.params as { id: string }).id));
  });
  app.post('/api/v1/models/:id/migration-previews', { bodyLimit: 1_048_576, schema: { params: modelParams, body: requestBody } }, async req => {
    const { principal: p } = await authenticate(req), id = (req.params as { id: string }).id, expected = version(req);
    return scope(p.tenantId, p.id, async tx => ({ preview: await previewMigration(tx, p, id, expected, req.body as MigrationRequest) }));
  });
  app.post('/api/v1/models/:id/migrations', {
    bodyLimit: 1_048_576, schema: { params: modelParams, body: Type.Object({
      definition: Type.Unknown(), plan: Type.Unknown(), previewDigest: Type.String({ pattern: '^[a-f0-9]{64}$' }),
    }, { additionalProperties: false }) },
  }, async (req, reply) => {
    const { principal: p } = await authenticate(req);
    for (const permission of writePermissions) requirePermission(p, permission);
    const id = (req.params as { id: string }).id, expected = version(req), body = req.body as MigrationExecutionRequest;
    try {
      const result = await scope(p.tenantId, p.id, async tx => {
        const executed = await once(tx, p, 'model.migrate', req.headers['idempotency-key'], { id, expected, ...body },
          () => executeMigration(tx, p, req.id, id, expected, body, hooks));
        // Cached receipts can include literal values. Recheck their original
        // recorded assets and current write permission, even after reassignment.
        const authorized = await getMigrationReceipt(tx, p, id, executed.receipt.id, { forExecutionReplay: true });
        return { model: executed.model, receipt: authorized.receipt };
      });
      reply.code(201); return result;
    } catch (error) {
      // The failed mutation transaction has ended before this separate journal
      // transaction. Never persist raw plan literals, values, or SQL diagnostics.
      const code = error instanceof Problem ? error.code : 'MIGRATION_EXECUTION_FAILED';
      try {
        await scope(p.tenantId, p.id, tx => record(tx, p, 'model.migration_attempt_failed', id, expected,
          { code, attemptResult: 'failed', proposedVersion: expected + 1 }, req.id));
      } catch {
        req.log.error({ correlationId: req.id, event: 'model_migration_failure_audit_unavailable' }, 'Failure audit unavailable; details redacted');
      }
      throw error;
    }
  });
  app.get('/api/v1/models/:id/migrations/:migrationId', {
    schema: { params: Type.Object({ id: ModelId, migrationId: Id }, { additionalProperties: false }) },
  }, async req => {
    const { principal: p } = await authenticate(req), params = req.params as { id: string; migrationId: string };
    return scope(p.tenantId, p.id, tx => getMigrationReceipt(tx, p, params.id, params.migrationId));
  });
}
