// SPDX-License-Identifier: Apache-2.0
import type { FastifyRequest } from 'fastify';
import { Type } from '@sinclair/typebox';
import { Problem } from '../../../packages/authz/src/index.ts';
import { scope, type Tx } from '../../../packages/db/src/index.ts';
import { relationQuery, relationFailure } from '../../../packages/domain/src/relation-store.ts';

/** Model operations now expand incident relation scope; bound waits before idempotency too. */
export async function boundedModelScope<T>(tenantId: string, actorId: string, work: (tx: Tx) => Promise<T>): Promise<T> {
  try { return await scope(tenantId, actorId, tx => relationQuery(tx, () => work(tx))); }
  catch (error) {
    // Preserve pre-existing model/type validation errors and constraint labels.
    if (error && typeof error === 'object' && 'code' in error && ['55P03', '40P01', '57014', '40001'].includes(String(error.code))) throw relationFailure(error);
    throw error;
  }
}

export const ModelId = Type.String({ pattern: '^[A-Za-z_][A-Za-z0-9_.-]{0,63}$' });
export const modelParams = Type.Object({ id: ModelId }, { additionalProperties: false });
export function version(req: FastifyRequest): number {
  const value = String(req.headers['if-match'] ?? '');
  if (!/^(?:[1-9][0-9]*|"[1-9][0-9]*")$/.test(value)) throw new Problem(428, 'VERSION_REQUIRED', 'Send the current version using If-Match.');
  const parsed = Number(value.replaceAll('"', ''));
  if (!Number.isSafeInteger(parsed) || parsed > 2_147_483_646) throw new Problem(400, 'VERSION_INVALID', 'The version is outside the supported range.');
  return parsed;
}
