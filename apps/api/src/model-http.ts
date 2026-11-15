// SPDX-License-Identifier: Apache-2.0
import type { FastifyRequest } from 'fastify';
import { Type } from '@sinclair/typebox';
import { Problem } from '../../../packages/authz/src/index.ts';

export const ModelId = Type.String({ pattern: '^[A-Za-z_][A-Za-z0-9_.-]{0,63}$' });
export const modelParams = Type.Object({ id: ModelId }, { additionalProperties: false });
export function version(req: FastifyRequest): number {
  const value = String(req.headers['if-match'] ?? '');
  if (!/^(?:[1-9][0-9]*|"[1-9][0-9]*")$/.test(value)) throw new Problem(428, 'VERSION_REQUIRED', 'Send the current version using If-Match.');
  const parsed = Number(value.replaceAll('"', ''));
  if (!Number.isSafeInteger(parsed) || parsed > 2_147_483_646) throw new Problem(400, 'VERSION_INVALID', 'The version is outside the supported range.');
  return parsed;
}
