// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { signedCursor } from '../../packages/domain/src/cursor.ts';

test('signed cursors reject tampering, unsigned input and malformed signatures', () => {
  const codec = signedCursor(randomBytes(32).toString('hex'), 'models');
  const value = { tenant: 'synthetic-tenant', q: 'أمثلة', after: 'asset_20' };
  const encoded = codec.encode(value);
  assert.deepEqual(codec.decode(encoded), value);
  const [payload, signature] = encoded.split('.');
  const forged = Buffer.from(JSON.stringify({ ...value, after: 'asset_40' })).toString('base64url');
  for (const input of [payload, `${forged}.${signature}`, `${payload}.${'A'.repeat(43)}`, encoded + '.extra', encoded + '=', '', 'a'.repeat(1025)]) {
    assert.throws(() => codec.decode(input));
  }
});

test('cursor keys fail closed and signatures are purpose- and key-bound', () => {
  for (const key of [undefined, '', 'a'.repeat(31)]) assert.throws(() => signedCursor(key, 'models'), { code: 'CURSOR_CONFIGURATION_INVALID' });
  const key = randomBytes(32).toString('hex'), codec = signedCursor(key, 'models');
  const encoded = codec.encode({ after: 'last' });
  assert.throws(() => signedCursor(key, 'assets').decode(encoded));
  assert.throws(() => signedCursor(randomBytes(32).toString('hex'), 'models').decode(encoded));
});

test('cursor envelope accommodates bounded Unicode searches and rejects oversized output', () => {
  const codec = signedCursor(randomBytes(32).toString('hex'), 'model-inventory-v2');
  const value = { v: 2, tenantId: 'a'.repeat(36), actorId: 'b'.repeat(36), q: 'ج'.repeat(64), sort: 'id:asc', limit: 100, after: 'x'.repeat(64) };
  assert.deepEqual(codec.decode(codec.encode(value)), value);
  assert.throws(() => codec.encode({ q: 'x'.repeat(1024) }));
});
