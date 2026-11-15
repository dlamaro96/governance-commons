// SPDX-License-Identifier: Apache-2.0
import { createHmac, timingSafeEqual } from 'node:crypto';
import { Problem } from '../../authz/src/index.ts';

/** Signed selectors are not authorization grants. Callers still bind and authorize every page. */
export function signedCursor(secret: string | undefined, purpose: string) {
  if (!secret || Buffer.byteLength(secret) < 32) {
    throw new Problem(500, 'CURSOR_CONFIGURATION_INVALID', 'Page cursors are temporarily unavailable.');
  }
  const signature = (payload: string) => createHmac('sha256', secret)
    .update(`governance-commons:cursor:${purpose}\0`).update(payload).digest();
  const invalid = () => new Error('Invalid signed cursor');
  return {
    encode(value: unknown): string {
      const payload = Buffer.from(JSON.stringify(value)).toString('base64url');
      const encoded = `${payload}.${signature(payload).toString('base64url')}`;
      if (encoded.length > 1024) throw invalid();
      return encoded;
    },
    decode(input: string): unknown {
      if (typeof input !== 'string' || input.length > 1024 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/.test(input)) throw invalid();
      const [payload, mac] = input.split('.');
      const received = Buffer.from(mac, 'base64url');
      if (received.length !== 32 || received.toString('base64url') !== mac || !timingSafeEqual(received, signature(payload))) throw invalid();
      const decoded = Buffer.from(payload, 'base64url');
      if (decoded.toString('base64url') !== payload) throw invalid();
      return JSON.parse(decoded.toString('utf8'));
    },
  };
}
