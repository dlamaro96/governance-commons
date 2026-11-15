// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseBoundedJSONEnvelope, parseBoundedJSONFile } from '../../packages/domain/src/model.ts';
test('HTTP envelopes retain duplicate-key rejection and independent UTF8 bounds without relaxing authored file limits', () => {
  for (const text of ['{"definition":{"version":1,"version":2}}', '{"ownerId":null,"owner\\u0049d":"overwritten"}', '{"attributes":{"nested":[{"x":1,"x":2}]}}']) {
    const parsed = parseBoundedJSONEnvelope(text); assert.equal(parsed.ok, false);
    if (!parsed.ok) assert.ok(parsed.issues.some(issue => issue.code === 'duplicate'));
  }
  const envelope = JSON.stringify({ text: 'a'.repeat(270000) });
  assert.equal(parseBoundedJSONEnvelope(envelope).ok, true); assert.equal(parseBoundedJSONFile(envelope).ok, false);
  assert.equal(parseBoundedJSONEnvelope(JSON.stringify({ text: '界'.repeat(350000) })).ok, false);
  const parsed = parseBoundedJSONEnvelope('{"version":"1","identities":"uuid"}');
  assert.ok(parsed.ok); assert.deepEqual(parsed.value, { version: '1', identities: 'uuid' });
});
