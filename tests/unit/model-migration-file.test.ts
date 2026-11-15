// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseBoundedJSONFile, MODEL_LIMITS } from '../../packages/domain/src/model.ts';
import { parseMigrationPlan, MIGRATION_LIMITS } from '../../packages/domain/src/model-migration.ts';

test('declarative migration files reject duplicate escaped operation keys before JSON parsing can overwrite them', () => {
  for (const text of ['{"operations":[],"operations":[{"op":"remove"}]}', '{"operations":[{"op":"set","o\\u0070":"remove"}]}']) {
    const parsed = parseBoundedJSONFile(text);
    assert.equal(parsed.ok, false);
    if (!parsed.ok) assert.ok(parsed.issues.some(issue => issue.code === 'duplicate'));
  }
});

test('bounded raw migration parsing preserves exact decimal literals and rejects oversized or malformed documents', () => {
  const value = '12345678901234567890.123456789';
  const plan = { formatVersion: 1, modelId: 'harbor.file', targetVersion: 2, sourceVersions: [1], acknowledgedChanges: [],
    operations: [{ op: 'set', path: ['amount'], value, mode: 'replace' }] };
  const file = parseBoundedJSONFile(JSON.stringify(plan), 'migration');
  assert.equal(file.ok, true);
  if (file.ok) {
    const validated = parseMigrationPlan(file.value); assert.equal(validated.ok, true);
    if (validated.ok) assert.deepEqual(validated.value, plan);
  }
  assert.equal(parseBoundedJSONFile(' '.repeat(MODEL_LIMITS.fileLength + 1)).ok, false);
  assert.equal(parseBoundedJSONFile('{"operations":[').ok, false);
});

test('raw migration files round trip the full destructive-acknowledgement bound', () => {
  const plan = { formatVersion: 1, modelId: 'harbor.large_file', targetVersion: 2, sourceVersions: [], operations: [],
    acknowledgedChanges: Array.from({ length: MIGRATION_LIMITS.acknowledgements }, (_, i) => ({ code: 'attribute_removed', path: '/attributes/field' + i })) };
  assert.equal(parseMigrationPlan(plan).ok, true);
  const file = parseBoundedJSONFile(JSON.stringify(plan), 'migration');
  assert.equal(file.ok, true);
  if (file.ok) assert.deepEqual(parseMigrationPlan(file.value), parseMigrationPlan(plan));
  assert.equal(parseBoundedJSONFile(JSON.stringify(plan), 'model').ok, false);
});
