// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Problem } from '../../packages/authz/src/index.ts';
import { relationFailure } from '../../packages/domain/src/relation-store.ts';
import { graphInvalid } from '../../packages/domain/src/relation-migration-service.ts';

test('deferred participation rejection becomes an actionable constraint error', () => {
  const error = relationFailure({ code: '23514', message: 'RELATION_PARTICIPATION_REQUIRED', detail: 'private database detail' });
  assert.ok(error instanceof Problem);
  assert.equal(error.status, 422);
  assert.equal(error.code, 'RELATION_PARTICIPATION_REQUIRED');
  assert.doesNotMatch(error.message, /private database detail/);
});

test('complete hidden graph scope remains a generic denial without database details', () => {
  const error = relationFailure({ code: '42501', message: 'RELATION_SCOPE_UNAVAILABLE', detail: 'private subject and count' });
  assert.ok(error instanceof Problem);
  assert.equal(error.status, 403);
  assert.equal(error.code, 'RELATION_SCOPE_UNAVAILABLE');
  assert.doesNotMatch(error.message, /private subject|count/);
});

test('locked preparation expiry and consumption conflicts keep their documented statuses', () => {
  for (const [state, code, status] of [
    ['23514', 'RELATION_PREPARATION_EXPIRED', 410],
    ['23514', 'RELATION_PREPARATION_CONFLICT', 409],
    ['23505', 'RELATION_PREPARATION_CONFLICT', 409],
  ] as const) {
    const error = relationFailure({ code: state, message: code, detail: 'private preparation' });
    assert.ok(error instanceof Problem);
    assert.equal(error.status, status);
    assert.equal(error.code, code);
    assert.doesNotMatch(error.message, /private preparation/);
  }
});

test('SQL mapping requires both the known state and exact message', () => {
  for (const error of [
    { code: '23514', message: 'unknown invariant' },
    { code: '42501', message: 'unrecognized permission failure' },
    { code: '23514', message: 'RELATION_SCOPE_UNAVAILABLE' },
    { code: '42501', message: 'RELATION_PARTICIPATION_REQUIRED' },
  ]) assert.equal(relationFailure(error), error);
  const problem = new Problem(409, 'RELATION_PREVIEW_STALE', 'Refresh the preview.');
  assert.equal(relationFailure(problem), problem);
});

test('missing optimistic graph revisions use428 while invalid values and governed field names remain validation errors', () => {
  for (const path of ['/relationTargets/0/expectedHeadVersion', '/relationTargets/2/plan/edges/1/expectedVersion',
    '/relationTargets/2/plan/bindings/1/expectedVersion', '/relationTargets/0/plan/creations/3/sourceAssetVersion',
    '/relationTargets/0/plan/creations/3/targetAssetVersion', '/assetChanges/1/expectedVersion', '/assetTypeMigrations/0/expectedHeadVersion']) {
    const error = graphInvalid([{ code: 'required', path, message: 'Required field is missing.' }]);
    assert.equal(error.status, 428); assert.equal(error.code, 'VERSION_REQUIRED');
  }
  for (const issue of [
    { code: 'model_version' as const, path: '/assetChanges/1/expectedVersion', message: 'Invalid revision.' },
    { code: 'required' as const, path: '/assetChanges/1/attributes/expectedVersion', message: 'Required value.' },
    { code: 'required' as const, path: '/relationTargets/0/plan/creations/0/values/attributes/sourceAssetVersion', message: 'Required value.' },
  ]) { const error = graphInvalid([issue]); assert.equal(error.status, 422); assert.equal(error.code, 'RELATION_MIGRATION_INVALID'); }
  assert.equal(graphInvalid([{ code: 'limit', path: '', message: 'Bound exceeded.' }]).code, 'RELATION_PROFILE_LIMIT');
});
