// SPDX-License-Identifier: Apache-2.0
/** Separate real wall-clock qualification, deliberately outside test:integration.
 * Run against a matching core API + SQL009 with seeded synthetic personas:
 *   node --import tsx --test --test-concurrency=1 --test-reporter=tap tests/qualification/relation-preparation-expiry.test.ts
 * Supply the existing private runtime DATABASE_URL and ordinary TEST_BASE_URL /
 * PUBLIC_URL through the environment; never paste or log credentials. Capture
 * TAP plus the exact executed image/source hashes as qualification evidence.
 * This takes at least 15 real minutes. No clock overrides, shortened leases,
 * protected-row edits, owner credentials, skipped assertions or fake time.
 * Source authoring/typechecking is NOT execution evidence. The test qualifies
 * preparation lifetime/replay only; joint positive-degree creation has its own
 * ordinary HTTP/browser gates. The unique authored type has no eligible assets.
 */
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { createHash, randomUUID } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { db, scope, sql } from '../../packages/db/src/index.ts';
import type { GraphChangeSet, RelationMigrationContext, RelationMigrationPreview, RelationMigrationReceipt,
  RelationPreparationView } from '../../packages/domain/src/relation-migration-contracts.ts';
import type { RelationTypeDefinitionV2 } from '../../packages/domain/src/relation-contracts.ts';
import { authoredDefinition, contextRequest, emptyChange, plan, positiveDefinition } from '../fixtures/relation-migration-api.ts';

const tenant = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', creator = '10000000-0000-4000-8000-000000000001';
const noncreator = '10000000-0000-4000-8000-000000000006';
const base = process.env.TEST_BASE_URL ?? 'http://api:4310', origin = process.env.PUBLIC_URL ?? 'http://localhost:4310';
type Headers = Record<string, string>;
const sessionIds: string[] = [];
before(async () => {
  assert.ok(process.env.DATABASE_URL, 'A real core runtime DATABASE_URL is required; no expiry checks ran.');
  const row = (await sql<{ installed: boolean; superuser: boolean; bypass: boolean; role: string }>`SELECT
    to_regclass('public.relation_type_preparations') IS NOT NULL AS installed,
    rolsuper AS superuser, rolbypassrls AS bypass, current_user AS role FROM pg_roles WHERE rolname=current_user`.execute(db)).rows[0];
  assert.ok(row?.installed, 'Matching SQL009 and API must be running before this qualification.');
  assert.equal(row.superuser, false); assert.equal(row.bypass, false); assert.equal(row.role, 'gc_app');
});
after(async () => {
  try { if (sessionIds.length) await db.deleteFrom('sessions').where('id_hash', 'in', sessionIds).execute(); }
  finally { await db.destroy(); }
});
async function session(actor: string): Promise<Headers> {
  const token = randomUUID() + randomUUID(), csrf = randomUUID(), hash = createHash('sha256').update(token).digest('hex');
  // Auth-session fixtures are the only direct SQL mutations. Canonical types,
  // preparations, protected outcomes and receipts are created through HTTP.
  await db.insertInto('sessions').values({ id_hash: hash, identity_id: actor, tenant_id: tenant, csrf,
    expires_at: sql`clock_timestamp() + interval '30 minutes'` }).execute();
  sessionIds.push(hash);
  return { Cookie: `gc_session=${token}`, 'X-CSRF-Token': csrf, Origin: origin, 'Content-Type': 'application/json' };
}
const mutation = (headers: Headers) => ({ ...headers, 'Idempotency-Key': randomUUID() });
function request(path: string, headers: Headers, body: unknown) {
  return fetch(`${base}/api/v1${path}`, { method: 'POST', headers, body: JSON.stringify(body), signal: AbortSignal.timeout(45_000) });
}
async function response<T = any>(result: Response, status: number): Promise<T> {
  const body = await result.json(); assert.equal(result.status, status, JSON.stringify(body)); return body as T;
}
async function failure(result: Response, status: number, code: string) {
  const body = await response(result, status); assert.equal(body.code, code); return body;
}
function creation(preparation: RelationPreparationView, definition: RelationTypeDefinitionV2): GraphChangeSet {
  return { ...emptyChange(), relationTargets: [{ kind: 'create', reservationId: preparation.id,
    expectedHeadVersion: null, definition, plan: plan(preparation.relationTypeId) }] };
}
async function reserve(headers: Headers, definition: RelationTypeDefinitionV2) {
  const preparationHeaders = mutation(headers), body = { definition };
  const { preparation } = await response<{ preparation: RelationPreparationView }>(
    await request('/relation-migrations/preparations', preparationHeaders, body), 201);
  assert.equal(Date.parse(preparation.expiresAt) - Date.parse(preparation.createdAt), 900_000);
  assert.notEqual(preparation.id, preparation.relationTypeId);
  return { preparation, headers: preparationHeaders, body, change: creation(preparation, definition) };
}
type Prepared = Awaited<ReturnType<typeof reserve>>;
interface Observation {
  id: string; created_at: Date; expires_at: Date; consumed_operation_id: string | null;
  expired: boolean; remaining_ms: string; checked_at: Date; created_exact: string; expires_exact: string;
}
async function observe(preparations: readonly Prepared[]): Promise<Observation[]> {
  return scope(tenant, creator, async tx => (await sql<Observation>`SELECT id, created_at, expires_at, consumed_operation_id,
    expires_at <= clock_timestamp() AS expired,
    extract(epoch FROM (expires_at - clock_timestamp())) * 1000 AS remaining_ms,
    clock_timestamp() AS checked_at, created_at::text AS created_exact, expires_at::text AS expires_exact
    FROM relation_type_preparations WHERE tenant_id=${tenant}::uuid AND created_by=${creator}::uuid
      AND id=ANY(${preparations.map(item => item.preparation.id)}::uuid[]) ORDER BY id`.execute(tx)).rows);
}
function originals(rows: readonly Observation[]) {
  return rows.map(row => ({ id: row.id, createdAt: row.created_exact, expiresAt: row.expires_exact, consumedOperationId: row.consumed_operation_id }));
}

test('real database-clock expiry cannot renew an unconsumed preparation and cannot invalidate a committed execution retry', { timeout: 1_320_000 }, async t => {
  const headers = await session(creator), otherHeaders = await session(noncreator), suffix = randomUUID().replaceAll('-', '');
  const { type } = await response(await request('/asset-types', mutation(headers), { definition: authoredDefinition(`expiry_asset_${suffix}`) }), 201);
  const unconsumed = await reserve(headers, positiveDefinition(`expiry_unconsumed_${suffix}`, type.typeId));
  const consumed = await reserve(headers, positiveDefinition(`expiry_consumed_${suffix}`, type.typeId));
  const reservations = [unconsumed, consumed];
  for (const reserved of reservations) {
    assert.deepEqual((await response<{ preparation: RelationPreparationView }>(await request('/relation-migrations/preparations', reserved.headers, reserved.body), 201)).preparation,
      reserved.preparation);
    const captured = (await response<{ context: RelationMigrationContext }>(await request('/relation-migrations/context', headers, contextRequest(reserved.change)), 200)).context;
    assert.equal(captured.before.endpoints.length, 0, 'The unique synthetic type must have a genuinely empty eligible cohort.');
    assert.deepEqual(captured.preparations, [reserved.preparation]);
    await failure(await request('/relation-migrations/context', otherHeaders, contextRequest(reserved.change)), 404, 'RELATION_PREPARATION_NOT_FOUND');
  }
  const reviewed = (await response<{ preview: RelationMigrationPreview }>(await request('/relation-migrations/previews', headers,
    { changeSet: consumed.change }), 200)).preview;
  assert.equal(reviewed.ready, true, JSON.stringify(reviewed.targetIssues)); assert.match(reviewed.previewDigest!, /^[a-f0-9]{64}$/);
  const executionHeaders = mutation(headers), executionBody = { changeSet: consumed.change, previewDigest: reviewed.previewDigest };
  const { receipt } = await response<{ receipt: RelationMigrationReceipt }>(await request('/relation-migrations', executionHeaders, executionBody), 201);
  assert.equal(receipt.creations.length, 0); assert.equal(receipt.enrollments.length, 0);
  const started = await observe(reservations); assert.equal(started.length, 2); assert.ok(started.every(row => !row.expired));
  assert.equal(started.find(row => row.id === unconsumed.preparation.id)!.consumed_operation_id, null);
  assert.equal(started.find(row => row.id === consumed.preparation.id)!.consumed_operation_id, receipt.id);
  for (const reserved of reservations) {
    const row = started.find(row => row.id === reserved.preparation.id)!;
    assert.equal(row.created_at.toISOString(), reserved.preparation.createdAt); assert.equal(row.expires_at.toISOString(), reserved.preparation.expiresAt);
  }
  t.diagnostic(JSON.stringify({ phase: 'waiting-for-original-database-expiry', observedAt: started[0].checked_at.toISOString(),
    preparations: originals(started), operationId: receipt.id, minimumLeaseMs: 900_000, maximumPollWaitMs: 30_000 }));
  // Wait against the original persisted deadline using database time. The
  // process's monotonic clock only caps the test; it cannot decide expiry.
  const stopAt = performance.now() + 1_020_000;
  let observed = started, pollCount = 0;
  while (!observed.every(row => row.expired)) {
    assert.ok(performance.now() < stopAt, 'Database expiry was not observed within the bounded real wait.');
    const remaining = Math.max(...observed.map(row => Number(row.remaining_ms)));
    assert.ok(Number.isFinite(remaining));
    await delay(Math.min(30_000, Math.max(100, remaining + 100)));
    observed = await observe(reservations); pollCount += 1;
    assert.equal(observed.length, 2); assert.deepEqual(originals(observed), originals(started));
    if (pollCount % 2 === 0) t.diagnostic(JSON.stringify({ phase: 'waiting', pollCount, observedAt: observed[0].checked_at.toISOString(),
      remainingMs: Math.max(0, ...observed.map(row => Math.ceil(Number(row.remaining_ms)))) }));
  }
  assert.ok(observed.every(row => row.checked_at.getTime() - row.created_at.getTime() >= 900_000));
  for (let attempt = 0; attempt < 2; attempt += 1)
    await failure(await request('/relation-migrations/preparations', unconsumed.headers, unconsumed.body), 410, 'RELATION_PREPARATION_EXPIRED');
  const hidden = await failure(await request('/relation-migrations/context', otherHeaders, contextRequest(unconsumed.change)), 404, 'RELATION_PREPARATION_NOT_FOUND');
  assert.equal(JSON.stringify(hidden).includes(unconsumed.preparation.expiresAt), false);
  await failure(await request('/relation-migrations/context', headers, contextRequest(unconsumed.change)), 410, 'RELATION_PREPARATION_EXPIRED');
  // Completed execution uses its original body and idempotency key after the
  // preparation expires. It does not request a new preview or consume again.
  const retry = await response<{ receipt: RelationMigrationReceipt }>(await request('/relation-migrations', executionHeaders, executionBody), 201);
  assert.deepEqual(retry.receipt, receipt);
  await failure(await request('/relation-migrations', mutation(headers), executionBody), 409, 'RELATION_PREPARATION_CONFLICT');
  const preparationReplay = await response<{ preparation: RelationPreparationView }>(await request('/relation-migrations/preparations', consumed.headers, consumed.body), 201);
  assert.deepEqual(preparationReplay.preparation, consumed.preparation);
  await failure(await request('/relation-migrations/context', otherHeaders, contextRequest(consumed.change)), 404, 'RELATION_PREPARATION_NOT_FOUND');
  const final = await observe(reservations); assert.equal(final.length, 2); assert.ok(final.every(row => row.expired));
  assert.deepEqual(originals(final), originals(started));
  t.diagnostic(JSON.stringify({ phase: 'qualified-original-expiry-and-replay', finishedAt: final[0].checked_at.toISOString(), pollCount,
    operationId: receipt.id, preparations: originals(final), elapsedDatabaseMs: final[0].checked_at.getTime() - started[0].checked_at.getTime(),
    unconsumedOriginalKeyStatus: 410, noncreatorStatus: 404, consumedExecutionOriginalKeyStatus: 201,
    consumedPreparationOriginalKeyStatus: 201, consumedNewExecutionKeyStatus: 409, clockOrProtectedRowOverrides: false }));
});
