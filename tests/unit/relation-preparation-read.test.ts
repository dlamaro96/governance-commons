// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import { Kysely, PostgresDialect } from 'kysely';
import type { Tx } from '../../packages/db/src/index.ts';
import { Problem, type Principal } from '../../packages/authz/src/index.ts';
import { getRelationPreparation } from '../../packages/domain/src/relation-migration-read.ts';

// Scripted PostgreSQL driver: these tests exercise the real reader, its query
// bindings and decision order. They do not qualify database time, RLS, protected
// preparation writes, idempotency storage or completed-operation replay.
const id = (value: number) => `90000000-0000-4000-8000-${String(value).padStart(12, '0')}`;
const principal: Principal = { id: id(1), tenantId: id(2), name: 'Synthetic preparation creator',
  permissions: ['models:read', 'models:write', 'catalog:read', 'catalog:write'] };
const preparationId = id(3), typeId = id(4), operationId = id(5);
const createdAt = '2000-01-01T00:00:00.000Z', expiresAt = '2000-01-01T00:15:00.000Z';
type Row = Record<string, unknown>;
function row(expired = false, consumed: string | null = null): Row {
  return { id: preparationId, type_id: typeId, definition_hash: 'a'.repeat(64),
    created_at: new Date(createdAt), expires_at: new Date(expiresAt), expired, consumed_operation_id: consumed };
}
function database(preparation: Row | null = row(), permissions: string[] | null = principal.permissions) {
  const calls: { kind: string; sql: string; parameters: readonly unknown[] }[] = [];
  const client = {
    release() {},
    async query(sql: string, parameters: readonly unknown[]) {
      let kind: string, rows: Row[];
      if (sql.includes('set_config')) { kind = 'deadline'; rows = []; }
      else if (sql.includes('from "memberships"')) { kind = 'authorize'; rows = permissions === null ? [] : [{ permissions }]; }
      else if (sql.includes('from "relation_type_preparations"')) { kind = 'preparation'; rows = preparation === null ? [] : [preparation]; }
      else throw Error(`Unexpected preparation-reader unit query: ${sql}`);
      calls.push({ kind, sql, parameters });
      return { command: 'SELECT', rowCount: rows.length, rows };
    },
  };
  const db = new Kysely<Record<string, any>>({ dialect: new PostgresDialect({ pool: { connect: async () => client, end: async () => {} } as any }) });
  return { tx: db as unknown as Tx, calls, close: () => db.destroy() };
}
async function run<T>(preparation: Row | null, work: (db: ReturnType<typeof database>) => Promise<T>, permissions: string[] | null = principal.permissions) {
  const db = database(preparation, permissions); try { return await work(db); } finally { await db.close(); }
}
const failure = (status: number, code: string) => (error: unknown) => {
  assert.ok(error instanceof Problem); assert.equal(error.status, status); assert.equal(error.code, code); return true;
};
const view = { id: preparationId, relationTypeId: typeId, definitionHash: 'a'.repeat(64), createdAt, expiresAt };

test('preparation reader uses database expiry result and retains exact original identity and timestamps', async () => {
  await run(row(false), async db => {
    // Past illustrative timestamps plus expired=false prove that this decision
    // consumes the database result; they do not simulate a real database clock.
    assert.deepEqual(await getRelationPreparation(db.tx, principal, preparationId), { preparation: view });
    const query = db.calls.find(call => call.kind === 'preparation')!;
    assert.match(query.sql, /expires_at <= clock_timestamp\(\)/);
    assert.match(query.sql, /"consumed_operation_id"/);
    assert.match(query.sql, /where "tenant_id" = \$1 and "created_by" = \$2 and "id" = \$3/);
    assert.deepEqual(query.parameters, [principal.tenantId, principal.id, preparationId]);
    assert.ok(db.calls.findIndex(call => call.kind === 'authorize') < db.calls.findIndex(call => call.kind === 'preparation'));
    assert.equal(db.calls.some(call => /^(insert|update|delete)\b/i.test(call.sql)), false);
  });
});

test('expired unconsumed preparation gives its authorized creator 410 without a renewed view', async () => {
  await run(row(true), db => assert.rejects(getRelationPreparation(db.tx, principal, preparationId), failure(410, 'RELATION_PREPARATION_EXPIRED')));
});

test('consumed preparation keeps original evidence before and after expiry without exposing private consumption fields', async () => {
  for (const expired of [false, true]) await run(row(expired, operationId), async db => {
    const result = await getRelationPreparation(db.tx, principal, preparationId);
    assert.deepEqual(result, { preparation: view });
    assert.equal(Object.hasOwn(result.preparation, 'consumedOperationId'), false);
    assert.equal(Object.hasOwn(result.preparation, 'expired'), false);
  });
});

test('creator-scoped missing result stays 404 for a different actor or tenant before an expiry decision', async () => {
  for (const actor of [principal, { ...principal, id: id(6) }, { ...principal, tenantId: id(7) }]) await run(null, async db => {
    await assert.rejects(getRelationPreparation(db.tx, actor, preparationId), failure(404, 'RELATION_PREPARATION_NOT_FOUND'));
    const query = db.calls.find(call => call.kind === 'preparation')!;
    assert.deepEqual(query.parameters, [actor.tenantId, actor.id, preparationId]);
  });
  await run(row(true), async db => {
    await assert.rejects(getRelationPreparation(db.tx, principal, 'invalid'), failure(404, 'RELATION_PREPARATION_NOT_FOUND'));
    assert.equal(db.calls.length, 0);
  });
});

test('fresh permission loss prevents any preparation lookup even when its scripted row is expired or consumed', async () => {
  for (const permissions of [null, principal.permissions.filter(action => action !== 'models:write')])
    await run(row(true, operationId), async db => {
      await assert.rejects(getRelationPreparation(db.tx, principal, preparationId), failure(403, 'FORBIDDEN'));
      assert.equal(db.calls.some(call => call.kind === 'preparation'), false);
    }, permissions);
});
