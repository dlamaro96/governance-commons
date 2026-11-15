// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import { Kysely, PostgresDialect } from 'kysely';
import Fastify from 'fastify';
import type { Tx } from '../../packages/db/src/index.ts';
import { Problem, type Principal } from '../../packages/authz/src/index.ts';
import { listAssetParticipation, listParticipationRevisions } from '../../packages/domain/src/relation-participation-read.ts';
import { signedCursor } from '../../packages/domain/src/cursor.ts';
import { typeHash } from '../../packages/domain/src/asset-type-policy.ts';
import { structuralProjection } from '../../packages/domain/src/relation-participation.ts';
import { installRelationMigrations } from '../../apps/api/src/relation-migrations.ts';
import { a, actor, definition, id, policy, relationId } from './relation-participation-fixtures.ts';
import type { ParticipationBindingView } from '../../packages/domain/src/relation-migration-contracts.ts';

// This is a scripted driver, not a PostgreSQL substitute. It exercises service
// ordering, compiled SQL contracts, snapshot validation and actual cursor code;
// SQL009/RLS/concurrency and database aggregate behavior need their real gates.
const secret = 'synthetic-unit-cursor-key-not-a-runtime-credential';
process.env.SESSION_KEY = secret;
const principal: Principal = { id: actor, tenantId: id(90), name: 'Synthetic reader', permissions: ['catalog:read', 'models:read'] };
const bindingId = id(200), timestamp = '2026-11-16T00:00:00.000Z';
type Row = Record<string, any>;
function binding(changes: Partial<ParticipationBindingView> = {}): ParticipationBindingView {
  return { id: bindingId, version: 1, relationTypeId: relationId, relationTypeVersion: 1, assetId: a, assetVersion: 2,
    side: 'source', status: 'active', createdBy: actor, createdAt: timestamp, updatedBy: actor, updatedAt: timestamp, ...changes };
}
function stored(value = binding()): Row {
  return { tenant_id: principal.tenantId, id: value.id, version: value.version, relation_type_id: value.relationTypeId,
    relation_type_version: value.relationTypeVersion, asset_id: value.assetId, asset_version: value.assetVersion,
    side: value.side, status: value.status, created_by: value.createdBy, created_at: value.createdAt, updated_by: value.updatedBy, updated_at: value.updatedAt };
}
function withPolicy(row: Row, value = definition({ version: row.relation_type_version,
  cardinality: { outgoing: { min: 1, max: 5 }, incoming: { min: 2, max: 4 } } })): Row {
  const parsed = policy(value);
  return { ...row, policy_definition: parsed.definition, policy_hash: typeHash(parsed.definition), policy_version: parsed.definition.version };
}
function listRow(value = binding(), degree = '3') { return { ...withPolicy(stored(value)), degree }; }
function historyRow(value: ParticipationBindingView): Row {
  return withPolicy({ tenant_id: principal.tenantId, binding_id: value.id, version: value.version, snapshot: value,
    relation_type_id: value.relationTypeId, relation_type_version: value.relationTypeVersion, asset_id: value.assetId,
    asset_version: value.assetVersion, side: value.side, operation_id: id(300 + value.version), recorded_by: value.updatedBy, recorded_at: value.updatedAt });
}
interface Script {
  rows?: Row[]; revisions?: Row[]; current?: Row; hiddenDegree?: boolean; hiddenHistory?: boolean;
  missingAsset?: boolean; missingBinding?: boolean; revokeAfterPrincipalLock?: boolean;
  counter?: string; bytes?: number | ((query: string) => number);
}
function database(script: Script = {}) {
  const calls: { kind: string; sql: string; parameters: readonly unknown[] }[] = [];
  let principalLocked = false;
  const client = {
    release() {},
    async query(sql: string, parameters: readonly unknown[]) {
      let kind: string, rows: Row[];
      if (sql.includes('set_config')) { kind = 'deadline'; rows = []; }
      else if (sql.includes('pg_advisory_xact_lock')) { kind = 'scope-lock'; rows = []; }
      else if (sql.includes('gc_lock_type_migration_principals')) { kind = 'principal-lock'; principalLocked = true; rows = []; }
      else if (sql.includes('from "memberships"')) {
        kind = sql.includes('"memberships"."permissions"') ? 'authorize' : 'members';
        rows = kind === 'authorize' ? script.revokeAfterPrincipalLock && principalLocked ? [] : [{ permissions: principal.permissions }]
          : [{ identity_id: actor, active: true, identity_active: true }];
      } else if (sql.includes('from "assets"')) { kind = 'asset'; rows = script.missingAsset ? [] : [{ id: a, version: 9 }]; }
      else if (sql.startsWith('SELECT 1 FROM relations r')) { kind = 'degree-authorization'; rows = script.hiddenDegree ? [{ hidden: 1 }] : []; }
      else if (sql.includes('relation_graph_receipts operation')) { kind = 'history-authorization'; rows = script.hiddenHistory ? [{ binding_id: bindingId }] : []; }
      else if (sql.includes('from "tenant_graph_revisions"')) { kind = 'fence'; rows = [{ value: script.counter ?? '999999999999999999' }]; }
      else if (sql.includes('to_jsonb(bounded)')) { kind = 'size'; rows = [{ bytes: String(typeof script.bytes === 'function' ? script.bytes(sql) : script.bytes ?? 4096) }]; }
      else if (sql.includes('from "relation_participation_revisions" as "h"')) { kind = 'history-rows'; rows = script.revisions ?? []; }
      else if (sql.includes('from "relation_participations" as "b"')) { kind = 'list-rows'; rows = script.rows ?? [listRow()]; }
      else if (sql.includes('from "relation_participations"')) {
        kind = sql.startsWith('select "id"') ? 'binding-exists' : 'binding-row';
        rows = script.missingBinding ? [] : [script.current ?? stored()];
      } else throw new Error(`Unexpected unit query: ${sql}`);
      calls.push({ kind, sql, parameters }); return { command: 'SELECT', rowCount: rows.length, rows };
    },
  };
  const db = new Kysely<Record<string, any>>({ dialect: new PostgresDialect({ pool: { connect: async () => client, end: async () => {} } as any }) });
  return { tx: db as unknown as Tx, calls, close: () => db.destroy() };
}
async function run<T>(script: Script, work: (db: ReturnType<typeof database>) => Promise<T>) {
  const db = database(script); try { return await work(db); } finally { await db.close(); }
}
const code = (expected: string) => (error: unknown) => { assert.ok(error instanceof Problem); assert.equal(error.code, expected); return true; };

test('participation list preserves recorded pin and asset observation, uses current structural degree, and defaults to 50 active rows', async () => {
  await run({}, async db => {
    const result = await listAssetParticipation(db.tx, principal, a, {}), item = result.items[0];
    assert.deepEqual(item.binding, binding()); assert.equal(item.currentAssetVersion, 9); assert.equal(item.currentDegree, 3);
    assert.equal(item.minimum, 1); assert.equal(item.maximum, 5); assert.equal(item.policy.definition.version, 1);
    assert.equal(item.structuralFingerprint, typeHash(structuralProjection(item.policy.definition)));
    assert.match(result.snapshotToken, /^[A-Za-z0-9_-]{43}$/); assert.equal(result.nextCursor, null);
    const scope = db.calls.find(call => call.kind === 'degree-authorization')!;
    const page = db.calls.find(call => call.kind === 'list-rows')!;
    assert.ok(scope.parameters.includes('active')); assert.ok(page.parameters.includes(51));
    assert.match(page.sql, /order by "b"\."id" asc/); assert.match(page.sql, /r.status='active'/);
    assert.doesNotMatch(page.sql, /valid_from|valid_to|r\.state|current_version/);
    assert.ok(db.calls.findIndex(call => call.kind === 'degree-authorization') < db.calls.findIndex(call => call.kind === 'size'));
    assert.ok(db.calls.findIndex(call => call.kind === 'principal-lock') < db.calls.findIndex(call => call.kind === 'asset'));
    assert.equal(db.calls.at(-1)!.kind, 'authorize');
  });
});

test('released, target and undirected incident views use their exact policy bounds and live degree', async () => {
  const released = binding({ status: 'released', side: 'target' });
  await run({ rows: [listRow(released, '7')] }, async db => {
    const result = await listAssetParticipation(db.tx, principal, a, { status: 'released' });
    assert.equal(result.items[0].minimum, 2); assert.equal(result.items[0].maximum, 4); assert.equal(result.items[0].currentDegree, 7);
    assert.equal(result.items[0].binding.status, 'released');
  });
  const incident = binding({ side: 'incident' }), undirected = definition({ direction: 'undirected', allowSelf: true });
  await run({ rows: [{ ...withPolicy(stored(incident), undirected), degree: '1' }] }, async db => {
    const result = await listAssetParticipation(db.tx, principal, a, { status: 'all' });
    assert.equal(result.items[0].currentDegree, 1); assert.equal(result.items[0].maximum, null);
    const count = db.calls.find(call => call.kind === 'list-rows')!.sql;
    // OR counts a self edge once, not as two endpoint rows or a UNION ALL.
    assert.match(count, /r.source_asset_id=b.asset_id OR r.target_asset_id=b.asset_id/); assert.doesNotMatch(count, /union all/i);
  });
});

test('hidden degree scope fails before any count, size, fence or partial page, including a later binding', async () => {
  await run({ hiddenDegree: true, rows: [listRow(), listRow(binding({ id: id(201) }))], bytes: 999999 }, async db => {
    await assert.rejects(listAssetParticipation(db.tx, principal, a, { limit: 1 }), code('RELATION_SCOPE_UNAVAILABLE'));
    assert.deepEqual(db.calls.filter(call => ['fence', 'size', 'list-rows'].includes(call.kind)), []);
    const query = db.calls.find(call => call.kind === 'degree-authorization')!;
    assert.match(query.sql, /b\.relation_type_id=r\.relation_type_id/);
    assert.match(query.sql, /s\.tenant_id=r\.tenant_id/); assert.match(query.sql, /t\.tenant_id=r\.tenant_id/);
    assert.match(query.sql, /r\.allowed_identities/); assert.match(query.sql, /s\.allowed_identities/); assert.match(query.sql, /t\.allowed_identities/);
    assert.doesNotMatch(query.sql, /count\(|valid_from|valid_to|order by|b\.id[<>]/i);
  });
});

test('direct missing assets and mismatched binding paths are indistinguishable 404s; fresh revocation wins under locks', async () => {
  await run({ missingAsset: true }, db => assert.rejects(listAssetParticipation(db.tx, principal, a, {}), code('RELATION_NOT_FOUND')));
  await run({ missingBinding: true }, async db => {
    await assert.rejects(listParticipationRevisions(db.tx, principal, a, bindingId, {}), code('RELATION_NOT_FOUND'));
    assert.equal(db.calls.some(call => call.kind === 'history-authorization'), false);
    const query = db.calls.find(call => call.kind === 'binding-exists')!;
    assert.ok(query.parameters.includes(a)); assert.ok(query.parameters.includes(bindingId)); assert.ok(query.parameters.includes(principal.tenantId));
  });
  await run({ revokeAfterPrincipalLock: true }, async db => {
    await assert.rejects(listAssetParticipation(db.tx, principal, a, {}), code('FORBIDDEN'));
    assert.equal(db.calls.some(call => call.kind === 'asset'), false);
  });
});

test('list cursor binds actor, tenant, asset, filters, page size, purpose, last UUID and opaque fence', async () => {
  const first = await run({ rows: [listRow(), listRow(binding({ id: id(201) }))] }, db => listAssetParticipation(db.tx, principal, a, { limit: 1 }));
  assert.ok(first.nextCursor); const cursor = first.nextCursor;
  const decoded = signedCursor(secret, 'asset-participation').decode(cursor) as Row;
  assert.deepEqual(Object.keys(decoded).sort(), ['binding', 'fence', 'last', 'v']);
  assert.equal(decoded.last, bindingId); assert.equal(decoded.fence, first.snapshotToken);
  assert.equal(JSON.stringify(decoded).includes('999999999999999999'), false); assert.ok(cursor.length <= 1024);
  await run({ rows: [listRow(binding({ id: id(201) }))] }, async db => {
    const second = await listAssetParticipation(db.tx, principal, a, { limit: 1, cursor });
    assert.equal(second.items[0].binding.id, id(201)); assert.equal(second.snapshotToken, first.snapshotToken);
    const page = db.calls.find(call => call.kind === 'list-rows')!;
    assert.match(page.sql, /"b"\."id" > \$/); assert.ok(page.parameters.includes(bindingId));
  });
  for (const changed of [{ p: { ...principal, id: id(77) } }, { p: { ...principal, tenantId: id(78) } }, { asset: id(79) },
    { query: { limit: 2 } }, { query: { status: 'all' as const } }]) {
    await run({}, db => assert.rejects(listAssetParticipation(db.tx, changed.p ?? principal, changed.asset ?? a,
      { limit: 1, cursor, ...changed.query }), code('RELATION_PAGE_INVALID')));
  }
  await run({}, db => assert.rejects(listParticipationRevisions(db.tx, principal, a, bindingId, { limit: 1, cursor }), code('RELATION_PAGE_INVALID')));
  await run({ counter: '1000000000000000000' }, db => assert.rejects(listAssetParticipation(db.tx, principal, a, { limit: 1, cursor }), code('RELATION_GRAPH_STALE')));
  await run({ hiddenDegree: true, counter: '1000000000000000000' }, db => assert.rejects(listAssetParticipation(db.tx, principal, a, { limit: 1, cursor }), code('RELATION_SCOPE_UNAVAILABLE')));
  for (const altered of [{ ...decoded, last: 1 }, { ...decoded, counter: '999999999999999999' }, { ...decoded, fence: 'x' }, { ...decoded, v: 2 }]) {
    await run({}, db => assert.rejects(listAssetParticipation(db.tx, principal, a,
      { limit: 1, cursor: signedCursor(secret, 'asset-participation').encode(altered) }), code('RELATION_PAGE_INVALID')));
  }
  await run({}, db => assert.rejects(listAssetParticipation(db.tx, principal, a, { limit: 1, cursor: cursor + 'x' }), code('RELATION_PAGE_INVALID')));
});

test('history retains exact immutable policy and asset references, descending versions, and operation scope across all pages', async () => {
  const older = binding({ version: 2, assetVersion: 4, updatedAt: '2026-11-16T00:01:00.000Z' });
  const current = binding({ version: 3, relationTypeVersion: 2, assetVersion: 5, status: 'released', updatedAt: '2026-11-16T00:02:00.000Z' });
  const result = await run({ current: stored(current), revisions: [historyRow(current), historyRow(older)] }, async db => {
    const page = await listParticipationRevisions(db.tx, principal, a, bindingId, { limit: 1 });
    assert.deepEqual(page.items[0].binding, current); assert.deepEqual(page.items[0].assetRevision, { id: a, version: 5 });
    assert.equal(page.items[0].operationId, id(303)); assert.equal('currentDegree' in page.items[0], false);
    const auth = db.calls.find(call => call.kind === 'history-authorization')!;
    assert.match(auth.sql, /scope_asset/); assert.match(auth.sql, /scope_edge/); assert.match(auth.sql, /scope_binding/);
    assert.doesNotMatch(auth.sql, /"h"\."version" <|status='active'/);
    assert.ok(db.calls.findIndex(call => call.kind === 'history-authorization') < db.calls.findIndex(call => call.kind === 'size'));
    assert.match(db.calls.find(call => call.kind === 'history-rows')!.sql, /order by "h"\."version" desc/);
    return page;
  });
  assert.ok(result.nextCursor);
  const decoded = signedCursor(secret, 'binding-participation-history').decode(result.nextCursor) as Row;
  assert.equal(decoded.last, 3); assert.match(decoded.fence, /^[A-Za-z0-9_-]{43}$/);
  await run({ current: stored(current), revisions: [historyRow(older)] }, async db => {
    const page = await listParticipationRevisions(db.tx, principal, a, bindingId, { limit: 1, cursor: result.nextCursor! });
    assert.deepEqual(page.items[0].binding, older); assert.equal(page.items[0].assetRevision.version, 4); assert.equal(page.items[0].policy.definition.version, 1);
    assert.match(db.calls.find(call => call.kind === 'history-rows')!.sql, /"h"\."version" < \$/);
  });
  await run({}, db => assert.rejects(listParticipationRevisions(db.tx, principal, a, id(201), { limit: 1, cursor: result.nextCursor! }), code('RELATION_PAGE_INVALID')));
  await run({ hiddenHistory: true, bytes: 999999, counter: 'changed' }, async db => {
    await assert.rejects(listParticipationRevisions(db.tx, principal, a, bindingId, { limit: 1, cursor: result.nextCursor! }), code('RELATION_SCOPE_UNAVAILABLE'));
    assert.equal(db.calls.some(call => ['size', 'fence', 'history-rows'].includes(call.kind)), false);
  });
});

test('complete physical binding/revision rows and policy copies are bounded before JSON transfer', async () => {
  await run({ bytes: 524289 }, async db => {
    await assert.rejects(listAssetParticipation(db.tx, principal, a, {}), code('RELATION_PROFILE_LIMIT'));
    assert.equal(db.calls.some(call => call.kind === 'list-rows'), false);
    const query = db.calls.find(call => call.kind === 'size')!.sql;
    assert.match(query, /to_jsonb\(bounded\)/); assert.match(query, /"b"\.\*/); assert.match(query, /policy_definition/);
  });
  await run({ bytes: query => query.includes('"relation_participation_revisions"') ? 524289 : 1024 }, async db => {
    await assert.rejects(listParticipationRevisions(db.tx, principal, a, bindingId, {}), code('RELATION_PROFILE_LIMIT'));
    assert.equal(db.calls.some(call => call.kind === 'history-rows'), false);
    assert.match(db.calls.filter(call => call.kind === 'size').at(-1)!.sql, /"h"\.\*/);
  });
});

test('readers reject corrupt immutable snapshot references, attribution, policy hashes and side semantics', async () => {
  for (const changed of [
    { policy_hash: '0'.repeat(64) }, { policy_version: null }, { side: 'incident' }, { asset_version: 0 }, { degree: '-1' },
  ]) await run({ rows: [{ ...listRow(), ...changed }] }, db => assert.rejects(listAssetParticipation(db.tx, principal, a, {}), code('RELATION_STORAGE_INVALID')));
  const base = historyRow(binding());
  for (const changed of [
    { snapshot: { ...binding(), assetVersion: 77 } }, { snapshot: { ...binding(), relationTypeId: id(81) } },
    { snapshot: { ...binding(), secret: 'forbidden extra field' } }, { recorded_by: id(82) }, { recorded_at: 'invalid' },
    { operation_id: 'not-an-operation' }, { policy_hash: '0'.repeat(64) },
  ]) await run({ revisions: [{ ...base, ...changed }] }, db => assert.rejects(listParticipationRevisions(db.tx, principal, a, bindingId, {}), code('RELATION_STORAGE_INVALID')));
});

test('service queries reject coerced, unknown, out-of-range and accessor fields', async () => {
  for (const query of [{ limit: '1' }, { limit: 0 }, { limit: 101 }, { limit: 1.5 }, { limit: null }, { cursor: '' },
    { cursor: 'x'.repeat(1025) }, { status: 'ACTIVE' }, { status: null }, { other: 1 }, { limit: [1] }]) {
    await run({}, db => assert.rejects(listAssetParticipation(db.tx, principal, a, query as any), code('RELATION_PAGE_INVALID')));
  }
  let invoked = false;
  await run({}, db => assert.rejects(listAssetParticipation(db.tx, principal, a,
    Object.defineProperty({}, 'limit', { enumerable: true, get() { invoked = true; return 1; } })), code('RELATION_PAGE_INVALID')));
  assert.equal(invoked, false);
  await run({}, db => assert.rejects(listParticipationRevisions(db.tx, principal, a, bindingId, { status: 'all' } as any), code('RELATION_PAGE_INVALID')));
});

test('HTTP preValidation rejects repeated and coerced participation query spellings before AJV can erase them', async () => {
  const app = Fastify();
  app.setErrorHandler((error: any, _request, reply) => reply.code(error instanceof Problem ? error.status : 500).send({ code: error.code }));
  await installRelationMigrations(app);
  try {
    for (const suffix of ['?limit=01', '?limit=1e1', '?limit=1.0', '?limit=+1', '?limit=0', '?limit=101', '?limit=1&limit=2',
      '?status=active&status=released', '?unknown=x', '?cursor=', '?status=ACTIVE']) {
      const response = await app.inject({ method: 'GET', url: `/api/v1/assets/${a}/relation-participation${suffix}` });
      assert.equal(response.statusCode, 400, suffix); assert.equal(response.json().code, 'RELATION_PAGE_INVALID', suffix);
    }
    const response = await app.inject({ method: 'GET', url: `/api/v1/assets/${a}/relation-participation/${bindingId}/history?status=active` });
    assert.equal(response.statusCode, 400); assert.equal(response.json().code, 'RELATION_PAGE_INVALID');
  } finally { await app.close(); }
});
