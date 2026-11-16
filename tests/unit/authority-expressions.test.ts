// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { evaluatePolicyExpression, type ExpressionFacts, type ExpressionRequest, type Fact } from '../../packages/authority/src/expressions.ts';
import { parsePolicy } from '../../packages/authority/src/policy.ts';
import type { FieldId, PolicyExpr, RolePin, UTC, UUID, Version } from '../../packages/authority/src/types.ts';

const id = (value: number): UUID => `00000000-0000-0000-0000-${value.toString(16).padStart(12, '0')}` as UUID;
const utc = (value: string): UTC => value as UTC;
const known = <T>(value: T): Fact<T> => ({ status: 'known', value });
const missing = { status: 'unavailable' } as const;
const pin: RolePin = { roleId: id(7), version: 2 as Version };
function facts(): ExpressionFacts {
  const subject = { kind: 'human', id: id(1) } as const;
  const request: ExpressionRequest = { action: 'asset:discover',
    resource: { tenantId: id(2), kind: 'asset', id: id(3) }, revision: 4 as Version, field: null };
  return { subject, request, now: utc('2026-11-16T12:00:00.000Z'),
    groups: known([id(6)]), requestRoles: known({ subject, request, roles: [pin] }),
    domainPath: known([id(8), id(9)]), classifications: known([id(10)]), approvedTags: known([id(11)]),
    purpose: known(id(12)), environment: known(id(13)) };
}
function parsed(expression: unknown): PolicyExpr {
  const result = parsePolicy({ formatVersion: 1, id: id(100), version: 1,
    rules: [{ id: id(101), effect: 'allow', actions: ['asset:discover'], fields: null, when: expression }] });
  assert.equal(result.ok, true, JSON.stringify(result));
  if (!result.ok) throw new Error('Expected canonical expression');
  return result.value.rules[0].when;
}
function evaluate(expression: unknown, context: unknown = facts()): ReturnType<typeof evaluatePolicyExpression> {
  return evaluatePolicyExpression(expression as PolicyExpr, context as ExpressionFacts);
}
const match = () => ({ op: 'subject-in', subjects: [{ kind: 'human', id: id(1) }] });
const noMatch = () => ({ op: 'subject-in', subjects: [{ kind: 'human', id: id(99) }] });
const unknown = () => ({ op: 'group-any', groupIds: [id(6)] });

test('expression interpreter covers every exact predicate with matching and nonmatching canonical facts', () => {
  const cases = [
    [{ op: 'all', children: [match(), match()] }, { op: 'all', children: [match(), noMatch()] }],
    [{ op: 'any', children: [noMatch(), match()] }, { op: 'any', children: [noMatch(), noMatch()] }],
    [match(), noMatch()],
    [{ op: 'group-any', groupIds: [id(6)] }, { op: 'group-any', groupIds: [id(99)] }],
    [{ op: 'role-any', roles: [pin] }, { op: 'role-any', roles: [{ ...pin, version: 1 }] }],
    [{ op: 'action-in', actions: ['asset:discover'] }, { op: 'action-in', actions: ['asset:attributes.read'] }],
    [{ op: 'resource-kind-in', kinds: ['asset'] }, { op: 'resource-kind-in', kinds: ['model-definition'] }],
    [{ op: 'domain-in', domainIds: [id(9)], includeAncestors: true }, { op: 'domain-in', domainIds: [id(9)], includeAncestors: false }],
    [{ op: 'classification-any', ids: [id(10)] }, { op: 'classification-any', ids: [id(11)] }],
    [{ op: 'approved-tag-any', ids: [id(11)] }, { op: 'approved-tag-any', ids: [id(10)] }],
    [{ op: 'purpose-in', ids: [id(12)] }, { op: 'purpose-in', ids: [id(13)] }],
    [{ op: 'environment-in', ids: [id(13)] }, { op: 'environment-in', ids: [id(12)] }],
    [{ op: 'time-within', validity: { notBefore: null, expiresAt: null } },
      { op: 'time-within', validity: { notBefore: '2026-11-16T12:00:00.001Z', expiresAt: null } }],
  ];
  for (const [yes, no] of cases) {
    assert.equal(evaluate(parsed(yes)), 'match', JSON.stringify(yes));
    assert.equal(evaluate(parsed(no)), 'no-match', JSON.stringify(no));
  }
});
test('subject kind, exact actions and canonical resource kinds do not alias', () => {
  const expression = parsed(match()), context = facts();
  assert.equal(evaluate(expression, { ...context, subject: { kind: 'service', id: id(1) } }), 'no-match');
  assert.equal(evaluate(parsed({ op: 'subject-in', subjects: [{ kind: 'service', id: id(1) }] }),
    { ...context, subject: { kind: 'service', id: id(1) } }), 'match');
  assert.equal(evaluate(parsed({ op: 'action-in', actions: ['source:metadata.scan'] }),
    { ...context, request: { ...context.request, action: 'source:metadata.scan' } }), 'match');
  assert.equal(evaluate(parsed({ op: 'resource-kind-in', kinds: ['model-definition'] }),
    { ...context, request: { ...context.request, resource: { ...context.request.resource, kind: 'model-definition' } } }), 'match');
  assert.equal(evaluate({ op: 'resource-kind-in', kinds: ['asset-type'] }), 'indeterminate');
  assert.equal(evaluate({ op: 'action-in', actions: ['asset:*'] }), 'indeterminate');
});
test('all and any evaluate every branch and indeterminate dominates in either child order', () => {
  const context = { ...facts(), groups: missing };
  for (const op of ['all', 'any']) for (const decisive of [match(), noMatch()]) {
    for (const children of [[decisive, unknown()], [unknown(), decisive]]) {
      assert.equal(evaluate(parsed({ op, children }), context), 'indeterminate');
    }
  }
  const nested = parsed({ op: 'any', children: [match(), { op: 'all', children: [noMatch(), unknown()] }] });
  assert.equal(evaluate(nested, context), 'indeterminate');
  for (const op of ['all', 'any']) {
    assert.equal(evaluate({ op, children: [match(), { op: 'future-operator', value: true }] }), 'indeterminate');
  }
});
test('known empty facts are no-match while unavailable used facts are indeterminate', () => {
  const cases = [
    ['groups', { op: 'group-any', groupIds: [id(6)] }],
    ['domainPath', { op: 'domain-in', domainIds: [id(8)], includeAncestors: true }],
    ['classifications', { op: 'classification-any', ids: [id(10)] }],
    ['approvedTags', { op: 'approved-tag-any', ids: [id(11)] }],
  ] as const;
  for (const [key, expression] of cases) {
    assert.equal(evaluate(parsed(expression), { ...facts(), [key]: known([]) }), 'no-match', key);
    assert.equal(evaluate(parsed(expression), { ...facts(), [key]: missing }), 'indeterminate', key);
  }
  const context = facts();
  assert.equal(evaluate(parsed({ op: 'role-any', roles: [pin] }), { ...context,
    requestRoles: known({ subject: context.subject, request: context.request, roles: [] }) }), 'no-match');
  assert.equal(evaluate(parsed({ op: 'role-any', roles: [pin] }), { ...context, requestRoles: missing }), 'indeterminate');
  assert.equal(evaluate(parsed(match()), { ...context, groups: missing, requestRoles: missing, domainPath: missing,
    classifications: missing, approvedTags: missing, purpose: missing, environment: missing }), 'match');
});
test('purpose absence is explicit and environment has no implicit default', () => {
  const purpose = parsed({ op: 'purpose-in', ids: [id(12)] }), environment = parsed({ op: 'environment-in', ids: [id(13)] });
  assert.equal(evaluate(purpose, { ...facts(), purpose: known(null) }), 'no-match');
  assert.equal(evaluate(purpose, { ...facts(), purpose: missing }), 'indeterminate');
  assert.equal(evaluate(environment, { ...facts(), environment: known(null) }), 'indeterminate');
  assert.equal(evaluate(environment, { ...facts(), environment: missing }), 'indeterminate');
});
test('role evidence is bound to every exact subject and atomic request tuple component', () => {
  const context = facts(), expression = parsed({ op: 'role-any', roles: [pin] });
  const requests = [
    { ...context.request, action: 'source:discover' },
    { ...context.request, resource: { ...context.request.resource, tenantId: id(91) } },
    { ...context.request, resource: { ...context.request.resource, id: id(92) } },
    { ...context.request, resource: { ...context.request.resource, kind: 'source' } },
    { ...context.request, revision: 3 }, { ...context.request, revision: null },
    { ...context.request, field: 'asset.description' },
  ];
  for (const request of requests) assert.equal(evaluate(expression, { ...context,
    requestRoles: known({ subject: context.subject, request, roles: [pin] }) }), 'indeterminate', JSON.stringify(request));
  for (const subject of [{ ...context.subject, id: id(90) }, { ...context.subject, kind: 'service' }]) {
    assert.equal(evaluate(expression, { ...context, requestRoles: known({ subject, request: context.request, roles: [pin] }) }), 'indeterminate');
  }
  const changed = { ...context.request, revision: 5 as Version, field: 'asset.description' as FieldId };
  assert.equal(evaluate(expression, { ...context, request: changed,
    requestRoles: known({ subject: context.subject, request: changed, roles: [pin] }) }), 'match');
  assert.equal(evaluate(expression, { ...context,
    requestRoles: known({ subject: context.subject, request: context.request, roles: [{ ...pin, version: 3 }] }) }), 'no-match');
});
test('role fact payloads must be complete, current-version-shaped and distinct', () => {
  const context = facts(), expression = parsed({ op: 'role-any', roles: [pin] });
  for (const value of [
    [pin], { subject: context.subject, roles: [pin] },
    { subject: context.subject, request: { ...context.request, revision: 0 }, roles: [pin] },
    { subject: context.subject, request: context.request, roles: [pin, pin] },
    { subject: context.subject, request: context.request, roles: [pin, { ...pin, version: Number.MAX_SAFE_INTEGER }] },
    { subject: context.subject, request: context.request, roles: [pin], allHeldRoles: true },
  ]) assert.equal(evaluate(expression, { ...context, requestRoles: known(value) }), 'indeterminate');
});
test('domain direct/ancestor interpretation allows exactly direct plus32 distinct ancestors', () => {
  const path = Array.from({ length: 33 }, (_, index) => id(index + 200));
  const direct = parsed({ op: 'domain-in', domainIds: [path[0]], includeAncestors: false });
  const ancestor = parsed({ op: 'domain-in', domainIds: [path[32]], includeAncestors: true });
  assert.equal(evaluate(direct, { ...facts(), domainPath: known(path) }), 'match');
  assert.equal(evaluate(ancestor, { ...facts(), domainPath: known(path) }), 'match');
  assert.equal(evaluate(parsed({ op: 'domain-in', domainIds: [path[32]], includeAncestors: false }),
    { ...facts(), domainPath: known(path) }), 'no-match');
  for (const invalid of [[...path, id(250)], [...path.slice(0, 32), path[0]], [path[0], 'invalid']]) {
    assert.equal(evaluate(direct, { ...facts(), domainPath: known(invalid) }), 'indeterminate');
  }
  const cycle: unknown[] = [path[0]]; cycle.push(cycle);
  assert.equal(evaluate(direct, { ...facts(), domainPath: known(cycle) }), 'indeterminate');
});
test('fact sets validate every entry and do not invent a256-member population cap', () => {
  const expression = parsed(unknown()), context = facts();
  for (const value of [[id(6), id(6)], [id(6), 'invalid'], [id(6), null], [id(6), {}]]) {
    assert.equal(evaluate(expression, { ...context, groups: known(value) }), 'indeterminate');
  }
  const groups = Array.from({ length: 1024 }, (_, index) => id(index + 1000));
  groups[1023] = id(6);
  assert.equal(evaluate(expression, { ...context, groups: known(groups) }), 'match');
  assert.equal(evaluate(parsed(match()), { ...context, groups: { irrelevantMalformedPayload: true } }), 'match');
});
test('time intervals are half-open with canonical millisecond UTC and no wall-clock dependency', () => {
  const expression = parsed({ op: 'time-within', validity: {
    notBefore: '2024-02-29T00:00:00.000Z', expiresAt: '2024-02-29T00:00:00.002Z' } });
  for (const [now, expected] of [
    ['2024-02-28T23:59:59.999Z', 'no-match'], ['2024-02-29T00:00:00.000Z', 'match'],
    ['2024-02-29T00:00:00.001Z', 'match'], ['2024-02-29T00:00:00.002Z', 'no-match'],
  ]) assert.equal(evaluate(expression, { ...facts(), now }), expected);
  assert.equal(evaluate(parsed({ op: 'time-within', validity: { notBefore: null, expiresAt: null } })), 'match');
  for (const now of ['2023-02-29T00:00:00.000Z', '2024-02-29T00:00:00Z', '2024-02-29T00:00:00.000+00:00', 'invalid', 42]) {
    assert.equal(evaluate(expression, { ...facts(), now }), 'indeterminate');
  }
  for (const validity of [
    { notBefore: '2024-02-29T00:00:00.000Z', expiresAt: '2024-02-29T00:00:00.000Z' },
    { notBefore: '2024-03-01T00:00:00.000Z', expiresAt: '2024-02-29T00:00:00.000Z' },
    { notBefore: null, expiresAt: '2023-02-29T00:00:00.000Z' }, { notBefore: null },
  ]) assert.equal(evaluate({ op: 'time-within', validity }), 'indeterminate');
});
test('expression node/depth bounds pass at128/depth8 and reject immediately over', () => {
  const atNodes = { op: 'all', children: Array.from({ length: 127 }, match) };
  assert.equal(evaluate(parsed(atNodes)), 'match');
  assert.equal(evaluate({ op: 'all', children: [...atNodes.children, match()] }), 'indeterminate');
  let depth: unknown = match();
  for (let index = 1; index < 8; index++) depth = { op: 'all', children: [depth] };
  assert.equal(evaluate(parsed(depth)), 'match');
  assert.equal(evaluate({ op: 'all', children: [depth] }), 'indeterminate');
  const cycle: { op: string; children: unknown[] } = { op: 'all', children: [] }; cycle.children.push(cycle);
  assert.equal(evaluate(cycle), 'indeterminate');
});
test('AST finite sets retain256-entry limit, distinctness and exact required properties', () => {
  const groupIds = Array.from({ length: 256 }, (_, index) => id(index + 300));
  assert.equal(evaluate(parsed({ op: 'group-any', groupIds }), { ...facts(), groups: known([groupIds[255]]) }), 'match');
  const invalid = [
    { op: 'group-any', groupIds: [...groupIds, id(999)] }, { op: 'group-any', groupIds: [id(6), id(6)] },
    { op: 'group-any', groupIds: [] }, { op: 'any', children: [] }, { op: 'all', children: Array(1) },
    { ...match(), extra: true }, { op: 'subject-in' }, { op: 'not', child: match() },
    { op: 'role-any', roles: [{ ...pin, version: 0 }] },
    { op: 'domain-in', domainIds: [id(8)], includeAncestors: 'true' },
  ];
  for (const expression of invalid) assert.equal(evaluate(expression), 'indeterminate', JSON.stringify(expression));
});
test('closed context and request structural validation fail safely on malformed scalar evidence', () => {
  const context = facts(), expression = parsed(match());
  const invalid = [
    { ...context, extra: true }, { ...context, subject: { kind: 'group', id: id(1) } },
    { ...context, request: { ...context.request, action: 'asset:*' } },
    { ...context, request: { ...context.request, revision: NaN } },
    { ...context, request: { ...context.request, revision: 2147483648 } },
    { ...context, request: { ...context.request, field: '' } },
    { ...context, request: { ...context.request, field: '\ud800' } },
    { ...context, request: { ...context.request, field: '😀'.repeat(65) } },
    { ...context, request: { ...context.request, resource: { ...context.request.resource, tenantId: 'wrong' } } },
  ];
  for (const value of invalid) assert.equal(evaluate(expression, value), 'indeterminate');
  const omitted = Object.fromEntries(Object.entries(context).filter(([key]) => key !== 'groups'));
  assert.equal(evaluate(expression, omitted), 'indeterminate');
  for (const value of [undefined, null, { status: 'known' }, { status: 'known', value: [id(6)], extra: true }]) {
    assert.equal(evaluate(parsed(unknown()), { ...context, groups: value }), 'indeterminate');
  }
});
test('proxy and accessor data are refused without executing traps or getters', () => {
  let executions = 0;
  const proxy = new Proxy({}, { get() { executions++; throw new Error('get'); },
    ownKeys() { executions++; throw new Error('ownKeys'); }, getPrototypeOf() { executions++; throw new Error('prototype'); } });
  assert.equal(evaluate(proxy), 'indeterminate');
  assert.equal(evaluate(parsed(match()), proxy), 'indeterminate');
  assert.equal(evaluate(parsed(unknown()), { ...facts(), groups: known(proxy) }), 'indeterminate');
  const accessor = { op: 'subject-in', get subjects() { executions++; return [{ kind: 'human', id: id(1) }]; } };
  assert.equal(evaluate(accessor), 'indeterminate');
  const fact = { status: 'known', get value() { executions++; return [id(6)]; } };
  assert.equal(evaluate(parsed(unknown()), { ...facts(), groups: fact }), 'indeterminate');
  const root = { ...facts(), get groups() { executions++; return known([id(6)]); } };
  assert.equal(evaluate(parsed(match()), root), 'indeterminate');
  assert.equal(executions, 0);
});
test('exotic, inherited, symbol-bearing and sparse data cannot create predicate matches', () => {
  const inherited = Object.assign(Object.create({ inherited: true }), match());
  assert.equal(evaluate(inherited), 'indeterminate');
  const symbol = { ...match(), [Symbol('extra')]: true };
  assert.equal(evaluate(symbol), 'indeterminate');
  assert.equal(evaluate(parsed(unknown()), { ...facts(), groups: known(new Set([id(6)])) }), 'indeterminate');
  const sparse = Array(2); sparse[0] = id(6);
  assert.equal(evaluate(parsed(unknown()), { ...facts(), groups: known(sparse) }), 'indeterminate');
  const arrayExtra = [id(6)]; Object.defineProperty(arrayExtra, 'extra', { value: true });
  assert.equal(evaluate(parsed(unknown()), { ...facts(), groups: known(arrayExtra) }), 'indeterminate');
  const revoked = Proxy.revocable({}, {}); revoked.revoke();
  assert.equal(evaluate(revoked.proxy), 'indeterminate');
});
test('evaluation returns truth only and never mutates parsed expression or admitted facts', () => {
  const expression = parsed({ op: 'all', children: [match(), { op: 'role-any', roles: [pin] }, unknown()] });
  const context = facts(), before = JSON.stringify({ expression, context });
  assert.equal(evaluate(expression, context), 'match');
  assert.equal(JSON.stringify({ expression, context }), before);
  assert.equal(Object.isFrozen(context), false);
  assert.equal(typeof evaluate(expression, context), 'string');
  const nullPrototype = Object.assign(Object.create(null), context);
  assert.equal(evaluate(expression, nullPrototype), 'match');
});
