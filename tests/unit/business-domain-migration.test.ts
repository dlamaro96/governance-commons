// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import { applyDomainTypeMigration, parseDomainTypeMigrationFile, parseDomainTypeMigrationPlan, projectDomainTypeMigration,
  type DomainTypeMigrationScope } from '../../packages/domain/src/business-domain-migration.ts';
import { resolveDomainType } from '../../packages/domain/src/business-domain-type.ts';
import { parseBoundedJSONFile, type ValidationResult } from '../../packages/domain/src/model.ts';
import type { DomainTypeDefinition, DomainTypeMigrationPlan, DomainTypeView, DomainView } from '../../packages/domain/src/business-domain-contracts.ts';

const id = (number: number) => `00000000-0000-4000-8000-${number.toString(16).padStart(12, '0')}`;
const lifecycle = { initial: 'draft', states: ['draft', 'active'], transitions: [{ from: 'draft', to: 'active' }] };
const time = '2026-11-16T00:00:00Z';
function ok<T>(result: ValidationResult<T>): T { assert.ok(result.ok, JSON.stringify(result)); if (!result.ok) throw Error('Expected success'); return result.value; }
function fails(result: ValidationResult<unknown>, code?: string, path?: string) {
  assert.equal(result.ok, false); if (result.ok) throw Error('Expected failure');
  if (code) assert.ok(result.issues.some(issue => issue.code === code && (path === undefined || issue.path.includes(path))), JSON.stringify(result));
  assert.ok(result.issues.length <= 100); assert.ok(Object.isFrozen(result.issues));
}
function definition(version: number, changes: Partial<DomainTypeDefinition> = {}): DomainTypeDefinition {
  return { formatVersion: 1, kind: 'domain-type', id: 'business_domain', version, label: 'Synthetic business domain', parents: [],
    attributes: { amount: { type: 'number', integer: true } }, overrideAttributes: [], requiredOwner: false, lifecycle: structuredClone(lifecycle), ...changes };
}
function view(definition: DomainTypeDefinition, dependencies: readonly { typeId: string; definition: DomainTypeDefinition }[] = []): DomainTypeView {
  return { typeId: id(1), key: definition.id, version: definition.version, currentVersion: 2, definition,
    resolved: ok(resolveDomainType(id(1), definition, dependencies)), definitionHash: 'a'.repeat(64), resolutionHash: 'b'.repeat(64), createdAt: time, createdBy: id(99) };
}
function domain(number: number, version: number, changes: Partial<DomainView> = {}): DomainView {
  return { id: id(number), version: 7, name: `مجال ${number} 🌊`, description: 'Synthetic domain', parentId: null,
    type: { typeId: id(1), version }, attributes: { amount: 42 }, ownerId: null, state: 'draft', status: 'active',
    createdAt: time, createdBy: id(99), updatedAt: time, updatedBy: id(99), ...changes };
}
function fixture(): { scope: DomainTypeMigrationScope; plan: DomainTypeMigrationPlan } {
  const head = view(definition(2)), target = definition(3, { attributes: { amount: { type: 'decimal' } } });
  return { scope: { coverage: 'complete-direct-domain-type-bindings', head, sources: [view(definition(1)), head],
    target: { definition: target, resolved: ok(resolveDomainType(id(1), target, [])) },
    domains: [domain(10, 1), domain(11, 2, { version: 12, state: 'active', status: 'retired' })], dependencies: [], ownerActivity: [] },
  plan: { formatVersion: 1, kind: 'domain-type-migration', typeId: id(1), attributes: { formatVersion: 1, modelId: 'business_domain', targetVersion: 3,
    sourceVersions: [1, 2], acknowledgedChanges: [{ code: 'type_changed', path: '/attributes/amount' }],
    operations: [{ op: 'convert', path: ['amount'], conversion: 'safeIntegerToDecimal', onMissing: 'error' }] },
    owner: { default: 'preserve', overrides: [] }, lifecycle: { onUnmapped: 'preserve', mappings: [] }, acknowledgedPolicyChanges: [] } };
}
function target(scope: DomainTypeMigrationScope, changes: Partial<DomainTypeDefinition>): DomainTypeMigrationScope {
  const authored = { ...scope.target.definition, ...changes };
  return { ...scope, target: { definition: authored, resolved: ok(resolveDomainType(id(1), authored, scope.dependencies)) } };
}

test('domain migration plan roundtrip retains exact authored grammar and immutable copies', () => {
  const { plan } = fixture(); const parsed = ok(parseDomainTypeMigrationPlan(plan));
  assert.deepEqual(ok(parseDomainTypeMigrationFile(JSON.stringify(parsed, null, 2))), plan);
  assert.ok(Object.isFrozen(parsed.attributes.operations[0])); assert.equal(Object.isFrozen(plan), false);
  for (const text of [JSON.stringify(plan).replace('"formatVersion":1', '"formatVersion":1,"formatVersion":1'),
    JSON.stringify(plan).replace('"kind":', '"kind":"domain-type-migration","ki\\u006ed":'), JSON.stringify(plan) + 'null']) fails(parseDomainTypeMigrationFile(text));
});

test('one complete mixed-version migration includes retired domains, computes actual attributes and advances domain revisions', () => {
  const { scope, plan } = fixture(), projection = ok(projectDomainTypeMigration(scope, plan));
  assert.equal(projection.valid, true); assert.deepEqual(projection.issues, []); assert.deepEqual(projection.policyChanges, []);
  const outcomes = ok(applyDomainTypeMigration(scope, plan));
  assert.equal(outcomes.length, 2); assert.deepEqual(outcomes.map(value => [value.fromVersion, value.toVersion]), [[7, 8], [12, 13]]);
  assert.deepEqual(outcomes.map(value => value.after.attributes), [{ amount: '42' }, { amount: '42' }]);
  assert.equal(outcomes[1].after.status, 'retired');
  for (const outcome of outcomes) {
    assert.equal(outcome.after.name, outcome.before.name); assert.equal(outcome.after.parentId, outcome.before.parentId);
    assert.equal(outcome.after.description, outcome.before.description); assert.deepEqual(outcome.after.type, { typeId: id(1), version: 3 });
    assert.ok(Object.isFrozen(outcome.after.attributes));
  }
  assert.equal(Object.isFrozen(scope.domains[0]), false);
  assert.deepEqual(ok(applyDomainTypeMigration({ ...scope, domains: [...scope.domains].reverse(), sources: [...scope.sources].reverse() }, plan)), outcomes);
});

test('empty cohorts still validate the exact target and plan without inventing outcomes', () => {
  const { scope, plan } = fixture(), empty = { ...scope, domains: [], sources: [] }, emptyPlan = { ...plan, attributes: { ...plan.attributes, sourceVersions: [] } };
  assert.deepEqual(ok(applyDomainTypeMigration(empty, emptyPlan)), []);
  fails(projectDomainTypeMigration(empty, { ...emptyPlan, attributes: { ...emptyPlan.attributes, acknowledgedChanges: [] } }), 'required');
  assert.equal(ok(projectDomainTypeMigration(empty, plan)).valid, false);
});

test('plan shape is strict about kind, UUID identity, database versions, duplicate overrides and mapping keys', () => {
  const { plan } = fixture();
  for (const changed of [{ ...plan, kind: 'asset-type-migration' }, { ...plan, typeId: 'business_domain' }, { ...plan, extra: true },
    { ...plan, attributes: { ...plan.attributes, targetVersion: 2147483648 } },
    { ...plan, owner: { default: 'preserve', overrides: [{ domainId: id(10), ownerId: null }, { domainId: id(10), ownerId: id(90) }] } },
    { ...plan, lifecycle: { onUnmapped: 'preserve', mappings: [{ sourceVersion: 1, from: 'draft', to: 'active' }, { sourceVersion: 1, from: 'draft', to: 'draft' }] } },
    { ...plan, acknowledgedPolicyChanges: ['lifecycle_changed', 'lifecycle_changed'] }]) fails(parseDomainTypeMigrationPlan(changed));
});

test('exact source policies and the entire direct cohort are independently revalidated', () => {
  const { scope, plan } = fixture();
  for (const changed of [{ ...scope, sources: scope.sources.slice(1) }, { ...scope, sources: [...scope.sources, scope.sources[0]] },
    { ...scope, domains: [scope.domains[0], scope.domains[0]] }, { ...scope, sources: [...scope.sources, view(definition(3))] },
    { ...scope, domains: [{ ...scope.domains[0], type: { typeId: id(22), version: 1 } }, scope.domains[1]] },
    { ...scope, head: { ...scope.head, typeId: id(22) } }, { ...scope, head: { ...scope.head, currentVersion: 3 } },
    { ...scope, sources: [scope.sources[0], { ...scope.head, resolutionHash: 'c'.repeat(64) }] }]) fails(projectDomainTypeMigration(changed, plan));
  fails(applyDomainTypeMigration(scope, { ...plan, attributes: { ...plan.attributes, sourceVersions: [1] } }));
  assert.equal(ok(projectDomainTypeMigration(scope, { ...plan, typeId: id(22) })).valid, false);
});

test('unknown structural types, metadata and invalid source values cannot be repaired by the target plan', () => {
  const { scope, plan } = fixture();
  for (const changed of [{ ...scope, extra: true }, { ...scope, coverage: 'sampled' },
    { ...scope, head: { ...scope.head, definitionHash: 'not-a-hash' } }, { ...scope, head: { ...scope.head, createdAt: '2025-02-29T00:00:00Z' } },
    { ...scope, head: { ...scope.head, currentVersion: { toString: 'not callable' } } },
    ...[{ amount: '42' }, { unknown: true }].map(attributes => ({ ...scope, domains: [{ ...scope.domains[0], attributes }, scope.domains[1]] })),
    ...[{ state: 'missing' }, { parentId: id(10) }, { status: 'deleted' }, { name: 'bad\nname' }, { description: 'x'.repeat(4001) },
      { updatedAt: '2020-01-01T00:00:00Z' }, { updatedAt: { toString: 'not callable' } }, { version: 2147483647 }, { id: 'business_domain' }].map(patch => ({ ...scope, domains: [{ ...scope.domains[0], ...patch }, scope.domains[1]] }))])
    fails(projectDomainTypeMigration(changed as DomainTypeMigrationScope, plan));
});

test('recorded resolutions are recomputed against exact dependencies rather than trusting typed views', () => {
  const { scope, plan } = fixture();
  for (const changed of [{ ...scope, head: { ...scope.head, resolved: { ...scope.head.resolved, requiredOwner: true } } },
    { ...scope, target: { ...scope.target, resolved: { ...scope.target.resolved, attributes: {} } } },
    { ...scope, target: { ...scope.target, definition: { ...scope.target.definition, kind: 'asset-type' } } },
    { ...scope, dependencies: [{ typeId: id(30), definition: definition(1, { id: 'unused' }) }] }])
    fails(projectDomainTypeMigration(changed as DomainTypeMigrationScope, plan));
});

test('dependency pools admit historical parent versions only through each exact required closure', () => {
  const { scope, plan } = fixture();
  const oldParent = { typeId: id(30), definition: definition(1, { id: 'domain_parent', attributes: {} }) };
  const newParent = { typeId: id(30), definition: definition(2, { id: 'domain_parent', attributes: {} }) };
  const sourceOne = view(definition(1, { parents: [{ typeId: id(30), version: 1 }] }), [oldParent]);
  const head = view(definition(2, { parents: [{ typeId: id(30), version: 2 }] }), [newParent]);
  const authored = { ...scope.target.definition, parents: [{ typeId: id(30), version: 2 }] };
  const inherited = { ...scope, head, sources: [sourceOne, head], dependencies: [newParent, oldParent],
    target: { definition: authored, resolved: ok(resolveDomainType(id(1), authored, [newParent])) } };
  assert.equal(ok(projectDomainTypeMigration(inherited, plan)).valid, true);
  fails(projectDomainTypeMigration({ ...inherited, dependencies: [newParent] }, plan), 'required');
  fails(projectDomainTypeMigration({ ...inherited, dependencies: [newParent, oldParent, oldParent] }, plan), 'duplicate');
  fails(projectDomainTypeMigration({ ...inherited, dependencies: [newParent, { ...oldParent, definition: { ...oldParent.definition, id: 'changed_key' } }] }, plan), 'model_identity');
});

test('policy acknowledgements are exact and invalid owner drafts contain actual transformed attributes', () => {
  const { scope, plan } = fixture(), changed = target(scope, { requiredOwner: true });
  const projection = ok(projectDomainTypeMigration(changed, plan));
  assert.equal(projection.valid, false); assert.deepEqual(projection.policyChanges, ['required_owner_changed']);
  assert.ok(projection.issues.some(issue => issue.code === 'required'));
  assert.deepEqual(projection.domains[0].proposed.attributes, { amount: '42' });
  assert.ok(projection.domains.every(domain => domain.issues.some(issue => issue.path === '/ownerId')));
  fails(applyDomainTypeMigration(changed, plan), 'required');
  assert.equal(ok(projectDomainTypeMigration(scope, { ...plan, acknowledgedPolicyChanges: ['lifecycle_changed'] })).valid, false);
});

test('inactive required source owners need explicit active replacement or acknowledged policy removal', () => {
  const { scope, plan } = fixture();
  const head = view(definition(2, { requiredOwner: true })), sourceOne = view(definition(1, { requiredOwner: true }));
  const owned = target({ ...scope, head, sources: [sourceOne, head], domains: scope.domains.map(domain => ({ ...domain, ownerId: id(90) })),
    ownerActivity: [{ identityId: id(90), active: false }] }, { requiredOwner: true });
  assert.equal(ok(projectDomainTypeMigration(owned, plan)).valid, false);
  const overrides = owned.domains.map(domain => ({ domainId: domain.id, ownerId: id(91) }));
  const replacement = { ...plan, owner: { default: 'preserve' as const, overrides } };
  const repaired = { ...owned, ownerActivity: [...owned.ownerActivity, { identityId: id(91), active: true }] };
  assert.ok(ok(applyDomainTypeMigration(repaired, replacement)).every(outcome => outcome.after.ownerId === id(91)));
  const removal = target(owned, { requiredOwner: false });
  assert.equal(ok(projectDomainTypeMigration(removal, plan)).valid, false);
  assert.equal(ok(projectDomainTypeMigration(removal, { ...plan, acknowledgedPolicyChanges: ['required_owner_changed'] })).valid, true);
  const explicitInactive = { ...plan, acknowledgedPolicyChanges: ['required_owner_changed' as const], owner: { default: 'preserve' as const,
    overrides: owned.domains.map(domain => ({ domainId: domain.id, ownerId: id(90) })) } };
  assert.equal(ok(projectDomainTypeMigration(removal, explicitInactive)).valid, false);
});

test('owner activity evidence is the exact old/new union and never inferred from arbitrary IDs', () => {
  const { scope, plan } = fixture(), ownerPlan = { ...plan, owner: { default: 'preserve' as const, overrides: [{ domainId: id(10), ownerId: id(90) }] } };
  fails(projectDomainTypeMigration(scope, ownerPlan), 'required', 'ownerActivity');
  for (const owners of [[{ identityId: id(90), active: true }, { identityId: id(90), active: true }],
    [{ identityId: id(90), active: true }, { identityId: id(91), active: true }], [{ identityId: id(90), active: 'true' }]])
    fails(projectDomainTypeMigration({ ...scope, ownerActivity: owners } as DomainTypeMigrationScope, ownerPlan));
  assert.equal(ok(projectDomainTypeMigration({ ...scope, ownerActivity: [{ identityId: id(90), active: false }] }, ownerPlan)).valid, false);
  assert.equal(ok(projectDomainTypeMigration(scope, { ...plan, owner: { default: 'preserve', overrides: [{ domainId: id(30), ownerId: null }] } })).valid, false);
});

test('lifecycle mappings bind exact source versions, allow explicit migration state changes and preserve administrative status', () => {
  const { scope, plan } = fixture(), changed = target(scope, { lifecycle: { initial: 'review', states: ['review', 'published'], transitions: [] } });
  const mapped = { ...plan, acknowledgedPolicyChanges: ['lifecycle_changed' as const], lifecycle: { onUnmapped: 'error' as const,
    mappings: [{ sourceVersion: 1, from: 'draft', to: 'review' }, { sourceVersion: 2, from: 'active', to: 'published' }] } };
  const outcomes = ok(applyDomainTypeMigration(changed, mapped));
  assert.deepEqual(outcomes.map(outcome => [outcome.after.state, outcome.after.status]), [['review', 'active'], ['published', 'retired']]);
  assert.equal(ok(projectDomainTypeMigration(changed, { ...mapped, lifecycle: { ...mapped.lifecycle, mappings: mapped.lifecycle.mappings.slice(1) } })).valid, false);
  assert.equal(ok(projectDomainTypeMigration(changed, { ...mapped, lifecycle: { ...mapped.lifecycle, mappings: [{ sourceVersion: 1, from: 'missing', to: 'unknown' }] } })).valid, false);
});

test('failed transforms and missing attribute acknowledgements return errors without invented proposed values', () => {
  const { scope, plan } = fixture();
  fails(projectDomainTypeMigration(scope, { ...plan, attributes: { ...plan.attributes, acknowledgedChanges: [] } }), 'required');
  fails(projectDomainTypeMigration(scope, { ...plan, attributes: { ...plan.attributes, operations: [] } }), 'type');
  fails(projectDomainTypeMigration(scope, { ...plan, attributes: { ...plan.attributes, operations: [{ op: 'convert', path: ['amount'], conversion: 'textToDecimal', onMissing: 'error' }] } }));
  fails(projectDomainTypeMigration(scope, { ...plan, attributes: { ...plan.attributes, modelId: 'different' } }), 'model_identity');
});

test('descriptor-safe plan and scope boundaries reject hidden fields, getters, cycles, sparse arrays and prototype substitutions', () => {
  const { scope, plan } = fixture(); let calls = 0;
  const getter = { ...scope }; Object.defineProperty(getter, 'domains', { enumerable: true, get() { calls++; return scope.domains; } });
  fails(projectDomainTypeMigration(getter, plan), 'invalid_json');
  const planGetter = { ...plan }; Object.defineProperty(planGetter, 'attributes', { enumerable: true, get() { calls++; return plan.attributes; } });
  fails(parseDomainTypeMigrationPlan(planGetter), 'invalid_json'); assert.equal(calls, 0);
  for (const changed of [Object.create(scope), { ...scope, [Symbol('extra')]: true }, { ...scope, domains: new Array(1) }]) fails(projectDomainTypeMigration(changed, plan));
  const cycle: any = { ...plan }; cycle.self = cycle; fails(parseDomainTypeMigrationPlan(cycle), 'cycle');
  const hidden = { ...plan }; Object.defineProperty(hidden, 'typeId', { value: id(1), enumerable: false }); fails(parseDomainTypeMigrationPlan(hidden), 'invalid_json');
});

test('nested transformation literals and inherited fields preserve own values under hostile prototype setters and read-only properties', () => {
  const name = 'domain_migration_copy_probe', previous = Object.getOwnPropertyDescriptor(Object.prototype, name); let calls = 0;
  for (const descriptor of [{ configurable: true, set() { calls++; throw Error('Inherited setter must not execute'); } },
    { configurable: true, value: 'read-only sentinel', writable: false }]) {
    const { scope, plan } = fixture();
    const changed = target(scope, { attributes: { ...scope.target.definition.attributes, configuration: { type: 'object', properties: { [name]: { type: 'text' as const }, toString: { type: 'text' as const } } } } });
    const authored: DomainTypeMigrationPlan = { ...plan, attributes: { ...plan.attributes, operations: [...plan.attributes.operations,
      { op: 'set', path: ['configuration'], value: { [name]: 'kept', toString: 'allowed' }, mode: 'replace' }] } };
    Object.defineProperty(Object.prototype, name, descriptor);
    try {
      ok(parseDomainTypeMigrationFile(JSON.stringify(authored)));
      const outcomes = ok(applyDomainTypeMigration(changed, authored)); assert.equal(calls, 0);
      const value = outcomes[0].after.attributes.configuration as object;
      assert.deepEqual(value, { [name]: 'kept', toString: 'allowed' }); assert.equal(Object.hasOwn(value, name), true);
      assert.equal(Object.getPrototypeOf(value), Object.prototype); assert.ok(Object.isFrozen(value));
      assert.equal(Object.isFrozen(authored), false);
    } finally { if (previous) Object.defineProperty(Object.prototype, name, previous); else Reflect.deleteProperty(Object.prototype, name); }
  }
});

test('bounds cover the whole cohort, retained copies, returned issues and raw file profile', () => {
  const { scope, plan } = fixture();
  fails(projectDomainTypeMigration({ ...scope, domains: Array.from({ length: 1001 }, (_, index) => domain(index + 200, 1)) }, plan), 'limit');
  const many = { ...scope, sources: [scope.sources[0]], domains: Array.from({ length: 120 }, (_, index) => domain(index + 200, 1)) };
  const oneVersion = { ...plan, attributes: { ...plan.attributes, sourceVersions: [1] } };
  const invalid = ok(projectDomainTypeMigration(target(many, { requiredOwner: true }), { ...oneVersion, acknowledgedPolicyChanges: ['required_owner_changed'] }));
  assert.equal(invalid.valid, false); assert.equal(invalid.issues.length + invalid.domains.reduce((sum, item) => sum + item.issues.length, 0), 100);
  assert.ok(invalid.issues.some(issue => issue.code === 'limit'));
  fails(projectDomainTypeMigration({ ...scope, sources: [scope.sources[0]], domains: Array.from({ length: 150 }, (_, index) => domain(index + 200, 1, { description: '界'.repeat(1000) })) }, oneVersion), 'limit');
  const text = ' '.repeat(270000) + JSON.stringify(plan);
  assert.deepEqual(ok(parseDomainTypeMigrationFile(text)), plan); assert.equal(parseBoundedJSONFile(text, 'migration').ok, false);
  fails(parseDomainTypeMigrationFile(' '.repeat(524289)), 'limit');
});
