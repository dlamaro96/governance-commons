// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ADMIN_ACTIONS, COMPATIBILITY_ACTIONS, FIELD_ACTIONS, LEGACY_PERMISSIONS, SERVICE_ACTIONS, compatibilityActions, type LegacyPermission } from '../../packages/authority/src/actions.ts';

// Independently authored oracle: numeric bit predicates over the literal legacy
// ordering. This never derives expected results from the implementation registry.
const permissions = ['catalog:read', 'catalog:write', 'sources:read', 'sources:write', 'audit:read', 'models:read', 'models:write', 'domains:read', 'domains:write', 'domains:assign'] as const;
const oracle: readonly (readonly [string, number])[] = [
  ['session:self.read',0], ['session:tenant.select',0], ['schema:read',0], ['capability:read',0],
  ['member:owner-candidates.read',2],
  ['asset:discover',1], ['asset:metadata.read',1], ['catalog:summary.read',1],
  ['asset:description.edit',3], ['asset:owner.assign',3],
  ['asset:attributes.read',33], ['asset:type-state.read',33],
  ['asset:model.assign',35], ['asset:attributes.edit',35], ['asset:type-state.transition',35],
  ['model:discover',32], ['model:definition.read',32],
  ['model:definition.validate',64], ['model:migration-plan.validate',64], ['model:create',96],
  ['model:publication.preview',97], ['model:version.publish',97],
  ['model:migration.context',99], ['model:migration.preview',99], ['model:migration.execute',99], ['model:migration.receipt.read',33],
  ['asset-type:discover',32], ['asset-type:definition.read',32], ['asset-type:definition.validate',96], ['asset-type:create',96],
  ['asset-type:publication.preview',97], ['asset-type:version.publish',97],
  ['asset-type:migration-plan.validate',99], ['asset-type:migration.context',99], ['asset-type:migration.preview',99], ['asset-type:migration.execute',99], ['asset-type:migration.receipt.read',33],
  ['relation-type:discover',32], ['relation-type:definition.read',32], ['relation-type:definition.validate',96], ['relation-type:create',96],
  ['relation-type:publication.preview',97], ['relation-type:version.publish',97],
  ['relation:read',33], ['relation:discover',33], ['graph:traverse',33], ['relation:history.read',49],
  ['relation:create',35], ['relation:attributes.edit',35], ['relation:owner.assign',35], ['relation:visibility.edit',35], ['relation:validity.edit',35], ['relation:state.transition',35], ['relation:tombstone',35],
  ['relation-migration:validate',99], ['relation-migration:context',99], ['relation-migration:preview',99], ['relation-migration:execute',99], ['relation-preparation:create',99], ['relation-preparation:replay',99],
  ['relation-operation:receipt.read',33], ['participation:read',33], ['participation:history.read',33],
  ['participation:enroll',99], ['participation:release',99], ['participation:repin',99],
  ['domain-type:discover',32], ['domain-type:definition.read',32], ['domain-type:definition.validate',32], ['domain-type:migration-plan.validate',32],
  ['domain-type:create',96], ['domain-type:publication.preview',224], ['domain-type:version.publish',224], ['domain-type:migration.preview',224],
  ['domain-type:migration.context',160], ['domain-type:migration.receipt.read',160], ['domain-type:migration.execute',480],
  ['domain:discover',128], ['domain:metadata.read',128], ['domain:history.read',128],
  ['domain:owner-candidates.read',384], ['domain:create',384], ['domain:metadata.edit',384], ['domain:owner.assign',384], ['domain:state.transition',384], ['domain:hierarchy.preview',384], ['domain:move',384], ['domain:retire',384], ['domain:restore',384],
  ['domain:assets.read',129], ['placement:read',129], ['placement:history.read',129],
  ['placement:assign',643], ['placement:reassign',643], ['placement:unassign',643],
  ['source:discover',4], ['source:configuration.read',4], ['scan-job:discover',4], ['scan-job:read',4],
  ['source:create',8], ['source:scan.request',8], ['audit:event.read',16], ['audit:chain.verify',16],
];

test('all 1024 permission subsets match the independent 103-action legacy oracle', () => {
  assert.deepEqual(LEGACY_PERMISSIONS, permissions);
  assert.equal(oracle.length,103); assert.equal(new Set(oracle.map(([id]) => id)).size,103);
  assert.deepEqual(COMPATIBILITY_ACTIONS.flatMap(([ids]) => [...ids]), oracle.map(([id]) => id));
  for (let subset = 0; subset < 1024; subset++) {
    const selected = permissions.filter((_, index) => subset & (1 << index));
    const actual = compatibilityActions(selected);
    const expected = oracle.filter(([, required]) => (subset & required) === required).map(([id]) => id);
    assert.deepEqual(actual, expected, `legacy subset ${subset}`);
    assert.deepEqual(compatibilityActions([...selected].reverse()), expected, `input order ${subset}`);
    assert.ok(Object.isFrozen(actual));
  }
});
test('registry is finite, disjoint, immutable and adds no administrative, field or service grant', () => {
  assert.equal(ADMIN_ACTIONS.length,21); assert.equal(FIELD_ACTIONS.length,2); assert.equal(SERVICE_ACTIONS.length,10);
  const all = [...oracle.map(([id]) => id), ...ADMIN_ACTIONS, ...FIELD_ACTIONS, ...SERVICE_ACTIONS];
  assert.equal(new Set(all).size,136);
  assert.deepEqual(compatibilityActions([]), ['session:self.read','session:tenant.select','schema:read','capability:read']);
  const maximum = compatibilityActions(permissions);
  for (const id of [...ADMIN_ACTIONS,...FIELD_ACTIONS,...SERVICE_ACTIONS]) assert.equal((maximum as readonly string[]).includes(id),false);
  for (const value of [LEGACY_PERMISSIONS,COMPATIBILITY_ACTIONS,ADMIN_ACTIONS,FIELD_ACTIONS,SERVICE_ACTIONS,
    ...COMPATIBILITY_ACTIONS.flatMap(row => [row,...row])]) assert.ok(Object.isFrozen(value));
  assert.throws(() => (ADMIN_ACTIONS as unknown as string[]).push('authority:anything'), TypeError);
});
test('mapping rejects unknown, duplicated, coerced and hostile permission inputs without executing them', () => {
  const run = (input: unknown) => compatibilityActions(input as readonly LegacyPermission[]);
  for (const input of [null,{},'catalog:read',['catalog:*'],['domains:read','domains:read'],[1],['Catalog:read'],[undefined],new Set(['catalog:read'])]) assert.throws(() => run(input),TypeError);
  assert.throws(() => run(Array.from({length:11},()=> 'catalog:read')),RangeError);
  let invoked = 0;
  const accessor: unknown[] = []; Object.defineProperty(accessor,'0',{enumerable:true,get(){ invoked++; return 'catalog:read'; }});
  const proxy = new Proxy([], { ownKeys(){ invoked++; throw new Error('trap'); },getPrototypeOf(){ invoked++; throw new Error('trap'); } });
  const revoked = Proxy.revocable([],{}); revoked.revoke();
  const symbol = ['catalog:read']; Object.defineProperty(symbol,Symbol('extra'),{value:1});
  const extra = Object.assign(['catalog:read'],{extra:true});
  const sparse = new Array(1), inherited = Object.create(['catalog:read']);
  for (const input of [accessor,proxy,revoked.proxy,symbol,extra,sparse,inherited]) assert.throws(() => run(input),TypeError);
  assert.equal(invoked,0);
});
test('legacy compatibility keeps asymmetric validator, source and domain permissions exact', () => {
  assert.ok(compatibilityActions(['models:write']).includes('model:definition.validate'));
  assert.equal(compatibilityActions(['models:write']).includes('asset-type:definition.validate'),false);
  const source = compatibilityActions(['sources:write']); assert.ok(source.includes('source:create')); assert.equal(source.includes('source:discover'),false);
  const placement = compatibilityActions(['catalog:read','catalog:write','domains:read','domains:assign']);
  assert.ok(placement.includes('placement:assign')); assert.equal(placement.includes('domain:move'),false);
  const history = compatibilityActions(['domains:read']); assert.ok(history.includes('domain:history.read')); assert.equal(history.includes('audit:event.read'),false);
});
