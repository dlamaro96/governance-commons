// SPDX-License-Identifier: Apache-2.0
// Literal registry adopted by SCOPED_AUTHORITY_PURE_CONTRACT.md. No wildcards,
// authentication, activity checks, resource adapters, or installed grants here.
import { types as utilTypes } from 'node:util';
export const LEGACY_PERMISSIONS = [
  'catalog:read', 'catalog:write', 'sources:read', 'sources:write', 'audit:read',
  'models:read', 'models:write', 'domains:read', 'domains:write', 'domains:assign',
] as const;
export type LegacyPermission = (typeof LEGACY_PERMISSIONS)[number];
const CR = 'catalog:read', CW = 'catalog:write', SR = 'sources:read', SW = 'sources:write';
const AR = 'audit:read', MR = 'models:read', MW = 'models:write';
const DR = 'domains:read', DW = 'domains:write', DA = 'domains:assign';

// [literal action IDs, exact legacy all-of predicate]. Empty all-of means
// authenticated active-member baseline ONLY for the first row.
export const COMPATIBILITY_ACTIONS = [
  [['session:self.read', 'session:tenant.select', 'schema:read', 'capability:read'], []],
  [['member:owner-candidates.read'], [CW]],
  [['asset:discover', 'asset:metadata.read', 'catalog:summary.read'], [CR]],
  [['asset:description.edit', 'asset:owner.assign'], [CR, CW]],
  [['asset:attributes.read', 'asset:type-state.read'], [CR, MR]],
  [['asset:model.assign', 'asset:attributes.edit', 'asset:type-state.transition'], [CR, CW, MR]],
  [['model:discover', 'model:definition.read'], [MR]],
  [['model:definition.validate', 'model:migration-plan.validate'], [MW]],
  [['model:create'], [MR, MW]],
  [['model:publication.preview', 'model:version.publish'], [MR, MW, CR]],
  [['model:migration.context', 'model:migration.preview', 'model:migration.execute'], [MR, MW, CR, CW]],
  [['model:migration.receipt.read'], [MR, CR]],
  [['asset-type:discover', 'asset-type:definition.read'], [MR]],
  [['asset-type:definition.validate', 'asset-type:create'], [MR, MW]],
  [['asset-type:publication.preview', 'asset-type:version.publish'], [MR, MW, CR]],
  [['asset-type:migration-plan.validate', 'asset-type:migration.context', 'asset-type:migration.preview', 'asset-type:migration.execute'], [MR, MW, CR, CW]],
  [['asset-type:migration.receipt.read'], [MR, CR]],
  [['relation-type:discover', 'relation-type:definition.read'], [MR]],
  [['relation-type:definition.validate', 'relation-type:create'], [MR, MW]],
  [['relation-type:publication.preview', 'relation-type:version.publish'], [MR, MW, CR]],
  [['relation:read', 'relation:discover', 'graph:traverse'], [CR, MR]],
  [['relation:history.read'], [CR, MR, AR]],
  [['relation:create', 'relation:attributes.edit', 'relation:owner.assign', 'relation:visibility.edit',
    'relation:validity.edit', 'relation:state.transition', 'relation:tombstone'], [CR, MR, CW]],
  [['relation-migration:validate', 'relation-migration:context', 'relation-migration:preview', 'relation-migration:execute',
    'relation-preparation:create', 'relation-preparation:replay'], [CR, CW, MR, MW]],
  [['relation-operation:receipt.read', 'participation:read', 'participation:history.read'], [CR, MR]],
  [['participation:enroll', 'participation:release', 'participation:repin'], [CR, CW, MR, MW]],
  [['domain-type:discover', 'domain-type:definition.read', 'domain-type:definition.validate', 'domain-type:migration-plan.validate'], [MR]],
  [['domain-type:create'], [MR, MW]],
  [['domain-type:publication.preview', 'domain-type:version.publish', 'domain-type:migration.preview'], [MR, MW, DR]],
  [['domain-type:migration.context', 'domain-type:migration.receipt.read'], [MR, DR]],
  [['domain-type:migration.execute'], [MR, MW, DR, DW]],
  [['domain:discover', 'domain:metadata.read', 'domain:history.read'], [DR]],
  [['domain:owner-candidates.read', 'domain:create', 'domain:metadata.edit', 'domain:owner.assign',
    'domain:state.transition', 'domain:hierarchy.preview', 'domain:move', 'domain:retire', 'domain:restore'], [DR, DW]],
  [['domain:assets.read', 'placement:read', 'placement:history.read'], [CR, DR]],
  [['placement:assign', 'placement:reassign', 'placement:unassign'], [CR, CW, DR, DA]],
  [['source:discover', 'source:configuration.read', 'scan-job:discover', 'scan-job:read'], [SR]],
  [['source:create', 'source:scan.request'], [SW]],
  [['audit:event.read', 'audit:chain.verify'], [AR]],
] as const;
export type CompatibleActionId = (typeof COMPATIBILITY_ACTIONS)[number][0][number];

export const ADMIN_ACTIONS = [
  'authority:read', 'authority:simulate', 'authority:manage-policy',
  'authority:assign-role', 'authority:assign-responsibility', 'authority:delegate', 'authority:revoke',
  'authority:group.create', 'authority:group.version.publish', 'authority:group.retire',
  'authority:group.member.assign', 'authority:group.member.revoke',
  'authority:role.create', 'authority:role.version.publish', 'authority:role.retire',
  'authority:responsibility-type.create', 'authority:responsibility-type.version.publish',
  'authority:responsibility-type.retire',
  'authority:elevation.issue', 'authority:elevation.use', 'authority:elevation.revoke',
] as const;
export const FIELD_ACTIONS = ['field:read', 'field:sensitive.read'] as const;
export const SERVICE_ACTIONS = [
  'scan-job:dispatch', 'scan-job:claim', 'source:metadata.scan', 'scan-job:complete', 'scan-job:fail',
  'secret:resolve', 'projection:consume', 'projection:write', 'audit:append', 'outbox:append',
] as const;
export type HumanActionId = CompatibleActionId | (typeof ADMIN_ACTIONS)[number];
export type FieldActionId = (typeof FIELD_ACTIONS)[number];
export type ServiceActionId = (typeof SERVICE_ACTIONS)[number];
export type ActionId = HumanActionId | FieldActionId | ServiceActionId;

// TypeScript readonly is insufficient at the runtime trust boundary.
for (const [actions, permissions] of COMPATIBILITY_ACTIONS) {
  Object.freeze(actions); Object.freeze(permissions);
}
for (const row of COMPATIBILITY_ACTIONS) Object.freeze(row);
Object.freeze(COMPATIBILITY_ACTIONS);
Object.freeze(LEGACY_PERMISSIONS); Object.freeze(ADMIN_ACTIONS);
Object.freeze(FIELD_ACTIONS); Object.freeze(SERVICE_ACTIONS);

/** Closed, literal all-of mapping only. Empty input presumes an active member;
 * this function neither proves that prerequisite nor grants runtime authority.
 * Malformed/unknown/duplicate input throws TypeError; over-limit input RangeError.
 * Results follow the frozen registry order and cannot be mutated by the caller.
 * Input comes from a trusted bounded permission loader. Exact extra-key rejection
 * reflects all preexisting own keys; this is not an arbitrary-object ingress. */
export function compatibilityActions(permissions: readonly LegacyPermission[]): readonly CompatibleActionId[] {
  if (typeof permissions !== 'object' || permissions === null || utilTypes.isProxy(permissions)
      || !Array.isArray(permissions) || Object.getPrototypeOf(permissions) !== Array.prototype) {
    throw new TypeError('Expected a plain permission array.');
  }
  const length = Object.getOwnPropertyDescriptor(permissions, 'length')?.value as number;
  if (length > LEGACY_PERMISSIONS.length) throw new RangeError('Permission count exceeds the closed registry.');
  const keys = Reflect.ownKeys(permissions);
  if (keys.length !== length + 1) throw new TypeError('Permission arrays must be dense and contain only entries.');
  const selected = new Set<LegacyPermission>();
  const registered = new Set<string>(LEGACY_PERMISSIONS);
  for (let index = 0; index < length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(permissions, String(index));
    if (!descriptor || !('value' in descriptor) || !descriptor.enumerable || typeof descriptor.value !== 'string'
        || !registered.has(descriptor.value) || selected.has(descriptor.value as LegacyPermission)) {
      throw new TypeError('Expected unique registered permissions.');
    }
    selected.add(descriptor.value as LegacyPermission);
  }
  return Object.freeze(COMPATIBILITY_ACTIONS.flatMap(([actions, required]) =>
    required.every(permission => selected.has(permission)) ? [...actions] : []));
}
