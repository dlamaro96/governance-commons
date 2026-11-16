// SPDX-License-Identifier: Apache-2.0
import { types as utilTypes } from 'node:util';
import { ADMIN_ACTIONS, COMPATIBILITY_ACTIONS, FIELD_ACTIONS, SERVICE_ACTIONS, type ActionId } from './actions.ts';
import { POLICY_LIMITS } from './policy.ts';
import type { FieldId, PolicyExpr, ResourceKind, ResourceRef, RolePin, SubjectRef, UTC, UUID, Version } from './types.ts';

/** Predicate truth only. A match is not an authorization decision. */
export type ExpressionTruth = 'match' | 'no-match' | 'indeterminate';
export type Fact<T> = { readonly status: 'known'; readonly value: T } | { readonly status: 'unavailable' };
export type ExpressionRequest = {
  readonly action: ActionId; readonly resource: ResourceRef;
  readonly revision: Version | null; readonly field: FieldId | null;
};
export type RequestRoleFacts = {
  readonly subject: SubjectRef; readonly request: ExpressionRequest; readonly roles: readonly RolePin[];
};
export type ExpressionFacts = {
  readonly subject: SubjectRef; readonly request: ExpressionRequest; readonly now: UTC;
  readonly groups: Fact<readonly UUID[]>;
  readonly requestRoles: Fact<RequestRoleFacts>;
  readonly domainPath: Fact<readonly UUID[]>;
  readonly classifications: Fact<readonly UUID[]>;
  readonly approvedTags: Fact<readonly UUID[]>;
  readonly purpose: Fact<UUID | null>;
  readonly environment: Fact<UUID>;
};

const resourceKinds = [
  'tenant', 'tenant-member', 'source', 'scan-job', 'asset', 'model-definition', 'model-migration',
  'asset-type-migration', 'relation-type', 'relation', 'relation-participation', 'relation-operation',
  'relation-preparation', 'domain-type', 'domain', 'asset-domain-placement', 'domain-type-migration',
  'audit-event', 'authority-group', 'authority-role', 'authority-policy', 'authority-grant',
  'responsibility-type', 'responsibility-assignment', 'authority-delegation', 'authority-elevation',
  'execution-site', 'service-principal', 'authority-decision',
] as const satisfies readonly ResourceKind[];
// A shared kind addition must also be reviewed here; no permissive string fallback.
const completeKinds: Record<Exclude<ResourceKind, (typeof resourceKinds)[number]>, never> = {};
void completeKinds;
const kinds = new Set<string>(resourceKinds);
const actions = new Set<string>([...COMPATIBILITY_ACTIONS.flatMap(([ids]) => [...ids]), ...ADMIN_ACTIONS, ...FIELD_ACTIONS, ...SERVICE_ACTIONS]);
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const utcPattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const malformedUnicode = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
const unavailable = Symbol('unavailable expression fact');
function requireInput(condition: unknown): asserts condition { if (!condition) throw unavailable; }

/** Reflection assumes caller-admitted objects. It cannot bound arbitrary already
 * materialized own-key metadata; see SCOPED_AUTHORITY_EXPRESSION_CONTRACT.md. */
function dataObject(value: unknown, maximumKeys: number): Record<string, unknown> {
  requireInput(typeof value === 'object' && value !== null && !utilTypes.isProxy(value) && !Array.isArray(value));
  const prototype = Object.getPrototypeOf(value);
  requireInput(prototype === Object.prototype || prototype === null);
  const names = Reflect.ownKeys(value);
  requireInput(names.length <= maximumKeys);
  return Object.fromEntries(names.map(name => {
    requireInput(typeof name === 'string');
    const descriptor = Object.getOwnPropertyDescriptor(value, name)!;
    requireInput('value' in descriptor && descriptor.enumerable);
    return [name, descriptor.value];
  }));
}
function exact(value: unknown, names: readonly string[]): Record<string, unknown> {
  const row = dataObject(value, names.length);
  requireInput(Object.keys(row).length === names.length && names.every(name => Object.hasOwn(row, name)));
  return row;
}
function array(value: unknown, maximum?: number): readonly unknown[] {
  requireInput(typeof value === 'object' && value !== null && !utilTypes.isProxy(value)
    && Array.isArray(value) && Object.getPrototypeOf(value) === Array.prototype);
  const length = Object.getOwnPropertyDescriptor(value, 'length')!.value as number;
  requireInput(maximum === undefined || length <= maximum);
  requireInput(Reflect.ownKeys(value).length === length + 1);
  return Array.from({ length }, (_, index) => {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    requireInput(descriptor && 'value' in descriptor && descriptor.enumerable);
    return descriptor.value as unknown;
  });
}
function uuid(value: unknown): UUID {
  requireInput(typeof value === 'string' && value.length === 36 && uuidPattern.test(value));
  return value as UUID;
}
function version(value: unknown): Version {
  requireInput(typeof value === 'number' && Number.isInteger(value) && value > 0 && value <= POLICY_LIMITS.version);
  return value as Version;
}
function timestamp(value: unknown): UTC {
  requireInput(typeof value === 'string' && value.length === 24 && utcPattern.test(value)
    && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value);
  return value as UTC;
}
function subject(value: unknown): SubjectRef {
  const row = exact(value, ['kind', 'id']);
  requireInput(row.kind === 'human' || row.kind === 'service');
  return { kind: row.kind, id: uuid(row.id) };
}
function role(value: unknown): RolePin {
  const row = exact(value, ['roleId', 'version']);
  return { roleId: uuid(row.roleId), version: version(row.version) };
}
function registered(value: unknown, registry: ReadonlySet<string>): string {
  requireInput(typeof value === 'string' && registry.has(value));
  return value;
}
function request(value: unknown): ExpressionRequest {
  const row = exact(value, ['action', 'resource', 'revision', 'field']);
  const resource = exact(row.resource, ['tenantId', 'kind', 'id']);
  if (row.field !== null) {
    requireInput(typeof row.field === 'string' && row.field.length > 0 && row.field.length <= POLICY_LIMITS.fieldBytes
      && !malformedUnicode.test(row.field) && Buffer.byteLength(row.field, 'utf8') <= POLICY_LIMITS.fieldBytes);
  }
  return {
    action: registered(row.action, actions) as ActionId,
    resource: { tenantId: uuid(resource.tenantId), kind: registered(resource.kind, kinds) as ResourceKind, id: uuid(resource.id) },
    revision: row.revision === null ? null : version(row.revision), field: row.field as FieldId | null,
  };
}
function subjectKey(value: SubjectRef): string { return `${value.kind}:${value.id}`; }
function roleKey(value: RolePin): string { return `${value.roleId}:${value.version}`; }
function sameRequest(a: ExpressionRequest, b: ExpressionRequest): boolean {
  return a.action === b.action && a.resource.tenantId === b.resource.tenantId && a.resource.kind === b.resource.kind
    && a.resource.id === b.resource.id && a.revision === b.revision && a.field === b.field;
}
function distinct<T>(input: unknown, parse: (entry: unknown) => T, key: (entry: T) => string,
  maximum?: number, nonempty = false): readonly T[] {
  const entries = array(input, maximum);
  requireInput(!nonempty || entries.length > 0);
  const seen = new Set<string>();
  return entries.map(entry => {
    const parsed = parse(entry), identity = key(parsed);
    requireInput(!seen.has(identity)); seen.add(identity);
    return parsed;
  });
}
const stringKey = (value: string): string => value;
function interval(value: unknown): { notBefore: UTC | null; expiresAt: UTC | null } {
  const row = exact(value, ['notBefore', 'expiresAt']);
  const notBefore = row.notBefore === null ? null : timestamp(row.notBefore);
  const expiresAt = row.expiresAt === null ? null : timestamp(row.expiresAt);
  requireInput(notBefore === null || expiresAt === null || notBefore < expiresAt);
  return { notBefore, expiresAt };
}

/** Entire AST validation precedes evaluation. No malformed unvisited branch can
 * disappear behind a matching any or failing all. Counts are per occurrence. */
function expression(value: unknown, depth: number, budget: { nodes: number }): asserts value is PolicyExpr {
  requireInput(++budget.nodes <= POLICY_LIMITS.nodes && depth <= POLICY_LIMITS.depth);
  const row = dataObject(value, 3);
  requireInput(Object.hasOwn(row, 'op'));
  const scalarSet = (name: string, parse: (entry: unknown) => string): void => {
    distinct(exact(value, ['op', name])[name], parse, stringKey, POLICY_LIMITS.setEntries, true);
  };
  switch (row.op) {
    case 'all': case 'any': {
      const children = array(exact(value, ['op', 'children']).children, POLICY_LIMITS.setEntries);
      requireInput(children.length > 0);
      for (const child of children) expression(child, depth + 1, budget);
      return;
    }
    case 'subject-in':
      distinct(exact(value, ['op', 'subjects']).subjects, subject, subjectKey, POLICY_LIMITS.setEntries, true); return;
    case 'role-any':
      distinct(exact(value, ['op', 'roles']).roles, role, roleKey, POLICY_LIMITS.setEntries, true); return;
    case 'group-any': scalarSet('groupIds', uuid); return;
    case 'action-in': scalarSet('actions', entry => registered(entry, actions)); return;
    case 'resource-kind-in': scalarSet('kinds', entry => registered(entry, kinds)); return;
    case 'domain-in': {
      const domain = exact(value, ['op', 'domainIds', 'includeAncestors']);
      requireInput(typeof domain.includeAncestors === 'boolean');
      distinct(domain.domainIds, uuid, stringKey, POLICY_LIMITS.setEntries, true); return;
    }
    case 'classification-any': case 'approved-tag-any': case 'purpose-in': case 'environment-in':
      scalarSet('ids', uuid); return;
    case 'time-within': interval(exact(value, ['op', 'validity']).validity); return;
    default: throw unavailable;
  }
}

/** Evaluate admitted canonical facts, not authority. The trusted producer still
 * proves provenance, current memberships, exact grants and connected chains.
 * Invalid used data and unsupported constructs return indeterminate. */
export function evaluatePolicyExpression(input: PolicyExpr, facts: ExpressionFacts): ExpressionTruth {
  try {
    expression(input, 1, { nodes: 0 });
    const context = exact(facts, ['subject', 'request', 'now', 'groups', 'requestRoles', 'domainPath',
      'classifications', 'approvedTags', 'purpose', 'environment']);
    const currentSubject = subject(context.subject), currentRequest = request(context.request), now = timestamp(context.now);
    const cache = new Map<string, unknown>();
    function fact<T>(name: string, parse: (value: unknown) => T): T {
      if (cache.has(name)) {
        const result = cache.get(name); if (result === unavailable) throw unavailable;
        return result as T;
      }
      try {
        const header = dataObject(context[name], 2);
        requireInput(header.status === 'known');
        const value = parse(exact(context[name], ['status', 'value']).value);
        cache.set(name, value); return value;
      } catch {
        cache.set(name, unavailable); throw unavailable;
      }
    }
    const ids = (name: string): ReadonlySet<UUID> => fact(name, value => new Set(distinct(value, uuid, stringKey)));
    function evaluate(node: PolicyExpr): ExpressionTruth {
      if (node.op === 'all' || node.op === 'any') {
        // No some/every short-circuit: every expression branch is evaluated.
        const children = node.children.map(evaluate);
        if (children.includes('indeterminate')) return 'indeterminate';
        const matched = node.op === 'all' ? !children.includes('no-match') : children.includes('match');
        return matched ? 'match' : 'no-match';
      }
      try {
        let matched: boolean;
        switch (node.op) {
          case 'subject-in': matched = node.subjects.some(entry => subjectKey(entry) === subjectKey(currentSubject)); break;
          case 'action-in': matched = node.actions.includes(currentRequest.action); break;
          case 'resource-kind-in': matched = node.kinds.includes(currentRequest.resource.kind); break;
          case 'group-any': { const known = ids('groups'); matched = node.groupIds.some(id => known.has(id)); break; }
          case 'role-any': {
            const known = fact('requestRoles', value => {
              const bound = exact(value, ['subject', 'request', 'roles']);
              requireInput(subjectKey(subject(bound.subject)) === subjectKey(currentSubject)
                && sameRequest(request(bound.request), currentRequest));
              return new Set(distinct(bound.roles, role, roleKey).map(roleKey));
            });
            matched = node.roles.some(pin => known.has(roleKey(pin))); break;
          }
          case 'domain-in': {
            const path = fact('domainPath', value => distinct(value, uuid, stringKey, POLICY_LIMITS.domainAncestors + 1));
            matched = node.domainIds.some(id => node.includeAncestors ? path.includes(id) : path[0] === id); break;
          }
          case 'classification-any': case 'approved-tag-any': {
            const known = ids(node.op === 'classification-any' ? 'classifications' : 'approvedTags');
            matched = node.ids.some(id => known.has(id)); break;
          }
          case 'purpose-in': {
            const purpose = fact('purpose', value => value === null ? null : uuid(value));
            matched = purpose !== null && node.ids.includes(purpose); break;
          }
          case 'environment-in': matched = node.ids.includes(fact('environment', uuid)); break;
          case 'time-within': {
            const { notBefore, expiresAt } = node.validity;
            matched = (notBefore === null || now >= notBefore) && (expiresAt === null || now < expiresAt); break;
          }
          default: throw unavailable;
        }
        return matched ? 'match' : 'no-match';
      } catch { return 'indeterminate'; }
    }
    return evaluate(input);
  } catch { return 'indeterminate'; }
}
