// SPDX-License-Identifier: Apache-2.0
import type { ActionId } from './actions.ts';

export type UUID = string & { readonly __uuid: unique symbol };
export type Version = number & { readonly __version: unique symbol };
export type UTC = string & { readonly __utc: unique symbol };
export type Digest = string & { readonly __sha256: unique symbol };
export type Counter = string & { readonly __counter: unique symbol };
export type FieldId = string & { readonly __registeredField: unique symbol };
export type ProjectionId = string & { readonly __registeredProjection: unique symbol };
export type ResourceKind = 'tenant' | 'tenant-member' | 'source' | 'scan-job' | 'asset'
  | 'model-definition' | 'model-migration' | 'asset-type-migration' | 'relation-type' | 'relation'
  | 'relation-participation' | 'relation-operation' | 'relation-preparation'
  | 'domain-type' | 'domain' | 'asset-domain-placement' | 'domain-type-migration' | 'audit-event'
  | 'authority-group' | 'authority-role' | 'authority-policy' | 'authority-grant'
  | 'responsibility-type' | 'responsibility-assignment' | 'authority-delegation' | 'authority-elevation'
  | 'execution-site' | 'service-principal' | 'authority-decision';
export type ResourceRef = { readonly tenantId: UUID; readonly kind: ResourceKind; readonly id: UUID };
export type RevisionRef = { readonly resource: ResourceRef; readonly version: Version };
export type SubjectRef = { readonly kind: 'human' | 'service'; readonly id: UUID };
export type Scope =
  | { readonly kind: 'tenant'; readonly tenantId: UUID }
  | { readonly kind: 'domain'; readonly tenantId: UUID; readonly domainId: UUID; readonly includeDescendants: boolean }
  | { readonly kind: 'resource'; readonly resource: ResourceRef };
export type RolePin = { readonly roleId: UUID; readonly version: Version };
export type PolicyPin = { readonly policyId: UUID; readonly version: Version; readonly hash: Digest };
export type Validity = { readonly notBefore: UTC | null; readonly expiresAt: UTC | null };
export type PolicyExpr =
  | { readonly op: 'all' | 'any'; readonly children: readonly PolicyExpr[] }
  | { readonly op: 'subject-in'; readonly subjects: readonly SubjectRef[] }
  | { readonly op: 'group-any'; readonly groupIds: readonly UUID[] }
  | { readonly op: 'role-any'; readonly roles: readonly RolePin[] }
  | { readonly op: 'action-in'; readonly actions: readonly ActionId[] }
  | { readonly op: 'resource-kind-in'; readonly kinds: readonly ResourceKind[] }
  | { readonly op: 'domain-in'; readonly domainIds: readonly UUID[]; readonly includeAncestors: boolean }
  | { readonly op: 'classification-any' | 'approved-tag-any'; readonly ids: readonly UUID[] }
  | { readonly op: 'purpose-in' | 'environment-in'; readonly ids: readonly UUID[] }
  | { readonly op: 'time-within'; readonly validity: Validity };
export type PolicyRule = {
  readonly id: UUID; readonly effect: 'allow' | 'deny'; readonly actions: readonly ActionId[];
  readonly fields: readonly FieldId[] | null; readonly when: PolicyExpr;
};
export type PolicyDefinition = {
  readonly formatVersion: 1; readonly id: UUID; readonly version: Version;
  readonly rules: readonly PolicyRule[];
};
export type AuthorityIssue = {
  readonly code: 'invalid_json' | 'unknown_field' | 'type' | 'required' | 'duplicate'
    | 'format' | 'range' | 'limit' | 'unsupported' | 'scope' | 'version';
  readonly path: string; readonly message: string;
};
export type Parsed<T> = { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly issues: readonly AuthorityIssue[] };

/** Trusted exact field registry input; it is syntax evidence, never a grant. */
export type PolicyFieldCatalog = readonly string[];
