// SPDX-License-Identifier: Apache-2.0
import { makeDecisionFixture, sealDecisionFixture, id, v, zero, type DecisionFixture, type Mutable } from './authority-decision.ts';
import { decisionHash } from '../../../packages/authority/src/decision-schema.ts';
import type { DecisionNode, ProjectionFieldRegistration } from '../../../packages/authority/src/decision-types.ts';
import type { Digest, FieldId, ProjectionId } from '../../../packages/authority/src/types.ts';
export function makeFieldFixture(path: 'direct' | 'registered-reference' = 'direct', sensitive = false): DecisionFixture {
  const f = makeDecisionFixture(), { bundle, registry } = f, parent = bundle.nodes[0];
  const fieldId = 'asset.description' as FieldId, projectionId = 'asset.detail' as ProjectionId;
  registry.fields.push(fieldId);
  const registration = { projectionId, version: v, fieldId, resourceKind: 'asset' as const, path,
    prerequisites: [{ action: 'asset:metadata.read' as const, resource: path === 'direct' ? 'field-owner' as const : 'reference-parent' as const }] };
  registry.projections.push({ ...registration, registrationHash: decisionHash(registration) });
  const field: Mutable<DecisionNode> = { ...structuredClone(parent), id: 'a'.repeat(64) as Digest, intentGuard: 'b'.repeat(64) as Digest,
    adapterId: 'field.read', request: { ...structuredClone(parent.request), action: 'field:read', field: fieldId } };
  if (path === 'registered-reference') {
    field.request.resource.id = id(60); field.resource.requestResource = field.request.resource; field.resource.containment.resource = field.request.resource;
    bundle.references.push({ id: id(61), version: v, tenantId: id(1), projectionId, projectionVersion: v, registrationHash: decisionHash(registration),
      parent: { resource: parent.request.resource, revision: v }, target: { resource: field.request.resource, revision: v }, fieldId, sourceRecordId: id(62), sourceRecordVersion: v });
  }
  field.projection = { projectionId, version: v, registrationHash: decisionHash(registration), fieldId, resource: field.request.resource, revision: v,
    sensitivityRevision: field.resource.containment.securityRevision, sensitivity: sensitive ? 'sensitive' : 'ordinary',
    prerequisites: [parent.id], sensitiveDecision: sensitive ? 'c'.repeat(64) as Digest : null,
    path: path === 'direct' ? { kind: 'direct' } : { kind: 'registered-reference', referenceId: id(61), referenceVersion: v } };
  registry.adapters.push({ ...structuredClone(registry.adapters[0]), id: field.adapterId, branch: 'field', action: 'field:read' });
  const add = (node: Mutable<DecisionNode>) => {
    const guard: Mutable<DecisionNode> = { ...structuredClone(node), id: node.intentGuard!, mode: 'resource-wide-deny', intentGuard: null, guardOrigin: node.id,
      adapterId: 'asset.guard', request: { ...node.request, action: 'asset:metadata.read', field: null }, projection: null };
    bundle.nodes.push(node, guard);
    for (const n of [node, guard]) bundle.candidates.push({ nodeId: n.id, snapshotDigest: bundle.snapshot.snapshotDigest, subject: n.subject,
      request: n.request, anchorDigest: zero, candidates: [] });
  };
  add(field);
  if (sensitive) {
    const companion: Mutable<DecisionNode> = { ...structuredClone(field), id: field.projection.sensitiveDecision!, intentGuard: 'd'.repeat(64) as Digest,
      adapterId: 'field.sensitive', request: { ...field.request, action: 'field:sensitive.read' }, projection: { ...field.projection, sensitiveDecision: null } };
    registry.adapters.push({ ...structuredClone(registry.adapters[0]), id: companion.adapterId, branch: 'field', action: 'field:sensitive.read' }); add(companion);
  }
  bundle.root = field.id;
  return sealDecisionFixture(JSON.parse(JSON.stringify(f)) as DecisionFixture);
}
