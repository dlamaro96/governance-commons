// SPDX-License-Identifier: Apache-2.0
import { type AttributeValues, type ValidationResult } from './model.ts';
import { RELATION_LIMITS, parseRelationValidity, resolveRelationDefinition, relationValidationInternals as v } from './relation.ts';
import type { RelationDefinition, RelationEndpointPolicyState } from './relation-contracts.ts';
import type { CompleteGraphSnapshot, FinalRelationGraphConstraintsInput, GraphBindingSnapshot, GraphEdgeSnapshot,
  ParticipationDerivationInput, ParticipationSide, RelationMigrationValues, RelationPolicySnapshot,
  RelationStructuralPolicy, RequiredParticipation } from './relation-migration-contracts.ts';
const encoder = new TextEncoder();
const { Issues, copyJSON, fields, list, id, key, version, canonical, freeze, compare, endpoint } = v;
type Issues = InstanceType<typeof Issues>;
type Fields = Record<string, unknown>;
export const PARTICIPATION_LIMITS = Object.freeze({ targets: 8, bindings: 4000, assets: 2000, changes: 1000, principals: 2001 });
export const policyKey = (type: string, version: number): string => `${type}:${version}`;
export const edgeKey = (edge: GraphEdgeSnapshot): string => edge.key.kind === 'existing' ? `existing:${edge.key.relationId}` : `creation:${edge.key.relationTypeId}:${edge.key.key}`;
export const bindingKey = (binding: GraphBindingSnapshot): string => binding.key.kind === 'existing' ? `existing:${binding.key.bindingId}` : `enrollment:${binding.key.relationTypeId}:${binding.key.assetId}:${binding.key.side}`;
export const bindingIdentity = (binding: Pick<GraphBindingSnapshot, 'relationTypeId' | 'assetId' | 'side'>): string => `${binding.relationTypeId}:${binding.assetId}:${binding.side}`;
export function structuralProjection(definition: RelationDefinition): RelationStructuralPolicy {
  return { direction: definition.direction, sourceTypes: definition.sourceTypes, targetTypes: definition.targetTypes,
    sourceStates: definition.sourceStates, targetStates: definition.targetStates, cardinality: definition.cardinality,
    allowSelf: definition.allowSelf, cycles: definition.cycles };
}
export function relationStructuralPolicy(input: unknown): ValidationResult<RelationStructuralPolicy> {
  const result = resolveRelationDefinition(input); return result.ok ? { ok: true, value: freeze(structuralProjection(result.value.definition)) } : result;
}
export function policiesFromJSON(input: unknown, issues: Issues): Map<string, RelationPolicySnapshot> {
  const output = new Map<string, RelationPolicySnapshot>(), logical = new Map<string, string>(), names = new Map<string, string>();
  for (const [i, raw] of list(input, '/policies', 5000, issues).entries()) {
    const path = `/policies/${i}`, value = fields(raw, path, ['relationTypeId', 'definition', 'model'], issues);
    if (!value || !id(value.relationTypeId, `${path}/relationTypeId`, issues)) continue;
    const parsed = resolveRelationDefinition(value.definition);
    if (!parsed.ok) { issues.append(`${path}/definition`, parsed.issues); continue; }
    if (canonical(value.model) !== canonical(parsed.value.model)) issues.add('invalid_definition', `${path}/model`, 'The exact resolved relation model must match its definition.');
    const pin = policyKey(value.relationTypeId, parsed.value.definition.version);
    if (output.has(pin)) issues.add('duplicate', path, 'An exact policy pin occurs once.');
    if (logical.has(value.relationTypeId) && logical.get(value.relationTypeId) !== parsed.value.definition.id || names.has(parsed.value.definition.id) && names.get(parsed.value.definition.id) !== value.relationTypeId)
      issues.add('model_identity', path, 'Logical keys and immutable relation identities must agree.');
    logical.set(value.relationTypeId, parsed.value.definition.id); names.set(parsed.value.definition.id, value.relationTypeId);
    output.set(pin, { relationTypeId: value.relationTypeId, ...parsed.value });
  }
  return output;
}
/** Input has already passed the aggregate descriptor-safe copier. */
export function valuesFromJSON(input: unknown, path: string, issues: Issues): RelationMigrationValues | undefined {
  const value = fields(input, path, ['attributes', 'ownerId', 'state', 'validFrom', 'validTo', 'visibility', 'allowedIdentityIds'], issues);
  if (!value) return;
  if (!value.attributes || typeof value.attributes !== 'object' || Array.isArray(value.attributes)) issues.add('type', `${path}/attributes`, 'Expected an attribute object.');
  if (value.ownerId !== null) id(value.ownerId, `${path}/ownerId`, issues);
  key(value.state, `${path}/state`, issues);
  const validity = parseRelationValidity({ validFrom: value.validFrom, validTo: value.validTo });
  if (!validity.ok) issues.append(path, validity.issues);
  if (value.visibility !== 'tenant' && value.visibility !== 'restricted') issues.add('enum', `${path}/visibility`, 'Choose tenant or restricted visibility.');
  const identities: string[] = [], seen = new Set<string>();
  for (const [i, member] of list(value.allowedIdentityIds, `${path}/allowedIdentityIds`, 100, issues).entries()) {
    if (!id(member, `${path}/allowedIdentityIds/${i}`, issues)) continue;
    if (seen.has(member)) issues.add('duplicate', `${path}/allowedIdentityIds/${i}`, 'ACL identities occur once.');
    seen.add(member); identities.push(member);
  }
  if (value.visibility === 'tenant' && identities.length || value.visibility === 'restricted' && !identities.length)
    issues.add('invalid_definition', `${path}/allowedIdentityIds`, 'Tenant visibility has no ACL; restricted visibility requires a nonempty ACL.');
  return { attributes: value.attributes as AttributeValues, ownerId: value.ownerId as string | null, state: value.state as string,
    validFrom: value.validFrom as string | null, validTo: value.validTo as string | null,
    visibility: value.visibility as 'tenant' | 'restricted', allowedIdentityIds: identities.sort(compare) };
}
function side(input: unknown, path: string, issues: Issues): input is ParticipationSide {
  if (input === 'source' || input === 'target' || input === 'incident') return true;
  issues.add('enum', path, 'Choose source, target or incident participation.'); return false;
}
export function graphFromJSON(input: unknown, path: string, issues: Issues): CompleteGraphSnapshot | undefined {
  const raw = fields(input, path, ['heads', 'endpoints', 'edges', 'bindings'], issues); if (!raw) return;
  const heads: CompleteGraphSnapshot['heads'][number][] = [], endpoints: RelationEndpointPolicyState[] = [], edges: GraphEdgeSnapshot[] = [], bindings: GraphBindingSnapshot[] = [];
  const headIds = new Set<string>(), endpointIds = new Set<string>(), edgeIds = new Set<string>(), bindingIds = new Set<string>();
  for (const [i, item] of list(raw.heads, `${path}/heads`, 5000, issues).entries()) {
    const p = `${path}/heads/${i}`, head = fields(item, p, ['relationTypeId', 'version'], issues); if (!head) continue;
    if (id(head.relationTypeId, `${p}/relationTypeId`, issues) && version(head.version, `${p}/version`, issues)) {
      if (headIds.has(head.relationTypeId)) issues.add('duplicate', p, 'A logical type has one admission head.');
      headIds.add(head.relationTypeId); heads.push({ relationTypeId: head.relationTypeId, version: head.version });
    }
  }
  for (const [i, item] of list(raw.endpoints, `${path}/endpoints`, 2000, issues).entries()) {
    const p = `${path}/endpoints/${i}`, asset = endpoint(item, p, issues); if (!asset) continue;
    if (endpointIds.has(asset.assetId)) issues.add('duplicate', p, 'An endpoint candidate occurs once.');
    endpointIds.add(asset.assetId); endpoints.push(asset);
  }
  for (const [i, item] of list(raw.edges, `${path}/edges`, 2000, issues).entries()) {
    const p = `${path}/edges/${i}`, edge = fields(item, p, ['key', 'version', 'relationTypeId', 'relationTypeVersion', 'sourceAssetId', 'sourceAssetVersion', 'targetAssetId', 'targetAssetVersion', 'status', 'values'], issues);
    if (!edge) continue;
    const k = edge.key as Fields | undefined;
    const tag = fields(k, `${p}/key`, k?.kind === 'existing' ? ['kind', 'relationId'] : ['kind', 'relationTypeId', 'key'], issues);
    if (!tag) continue;
    if (tag.kind === 'existing') id(tag.relationId, `${p}/key/relationId`, issues);
    else if (tag.kind === 'creation') { id(tag.relationTypeId, `${p}/key/relationTypeId`, issues); key(tag.key, `${p}/key/key`, issues); if (tag.relationTypeId !== edge.relationTypeId) issues.add('model_identity', `${p}/key`, 'Creation keys belong to their exact type.'); }
    else issues.add('enum', `${p}/key/kind`, 'Expected an existing or creation identity.');
    for (const name of ['relationTypeId', 'sourceAssetId', 'targetAssetId']) id(edge[name], `${p}/${name}`, issues);
    for (const name of ['version', 'relationTypeVersion', 'sourceAssetVersion', 'targetAssetVersion']) version(edge[name], `${p}/${name}`, issues);
    if (edge.status !== 'active' && edge.status !== 'tombstoned') issues.add('enum', `${p}/status`, 'Expected active or tombstoned.');
    const values = valuesFromJSON(edge.values, `${p}/values`, issues); if (!values) continue;
    const result = { ...edge, values } as unknown as GraphEdgeSnapshot, lookup = edgeKey(result);
    if (edgeIds.has(lookup)) issues.add('duplicate', p, 'An edge identity occurs once.'); edgeIds.add(lookup); edges.push(result);
  }
  for (const [i, item] of list(raw.bindings, `${path}/bindings`, 5000, issues).entries()) {
    const p = `${path}/bindings/${i}`, binding = fields(item, p, ['key', 'version', 'relationTypeId', 'relationTypeVersion', 'assetId', 'assetVersion', 'side', 'status'], issues); if (!binding) continue;
    const k = binding.key as Fields | undefined, tag = fields(k, `${p}/key`, k?.kind === 'existing' ? ['kind', 'bindingId'] : ['kind', 'relationTypeId', 'assetId', 'side'], issues); if (!tag) continue;
    if (tag.kind === 'existing') id(tag.bindingId, `${p}/key/bindingId`, issues);
    else if (tag.kind === 'enrollment') {
      if (tag.relationTypeId !== binding.relationTypeId || tag.assetId !== binding.assetId || tag.side !== binding.side) issues.add('model_identity', `${p}/key`, 'Enrollment key must equal its immutable binding identity.');
    } else issues.add('enum', `${p}/key/kind`, 'Expected existing or enrollment identity.');
    id(binding.relationTypeId, `${p}/relationTypeId`, issues); id(binding.assetId, `${p}/assetId`, issues);
    for (const name of ['version', 'relationTypeVersion', 'assetVersion']) version(binding[name], `${p}/${name}`, issues);
    side(binding.side, `${p}/side`, issues);
    if (binding.status !== 'active' && binding.status !== 'released') issues.add('enum', `${p}/status`, 'Expected active or released.');
    const result = binding as unknown as GraphBindingSnapshot, lookup = bindingKey(result);
    if (bindingIds.has(lookup)) issues.add('duplicate', p, 'A binding identity occurs once.'); bindingIds.add(lookup); bindings.push(result);
  }
  if (edges.filter(edge => edge.status === 'active').length > 1000 || bindings.filter(binding => binding.status === 'active').length > 4000)
    issues.add('limit', path, 'The active edge or participation bound was exceeded.');
  return { heads: heads.sort((a, b) => compare(a.relationTypeId, b.relationTypeId)), endpoints: endpoints.sort((a, b) => compare(a.assetId, b.assetId)),
    edges: edges.sort((a, b) => compare(edgeKey(a), edgeKey(b))), bindings: bindings.sort((a, b) => compare(bindingKey(a), bindingKey(b))) };
}
export function eligible(asset: RelationEndpointPolicyState, definition: RelationDefinition, side: ParticipationSide): boolean {
  const rules = side === 'target' ? definition.targetTypes : definition.sourceTypes, states = side === 'target' ? definition.targetStates : definition.sourceStates;
  return asset.typeId !== null && asset.policy !== null && asset.state !== null && asset.policy.lifecycle.states.includes(asset.state)
    && (states === null || states.includes(asset.state)) && rules.some(rule => rule.typeId === asset.typeId || rule.includeDescendants && asset.ancestorTypes.some(pin => pin.typeId === rule.typeId));
}
export function degreeFor(graph: CompleteGraphSnapshot, type: string, asset: string, side: ParticipationSide): number {
  return graph.edges.filter(edge => edge.status === 'active' && edge.relationTypeId === type && (side === 'source' ? edge.sourceAssetId === asset : side === 'target' ? edge.targetAssetId === asset : edge.sourceAssetId === asset || edge.targetAssetId === asset)).length;
}
export function deriveFromGraph(graph: CompleteGraphSnapshot, policies: Map<string, RelationPolicySnapshot>, issues: Issues): RequiredParticipation[] {
  const output: RequiredParticipation[] = [], active = new Map<string, GraphBindingSnapshot>();
  for (const binding of graph.bindings.filter(row => row.status === 'active')) {
    const identity = bindingIdentity(binding); if (active.has(identity)) issues.add('duplicate', '/participation', 'An asset has only one active binding per logical type and side.'); active.set(identity, binding);
  }
  for (const [i, head] of graph.heads.entries()) {
    const policy = policies.get(policyKey(head.relationTypeId, head.version));
    if (!policy) { issues.add('required', `/heads/${i}`, 'The exact admission policy is required.'); continue; }
    const sides: ParticipationSide[] = policy.definition.direction === 'directed' ? ['source', 'target'] : ['incident'];
    for (const asset of graph.endpoints) for (const side of sides) {
      const degree = side === 'target' ? policy.definition.cardinality.incoming : policy.definition.cardinality.outgoing;
      if (!degree.min || !eligible(asset, policy.definition, side)) continue;
      const binding = active.get(`${head.relationTypeId}:${asset.assetId}:${side}`);
      output.push({ relationTypeId: head.relationTypeId, policyVersion: head.version, assetId: asset.assetId, assetVersion: asset.assetVersion,
        side, min: degree.min, max: degree.max, existingBindingId: binding?.key.kind === 'existing' ? binding.key.bindingId : null });
    }
  }
  return output.sort((a, b) => compare(bindingIdentity(a), bindingIdentity(b)));
}
export function deriveRequiredParticipation(input: ParticipationDerivationInput): ValidationResult<readonly RequiredParticipation[]> {
  const issues = new Issues(), raw = copyJSON(input, issues); if (issues.values.length) return issues.result([]);
  const data = fields(raw, '', ['admissionHeads', 'policies', 'completeEligibleEndpointCandidates', 'currentBindings'], issues); if (!data) return issues.result([]);
  const graph = graphFromJSON({ heads: data.admissionHeads, endpoints: data.completeEligibleEndpointCandidates, bindings: data.currentBindings, edges: [] }, '', issues);
  const policies = policiesFromJSON(data.policies, issues); if (!graph || issues.values.length) return issues.result([]);
  const result = deriveFromGraph(graph, policies, issues);
  if (encoder.encode(canonical(raw)).length + encoder.encode(canonical(result)).length > RELATION_LIMITS.bytes) issues.add('limit', '', 'The retained input and participation result exceed the aggregate byte budget.');
  return issues.result(freeze(result));
}
export function checkFinalGraph(graph: CompleteGraphSnapshot, policies: Map<string, RelationPolicySnapshot>, issues: Issues): RequiredParticipation[] {
  const endpoints = new Map(graph.endpoints.map(asset => [asset.assetId, asset])), heads = new Map(graph.heads.map(head => [head.relationTypeId, head]));
  const required = deriveFromGraph(graph, policies, issues), activeBindings = new Map(graph.bindings.filter(row => row.status === 'active').map(row => [bindingIdentity(row), row]));
  for (const [i, row] of required.entries()) {
    if (!activeBindings.has(bindingIdentity(row))) issues.add('required', `/participation/${i}/binding`, 'An eligible required participant needs an active binding.');
    if (degreeFor(graph, row.relationTypeId, row.assetId, row.side) < row.min) issues.add('range', `/participation/${i}/minimum`, 'The complete structural degree is below the required minimum.');
  }
  for (const [i, binding] of graph.bindings.entries()) {
    if (binding.status !== 'active') continue;
    const pin = policies.get(policyKey(binding.relationTypeId, binding.relationTypeVersion)), head = heads.get(binding.relationTypeId), asset = endpoints.get(binding.assetId);
    const admission = head && policies.get(policyKey(head.relationTypeId, head.version));
    if (!pin || !admission || !asset) { issues.add('required', `/bindings/${i}`, 'Binding requires exact policy, head and endpoint evidence.'); continue; }
    if (binding.relationTypeVersion > head!.version) issues.add('model_version', `/bindings/${i}/relationTypeVersion`, 'A live binding cannot pin a future admission policy.');
    if (binding.assetVersion > asset.assetVersion) issues.add('model_version', `/bindings/${i}/assetVersion`, 'Recorded asset revision cannot exceed the actual endpoint revision.');
    if (canonical(structuralProjection(pin.definition)) !== canonical(structuralProjection(admission.definition))) issues.add('invalid_definition', `/bindings/${i}/relationTypeVersion`, 'Every active binding must share the final admission fingerprint.');
    if ((pin.definition.direction === 'directed') === (binding.side === 'incident') || !eligible(asset, pin.definition, binding.side)) issues.add('invalid_definition', `/bindings/${i}/side`, 'An active binding must remain eligible for its immutable side.');
    const constraint = binding.side === 'target' ? pin.definition.cardinality.incoming : pin.definition.cardinality.outgoing, count = degreeFor(graph, binding.relationTypeId, binding.assetId, binding.side);
    if (count < constraint.min) issues.add('range', `/participation/${required.length + i}/minimum`, 'A retained binding minimum is unsatisfied.');
    if (constraint.max !== null && count > constraint.max) issues.add('range', `/structure/${graph.heads.findIndex(row => row.relationTypeId === binding.relationTypeId)}/maximum`, 'A retained binding maximum is exceeded.');
  }
  for (const [typeIndex, head] of graph.heads.entries()) {
    const policy = policies.get(policyKey(head.relationTypeId, head.version)); if (!policy) continue;
    const definition = policy.definition, rows = graph.edges.filter(edge => edge.status === 'active' && edge.relationTypeId === head.relationTypeId);
    const pairs = new Set<string>(), adjacency = new Map<string, string[]>(), indegree = new Map<string, number>(), parents = new Map<string, string>();
    const find = (node: string): string => { if (!parents.has(node)) parents.set(node, node); let root = node; while (parents.get(root) !== root) root = parents.get(root)!; while (node !== root) { const next = parents.get(node)!; parents.set(node, root); node = next; } return root; };
    let cycle = false;
    for (const edge of rows) {
      const pin = policies.get(policyKey(edge.relationTypeId, edge.relationTypeVersion)), source = endpoints.get(edge.sourceAssetId), target = endpoints.get(edge.targetAssetId), path = `/structure/${typeIndex}`;
      if (!pin || !source || !target) { issues.add('required', path, 'Every edge requires exact policy and both endpoints.'); continue; }
      if (edge.relationTypeVersion > head.version) issues.add('model_version', `${path}/pins`, 'A live edge cannot pin a future admission policy.');
      if (canonical(structuralProjection(pin.definition)) !== canonical(structuralProjection(definition))) issues.add('invalid_definition', `${path}/pins`, 'All surviving edge pins must share the final admission fingerprint.');
      if (edge.sourceAssetVersion > source.assetVersion || edge.targetAssetVersion > target.assetVersion) issues.add('model_version', path, 'Historical endpoint observations cannot exceed current revisions.');
      if (!eligible(source, pin.definition, 'source') || !eligible(target, pin.definition, 'target')) issues.add('invalid_definition', `${path}/endpoints`, 'Both final endpoints must satisfy the exact pinned nominal and state policy.');
      if (definition.direction === 'undirected' && edge.sourceAssetId > edge.targetAssetId) issues.add('invalid_definition', `${path}/pairs`, 'Undirected endpoints must be stored in canonical order.');
      const pair = `${edge.sourceAssetId}:${edge.targetAssetId}`; if (pairs.has(pair)) issues.add('duplicate', `${path}/pairs`, 'The final live pair must be unique across pins.'); pairs.add(pair);
      if (!definition.allowSelf && source.assetId === target.assetId) issues.add('invalid_definition', `${path}/self`, 'The final policy forbids self-edges.');
      for (const [asset, side, bound] of [[source, definition.direction === 'directed' ? 'source' : 'incident', pin.definition.cardinality.outgoing.max], [target, definition.direction === 'directed' ? 'target' : 'incident', pin.definition.cardinality.incoming.max]] as const)
        if (bound !== null && degreeFor(graph, edge.relationTypeId, asset.assetId, side) > bound) issues.add('range', `${path}/maximum`, 'A surviving edge maximum is exceeded.');
      if (definition.cycles === 'acyclic') {
        if (definition.direction === 'undirected') { const a = find(source.assetId), b = find(target.assetId); if (a === b) cycle = true; else parents.set(a, b); }
        else { for (const asset of [source, target]) { if (!adjacency.has(asset.assetId)) adjacency.set(asset.assetId, []); if (!indegree.has(asset.assetId)) indegree.set(asset.assetId, 0); } adjacency.get(source.assetId)!.push(target.assetId); indegree.set(target.assetId, indegree.get(target.assetId)! + 1); }
      }
    }
    if (definition.cycles === 'acyclic' && definition.direction === 'directed') { const pending = [...indegree].filter(([, count]) => count === 0).map(([asset]) => asset); let seen = 0; for (let i = 0; i < pending.length; i++) { seen++; for (const next of adjacency.get(pending[i])!) { indegree.set(next, indegree.get(next)! - 1); if (!indegree.get(next)) pending.push(next); } } cycle = seen !== indegree.size; }
    if (cycle) issues.add('cycle', `/structure/${typeIndex}/cycles`, 'The complete final structural cohort contains a forbidden cycle.');
  }
  for (const [i, edge] of graph.edges.entries()) if (edge.status === 'active' && !heads.has(edge.relationTypeId)) issues.add('required', `/edges/${i}/relationTypeId`, 'Every active edge type needs its admission head.');
  return required;
}
export function validateFinalRelationGraphConstraints(input: FinalRelationGraphConstraintsInput): ValidationResult<readonly RequiredParticipation[]> {
  const issues = new Issues(), raw = copyJSON(input, issues); if (issues.values.length) return issues.result([]);
  const value = fields(raw, '', ['graph', 'policies'], issues); if (!value) return issues.result([]);
  const graph = graphFromJSON(value.graph, '/graph', issues), policies = policiesFromJSON(value.policies, issues);
  if (!graph || issues.values.length) return issues.result([]);
  const result = checkFinalGraph(graph, policies, issues);
  if (encoder.encode(canonical(raw)).length + encoder.encode(canonical(result)).length > RELATION_LIMITS.bytes) issues.add('limit', '', 'The retained input and participation result exceed the aggregate byte budget.');
  return issues.result(freeze(result));
}
