// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import { admitAuthorityInput, AUTHORITY_ADMISSION_LIMITS as limits } from '../../packages/authority/src/admission.ts';
import { canonicalDecisionJSON as canonical, decisionHash, decisionShapes } from '../../packages/authority/src/decision-schema.ts';
import { parsePolicyFile } from '../../packages/authority/src/policy.ts';
import type { Counter, PolicyExpr, UTC, Version } from '../../packages/authority/src/types.ts';
import type { AuthorityHumanClosure } from '../../packages/authority-storage/src/contracts.ts';
import { parseAuthorityHumanClosure } from '../../packages/authority-storage/src/loader.ts';
import { parseHumanAssetContext, type HumanAssetContext } from '../../packages/authority-runtime/src/asset-context.ts';
import { makeDecisionFixture, id, v, now, zero, parsed, type Mutable } from './fixtures/authority-decision.ts';

const bytes = (value: unknown) => Buffer.byteLength(canonical(value));
const expressionNodes = (expression: PolicyExpr): number => 1 + ('children' in expression ? expression.children.reduce((n, child) => n + expressionNodes(child), 0) : 0);
/** Only synthetic construction evidence, derived from the existing engine
 * fixture. These helpers neither load a session nor assert database coverage. */
function sealClosure(closure: Mutable<AuthorityHumanClosure>) {
  closure.partitions.sort((a, b) => a.key < b.key ? -1 : a.key > b.key ? 1 : 0);
  closure.lifecycleHeads.sort((a, b) => {
    const left = `${a.family}:${a.definitionKind ?? ''}:${a.id}`, right = `${b.family}:${b.definitionKind ?? ''}:${b.id}`;
    return left < right ? -1 : left > right ? 1 : 0;
  });
  const policies = closure.policies.map(policy => parsed(parsePolicyFile(policy.document, [])));
  closure.metrics = {
    selectors: closure.selectors.length, partitions: closure.partitions.length, dependencyEdges: 0, dependencyReferences: 0, dependencyDepth: 1,
    canonicalBytes: 0, jsonNodes: 0, maxDepth: 0, policies: policies.length, policyBytes: policies.reduce((n, policy) => n + bytes(policy), 0),
    policyRules: policies.reduce((n, policy) => n + policy.rules.length, 0), expressionNodes: policies.reduce((n, policy) => n + policy.rules.reduce((m, rule) => m + expressionNodes(rule.when), 0), 0),
    ordinaryOrigins: closure.grants.length, connectedRecords: 0, principals: closure.principals.length, directGroupsMaximum: 0,
    proofBytes: [closure.session, closure.partitions, closure.definitions, closure.principals, closure.groups, closure.memberships, closure.principalGroups, closure.grants, closure.elevationUses, closure.parents, closure.dependencies, closure.lifecycleHeads].reduce<number>((n, item) => n + bytes(item), 0),
  };
  const {metrics: _metrics, snapshot, ...rest} = closure, {closureDigest: _digest, ...snapshotBody} = snapshot;
  closure.snapshot.closureDigest = decisionHash({...rest, snapshot: snapshotBody});
  for (let round = 0; round < 4; round++) {
    const metrics = parsed(admitAuthorityInput(closure)).metrics;
    closure.metrics.canonicalBytes = metrics.canonicalBytes;
    closure.metrics.jsonNodes = metrics.nodes;
    closure.metrics.maxDepth = metrics.depth;
  }
  assert.equal(closure.metrics.canonicalBytes, bytes(closure));
  return closure;
}
function seal(context: Mutable<HumanAssetContext>) {
  context.contextDigest = decisionHash({...context, contextDigest: zero});
  return context;
}
function fixture(placed = false): Mutable<HumanAssetContext> {
  const {bundle, registry: rawRegistry} = makeDecisionFixture();
  const registry = structuredClone(decisionShapes.registry(rawRegistry, '')) as typeof rawRegistry;
  const session = bundle.sessions[0]!, node = bundle.nodes.find(entry => entry.mode === 'authorize')!;
  const closure: Mutable<AuthorityHumanClosure> = {
    formatVersion: 1, kind: 'inactive-human-candidate-closure', contentAuthority: false,
    session: {formatVersion: 1, sessionId: session.id, sessionVersion: v, identityId: session.identityId, tenantId: session.selectedTenantId, generation: '1' as Counter, authnFenceEpoch: '1' as Counter, issuingRegistrationId: id(501), issuerRegistrationId: id(502), identityBindingId: id(503), authenticatedAt: '2026-11-16T05:00:00.000Z' as UTC, issuedAt: '2026-11-16T05:01:00.000Z' as UTC, expiresAt: '2026-11-16T07:00:00.000Z' as UTC},
    snapshot: {tenantId: session.selectedTenantId, generation: '1' as Counter, authorityEpoch: '1' as Counter, registryId: id(500), registryVersion: v, registryDigest: registry.digest, asOf: now, identityRevisionDigest: zero, closureDigest: zero},
    selectors: [node.request], partitions: [{key: decisionHash({formatVersion: 1, subject: node.subject, request: node.request}), subject: node.subject as {kind: 'human'; id: typeof session.identityId}, request: node.request, candidates: bundle.candidates.find(entry => entry.nodeId === node.id)!.candidates}],
    parents: [], dependencies: [], principals: bundle.principals as Mutable<AuthorityHumanClosure>['principals'], groups: bundle.groups, memberships: bundle.memberships, principalGroups: bundle.principalGroups,
    definitions: bundle.definitions, policies: bundle.policies, grants: bundle.grants as Mutable<AuthorityHumanClosure>['grants'], elevationUses: [], lifecycleHeads: [], metrics: {} as never,
  };
  for (const definition of closure.definitions) closure.lifecycleHeads.push({family: 'definition', definitionKind: definition.kind, id: definition.id, headVersion: v});
  for (const policy of closure.policies) closure.lifecycleHeads.push({family: 'definition', definitionKind: 'policy', id: policy.pin.policyId, headVersion: v});
  for (const grant of closure.grants) closure.lifecycleHeads.push({family: 'grant', definitionKind: null, id: grant.ref.id, headVersion: v});
  sealClosure(closure);
  parsed(parseAuthorityHumanClosure(closure, registry));
  return seal({formatVersion: 1, kind: 'inactive-human-asset-context', contentAuthority: false, closure, registry,
    asset: {tenantId: session.selectedTenantId, id: node.request.resource.id, version: v, status: 'active', visibility: 'tenant', allowedIdentities: []},
    placement: placed ? {version: v, domainId: id(601), recordedAssetVersion: v, recordedDomainVersion: v} : null,
    domainPath: placed ? [{id: id(601), version: 3 as Version, parentId: id(600), typeId: id(650), typeVersion: v, status: 'active'}, {id: id(600), version: 2 as Version, parentId: null, typeId: id(650), typeVersion: v, status: 'active'}] : [],
    domainEpoch: (placed ? '5' : '0') as Counter, unavailableFacts: ['classification', 'approved-tags', 'purpose', 'environment'], contextDigest: zero});
}
function refuses(value: unknown, code?: string) {
  const result = parseHumanAssetContext(value);
  assert.equal(result.ok, false);
  if (result.ok) throw new Error('Expected refusal');
  if (code !== undefined) assert.equal(result.issues[0]!.code, code);
  return result.issues;
}

test('inactive context accepts placed and never-placed canonical facts without granting authority', () => {
  for (const placed of [false, true]) {
    const input = fixture(placed), before = canonical(input), output = parsed(parseHumanAssetContext(input));
    assert.equal(output.contentAuthority, false);
    assert.deepEqual(output.unavailableFacts, ['classification', 'approved-tags', 'purpose', 'environment']);
    assert.equal(canonical(output), before);
    assert.equal(canonical(input), before);
    assert.notEqual(output, input);
    assert.ok(Object.isFrozen(output) && Object.isFrozen(output.asset) && Object.isFrozen(output.domainPath));
    assert.ok(Object.isFrozen(output.closure) && Object.isFrozen(output.registry));
    assert.equal(Object.hasOwn(output.asset, 'securityRevision'), false);
    assert.equal(Object.hasOwn(output, 'decision'), false);
    assert.deepEqual(parsed(parseHumanAssetContext(JSON.stringify(input))), output);
  }
});

test('historical placement versions may precede current asset and domain versions', () => {
  const input = fixture(true);
  input.asset.version = 7 as Version;
  input.closure.selectors[0]!.revision = input.asset.version;
  input.closure.partitions[0]!.request.revision = input.asset.version;
  input.closure.partitions[0]!.key = decisionHash({formatVersion: 1, subject: input.closure.partitions[0]!.subject, request: input.closure.partitions[0]!.request});
  sealClosure(input.closure);
  const output = parsed(parseHumanAssetContext(seal(input)));
  assert.equal(output.placement!.recordedAssetVersion, 1);
  assert.equal(output.placement!.recordedDomainVersion, 1);
  assert.equal(output.domainPath[0]!.id, output.placement!.domainId);
});

test('explicit unplacement retains its positive epoch and immutable placement record', () => {
  const input = fixture();
  input.placement = {version: 3 as Version, domainId: null, recordedAssetVersion: v, recordedDomainVersion: null};
  input.domainEpoch = '9' as Counter;
  assert.equal(parsed(parseHumanAssetContext(seal(input))).placement!.version, 3);
});

test('retired and restricted facts are preserved without interpreting them as access', () => {
  const input = fixture(true);
  input.asset.status = 'retired'; input.asset.visibility = 'restricted'; input.asset.allowedIdentities = [id(2), id(900)];
  input.domainPath[0]!.status = 'retired';
  assert.deepEqual(parsed(parseHumanAssetContext(seal(input))).asset, input.asset);
});

test('source-observed unavailable asset remains an inactive fact without implying deletion or access', () => {
  for (const placed of [false, true]) {
    const input = fixture(placed);
    input.asset.status = 'unavailable';
    const output = parsed(parseHumanAssetContext(seal(input)));
    assert.equal(output.asset.status, 'unavailable');
    assert.equal(output.contentAuthority, false);
    assert.equal(output.closure.contentAuthority, false);
    assert.deepEqual(output.placement, input.placement);
    assert.equal(Object.hasOwn(output, 'decision'), false);
    assert.equal(Object.hasOwn(output.asset, 'deleted'), false);
  }
});

test('context digest binds every envelope field and copied digests do not attest edited evidence', () => {
  for (const mutate of [
    (input: Mutable<HumanAssetContext>) => {input.asset.visibility = 'restricted';},
    (input: Mutable<HumanAssetContext>) => {input.domainEpoch = '6' as Counter;},
    (input: Mutable<HumanAssetContext>) => {input.domainPath[0]!.version = 4 as Version;},
    (input: Mutable<HumanAssetContext>) => {input.asset.allowedIdentities = [id(2)];},
    (input: Mutable<HumanAssetContext>) => {input.contextDigest = zero;},
  ]) {const input = fixture(true); mutate(input); refuses(input);}
  const source = fixture(true), copy = structuredClone(source); copy.asset.status = 'retired'; copy.contextDigest = source.contextDigest; refuses(copy);
});

test('resealing the outer context cannot excuse registry or closure hash corruption', () => {
  for (const mutate of [
    (input: Mutable<HumanAssetContext>) => {input.registry.digest = zero;},
    (input: Mutable<HumanAssetContext>) => {input.closure.snapshot.closureDigest = zero;},
    (input: Mutable<HumanAssetContext>) => {input.closure.definitions[0]!.hash = zero;},
    (input: Mutable<HumanAssetContext>) => {input.closure.metrics.jsonNodes++;},
  ]) {const input = fixture(); mutate(input); refuses(seal(input));}
});

test('closure selector must be the sole exact current metadata read for this asset', () => {
  for (const mutate of [
    (input: Mutable<HumanAssetContext>) => {input.asset.id = id(900);},
    (input: Mutable<HumanAssetContext>) => {input.asset.version = 2 as Version;},
    (input: Mutable<HumanAssetContext>) => {input.closure.selectors.push(structuredClone(input.closure.selectors[0]!)); sealClosure(input.closure);},
    (input: Mutable<HumanAssetContext>) => {input.closure.selectors[0]!.field = 'asset.name' as never; sealClosure(input.closure);},
  ]) {const input = fixture(); mutate(input); refuses(seal(input));}
});

test('otherwise valid closure for another registered action cannot become asset metadata context', () => {
  const input = fixture(), closure = input.closure;
  closure.selectors[0]!.action = 'asset:discover';
  closure.partitions[0]!.request = closure.selectors[0]!;
  closure.partitions[0]!.key = decisionHash({formatVersion: 1, subject: closure.partitions[0]!.subject, request: closure.partitions[0]!.request});
  closure.partitions[0]!.candidates = []; closure.grants = []; closure.definitions = []; closure.policies = []; closure.lifecycleHeads = [];
  sealClosure(closure);
  parsed(parseAuthorityHumanClosure(closure, input.registry));
  refuses(seal(input));
});

test('otherwise valid multi-selector closure cannot widen an exact single-asset context', () => {
  const input = fixture(), closure = input.closure, second = structuredClone(closure.selectors[0]!);
  second.revision = 2 as Version;
  closure.selectors.push(second);
  closure.partitions.push({...structuredClone(closure.partitions[0]!), request: second, key: decisionHash({formatVersion: 1, subject: closure.partitions[0]!.subject, request: second})});
  sealClosure(closure);
  parsed(parseAuthorityHumanClosure(closure, input.registry));
  refuses(seal(input));
});

test('asset tenant must agree with independently validated session and snapshot tenants', () => {
  const input = fixture(); input.asset.tenantId = id(900); refuses(seal(input));
  const other = fixture(); other.closure.snapshot.tenantId = id(901); sealClosure(other.closure); refuses(seal(other));
});

test('ancestry is nearest-first, contiguous and terminates at the null-parent root', () => {
  for (const mutate of [
    (input: Mutable<HumanAssetContext>) => {input.domainPath.reverse();},
    (input: Mutable<HumanAssetContext>) => {input.domainPath[0]!.parentId = id(999);},
    (input: Mutable<HumanAssetContext>) => {input.domainPath[1]!.parentId = id(999);},
    (input: Mutable<HumanAssetContext>) => {input.domainPath[0]!.id = id(999);},
    (input: Mutable<HumanAssetContext>) => {input.domainPath = [];},
    (input: Mutable<HumanAssetContext>) => {input.domainPath[1] = {...input.domainPath[0]!, parentId: null}; input.domainPath[0]!.parentId = input.domainPath[0]!.id;},
    (input: Mutable<HumanAssetContext>) => {input.domainPath[1]!.parentId = input.domainPath[0]!.id;},
  ]) {const input = fixture(true); mutate(input); refuses(seal(input));}
});

test('unplaced evidence cannot carry ancestry or a recorded domain revision', () => {
  const missing = fixture(true); missing.placement = null; refuses(seal(missing));
  const nullDomain = fixture(true); nullDomain.placement!.domainId = null; nullDomain.placement!.recordedDomainVersion = null; refuses(seal(nullDomain));
  const extraneousPin = fixture(); extraneousPin.placement = {version: v, domainId: null, recordedAssetVersion: v, recordedDomainVersion: v}; extraneousPin.domainEpoch = '1' as Counter; refuses(seal(extraneousPin));
});

test('placement history cannot exceed current asset or current direct-domain versions', () => {
  for (const mutate of [
    (input: Mutable<HumanAssetContext>) => {input.placement!.recordedAssetVersion = 2 as Version;},
    (input: Mutable<HumanAssetContext>) => {input.placement!.recordedDomainVersion = 4 as Version;},
    (input: Mutable<HumanAssetContext>) => {input.placement!.recordedDomainVersion = null;},
  ]) {const input = fixture(true); mutate(input); refuses(seal(input));}
});

test('domain epoch admits zero only without written placement and rejects noncanonical or overflowing counters', () => {
  const placed = fixture(true); placed.domainEpoch = '0' as Counter; refuses(seal(placed));
  const unplaced = fixture(); unplaced.placement = {version: v, domainId: null, recordedAssetVersion: v, recordedDomainVersion: null}; refuses(seal(unplaced));
  for (const value of ['00', '-1', '+1', '1.0', ' 1', '9223372036854775808', 0]) {const input = fixture(); input.domainEpoch = value as Counter; refuses(seal(input));}
  const maximum = fixture(); maximum.domainEpoch = '9223372036854775807' as Counter; parsed(parseHumanAssetContext(seal(maximum)));
});

test('allowed identities are canonical nonnil UUIDs in distinct sorted order with a 4096-entry cap', () => {
  for (const identities of [[id(3), id(2)], [id(2), id(2)], ['00000000-0000-0000-0000-000000000000'], ['00000000-0000-0000-0000-0000000000AA'], ['private']]) {
    const input = fixture(); input.asset.allowedIdentities = identities as typeof input.asset.allowedIdentities; refuses(seal(input));
  }
  const input = fixture(); input.asset.allowedIdentities = Array.from({length: 4096}, (_, index) => id(index + 1)); parsed(parseHumanAssetContext(seal(input)));
  input.asset.allowedIdentities.push(id(4097)); refuses(seal(input), 'limit');
});

test('nearest-first domain path accepts 33 entries and refuses a 34th without truncation', () => {
  const input = fixture(true);
  input.domainPath = Array.from({length: 33}, (_, index) => ({id: id(601 + index), version: v, parentId: index === 32 ? null : id(602 + index), typeId: id(650), typeVersion: v, status: 'active'}));
  assert.equal(parsed(parseHumanAssetContext(seal(input))).domainPath.length, 33);
  input.domainPath[32]!.parentId = id(634);
  input.domainPath.push({id: id(634), version: v, parentId: null, typeId: id(650), typeVersion: v, status: 'active'});
  refuses(seal(input), 'limit');
});

test('closed context refuses fabricated metrics, security revisions, decisions and extra nested fields', () => {
  for (const mutate of [
    (input: Mutable<HumanAssetContext>) => {Object.assign(input, {metrics: {nodes: 1}});},
    (input: Mutable<HumanAssetContext>) => {Object.assign(input, {decision: 'allow'});},
    (input: Mutable<HumanAssetContext>) => {Object.assign(input.asset, {securityRevision: '1'});},
    (input: Mutable<HumanAssetContext>) => {Object.assign(input.placement!, {tenantId: input.asset.tenantId});},
    (input: Mutable<HumanAssetContext>) => {Object.assign(input.domainPath[0]!, {classification: 'public'});},
    (input: Mutable<HumanAssetContext>) => {input.contentAuthority = true as false;},
  ]) {const input = fixture(true); mutate(input); refuses(seal(input));}
});

test('unavailable fact markers are exact and cannot silently become available or disappear', () => {
  for (const facts of [[], ['classification', 'approved-tags', 'environment', 'purpose'], ['classification', 'approved-tags', 'purpose', 'environment', 'extra'], [{classification: []}, 'approved-tags', 'purpose', 'environment']]) {
    const input = fixture(); input.unavailableFacts = facts as unknown as typeof input.unavailableFacts; refuses(seal(input));
  }
});

test('UUID, version and status scalars are strict across canonical content facts', () => {
  for (const mutate of [
    (input: Mutable<HumanAssetContext>) => {input.asset.version = 0 as Version;},
    (input: Mutable<HumanAssetContext>) => {input.placement!.version = 2147483648 as Version;},
    (input: Mutable<HumanAssetContext>) => {input.domainPath[0]!.typeVersion = -0 as Version;},
    (input: Mutable<HumanAssetContext>) => {input.domainPath[0]!.typeId = '00000000-0000-0000-0000-000000000000' as never;},
    (input: Mutable<HumanAssetContext>) => {input.domainPath[0]!.status = 'deleted' as never;},
    (input: Mutable<HumanAssetContext>) => {input.domainPath[0]!.status = 'unavailable' as never;},
    (input: Mutable<HumanAssetContext>) => {input.asset.status = 'deleted' as never;},
    (input: Mutable<HumanAssetContext>) => {input.asset.visibility = 'public' as never;},
  ]) {const input = fixture(true); mutate(input); refuses(seal(input));}
});

test('whole-envelope admission rejects shared byte, node and depth excess before nested parsing', () => {
  const half = {text: 'x'.repeat(4_200_000)};
  parsed(admitAuthorityInput(half));
  refuses({...fixture(), closure: half, registry: half}, 'limit');
  refuses({...fixture(), unavailableFacts: Array.from({length: limits.jsonNodes}, () => null)}, 'limit');
  let nested: unknown = null;
  for (let level = 0; level < limits.jsonDepth - 1; level++) nested = {child: nested};
  parsed(admitAuthorityInput(nested));
  refuses({...fixture(), closure: nested}, 'limit');
  const raw = JSON.stringify(fixture()); refuses(raw + ' '.repeat(limits.rawBytes - Buffer.byteLength(raw) + 1), 'limit');
});

test('raw context rejects duplicate decoded keys and malformed JSON before interpretation', () => {
  const text = JSON.stringify(fixture());
  refuses('{"formatVersion":1,' + text.slice(1), 'duplicate');
  refuses('{"formatVersion":1,"format\\u0056ersion":1,' + text.slice(1), 'duplicate');
  refuses(text + ' private');
});

test('hostile accessors, proxies, cycles and executable values are never invoked', () => {
  let touched = 0;
  const root = fixture();
  Object.defineProperty(root, 'asset', {enumerable: true, get() {touched++; throw Error('private');}});
  refuses(root);
  const nested = fixture(); Object.defineProperty(nested.asset, 'id', {enumerable: true, get() {touched++; throw Error('private');}}); refuses(nested);
  const proxy = new Proxy(fixture(), {ownKeys() {touched++; throw Error('private');}}); refuses(proxy);
  const nestedProxy = fixture(); nestedProxy.closure = new Proxy(nestedProxy.closure, {get() {touched++; throw Error('private');}}); refuses(nestedProxy);
  const cycle = fixture(); Object.assign(cycle.asset, {cycle}); refuses(cycle);
  const executable = fixture(); Object.assign(executable.asset, {toJSON() {touched++; throw Error('private');}}); refuses(executable);
  assert.equal(touched, 0);
});

test('context does not normalize away changed registry array ordering under an existing digest', () => {
  const input = fixture(); input.registry.actions.reverse(); refuses(seal(input));
});
