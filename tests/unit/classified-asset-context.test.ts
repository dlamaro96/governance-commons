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
import { parseVersionedHumanAssetContext, type VersionedHumanAssetContext } from '../../packages/authority-runtime/src/versioned-asset-context.ts';
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
  rawRegistry.producers=[{ref:{id:id(700),version:v},kind:'classifications',tenantId:id(1),state:'active',validity:{notBefore:null,expiresAt:null}}];
  const {digest: ignoredDigest,...registryContent}=rawRegistry;rawRegistry.digest=decisionHash(decisionShapes.registryContent(registryContent,''));
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

function versionedFixture(): Mutable<VersionedHumanAssetContext> {
  const value: Mutable<VersionedHumanAssetContext> = {formatVersion: 1, kind: 'inactive-versioned-asset-context',
    contentAuthority: false, context: fixture(true), securityRevision: '7' as Counter, contextDigest: zero};
  value.contextDigest = decisionHash({...value, contextDigest: zero});
  return value;
}
import {parseInactiveClassifiedAssetContext,parseReviewedClassificationProducerSnapshot,type InactiveClassifiedAssetContext,type ReviewedClassificationProducerBinding} from '../../packages/authority-runtime/src/classified-asset-context.ts';
const producerBinding=():ReviewedClassificationProducerBinding=>({installationId:id(701),version:v,operation:'bind',implementation:'reviewed-metadata-classification-v1',producer:{id:id(700),version:v},authorityEpochAfter:'1' as Counter,manifestHash:zero});
function classified(populated=false):Mutable<InactiveClassifiedAssetContext>{
 const context=versionedFixture(),binding=producerBinding();
 const facts=populated?[{ref:{id:id(800),version:v},kind:'classifications' as const,provenance:{producer:binding.producer,tenantId:id(1),registryDigest:context.context.registry.digest,sourceRecordId:id(800),sourceRecordVersion:v},resource:{tenantId:id(1),kind:'asset' as const,id:id(3)},revision:v,fieldId:null,securityRevision:'7' as Counter,state:'approved' as const,validity:{notBefore:'2026-11-16T05:30:00.000Z' as UTC,expiresAt:null},values:[id(801)]}]:[];
 const out:Mutable<InactiveClassifiedAssetContext>={formatVersion:1,kind:'inactive-classified-asset-context',contentAuthority:false,context,producerBinding:structuredClone(binding),classifications:{status:'known',value:facts.map(f=>f.ref)},approvedFacts:facts,contextDigest:zero};return reseal(out);
}
function reseal(value:Mutable<InactiveClassifiedAssetContext>){value.contextDigest=decisionHash({...value,contextDigest:zero});return value;}
function rejected(value:unknown){const result=parseInactiveClassifiedAssetContext(value);assert.equal(result.ok,false);return result;}
test('classified inactive envelope admits exact installed producer for both populated and empty partitions',()=>{
 for(const populated of [false,true]){const value=classified(populated),result=parsed(parseInactiveClassifiedAssetContext(JSON.stringify(value)));assert.equal(result.contentAuthority,false);assert.deepEqual(result.classifications,value.classifications);assert.ok(Object.isFrozen(result));}
});
test('unavailable classification is explicit and cannot expose partial approved facts',()=>{
 const value=classified();value.producerBinding=null;value.classifications={status:'unavailable'};parsed(parseInactiveClassifiedAssetContext(reseal(value)));
 value.approvedFacts=classified(true).approvedFacts;rejected(reseal(value));
});
test('known empty cannot bypass missing, revoked, future-epoch or wrong producer installation',()=>{
 for(const mutate of [(x:Mutable<InactiveClassifiedAssetContext>)=>{x.producerBinding=null;},(x:Mutable<InactiveClassifiedAssetContext>)=>{x.producerBinding!.operation='revoke';},(x:Mutable<InactiveClassifiedAssetContext>)=>{x.producerBinding!.authorityEpochAfter='2' as Counter;},(x:Mutable<InactiveClassifiedAssetContext>)=>{x.producerBinding!.producer.id=id(999);}]){const value=classified();mutate(value);rejected(reseal(value));}
});
test('known empty also requires producer active state and current validity',()=>{
 for(const mode of ['retired','expired','future']){
  const value=classified(),inner=value.context.context,registration=inner.registry.producers[0]!;
  if(mode==='retired')registration.state='retired';else if(mode==='expired')registration.validity.expiresAt=now;else registration.validity.notBefore='2026-11-16T06:01:00.000Z' as UTC;
  const {digest:oldDigest,...content}=inner.registry;inner.registry.digest=decisionHash(decisionShapes.registryContent(content,''));inner.closure.snapshot.registryDigest=inner.registry.digest;sealClosure(inner.closure);seal(inner);value.context.contextDigest=decisionHash({...value.context,contextDigest:zero});
  rejected(reseal(value));value.classifications={status:'unavailable'};parsed(parseInactiveClassifiedAssetContext(reseal(value)));
 }
});
test('outer producer manifest and every nested digest remain bound',()=>{
 const value=classified();value.producerBinding!.manifestHash='a'.repeat(64) as typeof zero;rejected(value);parsed(parseInactiveClassifiedAssetContext(reseal(value)));
 value.context.contextDigest='b'.repeat(64) as typeof zero;rejected(reseal(value));
});
test('fact provenance, target, current revision and security revision must match exactly',()=>{
 const mutations=[(f:any)=>{f.provenance.tenantId=id(90);},(f:any)=>{f.resource.id=id(90);},(f:any)=>{f.revision=2;},(f:any)=>{f.securityRevision='8';},(f:any)=>{f.fieldId='private';},(f:any)=>{f.provenance.sourceRecordVersion=2;},(f:any)=>{f.provenance.producer.id=id(999);},(f:any)=>{f.provenance.registryDigest=zero;}];
 for(const mutate of mutations){const value=classified(true);mutate(value.approvedFacts[0]);rejected(reseal(value));}
});
test('facts require exact partition coverage, one real label and nonfuture approved publication',()=>{
 for(const mutate of [(x:any)=>{x.classifications.value=[];},(x:any)=>{x.approvedFacts[0].values=[];},(x:any)=>{x.approvedFacts[0].values.push(id(802));},(x:any)=>{x.approvedFacts[0].validity.notBefore='2026-11-16T06:01:00.000Z';},(x:any)=>{x.approvedFacts[0].validity.expiresAt=now;},(x:any)=>{x.approvedFacts[0].state='withdrawn';}]){const value=classified(true);mutate(value);rejected(reseal(value));}
});
test('classified parser rejects unknown fields, accessors and executable proxies before reading them',()=>{
 const value=classified();rejected({...value,producerId:id(700)});let called=false;
 const hostile={...value};Object.defineProperty(hostile,'context',{enumerable:true,get(){called=true;return value.context;}});rejected(hostile);assert.equal(called,false);
 rejected(new Proxy(value,{ownKeys(){called=true;return [];}}));assert.equal(called,false);
});
test('classified wrapper enforces the whole physical budget before nested parser work',()=>{
 const value=classified();rejected({...value,unknown:'x'.repeat(limits.rawBytes)});let nested:any=[];for(let n=0;n<34;n++)nested=[nested];rejected({...value,approvedFacts:nested});
});
test('producer snapshot is closed and binds positive decimal epochs and exact timestamps',()=>{
 const c=classified(),s=c.context.context.closure.snapshot,base={formatVersion:1,tenantId:s.tenantId,generation:s.generation,authorityEpoch:s.authorityEpoch,registryId:s.registryId,registryVersion:s.registryVersion,registryDigest:s.registryDigest,asOf:s.asOf,binding:c.producerBinding};
 parsed(parseReviewedClassificationProducerSnapshot(base));
 for(const bad of [{...base,authorityEpoch:1},{...base,asOf:'2026-11-16T06:00:00Z'},{...base,extra:true},{...base,binding:{...base.binding,authorityEpochAfter:'2'}}])assert.equal(parseReviewedClassificationProducerSnapshot(bad).ok,false);
});
