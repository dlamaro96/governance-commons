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
import {loadReviewedClassificationFacts,type ClassificationReadBudget} from '../../packages/authority-storage/src/reviewed-classification-facts.ts';
import {AuthorityFoundationError} from '../../packages/authority-storage/src/contracts.ts';
import {parseInactiveClassifiedAssetContext,type ReviewedClassificationProducerSnapshot} from '../../packages/authority-runtime/src/classified-asset-context.ts';
import {classificationDefinitionHash,evaluateMetadataClassification} from '../../packages/domain/src/classification.ts';

function producer(context=versionedFixture()):ReviewedClassificationProducerSnapshot{
 const s=context.context.closure.snapshot;return {formatVersion:1,tenantId:s.tenantId,generation:s.generation,authorityEpoch:s.authorityEpoch,registryId:s.registryId,registryVersion:s.registryVersion,registryDigest:s.registryDigest,asOf:s.asOf,
  binding:{installationId:id(701),version:v,operation:'bind',implementation:'reviewed-metadata-classification-v1',producer:{id:id(700),version:v},authorityEpochAfter:'1' as Counter,manifestHash:zero}};
}
// Detached synthetic storage rows exercise corruption paths unreachable through
// canonical writes. These tests are deliberately not database qualification.
function sourceProof(index=0):any{
 const tenant=id(1),actor=id(2),asset=id(3),reviewer=id(900),alternate=id(901),taxonomyId=id(1000+index),ruleId=id(2000+index),evaluationId=id(3000+index),assignmentId=id(4000+index),requestId=id(5000+index);
 const evaluated='2026-11-16T05:10:00.000Z',created='2026-11-16T05:20:00.000Z',decided='2026-11-16T05:21:00.000Z',published='2026-11-16T05:22:00.000Z',expires='2026-11-16T05:50:00.000Z';
 const taxonomy={formatVersion:1,name:'Synthetic taxonomy',description:'Synthetic proof',labels:[{key:'sensitive',name:'Sensitive metadata',description:'Synthetic label',status:'active'}]},taxonomyHash=classificationDefinitionHash(taxonomy);
 const rule={formatVersion:1,kind:'metadata-literal',name:'Synthetic rule',purpose:'Metadata match only',ownerId:actor,status:'active',assetTypes:['table'],label:{taxonomy:{id:taxonomyId,version:1,definitionHash:taxonomyHash},labelKey:'sensitive'},all:[{field:'name',operator:'contains',comparison:'exact',literal:'sensitive'}]},ruleHash=classificationDefinitionHash(rule);
 const assetInput={id:asset,version:1,type:'table',name:'sensitive records',qualifiedName:'synthetic.sensitive_records',dataType:null};
 const evaluatedResult=evaluateMetadataClassification(rule,{id:ruleId,version:1,definitionHash:ruleHash},assetInput,evaluated);assert.equal(evaluatedResult.ok,true);if(!evaluatedResult.ok)throw new Error('Synthetic evaluation refused');
 const evaluation=evaluatedResult.value,evidence=evaluation.evidence,evidenceHash=decisionHash(evidence);
 const workflow={formatVersion:1,id:'classification_review',version:1,name:'Independent review',separationOfDuties:true,stages:[{id:'review',name:'Review',assignments:['alternate','reviewer'],quorum:1,deadlineSeconds:1800,rejection:'any'}]},workflowHash=decisionHash(workflow);
 const payload={formatVersion:1,kind:'classification-review',change:'apply',assetId:asset,assignmentId,expectedAssignmentVersion:0,suggestionId:evaluationId,label:rule.label,evidence,evidenceHash,reason:''};
 const proof={
  assignment:{tenant_id:tenant,id:assignmentId,asset_id:asset,taxonomy_id:taxonomyId,label_key:'sensitive',version:1,status:'active',created_by:actor,created_at:published},
  revision:{tenant_id:tenant,assignment_id:assignmentId,version:1,status:'active',suggestion_id:evaluationId,approval_request_id:requestId,reason:null,actor_id:actor,created_at:published},
  evaluation:{tenant_id:tenant,id:evaluationId,asset_id:asset,asset_version:1,rule_id:ruleId,rule_version:1,rule_hash:ruleHash,...evaluation,evidence_hash:evidenceHash,created_by:actor,created_at:evaluated},
  rule:{tenant_id:tenant,rule_id:ruleId,version:1,definition:rule,definition_hash:ruleHash,taxonomy_id:taxonomyId,taxonomy_version:1,taxonomy_hash:taxonomyHash,owner_id:actor,created_by:actor,created_at:evaluated},
  taxonomy:{tenant_id:tenant,taxonomy_id:taxonomyId,version:1,definition:taxonomy,definition_hash:taxonomyHash,created_by:actor,created_at:evaluated},
  ruleHead:{tenant_id:tenant,id:ruleId,current_version:1},taxonomyHead:{tenant_id:tenant,id:taxonomyId,current_version:1},
  baseline:{tenant_id:tenant,taxonomy_id:taxonomyId,baseline_version:1,baseline_hash:taxonomyHash},
  identity:{tenant_id:tenant,id:id(6000+index),taxonomy_id:taxonomyId,label_key:'sensitive',first_registered_version:1,retired_at_version:null},
  labelBinding:{tenant_id:tenant,taxonomy_id:taxonomyId,taxonomy_version:1,label_key:'sensitive',label_id:id(6000+index),label_status:'active'},
  request:{tenant_id:tenant,id:requestId,binding:'classification.review',resource_id:asset,resource_version:1,payload,proposal_digest:zero,workflow_id:workflow.id,workflow_version:1,workflow_hash:workflowHash,requester_id:actor,stage_index:0,version:4,status:'succeeded',result:{binding:'classification.review',assetId:asset,assignmentId,assignmentVersion:1,status:'active',evidenceHash},error_code:null,expires_at:expires,created_at:created,updated_at:published},
  workflow:{tenant_id:tenant,workflow_id:workflow.id,version:1,definition:workflow,definition_hash:workflowHash},
  tasks:[{tenant_id:tenant,id:id(7000+index*2),request_id:requestId,stage_index:0,assignment:'reviewer',assigned_identity_id:reviewer,version:2,status:'decided',opened_at:created,expires_at:expires},{tenant_id:tenant,id:id(7001+index*2),request_id:requestId,stage_index:0,assignment:'alternate',assigned_identity_id:alternate,version:2,status:'cancelled',opened_at:created,expires_at:expires}],
  decisions:[{tenant_id:tenant,id:id(8000+index),request_id:requestId,task_id:id(7000+index*2),task_version:1,proposal_digest:zero,actor_id:reviewer,decision:'approve',reason:'Reviewed synthetic metadata',decided_at:decided}],
  historicalInput:assetInput,currentInput:structuredClone(assetInput)};
 sealProof(proof);return structuredClone(proof);
}
function sealProof(p:any){
 const assignments=Object.fromEntries(p.tasks.map((t:any)=>[t.assignment,t.assigned_identity_id]));
 p.request.proposal_digest=decisionHash({id:p.request.id,binding:p.request.binding,payload:p.request.payload,workflow:{id:p.request.workflow_id,version:p.request.workflow_version,definitionHash:p.request.workflow_hash},assignments,expiresAt:p.request.expires_at});
 for(const d of p.decisions)d.proposal_digest=p.request.proposal_digest;
}
function withdrawn(p=sourceProof()){
 p.assignment.version=p.revision.version=p.request.result.assignmentVersion=2;p.assignment.status=p.revision.status=p.request.result.status='withdrawn';p.revision.reason=p.request.payload.reason='Withdraw synthetic label';p.request.payload.change='withdraw';p.request.payload.expectedAssignmentVersion=1;sealProof(p);return p;
}
function harness(proofs:any[]=[],context=versionedFixture(),snapshot=producer(context)){
 const calls:string[]=[],charged:unknown[]=[];let checkCount=0;
 const budget:ClassificationReadBudget={check(){checkCount++;},admitSource(value){charged.push(value);parsed(admitAuthorityInput({context,producerSnapshot:snapshot,sourceProof:value}));}};
 const counts={assignments:String(proofs.length),tasks:String(proofs.reduce((n,p)=>n+p.tasks.length,0)),max_tasks:String(Math.max(0,...proofs.map(p=>p.tasks.length))),decisions:String(proofs.reduce((n,p)=>n+p.decisions.length,0)),max_decisions:String(Math.max(0,...proofs.map(p=>p.decisions.length)))};
 const measure={assignments:String(proofs.length),canonical_bytes:String(proofs.reduce((n,p)=>n+bytes(p),0)),raw_bytes:String(proofs.reduce((n,p)=>n+bytes(p),0)),component_bounds:true,dependencies_complete:true};
 const query=async(text:string,values?:unknown[])=>{calls.push(text);assert.deepEqual(values,[id(1),id(3)]);if(text.includes(':counts'))return {rows:[counts]};if(text.includes(':measure'))return {rows:[measure]};assert.ok(text.includes(':bodies'));return {rows:proofs.map(proof=>({proof}))};};
 return {calls,charged,budget,counts,measure,context,snapshot,checks:()=>checkCount,run:()=>loadReviewedClassificationFacts({query,context:context as unknown as VersionedHumanAssetContext,producerSnapshot:snapshot,budget})};
}
const refusesFact=async(h:ReturnType<typeof harness>,code='AUTHORITY_FOUNDATION_INTEGRITY')=>assert.rejects(h.run(),(e:unknown)=>e instanceof AuthorityFoundationError&&e.code===code);
test('reviewed facts emit exact real assignment refs, installed producer and stable label UUID',async()=>{
 const p=sourceProof(),h=harness([p]),out=await h.run();assert.equal(h.charged.length,1);assert.equal(h.calls.length,3);assert.ok(h.checks()>10);
 assert.deepEqual(out.classifications,{status:'known',value:[{id:p.assignment.id,version:1}]});const f=out.approvedFacts[0]!;
 assert.deepEqual(f.values,[p.identity.id]);assert.equal(f.securityRevision,'7');assert.equal(f.provenance.sourceRecordId,p.assignment.id);assert.equal(f.provenance.sourceRecordVersion,1);assert.deepEqual(f.provenance.producer,h.snapshot.binding!.producer);
 const wrapped={formatVersion:1,kind:'inactive-classified-asset-context',contentAuthority:false,context:h.context,...out,contextDigest:zero};wrapped.contextDigest=decisionHash(wrapped);parsed(parseInactiveClassifiedAssetContext(wrapped));
});
test('complete empty discovery with an available explicit producer is known empty',async()=>{
 const h=harness(),out=await h.run();assert.deepEqual(out.classifications,{status:'known',value:[]});assert.deepEqual(out.approvedFacts,[]);assert.equal(h.calls.length,1);assert.deepEqual(h.charged,[[]]);
});
test('missing or revoked installation is unavailable even when no assignments exist',async()=>{
 for(const revoke of [false,true]){const h=harness();if(revoke)(h.snapshot.binding as any).operation='revoke';else (h.snapshot as any).binding=null;assert.deepEqual((await h.run()).classifications,{status:'unavailable'});assert.equal(h.calls.length,0);assert.deepEqual(h.charged,[[]]);}
});
test('inactive, expired and future producer availability is checked even for an empty partition',async()=>{
 for(const mode of ['retired','expired','future']){
  const context=versionedFixture(),inner=context.context,registration=inner.registry.producers[0]!;
  if(mode==='retired')registration.state='retired';else if(mode==='expired')registration.validity.expiresAt=now;else registration.validity.notBefore='2026-11-16T06:01:00.000Z' as UTC;
  const {digest:oldDigest,...content}=inner.registry;inner.registry.digest=decisionHash(decisionShapes.registryContent(content,''));inner.closure.snapshot.registryDigest=inner.registry.digest;sealClosure(inner.closure);seal(inner);context.contextDigest=decisionHash({...context,contextDigest:zero});
  const h=harness([],context);assert.deepEqual((await h.run()).classifications,{status:'unavailable'});assert.equal(h.calls.length,0);assert.deepEqual(h.charged,[[]]);
 }
});
test('exact producer snapshot tuple mismatch fails before canonical discovery',async()=>{
 for(const field of ['tenantId','registryId','registryDigest','asOf','generation','authorityEpoch']){const h=harness();(h.snapshot as any)[field]=field.endsWith('Id')?id(888):field==='registryDigest'?zero:field==='asOf'?'2026-11-16T06:00:01.000Z':'2';await refusesFact(h);assert.equal(h.calls.length,0);}
});
test('valid reviewed withdrawal yields known empty without a current label mapping',async()=>{
 const p=withdrawn();p.ruleHead.current_version=2;p.taxonomyHead.current_version=2;p.identity=null;p.labelBinding=null;p.baseline=null;const h=harness([p]);assert.deepEqual((await h.run()).classifications,{status:'known',value:[]});
});
test('stale active source makes the entire partition unavailable with no surviving subset',async()=>{
 for(const mutate of [(p:any)=>{p.ruleHead.current_version=2;},(p:any)=>{p.taxonomyHead.current_version=2;},(p:any)=>{p.identity.retired_at_version=2;p.taxonomyHead.current_version=2;},(p:any)=>{p.currentInput.name='changed selected metadata';}]){
  const proofs=[sourceProof(),sourceProof(1)];mutate(proofs[1]);const out=await harness(proofs).run();assert.deepEqual(out.classifications,{status:'unavailable'});assert.deepEqual(out.approvedFacts,[]);
 }
});
test('legacy pre-baseline pin is unavailable, while missing current mapping is integrity failure',async()=>{
 const p=sourceProof();p.taxonomyHead.current_version=2;p.baseline.baseline_version=2;p.identity=null;p.labelBinding=null;assert.deepEqual((await harness([p]).run()).classifications,{status:'unavailable'});
 for(const field of ['baseline','identity','labelBinding']){const source=sourceProof();source[field]=null;await refusesFact(harness([source]));}
});
test('description-only asset revision retains selected input and binds current requested revision',async()=>{
 const context=versionedFixture();context.context.asset.version=2 as Version;context.context.closure.selectors[0]!.revision=2 as Version;context.context.closure.partitions[0]!.request.revision=2 as Version;context.context.closure.partitions[0]!.key=decisionHash({formatVersion:1,subject:context.context.closure.partitions[0]!.subject,request:context.context.closure.partitions[0]!.request});sealClosure(context.context.closure);seal(context.context);context.contextDigest=decisionHash({...context,contextDigest:zero});
 const p=sourceProof();p.currentInput.version=2;const result=await harness([p],context).run();assert.equal(result.approvedFacts[0]!.revision,2);
});
test('complete count/aggregate/per-request limits fail before body retrieval',async()=>{
 for(const [field,value]of [['assignments','257'],['tasks','4097'],['decisions','4097'],['max_tasks','257'],['max_decisions','257']]){const h=harness();(h.counts as any)[field!]=value;await refusesFact(h,'AUTHORITY_FOUNDATION_PROFILE_LIMIT');assert.equal(h.calls.length,1);assert.equal(h.charged.length,0);}
});
test('byte/component preflight and missing dependencies refuse before body retrieval',async()=>{
 for(const [field,value,code]of [['canonical_bytes','2097152','AUTHORITY_FOUNDATION_PROFILE_LIMIT'],['raw_bytes','2097152','AUTHORITY_FOUNDATION_PROFILE_LIMIT'],['component_bounds',false,'AUTHORITY_FOUNDATION_PROFILE_LIMIT'],['dependencies_complete',false,'AUTHORITY_FOUNDATION_INTEGRITY']]){const h=harness([sourceProof()]);(h.measure as any)[field as string]=value;await refusesFact(h,code as string);assert.equal(h.calls.length,2);}
});
test('source body count and byte claims must equal the measured inventory',async()=>{
 const h=harness([sourceProof()]);h.measure.canonical_bytes=String(Number(h.measure.canonical_bytes)-1);await refusesFact(h);assert.equal(h.charged.length,0);
});
test('shared physical budget refusal and absolute deadline propagate without retries',async()=>{
 const h=harness([sourceProof()]);h.budget.admitSource=()=>{throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_PROFILE_LIMIT');};await refusesFact(h,'AUTHORITY_FOUNDATION_PROFILE_LIMIT');assert.equal(h.calls.length,3);
 const expired=harness([sourceProof()]);expired.budget.check=()=>{throw new AuthorityFoundationError('AUTHORITY_FOUNDATION_DEADLINE');};await refusesFact(expired,'AUTHORITY_FOUNDATION_DEADLINE');assert.equal(expired.calls.length,0);
});
function multiStageProof(){
 const p=sourceProof(),stage={id:'second',name:'Second review',assignments:['alternate','reviewer'],quorum:1,deadlineSeconds:600,rejection:'any'};
 p.workflow.definition.stages.push(stage);p.workflow.definition_hash=decisionHash(p.workflow.definition);p.request.workflow_hash=p.workflow.definition_hash;
 p.request.stage_index=1;p.request.version=6;p.request.expires_at='2026-11-16T06:30:00.000Z';p.request.updated_at=p.revision.created_at=p.assignment.created_at='2026-11-16T05:40:00.000Z';
 for(const [i,t]of p.tasks.slice().entries())p.tasks.push({...t,id:id(9001+i),stage_index:1,version:3,opened_at:'2026-11-16T05:23:00.000Z',expires_at:'2026-11-16T05:33:00.000Z'});
 p.decisions.push({...p.decisions[0],id:id(9003),task_id:id(9001),task_version:2,decided_at:'2026-11-16T05:24:00.000Z'});sealProof(p);return p;
}
test('multistage quorum permits cancelled unanswered tasks and publication after final task deadline',async()=>{
 const out=await harness([multiStageProof()]).run();assert.equal(out.approvedFacts.length,1);assert.equal(out.approvedFacts[0]!.validity.notBefore,'2026-11-16T05:40:00.000Z');
});
test('multistage proof refuses wrong opening order, open-task version, quorum or global assignment mapping',async()=>{
 for(const mutate of [(p:any)=>{p.tasks[2].opened_at='2026-11-16T05:20:30.000Z';},(p:any)=>{p.tasks[2].version=2;},(p:any)=>{p.decisions.pop();},(p:any)=>{p.tasks[3].assigned_identity_id=id(999);}]){const p=multiStageProof();mutate(p);await refusesFact(harness([p]));}
});
test('256 complete reviewed withdrawals are discovered and validated without truncation',async()=>{
 const proofs=Array.from({length:256},(_,i)=>{const p=withdrawn(sourceProof(i));p.baseline=p.identity=p.labelBinding=null;p.tasks.pop();p.workflow.definition.stages[0].assignments=['reviewer'];p.workflow.definition_hash=decisionHash(p.workflow.definition);p.request.workflow_hash=p.workflow.definition_hash;sealProof(p);return p;});
 const h=harness(proofs);assert.ok(Number(h.measure.canonical_bytes)+257<=2097152,'Boundary fixture must fit the independent byte profile: '+h.measure.canonical_bytes);const out=await h.run();assert.deepEqual(out.classifications,{status:'known',value:[]});assert.equal((h.charged[0] as unknown[]).length,256);assert.equal(h.charged.length,1);assert.equal(h.calls.length,3);
});
test('missing exact producer registration is integrity failure before empty discovery',async()=>{
 const h=harness();(h.snapshot.binding!.producer as any).id=id(777);await refusesFact(h);assert.equal(h.calls.length,0);
});
test('snapshot authority epoch may advance beyond the retained producer installation epoch',async()=>{
 const context=versionedFixture();context.context.closure.snapshot.authorityEpoch='2' as Counter;sealClosure(context.context.closure);seal(context.context);context.contextDigest=decisionHash({...context,contextDigest:zero});
 assert.deepEqual((await harness([],context).run()).classifications,{status:'known',value:[]});
});
for(const [name,mutate] of [
 ['foreign tenant',(p:any)=>{p.revision.tenant_id=id(999);}],['wrong source ref',(p:any)=>{p.revision.suggestion_id=id(999);}],['different evidence',(p:any)=>{p.evaluation.evidence.matches[0].value='forged';}],
 ['wrong historical input',(p:any)=>{p.historicalInput.name='forged';}],['wrong workflow hash',(p:any)=>{p.workflow.definition_hash=zero;}],['pending approval',(p:any)=>{p.request.status='pending';}],
 ['wrong publisher',(p:any)=>{p.request.requester_id=id(999);}],['wrong publication version',(p:any)=>{p.request.result.assignmentVersion=3;}],['after request expiry',(p:any)=>{p.request.expires_at=p.request.updated_at;}],
 ['missing task',(p:any)=>{p.tasks.pop();}],['wrong decision task version',(p:any)=>{p.decisions[0].task_version=2;}],['self approval',(p:any)=>{p.decisions[0].actor_id=p.request.requester_id;}],
 ['decision on cancelled task',(p:any)=>{p.tasks[0].status='cancelled';}],['rejection',(p:any)=>{p.decisions[0].decision='reject';}],['decision after deadline',(p:any)=>{p.decisions[0].decided_at=p.tasks[0].expires_at;}],
 ['wrong stage opening',(p:any)=>{p.tasks[1].opened_at='2026-11-16T05:20:01.000Z';}],['wrong proposal digest',(p:any)=>{p.request.proposal_digest=zero;}],['duplicate identity keys',(p:any)=>{p.tasks[1].assigned_identity_id=p.tasks[0].assigned_identity_id;sealProof(p);}],
 ['unknown proof field',(p:any)=>{p.untrusted=true;}],['duplicate decision',(p:any)=>{p.decisions.push({...p.decisions[0],id:id(9999)});}]
 ] as const)test('reviewed proof rejects '+name,async()=>{const p=sourceProof();mutate(p);await refusesFact(harness([p]));});

// Synthetic repository protocol evidence only: no PostgreSQL cancellation is
// claimed here. Raw driver errors must cross the private reader boundary as
// fixed foundation errors before the fact validator handles malformed proofs.
import {createAuthorityFoundationRepository} from '../../packages/authority-storage/src/repository.ts';
import type {NativeOwnerPool} from '../../packages/authority-storage/src/contracts.ts';
import type {Digest} from '../../packages/authority/src/types.ts';
test('classified repository preserves raw statement and lock cancellations at every proof query phase and destroys the failed connection',async()=>{
 for(const code of ['57014','55P03'])for(const phase of ['counts','measure','bodies']){
  const context=versionedFixture(),inner=context.context,p=sourceProof(),calls:string[]=[],releases:boolean[]=[];
  const registryText=canonical(inner.registry),registryMetrics=parsed(admitAuthorityInput(inner.registry)).metrics;
  const pool:NativeOwnerPool={async connect(){return {async query(text,values){
   calls.push(text);
   if(text.includes('reviewed-classification:'+phase))throw Object.assign(new Error('PRIVATE_SQL_AND_PARAMETERS'),{code,detail:'PRIVATE_SOURCE_ROW'});
   if(text.includes(' AS native_owner'))return {rows:[{native_owner:true}]};
   if(text.includes('FROM gc_authn.foundation_session_v1'))return {rows:[{session:inner.closure.session}]};
   if(text.includes("current_setting('gc.tenant_id',true) AS tenant"))return {rows:[{tenant:id(990),actor:id(991)}]};
   if(text.includes(' AS acl_type'))return {rows:[{version:inner.asset.version,status_valid:true,visibility_valid:true,acl_type:'array',acl_bytes:'2',acl_count:'0'}]};
   if(text.includes('allowed_identities AS "allowedIdentities"'))return {rows:[inner.asset]};
   if(text.includes('FROM public.asset_domain_placements'))return {rows:[inner.placement]};
   if(text.includes('FROM public.domains'))return {rows:[inner.domainPath.find(domain=>domain.id===values?.[1])]};
   if(text.includes('FROM public.domain_scope_state'))return {rows:[{epoch:inner.domainEpoch}]};
   if(text.includes('FROM gc_authority.content_security_heads'))return {rows:[{revision:context.securityRevision}]};
   if(text.includes(' AS closure'))return {rows:[{closure:inner.closure}]};
   if(text.startsWith('SELECT octet_length(registry_document)'))return {rows:[{raw_bytes:String(Buffer.byteLength(registryText)),canonical_bytes:String(registryMetrics.canonicalBytes),json_nodes:String(registryMetrics.nodes)}]};
   if(text.startsWith('SELECT registry_document'))return {rows:[{registry_document:registryText}]};
   if(text.includes('load_reviewed_classification_producer_v1'))return {rows:[{producer:producer(context)}]};
   if(text.includes('reviewed-classification:counts'))return {rows:[{assignments:'1',tasks:'2',max_tasks:'2',decisions:'1',max_decisions:'1'}]};
   if(text.includes('reviewed-classification:measure'))return {rows:[{assignments:'1',canonical_bytes:String(bytes(p)),raw_bytes:String(bytes(p)),dependencies_complete:true,component_bounds:true}]};
   if(text.includes('reviewed-classification:bodies'))return {rows:[{proof:p}]};
   assert.ok(text.startsWith('SET ')||text.startsWith('BEGIN ')||text.startsWith('SELECT set_config(')||text==='ROLLBACK'||text==='COMMIT','Unexpected synthetic repository query');return {rows:[]};
  },release(destroy){releases.push(destroy??false);}};}};
  await assert.rejects(createAuthorityFoundationRepository(pool).loadClassifiedHumanAssetContext({sessionHash:'a'.repeat(64) as Digest,assetId:inner.asset.id,expectedVersion:inner.asset.version}),error=>{
   assert.ok(error instanceof AuthorityFoundationError);assert.equal(error.code,'AUTHORITY_FOUNDATION_DEADLINE');assert.equal(error.message,'AUTHORITY_FOUNDATION_DEADLINE');assert.equal(String(error).includes('PRIVATE_'),false);return true;
  });
  assert.equal(calls.filter(text=>text.includes('reviewed-classification:'+phase)).length,1);
  assert.equal(calls.filter(text=>text==='ROLLBACK').length,1);assert.equal(calls.at(-1),'ROLLBACK');assert.equal(calls.includes('COMMIT'),false);assert.deepEqual(releases,[true]);
 }
});
