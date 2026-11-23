// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {admitAuthorityInput} from '../../../packages/authority/src/admission.ts';
import {canonicalDecisionJSON as canonical,decisionHash,decisionShapes} from '../../../packages/authority/src/decision-schema.ts';
import {definitionKey,grantKey,policyKey,subjectKey,versionKey} from '../../../packages/authority/src/decision-types.ts';
import {parsePolicyFile} from '../../../packages/authority/src/policy.ts';
import type {PolicyExpr,UTC,Version,Digest,Counter} from '../../../packages/authority/src/types.ts';
import type {AuthorityHumanClosure,NativeOwnerConnection,NativeOwnerPool} from '../../../packages/authority-storage/src/contracts.ts';
import {parseAuthorityHumanClosure,parseClosureSelectors} from '../../../packages/authority-storage/src/loader.ts';
import {makeDecisionFixture,id,v,now,zero,parsed,type Mutable} from './authority-decision.ts';
import {makeFourEdgeFieldFixture} from './authority-decision-chain.ts';
const bytes=(x:unknown)=>Buffer.byteLength(canonical(x));
const sort=<T>(rows:T[],key:(x:T)=>string)=>rows.sort((a,b)=>key(a)<key(b)?-1:key(a)>key(b)?1:0);
const nodes=(e:PolicyExpr):number=>1+('children'in e?e.children.reduce((n,c)=>n+nodes(c),0):0);
/** Synthetic complete graph DTO for parser tests only; never a database/session assertion. */
export function closureFixture(source=makeDecisionFixture()){
 const {bundle:b,registry:rawRegistry}=structuredClone(source);
 for(const adapter of rawRegistry.adapters)adapter.ceilings=[{slot:'canonical-visibility',kind:'visibility'}];
 rawRegistry.producers=[{ref:{id:id(700),version:v},kind:'classifications',tenantId:id(1),state:'active',validity:{notBefore:null,expiresAt:null}}];
 const {digest:oldDigest,...registryContent}=rawRegistry;rawRegistry.digest=decisionHash(decisionShapes.registryContent(registryContent,''));
 for(const policy of b.policies)for(const mark of policy.resourceWideIntents){mark.registryVersion=rawRegistry.version;mark.registryDigest=rawRegistry.digest;}

 const registry=structuredClone(decisionShapes.registry(rawRegistry,'')) as typeof rawRegistry;
 const session=b.sessions[0]!,req=b.nodes.find(n=>n.subject.id===session.identityId&&n.mode==='authorize')!.request;
 const chosen=b.nodes.filter(n=>n.mode==='authorize');
 const partitions=chosen.map(n=>({key:decisionHash({formatVersion:1,subject:n.subject,request:n.request}),subject:n.subject,request:n.request,candidates:b.candidates.find(c=>c.nodeId===n.id)!.candidates}));
 const nodeKey=new Map(chosen.map((n,i)=>[n.id,partitions[i]!.key]));
 const parentMap=new Map(b.chainLinks.map(x=>[grantKey(x.child),{child:x.child,parent:x.parent,viaMembership:x.viaMembership}]));
 const dependencies=b.chainLinks.filter(x=>nodeKey.has(x.nodeId)).map(x=>({from:nodeKey.get(x.nodeId)!,issuer:nodeKey.get(x.issuerDecision)!,child:x.child}));
 const c:Mutable<AuthorityHumanClosure>={formatVersion:1,kind:'inactive-human-candidate-closure',contentAuthority:false,
  session:{formatVersion:1,sessionId:session.id,sessionVersion:v,identityId:session.identityId,tenantId:session.selectedTenantId,generation:'1' as Counter,authnFenceEpoch:'1' as Counter,issuingRegistrationId:id(501),issuerRegistrationId:id(502),identityBindingId:id(503),authenticatedAt:'2026-11-16T05:00:00.000Z' as UTC,issuedAt:'2026-11-16T05:01:00.000Z' as UTC,expiresAt:'2026-11-16T07:00:00.000Z' as UTC},
  snapshot:{tenantId:session.selectedTenantId,generation:'1' as Counter,authorityEpoch:'1' as Counter,registryId:id(500),registryVersion:v,registryDigest:registry.digest,asOf:now,identityRevisionDigest:zero,closureDigest:zero},
  selectors:[req],partitions:[...new Map(partitions.map(p=>[p.key,p])).values()] as Mutable<AuthorityHumanClosure>['partitions'],parents:[...parentMap.values()],dependencies:[...new Map(dependencies.map(d=>[`${d.from}:${d.issuer}:${grantKey(d.child)}`,d])).values()],
  principals:b.principals as Mutable<AuthorityHumanClosure>['principals'],groups:b.groups,memberships:b.memberships,principalGroups:b.principalGroups,definitions:b.definitions,policies:b.policies,grants:b.grants as Mutable<AuthorityHumanClosure>['grants'],elevationUses:[],lifecycleHeads:[],metrics:{} as never};
 for(const d of c.definitions)c.lifecycleHeads.push({family:'definition',id:d.id,definitionKind:d.kind,headVersion:v});
 for(const p of c.policies)c.lifecycleHeads.push({family:'definition',id:p.pin.policyId,definitionKind:'policy',headVersion:v});
 for(const g of c.grants)c.lifecycleHeads.push({family:'grant',id:g.ref.id,definitionKind:null,headVersion:v});
 return {closure:sealClosure(c),registry};
}
export function sealClosure(c:Mutable<AuthorityHumanClosure>){
 sort(c.selectors,canonical);sort(c.partitions,x=>x.key);c.partitions.forEach(p=>sort(p.candidates,grantKey));sort(c.parents,x=>grantKey(x.child));sort(c.dependencies,x=>`${x.from}:${x.issuer}:${grantKey(x.child)}`);
 sort(c.principals,subjectKey);sort(c.groups,x=>x.id);sort(c.memberships,x=>versionKey(x.ref));sort(c.principalGroups,x=>subjectKey(x.subject));c.principalGroups.forEach(g=>{if(g.memberships.status==='known')sort(g.memberships.value,versionKey);});
 sort(c.definitions,x=>definitionKey(x.kind,x.id,x.version));sort(c.policies,x=>policyKey(x.pin));sort(c.grants,x=>grantKey(x.ref));sort(c.elevationUses,x=>versionKey(x.ref));sort(c.lifecycleHeads,h=>`${h.family}:${h.definitionKind??''}:${h.id}`);
 const docs=c.policies.map(p=>parsed(parsePolicyFile(p.document,[]))),depth=(key:string,seen=new Set<string>()):number=>{if(seen.has(key))return 17;const next=new Set([...seen,key]);return 1+Math.max(0,...c.dependencies.filter(d=>d.from===key).map(d=>depth(d.issuer,next)));};
 c.metrics={selectors:c.selectors.length,partitions:c.partitions.length,dependencyEdges:new Set(c.dependencies.map(d=>`${d.from}:${d.issuer}`)).size,dependencyReferences:c.dependencies.length,dependencyDepth:Math.max(...c.partitions.map(p=>depth(p.key))),canonicalBytes:0,jsonNodes:0,maxDepth:0,policies:c.policies.length,policyBytes:docs.reduce((n,d)=>n+bytes(d),0),policyRules:docs.reduce((n,d)=>n+d.rules.length,0),expressionNodes:docs.reduce((n,d)=>n+d.rules.reduce((m,q)=>m+nodes(q.when),0),0),ordinaryOrigins:c.grants.filter(g=>g.kind==='ordinary-role'||g.kind==='responsibility').length,connectedRecords:c.grants.filter(g=>g.kind==='delegation'||g.kind==='elevation').length,principals:c.principals.length,directGroupsMaximum:Math.max(0,...c.principalGroups.map(g=>g.memberships.status==='known'?g.memberships.value.length:0)),proofBytes:[c.session,c.partitions,c.definitions,c.principals,c.groups,c.memberships,c.principalGroups,c.grants,c.elevationUses,c.parents,c.dependencies,c.lifecycleHeads].reduce<number>((n,x)=>n+bytes(x),0)};
 const {metrics:_m,snapshot,...rest}=c,{closureDigest:_d,...s}=snapshot;c.snapshot.closureDigest=decisionHash({...rest,snapshot:s});
 for(let round=0;round<4;round++){const a=parsed(admitAuthorityInput(c)).metrics;c.metrics.canonicalBytes=a.canonicalBytes;c.metrics.jsonNodes=a.nodes;c.metrics.maxDepth=a.depth;}
 assert.equal(c.metrics.canonicalBytes,bytes(c));return c;
}

import type {InactiveClassifiedAssetContext} from '../../../packages/authority-runtime/src/classified-asset-context.ts';
export function classified(source=makeDecisionFixture(),placed=true,populated=false):Mutable<InactiveClassifiedAssetContext>{
 const {closure,registry}=closureFixture(source),assetId=closure.selectors[0]!.resource.id;
 const inner={formatVersion:1 as const,kind:'inactive-human-asset-context' as const,contentAuthority:false as const,closure,registry,
 asset:{tenantId:closure.session.tenantId,id:assetId,version:v,status:'active' as const,visibility:'tenant' as const,allowedIdentities:[]},
 placement:placed?{version:v,domainId:id(601),recordedAssetVersion:v,recordedDomainVersion:v}:null,
 domainPath:placed?[{id:id(601),version:3 as Version,parentId:id(600),typeId:id(650),typeVersion:v,status:'active' as const},{id:id(600),version:2 as Version,parentId:null,typeId:id(650),typeVersion:v,status:'active' as const}]:[],
 domainEpoch:(placed?'5':'0') as Counter,unavailableFacts:['classification','approved-tags','purpose','environment'] as Array<'classification'|'approved-tags'|'purpose'|'environment'>,contextDigest:zero};
 const context={formatVersion:1 as const,kind:'inactive-versioned-asset-context' as const,contentAuthority:false as const,context:inner,securityRevision:'7' as Counter,contextDigest:zero};
 const binding={installationId:id(701),version:v,operation:'bind' as const,implementation:'reviewed-metadata-classification-v1' as const,producer:{id:id(700),version:v},authorityEpochAfter:'1' as Counter,manifestHash:zero};
 const facts=populated?[{ref:{id:id(800),version:v},kind:'classifications' as const,provenance:{producer:binding.producer,tenantId:id(1),registryDigest:registry.digest,sourceRecordId:id(800),sourceRecordVersion:v},resource:{tenantId:id(1),kind:'asset' as const,id:assetId},revision:v,fieldId:null,securityRevision:'7' as Counter,state:'approved' as const,validity:{notBefore:'2026-11-16T05:30:00.000Z' as UTC,expiresAt:null},values:[id(801)]}]:[];
 return reseal({formatVersion:1,kind:'inactive-classified-asset-context',contentAuthority:false,context,producerBinding:binding,classifications:{status:'known',value:facts.map(f=>f.ref)},approvedFacts:facts,contextDigest:zero} as Mutable<InactiveClassifiedAssetContext>);
}
export function reseal(value:Mutable<InactiveClassifiedAssetContext>){
 const inner=value.context.context,{digest:oldDigest,...content}=inner.registry;
 inner.registry=structuredClone(decisionShapes.registry({...inner.registry,digest:decisionHash(decisionShapes.registryContent(content,''))},'')) as typeof inner.registry;
 inner.closure.snapshot.registryDigest=inner.registry.digest;
 for(const policy of inner.closure.policies)for(const mark of policy.resourceWideIntents)mark.registryDigest=inner.registry.digest;
 for(const fact of value.approvedFacts)fact.provenance.registryDigest=inner.registry.digest;
 sealClosure(inner.closure);inner.contextDigest=decisionHash({...inner,contextDigest:zero});
 value.context.contextDigest=decisionHash({...value.context,contextDigest:zero});value.contextDigest=decisionHash({...value,contextDigest:zero});return value;
}
