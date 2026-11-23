// SPDX-License-Identifier: Apache-2.0
// Inert input composition; no authentication, evaluator or effect API.
import {admitAuthorityInput, AUTHORITY_ADMISSION_LIMITS as L} from '../../authority/src/admission.ts';
import {authorityAnchorDigest, authorityNodeIdentity, validateDecisionIdentities} from '../../authority/src/decision-identity.ts';
import {canonicalDecisionJSON, decisionHash, decisionShapes, parseDecisionInput} from '../../authority/src/decision-schema.ts';
import {DecisionInputError, grantKey, scopeKey} from '../../authority/src/decision-types.ts';
import type {AdapterRegistration, AuthorityDecisionRegistry, ChainLink, DecisionBundle, DecisionCatalogs,
  DecisionNode, NodeAuthentication, NodeDescriptor, ResourceEvidence, ScopeAnchorEvidence, SnapshotRef} from '../../authority/src/decision-types.ts';
import type {Parsed, Scope, UUID} from '../../authority/src/types.ts';
import type {ClosurePartition} from '../../authority-storage/src/contracts.ts';
import {parseInactiveClassifiedAssetContext} from './classified-asset-context.ts';

export type HeldMetadataComposition = Readonly<{bundle:DecisionBundle;registry:AuthorityDecisionRegistry}>;
export interface HeldMetadataCompositionBudget {
  check():void;
  /** Exactly once, complete inert value. Caller includes held source proof/context. */
  admitComposition(value:HeldMetadataComposition):void;
}
const same=(a:unknown,b:unknown)=>canonicalDecisionJSON(a)===canonicalDecisionJSON(b);
function fail(outcome:'invalid'|'unsupported'|'profile_limit',message:string):never {
  throw new DecisionInputError(outcome,{code:outcome==='profile_limit'?'limit':outcome==='unsupported'?'unsupported':'scope',path:'',message});
}
function value<T>(parsed:Parsed<T>):T {
  if(parsed.ok)return parsed.value;
  const issue=parsed.issues[0]!;
  throw new DecisionInputError(issue.code==='limit'?'profile_limit':issue.code==='unsupported'?'unsupported':'invalid',issue);
}
function exact<T>(rows:readonly T[],message:string):T {
  if(rows.length!==1)fail('unsupported',message);
  return rows[0]!;
}
function adapterProfile(adapter:AdapterRegistration):void {
  if(adapter.containment!=='asset-placement'||adapter.dependencyElevation!=='forbidden'
    ||adapter.ceilingFailure!=='ceiling_denied'||adapter.ceilings.length!==1||adapter.ceilings[0]!.kind!=='visibility') {
    fail('unsupported','Metadata adapter registration is outside the fixed visibility/containment profile.');
  }
}
type Instance={key:string;partition:ClosurePartition;authentication:NodeAuthentication;issuers:Map<string,Instance>;
  authorize?:NodeDescriptor;guard?:NodeDescriptor;nodes?:readonly [DecisionNode,DecisionNode]};

/** Native caller must invoke this before releasing its held snapshot. The
 * result is pure data, never authentication, producer attestation or an allow. */
export function composeHeldHumanMetadataDecision(input:{context:unknown;budget:HeldMetadataCompositionBudget}):HeldMetadataComposition {
  const {budget}=input;budget.check();
  const context=value(parseInactiveClassifiedAssetContext(input.context));budget.check();
  const versioned=context.context, assetContext=versioned.context, {closure,registry,asset}=assetContext;
  if(asset.status!=='active'||assetContext.domainPath.some(d=>d.status!=='active'))fail('unsupported','Current metadata composition requires active asset and ancestry.');
  const request=closure.selectors[0]!;
  if(closure.selectors.length!==1||request.action!=='asset:metadata.read'||request.field!==null||request.resource.kind!=='asset'
    ||request.revision!==asset.version||request.resource.id!==asset.id||request.resource.tenantId!==asset.tenantId)fail('invalid','Metadata selector differs from the current canonical asset.');
  const authorizeAdapter=exact(registry.adapters.filter(a=>a.action==='asset:metadata.read'&&a.branch==='human-resource'&&a.resourceKinds.includes('asset')),'Metadata adapter registration is missing or ambiguous.');
  const intent=exact(registry.intentContexts.filter(i=>i.resourceKind==='asset'&&i.subjectKind==='human'),'Metadata intent context is missing or ambiguous.');
  if(intent.denyContextAction!=='asset:metadata.read')fail('unsupported','A different guard action requires its own canonical candidate closure.');
  const guardAdapter=exact(registry.adapters.filter(a=>a.id===intent.guardAdapterId),'Metadata intent guard registration is missing or ambiguous.');
  if(guardAdapter.branch!=='intent-guard'||guardAdapter.action!==intent.denyContextAction||!guardAdapter.resourceKinds.includes('asset'))fail('unsupported','Metadata intent guard registration differs.');
  adapterProfile(authorizeAdapter);adapterProfile(guardAdapter);budget.check();
  const snapshot:SnapshotRef={tenantId:closure.snapshot.tenantId,generation:closure.snapshot.generation,authorityEpoch:closure.snapshot.authorityEpoch,
    registryVersion:closure.snapshot.registryVersion,registryDigest:closure.snapshot.registryDigest,snapshotDigest:context.contextDigest,now:closure.snapshot.asOf};
  const resource:ResourceEvidence={requestResource:request.resource,requestedRevision:asset.version,canonicalCurrentVersion:asset.version,
    containment:{resource:request.resource,revision:asset.version,context:'current',operation:null,securityRevision:versioned.securityRevision,
      domainPath:{status:'known',value:assetContext.domainPath.map(d=>d.id)}},classifications:context.classifications,approvedTags:{status:'unavailable'}};
  const partitions=new Map(closure.partitions.map(p=>[p.key,p]));
  const grants=new Map(closure.grants.map(g=>[grantKey(g.ref),g]));
  const parents=new Map(closure.parents.map(p=>[grantKey(p.child),p]));
  const dependencies=new Map(closure.dependencies.map(d=>[`${d.from}/${grantKey(d.child)}`,d]));
  const instances=new Map<string,Instance>(),queue:Instance[]=[];
  const add=(partition:ClosurePartition,authentication:NodeAuthentication):Instance=>{
    const key=canonicalDecisionJSON([partition.key,authentication]),prior=instances.get(key);if(prior)return prior;
    if((instances.size+1)*2>L.contexts)fail('profile_limit','Expanded authorization and guard contexts exceed the fixed profile.');
    const instance:Instance={key,partition,authentication,issuers:new Map()};instances.set(key,instance);queue.push(instance);return instance;
  };
  const rootKey=decisionHash({formatVersion:1,subject:{kind:'human',id:closure.session.identityId},request});
  const rootPartition=partitions.get(rootKey);if(!rootPartition)fail('invalid','Canonical root partition is missing.');
  const root=add(rootPartition,{kind:'human-session',sessionId:closure.session.sessionId,sessionVersion:closure.session.sessionVersion});
  let referenceCount=0;
  for(let cursor=0;cursor<queue.length;cursor++){
    budget.check();const instance=queue[cursor]!;
    for(const terminal of instance.partition.candidates){
      let next=terminal;const seen=new Set<string>();
      for(;;){
        budget.check();const key=grantKey(next);if(seen.has(key))fail('invalid','Canonical grant path is cyclic.');seen.add(key);
        const grant=grants.get(key);if(!grant)fail('invalid','Canonical candidate grant is missing.');
        if(grant.kind!=='delegation'&&grant.kind!=='elevation')break;
        const parent=parents.get(key),dependency=dependencies.get(`${instance.partition.key}/${key}`);
        if(!parent||!dependency||!same(parent.parent,grant.parent))fail('invalid','Canonical connected issuer dependency is missing.');
        const partition=partitions.get(dependency.issuer);
        if(!partition||!same(partition.subject,grant.issuer)||!same(partition.request,instance.partition.request))fail('invalid','Canonical issuer partition differs.');
        instance.issuers.set(key,add(partition,{kind:'live-issuer',childGrant:grant.ref,elevationSession:null}));next=parent.parent;
      }
    }
    referenceCount+=2+instance.issuers.size*2;
    if(referenceCount>L.dependencyReferences)fail('profile_limit','Expanded issuer references exceed the fixed profile.');
  }
  const visiting=new Set<string>(),depths=new Map<string,number>();let edges=0;
  for(const instance of queue)edges+=1+new Set(instance.issuers.values()).size*2;
  if(edges>L.dependencyEdges)fail('profile_limit','Expanded dependency edges exceed the fixed profile.');
  const depth=(instance:Instance):number=>{
    budget.check();const prior=depths.get(instance.key);if(prior!==undefined)return prior;
    if(visiting.has(instance.key))fail('invalid','Expanded issuer dependency graph is cyclic.');visiting.add(instance.key);
    let maximum=0;for(const issuer of instance.issuers.values())maximum=Math.max(maximum,depth(issuer));
    const result=maximum+2;if(result>L.dependencyDepth)fail('profile_limit','Expanded authorize/guard depth exceeds the fixed profile.');
    visiting.delete(instance.key);depths.set(instance.key,result);return result;
  };depth(root);

  const anchors=new Map<string,ScopeAnchorEvidence>();
  const anchor=(scope:Exclude<Scope,{kind:'tenant'}>):ScopeAnchorEvidence=>{
    const key=scopeKey(scope),old=anchors.get(key);if(old)return old;
    let containment:ScopeAnchorEvidence['containment'];
    if(scope.kind==='resource'&&same(scope.resource,request.resource))containment=resource.containment;
    else {
      const id=scope.kind==='domain'?scope.domainId:scope.resource.kind==='domain'?scope.resource.id:null;
      const index=id===null?-1:assetContext.domainPath.findIndex(d=>d.id===id);
      if(index<0)fail('unsupported','Required scope anchor is outside the held asset ancestry.');
      const domain=assetContext.domainPath[index]!;
      containment={resource:{tenantId:asset.tenantId,kind:'domain',id:domain.id},revision:domain.version,context:'current',operation:null,
        securityRevision:versioned.securityRevision,domainPath:{status:'known',value:assetContext.domainPath.slice(index).map(d=>d.id)}};
    }
    const result={scope,containment};anchors.set(key,result);return result;
  };
  const tenant=(scope:Scope)=>scope.kind==='resource'?scope.resource.tenantId:scope.tenantId;
  const attenuation=(parent:Scope,child:Scope):void=>{
    budget.check();if(tenant(parent)!==tenant(child)||tenant(parent)!==asset.tenantId)fail('invalid','Grant attenuation crosses tenant.');
    if(parent.kind==='tenant')return;
    if(parent.kind==='resource'){if(child.kind!=='resource'||!same(parent.resource,child.resource))fail('invalid','Resource scope widens its parent.');return;}
    if(child.kind==='tenant')fail('invalid','Tenant scope widens its domain parent.');
    if(child.kind==='domain'){
      if(child.domainId===parent.domainId){if(!parent.includeDescendants&&child.includeDescendants)fail('invalid','Domain scope widens descendants.');return;}
      if(!parent.includeDescendants)fail('invalid','Distinct domain scope widens a direct parent.');
    }
    const proof=anchor(child).containment.domainPath;
    if(proof.status!=='known'||!(parent.includeDescendants?proof.value.includes(parent.domainId):proof.value[0]===parent.domainId))fail('invalid','Canonical child scope is outside its domain parent.');
  };
  const neededPrincipals=new Set<UUID>(queue.map(i=>i.partition.subject.id));
  for(const grant of closure.grants){
    attenuation(grant.ceiling.scope,grant.scope);
    if('delegable'in grant&&grant.delegable){attenuation(grant.scope,grant.delegable.scope);attenuation(grant.ceiling.scope,grant.delegable.scope);}
    if(grant.kind==='delegation'||grant.kind==='elevation'){
      neededPrincipals.add(grant.issuer.id);neededPrincipals.add(grant.beneficiary.id);
      const parent=grants.get(grantKey(grant.parent));
      if(!parent||!('delegable'in parent)||!parent.delegable)fail('invalid','Connected parent delegation ceiling is missing.');
      for(const scope of [parent.scope,parent.ceiling.scope,parent.delegable.scope])attenuation(scope,grant.scope);
      attenuation(parent.ceiling.scope,grant.ceiling.scope);attenuation(parent.delegable.scope,grant.ceiling.scope);
    }
  }
  const session=closure.session,visibilityId=`asset-visibility:${asset.id}@${asset.version}`;
  const rawCatalogs:DecisionCatalogs={principals:closure.principals.filter(p=>neededPrincipals.has(p.id)),groups:closure.groups,
    memberships:closure.memberships,principalGroups:closure.principalGroups,definitions:closure.definitions,policies:closure.policies,grants:closure.grants,
    sessions:[{id:session.sessionId,version:session.sessionVersion,identityId:session.identityId,selectedTenantId:session.tenantId,generation:session.generation,
      state:'active',validity:{notBefore:session.issuedAt,expiresAt:session.expiresAt}}],scopeAnchors:[...anchors.values()],
    visibility:[{id:visibilityId,resource:request.resource,revision:asset.version,visibility:asset.visibility,allowedIdentities:asset.allowedIdentities}],
    approvedFacts:context.approvedFacts,credentials:[],creators:[],serviceAssignments:[],contextFacts:[],operations:[],references:[],sources:[],jobs:[],
    claims:[],leases:[],projectionEvents:[],journalClaims:[],terminals:[]};
  const catalogs=decisionShapes.catalogs(value(admitAuthorityInput(rawCatalogs)).data,'/catalogs') as DecisionCatalogs;
  for(const instance of queue){
    budget.check();const common={subject:instance.partition.subject,request:instance.partition.request,authentication:instance.authentication,resource,
      projection:null,service:null,purpose:{status:'unavailable' as const},environment:{status:'unavailable' as const},intentGuard:null,guardOrigin:null};
    instance.authorize={...common,mode:'authorize',adapterId:authorizeAdapter.id,ceilingRefs:[{slot:authorizeAdapter.ceilings[0]!.slot,recordId:visibilityId}]};
    instance.guard={...common,mode:'resource-wide-deny',adapterId:guardAdapter.id,ceilingRefs:[{slot:guardAdapter.ceilings[0]!.slot,recordId:visibilityId}]};
  }
  // One combined preflight before per-node identity work, not128 fresh input
  // allowances. Native caller's admission additionally includes its source proof.
  value(admitAuthorityInput({context,catalogs,descriptors:queue.flatMap(i=>[i.authorize,i.guard])}));budget.check();
  for(const instance of queue){
    budget.check();const authorize=value(authorityNodeIdentity(snapshot,instance.authorize!,catalogs,registry,null));
    const guard=value(authorityNodeIdentity(snapshot,instance.guard!,catalogs,registry,instance.authorize!));
    instance.nodes=[{...instance.authorize!,id:authorize.nodeId,factDigest:authorize.factDigest,intentGuard:guard.nodeId},
      {...instance.guard!,id:guard.nodeId,factDigest:guard.factDigest,guardOrigin:authorize.nodeId}];
  }
  const nodes=queue.flatMap(i=>[...i.nodes!]),chainLinks:ChainLink[]=[];
  const candidates=queue.flatMap(instance=>instance.nodes!.map(node=>({nodeId:node.id,snapshotDigest:snapshot.snapshotDigest,
    subject:node.subject,request:node.request,anchorDigest:value(authorityAnchorDigest(node.resource)),candidates:instance.partition.candidates})));
  for(const instance of queue)for(const node of instance.nodes!)for(const [child,issuer] of instance.issuers){
    budget.check();const parent=parents.get(child)!;
    chainLinks.push({nodeId:node.id,child:parent.child,parent:parent.parent,viaMembership:parent.viaMembership,issuerDecision:issuer.nodes![0].id});
  }
  const bundle:DecisionBundle={formatVersion:1,snapshot,root:root.nodes![0].id,nodes,candidates,chainLinks,...catalogs};
  budget.check();const parsed=value(parseDecisionInput(bundle,registry));
  const result=Object.freeze({bundle:parsed.bundle,registry:parsed.registry});
  budget.admitComposition(result);budget.check();validateDecisionIdentities(parsed);budget.check();return result;
}
