// SPDX-License-Identifier: Apache-2.0
// Consistency of an already admitted, closed private graph. Completeness against
// rows outside this payload is a canonical SQL/snapshot obligation, not attestation.
import { ADMIN_ACTIONS, COMPATIBILITY_ACTIONS, SERVICE_ACTIONS } from '../../authority/src/actions.ts';
import { canonicalDecisionJSON as canonical, decisionHash } from '../../authority/src/decision-schema.ts';
import { parsePolicyFile, policyHash } from '../../authority/src/policy.ts';
import { definitionKey, grantKey, policyKey, subjectKey, versionKey } from '../../authority/src/decision-types.ts';
import type { AtomicRequest, AuthorityDecisionRegistry, AuthorityGrant, DefinitionEvidence, GrantRef } from '../../authority/src/decision-types.ts';
import type { PolicyDefinition, PolicyExpr, Scope, Validity } from '../../authority/src/types.ts';
import type { AuthorityHumanClosure, FoundationLoadMetrics } from './contracts.ts';
import { equal, fail, foundationScalars } from './shape.ts';
const bytes=(x:unknown)=>Buffer.byteLength(canonical(x));
const liveFuture=(state:string,v:Validity,now:string)=>state==='active'&&(v.expiresAt===null||now<v.expiresAt);
const current=(v:Validity,now:string)=>(v.notBefore===null||v.notBefore<=now)&&(v.expiresAt===null||now<v.expiresAt);
const inside=(a:Validity,b:Validity)=>(b.notBefore===null||(a.notBefore!==null&&a.notBefore>=b.notBefore))&&(b.expiresAt===null||(a.expiresAt!==null&&a.expiresAt<=b.expiresAt));
const subset=<T>(a:readonly T[],b:readonly T[])=>a.every(x=>b.includes(x));
const fieldsInside=(a:readonly string[]|null,b:readonly string[]|null)=>b===null||(a!==null&&subset(a,b));
const needed=<T>(value:T|undefined,message:string):T=>value===undefined?fail(message,'required'):value;
const sorted=(s:Iterable<string>)=>[...s].sort();
const exactKeys=(actual:Iterable<string>,expected:Iterable<string>,message:string)=>equal(sorted(actual),sorted(expected),message);
const exprNodes=(e:PolicyExpr):number=>1+('children'in e?e.children.reduce((s,c)=>s+exprNodes(c),0):0);
const scopeTenant=(s:Scope)=>s.kind==='resource'?s.resource.tenantId:s.tenantId;
const compatible=new Set<string>(COMPATIBILITY_ACTIONS.flatMap(([a])=>[...a]));
const service=new Set<string>(SERVICE_ACTIONS);
const admin=new Set<string>(ADMIN_ACTIONS);
function literalScopeInside(child:Scope,parent:Scope):void{
 if(scopeTenant(child)!==scopeTenant(parent))fail('Scope tenant differs.');
 if(parent.kind==='resource'&&(child.kind!=='resource'||canonical(child)!==canonical(parent)))fail('Resource scope widens parent.');
 if(parent.kind==='domain'&&child.kind==='tenant')fail('Tenant scope widens domain parent.');
 if(parent.kind==='domain'&&child.kind==='domain'&&parent.domainId===child.domainId&&!parent.includeDescendants&&child.includeDescendants)fail('Domain descendants widen parent.');
 // Different domain/resource scopes require canonical content anchors later.
}
export function validateClosureConsistency(c:AuthorityHumanClosure,r:AuthorityDecisionRegistry):void{
 const tenant=c.session.tenantId,now=c.snapshot.asOf;
 equal(c.snapshot.tenantId,tenant,'Snapshot tenant differs from session.');equal(c.snapshot.generation,c.session.generation,'Snapshot generation differs from session.');
 equal([c.snapshot.registryVersion,c.snapshot.registryDigest],[r.version,r.digest],'Registry pin differs.');
 if(!(c.session.authenticatedAt<=c.session.issuedAt&&c.session.issuedAt<=now&&now<c.session.expiresAt))fail('Session time bounds do not include snapshot.');
 const walkTenant=(v:unknown):void=>{if(Array.isArray(v)){v.forEach(walkTenant);return;}if(v===null||typeof v!=='object')return;for(const [k,x]of Object.entries(v)){if(k==='tenantId'&&x!==tenant)fail('Cross-tenant closure evidence.');walkTenant(x);}};walkTenant(c);
 const actionMap=new Map(r.actions.map(x=>[x.action,x]));
 const checkRequest=(q:AtomicRequest)=>{const a=needed(actionMap.get(q.action),'Unregistered request action.');if(a.family==='service'||!a.resourceKinds.includes(q.resource.kind)||q.field!==null&&!r.fields.includes(q.field))fail('Request does not match exact human registry.');};
 if(!c.selectors.length)fail('Missing root selectors.','required');c.selectors.forEach(checkRequest);
 const principals=new Map(c.principals.map(x=>[x.id,x])),groups=new Map(c.groups.map(x=>[x.id,x]));
 const memberships=new Map(c.memberships.map(x=>[versionKey(x.ref),x]));
 const pgs=new Map(c.principalGroups.map(x=>[x.subject.id,x]));
 const grants=new Map(c.grants.map(x=>[grantKey(x.ref),x]));
 if(new Set(c.grants.map(x=>x.ref.id)).size!==c.grants.length)fail('A grant ID cannot change kind.','duplicate');
 const definitions=new Map(c.definitions.map(x=>[definitionKey(x.kind,x.id,x.version),x]));
 const policies=new Map(c.policies.map(x=>[policyKey(x.pin),x]));
 const parsedPolicies=new Map<string,PolicyDefinition>(),definitionHeads=new Map<string,string>();
 let policyBytes=0,policyRules=0,expressionNodes=0;
 for(const p of c.policies){
  if(p.currentHeadVersion<p.pin.version)fail('Policy pin exceeds published head.','version');
  const result=parsePolicyFile(p.document,r.fields);if(!result.ok)fail('Invalid exact policy document.',result.issues[0]!.code);
  const doc=result.value;foundationScalars(doc);const hash=policyHash(doc,r.fields);if(!hash.ok)fail('Invalid canonical policy hash.');
  equal([doc.id,doc.version,hash.value],[p.pin.policyId,p.pin.version,p.pin.hash],'Policy bytes differ from immutable pin.');
  const key=`policy:${doc.id}`,head=canonical([p.currentHeadVersion,p.state]);if(definitionHeads.has(key)&&definitionHeads.get(key)!==head)fail('Conflicting policy heads.');definitionHeads.set(key,head);
  parsedPolicies.set(policyKey(p.pin),doc);policyBytes+=bytes(doc);policyRules+=doc.rules.length;expressionNodes+=doc.rules.reduce((s,q)=>s+exprNodes(q.when),0);
  if(doc.rules.some(q=>q.actions.some(a=>service.has(a))))fail('Human policy contains service action.');
  for(const mark of p.resourceWideIntents){
   equal([mark.registryVersion,mark.registryDigest],[r.version,r.digest],'Intent registry differs.');
   const rule=needed(doc.rules.find(x=>x.id===mark.ruleId),'Missing marked rule.');
   const actionPredicate=(e:PolicyExpr):boolean=>e.op==='action-in'||('children'in e&&e.children.some(actionPredicate));
   if(rule.effect!=='deny'||rule.fields!==null||!mark.resourceKinds.length||actionPredicate(rule.when))fail('Invalid resource-wide intent.');
   const expanded=r.actions.filter(a=>a.family==='human'&&a.resourceKinds.some(k=>mark.resourceKinds.includes(k))).map(a=>a.action).sort();
   equal(mark.expandedActions,expanded,'Incomplete resource-wide expansion.');equal(rule.actions,expanded,'Marked rule action set differs.');
  }
 }
 for(const d of c.definitions){
  if(d.currentHeadVersion<d.version)fail('Definition pin exceeds published head.');
  equal(d.hash,decisionHash({formatVersion:d.formatVersion,kind:d.kind,id:d.id,version:d.version,content:d.content}),'Definition hash differs.');
  const key=`${d.kind}:${d.id}`,head=canonical([d.currentHeadVersion,d.state]);if(definitionHeads.has(key)&&definitionHeads.get(key)!==head)fail('Conflicting definition heads.');definitionHeads.set(key,head);
  if(d.kind==='role'){if(!d.content.policies.length)fail('Role policy pins are empty.');for(const pin of d.content.policies)needed(policies.get(policyKey(pin)),'Missing exact role policy.');}
 }
 const kindById=new Map<string,string>();for(const [id,kind]of [...c.definitions.map(d=>[d.id,d.kind]),...c.policies.map(p=>[p.pin.policyId,'policy']),...c.groups.map(g=>[g.id,'group'])]){const prior=kindById.get(id!);if(prior!==undefined&&prior!==kind)fail('Definition ID crosses kinds.');kindById.set(id!,kind!);}
 const expectedPrincipals=new Set<string>([c.session.identityId]),expectedGroups=new Set<string>(),expectedDefinitions=new Set<string>(),expectedPolicies=new Set<string>();
 const role=(pin:{roleId:string;version:number}):Extract<DefinitionEvidence,{kind:'role'}>=>{const key=definitionKey('role',pin.roleId as never,pin.version as never),d=needed(definitions.get(key),'Missing exact role definition.');if(d.kind!=='role')fail('Wrong role definition.');expectedDefinitions.add(key);for(const p of d.content.policies)expectedPolicies.add(policyKey(p));return d;};
 const originPolicies=new Map<string,readonly string[]>();
 for(const g of c.grants){
  if(g.ref.version!==1||g.issuer.kind!=='human'||g.beneficiary.kind==='service')fail('Invalid human issuance pin.');expectedPrincipals.add(g.issuer.id);
  if(g.beneficiary.kind==='human')expectedPrincipals.add(g.beneficiary.id);else expectedGroups.add(g.beneficiary.id);
  const expectedKind=g.kind==='ordinary-role'||g.kind==='responsibility'?'grant':g.kind;if(g.ref.kind!==expectedKind)fail('Grant kind and ref differ.');
  if(g.ceiling.actions.some(a=>service.has(a))||g.ceiling.resourceKinds.length===0||g.ceiling.actions.length===0)fail('Human effect ceiling is invalid.');
  for(const list of [g.ceiling.fields,'delegable'in g?g.delegable?.fields:null])if(list&&list.some(x=>!r.fields.includes(x)))fail('Unregistered ceiling field.');
  if(!inside(g.ceiling.validity,g.validity))fail('Effect validity widens grant.');literalScopeInside(g.ceiling.scope,g.scope);
  if('delegable'in g&&g.delegable){if(!subset(g.delegable.actions,g.ceiling.actions)||!fieldsInside(g.delegable.fields,g.ceiling.fields)||!inside(g.delegable.validity,g.validity)||!inside(g.delegable.validity,g.ceiling.validity))fail('Onward ceiling widens effect.');literalScopeInside(g.delegable.scope,g.scope);literalScopeInside(g.delegable.scope,g.ceiling.scope);}
  if(g.kind==='ordinary-role')originPolicies.set(grantKey(g.ref),role(g.role).content.policies.map(policyKey));
  if(g.kind==='responsibility'){
   const key=definitionKey('responsibility-type',g.type.id,g.type.version),d=needed(definitions.get(key),'Missing responsibility type.');expectedDefinitions.add(key);if(d.kind!=='responsibility-type')fail('Wrong responsibility type.');equal(g.mappedRole,d.content.grantsRole,'Responsibility mapping differs.');
   if(g.assignmentVersion!==1||g.mappedRole===null&&(g.effectiveGrantId!==null||g.delegable!==null)||g.mappedRole!==null&&g.effectiveGrantId!==g.ref.id)fail('Responsibility grant companion differs.');
   originPolicies.set(grantKey(g.ref),g.mappedRole===null?[]:role(g.mappedRole).content.policies.map(policyKey));
  }
  if(g.kind==='elevation'&&(g.validity.expiresAt===null||g.ceiling.actions.some(a=>!compatible.has(a))))fail('Elevation action or expiry invalid.');
 }
 exactKeys(definitions.keys(),expectedDefinitions,'Missing or unreferenced definition.');exactKeys(policies.keys(),expectedPolicies,'Missing or unreferenced policy.');
 const parents=new Map(c.parents.map(x=>[grantKey(x.child),x]));
 exactKeys(parents.keys(),c.grants.filter(g=>g.kind==='delegation'||g.kind==='elevation').map(g=>grantKey(g.ref)),'Connected parent set differs.');
 const viaIds=new Set<string>();
 for(const edge of c.parents){
  const child=needed(grants.get(grantKey(edge.child)),'Missing child.'),parent=needed(grants.get(grantKey(edge.parent)),'Missing parent.');
  if(child.kind!=='delegation'&&child.kind!=='elevation')fail('Ordinary grant has parent.');equal(child.parent,edge.parent,'Parent pin differs.');
  if(parent.kind==='elevation'||parent.kind==='responsibility'&&parent.mappedRole===null||!('delegable'in parent)||parent.delegable===null)fail('Parent cannot delegate.');
  const onward=parent.delegable;
  if(parent.beneficiary.kind==='group'){
   if(edge.viaMembership===null)fail('Group parent requires membership.');const m=needed(memberships.get(versionKey(edge.viaMembership)),'Missing exact historical membership.');
   if(m.identityId!==child.issuer.id||m.groupId!==parent.beneficiary.id)fail('Disconnected group parent.');viaIds.add(versionKey(m.ref));
  }else{if(edge.viaMembership!==null||parent.beneficiary.id!==child.issuer.id)fail('Disconnected human parent.');}
  if(!subset(child.ceiling.actions,parent.ceiling.actions)||!subset(child.ceiling.actions,onward.actions)||!subset(child.ceiling.resourceKinds,parent.ceiling.resourceKinds)||!fieldsInside(child.ceiling.fields,parent.ceiling.fields)||!fieldsInside(child.ceiling.fields,onward.fields)||!inside(child.validity,parent.validity)||!inside(child.validity,parent.ceiling.validity)||!inside(child.validity,onward.validity))fail('Connected ceiling widens parent.');
  if(child.ceiling.actions.some(a=>!compatible.has(a)&&!admin.has(a)))fail('Connected grants cannot introduce field actions.');
  literalScopeInside(child.scope,parent.scope);literalScopeInside(child.scope,parent.ceiling.scope);literalScopeInside(child.scope,onward.scope);
  if(child.kind==='delegation'&&(onward.remainingDepth<1||child.delegable!==null&&child.delegable.remainingDepth>=onward.remainingDepth))fail('Delegation depth widens parent.');
 }
 for(const m of c.memberships){if(m.ref.version!==1)fail('Membership issuance version differs.');needed(groups.get(m.groupId),'Missing membership group.');expectedPrincipals.add(m.identityId);expectedGroups.add(m.groupId);}
 for(const p of c.principals){if(p.membership!==null){if(p.membership.identityId!==p.id||p.membership.validity.notBefore!==null||p.membership.validity.expiresAt!==null)fail('Canonical tenant membership companion differs.');}}
 const rootPrincipal=needed(principals.get(c.session.identityId),'Missing session principal.');if(!rootPrincipal.active||rootPrincipal.membership?.state!=='active')fail('Session principal is inactive.');
 exactKeys(memberships.keys(),c.principalGroups.flatMap(g=>g.memberships.status==='known'?g.memberships.value.map(versionKey):[]),'Unreferenced membership evidence.');
 const activeGroups=(identity:string)=>new Set(c.memberships.filter(m=>m.identityId===identity&&liveFuture(m.state,m.validity,now)).map(m=>m.groupId));
 for(const pg of c.principalGroups){if(pg.memberships.status!=='known')fail('Group membership proof is unavailable.');const actual=pg.memberships.value.map(versionKey);const expected=c.memberships.filter(m=>m.identityId===pg.subject.id&&(liveFuture(m.state,m.validity,now)||viaIds.has(versionKey(m.ref)))).map(m=>versionKey(m.ref));exactKeys(actual,expected,'Incomplete direct/historical membership union.');if(actual.length>1024)fail('Direct group proof exceeds profile.','limit');}
 const membershipGroups=new Map<string,typeof c.memberships[number][]>();for(const m of c.memberships)if(liveFuture(m.state,m.validity,now)){const key=`${m.groupId}:${m.identityId}`,existing=membershipGroups.get(key)??[];for(const p of existing)if((m.validity.expiresAt===null||p.validity.notBefore===null||p.validity.notBefore<m.validity.expiresAt)&&(p.validity.expiresAt===null||m.validity.notBefore===null||m.validity.notBefore<p.validity.expiresAt))fail('Overlapping group membership intervals.');existing.push(m);membershipGroups.set(key,existing);}
 const pathCache=new Map<string,readonly AuthorityGrant[]>();
 const path=(ref:GrantRef):readonly AuthorityGrant[]=>{const key=grantKey(ref),cached=pathCache.get(key);if(cached)return cached;const out:AuthorityGrant[]=[],seen=new Set<string>();let next=ref,delegations=0;
  while(true){const k=grantKey(next);if(seen.has(k))fail('Cyclic parent chain.');seen.add(k);const g=needed(grants.get(k),'Missing path grant.');out.push(g);if(g.kind==='ordinary-role'||g.kind==='responsibility')break;if(g.kind==='delegation'&&++delegations>4)fail('Delegation path exceeds four edges.','limit');next=g.parent;}
  const people=new Set<string>(),forward=[...out].reverse();if(forward[0]!.beneficiary.kind==='human')people.add(forward[0]!.beneficiary.id);for(let n=1;n<forward.length;n++){const g=forward[n]!,p=forward[n-1]!;if(p.beneficiary.kind==='group')people.add(g.issuer.id);if(people.has(g.beneficiary.id))fail('Connected path repeats an issuer or beneficiary.');people.add(g.beneficiary.id);}
  pathCache.set(key,out);return out;};
 for(const g of c.grants)path(g.ref);
 const relevant=(g:typeof c.grants[number],q:AtomicRequest):boolean=>{
  const origin=path(g.ref).at(-1)!,keys=originPolicies.get(grantKey(origin.ref))??[];
  if(keys.some(k=>policies.get(k)!.resourceWideIntents.some(mark=>mark.resourceKinds.includes(q.resource.kind))))return true;
  return g.ceiling.actions.includes(q.action)&&g.ceiling.resourceKinds.includes(q.resource.kind)&&(q.field===null||g.ceiling.fields===null||g.ceiling.fields.includes(q.field));
 };
 const partitions=new Map(c.partitions.map(x=>[x.key,x])),expectedPartitions=new Set<string>(),expectedDeps=new Set<string>(),usedGrants=new Set<string>();
 const queue=c.selectors.map(q=>({subject:{kind:'human' as const,id:c.session.identityId},request:q}));
 for(let i=0;i<queue.length;i++){
  const wanted=queue[i]!,key=decisionHash({formatVersion:1,...wanted});if(expectedPartitions.has(key))continue;expectedPartitions.add(key);if(expectedPartitions.size>128)fail('Partition profile exceeded.','limit');
  const p=needed(partitions.get(key),'Missing root/issuer partition.');equal([p.subject,p.request],[wanted.subject,wanted.request],'Partition identity mismatch.');checkRequest(p.request);needed(pgs.get(p.subject.id),'Missing complete principal groups.');
  const groupIds=activeGroups(p.subject.id);
  const candidates=c.grants.filter(g=>liveFuture(g.state,g.validity,now)&&(g.beneficiary.kind==='human'?g.beneficiary.id===p.subject.id:groupIds.has(g.beneficiary.id))&&relevant(g,p.request));
  exactKeys(p.candidates.map(grantKey),candidates.map(g=>grantKey(g.ref)),'Candidate partition omits or adds a retained relevant terminal.');
  for(const terminal of p.candidates)for(const g of path(terminal)){
   usedGrants.add(grantKey(g.ref));if(g.kind==='delegation'||g.kind==='elevation'){
    const issuer=decisionHash({formatVersion:1,subject:g.issuer,request:p.request});expectedDeps.add(`${key}:${issuer}:${grantKey(g.ref)}`);queue.push({subject:{kind:'human',id:g.issuer.id},request:p.request});
   }
  }
 }
 exactKeys(partitions.keys(),expectedPartitions,'Unreachable/extra partition.');exactKeys(grants.keys(),usedGrants,'Unreferenced grant.');
 exactKeys(c.dependencies.map(d=>`${d.from}:${d.issuer}:${grantKey(d.child)}`),expectedDeps,'Issuer dependency inventory differs.');
 const expectedGroupSubjects=new Set([...c.partitions.map(p=>p.subject.id),...c.memberships.filter(m=>viaIds.has(versionKey(m.ref))).map(m=>m.identityId)]);exactKeys(pgs.keys(),expectedGroupSubjects,'Group partition subject inventory differs.');
 exactKeys(principals.keys(),expectedPrincipals,'Principal reference inventory differs.');exactKeys(groups.keys(),expectedGroups,'Group reference inventory differs.');
 const adjacency=new Map<string,Set<string>>();for(const d of c.dependencies){const edges=adjacency.get(d.from)??new Set();edges.add(d.issuer);adjacency.set(d.from,edges);}
 const depths=new Map<string,number>(),visiting=new Set<string>();const depth=(key:string):number=>{const old=depths.get(key);if(old!==undefined)return old;if(visiting.has(key))fail('Cyclic issuer dependency graph.');visiting.add(key);const n=1+Math.max(0,...[...(adjacency.get(key)??[])].map(depth));visiting.delete(key);if(n>16)fail('Dependency depth exceeds profile.','limit');depths.set(key,n);return n;};const dependencyDepth=Math.max(...[...partitions.keys()].map(depth));
 const useIds=new Set<string>();
 for(const use of c.elevationUses){if(use.ref.version!==1)fail('Use issuance version differs.');const g=needed(grants.get(grantKey(use.elevation)),'Unreferenced elevation use.');if(g.kind!=='elevation'||use.identityId!==g.beneficiary.id||use.validity.expiresAt===null||!inside(use.validity,g.validity))fail('Invalid elevation use companion.');useIds.add(versionKey(use.ref));}
 for(const g of c.grants)if(g.kind==='elevation'){
  const uses=c.elevationUses.filter(u=>grantKey(u.elevation)===grantKey(g.ref)&&u.identityId===c.session.identityId&&u.sessionId===c.session.sessionId&&u.sessionVersion===c.session.sessionVersion&&u.generation===c.session.generation&&liveFuture(u.state,u.validity,now));
  for(let i=0;i<uses.length;i++)for(let j=i+1;j<uses.length;j++){const a=uses[i]!.validity,b=uses[j]!.validity;if((a.expiresAt===null||b.notBefore===null||b.notBefore<a.expiresAt)&&(b.expiresAt===null||a.notBefore===null||a.notBefore<b.expiresAt))fail('Overlapping elevation uses.');}
  uses.sort((a,b)=>{const ac=current(a.validity,now),bc=current(b.validity,now);if(ac!==bc)return ac?-1:1;return (a.validity.notBefore??'').localeCompare(b.validity.notBefore??'')||versionKey(a.ref).localeCompare(versionKey(b.ref));});
  const u=uses[0];equal(g.use,u?{id:u.ref.id,version:u.ref.version,state:u.state,identityId:u.identityId,sessionId:u.sessionId,sessionVersion:u.sessionVersion,generation:u.generation,validity:u.validity}:null,'Elevation use selection differs.');
 }
 const expectedHeads=new Set<string>();for(const d of c.definitions)expectedHeads.add(`definition:${d.kind}:${d.id}`);for(const p of c.policies)expectedHeads.add(`definition:policy:${p.pin.policyId}`);for(const g of c.groups)expectedHeads.add(`definition:group:${g.id}`);for(const m of c.memberships)expectedHeads.add(`group-membership::${m.ref.id}`);for(const g of c.grants)expectedHeads.add(`grant::${g.ref.id}`);for(const u of c.elevationUses)expectedHeads.add(`elevation-use::${u.ref.id}`);
 exactKeys(c.lifecycleHeads.map(h=>`${h.family}:${h.definitionKind??''}:${h.id}`),expectedHeads,'Lifecycle head inventory differs.');
 for(const h of c.lifecycleHeads){if(h.family==='definition'){const versions=h.definitionKind==='policy'?c.policies.filter(p=>p.pin.policyId===h.id).map(p=>p.currentHeadVersion):c.definitions.filter(d=>d.id===h.id).map(d=>d.currentHeadVersion);if(versions.some(v=>h.headVersion<v))fail('Lifecycle head predates publication.');if(h.definitionKind==='group')equal(String(h.headVersion),groups.get(h.id)!.revision,'Group revision differs from lifecycle head.');}else{const state=h.family==='grant'?c.grants.find(g=>g.ref.id===h.id)!.state:h.family==='group-membership'?c.memberships.find(m=>m.ref.id===h.id)!.state:c.elevationUses.find(u=>u.ref.id===h.id)!.state;if(state==='revoked'&&h.headVersion<2||state==='active'&&h.headVersion!==1)fail('Issuance lifecycle state/version differs.');}}
 const proofBytes=[c.session,c.partitions,c.definitions,c.principals,c.groups,c.memberships,c.principalGroups,c.grants,c.elevationUses,c.parents,c.dependencies,c.lifecycleHeads].reduce<number>((s,x)=>s+bytes(x),0);
 const expected:Omit<FoundationLoadMetrics,'canonicalBytes'|'jsonNodes'|'maxDepth'>={selectors:c.selectors.length,partitions:c.partitions.length,dependencyEdges:[...adjacency.values()].reduce((s,v)=>s+v.size,0),dependencyReferences:c.dependencies.length,dependencyDepth,policies:c.policies.length,policyBytes,policyRules,expressionNodes,ordinaryOrigins:c.grants.filter(g=>g.kind==='ordinary-role'||g.kind==='responsibility').length,connectedRecords:c.grants.filter(g=>g.kind==='delegation'||g.kind==='elevation').length,principals:c.principals.length,directGroupsMaximum:Math.max(0,...c.principalGroups.map(g=>g.memberships.status==='known'?g.memberships.value.length:0)),proofBytes};
 for(const [key,value]of Object.entries(expected))equal(c.metrics[key as keyof FoundationLoadMetrics],value,'Closure semantic metrics mismatch.');
 const {metrics:_m,snapshot,...rest}=c,{closureDigest,...s}=snapshot;equal(closureDigest,decisionHash({...rest,snapshot:s}),'Closure digest mismatch.');
}
