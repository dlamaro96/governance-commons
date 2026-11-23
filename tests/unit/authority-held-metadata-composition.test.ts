// SPDX-License-Identifier: Apache-2.0
// Synthetic pure composition/evaluator tests. No native or activation claim.
import assert from 'node:assert/strict';
import test from 'node:test';
import {composeHeldHumanMetadataDecision as compose,type HeldMetadataCompositionBudget} from '../../packages/authority-runtime/src/held-metadata-composition.ts';
import {classified,reseal} from './fixtures/held-metadata.ts';
import {makeDecisionFixture,makeWideBindingFixture,sealDecisionFixture,id,v,zero,parsed,type Mutable} from './fixtures/authority-decision.ts';
import {makeFourEdgeFieldFixture} from './fixtures/authority-decision-chain.ts';
import {evaluateAuthority} from '../../packages/authority/src/decisions.ts';
import {DecisionInputError,grantKey,type AuthorityGrant,type DecisionNode} from '../../packages/authority/src/decision-types.ts';
import {canonicalDecisionJSON as canonical,decisionHash} from '../../packages/authority/src/decision-schema.ts';
import {parseInactiveClassifiedAssetContext,type InactiveClassifiedAssetContext} from '../../packages/authority-runtime/src/classified-asset-context.ts';
import type {Counter,UTC,Version} from '../../packages/authority/src/types.ts';

/** Same real issuer, independent child grants. Every child has its own full
 * engine fixture node before collapsing to the coarser storage partition. */
function parallelChildren(count:number){
 const f=makeFourEdgeFieldFixture(false),b=f.bundle,origin=b.grants.find(g=>g.kind==='ordinary-role')!;
 if(origin.kind!=='ordinary-role'||origin.beneficiary.kind!=='human')throw Error('fixture');
 const issuer={kind:'human' as const,id:origin.beneficiary.id};
 const root=b.nodes.find(n=>n.id===b.root)!,guard=b.nodes.find(n=>n.id===root.intentGuard)!,template=b.grants.find(g=>g.kind==='delegation')!;
 if(template.kind!=='delegation')throw Error('fixture');
 b.nodes=[root,guard];b.grants=[origin];b.chainLinks=[];b.candidates=[];
 b.principals=b.principals.filter(p=>p.id===root.subject.id||p.id===origin.beneficiary.id);b.principalGroups=b.principalGroups.filter(p=>b.principals.some(person=>person.id===p.subject.id));
 const children:typeof b.grants=[];
 for(let n=0;n<count;n++){
  const child={...structuredClone(template),ref:{kind:'delegation' as const,id:id(8000+n),version:v},parent:origin.ref,issuer,beneficiary:root.subject as {kind:'human';id:typeof root.subject.id},delegable:null};children.push(child);b.grants.push(child);
  const auth:Mutable<DecisionNode>={...structuredClone(root),id:(9000+n*2).toString(16).padStart(64,'0') as typeof zero,subject:issuer,authentication:{kind:'live-issuer',childGrant:child.ref,elevationSession:null},intentGuard:(9001+n*2).toString(16).padStart(64,'0') as typeof zero};
  const deny:Mutable<DecisionNode>={...structuredClone(guard),id:auth.intentGuard!,subject:auth.subject,authentication:auth.authentication,guardOrigin:auth.id};b.nodes.push(auth,deny);
  for(const node of [auth,deny])b.candidates.push({nodeId:node.id,snapshotDigest:b.snapshot.snapshotDigest,subject:node.subject,request:node.request,anchorDigest:zero,candidates:[origin.ref]});
  for(const node of [root,guard])b.chainLinks.push({nodeId:node.id,child:child.ref,parent:origin.ref,viaMembership:null,issuerDecision:auth.id});
 }
 for(const node of [root,guard])b.candidates.push({nodeId:node.id,snapshotDigest:b.snapshot.snapshotDigest,subject:node.subject,request:node.request,anchorDigest:zero,candidates:children.map(g=>g.ref)});
 return sealDecisionFixture(f);
}

const equal=(actual:unknown,expected:unknown)=>assert.equal(canonical(actual),canonical(expected));
function run(context:unknown){
 let checks=0,admissions=0;
 const result=compose({context,budget:{check(){checks++;},admitComposition(value){admissions++;assert.equal('allowed'in value,false);}}});
 assert.equal(admissions,1);assert.ok(checks>5);return result;
}
function refusal(context:unknown,outcome?:string){assert.throws(()=>run(context),(e:unknown)=>e instanceof DecisionInputError&&(outcome===undefined||e.outcome===outcome));}
function evaluated(context:unknown){const out=run(context),result=evaluateAuthority(out.bundle,out.registry);assert.equal(result.outcome,'evaluated',JSON.stringify(result.issues));assert.ok(result.root);return {out,result,root:result.root!};}
test('ordinary metadata composes immutable inert bundle with exact current registry, snapshots and reciprocal guard',()=>{
 const context=classified(),before=canonical(context),{out,root}=evaluated(context);
 assert.equal(root.allowed,true);assert.equal(out.bundle.nodes.length,2);assert.equal(out.bundle.snapshot.snapshotDigest,context.contextDigest);
 equal(out.registry,context.context.context.registry);equal(Object.keys(out).sort(),['bundle','registry']);
 const auth=out.bundle.nodes.find(n=>n.mode==='authorize')!,guard=out.bundle.nodes.find(n=>n.mode==='resource-wide-deny')!;
 assert.equal(auth.intentGuard,guard.id);assert.equal(guard.guardOrigin,auth.id);assert.equal(auth.resource.containment.securityRevision,'7');
 equal(auth.resource.containment.domainPath,{status:'known',value:[id(601),id(600)]});
 equal(out.bundle.sessions[0]!.validity,{notBefore:context.context.context.closure.session.issuedAt,expiresAt:context.context.context.closure.session.expiresAt});
 assert.equal(canonical(context),before);assert.ok(Object.isFrozen(out)&&Object.isFrozen(out.bundle));equal(run(context),out);
});
test('complete empty candidate inventory evaluates denial with authenticated root and guard',()=>{
 const f=makeDecisionFixture();f.bundle.grants=[];f.bundle.definitions=[];f.bundle.policies=[];for(const p of f.bundle.candidates)p.candidates=[];
 const {out,root}=evaluated(classified(f));assert.equal(root.allowed,false);assert.equal(out.bundle.nodes.length,2);assert.equal(out.bundle.candidates.length,2);
});
test('issuance-only ordinary principal stays in provenance but is omitted from evaluator catalogs',()=>{
 const f=makeDecisionFixture(),issuer=structuredClone(f.bundle.principals[0]!);issuer.id=id(91);if(issuer.kind!=='human'||issuer.membership===null)throw Error('fixture');issuer.membership.identityId=issuer.id;issuer.membership.ref.id=id(92);
 f.bundle.principals.push(issuer);f.bundle.grants[0]!.issuer={kind:'human',id:issuer.id};
 const context=classified(f),{out,root}=evaluated(context);assert.equal(root.allowed,true);assert.equal(context.context.context.closure.principals.length,2);equal(out.bundle.principals.map(p=>p.id),[id(2)]);
});
test('four connected edges preserve all child-specific issuer decisions and consuming-node links',()=>{
 const context=classified(makeFourEdgeFieldFixture(false)),{out,root}=evaluated(context);assert.equal(root.allowed,true);assert.equal(out.bundle.nodes.length,10);assert.equal(out.bundle.chainLinks.length,20);
 const issuers=out.bundle.nodes.filter(n=>n.mode==='authorize'&&n.authentication.kind==='live-issuer');assert.equal(issuers.length,4);
 for(const n of issuers){assert.equal(n.authentication.kind,'live-issuer');if(n.authentication.kind==='live-issuer')assert.equal(n.authentication.elevationSession,null);}
 for(const node of out.bundle.nodes){const p=out.bundle.candidates.find(c=>c.nodeId===node.id)!;equal(p.candidates,context.context.context.closure.partitions.find(p=>p.subject.id===node.subject.id)!.candidates);}
});
test('visibility applies to root and live issuers without removing complete ACL or candidate evidence',()=>{
 const rootDenied=classified();rootDenied.context.context.asset.visibility='restricted';rootDenied.context.context.asset.allowedIdentities=[id(99)];assert.equal(evaluated(reseal(rootDenied)).root.allowed,false);
 const issuerDenied=classified(makeFourEdgeFieldFixture(false));issuerDenied.context.context.asset.visibility='restricted';issuerDenied.context.context.asset.allowedIdentities=[id(2)];const {out,root}=evaluated(reseal(issuerDenied));assert.equal(root.allowed,false);assert.equal(out.bundle.grants.length,5);equal(out.bundle.visibility[0]!.allowedIdentities,[id(2)]);
});
test('unplaced asset uses known empty ancestry rather than unavailable or fabricated domain',()=>{
 const {out,root}=evaluated(classified(undefined,false));assert.equal(root.allowed,true);equal(out.bundle.nodes[0]!.resource.containment.domainPath,{status:'known',value:[]});equal(out.bundle.scopeAnchors,[]);
});
test('known, known-empty and unavailable classification partitions remain distinct and producer-bound',()=>{
 for(const populated of [false,true]){const c=classified(undefined,true,populated),{out,root}=evaluated(c);assert.equal(root.allowed,true);equal(out.bundle.approvedFacts,c.approvedFacts);equal(out.bundle.nodes[0]!.resource.classifications,c.classifications);equal(out.bundle.nodes[0]!.resource.approvedTags,{status:'unavailable'});}
 const c=classified();c.producerBinding=null;c.classifications={status:'unavailable'};const {out}=evaluated(reseal(c));equal(out.bundle.nodes[0]!.resource.classifications,{status:'unavailable'});
});
test('inactive canonical asset or ancestry is an explicit unsupported profile',()=>{
 for(const target of ['asset','domain']){const c=classified();if(target==='asset')c.context.context.asset.status='retired';else c.context.context.domainPath[0]!.status='retired';refusal(reseal(c),'unsupported');}
});
test('missing and ambiguous semantic metadata adapter refuse instead of selecting the first registration',()=>{
 for(const mode of ['missing','duplicate']){const c=classified(),r=c.context.context.registry;if(mode==='missing')r.adapters=r.adapters.filter(a=>a.branch!=='human-resource');else r.adapters.push({...r.adapters.find(a=>a.branch==='human-resource')!,id:'asset.alternative'});refusal(reseal(c),'unsupported');}
});
test('missing intent, unknown guard and different guard action never borrow metadata candidates',()=>{
 for(const mode of ['intent','guard','action']){const c=classified(),r=c.context.context.registry;if(mode==='intent')r.intentContexts=[];else if(mode==='guard')r.intentContexts[0]!.guardAdapterId='missing.guard';else{r.intentContexts[0]!.denyContextAction='asset:description.edit';r.adapters.find(a=>a.branch==='intent-guard')!.action='asset:description.edit';}refusal(reseal(c));}
});
test('unsupported ceiling, containment and elevation profiles fail closed',()=>{
 for(const mutate of [(a:any)=>{a.ceilings=[];},(a:any)=>{a.ceilings=[{slot:'creator',kind:'creator'}];},(a:any)=>{a.containment='none';},(a:any)=>{a.dependencyElevation='exact-live-session';}]){const c=classified();mutate(c.context.context.registry.adapters.find(a=>a.branch==='human-resource'));refusal(reseal(c));}
});
test('stale outer digest, stale security revision and wrong session do not produce composition',()=>{
 for(const mutate of [(c:Mutable<InactiveClassifiedAssetContext>)=>{c.contextDigest=zero;},(c:Mutable<InactiveClassifiedAssetContext>)=>{c.context.securityRevision='8' as Counter;},(c:Mutable<InactiveClassifiedAssetContext>)=>{c.context.context.closure.session.identityId=id(88);}]){const c=classified();mutate(c);refusal(c,'invalid');}
});
test('coherently resealed missing connected dependency, parent or principal still fails completeness',()=>{
 for(const target of ['dependency','parent','principal']){const c=classified(makeFourEdgeFieldFixture(false)),closure=c.context.context.closure;if(target==='dependency')closure.dependencies.pop();else if(target==='parent')closure.parents.pop();else closure.principals.pop();refusal(reseal(c),'invalid');}
});
test('deadline checks and complete aggregate admission propagate exact caller errors without resets',()=>{
 const c=classified(),sentinel=Error('shared deadline');let admitted=0,checks=0;
 assert.throws(()=>compose({context:c,budget:{check(){if(++checks===3)throw sentinel;},admitComposition(){admitted++;}}}),e=>e===sentinel);assert.equal(admitted,0);
 assert.throws(()=>compose({context:c,budget:{check(){},admitComposition(){admitted++;throw sentinel;}}}),e=>e===sentinel);assert.equal(admitted,1);
 let complete=false;assert.throws(()=>compose({context:c,budget:{check(){if(complete)throw sentinel;},admitComposition(){complete=true;}}}),e=>e===sentinel);
});
test('malicious accessors and proxies cannot run while context is admitted',()=>{
 let touched=false;const c=classified(),hostile={...c};Object.defineProperty(hostile,'context',{enumerable:true,get(){touched=true;return c.context;}});refusal(hostile,'invalid');refusal(new Proxy(c,{ownKeys(){touched=true;return [];}}),'invalid');assert.equal(touched,false);
});
test('two children from the same issuer retain distinct child-bound nodes while sharing canonical partition',()=>{
 const c=classified(parallelChildren(2)),{out,root}=evaluated(c);assert.equal(root.allowed,true);assert.equal(c.context.context.closure.partitions.length,2);assert.equal(out.bundle.nodes.length,6);
 const issuers=out.bundle.nodes.filter(n=>n.mode==='authorize'&&n.authentication.kind==='live-issuer');assert.equal(issuers[0]!.subject.id,issuers[1]!.subject.id);assert.notEqual(issuers[0]!.id,issuers[1]!.id);assert.equal(out.bundle.chainLinks.length,4);
});
test('actual child-specific expansion admits 128 contexts and refuses 130 before aggregate callback',()=>{
 const boundary=classified(parallelChildren(63));assert.equal(run(boundary).bundle.nodes.length,128);
 const over=classified(parallelChildren(64));let admissions=0;assert.throws(()=>compose({context:over,budget:{check(){},admitComposition(){admissions++;}}}),e=>e instanceof DecisionInputError&&e.outcome==='profile_limit');assert.equal(admissions,0);
});
test('connected scope attenuation derives only exact asset or ancestor suffix anchors',()=>{
 for(const target of ['domain','asset']){
  const f=makeFourEdgeFieldFixture(false),parent={kind:'domain' as const,tenantId:id(1),domainId:id(600),includeDescendants:true};
  const child=target==='domain'?{...parent,domainId:id(601)}:{kind:'resource' as const,resource:f.bundle.nodes[0]!.request.resource};
  for(const g of f.bundle.grants){g.scope=g.kind==='ordinary-role'?parent:child;g.ceiling={...g.ceiling,scope:g.scope};if('delegable'in g&&g.delegable)g.delegable.scope=g.scope;}
  const {out,root}=evaluated(classified(f));assert.equal(root.allowed,true);assert.equal(out.bundle.scopeAnchors.length,1);const anchor=out.bundle.scopeAnchors[0]!;
  assert.equal(anchor.containment.revision,target==='domain'?3:1);equal(anchor.containment.domainPath,{status:'known',value:[id(601),id(600)]});assert.equal(anchor.containment.securityRevision,'7');
 }
});
test('required off-path scope refuses unsupported; direct-domain widening refuses invalid',()=>{
 for(const offPath of [false,true]){const f=makeFourEdgeFieldFixture(false),parent={kind:'domain' as const,tenantId:id(1),domainId:id(600),includeDescendants:offPath};
  for(const g of f.bundle.grants){g.scope=g.kind==='ordinary-role'?parent:{...parent,domainId:id(offPath?999:601)};g.ceiling={...g.ceiling,scope:g.scope};if('delegable'in g&&g.delegable)g.delegable.scope=g.scope;}
  const c=classified(f);parsed(parseInactiveClassifiedAssetContext(c));refusal(c,offPath?'unsupported':'invalid');
 }
});
test('future grants and retired pinned definitions remain complete and cannot become current allows',()=>{
 const future=classified(),g=future.context.context.closure.grants[0]!;g.validity={notBefore:'2026-11-16T06:10:00.000Z' as UTC,expiresAt:null};g.ceiling.validity={...g.validity};const a=evaluated(reseal(future));assert.equal(a.root.allowed,false);assert.equal(a.out.bundle.grants.length,1);
 const retired=classified(),d=retired.context.context.closure.definitions[0]!;d.state='retired';const b=evaluated(reseal(retired));assert.equal(b.root.allowed,false);assert.equal(b.out.bundle.definitions[0]!.state,'retired');
});
test('resource-wide deny retains exact complete candidate inventory and marker registry pin',()=>{
 const f=makeWideBindingFixture(1,1,1,true),{out,root}=evaluated(classified(f));assert.equal(root.allowed,false);assert.equal(out.bundle.candidates.length,2);assert.equal(out.bundle.candidates[0]!.candidates.length,1);assert.equal(out.bundle.policies[0]!.resourceWideIntents[0]!.registryDigest,out.registry.digest);
});
test('canonical scope alignment accepts a narrowed grant and rejects widening before composition',()=>{
 const c=classified(),g=c.context.context.closure.grants[0]!;g.ceiling.scope={kind:'domain',tenantId:id(1),domainId:id(601),includeDescendants:true};
 assert.equal(parseInactiveClassifiedAssetContext(reseal(c)).ok,false);refusal(c,'invalid');
 const narrowed=classified(),grant=narrowed.context.context.closure.grants[0]!;
 grant.scope={kind:'domain',tenantId:id(1),domainId:id(601),includeDescendants:true};
 const result=evaluated(reseal(narrowed));assert.equal(result.root.allowed,true);
});
test('root elevation preserves current, future, null and other-session selection without borrowing live-issuer authentication',()=>{
 for(const mode of ['current','future','null','other-session']){
  const c=JSON.parse(JSON.stringify(classified(parallelChildren(1)))) as Mutable<InactiveClassifiedAssetContext>,closure=c.context.context.closure;
  const old=closure.grants.find(g=>g.kind==='delegation')!;if(old.kind!=='delegation')throw Error('fixture');
  const oldKey=grantKey(old.ref),ref={...old.ref,kind:'elevation' as const},validity={notBefore:'2026-11-16T05:30:00.000Z' as UTC,expiresAt:'2026-11-16T06:30:00.000Z' as UTC};
  const use={id:id(9901),version:v,state:'active' as const,identityId:id(2),sessionId:mode==='other-session'?id(9902):closure.session.sessionId,sessionVersion:v,generation:'1' as Counter,validity:{notBefore:(mode==='future'?'2026-11-16T06:05:00.000Z':'2026-11-16T05:35:00.000Z') as UTC,expiresAt:'2026-11-16T06:15:00.000Z' as UTC}};
  const {delegable:ignored,...base}=old;
  closure.grants=closure.grants.map(g=>grantKey(g.ref)===oldKey?{...base,kind:'elevation',ref,validity,ceiling:{...base.ceiling,validity},use:mode==='null'||mode==='other-session'?null:use}:g);
  for(const p of closure.partitions)p.candidates=p.candidates.map(r=>grantKey(r)===oldKey?ref:r);
  for(const p of closure.parents){if(grantKey(p.child)===oldKey)p.child=ref;if(grantKey(p.parent)===oldKey)p.parent=ref;}
  for(const d of closure.dependencies)if(grantKey(d.child)===oldKey)d.child=ref;
  if(mode!=='null'){closure.elevationUses=[{ref:{id:use.id,version:use.version},elevation:ref,identityId:use.identityId,sessionId:use.sessionId,sessionVersion:use.sessionVersion,generation:use.generation,state:use.state,validity:use.validity}];closure.lifecycleHeads.push({family:'elevation-use',definitionKind:null,id:use.id,headVersion:v});}
  const {out,root}=evaluated(reseal(c));assert.equal(root.allowed,mode==='current');
  const copied=out.bundle.grants.find(g=>g.kind==='elevation')!;assert.equal(copied.kind,'elevation');if(copied.kind==='elevation')equal(copied.use,mode==='null'||mode==='other-session'?null:use);
  for(const n of out.bundle.nodes)if(n.authentication.kind==='live-issuer')assert.equal(n.authentication.elevationSession,null);
 }
});
test('historical group parent membership remains in complete proof and makes revoked path ineffective',()=>{
 for(const revoked of [false,true]){
  const c=classified(makeFourEdgeFieldFixture(false)),closure=c.context.context.closure,origin=closure.grants.find(g=>g.kind==='ordinary-role')!;
  const issuer=origin.beneficiary.id,group=id(9950),membership={id:id(9951),version:v};origin.beneficiary={kind:'group',id:group};
  closure.groups.push({id:group,tenantId:id(1),revision:'1' as Counter,state:'active'});
  closure.memberships.push({ref:membership,tenantId:id(1),groupId:group,identityId:issuer,state:revoked?'revoked':'active',validity:{notBefore:null,expiresAt:null}});
  closure.parents.find(p=>grantKey(p.parent)===grantKey(origin.ref))!.viaMembership=membership;
  closure.principalGroups.find(p=>p.subject.id===issuer)!.memberships={status:'known',value:[membership]};
  if(revoked)closure.partitions.find(p=>p.subject.id===issuer)!.candidates=[];
  closure.lifecycleHeads.push({family:'definition',definitionKind:'group',id:group,headVersion:v},{family:'group-membership',definitionKind:null,id:membership.id,headVersion:(revoked?2:1) as Version});
  const {out,root}=evaluated(reseal(c));assert.equal(root.allowed,!revoked);assert.equal(out.bundle.memberships.length,1);assert.equal(out.bundle.memberships[0]!.state,revoked?'revoked':'active');
 }
});
