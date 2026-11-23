// SPDX-License-Identifier: Apache-2.0
// Canonical storage admission must preserve the evaluator containment contract.
import assert from 'node:assert/strict';
import test from 'node:test';
import {parseAuthorityHumanClosure as repaired} from '../../packages/authority-storage/src/loader.ts';
import {makeDecisionFixture,sealDecisionFixture,id,parsed,type DecisionFixture} from './fixtures/authority-decision.ts';
import {makeFourEdgeFieldFixture} from './fixtures/authority-decision-chain.ts';
import {classified,sealClosure} from './fixtures/held-metadata.ts';
import {evaluateAuthority} from '../../packages/authority/src/decisions.ts';
import {canonicalDecisionJSON} from '../../packages/authority/src/decision-schema.ts';
import type {Scope,UTC,Validity} from '../../packages/authority/src/types.ts';
const tenant:Scope={kind:'tenant',tenantId:id(1)},domain:Scope={kind:'domain',tenantId:id(1),domainId:id(601),includeDescendants:true},asset:Scope={kind:'resource',resource:{tenantId:id(1),kind:'asset',id:id(3)}};
const eternal:Validity={notBefore:null,expiresAt:null};
const interval=(a:string|null,b:string|null):Validity=>({notBefore:a===null?null:`2026-11-16T${a}:00.000Z` as UTC,expiresAt:b===null?null:`2026-11-16T${b}:00.000Z` as UTC});
const fixture=(chain=false)=>structuredClone(chain?makeFourEdgeFieldFixture(false):makeDecisionFixture());
function closure(f:DecisionFixture){const inner=classified(f).context.context;return {c:inner.closure,r:inner.registry};}
function admit(f:DecisionFixture){const {c,r}=closure(f),before=canonicalDecisionJSON(c),out=parsed(repaired(c,r));assert.equal(canonicalDecisionJSON(c),before);return out;}
function refuse(f:DecisionFixture){const {c,r}=closure(f),out=repaired(c,r);assert.equal(out.ok,false);return out;}
function onward(f:DecisionFixture,scope:Scope,validity:Validity=eternal){const g=f.bundle.grants[0]!;if(g.kind!=='ordinary-role')throw Error('fixture');g.delegable={actions:['asset:metadata.read'],fields:null,scope,validity,remainingDepth:4};}
test('corrected own scope admits domain/resource within tenant effect ceiling and agrees with pure evaluator',()=>{
 for(const scope of [domain,asset]){const f=fixture(),g=f.bundle.grants[0]!;g.scope=scope;g.ceiling={...g.ceiling,scope:tenant};
  for(const node of f.bundle.nodes)node.resource.containment.domainPath={status:'known',value:[id(601),id(600)]};sealDecisionFixture(f);
  const {c,r}=closure(f);admit(f);const e=evaluateAuthority(f.bundle,f.registry);assert.equal(e.outcome,'evaluated');assert.equal(e.root!.allowed,true);
 }
});
test('reversed own widening now refuses instead of merely accepting the old storage relation',()=>{
 for(const scope of [domain,asset]){const f=fixture(),g=f.bundle.grants[0]!;g.scope=tenant;g.ceiling={...g.ceiling,scope};const {c,r}=closure(f);refuse(f);}
});
test('own scope preserves equal tenant/domain/resource and exact same-domain descendants direction',()=>{
 for(const scope of [tenant,domain,asset]){const f=fixture(),g=f.bundle.grants[0]!;g.scope=scope;g.ceiling={...g.ceiling,scope};admit(f);}
 const f=fixture(),g=f.bundle.grants[0]!;g.scope=domain;g.ceiling={...g.ceiling,scope:{...domain,includeDescendants:false}};refuse(f);
 g.scope={...domain,includeDescendants:false};g.ceiling={...g.ceiling,scope:domain};admit(f);
});
test('onward scope must fit both grant and effect scope after own direction correction',()=>{
 const f=fixture(),g=f.bundle.grants[0]!;g.scope=asset;g.ceiling={...g.ceiling,scope:tenant};onward(f,asset);admit(f);onward(f,tenant);refuse(f);
 const d=fixture(),h=d.bundle.grants[0]!;h.scope=domain;h.ceiling={...h.ceiling,scope:domain};onward(d,tenant);refuse(d);
});
test('connected child effect cannot escape parent onward ceiling when its own grant scope is narrow',()=>{
 const f=fixture(true);
 for(const g of f.bundle.grants){g.scope=asset;g.ceiling={...g.ceiling,scope:tenant};if('delegable'in g&&g.delegable)g.delegable={...g.delegable,scope:asset};}
 // Make every child effect fit the protected parent onward scope first.
 for(const g of f.bundle.grants)if(g.kind!=='ordinary-role')g.ceiling={...g.ceiling,scope:asset};admit(f);
 f.bundle.grants[1]!.ceiling={...f.bundle.grants[1]!.ceiling,scope:tenant};refuse(f);
});
test('connected child effect cannot escape parent effect ceiling even when target scope fits',()=>{
 const f=fixture(true);for(const g of f.bundle.grants){g.scope=asset;g.ceiling={...g.ceiling,scope:asset};if('delegable'in g&&g.delegable)g.delegable={...g.delegable,scope:asset};}admit(f);
 f.bundle.grants[1]!.ceiling={...f.bundle.grants[1]!.ceiling,scope:tenant};refuse(f);
});
test('connected child grant must fit parent grant, effect and onward scopes independently',()=>{
 for(const family of ['grant','effect','onward']){const f=fixture(true),p=f.bundle.grants[0]!;if(p.kind!=='ordinary-role'||!p.delegable)throw Error('fixture');
  if(family==='grant'){p.scope=asset;p.delegable.scope=asset;}
  if(family==='effect'){p.scope=asset;p.ceiling={...p.ceiling,scope:asset};p.delegable.scope=asset;}
  if(family==='onward')p.delegable.scope=asset;
  refuse(f);
 }
});
test('canonical effect validity remains inside own grant even though generic evaluator permits intersection',()=>{
 const f=fixture(),g=f.bundle.grants[0]!;g.validity=interval('05:30','06:30');g.ceiling={...g.ceiling,validity:interval('05:45','06:15')};admit(f);
 for(const invalid of [eternal,interval('05:00','06:15'),interval('05:45','07:00')]){g.ceiling={...g.ceiling,validity:invalid};refuse(f);sealDecisionFixture(f);assert.equal(evaluateAuthority(f.bundle,f.registry).outcome,'evaluated');}
});
test('onward validity cannot erase own grant or effect finite bounds',()=>{
 for(const invalid of [eternal,interval('05:00','06:15'),interval('05:45','07:00')]){const f=fixture(),g=f.bundle.grants[0]!;g.validity=interval('05:30','06:30');g.ceiling={...g.ceiling,validity:interval('05:45','06:15')};onward(f,tenant,g.ceiling.validity);admit(f);onward(f,tenant,invalid);refuse(f);}
});
test('child lifetime must fit both parent effect and onward validity, not merely its own effect',()=>{
 for(const bound of ['effect','onward']){const f=fixture(true);for(const g of f.bundle.grants){g.validity=interval('05:00','07:00');g.ceiling={...g.ceiling,validity:interval('05:30','06:30')};if('delegable'in g&&g.delegable)g.delegable={...g.delegable,validity:interval('05:30','06:30')};}
  if(bound==='onward')f.bundle.grants[0]!.ceiling={...f.bundle.grants[0]!.ceiling,validity:interval('05:00','07:00')};refuse(f);
  for(const g of f.bundle.grants)if(g.kind!=='ordinary-role')g.validity=interval('05:30','06:30');admit(f);
 }
});
test('finite equal child lifetime boundaries succeed and null endpoints cannot widen parents',()=>{
 const f=fixture(true);for(const g of f.bundle.grants){g.validity=interval('05:30','06:30');g.ceiling={...g.ceiling,validity:g.validity};if('delegable'in g&&g.delegable)g.delegable={...g.delegable,validity:g.validity};}admit(f);
 for(const invalid of [interval(null,'06:30'),interval('05:30',null),eternal]){const copy=structuredClone(f);copy.bundle.grants[1]!.validity=invalid;refuse(copy);}
});
test('revoked retained parent remains in complete graph and structural widening never becomes an exemption',()=>{
 const f=fixture(true),{c,r}=closure(f),origin=c.grants.find(g=>g.kind==='ordinary-role')!;origin.state='revoked';c.lifecycleHeads.find(h=>h.family==='grant'&&h.id===origin.ref.id)!.headVersion=2 as never;
 c.partitions.find(p=>p.subject.id===origin.beneficiary.id)!.candidates=[];sealClosure(c);parsed(repaired(c,r));
 origin.ceiling.scope=asset;sealClosure(c);assert.equal(repaired(c,r).ok,false);
});
test('future candidates and malformed complete inventories remain checked without pruning',()=>{
 const f=fixture(true);for(const g of f.bundle.grants){g.validity=interval('06:10','06:30');g.ceiling={...g.ceiling,validity:g.validity};if('delegable'in g&&g.delegable)g.delegable={...g.delegable,validity:g.validity};}
 const {c,r}=closure(f);parsed(repaired(c,r));c.dependencies.pop();sealClosure(c);assert.equal(repaired(c,r).ok,false);
});
