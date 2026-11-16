// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { parseDecisionInput, parseDecisionInputFile, canonicalDecisionJSON } from '../../packages/authority/src/decision-schema.ts';
import { authorityNodeIdentity, authorityAnchorDigest, hashAuthorityRegistry, hashAuthorityDefinition, validateDecisionIdentities } from '../../packages/authority/src/decision-identity.ts';
import type { DecisionCatalogs, NodeDescriptor } from '../../packages/authority/src/decision-types.ts';
import { makeDecisionFixture, sealDecisionFixture, parsed, id, v, zero } from './fixtures/authority-decision.ts';
import { makeServiceFixture } from './fixtures/authority-service.ts';

const failure = (result: ReturnType<typeof parseDecisionInput>, code?:string) => {
 assert.equal(result.ok,false); if(result.ok)throw new Error('Expected refusal');
 if(code)assert.equal(result.issues[0]!.code,code); return result.issues;
};
function descriptor(f:ReturnType<typeof makeDecisionFixture>,index=0):NodeDescriptor{const {id:_id,factDigest:_fact,...rest}=f.bundle.nodes[index]!;return rest;}
function catalogs(f:ReturnType<typeof makeDecisionFixture>):DecisionCatalogs{const {formatVersion:_f,snapshot:_s,root:_r,nodes:_n,candidates:_c,chainLinks:_l,...rest}=f.bundle;return rest;}
function nodeIdentity(f:ReturnType<typeof makeDecisionFixture>,index=0){return parsed(authorityNodeIdentity(f.bundle.snapshot,descriptor(f,index),catalogs(f),f.registry,index?descriptor(f):null));}

test('closed schema accepts a complete exact human/guard bundle without mutating inputs',()=>{
 const f=makeDecisionFixture(),before=JSON.stringify(f),input=parsed(parseDecisionInput(f.bundle,f.registry));
 validateDecisionIdentities(input); assert.equal(JSON.stringify(f),before);
 assert.ok(Object.isFrozen(input.bundle.nodes));assert.ok(Object.isFrozen(input.bundle.nodes[0]));
 assert.equal(input.parsedPolicies.size,1);assert.equal(input.indexes.nodes.size,2);
});
test('schema refuses unknown nested fields and duplicate record identities',()=>{
 const f=makeDecisionFixture();(f.bundle.sessions[0] as unknown as Record<string,unknown>).role='administrator';failure(parseDecisionInput(f.bundle,f.registry),'unknown_field');
 const other=makeDecisionFixture();other.bundle.sessions.push(structuredClone(other.bundle.sessions[0]!));failure(parseDecisionInput(other.bundle,other.registry),'duplicate');
});
test('defensive admission rejects accessors and proxies without invoking either',()=>{
 const f=makeDecisionFixture();let touches=0;const accessor={...f.registry};Object.defineProperty(accessor,'fields',{enumerable:true,get(){touches++;return [];}});
 failure(parseDecisionInput(f.bundle,accessor));const proxy=new Proxy(f.bundle,{ownKeys(){touches++;throw Error('untrusted trap');}});failure(parseDecisionInput(proxy,f.registry));assert.equal(touches,0);
});
test('raw bundle parser rejects duplicate JSON keys and combines registry bytes with the raw allowance',()=>{
 const f=makeDecisionFixture(),raw=JSON.stringify(f.bundle);assert.equal(raw[0],'{');failure(parseDecisionInputFile('{"formatVersion":1,'+raw.slice(1),f.registry),'duplicate');
 const padded=raw+' '.repeat(8_388_608-Buffer.byteLength(raw));failure(parseDecisionInputFile(padded,f.registry),'limit');
});
test('embedded policy documents retain independent raw64KiB and duplicate-key admission',()=>{
 const f=makeDecisionFixture();f.bundle.policies[0]!.document=' '.repeat(65_537)+f.bundle.policies[0]!.document;failure(parseDecisionInput(f.bundle,f.registry),'limit');
 const g=makeDecisionFixture(),raw=g.bundle.policies[0]!.document;assert.equal(raw[0],'{');g.bundle.policies[0]!.document='{"formatVersion":1,'+raw.slice(1);failure(parseDecisionInput(g.bundle,g.registry),'duplicate');
});
test('registry and immutable definition/policy hashes cannot be caller-forged',()=>{
 const f=makeDecisionFixture();f.registry.digest=zero;failure(parseDecisionInput(f.bundle,f.registry),'version');
 const g=makeDecisionFixture();g.bundle.definitions[0]!.hash=zero;failure(parseDecisionInput(g.bundle,g.registry),'version');
 const h=makeDecisionFixture();h.bundle.policies[0]!.pin.hash=zero;failure(parseDecisionInput(h.bundle,h.registry),'version');
});
test('all literal actions and exact service branch mappings are mandatory',()=>{
 const f=makeDecisionFixture();const {digest:_d,...missing}=f.registry;missing.actions=missing.actions.slice(1);assert.equal(hashAuthorityRegistry(missing).ok,false);
 const g=makeDecisionFixture();g.registry.adapters[0]!.branch='service-secret';const {digest:_g,...wrong}=g.registry;assert.equal(hashAuthorityRegistry(wrong).ok,false);
});
test('set normalization gives exact order-independent registry hashes while preserving document bytes',()=>{
 const f=makeDecisionFixture();const {digest:original,...content}=f.registry;content.actions.reverse();content.adapters.reverse();assert.equal(parsed(hashAuthorityRegistry(content)),original);
 const input=parsed(parseDecisionInput(f.bundle,{...content,digest:original}));assert.equal(input.bundle.policies[0]!.document,f.bundle.policies[0]!.document);
});
test('canonical hashing has an independent sorted-key oracle including escaped strings',()=>{
 const f=makeDecisionFixture(),definition=f.bundle.definitions[0]!;
 const d={formatVersion:definition.formatVersion,kind:definition.kind,id:definition.id,version:definition.version,content:definition.content};
 const c=(x:unknown):string=>Array.isArray(x)?'['+x.map(c).join(',')+']':x!==null&&typeof x==='object'?'{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+c((x as Record<string,unknown>)[k])).join(',')+'}':JSON.stringify(x);
 const expected=createHash('sha256').update(c(d)).digest('hex');assert.equal(parsed(hashAuthorityDefinition(d)),expected);
 assert.equal(canonicalDecisionJSON({z:'a\n"\\',a:1}),c({z:'a\n"\\',a:1}));
});
test('exact current head and tenant associations are checked before use',()=>{
 const f=makeDecisionFixture();f.bundle.policies[0]!.pin.version=2 as typeof v;failure(parseDecisionInput(f.bundle,f.registry),'version');
 const g=makeDecisionFixture();g.bundle.sessions[0]!.selectedTenantId=id(99);const input=parsed(parseDecisionInput(g.bundle,g.registry));assert.throws(()=>validateDecisionIdentities(input));
 const h=makeDecisionFixture();h.bundle.grants[0]!.tenantId=id(99);failure(parseDecisionInput(h.bundle,h.registry),'scope');
});
test('candidate partitions bind exact snapshot, actor, request and anchor',()=>{
 for(const change of ['snapshot','actor','anchor'] as const){const f=makeDecisionFixture(),c=f.bundle.candidates[0]!;if(change==='snapshot')c.snapshotDigest=zero;else if(change==='actor')c.subject={...c.subject,id:id(99)};else c.anchorDigest=zero;failure(parseDecisionInput(f.bundle,f.registry),'version');}
 const f=makeDecisionFixture();f.bundle.candidates.pop();failure(parseDecisionInput(f.bundle,f.registry),'required');
});
test('node identities include Known empty versus Unavailable group partitions',()=>{
 const f=makeDecisionFixture(),known=nodeIdentity(f);f.bundle.principalGroups[0]!.memberships={status:'unavailable'};const unavailable=nodeIdentity(f);
 assert.notEqual(known.factDigest,unavailable.factDigest);assert.notEqual(known.nodeId,unavailable.nodeId);
});
test('node identities bind current principal records and enforce the full actual origin tuple',()=>{
 const f=makeDecisionFixture(),before=nodeIdentity(f);const human=f.bundle.principals[0]!;assert.equal(human.kind,'human');if(human.kind==='human')human.active=false;assert.notEqual(nodeIdentity(f).nodeId,before.nodeId);
 const g=makeDecisionFixture(),bad=descriptor(g);bad.request={...bad.request,revision:2 as typeof v};assert.equal(authorityNodeIdentity(g.bundle.snapshot,descriptor(g,1),catalogs(g),g.registry,bad).ok,false);
});
test('dependency IDs are excluded from context hashes but reciprocal guard references remain mandatory',()=>{
 const f=makeDecisionFixture(),before=nodeIdentity(f);f.bundle.nodes[0]!.intentGuard=zero;assert.equal(nodeIdentity(f).nodeId,before.nodeId);
 assert.throws(()=>validateDecisionIdentities(parsed(parseDecisionInput(f.bundle,f.registry))),/reciprocal/);
});
test('schema rejects malformed dates, negative zero and cross-kind field requests',()=>{
 const f=makeDecisionFixture();f.bundle.snapshot.now='2026-02-30T00:00:00.000Z' as typeof f.bundle.snapshot.now;failure(parseDecisionInput(f.bundle,f.registry),'format');
 const g=makeDecisionFixture();g.bundle.nodes[0]!.request.revision=-0 as typeof v;failure(parseDecisionInput(g.bundle,g.registry));
 const h=makeDecisionFixture();h.bundle.nodes[0]!.request.field='asset.name' as never;failure(parseDecisionInput(h.bundle,h.registry),'scope');
});
test('field catalog admission rejects overlong identifiers and excessive cumulative bytes',()=>{
 const f=makeDecisionFixture();const {digest:_d,...r}=f.registry;r.fields=['x'.repeat(257) as never];assert.equal(hashAuthorityRegistry(r).ok,false);
 r.fields=Array.from({length:513},(_,i)=>(String(i).padStart(3,'0')+'x'.repeat(253)) as never);assert.equal(hashAuthorityRegistry(r).ok,false);
});
test('a resealed coherent fixture passes while a post-seal fact edit is detected',()=>{
 const f=makeDecisionFixture();f.bundle.principalGroups[0]!.memberships={status:'unavailable'};sealDecisionFixture(f);validateDecisionIdentities(parsed(parseDecisionInput(f.bundle,f.registry)));
 f.bundle.sessions[0]!.version=2 as typeof v;const input=parsed(parseDecisionInput(f.bundle,f.registry));assert.throws(()=>validateDecisionIdentities(input),/session/);
 const anchor=parsed(authorityAnchorDigest(f.bundle.nodes[0]!.resource));assert.equal(anchor,f.bundle.candidates[0]!.anchorDigest);
});

test('selected visibility and creator ceilings bind their exact records into node hashes',()=>{
 for(const kind of ['visibility','creator'] as const){
  const f=makeDecisionFixture(),node=f.bundle.nodes[0]!;
  f.registry.adapters.find(row=>row.id===node.adapterId)!.ceilings=[{slot:'resource',kind}];
  node.ceilingRefs=[{slot:'resource',recordId:'exact-resource-ceiling'}];
  if(kind==='visibility')f.bundle.visibility=[{id:'exact-resource-ceiling',resource:node.request.resource,revision:node.request.revision,visibility:'restricted',allowedIdentities:[node.subject.id]}];
  else f.bundle.creators=[{id:'exact-resource-ceiling',resource:node.request.resource,creator:node.subject}];
  sealDecisionFixture(f);const before=nodeIdentity(f);
  if(kind==='visibility')f.bundle.visibility[0]!.allowedIdentities=[];else f.bundle.creators[0]!.creator={kind:'human',id:id(99)};
  const after=nodeIdentity(f);assert.notEqual(after.factDigest,before.factDigest);assert.notEqual(after.nodeId,before.nodeId);
 }
});
test('unknown hostile keys cannot amplify schema diagnostic paths',()=>{
 const f=makeDecisionFixture();const extra={...f.bundle,['x'.repeat(100_000)]:true};
 const issues=failure(parseDecisionInput(extra,f.registry),'unknown_field');assert.ok(issues[0]!.path.length<=1024);assert.ok(issues.length<=64);
});

test('finite grant field ceilings require exact registered field identifiers',()=>{
 const f=makeDecisionFixture();f.bundle.grants[0]!.ceiling.fields=['unregistered.field' as never];failure(parseDecisionInput(f.bundle,f.registry),'scope');
});


test('projection syntax requires a closed apply/replay mode and immutable action/request commitment',()=>{
 for(const kind of ['project-consume','project-write'] as const){
  const f=makeServiceFixture(kind);assert.equal(parseDecisionInput(f.bundle,f.registry).ok,true);
  for(const key of ['requestAction','requestHash']){
   const copy=structuredClone(f);delete (copy.bundle.projectionEvents[0] as unknown as Record<string,unknown>)[key];
   failure(parseDecisionInput(copy.bundle,copy.registry),'required');
  }
  const noMode=structuredClone(f);delete (noMode.bundle.nodes[0]!.service as unknown as Record<string,unknown>).mode;
  failure(parseDecisionInput(noMode.bundle,noMode.registry),'required');
  const wrongMode=structuredClone(f);(wrongMode.bundle.nodes[0]!.service as unknown as Record<string,unknown>).mode='replace';
  failure(parseDecisionInput(wrongMode.bundle,wrongMode.registry),'unsupported');
  const wrongAction=structuredClone(f);(wrongAction.bundle.projectionEvents[0] as unknown as Record<string,unknown>).requestAction='source:metadata.scan';
  failure(parseDecisionInput(wrongAction.bundle,wrongAction.registry),'unsupported');
 }
});
test('projection node identity binds immutable request action/hash and apply/replay mode',()=>{
 for(const edit of [
  (f:ReturnType<typeof makeServiceFixture>)=>{f.bundle.projectionEvents[0]!.requestHash='f'.repeat(64) as typeof zero;},
  (f:ReturnType<typeof makeServiceFixture>)=>{f.bundle.projectionEvents[0]!.requestAction='projection:consume';},
  (f:ReturnType<typeof makeServiceFixture>)=>{const use=f.bundle.nodes[0]!.service;assert.ok(use?.kind==='project-write');use.mode='replay';},
 ]){
  const f=makeServiceFixture('project-write'),before=nodeIdentity(f);edit(f);const after=nodeIdentity(f);
  assert.notEqual(after.nodeId,before.nodeId);
  const input=parsed(parseDecisionInput(f.bundle,f.registry));assert.throws(()=>validateDecisionIdentities(input),/identity/);
 }
});
