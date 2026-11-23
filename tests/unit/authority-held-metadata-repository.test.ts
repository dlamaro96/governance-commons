// SPDX-License-Identifier: Apache-2.0
// Synthetic native-query boundary only. Composer, parser and evaluator are real;
// these cases do not qualify PostgreSQL, runtime activation or a body executor.
import assert from 'node:assert/strict';
import test from 'node:test';
import {performance} from 'node:perf_hooks';
import {createAuthorityFoundationRepository} from '../../packages/authority-storage/src/repository.ts';
import {composeHeldHumanMetadataDecision as compose} from '../../packages/authority-runtime/src/held-metadata-composition.ts';
import {classified,reseal} from './fixtures/held-metadata.ts';
import {sourceProof} from './fixtures/reviewed-classification-proof.ts';
import {evaluateAuthority} from '../../packages/authority/src/decisions.ts';
import {admitAuthorityInput,AUTHORITY_ADMISSION_LIMITS as limits} from '../../packages/authority/src/admission.ts';
import {canonicalDecisionJSON as canonical,decisionHash} from '../../packages/authority/src/decision-schema.ts';
import {AuthorityFoundationError,type NativeOwnerPool} from '../../packages/authority-storage/src/contracts.ts';
import {makeDecisionFixture,makeWideBindingFixture,sealDecisionFixture,id,v,zero,parsed,type Mutable} from './fixtures/authority-decision.ts';
import type {ReviewedClassificationProducerSnapshot,InactiveClassifiedAssetContext} from '../../packages/authority-runtime/src/classified-asset-context.ts';
import type {Digest} from '../../packages/authority/src/types.ts';

const bytes=(value:unknown)=>Buffer.byteLength(canonical(value));
function producer(context:Mutable<InactiveClassifiedAssetContext>):ReviewedClassificationProducerSnapshot {
 const s=context.context.context.closure.snapshot;return {formatVersion:1,tenantId:s.tenantId,generation:s.generation,authorityEpoch:s.authorityEpoch,registryId:s.registryId,registryVersion:s.registryVersion,registryDigest:s.registryDigest,asOf:s.asOf,binding:context.producerBinding};
}
function protocol(context=classified(),proofs:any[]=[]){
 const inner=context.context.context,calls:Array<{text:string;values?:unknown[]}>=[],releases:boolean[]=[];
 const registryText=canonical(inner.registry),metrics=parsed(admitAuthorityInput(inner.registry)).metrics;
 let connections=0,sessionReads=0;
 const control:{beforeQuery?:(text:string,sessionReads:number)=>void;finalSession?:unknown}={};
 const pool:NativeOwnerPool={async connect(){connections++;return {async query(text,values){
  calls.push({text,values});control.beforeQuery?.(text,sessionReads);
  if(text.includes(' AS native_owner'))return {rows:[{native_owner:true}]};
  if(text.includes('FROM gc_authn.foundation_session_v1')){sessionReads++;return {rows:[{session:sessionReads===2&&control.finalSession!==undefined?control.finalSession:inner.closure.session}]};}
  if(text.includes("current_setting('gc.tenant_id',true) AS tenant"))return {rows:[{tenant:id(990),actor:id(991)}]};
  if(text.includes(' AS acl_type'))return {rows:[{version:inner.asset.version,status_valid:true,visibility_valid:true,acl_type:'array',acl_bytes:String(bytes(inner.asset.allowedIdentities)),acl_count:String(inner.asset.allowedIdentities.length)}]};
  if(text.includes('allowed_identities AS "allowedIdentities"'))return {rows:[inner.asset]};
  if(text.includes('FROM public.asset_domain_placements'))return {rows:inner.placement?[inner.placement]:[]};
  if(text.includes('FROM public.domains'))return {rows:[inner.domainPath.find(domain=>domain.id===values?.[1])]};
  if(text.includes('FROM public.domain_scope_state'))return {rows:[{epoch:inner.domainEpoch}]};
  if(text.includes('FROM gc_authority.content_security_heads'))return {rows:[{revision:context.context.securityRevision}]};
  if(text.includes(' AS closure'))return {rows:[{closure:inner.closure}]};
  if(text.startsWith('SELECT octet_length(registry_document)'))return {rows:[{raw_bytes:String(Buffer.byteLength(registryText)),canonical_bytes:String(metrics.canonicalBytes),json_nodes:String(metrics.nodes)}]};
  if(text.startsWith('SELECT registry_document'))return {rows:[{registry_document:registryText}]};
  if(text.includes('load_reviewed_classification_producer_v1'))return {rows:[{producer:producer(context)}]};
  if(text.includes('reviewed-classification:counts'))return {rows:[{assignments:String(proofs.length),tasks:String(proofs.reduce((n,p)=>n+p.tasks.length,0)),max_tasks:String(Math.max(0,...proofs.map(p=>p.tasks.length))),decisions:String(proofs.reduce((n,p)=>n+p.decisions.length,0)),max_decisions:String(Math.max(0,...proofs.map(p=>p.decisions.length)))}]};
  if(text.includes('reviewed-classification:measure'))return {rows:[{assignments:String(proofs.length),canonical_bytes:String(proofs.reduce((n,p)=>n+bytes(p),0)),raw_bytes:String(proofs.reduce((n,p)=>n+bytes(p),0)),dependencies_complete:true,component_bounds:true}]};
  if(text.includes('reviewed-classification:bodies'))return {rows:proofs.map(proof=>({proof}))};
  assert.ok(text.startsWith('SET ')||text.startsWith('BEGIN ')||text.startsWith('SELECT set_config(')||text==='ROLLBACK'||text==='COMMIT','Unexpected synthetic repository query: '+text);
  return {rows:[]};
 },release(destroy){releases.push(destroy??false);}};}};
 const input={sessionHash:'a'.repeat(64) as Digest,assetId:inner.asset.id,expectedVersion:inner.asset.version};
 return {context,proofs,pool,input,calls,releases,control,connections:()=>connections,sessions:()=>sessionReads,run:()=>createAuthorityFoundationRepository(pool).evaluateHeldHumanAssetMetadata(input)};
}
async function refused(p:ReturnType<typeof protocol>,code:string){
 await assert.rejects(p.run(),e=>e instanceof AuthorityFoundationError&&e.code===code&&e.message===code);
 assert.equal(p.calls.filter(c=>c.text==='COMMIT').length,0);assert.deepEqual(p.releases,[true]);
}
function composed(context:unknown){return compose({context,budget:{check(){},admitComposition(){}}});}

test('held repository returns exactly the real evaluated inert envelope before releasing its single snapshot',async()=>{
 const p=protocol(),out=await p.run(),composition=composed(p.context);
 assert.equal(out.formatVersion,1);assert.equal(out.kind,'inactive-held-human-asset-metadata-evaluation');assert.equal(out.contentAuthority,false);
 assert.equal(out.contextDigest,p.context.contextDigest);assert.equal(canonical(out.result),canonical(evaluateAuthority(composition.bundle,composition.registry)));assert.equal(out.result.root?.allowed,true);
 assert.deepEqual(Object.keys(out).sort(),['contentAuthority','contextDigest','formatVersion','kind','result']);assert.ok(Object.isFrozen(out)&&Object.isFrozen(out.result));
 assert.equal(p.connections(),1);assert.equal(p.sessions(),2);assert.equal(p.calls.filter(c=>c.text==='BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY').length,1);
 const final=p.calls.reduce((last,c,index)=>c.text.includes('FROM gc_authn.foundation_session_v1')?index:last,-1);assert.equal(final,p.calls.length-3);
 assert.deepEqual(p.calls.at(-2)?.values,[id(990),id(991)]);assert.equal(p.calls.at(-1)?.text,'COMMIT');assert.deepEqual(p.releases,[false]);
 assert.equal(p.calls.filter(c=>c.text.includes('reviewed-classification:counts')).length,1);
 assert.equal(p.calls.some(c=>c.text==='ROLLBACK'),false);assert.equal('sourceProof'in out,false);assert.equal('composition'in out,false);
});
test('held visibility denial is an evaluated inert result, preserving the exact context digest',async()=>{
 const context=classified();context.context.context.asset.visibility='restricted';const p=protocol(reseal(context)),out=await p.run();
 assert.equal(out.result.outcome,'evaluated');assert.equal(out.result.root?.allowed,false);assert.equal(out.result.root?.reason,'ceiling_denied');assert.equal(out.contentAuthority,false);assert.equal(out.contextDigest,p.context.contextDigest);
});
test('complete nonempty reviewed proof is validated and retained privately while the real evaluator runs',async()=>{
 const proof=sourceProof();proof.decisions[0].reason='PRIVATE_SYNTHETIC_REVIEW_REASON';
 const expected=protocol(classified(),[proof]),loaded=await createAuthorityFoundationRepository(expected.pool).loadClassifiedHumanAssetContext(expected.input);
 assert.equal(loaded.approvedFacts.length,1);const composition=composed(loaded),evaluation=evaluateAuthority(composition.bundle,composition.registry);
 const p=protocol(classified(),[proof]),out=await p.run();assert.equal(out.contextDigest,loaded.contextDigest);assert.equal(canonical(out.result),canonical(evaluation));
 assert.equal(out.result.outcome,'evaluated');assert.equal(out.result.root?.allowed,true);assert.equal(canonical(out).includes('PRIVATE_SYNTHETIC_REVIEW_REASON'),false);
 assert.equal(p.calls.filter(c=>c.text.includes('reviewed-classification:bodies')).length,1);assert.equal(p.sessions(),2);assert.deepEqual(p.releases,[false]);
});
test('unsupported composition fails before final session recheck or commit with no reflected issue',async()=>{
 const context=classified();context.context.context.registry.adapters=context.context.context.registry.adapters.filter(a=>a.branch!=='human-resource');
 const p=protocol(reseal(context));await refused(p,'AUTHORITY_FOUNDATION_UNSUPPORTED');assert.equal(p.sessions(),1);assert.equal(p.calls.at(-1)?.text,'ROLLBACK');
});
test('real evaluator profile refusal occurs inside the transaction before final session recheck or commit',async()=>{
 const context=classified(makeWideBindingFixture(2,257)),composition=composed(context);
 assert.equal(evaluateAuthority(composition.bundle,composition.registry).outcome,'profile_limit');
 const p=protocol(context);await refused(p,'AUTHORITY_FOUNDATION_PROFILE_LIMIT');assert.equal(p.sessions(),1);assert.equal(p.calls.at(-1)?.text,'ROLLBACK');
});
test('raw statement and lock errors retain fixed deadline mapping at all reviewed proof phases',async()=>{
 for(const code of ['57014','55P03'])for(const phase of ['counts','measure','bodies']){
  const p=protocol(classified(),[sourceProof()]);p.control.beforeQuery=text=>{if(text.includes('reviewed-classification:'+phase))throw Object.assign(new Error('PRIVATE_SQL_SOURCE'),{code,detail:'PRIVATE_PARAMS'});};
  await refused(p,'AUTHORITY_FOUNDATION_DEADLINE');assert.equal(p.calls.filter(c=>c.text.includes('reviewed-classification:'+phase)).length,1);assert.equal(p.calls.at(-1)?.text,'ROLLBACK');assert.equal(p.sessions(),1);
 }
});
test('final protected-session rejection discards evaluation and destroys the rolled back connection',async()=>{
 const p=protocol();p.control.beforeQuery=(text,reads)=>{if(reads===1&&text.includes('FROM gc_authn.foundation_session_v1'))throw Object.assign(new Error('PRIVATE_SESSION'),{code:'28000'});};
 await refused(p,'AUTHORITY_FOUNDATION_SESSION_REJECTED');assert.equal(p.calls.at(-1)?.text,'ROLLBACK');
});
test('final protected-session substitution is integrity failure and returns no diagnostic result',async()=>{
 const p=protocol();p.control.finalSession={...p.context.context.context.closure.session,sessionVersion:2};
 await refused(p,'AUTHORITY_FOUNDATION_INTEGRITY');assert.equal(p.sessions(),2);assert.equal(p.calls.at(-1)?.text,'ROLLBACK');
});
test('caller adapter, subject, action, time, producer and proof choices are rejected before connection',async()=>{
 for(const extra of [{adapterId:'asset.read'},{subject:{kind:'human',id:id(2)}},{action:'asset:metadata.read'},{now:'2026-11-16T06:00:00.000Z'},{producer:{id:id(700),version:v}},{sourceProof:[]},{registry:{}},{contentAuthority:true}]){
  const p=protocol();await assert.rejects(createAuthorityFoundationRepository(p.pool).evaluateHeldHumanAssetMetadata({...p.input,...extra}),e=>e instanceof AuthorityFoundationError&&e.code==='AUTHORITY_FOUNDATION_INPUT_INVALID');assert.equal(p.connections(),0);assert.equal(p.calls.length,0);
 }
});
test('the original absolute deadline includes final protected-session read without a phase reset',async t=>{
 let clock=0;t.mock.method(performance,'now',()=>clock);const p=protocol();
 p.control.beforeQuery=(text,reads)=>{if(text.includes(' AS native_owner'))clock=29000;if(text.includes('FROM gc_authn.foundation_session_v1')&&reads===1)clock=30001;};
 await refused(p,'AUTHORITY_FOUNDATION_DEADLINE');assert.equal(p.sessions(),2);assert.equal(p.calls.filter(c=>c.text==='ROLLBACK').length,0);assert.equal(p.connections(),1);
});
// Captured from the qualified SQL035 repository before this integration.
const legacyContracts=[
  {
    "method": "loadHumanClosure",
    "outputSha256": "6911d1e292e94f011d371b200dd63a886c13c4b3a937a72f24b3a6f97238bf86",
    "queriesSha256": "aa414fe8bdfa72f271e56982958aeecf64f39970ee936625a093cd41a9f45ae8",
    "queryCount": 9,
    "sessionReads": 0,
    "connections": 1,
    "releases": [
      false
    ]
  },
  {
    "method": "loadHumanAssetContext",
    "outputSha256": "a77142605a3c69e8b21bf6f029cdfec5f477c9b34faa2df8dc6b83c992f36f6c",
    "queriesSha256": "b5133caccf707829d8f66514cd3043b1bb5d6b48381014fc34cf87a089ca1bf8",
    "queryCount": 19,
    "sessionReads": 1,
    "connections": 1,
    "releases": [
      false
    ]
  },
  {
    "method": "loadVersionedHumanAssetContext",
    "outputSha256": "58e734cc08a827f75c4d78c62c8cd92c3ff3444f52808da0433a2e6323cd03ee",
    "queriesSha256": "778cf91ec67eaa4ffc8ec7a3131cff1353e72b1202bd899d52a666d394e8015d",
    "queryCount": 20,
    "sessionReads": 1,
    "connections": 1,
    "releases": [
      false
    ]
  },
  {
    "method": "loadClassifiedHumanAssetContext",
    "outputSha256": "d45f83fe0660ac96ac3790a16bf583eafb3aed11437b717e0b8bea9c0c5d243d",
    "queriesSha256": "5a7d12f6e853839fb8ac576e82d1c70b6b4f36d97f4bbea129c5f12c1d57034a",
    "queryCount": 23,
    "sessionReads": 2,
    "connections": 1,
    "releases": [
      false
    ]
  }
] as const;
test('existing repository methods retain their qualified canonical output and query contract',async()=>{
 for(const expected of legacyContracts){
  const p=protocol(),method=expected.method,input=method==='loadHumanClosure'?{sessionHash:p.input.sessionHash,selectors:{formatVersion:1,requests:p.context.context.context.closure.selectors}}:p.input;
  const output=await (createAuthorityFoundationRepository(p.pool)[method] as (x:unknown)=>Promise<unknown>)(input);
  assert.equal(decisionHash(output),expected.outputSha256);assert.equal(decisionHash(p.calls),expected.queriesSha256);assert.equal(p.calls.length,expected.queryCount);assert.equal(p.sessions(),expected.sessionReads);assert.equal(p.connections(),expected.connections);assert.deepEqual(p.releases,expected.releases);
 }
});
test('one measured aggregate exceeds8MiB only while the complete source proof is retained; individual phases fit',async()=>{
 const fixture=makeWideBindingFixture(1,90,70),base=fixture.bundle.definitions[0]!;assert.equal(base.kind,'role');if(base.kind!=='role')throw Error('role fixture');
 fixture.bundle.definitions=fixture.bundle.grants.map((grant,index)=>{
  if(grant.kind!=='ordinary-role')throw Error('ordinary fixture');grant.role={roleId:id(30000+index),version:v};
  return {...structuredClone(base),id:grant.role.roleId,content:{...structuredClone(base.content),metadata:{key:'role_'+index,label:'Synthetic role',description:'😀'.repeat(4000)}}};
 });
 const context=classified(sealDecisionFixture(fixture)),proofs=Array.from({length:200},(_,index)=>sourceProof(index));
 assert.ok(proofs.length<256);assert.ok(bytes(proofs)<limits.proofBytes);
 const expected=protocol(context,proofs),loaded=await createAuthorityFoundationRepository(expected.pool).loadClassifiedHumanAssetContext(expected.input),composition=composed(loaded),result=evaluateAuthority(composition.bundle,composition.registry);
 assert.equal(loaded.approvedFacts.length,200);assert.equal(result.outcome,'evaluated');
 const aggregate={context:loaded,producerSnapshot:producer(context),sourceProof:proofs,composition,result};
 for(const piece of Object.values(aggregate)){const admitted=parsed(admitAuthorityInput(piece));assert.ok(admitted.metrics.canonicalBytes<limits.canonicalBytes);assert.ok(admitted.metrics.nodes<limits.jsonNodes);}
 const {sourceProof:removed,...withoutProof}=aggregate;assert.equal(removed.length,200);parsed(admitAuthorityInput(withoutProof));
 const independentBytes=bytes(aggregate),independentNodes=Object.values(aggregate).reduce((n,piece)=>n+parsed(admitAuthorityInput(piece)).metrics.nodes,1);
 assert.ok(independentBytes>limits.canonicalBytes,'Actual aggregate bytes: '+independentBytes);assert.ok(independentNodes<limits.jsonNodes,'Byte fixture must not exceed node cap first');
 const admission=admitAuthorityInput(aggregate);assert.equal(admission.ok,false);if(!admission.ok)assert.equal(admission.issues[0]!.message,'Canonical authority JSON exceeds 8 MiB.');
 const p=protocol(context,proofs);await refused(p,'AUTHORITY_FOUNDATION_PROFILE_LIMIT');assert.equal(p.sessions(),1);assert.equal(p.calls.at(-1)?.text,'ROLLBACK');assert.equal(p.calls.filter(c=>c.text.includes('reviewed-classification:bodies')).length,1);
});
test('one measured aggregate enforces the shared node cap even while every individual phase fits',async()=>{
 const context=classified(makeWideBindingFixture(1,116,100)),composition=composed(context),result=evaluateAuthority(composition.bundle,composition.registry);assert.equal(result.outcome,'evaluated');
 const aggregate={context,producerSnapshot:producer(context),sourceProof:[],composition,result};
 const nodes=Object.values(aggregate).reduce((n,piece)=>n+parsed(admitAuthorityInput(piece)).metrics.nodes,1);
 assert.ok(nodes>limits.jsonNodes,'Actual aggregate node count: '+nodes);assert.ok(bytes(aggregate)<limits.canonicalBytes);
 const admission=admitAuthorityInput(aggregate);assert.equal(admission.ok,false);if(!admission.ok)assert.equal(admission.issues[0]!.message,'Authority JSON exceeds its node limit.');
 const p=protocol(context);await refused(p,'AUTHORITY_FOUNDATION_PROFILE_LIMIT');assert.equal(p.sessions(),1);assert.equal(p.calls.at(-1)?.text,'ROLLBACK');
});
