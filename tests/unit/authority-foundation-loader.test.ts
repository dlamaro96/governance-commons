// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import {admitAuthorityInput} from '../../packages/authority/src/admission.ts';
import {canonicalDecisionJSON as canonical,decisionHash,decisionShapes} from '../../packages/authority/src/decision-schema.ts';
import {definitionKey,grantKey,policyKey,subjectKey,versionKey} from '../../packages/authority/src/decision-types.ts';
import {parsePolicyFile} from '../../packages/authority/src/policy.ts';
import type {PolicyExpr,UTC,Version,Digest,Counter} from '../../packages/authority/src/types.ts';
import type {AuthorityHumanClosure,NativeOwnerConnection,NativeOwnerPool} from '../../packages/authority-storage/src/contracts.ts';
import {createAuthorityFoundationRepository} from '../../packages/authority-storage/src/repository.ts';
import {parseAuthorityHumanClosure,parseClosureSelectors} from '../../packages/authority-storage/src/loader.ts';
import {makeDecisionFixture,id,v,now,zero,parsed,type Mutable} from './fixtures/authority-decision.ts';
import {makeFourEdgeFieldFixture} from './fixtures/authority-decision-chain.ts';
const bytes=(x:unknown)=>Buffer.byteLength(canonical(x));
const sort=<T>(rows:T[],key:(x:T)=>string)=>rows.sort((a,b)=>key(a)<key(b)?-1:key(a)>key(b)?1:0);
const nodes=(e:PolicyExpr):number=>1+('children'in e?e.children.reduce((n,c)=>n+nodes(c),0):0);
/** Synthetic complete graph DTO for parser tests only; never a database/session assertion. */
function fixture(chain=false){
 const {bundle:b,registry:rawRegistry}=chain?makeFourEdgeFieldFixture(false):makeDecisionFixture();
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
  selectors:[req],partitions:partitions as Mutable<AuthorityHumanClosure>['partitions'],parents:[...parentMap.values()],dependencies,
  principals:b.principals as Mutable<AuthorityHumanClosure>['principals'],groups:b.groups,memberships:b.memberships,principalGroups:b.principalGroups,definitions:b.definitions,policies:b.policies,grants:b.grants as Mutable<AuthorityHumanClosure>['grants'],elevationUses:[],lifecycleHeads:[],metrics:{} as never};
 for(const d of c.definitions)c.lifecycleHeads.push({family:'definition',id:d.id,definitionKind:d.kind,headVersion:v});
 for(const p of c.policies)c.lifecycleHeads.push({family:'definition',id:p.pin.policyId,definitionKind:'policy',headVersion:v});
 for(const g of c.grants)c.lifecycleHeads.push({family:'grant',id:g.ref.id,definitionKind:null,headVersion:v});
 return {closure:seal(c),registry};
}
function seal(c:Mutable<AuthorityHumanClosure>){
 sort(c.selectors,canonical);sort(c.partitions,x=>x.key);c.partitions.forEach(p=>sort(p.candidates,grantKey));sort(c.parents,x=>grantKey(x.child));sort(c.dependencies,x=>`${x.from}:${x.issuer}:${grantKey(x.child)}`);
 sort(c.principals,subjectKey);sort(c.groups,x=>x.id);sort(c.memberships,x=>versionKey(x.ref));sort(c.principalGroups,x=>subjectKey(x.subject));c.principalGroups.forEach(g=>{if(g.memberships.status==='known')sort(g.memberships.value,versionKey);});
 sort(c.definitions,x=>definitionKey(x.kind,x.id,x.version));sort(c.policies,x=>policyKey(x.pin));sort(c.grants,x=>grantKey(x.ref));sort(c.elevationUses,x=>versionKey(x.ref));sort(c.lifecycleHeads,h=>`${h.family}:${h.definitionKind??''}:${h.id}`);
 const docs=c.policies.map(p=>parsed(parsePolicyFile(p.document,[]))),depth=(key:string,seen=new Set<string>()):number=>{if(seen.has(key))return 17;const next=new Set([...seen,key]);return 1+Math.max(0,...c.dependencies.filter(d=>d.from===key).map(d=>depth(d.issuer,next)));};
 c.metrics={selectors:c.selectors.length,partitions:c.partitions.length,dependencyEdges:new Set(c.dependencies.map(d=>`${d.from}:${d.issuer}`)).size,dependencyReferences:c.dependencies.length,dependencyDepth:Math.max(...c.partitions.map(p=>depth(p.key))),canonicalBytes:0,jsonNodes:0,maxDepth:0,policies:c.policies.length,policyBytes:docs.reduce((n,d)=>n+bytes(d),0),policyRules:docs.reduce((n,d)=>n+d.rules.length,0),expressionNodes:docs.reduce((n,d)=>n+d.rules.reduce((m,q)=>m+nodes(q.when),0),0),ordinaryOrigins:c.grants.filter(g=>g.kind==='ordinary-role'||g.kind==='responsibility').length,connectedRecords:c.grants.filter(g=>g.kind==='delegation'||g.kind==='elevation').length,principals:c.principals.length,directGroupsMaximum:Math.max(0,...c.principalGroups.map(g=>g.memberships.status==='known'?g.memberships.value.length:0)),proofBytes:[c.session,c.partitions,c.definitions,c.principals,c.groups,c.memberships,c.principalGroups,c.grants,c.elevationUses,c.parents,c.dependencies,c.lifecycleHeads].reduce<number>((n,x)=>n+bytes(x),0)};
 const {metrics:_m,snapshot,...rest}=c,{closureDigest:_d,...s}=snapshot;c.snapshot.closureDigest=decisionHash({...rest,snapshot:s});
 for(let round=0;round<4;round++){const a=parsed(admitAuthorityInput(c)).metrics;c.metrics.canonicalBytes=a.canonicalBytes;c.metrics.jsonNodes=a.nodes;c.metrics.maxDepth=a.depth;}
 assert.equal(c.metrics.canonicalBytes,bytes(c));return c;
}
const refuses=(value:ReturnType<typeof parseAuthorityHumanClosure>)=>{assert.equal(value.ok,false);if(value.ok)throw Error('Expected refusal');return value.issues;};
test('foundation parser accepts detached exact ordinary closure and synthetic four-edge graph without content authority',()=>{
 for(const chain of [false,true]){const f=fixture(chain),before=canonical(f),c=parsed(parseAuthorityHumanClosure(f.closure,f.registry));assert.equal(c.contentAuthority,false);assert.ok(Object.isFrozen(c.grants));assert.equal(c.metrics.dependencyDepth,chain?5:1);assert.equal(canonical(f),before);}
});
test('selectors reject duplicates, unknown keys, nil IDs, service actions and field mismatch',()=>{
 const f=fixture(),request=f.closure.selectors[0]!;for(const value of [{formatVersion:1,requests:[]},{formatVersion:1,requests:[request,request]},{formatVersion:1,requests:[{...request,field:'asset.name'}]},{formatVersion:1,requests:[{...request,action:'scan-job:complete'}]},{formatVersion:1,requests:[{...request,resource:{...request.resource,id:'00000000-0000-0000-0000-000000000000'}}]},{formatVersion:1,requests:[request],actor:id(99)}])assert.equal(parseClosureSelectors(value).ok,false);
 assert.equal(parseClosureSelectors('{"formatVersion":1,"formatVersion":1,"requests":[]}').ok,false);assert.equal(parseClosureSelectors({formatVersion:1,requests:[request]}).ok,true);
});
test('closure refuses accessors and proxies without invoking caller code',()=>{
 const f=fixture();let touched=0;const hostile={...f.closure};Object.defineProperty(hostile,'session',{enumerable:true,get(){touched++;throw Error('private');}});refuses(parseAuthorityHumanClosure(hostile,f.registry));refuses(parseAuthorityHumanClosure(new Proxy(f.closure,{ownKeys(){touched++;throw Error('private');}}),f.registry));assert.equal(touched,0);
});
test('closure raw parsing refuses duplicate JSON and shared registry bytes cannot reset admission',()=>{
 const f=fixture(),text=JSON.stringify(f.closure);refuses(parseAuthorityHumanClosure('{"formatVersion":1,'+text.slice(1),f.registry));
 const padded=text+' '.repeat(8388608-Buffer.byteLength(text));assert.equal(refuses(parseAuthorityHumanClosure(padded,f.registry))[0]!.code,'limit');
});
test('closure refuses unknown nested fields, unordered arrays, nil references and bad bigint/time scalars',()=>{
 for(const mutate of [(f:ReturnType<typeof fixture>)=>{Object.assign(f.closure.session,{permissions:['all']});},(f:ReturnType<typeof fixture>)=>{f.closure.lifecycleHeads.reverse();},(f:ReturnType<typeof fixture>)=>{f.closure.session.generation='9223372036854775808' as Counter;},(f:ReturnType<typeof fixture>)=>{f.closure.session.authenticatedAt='0000-01-01T00:00:00.000Z' as UTC;},(f:ReturnType<typeof fixture>)=>{f.closure.grants[0]!.issuer.id='00000000-0000-0000-0000-000000000000' as never;}]){const f=fixture();mutate(f);refuses(parseAuthorityHumanClosure(f.closure,f.registry));}
});
test('closure independently verifies registry, definition, policy and full closure hashes',()=>{
 for(const kind of ['registry','definition','policy','closure'] as const){const f=fixture();if(kind==='registry')f.registry.digest=zero;else if(kind==='definition')f.closure.definitions[0]!.hash=zero;else if(kind==='policy')f.closure.policies[0]!.pin.hash=zero;else f.closure.snapshot.closureDigest=zero;refuses(parseAuthorityHumanClosure(f.closure,f.registry));}
});
test('resealed missing parent, missing dependency and truncated policy still fail graph consistency',()=>{
 for(const change of ['parent','dependency','policy','candidate','principal'] as const){const f=fixture(true);if(change==='parent')f.closure.parents.pop();else if(change==='dependency')f.closure.dependencies.pop();else if(change==='policy')f.closure.policies=[];else if(change==='candidate')f.closure.partitions[0]!.candidates=[];else f.closure.principals.pop();seal(f.closure);refuses(parseAuthorityHumanClosure(f.closure,f.registry));}
});
test('revoked parent issuance1 remains exact history while current issuer partition has no allow candidate',()=>{
 const f=fixture(true),origin=f.closure.grants.find(g=>g.kind==='ordinary-role')!;origin.state='revoked';f.closure.lifecycleHeads.find(h=>h.family==='grant'&&h.id===origin.ref.id)!.headVersion=2 as Version;
 f.closure.partitions.find(p=>p.subject.id===origin.beneficiary.id)!.candidates=[];seal(f.closure);const value=parsed(parseAuthorityHumanClosure(f.closure,f.registry));assert.equal(value.grants.find(g=>g.ref.id===origin.ref.id)!.ref.version,1);assert.equal(value.grants.find(g=>g.ref.id===origin.ref.id)!.state,'revoked');
});
test('historical group-parent membership is required in the exact principal group ref union',()=>{
 const f=fixture(true),c=f.closure,origin=c.grants.find(g=>g.kind==='ordinary-role')!,issuer=origin.beneficiary.id,group=id(600),membership={id:id(601),version:v};origin.beneficiary={kind:'group',id:group};
 c.groups.push({id:group,tenantId:c.session.tenantId,revision:'1' as Counter,state:'active'});c.memberships.push({ref:membership,tenantId:c.session.tenantId,groupId:group,identityId:issuer,state:'revoked',validity:{notBefore:null,expiresAt:null}});
 c.parents.find(p=>grantKey(p.parent)===grantKey(origin.ref))!.viaMembership=membership;c.principalGroups.find(p=>p.subject.id===issuer)!.memberships={status:'known',value:[membership]};c.partitions.find(p=>p.subject.id===issuer)!.candidates=[];
 c.lifecycleHeads.push({family:'definition',definitionKind:'group',id:group,headVersion:v},{family:'group-membership',definitionKind:null,id:membership.id,headVersion:2 as Version});seal(c);parsed(parseAuthorityHumanClosure(c,f.registry));
 c.principalGroups.find(p=>p.subject.id===issuer)!.memberships={status:'known',value:[]};seal(c);refuses(parseAuthorityHumanClosure(c,f.registry));
});
test('metrics bind exact physical framing and canonical-only policy bytes separately from raw whitespace',()=>{
 const f=fixture();f.closure.policies[0]!.document='   '+f.closure.policies[0]!.document;seal(f.closure);parsed(parseAuthorityHumanClosure(f.closure,f.registry));
 f.closure.metrics.proofBytes++;refuses(parseAuthorityHumanClosure(f.closure,f.registry));
 const other=fixture();other.closure.metrics.jsonNodes--;refuses(parseAuthorityHumanClosure(other.closure,other.registry));
});
interface Fake {pool:NativeOwnerPool;calls:{sql:string;values?:unknown[]}[];released:boolean[];setHandler:(fn:(sql:string)=>Promise<{rows:unknown[]}>|undefined)=>void}
function fake(f=fixture()):Fake{
 const calls:Fake['calls']=[],released:boolean[]=[];let handler:((sql:string)=>Promise<{rows:unknown[]}>|undefined)|undefined;
 const registryText=canonical(f.registry),physical=parsed(admitAuthorityInput(f.registry)).metrics;
 const connection:NativeOwnerConnection={async query(sql,values){calls.push({sql,values});const custom=handler?.(sql);if(custom)return custom;
  if(sql.includes(' AS native_owner'))return {rows:[{native_owner:true}]};if(sql.includes(' AS closure'))return {rows:[{closure:f.closure}]};if(sql.startsWith('SELECT octet_length'))return {rows:[{raw_bytes:String(Buffer.byteLength(registryText)),canonical_bytes:String(physical.canonicalBytes),json_nodes:String(physical.nodes)}]};if(sql.startsWith('SELECT registry_document'))return {rows:[{registry_document:registryText}]};return {rows:[]};},release(error){released.push(error??false);}};
 return {pool:{async connect(){return connection;}},calls,released,setHandler(fn){handler=fn;}};
}
const input=(f:ReturnType<typeof fixture>)=>({sessionHash:'a'.repeat(64) as Digest,selectors:{formatVersion:1 as const,requests:f.closure.selectors}});
test('repository protocol uses fresh native connection, separately prearmed timers, one loader and exact registry before commit',async()=>{
 const f=fixture(),db=fake(f),repo=createAuthorityFoundationRepository(db.pool);const c=await repo.loadHumanClosure(input(f));assert.equal(c.contentAuthority,false);assert.deepEqual(db.calls.slice(0,4).map(c=>c.sql),["SET statement_timeout = '25s'","SET lock_timeout = '2s'","SET idle_in_transaction_session_timeout = '5s'",'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY']);assert.equal(db.calls.filter(c=>c.sql.includes('load_human_closure_v1')).length,1);assert.equal(db.calls.at(-1)!.sql,'COMMIT');assert.deepEqual(db.released,[false]);assert.deepEqual(db.calls.find(c=>c.sql.startsWith('SELECT registry_document'))!.values,[c.snapshot.registryId,c.snapshot.registryVersion,c.snapshot.registryDigest]);
 await repo.loadHumanClosure(input(f));assert.equal(db.calls.filter(c=>c.sql.startsWith('BEGIN')).length,2);
});
test('repository rejects native owner mismatch before loader and rolls back without exposing database errors',async()=>{
 const f=fixture(),db=fake(f);db.setHandler(sql=>sql.includes(' AS native_owner')?Promise.resolve({rows:[{native_owner:false}]}):undefined);
 await assert.rejects(createAuthorityFoundationRepository(db.pool).loadHumanClosure(input(f)),{message:'AUTHORITY_FOUNDATION_EXECUTOR_REJECTED'});assert.equal(db.calls.some(c=>c.sql.includes('load_human_closure')),false);assert.equal(db.calls.at(-1)!.sql,'ROLLBACK');assert.deepEqual(db.released,[true]);
});
test('repository scalar preflight refuses oversize registry before selecting its body',async()=>{
 const f=fixture(),db=fake(f);db.setHandler(sql=>sql.startsWith('SELECT octet_length')?Promise.resolve({rows:[{raw_bytes:'8388608',canonical_bytes:'8388608',json_nodes:'1'}]}):undefined);
 await assert.rejects(createAuthorityFoundationRepository(db.pool).loadHumanClosure(input(f)),{message:'AUTHORITY_FOUNDATION_PROFILE_LIMIT'});assert.equal(db.calls.some(c=>c.sql.startsWith('SELECT registry_document')),false);assert.equal(db.calls.at(-1)!.sql,'ROLLBACK');
});
test('repository rejects inconsistent registry scalar measures and no invalid result reaches commit',async()=>{
 const f=fixture(),db=fake(f);db.setHandler(sql=>sql.startsWith('SELECT octet_length')?Promise.resolve({rows:[{raw_bytes:'1',canonical_bytes:'1',json_nodes:'1'}]}):undefined);
 await assert.rejects(createAuthorityFoundationRepository(db.pool).loadHumanClosure(input(f)),{message:'AUTHORITY_FOUNDATION_INTEGRITY'});assert.equal(db.calls.some(c=>c.sql==='COMMIT'),false);
});
test('repository preserves cancellation but bounds all other driver errors without SQL or private payloads',async()=>{
 for(const [code,expected]of [['57014','AUTHORITY_FOUNDATION_DEADLINE'],['23514','AUTHORITY_FOUNDATION_INTEGRITY'],['XX000','AUTHORITY_FOUNDATION_INTEGRITY']]){const f=fixture(),db=fake(f);db.setHandler(sql=>sql.includes('load_human_closure')?Promise.reject(Object.assign(new Error('private sql/token'),{code,detail:'private'})):undefined);await assert.rejects(createAuthorityFoundationRepository(db.pool).loadHumanClosure(input(f)),{message:expected});assert.equal(db.calls.at(-1)!.sql,'ROLLBACK');}
});
test('repository refuses malformed inputs without touching pool',async()=>{
 let touched=0;const pool:NativeOwnerPool={async connect(){touched++;throw Error('must not connect');}};
 await assert.rejects(createAuthorityFoundationRepository(pool).loadHumanClosure({...input(fixture()),sessionHash:'private' as Digest}),{message:'AUTHORITY_FOUNDATION_INPUT_INVALID'});assert.equal(touched,0);
});
test('repository original deadline destroys a pending query and never starts overlapping rollback',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});const f=fixture(),db=fake(f);let entered!:()=>void;const ready=new Promise<void>(r=>entered=r);db.setHandler(sql=>sql.includes('load_human_closure')?new Promise(()=>entered()):undefined);
 const result=createAuthorityFoundationRepository(db.pool).loadHumanClosure(input(f));const rejection=assert.rejects(result,{message:'AUTHORITY_FOUNDATION_DEADLINE'});await ready;t.mock.timers.tick(30000);await rejection;assert.deepEqual(db.released,[true]);assert.equal(db.calls.some(c=>c.sql==='ROLLBACK'||c.sql==='COMMIT'),false);
});
test('repository deadline includes pool acquisition and destroys a connection delivered after expiry',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});let deliver!:(c:NativeOwnerConnection)=>void;const releases:boolean[]=[],pool:NativeOwnerPool={connect(){return new Promise(r=>deliver=r);}};
 const result=createAuthorityFoundationRepository(pool).loadHumanClosure(input(fixture())),rejection=assert.rejects(result,{message:'AUTHORITY_FOUNDATION_DEADLINE'});t.mock.timers.tick(30000);await rejection;deliver({async query(){throw Error('unexpected query');},release(x){releases.push(x??false);}});await Promise.resolve();await Promise.resolve();assert.deepEqual(releases,[true]);
});
test('repository commit completion is required and failure never returns a valid parsed closure',async()=>{
 const f=fixture(),db=fake(f);db.setHandler(sql=>sql==='COMMIT'?Promise.reject(Object.assign(new Error('private commit'),{code:'40001'})):undefined);
 await assert.rejects(createAuthorityFoundationRepository(db.pool).loadHumanClosure(input(f)),{message:'AUTHORITY_FOUNDATION_VERSION_CONFLICT'});assert.equal(db.calls.at(-1)!.sql,'ROLLBACK');assert.deepEqual(db.released,[true]);
});

test('future unreferenced group facts are retained and omission from the known union is refused',()=>{
 const f=fixture(),c=f.closure,group=id(700),membership={id:id(701),version:v};c.groups.push({id:group,tenantId:c.session.tenantId,revision:'1' as Counter,state:'active'});c.memberships.push({ref:membership,tenantId:c.session.tenantId,groupId:group,identityId:c.session.identityId,state:'active',validity:{notBefore:'2026-11-16T06:30:00.000Z' as UTC,expiresAt:null}});c.principalGroups[0]!.memberships={status:'known',value:[membership]};c.lifecycleHeads.push({family:'definition',definitionKind:'group',id:group,headVersion:v},{family:'group-membership',definitionKind:null,id:membership.id,headVersion:v});seal(c);parsed(parseAuthorityHumanClosure(c,f.registry));c.principalGroups[0]!.memberships={status:'known',value:[]};seal(c);refuses(parseAuthorityHumanClosure(c,f.registry));
});
test('elevation chooses current then earliest future exact-session use and preserves separate inventory',()=>{
 const f=fixture(true),c=f.closure,old=c.grants.find(g=>g.kind==='delegation'&&g.beneficiary.id===c.session.identityId)!;assert.equal(old.kind,'delegation');if(old.kind!=='delegation')throw Error('fixture');
 const {delegable:_d,...body}=old,elevation={...body,kind:'elevation' as const,ref:{...old.ref,kind:'elevation' as const},validity:{notBefore:null,expiresAt:'2026-11-16T06:59:00.000Z' as UTC},use:null};
 elevation.ceiling={...elevation.ceiling,validity:elevation.validity};c.grants[c.grants.indexOf(old)]=elevation;for(const p of c.partitions)p.candidates=p.candidates.map(x=>x.id===old.ref.id?elevation.ref:x);for(const p of c.parents)if(p.child.id===old.ref.id)p.child=elevation.ref;for(const d of c.dependencies)if(d.child.id===old.ref.id)d.child=elevation.ref;
 for(const [n,start,end]of [[1,'06:20','06:30'],[2,'06:40','06:50'],[3,'05:50','06:10']] as const)c.elevationUses.push({ref:{id:id(800+n),version:v},elevation:elevation.ref,identityId:c.session.identityId,sessionId:c.session.sessionId,sessionVersion:v,generation:'1' as Counter,state:'active',validity:{notBefore:`2026-11-16T${start}:00.000Z` as UTC,expiresAt:`2026-11-16T${end}:00.000Z` as UTC}});
 const setUse=(n:number)=>{const u=c.elevationUses.find(x=>x.ref.id===id(800+n))!;Object.assign(elevation,{use:{id:u.ref.id,version:v,state:u.state,identityId:u.identityId,sessionId:u.sessionId,sessionVersion:v,generation:u.generation,validity:u.validity}});};
 for(const u of c.elevationUses)c.lifecycleHeads.push({family:'elevation-use',id:u.ref.id,definitionKind:null,headVersion:v});setUse(3);seal(c);parsed(parseAuthorityHumanClosure(c,f.registry));
 c.snapshot.asOf='2026-11-16T06:15:00.000Z' as UTC;setUse(1);seal(c);parsed(parseAuthorityHumanClosure(c,f.registry));setUse(2);seal(c);refuses(parseAuthorityHumanClosure(c,f.registry));
});
test('repository registry read cannot renew the original deadline after earlier work',async t=>{
 t.mock.timers.enable({apis:['setTimeout']});const f=fixture(),db=fake(f);let entered!:()=>void;const ready=new Promise<void>(r=>entered=r);db.setHandler(sql=>{if(sql.includes('load_human_closure')){t.mock.timers.tick(20000);return undefined;}if(sql.startsWith('SELECT registry_document'))return new Promise(()=>entered());return undefined;});
 const result=createAuthorityFoundationRepository(db.pool).loadHumanClosure(input(f)),rejection=assert.rejects(result,{message:'AUTHORITY_FOUNDATION_DEADLINE'});await ready;t.mock.timers.tick(10000);await rejection;assert.deepEqual(db.released,[true]);assert.equal(db.calls.some(c=>c.sql==='COMMIT'),false);
});

test('installed raw registry set ordering normalizes independently while closure ordering remains strict',async()=>{
 const f=fixture(),expected=parsed(parseAuthorityHumanClosure(f.closure,f.registry));f.registry.actions.reverse();f.registry.adapters.reverse();const original=canonical(f.registry);
 assert.deepEqual(parsed(parseAuthorityHumanClosure(f.closure,JSON.stringify(f.registry))),expected);assert.equal(canonical(f.registry),original);
 const db=fake(f);assert.deepEqual(await createAuthorityFoundationRepository(db.pool).loadHumanClosure(input(f)),expected);assert.equal(db.calls.at(-1)!.sql,'COMMIT');
 f.closure.lifecycleHeads.reverse();refuses(parseAuthorityHumanClosure(f.closure,f.registry));
});
