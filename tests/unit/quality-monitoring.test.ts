// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {Problem} from '../../packages/authz/src/index.ts';
import {parseMonitorDefinition,monitorDefinitionHash,validateMonitorPublication,parsePublishMonitorInput,parseMonitorStateInput,parseIssueCommandInput,parseMonitoringPageQuery,parseMonitorListQuery,parseQualityIssueListQuery,parseMonitorView,parseMonitorDefinitionView,parseOccurrence,parseComparisonScope,comparisonScopeHash,parseIssueView,parseIssueEvent,parseNotification,firstMonitorSlotAtOrAfter,planDueMonitorSlots} from '../../packages/domain/src/quality-monitoring.ts';
const ID=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const H='a'.repeat(64),START='2026-11-17T00:00:00.000Z';
const at=(seconds:number)=>new Date(Date.parse(START)+seconds*1000).toISOString();
const schedule=()=>({kind:'fixed-interval' as const,timeZone:'UTC' as const,startsAt:START,endsAt:null,intervalSeconds:60,lateGraceSeconds:5,missedSlots:'skip' as const,overlap:'skip' as const});
const definition=()=>({formatVersion:1,name:'Email monitor',purpose:'Observe nulls',rule:{id:ID(1),version:1,definitionHash:H},executorId:ID(2),authorizationExpiresAt:at(86400),schedule:schedule(),maintenance:[],silences:[],routing:{channel:'in-app',ownerId:ID(2),recipientIds:[ID(2),ID(3)]},issue:{category:'data-quality',acknowledgeWithinSeconds:300,resolveWithinSeconds:3600},recoveryMaximumAgeSeconds:600,retry:{policy:'quality-run-v1'}});
const reject=(work:()=>unknown)=>assert.throws(work,(error:unknown)=>error instanceof Problem&&error.status===400&&error.code==='MONITOR_INPUT_INVALID'&&!error.message.includes('private'));
const canonical=(v:unknown):string=>v!==null&&typeof v==='object'?Array.isArray(v)?`[${v.map(canonical).join(',')}]`:`{${Object.entries(v).sort(([a],[b])=>a<b?-1:a>b?1:0).map(([k,x])=>`${JSON.stringify(k)}:${canonical(x)}`).join(',')}}`:JSON.stringify(v);
const evidence=(ordinal=1)=>({occurrenceId:ID(10+ordinal),ordinal,runId:ID(20+ordinal),runVersion:3,completionHash:H,comparisonScopeHash:H,observedFinishedAt:at(ordinal*60)});
const monitor=()=>({id:ID(5),revision:1,definitionVersion:1,definitionHash:monitorDefinitionHash(definition()),definition:definition(),state:'enabled',blocked:null,nextSlotAt:START,lastAdmittedOrdinal:0,lastProjectedOrdinal:0,currentObservation:{state:'unobserved'},lastConclusive:null,createdAt:START,createdBy:ID(2)});
const occurrence=()=>({monitorId:ID(5),definitionVersion:1,definitionHash:H,id:ID(11),ordinal:1,rule:definition().rule,executorId:ID(2),origin:'schedule',slots:{firstAt:START,lastAt:START,count:1},recordedAt:at(1),disposition:'enqueued',reason:null,runId:ID(21),comparisonScopeHash:H});
const scope=()=>({formatVersion:1,monitorId:ID(5),executorId:ID(2),rule:definition().rule,sourceId:ID(30),sourceVersion:1,sourceConfigHash:H,schemaAssetId:ID(31),tableAssetId:ID(32),columnAssetId:ID(33),targetHash:H,family:{kind:'reference-allowed-values',setId:ID(40),version:1,publicationHash:H,codeStatus:'active',codesHash:H}});
const issue=()=>({id:ID(50),version:1,monitorId:ID(5),comparisonScopeHash:H,rule:definition().rule,category:'data-quality',severity:'warning',tableAssetId:ID(32),columnAssetId:ID(33),status:'open',episode:1,assignedOwnerId:ID(2),ownerAvailable:true,openedAt:START,acknowledgeDueAt:at(300),resolveDueAt:at(3600),opening:evidence(),lastFailure:evidence(),recovery:null,resolution:null,superseded:null});
const event=()=>({id:ID(60),issueId:ID(50),version:1,episode:1,kind:'opened',monitor:{monitorId:ID(5),definitionVersion:1,definitionHash:H},occurrenceId:ID(11),runId:ID(21),actorId:'site:local',at:START,reason:null,resolution:null});
const notification=()=>({id:ID(70),eventId:ID(60),issueId:ID(50),recipientId:ID(2),template:'quality-issue-opened-v1',createdAt:START,readAt:null,version:1});
const plan=(now:number,extra:Record<string,unknown>={})=>planDueMonitorSlots({schedule:schedule(),maintenance:[],nextSlotAt:START,now:at(now),...extra});

test('monitor definitions are detached canonical data and normalization never mutates caller',()=>{
 const d=definition();d.name='  Cafe\u0301  ';d.purpose=' first\nsecond\t ';const original=structuredClone(d),parsed=parseMonitorDefinition(d);
 assert.equal(parsed.name,'Café');assert.equal(parsed.purpose,'first\nsecond');assert.deepEqual(d,original);d.routing.recipientIds[0]=ID(99);assert.equal(parsed.routing.recipientIds[0],ID(2));
});
test('descriptor copy refuses getters, symbols, reserved fields and arbitrary prototypes without executing getter',()=>{
 let calls=0;const getter=Object.defineProperty(definition(),'purpose',{enumerable:true,get(){calls++;return 'private';}});reject(()=>parseMonitorDefinition(getter));assert.equal(calls,0);
 reject(()=>parseMonitorDefinition({...definition(),[Symbol('private')]:1}));reject(()=>parseMonitorDefinition(Object.assign(Object.create({foreign:true}),definition())));
 reject(()=>parseMonitorDefinition(Object.defineProperty(definition(),'hidden',{value:1})));reject(()=>parseMonitorDefinition(JSON.parse(JSON.stringify(definition()).slice(0,-1)+',"__proto__":{}}')));
});
test('reflection failures are replaced without inspecting thrown getters and no toJSON is called',()=>{
 let calls=0;const thrown=new Proxy({}, {get(){calls++;throw new Error('private');}});reject(()=>parseMonitorDefinition(new Proxy({}, {ownKeys(){throw thrown;}})));assert.equal(calls,0);
 const d={...definition(),toJSON(){calls++;return definition();}};reject(()=>parseMonitorDefinition(d));assert.equal(calls,0);
});
test('cycles, sparse arrays, array properties, exotic arrays and nested getters fail closed',()=>{
 const d:any=definition();d.purpose=d;reject(()=>parseMonitorDefinition(d));
 for(const recipients of [[,ID(2)],Object.assign([ID(2)],{foreign:1}),new (class extends Array {})()])reject(()=>parseMonitorDefinition({...definition(),routing:{...definition().routing,recipientIds:recipients}}));
 let called=false;const recipients=[ID(2)];Object.defineProperty(recipients,'0',{enumerable:true,get(){called=true;return ID(2);}});reject(()=>parseMonitorDefinition({...definition(),routing:{...definition().routing,recipientIds:recipients}}));assert.equal(called,false);
});
test('bounded raw envelope and Unicode/control grammar are enforced before normalization',()=>{
 for(const name of ['\ud800','\udc00','a\u0000','a\u0085','a\n','a\t',' '.repeat(241)])reject(()=>parseMonitorDefinition({...definition(),name}));
 const d=definition();d.purpose='😀'.repeat(2048);assert.equal(parseMonitorDefinition(d).purpose,d.purpose);
 reject(()=>parseMonitorDefinition({...definition(),purpose:'😀'.repeat(2049)}));
 const large={...definition(),name:'x'.repeat(65537)};reject(()=>parseMonitorDefinition(large));
 const fields=Object.fromEntries(Array.from({length:100},(_,i)=>['x'+i,'x'.repeat(1024)]));reject(()=>parseMonitorDefinition(fields));
 // Individual field maxima still fit the whole-definition bound.
 const excessive={...definition(),purpose:'\n'.repeat(4095)+'x',maintenance:Array.from({length:32},(_,i)=>({from:at(i*3),until:at(i*3+1)})),silences:Array.from({length:32},(_,i)=>({from:at(i*3),until:at(i*3+1)})),name:'x'.repeat(240)};
 assert.ok(Buffer.byteLength(JSON.stringify(excessive))<32768);assert.doesNotThrow(()=>parseMonitorDefinition(excessive));
});
test('NFC and canonical field order produce the existing canonical SHA256 definition hash',()=>{
 const d=definition(),reverse=Object.fromEntries(Object.entries(d).reverse());assert.equal(monitorDefinitionHash(d),monitorDefinitionHash(reverse));
 assert.equal(monitorDefinitionHash(d),createHash('sha256').update(canonical(parseMonitorDefinition(d))).digest('hex'));
 assert.equal(monitorDefinitionHash({...d,name:'Cafe\u0301'}),monitorDefinitionHash({...d,name:'Café'}));
 assert.notEqual(monitorDefinitionHash({...d,purpose:'new'}),monitorDefinitionHash(d));
});
test('schedules admit only bounded fixed UTC intervals and exact real UTC millisecond instants',()=>{
 for(const change of [{timeZone:'Asia/Dubai'},{kind:'cron'},{intervalSeconds:59},{intervalSeconds:604801},{lateGraceSeconds:60},{startsAt:'2026-02-30T00:00:00.000Z'},{startsAt:'2026-11-17T00:00:00Z'},{endsAt:START},{missedSlots:'backfill'},{overlap:'allow'}])reject(()=>parseMonitorDefinition({...definition(),schedule:{...schedule(),...change}}));
 for(const intervalSeconds of [60,604800])assert.doesNotThrow(()=>parseMonitorDefinition({...definition(),schedule:{...schedule(),intervalSeconds},recoveryMaximumAgeSeconds:intervalSeconds}));
});
test('maintenance/silence retain exact independent sorted half-open windows',()=>{
 const windows=[{from:at(0),until:at(60)},{from:at(60),until:at(120)}];assert.deepEqual(parseMonitorDefinition({...definition(),maintenance:windows,silences:windows}).maintenance,windows);
 for(const maintenance of [[windows[1],windows[0]],[{from:at(0),until:at(90)},windows[1]],[{from:START,until:START}],Array(33).fill(windows[0])])reject(()=>parseMonitorDefinition({...definition(),maintenance}));
});
test('routing is exact in-app sorted unique IDs, includes owner, with no endpoint or implicit owner grant',()=>{
 for(const routing of [{...definition().routing,channel:'email'},{...definition().routing,recipientIds:[ID(3)]},{...definition().routing,recipientIds:[ID(3),ID(2)]},{...definition().routing,recipientIds:[ID(2),ID(2)]},{...definition().routing,url:'private'},{...definition().routing,recipientIds:Array.from({length:17},(_,i)=>ID(i+2))}])reject(()=>parseMonitorDefinition({...definition(),routing}));
 assert.equal(parseMonitorDefinition(definition()).routing.ownerId,ID(2)); // existence/current authority is SQL-owned
});
test('publication clock validation is explicitly self-execution and bounded future authorization',()=>{
 assert.doesNotThrow(()=>validateMonitorPublication(definition(),ID(2),START));reject(()=>validateMonitorPublication(definition(),ID(3),START));
 for(const expires of [START,at(-1),at(2678400+1)])reject(()=>validateMonitorPublication({...definition(),authorizationExpiresAt:expires},ID(2),START));
 assert.doesNotThrow(()=>validateMonitorPublication({...definition(),authorizationExpiresAt:at(2678400)},ID(2),START));
});
test('publication/state commands have exact optimistic revisions and closed actions',()=>{
 assert.equal(parsePublishMonitorInput({id:ID(5),expectedRevision:0,definition:definition()}).expectedRevision,0);
 for(const expectedRevision of [-0,-1,1.1,'1',2147483647])reject(()=>parsePublishMonitorInput({id:ID(5),expectedRevision,definition:definition()}));
 assert.equal(parseMonitorStateInput({expectedRevision:1,action:'pause',reason:' stop '}).reason,'stop');
 reject(()=>parseMonitorStateInput({expectedRevision:0,action:'pause',reason:'stop'}));reject(()=>parseMonitorStateInput({expectedRevision:1,action:'execute-as',reason:'stop'}));
});
test('issue commands keep exact evidence pins and nonblank multiline reasons, no verdict submission',()=>{
 const base={expectedVersion:1,reason:'  explain\nwhy '};assert.equal(parseIssueCommandInput('acknowledge',base).reason,'explain\nwhy');
 assert.equal(parseIssueCommandInput('assign',{...base,ownerId:ID(3)}).ownerId,ID(3));
 assert.equal(parseIssueCommandInput('resolve',{...base,recoveryOccurrenceId:ID(12),recoveryRunId:ID(22),recoveryRunVersion:3,rootCause:'bad fixture',remediation:'corrected externally'}).recoveryRunVersion,3);
 assert.equal(parseIssueCommandInput('supersede',{...base,replacementMonitorId:ID(9),replacementDefinitionVersion:2}).replacementDefinitionVersion,2);
 assert.equal(parseIssueCommandInput('recovery.request',{...base,id:ID(12)}).id,ID(12));
 reject(()=>parseIssueCommandInput('resolve',{...base,verdict:'PASS'}));reject(()=>parseIssueCommandInput('acknowledge',{...base,reason:' \n '}));reject(()=>parseIssueCommandInput('assign',{...base,ownerId:null}));
});
test('page/filter parsers reject coercion, null, extra or hostile fields and retain omitted values',()=>{
 assert.deepEqual(parseMonitoringPageQuery({}),{});assert.deepEqual(parseMonitoringPageQuery({limit:25,cursor:'abc.def_123-'}),{limit:25,cursor:'abc.def_123-'});
 assert.equal(parseMonitorListQuery({state:'paused',ruleId:ID(1)}).state,'paused');assert.equal(parseQualityIssueListQuery({assignedToMe:false}).assignedToMe,false);
 for(const v of [{limit:'25'},{limit:101},{cursor:''},{cursor:null},{cursor:'x'.repeat(1025)},{extra:1}])reject(()=>parseMonitoringPageQuery(v));reject(()=>parseQualityIssueListQuery({assignedToMe:'true'}));
});
test('monitor response parser checks canonical stored text/hash and separate observation state',()=>{
 assert.deepEqual(parseMonitorView(monitor()),monitor());const e=evidence();
 assert.doesNotThrow(()=>parseMonitorView({...monitor(),lastAdmittedOrdinal:1,lastProjectedOrdinal:1,currentObservation:{state:'conclusive',verdict:'PASS',evidence:e},lastConclusive:{verdict:'PASS',evidence:e}}));
 reject(()=>parseMonitorView({...monitor(),definitionHash:'b'.repeat(64)}));reject(()=>parseMonitorView({...monitor(),definition:{...definition(),name:' Email monitor '}}));
 reject(()=>parseMonitorView({...monitor(),currentObservation:{state:'conclusive',verdict:'PASS',evidence:e}}));
 reject(()=>parseMonitorView({...monitor(),lastProjectedOrdinal:2,lastAdmittedOrdinal:1}));reject(()=>parseMonitorView({...monitor(),state:'retired'}));
 assert.doesNotThrow(()=>parseMonitorView({...monitor(),lastAdmittedOrdinal:2,lastProjectedOrdinal:2,currentObservation:{state:'unknown',reason:'NO_DATA',occurrenceId:ID(12)},lastConclusive:{verdict:'PASS',evidence:e}}));
});
test('historical definitions do not manufacture current head metadata',()=>{
 const d={monitorId:ID(5),definitionVersion:1,definitionHash:monitorDefinitionHash(definition()),definition:definition(),createdAt:START,createdBy:ID(2)};assert.deepEqual(parseMonitorDefinitionView(d),d);reject(()=>parseMonitorDefinitionView({...d,currentVersion:99}));
});
test('occurrences distinguish one execution from compressed skips and finite blocking',()=>{
 assert.deepEqual(parseOccurrence(occurrence()),occurrence());
 assert.doesNotThrow(()=>parseOccurrence({...occurrence(),disposition:'skipped',reason:'RULE_VERSION_CHANGED',runId:null,comparisonScopeHash:null,slots:{firstAt:START,lastAt:at(600),count:11}}));
 assert.doesNotThrow(()=>parseOccurrence({...occurrence(),origin:'recovery-request',slots:null}));
 for(const v of [{...occurrence(),slots:{firstAt:START,lastAt:at(60),count:2}},{...occurrence(),disposition:'skipped',reason:'BLOCKED',runId:null,comparisonScopeHash:null},{...occurrence(),origin:'recovery-request'},{...occurrence(),reference:{codes:['private']}}])reject(()=>parseOccurrence(v));
});
test('comparison scope is closed per family and preserves exact canonical source/population identity',()=>{
 const s=scope();assert.deepEqual(parseComparisonScope(s),s);assert.equal(comparisonScopeHash(s),createHash('sha256').update(canonical(s)).digest('hex'));
 for(const change of [{sourceVersion:2},{sourceConfigHash:'b'.repeat(64)},{rule:{...s.rule,version:2}},{targetHash:'b'.repeat(64)},{family:{...s.family,codesHash:'b'.repeat(64)}}])assert.notEqual(comparisonScopeHash({...s,...change}),comparisonScopeHash(s));
 for(const extra of [{asOf:START},{definitionVersion:2},{codes:['private']},{source:{secretRef:'private'}}])reject(()=>comparisonScopeHash({...s,...extra}));
 for(const family of [{...s.family,asOf:START},{...s.family,codes:['private']},{kind:'uniqueness',comparison:'utf8-exact',nullPolicy:'exclude',reference:s.family},{kind:'range',rangeHash:H,reference:s.family}])reject(()=>comparisonScopeHash({...s,family}));
 for(const family of [{kind:'completeness'},{kind:'uniqueness',comparison:'utf8-exact',nullPolicy:'exclude'},{kind:'range',rangeHash:H}])assert.doesNotThrow(()=>comparisonScopeHash({...s,family}));
});
test('issue responses reject false recovery, cross-scope evidence and conflated supersession',()=>{
 assert.deepEqual(parseIssueView(issue()),issue());assert.doesNotThrow(()=>parseIssueView({...issue(),recovery:evidence(2)}));
 reject(()=>parseIssueView({...issue(),recovery:evidence(1)}));reject(()=>parseIssueView({...issue(),recovery:{...evidence(2),comparisonScopeHash:'b'.repeat(64)}}));
 const resolved={...issue(),status:'resolved',resolution:{rootCause:'bad row',remediation:'fixed outside app',reason:'verified',evidence:evidence(2),at:at(180),by:ID(2)}};assert.doesNotThrow(()=>parseIssueView(resolved));
 reject(()=>parseIssueView({...resolved,recovery:evidence(2)}));reject(()=>parseIssueView({...issue(),status:'resolved'}));
 const superseded={...issue(),status:'superseded',superseded:{reason:'new scope',replacementMonitorId:ID(5),replacementDefinitionVersion:2,at:at(180),by:ID(2)}};assert.doesNotThrow(()=>parseIssueView(superseded));reject(()=>parseIssueView({...superseded,resolution:resolved.resolution}));
});
test('events and notification DTOs refuse private copied source payloads',()=>{
 assert.deepEqual(parseIssueEvent(event()),event());assert.deepEqual(parseNotification(notification()),notification());
 reject(()=>parseIssueEvent({...event(),payload:{source:'private'}}));reject(()=>parseIssueEvent({...event(),occurrenceId:null}));
 reject(()=>parseNotification({...notification(),body:'private'}));reject(()=>parseNotification({...notification(),readAt:at(-1)}));
});
test('slot arithmetic honors anchor, fractional instant, exclusive end and date ceiling',()=>{
 assert.equal(firstMonitorSlotAtOrAfter(schedule(),at(-1)),START);assert.equal(firstMonitorSlotAtOrAfter(schedule(),START),START);assert.equal(firstMonitorSlotAtOrAfter(schedule(),at(0.001)),at(60));
 assert.equal(firstMonitorSlotAtOrAfter({...schedule(),endsAt:at(60)},at(60)),null);
 assert.equal(firstMonitorSlotAtOrAfter({...schedule(),startsAt:'9999-12-31T23:59:59.000Z'},'9999-12-31T23:59:59.999Z'),null);
});
test('due planning admits only newest slot in grace and compresses older misses',()=>{
 assert.deepEqual(plan(125),{records:[{slots:{firstAt:START,lastAt:at(60),count:2},decision:'skipped',reason:'MISSED'},{slots:{firstAt:at(120),lastAt:at(120),count:1},decision:'eligible',reason:null}],nextSlotAt:at(180)});
 assert.deepEqual(plan(126),{records:[{slots:{firstAt:START,lastAt:at(120),count:3},decision:'skipped',reason:'MISSED'}],nextSlotAt:at(180)});
 assert.deepEqual(plan(-1),{records:[],nextSlotAt:START});
});
test('maintenance is slot-based half-open even when delivery is later',()=>{
 assert.deepEqual(plan(125,{maintenance:[{from:at(60),until:at(120)}]}).records.map(r=>[r.slots.count,r.reason]),[[1,'MISSED'],[1,'MAINTENANCE'],[1,null]]);
 assert.equal(plan(125,{maintenance:[{from:at(120),until:at(121)}]}).records.at(-1)?.reason,'MAINTENANCE');
});
test('bounded plan continuation neither loses nor duplicates slots over window boundaries',()=>{
 const maintenance=[{from:at(60),until:at(120)},{from:at(180),until:at(240)}];const whole=plan(300,{maintenance});let next:string|null=START;const records=[];
 for(let i=0;i<8;i++){const p=plan(300,{maintenance,nextSlotAt:next,maximumRecords:1});records.push(...p.records);next=p.nextSlotAt;if(p.records.length===0)break;}
 assert.deepEqual(records,whole.records);assert.equal(next,whole.nextSlotAt);assert.equal(records.reduce((n,r)=>n+r.slots.count,0),6);
});
test('long downtime is constant-size span math, not unbounded per-slot materialization',()=>{
 const r=planDueMonitorSlots({schedule:{...schedule(),startsAt:'2000-01-01T00:00:00.000Z'},maintenance:[],nextSlotAt:'2000-01-01T00:00:00.000Z',now:'2026-11-17T00:00:00.000Z'});
 assert.equal(r.records.length,2);assert.ok(r.records[0].slots.count>10000000);assert.equal(r.records[1].decision,'eligible');
 reject(()=>planDueMonitorSlots({schedule:{...schedule(),startsAt:'0001-01-01T00:00:00.000Z'},maintenance:[],nextSlotAt:'0001-01-01T00:00:00.000Z',now:'9999-01-01T00:00:00.000Z'}));
});
test('cursor and end boundaries reject off-grid values and never execute expired schedule slots',()=>{
 reject(()=>plan(120,{nextSlotAt:at(1)}));reject(()=>plan(120,{nextSlotAt:at(-60)}));reject(()=>plan(120,{maximumRecords:9}));
 assert.deepEqual(plan(180,{schedule:{...schedule(),endsAt:at(120)}}),{records:[{slots:{firstAt:START,lastAt:at(60),count:2},decision:'skipped',reason:'MISSED'}],nextSlotAt:null});
 assert.deepEqual(plan(1,{nextSlotAt:null}),{records:[],nextSlotAt:null});
 assert.equal(plan(62,{schedule:{...schedule(),endsAt:at(62)}}).records.at(-1)?.reason,'MISSED');
});
test('small-domain independent slot oracle covers scheduling windows and grace boundaries',()=>{
 for(let now=-1;now<=240;now++)for(const maintenance of [[],[{from:at(60),until:at(120)}],[{from:at(1),until:at(61)},{from:at(180),until:at(220)}]]){
  const actual=plan(now,{maintenance}).records.flatMap(r=>Array.from({length:r.slots.count},(_,i)=>({at:Date.parse(r.slots.firstAt)+i*60000,reason:r.reason})));
  const expected=[];const last=Math.floor(now/60)*60;for(let t=0;t<=now;t+=60){const maintained=maintenance.some(w=>at(t)>=w.from&&at(t)<w.until);expected.push({at:Date.parse(at(t)),reason:maintained?'MAINTENANCE':t===last&&now-t<=5?null:'MISSED'});}
  assert.deepEqual(actual,expected);
 }
});

test('resolved event retains detached exact recovery narrative after the issue reopens',()=>{
 const resolution={rootCause:'Synthetic missing value',remediation:'Restored externally',reason:'Verified observed recovery',evidence:evidence(2),at:at(180),by:ID(2)};
 const resolved={...event(),kind:'resolved',version:3,actorId:ID(2),occurrenceId:ID(12),runId:ID(22),at:at(181),resolution};
 const result=parseIssueEvent(resolved);assert.deepEqual(result,resolved);resolution.rootCause='Caller mutation';assert.equal(result.resolution?.rootCause,'Synthetic missing value');
 const reopened=parseIssueView({...issue(),version:4,episode:2,lastFailure:evidence(3)});assert.equal(reopened.resolution,null);assert.equal(result.resolution?.remediation,'Restored externally');
});
test('resolved event refuses missing narrative, wrong actor/run/occurrence, premature event time and extra fields',()=>{
 const resolution={rootCause:'Missing value',remediation:'Corrected outside product',reason:'Observed recovery',evidence:evidence(2),at:at(180),by:ID(2)};
 const resolved={...event(),kind:'resolved',version:3,actorId:ID(2),occurrenceId:ID(12),runId:ID(22),at:at(180),resolution};assert.doesNotThrow(()=>parseIssueEvent(resolved));
 for(const delta of [{resolution:null},{actorId:'site:local'},{actorId:ID(3)},{occurrenceId:ID(99)},{runId:ID(99)},{at:at(179)},{resolution:{...resolution,sourceRows:['private']}},{resolution:{...resolution,rootCause:' noncanonical '}}])reject(()=>parseIssueEvent({...resolved,...delta}));
 reject(()=>parseIssueEvent({...event(),resolution}));const {resolution:ignored,...missing}=event();reject(()=>parseIssueEvent(missing));
});
