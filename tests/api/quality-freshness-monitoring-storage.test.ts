// SPDX-License-Identifier: Apache-2.0
/** Actual disposable SQL029 protocol qualification. Aggregates are explicitly
 * authored: this suite does not claim Python source execution or Temporal timers. */
import assert from 'node:assert/strict';
import test,{type TestContext} from 'node:test';
import {randomUUID} from 'node:crypto';
import {sql} from '../../packages/db/src/index.ts';
import {freshnessMonitoringFixture,exactError,claimed,permissions} from '../fixtures/quality-freshness-monitoring.ts';
import {code,denied} from '../fixtures/reference-quality.ts';
import {monitorFreshnessTimeDecision,comparisonScopeHash,parseComparisonScope} from '../../packages/domain/src/quality-monitoring.ts';
import {getQualityMonitor,getQualityIssue,listQualityIssueEvents,listMonitorOccurrences,publishQualityMonitor,commandQualityIssue} from '../../packages/domain/src/quality-monitoring-service.ts';
import {getQualityRun,finishQualityRun} from '../../packages/domain/src/quality-service.ts';
import type {FreshnessRuleDefinition} from '../../packages/domain/src/quality-contracts.ts';
import type {QualityMonitorView,QualityIssueView,QualityOccurrence,MonitorRunEvidence} from '../../packages/domain/src/quality-monitoring-contracts.ts';
type Fixture=Awaited<ReturnType<typeof freshnessMonitoringFixture>>;
const options={timeout:60000};
const problem=(status:number,expected:string)=>(e:unknown)=>!!e&&typeof e==='object'&&'status'in e&&e.status===status&&'code'in e&&e.code===expected;
function enqueued(o:QualityOccurrence):asserts o is Extract<QualityOccurrence,{disposition:'enqueued'}>{assert.equal(o.disposition,'enqueued');assert.ok(o.runId);}
async function setup(t:TestContext,maxAge=90,skew=0){
 const f=await freshnessMonitoringFixture(t),d=f.definition(maxAge,skew),{rule}=await f.publish(d),definition=await f.monitorDefinition(rule),body={id:randomUUID(),expectedRevision:0,definition};
 const {monitor}=await f.as(tx=>publishQualityMonitor(tx,f.principal(),body,randomUUID(),'freshness-schedule-native'));
 return {f,d,rule,monitor,definition};
}
async function scheduled(f:Fixture,m:QualityMonitorView){assert.ok(m.nextSlotAt);await f.waitUntil(m.nextSlotAt);for(let attempt=0;attempt<4;attempt++){await f.tick(m.id);const rows=(await f.occurrences(m.id)).filter(o=>o.definitionVersion===m.definitionVersion);if(rows.length){assert.equal(rows.length,1);const o=rows[0];enqueued(o);assert.equal(o.origin,'schedule');return o;}}assert.fail('Current exact schedule did not admit its first occurrence');}
async function ageCompletion(f:Fixture,runId:string,d:FreshnessRuleDefinition,age:string){
 const claim=await f.claim(runId);claimed(claim);assert.equal(claim.execution.kind,'freshness');
 const sourceObservedAt=await f.microNow(),latestObservedAt=await f.shift(sourceObservedAt,String(-BigInt(age))),at=sourceObservedAt.slice(0,23)+'Z';
 const measurement=await f.measurement(d,{sourceObservedAt,latestObservedAt,observedStartedAt:at,observedFinishedAt:at});
 assert.equal(measurement.ageMicroseconds,age);const {run}=await f.finish(runId,claim,measurement);return {claim,measurement,run};
}
async function failed(t:TestContext){const s=await setup(t),occurrence=await scheduled(s.f,s.monitor),done=await ageCompletion(s.f,occurrence.runId,s.d,'91000000');assert.equal(done.run.verdict,'FAIL');await s.f.reconcile(s.monitor.id);const issues=await s.f.issues(s.monitor.id);assert.equal(issues.length,1);return {...s,occurrence,issue:issues[0]};}
async function requestRecovery(f:Fixture,i:QualityIssueView){const {occurrence}=await f.command<{occurrence:QualityOccurrence}>('quality.issue.recovery.request',{issueId:i.id,expectedVersion:i.version,reason:'Verify observed correction.',id:randomUUID()});enqueued(occurrence);assert.equal(occurrence.origin,'recovery-request');return occurrence;}
async function recovered(t:TestContext,age='60000000'){const s=await failed(t),recovery=await requestRecovery(s.f,s.issue),done=await ageCompletion(s.f,recovery.runId,s.d,age);assert.equal(done.run.verdict,'PASS');await s.f.reconcile(s.monitor.id);const issue=await s.f.issue(s.issue.id);assert.ok(issue.recovery);assert.equal(issue.recovery.runId,recovery.runId);return {...s,issue,recovery,done};}
function resolveBody(i:QualityIssueView){assert.ok(i.recovery);return {issueId:i.id,expectedVersion:i.version,reason:'Verified the exact current observation.',recoveryOccurrenceId:i.recovery.occurrenceId,recoveryRunId:i.recovery.runId,recoveryRunVersion:i.recovery.runVersion,rootCause:'Synthetic timestamp lag.',remediation:'Updated independently owned source timestamp.'};}
async function rawCurrent(f:Fixture,m:string,e:MonitorRunEvidence,at:string|null=null){return f.ownerTx(async()=>String((await f.owner.query('SELECT public.gc_quality_monitor_freshness_current($1::uuid,$2::jsonb,$3::timestamptz) AS value',[m,JSON.stringify(e),at])).rows[0].value));}
async function events(f:Fixture,id:string){return f.as(tx=>listQualityIssueEvents(tx,f.principal(),id,{limit:100}));}
async function expiry(f:Fixture,runId:string){return f.ownerTx(async()=>String((await f.owner.query("SELECT to_char((claimed_at+((inputs#>>'{execution,freshness,maximumAgeSeconds}')::numeric*1000000-greatest((measurement->>'ageMicroseconds')::numeric,0))*interval '1 microsecond') AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS value FROM quality_runs WHERE tenant_id=$1 AND id=$2",[f.tenant,runId])).rows[0].value));}
async function waitExpired(f:Fixture,at:string){const delay=Number((await f.owner.query('SELECT greatest(extract(epoch FROM $1::timestamptz-clock_timestamp()),0) AS value',[at])).rows[0].value);assert.ok(delay<=3,'Only a deliberately short native expiry is awaited');await f.owner.query('SELECT pg_sleep(greatest(extract(epoch FROM $1::timestamptz-clock_timestamp()),0)+0.01)',[at]);}
// Date serializes exact integral milliseconds only; all arithmetic/comparison is BigInt.
function utc6(value:string){const n=BigInt(value);let ms=n/1000n,rem=n%1000n;if(rem<0){ms--;rem+=1000n;}return new Date(Number(ms)).toISOString().slice(0,-1)+String(rem).padStart(3,'0')+'Z';}

// All cases are mandatory, without skip/retry or a shared database fallback.
test('freshness scheduled scope uses exact settings hash and preserves the existing evidence DTO',options,async t=>{
 const {f,d,monitor}=await setup(t),o=await scheduled(f,monitor),stored=await f.as(tx=>tx.selectFrom('quality_monitor_occurrences').selectAll().where('id','=',o.id).executeTakeFirstOrThrow());
 assert.deepEqual(stored.comparison_scope.family,{kind:'freshness',freshnessHash:f.binding(d).freshnessHash});assert.deepEqual(parseComparisonScope(stored.comparison_scope),stored.comparison_scope);assert.equal(stored.comparison_scope_hash,comparisonScopeHash(stored.comparison_scope));
 const done=await ageCompletion(f,o.runId,d,'60000000');assert.equal(done.run.verdict,'PASS');await f.reconcile(monitor.id);const current=await f.monitor(monitor.id);assert.equal(current.currentObservation.state,'conclusive');assert.ok(current.lastConclusive);
 assert.deepEqual(Object.keys(current.lastConclusive.evidence).sort(),['comparisonScopeHash','completionHash','observedFinishedAt','occurrenceId','ordinal','runId','runVersion'].sort());
 assert.equal(await rawCurrent(f,monitor.id,current.lastConclusive.evidence),'eligible');
 const row=await f.as(tx=>tx.selectFrom('quality_runs').select(['requester_id','inputs']).where('id','=',o.runId).executeTakeFirstOrThrow());assert.equal(row.requester_id,f.actor);assert.deepEqual(row.inputs.execution.freshness,f.binding(d));
});

test('SQL exact microsecond expiry matches the independent domain oracle at both inclusive bounds',options,async t=>{
 const f=await freshnessMonitoringFixture(t),base={claimedAtUs:'1000000000',finishedAtUs:'1001000100',projectedAtUs:'1001000000',observedFinishedAtUs:'1001000000',evaluatedAtUs:'1030000000',measuredAgeUs:'60000000',maximumAgeSeconds:90,recoveryMaximumAgeSeconds:60};
 const patches=[{}, {evaluatedAtUs:'1030000001'},{measuredAgeUs:'-10000000',evaluatedAtUs:'1090000001',recoveryMaximumAgeSeconds:120},{maximumAgeSeconds:3600,evaluatedAtUs:'1061000000'},{maximumAgeSeconds:3600,evaluatedAtUs:'1061000001'},{measuredAgeUs:'90000000',evaluatedAtUs:'1001000100'},{evaluatedAtUs:'1001000099'},{measuredAgeUs:'90000001'},{claimedAtUs:'1020000000',finishedAtUs:'1021000100',projectedAtUs:'1021000000',observedFinishedAtUs:'1021000000',evaluatedAtUs:'1050000000'},{claimedAtUs:'1001000101'},{evaluatedAtUs:'1001000100'}, {claimedAtUs:'253402300000000000',finishedAtUs:'253402300000001001',projectedAtUs:'253402300000001000',observedFinishedAtUs:'253402300000001000',evaluatedAtUs:'253402300030000001'}];
 for(const patch of patches){const v={...base,...patch},args=[v.claimedAtUs,v.finishedAtUs,v.projectedAtUs,v.observedFinishedAtUs,v.evaluatedAtUs].map(utc6);const actual=(await f.owner.query('SELECT public.gc_quality_monitor_freshness_time($1::timestamptz,$2::timestamptz,$3::timestamptz,$4::timestamptz,$5::timestamptz,$6::numeric,$7::integer,$8::integer) AS value',[...args,v.measuredAgeUs,v.maximumAgeSeconds,v.recoveryMaximumAgeSeconds])).rows[0].value;assert.equal(actual,monitorFreshnessTimeDecision(v).reason);}
 for(const invalid of ['infinity','-infinity','10000-01-01T00:00:00Z'])assert.equal((await f.owner.query("SELECT public.gc_quality_monitor_freshness_time($1::timestamptz,$1::timestamptz,$1::timestamptz,$1::timestamptz,$1::timestamptz,0,90,60) AS value",[invalid])).rows[0].value,'evidence-unavailable');
});

test('freshness FAIL opens a real issue and linked current PASS announces one eligible recovery',options,async t=>{
 const {f,monitor,issue,recovery,done}=await recovered(t);assert.equal(issue.status,'open');assert.equal(issue.lastFailure.ordinal,1);assert.equal(issue.recovery?.ordinal,2);const retained=await f.as(tx=>tx.selectFrom('quality_runs').select('completion_hash').where('id','=',done.run.id).executeTakeFirstOrThrow());assert.equal(issue.recovery?.completionHash,retained.completion_hash);
 const list=await events(f,issue.id);assert.deepEqual(list.items.map(e=>e.kind),['opened','recovery-available']);assert.equal(list.items[1].runId,recovery.runId);
 const before=await f.state();await f.reconcile(monitor.id);assert.deepEqual(await f.state(),before);assert.equal((await f.monitor(monitor.id)).currentObservation.state,'conclusive');
});

test('zero remaining age keeps immutable PASS while current status is STALE and no recovery is announced',options,async t=>{
 const {f,d,monitor,issue}=await failed(t),o=await requestRecovery(f,issue),done=await ageCompletion(f,o.runId,d,'90000000');assert.equal(done.run.verdict,'PASS');await f.reconcile(monitor.id);
 const m=await f.monitor(monitor.id);assert.deepEqual(m.currentObservation,{state:'unknown',reason:'STALE',occurrenceId:o.id});assert.equal(m.lastConclusive?.verdict,'PASS');assert.equal((await f.issue(issue.id)).recovery,null);assert.deepEqual((await events(f,issue.id)).items.map(e=>e.kind),['opened']);assert.equal((await f.as(tx=>getQualityRun(tx,f.principal(),o.runId))).verdict,'PASS');
});

test('tolerated future timestamps receive exactly maximum age and no extra future credit',options,async t=>{
 const {f,d,monitor}=await setup(t,90,30),o=await scheduled(f,monitor),done=await ageCompletion(f,o.runId,d,'-10000000');assert.equal(done.run.verdict,'PASS');await f.reconcile(monitor.id);const e=(await f.monitor(monitor.id)).lastConclusive!.evidence;
 const boundary=await expiry(f,o.runId);assert.equal(await rawCurrent(f,monitor.id,e,boundary),'eligible');assert.equal(await rawCurrent(f,monitor.id,e,await f.shift(boundary,'1')),'expired');
 const beyond=await f.shift(boundary,'5000000');assert.equal(await rawCurrent(f,monitor.id,e,beyond),'expired');
});

test('current monitor and issue views agree after expiry without rewriting historical receipts',options,async t=>{
 const {f,monitor,issue,recovery}=await recovered(t,'89000000'),before=await f.state(),at=await expiry(f,recovery.runId);await waitExpired(f,at);
 const m=await f.monitor(monitor.id),i=await f.issue(issue.id);assert.deepEqual(m.currentObservation,{state:'unknown',reason:'STALE',occurrenceId:recovery.id});assert.equal(m.lastConclusive?.verdict,'PASS');assert.equal(i.recovery,null);assert.equal(m.lastAdmittedOrdinal,2);assert.equal(m.lastProjectedOrdinal,2);assert.deepEqual(await f.state(),before);
 await f.unchanged(()=>f.command('quality.issue.resolve',resolveBody(issue)),exactError('40001','RECOVERY_UNAVAILABLE'));
});

test('freshness resolution retains exact immutable evidence and authorized replay after expiry',options,async t=>{
 const {f,d,rule,monitor,issue,recovery}=await recovered(t,'89000000'),body=resolveBody(issue),key=randomUUID(),result=await f.command<{issue:QualityIssueView}>('quality.issue.resolve',body,key);assert.equal(result.issue.status,'resolved');assert.equal(result.issue.resolution?.evidence.runId,recovery.runId);const before=await f.state();await waitExpired(f,await expiry(f,recovery.runId));
 assert.deepEqual(await f.command('quality.issue.resolve',body,key),result);assert.deepEqual(await f.state(),before);assert.equal((await f.monitor(monitor.id)).currentObservation.state,'unknown');
 const list=await events(f,issue.id),resolved=list.items.find(e=>e.kind==='resolved');assert.ok(resolved);assert.deepEqual(resolved.resolution,result.issue.resolution);
 const current=await f.monitor(monitor.id),next=(await f.publishMonitor(rule,await f.monitorDefinition(rule),monitor.id,current.revision)).monitor,again=await scheduled(f,next);await ageCompletion(f,again.runId,d,'91000000');for(let i=0;i<3;i++)await f.reconcile(monitor.id);const reopened=await f.issue(issue.id);assert.equal(reopened.status,'open');assert.equal(reopened.episode,2);assert.equal(reopened.resolution,null);assert.deepEqual((await events(f,issue.id)).items.find(e=>e.kind==='resolved')?.resolution,result.issue.resolution);
 await f.revoke(f.actor,['catalog:read']);await f.unchanged(()=>f.command('quality.issue.resolve',body,key),code('42501'));
});

test('resolution waiting on an observed independent lock rechecks actual expiry after acquiring it',options,async t=>{
 const {f,issue,recovery}=await recovered(t,'89000000'),body=resolveBody(issue),at=await expiry(f,recovery.runId),before=await f.state(),pid=(await f.as(tx=>sql<{pid:number}>`select pg_backend_pid() as pid`.execute(tx))).rows[0].pid;
 await f.owner.query('BEGIN');await f.owner.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[f.tenant]);let failure:unknown,success:unknown;const work=f.command('quality.issue.resolve',body).then(v=>{success=v;},e=>{failure=e;});
 try{let observed=false;const end=performance.now()+1200;while(performance.now()<end){if((await f.owner.query('SELECT pg_backend_pid()=ANY(pg_blocking_pids($1)) AS blocked',[pid])).rows[0].blocked){observed=true;break;}await new Promise(r=>setTimeout(r,10));}assert.equal(observed,true,'Actual application connection waits on this exact holder');assert.equal((await f.owner.query('SELECT clock_timestamp()<$1::timestamptz AS before_expiry',[at])).rows[0].before_expiry,true,'The request is actually blocked while evidence remains eligible');await waitExpired(f,at);}finally{await f.owner.query('ROLLBACK');await work;}
 assert.equal(success,undefined);assert.equal(exactError('40001','RECOVERY_UNAVAILABLE')(failure),true);assert.deepEqual(await f.state(),before);assert.equal((await f.issue(issue.id)).recovery,null);
});

test('a newer pending observation invalidates earlier recovery before it finishes',options,async t=>{
 const {f,monitor,issue}=await recovered(t),next=await requestRecovery(f,issue),m=await f.monitor(monitor.id);assert.deepEqual(m.currentObservation,{state:'pending',occurrenceId:next.id,runId:next.runId});assert.equal(m.lastAdmittedOrdinal,3);assert.equal(m.lastConclusive?.verdict,'PASS');assert.equal((await f.issue(issue.id)).recovery,null);await f.unchanged(()=>f.command('quality.issue.resolve',resolveBody(issue)),exactError('40001','RECOVERY_UNAVAILABLE'));
});

test('NO_DATA and clock-skew failures cannot provide freshness recovery',options,async t=>{
 const {f,d,monitor,issue}=await failed(t),one=await requestRecovery(f,issue),noData=await f.complete(one.runId,d,{rowCount:3,nullCount:3,latestObservedAt:null,ageMicroseconds:null});assert.equal(noData.run.verdict,'NO_DATA');await f.reconcile(monitor.id);assert.equal((await f.monitor(monitor.id)).currentObservation.state,'unknown');assert.equal((await f.issue(issue.id)).recovery,null);
 const two=await requestRecovery(f,await f.issue(issue.id)),claim=await f.claim(two.runId);claimed(claim);const result=await f.as(tx=>finishQualityRun(tx,two.runId,{claimId:claim.claimId,attempt:claim.attempt,errorCode:'QUALITY_CLOCK_SKEW'}),'site:local');assert.equal(result.run.status,'failed');assert.equal(result.run.measurement,null);await f.reconcile(monitor.id);assert.deepEqual((await f.monitor(monitor.id)).currentObservation,{state:'unknown',reason:'EXECUTION_FAILED',occurrenceId:two.id});assert.equal((await f.issue(issue.id)).recovery,null);assert.equal((await events(f,issue.id)).items.some(e=>e.kind==='recovery-available'),false);
});

test('changed current rule pin refuses retained recovery and keeps the original run history',options,async t=>{
 const {f,d,rule,monitor,issue,recovery}=await recovered(t);await f.publish({...d,maximumAgeSeconds:120},rule.id,1);const m=await f.monitor(monitor.id);assert.deepEqual(m.currentObservation,{state:'unknown',reason:'BLOCKED',occurrenceId:recovery.id});assert.equal((await f.issue(issue.id)).recovery,null);assert.equal((await f.as(tx=>getQualityRun(tx,f.principal(),recovery.runId))).verdict,'PASS');await f.unchanged(()=>f.command('quality.issue.resolve',resolveBody(issue)),exactError('40001','RECOVERY_UNAVAILABLE'));
});

test('changed source configuration cannot reuse the same freshness setting hash as current evidence',options,async t=>{
 const {f,monitor,issue,recovery}=await recovered(t);await f.ownerTx(()=>f.owner.query("UPDATE sources SET host='changed.synthetic.invalid',version=version+1 WHERE tenant_id=$1 AND id=$2",[f.tenant,f.sourceId]));assert.deepEqual((await f.monitor(monitor.id)).currentObservation,{state:'unknown',reason:'BLOCKED',occurrenceId:recovery.id});assert.equal((await f.issue(issue.id)).recovery,null);await f.unchanged(()=>f.command('quality.issue.resolve',resolveBody(issue)),exactError('40001','RECOVERY_UNAVAILABLE'));
});

test('current executor and distinct rule owner authority are checked for retained freshness recovery',options,async t=>{
 const {f,monitor,issue,recovery}=await recovered(t);for(const who of [f.actor,f.ruleOwner]){if(who===f.actor)await f.revoke(who,['catalog:read','quality:read']);else await f.ownerTx(()=>f.owner.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,who]));const m=await f.as(tx=>getQualityMonitor(tx,f.principal(f.reader),monitor.id),f.reader);assert.deepEqual(m.currentObservation,{state:'unknown',reason:'BLOCKED',occurrenceId:recovery.id});assert.equal((await f.as(tx=>getQualityIssue(tx,f.principal(f.reader),issue.id),f.reader)).recovery,null);if(who===f.actor)await f.revoke(who,permissions);else await f.ownerTx(()=>f.owner.query('UPDATE memberships SET active=true WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,who]));}
 assert.ok((await f.issue(issue.id)).recovery);
});

test('current target visibility denies hidden freshness evidence and foreign identifiers remain unavailable',options,async t=>{
 const {f,monitor,issue}=await recovered(t);await f.ownerTx(()=>f.owner.query("UPDATE assets SET visibility='restricted',allowed_identities=$3::jsonb WHERE tenant_id=$1 AND id=$2",[f.tenant,f.schemaId,JSON.stringify([f.reviewer])]));
 await f.unchanged(()=>f.as(tx=>getQualityMonitor(tx,f.principal(),monitor.id)),problem(404,'MONITOR_UNAVAILABLE'));await f.unchanged(()=>f.as(tx=>getQualityIssue(tx,f.principal(),issue.id)),problem(404,'MONITOR_UNAVAILABLE'));await f.unchanged(()=>f.command('quality.issue.resolve',resolveBody(issue)),denied);
 await f.unchanged(()=>f.as(tx=>getQualityIssue(tx,f.principal(f.outsider,f.foreign),issue.id),f.outsider,f.foreign),problem(404,'MONITOR_UNAVAILABLE'));
});

test('consumer freshness history is authorized but command privileges and cursor identity remain current',options,async t=>{
 const {f,monitor,issue}=await recovered(t);assert.equal((await f.as(tx=>getQualityMonitor(tx,f.principal(f.reader),monitor.id),f.reader)).id,monitor.id);const first=await f.as(tx=>listMonitorOccurrences(tx,f.principal(f.reader),monitor.id,{limit:1}),f.reader);assert.equal(first.items.length,1);assert.ok(first.nextCursor);await f.unchanged(()=>f.as(tx=>listMonitorOccurrences(tx,f.principal(),monitor.id,{limit:1,cursor:first.nextCursor!})),problem(400,'PAGE_INVALID'));
 await f.unchanged(()=>f.command('quality.issue.resolve',resolveBody(issue),randomUUID(),f.reader),code('42501'));await f.revoke(f.reader,['catalog:read']);await f.unchanged(()=>f.as(tx=>listMonitorOccurrences(tx,f.principal(f.reader),monitor.id,{limit:1,cursor:first.nextCursor!}),f.reader),problem(403,'MONITOR_FORBIDDEN'));
});

test('private freshness timing helpers cannot let runtime callers substitute a decision clock',options,async t=>{
 const {f,monitor}=await setup(t),o=await scheduled(f,monitor);await ageCompletion(f,o.runId,f.definition(),'60000000');await f.reconcile(monitor.id);const evidence=(await f.monitor(monitor.id)).lastConclusive!.evidence;
 await f.unchanged(()=>f.as(tx=>sql`select public.gc_quality_monitor_freshness_current(${monitor.id}::uuid,${JSON.stringify(evidence)}::jsonb,clock_timestamp())`.execute(tx)),code('42501'));
 await f.unchanged(()=>f.as(tx=>sql`select public.gc_quality_monitor_freshness_time(clock_timestamp(),clock_timestamp(),clock_timestamp(),clock_timestamp(),clock_timestamp(),0::numeric,90,60)`.execute(tx)),code('42501'));
 const privileges=(await f.owner.query("SELECT p.proname,has_function_privilege('gc_app',p.oid,'EXECUTE') AS allowed FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.proname IN ('gc_quality_monitor_freshness_current','gc_quality_monitor_freshness_time') ORDER BY p.proname")).rows;assert.equal(privileges.length,2);assert.ok(privileges.every(p=>p.allowed===false));
});

test('freshness resolution exact evidence pins reject substitutions without consuming the command receipt',options,async t=>{
 const {f,issue}=await recovered(t),body=resolveBody(issue);for(const patch of [{recoveryOccurrenceId:randomUUID()},{recoveryRunId:randomUUID()},{recoveryRunVersion:body.recoveryRunVersion+1}])await f.unchanged(()=>f.command('quality.issue.resolve',{...body,...patch}),exactError('40001','RECOVERY_UNAVAILABLE'));
 const {issueId,...input}=body;const result=await f.as(tx=>commandQualityIssue(tx,f.principal(),issueId,'resolve',input,randomUUID(),'freshness-current-service'));assert.equal(result.issue.status,'resolved');assert.equal(result.issue.resolution?.evidence.runId,body.recoveryRunId);
});

test('freshness scheduled claim and finish retain immediate executor revocation fencing',options,async t=>{
 const {f,d,monitor}=await setup(t),o=await scheduled(f,monitor),claim=await f.claim(o.runId);claimed(claim);await f.revoke(f.actor,['catalog:read','quality:read']);const result=await f.finish(o.runId,claim,await f.measurement(d));assert.equal(result.run.status,'cancelled');assert.equal(result.run.errorCode,'QUALITY_AUTHORITY_REVOKED');assert.equal(result.run.measurement,null);await f.reconcile(monitor.id);assert.deepEqual((await f.as(tx=>getQualityMonitor(tx,f.principal(f.reader),monitor.id),f.reader)).currentObservation,{state:'unknown',reason:'CANCELLED',occurrenceId:o.id});assert.equal((await f.issues(monitor.id)).length,0);
});
