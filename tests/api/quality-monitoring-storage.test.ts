// SPDX-License-Identifier: Apache-2.0
/** Real disposable PostgreSQL qualification of the monitoring storage protocol.
 * Measurements are deliberately authored aggregate protocol fixtures, not worker,
 * Temporal, source-observation or wall-clock scheduler qualification. */
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import test,{type TestContext} from 'node:test';
import {sql} from '../../packages/db/src/index.ts';
import {assetView} from '../../apps/api/src/repository.ts';
import {monitoringFixture,monitoringTables,exactError} from '../fixtures/quality-monitoring.ts';
import {permissions,claimed,code,hash} from '../fixtures/reference-quality.ts';
import {monitorDefinitionHash,parseMonitorDefinition,firstMonitorSlotAtOrAfter,comparisonScopeHash} from '../../packages/domain/src/quality-monitoring.ts';
import {getQualityMonitor,getMonitorDefinition,getQualityIssue,listQualityMonitors,listMonitorDefinitions,listMonitorOccurrences,listQualityIssueEvents,listQualityIssues,listQualityNotifications,publishQualityMonitor,commandQualityIssue,markQualityNotificationRead,pendingMonitoringWork} from '../../packages/domain/src/quality-monitoring-service.ts';
import type {QualityMonitorView,QualityMonitorDefinition,QualityOccurrence,QualityIssueView} from '../../packages/domain/src/quality-monitoring-contracts.ts';
import type {QualityRuleView} from '../../packages/domain/src/quality-contracts.ts';
type Fixture=Awaited<ReturnType<typeof monitoringFixture>>;
const options={timeout:60000};
const problem=(status:number,expected:string)=>(e:unknown)=>!!e&&typeof e==='object'&&'status'in e&&e.status===status&&'code'in e&&e.code===expected;
function enqueued(o:QualityOccurrence):asserts o is Extract<QualityOccurrence,{disposition:'enqueued'}>{assert.equal(o.disposition,'enqueued');assert.ok(o.runId);}
async function setup(t:TestContext,patch:Partial<QualityMonitorDefinition>={}){
 const f=await monitoringFixture(t),{rule}=await f.publish(f.completeness());
 const definition=await f.monitorDefinition(rule,patch),{monitor}=await f.publishMonitor(rule,definition);
 return {f,rule,definition,monitor};
}
async function scheduled(f:Fixture,m:QualityMonitorView){
 assert.ok(m.nextSlotAt);await f.waitUntil(m.nextSlotAt);
 // A legitimate definition change can leave one closed schedule segment to drain.
 // Only the protected tick advances it; no row/cursor rewrites or synthetic clock.
 for(let i=0;i<4;i++){
  await f.tick(m.id);const matches=(await f.occurrences(m.id)).filter(o=>o.definitionVersion===m.definitionVersion);
  if(matches.length){const o=matches.at(-1)!;enqueued(o);return o;}
 }
 assert.fail('Current immutable schedule did not admit an occurrence');
}
async function failed(t:TestContext){
 const s=await setup(t),occurrence=await scheduled(s.f,s.monitor),completion=await s.f.complete(occurrence.runId);
 assert.equal(completion.run.verdict,'FAIL');await s.f.reconcile(s.monitor.id);
 const issues=await s.f.issues(s.monitor.id);assert.equal(issues.length,1);
 return {...s,occurrence,issue:issues[0]};
}
async function recovery(f:Fixture,i:QualityIssueView){
 const result=await f.command<{occurrence:QualityOccurrence}>('quality.issue.recovery.request',{issueId:i.id,expectedVersion:i.version,reason:'Validate the corrective action against current source state.',id:randomUUID()});
 enqueued(result.occurrence);assert.equal(result.occurrence.origin,'recovery-request');assert.equal(result.occurrence.slots,null);return result.occurrence;
}
async function finishError(f:Fixture,runId:string){
 const c=await f.claim(runId);claimed(c);
 return f.as(async tx=>(await sql<{value:any}>`select public.gc_quality_finish(${runId}::uuid,${JSON.stringify({claimId:c.claimId,attempt:c.attempt,errorCode:'QUALITY_SOURCE_FAILED'})}::jsonb) as value`.execute(tx)).rows[0].value,'site:local');
}
async function events(f:Fixture,issueId:string,who=f.actor){return f.as(tx=>listQualityIssueEvents(tx,f.principal(who),issueId,{limit:100}),who);}
async function deactivate(f:Fixture,who:string){await f.ownerTx(()=>f.owner.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,who]));}
async function freshDefinition(f:Fixture,rule:QualityRuleView,m:QualityMonitorView){return (await f.publishMonitor(rule,await f.monitorDefinition(rule),m.id,m.revision)).monitor;}

// All declarations are mandatory; no skip/retry or shared-runtime fallback.
test('monitor SQL definitions, canonical hash and half-open UTC slots match the TypeScript contract',options,async t=>{
 const {f,definition,monitor}=await setup(t);
 assert.deepEqual(parseMonitorDefinition(definition),definition);assert.equal(monitor.definitionHash,monitorDefinitionHash(definition));
 const values=[definition,{...definition,schedule:{...definition.schedule,intervalSeconds:59}},{...definition,routing:{...definition.routing,recipientIds:[f.reviewer,f.reviewer]}},{...definition,name:' padded '},{...definition,unknown:true}];
 for(const value of values){let normalized:QualityMonitorDefinition|null=null;try{normalized=parseMonitorDefinition(value);}catch{}
  // HTTP normalization precedes the SQL canonical-value contract.
  const stored=normalized??value,result=await f.ownerTx(()=>f.owner.query('SELECT public.gc_quality_monitor_definition_valid($1::jsonb) AS valid,public.gc_type_migration_hash($1::jsonb) AS hash',[JSON.stringify(stored)]));
  assert.equal(result.rows[0].valid,normalized!==null);if(normalized)assert.equal(result.rows[0].hash,monitorDefinitionHash(normalized));
 }
 const start=Date.parse(definition.schedule.startsAt),bounded={...definition,schedule:{...definition.schedule,endsAt:new Date(start+120000).toISOString()}};
 for(const offset of [-1,0,1,59999,60000,60001,120000]){const at=new Date(start+offset).toISOString(),value=await f.ownerTx(()=>f.owner.query('SELECT public.gc_relation_utc(public.gc_quality_monitor_first_slot($1::jsonb,$2::timestamptz)) AS at',[JSON.stringify(bounded),at]));assert.equal(value.rows[0].at,firstMonitorSlotAtOrAfter(bounded.schedule,at));}
});

test('monitor publication retains exact receipts across revisions and refuses stale or changed commands atomically',options,async t=>{
 const f=await monitoringFixture(t),{rule}=await f.publish(f.completeness()),definition=await f.monitorDefinition(rule),body={id:randomUUID(),expectedRevision:0,definition},key=randomUUID();
 const original=await f.command('quality.monitor.publish',body,key);
 const next=await f.publishMonitor(rule,{...definition,name:'Reviewed successor'},body.id,1);assert.equal(next.monitor.definitionVersion,2);
 const before=await f.state();assert.deepEqual(await f.command('quality.monitor.publish',body,key),original);assert.deepEqual(await f.state(),before);
 await f.unchanged(()=>f.command('quality.monitor.publish',{...body,definition:{...definition,name:'Changed retry'}},key),exactError('40001','IDEMPOTENCY_CONFLICT'));
 await f.unchanged(()=>f.publishMonitor(rule,definition,body.id,1),exactError('40001','VERSION_CONFLICT'));
});

test('monitor publication requires the authenticated self executor, exact current rule and current routing recipients',options,async t=>{
 const f=await monitoringFixture(t),{rule}=await f.publish(f.completeness()),definition=await f.monitorDefinition(rule);
 await f.unchanged(()=>f.publishMonitor(rule,{...definition,executorId:f.reviewer}),exactError('42501','MONITOR_FORBIDDEN'));
 await f.unchanged(()=>f.publishMonitor(rule,{...definition,rule:{...definition.rule,definitionHash:'0'.repeat(64)}}),exactError('40001','MONITOR_PIN_STALE'));
 await f.revoke(f.reviewer,['catalog:read']);
 await f.unchanged(()=>f.publishMonitor(rule,definition),exactError('42501','MONITOR_FORBIDDEN'));
});

test('a protected tick creates one scheduled run with immutable human requester and site audit provenance',options,async t=>{
 const {f,monitor,definition}=await setup(t),o=await scheduled(f,monitor);
 assert.equal(o.ordinal,1);assert.equal(o.executorId,f.actor);assert.deepEqual(o.slots,{firstAt:definition.schedule.startsAt,lastAt:definition.schedule.startsAt,count:1});
 const rows=await f.ownerTx(async()=>({run:(await f.owner.query('SELECT requester_id,status,inputs FROM quality_runs WHERE tenant_id=$1 AND id=$2',[f.tenant,o.runId])).rows[0],audit:(await f.owner.query("SELECT actor_id,action FROM audit WHERE tenant_id=$1 AND changes->>'runId'=$2 ORDER BY action",[f.tenant,o.runId])).rows,scope:(await f.owner.query('SELECT comparison_scope,comparison_scope_hash FROM quality_monitor_occurrences WHERE tenant_id=$1 AND id=$2',[f.tenant,o.id])).rows[0]}));
 assert.equal(rows.run.requester_id,f.actor);assert.equal(rows.run.status,'queued');assert.deepEqual(rows.audit.map(r=>r.action),['quality.monitor_occurrence','quality.run_requested']);assert.ok(rows.audit.every(r=>r.actor_id==='site:local'));
 assert.equal(rows.scope.comparison_scope_hash,comparisonScopeHash(rows.scope.comparison_scope));
 const before=await f.state();assert.equal((await f.tick(monitor.id)).state,'idle');assert.deepEqual(await f.state(),before);
 assert.deepEqual((await f.monitor(monitor.id)).currentObservation,{state:'pending',occurrenceId:o.id,runId:o.runId});
});

test('a missed grace window is recorded as unknown without running historical source work',options,async t=>{
 const f=await monitoringFixture(t),{rule}=await f.publish(f.completeness()),d=await f.monitorDefinition(rule);d.schedule.lateGraceSeconds=0;
 const {monitor}=await f.publishMonitor(rule,d);await f.waitUntil(new Date(Date.parse(d.schedule.startsAt)+100).toISOString());await f.tick(monitor.id);
 const [o]=await f.occurrences(monitor.id);assert.equal(o.disposition,'skipped');assert.equal(o.reason,'MISSED');assert.equal(o.runId,null);assert.equal(o.slots?.count,1);
 await f.reconcile(monitor.id);assert.deepEqual((await f.monitor(monitor.id)).currentObservation,{state:'unknown',reason:'SKIPPED',occurrenceId:o.id});assert.deepEqual(await f.issues(monitor.id),[]);
});

test('maintenance consumes the actual due slot without source work and silence only suppresses delivery',options,async t=>{
 const f=await monitoringFixture(t),{rule}=await f.publish(f.completeness()),d=await f.monitorDefinition(rule);d.maintenance=[{from:d.schedule.startsAt,until:new Date(Date.parse(d.schedule.startsAt)+60000).toISOString()}];
 const {monitor}=await f.publishMonitor(rule,d);await f.waitUntil(d.schedule.startsAt);await f.tick(monitor.id);const [skip]=await f.occurrences(monitor.id);assert.equal(skip.reason,'MAINTENANCE');assert.equal(skip.runId,null);await f.reconcile(monitor.id);
 const next=await f.monitorDefinition(rule);next.silences=[{from:next.schedule.startsAt,until:new Date(Date.parse(next.schedule.startsAt)+60000).toISOString()}];
 const m=(await f.publishMonitor(rule,next,monitor.id,1)).monitor,o=await scheduled(f,m);await f.complete(o.runId);await f.reconcile(m.id);assert.equal((await f.issues(m.id)).length,1);
 const suppressed=await f.ownerTx(()=>f.owner.query('SELECT suppressed FROM quality_monitor_notifications WHERE tenant_id=$1',[f.tenant]));assert.equal(suppressed.rows.length,1);assert.equal(suppressed.rows[0].suppressed,'SILENCED');
 assert.deepEqual((await f.as(tx=>listQualityNotifications(tx,f.principal(f.reviewer)),f.reviewer)).items,[]);
});

test('pause and resume retain paused slots and retirement cannot silently reactivate a monitor',options,async t=>{
 const {f,monitor,definition}=await setup(t);
 const paused=await f.command<{monitor:QualityMonitorView}>('quality.monitor.state',{monitorId:monitor.id,expectedRevision:1,action:'pause',reason:'Pause approved schedule.'});assert.equal(paused.monitor.state,'paused');
 await f.waitUntil(definition.schedule.startsAt);
 const resumed=await f.command<{monitor:QualityMonitorView}>('quality.monitor.state',{monitorId:monitor.id,expectedRevision:2,action:'resume',reason:'Resume current approved schedule.'});assert.equal(resumed.monitor.state,'enabled');
 for(let n=0;n<3;n++)await f.tick(monitor.id);
 const rows=await f.occurrences(monitor.id);assert.equal(rows.length,1);assert.equal(rows[0].reason,'PAUSED');assert.equal(rows[0].runId,null);
 await f.command('quality.monitor.state',{monitorId:monitor.id,expectedRevision:3,action:'retire',reason:'Retire schedule.'});
 await f.unchanged(()=>f.command('quality.monitor.state',{monitorId:monitor.id,expectedRevision:4,action:'resume',reason:'Attempt retired restart.'}),exactError('40001','VERSION_CONFLICT'));
});

test('overlap and per-source scheduled capacity are finite skipped occurrences rather than duplicate runs',options,async t=>{
 const f=await monitoringFixture(t),monitors:QualityMonitorView[]=[];let firstRule:QualityRuleView|undefined;
 for(let n=0;n<3;n++){const {rule}=await f.publish({...f.completeness(),name:'Capacity rule '+n});firstRule??=rule;monitors.push((await f.publishMonitor(rule)).monitor);}
 for(const m of monitors){await f.waitUntil(m.nextSlotAt!);await f.tick(m.id);}
 const third=(await f.occurrences(monitors[2].id))[0];assert.equal(third.reason,'CAPACITY');assert.equal(third.runId,null);
 const next=await freshDefinition(f,firstRule!,monitors[0]);await f.waitUntil(next.nextSlotAt!);for(let n=0;n<3;n++)await f.tick(next.id);
 const overlaps=(await f.occurrences(next.id)).filter(o=>o.definitionVersion===2);assert.equal(overlaps.length,1);assert.equal(overlaps[0].reason,'OVERLAP');assert.equal(overlaps[0].runId,null);
});

test('expired authorization records a blocked occurrence without changing the executor identity',options,async t=>{
 const f=await monitoringFixture(t),{rule}=await f.publish(f.completeness()),d=await f.monitorDefinition(rule);d.authorizationExpiresAt=d.schedule.startsAt;
 const {monitor}=await f.publishMonitor(rule,d);await f.waitUntil(d.schedule.startsAt);assert.equal((await f.tick(monitor.id)).state,'blocked');
 const [o]=await f.occurrences(monitor.id);assert.equal(o.reason,'AUTHORIZATION_EXPIRED');assert.equal(o.executorId,f.actor);assert.equal(o.runId,null);
 await f.reconcile(monitor.id);assert.equal((await f.monitor(monitor.id)).blocked,'AUTHORIZATION_EXPIRED');
});

test('canonical FAIL projection opens one owned SLA issue and replay never duplicates its journals',options,async t=>{
 const {f,monitor,issue,occurrence}=await failed(t);
 assert.equal(issue.status,'open');assert.equal(issue.assignedOwnerId,f.reviewer);assert.equal(issue.severity,'warning');assert.equal(issue.ownerAvailable,true);assert.equal(issue.opening.runId,occurrence.runId);
 assert.equal(Date.parse(issue.acknowledgeDueAt)-Date.parse(issue.openedAt),60000);assert.equal(Date.parse(issue.resolveDueAt)-Date.parse(issue.openedAt),600000);
 const before=await f.state();assert.equal((await f.reconcile(monitor.id)).state,'idle');assert.deepEqual(await f.state(),before);
 const history=await events(f,issue.id);assert.deepEqual(history.items.map(e=>[e.kind,e.actorId,e.resolution]),[['opened','site:local',null]]);
});

test('repeated same-scope FAIL reuses the issue and acknowledgement assignment preserve opening SLA',options,async t=>{
 const {f,monitor,issue}=await failed(t),o=await recovery(f,issue);await f.complete(o.runId);await f.reconcile(monitor.id);
 const [again]=await f.issues(monitor.id);assert.equal(again.id,issue.id);assert.equal(again.version,2);assert.equal(again.episode,1);assert.equal(again.openedAt,issue.openedAt);assert.equal(again.resolveDueAt,issue.resolveDueAt);assert.equal(again.lastFailure.runId,o.runId);
 const acknowledged=await f.command<{issue:QualityIssueView}>('quality.issue.acknowledge',{issueId:issue.id,expectedVersion:2,reason:'Investigating the current failure.'});assert.equal(acknowledged.issue.status,'acknowledged');
 const assigned=await f.command<{issue:QualityIssueView}>('quality.issue.assign',{issueId:issue.id,expectedVersion:3,reason:'Assign authorized owner.',ownerId:f.reader});assert.equal(assigned.issue.assignedOwnerId,f.reader);assert.equal(assigned.issue.resolveDueAt,issue.resolveDueAt);
 assert.deepEqual((await events(f,issue.id)).items.map(e=>e.kind),['opened','failed-again','acknowledged','assigned']);
});

test('linked later PASS permits explicit resolution and reopening preserves the immutable resolution evidence',options,async t=>{
 const {f,rule,monitor,issue}=await failed(t),o=await recovery(f,issue);await f.complete(o.runId,20,0);await f.reconcile(monitor.id);
 const ready=await f.issue(issue.id);assert.ok(ready.recovery);assert.equal(ready.recovery.runId,o.runId);
 const body={issueId:issue.id,expectedVersion:ready.version,recoveryOccurrenceId:o.id,recoveryRunId:o.runId,recoveryRunVersion:ready.recovery.runVersion,rootCause:'Required metadata was absent.',remediation:'Restored the required source value.',reason:'Reviewed the later same-scope observation.'};
 const resolved=await f.command<{issue:QualityIssueView}>('quality.issue.resolve',body);assert.equal(resolved.issue.status,'resolved');assert.equal(resolved.issue.resolution?.evidence.runId,o.runId);
 const next=await freshDefinition(f,rule,await f.monitor(monitor.id)),again=await scheduled(f,next);await f.complete(again.runId);for(let n=0;n<3;n++)await f.reconcile(monitor.id);
 const reopened=await f.issue(issue.id);assert.equal(reopened.status,'open');assert.equal(reopened.episode,2);assert.equal(reopened.resolution,null);assert.equal(reopened.opening.runId,again.runId);
 const history=(await events(f,issue.id)).items,retained=history.find(e=>e.kind==='resolved');assert.ok(retained?.resolution);assert.equal(retained.resolution.rootCause,body.rootCause);assert.equal(retained.resolution.remediation,body.remediation);assert.equal(retained.resolution.evidence.runId,o.runId);assert.equal(history.at(-1)?.kind,'reopened');
});

test('manual PASS runs never become linked recovery and fabricated evidence cannot resolve an issue',options,async t=>{
 const {f,rule,monitor,issue}=await failed(t),manual=await f.request(rule);await f.complete(manual.run.id,20,0);assert.equal((await f.reconcile(monitor.id)).state,'idle');assert.equal((await f.issue(issue.id)).recovery,null);
 await f.unchanged(()=>f.command('quality.issue.resolve',{issueId:issue.id,expectedVersion:issue.version,reason:'Unlinked measurement.',rootCause:'Cause',remediation:'Fix',recoveryOccurrenceId:randomUUID(),recoveryRunId:manual.run.id,recoveryRunVersion:3}),exactError('40001','RECOVERY_UNAVAILABLE'));
});

test('a late PASS with a newer pending occurrence never emits recovery available',options,async t=>{
 const {f,monitor,issue}=await failed(t),pass=await recovery(f,issue);await f.complete(pass.runId,20,0);
 const pending=await recovery(f,issue);await f.reconcile(monitor.id);assert.equal((await f.issue(issue.id)).recovery,null);
 assert.equal((await events(f,issue.id)).items.some(e=>e.kind==='recovery-available'),false);
 assert.deepEqual((await f.monitor(monitor.id)).currentObservation,{state:'pending',occurrenceId:pending.id,runId:pending.runId});
});

test('a newer NO_DATA or failed occurrence keeps recovery unavailable and projects unknown honestly',options,async t=>{
 const {f,monitor,issue}=await failed(t),pass=await recovery(f,issue);await f.complete(pass.runId,20,0);
 const unknown=await recovery(f,issue);await f.complete(unknown.runId,0,0);await f.reconcile(monitor.id);await f.reconcile(monitor.id);
 assert.equal((await f.issue(issue.id)).recovery,null);assert.deepEqual((await f.monitor(monitor.id)).currentObservation,{state:'unknown',reason:'NO_DATA',occurrenceId:unknown.id});
 assert.equal((await events(f,issue.id)).items.some(e=>e.kind==='recovery-available'),false);
 const failedRun=await recovery(f,await f.issue(issue.id));await finishError(f,failedRun.runId);await f.reconcile(monitor.id);
 assert.deepEqual((await f.monitor(monitor.id)).currentObservation,{state:'unknown',reason:'EXECUTION_FAILED',occurrenceId:failedRun.id});assert.equal((await f.issue(issue.id)).status,'open');
});

test('changed current rule or source configuration cannot make a retained PASS eligible for resolution',options,async t=>{
 const {f,rule,monitor,issue}=await failed(t),pass=await recovery(f,issue);await f.complete(pass.runId,20,0);
 const nextRule=(await f.publish({...f.completeness(),name:'New rule intent'},rule.id,1)).rule;await f.reconcile(monitor.id);
 assert.equal((await f.issue(issue.id)).recovery,null);assert.equal((await events(f,issue.id)).items.some(e=>e.kind==='recovery-available'),false);
 const next=await freshDefinition(f,nextRule,await f.monitor(monitor.id)),o=await scheduled(f,next);await f.complete(o.runId);await f.reconcile(monitor.id);
 const current=(await f.issues(monitor.id)).find(i=>i.rule.version===2)!;assert.ok(current);const later=await recovery(f,current);await f.complete(later.runId,20,0);
 await f.ownerTx(()=>f.owner.query("UPDATE sources SET host='changed.synthetic.invalid',version=version+1 WHERE tenant_id=$1 AND id=$2",[f.tenant,f.sourceId]));await f.reconcile(monitor.id);
 assert.equal((await f.issue(current.id)).recovery,null);assert.equal((await events(f,current.id)).items.some(e=>e.kind==='recovery-available'),false);
});

test('read-only consumers see authorized monitoring but cannot publish or change issue state',options,async t=>{
 const {f,monitor,issue}=await failed(t);
 assert.equal((await f.as(tx=>getQualityMonitor(tx,f.principal(f.reader),monitor.id),f.reader)).id,monitor.id);
 assert.equal((await f.as(tx=>getQualityIssue(tx,f.principal(f.reader),issue.id),f.reader)).id,issue.id);
 await f.unchanged(()=>f.as(tx=>publishQualityMonitor(tx,f.principal(f.reader),{id:randomUUID(),expectedRevision:0,definition:monitor.definition},randomUUID(),'native'),f.reader),problem(403,'MONITOR_FORBIDDEN'));
 await f.unchanged(()=>f.as(tx=>commandQualityIssue(tx,f.principal(f.reader),issue.id,'acknowledge',{expectedVersion:1,reason:'Read-only attempt.'},randomUUID(),'native'),f.reader),problem(403,'MONITOR_FORBIDDEN'));
 assert.deepEqual((await f.as(tx=>listQualityMonitors(tx,f.principal(f.outsider,f.foreign)),f.outsider,f.foreign)).items,[]);
 await assert.rejects(()=>f.as(tx=>getQualityIssue(tx,f.principal(f.outsider,f.foreign),issue.id),f.outsider,f.foreign),problem(404,'MONITOR_UNAVAILABLE'));
});

test('resume reauthorizes every retained recipient and exact command replay respects current visibility',options,async t=>{
 const {f,monitor}=await setup(t),key=randomUUID(),body={monitorId:monitor.id,expectedRevision:1,action:'pause',reason:'Pause before recipient change.'};await f.command('quality.monitor.state',body,key);
 await f.revoke(f.reviewer,['catalog:read']);await f.unchanged(()=>f.command('quality.monitor.state',{monitorId:monitor.id,expectedRevision:2,action:'resume',reason:'Resume denied recipient.'}),exactError('42501','MONITOR_FORBIDDEN'));
 await f.revoke(f.actor,['catalog:read']);await f.unchanged(()=>f.command('quality.monitor.state',body,key),code('42501'));
});

test('revoking the issue owner does not discard a completed observation or falsely deliver a notification',options,async t=>{
 const {f,monitor}=await setup(t),o=await scheduled(f,monitor),c=await f.claim(o.runId);claimed(c);const value=await f.measurement(c);await deactivate(f,f.reviewer);
 assert.equal((await f.finish(o.runId,c,value)).run.verdict,'FAIL');await f.reconcile(monitor.id);const [i]=await f.issues(monitor.id);assert.equal(i.ownerAvailable,false);assert.equal(i.status,'open');
 const rows=await f.ownerTx(()=>f.owner.query('SELECT suppressed FROM quality_monitor_notifications WHERE tenant_id=$1 AND issue_id=$2',[f.tenant,i.id]));assert.deepEqual(rows.rows.map(r=>r.suppressed),['RECIPIENT_UNAVAILABLE']);
 await assert.rejects(()=>f.as(tx=>listQualityNotifications(tx,f.principal(f.reviewer)),f.reviewer),problem(403,'MONITOR_FORBIDDEN'));
});

test('scheduled completeness rechecks rule owner at claim and finish without changing legacy manual runs',options,async t=>{
 const {f,rule,monitor}=await setup(t),o=await scheduled(f,monitor),manual=await f.request(rule);await deactivate(f,f.ruleOwner);
 const denied=await f.claim(o.runId);assert.equal(denied.status,'terminal');if(denied.status==='terminal'){assert.equal(denied.run.status,'cancelled');assert.equal(denied.run.errorCode,'QUALITY_AUTHORITY_REVOKED');}
 const legacy=await f.complete(manual.run.id);assert.equal(legacy.run.verdict,'FAIL');await f.reconcile(monitor.id);assert.deepEqual(await f.issues(monitor.id),[]);
 await f.ownerTx(()=>f.owner.query('UPDATE memberships SET active=true WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.ruleOwner]));
 const next=await freshDefinition(f,rule,await f.monitor(monitor.id)),running=await scheduled(f,next),c=await f.claim(running.runId);claimed(c);const value=await f.measurement(c);await deactivate(f,f.ruleOwner);
 const result=await f.finish(running.runId,c,value);assert.equal(result.run.status,'cancelled');assert.equal(result.run.errorCode,'QUALITY_AUTHORITY_REVOKED');
 await f.unchanged(()=>f.claim(running.runId),exactError('42501','QUALITY_AUTHORITY_REVOKED'));
});

test('executor and target authorization are rechecked between admission and execution',options,async t=>{
 const {f,monitor}=await setup(t),o=await scheduled(f,monitor);await f.revoke(f.actor,['catalog:read','quality:read']);const result=await f.claim(o.runId);assert.equal(result.status,'terminal');if(result.status==='terminal')assert.equal(result.run.errorCode,'QUALITY_AUTHORITY_REVOKED');
 await f.reconcile(monitor.id);assert.deepEqual(await f.issues(monitor.id),[]);
 await f.revoke(f.actor,permissions);const next=await freshDefinition(f,(await f.publish({...f.completeness(),name:'Repinned current authority'},monitor.definition.rule.id,1)).rule,await f.monitor(monitor.id)),later=await scheduled(f,next);
 await f.ownerTx(()=>f.owner.query("UPDATE assets SET visibility='restricted',allowed_identities=$3::jsonb WHERE tenant_id=$1 AND id=$2",[f.tenant,f.schemaId,JSON.stringify([f.reviewer])]));
 const hidden=await f.claim(later.runId);assert.equal(hidden.status,'terminal');if(hidden.status==='terminal')assert.equal(hidden.run.errorCode,'QUALITY_AUTHORITY_REVOKED');
});

test('recovery requests require the immutable executor but do not require quality write permission',options,async t=>{
 const {f,issue}=await failed(t);await f.revoke(f.actor,['catalog:read','quality:read','quality:execute']);
 const value=await f.as(tx=>commandQualityIssue(tx,f.principal(),issue.id,'recovery.request',{id:randomUUID(),expectedVersion:issue.version,reason:'Executor requested a current recheck.'},randomUUID(),'native'));enqueued(value.occurrence);
 await f.unchanged(()=>f.command('quality.issue.recovery.request',{issueId:issue.id,id:randomUUID(),expectedVersion:issue.version,reason:'Different executor.'},randomUUID(),f.reviewer),exactError('40001','RECOVERY_UNAVAILABLE'));
});

test('notification ownership, exact read replay and current issue visibility are enforced independently',options,async t=>{
 const {f,issue}=await failed(t),page=await f.as(tx=>listQualityNotifications(tx,f.principal(f.reviewer)),f.reviewer);assert.equal(page.items.length,1);const n=page.items[0];assert.equal(n.issueId,issue.id);
 assert.deepEqual((await f.as(tx=>listQualityNotifications(tx,f.principal()))).items,[]);
 await f.unchanged(()=>f.command('quality.notification.mark-read',{notificationId:n.id,expectedVersion:1}),exactError('P0002','MONITOR_UNAVAILABLE'));
 const key=randomUUID(),first=await f.as(tx=>markQualityNotificationRead(tx,f.principal(f.reviewer),n.id,{expectedVersion:1},key,'native'),f.reviewer);assert.ok(first.notification.readAt);
 const before=await f.state();assert.deepEqual(await f.as(tx=>markQualityNotificationRead(tx,f.principal(f.reviewer),n.id,{expectedVersion:1},key,'native'),f.reviewer),first);assert.deepEqual(await f.state(),before);
 await f.revoke(f.reviewer,['catalog:read']);await f.unchanged(()=>f.command('quality.notification.mark-read',{notificationId:n.id,expectedVersion:1},key,f.reviewer),code('42501'));
});

test('selected historical definitions and issues remain visible when a newer reference-restricted head is hidden',options,async t=>{
 const {f,rule,monitor,issue}=await failed(t),ref=await f.publishReference(f.proposal({audience:{visibility:'restricted',allowedIdentityIds:[f.actor,f.reviewer,f.ruleOwner].sort()}}));
 const newRule=(await f.publish(f.definition(ref.proposal.setId),rule.id,1)).rule;await freshDefinition(f,newRule,await f.monitor(monitor.id));
 await assert.rejects(()=>f.as(tx=>getQualityMonitor(tx,f.principal(f.reader),monitor.id),f.reader),problem(404,'MONITOR_UNAVAILABLE'));
 const definitions=await f.as(tx=>listMonitorDefinitions(tx,f.principal(f.reader),monitor.id,{limit:1}),f.reader);assert.deepEqual(definitions.items.map(d=>d.definitionVersion),[1]);assert.equal(definitions.nextCursor,null);
 assert.equal((await f.as(tx=>getMonitorDefinition(tx,f.principal(f.reader),monitor.id,1),f.reader)).definitionHash,monitor.definitionHash);
 assert.equal((await f.as(tx=>getQualityIssue(tx,f.principal(f.reader),issue.id),f.reader)).id,issue.id);assert.equal((await events(f,issue.id,f.reader)).items.length,1);
 const audits=await f.as(tx=>sql<{version:number}>`select (changes->>'definitionVersion')::integer as version from public.audit where tenant_id=${f.tenant}::uuid and action='quality.monitor_published' and resource_id=${monitor.id} and public.gc_quality_monitoring_audit_visible(action,resource_id,changes,${f.reader}::uuid) order by version`.execute(tx),f.reader);assert.deepEqual(audits.rows.map(r=>r.version),[1]);
});

test('superseded issue visibility includes the exact replacement definition and closes after endpoint permission loss',options,async t=>{
 const {f,monitor,issue}=await failed(t),ref=await f.publishReference(),newRule=(await f.publish(f.definition(ref.proposal.setId))).rule,replacement=(await f.publishMonitor(newRule)).monitor;
 const result=await f.command<{issue:QualityIssueView}>('quality.issue.supersede',{issueId:issue.id,expectedVersion:issue.version,reason:'Use the governed code-list check.',replacementMonitorId:replacement.id,replacementDefinitionVersion:1});assert.equal(result.issue.status,'superseded');
 assert.equal((await f.as(tx=>getQualityIssue(tx,f.principal(f.reader),issue.id),f.reader)).superseded?.replacementMonitorId,replacement.id);
 await f.revoke(f.reader,['catalog:read','quality:read','audit:read']);
 assert.equal((await f.as(tx=>getQualityMonitor(tx,f.principal(f.reader),monitor.id),f.reader)).id,monitor.id);
 await assert.rejects(()=>f.as(tx=>getQualityIssue(tx,f.principal(f.reader),issue.id),f.reader),problem(404,'MONITOR_UNAVAILABLE'));
 assert.deepEqual((await f.as(tx=>listQualityIssues(tx,f.principal(f.reader)),f.reader)).items,[]);
});

test('signed monitoring cursors bind tenant actor limit and filters while every page rechecks authority',options,async t=>{
 const {f,rule,monitor}=await setup(t);await freshDefinition(f,rule,monitor);
 const page=await f.as(tx=>listMonitorDefinitions(tx,f.principal(),monitor.id,{limit:1}));assert.ok(page.nextCursor);const cursor=page.nextCursor;
 assert.deepEqual((await f.as(tx=>listMonitorDefinitions(tx,f.principal(),monitor.id,{limit:1,cursor}))).items.map(d=>d.definitionVersion),[2]);
 await assert.rejects(()=>f.as(tx=>listMonitorDefinitions(tx,f.principal(f.reader),monitor.id,{limit:1,cursor}),f.reader),problem(400,'PAGE_INVALID'));
 await assert.rejects(()=>f.as(tx=>listMonitorDefinitions(tx,f.principal(),monitor.id,{limit:2,cursor})),problem(400,'PAGE_INVALID'));
 await f.revoke(f.actor,['catalog:read']);await assert.rejects(()=>f.as(tx=>listMonitorDefinitions(tx,f.principal(),monitor.id,{limit:1,cursor})),problem(403,'MONITOR_FORBIDDEN'));
});

test('forced tenant RLS direct DML and private helper grants prevent bypassing protected monitoring commands',options,async t=>{
 const {f,monitor}=await setup(t);
 const catalog=await f.owner.query('SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class WHERE relname=ANY($1::text[]) ORDER BY relname',[monitoringTables]);assert.equal(catalog.rows.length,monitoringTables.length);assert.ok(catalog.rows.every(r=>r.relrowsecurity&&r.relforcerowsecurity));
 for(const table of monitoringTables){const rows=await f.as(tx=>sql`select * from ${sql.table('public.'+table)} where tenant_id=${f.tenant}::uuid`.execute(tx),f.outsider,f.foreign);assert.deepEqual(rows.rows,[]);const grants=await f.owner.query("SELECT has_table_privilege('gc_app',$1,'INSERT,UPDATE,DELETE') AS allowed",['public.'+table]);assert.equal(grants.rows[0].allowed,false);}
 await f.unchanged(()=>f.as(tx=>sql`update public.quality_monitors set revision=revision where id=${monitor.id}::uuid`.execute(tx)),code('42501'));
 await f.unchanged(()=>f.as(tx=>sql`select public.gc_quality_monitor_definition_valid(${JSON.stringify(monitor.definition)}::jsonb)`.execute(tx)),code('42501'));
 await f.unchanged(()=>f.as(tx=>sql`select public.gc_quality_monitor_tick(${monitor.id}::uuid)`.execute(tx)),exactError('42501','MONITOR_FORBIDDEN'));
 await assert.rejects(()=>f.as(tx=>pendingMonitoringWork(tx,f.tenant)),exactError('42501','MONITOR_FORBIDDEN'));
});

test('observed rule-owner lock blocking rechecks current authority before stale pin diagnostics without source prelocks',options,async t=>{
 const f=await monitoringFixture(t),{rule}=await f.publish(f.completeness()),definition=await f.monitorDefinition(rule);definition.rule.definitionHash='0'.repeat(64);const id=randomUUID(),before=await f.state(),blocker=await f.connection();
 await blocker.query('BEGIN');await blocker.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[f.tenant,f.actor]);await blocker.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.ruleOwner]);
 const blockerPid=Number((await blocker.query('SELECT pg_backend_pid() AS pid')).rows[0].pid);let sendPid!:(n:number)=>void;const pidPromise=new Promise<number>(resolve=>{sendPid=resolve;});
 const result=f.as(async tx=>{const pid=(await sql<{pid:number}>`select pg_backend_pid() as pid`.execute(tx)).rows[0].pid;sendPid(pid);return (await sql`select public.gc_quality_monitor_command('quality.monitor.publish',${randomUUID()},${JSON.stringify({id,expectedRevision:0,definition})}::jsonb,'native-race')`.execute(tx));}).then(value=>({ok:true as const,value}),error=>({ok:false as const,error}));
 try{const pid=await Promise.race([pidPromise,result.then(()=>{throw Error('Protected command ended before its connection was observed');})]),deadline=performance.now()+1500;let observed=false;
  while(performance.now()<deadline){const wait=await blocker.query('SELECT pg_blocking_pids($1) AS blockers,ARRAY(SELECT locktype FROM pg_locks WHERE pid=$1 AND NOT granted) AS waits',[pid]);if(wait.rows[0].blockers.includes(blockerPid)&&wait.rows[0].waits.length>0){observed=true;break;}}
  assert.equal(observed,true,'The real protected command must be observed blocked by this exact connection');
  // Every identity is held before any membership or target/resource lock.
  await assert.rejects(()=>f.ownerTx(()=>f.owner.query('SELECT id FROM identities WHERE id=$1 FOR UPDATE NOWAIT',[f.actor])),code('55P03'));
  await f.ownerTx(()=>f.owner.query('SELECT id FROM sources WHERE tenant_id=$1 AND id=$2 FOR UPDATE NOWAIT',[f.tenant,f.sourceId]));
  await blocker.query('COMMIT');const outcome=await result;assert.equal(outcome.ok,false);if(!outcome.ok)assert.ok(exactError('42501','MONITOR_FORBIDDEN')(outcome.error));
  assert.deepEqual(await f.state(),before,'Revocation wins and no protected publication or journal is retained');
 }finally{await blocker.query('ROLLBACK');await result;}
});

test('scheduled reference checks retain exact reviewed binding and comparison scope without exposing codes in monitoring DTOs',options,async t=>{
 const f=await monitoringFixture(t),ref=await f.publishReference(),{rule}=await f.publish(f.definition(ref.proposal.setId)),{monitor}=await f.publishMonitor(rule),o=await scheduled(f,monitor),c=await f.claim(o.runId);claimed(c);assert.equal(c.execution.kind,'reference-allowed-values');if(c.execution.kind!=='reference-allowed-values')assert.fail('Expected reference execution');
 const binding=c.execution.reference;assert.deepEqual(binding.codes,['01','A']);assert.equal(binding.setId,ref.proposal.setId);
 const counts=(await f.owner.query(`SELECT count(*)::integer AS "rowCount",count(*) FILTER(WHERE code IS NULL)::integer AS "nullCount",count(*) FILTER(WHERE code IS NOT NULL AND code<>ALL($1::text[]))::integer AS "invalidCount" FROM "${f.namespace}".observations`,[binding.codes])).rows[0];assert.deepEqual(counts,{rowCount:20,nullCount:4,invalidCount:4});
 const at=await f.now(),value={formatVersion:1 as const,kind:'reference-allowed-values' as const,strategy:'exact-bounded-role-scope' as const,...counts,referenceBindingHash:binding.bindingHash,observedStartedAt:at,observedFinishedAt:at,elapsedMs:0,sourceVersion:'170006',adapterVersion:'1' as const,queryTemplate:'postgresql-reference-allowed-values-v1' as const,estimatedCost:1,estimatedBytes:160};
 assert.equal((await f.finish(o.runId,c,value)).run.verdict,'FAIL');await f.reconcile(monitor.id);
 const scope=await f.ownerTx(async()=>(await f.owner.query('SELECT comparison_scope FROM quality_monitor_occurrences WHERE tenant_id=$1 AND id=$2',[f.tenant,o.id])).rows[0].comparison_scope);
 assert.deepEqual(scope.family,{kind:'reference-allowed-values',setId:binding.setId,version:binding.version,publicationHash:binding.publicationHash,codeStatus:'active',codesHash:hash(binding.codes)});assert.equal(Object.hasOwn(scope.family,'asOf'),false);
 const publicPage=await f.as(tx=>listMonitorOccurrences(tx,f.principal(),monitor.id));assert.equal(Object.hasOwn(publicPage.items[0],'codes'),false);assert.equal(Object.hasOwn(publicPage.items[0],'comparisonScope'),false);assert.equal((await f.issues(monitor.id)).length,1);
});

test('scheduled uniqueness binds its byte budgets and projects an independently aggregated duplicate-group result',options,async t=>{
 const f=await monitoringFixture(t),{rule}=await f.publish({formatVersion:1,kind:'uniqueness',target:{tableAssetId:f.tableId,columnAssetId:f.columnId},name:'Monitored exact duplicate groups',purpose:'Retain scheduled bounded duplicate evidence.',ownerId:f.ruleOwner,severity:'critical',maximumDuplicateBasisPoints:0,comparison:'utf8-exact',nullPolicy:'exclude'}),{monitor}=await f.publishMonitor(rule),o=await scheduled(f,monitor),c=await f.claim(o.runId);claimed(c);assert.equal(c.execution.kind,'uniqueness');if(c.execution.kind!=='uniqueness')assert.fail('Expected uniqueness execution');
 assert.equal(c.execution.budget.maximumValueBytes,4096);assert.equal(c.execution.budget.maximumTotalValueBytes,67108864);
 const counts=(await f.owner.query(`WITH g AS(SELECT convert_to(code,'UTF8') AS k,count(*)::integer AS n FROM "${f.namespace}".observations WHERE code IS NOT NULL GROUP BY convert_to(code,'UTF8')) SELECT (SELECT count(*)::integer FROM "${f.namespace}".observations) AS "rowCount",(SELECT count(*)::integer FROM "${f.namespace}".observations WHERE code IS NULL) AS "nullCount",count(*)::integer AS "distinctCount",count(*) FILTER(WHERE n>1)::integer AS "duplicateGroupCount",coalesce(sum(n) FILTER(WHERE n>1),0)::integer AS "duplicateRowCount",sum(octet_length(k)*n)::integer AS "totalValueBytes",max(octet_length(k))::integer AS "largestValueBytes" FROM g`)).rows[0];
 assert.deepEqual(counts,{rowCount:20,nullCount:4,distinctCount:6,duplicateGroupCount:2,duplicateRowCount:12,totalValueBytes:58,largestValueBytes:10});
 const at=await f.now();assert.equal((await f.finish(o.runId,c,{formatVersion:1,kind:'uniqueness',strategy:'exact-bounded-role-scope',...counts,observedStartedAt:at,observedFinishedAt:at,elapsedMs:0,sourceVersion:'170006',adapterVersion:'1',queryTemplate:'postgresql-uniqueness-v1',estimatedCost:1,estimatedBytes:160})).run.verdict,'FAIL');await f.reconcile(monitor.id);
 const [issue]=await f.issues(monitor.id);assert.equal(issue.severity,'critical');assert.equal(issue.rule.id,rule.id);assert.equal(issue.lastFailure.runId,o.runId);
});

test('scheduled range binds exact integer bounds to a real bigint target before aggregate projection',options,async t=>{
 const f=await monitoringFixture(t);await f.ownerTx(async()=>{
  await f.owner.query(`TRUNCATE "${f.namespace}".observations`);await f.owner.query(`ALTER TABLE "${f.namespace}".observations ALTER code TYPE bigint USING code::bigint`);
  await f.owner.query(`INSERT INTO "${f.namespace}".observations VALUES(-1),(0),(5),(10),(11),(NULL)`);
  const row=(await f.owner.query("UPDATE assets SET metadata=jsonb_set(metadata,'{dataType}','\"bigint\"'::jsonb),version=version+1 WHERE tenant_id=$1 AND id=$2 RETURNING *",[f.tenant,f.columnId])).rows[0];
  await f.owner.query('INSERT INTO asset_revisions(tenant_id,asset_id,version,snapshot) VALUES($1,$2,$3,$4::jsonb)',[f.tenant,f.columnId,row.version,JSON.stringify(assetView(row))]);
 });
 const {rule}=await f.publish({formatVersion:1,kind:'range',target:{tableAssetId:f.tableId,columnAssetId:f.columnId},name:'Monitored integer range',purpose:'Retain exact bounded scheduled integer evidence.',ownerId:f.ruleOwner,severity:'warning',maximumOutOfRangeBasisPoints:3999,minimum:'0',maximum:'10',comparison:'int64-inclusive',nullPolicy:'exclude'}),{monitor}=await f.publishMonitor(rule),o=await scheduled(f,monitor),c=await f.claim(o.runId);claimed(c);assert.equal(c.execution.kind,'range');if(c.execution.kind!=='range')assert.fail('Expected range execution');
 assert.equal(c.execution.target.dataType,'bigint');assert.deepEqual(c.execution.range,{minimum:'0',maximum:'10',comparison:'int64-inclusive',nullPolicy:'exclude',rangeHash:'d9d1c5de1d8da97b52234be367e92343b365e59e7f3bde85748db969b857d161'});
 const counts=(await f.owner.query(`SELECT count(*)::integer AS "rowCount",count(*) FILTER(WHERE code IS NULL)::integer AS "nullCount",count(*) FILTER(WHERE code<$1::bigint)::integer AS "belowCount",count(*) FILTER(WHERE code>$2::bigint)::integer AS "aboveCount" FROM "${f.namespace}".observations`,['0','10'])).rows[0];assert.deepEqual(counts,{rowCount:6,nullCount:1,belowCount:1,aboveCount:1});
 const at=await f.now();assert.equal((await f.finish(o.runId,c,{formatVersion:1,kind:'range',strategy:'exact-bounded-role-scope',...counts,rangeHash:c.execution.range.rangeHash,observedStartedAt:at,observedFinishedAt:at,elapsedMs:0,sourceVersion:'170006',adapterVersion:'1',queryTemplate:'postgresql-range-v1',estimatedCost:1,estimatedBytes:160})).run.verdict,'FAIL');await f.reconcile(monitor.id);assert.equal((await f.issues(monitor.id))[0].lastFailure.runId,o.runId);
});
