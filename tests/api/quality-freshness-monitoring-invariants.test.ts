// SPDX-License-Identifier: Apache-2.0
/** Real disposable SQL hostile storage controls, never source-worker or Temporal evidence. */
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import test from 'node:test';
import {freshnessMonitoringFixture as monitoringFixture,exactError} from '../fixtures/quality-freshness-monitoring.ts';
async function queued(t:Parameters<typeof monitoringFixture>[0]){
 const f=await monitoringFixture(t),{rule}=await f.publish(f.definition(30)),{monitor}=await f.publishMonitor(rule);
 await f.waitUntil(monitor.definition.schedule.startsAt);const work=await f.tick(monitor.id);assert.equal(work.state,'advanced');assert.ok(work.runId);return {f,rule,monitor,work};
}
const stateCode=(e:unknown)=>e&&typeof e==='object'&&'code'in e&&typeof e.code==='string'&&/^[0-9A-Z]{5}$/.test(e.code)?e.code:'NO_SQLSTATE';
test('scheduled freshness post-flush projection journal mismatch refuses the entire site projection and restores guards',async t=>{
 const {f,monitor,work}=await queued(t);await f.complete(work.runId!,f.definition(30));const before=await f.state();
 const guards=async()=>(await f.owner.query("SELECT tgname,tgenabled FROM pg_trigger WHERE tgrelid='public.audit'::regclass AND NOT tgisinternal ORDER BY tgname")).rows;
 const guardBefore=await guards();let stage='initial-flush',flushed=false,projected=false,restored=false;
 await assert.rejects(()=>f.ownerTx(async()=>{
  await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');flushed=true;await f.owner.query('SET CONSTRAINTS ALL DEFERRED');
  stage='projection';const projectedWork=(await f.owner.query('SELECT public.gc_quality_monitor_reconcile($1::uuid) value',[monitor.id])).rows[0].value;assert.equal(projectedWork.state,'advanced');assert.equal(projectedWork.runId,work.runId);projected=true;
  const audit=(await f.owner.query("SELECT id,changes FROM audit WHERE tenant_id=$1 AND action='quality.monitor_projected' AND resource_id=$2",[f.tenant,monitor.id])).rows;assert.equal(audit.length,1);assert.equal(audit[0].changes.runId,work.runId);
  const outbox=(await f.owner.query('SELECT * FROM outbox WHERE tenant_id=$1 AND id=$2',[f.tenant,audit[0].id])).rows;assert.equal(outbox.length,1);assert.equal(outbox[0].payload.actorId,'site:local');
  // Clear only the valid journal checks. Projection/head/incident seals remain
  // deferred and must detect the subsequent non-key journal mismatch.
  stage='valid-journal-flush';await f.owner.query('SET CONSTRAINTS quality_monitor_journal_insert_seal,quality_monitor_journal_update_seal,quality_monitor_journal_delete_seal IMMEDIATE');
  await f.owner.query('SET CONSTRAINTS quality_monitor_journal_insert_seal,quality_monitor_journal_update_seal,quality_monitor_journal_delete_seal DEFERRED');
  stage='owner-nonkey-journal-attack';await f.owner.query('ALTER TABLE audit DISABLE TRIGGER USER');
  assert.equal((await f.owner.query("UPDATE audit SET changes=jsonb_set(changes,'{runId}',to_jsonb($3::uuid)) WHERE tenant_id=$1 AND id=$2",[f.tenant,audit[0].id,randomUUID()])).rowCount,1);
  assert.deepEqual((await f.owner.query('SELECT * FROM outbox WHERE tenant_id=$1 AND id=$2',[f.tenant,audit[0].id])).rows,outbox);
  stage='restore';await f.owner.query('ALTER TABLE audit ENABLE TRIGGER USER');assert.deepEqual(await guards(),guardBefore);restored=true;
  stage='final-seal';await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');
 },f.tenant,'site:local'),error=>{assert.equal(stage,'final-seal','Failure before intended seal: '+stage+' '+stateCode(error));return exactError('23514','MONITOR_STORAGE_INVALID')(error);});
 assert.ok(flushed&&projected&&restored);assert.deepEqual(await guards(),guardBefore);assert.deepEqual(await f.state(),before);
});
test('scheduled freshness deferred occurrence seal rejects a poisoned comparison scope after real protected admission',async t=>{
 const f=await monitoringFixture(t),{rule}=await f.publish(f.definition(30)),{monitor}=await f.publishMonitor(rule);await f.waitUntil(monitor.definition.schedule.startsAt);const before=await f.state();let stage='owner-guard-attack',admitted=false,poisoned=false;
 const guards=async()=>(await f.owner.query("SELECT tgname,tgenabled FROM pg_trigger WHERE tgrelid='public.quality_monitor_occurrences'::regclass AND NOT tgisinternal ORDER BY tgname")).rows,guardBefore=await guards();
 await assert.rejects(()=>f.ownerTx(async()=>{
  // Explicit owner-only attack before any pending RI events. The deferred seal
  // stays enabled; transaction rollback must restore both disabled guards.
  await f.owner.query('ALTER TABLE quality_monitor_occurrences DISABLE TRIGGER quality_monitor_guard');await f.owner.query('ALTER TABLE quality_monitor_occurrences DISABLE TRIGGER monitor_immutable');
  stage='tick';
  const work=(await f.owner.query('SELECT public.gc_quality_monitor_tick($1::uuid) value',[monitor.id])).rows[0].value;assert.equal(work.state,'advanced');assert.ok(work.runId);admitted=true;
  stage='owner-scope-attack';
  assert.equal((await f.owner.query("UPDATE quality_monitor_occurrences SET comparison_scope=jsonb_set(comparison_scope,'{sourceConfigHash}',to_jsonb($3::text)) WHERE tenant_id=$1 AND id=$2",[f.tenant,work.occurrenceId,'0'.repeat(64)])).rowCount,1);
  poisoned=true;assert.equal((await guards()).find(g=>g.tgname==='quality_monitor_occurrence_seal')?.tgenabled,'O');
  stage='final-seal';await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');
 },f.tenant,'site:local'),error=>{assert.equal(stage,'final-seal','Failure before intended seal: '+stage+' '+stateCode(error));return exactError('23514','MONITOR_STORAGE_INVALID')(error);});
 assert.ok(admitted&&poisoned);assert.deepEqual(await guards(),guardBefore);assert.deepEqual(await f.state(),before);
});
test('scheduled freshness head seal rejects forged last-conclusive evidence after a valid committed projection',async t=>{
 const {f,monitor,work}=await queued(t);await f.complete(work.runId!,f.definition(30));await f.reconcile(monitor.id);const view=await f.monitor(monitor.id);assert.equal(view.lastConclusive?.verdict,'FAIL');const before=await f.state();let stage='forged-head';
 await assert.rejects(()=>f.ownerTx(async()=>{
  assert.equal((await f.owner.query("UPDATE quality_monitors SET last_conclusive=jsonb_set(last_conclusive,'{evidence,completionHash}',to_jsonb($3::text)) WHERE tenant_id=$1 AND id=$2",[f.tenant,monitor.id,'0'.repeat(64)])).rowCount,1);
  stage='final-seal';await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');
 },f.tenant,'site:local'),error=>{assert.equal(stage,'final-seal','Failure before intended seal: '+stage+' '+stateCode(error));return exactError('23514','MONITOR_STORAGE_INVALID')(error);});
 assert.deepEqual(await f.state(),before);
});
test('scheduled freshness post-flush resolution event requires its exact paired journal',async t=>{
 const f=await monitoringFixture(t),d=f.definition(90),{rule}=await f.publish(d),{monitor}=await f.publishMonitor(rule);await f.waitUntil(monitor.definition.schedule.startsAt);
 const first=await f.tick(monitor.id);assert.ok(first.runId);const c=await f.claim(first.runId!);if(c.status!=='claimed')throw new Error('Actual claim required');
 const bad=await f.measurement(d);bad.latestObservedAt=await f.shift(bad.sourceObservedAt,'-100000000');bad.ageMicroseconds='100000000';await f.finish(first.runId!,c,bad);await f.reconcile(monitor.id);
 const issue=(await f.issues(monitor.id))[0];const requested=await f.command('quality.issue.recovery.request',{issueId:issue.id,expectedVersion:issue.version,id:randomUUID(),reason:'Actual linked recovery'});await f.complete(requested.occurrence.runId,d);await f.reconcile(monitor.id);
 const recovery=await f.issue(issue.id);assert.ok(recovery.recovery);const before=await f.state();let stage='prepare',resolved=false,poisoned=false;
 const guards=async()=>(await f.owner.query("SELECT tgname,tgenabled FROM pg_trigger WHERE tgrelid='audit'::regclass AND NOT tgisinternal ORDER BY tgname")).rows,original=await guards();
 await assert.rejects(()=>f.ownerTx(async()=>{
  stage='resolve';const body={issueId:issue.id,expectedVersion:recovery.version,recoveryOccurrenceId:recovery.recovery!.occurrenceId,recoveryRunId:recovery.recovery!.runId,recoveryRunVersion:recovery.recovery!.runVersion,rootCause:'Synthetic stale timestamp',remediation:'Observed recovery',reason:'Canonical valid recovery'};
  const result=(await f.owner.query("SELECT public.gc_quality_monitor_command('quality.issue.resolve',$1,$2::jsonb,'freshness-monitor-native') value",[randomUUID(),JSON.stringify(body)])).rows[0].value;assert.equal(result.issue.status,'resolved');resolved=true;
  stage='valid-journal-flush';await f.owner.query('SET CONSTRAINTS quality_monitor_journal_insert_seal,quality_monitor_journal_update_seal,quality_monitor_journal_delete_seal IMMEDIATE');await f.owner.query('SET CONSTRAINTS quality_monitor_journal_insert_seal,quality_monitor_journal_update_seal,quality_monitor_journal_delete_seal DEFERRED');
  await f.owner.query('ALTER TABLE audit DISABLE TRIGGER USER');
  stage='journal-attack';assert.equal((await f.owner.query("UPDATE audit SET changes=jsonb_set(changes,'{eventId}',to_jsonb($3::uuid)) WHERE tenant_id=$1 AND resource_id=$2 AND action='quality.issue_resolved'",[f.tenant,issue.id,randomUUID()])).rowCount,1);poisoned=true;
  await f.owner.query('ALTER TABLE audit ENABLE TRIGGER USER');assert.deepEqual(await guards(),original);
  stage='final-seal';await f.owner.query('SET CONSTRAINTS quality_monitor_event_seal IMMEDIATE');
 }),error=>{assert.equal(stage,'final-seal','Failure before intended seal: '+stage+' '+stateCode(error));return exactError('23514','MONITOR_STORAGE_INVALID')(error);});
 assert.ok(resolved&&poisoned);assert.deepEqual(await guards(),original);assert.deepEqual(await f.state(),before);
});
