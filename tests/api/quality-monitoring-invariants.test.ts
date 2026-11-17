// SPDX-License-Identifier: Apache-2.0
/** Real disposable SQL hostile storage controls, never source-worker or Temporal evidence. */
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import test from 'node:test';
import {monitoringFixture,exactError} from '../fixtures/quality-monitoring.ts';
async function queued(t:Parameters<typeof monitoringFixture>[0]){
 const f=await monitoringFixture(t),{rule}=await f.publish(f.completeness()),{monitor}=await f.publishMonitor(rule);
 await f.waitUntil(monitor.definition.schedule.startsAt);const work=await f.tick(monitor.id);assert.equal(work.state,'advanced');assert.ok(work.runId);return {f,rule,monitor,work};
}
const stateCode=(e:unknown)=>e&&typeof e==='object'&&'code'in e&&typeof e.code==='string'&&/^[0-9A-Z]{5}$/.test(e.code)?e.code:'NO_SQLSTATE';
test('monitoring post-flush projection journal mismatch refuses the entire site projection and restores guards',async t=>{
 const {f,monitor,work}=await queued(t);await f.complete(work.runId!,20,4);const before=await f.state();
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
test('monitoring deferred occurrence seal rejects a poisoned comparison scope after real protected admission',async t=>{
 const f=await monitoringFixture(t),{rule}=await f.publish(f.completeness()),{monitor}=await f.publishMonitor(rule);await f.waitUntil(monitor.definition.schedule.startsAt);const before=await f.state();let stage='owner-guard-attack',admitted=false,poisoned=false;
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
test('monitoring head seal rejects forged last-conclusive evidence after a valid committed projection',async t=>{
 const {f,monitor,work}=await queued(t);await f.complete(work.runId!,20,4);await f.reconcile(monitor.id);const view=await f.monitor(monitor.id);assert.equal(view.lastConclusive?.verdict,'FAIL');const before=await f.state();let stage='forged-head';
 await assert.rejects(()=>f.ownerTx(async()=>{
  assert.equal((await f.owner.query("UPDATE quality_monitors SET last_conclusive=jsonb_set(last_conclusive,'{evidence,completionHash}',to_jsonb($3::text)) WHERE tenant_id=$1 AND id=$2",[f.tenant,monitor.id,'0'.repeat(64)])).rowCount,1);
  stage='final-seal';await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');
 },f.tenant,'site:local'),error=>{assert.equal(stage,'final-seal','Failure before intended seal: '+stage+' '+stateCode(error));return exactError('23514','MONITOR_STORAGE_INVALID')(error);});
 assert.deepEqual(await f.state(),before);
});
test('monitoring segment seal refuses silently skipping unrecorded due slots',async t=>{
 const f=await monitoringFixture(t),{rule}=await f.publish(f.completeness()),{monitor}=await f.publishMonitor(rule),before=await f.state();let stage='advance-cursor';
 await assert.rejects(()=>f.ownerTx(async()=>{
  assert.equal((await f.owner.query("UPDATE quality_monitor_schedule_segments SET next_slot_at=next_slot_at+interval '60 seconds' WHERE tenant_id=$1 AND monitor_id=$2 AND cutoff_at IS NULL",[f.tenant,monitor.id])).rowCount,1);
  stage='final-seal';await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');
 },f.tenant,'site:local'),error=>{assert.equal(stage,'final-seal','Failure before intended seal: '+stage+' '+stateCode(error));return exactError('23514','MONITOR_STORAGE_INVALID')(error);});
 assert.deepEqual(await f.state(),before);
});
