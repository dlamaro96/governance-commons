// SPDX-License-Identifier: Apache-2.0
/** Rollback-contained owner attacks against actual protected PostgreSQL writes.
 * No production role is given DML or trigger-management authority. */
import assert from 'node:assert/strict';
import test from 'node:test';
import {randomUUID} from 'node:crypto';
import {volumeFixture,claimed,exactError} from '../fixtures/quality-volume.ts';
const stateCode=(e:unknown)=>e&&typeof e==='object'&&'code'in e&&typeof e.code==='string'&&/^[0-9A-Z]{5}$/.test(e.code)?e.code:'NO_SQLSTATE';
const guardQuery="SELECT tgrelid::regclass::text relation,tgname,tgenabled FROM pg_trigger WHERE tgrelid IN('quality_runs'::regclass,'audit'::regclass,'outbox'::regclass,'quality_rule_versions'::regclass,'quality_monitor_occurrences'::regclass) AND NOT tgisinternal ORDER BY 1,2";
test('volume retained binding substitution is rejected by the deferred seal with rollback restoring its immediate guard',async t=>{
 const f=await volumeFixture(t),d=f.definition(),{rule}=await f.publish(d),{run}=await f.request(rule),before=await f.state(),guards=(await f.owner.query(guardQuery)).rows;let stage='disable',changed=false;
 await assert.rejects(()=>f.ownerTx(async()=>{
  await f.owner.query('ALTER TABLE quality_runs DISABLE TRIGGER quality_runs_guard');stage='forged-binding';const b=f.binding(f.definition(0,5));assert.equal((await f.owner.query("UPDATE quality_runs SET inputs=jsonb_set(inputs,'{execution,volume}',$3::jsonb),input_hash=gc_type_migration_hash(jsonb_set(inputs,'{execution,volume}',$3::jsonb)) WHERE tenant_id=$1 AND id=$2 RETURNING id",[f.tenant,run.id,JSON.stringify(b)])).rowCount,1);changed=true;
  stage='final-seal';await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');
 }),e=>{assert.equal(stage,'final-seal','Wrong refusal phase '+stage+' '+stateCode(e));return exactError('23514','QUALITY_STORAGE_INVALID')(e);});
 assert.ok(changed);assert.deepEqual((await f.owner.query(guardQuery)).rows,guards);assert.deepEqual(await f.state(),before);
});
test('volume cancellation seal proves exact table resource rule and run identities even after an earlier flush',async t=>{
 const f=await volumeFixture(t),{rule}=await f.publish(f.definition()),{run}=await f.request(rule),before=await f.state(),guards=(await f.owner.query(guardQuery)).rows;let stage='flush',cancelled=false,changed=false,restored=false;
 await assert.rejects(()=>f.ownerTx(async()=>{
  await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');await f.owner.query('SET CONSTRAINTS ALL DEFERRED');stage='cancel';const body={runId:run.id,expectedVersion:1,reason:'Owned cancellation integrity attack'};const result=(await f.owner.query("SELECT gc_quality_command('quality.run.cancel',$1,$2::jsonb,'volume-native') value",[randomUUID(),JSON.stringify(body)])).rows[0].value;assert.equal(result.run.status,'cancelled');cancelled=true;
  stage='journal-attack';await f.owner.query('ALTER TABLE audit DISABLE TRIGGER USER');assert.equal((await f.owner.query("UPDATE audit SET changes=jsonb_set(changes,'{ruleId}',to_jsonb($3::uuid)) WHERE tenant_id=$1 AND action='quality.run_cancelled' AND resource_id=$2 AND changes->>'runId'=$4 RETURNING id",[f.tenant,f.tableId,randomUUID(),run.id])).rowCount,1);changed=true;
  await f.owner.query('ALTER TABLE audit ENABLE TRIGGER USER');assert.deepEqual((await f.owner.query(guardQuery)).rows,guards);restored=true;stage='final-seal';await f.owner.query('SET CONSTRAINTS quality_volume_run_seal IMMEDIATE');
 }),e=>{assert.equal(stage,'final-seal','Wrong refusal phase '+stage+' '+stateCode(e));return exactError('23514','QUALITY_STORAGE_INVALID')(e);});
 assert.ok(cancelled&&changed&&restored);assert.deepEqual((await f.owner.query(guardQuery)).rows,guards);assert.deepEqual(await f.state(),before);
});
test('volume finish after initial flush still requires its exact append-only audit and outbox pair',async t=>{
 const f=await volumeFixture(t),d=f.definition(),{rule}=await f.publish(d),{run}=await f.request(rule),c=await f.claim(run.id);claimed(c);const m=await f.measurement(d),before=await f.state(),guards=(await f.owner.query(guardQuery)).rows;let stage='flush',finished=false,changed=false,restored=false;
 await assert.rejects(()=>f.ownerTx(async()=>{
  await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');await f.owner.query('SET CONSTRAINTS ALL DEFERRED');stage='finish';const result=(await f.owner.query('SELECT gc_quality_finish($1,$2::jsonb) value',[run.id,JSON.stringify({claimId:c.claimId,attempt:c.attempt,measurement:m})])).rows[0].value;assert.equal(result.run.verdict,'PASS');finished=true;
  const pair=(await f.owner.query("SELECT a.id FROM audit a JOIN outbox o ON o.tenant_id=a.tenant_id AND o.id=a.id WHERE a.tenant_id=$1 AND a.action='quality.run_finished' AND a.resource_id=$2 AND a.changes->>'runId'=$3",[f.tenant,f.tableId,run.id])).rows;assert.equal(pair.length,1);
  stage='journal-attack';await f.owner.query('ALTER TABLE audit DISABLE TRIGGER USER');assert.equal((await f.owner.query("UPDATE audit SET changes=jsonb_set(changes,'{ruleId}',to_jsonb($3::uuid)) WHERE tenant_id=$1 AND id=$2",[f.tenant,pair[0].id,randomUUID()])).rowCount,1);changed=true;
  await f.owner.query('ALTER TABLE audit ENABLE TRIGGER USER');assert.deepEqual((await f.owner.query(guardQuery)).rows,guards);restored=true;stage='final-seal';await f.owner.query('SET CONSTRAINTS quality_volume_run_seal IMMEDIATE');
 },f.tenant,'site:local'),e=>{assert.equal(stage,'final-seal','Wrong refusal phase '+stage+' '+stateCode(e));return exactError('23514','QUALITY_STORAGE_INVALID')(e);});
 assert.ok(finished&&changed&&restored);assert.deepEqual((await f.owner.query(guardQuery)).rows,guards);assert.deepEqual(await f.state(),before);
});
test('volume monitored table scope rejects an injected column identity after actual protected admission',async t=>{
 const f=await volumeFixture(t),{rule}=await f.publish(f.definition()),{monitor}=await f.publishMonitor(rule);await f.waitUntil(monitor.definition.schedule.startsAt);const before=await f.state(),guards=(await f.owner.query(guardQuery)).rows;let stage='disable',admitted=false,changed=false;
 await assert.rejects(()=>f.ownerTx(async()=>{
  await f.owner.query('ALTER TABLE quality_monitor_occurrences DISABLE TRIGGER quality_monitor_guard');await f.owner.query('ALTER TABLE quality_monitor_occurrences DISABLE TRIGGER monitor_immutable');stage='admit';const work=(await f.owner.query('SELECT gc_quality_monitor_tick($1) value',[monitor.id])).rows[0].value;assert.equal(work.state,'advanced');assert.ok(work.runId);admitted=true;
  stage='scope-attack';assert.equal((await f.owner.query("UPDATE quality_monitor_occurrences SET comparison_scope=jsonb_set(comparison_scope,'{columnAssetId}',to_jsonb($3::uuid)),comparison_scope_hash=gc_type_migration_hash(jsonb_set(comparison_scope,'{columnAssetId}',to_jsonb($3::uuid))) WHERE tenant_id=$1 AND id=$2",[f.tenant,work.occurrenceId,f.columnId])).rowCount,1);changed=true;stage='final-seal';await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');
 },f.tenant,'site:local'),e=>{assert.equal(stage,'final-seal','Wrong refusal phase '+stage+' '+stateCode(e));return exactError('23514','MONITOR_STORAGE_INVALID')(e);});
 assert.ok(admitted&&changed);assert.deepEqual((await f.owner.query(guardQuery)).rows,guards);assert.deepEqual(await f.state(),before);
});
