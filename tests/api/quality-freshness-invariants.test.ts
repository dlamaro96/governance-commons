// SPDX-License-Identifier: Apache-2.0
/** Owner-only rollback attacks; actual protected commands and deferred seals.
 * Measurements are authored storage inputs, not claims of worker execution. */
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import test from 'node:test';
import {freshnessFixture,code,claimed} from '../fixtures/quality-freshness.ts';
const exactSeal=(e:unknown)=>code('23514')(e)&&e instanceof Error&&e.message==='QUALITY_STORAGE_INVALID';

test('freshness deferred run seal rejects a substituted immutable settings binding after prior constraint flush',async t=>{
 const f=await freshnessFixture(t),{rule}=await f.publish(f.definition()),{run}=await f.request(rule),before=await f.state();let changed=false,atSeal=false;
 const trigger=()=>f.owner.query("SELECT tgenabled FROM pg_trigger WHERE tgrelid='quality_runs'::regclass AND tgname='quality_runs_guard'");const original=(await trigger()).rows;
 await assert.rejects(()=>f.ownerTx(async()=>{
  await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');await f.owner.query('SET CONSTRAINTS ALL DEFERRED');
  await f.owner.query('ALTER TABLE public.quality_runs DISABLE TRIGGER quality_runs_guard');
  const update=await f.owner.query("UPDATE quality_runs SET inputs=jsonb_set(inputs,'{execution,freshness}',$3::jsonb),input_hash=public.gc_type_migration_hash(jsonb_set(inputs,'{execution,freshness}',$3::jsonb)) WHERE tenant_id=$1 AND id=$2 RETURNING id",[f.tenant,run.id,JSON.stringify(f.binding(f.definition(3600)))]);
  assert.equal(update.rowCount,1);changed=true;atSeal=true;await f.owner.query('SET CONSTRAINTS quality_freshness_run_seal IMMEDIATE');
 }),e=>changed&&atSeal&&exactSeal(e));assert.deepEqual((await trigger()).rows,original);assert.deepEqual(await f.state(),before);
});

test('freshness deferred completion seal independently recomputes exact microsecond age and refuses forged evidence',async t=>{
 const f=await freshnessFixture(t),d=f.definition(),{rule}=await f.publish(d),{run}=await f.request(rule),before=await f.state();let completed=false,poisoned=false,atSeal=false;
 const guard=()=>f.owner.query("SELECT tgenabled FROM pg_trigger WHERE tgrelid='quality_runs'::regclass AND tgname='quality_runs_guard'");const original=(await guard()).rows;
 await assert.rejects(()=>f.ownerTx(async()=>{
  const c=(await f.owner.query('SELECT public.gc_quality_claim($1::uuid,$2::uuid) AS value',[run.id,randomUUID()])).rows[0].value;claimed(c);
  await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');await f.owner.query('SET CONSTRAINTS ALL DEFERRED');
  await f.owner.query('ALTER TABLE public.quality_runs DISABLE TRIGGER quality_runs_guard');
  const m=await f.measurement(d),body={claimId:c.claimId,attempt:c.attempt,measurement:m};
  const outcome=(await f.owner.query('SELECT public.gc_quality_finish($1::uuid,$2::jsonb) AS value',[run.id,JSON.stringify(body)])).rows[0].value;assert.equal(outcome.run.status,'succeeded');assert.equal(outcome.run.verdict,'PASS');completed=true;
  const altered={...m,ageMicroseconds:'59999999'};assert.equal((await f.owner.query('UPDATE quality_runs SET measurement=$3::jsonb WHERE tenant_id=$1 AND id=$2',[f.tenant,run.id,JSON.stringify(altered)])).rowCount,1);poisoned=true;
  atSeal=true;await f.owner.query('SET CONSTRAINTS quality_freshness_run_seal IMMEDIATE');
 },f.tenant,'site:local'),e=>completed&&poisoned&&atSeal&&exactSeal(e));assert.deepEqual((await guard()).rows,original);assert.deepEqual(await f.state(),before);
});

test('freshness post-flush completion requires its exact paired finish journal under the unchanged site actor',async t=>{
 const f=await freshnessFixture(t),{rule}=await f.publish(f.definition()),{run}=await f.request(rule),before=await f.state();let completed=false,restored=false,atSeal=false;
 const guards=()=>f.owner.query("SELECT tgname,tgenabled FROM pg_trigger WHERE tgrelid='public.audit'::regclass AND NOT tgisinternal ORDER BY tgname");const original=(await guards()).rows;
 await assert.rejects(()=>f.ownerTx(async()=>{
  const c=(await f.owner.query('SELECT public.gc_quality_claim($1::uuid,$2::uuid) AS value',[run.id,randomUUID()])).rows[0].value;claimed(c);
  await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');await f.owner.query('SET CONSTRAINTS ALL DEFERRED');
  const body={claimId:c.claimId,attempt:c.attempt,measurement:await f.measurement()};
  const outcome=(await f.owner.query('SELECT public.gc_quality_finish($1::uuid,$2::jsonb) AS value',[run.id,JSON.stringify(body)])).rows[0].value;assert.equal(outcome.run.status,'succeeded');completed=true;
  const pair=await f.owner.query("SELECT a.actor_id,a.action,a.changes FROM audit a JOIN outbox o ON o.id=a.id AND o.tenant_id=a.tenant_id WHERE a.tenant_id=$1 AND a.action='quality.run_finished' AND a.changes->>'runId'=$2 AND o.event_type=a.action",[f.tenant,run.id]);assert.equal(pair.rowCount,1);assert.equal(pair.rows[0].actor_id,'site:local');assert.equal(pair.rows[0].changes.ruleId,rule.id);assert.equal(pair.rows[0].changes.resourceVersion,outcome.run.version);
  await f.owner.query('ALTER TABLE public.audit DISABLE TRIGGER USER');
  assert.equal((await f.owner.query("UPDATE audit SET changes=jsonb_set(changes,'{ruleId}',to_jsonb($3::uuid)) WHERE tenant_id=$1 AND action='quality.run_finished' AND changes->>'runId'=$2",[f.tenant,run.id,randomUUID()])).rowCount,1);
  await f.owner.query('ALTER TABLE public.audit ENABLE TRIGGER USER');restored=true;atSeal=true;await f.owner.query('SET CONSTRAINTS quality_freshness_run_seal IMMEDIATE');
 },f.tenant,'site:local'),e=>completed&&restored&&atSeal&&exactSeal(e));assert.deepEqual((await guards()).rows,original);assert.deepEqual(await f.state(),before);
});

test('freshness publication seal requires the exact immutable definition hash in its paired journal',async t=>{
 const f=await freshnessFixture(t),before=await f.state(),id=randomUUID();let published=false,restored=false,atSeal=false;
 await assert.rejects(()=>f.ownerTx(async()=>{
  const value=(await f.owner.query("SELECT public.gc_quality_command('quality.rule.publish',$1,$2::jsonb,'freshness-native') AS value",[randomUUID(),JSON.stringify({id,expectedVersion:0,definition:f.definition()})])).rows[0].value;assert.equal(value.rule.id,id);published=true;
  await f.owner.query('ALTER TABLE public.audit DISABLE TRIGGER USER');
  assert.equal((await f.owner.query("UPDATE audit SET changes=jsonb_set(changes,'{definitionHash}',to_jsonb($3::text)) WHERE tenant_id=$1 AND action='quality.rule_published' AND changes->>'ruleId'=$2",[f.tenant,id,'0'.repeat(64)])).rowCount,1);
  await f.owner.query('ALTER TABLE public.audit ENABLE TRIGGER USER');restored=true;atSeal=true;await f.owner.query('SET CONSTRAINTS quality_freshness_rule_seal IMMEDIATE');
 }),e=>published&&restored&&atSeal&&exactSeal(e));assert.deepEqual(await f.state(),before);
});
