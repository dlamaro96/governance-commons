// SPDX-License-Identifier: Apache-2.0
/** Disposable SQL storage qualification. Aggregate inputs below are authored protocol
 * fixtures; they do not assert source execution, Temporal delivery, or clock backfill. */
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import type {TestContext} from 'node:test';
import {sql,type Tx} from '../../packages/db/src/index.ts';
import {fixture,canonical,claimed} from './reference-quality.ts';
import type {CompletenessRuleDefinition,QualityClaim,QualityMeasurement,QualityRuleView} from '../../packages/domain/src/quality-contracts.ts';
import type {QualityMonitorDefinition,QualityMonitorView,QualityOccurrence,QualityIssueView,QualityNotification,MonitoringWorkResult} from '../../packages/domain/src/quality-monitoring-contracts.ts';
import {parseMonitorView,parseOccurrence,parseIssueView,parseNotification} from '../../packages/domain/src/quality-monitoring.ts';
import {monitoringQuery} from '../../packages/domain/src/quality-monitoring-service.ts';
export const monitoringTables=['quality_monitors','quality_monitor_versions','quality_monitor_schedule_segments','quality_monitor_occurrences','quality_monitor_incidents','quality_monitor_incident_events','quality_monitor_projection_receipts','quality_monitor_notifications'] as const;
export const exactError=(code:string,message:string)=>(error:unknown)=>!!error&&typeof error==='object'&&'code'in error&&error.code===code&&'message'in error&&error.message===message;
export async function monitoringFixture(t:TestContext){
 const f=await fixture(t);
 // Each operation starts with the actual actor and one original30s wrapper; no
 // fixture tenant-ledger prelock, impersonation, or second operation clock.
 const as=<T>(work:(tx:Tx)=>Promise<T>,who:string=f.actor,tenant:string=f.tenant):Promise<T>=>f.db.transaction().execute(async tx=>{await sql`select set_config('gc.tenant_id',${tenant},true),set_config('gc.actor_id',${who},true)`.execute(tx);return monitoringQuery(tx,()=>work(tx));});
 const ownerTx=async<T>(work:()=>Promise<T>,scope:string=f.tenant,who:string=f.actor):Promise<T>=>{await f.owner.query('BEGIN');try{await f.owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[scope,who]);const value=await work();await f.owner.query('COMMIT');return value;}catch(error){await f.owner.query('ROLLBACK');throw error;}};
 const command=<T=any>(operation:string,body:unknown,key:string=randomUUID(),who:string=f.actor,tenant:string=f.tenant)=>as(async tx=>(await sql<{value:T}>`select public.gc_quality_monitor_command(${operation},${key},${JSON.stringify(body)}::jsonb,'monitor-native') as value`.execute(tx)).rows[0].value,who,tenant);
 const completeness=(maximumNullBasisPoints=0):CompletenessRuleDefinition=>({formatVersion:1,kind:'completeness',target:{tableAssetId:f.tableId,columnAssetId:f.columnId},name:'Required source value',purpose:'Synthetic aggregate storage qualification.',ownerId:f.ruleOwner,severity:'warning',maximumNullBasisPoints});
 const monitorDefinition=async(rule:QualityRuleView,patch:Partial<QualityMonitorDefinition>={}):Promise<QualityMonitorDefinition>=>{
  const at=Date.parse(await f.now());return {formatVersion:1,name:'Synthetic source monitor',purpose:'Fixed UTC observations with independent current authority.',rule:{id:rule.id,version:rule.version,definitionHash:rule.definitionHash},executorId:f.actor,authorizationExpiresAt:new Date(at+3600000).toISOString(),
   schedule:{kind:'fixed-interval',timeZone:'UTC',startsAt:new Date(at+1500).toISOString(),endsAt:null,intervalSeconds:60,lateGraceSeconds:59,missedSlots:'skip',overlap:'skip'},maintenance:[],silences:[],routing:{channel:'in-app',ownerId:f.reviewer,recipientIds:[f.reviewer]},issue:{category:'data-quality',acknowledgeWithinSeconds:60,resolveWithinSeconds:600},recoveryMaximumAgeSeconds:600,retry:{policy:'quality-run-v1'},...patch};
 };
 const publishMonitor=async(rule:QualityRuleView,definition?:QualityMonitorDefinition,id:string=randomUUID(),expectedRevision=0,key:string=randomUUID())=>{
  const result=await command<{monitor:QualityMonitorView}>('quality.monitor.publish',{id,expectedRevision,definition:definition??await monitorDefinition(rule)},key);parseMonitorView(result.monitor);return result;
 };
 const tick=(id:string):Promise<MonitoringWorkResult>=>as(async tx=>(await sql<{value:MonitoringWorkResult}>`select public.gc_quality_monitor_tick(${id}::uuid) as value`.execute(tx)).rows[0].value,'site:local');
 const reconcile=(id:string):Promise<MonitoringWorkResult>=>as(async tx=>(await sql<{value:MonitoringWorkResult}>`select public.gc_quality_monitor_reconcile(${id}::uuid) as value`.execute(tx)).rows[0].value,'site:local');
 const monitor=(id:string)=>as(async tx=>parseMonitorView((await sql<{value:unknown}>`select public.gc_quality_monitor_view(${id}::uuid) as value`.execute(tx)).rows[0].value));
 const issue=(id:string)=>as(async tx=>parseIssueView((await sql<{value:unknown}>`select public.gc_quality_issue_view(${id}::uuid) as value`.execute(tx)).rows[0].value));
 const issues=(monitorId:string)=>as(async tx=>(await sql<{value:unknown}>`select public.gc_quality_issue_view(id) as value from public.quality_monitor_incidents where tenant_id=${f.tenant}::uuid and monitor_id=${monitorId}::uuid order by id`.execute(tx)).rows.map(r=>parseIssueView(r.value)));
 const occurrences=(monitorId:string)=>as(async tx=>(await sql<{value:unknown}>`select public.gc_quality_occurrence_view(id) as value from public.quality_monitor_occurrences where tenant_id=${f.tenant}::uuid and monitor_id=${monitorId}::uuid order by ordinal`.execute(tx)).rows.map(r=>parseOccurrence(r.value)));
 const notifications=()=>as(async tx=>(await sql<{value:unknown}>`select public.gc_quality_notification_view(id) as value from public.quality_monitor_notifications where tenant_id=${f.tenant}::uuid order by id`.execute(tx)).rows.map(r=>parseNotification(r.value)));
 const measurement=async(c:QualityClaim,rows=20,nulls=4):Promise<QualityMeasurement>=>{
  claimed(c);assert.equal(c.execution.kind,'completeness');const at=await f.now();return {formatVersion:1,kind:'completeness',strategy:'exact-bounded-role-scope',rowCount:rows,nullCount:nulls,observedStartedAt:at,observedFinishedAt:at,elapsedMs:0,sourceVersion:'170006',adapterVersion:'1',queryTemplate:'postgresql-completeness-v1',estimatedCost:1,estimatedBytes:160};
 };
 const complete=async(runId:string,rows=20,nulls=4)=>{const claim=await f.claim(runId);claimed(claim);const value=await measurement(claim,rows,nulls),result=await f.finish(runId,claim,value);return {claim,measurement:value,run:result.run};};
 const state=async()=>{const previous=await f.state();return f.ownerTx(async()=>{const out:Record<string,unknown>={...previous};for(const name of monitoringTables)out[name]=(await f.owner.query('SELECT * FROM public."'+name+'" WHERE tenant_id=$1',[f.tenant])).rows.sort((a,b)=>canonical(a)<canonical(b)?-1:1);return out;});};
 const unchanged=async(work:()=>Promise<unknown>,predicate:(e:unknown)=>boolean)=>{const before=await state();await assert.rejects(work,predicate);assert.deepEqual(await state(),before,'Refusal rolls back all monitoring, quality, reference, history, journal and idempotency rows');};
 return {...f,ownerTx,as,command,completeness,monitorDefinition,publishMonitor,tick,reconcile,monitor,issue,issues,occurrences,notifications,measurement,complete,state,unchanged};
}
