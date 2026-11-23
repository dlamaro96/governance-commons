// SPDX-License-Identifier: Apache-2.0
/** Actual owned PostgreSQL fixture. Authored aggregate envelopes qualify storage,
 * not source-worker execution. Clock overrides below are explicit test inputs. */
import assert from 'node:assert/strict';
import type {TestContext} from 'node:test';
import {assetView} from '../../apps/api/src/repository.ts';
import type {FreshnessRuleDefinition,FreshnessMeasurement,QualityFreshnessBinding} from '../../packages/domain/src/quality-contracts.ts';
import {qualityFreshnessBindingHash,qualityMicroInstant} from '../../packages/domain/src/quality.ts';
import {fixture,canonical} from './reference-quality.ts';
export {code,denied,claimed,permissions} from './reference-quality.ts';
export async function freshnessFixture(t:TestContext){
 const f=await fixture(t);
 await f.ownerTx(async()=>{
  await f.owner.query(`TRUNCATE "${f.namespace}".observations`);
  await f.owner.query(`ALTER TABLE "${f.namespace}".observations ALTER code TYPE timestamptz USING code::timestamptz`);
  await f.owner.query(`INSERT INTO "${f.namespace}".observations(code) VALUES ('2026-01-01T00:00:00Z'),('2026-01-01T00:01:00Z'),(NULL)`);
  const row=(await f.owner.query("UPDATE assets SET metadata=jsonb_set(metadata,'{dataType}','\"timestamp with time zone\"'::jsonb),version=version+1 WHERE tenant_id=$1 AND id=$2 RETURNING *",[f.tenant,f.columnId])).rows[0];
  await f.owner.query('INSERT INTO asset_revisions(tenant_id,asset_id,version,snapshot) VALUES($1,$2,$3,$4::jsonb)',[f.tenant,f.columnId,row.version,JSON.stringify(assetView(row))]);
 });
 const definition=(maximumAgeSeconds=60,maximumFutureSkewSeconds=0):FreshnessRuleDefinition=>({formatVersion:1,kind:'freshness',target:{tableAssetId:f.tableId,columnAssetId:f.columnId},name:'Latest observed timestamp',purpose:'Bounded exact latest timestamp observation.',ownerId:f.ruleOwner,severity:'warning',maximumAgeSeconds,maximumFutureSkewSeconds,comparison:'latest-timestamptz',clock:'source-statement-start',nullPolicy:'exclude',invalidTimestampPolicy:'fail'});
 const binding=(d:FreshnessRuleDefinition=definition()):QualityFreshnessBinding=>{const {maximumAgeSeconds,maximumFutureSkewSeconds,comparison,clock,nullPolicy,invalidTimestampPolicy}=d;const settings={maximumAgeSeconds,maximumFutureSkewSeconds,comparison,clock,nullPolicy,invalidTimestampPolicy};return {...settings,freshnessHash:qualityFreshnessBindingHash(settings)};};
 const microNow=async()=>String((await f.owner.query(`SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS value`)).rows[0].value);
 const shift=async(at:string,deltaMicroseconds:string)=>String((await f.owner.query(`SELECT to_char(($1::timestamptz+$2::bigint*interval '1 microsecond') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS value`,[at,deltaMicroseconds])).rows[0].value);
 const measurement=async(d:FreshnessRuleDefinition=definition(),patch:Partial<FreshnessMeasurement>={}):Promise<FreshnessMeasurement>=>{
  const sourceObservedAt=await microNow(),latestObservedAt=await shift(sourceObservedAt,'-60000000');
  const at=sourceObservedAt.slice(0,23)+'Z';
  const value:FreshnessMeasurement={formatVersion:1,kind:'freshness',strategy:'exact-bounded-role-scope',rowCount:3,nullCount:1,nonFiniteCount:0,unrepresentableCount:0,futureCount:0,sourceObservedAt,latestObservedAt,ageMicroseconds:'60000000',freshnessHash:binding(d).freshnessHash,observedStartedAt:at,observedFinishedAt:at,elapsedMs:0,sourceVersion:'170006',adapterVersion:'1',queryTemplate:'postgresql-freshness-v1',estimatedCost:1,estimatedBytes:24,...patch};
  if(!Object.hasOwn(patch,'ageMicroseconds'))value.ageMicroseconds=value.latestObservedAt===null?null:(qualityMicroInstant(value.sourceObservedAt).epochMicroseconds-qualityMicroInstant(value.latestObservedAt).epochMicroseconds).toString();
  return value;
 };
 const state=async()=>{const original=await f.state();return f.ownerTx(async()=>{for(const name of ['quality_monitors','quality_monitor_versions','quality_monitor_schedule_segments','quality_monitor_occurrences','quality_monitor_incidents','quality_monitor_incident_events','quality_monitor_projection_receipts','quality_monitor_notifications'])original[name]=(await f.owner.query('SELECT * FROM public."'+name+'" WHERE tenant_id=$1',[f.tenant])).rows.sort((a,b)=>canonical(a)<canonical(b)?-1:1);return original;});};
 const unchanged=async(work:()=>Promise<unknown>,predicate:(e:unknown)=>boolean)=>{const before=await state();await assert.rejects(work,predicate);assert.deepEqual(await state(),before);};
 const ownerTx=async<T>(work:()=>Promise<T>,scope:string=f.tenant,who:string=f.actor)=>{await f.owner.query('BEGIN');try{await f.owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[scope,who]);const value=await work();await f.owner.query('COMMIT');return value;}catch(e){await f.owner.query('ROLLBACK');throw e;}};
 return {...f,ownerTx,definition,binding,microNow,shift,measurement,state,unchanged};
}
