// SPDX-License-Identifier: Apache-2.0
/** Native storage qualification only. Source rows are actual owned timestamptz;
 * measurement envelopes are authored and do not claim worker/Temporal execution. */
import assert from 'node:assert/strict';
import type {TestContext} from 'node:test';
import {assetView} from '../../apps/api/src/repository.ts';
import type {FreshnessRuleDefinition,FreshnessMeasurement,QualityFreshnessBinding} from '../../packages/domain/src/quality-contracts.ts';
import {qualityFreshnessBindingHash,qualityMicroInstant} from '../../packages/domain/src/quality.ts';
import {monitoringFixture} from './quality-monitoring.ts';
import {claimed} from './reference-quality.ts';
export {exactError,monitoringTables} from './quality-monitoring.ts';
export {claimed,permissions,canonical} from './reference-quality.ts';
export async function freshnessMonitoringFixture(t:TestContext){
 const f=await monitoringFixture(t);
 await f.ownerTx(async()=>{
  await f.owner.query(`TRUNCATE "${f.namespace}".observations`);
  await f.owner.query(`ALTER TABLE "${f.namespace}".observations ALTER code TYPE timestamptz USING code::timestamptz`);
  await f.owner.query(`INSERT INTO "${f.namespace}".observations(code) VALUES ('2026-01-01T00:00:00Z'),('2026-01-01T00:01:00Z'),(NULL)`);
  const row=(await f.owner.query("UPDATE assets SET metadata=jsonb_set(metadata,'{dataType}','\"timestamp with time zone\"'::jsonb),version=version+1 WHERE tenant_id=$1 AND id=$2 RETURNING *",[f.tenant,f.columnId])).rows[0];
  await f.owner.query('INSERT INTO asset_revisions(tenant_id,asset_id,version,snapshot) VALUES($1,$2,$3,$4::jsonb)',[f.tenant,f.columnId,row.version,JSON.stringify(assetView(row))]);
 });
 const definition=(maximumAgeSeconds=90,maximumFutureSkewSeconds=0):FreshnessRuleDefinition=>({formatVersion:1,kind:'freshness',target:{tableAssetId:f.tableId,columnAssetId:f.columnId},name:'Scheduled latest timestamp',purpose:'Actual canonical scheduling with exact authored storage aggregates.',ownerId:f.ruleOwner,severity:'warning',maximumAgeSeconds,maximumFutureSkewSeconds,comparison:'latest-timestamptz',clock:'source-statement-start',nullPolicy:'exclude',invalidTimestampPolicy:'fail'});
 const binding=(d:FreshnessRuleDefinition=definition()):QualityFreshnessBinding=>{const {maximumAgeSeconds,maximumFutureSkewSeconds,comparison,clock,nullPolicy,invalidTimestampPolicy}=d;const settings={maximumAgeSeconds,maximumFutureSkewSeconds,comparison,clock,nullPolicy,invalidTimestampPolicy};return {...settings,freshnessHash:qualityFreshnessBindingHash(settings)};};
 const microNow=async()=>String((await f.owner.query(`SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS value`)).rows[0].value);
 const shift=async(at:string,deltaMicroseconds:string)=>String((await f.owner.query(`SELECT to_char(($1::timestamptz+$2::bigint*interval '1 microsecond') AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS value`,[at,deltaMicroseconds])).rows[0].value);
 const measurement=async(d:FreshnessRuleDefinition=definition(),patch:Partial<FreshnessMeasurement>={}):Promise<FreshnessMeasurement>=>{
  const sourceObservedAt=await microNow(),latestObservedAt=await shift(sourceObservedAt,'-60000000'),at=sourceObservedAt.slice(0,23)+'Z';
  const value:FreshnessMeasurement={formatVersion:1,kind:'freshness',strategy:'exact-bounded-role-scope',rowCount:3,nullCount:1,nonFiniteCount:0,unrepresentableCount:0,futureCount:0,sourceObservedAt,latestObservedAt,ageMicroseconds:'60000000',freshnessHash:binding(d).freshnessHash,observedStartedAt:at,observedFinishedAt:at,elapsedMs:0,sourceVersion:'170006',adapterVersion:'1',queryTemplate:'postgresql-freshness-v1',estimatedCost:1,estimatedBytes:24,...patch};
  if(!Object.hasOwn(patch,'ageMicroseconds'))value.ageMicroseconds=value.latestObservedAt===null?null:(qualityMicroInstant(value.sourceObservedAt).epochMicroseconds-qualityMicroInstant(value.latestObservedAt).epochMicroseconds).toString();
  return value;
 };
 const complete=async(runId:string,d:FreshnessRuleDefinition=definition(),patch:Partial<FreshnessMeasurement>={})=>{const claim=await f.claim(runId);claimed(claim);assert.equal(claim.execution.kind,'freshness');const value=await measurement(d,patch);const result=await f.finish(runId,claim,value);return {claim,measurement:value,run:result.run};};
 return {...f,definition,binding,microNow,shift,measurement,complete};
}
