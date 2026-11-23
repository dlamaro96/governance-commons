// SPDX-License-Identifier: Apache-2.0
/** Real disposable PostgreSQL fixture; source counts below are independent
 * protocol oracles, not claims of Python or Temporal execution. */
import type {TestContext} from 'node:test';
import {monitoringFixture} from './quality-monitoring.ts';
import type {VolumeRuleDefinition,VolumeMeasurement,QualityVolumeBinding} from '../../packages/domain/src/quality-contracts.ts';
import {qualityVolumeBindingHash} from '../../packages/domain/src/quality.ts';
export {exactError} from './quality-monitoring.ts';
export {code,denied,claimed,permissions,canonical} from './reference-quality.ts';
export async function volumeFixture(t:TestContext){
 const f=await monitoringFixture(t);
 await f.owner.query(`TRUNCATE "${f.namespace}".observations`);
 await f.owner.query(`INSERT INTO "${f.namespace}".observations SELECT NULL FROM generate_series(1,6)`);
 const definition=(minimumRows=6,maximumRows=6):VolumeRuleDefinition=>({formatVersion:1,kind:'volume',target:{kind:'table',tableAssetId:f.tableId},name:'Expected complete table population',purpose:'Exact bounded row count without child-column access.',ownerId:f.ruleOwner,severity:'warning',minimumRows,maximumRows,comparison:'row-count-inclusive',scope:'entire-table'});
 const binding=(d=definition()):QualityVolumeBinding=>{const {minimumRows,maximumRows,comparison,scope}=d;const settings={minimumRows,maximumRows,comparison,scope};return {...settings,volumeHash:qualityVolumeBindingHash(settings)};};
 const measurement=async(d=definition(),patch:Partial<VolumeMeasurement>={}):Promise<VolumeMeasurement>=>{const at=await f.now();const rowCount=Number((await f.owner.query(`SELECT count(*)::text AS value FROM ONLY "${f.namespace}".observations`)).rows[0].value);return {formatVersion:1,kind:'volume',strategy:'exact-bounded-role-scope',rowCount,volumeHash:binding(d).volumeHash,observedStartedAt:at,observedFinishedAt:at,elapsedMs:0,sourceVersion:'170006',adapterVersion:'1',queryTemplate:'postgresql-volume-v1',estimatedCost:1,estimatedBytes:rowCount*8,...patch};};
 return {...f,definition,binding,measurement};
}
