// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {qualityEvidenceMatches,qualityThreshold,volumeBoundsInput} from '../../apps/web/src/quality/presentation.ts';
import type {QualityRuleView,QualityRunView} from '../../packages/domain/src/quality-contracts.ts';
const rule:QualityRuleView={id:'rule',version:1,currentVersion:2,definitionHash:'a'.repeat(64),createdAt:'2026-11-17T00:00:00.000Z',createdBy:'actor',definition:{formatVersion:1,kind:'volume',target:{kind:'table',tableAssetId:'table'},name:'Rows',purpose:'Observe exact rows',ownerId:'actor',severity:'warning',minimumRows:6,maximumRows:6,comparison:'row-count-inclusive',scope:'entire-table'}};
const run:QualityRunView={id:'run',ruleId:'rule',ruleVersion:1,ruleHash:'a'.repeat(64),requesterId:'actor',columnAssetId:null,tableAssetId:'table',status:'succeeded',version:3,attempt:1,createdAt:'2026-11-17T00:00:00.000Z',startedAt:'2026-11-17T00:00:01.000Z',finishedAt:'2026-11-17T00:00:02.000Z',expiresAt:'2026-11-17T00:15:00.000Z',kind:'volume',volume:{minimumRows:6,maximumRows:6,comparison:'row-count-inclusive',scope:'entire-table',volumeHash:'b'.repeat(64)},verdict:'PASS',errorCode:null,measurement:{formatVersion:1,kind:'volume',strategy:'exact-bounded-role-scope',rowCount:6,volumeHash:'b'.repeat(64),observedStartedAt:'2026-11-17T00:00:01.000Z',observedFinishedAt:'2026-11-17T00:00:02.000Z',elapsedMs:1000,sourceVersion:'170000',adapterVersion:'1',queryTemplate:'postgresql-volume-v1',estimatedCost:1,estimatedBytes:24}};
test('volume input admits exact inclusive zero and cap bounds in English and localized digits',()=>{
 assert.deepEqual(volumeBoundsInput('0','100000'),{minimumRows:0,maximumRows:100000});assert.deepEqual(volumeBoundsInput('٦','٦'),{minimumRows:6,maximumRows:6});assert.deepEqual(volumeBoundsInput('۵','۶'),{minimumRows:5,maximumRows:6});
});
test('volume input refuses fractional, coerced, reversed and overflowing row counts',()=>{
 for(const value of ['', '-0','-1','+1','01','1.0','1e2','0x10','NaN','Infinity','100001','١٫٥'])assert.equal(volumeBoundsInput(value,'100000'),null,value);
 assert.equal(volumeBoundsInput('7','6'),null);assert.equal(volumeBoundsInput('0','-1'),null);
});
test('table evidence retains old immutable bounds even when the current rule head advances',()=>{
 assert.equal(qualityEvidenceMatches(run,rule),true);assert.equal(qualityEvidenceMatches(run,{...rule,currentVersion:null}),true);assert.throws(()=>qualityThreshold(rule.definition));
});
test('table evidence rejects a borrowed column, changed table, settings or measurement hash',()=>{
 const wrongs=[{...run,columnAssetId:'invented-column'},{...run,tableAssetId:'another-table'},{...run,volume:{...run.volume,minimumRows:5}},{...run,measurement:{...run.measurement,volumeHash:'c'.repeat(64)}},{...run,measurement:{...run.measurement,nullCount:0}},{...run,reference:{}},{...run,ruleHash:'c'.repeat(64)}];
 for(const value of wrongs)assert.equal(qualityEvidenceMatches(value as QualityRunView,rule),false);
});
test('volume evidence never borrows a column family and exact zero rows remain measurable',()=>{
 const column={...rule,definition:{formatVersion:1,kind:'completeness',target:{tableAssetId:'table',columnAssetId:'column'},name:'Column',purpose:'Measure',ownerId:'actor',severity:'warning',maximumNullBasisPoints:0}} as QualityRuleView;
 assert.equal(qualityEvidenceMatches(run,column),false);
 assert.equal(qualityEvidenceMatches({...run,volume:{...run.volume,minimumRows:0,maximumRows:0},measurement:{...run.measurement!,rowCount:0}}, {...rule,definition:{...rule.definition,minimumRows:0,maximumRows:0}} as QualityRuleView),true);
});
