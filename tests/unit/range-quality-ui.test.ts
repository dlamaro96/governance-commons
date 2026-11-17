// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {canonicalInt64,rangeBounds,qualityEvidenceMatches,qualityThreshold,qualityThresholdKey,percentageToBasisPoints,basisPointsToInput} from '../../apps/web/src/quality/presentation.ts';
import {qualityCopy} from '../../apps/web/src/quality/messages.ts';
import type {QualityRuleView,QualityRunView} from '../../packages/domain/src/quality-contracts.ts';

const rule:QualityRuleView={id:'rule',version:1,currentVersion:null,definitionHash:'a'.repeat(64),createdAt:'2026-11-17T00:00:00.000Z',createdBy:'actor',definition:{formatVersion:1,kind:'range',target:{tableAssetId:'table',columnAssetId:'column'},name:'Integer range',purpose:'Inclusive integer bounds',ownerId:'actor',severity:'warning',maximumOutOfRangeBasisPoints:3999,minimum:'0',maximum:'10',comparison:'int64-inclusive',nullPolicy:'exclude'}};
const run:QualityRunView={kind:'range',range:{minimum:'0',maximum:'10',comparison:'int64-inclusive',nullPolicy:'exclude',rangeHash:'b'.repeat(64)},id:'run',ruleId:rule.id,ruleVersion:rule.version,ruleHash:rule.definitionHash,requesterId:'actor',columnAssetId:'column',tableAssetId:'table',status:'succeeded',version:3,attempt:1,createdAt:'2026-11-17T00:00:00.000Z',startedAt:null,finishedAt:null,expiresAt:'2026-11-18T00:00:00.000Z',errorCode:null,verdict:'FAIL',measurement:{formatVersion:1,kind:'range',strategy:'exact-bounded-role-scope',rowCount:6,nullCount:1,belowCount:1,aboveCount:1,rangeHash:'b'.repeat(64),observedStartedAt:'2026-11-17T01:00:00.000Z',observedFinishedAt:'2026-11-17T01:00:00.001Z',elapsedMs:1,sourceVersion:'18',adapterVersion:'1',queryTemplate:'postgresql-range-v1',estimatedCost:1,estimatedBytes:48}};

test('range bounds preserve exact canonical int64 strings and compare without Number rounding',()=>{
 for(const value of ['0','-1','9223372036854775807','-9223372036854775808','9007199254740993'])assert.equal(canonicalInt64(value),value);
 assert.deepEqual(rangeBounds('-9223372036854775808','9223372036854775807'),{minimum:'-9223372036854775808',maximum:'9223372036854775807'});
 assert.deepEqual(rangeBounds('9007199254740993','9007199254740993'),{minimum:'9007199254740993',maximum:'9007199254740993'});
 assert.equal(rangeBounds('9007199254740993','9007199254740992'),null);assert.equal(rangeBounds('-1','-2'),null);
 assert.deepEqual(rangeBounds('0','0'),{minimum:'0',maximum:'0'});
});
test('range admission rejects noncanonical grammar, Unicode digits and overflow without normalization',()=>{
 for(const value of ['', ' ', ' 0','0 ','+1','-0','01','-01','1.0','1e3','٠','１','−1','1\n','9223372036854775808','-9223372036854775809','1'.repeat(100)]){
  assert.equal(canonicalInt64(value),null,JSON.stringify(value));assert.equal(rangeBounds(value,'10'),null);assert.equal(rangeBounds('0',value),null);
 }
});
test('range percentage editor retains exact fail/pass threshold in both locales',()=>{
 for(const [input,expected] of [['39.99',3999],['40',4000],['٣٩٫٩٩',3999],['٤٠',4000]] as const)assert.equal(percentageToBasisPoints(input),expected);
 assert.equal(basisPointsToInput(qualityThreshold(rule.definition)),'39.99');assert.equal(qualityThresholdKey('range'),'maximumOutOfRange');assert.equal(percentageToBasisPoints('39.999'),null);
});
test('range evidence preserves selected history with a hidden or advanced head',()=>{
 const before=JSON.stringify([rule,run]);assert.equal(qualityEvidenceMatches(run,rule),true);assert.equal(qualityEvidenceMatches(run,{...rule,currentVersion:2}),true);
 assert.equal(qualityEvidenceMatches({...run,status:'queued',measurement:null,verdict:null},rule),true);assert.equal(JSON.stringify([rule,run]),before);
});
test('range evidence refuses another rule, target, bound, hash or family',()=>{
 for(const bad of [{...run,ruleId:'other'},{...run,ruleVersion:2},{...run,ruleHash:'c'.repeat(64)},{...run,columnAssetId:'other'},{...run,tableAssetId:'other'},{...run,reference:undefined},{...run,range:{...run.range,minimum:'1'}},{...run,range:{...run.range,maximum:'9'}},{...run,range:{...run.range,minimum:'00'}},{...run,range:{...run.range,rangeHash:'BAD'}},{...run,range:{...run.range,rangeHash:'c'.repeat(64)}},{...run,range:{...run.range,comparison:'utf8-exact'}},{...run,range:{...run.range,nullPolicy:'include'}},{...run,measurement:{...run.measurement,kind:'uniqueness'}}])assert.equal(qualityEvidenceMatches(bad as unknown as QualityRunView,rule),false);
});
test('range evidence does not reinterpret older family thresholds',()=>{
 const common={formatVersion:1 as const,target:rule.definition.target,name:'Other',purpose:'Synthetic',ownerId:'actor',severity:'warning' as const};
 const definitions=[{...common,kind:'completeness' as const,maximumNullBasisPoints:3000},{...common,kind:'uniqueness' as const,maximumDuplicateBasisPoints:3750,comparison:'utf8-exact' as const,nullPolicy:'exclude' as const},{...common,kind:'reference-allowed-values' as const,maximumInvalidBasisPoints:2500,comparison:'utf8-exact' as const,nullPolicy:'exclude' as const,reference:{setId:'set',selection:'effective-at-run' as const,codeStatus:'active' as const}}];
 assert.deepEqual(definitions.map(qualityThreshold),[3000,3750,2500]);
 for(const definition of definitions)assert.equal(qualityEvidenceMatches(run,{...rule,definition}),false);
});
test('range copy explains inclusive bounds, null exclusion, exact ratios and both locales',()=>{
 assert.deepEqual(Object.keys(qualityCopy.en).sort(),Object.keys(qualityCopy.ar).sort());
 for(const copy of Object.values(qualityCopy))for(const key of ['range','minimum','maximum','maximumOutOfRange','rangeBoundsHint','rangeInvalid','rangeComparison','rangeThresholdHint','belowRows','aboveRows','outOfRangeRows','outOfRangePercentage','rangeFormula','rangeHash'] as const)assert.ok(copy[key].trim());
 assert.match(qualityCopy.en.rangeBoundsHint,/-9223372036854775808/);assert.match(qualityCopy.en.rangeFormula,/equal to either bound/);assert.match(qualityCopy.en.rangeComparison,/zero is a value/);
});
