// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {qualityEvidenceMatches,qualityThreshold,qualityThresholdKey,percentageToBasisPoints,basisPointsToInput} from '../../apps/web/src/quality/presentation.ts';
import {qualityCopy} from '../../apps/web/src/quality/messages.ts';
import type {QualityRuleView,QualityRunView,UniquenessRuleDefinition} from '../../packages/domain/src/quality-contracts.ts';

const rule:QualityRuleView & {definition:UniquenessRuleDefinition}={id:'rule',version:1,currentVersion:null,definitionHash:'a'.repeat(64),createdAt:'2026-11-17T00:00:00.000Z',createdBy:'actor',definition:{formatVersion:1,kind:'uniqueness',target:{tableAssetId:'table',columnAssetId:'column'},name:'Uniqueness',purpose:'Exact duplicate rows',ownerId:'actor',severity:'warning',maximumDuplicateBasisPoints:3749,comparison:'utf8-exact',nullPolicy:'exclude'}};
const run:QualityRunView={kind:'uniqueness',id:'run',ruleId:rule.id,ruleVersion:rule.version,ruleHash:rule.definitionHash,requesterId:'actor',columnAssetId:'column',tableAssetId:'table',status:'succeeded',version:3,attempt:1,createdAt:'2026-11-17T00:00:00.000Z',startedAt:null,finishedAt:null,expiresAt:'2026-11-18T00:00:00.000Z',errorCode:null,verdict:'FAIL',measurement:{formatVersion:1,kind:'uniqueness',strategy:'exact-bounded-role-scope',rowCount:20,nullCount:4,distinctCount:12,duplicateGroupCount:2,duplicateRowCount:6,totalValueBytes:16,largestValueBytes:1,observedStartedAt:'2026-11-17T01:00:00.000Z',observedFinishedAt:'2026-11-17T01:00:00.001Z',elapsedMs:1,sourceVersion:'18',adapterVersion:'1',queryTemplate:'postgresql-uniqueness-v1',estimatedCost:1,estimatedBytes:160}};

test('uniqueness threshold editor preserves the exact boundary in English and Arabic',()=>{
 for(const [input,expected] of [['37.49',3749],['37.50',3750],['٣٧٫٤٩',3749],['٣٧٫٥٠',3750]] as const)assert.equal(percentageToBasisPoints(input),expected);
 assert.equal(basisPointsToInput(qualityThreshold(rule.definition)),'37.49');assert.equal(qualityThresholdKey('uniqueness'),'maximumDuplicate');
 assert.equal(percentageToBasisPoints('37.499'),null);
});
test('uniqueness evidence uses the immutable rule even when the current head is hidden or newer',()=>{
 const before=JSON.stringify([run,rule]);assert.equal(qualityEvidenceMatches(run,rule),true);assert.equal(qualityEvidenceMatches(run,{...rule,currentVersion:2}),true);
 assert.equal(qualityEvidenceMatches({...run,status:'queued',measurement:null,verdict:null},rule),true);assert.equal(JSON.stringify([run,rule]),before);
});
test('uniqueness evidence refuses mismatched exact pins, targets and reference-shaped records',()=>{
 for(const bad of [{...run,ruleHash:'b'.repeat(64)},{...run,ruleVersion:2},{...run,ruleId:'other'},{...run,columnAssetId:'other'},{...run,tableAssetId:'other'},{...run,reference:undefined}])assert.equal(qualityEvidenceMatches(bad as QualityRunView,rule),false);
 const wrong={...run,measurement:{...run.measurement,kind:'completeness'}} as unknown as QualityRunView;assert.equal(qualityEvidenceMatches(wrong,rule),false);
});
test('completeness and reference thresholds remain independent from uniqueness history',()=>{
 const common={formatVersion:1 as const,target:rule.definition.target,name:'Other',purpose:'Synthetic',ownerId:'actor',severity:'warning' as const};
 const completeness:QualityRuleView={...rule,definition:{...common,kind:'completeness',maximumNullBasisPoints:3000}};
 const reference:QualityRuleView={...rule,definition:{...common,kind:'reference-allowed-values',maximumInvalidBasisPoints:2500,reference:{setId:'set',selection:'effective-at-run',codeStatus:'active'},comparison:'utf8-exact',nullPolicy:'exclude'}};
 assert.equal(qualityThreshold(completeness.definition),3000);assert.equal(qualityThreshold(reference.definition),2500);
 assert.equal(qualityThresholdKey('completeness'),'maximumNull');assert.equal(qualityThresholdKey('reference-allowed-values'),'maximumInvalid');
 assert.equal(qualityEvidenceMatches(run,completeness),false);assert.equal(qualityEvidenceMatches(run,reference),false);
});
test('uniqueness copy explains all repeated rows, null exclusion and logical byte limits in both locales',()=>{
 assert.deepEqual(Object.keys(qualityCopy.en).sort(),Object.keys(qualityCopy.ar).sort());
 for(const copy of Object.values(qualityCopy))for(const key of ['uniqueness','maximumDuplicate','uniquenessThresholdHint','uniquenessComparison','distinctValues','duplicateGroups','duplicateRows','duplicatePercentage','totalValueBytes','largestValueBytes','logicalBytesHint','uniquenessFormula'] as const)assert.ok(copy[key].trim());
 assert.match(qualityCopy.en.uniquenessFormula,/Every occurrence counts/);assert.match(qualityCopy.en.logicalBytesHint,/not physical disk or network I\/O/);
});
