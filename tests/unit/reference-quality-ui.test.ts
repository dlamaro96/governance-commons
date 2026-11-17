// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {qualityEvidenceMatches,referenceTimeInput,percentageToBasisPoints} from '../../apps/web/src/quality/presentation.ts';
import type {QualityRuleView,QualityRunView,ReferenceAllowedValuesRuleDefinition} from '../../packages/domain/src/quality-contracts.ts';
const now=Date.parse('2026-11-17T12:30:00.000Z');
test('reference input preserves omission and explicit UTC milliseconds without local reinterpretation',()=>{
 assert.equal(referenceTimeInput('',now),'');assert.equal(referenceTimeInput('2026-11-17T12:30:00.000Z',now),'2026-11-17T12:30:00.000Z');
 assert.equal(referenceTimeInput('2024-02-29T12:30:00.001Z',now),'2024-02-29T12:30:00.001Z');
});
test('reference input rejects rollover, offsets, padding, missing milliseconds and future instants',()=>{
 for(const value of ['2025-02-29T00:00:00.000Z','2026-11-31T00:00:00.000Z','2026-11-17T24:00:00.000Z','2026-11-17T12:30:00Z','2026-11-17T12:30:00.000+00:00','2026-11-17T12:30:00.001Z','0000-01-01T00:00:00.000Z',' 2026-11-17T12:30:00.000Z',' '])assert.equal(referenceTimeInput(value,now),null,value);
});
test('threshold editor preserves the exact 2499/2500 boundary in English and Arabic',()=>{
 assert.equal(percentageToBasisPoints('24.99'),2499);assert.equal(percentageToBasisPoints('25'),2500);assert.equal(percentageToBasisPoints('٢٤٫٩٩'),2499);assert.equal(percentageToBasisPoints('٢٥٫٠٠'),2500);assert.equal(percentageToBasisPoints('24.999'),null);
});
const rule:QualityRuleView & {definition:ReferenceAllowedValuesRuleDefinition}={id:'rule',version:1,currentVersion:null,definitionHash:'a'.repeat(64),createdAt:'2026-11-17T00:00:00.000Z',createdBy:'actor',definition:{formatVersion:1,kind:'reference-allowed-values',name:'Reference',purpose:'Test',ownerId:'actor',severity:'warning',target:{columnAssetId:'column',tableAssetId:'table'},maximumInvalidBasisPoints:2500,reference:{setId:'set',selection:'effective-at-run',codeStatus:'active'},comparison:'utf8-exact',nullPolicy:'exclude'}};
const run:QualityRunView={kind:'reference-allowed-values',id:'run',ruleId:'rule',ruleVersion:1,ruleHash:'a'.repeat(64),requesterId:'actor',columnAssetId:'column',tableAssetId:'table',status:'succeeded',version:3,attempt:1,createdAt:'2026-11-17T00:00:00.000Z',startedAt:null,finishedAt:null,expiresAt:'2026-11-18T00:00:00.000Z',errorCode:null,verdict:'PASS',reference:{setId:'set',version:1,publicationHash:'b'.repeat(64),asOf:'2026-11-17T00:00:00.000Z',codeStatus:'active',bindingHash:'c'.repeat(64)},measurement:{formatVersion:1,kind:'reference-allowed-values',strategy:'exact-bounded-role-scope',rowCount:20,nullCount:4,invalidCount:4,referenceBindingHash:'c'.repeat(64),observedStartedAt:'2026-11-17T01:00:00.000Z',observedFinishedAt:'2026-11-17T01:00:00.001Z',elapsedMs:1,sourceVersion:'18',adapterVersion:'1',queryTemplate:'postgresql-reference-allowed-values-v1',estimatedCost:1,estimatedBytes:1}};
test('immutable evidence remains usable when the latest rule head is hidden',()=>{
 assert.equal(qualityEvidenceMatches(run,rule),true);assert.equal(qualityEvidenceMatches({...run,measurement:null,verdict:null,status:'queued'},rule),true);
});
test('evidence refuses a different target, rule pin, reference set or measurement commitment',()=>{
 for(const bad of [{...run,ruleHash:'d'.repeat(64)},{...run,ruleVersion:2},{...run,columnAssetId:'other'},{...run,tableAssetId:'other'},{...run,reference:{...run.reference,setId:'other'}},{...run,measurement:{...run.measurement!,kind:'reference-allowed-values' as const,invalidCount:4,referenceBindingHash:'d'.repeat(64),queryTemplate:'postgresql-reference-allowed-values-v1' as const}}])assert.equal(qualityEvidenceMatches(bad,rule),false);
 const completeness:QualityRuleView={...rule,definition:{formatVersion:1,kind:'completeness',target:rule.definition.target,name:'Completeness',purpose:'Test',ownerId:'actor',severity:'warning',maximumNullBasisPoints:2500}};
 assert.equal(qualityEvidenceMatches(run,completeness),false);
});
