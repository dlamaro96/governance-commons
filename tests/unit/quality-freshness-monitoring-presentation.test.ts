// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import type {MonitorObservation,MonitorRunEvidence} from '../../packages/domain/src/quality-monitoring-contracts.ts';
import {observationLabel,observationTone,retainedPassIsNotCurrent} from '../../apps/web/src/quality/monitoring/presentation.ts';
const evidence:MonitorRunEvidence={occurrenceId:'10000000-0000-4000-8000-000000000001',ordinal:2,runId:'20000000-0000-4000-8000-000000000002',runVersion:3,completionHash:'a'.repeat(64),comparisonScopeHash:'b'.repeat(64),observedFinishedAt:'2026-11-17T00:00:00.000Z'};
test('server STALE remains unknown while immutable prior PASS is explained separately',()=>{
 const currentObservation:MonitorObservation={state:'unknown',reason:'STALE',occurrenceId:evidence.occurrenceId},m={currentObservation,lastConclusive:{verdict:'PASS' as const,evidence}},before=structuredClone(m);
 assert.equal(observationLabel(m.currentObservation),'STALE');assert.equal(observationTone(m.currentObservation),'unknown');assert.equal(retainedPassIsNotCurrent(m),true);assert.deepEqual(m,before);
});
test('pending blocked skipped and failed observations never inherit a previous PASS tone',()=>{
 const observations:MonitorObservation[]=[{state:'pending',occurrenceId:evidence.occurrenceId,runId:evidence.runId},...(['BLOCKED','SKIPPED','NO_DATA','EXECUTION_FAILED','CANCELLED'] as const).map(reason=>({state:'unknown' as const,reason,occurrenceId:evidence.occurrenceId})),{state:'conclusive',verdict:'FAIL',evidence}];
 for(const currentObservation of observations){assert.equal(retainedPassIsNotCurrent({currentObservation,lastConclusive:{verdict:'PASS',evidence}}),true);assert.notEqual(observationTone(currentObservation),'verified');}
});
test('display follows server eligibility without local wall-clock authority',()=>{
 for(const observedFinishedAt of ['2001-01-01T00:00:00.000Z','9999-12-31T23:59:59.999Z']){
  const retained={...evidence,observedFinishedAt},currentObservation:MonitorObservation={state:'conclusive',verdict:'PASS',evidence:retained};assert.equal(retainedPassIsNotCurrent({currentObservation,lastConclusive:{verdict:'PASS',evidence:retained}}),false);assert.equal(observationTone(currentObservation),'verified');
 }
 assert.equal(retainedPassIsNotCurrent({currentObservation:{state:'unobserved'},lastConclusive:null}),false);
});
