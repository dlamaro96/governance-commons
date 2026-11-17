// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {monitoringFailure} from '../../packages/domain/src/quality-monitoring-service.ts';
test('freshness unsupported scheduling has a finite redacted error without widening database error exposure',()=>{
 const refusal=monitoringFailure({code:'0A000',message:'MONITOR_RULE_UNSUPPORTED',detail:'private source'});
 assert.equal(refusal.status,422);assert.equal(refusal.code,'MONITOR_RULE_UNSUPPORTED');assert.equal(refusal.message.includes('private'),false);
 for(const raw of [{code:'0A000',message:'private source'},{code:'XX000',message:'MONITOR_RULE_UNSUPPORTED'},{code:'0A000',message:'MONITOR_RULE_UNSUPPORTED private source'}]){
  const e=monitoringFailure(raw);assert.equal(e.status,500);assert.equal(e.code,'MONITOR_STORAGE_INVALID');assert.equal(e.message.includes('private'),false);
 }
});
