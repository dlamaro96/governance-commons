// SPDX-License-Identifier: Apache-2.0
// The isolated harness authenticates this private marker before applying SQL036.
import assert from 'node:assert/strict';
import test from 'node:test';
import {fixture} from '../fixtures/authority-foundation.ts';
import {seedLegacyScopeHistory} from '../fixtures/authority-scope-legacy.ts';

test('SQL035 explicitly revokes and preserves nine canonical legacy scope heads before installation',async t=>{
 const f=await fixture(t),marker=await seedLegacyScopeHistory(f);
 assert.equal(marker.grants.length,9);
 assert.equal(marker.grants.filter(g=>g.mustRefuse).length,7);
 t.diagnostic('GC_SCOPE_LEGACY_V1='+JSON.stringify(marker));
});
