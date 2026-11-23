// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import {fixture} from '../fixtures/relation-candidate.ts';
test('candidate upgrade baseline retains a real approved glossary link with canonical history and exact replay',async t=>{
 const f=await fixture(t),r=await f.relation(),target=await f.makeTerm(),request=await f.ready(f.input({publication:f.publication({links:[f.link(r,target)]})})),result=await f.publish(request);
 assert.equal(result.status,'succeeded');const before=await f.state();assert.equal(before.edges.length,1);assert.equal(before.publications.length,2);assert.ok(before.audit.length>0&&before.outbox.length>0);assert.deepEqual(await f.publish(request),result);assert.deepEqual(await f.state(),before);
});
