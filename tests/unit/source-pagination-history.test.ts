// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {sourcePageHistory} from '../../apps/web/src/pages/source-pagination-history.ts';

test('source page predecessors follow the current URL after browser Back and Forward',()=>{
 const history=sourcePageHistory();
 history.remember('warehouse','','page2');
 history.remember('warehouse','page2','page3');
 // Browser Back selects page2 without another pagination-button invocation.
 assert.equal(history.previous('warehouse','page2'),'');
 assert.equal(history.previous('warehouse','page3'),'page2');
 // Previous must not consume entries needed by subsequent browser Forward.
 assert.equal(history.previous('warehouse','page2'),'');
 assert.equal(history.previous('warehouse','page3'),'page2');
});
test('source page history isolates searches and safely restarts unknown deep links',()=>{
 const history=sourcePageHistory();
 history.remember('first','','shared');
 history.remember('second','earlier','shared');
 assert.equal(history.previous('first','shared'),'');
 assert.equal(history.previous('second','shared'),'earlier');
 assert.equal(history.previous('unknown','shared'),'');
 assert.equal(history.previous('second','unknown'),'');
 history.remember('a:b','colon-query','c');
 history.remember('a','colon-cursor','b:c');
 assert.equal(history.previous('a:b','c'),'colon-query');
 assert.equal(history.previous('a','b:c'),'colon-cursor');
});
test('source page history bounds retained predecessors and falls back to the first page after eviction',()=>{
 const history=sourcePageHistory();
 for(let i=0;i<128;i++)history.remember('warehouse',`before${i}`,`page${i}`);
 history.remember('warehouse','refreshed','page0');
 history.remember('warehouse','before128','page128');
 assert.equal(history.previous('warehouse','page1'),'');
 assert.equal(history.previous('warehouse','page0'),'refreshed');
 assert.equal(history.previous('warehouse','page127'),'before127');
 assert.equal(history.previous('warehouse','page128'),'before128');
});
