// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {Problem} from '../../packages/authz/src/index.ts';
import {parseComparisonScope,comparisonScopeHash,monitorFreshnessTimeDecision} from '../../packages/domain/src/quality-monitoring.ts';
const base={"formatVersion":1,"monitorId":"10000000-0000-4000-8000-000000000005","executorId":"10000000-0000-4000-8000-000000000002","rule":{"id":"10000000-0000-4000-8000-000000000001","version":1,"definitionHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"sourceId":"10000000-0000-4000-8000-000000000030","sourceVersion":1,"sourceConfigHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schemaAssetId":"10000000-0000-4000-8000-000000000031","tableAssetId":"10000000-0000-4000-8000-000000000032","columnAssetId":"10000000-0000-4000-8000-000000000033","targetHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
const known=[{"family":{"kind":"completeness"},"hash":"6e1a716a3c194c87354d13ca0691e48c774097d6cdf9c4c8bfb7c6fdf53cf311"},{"family":{"kind":"uniqueness","comparison":"utf8-exact","nullPolicy":"exclude"},"hash":"032b50ff020bad845030919dbb38bf4f43081d1f0de9f5bb5cc6d7fb2009fa52"},{"family":{"kind":"range","rangeHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"hash":"eb961a49043be0343090105cffce8f5c19308406ff903ac2565f87234b2edd84"},{"family":{"kind":"reference-allowed-values","setId":"10000000-0000-4000-8000-000000000040","version":1,"publicationHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","codeStatus":"active","codesHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"hash":"09a12dfc8e2b200cd50beede1407365a0052bcbccc869e1de0eaa7957a3fc54a"},{"family":{"kind":"freshness","freshnessHash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"hash":"cd323fed6f6c0555a28a62a6fabd3fc90ee81388db8f2b78ce4f60dfe678d832"}];
const vectors=[{"name":"inclusive exact remaining-age boundary","input":{"claimedAtUs":"1000000000","finishedAtUs":"1001000100","projectedAtUs":"1001000000","observedFinishedAtUs":"1001000000","evaluatedAtUs":"1030000000","measuredAgeUs":"60000000","maximumAgeSeconds":90,"recoveryMaximumAgeSeconds":60},"expected":{"valid":true,"reason":"eligible","validThroughUs":"1030000000"}},{"name":"one microsecond after boundary","input":{"claimedAtUs":"1000000000","finishedAtUs":"1001000100","projectedAtUs":"1001000000","observedFinishedAtUs":"1001000000","evaluatedAtUs":"1030000001","measuredAgeUs":"60000000","maximumAgeSeconds":90,"recoveryMaximumAgeSeconds":60},"expected":{"valid":false,"reason":"expired","validThroughUs":"1030000000"}},{"name":"negative age gets no future credit","input":{"claimedAtUs":"1000000000","finishedAtUs":"1001000100","projectedAtUs":"1001000000","observedFinishedAtUs":"1001000000","evaluatedAtUs":"1090000001","measuredAgeUs":"-10000000","maximumAgeSeconds":90,"recoveryMaximumAgeSeconds":120},"expected":{"valid":false,"reason":"expired","validThroughUs":"1090000000"}},{"name":"observation age cap can be earlier","input":{"claimedAtUs":"1000000000","finishedAtUs":"1001000100","projectedAtUs":"1001000000","observedFinishedAtUs":"1001000000","evaluatedAtUs":"1061000000","measuredAgeUs":"60000000","maximumAgeSeconds":3600,"recoveryMaximumAgeSeconds":60},"expected":{"valid":true,"reason":"eligible","validThroughUs":"1061000000"}},{"name":"observation age cap exact plus one","input":{"claimedAtUs":"1000000000","finishedAtUs":"1001000100","projectedAtUs":"1001000000","observedFinishedAtUs":"1001000000","evaluatedAtUs":"1061000001","measuredAgeUs":"60000000","maximumAgeSeconds":3600,"recoveryMaximumAgeSeconds":60},"expected":{"valid":false,"reason":"expired","validThroughUs":"1061000000"}},{"name":"zero remaining budget is already expired on successful finish","input":{"claimedAtUs":"1000000000","finishedAtUs":"1001000100","projectedAtUs":"1001000000","observedFinishedAtUs":"1001000000","evaluatedAtUs":"1001000100","measuredAgeUs":"90000000","maximumAgeSeconds":90,"recoveryMaximumAgeSeconds":60},"expected":{"valid":false,"reason":"expired","validThroughUs":"1000000000"}},{"name":"clock before successful finish","input":{"claimedAtUs":"1000000000","finishedAtUs":"1001000100","projectedAtUs":"1001000000","observedFinishedAtUs":"1001000000","evaluatedAtUs":"1001000099","measuredAgeUs":"60000000","maximumAgeSeconds":90,"recoveryMaximumAgeSeconds":60},"expected":{"valid":false,"reason":"clock-before-recorded-marker","validThroughUs":"1030000000"}},{"name":"impossible PASS age is refused","input":{"claimedAtUs":"1000000000","finishedAtUs":"1001000100","projectedAtUs":"1001000000","observedFinishedAtUs":"1001000000","evaluatedAtUs":"1030000000","measuredAgeUs":"90000001","maximumAgeSeconds":90,"recoveryMaximumAgeSeconds":60},"expected":{"valid":false,"reason":"evidence-unavailable","validThroughUs":null}},{"name":"success retry uses final claim, not first attempt","input":{"claimedAtUs":"1020000000","finishedAtUs":"1021000100","projectedAtUs":"1021000000","observedFinishedAtUs":"1021000000","evaluatedAtUs":"1050000000","measuredAgeUs":"60000000","maximumAgeSeconds":90,"recoveryMaximumAgeSeconds":60},"expected":{"valid":true,"reason":"eligible","validThroughUs":"1050000000"}},{"name":"claim beyond finish is malformed","input":{"claimedAtUs":"1001000101","finishedAtUs":"1001000100","projectedAtUs":"1001000000","observedFinishedAtUs":"1001000000","evaluatedAtUs":"1030000000","measuredAgeUs":"60000000","maximumAgeSeconds":90,"recoveryMaximumAgeSeconds":60},"expected":{"valid":false,"reason":"evidence-unavailable","validThroughUs":null}},{"name":"submillisecond projection truncation is not rollback","input":{"claimedAtUs":"1000000000","finishedAtUs":"1001000100","projectedAtUs":"1001000000","observedFinishedAtUs":"1001000000","evaluatedAtUs":"1001000100","measuredAgeUs":"60000000","maximumAgeSeconds":90,"recoveryMaximumAgeSeconds":60},"expected":{"valid":true,"reason":"eligible","validThroughUs":"1030000000"}}];
const invalid=(work:()=>unknown)=>assert.throws(work,(e:unknown)=>e instanceof Problem&&e.status===400&&e.code==='MONITOR_INPUT_INVALID');

test('all five scope families retain independent literal canonical hash vectors',()=>{
 for(const {family,hash} of known){const value={...base,family};assert.deepEqual(parseComparisonScope(value),value);assert.equal(comparisonScopeHash(value),hash);}
});
test('freshness scope pins only immutable settings and changes with source, target, owner or rule identity',()=>{
 const family={kind:'freshness',freshnessHash:'a'.repeat(64)},value={...base,family},original=comparisonScopeHash(value);
 for(const patch of [{family:{...family,freshnessHash:'b'.repeat(64)}},{sourceVersion:2},{sourceConfigHash:'b'.repeat(64)},{targetHash:'b'.repeat(64)},{executorId:'10000000-0000-4000-8000-000000000099'},{rule:{...base.rule,version:2}}])assert.notEqual(comparisonScopeHash({...value,...patch}),original);
 for(const patch of [{sourceObservedAt:'2026-01-01T00:00:00.000000Z'},{ageMicroseconds:'0'},{claimed_at:'2026-01-01T00:00:00Z'}])invalid(()=>parseComparisonScope({...value,...patch}));
 for(const patch of [{maximumAgeSeconds:60},{sourceObservedAt:'2026-01-01T00:00:00.000000Z'},{ageMicroseconds:'0'},{rangeHash:'a'.repeat(64)}])invalid(()=>parseComparisonScope({...value,family:{...family,...patch}}));
});
test('freshness scope refuses unknown families, missing hash and every older-family discriminator escape',()=>{
 for(const family of [{kind:'future'},{kind:'freshness'},{kind:'freshness',freshnessHash:'A'.repeat(64)},{kind:'freshness',freshnessHash:'a'.repeat(63)},...known.slice(0,4).map(x=>({...x.family,freshnessHash:'a'.repeat(64)}))])invalid(()=>parseComparisonScope({...base,family}));
});
test('freshness scope snapshots hostile descriptors without calling accessors or toJSON',()=>{
 let calls=0;const family=Object.defineProperty({kind:'freshness'},'freshnessHash',{enumerable:true,get(){calls++;return 'a'.repeat(64);}});
 invalid(()=>parseComparisonScope({...base,family}));assert.equal(calls,0);
 invalid(()=>parseComparisonScope({...base,family:{kind:'freshness',freshnessHash:'a'.repeat(64),toJSON(){calls++;return {};}}}));assert.equal(calls,0);
});
for(const {name,input,expected} of vectors)test('freshness time: '+name,()=>{
 const actual=monitorFreshnessTimeDecision(input),{remainingAtObservationUs:remaining,...closed}=actual;
 assert.deepEqual(closed,expected);assert.equal(remaining,expected.reason==='evidence-unavailable'?null:String(BigInt(input.maximumAgeSeconds)*1000000n-(BigInt(input.measuredAgeUs)>0n?BigInt(input.measuredAgeUs):0n)));
});
test('time oracle refuses coercion, noncanonical integers, out-of-range instants and settings',()=>{
 const input=vectors[0].input;
 for(const value of [0,-0,1.5,null,true,'-0','+1','01','1e3','1.0',' 1','1\n','253402300800000000','-62135596800000001','9'.repeat(10000)])invalid(()=>monitorFreshnessTimeDecision({...input,claimedAtUs:value}));
 for(const value of ['315537897600000000','-315537897600000000'])invalid(()=>monitorFreshnessTimeDecision({...input,measuredAgeUs:value}));
 for(const patch of [{maximumAgeSeconds:0},{maximumAgeSeconds:31536001},{maximumAgeSeconds:'90'},{recoveryMaximumAgeSeconds:59},{recoveryMaximumAgeSeconds:604801},{recoveryMaximumAgeSeconds:-0},{unknown:true}])invalid(()=>monitorFreshnessTimeDecision({...input,...patch}));
});
test('time oracle keeps microsecond precision beyond Number safe integers and year boundaries',()=>{
 const C=253402300000000000n,input={...vectors[0].input,claimedAtUs:String(C),finishedAtUs:String(C+1001n),projectedAtUs:String(C+1000n),observedFinishedAtUs:String(C+1000n),evaluatedAtUs:String(C+30000000n)};
 assert.equal(monitorFreshnessTimeDecision(input).valid,true);
 assert.equal(monitorFreshnessTimeDecision({...input,evaluatedAtUs:String(C+30000001n)}).reason,'expired');
 assert.equal(monitorFreshnessTimeDecision({...input,claimedAtUs:'253402300799999000',finishedAtUs:'253402300799999100',projectedAtUs:'253402300799999000',observedFinishedAtUs:'253402300799999000',evaluatedAtUs:'253402300799999999',measuredAgeUs:'0'}).validThroughUs,'253402300859999000');
});
test('no future credit even at maximum tolerated future age and no rounded expiry boundary',()=>{
 const input={...vectors[0].input,measuredAgeUs:'-300000000',recoveryMaximumAgeSeconds:600,evaluatedAtUs:'1090000000'};
 assert.equal(monitorFreshnessTimeDecision(input).valid,true);
 assert.equal(monitorFreshnessTimeDecision({...input,evaluatedAtUs:'1090000001'}).reason,'expired');
});
test('every recorded marker independently rejects a backwards clock without inventing marker order',()=>{
 const input=vectors[0].input;
 for(const field of ['claimedAtUs','finishedAtUs','projectedAtUs','observedFinishedAtUs'] as const){
  const changed={...input,[field]:'1030000001',...(field==='claimedAtUs'?{finishedAtUs:'1030000001'}:{})};
  assert.equal(monitorFreshnessTimeDecision(changed).reason,'clock-before-recorded-marker',field);
 }
});
test('time helper does not claim to remember an unrecorded expiry across wall-clock rewind',()=>{
 const input=vectors[0].input;
 assert.equal(monitorFreshnessTimeDecision({...input,evaluatedAtUs:'1030000001'}).valid,false);
 assert.equal(monitorFreshnessTimeDecision({...input,evaluatedAtUs:'1029000000'}).valid,true);
});
test('time parser refuses getters, aliases, cycles and mutation of returned decisions',()=>{
 let calls=0;const input=vectors[0].input,hostile=Object.defineProperty({...input},'claimedAtUs',{enumerable:true,get(){calls++;return input.claimedAtUs;}});
 invalid(()=>monitorFreshnessTimeDecision(hostile));assert.equal(calls,0);
 invalid(()=>monitorFreshnessTimeDecision({...input,toJSON(){calls++;return input;}}));assert.equal(calls,0);
 const cycle:any={...input};cycle.measuredAgeUs=cycle;invalid(()=>monitorFreshnessTimeDecision(cycle));
 const result=monitorFreshnessTimeDecision(input);result.valid=false;assert.equal(monitorFreshnessTimeDecision(input).valid,true);
});
