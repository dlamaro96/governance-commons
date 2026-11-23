// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import test from 'node:test';
import type {ApprovalDefinition} from '../../packages/domain/src/approval-contracts.ts';
import {pinOf,proposalExpiry,reviewAssignments,reviewerKeys} from '../../apps/web/src/classification/presentation.ts';

const workflow:ApprovalDefinition={formatVersion:1,id:'classification_review',version:2,name:'Independent sensitivity review',separationOfDuties:true,stages:[
 {id:'privacy',name:'Privacy',assignments:['steward','owner'],quorum:2,deadlineSeconds:3600,rejection:'any'},
 {id:'final',name:'Final',assignments:['owner','custodian'],quorum:2,deadlineSeconds:7200,rejection:'any'},
]};
test('classification review binds every unique workflow assignment without conflating stage IDs or roles',()=>{
 assert.deepEqual(reviewerKeys(workflow),['steward','owner','custodian']);
 assert.deepEqual(reviewAssignments(workflow,{custodian:'c',owner:'b',steward:'a'},['a','b','c'],'requester'),{steward:'a',owner:'b',custodian:'c'});
 assert.equal(reviewAssignments(workflow,{steward:'a',owner:'b'},['a','b','c'],'requester'),null);
 assert.equal(reviewAssignments(workflow,{steward:'a',owner:'b',custodian:'c',extra:'d'},['a','b','c','d'],'requester'),null);
});
test('review setup rejects self-review, cross-stage duplicates, inactive identities and workflows without separation',()=>{
 for(const values of [{steward:'requester',owner:'b',custodian:'c'},{steward:'a',owner:'b',custodian:'a'},{steward:'a',owner:'b',custodian:'inactive'}])
  assert.equal(reviewAssignments(workflow,values,['requester','a','b','c'],'requester'),null);
 assert.equal(reviewAssignments({...workflow,separationOfDuties:false},{steward:'a',owner:'b',custodian:'c'},['a','b','c'],'requester'),null);
 const inherited=Object.assign(Object.create({steward:'a'}),{owner:'b',custodian:'c',unrelated:'a'});
 assert.equal(reviewAssignments(workflow,inherited,['a','b','c'],'requester'),null);
});
test('published pin copies only immutable identity and does not borrow mutable current-version metadata',()=>{
 const value={id:'tax',version:2,definitionHash:'a'.repeat(64),currentVersion:9,definition:{name:'later'}};
 assert.deepEqual(pinOf(value),{id:'tax',version:2,definitionHash:'a'.repeat(64)});
});
test('proposal expiry rejects malformed, impossible, expired and excessive local dates',()=>{
 const local=(value:string)=>new Date(value).getTime(),now=local('2026-06-01T10:00');
 assert.equal(proposalExpiry('2026-06-02T10:30',now),new Date('2026-06-02T10:30').toISOString());
 for(const value of ['','tomorrow','2026-06-01','2026-06-01T10:00','2026-02-30T12:00','2026-06-01T25:00','2028-06-01T10:00','2026-06-02T10:30Z'])
  assert.equal(proposalExpiry(value,now),null);
});
