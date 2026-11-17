// SPDX-License-Identifier: Apache-2.0
/** Real disposable PostgreSQL checks; never infer API/browser or source execution. */
import assert from 'node:assert/strict';
import test from 'node:test';
import {randomUUID} from 'node:crypto';
import {Problem} from '../../packages/authz/src/index.ts';
import {previewReferenceImport} from '../../packages/domain/src/reference-import-service.ts';
import {getReferenceRelease} from '../../packages/domain/src/reference-data-service.ts';
import {fixture,labels} from '../fixtures/reference-quality.ts';
import type {ReferenceValue} from '../../packages/domain/src/reference-data-contracts.ts';
import type {ImportPreview,ImportReady} from '../../packages/domain/src/reference-import-contracts.ts';
const raw=(values:readonly ReferenceValue[])=>Buffer.from(JSON.stringify({formatVersion:1,kind:'reference-code-rows',values}));
function ready(value:ImportPreview):asserts value is ImportReady{assert.equal(value.state,'ready');}
const problem=(code:string)=>(e:unknown)=>e instanceof Problem&&e.code===code;

test('import preview retains exact case and leading zeros and creates no durable effects',async t=>{
 const f=await fixture(t),base={setId:randomUUID(),expectedVersion:0,publicationHash:null};
 const rows=f.release(['001','1','A','a']).values,before=await f.state();
 const result=await f.as(tx=>previewReferenceImport(tx,f.principal(),base,'json','replace',raw(rows)));ready(result);
 assert.deepEqual(result.values.map(v=>v.code),['001','1','A','a']);assert.deepEqual(result.counts,{added:4,changed:0,removed:0,unchanged:0});assert.deepEqual(await f.state(),before);
});

test('import merge and replacement expose validity and removal changes without rewriting history',async t=>{
 const f=await fixture(t),published=await f.publishReference(),id=published.proposal.setId;
 const old=await f.as(tx=>getReferenceRelease(tx,f.principal(),id,1)),base={setId:id,expectedVersion:1,publicationHash:old.publicationHash};
 const modified={...old.release.values[0],validUntil:'2099-01-01T00:00:00.000Z',labels:labels('Changed validity')};
 const merge=await f.as(tx=>previewReferenceImport(tx,f.principal(),base,'json','merge',raw([modified])));ready(merge);
 assert.deepEqual(merge.counts,{added:0,changed:1,removed:0,unchanged:1});assert.ok(merge.changes.find(c=>c.kind==='changed')!.changedFields.includes('validUntil'));
 const replace=await f.as(tx=>previewReferenceImport(tx,f.principal(),base,'json','replace',raw([modified])));ready(replace);
 assert.equal(replace.counts.removed,1);assert.ok(replace.changes.some(c=>c.kind==='removed'&&c.before!==null&&c.after===null));
 const next=f.proposal({setId:id,expectedVersion:1,release:{...published.proposal.release,values:replace.values}});await f.publishReference(next);
 const current=await f.as(tx=>getReferenceRelease(tx,f.principal(),id,2));assert.deepEqual(current.release.values,replace.values);
 assert.deepEqual(await f.as(tx=>getReferenceRelease(tx,f.principal(),id,1)),old);
});

test('import duplicates return closed diagnostics and do not partially accept values',async t=>{
 const f=await fixture(t),rows=f.release(['A','A']).values,before=await f.state();
 const result=await f.as(tx=>previewReferenceImport(tx,f.principal(),{setId:randomUUID(),expectedVersion:0,publicationHash:null},'json','replace',raw(rows)));
 assert.equal(result.state,'invalid');if(result.state!=='invalid')throw Error('Expected invalid import');
 assert.ok(result.issues.some(i=>i.code==='DUPLICATE'&&i.row===2&&i.relatedRow===1));assert.equal(Object.hasOwn(result,'values'),false);assert.deepEqual(await f.state(),before);
});

test('import refuses revoked writers and foreign or hidden current baselines before returning counts',async t=>{
 const f=await fixture(t),p=f.proposal({audience:{visibility:'restricted',allowedIdentityIds:[f.actor,f.reviewer].sort()}});await f.publishReference(p);
 const view=await f.as(tx=>getReferenceRelease(tx,f.principal(),p.setId,1)),base={setId:p.setId,expectedVersion:1,publicationHash:view.publicationHash},bytes=raw(p.release.values);
 await assert.rejects(f.as(tx=>previewReferenceImport(tx,f.principal(f.reader),base,'json','replace',bytes),f.reader),problem('FORBIDDEN'));
 await assert.rejects(f.as(tx=>previewReferenceImport(tx,f.principal(f.ruleOwner),base,'json','replace',bytes),f.ruleOwner),problem('REFERENCE_UNAVAILABLE'));
 await assert.rejects(f.as(tx=>previewReferenceImport(tx,f.principal(f.outsider,f.foreign),base,'json','replace',bytes),f.outsider,f.foreign),problem('REFERENCE_UNAVAILABLE'));
 const stalePrincipal=f.principal(),before=await f.state();
 await f.revoke(f.actor,stalePrincipal.permissions.filter(permission=>permission!=='reference:write'));
 await assert.rejects(f.as(tx=>previewReferenceImport(tx,stalePrincipal,base,'json','replace',bytes)),problem('FORBIDDEN'));
 assert.deepEqual(await f.state(),before,'Current write revocation overrides stale caller grants without durable preview effects');
});

test('import rejects stale version/hash and inactive or foreign owners without preview effects',async t=>{
 const f=await fixture(t),published=await f.publishReference(),id=published.proposal.setId;
 const view=await f.as(tx=>getReferenceRelease(tx,f.principal(),id,1)),base={setId:id,expectedVersion:1,publicationHash:view.publicationHash},before=await f.state();
 await assert.rejects(f.as(tx=>previewReferenceImport(tx,f.principal(),{...base,publicationHash:'0'.repeat(64)},'json','replace',raw(view.release.values))),problem('REFERENCE_IMPORT_STALE'));
 await f.ownerTx(()=>f.owner.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.reader]));
 for(const ownerId of [f.reader,f.outsider,randomUUID()])await assert.rejects(f.as(tx=>previewReferenceImport(tx,f.principal(),base,'json','replace',raw([{...view.release.values[0],ownerId}]))),problem('REFERENCE_IMPORT_OWNER_UNAVAILABLE'));
 assert.deepEqual(await f.state(),before);
 await f.publishReference(f.proposal({setId:id,expectedVersion:1}));
 await assert.rejects(f.as(tx=>previewReferenceImport(tx,f.principal(),base,'json','merge',raw(view.release.values))),problem('REFERENCE_IMPORT_STALE'));
});
