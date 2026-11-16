// SPDX-License-Identifier: Apache-2.0
/** Prospective native reference-quality storage/service tests; requires the
 * forward migration in a disposable DB. No source executor, HTTP, Temporal or
 * historical source-data claim. Completion measurements are explicit fixture
 * inputs; the source catalog and reference publication are real PostgreSQL. */
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import test from 'node:test';
import {sql} from '../../packages/db/src/index.ts';
import {Problem} from '../../packages/authz/src/index.ts';
import {visibleAudit} from '../../apps/api/src/repository.ts';
import {getQualityAsset,getQualityRule,getQualityRun,listQualityRuns} from '../../packages/domain/src/quality-service.ts';
import type {QualityClaim,QualityMeasurement,QualityRunView} from '../../packages/domain/src/quality-contracts.ts';
import {fixture,permissions,bindings,code,denied,sealFailure,hash,claimed,resolved,referenceRun} from '../fixtures/reference-quality.ts';
const unavailable=(e:unknown)=>e instanceof Problem&&e.status===404;

test('reference quality retains exact published pin and binding projections without codes in public run or journals',async t=>{
 const f=await fixture(t),ref=await f.publishReference(),{rule}=await f.publish(f.definition(ref.proposal.setId)),{run}=await f.request(rule);referenceRun(run);
 const c=await f.claim(run.id),b=resolved(c),{bindingHash,...preimage}=b;assert.equal(bindingHash,hash(preimage));assert.deepEqual(b.codes,['01','A']);
 assert.deepEqual(run.reference,{setId:ref.proposal.setId,version:1,publicationHash:ref.result.publicationHash,asOf:run.reference.asOf,codeStatus:'active',bindingHash});
 const publicView=await f.as(tx=>getQualityRun(tx,f.principal(),run.id));assert.deepEqual(publicView,await f.as(async tx=>(await sql<{value:any}>`select public.gc_quality_run_view(${run.id}::uuid) as value`.execute(tx)).rows[0].value));
 assert.equal(JSON.stringify(publicView).includes('"codes"'),false);assert.equal(JSON.stringify(publicView).includes('secretRef'),false);
 const state=await f.state(),rb=state.quality_rule_reference_bindings[0],qb=state.quality_run_reference_bindings[0];
 assert.deepEqual([rb.tenant_id,rb.rule_id,rb.rule_version,rb.set_id],[f.tenant,rule.id,1,ref.proposal.setId]);
 assert.deepEqual([qb.run_id,qb.release_version,qb.publication_hash,qb.as_of.toISOString(),qb.binding_hash],[run.id,1,b.publicationHash,b.asOf,bindingHash]);
 assert.equal(state.quality_runs[0].input_hash,hash(state.quality_runs[0].inputs));
 for(const row of [...state.audit.filter(r=>r.action.startsWith('quality.')),...state.outbox.filter(r=>r.event_type.startsWith('quality.'))])assert.equal(JSON.stringify(row).includes('"codes"'),false);
});

test('reference quality exact non-null denominator and versioned threshold retain older FAIL after successor PASS',async t=>{
 const f=await fixture(t),ref=await f.publishReference(),one=await f.publish(f.definition(ref.proposal.setId,2499));
 const counts=(await f.owner.query(`SELECT count(*)::integer AS rows,count(*) FILTER(WHERE code IS NULL)::integer AS nulls,count(*) FILTER(WHERE code IS NOT NULL AND code NOT IN ('01','A'))::integer AS invalid FROM "${f.namespace}".observations`)).rows[0];assert.deepEqual(counts,{rows:20,nulls:4,invalid:4});
 const run1=(await f.request(one.rule)).run,c1=await f.claim(run1.id);claimed(c1);const old=(await f.finish(run1.id,c1,await f.measurement(c1,counts.rows,counts.nulls,counts.invalid))).run;assert.equal(old.verdict,'FAIL');
 const two=await f.publish(f.definition(ref.proposal.setId,2500),one.rule.id,1),run2=(await f.request(two.rule)).run,c2=await f.claim(run2.id);claimed(c2);
 assert.equal((await f.finish(run2.id,c2,await f.measurement(c2))).run.verdict,'PASS');
 assert.deepEqual(await f.as(tx=>getQualityRun(tx,f.principal(),run1.id)),old);assert.equal((await f.state()).quality_rule_versions.length,2);
});

test('reference quality empty and all-null measurements yield NO_DATA; an empty active code vector makes non-null rows invalid',async t=>{
 const f=await fixture(t),base=f.proposal(),p={...base,release:{...base.release,values:base.release.values.map(v=>({...v,status:'deprecated' as const}))}};const ref=await f.publishReference(p),{rule}=await f.publish(f.definition(ref.proposal.setId));
 for(const [rows,nulls,invalid,verdict]of [[0,0,0,'NO_DATA'],[20,20,0,'NO_DATA'],[20,4,16,'FAIL']] as const){
  const {run}=await f.request(rule),c=await f.claim(run.id);claimed(c);assert.deepEqual(resolved(c).codes,[]);
  assert.equal((await f.finish(run.id,c,await f.measurement(c,rows,nulls,invalid))).run.verdict,verdict);
 }
});

test('reference quality selects actual historical and scheduled release boundaries with half-open active values',async t=>{
 const f=await fixture(t),first=await f.publishReference(),{rule}=await f.publish(f.definition(first.proposal.setId));
 const at=new Date(Date.parse(await f.now())+1800).toISOString(),until=new Date(Date.parse(at)+250).toISOString();
 const base=f.proposal({setId:first.proposal.setId,expectedVersion:1,release:{...f.release(['AT','BEFORE','DEPRECATED']),activation:{kind:'at',at},validUntil:until}});
 const p={...base,release:{...base.release,values:base.release.values.map(v=>({...v,validFrom:v.code==='AT'?at:null,validUntil:v.code==='BEFORE'?at:null,status:(v.code==='DEPRECATED'?'deprecated':'active') as 'deprecated'|'active'}))}};
 await f.publishReference(p);const before=(await f.request(rule,randomUUID(),first.result.effectiveFrom)).run;referenceRun(before);assert.equal(before.reference.version,1);
 await f.waitUntil(at);const current=(await f.request(rule,randomUUID(),at)).run;referenceRun(current);assert.equal(current.reference.version,2);assert.deepEqual(resolved(await f.claim(current.id)).codes,['AT']);
 await f.waitUntil(until);await f.unchanged(()=>f.request(rule,randomUUID(),until),code('0A000'));
 const future=new Date(Date.parse(await f.now())+60000).toISOString();await f.unchanged(()=>f.request(rule,randomUUID(),future),code('22023'));
});

test('reference quality omitted asOf request replay preserves original pin after release advance and rejects explicit-body substitution',async t=>{
 const f=await fixture(t),first=await f.publishReference(),{rule}=await f.publish(f.definition(first.proposal.setId)),key=randomUUID(),body=f.requestBody(rule);
 const original=await f.quality<{run:QualityRunView}>('quality.run.request',body,key);referenceRun(original.run);const retainedAsOf=original.run.reference.asOf;
 await f.waitUntil(new Date(Date.parse(original.run.reference.asOf)+2).toISOString());await f.publishReference(f.proposal({setId:first.proposal.setId,expectedVersion:1,release:f.release(['NEW'])}));
 assert.deepEqual(await f.quality('quality.run.request',body,key),original);const c=await f.claim(original.run.id);claimed(c);assert.equal(resolved(c).version,1);
 await f.unchanged(()=>f.quality('quality.run.request',{...body,referenceAsOf:retainedAsOf},key),code('40001'));
 const done=await f.finish(original.run.id,c,await f.measurement(c));assert.equal(done.run.status,'succeeded');
 assert.deepEqual(await f.quality('quality.run.request',body,key),original,'Command replay retains exact queued receipt, not a fabricated current response');
});

test('reference quality current reference read revocation denies requests and terminates outstanding claim or completion',async t=>{
 const f=await fixture(t),ref=await f.publishReference(),{rule}=await f.publish(f.definition(ref.proposal.setId));
 const queued=(await f.request(rule)).run,active=(await f.request(rule)).run,c=await f.claim(active.id);claimed(c);const m=await f.measurement(c);
 await f.revoke(f.actor,permissions.filter(x=>x!=='reference:read'));
 await f.unchanged(()=>f.request(rule),denied);const rejected=await f.claim(queued.id);assert.equal(rejected.status,'terminal');if(rejected.status==='terminal'){assert.equal(rejected.run.errorCode,'QUALITY_AUTHORITY_REVOKED');assert.equal(rejected.run.measurement,null);}
 const finished=await f.finish(active.id,c,m);assert.equal(finished.run.status,'cancelled');assert.equal(finished.run.errorCode,'QUALITY_AUTHORITY_REVOKED');assert.equal(finished.run.measurement,null);
 await assert.rejects(()=>f.as(tx=>getQualityRun(tx,f.principal(),active.id)),unavailable);
});

test('reference quality current rule owner revocation prevents request and cancels claim or finish',async t=>{
 const f=await fixture(t),ref=await f.publishReference(),{rule}=await f.publish(f.definition(ref.proposal.setId)),queued=(await f.request(rule)).run,running=(await f.request(rule)).run,c=await f.claim(running.id);claimed(c);
 await f.ownerTx(()=>f.owner.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.ruleOwner]));
 await f.unchanged(()=>f.request(rule),denied);const terminal=await f.claim(queued.id);assert.equal(terminal.status,'terminal');if(terminal.status==='terminal')assert.equal(terminal.run.errorCode,'QUALITY_AUTHORITY_REVOKED');
 assert.equal((await f.finish(running.id,c,await f.measurement(c))).run.errorCode,'QUALITY_AUTHORITY_REVOKED');
});

test('reference quality selected-version reads and run pagination authorize retained bindings rather than a visible successor head',async t=>{
 const f=await fixture(t),hidden=await f.publishReference(f.proposal({audience:{visibility:'restricted',allowedIdentityIds:[f.actor,f.reviewer,f.ruleOwner].sort()}})),open=await f.publishReference();
 const ids=['00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000002','ffffffff-ffff-4fff-8fff-ffffffffffff'];
 const first=await f.publish(f.definition(hidden.proposal.setId)),old=(await f.request(first.rule,ids[0])).run;await f.request(first.rule,ids[1]);
 const second=await f.publish(f.definition(open.proposal.setId),first.rule.id,1),visible=(await f.request(second.rule,ids[2])).run;
 await assert.rejects(()=>f.as(tx=>getQualityRule(tx,f.principal(f.reader),first.rule.id,1),f.reader),unavailable);
 await assert.rejects(()=>f.as(tx=>getQualityRun(tx,f.principal(f.reader),old.id),f.reader),unavailable);
 const page=await f.as(tx=>listQualityRuns(tx,f.principal(f.reader),first.rule.id,{limit:1}),f.reader);assert.deepEqual(page.items.map(v=>v.id),[visible.id]);assert.equal(page.nextCursor,null);
 const audit=await f.as(tx=>visibleAudit(tx,f.principal(f.reader)).where('action','like','quality.%').execute(),f.reader);
 assert.equal(audit.some(row=>(row.changes as any).runId===old.id),false);assert.equal(audit.some(row=>row.action==='quality.rule_published'&&(row.changes as any).resourceVersion===1),false);assert.equal(audit.some(row=>(row.changes as any).runId===visible.id),true);
 const third=await f.publish(f.definition(hidden.proposal.setId),first.rule.id,2);assert.equal(third.rule.version,3);
 const historical=await f.as(tx=>getQualityRule(tx,f.principal(f.reader),first.rule.id,2),f.reader);assert.equal(historical.currentVersion,null);
 assert.equal((await f.as(tx=>getQualityAsset(tx,f.principal(f.reader),f.columnId,{limit:1}),f.reader)).items.length,0);
 assert.deepEqual((await f.as(tx=>listQualityRuns(tx,f.principal(f.reader),first.rule.id,{limit:1}),f.reader)).items.map(v=>v.id),[visible.id]);
});

test('reference quality hidden retained receipts cannot be authorized by a visible replacement rule or target',async t=>{
 const f=await fixture(t),ref=await f.publishReference(),definition=f.definition(ref.proposal.setId),key=randomUUID(),id=randomUUID();
 const published=await f.publish(definition,id,0,key),runKey=randomUUID(),body=f.requestBody(published.rule),original=await f.quality('quality.run.request',body,runKey);
 const replacement=await f.publish({...definition,kind:'completeness',maximumNullBasisPoints:0,reference:undefined,comparison:undefined,nullPolicy:undefined,maximumInvalidBasisPoints:undefined} as any,id,1);
 assert.equal(replacement.rule.version,2);await f.revoke(f.actor,permissions.filter(x=>x!=='reference:read'));
 await f.unchanged(()=>f.publish(definition,id,0,key),denied);await f.unchanged(()=>f.quality('quality.run.request',body,runKey),denied);
 await f.unchanged(()=>f.quality('quality.run.request',{...body,ruleVersion:2,ruleHash:replacement.rule.definitionHash},runKey),e=>denied(e)||code('40001')(e));
 await assert.rejects(()=>f.as(tx=>getQualityRun(tx,f.principal(),original.run.id)),unavailable);
});

test('reference quality foreign tenants and target-parent ACL changes cannot disclose or execute a retained run',async t=>{
 const f=await fixture(t),ref=await f.publishReference(),{rule}=await f.publish(f.definition(ref.proposal.setId)),{run}=await f.request(rule);
 await assert.rejects(()=>f.as(tx=>getQualityRule(tx,f.principal(f.outsider,f.foreign),rule.id,1),f.outsider,f.foreign),unavailable);
 await assert.rejects(()=>f.as(tx=>getQualityRun(tx,f.principal(f.outsider,f.foreign),run.id),f.outsider,f.foreign),unavailable);
 await f.ownerTx(()=>f.owner.query("UPDATE assets SET visibility='restricted',allowed_identities=$3::jsonb WHERE tenant_id=$1 AND id=$2",[f.tenant,f.schemaId,JSON.stringify([f.reviewer])]));
 const c=await f.claim(run.id);assert.equal(c.status,'terminal');if(c.status==='terminal')assert.equal(c.run.errorCode,'QUALITY_AUTHORITY_REVOKED');
 await assert.rejects(()=>f.as(tx=>getQualityRule(tx,f.principal(),rule.id,1)),unavailable);
});

test('reference quality completion validates exact binding hash, count equations and family before any journal',async t=>{
 const f=await fixture(t),ref=await f.publishReference(),{rule}=await f.publish(f.definition(ref.proposal.setId)),{run}=await f.request(rule),c=await f.claim(run.id);claimed(c);const m=await f.measurement(c);
 for(const bad of [{...m,referenceBindingHash:'0'.repeat(64)},{...m,invalidCount:17},{...m,rowCount:100001},{...m,invalidCount:-1},{...m,extra:true},{...m,queryTemplate:'postgresql-completeness-v1'}])await f.unchanged(()=>f.finish(run.id,c,bad as QualityMeasurement),code('22023'));
 const result=await f.finish(run.id,c,m),before=await f.state();assert.deepEqual(await f.finish(run.id,c,m),result);assert.deepEqual(await f.state(),before);
 await f.unchanged(()=>f.finish(run.id,c,{...m,invalidCount:3} as QualityMeasurement),code('40001'));
});

test('reference quality wrong claim and cancellation fence late completion without inventing source success',async t=>{
 const f=await fixture(t),ref=await f.publishReference(),{rule}=await f.publish(f.definition(ref.proposal.setId)),{run}=await f.request(rule),c=await f.claim(run.id);claimed(c);
 const m=await f.measurement(c);assert.equal((await f.claim(run.id,randomUUID())).status,'busy');
 await f.unchanged(()=>f.finish(run.id,{...c,claimId:randomUUID()},m),code('40001'));
 const current=await f.as(tx=>getQualityRun(tx,f.principal(),run.id));const cancelled=await f.quality('quality.run.cancel',{runId:run.id,expectedVersion:current.version,reason:'Cancel the owned native test'});
 assert.equal(cancelled.run.status,'cancelled');assert.equal(cancelled.run.measurement,null);await f.unchanged(()=>f.finish(run.id,c,m),code('40001'));
});

test('reference quality locks the complete sorted owner and requester set before target rows on request claim and finish',async t=>{
 const f=await fixture(t),ref=await f.publishReference(),{rule}=await f.publish(f.definition(ref.proposal.setId));assert.ok(f.ruleOwner<f.actor);
 const probe=await f.connection();const pid=(await f.as(tx=>sql<{pid:number}>`select pg_backend_pid() as pid`.execute(tx))).rows[0].pid;
 async function blockedOwner<T>(operation:()=>Promise<T>):Promise<T>{
  await f.owner.query('BEGIN');await f.owner.query('SELECT id FROM identities WHERE id=$1 FOR UPDATE',[f.ruleOwner]);
  const work=operation();let value:T|undefined,error:unknown;const observed=work.then(v=>{value=v},e=>{error=e});
  try{
   let waiting=false;const until=performance.now()+1500;while(performance.now()<until){const row=(await f.owner.query('SELECT pg_backend_pid()=ANY(pg_blocking_pids($1)) AS blocked',[pid])).rows[0];if(row.blocked){waiting=true;break;}await new Promise(r=>setTimeout(r,10));}
   assert.equal(waiting,true,'Actual runtime request must be blocked by the distinct owner identity lock');
   await probe.query('BEGIN');try{await probe.query('SELECT id FROM identities WHERE id=$1 FOR UPDATE NOWAIT',[f.actor]);await probe.query('SELECT id FROM public.assets WHERE tenant_id=$1 AND id=$2 FOR UPDATE NOWAIT',[f.tenant,f.columnId]);}finally{await probe.query('ROLLBACK');}
  }finally{await f.owner.query('ROLLBACK');await observed;}
  if(error)throw error;assert.ok(value);return value;
 }
 const queued=await blockedOwner(()=>f.request(rule)),c=await blockedOwner(()=>f.claim(queued.run.id));claimed(c);
 assert.equal((await blockedOwner(async()=>f.finish(queued.run.id,c,await f.measurement(c)))).run.status,'succeeded');
});

test('reference quality binding tables force tenant isolation and refuse runtime writes or late owner projection inserts',async t=>{
 const f=await fixture(t),ref=await f.publishReference(),{rule}=await f.publish(f.definition(ref.proposal.setId));await f.request(rule);
 const rows=(await f.owner.query("SELECT relname,relrowsecurity,relforcerowsecurity,has_table_privilege('gc_app',oid,'SELECT') AS read,has_table_privilege('gc_app',oid,'INSERT,UPDATE,DELETE,TRUNCATE') AS write FROM pg_class WHERE oid=ANY($1::regclass[]) ORDER BY relname",[bindings.map(n=>'public.'+n)])).rows;
 assert.equal(rows.length,2);for(const row of rows)assert.deepEqual([row.relrowsecurity,row.relforcerowsecurity,row.read,row.write],[true,true,true,false]);
 for(const table of bindings){assert.equal((await f.as(tx=>sql`select * from ${sql.table(table)}`.execute(tx),f.outsider,f.foreign)).rows.length,0);
  await f.unchanged(()=>f.as(tx=>sql`delete from ${sql.table(table)} where tenant_id=${f.tenant}::uuid`.execute(tx)),code('42501'));
  await f.unchanged(()=>f.ownerTx(()=>f.owner.query('UPDATE public."'+table+'" SET created_xid=created_xid WHERE tenant_id=$1',[f.tenant])),code('P0001'));
 }
 await f.unchanged(()=>f.ownerTx(()=>f.owner.query('INSERT INTO quality_run_reference_bindings SELECT tenant_id,$2::uuid,set_id,release_version,publication_hash,as_of,code_status,binding_hash,pg_current_xact_id() FROM quality_run_reference_bindings WHERE tenant_id=$1',[f.tenant,randomUUID()])),sealFailure);
});

test('reference quality deferred projection checks reject missing run binding after an early flush and preserve atomic journals',async t=>{
 const f=await fixture(t),ref=await f.publishReference(),{rule}=await f.publish(f.definition(ref.proposal.setId));let created=false,flushed=false,restored=false;
 const before=await f.state();await assert.rejects(()=>f.ownerTx(async()=>{
  const body=f.requestBody(rule),createdRun=(await f.owner.query("SELECT public.gc_quality_command('quality.run.request',$1,$2::jsonb,'reference-quality-native') AS value",[randomUUID(),JSON.stringify(body)])).rows[0].value.run;created=true;
  await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');flushed=true;await f.owner.query('SET CONSTRAINTS ALL DEFERRED');
  // Explicit hostile native-owner fixture mutation. Restore every user trigger
  // before invoking protected code; the outer transaction always rolls back.
  await f.owner.query('ALTER TABLE public.quality_run_reference_bindings DISABLE TRIGGER USER');
  await f.owner.query('DELETE FROM public.quality_run_reference_bindings WHERE tenant_id=$1 AND run_id=$2',[f.tenant,createdRun.id]);
  await f.owner.query('ALTER TABLE public.quality_run_reference_bindings ENABLE TRIGGER USER');restored=true;
  // A new protected status transition must reschedule the cross-table proof.
  await f.owner.query("SELECT set_config('gc.actor_id','site:local',true)");
  await f.owner.query('SELECT public.gc_quality_claim($1,$2)',[createdRun.id,randomUUID()]);
  await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');
 }),sealFailure);assert.equal(created,true);assert.equal(flushed,true);assert.equal(restored,true);assert.deepEqual(await f.state(),before);
});

test('reference quality maximum legal code vector exceeds old16KiB intact while public run remains bounded metadata',async t=>{
 const f=await fixture(t),codes=Array.from({length:256},(_,i)=>'C'+String(i).padStart(3,'0')+'x'.repeat(124));assert.ok(codes.every(x=>x.length===128));
 const ref=await f.publishReference(f.proposal({release:f.release(codes)})),{rule}=await f.publish(f.definition(ref.proposal.setId)),{run}=await f.request(rule),c=await f.claim(run.id);const b=resolved(c);
 assert.deepEqual(b.codes,codes);assert.ok(Buffer.byteLength(JSON.stringify(c))>16384);assert.ok(Buffer.byteLength(JSON.stringify(c))<=65536);referenceRun(run);assert.ok(Buffer.byteLength(JSON.stringify(run))<4096);
 const stored=(await f.state()).quality_runs[0];assert.deepEqual(stored.inputs.execution.reference,b);assert.equal(stored.input_hash,hash(stored.inputs));
});

test('reference quality retained release is not reselected after an owner-fixture same-millisecond head collision',async t=>{
 const f=await fixture(t),first=await f.publishReference();await f.waitUntil(new Date(Date.parse(first.result.effectiveFrom)+3).toISOString());const {rule}=await f.publish(f.definition(first.proposal.setId)),{run}=await f.request(rule);referenceRun(run);
 const second=await f.publishReference(f.proposal({setId:first.proposal.setId,expectedVersion:1,release:f.release(['NEW'])}));
 const before=await f.state();let observed=false,restored=false;
 await f.owner.query('BEGIN');try{
  await f.owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[f.tenant,f.actor]);
  const row=(await f.owner.query('SELECT published_bundle FROM reference_releases WHERE tenant_id=$1 AND set_id=$2 AND version=2',[f.tenant,first.proposal.setId])).rows[0];
  const bundle={...row.published_bundle,publishedAt:run.reference.asOf,effectiveFrom:run.reference.asOf};
  // Explicit owner-only timestamp-collision fixture, not a production-clock or
  // publication-authority test. Published values are unchanged. The complete
  // transaction is always rolled back; no altered predecessor state survives.
  await f.owner.query('ALTER TABLE public.reference_releases DISABLE TRIGGER USER');
  await f.owner.query('UPDATE reference_releases SET published_at=$3,effective_from=$3,published_bundle=$4::jsonb,publication_hash=$5 WHERE tenant_id=$1 AND set_id=$2 AND version=2',[f.tenant,first.proposal.setId,run.reference.asOf,JSON.stringify(bundle),hash(bundle)]);
  await f.owner.query('ALTER TABLE public.reference_releases ENABLE TRIGGER USER');restored=true;
  const selected=(await f.owner.query('SELECT version FROM reference_releases WHERE tenant_id=$1 AND set_id=$2 AND published_at<=$3 AND effective_from<=$3 ORDER BY effective_from DESC,version DESC LIMIT 1',[f.tenant,first.proposal.setId,run.reference.asOf])).rows[0];assert.equal(selected.version,2);
  await f.owner.query("SELECT set_config('gc.actor_id','site:local',true)");const c=(await f.owner.query('SELECT public.gc_quality_claim($1,$2) AS value',[run.id,randomUUID()])).rows[0].value as QualityClaim;claimed(c);const retained=resolved(c);assert.equal(retained.version,1);assert.equal(retained.publicationHash,first.result.publicationHash);assert.deepEqual(retained.codes,['01','A']);
  const m=await f.measurement(c);const done=(await f.owner.query('SELECT public.gc_quality_finish($1,$2::jsonb) AS value',[run.id,JSON.stringify({claimId:c.claimId,attempt:c.attempt,measurement:m})])).rows[0].value;assert.equal(done.run.status,'succeeded');observed=true;
 }finally{await f.owner.query('ROLLBACK');}
 assert.equal(restored,true);assert.equal(observed,true);assert.deepEqual(await f.state(),before);assert.equal(second.result.version,2);
});

test('reference quality source failure remains a closed terminal error and exact completion replay never supplies a verdict',async t=>{
 const f=await fixture(t),ref=await f.publishReference(),{rule}=await f.publish(f.definition(ref.proposal.setId)),{run}=await f.request(rule),c=await f.claim(run.id);claimed(c);
 const body={claimId:c.claimId,attempt:c.attempt,errorCode:'QUALITY_RESOURCE_LIMIT'};
 const finish=()=>f.as(async tx=>(await sql<{value:any}>`select public.gc_quality_finish(${run.id}::uuid,${JSON.stringify(body)}::jsonb) as value`.execute(tx)).rows[0].value,'site:local');
 const failure=await finish();assert.equal(failure.run.status,'failed');assert.equal(failure.run.errorCode,'QUALITY_RESOURCE_LIMIT');assert.equal(failure.run.measurement,null);assert.equal(failure.run.verdict,null);referenceRun(failure.run);const before=await f.state();assert.deepEqual(await finish(),failure);assert.deepEqual(await f.state(),before);
});

test('reference quality extension preserves exact completeness wire shape and existing reference-independent authority',async t=>{
 const f=await fixture(t);await f.revoke(f.actor,permissions.filter(x=>!x.startsWith('reference:')));
 const definition={formatVersion:1 as const,kind:'completeness' as const,target:{tableAssetId:f.tableId,columnAssetId:f.columnId},name:'Existing completeness',purpose:'Preserve previous native behavior.',ownerId:f.ruleOwner,severity:'warning' as const,maximumNullBasisPoints:2500};
 const {rule}=await f.publish(definition),{run}=await f.request(rule),c=await f.claim(run.id);claimed(c);assert.equal(c.execution.kind,'completeness');
 assert.equal(Object.hasOwn(run,'kind'),false);assert.equal(Object.hasOwn(run,'reference'),false);assert.equal(Object.hasOwn(c.execution,'reference'),false);
 const at=await f.now(),measurement:QualityMeasurement={formatVersion:1,kind:'completeness',strategy:'exact-bounded-role-scope',rowCount:20,nullCount:5,observedStartedAt:at,observedFinishedAt:at,elapsedMs:0,sourceVersion:'170006',adapterVersion:'1',queryTemplate:'postgresql-completeness-v1',estimatedCost:1,estimatedBytes:80};
 const completed=(await f.finish(run.id,c,measurement)).run;assert.equal(completed.verdict,'PASS');assert.equal(Object.hasOwn(completed,'reference'),false);assert.equal(Object.hasOwn(completed,'kind'),false);
 const state=await f.state();assert.equal(state.quality_rule_reference_bindings.length,0);assert.equal(state.quality_run_reference_bindings.length,0);
 await f.unchanged(()=>f.request(rule,randomUUID(),at),code('22023'));
});

test('reference quality rechecks retained visibility after blocked membership revocation before publish stale diagnostics',async t=>{
 const operation='publish' as string;
 const f=await fixture(t),ref=await f.publishReference(),{rule}=await f.publish(f.definition(ref.proposal.setId));
 const before=await f.state(),pid=(await f.as(tx=>sql<{pid:number}>`select pg_backend_pid() as pid`.execute(tx))).rows[0].pid;
 const replacement={formatVersion:1 as const,kind:'completeness' as const,target:{tableAssetId:f.tableId,columnAssetId:f.columnId},name:'Replacement',purpose:'A revoked reference must not authorize replacement.',ownerId:f.ruleOwner,severity:'warning' as const,maximumNullBasisPoints:0};
 let deniedError:unknown,settled=false;
 await f.owner.query('BEGIN');await f.owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[f.tenant,f.actor]);
 await f.owner.query('SELECT identity_id FROM memberships WHERE tenant_id=$1 AND identity_id=$2 FOR UPDATE',[f.tenant,f.actor]);
 const work=(operation==='publish'?f.publish(replacement,rule.id,1):f.quality('quality.run.request',{...f.requestBody(rule),ruleHash:'0'.repeat(64)})).then(()=>{settled=true},e=>{deniedError=e;settled=true});
 try{
  let blocked=false;const until=performance.now()+1500;
  while(performance.now()<until){if((await f.owner.query('SELECT pg_backend_pid()=ANY(pg_blocking_pids($1)) AS blocked',[pid])).rows[0].blocked){blocked=true;break;}await new Promise(r=>setTimeout(r,10));}
  assert.equal(blocked,true,'Real runtime command reached its principal lock after initial visibility');assert.equal(settled,false);
  await f.owner.query('UPDATE memberships SET permissions=$3::jsonb WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.actor,JSON.stringify(permissions.filter(x=>x!=='reference:read'))]);await f.owner.query('COMMIT');
 }catch(e){await f.owner.query('ROLLBACK');await work;throw e;}
 await work;assert.ok(code('P0002')(deniedError),'Revoked retained visibility is unavailable, never stale version/hash diagnostics');
 assert.deepEqual(await f.state(),before,'The only committed change is the intended membership permission revocation; protected state stays unchanged');
});
test('reference quality rechecks retained visibility after blocked membership revocation before request stale diagnostics',async t=>{
 const operation='request' as string;
 const f=await fixture(t),ref=await f.publishReference(),{rule}=await f.publish(f.definition(ref.proposal.setId));
 const before=await f.state(),pid=(await f.as(tx=>sql<{pid:number}>`select pg_backend_pid() as pid`.execute(tx))).rows[0].pid;
 const replacement={formatVersion:1 as const,kind:'completeness' as const,target:{tableAssetId:f.tableId,columnAssetId:f.columnId},name:'Replacement',purpose:'A revoked reference must not authorize replacement.',ownerId:f.ruleOwner,severity:'warning' as const,maximumNullBasisPoints:0};
 let deniedError:unknown,settled=false;
 await f.owner.query('BEGIN');await f.owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[f.tenant,f.actor]);
 await f.owner.query('SELECT identity_id FROM memberships WHERE tenant_id=$1 AND identity_id=$2 FOR UPDATE',[f.tenant,f.actor]);
 const work=(operation==='publish'?f.publish(replacement,rule.id,1):f.quality('quality.run.request',{...f.requestBody(rule),ruleHash:'0'.repeat(64)})).then(()=>{settled=true},e=>{deniedError=e;settled=true});
 try{
  let blocked=false;const until=performance.now()+1500;
  while(performance.now()<until){if((await f.owner.query('SELECT pg_backend_pid()=ANY(pg_blocking_pids($1)) AS blocked',[pid])).rows[0].blocked){blocked=true;break;}await new Promise(r=>setTimeout(r,10));}
  assert.equal(blocked,true,'Real runtime command reached its principal lock after initial visibility');assert.equal(settled,false);
  await f.owner.query('UPDATE memberships SET permissions=$3::jsonb WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.actor,JSON.stringify(permissions.filter(x=>x!=='reference:read'))]);await f.owner.query('COMMIT');
 }catch(e){await f.owner.query('ROLLBACK');await work;throw e;}
 await work;assert.ok(code('P0002')(deniedError),'Revoked retained visibility is unavailable, never stale version/hash diagnostics');
 assert.deepEqual(await f.state(),before,'The only committed change is the intended membership permission revocation; protected state stays unchanged');
});
