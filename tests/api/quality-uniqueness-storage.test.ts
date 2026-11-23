// SPDX-License-Identifier: Apache-2.0
/** Real disposable PostgreSQL storage/service qualification. Aggregate completions
 * are explicit fixture inputs, independently checked against owned source rows;
 * this file does not execute the Python worker or claim HTTP/Temporal coverage. */
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import test,{type TestContext} from 'node:test';
import {sql} from '../../packages/db/src/index.ts';
import {Problem} from '../../packages/authz/src/index.ts';
import {assetView} from '../../apps/api/src/repository.ts';
import {QUALITY_UNIQUENESS_BUDGET,type QualityMeasurement,type UniquenessMeasurement,type UniquenessRuleDefinition} from '../../packages/domain/src/quality-contracts.ts';
import {parseQualityDefinition,parseQualityMeasurement} from '../../packages/domain/src/quality.ts';
import {getQualityAsset,getQualityRule,getQualityRun,listQualityRuns,publishQualityRule,requestQualityRun,finishQualityRun} from '../../packages/domain/src/quality-service.ts';
import {fixture,permissions,code,denied,sealFailure,hash,claimed} from '../fixtures/reference-quality.ts';
type Fixture=Awaited<ReturnType<typeof fixture>>;
const unavailable=(e:unknown)=>e instanceof Problem&&e.status===404;
const definition=(f:Fixture,threshold=3750):UniquenessRuleDefinition=>({formatVersion:1,kind:'uniqueness',target:{tableAssetId:f.tableId,columnAssetId:f.columnId},name:'Exact duplicate groups',purpose:'All nonnull rows in repeated byte-key groups.',ownerId:f.ruleOwner,severity:'warning',maximumDuplicateBasisPoints:threshold,comparison:'utf8-exact',nullPolicy:'exclude'});
async function uniqueFixture(t:TestContext){const f=await fixture(t);await f.owner.query(`TRUNCATE "${f.namespace}".observations`);
 await f.owner.query(`INSERT INTO "${f.namespace}".observations SELECT CASE WHEN i<=4 THEN 'A' WHEN i<=6 THEN 'B' WHEN i<=16 THEN chr(67+i-7) ELSE NULL END FROM generate_series(1,20) i`);return f;}
async function measurement(f:Fixture,patch:Partial<UniquenessMeasurement>={}):Promise<UniquenessMeasurement>{const at=await f.now();return {formatVersion:1,kind:'uniqueness',strategy:'exact-bounded-role-scope',rowCount:20,nullCount:4,distinctCount:12,duplicateGroupCount:2,duplicateRowCount:6,totalValueBytes:16,largestValueBytes:1,observedStartedAt:at,observedFinishedAt:at,elapsedMs:0,sourceVersion:'170006',adapterVersion:'1',queryTemplate:'postgresql-uniqueness-v1',estimatedCost:1,estimatedBytes:160,...patch};}
const unique=(run:{kind?:string;reference?:unknown})=>{assert.equal(run.kind,'uniqueness');assert.equal(Object.hasOwn(run,'reference'),false);};

test('uniqueness SQL and pure parsers agree on exact definition and aggregate algebra without new runtime grants',async t=>{
 const f=await uniqueFixture(t),d=definition(f),m=await measurement(f);
 assert.deepEqual(parseQualityDefinition({...d,name:'  Cafe\u0301  '}),{...d,name:'Café'});
 for(const [fn,values,parse] of [
  ['gc_quality_uniqueness_definition_valid',[d,{...d,comparison:'fold'},{...d,maximumDuplicateBasisPoints:10001},{...d,reference:{}}],parseQualityDefinition],
  ['gc_quality_uniqueness_measurement_valid',[m,{...m,distinctCount:11},{...m,duplicateGroupCount:0},{...m,duplicateRowCount:5},{...m,totalValueBytes:17},{...m,largestValueBytes:4097},{...m,totalValueBytes:67108865},{...m,invalidCount:1}],parseQualityMeasurement]
 ] as const){for(const value of values){let valid=true;try{parse(value);}catch{valid=false;}const row=(await f.owner.query('SELECT public.'+fn+'($1::jsonb) AS valid',[JSON.stringify(value)])).rows[0];assert.equal(row.valid,valid);}
  await f.unchanged(()=>f.as(tx=>sql`select ${sql.ref('public.'+fn)}(${JSON.stringify(fn.includes('definition')?d:m)}::jsonb)`.execute(tx)),code('42501'));
 }
});
test('uniqueness independent twenty-row oracle proves 3749 FAIL and 3750 PASS with immutable old result',async t=>{
 const f=await uniqueFixture(t),rows=(await f.owner.query(`WITH g AS(SELECT convert_to(code,'UTF8') AS k,count(*)::integer AS n FROM "${f.namespace}".observations WHERE code IS NOT NULL GROUP BY convert_to(code,'UTF8')) SELECT (SELECT count(*)::integer FROM "${f.namespace}".observations) AS rows,(SELECT count(*)::integer FROM "${f.namespace}".observations WHERE code IS NULL) AS nulls,count(*)::integer AS distinct,count(*) FILTER(WHERE n>1)::integer AS groups,coalesce(sum(n) FILTER(WHERE n>1),0)::integer AS duplicates FROM g`)).rows[0];
 assert.deepEqual(rows,{rows:20,nulls:4,distinct:12,groups:2,duplicates:6});
 const first=await f.as(tx=>publishQualityRule(tx,f.principal(),{id:randomUUID(),expectedVersion:0,definition:definition(f,3749)},randomUUID(),'unique-native'));
 const requested=await f.as(tx=>requestQualityRun(tx,f.principal(),first.rule.id,{id:randomUUID(),ruleVersion:1,ruleHash:first.rule.definitionHash},randomUUID(),'unique-native')),c=await f.claim(requested.run.id);claimed(c);assert.equal(c.execution.kind,'uniqueness');assert.deepEqual(c.execution.budget,QUALITY_UNIQUENESS_BUDGET);
 const observed=await measurement(f),old=(await f.as(tx=>finishQualityRun(tx,requested.run.id,{claimId:c.claimId,attempt:c.attempt,measurement:observed}),'site:local')).run;assert.equal(old.verdict,'FAIL');unique(old);
 const second=await f.publish(definition(f,3750),first.rule.id,1),next=(await f.request(second.rule)).run,c2=await f.claim(next.id);claimed(c2);assert.equal((await f.finish(next.id,c2,await measurement(f))).run.verdict,'PASS');
 assert.deepEqual(await f.as(tx=>getQualityRun(tx,f.principal(),old.id)),old);const state=await f.state();assert.equal(state.quality_rule_versions.length,2);assert.equal(state.quality_run_reference_bindings.length,0);assert.equal(state.quality_rule_reference_bindings.length,0);
});
test('uniqueness empty, all-null and repeated zero-byte values retain distinct NO_DATA and duplicate verdicts',async t=>{
 const f=await uniqueFixture(t),{rule}=await f.publish(definition(f,9999));
 for(const [rows,nulls,k,g,d,verdict] of [[0,0,0,0,0,'NO_DATA'],[20,20,0,0,0,'NO_DATA'],[3,0,1,1,3,'FAIL']] as const){
  const {run}=await f.request(rule),c=await f.claim(run.id);claimed(c);const result=await f.finish(run.id,c,await measurement(f,{rowCount:rows,nullCount:nulls,distinctCount:k,duplicateGroupCount:g,duplicateRowCount:d,totalValueBytes:0,largestValueBytes:0}));assert.equal(result.run.verdict,verdict);unique(result.run);
 }
});
test('uniqueness is reference-independent while historical runs stay visible behind a reference-restricted successor',async t=>{
 const f=await uniqueFixture(t),ref=await f.publishReference(f.proposal({audience:{visibility:'restricted',allowedIdentityIds:[f.actor,f.reviewer,f.ruleOwner].sort()}})),one=await f.publish(definition(f)),{run}=await f.request(one.rule);
 await f.publish(f.definition(ref.proposal.setId),one.rule.id,1);const historical=await f.as(tx=>getQualityRule(tx,f.principal(f.reader),one.rule.id,1),f.reader);assert.equal(historical.currentVersion,null);
 unique(await f.as(tx=>getQualityRun(tx,f.principal(f.reader),run.id),f.reader));assert.deepEqual((await f.as(tx=>listQualityRuns(tx,f.principal(f.reader),one.rule.id),f.reader)).items.map(x=>x.id),[run.id]);
 await f.revoke(f.actor,permissions.filter(p=>!p.startsWith('reference:')));const {rule}=await f.publish(definition(f)),fresh=await f.request(rule);unique(fresh.run);assert.equal(Object.hasOwn((await f.claim(fresh.run.id)),'reference'),false);
});
test('uniqueness request rejects reference selectors and stale pins without writes or binding rows',async t=>{
 const f=await uniqueFixture(t),{rule}=await f.publish(definition(f));
 const now=await f.now();await f.unchanged(()=>f.request(rule,randomUUID(),now),code('22023'));
 await f.unchanged(()=>f.quality('quality.run.request',{...f.requestBody(rule),ruleHash:'0'.repeat(64)}),code('40001'));
 await f.publish(definition(f,4000),rule.id,1);await f.unchanged(()=>f.request(rule),code('40001'));
 for(const bad of [{...definition(f),reference:{}},{...definition(f),maximumNullBasisPoints:0}])await f.unchanged(()=>f.publish(bad as UniquenessRuleDefinition),code('22023'));
});
test('uniqueness current requester revocation denies new work and cancels outstanding claim and finish',async t=>{
 const f=await uniqueFixture(t),{rule}=await f.publish(definition(f)),queued=(await f.request(rule)).run,running=(await f.request(rule)).run,c=await f.claim(running.id);claimed(c);const m=await measurement(f);
 await f.revoke(f.actor,permissions.filter(p=>p!=='quality:execute'));await f.unchanged(()=>f.request(rule),denied);
 const stopped=await f.claim(queued.id);assert.equal(stopped.status,'terminal');if(stopped.status==='terminal')assert.equal(stopped.run.errorCode,'QUALITY_AUTHORITY_REVOKED');
 const result=await f.finish(running.id,c,m);assert.equal(result.run.status,'cancelled');assert.equal(result.run.measurement,null);assert.equal(result.run.errorCode,'QUALITY_AUTHORITY_REVOKED');
});
test('uniqueness immutable owner eligibility is checked at request claim and finish under current membership',async t=>{
 const f=await uniqueFixture(t),{rule}=await f.publish(definition(f)),queued=(await f.request(rule)).run,running=(await f.request(rule)).run,c=await f.claim(running.id);claimed(c);
 await f.ownerTx(()=>f.owner.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.ruleOwner]));await f.unchanged(()=>f.request(rule),denied);
 const result=await f.claim(queued.id);assert.equal(result.status,'terminal');if(result.status==='terminal')assert.equal(result.run.errorCode,'QUALITY_AUTHORITY_REVOKED');assert.equal((await f.finish(running.id,c,await measurement(f))).run.errorCode,'QUALITY_AUTHORITY_REVOKED');
});
test('uniqueness exact command replay survives head drift but never revoked current read authority',async t=>{
 const f=await uniqueFixture(t),id=randomUUID(),key=randomUUID(),d=definition(f),one=await f.publish(d,id,0,key),requestKey=randomUUID(),body=f.requestBody(one.rule),receipt=await f.quality('quality.run.request',body,requestKey);
 await f.publish(definition(f,4000),id,1);const before=await f.state();assert.deepEqual(await f.publish(d,id,0,key),one);assert.deepEqual(await f.quality('quality.run.request',body,requestKey),receipt);assert.deepEqual(await f.state(),before);
 await f.unchanged(()=>f.quality('quality.run.request',{...body,id:randomUUID()},requestKey),code('40001'));
 await f.revoke(f.actor,permissions.filter(p=>p!=='quality:read'));await f.unchanged(()=>f.publish(d,id,0,key),denied);await f.unchanged(()=>f.quality('quality.run.request',body,requestKey),denied);
});
test('uniqueness site fencing, exact completion replay and cancellation refuse late or substituted results',async t=>{
 const f=await uniqueFixture(t),{rule}=await f.publish(definition(f)),{run}=await f.request(rule),c=await f.claim(run.id);claimed(c);const m=await measurement(f);
 assert.equal((await f.claim(run.id)).status,'busy');await f.unchanged(()=>f.finish(run.id,{...c,claimId:randomUUID()},m),code('40001'));
 const first=await f.finish(run.id,c,m),before=await f.state();assert.deepEqual(await f.finish(run.id,c,m),first);assert.deepEqual(await f.state(),before);await f.unchanged(()=>f.finish(run.id,c,{...m,estimatedBytes:161}),code('40001'));
 const queued=(await f.request(rule)).run,c2=await f.claim(queued.id);claimed(c2);const current=await f.as(tx=>getQualityRun(tx,f.principal(),queued.id));await f.quality('quality.run.cancel',{runId:queued.id,expectedVersion:current.version,reason:'Cancel owned native observation'});await f.unchanged(async()=>f.finish(queued.id,c2,await measurement(f)),code('40001'));
});
test('uniqueness invalid aggregates or substituted families fail before journal or terminal mutation',async t=>{
 const f=await uniqueFixture(t),{rule}=await f.publish(definition(f)),{run}=await f.request(rule),c=await f.claim(run.id);claimed(c);const m=await measurement(f);
 for(const patch of [{distinctCount:11},{duplicateGroupCount:0},{duplicateRowCount:5},{totalValueBytes:17},{largestValueBytes:4097},{totalValueBytes:67108865},{referenceBindingHash:'a'.repeat(64)},{queryTemplate:'postgresql-completeness-v1'}])await f.unchanged(()=>f.finish(run.id,c,{...m,...patch} as QualityMeasurement),code('22023'));
 const {distinctCount,duplicateGroupCount,duplicateRowCount,totalValueBytes,largestValueBytes,...common}=m;await f.unchanged(()=>f.finish(run.id,c,{...common,kind:'completeness',queryTemplate:'postgresql-completeness-v1'}),code('22023'));
 assert.equal((await f.finish(run.id,c,m)).run.status,'succeeded');
});
test('uniqueness locks distinct owner before requester and target on request claim and finish',async t=>{
 const f=await uniqueFixture(t),{rule}=await f.publish(definition(f)),probe=await f.connection(),pid=(await f.as(tx=>sql<{pid:number}>`select pg_backend_pid() as pid`.execute(tx))).rows[0].pid;assert.ok(f.ruleOwner<f.actor);
 async function blocked<T>(operation:()=>Promise<T>){await f.owner.query('BEGIN');await f.owner.query('SELECT id FROM identities WHERE id=$1 FOR UPDATE',[f.ruleOwner]);let value:T|undefined,error:unknown;const work=operation().then(v=>{value=v},e=>{error=e});
  try{let waiting=false;const until=performance.now()+1500;while(performance.now()<until){if((await f.owner.query('SELECT pg_backend_pid()=ANY(pg_blocking_pids($1)) AS blocked',[pid])).rows[0].blocked){waiting=true;break;}await new Promise(r=>setTimeout(r,10));}assert.equal(waiting,true);
   await probe.query('BEGIN');try{await probe.query('SELECT id FROM identities WHERE id=$1 FOR UPDATE NOWAIT',[f.actor]);await probe.query('SELECT id FROM assets WHERE tenant_id=$1 AND id=$2 FOR UPDATE NOWAIT',[f.tenant,f.columnId]);}finally{await probe.query('ROLLBACK');}
  }finally{await f.owner.query('ROLLBACK');await work;}if(error)throw error;assert.ok(value);return value;
 }
 const queued=await blocked(()=>f.request(rule)),c=await blocked(()=>f.claim(queued.run.id));claimed(c);assert.equal((await blocked(async()=>f.finish(queued.run.id,c,await measurement(f)))).run.status,'succeeded');
});
test('uniqueness runtime grants remain read-only and early flush cannot admit a foreign reference binding',async t=>{
 const f=await uniqueFixture(t),ref=await f.publishReference(),{rule}=await f.publish(definition(f)),{run}=await f.request(rule);
 for(const table of ['quality_rules','quality_rule_versions','quality_runs','quality_rule_reference_bindings','quality_run_reference_bindings'])await f.unchanged(()=>f.as(tx=>sql`delete from ${sql.table(table)} where tenant_id=${f.tenant}::uuid`.execute(tx)),code('42501'));
 await f.unchanged(()=>f.ownerTx(async()=>{await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');await f.owner.query('INSERT INTO quality_rule_reference_bindings(tenant_id,rule_id,rule_version,set_id) VALUES($1,$2,1,$3)',[f.tenant,rule.id,ref.proposal.setId]);}),sealFailure);
 const before=await f.state();await assert.rejects(()=>f.ownerTx(async()=>{await f.owner.query('INSERT INTO quality_rule_versions SELECT tenant_id,rule_id,version+1,definition,definition_hash,owner_id,created_by,clock_timestamp() FROM quality_rule_versions WHERE tenant_id=$1 AND rule_id=$2 AND version=1',[f.tenant,rule.id]);await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');}),sealFailure);assert.deepEqual(await f.state(),before);
 assert.equal((await f.as(tx=>sql`select id from quality_runs`.execute(tx),f.outsider,f.foreign)).rows.length,0);await assert.rejects(()=>f.as(tx=>getQualityRun(tx,f.principal(f.outsider,f.foreign),run.id),f.outsider,f.foreign),unavailable);
});
test('uniqueness source and asset version drift invalidate queued and in-flight observations',async t=>{
 for(const phase of ['claim','finish'])for(const kind of ['source','column']){const f=await uniqueFixture(t),{rule}=await f.publish(definition(f)),{run}=await f.request(rule),c=phase==='finish'?await f.claim(run.id):null;if(c)claimed(c);
  await f.ownerTx(async()=>{if(kind==='source')await f.owner.query('UPDATE sources SET version=version+1 WHERE tenant_id=$1 AND id=$2',[f.tenant,f.sourceId]);else{const row=(await f.owner.query('UPDATE assets SET version=version+1 WHERE tenant_id=$1 AND id=$2 RETURNING *',[f.tenant,f.columnId])).rows[0];await f.owner.query('INSERT INTO asset_revisions(tenant_id,asset_id,version,snapshot) VALUES($1,$2,$3,$4::jsonb)',[f.tenant,f.columnId,row.version,JSON.stringify(assetView(row))]);}});
  const result=c?(await f.finish(run.id,c,await measurement(f))).run:await f.claim(run.id).then(result=>{assert.equal(result.status,'terminal');if(result.status!=='terminal')throw Error('Expected terminal');return result.run;});assert.equal(result.errorCode,'QUALITY_TARGET_STALE');assert.equal(result.measurement,null);
 }
});
test('uniqueness deferred seal catches a mismatched finish journal after prior flush and rolls back the complete command',async t=>{
 const f=await uniqueFixture(t),{rule}=await f.publish(definition(f)),queued=(await f.request(rule)).run;
 let didClaim=false,flushed=false,didFinish=false,restored=false,stage='claim';const before=await f.state();
 const guards=async()=> (await f.owner.query("SELECT tgrelid::regclass::text AS relation,tgname,tgenabled FROM pg_trigger WHERE NOT tgisinternal AND tgrelid IN('public.audit'::regclass,'public.outbox'::regclass,'public.quality_runs'::regclass) ORDER BY 1,2")).rows;const beforeGuards=await guards();
 const siteTx=async(work:()=>Promise<void>)=>{await f.owner.query('BEGIN');try{await f.owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id','site:local',true)",[f.tenant]);await work();await f.owner.query('COMMIT');}catch(error){await f.owner.query('ROLLBACK');throw error;}};
 await assert.rejects(()=>siteTx(async()=>{
  // Production actor boundaries remain intact: the requester transaction has
  // committed; every mutation in this transaction uses only site:local.
  const claim=(await f.owner.query('SELECT public.gc_quality_claim($1,$2) AS value',[queued.id,randomUUID()])).rows[0].value;assert.equal(claim.status,'claimed');assert.equal(claim.attempt,1);didClaim=true;
  stage='initial-flush';await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');flushed=true;await f.owner.query('SET CONSTRAINTS ALL DEFERRED');
  stage='finish';const observed=await measurement(f),completed=(await f.owner.query('SELECT public.gc_quality_finish($1,$2::jsonb) AS value',[queued.id,JSON.stringify({claimId:claim.claimId,attempt:claim.attempt,measurement:observed})])).rows[0].value.run;
  assert.equal(completed.status,'succeeded');assert.equal(completed.version,queued.version+2);assert.equal(completed.verdict,'PASS');assert.deepEqual(completed.measurement,observed);didFinish=true;
  // Explicit rollback-contained owner attack changes only non-key audit data;
  // retain the exact outbox row and restore guards before the intended seal.
  stage='inspect-finished-journals';
  const outbox=await f.owner.query("SELECT id,event_type,resource_id,resource_version,payload FROM outbox WHERE tenant_id=$1 AND event_type='quality.run_finished' AND resource_id=$2 AND resource_version=$3",[f.tenant,f.columnId,completed.version]);
  assert.equal(outbox.rowCount,1);const eventId=outbox.rows[0].id;assert.match(eventId,/^[0-9a-f-]{36}$/);assert.equal(outbox.rows[0].payload.actorId,'site:local');assert.equal(outbox.rows[0].payload.type,'quality.run_finished');
  const audit=await f.owner.query("SELECT id,actor_id,action,resource_id,changes FROM audit WHERE tenant_id=$1 AND action='quality.run_finished' AND resource_id=$2 AND changes->>'runId'=$3",[f.tenant,f.columnId,queued.id]);
  assert.equal(audit.rowCount,1);assert.deepEqual(audit.rows,[{id:eventId,actor_id:'site:local',action:'quality.run_finished',resource_id:f.columnId,changes:{ruleId:rule.id,runId:queued.id,ruleVersion:rule.version,verdict:'PASS',errorCode:null,resourceVersion:completed.version}}]);
  stage='disable-audit-guards';await f.owner.query('ALTER TABLE public.audit DISABLE TRIGGER USER');
  stage='corrupt-finished-audit';const wrongRule=randomUUID();assert.notEqual(wrongRule,rule.id);
  const changed=await f.owner.query("UPDATE audit SET changes=jsonb_set(changes,'{ruleId}',to_jsonb($3::uuid)) WHERE tenant_id=$1 AND id=$2 RETURNING id,actor_id,action,resource_id,changes",[f.tenant,eventId,wrongRule]);
  assert.equal(changed.rowCount,1);assert.deepEqual(changed.rows,[{...audit.rows[0],changes:{...audit.rows[0].changes,ruleId:wrongRule}}]);
  assert.deepEqual((await f.owner.query("SELECT id,event_type,resource_id,resource_version,payload FROM outbox WHERE tenant_id=$1 AND id=$2",[f.tenant,eventId])).rows,outbox.rows);
  stage='restore-audit-guards';await f.owner.query('ALTER TABLE public.audit ENABLE TRIGGER USER');assert.deepEqual(await guards(),beforeGuards);restored=true;
  stage='final-seal';await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');
 }),error=>{const state=error&&typeof error==='object'&&'code'in error&&typeof error.code==='string'&&/^[A-Z0-9]{5}$/.test(error.code)?error.code:'NO_SQLSTATE';
  assert.equal(stage,'final-seal','Fixture failed before seal at '+stage+' ('+state+')');return code('23514')(error)&&error instanceof Error&&error.message==='QUALITY_STORAGE_INVALID';});
 assert.equal(didClaim,true);assert.equal(flushed,true);assert.equal(didFinish,true);assert.equal(restored,true);assert.deepEqual(await guards(),beforeGuards);assert.deepEqual(await f.state(),before,'Failed post-flush seal restores the original queued run, journals and receipts');
});
test('uniqueness blocked request rechecks membership revocation before stale hash diagnostics',async t=>{
 const f=await uniqueFixture(t),{rule}=await f.publish(definition(f)),before=await f.state(),pid=(await f.as(tx=>sql<{pid:number}>`select pg_backend_pid() as pid`.execute(tx))).rows[0].pid;
 await f.owner.query('BEGIN');await f.owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[f.tenant,f.actor]);assert.equal((await f.owner.query('SELECT identity_id FROM memberships WHERE tenant_id=$1 AND identity_id=$2 FOR UPDATE',[f.tenant,f.actor])).rowCount,1);let error:unknown,settled=false;
 const work=f.quality('quality.run.request',{...f.requestBody(rule),ruleHash:'0'.repeat(64)}).then(()=>{settled=true},e=>{error=e;settled=true});
 try{let blocked=false;const until=performance.now()+1500;while(performance.now()<until){if((await f.owner.query('SELECT pg_backend_pid()=ANY(pg_blocking_pids($1)) AS blocked',[pid])).rows[0].blocked){blocked=true;break;}await new Promise(r=>setTimeout(r,10));}assert.equal(blocked,true);assert.equal(settled,false);
  await f.owner.query('UPDATE memberships SET permissions=$3::jsonb WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.actor,JSON.stringify(permissions.filter(p=>p!=='quality:execute'))]);await f.owner.query('COMMIT');
 }catch(e){await f.owner.query('ROLLBACK');await work;throw e;}await work;assert.ok(code('42501')(error));assert.deepEqual(await f.state(),before);
});

test('uniqueness deferred cancellation seal binds exact rule identity rather than trusting selected journal contents',async t=>{
 const f=await uniqueFixture(t),{rule}=await f.publish(definition(f)),{run}=await f.request(rule),before=await f.state();let cancelled=false,restored=false;
 await assert.rejects(()=>f.ownerTx(async()=>{
  await f.owner.query("SELECT public.gc_quality_command('quality.run.cancel',$1,$2::jsonb,'unique-native')",[randomUUID(),JSON.stringify({runId:run.id,expectedVersion:1,reason:'Cancel synthetic run'})]);cancelled=true;
  await f.owner.query('ALTER TABLE public.audit DISABLE TRIGGER USER');
  await f.owner.query("UPDATE audit SET changes=jsonb_set(changes,'{ruleId}',to_jsonb($3::uuid)) WHERE tenant_id=$1 AND action='quality.run_cancelled' AND changes->>'runId'=$2",[f.tenant,run.id,randomUUID()]);
  await f.owner.query('ALTER TABLE public.audit ENABLE TRIGGER USER');restored=true;await f.owner.query('SET CONSTRAINTS ALL IMMEDIATE');
 }),sealFailure);assert.ok(cancelled&&restored);assert.deepEqual(await f.state(),before);
});
