// SPDX-License-Identifier: Apache-2.0
/** Native SQL030 storage qualification. Aggregate envelopes are explicitly
 * authored from independent owned source counts; Python/Temporal is separate. */
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import test from 'node:test';
import {sql} from '../../packages/db/src/index.ts';
import {Problem} from '../../packages/authz/src/index.ts';
import {assetView,visibleAudit} from '../../apps/api/src/repository.ts';
import {parseQualityDefinition,parseQualityMeasurement,parseQualityRunView,qualityVolumeVerdict} from '../../packages/domain/src/quality.ts';
import {comparisonScopeHash,parseComparisonScope} from '../../packages/domain/src/quality-monitoring.ts';
import {getQualityAsset,getQualityRule,getQualityRun,listQualityRuns,publishQualityRule,requestQualityRun,finishQualityRun,qualityFailure} from '../../packages/domain/src/quality-service.ts';
import {getQualityMonitor,getQualityIssue,listQualityIssueEvents} from '../../packages/domain/src/quality-monitoring-service.ts';
import {volumeFixture,code,denied,claimed,permissions,exactError} from '../fixtures/quality-volume.ts';
import type {VolumeRuleDefinition,QualityRuleView,QualityRunView} from '../../packages/domain/src/quality-contracts.ts';
import type {QualityMonitorView,QualityIssueView,QualityOccurrence} from '../../packages/domain/src/quality-monitoring-contracts.ts';
type Fixture=Awaited<ReturnType<typeof volumeFixture>>;
const unavailable=(e:unknown)=>e instanceof Problem&&e.status===404&&e.code==='QUALITY_UNAVAILABLE';
// Direct service invocation retains the native refusal; the real API uses this mapper.
const nativeUnavailableMapped=(e:unknown)=>exactError('P0002','QUALITY_UNAVAILABLE')(e)&&unavailable(qualityFailure(e));
const pureValid=(parse:(v:unknown)=>unknown,v:unknown)=>{try{parse(v);return true;}catch{return false;}};
async function finish(f:Fixture,r:QualityRunView,d:VolumeRuleDefinition,rows?:number){const c=await f.claim(r.id);claimed(c);assert.equal(c.execution.kind,'volume');assert.equal(c.execution.budget.maximumRows,100000);const m=await f.measurement(d,rows===undefined?{}:{rowCount:rows,estimatedBytes:rows*8});const result=(await f.finish(r.id,c,m)).run;assert.equal(result.kind,'volume');return {run:result,c,m};}
async function schedule(f:Fixture,m:QualityMonitorView){assert.ok(m.nextSlotAt);await f.waitUntil(m.nextSlotAt);await f.tick(m.id);const o=(await f.occurrences(m.id)).at(-1)!;assert.equal(o.disposition,'enqueued');if(o.disposition!=='enqueued')throw Error('Actual scheduled run required');return o;}
async function failed(t:Parameters<typeof volumeFixture>[0]){const f=await volumeFixture(t),d=f.definition(7,7),{rule}=await f.publish(d),{monitor}=await f.publishMonitor(rule),o=await schedule(f,monitor);await finish(f,(await f.as(tx=>getQualityRun(tx,f.principal(),o.runId))),d);await f.reconcile(monitor.id);const issue=(await f.issues(monitor.id))[0];assert.equal(issue.status,'open');return {f,d,rule,monitor,o,issue};}
async function recovery(f:Fixture,i:QualityIssueView){const result=await f.command<{occurrence:QualityOccurrence}>('quality.issue.recovery.request',{issueId:i.id,expectedVersion:i.version,id:randomUUID(),reason:'Verify corrected table population.'});assert.equal(result.occurrence.disposition,'enqueued');if(result.occurrence.disposition!=='enqueued')throw Error('Linked recovery run required');return result.occurrence;}
function resolveBody(i:QualityIssueView){assert.ok(i.recovery);return {issueId:i.id,expectedVersion:i.version,reason:'Verified exact table count.',rootCause:'Synthetic missing row.',remediation:'Restored one owned row.',recoveryOccurrenceId:i.recovery.occurrenceId,recoveryRunId:i.recovery.runId,recoveryRunVersion:i.recovery.runVersion};}

test('volume SQL and TypeScript closed definition binding grammar agree at exact inclusive bounds',async t=>{
 const f=await volumeFixture(t),d=f.definition();
 for(const v of [d,f.definition(0,0),f.definition(0,100000),f.definition(100000,100000),...[-1,100001,1.5,'6',null].map(minimumRows=>({...d,minimumRows})),{...d,minimumRows:7},{...d,nullPolicy:'exclude'},{...d,target:{tableAssetId:f.tableId,columnAssetId:f.columnId}},{...d,target:{...d.target,columnAssetId:null}}]){const actual=(await f.owner.query('SELECT gc_quality_definition_valid($1::jsonb) valid',[JSON.stringify(v)])).rows[0].valid;assert.equal(actual,pureValid(parseQualityDefinition,v));}
 assert.deepEqual((await f.owner.query('SELECT gc_quality_volume_binding($1::jsonb) value',[JSON.stringify(d)])).rows[0].value,f.binding());assert.equal(f.binding().volumeHash,'08d5c181809ded58cf68240b793f9e54f7a372b32b9fd0bf16cce1fcd993f421');
});
test('volume SQL measurement and verdict parity separates authored limits from the fixed execution budget',async t=>{
 const f=await volumeFixture(t),d=f.definition(0,5),m=await f.measurement(d);assert.equal(m.rowCount,6);
 for(const value of [m,{...m,rowCount:0},{...m,rowCount:100000},{...m,rowCount:100001},{...m,rowCount:1.5},{...m,nullCount:0},{...m,values:[]},{...m,volumeHash:'x'},{...m,estimatedBytes:67108865}])assert.equal((await f.owner.query('SELECT gc_quality_volume_measurement_valid($1::jsonb) value',[JSON.stringify(value)])).rows[0].value,pureValid(parseQualityMeasurement,value));
 for(const [rows,expected] of [[0,'PASS'],[5,'PASS'],[6,'FAIL'],[100000,'FAIL']] as const){const value={...m,rowCount:rows};assert.equal(qualityVolumeVerdict(value,f.binding(d)),expected);assert.equal((await f.owner.query('SELECT gc_quality_volume_verdict($1::jsonb,$2::jsonb) value',[JSON.stringify(value),JSON.stringify(f.binding(d))])).rows[0].value,expected);}
});
test('volume table eligibility and execution expose no column even when every canonical child is hidden',async t=>{
 const f=await volumeFixture(t);await f.ownerTx(()=>f.owner.query("UPDATE assets SET visibility='restricted',allowed_identities=$3::jsonb WHERE tenant_id=$1 AND id=$2",[f.tenant,f.columnId,JSON.stringify([f.ruleOwner])]));
 const view=await f.as(tx=>getQualityAsset(tx,f.principal(),f.tableId));assert.deepEqual(view.eligibility,{supported:true,reason:null,tableAssetId:f.tableId,columnAssetId:null});assert.deepEqual(view.items,[]);
 const {rule}=await f.publish(f.definition()),{run}=await f.request(rule),c=await f.claim(run.id);claimed(c);assert.equal(c.execution.kind,'volume');assert.deepEqual(Object.keys(c.execution.target).sort(),['kind','databaseOid','schemaOid','relationOid','schemaName','tableName'].sort());
 assert.equal(run.columnAssetId,null);assert.equal((await f.as(tx=>getQualityAsset(tx,f.principal(),f.tableId))).items[0].id,rule.id);await assert.rejects(()=>f.as(tx=>getQualityAsset(tx,f.principal(),f.columnId)),unavailable);
});
test('volume target supports a real relation with no canonical columns and no implicit child population query',async t=>{
 const f=await volumeFixture(t),table=randomUUID();await f.owner.query(`CREATE TABLE "${f.namespace}".empty_shape()`);for(let n=0;n<6;n++)await f.owner.query(`INSERT INTO "${f.namespace}".empty_shape DEFAULT VALUES`);
 const oid=(await f.owner.query('SELECT oid::text value FROM pg_class WHERE relnamespace=$1::oid AND relname=$2',[f.target.schemaOid,'empty_shape'])).rows[0].value;
 await f.ownerTx(async()=>{const parent='pg:'+f.target.databaseOid+':schema:'+f.target.schemaOid,row=(await f.owner.query("INSERT INTO assets(tenant_id,id,source_id,external_id,name,qualified_name,type,parent_external_id,metadata,observed_at) VALUES($1,$2,$3,$4,'empty_shape','synthetic.empty_shape','table',$5,$6::jsonb,clock_timestamp()) RETURNING *",[f.tenant,table,f.sourceId,'pg:'+f.target.databaseOid+':relation:'+oid,parent,JSON.stringify({oid,relationKind:'r',schema:f.namespace,table:'empty_shape',provenance:'source-observed'})])).rows[0];await f.owner.query('INSERT INTO asset_revisions(tenant_id,asset_id,version,snapshot) VALUES($1,$2,1,$3::jsonb)',[f.tenant,table,JSON.stringify(assetView(row))]);});
 const d={...f.definition(),target:{kind:'table' as const,tableAssetId:table}},{rule}=await f.publish(d),{run}=await f.request(rule),c=await f.claim(run.id);claimed(c);assert.equal(c.execution.target.relationOid,oid);assert.equal(run.columnAssetId,null);const count=Number((await f.owner.query(`SELECT count(*) value FROM ONLY "${f.namespace}".empty_shape`)).rows[0].value);assert.equal(count,6);const m=await f.measurement(d,{rowCount:count});assert.equal((await f.finish(run.id,c,m)).run.verdict,'PASS');
});
test('volume independent actual table count FAIL then revised PASS retains both exact pinned historical outcomes',async t=>{
 const f=await volumeFixture(t),d=f.definition(0,5),{rule}=await f.as(tx=>publishQualityRule(tx,f.principal(),{id:randomUUID(),expectedVersion:0,definition:d},randomUUID(),'volume-native'));
 const first=(await f.as(tx=>requestQualityRun(tx,f.principal(),rule.id,{id:randomUUID(),ruleVersion:1,ruleHash:rule.definitionHash},randomUUID(),'volume-native'))).run,old=await finish(f,first,d);assert.equal(old.run.verdict,'FAIL');assert.equal(old.m.rowCount,6);
 const v2=await f.publish(f.definition(0,6),rule.id,1),next=(await f.request(v2.rule)).run,current=await finish(f,next,f.definition(0,6));assert.equal(current.run.verdict,'PASS');assert.deepEqual(await f.as(tx=>getQualityRun(tx,f.principal(),old.run.id)),old.run);assert.notDeepEqual(old.run.measurement,current.run.measurement);
 const history=await f.as(tx=>getQualityRule(tx,f.principal(),rule.id,1));assert.deepEqual(history.definition,d);assert.equal(history.currentVersion,2);const bindings=(await f.state()).quality_run_reference_bindings;assert.ok(Array.isArray(bindings));assert.equal(bindings.length,0);
});
test('volume empty relation is exact measured PASS or FAIL and never NO_DATA',async t=>{
 const f=await volumeFixture(t);await f.owner.query(`TRUNCATE "${f.namespace}".observations`);
 for(const [minimum,expected] of [[0,'PASS'],[1,'FAIL']] as const){const d=f.definition(minimum,6),{rule}=await f.publish(d),{run}=await f.request(rule),done=await finish(f,run,d);assert.equal(done.m.rowCount,0);assert.equal(done.run.verdict,expected);assert.equal(Object.hasOwn(done.m,'nullCount'),false);}
});
test('volume immutable table identity rejects column substitution and reference selectors without canonical effects',async t=>{
 const f=await volumeFixture(t),d=f.definition(),{rule}=await f.publish(d);
 await f.unchanged(()=>f.publish({...d,target:{kind:'table',tableAssetId:f.columnId}},rule.id,1),code('40001'));
 await f.unchanged(()=>f.publish({...d,target:{tableAssetId:f.tableId,columnAssetId:f.columnId}} as unknown as VolumeRuleDefinition),code('22023'));
 const at=await f.now();await f.unchanged(()=>f.request(rule,randomUUID(),at),code('22023'));
 await f.publish(f.definition(0,6),rule.id,1);await f.unchanged(()=>f.request(rule),code('40001'));
});
test('volume exact request completion and cancel retries remain authorized and idempotent',async t=>{
 const f=await volumeFixture(t),d=f.definition(),{rule}=await f.publish(d),body=f.requestBody(rule),key=randomUUID(),first=await f.quality('quality.run.request',body,key),before=await f.state();assert.deepEqual(await f.quality('quality.run.request',body,key),first);assert.deepEqual(await f.state(),before);
 const done=await finish(f,first.run,d),finished=await f.state();assert.deepEqual((await f.finish(first.run.id,done.c,done.m)).run,done.run);assert.deepEqual(await f.state(),finished);
 const next=(await f.request(rule)).run,cancel={runId:next.id,expectedVersion:1,reason:'No source execution needed.'},cancelKey=randomUUID(),result=await f.quality('quality.run.cancel',cancel,cancelKey),after=await f.state();assert.deepEqual(await f.quality('quality.run.cancel',cancel,cancelKey),result);assert.deepEqual(await f.state(),after);
 await f.revoke(f.actor,['catalog:read','quality:read']);await f.unchanged(()=>f.quality('quality.run.request',body,key),code('42501'));
});
test('volume current schema and table visibility applies before listings run history audit and foreign identifiers',async t=>{
 const f=await volumeFixture(t),{rule}=await f.publish(f.definition()),{run}=await f.request(rule);await finish(f,run,f.definition());
 const audit=()=>f.as(tx=>visibleAudit(tx,f.principal()).where('resource_id','=',f.tableId).execute());assert.equal((await audit()).length,4);
 for(const id of [f.tableId,f.schemaId]){await f.ownerTx(()=>f.owner.query("UPDATE assets SET visibility='restricted',allowed_identities=$3::jsonb WHERE tenant_id=$1 AND id=$2",[f.tenant,id,JSON.stringify([f.ruleOwner])]));await assert.rejects(()=>f.as(tx=>getQualityAsset(tx,f.principal(),f.tableId)),id===f.schemaId?nativeUnavailableMapped:unavailable);await assert.rejects(()=>f.as(tx=>listQualityRuns(tx,f.principal(),rule.id)),unavailable);await assert.rejects(()=>f.as(tx=>getQualityRun(tx,f.principal(),run.id)),unavailable);assert.equal((await audit()).length,0);await f.ownerTx(()=>f.owner.query("UPDATE assets SET visibility='tenant',allowed_identities='[]' WHERE tenant_id=$1 AND id=$2",[f.tenant,id]));}
 await assert.rejects(()=>f.as(tx=>getQualityRun(tx,f.principal(f.outsider,f.foreign),run.id),f.outsider,f.foreign),unavailable);
});
test('volume current distinct rule owner and requester authority refuse request and terminal replay',async t=>{
 const f=await volumeFixture(t),d=f.definition(),{rule}=await f.publish(d),{run}=await f.request(rule),done=await finish(f,run,d);
 await f.ownerTx(()=>f.owner.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.ruleOwner]));await f.unchanged(()=>f.request(rule),code('42501'));await f.unchanged(()=>f.finish(run.id,done.c,done.m),code('42501'));
 await f.ownerTx(()=>f.owner.query('UPDATE memberships SET active=true WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.ruleOwner]));await f.revoke(f.actor,['catalog:read','quality:read']);await f.unchanged(()=>f.finish(run.id,done.c,done.m),code('42501'));
});
test('volume source configuration or table revision drift prevents completion and retains no accepted measurement',async t=>{
 const f=await volumeFixture(t),d=f.definition(),{rule}=await f.publish(d),{run}=await f.request(rule),c=await f.claim(run.id);claimed(c);
 await f.ownerTx(()=>f.owner.query('UPDATE sources SET version=version+1 WHERE tenant_id=$1 AND id=$2',[f.tenant,f.sourceId]));const result=(await f.finish(run.id,c,await f.measurement(d))).run;assert.equal(result.status,'failed');assert.equal(result.errorCode,'QUALITY_TARGET_STALE');assert.equal(result.measurement,null);
 const next=(await f.request(rule)).run,claim=await f.claim(next.id);claimed(claim);await f.ownerTx(async()=>{const row=(await f.owner.query('UPDATE assets SET version=version+1 WHERE tenant_id=$1 AND id=$2 RETURNING *',[f.tenant,f.tableId])).rows[0];await f.owner.query('INSERT INTO asset_revisions(tenant_id,asset_id,version,snapshot) VALUES($1,$2,$3,$4::jsonb)',[f.tenant,f.tableId,row.version,JSON.stringify(assetView(row))]);});assert.equal((await f.finish(next.id,claim,await f.measurement(d))).run.errorCode,'QUALITY_TARGET_STALE');
});
test('volume overflow is a finite execution error and never a partial population or forged measurement',async t=>{
 const f=await volumeFixture(t),d=f.definition(0,5),{rule}=await f.publish(d),{run}=await f.request(rule),c=await f.claim(run.id);claimed(c);
 const m=await f.measurement(d,{rowCount:100001});await f.unchanged(()=>f.finish(run.id,c,m),code('22023'));const result=await f.as(tx=>finishQualityRun(tx,run.id,{claimId:c.claimId,attempt:c.attempt,errorCode:'QUALITY_RESOURCE_LIMIT'}),'site:local');assert.equal(result.run.status,'failed');assert.equal(result.run.measurement,null);assert.equal(result.run.verdict,null);parseQualityRunView(result.run);
});
test('volume nullable table schema retains forced RLS tenant FKs and runtime SELECT-only authority',async t=>{
 const f=await volumeFixture(t),{rule}=await f.publish(f.definition());assert.equal((await f.as(tx=>tx.selectFrom('quality_rules').selectAll().where('id','=',rule.id).execute(),f.outsider,f.foreign)).length,0);
 await assert.rejects(()=>f.as(tx=>sql`update public.quality_rules set table_asset_id=${f.columnId}::uuid where tenant_id=${f.tenant}::uuid and id=${rule.id}::uuid`.execute(tx)),code('42501'));
 await assert.rejects(()=>f.ownerTx(()=>f.owner.query('INSERT INTO quality_rules(tenant_id,id,table_asset_id,current_version,created_by,created_at) VALUES($1,$2,$3,1,$4,clock_timestamp())',[f.foreign,randomUUID(),f.tableId,f.outsider]),f.foreign,f.outsider),code('23503'));
 await f.unchanged(()=>f.ownerTx(()=>f.owner.query('INSERT INTO quality_rules(tenant_id,id,table_asset_id,column_asset_id,current_version,created_by,created_at) VALUES($1,$2,$3,$4,1,$5,clock_timestamp())',[f.tenant,randomUUID(),f.tableId,f.columnId,f.actor])),code('23514'));
});
test('volume current rule and run pagination contains only visible exact table identities',async t=>{
 const f=await volumeFixture(t),{rule}=await f.publish(f.definition());for(let n=0;n<3;n++)await f.request(rule);
 const first=await f.as(tx=>listQualityRuns(tx,f.principal(),rule.id,{limit:1}));assert.equal(first.items.length,1);assert.ok(first.nextCursor);const second=await f.as(tx=>listQualityRuns(tx,f.principal(),rule.id,{limit:1,cursor:first.nextCursor!}));assert.equal(second.items.length,1);assert.notEqual(first.items[0].id,second.items[0].id);
 await assert.rejects(()=>f.as(tx=>listQualityRuns(tx,f.principal(f.reader),rule.id,{limit:1,cursor:first.nextCursor!}),f.reader),e=>e instanceof Problem&&e.code==='QUALITY_PAGE_INVALID');
 await f.ownerTx(()=>f.owner.query("UPDATE assets SET visibility='restricted',allowed_identities=$3::jsonb WHERE tenant_id=$1 AND id=$2",[f.tenant,f.tableId,JSON.stringify([f.ruleOwner])]));await assert.rejects(()=>f.as(tx=>listQualityRuns(tx,f.principal(),rule.id,{limit:1,cursor:first.nextCursor!})),unavailable);
});
test('volume scheduling derives a closed table comparison scope and deduplicates repeated same-scope failures',async t=>{
 const {f,d,monitor,issue}=await failed(t);assert.equal(issue.columnAssetId,null);assert.equal('targetKind'in issue&&issue.targetKind,'table');const stored=await f.as(tx=>tx.selectFrom('quality_monitor_occurrences').selectAll().where('monitor_id','=',monitor.id).executeTakeFirstOrThrow());assert.deepEqual(stored.comparison_scope.family,{kind:'volume',volumeHash:f.binding(d).volumeHash});assert.equal(stored.comparison_scope.targetKind,'table');assert.equal(stored.comparison_scope.columnAssetId,null);assert.equal(stored.comparison_scope_hash,comparisonScopeHash(parseComparisonScope(stored.comparison_scope)));
 const again=await recovery(f,issue);await finish(f,await f.as(tx=>getQualityRun(tx,f.principal(),again.runId)),d);await f.reconcile(monitor.id);const same=await f.issue(issue.id);assert.equal(same.id,issue.id);assert.equal(same.episode,1);assert.equal(same.lastFailure.ordinal,2);assert.equal((await f.issues(monitor.id)).length,1);const before=await f.state();await f.reconcile(monitor.id);assert.deepEqual(await f.state(),before);
});
test('volume linked recovery resolves only current same-scope PASS and a later FAIL reopens with retained history',async t=>{
 const {f,d,monitor,issue}=await failed(t);await f.owner.query(`INSERT INTO "${f.namespace}".observations VALUES(NULL)`);const requested=await recovery(f,issue),done=await finish(f,await f.as(tx=>getQualityRun(tx,f.principal(),requested.runId)),d);assert.equal(done.run.verdict,'PASS');await f.reconcile(monitor.id);const ready=await f.issue(issue.id);assert.equal(ready.recovery?.runId,requested.runId);
 const body=resolveBody(ready),key=randomUUID(),result=await f.command<{issue:QualityIssueView}>('quality.issue.resolve',body,key);assert.equal(result.issue.status,'resolved');const retained=await f.state();assert.deepEqual(await f.command('quality.issue.resolve',body,key),result);assert.deepEqual(await f.state(),retained);
 // Explicit monitor edit creates a new immediate future segment without changing comparison scope.
 const current=await f.monitor(monitor.id),rule=await f.as(tx=>getQualityRule(tx,f.principal(),current.definition.rule.id)),updated=(await f.publishMonitor(rule,await f.monitorDefinition(rule),monitor.id,current.revision)).monitor;await f.owner.query(`DELETE FROM "${f.namespace}".observations WHERE ctid IN(SELECT ctid FROM "${f.namespace}".observations LIMIT 1)`);const o=await schedule(f,updated);await finish(f,await f.as(tx=>getQualityRun(tx,f.principal(),o.runId)),d);await f.reconcile(monitor.id);const reopened=await f.issue(issue.id);assert.equal(reopened.status,'open');assert.equal(reopened.episode,2);assert.equal(reopened.resolution,null);const events=await f.as(tx=>listQualityIssueEvents(tx,f.principal(),issue.id,{limit:100}));assert.deepEqual(events.items.find(e=>e.kind==='resolved')?.resolution,result.issue.resolution);
});
test('volume manual PASS cannot recover an issue and changed rule pin blocks scheduled admissions',async t=>{
 const {f,d,rule,monitor,issue}=await failed(t);await f.owner.query(`INSERT INTO "${f.namespace}".observations VALUES(NULL)`);const manual=(await f.request(rule)).run;assert.equal((await finish(f,manual,d)).run.verdict,'PASS');await f.reconcile(monitor.id);assert.equal((await f.issue(issue.id)).recovery,null);
 // Create a real near-future segment while v1 is current, then change the rule before its due slot.
 const current=await f.monitor(monitor.id),updated=(await f.publishMonitor(rule,await f.monitorDefinition(rule),monitor.id,current.revision)).monitor,prior=(await f.occurrences(monitor.id)).at(-1)!;
 await f.publish(f.definition(6,7),rule.id,1);assert.ok(updated.nextSlotAt);await f.waitUntil(updated.nextSlotAt);const tick=await f.tick(monitor.id);assert.equal(tick.state,'blocked');assert.equal(tick.runId,null);
 const skipped=(await f.occurrences(monitor.id)).at(-1)!;assert.equal(skipped.id,tick.occurrenceId);assert.equal(skipped.ordinal,prior.ordinal+1);assert.equal(skipped.disposition,'skipped');assert.equal(skipped.reason,'RULE_VERSION_CHANGED');assert.equal(skipped.runId,null);
 const view=await f.as(tx=>getQualityMonitor(tx,f.principal(),monitor.id));assert.equal(view.blocked,'RULE_VERSION_CHANGED');await f.unchanged(()=>f.command('quality.issue.recovery.request',{issueId:issue.id,expectedVersion:issue.version,id:randomUUID(),reason:'Must repin explicitly.'}),code('40001'));
});
test('volume request rechecks owner revocation after an observed membership lock wait',async t=>{
 const f=await volumeFixture(t),{rule}=await f.publish(f.definition()),before=await f.state(),pid=(await f.as(tx=>sql<{pid:number}>`select pg_backend_pid() pid`.execute(tx))).rows[0].pid;
 await f.owner.query('BEGIN');await f.owner.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[f.tenant,f.actor]);assert.equal((await f.owner.query('SELECT identity_id FROM memberships WHERE tenant_id=$1 AND identity_id=$2 FOR UPDATE',[f.tenant,f.ruleOwner])).rowCount,1);let failure:unknown,success:unknown;const pending=f.request(rule).then(v=>{success=v},e=>{failure=e});
 try{let observed=false;const until=performance.now()+1200;while(performance.now()<until){if((await f.owner.query('SELECT pg_backend_pid()=ANY(pg_blocking_pids($1)) blocked',[pid])).rows[0].blocked){observed=true;break;}await new Promise(r=>setTimeout(r,10));}assert.equal(observed,true);await f.owner.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.ruleOwner]);await f.owner.query('COMMIT');}catch(e){await f.owner.query('ROLLBACK');throw e;}finally{await pending;}
 assert.equal(success,undefined);assert.equal(code('42501')(failure),true);const after=await f.state();assert.deepEqual(after,before);await f.ownerTx(()=>f.owner.query('UPDATE memberships SET active=true WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.ruleOwner]));
});
