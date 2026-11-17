// SPDX-License-Identifier: Apache-2.0
/** Disposable PostgreSQL storage qualification. Explicit aggregate envelopes do
 * not prove Python execution, HTTP transport or Temporal delivery. The owned
 * source oracle below independently verifies MAX/count/age with PostgreSQL. */
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import test from 'node:test';
import {sql} from '../../packages/db/src/index.ts';
import {Problem} from '../../packages/authz/src/index.ts';
import {assetView} from '../../apps/api/src/repository.ts';
import {QUALITY_BUDGET,type FreshnessMeasurement,type FreshnessRuleDefinition,type QualityMeasurement,type QualityRunView} from '../../packages/domain/src/quality-contracts.ts';
import type {QualityMonitorDefinition} from '../../packages/domain/src/quality-monitoring-contracts.ts';
import {parseQualityDefinition,parseQualityMeasurement,qualityFreshnessVerdict,qualityMicroInstant} from '../../packages/domain/src/quality.ts';
import {getQualityAsset,getQualityRule,getQualityRun,listQualityRuns,publishQualityRule,requestQualityRun,finishQualityRun} from '../../packages/domain/src/quality-service.ts';
import {publishQualityMonitor,monitoringFailure} from '../../packages/domain/src/quality-monitoring-service.ts';
import {freshnessFixture,code,denied,claimed,permissions} from '../fixtures/quality-freshness.ts';

type Fixture=Awaited<ReturnType<typeof freshnessFixture>>;
const unavailable=(e:unknown)=>e instanceof Problem&&e.status===404&&e.code==='QUALITY_UNAVAILABLE';
const invalidPage=(e:unknown)=>e instanceof Problem&&e.status===400&&e.code==='QUALITY_PAGE_INVALID';
const exactError=(state:string,message:string)=>(e:unknown)=>code(state)(e)&&!!e&&typeof e==='object'&&'message'in e&&e.message===message;
function freshness(run:QualityRunView):asserts run is QualityRunView&{kind:'freshness'}{
 assert.equal(run.kind,'freshness');assert.equal(Object.hasOwn(run,'reference'),false);assert.equal(Object.hasOwn(run,'range'),false);
}
async function sqlValid(f:Fixture,kind:'definition'|'measurement',value:unknown){return (await f.owner.query(`SELECT public.gc_quality_freshness_${kind}_valid($1::jsonb) AS valid`,[JSON.stringify(value)])).rows[0].valid as boolean;}
async function sqlVerdict(f:Fixture,m:unknown,b:unknown){return (await f.owner.query('SELECT public.gc_quality_freshness_verdict($1::jsonb,$2::jsonb) AS verdict',[JSON.stringify(m),JSON.stringify(b)])).rows[0].verdict as string|null;}
function pureValid(parse:(v:unknown)=>unknown,value:unknown){try{parse(value);return true;}catch{return false;}}
async function updateTarget(f:Fixture,patch:'acl'|'version'){
 await f.ownerTx(async()=>{
  const query=patch==='acl'?"UPDATE assets SET visibility='restricted',allowed_identities=$3::jsonb,version=version+1 WHERE tenant_id=$1 AND id=$2 RETURNING *":'UPDATE assets SET version=version+1 WHERE tenant_id=$1 AND id=$2 RETURNING *';
  const row=(await f.owner.query(query,patch==='acl'?[f.tenant,f.columnId,JSON.stringify([f.ruleOwner])]:[f.tenant,f.columnId])).rows[0];
  await f.owner.query('INSERT INTO asset_revisions(tenant_id,asset_id,version,snapshot) VALUES($1,$2,$3,$4::jsonb)',[f.tenant,f.columnId,row.version,JSON.stringify(assetView(row))]);
 });
}

test('freshness SQL and TypeScript preserve exact Gregorian UTC6 epochs and refuse rounded or malformed instants',async t=>{
 const f=await freshnessFixture(t);
 const valid=[['0001-01-01T00:00:00.000000Z','-62135596800000000'],['1970-01-01T00:00:00.000001Z','1'],['1969-12-31T23:59:59.999999Z','-1'],['2000-02-29T12:34:56.123456Z','951827696123456'],['9999-12-31T23:59:59.999999Z','253402300799999999']];
 for(const [value,expected] of valid){assert.equal(qualityMicroInstant(value).epochMicroseconds.toString(),expected);assert.equal((await f.owner.query('SELECT public.gc_quality_microseconds($1::jsonb)::text AS value',[JSON.stringify(value)])).rows[0].value?.replace(/\.0+$/,''),expected);}
 for(const value of ['0000-01-01T00:00:00.000000Z','1900-02-29T00:00:00.000000Z','2026-04-31T00:00:00.000000Z','2026-01-01T24:00:00.000000Z','2026-01-01T23:59:60.000000Z','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.0000000Z','2026-01-01T00:00:00.000000+00:00','2026-01-01T00:00:00.000000Z\n','infinity',0,null]){
  assert.throws(()=>qualityMicroInstant(value));assert.equal((await f.owner.query('SELECT public.gc_quality_microseconds($1::jsonb) AS value',[JSON.stringify(value)])).rows[0].value,null);
 }
});

test('freshness closed definition grammar and canonical binding agree across SQL and TypeScript',async t=>{
 const f=await freshnessFixture(t),d=f.definition(3600),expected='b7cd429cfbc4669fdd7ddd36964234b7ec458affbe757af28de26030f063faf9';
 const vectors=[d,f.definition(1,300),f.definition(31536000),...[0,-1,31536001,1.5,'60',null].map(maximumAgeSeconds=>({...d,maximumAgeSeconds})),...[-1,301,0.5,'0'].map(maximumFutureSkewSeconds=>({...d,maximumFutureSkewSeconds})),{...d,clock:'worker'},{...d,comparison:'all-rows'},{...d,nullPolicy:'include'},{...d,invalidTimestampPolicy:'ignore'},{...d,maximumNullBasisPoints:0},{...d,reference:{}}];
 for(const value of vectors)assert.equal(await sqlValid(f,'definition',value),pureValid(parseQualityDefinition,value));
 assert.equal(f.binding(d).freshnessHash,expected);assert.deepEqual((await f.owner.query('SELECT public.gc_quality_freshness_binding($1::jsonb) AS value',[JSON.stringify(d)])).rows[0].value,f.binding(d));
 const changed=f.definition(3601);assert.notEqual(f.binding(changed).freshnessHash,expected);assert.deepEqual((await f.owner.query('SELECT public.gc_quality_freshness_binding($1::jsonb) AS value',[JSON.stringify(changed)])).rows[0].value,f.binding(changed));
});

test('freshness measurement parity keeps microsecond thresholds future coherence and exact five-second clock edges',async t=>{
 const f=await freshnessFixture(t),d=f.definition(60,1),source='2026-01-01T00:00:00.000000Z',wall='2026-01-01T00:00:00.000Z';
 const m=await f.measurement(d,{sourceObservedAt:source,latestObservedAt:'2025-12-31T23:59:00.000000Z',observedStartedAt:wall,observedFinishedAt:wall});
 const values=[m,{...m,ageMicroseconds:'60000001'},{...m,ageMicroseconds:60000000},{...m,ageMicroseconds:'060000000'},{...m,ageMicroseconds:'-0'},{...m,nonFiniteCount:2,unrepresentableCount:1},{...m,futureCount:3},{...m,latestObservedAt:null},{...m,latestObservedAt:'2025-12-31T23:59:00.0000000Z'},{...m,freshnessHash:'x'},{...m,estimatedBytes:67108865},{...m,rawMaximum:'secret'}];
 for(const value of values)assert.equal(await sqlValid(f,'measurement',value),pureValid(parseQualityMeasurement,value));
 for(const [offset,expected] of [['-5000000',true],['5000000',true],['-5000001',false],['5000001',false]] as const){const v=await f.measurement(d,{sourceObservedAt:await f.shift(source,offset),latestObservedAt:source,observedStartedAt:wall,observedFinishedAt:wall});assert.equal(await sqlValid(f,'measurement',v),expected);assert.equal(pureValid(parseQualityMeasurement,v),expected);}
 for(const [latest,futureCount,verdict] of [['2025-12-31T23:59:00.000000Z',0,'PASS'],['2025-12-31T23:58:59.999999Z',0,'FAIL'],['2026-01-01T00:00:01.000000Z',0,'PASS'],['2026-01-01T00:00:01.000001Z',1,'FAIL']] as const){const v=await f.measurement(d,{...m,latestObservedAt:latest,futureCount,ageMicroseconds:(qualityMicroInstant(source).epochMicroseconds-qualityMicroInstant(latest).epochMicroseconds).toString()});assert.equal(await sqlVerdict(f,v,f.binding(d)),verdict);assert.equal(qualityFreshnessVerdict(v,f.binding(d)),verdict);}
 const incoherent=await f.measurement(d,{...m,latestObservedAt:'2026-01-01T00:00:01.000001Z',ageMicroseconds:'-1000001',futureCount:0});assert.equal(await sqlVerdict(f,incoherent,f.binding(d)),null);assert.throws(()=>qualityFreshnessVerdict(incoherent,f.binding(d)));
});

test('freshness independent PostgreSQL MAX oracle proves duration PASS then FAIL with immutable prior evidence',async t=>{
 const f=await freshnessFixture(t),first=await f.as(tx=>publishQualityRule(tx,f.principal(),{id:randomUUID(),expectedVersion:0,definition:f.definition(60)},randomUUID(),'freshness-native'));
 const requested=await f.as(tx=>requestQualityRun(tx,f.principal(),first.rule.id,{id:randomUUID(),ruleVersion:1,ruleHash:first.rule.definitionHash},randomUUID(),'freshness-native')),c=await f.claim(requested.run.id);claimed(c);assert.equal(c.execution.kind,'freshness');assert.deepEqual(c.execution.budget,QUALITY_BUDGET);if(c.execution.kind!=='freshness')throw Error('Wrong native execution family');assert.deepEqual(c.execution.freshness,f.binding());
 // The disposable source rows and fixed clock are independently aggregated by
 // PostgreSQL. These rows are never used as an assertion of worker execution.
 const sourceObservedAt=await f.microNow();await f.owner.query(`UPDATE "${f.namespace}".observations SET code=$1::timestamptz-interval '60 seconds' WHERE code IS NOT NULL`,[sourceObservedAt]);
 const oracle=(await f.owner.query(`SELECT count(*)::integer AS rows,count(*) FILTER(WHERE code IS NULL)::integer AS nulls,to_char(max(code) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS latest,((extract(epoch FROM $1::timestamptz)-extract(epoch FROM max(code)))*1000000)::bigint::text AS age FROM "${f.namespace}".observations`,[sourceObservedAt])).rows[0];assert.equal(oracle.rows,3);assert.equal(oracle.nulls,1);assert.equal(oracle.age,'60000000');
 const wall=sourceObservedAt.slice(0,23)+'Z',m=await f.measurement(f.definition(),{rowCount:oracle.rows,nullCount:oracle.nulls,sourceObservedAt,latestObservedAt:oracle.latest,ageMicroseconds:oracle.age,observedStartedAt:wall,observedFinishedAt:wall});
 const old=(await f.as(tx=>finishQualityRun(tx,requested.run.id,{claimId:c.claimId,attempt:c.attempt,measurement:m}),'site:local')).run;freshness(old);assert.equal(old.verdict,'PASS');assert.deepEqual(old.measurement,m);
 const second=await f.publish(f.definition(59),first.rule.id,1),next=(await f.request(second.rule)).run,c2=await f.claim(next.id);claimed(c2);const failed=(await f.finish(next.id,c2,await f.measurement(f.definition(59)))).run;freshness(failed);assert.equal(failed.verdict,'FAIL');assert.notEqual(failed.freshness.freshnessHash,old.freshness.freshnessHash);
 assert.deepEqual(await f.as(tx=>getQualityRun(tx,f.principal(),old.id)),old);const state=await f.state();assert.equal(state.quality_rule_versions.length,2);assert.equal(state.quality_run_reference_bindings.length,0);assert.equal(state.quality_rule_reference_bindings.length,0);
});

test('freshness empty all-null invalid and future observations retain distinct canonical outcomes',async t=>{
 const f=await freshnessFixture(t),d=f.definition(60,1),{rule}=await f.publish(d);
 const cases:Array<[Partial<FreshnessMeasurement>,'PASS'|'FAIL'|'NO_DATA']>=[
  [{rowCount:0,nullCount:0,latestObservedAt:null},'NO_DATA'],[{rowCount:3,nullCount:3,latestObservedAt:null},'NO_DATA'],
  [{nonFiniteCount:2,latestObservedAt:null},'FAIL'],[{unrepresentableCount:2,latestObservedAt:null},'FAIL'],[{nonFiniteCount:1},'FAIL'],
 ];
 for(const [patch,expected] of cases){const {run}=await f.request(rule),c=await f.claim(run.id);claimed(c);const value=await f.measurement(d,patch),result=(await f.finish(run.id,c,value)).run;freshness(result);assert.equal(result.verdict,expected);assert.deepEqual(result.measurement,value);}
 for(const [offset,futureCount,expected] of [['1000000',0,'PASS'],['1000001',1,'FAIL']] as const){const {run}=await f.request(rule),c=await f.claim(run.id);claimed(c);const source=await f.microNow(),value=await f.measurement(d,{sourceObservedAt:source,latestObservedAt:await f.shift(source,offset),futureCount});assert.equal((await f.finish(run.id,c,value)).run.verdict,expected);}
});

test('freshness rejects stale rule pins reference selectors and undeclared family fields without writes',async t=>{
 const f=await freshnessFixture(t),{rule}=await f.publish(f.definition()),at=await f.now();
 await f.unchanged(()=>f.request(rule,randomUUID(),at),code('22023'));await f.unchanged(()=>f.quality('quality.run.request',{...f.requestBody(rule),ruleHash:'0'.repeat(64)}),code('40001'));
 for(const definition of [{...f.definition(),reference:{}},{...f.definition(),minimum:'0'},{...f.definition(),maximumNullBasisPoints:0}])await f.unchanged(()=>f.publish(definition as FreshnessRuleDefinition),code('22023'));
 await f.publish(f.definition(120),rule.id,1);await f.unchanged(()=>f.request(rule),code('40001'));
});

test('freshness exact retained command replay survives head drift and still requires current authority',async t=>{
 const f=await freshnessFixture(t),id=randomUUID(),key=randomUUID(),definition=f.definition(),one=await f.publish(definition,id,0,key),runKey=randomUUID(),body=f.requestBody(one.rule),receipt=await f.quality('quality.run.request',body,runKey);
 await f.publish(f.definition(120),id,1);const before=await f.state();assert.deepEqual(await f.publish(definition,id,0,key),one);assert.deepEqual(await f.quality('quality.run.request',body,runKey),receipt);assert.deepEqual(await f.state(),before);
 await f.unchanged(()=>f.quality('quality.run.request',{...body,id:randomUUID()},runKey),code('40001'));
 await f.revoke(f.actor,permissions.filter(p=>p!=='quality:read'));await f.unchanged(()=>f.publish(definition,id,0,key),denied);await f.unchanged(()=>f.quality('quality.run.request',body,runKey),denied);
});

test('freshness current requester revocation denies new work and cancels queued and running observations',async t=>{
 const f=await freshnessFixture(t),{rule}=await f.publish(f.definition()),queued=(await f.request(rule)).run,running=(await f.request(rule)).run,c=await f.claim(running.id);claimed(c);const m=await f.measurement();
 await f.revoke(f.actor,permissions.filter(p=>p!=='quality:execute'));await f.unchanged(()=>f.request(rule),denied);
 const stopped=await f.claim(queued.id);assert.equal(stopped.status,'terminal');if(stopped.status!=='terminal')throw Error('Expected refused native claim');assert.equal(stopped.run.status,'cancelled');assert.equal(stopped.run.errorCode,'QUALITY_AUTHORITY_REVOKED');
 const result=(await f.finish(running.id,c,m)).run;assert.equal(result.status,'cancelled');assert.equal(result.measurement,null);assert.equal(result.verdict,null);assert.equal(result.errorCode,'QUALITY_AUTHORITY_REVOKED');
});

test('freshness immutable distinct owner remains eligible at request claim finish and terminal replay',async t=>{
 const f=await freshnessFixture(t),{rule}=await f.publish(f.definition()),queued=(await f.request(rule)).run,running=(await f.request(rule)).run,done=(await f.request(rule)).run,c=await f.claim(running.id),finishedClaim=await f.claim(done.id);claimed(c);claimed(finishedClaim);const measured=await f.measurement();await f.finish(done.id,finishedClaim,measured);
 await f.ownerTx(()=>f.owner.query('UPDATE memberships SET active=false WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.ruleOwner]));await f.unchanged(()=>f.request(rule),denied);
 const stopped=await f.claim(queued.id);assert.equal(stopped.status,'terminal');if(stopped.status!=='terminal')throw Error('Expected refused native claim');assert.equal(stopped.run.errorCode,'QUALITY_AUTHORITY_REVOKED');assert.equal((await f.finish(running.id,c,await f.measurement())).run.errorCode,'QUALITY_AUTHORITY_REVOKED');await f.unchanged(()=>f.finish(done.id,finishedClaim,measured),denied);
});

test('freshness current target ACL prevents reads and cancels work without exposing retained evidence',async t=>{
 const f=await freshnessFixture(t),{rule}=await f.publish(f.definition()),queued=(await f.request(rule)).run,running=(await f.request(rule)).run,c=await f.claim(running.id);claimed(c);await updateTarget(f,'acl');
 for(const read of [()=>f.as(tx=>getQualityRun(tx,f.principal(),running.id)),()=>f.as(tx=>getQualityRule(tx,f.principal(),rule.id)),()=>f.as(tx=>listQualityRuns(tx,f.principal(),rule.id)),()=>f.as(tx=>getQualityAsset(tx,f.principal(),f.columnId))])await f.unchanged(read,unavailable);
 const stopped=await f.claim(queued.id);assert.equal(stopped.status,'terminal');if(stopped.status!=='terminal')throw Error('Expected refused native claim');assert.equal(stopped.run.errorCode,'QUALITY_AUTHORITY_REVOKED');const result=(await f.finish(running.id,c,await f.measurement())).run;assert.equal(result.errorCode,'QUALITY_AUTHORITY_REVOKED');assert.equal(result.measurement,null);
});

test('freshness source configuration and catalog revision drift invalidate exact queued and claimed inputs',async t=>{
 for(const phase of ['claim','finish'])for(const target of ['source','column']){const f=await freshnessFixture(t),{rule}=await f.publish(f.definition()),{run}=await f.request(rule),c=phase==='finish'?await f.claim(run.id):null;if(c)claimed(c);
  if(target==='source')await f.ownerTx(()=>f.owner.query('UPDATE sources SET version=version+1 WHERE tenant_id=$1 AND id=$2',[f.tenant,f.sourceId]));else await updateTarget(f,'version');
  const result=c?(await f.finish(run.id,c,await f.measurement())).run:await f.claim(run.id).then(v=>{assert.equal(v.status,'terminal');if(v.status!=='terminal')throw Error('Expected stale native claim');return v.run;});assert.equal(result.errorCode,'QUALITY_TARGET_STALE');assert.equal(result.status,'failed');assert.equal(result.measurement,null);assert.equal(result.verdict,null);
 }
});

test('freshness claim fencing exact completion replay and cancellation refuse late or substituted results',async t=>{
 const f=await freshnessFixture(t),{rule}=await f.publish(f.definition()),{run}=await f.request(rule),c=await f.claim(run.id);claimed(c);const measured=await f.measurement();assert.equal((await f.claim(run.id)).status,'busy');
 await f.unchanged(()=>f.finish(run.id,{...c,claimId:randomUUID()},measured),code('40001'));await f.unchanged(()=>f.finish(run.id,{...c,attempt:c.attempt+1},measured),code('40001'));
 const first=await f.finish(run.id,c,measured),before=await f.state();assert.deepEqual(await f.finish(run.id,c,measured),first);assert.deepEqual(await f.state(),before);await f.unchanged(()=>f.finish(run.id,c,{...measured,estimatedBytes:25}),code('40001'));
 const next=(await f.request(rule)).run,c2=await f.claim(next.id);claimed(c2);const current=await f.as(tx=>getQualityRun(tx,f.principal(),next.id));const cancelled=await f.quality('quality.run.cancel',{runId:next.id,expectedVersion:current.version,reason:'Cancel owned timestamp observation'});assert.equal(cancelled.run.status,'cancelled');assert.equal(cancelled.run.measurement,null);await f.unchanged(async()=>f.finish(next.id,c2,await f.measurement()),code('40001'));
});

test('freshness malformed hashes ages counts clock envelopes and substituted families roll back completion',async t=>{
 const f=await freshnessFixture(t),{rule}=await f.publish(f.definition()),{run}=await f.request(rule),c=await f.claim(run.id);claimed(c);const m=await f.measurement();
 const invalid:unknown[]=[{...m,freshnessHash:'a'.repeat(64)},{...m,ageMicroseconds:'60000001'},{...m,nonFiniteCount:3},{...m,futureCount:3},{...m,latestObservedAt:null},{...m,sourceObservedAt:await f.shift(m.sourceObservedAt,'6000000'),ageMicroseconds:'66000000'},{...m,futureCount:1},{...m,queryTemplate:'postgresql-range-v1'},{...m,rawMaximum:'source-row'}];
 const {nonFiniteCount,unrepresentableCount,futureCount,sourceObservedAt,latestObservedAt,ageMicroseconds,freshnessHash,...common}=m;invalid.push({...common,kind:'completeness',queryTemplate:'postgresql-completeness-v1'});
 for(const value of invalid)await f.unchanged(()=>f.finish(run.id,c,value as QualityMeasurement),code('22023'));
 assert.equal((await f.finish(run.id,c,await f.measurement())).run.status,'succeeded');
});

test('freshness clock-skew failure is retained without evidence and cannot be injected into older families',async t=>{
 const f=await freshnessFixture(t),{rule}=await f.publish(f.definition()),{run}=await f.request(rule),c=await f.claim(run.id);claimed(c);const body={claimId:c.claimId,attempt:c.attempt,errorCode:'QUALITY_CLOCK_SKEW' as const};
 const failed=await f.as(tx=>finishQualityRun(tx,run.id,body),'site:local');freshness(failed.run);assert.equal(failed.run.status,'failed');assert.equal(failed.run.errorCode,'QUALITY_CLOCK_SKEW');assert.equal(failed.run.measurement,null);assert.equal(failed.run.verdict,null);const before=await f.state();assert.deepEqual(await f.as(tx=>finishQualityRun(tx,run.id,body),'site:local'),failed);assert.deepEqual(await f.state(),before);
 const {maximumAgeSeconds,maximumFutureSkewSeconds,comparison,clock,nullPolicy,invalidTimestampPolicy,...base}=f.definition(),older=await f.publish({...base,kind:'completeness',maximumNullBasisPoints:0}),oldRun=(await f.request(older.rule)).run,oldClaim=await f.claim(oldRun.id);claimed(oldClaim);
 await f.unchanged(()=>f.as(tx=>finishQualityRun(tx,oldRun.id,{claimId:oldClaim.claimId,attempt:oldClaim.attempt,errorCode:'QUALITY_CLOCK_SKEW'}),'site:local'),code('22023'));
 const terminal=await f.claim(run.id);assert.equal(terminal.status,'terminal');if(terminal.status==='terminal')assert.deepEqual(terminal.run,failed.run);
});

test('freshness historical readers retain authorized evidence while cursors and hidden successor heads stay scoped',async t=>{
 const f=await freshnessFixture(t),one=await f.publish(f.definition()),runs:string[]=[];
 for(let i=0;i<3;i++){const {run}=await f.request(one.rule);runs.push(run.id);}
 const ref=await f.publishReference(f.proposal({audience:{visibility:'restricted',allowedIdentityIds:[f.actor,f.reviewer,f.ruleOwner].sort()}})),old=f.definition();
 await f.publish({formatVersion:1,kind:'reference-allowed-values',target:old.target,name:old.name,purpose:old.purpose,ownerId:old.ownerId,severity:old.severity,maximumInvalidBasisPoints:0,reference:{setId:ref.proposal.setId,selection:'effective-at-run',codeStatus:'active'},comparison:'utf8-exact',nullPolicy:'exclude'},one.rule.id,1);
 const historic=await f.as(tx=>getQualityRule(tx,f.principal(f.reader),one.rule.id,1),f.reader);assert.equal(historic.currentVersion,null);assert.equal(historic.definition.kind,'freshness');
 const first=await f.as(tx=>listQualityRuns(tx,f.principal(f.reader),one.rule.id,{limit:1}),f.reader);assert.equal(first.items.length,1);assert.ok(first.nextCursor);freshness(first.items[0]);
 const next=await f.as(tx=>listQualityRuns(tx,f.principal(f.reader),one.rule.id,{limit:1,cursor:first.nextCursor!}),f.reader);assert.equal(next.items.length,1);assert.notEqual(next.items[0].id,first.items[0].id);
 await f.unchanged(()=>f.as(tx=>listQualityRuns(tx,f.principal(),one.rule.id,{limit:1,cursor:first.nextCursor!})),invalidPage);await f.unchanged(()=>f.as(tx=>listQualityRuns(tx,f.principal(f.reader),one.rule.id,{limit:2,cursor:first.nextCursor!}),f.reader),invalidPage);
 await f.unchanged(()=>f.as(tx=>getQualityRun(tx,f.principal(f.outsider,f.foreign),runs[0]),f.outsider,f.foreign),unavailable);await f.unchanged(()=>f.quality('quality.run.request',f.requestBody(one.rule),randomUUID(),f.reader),denied);
 await f.revoke(f.reader,['catalog:read','reference:read']);await f.unchanged(()=>f.as(tx=>listQualityRuns(tx,f.principal(f.reader),one.rule.id,{limit:1,cursor:first.nextCursor!}),f.reader),e=>e instanceof Problem&&e.status===403);
});

test('freshness request claim and finish block on the sorted owner before requester and target locks',async t=>{
 const f=await freshnessFixture(t),{rule}=await f.publish(f.definition()),probe=await f.connection(),pid=(await f.as(tx=>sql<{pid:number}>`select pg_backend_pid() as pid`.execute(tx))).rows[0].pid;assert.ok(f.ruleOwner<f.actor);
 async function blocked<T>(operation:()=>Promise<T>){await f.owner.query('BEGIN');await f.owner.query('SELECT id FROM identities WHERE id=$1 FOR UPDATE',[f.ruleOwner]);let value:T|undefined,error:unknown;const work=operation().then(v=>{value=v},e=>{error=e});try{
   let observed=false;const until=performance.now()+1500;while(performance.now()<until){if((await f.owner.query('SELECT pg_backend_pid()=ANY(pg_blocking_pids($1)) AS blocked',[pid])).rows[0].blocked){observed=true;break;}await new Promise(r=>setTimeout(r,10));}assert.equal(observed,true,'Actual independent connection blocks on the exact owner holder');
   await probe.query('BEGIN');try{
    await probe.query("SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[f.tenant,f.actor]);
    assert.equal((await probe.query('SELECT id FROM identities WHERE id=$1 FOR UPDATE NOWAIT',[f.actor])).rowCount,1);
    assert.equal((await probe.query('SELECT id FROM assets WHERE tenant_id=$1 AND id=$2 FOR UPDATE NOWAIT',[f.tenant,f.columnId])).rowCount,1);
   }finally{await probe.query('ROLLBACK');}
  }finally{await f.owner.query('ROLLBACK');await work;}if(error)throw error;assert.ok(value);return value;
 }
 const queued=await blocked(()=>f.request(rule)),c=await blocked(()=>f.claim(queued.run.id));claimed(c);const m=await f.measurement();assert.equal((await blocked(()=>f.finish(queued.run.id,c,m))).run.status,'succeeded');
});

test('freshness private helpers direct writes and foreign tenant rows remain inaccessible to the runtime role',async t=>{
 const f=await freshnessFixture(t),{rule}=await f.publish(f.definition()),{run}=await f.request(rule),m=await f.measurement();
 for(const table of ['quality_rules','quality_rule_versions','quality_runs'])await f.unchanged(()=>f.as(tx=>sql`delete from ${sql.table(table)} where tenant_id=${f.tenant}::uuid`.execute(tx)),code('42501'));
 for(const [name,value] of [['gc_quality_microseconds',m.sourceObservedAt],['gc_quality_freshness_settings_valid',f.binding()],['gc_quality_freshness_definition_valid',f.definition()],['gc_quality_freshness_binding',f.definition()],['gc_quality_freshness_measurement_valid',m]] as const)await f.unchanged(()=>f.as(tx=>sql`select ${sql.ref('public.'+name)}(${JSON.stringify(value)}::jsonb)`.execute(tx)),code('42501'));
 await f.unchanged(()=>f.as(tx=>sql`select public.gc_quality_freshness_verdict(${JSON.stringify(m)}::jsonb,${JSON.stringify(f.binding())}::jsonb)`.execute(tx)),code('42501'));
 assert.equal((await f.as(tx=>sql`select id from quality_runs`.execute(tx),f.outsider,f.foreign)).rows.length,0);await f.unchanged(()=>f.as(tx=>getQualityRun(tx,f.principal(f.outsider,f.foreign),run.id),f.outsider,f.foreign),unavailable);
});

test('freshness scheduling admits the exact retained manual rule and identical worker execution binding',async t=>{
 const f=await freshnessFixture(t),{rule}=await f.publish(f.definition()),at=Date.parse(await f.now());
 const definition:QualityMonitorDefinition={formatVersion:1,name:'Scheduled freshness',purpose:'Exact same governed latest timestamp execution binding.',rule:{id:rule.id,version:rule.version,definitionHash:rule.definitionHash},executorId:f.actor,authorizationExpiresAt:new Date(at+3600000).toISOString(),schedule:{kind:'fixed-interval',timeZone:'UTC',startsAt:new Date(at+1500).toISOString(),endsAt:null,intervalSeconds:60,lateGraceSeconds:59,missedSlots:'skip',overlap:'skip'},maintenance:[],silences:[],routing:{channel:'in-app',ownerId:f.reviewer,recipientIds:[f.reviewer]},issue:{category:'data-quality',acknowledgeWithinSeconds:60,resolveWithinSeconds:600},recoveryMaximumAgeSeconds:600,retry:{policy:'quality-run-v1'}};
 const body={id:randomUUID(),expectedRevision:0,definition};
 const created=await f.as(tx=>publishQualityMonitor(tx,f.principal(),body,randomUUID(),'freshness-native'));assert.equal(created.monitor.id,body.id);assert.deepEqual(created.monitor.definition.rule,definition.rule);
 await f.waitUntil(definition.schedule.startsAt);
 const work=await f.as(async tx=>(await sql<{value:any}>`select public.gc_quality_monitor_tick(${body.id}::uuid) value`.execute(tx)).rows[0].value,'site:local');assert.equal(work.state,'advanced');assert.ok(work.runId);
 const scheduled=await f.claim(work.runId);claimed(scheduled);assert.equal(scheduled.execution.kind,'freshness');if(scheduled.execution.kind!=='freshness')assert.fail('Freshness claim required');assert.deepEqual(scheduled.execution.freshness,f.binding());
 const current=await f.as(tx=>getQualityRule(tx,f.principal(),rule.id));assert.equal(current.definition.kind,'freshness');const {run}=await f.request(current),manual=await f.claim(run.id);claimed(manual);assert.deepEqual(scheduled.execution,manual.execution);
});
