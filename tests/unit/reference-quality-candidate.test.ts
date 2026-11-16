// SPDX-License-Identifier: Apache-2.0
/** Private host-only parser/protocol and compiled SQL tests. No DB/source execution. */
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createHash} from 'node:crypto';
import Fastify from 'fastify';
import {Value} from '@sinclair/typebox/value';
import {Kysely,DummyDriver,PostgresAdapter,PostgresIntrospector,PostgresQueryCompiler,type CompiledQuery,type DatabaseConnection,type QueryResult} from 'kysely';
import type {Tx} from '../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../packages/authz/src/index.ts';
import {QUALITY_BUDGET} from '../../packages/domain/src/quality-contracts.ts';
import {parseQualityDefinition,parseQualityRunInput,parseQualityMeasurement,qualityVerdict,parseQualityRunView,parseQualityRuleView,parseQualityClaim,parseQualityExecution,parseQualityReferenceBinding,parseQualityReferenceMetadata,qualityReferenceBindingHash} from '../../packages/domain/src/quality.ts';
import {visibleAudit} from '../../apps/api/src/repository.ts';
import {qualityHttp} from '../../apps/api/src/quality.ts';
import {getQualityAsset,getQualityRule,listQualityRuns,getQualityRun,requestQualityRun,qualityFailure} from '../../packages/domain/src/quality-service.ts';
import {modelPersistence} from '../../packages/domain/src/model-service.ts';
import {createQualityTransport} from '../../apps/workflow-worker/src/quality-http.ts';
import {createQualityActivity} from '../../apps/site-runner/src/quality-activity.ts';
const id=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const stamp='2026-11-17T00:00:00.000Z';
const preimage={asOf:stamp,codeStatus:'active' as const,codes:['A','B','a'],publicationHash:'a'.repeat(64),setId:id(6),version:2};
const binding={...preimage,bindingHash:createHash('sha256').update(JSON.stringify(preimage)).digest('hex')};
const {codes:_,...metadata}=binding;
const rule={formatVersion:1 as const,kind:'reference-allowed-values' as const,target:{tableAssetId:id(1),columnAssetId:id(2)},name:'Allowed codes',purpose:'Govern exact values',ownerId:id(3),severity:'warning' as const,maximumInvalidBasisPoints:2500,reference:{setId:id(6),selection:'effective-at-run' as const,codeStatus:'active' as const},comparison:'utf8-exact' as const,nullPolicy:'exclude' as const};
const view={id:id(5),version:1,currentVersion:2,definition:rule,definitionHash:modelPersistence.hash(rule),createdAt:stamp,createdBy:id(3)};
const measurement={formatVersion:1 as const,kind:'reference-allowed-values' as const,strategy:'exact-bounded-role-scope' as const,rowCount:20,nullCount:4,invalidCount:4,referenceBindingHash:binding.bindingHash,observedStartedAt:stamp,observedFinishedAt:'2026-11-17T00:00:00.100Z',elapsedMs:100,sourceVersion:'180001',adapterVersion:'1' as const,queryTemplate:'postgresql-reference-allowed-values-v1' as const,estimatedCost:3,estimatedBytes:100};
const queued={id:id(4),ruleId:id(5),ruleVersion:1,ruleHash:view.definitionHash,requesterId:id(3),columnAssetId:id(2),tableAssetId:id(1),status:'queued' as const,version:1,attempt:0,createdAt:stamp,startedAt:null,finishedAt:null,expiresAt:'2026-11-17T00:10:00.000Z',measurement:null,verdict:null,errorCode:null,kind:'reference-allowed-values' as const,reference:metadata};
const succeeded={...queued,status:'succeeded' as const,version:3,attempt:1,startedAt:stamp,finishedAt:measurement.observedFinishedAt,measurement,verdict:'PASS' as const};
const execution={formatVersion:1 as const,kind:'reference-allowed-values' as const,target:{databaseOid:'16384',schemaOid:'2200',relationOid:'16385',attributeNumber:2,schemaName:'public',tableName:'quality_fixture',columnName:'code',dataType:'text'},budget:{...QUALITY_BUDGET},reference:binding};
const source={connectorId:'postgresql' as const,host:'source-postgres',port:5432,database:'harbor',schema:'public',secretRef:'synthetic-private-reference'};
const claim={status:'claimed' as const,runId:id(4),claimId:id(7),attempt:1,leaseExpiresAt:new Date(Date.now()+600000).toISOString(),source,execution};
const code=(c:string)=>(e:unknown)=>e instanceof Problem&&e.code===c;
const invalid=(work:()=>unknown)=>assert.throws(work,code('QUALITY_INPUT_INVALID'));
const json=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers:{'content-type':'application/json'}});

test('reference definitions preserve closed selection, normalization and independent threshold',()=>{
 assert.deepEqual(parseQualityDefinition({...rule,name:'  Cafe\u0301  '}),{...rule,name:'Café'});
 for(const value of [{...rule,reference:{...rule.reference,setId:'00000000-0000-0000-0000-000000000000'}},{...rule,maximumNullBasisPoints:0},{...rule,maximumInvalidBasisPoints:10001},{...rule,comparison:'case-fold'},{...rule,nullPolicy:'include'},{...rule,reference:{...rule.reference,version:1}},{...rule,reference:{...rule.reference,codeStatus:'deprecated'}},{...rule,sql:'SELECT code'}])invalid(()=>parseQualityDefinition(value));
 assert.ok(Value.Check(qualityHttp.definition,rule));assert.equal(Value.Check(qualityHttp.definition,{...rule,maximumNullBasisPoints:0}),false);
});
test('binding hash uses exact canonical retained bytes and never normalizes, sorts or deduplicates codes',()=>{
 assert.equal(qualityReferenceBindingHash(binding),binding.bindingHash);assert.deepEqual(parseQualityReferenceBinding(binding),binding);
 assert.deepEqual(parseQualityReferenceMetadata(metadata),metadata);
 for(const codes of [['a','A'],['A','A'],['A '],['é'],['A\n'],['a'.repeat(129)],Array(257).fill('A')])invalid(()=>parseQualityReferenceBinding({...binding,codes}));
 for(const value of [{...binding,bindingHash:'b'.repeat(64)},{...binding,publicationHash:'b'.repeat(64)},{...binding,asOf:'2026-02-30T00:00:00.000Z'},{...binding,asOf:'0000-01-01T00:00:00.000Z'},{...binding,setId:'00000000-0000-0000-0000-000000000000'},{...binding,extra:true}])invalid(()=>parseQualityReferenceBinding(value));
 invalid(()=>parseQualityReferenceMetadata(binding));
 const empty={...preimage,codes:[]};assert.deepEqual(parseQualityReferenceBinding({...empty,bindingHash:qualityReferenceBindingHash(empty)}).codes,[]);
});
test('binding snapshot refuses accessors, sparse arrays, symbols and inherited fields without execution',()=>{
 let reads=0;const codes=['A'];Object.defineProperty(codes,'0',{enumerable:true,get(){reads++;return 'A';}});
 invalid(()=>parseQualityReferenceBinding({...binding,codes}));assert.equal(reads,0);
 invalid(()=>parseQualityReferenceBinding({...binding,codes:new Array(1)}));
 const symbols=Object.assign(['A'],{[Symbol('private')]:'value'});invalid(()=>parseQualityReferenceBinding({...binding,codes:symbols}));
 invalid(()=>parseQualityReferenceBinding(Object.create(binding)));
 const detached=parseQualityReferenceBinding(binding);assert.notEqual(detached.codes,binding.codes);detached.codes.push('z');assert.deepEqual(binding.codes,['A','B','a']);
});
test('request hash input preserves omitted asOf and exact explicit instant without defaulting a clock',()=>{
 const input={id:id(4),ruleVersion:1,ruleHash:view.definitionHash};assert.deepEqual(parseQualityRunInput(input),input);
 assert.deepEqual(parseQualityRunInput({...input,referenceAsOf:stamp}),{...input,referenceAsOf:stamp});
 for(const referenceAsOf of [null,undefined,stamp.replace('.000Z','Z'),'2026-11-17T00:00:00.000+00:00'])invalid(()=>parseQualityRunInput({...input,referenceAsOf}));
});
test('allowed values verdict uses nonnull denominator with exact integer boundaries and empty set evidence',()=>{
 assert.equal(qualityVerdict(measurement,2500),'PASS');assert.equal(qualityVerdict(measurement,2499),'FAIL');
 assert.equal(qualityVerdict({...measurement,rowCount:20,nullCount:20,invalidCount:0},0),'NO_DATA');
 assert.equal(qualityVerdict({...measurement,rowCount:0,nullCount:0,invalidCount:0},0),'NO_DATA');
 assert.equal(qualityVerdict({...measurement,invalidCount:16},9999),'FAIL');assert.equal(qualityVerdict({...measurement,invalidCount:16},10000),'PASS');
 invalid(()=>parseQualityMeasurement({...measurement,invalidCount:17}));invalid(()=>parseQualityMeasurement({...measurement,invalidCount:0.5}));
 invalid(()=>parseQualityMeasurement({...measurement,queryTemplate:'postgresql-completeness-v1'}));invalid(()=>parseQualityMeasurement({...measurement,codes:['A']}));
});
test('reference run requires code-free metadata in every state and exact measurement family/hash',()=>{
 assert.deepEqual(parseQualityRunView(queued),queued);assert.deepEqual(parseQualityRunView(succeeded),succeeded);
 const {kind,reference,...legacy}=queued;assert.deepEqual(parseQualityRunView(legacy),legacy);
 for(const value of [{...legacy,reference},{...legacy,kind},{...queued,reference:binding},{...queued,kind:'completeness'},{...succeeded,measurement:{...measurement,referenceBindingHash:'c'.repeat(64)}},{...succeeded,measurement:{...measurement,rowCount:20,nullCount:20,invalidCount:0},verdict:'PASS'},{...succeeded,verdict:'NO_DATA'}])invalid(()=>parseQualityRunView(value));
 assert.equal(parseQualityRunView({...succeeded,measurement:{...measurement,rowCount:20,nullCount:20,invalidCount:0},verdict:'NO_DATA'}).verdict,'NO_DATA');
 assert.equal(Value.Check(qualityHttp.run,{...queued,reference:binding}),false);assert.ok(Value.Check(qualityHttp.run,queued));assert.ok(Value.Check(qualityHttp.run,legacy));
});
test('historical rule view redacts hidden head without fabricating a current version',()=>{
 assert.equal(parseQualityRuleView({...view,currentVersion:null}).currentVersion,null);assert.ok(Value.Check(qualityHttp.rule,{...view,currentVersion:null}));
 invalid(()=>parseQualityRuleView({...view,version:2,currentVersion:1}));
 let reads=0;const definition={...rule};Object.defineProperty(definition,'name',{enumerable:true,get(){reads++;return 'bad';}});invalid(()=>parseQualityRuleView({...view,definition}));assert.equal(reads,0);
});
test('private execution and claim require the entire verified retained binding',()=>{
 assert.deepEqual(parseQualityExecution(execution),execution);assert.deepEqual(parseQualityClaim(claim),claim);
 invalid(()=>parseQualityExecution({...execution,reference:metadata}));invalid(()=>parseQualityExecution({...execution,reference:{...binding,bindingHash:'b'.repeat(64)}}));
 invalid(()=>parseQualityExecution({...execution,kind:'completeness'}));
 const parsed=parseQualityClaim(claim);assert.equal(parsed.status,'claimed');if(parsed.status==='claimed'){assert.notEqual(parsed.source,source);assert.notEqual(parsed.execution,execution);}
});
test('64KiB claim transport accepts largest closed binding and rejects old-family padded frames',async()=>{
 const codes=Array.from({length:256},(_,i)=>String(i).padStart(3,'0')+'a'.repeat(125)),large={...preimage,codes};
 const bigClaim={...claim,execution:{...execution,reference:{...large,bindingHash:qualityReferenceBindingHash(large)}}};
 const bytes=Buffer.byteLength(JSON.stringify(bigClaim));assert.ok(bytes>32768&&bytes<65536);
 const request=createQualityTransport({url:'http://canonical.test',token:'synthetic',fetch:async()=>json(bigClaim)});
 assert.equal((await request(`/internal/quality-runs/${id(4)}/claim`,{body:{claimId:id(7)},maximum:65536,timeoutMs:100})).status,200);
 const {reference,...oldExecution}=execution;const oldClaim={...claim,execution:{...oldExecution,kind:'completeness'}};
 for(const raw of [' '.repeat(17000)+JSON.stringify(oldClaim),' '.repeat(65536)+JSON.stringify(bigClaim),JSON.stringify({...bigClaim,extra:'hidden'})]){
  const invalidTransport=createQualityTransport({url:'http://canonical.test',token:'synthetic',fetch:async()=>new Response(raw,{headers:{'content-type':'application/json'}})});
  await assert.rejects(invalidTransport(`/internal/quality-runs/${id(4)}/claim`,{body:{claimId:id(7)},maximum:65536,timeoutMs:100}),/QUALITY_PROTOCOL_INVALID/);
 }
});
test('site activity rejects substituted measurement binding without sending codes or diagnostics to Temporal',async()=>{
 for(const substituted of [false,true]){const calls:{url:string;body:any}[]=[];
  const activity=createQualityActivity({apiUrl:'http://canonical.test',apiToken:'synthetic',workerUrl:'http://worker.test',workerToken:'synthetic',tenants:new Set([id(8)]),claimId:()=>id(7),fetch:async(url,init)=>{
   calls.push({url:String(url),body:JSON.parse(String(init?.body))});if(String(url).endsWith('/claim'))return json(claim);
   if(String(url).endsWith('/quality'))return json({measurement:substituted?{...measurement,referenceBindingHash:'b'.repeat(64)}:measurement});
   return json({run:substituted?{...succeeded,status:'failed',measurement:null,verdict:null,errorCode:'QUALITY_SOURCE_FAILED'}:succeeded});
  }});
  const result=await activity({tenantId:id(8),runId:id(4)});assert.deepEqual(Object.keys(result).sort(),['retryAt','runId','status','version']);
  assert.equal(result.status,substituted?'failed':'succeeded');assert.deepEqual(calls[1].body.execution.reference,binding);
  assert.equal(JSON.stringify(calls[2].body).includes('codes'),false);assert.equal(JSON.stringify(result).includes('reference'),false);
  if(substituted)assert.deepEqual(calls[2].body,{claimId:id(7),attempt:1,errorCode:'QUALITY_SOURCE_FAILED'});
 }
});

type Query=CompiledQuery<unknown>;
const principal:Principal={tenantId:id(8),id:id(3),name:'Synthetic author',permissions:['catalog:read','quality:read','quality:execute']};
function recording(respond:(q:Query)=>Record<string,unknown>[]){const calls:Query[]=[];
 const connection:DatabaseConnection={async executeQuery<R>(q:CompiledQuery):Promise<QueryResult<R>>{calls.push(q);return {rows:respond(q) as R[]};},async *streamQuery<R>():AsyncIterableIterator<QueryResult<R>>{throw new Error('Host fixture has no stream');}};
 class Driver extends DummyDriver{override async acquireConnection(){return connection;}}
 const db=new Kysely<Record<string,any>>({dialect:{createAdapter:()=>new PostgresAdapter(),createDriver:()=>new Driver(),createIntrospector:d=>new PostgresIntrospector(d),createQueryCompiler:()=>new PostgresQueryCompiler()}});
 return {tx:db as unknown as Tx,calls,close:()=>db.destroy()};}
const member=(q:Query)=>q.sql.includes('from "memberships"')?[{permissions:principal.permissions}]:[];
test('service uses exact rule version and per-run authority before LIMIT, including hidden-head historical admission',async()=>{
 const previous=process.env.SESSION_KEY;process.env.SESSION_KEY='synthetic-reference-quality-secret-32';
 const f=recording(q=>q.sql.includes('select 1 from public.quality_rules')?[{ok:1}]:q.sql.includes('gc_quality_run_view')?[{value:queued}]:q.sql.includes('gc_quality_rule_view')?[{value:{...view,currentVersion:null}}]:member(q));
 try{
  assert.equal((await getQualityRule(f.tx,principal,id(5),1)).currentVersion,null);
  assert.equal((await listQualityRuns(f.tx,principal,id(5),{limit:1})).items[0].id,id(4));assert.equal((await getQualityRun(f.tx,principal,id(4))).id,id(4));
  const admission=f.calls.find(q=>q.sql.includes('select 1 from public.quality_rules'))!;assert.match(admission.sql,/exists\(select 1 from public\.quality_rule_versions/);assert.match(admission.sql,/gc_quality_rule_visible\(v.rule_id,v.version/);assert.equal(admission.sql.includes('current_version'),false);
  const selected=f.calls.find(q=>q.sql.includes('gc_quality_rule_view'))!;assert.match(selected.sql,/gc_quality_rule_visible\(r.id,\$\d+,/);assert.equal(selected.parameters.filter(v=>v===1).length,2);
  const page=f.calls.find(q=>q.sql.includes('gc_quality_run_view')&&q.sql.includes('limit'))!;assert.match(page.sql,/gc_quality_run_visible\(q.id,\$\d+::uuid\).*order by q.id limit/s);assert.equal(page.sql.includes('gc_quality_visible('),false);
 }finally{await f.close();if(previous===undefined)delete process.env.SESSION_KEY;else process.env.SESSION_KEY=previous;}
});
test('service passes unresolved request unchanged and rejects substituted resolved-asOf receipts',async()=>{
 const input={id:id(4),ruleVersion:1,ruleHash:view.definitionHash};
 for(const asOf of [undefined,stamp]){const f=recording(q=>q.sql.includes('gc_quality_command')?[{value:{run:queued}}]:member(q));
  try{await requestQualityRun(f.tx,principal,id(5),{...input,...(asOf?{referenceAsOf:asOf}:{})},'synthetic-quality-key',id(9));const command=f.calls.find(q=>q.sql.includes('gc_quality_command'))!;assert.deepEqual(JSON.parse(command.parameters[2] as string),{ruleId:id(5),...input,...(asOf?{referenceAsOf:asOf}:{})});assert.equal(f.calls.some(q=>q.sql.includes('gc_reference_')),false);}finally{await f.close();}
 }
 const f=recording(q=>q.sql.includes('gc_quality_command')?[{value:{run:queued}}]:member(q));try{await assert.rejects(requestQualityRun(f.tx,principal,id(5),{...input,referenceAsOf:'2026-11-16T00:00:00.000Z'},'synthetic-quality-key',id(9)),code('QUALITY_STORAGE_INVALID'));}finally{await f.close();}
});
test('new no-effective-reference failure is finite and existing unsupported target mapping remains intact',()=>{
 assert.equal(qualityFailure({code:'0A000',message:'QUALITY_REFERENCE_UNAVAILABLE'}).code,'QUALITY_REFERENCE_UNAVAILABLE');
 assert.equal(qualityFailure({code:'0A000',message:'private source detail'}).code,'QUALITY_TARGET_UNSUPPORTED');
});

test('actual candidate audit query authorizes exact immutable rule or retained run before surrounding pagination',async()=>{
 const f=recording(()=>[]);try{
  await visibleAudit(f.tx,principal).limit(25).execute();const q=f.calls[0];
  assert.match(q.sql,/audit.action='quality.rule_published'/);assert.match(q.sql,/qv.version::text=audit.changes->>'resourceVersion'/);
  assert.match(q.sql,/qv.definition_hash=audit.changes->>'definitionHash'/);assert.match(q.sql,/gc_quality_rule_visible\(qr.id,qv.version,/);
  assert.match(q.sql,/qrun.id::text=audit.changes->>'runId'/);assert.match(q.sql,/gc_quality_run_visible\(qrun.id,/);
  assert.equal(q.sql.includes('gc_quality_visible('),false);assert.ok(q.parameters.includes('quality.%'));assert.match(q.sql,/limit \$\d+$/);
 }finally{await f.close();}
});

test('actual Fastify serializer preserves the exact two closed run shapes without exposing binding codes',async()=>{
 const app=Fastify({logger:false});let value:unknown=queued;
 app.get('/run',{schema:{response:{200:qualityHttp.run}}},async()=>value);await app.ready();
 try{for(const run of [queued,succeeded]){value=run;const response=await app.inject('/run');assert.equal(response.statusCode,200);assert.deepEqual(response.json(),run);assert.equal(Object.hasOwn(response.json().reference,'codes'),false);}
  const {kind,reference,...completeness}=queued;value=completeness;assert.deepEqual((await app.inject('/run')).json(),completeness);
 }finally{await app.close();}
});
