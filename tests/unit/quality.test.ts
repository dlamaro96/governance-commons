// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {Value} from '@sinclair/typebox/value';
import {QUALITY_BUDGET,type CompletenessRuleDefinition,type QualityMeasurement,type QualityTarget,type QualityRunView} from '../../packages/domain/src/quality-contracts.ts';
import {parseQualityDefinition,parseQualityPublish,parseQualityRunInput,parseQualityMeasurement,qualityVerdict,parseQualityRunView,parseQualityCompletion,parseQualityClaim,parseQualityExecution} from '../../packages/domain/src/quality.ts';
import {parseQualityRequestJSON,qualityRawQuery,qualityHttp} from '../../apps/api/src/quality.ts';
import {qualityFailure} from '../../packages/domain/src/quality-service.ts';
const id=(n:number)=>`10000000-0000-4000-8000-${String(n).padStart(12,'0')}`;
const rule:CompletenessRuleDefinition={formatVersion:1,kind:'completeness',target:{tableAssetId:id(1),columnAssetId:id(2)},name:'Email completeness',purpose:'Explain contact coverage',ownerId:id(3),severity:'warning',maximumNullBasisPoints:2500};
const measurement:QualityMeasurement={formatVersion:1,kind:'completeness',strategy:'exact-bounded-role-scope',rowCount:20,nullCount:5,observedStartedAt:'2026-11-16T00:00:00.000Z',observedFinishedAt:'2026-11-16T00:00:00.100Z',elapsedMs:100,sourceVersion:'180001',adapterVersion:'1',queryTemplate:'postgresql-completeness-v1',estimatedCost:3.5,estimatedBytes:100};
const queued:QualityRunView={id:id(4),ruleId:id(5),ruleVersion:1,ruleHash:'a'.repeat(64),requesterId:id(3),columnAssetId:id(2),tableAssetId:id(1),status:'queued',version:1,attempt:0,createdAt:'2026-11-16T00:00:00.000Z',startedAt:null,finishedAt:null,expiresAt:'2026-11-16T00:10:00.000Z',measurement:null,verdict:null,errorCode:null};
const invalid=(work:()=>unknown)=>assert.throws(work,error=>error instanceof Error&&error.message==='Provide exactly the declared quality fields and values.');

test('completeness definitions normalize human text without coercing machine fields',()=>{
 assert.deepEqual(parseQualityDefinition({...rule,name:'  Cafe\u0301  ',purpose:'  Purpose\nnext line  '}),{...rule,name:'Café',purpose:'Purpose\nnext line'});
 for(const v of [{...rule,maximumNullBasisPoints:'2500'},{...rule,maximumNullBasisPoints:-0},{...rule,maximumNullBasisPoints:10001},{...rule,maximumNullBasisPoints:0.5},
  {...rule,target:{...rule.target,columnAssetId:rule.target.tableAssetId}},{...rule,name:'x\ny'},{...rule,name:'x'.repeat(241)},{...rule,purpose:'\ud800'},
  {...rule,ownerId:id(3).toUpperCase()+'x'},{...rule,sql:'SELECT 1'},{...rule,severity:'urgent'}])invalid(()=>parseQualityDefinition(v));
 for(const k of Object.keys(rule)){const v:any={...rule};delete v[k];invalid(()=>parseQualityDefinition(v));}
 let reads=0;const getter={...rule};Object.defineProperty(getter,'name',{enumerable:true,get(){reads++;return 'secret';}});invalid(()=>parseQualityDefinition(getter));assert.equal(reads,0);
});
test('publish and run pins are closed, bounded and preserve precise selected versions',()=>{
 assert.deepEqual(parseQualityPublish({id:id(5),expectedVersion:0,definition:rule}),{id:id(5),expectedVersion:0,definition:rule});
 for(const v of [{id:id(5),expectedVersion:2147483647,definition:rule},{id:id(5),expectedVersion:-1,definition:rule},{id:id(5),expectedVersion:0,definition:rule,tenantId:id(9)}])invalid(()=>parseQualityPublish(v));
 assert.deepEqual(parseQualityRunInput({id:id(4),ruleVersion:3,ruleHash:'b'.repeat(64)}),{id:id(4),ruleVersion:3,ruleHash:'b'.repeat(64)});
 invalid(()=>parseQualityRunInput({id:id(4),ruleVersion:0,ruleHash:'b'.repeat(64)}));invalid(()=>parseQualityRunInput({id:id(4),ruleVersion:3,ruleHash:'b'.repeat(63)}));
});
test('exact integer verdicts handle threshold boundary and zero observations separately',()=>{
 assert.equal(qualityVerdict(measurement,2500),'PASS');assert.equal(qualityVerdict(measurement,2499),'FAIL');
 assert.equal(qualityVerdict({...measurement,rowCount:0,nullCount:0},0),'NO_DATA');
 assert.equal(qualityVerdict({...measurement,rowCount:100000,nullCount:99999},9999),'FAIL');
 assert.equal(qualityVerdict({...measurement,rowCount:100000,nullCount:99990},9999),'PASS');
});
test('measurements refuse arbitrary values, impossible counts, timestamps and budget overflow',()=>{
 assert.deepEqual(parseQualityMeasurement(measurement),measurement);
 for(const v of [{...measurement,rowCount:100001},{...measurement,nullCount:21},{...measurement,nullCount:1.5},{...measurement,rows:[{email:'private'}]},
  {...measurement,sourceVersion:'PostgreSQL 18'},{...measurement,observedStartedAt:'2026-02-30T00:00:00.000Z'},{...measurement,observedFinishedAt:'2026-11-15T23:59:59.000Z'},
  {...measurement,elapsedMs:30001},{...measurement,elapsedMs:2000},{...measurement,estimatedCost:Infinity},{...measurement,estimatedBytes:0.1},
  {...measurement,estimatedBytes:QUALITY_BUDGET.maximumEstimatedBytes+1},{...measurement,strategy:'sample'},{...measurement,verdict:'PASS'}])invalid(()=>parseQualityMeasurement(v));
});
test('run outputs keep nonterminal, error and measurement outcomes distinct',()=>{
 assert.deepEqual(parseQualityRunView(queued),queued);
 const succeeded={...queued,status:'succeeded' as const,version:3,attempt:1,startedAt:queued.createdAt,finishedAt:measurement.observedFinishedAt,measurement,verdict:'FAIL' as const};
 assert.deepEqual(parseQualityRunView(succeeded),succeeded);
 for(const v of [{...queued,source:{secretRef:'private'}},{...queued,status:'succeeded'},{...queued,errorCode:'QUALITY_SOURCE_FAILED'},
  {...succeeded,finishedAt:null},{...succeeded,errorCode:'QUALITY_SOURCE_FAILED'},{...succeeded,verdict:'NO_DATA'},
  {...succeeded,measurement:{...measurement,rowCount:0,nullCount:0},verdict:'PASS'}])invalid(()=>parseQualityRunView(v));
 assert.equal(parseQualityRunView({...queued,status:'cancelled',finishedAt:measurement.observedFinishedAt,errorCode:'QUALITY_CANCELLED'}).status,'cancelled');
});
test('claims and completions bind exact IDs, attempts, budgets and closed result variants',()=>{
 const execution={formatVersion:1,kind:'completeness',target:{databaseOid:'16384',schemaOid:'2200',relationOid:'16385',attributeNumber:2,schemaName:'public',tableName:'quality_fixture',columnName:'email',dataType:'text'},budget:{...QUALITY_BUDGET}};
 assert.deepEqual(parseQualityExecution(execution),execution);
 invalid(()=>parseQualityExecution({...execution,budget:{...QUALITY_BUDGET,maximumRows:100001}}));
 invalid(()=>parseQualityExecution({...execution,target:{...execution.target,relationOid:'4294967296'}}));
 const claim={status:'claimed',runId:id(4),claimId:id(6),attempt:1,leaseExpiresAt:queued.expiresAt,source:{connectorId:'postgresql',host:'source-postgres',port:5432,database:'harbor',schema:'public',secretRef:'demo-postgres'},execution};
 assert.deepEqual(parseQualityClaim(claim),claim);invalid(()=>parseQualityClaim({...claim,source:{...claim.source,password:'private'}}));
 assert.deepEqual(parseQualityCompletion({claimId:id(6),attempt:1,measurement}),{claimId:id(6),attempt:1,measurement});
 invalid(()=>parseQualityCompletion({claimId:id(6),attempt:1,measurement,errorCode:'QUALITY_SOURCE_FAILED'}));
 invalid(()=>parseQualityCompletion({claimId:id(6),attempt:0,errorCode:'QUALITY_SOURCE_FAILED'}));
 invalid(()=>parseQualityClaim({status:'terminal',run:queued}));
});
test('PostgreSQL execution preserves exact quoted names and bounds valid Unicode by the worker contract',()=>{
 const target={databaseOid:'16384',schemaOid:'2200',relationOid:'16385',attributeNumber:2,schemaName:' schema\t\n',tableName:'table\r\n\"\u007f',columnName:'cafe\u0301\t\n',dataType:'text'};
 const execution={formatVersion:1,kind:'completeness',target,budget:{...QUALITY_BUDGET}};
 assert.deepEqual(parseQualityExecution(execution),execution);
 const claim={status:'claimed',runId:id(4),claimId:id(6),attempt:1,leaseExpiresAt:queued.expiresAt,
  source:{connectorId:'postgresql',host:'source-postgres',port:5432,database:' database\t\n',schema:target.schemaName,secretRef:'demo-postgres'},execution};
 assert.deepEqual(parseQualityClaim(claim),claim);
 // A four-byte scalar counts once for datatype text, but four bytes in a name.
 const name='😀'.repeat(15)+'abc',datatype='😀'.repeat(256);
 assert.equal(Buffer.byteLength(name),63);
 assert.equal((parseQualityExecution({...execution,target:{...target,columnName:name,dataType:datatype}}).target as QualityTarget).columnName,name);
 assert.equal((parseQualityExecution({...execution,target:{...target,dataType:datatype}}).target as QualityTarget).dataType,datatype);
 invalid(()=>parseQualityExecution({...execution,target:{...target,columnName:name+'a'}}));
 invalid(()=>parseQualityExecution({...execution,target:{...target,dataType:datatype+'a'}}));
 for(const value of ['x\0y','x\ud800y','x\udc00y']){
  for(const field of ['schemaName','tableName','columnName','dataType'])invalid(()=>parseQualityExecution({...execution,target:{...target,[field]:value}}));
  for(const field of ['database','schema','host'])invalid(()=>parseQualityClaim({...claim,source:{...claim.source,[field]:value}}));
 }
 assert.equal(parseQualityClaim({...claim,source:{...claim.source,database:name}}).status,'claimed');
 invalid(()=>parseQualityClaim({...claim,source:{...claim.source,database:name+'a'}}));
 invalid(()=>parseQualityClaim({...claim,source:{...claim.source,schema:'different'}}));
 invalid(()=>parseQualityClaim({...claim,source:{...claim.source,schema:target.schemaName.normalize('NFC')+' '}}));
 for(const value of ['source\npostgres','x'.repeat(254)])invalid(()=>parseQualityClaim({...claim,source:{...claim.source,host:value}}));
 for(const value of ['env:demo','../demo','a'.repeat(129)])invalid(()=>parseQualityClaim({...claim,source:{...claim.source,secretRef:value}}));
});
test('HTTP parsing rejects duplicate JSON keys and ambiguous query selectors',()=>{
 assert.deepEqual(qualityRawQuery('/x?limit=25&version=2',['limit','version']),{__proto__:null,limit:25,version:2});
 for(const url of ['/x?limit=01','/x?limit=101','/x?version=2147483648','/x?limit=1&limit=2','/x?tenantId=x','/x?cursor=%zz','/x?cursor='])invalid(()=>qualityRawQuery(url,['limit','version','cursor']));
 for(const raw of ['{"id":1,"id":2}','{"id":1,"\\u0069d":2}','{"__proto__":{}}','['+' '.repeat(16384)+']'])invalid(()=>parseQualityRequestJSON(raw));
 assert.ok(Value.Check(qualityHttp.publish,{id:id(5),expectedVersion:0,definition:rule}));
 assert.equal(Value.Check(qualityHttp.run,{...queued,secretRef:'private'}),false);
});
test('SQL failures expose stable safe codes without SQL or private source diagnostics',()=>{
 for(const [source,expected,status] of [
  [{code:'40001',message:'QUALITY_TARGET_IMMUTABLE'},'QUALITY_TARGET_IMMUTABLE',409],
  [{code:'P0002',message:'private tenant'},'QUALITY_UNAVAILABLE',404],
  [{code:'42501',message:'secret-ref private'},'QUALITY_FORBIDDEN',403],
  [{code:'57014',message:'private SQL'},'QUALITY_RETRY',503],
  [{code:'0A000',message:'private source'},'QUALITY_TARGET_UNSUPPORTED',422],
  [{code:'42P01',message:'private table'},'QUALITY_STORAGE_INVALID',500],
 ] as const){const actual=qualityFailure(source);assert.equal(actual.code,expected);assert.equal(actual.status,status);assert.equal(actual.message.includes('private'),false);}
});
