// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import {Value} from '@sinclair/typebox/value';
import {Problem} from '../../packages/authz/src/index.ts';
import {ScanLineage} from '../../packages/contracts/src/index.ts';
import {LINEAGE_GAPS,type PgViewLineage} from '../../packages/domain/src/lineage-contracts.ts';
import {validateLineage,type LineageRecord} from '../../packages/domain/src/lineage-ingest.ts';
import {installSourceScans} from '../../apps/api/src/source-scans.ts';

const relation=(oid:string|number,database:string|number=42)=>`pg:${database}:relation:${oid}`;
const record=(oid:string|number,kind='r',database:string|number=42):LineageRecord=>({
 externalId:relation(oid,database),type:['v','m'].includes(kind)?'view':'table',metadata:{oid:String(oid),relationKind:kind},
});
const column=(oid:string|number,n:number,database:string|number=42):LineageRecord=>({
 externalId:`${relation(oid,database)}:column:${n}`,type:'column',parentExternalId:relation(oid,database),metadata:{ordinalPosition:n},
});
const envelope=(views:PgViewLineage['views']):PgViewLineage=>({
 formatVersion:1,kind:'postgresql-view-dependencies',adapterVersion:'1',queryTemplate:'postgresql-view-dependencies-v1',views,
});
function fixture(){
 const records=[record(101),record(102,'p'),record(201,'v'),record(202,'m'),column(101,1),column(102,2)];
 const lineage=envelope([
  {viewExternalId:relation(201),rewriteOid:'301',dependencies:[
   {referencedExternalId:relation(101),referencedAttributeNumbers:[0,1]},
   {referencedExternalId:relation(102),referencedAttributeNumbers:[2]},
  ],gaps:[...LINEAGE_GAPS]},
  {viewExternalId:relation(202),rewriteOid:'302',dependencies:[],gaps:[]},
 ]);
 return {records,lineage};
}
function refused(value:unknown,records:readonly LineageRecord[],connector='postgresql'){
 assert.throws(()=>validateLineage(value,records,connector),(error:unknown)=>{
  assert.ok(error instanceof Problem);assert.equal(error.status,422);assert.equal(error.code,'LINEAGE_INVALID');
  assert.equal(error.message,'The source dependency observation is invalid.');return true;
 });
}
function changed(change:(lineage:any,records:LineageRecord[])=>void){
 const {lineage,records}=fixture();change(lineage,records);refused(lineage,records);
}

test('lineage retains exact same-scan evidence, every empty view and the caller data unchanged',()=>{
 const {lineage,records}=fixture(),before=structuredClone({lineage,records});
 assert.equal(Value.Check(ScanLineage,lineage),true);
 assert.strictEqual(validateLineage(lineage,records,'postgresql'),lineage);
 assert.deepEqual({lineage,records},before);
 // A scan with no views still supplies a collected, empty observation.
 assert.deepEqual(validateLineage(envelope([]),[record(101)],'postgresql'),envelope([]));
});

test('lineage is optional for older completions but PostgreSQL evidence is refused for Unity or unknown connectors',()=>{
 const {lineage,records}=fixture();
 for(const connector of ['postgresql','unity-catalog','unknown'])assert.equal(validateLineage(undefined,records,connector),undefined);
 for(const connector of ['unity-catalog','unknown'])refused(lineage,records,connector);
 for(const value of [null,false,0,'',[],{}])refused(value,records);
});

test('lineage closes every authored object and never accepts SQL bodies or invented column mappings',()=>{
 const alterations:((lineage:any)=>void)[]=[
  x=>{x.sql='SELECT synthetic_private_marker';},x=>{x.views[0].sql='SELECT synthetic_private_marker';},
  x=>{x.views[0].dependencies[0].columnMappings=[{output:'invented'}];},
  x=>{delete x.adapterVersion;},x=>{delete x.views[0].gaps;},x=>{delete x.views[0].dependencies[0].referencedAttributeNumbers;},
  x=>{x.formatVersion='1';},x=>{x.formatVersion=2;},x=>{x.adapterVersion=1;},
  x=>{x.kind='sql-analysis';},x=>{x.queryTemplate='SELECT synthetic_private_marker';},
 ];
 for(const alteration of alterations){
  const {lineage,records}=fixture();alteration(lineage);
  assert.equal(Value.Check(ScanLineage,lineage),false);refused(lineage,records);
 }
});

test('actual completion preValidation refuses unknown lineage fields and coercion before handler entry',async()=>{
 const app=Fastify({logger:false});let handlerBoundary=0;
 app.setErrorHandler((error,_request,reply)=>{
  if(error instanceof Problem)return reply.code(error.status).send({code:error.code});
  return reply.code(500).send({code:'UNEXPECTED_TEST_ERROR'});
 });
 // Exercise the installed route's real preValidation and JSON schema. This hook stops
 // every accepted control before site authentication or any SQL handler can run.
 app.addHook('preHandler',async(_request,reply)=>{handlerBoundary++;return reply.code(204).send();});
 await installSourceScans(app);
 const completion=()=>{
  const {records,lineage}=fixture();return {observedAt:'2026-01-01T00:00:00.000Z',sourceVersion:'17.0',
   permissionFingerprint:'synthetic-fixture',complete:true,
   records:records.map(r=>({...r,name:r.externalId,qualifiedName:r.externalId})),lineage};
 };
 const url='/internal/jobs/10000000-0000-4000-8000-000000000001/complete';
 try{
  const accepted=await app.inject({method:'POST',url,payload:completion()});assert.equal(accepted.statusCode,204,accepted.body);
  const legacy=completion();Reflect.deleteProperty(legacy,'lineage');
  assert.equal((await app.inject({method:'POST',url,payload:legacy})).statusCode,204);assert.equal(handlerBoundary,2);
  const changes:((x:any)=>void)[]=[
   x=>{x.sql='SELECT synthetic_private_marker';},x=>{x.views[0].definition='synthetic_private_marker';},
   x=>{x.views[0].dependencies[0].columnMappings=['synthetic_private_marker'];},
   x=>{x.formatVersion='1';},x=>{x.views[0].rewriteOid=301;},
   x=>{x.views[0].dependencies[0].referencedAttributeNumbers=['1'];},x=>{x.views[0].gaps=['synthetic_private_marker'];},
  ];
  for(const change of changes){
   const payload=completion();change(payload.lineage);const before=structuredClone(payload);
   const response=await app.inject({method:'POST',url,payload});
   assert.equal(response.statusCode,422,response.body);assert.deepEqual(response.json(),{code:'LINEAGE_INVALID'});
   assert.equal(response.body.includes('synthetic_private_marker'),false);assert.equal(handlerBoundary,2);
   assert.deepEqual(payload,before);
  }
 }finally{await app.close();}
});

test('lineage requires exactly all scanned views, unique rewrite OIDs and lexical view ordering',()=>{
 for(const change of [
  (x:any)=>{x.views.pop();},(x:any)=>{x.views.push(structuredClone(x.views[0]));},
  (x:any)=>{x.views.reverse();},(x:any)=>{x.views[1].viewExternalId=relation(999);},
  (x:any)=>{x.views[1].rewriteOid=x.views[0].rewriteOid;},
 ])changed(change);
 const records=[record(2,'v'),record(10,'m')];
 const lineage=envelope([10,2].map((id,i)=>({viewExternalId:relation(id),rewriteOid:String(100+i),dependencies:[],gaps:[]})));
 assert.equal(validateLineage(lineage,records,'postgresql'),lineage);
 lineage.views.reverse();refused(lineage,records);
});

test('lineage OIDs are canonical bounded strings and every relation belongs to the same database',()=>{
 for(const oid of ['0','01','4294967296','-1','1.0','1e2','1\n','',301]){
  changed(x=>{x.views[0].rewriteOid=oid;});
 }
 for(const id of ['0','01','4294967296','-1','1.0','1e2']){
  const r=record(id,'v');refused(envelope([{viewExternalId:r.externalId,rewriteOid:'1',dependencies:[],gaps:[]}]),[r]);
  const db=record(1,'v',id);refused(envelope([{viewExternalId:db.externalId,rewriteOid:'1',dependencies:[],gaps:[]}]),[db]);
 }
 const max=record('4294967295','v','4294967295');
 const valid=envelope([{viewExternalId:max.externalId,rewriteOid:'4294967295',dependencies:[],gaps:[]}]);
 assert.equal(validateLineage(valid,[max],'postgresql'),valid);
 changed((_x,records)=>{records[0].metadata.oid='102';});
 changed((_x,records)=>{records[0].metadata.relationKind='S';});
 changed((_x,records)=>{records[2].metadata.relationKind='r';});
 changed((_x,records)=>{records.push(record(999,'r',43));});
 changed((_x,records)=>{records.push(structuredClone(records[0]));});
});

test('positive witnesses require exact column identity, parent and numeric ordinal from this completion',()=>{
 for(const mutate of [
  (records:LineageRecord[])=>{records.splice(4,1);},
  (records:LineageRecord[])=>{records[4].parentExternalId=relation(102);},
  (records:LineageRecord[])=>{records[4].metadata.ordinalPosition=2;},
  (records:LineageRecord[])=>{records[4].metadata.ordinalPosition='1';},
  (records:LineageRecord[])=>{records[4].externalId=relation(101)+':column:01';},
  (records:LineageRecord[])=>{records[4].type='field';},
 ])changed((_x,records)=>mutate(records));
 changed(x=>{x.views[0].dependencies[0].referencedExternalId=relation(101)+':column:1';});
 changed(x=>{x.views[0].dependencies[0].referencedExternalId=relation(100);});
 changed(x=>{x.views[0].dependencies[0].referencedExternalId=relation(101,43);});
});

test('zero denotes a relation witness, positive attnums are numeric, unique, ascending and bounded',()=>{
 const {lineage,records}=fixture();lineage.views[0].dependencies=[{referencedExternalId:relation(101),referencedAttributeNumbers:[0]}];
 assert.equal(validateLineage(lineage,records.filter(r=>r.type!=='column'),'postgresql'),lineage);
 for(const values of [[],[-1],[32768],[1.5],[false],['1'],[0,0],[1,0],[1,1]]){
  changed(x=>{x.views[0].dependencies[0].referencedAttributeNumbers=values;});
 }
 lineage.views[0].dependencies[0].referencedAttributeNumbers=[0,32767];records.push(column(101,32767));
 assert.equal(validateLineage(lineage,records,'postgresql'),lineage);
});

test('normal self edges and cycles remain evidence without inventing output column mappings',()=>{
 const records=[record(101,'v'),record(102,'m')];
 const lineage=envelope([
  {viewExternalId:relation(101),rewriteOid:'301',dependencies:[
   {referencedExternalId:relation(101),referencedAttributeNumbers:[0]},
   {referencedExternalId:relation(102),referencedAttributeNumbers:[0]},
  ],gaps:[]},
  {viewExternalId:relation(102),rewriteOid:'302',dependencies:[{referencedExternalId:relation(101),referencedAttributeNumbers:[0]}],gaps:[]},
 ]);
 assert.equal(validateLineage(lineage,records,'postgresql'),lineage);
 assert.equal(lineage.views.flatMap(v=>v.dependencies).length,3);
});

test('dependency identities and closed gap codes are unique and lexically ordered',()=>{
 changed(x=>{x.views[0].dependencies.reverse();});
 changed(x=>{x.views[0].dependencies.push(structuredClone(x.views[0].dependencies[1]));});
 for(const gaps of [['OUT_OF_SCOPE_RELATION','OPAQUE_ROUTINE_DEPENDENCY'],['OUT_OF_SCOPE_RELATION','OUT_OF_SCOPE_RELATION'],
  ['OUT_OF_SCOPE_RELATION:private_schema'],['SELECT synthetic_private_marker'],[null]])changed(x=>{x.views[0].gaps=gaps;});
 const records=[record(2),record(10),record(99,'v')];
 const lineage=envelope([{viewExternalId:relation(99),rewriteOid:'100',dependencies:[10,2].map(id=>({
  referencedExternalId:relation(id),referencedAttributeNumbers:[0],
 })),gaps:[]}]);
 assert.equal(validateLineage(lineage,records,'postgresql'),lineage);
 lineage.views[0].dependencies.reverse();refused(lineage,records);
});

test('view admission accepts exactly 1000 including empty views and refuses 1001',()=>{
 const records=Array.from({length:1001},(_,i)=>record(i+10000,'v'));
 const views=records.map((r,i)=>({viewExternalId:r.externalId,rewriteOid:String(i+20000),dependencies:[],gaps:[]}));
 const lineage=envelope(views.slice(0,1000));assert.equal(Value.Check(ScanLineage,lineage),true);
 assert.equal(validateLineage(lineage,records.slice(0,1000),'postgresql'),lineage);
 const oversized=envelope(views);assert.equal(Value.Check(ScanLineage,oversized),false);refused(oversized,records);
});

test('edge admission counts the whole envelope, accepting 5000 and refusing 5001',()=>{
 const tables=Array.from({length:2501},(_,i)=>record(i+10000));
 const records=[...tables,record(20000,'v'),record(20001,'m')];
 const dependencies=tables.map(r=>({referencedExternalId:r.externalId,referencedAttributeNumbers:[0]}));
 const lineage=envelope([20000,20001].map((id,i)=>({viewExternalId:relation(id),rewriteOid:String(30000+i),
  dependencies:structuredClone(dependencies.slice(0,2500)),gaps:[]})));
 assert.equal(Value.Check(ScanLineage,lineage),true);assert.equal(validateLineage(lineage,records,'postgresql'),lineage);
 lineage.views[1].dependencies.push(dependencies[2500]);
 assert.equal(Value.Check(ScanLineage,lineage),true,'each individual array fits the wire schema');refused(lineage,records);
});

test('witness admission is aggregate across views, accepting 10000 and refusing 10001',()=>{
 const records=[record(100),...Array.from({length:1001},(_,i)=>column(100,i+1)),
  ...Array.from({length:10},(_,i)=>record(200+i,'v'))];
 const attributes=Array.from({length:1000},(_,i)=>i+1);
 const lineage=envelope(Array.from({length:10},(_,i)=>({viewExternalId:relation(200+i),rewriteOid:String(300+i),
  dependencies:[{referencedExternalId:relation(100),referencedAttributeNumbers:[...attributes]}],gaps:[]})));
 assert.equal(Value.Check(ScanLineage,lineage),true);assert.equal(validateLineage(lineage,records,'postgresql'),lineage);
 lineage.views[9].dependencies[0].referencedAttributeNumbers.push(1001);
 assert.equal(Value.Check(ScanLineage,lineage),true,'individual witness arrays remain within their schema limit');refused(lineage,records);
});
