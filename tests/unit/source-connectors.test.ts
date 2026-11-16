// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';
import { SourceInput } from '../../packages/contracts/src/index.ts';
import { sourceStorage, sourceConfiguration, validateSourceInput, mayReconcileAbsence } from '../../packages/connectors/src/sources.ts';

const postgres = {name:'Harbor',host:'source-postgres',port:5432,database:'harbor',schema:'public',secretRef:'demo-postgres'} as const;
const unity = {connectorId:'unity-catalog',name:'Commerce',workspaceUrl:'https://adb-123.1.azuredatabricks.net',catalog:'harbor',schema:'commerce',secretRef:'harbor-uc-reader'} as const;

test('source registration accepts both closed connector shapes without union field removal', async () => {
  const app=Fastify();
  app.post('/source',{schema:{body:SourceInput},validatorCompiler:()=>validateSourceInput},async request=>({accepted:request.body}));
  try {
    for(const input of [postgres,{...postgres,connectorId:'postgresql'},unity]){
      const response=await app.inject({method:'POST',url:'/source',payload:input});
      assert.equal(response.statusCode,200,response.body); assert.deepEqual(response.json().accepted,input);
    }
    for(const input of [{...unity,accessToken:'must-never-be-accepted'},{...unity,host:'source-postgres'},{...unity,workspaceUrl:'http://169.254.169.254'},{...unity,connectorId:'arbitrary'}, {...unity,secretRef:'../private'},{...unity,catalog:'other.scope'},{...postgres,port:'5432'}, {...unity,catalog:'bad\u007f'}, {...unity,schema:'bad\ud800'}, {...unity,name:'bad\0'}, {...unity,name:'bad\n'}, {...postgres,name:'bad\udc00'}]){
      const response=await app.inject({method:'POST',url:'/source',payload:input});assert.equal(response.statusCode,400);assert.equal(response.json().code,'VALIDATION_FAILED');
      assert.equal(response.body.includes('must-never-be-accepted'),false);
    }
  } finally {await app.close();}
});

test('source storage and public configuration round trip without credential fields',()=>{
  for(const input of [postgres,unity]){
    const stored=sourceStorage(input), output=sourceConfiguration(stored);
    const {name,...expected}=input;
    assert.deepEqual(output,{connectorId:'postgresql',...expected});
    assert.equal('accessToken' in stored,false);
  }
  assert.throws(()=>sourceConfiguration({...sourceStorage(unity),connector_id:'unknown'}),/SOURCE_CONNECTOR_UNSUPPORTED/);
});

test('permission-filtered connectors cannot gain absence authority from missing or forged flags',()=>{
  for(const id of ['unity-catalog','unknown'])for(const completion of [{},{absenceReconciliation:false},{absenceReconciliation:true}]){
    assert.equal(mayReconcileAbsence(id,completion as {absenceReconciliation?:false}),false);
  }
  assert.equal(mayReconcileAbsence('postgresql',{}),true);
  assert.equal(mayReconcileAbsence('postgresql',{absenceReconciliation:false}),false);
});

test('PostgreSQL registration admits canonical configurable scopes without network or credential authority',async()=>{
  const app=Fastify();
  app.post('/source',{schema:{body:SourceInput},validatorCompiler:()=>validateSourceInput},async request=>({accepted:request.body}));
  try {
    for(const host of ['db.example.invalid','tenant-db.internal','10.42.0.7','2001:db8::1','::ffff:c000:201']) {
      const input={...postgres,connectorId:'postgresql' as const,host,port:6432,database:'warehouse',schema:'المبيعات',secretRef:'warehouse-reader.1'};
      const response=await app.inject({method:'POST',url:'/source',payload:input});
      assert.equal(response.statusCode,200,response.body);assert.deepEqual(response.json().accepted,input);
      assert.deepEqual(sourceConfiguration(sourceStorage(input)),{connectorId:'postgresql',host,port:6432,database:input.database,schema:input.schema,secretRef:input.secretRef});
    }
    const invalid=[
      ...['DB.example.invalid','db.example.invalid.','db,backup','db:5432','postgresql://db','/var/run/postgresql','*','0x7f000001','0x7f.0.0.1','127.1','0177.0.0.1','2130706433','[2001:db8::1]','2001:0db8::1','fe80::1%eth0','a'.repeat(64)+'.invalid'].map(host=>({host})),
      ...[0,65536,1.5,true,'5432'].map(port=>({port})),
      ...['host=db','postgresql://db','postgres://db','é'.repeat(32),'x\n','x\ud800'].map(database=>({database})),
      {schema:'界'.repeat(22)},{schema:'x\0'},{secretRef:'../secrets'},{password:'must-never-be-accepted'},
    ];
    for(const change of invalid){
      const response=await app.inject({method:'POST',url:'/source',payload:{...postgres,...change}});
      assert.equal(response.statusCode,400,JSON.stringify(change));assert.equal(response.json().code,'VALIDATION_FAILED');
      assert.equal(response.body.includes('must-never-be-accepted'),false);
    }
    for(const change of [{database:'é'.repeat(31)+'x'},{schema:'界'.repeat(21)}]) {
      const response=await app.inject({method:'POST',url:'/source',payload:{...postgres,...change}});
      assert.equal(response.statusCode,200,response.body);
    }
  }finally{await app.close();}
});
