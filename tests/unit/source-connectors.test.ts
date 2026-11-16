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
