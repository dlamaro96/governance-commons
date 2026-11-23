// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {applicationBridgeEncoding,applicationBridgeHash,applicationBridgeQuery,parseApplicationBridgeManifest,parseApplicationBridgeManifestFile} from '../../packages/authn/src/application-installation.ts';
const requestId='11111111-1111-4111-8111-111111111111',bridgeId='22222222-2222-4222-8222-222222222222',apiId='33333333-3333-4333-8333-333333333333';
function input(){return {formatVersion:1,requestId,releaseReference:'synthetic/release',deploymentOperatorReference:'explicit-test',expectedDatabaseOid:42,expectedOwnerRoleOid:43,predecessorManifestHash:null,operation:{type:'application-bridge-install',bridgeId,expectedAppRoleOid:44,apiRegistrationId:apiId,bridgeGeneration:1,authenticationGeneration:2,expiresAt:'2030-01-01T00:00:00.000Z'}};}
function admitted(value:unknown=input()){const p=parseApplicationBridgeManifest(value);assert.ok(p.ok);return p.value;}
test('Application bridge installation agrees with independently specified byte protocol',()=>{
 const bytes=`gc-app-authn-install/v1;S26:application-bridge-installS10:request_idU${requestId};S11:release_refS17:synthetic/releaseS12:operator_refS13:explicit-testS15:expected_db_oidI42;S18:expected_owner_oidI43;S16:predecessor_hashN;S9:bridge_idU${bridgeId};S16:expected_app_oidI44;S19:api_registration_idU${apiId};S17:bridge_generationI1;S16:authn_generationI2;S10:expires_atT2030-01-01T00:00:00.000Z;`;
 // String lengths are independent literal protocol coordinates.
 assert.equal(Buffer.from(applicationBridgeEncoding(admitted())).toString(),bytes);
 assert.equal(applicationBridgeHash(admitted()),createHash('sha256').update(bytes).digest('hex'));
 const query=applicationBridgeQuery(admitted());assert.equal(query.values.length,12);assert.ok(!query.text.includes(requestId));assert.ok(Object.isFrozen(query.values));
});
test('Application bridge revoke binds exact original receipt and predecessor with distinct encoding',()=>{
 const raw={...input(),predecessorManifestHash:'a'.repeat(64),operation:{type:'application-bridge-revoke',bridgeId,expectedManifestHash:'b'.repeat(64)}};
 const m=admitted(raw),q=applicationBridgeQuery(m);assert.match(q.text,/gc_authn\.revoke_application_bridge_v1\(/);assert.equal(q.values.length,8);assert.equal(q.values[5],'a'.repeat(64));assert.equal(q.values[7],'b'.repeat(64));
 assert.notEqual(applicationBridgeHash(m),applicationBridgeHash(admitted()));assert.notEqual(applicationBridgeHash(m),applicationBridgeHash(admitted({...raw,predecessorManifestHash:null})));
});
test('Application bridge manifest rejects unknown fields, coercions and invalid OIDs/generations',()=>{
 const base=input();
 for(const bad of [{...base,extra:true},{...base,formatVersion:2},{...base,requestId:'AAAAAAAA-1111-4111-8111-111111111111'},{...base,expectedDatabaseOid:'42'},{...base,expectedOwnerRoleOid:0},{...base,predecessorManifestHash:''},{...base,releaseReference:'bad\nreference'},...[-1,0,1.5,2**32].map(v=>({...base,operation:{...base.operation,bridgeGeneration:v}})),{...base,operation:{...base.operation,contentAuthority:true}},{...base,operation:{...base.operation,expiresAt:'2030-01-01T00:00:00Z'}}]){
  assert.equal(parseApplicationBridgeManifest(bad).ok,false);
 }
});
test('Application bridge parser does not invoke accessors or admit prototype metadata',()=>{
 let invoked=false;const getter=Object.defineProperty(input(),'requestId',{get(){invoked=true;return requestId;}});
 assert.equal(parseApplicationBridgeManifest(getter).ok,false);assert.equal(invoked,false);
 assert.equal(parseApplicationBridgeManifest(Object.assign(Object.create({unexpected:true}),input())).ok,false);
});
test('Application bridge file parser rejects duplicate keys, over-limit input and truncation',()=>{
 const text=JSON.stringify(input());assert.ok(parseApplicationBridgeManifestFile(text).ok);
 assert.equal(parseApplicationBridgeManifestFile(text.replace('"formatVersion":1','"formatVersion":1,"formatVersion":1')).ok,false);
 assert.equal(parseApplicationBridgeManifestFile(' '.repeat(65537)+text).ok,false);assert.equal(parseApplicationBridgeManifestFile(text.slice(0,-1)).ok,false);
});
test('Application bridge manifests detach immutable authority-relevant input',()=>{
 const raw=input(),m=admitted(raw),before=applicationBridgeHash(m);raw.operation.bridgeGeneration=10;raw.releaseReference='changed';
 assert.equal(applicationBridgeHash(m),before);assert.ok(Object.isFrozen(m));assert.ok(Object.isFrozen(m.operation));
});
