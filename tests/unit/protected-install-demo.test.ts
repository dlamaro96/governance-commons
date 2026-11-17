// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createDemoManifests, validateDemoManifests, safeDemoInstallationReason } from '../../scripts/authentication-install-demo.ts';
import { installationHash, type InstallationManifest } from '../../packages/authority/src/authentication-installation.ts';
const config={issuer:'http://localhost:4315/realms/governance',publicOrigin:'http://localhost:4314',environment:'isolated-test' as const};
const target={databaseOid:17001,ownerRoleOid:17002,loginRoleOid:17003,apiRoleOid:17004};
const expiry='2030-01-01T00:00:00.000Z';
function rechain(values:InstallationManifest[]){let predecessor:InstallationManifest['predecessorManifestHash']=null;return values.map(value=>{const next={...value,predecessorManifestHash:predecessor};predecessor=installationHash(next);return next;});}
test('explicit demo installation is thirteen closed operations with one fixed expiry and stable exact replay',()=>{
 const values=createDemoManifests(config,target,expiry);assert.equal(values.length,13);
 assert.deepEqual(validateDemoManifests(JSON.parse(JSON.stringify(values)),config,target),values);
 assert.equal(new Set(values.map(m=>m.requestId)).size,13);
 assert.deepEqual(values.filter(m=>'expiresAt'in m.operation).map(m=>(m.operation as {expiresAt:string}).expiresAt),Array(9).fill(expiry));
 assert.deepEqual(values.map(m=>m.operation.type),['register-executor','advance-generation','register-executor','advance-generation','register-issuer',...Array(6).fill('bind-identity'),'initialize-tenant','initialize-tenant']);
});
test('private batch cannot silently change targets, identity scope, generation, renewal or native executor families',()=>{
 const original=createDemoManifests(config,target,expiry);
 assert.throws(()=>validateDemoManifests(original,config,{...target,databaseOid:17005}));
 assert.throws(()=>validateDemoManifests(original,{...config,issuer:'http://localhost:4311/realms/governance'},target));
 assert.throws(()=>validateDemoManifests(original.slice(0,12),config,target));
 for(const mutate of [
  (v:any[])=>{v[0].operation.roleName='gc_app';},
  (v:any[])=>{v[2].operation.generation=2;},
  (v:any[])=>{v[4].operation.expiresAt='2031-01-01T00:00:00.000Z';},
  (v:any[])=>{v[5].operation.identityId='10000000-0000-4000-8000-000000000007';},
  (v:any[])=>{v[12].operation.generation=2;},
  (v:any[])=>{v[0].operation={type:'revoke-executor',registrationId:v[0].operation.registrationId};},
 ]){const copy=structuredClone(original) as InstallationManifest[];mutate(copy);assert.throws(()=>validateDemoManifests(rechain(copy),config,target));}
});
test('local demo installer refuses production and invalid public origin',()=>{
 assert.throws(()=>createDemoManifests({...config,environment:'production' as any},target,expiry));
 assert.throws(()=>createDemoManifests({...config,publicOrigin:'http://attacker.invalid'},target,expiry));
});

test('installer diagnostics expose only closed local reason codes',()=>{
 assert.equal(safeDemoInstallationReason(new Error('CANONICAL_IDENTITIES_REQUIRED')),'CANONICAL_IDENTITIES_REQUIRED');
 for(const input of [new Error('postgres://private.invalid/credential'),{message:'OWNER_REQUIRED'},null,new Error('arbitrary database detail')]){
  assert.equal(safeDemoInstallationReason(input),'PREREQUISITE_OR_OPERATION_FAILED');
 }
});
