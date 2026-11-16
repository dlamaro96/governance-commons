// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {INSTALLATION_SIGNATURES,installationEncoding,installationHash,installationQuery,parseInstallationManifest,parseInstallationManifestFile,parseInstallationReceipt,type InstallationManifest} from '../../packages/authority/src/authentication-installation.ts';
import type {Parsed} from '../../packages/authority/src/types.ts';
const uuid=(n:number)=>`10000000-0000-4000-8000-${n.toString().padStart(12,'0')}`;
const date='2026-11-17T10:20:30.123Z';
const base={formatVersion:1,requestId:uuid(1),releaseReference:'release/123',deploymentOperatorReference:'operator/ref',expectedDatabaseOid:123,expectedOwnerRoleOid:456,predecessorManifestHash:null};
function accepted<T>(x:Parsed<T>):T {assert.equal(x.ok,true);if(!x.ok)throw Error('invalid fixture');return x.value;}
function manifest(operation:object):InstallationManifest{return accepted(parseInstallationManifest({...base,operation}));}
const ops=[
 {type:'register-executor',registrationId:uuid(2),channelId:uuid(3),roleName:'gc_a1_login_g1',expectedRoleOid:789,kind:'login',generation:1,expiresAt:date},
 {type:'advance-generation',kind:'login',channelId:uuid(3),registrationId:uuid(2),expectedPreviousRegistrationId:null,expectedHeadVersion:null},
 {type:'register-issuer',issuerId:uuid(4),registrationId:uuid(2),generation:1,issuer:'https://issuer.example/realm',clientId:'web',redirectUri:'https://app.example/auth/callback',environment:'production',expiresAt:date},
 {type:'bind-identity',bindingId:uuid(5),issuerId:uuid(4),identityId:uuid(6),expectedCanonicalIssuer:'https://issuer.example/realm',expectedCanonicalSubject:'subject-é-😀',expiresAt:date},
 {type:'initialize-tenant',tenantId:uuid(7),generation:1},
 {type:'advance-tenant-generation',tenantId:uuid(7),expectedGeneration:1,expectedEpoch:3,generation:2},
 {type:'revoke-executor',registrationId:uuid(2)},
 {type:'revoke-issuer',issuerId:uuid(4)},
 {type:'revoke-binding',bindingId:uuid(5)},
];
test('nine closed operations retain exact scalar SQL argument order and immutable maps',()=>{
 const expected=[
  ['provision_executor',[uuid(2),uuid(3),'gc_a1_login_g1',789,'login',1,date]],
  ['advance_generation',['login',uuid(3),uuid(2),null,null]],
  ['provision_issuer',[uuid(4),uuid(2),1,'https://issuer.example/realm','web','https://app.example/auth/callback','production',date]],
  ['bind_identity',[uuid(5),uuid(4),uuid(6),'https://issuer.example/realm','subject-é-😀',date]],
  ['initialize_tenant',[uuid(7),1]],['advance_tenant_generation',[uuid(7),1,3,2]],
  ['revoke_executor',[uuid(2)]],['revoke_issuer',[uuid(4)]],['revoke_binding',[uuid(5)]],
 ] as const;
 for(let i=0;i<ops.length;i++){
  const m=manifest(ops[i]!),q=installationQuery(m),[name,tail]=expected[i]!;
  assert.match(q.text,new RegExp(`FROM gc_authn\\.${name}\\(`));
  assert.deepEqual(q.values,[uuid(1),'release/123','operator/ref',123,456,null,...tail]);
  assert.equal(q.text.includes('subject-é'),false);assert.equal(q.text.includes('gc_a1_login_g1'),false);
  assert.equal(Object.isFrozen(m),true);assert.equal(Object.isFrozen(m.operation),true);assert.equal(Object.isFrozen(q.values),true);
 }
 assert.equal(Object.isFrozen(INSTALLATION_SIGNATURES),true);
 assert.equal(Object.isFrozen(INSTALLATION_SIGNATURES['register-executor'].arguments[0]),true);
});
test('receipt codec has an independently spelled exact byte vector, typed values and no generated tail',()=>{
 const m=manifest(ops[4]!);
 const expected='gc-authn-install/v1;S17:initialize-tenant'+
  `S10:request_idU${uuid(1)};`+'S11:release_refS11:release/123'+
  'S12:operator_refS12:operator/ref'+'S15:expected_db_oidI123;'+
  'S18:expected_owner_oidI456;'+'S16:predecessor_hashN;'+
  `S9:tenant_idU${uuid(7)};`+'S10:generationI1;';
 assert.equal(Buffer.from(installationEncoding(m)).toString('utf8'),expected);
 assert.equal(installationHash(m),createHash('sha256').update(expected,'utf8').digest('hex'));
 const unicode=Buffer.from(installationEncoding(manifest(ops[3]!))).toString('utf8');
 assert.ok(unicode.includes('S16:expected_subjectS15:subject-é-😀'));
 assert.ok(unicode.endsWith(`S10:expires_atT${date};`));
 const copy=installationEncoding(m);copy[0]=0;assert.equal(Buffer.from(installationEncoding(m)).toString('utf8'),expected);
 assert.notEqual(installationHash(m),installationHash(manifest({...ops[4],generation:2})));
});
test('file admission checks exact64KiB raw bound and escaped duplicate keys before accepting',()=>{
 const raw=JSON.stringify({...base,operation:ops[4]});const padded=raw+' '.repeat(65_536-Buffer.byteLength(raw));
 assert.equal(parseInstallationManifestFile(padded).ok,true);
 assert.equal(parseInstallationManifestFile(padded+' ').ok,false);
 assert.equal(parseInstallationManifestFile(raw.replace('"requestId":',`"request\\u0049d":"${uuid(9)}","requestId":`)).ok,false);
 assert.equal(parseInstallationManifestFile(raw.replace('"type":"initialize-tenant"','"type":"initialize-tenant","type":"revoke-binding"')).ok,false);
 assert.equal(parseInstallationManifestFile(raw+'x').ok,false);
});
test('unknown keys, missing fields, JSON escape objects and hostile reflection never authorize or run getters',()=>{
 for(const value of [{...base,operation:{...ops[4],allow:true}},{...base,extra:'secret',operation:ops[4]},{...base,operation:{type:'sql',query:'select 1'}},{...base,operation:{...ops[0],type2:'api'}},{...base,operation:null}])assert.equal(parseInstallationManifest(value).ok,false);
 const absent={...base,operation:ops[4]} as Record<string,unknown>;delete absent.predecessorManifestHash;assert.equal(parseInstallationManifest(absent).ok,false);
 let invoked=0;const getter={...base,operation:ops[4]};Object.defineProperty(getter,'requestId',{get(){invoked++;throw Error('secret');},enumerable:true});
 assert.equal(parseInstallationManifest(getter).ok,false);assert.equal(invoked,0);
 assert.equal(parseInstallationManifest(new Proxy({}, {ownKeys(){invoked++;throw Error('secret');}})).ok,false);assert.equal(invoked,0);
 const symbolic={...base,operation:ops[4],[Symbol('secret')]:true};assert.equal(parseInstallationManifest(symbolic).ok,false);
 const result=parseInstallationManifest({...base,operation:{...ops[4],['secret'.repeat(10_000)]:true}});
 assert.equal(result.ok,false);assert.ok(JSON.stringify(result).length<500);assert.equal(JSON.stringify(result).includes('secret'),false);
});
test('scalar boundaries refuse coercion, truncated roles, wrong nullable pairs and time normalization',()=>{
 const bad=[
  {...base,expectedDatabaseOid:0},{...base,expectedDatabaseOid:4_294_967_296},{...base,expectedOwnerRoleOid:'456'},
  {...base,requestId:uuid(1).toUpperCase().replace('10000000','A0000000')},{...base,requestId:'00000000-0000-0000-0000-000000000000'},
  {...base,releaseReference:'é'}, {...base,predecessorManifestHash:'A'.repeat(64)},
 ];for(const b of bad)assert.equal(parseInstallationManifest({...b,operation:ops[4]}).ok,false);
 assert.equal(parseInstallationManifest({...base,expectedDatabaseOid:4_294_967_295,operation:ops[4]}).ok,true);
 for(const roleName of ['a'.repeat(64),'é'.repeat(32),'bad\nrole'])assert.equal(parseInstallationManifest({...base,operation:{...ops[0],roleName}}).ok,false);
 assert.equal(parseInstallationManifest({...base,operation:{...ops[0],roleName:'é'.repeat(31)+'a'}}).ok,true);
 for(const expiresAt of ['2026-02-30T10:20:30.123Z','2026-11-17T10:20:30.1230Z','2026-11-17T10:20:30Z','2026-11-17T11:20:30.123+01:00',new Date(date)])assert.equal(parseInstallationManifest({...base,operation:{...ops[0],expiresAt}}).ok,false);
 assert.equal(parseInstallationManifest({...base,operation:{...ops[1],expectedHeadVersion:1}}).ok,false);
 assert.equal(parseInstallationManifest({...base,operation:{...ops[1],expectedPreviousRegistrationId:uuid(2)}}).ok,false);
 assert.equal(parseInstallationManifest({...base,operation:{...ops[5],generation:1}}).ok,false);
 assert.equal(parseInstallationManifest({...base,operation:{...ops[0],generation:2_147_483_648}}).ok,false);
});
test('issuer endpoints enforce declared HTTPS versus explicit loopback development without normalization',()=>{
 for(const issuer of ['http://issuer.example','https://user:password@issuer.example','https://issuer.example/#fragment','ftp://issuer.example'])assert.equal(parseInstallationManifest({...base,operation:{...ops[2],issuer}}).ok,false);
 const local={...ops[2],environment:'local-development',issuer:'http://localhost:4311/realm',redirectUri:'http://127.0.0.1:4310/auth/callback'};
 assert.equal(parseInstallationManifest({...base,operation:local}).ok,true);
 assert.equal(parseInstallationManifest({...base,operation:{...local,issuer:'http://localhost.evil.example/realm'}}).ok,false);
 const m=manifest({...ops[2],issuer:'https://issuer.example/Realm/'});assert.equal(m.operation.type,'register-issuer');if(m.operation.type==='register-issuer')assert.equal(m.operation.issuer,'https://issuer.example/Realm/');
});
test('receipt parser admits exact SQL snake_case only and detaches into camelCase',()=>{
 const row={installation_id:uuid(8),manifest_hash:'a'.repeat(64),target_id:uuid(7),recorded_at:date};const receipt=accepted(parseInstallationReceipt(row));
 assert.deepEqual(receipt,{installationId:uuid(8),manifestHash:'a'.repeat(64),targetId:uuid(7),recordedAt:date});assert.equal(Object.isFrozen(receipt),true);
 assert.equal(parseInstallationReceipt({...row,secret:'private'}).ok,false);
 assert.equal(parseInstallationReceipt({...row,recorded_at:new Date(date)}).ok,false);
 assert.equal(parseInstallationReceipt({...row,target_id:null}).ok,false);
});

test('raw endpoint grammar agrees with the bounded SQL spelling without URL repair',()=>{
 const acceptedEndpoints=['https://issuer.example/path?x=%2F&y=ok','https://192.0.2.1:65535/?a=1','https://[::1]:443/callback','https://localhost','https://a-b.example/path:@?x=~'];
 for(const issuer of acceptedEndpoints){const m=manifest({...ops[2],issuer});if(m.operation.type==='register-issuer')assert.equal(m.operation.issuer,issuer);}
 const rejected=['https:issuer.example','HTTPS://issuer.example','https://issuer.example:0','https://issuer.example:01','https://issuer.example:65536','https://user@issuer.example','https://issuer.example/#x','https://issuer.example/space here','https://issuer.example/é','https://issuer.example/%','https://issuer.example/%2','https://issuer.example/%GG','https://issuer.example/\\evil','https://127.1','https://127.000.0.1','https://256.0.0.1','https://0x7f000001','https://example.123','https://%65xample.com','https://issuer.example.','https://-issuer.example','https://[2001:db8::1]','https://issuer.example:'];
 for(const issuer of rejected)assert.equal(parseInstallationManifest({...base,operation:{...ops[2],issuer}}).ok,false,issuer);
 for(const host of ['localhost','127.0.0.1','[::1]'])assert.equal(parseInstallationManifest({...base,operation:{...ops[2],environment:'local-development',redirectUri:`http://${host}:4310/auth/callback`}}).ok,true);
 assert.equal(parseInstallationManifest({...base,operation:{...ops[2],environment:'local-development',redirectUri:'http://192.0.2.1/auth/callback'}}).ok,false);
});
