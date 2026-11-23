// SPDX-License-Identifier: Apache-2.0
import {createHash} from 'node:crypto';
import {parseAuthorityInputFile} from '../../authority/src/admission.ts';
import {AUTHENTICATION_SCALARS as S,AuthenticationError,authenticationObject,authenticationParsed,type AuthenticationQuery,type AuthenticationSQLValue} from '../../authority/src/authentication.ts';
import {INSTALLATION_INPUT_BYTES,type InstallationArgumentType,type InstallationSignature} from '../../authority/src/authentication-installation.ts';
import type {Parsed,UUID,Digest,UTC} from '../../authority/src/types.ts';

export type ApplicationBridgeOperation=
 | Readonly<{type:'application-bridge-install';bridgeId:UUID;expectedAppRoleOid:number;apiRegistrationId:UUID;bridgeGeneration:number;authenticationGeneration:number;expiresAt:UTC}>
 | Readonly<{type:'application-bridge-revoke';bridgeId:UUID;expectedManifestHash:Digest}>;
export type ApplicationBridgeManifest=Readonly<{formatVersion:1;requestId:UUID;releaseReference:string;deploymentOperatorReference:string;expectedDatabaseOid:number;expectedOwnerRoleOid:number;predecessorManifestHash:Digest|null;operation:ApplicationBridgeOperation}>;
const fail=():never=>{throw new AuthenticationError('AUTHN_INPUT_INVALID');};
function operation(input:unknown):ApplicationBridgeOperation {
 if(input===null||typeof input!=='object'||Array.isArray(input))return fail();
 const admitted=authenticationObject(input,Object.keys(input));
 if(admitted.type==='application-bridge-install'){
  const x=authenticationObject(admitted,['type','bridgeId','expectedAppRoleOid','apiRegistrationId','bridgeGeneration','authenticationGeneration','expiresAt']);
  return Object.freeze({type:'application-bridge-install',bridgeId:S.uuid(x.bridgeId),expectedAppRoleOid:S.oid(x.expectedAppRoleOid),apiRegistrationId:S.uuid(x.apiRegistrationId),bridgeGeneration:S.integer(x.bridgeGeneration),authenticationGeneration:S.integer(x.authenticationGeneration),expiresAt:S.time(x.expiresAt)});
 }
 if(admitted.type==='application-bridge-revoke'){
  const x=authenticationObject(admitted,['type','bridgeId','expectedManifestHash']);
  return Object.freeze({type:'application-bridge-revoke',bridgeId:S.uuid(x.bridgeId),expectedManifestHash:S.digest(x.expectedManifestHash)});
 }
 return fail();
}
export function parseApplicationBridgeManifest(input:unknown):Parsed<ApplicationBridgeManifest>{return authenticationParsed(()=>{
 const x=authenticationObject(input,['formatVersion','requestId','releaseReference','deploymentOperatorReference','expectedDatabaseOid','expectedOwnerRoleOid','predecessorManifestHash','operation']);
 if(x.formatVersion!==1)return fail();
 return Object.freeze({formatVersion:1,requestId:S.uuid(x.requestId),releaseReference:S.reference(x.releaseReference),deploymentOperatorReference:S.reference(x.deploymentOperatorReference),expectedDatabaseOid:S.oid(x.expectedDatabaseOid),expectedOwnerRoleOid:S.oid(x.expectedOwnerRoleOid),predecessorManifestHash:x.predecessorManifestHash===null?null:S.digest(x.predecessorManifestHash),operation:operation(x.operation)});
});}
export function parseApplicationBridgeManifestFile(text:string):Parsed<ApplicationBridgeManifest>{return authenticationParsed(()=>{
 if(typeof text!=='string'||text.length>INSTALLATION_INPUT_BYTES||Buffer.byteLength(text,'utf8')>INSTALLATION_INPUT_BYTES)return fail();
 const admitted=parseAuthorityInputFile(text);if(!admitted.ok||admitted.value.metrics.canonicalBytes>INSTALLATION_INPUT_BYTES)return fail();
 const parsed=parseApplicationBridgeManifest(admitted.value.data);if(!parsed.ok)return fail();return parsed.value;
});}
const arg=(name:string,type:InstallationArgumentType)=>Object.freeze({name,type});
const common=[arg('request_id','uuid'),arg('release_ref','text'),arg('operator_ref','text'),arg('expected_db_oid','oid'),arg('expected_owner_oid','oid'),arg('predecessor_hash','text')];
const signature=(functionName:string,...args:ReturnType<typeof arg>[]):InstallationSignature=>Object.freeze({functionName,arguments:Object.freeze([...common,...args])});
export const APPLICATION_BRIDGE_SIGNATURES:Readonly<Record<ApplicationBridgeOperation['type'],InstallationSignature>>=Object.freeze({
 'application-bridge-install':signature('install_application_bridge_v1',arg('bridge_id','uuid'),arg('expected_app_oid','oid'),arg('api_registration_id','uuid'),arg('bridge_generation','integer'),arg('authn_generation','integer'),arg('expires_at','timestamptz')),
 'application-bridge-revoke':signature('revoke_application_bridge_v1',arg('bridge_id','uuid'),arg('expected_manifest_hash','text')),
});
function validated(input:ApplicationBridgeManifest):ApplicationBridgeManifest {const parsed=parseApplicationBridgeManifest(input);if(!parsed.ok)return fail();return parsed.value;}
function values(m:ApplicationBridgeManifest):AuthenticationSQLValue[]{
 const base:AuthenticationSQLValue[]=[m.requestId,m.releaseReference,m.deploymentOperatorReference,m.expectedDatabaseOid,m.expectedOwnerRoleOid,m.predecessorManifestHash];
 const x=m.operation;
 return x.type==='application-bridge-install'?[...base,x.bridgeId,x.expectedAppRoleOid,x.apiRegistrationId,x.bridgeGeneration,x.authenticationGeneration,x.expiresAt]:[...base,x.bridgeId,x.expectedManifestHash];
}
export function applicationBridgeQuery(input:ApplicationBridgeManifest):AuthenticationQuery {
 const m=validated(input),spec=APPLICATION_BRIDGE_SIGNATURES[m.operation.type];
 return Object.freeze({text:`SELECT f.installation_id,f.manifest_hash,f.target_id,pg_catalog.to_char(f.recorded_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS recorded_at FROM gc_authn.${spec.functionName}(${spec.arguments.map((a,i)=>`$${i+1}::${a.type}`).join(',')}) AS f`,values:Object.freeze(values(m))});
}
const stringScalar=(s:string)=>`S${Buffer.byteLength(s,'utf8')}:${s}`;
export function applicationBridgeEncoding(input:ApplicationBridgeManifest):Uint8Array {
 const m=validated(input),spec=APPLICATION_BRIDGE_SIGNATURES[m.operation.type],parameters=values(m);
 let text='gc-app-authn-install/v1;'+stringScalar(m.operation.type);
 spec.arguments.forEach((a,i)=>{
  const value=parameters[i]!;text+=stringScalar(a.name);
  text+=value===null?'N;':a.type==='integer'||a.type==='oid'?`I${value};`:a.type==='uuid'?`U${value};`:a.type==='timestamptz'?`T${value};`:stringScalar(value as string);
 });
 const bytes=Buffer.from(text,'utf8');if(bytes.length>INSTALLATION_INPUT_BYTES)return fail();return new Uint8Array(bytes);
}
export function applicationBridgeHash(input:ApplicationBridgeManifest):Digest{return createHash('sha256').update(applicationBridgeEncoding(input)).digest('hex') as Digest;}
