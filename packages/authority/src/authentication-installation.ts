// SPDX-License-Identifier: Apache-2.0
import {createHash} from 'node:crypto';
import {parseAuthorityInputFile} from './admission.ts';
import type {Parsed,UUID,Digest,UTC} from './types.ts';
import {AUTHENTICATION_SCALARS as S,AuthenticationError,authenticationObject,authenticationParsed,type AuthenticationQuery,type AuthenticationSQLValue} from './authentication.ts';

export type ExecutorKind='login'|'api';
export type InstallationEnvironment='isolated-test'|'local-development'|'production';
export type InstallationOperation=
 | {readonly type:'register-executor';readonly registrationId:UUID;readonly channelId:UUID;readonly roleName:string;readonly expectedRoleOid:number;readonly kind:ExecutorKind;readonly generation:number;readonly expiresAt:UTC}
 | {readonly type:'advance-generation';readonly kind:ExecutorKind;readonly channelId:UUID;readonly registrationId:UUID;readonly expectedPreviousRegistrationId:UUID|null;readonly expectedHeadVersion:number|null}
 | {readonly type:'register-issuer';readonly issuerId:UUID;readonly registrationId:UUID;readonly generation:number;readonly issuer:string;readonly clientId:string;readonly redirectUri:string;readonly environment:InstallationEnvironment;readonly expiresAt:UTC}
 | {readonly type:'bind-identity';readonly bindingId:UUID;readonly issuerId:UUID;readonly identityId:UUID;readonly expectedCanonicalIssuer:string;readonly expectedCanonicalSubject:string;readonly expiresAt:UTC}
 | {readonly type:'initialize-tenant';readonly tenantId:UUID;readonly generation:number}
 | {readonly type:'advance-tenant-generation';readonly tenantId:UUID;readonly expectedGeneration:number;readonly expectedEpoch:number;readonly generation:number}
 | {readonly type:'revoke-executor';readonly registrationId:UUID}
 | {readonly type:'revoke-issuer';readonly issuerId:UUID}
 | {readonly type:'revoke-binding';readonly bindingId:UUID};
export type InstallationManifest={readonly formatVersion:1;readonly requestId:UUID;readonly releaseReference:string;readonly deploymentOperatorReference:string;readonly expectedDatabaseOid:number;readonly expectedOwnerRoleOid:number;readonly predecessorManifestHash:Digest|null;readonly operation:InstallationOperation};
export type InstallationReceipt={readonly installationId:UUID;readonly manifestHash:Digest;readonly targetId:UUID;readonly recordedAt:UTC};
export type InstallationArgumentType='text'|'integer'|'oid'|'uuid'|'timestamptz';
export type InstallationArgument={readonly name:string;readonly type:InstallationArgumentType};
export type InstallationSignature={readonly functionName:string;readonly arguments:readonly InstallationArgument[]};
export const INSTALLATION_INPUT_BYTES=65_536;
const fail=():never=>{throw new AuthenticationError('AUTHN_INPUT_INVALID');};
const kind=(value:unknown):ExecutorKind=>value==='login'||value==='api'?value:fail();
const environment=(value:unknown):InstallationEnvironment=>value==='isolated-test'||value==='local-development'||value==='production'?value:fail();
const nullableUUID=(value:unknown)=>value===null?null:S.uuid(value);
const nullableVersion=(value:unknown)=>value===null?null:S.integer(value);
function endpoint(value:unknown,profile:InstallationEnvironment):string {
 const text=S.text(value,2048);
 // Admit the same raw grammar as SQL; URL parsers repair strings and normalize hosts.
 const match=/^(https?):\/\/(\[::1\]|[a-z0-9.-]+)(?::([1-9][0-9]{0,4}))?([/?][A-Za-z0-9._~!$&'()*+,;=:@/?%-]*)?$/.exec(text);
 if(!match||/%(?![A-Fa-f0-9]{2})/.test(text))return fail();
 const [,scheme,host,port]=match;if(!host||(port!==undefined&&Number(port)>65535))return fail();
 if(host!=='[::1]'){
  if(/^[0-9.]+$/.test(host)){
   const parts=host.split('.');if(parts.length!==4||parts.some(part=>!/^(?:0|[1-9][0-9]{0,2})$/.test(part)||Number(part)>255))return fail();
  }else{
   const labels=host.split('.');
   if(host.length>253||labels.some(label=>!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))||!/[a-z]/.test(labels.at(-1)?.[0]??''))return fail();
  }
 }
 if(scheme==='http'&&(profile==='production'||!['localhost','127.0.0.1','[::1]'].includes(host)))return fail();
 return text;
}
function operation(input:unknown):InstallationOperation {
 // The outer admission already detached the record, so reading this discriminant cannot run a getter.
 if(input===null||typeof input!=='object'||Array.isArray(input))return fail();
 const admitted=authenticationObject(input,Object.keys(input));
 switch(admitted.type){
  case 'register-executor': {const x=authenticationObject(admitted,['type','registrationId','channelId','roleName','expectedRoleOid','kind','generation','expiresAt']);return Object.freeze({type:'register-executor',registrationId:S.uuid(x.registrationId),channelId:S.uuid(x.channelId),roleName:S.roleName(x.roleName),expectedRoleOid:S.oid(x.expectedRoleOid),kind:kind(x.kind),generation:S.integer(x.generation),expiresAt:S.time(x.expiresAt)});}
  case 'advance-generation': {const x=authenticationObject(admitted,['type','kind','channelId','registrationId','expectedPreviousRegistrationId','expectedHeadVersion']);const expectedPreviousRegistrationId=nullableUUID(x.expectedPreviousRegistrationId),expectedHeadVersion=nullableVersion(x.expectedHeadVersion);if((expectedPreviousRegistrationId===null)!==(expectedHeadVersion===null))return fail();return Object.freeze({type:'advance-generation',kind:kind(x.kind),channelId:S.uuid(x.channelId),registrationId:S.uuid(x.registrationId),expectedPreviousRegistrationId,expectedHeadVersion});}
  case 'register-issuer': {const x=authenticationObject(admitted,['type','issuerId','registrationId','generation','issuer','clientId','redirectUri','environment','expiresAt']);const profile=environment(x.environment);return Object.freeze({type:'register-issuer',issuerId:S.uuid(x.issuerId),registrationId:S.uuid(x.registrationId),generation:S.integer(x.generation),issuer:endpoint(x.issuer,profile),clientId:S.text(x.clientId,256),redirectUri:endpoint(x.redirectUri,profile),environment:profile,expiresAt:S.time(x.expiresAt)});}
  case 'bind-identity': {const x=authenticationObject(admitted,['type','bindingId','issuerId','identityId','expectedCanonicalIssuer','expectedCanonicalSubject','expiresAt']);return Object.freeze({type:'bind-identity',bindingId:S.uuid(x.bindingId),issuerId:S.uuid(x.issuerId),identityId:S.uuid(x.identityId),expectedCanonicalIssuer:S.text(x.expectedCanonicalIssuer,2048),expectedCanonicalSubject:S.text(x.expectedCanonicalSubject,1024),expiresAt:S.time(x.expiresAt)});}
  case 'initialize-tenant': {const x=authenticationObject(admitted,['type','tenantId','generation']);return Object.freeze({type:'initialize-tenant',tenantId:S.uuid(x.tenantId),generation:S.integer(x.generation)});}
  case 'advance-tenant-generation': {const x=authenticationObject(admitted,['type','tenantId','expectedGeneration','expectedEpoch','generation']);const expectedGeneration=S.integer(x.expectedGeneration),generation=S.integer(x.generation);if(generation<=expectedGeneration)return fail();return Object.freeze({type:'advance-tenant-generation',tenantId:S.uuid(x.tenantId),expectedGeneration,expectedEpoch:S.integer(x.expectedEpoch),generation});}
  case 'revoke-executor': {const x=authenticationObject(admitted,['type','registrationId']);return Object.freeze({type:'revoke-executor',registrationId:S.uuid(x.registrationId)});}
  case 'revoke-issuer': {const x=authenticationObject(admitted,['type','issuerId']);return Object.freeze({type:'revoke-issuer',issuerId:S.uuid(x.issuerId)});}
  case 'revoke-binding': {const x=authenticationObject(admitted,['type','bindingId']);return Object.freeze({type:'revoke-binding',bindingId:S.uuid(x.bindingId)});}
  default:return fail();
 }
}
export function parseInstallationManifest(input:unknown):Parsed<InstallationManifest>{return authenticationParsed(()=>{
 const x=authenticationObject(input,['formatVersion','requestId','releaseReference','deploymentOperatorReference','expectedDatabaseOid','expectedOwnerRoleOid','predecessorManifestHash','operation']);
 if(x.formatVersion!==1)return fail();
 return Object.freeze({formatVersion:1,requestId:S.uuid(x.requestId),releaseReference:S.reference(x.releaseReference),deploymentOperatorReference:S.reference(x.deploymentOperatorReference),expectedDatabaseOid:S.oid(x.expectedDatabaseOid),expectedOwnerRoleOid:S.oid(x.expectedOwnerRoleOid),predecessorManifestHash:x.predecessorManifestHash===null?null:S.digest(x.predecessorManifestHash),operation:operation(x.operation)});
});}
export function parseInstallationManifestFile(text:string):Parsed<InstallationManifest>{return authenticationParsed(()=>{
 if(typeof text!=='string'||text.length>INSTALLATION_INPUT_BYTES||Buffer.byteLength(text,'utf8')>INSTALLATION_INPUT_BYTES)return fail();
 const admitted=parseAuthorityInputFile(text);if(!admitted.ok||admitted.value.metrics.canonicalBytes>INSTALLATION_INPUT_BYTES)return fail();
 const parsed=parseInstallationManifest(admitted.value.data);if(!parsed.ok)return fail();return parsed.value;
});}
const arg=(name:string,type:InstallationArgumentType):InstallationArgument=>Object.freeze({name,type});
const common=Object.freeze([arg('request_id','uuid'),arg('release_ref','text'),arg('operator_ref','text'),arg('expected_db_oid','oid'),arg('expected_owner_oid','oid'),arg('predecessor_hash','text')]);
const signature=(functionName:string,...args:InstallationArgument[]):InstallationSignature=>Object.freeze({functionName,arguments:Object.freeze([...common,...args])});
export const INSTALLATION_SIGNATURES:Readonly<Record<InstallationOperation['type'],InstallationSignature>>=Object.freeze({
 'register-executor':signature('provision_executor',arg('registration_id','uuid'),arg('channel_id','uuid'),arg('role_name','text'),arg('expected_role_oid','oid'),arg('kind','text'),arg('generation','integer'),arg('expires_at','timestamptz')),
 'advance-generation':signature('advance_generation',arg('kind','text'),arg('channel_id','uuid'),arg('registration_id','uuid'),arg('expected_previous_registration_id','uuid'),arg('expected_head_version','integer')),
 'register-issuer':signature('provision_issuer',arg('issuer_id','uuid'),arg('registration_id','uuid'),arg('generation','integer'),arg('issuer','text'),arg('client_id','text'),arg('redirect_uri','text'),arg('environment','text'),arg('expires_at','timestamptz')),
 'bind-identity':signature('bind_identity',arg('binding_id','uuid'),arg('issuer_id','uuid'),arg('identity_id','uuid'),arg('expected_issuer','text'),arg('expected_subject','text'),arg('expires_at','timestamptz')),
 'initialize-tenant':signature('initialize_tenant',arg('tenant_id','uuid'),arg('generation','integer')),
 'advance-tenant-generation':signature('advance_tenant_generation',arg('tenant_id','uuid'),arg('expected_generation','integer'),arg('expected_epoch','integer'),arg('generation','integer')),
 'revoke-executor':signature('revoke_executor',arg('registration_id','uuid')),
 'revoke-issuer':signature('revoke_issuer',arg('issuer_id','uuid')),
 'revoke-binding':signature('revoke_binding',arg('binding_id','uuid')),
});
function validated(input:InstallationManifest):InstallationManifest {const result=parseInstallationManifest(input);if(!result.ok)return fail();return result.value;}
function values(manifest:InstallationManifest):AuthenticationSQLValue[]{
 const base:AuthenticationSQLValue[]=[manifest.requestId,manifest.releaseReference,manifest.deploymentOperatorReference,manifest.expectedDatabaseOid,manifest.expectedOwnerRoleOid,manifest.predecessorManifestHash];const x=manifest.operation;
 switch(x.type){
  case 'register-executor':return [...base,x.registrationId,x.channelId,x.roleName,x.expectedRoleOid,x.kind,x.generation,x.expiresAt];
  case 'advance-generation':return [...base,x.kind,x.channelId,x.registrationId,x.expectedPreviousRegistrationId,x.expectedHeadVersion];
  case 'register-issuer':return [...base,x.issuerId,x.registrationId,x.generation,x.issuer,x.clientId,x.redirectUri,x.environment,x.expiresAt];
  case 'bind-identity':return [...base,x.bindingId,x.issuerId,x.identityId,x.expectedCanonicalIssuer,x.expectedCanonicalSubject,x.expiresAt];
  case 'initialize-tenant':return [...base,x.tenantId,x.generation];
  case 'advance-tenant-generation':return [...base,x.tenantId,x.expectedGeneration,x.expectedEpoch,x.generation];
  case 'revoke-executor':return [...base,x.registrationId];
  case 'revoke-issuer':return [...base,x.issuerId];
  case 'revoke-binding':return [...base,x.bindingId];
 }
}
export function installationQuery(input:InstallationManifest):AuthenticationQuery {
 const manifest=validated(input),spec=INSTALLATION_SIGNATURES[manifest.operation.type];
 const placeholders=spec.arguments.map((a,i)=>`$${i+1}::${a.type}`).join(',');
 return Object.freeze({text:`SELECT f.installation_id,f.manifest_hash,f.target_id,pg_catalog.to_char(f.recorded_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS recorded_at FROM gc_authn.${spec.functionName}(${placeholders}) AS f`,values:Object.freeze(values(manifest))});
}
const stringScalar=(value:string)=>`S${Buffer.byteLength(value,'utf8')}:${value}`;
function scalar(value:AuthenticationSQLValue,type:InstallationArgumentType):string {
 if(value===null)return 'N;';
 if(type==='integer'||type==='oid')return `I${value};`;
 if(type==='uuid')return `U${value};`;
 if(type==='timestamptz')return `T${value};`;
 return stringScalar(value as string);
}
export function installationEncoding(input:InstallationManifest):Uint8Array {
 const manifest=validated(input),spec=INSTALLATION_SIGNATURES[manifest.operation.type],parameters=values(manifest);
 let text=`gc-authn-install/v1;${stringScalar(manifest.operation.type)}`;
 for(let i=0;i<spec.arguments.length;i++){const a=spec.arguments[i]!;text+=stringScalar(a.name)+scalar(parameters[i]!,a.type);}
 const bytes=Buffer.from(text,'utf8');if(bytes.byteLength>INSTALLATION_INPUT_BYTES)return fail();return new Uint8Array(bytes);
}
export function installationHash(input:InstallationManifest):Digest {return createHash('sha256').update(installationEncoding(input)).digest('hex') as Digest;}
export function parseInstallationReceipt(input:unknown):Parsed<InstallationReceipt>{return authenticationParsed(()=>{
 const x=authenticationObject(input,['installation_id','manifest_hash','target_id','recorded_at']);return Object.freeze({installationId:S.uuid(x.installation_id),manifestHash:S.digest(x.manifest_hash),targetId:S.uuid(x.target_id),recordedAt:S.time(x.recorded_at)});
});}
