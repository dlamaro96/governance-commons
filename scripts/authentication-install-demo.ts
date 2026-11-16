// SPDX-License-Identifier: Apache-2.0
/** Explicit local installation only. Ordinary bootstrap/seed never invokes this file. */
import { constants } from 'node:fs';
import { open, mkdir, lstat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import pg from 'pg';
import { parseAuthorityInputFile } from '../packages/authority/src/admission.ts';
import { parseInstallationManifest, installationHash, type InstallationManifest, type InstallationOperation } from '../packages/authority/src/authentication-installation.ts';
import { AUTHENTICATION_SCALARS as S } from '../packages/authority/src/authentication.ts';
import { validatePublicAuthnConfig } from '../packages/authn/src/transport.ts';
import type { Digest } from '../packages/authority/src/types.ts';

const identities=Array.from({length:6},(_,i)=>`10000000-0000-4000-8000-${String(i+1).padStart(12,'0')}`);
type InstallationStage='admission'|'private-directory'|'owner-connect'|'native-target'|'canonical-identities'|'private-plan'|'plan-create'|'plan-validate'|'manifest-apply';
let installationStage:InstallationStage='admission';
export function safeDemoInstallationReason(error:unknown):string{
 const allowed=new Set(['BATCH_REQUIRED','LOCAL_ONLY','PRIVATE_DIRECTORY_REQUIRED','PRIVATE_PLAN_REQUIRED','PLAN_TOO_LARGE','OWNER_REQUIRED','CANONICAL_IDENTITIES_REQUIRED','PLAN_INVALID','PLAN_TARGET_MISMATCH','MANIFEST_INVALID','INSTALL_NOT_CONFIRMED','AUTHN_UNAVAILABLE']);
 return error instanceof Error&&allowed.has(error.message)?error.message:'PREREQUISITE_OR_OPERATION_FAILED';
}
const tenants=['aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'];
type Target={databaseOid:number;ownerRoleOid:number;loginRoleOid:number;apiRoleOid:number};
export type DemoInstallationConfig={issuer:string;publicOrigin:string;environment:'isolated-test'|'local-development'};
export function createDemoManifests(config:DemoInstallationConfig,target:Target,expiresAt:string):readonly InstallationManifest[] {
 validatePublicAuthnConfig(config);
 if(config.environment!=='isolated-test'&&config.environment!=='local-development')throw Error('LOCAL_ONLY');
 const expiry=S.time(expiresAt),loginId=S.uuid(randomUUID()),loginChannel=S.uuid(randomUUID()),apiId=S.uuid(randomUUID()),apiChannel=S.uuid(randomUUID()),issuerId=S.uuid(randomUUID());
 const operations:InstallationOperation[]=[
  {type:'register-executor',registrationId:loginId,channelId:loginChannel,roleName:'gc_authn_login',expectedRoleOid:S.oid(target.loginRoleOid),kind:'login',generation:1,expiresAt:expiry},
  {type:'advance-generation',kind:'login',channelId:loginChannel,registrationId:loginId,expectedPreviousRegistrationId:null,expectedHeadVersion:null},
  {type:'register-executor',registrationId:apiId,channelId:apiChannel,roleName:'gc_authn_api',expectedRoleOid:S.oid(target.apiRoleOid),kind:'api',generation:1,expiresAt:expiry},
  {type:'advance-generation',kind:'api',channelId:apiChannel,registrationId:apiId,expectedPreviousRegistrationId:null,expectedHeadVersion:null},
  {type:'register-issuer',issuerId,registrationId:loginId,generation:1,issuer:config.issuer,clientId:'governance-protected-web',redirectUri:config.publicOrigin+'/authn/callback',environment:config.environment,expiresAt:expiry},
  ...identities.map(id=>({type:'bind-identity' as const,bindingId:S.uuid(randomUUID()),issuerId,identityId:S.uuid(id),expectedCanonicalIssuer:config.issuer,expectedCanonicalSubject:id,expiresAt:expiry})),
  ...tenants.map(id=>({type:'initialize-tenant' as const,tenantId:S.uuid(id),generation:1})),
 ];
 let predecessor:Digest|null=null;
 return Object.freeze(operations.map(operation=>{
  const parsed=parseInstallationManifest({formatVersion:1,requestId:randomUUID(),releaseReference:'governance-commons/protected-authentication-local/v1',deploymentOperatorReference:'explicit-local-development-installation',expectedDatabaseOid:target.databaseOid,expectedOwnerRoleOid:target.ownerRoleOid,predecessorManifestHash:predecessor,operation});
  if(!parsed.ok)throw Error('MANIFEST_INVALID');
  predecessor=installationHash(parsed.value);return parsed.value;
 }));
}
export function validateDemoManifests(raw:readonly unknown[],config:DemoInstallationConfig,target:Target):readonly InstallationManifest[]{
 if(raw.length!==13)throw Error('PLAN_INVALID');
 let predecessor:Digest|null=null;
 const manifests=raw.map(value=>{
  const parsed=parseInstallationManifest(value);
  if(!parsed.ok||parsed.value.predecessorManifestHash!==predecessor||parsed.value.expectedDatabaseOid!==target.databaseOid
   ||parsed.value.expectedOwnerRoleOid!==target.ownerRoleOid||parsed.value.releaseReference!=='governance-commons/protected-authentication-local/v1'
   ||parsed.value.deploymentOperatorReference!=='explicit-local-development-installation')throw Error('PLAN_INVALID');
  predecessor=installationHash(parsed.value);return parsed.value;
 });
 const operations=manifests.map(m=>m.operation);
 const login=operations[0]!,loginHead=operations[1]!,api=operations[2]!,apiHead=operations[3]!,issuer=operations[4]!;
 if(login.type!=='register-executor'||api.type!=='register-executor'||loginHead.type!=='advance-generation'||apiHead.type!=='advance-generation'||issuer.type!=='register-issuer')throw Error('PLAN_INVALID');
 for(const [role,head,kind,oid] of [[login,loginHead,'login',target.loginRoleOid],[api,apiHead,'api',target.apiRoleOid]] as const){
  if(role.kind!==kind||role.roleName!==`gc_authn_${kind}`||role.expectedRoleOid!==oid||role.generation!==1||role.expiresAt!==login.expiresAt
   ||head.kind!==kind||head.channelId!==role.channelId||head.registrationId!==role.registrationId||head.expectedPreviousRegistrationId!==null||head.expectedHeadVersion!==null)throw Error('PLAN_INVALID');
 }
 if(login.registrationId===api.registrationId||login.channelId===api.channelId||issuer.registrationId!==login.registrationId||issuer.generation!==1
  ||issuer.clientId!=='governance-protected-web'||issuer.issuer!==config.issuer||issuer.redirectUri!==config.publicOrigin+'/authn/callback'
  ||issuer.environment!==config.environment||issuer.expiresAt!==login.expiresAt)throw Error('PLAN_INVALID');
 for(let i=0;i<identities.length;i++){
  const op=operations[5+i]!;if(op.type!=='bind-identity'||op.issuerId!==issuer.issuerId||op.identityId!==identities[i]
   ||op.expectedCanonicalIssuer!==config.issuer||op.expectedCanonicalSubject!==identities[i]||op.expiresAt!==login.expiresAt)throw Error('PLAN_INVALID');
 }
 for(let i=0;i<tenants.length;i++){const op=operations[11+i]!;if(op.type!=='initialize-tenant'||op.tenantId!==tenants[i]||op.generation!==1)throw Error('PLAN_INVALID');}
 return Object.freeze(manifests);
}
async function privateRead(path:string):Promise<string>{
 const file=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW);
 try {
  const stat=await file.stat();
  if(!stat.isFile()||(stat.mode&0o077)!==0||stat.uid!==process.getuid?.()||stat.size>65_536)throw Error('PRIVATE_PLAN_REQUIRED');
  const data=Buffer.alloc(65_537);let offset=0;
  for(;;){const {bytesRead}=await file.read(data,offset,data.length-offset,null);if(!bytesRead)break;offset+=bytesRead;if(offset>65_536)throw Error('PLAN_TOO_LARGE');}
  return new TextDecoder('utf-8',{fatal:true}).decode(data.subarray(0,offset));
 }finally{await file.close();}
}
async function apply(manifest:InstallationManifest):Promise<Record<string,unknown>>{
 return new Promise((accept,reject)=>{
  const child=spawn(process.execPath,['--import','tsx','scripts/authentication-install.ts','--stdin'],{stdio:['pipe','pipe','pipe'],env:process.env});
  const output:Buffer[]=[];let size=0,failed=false;
  const timer=setTimeout(()=>{failed=true;child.kill('SIGKILL');},45_000);timer.unref();
  const capture=(chunk:Buffer,save:boolean)=>{size+=chunk.length;if(size>8192){failed=true;child.kill('SIGKILL');}else if(save)output.push(chunk);};
  child.stdout.on('data',chunk=>capture(chunk,true));child.stderr.on('data',chunk=>capture(chunk,false));
  child.on('error',()=>{clearTimeout(timer);reject(Error('INSTALL_NOT_CONFIRMED'));});
  child.on('close',code=>{
   clearTimeout(timer);
   if(code!==0||failed){reject(Error('INSTALL_NOT_CONFIRMED'));return;}
   try{
    const admitted=parseAuthorityInputFile(Buffer.concat(output).toString('utf8'));
    if(!admitted.ok)throw Error('RECEIPT_INVALID');
    const receipt=admitted.value.data as Record<string,unknown>;
    if(!receipt||Array.isArray(receipt)||Object.keys(receipt).sort().join(',')!=='installationId,manifestHash,recordedAt,result,targetId'
      ||receipt.result!=='COMMITTED_INACTIVE'||receipt.manifestHash!==installationHash(manifest))throw Error('RECEIPT_INVALID');
    S.uuid(receipt.installationId);S.uuid(receipt.targetId);S.time(receipt.recordedAt);accept(receipt);
   }catch{reject(Error('INSTALL_NOT_CONFIRMED'));}
  });
  child.stdin.on('error',()=>undefined);child.stdin.end(JSON.stringify(manifest));
 });
}
async function main(){
 if(process.argv.length!==4||process.argv[2]!=='--batch')throw Error('BATCH_REQUIRED');
 const config={issuer:process.env.OIDC_ISSUER ?? '',publicOrigin:process.env.PUBLIC_AUTHN_ORIGIN ?? '',environment:process.env.AUTHN_ENVIRONMENT as DemoInstallationConfig['environment']};
 validatePublicAuthnConfig(config);
 if(!['isolated-test','local-development'].includes(config.environment))throw Error('LOCAL_ONLY');
 installationStage='private-directory';
 const folder=resolve(process.argv[3]!);await mkdir(folder,{mode:0o700,recursive:true});
 const stat=await lstat(folder);if(!stat.isDirectory()||stat.isSymbolicLink()||(stat.mode&0o077)!==0||stat.uid!==process.getuid?.())throw Error('PRIVATE_DIRECTORY_REQUIRED');
 const client=new pg.Client({connectionString:process.env.MIGRATION_DATABASE_URL,application_name:'gc-authn-explicit-demo-install',connectionTimeoutMillis:5_000,statement_timeout:5_000,lock_timeout:2_000});
 if(!process.env.MIGRATION_DATABASE_URL)throw Error('OWNER_REQUIRED');
 let target:Target;
 try {
  installationStage='owner-connect';await client.connect();
  installationStage='native-target';
  const result=await client.query(`SELECT d.oid AS database_oid, o.oid AS owner_role_oid,
   (SELECT oid FROM pg_roles WHERE rolname='gc_authn_login') AS login_role_oid,
   (SELECT oid FROM pg_roles WHERE rolname='gc_authn_api') AS api_role_oid
   FROM pg_database d JOIN pg_roles o ON o.oid=d.datdba
   WHERE d.datname=current_database() AND o.rolname=session_user AND current_user=session_user
    AND NOT o.rolsuper AND NOT o.rolbypassrls AND NOT o.rolcreaterole AND NOT o.rolcreatedb`);
  if(result.rows.length!==1)throw Error('OWNER_REQUIRED');
  const row=result.rows[0];target={databaseOid:S.oid(row.database_oid),ownerRoleOid:S.oid(row.owner_role_oid),loginRoleOid:S.oid(row.login_role_oid),apiRoleOid:S.oid(row.api_role_oid)};
  installationStage='canonical-identities';
  const rows=await client.query('SELECT id,issuer,subject FROM public.identities WHERE id=ANY($1::uuid[]) ORDER BY id',[identities]);
  if(rows.rows.length!==6||rows.rows.some((r,i)=>r.id!==identities[i]||r.issuer!==config.issuer||r.subject!==r.id))throw Error('CANONICAL_IDENTITIES_REQUIRED');
 }finally{await client.end().catch(()=>undefined);}
 installationStage='private-plan';
 const path=folder+'/plan.json';let text:string;
 try{text=await privateRead(path);}catch(error){
  if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;
  installationStage='plan-create';
  const manifests=createDemoManifests(config,target,new Date(Date.now()+86_400_000).toISOString());
  const bytes=Buffer.from(JSON.stringify({version:1,config,target,manifests},null,2)+'\n');
  const file=await open(path,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{await file.writeFile(bytes);await file.sync();}finally{await file.close();}
  text=await privateRead(path);
 }
 installationStage='plan-validate';
 const parsed=parseAuthorityInputFile(text);if(!parsed.ok)throw Error('PLAN_INVALID');
 const plan=parsed.value.data as unknown as {version:number;config:DemoInstallationConfig;target:Target;manifests:unknown[]};
 if(!plan||Array.isArray(plan)||Object.keys(plan).sort().join(',')!=='config,manifests,target,version'||plan.version!==1
   ||!plan.config||Object.keys(plan.config).sort().join(',')!=='environment,issuer,publicOrigin'||Object.entries(config).some(([k,v])=>plan.config[k as keyof DemoInstallationConfig]!==v)||!plan.target||Object.keys(plan.target).sort().join(',')!=='apiRoleOid,databaseOid,loginRoleOid,ownerRoleOid'||Object.entries(target).some(([k,v])=>plan.target[k as keyof Target]!==v)
   ||!Array.isArray(plan.manifests)||plan.manifests.length!==13)throw Error('PLAN_TARGET_MISMATCH');
 const manifests=validateDemoManifests(plan.manifests,config,target);
 installationStage='manifest-apply';
 for(const manifest of manifests)await apply(manifest);
 console.log(JSON.stringify({result:'COMMITTED_INACTIVE',operations:manifests.length,renewed:false}));
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(error=>{
 process.stderr.write(`AUTHN_DEMO_INSTALLATION_NOT_CONFIRMED stage=${installationStage} reason=${safeDemoInstallationReason(error)}: preserve the private batch and replay that exact batch after inspecting prerequisites; no renewal or reactivation was attempted.\n`);process.exitCode=1;
});
