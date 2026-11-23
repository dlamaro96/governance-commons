// SPDX-License-Identifier: Apache-2.0
/** Explicit local core activation. The persisted private manifests are replayed
 * exactly; neither restart nor seed invokes this command or renews authority. */
import {constants} from 'node:fs';
import {open,lstat,mkdir} from 'node:fs/promises';
import {resolve} from 'node:path';
import {randomUUID} from 'node:crypto';
import {spawn} from 'node:child_process';
import {Client} from 'pg';
import {AUTHENTICATION_SCALARS as S} from '../packages/authority/src/authentication.ts';
import {parseAuthorityInputFile} from '../packages/authority/src/admission.ts';
import {validateDemoManifests,type DemoInstallationConfig} from './authentication-install-demo.ts';
import {parseApplicationBridgeManifestFile,parseApplicationBridgeManifest,applicationBridgeHash} from '../packages/authn/src/application-installation.ts';
import {applyApplicationBridgeManifest} from './application-authentication-install.ts';
import {validatePublicAuthnConfig} from '../packages/authn/src/transport.ts';
async function readPrivate(path:string):Promise<string>{
 const f=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const before=await f.stat();if(!before.isFile()||before.uid!==process.getuid?.()||(before.mode&0o077)!==0||before.size<1||before.size>65536)throw Error();
  const bytes=Buffer.alloc(65537);let offset=0;
  while(offset<bytes.length){const r=await f.read(bytes,offset,bytes.length-offset,null);if(!r.bytesRead)break;offset+=r.bytesRead;}
  const after=await f.stat();if(offset!==before.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs||before.size!==after.size)throw Error();
  return new TextDecoder('utf8',{fatal:true}).decode(bytes.subarray(0,offset));
 }finally{await f.close();}
}
async function installDemo(folder:string):Promise<void>{
 await new Promise<void>((accept,reject)=>{
  const child=spawn(process.execPath,['--import','tsx','scripts/authentication-install-demo.ts','--batch',folder],{stdio:['ignore','pipe','pipe'],env:process.env});
  let bytes=0,failed=false;const timer=setTimeout(()=>{failed=true;child.kill('SIGKILL');},120000);timer.unref();
  const consume=(chunk:Buffer)=>{bytes+=chunk.length;if(bytes>8192){failed=true;child.kill('SIGKILL');}};
  child.stdout.on('data',consume);child.stderr.on('data',consume);child.on('error',()=>{clearTimeout(timer);reject(Error());});
  child.on('close',code=>{clearTimeout(timer);code===0&&!failed?accept():reject(Error());});
 });
}
async function main(){
 if(process.argv.length!==4||process.argv[2]!=='--batch'||!process.env.MIGRATION_DATABASE_URL)throw Error();
 const config={issuer:process.env.OIDC_ISSUER??'',publicOrigin:process.env.PUBLIC_AUTHN_ORIGIN??'',environment:process.env.AUTHN_ENVIRONMENT as DemoInstallationConfig['environment']};
 validatePublicAuthnConfig(config);if(!['local-development','isolated-test'].includes(config.environment))throw Error();
 const folder=resolve(process.argv[3]!);await mkdir(folder,{recursive:true,mode:0o700});const stat=await lstat(folder);
 if(!stat.isDirectory()||stat.isSymbolicLink()||stat.uid!==process.getuid?.()||(stat.mode&0o077)!==0)throw Error();
 await installDemo(folder);
 const owner=new Client({connectionString:process.env.MIGRATION_DATABASE_URL,connectionTimeoutMillis:5000,statement_timeout:5000,lock_timeout:2000,query_timeout:6000});
 let target:{databaseOid:number;ownerRoleOid:number;loginRoleOid:number;apiRoleOid:number},appOid:number;
 try{
  await owner.connect();await owner.query('SELECT gc_authn.install_check($1,$2,$3,(SELECT oid FROM pg_database WHERE datname=current_database()),session_user::regrole::oid,NULL)',[randomUUID(),'synthetic/core-readiness','explicit-local-installation']);
  const q=await owner.query(`SELECT (SELECT oid FROM pg_database WHERE datname=current_database()) db,session_user::regrole::oid owner,
   (SELECT oid FROM pg_roles WHERE rolname='gc_authn_login') login,(SELECT oid FROM pg_roles WHERE rolname='gc_authn_api') api,(SELECT oid FROM pg_roles WHERE rolname='gc_app') app`);
  const r=q.rows[0];target={databaseOid:S.oid(r.db),ownerRoleOid:S.oid(r.owner),loginRoleOid:S.oid(r.login),apiRoleOid:S.oid(r.api)};appOid=S.oid(r.app);
 }finally{await owner.end().catch(()=>undefined);}
 const parsed=parseAuthorityInputFile(await readPrivate(folder+'/plan.json'));if(!parsed.ok)throw Error();
 const plan=parsed.value.data as unknown as {version:number;config:DemoInstallationConfig;target:typeof target;manifests:unknown[]};
 if(!plan||Array.isArray(plan)||Object.keys(plan).sort().join(',')!=='config,manifests,target,version'||plan.version!==1
  ||!plan.config||Object.keys(plan.config).sort().join(',')!=='environment,issuer,publicOrigin'||Object.entries(config).some(([key,value])=>plan.config[key as keyof DemoInstallationConfig]!==value)
  ||!plan.target||Object.keys(plan.target).sort().join(',')!=='apiRoleOid,databaseOid,loginRoleOid,ownerRoleOid'||Object.entries(target).some(([key,value])=>plan.target[key as keyof typeof target]!==value)
  ||!Array.isArray(plan.manifests))throw Error();
 const manifests=validateDemoManifests(plan.manifests,config,target),api=manifests[2]!.operation;
 if(api.type!=='register-executor'||api.kind!=='api')throw Error();
 const path=folder+'/application-bridge.json';let text:string;
 try{text=await readPrivate(path);}catch(error){
  if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;
  const candidate=parseApplicationBridgeManifest({formatVersion:1,requestId:randomUUID(),releaseReference:'governance-commons/protected-core/v1',deploymentOperatorReference:'explicit-local-core-installation',expectedDatabaseOid:target.databaseOid,expectedOwnerRoleOid:target.ownerRoleOid,predecessorManifestHash:null,
   operation:{type:'application-bridge-install',bridgeId:randomUUID(),expectedAppRoleOid:appOid,apiRegistrationId:api.registrationId,bridgeGeneration:1,authenticationGeneration:api.generation,expiresAt:api.expiresAt}});
  if(!candidate.ok)throw Error();
  const f=await open(path,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{await f.writeFile(JSON.stringify(candidate.value,null,2)+'\n');await f.sync();}finally{await f.close();}
  text=await readPrivate(path);
 }
 const m=parseApplicationBridgeManifestFile(text);if(!m.ok)throw Error();const op=m.value.operation;
 if(m.value.releaseReference!=='governance-commons/protected-core/v1'||m.value.deploymentOperatorReference!=='explicit-local-core-installation'||m.value.expectedDatabaseOid!==target.databaseOid||m.value.expectedOwnerRoleOid!==target.ownerRoleOid||m.value.predecessorManifestHash!==null||op.type!=='application-bridge-install'||op.expectedAppRoleOid!==appOid||op.apiRegistrationId!==api.registrationId||op.authenticationGeneration!==api.generation||op.bridgeGeneration!==1||op.expiresAt!==api.expiresAt)throw Error();
 const receipt=await applyApplicationBridgeManifest(m.value,process.env.MIGRATION_DATABASE_URL);
 if(receipt.manifestHash!==applicationBridgeHash(m.value))throw Error();
 console.log(JSON.stringify({result:'COMMITTED',applicationAuthentication:true,contentAuthority:false,renewed:false,expiresAt:op.expiresAt}));
}
main().catch(()=>{process.stderr.write('CORE_AUTHENTICATION_INSTALLATION_NOT_CONFIRMED: preserve the private batch and replay it exactly after checking prerequisites. Expired or revoked installations require a separate explicit successor manifest.\n');process.exitCode=1;});
