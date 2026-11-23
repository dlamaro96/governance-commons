// SPDX-License-Identifier: Apache-2.0
/** Explicit owner-only SQL037 installation/revocation. No role provisioning,
 * expiry renewal, generation selection or implicit activation occurs here. */
import {constants} from 'node:fs';
import {open} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {Client} from 'pg';
import {INSTALLATION_INPUT_BYTES,parseInstallationReceipt,type InstallationReceipt} from '../packages/authority/src/authentication-installation.ts';
import {applicationBridgeHash,applicationBridgeQuery,parseApplicationBridgeManifestFile,type ApplicationBridgeManifest} from '../packages/authn/src/application-installation.ts';

async function input(args:string[]):Promise<{bytes:Uint8Array;check:boolean}>{
 const check=args.includes('--check'),rest=args.filter(x=>x!=='--check');if(args.filter(x=>x==='--check').length>1)throw Error();
 if(rest.length===1&&rest[0]==='--stdin'){
  const parts:Buffer[]=[];let length=0;
  for await(const part of process.stdin){const b=Buffer.from(part);length+=b.length;if(length>INSTALLATION_INPUT_BYTES)throw Error();parts.push(b);}
  return {bytes:Buffer.concat(parts,length),check};
 }
 if(rest.length!==2||rest[0]!=='--input')throw Error();
 const f=await open(rest[1]!,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const before=await f.stat();
  if(!before.isFile()||(before.mode&0o077)!==0||before.uid!==process.getuid?.()||before.size<1||before.size>INSTALLATION_INPUT_BYTES)throw Error();
  const b=Buffer.alloc(INSTALLATION_INPUT_BYTES+1);let offset=0;
  while(offset<b.length){const r=await f.read(b,offset,b.length-offset,null);if(!r.bytesRead)break;offset+=r.bytesRead;}
  const after=await f.stat();
  if(offset!==before.size||before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs)throw Error();
  return {bytes:b.subarray(0,offset),check};
 }finally{await f.close();}
}
export async function applyApplicationBridgeManifest(manifest:ApplicationBridgeManifest,connectionString:string):Promise<InstallationReceipt>{
 if(!connectionString)throw Error('OWNER_CONNECTION_REQUIRED');
 const q=applicationBridgeQuery(manifest),hash=applicationBridgeHash(manifest);
 const client=new Client({connectionString,application_name:'gc-application-authn-install',connectionTimeoutMillis:5000,statement_timeout:30000,lock_timeout:5000,query_timeout:35000});
 let started=false;
 try{
  await client.connect();await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');started=true;
  const result=await client.query(q.text,[...q.values]);if(result.rows.length!==1)throw Error();
  const parsed=parseInstallationReceipt(result.rows[0]);
  if(!parsed.ok||parsed.value.manifestHash!==hash||parsed.value.targetId!==manifest.operation.bridgeId)throw Error();
  await client.query('COMMIT');started=false;return parsed.value;
 }catch{if(started)try{await client.query('ROLLBACK');}catch{/* Discard connection. */}throw Error('APPLICATION_AUTHN_INSTALLATION_NOT_CONFIRMED');}
 finally{await client.end().catch(()=>undefined);}
}
async function main(){
 const x=await input(process.argv.slice(2)),parsed=parseApplicationBridgeManifestFile(new TextDecoder('utf8',{fatal:true}).decode(x.bytes));
 if(!parsed.ok)throw Error();
 if(x.check){console.log(JSON.stringify({result:'VALIDATED_ONLY',operation:parsed.value.operation.type,manifestHash:applicationBridgeHash(parsed.value)}));return;}
 const receipt=await applyApplicationBridgeManifest(parsed.value,process.env.MIGRATION_DATABASE_URL??'');
 console.log(JSON.stringify({result:'COMMITTED',contentAuthority:false,...receipt}));
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(()=>{
 process.stderr.write('APPLICATION_AUTHN_INSTALLATION_NOT_CONFIRMED: inspect the private manifest and native owner connection; replay the identical manifest after an uncertain commit. No expiry or permissions were renewed.\n');process.exitCode=1;
});
