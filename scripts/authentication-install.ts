// SPDX-License-Identifier: Apache-2.0
import {constants} from 'node:fs';
import {open} from 'node:fs/promises';
import {Client} from 'pg';
import {INSTALLATION_INPUT_BYTES,parseInstallationManifestFile,installationHash,installationQuery,
 parseInstallationReceipt,type InstallationManifest} from '../packages/authority/src/authentication-installation.ts';

async function inputBytes(args:string[]):Promise<{bytes:Uint8Array;check:boolean}>{
 const check=args.includes('--check'),rest=args.filter(x=>x!=='--check');
 if(args.filter(x=>x==='--check').length>1)throw Error('INVALID_ARGUMENTS');
 if(rest.length===1&&rest[0]==='--stdin'){
  const parts:Buffer[]=[];let size=0;
  for await(const part of process.stdin){const bytes=Buffer.from(part);size+=bytes.length;
   if(size>INSTALLATION_INPUT_BYTES)throw Error('INPUT_LIMIT');parts.push(bytes);}
  return {bytes:Buffer.concat(parts,size),check};
 }
 if(rest.length!==2||rest[0]!=='--input')throw Error('INVALID_ARGUMENTS');
 const file=await open(rest[1]!,constants.O_RDONLY|constants.O_NOFOLLOW);
 try{
  const info=await file.stat();
  if(!info.isFile()||(info.mode&0o077)!==0||info.size>INSTALLATION_INPUT_BYTES)throw Error('PRIVATE_FILE_REQUIRED');
  const bytes=Buffer.alloc(INSTALLATION_INPUT_BYTES+1);let offset=0;
  while(offset<bytes.length){const {bytesRead}=await file.read(bytes,offset,bytes.length-offset,null);if(!bytesRead)break;offset+=bytesRead;}
  if(offset>INSTALLATION_INPUT_BYTES)throw Error('INPUT_LIMIT');
  return {bytes:bytes.subarray(0,offset),check};
 }finally{await file.close();}
}

function expectedTarget(manifest:InstallationManifest):string{
 const x=manifest.operation;
 switch(x.type){
  case 'register-executor':case 'advance-generation':case 'revoke-executor':return x.registrationId;
  case 'register-issuer':case 'revoke-issuer':return x.issuerId;
  case 'bind-identity':case 'revoke-binding':return x.bindingId;
  case 'initialize-tenant':case 'advance-tenant-generation':return x.tenantId;
 }
}

async function main():Promise<void>{
 const input=await inputBytes(process.argv.slice(2));
 const parsed=parseInstallationManifestFile(new TextDecoder('utf-8',{fatal:true}).decode(input.bytes));
 if(!parsed.ok)throw Error('INPUT_REJECTED');
 const manifest=parsed.value,hash=installationHash(manifest),query=installationQuery(manifest);
 if(input.check){console.log(JSON.stringify({result:'VALIDATED_ONLY',operation:manifest.operation.type,manifestHash:hash}));return;}
 const connectionString=process.env.MIGRATION_DATABASE_URL;
 if(!connectionString)throw Error('OWNER_CONNECTION_REQUIRED');
 const client=new Client({connectionString,application_name:'gc-authn-install',connectionTimeoutMillis:5000,
  statement_timeout:30000,lock_timeout:5000,query_timeout:35000});
 let transaction=false;
 try{
  await client.connect();
  await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');transaction=true;
  const result=await client.query(query.text,[...query.values]);
  if(result.rows.length!==1)throw Error('RECEIPT_REJECTED');
  const receipt=parseInstallationReceipt(result.rows[0]);
  if(!receipt.ok||receipt.value.manifestHash!==hash||receipt.value.targetId!==expectedTarget(manifest))throw Error('RECEIPT_REJECTED');
  await client.query('COMMIT');transaction=false;
  console.log(JSON.stringify({result:'COMMITTED_INACTIVE',...receipt.value}));
 }catch{
  if(transaction)try{await client.query('ROLLBACK');}catch{/* The connection is discarded below. */}
  // Do not print database causes, connection strings, manifest fields or SQL.
  // Replaying the exact request is safe if COMMIT's response was interrupted.
  throw Error('INSTALLATION_NOT_CONFIRMED');
 }finally{await client.end().catch(()=>undefined);}
}

main().catch(()=>{
 console.error('AUTHN_INSTALLATION_NOT_CONFIRMED: check the private input and owner connection; retry the same manifest after an uncertain commit.');
 process.exitCode=1;
});
