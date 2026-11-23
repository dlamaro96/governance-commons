// SPDX-License-Identifier: Apache-2.0
import {constants} from 'node:fs';
import {lstat,open,realpath} from 'node:fs/promises';
import {isAbsolute,resolve} from 'node:path';
import type {BigIntStats} from 'node:fs';

const credentials=new WeakMap<object,string>();
declare const credentialBrand:unique symbol;
/** Opaque startup capability. Its value/path never appears in a config or DTO. */
export type EntraClientAuthentication={readonly [credentialBrand]:true};
const invalid=():never=>{throw new Error('AUTHN_CONFIGURATION_INVALID');};
function stamp(value:BigIntStats):string{return [value.dev,value.ino,value.mode,value.uid,value.size,value.mtimeNs,value.ctimeNs].join(':');}
export function hasEntraClientAuthentication(value:unknown):value is EntraClientAuthentication {
 return typeof value==='object'&&value!==null&&credentials.has(value);
}
export function appendEntraClientSecret(value:EntraClientAuthentication,form:URLSearchParams):void {
 const secret=credentials.get(value);if(secret===undefined||form.has('client_secret'))return invalid();
 form.set('client_secret',secret);
}
/** Read once before serving requests. Atomic rotation takes effect after restart. */
export async function loadEntraClientSecret(path:string):Promise<EntraClientAuthentication> {
 let file:Awaited<ReturnType<typeof open>>|undefined;
 const buffer=Buffer.alloc(4097);
 try {
  if(typeof path!=='string'||!isAbsolute(path)||path.length>4096||path.includes('\0')||resolve(path)!==path
   ||typeof process.geteuid!=='function'||await realpath(path)!==path)return invalid();
  file=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  const before=await file.stat({bigint:true}),mode=Number(before.mode&0o7777n);
  if(!before.isFile()||before.uid!==BigInt(process.geteuid())||![0o400,0o600].includes(mode)
   ||before.size<1n||before.size>4096n||stamp(await lstat(path,{bigint:true}))!==stamp(before))return invalid();
  let size=0;
  while(size<buffer.length){const result=await file.read(buffer,size,buffer.length-size,null);if(!result.bytesRead)break;size+=result.bytesRead;}
  if(BigInt(size)!==before.size||stamp(await file.stat({bigint:true}))!==stamp(before)
   ||stamp(await lstat(path,{bigint:true}))!==stamp(before)||await realpath(path)!==path)return invalid();
  for(let i=0;i<size;i++)if(buffer[i]!<0x21||buffer[i]!>0x7e)return invalid();
  const capability=Object.freeze(Object.create(null)) as EntraClientAuthentication;
  credentials.set(capability,buffer.subarray(0,size).toString('ascii'));return capability;
 }catch{return invalid();}finally{buffer.fill(0);await file?.close().catch(()=>{});}
}
