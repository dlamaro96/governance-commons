// SPDX-License-Identifier: Apache-2.0
import {Socket,isIP} from 'node:net';
import {types} from 'node:util';
import {Problem} from '../../../packages/authz/src/index.ts';

const MAX_BYTES=262144,MAX_RESPONSE=8192,TIMEOUT_MS=5000;
const unavailable=()=>new Problem(503,'UPLOAD_SCANNER_UNAVAILABLE','The upload scanner is unavailable. Retry later.');
const invalid=()=>new Problem(422,'UPLOAD_INVALID','Provide a bounded UTF-8 upload.');
const rejected=()=>new Problem(422,'UPLOAD_REJECTED','The uploaded content was rejected.');

/** Operator configuration only. No request field can select a scanner endpoint.
 * ClamD TCP has no built-in transport authentication: deployment owns this trusted channel. */
function configuration():{host:string;port:number}|null {
 const enabled=process.env.GC_UPLOAD_SCANNER_ENABLED;
 if(enabled===undefined||enabled==='false')return null;
 if(enabled!=='true')throw unavailable();
 const host=process.env.GC_UPLOAD_SCANNER_HOST,port=process.env.GC_UPLOAD_SCANNER_PORT;
 if(typeof host!=='string'||host.length<1||host.length>253||!isIP(host)&&!host.split('.').every(label=>/^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label)))throw unavailable();
 if(typeof port!=='string'||! /^[1-9][0-9]{0,4}$/.test(port)||Number(port)>65535)throw unavailable();
 return {host,port:Number(port)};
}
function snapshot(input:unknown):Buffer {
 // Intrinsic typed-array getters avoid input accessors/iterators/species, and
 // shared/resizable memory cannot supply a stable snapshot across the async scan.
 try{
  if(input===null||typeof input!=='object'||types.isProxy(input)||!types.isUint8Array(input))throw 0;
  const prototype=Object.getPrototypeOf(input);if(prototype!==Uint8Array.prototype&&prototype!==Buffer.prototype)throw 0;
  const typed=Object.getPrototypeOf(Uint8Array.prototype);
  const get=(key:string)=>Reflect.apply(Object.getOwnPropertyDescriptor(typed,key)!.get!,input,[]);
  const length=get('byteLength') as number,offset=get('byteOffset') as number,buffer=get('buffer') as ArrayBuffer;
  if(length>MAX_BYTES||types.isSharedArrayBuffer(buffer)||!types.isArrayBuffer(buffer))throw 0;
  const resize=Object.getOwnPropertyDescriptor(ArrayBuffer.prototype,'resizable')?.get;
  if(resize&&Reflect.apply(resize,buffer,[]))throw 0;
  const keys=Reflect.ownKeys(input);if(keys.length!==length)throw 0;
  for(let i=0;i<length;i++){if(keys[i]!==String(i))throw 0;const d=Object.getOwnPropertyDescriptor(input,String(i));if(!d?.enumerable||!Object.hasOwn(d,'value'))throw 0;}
  const bytes=Buffer.alloc(length);Uint8Array.prototype.set.call(bytes,new Uint8Array(buffer,offset,length));
  new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);return bytes;
 }catch{throw invalid();}
}

/** INSTREAM protocol, not a file/path command. No upload is persisted, logged or
 * queued here. Call after authentication/body admission and before a DB transaction.
 * Disabled mode preserves the normal import parser's diagnostics. Enabled mode
 * fails closed; only the one exact OK record followed by EOF authorizes continuation. */
export async function scanUploadedBytes(raw:Uint8Array):Promise<void>{
 const started=performance.now(),config=configuration();if(config===null)return;
 const bytes=snapshot(raw),remaining=TIMEOUT_MS-(performance.now()-started);if(remaining<=0)throw unavailable();
 const command=Buffer.from('zINSTREAM\0','ascii'),size=Buffer.alloc(4);size.writeUInt32BE(bytes.length);
 const frame=bytes.length?Buffer.concat([command,size,bytes,Buffer.alloc(4)]):Buffer.concat([command,Buffer.alloc(4)]);
 await new Promise<void>((resolve,reject)=>{
  const socket=new Socket();let settled=false,written=false,ended=false;let response=Buffer.alloc(0);
  const finish=(error?:Problem)=>{
   if(settled)return;settled=true;clearTimeout(timer);socket.destroy();
   // Clear only our owned copies; the caller retains its original bytes for parsing.
   bytes.fill(0);frame.fill(0);response.fill(0);response=Buffer.alloc(0);
   if(error)reject(error);else resolve();
  };
  const timer=setTimeout(()=>finish(unavailable()),remaining);
  const complete=()=>{
   if(!ended||!written||settled)return;
   if(performance.now()-started>=TIMEOUT_MS){finish(unavailable());return;}
   if(response.equals(Buffer.from('stream: OK\0','ascii'))){finish();return;}
   // Never expose signature names, scanner messages or endpoint details.
   const found=response.length>15&&response.at(-1)===0&&/^stream: [\x20-\x7e]+ FOUND\x00$/.test(response.toString('latin1'));
   finish(found?rejected():unavailable());
  };
  socket.on('error',()=>finish(unavailable()));
  socket.on('close',()=>{if(!ended)finish(unavailable());});
  socket.on('data',(chunk:Buffer)=>{
   if(settled)return;
   if(response.length+chunk.length>MAX_RESPONSE){finish(unavailable());return;}
   response=Buffer.concat([response,chunk]);
  });
  socket.on('end',()=>{ended=true;complete();});
  socket.once('connect',()=>{
   try{socket.write(frame,error=>{if(error){finish(unavailable());return;}written=true;complete();});}
   catch{finish(unavailable());}
  });
  try{socket.connect({host:config.host,port:config.port});}catch{finish(unavailable());}
 });
}
