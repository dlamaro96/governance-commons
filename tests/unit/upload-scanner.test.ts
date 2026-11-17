// SPDX-License-Identifier: Apache-2.0
// Actual owned loopback TCP protocol peers, not a live ClamAV engine qualification.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer,type Socket} from 'node:net';
import {once} from 'node:events';
import {createHash} from 'node:crypto';
import {scanUploadedBytes} from '../../apps/api/src/upload-scanner.ts';
import {Problem} from '../../packages/authz/src/index.ts';

const envKeys=['GC_UPLOAD_SCANNER_ENABLED','GC_UPLOAD_SCANNER_HOST','GC_UPLOAD_SCANNER_PORT'] as const;
function environment(t:test.TestContext){const saved=envKeys.map(k=>[k,process.env[k]] as const);t.after(()=>{for(const [k,v] of saved)if(v===undefined)delete process.env[k];else process.env[k]=v;});for(const k of envKeys)delete process.env[k];}
function error(code:string,status:number){return (e:unknown)=>{assert.ok(e instanceof Problem);assert.equal(e.code,code);assert.equal(e.status,status);assert.equal(e.issues,undefined);for(const sensitive of ['private-signature','127.0.0.1','secret body','ECONN','ENOTFOUND'])assert.ok(!e.message.includes(sensitive));return true;};}
async function peer(t:test.TestContext,handle:(socket:Socket,body:Buffer)=>void){
 const sockets=new Set<Socket>(),received:Buffer[]=[];let connected=0,closed=0;
 const server=createServer(socket=>{
  sockets.add(socket);connected++;let frame=Buffer.alloc(0),called=false;
  socket.on('error',()=>{});socket.on('close',()=>{sockets.delete(socket);closed++;});
  socket.on('data',(chunk:Buffer)=>{
   if(called)return;frame=Buffer.concat([frame,chunk]);assert.ok(frame.length<=262162);
   if(frame.length<14)return;assert.deepEqual(frame.subarray(0,10),Buffer.from('zINSTREAM\0'));
   let at=10;const chunks:Buffer[]=[];
   while(at+4<=frame.length){const count=frame.readUInt32BE(at);at+=4;if(count===0){assert.equal(at,frame.length);called=true;const body=Buffer.concat(chunks);received.push(body);handle(socket,body);return;}if(at+count>frame.length)return;chunks.push(frame.subarray(at,at+count));at+=count;}
  });
 });
 t.after(async()=>{for(const socket of sockets)socket.destroy();if(server.listening)await new Promise<void>((resolve,reject)=>server.close(e=>e?reject(e):resolve()));});
 server.listen(0,'127.0.0.1');await once(server,'listening');const address=server.address();assert.ok(address&&typeof address!=='string');
 process.env.GC_UPLOAD_SCANNER_ENABLED='true';process.env.GC_UPLOAD_SCANNER_HOST='127.0.0.1';process.env.GC_UPLOAD_SCANNER_PORT=String(address.port);
 const drained=async()=>{const deadline=performance.now()+1000;while(sockets.size&&performance.now()<deadline)await new Promise(r=>setTimeout(r,5));assert.equal(sockets.size,0);assert.equal(closed,connected);};
 return {server,sockets,received,drained,connections:()=>connected};
}

test('scanner disabled by default or exact false makes no connection and leaves parser diagnostics untouched',async t=>{
 environment(t);const p=await peer(t,s=>s.end('stream: OK\0'));
 delete process.env.GC_UPLOAD_SCANNER_ENABLED;await scanUploadedBytes(Buffer.from([0xff]));
 process.env.GC_UPLOAD_SCANNER_ENABLED='false';process.env.GC_UPLOAD_SCANNER_HOST='invalid endpoint';await scanUploadedBytes(Buffer.from('valid'));
 assert.equal(p.connections(),0);
});

test('enabled configuration is closed and requires operator static host and canonical port',async t=>{
 environment(t);
 for(const [enabled,host,port] of [['TRUE','127.0.0.1','3310'],['','127.0.0.1','3310'],['true',undefined,'3310'],['true','http://private.example','3310'],['true','private.example\n','3310'],['true','private.example','03310'],['true','private.example','0'],['true','private.example','65536'],['true','private.example',undefined]]){
  for(const [key,value] of [[envKeys[0],enabled],[envKeys[1],host],[envKeys[2],port]])if(value===undefined)delete process.env[key!];else process.env[key!]=value;
  await assert.rejects(scanUploadedBytes(Buffer.from('secret body')),error('UPLOAD_SCANNER_UNAVAILABLE',503));
 }
});

test('actual INSTREAM bytes use one length-prefixed bounded view, zero terminator and no filename',async t=>{
 environment(t);const p=await peer(t,s=>s.end('stream: OK\0'));
 const original=Buffer.from('secret body جملة UTF8'),wrapped=Buffer.concat([Buffer.from('HEAD'),original,Buffer.from('TAIL')]);
 const view=new Uint8Array(wrapped.buffer,wrapped.byteOffset+4,original.length);await scanUploadedBytes(view);
 assert.deepEqual(p.received,[original]);assert.deepEqual(wrapped,Buffer.concat([Buffer.from('HEAD'),original,Buffer.from('TAIL')]));await p.drained();
});

test('exact 262144-byte boundary and empty UTF8 stream are real protocol requests',async t=>{
 environment(t);const p=await peer(t,s=>s.end('stream: OK\0'));
 const raw=Buffer.alloc(262144,0x41);await scanUploadedBytes(raw);await scanUploadedBytes(Buffer.alloc(0));
 assert.equal(p.received[0].length,262144);assert.equal(createHash('sha256').update(p.received[0]).digest('hex'),createHash('sha256').update(raw).digest('hex'));assert.equal(p.received[1].length,0);await p.drained();
});

test('fragmented exact OK is accepted only after complete EOF, not first positive record',async t=>{
 environment(t);let finishPeer:()=>void=()=>{};
 const p=await peer(t,s=>{s.write('stream: ');s.write('OK\0');finishPeer=()=>s.end();});
 let done=false;const scan=scanUploadedBytes(Buffer.from('synthetic')).then(()=>{done=true;});
 const limit=performance.now()+1000;while(p.received.length===0&&performance.now()<limit)await new Promise(r=>setTimeout(r,5));assert.equal(p.received.length,1);
 await new Promise(r=>setTimeout(r,20));assert.equal(done,false);finishPeer();await scan;await p.drained();
});

test('FOUND returns only a generic safe422 without signature, body or endpoint reflection',async t=>{
 environment(t);const p=await peer(t,s=>s.end('stream: private-signature FOUND\0'));
 await assert.rejects(scanUploadedBytes(Buffer.from('secret body')),error('UPLOAD_REJECTED',422));await p.drained();
});

test('unknown, malformed, multiline and ERROR replies are unavailable rather than clean',async t=>{
 environment(t);
 const responses=[Buffer.alloc(0),Buffer.from('stream: OK\n'),Buffer.from('stream: OK'),Buffer.from('1: stream: OK\0'),Buffer.from('stream: OK\0stream: OK\0'),Buffer.from('stream: private-signature ERROR\0'),Buffer.from('stream: \n FOUND\0'),Buffer.from([0xff,0]),Buffer.from('OK\0'),Buffer.from('stream: OK\0junk')];
 let index=0;const p=await peer(t,s=>s.end(responses[index++]));
 for(const _ of responses)await assert.rejects(scanUploadedBytes(Buffer.from('synthetic')),error('UPLOAD_SCANNER_UNAVAILABLE',503));await p.drained();
});

test('a positive record followed in another TCP write by a later result cannot pass',async t=>{
 environment(t);const timers=new Set<ReturnType<typeof setTimeout>>();t.after(()=>{for(const timer of timers)clearTimeout(timer);});
 const p=await peer(t,s=>{s.write('stream: OK\0');const timer=setTimeout(()=>{timers.delete(timer);s.end('stream: private-signature FOUND\0');},20);timers.add(timer);});
 await assert.rejects(scanUploadedBytes(Buffer.from('synthetic')),error('UPLOAD_SCANNER_UNAVAILABLE',503));await p.drained();
});

test('response cap is inclusive8192 and overflow destroys the owned connection',async t=>{
 environment(t);let index=0;const prefix='stream: ',suffix=' FOUND\0';
 const exact=prefix+'S'.repeat(8192-prefix.length-suffix.length)+suffix;
 const p=await peer(t,s=>{if(index++===0)s.end(exact);else s.write(Buffer.alloc(8193,0x41));});
 await assert.rejects(scanUploadedBytes(Buffer.from('synthetic')),error('UPLOAD_REJECTED',422));
 await assert.rejects(scanUploadedBytes(Buffer.from('synthetic')),error('UPLOAD_SCANNER_UNAVAILABLE',503));await p.drained();
});

test('disconnect and refused connection both fail closed with redacted errors',async t=>{
 environment(t);const p=await peer(t,s=>s.destroy());await assert.rejects(scanUploadedBytes(Buffer.from('synthetic')),error('UPLOAD_SCANNER_UNAVAILABLE',503));await p.drained();
 await new Promise<void>((resolve,reject)=>p.server.close(e=>e?reject(e):resolve()));
 await assert.rejects(scanUploadedBytes(Buffer.from('synthetic')),error('UPLOAD_SCANNER_UNAVAILABLE',503));
});

test('invalid raw bytes and hostile typed arrays refuse before making a connection',async t=>{
 environment(t);const p=await peer(t,s=>s.end('stream: OK\0'));let called=0;
 const trap=()=>{called++;throw Error('Never execute');};
 const proxy=new Proxy(Buffer.from('synthetic'),{ownKeys:trap,get:trap,getPrototypeOf:trap});
 const getter=Buffer.from('synthetic');Object.defineProperty(getter,'buffer',{get:trap});
 const iterable=Buffer.from('synthetic');Object.defineProperty(iterable,Symbol.iterator,{value:trap});
 for(const raw of [Buffer.alloc(262145),Buffer.from([0xff]),Buffer.from([0xed,0xa0,0x80]),proxy,getter,iterable,new Uint8Array(new SharedArrayBuffer(1)),new Uint8Array(Reflect.construct(ArrayBuffer,[1,{maxByteLength:10}]) as ArrayBuffer)])await assert.rejects(scanUploadedBytes(raw),error('UPLOAD_INVALID',422));
 assert.equal(called,0);assert.equal(p.connections(),0);
});

test('five-second deadline is total and drip-fed response data cannot reset it',async t=>{
 environment(t);const timers=new Set<ReturnType<typeof setInterval>>();t.after(()=>{for(const timer of timers)clearInterval(timer);});
 const p=await peer(t,s=>{const timer=setInterval(()=>s.write('x'),100);timers.add(timer);s.once('close',()=>{clearInterval(timer);timers.delete(timer);});});
 const start=performance.now();await assert.rejects(scanUploadedBytes(Buffer.from('synthetic')),error('UPLOAD_SCANNER_UNAVAILABLE',503));const elapsed=performance.now()-start;
 assert.ok(elapsed>=4800&&elapsed<6500,'Deadline remains one five-second budget');await p.drained();assert.equal(timers.size,0);
});
