// SPDX-License-Identifier: Apache-2.0
import http, { type IncomingMessage, type ServerResponse, type OutgoingHttpHeaders } from 'node:http';
import https from 'node:https';
import { randomUUID } from 'node:crypto';
import type { PublicAuthnConfig } from '../../../packages/authn/src/contracts.ts';
import { AUTHN_LIMITS } from '../../../packages/authn/src/contracts.ts';
import { cookieNames, validatePublicAuthnConfig } from '../../../packages/authn/src/transport.ts';

export type EdgeConfig = PublicAuthnConfig & {
 readonly loginUpstream: string; readonly sessionUpstream: string; readonly legacyUpstream?: string; readonly applicationUpstream?: string;
};
type Route = 'login' | 'session' | 'legacy' | 'missing';
const hopHeaders = new Set(['connection','keep-alive','proxy-authenticate','proxy-authorization','te','trailer','transfer-encoding','upgrade']);
const protectedCookieNames = new Set(['gc_authn_session','gc_authn_csrf','gc_authn_attempt',
 '__Host-gc_authn_session','__Host-gc_authn_csrf','__Host-gc_authn_attempt']);
const sensitiveHeaders = /^(?:forwarded|x-forwarded(?:-.*)?|x-original(?:-.*)?|x-authn(?:-.*)?|x-gc-authn(?:-.*)?|x-authenticated(?:-.*)?|x-principal(?:-.*)?|x-user(?:-.*)?|x-identity(?:-.*)?|x-actor(?:-.*)?|x-role(?:s|-.*)?|x-permission(?:s|-.*)?|remote-user)$/i;
const authnRequestHeaders = new Set(['accept','content-type','origin','x-csrf-token']);

function upstream(value: string): URL {
 const url = new URL(value);
 if (!['http:','https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash
   || url.origin !== value || url.hostname.length === 0) throw new Error('AUTHN_EDGE_CONFIG_INVALID');
 return url;
}
/** Route only the raw origin-form path. Ambiguous spellings never reach a fallback. */
export function edgeRoute(method: string, rawUrl: string): Route {
 if (!rawUrl.startsWith('/') || rawUrl.startsWith('//') || rawUrl.includes('#') || /[\\\u0000-\u0020\u007f]/.test(rawUrl)) return 'missing';
 const path = rawUrl.split('?')[0]!;
 if (/%(?:2f|5c)/i.test(path) || /%(?![0-9a-f]{2})/i.test(path) || path.includes('//') || path.split('/').some(x => x === '.' || x === '..')) return 'missing';
 let decoded: string;
 try { decoded = decodeURIComponent(path); } catch { return 'missing'; }
 if (decoded.split('/').some(x=>x==='.'||x==='..')) return 'missing';
 const isProtected = decoded === '/authn' || decoded.startsWith('/authn/');
 if (!isProtected) return 'legacy';
 if (path !== decoded) return 'missing';
 if (method === 'GET' && (path === '/authn/login' || path === '/authn/callback')) return 'login';
 if ((method === 'GET' && ['/authn/','/authn/session','/authn/ui.js','/authn/ui.css'].includes(path))
   || (method === 'POST' && ['/authn/tenant','/authn/logout'].includes(path))) return 'session';
 return 'missing';
}
function cookieHeader(raw: string | undefined, allowed: Set<string>, invert = false): string | undefined {
 if (!raw) return undefined;
 const values = raw.split(';').map(v => v.trim()).filter(v => {
  const index = v.indexOf('=');
  if (index < 1) return !invert; // Protected backend rejects malformed cookies; legacy never receives them.
  return allowed.has(v.slice(0,index)) !== invert;
 });
 return values.length ? values.join('; ') : undefined;
}
/** Application authentication is cookie-only. Never turn forwarding headers or
 * a legacy/attempt cookie into a protected application identity. */
function applicationCookieHeader(raw: string | undefined, names: Set<string>): string | undefined {
 if (raw === undefined) return undefined;
 const selected = new Map<string,string>();
 for (const item of raw.split(';')) {
  const part = item.trim(), equal = part.indexOf('=');
  if (equal < 1) throw new Error('AUTHN_REQUEST_INVALID');
  const name = part.slice(0,equal);
  if (!names.has(name)) continue;
  const value = part.slice(equal+1);
  if (selected.has(name) || !/^[A-Za-z0-9_-]{43}$/.test(value)) throw new Error('AUTHN_REQUEST_INVALID');
  selected.set(name,value);
 }
 return selected.size ? [...selected].map(([name,value])=>`${name}=${value}`).join('; ') : undefined;
}
function securityHeaders(): OutgoingHttpHeaders {
 return {'cache-control':'no-store','referrer-policy':'no-referrer','x-content-type-options':'nosniff',
  'content-security-policy':"default-src 'none'; frame-ancestors 'none'; base-uri 'none'"};
}
function fail(res: ServerResponse, status: number, code = 'AUTHN_REQUEST_INVALID') {
 if (res.destroyed || res.writableEnded) return;
 if (res.headersSent) { res.destroy(); return; }
 res.writeHead(status, {...securityHeaders(),'content-type':'application/json; charset=utf-8'});
 res.end(JSON.stringify({code,correlationId:randomUUID()}));
}
function validSetCookie(value: string, names: Set<string>, config: PublicAuthnConfig): boolean {
 const parts = value.split(';').map(v => v.trim());
 const nameValue = parts.shift()!;
 const equal = nameValue.indexOf('=');
 if (equal < 1 || !names.has(nameValue.slice(0,equal)) || !/^[A-Za-z0-9._~-]*$/.test(nameValue.slice(equal+1))) return false;
 const attributes = new Map<string,string>();
 for (const part of parts) {
  const split = part.indexOf('=');
  const name = (split < 0 ? part : part.slice(0,split)).toLowerCase();
  if (attributes.has(name) || !['path','httponly','samesite','secure','max-age','expires'].includes(name)) return false;
  attributes.set(name,split < 0 ? '' : part.slice(split+1));
 }
 const production = config.environment === 'production';
 const name = nameValue.slice(0,equal), cookieValue = nameValue.slice(equal+1);
 const expectedPath = production || name !== cookieNames(config).attempt ? '/' : '/authn';
 const legacyClear = !production && name !== cookieNames(config).attempt && attributes.get('path') === '/authn'
  && cookieValue === '' && attributes.get('max-age') === '0' && attributes.get('expires') === 'Thu, 01 Jan 1970 00:00:00 GMT';
 return (attributes.get('path') === expectedPath || legacyClear) && attributes.get('httponly') === ''
  && attributes.get('samesite')?.toLowerCase() === 'lax' && attributes.has('secure') === production
  && (!attributes.has('secure') || attributes.get('secure') === '')
  && (!attributes.has('max-age') || /^(?:0|[1-9][0-9]{0,4})$/.test(attributes.get('max-age')!));
}
export function createAuthnEdge(input: EdgeConfig): http.Server {
 if (input.applicationUpstream !== undefined && input.legacyUpstream !== undefined) throw new Error('AUTHN_EDGE_CONFIG_INVALID');
 const config = validatePublicAuthnConfig({publicOrigin:input.publicOrigin,environment:input.environment});
 const publicHost = new URL(config.publicOrigin).host;
 const targets = {login:upstream(input.loginUpstream),session:upstream(input.sessionUpstream),legacy:input.legacyUpstream === undefined ? undefined : upstream(input.legacyUpstream),application:input.applicationUpstream === undefined ? undefined : upstream(input.applicationUpstream)};
 const names = cookieNames(config);
 const allowedCookies = new Set(Object.values(names));
 const applicationCookies = new Set([names.session,names.csrf]);
 let inflight = 0;
 const server = http.createServer({maxHeaderSize:AUTHN_LIMITS.headerBytes,requestTimeout:AUTHN_LIMITS.requestTimeoutMs,
  headersTimeout:10_000,keepAliveTimeout:5_000}, (req,res) => {
  const headerCounts = new Map<string,number>();
  for (let i=0;i<req.rawHeaders.length;i+=2) {
   const name=req.rawHeaders[i]!.toLowerCase(); headerCounts.set(name,(headerCounts.get(name) ?? 0)+1);
  }
  if (headerCounts.get('host') !== 1 || req.headers.host !== publicHost || req.method === 'CONNECT') { fail(res,400);req.resume();return; }
  const selected = edgeRoute(req.method ?? '',req.url ?? '');
  const route = selected === 'legacy' && targets.application ? 'application' : selected;
  if (route === 'missing' || !targets[route]) { fail(res,404);req.resume();return; }
  const protectedRoute = route === 'login' || route === 'session';
  const applicationRoute = route === 'application';
  if ((protectedRoute || applicationRoute) && (['cookie','origin','content-type','x-csrf-token','authorization'].some(name=>(headerCounts.get(name)??0)>1)
    || protectedRoute && Buffer.byteLength(req.url ?? '') > AUTHN_LIMITS.queryBytes + 64)) {fail(res,400);req.resume();return;}
  let rawCookie: string | undefined;
  try { rawCookie = applicationRoute ? applicationCookieHeader(req.headers.cookie,applicationCookies)
   : cookieHeader(req.headers.cookie,protectedRoute ? allowedCookies : protectedCookieNames,!protectedRoute); }
  catch { fail(res,400);req.resume();return; }
  if (protectedRoute && inflight >= AUTHN_LIMITS.processInflight) {fail(res,503,'AUTHN_UNAVAILABLE');req.resume();return;}
  if (protectedRoute) inflight++;
  let done=false,rejected=false;
  let client:http.ClientRequest|undefined;
  let deadline:ReturnType<typeof setTimeout>|undefined;
  const release=()=>{if(!done){done=true;clearTimeout(deadline);if(protectedRoute)inflight--;}};
  // One wall deadline includes body receipt and upstream work; no reset at forwarding.
  deadline=setTimeout(()=>{
   rejected=true;fail(res,503,'AUTHN_UNAVAILABLE');
   if(client)client.destroy(new Error('AUTHN_UPSTREAM_TIMEOUT'));else release();
   req.resume();
  },protectedRoute ? AUTHN_LIMITS.requestTimeoutMs : 120_000);
  deadline.unref();
  req.on('aborted',()=>{rejected=true;if(client)client.destroy();else release();});
  res.on('close',()=>{if(!res.writableFinished){rejected=true;if(client)client.destroy();else release();}});
  const headers: OutgoingHttpHeaders = {};
  const connectionNames = new Set((req.headers.connection ?? '').toLowerCase().split(',').map(v=>v.trim()));
  for (const [name,value] of Object.entries(req.headers)) {
   if (hopHeaders.has(name) || connectionNames.has(name) || sensitiveHeaders.test(name) || name === 'host' || name === 'cookie') continue;
   if (!protectedRoute || authnRequestHeaders.has(name)) headers[name]=value;
  }
  headers.host=publicHost;
  if(rawCookie)headers.cookie=rawCookie;
  const target=targets[route]!;
  const forward=(body?:Buffer)=>{
   if(rejected || done || res.destroyed || res.writableEnded)return;
   if(body)headers['content-length']=body.byteLength;
   client=(target.protocol==='https:' ? https : http).request(target,{method:req.method,path:req.url,headers},up=>{
    const responseHeaders:OutgoingHttpHeaders={};
    const responseConnection=new Set((up.headers.connection ?? '').toLowerCase().split(',').map(v=>v.trim()));
    for(const [name,value] of Object.entries(up.headers)) {
     if(!hopHeaders.has(name)&&!responseConnection.has(name)&&!sensitiveHeaders.test(name)&&!(protectedRoute&&name.startsWith('access-control-')))responseHeaders[name]=value;
    }
    const setCookies=up.headers['set-cookie'] ?? [];
    if(protectedRoute && setCookies.some(value=>!validSetCookie(value,allowedCookies,config))) {up.destroy();release();fail(res,503,'AUTHN_UNAVAILABLE');return;}
    if(!protectedRoute && setCookies.some(value=>protectedCookieNames.has(value.split('=',1)[0]!))) {up.destroy();release();fail(res,503,'AUTHN_UNAVAILABLE');return;}
    res.writeHead(up.statusCode ?? 502,responseHeaders);
    up.on('error',()=>{release();res.destroy();});
    up.on('end',release);
    up.pipe(res);
   });
   client.on('close',release);
   client.on('error',()=>{release();fail(res,503,'AUTHN_UNAVAILABLE');});
   if(body)client.end(body);else req.pipe(client);
  };
  if(!protectedRoute){forward();return;}
  const chunks:Buffer[]=[];let size=0;
  req.on('data',(chunk:Buffer)=>{
   if(rejected)return;
   size+=chunk.length;
   if(size>AUTHN_LIMITS.bodyBytes){rejected=true;chunks.length=0;release();fail(res,400);return;}
   chunks.push(chunk);
  });
  req.on('end',()=>{if(!rejected)forward(Buffer.concat(chunks,size));});
  req.on('error',()=>{release();fail(res,400);});
 });
 server.on('upgrade',(_req,socket)=>socket.destroy());
 server.on('connect',(_req,socket)=>socket.destroy());
 server.on('clientError',(_error,socket)=>{
  if(!socket.writable)return;
  const body=JSON.stringify({code:'AUTHN_REQUEST_INVALID',correlationId:randomUUID()});
  socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: '+Buffer.byteLength(body)+'\r\n\r\n'+body);
 });
 return server;
}
