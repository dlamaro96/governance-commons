// SPDX-License-Identifier: Apache-2.0
import {createHash} from 'node:crypto';
import {createRemoteJWKSet, customFetch, jwtVerify, type JWK} from 'jose';
import type {AttemptExchange} from '../../authority/src/authentication.ts';
import {AUTHENTICATION_SCALARS as S} from '../../authority/src/authentication.ts';
import type {UTC} from '../../authority/src/types.ts';
import {AUTHN_LIMITS as L, type BrokerOidcConfig, type VerifiedIdentityToken} from './contracts.ts';
import {AuthnHttpError, equalSecret, sha256, strictJson, validatePublicAuthnConfig} from './transport.ts';

export interface OidcClient {
 initialize():Promise<void>;
 authorizationUrl(input:{state:string;nonce:string;verifier:string}):string;
 exchangeAndVerify(attempt:AttemptExchange,code:string,options?:{signal?:AbortSignal}):Promise<VerifiedIdentityToken>;
}
const reject=():never=>{throw new AuthnHttpError('AUTHN_LOGIN_INVALID');};
const configReject=():never=>{throw new Error('AUTHN_CONFIGURATION_INVALID');};
function object(value:unknown):Record<string,unknown>{if(value===null||typeof value!=='object'||Array.isArray(value))return reject();return value as Record<string,unknown>;}
function text(value:unknown,max:number):string{try{return S.text(value,max);}catch{return reject();}}
function endpoint(value:string,production:boolean):URL {
 if(typeof value!=='string'||Buffer.byteLength(value)>2048||!value||/[\s\\\u0000-\u001f\u007f]/u.test(value))return configReject();
 // Keep the foundation's admitted host/escape grammar; the broker additionally
 // requires canonical, query-free endpoint paths so aliases remain exact.
 const spelling=/^(https?):\/\/(\[::1\]|[a-z0-9.-]+)(?::([1-9][0-9]{0,4}))?([/?][A-Za-z0-9._~!$&'()*+,;=:@/?%-]*)?$/.exec(value);
 if(!spelling||/%(?![A-Fa-f0-9]{2})/.test(value)||spelling[3]!==undefined&&Number(spelling[3])>65535)return configReject();
 const rawHost=spelling[2]!;
 if(rawHost!=='[::1]'){
  if(/^[0-9.]+$/.test(rawHost)){const parts=rawHost.split('.');if(parts.length!==4||parts.some(part=>!/^(?:0|[1-9][0-9]{0,2})$/.test(part)||Number(part)>255))return configReject();}
  else {const labels=rawHost.split('.');if(rawHost.length>253||labels.some(label=>!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))||!/[a-z]/.test(labels.at(-1)?.[0]??''))return configReject();}
 }
 let url:URL;try{url=new URL(value);}catch{return configReject();}
 if(url.href!==value||url.username||url.password||url.hash||url.search||!url.hostname||url.pathname.includes('//')||/%(?:2f|5c|2e)/i.test(url.pathname))return configReject();
 if(production?url.protocol!=='https:':!['https:','http:'].includes(url.protocol))return configReject();
 if(!production&&url.protocol==='http:'&&!['localhost','127.0.0.1','[::1]'].includes(url.hostname))return configReject();
 return url;
}
/** Configuration is deployment-owned, immutable after startup, and never derived from request headers. */
export function validateBrokerOidcConfig(input:BrokerOidcConfig):BrokerOidcConfig {
 const base=validatePublicAuthnConfig(input),production=base.environment==='production';
 const issuer=endpoint(input.issuer,production),authorization=endpoint(input.authorizationEndpoint,production),token=endpoint(input.tokenEndpoint,production),jwks=endpoint(input.jwksUri,production),callback=endpoint(input.redirectUri,production);
 if(issuer.pathname.endsWith('/')||callback.href!==`${base.publicOrigin}/authn/callback`||!input.clientId||Buffer.byteLength(input.clientId)>256||!/^[A-Za-z0-9._-]+$/.test(input.clientId))return configReject();
 if([authorization,token,jwks].some(url=>url.origin!==issuer.origin||!url.pathname.startsWith(`${issuer.pathname}/`)))return configReject();
 if(production&&issuer.hostname===new URL(base.publicOrigin).hostname)return configReject();
 const discovery=`${issuer.href}/.well-known/openid-configuration`,aliases:Record<string,string>=Object.create(null);
 if(input.transportAliases!==undefined){
  if(input.transportAliases===null||typeof input.transportAliases!=='object'||Array.isArray(input.transportAliases))return configReject();
  for(const [source,target] of Object.entries(input.transportAliases)){
   if(production||![discovery,token.href,jwks.href].includes(source)||typeof target!=='string')return configReject();
   const original=new URL(source);if(target!==`http://keycloak:8080${original.pathname}`)return configReject();aliases[source]=target;
  }
 }
 return Object.freeze({...base,issuer:issuer.href,clientId:input.clientId,redirectUri:callback.href,authorizationEndpoint:authorization.href,tokenEndpoint:token.href,jwksUri:jwks.href,transportAliases:Object.freeze(aliases)});
}
function checkSignal(signal?:AbortSignal):void{if(signal?.aborted)return reject();}
async function abortable<T>(promise:Promise<T>,signal:AbortSignal):Promise<T>{
 checkSignal(signal);let listener:()=>void=()=>{};
 try{return await Promise.race([promise,new Promise<never>((_,rejectPromise)=>{listener=()=>rejectPromise(new AuthnHttpError('AUTHN_LOGIN_INVALID'));signal.addEventListener('abort',listener,{once:true});})]);}
 finally{signal.removeEventListener('abort',listener);}
}
function base64(segment:string,limit:number):Buffer{
 if(!segment||!/^[A-Za-z0-9_-]+$/.test(segment)||segment.length>Math.ceil(limit*4/3))return reject();
 const bytes=Buffer.from(segment,'base64url');if(bytes.length>limit||bytes.toString('base64url')!==segment)return reject();return bytes;
}
function signingKeys(value:unknown):{keys:JWK[]}{
 const body=object(value);if(!Array.isArray(body.keys)||body.keys.length<1||body.keys.length>32)return reject();
 const seen=new Set<string>(),keys:JWK[]=[];
 for(const item of body.keys){
  const key=object(item),kid=text(key.kid,256);if(seen.has(kid))return reject();seen.add(kid);
  text(key.kty,32);if(['d','p','q','dp','dq','qi','oth','k'].some(name=>Object.hasOwn(key,name)))return reject();
  if(key.alg!==undefined)text(key.alg,32);if(key.use!==undefined&&!['sig','enc'].includes(text(key.use,8)))return reject();
  if(key.key_ops!==undefined&&(!Array.isArray(key.key_ops)||key.key_ops.length>8||key.key_ops.some(x=>typeof x!=='string'||x.length>32)||new Set(key.key_ops).size!==key.key_ops.length))return reject();
  // Count and bound unrelated public encryption/other-algorithm keys; they never enter jose's resolver.
  const applicable=key.kty==='RSA'&&(key.alg===undefined||key.alg==='RS256')&&(key.use===undefined||key.use==='sig')&&(key.key_ops===undefined||(key.key_ops as string[]).includes('verify'));
  if(applicable){
   const modulus=base64(text(key.n,684),512),exponent=base64(text(key.e,16),8);
   if(modulus[0]===0||exponent[0]===0||!(modulus.at(-1)!&1))return reject();
   const exponentValue=BigInt(`0x${exponent.toString('hex')}`);if(exponentValue<3n||!(exponentValue&1n))return reject();
   const bits=(modulus.length-1)*8+(32-Math.clz32(modulus[0]!));
   if(bits<2048||bits>4096||exponent.length<1)return reject();
   keys.push({...key,alg:'RS256',use:'sig',key_ops:['verify']} as JWK);
  }
 }
 if(keys.length===0)return reject();return {keys};
}
function numericDate(value:unknown):UTC {
 if(typeof value!=='number'||!Number.isSafeInteger(value)||value<0||value>253402300799)return reject();
 return S.time(new Date(value*1000).toISOString());
}

/** Pinned jose performs real RS256 verification; all transport and JSON admission precede it. */
export function createOidcClient(rawConfig:BrokerOidcConfig,dependencies:{fetch?:typeof fetch;now?:()=>number}={}):OidcClient {
 const config=validateBrokerOidcConfig(rawConfig),fetchImpl=dependencies.fetch??fetch,now=dependencies.now??Date.now;
 const discovery=`${config.issuer}/.well-known/openid-configuration`,allow=new Set([discovery,config.tokenEndpoint,config.jwksUri]);
 let initialized=false,initializing:Promise<void>|undefined;
 async function fetchJson(url:string,init:RequestInit,limit:number,timeout:number,outer?:AbortSignal):Promise<unknown>{
  if(!allow.has(url))return reject();checkSignal(outer);
  const timeoutSignal=AbortSignal.timeout(timeout),signal=outer?AbortSignal.any([outer,timeoutSignal]):timeoutSignal;
  let reader:ReadableStreamDefaultReader<Uint8Array>|undefined,body:ReadableStream<Uint8Array>|null=null;
  try{
   const response=await abortable(fetchImpl(config.transportAliases?.[url]??url,{...init,redirect:'manual',credentials:'omit',signal}),signal);
   body=response.body;if(response.status!==200||response.redirected||!body)return reject();
   const contentType=response.headers.get('content-type')?.split(';')[0]?.trim().toLowerCase();
   if(contentType!=='application/json'&&contentType!=='application/jwk-set+json')return reject();
   const declared=response.headers.get('content-length');
   if(declared!==null&&(!/^\d+$/.test(declared)||!Number.isSafeInteger(Number(declared))||Number(declared)>limit))return reject();
   reader=body.getReader();let size=0;const parts:Uint8Array[]=[];
   for(;;){const part=await abortable(reader.read(),signal);if(part.done)break;size+=part.value.byteLength;if(size>limit)return reject();parts.push(part.value);}
   checkSignal(signal);return strictJson(Buffer.concat(parts,size),limit);
  }catch{return reject();}finally{
   // Cancellation is initiated even when status/headers reject before a reader is acquired.
   // Do not extend the original request deadline while waiting for transport teardown.
   if(reader){void reader.cancel().catch(()=>{});try{reader.releaseLock();}catch{/* An aborted read is being cancelled. */}}
   else if(body)void body.cancel().catch(()=>{});
  }
 }
 const remote=createRemoteJWKSet(new URL(config.jwksUri),{
  cacheMaxAge:L.jwksCacheMs,cooldownDuration:L.jwksCooldownMs,timeoutDuration:L.metadataTimeoutMs,
  [customFetch]:async(url,options)=>new Response(JSON.stringify(signingKeys(await fetchJson(url,options,L.jwksBytes,L.metadataTimeoutMs,options.signal))),{status:200,headers:{'content-type':'application/json'}}),
 });
 async function initialize():Promise<void>{
  if(initialized)return;if(initializing)return initializing;
  initializing=(async()=>{const metadata=object(await fetchJson(discovery,{method:'GET',headers:{accept:'application/json'}},L.metadataBytes,L.metadataTimeoutMs));
   if(metadata.issuer!==config.issuer||metadata.authorization_endpoint!==config.authorizationEndpoint||metadata.token_endpoint!==config.tokenEndpoint||metadata.jwks_uri!==config.jwksUri)return reject();
   if(!Array.isArray(metadata.id_token_signing_alg_values_supported)||!metadata.id_token_signing_alg_values_supported.includes('RS256'))return reject();
   await remote.reload();initialized=true;
  })();try{await initializing;}finally{initializing=undefined;}
 }
 return Object.freeze({initialize,
  authorizationUrl({state,nonce,verifier}:{state:string;nonce:string;verifier:string}):string {
   if(!initialized||! /^[A-Za-z0-9_-]{43}$/.test(state)||! /^[A-Za-z0-9_-]{43}$/.test(nonce))return reject();S.verifier(verifier);
   const url=new URL(config.authorizationEndpoint);url.search=new URLSearchParams({client_id:config.clientId,redirect_uri:config.redirectUri,response_type:'code',response_mode:'query',scope:'openid',state,nonce,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256',max_age:'0',claims:JSON.stringify({id_token:{auth_time:{essential:true}}})}).toString();return url.href;
  },
  async exchangeAndVerify(attempt:AttemptExchange,code:string,{signal:outer}:{signal?:AbortSignal}={}):Promise<VerifiedIdentityToken>{
   try{
    if(!initialized||attempt.issuer!==config.issuer||attempt.clientId!==config.clientId||attempt.redirectUri!==config.redirectUri)return reject();
    S.uuid(attempt.attemptId);S.digest(attempt.nonceHash);S.time(attempt.expiresAt);S.verifier(attempt.verifier);text(code,L.codeBytes);
    const signal=outer?AbortSignal.any([outer,AbortSignal.timeout(L.requestTimeoutMs)]):AbortSignal.timeout(L.requestTimeoutMs);checkSignal(signal);
    const response=object(await fetchJson(config.tokenEndpoint,{method:'POST',headers:{accept:'application/json','content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',code,client_id:config.clientId,redirect_uri:config.redirectUri,code_verifier:attempt.verifier}).toString()},L.tokenResponseBytes,L.tokenTimeoutMs,signal));
    const compact=text(response.id_token,L.compactTokenBytes),segments=compact.split('.');if(segments.length!==3)return reject();
    const header=object(strictJson(base64(segments[0]!,L.tokenHeaderBytes),L.tokenHeaderBytes));
    const claims=object(strictJson(base64(segments[1]!,L.tokenPayloadBytes),L.tokenPayloadBytes));base64(segments[2]!,512);
    if(header.alg!=='RS256'||['jku','jwk','x5u','crit','b64'].some(name=>Object.hasOwn(header,name)))return reject();text(header.kid,256);
    if(header.typ!==undefined&&header.typ!=='JWT')return reject();
    const clock=now();if(!Number.isFinite(clock))return reject();
    await abortable(jwtVerify(compact,remote,{algorithms:['RS256'],issuer:config.issuer,audience:config.clientId,requiredClaims:['iss','sub','aud','exp','iat','nonce','auth_time'],currentDate:new Date(clock),clockTolerance:0}),signal);
    const subject=text(claims.sub,1024),nonce=text(claims.nonce,128);if(!/^[A-Za-z0-9_-]{43}$/.test(nonce)||!equalSecret(sha256(nonce),attempt.nonceHash))return reject();
    const audience=typeof claims.aud==='string'?[text(claims.aud,256)]:claims.aud;
    if(!Array.isArray(audience)||audience.length<1||audience.length>8||audience.some(value=>typeof value!=='string'||text(value,256)!==value)||new Set(audience).size!==audience.length||!audience.includes(config.clientId))return reject();
    if((audience.length>1&&claims.azp!==config.clientId)||(claims.azp!==undefined&&claims.azp!==config.clientId))return reject();
    const authenticatedAt=numericDate(claims.auth_time),tokenIssuedAt=numericDate(claims.iat),tokenExpiresAt=numericDate(claims.exp);
    if(authenticatedAt>tokenIssuedAt||Date.parse(tokenIssuedAt)>clock||Date.parse(tokenExpiresAt)<=clock||tokenExpiresAt<=tokenIssuedAt||Date.parse(authenticatedAt)<Date.parse(attempt.expiresAt)-330_000)return reject();
    checkSignal(signal);return Object.freeze({issuer:config.issuer,subject,audience:config.clientId,nonceHash:sha256(nonce),idTokenHash:sha256(compact),authenticatedAt,tokenIssuedAt,tokenExpiresAt});
   }catch{return reject();}
  },
 });
}
