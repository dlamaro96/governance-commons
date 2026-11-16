// SPDX-License-Identifier: Apache-2.0
import type {FastifyInstance} from 'fastify';
import {AUTHENTICATION_SCALARS as S} from '../../../packages/authority/src/authentication.ts';
import {AUTHN_LIMITS as L, type BrokerAuthentication, type BrokerOidcConfig} from '../../../packages/authn/src/contracts.ts';
import type {OidcClient} from '../../../packages/authn/src/oidc.ts';
import {validateBrokerOidcConfig} from '../../../packages/authn/src/oidc.ts';
import {AuthnHttpError, clearAuthnCookies, cookies, createAuthnApp, equalSecret, mapAuthenticationError, noQuery, randomSecret, requestAbortSignal, sendAuthnError, setAuthnCookie, sha256, strictQuery} from '../../../packages/authn/src/transport.ts';

function badRequest():never{throw new AuthnHttpError('AUTHN_REQUEST_INVALID');}
function loginInvalid():never{throw new AuthnHttpError('AUTHN_LOGIN_INVALID');}
function bounded(value:string|undefined,maximum:number):string{
 if(value===undefined||!value||Buffer.byteLength(value)>maximum||/[\u0000-\u001f\u007f-\u009f]/u.test(value))return badRequest();return value;
}
function callbackQuery(rawUrl:string,issuer:string):Readonly<{state:string;code?:string;error?:string}>{
 const query=strictQuery(rawUrl),isError=Object.hasOwn(query,'error');
 const allowed=isError?['error','state','iss','error_description','error_uri']:['code','state','iss','session_state'];
 if(Object.keys(query).some(key=>!allowed.includes(key)))return badRequest();
 const state=bounded(query.state,43);if(!/^[A-Za-z0-9_-]{43}$/.test(state))return badRequest();
 if(query.iss!==undefined&&bounded(query.iss,2048)!==issuer)return loginInvalid();
 if(query.session_state!==undefined)bounded(query.session_state,1024);
 if(query.error_description!==undefined)bounded(query.error_description,2048);
 if(query.error_uri!==undefined)bounded(query.error_uri,2048);
 return isError?{state,error:bounded(query.error,256)}:{state,code:bounded(query.code,L.codeBytes)};
}
/** The injected client is the committed native login-only protocol; no legacy principal exists here. */
export function buildLoginBroker({config:input,authentication,oidc,readiness}:{config:BrokerOidcConfig;authentication:BrokerAuthentication;oidc:OidcClient;readiness:()=>Promise<void>}):FastifyInstance {
 const config=validateBrokerOidcConfig(input),app=createAuthnApp(config,{loginRateLimit:true});
 app.get('/health/ready',async(request,reply)=>{
  try{noQuery(request);await oidc.initialize();await readiness();if(requestAbortSignal(request).aborted)return reply;return {ready:true};}
  catch(error){return sendAuthnError(reply,error instanceof AuthnHttpError&&error.code==='AUTHN_REQUEST_INVALID'?'AUTHN_REQUEST_INVALID':'AUTHN_UNAVAILABLE');}
 });
 app.get('/authn/login',async(request,reply)=>{
  try{
   noQuery(request);const signal=requestAbortSignal(request);if(signal.aborted)return loginInvalid();
   const state=randomSecret(),nonce=randomSecret(),verifier=randomSecret();
   // attemptBegin commits through the native client before the redirect/cookie can escape.
   const attempt=await authentication.attemptBegin({stateHash:sha256(state),nonceHash:sha256(nonce),verifier});
   if(signal.aborted)return loginInvalid();
   const location=oidc.authorizationUrl({state,nonce,verifier});
   setAuthnCookie(reply,config,'attempt',`${attempt.attemptId}.${state}`,attempt.expiresAt);
   return reply.code(302).header('location',location).send();
  }catch(error){return sendAuthnError(reply,mapAuthenticationError(error,'login'));}
 });
 app.get('/authn/callback',async(request,reply)=>{
  try{
   const query=callbackQuery(request.raw.url??'',config.issuer),cookie=cookies(request,config).attempt;
   if(cookie===undefined)return loginInvalid();
   const match=/^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.([A-Za-z0-9_-]{43})$/.exec(cookie);
   if(!match||!equalSecret(match[2]!,query.state))return loginInvalid();
   let attemptId;try{attemptId=S.uuid(match[1]);}catch{return loginInvalid();}
   const signal=requestAbortSignal(request);if(signal.aborted)return loginInvalid();
   let attempt;
   try{attempt=await authentication.attemptConsume({attemptId,stateHash:sha256(query.state)});}
   finally{clearAuthnCookies(reply,config,['attempt']);}
   // A matched provider error consumes the attempt too. Its supplied description/URI is never emitted.
   if(query.error!==undefined||signal.aborted)return loginInvalid();
   const identity=await oidc.exchangeAndVerify(attempt,query.code!,{signal});
   if(signal.aborted)return loginInvalid();
   const session=randomSecret(),csrf=randomSecret();
   const issued=await authentication.sessionIssue({attemptId:attempt.attemptId,...identity,sessionHash:sha256(session),csrfHash:sha256(csrf)});
   if(signal.aborted)return loginInvalid();
   // No cookies on uncertain COMMIT, no retry of one-use token issuance, no implicit legacy login.
   setAuthnCookie(reply,config,'session',session,issued.expiresAt);setAuthnCookie(reply,config,'csrf',csrf,issued.expiresAt);
   return reply.code(302).header('location','/authn/').send();
  }catch(error){return sendAuthnError(reply,mapAuthenticationError(error,'login'));}
 });
 return app;
}
