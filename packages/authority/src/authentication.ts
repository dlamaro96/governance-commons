// SPDX-License-Identifier: Apache-2.0
import {types as utilTypes} from 'node:util';
import {admitAuthorityInput, type AuthorityJSON} from './admission.ts';
import type {Parsed, UUID, Digest, UTC} from './types.ts';

export type AuthenticationVersion = number;
export type AuthenticationSQLValue = string | number | null;
export type AuthenticationQuery = {readonly text:string; readonly values:readonly AuthenticationSQLValue[]};
export type AuthenticationFailureCode = 'AUTHN_INPUT_INVALID' | 'AUTHN_RESPONSE_INVALID'
 | 'AUTHN_REJECTED' | 'AUTHN_VERSION_CONFLICT' | 'AUTHN_EXECUTOR_REJECTED'
 | 'AUTHN_INSTALL_CONFLICT' | 'AUTHN_TRANSPORT_FAILED';
export class AuthenticationError extends Error {
 constructor(readonly code:AuthenticationFailureCode) { super(code); this.name='AuthenticationError'; }
}
const inputError=():never=>{throw new AuthenticationError('AUTHN_INPUT_INVALID');};
/** Pure syntax helpers shared with the closed installation protocol; no authority is conferred. */
export const AUTHENTICATION_SCALARS=Object.freeze({
 uuid(value:unknown):UUID {if(typeof value!=='string'||! /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)||value==='00000000-0000-0000-0000-000000000000')return inputError();return value as UUID;},
 digest(value:unknown):Digest {if(typeof value!=='string'||! /^[0-9a-f]{64}$/.test(value))return inputError();return value as Digest;},
 integer(value:unknown,maximum=2_147_483_647):number {if(typeof value!=='number'||!Number.isSafeInteger(value)||value<1||value>maximum)return inputError();return value;},
 oid(value:unknown):number {return AUTHENTICATION_SCALARS.integer(value,4_294_967_295);},
 time(value:unknown):UTC {if(typeof value!=='string'||! /^(?!0000)[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/.test(value))return inputError();const date=new Date(value);if(!Number.isFinite(date.getTime())||date.toISOString()!==value)return inputError();return value as UTC;},
 text(value:unknown,maximum:number):string {if(typeof value!=='string'||/[\uD800-\uDFFF]/u.test(value)||value.length===0||Buffer.byteLength(value,'utf8')>maximum||/[\u0000-\u001f\u007f-\u009f]/.test(value))return inputError();return value;},
 reference(value:unknown):string {const text=AUTHENTICATION_SCALARS.text(value,256);if(!/^[\x20-\x7e]+$/.test(text))return inputError();return text;},
 verifier(value:unknown):string {if(typeof value!=='string'||! /^[A-Za-z0-9._~-]{43,128}$/.test(value))return inputError();return value;},
 roleName(value:unknown):string {return AUTHENTICATION_SCALARS.text(value,63);},
});
export function authenticationObject(input:unknown,keys:readonly string[]):Readonly<Record<string,AuthorityJSON>> {
 const result=admitAuthorityInput(input);
 if(!result.ok||result.value.metrics.canonicalBytes>65_536)return inputError();
 const value=result.value.data;
 if(value===null||typeof value!=='object'||Array.isArray(value))return inputError();
 const object=value as Readonly<Record<string,AuthorityJSON>>;
 const actual=Object.keys(object);
 if(actual.length!==keys.length||actual.some(key=>!keys.includes(key)))return inputError();
 return object;
}
export function authenticationParsed<T>(read:()=>T):Parsed<T> {
 try{return Object.freeze({ok:true,value:read()});}catch{return Object.freeze({ok:false,issues:Object.freeze([Object.freeze({code:'format' as const,path:'',message:'Invalid authentication protocol data.'})])});}
}
function unwrap<T>(result:Parsed<T>,code:AuthenticationFailureCode='AUTHN_INPUT_INVALID'):T {if(!result.ok)throw new AuthenticationError(code);return result.value;}
function frozen<T extends object>(value:T):Readonly<T>{return Object.freeze(value);}
const S=AUTHENTICATION_SCALARS;

export type AttemptBeginRequest={readonly stateHash:Digest;readonly verifier:string;readonly nonceHash:Digest};
export type AttemptConsumeRequest={readonly attemptId:UUID;readonly stateHash:Digest};
export type SessionIssueRequest={readonly attemptId:UUID;readonly issuer:string;readonly subject:string;readonly audience:string;readonly nonceHash:Digest;readonly idTokenHash:Digest;readonly authenticatedAt:UTC;readonly tokenIssuedAt:UTC;readonly tokenExpiresAt:UTC;readonly sessionHash:Digest;readonly csrfHash:Digest};
export type SessionInspectRequest={readonly sessionHash:Digest};
export type SessionRevokeRequest={readonly sessionHash:Digest;readonly csrfHash:Digest;readonly expectedSessionVersion:AuthenticationVersion};
export type SessionSelectRequest=SessionRevokeRequest & {readonly tenantId:UUID;readonly replacementCsrfHash:Digest};
export type AttemptStarted={readonly formatVersion:1;readonly attemptId:UUID;readonly expiresAt:UTC};
export type AttemptExchange=AttemptStarted & {readonly verifier:string;readonly issuerId:UUID;readonly issuer:string;readonly clientId:string;readonly redirectUri:string;readonly nonceHash:Digest};
export type SessionIssued={readonly formatVersion:1;readonly sessionId:UUID;readonly sessionVersion:AuthenticationVersion;readonly selectedTenantId:UUID;readonly expiresAt:UTC};
export type AuthenticatedSession=SessionIssued & {readonly identityId:UUID;readonly issuerId:UUID;readonly identityBindingId:UUID;readonly authenticatedAt:UTC;readonly generation:number;readonly tenantFenceEpoch:number;readonly authorityMode:'inactive';readonly contentAuthority:false};
export type SessionRevoked={readonly formatVersion:1;readonly sessionId:UUID;readonly sessionVersion:AuthenticationVersion;readonly loggedOut:true};
export type SessionSelected={readonly formatVersion:1;readonly sessionId:UUID;readonly sessionVersion:AuthenticationVersion;readonly selectedTenantId:UUID;readonly tenantFenceEpoch:number;readonly authorityMode:'inactive'};

export function parseAttemptBegin(input:unknown):Parsed<AttemptBeginRequest>{return authenticationParsed(()=>{const x=authenticationObject(input,['stateHash','verifier','nonceHash']);return frozen({stateHash:S.digest(x.stateHash),verifier:S.verifier(x.verifier),nonceHash:S.digest(x.nonceHash)});});}
export function parseAttemptConsume(input:unknown):Parsed<AttemptConsumeRequest>{return authenticationParsed(()=>{const x=authenticationObject(input,['attemptId','stateHash']);return frozen({attemptId:S.uuid(x.attemptId),stateHash:S.digest(x.stateHash)});});}
export function parseSessionIssue(input:unknown):Parsed<SessionIssueRequest>{return authenticationParsed(()=>{
 const x=authenticationObject(input,['attemptId','issuer','subject','audience','nonceHash','idTokenHash','authenticatedAt','tokenIssuedAt','tokenExpiresAt','sessionHash','csrfHash']);
 const authenticatedAt=S.time(x.authenticatedAt),tokenIssuedAt=S.time(x.tokenIssuedAt),tokenExpiresAt=S.time(x.tokenExpiresAt);
 if(authenticatedAt>tokenIssuedAt||tokenExpiresAt<=tokenIssuedAt)return inputError();
 return frozen({attemptId:S.uuid(x.attemptId),issuer:S.text(x.issuer,2048),subject:S.text(x.subject,1024),audience:S.text(x.audience,256),nonceHash:S.digest(x.nonceHash),idTokenHash:S.digest(x.idTokenHash),authenticatedAt,tokenIssuedAt,tokenExpiresAt,sessionHash:S.digest(x.sessionHash),csrfHash:S.digest(x.csrfHash)});
});}
export function parseSessionInspect(input:unknown):Parsed<SessionInspectRequest>{return authenticationParsed(()=>{const x=authenticationObject(input,['sessionHash']);return frozen({sessionHash:S.digest(x.sessionHash)});});}
export function parseSessionRevoke(input:unknown):Parsed<SessionRevokeRequest>{return authenticationParsed(()=>{const x=authenticationObject(input,['sessionHash','csrfHash','expectedSessionVersion']);return frozen({sessionHash:S.digest(x.sessionHash),csrfHash:S.digest(x.csrfHash),expectedSessionVersion:S.integer(x.expectedSessionVersion)});});}
export function parseSessionSelect(input:unknown):Parsed<SessionSelectRequest>{return authenticationParsed(()=>{
 const x=authenticationObject(input,['sessionHash','csrfHash','expectedSessionVersion','tenantId','replacementCsrfHash']);
 const csrfHash=S.digest(x.csrfHash),replacementCsrfHash=S.digest(x.replacementCsrfHash);if(csrfHash===replacementCsrfHash)return inputError();
 return frozen({sessionHash:S.digest(x.sessionHash),csrfHash,expectedSessionVersion:S.integer(x.expectedSessionVersion),tenantId:S.uuid(x.tenantId),replacementCsrfHash});
});}
function row(input:unknown,keys:readonly string[]):Readonly<Record<string,AuthorityJSON>> {const x=authenticationObject(input,['format_version',...keys]);if(x.format_version!==1)return inputError();return x;}
export function parseAttemptStarted(input:unknown):Parsed<AttemptStarted>{return authenticationParsed(()=>{const x=row(input,['attempt_id','expires_at']);return frozen({formatVersion:1,attemptId:S.uuid(x.attempt_id),expiresAt:S.time(x.expires_at)});});}
export function parseAttemptExchange(input:unknown):Parsed<AttemptExchange>{return authenticationParsed(()=>{const x=row(input,['attempt_id','verifier','issuer_id','issuer','client_id','redirect_uri','nonce_hash','expires_at']);return frozen({formatVersion:1,attemptId:S.uuid(x.attempt_id),verifier:S.verifier(x.verifier),issuerId:S.uuid(x.issuer_id),issuer:S.text(x.issuer,2048),clientId:S.text(x.client_id,256),redirectUri:S.text(x.redirect_uri,2048),nonceHash:S.digest(x.nonce_hash),expiresAt:S.time(x.expires_at)});});}
export function parseSessionIssued(input:unknown):Parsed<SessionIssued>{return authenticationParsed(()=>{const x=row(input,['session_id','session_version','selected_tenant_id','expires_at']);return frozen({formatVersion:1,sessionId:S.uuid(x.session_id),sessionVersion:S.integer(x.session_version),selectedTenantId:S.uuid(x.selected_tenant_id),expiresAt:S.time(x.expires_at)});});}
export function parseAuthenticatedSession(input:unknown):Parsed<AuthenticatedSession>{return authenticationParsed(()=>{
 const x=row(input,['session_id','session_version','identity_id','selected_tenant_id','issuer_id','identity_binding_id','authenticated_at','expires_at','generation','tenant_fence_epoch','authority_mode','content_authority']);
 if(x.authority_mode!=='inactive'||x.content_authority!==false)return inputError();
 const authenticatedAt=S.time(x.authenticated_at),expiresAt=S.time(x.expires_at);if(authenticatedAt>=expiresAt)return inputError();
 return frozen({formatVersion:1,sessionId:S.uuid(x.session_id),sessionVersion:S.integer(x.session_version),identityId:S.uuid(x.identity_id),selectedTenantId:S.uuid(x.selected_tenant_id),issuerId:S.uuid(x.issuer_id),identityBindingId:S.uuid(x.identity_binding_id),authenticatedAt,expiresAt,generation:S.integer(x.generation),tenantFenceEpoch:S.integer(x.tenant_fence_epoch),authorityMode:'inactive',contentAuthority:false});
});}
export function parseSessionRevoked(input:unknown):Parsed<SessionRevoked>{return authenticationParsed(()=>{const x=row(input,['session_id','session_version','logged_out']);if(x.logged_out!==true)return inputError();return frozen({formatVersion:1,sessionId:S.uuid(x.session_id),sessionVersion:S.integer(x.session_version),loggedOut:true});});}
export function parseSessionSelected(input:unknown):Parsed<SessionSelected>{return authenticationParsed(()=>{const x=row(input,['session_id','session_version','selected_tenant_id','tenant_fence_epoch','authority_mode']);if(x.authority_mode!=='inactive')return inputError();return frozen({formatVersion:1,sessionId:S.uuid(x.session_id),sessionVersion:S.integer(x.session_version),selectedTenantId:S.uuid(x.selected_tenant_id),tenantFenceEpoch:S.integer(x.tenant_fence_epoch),authorityMode:'inactive'});});}

const utc=(column:string)=>`pg_catalog.to_char(f.${column} AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS ${column}`;
function query(text:string,values:AuthenticationSQLValue[]):AuthenticationQuery{return frozen({text,values:Object.freeze(values)});}
export function attemptBeginQuery(input:AttemptBeginRequest):AuthenticationQuery {const x=unwrap(parseAttemptBegin(input));return query(`SELECT f.format_version,f.attempt_id,${utc('expires_at')} FROM public.gc_authn_attempt_begin($1::text,$2::text,$3::text) AS f`,[x.stateHash,x.verifier,x.nonceHash]);}
export function attemptConsumeQuery(input:AttemptConsumeRequest):AuthenticationQuery {const x=unwrap(parseAttemptConsume(input));return query(`SELECT f.format_version,f.attempt_id,f.verifier,f.issuer_id,f.issuer,f.client_id,f.redirect_uri,f.nonce_hash,${utc('expires_at')} FROM public.gc_authn_attempt_consume($1::uuid,$2::text) AS f`,[x.attemptId,x.stateHash]);}
export function sessionIssueQuery(input:SessionIssueRequest):AuthenticationQuery {const x=unwrap(parseSessionIssue(input));return query(`SELECT f.format_version,f.session_id,f.session_version,f.selected_tenant_id,${utc('expires_at')} FROM public.gc_authn_session_issue($1::uuid,$2::text,$3::text,$4::text,$5::text,$6::text,$7::timestamptz,$8::timestamptz,$9::timestamptz,$10::text,$11::text) AS f`,[x.attemptId,x.issuer,x.subject,x.audience,x.nonceHash,x.idTokenHash,x.authenticatedAt,x.tokenIssuedAt,x.tokenExpiresAt,x.sessionHash,x.csrfHash]);}
export function sessionInspectQuery(input:SessionInspectRequest):AuthenticationQuery {const x=unwrap(parseSessionInspect(input));return query(`SELECT f.format_version,f.session_id,f.session_version,f.identity_id,f.selected_tenant_id,f.issuer_id,f.identity_binding_id,${utc('authenticated_at')},${utc('expires_at')},f.generation,f.tenant_fence_epoch,f.authority_mode,f.content_authority FROM public.gc_authn_session_inspect($1::text) AS f`,[x.sessionHash]);}
export function sessionRevokeQuery(input:SessionRevokeRequest):AuthenticationQuery {const x=unwrap(parseSessionRevoke(input));return query('SELECT f.format_version,f.session_id,f.session_version,f.logged_out FROM public.gc_authn_session_revoke($1::text,$2::text,$3::integer) AS f',[x.sessionHash,x.csrfHash,x.expectedSessionVersion]);}
export function sessionSelectQuery(input:SessionSelectRequest):AuthenticationQuery {const x=unwrap(parseSessionSelect(input));return query('SELECT f.format_version,f.session_id,f.session_version,f.selected_tenant_id,f.tenant_fence_epoch,f.authority_mode FROM public.gc_authn_session_select($1::text,$2::text,$3::integer,$4::uuid,$5::text) AS f',[x.sessionHash,x.csrfHash,x.expectedSessionVersion,x.tenantId,x.replacementCsrfHash]);}

/** Minimal pg-compatible injection. This module neither creates nor imports an application pool. */
export interface AuthenticationConnection {
 query(text:string,values?:AuthenticationSQLValue[]):Promise<{rows:unknown[]}>;
 release(error?:boolean):void;
}
export interface AuthenticationPool {connect():Promise<AuthenticationConnection>}
export interface AuthenticationClient {
 attemptBegin(input:AttemptBeginRequest):Promise<AttemptStarted>;
 attemptConsume(input:AttemptConsumeRequest):Promise<AttemptExchange>;
 sessionIssue(input:SessionIssueRequest):Promise<SessionIssued>;
 sessionInspect(input:SessionInspectRequest):Promise<AuthenticatedSession>;
 sessionRevoke(input:SessionRevokeRequest):Promise<SessionRevoked>;
 sessionSelect(input:SessionSelectRequest):Promise<SessionSelected>;
}
export function safeAuthenticationError(error:unknown):AuthenticationError {
 let code:unknown;
 try{if(error!==null&&typeof error==='object'&&!utilTypes.isProxy(error)){const descriptor=Object.getOwnPropertyDescriptor(error,'code');if(descriptor&&'value'in descriptor)code=descriptor.value;}}catch{/* Never reflect raw driver errors into diagnostics. */}
 const known:readonly AuthenticationFailureCode[]=['AUTHN_INPUT_INVALID','AUTHN_RESPONSE_INVALID','AUTHN_REJECTED','AUTHN_VERSION_CONFLICT','AUTHN_EXECUTOR_REJECTED','AUTHN_INSTALL_CONFLICT','AUTHN_TRANSPORT_FAILED'];
 if(typeof code==='string'&&known.includes(code as AuthenticationFailureCode))return new AuthenticationError(code as AuthenticationFailureCode);
 const mapped:Partial<Record<string,AuthenticationFailureCode>>={'28000':'AUTHN_REJECTED','22023':'AUTHN_INPUT_INVALID','40001':'AUTHN_VERSION_CONFLICT','42501':'AUTHN_EXECUTOR_REJECTED','23505':'AUTHN_INSTALL_CONFLICT'};
 return new AuthenticationError(typeof code==='string'&&Object.hasOwn(mapped,code)?mapped[code]!:'AUTHN_TRANSPORT_FAILED');
}
export function createAuthenticationClient(pool:AuthenticationPool):AuthenticationClient {
 async function execute<T>(statement:AuthenticationQuery,parse:(row:unknown)=>Parsed<T>,readOnly=false,corresponds:(value:T)=>boolean=()=>true):Promise<T>{
  let connection:AuthenticationConnection|undefined,started=false,destroy=false;
  try {
   connection=await pool.connect();destroy=true;
   await connection.query(readOnly?'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY':'BEGIN ISOLATION LEVEL READ COMMITTED READ WRITE');started=true;destroy=false;
   const result=await connection.query(statement.text,[...statement.values]);
   if(!Array.isArray(result.rows)||result.rows.length!==1)throw new AuthenticationError('AUTHN_RESPONSE_INVALID');
   const value=unwrap(parse(result.rows[0]),'AUTHN_RESPONSE_INVALID');
   if(!corresponds(value))throw new AuthenticationError('AUTHN_RESPONSE_INVALID');
   destroy=true;await connection.query('COMMIT');started=false;destroy=false;
   return value;
  }catch(error){
   if(connection&&started){try{await connection.query('ROLLBACK');}catch{destroy=true;}}
   throw safeAuthenticationError(error);
  }finally{if(connection){try{connection.release(destroy);}catch{/* Release exceptions must not expose credentials or replace a completed result. */}}}
 }
 return frozen({
  attemptBegin:(input:AttemptBeginRequest)=>execute(attemptBeginQuery(input),parseAttemptStarted),
  attemptConsume:(input:AttemptConsumeRequest)=>{const request=unwrap(parseAttemptConsume(input));return execute(attemptConsumeQuery(request),parseAttemptExchange,false,value=>value.attemptId===request.attemptId);},
  sessionIssue:(input:SessionIssueRequest)=>execute(sessionIssueQuery(input),parseSessionIssued,false,value=>value.sessionVersion===1),
  sessionInspect:(input:SessionInspectRequest)=>execute(sessionInspectQuery(input),parseAuthenticatedSession,true),
  sessionRevoke:(input:SessionRevokeRequest)=>{const request=unwrap(parseSessionRevoke(input));return execute(sessionRevokeQuery(request),parseSessionRevoked,false,value=>value.sessionVersion===request.expectedSessionVersion+1);},
  sessionSelect:(input:SessionSelectRequest)=>{const request=unwrap(parseSessionSelect(input));return execute(sessionSelectQuery(request),parseSessionSelected,false,value=>value.sessionVersion===request.expectedSessionVersion+1&&value.selectedTenantId===request.tenantId);},
 });
}
