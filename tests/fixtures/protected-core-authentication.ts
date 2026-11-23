// SPDX-License-Identifier: Apache-2.0
/** Native protected test credentials are isolated from application DATABASE_URL.
 * This helper never receives an owner credential or writes private SQL tables. */
import {constants} from 'node:fs';
import {open} from 'node:fs/promises';
import {isAbsolute} from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {Pool} from 'pg';
import {request as nativeRequest} from 'node:http';
import {AUTHENTICATION_SCALARS as S,createAuthenticationClient} from '../../packages/authority/src/authentication.ts';
import {parseAuthorityInputFile} from '../../packages/authority/src/admission.ts';
import {validatePublicAuthnConfig} from '../../packages/authn/src/transport.ts';
import {PROTECTED_SEARCH_FIXTURE as search} from './protected-core-tenants.ts';

export type ProtectedCoreEndpointConfig={formatVersion:1;loginDatabaseUrl:string;apiDatabaseUrl:string;
 issuer:string;clientId:string;publicOrigin:string;environment:'local-development'|'isolated-test'};
export type PersistedProtectedSession={sessionToken:string;csrfToken:string;sessionHash:string;sessionVersion:number;
 selectedTenantId:string;expiresAt:string;identityId:string};
export type ProtectedCoreTestConfig=ProtectedCoreEndpointConfig&{membershipLossSession:PersistedProtectedSession;expiredSession:PersistedProtectedSession};
const hash=(value:string)=>S.digest(createHash('sha256').update(value).digest('hex'));
const random=()=>randomBytes(32).toString('base64url');
const requireValue=(value:unknown):void=>{if(!value)throw Error('PROTECTED_CORE_FIXTURE_INVALID');};
export async function readProtectedPrivateJson(path:string):Promise<unknown>{
 requireValue(isAbsolute(path));const file=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const before=await file.stat();requireValue(before.isFile()&&before.uid===process.getuid?.()&&(before.mode&0o077)===0&&before.size>0&&before.size<=65536);
  const bytes=Buffer.alloc(65537);let offset=0;
  while(offset<bytes.length){const result=await file.read(bytes,offset,bytes.length-offset,null);if(!result.bytesRead)break;offset+=result.bytesRead;}
  const after=await file.stat();requireValue(offset===before.size&&before.size===after.size&&before.mtimeMs===after.mtimeMs&&before.ctimeMs===after.ctimeMs);
  const parsed=parseAuthorityInputFile(new TextDecoder('utf8',{fatal:true}).decode(bytes.subarray(0,offset)));
  if(!parsed.ok)throw Error('PROTECTED_CORE_FIXTURE_INVALID');return parsed.value.data;
 }finally{await file.close();}
}
export function validateProtectedCoreEndpoints(value:ProtectedCoreEndpointConfig):void{
 requireValue(value.formatVersion===1&&['local-development','isolated-test'].includes(value.environment));validatePublicAuthnConfig(value);
 requireValue(value.clientId==='governance-protected-web'&&typeof value.issuer==='string'&&value.issuer.length<2048);
 const issuer=new URL(value.issuer);requireValue(['http:','https:'].includes(issuer.protocol)&&!issuer.username&&!issuer.password&&!issuer.search&&!issuer.hash);
 for(const [url,role] of [[value.loginDatabaseUrl,'gc_authn_login'],[value.apiDatabaseUrl,'gc_authn_api']]){
  const parsed=new URL(url!);requireValue(['postgres:','postgresql:'].includes(parsed.protocol)&&decodeURIComponent(parsed.username)===role&&parsed.password&&parsed.pathname.length>1&&!parsed.hash);
 }
}
function validatePersisted(value:PersistedProtectedSession,identity:string):void{
 requireValue(value&&Object.keys(value).sort().join(',')==='csrfToken,expiresAt,identityId,selectedTenantId,sessionHash,sessionToken,sessionVersion');
 requireValue(/^[A-Za-z0-9_-]{43}$/.test(value.sessionToken)&&/^[A-Za-z0-9_-]{43}$/.test(value.csrfToken)&&value.sessionHash===hash(value.sessionToken));
 requireValue(value.identityId===identity&&value.selectedTenantId===search.tenant&&value.sessionVersion===1);S.time(value.expiresAt);
}
let configuration:Promise<ProtectedCoreTestConfig>|undefined;
export function protectedCoreConfig():Promise<ProtectedCoreTestConfig>{
 return configuration??=(async()=>{
  requireValue(!process.env.MIGRATION_DATABASE_URL&&!process.env.AUTHN_OWNER_DATABASE_URL&&!process.env.AUTHN_ADMIN_DATABASE_URL);
  const value=await readProtectedPrivateJson(process.env.AUTHN_PROTECTED_CORE_CONFIG??'') as ProtectedCoreTestConfig;
  requireValue(value&&Object.keys(value).sort().join(',')==='apiDatabaseUrl,clientId,environment,expiredSession,formatVersion,issuer,loginDatabaseUrl,membershipLossSession,publicOrigin');
  validateProtectedCoreEndpoints(value);validatePersisted(value.membershipLossSession,search.membershipLoss);validatePersisted(value.expiredSession,search.expired);
  if(process.env.PUBLIC_AUTHN_ORIGIN)requireValue(process.env.PUBLIC_AUTHN_ORIGIN===value.publicOrigin);
  if(process.env.PUBLIC_URL)requireValue(process.env.PUBLIC_URL===value.publicOrigin);
  return value;
 })();
}
async function native<T>(url:string,work:(client:ReturnType<typeof createAuthenticationClient>,pool:Pool)=>Promise<T>):Promise<T>{
 const pool=new Pool({connectionString:url,max:1,connectionTimeoutMillis:5000,statement_timeout:5000,lock_timeout:2000,query_timeout:6000});
 try{return await work(createAuthenticationClient(pool),pool);}finally{await pool.end();}
}
export function protectedHeaders(config:ProtectedCoreEndpointConfig,value:PersistedProtectedSession):Record<string,string>{
 return {Cookie:`gc_authn_session=${value.sessionToken}; gc_authn_csrf=${value.csrfToken}`,'X-CSRF-Token':value.csrfToken,
  Origin:config.publicOrigin,'Content-Type':'application/json'};
}
/** All three login calls commit separately; no mocked issuer or public session insert. */
export async function issueProtectedCoreSession(config:ProtectedCoreEndpointConfig,identityId:string):Promise<PersistedProtectedSession>{
 validateProtectedCoreEndpoints(config);S.uuid(identityId);
 const sessionToken=random(),csrfToken=random(),stateHash=hash(random()),nonceHash=hash(random()),verifier=random();
 return native(config.loginDatabaseUrl,async(client,pool)=>{
  const started=await client.attemptBegin({stateHash,nonceHash,verifier});
  const consumed=await client.attemptConsume({attemptId:started.attemptId,stateHash});
  requireValue(consumed.issuer===config.issuer&&consumed.clientId===config.clientId&&consumed.verifier===verifier&&consumed.nonceHash===nonceHash&&consumed.redirectUri===config.publicOrigin+'/authn/callback');
  const now=(await pool.query("SELECT to_char(date_trunc('milliseconds',clock_timestamp()) AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') AS now")).rows[0].now as string;
  const issued=await client.sessionIssue({attemptId:started.attemptId,issuer:config.issuer,subject:identityId,audience:config.clientId,
   nonceHash,idTokenHash:hash(random()),authenticatedAt:S.time(now),tokenIssuedAt:S.time(now),
   tokenExpiresAt:S.time(new Date(Date.parse(now)+300000).toISOString()),sessionHash:hash(sessionToken),csrfHash:hash(csrfToken)});
  return {sessionToken,csrfToken,sessionHash:hash(sessionToken),sessionVersion:issued.sessionVersion,selectedTenantId:issued.selectedTenantId,expiresAt:issued.expiresAt,identityId};
 });
}
export async function inspectProtectedCoreSession(config:ProtectedCoreEndpointConfig,value:PersistedProtectedSession){
 return native(config.apiDatabaseUrl,client=>client.sessionInspect({sessionHash:S.digest(value.sessionHash)}));
}
export type ProtectedCoreSession={readonly headers:Record<string,string>;readonly sessionHash:string;readonly sessionVersion:number;
 readonly selectedTenantId:string;readonly expiresAt:string;revoke():Promise<void>;selectTenant(tenantId:string):Promise<void>};
const issuedSessions=new Set<ProtectedCoreSession>();
export async function closeProtectedCoreSessions(){for(const session of issuedSessions){await session.revoke();issuedSessions.delete(session);}}
export async function createProtectedCoreSession(identityId:string,tenantId:string):Promise<ProtectedCoreSession>{
 const config=await protectedCoreConfig(),value=await issueProtectedCoreSession(config,identityId);let revoked=false;
 const session:ProtectedCoreSession={
  get headers(){return protectedHeaders(config,value);},get sessionHash(){return value.sessionHash;},get sessionVersion(){return value.sessionVersion;},
  get selectedTenantId(){return value.selectedTenantId;},get expiresAt(){return value.expiresAt;},
  async revoke(){if(revoked)return;const result=await native(config.apiDatabaseUrl,client=>client.sessionRevoke({sessionHash:S.digest(value.sessionHash),csrfHash:hash(value.csrfToken),expectedSessionVersion:S.integer(value.sessionVersion)}));value.sessionVersion=result.sessionVersion;revoked=true;},
  async selectTenant(selected){const replacement=random();const result=await native(config.apiDatabaseUrl,client=>client.sessionSelect({sessionHash:S.digest(value.sessionHash),csrfHash:hash(value.csrfToken),expectedSessionVersion:S.integer(value.sessionVersion),tenantId:S.uuid(selected),replacementCsrfHash:hash(replacement)}));value.sessionVersion=result.sessionVersion;value.selectedTenantId=result.selectedTenantId;value.csrfToken=replacement;},
 };
 if(value.selectedTenantId!==tenantId)await session.selectTenant(tenantId);
 const observed=await inspectProtectedCoreSession(config,value);requireValue(observed.identityId===identityId&&observed.selectedTenantId===tenantId&&observed.sessionVersion===session.sessionVersion);
 issuedSessions.add(session);return session;
}
export async function preparedProtectedSession(kind:'membershipLossSession'|'expiredSession'){
 const config=await protectedCoreConfig(),value=config[kind];return {...value,headers:protectedHeaders(config,value)};
}

/** Node fetch drops caller Host. This bounded probe retains the product edge's
 * exact public-host admission while connecting over the private Compose network.
 * It does not retry or update a caller session after an uncertain mutation. */
export async function probeProtectedTenantSelection(headers:Record<string,string>,body:{tenantId:string;expectedSessionVersion:number}):Promise<{status:number}>{
 const config=await protectedCoreConfig(),edge=new URL(process.env.AUTHN_CORE_EDGE_URL??config.publicOrigin);
 requireValue(edge.protocol==='http:'&&['authn-edge','127.0.0.1','localhost','[::1]'].includes(edge.hostname)
  &&!edge.username&&!edge.password&&edge.pathname==='/'&&!edge.search&&!edge.hash&&headers.Origin===config.publicOrigin);
 S.uuid(body.tenantId);S.integer(body.expectedSessionVersion);
 const data=JSON.stringify(body),target=new URL('/authn/tenant',edge);
 return new Promise((resolve,reject)=>{
  let timer:ReturnType<typeof setTimeout>|undefined,settled=false;
  const fail=()=>{if(timer)clearTimeout(timer);if(!settled){settled=true;reject(Error('BOUNDED_PROTECTED_TENANT_PROBE_FAILED'));}};
  const request=nativeRequest(target,{method:'POST',maxHeaderSize:8192,headers:{Cookie:headers.Cookie!,
   'X-CSRF-Token':headers['X-CSRF-Token']!,Origin:config.publicOrigin,Host:new URL(config.publicOrigin).host,
   'Content-Type':'application/json','Content-Length':Buffer.byteLength(data)}},response=>{
   let size=0;response.on('data',(chunk:Buffer)=>{size+=chunk.length;if(size>8192){request.destroy();response.destroy();fail();}});
   response.on('error',fail);response.on('aborted',fail);
   response.on('end',()=>{if(timer)clearTimeout(timer);if(!settled){settled=true;resolve({status:response.statusCode??500});}});
  });
  timer=setTimeout(()=>{request.destroy();fail();},15000);request.on('error',fail);request.end(data);
 });
}
