// SPDX-License-Identifier: Apache-2.0
import {createHash,randomBytes,timingSafeEqual} from 'node:crypto';
import {CompiledQuery} from 'kysely';
import type {FastifyInstance,FastifyRequest} from 'fastify';
import {db,sql,type Tx} from '../../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../../packages/authz/src/index.ts';
import {AUTHENTICATION_SCALARS,AuthenticationError,type AuthenticatedSession,type AuthenticationConnection} from '../../../packages/authority/src/authentication.ts';
import {readApplicationSession} from '../../../packages/authn/src/application-bridge.ts';
import type {AuthnEnvironment,PublicAuthnConfig} from '../../../packages/authn/src/contracts.ts';
import {AuthnHttpError,cookies,equalSecret,header,noQuery,sha256,validatePublicAuthnConfig} from '../../../packages/authn/src/transport.ts';

export const hash=(s:string)=>createHash('sha256').update(s).digest('hex');
export const random=()=>randomBytes(32).toString('base64url');
export const publicUrl=process.env.PUBLIC_AUTHN_ORIGIN??process.env.PUBLIC_URL??'http://localhost:4310';
export type Auth={principal:Principal;sessionHash:string;sessionVersion:number;csrf:string;tenants:{id:string;name:string;role:string}[]};
const expired=()=>new Problem(401,'SESSION_EXPIRED','Your session has expired. Sign in again.');
const unavailable=()=>new Problem(503,'AUTHN_UNAVAILABLE','Sign-in is temporarily unavailable. Try again.');

/** Deployment configuration only; neither a caller header nor a legacy cookie
 * can choose an origin, environment, executor or authentication mechanism. */
function authenticationConfig():PublicAuthnConfig {
 try {
  const config=validatePublicAuthnConfig({publicOrigin:process.env.PUBLIC_AUTHN_ORIGIN??'',environment:process.env.AUTHN_ENVIRONMENT as AuthnEnvironment});
  if(process.env.PUBLIC_URL!==undefined&&process.env.PUBLIC_URL!==config.publicOrigin)throw unavailable();
  return config;
 } catch {throw unavailable();}
}
function transportFailure(error:unknown):never {
 if(error instanceof AuthnHttpError){
  if(error.code==='AUTHN_CSRF_REJECTED')throw new Problem(403,'CSRF_REJECTED','The request could not be verified. Reload and try again.');
  if(error.code==='AUTHN_REQUEST_INVALID')throw new Problem(400,'AUTHN_REQUEST_INVALID','The authentication request is invalid.');
 }
 throw unavailable();
}

/** The supplied connection is the caller's existing native gc_app RR READ ONLY
 * transaction. SQL037 owns identity derivation and all protected-state checks. */
export async function readProtectedSession(connection:Pick<AuthenticationConnection,'query'>,sessionHash:string,csrfHash:string|null=null):Promise<AuthenticatedSession> {
 try {
  return await readApplicationSession(connection,{sessionHash:AUTHENTICATION_SCALARS.digest(sessionHash),csrfHash:csrfHash===null?null:AUTHENTICATION_SCALARS.digest(csrfHash)});
 } catch(error){
  if(error instanceof AuthenticationError&&error.code==='AUTHN_REJECTED')throw expired();
  throw unavailable();
 }
}
export function readProtectedSessionSnapshot(tx:Tx,sessionHash:string,csrfHash:string|null=null):Promise<AuthenticatedSession> {
 return readProtectedSession({query:async(text,values)=>{
  const result=await tx.executeQuery(CompiledQuery.raw(text,values??[]));
  return {rows:result.rows};
 }},sessionHash,csrfHash);
}
/** A held MVCC snapshot does not freeze wall-clock expiry or renew its profile. */
export async function requireLiveProtectedSession(tx:Tx,session:AuthenticatedSession):Promise<void> {
 const result=await sql<{live:boolean;within_profile:boolean}>`SELECT ${session.expiresAt}::timestamptz > clock_timestamp() AS live,
  clock_timestamp() < transaction_timestamp() + interval '30 seconds' AS within_profile`.execute(tx);
 if(result.rows.length!==1||result.rows[0]?.within_profile!==true)throw unavailable();
 if(result.rows[0].live!==true)throw expired();
}

/** Authentication is a bounded preflight for existing content handlers. Their
 * permission/ACL checks remain authoritative; this is not commit-time session
 * revocation fencing for a later mutation transaction. */
export async function authenticate(req:FastifyRequest):Promise<Auth>{
 const config=authenticationConfig();
 let jar:ReturnType<typeof cookies>;
 try {
  jar=cookies(req,config);
  if(!['GET','HEAD','OPTIONS'].includes(req.method)){
   const origin=header(req,'origin'),csrf=header(req,'x-csrf-token');
   if(origin!==config.publicOrigin||!jar.csrf||!csrf||!equalSecret(csrf,jar.csrf))throw new AuthnHttpError('AUTHN_CSRF_REJECTED');
  }
 } catch(error){return transportFailure(error);}
 if(!jar.session)throw new Problem(401,'SESSION_REQUIRED','Sign in to continue.');
 if(!jar.csrf)throw expired();
 const sessionHash=sha256(jar.session),csrf=jar.csrf;
 return db.transaction().setIsolationLevel('repeatable read').setAccessMode('read only').execute(async tx=>{
  await sql`SELECT set_config('statement_timeout','5000',true),set_config('lock_timeout','2000',true),set_config('idle_in_transaction_session_timeout','5000',true)`.execute(tx);
  const session=await readProtectedSessionSnapshot(tx,sessionHash,sha256(csrf));
  await sql`SELECT set_config('gc.tenant_id',${session.selectedTenantId},true),set_config('gc.actor_id',${session.identityId},true)`.execute(tx);
  const identity=await tx.selectFrom('identities').select('name').where('id','=',session.identityId).where('active','=',true).executeTakeFirst();
  const memberships=await tx.selectFrom('memberships').innerJoin('tenants','tenants.id','memberships.tenant_id')
   .select(['tenants.id','tenants.name','memberships.role','memberships.permissions'])
   .where('memberships.identity_id','=',session.identityId).where('memberships.active','=',true).orderBy('tenants.id').execute();
  const current=memberships.find(row=>row.id===session.selectedTenantId);
  if(!identity||!current)throw expired();
  if(!Array.isArray(current.permissions)||!current.permissions.every((permission:unknown)=>typeof permission==='string'))throw unavailable();
  await requireLiveProtectedSession(tx,session);
  return {principal:{id:session.identityId,name:identity.name,tenantId:session.selectedTenantId,permissions:current.permissions},
   sessionHash,sessionVersion:session.sessionVersion,csrf,tenants:memberships.map(({id,name,role})=>({id,name,role}))};
 });
}
export function equal(a:string,b:string){const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&timingSafeEqual(x,y);}
export function siteTenant(req:FastifyRequest){
 const expected=process.env.SITE_TOKEN??'', provided=(req.headers.authorization??'').replace(/^Bearer /,'');
 if(expected.length<32||!equal(expected,provided))throw new Problem(401,'SITE_AUTH_REQUIRED','Valid site identity required.');
 const tenant=req.headers['x-tenant-id'];
 if(typeof tenant!=='string'||!(process.env.SITE_TENANTS??'').split(',').includes(tenant))throw new Problem(403,'SITE_SCOPE_DENIED','Site is not assigned to this tenant.');
 return tenant;
}
export async function installAuth(app:FastifyInstance){
 authenticationConfig();
 if(['AUTHN_LOGIN_DATABASE_URL','AUTHN_API_DATABASE_URL','MIGRATION_DATABASE_URL','OWNER_DATABASE_URL','DATABASE_OWNER_URL','OIDC_CLIENT_SECRET'].some(name=>process.env[name]))throw unavailable();
 // A fixed navigation alias retains old bookmarks without any legacy issuance,
 // exchange, session lookup, tenant mutation or logout authority in this API.
 app.get('/auth/login',async(req,reply)=>{
  try{noQuery(req);}catch(error){return transportFailure(error);}
  return reply.redirect('/authn/login');
 });
}
