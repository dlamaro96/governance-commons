// SPDX-License-Identifier: Apache-2.0
import {createHash,randomBytes,timingSafeEqual} from 'node:crypto';
import {createRemoteJWKSet,jwtVerify} from 'jose';
import type {FastifyInstance,FastifyRequest} from 'fastify';
import {db,scope,sql} from '../../../packages/db/src/index.ts';
import {Problem,type Principal} from '../../../packages/authz/src/index.ts';
export const hash=(s:string)=>createHash('sha256').update(s).digest('hex');
export const random=()=>randomBytes(32).toString('base64url');
export const publicUrl=process.env.PUBLIC_URL??'http://localhost:4310';
const issuer=process.env.OIDC_ISSUER??'http://localhost:4311/realms/governance';
const internal=process.env.OIDC_INTERNAL_BASE??issuer;
const clientId=process.env.OIDC_CLIENT_ID??'governance-web';
const secure=process.env.NODE_ENV==='production';
export type Auth={principal:Principal;sessionHash:string;csrf:string;tenants:{id:string;name:string;role:string}[]};
export async function authenticate(req:FastifyRequest):Promise<Auth>{
 const token=req.cookies.gc_session;if(!token)throw new Problem(401,'SESSION_REQUIRED','Sign in to continue.');
 const session=await db.selectFrom('sessions').innerJoin('identities','identities.id','sessions.identity_id').select(['sessions.id_hash','sessions.identity_id','sessions.tenant_id','sessions.csrf','identities.name']).where('sessions.id_hash','=',hash(token)).where('sessions.expires_at','>',new Date()).where('identities.active','=',true).executeTakeFirst();
 if(!session)throw new Problem(401,'SESSION_EXPIRED','Your session has expired. Sign in again.');
 const memberships=await scope(session.tenant_id,session.identity_id,tx=>tx.selectFrom('memberships').innerJoin('tenants','tenants.id','memberships.tenant_id').select(['tenants.id','tenants.name','memberships.role','memberships.permissions']).where('memberships.identity_id','=',session.identity_id).where('memberships.active','=',true).execute());
 const current=memberships.find(x=>x.id===session.tenant_id);if(!current)throw new Problem(401,'MEMBERSHIP_REVOKED','Access to this organization has been revoked.');
 if(!['GET','HEAD','OPTIONS'].includes(req.method)) {
  const origin=req.headers.origin,csrf=req.headers['x-csrf-token'];
  if(origin!==new URL(publicUrl).origin||typeof csrf!=='string'||!equal(csrf,session.csrf))throw new Problem(403,'CSRF_REJECTED','The request could not be verified. Reload and try again.');
 }
 return {principal:{id:session.identity_id,name:session.name,tenantId:session.tenant_id,permissions:current.permissions},sessionHash:session.id_hash,csrf:session.csrf,tenants:memberships.map(({id,name,role})=>({id,name,role}))};
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
 const jwks=createRemoteJWKSet(new URL(internal+'/protocol/openid-connect/certs'));
 app.get('/auth/login',async(req,reply)=>{
  const state=random(),verifier=random(),nonce=random();
  await db.deleteFrom('login_states').where('expires_at','<',new Date()).execute();
  await db.insertInto('login_states').values({id_hash:hash(state),verifier,nonce,expires_at:new Date(Date.now()+300000)}).execute();
  const url=new URL(issuer+'/protocol/openid-connect/auth');url.search=new URLSearchParams({client_id:clientId,redirect_uri:publicUrl+'/auth/callback',response_type:'code',scope:'openid profile',state,nonce,code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'}).toString();
  reply.setCookie('gc_state',state,{path:'/auth',httpOnly:true,sameSite:'lax',secure,maxAge:300});return reply.redirect(url.href);
 });
 app.get('/auth/callback',async(req,reply)=>{
  const q=req.query as Record<string,string>,state=req.cookies.gc_state;
  if(!state||!q.state||!equal(state,q.state)||!q.code)throw new Problem(401,'OIDC_STATE_INVALID','Sign-in could not be verified. Start again.');
  const pending=await db.deleteFrom('login_states').where('id_hash','=',hash(state)).where('expires_at','>',new Date()).returningAll().executeTakeFirst();
  reply.clearCookie('gc_state',{path:'/auth'});
  if(!pending)throw new Problem(401,'OIDC_STATE_EXPIRED','Sign-in expired or was already used.');
  const result=await fetch(internal+'/protocol/openid-connect/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',client_id:clientId,code:q.code,redirect_uri:publicUrl+'/auth/callback',code_verifier:pending.verifier}),signal:AbortSignal.timeout(10000)});
  if(!result.ok)throw new Problem(401,'OIDC_EXCHANGE_FAILED','The identity provider could not complete sign-in.');
  const tokens=await result.json() as {id_token:string};
  let claims;try{claims=(await jwtVerify(tokens.id_token,jwks,{issuer,audience:clientId,algorithms:['RS256'],requiredClaims:['sub','exp','iat','nonce']})).payload;}catch{throw new Problem(401,'OIDC_TOKEN_INVALID','The identity token could not be verified.');}
  if(claims.nonce!==pending.nonce||!claims.sub)throw new Problem(401,'OIDC_NONCE_INVALID','Sign-in could not be verified.');
  const identity=await db.selectFrom('identities').selectAll().where('issuer','=',issuer).where('subject','=',claims.sub).where('active','=',true).executeTakeFirst();
  if(!identity)throw new Problem(403,'IDENTITY_NOT_PROVISIONED','This identity has not been provisioned for an organization.');
  const membership=await scope('',identity.id,tx=>tx.selectFrom('memberships').selectAll().where('identity_id','=',identity.id).where('active','=',true).orderBy('tenant_id').executeTakeFirst());
  if(!membership)throw new Problem(403,'NO_MEMBERSHIP','No active organization membership.');
  if(req.cookies.gc_session)await db.deleteFrom('sessions').where('id_hash','=',hash(req.cookies.gc_session)).execute();
  const token=random();await db.insertInto('sessions').values({id_hash:hash(token),identity_id:identity.id,tenant_id:membership.tenant_id,csrf:random(),expires_at:new Date(Date.now()+1800000)}).execute();
  reply.setCookie('gc_session',token,{path:'/',httpOnly:true,sameSite:'lax',secure,maxAge:1800});return reply.redirect('/');
 });
 app.post('/auth/logout',async(req,reply)=>{const auth=await authenticate(req);await db.deleteFrom('sessions').where('id_hash','=',auth.sessionHash).execute();reply.clearCookie('gc_session',{path:'/'});return {loggedOut:true};});
}
