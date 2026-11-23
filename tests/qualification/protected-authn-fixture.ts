// SPDX-License-Identifier: Apache-2.0
/** Private isolated qualification helpers. No default URL or shared-core fallback. */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {randomUUID,randomBytes,createHash} from 'node:crypto';
import {createServer,request as nativeRequest,type IncomingMessage,type ServerResponse} from 'node:http';
import type {TestContext} from 'node:test';
import {generateKeyPair,exportJWK,SignJWT} from 'jose';
import pg from 'pg';
import {connect,query,scalar,tx,install,counts,iso,type Row} from '../fixtures/authority-authn-foundation.ts';
import {createAuthenticationClient} from '../../packages/authority/src/authentication.ts';
import {createOidcClient,type OidcClient} from '../../packages/authn/src/oidc.ts';
import {buildLoginBroker} from '../../apps/login-broker/src/app.ts';
import {createSessionApp} from '../../apps/session-api/src/server.ts';
import type {BrokerAuthentication,BrokerOidcConfig} from '../../packages/authn/src/contracts.ts';
import type {FastifyInstance} from 'fastify';
export {query,scalar,tx,install,counts,iso};
const path=process.env.AUTHN_PROTECTED_CONFIG;
if(!path)throw Error('Explicit isolated protected-authn config required');
export const config=JSON.parse(readFileSync(path,'utf8')) as {owner:string;admin:string;legacy:string;login:string;api:string;slots:{login:{name:string;url:string};api:{name:string;url:string}}[]};
let nextSlot=0;
export const hash=(value:string)=>createHash('sha256').update(value).digest('hex');
export const random=()=>randomBytes(32).toString('base64url');
export const origin='http://127.0.0.1:4314';
export type ProbeFixture={owner:pg.Client;login:pg.Client;api:pg.Client;legacy:pg.Client;loginPool:pg.Pool;apiPool:pg.Pool;apiUrl:string;tenant:string;otherTenant:string;identity:string;issuerId:string;bindingId:string;loginId:string;apiId:string;issuer:string;expiry:string;config:BrokerOidcConfig};
export async function fixture(t:TestContext,expiryMs=3_600_000):Promise<ProbeFixture>{
 const slot=config.slots[nextSlot++];assert.ok(slot,'Native fixture roles exhausted');
 const clients:pg.Client[]=[];
 t.after(async()=>{await Promise.all(clients.map(c=>c.end()));});
 const open=async(url:string)=>{const c=await connect(url);clients.push(c);return c;};
 const owner=await open(config.owner),login=await open(slot.login.url),api=await open(slot.api.url),legacy=await open(config.legacy);
 const loginPool=new pg.Pool({connectionString:slot.login.url,max:4,connectionTimeoutMillis:5000,statement_timeout:5000,lock_timeout:2000}),apiPool=new pg.Pool({connectionString:slot.api.url,max:4,connectionTimeoutMillis:5000,statement_timeout:5000,lock_timeout:2000});
 t.after(async()=>{await Promise.all([loginPool.end(),apiPool.end()]);});
 const [tenant,otherTenant]=[randomUUID(),randomUUID()].sort() as [string,string];
 const identity=randomUUID(),issuerId=randomUUID(),bindingId=randomUUID(),loginId=randomUUID(),apiId=randomUUID(),issuer='https://synthetic-protected.example/'+randomUUID();
 const now=Date.parse(iso((await scalar(owner,"SELECT date_trunc('milliseconds',clock_timestamp()) t")).t));
 const expiry=iso(new Date(now+expiryMs)),registrationExpiry=iso(new Date(now+3_600_000));
 await query(owner,'INSERT INTO public.tenants(id,name) VALUES($1,$3),($2,$3)',[tenant,otherTenant,'Synthetic isolated authn probe']);
 await query(owner,'INSERT INTO public.identities(id,issuer,subject,name) VALUES($1::uuid,$2::text,($1::uuid)::text,$3::text)',[identity,issuer,'Synthetic probe identity']);
 for(const id of [tenant,otherTenant])await tx(owner,async()=>{await query(owner,"SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[id,identity]);await query(owner,"INSERT INTO public.memberships(tenant_id,identity_id,role,permissions) VALUES($1,$2,'synthetic','[]')",[id,identity]);});
 for(const [kind,role,id] of [['login',slot.login,loginId],['api',slot.api,apiId]] as const){
  const oid=Number((await scalar(owner,'SELECT oid::int8 AS oid FROM pg_roles WHERE rolname=$1',[role.name])).oid),channel=randomUUID();
  await install(owner,'register-executor',[id,channel,role.name,oid,kind,1,registrationExpiry]);await install(owner,'advance-generation',[kind,channel,id,null,null]);
 }
 await install(owner,'register-issuer',[issuerId,loginId,1,issuer,'synthetic-protected-client',origin+'/authn/callback','isolated-test',registrationExpiry]);
 await install(owner,'bind-identity',[bindingId,issuerId,identity,issuer,identity,expiry]);
 for(const id of [tenant,otherTenant])await install(owner,'initialize-tenant',[id,1]);
 const oidc:BrokerOidcConfig={publicOrigin:origin,environment:'isolated-test',issuer,clientId:'synthetic-protected-client',redirectUri:origin+'/authn/callback',authorizationEndpoint:issuer+'/authorize',tokenEndpoint:issuer+'/token',jwksUri:issuer+'/jwks'};
 return {owner,login,api,legacy,loginPool,apiPool,apiUrl:slot.api.url,tenant,otherTenant,identity,issuerId,bindingId,loginId,apiId,issuer,expiry,config:oidc};
}
export type TokenMode='valid'|'nonce'|'issuer'|'audience'|'azp'|'signature'|'algorithm'|'missing_auth_time'|'stale_auth_time'|'expiry'|'future_iat'|'network';
export async function provider(t:TestContext,f:ProbeFixture){
 const keys=await generateKeyPair('RS256',{extractable:true}),wrong=await generateKeyPair('RS256');
 const jwk={...await exportJWK(keys.publicKey),kid:'synthetic-signing-key',alg:'RS256',use:'sig'};
 let subject=f.identity;let mode:TokenMode='valid',nonce='',attemptId='',verifierChallenge='',exchanges=0,observedCommitted=0;
 let beforeToken:()=>Promise<void>=async()=>{};
 const server=createServer((req,res)=>{void handle(req,res).catch(()=>{if(!res.headersSent)res.writeHead(500);res.end();});});
 async function handle(req:IncomingMessage,res:ServerResponse){
  res.setHeader('content-type','application/json');
  if(req.url==='/metadata'){res.end(JSON.stringify({issuer:f.issuer,authorization_endpoint:f.config.authorizationEndpoint,token_endpoint:f.config.tokenEndpoint,jwks_uri:f.config.jwksUri,id_token_signing_alg_values_supported:['RS256']}));return;}
  if(req.url==='/jwks'){res.end(JSON.stringify({keys:[jwk]}));return;}
  assert.equal(req.url,'/token');assert.equal(req.method,'POST');
  const parts:Buffer[]=[];let size=0;for await(const chunk of req){size+=Buffer.byteLength(chunk);assert.ok(size<=8192);parts.push(Buffer.from(chunk));}
  const form=new URLSearchParams(Buffer.concat(parts).toString());assert.ok(form.get('grant_type')==='authorization_code'&&form.get('client_id')===f.config.clientId&&form.get('redirect_uri')===f.config.redirectUri);
  assert.ok(createHash('sha256').update(form.get('code_verifier')??'').digest('base64url')===verifierChallenge);
  exchanges++;
  const row=await scalar(f.owner,'SELECT count(*)::int AS n FROM gc_authn.attempt_consumptions WHERE attempt_id=$1',[attemptId]);assert.equal(row.n,1);observedCommitted++;
  await beforeToken();if(mode==='network'){res.writeHead(503);res.end('{}');return;}
  const now=Math.floor(Date.now()/1000),claims:Record<string,unknown>={iss:f.issuer,sub:subject,aud:f.config.clientId,nonce,auth_time:now,iat:now,exp:now+300};
  if(mode==='nonce')claims.nonce=random();if(mode==='issuer')claims.iss='https://wrong.example';if(mode==='audience')claims.aud='other-client';if(mode==='azp'){claims.aud=[f.config.clientId,'other-client'];claims.azp='wrong';}
  if(mode==='missing_auth_time')delete claims.auth_time;if(mode==='stale_auth_time')claims.auth_time=now-3600;if(mode==='expiry')claims.exp=now-1;if(mode==='future_iat'){claims.iat=now+60;claims.exp=now+300;}
  const token=mode==='algorithm'?await new SignJWT(claims).setProtectedHeader({alg:'HS256',kid:'synthetic-signing-key'}).sign(randomBytes(32)):await new SignJWT(claims).setProtectedHeader({alg:'RS256',kid:'synthetic-signing-key'}).sign(mode==='signature'?wrong.privateKey:keys.privateKey);
  res.end(JSON.stringify({id_token:token}));
 }
 await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
 t.after(()=>new Promise<void>((r,j)=>server.close(e=>e?j(e):r())));
 const address=server.address();assert.ok(address&&typeof address==='object');
 const base=`http://127.0.0.1:${address.port}`;
 // Test-only transport injection traverses an actual bounded local HTTP server.
 // It is not a product alias or a substitute for the separate real Keycloak gate.
 const route=new Map([[f.issuer+'/.well-known/openid-configuration','/metadata'],[f.config.jwksUri,'/jwks'],[f.config.tokenEndpoint,'/token']]);
 const oidc=createOidcClient(f.config,{fetch:async(input,init)=>{const path=route.get(String(input));assert.ok(path);return fetch(base+path,init);}});await oidc.initialize();
 return {oidc,setSubject(value:string){subject=value;},setMode(value:TokenMode){mode=value;},onExchange(fn:()=>Promise<void>){beforeToken=fn;},bind(url:string,cookie:string){const u=new URL(url);nonce=u.searchParams.get('nonce')!;verifierChallenge=u.searchParams.get('code_challenge')!;attemptId=cookie.split('=')[1]!.split('.')[0]!;},stats:()=>({exchanges,observedCommitted})};
}
export async function broker(t:TestContext,f:ProbeFixture,oidc:OidcClient,authentication:BrokerAuthentication=createAuthenticationClient(f.loginPool)){
 const app=await buildLoginBroker({config:f.config,authentication,oidc,readiness:async()=>{}});return serve(t,app);
}
export async function sessionApp(t:TestContext,f:ProbeFixture){return serve(t,await createSessionApp(f.config,createAuthenticationClient(f.apiPool),async()=>{}));}
export async function serve(t:TestContext,app:FastifyInstance){const url=await app.listen({port:0,host:'127.0.0.1'});t.after(()=>app.close());return {app,url};}
export async function request(url:string,path:string,init:RequestInit={}):Promise<Response>{
 const target=new URL(url+path),base=new URL(url);
 assert.ok(target.protocol==='http:'&&target.hostname==='127.0.0.1'&&target.origin===base.origin&&!target.username&&!target.password&&!target.hash,'Explicit isolated loopback HTTP endpoint required');
 assert.ok(init.body==null||typeof init.body==='string','Qualification request body must be a string');
 const headers=new Headers(init.headers);if(!headers.has('host'))headers.set('host','127.0.0.1:4314');
 // Node fetch does not transmit a caller-supplied Host. Use the native HTTP client
 // to exercise the product's unchanged exact Host admission on ephemeral servers.
 return new Promise<Response>((resolve,reject)=>{
  let timer:ReturnType<typeof setTimeout>|undefined;
  const fail=()=>{if(timer)clearTimeout(timer);reject(Error('Bounded qualification HTTP request failed'));};
  const req=nativeRequest(target,{method:init.method??'GET',headers:Object.fromEntries(headers)},res=>{
   const chunks:Buffer[]=[];let size=0;
   res.on('data',(chunk:Buffer)=>{size+=chunk.length;if(size>1024*1024){req.destroy();res.destroy();fail();}else chunks.push(chunk);});
   res.on('error',fail);res.on('aborted',fail);
   res.on('end',()=>{if(timer)clearTimeout(timer);try{
    const responseHeaders=new Headers();for(let i=0;i<res.rawHeaders.length;i+=2)responseHeaders.append(res.rawHeaders[i]!,res.rawHeaders[i+1]!);
    const body=Buffer.concat(chunks),status=res.statusCode??500;
    resolve(new Response(body.length?new Uint8Array(body):null,{status,headers:responseHeaders}));
   }catch{fail();}});
  });
  timer=setTimeout(()=>{req.destroy();fail();},20_000);req.on('error',fail);
  req.end(init.body??undefined);
 });
}
export const responseCookies=(r:Response)=>r.headers.getSetCookie().filter(c=>!c.includes('Max-Age=0')).map(c=>c.split(';')[0]!).join('; ');
export async function start(url:string,p:Awaited<ReturnType<typeof provider>>){const r=await request(url,'/authn/login');assert.equal(r.status,302);const cookie=responseCookies(r),location=r.headers.get('location')!;p.bind(location,cookie);return {cookie,state:new URL(location).searchParams.get('state')!};}
export async function callback(url:string,a:{cookie:string;state:string}){return request(url,'/authn/callback?'+new URLSearchParams({code:'synthetic-one-use-code',state:a.state}),{headers:{cookie:a.cookie}});}
export async function loggedIn(t:TestContext,f:ProbeFixture){const p=await provider(t,f),b=await broker(t,f,p.oidc),a=await start(b.url,p),r=await callback(b.url,a);assert.equal(r.status,302);const cookie=responseCookies(r);return {p,b,a,cookie,session:cookie.split('; ').find(x=>x.startsWith('gc_authn_session='))!.split('=')[1]!,csrf:cookie.split('; ').find(x=>x.startsWith('gc_authn_csrf='))!.split('=')[1]!};}
export async function activeMember(f:ProbeFixture,active:boolean){await tx(f.owner,async()=>{await query(f.owner,"SELECT set_config('gc.tenant_id',$1,true),set_config('gc.actor_id',$2,true)",[f.tenant,f.identity]);await query(f.owner,'UPDATE memberships SET active=$3 WHERE tenant_id=$1 AND identity_id=$2',[f.tenant,f.identity,active]);});}
