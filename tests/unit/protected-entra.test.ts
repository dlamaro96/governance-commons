// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,chmod,symlink,mkdir,rm,rename,realpath} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {inspect} from 'node:util';
import {SignJWT,exportJWK,generateKeyPair} from 'jose';
import type {AttemptExchange} from '../../packages/authority/src/authentication.ts';
import type {UTC,UUID} from '../../packages/authority/src/types.ts';
import type {BrokerOidcConfig} from '../../packages/authn/src/contracts.ts';
import {microsoftEntraPreset} from '../../packages/authn/src/providers.ts';
import {loadEntraClientSecret,appendEntraClientSecret,type EntraClientAuthentication} from '../../packages/authn/src/client-secret.ts';
import {loadBrokerOidcEnvironment} from '../../packages/authn/src/configuration.ts';
import {createOidcClient,validateBrokerOidcConfig} from '../../packages/authn/src/oidc.ts';
import {sha256} from '../../packages/authn/src/transport.ts';

const directoryTenantId='11111111-2222-3333-4444-555555555555',clientId='66666666-7777-8888-9999-aaaaaaaaaaaa';
const preset={publicOrigin:'https://governance.example',environment:'production' as const,directoryTenantId,clientId};
const config=microsoftEntraPreset(preset),clock=Date.parse('2026-11-16T12:00:00.000Z'),seconds=clock/1000;
const nonce='n'.repeat(43),state='s'.repeat(43),verifier='v'.repeat(43),secret='synthetic-entra-private~+&=/%';
const env={PUBLIC_AUTHN_ORIGIN:preset.publicOrigin,AUTHN_ENVIRONMENT:preset.environment,OIDC_PROVIDER:'microsoft-entra',OIDC_DIRECTORY_TENANT_ID:directoryTenantId,OIDC_CLIENT_ID:clientId};
const attempt:AttemptExchange={formatVersion:1,attemptId:'10000000-0000-0000-0000-000000000001' as UUID,issuerId:'10000000-0000-0000-0000-000000000002' as UUID,issuer:config.issuer,clientId,redirectUri:config.redirectUri,nonceHash:sha256(nonce),verifier,expiresAt:new Date(clock+300_000).toISOString() as UTC};
const pair=await generateKeyPair('RS256',{modulusLength:2048}),key={...await exportJWK(pair.publicKey),kid:'synthetic-entra-rsa',alg:'RS256',use:'sig'};
const claims=()=>({iss:config.issuer,sub:'exact-pairwise-subject',aud:clientId,tid:directoryTenantId,ver:'2.0',nonce,iat:seconds,exp:seconds+300,auth_time:seconds});
const metadata=()=>({issuer:config.issuer,authorization_endpoint:config.authorizationEndpoint,token_endpoint:config.tokenEndpoint,jwks_uri:config.jwksUri,id_token_signing_alg_values_supported:['RS256'],token_endpoint_auth_methods_supported:['client_secret_post']});
const json=(value:unknown)=>new Response(JSON.stringify(value),{headers:{'content-type':'application/json'}});
const loginRejected=(error:unknown)=>error instanceof Error&&'code'in error&&error.code==='AUTHN_LOGIN_INVALID';
const configurationRejected=(error:unknown)=>error instanceof Error&&error.message==='AUTHN_CONFIGURATION_INVALID'&&!inspect(error).includes(secret);
async function privateFile(t:{after:(fn:()=>Promise<void>)=>void},contents:string|Uint8Array=secret){
 const dir=await realpath(await mkdtemp(join(tmpdir(),'gc-entra-unit-')));t.after(()=>rm(dir,{recursive:true,force:true}));
 const path=join(dir,'client-secret');await writeFile(path,contents,{mode:0o600});return {dir,path};
}
async function signed(changes:Record<string,unknown>={}){return new SignJWT({...claims(),...changes}).setProtectedHeader({alg:'RS256',kid:key.kid}).sign(pair.privateKey);}
function fixture(authentication:EntraClientAuthentication,token:string,override?:{metadata?:unknown;tokenResponse?:Response}){
 const requests:{url:string;init:RequestInit}[]=[];
 const client=createOidcClient(config,{clientAuthentication:authentication,now:()=>clock,fetch:(async(input,init={})=>{
  const url=String(input);requests.push({url,init});
  if(url===config.issuer+'/.well-known/openid-configuration')return json(override?.metadata??metadata());
  if(url===config.jwksUri)return json({keys:[key]});
  if(url===config.tokenEndpoint)return override?.tokenResponse??json({id_token:token,access_token:'discarded-access',refresh_token:'discarded-refresh'});
  throw new Error('Unexpected fixture destination');
 }) as typeof fetch});return {client,requests};
}

test('Entra preset derives one exact public-cloud directory and retains its discriminator through validation',()=>{
 const expected={...preset,provider:'microsoft-entra',issuer:`https://login.microsoftonline.com/${directoryTenantId}/v2.0`,authorizationEndpoint:`https://login.microsoftonline.com/${directoryTenantId}/oauth2/v2.0/authorize`,tokenEndpoint:`https://login.microsoftonline.com/${directoryTenantId}/oauth2/v2.0/token`,jwksUri:`https://login.microsoftonline.com/${directoryTenantId}/discovery/v2.0/keys`,redirectUri:'https://governance.example/authn/callback'};
 assert.deepEqual(config,expected);assert.deepEqual(validateBrokerOidcConfig(config),expected);assert.ok(Object.isFrozen(config));
 const local=microsoftEntraPreset({...preset,environment:'local-development',publicOrigin:'http://localhost:4314'});
 assert.equal(local.redirectUri,'http://localhost:4314/authn/callback');assert.equal(local.tokenEndpoint,config.tokenEndpoint);
});

test('Entra preset rejects nil, noncanonical, common, organizations, consumers, domains and endpoint overrides',()=>{
 for(const bad of ['00000000-0000-0000-0000-000000000000',clientId.toUpperCase(),'common','organizations','consumers','contoso.onmicrosoft.com','../common',directoryTenantId+' ']){
  assert.throws(()=>microsoftEntraPreset({...preset,directoryTenantId:bad}),configurationRejected);
  assert.throws(()=>microsoftEntraPreset({...preset,clientId:bad}),configurationRejected);
 }
 assert.throws(()=>microsoftEntraPreset({...preset,issuer:config.issuer} as typeof preset),configurationRejected);
 for(const name of ['issuer','authorizationEndpoint','tokenEndpoint','jwksUri','redirectUri'])assert.throws(()=>validateBrokerOidcConfig({...config,[name]:'https://attacker.example/path'}),configurationRejected);
 for(const extra of [{provider:'unknown'},{provider:'keycloak'},{provider:undefined},{transportAliases:{}},{clientSecret:secret}])assert.throws(()=>validateBrokerOidcConfig({...config,...extra} as BrokerOidcConfig),configurationRejected);
 assert.throws(()=>validateBrokerOidcConfig(microsoftEntraPreset({...preset,publicOrigin:'https://invalid_host.example'})),configurationRejected);
});

test('Entra startup uses only the closed preset environment and loads an opaque file capability',async t=>{
 const {path}=await privateFile(t),loaded=await loadBrokerOidcEnvironment({...env,OIDC_CLIENT_SECRET_FILE:path});
 assert.deepEqual(loaded.config,config);assert.ok(loaded.clientAuthentication);
 assert.deepEqual(Object.keys(loaded.clientAuthentication),[]);assert.deepEqual(Reflect.ownKeys(loaded.clientAuthentication),[]);
 assert.equal(JSON.stringify(loaded.clientAuthentication),'{}');assert.ok(Object.isFrozen(loaded.clientAuthentication));
 assert.ok(!JSON.stringify(loaded).includes(secret));assert.ok(!inspect(loaded).includes(secret));assert.ok(!inspect(loaded).includes(path));
});

test('Entra startup refuses mixed endpoint aliases and raw-secret environment variables before any secret read',async()=>{
 for(const name of ['OIDC_ISSUER','OIDC_AUTHORIZATION_ENDPOINT','OIDC_TOKEN_ENDPOINT','OIDC_JWKS_URI','OIDC_REDIRECT_URI','OIDC_TRANSPORT_ALIASES_JSON','OIDC_CLIENT_SECRET','AUTHN_CLIENT_SECRET','ENTRA_CLIENT_SECRET','AZURE_CLIENT_SECRET']){
  await assert.rejects(loadBrokerOidcEnvironment({...env,OIDC_CLIENT_SECRET_FILE:'/absent/synthetic-secret',[name]:name.includes('SECRET')?secret:''}),configurationRejected);
 }
 await assert.rejects(loadBrokerOidcEnvironment({...env,OIDC_PROVIDER:'unknown'}),configurationRejected);
 await assert.rejects(loadBrokerOidcEnvironment({...env,OIDC_PROVIDER:'keycloak'}),configurationRejected);
 await assert.rejects(loadBrokerOidcEnvironment(env),configurationRejected);
});

test('Entra secret file admits exact owner-only bytes and snapshots rotation until the next startup',async t=>{
 const {path,dir}=await privateFile(t),old=await loadEntraClientSecret(path);
 await chmod(path,0o400);assert.ok(await loadEntraClientSecret(path));
 const next=join(dir,'replacement');await writeFile(next,'synthetic-rotated-secret',{mode:0o600});await rename(next,path);
 const current=await loadEntraClientSecret(path),a=new URLSearchParams(),b=new URLSearchParams();
 appendEntraClientSecret(old,a);appendEntraClientSecret(current,b);
 assert.equal(a.get('client_secret'),secret);assert.equal(b.get('client_secret'),'synthetic-rotated-secret');
 assert.throws(()=>appendEntraClientSecret(old,a),configurationRejected);
});

test('Entra secret file rejects missing, symlinked, parent-symlinked, FIFO, directory and insecure files safely',async t=>{
 const {path,dir}=await privateFile(t);
 for(const mode of [0o644,0o640,0o700,0o660,0o4600]){await chmod(path,mode);await assert.rejects(loadEntraClientSecret(path),configurationRejected);}await chmod(path,0o600);
 const link=join(dir,'link');await symlink(path,link);await assert.rejects(loadEntraClientSecret(link),configurationRejected);
 const directoryLink=join(dir,'directory-link');await symlink(dir,directoryLink);await assert.rejects(loadEntraClientSecret(join(directoryLink,'client-secret')),configurationRejected);
 const folder=join(dir,'folder');await mkdir(folder);await assert.rejects(loadEntraClientSecret(folder),configurationRejected);
 const fifo=join(dir,'fifo');execFileSync('mkfifo',[fifo]);await chmod(fifo,0o600);const start=Date.now();await assert.rejects(loadEntraClientSecret(fifo),configurationRejected);assert.ok(Date.now()-start<1000);
 for(const bad of [join(dir,'missing'),'relative-secret',path+'\0'])await assert.rejects(loadEntraClientSecret(bad),configurationRejected);
});

test('Entra secret bounds reject empty, oversized, control, whitespace and invalid UTF8 without trimming',async t=>{
 const {path}=await privateFile(t);
 for(const value of ['',secret+'\n',' '+secret,secret+'\r',secret+'\0','x'.repeat(4097),Buffer.from([0xc3,0x28]),'é']){
  await writeFile(path,value);await assert.rejects(loadEntraClientSecret(path),configurationRejected);
 }
 await writeFile(path,'x'.repeat(4096));assert.ok(await loadEntraClientSecret(path));
});

test('Entra requires a real private capability and Keycloak never accepts confidential credentials',async t=>{
 assert.throws(()=>createOidcClient(config),configurationRejected);
 assert.throws(()=>createOidcClient(config,{clientAuthentication:{} as EntraClientAuthentication}),configurationRejected);
 const {path}=await privateFile(t),authentication=await loadEntraClientSecret(path);
 const keycloak:BrokerOidcConfig={publicOrigin:'http://localhost:4314',environment:'isolated-test',issuer:'http://localhost:4315/realms/governance',clientId:'public-keycloak',redirectUri:'http://localhost:4314/authn/callback',authorizationEndpoint:'http://localhost:4315/realms/governance/auth',tokenEndpoint:'http://localhost:4315/realms/governance/token',jwksUri:'http://localhost:4315/realms/governance/keys'};
 assert.throws(()=>createOidcClient(keycloak,{clientAuthentication:authentication}),configurationRejected);
 assert.throws(()=>validateBrokerOidcConfig({...keycloak,directoryTenantId}),configurationRejected);
 const loaded=await loadBrokerOidcEnvironment({PUBLIC_AUTHN_ORIGIN:keycloak.publicOrigin,AUTHN_ENVIRONMENT:keycloak.environment,OIDC_ISSUER:keycloak.issuer,OIDC_CLIENT_ID:keycloak.clientId,OIDC_REDIRECT_URI:keycloak.redirectUri,OIDC_AUTHORIZATION_ENDPOINT:keycloak.authorizationEndpoint,OIDC_TOKEN_ENDPOINT:keycloak.tokenEndpoint,OIDC_JWKS_URI:keycloak.jwksUri});
 assert.equal(loaded.clientAuthentication,undefined);assert.equal(loaded.config.provider,undefined);
});

test('Entra verifies an actual RS256 ID token and sends confidential authentication only to the fixed token endpoint',async t=>{
 const {path}=await privateFile(t),authentication=await loadEntraClientSecret(path),token=await signed(),{client,requests}=fixture(authentication,token);
 await client.initialize();const result=await client.exchangeAndVerify(attempt,'synthetic-code');
 assert.equal(result.subject,'exact-pairwise-subject');assert.equal(result.issuer,config.issuer);assert.equal(result.idTokenHash,sha256(token));
 assert.deepEqual(Object.keys(result).sort(),['issuer','subject','audience','nonceHash','idTokenHash','authenticatedAt','tokenIssuedAt','tokenExpiresAt'].sort());
 const auth=new URL(client.authorizationUrl({state,nonce,verifier}));assert.equal(auth.origin,'https://login.microsoftonline.com');assert.equal(auth.searchParams.get('client_secret'),null);assert.equal(auth.searchParams.get('scope'),'openid');assert.equal(auth.searchParams.get('code_challenge_method'),'S256');
 assert.equal(requests.length,3);const sent=requests.find(x=>x.url===config.tokenEndpoint)!;
 assert.deepEqual(Object.fromEntries(new URLSearchParams(String(sent.init.body))),{grant_type:'authorization_code',code:'synthetic-code',client_id:clientId,redirect_uri:config.redirectUri,code_verifier:verifier,client_secret:secret});
 for(const request of requests){assert.equal(request.init.redirect,'manual');assert.equal(request.init.credentials,'omit');assert.equal(new Headers(request.init.headers).has('authorization'),false);if(request.url!==config.tokenEndpoint)assert.equal(request.init.body,undefined);assert.ok(!request.url.includes(secret));}
 assert.ok(!JSON.stringify(result).includes(secret));
});

test('Entra refuses signed wrong or missing tid/ver and does not map email or oid instead of sub',async t=>{
 const {path}=await privateFile(t),authentication=await loadEntraClientSecret(path);
 for(const change of [{tid:clientId},{tid:undefined},{tid:directoryTenantId.toUpperCase()+'x'},{tid:[directoryTenantId]},{ver:undefined},{ver:'1.0'},{ver:2},{sub:undefined,oid:'canonical-looking-oid',email:'member@example.invalid'}]){
  const {client}=fixture(authentication,await signed(change));await client.initialize();await assert.rejects(client.exchangeAndVerify(attempt,'code'),loginRejected);
 }
 const {client}=fixture(authentication,await signed({oid:'ignored-object-id',email:'ignored@example.invalid',tenantId:clientId}));await client.initialize();assert.equal((await client.exchangeAndVerify(attempt,'code')).subject,'exact-pairwise-subject');
});

test('Entra still refuses signed issuer, audience, nonce and auth_time violations',async t=>{
 const {path}=await privateFile(t),authentication=await loadEntraClientSecret(path);
 for(const change of [{iss:`https://login.microsoftonline.com/${clientId}/v2.0`},{aud:directoryTenantId},{nonce:'x'.repeat(43)},{auth_time:undefined},{auth_time:seconds-31},{exp:seconds}]){
  const {client}=fixture(authentication,await signed(change));await client.initialize();await assert.rejects(client.exchangeAndVerify(attempt,'code'),loginRejected);
 }
});

test('Entra discovery cannot redirect credentials or change required client authentication',async t=>{
 const {path}=await privateFile(t),authentication=await loadEntraClientSecret(path),token=await signed();
 for(const change of [{issuer:config.issuer.replace(directoryTenantId,'common')},{token_endpoint:'https://attacker.example/token'},{jwks_uri:'https://login.microsoftonline.com/common/discovery/v2.0/keys'},{token_endpoint_auth_methods_supported:undefined},{token_endpoint_auth_methods_supported:['none']}]){
  const {client,requests}=fixture(authentication,token,{metadata:{...metadata(),...change}});await assert.rejects(client.initialize(),loginRejected);assert.equal(requests.length,1);assert.equal(requests[0]!.init.body,undefined);
 }
});

test('Entra token redirects and provider error bodies remain generic failures without secret leakage',async t=>{
 const {path}=await privateFile(t),authentication=await loadEntraClientSecret(path);
 for(const response of [new Response(secret,{status:302,headers:{location:'https://attacker.example/token','content-type':'application/json'}}),json({error_description:secret,error:'invalid_client'})]){
  const {client,requests}=fixture(authentication,await signed(),{tokenResponse:response});await client.initialize();
  await assert.rejects(client.exchangeAndVerify(attempt,'code'),error=>loginRejected(error)&&!inspect(error).includes(secret));assert.equal(requests.length,3);
 }
});
