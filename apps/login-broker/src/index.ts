// SPDX-License-Identifier: Apache-2.0
import {createAuthenticationClient} from '../../../packages/authority/src/authentication.ts';
import type {AuthnEnvironment,BrokerOidcConfig} from '../../../packages/authn/src/contracts.ts';
import {createOidcClient,validateBrokerOidcConfig} from '../../../packages/authn/src/oidc.ts';
import {createNativeAuthenticationPool,verifyNativeAuthenticationPool} from '../../../packages/authn/src/pool.ts';
import {strictJson} from '../../../packages/authn/src/transport.ts';
import {buildLoginBroker} from './app.ts';

function required(name:string):string{const value=process.env[name];if(!value)throw new Error('AUTHN_CONFIGURATION_INVALID');return value;}
async function main():Promise<void>{
 // Dedicated process boundary: neither a legacy content credential nor a second executor is accepted.
 for(const name of ['DATABASE_URL','AUTHN_API_DATABASE_URL','MIGRATION_DATABASE_URL','DATABASE_OWNER_URL','OWNER_DATABASE_URL','OIDC_CLIENT_SECRET'])if(process.env[name])throw new Error('AUTHN_CONFIGURATION_INVALID');
 const aliases=process.env.OIDC_TRANSPORT_ALIASES_JSON;
 const config=validateBrokerOidcConfig({publicOrigin:required('PUBLIC_AUTHN_ORIGIN'),environment:required('AUTHN_ENVIRONMENT') as AuthnEnvironment,
  issuer:required('OIDC_ISSUER'),clientId:required('OIDC_CLIENT_ID'),redirectUri:required('OIDC_REDIRECT_URI'),authorizationEndpoint:required('OIDC_AUTHORIZATION_ENDPOINT'),tokenEndpoint:required('OIDC_TOKEN_ENDPOINT'),jwksUri:required('OIDC_JWKS_URI'),
  ...(aliases?{transportAliases:strictJson(aliases,8192) as BrokerOidcConfig['transportAliases']}:{})});
 const pool=createNativeAuthenticationPool('login',required('AUTHN_LOGIN_DATABASE_URL'),config.environment);
 try{
  await verifyNativeAuthenticationPool(pool,'login');
  const oidc=createOidcClient(config);await oidc.initialize();
  const app=await buildLoginBroker({config,authentication:createAuthenticationClient(pool),oidc,readiness:()=>verifyNativeAuthenticationPool(pool,'login')});
  app.addHook('onClose',async()=>{await pool.end();});
  const port=Number(process.env.PORT??4312),host=process.env.HOST??'0.0.0.0';
  if(!Number.isSafeInteger(port)||port<1||port>65535||!['0.0.0.0','127.0.0.1','::1'].includes(host))throw new Error('AUTHN_CONFIGURATION_INVALID');
  await app.listen({port,host});
  for(const signal of ['SIGTERM','SIGINT'] as const)process.once(signal,()=>{void app.close().catch(()=>{process.exitCode=1;});});
 }catch{await pool.end();throw new Error('AUTHN_STARTUP_FAILED');}
}
main().catch(()=>{process.stderr.write('{"code":"AUTHN_STARTUP_FAILED"}\n');process.exitCode=1;});
