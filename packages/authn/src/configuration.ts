// SPDX-License-Identifier: Apache-2.0
import type {AuthnEnvironment,BrokerOidcConfig} from './contracts.ts';
import {validateBrokerOidcConfig} from './oidc.ts';
import {microsoftEntraPreset} from './providers.ts';
import {loadEntraClientSecret,type EntraClientAuthentication} from './client-secret.ts';
import {strictJson} from './transport.ts';
const invalid=():never=>{throw new Error('AUTHN_CONFIGURATION_INVALID');};
/** Deployment-only startup reader; no request/header or directory claim input. */
export async function loadBrokerOidcEnvironment(env:Readonly<Record<string,string|undefined>>):Promise<{config:BrokerOidcConfig;clientAuthentication?:EntraClientAuthentication}> {
 const required=(name:string):string=>{const value=env[name];return value?value:invalid();};
 for(const name of ['OIDC_CLIENT_SECRET','AUTHN_CLIENT_SECRET','ENTRA_CLIENT_SECRET','AZURE_CLIENT_SECRET'])if(env[name]!==undefined)return invalid();
 const postLoginPath=env.AUTHN_POST_LOGIN_PATH;
 if(postLoginPath!==undefined&&postLoginPath!=='/'&&postLoginPath!=='/authn/')return invalid();
 const postLogin:Pick<BrokerOidcConfig,'postLoginPath'>=postLoginPath===undefined?{}:{postLoginPath};
 const base={publicOrigin:required('PUBLIC_AUTHN_ORIGIN'),environment:required('AUTHN_ENVIRONMENT') as AuthnEnvironment};
 if(env.OIDC_PROVIDER==='microsoft-entra'){
  for(const name of ['OIDC_ISSUER','OIDC_AUTHORIZATION_ENDPOINT','OIDC_TOKEN_ENDPOINT','OIDC_JWKS_URI','OIDC_REDIRECT_URI','OIDC_TRANSPORT_ALIASES_JSON'])if(env[name]!==undefined)return invalid();
  const config=validateBrokerOidcConfig({...microsoftEntraPreset({...base,directoryTenantId:required('OIDC_DIRECTORY_TENANT_ID'),clientId:required('OIDC_CLIENT_ID')}),...postLogin});
  return {config,clientAuthentication:await loadEntraClientSecret(required('OIDC_CLIENT_SECRET_FILE'))};
 }
 if(env.OIDC_PROVIDER!==undefined&&env.OIDC_PROVIDER!=='keycloak')return invalid();
 for(const name of ['OIDC_DIRECTORY_TENANT_ID','OIDC_CLIENT_SECRET_FILE'])if(env[name]!==undefined)return invalid();
 const aliases=env.OIDC_TRANSPORT_ALIASES_JSON;
 return {config:validateBrokerOidcConfig({...base,...postLogin,...(env.OIDC_PROVIDER===undefined?{}:{provider:'keycloak' as const}),
  issuer:required('OIDC_ISSUER'),clientId:required('OIDC_CLIENT_ID'),redirectUri:required('OIDC_REDIRECT_URI'),
  authorizationEndpoint:required('OIDC_AUTHORIZATION_ENDPOINT'),tokenEndpoint:required('OIDC_TOKEN_ENDPOINT'),jwksUri:required('OIDC_JWKS_URI'),
  ...(aliases?{transportAliases:strictJson(aliases,8192) as BrokerOidcConfig['transportAliases']}:{})})};
}
