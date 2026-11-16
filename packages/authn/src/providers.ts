// SPDX-License-Identifier: Apache-2.0
import type {BrokerOidcConfig,PublicAuthnConfig} from './contracts.ts';
import {validatePublicAuthnConfig} from './transport.ts';

export type MicrosoftEntraPreset = PublicAuthnConfig & {readonly directoryTenantId:string;readonly clientId:string};
const invalid=():never=>{throw new Error('AUTHN_CONFIGURATION_INVALID');};
const uuid=/^(?!00000000-0000-0000-0000-000000000000$)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** Public-cloud, one-directory preset. No endpoint or cloud aliases are inputs. */
export function microsoftEntraPreset(input:MicrosoftEntraPreset):BrokerOidcConfig {
 if(!input||typeof input!=='object'||Array.isArray(input)
  ||Object.keys(input).some(key=>!['publicOrigin','environment','directoryTenantId','clientId'].includes(key))
  ||typeof input.directoryTenantId!=='string'||!uuid.test(input.directoryTenantId)
  ||typeof input.clientId!=='string'||!uuid.test(input.clientId))return invalid();
 const base=validatePublicAuthnConfig(input),authority=`https://login.microsoftonline.com/${input.directoryTenantId}`;
 return Object.freeze({...base,provider:'microsoft-entra',directoryTenantId:input.directoryTenantId,clientId:input.clientId,
  issuer:`${authority}/v2.0`,authorizationEndpoint:`${authority}/oauth2/v2.0/authorize`,tokenEndpoint:`${authority}/oauth2/v2.0/token`,
  jwksUri:`${authority}/discovery/v2.0/keys`,redirectUri:`${base.publicOrigin}/authn/callback`});
}
