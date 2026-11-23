// SPDX-License-Identifier: Apache-2.0
import {
 AUTHENTICATION_SCALARS as scalar, AuthenticationError, authenticationObject,
 parseAuthenticatedSession, safeAuthenticationError,
 type AuthenticatedSession, type AuthenticationConnection, type AuthenticationQuery,
} from '../../authority/src/authentication.ts';
import type {Digest} from '../../authority/src/types.ts';

export type ApplicationSessionRequest = Readonly<{sessionHash:Digest;csrfHash:Digest|null}>;
/** Only hashes are accepted. Identity, tenant, role and content authority are
 * never request parameters. The caller owns the bounded RR read-only snapshot. */
export function applicationSessionQuery(input:ApplicationSessionRequest):AuthenticationQuery {
 const value=authenticationObject(input,['sessionHash','csrfHash']);
 const sessionHash=scalar.digest(value.sessionHash),csrfHash=value.csrfHash===null?null:scalar.digest(value.csrfHash);
 return Object.freeze({text:`SELECT f.format_version,f.session_id,f.session_version,f.identity_id,
 f.selected_tenant_id,f.issuer_id,f.identity_binding_id,
 pg_catalog.to_char(f.authenticated_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS authenticated_at,
 pg_catalog.to_char(f.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS expires_at,
 f.generation,f.tenant_fence_epoch,f.authority_mode,f.content_authority
 FROM public.gc_app_protected_session_v1($1::text,$2::text) AS f`,values:Object.freeze([sessionHash,csrfHash])});
}

/** Uses the original native gc_app connection; never an owner/authn executor
 * pool. It neither starts/commits a transaction nor grants content permission. */
export async function readApplicationSession(connection:Pick<AuthenticationConnection,'query'>,input:ApplicationSessionRequest):Promise<AuthenticatedSession> {
 try {
  const statement=applicationSessionQuery(input);
  const result=await connection.query(statement.text,[...statement.values]);
  if(!Array.isArray(result.rows)||result.rows.length!==1)throw new AuthenticationError('AUTHN_RESPONSE_INVALID');
  const parsed=parseAuthenticatedSession(result.rows[0]);
  if(!parsed.ok)throw new AuthenticationError('AUTHN_RESPONSE_INVALID');
  return parsed.value;
 } catch(error) {throw safeAuthenticationError(error);}
}
