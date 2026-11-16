// SPDX-License-Identifier: Apache-2.0
import type { AuthenticationClient, AuthenticatedSession } from '../../authority/src/authentication.ts';
import type { UUID, Digest, UTC } from '../../authority/src/types.ts';

export type BrokerAuthentication = Pick<AuthenticationClient, 'attemptBegin' | 'attemptConsume' | 'sessionIssue'>;
export type SessionAuthentication = Pick<AuthenticationClient, 'sessionInspect' | 'sessionSelect' | 'sessionRevoke'>;
export type ProtectedSessionResponse = { readonly session: AuthenticatedSession; readonly csrfToken: string };
export type SelectTenantBody = { readonly tenantId: UUID; readonly expectedSessionVersion: number };
export type LogoutBody = { readonly expectedSessionVersion: number };
export type VerifiedIdentityToken = {
 readonly issuer: string; readonly subject: string; readonly audience: string;
 readonly nonceHash: Digest; readonly idTokenHash: Digest;
 readonly authenticatedAt: UTC; readonly tokenIssuedAt: UTC; readonly tokenExpiresAt: UTC;
};
export type AuthnEnvironment = 'isolated-test' | 'local-development' | 'production';
export type PublicAuthnConfig = { readonly publicOrigin: string; readonly environment: AuthnEnvironment };
export type BrokerOidcConfig = PublicAuthnConfig & {
 readonly issuer: string; readonly clientId: string; readonly redirectUri: string;
 readonly authorizationEndpoint: string; readonly tokenEndpoint: string; readonly jwksUri: string;
 /** Exact server-owned endpoint pairs only; never an accepted claim issuer alias. */
 readonly transportAliases?: Readonly<Record<string, string>>;
};
export type AuthnErrorCode = 'AUTHN_REQUEST_INVALID' | 'AUTHN_LOGIN_INVALID' | 'AUTHN_SESSION_REJECTED'
 | 'AUTHN_CSRF_REJECTED' | 'AUTHN_SELECTION_REJECTED' | 'AUTHN_VERSION_CONFLICT'
 | 'AUTHN_RATE_LIMITED' | 'AUTHN_UNAVAILABLE';
export const AUTHN_HTTP_STATUS: Readonly<Record<AuthnErrorCode, number>> = Object.freeze({
 AUTHN_REQUEST_INVALID: 400, AUTHN_LOGIN_INVALID: 401, AUTHN_SESSION_REJECTED: 401,
 AUTHN_CSRF_REJECTED: 403, AUTHN_SELECTION_REJECTED: 403, AUTHN_VERSION_CONFLICT: 409,
 AUTHN_RATE_LIMITED: 429, AUTHN_UNAVAILABLE: 503,
});
export const AUTHN_LIMITS = Object.freeze({
 bodyBytes: 2_048, headerBytes: 16_384, queryBytes: 8_192, codeBytes: 4_096,
 metadataBytes: 32_768, jwksBytes: 131_072, tokenResponseBytes: 65_536,
 compactTokenBytes: 16_384, tokenHeaderBytes: 2_048, tokenPayloadBytes: 8_192,
 jsonDepth: 8, jsonNodes: 2_048, processInflight: 16, poolConnections: 4,
 requestTimeoutMs: 20_000, connectTimeoutMs: 5_000, statementTimeoutMs: 5_000,
 lockTimeoutMs: 2_000, idleTransactionTimeoutMs: 5_000,
 metadataTimeoutMs: 5_000, tokenTimeoutMs: 10_000, jwksCacheMs: 300_000,
 jwksCooldownMs: 30_000, loginRequestsPerMinute: 30,
});
