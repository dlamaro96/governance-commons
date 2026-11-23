// SPDX-License-Identifier: Apache-2.0
import type { FastifyInstance } from 'fastify';
import { AUTHENTICATION_SCALARS as scalar, authenticationObject } from '../../../packages/authority/src/authentication.ts';
import type { PublicAuthnConfig, SessionAuthentication, ProtectedSessionResponse } from '../../../packages/authn/src/contracts.ts';
import { AuthnHttpError, createAuthnApp, noQuery, cookies, requireMutation, sha256, randomSecret,
 clearAuthnCookies, setAuthnCookie, mapAuthenticationError, sendAuthnError, requestAbortSignal, markLogoutAdmitted } from '../../../packages/authn/src/transport.ts';
import { PAGE, SCRIPT, STYLE } from './ui.ts';
export async function createSessionApp(config: PublicAuthnConfig, authentication: SessionAuthentication,
 readiness: () => Promise<void>): Promise<FastifyInstance> {
 const app = await createAuthnApp(config);
 app.get('/health/ready', async (request, reply) => {
  noQuery(request);
  try { await readiness(); if (requestAbortSignal(request).aborted) return reply; return { ready: true }; }
  catch { return sendAuthnError(reply, 'AUTHN_UNAVAILABLE'); }
 });
 app.get('/authn/', async (request, reply) => { noQuery(request); return reply.type('text/html; charset=utf-8').send(PAGE); });
 app.get('/authn/ui.js', async (request, reply) => { noQuery(request); return reply.type('application/javascript; charset=utf-8').send(SCRIPT); });
 app.get('/authn/ui.css', async (request, reply) => { noQuery(request); return reply.type('text/css; charset=utf-8').send(STYLE); });
 app.get('/authn/session', async (request, reply) => {
  noQuery(request);
  const jar = cookies(request, config);
  if (!jar.session || !jar.csrf) return sendAuthnError(reply, 'AUTHN_SESSION_REJECTED');
  try {
   const session = await authentication.sessionInspect({ sessionHash: sha256(jar.session) });
   if (requestAbortSignal(request).aborted) return reply;
   const result: ProtectedSessionResponse = { session, csrfToken: jar.csrf };
   return result;
  } catch (error) { return sendAuthnError(reply, mapAuthenticationError(error, 'session')); }
 });
 app.post('/authn/tenant', async (request, reply) => {
  const jar = requireMutation(request, config);
  let tenantId, expectedSessionVersion;
  try { const body = authenticationObject(request.body, ['tenantId', 'expectedSessionVersion']); tenantId = scalar.uuid(body.tenantId); expectedSessionVersion = scalar.integer(body.expectedSessionVersion); }
  catch { throw new AuthnHttpError('AUTHN_REQUEST_INVALID'); }
  const replacement = randomSecret();
  try {
   // This existing-session read supplies the immutable expiry for the replacement
   // CSRF cookie. Select still rechecks current canonical state and exact version.
   const current = await authentication.sessionInspect({ sessionHash: sha256(jar.session) });
   if (requestAbortSignal(request).aborted) return reply;
   const selected = await authentication.sessionSelect({ sessionHash: sha256(jar.session), csrfHash: sha256(jar.csrf),
    tenantId, expectedSessionVersion, replacementCsrfHash: sha256(replacement) });
   if (requestAbortSignal(request).aborted) return reply;
   if (selected.sessionId !== current.sessionId) throw new AuthnHttpError('AUTHN_UNAVAILABLE');
   // Move an existing local /authn session cookie to the application path only
   // after confirmed selection; retain the exact token and original expiry.
   setAuthnCookie(reply, config, 'session', jar.session, current.expiresAt);
   setAuthnCookie(reply, config, 'csrf', replacement, current.expiresAt);
   return { session: selected };
  } catch (error) { return sendAuthnError(reply, mapAuthenticationError(error, 'selection')); }
 });
 app.post('/authn/logout', async (request, reply) => {
  const jar = requireMutation(request, config);
  let expectedSessionVersion;
  try { const body = authenticationObject(request.body, ['expectedSessionVersion']); expectedSessionVersion = scalar.integer(body.expectedSessionVersion); }
  catch { throw new AuthnHttpError('AUTHN_REQUEST_INVALID'); }
  // Admission is complete. Clear browser credentials even when the native revoke
  // fails or COMMIT is uncertain; this never asserts a successful server revoke.
  markLogoutAdmitted(request);
  clearAuthnCookies(reply, config, ['session', 'csrf', 'attempt']);
  try {
   const revoked = await authentication.sessionRevoke({ sessionHash: sha256(jar.session), csrfHash: sha256(jar.csrf), expectedSessionVersion });
   if (requestAbortSignal(request).aborted) return reply;
   if (revoked.loggedOut !== true) throw new AuthnHttpError('AUTHN_UNAVAILABLE');
   return { loggedOut: true, serverRevocationConfirmed: true, browserCredentialsCleared: true };
  } catch (error) { return sendAuthnError(reply, mapAuthenticationError(error, 'session'), { browserCredentialsCleared: true, serverRevocationConfirmed: false }); }
 });
 return app;
}
