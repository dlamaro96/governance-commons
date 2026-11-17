// SPDX-License-Identifier: Apache-2.0
import Fastify, { type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { createServer } from 'node:http';
import rateLimit from '@fastify/rate-limit';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { parseAuthorityInputFile } from '../../authority/src/admission.ts';
import { safeAuthenticationError } from '../../authority/src/authentication.ts';
import type { Digest } from '../../authority/src/types.ts';
import { AUTHN_HTTP_STATUS, AUTHN_LIMITS, type AuthnErrorCode, type PublicAuthnConfig } from './contracts.ts';

export type CookieKind = 'session' | 'csrf' | 'attempt';
export class AuthnHttpError extends Error {
 constructor(readonly code: AuthnErrorCode) { super(code); this.name = 'AuthnHttpError'; }
}
const invalid = (): never => { throw new AuthnHttpError('AUTHN_REQUEST_INVALID'); };
const secretPattern = /^[A-Za-z0-9_-]{43}$/;
const attemptPattern = /^(?!00000000-0000-0000-0000-000000000000\.)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[A-Za-z0-9_-]{43}$/;
export function validatePublicAuthnConfig(config: PublicAuthnConfig): PublicAuthnConfig {
 try {
  if (!config || !['isolated-test', 'local-development', 'production'].includes(config.environment)
    || typeof config.publicOrigin !== 'string' || config.publicOrigin.length > 2048
    || !/^[\x21-\x7e]+$/.test(config.publicOrigin) || config.publicOrigin.includes('\\')) invalid();
  const url = new URL(config.publicOrigin);
  if (url.origin !== config.publicOrigin || url.username || url.password || url.pathname !== '/' || url.search || url.hash) invalid();
  if (config.environment === 'production' ? url.protocol !== 'https:'
    : url.protocol !== 'http:' || !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) invalid();
  return Object.freeze({ publicOrigin: config.publicOrigin, environment: config.environment });
 } catch { throw new AuthnHttpError('AUTHN_UNAVAILABLE'); }
}
/** Reuses the duplicate-aware syntax parser, with a strictly smaller transport profile. */
export function strictJson(input: Uint8Array | string, maxBytes: number): unknown {
 if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > AUTHN_LIMITS.jwksBytes) invalid();
 try {
  if ((typeof input === 'string' ? Buffer.byteLength(input, 'utf8') : input.byteLength) > maxBytes) invalid();
  const text = typeof input === 'string' ? input : new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(input);
  const parsed = parseAuthorityInputFile(text);
  if (!parsed.ok) return invalid();
  if (parsed.value.metrics.depth > AUTHN_LIMITS.jsonDepth || parsed.value.metrics.nodes > AUTHN_LIMITS.jsonNodes) return invalid();
  return parsed.value.data;
 } catch { return invalid(); }
}
export function strictQuery(rawUrl: string): Readonly<Record<string, string>> {
 if (typeof rawUrl !== 'string' || !rawUrl.startsWith('/') || rawUrl.startsWith('//') || rawUrl.includes('#')) invalid();
 const at = rawUrl.indexOf('?');
 if (at < 0) return Object.freeze({});
 const query = rawUrl.slice(at + 1);
 if (!query || Buffer.byteLength(query, 'utf8') > AUTHN_LIMITS.queryBytes || /[^\x21-\x7e]/.test(query)) invalid();
 const values = new Map<string, string>();
 try {
  for (const item of query.split('&')) {
   if (!item || !item.includes('=')) invalid();
   const split = item.indexOf('=');
   const key = decodeURIComponent(item.slice(0, split).replaceAll('+', ' '));
   const value = decodeURIComponent(item.slice(split + 1).replaceAll('+', ' '));
   if (!key || values.has(key) || /[\u0000-\u001f\u007f-\u009f]/.test(key + value)) invalid();
   values.set(key, value);
  }
 } catch { return invalid(); }
 return Object.freeze(Object.fromEntries(values));
}
export function noQuery(request: FastifyRequest): void { if (request.raw.url?.includes('?')) invalid(); }
export function header(request: FastifyRequest, name: string): string | undefined {
 const found: string[] = [];
 for (let index = 0; index < request.raw.rawHeaders.length; index += 2) {
  if (request.raw.rawHeaders[index]!.toLowerCase() === name.toLowerCase()) found.push(request.raw.rawHeaders[index + 1]!);
 }
 if (found.length > 1) invalid();
 return found[0];
}
export function cookieNames(config: PublicAuthnConfig): Readonly<Record<CookieKind, string>> {
 const admitted = validatePublicAuthnConfig(config);
 const prefix = admitted.environment === 'production' ? '__Host-gc_authn_' : 'gc_authn_';
 return Object.freeze({ session: prefix + 'session', csrf: prefix + 'csrf', attempt: prefix + 'attempt' });
}
export function cookies(request: FastifyRequest, config: PublicAuthnConfig): Readonly<Partial<Record<CookieKind, string>>> {
 const names = cookieNames(config), raw = header(request, 'cookie');
 const result: Partial<Record<CookieKind, string>> = {};
 if (raw === undefined) return Object.freeze(result);
 for (const item of raw.split(';')) {
  const part = item.trim(), at = part.indexOf('=');
  if (!part || at < 1) invalid();
  const name = part.slice(0, at), value = part.slice(at + 1);
  if (/^(?:__Host-)?gc_authn_(session|csrf|attempt)$/.test(name)) {
   const kind = (Object.keys(names) as CookieKind[]).find(key => names[key] === name);
   if (!kind) return invalid();
   if (Object.hasOwn(result, kind) || !(kind === 'attempt' ? attemptPattern : secretPattern).test(value)) return invalid();
   result[kind] = value;
  }
 }
 return Object.freeze(result);
}
function appendCookie(reply: FastifyReply, value: string): void {
 // Fastify appends Set-Cookie itself; supplying earlier values would duplicate them.
 reply.header('set-cookie', value);
}
function cookieBase(config: PublicAuthnConfig, kind: CookieKind, value: string): string {
 const names = cookieNames(config);
 return `${names[kind]}=${value}; Path=${config.environment === 'production' ? '/' : '/authn'}; HttpOnly; SameSite=Lax${config.environment === 'production' ? '; Secure' : ''}`;
}
export function setAuthnCookie(reply: FastifyReply, config: PublicAuthnConfig, kind: CookieKind, value: string, expiresAt: string): void {
 if (reply.sent || requestAbortSignal(reply.request).aborted) throw new AuthnHttpError('AUTHN_UNAVAILABLE');
 if (!(kind === 'attempt' ? attemptPattern : secretPattern).test(value)) throw new AuthnHttpError('AUTHN_UNAVAILABLE');
 const expiry = Date.parse(expiresAt), remaining = Math.floor((expiry - Date.now()) / 1000);
 if (!Number.isFinite(expiry) || remaining < 1 || remaining > (kind === 'attempt' ? 300 : 1800)) throw new AuthnHttpError('AUTHN_UNAVAILABLE');
 appendCookie(reply, `${cookieBase(config, kind, value)}; Max-Age=${remaining}; Expires=${new Date(expiry).toUTCString()}`);
}
export function clearAuthnCookies(reply: FastifyReply, config: PublicAuthnConfig, kinds: readonly CookieKind[]): void {
 for (const kind of kinds) appendCookie(reply, `${cookieBase(config, kind, '')}; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`);
}
export const randomSecret = (): string => randomBytes(32).toString('base64url');
export const sha256 = (value: string): Digest => createHash('sha256').update(value, 'utf8').digest('hex') as Digest;
export function equalSecret(left: string, right: string): boolean {
 const a = Buffer.from(left, 'utf8'), b = Buffer.from(right, 'utf8');
 return a.length === b.length && timingSafeEqual(a, b);
}
export function requireMutation(request: FastifyRequest, config: PublicAuthnConfig): { session: string; csrf: string } {
 noQuery(request);
 if (header(request, 'origin') !== config.publicOrigin) throw new AuthnHttpError('AUTHN_CSRF_REJECTED');
 if (!/^application\/json(?:;\s*charset=utf-8)?$/i.test(header(request, 'content-type') ?? '')) invalid();
 const jar = cookies(request, config), csrf = header(request, 'x-csrf-token');
 if (!jar.csrf || !csrf || !secretPattern.test(csrf) || !equalSecret(jar.csrf, csrf)) throw new AuthnHttpError('AUTHN_CSRF_REJECTED');
 if (!jar.session) throw new AuthnHttpError('AUTHN_SESSION_REJECTED');
 return { session: jar.session, csrf: jar.csrf };
}
export function mapAuthenticationError(error: unknown, context: 'login' | 'session' | 'selection'): AuthnErrorCode {
 if (error instanceof AuthnHttpError) return error.code;
 const code = safeAuthenticationError(error).code;
 if (code === 'AUTHN_VERSION_CONFLICT') return 'AUTHN_VERSION_CONFLICT';
 if (code === 'AUTHN_REJECTED') return context === 'login' ? 'AUTHN_LOGIN_INVALID' : context === 'selection' ? 'AUTHN_SELECTION_REJECTED' : 'AUTHN_SESSION_REJECTED';
 if (code === 'AUTHN_INPUT_INVALID') return 'AUTHN_REQUEST_INVALID';
 return 'AUTHN_UNAVAILABLE';
}
export function sendAuthnError(reply: FastifyReply, code: AuthnErrorCode,
 logout?: { browserCredentialsCleared: true; serverRevocationConfirmed: false }): FastifyReply {
 if (reply.sent) return reply;
 return reply.code(AUTHN_HTTP_STATUS[code]).type('application/problem+json').send({
  type: 'about:blank', title: code, status: AUTHN_HTTP_STATUS[code], code, correlationId: reply.request.id, ...(logout ?? (states.get(reply.request)?.logoutAdmitted ? { browserCredentialsCleared: true, serverRevocationConfirmed: false } : {})),
 });
}
export function markLogoutAdmitted(request: FastifyRequest): void {
 const state = states.get(request); if (!state) throw new AuthnHttpError('AUTHN_UNAVAILABLE'); state.logoutAdmitted = true;
}
type RequestState = { logoutAdmitted?: boolean; controller: AbortController; timer: ReturnType<typeof setTimeout>; running: boolean; released: boolean; release: () => void };
const states = new WeakMap<FastifyRequest, RequestState>();
export function requestAbortSignal(request: FastifyRequest): AbortSignal {
 const state = states.get(request);
 if (!state) throw new AuthnHttpError('AUTHN_UNAVAILABLE');
 return state.controller.signal;
}
export async function createAuthnApp(config: PublicAuthnConfig, options: { loginRateLimit?: boolean } = {}): Promise<FastifyInstance> {
 const admitted = validatePublicAuthnConfig(config), host = new URL(admitted.publicOrigin).host;
 const app = Fastify({ exposeHeadRoutes: false, logger: false, trustProxy: false, bodyLimit: AUTHN_LIMITS.bodyBytes,
  requestTimeout: AUTHN_LIMITS.requestTimeoutMs, connectionTimeout: AUTHN_LIMITS.requestTimeoutMs,
  genReqId: () => randomUUID(), serverFactory: handler => createServer({ maxHeaderSize: AUTHN_LIMITS.headerBytes,
   requestTimeout: AUTHN_LIMITS.requestTimeoutMs, headersTimeout: AUTHN_LIMITS.requestTimeoutMs }, handler),
  clientErrorHandler: (_error, socket) => {
   if (!socket.writable || socket.destroyed) return;
   const correlationId = randomUUID();
   const body = JSON.stringify({ type: 'about:blank', title: 'AUTHN_REQUEST_INVALID', status: 400, code: 'AUTHN_REQUEST_INVALID', correlationId });
   socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Type: application/problem+json\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src \'none\'; frame-ancestors \'none\'\r\nX-Correlation-Id: ' + correlationId + '\r\nContent-Length: ' + Buffer.byteLength(body) + '\r\n\r\n' + body);
  },
 });
 // Complete registration before callers add any route. The shared per-socket
 // budget covers readiness, reads and mutations, with no forwarding-header trust.
 await app.register(rateLimit, { max: AUTHN_LIMITS.requestsPerMinute, timeWindow: 60_000, cache: 1024,
  keyGenerator: request => request.raw.socket.remoteAddress ?? 'unknown',
  errorResponseBuilder: () => new AuthnHttpError('AUTHN_RATE_LIMITED'), skipOnError: false,
 });
 app.removeAllContentTypeParsers();
 app.addContentTypeParser('application/json', { parseAs: 'buffer', bodyLimit: AUTHN_LIMITS.bodyBytes }, (_request, body, done) => {
  try { done(null, strictJson(body as Buffer, AUTHN_LIMITS.bodyBytes)); } catch { done(new AuthnHttpError('AUTHN_REQUEST_INVALID')); }
 });
 let inflight = 0;
 const rates = new Map<string, { started: number; count: number }>();
 app.addHook('onRequest', async (request, reply) => {
  reply.header('cache-control', 'no-store').header('referrer-policy', 'no-referrer').header('x-content-type-options', 'nosniff')
   .header('content-security-policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
   .header('x-frame-options', 'DENY').header('x-correlation-id', request.id);
  if (inflight >= AUTHN_LIMITS.processInflight) return sendAuthnError(reply, 'AUTHN_UNAVAILABLE');
  inflight++;
  const controller = new AbortController();
  const state: RequestState = { controller, running: false, released: false, timer: setTimeout(() => {
   controller.abort(); sendAuthnError(reply, 'AUTHN_UNAVAILABLE');
  }, AUTHN_LIMITS.requestTimeoutMs), release() { if (!state.released) { state.released = true; inflight--; clearTimeout(state.timer); } } };
  state.timer.unref(); states.set(request, state);
  const raw = request.raw.rawHeaders;
  let size = 2;
  for (let i = 0; i < raw.length; i += 2) size += Buffer.byteLength(raw[i]!, 'utf8') + Buffer.byteLength(raw[i + 1]!, 'utf8') + 4;
  if (size > AUTHN_LIMITS.headerBytes) invalid();
  for (const name of ['host', 'cookie', 'origin', 'content-type', 'x-csrf-token', 'content-length', 'transfer-encoding']) header(request, name);
  if (header(request, 'host') !== host || !request.raw.url?.startsWith('/') || request.raw.url.startsWith('//')
    || /[%\\#]/.test(request.raw.url.split('?')[0]!)) invalid();
  if (options.loginRateLimit && ['/authn/login', '/authn/callback'].includes((request.raw.url ?? '').split('?')[0]!)) {
   const now = Date.now();
   for (const [key, value] of rates) if (now - value.started >= 60_000) rates.delete(key);
   const key = request.raw.socket.remoteAddress ?? 'unknown';
   const rate = rates.get(key);
   if ((!rate && rates.size >= 1024) || rate && rate.count >= AUTHN_LIMITS.loginRequestsPerMinute) return sendAuthnError(reply, 'AUTHN_RATE_LIMITED');
   if (rate) rate.count++; else rates.set(key, { started: now, count: 1 });
  }
 });
 app.addHook('onRoute', route => {
  const handler = route.handler;
  route.handler = async function (request, reply) {
   const state = states.get(request); if (state) state.running = true;
   try { if (reply.sent || state?.controller.signal.aborted) return reply; return await handler.call(this, request, reply); }
   finally { if (state) { state.running = false; if (reply.sent || state.controller.signal.aborted) state.release(); } }
  };
 });
 app.addHook('onResponse', async request => { const state = states.get(request); if (state) { clearTimeout(state.timer); state.controller.abort(); if (!state.running) state.release(); } });
 app.addHook('onRequestAbort', async request => { const state = states.get(request); if (state) { state.controller.abort(); if (!state.running) state.release(); } });
 app.addHook('onTimeout', async request => { const state = states.get(request); if (state) { state.controller.abort(); if (!state.running) state.release(); } });
 app.setErrorHandler((error, _request, reply) => sendAuthnError(reply, error instanceof AuthnHttpError ? error.code
  : typeof error === 'object' && error !== null && 'statusCode' in error && [400, 413, 415].includes(Number(error.statusCode)) ? 'AUTHN_REQUEST_INVALID' : 'AUTHN_UNAVAILABLE'));
 app.setNotFoundHandler((_request, reply) => reply.code(404).type('application/problem+json').send({ type: 'about:blank', title: 'Not found', status: 404, correlationId: reply.request.id }));
 return app;
}
