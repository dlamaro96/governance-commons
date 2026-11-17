// SPDX-License-Identifier: Apache-2.0
import pg from 'pg';
import { AUTHN_LIMITS, type AuthnEnvironment } from './contracts.ts';
import { AuthnHttpError } from './transport.ts';
export type ExecutorKind = 'login' | 'api';
export function nativePoolOptions(kind: ExecutorKind, databaseUrl: string, environment: AuthnEnvironment): pg.PoolConfig {
 try {
  if (!['login', 'api'].includes(kind) || !['isolated-test', 'local-development', 'production'].includes(environment)
    || typeof databaseUrl !== 'string' || databaseUrl.length > 8192 || /[\u0000-\u0020\u007f]/.test(databaseUrl)) throw Error();
  const url = new URL(databaseUrl);
  if (!['postgres:', 'postgresql:'].includes(url.protocol) || decodeURIComponent(url.username) !== `gc_authn_${kind}`
    || !url.password || !url.hostname || url.search || url.hash || !/^\/[^/]+$/.test(url.pathname)) throw Error();
  const port = url.port ? Number(url.port) : 5432;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw Error();
  const database = decodeURIComponent(url.pathname.slice(1)), password = decodeURIComponent(url.password);
  if (!database || /[\u0000-\u001f\u007f]/.test(database + password)) throw Error();
  return { host: url.hostname.replace(/^\[|\]$/g, ''), port, database, user: `gc_authn_${kind}`, password,
   ssl: environment === 'production' ? { rejectUnauthorized: true } : false,
   max: AUTHN_LIMITS.poolConnections, connectionTimeoutMillis: AUTHN_LIMITS.connectTimeoutMs,
   statement_timeout: AUTHN_LIMITS.statementTimeoutMs, lock_timeout: AUTHN_LIMITS.lockTimeoutMs,
   idle_in_transaction_session_timeout: AUTHN_LIMITS.idleTransactionTimeoutMs,
   application_name: `governance-protected-${kind}`,
   options: '-c statement_timeout=5000 -c lock_timeout=2000 -c idle_in_transaction_session_timeout=5000',
  };
 } catch { throw new AuthnHttpError('AUTHN_UNAVAILABLE'); }
}
export function createNativeAuthenticationPool(kind: ExecutorKind, databaseUrl: string, environment: AuthnEnvironment): pg.Pool {
 const pool = new pg.Pool(nativePoolOptions(kind, databaseUrl, environment));
 pool.on('error', () => { /* Raw driver diagnostics never enter request logs. Readiness/next operation fails closed. */ });
 return pool;
}
export async function verifyNativeAuthenticationPool(pool: pg.Pool, kind: ExecutorKind): Promise<void> {
 let connection: pg.PoolClient | undefined;
 try {
  connection = await pool.connect();
  const { rows } = await connection.query(`SELECT current_user AS current_role,session_user AS native_role,
   current_setting('statement_timeout') AS statement_timeout,current_setting('lock_timeout') AS lock_timeout,
   current_setting('idle_in_transaction_session_timeout') AS idle_timeout,
   r.rolcanlogin AND NOT(r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolinherit OR r.rolreplication OR r.rolbypassrls)
    AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.roleid=r.oid OR m.member=r.oid) AS safe
   FROM pg_catalog.pg_roles r WHERE r.rolname=session_user`);
  const row = rows[0];
  if (rows.length !== 1 || row.current_role !== `gc_authn_${kind}` || row.native_role !== `gc_authn_${kind}`
    || row.statement_timeout !== '5s' || row.lock_timeout !== '2s' || row.idle_timeout !== '5s' || row.safe !== true) throw Error();
 } catch { throw new AuthnHttpError('AUTHN_UNAVAILABLE'); }
 finally { connection?.release(); }
}
