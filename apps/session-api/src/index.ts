// SPDX-License-Identifier: Apache-2.0
import { createAuthenticationClient } from '../../../packages/authority/src/authentication.ts';
import type { AuthnEnvironment } from '../../../packages/authn/src/contracts.ts';
import { createNativeAuthenticationPool, verifyNativeAuthenticationPool } from '../../../packages/authn/src/pool.ts';
import { validatePublicAuthnConfig } from '../../../packages/authn/src/transport.ts';
import { createSessionApp } from './server.ts';
async function start(): Promise<void> {
 if (['DATABASE_URL', 'AUTHN_LOGIN_DATABASE_URL', 'MIGRATION_DATABASE_URL', 'OWNER_DATABASE_URL', 'DATABASE_OWNER_URL', 'OIDC_CLIENT_SECRET'].some(name => process.env[name])) throw Error();
 const config = validatePublicAuthnConfig({ publicOrigin: process.env.PUBLIC_AUTHN_ORIGIN ?? '', environment: process.env.AUTHN_ENVIRONMENT as AuthnEnvironment });
 const pool = createNativeAuthenticationPool('api', process.env.AUTHN_API_DATABASE_URL ?? '', config.environment);
 try {
  await verifyNativeAuthenticationPool(pool, 'api');
  const client = createAuthenticationClient(pool);
  const app = await createSessionApp(config, { sessionInspect: client.sessionInspect, sessionSelect: client.sessionSelect, sessionRevoke: client.sessionRevoke }, () => verifyNativeAuthenticationPool(pool, 'api'));
  app.addHook('onClose', async () => { await pool.end(); });
  for (const signal of ['SIGINT', 'SIGTERM'] as const) process.once(signal, () => { void app.close(); });
  await app.listen({ host: '0.0.0.0', port: 4313 });
 } catch { await pool.end(); throw Error(); }
}
void start().catch(() => { process.stderr.write('AUTHN_UNAVAILABLE\n'); process.exitCode = 1; });
