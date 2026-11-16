// SPDX-License-Identifier: Apache-2.0
import { createAuthnEdge } from './server.ts';
import type { AuthnEnvironment } from '../../../packages/authn/src/contracts.ts';
try {
 if(['DATABASE_URL','AUTHN_LOGIN_DATABASE_URL','AUTHN_API_DATABASE_URL','MIGRATION_DATABASE_URL','OWNER_DATABASE_URL','DATABASE_OWNER_URL','OIDC_CLIENT_SECRET'].some(name=>process.env[name]))throw new Error('AUTHN_EDGE_CONFIG_INVALID');
 const environment=process.env.AUTHN_ENVIRONMENT as AuthnEnvironment;
 const app=createAuthnEdge({environment,publicOrigin:process.env.PUBLIC_AUTHN_ORIGIN ?? '',
  loginUpstream:process.env.AUTHN_LOGIN_UPSTREAM ?? '',sessionUpstream:process.env.AUTHN_SESSION_UPSTREAM ?? '',
  legacyUpstream:process.env.LEGACY_API_UPSTREAM});
 const port=Number(process.env.PORT ?? 4310);
 if(!Number.isInteger(port)||port<1||port>65535)throw new Error('AUTHN_EDGE_CONFIG_INVALID');
 app.listen(port,process.env.HOST ?? '0.0.0.0');
 const stop=()=>{app.close(()=>process.exit(0));setTimeout(()=>process.exit(1),10_000).unref();};
 process.on('SIGTERM',stop);process.on('SIGINT',stop);
 app.on('error',()=>{process.stderr.write('AUTHN_EDGE_UNAVAILABLE\n');process.exitCode=1;});
} catch { process.stderr.write('AUTHN_EDGE_CONFIG_INVALID\n');process.exitCode=1; }
