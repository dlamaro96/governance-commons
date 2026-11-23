# Protected login and session lifecycle

This increment adds a dedicated OIDC login broker, session service and fixed-route edge. The session is backed by SQL012 and native `gc_authn_login` / `gc_authn_api` executor roles. It remains separate from the existing application's content authorization. A successful protected sign-in does not grant catalog access or activate the authority engine.

Implementation and qualification are separate. The source and focused host tests are under development; do not infer a runtime or release pass until an evidence record identifies the executed source and real-service result. The adopted [transport contract](../execution/PROTECTED_BROKER_CONTRACT.md) defines the exact deployment, cookie, OIDC, CSRF, native-role and failure behavior. Applied migrations are immutable.

## Isolated qualification

Run `./dev test --suite protected-authn` from the protected-broker checkout. Its isolated Compose project uses fresh PostgreSQL and Keycloak services, public application port4314 and identity port4315. It does not reuse the shared core's credentials, identity records or volumes. Existing pinned images must be present; the gate must not build or pull an image. Resource admission and exact pre/post inventories are mandatory. The harness writes private0600 credentials and records only safe summaries for publication.

Set `GC_PINNED_NODE` and `GC_BROWSER_EXECUTABLE` to the installed Node24.22.3 and browser executable paths when the defaults are unavailable. The default `mounted-source` mode overlays this checkout read-only on the cached application image. It qualifies local behavior against those recorded source bytes; it does not certify a baked image.

For an already built image containing the exact committed source, set `GC_PROTECTED_AUTHN_MODE=immutable-image` and `GC_PROTECTED_AUTHN_IMAGE=sha256:<64 lowercase hex digits>`. This requires Compose2.24.4 or newer. The gate first compares every declared source with immutable Git blobs and an unmounted, network-isolated image reader; application containers then run without source bind mounts. Private owner/helper configuration uses only the project-owned volume. All five application-role image identities are read back before execution.

Hosted CI invokes `scripts/runtime-protected-ci.py` after the core browser gate. It selects the actual tested core API image, stops only that CI project's core services while preserving volumes, discovers the pinned installed tools and runs the separate immutable-image gate. Its two browser journeys and eight captures remain distinct from the core's 37 journeys. The evidence publisher rejects mounted-source reports for hosted qualification and independently checks the exact source, migration, installation, Keycloak, TAP, browser, asset and cleanup records.

The harness establishes canonical synthetic identities using the exact isolated issuer, provisions the native executor roles, runs exact SQL001–032 migrations and ordinary seed, and separately invokes the explicit local installation batch. Ordinary bootstrap and seed do not activate these executors. Six seeded persona memberships remain intact; a seventh test identity exercises a real two-tenant selection flow. The gate must qualify actual Keycloak `auth_time` issuance, signature and claim checks, committed consume before token exchange, session selection, expiry, revocation, browser cookie isolation and CSRF rejection before passing. Controlled adversarial endpoints supplement real Keycloak journeys; they are not a substitute for them.

## Explicit local installation

`scripts/authentication-install-demo.ts --batch <private-directory>` is a standalone owner operation for an already migrated, explicitly selected local development database. It requires `MIGRATION_DATABASE_URL`, `OIDC_ISSUER`, `PUBLIC_AUTHN_ORIGIN` and a local `AUTHN_ENVIRONMENT`. Do not paste credentials into chats or shell history; use the harness's private environment files or the existing private operator mechanism.

The batch saves13 validated manifests with one fixed24-hour registration/binding expiry before executing them. It verifies the original database/owner/executor OIDs and six existing canonical issuer/subject pairs. Replay the same private batch after an interrupted or uncertain result; the operation never silently creates a new expiry, renews authority or reactivates a revoked registration. Preserve failed attempts and investigate prerequisites before replay. This convenience installer refuses production.

## Service configuration

`login-broker` accepts only its native login database URL plus the exact server-owned OIDC configuration. `session-api` accepts only its native API database URL and public origin. The edge receives no database or OIDC secret. Processes reject legacy/owner credential aliases. Production requires HTTPS with the Secure `__Host-` cookie family, a separate IdP hostname and separately qualified infrastructure. Both nonproduction modes require exact loopback HTTP and use host-only `/authn` cookies. Forwarded headers never select an issuer, tenant, identity or proxy target.

The lifecycle page supports English/Arabic direction, keyboard operation and narrow layouts. Its tenant-ID entry is deliberately scoped to this transport qualification. Arabic linguistic review, complete product administration, integrated core routing and all-ingress content-authority cutover remain separate required work.

## Linux tool admission

CI selects the installed Playwright Chromium executable explicitly. Its current Linux binary is 311,672,136 bytes, so the shared admission/launch/exit digest helper admits regular executable files up to 512 MiB, hashing in 1 MiB chunks. It refuses symlinks, empty/nonregular/oversized files and size or metadata changes during reading. This does not increase the browser process memory, output or time budgets. Failed runs print only a closed phase name; raw exceptions, callbacks and credentials remain private. See the [scoped compatibility evidence](../verification/protected-linux-tool-admission-local.json); the historical hosted failure remains failed until a fresh hosted run passes.
