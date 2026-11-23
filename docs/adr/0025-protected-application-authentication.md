# Protected application authentication

Status: implemented candidate; integrated qualification is recorded separately.

The application uses the protected login broker, session service and native
PostgreSQL session provenance. The edge forwards only the protected session and
CSRF cookies to the application. Browser tenant selection and logout use
versioned protected session commands. The legacy login link redirects to the
protected entry point; legacy session cookies do not authenticate application
requests.

SQL037 adds an explicitly installed, bounded application-reader bridge. The
ordinary application role receives a closed read interface, not login executor
credentials, ownership or access to private authentication tables. Installation
and revocation require a native owner manifest, exact deployment identity and
receipt chain. Identical replay neither renews expiry nor reactivates a revoked
bridge. Migration alone does not activate it.

The local application origin is `http://127.0.0.1:4310`; Keycloak retains
`http://localhost:4311/realms/governance`. Different hostnames prevent application
cookies from being sent to the identity provider. Internal transport aliases
retain exact issuer, audience, callback, state, nonce and PKCE validation.

Application authentication runs in a bounded read-only repeatable-read snapshot.
Search and audit revalidate the protected session within their own read snapshot
before counts or records. Existing content permissions and row-level security
remain required. This change does not implement commit-linearized revocation for
ordinary content mutations or activate the canonical content-authority evaluator.

Core startup builds and verifies the application, applies the forward migration
and starts the services. Operators explicitly invoke `./dev authn-core-install`
after seeding. Its private manifests persist across restarts; expiry and revocation
require an explicit successor installation. CI records installation and the
isolated SQL037 gate as separate required outcomes.

Qualification fixtures use separate native login/session credentials and preserve
dedicated synthetic identity, membership and audit history. The application API
retains only its ordinary runtime database role. Fixture preparation, test source
readback and real API execution have separate failure boundaries; a fixture or
unit pass is not vendor-live identity-provider qualification.

Microsoft Entra configuration and token-validation controls remain distinct from
live Entra qualification, directory synchronization, group mapping, SCIM and
production deployment requirements. Those obligations remain in the requirement
register.
