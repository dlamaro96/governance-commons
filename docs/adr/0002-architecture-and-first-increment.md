# ADR 0002 — Fixed architecture and first increment

Status: accepted for implementation, 2026-11-15. Governing decisions: BUILD_SPEC §5.

Use a modular TypeScript/Fastify control plane, React/Vite web, PostgreSQL canonical persistence through Kysely and explicit migrations, OpenSearch rebuildable search, Temporal orchestration, a TypeScript site coordinator, uv-managed Python connector worker, Keycloak OIDC and SeaweedFS S3. Core dependencies run as real local services. One coordinated prerelease version is used. No alternative in-memory business path, Redis, Kafka or substitute workflow system.

M1 implements only catalog authentication/source scan/ownership/audit behavior; all other scope stays in the register. Source rows and credentials remain outside Temporal payloads. Initially only an explicit local PostgreSQL host/port/database/schema/secret-reference allowlist is accepted. Arbitrary administrator destinations require later validated site egress policy; they are not implicitly trusted.

Authorization currently uses seeded permission arrays plus tenant scope and explicit restricted asset visibility. This is a foundation for the required typed DSL, not its completion. Current canonical asset authorization limits search IDs before OpenSearch totals and facets. This development profile stops with an explicit limit above 10,000 allowed IDs; it does not claim enterprise scale. Later compiled equivalent predicates must replace this bounded approach with semantic-equivalence tests.

OIDC canonical browser issuer is localhost:4311; containers use explicit Keycloak transport endpoints while JWT issuer/audience/nonce remain strictly checked. Browser return URI is fixed. Local cookies are HttpOnly/SameSite=Lax, state-changing requests require same-origin plus session CSRF token; production uses Secure cookies.

Alternatives rejected: custom passwords, in-memory queue, search-only ACLs, source code in API handlers, static UI demonstration. Revisit performance limits only with measured evidence and equivalent security tests. Deployment profiles, encryption/vault integration, SCIM, signed site enrollment, full policy DSL and complete release qualification remain open.
