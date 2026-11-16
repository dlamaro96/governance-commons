# Governance Commons

Read `docs/execution/STATE.md` and relevant rows of `docs/product/requirements.yaml` before work. The complete, frozen governing specification is `docs/product/BUILD_SPEC.md`; do not reduce its scope to the first slice.

- Preserve unrelated work. One monorepo; Apache-2.0 original work and synthetic examples only.
- Architecture: React/TypeScript/Vite; Fastify; Kysely/PostgreSQL with forced RLS; OpenSearch projections; Temporal; TypeScript site coordinator and uv-managed Python source workers; Keycloak OIDC; SeaweedFS S3 locally.
- Root owns shared contracts and migrations. Agree interfaces before parallel edits; never revert another workstream.
- Tenant scope derives from authenticated membership. Every tenant table, FK, job, search and audit boundary is scoped. Runtime roles must not own tables or bypass RLS.
- Browser auth uses OIDC code+PKCE and server-side HttpOnly sessions, CSRF checks, no stored browser bearer tokens. No connector execution in request handlers; secrets stay outside source/history and Temporal payloads.
- Mutations commit canonical data, append-only audit and outbox together. Validate versions/idempotency; authorize before counts/facets. Failed scans cannot delete assets.
- Applied SQL001–012 migrations are immutable. This root checkout is the sole shared-runtime launcher; older checkouts share private bootstrap files and must not run their old bootstrap/startup commands. Database corrections require a forward migration and an isolated upgrade gate.
- Use `./dev help`, `./dev doctor`, `./dev bootstrap`, `./dev up --profile core`, `./dev seed --dataset harbor-demo`, `./dev test --suite smoke`. Commands under implementation must fail explicitly, never report unrun checks as passing.
- Run type/schema checks and relevant real integration/security/browser gates. Keep implementation, verification, release readiness and runtime health distinct.
- Canonical requirements live in YAML; use `python3 scripts/requirements.py` for generated views. Never hand-edit projections or remove failing requirements.
- Update STATE, evidence manifest and requirement evidence per coherent slice. Evidence identifies exact revision, profile, tool/source versions, command and limitations.
- No secrets, private data, invented sign-offs/reviewers, paid resources or production deployment. GitHub repository/push setup is authorized; use existing authentication without printing credentials.
