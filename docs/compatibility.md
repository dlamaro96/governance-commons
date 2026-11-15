# Compatibility and dependency resolution

Resolved 2026-11-15 from primary registries; installed exact packages are in pnpm-lock.yaml and python/uv.lock. This is a development selection, not blanket qualification. [Node24 release archive](https://nodejs.org/en/download/archive/v24), [Fastify releases](https://github.com/fastify/fastify/releases), [Temporal self-hosting](https://docs.temporal.io/self-hosted-guide), [PostgreSQL RLS](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).

| Component | Selected version | License / scope | Verification |
|---|---|---|---|
| Node |24.22.3|MIT and bundled notices|macOS arm64 checksum verified; Linux image pending smoke|
| pnpm |10.32.1|MIT/build|lockfile installation executed|
| TypeScript |7.0.2|Apache-2.0/build|type checks executed|
| React |19.3.1|MIT/web|production build executed|
| Vite |8.3.8|MIT/build|production build executed|
| Fastify |5.12.8|MIT/API|type checks; runtime pending|
| Kysely / pg |0.29.9 /8.23.1|MIT|DB integration pending|
| TypeBox |0.34.52|MIT|ingress schemas; OpenAPI compatibility gate pending|
| Temporal SDK |1.25.0|MIT|build/type only; replay/integration pending|
| PostgreSQL |17.11 (selected digest)|PostgreSQL|local server started; RLS suite pending|
| OpenSearch |3.9.0|Apache-2.0|local health reached; semantic/rebuild gates pending|
| Keycloak |26.8.1|Apache-2.0|local login pending|
| SeaweedFS |4.51|Apache-2.0|S3 conformance pending|
| Temporal server |1.32.2|MIT|startup repair under integration|
| Python |3.14.5|PSF-2.0|worker image build pending|
| psycopg |3.3.3|LGPL-3.0-or-later (check bundled artifacts)|worker dependency inventory/release review pending|
| Playwright |1.65.1|Apache-2.0/test|browser installation and execution pending|
| axe-core |4.14.0|MPL-2.0/test only|accessibility execution pending|

Container image digests are pinned in Dockerfile and Compose. Dependency/license metadata is not an audited distribution inventory; transitive/container SBOM and license gates remain open. Same monorepo version0.1.0-dev.1; no released compatibility/skew support promised. No amd64, Kubernetes, OpenShift, cloud, offline, HA or enterprise scale has been qualified.
