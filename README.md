# Governance Commons

An independent open-source data and AI governance platform, built in one monorepo. Original code and synthetic examples only. Apache-2.0.

**Development in progress.** This repository preserves the full [product specification](docs/product/BUILD_SPEC.md), [machine-readable requirements](docs/product/requirements.yaml), and [current execution state](docs/execution/STATE.md). A catalog slice is an intermediate milestone; it does not represent the complete target or a supported enterprise release.

The first increment connects Keycloak login, tenant-scoped PostgreSQL persistence, Temporal/site/Python PostgreSQL metadata scans, OpenSearch discovery, ownership and audit. This core journey passes real local browser and isolation tests. The model workspace adds immutable typed definitions, visual authoring, pinned inheritance, complete bounded migrations, constrained relations, required participation and typed business domains. Their scoped local and hosted checks are recorded in the evidence register. The bounded reference authority engine is checked and merged; its canonical storage and runtime integration are in progress. PostgreSQL metadata scanning is locally qualified; lineage, DQ, source grants, full capabilities and enterprise profiles remain open.

```sh
./dev doctor
./dev bootstrap
./dev up --profile core
./dev seed --dataset harbor-demo
./dev test --suite smoke
```

Local application: http://localhost:4310. Bootstrap generates local credentials under ignored protected storage; never commit them. `./dev down` preserves data. Full/AI/enterprise profiles remain under implementation, and unsupported commands fail explicitly.

The [inactive authentication foundation](docs/development/authentication-foundation.md) documents role prerequisites, typed installation receipts and its separate real PostgreSQL gate. Its implementation does not imply authority activation or release qualification.

The [protected login and session lifecycle](docs/development/protected-authentication.md) describes its isolated real-service gate and explicit local installation batch. Content authority remains inactive until the later qualified cutover.

See [execution plan](docs/execution/PLAN.md), [release readiness](docs/release/READINESS.md), [capability traceability](docs/product/parity-matrix.md), [contributing](CONTRIBUTING.md), and [security](SECURITY.md). See the [executed evidence](docs/verification/evidence-manifest.json) and [inspected screenshots](docs/verification/screenshots/README.md). There is no external LLM or paid-service requirement for the core product.

![Actual synthetic asset ownership and audit UI](docs/verification/screenshots/asset-en-light-1440.png)
