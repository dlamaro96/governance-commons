<p align="center"><img src="docs/media/governance-commons.svg" alt="Governance Commons — open source data governance" width="100%"></p>

<p align="center"><a href="#run-it-locally">Run locally</a> · <a href="docs/product/parity-matrix.md">Capability roadmap</a> · <a href="CONTRIBUTING.md">Contribute</a> · <a href="SECURITY.md">Security</a></p>

Governance Commons brings technical metadata, business context, ownership and change history into one self-hosted workspace. It is an independent Apache-2.0 project with original code and synthetic examples.

**Development preview.** The core catalog and governance workflows run against real services. The broader programme and enterprise release gates remain in progress. See the [capability register](docs/product/requirements.yaml) and [release readiness](docs/release/READINESS.md) for exact implementation and verification status.

## Explore the workspace

![Actual catalog with a freshly scanned synthetic PostgreSQL source, curated ownership and descriptions](docs/media/catalog.png)

*Actual application capture. Five synthetic tables and views were discovered by a real PostgreSQL scan; their descriptions and ownership were saved through the application API.*

<table><tr><td width="50%"><img src="docs/media/asset-columns.png" alt="Actual orders asset with source columns"><br><strong>From discovery to understanding</strong><br>Inspect source columns, provenance, ownership and governed context.</td><td width="50%"><img src="docs/media/audit-history.png" alt="Actual asset audit history"><br><strong>Understand what changed</strong><br>Trace collected metadata and stewardship changes in the asset history.</td></tr></table>

## What you can use today

| Workflow | Current development capability |
|---|---|
| Discover | Register a PostgreSQL source, run a real metadata scan, search assets and inspect table, view and column metadata. |
| Steward | Assign owners, maintain descriptions, inspect change history and retain source provenance. |
| Model | Author versioned operating models, inherited asset types, lifecycle rules, constrained relations and typed business domains. |
| Change safely | Preview bounded model and graph migrations, detect stale versions and retain operation receipts. |
| Collaborate securely | Keycloak OIDC login, server-side sessions, tenant-scoped API/database checks and append-only audit/outbox records. |
| Work in your language | English and Arabic layouts, light and dark themes, responsive views and scoped automated accessibility checks. |

These are scoped development capabilities. Passing one workflow does not qualify an entire enterprise release.

## Configurable identity and integrations

Microsoft Entra ID and other OIDC identity providers are part of the required identity design. Entra federation, account/group synchronization and live vendor qualification are separate capabilities; only the recorded Keycloak profile is currently locally qualified.

Databricks Unity Catalog is a required connector target, alongside the complete [connector matrix](docs/product/connector-support.yaml). Metadata, lineage, model registry, writeback and source permissions have separate implementation and verification states. Unity Catalog is **not yet implemented or live-qualified**. PostgreSQL metadata scanning is the currently qualified source path.

The remaining programme includes glossary and policies, stewardship workflows, lineage, quality and observability, data products and access, privacy, AI governance, notebooks, marketplace integrations and enterprise operations. Required features stay in the open-source project; there is no seat, asset or connector license gate.

## Run it locally

Install Docker with Compose and the documented development toolchain, then run:

```sh
./dev doctor
./dev bootstrap
./dev up --profile core
./dev seed --dataset harbor-demo
./dev test --suite smoke
```

Open **http://localhost:4310**. Bootstrap generates synthetic development credentials in ignored local storage. `./dev down` stops the project while preserving data. The core requires no cloud account, paid service or LLM key. Profiles still under implementation fail explicitly instead of reporting an unexecuted success.

## Built for transparent engineering

React and TypeScript power the interface. Fastify and PostgreSQL own canonical state, with forced row-level security at tenant boundaries. OpenSearch serves search projections; Temporal coordinates work; TypeScript site runners and Python workers execute connectors. Keycloak supplies the local identity provider and SeaweedFS supplies local S3-compatible storage.

The [product specification](docs/product/BUILD_SPEC.md), [architecture decisions](docs/adr), [verification index](docs/verification/evidence-manifest.json) and [source code](apps) make scope and evidence inspectable. Screenshots show actual synthetic runtime data; they are not claims of unimplemented workflows, production certification or live vendor support.

Contributions are welcome through [issues](https://github.com/dlamaro96/governance-commons/issues) and [pull requests](https://github.com/dlamaro96/governance-commons/pulls). Start with [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately using [SECURITY.md](SECURITY.md), and follow the [Code of Conduct](CODE_OF_CONDUCT.md).
