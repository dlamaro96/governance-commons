# Product status

Updated 17 November 2026. Governance Commons is a working **development preview**, not a completed enterprise product or supported release. This page describes integration checkpoint `514ddee` plus test repairs through `f3f21e5`. Hosted evidence at `2186dcb` covers the preceding revision; `main` can lag until protected CI and review permit merging.

## Implemented workflows with scoped local evidence

- OIDC login and server-side sessions; tenant-scoped PostgreSQL/API checks; ownership, audit and transactional outbox.
- Real PostgreSQL metadata scans, authorized catalog search, asset details and source registration.
- Versioned operating models, inherited types, constrained relations, bounded graph migrations and business domains.
- Reviewed glossary publication; reference code lists, effective dates, historical reads, exports, hierarchy/crosswalk and import workflows.
- PostgreSQL view-dependency lineage and reviewed metadata classification.
- Source-worker quality checks for completeness, allowed reference values, uniqueness, integer ranges and latest-timestamp freshness.
- Table-volume rules count entire ordinary PostgreSQL tables with immutable row bounds. Isolated storage and real source-worker checks pass; its real browser lifecycle passes with all 18 captures inspected. All 171 current API cases pass after repair of the rollback-snapshot fixture; the full 37-journey browser regression is running.
- UTC quality schedules, deduplicated incidents, in-app notifications and verified recovery/reopening. A historical freshness pass remains in history after its eligibility expires.
- English/Arabic and responsive layouts, with automated accessibility checks and recorded visual inspections in the tested journeys.

Each item is narrower than its complete baseline requirement. Consult the [evidence manifest](../verification/evidence-manifest.json), [current state](../execution/STATE.md) and canonical [requirement register](requirements.yaml) before making support claims.

## What remains

| Workstream | Remaining implementation or qualification |
|---|---|
| Identity and authorization | Canonical authority activation across every ingress, policy/admin tooling, delegated operator access, service identities, identity synchronization and live Microsoft Entra qualification. |
| Discovery and collaboration | More source object types, incremental/recovery ingestion, saved searches/views, subscriptions/comments, governed samples and complete bulk metadata interchange. |
| Governance | Visual workflow/form designer and declared BPMN subset; broader approvals, policies/controls/risks/assessments, delegation/escalation and email/webhook delivery. |
| Quality, lineage and semantics | Complete full table-volume browser and hosted qualification. Schema/distribution drift, remaining rule families, filters/partition scope, anomaly baselines and aggregation remain; broader SQL/OpenLineage/column lineage and semantic modelling remain. |
| Contracts, products and access | Contract lifecycle, data-product marketplace, source grant/revoke/expiry/drift reconciliation and bounded SQL notebooks. |
| AI and MCP | AI registry/evaluations, permission-filtered context assistant, authenticated MCP server and governed tool gateway. |
| Documents and privacy | Document/version/ACL/delete propagation, privacy registers and assessments, cross-system evidence and complete portable migration. |
| Integrations | The complete named connector inventory. Unity metadata adapter code exists; live Databricks and its other capability routes remain unqualified. A generic connector does not complete named integrations. |
| Operations and release | Clean-install reproduction, Kubernetes/OpenShift and offline profiles, backup/restore, upgrades, performance/soak tests, final artifact scans/SBOM/signing/provenance and independent security/accessibility reviews. |

There are 354 named baseline requirements plus their detailed and supplemental tracking records (1,106 total). The register marks 128 records in progress and 978 not started; these are scope-tracking states, **not a percentage-complete estimate**. All 5,530 per-record verification outcomes remain `NOT_RUN`; narrower evidence is attached separately. No whole baseline requirement is promoted solely because a narrower journey passes.

## Immediate delivery gates

1. Diagnose and repair the remaining hosted governance, completeness-upgrade and browser failures. The historical SQL018 population failure remains open. Fresh security job metadata is successful, but it does not establish enterprise security or release readiness.
2. All 171 API cases pass against applied SQL001–031. The bounded snapshot repair retains the original rollback assertions; the preceding 154-pass/test-process-abort result remains recorded. Complete the running full 37-journey browser graph before claiming full acceptance. The volume and repaired classification targets pass. The predecessor full 36 attempt15 passes without retries or skips; three of 281 screenshots were reviewed, so complete visual verification is still open.
3. Preserve the scoped volume320/worker15-check and authority133/423 native evidence with exact source-equivalence limits. The authority-read optimization remains an inactive foundation; runtime policy activation and its broader obligations are unfinished.
4. Keep the README, requirement evidence, GitHub backlog and PR descriptions aligned with the tested implementation. Merge through protected checks; do not bypass red CI.
5. Continue every workstream above through the [M0–M10 delivery plan](../execution/PLAN.md) and [GitHub delivery backlog](https://github.com/dlamaro96/governance-commons/issues?q=is%3Aissue%20is%3Aopen). The [requirement-to-issue mapping](../execution/backlog.json) covers all 1,106 records.

External vendor accounts, licensed infrastructure and independent human reviews are explicit qualification prerequisites. They do not excuse missing adapter code or locally executable work. Optional runtime activation also does not make required implementation optional.
