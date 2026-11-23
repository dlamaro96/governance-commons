# Product status

Updated 23 November 2026. Governance Commons is a working **development preview**, not a completed enterprise product or supported release. PR #39 merged normally as `fb1fd0e` after all 45 required development outcomes, source scanning and both native runtime image scans passed at `80101e0`. Its five behavior archives and exact source bindings are verified. PR #40's navigation/context increment passes all 46 outcomes at `4cbde6a` and merged normally as `ed0c6e4`. PR #41's SQL033 increment passes all 47 outcomes at `296d1e5` and merged normally as `1db2f71`. See [current state](../execution/STATE.md), [development evidence](../verification/hosted-checkpoint-296d1e5.json), [source evidence](../verification/source-security-296d1e5.json) and [image evidence](../verification/runtime-images-hosted-296d1e5.json).
PR #42 dependency/startup changes pass all 47 outcomes and exact artifacts at `82859ad` and merged normally as `9e60da8`. [PR #42 hosted checkpoint](../verification/hosted-checkpoint-82859ad.json).

## Implemented workflows with scoped local evidence

- OIDC login and server-side sessions; tenant-scoped PostgreSQL/API checks; ownership, audit and transactional outbox.
- Real PostgreSQL metadata scans, authorized catalog search, asset details and source registration. Global name/recent-update ordering across pages passes 172 local API cases and five targeted browser journeys; exact hosted qualification passed in PR #40. Browser history and direct-link recovery also pass an expanded local journey. [Scoped ordering evidence](../verification/catalog-global-sorting-local.json).
- Versioned operating models, inherited types, constrained relations, bounded graph migrations and business domains.
- Reviewed glossary publication; reference code lists, effective dates, historical reads, exports, hierarchy/crosswalk and import workflows.
- PostgreSQL view-dependency lineage and reviewed metadata classification, with stable label identities and permanent key retirement.
- Source-worker quality checks for completeness, allowed reference values, uniqueness, integer ranges and latest-timestamp freshness.
- Table-volume rules count entire ordinary PostgreSQL tables with immutable row bounds. Isolated storage and real source-worker checks pass; its real browser lifecycle passes with all 18 captures inspected. All 171 API cases pass on SQL032 at `5d37594`, retaining the preceding pass and failed attempt. Full 37 attempt 16 failed with 24 passes, one obsolete table-refusal assertion and 12 unexecuted journeys; the corrected quality target and the subsequent hosted full 37 journeys pass. The earlier local failure remains recorded.
- UTC quality schedules, deduplicated incidents, in-app notifications and verified recovery/reopening. A historical freshness pass remains in history after its eligibility expires.
- English/Arabic and responsive layouts, with automated accessibility checks and recorded visual inspections in the tested journeys.

Each item is narrower than its complete baseline requirement. Consult the [evidence manifest](../verification/evidence-manifest.json), [current state](../execution/STATE.md) and canonical [requirement register](requirements.yaml) before making support claims.

## What remains

| Workstream | Remaining implementation or qualification |
|---|---|
| Identity and authorization | Canonical authority activation across every ingress, policy/admin tooling, delegated operator access, service identities, identity synchronization and live Microsoft Entra qualification. |
| Discovery and collaboration | More source object types, incremental/recovery ingestion, saved searches/views, subscriptions/comments, governed samples and complete bulk metadata interchange. |
| Governance | Visual workflow/form designer and declared BPMN subset; broader approvals, policies/controls/risks/assessments, delegation/escalation and email/webhook delivery. |
| Quality, lineage and semantics | The merged `80101e0` checkpoint passes its full 38-journey browser suite and all 45 outcomes. The navigation/context increment passes its separate 46-outcome checkpoint. Schema/distribution drift, remaining rule families, filters/partition scope, anomaly baselines and aggregation remain; broader SQL/OpenLineage/column lineage and semantic modelling remain. |
| Contracts, products and access | Contract lifecycle, data-product marketplace, source grant/revoke/expiry/drift reconciliation and bounded SQL notebooks. |
| AI and MCP | AI registry/evaluations, permission-filtered context assistant, authenticated MCP server and governed tool gateway. |
| Documents and privacy | Document/version/ACL/delete propagation, privacy registers and assessments, cross-system evidence and complete portable migration. |
| Integrations | The complete named connector inventory. Unity metadata adapter code exists; live Databricks and its other capability routes remain unqualified. A generic connector does not complete named integrations. |
| Operations and release | Clean-install reproduction, Kubernetes/OpenShift and offline profiles, backup/restore, upgrades, performance/soak tests, final artifact scans/SBOM/signing/provenance and independent security/accessibility reviews. |

There are 354 named baseline requirements plus their detailed and supplemental tracking records (1,106 total). The register marks 18 narrow repository clauses implemented, 155 records in progress and 933 not started; these are scope-tracking states, **not a percentage-complete estimate**. An [implementation audit](../verification/oss-requirement-reconciliation.json) corrected stale repository-control labels against actual files. All 5,530 per-record verification outcomes remain `NOT_RUN`; narrower evidence is attached separately. No whole baseline requirement is promoted solely because a narrower journey passes.

## Immediate delivery gates

1. PR #39 is merged normally after exact all 45-outcome and artifact verification. PR #40 is also merged after its exact 46-outcome qualification. PR #41 is merged after its exact 47-outcome qualification. PR #42 also passes all 47 outcomes, source security and both native image gates at `82859ad`, then merged normally as `9e60da8`. SQL034 and SQL035 have scoped native and core evidence; their open hosted assignments retain their own outcomes. The superseded SQL035 `bc1f650` run is [cancelled](../verification/hosted-checkpoint-bc1f650-cancelled.json), not passed. SQL036 passes its separate local native and core checks below; its new 50-outcome hosted assignment remains required.
2. Qualify the runtime-security aggregate for fork use before adding it to enforced branch requirements. No scan alone completes security or release acceptance.
3. Preserve the separately scoped volume, freshness, authority, reference and import evidence. The authority-read foundation remains inactive across content APIs.
4. Keep the README, canonical register, GitHub backlog and PR descriptions aligned with executed behavior. Merge through protected checks.
5. Continue every workstream above through the [M0–M10 delivery plan](../execution/PLAN.md). The [requirement-to-issue mapping](../execution/backlog.json) covers all 1,106 records.

External vendor accounts, licensed infrastructure and independent human reviews are explicit qualification prerequisites. They do not excuse missing adapter code or locally executable work. Optional runtime activation also does not make required implementation optional.

The SQL033 private content revision increment passes isolated migration/concurrency
qualification, all 172 current-core API cases and seven focused browser journeys.
It does not activate content authority or complete the broader requirements.
[Integrated evidence](../verification/content-security-revision-integrated-local.json).

The SQL035 reviewed-classification producer and approval-proof reader pass 98
isolated native cases and 1,207 unit cases. Its new required CI outcome brings
this development assignment to 49. All 172 core API cases and the selected real
classification browser journey pass on the exact rebuilt images. Hosted
qualification remains separate.
This is inactive authorization provenance. [SQL035 native evidence](../verification/reviewed-classification-facts-local.json) and
[integrated evidence](../verification/reviewed-classification-facts-integrated-local.json) retain their original scope.

SQL036 aligns storage and evaluator scope checks and performs held metadata
composition and evaluation. All 140 native cases and 1,257 unit cases pass.
The rebuilt core passes all 172 API cases and one real classification browser
journey, with 36 migration checksums and 349 source/image bindings verified;
three of fourteen captures were inspected. The browser covers the existing
classification workflow, not authority activation. The native gate separately
qualifies the inactive evaluator. Fresh hosted scans and the 50-outcome pipeline,
effect fencing and complete ingress activation remain required.
[SQL036 native evidence](../verification/held-metadata-authority-local.json) and
[integrated evidence](../verification/held-metadata-authority-integrated-local.json).
