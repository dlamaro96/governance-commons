# Product status

Updated 23 November 2026. Governance Commons is a working **development preview**, not a completed enterprise product or supported release. PR #23 merged as `0fc25d4` after all 45 required outcomes and source scanning passed at `e51e8ec`. The separate runtime-security PR #39 passes both native image scans at `a6cd20d`; its broader regression exposed a worker-launcher compatibility issue. A local correction passes all seven affected real worker gates and awaits fresh hosted regression. See [current state](../execution/STATE.md) and the exact [hosted checkpoint](../verification/hosted-checkpoint-e51e8ec.json).
## Implemented workflows with scoped local evidence

- OIDC login and server-side sessions; tenant-scoped PostgreSQL/API checks; ownership, audit and transactional outbox.
- Real PostgreSQL metadata scans, authorized catalog search, asset details and source registration. Global name/recent-update ordering across pages passes 172 local API cases and five targeted browser journeys; fresh hosted qualification is pending. [Scoped ordering evidence](../verification/catalog-global-sorting-local.json).
- Versioned operating models, inherited types, constrained relations, bounded graph migrations and business domains.
- Reviewed glossary publication; reference code lists, effective dates, historical reads, exports, hierarchy/crosswalk and import workflows.
- PostgreSQL view-dependency lineage and reviewed metadata classification.
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
| Quality, lineage and semantics | The merged checkpoint passes its full 37-journey browser suite and all 45 outcomes. The new runtime and catalog increment requires fresh qualification. Schema/distribution drift, remaining rule families, filters/partition scope, anomaly baselines and aggregation remain; broader SQL/OpenLineage/column lineage and semantic modelling remain. |
| Contracts, products and access | Contract lifecycle, data-product marketplace, source grant/revoke/expiry/drift reconciliation and bounded SQL notebooks. |
| AI and MCP | AI registry/evaluations, permission-filtered context assistant, authenticated MCP server and governed tool gateway. |
| Documents and privacy | Document/version/ACL/delete propagation, privacy registers and assessments, cross-system evidence and complete portable migration. |
| Integrations | The complete named connector inventory. Unity metadata adapter code exists; live Databricks and its other capability routes remain unqualified. A generic connector does not complete named integrations. |
| Operations and release | Clean-install reproduction, Kubernetes/OpenShift and offline profiles, backup/restore, upgrades, performance/soak tests, final artifact scans/SBOM/signing/provenance and independent security/accessibility reviews. |

There are 354 named baseline requirements plus their detailed and supplemental tracking records (1,106 total). The register marks 132 records in progress and 974 not started; these are scope-tracking states, **not a percentage-complete estimate**. All 5,530 per-record verification outcomes remain `NOT_RUN`; narrower evidence is attached separately. No whole baseline requirement is promoted solely because a narrower journey passes.

## Immediate delivery gates

1. Complete PR #39's hosted regression after the portable worker-timeout correction. Keep its earlier failure and passing image scans separately bound to their executed revisions.
2. Qualify the runtime-security aggregate for fork use before adding it to enforced branch requirements. No scan alone completes security or release acceptance.
3. Preserve the separately scoped volume, freshness, authority, reference and import evidence. The authority-read foundation remains inactive across content APIs.
4. Keep the README, canonical register, GitHub backlog and PR descriptions aligned with executed behavior. Merge through protected checks.
5. Continue every workstream above through the [M0–M10 delivery plan](../execution/PLAN.md). The [requirement-to-issue mapping](../execution/backlog.json) covers all 1,106 records.

External vendor accounts, licensed infrastructure and independent human reviews are explicit qualification prerequisites. They do not excuse missing adapter code or locally executable work. Optional runtime activation also does not make required implementation optional.
