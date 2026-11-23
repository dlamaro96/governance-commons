# Product status

Updated 23 November 2026. Governance Commons is a working **development preview**, not a completed enterprise product or supported release. Published checkpoint `b08b88d` corrects reference-prefix qualification and the protected-login schema boundary. The independent local reference022/023/024 scopes pass 158/194/263 native cases; protected authentication passes 15 native and 2 browser cases. Source security is verified with zero findings across 1,522 files. The new pipeline has confirmed SQL024 and protected-login failures, with the foundation job active; `main` can lag until protected CI and review permit merging. The preceding checkpoint passes 171 API cases and all 37 main browser journeys, while its two other gate failures remain recorded.

## Implemented workflows with scoped local evidence

- OIDC login and server-side sessions; tenant-scoped PostgreSQL/API checks; ownership, audit and transactional outbox.
- Real PostgreSQL metadata scans, authorized catalog search, asset details and source registration.
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
| Quality, lineage and semantics | The hosted 37-journey browser suite passes; the preceding aggregate failed two gates, and the corrected revision exposes a SQL024 lifecycle timeout under repair. Schema/distribution drift, remaining rule families, filters/partition scope, anomaly baselines and aggregation remain; broader SQL/OpenLineage/column lineage and semantic modelling remain. |
| Contracts, products and access | Contract lifecycle, data-product marketplace, source grant/revoke/expiry/drift reconciliation and bounded SQL notebooks. |
| AI and MCP | AI registry/evaluations, permission-filtered context assistant, authenticated MCP server and governed tool gateway. |
| Documents and privacy | Document/version/ACL/delete propagation, privacy registers and assessments, cross-system evidence and complete portable migration. |
| Integrations | The complete named connector inventory. Unity metadata adapter code exists; live Databricks and its other capability routes remain unqualified. A generic connector does not complete named integrations. |
| Operations and release | Clean-install reproduction, Kubernetes/OpenShift and offline profiles, backup/restore, upgrades, performance/soak tests, final artifact scans/SBOM/signing/provenance and independent security/accessibility reviews. |

There are 354 named baseline requirements plus their detailed and supplemental tracking records (1,106 total). The register marks 128 records in progress and 978 not started; these are scope-tracking states, **not a percentage-complete estimate**. All 5,530 per-record verification outcomes remain `NOT_RUN`; narrower evidence is attached separately. No whole baseline requirement is promoted solely because a narrower journey passes.

## Immediate delivery gates

1. Repair the two failed gates from the final `5d37594` pipeline (39 successes, two failures, four skips), then verify all 45 outcomes on the new revision. [Source security](../verification/source-security-5d37594.json) is fully verified across 1,518 source files with zero findings; this remains narrower than enterprise security or release readiness. The preceding `f7fc213` run failed with 30 successes, three failures and ten skips. SQL032 standalone scopes each pass 37 native cases, repaired019 passes 113, and the composed repaired024 chain passes 263 against 176 exact source inputs. Current SQL032 import passes five cases against 103 exact inputs. All 457 affected host controls pass, and the healthy local core has SQL032 applied with 300 application and 13 worker files verified. Historical failures remain unchanged.
2. All 171 API cases pass on SQL032 at `5d37594`. The hosted full 37 browser journeys pass. Qualify the reference-prefix compatibility correction and exact SQL001–032 protected-authentication gate. The previous API pass at `f3f21e5` and earlier 154-pass/process-abort result remain recorded. Full 37 attempt 16 failed with 24 passed, one failed and 12 unexecuted; its bindings and cleanup are verified. The [quality-target repair](../verification/quality-table-browser-repair-local.json) at `a1a2972` passes without retries/skips, with all four scrolled evidence captures inspected. Volume and classification targets also pass. The predecessor full 36 attempt 15 passed, with only three of 281 screenshots inspected; no complete visual or Arabic-language certification is implied.
3. Preserve the scoped volume 320/worker 15-check and authority 133/423 native evidence with exact source-equivalence limits. The authority-read optimization remains an inactive foundation; runtime policy activation and its broader obligations are unfinished.
4. Keep the README, requirement evidence, GitHub backlog and PR descriptions aligned with the tested implementation. Merge through protected checks; do not bypass red CI.
5. Continue every workstream above through the [M0–M10 delivery plan](../execution/PLAN.md) and [GitHub delivery backlog](https://github.com/dlamaro96/governance-commons/issues?q=is%3Aissue%20is%3Aopen). The [requirement-to-issue mapping](../execution/backlog.json) covers all 1,106 records.

External vendor accounts, licensed infrastructure and independent human reviews are explicit qualification prerequisites. They do not excuse missing adapter code or locally executable work. Optional runtime activation also does not make required implementation optional.

The reference022 correction now passes all 158 native cases with 163 exact candidate inputs, 26 process startup/exit proofs, preservation/replay and owned cleanup verified. All 270 affected host controls pass. Independent SQL023/024 and protected immutable-image runs now pass; the full hosted aggregate remains pending. [Scoped correction evidence](../verification/pipeline-prefix-repair-local.json).

Latest correction evidence: [independent reference prefixes](../verification/reference-prefix-composition-b08b88d.json), [immutable protected login](../verification/protected-authentication-sql032-local.json), and [published source security](../verification/source-security-b08b88d.json). These do not activate the canonical content-authority foundation or complete the remaining capability programme.
