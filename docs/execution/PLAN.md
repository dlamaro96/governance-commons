# Delivery plan

Updated 17 November 2026. The complete M0–M10 programme remains required. [Product status](../product/STATUS.md) identifies usable workflows and major gaps; [requirements.yaml](../product/requirements.yaml) remains the canonical scope and verification register.

## Active delivery sequence

1. Repair the affected historical and hosted paths. The published five-runner CI at `2186dcb` records failures in governance population, the quality-basics completeness upgrade and browser acceptance; exact-source artifact verification is complete. The classification failure is a request-budget refusal; the completeness-upgrade cause remains unknown. The historical SQL018 population budget failure remains open. Diagnose each exact result, implement forward repairs and retain the original assertions and deadlines.
2. Complete integration checks for product checkpoint `514ddee` and subsequent test repairs through `f3f21e5`. SQL001–031 is applied and running images match 299 application and 13 worker source files. All 1,126 host unit cases pass. The API regression fails after 154 passing cases and one test-file abort: 155 results against 168 expected. The bounded rollback-snapshot repair is committed; all 171 API cases pass, including three new real database regression cases. The preceding full 36 browser attempt15 at `ac464af` passes without retries or skips, with only three of 281 captures visually inspected. The new volume and repaired classification targets pass. The full 37-journey graph is now running after the API fixture repair.
3. Retain the independently qualified storage/source evidence: volume passes the 320-case upgrade and real worker checks (15 checks/eight measurements). SQL031 passes original-prefix133 and current-prefix423 native cases, with unchanged limits, preservation/replay and cleanup. Later CI/documentation/harness changes require explicit source-equivalence records. These independent paths do not call the failing relation/glossary code; proceeding with them does not waive the historical or release gates.
4. Publish coherent development changes after the affected checks, with exact-source evidence, current support status and an actionable backlog. Local CI has 43 mandatory outcomes; the published configuration still has 40. Verify fresh hosted execution after publication. Do not merge failed checks or publish a supported release.
5. Continue canonical authorization, remaining quality/lineage and every milestone below. Vendor credentials and independent reviews block only their own qualification; executable implementation continues.

## GitHub delivery backlog

[Issues #24–#33](https://github.com/dlamaro96/governance-commons/issues?q=is%3Aissue%20is%3Aopen) cover pipeline repair, identity, discovery, governance, quality, access, AI/MCP, privacy, connectors and release. [backlog.json](backlog.json) maps every canonical requirement to exactly one delivery workstream without duplicating its status. Existing scoped qualification issues retain their own acceptance criteria.

## Programme milestones

| Milestone | Required delivery |
|---|---|
| M0 | Repository/licence, inventory, contracts, architecture, threat model, CI and reproducible local infrastructure. |
| M1 | Identity, tenant isolation, audit/outbox, minimal operating model and the real catalog vertical slice. |
| M2 | Design system, discovery/detail experiences, glossary, governance and reference data. |
| M3 | Durable workflows and BPMN/forms, assessments, issues, notifications and configurable operating model. |
| M4 | Lineage, contracts, data products/marketplace and real quality execution. |
| M5 | Source access requests, grants, revocation, reconciliation and bounded notebooks. |
| M6 | AI registry/evaluations/context assistant and authenticated MCP server/tool gateway. |
| M7 | Documents, privacy, cross-system evidence, portable migration and advanced differentiators. |
| M8 | Every frozen named connector family, local conformance and explicit live qualification prerequisites. |
| M9 | Enterprise packaging, Kubernetes/OpenShift, scaling, upgrades, restore, offline delivery and observability. |
| M10 | Independent reviews, signed reproducible release artifacts, documentation and contributor onboarding. |

M8 proceeds alongside product work; operational, security and accessibility requirements apply throughout. The milestone exit criteria in [BUILD_SPEC.md](../product/BUILD_SPEC.md#9-implementation-milestones-and-completion-discipline) remain authoritative.

## Completion rules

A vertical slice includes its real UI, API, persistence, worker and authorization behavior. Validate types/schemas, domain invariants, real database/source execution and browser workflows before advancing its affected milestone. Failure, missing credentials and skipped execution retain separate statuses. Bind evidence to the actual revision/image and preserve historical failures.

Historical plans remain in Git history. Evidence records retain their original revision and scope.
