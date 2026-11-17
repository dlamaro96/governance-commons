# Delivery plan

Updated 17 November 2026. The complete M0–M10 programme remains required. [Product status](../product/STATUS.md) identifies usable workflows and major gaps; [requirements.yaml](../product/requirements.yaml) remains the canonical scope and verification register.

## Active delivery sequence

1. Restore green integration CI: qualify the forward authority-read repair without increasing the SQL013 limits; preserve failed evidence. Publish and verify the five fixed CI groups. Verify all historical quality gates against their declared source/schema versions.
2. Complete scheduled-freshness regression: SQL001–029 is applied locally; 276 native cases, 1,103 host cases, types/build and the real freshness lifecycle journey pass. The repaired reference picker and protected outbox target also pass. All 168 current API cases pass; the full 36-journey attempt records 31 passed, one uniqueness-quality failure and four skipped. Repair and rerun the affected journey, then the complete profile.
3. Finish table-volume integration: the composed 320-case SQL029→030 upgrade, real worker (15 checks/eight measurements) and fixture (29 checks) pass. The historical SQL019 gate exposes an inherited glossary-population budget failure; fix and qualify it before the remaining historical gates and combined application/browser checks. No shared SQL030 application is yet claimed.
4. Publish coherent development changes with exact-source evidence, current README/support status and a small actionable GitHub backlog. Consolidate superseded integration PRs without discarding history. Do not merge failed checks or publish a supported release.
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
