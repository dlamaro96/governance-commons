# Delivery plan

Updated 23 November 2026. The complete M0–M10 programme remains required. [Product status](../product/STATUS.md) identifies usable workflows and major gaps; [requirements.yaml](../product/requirements.yaml) remains the canonical scope and verification register.

## Active delivery sequence

1. Repair and independently qualify the two failed gates in the published `5d37594` pipeline: reference022 and protected authentication. The final result is 39 successes, two failures and four skips across exactly 45 outcomes; all five authenticated archives and source bindings are verified. The local reference022 reproduction exposed incompatible approval/repository modules at SQL022. Adopt explicit immutable predecessor bindings for SQL022/023 and verify that SQL024 composition still passes. Protected authentication must admit and execute the exact current SQL001–032 schema. Keep the original failed attempts.
2. The current API passes 171 cases and hosted browser acceptance passes all 37 journeys without retries. Three of 22 published screenshots were visually inspected with fixed-viewport limitations. Source security separately verifies 1,518 source files with zero findings. Preserve the earlier local browser failure and every source-equivalence limit. Publish the checked gate fixes and verify a fresh complete pipeline; no aggregate pass is implied by the successful browser or source scans.
3. Retain the exact local repair evidence: SQL032 standalone scopes each pass 37 cases, repaired019 passes 113, and the final composed repaired024 chain passes 263 with 176 exact source inputs. Current import on SQL001–032 passes five cases with 103 exact inputs. All 457 affected host controls pass. Volume 320/worker 15-check and SQL031 133/423 evidence retain their original source-equivalence limits. None changes historical failed results or waives a release gate.
4. Keep published development changes, support status, evidence and the actionable backlog aligned. SQL032 and CI45 are committed at `fabc708` and published in `5d37594`; the current gate repairs and subsequent runtime/hosted outcomes must be recorded when executed. Keep PR #23 draft while required checks fail; do not bypass protected merge or release gates.
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

The reference022 correction now passes all 158 native cases with 163 exact candidate inputs, 26 process startup/exit proofs, preservation/replay and owned cleanup verified. All 270 affected host controls pass. Fresh SQL023/024 hosted and protected immutable-image execution remain pending. [Scoped correction evidence](../verification/pipeline-prefix-repair-local.json).
