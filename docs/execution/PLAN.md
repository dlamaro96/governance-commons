# Delivery plan

Updated 23 November 2026. The complete M0–M10 programme remains required. [Product status](../product/STATUS.md) identifies usable workflows and major gaps; [requirements.yaml](../product/requirements.yaml) remains the canonical scope and verification register.

## Active delivery sequence

1. Completed: all 45 development outcomes and source security pass at `e51e8ec`; five behavior archives and three stored analyses are verified. PR #23 merged normally as `0fc25d4`. Historical failures remain recorded.
2. Publish the separate runtime-security increment (`15496e3`) and qualify both native Linux architectures. Local evidence covers exact image scans, worker tests, PostgreSQL TLS, API/browser smoke and a clean committed-image protected-login run.
3. Complete the security PR through the normal required checks. Qualify hosted and fork behavior before adding the new runtime aggregate to enforced requirements; no gate bypass or independent sign-off is inferred.
4. Continue canonical authorization, remaining quality/lineage and every milestone below. Vendor credentials and independent reviews block only their own qualification; executable implementation continues.

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
