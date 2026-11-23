# Delivery plan

Updated 23 November 2026. The complete M0–M10 programme remains required. [Product status](../product/STATUS.md) identifies usable workflows and major gaps; [requirements.yaml](../product/requirements.yaml) remains the canonical scope and verification register.

## Active delivery sequence

1. Completed: all 45 development outcomes and source security pass at `e51e8ec`; five behavior archives and three stored analyses are verified. PR #23 merged normally as `0fc25d4`. Historical failures remain recorded.
2. Completed: PR #39 at `80101e0` passes all 45 development outcomes, source security and both native image scans. Five authenticated behavior archives verified before normal merge `fb1fd0e`; historical failures remain preserved.
3. Completed: PR #40 publishes the catalog navigation fix and inactive canonical asset-context reader. All 46 outcomes at exact head `4cbde6a` and authenticated artifacts pass; it merged normally as `ed0c6e4`. The 38 browser journeys and historical authority profiles remain separate.
4. SQL033 private monotone content revisions and same-snapshot versioned context pass isolated local qualification. All 172 current-schema API cases and seven focused browser journeys pass; PR #41 also passes its exact 47 hosted outcomes at `296d1e5` and merged normally as `1db2f71`. PR #42 runtime dependency fixes and receipt-backed startup pass their exact 47-outcome hosted qualification, source security and native image gates at `82859ad`; it merged normally as `9e60da8`, preserving exact replay/runtime/image bindings. SQL034 stable label identities pass their 50-case isolated gate, core migration, all 172 API cases and the expanded real classification browser journey. Qualify its separate 48-outcome hosted assignment. Implement the reviewed-classification fact producer, then compose the existing evaluator inside the held database snapshot. Runtime executor capabilities, revocation fences, field projections and all-ingress cutover remain required before activation.
5. Continue every milestone below. Qualify fork behavior before adding the runtime aggregate to enforced requirements; vendor credentials and independent reviews block only their own qualification.

## GitHub delivery backlog

The scoped pipeline issue #24 is closed. [Issues #25–#33](https://github.com/dlamaro96/governance-commons/issues?q=is%3Aissue%20is%3Aopen) cover identity, discovery, governance, quality, access, AI/MCP, privacy, connectors and release. [backlog.json](backlog.json) maps every canonical requirement to exactly one delivery workstream without duplicating its status. Existing scoped qualification issues retain their own acceptance criteria.

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
