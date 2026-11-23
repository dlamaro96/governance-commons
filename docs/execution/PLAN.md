# Delivery plan

Updated 23 November 2026. The complete M0–M10 programme remains required. [Product status](../product/STATUS.md) identifies usable workflows and major gaps; [requirements.yaml](../product/requirements.yaml) remains the canonical scope and verification register.

## Active delivery sequence

1. Completed: all 45 development outcomes and source security pass at `e51e8ec`; five behavior archives and three stored analyses are verified. PR #23 merged normally as `0fc25d4`. Historical failures remain recorded.
2. Completed: PR #39 at `80101e0` passes all 45 development outcomes, source security and both native image scans. Five authenticated behavior archives verified before normal merge `fb1fd0e`; historical failures remain preserved.
3. Completed: PR #40 publishes the catalog navigation fix and inactive canonical asset-context reader. All 46 outcomes at exact head `4cbde6a` and authenticated artifacts pass; it merged normally as `ed0c6e4`. The 38 browser journeys and historical authority profiles remain separate.
4. SQL033 and the runtime dependency/startup increments are merged through PR #41 and PR #42 with their separate 47-outcome qualification. SQL034 stable label identities pass their 50-case native gate and core workflows. SQL035 reviewed classification provenance passes 98 native cases, 1,207 unit cases, 172 API cases and one real browser journey with 347 source/image bindings. Finish the open SQL034/SQL035 hosted assignments. PR #48's superseded `bc1f650` run remains cancelled; its fresh `7d91aae` qualification is separate. [Retained checkpoint](../verification/hosted-checkpoint-bc1f650-cancelled.json).
5. SQL036 aligns storage and evaluator scope checks and evaluates within the held database snapshot. All 140 isolated native cases and 1,257 unit cases pass. The rebuilt SQL036 core passes 172 API cases and one real classification browser journey with 349 source/image bindings; three of fourteen captures were inspected. Publish and qualify its separate 50-outcome pipeline and fresh source/image scans. Preserve incompatible retained history and require explicit remediation before upgrade. Effect/revocation fencing, field projections, compiled-filter equivalence and all-ingress cutover remain required before activation. [Native](../verification/held-metadata-authority-local.json) and [integrated](../verification/held-metadata-authority-integrated-local.json) evidence.
6. Continue every milestone below. Qualify fork behavior before adding the runtime aggregate to enforced requirements; vendor credentials and independent reviews block only their own qualification.

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
