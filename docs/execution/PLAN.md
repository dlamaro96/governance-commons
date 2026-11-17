# Delivery plan

Updated 17 November 2026. The complete M0–M10 programme remains required. [Product status](../product/STATUS.md) identifies usable workflows and major gaps; [requirements.yaml](../product/requirements.yaml) remains the canonical scope and verification register.

## Active delivery sequence

1. Repair the remaining hosted paths. The latest published checkpoint `f7fc213` has 43 mandatory CI outcomes; development execution is in progress with known failures in governance population, the quality-basics completeness upgrade and browser acceptance. Complete development evidence remains pending. Source security is independently verified against all 1,502 exact source files, with zero findings. Preserve the earlier `2186dcb` failures and their evidence.
2. Complete integration checks after the test repairs through `a1a2972`. SQL001–031 is applied and running images match 299 application and 13 worker source files. All 1,126 host unit cases and 171 API cases pass; the preceding 154-pass API attempt with a process abort remains recorded. Full 37 attempt 16 failed with 24 passes, one obsolete table-refusal assertion and 12 unexecuted journeys. Its 692 source bindings, 187 artifacts, 154 restored tracked captures and cleanup are verified. The repaired quality target passes 1/1 with four inspected scrolled evidence captures; the volume and classification targets also pass. Run the full 37 graph again; targeted passes do not replace it.
3. Retain independently qualified storage/source evidence: volume 320 and the real worker 15-check/eight-measurement run, plus SQL031 original-prefix 133 and current-prefix 423 native cases. Preserve their limits, replay and cleanup evidence and subsequent source-equivalence records. These paths do not call the failing relation/glossary code; their passes do not waive historical or release gates. SQL032 and the 45-outcome composition are committed at `fabc708`; 457 affected host controls pass. The two standalone scopes each pass 37 native cases, and the frozen repaired019 chain passes 113. Finish the running composed024 qualification and current-import32 check before shared SQL032 adoption. No broader outcome is inferred.
4. Publish coherent development changes with exact-source evidence, current support status and an actionable backlog. The configured pipeline has 45 outcomes; the preceding published revision has 43. Publish the checked development increment with its pending native/runtime scopes explicit, then verify fresh hosted execution. Keep PR #23 draft while required checks fail; do not bypass protected merge or release gates.
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
