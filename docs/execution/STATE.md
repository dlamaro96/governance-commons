# Current state

Updated 23 November 2026. **Development preview; the complete product programme and release qualification remain open.** [PR #23](https://github.com/dlamaro96/governance-commons/pull/23) merged normally as `0fc25d4` after all 45 required outcomes passed at `e51e8ec`. Five authenticated archives, exact Git sources, 171 API cases, 35 inactive-authentication cases, 37 main browser journeys and protected login (15 native checks and two browser journeys) are verified. Four hosted captures were inspected. [Hosted record](../verification/hosted-checkpoint-e51e8ec.json).

Source security at `e51e8ec` verifies all 1,530 files and three stored analyses with zero findings. [Source record](../verification/source-security-e51e8ec.json). The runtime-security implementation is committed separately as `15496e3`; its later hosted qualification is scoped below.

The preceding `b08b88d` development run completed with **42 successful outcomes, two failures and one dependent skip** across the exact 45-outcome assignment. All 171 API cases, 35 inactive-authentication cases and 37 main browser journeys pass. SQL024 exhausted its inherited 600-second lifecycle; protected login stopped during admission. Five authenticated archives, exact Git sources and static test coordinates are verified. [Completed hosted record](../verification/hosted-checkpoint-b08b88d.json).

## Runtime security increment in validation

The separate `codex/runtime-image-security` branch follows published checkpoint
`e51e8ec`. Its minimal Node and Python images run a healthy core stack. The exact
local images pass pinned Trivy scans with zero high/critical findings; all 39
lower/unknown application findings and 11 lower worker findings remain visible.
Real PostgreSQL TLS passes 12 checks; all 285 worker tests and seven source
conformance checks pass in the running worker. These are local arm64 observations.

The first API smoke attempt could not start because the minimal image lacks GNU
`timeout`; no API cases ran or passed in that attempt. A Node supervisor now keeps
the original 1,740-second deadline, ten-second termination grace and 1,800-second
host limit. Seven real process controls pass; the rerun passes all 171 API cases and both real
Keycloak/source-scan browser journeys. All three captures were inspected.
[Scoped local evidence](../verification/runtime-images-local.json).
The new [image-security workflow](../../.github/workflows/runtime-security.yml) passes on native Linux amd64 and arm64 at `a6cd20d`. Both authenticated archives and all four full image reports are verified: zero high/critical findings, with every lower/unknown finding retained. [Hosted image record](../verification/runtime-images-hosted-a6cd20d.json). Required-check/fork qualification and supported-release qualification remain pending.

[PR #39](https://github.com/dlamaro96/governance-commons/pull/39) remains open. Its broader development run exposed GNU-only timeout flags in the Alpine worker test launchers. The correction preserves all durations and the three-second kill grace. Seven real worker gates and 82 host controls pass locally, plus normal/TERM/KILL process probes. Lineage initially refused its old image source and passed after the worker-only rebuild. [Correction and retained failures](../verification/runtime-worker-timeout-local.json). Fresh hosted regression remains required. [Runtime decision](../adr/0019-minimal-runtime-images.md).

A clean core rebuild of `15496e3` matches all 300 application and 13 worker files and the 32-row migration ledger. Its exact immutable image passes protected authentication: 15 native checks, both real Keycloak journeys, 203 Git inputs and every cleanup check. Two local captures were inspected. This is separate from the earlier candidate scans and API execution. [Committed-image record](../verification/runtime-protected-authentication-15496e3.json).

The `62b834c` secret job flagged 14 source digests whose path keys included security-related words. Each value equals the SHA-256 of its named immutable Git source. The current record now uses explicit `path`/`sha256` fields; only those exact historical fingerprints are dispositioned. Five native scanner controls and a fresh worktree/history scan pass, including controls that retain detection at changed paths/revisions and for a credential fixture. [Disposition record](../verification/runtime-worker-hash-dispositions.json). This does not excuse a fresh hosted scan.

## Catalog ordering increment

Catalog order now applies to the complete authorized candidate set before pagination, using canonical PostgreSQL names and update timestamps. All three orders bind the cursor; changing order resets the page. The desktop source column stays within the table layout. [Search contract](../runbooks/catalog-search.md).

The local candidate passes 20 targeted search unit cases, all 172 API cases and five real browser journeys. All three new desktop/mobile/Arabic captures were inspected. Exact image readback matches 303 application files and 33 worker source/test files; four application containers use those images. Type checks and 134 evidence/28 shard controls pass. The hosted assignment now requires 38 main browser journeys across the existing 45 outcomes. These runs have dirty-tree source bindings and do not qualify a later clean revision. [Exact sources, images and limitations](../verification/catalog-global-sorting-local.json).

## Current corrections

The SQL024 correction passes all 263 native cases across 13 invocations, with 176 measured inputs and 37 process startup/exit proofs. All 112 canonical tables, prior migration ledgers, SQL032 replay and owned cleanup are preserved. Local elapsed time fell from 545 to 387 seconds and command logs from 4,114 to 2,407. These are single local observations, not a hosted performance claim. Batches contain at most 16 unchanged row-hash statements in a read-only repeatable-read transaction; the 600-second lifecycle, 120-second command and 4 MiB output bounds remain unchanged. All 77 affected host controls pass. [Scoped evidence](../verification/reference-snapshot-batching-local.json).

The installed Linux Chromium executable is 311,672,136 bytes, exceeding the old 256 MiB hashing cap. A shared streaming helper now admits regular files up to 512 MiB in 1 MiB chunks, refusing symlinks, empty/nonregular files and changes during hashing. Process memory, output and time budgets remain unchanged. All 17 process, 12 bootstrap and 27 publication controls pass. The original hosted private failure phase was unavailable; the deterministic size incompatibility is identified separately. [Admission evidence](../verification/protected-linux-tool-admission-local.json).

Fresh immutable-image protected authentication at `5d9e501` passes **15 native HTTP/database checks and both real Keycloak browser journeys**, without retries or skips. All 203 inputs match Git and the unmounted image; the 32-row migration ledger is unchanged and all cleanup checks pass. Two of eight captures were inspected. This local macOS/arm64-services run does not substitute for Linux hosted qualification. [Runtime evidence](../verification/protected-authentication-tool-admission-local.json).

## Product and runtime

The healthy Docker Compose core runs real PostgreSQL, OpenSearch, Temporal, Keycloak and source workers with synthetic data. The latest images contain the catalog ordering candidate and portable worker timeout correction; their exact dirty-tree bindings are recorded above. Earlier observations retain their original revisions. Applied SQL001–032 migrations are immutable.

Usable workflows include tenant-scoped catalog/search/ownership/audit, operating models and graph migrations, glossary/reference publication and imports, reviewed classification, PostgreSQL view lineage, and six source-executed quality families. Scheduled quality incidents support notification, verified resolution and reopening; expired freshness evidence remains historical without authorizing a new resolution.

Canonical content authority remains an inactive foundation. The full [product status](../product/STATUS.md), frozen [specification](../product/BUILD_SPEC.md) and canonical [requirements](../product/requirements.yaml) retain every required workstream. Narrow passes do not complete whole requirements or authorize a supported release.

## Other retained qualification

| Scope | Recorded result |
|---|---|
| Source security at `b08b88d` | All 1,522 committed files, three authenticated archives and three stored analyses verified; zero JavaScript/TypeScript, Python or Actions findings on attempt 2. Attempt 1's Actions installer failure is retained. [Record](../verification/source-security-b08b88d.json). Fresh revision scanning remains required. |
| Independent reference prefixes at `b08b88d` | SQL022/023/024 pass 158/194/263 native cases respectively. These overlapping counts are not a unique-test total. [Record](../verification/reference-prefix-composition-b08b88d.json). |
| SQL032 repair | Original/current standalone scopes each pass 37 cases; repaired019 passes 113 and the composed repaired024 chain passes 263. Preservation, replay and cleanup are independently scoped. [Record](../verification/relation-candidate-repair-local.json). |
| Current reference import | Five real PostgreSQL import cases on SQL001–032, with 103 exact inputs and owned cleanup. This is service qualification, not HTTP, scanner or browser coverage. |
| Authority read | Original SQL001–013 plus SQL031 passes 133 cases; populated SQL001–030 plus SQL031 passes 423. Original limits, preservation and cleanup remain mandatory. This does not activate content authority. |
| Table volume | Isolated upgrade passes 320 cases; the real PostgreSQL worker passes 15 checks. Its browser lifecycle passes, with all 18 captures inspected. |
| Scheduled freshness | Isolated upgrade passes 276 cases; the real browser failure/recovery/reopening/expiry journey passes. Historical evidence eligibility remains fenced. |

Earlier failed and passing attempts retain their original source bindings in the [evidence manifest](../verification/evidence-manifest.json). In particular, `5d37594` completed with 39 successes, two failures and four skips; `f7fc213` completed with 30 successes, three failures and ten skips. The earlier local main-browser attempt 16 remains failed despite subsequent hosted passes. No historical result is relabelled.

## Delivery sequence

1. Integrate catalog ordering and the scoped hash-record correction into PR #39. Qualify its exact final revision through both native Linux image builds, source analysis and all 45 development outcomes, including 38 main browser journeys. Inspect any failure before advancing.
2. Keep the new security checks distinct from enforced branch requirements until hosted and fork qualification is complete. The preceding development PR is merged without bypassing its required checks.
3. Continue canonical authorization and the remaining M0–M10 implementation in the [delivery plan](PLAN.md). Vendor credentials and independent reviews block only their own qualification; they do not excuse unfinished required code.

[Issues #24–#33](https://github.com/dlamaro96/governance-commons/issues?q=is%3Aissue%20is%3Aopen) cover the delivery workstreams; [backlog.json](backlog.json) maps all 1,106 requirements exactly once. Qualification issues #11–#13 remain open. PR #22 is closed unmerged and superseded by #23 without rewriting history. Scoped issue #10 is closed; broader model and authority obligations remain open. Dependency PRs #1, #2 and #5 are closed as superseded by the published updates.

Public documentation removes obsolete internal handoff instructions while preserving technical contracts, the complete specification and historical evidence. Public-content checks and pinned worktree/history secret scans pass; the latter initially flagged two labelled source hashes and passed after their schema was made explicit, without scanner suppression. Independent security, accessibility, deployment/restore and release qualifications remain open under [release readiness](../release/READINESS.md).
