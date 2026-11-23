# Current state

Updated 23 November 2026. **Development preview; the complete product programme and release qualification remain open.** [PR #23](https://github.com/dlamaro96/governance-commons/pull/23) merged normally as `0fc25d4` after all 45 required outcomes passed at `e51e8ec`. Five authenticated archives, exact Git sources, 171 API cases, 35 inactive-authentication cases, 37 main browser journeys and protected login (15 native checks and two browser journeys) are verified. Four hosted captures were inspected. [Hosted record](../verification/hosted-checkpoint-e51e8ec.json).

Source security at `e51e8ec` verifies all 1,530 files and three stored analyses with zero findings. [Source record](../verification/source-security-e51e8ec.json). The runtime-security implementation is committed separately as `15496e3`; its later hosted qualification is scoped below.

The preceding `b08b88d` development run completed with **42 successful outcomes, two failures and one dependent skip** across the exact 45-outcome assignment. All 171 API cases, 35 inactive-authentication cases and 37 main browser journeys pass. SQL024 exhausted its inherited 600-second lifecycle; protected login stopped during admission. Five authenticated archives, exact Git sources and static test coordinates are verified. [Completed hosted record](../verification/hosted-checkpoint-b08b88d.json).

## Published increment under qualification

[PR #39](https://github.com/dlamaro96/governance-commons/pull/39) publishes global
catalog sorting, minimal runtime images, portable worker deadlines and exact
historical source-hash dispositions at `80101e0`.

Source security passes with all 1,547 published files matched to Git and all three
stored CodeQL analyses verified, with zero findings. Both native Linux image jobs
pass: all four reports have zero high/critical findings. Application images retain
22 medium, 14 low and three unknown findings; worker images retain seven medium
and four low findings. These are scoped scan results, not complete security or
release qualification. [Source record](../verification/source-security-80101e0.json)
and [image record](../verification/runtime-images-hosted-80101e0.json).

Development run `45117553519` is still in progress at the last readback. Its
quality and secret jobs pass. All 45 required outcomes, 172 API cases, 35 inactive
authentication cases, 38 main browser journeys and protected login must finish
and have their artifacts verified before this revision is merged.

The local sorting candidate passes 20 targeted unit cases, all 172 API cases and
five real browser journeys. Its three desktop/mobile/Arabic captures were
inspected. Canonical PostgreSQL order applies before pagination; sort changes
reset the cursor. [Search contract](../runbooks/catalog-search.md) and
[exact local source/image evidence](../verification/catalog-global-sorting-local.json).

Earlier runtime failures remain recorded: the minimal application lacked GNU
`timeout`; worker launchers used GNU-only flags; and the secret scan flagged
14 values independently verified as source digests. Corrections preserve the
original deadlines and exact historical dispositions. No earlier failure is
relabeled. See [application runtime](../verification/runtime-images-local.json),
[worker deadline correction](../verification/runtime-worker-timeout-local.json)
and [hash dispositions](../verification/runtime-worker-hash-dispositions.json).

## Next implementation increment

Catalog pagination now restores bounded history across Back/Forward, reload and
browser return from an asset. Direct links and invalid history offer honest
“Current page” / “First page” recovery. The expanded real browser journey passes
with all three captures inspected. Its source binding is local and dirty;
hosted qualification remains separate. [Navigation evidence](../verification/catalog-navigation-local.json).

The inactive authority repository now composes protected identity and authority
closure with canonical asset, ACL, placement and current domain ancestry in one
read-only repeatable-read snapshot. It does not manufacture a security revision
or approved classification facts, change runtime privileges or activate content
authority. [Decision](../adr/0020-inactive-canonical-asset-context.md).
The isolated native gate passes all 13 cases with exact 249-source readback,
row/ledger/ACL preservation, replay and owned cleanup. All 1,151 unit cases and type checks pass. Three failed native attempts and
the preceding passing source snapshot remain recorded. The execution budget is
780 seconds, with 90 seconds for cleanup inside the 900-second wrapper. The next
development assignment adds a separate 46th required outcome; 134 evidence,
38 shard, 15 routing and three lifecycle controls pass. [Scoped evidence](../verification/authority-asset-context-local.json).
Hosted qualification of this next increment remains required.

## Current corrections

The SQL024 correction passes all 263 native cases across 13 invocations, with 176 measured inputs and 37 process startup/exit proofs. All 112 canonical tables, prior migration ledgers, SQL032 replay and owned cleanup are preserved. Local elapsed time fell from 545 to 387 seconds and command logs from 4,114 to 2,407. These are single local observations, not a hosted performance claim. Batches contain at most 16 unchanged row-hash statements in a read-only repeatable-read transaction; the 600-second lifecycle, 120-second command and 4 MiB output bounds remain unchanged. All 77 affected host controls pass. [Scoped evidence](../verification/reference-snapshot-batching-local.json).

The installed Linux Chromium executable is 311,672,136 bytes, exceeding the old 256 MiB hashing cap. A shared streaming helper now admits regular files up to 512 MiB in 1 MiB chunks, refusing symlinks, empty/nonregular files and changes during hashing. Process memory, output and time budgets remain unchanged. All 17 process, 12 bootstrap and 27 publication controls pass. The original hosted private failure phase was unavailable; the deterministic size incompatibility is identified separately. [Admission evidence](../verification/protected-linux-tool-admission-local.json).

Fresh immutable-image protected authentication at `5d9e501` passes **15 native HTTP/database checks and both real Keycloak browser journeys**, without retries or skips. All 203 inputs match Git and the unmounted image; the 32-row migration ledger is unchanged and all cleanup checks pass. Two of eight captures were inspected. This local macOS/arm64-services run does not substitute for Linux hosted qualification. [Runtime evidence](../verification/protected-authentication-tool-admission-local.json).

## Product and runtime

The healthy Docker Compose core runs real PostgreSQL, OpenSearch, Temporal, Keycloak and source workers with synthetic data. The latest core image contains the catalog navigation candidate; its browser evidence is separate from the isolated mounted-source authority checks. Earlier observations retain their original revisions. Applied SQL001–032 migrations are immutable.

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

1. Finish and verify the exact `80101e0` hosted development run, then merge PR #39 through protected checks.
2. Publish the locally verified navigation/context and its 46-outcome pipeline as the next increment.
3. Implement trusted content-security revisions, classification facts and a held-snapshot executor before any canonical authority activation. Continue the remaining M0–M10 workstreams in the [delivery plan](PLAN.md).
4. Qualify fork behavior before adding the new runtime security aggregate to enforced branch requirements. Independent reviews and live vendor prerequisites retain their own open qualifications.

[Issues #24–#33](https://github.com/dlamaro96/governance-commons/issues?q=is%3Aissue%20is%3Aopen) cover the delivery workstreams; [backlog.json](backlog.json) maps all 1,106 requirements exactly once. Qualification issues #11–#13 remain open. PR #22 is closed unmerged and superseded by #23 without rewriting history. Scoped issue #10 is closed; broader model and authority obligations remain open. Dependency PRs #1, #2 and #5 are closed as superseded by the published updates.

Public documentation removes obsolete internal handoff instructions while preserving technical contracts, the complete specification and historical evidence. Public-content checks and pinned worktree/history secret scans pass; the latter initially flagged two labelled source hashes and passed after their schema was made explicit, without scanner suppression. Independent security, accessibility, deployment/restore and release qualifications remain open under [release readiness](../release/READINESS.md).
