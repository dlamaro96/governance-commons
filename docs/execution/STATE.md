# Current state

Updated 17 November 2026. **Development preview; full programme and release qualification remain open.** The active integration branch is `codex/unity-catalog`, in [PR #23](https://github.com/dlamaro96/governance-commons/pull/23), targeting `main`. The latest hosted-qualified checkpoint `2186dcb` contains the five-runner CI configuration with 40 required outcomes. Product checkpoint `514ddee` adds table-volume quality, the authority-read optimization and 43 required CI outcomes. The classification test-only request-budget repair is committed at `a5e3019`; `f3f21e5` adds bounded rollback snapshots and three real database regression cases. Hosted source security and development artifacts are qualified for the published revision; failures and skipped gates are retained.

## Product and runtime

The Docker Compose core runs real PostgreSQL, OpenSearch, Temporal, Keycloak and source workers with synthetic data. SQL001–031 is applied locally; all applied migrations are immutable. Running-image readback matches 299 application and 13 worker source files. Current workflows include catalog/search/ownership/audit, operating models and graph migrations, glossary/reference publication and imports, metadata classification, PostgreSQL view lineage, and six implemented source-executed quality families. Table volume has isolated storage/worker evidence and a passing real browser lifecycle journey; all 171 current API cases pass, and the full 37-journey browser regression is running.

Scheduled quality incidents support notification, verified resolution and reopening; an expired freshness pass remains in immutable history without authorizing a new resolution. SQL031 reduces repeated registry validation inside the inactive authority loader. It does not activate canonical authority across content APIs or complete the remaining policy work.

[Product status](../product/STATUS.md) describes usable scope and the remaining work. [BUILD_SPEC.md](../product/BUILD_SPEC.md) and [requirements.yaml](../product/requirements.yaml) retain the complete programme. Implementation, execution evidence and release readiness remain separate.

## Current validation

| Gate | Actual result and scope |
|---|---|
| Scheduled freshness upgrade | 276 real isolated native cases pass across 18 phases, with predecessor preservation and owned-resource cleanup. |
| Current API | All 171 cases pass at `f3f21e5`, including three new real database snapshot regressions. The repaired fixture retains complete-row equality, duplicates and rollback assertions within the original 256 MiB process limit. The preceding 154-pass/test-process-abort attempt remains recorded. |
| Host checks | All 1,126 unit cases pass. The preceding sandbox invocation recorded 1,102 passed and 24 loopback-related failures; that failed result is retained. |
| Freshness lifecycle browser | One real scheduled failure/recovery/reopening/expiry journey passes without retries or skips. All eight original English/Arabic captures inspected with viewport limitations. |
| Reference workflow picker | Repaired target journey passes without retries or skips. Two of its 12 captures were inspected in this attempt. |
| Predecessor full browser | Attempt15 at `ac464af` passes all 36 journeys without retries or skips. Three of its 281 captures were visually inspected; this is a sample, not complete visual or Arabic-language certification. Earlier failures remain retained. |
| Classification browser repair | The request-budget admission repair passes its real target journey without retries or skips; four of 12 captures inspected. Full37 and hosted regression remain required. |
| Table-volume browser | The new target journey passes with no retries/skips. All18 English/Arabic captures were inspected with fixed-viewport limitations. The complete 37-journey graph is running. |
| Table-volume upgrade and source | Isolated SQL029→030 qualification passes 320 cases with preservation, replay and owned cleanup. The real PostgreSQL worker passes 15 checks with eight measurements. |
| Authority-read upgrade | Original SQL001–013 followed by SQL031 passes 133 cases; current SQL001–030 followed by SQL031 passes 423. Both preserve the original limits, validate preservation/replay and complete owned cleanup. They do not relabel the historical SQL013-only failure. |
| Published source security | [Run44042091992](https://github.com/dlamaro96/governance-commons/actions/runs/44042091992) passes exact-source JavaScript/TypeScript, Python and Actions analyses for `2186dcb`:1,466 source files rehashed, three authenticated archives and stored analyses verified, zero findings. This is not a container or enterprise-security qualification. |
| Latest published integration CI | At `2186dcb`,27 of 40 required outcomes pass, three fail and ten are skipped. Glossary publication exceeds its existing budget; classification approval polling hits HTTP 429. The completeness-upgrade cause remains unknown because its detailed native report is unavailable. [Verified hosted record](../verification/hosted-checkpoint-2186dcb.json). |
| Historical integration CI | [Run44027780537](https://github.com/dlamaro96/governance-commons/actions/runs/44027780537) passes 168 API cases, then fails the 512-origin authority-loader SQL closure at the existing 25-second deadline. This retained failure precedes SQL031. Fresh exact-revision hosted qualification remains required under [#24](https://github.com/dlamaro96/governance-commons/issues/24). |

Exact source/image bindings and historical results belong in the [evidence manifest](../verification/evidence-manifest.json). The volume and authority native runs used recorded source trees; subsequent CI, documentation and qualification-wrapper changes require explicit source-equivalence review. Their entire execution manifests are not described as byte-identical reruns of `514ddee`. [Manual freshness](../verification/product-quality-freshness-local.json) and [scheduled freshness](../verification/product-quality-freshness-scheduling-local.json) retain their original scope. No whole requirement or release status is promoted by these narrower passes.

## Remaining qualification and performance repair

The historical SQL019 gate still fails an inherited SQL018 glossary-population budget assertion before SQL019-specific tests execute. Diagnostic measurements identify repeated eligibility evaluation over unrelated assets; a filtered diagnostic pass is not a full historical-gate pass. Preserve the failed evidence and qualify a forward repair without changing the original deadlines or assertions.

SQL030 and SQL031 were qualified and applied independently because their volume and authority-read paths do not call the failing relation/glossary code. This permits progress on those independent paths; it does not waive the historical gate or release requirements. The expanded API regression passes after the bounded snapshot repair; complete the running full 37 browser graph before claiming integrated volume qualification. See the [volume developer guide](../development/table-volume-quality.md), [operator runbook](../runbooks/table-volume-quality.md) and [ADR0017](../adr/0017-invocation-local-authority-read-validation.md).

## Repository and delivery

[PR #23](https://github.com/dlamaro96/governance-commons/pull/23) contains all commits from superseded [#22](https://github.com/dlamaro96/governance-commons/pull/22); #22 is closed without merging or rewriting history. #23 stays draft while checks fail. [Issue #10](https://github.com/dlamaro96/governance-commons/issues/10) is closed against its scoped relation-migration evidence; broader model and authority obligations remain open.

[Issues #24–#33](https://github.com/dlamaro96/governance-commons/issues?q=is%3Aissue%20is%3Aopen) cover the active delivery workstreams. [backlog.json](backlog.json) maps all 1,106 requirement records exactly once. Qualification issues #11–#13 remain open. Dependency PRs #1, #2 and #5 are closed without merging as superseded by the published exact updates; hosted setup/upload checks and downloaded artifact verification passed. No protection or failing check was bypassed.

Continue the [delivery plan](PLAN.md): repair the affected historical path, complete current API/browser checks, verify hosted CI and publish a checked development increment, then continue the remaining M0–M10 capabilities. External credentials or independent reviewers block only their own qualification; required implementation continues. [Release readiness](../release/READINESS.md) records the broader release gates. Historical state is preserved in Git.

## Pipeline repair in progress

The published five-runner configuration retains 40 mandatory outcomes and the stable `required` check. `514ddee` extends the same fixed grouping to 43 outcomes for volume and authority-read qualification; fresh hosted execution is required. [ADR0016](../adr/0016-fixed-ci-shards.md) records the grouping decision. No new hosted pass is inferred from local execution.
