# Current state

Updated 17 November 2026. **Development preview; full programme and release qualification remain open.** The active integration branch is `codex/unity-catalog`, in [PR #23](https://github.com/dlamaro96/governance-commons/pull/23), targeting `main`. Published checkpoint `0b48592` includes SQL029, pinned CI Action updates and the refreshed public documentation. The five-runner CI change and browser admission repair are locally validated and awaiting publication.

## Product and runtime

The Docker Compose core runs real PostgreSQL, OpenSearch, Temporal, Keycloak and source workers with synthetic data. SQL001–029 is applied locally; applied migrations are immutable. Current workflows include catalog/search/ownership/audit, operating models and graph migrations, glossary/reference publication and imports, metadata classification, PostgreSQL view lineage, and five source-executed quality families. Scheduled quality incidents support notification, verified resolution and reopening; an expired freshness pass remains in immutable history without authorizing a new resolution.

[Product status](../product/STATUS.md) describes usable scope and the remaining work. [BUILD_SPEC.md](../product/BUILD_SPEC.md) and [requirements.yaml](../product/requirements.yaml) retain the complete programme. Implementation, execution evidence and release readiness remain separate.

## Current validation

| Gate | Actual result and scope |
|---|---|
| Scheduled freshness upgrade | 276 real isolated native cases pass across 18 phases, with predecessor preservation and owned-resource cleanup. |
| Current API | All 168 cases pass, with no failures or skips and matching baked test sources. |
| Host checks | 1,103 unit cases, root/web type checks and production build pass. |
| Freshness lifecycle browser | One real scheduled failure/recovery/reopening/expiry journey passes without retries or skips. All eight original English/Arabic captures inspected with viewport limitations. |
| Reference workflow picker | Repaired target journey passes without retries or skips. Two of its 12 captures were inspected in this attempt. |
| Full browser regression | Current 36-journey attempt14 records 31 passed, one uniqueness-quality failure and four skipped. Its recorded UI shows request-rate refusal; diagnosis is in progress. Sources stayed unchanged, original screenshots were restored and browser cleanup passed. The repaired uniqueness target passes with all eight English/Arabic captures inspected; fresh full36 attempt15 is running. Earlier full35 attempt13 remains failed: 27 passed, one failed and seven skipped. |
| Published source security | [Run44027780524](https://github.com/dlamaro96/governance-commons/actions/runs/44027780524) passes exact-source JavaScript/TypeScript, Python and Actions analyses for `fca6bb94`. This is not a container/dependency or enterprise-security qualification. |
| Published integration CI | [Run44027780537](https://github.com/dlamaro96/governance-commons/actions/runs/44027780537) passes 168 API cases, then fails the 512-origin authority-loader SQL closure at the existing 25-second deadline. Later stages are unexecuted. Profiling identifies repeated registry validation as the dominant cost. A forward migration and fresh qualification remain required under [#24](https://github.com/dlamaro96/governance-commons/issues/24). |

Exact source/image bindings and historical results belong in the [evidence manifest](../verification/evidence-manifest.json). [Manual freshness](../verification/product-quality-freshness-local.json) and [scheduled freshness](../verification/product-quality-freshness-scheduling-local.json) record their exact source-bound local checks. No whole requirement or release status is promoted by these narrower passes.

## Next product increment

Table-volume quality remains isolated and is not applied to core. Its corrected forward-upgrade gate passes all 320 cases with predecessor preservation, replay and owned-resource cleanup. Its real worker passes 15 checks with eight measurements; the fixture passes 29 checks. Earlier SQL parsing and fixture-assertion failures remain retained. The composed source tree separately passes 320 upgrade cases and the real worker check. Its historical SQL019 gate fails an inherited SQL018 glossary-population budget assertion before SQL019 tests execute; that failure and owned-resource cleanup are retained. Diagnose and repair the affected path before continuing historical gates and combined UI/browser qualification.

## Repository and delivery

[PR #23](https://github.com/dlamaro96/governance-commons/pull/23) contains all commits from superseded [#22](https://github.com/dlamaro96/governance-commons/pull/22); #22 is closed without merging or rewriting history. #23 stays draft while checks fail. [Issue #10](https://github.com/dlamaro96/governance-commons/issues/10) is closed against its scoped relation-migration evidence; broader model and authority obligations remain open.

[Issues #24–#33](https://github.com/dlamaro96/governance-commons/issues?q=is%3Aissue%20is%3Aopen) cover the active delivery workstreams. [backlog.json](backlog.json) maps all 1,106 requirement records exactly once. Qualification issues #11–#13 remain open. Dependency PRs #1, #2 and #5 are closed without merging as superseded by the published exact updates; hosted setup/upload checks and downloaded artifact verification passed. No protection or failing check was bypassed.

Continue the [delivery plan](PLAN.md): repair hosted CI, finish current browser qualification, publish this checked increment, finish table volume, and deliver the remaining M0–M10 capabilities. External credentials or independent reviewers block only their own qualification; required implementation continues. [Release readiness](../release/READINESS.md) records the broader release gates. Historical state is preserved in Git.

## Pipeline repair in progress

The fixed five-runner CI groups retain all 40 mandatory outcomes and the stable `required` check; 156 host controls pass, with separate independent source review. Hosted execution is pending. [ADR 0016](../adr/0016-fixed-ci-shards.md) records the decision.

A private SQL031 authority-read optimization retains the original per-grant validations and 25-second SQL/30-second operation limits. Its first original-prefix native run passes all 123 original assertions, including the previously failing loader case, but two of ten new fixtures fail during registry installation: 131 passed, two failed. A fixture-digest correction and complete fresh original/current-prefix qualification are still required. SQL031 is not applied to core.
