# Repository readiness

Current checkpoint, 17 November 2026: the project remains a development preview. [Product status](../product/STATUS.md), [delivery plan](../execution/PLAN.md) and [release readiness](../release/READINESS.md) describe the active implementation. Delivery issues #24–#33 are created and verified; [the mapping](../execution/backlog.json) covers all1,106 requirements. PR #23 targets main and supersedes closed #22 with every commit preserved; it remains draft. Latest published source security passes, but integration CI fails the authority-loader deadline after168 passing API cases. No merge or release qualification is claimed.

## Historical repository bootstrap — 15 November 2026

The evidence and settings below describe their recorded bootstrap dates, not a fresh read-back of every setting.

Repository: [dlamaro96/governance-commons](https://github.com/dlamaro96/governance-commons),
public, default branch `main`. Initial published commit:
`026611973a9fef5d02fb5a879beecf16fdcc44f3`.
Assessment date: 15 November 2026. Overall status: **development collaboration
available; full repository, security and release qualification incomplete**.

## Executed evidence

| Check | Result and scope | Evidence |
| --- | --- | --- |
| Initial CI | `quality` and `required` passed for the exact initial commit. These checks covered requirement validation, type checking, unit tests, web build and publication policy, not real-service behavior. | [Run 43727376708](https://github.com/dlamaro96/governance-commons/actions/runs/43727376708) |
| GitHub bootstrap apply | Created project-owned rulesets and enabled private vulnerability reporting/dependency alerts; preserved public visibility, `main` and existing history. Read-back completed at `2026-11-15T15:03:09Z`. | [Before/after JSON](repository-readiness.json) |
| Idempotent recheck | `apply` at `2026-11-15T15:14:03Z` produced **zero operations**. Full conditions/rules, bypass actors and application-bound required check were read back. | [Recheck JSON](repository-readiness-recheck.json) |
| Existing failed PRs | PRs 1 and 2 have failing `quality`/`required` and GitHub reports `BLOCKED`. Actual failed logs identify `unverified-action-pin`: the bot changed an Action revision without updating verified provenance. Neither PR was merged. | [PR 1](https://github.com/dlamaro96/governance-commons/pull/1), [PR 2](https://github.com/dlamaro96/governance-commons/pull/2) |
| Source/history secret scan | Pinned gitleaks 8.30.1 passed both publishable files and all reachable Git history, zero findings. Working tree was dirty and is identified by a manifest hash; rerun after final changes. | [Scoped scanner evidence](../security/secret-scan.json) |
| Installed dependency licensing | 297 installed host-profile packages, zero unresolved decisions after exact package/version/profile decisions and verified missing-license evidence. SPDX parser self-test: 9 cases passed. This is not a release/image SBOM or vulnerability scan. | [Inventory](../legal/dependency-inventory.json), [policy](../../policies/dependencies.yml) |
| Bootstrap publication policy | Recorded local run passed on 137 publishable files and 105 historical blobs. No private identity or token values are published by findings. | [Scoped local policy evidence](repository-readiness-local.json) |

The enhanced workflow now has mandatory `quality`, `secrets` and `behavior` jobs
and an always-running `required` aggregate. `behavior` builds/starts real core
Compose services, seeds synthetic tenants, runs connector conformance and
isolation tests, then browser acceptance/accessibility. This new workflow is
**not marked passing until an actual run succeeds at its published commit**.
Browser CI disables traces, videos and automatic failure screenshots; only a
bounded outcome summary and explicit successful post-login synthetic catalog
screenshots may be uploaded. Bootstrap files and raw browser reports are excluded.

## Actual settings and limitations

The active [branch ruleset](https://github.com/dlamaro96/governance-commons/rules/27317248)
requires PRs, resolved review threads and an up-to-date `required` check from the
observed GitHub Actions app (`integration_id: 15368`) for `main` and `release/**`.
It prevents deletion and non-fast-forward pushes. The active
[tag ruleset](https://github.com/dlamaro96/governance-commons/rules/27317249)
prevents updating or deleting `v*` tags. Both have empty bypass actor lists;
read-back says the current user cannot bypass. A maintainer with administrative
rights can still edit repository settings; no rule makes administrators unable
to reconfigure the repository. Tag immutability was read back, not tested by
trying to rewrite a real release.

`@dlamaro96` is the one actual eligible maintainer. CODEOWNERS validation reports
no errors, but **zero independent approvals** are currently required and
CODEOWNER approval is not enforced. This is an explicit solo-bootstrap gap, not
a claim of independent review. The bootstrap can strengthen approval rules once
another real eligible maintainer exists; it will not lower stronger rules.
No human DCO certification or review is fabricated for agent-written commits.

Actions default to read-only and cannot approve PRs. Workflows use full verified
commit pins and frozen dependency inputs. The personal repository has no merge
queue; strict branch currency is the selected integration path. Official Actions
lockfile onboarding is currently plan-scoped; the verified full-SHA fallback is
recorded rather than a hand-written `actions.lock`.

Dependency alerts, GitHub secret scanning and push protection are enabled.
[Private vulnerability reporting](https://github.com/dlamaro96/governance-commons/security/advisories/new)
is enabled and API-verified; no synthetic vulnerability report or response SLA
is claimed. Private project conduct reporting and independent escalation remain
unassigned. Platform abuse reporting is distinct from project conduct handling.

## Outstanding acceptance gates

- Publish and pass the enhanced workflow on the coherent integration PR, evaluate
  its final SHA and record the merge result; existing failed bot PRs demonstrate
  blocked state only, not a completed successful integration.
- Complete independent review, contribution certification and an actual private
  conduct/escalation route. Do not invent a person, mailbox or sign-off.
- Qualify hosted and portable SAST, dependency vulnerability checks, final
  artifact/OS/Python/driver license inventories, SBOMs and license notices.
- Implement and test trusted release build/sign/verify/attest, immutable release
  publication, offline verification and recovery. There is no supported release
  or independent security certification yet.
- Finish the complete ASVS control-ID mapping, manual verification and independent
  penetration testing; the threat model and preliminary area map are partial.
- Qualify backup/restore, signing rotation, revocation, incident and break-glass
  recovery against declared deployment targets.

Reproduce configuration inspection with
`python3 scripts/github/bootstrap inspect --repo dlamaro96/governance-commons --output docs/verification/repository-readiness-latest.json`.
Use `apply` only for the authorized target; it records before/after state and
preserves unrelated settings. Retain historical evidence files rather than
rewriting old checks as passing after new changes.
