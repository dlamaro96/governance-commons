# Repository readiness

Current checkpoint, 23 November 2026: the project remains a development preview.
[Product status](../product/STATUS.md), [delivery plan](../execution/PLAN.md) and
[release readiness](../release/READINESS.md) describe the active implementation.
The [backlog mapping](../execution/backlog.json) covers all 1,106 requirements.
PR #23 and the later PRs #39 and #40 merged normally after their exact required
checks and authenticated artifacts passed. PR #40's 46-outcome checkpoint is
[recorded separately](hosted-checkpoint-4cbde6a.json). PR #41's SQL033 increment
also merged normally as `1db2f71` after all 47 outcomes and its exact source and
native image scans passed. Its [record](hosted-checkpoint-296d1e5.json) retains
the distinction between exported evidence and native step outcomes.
Issue #24 is closed for its scoped pipeline checkpoint; the broader delivery and
release issues remain open. Earlier failures below retain their original dates
and scope; they are not the current integration result.

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

The bootstrap workflow introduced mandatory `quality`, `secrets` and `behavior` jobs
and an always-running `required` aggregate. `behavior` builds/starts real core
Compose services, seeds synthetic tenants, runs connector conformance and
isolation tests, then browser acceptance/accessibility. This new workflow is
qualified only by an actual run at its published commit. The current workflow
uses independently assigned behavior shards and an always-running aggregate;
the exact successful checkpoints are linked above.
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

- Qualify the new runtime-image aggregate on real fork runs before adding it to
  enforced branch requirements. Exact hosted development, source security and
  native image results are recorded per revision; they do not certify every
  future commit or fork configuration.
- Complete independent review, contribution certification and an actual private
  conduct/escalation route. Do not invent a person, mailbox or sign-off.
- Complete final artifact/OS/Python/driver license inventories, release SBOMs and
  notices, and remaining deployment/security profiles. Hosted SAST, dependency
  audits and both application-image scans have scoped evidence; they do not
  replace exploitability review or independent security qualification.
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
