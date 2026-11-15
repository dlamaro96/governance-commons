# Security scanning qualification plan

Status: **PLANNED — NOT IMPLEMENTED OR EXECUTED.** Read-only research and GitHub
inspection on 16 November 2026 (Asia/Dubai). Track implementation in
[issue 11](https://github.com/dlamaro96/governance-commons/issues/11), on a separate
`codex/sast-qualification` branch after the current increment. This document
changes no workflow, repository setting, requirement status or execution evidence.

Scope: the SAST part of BUILD_SPEC OSS-006/007. Read SECURITY.md, the threat model,
release readiness and current STATE. Hosted services must complement a documented
local command; scanner execution, findings disposition and release readiness are
different outcomes. Dependency vulnerabilities, image/IaC scanning and broader
security qualification remain separate required work.

## Observed repository state

Read-only authenticated REST calls confirmed public personal repository
`dlamaro96/governance-commons`, default branch `main`, with admin permission.
Actions is enabled; default workflow permissions are read-only and workflows
cannot approve pull requests. Repository-wide SHA enforcement is off, while the
project's local publication policy checks verified full-SHA action pins.

CodeQL default setup returned `state: not-configured`. The analyses endpoint
returned HTTP404 with `no analysis found`; `gh` also printed an ancillary OAuth
scope suggestion. Preserve this exact limitation: no analysis was available from
that request, and no scanner execution or clean result was established. No scope
refresh, default-setup activation or other setting change was attempted.

Dependency alerts, private vulnerability reporting, secret scanning and push
protection were enabled. Dependabot security updates were disabled; this is
distinct from alerts and the existing weekly npm/Actions version-update config.
After that inspection, root enabled Dependabot security updates and verified
`enabled:true, paused:false`; see `docs/verification/dependency-security-updates.json`.
The local CI workflow has quality, secrets, behavior and required jobs, but no
SAST job. Existing secret/license checks do not qualify SAST.

## Verified upstream inputs

Use advanced setup so action, CLI, query configuration and local reproduction
can be recorded together. Do not also enable default setup for the same scanner.

| Input | Verified value and primary source |
| --- | --- |
| CodeQL Action | `github/codeql-action/init` and `github/codeql-action/analyze` at `33d7b85da1a04171e211befe2c739303b9a4c066`, version `v4.39.3`, released 2026-11-04. [Official release](https://github.com/github/codeql-action/releases/tag/v4.39.3). |
| Provenance | The release is immutable; the annotated tag resolves through `f3bbb05694c2f74569081c28664c0866d64dec21` to the commit above. The commit signature reports verified/valid; the annotated tag itself is unsigned. [Tag object](https://api.github.com/repos/github/codeql-action/git/tags/f3bbb05694c2f74569081c28664c0866d64dec21), [commit](https://api.github.com/repos/github/codeql-action/commits/33d7b85da1a04171e211befe2c739303b9a4c066). |
| Runtime and linked CLI | Action runtime Node24; linked CodeQL bundle/CLI `2.27.4`. [Pinned init inputs](https://github.com/github/codeql-action/blob/33d7b85da1a04171e211befe2c739303b9a4c066/init/action.yml), [pinned defaults](https://github.com/github/codeql-action/blob/33d7b85da1a04171e211befe2c739303b9a4c066/src/defaults.json). |
| Linux x64 full bundle | `codeql-bundle-linux64.tar.gz`, 696,320,500 bytes, SHA256 `89ed56c8ec6bfccef6a0d2e7fe86da0469ca24b4db08b88016ec134b942c17a4`. |
| Linux arm64 full bundle | `codeql-bundle-linux-arm64.tar.gz`, 678,801,372 bytes, SHA256 `7dd066f805dfed19c9c4323d5f2003cd24fabd6e7304cdf799b94a84509fe92b`. |

Bundle sizes/digests came from the immutable [2.27.4 release
metadata](https://api.github.com/repos/github/codeql-action/releases/tags/codeql-bundle-v2.27.4).
No binary was downloaded or executed. Verify downloaded bytes before extraction.
Add each action subpath to `.github/action-pins.json`; the publication checker
matches full action paths, so a repository-only entry is insufficient. Retain
existing verified checkout/artifact pins unless a separately reviewed update is
needed. Pin the bundle explicitly or use the verified linked version and verify
the resolved CLI version; do not silently accept a runner's different cached CLI.
Record resolved bundled query packs/configuration. Review Dependabot updates and
upstream support changes rather than leaving a full-SHA pin indefinitely stale.

## Proposed execution and permissions

1. Add an explicit three-language matrix: `javascript-typescript`, `python`,
   `actions`, each using `build-mode: none`. Use one shared query configuration
   locally and in CI, initially the bundled security suite with explicitly
   selected security-extended queries where qualified. No application build,
   package lifecycle script, service bootstrap or connector credential is needed.
   Current documented support includes TypeScript7.0, Python3.14, Fastify, React
   and psycopg; extraction coverage still needs execution evidence. SQL/RLS
   semantics and general IaC are not covered by those language declarations.
   [Language/build configuration](https://docs.github.com/en/code-security/reference/code-scanning/workflow-configuration-options),
   [supported frameworks](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/).
2. Use disposable standard `ubuntu-24.04` runners; `pull_request`, trusted
   `main`/`release/**` pushes, a weekly schedule and manual dispatch. Avoid
   workflow-level path filters. Set bounded timeouts and per-ref cancellation;
   preserve each failed attempt separately. Start with no shared extraction or
   dependency cache and disable database upload/debug artifacts. Upload only
   reviewed SARIF and bounded execution evidence with short retention.
3. Default to `contents: read`; grant `security-events: write` only to analysis
   jobs needing ordinary code-scanning upload. Retain effective read-only fork
   restrictions, checkout `persist-credentials: false`, and no PAT, OIDC,
   provider/signing secrets, privileged follow-up or `pull_request_target`.
   GitHub documents an upload exception for `pull_request` runs, including
   read-only Dependabot runs. Qualify actual contribution events before claiming
   their behavior verified. A Dependabot-authored default-branch push can have
   different permissions; diagnose an upload failure without escalating trust.
   [Official permission guidance](https://docs.github.com/en/code-security/reference/code-scanning/troubleshoot-analysis-errors/resource-not-accessible).
4. Implement `./dev test --suite sast` with a checksummed standalone CLI bundle,
   exact publishable source snapshot and the same configuration. Local execution
   must produce SARIF and a bounded JSON summary without requiring upload or a
   token. Exclude ignored credentials/build data by constructing a source
   snapshot, not by scanning the whole developer workspace. Preserve relevant
   application, scripts and workflow source; report deliberate exclusions and
   extracted-file coverage. Run languages serially locally; check capacity before
   download/extraction and preserve the current 2GiB disk floor.

## Findings, failure behavior and qualification

The pinned analyze action supports an output directory, `upload: always|never`
and waiting for processing; use explicit settings and report upload separately
from analysis. A successful CLI exit means execution succeeded, not that no
vulnerabilities were found. [Pinned analyze contract](https://github.com/github/codeql-action/blob/33d7b85da1a04171e211befe2c739303b9a4c066/analyze/action.yml),
[CLI exit codes](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli/exit-codes).

Validate all expected language reports, source coverage and invocation status.
Missing/malformed/partial reports, no extracted source, query timeout, cancellation,
resource exhaustion or scanner failure must fail the aggregate. Preserve local
SARIF if ingestion fails; do not label hosted qualification successful. Apply a
shared local/CI findings policy, recording severity, exploitability, exposure and
affected component. Applicable unresolved high/critical findings block release;
any exception needs evidence, a real owner and expiry. No blanket baseline or
unexplained suppression may turn new findings into a pass.

Add a stable `sast-required` aggregate that checks every child result, including
failure, cancellation and unexpected skip. After real qualification, require the
observed check through the existing managed ruleset, preserving its other rules.
Native CodeQL alert merge protection can supplement this policy after its actual
availability/read-back is verified; analysis-job success alone is insufficient.
[GitHub merge protection](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/manage-your-configuration/set-merge-protection).

Acceptance requires actual local and hosted PR/default-branch scans; ingestion
read-back for exact commits/languages; a meaningful synthetic finding proving the
findings gate; and negative checks for missing, malformed, partial and failed
scans. Record source revision/manifest, runner and resolved tool/query versions,
configuration/report hashes, coverage, original failures and dispositions. Update
the evidence manifest/register only with scoped actual results. A clean scanner
result does not replace tenant/security tests or independent human review.

## Licensing, cost and remaining scope

The Action is MIT; its underlying CLI is separately licensed under GitHub CodeQL
terms. The CLI is free for this public GitHub open-source project and can run
locally. It is **not** an unrestricted private-project fallback. Do not bundle it
into application release images or imply the project's Apache-2.0 license covers
the CLI. Private/internal operators without the relevant entitlement need a
separately selected, appropriately licensed portable scanner and rule set; that
selection/qualification remains open. [Pinned license statement](https://github.com/github/codeql-action/blob/33d7b85da1a04171e211befe2c739303b9a4c066/README.md#license),
[CLI availability and platform limits](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-cli).

Public standard-runner compute requires no paid plan; larger runners are billed.
Bound artifacts/caches and retain current budget restrictions rather than assuming
all storage is unlimited/free. No paid feature, purchase or new organization is
part of this plan. [Official Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions).

Implementing this plan will qualify a bounded SAST path, not complete OSS-007,
ASVS, release security, vulnerability dependency scanning, image/IaC analysis or
the full product programme.
