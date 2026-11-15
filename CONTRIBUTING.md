# Contributing to Governance Commons

This is an independent Apache-2.0 project under active development. Read the
[current implementation state](docs/execution/STATE.md) before choosing work;
the [full specification](docs/product/BUILD_SPEC.md) remains the target.

## Set up and check a change

Use Node.js **24.22.3**, pnpm **10.32.1**, Python **3.14.5** for repository checks,
and the Docker/Compose versions recorded by `./dev doctor`. Python source
workers use their separately pinned uv environment. No paid cloud or AI account
is needed for the local reference profile.

```sh
pnpm install --frozen-lockfile
python3 scripts/requirements.py validate
pnpm typecheck
pnpm test
pnpm build
python3 policies/check_dependencies.py --self-test
python3 policies/check_dependencies.py --write
python3 policies/scan_secrets.py --install
python3 scripts/github/bootstrap check-local
./dev doctor
./dev bootstrap
./dev up --profile core
./dev seed --dataset harbor-demo
./dev test --suite smoke
```

The static, unit, dependency-license and secret checks form the development
pull-request gate. The secret scanner downloads a pinned official release on
first use and scans publishable files and reachable history, without publishing
secret matches. Docker, acceptance,
security, connector, upgrade and release qualifications remain separate gates;
inspect STATE and readiness records for what has actually run. A command that
reports an unavailable prerequisite is not passing evidence. `./dev down`
preserves volumes; never remove another project's containers or volumes.

## Repository map and work boundaries

`apps/web` contains the React interface; `apps/api` owns Fastify application
services. `apps/workflow-worker` orchestrates Temporal; `apps/site-runner`
coordinates source execution. Shared schemas live in `packages/contracts`,
authorization in `packages/authz`, and reviewed SQL migrations in `packages/db`.
Python adapters belong under `python`, source manifests under `connectors`,
and deployment profiles under `deploy`.

Agree schema/API contracts and file ownership before parallel changes. Preserve
unrelated work. Keep module dependencies acyclic; cross-module writes use
application services. Every tenant-owned record, worker task and index query
needs the same authorization boundary. Source credentials never belong in code,
test output, the browser, Temporal history or public fixtures.

Start with a small issue describing an observable outcome and its requirement
ID. Browse the [actionable backlog](https://github.com/dlamaro96/governance-commons/issues)
and [open milestones](https://github.com/dlamaro96/governance-commons/milestones)
first; discuss scope before starting overlapping work. For a routine fix, make a focused `codex/` or descriptive short-lived branch
and open a pull request. Use an ADR for architecture, security or compatibility
changes; a typo does not need one. Good first contributions include improving a
reproducible error message, adding an adversarial authorization case, or adding
an original connector fixture for a specific unsupported capability.

## Evidence and review

Include the problem, resulting behavior, requirement IDs, checks actually run,
remaining prerequisites and migration/security impact. UI changes need a
rendered screenshot plus an interaction check; an image is not functional
evidence. Connector changes need a manifest, minimum source privileges, identity
and reconciliation semantics, protocol fixtures and an opt-in real-source test
plan. A local HTTP fixture does not verify the named cloud vendor.

Never edit old applied migrations. New migrations require constraints, RLS and
an upgrade/recovery test appropriate to the change. Do not remove a failed test
or lower a release threshold to make a check green. Modify canonical
`docs/product/requirements.yaml`, then run
`python3 scripts/requirements.py generate`; generated CSV/Markdown are not
hand-maintained. Evidence records need the exact revision, profile, command,
versions, timestamp, result and limitations.

CI runs fork code with read-only permissions and no private secrets. Fork
contributors do not receive publishing credentials. Do not add
`pull_request_target`, privileged artifact execution or a persistent runner to
bypass this boundary. The bootstrap currently has one eligible maintainer;
independent review remains an explicit qualification gap.

## Contribution certification and attribution

Contributions use [DCO 1.1](docs/legal/DCO-1.1.txt). Read the complete certificate.
Only add a sign-off when you personally can make that certification:

```sh
git commit -s
```

Use your legitimate configured Git identity. A verified GitHub noreply address
can protect your email address; commit metadata and sign-offs remain public and
persistent. The DCO is not a copyright assignment or a change to Apache-2.0.
Do not invent a contributor, reviewer, co-author or sign-off. Agent-authored
bootstrap commits without a human certification must remain identified as such;
CI does not fabricate certification or retroactively sign them. Maintainers
review contribution certification before accepting external contributions.

AI-assisted changes receive the same provenance, license, testing and review
requirements. Use original synthetic examples only; exclude employer/client
names, private schemas, credentials and third-party proprietary content.

See [SECURITY.md](SECURITY.md) for vulnerabilities and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for community behavior.
