# Source security scanning

Status: the isolated Linux arm64 qualification has executed all three source
analyses and the real vulnerable-fixture rejection control. Their exact source,
findings and artifact-hygiene results are recorded separately in
`SAST_QUALIFICATION.md`; this is **not a full security/release pass**. The eighth
hosted attempt passes default-branch source analysis, exact coverage, zero
findings and independent stored-analysis read-back on
`77b73e75016435d6f12e67cda76ea84b91cd1086`. Main's complete alert inventory is
empty. The prior PR source/ingestion and14-browser/11-step Development pass remain
bound to their exact merge. See `SAST_HOSTED_QUALIFICATION.md` for originals and
source binding. Post-merge Development also passes14 browser journeys and11
service steps on the exact main commit. Fork/Dependabot qualification remains
open; the new required status remains disabled. No human finding disposition or
complete release qualification is inferred.
This implements the bounded source-scanning part of issue 11 and OSS-006/007;
SQL/RLS, dependency vulnerabilities, images, general IaC, ASVS and independent
review remain separate required work.

The final engineering choice is one CLI extraction/query/evaluation path for
local runs and every hosted language job. The pinned `upload-sarif` Action only
ingests a report; this implementation does not invoke Action `init` or `analyze`,
and does not enable CodeQL default setup. The prior research plan proposed those
Actions before this shared-runner decision.

## Tool and source contract

`policies/sast-policy.json` pins CodeQL 2.27.4 and the three bundled query packs:
JavaScript/TypeScript 2.5.0, Python 1.9.0 and Actions 0.6.39. Each uses the standard
code-scanning plus security-extended suite. `.github/codeql/codeql-config.yml`
retains default queries and security-extended. Resolved query paths must be in
the verified bundle; their hashes and combined digest are recorded. No floating
pack download, application build, package install or connector credential is
part of a scan. Coverage queries enumerate database `File` records and compare
them to all expected source files, including tests, tools and workflows.

The snapshot consists of Git tracked and untracked non-ignored regular files,
with actual worktree bytes. Ignored files and worktree deletions are excluded;
symlinks and submodules fail explicitly. Every copied file has a byte count and
SHA256. The report identifies HEAD **and** dirty state **and** the source digest;
a dirty scan is never described as a clean scan of HEAD. CodeQL reads the frozen
copy, which is verified again before success. JS/TS extensions, `.py`, extensionless Python/Node shebang tools, workflow
YAML and action manifests are required extraction targets; other file types are
copied but are not covered by the declared three languages. No coverage waiver
or source exclusion is configured. Missing source, extraction warnings/errors,
empty/incomplete coverage, unavailable queries, wrong tool/category, malformed
or missing results and unsuccessful invocations fail closed.

The pinned upload Action is `github/codeql-action/upload-sarif` at
`33d7b85da1a04171e211befe2c739303b9a4c066` (v4.39.3). Bundle checksums and sizes
come from the immutable [official 2.27.4 release metadata](https://api.github.com/repos/github/codeql-action/releases/tags/codeql-bundle-v2.27.4).
The [pinned query source](https://github.com/github/codeql/tree/codeql-cli/v2.27.4)
and [CLI query resolution contract](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/resolve-queries)
are the primary configuration references. Review pin updates through normal PRs.

## Local commands

Python 3.9+ and Git are required for the stdlib runner. The policy regression
suite also requires Node for its synthetic package-scope handshake. Extraction additionally
requires the pinned Node 24.22.3 and Python 3.14.5 runtimes; CI installs those exact
runtimes, and the scanner verifies their versions. Native runs with an ambient
`~/.config/codeql/config` refuse to proceed; use the isolated runtime instead. Linux x64/arm64, macOS and
Linux inside WSL2 are supported by the selected upstream bundles, subject to
actual platform qualification. Download/install is explicit and separate from
execution; no token is needed for the public bundle or local analysis.

```sh
python3 -m unittest discover -s policies -p test_sast.py -v
python3 policies/sast.py install
./dev test --suite sast
```

These SAST commands do not require `./dev bootstrap`, Docker or app secrets for a
native Linux/macOS run. The origin must identify the configured public project.
A public fork passes `--public-repository owner/public-fork` explicitly to
`policies/sast.py install` and `run`; the value must match its Git origin. It is an
operator declaration of public scope, not a private-use licensing override.

For a Linux bundle on a macOS host, an existing local image with a compatible
Linux userland and the required extractor runtimes may be used without downloading or building an image:

```sh
python3 policies/sast.py install --platform linux-arm64
python3 policies/sast.py run --platform linux-arm64 \
  --container-image sha256:REPLACE_WITH_ACTUAL_EXISTING_LOCAL_IMAGE_ID
```

Obtain the actual immutable ID with `docker image inspect IMAGE --format
'{{.Id}}'`; the runner rejects a tag. Do not paste the example placeholder as an
image. If the existing Node and Python images are separate, pass
`--container-images` with a JSON object mapping exactly `javascript-typescript`,
`python`, and `actions` to their real immutable IDs instead of `--container-image`.
Each language summary records its actual image. The equivalent
`GC_SAST_PLATFORM`, `GC_SAST_CONTAINER_IMAGES` (JSON), `GC_SAST_CONTAINER_IMAGE`
and `GC_SAST_TOOLCHAIN` environment variables are supported so the same selected
local runtime also works through `./dev test --suite sast`; they carry no secrets. Each CLI invocation uses a uniquely named, disposable container: no
network, no application volume, no Docker socket, read-only root/bundle/source,
4 GiB memory cap, two CPUs and only its private output mount writable. Its
`finally` cleanup removes that exact container even when the Docker client is
interrupted. The selected Docker endpoint must be local. No app service is
stopped or modified. The CodeQL CLI remains outside application images.

The shared policy requests 4,096 MiB for native CodeQL and retains 2,048 MiB
inside the 4 GiB container cap; both use two threads. Native commands require an
estimated 2 GiB reserve beyond their requested budget before startup. Linux
admission takes the minimum of `MemAvailable`, visible cgroup v2 ancestor
headroom and inherited finite address/data limits. Darwin estimates available
memory from free, inactive and speculative pages, also checking inherited
limits. Unknown/malformed accounting, cgroup v1 memory limits or insufficient
capacity fail before the scanner starts. Safe summaries preserve numeric
admission observations, including a rejected request's available/required bytes.

These are admission estimates. Native execution adds no hard memory cap, does
not reserve memory against concurrent work, and does not use an address-space
RLIMIT as a resident-memory bound. CodeQL's
[`--ram` option](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli-manual/database-analyze)
is an evaluator/extractor budget request. The fifth hosted attempt completes all
three analyses with this budget; its open high finding separately blocks the
complete gate. Admission estimates and policy tests alone do not qualify a scan.

Outputs are unique directories beneath `.local/sast/`; an existing output path
is refused. `--output .local/sast/my-attempt` selects a fresh location. The
installer refuses overwriting an existing tool directory and validates every
cached file/symlink against its install provenance before use. The owned cache
also has a fixed CommonJS `package.json` outside the verified bundle, so Node
cannot inherit the application's ES-module scope. This file is created only if
absent; symlinks and differing existing content fail without overwriting them.
Custom toolchain ancestors remain untouched; native execution refuses an
incompatible nearest package scope and records its hash. The package-boundary
correction has exact-wrapper handshake evidence and hosted extraction now passes.
The fourth hosted attempt subsequently failed analysis with CodeQL out of memory.
The fifth passes analysis with the revised native budget and blocks an actual
high finding; its complete source-security gate remains unqualified.
`--archive PATH`
reuses already-downloaded bytes only after the same exact size/checksum checks.

The installer admits a conservative compressed+unpacked+2 GiB disk budget. Scans
require 4.5 GiB initially and monitor a 2 GiB floor, bounded logs and a 30-minute
whole-language deadline. Language runs are serial locally. These are admission
limits, not measured performance promises. The 4.5 GiB admission was explicitly
selected after the first real full scan used approximately 0.3 GiB of additional
space; the 2 GiB watchdog remains mandatory during every CLI command. macOS's 1.26 GB compressed bundle is
larger than the 679 MB Linux arm64 bundle. A 16 November 2026 metadata inspection of
the verified Linux arm64 archive measured 1,298,284,624 regular-file bytes across
40,452 archive members; this is installation sizing, not scan evidence. Existing
Hive Citadel/unrelated images, volumes, source and caches must be preserved.

## Findings and publication

Each language summary separates `analysis`, `findingsGate` and `upload`.
A successful scanner exit does not imply an empty result set. All findings need
an explicit disposition. Untriaged findings block. Applicable pending high or
critical findings block; lower-severity pending work can pass only with recorded
triage. False-positive and accepted-risk decisions match an exact fingerprint
bound to rule, language, source file bytes, line fingerprint and query pack
version. A changed file invalidates the prior match.

`policies/sast-triage.json` starts empty. A decision must contain exactly:

```text
fingerprint, disposition, owner, reviewedBy, reviewUrl, reviewedAt, expiresAt,
component, exploitability, exposure, evidence, mitigation
```

`disposition` is `false_positive`, `accepted_risk` or `remediation_pending`.
Owner and reviewer are actual GitHub accounts; `reviewUrl` points to the real
review. UTC timestamps use `YYYY-MM-DDTHH:MM:SSZ`; the decision must be unexpired,
not future-reviewed and at most 90 days long. No wildcard, blanket baseline or
in-source suppression independently dismisses a finding. The parser checks the
record shape; maintainers must verify the linked human review. Never invent a
review or convert scanner output into an automatic human risk acceptance.

Raw SARIF, decoded coverage, query hashes and scanner logs remain local. The
`public/` directory contains the source manifest, summaries and a scrubbed SARIF
copy without source snippets, contents, environment variables or command lines.
Absolute local roots, including percent-encoded URI spellings, are replaced.
Review reports before any manual publication;
findings can be security-sensitive. The hosted workflow uploads only this bounded
public directory with 7-day retention, including failed-attempt summaries. It
never uploads a database or debug artifact. Its upload status record separately
identifies upload+processing outcome and the exact Actions commit. An additional
analysis API read-back is required for qualification.

A failed scanner command may additionally publish fixed allowlisted diagnostic
markers, byte counts and SHA256 values for its bounded stdout/stderr files.
Markers inspect at most the first and last 32 KiB; they are hints, not a cause
determination, and do not change any gate. No log text, source value, command
line, path or environment value is published. Successful commands add no failure
diagnostic. Private full logs retain the details needed for an authorized local
investigation.

`.github/workflows/security.yml` uses separate jobs for each language, no path
filters, read-only contents, `security-events: write` only where ingestion needs
it, no repository secrets, no privileged fork follow-up, explicit timeouts and
per-ref cancellation. `sast-required` requires every language and policy job to
succeed; failure, cancellation and unexpected skip fail. Public fork and
Dependabot permission behavior remains unqualified until actual events are
observed. Root integrates required-check/ruleset changes after qualification.

## Real negative control and next qualification actions

`python3 policies/sast_probe.py` generates an isolated synthetic Express command
injection, Flask command injection and Actions expression-injection fixture. It
executes the **real** pinned scanner and requires successful analysis plus a
blocked high/critical finding in each language. It accepts the same `--toolchain`,
`--platform`, `--container-image` and `--container-images` options. It never runs the vulnerable source,
installs dependencies, uploads findings or modifies project Git history. Its
throwaway fixture Git commit is identified as synthetic. A passing negative
control means the gate rejected vulnerable fixtures; it is not a product pass.

Resume in this order:

1. Consult `SAST_QUALIFICATION.md` for the actual local attempts and exact source
   evidence. Preserve failures and blocked findings with their original status.
2. Scan the final integrated source again; the isolated worktree scan does not
   qualify a different root revision. Record source/config/query/bundle/report
   hashes, runtime image, coverage and measured resources. Remediate or explicitly
   triage actual findings; do not manufacture approvals.
3. Root reviews and integrates the branch. Execute ordinary hosted PR and trusted
   default-branch scans, then read back all three analyses for their exact commits
   and categories. Exercise a public fork and Dependabot contribution path.
4. Only then update requirement/evidence/readiness records and require the
   observed stable aggregate. The source job's green execution alone is not a
   clean-findings, ingestion, release or full OSS-007 pass.

## Material implementation decisions

The migration interpreter uses private `Map` nodes for its mutable working tree.
Dynamic field names therefore cannot invoke an inherited setter or mutate an
object prototype. The existing parser, forbidden-name checks, schema/operation
limits and complete source/target validation still apply. Arrays cannot be
traversed as objects. The result is materialized as ordinary own-data-property
JSON before final validation; no Map crosses the public contract. The shared
model normalizer also creates own data properties explicitly. A regression first
reproduced an inherited-setter invocation and then verified it was eliminated,
including optional nested fields and exact-decimal object/list literals.

This decision followed actual blocked scans: seven dynamic property findings
plus one publication-rule-label finding initially; seven after fixed public
rule-ID projection; one at a safe `Object.defineProperty` helper after own-data
mutation hardening. The pinned medium-precision property query still treats that
helper as a dynamic property sink. The final working-tree design removes that
operation entirely. Earlier reports retain their actual blocked status. No
blanket suppression or invented human finding decision was added. The exact
final scan result belongs in its separate qualification record, not in a claim
inferred from this implementation choice.

## Licensing and remaining limits

CodeQL Action is MIT; the CLI is separately licensed. This local route is for the
public GitHub open-source project under the [CodeQL terms](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md).
It is **not** an unrestricted private/internal fallback. A private operator must
verify entitlement or select and qualify a separately licensed portable scanner;
that remaining requirement is not fulfilled by this configuration. Source/runtime
policy rejects an explicitly private hosted repository. No paid runner, plan,
subscription or production deployment is introduced. SQL/RLS correctness,
connector security, dependency/image/IaC scanning and independent review remain
outside the capabilities asserted here.


The relation JSON copier now also creates own data properties explicitly. The
single guarded dynamic assignment could invoke an inherited setter for an
otherwise valid field name. A synthetic hostile-prototype regression reproduced
that side effect before the repair and passes afterward, while reserved keys,
getter rejection, ordinary object prototypes and dense arrays retain their
existing behavior. This is a source repair with no scanner suppression or risk
waiver; its hosted rescan remains required.

The relation, asset-type migration and model-migration bounded copiers collect
validated children in private Maps before `Object.fromEntries`/`Array.from`
materialization. This avoids input-derived destination-property writes entirely.
Equivalent inherited-setter regressions fail before and pass after the repair;
validation, order, budgets, ordinary prototypes and dense output are preserved.
The sixth hosted scan retains its original blocked finding; no rescan is inferred
from these local checks.

The seventh hosted attempt executes the Map-based repair with complete coverage
and zero findings. Its exact stored analyses and fixed alert inventory are
verified independently. This qualifies that tested source only; original failed
reports, separate runtime qualification and remaining permission/release gates
retain their own statuses.

PR15 merged as `77b73e75016435d6f12e67cda76ea84b91cd1086` after the exact
qualified head passed Source security and Development. Post-merge default-branch
execution/read-back and fork/Dependabot qualification remain pending.

The eighth hosted attempt separately qualifies default-branch source scanning and
exact stored-analysis read-back on the repository merge commit. This resolves the
previous default-branch prerequisite without altering the earlier PR evidence.
Fork/Dependabot and wider release prerequisites remain open.
