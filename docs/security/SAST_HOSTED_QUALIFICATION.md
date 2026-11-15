# Hosted source scanning attempts

Latest checkpoint: attempt 4 fixes hosted JavaScript extraction but fails its
analysis with CodeQL out of memory. Python and Actions have independent stored
analysis read-back; full source-security qualification remains open. Earlier
attempts below retain their original outcomes and limitations.

Status: source-security run [43768124973](https://github.com/dlamaro96/governance-commons/actions/runs/43768124973)
**failed** on PR15 merge commit `1bb4637def199c12226d1d337dcd2eece61ee57e`.
The exact clean source digest is
`ab80a7ab2f90ea68a7f139de1154dff1c563b094c68baff533edb846371a336e`.
Original safe artifacts and their hashes are preserved under
`sast-evidence/hosted-attempt-1/`; `record.json` separates analysis, findings,
upload/processing, read-back and the independent behavior workflow.

| Language | Analysis and coverage | Findings | Upload/processing |
| --- | --- | --- | --- |
| JavaScript/TypeScript | Extraction exited 2 after 2.504 seconds; not passed | Not evaluated | Skipped; no SARIF |
| Python | Passed; 25/25 expected files, 52 queries | Passed; zero findings | Success |
| Actions | Passed; 2/2 expected files, 24 queries | Passed; zero findings | Success |

The hosted policy job passed and the aggregate failed, as observed in the public
Actions UI. JavaScript successfully verified Node v24.22.3, CodeQL 2.27.4 and all
105 pinned queries before extraction failed. That failure is not evidence of a
source finding. The original artifact contains the phase, exit status and elapsed
time, but no raw log or diagnostic classification; its cause remains undetermined.
No original failure has been replaced or relabeled.

The separate [Development run 43768124770](https://github.com/dlamaro96/governance-commons/actions/runs/43768124770)
passed all four jobs on the same merge commit. Its byte-identical safe behavior
summary records 11 successful steps and 14 distinct browser tests, each passing
on its first attempt. Its SHA256 is
`0773807949188780f1bc4a3b69b236db60560d3c2be6ca6402bd565dde942a94`.
Behavior success does not override the source-security failure.

## Bounded local diagnostic

An extraction-only comparison used the same frozen source digest, verified
CodeQL 2.27.4 Linux arm64 bundle and existing immutable Node image. Extraction
passed both with `HOME` explicitly unset (15.314 seconds) and with the image
default (14.350 seconds). Each invocation had a 70-second deadline, the existing
2 GiB disk watchdog and isolated mounts with no network. Both owned containers
were removed. `home-extraction-comparison.json` preserves fixed flags and private
log hashes; full logs remain private.

This comparison did not reproduce the hosted Linux x64 failure and did not run
queries, coverage or a findings gate. It does not establish native x64 success.
The runner's environment and scanner configuration remain unchanged.

## First diagnostic change and its hosted execution

Failed commands can now add fixed allowlisted markers, stream sizes and hashes
to their existing failure summary. Sampling is bounded to the first and last
32 KiB of each already-bounded stream. No raw text, path, source, command line or
environment value is published. Marker names are hints rather than root-cause
claims. The existing command rejection, extraction coverage, findings and upload
gates remain unchanged, and success adds no diagnostic record.

The focused policy checks exercise a real failing subprocess, preserved rejection,
success reset, private-content exclusion, head/tail limits, oversized logs and
symlink refusal. Their exact executable hashes and results are recorded in
`sast-evidence/hosted-attempt-1/diagnostic-checks.json`. These are tooling tests;
at that checkpoint, the changed runner still needed hosted execution. The second
attempt below records that execution separately.

That diagnostic patch was published as `61543a062b9818d08f2b7a7904383d58303d562a`.
The second attempt below executed it; the historical focused checks do not change.

## Second hosted attempt

[Source-security run 43770132214](https://github.com/dlamaro96/governance-commons/actions/runs/43770132214)
failed on tested merge `6521d92cab468ad434117cfe2eebe8d53d3272be`, with clean source
digest `f3f93d9944b9f143068cdfea8e34ed8648f2da41258f1ead46142e1bd009f904`.
Byte-identical safe summaries, upload statuses and source manifests are preserved
under `sast-evidence/hosted-attempt-2/`; the record hashes every original artifact,
including the Python and Actions SARIF files retained in local downloaded evidence.

JavaScript verified its runtime, CLI and 105 queries, then extraction exited 2 after
3.503 seconds. Its fixed markers confirm database initialization, the build and
extractor command starting, a fatal error, and an abnormal subprocess exit. No
existing specific error marker matched. Standard output was 3,994 bytes and standard
error 554 bytes; their original hashes are retained. These facts do not identify
an error class or establish a root cause. No JavaScript analysis, findings gate or
SARIF exists for this attempt. Python and Actions both pass analysis, coverage and
zero-findings gates; their SARIF upload and processing pass. Independent analysis
read-back remains open. The aggregate correctly fails.

The next additive diagnostic change covers the pinned extractor's fixed early
phases, Node/TypeScript start failures, known public Java exception classes,
filesystem and JVM failures. It also extracts at most 16 distinct signed 32-bit child
exit statuses, exclusively from CodeQL's fixed subprocess-failure syntax. All
markers remain fixed labels; arbitrary exception names, descriptions, source,
paths, command lines and environment values cannot enter the public report.
The original first/last 32 KiB bounds and failure-only behavior remain intact.
A marker is still a diagnostic hint, not a causal determination.

The literal signatures were checked against the locally checksum-verified
CodeQL 2.27.4 JavaScript extractor JAR and scripts; upstream
[AutoBuild.java at codeql-cli/v2.27.4](https://github.com/github/codeql/blob/codeql-cli/v2.27.4/javascript/extractor/src/com/semmle/js/extractor/AutoBuild.java)
provides the corresponding public phase/error paths. No execution environment,
resource budget, query, coverage, findings, triage or workflow change was made.
The focused tests verify private-content exclusion, fixed markers, contextual
numeric parsing, integer bounds, duplicate removal and the 16-code cap. See
`hosted-attempt-2/diagnostic-checks.json` for exact files and executed checks.
The separate `hosted-attempt-2/secret-scan.json` records the pinned publication
secret scan. This is diagnostic tooling qualification, not a corrected source scan.

That additive diagnostic patch was published as `123d9b8b8960cedd4817da776fe2953749d50e89`.
The third attempt below records its execution separately.


## Third hosted attempt and native package-boundary correction

[Source-security run 43771280988](https://github.com/dlamaro96/governance-commons/actions/runs/43771280988)
failed on tested merge `fba921b340943af4ca811eb09ce4cc761d7dc1bc`, source digest
`2ae949bd3d7b7bd842e4dbe171d43909bbf6178bb99104a77d0e9f63d6fb99ff`.
JavaScript extraction exited 2 after 2.254 seconds. The expanded fixed markers
show parallel extraction starting, successful Node location/version detection,
then a `CatastrophicError` and child exit 1. The original stdout is 3,994 bytes
and stderr 554 bytes. Python and Actions pass analysis, coverage, zero findings
and upload/processing; policy passes and the aggregate fails. Original safe
artifacts are preserved under `sast-evidence/hosted-attempt-3/`.

A bounded local probe demonstrated a native installation defect. The exact
bundled TypeScript parser is CommonJS JavaScript without its own `package.json`.
In the repository's `.local/security-tools` directory, Node inherits the
repository's `"type":"module"`, interprets the wrapper as an ES module and rejects
its CommonJS `exports` reference. The isolated container mounts the bundle alone,
so the repository's ancestor `package.json` is absent there. This explains why
that specific local layout defect does not affect the earlier container probe;
it does not retrospectively expose the unavailable hosted exception message.

Using Node 24.22.3, the original wrapper exited 1 in 0.030 seconds with fixed
ES-module mismatch markers. Adding only an owned CommonJS package boundary
outside the bundle made the identical wrapper return its metadata response and
exit 0 in 0.108 seconds. All 137 wrapper/dependency files matched the installed
bundle provenance and stayed byte-identical. Both attempts' private stdout/stderr
are retained with restrictive permissions; the public record contains only fixed
flags, byte counts and hashes. See `hosted-attempt-3/native-package-boundary.json`.
No CodeQL CLI, database extraction, security query or upload ran in this probe.

The correction creates or verifies only `.local/security-tools/package.json`,
with fixed `private` and `type: commonjs` fields. It refuses symlinked cache
components and conflicting existing content, never overwrites a package file,
and leaves verified bundle bytes unchanged. Custom cache ancestors are never
modified. Native execution verifies the nearest package scope and reports its
hash; an incompatible custom scope fails with an actionable reason. Focused
regressions exercise the real Node module-type boundary with a clearly synthetic
protocol, preserve bundle/source bytes, and reject symlinks and foreign content.

At this checkpoint, the local defect was corrected and hosted Linux x64
qualification was pending. The correction was published as
`3a5de6090a5a04e056c3e848d8fe272d20a713e4`; attempt 4 below records its execution
without changing this historical evidence.


## Fourth hosted attempt, stored analyses and native memory correction

[Source-security run 43772519032](https://github.com/dlamaro96/governance-commons/actions/runs/43772519032)
failed on tested merge `b3596f3525e26b8e01ce6bd8d538cf9113ac1cd1`, source digest
`e70eb504e06494664ba853222592eedfa05fa757b3ec0e783319e251e38c7a68`.
All three jobs verify the exact owned CommonJS package hash. JavaScript extraction
now passes in 15.270 seconds; analysis exits 99 after 25.288 seconds. Its bounded
stderr diagnostic contains the fixed `out_of_memory` marker. No JavaScript
findings, coverage-query result or SARIF upload is claimed. Python and Actions
pass analysis, coverage, zero findings and upload/processing. Policy passes;
the aggregate correctly fails. Twelve byte-identical original JSON reports and
hashes of every downloaded artifact are preserved under
`sast-evidence/hosted-attempt-4/`; raw logs are not published.

GitHub documents [exit 99](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-cli/exit-codes)
as CodeQL running out of memory; that does not prove exhaustion of physical
host RAM. The failed runner requested 2,048 MiB with two threads and imposed no
native RLIMIT. It did not record actual hosted available memory. The standard
public `ubuntu-24.04` runner is
[documented with 16 GB RAM](https://docs.github.com/en/actions/reference/runners/github-hosted-runners);
that platform specification is separate from measurements of this failed job.

The correction requests 4,096 MiB in native mode, retains the existing 2,048 MiB
budget and 4 GiB cap in containers, and leaves two threads, all pinned queries,
coverage, findings, triage and workflow permissions unchanged. Before each native
command, bounded kernel counters estimate capacity including visible Linux
cgroup v2 ancestor headroom or Darwin reclaimable pages and inherited finite
limits. At least 6 GiB must be available: the requested 4 GiB plus a 2 GiB reserve.
Malformed/unsupported accounting and insufficient capacity fail closed. Rejected
admission retains safe available/required numbers and never starts a scanner.
These checks are admission estimates, not a native hard cap or a guarantee
against concurrent memory use. A host-counter-only probe found less than 6 GiB
available and correctly would reject a local native scan; no heavy scan or Docker
operation ran alongside the separate SQL work. See `resource-diagnosis.json`.

Independent authenticated reads of GitHub's security-analysis endpoints bind
Python analysis `2172609160` and Actions analysis `2172607137` to this exact merge,
category, SARIF ID, published SARIF hash and CodeQL 2.27.4. Stored result counts
are zero; stored rule definitions are 50 and 23, respectively, matching their
actual SARIF definitions. Resolved query counts remain 52 and 24 and are a
different measure. Both stored analyses have no error or warning. The separate
complete CodeQL alert inventory for `refs/pull/15/merge`, with no state filter,
contains zero alerts. No JavaScript analysis exists at this merge. Consequently,
these two language read-backs and the empty alert list do not qualify the complete
scan. Safe projections and private-response hashes are in `analysis-readback.json`;
no Actions/check/log API or raw alert payload was used.

Forty-two focused policy regressions cover mode budgets, admission thresholds,
parent cgroup limits, malformed counters, inherited limits, Darwin counters and
rejected-summary publication before process launch. Their exact source hashes and
executed results are recorded in `memory-checks.json`; pinned publication secret
scanning is separate. The first test run had two portable-fixture errors caused
by assuming a platform-independent RLIM_INFINITY value; the fixture correction
is recorded and no scan pass is inferred. A new hosted run must pass all three
analyses and exact ingestion read-back before complete hosted qualification can
be claimed. Fork/Dependabot permissions, default-branch execution, full OSS-007
and release readiness remain open; no new required repository check is enabled.


The separate [Development run 43772519043](https://github.com/dlamaro96/governance-commons/actions/runs/43772519043)
passed all four required checks on tested merge `b3596f3525e26b8e01ce6bd8d538cf9113ac1cd1`.
Its original safe `behavior-summary.json` is retained with this attempt. That
behavior pass does not override the source-security failure or qualify the later
native-memory policy correction.
