# First hosted source scanning attempt

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

## Diagnostic change awaiting hosted execution

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
the changed runner still needs its hosted scan and failure diagnostic read-back.

Next, review and publish the diagnostic patch, inspect the next safe artifact,
then fix the demonstrated failure. Complete all three hosted analyses and
independently read back the exact commit/category analyses. Fork/Dependabot
permissions and default-branch execution still need evidence. The earlier
isolated `product-5` pass qualifies only its own source digest; complete OSS-007
and release readiness remain open.
