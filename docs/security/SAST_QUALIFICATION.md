# Local source scanning qualification

This historical record covers the isolated local runs below. The later integrated
hosted attempt and its separate failure are recorded in
`SAST_HOSTED_QUALIFICATION.md`; neither record overrides the other.

Status: the final local source analysis, findings gate and artifact-hygiene checks
**PASS** on the isolated `codex/sast-qualification`
worktree based on `8d9c9c701d1f0ea49df13671088cbc8b1e294832`. Exact dirty
snapshots are identified by their source manifests; no result claims that
unchanged base HEAD or the newer root application was scanned. No report has
been uploaded and the triage register is empty.

## Evidence and boundaries

- `sast-evidence/attempt-ledger.json` indexes 12 original completed summaries;
  each copied summary is byte-identical to its invocation output.
- `sast-evidence/negative-control.json` records the actual three-language
  vulnerable-fixture rejection control. Its analysis passed and its findings gate
  deliberately blocked; this is not a product clean-findings pass.
- `sast-evidence/product-4-reprocess.json` binds original raw/published reports
  and newly sanitized copies without claiming an analysis rerun.
- `sast-evidence/local-checks.json` records 28 policy tests, 40 model/migration
  tests, 22 existing typed-migration/file-parser composition tests, focused
  TypeScript, publication baseline and whitespace checks, all
  passing. It includes exact executable/test hashes and actual tool versions.

The first full zero-finding result (`product-4`) completed all three analyses,
with 97/97 required JavaScript/TypeScript files, 24/24 Python files and 2/2 Actions
files extracted. Its source digest is
`69ae3b93308e71761b50781ae3446ef7bfef1e3de7b8d613fb7056e0c1142591`.
It resolved 105/52/24 queries respectively and completed in 187.956 seconds.
The original published SARIF contained percent-encoded local tool paths;
artifact hygiene was therefore not qualified by that run. The raw reports and
original published reports remain unchanged. Separate reprocessing with the
corrected scrubber verified all three sanitized copies, including decoded-path
checks, without rerunning analysis. The later `product-5` rerun below independently qualifies the corrected runner
and report copies; reprocessing alone was never treated as that rerun.

## Final local run

`product-5` completed at 2026-11-15T21:52:12.128631Z in 202.866 seconds using
`./dev test --suite sast --output .local/sast/product-5`, with the recorded Linux
arm64 platform and immutable per-language images. Its exact dirty source digest is
`b841349ba0f21dc2d57cdd77b078b318dce41687038a47cce894b716117e73b8`.

| Check | Executed result |
| --- | --- |
| JavaScript/TypeScript | 97/97 required files; 105 queries; zero findings |
| Python, including extensionless tools | 24/24 required files; 52 queries; zero findings |
| Actions | 2/2 required files; 24 queries; zero findings |
| Report hygiene | All public JSON parses; no plain/twice-decoded local user/worktree roots or SARIF source-body fields; actual result counts and raw/published hashes preserved |
| Source preservation | All 123 required executable paths still match the frozen snapshot |
| Human dispositions | None; triage register remains empty |
| Upload/hosted execution | Not performed |

The original source manifest, summaries and sanitized SARIF are under
`sast-evidence/product-5/`, with `artifact-hygiene.json` recording the independent
post-scan checks. The source manifest SHA256 is
`66ff481c7f4aa88b684feb2fc43fc84e66bf4625ea2ef02d9bb930e9312a3293`;
the summary SHA256 is
`465f95b5a110d60ca80fd3550e855ee29094bde0df7c85884179fca42bdbf126`.
Subsequent changes are evidence/documentation only; they do not retroactively
change the frozen scan digest or imply qualification of another checkout.

## Original attempts

| Attempt | Actual outcome and subsequent correction |
| --- | --- |
| Actions 1 | Tooling failure: CLI progress on stderr was mixed into JSON stdout. Capture streams separately. |
| Actions 2 | Analysis executed, but coverage query failed because nested private packs duplicated the search path. Restrict to verified top-level bundle packs. |
| Actions 3 | Actions-only analysis/coverage/findings passed; not a three-language pass. |
| Control 1 | Missing Node in the Python runtime image; control not passed. Use existing immutable images per language. |
| Control 2 | Analyses ran and findings blocked, but the initial read-only Actions fixture was medium severity, so the required high/critical control did not pass. |
| Control 3 | Generated contents-write Actions fixture produced the critical injection rule; all three control languages passed. |
| Control 4 | Final exact-rule checks passed for `js/command-line-injection`, `py/command-line-injection` and `actions/code-injection/critical`. |
| Product 1 | Analysis passed; findings blocked: seven dynamic property findings and one publication rule-label finding. |
| Product 2 | Fixed literal public rule-ID projection removed Python finding; seven JavaScript findings still blocked. |
| Product 3 | Own-data-property mutation removed six more findings; one dynamic `Object.defineProperty` sink remained blocked. |
| Product 4 | Private Map working tree produced zero findings in all languages; later artifact-path inspection found the separate publication defect described above. |
| Product 5 | Corrected runner: all three analyses, required coverage, zero-findings gate and separately inspected report hygiene passed. |

No original failure was relabeled as passing. The property query has medium
precision; parser guards already rejected forbidden names, and no remote exploit
was claimed from the scanner output alone. A separate inherited-setter regression
actually reproduced a normalizer problem. The normalizer now constructs own data
properties, while the migration working tree uses Maps and materializes plain
JSON only at the strict validation boundary. Tests preserve shadowing field names,
nested objects/lists, absent-path behavior, exact decimals and immutable inputs.
No suppression, risk waiver or invented reviewer was added.

## Actual runtime and resources

CodeQL 2.27.4 uses the checksum-verified Linux arm64 bundle
`7dd066f805dfed19c9c4323d5f2003cd24fabd6e7304cdf799b94a84509fe92b`.
The 678,801,372-byte archive contained 1,298,284,624 regular-file bytes; after
verified installation the invocation-owned compressed archive was removed.
The complete installed file/symlink inventory is checked before each execution.
Local Python is 3.14.5, Node is v24.22.3 and focused TypeScript is 7.0.2.

The existing Node image is
`sha256:309f28b6153c822533b01c29a72b79db58c9ecbaaf1f803c8386c511ec059651`;
Python and Actions use
`sha256:754f4044cfed7f63436c6bbb6d14aed540570c7f3586a5ff62e77aa4f705d44a`.
There were no image pulls/builds, application-volume mounts or application service
changes. Each CLI container had no network, a read-only source/toolchain/root,
a private output mount, 4 GiB memory and two CPUs. Explicit bounded cleanup
removes only that invocation's container, including timeout paths.

Scan admission remains 4.5 GiB with a 2 GiB hard watchdog; the measured complete
scan grew by approximately 0.3 GiB. Completed invocation-owned large logs were
losslessly compressed with original/compressed hashes and decompression proofs.
Twelve completed product extracted-database caches were removed after journaling
17,620 file hashes; all 80 retained report/coverage/query hashes were verified
unchanged. Snapshots, manifests, original SARIF, decoded coverage, query outputs,
diagnostics and logs remain. Cache re-extraction is reproducible using the pinned
toolchain and exact snapshots. No unrelated/unrelated local projects resources were changed.

Physical free space initially remained approximately 4.33 GiB, so execution
waited. Exact-ID pruning of 16 obsolete, non-shared Governance Commons COPY/build
cache records subsequently restored 4,925,825,024 available host bytes after
reclamation completed. Before/after image, container and volume ID sets were
identical; current dependency and shared current-build caches remained. No broad
prune was used. The final run then passed its unchanged admission check and
finished above the hard floor. Cleanup journals and proof digests are summarized
in `sast-evidence/resource-cleanup.json`.

## Resume and integration

1. Root reviews the source, final `product-5` evidence and original attempts.
   Preserve the final artifacts and their separate analysis/findings/hygiene
   status; no additional isolated rerun is implied.
2. Root integrates tracked-file patches, preserving newer root
   changes in `model.ts`, runtime dispatch and shared interfaces. New files may be
   added directly; whole older-base files must not overwrite newer source.
3. Re-run the integrated root source and hosted PR/default-branch jobs. Read back
   all three commit/category analyses, then exercise public fork and Dependabot
   permissions. Configure the observed stable `sast-required` gate only after
   qualification. No commits, pushes, settings changes or uploads were performed
   from this isolated workstream.

Native platforms, hosted ingestion/read-back, fork/Dependabot behavior and the
integrated root revision remain unqualified. CodeQL is the licensed public-OSS
route, not an unrestricted private fallback. SQL/RLS, dependency/image/general-IaC
scanning, independent review and the rest of OSS-007 remain separate requirements.
