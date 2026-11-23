# Release readiness

**Development preview — not a supported release.** Updated 23 November 2026.

The active integration includes real catalog/ownership/audit workflows, operating models and graph migrations, glossary/reference publication, PostgreSQL lineage/classification, and several source-executed quality families with scheduled incidents and recovery. These have scoped local evidence; they do not complete the entire product baseline. See [product status](../product/STATUS.md) for the remaining capability areas.

Published checkpoint `5d37594` passes verified exact-source JavaScript/TypeScript, Python and Actions security analysis: all 1,518 source files match, three authenticated archives and stored analyses are verified, and there are zero findings. Its 45-outcome development pipeline completed with 39 successes, two failures and four skips. Reference022 and protected authentication failed; their independent local corrections now pass, with the new hosted aggregate pending. [Verified current result](../verification/hosted-checkpoint-5d37594.json). The preceding `f7fc213` development run failed with 30 successes, three failures and ten skips across 43 outcomes. [Current source-security scope](../verification/source-security-5d37594.json) and [preceding CI result](../verification/hosted-checkpoint-f7fc213.json) remain separate from release qualification.

Locally applied SQL001–032 includes table-volume quality, authority-read optimization and the relation-validation repair. The healthy core matches 300 application and 13 worker source files at `5d37594`. SQL032 standalone scopes each pass 37 native cases; repaired019 passes 113, the composed repaired024 chain passes 263 with 176 exact inputs, and current-schema import passes five with 103 exact inputs. All 457 affected host controls and types pass. The earlier volume 320/worker 15-check and authority 133/423 evidence retain their recorded source-equivalence limits.

All 171 API cases pass on SQL032 at `5d37594`; the previous pass at `f3f21e5` and earlier process-abort attempt are retained. The hosted main browser suite passes all 37 journeys without retries; exact source/artifact bindings are verified, and three of 22 published screenshots were inspected. A fresh complete local rerun is not inferred. Attempt 16 failed with 24 passes, one obsolete table-refusal assertion and 12 unexecuted journeys; its source/artifact bindings and cleanup are verified. The [targeted quality repair](../verification/quality-table-browser-repair-local.json) passes, as do the volume and classification targets. Those target passes remain distinct from the later hosted full run. The prior full 36 pass has only a visual sample of three of 281 captures. Historical results remain bound to their sources in the [evidence manifest](../verification/evidence-manifest.json).

Published correction `b08b88d` now passes independent local reference022/023/024 qualification (158/194/263 cases), all 270 affected host controls, and immutable-image protected authentication (15 native / 2 browser cases, 203 exact source inputs, full 32-migration ledger). Source security attempt2 verifies all 1,522 files and all three stored analyses with zero findings. The initial installer HTTP failure is retained. Development run45102259563 fails SQL024 at its original 600-second lifecycle deadline and protected login during admission; the foundation job remains active. The read-only snapshot batching candidate needs native and fresh hosted qualification before protected merge. These corrections do not complete the release blockers below.

## Blocking release work

- Finish the remaining M0–M10 implementation and all 354 named baseline requirements. Optional activation does not remove required implementation.
- Pass clean installation, complete declared browser/security suites, current immutable-image CI and contributor onboarding.
- Qualify required connectors and identity providers against their declared real environments; retain exact external prerequisites until executed.
- Execute Kubernetes/OpenShift, offline, upgrade/restore, failure/recovery and measured load/soak profiles.
- Complete artifact/container/dependency scans, licence/SBOM inventories, signing/attestation and offline verification.
- Complete independent security, accessibility/Arabic and architecture review, plus a functioning private conduct-reporting/escalation route.

No production, parity, scale, high availability, backup/restore, live-vendor or certification claim is made. The qualified local host profile is Linux arm64 containers under Docker Desktop. GitHub source publication is allowed independently of supported-release qualification; protected merge/release gates stay blocking.

The reference022 correction now passes all 158 native cases with 163 exact candidate inputs, 26 process startup/exit proofs, preservation/replay and owned cleanup verified. All 270 affected host controls pass. Independent SQL023/024 and protected immutable-image runs now pass; the full hosted aggregate remains pending. [Scoped correction evidence](../verification/pipeline-prefix-repair-local.json).
