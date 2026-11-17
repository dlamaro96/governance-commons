# Release readiness

**Development preview — not a supported release.** Updated 17 November 2026.

The active integration includes real catalog/ownership/audit workflows, operating models and graph migrations, glossary/reference publication, PostgreSQL lineage/classification, and several source-executed quality families with scheduled incidents and recovery. These have scoped local evidence; they do not complete the entire product baseline. See [product status](../product/STATUS.md) for the remaining capability areas.

The latest published checkpoint `f7fc213` passes fully verified exact-source JavaScript/TypeScript, Python and Actions security analysis: all 1,502 source files match, three authenticated archives and stored analyses are verified, and there are zero findings. Its 43-outcome development pipeline is still in progress with known governance, completeness-upgrade and browser failures; complete development evidence remains pending. [Source-security scope](../verification/source-security-f7fc213.json).

Locally applied SQL001–031 includes table-volume quality and authority-read optimization. Isolated volume 320 and authority 133/423 native cases pass; volume and classification browser targets pass. All 171 API cases pass at `f3f21e5`, retaining the preceding 154-pass/process-abort attempt. Full 37 attempt 16 failed with 24 passes, one obsolete table-refusal assertion and 12 unexecuted journeys. Its 692 source files and 187 artifacts were rehashed, 154 tracked captures restored, and cleanup passed. The [targeted quality repair](../verification/quality-table-browser-repair-local.json) at `a1a2972` passes 1/1 with four inspected scrolled evidence captures; it does not replace a fresh full 37 run. The prior full 36 pass has only a visual sample of three of 281 captures. SQL032 and the 45-outcome pipeline are integrated at `fabc708`; all457 affected host controls and types pass. Standalone37/37 and frozen repaired019113 native cases pass; the final composed024 run is in progress. Shared adoption and fresh hosted45 qualification remain pending. Historical results stay bound to their sources in the [evidence manifest](../verification/evidence-manifest.json).

## Blocking release work

- Finish the remaining M0–M10 implementation and all 354 named baseline requirements. Optional activation does not remove required implementation.
- Pass clean installation, complete declared browser/security suites, current immutable-image CI and contributor onboarding.
- Qualify required connectors and identity providers against their declared real environments; retain exact external prerequisites until executed.
- Execute Kubernetes/OpenShift, offline, upgrade/restore, failure/recovery and measured load/soak profiles.
- Complete artifact/container/dependency scans, licence/SBOM inventories, signing/attestation and offline verification.
- Complete independent security, accessibility/Arabic and architecture review, plus a functioning private conduct-reporting/escalation route.

No production, parity, scale, high availability, backup/restore, live-vendor or certification claim is made. The qualified local host profile is Linux arm64 containers under Docker Desktop. GitHub source publication is allowed independently of supported-release qualification; protected merge/release gates stay blocking.
