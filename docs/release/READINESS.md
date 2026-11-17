# Release readiness

**Development preview — not a supported release.** Updated 17 November 2026.

The active integration includes real catalog/ownership/audit workflows, operating models and graph migrations, glossary/reference publication, PostgreSQL lineage/classification, and several source-executed quality families with scheduled incidents and recovery. These have scoped local evidence; they do not complete the entire product baseline. See [product status](../product/STATUS.md) for the remaining capability areas.

The current source-security run on `fca6bb94` passes its JavaScript/TypeScript, Python and Actions analyses. Its Development run passes 168 API cases but fails the authority-loader deadline; later stages are unexecuted. Local SQL029 scheduled freshness passes its target browser journey and 276 native cases. All 168 current local API cases pass; the full 36-journey browser regression records 31 passed, one failure and four skipped and a fresh exact-head hosted pass remains required. Historical results stay bound to their original sources in the [evidence manifest](../verification/evidence-manifest.json).

## Blocking release work

- Finish the remaining M0–M10 implementation and all 354 named baseline requirements. Optional activation does not remove required implementation.
- Pass clean installation, complete declared browser/security suites, current immutable-image CI and contributor onboarding.
- Qualify required connectors and identity providers against their declared real environments; retain exact external prerequisites until executed.
- Execute Kubernetes/OpenShift, offline, upgrade/restore, failure/recovery and measured load/soak profiles.
- Complete artifact/container/dependency scans, licence/SBOM inventories, signing/attestation and offline verification.
- Complete independent security, accessibility/Arabic and architecture review, plus a functioning private conduct-reporting/escalation route.

No production, parity, scale, high availability, backup/restore, live-vendor or certification claim is made. The qualified local host profile is Linux arm64 containers under Docker Desktop. GitHub source publication is allowed independently of supported-release qualification; protected merge/release gates stay blocking.
