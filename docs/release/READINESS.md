# Release readiness

**Development preview — not a supported release.** Updated 17 November 2026.

The active integration includes real catalog/ownership/audit workflows, operating models and graph migrations, glossary/reference publication, PostgreSQL lineage/classification, and several source-executed quality families with scheduled incidents and recovery. These have scoped local evidence; they do not complete the entire product baseline. See [product status](../product/STATUS.md) for the remaining capability areas.

The latest hosted-qualified checkpoint `2186dcb` passes exact-source JavaScript/TypeScript, Python and Actions security analysis with zero findings. Its development pipeline records 27 of 40 required outcomes passing, three failing and ten skipped. Local product checkpoint `514ddee` adds table-volume quality and authority-read optimization; isolated volume (320 cases) and authority (133/423 cases) native cases pass. The volume and repaired classification browser targets pass. At `f3f21e5`, all 171 API cases pass after a bounded rollback-snapshot fixture repair; the preceding API attempt passed 154 before a test-process heap abort. The predecessor full 36-journey browser run passes all journeys without retries or skips, with only three of 281 captures inspected. The full 37-journey browser run is in progress, and fresh exact-revision hosted qualification remain required. Historical results stay bound to their sources in the [evidence manifest](../verification/evidence-manifest.json).

## Blocking release work

- Finish the remaining M0–M10 implementation and all 354 named baseline requirements. Optional activation does not remove required implementation.
- Pass clean installation, complete declared browser/security suites, current immutable-image CI and contributor onboarding.
- Qualify required connectors and identity providers against their declared real environments; retain exact external prerequisites until executed.
- Execute Kubernetes/OpenShift, offline, upgrade/restore, failure/recovery and measured load/soak profiles.
- Complete artifact/container/dependency scans, licence/SBOM inventories, signing/attestation and offline verification.
- Complete independent security, accessibility/Arabic and architecture review, plus a functioning private conduct-reporting/escalation route.

No production, parity, scale, high availability, backup/restore, live-vendor or certification claim is made. The qualified local host profile is Linux arm64 containers under Docker Desktop. GitHub source publication is allowed independently of supported-release qualification; protected merge/release gates stay blocking.
